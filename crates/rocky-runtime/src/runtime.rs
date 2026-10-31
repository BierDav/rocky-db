use crate::{scoped_connection::ScopedConnection, storage, worker, *};

/// Installed code and policy for one declared domain. All domains are installed
/// before admission; optional additive indexes are installed during open.
pub struct DomainInstallation<A: StoredApplication> {
    pub app: A,
    pub policy: A::Policy,
    pub identity: Identity,
    pub config: RuntimeConfig,
}
/// When commits reach the device. Either way nothing leaves the device before
/// a full flush covers it, so power loss can only drop local work that was
/// never sent, sealed or acknowledged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Durability {
    /// Commits at `synchronous=NORMAL` without a device flush. A flush, forced
    /// before anything is exposed outside the device, advances the durable
    /// watermark; see `CommitClass`.
    #[default]
    Buffered,
    /// Every group is flushed (`F_FULLFSYNC` where available) before replies.
    Full,
}
impl Durability {
    /// The `synchronous` level for ordinary groups. Flushes always use FULL
    /// with `fullfsync`.
    pub(crate) fn synchronous(self) -> i64 {
        match self {
            Self::Buffered => 1,
            Self::Full => 2,
        }
    }
}
/// Most files one `Runtime` spreads its domains over.
pub(crate) const MAX_FILES: usize = 16;
/// Explicit layouts can serve larger domain sets.
pub(crate) const MAX_PLACED_FILES: usize = 256;
/// Most writing steps one group commit may hold.
pub(crate) const MAX_GROUP_COMMIT: usize = 256;
/// Bounds of `RuntimeOptions::checkpoint_frames`: 1 MiB to 4 GiB of WAL.
pub(crate) const MIN_CHECKPOINT_FRAMES: u32 = 256;
pub(crate) const MAX_CHECKPOINT_FRAMES: u32 = 1 << 20;
/// Experimental scaling controls; defaults reproduce the qualified behaviour.
/// See `docs/runtime/scaling-limits.md` before changing them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeOptions {
    pub durability: Durability,
    /// Most writing steps, across all domains of the file, that share one
    /// commit and flush. One means a commit per step.
    pub group_commit: usize,
    /// When each domain checkpoints and prunes its history.
    pub retention: RetentionPolicy,
    /// Files the domains are spread over, each with its own writer thread,
    /// WAL and flush. Fixed at first install: up to 16 for automatic layouts,
    /// or 256 with `Runtime::open_placed`.
    pub files: usize,
    /// WAL frames of 4 KiB after which a file's writer checkpoints between
    /// groups; the WAL file can reach about twice this. Each checkpoint
    /// holds the writer for tens of milliseconds, so a file under sustained
    /// load trades WAL size for tail latency here.
    pub checkpoint_frames: u32,
    /// Collect per-step subphase timing (admission/reduction/encoding/SQL) and
    /// record checkpoint intervals with monotonic timestamps. Off by default:
    /// the added timestamps and atomics are measurable at high write rates.
    pub instrument: bool,
}
impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            durability: Durability::Buffered,
            // Enough for 16 domains with 8 waiting writers each to share one
            // commit. A group takes only what is already queued, so the bound
            // adds no delay under light load.
            group_commit: 128,
            retention: RetentionPolicy::default(),
            files: 1,
            checkpoint_frames: crate::writer::CHECKPOINT_FRAMES,
            instrument: false,
        }
    }
}
impl RuntimeOptions {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.group_commit == 0 || self.group_commit > MAX_GROUP_COMMIT {
            return Err(Error::Quota {
                resource: "group commit steps",
                limit: MAX_GROUP_COMMIT,
            });
        }
        if !(MIN_CHECKPOINT_FRAMES..=MAX_CHECKPOINT_FRAMES).contains(&self.checkpoint_frames) {
            return Err(Error::Quota {
                resource: "checkpoint frames",
                limit: MAX_CHECKPOINT_FRAMES as usize,
            });
        }
        Ok(())
    }
}
/// Persistent file assignment. Supply the recorded set plus any new domains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainPlacement {
    pub scope: Scope,
    pub file: usize,
}
pub struct Runtime<A: StoredApplication> {
    domains: std::collections::HashMap<Scope, Replica<A>>,
    /// One file writer per file; each owns the domains of its file.
    threads: Vec<JoinHandle<()>>,
}
impl<A> Runtime<A>
where
    A: StoredApplication,
    A::State: Clone,
    A::Policy: Send + 'static,
{
    /// Opens or installs the domains in `path` and its sibling files; see
    /// `crate::layout` for names, assignment and the install order.
    pub async fn open(
        path: impl AsRef<Path>,
        installations: Vec<DomainInstallation<A>>,
    ) -> Result<Self, Error> {
        Self::open_with_options(path, installations, RuntimeOptions::default()).await
    }
    pub async fn open_with_options(
        path: impl AsRef<Path>,
        installations: Vec<DomainInstallation<A>>,
        options: RuntimeOptions,
    ) -> Result<Self, Error> {
        Self::open_layout(path, installations, options, None).await
    }
    /// Opens only files serving these installations. Assignments are persisted
    /// independently of sorted scope order and may only be extended.
    pub async fn open_placed(
        path: impl AsRef<Path>,
        installations: Vec<DomainInstallation<A>>,
        placement: Vec<DomainPlacement>,
        options: RuntimeOptions,
    ) -> Result<Self, Error> {
        Self::open_layout(path, installations, options, Some(placement)).await
    }
    async fn open_layout(
        path: impl AsRef<Path>,
        mut installations: Vec<DomainInstallation<A>>,
        options: RuntimeOptions,
        placement: Option<Vec<DomainPlacement>>,
    ) -> Result<Self, Error> {
        options.validate()?;
        let max_files = if placement.is_some() {
            MAX_PLACED_FILES
        } else {
            MAX_FILES
        };
        if options.files == 0 || options.files > max_files {
            return Err(Error::Quota {
                resource: "runtime files",
                limit: max_files,
            });
        }
        if installations.is_empty() || installations.len() > 4096 {
            return Err(Error::Incompatible(
                "install between one and 4096 domains".into(),
            ));
        }
        installations.sort_by_key(|domain| {
            (
                domain.identity.scope.mesh,
                domain.identity.scope.app,
                domain.identity.scope.domain,
            )
        });
        let mut binding = Vec::new();
        let mut scopes = Vec::new();
        for domain in &mut installations {
            validate_config(domain.identity, &mut domain.config)?;
            domain.app.descriptor().operations.validate()?;
            let manifest = domain.app.manifest().ok_or_else(|| {
                Error::Incompatible("shared runtime requires an installed manifest".into())
            })?;
            manifest.validate()?;
            if !manifest.supports(
                domain.identity.scope,
                domain.app.descriptor().operations,
                domain.app.descriptor().projection,
            ) {
                return Err(Error::Incompatible(
                    "manifest does not bind installed domain and generations".into(),
                ));
            }
            if scopes.contains(&domain.identity.scope) {
                return Err(Error::Conflict);
            }
            domain
                .app
                .admit_read(
                    domain.identity.scope,
                    domain.identity.caller,
                    &domain.policy,
                )
                .map_err(storage::application)?;
            scopes.push(domain.identity.scope);
            let bytes = worker::identity_bytes(domain.identity, &domain.app, &domain.config);
            binding.extend((bytes.len() as u32).to_le_bytes());
            binding.extend(bytes);
        }
        let path = path.as_ref().to_path_buf();
        // Fewer domains than files use only as many files as domains.
        let used = if placement.is_some() {
            options.files
        } else {
            options.files.min(installations.len())
        };
        let routes: Vec<usize> = if let Some(placement) = &placement {
            let mut assigned = std::collections::HashMap::new();
            if placement.is_empty() || placement.len() > 4096 {
                return Err(Error::Incompatible(
                    "placement requires one to 4096 domains".into(),
                ));
            }
            for item in placement {
                if item.file >= used || assigned.insert(item.scope, item.file).is_some() {
                    return Err(Error::Incompatible(
                        "invalid or duplicate domain placement".into(),
                    ));
                }
            }
            scopes
                .iter()
                .map(|scope| {
                    assigned
                        .get(scope)
                        .copied()
                        .ok_or_else(|| Error::Incompatible("unassigned scope".into()))
                })
                .collect::<Result<_, _>>()?
        } else {
            (0..installations.len()).map(|index| index % used).collect()
        };
        let metrics: Vec<_> = (0..used)
            .map(|_| Arc::new(crate::writer::Metrics::default()))
            .collect();
        let mut domains = Vec::new();
        let mut channels = Vec::new();
        for (index, scope) in scopes.into_iter().enumerate() {
            let (sender, receiver) = mpsc::channel(32);
            let (revisions, revision_receiver) = watch::channel(LocalRevision::default());
            let (changes, change_receiver) = watch::channel(0);
            let nonce = rocky_core::commitment(
                "rocky.runtime.session",
                &[
                    binding.as_slice(),
                    &std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|error| Error::Incompatible(error.to_string()))?
                        .as_nanos()
                        .to_le_bytes(),
                    &scope.domain.0,
                ]
                .concat(),
            );
            domains.push((
                scope,
                Replica {
                    inner: Arc::new(Inner {
                        scope,
                        commands: CommandQueue {
                            sender,
                            bytes: Arc::new(tokio::sync::Semaphore::new(MAX_QUEUE_BYTES)),
                        },
                        revisions: revision_receiver,
                        changes: change_receiver,
                        thread: Mutex::new(None),
                        nonce,
                        submissions: std::sync::atomic::AtomicU64::new(0),
                        observers: Arc::new(tokio::sync::Semaphore::new(MAX_OBSERVERS)),
                        reads: std::sync::OnceLock::new(),
                        // File assignment follows the validated routes.
                        metrics: metrics[routes[index]].clone(),
                    }),
                },
            ));
            channels.push((receiver, worker::Notifications { revisions, changes }));
        }
        let (installations, files) = if let Some(placement) = placement {
            crate::placement::install(path, options.files, placement, installations).await?
        } else {
            let (installations, files) =
                crate::layout::install(path, options.files, used, binding, installations).await?;
            (installations, files.into_iter().enumerate().collect())
        };
        // File assignment follows the validated routes.
        let mut assigned: Vec<Vec<_>> = (0..used).map(|_| Vec::new()).collect();
        for (index, domain) in installations.into_iter().zip(channels).enumerate() {
            assigned[routes[index]].push(domain);
        }
        let mut threads = Vec::new();
        let mut readiness = Vec::new();
        let mut failure = None;
        for (index, (owner, raw)) in files {
            let domains = std::mem::take(&mut assigned[index]);
            let (ready, initialized) = oneshot::channel();
            let metrics = metrics[index].clone();
            let spawned = std::thread::Builder::new()
                .name(format!("rocky-writer-{index}"))
                .spawn(move || {
                    let runtime = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(runtime) => runtime,
                        Err(error) => {
                            let _ = ready.send(Err(Error::Io(error)));
                            return;
                        }
                    };
                    runtime.block_on(async move {
                        let pool = crate::read::ReadPool::new();
                        let setup = async {
                            let conn = Arc::new(raw);
                            let mut workers = Vec::new();
                            let mut reads = Vec::new();
                            for (domain, (receiver, notifications)) in domains {
                                let scoped = ScopedConnection::shared(
                                    conn.clone(),
                                    Some(&namespace(domain.identity.scope)),
                                    &domain.app.installed_schema().statements,
                                );
                                let scope = domain.identity.scope;
                                let worker = worker::Worker::open_connection(
                                    scoped,
                                    domain,
                                    options,
                                    notifications,
                                    pool.clone(),
                                    metrics.clone(),
                                )
                                .await?;
                                reads.push((scope, worker.reads()));
                                workers.push((worker, receiver));
                            }
                            let writer = crate::writer::Writer::new(
                                owner, conn, workers, options, pool, metrics,
                            )?;
                            Ok((writer, reads))
                        }
                        .await;
                        match setup {
                            Ok((writer, reads)) => {
                                let _ = ready.send(Ok(reads));
                                writer.run().await;
                            }
                            Err(error) => {
                                let _ = ready.send(Err(error));
                            }
                        }
                    });
                });
            match spawned {
                Ok(thread) => {
                    threads.push(thread);
                    readiness.push(initialized);
                }
                Err(error) => {
                    failure = Some(Error::Io(error));
                    break;
                }
            }
        }
        for initialized in readiness {
            let outcome: Result<Vec<(Scope, Arc<crate::read::Reads>)>, Error> = initialized
                .await
                .map_err(|_| Error::Closed)
                .and_then(|result| result);
            match outcome {
                Ok(reads) => {
                    for (scope, reads) in reads {
                        if let Some((_, domain)) = domains.iter().find(|(key, _)| *key == scope) {
                            let _ = domain.inner.reads.set(reads);
                        }
                    }
                }
                Err(error) => {
                    if failure.is_none() {
                        failure = Some(error);
                    }
                }
            }
        }
        if let Some(error) = failure {
            // Dropping the queues stops the writers that did open.
            drop(domains);
            for thread in threads {
                let _ = thread.join();
            }
            return Err(error);
        }
        let domains: std::collections::HashMap<_, _> = domains.into_iter().collect();
        Ok(Self { domains, threads })
    }
    pub fn domain(&self, scope: Scope) -> Result<Replica<A>, Error> {
        self.domains
            .get(&scope)
            .cloned()
            .ok_or(Error::Protocol(rocky_core::ProtocolError::ForeignScope))
    }
    pub async fn close(mut self) -> Result<(), Error> {
        let mut failure = None;
        for domain in self.domains.values() {
            match domain.close().await {
                Ok(()) | Err(Error::Closed) => {}
                Err(error) => {
                    if failure.is_none() {
                        failure = Some(error);
                    }
                }
            }
        }
        for thread in std::mem::take(&mut self.threads) {
            tokio::task::spawn_blocking(move || thread.join())
                .await
                .map_err(|_| Error::Closed)?
                .map_err(|_| Error::Closed)?;
        }
        failure.map_or(Ok(()), Err)
    }
}
pub(crate) fn namespace(scope: Scope) -> String {
    let bytes = [scope.mesh.0, scope.app.0, scope.domain.0].concat();
    let hash = rocky_core::commitment("rocky.domain.tables.v1", &bytes);
    let mut namespace = String::from("d");
    for byte in hash {
        use std::fmt::Write;
        let _ = write!(namespace, "{byte:02x}");
    }
    namespace
}
pub(crate) fn validate_config(identity: Identity, config: &mut RuntimeConfig) -> Result<(), Error> {
    if config.authors.len() > 64 || config.delivery_targets.len() > 64 {
        return Err(Error::Quota {
            resource: "configured peers",
            limit: 64,
        });
    }
    config.authors.sort();
    config.authors.dedup();
    config.delivery_targets.sort();
    config.delivery_targets.dedup();
    config
        .delivery_targets
        .retain(|node| *node != identity.node);
    config.full_nodes.sort();
    config.full_nodes.dedup();
    if !config.authors.contains(&(identity.node, identity.caller))
        || config
            .delivery_targets
            .iter()
            .any(|node| !config.authors.iter().any(|(author, _)| author == node))
        || config
            .full_nodes
            .iter()
            .any(|node| !config.delivery_targets.contains(node))
    {
        return Err(Error::Incompatible(
            "invalid author or delivery configuration".into(),
        ));
    }
    Ok(())
}
