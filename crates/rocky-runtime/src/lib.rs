//! Persistent local replicas. See `docs/runtime/local-replica.md` for lifecycle and APIs.
mod bootstrap;
mod checkpoint;
mod layout;
mod logical;
mod placement;
mod query;
mod read;
mod relocation;
mod runtime;
mod schema_evolution;
/// Versioned language-neutral SDK session over the precise runtime contract.
pub mod sdk;
pub use relocation::migrate_placement;
pub use rocky_storage::cursor::{
    CursorLimits, CursorPage, MAX_CURSOR_LIFETIME, MAX_SESSION_CURSORS, ResultColumn,
    SnapshotCursor, SnapshotRows,
};
pub use rocky_storage::observe::{Cause, TableChange, TableObserver};
/// How a session reads a statement's transaction control.
pub use rocky_storage::sql::{Control as SqlControl, classify as classify_sql};
mod tracking;
pub use query::{
    BoundQuery, Completeness, CursorKind, ReadCursor, ReadObserver, ReadOptions, ReadSnapshot,
    TypedQuery, TypedSnapshot,
};
pub use runtime::{DomainInstallation, DomainPlacement, Durability, Runtime, RuntimeOptions};
pub use writer::{CheckpointInterval, CheckpointKind, WriterStats};

pub use tracking::{MutationProgress, PeerEvidence, ProgressObserver};
mod replication;
mod storage;
mod worker;
mod writer;
pub use checkpoint::{
    AuditReport, Catchup, CheckpointCursor, CheckpointHold, CheckpointInfo, CheckpointPage,
    CheckpointRecord, Deduplication, PeerRetention, PrunedNotice, RebootstrapReport,
    RetentionPolicy, RetentionStatus,
};
pub use digest::SetDigest;
pub use replication::{
    Acknowledgment, MAX_SYNC_EXCEPTIONS, PeerProgress, SyncState, TRANSFER_PAGE_SIZE, TransferPage,
};

use rocky_core::{
    Envelope, LocalRevision, NodeId, OperationId, PrincipalId, Scope, StoredApplication,
};
use std::{
    path::Path,
    sync::{Arc, Mutex, Weak},
    thread::JoinHandle,
};
use tokio::sync::{mpsc, oneshot, watch};

pub use rocky_storage::{CommitClass, Error, FailureReason, MAX_FRAME_BYTES, StorageFailure};
pub(crate) use rocky_storage::{database, digest, observe, scoped_connection, sqlite};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub scope: Scope,
    pub node: NodeId,
    pub caller: PrincipalId,
}
impl Identity {
    pub fn author_key(self) -> rocky_core::AuthorKey {
        rocky_core::AuthorKey {
            scope: self.scope,
            node: self.node,
        }
    }
}
/// Explicit trusted development author bindings and delivery obligations.
/// This configuration is not cryptographic authentication.
#[derive(Clone, Debug, Default)]
pub struct RuntimeConfig {
    pub authors: Vec<(NodeId, PrincipalId)>,
    pub delivery_targets: Vec<NodeId>,
    /// Delivery targets trusted as full replica nodes. With a nonzero
    /// `RetentionPolicy::custody`, only their applied frontiers move the pruned_prefix.
    pub full_nodes: Vec<NodeId>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot<R> {
    pub rows: Vec<R>,
    pub revision: LocalRevision,
    pub frontier: rocky_core::AppliedFrontier,
    pub query: QueryIdentity,
}

impl<R> Snapshot<R> {
    pub fn revision_key(&self) -> rocky_core::RevisionKey {
        rocky_core::RevisionKey {
            scope: self.query.scope,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryIdentity {
    pub scope: Scope,
    pub name: &'static str,
}
/// Cursor pages cover retained records in key order. Restart a pass to discover
/// new records inserted before its cursor. Records behind the pruned prefix are gone.
#[derive(Clone, Debug)]
pub struct Page<T, C> {
    pub items: Vec<T>,
    pub next: Option<C>,
}
/// A precise encoded application action. None targets the newly allocated ID.
pub struct Mutation {
    pub entity: Option<OperationId>,
    pub payload: Vec<u8>,
}

fn mutation_hash(payload: &[u8], entity: Option<OperationId>) -> rocky_core::Commitment {
    let mut bytes = (payload.len() as u64).to_le_bytes().to_vec();
    bytes.extend(payload);
    bytes.push(u8::from(entity.is_some()));
    if let Some(entity) = entity {
        bytes.extend(entity.node.0);
        bytes.extend(entity.sequence.get().to_le_bytes());
    }
    rocky_core::commitment("rocky.mutation.input", &bytes)
}
/// Awaiting this receipt is optional; admitted work belongs to the runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MutationHandle(pub rocky_core::Commitment);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedMutation {
    pub operation: Envelope,
    pub class: CommitClass,
}
pub struct MutationReceipt {
    handle: MutationHandle,
    result: oneshot::Receiver<Result<CommittedMutation, Error>>,
    domain: Weak<dyn FlushDomain>,
}
impl MutationReceipt {
    pub fn handle(&self) -> MutationHandle {
        self.handle
    }
    /// The local commit, which may still be buffered. The operation is local
    /// evidence: send operations to peers through the replication API, or
    /// await `flushed` first.
    pub async fn committed(self) -> Result<Envelope, Error> {
        Ok(self.receipt().await?.operation)
    }
    /// The local commit and the class it reached.
    pub async fn receipt(self) -> Result<CommittedMutation, Error> {
        self.result.await.map_err(|_| Error::Closed)?
    }
    /// Waits until a flush covers the commit, forcing one if needed.
    pub async fn flushed(self) -> Result<Envelope, Error> {
        let domain = self.domain.clone();
        let committed = self.receipt().await?;
        if committed.class == CommitClass::Buffered {
            domain.upgrade().ok_or(Error::Closed)?.flush().await?;
        }
        Ok(committed.operation)
    }
}
/// Lets a receipt force its domain's flush without knowing the row type.
trait FlushDomain: Send + Sync {
    fn flush(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + Send + '_>>;
}
impl<R: Send + 'static> FlushDomain for Inner<R> {
    fn flush(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + Send + '_>> {
        Box::pin(async move {
            let (reply, result) = oneshot::channel();
            self.commands.send(Command::Flush(reply)).await?;
            result.await.map_err(|_| Error::Closed)?
        })
    }
}

type Reply<T> = oneshot::Sender<Result<T, Error>>;
enum Command<R> {
    Mutate(
        MutationHandle,
        Mutation,
        Option<LocalRevision>,
        Reply<CommittedMutation>,
    ),
    LookupMutation(MutationHandle, Reply<Option<CommittedMutation>>),
    /// Answers once a flush covers every commit of the domain so far.
    Flush(Reply<()>),
    Query(Reply<Snapshot<R>>),
    Close(Reply<()>),
    Sync(replication::Request, Reply<replication::Response>),
    Retention(Box<checkpoint::Request>, Reply<checkpoint::Response>),
    #[cfg(test)]
    Fault(worker::Fault, Reply<()>),
}
impl<R> Command<R> {
    /// Whether the command joins the file writer's group; others only read.
    fn writes(&self) -> bool {
        match self {
            Self::Mutate(..) => true,
            Self::Sync(request, _) => request.writes(),
            Self::Retention(request, _) => request.writes(),
            _ => false,
        }
    }
    /// Whether the reply can leave the device. It is answered only once the
    /// file's durable watermark covers everything the domain has committed.
    fn exposes(&self) -> bool {
        match self {
            Self::Flush(_) => true,
            Self::Sync(request, _) => request.exposes(),
            Self::Retention(request, _) => request.exposes(),
            _ => false,
        }
    }
    /// The kind of work a writer step runs, for `WriterStats` attribution.
    fn step_kind(&self) -> crate::writer::StepKind {
        match self {
            Self::Mutate(..) => crate::writer::StepKind::Authoring,
            Self::Sync(request, _) if request.writes() => crate::writer::StepKind::Incoming,
            _ => crate::writer::StepKind::Other,
        }
    }
    /// Answers without running the command.
    fn refuse(self, error: Error) {
        match self {
            Self::Mutate(_, _, _, reply) => drop(reply.send(Err(error))),
            Self::LookupMutation(_, reply) => drop(reply.send(Err(error))),
            Self::Flush(reply) => drop(reply.send(Err(error))),
            Self::Query(reply) => drop(reply.send(Err(error))),
            Self::Close(reply) => drop(reply.send(Err(error))),
            Self::Sync(_, reply) => drop(reply.send(Err(error))),
            Self::Retention(_, reply) => drop(reply.send(Err(error))),
            #[cfg(test)]
            Self::Fault(_, reply) => drop(reply.send(Err(error))),
        }
    }
}
struct Inner<R> {
    scope: Scope,
    commands: CommandQueue<R>,
    revisions: watch::Receiver<LocalRevision>,
    changes: watch::Receiver<u64>,
    thread: Mutex<Option<JoinHandle<()>>>,
    nonce: rocky_core::Commitment,
    submissions: std::sync::atomic::AtomicU64,
    observers: Arc<tokio::sync::Semaphore>,
    /// Set by the file's writer once the domain is open.
    reads: std::sync::OnceLock<Arc<read::Reads>>,
    /// Counters of the file writer that owns this domain.
    metrics: Arc<writer::Metrics>,
}
impl<R> Inner<R> {
    fn reads(&self) -> Result<&Arc<read::Reads>, Error> {
        if self.commands.sender.is_closed() {
            return Err(Error::Closed);
        }
        self.reads.get().ok_or(Error::Closed)
    }
}

pub struct Replica<A: StoredApplication> {
    inner: Arc<Inner<A::Row>>,
}
impl<A: StoredApplication> Clone for Replica<A> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}
impl<A> Replica<A>
where
    A: StoredApplication,
    A::State: Clone,
    A::Policy: Send + 'static,
{
    pub async fn open(
        path: impl AsRef<Path>,
        app: A,
        policy: A::Policy,
        identity: Identity,
    ) -> Result<Self, Error> {
        Self::open_with_config(
            path,
            app,
            policy,
            identity,
            RuntimeConfig {
                authors: vec![(identity.node, identity.caller)],
                ..RuntimeConfig::default()
            },
        )
        .await
    }
    pub async fn open_with_config(
        path: impl AsRef<Path>,
        app: A,
        policy: A::Policy,
        identity: Identity,
        config: RuntimeConfig,
    ) -> Result<Self, Error> {
        Self::open_with_options(
            path,
            app,
            policy,
            identity,
            config,
            RuntimeOptions::default(),
        )
        .await
    }
    /// A single-domain file with explicit options; `files` does not apply.
    pub async fn open_with_options(
        path: impl AsRef<Path>,
        app: A,
        policy: A::Policy,
        identity: Identity,
        mut config: RuntimeConfig,
        options: RuntimeOptions,
    ) -> Result<Self, Error> {
        options.validate()?;
        runtime::validate_config(identity, &mut config)?;
        let path = path.as_ref().to_path_buf();
        let (sender, receiver) = mpsc::channel(32);
        let commands = CommandQueue {
            sender,
            bytes: Arc::new(tokio::sync::Semaphore::new(MAX_QUEUE_BYTES)),
        };
        let (revisions, revision_receiver) = watch::channel(LocalRevision::default());
        let (changes, change_receiver) = watch::channel(0);
        let (ready, initialized) = oneshot::channel();
        let metrics = Arc::new(writer::Metrics::default());
        let writer_metrics = metrics.clone();
        let thread = std::thread::Builder::new()
            .name("rocky-writer".into())
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
                    // One domain can use the file writer directly.
                    let pool = read::ReadPool::new();
                    let setup = async {
                        let (owner, raw) = database::DatabaseOwner::open(&path).await?;
                        let conn = Arc::new(raw);
                        let scoped = scoped_connection::ScopedConnection::shared(
                            conn.clone(),
                            None,
                            &app.installed_schema().statements,
                        );
                        let worker = worker::Worker::open_connection(
                            scoped,
                            DomainInstallation {
                                app,
                                policy,
                                identity,
                                config,
                            },
                            options,
                            worker::Notifications { revisions, changes },
                            pool.clone(),
                            writer_metrics.clone(),
                        )
                        .await?;
                        let reads = worker.reads();
                        let writer = writer::Writer::new(
                            owner,
                            conn,
                            vec![(worker, receiver)],
                            options,
                            pool,
                            writer_metrics,
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
            })
            .map_err(Error::Io)?;
        let reads = initialized.await.map_err(|_| Error::Closed)??;
        Ok(Self {
            inner: Arc::new(Inner {
                scope: identity.scope,
                commands,
                revisions: revision_receiver,
                changes: change_receiver,
                thread: Mutex::new(Some(thread)),
                nonce: rocky_core::commitment(
                    "rocky.submission.session",
                    &std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|e| Error::Incompatible(e.to_string()))?
                        .as_nanos()
                        .to_le_bytes(),
                ),
                submissions: std::sync::atomic::AtomicU64::new(0),
                observers: Arc::new(tokio::sync::Semaphore::new(MAX_OBSERVERS)),
                reads: reads.into(),
                metrics,
            }),
        })
    }
    fn next_handle(&self) -> MutationHandle {
        let next = self
            .inner
            .submissions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut bytes = self.inner.nonce.to_vec();
        bytes.extend(next.to_le_bytes());
        MutationHandle(rocky_core::commitment("rocky.mutation.handle", &bytes))
    }
    /// Queues the mutation or returns `Backpressure` at once when the domain's
    /// queue is full; `submit` waits instead.
    pub fn mutate(&self, mutation: Mutation) -> Result<MutationReceipt, Error> {
        self.mutate_with_handle(self.next_handle(), mutation)
    }
    /// Like `mutate`, but waits for room in the domain's queue instead of
    /// returning `Backpressure`. Dropping the future before it resolves
    /// queues nothing.
    pub async fn submit(&self, mutation: Mutation) -> Result<MutationReceipt, Error> {
        self.submit_with_handle(self.next_handle(), mutation).await
    }
    /// `submit` with a caller-chosen handle; see `mutate_with_handle`.
    pub async fn submit_with_handle(
        &self,
        handle: MutationHandle,
        mutation: Mutation,
    ) -> Result<MutationReceipt, Error> {
        let (reply, result) = oneshot::channel();
        self.inner
            .commands
            .wait(Command::Mutate(handle, mutation, None, reply))
            .await?;
        let domain: Weak<dyn FlushDomain> = Arc::downgrade(&self.inner) as _;
        Ok(MutationReceipt {
            handle,
            result,
            domain,
        })
    }
    /// Work admitted to this domain's queue and not yet taken by its writer.
    pub fn queue_depth(&self) -> QueueDepth {
        self.inner.commands.depth()
    }
    /// Counters of the file writer this domain shares with its file's others.
    pub fn writer_stats(&self) -> WriterStats {
        self.inner.metrics.snapshot()
    }
    /// The most recent checkpoint intervals with monotonic timestamps, in
    /// completion order, and how many were dropped once the bounded log filled.
    /// Empty unless the file was opened with `RuntimeOptions::instrument`.
    pub fn checkpoint_intervals(&self) -> (Vec<CheckpointInterval>, u64) {
        self.inner.metrics.checkpoint_intervals()
    }
    /// Reusing a handle retries the same mutation; a different payload conflicts.
    pub fn mutate_with_handle(
        &self,
        handle: MutationHandle,
        mutation: Mutation,
    ) -> Result<MutationReceipt, Error> {
        self.mutate_with_precondition(handle, mutation, None)
    }
    /// A baseline mismatch rejects the entire mutation. Retrying a committed
    /// handle returns its original result even after the baseline has advanced.
    pub fn mutate_with_precondition(
        &self,
        handle: MutationHandle,
        mutation: Mutation,
        baseline: Option<LocalRevision>,
    ) -> Result<MutationReceipt, Error> {
        let (reply, result) = oneshot::channel();
        enqueue(
            &self.inner.commands,
            Command::Mutate(handle, mutation, baseline, reply),
        )?;
        let domain: Weak<dyn FlushDomain> = Arc::downgrade(&self.inner) as _;
        Ok(MutationReceipt {
            handle,
            result,
            domain,
        })
    }
    /// None means no local commit, including work still in the queue. Some is
    /// local commit evidence that may still be buffered; `lookup_commit`
    /// reports whether a flush made it durable.
    pub async fn lookup_mutation(&self, handle: MutationHandle) -> Result<Option<Envelope>, Error> {
        Ok(self
            .lookup_commit(handle)
            .await?
            .map(|committed| committed.operation))
    }
    /// The committed operation for `handle` and the class it has reached.
    pub async fn lookup_commit(
        &self,
        handle: MutationHandle,
    ) -> Result<Option<CommittedMutation>, Error> {
        let (reply, result) = oneshot::channel();
        self.inner
            .commands
            .send(Command::LookupMutation(handle, reply))
            .await?;
        result.await.map_err(|_| Error::Closed)?
    }
    /// Waits until a flush covers every commit of this domain so far, forcing
    /// one if needed. Flushes are shared by every domain of the file.
    pub async fn flush(&self) -> Result<(), Error> {
        let (reply, result) = oneshot::channel();
        self.inner.commands.send(Command::Flush(reply)).await?;
        result.await.map_err(|_| Error::Closed)?
    }
    /// The logical schema this domain is bound to, as verified against the
    /// installed tables at open. None for an application without one.
    pub fn logical_schema(&self) -> Result<Option<Arc<rocky_core::LogicalSchema>>, Error> {
        Ok(self.inner.reads()?.logical())
    }
    pub async fn query(&self) -> Result<Snapshot<A::Row>, Error> {
        query(&self.inner.commands, false).await
    }
    pub fn scope(&self) -> Scope {
        self.inner.scope
    }
    /// Observes committed changes of this domain's tables by name; None is
    /// every table. Register before reading the initial snapshot: every
    /// later commit that changes an observed table is reported once, after
    /// it committed, with the domain's revision after it.
    pub fn observe_tables(&self, tables: Option<&[&str]>) -> Result<observe::TableObserver, Error> {
        let labels: Option<Vec<(String, String)>> = tables.map(|tables| {
            tables
                .iter()
                .map(|table| (table.to_string(), table.to_string()))
                .collect()
        });
        let mut observer = observe::TableObserver::new();
        self.register_tables(&mut observer, labels.as_deref())?;
        Ok(observer)
    }
    pub(crate) fn register_tables(
        &self,
        observer: &mut observe::TableObserver,
        tables: Option<&[(String, String)]>,
    ) -> Result<(), Error> {
        self.inner.reads()?.events()?.register(observer, tables)?;
        // Read after registering: a commit published before is in this revision.
        observer.registered_at(self.inner.scope, self.inner.revisions.borrow().get());
        Ok(())
    }
    /// Registers immediately, before the initial query. No per-observer task.
    pub fn observe(&self) -> Result<Observer<A::Row>, Error> {
        Ok(Observer {
            _budget: self.observer_budget()?,
            runtime: Arc::downgrade(&self.inner),
            revisions: self.inner.revisions.clone(),
            initial: true,
            delivered: LocalRevision::default(),
        })
    }
    fn observer_budget(&self) -> Result<tokio::sync::OwnedSemaphorePermit, Error> {
        self.inner
            .observers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Quota {
                resource: "observers",
                limit: MAX_OBSERVERS,
            })
    }
    /// Drains admitted work before releasing the database and stopping observers.
    pub async fn close(&self) -> Result<(), Error> {
        let (reply, result) = oneshot::channel();
        self.inner.commands.send(Command::Close(reply)).await?;
        result.await.map_err(|_| Error::Closed)??;
        let thread = self.inner.thread.lock().map_err(|_| Error::Closed)?.take();
        if let Some(thread) = thread {
            tokio::task::spawn_blocking(move || thread.join())
                .await
                .map_err(|_| Error::Closed)?
                .map_err(|_| Error::Closed)?;
        }
        Ok(())
    }
}
/// Commands and bytes waiting in one domain's queue, with their bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueDepth {
    pub commands: usize,
    pub command_capacity: usize,
    pub bytes: usize,
    pub byte_capacity: usize,
}
pub const MAX_OBSERVERS: usize = 128;
pub const MAX_QUEUE_BYTES: usize = 8 * MAX_FRAME_BYTES;
struct QueuedCommand<R> {
    command: Command<R>,
    _budget: tokio::sync::OwnedSemaphorePermit,
}
struct CommandQueue<R> {
    sender: mpsc::Sender<QueuedCommand<R>>,
    bytes: Arc<tokio::sync::Semaphore>,
}
impl<R> CommandQueue<R> {
    /// Bytes `command` holds of the queue's byte budget while it waits.
    fn weight(command: &Command<R>) -> Result<usize, Error> {
        let control = matches!(
            command,
            Command::Close(_)
                | Command::Query(_)
                | Command::LookupMutation(_, _)
                | Command::Flush(_)
        );
        let weight = match command {
            Command::Mutate(_, mutation, _, _) => mutation.payload.len(),
            Command::Sync(replication::Request::Receive(bytes), _) => bytes.len(),
            Command::Sync(replication::Request::ReceivePage(records), _) => {
                records.iter().map(Vec::len).sum()
            }
            Command::Sync(replication::Request::Missing(ids), _) => ids.len().saturating_mul(24),
            Command::Retention(request, _) => request.weight(),
            _ => 0,
        }
        .saturating_add(if control { 0 } else { 256 });
        if weight > MAX_FRAME_BYTES {
            return Err(Error::Quota {
                resource: "frame bytes",
                limit: MAX_FRAME_BYTES,
            });
        }
        Ok(weight)
    }
    fn reserve(&self, command: Command<R>) -> Result<QueuedCommand<R>, Error> {
        let budget = self
            .bytes
            .clone()
            .try_acquire_many_owned(Self::weight(&command)? as u32)
            .map_err(|_| Error::Backpressure)?;
        Ok(QueuedCommand {
            command,
            _budget: budget,
        })
    }
    /// Waits for both the byte budget and a queue slot; never `Backpressure`.
    async fn wait(&self, command: Command<R>) -> Result<(), Error> {
        let budget = self
            .bytes
            .clone()
            .acquire_many_owned(Self::weight(&command)? as u32)
            .await
            .map_err(|_| Error::Closed)?;
        self.sender
            .send(QueuedCommand {
                command,
                _budget: budget,
            })
            .await
            .map_err(|_| Error::Closed)
    }
    fn depth(&self) -> QueueDepth {
        let capacity = self.sender.max_capacity();
        QueueDepth {
            commands: capacity - self.sender.capacity(),
            command_capacity: capacity,
            bytes: MAX_QUEUE_BYTES.saturating_sub(self.bytes.available_permits()),
            byte_capacity: MAX_QUEUE_BYTES,
        }
    }
    fn try_send(&self, command: Command<R>) -> Result<(), Error> {
        self.sender
            .try_send(self.reserve(command)?)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => Error::Backpressure,
                mpsc::error::TrySendError::Closed(_) => Error::Closed,
            })
    }
    async fn send(&self, command: Command<R>) -> Result<(), Error> {
        self.sender
            .send(self.reserve(command)?)
            .await
            .map_err(|_| Error::Closed)
    }
}
fn enqueue<R>(sender: &CommandQueue<R>, command: Command<R>) -> Result<(), Error> {
    sender.try_send(command)
}
async fn query<R>(sender: &CommandQueue<R>, wait: bool) -> Result<Snapshot<R>, Error> {
    let (reply, result) = oneshot::channel();
    if wait {
        sender.send(Command::Query(reply)).await?;
    } else {
        enqueue(sender, Command::Query(reply))?;
    }
    result.await.map_err(|_| Error::Closed)?
}
pub struct Observer<R> {
    _budget: tokio::sync::OwnedSemaphorePermit,
    runtime: Weak<Inner<R>>,
    revisions: watch::Receiver<LocalRevision>,
    initial: bool,
    delivered: LocalRevision,
}
impl<R> Observer<R> {
    pub async fn next(&mut self) -> Result<Snapshot<R>, Error> {
        loop {
            let current = *self.revisions.borrow_and_update();
            if self.initial || current > self.delivered {
                break;
            }
            self.revisions.changed().await.map_err(|_| Error::Closed)?;
        }
        let runtime = self.runtime.upgrade().ok_or(Error::Closed)?;
        let snapshot = query(&runtime.commands, true).await?;
        self.delivered = snapshot.revision;
        self.initial = false;
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod sync_tests;

#[cfg(test)]
mod audit_tests;

#[cfg(test)]
mod app_runtime_tests;

#[cfg(test)]
mod scaling_option_tests;

#[cfg(test)]
mod writer_tests;

#[cfg(test)]
mod instrumentation_tests;

#[cfg(test)]
mod watermark_tests;

#[cfg(test)]
mod write_concurrency_tests;

#[cfg(test)]
mod layout_tests;

#[cfg(test)]
mod read_tests;

#[cfg(test)]
mod stored_state_tests;

#[cfg(all(test, unix))]
mod crash_tests;

#[cfg(all(test, unix))]
mod retention_tests;

#[cfg(test)]
mod wide_schema_tests;

#[cfg(all(test, unix))]
mod relocation_tests;

#[cfg(test)]
mod roles_tests;
