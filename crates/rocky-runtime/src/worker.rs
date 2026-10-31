mod audit;
mod incoming;
mod pruning;
mod rebootstrap;
pub(crate) mod retention;
use crate::read::{Changed, ReadPlan, ReadPool, Reads};
use crate::scoped_connection::ScopedConnection;
use crate::{
    Command, Identity, Mutation, Snapshot,
    storage::{self, Error, application, bindings, finish, retryable, rows},
    writer::{Answer, Answered, Metrics, nanos},
};
use rocky_core::{
    AdmissionBoundary, AuthorSequence, Envelope, LamportTime, LocalRevision, NodeId, OperationId,
    ProjectionStatement, SqlValue, StoredApplication, required_dependencies,
};
use std::{collections::BTreeMap, sync::Arc, time::Instant};
use tokio::sync::watch;

#[cfg(test)]
pub(crate) enum Fault {
    FailBeforeCommit,
    RetryBeforeCommit(usize),
    /// Kill the process inside a group, after this many written steps.
    AbortAfterWrites(usize),
    /// Kill the process after every step of the next group has released its
    /// savepoint, before the group's `COMMIT`.
    AbortBeforeCommit,
    /// Kill the process after a group commits, before any submitter is answered.
    AbortAfterCommit,
    /// Fail the next group's `COMMIT`, as a full disk would.
    FailCommit,
    /// Kill the process inside a resetting checkpoint that waits for a reader.
    AbortInCheckpoint,
    Pause(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    ),
    /// Test hook: the file writer logs each committed group.
    RecordGroups(GroupLog),
    /// Test hook: copy the file and its WAL to this directory at every flush,
    /// as power loss would leave them.
    SnapshotAtFlush(std::path::PathBuf),
    /// Test hook: the passive checkpoint threshold; resets happen at twice it.
    CheckpointFrames(i64),
}
/// Per committed group: each step's domain index and queue weight.
#[cfg(test)]
pub(crate) type GroupLog = Arc<std::sync::Mutex<Vec<Vec<(usize, usize)>>>>;
#[cfg(test)]
impl Fault {
    /// Faults the file writer handles instead of a domain's worker.
    pub(crate) fn file_level(&self) -> bool {
        matches!(
            self,
            Self::AbortBeforeCommit
                | Self::AbortAfterCommit
                | Self::FailCommit
                | Self::AbortInCheckpoint
                | Self::RecordGroups(_)
                | Self::SnapshotAtFlush(_)
                | Self::CheckpointFrames(_)
        )
    }
}

pub(crate) struct Notifications {
    pub(crate) revisions: watch::Sender<LocalRevision>,
    pub(crate) changes: watch::Sender<u64>,
}
/// Notifications held back until the file writer's group has committed.
#[derive(Default)]
struct Unpublished {
    revision: bool,
    changes: bool,
    /// Completeness may have changed.
    meta: bool,
    views: Changed,
    /// Why the tables in `views` changed.
    causes: std::collections::BTreeSet<crate::observe::Cause>,
}
impl Unpublished {
    /// Committed changes of the step that ends.
    pub(crate) fn changed(&mut self, changed: Changed, cause: crate::observe::Cause) {
        if changed.any() {
            self.causes.insert(cause);
        }
        self.views.merge(changed);
    }
}
/// Distinct projection statements whose changed views are remembered.
const MAX_STATEMENT_TARGETS: usize = 4096;
/// Bytes one retained operation counts beyond its encoding.
const RECORD_OVERHEAD: usize = 128;
/// One domain's counters and storage steps. Application state, operation
/// records and applied history live in storage only. Every domain in a file
/// writes through the file writer's connection; see `crate::writer`.
pub(crate) struct Worker<A: StoredApplication> {
    writer: ScopedConnection,
    /// Read-only connection for requests that write nothing.
    reader: Option<ScopedConnection>,
    reading: bool,
    /// The running read transaction has no time bound.
    unbounded: bool,
    /// Set by the file writer while this worker runs a step of its group.
    pub(crate) in_group: bool,
    /// Whether subphase timing is collected, from `RuntimeOptions::instrument`.
    instrument: bool,
    /// File writer counters this worker's step subphases feed.
    metrics: Arc<Metrics>,
    unpublished: Unpublished,
    /// Committed since the file's last flush; exposure must wait for one.
    dirty: bool,
    /// Local author sequence covered by the file's durable watermark.
    flushed_sequence: u64,
    /// The application's SQL, read once at open.
    schema: rocky_core::InstalledSchema,
    app: A,
    policy: A::Policy,
    identity: Identity,
    config: crate::RuntimeConfig,
    plan: Arc<ReadPlan>,
    reads: Arc<Reads>,
    /// The table and the views each installed projection statement can
    /// change, by statement; None if its target is not recognized.
    targets: std::collections::HashMap<Box<str>, Option<(String, Vec<usize>)>>,
    /// Observers of this domain's committed tables.
    events: Arc<crate::observe::TableEvents>,
    retention: retention::Retention,
    /// Retained operation records and their accounted bytes.
    retained: usize,
    retained_bytes: usize,
    /// Highest applied sequence of each author; applied logs have no gaps.
    frontier: BTreeMap<NodeId, AuthorSequence>,
    sequence: u64,
    lamport: u64,
    revision: LocalRevision,
    revisions: watch::Sender<LocalRevision>,
    changes: watch::Sender<u64>,
    /// One change counter per authorized view, and one for read metadata.
    views: Vec<watch::Sender<u64>>,
    meta: watch::Sender<u64>,
    #[cfg(test)]
    pub(crate) fault: Option<Fault>,
}
pub(crate) fn identity_bytes<A: StoredApplication>(
    identity: Identity,
    app: &A,
    config: &crate::RuntimeConfig,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    for id in [
        identity.scope.mesh.0,
        identity.scope.app.0,
        identity.scope.domain.0,
        identity.node.0,
        identity.caller.0,
    ] {
        bytes.extend(id);
    }
    let descriptor = app.descriptor();
    for version in [
        4u32,
        descriptor.operations.protocol,
        descriptor.operations.schema,
        descriptor.operations.operation,
        descriptor.projection,
    ] {
        bytes.extend(version.to_le_bytes());
    }
    bytes.extend((config.authors.len() as u64).to_le_bytes());
    for (node, caller) in &config.authors {
        bytes.extend(node.0);
        bytes.extend(caller.0);
    }
    bytes.extend((config.delivery_targets.len() as u64).to_le_bytes());
    for node in &config.delivery_targets {
        bytes.extend(node.0);
    }
    bytes.extend(retention::definition_commitment(app));
    bytes
}
impl<A> Worker<A>
where
    A: StoredApplication,
    A::State: Clone,
{
    pub(crate) async fn open_connection(
        conn: ScopedConnection,
        domain: crate::DomainInstallation<A>,
        options: crate::RuntimeOptions,
        notifications: Notifications,
        pool: Arc<ReadPool>,
        metrics: Arc<Metrics>,
    ) -> Result<Self, Error> {
        let crate::DomainInstallation {
            app,
            policy,
            identity,
            config,
        } = domain;
        if options.retention.custody > config.full_nodes.len() {
            return Err(Error::Incompatible(
                "custody needs that many configured full nodes".into(),
            ));
        }
        app.descriptor().operations.validate()?;
        if let Some(schema) = app.logical_schema() {
            schema
                .supported_on(rocky_core::Profile::Trusted)
                .map_err(|error| Error::Incompatible(error.to_string()))?;
        }
        let schema = app.installed_schema();
        if let Some(manifest) = app.manifest() {
            manifest.validate()?;
            if !manifest.supports(
                identity.scope,
                app.descriptor().operations,
                app.descriptor().projection,
            ) {
                return Err(Error::Incompatible(
                    "installed manifest binding differs".into(),
                ));
            }
        }
        let tables = rows(&conn, "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").await?;
        let mut tables = conn.logical_tables(tables);
        let mut fresh = tables.is_empty();
        let interrupted = conn.names().namespace().is_none()
            && tables.contains(&vec![SqlValue::Text("rocky_bootstrap".into())]);
        let expected = identity_bytes(identity, &app, &config);
        if !fresh && !interrupted {
            if !tables.contains(&vec![SqlValue::Text("rocky_replica".into())]) {
                return Err(Error::Incompatible(
                    "missing Rocky identity metadata".into(),
                ));
            }
            let stored = rows(&conn, "SELECT identity FROM rocky_replica WHERE id=1").await?;
            if stored != vec![vec![SqlValue::Blob(expected.clone())]] {
                return Err(Error::Incompatible(
                    "node, scope, caller or installed definition differs".into(),
                ));
            }
        }
        // Validate identity before any configuration or schema write.
        crate::writer::configure(&conn, options.durability).await?;
        app.admit_read(identity.scope, identity.caller, &policy)
            .map_err(application)?;
        if conn.names().namespace().is_none()
            && ((fresh && schema.statements.len() > crate::bootstrap::STEP) || interrupted)
        {
            crate::bootstrap::install(
                &conn,
                &expected,
                crate::bootstrap::domain_statements(&conn, identity, &app, &config)?,
            )
            .await?;
            crate::writer::configure(&conn, options.durability).await?;
            tables = rows(&conn, "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").await?;
            fresh = false;
        }
        let context = rocky_core::AdmissionContext {
            scope: identity.scope,
            caller: identity.caller,
            policy_version: app.policy_version(&policy),
            boundary: AdmissionBoundary::Local,
        };
        let plan = Arc::new(ReadPlan::compile(
            conn.names(),
            app.read_views(context, &policy).map_err(application)?,
        )?);
        let (views, view_changes): (Vec<_>, Vec<_>) =
            (0..plan.views()).map(|_| watch::channel(0u64)).unzip();
        let (meta, meta_changes) = watch::channel(0u64);
        let retention = retention::Retention::new(&conn, &app, options.retention)?;
        let marker = conn
            .names()
            .physical("rocky_checkpoint")
            .unwrap_or("rocky_checkpoint")
            .to_string();
        let reads = Arc::new(Reads::new(
            identity.scope,
            plan.clone(),
            pool,
            view_changes,
            meta_changes,
            retention.row_audit(marker),
        ));
        let observed: Vec<String> = match app.logical_schema() {
            Some(logical) => logical
                .tables
                .iter()
                .map(|table| table.sql_name.clone())
                .collect(),
            None => crate::scoped_connection::tables(&schema.statements)
                .into_iter()
                .map(|(table, _)| table)
                .filter(|table| !table.to_ascii_lowercase().starts_with("rocky_"))
                .collect(),
        };
        let events = crate::observe::TableEvents::new(identity.scope, observed);
        reads.bind_events(&events);
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        let initialization = async {
            if fresh {
                for sql in storage::SCHEMA {
                    conn.execute(*sql, ()).await?;
                }
                for sql in &schema.statements {
                    conn.execute(sql, ()).await?;
                }
                conn.execute(
                    "INSERT INTO rocky_replica VALUES(1,?,0,0,0)",
                    [crate::sqlite::Value::Blob(expected)],
                )
                .await?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = initialization {
            return finish(&conn, Err(error)).await;
        }
        let mut worker = Self {
            writer: conn,
            reader: None,
            reading: false,
            unbounded: false,
            in_group: false,
            instrument: options.instrument,
            metrics,
            unpublished: Unpublished::default(),
            // Open-time work may be buffered until the writer's first flush.
            dirty: true,
            flushed_sequence: 0,
            schema,
            app,
            policy,
            identity,
            config,
            plan,
            reads,
            targets: Default::default(),
            events,
            retention,
            retained: 0,
            retained_bytes: 0,
            frontier: BTreeMap::new(),
            sequence: 0,
            lamport: 0,
            revision: LocalRevision::default(),
            revisions: notifications.revisions,
            changes: notifications.changes,
            views,
            meta,
            #[cfg(test)]
            fault: None,
        };
        let migration = async {
            crate::schema_evolution::apply(worker.conn(), &worker.app).await?;
            if let Some(schema) = worker.app.logical_schema() {
                crate::logical::bind(worker.conn(), schema).await?;
                worker.reads.bind_logical(schema.clone());
            }
            if fresh {
                worker.conn().execute(storage::PEER_SCHEMA, ()).await?;
            } else {
                for table in ["rocky_mutation_handles", "rocky_peer_ack"] {
                    if !tables.contains(&vec![SqlValue::Text(table.into())]) {
                        return Err(Error::Corrupt(format!("missing storage table {table}")));
                    }
                }
            }
            if fresh {
                worker.conn().execute(storage::UNAPPLIED_INDEX, ()).await?;
            }
            if fresh {
                for sql in retention::SCHEMA {
                    worker.conn().execute(*sql, ()).await?;
                }
                worker.install_retention().await?;
            } else {
                for table in crate::scoped_connection::tables(retention::SCHEMA)
                    .into_iter()
                    .map(|(table, _)| table)
                {
                    if !tables.contains(&vec![SqlValue::Text(table.clone())]) {
                        return Err(Error::Corrupt(format!("missing storage table {table}")));
                    }
                }
            }
            Ok(())
        }
        .await;
        finish(worker.conn(), migration).await?;
        worker
            .transaction(async |worker| worker.restore(true).await)
            .await?;
        if let Err(error) = worker.process_pending().await
            && !matches!(error, Error::Rejected(_))
        {
            return Err(error);
        }
        worker.revisions.send_replace(worker.revision);
        worker.publish();
        Ok(worker)
    }
    /// The connection for the current step: the file's write connection, or
    /// the read-only connection inside `read_transaction`.
    pub(super) fn conn(&self) -> &ScopedConnection {
        match (&self.reader, self.reading) {
            (Some(reader), true) => reader,
            _ => &self.writer,
        }
    }
    /// Serve requests that write nothing from `reader`, a read-only connection.
    pub(crate) fn attach_reader(&mut self, reader: Arc<crate::sqlite::Connection>) {
        self.retention.attach_reader(reader.clone());
        self.reader = Some(self.writer.with_connection(reader));
    }
    /// The domain's read side, handed to its `Replica` once it is open.
    pub(crate) fn reads(&self) -> Arc<Reads> {
        self.reads.clone()
    }
    /// Releases notifications held back while the group was open.
    pub(crate) fn publish(&mut self) {
        let pending = std::mem::take(&mut self.unpublished);
        if pending.revision {
            self.revisions.send_replace(self.revision);
        }
        if pending.changes {
            self.changes
                .send_modify(|generation| *generation = generation.wrapping_add(1));
        }
        pending.views.publish(&self.views);
        if pending.views.any() {
            let causes: Vec<_> = pending.causes.iter().copied().collect();
            self.events
                .publish(pending.views.tables(), self.revision.get(), &causes);
        }
        if pending.meta {
            self.meta
                .send_modify(|generation| *generation = generation.wrapping_add(1));
        }
    }
    pub(crate) fn dirty(&self) -> bool {
        self.dirty
    }
    /// A group touching this domain committed without a flush.
    pub(crate) fn buffered(&mut self) {
        self.dirty = true;
    }
    /// A flush covered everything committed so far.
    pub(crate) fn flushed(&mut self) {
        self.dirty = false;
        self.flushed_sequence = self.sequence;
        self.retention.flushed();
    }
    fn class(&self, operation: &Envelope) -> crate::CommitClass {
        if operation.id.sequence.get() <= self.flushed_sequence {
            crate::CommitClass::Flushed
        } else {
            crate::CommitClass::Buffered
        }
    }
    fn notify(&mut self, revision: bool) {
        self.unpublished.revision |= revision;
        self.unpublished.changes = true;
    }
    /// After a group failed to commit: drop held notifications and reread the
    /// counters from storage, so nothing the group adopted survives.
    pub(crate) async fn recover(&mut self) -> Result<(), Error> {
        self.unpublished = Unpublished::default();
        self.transaction(async |worker| worker.restore(false).await)
            .await
    }
    /// Drops the domain except its notification senders, which the file
    /// writer releases after the file itself is closed.
    pub(crate) fn into_notifications(self) -> Notifications {
        Notifications {
            revisions: self.revisions,
            changes: self.changes,
        }
    }
    /// One step of the file writer's group. The answer is held until the
    /// group commits.
    pub(crate) async fn step(&mut self, command: Command<A::Row>) -> Box<dyn Answer> {
        match command {
            Command::Mutate(handle, mutation, baseline, reply) => {
                let result = self.mutate(handle, mutation, baseline).await;
                let result = result.map(|operation| {
                    let class = self.class(&operation);
                    crate::CommittedMutation { operation, class }
                });
                Box::new(crate::writer::Committing { reply, result })
            }
            Command::Sync(request, reply) => {
                let result = self.sync(request).await;
                if result.is_ok() {
                    self.notify(false);
                    self.unpublished.meta = true;
                }
                Box::new(Answered { reply, result })
            }
            Command::Retention(request, reply) => {
                let result = self.retention(*request).await;
                Box::new(Answered { reply, result })
            }
            other => {
                self.read(other).await;
                Box::new(crate::writer::Unanswered)
            }
        }
    }
    /// A request that writes nothing, answered at once on the read connection.
    pub(crate) async fn read(&mut self, command: Command<A::Row>) {
        match command {
            Command::Query(reply) => {
                let _ = reply.send(self.query().await);
            }
            Command::LookupMutation(handle, reply) => {
                let result = self
                    .read_transaction(async |worker| worker.lookup_mutation(handle).await)
                    .await;
                let result = result.and_then(|result| match result {
                    Some((_, operation)) => operation.map(|operation| {
                        Some(crate::CommittedMutation {
                            class: self.class(&operation),
                            operation,
                        })
                    }),
                    None => Ok(None),
                });
                let _ = reply.send(result);
            }
            // Served only once the domain is clean; see `crate::writer`.
            Command::Flush(reply) => {
                let _ = reply.send(Ok(()));
            }
            Command::Sync(request, reply) => {
                let _ = reply.send(self.sync(request).await);
            }
            Command::Retention(request, reply) => {
                let _ = reply.send(self.retention(*request).await);
            }
            other => other.refuse(Error::Closed),
        }
    }
    fn admission_context(
        &self,
        op: &Envelope,
        boundary: AdmissionBoundary,
    ) -> rocky_core::AdmissionContext {
        rocky_core::AdmissionContext {
            scope: op.scope,
            caller: op.caller,
            policy_version: self.app.policy_version(&self.policy),
            boundary,
        }
    }
    /// Runs `body` as one step that writes. Inside the file writer's group it
    /// gets its own savepoint, so a failure rolls back alone and the rest of
    /// the group still commits. Outside a group, at open, it is one
    /// `BEGIN IMMEDIATE` transaction. Either way a busy engine reruns the whole
    /// step. `body` must leave memory unchanged until it has returned: callers
    /// adopt its result afterwards.
    pub(super) async fn transaction<T>(
        &mut self,
        mut body: impl AsyncFnMut(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if !self.in_group {
            return self.standalone(body).await;
        }
        for _ in 0..storage::TRANSACTION_ATTEMPTS {
            if self.conn().is_autocommit()? {
                return Err(storage::group_lost());
            }
            self.conn().execute("SAVEPOINT step", ()).await?;
            self.retention.begin_step()?;
            let result = match body(self).await {
                Ok(value) => match self.settle().await {
                    Ok(digests) => match self.conn().execute("RELEASE step", ()).await {
                        Ok(_) => {
                            self.adopt_digests(digests);
                            return Ok(value);
                        }
                        Err(error) => Err(Error::from(error)),
                    },
                    Err(error) => Err(error),
                },
                Err(error) => Err(error),
            };
            if self.conn().is_autocommit()? {
                // The engine ended the whole group, for example on a full disk.
                return Err(result.err().unwrap_or_else(storage::group_lost));
            }
            let rolled_back = match self.conn().execute("ROLLBACK TO step", ()).await {
                Ok(_) => self.conn().execute("RELEASE step", ()).await,
                Err(error) => Err(error),
            };
            if let Err(rollback) = rolled_back {
                return Err(Error::Rollback {
                    cause: result.err().map(|e| e.to_string()).unwrap_or_default(),
                    rollback: rollback.into(),
                });
            }
            match result {
                // Inside a held write lock only an injected fault is busy.
                Err(error) if retryable(&error) => {}
                result => return result,
            }
        }
        Err(Error::RetryExhausted)
    }
    async fn standalone<T>(
        &mut self,
        mut body: impl AsyncFnMut(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        for attempt in 0..storage::TRANSACTION_ATTEMPTS {
            let result = match self.conn().execute("BEGIN IMMEDIATE", ()).await {
                Ok(_) => {
                    let result = match self.retention.begin_step() {
                        Ok(()) => match body(self).await {
                            Ok(value) => self.settle().await.map(|digests| (value, digests)),
                            Err(error) => Err(error),
                        },
                        Err(error) => Err(error),
                    };
                    finish(self.conn(), result).await
                }
                Err(error) => Err(Error::from(error)),
            };
            match result {
                Err(error) if retryable(&error) => {
                    if attempt + 1 < storage::TRANSACTION_ATTEMPTS {
                        tokio::time::sleep(storage::backoff(attempt)).await;
                    }
                }
                Ok((value, digests)) => {
                    self.adopt_digests(digests);
                    return Ok(value);
                }
                Err(error) => return Err(error),
            }
        }
        Err(Error::RetryExhausted)
    }
    /// Runs `body` in one bounded read transaction on the read-only
    /// connection, never inside the writer's group. The file writer runs reads
    /// between groups, so memory then equals the committed state; `body`
    /// checks that against the stored revision.
    pub(super) async fn read_transaction<T>(
        &mut self,
        mut body: impl AsyncFnMut(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if self.reader.is_none() {
            return self.standalone(body).await;
        }
        for attempt in 0..storage::TRANSACTION_ATTEMPTS {
            self.reading = true;
            let deadline = (!self.unbounded)
                .then(|| std::time::Instant::now() + storage::READ_TRANSACTION_BOUND);
            let result = match self.conn().connection().set_deadline(deadline) {
                Ok(()) => match self.conn().execute("BEGIN", ()).await {
                    Ok(_) => {
                        let result = body(self).await;
                        finish(self.conn(), result).await
                    }
                    Err(error) => Err(Error::from(error)),
                },
                Err(error) => Err(Error::from(error)),
            };
            let cleared = self.conn().connection().set_deadline(None);
            self.reading = false;
            cleared?;
            match result {
                Err(error) if retryable(&error) => {
                    if attempt + 1 < storage::TRANSACTION_ATTEMPTS {
                        tokio::time::sleep(storage::backoff(attempt)).await;
                    }
                }
                result => return result,
            }
        }
        Err(Error::RetryExhausted)
    }
    /// The committed revision in the current read transaction. Memory must be
    /// at the same revision, or a reply would mix two states.
    pub(super) async fn committed_revision(&self) -> Result<LocalRevision, Error> {
        let metadata = rows(self.conn(), "SELECT revision FROM rocky_replica WHERE id=1").await?;
        let Some([SqlValue::Integer(revision)]) = metadata.first().map(Vec::as_slice) else {
            return Err(Error::Corrupt("missing revision".into()));
        };
        let revision = LocalRevision::new(*revision as u64)?;
        if revision != self.revision {
            return Err(Error::Corrupt(
                "applied memory differs from the committed revision".into(),
            ));
        }
        Ok(revision)
    }
    async fn query(&mut self) -> Result<Snapshot<A::Row>, Error> {
        self.app
            .admit_read(self.identity.scope, self.identity.caller, &self.policy)
            .map_err(application)?;
        self.read_transaction(async |worker| worker.snapshot().await)
            .await
    }
    async fn snapshot(&self) -> Result<Snapshot<A::Row>, Error> {
        {
            let revision = self.committed_revision().await?;
            let rows = self
                .app
                .decode_rows(rows(self.conn(), &self.schema.projection_query).await?)
                .map_err(application)?;
            let rows = self
                .app
                .select_rows(
                    rows,
                    rocky_core::AdmissionContext {
                        scope: self.identity.scope,
                        caller: self.identity.caller,
                        policy_version: self.app.policy_version(&self.policy),
                        boundary: AdmissionBoundary::Local,
                    },
                    &self.policy,
                )
                .map_err(application)?;
            Ok(Snapshot {
                rows,
                revision,
                frontier: self.applied_frontier(),
                query: crate::QueryIdentity {
                    scope: self.identity.scope,
                    name: self.app.definition(),
                },
            })
        }
    }
    /// The operation a handle committed. A handle whose operation is behind
    /// the pruned_prefix reports `Pruned`: it was committed and must not run again.
    async fn lookup_mutation(
        &self,
        handle: crate::MutationHandle,
    ) -> Result<Option<(rocky_core::Commitment, Result<Envelope, Error>)>, Error> {
        let mut records = self
            .conn()
            .query(
                "SELECT request_hash,node,sequence FROM rocky_mutation_handles WHERE handle=?",
                [handle.0.to_vec()],
            )
            .await?;
        let Some(row) = records.next().await? else {
            return Ok(None);
        };
        let hash: rocky_core::Commitment = row
            .get::<Vec<u8>>(0)?
            .as_slice()
            .try_into()
            .map_err(|_| Error::Corrupt("mutation handle".into()))?;
        let id = incoming::operation_id(&row.get::<Vec<u8>>(1)?, row.get(2)?)?;
        Ok(Some((
            hash,
            match self.record(id).await? {
                Some((bytes, _)) if !self.retention.below_pruned_prefix(id) => {
                    Ok(Envelope::decode(&bytes)?)
                }
                _ => Err(Error::Pruned {
                    node: id.node,
                    sequence: id.sequence.get(),
                }),
            },
        )))
    }
    pub(super) fn applied_frontier(&self) -> rocky_core::AppliedFrontier {
        rocky_core::AppliedFrontier(
            self.frontier
                .iter()
                .map(|(node, sequence)| (*node, *sequence))
                .collect(),
        )
    }
    /// Retained history is bounded by bytes. At the bound nothing more is
    /// accepted until a checkpoint and pruning release history.
    fn operation_budget(&self, bytes: usize) -> Result<(), Error> {
        let limit = self.retention.policy.retained_bytes;
        if self
            .retained_bytes
            .saturating_add(bytes)
            .saturating_add(RECORD_OVERHEAD)
            > limit
        {
            return Err(Error::Retention {
                retained: self.retained_bytes,
                limit,
            });
        }
        Ok(())
    }
    /// The stored rows `op` touches, as the reducer's state.
    pub(super) async fn window(&self, op: &Envelope) -> Result<A::State, Error> {
        let mut loaded = Vec::new();
        for statement in self.app.touched(op) {
            loaded.extend(
                storage::collect_rows(
                    self.conn()
                        .query(&statement.sql, bindings(statement.values))
                        .await?,
                )
                .await?,
            );
        }
        self.app.window(loaded).map_err(application)
    }
    /// Runs the reducer and candidate admission on the rows `op` touches and
    /// returns the statements that store its result. Writes nothing.
    pub(super) async fn transition(
        &self,
        op: &Envelope,
        boundary: AdmissionBoundary,
    ) -> Result<Result<Vec<ProjectionStatement>, A::Error>, Error> {
        // Reduction: loading the touched rows and running the reducer.
        let reduce_started = Instant::now();
        let before = self.window(op).await?;
        if self.retention.below_pruned_prefix(op.entity) && self.app.definite_drop(&before, op) {
            return Ok(self
                .app
                .admit_candidate(
                    &before,
                    &before,
                    op,
                    self.admission_context(op, boundary),
                    &self.policy,
                )
                .map(|()| Vec::new()));
        }
        let mut after = before.clone();
        let reduced = self.app.apply_ready(&mut after, op, boundary);
        if self.instrument {
            self.metrics.add_reduction(nanos(reduce_started));
        }
        // Admission: the candidate check against the before/after state.
        let admit_started = Instant::now();
        let admitted = reduced.and_then(|()| {
            self.app.admit_candidate(
                &before,
                &after,
                op,
                self.admission_context(op, boundary),
                &self.policy,
            )
        });
        if self.instrument {
            self.metrics.add_admission(nanos(admit_started));
        }
        // Encoding: projecting the resulting statements.
        let project_started = Instant::now();
        let projected = admitted.map(|()| self.app.project(&after, op));
        if self.instrument {
            self.metrics.add_encoding(nanos(project_started));
        }
        Ok(projected)
    }
    /// Executes projection statements and reports the views they changed.
    pub(super) async fn store(
        &mut self,
        statements: Vec<ProjectionStatement>,
    ) -> Result<Changed, Error> {
        let mut changed = Changed::default();
        for statement in statements {
            // An installation has few distinct statements: parse each once.
            if !self.targets.contains_key(statement.sql.as_ref()) {
                if self.targets.len() >= MAX_STATEMENT_TARGETS {
                    self.targets.clear();
                }
                let target = crate::read::written_table(&statement.sql)
                    .map(|table| (table.clone(), self.plan.reading(&table).collect()));
                self.targets.insert(statement.sql.as_ref().into(), target);
            }
            match self.targets.get(statement.sql.as_ref()) {
                Some(Some((table, views))) => {
                    changed.record(Some(views));
                    changed.table(table);
                }
                _ => changed.record(None),
            }
            self.conn()
                .execute(&statement.sql, bindings(statement.values))
                .await?;
        }
        Ok(changed)
    }
    /// Validate against stored rows without writing. Err is a committed retry.
    async fn prepare(
        &self,
        handle: crate::MutationHandle,
        mutation: &Mutation,
        baseline: Option<LocalRevision>,
    ) -> Result<Result<Prepared, Envelope>, Error> {
        let request_hash = crate::mutation_hash(&mutation.payload, mutation.entity);
        if let Some((old, operation)) = self.lookup_mutation(handle).await? {
            if old != request_hash {
                return Err(Error::Conflict);
            }
            return operation.map(Err);
        }
        if baseline.is_some_and(|revision| revision != self.revision) {
            return Err(Error::Conflict);
        }
        let sequence = AuthorSequence::new(
            self.sequence
                .checked_add(1)
                .ok_or(rocky_core::ProtocolError::InvalidCounter)?,
        )?;
        let id = OperationId {
            node: self.identity.node,
            sequence,
        };
        let entity = mutation.entity.unwrap_or(id);
        let op = Envelope {
            scope: self.identity.scope,
            caller: self.identity.caller,
            versions: self.app.descriptor().operations,
            id,
            lamport: LamportTime::new(
                self.lamport
                    .checked_add(1)
                    .ok_or(rocky_core::ProtocolError::InvalidCounter)?,
            )?,
            entity,
            dependencies: required_dependencies(id, entity, mutation.entity.is_none())?,
            payload: mutation.payload.clone(),
        };
        let encode_started = Instant::now();
        let bytes = op.encode()?;
        if self.instrument {
            self.metrics.add_encoding(nanos(encode_started));
        }
        self.operation_budget(bytes.len())?;
        let admit_started = Instant::now();
        self.app.validate(&op).map_err(application)?;
        self.app.admit(&op, &self.policy).map_err(application)?;
        if self.instrument {
            self.metrics.add_admission(nanos(admit_started));
        }
        let ready_started = Instant::now();
        let ready = self.readiness(&op).await?;
        if self.instrument {
            self.metrics.add_reduction(nanos(ready_started));
        }
        if !matches!(ready, incoming::Readiness::Ready) {
            return Err(Error::Protocol(rocky_core::ProtocolError::NotReady(
                op.dependencies.clone(),
            )));
        }
        let statements = self
            .transition(&op, AdmissionBoundary::Local)
            .await?
            .map_err(application)?;
        let revision = self.revision.next()?;
        Ok(Ok(Prepared {
            handle,
            request_hash,
            op,
            bytes,
            statements,
            revision,
        }))
    }
    /// Advance the counters to a written operation; notifications follow the commit.
    fn adopt(&mut self, op: &Envelope, bytes: usize, revision: LocalRevision) {
        self.retained += 1;
        self.retained_bytes = self
            .retained_bytes
            .saturating_add(bytes)
            .saturating_add(RECORD_OVERHEAD);
        self.frontier.insert(op.id.node, op.id.sequence);
        self.sequence = op.id.sequence.get();
        self.lamport = op.lamport.get();
        self.revision = revision;
    }
    async fn mutate(
        &mut self,
        handle: crate::MutationHandle,
        mutation: Mutation,
        baseline: Option<LocalRevision>,
    ) -> Result<Envelope, Error> {
        // Preparation writes nothing, so a retried attempt recomputes it in its own snapshot.
        let outcome = self
            .transaction(async |worker| {
                Ok(match worker.prepare(handle, &mutation, baseline).await? {
                    Ok(prepared) => {
                        let Prepared {
                            handle,
                            request_hash,
                            op,
                            bytes,
                            statements,
                            revision,
                        } = prepared;
                        let changed = worker
                            .write_mutation(handle, request_hash, &op, &bytes, statements, revision)
                            .await?;
                        Ok((op, bytes.len(), revision, changed))
                    }
                    Err(committed) => Err(committed),
                })
            })
            .await?;
        match outcome {
            Ok((op, bytes, revision, changed)) => {
                self.adopt(&op, bytes, revision);
                self.unpublished
                    .changed(changed, crate::observe::Cause::Local);
                self.notify(true);
                self.process_following().await?;
                Ok(op)
            }
            Err(committed) => Ok(committed),
        }
    }
    pub(super) async fn process_following(&mut self) -> Result<bool, Error> {
        let mut loaded = Vec::new();
        for query in self.app.following_queries(self.identity.node) {
            loaded.extend(
                storage::collect_rows(
                    self.conn()
                        .query(&query.sql, bindings(query.values))
                        .await?,
                )
                .await?,
            );
        }
        let follows = self
            .app
            .following_intents(loaded, self.identity.node)
            .map_err(application)?;
        let mut changed = false;
        for follow in follows {
            if follow.original.node != self.identity.node
                || self.retention.below_pruned_prefix(follow.original)
            {
                continue;
            }
            let mutation = Mutation {
                entity: follow.intent.entity,
                payload: follow.intent.payload,
            };
            let result = self
                .transaction(async |worker| {
                    match worker
                        .prepare(crate::MutationHandle(follow.handle), &mutation, None)
                        .await?
                    {
                        Ok(prepared) => {
                            let changed = worker
                                .write_mutation(
                                    prepared.handle,
                                    prepared.request_hash,
                                    &prepared.op,
                                    &prepared.bytes,
                                    prepared.statements,
                                    prepared.revision,
                                )
                                .await?;
                            Ok(Some((
                                prepared.op,
                                prepared.bytes.len(),
                                prepared.revision,
                                changed,
                            )))
                        }
                        Err(_) => Ok(None),
                    }
                })
                .await?;
            if let Some((op, bytes, revision, views)) = result {
                self.adopt(&op, bytes, revision);
                self.unpublished
                    .changed(views, crate::observe::Cause::Local);
                self.notify(true);
                changed = true;
            }
        }
        Ok(changed)
    }
    /// Statements for one prepared mutation inside the caller's transaction.
    async fn write_mutation(
        &mut self,
        handle: crate::MutationHandle,
        request_hash: rocky_core::Commitment,
        op: &Envelope,
        bytes: &[u8],
        statements: Vec<ProjectionStatement>,
        revision: LocalRevision,
    ) -> Result<Changed, Error> {
        let sql_started = Instant::now();
        let changed = self
            .write_operation(handle, request_hash, op, bytes, statements)
            .await?;
        self.write_counters(op.id.sequence.get(), op.lamport.get(), revision)
            .await?;
        if self.instrument {
            self.metrics.add_sql(nanos(sql_started));
        }
        self.inject_fault().await?;
        Ok(changed)
    }
    /// One local operation: its record, handle, projection and outbox entry.
    async fn write_operation(
        &mut self,
        handle: crate::MutationHandle,
        request_hash: rocky_core::Commitment,
        op: &Envelope,
        bytes: &[u8],
        statements: Vec<ProjectionStatement>,
    ) -> Result<Changed, Error> {
        self.conn()
            .execute(
                "INSERT INTO rocky_operations VALUES(?,?,?,?,'applied','local')",
                crate::sqlite::params![
                    op.id.node.0.to_vec(),
                    op.id.sequence.get() as i64,
                    bytes.to_vec(),
                    op.lamport.get() as i64
                ],
            )
            .await?;
        self.conn()
            .execute(
                "INSERT INTO rocky_mutation_handles VALUES(?,?,?,?)",
                crate::sqlite::params![
                    handle.0.to_vec(),
                    request_hash.to_vec(),
                    op.id.node.0.to_vec(),
                    op.id.sequence.get() as i64
                ],
            )
            .await?;
        let changed = self.store(statements).await?;
        if !self.config.delivery_targets.is_empty() {
            self.conn()
                .execute(
                    "INSERT INTO rocky_outbox VALUES(?,?)",
                    crate::sqlite::params![op.id.node.0.to_vec(), op.id.sequence.get() as i64],
                )
                .await?;
        }
        Ok(changed)
    }
    async fn write_counters(
        &self,
        sequence: u64,
        lamport: u64,
        revision: LocalRevision,
    ) -> Result<(), Error> {
        self.conn()
            .execute(
                "UPDATE rocky_replica SET sequence=?,lamport=?,revision=? WHERE id=1",
                (sequence as i64, lamport as i64, revision.get() as i64),
            )
            .await?;
        Ok(())
    }
}
struct Prepared {
    handle: crate::MutationHandle,
    request_hash: rocky_core::Commitment,
    op: Envelope,
    bytes: Vec<u8>,
    statements: Vec<ProjectionStatement>,
    revision: LocalRevision,
}
