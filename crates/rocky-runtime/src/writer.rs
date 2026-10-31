//! One writer per file. A single thread owns the file's only write connection
//! and every domain's worker in the file; the writes waiting across those
//! domains commit in one transaction. Each step runs in its own savepoint,
//! and nothing is published before the group's `COMMIT` returns.
//!
//! Groups commit at `synchronous=NORMAL` unless `Durability::Full` is set. A
//! group that commits at FULL is a flush and advances the file's durable
//! watermark. Nothing leaves the device above that watermark: a request whose
//! reply is exposed (`Command::exposes`) waits until its domain is clean, and
//! the writer then flushes once for every waiting exposure.
use crate::{
    Command, Durability, QueuedCommand, Reply, RuntimeOptions,
    database::DatabaseOwner,
    scoped_connection::ScopedConnection,
    sqlite,
    storage::{self, Error, retryable, rows},
    worker::{Notifications, Worker},
};
use rocky_core::{SqlValue, StoredApplication};
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    task::Poll,
    time::Instant,
};
use tokio::sync::mpsc;

/// Queue bytes one group may hold. With `RuntimeOptions::group_commit` this
/// bounds the work and memory between two commits.
pub(crate) const MAX_GROUP_BYTES: usize = 4 * crate::MAX_FRAME_BYTES;
/// Default of `RuntimeOptions::checkpoint_frames`: WAL frames (32 MiB at
/// 4 KiB pages) after which the writer runs a passive checkpoint between
/// groups. A mutation logs tens of KiB, so a 4 MiB bound halved buffered
/// throughput. A checkpoint holds the writer for 25 to 160 ms, longer as
/// the file grows, so a larger bound trades WAL size for fewer stalls.
pub(crate) const CHECKPOINT_FRAMES: u32 = 8_192;
/// Bytes the WAL file is cut back to whenever a checkpoint resets it.
const WAL_SIZE_LIMIT: i64 = 4 * 1024 * 1024;
/// The writer's page cache, negative as SQLite counts KiB.
#[cfg(target_os = "android")]
const WRITER_CACHE_KIB: i64 = -8 * 1024;
#[cfg(not(target_os = "android"))]
const WRITER_CACHE_KIB: i64 = -32 * 1024;
/// Longest wait of a resetting checkpoint for readers of the old log.
const RESET_WAIT: std::time::Duration = std::time::Duration::from_millis(50);

/// What one file writer has done since open. Times are microseconds on the
/// writer thread; whatever is left of wall time was spent idle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriterStats {
    /// Committed groups and the writing steps they held.
    pub groups: u64,
    pub steps: u64,
    /// Commits that were a full device flush.
    pub flushes: u64,
    /// Admission, reduction, encoding and statements of the steps.
    pub step_micros: u64,
    /// `COMMIT`, including the flush where the group had one.
    pub commit_micros: u64,
    /// Requests answered outside groups, on the writer thread.
    pub read_micros: u64,
    /// Mutation step subphases, collected only when `RuntimeOptions::instrument`
    /// is set; zero otherwise. `admission` is application validation and
    /// candidate admission; `reduction` reads the reducer's rows and applies
    /// the transition; `encoding` serializes the operation and projects its
    /// statements; `sql` executes every SQLite statement of the write.
    pub admission_micros: u64,
    pub reduction_micros: u64,
    pub encoding_micros: u64,
    pub sql_micros: u64,
    /// Writer step time split by the kind of request that ran, collected only
    /// when `RuntimeOptions::instrument` is set. `authoring` counts local
    /// mutations; `incoming` counts page receipts and pending application; the
    /// rest of `step_micros` is strong commands, retention and other writes.
    pub authoring_steps: u64,
    pub incoming_steps: u64,
    pub authoring_step_micros: u64,
    pub incoming_step_micros: u64,
    /// WAL checkpoints run between groups, and how long they held the writer.
    pub checkpoints: u64,
    pub checkpoint_micros: u64,
    pub checkpoint_max_micros: u64,
    /// Of the passive checkpoints: the flush of the WAL before the copy,
    /// copying pages into the database file, and its flush after.
    pub checkpoint_wal_flush_micros: u64,
    pub checkpoint_copy_micros: u64,
    pub checkpoint_flush_micros: u64,
    /// Truncating checkpoints, included above, and their time.
    pub truncations: u64,
    pub truncate_micros: u64,
    /// WAL frames after the latest commit, and the most seen.
    pub wal_frames: u64,
    pub wal_frames_max: u64,
}
/// The kind of request a writer step ran, for `WriterStats` attribution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StepKind {
    /// A local mutation authored through this runtime.
    Authoring,
    /// A page receipt or pending application from a peer.
    Incoming,
    /// Strong commands, retention and other writes.
    Other,
}
#[derive(Default)]
pub(crate) struct Metrics {
    groups: AtomicU64,
    steps: AtomicU64,
    flushes: AtomicU64,
    step_micros: AtomicU64,
    commit_micros: AtomicU64,
    read_micros: AtomicU64,
    admission_nanos: AtomicU64,
    reduction_nanos: AtomicU64,
    encoding_nanos: AtomicU64,
    sql_nanos: AtomicU64,
    authoring_steps: AtomicU64,
    incoming_steps: AtomicU64,
    authoring_step_micros: AtomicU64,
    incoming_step_micros: AtomicU64,
    checkpoints: AtomicU64,
    checkpoint_micros: AtomicU64,
    checkpoint_max_micros: AtomicU64,
    checkpoint_wal_flush_micros: AtomicU64,
    checkpoint_copy_micros: AtomicU64,
    checkpoint_flush_micros: AtomicU64,
    truncations: AtomicU64,
    truncate_micros: AtomicU64,
    wal_frames: AtomicU64,
    wal_frames_max: AtomicU64,
    /// Bounded record of the most recent checkpoint intervals, plus how many
    /// intervals were dropped once the bound filled.
    checkpoint_log: std::sync::Mutex<CheckpointLog>,
}
/// Upper bound on retained checkpoint intervals; older ones are dropped and
/// counted so callers know the log is truncated.
pub(crate) const MAX_CHECKPOINT_INTERVALS: usize = 4096;
#[derive(Default)]
struct CheckpointLog {
    intervals: VecDeque<CheckpointInterval>,
    dropped: u64,
}
impl Metrics {
    /// Accumulate the four mutation-step subphases from the worker thread.
    /// Nanoseconds are kept so a phase faster than a microsecond is not
    /// truncated to zero; the snapshot reports microseconds.
    pub(crate) fn add_admission(&self, nanos: u64) {
        self.admission_nanos.fetch_add(nanos, Relaxed);
    }
    pub(crate) fn add_reduction(&self, nanos: u64) {
        self.reduction_nanos.fetch_add(nanos, Relaxed);
    }
    pub(crate) fn add_encoding(&self, nanos: u64) {
        self.encoding_nanos.fetch_add(nanos, Relaxed);
    }
    pub(crate) fn add_sql(&self, nanos: u64) {
        self.sql_nanos.fetch_add(nanos, Relaxed);
    }
    /// Attribute one writer step to the kind of request it ran.
    pub(crate) fn add_step(&self, kind: StepKind, micros: u64) {
        match kind {
            StepKind::Authoring => {
                self.authoring_steps.fetch_add(1, Relaxed);
                self.authoring_step_micros.fetch_add(micros, Relaxed);
            }
            StepKind::Incoming => {
                self.incoming_steps.fetch_add(1, Relaxed);
                self.incoming_step_micros.fetch_add(micros, Relaxed);
            }
            StepKind::Other => {}
        }
    }
    pub(crate) fn snapshot(&self) -> WriterStats {
        WriterStats {
            groups: self.groups.load(Relaxed),
            steps: self.steps.load(Relaxed),
            flushes: self.flushes.load(Relaxed),
            step_micros: self.step_micros.load(Relaxed),
            commit_micros: self.commit_micros.load(Relaxed),
            read_micros: self.read_micros.load(Relaxed),
            admission_micros: self.admission_nanos.load(Relaxed) / 1_000,
            reduction_micros: self.reduction_nanos.load(Relaxed) / 1_000,
            encoding_micros: self.encoding_nanos.load(Relaxed) / 1_000,
            sql_micros: self.sql_nanos.load(Relaxed) / 1_000,
            authoring_steps: self.authoring_steps.load(Relaxed),
            incoming_steps: self.incoming_steps.load(Relaxed),
            authoring_step_micros: self.authoring_step_micros.load(Relaxed),
            incoming_step_micros: self.incoming_step_micros.load(Relaxed),
            checkpoints: self.checkpoints.load(Relaxed),
            checkpoint_micros: self.checkpoint_micros.load(Relaxed),
            checkpoint_max_micros: self.checkpoint_max_micros.load(Relaxed),
            checkpoint_wal_flush_micros: self.checkpoint_wal_flush_micros.load(Relaxed),
            checkpoint_copy_micros: self.checkpoint_copy_micros.load(Relaxed),
            checkpoint_flush_micros: self.checkpoint_flush_micros.load(Relaxed),
            truncations: self.truncations.load(Relaxed),
            truncate_micros: self.truncate_micros.load(Relaxed),
            wal_frames: self.wal_frames.load(Relaxed),
            wal_frames_max: self.wal_frames_max.load(Relaxed),
        }
    }
    /// Records one completed checkpoint interval, dropping the oldest when the
    /// bound is reached and counting it so callers know the log is truncated.
    pub(crate) fn record_checkpoint(&self, interval: CheckpointInterval) {
        let Ok(mut log) = self.checkpoint_log.lock() else {
            return;
        };
        if log.intervals.len() >= MAX_CHECKPOINT_INTERVALS {
            log.intervals.pop_front();
            log.dropped += 1;
        }
        log.intervals.push_back(interval);
    }
    /// The retained checkpoint intervals in completion order, and how many were
    /// dropped from the front of the log after it filled.
    pub(crate) fn checkpoint_intervals(&self) -> (Vec<CheckpointInterval>, u64) {
        let Ok(log) = self.checkpoint_log.lock() else {
            return (Vec::new(), 0);
        };
        (log.intervals.iter().copied().collect(), log.dropped)
    }
}
/// Which kind of WAL checkpoint an interval records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointKind {
    /// A `PASSIVE` checkpoint past `checkpoint_frames` frames.
    Passive,
    /// A resetting `TRUNCATE` checkpoint past twice `checkpoint_frames`.
    Truncate,
}
/// One WAL checkpoint with monotonic start/end timestamps, so a caller can
/// correlate individual write latencies with the checkpoints they overlapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointInterval {
    /// Monotonic clock when the checkpoint started.
    pub start: Instant,
    /// Monotonic clock when the checkpoint completed.
    pub end: Instant,
    pub kind: CheckpointKind,
    /// Time spent copying WAL pages into the database file.
    pub copy_micros: u64,
    /// Time spent flushing the database file to the device.
    pub flush_micros: u64,
}
pub(crate) fn micros(since: Instant) -> u64 {
    since.elapsed().as_micros() as u64
}
/// For subphases: whole-microsecond truncation would hide phases that run
/// faster than a microsecond on fast hardware.
pub(crate) fn nanos(since: Instant) -> u64 {
    since.elapsed().as_nanos() as u64
}

/// Sets and verifies durability and checkpoint pragmas on the write connection.
/// `fullfsync` is fixed here: SQLite refuses these inside a transaction.
pub(crate) async fn configure(
    conn: &ScopedConnection,
    durability: Durability,
) -> Result<(), Error> {
    let synchronous = durability.synchronous();
    let settings = [
        (
            "journal_mode",
            "wal".to_string(),
            SqlValue::Text("wal".into()),
        ),
        (
            "synchronous",
            synchronous.to_string(),
            SqlValue::Integer(synchronous),
        ),
        // Flushes and checkpoints reach the device, not only its cache.
        ("fullfsync", "1".to_string(), SqlValue::Integer(1)),
        (
            "checkpoint_fullfsync",
            "1".to_string(),
            SqlValue::Integer(1),
        ),
        // The writer checkpoints between groups instead; see `Writer::checkpoint`.
        ("wal_autocheckpoint", "0".to_string(), SqlValue::Integer(0)),
        (
            "cache_size",
            WRITER_CACHE_KIB.to_string(),
            SqlValue::Integer(WRITER_CACHE_KIB),
        ),
        (
            "journal_size_limit",
            WAL_SIZE_LIMIT.to_string(),
            SqlValue::Integer(WAL_SIZE_LIMIT),
        ),
    ];
    for (name, value, _) in &settings {
        rows(conn, &format!("PRAGMA {name}={value}")).await?;
    }
    for (name, _, expected) in settings {
        let sql = format!("PRAGMA {name}");
        if rows(conn, &sql).await? != vec![vec![expected]] {
            return Err(Error::Durability(sql));
        }
    }
    conn.connection().track_wal()?;
    Ok(())
}

/// A reply held until the group's outcome is known.
pub(crate) trait Answer {
    /// The step could not roll back; the connection state is unknown.
    fn fatal(&self) -> bool;
    /// `flushed`: the group's commit was a full flush.
    fn send(self: Box<Self>, flushed: bool);
    fn fail(self: Box<Self>, error: Error);
}
pub(crate) struct Answered<T> {
    pub(crate) reply: Reply<T>,
    pub(crate) result: Result<T, Error>,
}
impl<T> Answer for Answered<T> {
    fn fatal(&self) -> bool {
        matches!(self.result, Err(Error::Rollback { .. }))
    }
    fn send(self: Box<Self>, _: bool) {
        let _ = self.reply.send(self.result);
    }
    fn fail(self: Box<Self>, error: Error) {
        let _ = self.reply.send(Err(error));
    }
}
/// A mutation's reply, which reports the class its commit reached.
pub(crate) struct Committing {
    pub(crate) reply: Reply<crate::CommittedMutation>,
    pub(crate) result: Result<crate::CommittedMutation, Error>,
}
impl Answer for Committing {
    fn fatal(&self) -> bool {
        matches!(self.result, Err(Error::Rollback { .. }))
    }
    fn send(self: Box<Self>, flushed: bool) {
        let result = self.result.map(|mut committed| {
            if flushed {
                committed.class = crate::CommitClass::Flushed;
            }
            committed
        });
        let _ = self.reply.send(result);
    }
    fn fail(self: Box<Self>, error: Error) {
        let _ = self.reply.send(Err(error));
    }
}
/// A step that answered its caller itself.
pub(crate) struct Unanswered;
impl Answer for Unanswered {
    fn fatal(&self) -> bool {
        false
    }
    fn send(self: Box<Self>, _: bool) {}
    fn fail(self: Box<Self>, _: Error) {}
}

struct Slot<A: StoredApplication> {
    /// None once the domain is closed.
    worker: Option<Worker<A>>,
    receiver: mpsc::Receiver<QueuedCommand<A::Row>>,
    /// Taken from the queue but not yet run, in queue order.
    deferred: VecDeque<QueuedCommand<A::Row>>,
    /// The queue is closed and empty.
    drained: bool,
    closing: Option<Reply<()>>,
}
struct File {
    conn: Arc<sqlite::Connection>,
    _owner: DatabaseOwner,
    /// Read connections beside this writer; closed before the file is.
    pool: Arc<crate::read::ReadPool>,
}
pub(crate) struct Writer<A: StoredApplication> {
    slots: Vec<Slot<A>>,
    file: Option<File>,
    group: usize,
    cursor: usize,
    durability: Durability,
    /// An exposure waits for the next flush.
    flush_wanted: bool,
    /// Domains whose first deferred request waits for that flush.
    waiting: Vec<usize>,
    checkpoint_frames: i64,
    /// Whether subphase timing and checkpoint-interval recording are on.
    instrument: bool,
    metrics: Arc<Metrics>,
    #[cfg(test)]
    fault: Option<crate::worker::Fault>,
    #[cfg(test)]
    groups: Option<crate::worker::GroupLog>,
    /// Test hook: copy the file and its WAL here after every flush.
    #[cfg(test)]
    snapshots: Option<std::path::PathBuf>,
}
type Work<R> = (usize, QueuedCommand<R>);
/// A domain's worker and its command queue.
pub(crate) type Domain<A> = (
    Worker<A>,
    mpsc::Receiver<QueuedCommand<<A as StoredApplication>::Row>>,
);

impl<A> Writer<A>
where
    A: StoredApplication,
    A::State: Clone,
{
    pub(crate) fn new(
        owner: DatabaseOwner,
        conn: Arc<sqlite::Connection>,
        workers: Vec<Domain<A>>,
        options: RuntimeOptions,
        pool: Arc<crate::read::ReadPool>,
        metrics: Arc<Metrics>,
    ) -> Result<Self, Error> {
        // Opened after the write connection has put the file in WAL mode.
        let reader = Arc::new(owner.connect_read_only()?);
        pool.attach(owner.path().to_path_buf());
        reader.set_query_only()?;
        let slots = workers
            .into_iter()
            .map(|(mut worker, receiver)| {
                worker.attach_reader(reader.clone());
                Slot {
                    worker: Some(worker),
                    receiver,
                    deferred: VecDeque::new(),
                    drained: false,
                    closing: None,
                }
            })
            .collect();
        Ok(Self {
            slots,
            file: Some(File {
                conn,
                _owner: owner,
                pool,
            }),
            group: options.group_commit.max(1),
            cursor: 0,
            durability: options.durability,
            // What survived a restart may sit unflushed in the OS cache.
            flush_wanted: true,
            waiting: Vec::new(),
            checkpoint_frames: i64::from(options.checkpoint_frames),
            instrument: options.instrument,
            metrics,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            groups: None,
            #[cfg(test)]
            snapshots: None,
        })
    }
    pub(crate) async fn run(mut self) {
        // Whatever survived a restart may sit unflushed in the OS cache.
        let mut stopped = self.flush().await;
        while !stopped {
            self.retire().await;
            if self.slots.iter().all(|slot| slot.worker.is_none()) {
                break;
            }
            if self.slots.iter().all(|slot| slot.deferred.is_empty()) {
                self.wait().await;
            }
            let (group, exposing) = self.collect().await;
            if group.is_empty() {
                stopped = self.flush_wanted && self.flush().await;
                continue;
            }
            // The next group starts at the next domain.
            self.cursor = (self.cursor + 1) % self.slots.len();
            let full = exposing || self.flush_wanted || self.durability == Durability::Full;
            stopped = self.commit(group, full).await;
        }
        // After a fatal error: stop every domain; queued callers see `Closed`.
        let notifications: Vec<_> = self
            .slots
            .iter_mut()
            .filter_map(|slot| slot.worker.take())
            .map(Worker::into_notifications)
            .collect();
        self.close_file().await;
        drop(notifications);
    }
    /// Waits, without polling for more, until any domain has work.
    async fn wait(&mut self) {
        std::future::poll_fn(|context| {
            let mut ready = true;
            for slot in &mut self.slots {
                if slot.worker.is_none() || slot.drained {
                    continue;
                }
                match slot.receiver.poll_recv(context) {
                    Poll::Ready(Some(command)) => {
                        slot.deferred.push_back(command);
                        return Poll::Ready(());
                    }
                    Poll::Ready(None) => {
                        slot.drained = true;
                        return Poll::Ready(());
                    }
                    Poll::Pending => ready = false,
                }
            }
            if ready {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
    fn next(&mut self, index: usize) -> Option<QueuedCommand<A::Row>> {
        let slot = &mut self.slots[index];
        slot.worker.as_ref()?;
        if let Some(command) = slot.deferred.pop_front() {
            return Some(command);
        }
        if slot.drained {
            return None;
        }
        match slot.receiver.try_recv() {
            Ok(command) => Some(command),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                slot.drained = true;
                None
            }
            Err(mpsc::error::TryRecvError::Empty) => None,
        }
    }
    /// Takes what is already queued, one write per domain per pass, starting
    /// at a rotating domain, until the group is full. Never waits for more.
    /// A domain's requests that precede its first write run at once, outside
    /// the group; a later one waits for the commit so queue order holds.
    /// Also returns whether a write in the group exposes its reply, so the
    /// group must be a flush. An exposing request of a domain with buffered
    /// commits waits for the next flush instead.
    async fn collect(&mut self) -> (Vec<Work<A::Row>>, bool) {
        let count = self.slots.len();
        let start = self.cursor % count;
        let mut exposing = false;
        let mut group = Vec::new();
        let mut bytes = 0usize;
        let mut writing = vec![false; count];
        let mut done = vec![false; count];
        loop {
            let mut taken = false;
            for index in (0..count).map(|offset| (start + offset) % count) {
                while !done[index] {
                    let Some(queued) = self.next(index) else {
                        done[index] = true;
                        break;
                    };
                    if !queued.command.writes() {
                        if writing[index] {
                            self.slots[index].deferred.push_front(queued);
                            done[index] = true;
                        } else if queued.command.exposes() && self.dirty(index) {
                            self.slots[index].deferred.push_front(queued);
                            done[index] = true;
                            self.flush_wanted = true;
                            self.waiting.push(index);
                        } else {
                            let started = Instant::now();
                            self.serve(index, queued.command).await;
                            self.metrics.read_micros.fetch_add(micros(started), Relaxed);
                        }
                        continue;
                    }
                    let weight = queued._budget.num_permits();
                    if group.len() >= self.group
                        || (!group.is_empty() && bytes.saturating_add(weight) > MAX_GROUP_BYTES)
                    {
                        self.slots[index].deferred.push_front(queued);
                        return (group, exposing);
                    }
                    exposing |= queued.command.exposes();
                    bytes = bytes.saturating_add(weight);
                    writing[index] = true;
                    group.push((index, queued));
                    taken = true;
                    break;
                }
            }
            if !taken {
                return (group, exposing);
            }
        }
    }
    /// Reads, closes and test faults, which never join a group.
    async fn serve(&mut self, index: usize, command: Command<A::Row>) {
        let closing = self.slots[index].closing.is_some();
        match command {
            Command::Close(reply) if closing => drop(reply.send(Err(Error::Closed))),
            Command::Close(reply) => {
                // Work admitted before the close still runs.
                let slot = &mut self.slots[index];
                slot.receiver.close();
                slot.closing = Some(reply);
            }
            command @ Command::Query(_) if closing => command.refuse(Error::Closed),
            #[cfg(test)]
            Command::Fault(_, reply) if closing => drop(reply.send(Err(Error::Closed))),
            #[cfg(test)]
            Command::Fault(crate::worker::Fault::AbortInCheckpoint, reply) => {
                let _ = reply.send(Ok(()));
                self.abort_in_checkpoint().await;
            }
            #[cfg(test)]
            Command::Fault(crate::worker::Fault::RecordGroups(log), reply) => {
                self.groups = Some(log);
                let _ = reply.send(Ok(()));
            }
            #[cfg(test)]
            Command::Fault(crate::worker::Fault::SnapshotAtFlush(directory), reply) => {
                self.snapshots = Some(directory);
                let _ = reply.send(Ok(()));
            }
            #[cfg(test)]
            Command::Fault(crate::worker::Fault::CheckpointFrames(frames), reply) => {
                self.checkpoint_frames = frames;
                let _ = reply.send(Ok(()));
            }
            #[cfg(test)]
            Command::Fault(fault, reply) => {
                if fault.file_level() {
                    self.fault = Some(fault);
                } else if let Some(worker) = self.slots[index].worker.as_mut() {
                    worker.fault = Some(fault);
                }
                let _ = reply.send(Ok(()));
            }
            command => match self.slots[index].worker.as_mut() {
                Some(worker) => worker.read(command).await,
                None => command.refuse(Error::Closed),
            },
        }
    }
    fn dirty(&self, index: usize) -> bool {
        self.durability == Durability::Buffered
            && self.slots[index].worker.as_ref().is_some_and(Worker::dirty)
    }
    /// Groups that flush run at FULL; SQLite refuses the switch inside a
    /// transaction, so it happens between groups.
    async fn synchronous(&self, conn: &sqlite::Connection, full: bool) -> Result<(), Error> {
        if self.durability == Durability::Full {
            return Ok(());
        }
        let level = if full {
            2
        } else {
            self.durability.synchronous()
        };
        conn.execute(format!("PRAGMA synchronous={level}"), ())
            .await?;
        Ok(())
    }
    /// After a flush every domain of the file is at the watermark.
    fn flushed(&mut self) {
        self.flush_wanted = false;
        self.waiting.clear();
        for worker in self
            .slots
            .iter_mut()
            .filter_map(|slot| slot.worker.as_mut())
        {
            worker.flushed();
        }
        #[cfg(test)]
        self.snapshot();
    }
    /// A flush failed: the exposures waiting for it fail too.
    fn flush_failed(&mut self, error: &Error) {
        self.flush_wanted = false;
        for index in std::mem::take(&mut self.waiting) {
            if let Some(queued) = self.slots[index].deferred.pop_front() {
                queued.command.refuse(storage::group_error(error));
            }
        }
    }
    /// A flush with no group to carry it: one FULL commit that writes only
    /// the file header's counter. Returns true when the writer must stop.
    async fn flush(&mut self) -> bool {
        let Some(conn) = self.conn() else {
            return true;
        };
        let result = async {
            self.synchronous(&conn, true).await?;
            self.begin(&conn).await?;
            // A changed header page guarantees a WAL frame for the flush to sync.
            let written = async {
                let current = rows_raw(&conn, "PRAGMA user_version").await?;
                let next = match current.first().map(Vec::as_slice) {
                    Some([SqlValue::Integer(value)]) => (value + 1).rem_euclid(i64::from(i32::MAX)),
                    _ => 1,
                };
                conn.execute(format!("PRAGMA user_version={next}"), ())
                    .await?;
                Ok(())
            }
            .await;
            storage::finish_raw(&conn, written).await
        }
        .await;
        let restored = self.synchronous(&conn, false).await;
        match result.and(restored) {
            Ok(_) => {
                self.flushed();
                false
            }
            Err(error) => {
                self.flush_failed(&error);
                matches!(error, Error::Rollback { .. })
            }
        }
    }
    #[cfg(test)]
    fn snapshot(&self) {
        let (Some(directory), Some(file)) = (&self.snapshots, &self.file) else {
            return;
        };
        let path = file._owner.path();
        let mut wal = path.as_os_str().to_owned();
        wal.push("-wal");
        let name = path.file_name().unwrap_or_default();
        let mut saved_wal = name.to_owned();
        saved_wal.push("-wal");
        let _ = std::fs::create_dir_all(directory);
        let _ = std::fs::copy(path, directory.join(name));
        if std::fs::copy(&wal, directory.join(&saved_wal)).is_err() {
            let _ = std::fs::remove_file(directory.join(saved_wal));
        }
    }
    fn conn(&self) -> Option<Arc<sqlite::Connection>> {
        self.file.as_ref().map(|file| file.conn.clone())
    }
    /// `BEGIN IMMEDIATE`, retried with backoff while another connection or
    /// process holds the file. This writer is the only one in the process.
    async fn begin(&self, conn: &sqlite::Connection) -> Result<(), Error> {
        self.begin_as(conn, "BEGIN IMMEDIATE").await
    }
    async fn begin_as(&self, conn: &sqlite::Connection, begin: &str) -> Result<(), Error> {
        for attempt in 0..storage::TRANSACTION_ATTEMPTS {
            match conn.execute(begin, ()).await {
                Ok(_) => return Ok(()),
                Err(error) => {
                    let error = Error::from(error);
                    if !retryable(&error) {
                        return Err(error);
                    }
                    if attempt + 1 < storage::TRANSACTION_ATTEMPTS {
                        tokio::time::sleep(storage::backoff(attempt)).await;
                    }
                }
            }
        }
        Err(Error::RetryExhausted)
    }
    /// Runs one group; `full` makes its commit a flush. Returns true when
    /// the writer must stop.
    async fn commit(&mut self, group: Vec<Work<A::Row>>, full: bool) -> bool {
        let Some(conn) = self.conn() else {
            for (_, queued) in group {
                queued.command.refuse(Error::Closed);
            }
            return true;
        };
        if let Err(error) = self.synchronous(&conn, full).await {
            self.flush_failed(&error);
            fail(
                group
                    .into_iter()
                    .map(|(_, queued)| queued.command)
                    .collect(),
                error,
            );
            return false;
        }
        // Off by default: the step timer and kind match never run unless asked.
        let instrument = self.instrument;
        let metrics = self.metrics.clone();
        #[cfg(test)]
        let composition: Vec<_> = group
            .iter()
            .map(|(index, queued)| (*index, queued._budget.num_permits()))
            .collect();
        if let Err(error) = self.begin(&conn).await {
            let _ = self.synchronous(&conn, false).await;
            if full {
                self.flush_failed(&error);
            }
            fail(
                group
                    .into_iter()
                    .map(|(_, queued)| queued.command)
                    .collect(),
                error,
            );
            return false;
        }
        let started = Instant::now();
        let mut answers = Vec::new();
        let mut touched = vec![0usize; self.slots.len()];
        // Domains whose steps changed rows; the others committed nothing.
        let mut changed = vec![false; self.slots.len()];
        let mut failure = None;
        let mut fatal = false;
        let mut skipped = Vec::new();
        for (index, queued) in group {
            let Some(worker) = self.slots[index].worker.as_mut() else {
                queued.command.refuse(Error::Closed);
                continue;
            };
            if failure.is_some() {
                skipped.push(queued.command);
                continue;
            }
            touched[index] += 1;
            let before = conn.total_changes().ok();
            let timed = instrument.then(|| (queued.command.step_kind(), Instant::now()));
            worker.in_group = true;
            let answer = worker.step(queued.command).await;
            worker.in_group = false;
            if let Some((kind, step_started)) = timed {
                metrics.add_step(kind, micros(step_started));
            }
            // An unreadable counter counts as a change.
            changed[index] |= before.is_none() || before != conn.total_changes().ok();
            if answer.fatal() {
                fatal = true;
                failure = Some(Error::Corrupt("a step could not roll back".into()));
            } else if conn.is_autocommit().unwrap_or(true) {
                failure = Some(storage::group_lost());
            }
            // Queue budgets stay reserved until the caller is answered.
            answers.push((answer, queued._budget));
        }
        // Checkpoint and prune steps ride on the group of the domains it wrote.
        for (index, writes) in touched.iter().enumerate() {
            let Some(worker) = self.slots[index].worker.as_mut() else {
                continue;
            };
            if failure.is_some() || *writes == 0 || !worker.maintenance_due() {
                continue;
            }
            let before = conn.total_changes().ok();
            worker.in_group = true;
            let result = worker.maintain(*writes).await;
            worker.in_group = false;
            changed[index] |= before.is_none() || before != conn.total_changes().ok();
            if matches!(result, Err(Error::Rollback { .. })) {
                fatal = true;
                failure = Some(Error::Corrupt("a step could not roll back".into()));
            } else if conn.is_autocommit().unwrap_or(true) {
                failure = Some(storage::group_lost());
            }
        }
        // A new checkpoint must be flushed before history behind it may go.
        if self
            .slots
            .iter()
            .filter_map(|slot| slot.worker.as_ref())
            .any(Worker::wants_flush)
        {
            self.flush_wanted = true;
        }
        #[cfg(test)]
        if matches!(self.fault, Some(crate::worker::Fault::AbortBeforeCommit)) {
            std::process::abort();
        }
        #[cfg(test)]
        if failure.is_none() && matches!(self.fault, Some(crate::worker::Fault::FailCommit)) {
            self.fault = None;
            failure = Some(Error::InjectedFailure);
        }
        self.metrics.step_micros.fetch_add(micros(started), Relaxed);
        let committing = Instant::now();
        let committed = match failure {
            None => conn.execute("COMMIT", ()).await.map_err(Error::from),
            Some(error) => Err(error),
        };
        self.metrics
            .commit_micros
            .fetch_add(micros(committing), Relaxed);
        if committed.is_err()
            && !conn.is_autocommit().unwrap_or(false)
            && conn.execute("ROLLBACK", ()).await.is_err()
        {
            fatal = true;
        }
        let _ = self.synchronous(&conn, false).await;
        match committed {
            Ok(_) => {
                #[cfg(test)]
                if matches!(self.fault, Some(crate::worker::Fault::AbortAfterCommit)) {
                    std::process::abort();
                }
                #[cfg(test)]
                if let Some(log) = &self.groups
                    && let Ok(mut log) = log.lock()
                {
                    log.push(composition);
                }
                self.metrics.groups.fetch_add(1, Relaxed);
                self.metrics
                    .steps
                    .fetch_add(touched.iter().sum::<usize>() as u64, Relaxed);
                if full {
                    self.metrics.flushes.fetch_add(1, Relaxed);
                }
                for (index, slot) in self.slots.iter_mut().enumerate() {
                    if let (true, Some(worker)) = (touched[index] > 0, slot.worker.as_mut()) {
                        worker.publish();
                        // A step that changed no row left nothing to flush.
                        if changed[index] {
                            worker.buffered();
                        }
                    }
                }
                if full {
                    self.flushed();
                }
                for (answer, budget) in answers {
                    answer.send(full);
                    drop(budget);
                }
                self.checkpoint(&conn).await || fatal
            }
            Err(error) => {
                // Nothing of the group is durable: rebuild every touched
                // domain's memory from storage and fail every waiter.
                if full {
                    self.flush_failed(&error);
                }
                for (slot, touched) in self.slots.iter_mut().zip(&touched) {
                    if let (true, Some(worker)) = (*touched > 0, slot.worker.as_mut())
                        && worker.recover().await.is_err()
                    {
                        fatal = true;
                    }
                }
                let mut errors = copies(error, answers.len() + skipped.len());
                for (answer, budget) in answers {
                    answer.fail(errors.pop().unwrap_or(Error::Closed));
                    drop(budget);
                }
                for command in skipped {
                    command.refuse(errors.pop().unwrap_or(Error::Closed));
                }
                fatal
            }
        }
    }
    /// Between groups, keep the WAL bounded: a passive checkpoint past
    /// `CHECKPOINT_FRAMES`, and a resetting `TRUNCATE` past twice that when
    /// readers kept passive ones from completing. A checkpoint that
    /// cannot finish now is retried after a later group. Returns true when
    /// the writer must stop.
    async fn checkpoint(&self, conn: &sqlite::Connection) -> bool {
        let frames = sqlite::wal_frames();
        self.metrics.wal_frames.store(frames.max(0) as u64, Relaxed);
        self.metrics
            .wal_frames_max
            .fetch_max(frames.max(0) as u64, Relaxed);
        if frames < self.checkpoint_frames {
            return false;
        }
        let started = Instant::now();
        let mut stop = false;
        let mut kind = CheckpointKind::Passive;
        let mut copy_micros = 0u64;
        let mut flush_micros = 0u64;
        if frames < 2 * self.checkpoint_frames {
            let (passive_stop, copy, flush) = self.passive(conn).await;
            stop = passive_stop;
            copy_micros = copy;
            flush_micros = flush;
        } else {
            // A reset must wait for readers of the old log; bound that wait well
            // below the retry bound, and try again after a later group.
            kind = CheckpointKind::Truncate;
            if conn.set_busy_timeout(RESET_WAIT).is_ok() {
                let _ = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)", ()).await;
            }
            let _ = conn.set_busy_timeout(std::time::Duration::ZERO);
            self.metrics.truncations.fetch_add(1, Relaxed);
            self.metrics
                .truncate_micros
                .fetch_add(micros(started), Relaxed);
        }
        let elapsed = micros(started);
        self.metrics.checkpoints.fetch_add(1, Relaxed);
        self.metrics.checkpoint_micros.fetch_add(elapsed, Relaxed);
        self.metrics
            .checkpoint_max_micros
            .fetch_max(elapsed, Relaxed);
        if self.instrument {
            self.metrics.record_checkpoint(CheckpointInterval {
                start: started,
                end: Instant::now(),
                kind,
                copy_micros,
                flush_micros,
            });
        }
        stop
    }
    /// A passive checkpoint with SQLite's flushes taken out and issued here,
    /// in its order, so their time is measured apart from the page copy:
    /// the WAL before the copy, the database file after it. Nothing else
    /// writes between the copy and the second flush. Returns whether the
    /// copy could not be flushed or the flush level not restored, plus the
    /// copy and database-file flush time of this checkpoint.
    async fn passive(&self, conn: &sqlite::Connection) -> (bool, u64, u64) {
        let Some(file) = &self.file else {
            return (false, 0, 0);
        };
        let path = file._owner.path();
        let mut wal = path.as_os_str().to_owned();
        wal.push("-wal");
        let flush = |path: &std::path::Path, spent: &AtomicU64| {
            let started = Instant::now();
            let result = std::fs::File::open(path).and_then(|file| file.sync_all());
            let elapsed = micros(started);
            spent.fetch_add(elapsed, Relaxed);
            (result, elapsed)
        };
        let (wal_result, _) = flush(
            std::path::Path::new(&wal),
            &self.metrics.checkpoint_wal_flush_micros,
        );
        if wal_result.is_err() || conn.execute("PRAGMA synchronous=0", ()).await.is_err() {
            return (false, 0, 0);
        }
        let copying = Instant::now();
        let copied = conn.execute("PRAGMA wal_checkpoint(PASSIVE)", ()).await;
        let copy_micros = micros(copying);
        self.metrics
            .checkpoint_copy_micros
            .fetch_add(copy_micros, Relaxed);
        // The log may be reused once copied, so an unflushed copy must stop.
        let (flush_result, flush_micros) = flush(path, &self.metrics.checkpoint_flush_micros);
        let unflushed = copied.is_ok() && flush_result.is_err();
        let level = format!("PRAGMA synchronous={}", self.durability.synchronous());
        (
            conn.execute(level, ()).await.is_err() || unflushed,
            copy_micros,
            flush_micros,
        )
    }
    #[cfg(test)]
    async fn abort_in_checkpoint(&self) {
        if let Some(conn) = self.conn() {
            let _ = conn.abort_when_busy();
            let _ = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)", ()).await;
        }
    }
    /// Retires domains whose queues are closed and drained. The last one
    /// closes the file before its observers stop and its closer is answered,
    /// so a caller that saw the close can reopen the file at once.
    async fn retire(&mut self) {
        let ready: Vec<_> = (0..self.slots.len())
            .filter(|index| {
                let slot = &self.slots[*index];
                slot.worker.is_some() && slot.drained && slot.deferred.is_empty()
            })
            .collect();
        if ready.is_empty() {
            return;
        }
        let mut retired: Vec<(Notifications, Option<Reply<()>>)> = Vec::new();
        for index in ready {
            let slot = &mut self.slots[index];
            if let Some(worker) = slot.worker.take() {
                retired.push((worker.into_notifications(), slot.closing.take()));
            }
        }
        if self.slots.iter().all(|slot| slot.worker.is_none()) {
            self.close_file().await;
        }
        for (notifications, closing) in retired {
            drop(notifications);
            if let Some(reply) = closing {
                let _ = reply.send(Ok(()));
            }
        }
    }
    /// Checkpoints and truncates the WAL, then releases the connection and lock.
    async fn close_file(&mut self) {
        if let Some(file) = self.file.take() {
            // A reader still holding the log would keep it from being reset.
            file.pool.close();
            let _ = file.conn.execute("PRAGMA optimize", ()).await;
            let _ = file
                .conn
                .execute("PRAGMA wal_checkpoint(TRUNCATE)", ())
                .await;
            drop(file);
        }
    }
}
async fn rows_raw(conn: &sqlite::Connection, sql: &str) -> Result<Vec<Vec<SqlValue>>, Error> {
    storage::collect_rows(conn.query(sql, ()).await?).await
}
/// Answers commands that never ran because their group could not begin.
fn fail<R>(commands: Vec<Command<R>>, error: Error) {
    let mut errors = copies(error, commands.len());
    for command in commands {
        command.refuse(errors.pop().unwrap_or(Error::Closed));
    }
}
/// One error per waiter; the first popped is the original.
fn copies(error: Error, count: usize) -> Vec<Error> {
    let mut errors: Vec<_> = (1..count.max(1))
        .map(|_| storage::group_error(&error))
        .collect();
    errors.push(error);
    errors
}
