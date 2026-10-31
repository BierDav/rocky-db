//! Group commit for authoring and incoming frames. Callers enqueue requests;
//! whoever holds the replica lock drains the queue as leader and runs
//! bounded `BEGIN IMMEDIATE` transactions with one savepoint per request. Results,
//! the revision watch and everything readers see follow the commit; results
//! that may leave the device also follow one shared flush.
use super::*;
use std::collections::VecDeque;
use tokio::sync::oneshot::{self, error::TryRecvError};

/// Requests drained for one shared flush, across bounded transactions.
pub(super) const GROUP_REQUESTS: usize = 64;
/// Request bytes per group; a single larger request still forms its own group.
pub(super) const GROUP_BYTES: usize = 4 * 1024 * 1024;
/// Author requests per transaction. Receive admission also applies a ready
/// request, so it uses RECEIVE_REQUESTS instead of this admission-only bound.
const STEP_REQUESTS: usize = 2;
/// One-row incoming frames per transaction, including ready application.
/// Pixel cold/warm p99 27.032/25.025 ms, including inspection and commit;
/// see docs/features_12/02-bounded-holds-evidence.md. Larger requests run alone.
pub(crate) const RECEIVE_REQUESTS: usize = 4;
/// Encoded input bytes per transaction; a larger atomic request runs alone.
/// Sized in the receive-step sizing evidence.
const STEP_BYTES: usize = 32 * 1024;
/// One discovery, application or cleanup unit per acquisition. Pixel warm
/// one-row application p99 8.466 ms; see the receive-step sizing evidence.
pub(super) const SETTLE_REQUESTS: usize = 1;
/// Larger atomic frames/bundles are reported as oversized requests.
/// One warm row costs 8.466 ms at p99 on Pixel; see the sizing evidence.
pub(super) const APPLICATION_ROWS: u64 = 1;
/// WAL size that triggers a passive checkpoint between groups, and the
/// size a reset WAL is cut back to.
pub(super) const WAL_CHECKPOINT_BYTES: u64 = 32 * 1024 * 1024;
/// WAL size that triggers a truncating checkpoint between groups.
pub(super) const WAL_LIMIT_BYTES: u64 = 64 * 1024 * 1024;
/// Longest wait of a truncating checkpoint for readers of the old log.
const TRUNCATE_WAIT: std::time::Duration = std::time::Duration::from_millis(50);
/// Free pages past which, and at most how many, one step returns to the file
/// system after a commit.
pub(crate) const RECLAIM_PAGES: i64 = 1024;
pub(crate) const RECLAIM_STEP: i64 = 4096;
/// Combined main and temporary page caches, negative as SQLite counts KiB.
#[cfg(target_os = "android")]
pub(super) const CACHE_KIB: i64 = -8 * 1024;
#[cfg(not(target_os = "android"))]
pub(super) const CACHE_KIB: i64 = -32 * 1024;

pub(super) enum Work {
    Author {
        handle: Commitment,
        input: Commitment,
        changes: Vec<RowChange>,
        dependencies: Vec<Hash>,
    },
    Bundle {
        handle: Commitment,
        input: Commitment,
        writes: Vec<RowWrite>,
        dependencies: Vec<Hash>,
        /// The session authority the bundle was prepared under, if any.
        authority: Option<u64>,
    },
    Receive(EncryptedFrame),
}
pub(super) enum Done {
    Author(EncryptedFrame),
    Bundle(Vec<EncryptedFrame>),
    /// The handle's operation committed earlier and has been pruned.
    Pruned(Hash),
    Receive(ReceiveStatus),
}
/// A request's state inside the group, before its final status is known.
enum Staged {
    Author(EncryptedFrame),
    Bundle(Vec<EncryptedFrame>),
    Handled(Hash),
    Covered,
    Duplicate,
    Stored(Hash),
}
type Reply = Result<(Done, u64), Error>;
pub(super) struct Request {
    work: Work,
    weight: usize,
    /// The result may leave the device, so it waits for the flush.
    exposed: bool,
    reply: oneshot::Sender<Reply>,
}
pub(super) type Queue = std::sync::Mutex<VecDeque<Request>>;

#[derive(Default)]
struct Outcome {
    results: Vec<Result<Staged, Error>>,
    /// Previously blocked work may be ready after this commit.
    more: bool,
    revision: u64,
    pass: Option<Error>,
}

/// Fault points inside a group, for crash and visibility tests.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum GroupFault {
    ExitAfterRequests(usize),
    ExitBeforeCommit,
    ExitAfterCommit,
    FailBeforeCommit,
    FailAfterCommits(usize),
}

impl<A: RowApplication> EncryptedReplica<A> {
    #[cfg(test)]
    pub(crate) async fn stage_bundle_before_apply_for_test(
        &self,
        frames: &[EncryptedFrame],
    ) -> Result<(), Error> {
        let time = now()?;
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        transaction!(inner, |inner| {
            for frame in frames {
                assert!(matches!(
                    inner.receive_step(frame, time).await?,
                    Staged::Stored(_)
                ));
            }
            Ok(())
        })
    }
    /// Enqueues `work` as contiguous requests and returns their results in order.
    pub(super) async fn submit(&self, work: Vec<(Work, usize)>, exposed: bool) -> Vec<Reply> {
        #[cfg(feature = "qualification")]
        let receive_limit = match crate::qualification_bound(
            "ROCKY_RECEIVE_REQUESTS",
            RECEIVE_REQUESTS,
            GROUP_REQUESTS,
        ) {
            Ok(limit) => limit,
            Err(error) => return work.iter().map(|_| Err(shared(&error))).collect(),
        };
        #[cfg(not(feature = "qualification"))]
        let receive_limit = RECEIVE_REQUESTS;
        let class = class_of(work.iter().map(|(work, _)| work));
        let mut pending = Vec::with_capacity(work.len());
        {
            let mut queue = self.queue();
            for (work, weight) in work {
                let (reply, done) = oneshot::channel();
                queue.push_back(Request {
                    work,
                    weight,
                    exposed,
                    reply,
                });
                pending.push(done);
            }
        }
        let mut results: Vec<Option<Reply>> = pending.iter().map(|_| None).collect();
        let (Some(last), Some(slot)) = (pending.last_mut(), results.last_mut()) else {
            return Vec::new();
        };
        // Groups take queue prefixes, so the last reply arrives after the others.
        let guard = tokio::select! {
            biased;
            result = last => {
                *slot = Some(result.unwrap_or(Err(Error::RetryExhausted)));
                None
            }
            guard = self.inner.lock(class) => Some(guard),
        };
        let mut guard = guard;
        let mut first = true;
        while !collect(&mut pending, &mut results) {
            let mut inner = match guard.take() {
                Some(guard) => guard,
                None => self.inner.lock(class).await,
            };
            if std::mem::take(&mut first) {
                drop(inner);
                tokio::task::yield_now().await;
                inner = self.inner.lock(class).await;
            }
            let mut cohort: VecDeque<_> = self.drain().into();
            if cohort.is_empty() {
                break;
            }
            let mut exposed = None;
            let mut scopes = BTreeSet::new();
            let mut pending_replies = VecDeque::new();
            let mut settle_failure = None;
            let flusher = inner.flusher.clone();
            while !cohort.is_empty() {
                let group = step(&mut cohort, &inner, receive_limit);
                #[cfg(any(test, feature = "qualification"))]
                let row_bound = group.len() as u64 * APPLICATION_ROWS;
                #[cfg(any(test, feature = "qualification"))]
                {
                    inner.units("encoded_byte", group.iter().map(|r| r.weight as u64).sum());
                    if group.iter().all(|r| matches!(r.work, Work::Receive(_))) {
                        inner.units("received_frame", group.len() as u64);
                    }
                }
                #[cfg(any(test, feature = "qualification"))]
                let received_work = group
                    .iter()
                    .all(|request| matches!(request.work, Work::Receive(_)))
                    .then(|| {
                        (
                            inner.frames_written.load(Ordering::Relaxed),
                            inner.rows_written.load(Ordering::Relaxed),
                            inner.applied_frames,
                        )
                    });
                let (answers, written, settling) = inner.commit_group(group).await;
                #[cfg(any(test, feature = "qualification"))]
                if let Some(before) = received_work {
                    let rows = inner.rows_written.load(Ordering::Relaxed) - before.1;
                    let frames = inner.frames_written.load(Ordering::Relaxed) - before.0;
                    let requests = inner.applied_frames - before.2;
                    inner.row_work(row_bound);
                    inner.units("applied_row", rows);
                    inner.units("applied_frame", frames);
                    inner.units("applied_request", requests);
                    if rows > row_bound {
                        inner.units("oversized_request", 1);
                    }
                }
                Exposed::append(&mut exposed, answers);
                scopes.extend(written);
                drop(inner);
                pending_replies.extend(settling);
                if !pending_replies.is_empty()
                    && cohort
                        .front()
                        .is_some_and(|r| !matches!(r.work, Work::Receive(_)))
                    && let Err(error) = self.settle().await
                {
                    settle_failure.get_or_insert(error);
                }
                // Yield outside the guard even when no mutex waiter has registered.
                // A drained local write keeps the leader interactive.
                tokio::task::yield_now().await;
                let class = class.min(class_of(cohort.iter().map(|request| &request.work)));
                inner = self.inner.lock(class).await;
            }
            let mut last_commit = inner.commit;
            drop(inner);
            if !pending_replies.is_empty() {
                if let Err(error) = self.settle().await {
                    settle_failure.get_or_insert(error);
                }
                while !pending_replies.is_empty() {
                    tokio::task::yield_now().await;
                    let count = pending_replies.len().min(STEP_REQUESTS);
                    let replies = pending_replies.drain(..count).collect();
                    let inner = self.inner.lock(Class::Background).await;
                    last_commit = inner.commit;
                    let settled = settle_failure
                        .as_ref()
                        .map_or(Ok(()), |error| Err(shared(error)));
                    Exposed::append(&mut exposed, inner.answer_settled(replies, settled).await);
                }
            }
            if let Some(mut exposed) = exposed {
                exposed.commit = last_commit;
                exposed.answer(flusher).await;
            }
            self.maintain_scopes(scopes).await;
            let mut inner = self.inner.lock(Class::Background).await;
            inner.checkpoint_if_due().await;
        }
        // Another leader took these requests and answers them after its
        // flush, outside the lock. A reply is lost only when its leader was
        // cancelled while waiting out a busy file; the outcome is then
        // unknown and retrying by handle is safe.
        let mut answered = Vec::with_capacity(pending.len());
        for (receiver, result) in pending.into_iter().zip(results) {
            answered.push(match result {
                Some(result) => result,
                None => receiver.await.unwrap_or(Err(Error::RetryExhausted)),
            });
        }
        answered
    }
    fn queue(&self) -> std::sync::MutexGuard<'_, VecDeque<Request>> {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// Takes the oldest live requests within the group bounds.
    fn drain(&self) -> Vec<Request> {
        let mut queue = self.queue();
        let mut group = Vec::new();
        let mut bytes = 0usize;
        while let Some(request) = queue.front() {
            if request.reply.is_closed() {
                queue.pop_front();
                continue;
            }
            if !group.is_empty()
                && (group.len() == GROUP_REQUESTS
                    || bytes.saturating_add(request.weight) > GROUP_BYTES)
            {
                break;
            }
            bytes = bytes.saturating_add(request.weight);
            if let Some(request) = queue.pop_front() {
                group.push(request);
            }
        }
        group
    }
}

/// Local writes acquire as interactive; everything else is background.
fn class_of<'a>(mut work: impl Iterator<Item = &'a Work>) -> Class {
    if work.any(|work| matches!(work, Work::Author { .. } | Work::Bundle { .. })) {
        Class::Interactive
    } else {
        Class::Background
    }
}

/// Takes one homogeneous transaction from an already admitted cohort.
fn step<A: RowApplication>(
    cohort: &mut VecDeque<Request>,
    inner: &Inner<A>,
    receive_limit: usize,
) -> Vec<Request> {
    let receiving = cohort
        .front()
        .is_some_and(|r| matches!(r.work, Work::Receive(_)));
    let limit = if receiving {
        receive_limit
    } else {
        STEP_REQUESTS
    };
    let mut group = Vec::new();
    let mut bytes = 0usize;
    while let Some(request) = cohort.front() {
        if !group.is_empty()
            && (group.len() == limit
                || bytes.saturating_add(request.weight) > STEP_BYTES
                || receiving != matches!(request.work, Work::Receive(_)))
        {
            break;
        }
        // Only known one-row frames share a receive step. An atomic bundle,
        // larger frame or unopened payload keeps its own transaction.
        let indivisible = if let Work::Receive(frame) = &request.work {
            inner
                .open_payload(frame)
                .and_then(|bytes| inner.decode_row_payload(frame, &bytes))
                .map_or(true, |payload| {
                    payload.membership().is_some()
                        || payload.writes().len() as u64 > APPLICATION_ROWS
                })
        } else {
            false
        };
        if !group.is_empty() && indivisible {
            break;
        }
        bytes = bytes.saturating_add(request.weight);
        if let Some(request) = cohort.pop_front() {
            group.push(request);
        }
        if indivisible {
            break;
        }
    }
    group
}

/// Moves delivered replies into `results`; true when every request has one.
fn collect(pending: &mut [oneshot::Receiver<Reply>], results: &mut [Option<Reply>]) -> bool {
    for (receiver, slot) in pending.iter_mut().zip(results.iter_mut()) {
        if slot.is_none() {
            match receiver.try_recv() {
                Ok(result) => *slot = Some(result),
                Err(TryRecvError::Closed) => *slot = Some(Err(Error::RetryExhausted)),
                Err(TryRecvError::Empty) => {}
            }
        }
    }
    results.iter().all(Option::is_some)
}

/// Received frames whose status waits for the rest of the pending pass:
/// each reply, whether it is exposed, and its final status kind.
enum PendingReply {
    Stored(Hash),
    Duplicate,
    Covered,
}
type Settling = Vec<(oneshot::Sender<Reply>, bool, PendingReply)>;

/// Results that may leave the device: answered after a flush covers `commit`.
struct Exposed {
    replies: Vec<(oneshot::Sender<Reply>, Done)>,
    commit: u64,
}
impl Exposed {
    fn append(all: &mut Option<Self>, next: Option<Self>) {
        if let Some(mut next) = next {
            if let Some(all) = all {
                all.commit = all.commit.max(next.commit);
                all.replies.append(&mut next.replies);
            } else {
                *all = Some(next);
            }
        }
    }
    /// One flush covers every exposed result in the group.
    async fn answer(self, flusher: Arc<Flusher>) {
        // A cancelled leader still owes every queued caller its durable reply.
        let _ = tokio::task::spawn_blocking(move || {
            let flushed = flusher.flush(self.commit);
            for (reply, done) in self.replies {
                let _ = reply.send(match &flushed {
                    Ok(()) => Ok((done, self.commit)),
                    Err(error) => Err(shared(error)),
                });
            }
        })
        .await;
    }
}

impl<A: RowApplication> Inner<A> {
    /// Commits one group and answers its requests after the commit, except
    /// the exposed ones, which it returns for the flush, and the received
    /// frames whose status waits for more pending passes. Also returns the
    /// scopes the group wrote, for maintenance.
    async fn commit_group(
        &mut self,
        group: Vec<Request>,
    ) -> (Option<Exposed>, BTreeSet<ResourceScope>, Settling) {
        let mut works = Vec::with_capacity(group.len());
        let mut replies = Vec::with_capacity(group.len());
        let mut scopes = BTreeSet::new();
        for request in group {
            match &request.work {
                Work::Author { changes, .. } => scopes.extend(changes.first().map(|c| c.scope)),
                Work::Bundle { writes, .. } => {
                    scopes.extend(writes.iter().map(|write| write.change.scope));
                }
                Work::Receive(frame) => scopes.extend(frame.scope().ok()),
            }
            works.push(request.work);
            replies.push((request.reply, request.exposed));
        }
        let kept = self.pending_pass_current(self.commit)
            && !works.iter().any(|work| matches!(work, Work::Receive(_)));
        let outcome = match now() {
            Ok(time) => transaction!(@commit self, |inner| inner.run_group(&works, time).await)
                .map(|outcome| (outcome, time)),
            Err(error) => Err(error),
        };
        let (outcome, _) = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                for (reply, _) in replies {
                    let _ = reply.send(Err(shared(&error)));
                }
                return (None, BTreeSet::new(), Vec::new());
            }
        };
        if kept {
            self.keep_pending_pass();
        }
        #[cfg(any(test, feature = "qualification"))]
        if let Err(error) = self.crash_at(|point| point == super::CrashPoint::GroupAfterCommit) {
            for (reply, _) in replies {
                let _ = reply.send(Err(shared(&error)));
            }
            return (None, BTreeSet::new(), Vec::new());
        }
        #[cfg(test)]
        {
            if matches!(self.group_fault, Some(GroupFault::ExitAfterCommit)) {
                std::process::exit(77);
            }
            self.group_commits += 1;
        }
        if outcome.results.iter().any(|result| {
            matches!(
                result,
                Ok(Staged::Author(_) | Staged::Bundle(_) | Staged::Stored(_))
            )
        }) {
            self.frames.send_replace(());
        }
        self.revision = outcome.revision;
        let revision = outcome.revision;
        self.notifications.send_if_modified(|current| {
            let changed = *current != revision;
            *current = revision;
            changed
        });
        let more = outcome.more && outcome.pass.is_none();
        let mut exposed = Vec::new();
        let mut settling = Vec::new();
        for ((reply, flush), result) in replies.into_iter().zip(outcome.results) {
            let done = match result {
                Ok(Staged::Stored(hash)) if more => {
                    settling.push((reply, flush, PendingReply::Stored(hash)));
                    continue;
                }
                Ok(Staged::Duplicate) if more => {
                    settling.push((reply, flush, PendingReply::Duplicate));
                    continue;
                }
                Ok(Staged::Covered) if more => {
                    settling.push((reply, flush, PendingReply::Covered));
                    continue;
                }
                Ok(Staged::Author(frame)) => Ok(Done::Author(frame)),
                Ok(Staged::Bundle(frames)) => Ok(Done::Bundle(frames)),
                Ok(Staged::Handled(hash)) => Ok(Done::Pruned(hash)),
                Ok(Staged::Covered) => outcome
                    .pass
                    .as_ref()
                    .map_or(Ok(Done::Receive(ReceiveStatus::Pruned)), |error| {
                        Err(shared(error))
                    }),
                Ok(Staged::Duplicate) => outcome
                    .pass
                    .as_ref()
                    .map_or(Ok(Done::Receive(ReceiveStatus::Duplicate)), |error| {
                        Err(shared(error))
                    }),
                Ok(Staged::Stored(hash)) => match &outcome.pass {
                    Some(error) => Err(shared(error)),
                    None => self.status(hash).await.map(Done::Receive),
                },
                Err(error) => Err(error),
            };
            match done {
                Ok(done) if flush => exposed.push((reply, done)),
                // A caller that went away still has its request committed.
                done => {
                    let _ = reply.send(done.map(|done| (done, self.commit)));
                }
            }
        }
        let exposed = (!exposed.is_empty()).then_some(Exposed {
            replies: exposed,
            commit: self.commit,
        });
        (exposed, scopes, settling)
    }
    /// Answers received frames with their status once the pending pass
    /// settled, or with its failure; returns the exposed ones for the flush.
    async fn answer_settled(
        &self,
        settling: Settling,
        settled: Result<(), Error>,
    ) -> Option<Exposed> {
        let mut exposed = Vec::new();
        for (reply, flush, pending) in settling {
            let done = match &settled {
                Ok(()) => match pending {
                    PendingReply::Stored(hash) => self.status(hash).await.map(Done::Receive),
                    PendingReply::Duplicate => Ok(Done::Receive(ReceiveStatus::Duplicate)),
                    PendingReply::Covered => Ok(Done::Receive(ReceiveStatus::Pruned)),
                },
                Err(error) => Err(shared(error)),
            };
            match done {
                Ok(done) if flush => exposed.push((reply, done)),
                done => {
                    let _ = reply.send(done.map(|done| (done, self.commit)));
                }
            }
        }
        (!exposed.is_empty()).then_some(Exposed {
            replies: exposed,
            commit: self.commit,
        })
    }
    async fn run_group(&mut self, works: &[Work], time: u64) -> Result<Outcome, Error> {
        let mut outcome = Outcome::default();
        let mut unapplied = false;
        for work in works {
            self.cause(match work {
                Work::Receive(_) => crate::observe::Cause::Sync,
                Work::Author { .. } | Work::Bundle { .. } => crate::observe::Cause::Local,
            });
            self.conn.execute("SAVEPOINT request", ()).await?;
            let result = match work {
                Work::Author {
                    handle,
                    input,
                    changes,
                    dependencies,
                } => match self.lookup_handle(*handle, *input).await {
                    Ok(Some(Ok(frame))) => Ok(Staged::Author(frame)),
                    Ok(Some(Err(hash))) => Ok(Staged::Handled(hash)),
                    Ok(None) => self
                        .author_transaction(*handle, *input, changes, dependencies, time)
                        .await
                        .map(Staged::Author),
                    Err(error) => Err(error),
                },
                Work::Bundle {
                    handle,
                    input,
                    writes,
                    dependencies,
                    authority,
                } => match self.lookup_bundle(*handle, *input).await {
                    Ok(Some(Ok(frames))) => Ok(Staged::Bundle(frames)),
                    Ok(Some(Err(hash))) => Ok(Staged::Handled(hash)),
                    // The commit's linearization point: authority is checked
                    // under the replica lock, inside the write transaction.
                    Ok(None) => match self.check_authority(*authority) {
                        Ok(()) => self
                            .author_bundle(*handle, *input, writes, dependencies, time)
                            .await
                            .map(Staged::Bundle),
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error),
                },
                Work::Receive(frame) => self.receive_step(frame, time).await,
            };
            match result {
                Err(error) if retryable(&error) => return Err(error),
                Err(error) => {
                    self.conn.execute("ROLLBACK TO request", ()).await?;
                    self.invalidate_context();
                    self.conn.execute("RELEASE request", ()).await?;
                    outcome.results.push(Err(error));
                }
                Ok(staged) => {
                    // A retry must resume a pass interrupted after receipt committed.
                    unapplied |= matches!(
                        staged,
                        Staged::Stored(_) | Staged::Covered | Staged::Duplicate
                    );
                    self.conn.execute("RELEASE request", ()).await?;
                    if outcome.pass.is_none()
                        && matches!(staged, Staged::Stored(_) | Staged::Duplicate)
                        && let Work::Receive(frame) = work
                    {
                        self.conn
                            .execute("SAVEPOINT received_application", ())
                            .await?;
                        #[cfg(test)]
                        let before = self.applied_frames;
                        let applied = self.apply_received(frame, time).await;
                        #[cfg(test)]
                        let applied = if self.applied_frames != before && !crate::apply_allowed() {
                            Err(Error::InjectedFailure)
                        } else {
                            applied
                        };
                        if let Err(error) = applied {
                            self.conn
                                .execute("ROLLBACK TO received_application", ())
                                .await?;
                            self.invalidate_context();
                            self.invalidate_held_refresh();
                            self.untouch();
                            if retryable(&error) {
                                return Err(error);
                            }
                            outcome.pass = Some(error);
                        }
                        self.conn
                            .execute("RELEASE received_application", ())
                            .await?;
                    }
                    outcome.results.push(Ok(staged));
                }
            }
            #[cfg(test)]
            if let Some(GroupFault::ExitAfterRequests(count)) = self.group_fault
                && outcome.results.len() == count
            {
                std::process::exit(77);
            }
        }
        // Ready requests apply with admission so readers never see an artificial
        // pending interval. Previously blocked work settles between groups.
        outcome.more = unapplied;
        #[cfg(any(test, feature = "qualification"))]
        self.crash_at(|point| point == super::CrashPoint::GroupBeforeCommit)?;
        #[cfg(test)]
        match self.group_fault {
            Some(GroupFault::ExitBeforeCommit) => std::process::exit(77),
            Some(GroupFault::FailBeforeCommit) => return Err(Error::InjectedFailure),
            Some(GroupFault::FailAfterCommits(count)) if self.group_commits >= count => {
                return Err(Error::InjectedFailure);
            }
            _ => {}
        }
        outcome.revision = self.stored_revision().await?;
        Ok(outcome)
    }
    /// Admits one incoming frame into custody; application follows in the pass.
    async fn receive_step(&mut self, frame: &EncryptedFrame, time: u64) -> Result<Staged, Error> {
        let bytes =
            usize::try_from(frame.stored_bytes()?).map_err(|_| denied("stored frame size"))?;
        let migration = self.check_migration_frame(frame, time).await?;
        let operation = frame.operation_ref()?;
        let mut store = TransactionStore(self.conn.clone());
        let held = store.has_operation(operation.hash).await?;
        // A held frame of a generation this replica does not admit, such as
        // one refused as unknown, was verified as it arrived; any other is
        // verified again.
        if held
            && self
                .manifest_of_tip(operation.header.extensions.tip)
                .and_then(|manifest| self.admits(manifest))
                .is_err()
        {
            return Ok(Staged::Duplicate);
        }
        self.verify_frame(frame, time)?;
        let operation = frame.operation_ref()?;
        // Under the lock that installs no-frames bases, so neither order
        // commits both a base and history it says the seal excludes.
        self.refuse_no_frames_contradiction(&operation.header)
            .await?;
        let extension = &operation.header.extensions;
        if self
            .opening_key(extension.scope, extension.generation)
            .is_some()
            && let Ok(plaintext) = self.open_payload(frame)
        {
            RowPayload::check_formats(&plaintext)?;
        }
        let local = self.local_grants(time)?;
        if !roles::holds_whole(&local, operation.header.extensions.scope) {
            return Err(denied("incoming custody denied"));
        }
        if held {
            return Ok(Staged::Duplicate);
        }
        // A late frame from before the pruned_prefix is part of the checkpoint: it
        // is not stored and cannot be applied a second time.
        let scope = operation.header.extensions.scope;
        if self.frame_reach(frame)? != tips::FrameReach::Held
            && let Some(id) = self.find_scope_id(scope).await?
            && let Some(log) = self.log(id, operation.header.public_key).await?
            && operation.header.seq_num as i64 <= log.pruned_prefix
        {
            // A pending frame may name it as a dependency.
            if self.has_pending(scope).await? {
                self.put_stub(operation.hash, id, operation.header.timestamp, false)
                    .await?;
            }
            return Ok(Staged::Covered);
        }
        // A void consumed this position: the frame forks its log.
        if self
            .voided_position(scope, operation.header.public_key, operation.header.seq_num)
            .await?
        {
            return Ok(Staged::Covered);
        }
        self.admit_scope(&operation.header).await?;
        if migration.is_none() {
            self.check_budget(bytes).await?;
        }
        self.keep_chain(frame.chain()?).await?;
        self.no_frames_intake(&operation.header).await?;
        store
            .insert_operation(
                operation.hash,
                &operation.header,
                operation.body.as_ref(),
                frame.header_bytes(),
                &operation.header.extensions.scope,
            )
            .await?;
        self.settle_placement(&operation.header).await?;
        if let Some(statement) = migration {
            let proof = &frame
                .migration
                .as_ref()
                .ok_or_else(|| denied("migration proof missing"))?
                .proof;
            self.classify_migration(&statement, frame, proof).await?;
        }
        self.conn
            .execute(
                "INSERT INTO secure_outbox VALUES(?)",
                [operation.hash.as_bytes().to_vec()],
            )
            .await?;
        Ok(Staged::Stored(operation.hash))
    }
    pub(super) async fn stored_revision(&self) -> Result<u64, Error> {
        let revision = rows(
            &self.conn,
            "SELECT revision FROM secure_metadata WHERE id=1",
        )
        .await?;
        match revision.first().map(Vec::as_slice) {
            Some([SqlValue::Integer(revision)]) if *revision >= 0 => Ok(*revision as u64),
            _ => Err(denied("invalid secure revision")),
        }
    }
    /// Keeps the WAL bounded: passive past the checkpoint size whenever the
    /// file has grown since the last one, truncating past the hard limit.
    /// Best effort: the commit already succeeded, so a failure waits for the
    /// next transaction.
    pub(crate) async fn checkpoint_if_due(&mut self) {
        self.checkpoint_over(self.wal_limits.1).await;
    }
    /// [`Self::checkpoint_if_due`], truncating once the WAL holds `limit`.
    pub(super) async fn checkpoint_over(&mut self, limit: u64) {
        self.reclaim_free_pages().await;
        let size = std::fs::metadata(&self.wal).map_or(0, |metadata| metadata.len());
        let truncate = size >= limit;
        if !truncate {
            if size >= self.wal_limits.0 {
                self.passive.schedule(size, self.flusher.clone());
            }
            return;
        }
        let waits = self
            .conn
            .connection()
            .set_busy_timeout(TRUNCATE_WAIT)
            .is_ok();
        #[cfg(feature = "qualification")]
        let started = std::time::Instant::now();
        let checkpoint = rows(&self.conn, "PRAGMA wal_checkpoint(TRUNCATE)").await;
        #[cfg(feature = "qualification")]
        if let Ok(result) = &checkpoint {
            let pages = match result.first().map(Vec::as_slice) {
                Some([_, _, SqlValue::Integer(done)]) => (*done).max(0) as u64,
                _ => 0,
            };
            self.flusher
                .measurements
                .checkpoint("truncate", pages, started.elapsed());
        }
        if waits {
            let _ = self
                .conn
                .connection()
                .set_busy_timeout(std::time::Duration::ZERO);
        }
        if let Ok(result) = checkpoint {
            let complete = matches!(
                result.first().map(Vec::as_slice),
                Some([SqlValue::Integer(0), SqlValue::Integer(log), SqlValue::Integer(done)])
                    if log == done
            );
            if complete {
                self.passive.reset();
            }
            #[cfg(test)]
            {
                self.checkpoints += 1;
            }
        }
    }
    /// Compaction and pruning free pages; between commits, one bounded
    /// incremental vacuum step gives them back to the file system.
    async fn reclaim_free_pages(&self) {
        let free = rows(&self.conn, "PRAGMA freelist_count").await;
        if let Ok(free) = free
            && let Some([SqlValue::Integer(free)]) = free.first().map(Vec::as_slice)
            && *free >= RECLAIM_PAGES
        {
            let _ = rows(
                &self.conn,
                &format!("PRAGMA incremental_vacuum({RECLAIM_STEP})"),
            )
            .await;
            #[cfg(any(test, feature = "qualification"))]
            if let Ok(after) = rows(&self.conn, "PRAGMA freelist_count").await
                && let Some([SqlValue::Integer(after)]) = after.first().map(Vec::as_slice)
            {
                self.flusher.measurements.work(
                    lock::WorkUnit::ReclaimedPage,
                    free.saturating_sub(*after).max(0) as u64,
                );
            }
        }
    }
}

#[cfg(test)]
impl<A: RowApplication> EncryptedReplica<A> {
    pub(crate) async fn reclaim_free_pages_for_test(&self) {
        self.inner
            .lock(Class::Background)
            .await
            .reclaim_free_pages()
            .await;
    }
}

/// The group's failure as reported to each of its callers.
pub(super) fn shared(error: &Error) -> Error {
    match error {
        #[cfg(test)]
        Error::InjectedFailure => Error::InjectedFailure,
        Error::RetryExhausted => Error::RetryExhausted,
        Error::Closed => Error::Closed,
        Error::Conflict => Error::Conflict,
        Error::Blocked(blockers) => Error::Blocked(blockers.clone()),
        Error::Sql(error) => Error::Sql(error.clone()),
        Error::Backpressure => Error::Backpressure,
        Error::Quota { resource, limit } => Error::Quota {
            resource,
            limit: *limit,
        },
        Error::Rejected(message) => Error::Rejected(message.clone()),
        Error::Incompatible(message) => Error::Incompatible(message.clone()),
        Error::Durability(message) => Error::Durability(message.clone()),
        Error::Corrupt(_) | Error::Rollback { .. } => Error::Corrupt(error.to_string()),
        Error::Io(source) => Error::Io(std::io::Error::new(source.kind(), source.to_string())),
        other => Error::Io(std::io::Error::other(other.to_string())),
    }
}
