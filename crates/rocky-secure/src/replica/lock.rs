use std::{
    ops::{Deref, DerefMut},
    panic::Location,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, MutexGuard, Notify, OwnedMutexGuard};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Class {
    Interactive,
    Background,
}

/// Interactive acquisitions a background acquisition defers to before it
/// queues anyway, so background work still advances under continuous writes.
pub(crate) const STARVATION_YIELDS: u64 = 8;

/// The raw mutex stays private so every acquisition has a class and a caller.
///
/// Interactive acquisitions register before they wait. A background
/// acquisition starts only when none is registered, and rechecks after it
/// obtains the mutex, so an interactive one waits for at most the one
/// background step already running. Transitions and other oversized steps
/// acquire as background and therefore start only when the gate is quiet.
pub(crate) struct ReplicaLock<T> {
    mutex: Arc<Mutex<T>>,
    gate: Arc<Gate>,
    #[cfg(any(test, feature = "qualification"))]
    measurements: LockMeasurements,
}

#[derive(Default)]
struct Gate {
    state: std::sync::Mutex<GateState>,
    changed: Notify,
}
#[derive(Default, Clone, Copy)]
struct GateState {
    /// Registered interactive waiters.
    waiting: u64,
    /// Interactive acquisitions so far; counts the starvation guard's yields.
    acquired: u64,
    /// Background grants so far and whether one holds, for the step counter.
    #[cfg(any(test, feature = "qualification"))]
    background_grants: u64,
    #[cfg(any(test, feature = "qualification"))]
    background_holding: bool,
}
impl Gate {
    fn state(&self) -> std::sync::MutexGuard<'_, GateState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn update<R>(&self, change: impl FnOnce(&mut GateState) -> R) -> R {
        let result = change(&mut self.state());
        self.changed.notify_waiters();
        result
    }
}

/// An interactive waiter's registration; dropping it unacquired cancels it.
struct Registration {
    gate: Arc<Gate>,
    #[cfg(any(test, feature = "qualification"))]
    start: GateState,
}
impl Registration {
    fn new(gate: &Arc<Gate>) -> Self {
        let mut state = gate.state();
        state.waiting += 1;
        #[cfg(any(test, feature = "qualification"))]
        let start = *state;
        drop(state);
        Self {
            gate: gate.clone(),
            #[cfg(any(test, feature = "qualification"))]
            start,
        }
    }
    /// Background steps this waiter waited for: the one running when it
    /// registered plus any granted afterwards.
    fn acquired(self) -> u64 {
        self.gate.update(|state| {
            state.acquired += 1;
            #[cfg(any(test, feature = "qualification"))]
            return state.background_grants - self.start.background_grants
                + u64::from(self.start.background_holding);
            #[cfg(not(any(test, feature = "qualification")))]
            0
        })
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.gate.update(|state| state.waiting -= 1);
    }
}

impl<T> ReplicaLock<T> {
    pub(crate) fn new(
        value: T,
        #[cfg(any(test, feature = "qualification"))] measurements: LockMeasurements,
    ) -> Self {
        Self {
            mutex: Arc::new(Mutex::new(value)),
            gate: Arc::default(),
            #[cfg(any(test, feature = "qualification"))]
            measurements,
        }
    }

    #[track_caller]
    pub(crate) fn lock(&self, class: Class) -> impl Future<Output = Guard<MutexGuard<'_, T>>> {
        self.acquire(class, || self.mutex.lock())
    }

    #[track_caller]
    pub(crate) fn lock_owned(
        &self,
        class: Class,
    ) -> impl Future<Output = Guard<OwnedMutexGuard<T>>> + use<T> {
        let mutex = self.mutex.clone();
        self.acquire(class, move || mutex.clone().lock_owned())
    }

    #[cfg(test)]
    pub(crate) fn interactive_waiting(&self) -> bool {
        self.gate.state().waiting > 0
    }

    #[track_caller]
    fn acquire<G, F: Future<Output = G>, L: Fn() -> F>(
        &self,
        class: Class,
        lock: L,
    ) -> impl Future<Output = Guard<G>> + use<T, G, F, L> {
        let site = Location::caller();
        // With no sink only acquisition and release need clock reads.
        let timing = cfg!(feature = "qualification")
            || tracing::enabled!(target: "replica", tracing::Level::DEBUG);
        let requested = timing.then(Instant::now);
        let gate = self.gate.clone();
        #[cfg(any(test, feature = "qualification"))]
        let measurements = self.measurements.clone();
        async move {
            let (guard, _steps) = match class {
                Class::Interactive => {
                    let registration = Registration::new(&gate);
                    let guard = lock().await;
                    (guard, registration.acquired())
                }
                Class::Background => (background(&gate, lock).await, 0),
            };
            let acquired = Instant::now();
            #[cfg(any(test, feature = "qualification"))]
            if class == Class::Interactive {
                measurements.interactive_steps(_steps);
            }
            #[cfg(any(test, feature = "qualification"))]
            let work_start = measurements.work_snapshot();
            Guard {
                guard,
                #[cfg(any(test, feature = "qualification"))]
                work_start,
                _timing: Hold {
                    site,
                    class,
                    acquired,
                    wait: requested.map_or(Duration::ZERO, |start| acquired.duration_since(start)),
                    #[cfg(any(test, feature = "qualification"))]
                    gate: (class == Class::Background).then_some(gate),
                    #[cfg(any(test, feature = "qualification"))]
                    measurements,
                    #[cfg(any(test, feature = "qualification"))]
                    connection: qualification::connection(),
                    #[cfg(any(test, feature = "qualification"))]
                    units: Vec::new(),
                    #[cfg(any(test, feature = "qualification"))]
                    normal_rows: super::group::APPLICATION_ROWS,
                },
            }
        }
    }

    #[cfg(any(test, feature = "qualification"))]
    pub(crate) fn measurements(&self) -> LockMeasurements {
        self.measurements.clone()
    }
}

/// Waits until no interactive waiter is registered, unless this acquisition
/// has deferred to `STARVATION_YIELDS` interactive acquisitions already.
async fn background<G, F: Future<Output = G>>(gate: &Gate, lock: impl Fn() -> F) -> G {
    let mut first_deferral = None;
    loop {
        let starved = loop {
            let changed = gate.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let state = *gate.state();
            if state.waiting == 0 {
                break false;
            }
            let first = *first_deferral.get_or_insert(state.acquired);
            if state.acquired - first >= STARVATION_YIELDS {
                break true;
            }
            changed.await;
        };
        let guard = lock().await;
        // A waiter that registered while this one queued goes first.
        let state = *gate.state();
        let first = *first_deferral.get_or_insert(state.acquired);
        if starved || state.waiting == 0 || state.acquired - first >= STARVATION_YIELDS {
            #[cfg(any(test, feature = "qualification"))]
            gate.update(|state| {
                state.background_grants += 1;
                state.background_holding = true;
            });
            return guard;
        }
        drop(guard);
    }
}

pub(crate) struct Guard<G> {
    // Field order releases the mutex before recording its completed hold.
    guard: G,
    _timing: Hold,
    #[cfg(any(test, feature = "qualification"))]
    work_start: [u64; 17],
}
struct Hold {
    site: &'static Location<'static>,
    class: Class,
    acquired: Instant,
    wait: Duration,
    #[cfg(any(test, feature = "qualification"))]
    gate: Option<Arc<Gate>>,
    #[cfg(any(test, feature = "qualification"))]
    measurements: LockMeasurements,
    #[cfg(any(test, feature = "qualification"))]
    connection: Option<u64>,
    #[cfg(any(test, feature = "qualification"))]
    units: Vec<(&'static str, u64)>,
    #[cfg(any(test, feature = "qualification"))]
    normal_rows: u64,
}
#[cfg(any(test, feature = "qualification"))]
impl<G> Guard<G> {
    pub(crate) fn row_work(&mut self, bound: u64) {
        self._timing.normal_rows = bound;
    }
}
#[cfg(any(test, feature = "qualification"))]
impl<G> Guard<G> {
    pub(crate) fn units(&mut self, unit: &'static str, count: u64) {
        if count > 0 {
            self._timing.units.push((unit, count));
        }
    }
}
#[cfg(any(test, feature = "qualification"))]
impl<G> Drop for Guard<G> {
    fn drop(&mut self) {
        let end = self._timing.measurements.work_snapshot();
        for (index, unit) in [
            "replayed_frame",
            "base_row",
            "checkpoint_row",
            "maintenance_record",
            "held_refresh_record",
            "held_refresh_frame",
            "held_member_frame",
            "held_member_row",
            "held_token_record",
            "held_page_record",
            "received_input_row",
            "held_listing_row",
            "migration_storage_record",
            "prune_candidate",
            "reclaimed_page",
            "domain_header",
            "scan_fallback",
        ]
        .into_iter()
        .enumerate()
        {
            let count = end[index].saturating_sub(self.work_start[index]);
            if count > 0 {
                self._timing.units.push((unit, count));
            }
        }
    }
}
impl<G: Deref> Deref for Guard<G> {
    type Target = G::Target;
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}
impl<G: DerefMut> DerefMut for Guard<G> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}
impl Drop for Hold {
    fn drop(&mut self) {
        #[cfg(any(test, feature = "qualification"))]
        if let Some(gate) = &self.gate {
            gate.update(|state| state.background_holding = false);
        }
        let hold = self.acquired.elapsed();
        if hold > Duration::from_millis(1) {
            tracing::debug!(target: "replica", site = %self.site, class = ?self.class,
                wait_us = self.wait.as_micros() as u64, hold_us = hold.as_micros() as u64,
                "replica lock hold");
        }
        #[cfg(any(test, feature = "qualification"))]
        self.measurements.record(
            self.site,
            self.class,
            (self.wait, hold),
            self.connection,
            &self.units,
            self.normal_rows,
        );
    }
}

#[cfg(any(test, feature = "qualification"))]
mod qualification {
    use super::*;
    use std::collections::BTreeMap;

    tokio::task_local! { static CONNECTION: u64; }
    pub(super) fn connection() -> Option<u64> {
        CONNECTION.try_with(|id| *id).ok()
    }
    /// Carries an SDK SQL connection identity across its server-side task.
    #[cfg(feature = "qualification")]
    pub async fn with_measurement_connection<T>(id: u64, future: impl Future<Output = T>) -> T {
        CONNECTION.scope(id, future).await
    }
    /// Opt-in, replica-local histograms. Disabled until `start` is called.
    #[derive(Clone, Default)]
    pub struct LockMeasurements(Arc<Recording>);
    #[derive(Default)]
    struct Recording {
        data: std::sync::Mutex<Option<Measurements>>,
        work: [std::sync::atomic::AtomicU64; 17],
    }
    pub(crate) enum WorkUnit {
        #[cfg(feature = "qualification")]
        ReplayedFrame = 0,
        BaseRow = 1,
        #[cfg(feature = "qualification")]
        CheckpointRow = 2,
        MaintenanceRecord = 3,
        HeldRefreshRecord = 4,
        HeldRefreshFrame = 5,
        HeldMemberFrame = 6,
        HeldMemberRow = 7,
        HeldTokenRecord = 8,
        HeldPageRecord = 9,
        ReceivedInputRow = 10,
        HeldListingRow = 11,
        MigrationStorageRecord = 12,
        PruneCandidate = 13,
        ReclaimedPage = 14,
        DomainHeader = 15,
        ScanFallback = 16,
    }

    #[derive(Default, Debug)]
    pub struct Measurements {
        pub holders: BTreeMap<(String, String), HolderMeasurements>,
        pub flush_us: Vec<u64>,
        /// Background steps each interactive acquisition waited for.
        pub interactive_steps: Vec<u64>,
        pub connections: BTreeMap<u64, ConnectionMeasurements>,
        pub checkpoints: BTreeMap<String, Vec<(u64, u64)>>,
    }
    #[derive(Default, Debug)]
    pub struct HolderMeasurements {
        pub wait_us: Vec<u64>,
        pub hold_us: Vec<u64>,
        /// Indivisible requests, excluded from the ordinary hold histogram.
        pub oversized_request_us: Vec<u64>,
        /// (work count, full acquisition hold in microseconds).
        pub units: BTreeMap<String, Vec<(u64, u64)>>,
    }
    #[derive(Default, Debug)]
    pub struct ConnectionMeasurements {
        pub wait_us: u64,
        pub hold_us: u64,
        pub flush_us: u64,
    }
    impl LockMeasurements {
        pub(crate) fn work(&self, unit: WorkUnit, count: u64) {
            self.0.work[unit as usize].fetch_add(count, std::sync::atomic::Ordering::Relaxed);
        }
        pub(super) fn interactive_steps(&self, steps: u64) {
            if let Some(measurements) = self
                .0
                .data
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
            {
                measurements.interactive_steps.push(steps);
            }
        }
        pub(crate) fn work_snapshot(&self) -> [u64; 17] {
            std::array::from_fn(|index| {
                self.0.work[index].load(std::sync::atomic::Ordering::Relaxed)
            })
        }

        pub fn start(&self) {
            *self
                .0
                .data
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Measurements::default());
        }
        /// Drains the interval while continuing to record the next one.
        pub fn take(&self) -> Measurements {
            self.0
                .data
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
                .map(std::mem::take)
                .unwrap_or_default()
        }
        pub fn stop(&self) -> Measurements {
            self.0
                .data
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .unwrap_or_default()
        }
        pub(crate) fn record(
            &self,
            site: &Location<'_>,
            class: Class,
            (wait, hold): (Duration, Duration),
            connection: Option<u64>,
            units: &[(&str, u64)],
            normal_rows: u64,
        ) {
            if let Some(measurements) = self
                .0
                .data
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
            {
                let holder = measurements
                    .holders
                    .entry((site.to_string(), format!("{class:?}")))
                    .or_default();
                holder.wait_us.push(wait.as_micros() as u64);
                let oversized = units.iter().any(|(unit, count)| {
                    (*unit == "oversized_request" && *count > 0)
                        || (*unit == "held_member_row"
                            && *count > super::super::group::APPLICATION_ROWS)
                        || (*unit == "received_input_row" && *count > normal_rows)
                });
                if oversized {
                    holder.oversized_request_us.push(hold.as_micros() as u64);
                } else {
                    holder.hold_us.push(hold.as_micros() as u64);
                }
                for (unit, count) in units {
                    holder
                        .units
                        .entry((*unit).into())
                        .or_default()
                        .push((*count, hold.as_micros() as u64));
                }
                if let Some(id) = connection {
                    let work = measurements.connections.entry(id).or_default();
                    work.wait_us += wait.as_micros() as u64;
                    work.hold_us += hold.as_micros() as u64;
                }
            }
        }
        #[cfg(feature = "qualification")]
        pub(crate) fn checkpoint(&self, mode: &str, pages: u64, elapsed: Duration) {
            if let Some(measurements) = self
                .0
                .data
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
            {
                measurements
                    .checkpoints
                    .entry(mode.into())
                    .or_default()
                    .push((pages, elapsed.as_micros() as u64));
            }
        }
        #[cfg(feature = "qualification")]
        pub(crate) fn flush(&self, elapsed: Duration) {
            if let Some(measurements) = self
                .0
                .data
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
            {
                measurements.flush_us.push(elapsed.as_micros() as u64);
                if let Some(id) = connection() {
                    measurements.connections.entry(id).or_default().flush_us +=
                        elapsed.as_micros() as u64;
                }
            }
        }
    }
}
#[cfg(any(test, feature = "qualification"))]
pub use qualification::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, sync::Mutex as StdMutex};
    use tracing::{
        Subscriber,
        field::{Field, Visit},
        span::{Attributes, Id, Record},
    };

    #[derive(Clone, Default)]
    struct Events(Arc<StdMutex<Vec<BTreeMap<String, String>>>>);
    struct Fields(BTreeMap<String, String>);
    impl Visit for Fields {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().into(), format!("{value:?}"));
        }
    }
    impl Subscriber for Events {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            assert_eq!(event.metadata().target(), "replica");
            assert_eq!(event.metadata().level(), &tracing::Level::DEBUG);
            let mut fields = Fields(BTreeMap::new());
            event.record(&mut fields);
            self.0.lock().unwrap().push(fields.0);
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    #[tokio::test]
    async fn slow_holds_report_the_request_site_and_class() {
        let events = Events::default();
        let _subscriber = tracing::subscriber::set_default(events.clone());
        let mutex = ReplicaLock::new(
            (),
            #[cfg(any(test, feature = "qualification"))]
            LockMeasurements::default(),
        );
        let line = line!() + 1;
        let future = mutex.lock(Class::Interactive);
        // Polling somewhere else must not change the attributed caller.
        let mut guard = future.await;
        guard._timing.acquired -= Duration::from_millis(2);
        drop(guard);
        let events = events.0.lock().unwrap();
        let fields = &events[0];
        assert!(
            fields["site"].contains(&format!("lock.rs:{line}:")),
            "{fields:?}"
        );
        assert_eq!(fields["class"], "Interactive");
        assert!(fields["hold_us"].parse::<u64>().unwrap() >= 2000);
        assert!(fields["wait_us"].parse::<u64>().is_ok());
    }

    #[cfg(any(test, feature = "qualification"))]
    #[tokio::test]
    async fn histogram_records_both_classes_and_owned_guards() {
        let measurements = LockMeasurements::default();
        let mutex = ReplicaLock::new((), measurements.clone());
        measurements.start();
        let mut guard = mutex.lock(Class::Background).await;
        guard._timing.acquired -= Duration::from_millis(2);
        measurements.work(WorkUnit::BaseRow, 7);
        drop(guard);
        let line = line!() + 1;
        let future = mutex.lock_owned(Class::Interactive);
        drop(future.await);
        let snapshot = measurements.stop();
        assert_eq!(snapshot.holders.len(), 2);
        let background = snapshot
            .holders
            .iter()
            .find(|((_, class), _)| class == "Background")
            .unwrap()
            .1;
        let samples = &background.units["base_row"];
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].0, 7);
        assert!(samples[0].1 >= 2000);
        assert_eq!(background.hold_us.len(), 1);
        let interactive = snapshot
            .holders
            .iter()
            .find(|((_, class), _)| class == "Interactive")
            .unwrap();
        assert!(interactive.0.0.contains(&format!("lock.rs:{line}:")));
        assert_eq!(interactive.1.hold_us.len(), 1);
        assert!(measurements.take().holders.is_empty());
    }
    #[tokio::test]
    async fn indivisible_requests_keep_their_own_histogram() {
        let measurements = LockMeasurements::default();
        let mutex = ReplicaLock::new((), measurements.clone());
        measurements.start();
        for rows in [0, 2] {
            let guard = mutex.lock(Class::Background).await;
            measurements.work(WorkUnit::HeldMemberRow, rows);
            drop(guard);
        }
        let snapshot = measurements.stop();
        assert_eq!(snapshot.holders.len(), 1);
        let holder = snapshot.holders.values().next().unwrap();
        assert_eq!(holder.wait_us.len(), 2);
        assert_eq!(holder.hold_us.len(), 1);
        assert_eq!(holder.oversized_request_us.len(), 1);
    }

    fn order() -> (
        Arc<StdMutex<Vec<&'static str>>>,
        ReplicaLock<()>,
        LockMeasurements,
    ) {
        let measurements = LockMeasurements::default();
        measurements.start();
        (
            Arc::default(),
            ReplicaLock::new((), measurements.clone()),
            measurements,
        )
    }
    async fn settle() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn background_queued_first_acquires_after_interactive() {
        let (order, lock, measurements) = order();
        let lock = Arc::new(lock);
        let holder = lock.lock(Class::Background).await;
        let spawn = |class, name| {
            let (lock, order) = (lock.clone(), order.clone());
            tokio::spawn(async move {
                let _guard = lock.lock(class).await;
                order.lock().unwrap().push(name);
            })
        };
        let background = spawn(Class::Background, "background");
        settle().await;
        let interactive = spawn(Class::Interactive, "interactive");
        settle().await;
        assert!(lock.interactive_waiting());
        drop(holder);
        background.await.unwrap();
        interactive.await.unwrap();
        assert_eq!(*order.lock().unwrap(), ["interactive", "background"]);
        assert!(!lock.interactive_waiting());
        assert_eq!(measurements.stop().interactive_steps, [1]);
    }

    #[tokio::test]
    async fn cancelled_interactive_waiter_unregisters() {
        let (_, lock, _) = order();
        let holder = lock.lock(Class::Background).await;
        {
            let waiter = lock.lock(Class::Interactive);
            tokio::pin!(waiter);
            std::future::poll_fn(|context| {
                assert!(waiter.as_mut().poll(context).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            assert!(lock.interactive_waiting());
        }
        assert!(!lock.interactive_waiting());
        drop(holder);
        // A background acquisition is not deferred by the cancelled waiter.
        drop(lock.lock(Class::Background).await);
    }

    #[tokio::test]
    async fn interactive_acquisitions_stay_fifo() {
        let (order, lock, _) = order();
        let lock = Arc::new(lock);
        let holder = lock.lock(Class::Interactive).await;
        let mut tasks = Vec::new();
        for name in ["first", "second", "third"] {
            let (lock, order) = (lock.clone(), order.clone());
            tasks.push(tokio::spawn(async move {
                let _guard = lock.lock(Class::Interactive).await;
                order.lock().unwrap().push(name);
            }));
            settle().await;
        }
        drop(holder);
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(*order.lock().unwrap(), ["first", "second", "third"]);
    }

    #[tokio::test]
    async fn starvation_guard_lets_background_advance() {
        let (order, lock, _) = order();
        let lock = Arc::new(lock);
        let mut holder = Some(lock.lock_owned(Class::Interactive).await);
        let background = {
            let (lock, order) = (lock.clone(), order.clone());
            tokio::spawn(async move {
                let _guard = lock.lock(Class::Background).await;
                order.lock().unwrap().push("background");
            })
        };
        // Overlapping interactive writes keep a waiter registered throughout.
        for _ in 0..2 * STARVATION_YIELDS {
            let (lock, order) = (lock.clone(), order.clone());
            let next = tokio::spawn(async move {
                let guard = lock.lock_owned(Class::Interactive).await;
                order.lock().unwrap().push("interactive");
                guard
            });
            settle().await;
            drop(holder.take());
            holder = Some(next.await.unwrap());
        }
        drop(holder);
        background.await.unwrap();
        let order = order.lock().unwrap();
        let position = order.iter().position(|name| *name == "background").unwrap();
        assert_eq!(position as u64, STARVATION_YIELDS);
    }
}
