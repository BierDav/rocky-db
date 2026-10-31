//! Network-service-owned links, signals and liveness.
use super::*;
use rocky_secure::network::link::{self, CloseReason, Frame, Message};
use std::collections::BTreeSet;
mod io;
mod liveness;

pub(super) const BUDGET: usize = 32;

struct Entry {
    opened_at: u64,
    /// The transport's live path measurements, when it reports them.
    paths: Option<Arc<dyn crate::transport::PathSource>>,
    id: u64,
    dialed: bool,
    persistent: bool,
    /// Requests in flight that keep a link open which is not persistent.
    shorts: usize,
    /// Delay publication back to an origin until its durable intake updates our cursor.
    receiving: usize,
    handle: link::channels::Handle,
    authority: watch::Receiver<u64>,
    close: watch::Sender<Option<CloseReason>>,
    changed: watch::Sender<Option<Vec<ResourceScope>>>,
    frontiers: BTreeMap<ResourceScope, [u8; 32]>,
    cursors: BTreeMap<ResourceScope, rocky_secure::ScopeFrontier>,
}
pub(super) struct Registry {
    pub(super) publishing: Mutex<()>,
    entries: std::sync::Mutex<BTreeMap<PublicKey, Entry>>,
    opening: std::sync::Mutex<BTreeMap<PublicKey, usize>>,
    next: AtomicU64,
    events: watch::Sender<()>,
    #[cfg(test)]
    pub closing: AtomicU64,
    #[cfg(test)]
    pub(super) push_gate: std::sync::Mutex<Option<Arc<Semaphore>>>,
    #[cfg(test)]
    pub(super) dropped_pushes: AtomicU64,
}
impl Default for Registry {
    fn default() -> Self {
        Self {
            publishing: Mutex::new(()),
            entries: Default::default(),
            opening: Default::default(),
            next: AtomicU64::new(0),
            events: watch::channel(()).0,
            #[cfg(test)]
            closing: AtomicU64::new(0),
            #[cfg(test)]
            push_gate: Default::default(),
            #[cfg(test)]
            dropped_pushes: AtomicU64::new(0),
        }
    }
}
pub(super) struct Opening<'a> {
    node: &'a Node,
    service: &'a Link,
    peer: PublicKey,
}
impl Drop for Opening<'_> {
    fn drop(&mut self) {
        let mut opening = self
            .service
            .live
            .opening
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = opening.get_mut(&self.peer) {
            *count -= 1;
            if *count == 0 {
                opening.remove(&self.peer);
            }
        }
        drop(opening);
        self.node.link_status_changed();
    }
}
/// Cleanup belongs to the admitted stream, including when a duplicate replaces it.
pub(super) struct ShortLink<'a> {
    registry: &'a Registry,
    peer: PublicKey,
    id: Option<u64>,
}
impl Drop for ShortLink<'_> {
    fn drop(&mut self) {
        self.registry.close_short(self.peer, self.id);
    }
}
struct Receiving<'a> {
    registry: &'a Registry,
    peer: PublicKey,
    id: Option<u64>,
}
impl Drop for Receiving<'_> {
    fn drop(&mut self) {
        let mut entries = self
            .registry
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = entries
            .get_mut(&self.peer)
            .filter(|entry| Some(entry.id) == self.id)
        {
            entry.receiving = entry.receiving.saturating_sub(1);
        }
        drop(entries);
        self.registry.events.send_replace(());
    }
}
impl Registry {
    fn receiving(&self, peer: PublicKey) -> Receiving<'_> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let id = entries.get_mut(&peer).map(|entry| {
            entry.receiving += 1;
            entry.id
        });
        Receiving {
            registry: self,
            peer,
            id,
        }
    }
    pub fn nodes(&self) -> Vec<PublicKey> {
        let mut nodes: Vec<_> = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .copied()
            .collect();
        nodes.extend(
            self.opening
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .keys()
                .copied(),
        );
        nodes
    }
    pub fn status(&self, peer: PublicKey) -> Value {
        let source = {
            let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
            entries.get(&peer).map(|entry| {
                (
                    entry.opened_at,
                    entry.paths.clone(),
                    entry.close.borrow().is_some()
                        || entry.handle.is_closed()
                        || entry.authority.has_changed().unwrap_or(true),
                )
            })
        };
        if let Some((opened, source, closing)) = source {
            // Measured now, outside the registry lock.
            let paths = source.map(|source| source.paths()).unwrap_or_default();
            let round_trip = paths
                .iter()
                .find(|path| path.selected)
                .map(|path| path.rtt.as_millis().to_string());
            return json!({
                "state": if closing { "closing" } else { "open" },
                "opened": opened.to_string(),
                "round_trip_ms": round_trip,
                "paths": paths.iter().map(path_json).collect::<Vec<_>>(),
            });
        }
        let opening = self.opening.lock().unwrap_or_else(PoisonError::into_inner);
        json!({"state": if opening.contains_key(&peer) { "opening" } else { "closed" }, "opened": null, "round_trip_ms": null, "paths": []})
    }

    pub async fn wait_inbound_short(&self, peer: PublicKey) -> Result<(), Failure> {
        let mut events = self.events.subscribe();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                events.borrow_and_update();
                if !self.inbound_short(peer) {
                    return Ok(());
                }
                events.changed().await.map_err(|_| "link registry ended")?;
            }
        })
        .await
        .map_err(|_| "incoming short reconcile did not finish")?
    }

    pub fn inbound_short(&self, peer: PublicKey) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&peer)
            .is_some_and(|entry| !entry.persistent && !entry.dialed)
    }

    pub fn close_peer(&self, peer: PublicKey) {
        if let Some(entry) = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&peer)
        {
            entry.close.send_replace(Some(CloseReason::Detached));
        }
    }

    /// Keeps the link with `peer` for one request. A link that is not
    /// persistent closes when its last request ends: requests share it.
    pub fn short(&self, peer: PublicKey) -> ShortLink<'_> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let id = entries.get_mut(&peer).map(|entry| {
            entry.shorts += 1;
            entry.id
        });
        ShortLink {
            registry: self,
            peer,
            id,
        }
    }

    fn close_short(&self, peer: PublicKey, id: Option<u64>) {
        if let Some(entry) = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(&peer)
            && Some(entry.id) == id
        {
            entry.shorts = entry.shorts.saturating_sub(1);
            if entry.shorts == 0 && !entry.persistent {
                entry.close.send_replace(Some(CloseReason::Detached));
            }
        }
    }

    pub fn handle(&self, peer: PublicKey) -> Option<link::channels::Handle> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&peer)
            .filter(|entry| {
                entry.close.borrow().is_none()
                    && !entry.handle.is_closed()
                    && !entry.authority.has_changed().unwrap_or(true)
            })
            .map(|entry| entry.handle.clone())
    }
    pub async fn wait_empty(&self) {
        let mut events = self.events.subscribe();
        loop {
            events.borrow_and_update();
            if self
                .entries
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty()
            {
                return;
            }
            if events.changed().await.is_err() {
                return;
            }
        }
    }
    pub fn close(&self, reason: CloseReason) {
        for entry in self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
        {
            entry.close.send_replace(Some(reason));
        }
    }
    pub fn contains(&self, peer: PublicKey) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&peer)
            .is_some_and(|entry| {
                entry.close.borrow().is_none()
                    && !entry.handle.is_closed()
                    && !entry.authority.has_changed().unwrap_or(true)
            })
    }
    #[cfg(test)]
    pub fn dialed(&self, peer: PublicKey) -> Option<bool> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&peer)
            .map(|entry| entry.dialed)
    }
    #[cfg(test)]
    pub fn id(&self, peer: PublicKey) -> Option<u64> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&peer)
            .map(|entry| entry.id)
    }
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}
impl Node {
    pub(super) fn opening<'a>(&'a self, service: &'a Link, peer: PublicKey) -> Opening<'a> {
        *service
            .live
            .opening
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(peer)
            .or_default() += 1;
        self.link_status_changed();
        Opening {
            node: self,
            service,
            peer,
        }
    }
    fn link_status_changed(&self) {
        self.link_revision.fetch_add(1, Ordering::SeqCst);
        let status = self.sync_status.borrow().clone();
        self.synced(status);
    }

    pub(super) async fn publish_links(self: Arc<Self>, service: Arc<Link>) {
        let mut stage = service.stage.subscribe();
        let mut frames = self.replica.observe_frames().await;
        let mut revisions = self.replica.observe_revision();
        let mut ready = service.live.events.subscribe();
        loop {
            tokio::select! {
                _ = stage.wait_for(|stage| *stage != Stage::Open) => break,
                changed = frames.changed() => { if changed.is_err() { break; } },
                changed = ready.changed() => { if changed.is_err() { break; } },
                changed = revisions.changed() => { if changed.is_err() { break; } },
            }
            settle().await;
            if self.automatic.load(Ordering::SeqCst)
                && self.online.load(Ordering::SeqCst)
                && let Err(error) = self.signal_links(&service).await
            {
                self.activity
                    .record_changed("link_signal_failed", json!({"error":error.to_string()}));
            }
        }
    }
    pub(super) async fn open_links(self: &Arc<Self>, service: &Arc<Link>) {
        if !self.automatic.load(Ordering::SeqCst) || !self.online.load(Ordering::SeqCst) {
            return;
        }
        let settings = self.settings.lock().await.clone();
        let targets = self.dialed(&settings);
        let attempts = stream::iter(targets)
            .map(|(peer, contact)| {
                let node = self.clone();
                let service = service.clone();
                let settings = settings.clone();
                async move {
                    if service.live.contains(peer)
                        || !node
                            .retries
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .get(&peer)
                            .is_none_or(|retry| {
                                !retry.short
                                    && retry.link_retry.ready()
                                    && (retry.link || retry.retry.ready())
                            })
                    {
                        return;
                    }
                    let _opening = node.opening(&service, peer);
                    let mut attempt = node.observations.begin(
                        peer.to_hex(),
                        crate::AttemptOperation::OpenLink,
                        crate::AttemptStage::Dial,
                    );
                    let result = async {
                        let stream = crate::enrollment::dial(
                            &*service.transport,
                            &contact.addresses(service.transport.kind()),
                            Protocol::Link,
                        )
                        .await?;
                        attempt.stage(crate::AttemptStage::Admission);
                        node.admit_link(service.clone(), stream, Some(peer), settings, None)
                            .await
                    }
                    .await;
                    let failure = result
                        .as_ref()
                        .err()
                        .map(|error| crate::status::failure(error, &attempt.current_stage()));
                    attempt.finish(failure);
                    if let Err(error) = result {
                        {
                            let mut retries =
                                node.retries.lock().unwrap_or_else(PoisonError::into_inner);
                            let state =
                                retries.entry(peer).or_insert_with(|| node.peer_retry(peer));
                            state.link = true;
                            state.link_retry.failed();
                        }
                        let _ = node.absorb_revocations(Some(&error)).await;
                        if node.learned.load(Ordering::SeqCst) {
                            node.wake_sync();
                        }
                        // Reconciliation retries the link; only busy refusal permits native sync.
                        node.activity.record_changed(
                            "link_attempt_failed",
                            json!({"peer":peer.to_hex(),"error":error.to_string()}),
                        );
                    }
                }
            })
            .buffer_unordered(4);
        tokio::pin!(attempts);
        while attempts.next().await.is_some() {}
    }
    pub(super) async fn admit_link(
        self: &Arc<Self>,
        service: Arc<Link>,
        mut stream: Stream,
        expected: Option<PublicKey>,
        settings: Shared<Settings>,
        handshake_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    ) -> Result<(), Failure> {
        if !self.foreground.load(Ordering::SeqCst)
            || !self.online.load(Ordering::SeqCst)
            || *service.stage.borrow() != Stage::Open
        {
            return Err("live links are disabled".into());
        }
        let mut authority = self.replica.observe_authority().await;
        let local = PrivateKey::from_bytes(&self.vault.get("node")?);
        let own = local.public_key();
        let paths = stream.paths();
        let lanes = stream.take_lanes();
        let opened = match expected {
            Some(_) => Box::pin(link::Link::open(
                stream,
                &self.replica,
                local,
                settings.credentials.clone(),
                expected,
            ))
            .await
            .map(Some),
            // An inbound stream may only resolve a pinned contact reference.
            None => {
                Box::pin(link::Link::accept_or_resolve(
                    stream,
                    &self.replica,
                    local,
                    settings.credentials.clone(),
                ))
                .await
            }
        };
        let mut opened = match opened {
            Err(_) if expected.is_some_and(|peer| service.live.contains(peer)) => return Ok(()),
            other => match other? {
                Some(opened) => opened,
                None => return Ok(()),
            },
        };
        opened.attach_lanes(lanes)?;
        if !self.foreground.load(Ordering::SeqCst)
            || !self.online.load(Ordering::SeqCst)
            || *service.stage.borrow() != Stage::Open
            || authority.has_changed()?
        {
            let _ = opened
                .writer
                .send(Frame::new(
                    opened.direction,
                    Message::Close {
                        reason: CloseReason::Authority,
                    },
                ))
                .await;
            let _ = opened.writer.finish().await;
            return Err(Box::new(rocky_secure::Error::Application(Box::new(
                link::AuthorityChanged,
            ))));
        }
        authority.borrow_and_update();
        self.absorb_revocations(None).await?;
        if authority.has_changed()? {
            let _ = opened
                .writer
                .send(Frame::new(
                    opened.direction,
                    Message::Close {
                        reason: CloseReason::Authority,
                    },
                ))
                .await;
            let _ = opened.writer.finish().await;
            return Err(Box::new(rocky_secure::Error::Application(Box::new(
                link::AuthorityChanged,
            ))));
        }
        drop(handshake_permit);
        let permit = if expected.is_none() {
            match service.live_budget.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    service.refused.fetch_add(1, Ordering::Relaxed);
                    let _ = opened
                        .writer
                        .send(Frame::new(
                            opened.direction,
                            Message::Close {
                                reason: CloseReason::Busy,
                            },
                        ))
                        .await;
                    let _ = opened.writer.finish().await;
                    return Err("live link budget is busy".into());
                }
            }
        } else {
            None
        };
        let persistent = match opened.ready(self.automatic.load(Ordering::SeqCst)).await {
            Err(_) if expected.is_some_and(|peer| service.live.contains(peer)) => return Ok(()),
            other => other?,
        };
        let peer = opened.peer;
        let dialed = expected.is_some();
        let preferred = own < peer;
        let id = service.live.next.fetch_add(1, Ordering::Relaxed);
        let close = watch::channel(None).0;
        let changed = watch::channel(None).0;
        let mut frontiers = BTreeMap::new();
        let mut cursors = BTreeMap::new();
        for scope in &opened.held {
            cursors.insert(*scope, self.replica.frontier(*scope).await?);
            let token = match opened.local_states.get(scope) {
                Some(token) => *token,
                None => self.link_scope_state(*scope).await?,
            };
            frontiers.insert(*scope, token);
        }
        let initial: Vec<_> = frontiers
            .iter()
            .filter(|(scope, token)| opened.states.get(scope) != Some(token))
            .map(|(scope, _)| *scope)
            .take(link::SIGNAL_SCOPES)
            .collect();
        if !initial.is_empty() {
            changed.send_replace(Some(initial));
        }
        let accepted = {
            self.replica.flush().await?;
            if !self.foreground.load(Ordering::SeqCst) {
                return Err("live links are disabled in the background".into());
            }
            let mut entries = service
                .live
                .entries
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            // Crossed dials keep the preferred direction. A peer opens a
            // second persistent link the same way only once it lost the
            // first, as a restarted process does: that one replaces it.
            if entries.get(&peer).is_some_and(|old| {
                ((old.dialed == preferred && old.dialed != dialed)
                    || (old.dialed == dialed && !persistent))
                    && !old.handle.is_closed()
                    && old.close.borrow().is_none()
                    && !old.authority.has_changed().unwrap_or(true)
            }) {
                false
            } else {
                if let Some(old) = entries.insert(
                    peer,
                    Entry {
                        opened_at: now()?,
                        paths: paths.clone(),
                        id,
                        dialed,
                        persistent,
                        shorts: 0,
                        receiving: 0,
                        handle: opened.channels.handle.clone(),
                        authority: authority.clone(),
                        close: close.clone(),
                        changed: changed.clone(),
                        frontiers,
                        cursors,
                    },
                ) {
                    old.close.send_replace(Some(CloseReason::Duplicate));
                    self.activity.record(
                        "link_closed",
                        json!({"peer":peer.to_hex(),"reason":"duplicate","error":null}),
                    );
                }
                true
            }
        };
        if !accepted {
            let _ = opened
                .writer
                .send(Frame::new(
                    opened.direction,
                    Message::Close {
                        reason: CloseReason::Duplicate,
                    },
                ))
                .await;
            let _ = opened.writer.finish().await;
            return Ok(());
        }
        if persistent || dialed {
            self.inbound_sync(peer);
        } else {
            self.reset_retry(Some(peer));
        }
        {
            let mut met = self.met.lock().unwrap_or_else(PoisonError::into_inner);
            met.insert(peer, now()?);
            if met.len() > MET
                && let Some(oldest) = met.iter().min_by_key(|(_, at)| **at).map(|(peer, _)| *peer)
            {
                met.remove(&oldest);
            }
            let mut retries = self.retries.lock().unwrap_or_else(PoisonError::into_inner);
            let state = retries.entry(peer).or_insert_with(|| self.peer_retry(peer));
            state.link = false;
            state.short = !persistent;
            state.link_retry.wake();
            state.retry.wake();
            state.pending |= persistent || dialed;
            if state.pending && (persistent || dialed) {
                self.link_events.send_replace(());
            }
        }
        if let Ok(mut reached) = self.reached()
            && let Some(last) = reached.get_mut(&peer)
        {
            last.error = None;
        }
        service.live.events.send_replace(());
        self.activity.record(
            "link_opened",
            json!({"peer":peer.to_hex(),"reason": if dialed { "dialed" } else { "accepted" }}),
        );
        self.link_status_changed();
        let node = self.clone();
        // The stage watch owns cancellation even for outbound links.
        let close_rx = close.subscribe();
        let changed_tx = changed.clone();
        crate::reactor::spawn_local("live_link", async move {
            let started = tokio::time::Instant::now();
            let _permit = permit;
            let result = node
                .run_link(&service, opened, close_rx, changed_tx, authority)
                .await;
            let removed = {
                let mut entries = service
                    .live
                    .entries
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if entries.get(&peer).is_some_and(|entry| entry.id == id) {
                    entries.remove(&peer);
                    true
                } else {
                    false
                }
            };
            if removed {
                service.live.events.send_replace(());
                node.activity.record("link_closed", json!({"peer":peer.to_hex(),"reason":result.as_ref().copied().unwrap_or("error"),"error":result.as_ref().err().map(ToString::to_string)}));
                node.link_status_changed();
                if result.is_ok() && !persistent && !dialed && node.automatic.load(Ordering::SeqCst)
                {
                    node.link_pending(peer);
                }
                if let Err(error) = &result
                    && *service.stage.borrow() == Stage::Open
                {
                    if let Ok(mut reached) = node.reached() {
                        let last = reached.entry(peer).or_insert_with(|| Reached {
                            at: now().unwrap_or_default(),
                            error: None,
                            refused: vec![],
                            waiting: vec![],
                            held: vec![],
                        });
                        last.error = Some(error.to_string());
                    }
                    let mut retries = node.retries.lock().unwrap_or_else(PoisonError::into_inner);
                    let state = retries.entry(peer).or_insert_with(|| node.peer_retry(peer));
                    state.link_retry.survived(started.elapsed());
                    state.retry.survived(started.elapsed());
                    state.link = persistent;
                    if persistent {
                        state.link_retry.failed();
                    } else {
                        state.pending = true;
                        state.retry.failed();
                    }
                    drop(retries);
                    node.link_events.send_replace(());
                }
            }
        });
        Ok(())
    }
    pub(super) async fn signal_links(&self, service: &Link) -> Result<(), Failure> {
        let _publishing = service.live.publishing.lock().await;
        let holdings: Vec<_> = service
            .live
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(_, entry)| entry.receiving == 0)
            .map(|(peer, entry)| {
                (
                    *peer,
                    entry.id,
                    entry.handle.clone(),
                    entry.frontiers.clone(),
                    entry.cursors.clone(),
                )
            })
            .collect();
        let attempts = stream::iter(holdings)
            .map(|(peer, id, handle, old, cursors)| async move {
                let mut frontiers = old.clone();
                let mut next = cursors.clone();
                let mut scopes = BTreeSet::new();
                for (scope, cursor) in &cursors {
                    let token = self.link_scope_state(*scope).await?;
                    if old.get(scope) == Some(&token) {
                        continue;
                    }
                    // Capture the cursor before export; a later commit must remain pending.
                    let frontier = self.replica.frontier(*scope).await?;
                    let rows_changed = frontier != *cursor;
                    let pushed =
                        rows_changed && handle.push_committed(&self.replica, cursor).await?;
                    if !pushed {
                        scopes.insert(*scope);
                    }
                    frontiers.insert(*scope, token);
                    next.insert(*scope, frontier);
                }
                self.replica.flush().await?;
                let mut entries = service
                    .live
                    .entries
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let Some(entry) = entries
                    .get_mut(&peer)
                    .filter(|entry| entry.id == id && entry.receiving == 0)
                else {
                    return Ok::<_, Failure>(());
                };
                entry.frontiers = frontiers;
                entry.cursors = next;
                if !scopes.is_empty() {
                    if let Some(pending) = entry.changed.borrow().as_ref() {
                        scopes.extend(pending);
                    }
                    // Unsent scopes keep their old token so the next publication can send them.
                    for scope in scopes.iter().skip(link::SIGNAL_SCOPES) {
                        if let Some(token) = old.get(scope) {
                            entry.frontiers.insert(*scope, *token);
                        }
                    }
                    entry
                        .changed
                        .send_replace(Some(scopes.into_iter().take(link::SIGNAL_SCOPES).collect()));
                }
                Ok::<_, Failure>(())
            })
            .buffer_unordered(4);
        tokio::pin!(attempts);
        let mut first = None;
        while let Some(result) = attempts.next().await {
            if let Err(error) = result {
                first.get_or_insert(error);
            }
        }
        if let Some(error) = first {
            return Err(error);
        }
        Ok(())
    }
    async fn received_push(
        &self,
        service: &Link,
        peer: PublicKey,
        scope: ResourceScope,
        received: Vec<(PublicKey, u64)>,
    ) -> Result<(), Failure> {
        let frontier = self.replica.frontier(scope).await?;
        let token = self.link_scope_state(scope).await?;
        let mut entries = service
            .live
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(entry) = entries.get_mut(&peer) else {
            return Ok(());
        };
        let Some(cursor) = entry.cursors.get_mut(&scope) else {
            return Ok(());
        };
        for (author, sequence) in received {
            if let Some(log) = frontier.log(author) {
                let mut shared = *log;
                shared.held = shared.held.min(sequence);
                shared.applied = shared.applied.min(sequence);
                if let Some(held) = cursor.logs.iter_mut().find(|held| held.author == author) {
                    held.held = held.held.max(shared.held);
                    held.applied = held.applied.max(shared.applied);
                } else {
                    cursor.logs.push(shared);
                }
            }
        }
        cursor.logs.sort_by_key(|log| log.author);
        if *cursor == frontier {
            entry.frontiers.insert(scope, token);
        }
        Ok(())
    }
    async fn link_scope_state(&self, scope: ResourceScope) -> Result<[u8; 32], Failure> {
        Ok(link::scope_token(&self.replica, scope).await?)
    }
    async fn signal_token(&self, scopes: &[ResourceScope]) -> Result<[u8; 32], Failure> {
        let mut state = Vec::new();
        for scope in scopes {
            state.push((*scope, self.link_scope_state(*scope).await?));
        }
        self.replica.flush().await?;
        Ok(commitment(
            "rocky.link-batch.v1",
            &serde_json::to_vec(&state)?,
        ))
    }
    fn reopen_link(&self, peer: PublicKey) {
        self.reset_retry(Some(peer));
        self.retries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(peer)
            .or_default()
            .link = true;
        self.link_events.send_replace(());
    }
    fn link_pending(&self, peer: PublicKey) {
        let mut retries = self.retries.lock().unwrap_or_else(PoisonError::into_inner);
        retries
            .entry(peer)
            .or_insert_with(|| self.peer_retry(peer))
            .pending = true;
        drop(retries);
        self.link_events.send_replace(());
    }
}

/// One measured path in link status; integers are decimal strings.
fn path_json(path: &crate::transport::NetworkPath) -> Value {
    json!({
        "selected": path.selected,
        "kind": path.kind,
        "remote": path.remote,
        "local": path.local,
        "rtt_us": path.rtt.as_micros().to_string(),
        "mtu": path.mtu.to_string(),
        "window": path.window.to_string(),
        "sent_bytes": path.sent_bytes.to_string(),
        "sent_datagrams": path.sent_datagrams.to_string(),
        "received_bytes": path.received_bytes.to_string(),
        "received_datagrams": path.received_datagrams.to_string(),
        "lost_packets": path.lost_packets.to_string(),
        "lost_bytes": path.lost_bytes.to_string(),
        "congestion_events": path.congestion_events.to_string(),
    })
}

#[cfg(test)]
pub(super) fn control_probe(
    near: link::Link,
    far: link::Link,
) -> (
    std::sync::mpsc::Receiver<Result<(), Failure>>,
    tokio::task::JoinHandle<()>,
) {
    let (near_direction, far_direction) = (near.direction, far.direction);
    let mut near = io::Io::start(near, None);
    let mut far = io::Io::start(far, None);
    let (done, answer) = std::sync::mpsc::sync_channel(1);
    let task = tokio::spawn(async move {
        let result: Result<(), Failure> = async {
            near.send(Frame::new(
                near_direction,
                Message::Close {
                    reason: CloseReason::Duplicate,
                },
            ))
            .await?;
            let _ = far.receive().await?;
            far.send(Frame::new(
                far_direction,
                Message::Close {
                    reason: CloseReason::Duplicate,
                },
            ))
            .await?;
            let _ = near.receive().await?;
            Ok(())
        }
        .await;
        let _ = done.send(result);
    });
    (answer, task)
}
