//! Bounded native request channels inheriting the authenticated link admission.
use super::*;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
};
use tokio::sync::mpsc;

const FRAGMENT: usize = IO_CHUNK;
const QUEUE: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Packet {
    Open {
        generation: u64,
    },
    Data {
        generation: u64,
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
        last: bool,
    },
    End {
        generation: u64,
    },
    Working {
        generation: u64,
    },
}
impl Packet {
    pub(super) fn validate(&self) -> Result<(), Error> {
        if let Self::Data { bytes, .. } = self
            && (bytes.is_empty() || bytes.len() > FRAGMENT)
        {
            return Err(denied("link fragment quota"));
        }
        Ok(())
    }
    fn generation(&self) -> u64 {
        match self {
            Self::Open { generation }
            | Self::Data { generation, .. }
            | Self::End { generation }
            | Self::Working { generation } => *generation,
        }
    }
}
#[derive(Clone)]
struct Admission {
    local: PrivateKey,
    peer: PublicKey,
    credentials: CredentialChain,
    peer_chain: crate::wire::Chain,
    binding: Commitment,
    proved: std::collections::BTreeSet<ResourceScope>,
    offered: std::collections::BTreeSet<ResourceScope>,
    contact_key: Commitment,
}
struct Slot {
    generation: u64,
    receive: Option<mpsc::Sender<Vec<u8>>>,
    bytes: Vec<u8>,
    total: usize,
    closed: bool,
    ended: bool,
    progress: u64,
}
#[derive(Default)]
struct State {
    closed: bool,
    retired_frames: u64,
    next: u64,
    remote: BTreeMap<u16, u64>,
    reconciling: BTreeMap<bool, u64>,
    next_reconcile: u64,
    remote_reconcile: u64,
    flushed_reconcile: Option<u64>,
    slots: BTreeMap<(bool, u16), Slot>,
}
#[derive(Clone)]
pub struct Handle {
    admission: Admission,
    direction: bool,
    state: Arc<Mutex<State>>,
    send: mpsc::Sender<Frame>,
    events: tokio::sync::watch::Sender<()>,
}
pub struct Channels {
    pub handle: Handle,
    pub outgoing: mpsc::Receiver<Frame>,
}
pub(crate) struct Io {
    handle: Handle,
    key: (bool, u16),
    generation: u64,
    receive: mpsc::Receiver<Vec<u8>>,
    closed: bool,
}
impl Channels {
    pub(super) fn new(session: &NativeSession, direction: bool) -> Self {
        let (send, outgoing) = mpsc::channel(QUEUE);
        Self {
            handle: Handle {
                admission: Admission {
                    local: session.local.clone(),
                    peer: session.peer,
                    credentials: session.credentials.clone(),
                    peer_chain: session.peer_chain.clone(),
                    binding: session.binding,
                    proved: session.proved.clone(),
                    offered: session.offered.clone(),
                    contact_key: session.contact_key,
                },
                direction,
                state: Default::default(),
                send,
                events: tokio::sync::watch::channel(()).0,
            },
            outgoing,
        }
    }
    pub fn reconcile(&self, direction: bool, generation: u64, started: bool) -> Result<(), Error> {
        if direction == self.handle.direction {
            return Err(denied("link reconcile direction"));
        }
        let mut state = self
            .handle
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if state.closed {
            return Err(denied("link ended"));
        }
        if started {
            if state.reconciling.contains_key(&direction) || generation < state.remote_reconcile {
                return Err(denied("link reconcile lifecycle"));
            }
            state.remote_reconcile = generation
                .checked_add(1)
                .ok_or_else(|| denied("link reconcile generation exhausted"))?;
            state.reconciling.insert(direction, generation);
        } else {
            if state.reconciling.get(&direction) != Some(&generation) {
                return Err(denied("link reconcile lifecycle"));
            }
            state.reconciling.remove(&direction);
        }
        self.handle.events.send_replace(());
        Ok(())
    }
    /// Dispatches a data frame without awaiting a slow request handler.
    pub fn accept(&self, frame: Frame) -> Result<Option<NativeSession>, Error> {
        frame.validate()?;
        let Message::Channel(packet) = frame.message else {
            return Err(denied("link channel message"));
        };
        let key = (frame.direction, frame.channel);
        let generation = packet.generation();
        let mut state = self
            .handle
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if state.closed {
            return Err(denied("link ended"));
        }
        if let Packet::Open { .. } = packet {
            if frame.direction == self.handle.direction
                || state.slots.contains_key(&key)
                || generation < state.remote.get(&frame.channel).copied().unwrap_or(0)
            {
                return Err(denied("link channel open quota/sequence"));
            }
            state.remote.insert(
                frame.channel,
                generation
                    .checked_add(1)
                    .ok_or_else(|| denied("link channel generation exhausted"))?,
            );
            let (send, receive) = mpsc::channel(QUEUE);
            state.slots.insert(
                key,
                Slot {
                    generation,
                    receive: Some(send),
                    bytes: Vec::new(),
                    total: 0,
                    closed: false,
                    ended: false,
                    progress: 0,
                },
            );
            return Ok(Some(self.handle.session(key, generation, receive)?));
        }
        let slot = state
            .slots
            .get_mut(&key)
            .ok_or_else(|| denied("unknown link channel"))?;
        if slot.generation != generation {
            return Err(denied("stale link channel"));
        }
        if slot.closed {
            if matches!(packet, Packet::End { .. }) {
                state.slots.remove(&key);
                self.handle.events.send_replace(());
            } else {
                state.retired_frames = state.retired_frames.saturating_add(1);
                tracing::debug!(
                    channel = key.1,
                    generation,
                    retired_frames = state.retired_frames,
                    "retired_channel_frame"
                );
            }
            return Ok(None);
        }
        if slot.ended {
            return Err(denied("data after link channel end"));
        }
        match packet {
            Packet::Data { bytes, last, .. } => {
                slot.total = slot
                    .total
                    .checked_add(bytes.len())
                    .filter(|total| *total <= MAX_SECURE_BYTES)
                    .ok_or_else(|| denied("link channel byte quota"))?;
                if slot.bytes.len() + bytes.len() > MAX_SECURE_FRAME {
                    return Err(denied("link channel message quota"));
                }
                slot.bytes.extend(bytes);
                self.handle.events.send_replace(());
                if last {
                    let Some(receive) = &slot.receive else {
                        return Err(denied("data after link channel end"));
                    };
                    match receive.try_send(std::mem::take(&mut slot.bytes)) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) if !receive.is_closed() => {
                            return Err(denied("link channel queue quota"));
                        }
                        Err(_) => {
                            slot.closed = true;
                            slot.receive.take();
                            state.retired_frames = state.retired_frames.saturating_add(1);
                        }
                    }
                }
            }
            Packet::Working { .. } => {
                slot.progress = slot.progress.saturating_add(1);
                self.handle.events.send_replace(());
            }
            Packet::End { .. } => {
                if !slot.bytes.is_empty() {
                    return Err(denied("unfinished link channel message"));
                }
                slot.ended = true;
                slot.receive.take();
            }
            Packet::Open { .. } => return Err(denied("duplicate link channel")),
        }
        Ok(None)
    }
}
pub struct Reconcile {
    handle: Handle,
    generation: u64,
    closed: bool,
}
impl Reconcile {
    pub async fn close(mut self) -> Result<(), Error> {
        if self.handle.is_closed() {
            return Err(denied("link ended"));
        }
        timeout(
            TIMEOUT,
            self.handle.send.send(Frame::new(
                self.handle.direction,
                Message::Reconcile {
                    generation: self.generation,
                    started: false,
                },
            )),
        )
        .await
        .map_err(|_| timed_out("link reconcile close timeout"))?
        .map_err(|_| denied("link ended"))?;
        let mut events = self.handle.events.subscribe();
        timeout(TIMEOUT, async {
            loop {
                events.borrow_and_update();
                if self
                    .handle
                    .state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .flushed_reconcile
                    == Some(self.generation)
                {
                    return Ok(());
                }
                if self.handle.is_closed() {
                    return Err(denied("link ended before reconcile finish"));
                }
                events.changed().await.map_err(|_| denied("link ended"))?;
            }
        })
        .await
        .map_err(|_| timed_out("link reconcile finish timeout"))??;
        self.mark_closed();
        Ok(())
    }
    fn mark_closed(&mut self) {
        self.closed = true;
        let mut state = self
            .handle
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if state.reconciling.get(&self.handle.direction) == Some(&self.generation) {
            state.reconciling.remove(&self.handle.direction);
        }
        self.handle.events.send_replace(());
    }
}
impl Drop for Reconcile {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.handle.send.try_send(Frame::new(
                self.handle.direction,
                Message::Reconcile {
                    generation: self.generation,
                    started: false,
                },
            ));
            self.mark_closed();
        }
    }
}
impl Handle {
    pub fn retired_frames(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retired_frames
    }
    pub fn is_closed(&self) -> bool {
        self.send.is_closed()
            || self
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .closed
    }
    /// Ends channel ownership even when the transport still owns its outgoing queue.
    pub fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.closed = true;
        state.slots.clear();
        state.reconciling.clear();
        self.events.send_replace(());
    }
    /// Called only after the link writer flushes the final reconcile marker.
    pub fn flushed_reconcile(&self, generation: u64) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.flushed_reconcile = Some(generation);
        self.events.send_replace(());
    }
    pub async fn begin_reconcile(&self) -> Result<Reconcile, Error> {
        let generation = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if state.closed {
                return Err(denied("link ended"));
            }
            if state.reconciling.contains_key(&self.direction) {
                return Err(denied("link reconcile already active"));
            }
            let generation = state.next_reconcile;
            state.next_reconcile = generation
                .checked_add(1)
                .ok_or_else(|| denied("link reconcile generation exhausted"))?;
            state.reconciling.insert(self.direction, generation);
            generation
        };
        let lease = Reconcile {
            handle: self.clone(),
            generation,
            closed: false,
        };
        timeout(
            TIMEOUT,
            self.send.send(Frame::new(
                self.direction,
                Message::Reconcile {
                    generation,
                    started: true,
                },
            )),
        )
        .await
        .map_err(|_| timed_out("link reconcile start timeout"))?
        .map_err(|_| denied("link ended"))?;
        Ok(lease)
    }

    /// Waits for both request directions to finish before ending a short link.
    pub async fn drain(&self) -> Result<(), Error> {
        let mut events = self.events.subscribe();
        timeout(TIMEOUT, async {
            loop {
                events.borrow_and_update();
                let drained = {
                    let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                    state.slots.values().all(|slot| slot.closed) && state.reconciling.is_empty()
                };
                if drained {
                    return Ok(());
                }
                events.changed().await.map_err(|_| denied("link ended"))?;
            }
        })
        .await
        .map_err(|_| timed_out("link drain timeout"))?
    }

    /// Captures one bounded page after a committed cursor, without querying the peer.
    pub async fn push_committed<A: RowApplication>(
        &self,
        replica: &EncryptedReplica<A>,
        cursor: &ScopeFrontier,
    ) -> Result<bool, Error> {
        if !self.admission.proved.contains(&cursor.scope) {
            return Err(denied("unproved link push scope"));
        }
        let page = match replica
            .range_page(
                self.admission.peer,
                &self.admission.credentials,
                cursor,
                None,
                FRAME_BYTES / 8,
            )
            .await
        {
            Err(Error::Rejected(reason)) if reason == "byte quota smaller than one frame" => {
                return Ok(false);
            }
            other => other?,
        };
        if page.behind {
            return Ok(false);
        }
        if page.frames.is_empty() && page.voids.is_empty() {
            return Ok(true);
        }
        let frame = Frame::new(
            self.direction,
            Message::Push {
                scope: cursor.scope,
                frames: page.frames,
                voids: page.voids,
            },
        );
        let bytes = encode(&frame)?;
        if encode(&SignedMessage {
            sequence: u64::MAX,
            signature: self.admission.local.sign(b"push bound"),
            bytes,
        })?
        .len()
            > FRAME_BYTES
        {
            return Ok(false);
        }
        timeout(TIMEOUT, self.send.send(frame))
            .await
            .map_err(|_| timed_out("link push write timeout"))?
            .map_err(|_| denied("link ended"))?;
        Ok(page.next.is_none())
    }
    /// Applies self-contained frames using the same authorization and receive path as a catch-up page.
    pub async fn receive_push<A: RowApplication>(
        &self,
        replica: &EncryptedReplica<A>,
        scope: ResourceScope,
        frames: Vec<EncryptedFrame>,
        voids: Vec<SignedVoid>,
    ) -> Result<(bool, Vec<(PublicKey, u64)>), Error> {
        if !self.admission.offered.contains(&scope)
            || (frames.is_empty() && voids.is_empty())
            || frames.len() + voids.len() > rows::MAX_SECURE_PAGE
        {
            return Err(denied("unproved or overfull link push"));
        }
        replica
            .authorize_scope_peer(self.admission.peer, &self.admission.credentials, scope)
            .await?;
        rows::receive_voids(replica, &voids, &[scope]).await?;
        let mut received = Vec::new();
        for void in &voids {
            for (_, header, _) in void.verify()? {
                received.push((header.public_key, header.seq_num.saturating_add(1)));
            }
        }
        for frame in &frames {
            if frame.scope()? != scope {
                return Err(denied("pushed frame outside its scope"));
            }
            frame.chain()?;
            let header = frame.operation_ref()?.header.clone();
            received.push((
                header.public_key,
                header
                    .seq_num
                    .checked_add(1)
                    .ok_or_else(|| denied("push log exhausted"))?,
            ));
        }
        let mut complete = true;
        for status in replica.receive_migration_all(frames).await {
            complete &= !matches!(
                status?,
                ReceiveStatus::PendingDependencies | ReceiveStatus::MissingKey
            );
        }
        Ok((complete, received))
    }

    pub async fn open(&self) -> Result<NativeSession, Error> {
        let mut events = self.events.subscribe();
        let (key, generation, receive) = timeout(TIMEOUT, async {
            loop {
                events.borrow_and_update();
                let reserved = {
                    let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                    if state.closed {
                        return Err(denied("link ended"));
                    }
                    if let Some(channel) = (2..CHANNELS)
                        .find(|channel| !state.slots.contains_key(&(self.direction, *channel)))
                    {
                        let generation = state.next;
                        state.next = generation
                            .checked_add(1)
                            .ok_or_else(|| denied("link channel generation exhausted"))?;
                        let key = (self.direction, channel);
                        let (send, receive) = mpsc::channel(QUEUE);
                        state.slots.insert(
                            key,
                            Slot {
                                generation,
                                receive: Some(send),
                                bytes: Vec::new(),
                                total: 0,
                                closed: false,
                                ended: false,
                                progress: 0,
                            },
                        );
                        Some((key, generation, receive))
                    } else {
                        None
                    }
                };
                if let Some(reserved) = reserved {
                    return Ok::<_, Error>(reserved);
                }
                events.changed().await.map_err(|_| denied("link ended"))?;
            }
        })
        .await
        .map_err(|_| timed_out("link channel quota timeout"))??;
        let session = self.session(key, generation, receive)?;
        self.send_frame(key, Packet::Open { generation }).await?;
        Ok(session)
    }
    fn session(
        &self,
        key: (bool, u16),
        generation: u64,
        receive: mpsc::Receiver<Vec<u8>>,
    ) -> Result<NativeSession, Error> {
        let admission = &self.admission;
        let binding = signing_bytes(
            "rocky.link-channel.v1",
            &(admission.binding, key, generation),
        )?;
        Ok(NativeSession {
            stream: SessionIo::Channel(Box::new(Io {
                handle: self.clone(),
                key,
                generation,
                receive,
                closed: false,
            })),
            local: admission.local.clone(),
            peer: admission.peer,
            credentials: admission.credentials.clone(),
            peer_chain: admission.peer_chain.clone(),
            chains: Default::default(),
            signing: frame_binding(&binding),
            binding: admission.binding,
            proved: admission.proved.clone(),
            offered: admission.offered.clone(),
            tip_incoming: Vec::new(),
            #[cfg(test)]
            sent_counts: SentCounts::default(),
            contact_requests: 0,
            contact_handed: 0,
            contact_received: 0,
            contact_key: admission.contact_key,
            sent: 0,
            received: 0,
            remaining: MAX_SECURE_BYTES,
            span: crate::network::trace::session(key.1),
            request: None,
            serving: false,
        })
    }
    async fn send_frame(
        &self,
        (direction, channel): (bool, u16),
        packet: Packet,
    ) -> Result<(), Error> {
        if self.is_closed() {
            return Err(denied("link ended"));
        }
        timeout(
            TIMEOUT,
            self.send.send(Frame {
                channel,
                through: Vec::new(),
                direction,
                message: Message::Channel(packet),
            }),
        )
        .await
        .map_err(|_| timed_out("link channel write timeout"))?
        .map_err(|_| denied("link ended"))
    }
}
/// Progress is emitted independently of the response builder's session borrow.
#[derive(Clone)]
pub(crate) struct Progress {
    handle: Handle,
    key: (bool, u16),
    generation: u64,
}
impl Progress {
    pub(crate) async fn run(&self) -> Result<(), Error> {
        loop {
            tokio::time::sleep(WORKING_INTERVAL).await;
            self.handle
                .send_frame(
                    self.key,
                    Packet::Working {
                        generation: self.generation,
                    },
                )
                .await?;
        }
    }
}
impl Io {
    pub(crate) fn progress(&self) -> Progress {
        Progress {
            handle: self.handle.clone(),
            key: self.key,
            generation: self.generation,
        }
    }
    pub(crate) fn retire(&mut self) {
        if !self.closed {
            let _ = self.handle.send.try_send(Frame {
                channel: self.key.1,
                through: Vec::new(),
                direction: self.key.0,
                message: Message::Channel(Packet::End {
                    generation: self.generation,
                }),
            });
            self.mark_closed();
        }
    }

    pub(crate) fn channel(&self) -> u16 {
        self.key.1
    }
    pub async fn send(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Io(super::closed_by_peer()));
        }
        if bytes.is_empty() || bytes.len() > MAX_SECURE_FRAME {
            return Err(denied("link channel message quota"));
        }
        let count = bytes.len().div_ceil(FRAGMENT);
        for (index, bytes) in bytes.chunks(FRAGMENT).enumerate() {
            self.handle
                .send_frame(
                    self.key,
                    Packet::Data {
                        generation: self.generation,
                        bytes: bytes.to_vec(),
                        last: index + 1 == count,
                    },
                )
                .await?;
        }
        Ok(())
    }
    pub async fn receive(&mut self) -> Result<Vec<u8>, Error> {
        self.receive_with_idle(false).await
    }
    pub(crate) async fn receive_with_idle(&mut self, idle: bool) -> Result<Vec<u8>, Error> {
        let mut events = self.handle.events.subscribe();
        let received = || {
            self.handle
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .slots
                .get(&self.key)
                .filter(|slot| slot.generation == self.generation)
                .map_or((0, 0, false), |slot| {
                    (slot.total, slot.progress, !slot.bytes.is_empty())
                })
        };
        let (mut covered, mut progress, started) = received();
        let mut deadline = (!idle || started).then(|| tokio::time::Instant::now() + TIMEOUT);
        loop {
            tokio::select! {
                biased;
                bytes = self.receive.recv() => {
                    return bytes.ok_or_else(|| Error::Io(super::closed_by_peer()));
                }
                _ = async {
                    match deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                } => {
                    self.retire();
                    return Err(timed_out("link channel read timeout"));
                }
                changed = events.changed() => {
                    changed.map_err(|_| Error::Io(super::closed_by_peer()))?;
                    let (total, working, _) = received();
                    // A full fragment earns another deadline; trickles and other channels do not.
                    if working > progress || (total > covered && (deadline.is_none() || total.saturating_sub(covered) >= FRAGMENT)) {
                        progress = working;
                        covered = total;
                        deadline = Some(tokio::time::Instant::now() + TIMEOUT);
                    }
                }
            }
        }
    }
    pub async fn close(&mut self) -> Result<(), Error> {
        if !self.closed {
            self.handle
                .send_frame(
                    self.key,
                    Packet::End {
                        generation: self.generation,
                    },
                )
                .await?;
            self.mark_closed();
        }
        let mut events = self.handle.events.subscribe();
        timeout(TIMEOUT, async {
            loop {
                events.borrow_and_update();
                let pending = self
                    .handle
                    .state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .slots
                    .get(&self.key)
                    .is_some_and(|slot| slot.generation == self.generation);
                if !pending {
                    return Ok(());
                }
                events.changed().await.map_err(|_| denied("link ended"))?;
            }
        })
        .await
        .map_err(|_| timed_out("link channel close timeout"))?
    }
    fn mark_closed(&mut self) {
        self.closed = true;
        let mut state = self
            .handle
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(slot) = state
            .slots
            .get_mut(&self.key)
            .filter(|slot| slot.generation == self.generation)
        {
            slot.closed = true;
            slot.receive.take();
            slot.bytes.clear();
            if slot.ended {
                state.slots.remove(&self.key);
                self.handle.events.send_replace(());
            }
        }
    }
}
impl Drop for Io {
    fn drop(&mut self) {
        self.retire();
    }
}

impl Drop for Channels {
    fn drop(&mut self) {
        self.handle.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn channels() -> Channels {
        let credentials = CredentialChain(vec![]);
        let (send, outgoing) = mpsc::channel(QUEUE);
        Channels {
            handle: Handle {
                admission: Admission {
                    local: PrivateKey::from_bytes(&[7; 32]),
                    peer: PrivateKey::from_bytes(&[8; 32]).public_key(),
                    peer_chain: crate::wire::Chain::new(credentials.clone()).unwrap(),
                    credentials,
                    binding: [1; 32],
                    proved: Default::default(),
                    offered: Default::default(),
                    contact_key: [2; 32],
                },
                direction: false,
                state: Default::default(),
                send,
                events: tokio::sync::watch::channel(()).0,
            },
            outgoing,
        }
    }
    fn frame(channel: u16, packet: Packet) -> Frame {
        Frame {
            channel,
            through: Vec::new(),
            direction: true,
            message: Message::Channel(packet),
        }
    }
    #[tokio::test(start_paused = true)]
    async fn a_timed_out_generation_discards_late_fragments_then_reuses_its_slot() {
        let channels = channels();
        let mut session = channels
            .accept(frame(2, Packet::Open { generation: 0 }))
            .unwrap()
            .unwrap();
        let SessionIo::Channel(io) = &mut session.stream else {
            panic!("channel");
        };
        assert!(io.receive().await.is_err());
        channels.handle.drain().await.unwrap();
        for last in [false, true] {
            channels
                .accept(frame(
                    2,
                    Packet::Data {
                        generation: 0,
                        bytes: vec![7],
                        last,
                    },
                ))
                .unwrap();
        }
        assert_eq!(channels.handle.retired_frames(), 2);
        channels
            .accept(frame(2, Packet::End { generation: 0 }))
            .unwrap();
        let mut next = channels
            .accept(frame(2, Packet::Open { generation: 1 }))
            .unwrap()
            .unwrap();
        channels
            .accept(frame(
                2,
                Packet::Data {
                    generation: 1,
                    bytes: vec![9],
                    last: true,
                },
            ))
            .unwrap();
        let SessionIo::Channel(io) = &mut next.stream else {
            panic!("channel");
        };
        assert_eq!(io.receive().await.unwrap(), vec![9]);
    }

    #[tokio::test]
    async fn losing_the_channel_owner_wakes_reconcile_before_the_writer_drops_its_queue() {
        let mut channels = channels();
        let _outgoing = std::mem::replace(&mut channels.outgoing, mpsc::channel(1).1);
        let handle = channels.handle.clone();
        let reconcile = handle.begin_reconcile().await.unwrap();
        let closing = reconcile.close();
        tokio::pin!(closing);
        tokio::select! {
            result = &mut closing => panic!("reconcile finished before writer or shutdown: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }
        drop(channels);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut closing)
                .await
                .expect("shutdown did not wake reconcile")
                .is_err()
        );
        assert!(handle.is_closed());
        assert!(handle.open().await.is_err());
        assert!(handle.begin_reconcile().await.is_err());
    }

    #[tokio::test]
    async fn dropping_a_receiver_retires_its_partial_message() {
        let channels = channels();
        let session = channels
            .accept(frame(2, Packet::Open { generation: 0 }))
            .unwrap()
            .unwrap();
        channels
            .accept(frame(
                2,
                Packet::Data {
                    generation: 0,
                    bytes: vec![1],
                    last: false,
                },
            ))
            .unwrap();
        drop(session);
        channels
            .accept(frame(
                2,
                Packet::Data {
                    generation: 0,
                    bytes: vec![2],
                    last: true,
                },
            ))
            .unwrap();
        channels
            .accept(frame(2, Packet::End { generation: 0 }))
            .unwrap();
        assert_eq!(channels.handle.retired_frames(), 1);
        assert!(channels.handle.state.lock().unwrap().slots.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn working_renews_only_its_channel_and_the_request_still_has_a_lifetime_limit() {
        let channels = channels();
        let mut session = channels
            .accept(frame(2, Packet::Open { generation: 0 }))
            .unwrap()
            .unwrap();
        let start = tokio::time::Instant::now();
        let work = async {
            loop {
                tokio::time::sleep(WORKING_INTERVAL).await;
                channels
                    .accept(frame(2, Packet::Working { generation: 0 }))
                    .unwrap();
            }
        };
        tokio::pin!(work);
        let result = tokio::select! {
            result = session.answered() => result,
            () = &mut work => unreachable!(),
        };
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("request lifetime timeout")
        );
        assert_eq!(start.elapsed(), REQUEST_LIMIT);
        assert!(channels.handle.state.lock().unwrap().slots[&(true, 2)].closed);
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_response_sends_working_every_four_seconds() {
        let mut channels = channels();
        let session = channels
            .accept(frame(2, Packet::Open { generation: 0 }))
            .unwrap()
            .unwrap();
        let SessionIo::Channel(io) = &session.stream else {
            panic!("channel");
        };
        let progress = io.progress();
        let start = tokio::time::Instant::now();
        let observed = async {
            for index in 1..=4 {
                let frame = channels.outgoing.recv().await.unwrap();
                assert!(matches!(
                    frame.message,
                    Message::Channel(Packet::Working { generation: 0 })
                ));
                assert_eq!(start.elapsed(), WORKING_INTERVAL * index);
            }
        };
        tokio::pin!(observed);
        tokio::select! {
            () = &mut observed => {},
            result = progress.run() => panic!("progress ended: {result:?}"),
        }
    }
    #[tokio::test]
    async fn fragments_close_and_generation_reuse_are_bounded() {
        let mut channels = channels();
        let mut session = channels
            .accept(frame(2, Packet::Open { generation: 0 }))
            .unwrap()
            .unwrap();
        assert!(
            channels
                .accept(frame(2, Packet::Open { generation: 1 }))
                .is_err()
        );
        channels
            .accept(frame(
                2,
                Packet::Data {
                    generation: 0,
                    bytes: vec![1, 2],
                    last: false,
                },
            ))
            .unwrap();
        channels
            .accept(frame(
                2,
                Packet::Data {
                    generation: 0,
                    bytes: vec![3],
                    last: true,
                },
            ))
            .unwrap();
        assert_eq!(
            match &mut session.stream {
                SessionIo::Channel(channel) => channel.receive().await.unwrap(),
                _ => panic!("request channel"),
            },
            [1, 2, 3]
        );
        channels
            .accept(frame(2, Packet::End { generation: 0 }))
            .unwrap();
        session.close().await.unwrap();
        assert!(channels.handle.state.lock().unwrap().slots.is_empty());
        assert!(matches!(
            channels.outgoing.recv().await.unwrap().message,
            Message::Channel(Packet::End { generation: 0 })
        ));
        assert!(
            channels
                .accept(frame(2, Packet::Open { generation: 0 }))
                .is_err()
        );
        let _next = channels
            .accept(frame(2, Packet::Open { generation: 1 }))
            .unwrap()
            .unwrap();
        assert!(
            channels
                .accept(frame(
                    2,
                    Packet::Data {
                        generation: 0,
                        bytes: vec![4],
                        last: true
                    }
                ))
                .is_err()
        );
    }
    #[tokio::test(start_paused = true)]
    async fn a_requester_can_apply_an_answer_before_asking_again() {
        let channels = channels();
        let mut session = channels
            .accept(frame(2, Packet::Open { generation: 0 }))
            .unwrap()
            .unwrap();
        let SessionIo::Channel(io) = &mut session.stream else {
            panic!("request channel")
        };
        let deliver = async {
            tokio::time::sleep(TIMEOUT * 2).await;
            channels
                .accept(frame(
                    2,
                    Packet::Data {
                        generation: 0,
                        bytes: vec![7],
                        last: true,
                    },
                ))
                .unwrap();
        };
        let (received, ()) = tokio::join!(io.receive_with_idle(true), deliver);
        assert_eq!(received.unwrap(), vec![7]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_queued_partial_request_is_already_started() {
        let channels = channels();
        let mut session = channels
            .accept(frame(2, Packet::Open { generation: 0 }))
            .unwrap()
            .unwrap();
        channels
            .accept(frame(
                2,
                Packet::Data {
                    generation: 0,
                    bytes: vec![7],
                    last: false,
                },
            ))
            .unwrap();
        let SessionIo::Channel(io) = &mut session.stream else {
            panic!("request channel")
        };
        let start = tokio::time::Instant::now();
        assert!(
            io.receive_with_idle(true)
                .await
                .unwrap_err()
                .to_string()
                .contains("link channel read timeout")
        );
        assert_eq!(start.elapsed(), TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_started_request_cannot_stall_after_idle() {
        let channels = channels();
        let mut session = channels
            .accept(frame(2, Packet::Open { generation: 0 }))
            .unwrap()
            .unwrap();
        let SessionIo::Channel(io) = &mut session.stream else {
            panic!("request channel")
        };
        let start = tokio::time::Instant::now();
        let deliver = async {
            tokio::time::sleep(TIMEOUT * 2).await;
            channels
                .accept(frame(
                    2,
                    Packet::Data {
                        generation: 0,
                        bytes: vec![7],
                        last: false,
                    },
                ))
                .unwrap();
        };
        let (received, ()) = tokio::join!(io.receive_with_idle(true), deliver);
        assert!(
            received
                .unwrap_err()
                .to_string()
                .contains("link channel read timeout")
        );
        assert_eq!(start.elapsed(), TIMEOUT * 3);
    }

    #[tokio::test(start_paused = true)]
    async fn progressing_reassembly_outlives_one_read_deadline() {
        let channels = channels();
        let mut session = channels
            .accept(frame(2, Packet::Open { generation: 0 }))
            .unwrap()
            .unwrap();
        let SessionIo::Channel(io) = &mut session.stream else {
            panic!("request channel");
        };
        let deliver = async {
            for index in 0..3 {
                tokio::time::sleep(TIMEOUT * 3 / 5).await;
                channels
                    .accept(frame(
                        2,
                        Packet::Data {
                            generation: 0,
                            bytes: vec![index; FRAGMENT],
                            last: index == 2,
                        },
                    ))
                    .unwrap();
            }
        };
        let (received, ()) = tokio::join!(io.receive(), deliver);
        let expected: Vec<_> = (0..3).flat_map(|index| vec![index; FRAGMENT]).collect();
        assert_eq!(received.unwrap(), expected);
    }

    #[tokio::test(start_paused = true)]
    async fn reassembly_still_times_out_after_progress_stops() {
        let channels = channels();
        let mut session = channels
            .accept(frame(2, Packet::Open { generation: 0 }))
            .unwrap()
            .unwrap();
        let SessionIo::Channel(io) = &mut session.stream else {
            panic!("request channel");
        };
        let read = async {
            let start = tokio::time::Instant::now();
            assert!(
                io.receive()
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("link channel read timeout")
            );
            assert_eq!(start.elapsed(), TIMEOUT * 8 / 5);
        };
        let deliver = async {
            tokio::time::sleep(TIMEOUT * 3 / 5).await;
            channels
                .accept(frame(
                    2,
                    Packet::Data {
                        generation: 0,
                        bytes: vec![1; FRAGMENT],
                        last: false,
                    },
                ))
                .unwrap();
        };
        tokio::join!(read, deliver);
    }

    #[tokio::test(start_paused = true)]
    async fn trickles_and_other_channels_do_not_extend_a_read_deadline() {
        let channels = channels();
        let mut session = channels
            .accept(frame(2, Packet::Open { generation: 0 }))
            .unwrap()
            .unwrap();
        let _other = channels
            .accept(frame(3, Packet::Open { generation: 1 }))
            .unwrap();
        let SessionIo::Channel(io) = &mut session.stream else {
            panic!("request channel");
        };
        let read = async {
            let start = tokio::time::Instant::now();
            let error = io.receive().await.unwrap_err();
            assert!(error.to_string().contains("link channel read timeout"));
            assert_eq!(start.elapsed(), TIMEOUT);
        };
        let deliver = async {
            for index in 0..4 {
                tokio::time::sleep(TIMEOUT * 3 / 10).await;
                channels
                    .accept(frame(
                        2,
                        Packet::Data {
                            generation: 0,
                            bytes: vec![0],
                            last: false,
                        },
                    ))
                    .unwrap();
                channels
                    .accept(frame(
                        3,
                        Packet::Data {
                            generation: 1,
                            bytes: vec![index; FRAGMENT],
                            last: false,
                        },
                    ))
                    .unwrap();
            }
        };
        tokio::join!(read, deliver);
    }

    #[test]
    fn oversized_reassembly_and_slow_channel_queues_are_refused() {
        let channels = channels();
        let _session = channels
            .accept(frame(2, Packet::Open { generation: 0 }))
            .unwrap()
            .unwrap();
        for _ in 0..MAX_SECURE_FRAME / FRAGMENT {
            channels
                .accept(frame(
                    2,
                    Packet::Data {
                        generation: 0,
                        bytes: vec![1; FRAGMENT],
                        last: false,
                    },
                ))
                .unwrap();
        }
        assert!(
            channels
                .accept(frame(
                    2,
                    Packet::Data {
                        generation: 0,
                        bytes: vec![1],
                        last: true
                    }
                ))
                .is_err()
        );
        let _other = channels
            .accept(frame(3, Packet::Open { generation: 1 }))
            .unwrap()
            .unwrap();
        for _ in 0..QUEUE {
            channels
                .accept(frame(
                    3,
                    Packet::Data {
                        generation: 1,
                        bytes: vec![1],
                        last: true,
                    },
                ))
                .unwrap();
        }
        assert!(
            channels
                .accept(frame(
                    3,
                    Packet::Data {
                        generation: 1,
                        bytes: vec![1],
                        last: true
                    }
                ))
                .is_err()
        );
        assert!(
            Packet::Data {
                generation: 2,
                bytes: vec![0; FRAGMENT + 1],
                last: true
            }
            .validate()
            .is_err()
        );
        assert!(
            Packet::Data {
                generation: 2,
                bytes: vec![],
                last: true
            }
            .validate()
            .is_err()
        );
    }
}

#[cfg(test)]
mod reconcile_tests {
    use super::*;
    #[tokio::test]
    async fn a_previous_finish_cannot_release_a_new_reconcile() {
        let mut channels = super::tests::channels();
        let first = channels.handle.begin_reconcile().await.unwrap();
        channels.handle.flushed_reconcile(0);
        assert!(channels.handle.begin_reconcile().await.is_err());
        drop(first);
        let second = channels.handle.begin_reconcile().await.unwrap();
        channels.handle.flushed_reconcile(0);
        assert_eq!(
            channels
                .handle
                .state
                .lock()
                .unwrap()
                .reconciling
                .get(&false),
            Some(&1)
        );
        let close = second.close();
        let write = async {
            loop {
                let frame = channels.outgoing.recv().await.unwrap();
                if let Message::Reconcile {
                    generation,
                    started: false,
                } = frame.message
                {
                    channels.handle.flushed_reconcile(generation);
                    if generation == 1 {
                        break;
                    }
                }
            }
        };
        let (closed, ()) = tokio::join!(close, write);
        closed.unwrap();
        assert!(channels.handle.state.lock().unwrap().reconciling.is_empty());
    }
}
