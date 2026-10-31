//! Authenticated live link framing. See `docs/runtime/live-links.md`.
use super::*;
use tokio::io::{ReadHalf, WriteHalf};

/// The handshake's version; its signing label carries it, so another is refused.
pub(super) const HANDSHAKE_VERSION: u32 = 19;
pub const CHANNELS: u16 = 6;
pub mod channels;
mod lanes;
pub use lanes::{Reader, Writer};
pub const FRAME_BYTES: usize = 64 * 1024;
pub const SIGNAL_SCOPES: usize = 64;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CloseReason {
    Authority,
    Duplicate,
    NetworkingDisabled,
    Suspended,
    WorkerDisabled,
    Detached,
    Busy,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    Changed {
        scopes: Vec<ResourceScope>,
        token: [u8; 32],
    },
    Reconcile {
        generation: u64,
        started: bool,
    },
    Push {
        scope: ResourceScope,
        frames: Vec<EncryptedFrame>,
        /// Void records consuming the positions before the frames.
        voids: Vec<SignedVoid>,
    },
    Ready {
        persistent: bool,
    },
    Channel(channels::Packet),
    Close {
        reason: CloseReason,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub channel: u16,
    /// Per-lane delivery barrier for the final reconciliation marker.
    pub through: Vec<u64>,
    /// The request lane: false for the dialer, true for the acceptor.
    pub direction: bool,
    pub message: Message,
}
impl Frame {
    pub fn new(direction: bool, message: Message) -> Self {
        Self {
            through: Vec::new(),
            channel: match message {
                Message::Changed { .. } | Message::Push { .. } | Message::Reconcile { .. } => 1,
                _ => 0,
            },
            direction,
            message,
        }
    }
    fn validate(&self) -> Result<(), Error> {
        if !self.through.is_empty()
            && (self.through.len() != 5
                || !matches!(self.message, Message::Reconcile { started: false, .. }))
        {
            return Err(denied("link delivery barrier"));
        }
        let channel = match &self.message {
            Message::Channel(packet) => {
                packet.validate()?;
                if self.channel < 2 {
                    return Err(denied("link request channel"));
                }
                self.channel
            }
            Message::Changed { .. } | Message::Push { .. } | Message::Reconcile { .. } => 1,
            _ => 0,
        };
        if self.channel >= CHANNELS || self.channel != channel {
            return Err(denied("link channel quota"));
        }
        if let Message::Changed { scopes, .. } = &self.message
            && (scopes.is_empty()
                || scopes.len() > SIGNAL_SCOPES
                || scopes
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != scopes.len())
        {
            return Err(denied("link signal scope quota"));
        }
        if let Message::Push { frames, voids, .. } = &self.message
            && ((frames.is_empty() && voids.is_empty())
                || frames.len() + voids.len() > rows::MAX_SECURE_PAGE)
        {
            return Err(denied("link push frame quota"));
        }
        Ok(())
    }
}

pub struct Link {
    pub peer: PublicKey,
    /// Bytes the handshake itself exchanged, before holdings.
    #[cfg(test)]
    pub(crate) handshake_bytes: usize,
    #[cfg(test)]
    pub(crate) statements_sent: usize,
    pub held: Vec<ResourceScope>,
    pub offered: Vec<ResourceScope>,
    pub direction: bool,
    pub expires: u64,
    pub local_states: std::collections::BTreeMap<ResourceScope, Commitment>,
    pub states: std::collections::BTreeMap<ResourceScope, Commitment>,
    pub channels: channels::Channels,
    pub reader: Reader,
    pub writer: Writer,
}
struct FrameReader {
    stream: ReadHalf<Box<dyn SessionStream>>,
    peer: PublicKey,
    signing: Commitment,
    sequence: u64,
}
struct FrameWriter {
    stream: WriteHalf<Box<dyn SessionStream>>,
    local: PrivateKey,
    signing: Commitment,
    sequence: u64,
}
#[derive(Debug)]
pub struct AuthorityChanged;
impl std::fmt::Display for AuthorityChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("link authority changed during handshake")
    }
}
impl std::error::Error for AuthorityChanged {}
#[derive(Debug)]
pub struct Busy;
impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("live link budget is busy")
    }
}
impl std::error::Error for Busy {}
pub(super) fn timed_out(message: &'static str) -> Error {
    Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, message))
}
impl Link {
    /// Both ends confirm their independent link budget before any data channel opens.
    pub async fn ready(&mut self, persistent: bool) -> Result<bool, Error> {
        let span = tracing::debug_span!(
            "ready",
            peer = crate::network::trace::peer(&self.peer),
            persistent,
            outcome = tracing::field::Empty
        );
        let result =
            tracing::Instrument::instrument(self.ready_inner(persistent), span.clone()).await;
        crate::network::trace::outcome(&span, &result);
        result
    }
    async fn ready_inner(&mut self, persistent: bool) -> Result<bool, Error> {
        let sent = self
            .writer
            .send(Frame::new(self.direction, Message::Ready { persistent }))
            .await;
        let frame = timeout(TIMEOUT, self.reader.receive())
            .await
            .map_err(|_| timed_out("link ready timeout"))??;
        match frame.message {
            Message::Ready { persistent: remote } if frame.direction != self.direction => {
                sent?;
                Ok(persistent && remote)
            }
            Message::Close {
                reason: CloseReason::Busy,
            } => Err(Error::Application(Box::new(Busy))),
            Message::Close {
                reason: CloseReason::Authority,
            } => Err(Error::Application(Box::new(AuthorityChanged))),
            _ => Err(denied("link ready response")),
        }
    }

    /// Authenticates the peer over `stream`: `expected` when dialing, whoever
    /// dialed when accepting. Holdings and scope states follow the handshake.
    pub async fn open<A: RowApplication>(
        stream: impl SessionStream + 'static,
        replica: &EncryptedReplica<A>,
        local: PrivateKey,
        credentials: CredentialChain,
        expected: Option<PublicKey>,
    ) -> Result<Self, Error> {
        Box::pin(Self::open_as(
            stream,
            replica,
            (local, credentials),
            expected,
            (HANDSHAKE_VERSION, false),
        ))
        .await?
        .ok_or_else(|| denied("link handshake required"))
    }
    /// Accepts a link, or answers a pinned contact reference's resolution
    /// (`NativeSession::resolve_peer`) with `None`.
    pub async fn accept_or_resolve<A: RowApplication>(
        stream: impl SessionStream + 'static,
        replica: &EncryptedReplica<A>,
        local: PrivateKey,
        credentials: CredentialChain,
    ) -> Result<Option<Self>, Error> {
        Box::pin(Self::open_as(
            stream,
            replica,
            (local, credentials),
            None,
            (HANDSHAKE_VERSION, true),
        ))
        .await
    }
    /// A handshake under another version, as another build runs.
    #[cfg(test)]
    pub(crate) async fn open_as_version<A: RowApplication>(
        stream: impl SessionStream + 'static,
        replica: &EncryptedReplica<A>,
        (local, credentials): (PrivateKey, CredentialChain),
        expected: Option<PublicKey>,
        version: u32,
    ) -> Result<Self, Error> {
        Box::pin(Self::open_as(
            stream,
            replica,
            (local, credentials),
            expected,
            (version, false),
        ))
        .await?
        .ok_or_else(|| denied("link handshake required"))
    }
    async fn open_as<A: RowApplication>(
        stream: impl SessionStream + 'static,
        replica: &EncryptedReplica<A>,
        local: (PrivateKey, CredentialChain),
        expected: Option<PublicKey>,
        version: (u32, bool),
    ) -> Result<Option<Self>, Error> {
        let span = tracing::debug_span!(
            "admission",
            dialing = expected.is_some(),
            peer = tracing::field::Empty,
            scopes = tracing::field::Empty,
            outcome = tracing::field::Empty
        );
        let result = tracing::Instrument::instrument(
            Self::admit(stream, replica, local, expected, version),
            span.clone(),
        )
        .await;
        if let Ok(Some(link)) = &result {
            span.record("peer", crate::network::trace::peer(&link.peer));
            span.record("scopes", link.held.len() as u64);
        }
        crate::network::trace::outcome(&span, &result);
        result
    }
    async fn admit<A: RowApplication>(
        stream: impl SessionStream + 'static,
        replica: &EncryptedReplica<A>,
        (local, credentials): (PrivateKey, CredentialChain),
        expected: Option<PublicKey>,
        version: (u32, bool),
    ) -> Result<Option<Self>, Error> {
        let side = if expected.is_some() {
            Side::Initiator
        } else {
            Side::Acceptor
        };
        let session = NativeSession::handshake(
            Box::new(stream),
            replica,
            (local, credentials.clone()),
            (side, expected),
            MAX_SECURE_BYTES,
            version,
        )
        .await?;
        let Some(mut session) = session else {
            return Ok(None);
        };
        #[cfg(test)]
        let handshake_bytes = MAX_SECURE_BYTES - session.remaining;
        let mut scopes = Vec::new();
        let mut after = None;
        loop {
            let (page, next) = replica
                .held_scopes(session.local.public_key(), &credentials, after)
                .await?;
            scopes.extend(page);
            if next.is_none() {
                break;
            }
            after = next;
        }
        {
            let inner = replica.inner.lock(crate::replica::Class::Background).await;
            for grant in inner.local_grants(now()?)?.iter() {
                if grant.rows == rocky_core::RowSelection::All
                    && (grant.rights.contains(&rocky_core::Right::Read)
                        || grant.rights.contains(&rocky_core::Right::Custody))
                    && inner.holds(grant.scope).await?
                {
                    scopes.push(grant.scope);
                }
            }
        }
        scopes.sort();
        scopes.dedup();
        // Exchange proofs in handshake order so bounded transports cannot deadlock.
        if side == Side::Initiator {
            session.offer_link_holdings(replica, &scopes).await?;
            session.accept_link_holdings(replica).await?;
        } else {
            session.accept_link_holdings(replica).await?;
            session.offer_link_holdings(replica, &scopes).await?;
        }
        let mut local_states = std::collections::BTreeMap::new();
        let states = if side == Side::Initiator {
            session
                .offer_link_states(replica, &mut local_states)
                .await?;
            session.accept_link_states().await?
        } else {
            let states = session.accept_link_states().await?;
            session
                .offer_link_states(replica, &mut local_states)
                .await?;
            states
        };
        let held = session.proved.iter().copied().collect();
        let channels = channels::Channels::new(&session, side == Side::Acceptor);
        let SessionIo::Native(stream) = session.stream else {
            return Err(denied("link handshake requires a transport"));
        };
        let (read, write) = tokio::io::split(stream);
        Ok(Some(Self {
            peer: session.peer,
            #[cfg(test)]
            handshake_bytes,
            #[cfg(test)]
            statements_sent: session.sent_counts.statements,
            channels,
            states,
            local_states,
            held,
            offered: session.offered.iter().copied().collect(),
            direction: side == Side::Acceptor,
            expires: credentials.expires().min(session.credentials.expires()),
            reader: Reader::new(FrameReader {
                stream: read,
                peer: session.peer,
                signing: session.signing,
                sequence: session.received,
            }),
            writer: Writer::new(FrameWriter {
                stream: write,
                local: session.local,
                signing: session.signing,
                sequence: session.sent,
            }),
        }))
    }
}
impl Link {
    /// Carries request channels until either side ends the link: sessions the
    /// peer opens go to `incoming`. Signals and pushes are ignored; an
    /// embedder that needs live changes drives the link itself, as the SDK
    /// does. Liveness is the transport's.
    pub async fn drive(
        self,
        incoming: tokio::sync::mpsc::Sender<NativeSession>,
    ) -> Result<(), Error> {
        let Self {
            mut reader,
            mut writer,
            mut channels,
            ..
        } = self;
        let mut outgoing =
            std::mem::replace(&mut channels.outgoing, tokio::sync::mpsc::channel(1).1);
        let receive = async {
            loop {
                let frame = match reader.receive().await {
                    Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Ok(());
                    }
                    frame => frame?,
                };
                match frame.message {
                    Message::Channel(_) => {
                        if let Some(session) = channels.accept(frame)? {
                            incoming
                                .send(session)
                                .await
                                .map_err(|_| denied("link ended"))?;
                        }
                    }
                    Message::Reconcile {
                        generation,
                        started,
                    } => channels.reconcile(frame.direction, generation, started)?,
                    Message::Close { .. } => return Ok(()),
                    _ => {}
                }
            }
        };
        let send = async {
            while let Some(frame) = outgoing.recv().await {
                let finished = match frame.message {
                    Message::Reconcile {
                        generation,
                        started: false,
                    } => Some(generation),
                    _ => None,
                };
                writer.send(frame).await?;
                if let Some(generation) = finished {
                    channels.handle.flushed_reconcile(generation);
                }
            }
            writer.finish().await
        };
        tokio::select! {
            result = receive => result,
            result = send => result,
        }
    }
}
/// A scope's committed receipt state, flushed before its token can leave.
pub async fn scope_token<A: RowApplication>(
    replica: &EncryptedReplica<A>,
    scope: ResourceScope,
) -> Result<Commitment, Error> {
    let (bytes, flusher, commit) = {
        let inner = replica.inner.lock(crate::replica::Class::Background).await;
        let frontier = inner.frontier(scope).await?;
        let logs: Vec<_> = frontier
            .logs
            .into_iter()
            .map(|log| (log.author, log.held))
            .collect();
        let mut metadata = Vec::new();
        if let Some(graph) = inner.graphs.get(&scope.domain) {
            for seal in &graph.seals {
                metadata.push(seal.id().map_err(credential)?);
            }
            for opening in &graph.openings {
                metadata.push(opening.id().map_err(credential)?);
            }
            for movement in &graph.moves {
                metadata.push(movement.id().map_err(credential)?);
            }
            for line in &graph.genesis_lines {
                metadata.push(line.id().map_err(credential)?);
            }
            for proof in &graph.finalities {
                metadata.push(proof.id().map_err(credential)?);
            }
            for checkpoint in &graph.checkpoints {
                metadata.push(checkpoint.id().map_err(credential)?);
            }
        }
        for (_, batch) in inner.pending_tips(None).await? {
            for statement in batch.iter().filter(|s| s.scope() == scope.domain) {
                metadata.push(statement.id()?);
            }
        }
        metadata.sort_unstable();
        metadata.dedup();
        let bytes = encode(&(logs, metadata))?;
        (bytes, inner.flusher.clone(), inner.commit)
    };
    flusher.flush(commit)?;
    Ok(rocky_core::commitment("rocky.link-scope.v2", &bytes))
}
impl NativeSession {
    async fn offer_link_states<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        local_states: &mut std::collections::BTreeMap<ResourceScope, Commitment>,
    ) -> Result<(), Error> {
        let scopes: Vec<_> = self.proved.iter().copied().collect();
        for batch in scopes.chunks(SIGNAL_SCOPES) {
            let mut states = Vec::new();
            for scope in batch {
                let token = scope_token(replica, *scope).await?;
                local_states.insert(*scope, token);
                states.push((*scope, token));
            }
            self.send(super::Message::LinkState(states)).await?;
            self.acknowledged("link state acknowledgement").await?;
        }
        self.send(super::Message::Acknowledged).await
    }
    async fn accept_link_states(
        &mut self,
    ) -> Result<std::collections::BTreeMap<ResourceScope, Commitment>, Error> {
        let mut states = std::collections::BTreeMap::new();
        loop {
            match self.receive().await? {
                super::Message::Acknowledged => {
                    if states.len() != self.offered.len() {
                        return Err(denied("incomplete link state"));
                    }
                    return Ok(states);
                }
                super::Message::LinkState(batch)
                    if !batch.is_empty() && batch.len() <= SIGNAL_SCOPES =>
                {
                    for (scope, token) in batch {
                        if !self.offered.contains(&scope) || states.insert(scope, token).is_some() {
                            return Err(denied("unproved link state"));
                        }
                    }
                    self.send(super::Message::Acknowledged).await?;
                }
                _ => return Err(denied("link state response")),
            }
        }
    }
    async fn offer_link_holdings<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scopes: &[ResourceScope],
    ) -> Result<(), Error> {
        for batch in scopes.chunks(SIGNAL_SCOPES) {
            let allowed = replica
                .peer_holds(self.peer, &self.credentials, batch)
                .await?;
            if allowed.is_empty() {
                continue;
            }
            let proofs = replica.holding_proofs(self.binding, &allowed).await?;
            let partitions = replica
                .tuple_proofs(self.peer, &self.credentials, &allowed)
                .await?;
            for message in holdings::prove_pages(&allowed, &proofs, &partitions)? {
                let HoldingMessage::Prove { ref scopes, .. } = message else {
                    return Err(denied("link holding response"));
                };
                let requested = scopes.clone();
                self.send(message).await?;
                let HoldingMessage::Proved { scopes: accepted } =
                    self.reply::<HoldingMessage>().await?
                else {
                    return Err(denied("link holding response"));
                };
                if accepted.iter().any(|scope| !requested.contains(scope))
                    || accepted
                        .iter()
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        != accepted.len()
                {
                    return Err(denied("link unoffered holding"));
                }
                self.offered.extend(accepted);
            }
        }
        self.send(super::Message::Acknowledged).await
    }
    async fn accept_link_holdings<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
    ) -> Result<(), Error> {
        loop {
            match self.receive().await? {
                super::Message::Acknowledged => return Ok(()),
                super::Message::Holdings(HoldingMessage::Prove {
                    scopes,
                    proofs,
                    partitions,
                }) => {
                    self.accept_link_proofs(replica, &scopes, &proofs, &partitions)
                        .await?;
                    let mut accepted = Vec::new();
                    for scope in scopes {
                        if self.require_holding(replica, scope).await.is_ok()
                            && replica
                                .authorize_scope_peer(self.peer, &self.credentials, scope)
                                .await
                                .is_ok()
                        {
                            self.proved.insert(scope);
                            accepted.push(scope);
                        } else {
                            self.proved.remove(&scope);
                        }
                    }
                    self.send(HoldingMessage::Proved { scopes: accepted })
                        .await?;
                }
                _ => return Err(denied("link holding request")),
            }
        }
    }
}
impl FrameWriter {
    /// Finishes queued frames before a transport resets an unfinished stream.
    pub async fn finish(&mut self) -> Result<(), Error> {
        timeout(TIMEOUT, self.stream.shutdown())
            .await
            .map_err(|_| timed_out("link finish timeout"))?
            .map_err(Error::Io)
    }
    pub async fn send(&mut self, frame: Frame) -> Result<(), Error> {
        frame.validate()?;
        let bytes = encode(&frame)?;
        let frame = encode(&SignedMessage {
            sequence: self.sequence,
            signature: self
                .local
                .sign(&frame_signing_bytes(&self.signing, self.sequence, &bytes)?),
            bytes,
        })?;
        if frame.len() > FRAME_BYTES {
            return Err(denied("link frame quota"));
        }
        let expired = || timed_out("link write timeout");
        write_progress(
            &mut self.stream,
            &(frame.len() as u32).to_be_bytes(),
            expired,
        )
        .await?;
        write_progress(&mut self.stream, &frame, expired).await?;
        timeout(TIMEOUT, self.stream.flush())
            .await
            .map_err(|_| expired())?
            .map_err(Error::Io)?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| denied("link sequence exhausted"))?;
        Ok(())
    }
}
/// A link the peer ended between frames; its kind stays `UnexpectedEof`.
pub(super) fn closed_by_peer() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "the peer closed the link",
    )
}
impl FrameReader {
    /// Idle reads have no deadline; started frames must keep making chunk progress.
    pub async fn receive(&mut self) -> Result<Frame, Error> {
        let first = self.stream.read_u8().await.map_err(|error| {
            Error::Io(match error.kind() {
                std::io::ErrorKind::UnexpectedEof => closed_by_peer(),
                _ => error,
            })
        })?;
        let expired = || timed_out("link read timeout");
        let mut header = [first, 0, 0, 0];
        read_progress(&mut self.stream, &mut header[1..], expired).await?;
        let length = u32::from_be_bytes(header) as usize;
        if length == 0 || length > FRAME_BYTES {
            return Err(denied("link frame quota"));
        }
        let mut bytes = vec![0; length];
        read_progress(&mut self.stream, &mut bytes, expired).await?;
        let signed: SignedMessage = decode(&bytes)?;
        if signed.sequence != self.sequence
            || !self.peer.verify(
                &frame_signing_bytes(&self.signing, signed.sequence, &signed.bytes)?,
                &signed.signature,
            )
        {
            return Err(denied("link signature/sequence"));
        }
        let frame: Frame = decode(&signed.bytes)?;
        frame.validate()?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| denied("link sequence exhausted"))?;
        Ok(frame)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn channels_are_bounded_and_control_has_its_own_channel() {
        let close = || Message::Close {
            reason: CloseReason::NetworkingDisabled,
        };
        assert!(Frame::new(false, close()).validate().is_ok());
        assert!(
            Frame {
                channel: CHANNELS,
                through: Vec::new(),
                direction: false,
                message: close()
            }
            .validate()
            .is_err()
        );
        assert!(
            Frame {
                channel: 1,
                through: Vec::new(),
                direction: false,
                message: close()
            }
            .validate()
            .is_err()
        );
        assert!(
            Frame::new(
                false,
                Message::Changed {
                    scopes: vec![],
                    token: [0; 32]
                }
            )
            .validate()
            .is_err()
        );
    }
    #[test]
    fn scope_bounds_and_maximal_frame_fit_the_byte_quota() {
        let scope = ResourceScope {
            domain: rocky_core::Scope {
                mesh: rocky_core::MeshId([255; 16]),
                app: rocky_core::AppId([255; 16]),
                domain: rocky_core::DomainId([255; 16]),
            },
            table: [255; 32],
            encryption: [255; 32],
        };
        let scopes: Vec<_> = (0..SIGNAL_SCOPES)
            .map(|index| ResourceScope {
                table: {
                    let mut table = scope.table;
                    table[0] = index as u8;
                    table
                },
                ..scope
            })
            .collect();
        let frame = Frame::new(
            true,
            Message::Changed {
                scopes: scopes.clone(),
                token: [255; 32],
            },
        );
        frame.validate().unwrap();
        let bytes = encode(&frame).unwrap();
        let signed = SignedMessage {
            sequence: u64::MAX,
            bytes,
            signature: PrivateKey::new().sign(b"bounds"),
        };
        assert!(encode(&signed).unwrap().len() <= FRAME_BYTES);
        assert!(
            Frame::new(
                false,
                Message::Changed {
                    scopes: vec![scope; 2],
                    token: [0; 32]
                }
            )
            .validate()
            .is_err()
        );
        let mut too_many = scopes;
        too_many.push(ResourceScope {
            table: [254; 32],
            ..scope
        });
        assert!(
            Frame::new(
                false,
                Message::Changed {
                    scopes: too_many,
                    token: [0; 32]
                }
            )
            .validate()
            .is_err()
        );
    }
    #[test]
    fn only_current_link_name_and_handshake_label() {
        // Transport and handshake each accept one current version.
        assert_eq!(
            rocky_core::net::Protocol::named(b"rocky/link/5"),
            Some(rocky_core::net::Protocol::Link)
        );
        assert_eq!(rocky_core::net::Protocol::named(b"rocky/link/1"), None);
        assert_eq!(rocky_core::net::Protocol::named(b"rocky/link/2"), None);
        assert_eq!(rocky_core::net::Protocol::named(b"rocky/link/3"), None);
        assert_eq!(rocky_core::net::Protocol::named(b"rocky/link/4"), None);
        assert_eq!(session_label(HANDSHAKE_VERSION), "rocky.link.v19");
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_signed_link_frame_can_arrive_across_multiple_read_deadlines() {
        let signer = PrivateKey::from_bytes(&[7; 32]);
        let binding = [3; 32];
        let frame = Frame {
            channel: 2,
            through: Vec::new(),
            direction: false,
            message: Message::Channel(channels::Packet::Data {
                generation: 0,
                bytes: vec![1; IO_CHUNK],
                last: true,
            }),
        };
        let body = encode(&frame).unwrap();
        let bytes = encode(&SignedMessage {
            sequence: 0,
            signature: signer.sign(&frame_signing_bytes(&binding, 0, &body).unwrap()),
            bytes: body,
        })
        .unwrap();
        assert!(bytes.len() > IO_CHUNK);
        let (near, mut far) = tokio::io::duplex(IO_CHUNK * 2);
        let (stream, _) = tokio::io::split(Box::new(near) as Box<dyn SessionStream>);
        let mut reader = FrameReader {
            stream,
            peer: signer.public_key(),
            signing: binding,
            sequence: 0,
        };
        let deliver = async {
            far.write_u32(bytes.len() as u32).await.unwrap();
            for chunk in bytes.chunks(IO_CHUNK) {
                tokio::time::sleep(TIMEOUT * 3 / 5).await;
                far.write_all(chunk).await.unwrap();
            }
        };
        let (received, ()) = tokio::join!(reader.receive(), deliver);
        assert!(
            matches!(received.unwrap().message, Message::Channel(channels::Packet::Data { bytes, last: true, .. }) if bytes == vec![1; IO_CHUNK])
        );
        assert_eq!(reader.sequence, 1);
    }
    #[tokio::test(start_paused = true)]
    async fn oversized_and_empty_headers_are_refused_before_body_read() {
        for length in [0, FRAME_BYTES as u32 + 1] {
            let (near, mut far) = tokio::io::duplex(16);
            let (stream, _) = tokio::io::split(Box::new(near) as Box<dyn SessionStream>);
            let mut reader = FrameReader {
                stream,
                peer: PrivateKey::new().public_key(),
                signing: [0; 32],
                sequence: 0,
            };
            far.write_u32(length).await.unwrap();
            assert!(
                reader
                    .receive()
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("link frame quota")
            );
        }
    }
}

/// Request sessions on a link both of whose ends this process drives.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    pub(crate) type End<'a, A> = (&'a EncryptedReplica<A>, PrivateKey, CredentialChain);
    /// A dialed and an accepted link over an in-memory pipe.
    pub(crate) async fn sessions<A: RowApplication, B: RowApplication>(
        client: End<'_, A>,
        server: End<'_, B>,
    ) -> Result<(NativeSession, NativeSession), Error> {
        let (near, far) = tokio::io::duplex(64 * 1024);
        sessions_over(near, far, client, server).await
    }
    /// Both ends of a loopback TCP connection.
    pub(crate) async fn tcp() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (near, far) = tokio::join!(tokio::net::TcpStream::connect(address), listener.accept());
        let (near, far) = (near.unwrap(), far.unwrap().0);
        // Request frames must not wait for Nagle's algorithm and delayed acknowledgments.
        near.set_nodelay(true).unwrap();
        far.set_nodelay(true).unwrap();
        (near, far)
    }
    /// The dialed and the accepted end of a link, each as its handshake ended.
    pub(crate) async fn links<A: RowApplication, B: RowApplication>(
        near: impl SessionStream + 'static,
        far: impl SessionStream + 'static,
        (client, client_key, client_chain): End<'_, A>,
        (server, server_key, server_chain): End<'_, B>,
    ) -> (Result<Link, Error>, Result<Link, Error>) {
        let expected = server_key.public_key();
        tokio::join!(
            Link::open(near, client, client_key, client_chain, Some(expected)),
            Link::open(far, server, server_key, server_chain, None),
        )
    }
    /// Drives both ends and opens one request channel: the client's session
    /// and the server's session answering it.
    pub(crate) async fn requests(
        mut dialed: Link,
        mut accepted: Link,
    ) -> Result<(NativeSession, NativeSession), Error> {
        let (near, far) = tokio::join!(dialed.ready(false), accepted.ready(false));
        near?;
        far?;
        let handle = dialed.channels.handle.clone();
        let (served, mut incoming) = tokio::sync::mpsc::channel(4);
        tokio::spawn(dialed.drive(tokio::sync::mpsc::channel(1).0));
        tokio::spawn(accepted.drive(served));
        let session = handle.open().await?;
        let answering = incoming.recv().await.ok_or_else(|| denied("link ended"))?;
        Ok((session, answering))
    }
    /// The client's request session and the server's session answering it.
    pub(crate) async fn sessions_over<A: RowApplication, B: RowApplication>(
        near: impl SessionStream + 'static,
        far: impl SessionStream + 'static,
        client: End<'_, A>,
        server: End<'_, B>,
    ) -> Result<(NativeSession, NativeSession), Error> {
        let (dialed, accepted) = links(near, far, client, server).await;
        requests(dialed?, accepted?).await
    }
}
