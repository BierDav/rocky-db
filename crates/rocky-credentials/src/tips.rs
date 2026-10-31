//! Domain-scoped seal, tip-opening and bookmark statements.
use crate::{
    CredentialChain, Endorsement, Error, IdentityProvider, PublicKey, RevocationSet, SealFinality,
    SignedCheckpointRecord, decode_bounded, denied, encode,
};
use rocky_core::{Commitment, Scope, TipId};
use serde::{Deserialize, Serialize};
use std::{cmp::Reverse, collections::BTreeSet};

pub const SEAL_FORMAT: u32 = 1;
pub const TIP_OPENING_FORMAT: u32 = 2;
pub const BOOKMARK_MOVE_FORMAT: u32 = 1;
pub const GENESIS_LINE_FORMAT: u32 = 1;
pub const MAX_BOOKMARK_NAME: usize = 128;

/// Genesis uses the current schema digest; its domain is the graph's scope.
pub fn genesis_tip(schema: Commitment) -> TipId {
    TipId(rocky_core::commitment("rocky.genesis-tip.v1", &schema))
}

/// Last included sequence of one node's author log, ordered by author number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorMark {
    pub author: u32,
    pub sequence: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SealAction {
    Continue { schema: Commitment },
    Close,
}
/// A position of a tip's coordinated log and the running hash after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogPoint {
    pub position: u64,
    pub running: Commitment,
}
/// What the owner's recovery seal of a stuck tip abandons: the committed
/// entries of the tip's log after `retained` through `replaced`, the exact
/// commit it ends. See `docs/runtime/stuck-recovery.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recovery {
    /// The end of the prefix that stays: `retained ≤ replaced`.
    pub retained: LogPoint,
    pub replaced: LogPoint,
}
impl Recovery {
    fn validate(&self) -> Result<(), Error> {
        if self.retained.position > self.replaced.position
            || self.replaced.position >= rocky_core::MAX_COUNTER
            || (self.retained.position == self.replaced.position
                && self.retained.running != self.replaced.running)
        {
            return Err(denied("invalid recovery"));
        }
        Ok(())
    }
    /// Whether the entry at `position` of the sealed tip's log is abandoned.
    pub fn abandons(&self, position: u64) -> bool {
        self.retained.position < position && position <= self.replaced.position
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealStatement {
    pub format: u32,
    pub scope: Scope,
    pub tip: TipId,
    pub frontier: Vec<AuthorMark>,
    pub action: SealAction,
    /// Only the owner's `continue` seal of a stuck tip carries one.
    pub recovery: Option<Recovery>,
}
impl SealStatement {
    pub fn validate(&self) -> Result<(), Error> {
        if self.format != SEAL_FORMAT {
            return Err(denied("unsupported seal format"));
        }
        if let Some(recovery) = &self.recovery {
            recovery.validate()?;
            if self.action == SealAction::Close {
                return Err(denied("a recovery seal continues its tip"));
            }
        }
        if self.frontier.len() > 256
            || self
                .frontier
                .windows(2)
                .any(|pair| pair[0].author >= pair[1].author)
            || self.frontier.iter().any(|mark| {
                mark.author == 0
                    || mark.author > crate::MAX_AUTHOR
                    || mark.sequence > i64::MAX as u64
            })
        {
            return Err(denied("invalid seal frontier"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipOpeningStatement {
    pub format: u32,
    pub scope: Scope,
    pub seal: Commitment,
    pub schema: Commitment,
    pub minimum_in_sync: u32,
}
impl TipOpeningStatement {
    pub fn validate(&self) -> Result<(), Error> {
        if self.format != TIP_OPENING_FORMAT {
            return Err(denied("unsupported tip opening format"));
        }
        if self.minimum_in_sync == 0 {
            return Err(denied("tip minimum in-sync size must be positive"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookmarkMoveStatement {
    pub format: u32,
    pub scope: Scope,
    pub name: String,
    pub from: Option<TipId>,
    pub to: Option<TipId>,
}
impl BookmarkMoveStatement {
    pub fn validate(&self) -> Result<(), Error> {
        if self.format != BOOKMARK_MOVE_FORMAT {
            return Err(denied("unsupported bookmark move format"));
        }
        if self.name.is_empty()
            || self.name.len() > MAX_BOOKMARK_NAME
            || self.name.chars().any(char::is_control)
            || self.from == self.to
        {
            return Err(denied("invalid bookmark move"));
        }
        Ok(())
    }
}

/// The owner's minimum of distinct trusted nodes whose acknowledgments make
/// a seal on the genesis line final. Several resolve to the largest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisLineStatement {
    pub format: u32,
    pub scope: Scope,
    pub minimum_in_sync: u32,
}
impl GenesisLineStatement {
    pub fn validate(&self) -> Result<(), Error> {
        if self.format != GENESIS_LINE_FORMAT {
            return Err(denied("unsupported genesis line format"));
        }
        if self.minimum_in_sync == 0 || self.minimum_in_sync as usize > crate::MAX_FINALITY_ACKS {
            return Err(denied("genesis line minimum out of range"));
        }
        Ok(())
    }
}

macro_rules! signed_statement {
    ($signed:ident, $statement:ident, $format:ident, $label:literal, $id:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $signed {
            pub statement: $statement,
            endorsement: Endorsement,
        }
        impl $signed {
            pub fn sign(
                statement: $statement,
                owner: &dyn IdentityProvider,
            ) -> Result<Self, Error> {
                Self::endorse(statement, owner, &CredentialChain::default())
            }
            pub fn endorse(
                statement: $statement,
                signer: &dyn IdentityProvider,
                chain: &CredentialChain,
            ) -> Result<Self, Error> {
                statement.validate()?;
                let signed = Self {
                    endorsement: Endorsement::sign(signer, chain, $label, &statement)?,
                    statement,
                };
                signed.to_bytes()?;
                Ok(signed)
            }
            pub fn verify(&self, publisher: PublicKey, graph: &TipGraph) -> Result<(), Error> {
                self.check(publisher, graph, None)
            }
            pub fn verify_current(
                &self,
                publisher: PublicKey,
                graph: &TipGraph,
                revocations: &RevocationSet,
                time: u64,
            ) -> Result<(), Error> {
                self.check(publisher, graph, Some((revocations, time)))
            }
            fn check(
                &self,
                publisher: PublicKey,
                graph: &TipGraph,
                current: Option<(&RevocationSet, u64)>,
            ) -> Result<(), Error> {
                self.statement.validate()?;
                graph.check_scope(self.statement.scope)?;
                let trusted = self.endorsement.verify_tip_statement(
                    publisher,
                    self.statement.scope,
                    $label,
                    &self.statement,
                    current,
                )?;
                self.check_graph(graph, trusted)
            }
            pub fn endorsement(&self) -> &Endorsement {
                &self.endorsement
            }
            pub fn id(&self) -> Result<Commitment, Error> {
                Ok(rocky_core::commitment($id, &self.to_bytes()?))
            }
            pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
                let bytes = encode(self)?;
                if bytes.len() > crate::MAX_CREDENTIAL_BYTES {
                    return Err(denied("tip statement quota"));
                }
                Ok(bytes)
            }
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                #[derive(Deserialize)]
                struct Format {
                    format: u32,
                }
                #[derive(Deserialize)]
                struct Envelope {
                    statement: Format,
                }
                if bytes.len() > crate::MAX_CREDENTIAL_BYTES {
                    return Err(denied("tip statement quota"));
                }
                let envelope: Envelope = p2panda_core::cbor::decode_cbor(bytes)
                    .map_err(|_| denied("invalid tip statement"))?;
                if envelope.statement.format != $format {
                    return Err(denied(concat!("unsupported ", $label, " format")));
                }
                let signed: Self = decode_bounded(bytes, crate::MAX_CREDENTIAL_BYTES)?;
                signed.statement.validate()?;
                Ok(signed)
            }
        }
    };
}
pub(crate) use signed_statement;
signed_statement!(
    SignedSeal,
    SealStatement,
    SEAL_FORMAT,
    "rocky.seal.v1",
    "rocky.seal.id.v1"
);
signed_statement!(
    SignedTipOpening,
    TipOpeningStatement,
    TIP_OPENING_FORMAT,
    "rocky.tip-opening.v2",
    "rocky.tip-opening.id.v2"
);
signed_statement!(
    SignedGenesisLine,
    GenesisLineStatement,
    GENESIS_LINE_FORMAT,
    "rocky.genesis-line.v1",
    "rocky.genesis-line.id.v1"
);
signed_statement!(
    SignedBookmarkMove,
    BookmarkMoveStatement,
    BOOKMARK_MOVE_FORMAT,
    "rocky.bookmark-move.v1",
    "rocky.bookmark-move.id.v1"
);

impl SignedSeal {
    fn check_graph(&self, graph: &TipGraph, _trusted: bool) -> Result<(), Error> {
        if self.statement.recovery.is_some() && !self.endorsement.chain.0.is_empty() {
            return Err(denied("only the owner signs a recovery seal"));
        }
        let schema = graph.schema_any(self.statement.tip)?;
        if self.statement.recovery.is_some()
            && matches!(self.statement.action, SealAction::Continue { schema: next } if next != schema)
        {
            return Err(denied("a recovery seal must keep its parent's schema"));
        }
        Ok(())
    }
    /// The recovery of a seal `owner` signed directly: what a coordinator
    /// checks before ending a stuck log. Devices verify it in the graph.
    pub fn verify_recovery(&self, owner: PublicKey) -> Result<&Recovery, Error> {
        self.statement.validate()?;
        let recovery = self
            .statement
            .recovery
            .as_ref()
            .ok_or_else(|| denied("not a recovery seal"))?;
        if !self.endorsement.chain.0.is_empty() {
            return Err(denied("only the owner signs a recovery seal"));
        }
        self.endorsement
            .verify(owner, "rocky.seal.v1", &self.statement)?;
        Ok(recovery)
    }
    pub fn successor(&self) -> Result<Option<TipId>, Error> {
        match self.statement.action {
            SealAction::Continue { .. } => Ok(Some(TipId(self.id()?))),
            SealAction::Close => Ok(None),
        }
    }
}
impl SignedTipOpening {
    fn check_graph(&self, graph: &TipGraph, trusted: bool) -> Result<(), Error> {
        graph.seal_by_id(self.statement.seal)?;
        if !trusted && !graph.migration_opening(self, false)? {
            return Err(denied("an issuer only opens migration successors"));
        }
        Ok(())
    }
    pub fn tip(&self) -> Result<TipId, Error> {
        Ok(TipId(self.id()?))
    }
}
impl SignedGenesisLine {
    fn check_graph(&self, _graph: &TipGraph, _trusted: bool) -> Result<(), Error> {
        if !self.endorsement.chain.0.is_empty() {
            return Err(denied("only the owner signs the genesis line's minimum"));
        }
        Ok(())
    }
}
impl SignedBookmarkMove {
    fn check_graph(&self, graph: &TipGraph, trusted: bool) -> Result<(), Error> {
        if let Some(from) = self.statement.from {
            graph.schema_any(from)?;
        }
        if let Some(to) = self.statement.to {
            graph.schema_any(to)?;
        }
        if !trusted {
            match (self.statement.from, self.statement.to) {
                (Some(from), Some(to)) if graph.succeeds_any(from, to)? => {}
                _ => {
                    return Err(denied(
                        "an issuer only moves bookmarks forward along schema successors",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Who signed a tip statement, in the order races resolve by: the owner,
/// then a trusted identity, then an issuer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TipAuthority {
    Issuer,
    Trusted,
    Owner,
}
impl TipAuthority {
    /// Reads the shape of an endorsement admission already verified: no
    /// links is the owner, one owner-direct trusted grant for `scope` a
    /// trusted identity, anything else an issuer.
    pub fn of(endorsement: &Endorsement, scope: Scope) -> Self {
        match endorsement.chain.0.as_slice() {
            [] => Self::Owner,
            [link]
                if link
                    .capability
                    .extended()
                    .is_ok_and(|extended| extended.trusted == Some(scope)) =>
            {
                Self::Trusted
            }
            _ => Self::Issuer,
        }
    }
}

/// Pure graph resolution over already verified statements. Durable admission
/// verifies statements and their dependencies before adding them to this value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipGraph {
    pub scope: Scope,
    pub genesis_schema: Commitment,
    pub seals: Vec<SignedSeal>,
    pub openings: Vec<SignedTipOpening>,
    pub moves: Vec<SignedBookmarkMove>,
    pub genesis_lines: Vec<SignedGenesisLine>,
    pub finalities: Vec<SealFinality>,
    pub checkpoints: Vec<SignedCheckpointRecord>,
    /// Seals, moves and checkpoint records a revocation ended the signer of, and finality
    /// records it left below their line's minimum: kept, inspectable, and
    /// left out of resolution. See [`Self::exclude_revoked`].
    #[serde(skip)]
    pub revoked: BTreeSet<Commitment>,
}
type BookmarkWalk<'a> = (
    Option<TipId>,
    Vec<&'a SignedBookmarkMove>,
    Vec<(TipId, TipId)>,
);
impl TipGraph {
    pub fn new(scope: Scope, genesis_schema: Commitment) -> Self {
        Self {
            scope,
            genesis_schema,
            seals: Vec::new(),
            openings: Vec::new(),
            moves: Vec::new(),
            genesis_lines: Vec::new(),
            finalities: Vec::new(),
            checkpoints: Vec::new(),
            revoked: BTreeSet::new(),
        }
    }
    /// Leaves out of resolution every seal, opening, move and checkpoint record whose
    /// signer's chain `revocations` ends; the owner's never are. Returns whether the set
    /// changed, so callers resolve again.
    pub fn exclude_revoked(&mut self, revocations: &RevocationSet) -> Result<bool, Error> {
        let mut revoked = BTreeSet::new();
        let signed = self
            .seals
            .iter()
            .map(|seal| (seal.id(), &seal.endorsement().chain))
            .chain(
                self.openings
                    .iter()
                    .map(|opening| (opening.id(), &opening.endorsement().chain)),
            )
            .chain(
                self.moves
                    .iter()
                    .map(|movement| (movement.id(), &movement.endorsement().chain)),
            )
            .chain(
                self.checkpoints
                    .iter()
                    .map(|record| (record.id(), &record.endorsement().chain)),
            );
        for (id, chain) in signed {
            for link in &chain.0 {
                if revocations.ends(link)? {
                    revoked.insert(id?);
                    break;
                }
            }
        }
        // Revoked acknowledgments no longer count toward a seal's finality.
        for record in &self.finalities {
            let minimum = match self.finality_minimum(record) {
                Ok(minimum) => minimum,
                Err(_) => continue,
            };
            if record.acknowledgments.len() - record.revoked(revocations)? < minimum {
                revoked.insert(record.id()?);
            }
        }
        let changed = revoked != self.revoked;
        self.revoked = revoked;
        Ok(changed)
    }
    /// The order races resolve by: higher authority first, then the lower
    /// digest. Smaller wins.
    fn precedence(
        &self,
        endorsement: &Endorsement,
        id: Commitment,
    ) -> (Reverse<TipAuthority>, Commitment) {
        (Reverse(TipAuthority::of(endorsement, self.scope)), id)
    }
    /// Whether a finality record that revocation left whole names `seal`.
    /// Admission verified the record against its line's minimum.
    pub fn is_final(&self, seal: Commitment) -> Result<bool, Error> {
        for record in &self.finalities {
            if record.seal == seal && !self.revoked.contains(&record.id()?) {
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// The checkpoints listed at `seal` that no revocation ended.
    pub fn checkpoints_at(&self, seal: Commitment) -> Result<Vec<&SignedCheckpointRecord>, Error> {
        let mut listed = Vec::new();
        for record in &self.checkpoints {
            if record.statement.seal == seal && !self.revoked.contains(&record.id()?) {
                listed.push(record);
            }
        }
        Ok(listed)
    }
    /// The minimum of distinct trusted nodes a seal of `tip` needs to be
    /// final: its line's opening's, or on the genesis line the largest the
    /// owner signed; none while the owner signed none.
    pub fn line_minimum(&self, tip: TipId) -> Result<Option<usize>, Error> {
        let root = self.line_root_any(tip)?;
        if root == self.genesis() {
            return Ok(self
                .genesis_lines
                .iter()
                .filter(|line| line.statement.scope == self.scope)
                .map(|line| line.statement.minimum_in_sync as usize)
                .max());
        }
        for opening in &self.openings {
            if opening.statement.scope == self.scope && opening.tip()? == root {
                return Ok(Some(opening.statement.minimum_in_sync as usize));
            }
        }
        Err(denied("unknown tip"))
    }
    fn finality_minimum(&self, record: &SealFinality) -> Result<usize, Error> {
        let seal = self.seal_by_id(record.seal)?;
        self.line_minimum(seal.statement.tip)?
            .ok_or_else(|| denied("the genesis line has no signed minimum"))
    }
    /// Verifies a finality record against the graph: it names a held seal,
    /// its acknowledgments name that seal's tip and continuation, and
    /// enough distinct trusted nodes signed them.
    pub fn verify_finality(
        &self,
        record: &SealFinality,
        publisher: PublicKey,
        current: Option<(&RevocationSet, u64)>,
    ) -> Result<(), Error> {
        record.validate()?;
        self.check_scope(record.scope)?;
        let seal = self.seal_by_id(record.seal)?;
        if record.terminal() != Some((seal.statement.tip, seal.successor()?)) {
            return Err(denied("seal finality names another terminal"));
        }
        if let Some(recovery) = seal.statement.recovery {
            let position = recovery.replaced.position + 1;
            let running =
                rocky_core::coordinated_chain(recovery.replaced.running, position, record.seal);
            if record
                .acknowledgments
                .iter()
                .any(|ack| ack.statement.position != position || ack.statement.running != running)
            {
                return Err(denied("recovery finality names another replaced head"));
            }
        }
        if record.verified_nodes(publisher, current)? < self.finality_minimum(record)? {
            return Err(denied("seal finality below its line's minimum"));
        }
        Ok(())
    }
    pub fn genesis(&self) -> TipId {
        genesis_tip(self.genesis_schema)
    }
    pub(crate) fn check_scope(&self, scope: Scope) -> Result<(), Error> {
        if scope != self.scope {
            return Err(denied("tip statement names another domain"));
        }
        Ok(())
    }
    /// Concurrent seals have one winner, independent of receipt order: a
    /// final seal, then the highest authority, then the lower digest.
    /// Revoked seals never win.
    pub fn seal(&self, tip: TipId) -> Result<Option<&SignedSeal>, Error> {
        type Key = (Reverse<bool>, (Reverse<TipAuthority>, Commitment));
        let mut winner: Option<(Key, &SignedSeal)> = None;
        for seal in self
            .seals
            .iter()
            .filter(|seal| seal.statement.tip == tip && seal.statement.scope == self.scope)
        {
            let id = seal.id()?;
            if self.revoked.contains(&id) {
                continue;
            }
            let key = (
                Reverse(self.is_final(id)?),
                self.precedence(seal.endorsement(), id),
            );
            if winner.as_ref().is_none_or(|(current, _)| key < *current) {
                winner = Some((key, seal));
            }
        }
        Ok(winner.map(|(_, seal)| seal))
    }
    /// Whether the winning seal of `tip` is the owner's recovery and
    /// abandons the entry at `position` of the tip's coordinated log.
    pub fn abandons(&self, tip: TipId, position: u64) -> Result<bool, Error> {
        Ok(self.seal(tip)?.is_some_and(|seal| {
            seal.statement
                .recovery
                .is_some_and(|recovery| recovery.abandons(position))
        }))
    }
    /// The authority a statement was signed with.
    pub fn authority(&self, endorsement: &Endorsement) -> TipAuthority {
        TipAuthority::of(endorsement, self.scope)
    }
    pub fn seal_by_id(&self, id: Commitment) -> Result<&SignedSeal, Error> {
        for seal in &self.seals {
            if seal.statement.scope == self.scope && seal.id()? == id {
                return Ok(seal);
            }
        }
        Err(denied("unknown seal"))
    }
    /// Each tip commits its schema. Losing seals
    /// remain inspectable, but their continuations never become active.
    pub fn schema(&self, tip: TipId) -> Result<Commitment, Error> {
        self.schema_inner(tip, true)
    }
    /// Structural lookup for retained statements whose seal later lost a race.
    pub fn schema_any(&self, tip: TipId) -> Result<Commitment, Error> {
        self.schema_inner(tip, false)
    }
    fn schema_inner(&self, tip: TipId, active: bool) -> Result<Commitment, Error> {
        if tip == self.genesis() {
            return Ok(self.genesis_schema);
        }
        // Each ancestor lookup otherwise rehashes every earlier signed seal.
        let mut continuations = std::collections::BTreeMap::new();
        for seal in &self.seals {
            if seal.statement.scope == self.scope
                && let Ok(Some(successor)) = seal.successor()
            {
                continuations.entry(successor).or_insert(seal);
            }
        }
        let mut cursor = tip;
        let mut requested = None;
        let mut visited = std::collections::BTreeSet::new();
        loop {
            if !visited.insert(cursor) {
                return Err(denied("cyclic tip graph"));
            }
            if cursor == self.genesis() {
                return Ok(requested.unwrap_or(self.genesis_schema));
            }
            if let Some(&seal) = continuations.get(&cursor) {
                let canonical = self.seal(seal.statement.tip)? == Some(seal);
                if active && !canonical {
                    return Err(denied("tip belongs to a losing seal"));
                }
                if let SealAction::Continue { schema } = seal.statement.action {
                    requested.get_or_insert(schema);
                }
                cursor = seal.statement.tip;
                continue;
            }
            let mut parent = None;
            for opening in &self.openings {
                if opening.statement.scope == self.scope && opening.tip()? == cursor {
                    let seal = self.seal_by_id(opening.statement.seal)?;
                    if active {
                        if self.revoked.contains(&opening.id()?) {
                            return Err(denied("tip opening is revoked"));
                        }
                        if self.seal(seal.statement.tip)? != Some(seal) {
                            return Err(denied("tip opens on a losing seal"));
                        }
                        if self.authority(opening.endorsement()) == TipAuthority::Issuer
                            && !self.migration_opening(opening, true)?
                        {
                            return Err(denied(
                                "migration opening does not inherit the line minimum",
                            ));
                        }
                    }
                    requested.get_or_insert(opening.statement.schema);
                    parent = Some(seal.statement.tip);
                    break;
                }
            }
            cursor = parent.ok_or_else(|| denied("unknown tip"))?;
        }
    }
    /// Whether `to` follows one or more canonical continue seals from `from`.
    pub fn continues(&self, from: TipId, to: TipId) -> Result<bool, Error> {
        self.schema(from)?;
        self.schema(to)?;
        let mut cursor = from;
        let mut visited = std::collections::BTreeSet::new();
        while visited.insert(cursor) {
            let Some(seal) = self.seal(cursor)? else {
                return Ok(false);
            };
            let Some(next) = seal.successor()? else {
                return Ok(false);
            };
            if next == to {
                return Ok(true);
            }
            cursor = next;
        }
        Err(denied("cyclic tip graph"))
    }
    /// Structural forward reach also retains work signed before a seal lost.
    pub fn continues_any(&self, from: TipId, to: TipId) -> Result<bool, Error> {
        self.schema_any(from)?;
        self.schema_any(to)?;
        let mut cursor = to;
        let mut visited = std::collections::BTreeSet::new();
        while visited.insert(cursor) {
            let mut parent = None;
            for seal in &self.seals {
                if seal.statement.scope == self.scope && seal.successor()? == Some(cursor) {
                    parent = Some(seal.statement.tip);
                    break;
                }
            }
            let Some(tip) = parent else { return Ok(false) };
            if tip == from {
                return Ok(true);
            }
            cursor = tip;
        }
        Err(denied("cyclic tip graph"))
    }
    /// Whether an opening is a restricted schema migration, independent of
    /// its signer's authority. Historical validation retains old minima.
    pub(crate) fn migration_opening(
        &self,
        opening: &SignedTipOpening,
        active: bool,
    ) -> Result<bool, Error> {
        self.check_scope(opening.statement.scope)?;
        let seal = self.seal_by_id(opening.statement.seal)?;
        if seal.statement.action != SealAction::Close
            || opening.statement.schema == self.schema_any(seal.statement.tip)?
        {
            return Ok(false);
        }
        let minimum = opening.statement.minimum_in_sync as usize;
        if active || self.line_root_any(seal.statement.tip)? != self.genesis() {
            return Ok(self.line_minimum(seal.statement.tip)? == Some(minimum));
        }
        Ok(self.genesis_lines.iter().any(|line| {
            line.statement.scope == self.scope && line.statement.minimum_in_sync as usize == minimum
        }))
    }
    /// Forward schema successors along canonical ancestry. Migration edges
    /// start new author lines; frame continuation still uses `continues`.
    pub fn succeeds(&self, from: TipId, to: TipId) -> Result<bool, Error> {
        self.schema(from)?;
        self.schema(to)?;
        self.succeeds_inner(from, to, true)
    }
    /// Structural forward authorization, including retained losing migrations.
    pub fn succeeds_any(&self, from: TipId, to: TipId) -> Result<bool, Error> {
        self.schema_any(from)?;
        self.schema_any(to)?;
        self.succeeds_inner(from, to, false)
    }
    fn succeeds_inner(&self, from: TipId, to: TipId, active: bool) -> Result<bool, Error> {
        let mut cursor = to;
        let mut visited = BTreeSet::new();
        while visited.insert(cursor) {
            let mut parent = None;
            for seal in &self.seals {
                if seal.statement.scope == self.scope && seal.successor()? == Some(cursor) {
                    parent = Some(seal.statement.tip);
                    break;
                }
            }
            if parent.is_none() {
                for opening in &self.openings {
                    if opening.statement.scope == self.scope && opening.tip()? == cursor {
                        if !self.migration_opening(opening, active)? {
                            return Ok(false);
                        }
                        parent = Some(self.seal_by_id(opening.statement.seal)?.statement.tip);
                        break;
                    }
                }
            }
            let Some(tip) = parent else { return Ok(false) };
            if tip == from {
                return Ok(true);
            }
            cursor = tip;
        }
        Err(denied("cyclic tip graph"))
    }
    /// A losing forward continuation resolves to the winner's continuation.
    pub fn canonical_tip(&self, tip: TipId) -> Result<TipId, Error> {
        // Active ancestry also proves structural ancestry; valid tips need one walk.
        if self.schema(tip).is_ok() {
            return Ok(tip);
        }
        self.schema_any(tip)?;
        let mut path = Vec::new();
        let mut cursor = tip;
        let mut visited = std::collections::BTreeSet::new();
        while self.schema(cursor).is_err() {
            if !visited.insert(cursor) {
                return Err(denied("cyclic tip graph"));
            }
            let mut parent = None;
            for seal in &self.seals {
                if seal.statement.scope == self.scope && seal.successor()? == Some(cursor) {
                    parent = Some(seal.statement.tip);
                    break;
                }
            }
            cursor = parent.ok_or_else(|| denied("tip opens on a losing seal"))?;
            path.push(());
        }
        for () in path {
            if let Some(seal) = self.seal(cursor)?
                && let Some(next) = seal.successor()?
            {
                cursor = next;
            }
        }
        Ok(cursor)
    }
    /// A line starts at genesis or at an explicit opening, not at a continue.
    pub fn line_root(&self, tip: TipId) -> Result<TipId, Error> {
        self.schema(tip)?;
        let mut cursor = tip;
        let mut visited = std::collections::BTreeSet::new();
        while visited.insert(cursor) {
            let mut parent = None;
            for seal in &self.seals {
                if seal.statement.scope == self.scope && seal.successor()? == Some(cursor) {
                    parent = Some(seal.statement.tip);
                    break;
                }
            }
            match parent {
                Some(tip) => cursor = tip,
                None => return Ok(cursor),
            }
        }
        Err(denied("cyclic tip graph"))
    }
    /// The tip a line starts at, through seals whatever their resolution.
    fn line_root_any(&self, tip: TipId) -> Result<TipId, Error> {
        self.schema_any(tip)?;
        let mut cursor = tip;
        let mut visited = std::collections::BTreeSet::new();
        while visited.insert(cursor) {
            let mut parent = None;
            for seal in &self.seals {
                if seal.statement.scope == self.scope && seal.successor()? == Some(cursor) {
                    parent = Some(seal.statement.tip);
                    break;
                }
            }
            match parent {
                Some(tip) => cursor = tip,
                None => return Ok(cursor),
            }
        }
        Err(denied("cyclic tip graph"))
    }
    /// Resolve conflicts per `(name, from)` by authority, then the lower
    /// move digest, and walk from creation; a tip without a move that the
    /// owner's recovery sealed continues on. A revisit ends the walk at the
    /// revisited tip. Revoked moves never win.
    pub fn bookmark(&self, name: &str) -> Result<Option<TipId>, Error> {
        Ok(self.bookmark_walk(name)?.0)
    }
    /// The moves of `name` that lost a race along its path, in path and
    /// then resolution order: inspection's `main/1`, `main/2`. They stay
    /// branches; revoked moves are not listed.
    pub fn losing_moves(&self, name: &str) -> Result<Vec<&SignedBookmarkMove>, Error> {
        Ok(self.bookmark_walk(name)?.1)
    }
    /// The resolved edges a bookmark traverses, using the same authority,
    /// revocation and ancestry rules as its final target.
    pub fn bookmark_path(&self, name: &str) -> Result<Vec<(TipId, TipId)>, Error> {
        Ok(self.bookmark_walk(name)?.2)
    }
    /// The target, losing moves and resolved edges of a bookmark.
    fn bookmark_walk(&self, name: &str) -> Result<BookmarkWalk<'_>, Error> {
        let mut cursor = None;
        let mut losers = Vec::new();
        let mut path = Vec::new();
        let mut visited = std::collections::BTreeSet::new();
        while visited.insert(cursor) {
            let mut candidates = Vec::new();
            for movement in self.moves.iter().filter(|movement| {
                movement.statement.scope == self.scope
                    && movement.statement.name == name
                    && movement.statement.from == cursor
            }) {
                let id = movement.id()?;
                if self.revoked.contains(&id) {
                    continue;
                }
                candidates.push((self.precedence(movement.endorsement(), id), movement));
            }
            candidates.sort_by_key(|candidate| candidate.0);
            let mut winner = None;
            for (_, movement) in candidates {
                let target = movement
                    .statement
                    .to
                    .map(|tip| self.canonical_tip(tip))
                    .transpose();
                if let Ok(target) = target
                    && (target.is_none() || target != cursor)
                    && winner.is_none()
                {
                    winner = Some(target);
                } else {
                    losers.push(movement);
                }
            }
            match winner {
                Some(target) => {
                    if let (Some(from), Some(to)) = (cursor, target) {
                        path.push((from, to));
                    }
                    cursor = target;
                }
                None => {
                    // The owner's recovery carries the tip's bookmarks to
                    // its continuation; an explicit move from it comes first.
                    if let Some(tip) = cursor
                        && let Some(seal) = self.seal(tip)?
                        && seal.statement.recovery.is_some()
                        && let Some(next) = seal.successor()?
                    {
                        path.push((tip, next));
                        cursor = Some(next);
                        continue;
                    }
                    return Ok((cursor, losers, path));
                }
            }
        }
        Ok((cursor, losers, path))
    }
}
