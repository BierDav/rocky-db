//! Signed checkpoints, pruning and rebootstrap of one encryption scope.
//! Format and rules: `docs/runtime/encrypted-checkpoints.md`.
mod archive;
#[cfg(test)]
mod backend_vectors;
pub(super) use archive::SCHEMA as ARCHIVE_SCHEMA;
mod audit;
mod create;
mod failures;
pub use failures::IMPORT_ATTEMPTS;
pub(crate) use failures::SCHEMA as FAILURE_SCHEMA;
mod no_frames;
mod origin_legend;
mod proof_headers;
mod prune;
pub(super) mod pulled;
pub(crate) use pulled::SCHEMA as PULLED_SCHEMA;
mod served;
pub(crate) use served::SCHEMA as SERVED_SCHEMA;
pub(super) use served::Served;
mod transfer;
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ReplayMode {
    Mint,
    Check,
    Rows,
}
pub use audit::AuditReport;
use p2panda_core::Signature;
pub use prune::{PruneBlock, PruneReport};
pub use transfer::{CheckpointPage, PrunedPage, RebootstrapReport};
#[cfg(test)]
pub(crate) use transfer::{forge_page, forge_page_clocks, forge_page_legend};

pub(crate) const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS secure_compaction_live_creations(scope INTEGER NOT NULL,hash BLOB NOT NULL,PRIMARY KEY(scope,hash)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_checkpoint_stubs(scope INTEGER NOT NULL,hash BLOB NOT NULL,clock INTEGER NOT NULL,PRIMARY KEY(scope,hash)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_identity_marks(scope BLOB NOT NULL,author INTEGER NOT NULL,signer BLOB NOT NULL,sequence INTEGER NOT NULL,PRIMARY KEY(scope,author)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_scope_state(id INTEGER PRIMARY KEY,scope BLOB NOT NULL UNIQUE,rows INTEGER NOT NULL,tombstones INTEGER NOT NULL,digest BLOB NOT NULL,applied INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS secure_retained(id INTEGER PRIMARY KEY CHECK(id=1),records INTEGER NOT NULL,bytes INTEGER NOT NULL,handles INTEGER NOT NULL,handle_digest BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS secure_applied(position INTEGER PRIMARY KEY AUTOINCREMENT,scope INTEGER NOT NULL,hash BLOB NOT NULL UNIQUE)",
    "CREATE INDEX IF NOT EXISTS secure_applied_scope ON secure_applied(scope,position)",
    "CREATE TABLE IF NOT EXISTS secure_finalization_rows(scope INTEGER NOT NULL,row BLOB NOT NULL,PRIMARY KEY(scope,row)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_birth_positions(scope INTEGER NOT NULL,position INTEGER NOT NULL,author INTEGER NOT NULL,signer BLOB NOT NULL,sequence INTEGER NOT NULL,PRIMARY KEY(scope,position,author)) WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS secure_birth_position_operation ON secure_birth_positions(position)",
    "CREATE TABLE IF NOT EXISTS secure_row_positions(scope INTEGER NOT NULL,row BLOB NOT NULL,position INTEGER NOT NULL,PRIMARY KEY(scope,row,position)) WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS secure_row_position_operations ON secure_row_positions(position,scope,row)",
    "CREATE TRIGGER IF NOT EXISTS secure_row_positions_delete AFTER DELETE ON secure_applied BEGIN DELETE FROM secure_row_positions WHERE position=OLD.position; DELETE FROM secure_birth_positions WHERE position=OLD.position; END",
    "CREATE TABLE IF NOT EXISTS secure_logs(scope INTEGER NOT NULL,author BLOB NOT NULL,sequence INTEGER NOT NULL,hash BLOB NOT NULL,clock INTEGER NOT NULL,pruned_prefix INTEGER NOT NULL,PRIMARY KEY(scope,author)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_stubs(hash BLOB PRIMARY KEY,scope INTEGER NOT NULL,clock INTEGER NOT NULL,creation INTEGER NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_checkpoints(scope INTEGER NOT NULL,sequence INTEGER NOT NULL,position INTEGER NOT NULL,sets BLOB NOT NULL,signed BLOB NOT NULL,PRIMARY KEY(scope,sequence))",
    // The replay base. `fields` is NULL while the stored row holds the same
    // record: a base row is kept once, and the stored row's change or
    // removal first copies it here. Read and insert through the view.
    "CREATE TABLE IF NOT EXISTS secure_checkpoint_base(scope INTEGER NOT NULL,row BLOB NOT NULL,fields BLOB,PRIMARY KEY(scope,row)) WITHOUT ROWID",
    "CREATE VIEW IF NOT EXISTS secure_checkpoint_rows AS SELECT b.scope,b.row,coalesce(b.fields,r.fields) AS fields FROM secure_checkpoint_base b LEFT JOIN secure_rows r ON b.fields IS NULL AND r.scope=b.scope AND r.row=b.row",
    "CREATE TRIGGER IF NOT EXISTS secure_checkpoint_rows_insert INSTEAD OF INSERT ON secure_checkpoint_rows BEGIN INSERT INTO secure_checkpoint_base VALUES(NEW.scope,NEW.row,CASE WHEN NEW.fields IS (SELECT fields FROM secure_rows WHERE scope=NEW.scope AND row=NEW.row) THEN NULL ELSE NEW.fields END); END",
    "CREATE TRIGGER IF NOT EXISTS secure_checkpoint_base_update BEFORE UPDATE OF fields ON secure_rows BEGIN UPDATE secure_checkpoint_base SET fields=OLD.fields WHERE scope=OLD.scope AND row=OLD.row AND fields IS NULL; END",
    "CREATE TRIGGER IF NOT EXISTS secure_checkpoint_base_delete BEFORE DELETE ON secure_rows BEGIN UPDATE secure_checkpoint_base SET fields=OLD.fields WHERE scope=OLD.scope AND row=OLD.row AND fields IS NULL; END",
    "CREATE TABLE IF NOT EXISTS secure_checkpoint_overlay(scope INTEGER NOT NULL,row BLOB NOT NULL,fields BLOB NOT NULL,PRIMARY KEY(scope,row)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_checkpoint_scratch(scope INTEGER NOT NULL,row BLOB NOT NULL,fields BLOB NOT NULL,PRIMARY KEY(scope,row)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_retention(scope BLOB PRIMARY KEY,policy BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS secure_rebootstrap(scope INTEGER PRIMARY KEY,signed BLOB NOT NULL,cursor BLOB,complete INTEGER NOT NULL,sets BLOB NOT NULL,direct INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS secure_rebootstrap_pages(scope INTEGER NOT NULL,after BLOB NOT NULL,next BLOB,signature BLOB NOT NULL,PRIMARY KEY(scope,after)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_checkpoint_page_headers(scope INTEGER NOT NULL,view INTEGER NOT NULL,header BLOB NOT NULL,first_row BLOB NOT NULL,PRIMARY KEY(scope,view,header)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_checkpoint_pages(scope INTEGER NOT NULL,after BLOB NOT NULL,next BLOB,signature BLOB NOT NULL,PRIMARY KEY(scope,after)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_rebootstrap_rows(scope INTEGER NOT NULL,row BLOB NOT NULL,fields BLOB NOT NULL,PRIMARY KEY(scope,row)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_rebootstrap_stubs(scope INTEGER NOT NULL,hash BLOB NOT NULL,clock INTEGER NOT NULL,PRIMARY KEY(scope,hash)) WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS secure_handles_hash ON secure_handles(hash)",
    "CREATE INDEX IF NOT EXISTS secure_ack_hash ON secure_ack(hash)",
];

/// Shares the base rows of scope `?1` that equal their stored rows again,
/// after a bulk rewrite of the stored rows copied them out.
pub(super) const SHARE_BASE: &str = "UPDATE secure_checkpoint_base SET fields=NULL WHERE scope=?1 AND fields=(SELECT fields FROM secure_rows r WHERE r.scope=?1 AND r.row=secure_checkpoint_base.row)";

// Walk applied positions before testing row membership, so LIMIT bounds the work.
pub(crate) const ROW_REPLAY_SQL: &str = "SELECT a.position,o.header,o.body,o.status FROM secure_applied a LEFT JOIN secure_operations o ON o.hash=a.hash WHERE a.scope=?1 AND a.position>?2 AND a.position<=?3 AND EXISTS(SELECT 1 FROM secure_row_positions p JOIN secure_finalization_rows r ON r.scope=p.scope AND r.row=p.row WHERE p.position=a.position AND p.scope=a.scope) ORDER BY a.position LIMIT ?4";

/// Applied operations replayed, or pruned, per bounded step.
#[cfg(not(test))]
pub(super) const STEP_OPERATIONS: usize = 64;
/// Checkpoint rows installed, staged or streamed per bounded step.
#[cfg(not(test))]
pub(super) const STEP_ROWS: usize = 256;
// Small steps let tests cross every step boundary with little data.
#[cfg(test)]
pub(super) const STEP_OPERATIONS: usize = 8;
#[cfg(test)]
pub(super) const STEP_ROWS: usize = 16;
/// Logs of one scope a checkpoint frontier may name.
pub const MAX_CHECKPOINT_LOGS: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityMark {
    pub author: u32,
    pub signer: PublicKey,
    pub sequence: u32,
}

/// Covered maxima over all births and over the author's own births only.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoveredMark {
    pub author: u32,
    pub signer: PublicKey,
    pub sequence: u32,
    pub own: u32,
}
impl CoveredMark {
    pub(crate) fn mark(&self) -> IdentityMark {
        IdentityMark {
            author: self.author,
            signer: self.signer,
            sequence: self.sequence,
        }
    }
    pub(crate) fn own_mark(&self) -> Option<IdentityMark> {
        (self.own > 0).then_some(IdentityMark {
            author: self.author,
            signer: self.signer,
            sequence: self.own,
        })
    }
}

/// The applied tip of one author's log in a scope.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogPosition {
    pub author: PublicKey,
    pub sequence: u64,
    pub hash: Hash,
    pub clock: u64,
}
/// A set bound by its size and an order-independent digest.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetSummary {
    pub count: u64,
    pub digest: Commitment,
}
/// Recovery copies of the covered operations when the checkpoint was sealed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustodySummary {
    /// Retained covered operations another node acknowledged holding.
    pub superseded: u64,
    /// Retained covered operations nobody acknowledged: sole copies.
    pub sole: SetSummary,
}
/// The current checkpoint statement format; every other one is refused.
pub(crate) const CHECKPOINT_FORMAT: u32 = 17;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointStatement {
    pub format: u32,
    /// The seal whose finalized state this is, in a domain with a tip graph;
    /// its frontier bounds the covered frames. None for another cut.
    pub seal: Option<Commitment>,
    pub partition: Option<rocky_core::PartitionTuple>,
    pub identities: Vec<CoveredMark>,
    /// Opaque move links, also committed by the corresponding materialized rows.
    pub moves: SetSummary,
    pub tip: rocky_core::TipId,
    pub schema: u32,
    /// The digest of the revocations the signer held.
    pub revocations: Commitment,
    pub scope: ResourceScope,
    pub state: CheckpointState,
    /// Length of the checkpoint chain of this scope, starting at 1.
    pub sequence: u64,
    pub previous: Option<Commitment>,
    /// Applied tip of every log, ordered by author.
    pub frontier: Vec<LogPosition>,
    pub clock: u64,
    pub operations: u64,
    /// Stored rows, tombstones and creation identities included.
    pub rows: SetSummary,
    pub tombstones: u64,
    /// Creation operations of the stored rows with their clocks.
    pub creations: SetSummary,
    /// Mutation handles the signer retains.
    pub handles: SetSummary,
    pub custody: CustodySummary,
}
/// How a checkpoint's state is held. See `docs/runtime/encrypted-checkpoints.md`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CheckpointState {
    /// Rows sealed under this key epoch, transferred in pages.
    Keyed { key_epoch: rocky_core::KeyEpoch },
    /// The scope's state at the seal holds no frame history at all,
    /// inherited history included: no rows, pages or key epoch.
    NoFrames,
}
impl CheckpointStatement {
    pub fn key_epoch(&self) -> Option<rocky_core::KeyEpoch> {
        match &self.state {
            CheckpointState::Keyed { key_epoch } => Some(*key_epoch),
            CheckpointState::NoFrames => None,
        }
    }
    pub fn no_frames(&self) -> bool {
        self.state == CheckpointState::NoFrames
    }
    /// A no-frames statement's only shape: at a seal, with empty history,
    /// identities, rows, moves and custody.
    fn canonical_no_frames(&self) -> Result<bool, Error> {
        let empty = Sets::new();
        Ok(self.seal.is_some()
            && self.operations == 0
            && self.frontier.is_empty()
            && self.clock == 0
            && self.identities.is_empty()
            && self.rows == empty.rows_summary()
            && self.tombstones == 0
            && self.creations == empty.creations_summary()
            && self.moves
                == (SetSummary {
                    count: 0,
                    digest: [0; 32],
                })
            && self.custody == create::no_custody()?)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedCheckpoint {
    pub statement: CheckpointStatement,
    node: PublicKey,
    credentials: CredentialChain,
    signature: Signature,
}
impl SignedCheckpoint {
    fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        signing_bytes(
            "rocky.encrypted-checkpoint.v3",
            &(&self.statement, self.node, &self.credentials),
        )
    }
    pub(crate) fn sign(
        statement: CheckpointStatement,
        node: &PrivateKey,
        credentials: CredentialChain,
    ) -> Result<Self, Error> {
        let mut signed = Self {
            statement,
            node: node.public_key(),
            credentials,
            signature: node.sign(b""),
        };
        signed.signature = node.sign(&signed.signing_bytes()?);
        signed.to_bytes()?;
        Ok(signed)
    }
    fn checkpoint_grants(
        &self,
        publisher: PublicKey,
        revocations: &RevocationSet,
        time: u64,
    ) -> Result<Vec<rocky_core::ResourceGrant>, Error> {
        match &self.statement.partition {
            Some(tuple) => self
                .credentials
                .verify_partition(
                    publisher,
                    self.node,
                    self.statement.scope,
                    tuple,
                    revocations,
                    time,
                )
                .map_err(credential),
            None => self
                .credentials
                .verify_selectors(publisher, self.node, revocations, time)
                .map(|(grants, _)| grants)
                .map_err(credential),
        }
    }
    pub fn signer(&self) -> PublicKey {
        self.node
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let bytes = encode(self)?;
        if bytes.len() > MAX_SECURE_FRAME {
            return Err(Error::Quota {
                resource: "encrypted checkpoint statement",
                limit: MAX_SECURE_FRAME,
            });
        }
        Ok(bytes)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        #[derive(Deserialize)]
        struct Format {
            format: u32,
        }
        #[derive(Deserialize)]
        struct Version {
            statement: Format,
        }
        let version: Version =
            p2panda_core::cbor::decode_cbor(bytes).map_err(|_| denied("invalid checkpoint"))?;
        if version.statement.format != CHECKPOINT_FORMAT {
            return Err(denied("unsupported checkpoint format"));
        }
        decode(bytes)
    }
    pub fn id(&self) -> Result<Commitment, Error> {
        Ok(rocky_core::commitment(
            "rocky.encrypted-checkpoint.id.v3",
            &self.to_bytes()?,
        ))
    }
    /// The signature and the frontier's canonical order.
    pub(crate) fn verify_signature(&self) -> Result<(), Error> {
        let statement = &self.statement;
        if statement.format != CHECKPOINT_FORMAT {
            return Err(denied("unsupported checkpoint format"));
        }
        if statement.partition.as_ref().is_some_and(|tuple| {
            tuple
                .scope(statement.scope.domain, statement.scope.table)
                .ok()
                != Some(statement.scope)
        }) || statement.identities.len() > MAX_CHECKPOINT_LOGS
            || statement
                .identities
                .windows(2)
                .any(|pair| pair[0].author >= pair[1].author)
            || statement.identities.iter().any(|mark| {
                mark.own > mark.sequence
                    || rocky_core::RowIdentity::new(mark.author, mark.sequence).is_err()
            })
            || statement.sequence == 0
            || statement.frontier.len() > MAX_CHECKPOINT_LOGS
            || statement
                .frontier
                .windows(2)
                .any(|pair| pair[0].author >= pair[1].author)
            || !self.node.verify(&self.signing_bytes()?, &self.signature)
        {
            return Err(denied("invalid checkpoint signature or frontier"));
        }
        if statement.no_frames() && !statement.canonical_no_frames()? {
            return Err(denied("a no-frames checkpoint must be empty at a seal"));
        }
        Ok(())
    }
    /// Bootstrap state needs a current whole-scope reader with a write grant,
    /// under the held revocations.
    pub(super) fn verify_authority<A: RowApplication>(
        &self,
        inner: &Inner<A>,
        time: u64,
    ) -> Result<(), Error> {
        self.verify_signature()?;
        inner.admits(inner.manifest_of_tip(self.statement.tip)?)?;
        inner.check_authenticated_partition(
            self.statement.scope,
            self.statement.partition.as_ref(),
        )?;
        let grants = self.checkpoint_grants(
            inner.config.publisher,
            inner.revocations_for(
                inner.manifest_of_tip(self.statement.tip)?,
                &inner.config.revocations,
            )?,
            time,
        )?;
        if !grants.iter().any(|grant| {
            grant.scope == self.statement.scope
                && grant.rows == RowSelection::All
                && grant.rights.contains(&Right::Read)
                && [Right::Insert, Right::Update, Right::Delete]
                    .iter()
                    .any(|right| grant.rights.contains(right))
        }) {
            return Err(denied(
                "checkpoint signer lacks whole-scope read and write authority",
            ));
        }
        Ok(())
    }
}

/// When covered operations of a scope may be pruned. Local configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Peers that must have acknowledged an operation before it is pruned.
    pub required: BTreeSet<rocky_credentials::PeerId>,
    /// Peers declared behind the pruned_prefix: not waited for; they rebootstrap.
    pub behind: BTreeSet<rocky_credentials::PeerId>,
    /// Other nodes that must hold a copy; at least one is always required.
    pub copies: usize,
    /// Newest covered operations kept for peers that catch up without a checkpoint.
    pub window: usize,
}
/// Replica-wide bounds on retained operations. Not persisted.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetentionLimits {
    /// Retained bytes at which authoring and receiving report backpressure.
    pub hard_bytes: usize,
    /// Most recent mutation handles kept for retries after their operations
    /// are pruned. An older handle is forgotten; its retry authors again.
    pub handles: usize,
}
impl Default for RetentionLimits {
    fn default() -> Self {
        Self {
            hard_bytes: 2 * MAX_SECURE_BYTES,
            handles: 65_536,
        }
    }
}
#[derive(Clone, Debug)]
pub struct CheckpointStatus {
    /// The latest verified checkpoint.
    pub checkpoint: Option<SignedCheckpoint>,
    /// Applied operations after the verified checkpoint.
    pub uncovered: u64,
    /// Retained operations at or before it.
    pub covered: u64,
    /// Admitted operations of the scope that are not applied.
    pub pending: u64,
    /// Logs with pruned history and the last pruned sequence of each.
    pub pruned_prefix: Vec<(PublicKey, u64)>,
    /// Retained header and body bytes of the whole replica.
    pub retained_bytes: u64,
    /// The last failure of automatic maintenance.
    pub maintenance_error: Option<String>,
}

/// Fault points of the bounded maintenance steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    #[cfg(test)]
    AuditReplay,
    #[cfg(test)]
    AuditStaged,
    Compact,
    Prune,
    Import,
    Switch,
    Evict,
    /// After a seal rebootstrap installed or refused pulled states.
    Settle,
}

const LANES: usize = 1024;
/// LtHash16: an order-independent digest that elements can be added to and
/// removed from. Each element expands to 1,024 lanes added modulo 2^16.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Lt(Vec<u16>);
impl Lt {
    pub(super) fn new() -> Self {
        Self(vec![0; LANES])
    }
    pub(super) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 2 * LANES {
            return Err(Error::Corrupt("set digest state".into()));
        }
        Ok(Self(
            bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect(),
        ))
    }
    pub(super) fn to_bytes(&self) -> Vec<u8> {
        self.0.iter().flat_map(|lane| lane.to_le_bytes()).collect()
    }
    fn mix(&mut self, label: &str, item: &[u8], add: bool) {
        let mut seed = [0u8; 33];
        seed[..32].copy_from_slice(&rocky_core::commitment(label, item));
        for block in 0..LANES / 16 {
            seed[32] = block as u8;
            let lanes = rocky_core::commitment("rocky.checkpoint-lanes.v1", &seed);
            for (index, pair) in lanes.as_chunks::<2>().0.iter().enumerate() {
                let value = u16::from_le_bytes([pair[0], pair[1]]);
                let lane = &mut self.0[block * 16 + index];
                *lane = if add {
                    lane.wrapping_add(value)
                } else {
                    lane.wrapping_sub(value)
                };
            }
        }
    }
    pub(super) fn add(&mut self, label: &str, item: &[u8]) {
        self.mix(label, item, true);
    }
    pub(super) fn remove(&mut self, label: &str, item: &[u8]) {
        self.mix(label, item, false);
    }
    pub(super) fn digest(&self) -> Commitment {
        rocky_core::commitment("rocky.checkpoint-set.v1", &self.to_bytes())
    }
    /// Adds every element of `other`: the digest of the union of disjoint sets.
    pub(super) fn merge(&mut self, other: &Self) {
        for (lane, value) in self.0.iter_mut().zip(&other.0) {
            *lane = lane.wrapping_add(*value);
        }
    }
}
pub(super) const ROW_LABEL: &str = "rocky.checkpoint-row.v2";
pub(super) const CREATION_LABEL: &str = "rocky.checkpoint-creation.v1";
pub(super) const HANDLE_LABEL: &str = "rocky.checkpoint-handle.v1";

/// Stored rows of a scope and the creation operations behind them.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Sets {
    pub rows: u64,
    pub tombstones: u64,
    pub digest: Lt,
    pub creations: u64,
    pub creation_digest: Lt,
}
impl Sets {
    pub(super) fn new() -> Self {
        Self {
            rows: 0,
            tombstones: 0,
            digest: Lt::new(),
            creations: 0,
            creation_digest: Lt::new(),
        }
    }
    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24 + 4 * LANES);
        for count in [self.rows, self.tombstones, self.creations] {
            bytes.extend(count.to_le_bytes());
        }
        bytes.extend(self.digest.to_bytes());
        bytes.extend(self.creation_digest.to_bytes());
        bytes
    }
    pub(super) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 24 + 4 * LANES {
            return Err(Error::Corrupt("checkpoint set state".into()));
        }
        let count = |index: usize| {
            let mut value = [0; 8];
            value.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
            u64::from_le_bytes(value)
        };
        Ok(Self {
            rows: count(0),
            tombstones: count(1),
            creations: count(2),
            digest: Lt::from_bytes(&bytes[24..24 + 2 * LANES])?,
            creation_digest: Lt::from_bytes(&bytes[24 + 2 * LANES..])?,
        })
    }
    /// Replaces one stored row record by another.
    pub(super) fn replace(
        &mut self,
        row: &Commitment,
        old: Option<&[u8]>,
        new: &[u8],
    ) -> Result<(), Error> {
        let old = old
            .map(|bytes| Ok::<_, Error>((bytes, decode::<Materialized>(bytes)?.deleted)))
            .transpose()?;
        self.replace_encoded(row, old, (new, decode::<Materialized>(new)?.deleted));
        Ok(())
    }
    /// Canonical records and their already decoded tombstone flags.
    pub(super) fn replace_encoded(
        &mut self,
        row: &Commitment,
        old: Option<(&[u8], bool)>,
        new: (&[u8], bool),
    ) {
        if let Some((bytes, deleted)) = old {
            self.digest
                .remove(ROW_LABEL, &[row.as_slice(), bytes].concat());
            self.rows -= 1;
            self.tombstones -= u64::from(deleted);
        }
        self.digest
            .add(ROW_LABEL, &[row.as_slice(), new.0].concat());
        self.rows += 1;
        self.tombstones += u64::from(new.1);
    }
    pub(super) fn replace_materialized(
        &mut self,
        row: &Commitment,
        old: Option<&Materialized>,
        new: &Materialized,
    ) -> Result<(), Error> {
        let old = old
            .map(|record| Ok::<_, Error>((encode(record)?, record.deleted)))
            .transpose()?;
        self.replace_encoded(
            row,
            old.as_ref()
                .map(|(bytes, deleted)| (bytes.as_slice(), *deleted)),
            (&encode(new)?, new.deleted),
        );
        Ok(())
    }
    /// Removes one stored row record.
    pub(super) fn remove(&mut self, row: &Commitment, old: &[u8]) -> Result<(), Error> {
        self.digest
            .remove(ROW_LABEL, &[row.as_slice(), old].concat());
        self.rows -= 1;
        self.tombstones -= u64::from(decode::<Materialized>(old)?.deleted);
        Ok(())
    }
    /// Adds the rows of `delta`, stored rows disjoint from these.
    pub(super) fn merge_rows(&mut self, delta: &Self) {
        self.rows += delta.rows;
        self.tombstones += delta.tombstones;
        self.digest.merge(&delta.digest);
    }
    pub(super) fn create(&mut self, hash: Hash, clock: u64) {
        self.creations += 1;
        self.creation_digest
            .add(CREATION_LABEL, &creation_item(hash, clock));
    }
    pub(super) fn rows_summary(&self) -> SetSummary {
        SetSummary {
            count: self.rows,
            digest: self.digest.digest(),
        }
    }
    pub(super) fn creations_summary(&self) -> SetSummary {
        SetSummary {
            count: self.creations,
            digest: self.creation_digest.digest(),
        }
    }
}
pub(super) fn creation_item(hash: Hash, clock: u64) -> Vec<u8> {
    [hash.as_bytes().as_slice(), &clock.to_le_bytes()].concat()
}
pub(super) fn handle_item(handle: &[u8], input: &[u8], hash: &[u8]) -> Vec<u8> {
    [handle, input, hash].concat()
}

/// A scope's replay base: through which applied position, its set state
/// and statement.
#[derive(Clone)]
pub(super) struct Record {
    pub position: i64,
    pub sets: Sets,
    pub signed: Option<SignedCheckpoint>,
}
/// One author's log in a scope: its applied tip and pruned prefix.
pub(super) struct Log {
    pub sequence: i64,
    pub hash: Hash,
    pub clock: u64,
    pub pruned_prefix: i64,
}
/// Which replay overlay a caller uses over the checkpoint rows.
#[derive(Clone, Copy)]
pub(super) enum Overlay {
    Build,
    Scratch,
    /// The scratch rows over the stored rows, not the checkpoint rows.
    Rewind,
}
impl Overlay {
    pub(super) fn table(self) -> &'static str {
        match self {
            Self::Build => "secure_checkpoint_overlay",
            Self::Scratch | Self::Rewind => "secure_checkpoint_scratch",
        }
    }
    fn under(self) -> &'static str {
        match self {
            Self::Build | Self::Scratch => {
                "SELECT fields FROM secure_checkpoint_rows WHERE scope=? AND row=?"
            }
            Self::Rewind => {
                "SELECT fields FROM secure_row_records WHERE scope=(SELECT scope FROM secure_scope_state WHERE id=?) AND row=?"
            }
        }
    }
}

impl<A: RowApplication> Inner<A> {
    /// Filters the replay's view of a verified base, leaving its signed
    /// bytes and summaries untouched. Unchanged schemas require no row scan.
    pub(super) async fn prime_path_base(
        &self,
        scope: ResourceScope,
        id: i64,
        overlay: Overlay,
        target: TipId,
        mut sets: Sets,
    ) -> Result<Sets, Error> {
        if self.ignores_base() {
            return Ok(sets);
        }
        let Some(signed) = self
            .checkpoint_record(id, true)
            .await?
            .and_then(|record| record.signed)
        else {
            return Ok(sets);
        };
        let graph = self.graph_for(scope.domain)?;
        let source = graph.schema_any(signed.statement.tip).map_err(credential)?;
        let definition = self
            .catalog
            .get(&source)
            .ok_or_else(|| denied("checkpoint source schema missing"))?;
        let fields = self.path_fields_to(scope.domain, signed.statement.tip, target)?;
        if !fields.strips(definition) {
            return Ok(sets);
        }
        let mut after = Vec::new();
        loop {
            let records = collect_rows(self.conn.query("SELECT row,fields FROM secure_checkpoint_rows WHERE scope=? AND row>? ORDER BY row LIMIT 256", bindings(vec![SqlValue::Integer(id), SqlValue::Blob(after.clone())])).await?).await?;
            #[cfg(feature = "qualification")]
            self.flusher
                .measurements
                .work(super::lock::WorkUnit::BaseRow, records.len() as u64);
            for row in &records {
                let [SqlValue::Blob(key), SqlValue::Blob(bytes)] = row.as_slice() else {
                    return Err(Error::Corrupt("checkpoint base row".into()));
                };
                after = key.clone();
                let mut row = self.decode_record(bytes).await?;
                let next = if !fields.tables.contains(&scope.table) {
                    Some(Vec::new())
                } else if fields.strip(scope.table, &mut row) {
                    Some(self.encode_record(&row).await?)
                } else {
                    None
                };
                if let Some(next) = next {
                    let key = row_of(key)?;
                    if next.is_empty() {
                        sets.remove_stored(self, &key, bytes).await?;
                    } else {
                        sets.replace_stored(self, &key, Some(bytes), &next).await?;
                    }
                    self.conn
                        .execute(
                            format!("INSERT OR REPLACE INTO {} VALUES(?,?,?)", overlay.table()),
                            bindings(vec![
                                SqlValue::Integer(id),
                                SqlValue::Blob(key.to_vec()),
                                SqlValue::Blob(next),
                            ]),
                        )
                        .await?;
                }
            }
            if records.len() < 256 {
                break;
            }
        }
        Ok(sets)
    }
}

pub(super) fn hash_of(bytes: &[u8]) -> Result<Hash, Error> {
    Hash::try_from(bytes).map_err(|_| Error::Corrupt("stored operation hash".into()))
}
pub(super) fn key_of(bytes: &[u8]) -> Result<PublicKey, Error> {
    PublicKey::try_from(bytes).map_err(|_| Error::Corrupt("stored author key".into()))
}
pub(super) fn row_of(bytes: &[u8]) -> Result<Commitment, Error> {
    bytes
        .try_into()
        .map_err(|_| Error::Corrupt("stored row identity".into()))
}
fn integer(value: u64) -> SqlValue {
    SqlValue::Integer(value as i64)
}

impl<A: RowApplication> Inner<A> {
    pub(super) fn sign_checkpoint(
        &self,
        statement: CheckpointStatement,
    ) -> Result<SignedCheckpoint, Error> {
        match self.node_author.as_ref() {
            Some(author) => {
                SignedCheckpoint::sign(statement, &author.key, author.credentials.clone())
            }
            None => SignedCheckpoint::sign(
                statement,
                self.credential_signer.as_ref().unwrap_or(&self.config.node),
                self.config.credentials.clone(),
            ),
        }
    }
    #[cfg(any(test, feature = "qualification"))]
    pub(crate) fn fault(&mut self, stage: Stage) -> Result<(), Error> {
        self.crash_at(|point| point.stage() == Some(stage))?;
        #[cfg(test)]
        if let Some((at, skip)) = &mut self.stage_fault
            && *at == stage
        {
            if *skip == 0 {
                if self.stage_exit {
                    std::process::exit(77);
                }
                self.stage_fault = None;
                return Err(Error::InjectedFailure);
            }
            *skip -= 1;
        }
        Ok(())
    }
    #[cfg(not(any(test, feature = "qualification")))]
    pub(crate) fn fault(&mut self, _stage: Stage) -> Result<(), Error> {
        Ok(())
    }
    pub(super) async fn find_scope_id(&self, scope: ResourceScope) -> Result<Option<i64>, Error> {
        let blob = encode(&scope)?;
        if let Some(id) = self.cached_scope_id(&blob) {
            return Ok(Some(id));
        }
        let mut result = self
            .conn
            .query(
                "SELECT id FROM secure_scope_state WHERE scope=?",
                [blob.clone()],
            )
            .await?;
        let Some(row) = result.next().await? else {
            return Ok(None);
        };
        let id = row.get::<i64>(0)?;
        self.cache_scope_id(blob, id);
        Ok(Some(id))
    }
    /// The scope's number, assigned inside the caller's write transaction.
    pub(super) async fn scope_id(&self, scope: ResourceScope) -> Result<i64, Error> {
        if let Some(id) = self.find_scope_id(scope).await? {
            return Ok(id);
        }
        self.conn
            .execute(
                "INSERT INTO secure_scope_state(scope,rows,tombstones,digest,applied) VALUES(?,0,0,?,0)",
                [encode(&scope)?, Lt::new().to_bytes()],
            )
            .await?;
        self.find_scope_id(scope)
            .await?
            .ok_or_else(|| Error::Corrupt("scope state".into()))
    }
    /// Live rows, tombstones and digest of a scope, and its applied operations.
    pub(super) async fn scope_state(&self, id: i64) -> Result<(u64, u64, Lt, u64), Error> {
        let mut result = self
            .conn
            .query(
                "SELECT rows,tombstones,digest,applied FROM secure_scope_state WHERE id=?",
                [id],
            )
            .await?;
        let row = result
            .next()
            .await?
            .ok_or_else(|| Error::Corrupt("scope state".into()))?;
        Ok((
            row.get::<i64>(0)? as u64,
            row.get::<i64>(1)? as u64,
            Lt::from_bytes(&row.get::<Vec<u8>>(2)?)?,
            row.get::<i64>(3)? as u64,
        ))
    }
    pub(super) async fn store_scope_state(
        &self,
        id: i64,
        rows: u64,
        tombstones: u64,
        digest: &Lt,
        applied: u64,
    ) -> Result<(), Error> {
        self.conn
            .execute(
                "UPDATE secure_scope_state SET rows=?,tombstones=?,digest=?,applied=? WHERE id=?",
                bindings(vec![
                    integer(rows),
                    integer(tombstones),
                    SqlValue::Blob(digest.to_bytes()),
                    integer(applied),
                    SqlValue::Integer(id),
                ]),
            )
            .await?;
        Ok(())
    }
    pub(super) async fn log(&self, scope: i64, author: PublicKey) -> Result<Option<Log>, Error> {
        let mut result = self
            .conn
            .query(
                "SELECT sequence,hash,clock,pruned_prefix FROM secure_logs WHERE scope=? AND author=?",
                bindings(vec![
                    SqlValue::Integer(scope),
                    SqlValue::Blob(author.as_bytes().to_vec()),
                ]),
            )
            .await?;
        let Some(row) = result.next().await? else {
            return Ok(None);
        };
        Ok(Some(Log {
            sequence: row.get::<i64>(0)?,
            hash: hash_of(&row.get::<Vec<u8>>(1)?)?,
            clock: row.get::<i64>(2)? as u64,
            pruned_prefix: row.get::<i64>(3)?,
        }))
    }
    /// Every log of a scope in author order; `pruned` keeps only logs with a pruned_prefix.
    pub(super) async fn logs(
        &self,
        scope: i64,
        after: Option<PublicKey>,
        pruned: bool,
        limit: usize,
    ) -> Result<Vec<(LogPosition, i64)>, Error> {
        let records = collect_rows(
            self.conn
                .query(
                    "SELECT author,sequence,hash,clock,pruned_prefix FROM secure_logs WHERE scope=? AND author>? AND pruned_prefix>=? ORDER BY author LIMIT ?",
                    bindings(vec![
                        SqlValue::Integer(scope),
                        SqlValue::Blob(after.map(|key| key.as_bytes().to_vec()).unwrap_or_default()),
                        SqlValue::Integer(if pruned { 0 } else { -1 }),
                        SqlValue::Integer(limit as i64),
                    ]),
                )
                .await?,
        )
        .await?;
        records
            .into_iter()
            .map(|record| {
                let [
                    SqlValue::Blob(author),
                    SqlValue::Integer(sequence),
                    SqlValue::Blob(hash),
                    SqlValue::Integer(clock),
                    SqlValue::Integer(pruned_prefix),
                ] = record.as_slice()
                else {
                    return Err(Error::Corrupt("log record".into()));
                };
                Ok((
                    LogPosition {
                        author: key_of(author)?,
                        sequence: *sequence as u64,
                        hash: hash_of(hash)?,
                        clock: *clock as u64,
                    },
                    *pruned_prefix,
                ))
            })
            .collect()
    }
    pub(super) async fn retains(&self, hash: Hash) -> Result<bool, Error> {
        let mut result = self
            .conn
            .query(
                "SELECT 1 FROM secure_operations WHERE hash=?",
                [hash.as_bytes().to_vec()],
            )
            .await?;
        Ok(result.next().await?.is_some())
    }
    /// A pruned operation still known as applied: its scope and clock.
    pub(super) async fn stub(&self, hash: Hash) -> Result<Option<(i64, u64)>, Error> {
        let mut result = self
            .conn
            .query(
                "SELECT scope,clock FROM secure_stubs WHERE hash=?",
                [hash.as_bytes().to_vec()],
            )
            .await?;
        Ok(match result.next().await? {
            Some(row) => Some((row.get::<i64>(0)?, row.get::<i64>(1)? as u64)),
            None => None,
        })
    }
    /// The clock of a stored row's creation: its stub once pruned, else
    /// its retained operation's.
    pub(super) async fn creation_clock(&self, hash: Hash) -> Result<Option<u64>, Error> {
        if let Some((_, clock)) = self.stub(hash).await? {
            return Ok(Some(clock));
        }
        match collect_rows(
            self.conn
                .query(
                    "SELECT header FROM secure_operations WHERE hash=?",
                    [hash.as_bytes().to_vec()],
                )
                .await?,
        )
        .await?
        .first()
        .map(Vec::as_slice)
        {
            Some([SqlValue::Blob(header)]) => Ok(Some(
                decode::<p2panda_core::Header<Extensions>>(header)?.timestamp,
            )),
            _ => Ok(None),
        }
    }
    pub(super) async fn put_stub(
        &self,
        hash: Hash,
        scope: i64,
        clock: u64,
        creation: bool,
    ) -> Result<(), Error> {
        self.conn
            .execute(
                "INSERT INTO secure_stubs VALUES(?,?,?,?) ON CONFLICT(hash) DO UPDATE SET creation=MAX(creation,excluded.creation)",
                bindings(vec![
                    SqlValue::Blob(hash.as_bytes().to_vec()),
                    SqlValue::Integer(scope),
                    integer(clock),
                    SqlValue::Integer(i64::from(creation)),
                ]),
            )
            .await?;
        Ok(())
    }
    /// Records an applied operation: its position and its log's new tip.
    pub(super) async fn note_applied(
        &self,
        scope: i64,
        operation: &p2panda_core::Operation<Extensions>,
    ) -> Result<(), Error> {
        self.conn
            .execute(
                "INSERT INTO secure_applied(scope,hash) VALUES(?,?)",
                bindings(vec![
                    SqlValue::Integer(scope),
                    SqlValue::Blob(operation.hash.as_bytes().to_vec()),
                ]),
            )
            .await?;
        self.conn
            .execute(
                "INSERT INTO secure_logs VALUES(?,?,?,?,?,-1) ON CONFLICT(scope,author) DO UPDATE SET sequence=excluded.sequence,hash=excluded.hash,clock=excluded.clock",
                bindings(vec![
                    SqlValue::Integer(scope),
                    SqlValue::Blob(operation.header.public_key.as_bytes().to_vec()),
                    integer(operation.header.seq_num),
                    SqlValue::Blob(operation.hash.as_bytes().to_vec()),
                    integer(operation.header.timestamp),
                ]),
            )
            .await?;
        Ok(())
    }
    /// Retained operations and their header and body bytes.
    pub(super) async fn retained(&self) -> Result<(u64, u64), Error> {
        let record = rows(&self.conn, "SELECT records,bytes FROM secure_retained").await?;
        match record.first().map(Vec::as_slice) {
            Some([SqlValue::Integer(records), SqlValue::Integer(bytes)]) => {
                Ok((*records as u64, *bytes as u64))
            }
            _ => Err(Error::Corrupt("retained history counters".into())),
        }
    }
    pub(super) async fn handle_set(&self) -> Result<(u64, Lt), Error> {
        let mut result = self
            .conn
            .query("SELECT handles,handle_digest FROM secure_retained", ())
            .await?;
        let row = result
            .next()
            .await?
            .ok_or_else(|| Error::Corrupt("retained history counters".into()))?;
        Ok((
            row.get::<i64>(0)? as u64,
            Lt::from_bytes(&row.get::<Vec<u8>>(1)?)?,
        ))
    }
    /// Stores a mutation handle and adds it to the retained handle set.
    pub(crate) async fn put_handle(
        &self,
        handle: &[u8],
        input: &[u8],
        hash: &[u8],
    ) -> Result<(), Error> {
        let inserted = self
            .conn
            .execute(
                "INSERT INTO secure_handles VALUES(?,?,?) ON CONFLICT(handle) DO NOTHING",
                [handle.to_vec(), input.to_vec(), hash.to_vec()],
            )
            .await?;
        if inserted == 1 {
            let (count, mut digest) = self.handle_set().await?;
            digest.add(HANDLE_LABEL, &handle_item(handle, input, hash));
            self.conn
                .execute(
                    "UPDATE secure_retained SET handles=?,handle_digest=?",
                    bindings(vec![integer(count + 1), SqlValue::Blob(digest.to_bytes())]),
                )
                .await?;
        }
        Ok(())
    }
    /// Forgets up to `limit` of the oldest handles beyond `limits.handles`
    /// whose operations are pruned. Handles of retained operations stay.
    pub(super) async fn forget_handles(&self, limit: usize) -> Result<(), Error> {
        let (count, mut digest) = self.handle_set().await?;
        let excess = count.saturating_sub(self.limits.handles as u64);
        if excess == 0 {
            return Ok(());
        }
        let forgotten = collect_rows(
            self.conn
                .query(
                    "SELECT rowid,handle,input,hash FROM secure_handles h WHERE NOT EXISTS(SELECT 1 FROM secure_operations o WHERE o.hash=h.hash) ORDER BY rowid LIMIT ?",
                    [excess.min(limit as u64) as i64],
                )
                .await?,
        )
        .await?;
        for record in &forgotten {
            let [
                SqlValue::Integer(rowid),
                SqlValue::Blob(handle),
                SqlValue::Blob(input),
                SqlValue::Blob(hash),
            ] = record.as_slice()
            else {
                return Err(Error::Corrupt("mutation handle".into()));
            };
            self.conn
                .execute("DELETE FROM secure_handles WHERE rowid=?", [*rowid])
                .await?;
            self.conn
                .execute(
                    "DELETE FROM secure_bundle_handles WHERE handle=?",
                    [handle.clone()],
                )
                .await?;
            digest.remove(HANDLE_LABEL, &handle_item(handle, input, hash));
        }
        if !forgotten.is_empty() {
            self.conn
                .execute(
                    "UPDATE secure_retained SET handles=?,handle_digest=?",
                    bindings(vec![
                        integer(count - forgotten.len() as u64),
                        SqlValue::Blob(digest.to_bytes()),
                    ]),
                )
                .await?;
        }
        Ok(())
    }
    /// The newest checkpoint record of a scope, or its newest verified one.
    pub(super) async fn checkpoint_record(
        &self,
        scope: i64,
        verified: bool,
    ) -> Result<Option<Record>, Error> {
        if let Some(record) = self
            .metadata
            .with(|cache| cache.checkpoints.get(&scope).cloned())
        {
            return Ok(record);
        }
        let mut result = self
            .conn
            .query(
                "SELECT position,sets,signed FROM secure_checkpoints WHERE scope=? ORDER BY sequence DESC LIMIT 1",
                [scope],
            )
            .await?;
        let record = match result.next().await? {
            Some(row) => Some(Record {
                position: row.get::<i64>(0)?,
                sets: Sets::from_bytes(&row.get::<Vec<u8>>(1)?)?,
                signed: Some(self.decoded_checkpoint((scope, verified), row.get::<Vec<u8>>(2)?)?),
            }),
            None => None,
        };
        self.metadata.with(|cache| {
            cache.checkpoints.insert(scope, record.clone());
        });
        Ok(record)
    }
    /// Decodes a stored statement once; maintenance reads it in every step.
    fn decoded_checkpoint(
        &self,
        scope: (i64, bool),
        bytes: Vec<u8>,
    ) -> Result<SignedCheckpoint, Error> {
        let mut cache = self
            .decoded_checkpoints
            .lock()
            .map_err(|_| Error::Corrupt("checkpoint cache poisoned".into()))?;
        if let Some((held, signed)) = cache.get(&scope)
            && *held == bytes
        {
            return Ok(signed.clone());
        }
        let signed = SignedCheckpoint::from_bytes(&bytes)?;
        cache.insert(scope, (bytes, signed.clone()));
        Ok(signed)
    }
    /// A stored checkpoint is used only while it still verifies: signature,
    /// installed definition, scope and the row sets it was sealed over.
    pub(super) fn verify_record(
        &self,
        scope: ResourceScope,
        record: &Record,
    ) -> Result<SignedCheckpoint, Error> {
        let unverifiable = |reason: &str| Error::Corrupt(format!("checkpoint {reason}"));
        let signed = record
            .signed
            .clone()
            .ok_or_else(|| unverifiable("statement is missing"))?;
        signed
            .verify_signature()
            .map_err(|_| unverifiable("signature is invalid"))?;
        let statement = &signed.statement;
        // A checkpoint made before an upgrade stays valid while its
        // generation is admitted.
        let generation = self
            .generation_of(self.manifest_of_tip(statement.tip)?, false)
            .map_err(|_| unverifiable("names a definition this replica no longer admits"))?;
        if statement.schema != generation.schema
            || statement.scope != scope
            || statement.rows != record.sets.rows_summary()
            || statement.tombstones != record.sets.tombstones
            || statement.creations != record.sets.creations_summary()
        {
            return Err(unverifiable(
                "differs from the installed definition or stored rows",
            ));
        }
        Ok(signed)
    }
    /// The key of a scope this node may read in whole.
    pub(super) fn scope_key(
        &self,
        scope: ResourceScope,
    ) -> Result<(rocky_core::KeyEpoch, [u8; 32]), Error> {
        if !self.can_read_key(scope, &self.local_grants(now()?)?) {
            return Err(denied("checkpoint needs whole-scope read authority"));
        }
        self.config
            .keys
            .iter()
            .find(|key| key.scope == scope)
            .map(|key| (key.generation, key.key))
            .ok_or_else(|| denied("checkpoint needs the scope key"))
    }
    /// One stored row record from an overlay, else from the checkpoint rows,
    /// or the stored rows for a rewind. An empty overlay record marks a row
    /// a finalized seal dropped or a kept seal did not have.
    pub(super) async fn replay_row(
        &self,
        overlay: Overlay,
        scope: i64,
        row: Commitment,
    ) -> Result<Option<Vec<u8>>, Error> {
        let over = format!(
            "SELECT fields FROM {} WHERE scope=? AND row=?",
            overlay.table()
        );
        for (index, sql) in [over.as_str(), overlay.under()].into_iter().enumerate() {
            if index == 1 && self.ignores_base() && !matches!(overlay, Overlay::Rewind) {
                continue;
            }
            let mut result = self
                .conn
                .query(
                    sql.to_string(),
                    bindings(vec![SqlValue::Integer(scope), SqlValue::Blob(row.to_vec())]),
                )
                .await?;
            if let Some(record) = result.next().await? {
                let fields = record.get::<Vec<u8>>(0)?;
                return Ok((!fields.is_empty()).then_some(fields));
            }
        }
        Ok(None)
    }
    /// Replays applied operations with positions in `(after, through]` in
    /// application order into `overlay`, at most `limit`, and folds every row
    /// change into `sets`. Each operation opens with the key epoch that
    /// sealed it. Returns the last position replayed.
    // The scope, its base, the view and target replayed, and the bounds.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn replay(
        &self,
        scope: ResourceScope,
        id: i64,
        overlay: Overlay,
        target: TipId,
        (after, through): (i64, i64),
        limit: usize,
        sets: &mut Sets,
        ledger: &mut identity::IdentityLedger,
        mode: ReplayMode,
    ) -> Result<Option<i64>, Error> {
        let records = collect_rows(
            self.conn
                .query(
                    if mode == ReplayMode::Rows {
                        ROW_REPLAY_SQL
                    } else {
                        "SELECT a.position,o.header,o.body,o.status FROM secure_applied a LEFT JOIN secure_operations o ON o.hash=a.hash WHERE a.scope=? AND a.position>? AND a.position<=? ORDER BY a.position LIMIT ?"
                    },
                    bindings(vec![
                        SqlValue::Integer(id),
                        SqlValue::Integer(after),
                        SqlValue::Integer(through),
                        SqlValue::Integer(limit as i64),
                    ]),
                )
                .await?,
        )
        .await?;
        #[cfg(feature = "qualification")]
        self.flusher
            .measurements
            .work(super::lock::WorkUnit::ReplayedFrame, records.len() as u64);
        let mut last = None;
        let finalized = self.seal_finalized(scope).await?;
        let mut paths = HashMap::new();
        for record in records {
            let [
                SqlValue::Integer(position),
                SqlValue::Blob(header),
                SqlValue::Blob(body),
                SqlValue::Text(status),
            ] = record.as_slice()
            else {
                return Err(Error::Corrupt(
                    "an applied operation after the checkpoint is not retained".into(),
                ));
            };
            let frame = self.chained_frame(header.clone(), body.clone()).await?;
            let operation = frame.operation_ref()?;
            // A frame of another line, such as a branch this device left,
            // or of an ancestor tip past the seal the path leaves it at, is
            // no part of the target's state.
            let e = &operation.header.extensions;
            let visible = match self.graphs.get(&scope.domain) {
                Some(graph) => {
                    let path = match paths.entry(e.tip) {
                        std::collections::hash_map::Entry::Occupied(path) => path.into_mut(),
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            entry.insert(Self::frame_path(graph, e.tip, target)?)
                        }
                    };
                    path.admits(
                        e.author.ok_or_else(|| denied("node author missing"))?,
                        e.author_sequence,
                    )?
                }
                None => true,
            };
            if !self.replay_eligible(status, operation, self.rebuilding_tip)? || !visible {
                last = Some(*position);
                continue;
            }
            if self
                .manifest_of_tip(operation.header.extensions.tip)
                .and_then(|manifest| self.known(manifest))
                .is_err()
                || !self
                    .dependencies_ready(&frame, &BTreeSet::new(), None)
                    .await?
            {
                return Err(denied("applied encrypted dependency missing"));
            }
            let payload = self.row_payload(&frame)?;
            if operation.header.extensions.scope != scope {
                return Err(denied("replay scope mismatch"));
            }
            let writes = restore::replay_changes(scope, &payload)?;
            let mut created = false;
            // Births compare with the marks the frame entered with, as live
            // application loads them once per frame.
            if mode == ReplayMode::Rows {
                *ledger = self
                    .row_replay_ledger(
                        scope,
                        id,
                        position
                            .checked_sub(1)
                            .ok_or_else(|| Error::Corrupt("applied position underflow".into()))?,
                        target,
                    )
                    .await?;
            }
            let entry = ledger.clone();
            let mut identities = BTreeSet::new();
            let path_fields =
                self.path_fields_to(scope.domain, operation.header.extensions.tip, target)?;
            // The live schema reads a write through its own path's fields.
            let live_fields = if target == self.workspace.tip {
                None
            } else {
                Some(self.path_fields(scope.domain, operation.header.extensions.tip)?)
            };
            let prior = self.receipt_of(operation.hash).await?;
            if let Some((_, receipt)) = &prior {
                self.check_frame_receipt(receipt, &frame, writes, &payload)
                    .await?;
            }
            let allocation = match mode {
                ReplayMode::Mint | ReplayMode::Rows => self.optional_allocation_of(scope).await?,
                ReplayMode::Check => self.allocation_binding(scope).await?,
            };
            let allocation_marks = match allocation {
                Some((_, allocation)) => self.identity_marks(allocation).await?,
                None => Vec::new(),
            };
            let mut snapshot = identity::receipts::BirthSnapshot {
                permanent: self.identity_marks(scope).await?,
                own: self.own_marks(scope).await?,
                allocation: allocation_marks,
                ledger: entry,
                summary: self.summary_marks(scope).await?,
                receipt: prior,
                claims: Default::default(),
            };
            let mut changed = BTreeSet::new();
            for (ordinal, write) in writes.iter().enumerate() {
                let Some(write) = path_fields.current(write) else {
                    continue;
                };
                let live = match &live_fields {
                    Some(fields) => fields.project(&write),
                    None => Some(write.clone()),
                };
                let row = match &live {
                    Some(live) => self.storage_row(&live.change)?,
                    None => write.change.row,
                };
                if mode == ReplayMode::Rows {
                    let mut selected = self
                        .conn
                        .query(
                            "SELECT 1 FROM secure_finalization_rows WHERE scope=? AND row=?",
                            bindings(vec![SqlValue::Integer(id), SqlValue::Blob(row.to_vec())]),
                        )
                        .await?;
                    if selected.next().await?.is_none() {
                        continue;
                    }
                }
                let old = self.replay_row(overlay, id, row).await?;
                let current: Option<Materialized> = self.optional_record(old.as_deref()).await?;
                let carried = payload.carried(&write.change.row);
                let identity = if write.change.before.is_none() {
                    live.as_ref()
                        .map(|live| self.app.row_identity(&live.change))
                        .transpose()
                        .map_err(|message| denied(&message))?
                        .flatten()
                } else {
                    None
                };
                let mut restoration = None;
                let mut observation = None;
                if let Some(identity) = identity {
                    if !identities.insert(identity) {
                        return Err(denied("forged row author or reused identity sequence"));
                    }
                    let (signer, provenance) = match carried {
                        Some(carried) => (carried.proof.signer()?, carried.proof.provenance()?),
                        None => (
                            operation.header.public_key,
                            payload
                                .proof(&write.change.row)
                                .ok_or_else(|| denied("numeric birth requires a creation proof"))?
                                .provenance()?,
                        ),
                    };
                    match self
                        .classify_birth(
                            allocation.ok_or_else(|| {
                                Error::Corrupt("applied identity allocation missing".into())
                            })?,
                            &mut snapshot,
                            identity::receipts::BirthInput {
                                frame: operation.hash,
                                ordinal: ordinal as u8,
                                identity,
                                provenance,
                                signer,
                                author: operation.header.extensions.author,
                                carried: carried.is_some(),
                                existing: current.is_some(),
                                finalized,
                                target,
                                first: false,
                            },
                        )
                        .await?
                    {
                        identity::receipts::BirthClass::Suppressed(_) => continue,
                        identity::receipts::BirthClass::Restore(grant) => restoration = Some(grant),
                        identity::receipts::BirthClass::Exact => {}
                        identity::receipts::BirthClass::Observe(record) => {
                            observation = Some(record)
                        }
                        identity::receipts::BirthClass::Created
                        | identity::receipts::BirthClass::Carried => {
                            return Err(Error::Corrupt("replay cannot first-admit a birth".into()));
                        }
                    }
                }
                let ceiling = Stamp {
                    clock: operation.header.timestamp,
                    author: operation.header.extensions.author.unwrap_or(0),
                    sequence: operation.header.extensions.author_sequence,
                };
                if restoration.is_some() {
                    let checked = async {
                        self.check_write(
                            &write,
                            scope,
                            &mut changed,
                            operation.header.extensions.partition.clone(),
                        )
                        .await?;
                        self.app
                            .validate_changes(std::slice::from_ref(&write.change))
                            .map_err(|message| denied(&message))?;
                        let proof = payload
                            .proof(&write.change.row)
                            .ok_or_else(|| denied("numeric birth requires a creation proof"))?;
                        proof.verify(
                            self.config.publisher,
                            self.manifest_of_tip(operation.header.extensions.tip)?,
                            scope.table,
                            identity
                                .ok_or_else(|| Error::Corrupt("restoration identity".into()))?,
                            &ceiling,
                        )?;
                        if proof.stamp() != &ceiling {
                            return Err(denied("birth proof must name its creating frame stamp"));
                        }
                        Ok::<_, Error>(())
                    }
                    .await;
                    match checked {
                        Ok(()) => {}
                        Err(error) if identity::receipts::semantic_refusal(&error) => continue,
                        Err(error) => return Err(error),
                    }
                }
                if let Some(carried) = carried {
                    if payload.membership().is_none() {
                        return Err(denied("a move or follow requires a transaction bundle"));
                    }
                    self.check_carried(&write, carried, &ceiling)?;
                }
                if let Some(live) = &live
                    && self
                        .app
                        .row_partition(&live.change)
                        .map_err(|error| denied(&error))?
                        != operation.header.extensions.partition
                {
                    return Err(denied("replayed row differs from its partition"));
                }

                if finalized
                    && ((write.change.before.is_some() && current.is_none())
                        || (write.change.before.is_none() && current.is_some()))
                {
                    continue;
                }
                created |= current.is_none();
                let prior = current
                    .as_ref()
                    .map(|record| Ok::<_, Error>((encode(record)?, record.deleted)))
                    .transpose()?;
                let (_, mut record) = apply::merge_row(
                    &write,
                    current,
                    operation,
                    payload.carried(&write.change.row),
                )?;
                if write.change.before.is_none() && payload.carried(&write.change.row).is_none() {
                    record.proof = payload
                        .proof(&write.change.row)
                        .map(moves::CreationProof::stored)
                        .transpose()?;
                }
                record.key = Some(write.change.row);
                record.identity = live
                    .as_ref()
                    .map(|live| self.app.row_identity(&live.change))
                    .transpose()
                    .map_err(|message| denied(&message))?
                    .flatten()
                    .map(|identity| identity.integer());
                if let Some(grant) = restoration {
                    let actual = RowChange {
                        scope,
                        row: write.change.row,
                        before: None,
                        after: Some(record.fields.clone()),
                    };
                    if self
                        .app
                        .validate_changes(std::slice::from_ref(&actual))
                        .is_err()
                    {
                        continue;
                    }
                    if mode == ReplayMode::Check {
                        return Err(Error::Corrupt(
                            "an eligible restoration has no grant".into(),
                        ));
                    }
                    self.put_identity_mark(
                        scope,
                        &IdentityMark {
                            author: grant.identity.author(),
                            signer: operation.header.public_key,
                            sequence: grant.identity.sequence(),
                        },
                        identity::Raise::Own,
                    )
                    .await?;
                    self.append_admission(identity::receipts::EntryKind::Restoration(grant))
                        .await?;
                }
                if let Some(observation) = observation {
                    if mode == ReplayMode::Check {
                        return Err(Error::Corrupt(
                            "an eligible carry has no observation".into(),
                        ));
                    }
                    self.append_admission(identity::receipts::EntryKind::CarryObservation(
                        observation,
                    ))
                    .await?;
                }
                let new = match mode {
                    ReplayMode::Mint | ReplayMode::Rows => {
                        if let Some(proof) = payload
                            .carried(&write.change.row)
                            .map(|carried| &carried.proof)
                            .or_else(|| payload.proof(&write.change.row))
                            .filter(|_| record.proof.is_some())
                        {
                            self.keep_bindings(proof).await?;
                        }
                        self.encode_record(&record).await?
                    }
                    ReplayMode::Check => self.encode_existing_record(&record).await?,
                };
                sets.replace_encoded(
                    &row,
                    prior
                        .as_ref()
                        .map(|(bytes, deleted)| (bytes.as_slice(), *deleted)),
                    (&encode(&record)?, record.deleted),
                );
                self.conn
                    .execute(
                        format!("INSERT OR REPLACE INTO {} VALUES(?,?,?)", overlay.table()),
                        bindings(vec![
                            SqlValue::Integer(id),
                            SqlValue::Blob(row.to_vec()),
                            SqlValue::Blob(new),
                        ]),
                    )
                    .await?;
            }
            if created {
                sets.create(operation.hash, operation.header.timestamp);
                if matches!(overlay, Overlay::Build) {
                    self.put_stub(operation.hash, id, operation.header.timestamp, true)
                        .await?;
                }
            }
            // Own births retire sequences in replay order even without a row;
            // another author's carry cannot retire that author's log.
            for birth in self.payload_birth_marks(&frame, &payload)? {
                if !birth.carried {
                    ledger.merge(birth.mark)?;
                }
            }
            last = Some(*position);
        }
        Ok(last)
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// Sets when covered operations of a scope may be pruned. Without a
    /// policy nothing is pruned.
    pub async fn set_retention_policy(
        &self,
        scope: ResourceScope,
        policy: RetentionPolicy,
    ) -> Result<(), Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        if policy.required.len() > 64
            || policy.behind.len() > 64
            || policy.copies > 64
            || policy.required.contains(&rocky_credentials::PeerId::of(
                inner.config.node.public_key(),
            ))
        {
            return Err(denied("invalid retention policy"));
        }
        if !inner.local_grants(now()?)?.iter().any(|grant| {
            grant.scope == scope
                && grant.rows == RowSelection::All
                && (grant.rights.contains(&Right::Read) || grant.rights.contains(&Right::Custody))
        }) {
            return Err(denied("retention configuration denied"));
        }
        let values = [encode(&scope)?, encode(&policy)?];
        transaction!(inner, |inner| {
            inner
                .conn
                .execute(
                    "INSERT INTO secure_retention VALUES(?,?) ON CONFLICT(scope) DO UPDATE SET policy=excluded.policy",
                    values.clone(),
                )
                .await?;
            Ok(())
        })
    }
    /// The persisted pruning policy, if one was configured.
    pub async fn retention_policy(
        &self,
        scope: ResourceScope,
    ) -> Result<Option<RetentionPolicy>, Error> {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .retention_policy(scope)
            .await
    }
    /// The retained-history bounds of this open replica.
    pub async fn retention_limits(&self) -> RetentionLimits {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .limits
    }
    /// Replaces the retained-history bounds of this open replica.
    pub async fn set_retention_limits(&self, limits: RetentionLimits) -> Result<(), Error> {
        if limits.hard_bytes == 0 {
            return Err(denied("invalid retention limits"));
        }
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .limits = limits;
        Ok(())
    }
    pub async fn checkpoint_status(&self, scope: ResourceScope) -> Result<CheckpointStatus, Error> {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        let mut status = CheckpointStatus {
            checkpoint: None,
            uncovered: 0,
            covered: 0,
            pending: 0,
            pruned_prefix: vec![],
            retained_bytes: inner.retained().await?.1,
            maintenance_error: inner.maintenance_error.clone(),
        };
        let pending = collect_rows(
            inner
                .conn
                .query(
                    "SELECT COUNT(*) FROM secure_operations WHERE scope=? AND status='pending'",
                    [encode(&scope)?],
                )
                .await?,
        )
        .await?;
        if let Some([SqlValue::Integer(count)]) = pending.first().map(Vec::as_slice) {
            status.pending = *count as u64;
        }
        let Some(id) = inner.find_scope_id(scope).await? else {
            return Ok(status);
        };
        let verified = inner.checkpoint_record(id, true).await?;
        let position = verified.as_ref().map_or(0, |record| record.position);
        status.checkpoint = verified.and_then(|record| record.signed);
        let counts = collect_rows(
            inner
                .conn
                .query(
                    "SELECT COALESCE(SUM(position>?),0),COALESCE(SUM(position<=?),0) FROM secure_applied WHERE scope=?",
                    [position, position, id],
                )
                .await?,
        )
        .await?;
        if let Some([SqlValue::Integer(uncovered), SqlValue::Integer(covered)]) =
            counts.first().map(Vec::as_slice)
        {
            status.uncovered = *uncovered as u64;
            status.covered = *covered as u64;
        }
        status.pruned_prefix = inner
            .logs(id, None, true, MAX_CHECKPOINT_LOGS)
            .await?
            .into_iter()
            .map(|(log, pruned_prefix)| (log.author, pruned_prefix as u64))
            .collect();
        Ok(status)
    }
    /// The operation a mutation handle committed, also after it was pruned,
    /// while the handle is inside `RetentionLimits::handles`.
    pub async fn lookup_mutation(&self, handle: Commitment) -> Result<Option<Hash>, Error> {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        let mut result = inner
            .conn
            .query(
                "SELECT hash FROM secure_handles WHERE handle=?",
                [handle.to_vec()],
            )
            .await?;
        let hash = match result.next().await? {
            Some(row) => hash_of(&row.get::<Vec<u8>>(0)?)?,
            None => return Ok(None),
        };
        drop(result);
        Ok(Some(hash))
    }
    #[cfg(test)]
    pub(crate) async fn verify_checkpoint_at_for_test(
        &self,
        signed: &SignedCheckpoint,
        time: u64,
    ) -> Result<(), Error> {
        signed.verify_authority(
            &*self.inner.lock(crate::replica::Class::Background).await,
            time,
        )
    }
    #[cfg(test)]
    pub(crate) async fn maintain_checkpoint_for_test(&self, scope: ResourceScope) {
        self.maintain_scopes([scope].into()).await;
    }
    #[cfg(test)]
    pub(crate) async fn inject_stage_fault(&self, stage: Stage, skip: usize) {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .stage_fault = Some((stage, skip));
    }
    /// Exits the process inside the step's transaction instead of failing it.
    #[cfg(test)]
    pub(crate) async fn inject_stage_exit(&self, stage: Stage, skip: usize) {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        inner.stage_fault = Some((stage, skip));
        inner.stage_exit = true;
    }
}

impl<A: RowApplication> Inner<A> {}
