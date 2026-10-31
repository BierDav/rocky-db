mod admission;
pub(crate) mod lock;
mod maintenance;
mod wal;
#[cfg(any(test, feature = "qualification"))]
pub use lock::LockMeasurements;
pub(crate) use lock::{Class, Guard, ReplicaLock};
#[cfg(feature = "qualification")]
pub use lock::{HolderMeasurements, Measurements, with_measurement_connection};
mod apply;
mod author;
mod backup;
mod blockers;
mod bulk;
pub use bulk::{MigrationMembership, MigrationStorage};
pub(super) mod bundle;
mod chains;
pub(crate) mod checkpoint;
mod compaction;
mod crypto;
pub use compaction::{CompactReport, CompactionStatus, FrameReplay, SealRebootstrap};
mod coordinated;
#[cfg(any(test, feature = "qualification"))]
mod crash;
#[cfg(any(test, feature = "qualification"))]
pub use crash::CrashPoint;
mod evict;
mod frontiers;
mod generation;
mod schemas;
mod staging;
pub use staging::SchemaStage;
mod inplace;
pub use schemas::{
    InstalledTipSchema, PendingSchema, SchemaConfig, installed_tip_schema,
    last_in_place_switch_changes,
};
pub(super) mod group;
pub(crate) mod headers;
mod held;
mod history;
pub use history::{HeldSeal, KeptSeals, SealViews};
mod author_sets;
mod holdings;
mod identity;
mod incoming;
mod intents;
mod keys;
mod metadata;
pub(crate) mod migrate;
pub(crate) mod moves;
mod offload;
mod partition;
mod placements;
pub(super) mod positions;
mod records;
mod stamp_authors;
pub use placements::{MAX_PLACEMENTS, Placement, PlacementPage, PlacementRequest};
pub(crate) mod publication;
mod quarantine;
mod queries;
mod reads;
mod rebuild;
mod recovery;
mod removal;
pub(crate) mod replay;
pub use removal::{local_row_counts, local_table_digests};
pub use replay::outcomes::OutcomeDivergence;
mod restore;
pub(super) mod roles;
mod session;
mod sql;
mod tip_drop;
mod tip_observation;
pub use tip_observation::{
    EarlierEpochWrites, PeerScopeFrontier, TipDevice, TipNodeObservation, TipObservation,
};
pub(crate) mod tips;
pub use tips::{LineNode, TipStatement};
mod typed;
mod workspace;
use super::store::{SCHEMA, TransactionStore};
use super::wire::{Chain, Extensions, Membership, ROW_FORMAT, RowPayload, author, decrypt};
use super::*;
use crate::{
    database::DatabaseOwner,
    scoped_connection::ScopedConnection,
    storage::{bindings, collect_rows, retryable, rows},
};
pub use admission::MAX_UNCONFIGURED_PEERS;
pub use bundle::{MAX_BUNDLE_BYTES, MAX_BUNDLE_FRAMES, MAX_BUNDLE_ROWS, ROWS_PER_FRAME};
pub use checkpoint::{
    AuditReport, CheckpointPage, CheckpointState, CheckpointStatement, CheckpointStatus,
    CoveredMark, CustodySummary, LogPosition, MAX_CHECKPOINT_LOGS, PruneBlock, PruneReport,
    PrunedPage, RebootstrapReport, RetentionLimits, RetentionPolicy, SetSummary, SignedCheckpoint,
};
pub use coordinated::{Refusal, StagedCloseStatus};
pub use evict::EvictReport;
pub use generation::GenerationStatus;
pub use held::{CurrentValue, HeldChange, HeldField, HeldKind, HeldRow, SignedVoid};
pub use migrate::ProjectionPlan;
pub use offload::RemotePage;
use p2panda_core::validate_backlink;
use p2panda_store::operations::LocalOperationStore;
#[cfg(feature = "qualification")]
pub use publication::CHUNK_PAGES;
pub use publication::{PUBLICATION_CHUNK_BUNDLES, Publication};
pub use queries::Describe;
use rocky_core::{
    Blocker, BlockerKind, ClearsBy, Commitment, ResourceScope, Right, RowApplication, RowChange,
    RowFields, RowSelection, RowWrite, SqlValue, TipId, WaitReason,
};
pub use roles::{
    FrontierLog, Holding, PeerLag, RangePage, ReplicaRole, ReplicaStatus, RoleConfig,
    ScopeFrontier, ScopeStatus, StateAdvice,
};
use serde::{Deserialize, Serialize};
pub use session::{SecureSession, SecureTransaction, SessionStatus, UpdateMode};
pub use sql::{SecureCommit, SecureRows, SecureSql};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::watch;

/// Keys are supplied from external secret storage and are never persisted in protocol tables.
/// A scope may hold several generations: the highest seals new writes, the
/// others open what they sealed.
#[derive(Clone)]
pub struct KeyMaterial {
    pub scope: ResourceScope,
    pub generation: rocky_core::KeyEpoch,
    pub key: [u8; 32],
}
impl KeyMaterial {
    pub fn new(scope: ResourceScope, generation: u64, key: [u8; 32]) -> Self {
        Self {
            scope,
            generation: rocky_core::KeyEpoch::new(generation, &key),
            key,
        }
    }
    /// Uses the group secret's identity for every derived table key.
    pub fn at(scope: ResourceScope, generation: rocky_core::KeyEpoch, key: [u8; 32]) -> Self {
        Self {
            scope,
            generation,
            key,
        }
    }
}
pub struct SecureConfig {
    pub publisher: PublicKey,
    pub manifest: SignedManifest,
    /// The revocations this device verified; the replica keeps the union of
    /// these and every set it learned.
    pub revocations: RevocationSet,
    pub node: PrivateKey,
    pub credentials: CredentialChain,
    pub keys: Vec<KeyMaterial>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveStatus {
    Custody,
    PendingDependencies,
    MissingKey,
    Applied,
    /// The original signed writes are held for application-directed re-authoring.
    Held,
    Duplicate,
    Rejected,
    /// At or before this replica's pruned_prefix: already part of its checkpoint.
    Pruned,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Companion {
    Present(RowFields),
    Unavailable,
    Deleted,
}
#[derive(Clone, Debug)]
pub struct SecureSnapshot {
    pub revision: u64,
    pub rows: BTreeMap<Commitment, RowFields>,
    pub complete: bool,
}
/// One page of a scope's live rows; `next` continues after the last row read.
#[derive(Clone, Debug)]
pub struct SecurePage {
    pub revision: u64,
    pub rows: BTreeMap<Commitment, RowFields>,
    pub complete: bool,
    pub next: Option<Commitment>,
}
/// Limits of one encrypted read.
pub const MAX_SNAPSHOT_ROWS: usize = 1024;
pub const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024;
/// Stored rows fetched per query while filling a page.
const PAGE_CHUNK: usize = 256;
#[derive(Clone, Debug)]
pub struct CiphertextPage {
    pub frames: Vec<EncryptedFrame>,
    pub next: Option<Hash>,
    /// Requested scopes with pruned history. A receiver compares
    /// `pruned_page` with what it holds before it relies on this pass.
    pub pruned: Vec<ResourceScope>,
    /// Void records consuming the positions before the frames.
    pub voids: Vec<SignedVoid>,
}
pub(crate) use rocky_core::SecureStamp as Stamp;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct AuthorKey(#[serde(with = "serde_bytes")] [u8; 32]);
impl AuthorKey {
    fn key(&self) -> Result<PublicKey, Error> {
        PublicKey::from_bytes(&self.0).map_err(|_| Error::Corrupt("author key".into()))
    }
}
impl From<PublicKey> for AuthorKey {
    fn from(key: PublicKey) -> Self {
        Self(*key.as_bytes())
    }
}

/// Decoded signed checkpoints by scope number and kind, with their bytes.
type DecodedCheckpoints = HashMap<(i64, bool), (Vec<u8>, SignedCheckpoint)>;
/// Canonical row state. Local records and page legends expand to these identities.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Materialized {
    proof: Option<moves::StoredProof>,
    #[serde(with = "serde_bytes")]
    moved_from: Option<Vec<u8>>,
    #[serde(with = "byte_fields")]
    fields: RowFields,
    #[serde(with = "byte_keys")]
    stamps: BTreeMap<Commitment, Stamp>,
    authors: stamp_authors::Authors,
    deleted: bool,
    creation: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "identity::decimal")]
    identity: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "serde_bytes")]
    key: Option<Commitment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created: Option<Stamp>,
}
/// A map keyed by commitments, its keys as byte strings.
mod byte_keys {
    use super::*;
    pub(super) fn serialize<S: serde::Serializer, V: Serialize>(
        map: &BTreeMap<Commitment, V>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_map(
            map.iter()
                .map(|(key, value)| (serde_bytes::Bytes::new(key), value)),
        )
    }
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>, V: Deserialize<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<Commitment, V>, D::Error> {
        let map = BTreeMap::<serde_bytes::ByteArray<32>, V>::deserialize(deserializer)?;
        Ok(map
            .into_iter()
            .map(|(key, value)| (key.into_array(), value))
            .collect())
    }
}
/// Row fields, keys and values as byte strings.
mod byte_fields {
    use super::*;
    pub(super) fn serialize<S: serde::Serializer>(
        fields: &RowFields,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_map(
            fields
                .iter()
                .map(|(key, value)| (serde_bytes::Bytes::new(key), serde_bytes::Bytes::new(value))),
        )
    }
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<RowFields, D::Error> {
        let map = BTreeMap::<serde_bytes::ByteArray<32>, serde_bytes::ByteBuf>::deserialize(
            deserializer,
        )?;
        Ok(map
            .into_iter()
            .map(|(key, value)| (key.into_array(), value.into_vec()))
            .collect())
    }
}
pub(super) struct Inner<A> {
    _owner: Arc<DatabaseOwner>,
    pub(super) conn: Arc<ScopedConnection>,
    pub(super) app: Arc<A>,
    /// `config.keys` holds the current key of every scope.
    pub(super) config: SecureConfig,
    /// `config.credentials` with the digest this device's frames name.
    pub(super) chain: Chain,
    /// Stored chains decoded recently, by digest.
    chains: std::sync::Mutex<HashMap<Commitment, Chain>>,
    crypto: Arc<crypto::Cache>,
    /// The last checkpoint statement decoded per scope number, newest or
    /// verified, with its bytes.
    decoded_checkpoints: std::sync::Mutex<DecodedCheckpoints>,
    /// Frontiers of committed history; invalidated before ordinary write attempts.
    tip_frontiers: std::sync::Mutex<frontiers::Frontiers>,
    /// Blockers per domain; invalidated with the frontiers, after commits
    /// and by writes to the state they derive from.
    pub(crate) readiness: blockers::Readiness,
    metadata: metadata::Metadata,
    held_refresh: std::sync::Mutex<BTreeMap<ResourceScope, Commitment>>,
    stamp_authors: stamp_authors::Cache,
    author_sets: std::sync::Mutex<author_sets::Cache>,
    record_dictionary: std::sync::Mutex<records::Dictionary>,
    /// Parsed headers for the scan oracle.
    #[cfg(test)]
    frontier_headers: std::sync::Mutex<tips::StoredHeaders>,
    migration_syntax: std::sync::Mutex<bulk::syntax::StoredDescriptorSyntax>,
    #[cfg(test)]
    frontier_queries: AtomicU64,
    #[cfg(test)]
    frontier_decodes: AtomicU64,
    #[cfg(test)]
    position_oracles: positions::OracleStats,
    #[cfg(test)]
    pub(crate) compare_finalization: bool,
    #[cfg(test)]
    pub(crate) finalization_oracle_time: std::time::Duration,
    #[cfg(test)]
    pub(crate) finalization_time: std::time::Duration,
    node_author: Option<identity::NodeAuthor>,
    pub(crate) credential_signer: Option<PrivateKey>,
    partitions: BTreeMap<ResourceScope, rocky_core::PartitionTuple>,
    /// Earlier key epochs, kept to open retained ciphertext.
    pub(super) history: Vec<KeyMaterial>,
    pub(super) manifest: Commitment,
    pub(super) graphs: BTreeMap<rocky_core::Scope, rocky_credentials::TipGraph>,
    catalog: BTreeMap<Commitment, rocky_core::ApplicationManifest>,
    path_fields: std::sync::Mutex<BTreeMap<(TipId, TipId), schemas::PathFields>>,
    graph_cache: std::sync::Mutex<tips::GraphCache>,
    /// Positions of a domain's nodes only a partition's custody can place.
    custody_required: std::sync::Mutex<BTreeSet<(rocky_core::Scope, u32, u64)>>,
    /// The live tables, the tip they hold and their observers.
    pub(super) workspace: workspace::Workspace,
    line_nodes: BTreeMap<TipId, identity::NodeAuthor>,
    pub(super) definition: rocky_core::ApplicationManifest,
    pub(super) tables: HashSet<Commitment>,
    pub(super) fields: HashSet<Commitment>,
    permission_fields: HashSet<Commitment>,
    domains: HashSet<rocky_core::DomainId>,
    pub(super) revision: u64,
    /// Grows whenever policy, credentials or keys change; sessions opened
    /// under an earlier value are refused.
    pub(super) authority: u64,
    pub(super) authority_events: watch::Sender<u64>,
    /// The recovery context after the last call that committed or changed
    /// keys, grants, schemas or the tip graph; see `quarantine_context`.
    recovery_events: watch::Sender<i64>,
    /// Set while a tip switch rebuilds a scope's rows.
    rebuilding_tip: bool,
    /// Supplied exclusions wait until the stored projection and L verify,
    /// then reconcile atomically through learn_revocations before open returns.
    opening_revocations: Option<RevocationSet>,
    /// During a tip rebuild: the scope's replay base is a seal on the new
    /// tip's path, so the rebuild starts from it.
    tip_base: bool,
    /// Set while a staged publication authors its bundles: one atomic
    /// transaction of any size, so the retained-history bound cannot hold
    /// it back; later writes wait until it is delivered and pruned.
    publishing: bool,
    /// This device's grants as last resolved, for the authority, partition
    /// count and second they were resolved at: resolving the chain against
    /// every registered partition otherwise repeats for each frame and scope.
    local: std::sync::Mutex<Option<LocalGrants>>,
    /// Scopes buffered SQL commits wrote, whose maintenance step `maintain`
    /// runs after the commit answered.
    deferred_maintenance: BTreeSet<ResourceScope>,
    /// Scopes the owner imports from a checkpoint: peers do not push their
    /// history, and maintenance waits until the import ends.
    importing: BTreeSet<ResourceScope>,
    /// Why each pending log head waited when an apply pass last examined it.
    waits: BTreeMap<Hash, WaitReason>,
    /// A frame of an earlier key epoch than its scope's current one applied
    /// since the last scan, and the followed tip that scan saw.
    earlier_epoch: AtomicBool,
    epochs_scanned: Option<TipId>,
    /// Rows applied frames wrote since open, for apply spans.
    rows_written: AtomicU64,
    frames_written: AtomicU64,
    /// Pending frames apply passes applied since open.
    applied_frames: u64,
    pending_pass: incoming::PendingPass,
    follow_pass: moves::FollowPass,
    context_epoch: AtomicU64,
    /// Scopes whose import writes verified pages straight into their rows;
    /// operations for them wait until the import ends.
    direct: BTreeSet<ResourceScope>,
    /// This device's verified partition selectors for an authority and
    /// second: every statement of a partitioned schema asks for them.
    local_selectors: std::sync::Mutex<Option<LocalSelectors>>,
    pub(super) notifications: watch::Sender<u64>,
    pub(super) frames: watch::Sender<()>,
    /// Checkpoint pages stored since open, by any import.
    pub(super) imported: watch::Sender<u64>,
    wal: PathBuf,
    /// Commits with changes since open. Nothing leaves the device until the
    /// flusher's durable watermark covers it.
    pub(super) commit: u64,
    pub(super) flusher: Arc<Flusher>,
    /// `total_changes()` at the last commit, to skip commits that changed nothing.
    changes: i64,
    /// Passive and truncating checkpoint sizes.
    wal_limits: (u64, u64),
    pub(super) passive: Arc<wal::Passive>,
    pub(super) limits: RetentionLimits,
    /// The last failure of automatic checkpointing or pruning.
    maintenance_error: Option<String>,
    maintenance: maintenance::Pass,
    /// When maintenance runs again after a failure, and how many failed.
    maintenance_backoff: Option<(u64, u32)>,
    /// Commit that made each scope's checkpoint current, by scope number.
    verified_at: BTreeMap<i64, u64>,
    /// Peers whose credentials and frontiers are kept whatever the bound.
    configured: BTreeSet<PublicKey>,
    /// When each peer was last served since open, by a growing count; a
    /// peer not served since open counts as the least recent.
    served: (u64, BTreeMap<rocky_credentials::PeerId, u64>),
    /// The generation each admitted session peer declared in its hello:
    /// what it can admit. Chains name none.
    pub(super) peer_tips: BTreeMap<rocky_credentials::PeerId, TipId>,
    #[cfg(test)]
    checkpoint_export_pause: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
    #[cfg(test)]
    checkpoint_store_pause: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
    #[cfg(test)]
    migration_storage_pause: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
    #[cfg(test)]
    header_scan_pause: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
    #[cfg(test)]
    held_listing_pause: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
    #[cfg(test)]
    held_token_pause: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
    #[cfg(test)]
    stage_fault: Option<(checkpoint::Stage, usize)>,
    /// The armed crash point and the one that fired.
    #[cfg(any(test, feature = "qualification"))]
    crash: std::sync::Mutex<(Option<CrashPoint>, Option<CrashPoint>)>,
    /// Fails publication after this step: 1 journaled, 2 committed at
    /// the coordinator, 3 inside the admission transaction.
    #[cfg(test)]
    publication_fault: Option<u8>,
    #[cfg(test)]
    schema_stage_pause: Option<staging::StagePause>,
    #[cfg(test)]
    plan_fault: bool,
    /// The stage fault exits the process instead of returning an error.
    #[cfg(test)]
    stage_exit: bool,
    /// Adopts generations in a domain with a tip graph, which production
    /// refuses until schema changes are seals.
    #[cfg(test)]
    pub(super) fail_before_commit: usize,
    #[cfg(test)]
    pub(super) fail_sql_commit: bool,
    /// Authors replayed effects without checking them, as a replica that
    /// skips its own admission would.
    #[cfg(test)]
    pub(super) unchecked_replayed_admission: bool,
    /// Tip switches rebuild from the replay base, as without kept seals.
    #[cfg(test)]
    pub(super) rebuild_switches: bool,
    /// Scopes rebuilt from a kept seal's rows by tip switches.
    #[cfg(test)]
    pub(super) rewound: usize,
    #[cfg(test)]
    pub(super) retry_before_commit: usize,
    #[cfg(test)]
    pub(super) group_fault: Option<group::GroupFault>,
    /// Pauses the next receive after its early checks, before it queues:
    /// signals the first sender, then waits for the second.
    #[cfg(test)]
    receive_gate: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
    /// Frames whose application fails as their own fault, for quarantine.
    #[cfg(test)]
    pub(super) poisoned: BTreeSet<Hash>,
    #[cfg(test)]
    pub(super) group_commits: usize,
    #[cfg(test)]
    pub(super) checkpoints: usize,
    #[cfg(test)]
    pub(super) audit_global_passes: usize,
    #[cfg(test)]
    pub(super) busy_hook: Option<Box<dyn FnMut(usize) + Send + Sync>>,
}
/// The durable watermark and the device flush that advances it. Shared, so a
/// group's flush runs after the replica lock is released and readers and the
/// next group do not wait behind it.
pub(super) struct Flusher {
    #[cfg(any(test, feature = "qualification"))]
    measurements: LockMeasurements,
    #[cfg(test)]
    pause: std::sync::Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    >,
    wal: PathBuf,
    /// The last commit known flushed.
    durable: AtomicU64,
    #[cfg(test)]
    path: PathBuf,
    #[cfg(test)]
    flushes: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    failures: std::sync::atomic::AtomicUsize,
    /// Copies the file at every flush, to simulate losing later commits.
    #[cfg(test)]
    copy: std::sync::Mutex<Option<PathBuf>>,
}
impl Flusher {
    async fn run(self: Arc<Self>, commit: u64) -> Result<(), Error> {
        if self.durable() >= commit {
            #[cfg(feature = "qualification")]
            self.measurements.flush(std::time::Duration::ZERO);
            return Ok(());
        }
        #[cfg(feature = "qualification")]
        let started = std::time::Instant::now();
        #[cfg(feature = "qualification")]
        let measurements = self.measurements.clone();
        let result = tokio::task::spawn_blocking(move || self.flush(commit))
            .await
            .map_err(|_| Error::Closed)?;
        #[cfg(feature = "qualification")]
        measurements.flush(started.elapsed());
        result
    }

    pub(super) fn durable(&self) -> u64 {
        self.durable.load(Ordering::Acquire)
    }
    /// Makes every commit up to `commit` durable with one full flush of the
    /// WAL; a no-op when the watermark already covers it. Commits run at
    /// `synchronous=NORMAL`, so this is the only flush they get. `commit`
    /// must have been read under the replica lock: whatever it counts is
    /// then in the WAL before the flush starts.
    pub(super) fn flush(&self, commit: u64) -> Result<(), Error> {
        if self.durable() >= commit {
            return Ok(());
        }
        #[cfg(test)]
        if self
            .failures
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(Error::Io(std::io::Error::other(
                "injected device flush failure",
            )));
        }
        #[cfg(test)]
        if let Some((entered, resume)) = self.pause.lock().unwrap().take() {
            let _ = entered.send(());
            let _ = resume.recv();
        }
        // `sync_all` is `F_FULLFSYNC` on Apple platforms, like `fullfsync=1`.
        // Windows requires write access for FlushFileBuffers.
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.wal)
        {
            Ok(wal) => wal.sync_all().map_err(Error::Io)?,
            // Without a WAL every commit is in the database file, which
            // checkpoints flush.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::Io(error)),
        }
        self.durable.fetch_max(commit, Ordering::AcqRel);
        #[cfg(test)]
        {
            self.flushes.fetch_add(1, Ordering::Relaxed);
            let directory = self
                .copy
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(directory) = directory {
                for (from, name) in [(&self.path, "copy.db"), (&self.wal, "copy.db-wal")] {
                    let to = directory.join(name);
                    match std::fs::copy(from, &to) {
                        Ok(_) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            let _ = std::fs::remove_file(&to);
                        }
                        Err(error) => return Err(Error::Io(error)),
                    }
                }
            }
        }
        Ok(())
    }
}
/// Releases the writer while forcing durability. Rechecking the commit after
/// reacquiring prevents a serving call from including a newer unflushed write.
async fn flush_guard<'a, A: RowApplication>(
    mut inner: Guard<tokio::sync::MutexGuard<'a, Inner<A>>>,
    owner: &'a ReplicaLock<Inner<A>>,
) -> Result<Guard<tokio::sync::MutexGuard<'a, Inner<A>>>, Error> {
    let authority = inner.authority;
    loop {
        let (flusher, commit) = (inner.flusher.clone(), inner.commit);
        if flusher.durable() >= commit {
            let context = inner.quarantine_context();
            inner.recovery_events.send_if_modified(|current| {
                let changed = *current != context;
                *current = context;
                changed
            });
            return Ok(inner);
        }
        drop(inner);
        flusher.run(commit).await?;
        inner = owner.lock(Class::Background).await;
        if inner.authority != authority {
            return Err(Error::Conflict);
        }
    }
}
/// A local commit that power loss may still remove. It is durable once
/// `EncryptedReplica::durable_commit` reaches `commit`; `flush` forces that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Buffered<T> {
    pub value: T,
    pub commit: u64,
}
/// Resolved grants, shared by the callers within one authority and second.
pub(super) type Grants = Arc<Vec<rocky_core::ResourceGrant>>;
/// Grants with the authority, partition count and second they hold for.
type LocalGrants = ((u64, usize, u64), Grants);
pub(super) type Selectors = Arc<Vec<rocky_credentials::PartitionGrant>>;
type LocalSelectors = ((u64, u64), Selectors);

/// Encrypted protocol files use an explicit API; trusted files cannot be opened here.
pub struct EncryptedReplica<A> {
    pub(super) inner: Arc<ReplicaLock<Inner<A>>>,
    queue: Arc<group::Queue>,
    revisions: watch::Receiver<u64>,
    /// The coordinated log whose terminal entries this trusted node ends
    /// and acknowledges.
    domain_log: Arc<std::sync::RwLock<Option<Arc<dyn rocky_core::DomainLog>>>>,
}
impl<A> Clone for EncryptedReplica<A> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            queue: self.queue.clone(),
            revisions: self.revisions.clone(),
            domain_log: self.domain_log.clone(),
        }
    }
}
impl<A> EncryptedReplica<A> {
    #[cfg(any(test, feature = "qualification"))]
    pub fn lock_measurements(&self) -> LockMeasurements {
        self.inner.measurements()
    }
    /// Makes this replica a trusted node of a coordinated log: it ends
    /// tips' logs with their seals and acknowledges their terminal entries.
    pub fn set_domain_log(&self, log: Option<Arc<dyn rocky_core::DomainLog>>) {
        *self
            .domain_log
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = log;
    }
    pub fn domain_log(&self) -> Option<Arc<dyn rocky_core::DomainLog>> {
        self.domain_log
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}
fn protocol_schema() -> impl Iterator<Item = String> {
    [
        schemas::SCHEMA,
        staging::SCHEMA,
        tips::SCHEMA,
        tip_drop::SCHEMA,
        migrate::SCHEMA,
        backup::SCHEMA,
        rebuild::SCHEMA,
        removal::SCHEMA,
        held::SCHEMA,
        placements::SCHEMA,
        history::SCHEMA,
        coordinated::statements::SCHEMA,
        coordinated::relay::SCHEMA,
        bundle::SCHEMA,
        replay::SCHEMA,
        replay::BASE_SCHEMA,
        replay::outcomes::SCHEMA,
        typed::SCHEMA,
        identity::SCHEMA,
        moves::SCHEMA,
        records::SCHEMA,
        records::SHAPE_SCHEMA,
        stamp_authors::SCHEMA,
        author_sets::SCHEMA,
        partition::SCHEMA,
        checkpoint::SCHEMA,
        checkpoint::ARCHIVE_SCHEMA,
        checkpoint::PULLED_SCHEMA,
        checkpoint::SERVED_SCHEMA,
        checkpoint::FAILURE_SCHEMA,
        compaction::SCHEMA,
        roles::SCHEMA,
        keys::SCHEMA,
        chains::SCHEMA,
        publication::SCHEMA,
        publication::INTENT_SCHEMA,
        bulk::SCHEMA,
        positions::SCHEMA,
        quarantine::SCHEMA,
    ]
    .into_iter()
    .flat_map(|schema| schema.iter().map(|sql| (*sql).to_owned()))
    .chain(positions::triggers())
}

/// Refuse another persisted format before opening a writer or changing SDK settings.
pub async fn check_replica_format(path: &Path) -> Result<(), Error> {
    rocky_storage::database::check_file_format(path).await?;
    if !std::fs::metadata(path).is_ok_and(|file| file.len() > 0) {
        return Ok(());
    }
    let raw = crate::sqlite::Connection::open_read_only(path)?;
    let conn = ScopedConnection::new(raw, None, SCHEMA);
    let tables = rows(
        &conn,
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    )
    .await?;
    if tables.is_empty() {
        return Ok(());
    }
    if !tables.contains(&vec![SqlValue::Text("secure_metadata".into())]) {
        return Err(Error::Incompatible(
            "unsupported encrypted replica format".into(),
        ));
    }
    let records = rows(&conn, "SELECT identity FROM secure_metadata WHERE id=1").await?;
    let Some([SqlValue::Blob(bytes)]) = records.first().map(Vec::as_slice) else {
        return Err(Error::Incompatible(
            "unsupported encrypted replica format".into(),
        ));
    };
    let (label, _, _): (String, rocky_core::TipId, PublicKey) = decode(bytes)?;
    if label != generation::FILE_IDENTITY {
        return Err(Error::Incompatible(
            "unsupported encrypted replica format".into(),
        ));
    }
    if tables.contains(&vec![SqlValue::Text("secure_typed".into())]) {
        for record in rows(&conn, "SELECT descriptor FROM secure_typed").await? {
            if let [SqlValue::Blob(bytes)] = record.as_slice() {
                rocky_core::LogicalSchema::check_stored_row_identity(bytes)
                    .map_err(|error| Error::Incompatible(error.to_string()))?;
            }
        }
    }
    if tables.contains(&vec![SqlValue::Text("secure_checkpoints".into())]) {
        #[derive(Deserialize)]
        struct Format {
            format: u32,
        }
        #[derive(Deserialize)]
        struct Version {
            statement: Format,
        }
        for record in rows(
            &conn,
            "SELECT signed FROM secure_checkpoints WHERE signed IS NOT NULL",
        )
        .await?
        {
            if let [SqlValue::Blob(bytes)] = record.as_slice() {
                let version: Version = p2panda_core::cbor::decode_cbor(bytes.as_slice())
                    .map_err(|_| denied("invalid checkpoint"))?;
                if version.statement.format != checkpoint::CHECKPOINT_FORMAT {
                    return Err(denied("unsupported checkpoint format"));
                }
            }
        }
    }
    let schema: Vec<_> = SCHEMA
        .iter()
        .map(|sql| (*sql).to_owned())
        .chain(protocol_schema())
        .collect();
    for (table, _) in rocky_storage::scoped_connection::tables(&schema) {
        if !tables.contains(&vec![SqlValue::Text(table.clone())]) {
            return Err(Error::Corrupt(format!(
                "missing secure storage table {table}"
            )));
        }
    }
    positions::check_schema(&conn).await?;
    compaction::check_incremental_schema(&conn).await?;
    // Admission evidence is never an empty journal by absence.
    if rows(&conn, "SELECT 1 FROM secure_admission_context WHERE id=1")
        .await?
        .is_empty()
    {
        return Err(Error::Corrupt(
            "admission evidence context is missing".into(),
        ));
    }
    Ok(())
}

/// Checks a configuration against its verified manifest: the revocations,
/// this node's credentials for that manifest, and keys it may read whole.
pub(super) fn check_config(
    config: &SecureConfig,
    manifest: &rocky_core::ApplicationManifest,
) -> Result<(), Error> {
    config
        .revocations
        .verify(config.publisher, manifest.app)
        .map_err(credential)?;
    let (grants, selectors) = config
        .credentials
        .verify_selectors(
            config.publisher,
            config.node.public_key(),
            &config.revocations,
            now()?,
        )
        .map_err(credential)?;
    let mut seen_scopes = BTreeSet::new();
    let mut seen_keys = BTreeSet::new();
    let mut counts = BTreeMap::<ResourceScope, usize>::new();
    for key in &config.keys {
        let count = counts.entry(key.scope).or_default();
        *count += 1;
        if *count > 256 {
            return Err(denied("key epoch capacity reached"));
        }
        if !key.generation.valid()
            || !seen_scopes.insert((key.scope, key.generation))
            || !seen_keys.insert(key.key)
            || (!grants.iter().any(|grant| {
                grant.scope == key.scope
                    && grant.rows == RowSelection::All
                    && grant.rights.contains(&Right::Read)
            }) && !selectors.iter().any(|grant| {
                grant.domain == key.scope.domain
                    && grant.table == key.scope.table
                    && grant.rows == RowSelection::All
                    && grant.rights.contains(&Right::Read)
            }))
        {
            return Err(denied(
                "encryption key does not have whole-scope read authority",
            ));
        }
    }
    Ok(())
}

impl<A: RowApplication> EncryptedReplica<A> {
    pub async fn open(path: impl AsRef<Path>, app: A, config: SecureConfig) -> Result<Self, Error> {
        Self::open_configured(path, app, config, None).await
    }
    /// Installs an enrollment's authenticated graph and explicit bookmark.
    pub async fn open_following(
        path: impl AsRef<Path>,
        app: A,
        config: SecureConfig,
        graph: rocky_credentials::TipGraph,
        bookmark: Option<String>,
    ) -> Result<Self, Error> {
        Self::open_configured(path, app, config, Some((graph, bookmark))).await
    }
    async fn open_configured(
        path: impl AsRef<Path>,
        app: A,
        mut config: SecureConfig,
        bootstrap: Option<(rocky_credentials::TipGraph, Option<String>)>,
    ) -> Result<Self, Error> {
        let genesis = config
            .manifest
            .verify(config.publisher)
            .map_err(credential)?;
        let manifest = app.manifest();
        if genesis.publisher != manifest.publisher
            || genesis.app != manifest.app
            || genesis.domains != manifest.domains
        {
            return Err(denied("compiled application differs from the domain root"));
        }
        check_config(&config, &manifest)?;
        let (current, history) = keys::split(std::mem::take(&mut config.keys));
        config.keys = current;
        check_replica_format(path.as_ref()).await?;
        let (owner, raw) = DatabaseOwner::open(path.as_ref()).await?;
        let conn = Arc::new(ScopedConnection::new(raw, None, SCHEMA));
        configure(&conn).await?;
        let mut identity = generation::identity(
            rocky_credentials::genesis_tip(manifest.hash()),
            config.node.public_key(),
        )?;
        let mut wal = path.as_ref().as_os_str().to_owned();
        wal.push("-wal");
        let (notifications, _) = watch::channel(0);
        let wal = PathBuf::from(wal);
        let flusher = Arc::new(Flusher {
            #[cfg(test)]
            pause: Default::default(),
            #[cfg(any(test, feature = "qualification"))]
            measurements: LockMeasurements::default(),
            wal: wal.clone(),
            durable: AtomicU64::new(0),
            #[cfg(test)]
            path: path.as_ref().to_path_buf(),
            #[cfg(test)]
            flushes: Default::default(),
            #[cfg(test)]
            failures: Default::default(),
            #[cfg(test)]
            copy: Default::default(),
        });
        let owner = Arc::new(owner);
        let passive = wal::Passive::open(owner.clone())?;
        let readiness = blockers::Readiness::new(&conn)?;
        let metadata = metadata::Metadata::new(&conn)?;
        let mut inner = Inner {
            _owner: owner,
            conn,
            permission_fields: app.permission_fields().into_iter().collect(),
            app: Arc::new(app),
            chain: Chain::new(config.credentials.clone())?,
            chains: Default::default(),
            crypto: Default::default(),
            decoded_checkpoints: Default::default(),
            tip_frontiers: Default::default(),
            readiness,
            metadata,
            held_refresh: Default::default(),
            record_dictionary: Default::default(),
            stamp_authors: Default::default(),
            author_sets: Default::default(),
            #[cfg(test)]
            frontier_headers: Default::default(),
            migration_syntax: Default::default(),
            #[cfg(test)]
            frontier_queries: AtomicU64::new(0),
            #[cfg(test)]
            frontier_decodes: AtomicU64::new(0),
            #[cfg(test)]
            position_oracles: Default::default(),
            #[cfg(test)]
            compare_finalization: true,
            #[cfg(test)]
            finalization_oracle_time: Default::default(),
            #[cfg(test)]
            finalization_time: Default::default(),
            node_author: Some(identity::NodeAuthor::new(&config)?),
            config,
            credential_signer: None,
            partitions: BTreeMap::new(),
            history,
            manifest: manifest.hash(),
            workspace: workspace::Workspace::new(rocky_credentials::genesis_tip(manifest.hash())),
            graphs: BTreeMap::new(),
            catalog: BTreeMap::new(),
            path_fields: Default::default(),
            graph_cache: Default::default(),
            custody_required: Default::default(),
            line_nodes: BTreeMap::new(),
            tables: manifest.entities.iter().map(|item| item.id).collect(),
            fields: manifest.fields.iter().map(|item| item.id).collect(),
            domains: manifest.domains.iter().map(|item| item.domain).collect(),
            definition: manifest,
            revision: 0,
            authority: 1,
            authority_events: watch::channel(1).0,
            recovery_events: watch::channel(0).0,
            rebuilding_tip: false,
            opening_revocations: None,
            tip_base: false,
            publishing: false,
            local: Default::default(),
            local_selectors: Default::default(),
            deferred_maintenance: BTreeSet::new(),
            importing: BTreeSet::new(),
            waits: BTreeMap::new(),
            earlier_epoch: AtomicBool::new(false),
            epochs_scanned: None,
            rows_written: AtomicU64::new(0),
            frames_written: AtomicU64::new(0),
            applied_frames: 0,
            pending_pass: Default::default(),
            follow_pass: Default::default(),
            context_epoch: AtomicU64::new(0),
            direct: BTreeSet::new(),
            notifications,
            frames: watch::channel(()).0,
            imported: watch::channel(0).0,
            wal,
            // A reopened file may hold commits a crashed process never flushed.
            commit: 1,
            flusher: flusher.clone(),
            changes: 0,
            wal_limits: (group::WAL_CHECKPOINT_BYTES, group::WAL_LIMIT_BYTES),
            passive,
            limits: RetentionLimits::default(),
            maintenance_error: None,
            maintenance: Default::default(),
            maintenance_backoff: None,
            verified_at: BTreeMap::new(),
            configured: BTreeSet::new(),
            served: (0, BTreeMap::new()),
            peer_tips: BTreeMap::new(),
            #[cfg(test)]
            checkpoint_export_pause: None,
            #[cfg(test)]
            checkpoint_store_pause: None,
            #[cfg(test)]
            header_scan_pause: None,
            #[cfg(test)]
            held_listing_pause: None,
            #[cfg(test)]
            migration_storage_pause: None,
            #[cfg(test)]
            held_token_pause: None,
            #[cfg(test)]
            stage_fault: None,
            #[cfg(any(test, feature = "qualification"))]
            crash: Default::default(),
            #[cfg(test)]
            #[cfg(test)]
            publication_fault: None,
            #[cfg(test)]
            schema_stage_pause: None,
            #[cfg(test)]
            plan_fault: false,
            #[cfg(test)]
            stage_exit: false,
            #[cfg(test)]
            fail_before_commit: 0,
            #[cfg(test)]
            fail_sql_commit: false,
            #[cfg(test)]
            unchecked_replayed_admission: false,
            #[cfg(test)]
            rebuild_switches: false,
            #[cfg(test)]
            rewound: 0,
            #[cfg(test)]
            retry_before_commit: 0,
            #[cfg(test)]
            group_fault: None,
            #[cfg(test)]
            receive_gate: None,
            #[cfg(test)]
            poisoned: BTreeSet::new(),
            #[cfg(test)]
            group_commits: 0,
            #[cfg(test)]
            checkpoints: 0,
            #[cfg(test)]
            audit_global_passes: 0,
            #[cfg(test)]
            busy_hook: None,
        };
        // Schema, metadata and later additive tables install in one transaction.
        let supplied_revocations = inner.config.revocations.clone();
        transaction!(&mut inner, |inner| {
            let tables = rows(
                &inner.conn,
                "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            )
            .await?;
            if tables.is_empty() {
                for sql in SCHEMA {
                    inner.conn.execute(sql, ()).await?;
                }
                inner
                    .conn
                    .execute(
                        "INSERT INTO secure_metadata VALUES(1,?,?,0)",
                        [
                            identity.clone(),
                            inner.config.revocations.to_bytes().map_err(credential)?,
                        ],
                    )
                    .await?;
            }
            if tables.is_empty() {
                for sql in protocol_schema() {
                    inner.conn.execute(sql, ()).await?;
                }
                inner
                    .conn
                    .execute(
                        "INSERT INTO secure_retained VALUES(1,0,0,0,?)",
                        [checkpoint::Lt::new().to_bytes()],
                    )
                    .await?;
                inner.create_admission_context().await?;
            }
            if tables.is_empty() {
                if inner.manifest != genesis.hash() && bootstrap.is_none() {
                    return Err(denied(
                        "a new replica must install its authenticated genesis first",
                    ));
                }
                inner.store_schema(&inner.definition, &[]).await?;
                inner.store_schema(&genesis, &[]).await?;
                let (grants, selectors) = inner
                    .config
                    .credentials
                    .verify_selectors(
                        inner.config.publisher,
                        inner.config.node.public_key(),
                        &inner.config.revocations,
                        now()?,
                    )
                    .map_err(credential)?;
                let scopes: BTreeSet<_> = grants
                    .iter()
                    .map(|grant| grant.scope.domain)
                    .chain(selectors.iter().map(|grant| grant.domain))
                    .chain(inner.config.keys.iter().map(|key| key.scope.domain))
                    .collect();
                if inner.definition.domains.iter().any(|rule| {
                    !scopes.iter().any(|scope| {
                        scope.app == inner.definition.app && scope.domain == rule.domain
                    })
                }) {
                    return Err(denied(
                        "each installed domain requires an authenticated scope",
                    ));
                }
                for scope in scopes {
                    inner
                        .conn
                        .execute(
                            "INSERT INTO secure_tip_graphs VALUES(?,?)",
                            [encode(&scope)?, genesis.hash().to_vec()],
                        )
                        .await?;
                }
                if let Some((graph, bookmark)) = &bootstrap {
                    if graph.genesis_schema != genesis.hash() {
                        return Err(denied("enrollment genesis mismatch"));
                    }
                    let statements = tips::graph_statements(graph);
                    for statement in &statements {
                        statement.verify(inner.config.publisher, graph, None)?;
                    }
                    let mut graph = graph.clone();
                    graph
                        .exclude_revoked(&inner.config.revocations)
                        .map_err(credential)?;
                    let target = match bookmark {
                        Some(name) => graph
                            .bookmark(name)
                            .map_err(credential)?
                            .ok_or_else(|| denied("enrollment bookmark missing"))?,
                        None => graph.genesis(),
                    };
                    if graph.schema(target).map_err(credential)? != inner.manifest {
                        return Err(denied("enrollment schema mismatch"));
                    }
                    for statement in statements {
                        inner.conn.execute("INSERT OR IGNORE INTO secure_tip_statements(digest,statement) VALUES(?,?)", [statement.id()?.to_vec(), encode(&statement)?]).await?;
                    }
                    if let Some(name) = bookmark {
                        inner.invalidate_context();
                        inner.workspace.tip = target;
                        inner.workspace.followed = Some((graph.scope, name.clone()));
                        inner.store_followed(graph.scope, name, target).await?;
                        identity = generation::identity(target, inner.config.node.public_key())?;
                    }
                }
            } else {
                inner.load_schemas().await?;
                inner.load_tip_graphs().await?;
                if inner.workspace.followed.is_some() {
                    identity =
                        generation::identity(inner.workspace.tip, inner.config.node.public_key())?;
                }
                inner
                    .load_revocations(&supplied_revocations, Some(identity.as_slice()))
                    .await?;
            }
            inner
                .conn
                .execute(
                    "UPDATE secure_metadata SET identity=? WHERE id=1",
                    [identity.clone()],
                )
                .await?;
            inner.bind_node_author(&inner.config.credentials).await?;
            Ok(())
        })?;
        inner.load_schemas().await?;
        inner.load_tip_graphs().await?;
        if !inner.schema_switching().await? {
            inner.finish_plan().await?;
        }
        inner.load_typed().await?;
        inner.load_partitions().await?;
        inner.revision = inner.stored_revision().await?;
        inner.notifications.send_replace(inner.revision);
        let revisions = inner.notifications.subscribe();
        inner.local_grants(now()?)?;
        inner.validate_keys(now()?)?;
        inner.adopt_keys().await?;
        inner.load_direct().await?;
        inner.rebuild_voided().await?;
        inner.verify_open().await?;
        let opening_revocations = inner.opening_revocations.take();
        let replica = Self {
            inner: Arc::new(ReplicaLock::new(
                inner,
                #[cfg(any(test, feature = "qualification"))]
                flusher.measurements.clone(),
            )),
            queue: Arc::default(),
            revisions,
            domain_log: Arc::default(),
        };
        if let Some(revocations) = opening_revocations {
            replica.learn_revocations(&revocations).await?;
        } else {
            replica.settle().await?;
        }
        Ok(replica)
    }
    #[cfg(test)]
    pub(crate) async fn maintenance_queued(&self, scope: ResourceScope) -> bool {
        self.inner
            .lock(Class::Background)
            .await
            .deferred_maintenance
            .contains(&scope)
    }
    #[cfg(test)]
    pub(crate) async fn pause_flush(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let (resume, resumed) = std::sync::mpsc::channel();
        *self
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .flusher
            .pause
            .lock()
            .unwrap() = Some((entered, resumed));
        (waiting, resume)
    }
    /// Wakes after a frame group commits, including keyless custody receipt.
    /// Duplicate incoming frames do not wake it; exports still require a flush.
    pub async fn observe_frames(&self) -> watch::Receiver<()> {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .frames
            .subscribe()
    }
    /// Ends authority-bound network links without polling.
    pub async fn observe_authority(&self) -> watch::Receiver<u64> {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .authority_events
            .subscribe()
    }
    /// Changes when keys, grants, schemas, the tip graph or the followed
    /// tip changed: what local recovery and quarantined frames depend on.
    pub async fn observe_recovery(&self) -> watch::Receiver<i64> {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .recovery_events
            .subscribe()
    }
    pub fn observe_revision(&self) -> watch::Receiver<u64> {
        self.revisions.clone()
    }
    /// Changes after every stored checkpoint page, so import progress can
    /// be shown as it moves.
    pub async fn observe_imports(&self) -> watch::Receiver<u64> {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .imported
            .subscribe()
    }
    /// Concurrent calls share one transaction and one flush; each request
    /// keeps its own savepoint, admission checks and result. The frame may be
    /// sent anywhere, so it is returned only after it is flushed.
    pub async fn author(
        &self,
        handle: Commitment,
        changes: Vec<RowChange>,
        dependencies: Vec<Hash>,
    ) -> Result<EncryptedFrame, Error> {
        match self
            .author_with(handle, changes, dependencies, true)
            .await?
        {
            (group::Done::Author(frame), _) => Ok(frame),
            // The handle did commit once; its frame is no longer retained.
            (group::Done::Pruned(_), _) => Err(denied(
                "mutation handle was committed before the pruned prefix",
            )),
            _ => Err(denied("missing authoring result")),
        }
    }
    /// Authors without waiting for a flush. Only the operation id is returned:
    /// the frame leaves the device through `author` with the same handle or
    /// a transfer page, both of which flush first.
    pub async fn author_buffered(
        &self,
        handle: Commitment,
        changes: Vec<RowChange>,
        dependencies: Vec<Hash>,
    ) -> Result<Buffered<Hash>, Error> {
        match self
            .author_with(handle, changes, dependencies, false)
            .await?
        {
            (group::Done::Author(frame), commit) => Ok(Buffered {
                value: frame.id()?,
                commit,
            }),
            (group::Done::Pruned(value), commit) => Ok(Buffered { value, commit }),
            _ => Err(denied("missing authoring result")),
        }
    }
    async fn author_with(
        &self,
        handle: Commitment,
        changes: Vec<RowChange>,
        dependencies: Vec<Hash>,
        exposed: bool,
    ) -> Result<(group::Done, u64), Error> {
        let encoded = encode(&(&changes, &dependencies))?;
        let input = rocky_core::commitment("rocky.secure-mutation.v1", &encoded);
        let work = group::Work::Author {
            handle,
            input,
            changes,
            dependencies,
        };
        self.submit(vec![(work, encoded.len())], exposed)
            .await
            .pop()
            .unwrap_or_else(|| Err(denied("missing authoring result")))
    }
    /// The status may be acknowledged to the sender, so it is returned only
    /// after the receipt is flushed.
    pub async fn receive(&self, frame: EncryptedFrame) -> Result<ReceiveStatus, Error> {
        self.receive_all(vec![frame])
            .await
            .pop()
            .unwrap_or_else(|| Err(denied("missing receive result")))
    }
    /// Receives frames that arrived together, such as one transfer page, in
    /// shared transactions and one flush. Results are in input order; each
    /// frame is admitted or refused on its own.
    pub async fn receive_all(
        &self,
        frames: Vec<EncryptedFrame>,
    ) -> Vec<Result<ReceiveStatus, Error>> {
        self.receive_with(frames, true, false)
            .await
            .into_iter()
            .map(|result| result.map(|status| status.value))
            .collect()
    }
    /// Like `receive_all` without the flush. Do not acknowledge these frames
    /// to their sender before `flush` or `durable_commit` covers `commit`.
    pub async fn receive_buffered(
        &self,
        frames: Vec<EncryptedFrame>,
    ) -> Vec<Result<Buffered<ReceiveStatus>, Error>> {
        self.receive_with(frames, false, false).await
    }
    pub(super) async fn receive_with(
        &self,
        frames: Vec<EncryptedFrame>,
        exposed: bool,
        proofs: bool,
    ) -> Vec<Result<Buffered<ReceiveStatus>, Error>> {
        let count = frames.len();
        let frames = match self.preopen(frames).await {
            Ok(frames) => frames,
            Err(error) => return (0..count).map(|_| Err(group::shared(&error))).collect(),
        };
        let mut work = Vec::new();
        let mut positions = Vec::new();
        let mut results: Vec<Option<Result<Buffered<ReceiveStatus>, Error>>> =
            (0..frames.len()).map(|_| None).collect();
        for (index, frame) in frames.into_iter().enumerate() {
            if let Some(membership) = &frame.migration {
                if !proofs {
                    results[index] = Some(Err(denied("proof-bearing receive required")));
                    continue;
                }
                if let Some(signed) = &membership.descriptor {
                    if signed.statement.publication != membership.publication {
                        results[index] = Some(Err(denied("migration descriptor identity")));
                        continue;
                    }
                    if let Err(error) = self.admit_migration_publication((**signed).clone()).await {
                        results[index] = Some(Err(error));
                        continue;
                    }
                }
            }
            let verified = {
                let inner = self.inner.lock(crate::replica::Class::Background).await;
                match now() {
                    Ok(time) => inner.check_migration_frame(&frame, time).await.map(|_| ()),
                    Err(error) => Err(error),
                }
            };
            if let Err(error) = verified {
                results[index] = Some(Err(error));
                continue;
            }
            // Covered history of a scope proven empty at a seal is a conflict;
            // an early exit, `receive_step` decides under the storing lock.
            let contradicted = match frame.operation_ref() {
                Ok(operation) => {
                    self.inner
                        .lock(crate::replica::Class::Background)
                        .await
                        .refuse_no_frames_contradiction(&operation.header)
                        .await
                }
                Err(error) => Err(error),
            };
            if let Err(error) = contradicted {
                results[index] = Some(Err(error));
                continue;
            }
            if let Err(error) = self.discover_partition(&frame).await {
                results[index] = Some(Err(error));
                continue;
            }
            let weight = frame.weight();
            positions.push(index);
            work.push((group::Work::Receive(frame), weight));
        }
        #[cfg(test)]
        {
            let gate = self
                .inner
                .lock(crate::replica::Class::Background)
                .await
                .receive_gate
                .take();
            if let Some((reached, resume)) = gate {
                let _ = reached.send(());
                let _ = resume.await;
            }
        }
        for (index, result) in positions.into_iter().zip(self.submit(work, exposed).await) {
            results[index] = Some(match result {
                Ok((group::Done::Receive(value), commit)) => Ok(Buffered { value, commit }),
                Ok(_) => Err(denied("missing receive result")),
                Err(error) => Err(error),
            });
        }
        results
            .into_iter()
            .map(|result| result.unwrap_or_else(|| Err(denied("missing receive result"))))
            .collect()
    }
    /// Flushes every commit so far with one device flush; returns the
    /// durable watermark. The flush runs on a blocking thread without the
    /// replica, so statements and reads proceed meanwhile.
    pub async fn flush(&self) -> Result<u64, Error> {
        let (flusher, commit) = {
            let inner = self.inner.lock(crate::replica::Class::Background).await;
            (inner.flusher.clone(), inner.commit)
        };
        if flusher.durable() < commit {
            let flushing = flusher.clone();
            tokio::task::spawn_blocking(move || flushing.flush(commit))
                .await
                .map_err(|_| Error::Closed)??;
        }
        Ok(flusher.durable())
    }
    /// Before the last handle closes the file: refreshes the planner's
    /// statistics where SQLite finds them stale. Best effort.
    pub async fn optimize(&self) {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        let _ = inner.conn.execute("PRAGMA optimize", ()).await;
        let passive = inner.passive.clone();
        drop(inner);
        passive.wait().await;
    }
    /// Runs maintenance queued by SQL commits: one bounded checkpoint or
    /// pruning step for their scopes, and a WAL checkpoint when due. Returns
    /// false, leaving work queued, if a newer commit still needs flushing.
    pub async fn maintain(&self) -> bool {
        loop {
            let mut inner = self.inner.lock(Class::Background).await;
            // Our own cleanup commits may continue. Another writer must first
            // become durable before maintenance can use its current state.
            if inner.flusher.durable() < inner.commit && inner.maintenance.commit != inner.commit {
                return false;
            }
            let Some(scope) = inner.deferred_maintenance.first().copied() else {
                inner.checkpoint_if_due().await;
                return true;
            };
            if !inner.maintain(scope).await {
                inner.deferred_maintenance.remove(&scope);
            }
            drop(inner);
            tokio::task::yield_now().await;
        }
    }
    pub(crate) async fn maintain_scopes(&self, mut scopes: BTreeSet<ResourceScope>) {
        while let Some(scope) = scopes.pop_first() {
            loop {
                let mut inner = self.inner.lock(Class::Background).await;
                let more = inner.maintain(scope).await;
                drop(inner);
                if !more {
                    break;
                }
                tokio::task::yield_now().await;
            }
        }
    }
    /// Names the scopes the owner is about to import from a checkpoint,
    /// replacing the previous set. A scope with a staged import counts too.
    pub async fn set_importing(&self, scopes: BTreeSet<ResourceScope>) {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .importing = scopes;
    }
    /// The last commit known to survive power loss.
    pub async fn durable_commit(&self) -> u64 {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .flusher
            .durable()
    }
    pub async fn install_key(&self, key: KeyMaterial) -> Result<(), Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        if inner
            .config
            .keys
            .iter()
            .any(|existing| existing.scope == key.scope)
        {
            return Err(denied(
                "key already installed; rotate with install_key_epoch",
            ));
        }
        let retained = collect_rows(
            inner
                .conn
                .query(
                    "SELECT generation,key_hash FROM secure_keys WHERE scope=?",
                    [encode(&key.scope)?],
                )
                .await?,
        )
        .await?;
        if let Some(record) = retained.first()
            && record
                != &vec![
                    SqlValue::Blob(encode(&key.generation)?),
                    SqlValue::Blob(rocky_core::commitment("rocky.scope-key.v1", &key.key).to_vec()),
                ]
        {
            return Err(denied("key differs from retained crypto state"));
        }
        inner.config.keys.push(key);
        if let Err(error) = inner.validate_keys(now()?) {
            inner.config.keys.pop();
            return Err(error);
        }
        drop(inner);
        self.settle().await
    }
    pub async fn evict_key(&self, scope: ResourceScope) {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        inner.config.keys.retain(|key| key.scope != scope);
        inner.history.retain(|key| key.scope != scope);
        inner.bump_authority();
    }
    /// Whether a mutation handle committed, whatever its writes were. A
    /// caller that lost a commit's answer checks this before planning the
    /// writes again. Handles are retained as `RetentionLimits` describes.
    pub async fn handle_committed(&self, handle: Commitment) -> Result<bool, Error> {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        let mut result = inner
            .conn
            .query(
                "SELECT 1 FROM secure_handles WHERE handle=?",
                [handle.to_vec()],
            )
            .await?;
        Ok(result.next().await?.is_some())
    }
    /// Flushes first: the status may be acknowledged to the sender.
    pub async fn receipt_status(&self, id: Hash) -> Result<ReceiveStatus, Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        inner = flush_guard(inner, &self.inner).await?;
        inner.status(id).await
    }
    /// Merges `revocations` into the set this replica holds: the union of
    /// the statements that verify, never a refusal for order or overlap. A
    /// statement that fails verification refuses the whole set and changes
    /// nothing. Returns the statements it added.
    pub async fn learn_revocations(
        &self,
        revocations: &RevocationSet,
    ) -> Result<Vec<SignedRevocation>, Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        let mut merged = inner.config.revocations.clone();
        let added = merged
            .merge(
                revocations,
                inner.config.publisher,
                inner.definition.app,
                now()?,
            )
            .map_err(credential)?;
        if merged == inner.config.revocations {
            return Ok(added);
        }
        let bytes = merged.to_bytes().map_err(credential)?;
        // Seals and moves of a revoked signer leave resolution with the
        // set, and the followed bookmark moves in the same commit.
        let old_graphs = inner.graphs.clone();
        let old_tip = inner.workspace.tip;
        let old_author = inner.node_author.clone();
        let old_nodes = inner.line_nodes.clone();
        let old_followed = inner.workspace.followed.clone();
        let old_revocations = inner.config.revocations.clone();
        let result = transaction!(inner, |inner| {
            inner.invalidate_context();
            // Checks inside the commit, such as installing a pulled state,
            // see the merged set.
            inner.config.revocations = merged.clone();
            inner.graphs = old_graphs.clone();
            inner.workspace.tip = old_tip;
            inner.node_author = old_author.clone();
            inner.line_nodes = old_nodes.clone();
            inner.workspace.followed = old_followed.clone();
            inner
                .conn
                .execute(
                    "UPDATE secure_metadata SET revocations=?,revision=revision+1 WHERE id=1",
                    [bytes.clone()],
                )
                .await?;
            inner.resolve_revoked(&merged).await?;
            Ok(())
        });
        if let Err(error) = result {
            inner.invalidate_context();
            inner.graphs = old_graphs;
            inner.workspace.tip = old_tip;
            inner.node_author = old_author;
            inner.line_nodes = old_nodes;
            inner.workspace.followed = old_followed;
            inner.config.revocations = old_revocations;
            return Err(error);
        }
        inner.invalidate_context();
        inner.config.revocations = merged;
        inner.bump_authority();
        inner.publish_revision().await?;
        drop(inner);
        self.settle().await?;
        Ok(added)
    }
    /// Merges the statements a session peer sent, except one that revokes
    /// `own`, this device's chain: a replica never holds the statement that
    /// revokes itself, which its owner records instead. Returns that
    /// statement, verified, if one came.
    pub(crate) async fn learn_session_revocations(
        &self,
        statements: Vec<SignedRevocation>,
        own: &CredentialChain,
    ) -> Result<Option<SignedRevocation>, Error> {
        let (publisher, app) = {
            let inner = self.inner.lock(crate::replica::Class::Background).await;
            (inner.config.publisher, inner.definition.app)
        };
        let mut revoking = None;
        let mut others = Vec::new();
        for signed in statements {
            signed.verify(publisher, app).map_err(credential)?;
            let single = RevocationSet::try_from(vec![signed.clone()]).map_err(credential)?;
            if single.revoking_holder(own).map_err(credential)?.is_some() {
                revoking.get_or_insert(signed);
            } else {
                others.push(signed);
            }
        }
        if !others.is_empty() {
            let set = RevocationSet::try_from(others).map_err(credential)?;
            self.learn_revocations(&set).await?;
        }
        Ok(revoking)
    }
    /// The revocations this replica holds.
    pub async fn revocations(&self) -> RevocationSet {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .config
            .revocations
            .clone()
    }
    /// The digest of the live revocations, which a session hello carries.
    pub async fn revocation_digest(&self) -> Result<Commitment, Error> {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .revocation_digest()
    }
    #[cfg(test)]
    pub(crate) async fn inject_failure(&self, retries: usize, failures: usize) {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        inner.retry_before_commit = retries;
        inner.fail_before_commit = failures;
    }
    #[cfg(test)]
    pub(crate) async fn retry_open_revocations_for_test(
        &self,
        supplied: RevocationSet,
    ) -> Result<RevocationSet, Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        inner.config.revocations = supplied.clone();
        transaction!(inner, |inner| {
            inner.load_revocations(&supplied, None).await?;
            inner.injected_commit_fault()?;
            Ok(())
        })?;
        Ok(inner
            .opening_revocations
            .take()
            .unwrap_or_else(|| inner.config.revocations.clone()))
    }
    #[cfg(test)]
    pub(crate) async fn inject_group_fault(&self, fault: Option<group::GroupFault>) {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .group_fault = fault;
    }
    /// Pauses the next receive after its early checks; returns a signal that
    /// it reached the pause and the sender that resumes it.
    #[cfg(test)]
    pub(crate) async fn gate_next_receive(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (reached, at_gate) = tokio::sync::oneshot::channel();
        let (resume, resumed) = tokio::sync::oneshot::channel();
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .receive_gate = Some((reached, resumed));
        (at_gate, resume)
    }
    #[cfg(test)]
    pub(crate) async fn group_commits(&self) -> usize {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .group_commits
    }
    #[cfg(test)]
    pub(crate) async fn checkpoints(&self) -> usize {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .checkpoints
    }
    #[cfg(test)]
    pub(crate) async fn set_wal_limits(&self, checkpoint: u64, limit: u64) {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .wal_limits = (checkpoint, limit);
    }
    #[cfg(test)]
    pub(crate) async fn set_busy_hook(&self, hook: Option<Box<dyn FnMut(usize) + Send + Sync>>) {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .busy_hook = hook;
    }
    #[cfg(test)]
    pub(crate) async fn watermark(&self) -> (u64, u64, usize) {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        (
            inner.commit,
            inner.flusher.durable(),
            inner.flusher.flushes.load(Ordering::Relaxed),
        )
    }
    #[cfg(test)]
    pub(crate) async fn copy_at_flush(&self, directory: Option<PathBuf>) {
        *self
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .flusher
            .copy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = directory;
    }
    #[cfg(test)]
    pub(crate) async fn stored_and_memory_revision(&self) -> (u64, u64) {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        (inner.stored_revision().await.unwrap(), inner.revision)
    }
    #[cfg(test)]
    pub(crate) async fn install_pulled_for_test(
        &self,
        scope: ResourceScope,
    ) -> Result<bool, Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        let id = inner
            .find_scope_id(scope)
            .await?
            .ok_or_else(|| denied("unknown scope"))?;
        transaction!(inner, |inner| {
            Ok(inner.install_pulled(scope, id).await?
                == checkpoint::pulled::PulledInstall::Installed)
        })
    }
    #[cfg(test)]
    pub(crate) async fn set_catalog_entry_for_test(
        &self,
        manifest: Commitment,
        definition: Option<rocky_core::ApplicationManifest>,
    ) -> Option<rocky_core::ApplicationManifest> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        inner.invalidate_context();
        match definition {
            Some(definition) => inner.catalog.insert(manifest, definition),
            None => inner.catalog.remove(&manifest),
        }
    }
}
impl<A: RowApplication> Inner<A> {
    /// The digest of the live revocations this replica holds.
    pub(crate) fn revocation_digest(&self) -> Result<Commitment, Error> {
        self.config.revocations.digest(now()?).map_err(credential)
    }
    pub(super) fn local_grants(&self, time: u64) -> Result<Grants, Error> {
        let key = (self.authority, self.partitions.len(), time);
        let mut local = self
            .local
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((resolved, grants)) = local.as_ref()
            && *resolved == key
        {
            return Ok(grants.clone());
        }
        let grants = Arc::new(self.resolve_chain(
            &self.config.credentials,
            self.config.node.public_key(),
            &self.config.revocations,
            time,
        )?);
        *local = Some((key, grants.clone()));
        Ok(grants)
    }
    /// This device's partition selectors under its current credentials,
    /// verified once per authority and second like `local_grants`.
    pub(super) fn local_selectors(&self, time: u64) -> Result<Selectors, Error> {
        let key = (self.authority, time);
        let mut local = self
            .local_selectors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((resolved, selectors)) = local.as_ref()
            && *resolved == key
        {
            return Ok(selectors.clone());
        }
        let (_, selectors) = self
            .config
            .credentials
            .verify_selectors(
                self.config.publisher,
                self.config.node.public_key(),
                &self.config.revocations,
                time,
            )
            .map_err(credential)?;
        let selectors = Arc::new(selectors);
        *local = Some((key, selectors.clone()));
        Ok(selectors)
    }
    pub(super) fn can_read_key(
        &self,
        scope: ResourceScope,
        grants: &[rocky_core::ResourceGrant],
    ) -> bool {
        grants.iter().any(|grant| {
            grant.scope == scope
                && grant.rows == RowSelection::All
                && grant.rights.contains(&Right::Read)
        })
    }
    fn validate_keys(&self, time: u64) -> Result<(), Error> {
        // `can_read_key` for every key at once.
        let readable: BTreeSet<_> = self
            .local_grants(time)?
            .iter()
            .filter(|grant| grant.rows == RowSelection::All && grant.rights.contains(&Right::Read))
            .map(|grant| grant.scope)
            .collect();
        let mut scopes = BTreeSet::new();
        let mut epochs = BTreeSet::new();
        let mut secrets = BTreeSet::new();
        let mut counts = BTreeMap::<ResourceScope, usize>::new();
        for key in self.opening_keys() {
            let current = self
                .config
                .keys
                .iter()
                .find(|current| current.scope == key.scope)
                .map(|current| current.generation);
            let count = counts.entry(key.scope).or_default();
            *count += 1;
            if *count > 256 {
                return Err(denied("key epoch capacity reached"));
            }
            if !key.generation.valid()
                || !epochs.insert((key.scope, key.generation))
                || (current == Some(key.generation) && !scopes.insert(key.scope))
                || current.is_none_or(|current| current < key.generation)
                || !secrets.insert(key.key)
                || !readable.contains(&key.scope)
            {
                return Err(denied(
                    "key requires read permission for every row in its encryption scope",
                ));
            }
        }
        Ok(())
    }
    pub(super) fn verify_frame(
        &self,
        frame: &EncryptedFrame,
        time: u64,
    ) -> Result<Vec<rocky_core::ResourceGrant>, Error> {
        let reach = self.frame_reach(frame)?;
        if matches!(reach, tips::FrameReach::Unfollowed) {
            return Err(denied(
                "frame belongs to a tip this replica does not follow",
            ));
        }
        self.verify_frame_authority(frame, time)
    }
    pub(super) fn verify_frame_authority(
        &self,
        frame: &EncryptedFrame,
        time: u64,
    ) -> Result<Vec<rocky_core::ResourceGrant>, Error> {
        let operation = frame.operation_ref()?;
        let frame_manifest = self.manifest_of_tip(operation.header.extensions.tip)?;
        if !self.catalog.contains_key(&frame_manifest)
            && self.frame_reach(frame)? == tips::FrameReach::Held
        {
            return Err(denied("held source schema is not installed"));
        }
        // Only bytes are shared by digest: the chain is verified here, for
        // every frame, against the current revocations.
        self.verify_header_authority(&operation.header, frame.chain()?.credentials(), time)
    }
    /// The write authority a frame was admitted with: its chain at its own
    /// time, unaffected by later revocations and expiry.
    pub(super) fn historical_frame_authority(
        &self,
        frame: &EncryptedFrame,
    ) -> Result<Vec<rocky_core::ResourceGrant>, Error> {
        let header = &frame.operation_ref()?.header;
        self.header_authority(
            header,
            frame.chain()?.credentials(),
            &RevocationSet::new(),
            header.timestamp / 1_000_000,
        )
    }
    /// A signed row header's write authority under `credentials`, the chain
    /// its digest names, against the current revocations.
    pub(super) fn verify_header_authority(
        &self,
        header: &p2panda_core::Header<Extensions>,
        credentials: &CredentialChain,
        time: u64,
    ) -> Result<Vec<rocky_core::ResourceGrant>, Error> {
        self.header_authority(header, credentials, &self.config.revocations, time)
    }
    fn header_authority(
        &self,
        header: &p2panda_core::Header<Extensions>,
        credentials: &CredentialChain,
        revocations: &RevocationSet,
        time: u64,
    ) -> Result<Vec<rocky_core::ResourceGrant>, Error> {
        let extension = &header.extensions;
        let manifest = &self.definition;
        let source = self.catalog.get(&self.manifest_of_tip(extension.tip)?);
        if extension.scope.domain.app != manifest.app
            || !self.domains.contains(&extension.scope.domain.domain)
            || source.is_some_and(|definition| {
                !definition
                    .entities
                    .iter()
                    .any(|table| table.id == extension.scope.table)
            })
        {
            return Err(denied("wrong app/domain/table/manifest"));
        }
        self.check_authenticated_partition(extension.scope, extension.partition.as_ref())?;
        let number = extension
            .author
            .ok_or_else(|| denied("node author number missing"))?;
        let verified = self.verified_chain(credentials, revocations, time)?;
        let grants = match &extension.partition {
            Some(tuple) => {
                verified.partition_author(header.public_key, number, extension.scope, tuple, time)
            }
            None => verified.author(header.public_key, number, extension.scope.table, time),
        }
        .map_err(credential)?;
        if !grants.iter().any(|grant| {
            grant.scope == extension.scope
                && grant
                    .rights
                    .iter()
                    .any(|right| [Right::Update, Right::Insert, Right::Delete].contains(right))
        }) {
            return Err(denied("no write authority for encrypted operation"));
        }
        Ok(grants)
    }
    async fn row(
        &self,
        scope: ResourceScope,
        row: Commitment,
    ) -> Result<Option<Materialized>, Error> {
        let mut result = self
            .conn
            .query(
                "SELECT fields FROM secure_row_records WHERE scope=? AND row=?",
                [encode(&scope)?, row.to_vec()],
            )
            .await?;
        match result.next().await? {
            Some(row) => {
                let bytes = row.get::<Vec<u8>>(0)?;
                Ok(Some(self.decode_record(&bytes).await?))
            }
            None => Ok(None),
        }
    }
    async fn frame(&self, id: Hash) -> Result<Option<EncryptedFrame>, Error> {
        let store = TransactionStore(self.conn.clone());
        match store.get_raw_operation(id).await? {
            Some((header, body)) => Ok(Some(
                self.stored_frame(header, body.unwrap_or_default()).await?,
            )),
            None => Ok(None),
        }
    }
    async fn status(&self, id: Hash) -> Result<ReceiveStatus, Error> {
        let mut result = self
            .conn
            .query(
                "SELECT status,header FROM secure_operations WHERE hash=?",
                [id.as_bytes().to_vec()],
            )
            .await?;
        let Some(row) = result.next().await? else {
            // A pruned operation is known as applied while its stub exists.
            return match self.stub(id).await? {
                Some(_) => Ok(ReceiveStatus::Applied),
                None => Err(denied("missing stored operation")),
            };
        };
        match row.get::<String>(0)?.as_str() {
            "applied" => Ok(ReceiveStatus::Applied),
            "held" => Ok(ReceiveStatus::Held),
            "rejected" => Ok(ReceiveStatus::Rejected),
            "pending" => {
                let header: p2panda_core::Header<Extensions> = decode(&row.get::<Vec<u8>>(1)?)?;
                if self
                    .opening_key(header.extensions.scope, header.extensions.generation)
                    .is_some()
                {
                    Ok(ReceiveStatus::PendingDependencies)
                } else if self.can_read_key(header.extensions.scope, &self.local_grants(now()?)?) {
                    Ok(ReceiveStatus::MissingKey)
                } else {
                    Ok(ReceiveStatus::Custody)
                }
            }
            _ => Err(denied("invalid stored status")),
        }
    }
    async fn lookup_handle(
        &self,
        handle: Commitment,
        input: Commitment,
    ) -> Result<Option<Result<EncryptedFrame, Hash>>, Error> {
        let mut result = self
            .conn
            .query(
                "SELECT input,hash FROM secure_handles WHERE handle=?",
                [handle.to_vec()],
            )
            .await?;
        let Some(row) = result.next().await? else {
            return Ok(None);
        };
        let stored = row.get::<Vec<u8>>(0)?;
        let hash = Hash::try_from(row.get::<Vec<u8>>(1)?.as_slice())
            .map_err(|_| denied("invalid handle hash"))?;
        drop(result);
        if stored != input {
            return Err(Error::Conflict);
        }
        // A handle outlives its pruned operation inside `RetentionLimits::handles`.
        Ok(Some(self.frame(hash).await?.ok_or(hash)))
    }
    /// Backpressure once retained history reaches the hard bound; automatic
    /// checkpointing and pruning start at the soft bound and make room.
    async fn check_budget(&self, incoming: usize) -> Result<(), Error> {
        if self.publishing {
            return Ok(());
        }
        let (_, bytes) = self.retained().await?;
        let bytes = bytes
            .checked_sub(self.migration_bytes().await?)
            .ok_or_else(|| Error::Corrupt("migration accounting exceeds history".into()))?;
        if bytes
            .checked_add(incoming as u64)
            .is_none_or(|total| total > self.limits.hard_bytes as u64)
        {
            return Err(Error::Backpressure);
        }
        Ok(())
    }
    /// Counts a committed write transaction for the durable watermark. An
    /// unreadable counter is treated as a change.
    pub(super) async fn note_commit(&mut self) {
        match rows(&self.conn, "SELECT total_changes()").await.as_deref() {
            Ok([row]) if row.as_slice() == [SqlValue::Integer(self.changes)] => {}
            Ok([row]) => {
                if let [SqlValue::Integer(total)] = row.as_slice() {
                    self.changes = *total;
                }
                self.commit += 1;
            }
            _ => self.commit += 1,
        }
        self.readiness.invalidate();
        self.refresh_readers().await;
    }
    #[cfg(test)]
    pub(crate) fn flush(&mut self) -> Result<(), Error> {
        self.flusher.flush(self.commit)
    }
    /// Adopts the committed revision; observers are woken only by a change.
    pub(super) async fn publish_revision(&mut self) -> Result<(), Error> {
        let revision = self.stored_revision().await?;
        self.revision = revision;
        self.notifications.send_if_modified(|current| {
            let changed = *current != revision;
            *current = revision;
            changed
        });
        self.announce();
        Ok(())
    }
    /// The replica's file.
    pub(super) fn path(&self) -> &Path {
        self._owner.path()
    }
    /// Checks the file identity and defers new exclusions until its stored
    /// state has verified under the retained revocations.
    async fn load_revocations(
        &mut self,
        supplied: &RevocationSet,
        identity: Option<&[u8]>,
    ) -> Result<(), Error> {
        let mut metadata = self
            .conn
            .query(
                "SELECT identity,revocations FROM secure_metadata WHERE id=1",
                (),
            )
            .await?;
        let row = metadata
            .next()
            .await?
            .ok_or_else(|| denied("missing secure metadata"))?;
        if identity.is_some_and(|identity| row.get::<Vec<u8>>(0).ok().as_deref() != Some(identity))
        {
            return Err(denied("secure file identity mismatch"));
        }
        let stored = RevocationSet::from_bytes(&row.get::<Vec<u8>>(1)?).map_err(credential)?;
        let mut merged = supplied.clone();
        merged
            .merge(&stored, self.config.publisher, self.definition.app, now()?)
            .map_err(credential)?;
        self.opening_revocations = (merged != stored).then_some(merged);
        self.invalidate_context();
        // Verify the stored projection and L before applying the new exclusion
        // through the ordinary atomic revocation path.
        self.config.revocations = stored;
        *self
            .local
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        *self
            .local_selectors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        Ok(())
    }
}

/// Commits run at `synchronous=NORMAL`; `Inner::flush` makes them durable
/// before anything leaves the device. Flushes and checkpoints use the full
/// device flush. Verified at open.
async fn configure(conn: &ScopedConnection) -> Result<(), Error> {
    let durability = [
        (
            "PRAGMA journal_mode=wal",
            "PRAGMA journal_mode",
            SqlValue::Text("wal".into()),
        ),
        (
            "PRAGMA synchronous=NORMAL",
            "PRAGMA synchronous",
            SqlValue::Integer(1),
        ),
        (
            "PRAGMA fullfsync=1",
            "PRAGMA fullfsync",
            SqlValue::Integer(1),
        ),
        (
            "PRAGMA checkpoint_fullfsync=1",
            "PRAGMA checkpoint_fullfsync",
            SqlValue::Integer(1),
        ),
    ];
    for (set, read, expected) in durability {
        rows(conn, set).await?;
        if rows(conn, read).await? != vec![vec![expected.clone()]] {
            return Err(Error::Durability(format!("{read} is not {expected:?}")));
        }
    }
    // Typed tables keep real foreign keys; Rocky's own tables declare none.
    rows(conn, "PRAGMA foreign_keys=ON").await?;
    if rows(conn, "PRAGMA foreign_keys").await? != vec![vec![SqlValue::Integer(1)]] {
        return Err(Error::Incompatible("foreign keys are not enforced".into()));
    }
    // Checkpoints run between groups; a busy file is retried by the replica, not by SQLite.
    for (set, read) in [
        ("PRAGMA wal_autocheckpoint=0", "PRAGMA wal_autocheckpoint"),
        ("PRAGMA busy_timeout=0", "PRAGMA busy_timeout"),
    ] {
        rows(conn, set).await?;
        if rows(conn, read).await? != vec![vec![SqlValue::Integer(0)]] {
            return Err(Error::Incompatible(format!("{read} is not 0")));
        }
    }
    for (name, value) in [
        ("cache_size", group::CACHE_KIB / 2),
        ("temp.cache_size", group::CACHE_KIB / 2),
        ("journal_size_limit", group::WAL_CHECKPOINT_BYTES as i64),
    ] {
        rows(conn, &format!("PRAGMA {name}={value}")).await?;
    }
    Ok(())
}
