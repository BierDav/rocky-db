//! Observable native SDK contract. Bindings are generated from these declarations.
pub use rocky_core::{Blocker, BlockerKind, ClearsBy, FrameReplay, WaitReason};
use serde::{Deserialize, Serialize};

mod attempts;
pub(crate) use attempts::{Attempt, Observations, epoch_millis, failure};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentState {
    Detached,
    Attached,
    Draining,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkState {
    Open,
    Opening,
    Closing,
    Closed,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryPathState {
    On,
    Off,
    Unavailable,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationMode {
    NotConfigured,
    Service,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptOperation {
    ResolveContact,
    OpenLink,
    Reconcile,
    CoordinatorRegister,
    CoordinatorControl,
    CoordinatorClose,
    CoordinatorUsage,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptStage {
    ResolveRoute,
    Dial,
    Admission,
    Reconciliation,
    CoordinatorRequest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptOutcome {
    Completed,
    NoResult,
    Cancelled,
    Failed,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Timeout,
    Transport,
    RemoteRefusal,
    LocalAuthorization,
    Protocol,
    Coordination,
    Other,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    NetworkingDisabled,
    Suspended,
    Backoff,
    InboundReconciliation,
    Covered,
    NoPendingWork,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptFailure {
    pub kind: FailureKind,
    pub code: Option<String>,
    pub detail: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptObservation {
    pub id: u64,
    pub target: String,
    pub operation: AttemptOperation,
    pub stage: AttemptStage,
    pub started_at_epoch_millis: Option<u64>,
    pub ended_at_epoch_millis: Option<u64>,
    pub elapsed_millis: Option<u64>,
    pub outcome: Option<AttemptOutcome>,
    pub failure: Option<AttemptFailure>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub transport: String,
    pub address: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationStatus {
    pub digest: String,
    pub statements: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusGrant {
    pub scope: String,
    pub rights: Vec<String>,
    pub columns: Option<Vec<String>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityProfile {
    pub kind: String,
    pub scopes: Vec<String>,
    pub grants: Vec<StatusGrant>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedRevocation {
    pub id: String,
    pub statement: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalRoute {
    pub target: String,
    pub routes: Vec<Route>,
    pub enrollment_routes: Vec<Route>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityStatus {
    pub principal: String,
    pub node: String,
    pub is_issuer: bool,
    pub expires_at_epoch_seconds: u64,
    pub expired: bool,
    pub logged_out: bool,
    pub verified_revocation: Option<VerifiedRevocation>,
    pub revocations: RevocationStatus,
    pub profile: AuthorityProfile,
    pub renewal_routes: Vec<RenewalRoute>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Generation {
    pub schema: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebuildProgress {
    pub schema: String,
    pub tables: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingGeneration {
    pub tip: String,
    pub manifest: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationStatus {
    pub manifest: String,
    pub current: Generation,
    pub pending: Option<PendingGeneration>,
    pub rebuilding: Option<RebuildProgress>,
    pub application: DeclaredSchema,
    /// A migration this device waits for or publishes.
    pub migration: Option<MigrationStatus>,
    /// An ahead member needs an issuer's signed generation, possibly offline.
    pub waiting_for_issuer: bool,
}
/// A schema migration as this device sees it. See
/// `docs/runtime/generations.md#migrations`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum MigrationStatus {
    /// The application's schema has migrations this device may not run:
    /// an issuer that reads and writes every partition must migrate first.
    FullAccessRequired,
    /// Bundles of migrations this device ran, and how many of them, in
    /// order, a peer holds.
    Publishing { bundles: u64, published: u64 },
}
/// How the schema the application declares stands to the installed
/// generation's. An application behind or ahead of its database still
/// opens it; its statements on what differs fail. See
/// `docs/runtime/adopting-generations.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredSchema {
    Current,
    /// Older than the database, which adopted a newer generation.
    Behind,
    /// Newer than the database: no issuer has signed it, or this device
    /// could not reach one yet.
    Ahead,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapProgress {
    pub rows_done: u64,
    pub rows_total: u64,
    pub scopes_done: u64,
    pub scopes_total: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeStatus {
    pub table: Option<String>,
    pub table_id: String,
    pub encryption: String,
    pub partition: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeImportStatus {
    pub scope: ScopeStatus,
    pub checkpoint: Option<String>,
    pub cursor: Option<String>,
    pub pages_complete: Option<bool>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionEpoch {
    pub generation: u64,
    pub secret_hash: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEpochStatus {
    pub collection: String,
    pub epochs: Vec<EncryptionEpoch>,
    pub current: Option<EncryptionEpoch>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataStatus {
    pub revision: u64,
    pub generation: GenerationStatus,
    /// Every reason a scope cannot read, write or import yet.
    pub blockers: Vec<Blocker>,
    /// A summary: the bootstrap intent or a staged import remains.
    pub bootstrap_pending: bool,
    pub bootstrap: Option<BootstrapProgress>,
    pub imports: Vec<ScopeImportStatus>,
    pub key_epochs: Vec<KeyEpochStatus>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryPath {
    pub state: DiscoveryPathState,
    pub reason: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryStatus {
    pub announcing: bool,
    pub local: DiscoveryPath,
    pub topic: DiscoveryPath,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkPath {
    pub selected: bool,
    pub kind: String,
    pub remote: String,
    pub local: Option<String>,
    pub round_trip_micros: u64,
    pub mtu: u32,
    pub window: u64,
    pub sent_bytes: u64,
    pub sent_datagrams: u64,
    pub received_bytes: u64,
    pub received_datagrams: u64,
    pub lost_packets: u64,
    pub lost_bytes: u64,
    pub congestion_events: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerLink {
    pub state: LinkState,
    pub opened_at_epoch_seconds: Option<u64>,
    pub round_trip_millis: Option<u64>,
    pub paths: Vec<LinkPath>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryStatus {
    pub pending: bool,
    pub reconciliation_retry_at_epoch_millis: Option<u64>,
    pub link_retry_at_epoch_millis: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub node: String,
    pub is_issuer: bool,
    pub is_configured: bool,
    pub source: String,
    pub choice: String,
    pub routes: Vec<Route>,
    pub is_local: bool,
    pub link: PeerLink,
    pub attempts: Vec<AttemptObservation>,
    pub last_authenticated_exchange_at_epoch_seconds: Option<u64>,
    pub retry: Option<RetryStatus>,
    /// The last exchange with this peer that was not skipped.
    pub last_sync: Option<PeerReconciliation>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayStatus {
    pub url: String,
    pub connected: bool,
    pub last_error: Option<String>,
    pub auth_denied_reason: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayObservation {
    pub initial_configuration: Option<String>,
    /// None when the attached transport cannot expose relay observations.
    pub relays: Option<Vec<RelayStatus>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkOwnership {
    Rocky,
    Application,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundStatus {
    pub active: u64,
    pub limit: u64,
    pub served: u64,
    pub refused: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub attachment: AttachmentState,
    pub kind: Option<String>,
    pub ownership: Option<NetworkOwnership>,
    pub networking_enabled: bool,
    pub foreground: bool,
    pub worker_enabled: bool,
    pub worker_running: bool,
    pub reconciling: bool,
    pub inbound: Option<InboundStatus>,
    pub peers: Vec<Peer>,
    pub connected_peer_count: u64,
    pub contact_resolutions: Vec<AttemptObservation>,
    pub discovery: DiscoveryStatus,
    pub relay: RelayObservation,
    pub last_reconciliation: Option<ReconciliationReport>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationStatus {
    pub mode: CoordinationMode,
    pub attempts: Vec<AttemptObservation>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseStatus {
    pub token: String,
    pub observed_at_epoch_millis: Option<u64>,
    pub authority: AuthorityStatus,
    pub data: DataStatus,
    pub network: NetworkStatus,
    pub coordination: CoordinationStatus,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeReconciliationTransfer {
    pub scope: ScopeStatus,
    /// Frames received.
    pub pulled: u64,
    /// Frames sent.
    pub pushed: u64,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub checkpoint: Option<String>,
    pub superseded: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerReconciliation {
    pub node: String,
    pub attempts: Vec<AttemptObservation>,
    pub skip: Option<SkipReason>,
    pub transfers: Vec<ScopeReconciliationTransfer>,
    pub refused: Vec<ScopeStatus>,
    pub waiting: Vec<ScopeStatus>,
    /// Always false: peer discovery never upgrades the installed workspace.
    pub upgrade_required: bool,
    pub retry_pending: bool,
    /// How each scope this exchange reached ended.
    pub scopes: Vec<ScopeOutcome>,
    /// Failed attempts of this exchange that timed out, by kind.
    pub timeouts: Vec<TimeoutCount>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeSyncOutcome {
    Synced,
    /// One side's credentials grant no whole-scope access to the other.
    Refused,
    /// The peer restores the scope from a checkpoint.
    PeerImporting,
    /// The exchange failed while this scope was syncing.
    Failed,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeOutcome {
    pub scope: ScopeStatus,
    pub outcome: ScopeSyncOutcome,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutCount {
    pub kind: String,
    pub count: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationReport {
    pub contact_resolutions: Vec<AttemptObservation>,
    pub started_at_epoch_millis: Option<u64>,
    pub ended_at_epoch_millis: Option<u64>,
    pub skip: Option<SkipReason>,
    pub peers: Vec<PeerReconciliation>,
}

/// The native request boundary's stable error, without losing its code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallFailure {
    pub code: String,
    pub retryable: bool,
    pub detail: String,
}
impl std::fmt::Display for CallFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}
impl std::error::Error for CallFailure {}
