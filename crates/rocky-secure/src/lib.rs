//! Signed capabilities, encrypted rows and bounded native ciphertext synchronization.
//! See `docs/runtime/permissions-and-sync.md` for the supported security boundary.
#[macro_use]
mod transaction;
use rocky_storage::{
    capture, cursor, database, observe, scoped_connection, sql, sqlite, statement, storage,
};
pub mod network;
mod replica;
mod store;
mod wire;
#[cfg(feature = "qualification")]
pub use replica::CHUNK_PAGES;
#[cfg(any(test, feature = "qualification"))]
pub use replica::CrashPoint;
pub use replica::{
    AuditReport, Buffered, CheckpointPage, CheckpointState, CheckpointStatement, CheckpointStatus,
    CiphertextPage, CompactReport, CompactionStatus, Companion, CoveredMark, CurrentValue,
    CustodySummary, Describe, EarlierEpochWrites, EncryptedReplica, EvictReport, FrameReplay,
    FrontierLog, GenerationStatus, HeldChange, HeldField, HeldKind, HeldRow, HeldSeal, Holding,
    InstalledTipSchema, KeptSeals, KeyMaterial, LineNode, LogPosition, MAX_BUNDLE_BYTES,
    MAX_BUNDLE_FRAMES, MAX_BUNDLE_ROWS, MAX_CHECKPOINT_LOGS, MAX_PLACEMENTS, MAX_SNAPSHOT_BYTES,
    MAX_SNAPSHOT_ROWS, MAX_UNCONFIGURED_PEERS, MigrationMembership, MigrationStorage,
    OutcomeDivergence, PUBLICATION_CHUNK_BUNDLES, PeerLag, PeerScopeFrontier, PendingSchema,
    Placement, PlacementPage, PlacementRequest, ProjectionPlan, PruneBlock, PruneReport,
    PrunedPage, Publication, ROWS_PER_FRAME, RangePage, RebootstrapReport, ReceiveStatus, Refusal,
    RemotePage, ReplicaRole, ReplicaStatus, RetentionLimits, RetentionPolicy, RoleConfig,
    SchemaConfig, SchemaStage, ScopeFrontier, ScopeStatus, SealRebootstrap, SealViews,
    SecureCommit, SecureConfig, SecurePage, SecureRows, SecureSession, SecureSnapshot, SecureSql,
    SecureTransaction, SessionStatus, SetSummary, SignedCheckpoint, SignedVoid, StagedCloseStatus,
    StateAdvice, TipDevice, TipNodeObservation, TipObservation, TipStatement, UpdateMode,
    installed_tip_schema,
};
pub use rocky_core::{Blocker, BlockerKind, ClearsBy, WaitReason, domain_label, scope_label};
/// The credential types live in `rocky-credentials`; these are the same types.
pub use rocky_credentials as credentials;
pub use rocky_credentials::{
    Capability, CredentialChain, Hash, MAX_CREDENTIAL_DEPTH, PrivateKey, PublicKey, Revocation,
    RevocationSet, SignedCapability, SignedManifest, SignedRevocation,
};
pub use rocky_storage::sql::{
    AbortReason, Certainty, MAX_SAVEPOINTS, MAX_TRANSACTION_TIMEOUT, SqlError, SqlOptions,
    SqlState, Unavailable,
};
pub use rocky_storage::{CommitClass, Error, FailureReason, MAX_FRAME_BYTES, StorageFailure};
use serde::{Serialize, de::DeserializeOwned};
pub use wire::{EncryptedFrame, EncryptedPackage, PackageKind};

pub const MAX_SECURE_FRAME: usize = 256 * 1024;
/// Encoded payload budget, leaving room for the signed framing.
pub(crate) const SECURE_MESSAGE_BYTES: usize = MAX_SECURE_FRAME - 4096;
/// Counts a prefix by encoded size, including room for family fields and cursors.
fn page_len<T: Serialize>(items: &[T], limit: usize) -> Result<usize, Error> {
    let mut bytes = 1024;
    let mut count = 0;
    for item in items.iter().take(limit) {
        let size = encode(item)?.len();
        if bytes + size > SECURE_MESSAGE_BYTES {
            if count == 0 {
                return Err(Error::Quota {
                    resource: "message item",
                    limit: SECURE_MESSAGE_BYTES - 1024,
                });
            }
            break;
        }
        bytes += size;
        count += 1;
    }
    Ok(count)
}
/// Retained protocol artifacts, such as journaled tip statements. Row
/// operations are bounded by `RetentionLimits` instead.
pub const MAX_SECURE_RECORDS: usize = 4096;
/// One native session, and the default soft bound on retained row operations.
pub const MAX_SECURE_BYTES: usize = 32 * 1024 * 1024;
/// The short node identity of a device key: contacts are requested by it.
pub fn secure_node_id(key: PublicKey) -> rocky_core::NodeId {
    let hash = rocky_core::commitment("rocky.secure-node.v1", key.as_bytes());
    let mut id = [0; 16];
    id.copy_from_slice(&hash[..16]);
    rocky_core::NodeId(id)
}
fn denied(message: &str) -> Error {
    Error::Rejected(message.into())
}
/// A credential refusal as this profile reports it.
fn credential(error: rocky_credentials::Error) -> Error {
    match error {
        rocky_credentials::Error::Protocol(error) => Error::Protocol(error),
        other => Error::Rejected(other.to_string()),
    }
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    p2panda_core::cbor::encode_cbor(value).map_err(|_| denied("invalid canonical encoding"))
}
fn decode<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    decode_bounded(bytes, MAX_SECURE_FRAME)
}
fn decode_bounded<T: Serialize + DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T, Error> {
    if bytes.len() > limit {
        return Err(denied("secure frame quota"));
    }
    let value: T =
        p2panda_core::cbor::decode_cbor(bytes).map_err(|_| denied("invalid secure frame"))?;
    if encode(&value)? != bytes {
        return Err(denied("non-canonical secure frame"));
    }
    Ok(value)
}
fn signing_bytes<T: Serialize>(label: &str, value: &T) -> Result<Vec<u8>, Error> {
    encode(&(label, value))
}
/// Microseconds since the epoch: the wall part of hybrid stamp clocks.
fn micros() -> Result<u64, Error> {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|time| u64::try_from(time.as_micros()).unwrap_or(u64::MAX))
        .map_err(|_| denied("clock before epoch"))?;
    #[cfg(test)]
    let time = time.saturating_add(
        CLOCK_SKEW
            .with(std::cell::Cell::get)
            .saturating_mul(1_000_000),
    );
    Ok(time)
}
fn now() -> Result<u64, Error> {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| denied("clock before epoch"))?;
    #[cfg(test)]
    let time = time.saturating_add(CLOCK_SKEW.with(std::cell::Cell::get));
    Ok(time)
}
#[cfg(test)]
thread_local! {
    /// Seconds this test thread's clock runs ahead, to expire credentials
    /// without sleeping.
    static CLOCK_SKEW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Transactions that apply operations this test thread may still commit
    /// before the pending pass is interrupted. Discovery does not spend it.
    static APPLY_BUDGET: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}
/// Spends one apply transaction of the thread's budget; false once it ran out.
#[cfg(test)]
fn apply_allowed() -> bool {
    APPLY_BUDGET.with(|budget| match budget.get() {
        Some(0) => false,
        Some(left) => {
            budget.set(Some(left - 1));
            true
        }
        None => true,
    })
}

#[cfg(test)]
mod tests;

pub use replica::checkpoint::IMPORT_ATTEMPTS;
#[doc(hidden)]
pub use replica::last_in_place_switch_changes;
pub use replica::replay::ROUTINE_SEAL_TRANSACTIONS;
pub use replica::{check_replica_format, local_row_counts, local_table_digests};

/// One-way reference used by durable peer metadata.
pub use rocky_credentials::PeerId;

#[cfg(feature = "qualification")]
pub use replica::{
    HolderMeasurements, LockMeasurements, Measurements, with_measurement_connection,
};

/// Measurement-only overrides are validated before any bounded work starts.
#[cfg(feature = "qualification")]
fn qualification_bound(name: &str, default: usize, maximum: usize) -> Result<usize, Error> {
    match std::env::var_os(name) {
        None => Ok(default),
        Some(value) => value
            .to_str()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|bound| (1..=maximum).contains(bound))
            .ok_or_else(|| denied(&format!("{name} must be between 1 and {maximum}"))),
    }
}
