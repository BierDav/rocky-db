//! Credentials independent of a database or a network: signed manifests,
//! capabilities and revocations, the identities they bind and the provider
//! port that supplies them, key providers, issuance and the enrollment and
//! renewal messages. A runtime enforces
//! what these verify. See `docs/runtime/credentials.md`.
mod author_binding;
mod checkpoint_record;
mod coordination;
mod delivery;
mod discovery;
mod enroll;
mod existence_base;
mod extension;
mod finality;
mod group;
mod identity;
mod issue;
mod keys;
mod migration;
pub use migration::{MAX_MIGRATION_DESCRIPTOR_BYTES, SignedMigrationPublication};
mod partition;
mod peer;
mod revocation;
mod signed;
mod tips;

pub use author_binding::AuthorBinding;
pub use checkpoint_record::{
    CHECKPOINT_RECORD_FORMAT, CheckpointRecordStatement, SignedCheckpointRecord,
};
pub use coordination::{
    CoordinationGrant, MAX_APPLICATION_NAME, SignedCoordinationGrant, SignedTenantAdmission,
    TenantAdmission,
};
pub use delivery::{DeliveryReceipt, MAX_DELIVERY_PAYLOAD, SealedDelivery};
pub use discovery::{DiscoverySecret, open_discovery, seal_discovery};
pub use enroll::{
    Admission, Exchange, IdentityAnswer, IdentityRequest, Invitation, PairRequest, RenewRequest,
    Renewal, open_enrollment, seal_enrollment,
};
pub use existence_base::{
    EXISTENCE_BASE_FORMAT, ExistenceBase, ExistenceBaseStatement, ExistenceCut, ExistenceIdentity,
    ExistenceLog, MAX_EXISTENCE_BASE_LOGS, SignedExistenceBase,
};
pub use extension::{AuthorRange, Extended, Extension, MAX_AUTHOR};
pub use finality::{
    MAX_FINALITY_ACKS, MAX_FINALITY_BYTES, MAX_TERMINAL_ACK_BYTES, SEAL_FINALITY_FORMAT,
    SealFinality, TERMINAL_ACK_FORMAT, TerminalAck, TerminalAckStatement,
};
pub use group::{GROUP_SECRET_LEN, GroupSecretEnvelope, derive_table_key};
pub use identity::{
    CoordinatorControl, ExternalLogin, FileIdentityProvider, Identity, IdentityProvider,
    LoginProvider, Publisher, Purpose, ReaderScope, SigningDevice, TransportEndpoint,
};
pub use issue::{Authority, Grant, MAX_GRANTS, Profile, Resource, device_chain};
pub use keys::{FileKeyProvider, KeyProvider, ProviderError, Vault, write_private};
pub use p2panda_core::{Hash, PrivateKey, PublicKey, Signature};
pub use partition::PartitionGrant;
pub use peer::PeerId;
pub use revocation::{
    DAY, LIFETIME_SKEW, MAX_CHAIN_LIFETIME, MAX_LIVE_REVOCATIONS, MAX_REVOCATION_BYTES,
    MAX_REVOCATION_SET_BYTES, REVOCATION_SET_FULL, Revocation, RevocationSet, SIGNATURE_OVERHEAD,
    SignedRevocation,
};
pub use signed::{
    Capability, CredentialChain, Credentials, Endorsement, MAX_ENDORSEMENT_BYTES, SignedCapability,
    SignedManifest, Verified, VerifiedChain,
};

pub use tips::{
    AuthorMark, BOOKMARK_MOVE_FORMAT, BookmarkMoveStatement, GENESIS_LINE_FORMAT,
    GenesisLineStatement, LogPoint, MAX_BOOKMARK_NAME, Recovery, SEAL_FORMAT, SealAction,
    SealStatement, SignedBookmarkMove, SignedGenesisLine, SignedSeal, SignedTipOpening,
    TIP_OPENING_FORMAT, TipAuthority, TipGraph, TipOpeningStatement, genesis_tip,
};

use serde::{Serialize, de::DeserializeOwned};

/// Longest delegation chain: publisher, issuer identities, identity, node.
pub const MAX_CREDENTIAL_DEPTH: usize = 8;
/// Largest signed credential structure.
pub const MAX_CREDENTIAL_BYTES: usize = 256 * 1024;

/// Why credentials were refused. `Denied` is final for the same input.
#[derive(Debug)]
pub enum Error {
    Denied(String),
    Protocol(rocky_core::ProtocolError),
    /// The key provider failed or holds no such secret.
    Provider(ProviderError),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied(message) => f.write_str(message),
            Self::Protocol(error) => write!(f, "{error}"),
            Self::Provider(error) => write!(f, "{error}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<rocky_core::ProtocolError> for Error {
    fn from(error: rocky_core::ProtocolError) -> Self {
        Self::Protocol(error)
    }
}
pub(crate) fn denied(message: &str) -> Error {
    Error::Denied(message.into())
}

/// The pinned canonical CBOR encoding every signature covers.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    p2panda_core::cbor::encode_cbor(value).map_err(|_| denied("invalid canonical encoding"))
}
/// Decodes at most `limit` bytes and refuses noncanonical or trailing input.
pub fn decode_bounded<T: Serialize + DeserializeOwned>(
    bytes: &[u8],
    limit: usize,
) -> Result<T, Error> {
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
/// The bytes a domain-separated signature covers.
pub fn signing_bytes<T: Serialize>(label: &str, value: &T) -> Result<Vec<u8>, Error> {
    encode(&(label, value))
}
