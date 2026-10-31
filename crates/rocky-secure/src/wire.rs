mod ordinals;
use super::*;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use p2panda_core::{Body, Header, Operation, validate_operation};
use rand::{RngCore, rngs::OsRng};
use rocky_core::{Commitment, ResourceScope, RowChange, RowFields, RowWrite};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

/// Frames decoded recently, by a digest of their bytes. A frame is decoded
/// several times as it is received and applied, and each decoding encodes
/// the header again for its canonical form, its hash and its signature;
/// the result depends on the bytes alone.
static DECODED: LazyLock<Mutex<HashMap<Hash, Operation<Extensions>>>> =
    LazyLock::new(Mutex::default);
const DECODED_FRAMES: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PackageKind {
    Checkpoint,
    /// Rows read on behalf of a peer that does not hold the scope.
    Read,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Extensions {
    pub tip: rocky_core::TipId,
    pub scope: ResourceScope,
    pub generation: rocky_core::KeyEpoch,
    /// The digest of the author's credential chain; see `Chain`.
    pub chain: Commitment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<u32>,
    /// Domain-wide position of this node, independent of its per-scope log.
    pub author_sequence: u64,
    pub row_format: u8,
    pub births: Vec<serde_bytes::ByteArray<32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition: Option<rocky_core::PartitionTuple>,
}

/// Source-schema ordinals and frame-bound birth statements, without
/// existence counts.
pub(crate) const ROW_FORMAT: u8 = 15;
/// The refusal of a frame whose credential chain the receiver lacks.
pub(crate) const INCOMPLETE_FRAME: &str = "incomplete frame: its credential chain is unknown";

/// A credential chain with the digest a frame header names it by. The digest
/// shares the chain's bytes between frames, sessions and stored operations;
/// it carries no authority, and every use still verifies the chain. See
/// `docs/decisions/0053-chains-by-reference.md`.
#[derive(Clone, Debug)]
pub(crate) struct Chain {
    digest: Commitment,
    credentials: Arc<CredentialChain>,
}
impl Chain {
    pub(crate) fn new(credentials: CredentialChain) -> Result<Self, Error> {
        Ok(Self::of_bytes(&encode(&credentials)?, credentials))
    }
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::of_bytes(bytes, decode(bytes)?))
    }
    fn of_bytes(bytes: &[u8], credentials: CredentialChain) -> Self {
        Self {
            digest: rocky_core::commitment("rocky.credential-chain.v1", bytes),
            credentials: Arc::new(credentials),
        }
    }
    pub(crate) fn digest(&self) -> Commitment {
        self.digest
    }
    pub(crate) fn credentials(&self) -> &CredentialChain {
        &self.credentials
    }
}
impl Serialize for Chain {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.credentials.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for Chain {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(CredentialChain::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// A signed header, its sealed body and, beside them, the author's
/// credential chain. The header signs the chain's digest only: a session
/// carries the chain once and sends its frames without it, and a replica
/// stores it once. A frame without its chain is incomplete and is refused.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedFrame {
    #[serde(with = "serde_bytes")]
    header: Vec<u8>,
    #[serde(with = "serde_bytes")]
    body: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chain: Option<Chain>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) migration: Option<crate::replica::MigrationMembership>,
    /// The verified operation of these immutable bytes, once decoded.
    #[serde(skip)]
    decoded: std::sync::OnceLock<Box<Operation<Extensions>>>,
}
impl EncryptedFrame {
    /// A frame without its chain, as storage and a session page hold it.
    pub(crate) fn bare(header: Vec<u8>, body: Vec<u8>) -> Self {
        Self {
            header,
            body,
            chain: None,
            migration: None,
            decoded: std::sync::OnceLock::new(),
        }
    }
    pub(crate) fn header_bytes(&self) -> &[u8] {
        &self.header
    }
    pub(crate) fn body_bytes(&self) -> &[u8] {
        &self.body
    }
    /// The frame with another body, as a test tampers with one.
    #[cfg(test)]
    pub(crate) fn with_body(&self, body: Vec<u8>) -> Self {
        Self {
            body,
            decoded: std::sync::OnceLock::new(),
            ..self.clone()
        }
    }
    pub(crate) fn with_chain(mut self, chain: Chain) -> Self {
        self.chain = Some(chain);
        self
    }
    /// The frame under another signed header, as a forger alters one.
    #[cfg(test)]
    pub(crate) fn with_header(&self, header: Vec<u8>) -> Self {
        Self {
            header,
            decoded: std::sync::OnceLock::new(),
            ..self.clone()
        }
    }
    /// Removes the chain, which a session sends once before the frame.
    pub(crate) fn take_chain(&mut self) -> Option<Chain> {
        self.chain.take()
    }
    /// The digest the signed header names its chain by.
    pub(crate) fn chain_digest(&self) -> Result<Commitment, Error> {
        Ok(self.operation_ref()?.header.extensions.chain)
    }
    /// The author's chain, which must be the one the header names.
    pub(crate) fn chain(&self) -> Result<&Chain, Error> {
        match &self.chain {
            Some(chain) if chain.digest() == self.chain_digest()? => Ok(chain),
            _ => Err(denied(INCOMPLETE_FRAME)),
        }
    }
    /// Bytes a page or a retention bound counts for the frame: its header
    /// and body with their encoding, without the chain.
    pub(crate) fn stored_bytes(&self) -> Result<u64, Error> {
        u64::try_from(self.header.len())
            .ok()
            .and_then(|n| n.checked_add(self.body.len() as u64))
            .ok_or_else(|| denied("stored frame length overflow"))
    }
    pub fn weight(&self) -> usize {
        self.header
            .len()
            .saturating_add(self.body.len())
            .saturating_add(32)
            .saturating_add(self.migration.as_ref().map_or(0, |proof| {
                encode(proof).map_or(usize::MAX, |bytes| bytes.len())
            }))
    }
    /// The frame with its chain, for a transport outside a native session.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.weight() > MAX_SECURE_FRAME {
            return Err(denied("secure frame quota"));
        }
        let bytes = encode(self)?;
        if bytes.len() > 2 * MAX_SECURE_FRAME {
            return Err(denied("secure frame quota"));
        }
        Ok(bytes)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let frame: Self = decode_bounded(bytes, 2 * MAX_SECURE_FRAME)?;
        if frame.weight() > MAX_SECURE_FRAME {
            return Err(denied("secure frame quota"));
        }
        frame.chain()?;
        Ok(frame)
    }
    pub fn id(&self) -> Result<Hash, Error> {
        Ok(self.operation_ref()?.hash)
    }
    pub fn scope(&self) -> Result<ResourceScope, Error> {
        Ok(self.operation_ref()?.header.extensions.scope)
    }
    pub(crate) fn operation(&self) -> Result<Operation<Extensions>, Error> {
        self.operation_ref().cloned()
    }
    /// The verified operation, decoded once per frame: its bytes never change.
    pub(crate) fn operation_ref(&self) -> Result<&Operation<Extensions>, Error> {
        if let Some(operation) = self.decoded.get() {
            return Ok(operation);
        }
        let _ = self.decoded.set(Box::new(self.verified_operation()?));
        self.decoded
            .get()
            .map(|operation| &**operation)
            .ok_or_else(|| Error::Corrupt("decoded frame".into()))
    }
    fn verified_operation(&self) -> Result<Operation<Extensions>, Error> {
        let digest = Hash::new(
            [
                &(self.header.len() as u64).to_le_bytes()[..],
                &self.header,
                &self.body,
            ]
            .concat(),
        );
        let decoded = || DECODED.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(operation) = decoded().get(&digest) {
            return Ok(operation.clone());
        }
        let operation = self.decode_operation()?;
        let mut decoded = decoded();
        if decoded.len() >= DECODED_FRAMES {
            decoded.clear();
        }
        decoded.insert(digest, operation.clone());
        Ok(operation)
    }
    fn decode_operation(&self) -> Result<Operation<Extensions>, Error> {
        let header: Header<Extensions> = decode(&self.header)?;
        check_header(&header)?;
        let operation = Operation {
            hash: header.hash(),
            header,
            body: Some(Body::new(&self.body)),
        };
        validate_operation(&operation)
            .map_err(|_| denied("invalid operation signature or payload"))?;
        Ok(operation)
    }
}

/// A row frame's signed header without its body: what a placement shows.
pub(crate) fn verified_header(bytes: &[u8]) -> Result<Header<Extensions>, Error> {
    let header: Header<Extensions> = decode(bytes)?;
    check_header(&header)?;
    p2panda_core::validate_header(&header).map_err(|_| denied("invalid header signature"))?;
    Ok(header)
}

/// The row format and authenticated metadata every row header satisfies.
fn check_header(header: &Header<Extensions>) -> Result<(), Error> {
    {
        if header.extensions.row_format != ROW_FORMAT {
            return Err(denied("unsupported row frame format"));
        }
        let extension = &header.extensions;
        if extension
            .author
            .is_some_and(|author| !(1..=0x7fff_ffff).contains(&author))
            || extension.partition.as_ref().is_some_and(|tuple| {
                tuple
                    .scope(extension.scope.domain, extension.scope.table)
                    .ok()
                    != Some(extension.scope)
            })
        {
            return Err(denied("invalid authenticated partition scope or author"));
        }
        if header.extensions.births.len() > 32
            || header.previous.len() > 64
            || header.seq_num > i64::MAX as u64
            || header.extensions.author_sequence > i64::MAX as u64
            || !header.extensions.generation.valid()
        {
            return Err(denied("invalid operation metadata"));
        }
        Ok(())
    }
}

pub(crate) fn encrypt(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut nonce = [0; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = XChaCha20Poly1305::new(key.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| denied("encryption failed"))?;
    let mut bytes = nonce.to_vec();
    bytes.extend(ciphertext);
    Ok(bytes)
}
pub(crate) fn decrypt(key: &[u8; 32], aad: &[u8], bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let nonce = bytes
        .get(..24)
        .ok_or_else(|| denied("missing encryption nonce"))?;
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: &bytes[24..],
                aad,
            },
        )
        .map_err(|_| denied("missing/wrong key or corrupt ciphertext"))
}
pub(crate) fn author(
    key: &PrivateKey,
    extensions: Extensions,
    chain: Chain,
    encryption_key: &[u8; 32],
    log: (u64, Option<Hash>, u64),
    previous: Vec<Hash>,
    plaintext: &[u8],
) -> Result<EncryptedFrame, Error> {
    if extensions.chain != chain.digest() {
        return Err(denied(INCOMPLETE_FRAME));
    }
    let bytes = encrypt(encryption_key, &encode(&extensions)?, plaintext)?;
    let body = Body::new(&bytes);
    let mut header = Header {
        version: 1,
        public_key: key.public_key(),
        signature: None,
        payload_size: body.size(),
        payload_hash: Some(body.hash()),
        timestamp: log.2,
        seq_num: log.0,
        backlink: log.1,
        previous,
        extensions,
    };
    header.sign(key);
    let frame = EncryptedFrame::bare(header.to_bytes(), bytes).with_chain(chain);
    frame.to_bytes()?;
    Ok(frame)
}

/// A frame's place in a transaction bundle. Every member carries the same
/// `members`: entry `i` names member `i`'s scope and sequence, sealed under
/// that member's scope key, so a reader learns only the partitions it holds
/// keys for and how many members there are.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Membership {
    pub transaction: Commitment,
    pub index: u16,
    #[serde(with = "member_bytes")]
    pub members: Vec<Vec<u8>>,
}
// Ciphertexts are byte strings, not arrays of encoded integer values.
mod member_bytes {
    use serde::{Deserialize, Serialize};

    pub(super) fn serialize<S: serde::Serializer>(
        members: &[Vec<u8>],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        members
            .iter()
            .map(|member| serde_bytes::Bytes::new(member))
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Vec<u8>>, D::Error> {
        Ok(Vec::<serde_bytes::ByteBuf>::deserialize(deserializer)?
            .into_iter()
            .map(serde_bytes::ByteBuf::into_vec)
            .collect())
    }
}

#[derive(Serialize, Deserialize)]
struct BundleBody {
    version: u8,
    proofs: BTreeMap<Commitment, crate::replica::moves::CreationProof>,
    carried: BTreeMap<Commitment, crate::replica::moves::Carried>,
    membership: Option<Membership>,
    writes: Vec<RowWrite>,
    /// A replayed table's part of the bundle, instead of `writes`.
    intent: Option<rocky_core::replay::Intent>,
    /// How a replica replayed a transaction, alone in its frame.
    outcome: Option<rocky_core::replay::OutcomeRecord>,
}
#[derive(Serialize, Deserialize)]
struct WitnessBody {
    version: u8,
    #[serde(with = "serde_bytes")]
    body: Vec<u8>,
    creations: Vec<(Commitment, Commitment)>,
}
/// A current row payload, always protected by a creation witness envelope.
#[derive(Clone)]
pub(crate) struct RowPayload {
    #[cfg(test)]
    source: Option<rocky_core::ApplicationManifest>,
    proofs: BTreeMap<Commitment, crate::replica::moves::CreationProof>,
    carried: BTreeMap<Commitment, crate::replica::moves::Carried>,
    membership: Option<Membership>,
    writes: Vec<RowWrite>,
    intent: Option<rocky_core::replay::Intent>,
    outcome: Option<rocky_core::replay::OutcomeRecord>,
    creations: Vec<(Commitment, Commitment)>,
}
impl RowPayload {
    #[cfg(test)]
    pub(crate) fn decode_test(
        bytes: &[u8],
        frame: &EncryptedFrame,
        application: &dyn rocky_core::RowApplication,
    ) -> Result<Self, Error> {
        let definition = application.manifest();
        let mut payload = Self::decode_source(bytes, &definition, frame.scope()?)?;
        payload.derive_births(frame, definition.hash(), application)?;
        Ok(payload)
    }
    #[cfg(test)]
    pub(crate) fn rebound_births_for_test(
        &self,
        chain: &Chain,
    ) -> Result<Vec<serde_bytes::ByteArray<32>>, Error> {
        self.proofs
            .values()
            .map(|proof| proof.rebound_provenance_for_test(chain).map(Into::into))
            .collect()
    }
    #[cfg(test)]
    pub(crate) fn compact_test(
        &self,
        bytes: &[u8],
        scope: ResourceScope,
    ) -> Result<Vec<u8>, Error> {
        ordinals::compact_test(
            bytes,
            self.source
                .as_ref()
                .ok_or_else(|| denied("test payload lacks source schema"))?,
            scope,
        )
    }
    pub(crate) fn derive_births(
        &mut self,
        frame: &EncryptedFrame,
        manifest: Commitment,
        application: &dyn rocky_core::RowApplication,
    ) -> Result<(), Error> {
        for write in &self.writes {
            if write.change.before.is_none()
                && !self.carried.contains_key(&write.change.row)
                && let Some(identity) = application
                    .row_identity(&write.change)
                    .map_err(|error| denied(&error))?
            {
                let proof =
                    crate::replica::moves::CreationProof::derived(manifest, identity, frame)?;
                if self.proofs.insert(write.change.row, proof).is_some() {
                    return Err(denied("repeated birth in a frame"));
                }
            }
        }
        let expected: Vec<serde_bytes::ByteArray<32>> = self
            .proofs
            .values()
            .map(|proof| proof.provenance().map(Into::into))
            .collect::<Result<_, _>>()?;
        if expected != frame.operation_ref()?.header.extensions.births {
            return Err(denied("frame creation statements differ from its births"));
        }
        Ok(())
    }
    pub(crate) fn compact(
        bytes: &[u8],
        definition: &rocky_core::ApplicationManifest,
        scope: ResourceScope,
    ) -> Result<Vec<u8>, Error> {
        ordinals::compact(bytes, definition, scope)
    }
    pub(crate) fn decode_source(
        bytes: &[u8],
        definition: &rocky_core::ApplicationManifest,
        scope: ResourceScope,
    ) -> Result<Self, Error> {
        ordinals::expand(bytes, definition, scope)
    }
    pub(crate) fn check_formats(plaintext: &[u8]) -> Result<(), Error> {
        #[derive(Deserialize)]
        struct Envelope {
            version: u8,
            #[serde(with = "serde_bytes")]
            body: Vec<u8>,
        }
        #[derive(Deserialize)]
        struct Version {
            version: u8,
        }
        let envelope: Envelope = p2panda_core::cbor::decode_cbor(plaintext)
            .map_err(|_| denied("unsupported creation witness format"))?;
        if envelope.version != 1 {
            return Err(denied("unsupported creation witness format"));
        }
        let body: Version = p2panda_core::cbor::decode_cbor(envelope.body.as_slice())
            .map_err(|_| denied("unsupported bundle version"))?;
        if body.version != 6 {
            return Err(denied("unsupported bundle version"));
        }
        Ok(())
    }
    pub(crate) fn rows(changes: &[RowChange]) -> Result<Vec<u8>, Error> {
        encode(&BundleBody {
            version: 5,
            proofs: BTreeMap::new(),
            carried: BTreeMap::new(),
            membership: None,
            writes: changes.iter().cloned().map(RowWrite::changed).collect(),
            intent: None,
            outcome: None,
        })
    }
    pub(crate) fn intent_bundle(
        membership: Membership,
        intent: rocky_core::replay::Intent,
    ) -> Result<Vec<u8>, Error> {
        encode(&BundleBody {
            version: 5,
            proofs: BTreeMap::new(),
            carried: BTreeMap::new(),
            membership: Some(membership),
            writes: Vec::new(),
            intent: Some(intent),
            outcome: None,
        })
    }
    pub(crate) fn outcome_record(
        record: rocky_core::replay::OutcomeRecord,
    ) -> Result<Vec<u8>, Error> {
        encode(&BundleBody {
            version: 5,
            proofs: BTreeMap::new(),
            carried: BTreeMap::new(),
            membership: None,
            writes: Vec::new(),
            intent: None,
            outcome: Some(record),
        })
    }
    pub(crate) fn bundle(membership: Membership, writes: Vec<RowWrite>) -> Result<Vec<u8>, Error> {
        encode(&BundleBody {
            version: 5,
            proofs: BTreeMap::new(),
            carried: BTreeMap::new(),
            membership: Some(membership),
            writes,
            intent: None,
            outcome: None,
        })
    }
    pub(crate) fn witness(
        body: Vec<u8>,
        creations: Vec<(Commitment, Commitment)>,
    ) -> Result<Vec<u8>, Error> {
        encode(&WitnessBody {
            version: 1,
            body,
            creations,
        })
    }
    pub(crate) fn stamp_body(
        bytes: &[u8],
        proofs: BTreeMap<Commitment, crate::replica::moves::CreationProof>,
        carried: BTreeMap<Commitment, crate::replica::moves::Carried>,
    ) -> Result<Vec<u8>, Error> {
        let mut body: BundleBody = decode(bytes)?;
        body.proofs = proofs;
        body.carried = carried;
        encode(&body)
    }
    pub(crate) fn proof(&self, row: &Commitment) -> Option<&crate::replica::moves::CreationProof> {
        self.proofs.get(row)
    }
    pub(crate) fn carried(&self, row: &Commitment) -> Option<&crate::replica::moves::Carried> {
        self.carried.get(row)
    }
    pub(crate) fn creations(&self) -> &[(Commitment, Commitment)] {
        &self.creations
    }
    pub(crate) fn membership(&self) -> Option<&Membership> {
        self.membership.as_ref()
    }
    pub(crate) fn writes(&self) -> &[RowWrite] {
        &self.writes
    }
    pub(crate) fn intent(&self) -> Option<&rocky_core::replay::Intent> {
        self.intent.as_ref()
    }
    pub(crate) fn outcome(&self) -> Option<&rocky_core::replay::OutcomeRecord> {
        self.outcome.as_ref()
    }
    pub(crate) fn into_writes(self) -> Vec<RowWrite> {
        self.writes
    }
}

/// Separately encrypted outputs. The aggregate commitment covers ciphertext and routing metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedPackage {
    pub scope: ResourceScope,
    pub generation: rocky_core::KeyEpoch,
    pub kind: PackageKind,
    pub(crate) bytes: Vec<u8>,
}
impl EncryptedPackage {
    pub fn seal(
        scope: ResourceScope,
        generation: rocky_core::KeyEpoch,
        kind: PackageKind,
        key: &[u8; 32],
        bytes: &[u8],
    ) -> Result<Self, Error> {
        if !generation.valid() || bytes.len() > rocky_core::MAX_PAYLOAD_BYTES {
            return Err(denied("package quota/generation"));
        }
        let encrypted = encrypt(key, &encode(&(scope, generation, &kind))?, bytes)?;
        Ok(Self {
            scope,
            generation,
            kind,
            bytes: encrypted,
        })
    }
    pub(crate) fn open(&self, key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        decrypt(
            key,
            &encode(&(self.scope, self.generation, &self.kind))?,
            &self.bytes,
        )
    }
    pub fn commitment(&self) -> Result<Commitment, Error> {
        Ok(rocky_core::commitment(
            "rocky.encrypted-package.v2",
            &encode(self)?,
        ))
    }
}
