//! Admission evidence: this file's signed record of the births it admitted,
//! consumed, withheld or saw carried, and the claims derived from it. See
//! `docs/runtime/admission-evidence.md`.
use super::*;
use crate::replica::checkpoint::row_of;
use p2panda_core::Signature;
use serde::{Deserialize, Serialize};

pub(in crate::replica) const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS secure_admission_context(id INTEGER PRIMARY KEY CHECK(id=1),context BLOB NOT NULL,signature BLOB NOT NULL,head BLOB NOT NULL,head_signature BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS secure_admission_entries(entry INTEGER PRIMARY KEY,scope BLOB NOT NULL,frame BLOB NOT NULL,kind INTEGER NOT NULL,bytes BLOB NOT NULL,signature BLOB NOT NULL,chain BLOB NOT NULL)",
    "CREATE UNIQUE INDEX IF NOT EXISTS secure_admission_frames ON secure_admission_entries(frame) WHERE kind=0",
    "CREATE INDEX IF NOT EXISTS secure_admission_scopes ON secure_admission_entries(scope,entry)",
    "CREATE TABLE IF NOT EXISTS secure_admission_claims(allocation INTEGER NOT NULL,identity INTEGER NOT NULL,kind INTEGER NOT NULL,provenance BLOB NOT NULL,entry INTEGER NOT NULL,ordinal INTEGER NOT NULL,PRIMARY KEY(allocation,identity,kind,provenance)) WITHOUT ROWID",
    "CREATE UNIQUE INDEX IF NOT EXISTS secure_admission_grants ON secure_admission_claims(allocation,identity) WHERE kind=0",
    "CREATE TABLE IF NOT EXISTS secure_identity_tables(id INTEGER PRIMARY KEY,scope BLOB NOT NULL UNIQUE)",
    "CREATE TABLE IF NOT EXISTS secure_identity_partitions(scope BLOB PRIMARY KEY,allocation INTEGER NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_identity_ledger(scope BLOB NOT NULL,author INTEGER NOT NULL,signer BLOB NOT NULL,sequence INTEGER NOT NULL,PRIMARY KEY(scope,author)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_identity_summary(scope BLOB NOT NULL,author INTEGER NOT NULL,sequence INTEGER NOT NULL,PRIMARY KEY(scope,author)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_admission_carries(receipt INTEGER NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal>=0 AND ordinal<32),entry INTEGER NOT NULL UNIQUE,PRIMARY KEY(receipt,ordinal)) WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS secure_admission_carry_frames ON secure_admission_entries(frame) WHERE kind=2",
    "CREATE TABLE IF NOT EXISTS secure_identity_own(scope BLOB NOT NULL,author INTEGER NOT NULL,sequence INTEGER NOT NULL,PRIMARY KEY(scope,author)) WITHOUT ROWID",
];

const CONTEXT: &str = "rocky.admission-context.v1";
const HEAD: &str = "rocky.admission-head.v1";
const ENTRY: &str = "rocky.admission-entry.v1";
const CHAIN: &str = "rocky.admission-chain.v1";
const VERSION: u8 = 1;

/// Who admits into this file and the finite cuts of predecessor evidence
/// it inherited by restore, oldest first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replica) struct AdmissionContext {
    version: u8,
    #[serde(with = "serde_bytes")]
    lineage: Commitment,
    publisher: PublicKey,
    node: PublicKey,
    cuts: Vec<PredecessorCut>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replica) struct PredecessorCut {
    #[serde(with = "serde_bytes")]
    lineage: Commitment,
    node: PublicKey,
    count: u64,
    #[serde(with = "serde_bytes")]
    chain: Commitment,
    revision: u64,
    head_signature: Signature,
}
/// The signed count and chain of every entry, pinned to a revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replica) struct AdmissionHead {
    version: u8,
    #[serde(with = "serde_bytes")]
    lineage: Commitment,
    count: u64,
    #[serde(with = "serde_bytes")]
    chain: Commitment,
    revision: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replica) struct AdmissionEntry {
    version: u8,
    index: u64,
    pub(in crate::replica) kind: EntryKind,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replica) enum EntryKind {
    Frame(FrameReceipt),
    Restoration(Restoration),
    CarryObservation(CarryObservation),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replica) enum ReceiptAllocation {
    Unresolved,
    Bound(ResourceScope),
}
/// What admitting one birth-bearing frame decided, per original ordinal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replica) struct FrameReceipt {
    pub(in crate::replica) frame: Hash,
    pub(in crate::replica) signer: PublicKey,
    pub(in crate::replica) author: Option<u32>,
    pub(in crate::replica) scope: ResourceScope,
    pub(in crate::replica) allocation: ReceiptAllocation,
    pub(in crate::replica) sequence: u64,
    pub(in crate::replica) author_sequence: u64,
    pub(in crate::replica) tip: TipId,
    #[serde(with = "serde_bytes")]
    pub(in crate::replica) schema: Commitment,
    /// The workspace tip, when the path withheld the frame's births.
    pub(in crate::replica) target: Option<TipId>,
    /// With `target`: O(scope, author) at the frame's own first admission
    /// (0 without a mark or an author).
    pub(in crate::replica) floor: Option<u32>,
    pub(in crate::replica) writes: u8,
    pub(in crate::replica) births: Vec<Birth>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replica) struct Birth {
    pub(in crate::replica) ordinal: u8,
    pub(in crate::replica) disposition: Disposition,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replica) enum Disposition {
    Created {
        identity: rocky_core::RowIdentity,
        #[serde(with = "serde_bytes")]
        provenance: Commitment,
    },
    Consumed {
        identity: rocky_core::RowIdentity,
    },
    Filtered,
    Carried {
        identity: rocky_core::RowIdentity,
        #[serde(with = "serde_bytes")]
        provenance: Commitment,
        signer: PublicKey,
    },
}
/// A withheld birth restored later at `target`: a new grant referring to
/// the receipt, which never changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replica) struct Restoration {
    pub(in crate::replica) receipt: u64,
    pub(in crate::replica) frame: Hash,
    pub(in crate::replica) ordinal: u8,
    pub(in crate::replica) identity: rocky_core::RowIdentity,
    pub(in crate::replica) allocation: ResourceScope,
    #[serde(with = "serde_bytes")]
    pub(in crate::replica) provenance: Commitment,
    pub(in crate::replica) target: TipId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replica) struct CarryObservation {
    pub receipt: u64,
    pub frame: Hash,
    pub ordinal: u8,
    pub allocation: ResourceScope,
    pub identity: rocky_core::RowIdentity,
    #[serde(with = "serde_bytes")]
    pub provenance: Commitment,
    pub signer: PublicKey,
    pub target: TipId,
}

/// A claim on a normalized table identity: kind 0 is its one original
/// assignment, kind 1 a carried observation of its provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::replica) struct Claim {
    pub(in crate::replica) kind: u8,
    pub(in crate::replica) provenance: Commitment,
    pub(in crate::replica) entry: u64,
    pub(in crate::replica) ordinal: u8,
}

type DerivedClaim = (i64, i64, u8, Commitment, u64, u8);

/// Verified entries shared only by the births of one frame in one transaction.
#[derive(Default)]
pub(in crate::replica) struct FrameClaims {
    entries: BTreeMap<u64, Vec<DerivedClaim>>,
}

/// Entry marks stay immutable while the frame's claims are checked.
pub(in crate::replica) struct BirthSnapshot {
    pub permanent: Vec<checkpoint::IdentityMark>,
    pub allocation: Vec<checkpoint::IdentityMark>,
    pub own: BTreeMap<u32, u32>,
    pub ledger: IdentityLedger,
    pub summary: BTreeMap<u32, u32>,
    pub receipt: Option<(u64, FrameReceipt)>,
    pub claims: FrameClaims,
}

pub(in crate::replica) enum BirthClass {
    Created,
    Carried,
    Exact,
    Restore(Restoration),
    Observe(CarryObservation),
    Suppressed(Option<&'static str>),
}

pub(in crate::replica) struct BirthInput {
    pub frame: Hash,
    pub ordinal: u8,
    pub identity: rocky_core::RowIdentity,
    pub provenance: Commitment,
    pub signer: PublicKey,
    pub author: Option<u32>,
    pub carried: bool,
    pub existing: bool,
    pub finalized: bool,
    pub target: TipId,
    pub first: bool,
}

impl<A: RowApplication> Inner<A> {
    /// Checks the complete ordinal mapping while the signed payload exists.
    /// Old negative decisions remain tied to their original target.
    pub(in crate::replica) async fn check_frame_receipt(
        &self,
        receipt: &FrameReceipt,
        frame: &EncryptedFrame,
        writes: &[RowWrite],
        payload: &RowPayload,
    ) -> Result<(), Error> {
        let operation = frame.operation_ref()?;
        let extension = &operation.header.extensions;
        if receipt.frame != operation.hash
            || receipt.signer != operation.header.public_key
            || receipt.author != extension.author
            || receipt.scope != extension.scope
            || receipt.sequence != operation.header.seq_num
            || receipt.author_sequence != extension.author_sequence
            || receipt.tip != extension.tip
            || receipt.schema != self.manifest_of_tip(extension.tip)?
            || usize::from(receipt.writes) != writes.len()
        {
            return Err(corrupt("receipt differs from its frame"));
        }
        check_receipt_shape(receipt)?;
        let fields = match receipt.target {
            Some(target) => match self.path_fields_to(receipt.scope.domain, receipt.tip, target) {
                Ok(fields) => Some(fields),
                Err(Error::Incompatible(_)) => None,
                Err(error) => return Err(error),
            },
            None => None,
        };
        for (ordinal, write) in writes.iter().enumerate() {
            let listed = receipt
                .births
                .iter()
                .find(|birth| usize::from(birth.ordinal) == ordinal);
            if let Some(birth) = listed {
                if write.change.before.is_some() {
                    return Err(corrupt("receipt lists a nonbirth"));
                }
                match &birth.disposition {
                    Disposition::Filtered => {
                        if fields
                            .as_ref()
                            .is_some_and(|fields| fields.current(write).is_some())
                        {
                            return Err(corrupt("filtered birth was current at admission"));
                        }
                    }
                    Disposition::Created { provenance, .. } => {
                        if payload.carried(&write.change.row).is_some()
                            || payload
                                .proof(&write.change.row)
                                .map(moves::CreationProof::provenance)
                                .transpose()?
                                != Some(*provenance)
                        {
                            return Err(corrupt("creation provenance differs from its frame"));
                        }
                    }
                    Disposition::Carried {
                        provenance, signer, ..
                    } => {
                        let carried = payload
                            .carried(&write.change.row)
                            .ok_or_else(|| corrupt("carry missing from frame"))?;
                        if carried.proof.provenance()? != *provenance
                            || carried.proof.signer()? != *signer
                        {
                            return Err(corrupt("carried provenance differs from its frame"));
                        }
                    }
                    Disposition::Consumed { .. } => {}
                }
            } else if write.change.before.is_none()
                && self.tables.contains(&write.change.scope.table)
            {
                let mut write = write.clone();
                for image in [&mut write.change.before, &mut write.change.after]
                    .into_iter()
                    .flatten()
                {
                    image.retain(|field, _| self.fields.contains(field));
                }
                if self
                    .app
                    .row_identity(&write.change)
                    .map_err(|message| denied(&message))?
                    .is_some()
                {
                    return Err(corrupt("an applied numeric birth is unlisted"));
                }
            }
        }
        Ok(())
    }
    /// Grants only the exact recorded origin; negative decisions never
    /// become grants merely because a replacement lowered the live ledger.
    pub(in crate::replica) async fn classify_birth(
        &self,
        (allocation, allocation_scope): (i64, ResourceScope),
        snapshot: &mut BirthSnapshot,
        birth: BirthInput,
    ) -> Result<BirthClass, Error> {
        let BirthInput {
            frame,
            ordinal,
            identity,
            provenance,
            signer,
            author,
            carried,
            existing,
            finalized,
            target,
            first,
        } = birth;
        if [&snapshot.permanent, &snapshot.allocation]
            .iter()
            .any(|marks| {
                marks
                    .iter()
                    .any(|mark| mark.author == identity.author() && mark.signer != signer)
            })
            || snapshot
                .ledger
                .get(identity.author())
                .is_some_and(|mark| mark.signer != signer)
            || (!carried && author != Some(identity.author()))
        {
            return Err(denied("forged row author or reused identity sequence"));
        }
        let retired = snapshot
            .ledger
            .get(identity.author())
            .is_some_and(|mark| identity.sequence() <= mark.sequence);
        let claims = self
            .claims_on_frame(allocation, identity, &mut snapshot.claims)
            .await?;
        let conflict = claims.iter().any(|claim| claim.provenance != provenance);
        let Some((index, receipt)) = &snapshot.receipt else {
            if !first {
                return Err(corrupt("an applied birth has no receipt"));
            }
            if carried {
                return if conflict {
                    Err(denied("a carried creation contradicts its known original"))
                } else {
                    Ok(BirthClass::Carried)
                };
            }
            // The concrete mark is the author's own order in this partition;
            // another partition's maximum proves no particular origin.
            let reused = snapshot
                .own
                .get(&identity.author())
                .is_some_and(|sequence| identity.sequence() <= *sequence)
                || conflict
                || claims.iter().any(|claim| claim.kind == 0);
            if reused {
                if finalized && existing {
                    return Ok(BirthClass::Suppressed(Some(
                        "row is unavailable behind the finalized seal",
                    )));
                }
                let summarized = snapshot
                    .summary
                    .get(&identity.author())
                    .is_some_and(|mark| identity.sequence() <= *mark);
                return Err(denied(if summarized {
                    "identity evidence below the summarized mark"
                } else {
                    "forged row author or reused identity sequence"
                }));
            }
            return Ok(BirthClass::Created);
        };
        let disposition = &receipt
            .births
            .iter()
            .find(|birth| birth.ordinal == ordinal)
            .ok_or_else(|| corrupt("an applied birth is unlisted"))?
            .disposition;
        match disposition {
            Disposition::Consumed { identity: recorded } => {
                if *recorded != identity || carried {
                    return Err(corrupt("consumed birth differs"));
                }
                Ok(BirthClass::Suppressed(None))
            }
            Disposition::Created {
                identity: recorded,
                provenance: original,
            } => {
                if carried
                    || *recorded != identity
                    || *original != provenance
                    || !claims.iter().any(|claim| {
                        claim.kind == 0
                            && claim.entry == *index
                            && claim.ordinal == ordinal
                            && claim.provenance == provenance
                    })
                {
                    return Err(corrupt("original assignment differs from its frame"));
                }
                Ok(if retired {
                    BirthClass::Suppressed(None)
                } else {
                    BirthClass::Exact
                })
            }
            Disposition::Carried {
                identity: recorded,
                provenance: original,
                signer: original_signer,
            } => {
                if !carried
                    || *recorded != identity
                    || *original != provenance
                    || *original_signer != signer
                {
                    return Err(corrupt("carried birth differs from its frame"));
                }
                if !claims
                    .iter()
                    .any(|claim| claim.kind == 1 && claim.provenance == provenance)
                {
                    return Err(corrupt("carried observation has no claim"));
                }
                Ok(if conflict {
                    BirthClass::Suppressed(None)
                } else {
                    BirthClass::Exact
                })
            }
            Disposition::Filtered => {
                // Carry authority comes from the original proof and bundle,
                // never from a filtered ordinary-creation grant.
                if carried {
                    if conflict {
                        return Ok(BirthClass::Suppressed(None));
                    }
                    let observed = self.carry_observation(*index, ordinal, frame).await?;
                    if let Some(observed) = observed {
                        if observed.identity != identity
                            || observed.provenance != provenance
                            || observed.signer != signer
                            || observed.allocation != allocation_scope
                        {
                            return Err(corrupt("carry observation differs from its frame"));
                        }
                        if !claims
                            .iter()
                            .any(|claim| claim.kind == 1 && claim.provenance == provenance)
                        {
                            return Err(corrupt("carry observation has no claim"));
                        }
                        return Ok(BirthClass::Exact);
                    }
                    return Ok(BirthClass::Observe(CarryObservation {
                        receipt: *index,
                        frame,
                        ordinal,
                        allocation: allocation_scope,
                        identity,
                        provenance,
                        signer,
                        target,
                    }));
                }
                if let Some((grant_index, restoration)) =
                    self.restoration_of(*index, ordinal, frame).await?
                {
                    if restoration.identity != identity
                        || restoration.provenance != provenance
                        || restoration.allocation != allocation_scope
                        || !claims.iter().any(|claim| {
                            claim.kind == 0
                                && claim.entry == grant_index
                                && claim.ordinal == ordinal
                                && claim.provenance == provenance
                        })
                    {
                        return Err(corrupt("restoration or its claim differs from its frame"));
                    }
                    return Ok(if retired {
                        BirthClass::Suppressed(None)
                    } else {
                        BirthClass::Exact
                    });
                }
                let floor = receipt
                    .floor
                    .ok_or_else(|| corrupt("filtered birth has no floor"))?;
                if identity.sequence() <= floor || (finalized && existing) {
                    return Ok(BirthClass::Suppressed(Some(
                        "identity at or below its admission-time mark",
                    )));
                }
                if conflict || claims.iter().any(|claim| claim.kind == 0) {
                    return Ok(BirthClass::Suppressed(None));
                }
                if snapshot
                    .summary
                    .get(&identity.author())
                    .is_some_and(|mark| identity.sequence() <= *mark)
                {
                    return Ok(BirthClass::Suppressed(Some(
                        "identity evidence below the summarized mark",
                    )));
                }
                Ok(if retired {
                    BirthClass::Suppressed(None)
                } else {
                    BirthClass::Restore(Restoration {
                        receipt: *index,
                        frame,
                        ordinal,
                        allocation: allocation_scope,
                        identity,
                        provenance,
                        target,
                    })
                })
            }
        }
    }
}

/// Decodes `bytes` and requires them to be its one canonical encoding.
fn canonical<T: Serialize + for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, Error> {
    let value: T = decode(bytes).map_err(|_| Error::Corrupt("admission evidence".into()))?;
    if encode(&value)? != bytes {
        return Err(Error::Corrupt("admission evidence is not canonical".into()));
    }
    Ok(value)
}
fn corrupt(reason: &str) -> Error {
    Error::Corrupt(format!("admission evidence {reason}"))
}
pub(in crate::replica) fn semantic_refusal(error: &Error) -> bool {
    matches!(
        error,
        Error::Rejected(_) | Error::Protocol(_) | Error::Incompatible(_)
    )
}
fn signature_of(bytes: &[u8]) -> Result<Signature, Error> {
    let bytes: [u8; 64] = bytes.try_into().map_err(|_| corrupt("signature"))?;
    Ok(Signature::from_bytes(&bytes))
}
fn genesis(lineage: Commitment) -> Commitment {
    rocky_core::commitment(CHAIN, &lineage)
}
fn link(previous: Commitment, bytes: &[u8]) -> Commitment {
    let mut joined = previous.to_vec();
    joined.extend(rocky_core::commitment(ENTRY, bytes));
    rocky_core::commitment(CHAIN, &joined)
}
fn sign<T: Serialize>(key: &PrivateKey, purpose: &str, value: &T) -> Result<Signature, Error> {
    Ok(key.sign(&signing_bytes(purpose, value)?))
}
fn verify<T: Serialize>(
    key: PublicKey,
    purpose: &str,
    value: &T,
    signature: &Signature,
) -> Result<(), Error> {
    if !key.verify(&signing_bytes(purpose, value)?, signature) {
        return Err(corrupt("signature does not verify"));
    }
    Ok(())
}

impl AdmissionContext {
    /// The lineage and node whose signature covers entry `index`.
    fn signer_of(&self, index: u64) -> (Commitment, PublicKey) {
        let mut low = 0;
        for cut in &self.cuts {
            if index > low && index <= cut.count {
                return (cut.lineage, cut.node);
            }
            low = cut.count;
        }
        (self.lineage, self.node)
    }
    fn genesis(&self) -> Commitment {
        genesis(self.cuts.first().map_or(self.lineage, |cut| cut.lineage))
    }
}

impl<A: RowApplication> Inner<A> {
    /// In the transaction that creates the file: a fresh lineage, an empty
    /// signed journal.
    pub(in crate::replica) async fn create_admission_context(&self) -> Result<(), Error> {
        let lineage: Commitment = rand::random();
        let context = AdmissionContext {
            version: VERSION,
            lineage,
            publisher: self.config.publisher,
            node: self.config.node.public_key(),
            cuts: Vec::new(),
        };
        let head = AdmissionHead {
            version: VERSION,
            lineage,
            count: 0,
            chain: genesis(lineage),
            revision: self.stored_revision().await?,
        };
        self.write_context(&context, &head, true).await
    }
    /// Pins journal changes to the revision that this transaction commits.
    pub(crate) async fn finish_admission_revision(&self) -> Result<(), Error> {
        self.conn
            .execute(
                "UPDATE secure_read_epoch SET epoch=epoch+1 WHERE id=1 AND total_changes()>?",
                [self.changes],
            )
            .await?;
        let (context, mut head) = self.admission_context().await?;
        let revision = self.stored_revision().await?;
        if head.revision != revision {
            head.revision = revision;
            self.write_context(&context, &head, false).await?;
        }
        Ok(())
    }
    async fn write_context(
        &self,
        context: &AdmissionContext,
        head: &AdmissionHead,
        insert: bool,
    ) -> Result<(), Error> {
        let key = &self.config.node;
        let values = bindings(vec![
            SqlValue::Blob(encode(context)?),
            SqlValue::Blob(sign(key, CONTEXT, context)?.to_bytes().to_vec()),
            SqlValue::Blob(encode(head)?),
            SqlValue::Blob(sign(key, HEAD, head)?.to_bytes().to_vec()),
        ]);
        let sql = match insert {
            true => "INSERT INTO secure_admission_context VALUES(1,?,?,?,?)",
            false => {
                "UPDATE secure_admission_context SET context=?,signature=?,head=?,head_signature=? WHERE id=1"
            }
        };
        self.conn.execute(sql, values).await?;
        Ok(())
    }
    /// The verified context and head: canonical, signed by this file's
    /// node and bound to its lineage and committed revision.
    pub(in crate::replica) async fn admission_context(
        &self,
    ) -> Result<(AdmissionContext, AdmissionHead), Error> {
        let records = rows(
            &self.conn,
            "SELECT context,signature,head,head_signature FROM secure_admission_context WHERE id=1",
        )
        .await?;
        let Some(
            [
                SqlValue::Blob(context),
                SqlValue::Blob(signature),
                SqlValue::Blob(head),
                SqlValue::Blob(head_signature),
            ],
        ) = records.first().map(Vec::as_slice)
        else {
            return Err(corrupt("context is missing"));
        };
        let context: AdmissionContext = canonical(context)?;
        let head: AdmissionHead = canonical(head)?;
        if context.version != VERSION
            || head.version != VERSION
            || context.node != self.config.node.public_key()
            || context.publisher != self.config.publisher
            || head.lineage != context.lineage
        {
            return Err(corrupt("context names another file"));
        }
        verify(context.node, CONTEXT, &context, &signature_of(signature)?)?;
        verify(context.node, HEAD, &head, &signature_of(head_signature)?)?;
        Ok((context, head))
    }
    /// Open's check: the head covers exactly the stored entries, each cut
    /// matches the predecessors and its stored chain, and the head is no
    /// newer than the committed revision.
    pub(in crate::replica) async fn verify_admission_head(&self) -> Result<(), Error> {
        let (context, head) = self.admission_context().await?;
        let predecessors = rows(
            &self.conn,
            "SELECT node FROM secure_predecessors ORDER BY rowid",
        )
        .await?;
        if predecessors.len() != context.cuts.len()
            || predecessors.iter().zip(&context.cuts).any(|(row, cut)| {
                !matches!(row.as_slice(), [SqlValue::Blob(node)] if node.as_slice() == cut.node.as_bytes())
            })
        {
            return Err(corrupt("cuts differ from the predecessors"));
        }
        let count = match rows(
            &self.conn,
            "SELECT MAX(entry) FROM secure_admission_entries",
        )
        .await?
        .first()
        .map(Vec::as_slice)
        {
            Some([SqlValue::Integer(count)]) => *count as u64,
            Some([SqlValue::Null]) => 0,
            _ => return Err(corrupt("entry count")),
        };
        if count != head.count
            || stored_chain_at(&self.conn, head.count, &context).await? != head.chain
        {
            return Err(corrupt("head does not cover the stored entries"));
        }
        let mut low = 0;
        for cut in &context.cuts {
            if cut.count < low
                || cut.count > head.count
                || stored_chain_at(&self.conn, cut.count, &context).await? != cut.chain
            {
                return Err(corrupt("cut does not match the stored entries"));
            }
            let cut_head = AdmissionHead {
                version: VERSION,
                lineage: cut.lineage,
                count: cut.count,
                chain: cut.chain,
                revision: cut.revision,
            };
            verify(cut.node, HEAD, &cut_head, &cut.head_signature)?;
            low = cut.count;
        }
        if head.revision > self.stored_revision().await? {
            return Err(corrupt("head is newer than the file"));
        }
        Ok(())
    }

    /// Appends `kind` signed by this node, with its derived claims, and
    /// re-signs the head, inside the caller's transaction. Returns its index.
    pub(in crate::replica) async fn append_admission(&self, kind: EntryKind) -> Result<u64, Error> {
        match &kind {
            EntryKind::Frame(receipt) => {
                check_receipt_shape(receipt)?;
                if let Some((index, held)) = self.receipt_of(receipt.frame).await? {
                    return if held == *receipt {
                        Ok(index)
                    } else {
                        Err(corrupt("frame receipt changed"))
                    };
                }
            }
            EntryKind::Restoration(grant) => {
                if let Some((index, held)) = self
                    .restoration_of(grant.receipt, grant.ordinal, grant.frame)
                    .await?
                {
                    return if held == *grant {
                        Ok(index)
                    } else {
                        Err(corrupt("restoration changed"))
                    };
                }
            }
            EntryKind::CarryObservation(observation) => {
                if let Some(held) = self
                    .carry_observation(observation.receipt, observation.ordinal, observation.frame)
                    .await?
                {
                    if held.identity != observation.identity
                        || held.provenance != observation.provenance
                        || held.signer != observation.signer
                        || held.allocation != observation.allocation
                    {
                        return Err(corrupt("carry observation changed"));
                    }
                    let records = rows_with(
                        &self.conn,
                        "SELECT entry FROM secure_admission_carries WHERE receipt=? AND ordinal=?",
                        vec![
                            SqlValue::Integer(observation.receipt as i64),
                            SqlValue::Integer(i64::from(observation.ordinal)),
                        ],
                    )
                    .await?;
                    let Some([SqlValue::Integer(index)]) = records.first().map(Vec::as_slice)
                    else {
                        return Err(corrupt("carry observation lookup missing"));
                    };
                    return Ok(*index as u64);
                }
            }
        }
        let (context, mut head) = self.admission_context().await?;
        let index = head
            .count
            .checked_add(1)
            .filter(|index| i64::try_from(*index).is_ok())
            .ok_or_else(|| denied("admission journal exhausted"))?;
        let entry = AdmissionEntry {
            version: VERSION,
            index,
            kind,
        };
        let bytes = encode(&entry)?;
        let signature = sign(&self.config.node, ENTRY, &(context.lineage, &entry))?;
        let chain = link(head.chain, &bytes);
        let claims = self.entry_claims(&entry).await?;
        let (scope, frame, kind) = entry_columns(&self.conn, &entry).await?;
        self.conn
            .execute(
                "INSERT INTO secure_admission_entries VALUES(?,?,?,?,?,?,?)",
                bindings(vec![
                    SqlValue::Integer(index as i64),
                    SqlValue::Blob(scope),
                    SqlValue::Blob(frame),
                    SqlValue::Integer(kind),
                    SqlValue::Blob(bytes),
                    SqlValue::Blob(signature.to_bytes().to_vec()),
                    SqlValue::Blob(chain.to_vec()),
                ]),
            )
            .await?;
        for claim in claims {
            self.insert_claim(claim).await?;
        }
        if let EntryKind::CarryObservation(observation) = &entry.kind {
            self.conn
                .execute(
                    "INSERT INTO secure_admission_carries VALUES(?,?,?)",
                    bindings(vec![
                        SqlValue::Integer(observation.receipt as i64),
                        SqlValue::Integer(i64::from(observation.ordinal)),
                        SqlValue::Integer(index as i64),
                    ]),
                )
                .await?;
        }
        head.count = index;
        head.chain = chain;
        head.revision = self.stored_revision().await?;
        self.write_context(&context, &head, false).await?;
        Ok(index)
    }
    /// The claims an entry derives: an original assignment per created or
    /// restored birth, an observation per carried one.
    async fn entry_claims(&self, entry: &AdmissionEntry) -> Result<Vec<DerivedClaim>, Error> {
        let mut claims = Vec::new();
        match &entry.kind {
            EntryKind::Frame(receipt) => {
                let ReceiptAllocation::Bound(expected) = receipt.allocation else {
                    return Ok(claims);
                };
                let (allocation, actual) = self.bound_allocation(receipt.scope).await?;
                if expected != actual {
                    return Err(corrupt("receipt allocation differs"));
                }
                for birth in &receipt.births {
                    match &birth.disposition {
                        Disposition::Created {
                            identity,
                            provenance,
                        } => claims.push((
                            allocation,
                            identity.integer(),
                            0,
                            *provenance,
                            entry.index,
                            birth.ordinal,
                        )),
                        Disposition::Carried {
                            identity,
                            provenance,
                            ..
                        } => claims.push((
                            allocation,
                            identity.integer(),
                            1,
                            *provenance,
                            entry.index,
                            birth.ordinal,
                        )),
                        Disposition::Consumed { .. } | Disposition::Filtered => {}
                    }
                }
            }
            EntryKind::Restoration(restoration) => {
                let (_, allocation) = self
                    .continuation_parent(
                        entry.index,
                        restoration.receipt,
                        restoration.frame,
                        restoration.ordinal,
                        restoration.allocation,
                    )
                    .await?;
                claims.push((
                    allocation,
                    restoration.identity.integer(),
                    0,
                    restoration.provenance,
                    entry.index,
                    restoration.ordinal,
                ));
            }
            EntryKind::CarryObservation(observation) => {
                let (_, allocation) = self
                    .continuation_parent(
                        entry.index,
                        observation.receipt,
                        observation.frame,
                        observation.ordinal,
                        observation.allocation,
                    )
                    .await?;
                claims.push((
                    allocation,
                    observation.identity.integer(),
                    1,
                    observation.provenance,
                    entry.index,
                    observation.ordinal,
                ));
            }
        }
        Ok(claims)
    }
    async fn continuation_parent(
        &self,
        index: u64,
        parent: u64,
        frame: Hash,
        ordinal: u8,
        allocation: ResourceScope,
    ) -> Result<(FrameReceipt, i64), Error> {
        if parent >= index {
            return Err(corrupt("continuation does not follow its receipt"));
        }
        let receipt = self.verified_receipt_at(parent).await?;
        if receipt.frame != frame
            || !receipt.births.iter().any(|birth| {
                birth.ordinal == ordinal && matches!(birth.disposition, Disposition::Filtered)
            })
        {
            return Err(corrupt("continuation does not name a filtered birth"));
        }
        let (id, bound) = self.bound_allocation(receipt.scope).await?;
        if bound != allocation
            || matches!(receipt.allocation, ReceiptAllocation::Bound(expected) if expected != allocation)
        {
            return Err(corrupt("continuation allocation differs"));
        }
        Ok((receipt, id))
    }
    async fn restoration_of(
        &self,
        parent: u64,
        ordinal: u8,
        frame: Hash,
    ) -> Result<Option<(u64, Restoration)>, Error> {
        let mut result = None;
        for record in rows_with(
            &self.conn,
            "SELECT entry FROM secure_admission_entries WHERE frame=? AND kind=1",
            vec![SqlValue::Blob(frame.as_bytes().to_vec())],
        )
        .await?
        {
            let [SqlValue::Integer(index)] = record.as_slice() else {
                return Err(corrupt("restoration index"));
            };
            let EntryKind::Restoration(grant) = self.verified_entry(*index as u64).await?.kind
            else {
                return Err(corrupt("restoration kind"));
            };
            if grant.receipt == parent && grant.ordinal == ordinal {
                if result.is_some() {
                    return Err(corrupt("duplicate restoration"));
                }
                result = Some((*index as u64, grant));
            }
        }
        Ok(result)
    }
    async fn carry_observation(
        &self,
        parent: u64,
        ordinal: u8,
        frame: Hash,
    ) -> Result<Option<CarryObservation>, Error> {
        let records = rows_with(
            &self.conn,
            "SELECT entry FROM secure_admission_entries WHERE frame=? AND kind=2",
            vec![SqlValue::Blob(frame.as_bytes().to_vec())],
        )
        .await?;
        let mut result = None;
        for record in records {
            let [SqlValue::Integer(index)] = record.as_slice() else {
                return Err(corrupt("carry observation index"));
            };
            let EntryKind::CarryObservation(observation) =
                self.verified_entry(*index as u64).await?.kind
            else {
                return Err(corrupt("carry observation kind"));
            };
            let derived = rows_with(
                &self.conn,
                "SELECT entry FROM secure_admission_carries WHERE receipt=? AND ordinal=?",
                vec![
                    SqlValue::Integer(observation.receipt as i64),
                    SqlValue::Integer(i64::from(observation.ordinal)),
                ],
            )
            .await?;
            if derived != vec![vec![SqlValue::Integer(*index)]] {
                return Err(corrupt("carry observation lookup differs"));
            }
            if observation.receipt == parent && observation.ordinal == ordinal {
                if result.is_some() {
                    return Err(corrupt("duplicate carry observation"));
                }
                result = Some(observation);
            }
        }
        let lookup = rows_with(
            &self.conn,
            "SELECT entry FROM secure_admission_carries WHERE receipt=? AND ordinal=?",
            vec![
                SqlValue::Integer(parent as i64),
                SqlValue::Integer(i64::from(ordinal)),
            ],
        )
        .await?;
        if result.is_none() && !lookup.is_empty() {
            return Err(corrupt("dangling carry observation"));
        }
        Ok(result)
    }
    async fn insert_claim(
        &self,
        (allocation, identity, kind, provenance, entry, ordinal): (
            i64,
            i64,
            u8,
            Commitment,
            u64,
            u8,
        ),
    ) -> Result<(), Error> {
        // An observation may repeat; a second original assignment may not.
        if kind == 0 && !rows_with(&self.conn,
            "SELECT entry FROM secure_admission_claims WHERE allocation=? AND identity=? AND kind=0",
            vec![SqlValue::Integer(allocation), SqlValue::Integer(identity)]).await?.is_empty()
        { return Err(corrupt("a second original assignment of one identity")); }
        let sql = match kind {
            0 => "INSERT INTO secure_admission_claims VALUES(?,?,?,?,?,?)",
            _ => "INSERT OR IGNORE INTO secure_admission_claims VALUES(?,?,?,?,?,?)",
        };
        self.conn
            .execute(
                sql,
                bindings(vec![
                    SqlValue::Integer(allocation),
                    SqlValue::Integer(identity),
                    SqlValue::Integer(i64::from(kind)),
                    SqlValue::Blob(provenance.to_vec()),
                    SqlValue::Integer(entry as i64),
                    SqlValue::Integer(i64::from(ordinal)),
                ]),
            )
            .await?;
        Ok(())
    }
    /// Entry `index`, verified in full before any decision uses it: its
    /// signature under the lineage and node of its range, canonical bytes,
    /// its link to the previous entry and its derived columns.
    pub(in crate::replica) async fn verified_entry(
        &self,
        index: u64,
    ) -> Result<AdmissionEntry, Error> {
        let (context, head) = self.admission_context().await?;
        if index == 0 || index > head.count {
            return Err(corrupt("entry beyond the head"));
        }
        verify_entry_with(&self.conn, &context, index).await
    }

    async fn verified_receipt_at(&self, index: u64) -> Result<FrameReceipt, Error> {
        match self.verified_entry(index).await?.kind {
            EntryKind::Frame(receipt) => Ok(receipt),
            EntryKind::Restoration(_) | EntryKind::CarryObservation(_) => {
                Err(corrupt("continuation names a continuation"))
            }
        }
    }
    /// The verified receipt of `frame`, with its index, if this file admitted it.
    pub(in crate::replica) async fn receipt_of(
        &self,
        frame: Hash,
    ) -> Result<Option<(u64, FrameReceipt)>, Error> {
        let records = rows_with(
            &self.conn,
            "SELECT entry FROM secure_admission_entries WHERE frame=? AND kind=0",
            vec![SqlValue::Blob(frame.as_bytes().to_vec())],
        )
        .await?;
        let Some([SqlValue::Integer(index)]) = records.first().map(Vec::as_slice) else {
            return Ok(None);
        };
        let index = *index as u64;
        let receipt = self.verified_receipt_at(index).await?;
        if receipt.frame != frame {
            return Err(corrupt("receipt names another frame"));
        }
        Ok(Some((index, receipt)))
    }
    /// Every claim on `identity` of allocation `allocation`, each verified
    /// against the entry it names.
    pub(in crate::replica) async fn claims_on(
        &self,
        allocation: i64,
        identity: rocky_core::RowIdentity,
    ) -> Result<Vec<Claim>, Error> {
        self.claims_on_frame(allocation, identity, &mut FrameClaims::default())
            .await
    }
    async fn claims_on_frame(
        &self,
        allocation: i64,
        identity: rocky_core::RowIdentity,
        verified: &mut FrameClaims,
    ) -> Result<Vec<Claim>, Error> {
        let mut claims = Vec::new();
        for record in rows_with(
            &self.conn,
            "SELECT kind,provenance,entry,ordinal FROM secure_admission_claims WHERE allocation=? AND identity=?",
            vec![
                SqlValue::Integer(allocation),
                SqlValue::Integer(identity.integer()),
            ],
        )
        .await?
        {
            let [
                SqlValue::Integer(kind),
                SqlValue::Blob(provenance),
                SqlValue::Integer(entry),
                SqlValue::Integer(ordinal),
            ] = record.as_slice()
            else {
                return Err(corrupt("claim"));
            };
            let claim = Claim {
                kind: u8::try_from(*kind).map_err(|_| corrupt("claim kind"))?,
                provenance: row_of(provenance)?,
                entry: *entry as u64,
                ordinal: u8::try_from(*ordinal).map_err(|_| corrupt("claim ordinal"))?,
            };
            // SQL claims are read and compared every time. Only their immutable
            // signed source entry is shared across this frame's births.
            let derived = match verified.entries.entry(claim.entry) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => entry.insert(
                    self.entry_claims(&self.verified_entry(claim.entry).await?)
                        .await?,
                ),
            };
            if !derived.iter().any(|(a, i, k, p, e, o)| {
                *a == allocation
                    && *i == identity.integer()
                    && *k == claim.kind
                    && *p == claim.provenance
                    && *e == claim.entry
                    && *o == claim.ordinal
            }) {
                return Err(corrupt("claim differs from its entry"));
            }
            claims.push(claim);
        }
        Ok(claims)
    }
    /// The full audit: every signature and link, contiguous indices, the
    /// claim index re-derived exactly, and every claim and consumed
    /// identity dominated by the permanent marks.
    pub(in crate::replica) async fn audit_admission(&self) -> Result<(), Error> {
        self.verify_admission_head().await?;
        let (context, head) = self.admission_context().await?;
        let mut derived = BTreeMap::new();
        let mut carried = BTreeSet::new();
        let mut frames = BTreeSet::new();
        let mut originals = BTreeSet::new();
        let mut carry_ordinals = BTreeSet::new();
        for index in 1..=head.count {
            let entry = verify_entry_with(&self.conn, &context, index).await?;
            match &entry.kind {
                EntryKind::Frame(receipt) => {
                    if !frames.insert(receipt.frame) {
                        return Err(corrupt("duplicate frame receipt"));
                    }
                    self.audit_receipt(receipt).await?;
                }
                EntryKind::Restoration(grant) => {
                    let (parent, _) = self
                        .continuation_parent(
                            index,
                            grant.receipt,
                            grant.frame,
                            grant.ordinal,
                            grant.allocation,
                        )
                        .await?;
                    self.check_dominance(
                        parent.scope,
                        grant.allocation,
                        grant.identity,
                        parent.signer,
                    )
                    .await?;
                    self.check_own_dominance(parent.scope, grant.identity)
                        .await?;
                }
                EntryKind::CarryObservation(observation) => {
                    let (parent, _) = self
                        .continuation_parent(
                            index,
                            observation.receipt,
                            observation.frame,
                            observation.ordinal,
                            observation.allocation,
                        )
                        .await?;
                    self.check_dominance(
                        parent.scope,
                        observation.allocation,
                        observation.identity,
                        observation.signer,
                    )
                    .await?;
                    if !carry_ordinals.insert((observation.receipt, observation.ordinal))
                        || !carried.insert((observation.receipt, observation.ordinal, index))
                    {
                        return Err(corrupt("duplicate carry observation"));
                    }
                }
            }
            for (a, i, k, p, e, o) in self.entry_claims(&entry).await? {
                if k == 0 && !originals.insert((a, i)) {
                    return Err(corrupt("duplicate original assignment"));
                }
                derived.entry((a, i, k, p)).or_insert((e, o));
            }
        }
        let derived: BTreeSet<_> = derived
            .into_iter()
            .map(|((a, i, k, p), (e, o))| (a, i, k, p, e, o))
            .collect();
        let mut stored = BTreeSet::new();
        for record in rows(
            &self.conn,
            "SELECT allocation,identity,kind,provenance,entry,ordinal FROM secure_admission_claims",
        )
        .await?
        {
            let [
                SqlValue::Integer(allocation),
                SqlValue::Integer(identity),
                SqlValue::Integer(kind),
                SqlValue::Blob(provenance),
                SqlValue::Integer(entry),
                SqlValue::Integer(ordinal),
            ] = record.as_slice()
            else {
                return Err(corrupt("claim"));
            };
            stored.insert((
                *allocation,
                *identity,
                u8::try_from(*kind).map_err(|_| corrupt("claim kind"))?,
                row_of(provenance)?,
                *entry as u64,
                u8::try_from(*ordinal).map_err(|_| corrupt("claim ordinal"))?,
            ));
        }
        if stored != derived {
            return Err(corrupt("claims differ from the entries"));
        }
        let mut stored_carries = BTreeSet::new();
        for row in rows(
            &self.conn,
            "SELECT receipt,ordinal,entry FROM secure_admission_carries",
        )
        .await?
        {
            let [
                SqlValue::Integer(receipt),
                SqlValue::Integer(ordinal),
                SqlValue::Integer(entry),
            ] = row.as_slice()
            else {
                return Err(corrupt("carry lookup"));
            };
            stored_carries.insert((
                *receipt as u64,
                u8::try_from(*ordinal).map_err(|_| corrupt("carry ordinal"))?,
                *entry as u64,
            ));
        }
        if stored_carries != carried {
            return Err(corrupt("carry lookup differs from entries"));
        }
        Ok(())
    }
    async fn check_dominance(
        &self,
        scope: ResourceScope,
        allocation: ResourceScope,
        identity: rocky_core::RowIdentity,
        signer: PublicKey,
    ) -> Result<(), Error> {
        for scope in BTreeSet::from([scope, allocation]) {
            if !self.identity_marks(scope).await?.iter().any(|mark| {
                mark.author == identity.author()
                    && mark.signer == signer
                    && mark.sequence >= identity.sequence()
            }) {
                return Err(corrupt("identity exceeds permanent marks"));
            }
        }
        Ok(())
    }
    async fn check_own_dominance(
        &self,
        scope: ResourceScope,
        identity: rocky_core::RowIdentity,
    ) -> Result<(), Error> {
        if !self
            .own_marks(scope)
            .await?
            .get(&identity.author())
            .is_some_and(|own| *own >= identity.sequence())
        {
            return Err(corrupt("identity exceeds its own-birth floor"));
        }
        Ok(())
    }
    /// A receipt's identities stay below the permanent marks, a filtered
    /// one carries its floor, and its derived allocation binding holds.
    async fn audit_receipt(&self, receipt: &FrameReceipt) -> Result<(), Error> {
        if receipt.floor.is_some() != receipt.target.is_some() {
            return Err(corrupt("floor and target disagree"));
        }
        if let ReceiptAllocation::Bound(expected) = receipt.allocation {
            let (_, allocation) = self.bound_allocation(receipt.scope).await?;
            if expected != allocation {
                return Err(corrupt("receipt names another allocation"));
            }
        }
        let marks = self.identity_marks(receipt.scope).await?;
        let own = self.own_marks(receipt.scope).await?;
        let reaches = |author: u32, sequence: u32, signer: Option<PublicKey>| {
            marks.iter().any(|mark| {
                mark.author == author
                    && mark.sequence >= sequence
                    && signer.is_none_or(|signer| signer == mark.signer)
            })
        };
        if let Some(floor) = receipt.floor
            && floor > 0
            && !receipt.author.is_some_and(|author| {
                reaches(author, floor, Some(receipt.signer))
                    && own.get(&author).is_some_and(|own| *own >= floor)
            })
        {
            return Err(corrupt("floor above own-birth mark"));
        }
        for birth in &receipt.births {
            match &birth.disposition {
                Disposition::Created { identity, .. } | Disposition::Consumed { identity } => {
                    self.check_own_dominance(receipt.scope, *identity).await?;
                    if !reaches(identity.author(), identity.sequence(), Some(receipt.signer)) {
                        return Err(corrupt("an admitted identity above the permanent mark"));
                    }
                    let ReceiptAllocation::Bound(allocation) = receipt.allocation else {
                        return Err(corrupt("identity allocation missing"));
                    };
                    self.check_dominance(receipt.scope, allocation, *identity, receipt.signer)
                        .await?;
                }
                Disposition::Carried {
                    identity, signer, ..
                } => {
                    if !reaches(identity.author(), identity.sequence(), Some(*signer)) {
                        return Err(corrupt("a carried identity above the permanent mark"));
                    }
                    let ReceiptAllocation::Bound(allocation) = receipt.allocation else {
                        return Err(corrupt("carry allocation missing"));
                    };
                    self.check_dominance(receipt.scope, allocation, *identity, *signer)
                        .await?;
                }
                Disposition::Filtered => {}
            }
        }
        Ok(())
    }
}

fn check_receipt_shape(receipt: &FrameReceipt) -> Result<(), Error> {
    if receipt.writes == 0
        || receipt.writes > 32
        || receipt.births.is_empty()
        || receipt
            .births
            .iter()
            .any(|birth| birth.ordinal >= receipt.writes)
        || receipt
            .births
            .windows(2)
            .any(|pair| pair[0].ordinal >= pair[1].ordinal)
        || receipt.floor.is_some() != receipt.target.is_some()
        || receipt.target.is_some()
            != receipt
                .births
                .iter()
                .any(|birth| matches!(birth.disposition, Disposition::Filtered))
        || receipt.target.is_some()
            && !receipt
                .births
                .iter()
                .all(|birth| matches!(birth.disposition, Disposition::Filtered))
        || matches!(receipt.allocation, ReceiptAllocation::Unresolved) && receipt.target.is_none()
    {
        return Err(corrupt("receipt shape"));
    }
    Ok(())
}

/// The derived columns of an entry: its scope, frame and kind.
async fn entry_columns(
    conn: &ScopedConnection,
    entry: &AdmissionEntry,
) -> Result<(Vec<u8>, Vec<u8>, i64), Error> {
    Ok(match &entry.kind {
        EntryKind::Frame(receipt) => (
            encode(&receipt.scope)?,
            receipt.frame.as_bytes().to_vec(),
            0,
        ),
        EntryKind::Restoration(restoration) => {
            (Vec::new(), restoration.frame.as_bytes().to_vec(), 1)
        }
        EntryKind::CarryObservation(observation) => {
            if observation.receipt >= entry.index {
                return Err(corrupt("carry parent is not earlier"));
            }
            let records = rows_with(
                conn,
                "SELECT bytes FROM secure_admission_entries WHERE entry=?",
                vec![SqlValue::Integer(observation.receipt as i64)],
            )
            .await?;
            let Some([SqlValue::Blob(bytes)]) = records.first().map(Vec::as_slice) else {
                return Err(corrupt("carry parent missing"));
            };
            let parent: AdmissionEntry = canonical(bytes)?;
            let EntryKind::Frame(receipt) = parent.kind else {
                return Err(corrupt("carry parent is not a frame"));
            };
            if receipt.frame != observation.frame {
                return Err(corrupt("carry parent frame differs"));
            }
            (
                encode(&receipt.scope)?,
                observation.frame.as_bytes().to_vec(),
                2,
            )
        }
    })
}

async fn rows_with(
    conn: &ScopedConnection,
    sql: &str,
    values: Vec<SqlValue>,
) -> Result<Vec<Vec<SqlValue>>, Error> {
    collect_rows(conn.query(sql, bindings(values)).await?).await
}

/// Called only inside the raw restore-adoption transaction, before rebinding
/// metadata or adding the predecessor. Old evidence gets a finite signed cut.
pub(in crate::replica) async fn adopt_admission(
    conn: &ScopedConnection,
    publisher: PublicKey,
    predecessor: PublicKey,
    node: &PrivateKey,
) -> Result<(), Error> {
    let records = rows(
        conn,
        "SELECT context,signature,head,head_signature FROM secure_admission_context WHERE id=1",
    )
    .await?;
    let Some(
        [
            SqlValue::Blob(context),
            SqlValue::Blob(signature),
            SqlValue::Blob(head),
            SqlValue::Blob(head_signature),
        ],
    ) = records.first().map(Vec::as_slice)
    else {
        return Err(corrupt("context is missing"));
    };
    let mut context: AdmissionContext = canonical(context)?;
    let head: AdmissionHead = canonical(head)?;
    let head_signature = signature_of(head_signature)?;
    if context.version != VERSION
        || head.version != VERSION
        || context.node != predecessor
        || context.publisher != publisher
        || head.lineage != context.lineage
    {
        return Err(corrupt("context is not the predecessor's"));
    }
    verify(predecessor, CONTEXT, &context, &signature_of(signature)?)?;
    verify(predecessor, HEAD, &head, &head_signature)?;
    let metadata = rows(conn, "SELECT revision FROM secure_metadata WHERE id=1").await?;
    let Some([SqlValue::Integer(revision)]) = metadata.first().map(Vec::as_slice) else {
        return Err(corrupt("revision"));
    };
    let count = rows(
        conn,
        "SELECT COALESCE(MAX(entry),0) FROM secure_admission_entries",
    )
    .await?;
    if head.revision > *revision as u64 || count != vec![vec![SqlValue::Integer(head.count as i64)]]
    {
        return Err(corrupt("head does not cover the copied file"));
    }
    let predecessors = rows(conn, "SELECT node FROM secure_predecessors ORDER BY rowid").await?;
    if predecessors.len() != context.cuts.len() || predecessors.iter().zip(&context.cuts).any(|(row, cut)| {
        !matches!(row.as_slice(), [SqlValue::Blob(node)] if node.as_slice() == cut.node.as_bytes())
    }) { return Err(corrupt("cuts differ from predecessors")); }
    let mut low = 0;
    for cut in &context.cuts {
        if cut.count < low
            || cut.count > head.count
            || stored_chain_at(conn, cut.count, &context).await? != cut.chain
        {
            return Err(corrupt("predecessor cut differs"));
        }
        verify(
            cut.node,
            HEAD,
            &AdmissionHead {
                version: VERSION,
                lineage: cut.lineage,
                count: cut.count,
                chain: cut.chain,
                revision: cut.revision,
            },
            &cut.head_signature,
        )?;
        low = cut.count;
    }
    for index in 1..=head.count {
        verify_entry_with(conn, &context, index).await?;
    }
    if stored_chain_at(conn, head.count, &context).await? != head.chain {
        return Err(corrupt("copied chain differs"));
    }
    context.cuts.push(PredecessorCut {
        lineage: context.lineage,
        node: predecessor,
        count: head.count,
        chain: head.chain,
        revision: head.revision,
        head_signature,
    });
    context.lineage = rand::random();
    context.node = node.public_key();
    let head = AdmissionHead {
        lineage: context.lineage,
        revision: *revision as u64 + 1,
        ..head
    };
    conn.execute("UPDATE secure_admission_context SET context=?,signature=?,head=?,head_signature=? WHERE id=1", bindings(vec![
        SqlValue::Blob(encode(&context)?), SqlValue::Blob(sign(node, CONTEXT, &context)?.to_bytes().to_vec()),
        SqlValue::Blob(encode(&head)?), SqlValue::Blob(sign(node, HEAD, &head)?.to_bytes().to_vec()),
    ])).await?;
    Ok(())
}

async fn stored_chain_at(
    conn: &ScopedConnection,
    index: u64,
    context: &AdmissionContext,
) -> Result<Commitment, Error> {
    if index == 0 {
        return Ok(context.genesis());
    }
    match rows_with(
        conn,
        "SELECT chain FROM secure_admission_entries WHERE entry=?",
        vec![SqlValue::Integer(index as i64)],
    )
    .await?
    .first()
    .map(Vec::as_slice)
    {
        Some([SqlValue::Blob(chain)]) => row_of(chain),
        _ => Err(corrupt("chain value is missing")),
    }
}
async fn verify_entry_with(
    conn: &ScopedConnection,
    context: &AdmissionContext,
    index: u64,
) -> Result<AdmissionEntry, Error> {
    let records = rows_with(
        conn,
        "SELECT scope,frame,kind,bytes,signature,chain FROM secure_admission_entries WHERE entry=?",
        vec![SqlValue::Integer(index as i64)],
    )
    .await?;
    let Some(
        [
            SqlValue::Blob(scope),
            SqlValue::Blob(frame),
            SqlValue::Integer(kind),
            SqlValue::Blob(bytes),
            SqlValue::Blob(signature),
            SqlValue::Blob(chain),
        ],
    ) = records.first().map(Vec::as_slice)
    else {
        return Err(corrupt("entry is missing"));
    };
    let entry: AdmissionEntry = canonical(bytes)?;
    if entry.version != VERSION || entry.index != index {
        return Err(corrupt("entry version or index"));
    }
    if let EntryKind::Frame(receipt) = &entry.kind {
        check_receipt_shape(receipt)?;
    }
    let (lineage, node) = context.signer_of(index);
    verify(node, ENTRY, &(lineage, &entry), &signature_of(signature)?)?;
    let previous = stored_chain_at(conn, index - 1, context).await?;
    if link(previous, bytes) != row_of(chain)? {
        return Err(corrupt("chain link is broken"));
    }
    let (derived_scope, derived_frame, derived_kind) = entry_columns(conn, &entry).await?;
    if derived_scope != *scope || derived_frame != *frame || derived_kind != *kind {
        return Err(corrupt("derived columns differ"));
    }
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The superseded receipt shape with a per-allocation floor vector.
    #[derive(Serialize)]
    struct VectorFloor {
        concrete: u32,
        allocations: Vec<(ResourceScope, u32)>,
    }
    #[derive(Serialize)]
    struct VectorReceipt {
        frame: Hash,
        signer: PublicKey,
        author: Option<u32>,
        scope: ResourceScope,
        allocation: ReceiptAllocation,
        sequence: u64,
        author_sequence: u64,
        tip: TipId,
        #[serde(with = "serde_bytes")]
        schema: Commitment,
        target: Option<TipId>,
        floor: Option<VectorFloor>,
        writes: u8,
        births: Vec<Birth>,
    }

    #[test]
    fn a_receipt_has_one_scalar_floor_encoding() {
        let scope = ResourceScope {
            domain: rocky_core::Scope {
                mesh: rocky_core::MeshId([1; 16]),
                app: rocky_core::AppId([2; 16]),
                domain: rocky_core::DomainId([3; 16]),
            },
            encryption: [4; 32],
            table: [5; 32],
        };
        let receipt = FrameReceipt {
            frame: Hash::new(b"frame"),
            signer: PrivateKey::from_bytes(&[6; 32]).public_key(),
            author: Some(1),
            scope,
            allocation: ReceiptAllocation::Unresolved,
            sequence: 0,
            author_sequence: 0,
            tip: TipId([7; 32]),
            schema: [8; 32],
            target: Some(TipId([9; 32])),
            floor: Some(3),
            writes: 1,
            births: vec![Birth {
                ordinal: 0,
                disposition: Disposition::Filtered,
            }],
        };
        let bytes = encode(&receipt).unwrap();
        assert_eq!(canonical::<FrameReceipt>(&bytes).unwrap(), receipt);
        check_receipt_shape(&receipt).unwrap();
        let vector = VectorReceipt {
            frame: receipt.frame,
            signer: receipt.signer,
            author: receipt.author,
            scope,
            allocation: ReceiptAllocation::Unresolved,
            sequence: 0,
            author_sequence: 0,
            tip: receipt.tip,
            schema: receipt.schema,
            target: receipt.target,
            floor: Some(VectorFloor {
                concrete: 3,
                allocations: vec![(scope, 8)],
            }),
            writes: 1,
            births: receipt.births.clone(),
        };
        assert!(matches!(
            canonical::<FrameReceipt>(&encode(&vector).unwrap()),
            Err(Error::Corrupt(_))
        ));
        for shape in [
            FrameReceipt {
                floor: None,
                ..receipt.clone()
            },
            FrameReceipt {
                target: None,
                ..receipt.clone()
            },
        ] {
            assert!(check_receipt_shape(&shape).is_err());
        }
    }
}
