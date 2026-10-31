//! Move provenance and field ordering, independent of source-key availability.
use super::*;
use serde::{Deserialize, Serialize};

mod compact;

struct VerifiedBindings<'a> {
    chain: &'a [rocky_credentials::AuthorBinding],
    publisher: PublicKey,
    table: Commitment,
    author: u32,
    signer: PublicKey,
}

/// Only the last historical chain success in one materialization attempt.
#[derive(Default)]
pub(super) struct FrameBindings<'a> {
    last: Option<VerifiedBindings<'a>>,
}

/// The digest a stored proof names an encoded set of author bindings by.
pub(super) fn bindings_digest(encoded: &[u8]) -> Commitment {
    rocky_core::commitment("rocky.author-bindings.v1", encoded)
}

pub(super) fn header_digest(header: &[u8]) -> Commitment {
    rocky_core::commitment("rocky.creation-header.v1", header)
}

/// A creation proof as a row record stores it. The author bindings its
/// signature covers repeat on every row an author creates, so they are
/// stored once in `secure_author_bindings` and named here by digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredProof {
    version: u8,
    #[serde(with = "serde_bytes")]
    manifest: Commitment,
    #[serde(with = "serde_bytes")]
    table: Commitment,
    id: rocky_core::RowIdentity,
    #[serde(with = "serde_bytes")]
    provenance: Commitment,
    stamp: Stamp,
    #[serde(with = "serde_bytes")]
    bindings: Commitment,
    signer: super::AuthorKey,
    #[serde(with = "serde_bytes")]
    header: Commitment,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Origin {
    version: u8,
    #[serde(with = "serde_bytes")]
    manifest: Commitment,
    #[serde(with = "serde_bytes")]
    table: Commitment,
    stamp: Stamp,
    #[serde(with = "serde_bytes")]
    bindings: Commitment,
    signer: super::AuthorKey,
    #[serde(with = "serde_bytes")]
    header: Commitment,
}
impl StoredProof {
    pub(super) fn origin(&self) -> Origin {
        Origin {
            version: self.version,
            manifest: self.manifest,
            table: self.table,
            stamp: self.stamp.clone(),
            bindings: self.bindings,
            signer: self.signer,
            header: self.header,
        }
    }
    pub(super) fn from_origin(
        origin: Origin,
        id: rocky_core::RowIdentity,
        provenance: Commitment,
    ) -> Self {
        Self {
            version: origin.version,
            manifest: origin.manifest,
            table: origin.table,
            id,
            provenance,
            stamp: origin.stamp,
            bindings: origin.bindings,
            signer: origin.signer,
            header: origin.header,
        }
    }
    pub(super) fn identity(&self) -> rocky_core::RowIdentity {
        self.id
    }

    pub(super) fn stamp(&self) -> &Stamp {
        &self.stamp
    }
    pub(super) fn header(&self) -> Commitment {
        self.header
    }
    pub(super) fn bindings(&self) -> Commitment {
        self.bindings
    }
    /// The original creation statement this proof names; see [`provenance`].
    pub(crate) fn provenance(&self) -> Result<Commitment, Error> {
        let calculated = provenance(
            self.version,
            self.manifest,
            self.table,
            self.id,
            &self.stamp,
            self.bindings,
        )?;
        if calculated != self.provenance {
            return Err(denied("stored creation provenance mismatch"));
        }
        Ok(self.provenance)
    }
}
/// A commitment to an original creation statement: what a row's identity
/// was first created as, whichever frame carries the proof now. Neither the
/// signature nor a transport hash enters it.
fn provenance(
    version: u8,
    manifest: Commitment,
    table: Commitment,
    id: rocky_core::RowIdentity,
    stamp: &Stamp,
    bindings: Commitment,
) -> Result<Commitment, Error> {
    if version != 2 {
        return Err(denied("unsupported creation statement version"));
    }
    Ok(
        rocky_core::CreationStatement::derived(manifest, table, id, stamp.clone(), bindings)
            .commitment(),
    )
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreationProof {
    version: u8,
    #[serde(with = "serde_bytes")]
    manifest: Commitment,
    #[serde(with = "serde_bytes")]
    table: Commitment,
    id: rocky_core::RowIdentity,
    #[serde(with = "serde_bytes")]
    provenance: Commitment,
    stamp: Stamp,
    bindings: Vec<rocky_credentials::AuthorBinding>,
    signer: super::AuthorKey,
    #[serde(with = "serde_bytes")]
    header: Vec<u8>,
}
impl CreationProof {
    pub(super) fn statement(
        manifest: Commitment,
        table: Commitment,
        id: rocky_core::RowIdentity,
        stamp: Stamp,
        author: &identity::NodeAuthor,
    ) -> Result<Self, Error> {
        let bindings: Vec<_> = author
            .credentials
            .0
            .iter()
            .map(|link| link.author_binding.clone())
            .collect();
        let provenance = provenance(
            2,
            manifest,
            table,
            id,
            &stamp,
            bindings_digest(&encode(&bindings)?),
        )?;
        Ok(Self {
            version: 2,
            manifest,
            table,
            id,
            provenance,
            stamp,
            bindings,
            signer: author.key.public_key().into(),
            header: Vec::new(),
        })
    }
    pub(crate) fn derived(
        manifest: Commitment,
        id: rocky_core::RowIdentity,
        frame: &EncryptedFrame,
    ) -> Result<Self, Error> {
        let header = &frame.operation_ref()?.header;
        let table = header.extensions.scope.table;
        let stamp = Stamp {
            clock: header.timestamp,
            author: header
                .extensions
                .author
                .ok_or_else(|| denied("numeric birth requires an author"))?,
            sequence: header.extensions.author_sequence,
        };
        let bindings: Vec<_> = frame
            .chain()?
            .credentials()
            .0
            .iter()
            .map(|link| link.author_binding.clone())
            .collect();
        let provenance = provenance(
            2,
            manifest,
            table,
            id,
            &stamp,
            bindings_digest(&encode(&bindings)?),
        )?;
        Ok(Self {
            version: 2,
            manifest,
            table,
            id,
            provenance,
            stamp,
            bindings,
            signer: header.public_key.into(),
            header: frame.header_bytes().to_vec(),
        })
    }
    #[cfg(test)]
    pub(crate) fn rebound_provenance_for_test(&self, chain: &Chain) -> Result<Commitment, Error> {
        let bindings: Vec<_> = chain
            .credentials()
            .0
            .iter()
            .map(|link| link.author_binding.clone())
            .collect();
        provenance(
            self.version,
            self.manifest,
            self.table,
            self.id,
            &self.stamp,
            bindings_digest(&encode(&bindings)?),
        )
    }
    fn authentic(&self) -> bool {
        let Ok(header) = crate::wire::verified_header(&self.header) else {
            return false;
        };
        header.public_key.as_bytes() == &self.signer.0
            && header.timestamp == self.stamp.clock
            && header.extensions.author == Some(self.stamp.author)
            && header.extensions.author_sequence == self.stamp.sequence
            && header.extensions.scope.table == self.table
            && self.provenance().is_ok_and(|provenance| {
                header
                    .extensions
                    .births
                    .iter()
                    .any(|birth| birth.as_ref() == &provenance)
            })
    }
    pub(crate) fn verify(
        &self,
        publisher: PublicKey,
        manifest: Commitment,
        table: Commitment,
        id: rocky_core::RowIdentity,
        ceiling: &Stamp,
    ) -> Result<(), Error> {
        self.verify_with_bindings(publisher, manifest, table, id, ceiling, None)
    }
    pub(super) fn verify_with_bindings<'a>(
        &'a self,
        publisher: PublicKey,
        manifest: Commitment,
        table: Commitment,
        id: rocky_core::RowIdentity,
        ceiling: &Stamp,
        mut memo: Option<&mut FrameBindings<'a>>,
    ) -> Result<(), Error> {
        if self.version != 2
            || self.manifest != manifest
            || self.table != table
            || self.id != id
            || self.stamp.author != id.author()
            || self.stamp > *ceiling
            || !self.authentic()
        {
            return Err(denied("invalid signed row creation proof"));
        }
        let signer = self.signer()?;
        let author = id.author();
        if let Some(memo) = memo.as_mut()
            && memo.last.as_ref().is_some_and(|old| {
                old.publisher == publisher
                    && old.table == table
                    && old.author == author
                    && old.signer == signer
                    && old.chain == self.bindings.as_slice()
            })
        {
            return Ok(());
        }
        rocky_credentials::AuthorBinding::verify_chain(
            &self.bindings,
            publisher,
            table,
            author,
            signer,
        )
        .map_err(credential)?;
        if let Some(memo) = memo {
            memo.last = Some(VerifiedBindings {
                chain: &self.bindings,
                publisher,
                table,
                author,
                signer,
            });
        }
        Ok(())
    }
    pub(crate) fn signer(&self) -> Result<PublicKey, Error> {
        self.signer.key()
    }
    pub(crate) fn stamp(&self) -> &Stamp {
        &self.stamp
    }
    pub(super) fn manifest(&self) -> Commitment {
        self.manifest
    }
    /// The original creation statement this proof names.
    fn computed_provenance(&self) -> Result<Commitment, Error> {
        provenance(
            self.version,
            self.manifest,
            self.table,
            self.id,
            &self.stamp,
            bindings_digest(&encode(&self.bindings)?),
        )
    }
    pub(crate) fn provenance(&self) -> Result<Commitment, Error> {
        if self.computed_provenance()? != self.provenance {
            return Err(denied("creation provenance mismatch"));
        }
        Ok(self.provenance)
    }
    /// The proof as a row record stores it.
    pub(super) fn stored(&self) -> Result<StoredProof, Error> {
        Ok(StoredProof {
            version: self.version,
            manifest: self.manifest,
            table: self.table,
            id: self.id,
            provenance: self.provenance,
            stamp: self.stamp.clone(),
            bindings: bindings_digest(&encode(&self.bindings)?),
            signer: self.signer,
            header: header_digest(&self.header),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Carried {
    pub(crate) proof: CreationProof,
    pub(crate) stamps: BTreeMap<Commitment, Stamp>,
    pub(crate) authors: stamp_authors::Authors,
    /// Present only on a destination insert; sealed with the source key.
    pub(crate) moved_from: Option<Vec<u8>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MoveSource {
    pub(super) scope: ResourceScope,
    pub(super) tuple: rocky_core::PartitionTuple,
    pub(super) creation: Hash,
    pub(super) generation: rocky_core::KeyEpoch,
    pub(super) deletion_author: PublicKey,
    pub(super) deletion_sequence: u64,
}

#[derive(Default)]
pub(super) struct FollowPass {
    pub(super) commit: u64,
    pub(super) epoch: u64,
    after: Option<(Vec<u8>, Vec<u8>)>,
    row: Option<FollowRow>,
    /// Writes to moved rows since the pass started; one may lie behind
    /// the cursor, so the pass then runs once more from the start.
    moved: Option<(Arc<crate::sqlite::Writes>, String, u64)>,
    rescan: bool,
}
struct FollowRow {
    key: (Vec<u8>, Vec<u8>),
    destination: ResourceScope,
    record: Materialized,
    identity: i64,
    proof: CreationProof,
    signer: PublicKey,
    link: Option<MoveSource>,
    visited: BTreeSet<ResourceScope>,
    sources: std::collections::VecDeque<MoveSource>,
    source: Option<MoveSource>,
    sequence: i64,
    candidates: BTreeMap<Commitment, (Stamp, Vec<u8>, Hash)>,
}

impl<A: RowApplication> Inner<A> {
    /// Stores the bindings of a proof a row record is about to name.
    pub(super) async fn keep_bindings(&self, proof: &CreationProof) -> Result<(), Error> {
        self.put_creation_header(&proof.header).await?;
        self.put_bindings(&encode(&proof.bindings)?).await
    }
    pub(super) async fn put_creation_header(&self, header: &[u8]) -> Result<(), Error> {
        let header = self.crypto.creation_header(header)?;
        self.put_verified_creation_header(&header).await
    }
    pub(super) async fn put_verified_creation_header(
        &self,
        header: &crypto::CreationHeader,
    ) -> Result<(), Error> {
        let signed = header.signed();
        if let Some(author) = signed.extensions.author {
            self.keep_stamp_author(signed.extensions.scope.domain, author, signed.public_key)
                .await?;
        }
        self.conn
            .execute(
                "INSERT INTO secure_creation_headers VALUES(?,?) ON CONFLICT(digest) DO NOTHING",
                [
                    header_digest(header.bytes()).to_vec(),
                    header.bytes().to_vec(),
                ],
            )
            .await?;
        Ok(())
    }
    pub(super) async fn stored_creation_header(
        &self,
        digest: Commitment,
    ) -> Result<Vec<u8>, Error> {
        let mut rows = self
            .conn
            .query(
                "SELECT header FROM secure_creation_headers WHERE digest=?",
                [digest.to_vec()],
            )
            .await?;
        let header: Vec<u8> = rows
            .next()
            .await?
            .ok_or_else(|| Error::Corrupt("creation header of a stored row".into()))?
            .get(0)?;
        if header_digest(&header) != digest {
            return Err(Error::Corrupt(
                "stored creation header digest mismatch".into(),
            ));
        }
        Ok(header)
    }
    pub(super) async fn put_bindings(&self, encoded: &[u8]) -> Result<(), Error> {
        self.conn
            .execute(
                "INSERT INTO secure_author_bindings VALUES(?,?) ON CONFLICT(digest) DO NOTHING",
                bindings(vec![
                    SqlValue::Blob(bindings_digest(encoded).to_vec()),
                    SqlValue::Blob(encoded.to_vec()),
                ]),
            )
            .await?;
        Ok(())
    }
    /// A stored set of author bindings, encoded as its digest names it.
    pub(super) async fn stored_bindings(&self, digest: Commitment) -> Result<Vec<u8>, Error> {
        let mut found = self
            .conn
            .query(
                "SELECT bindings FROM secure_author_bindings WHERE digest=?",
                [digest.to_vec()],
            )
            .await?;
        let encoded: Vec<u8> = found
            .next()
            .await?
            .ok_or_else(|| Error::Corrupt("author bindings of a stored row".into()))?
            .get(0)?;
        if bindings_digest(&encoded) != digest {
            return Err(Error::Corrupt(
                "stored author bindings digest mismatch".into(),
            ));
        }
        Ok(encoded)
    }
    /// A stored proof with its bindings, as a move carries it.
    pub(super) async fn carried_proof(&self, stored: &StoredProof) -> Result<CreationProof, Error> {
        Ok(CreationProof {
            version: stored.version,
            manifest: stored.manifest,
            table: stored.table,
            id: stored.id,
            provenance: stored.provenance,
            stamp: stored.stamp.clone(),
            bindings: decode(&self.stored_bindings(stored.bindings).await?)?,
            signer: stored.signer,
            header: self.stored_creation_header(stored.header).await?,
        })
    }
    pub(crate) fn check_carried(
        &self,
        write: &RowWrite,
        carried: &Carried,
        ceiling: &Stamp,
    ) -> Result<(), Error> {
        let id = self
            .app
            .row_identity(&write.change)
            .map_err(|error| denied(&error))?
            .ok_or_else(|| denied("carried fields require a numeric identity"))?;
        self.known(carried.proof.manifest())?;
        carried.proof.verify(
            self.config.publisher,
            carried.proof.manifest(),
            write.change.scope.table,
            id,
            ceiling,
        )?;
        let fields = write
            .change
            .after
            .as_ref()
            .ok_or_else(|| denied("cannot carry a deletion"))?;
        if carried.authors.keys().copied().collect::<BTreeSet<_>>()
            != carried.stamps.values().map(|stamp| stamp.author).collect()
        {
            return Err(denied("carried stamps require their exact signer legend"));
        }
        if carried
            .stamps
            .keys()
            .any(|field| !fields.contains_key(field))
            || carried.stamps.values().any(|stamp| stamp > ceiling)
            || (write.change.before.is_none()
                && (carried.moved_from.is_none()
                    || carried.stamps.keys().copied().collect::<BTreeSet<_>>()
                        != fields.keys().copied().collect()))
            || (write.change.before.is_some()
                && (carried.moved_from.is_some()
                    || carried.stamps.keys().copied().collect::<BTreeSet<_>>() != write.assigned))
        {
            return Err(denied("invalid carried field stamps or move link"));
        }
        if write.change.before.is_some()
            && carried
                .stamps
                .values()
                .any(|stamp| stamp.author != ceiling.author)
        {
            return Err(denied("only the original author can follow an update"));
        }
        Ok(())
    }
}

pub(super) const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS secure_move_rows(scope BLOB NOT NULL,row BLOB NOT NULL,PRIMARY KEY(scope,row)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_consumed(hash BLOB PRIMARY KEY,reason TEXT NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_followed(original BLOB NOT NULL,scope BLOB NOT NULL,field BLOB NOT NULL,PRIMARY KEY(original,scope,field)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_creation_headers(digest BLOB NOT NULL UNIQUE,header BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS secure_author_bindings(digest BLOB PRIMARY KEY,bindings BLOB NOT NULL) WITHOUT ROWID",
];
/// The moved rows each commit follows. `CROSS JOIN` keeps the few marked
/// moves as the outer loop: without it SQLite scans every stored row.
pub(crate) const MOVE_SCAN: &str = "SELECT r.scope,r.row,r.fields FROM secure_move_rows m CROSS JOIN secure_row_records r ON r.scope=m.scope AND r.row=m.row";
impl<A: RowApplication> Inner<A> {
    pub(super) async fn consume(&self, hash: Hash, reason: &str) -> Result<(), Error> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO secure_consumed VALUES(?,?)",
                bindings(vec![
                    SqlValue::Blob(hash.as_bytes().to_vec()),
                    SqlValue::Text(reason.into()),
                ]),
            )
            .await?;
        Ok(())
    }
    pub(super) async fn consumed(&self, hash: Hash) -> Result<Option<String>, Error> {
        let mut rows = self
            .conn
            .query(
                "SELECT reason FROM secure_consumed WHERE hash=?",
                [hash.as_bytes().to_vec()],
            )
            .await?;
        rows.next()
            .await?
            .map(|row| row.get::<String>(0))
            .transpose()
            .map_err(Error::from)
    }
}

impl<A: RowApplication> Inner<A> {
    fn open_move_source(
        &self,
        destination: ResourceScope,
        identity: i64,
        sealed: &[u8],
    ) -> Result<Option<MoveSource>, Error> {
        let aad = encode(&(destination, identity))?;
        for key in self.opening_keys() {
            if let Ok(bytes) = decrypt(&key.key, &aad, sealed) {
                let source: MoveSource = decode(&bytes)?;
                if source.scope != key.scope
                    || source.generation != key.generation
                    || source
                        .tuple
                        .scope(source.scope.domain, source.scope.table)
                        .ok()
                        != Some(source.scope)
                    || source.scope.table != destination.table
                {
                    return Err(denied("move source differs from authenticated key"));
                }
                return Ok(Some(source));
            }
        }
        Ok(None)
    }
    pub(super) async fn follow_moves(&mut self, time: u64) -> Result<bool, Error> {
        let mut pass = std::mem::take(&mut self.follow_pass);
        let epoch = self.context_epoch.load(Ordering::Relaxed);
        if pass.commit != self.commit || pass.epoch != epoch {
            if let Some(row) = &mut pass.row
                && (row.sources.pop_front().is_some()
                    || row.visited.pop_first().is_some()
                    || row.candidates.pop_first().is_some())
            {
                self.follow_pass = pass;
                return Ok(true);
            }
            // The current row restarts at its own key; unrelated commits
            // keep the cursor so the pass still completes under writes.
            pass.row = None;
            if pass.epoch != epoch {
                pass.after = None;
                pass.moved = None;
            }
        }
        if pass.moved.is_none() {
            let table = self
                .conn
                .names()
                .physical("secure_move_rows")
                .unwrap_or("secure_move_rows")
                .to_owned();
            let writes = self
                .conn
                .connection()
                .watch_writes([(table.clone(), true)])?;
            let count = writes.table_count(&table);
            pass.moved = Some((writes, table, count));
        }
        if let Some((writes, table, count)) = &mut pass.moved {
            let now = writes.table_count(table);
            if now != *count {
                *count = now;
                pass.rescan |= pass.after.is_some();
            }
        }
        let result = self.follow_move_step(&mut pass, time).await;
        pass.commit = if result.is_ok() {
            self.commit
        } else {
            u64::MAX
        };
        pass.epoch = self.context_epoch.load(Ordering::Relaxed);
        self.follow_pass = pass;
        result
    }
    async fn follow_move_step(&mut self, pass: &mut FollowPass, time: u64) -> Result<bool, Error> {
        if self.node_author.is_none() || self.local_grants(time).is_err() {
            return Ok(false);
        }
        let Some(current) = &mut pass.row else {
            let records = match &pass.after {
                Some((scope, row)) => collect_rows(self.conn.query(
                    format!("{MOVE_SCAN} WHERE (m.scope,m.row)>(?,?) ORDER BY m.scope,m.row LIMIT 1"),
                    [scope.clone(), row.clone()],
                ).await?).await?,
                None => rows(&self.conn, &format!("{MOVE_SCAN} ORDER BY m.scope,m.row LIMIT 1")).await?,
            };
            let Some(record) = records.into_iter().next() else {
                pass.after = None;
                return Ok(std::mem::take(&mut pass.rescan));
            };
            let [
                SqlValue::Blob(scope),
                SqlValue::Blob(storage_row),
                SqlValue::Blob(bytes),
            ] = record.as_slice()
            else {
                return Err(Error::Corrupt("move scan".into()));
            };
            let destination: ResourceScope = decode(scope)?;
            let record = self.decode_record(bytes).await?;
            let key = (scope.clone(), storage_row.clone());
            let Some(sealed) = record.moved_from.as_ref().filter(|_| !record.deleted) else {
                pass.after = Some(key);
                return Ok(true);
            };
            let Some(identity) = record.identity else {
                pass.after = Some(key);
                return Ok(true);
            };
            let signer = self
                .node_author
                .as_ref()
                .ok_or_else(|| denied("follow author missing"))?
                .key
                .public_key();
            let proof = self
                .carried_proof(
                    record
                        .proof
                        .as_ref()
                        .ok_or_else(|| denied("moved row lacks creation proof"))?,
                )
                .await?;
            if !self.holds(destination).await? || !self.readable(destination).unwrap_or(false) {
                pass.after = Some(key);
                return Ok(true);
            }
            let link = self.open_move_source(destination, identity, sealed)?;
            pass.row = Some(FollowRow {
                key,
                destination,
                record,
                identity,
                proof,
                signer,
                link,
                visited: BTreeSet::from([destination]),
                sources: Default::default(),
                source: None,
                sequence: -1,
                candidates: Default::default(),
            });
            return Ok(true);
        };
        if let Some(source) = current.link.take() {
            if !current.visited.insert(source.scope) {
                return Err(denied("cyclic move links"));
            }
            current.link = match self
                .row(
                    source.scope,
                    current
                        .key
                        .1
                        .as_slice()
                        .try_into()
                        .map_err(|_| denied("invalid incarnation"))?,
                )
                .await?
            {
                Some(row) => row
                    .moved_from
                    .as_ref()
                    .map(|sealed| self.open_move_source(source.scope, current.identity, sealed))
                    .transpose()?
                    .flatten(),
                None => None,
            };
            current.sources.push_back(source);
            return Ok(true);
        }
        if current.source.is_none() {
            current.source = current.sources.pop_front();
            current.sequence = -1;
            if current.source.is_none() {
                if current.visited.pop_first().is_some() {
                    return Ok(true);
                }
                let row = pass
                    .row
                    .take()
                    .ok_or_else(|| denied("missing follow row"))?;
                pass.after = Some(row.key.clone());
                self.publish_follow_row(row, time).await?;
                return Ok(true);
            }
        }
        let source = current
            .source
            .as_ref()
            .ok_or_else(|| denied("missing follow source"))?;
        let records = collect_rows(self.conn.query(
            "SELECT sequence,header,body,status FROM secure_operations WHERE scope=? AND author=? AND sequence>? ORDER BY sequence LIMIT 1",
            bindings(vec![SqlValue::Blob(encode(&source.scope)?), SqlValue::Blob(current.signer.as_bytes().to_vec()), SqlValue::Integer(current.sequence)]),
        ).await?).await?;
        let Some(record) = records.first() else {
            current.source = None;
            return Ok(true);
        };
        let [
            SqlValue::Integer(sequence),
            SqlValue::Blob(header),
            SqlValue::Blob(body),
            SqlValue::Text(status),
        ] = record.as_slice()
        else {
            return Err(Error::Corrupt("own updates".into()));
        };
        current.sequence = *sequence;
        if status != "applied" {
            return Ok(true);
        }
        let frame = self.chained_frame(header.clone(), body.clone()).await?;
        let operation = frame.operation_ref()?;
        let payload = self.row_payload(&frame)?;
        for write in payload.clone().into_writes() {
            if write.change.before.is_none()
                || write.change.after.is_none()
                || self
                    .app
                    .row_identity(&write.change)
                    .map_err(|error| denied(&error))?
                    .map(|id| id.integer())
                    != Some(current.identity)
            {
                continue;
            }
            let default_stamp = Stamp {
                clock: operation.header.timestamp,
                author: operation.header.extensions.author.unwrap_or(0),
                sequence: operation.header.extensions.author_sequence,
            };
            for field in write.published_fields() {
                let Some(value) = write
                    .change
                    .after
                    .as_ref()
                    .and_then(|fields| fields.get(&field))
                else {
                    continue;
                };
                let stamp = payload
                    .carried(&write.change.row)
                    .and_then(|carried| carried.stamps.get(&field))
                    .unwrap_or(&default_stamp);
                if Some(stamp.author) != operation.header.extensions.author
                    || current
                        .record
                        .stamps
                        .get(&field)
                        .is_some_and(|old| old >= stamp)
                {
                    continue;
                }
                if current
                    .candidates
                    .get(&field)
                    .is_none_or(|(old, _, _)| old < stamp)
                {
                    current
                        .candidates
                        .insert(field, (stamp.clone(), value.clone(), operation.hash));
                }
            }
        }
        Ok(true)
    }
    async fn publish_follow_row(&mut self, row: FollowRow, time: u64) -> Result<(), Error> {
        let FollowRow {
            key: (scope, _),
            destination,
            record,
            proof,
            signer,
            candidates,
            ..
        } = row;
        if candidates.is_empty() {
            return Ok(());
        }
        let mut after = record.fields.clone();
        let mut stamps = BTreeMap::new();
        let mut originals = Vec::new();
        for (field, (stamp, value, original)) in candidates {
            let seen = collect_rows(
                self.conn
                    .query(
                        "SELECT 1 FROM secure_followed WHERE original=? AND scope=? AND field=?",
                        [original.as_bytes().to_vec(), scope.clone(), field.to_vec()],
                    )
                    .await?,
            )
            .await?;
            if !seen.is_empty() {
                return Ok(());
            }
            stamps.insert(field, stamp);
            after.insert(field, value);
            originals.push((original, field));
        }
        if stamps.is_empty() {
            return Ok(());
        }
        let change = RowChange {
            scope: destination,
            row: record.key.ok_or_else(|| denied("moved row key missing"))?,
            before: Some(record.fields.clone()),
            after: Some(after),
        };
        let write = RowWrite {
            change,
            assigned: stamps.keys().copied().collect(),
        };
        let author = self
            .node_author
            .as_ref()
            .ok_or_else(|| denied("follow author missing"))?;
        let tuple = self
            .partitions
            .get(&destination)
            .ok_or_else(|| denied("follow partition missing"))?;
        let grants = author.credentials.verify_partition_author(
            self.config.publisher,
            signer,
            author.number,
            destination,
            tuple,
            &self.config.revocations,
            time,
        );
        let Ok(grants) = grants else {
            return Ok(());
        };
        if !write.permitted_by(&grants) {
            return Ok(());
        }
        let carried = BTreeMap::from([(
            (destination, write.change.row),
            Carried {
                proof,
                authors: self.carried_authors(destination.domain, &stamps).await?,
                stamps,
                moved_from: None,
            },
        )]);
        let input = rocky_core::commitment(
            "rocky.follow-input.v1",
            &encode(&(&originals, destination, &write, &carried))?,
        );
        let handle = rocky_core::commitment(
            "rocky.follow-handle.v1",
            &encode(&(&originals, destination))?,
        );
        self.conn.execute("SAVEPOINT follow", ()).await?;
        let authored =
            Box::pin(self.author_bundle_carried((handle, input), &[write], &[], time, &carried))
                .await;
        if let Err(error) = authored {
            self.conn.execute("ROLLBACK TO follow", ()).await?;
            self.invalidate_context();
            self.conn.execute("RELEASE follow", ()).await?;
            return Err(error);
        }
        for (original, field) in originals {
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO secure_followed VALUES(?,?,?)",
                    [original.as_bytes().to_vec(), scope.clone(), field.to_vec()],
                )
                .await?;
        }
        self.conn.execute("RELEASE follow", ()).await?;
        Ok(())
    }
}

impl<A: RowApplication> Inner<A> {
    pub(super) async fn rebootstrap_moves(
        &self,
        scope: i64,
    ) -> Result<checkpoint::SetSummary, Error> {
        self.move_summary(
            "SELECT row,fields FROM secure_rebootstrap_rows WHERE scope=?",
            scope,
        )
        .await
    }
    /// Move links of the rows a direct import stored.
    pub(super) async fn imported_moves(&self, scope: i64) -> Result<checkpoint::SetSummary, Error> {
        self.move_summary(
            "SELECT row,fields FROM secure_checkpoint_rows WHERE scope=?",
            scope,
        )
        .await
    }
    pub(super) async fn reindex_move_scope(&self, scope: ResourceScope) -> Result<(), Error> {
        let blob = encode(&scope)?;
        self.conn
            .execute("DELETE FROM secure_move_rows WHERE scope=?", [blob.clone()])
            .await?;
        let records = collect_rows(
            self.conn
                .query(
                    "SELECT row,fields FROM secure_row_records WHERE scope=?",
                    [blob.clone()],
                )
                .await?,
        )
        .await?;
        for values in records {
            let [SqlValue::Blob(row), SqlValue::Blob(bytes)] = values.as_slice() else {
                return Err(Error::Corrupt("move index row".into()));
            };
            let record = self.decode_record(bytes).await?;
            if record.moved_from.is_some() && !record.deleted {
                self.conn
                    .execute(
                        "INSERT INTO secure_move_rows VALUES(?,?)",
                        [blob.clone(), row.clone()],
                    )
                    .await?;
            }
        }
        Ok(())
    }
    async fn move_summary(&self, sql: &str, scope: i64) -> Result<checkpoint::SetSummary, Error> {
        let mut rows = self.conn.query(sql, [scope]).await?;
        let mut summary = checkpoint::SetSummary {
            count: 0,
            digest: [0; 32],
        };
        while let Some(row) = rows.next().await? {
            let id: Vec<u8> = row.get(0)?;
            let bytes: Vec<u8> = row.get(1)?;
            let row = self.decode_record(&bytes).await?;
            if let Some(link) = row.moved_from {
                summary.count += 1;
                let hash =
                    rocky_core::commitment("rocky.checkpoint.move.v1", &encode(&(id, link))?);
                for (digest, byte) in summary.digest.iter_mut().zip(hash) {
                    *digest ^= byte;
                }
            }
        }
        Ok(summary)
    }
}
