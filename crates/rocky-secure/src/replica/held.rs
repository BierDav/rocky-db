//! Held changes: this device's bundles, never offered to a peer, that a
//! newer generation's removal would split. Adopting the generation holds
//! them whole, voids their frames with a signed record so their author logs
//! continue, and rolls their effects back; the application re-authors or
//! drops them.
mod late;
mod listing;
use super::checkpoint::hash_of;
use super::*;
use p2panda_core::{Header, Signature, validate_header};

pub(super) const SCHEMA: &[&str] = &[
    // Frames this device authored and never offered to a peer: their
    // writes as signed, the storage row of each, and their bundle.
    "CREATE TABLE IF NOT EXISTS secure_unoffered(hash BLOB PRIMARY KEY,bundle BLOB NOT NULL,members INTEGER NOT NULL,writes BLOB NOT NULL) WITHOUT ROWID",
    // Log positions a void record consumed, with the voided header. This
    // device's own record is NULL until the log's key is registered.
    "CREATE TABLE IF NOT EXISTS secure_voids(scope BLOB NOT NULL,author BLOB NOT NULL,sequence INTEGER NOT NULL,hash BLOB NOT NULL UNIQUE,header BLOB NOT NULL,record BLOB,PRIMARY KEY(scope,author,sequence)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_void_records(digest BLOB PRIMARY KEY,record BLOB NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_held(id BLOB PRIMARY KEY,change BLOB NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_held_frames(hash BLOB PRIMARY KEY,id BLOB NOT NULL,scope BLOB NOT NULL,frame BLOB NOT NULL) WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS secure_held_frames_scope ON secure_held_frames(scope,hash)",
    "CREATE TABLE IF NOT EXISTS secure_held_resolved(id BLOB PRIMARY KEY,authority BLOB NOT NULL) WITHOUT ROWID",
];
/// Headers one void record covers.
const MAX_VOID_HEADERS: usize = 64;
const VOID_LABEL: &str = "rocky.void.v1";
type VoidedHeader = (Hash, Header<Extensions>, Vec<u8>);
type UnsignedLogs = BTreeMap<(Vec<u8>, Vec<u8>), Vec<(i64, Vec<u8>)>>;

/// The author's signed statement that frames of one log were never offered
/// and are cancelled: receivers treat their positions as consumed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedVoid {
    /// The voided frames' signed headers, of one author and scope, in
    /// increasing sequence order.
    headers: Vec<serde_bytes::ByteBuf>,
    signature: Signature,
}
impl SignedVoid {
    pub(crate) fn sign(key: &PrivateKey, headers: Vec<Vec<u8>>) -> Result<Self, Error> {
        let headers: Vec<_> = headers
            .into_iter()
            .map(serde_bytes::ByteBuf::from)
            .collect();
        let signature = key.sign(&encode(&(VOID_LABEL, &headers))?);
        Ok(Self { headers, signature })
    }
    /// The voided headers with their hashes, once the record and every
    /// header verify under one author key and one scope.
    pub(crate) fn verify(&self) -> Result<Vec<VoidedHeader>, Error> {
        if self.headers.is_empty() || self.headers.len() > MAX_VOID_HEADERS {
            return Err(denied("void record size"));
        }
        let mut voided: Vec<(Hash, Header<Extensions>, Vec<u8>)> = Vec::new();
        for bytes in &self.headers {
            let header: Header<Extensions> = decode(bytes)?;
            validate_header(&header).map_err(|_| denied("invalid voided header"))?;
            if header.extensions.row_format != ROW_FORMAT || header.seq_num > i64::MAX as u64 {
                return Err(denied("invalid voided header"));
            }
            if let Some((_, first, _)) = voided.first()
                && (first.public_key != header.public_key
                    || first.extensions.scope != header.extensions.scope)
            {
                return Err(denied("a void record covers one author log"));
            }
            if voided
                .last()
                .is_some_and(|(_, last, _)| last.seq_num >= header.seq_num)
            {
                return Err(denied("voided headers out of order"));
            }
            voided.push((header.hash(), header, bytes.to_vec()));
        }
        let author = voided[0].1.public_key;
        if !author.verify(&encode(&(VOID_LABEL, &self.headers))?, &self.signature) {
            return Err(denied("invalid void signature"));
        }
        Ok(voided)
    }
    pub(crate) fn scope(&self) -> Result<ResourceScope, Error> {
        let bytes = self
            .headers
            .first()
            .ok_or_else(|| denied("void record size"))?;
        Ok(decode::<Header<Extensions>>(bytes)?.extensions.scope)
    }
    /// Bytes a page counts for the record.
    pub fn weight(&self) -> usize {
        self.headers
            .iter()
            .map(|header| header.len() + 8)
            .sum::<usize>()
            .saturating_add(96)
    }
    pub(super) fn digest(&self) -> Result<Commitment, Error> {
        Ok(rocky_core::commitment("rocky.void.hash.v1", &encode(self)?))
    }
}

/// A local change held because a newer generation removed what it writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldChange {
    /// The bundle's transaction, or its only frame.
    pub id: Commitment,
    /// When it was made: its stamp in microseconds.
    pub time: u64,
    pub rows: Vec<HeldRow>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HeldKind {
    Insert,
    Update,
    Delete,
}
/// One row a held change writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldRow {
    pub scope: ResourceScope,
    /// The table's name in the generation the change was made under.
    pub table: String,
    /// A later generation removed the table.
    pub removed: bool,
    /// The stored row.
    pub row: Commitment,
    pub kind: HeldKind,
    /// The row as the change left it, or as it was before a delete.
    pub fields: Vec<HeldField>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldField {
    pub field: Commitment,
    pub name: String,
    /// The encoded value.
    pub value: Vec<u8>,
    /// The change wrote this field.
    pub written: bool,
    /// A later generation removed the field.
    pub removed: bool,
    /// What re-authoring a written, kept field replaces: the stored value
    /// and its last change. None when the row is not stored now.
    pub current: Option<CurrentValue>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentValue {
    /// None when the stored row lacks the field.
    pub value: Option<Vec<u8>>,
    /// The stamp of its last change, in microseconds.
    pub time: u64,
    /// The key that signed it: a node.
    pub author: PublicKey,
}

/// A held change as stored: its rows with names, without current values.
#[derive(Serialize, Deserialize)]
struct Stored {
    time: u64,
    rows: Vec<StoredRow>,
}
#[derive(Serialize, Deserialize)]
struct StoredRow {
    scope: ResourceScope,
    table: String,
    row: Commitment,
    kind: HeldKind,
    fields: Vec<(Commitment, String, serde_bytes::ByteBuf, bool)>,
}
/// An unoffered frame as the hold reads it.
struct Unoffered {
    hash: Hash,
    bundle: Vec<u8>,
    members: usize,
    writes: Vec<(RowWrite, Commitment)>,
    header: Header<Extensions>,
    header_bytes: Vec<u8>,
}

impl<A: RowApplication> Inner<A> {
    /// Records a frame this device just authored as never offered.
    pub(super) async fn record_unoffered(
        &self,
        hash: Hash,
        writes: &[RowWrite],
    ) -> Result<(), Error> {
        let rows = writes
            .iter()
            .map(|write| self.storage_row(&write.change))
            .collect::<Result<Vec<_>, _>>()?;
        let pairs: Vec<_> = writes.iter().zip(rows).collect();
        self.conn
            .execute(
                "INSERT INTO secure_unoffered VALUES(?1,?1,1,?2)",
                [hash.as_bytes().to_vec(), encode(&pairs)?],
            )
            .await?;
        Ok(())
    }
    /// Names the bundle `frames` were authored as.
    pub(super) async fn record_bundle(
        &self,
        transaction: Commitment,
        frames: &[EncryptedFrame],
    ) -> Result<(), Error> {
        for frame in frames {
            self.conn
                .execute(
                    "UPDATE secure_unoffered SET bundle=?,members=? WHERE hash=?",
                    bindings(vec![
                        SqlValue::Blob(transaction.to_vec()),
                        SqlValue::Integer(frames.len() as i64),
                        SqlValue::Blob(frame.id()?.as_bytes().to_vec()),
                    ]),
                )
                .await?;
        }
        Ok(())
    }
    /// Marks `hashes` offered in a durable transaction before they leave
    /// the device; a push that fails midway still counts as sent.
    pub(crate) async fn offer(&mut self, hashes: &[Hash]) -> Result<(), Error> {
        for hash in hashes {
            let mut found = self
                .conn
                .query(
                    "SELECT 1 FROM secure_publication_unsent WHERE hash=?",
                    [hash.as_bytes().to_vec()],
                )
                .await?;
            if found.next().await?.is_some() {
                return Err(denied("a publication still being authored is never sent"));
            }
        }
        let mut unoffered = Vec::new();
        for hash in hashes {
            let mut found = self
                .conn
                .query(
                    "SELECT 1 FROM secure_unoffered WHERE hash=?",
                    [hash.as_bytes().to_vec()],
                )
                .await?;
            if found.next().await?.is_some() {
                unoffered.push(hash.as_bytes().to_vec());
            }
        }
        if unoffered.is_empty() {
            return Ok(());
        }
        transaction!(@cache_neutral self, |inner| {
            for hash in &unoffered {
                inner
                    .conn
                    .execute("DELETE FROM secure_unoffered WHERE hash=?", [hash.clone()])
                    .await?;
            }
            Ok(())
        })?;
        Ok(())
    }
    /// Marks this device's frames of `scope` up to each log position
    /// offered, as a served checkpoint covers them.
    pub(super) async fn offer_covered(
        &mut self,
        scope: ResourceScope,
        logs: &[(PublicKey, u64)],
    ) -> Result<(), Error> {
        let mut hashes = Vec::new();
        for (author, sequence) in logs {
            for record in collect_rows(
                self.conn
                    .query(
                        "SELECT o.hash FROM secure_operations o JOIN secure_unoffered u ON u.hash=o.hash WHERE o.scope=? AND o.author=? AND o.sequence<=?",
                        bindings(vec![
                            SqlValue::Blob(encode(&scope)?),
                            SqlValue::Blob(author.as_bytes().to_vec()),
                            SqlValue::Integer(*sequence as i64),
                        ]),
                    )
                    .await?,
            )
            .await?
            {
                let [SqlValue::Blob(hash)] = record.as_slice() else {
                    return Err(Error::Corrupt("unoffered frame".into()));
                };
                hashes.push(hash_of(hash)?);
            }
        }
        self.offer(&hashes).await
    }
    /// Holds every bundle of this device never offered to a peer with a
    /// frame `target` sees that touches a table, or writes a field to other
    /// than its default, missing from some tip between the frame's and
    /// `target`, and every unoffered bundle that depends on one. A frame
    /// `target` does not see stays unsent on its own line. Inside the
    /// activation transaction: their frames are voided and deleted, and
    /// their scopes rebuilt after the switch. Returns how many bundles it held.
    pub(super) async fn hold_removed(
        &self,
        scope: rocky_core::Scope,
        target: TipId,
    ) -> Result<usize, Error> {
        let frames = self.unoffered().await?;
        if frames.is_empty() {
            return Ok(0);
        }
        let graph = self.graph_for(scope)?;
        // What each frame's tip had that the path to `target` lost.
        let mut removed_at = BTreeMap::<TipId, (HashSet<_>, HashSet<_>)>::new();
        let mut removed = Vec::with_capacity(frames.len());
        for frame in &frames {
            let extension = &frame.header.extensions;
            let author = extension
                .author
                .ok_or_else(|| denied("node author number missing"))?;
            if extension.scope.domain != scope
                || !self.visible_frame(
                    graph,
                    extension.tip,
                    author,
                    extension.author_sequence,
                    target,
                )?
            {
                removed.push(None);
                continue;
            }
            if let std::collections::btree_map::Entry::Vacant(entry) =
                removed_at.entry(extension.tip)
            {
                let path = self.path_fields_to(scope, extension.tip, target)?;
                let manifest = graph.schema_any(extension.tip).map_err(credential)?;
                let before = self
                    .definition_at(&manifest)
                    .ok_or_else(|| denied("source schema missing"))?;
                let tables: HashSet<_> = before
                    .entities
                    .iter()
                    .map(|table| table.id)
                    .filter(|table| !path.tables.contains(table))
                    .collect();
                let fields: HashSet<_> = before
                    .fields
                    .iter()
                    .map(|field| field.id)
                    .filter(|field| !path.fields.contains(field))
                    .collect();
                entry.insert((tables, fields));
            }
            removed.push(Some(extension.tip));
        }
        if removed_at
            .values()
            .all(|(tables, fields)| tables.is_empty() && fields.is_empty())
        {
            return Ok(0);
        }
        let defaults = self
            .defaults(
                &removed_at
                    .values()
                    .flat_map(|(_, fields)| fields.iter().copied())
                    .collect(),
            )
            .await?;
        let null = {
            let mut bytes = Vec::new();
            SqlValue::Null.encode(&mut bytes);
            bytes
        };
        let touches = |index: usize| {
            let frame = &frames[index];
            let Some((tables, fields)) = removed[index].and_then(|tip| removed_at.get(&tip)) else {
                return false;
            };
            tables.contains(&frame.header.extensions.scope.table)
                || frame.writes.iter().any(|(write, _)| {
                    tables.contains(&write.change.scope.table)
                        || write.change.after.as_ref().is_some_and(|after| {
                            write.published_fields().iter().any(|field| {
                                fields.contains(field)
                                    && after.get(field).is_some_and(|value| {
                                        value != defaults.get(field).unwrap_or(&null)
                                    })
                            })
                        })
                })
        };
        // Only a bundle whose every frame is unoffered can be held whole.
        let bundles = whole_bundles(&frames);
        let held: BTreeSet<Vec<u8>> = bundles
            .iter()
            .filter(|(_, members)| members.iter().any(|index| touches(*index)))
            .map(|(bundle, _)| bundle.clone())
            .collect();
        self.void_closure(&frames, &bundles, held, true).await
    }
    /// Voids `seeds` and every unoffered bundle that depends on one: their
    /// frames are deleted, void records signed and their kept scopes
    /// queued for rebuild. Dependants, and seeds when `hold_seeds`, are
    /// stored as held changes. Returns how many bundles are held.
    async fn void_closure(
        &self,
        frames: &[Unoffered],
        bundles: &BTreeMap<Vec<u8>, Vec<usize>>,
        seeds: BTreeSet<Vec<u8>>,
        hold_seeds: bool,
    ) -> Result<usize, Error> {
        let names = self.item_names().await?;
        let mut held = seeds.clone();
        // A bundle that saw a held one's effects is held with it.
        loop {
            let voided: HashSet<Hash> = held
                .iter()
                .flat_map(|bundle| &bundles[bundle])
                .map(|index| frames[*index].hash)
                .collect();
            let before = held.len();
            for (bundle, members) in bundles {
                if !held.contains(bundle)
                    && members.iter().any(|index| {
                        frames[*index]
                            .header
                            .previous
                            .iter()
                            .any(|hash| voided.contains(hash))
                    })
                {
                    held.insert(bundle.clone());
                }
            }
            if held.len() == before {
                break;
            }
        }
        let mut scopes = BTreeSet::new();
        let mut recorded = 0;
        for bundle in &held {
            let members: Vec<&Unoffered> = bundles[bundle].iter().map(|i| &frames[*i]).collect();
            for frame in &members {
                scopes.insert(frame.header.extensions.scope);
            }
            if !hold_seeds && seeds.contains(bundle) {
                continue;
            }
            recorded += 1;
            let id: Commitment = bundle
                .as_slice()
                .try_into()
                .map_err(|_| Error::Corrupt("unoffered bundle".into()))?;
            let mut stored = Stored {
                time: members
                    .iter()
                    .map(|frame| frame.header.timestamp)
                    .min()
                    .unwrap_or(0),
                rows: Vec::new(),
            };
            for frame in &members {
                for (write, row) in &frame.writes {
                    stored.rows.push(stored_row(write, *row, &names));
                }
            }
            self.conn
                .execute(
                    "INSERT OR REPLACE INTO secure_held VALUES(?,?)",
                    [id.to_vec(), encode(&stored)?],
                )
                .await?;
        }
        for frame in held
            .iter()
            .flat_map(|bundle| &bundles[bundle])
            .map(|i| &frames[*i])
        {
            self.no_frames_intake(&frame.header).await?;
            self.conn
                .execute(
                    "INSERT INTO secure_voids VALUES(?,?,?,?,?,NULL)",
                    bindings(vec![
                        SqlValue::Blob(encode(&frame.header.extensions.scope)?),
                        SqlValue::Blob(frame.header.public_key.as_bytes().to_vec()),
                        SqlValue::Integer(frame.header.seq_num as i64),
                        SqlValue::Blob(frame.hash.as_bytes().to_vec()),
                        SqlValue::Blob(frame.header_bytes.clone()),
                    ]),
                )
                .await?;
            positions::insert(&self.conn, &frame.header, 1, false, true).await?;
            self.delete_voided(frame.hash).await?;
        }
        // A node registered after open signs its logs' voids then.
        self.sign_voids().await?;
        for scope in scopes {
            if self.tables.contains(&scope.table) {
                self.conn
                    .execute(
                        "INSERT OR IGNORE INTO secure_rebuild_scopes VALUES(?)",
                        [encode(&scope)?],
                    )
                    .await?;
            }
        }
        Ok(recorded)
    }
    async fn unoffered(&self) -> Result<Vec<Unoffered>, Error> {
        let mut frames = Vec::new();
        for record in rows(
            &self.conn,
            "SELECT u.hash,u.bundle,u.members,u.writes,o.header FROM secure_unoffered u JOIN secure_operations o ON o.hash=u.hash WHERE NOT EXISTS(SELECT 1 FROM secure_migration_frames m WHERE m.hash=u.hash) ORDER BY o.scope,o.author,o.sequence",
        )
        .await?
        {
            let [
                SqlValue::Blob(hash),
                SqlValue::Blob(bundle),
                SqlValue::Integer(members),
                SqlValue::Blob(writes),
                SqlValue::Blob(header),
            ] = record.as_slice()
            else {
                return Err(Error::Corrupt("unoffered frame".into()));
            };
            frames.push(Unoffered {
                hash: hash_of(hash)?,
                bundle: bundle.clone(),
                members: usize::try_from(*members)
                    .map_err(|_| Error::Corrupt("unoffered frame".into()))?,
                writes: decode(writes)?,
                header: decode(header)?,
                header_bytes: header.clone(),
            });
        }
        Ok(frames)
    }
    /// The private key of a log this device writes: its node key or a
    /// node.
    fn log_key(&self, author: PublicKey) -> Result<&PrivateKey, Error> {
        if self.config.node.public_key() == author {
            return Ok(&self.config.node);
        }
        self.node_author
            .iter()
            .map(|node| &node.key)
            .find(|key| key.public_key() == author)
            .ok_or_else(|| denied("a held frame's log key is not registered"))
    }
    /// Table and field names of the installed typed tables and of every
    /// manifest this replica holds.
    async fn item_names(&self) -> Result<BTreeMap<Commitment, String>, Error> {
        let mut names = BTreeMap::new();
        let manifests: Vec<_> = std::iter::once(&self.definition)
            .chain(self.catalog.values())
            .collect();
        for manifest in &manifests {
            for table in &manifest.entities {
                names.entry(table.id).or_insert_with(|| table.name.clone());
            }
            for field in &manifest.fields {
                let name = field.name.split_once('.').map_or(&*field.name, |(_, f)| f);
                names.entry(field.id).or_insert_with(|| name.to_owned());
            }
        }
        if let Some((schema, _, _)) = self.installed_typed().await? {
            for table in &schema.tables {
                names.insert(schema.table_id(table), table.sql_name.clone());
                for column in &table.columns {
                    names.insert(schema.field_id(table, column), column.sql_name.clone());
                }
            }
        }
        Ok(names)
    }
    /// The encoded default of each of `fields` the installed typed tables
    /// declare one for; NULL otherwise.
    async fn defaults(
        &self,
        fields: &HashSet<Commitment>,
    ) -> Result<BTreeMap<Commitment, Vec<u8>>, Error> {
        let mut defaults = BTreeMap::new();
        if let Some((schema, _, _)) = self.installed_typed().await? {
            for table in &schema.tables {
                for column in &table.columns {
                    let id = schema.field_id(table, column);
                    if fields.contains(&id)
                        && let Some(value) = rocky_core::default_value(column)
                    {
                        let mut bytes = Vec::new();
                        value.encode(&mut bytes);
                        defaults.insert(id, bytes);
                    }
                }
            }
        }
        Ok(defaults)
    }

    /// Signs void records for this device's voided positions whose log key
    /// is registered, at most `MAX_VOID_HEADERS` positions each.
    pub(super) async fn sign_voids(&self) -> Result<(), Error> {
        let mut logs = UnsignedLogs::new();
        for record in rows(
            &self.conn,
            "SELECT scope,author,sequence,header FROM secure_voids WHERE record IS NULL ORDER BY scope,author,sequence",
        )
        .await?
        {
            let [
                SqlValue::Blob(scope),
                SqlValue::Blob(author),
                SqlValue::Integer(sequence),
                SqlValue::Blob(header),
            ] = record.as_slice()
            else {
                return Err(Error::Corrupt("voided position".into()));
            };
            logs.entry((scope.clone(), author.clone()))
                .or_default()
                .push((*sequence, header.clone()));
        }
        for ((scope, author), positions) in logs {
            let Ok(key) = self.log_key(super::checkpoint::key_of(&author)?) else {
                continue;
            };
            for chunk in positions.chunks(MAX_VOID_HEADERS) {
                let record = SignedVoid::sign(
                    key,
                    chunk.iter().map(|(_, header)| header.clone()).collect(),
                )?;
                let digest = record.digest()?;
                self.conn
                    .execute(
                        "INSERT OR IGNORE INTO secure_void_records VALUES(?,?)",
                        [digest.to_vec(), encode(&record)?],
                    )
                    .await?;
                for (sequence, _) in chunk {
                    self.conn
                        .execute(
                            "UPDATE secure_voids SET record=? WHERE scope=? AND author=? AND sequence=?",
                            bindings(vec![
                                SqlValue::Blob(digest.to_vec()),
                                SqlValue::Blob(scope.clone()),
                                SqlValue::Blob(author.clone()),
                                SqlValue::Integer(*sequence),
                            ]),
                        )
                        .await?;
                }
            }
        }
        Ok(())
    }
    /// Deletes a held frame as pruning does. Its handle stays: committing
    /// it again is refused like a pruned one, and it is forgotten later.
    async fn delete_voided(&self, hash: Hash) -> Result<(), Error> {
        let scope = self
            .frame(hash)
            .await?
            .ok_or_else(|| Error::Corrupt("voided frame".into()))?
            .operation_ref()?
            .header
            .extensions
            .scope;
        let bytes = hash.as_bytes().to_vec();
        let mut size = self
            .conn
            .query(
                "SELECT LENGTH(header)+LENGTH(body) FROM secure_operations WHERE hash=?",
                [bytes.clone()],
            )
            .await?;
        let size = match size.next().await? {
            Some(row) => row.get::<i64>(0)?,
            None => return Err(Error::Corrupt("held frame is not retained".into())),
        };
        for sql in [
            "DELETE FROM secure_operations WHERE hash=?",
            "DELETE FROM secure_applied WHERE hash=?",
            "DELETE FROM secure_unoffered WHERE hash=?",
            "DELETE FROM secure_outbox WHERE hash=?",
            "DELETE FROM secure_ack WHERE hash=?",
        ] {
            self.conn.execute(sql, [bytes.clone()]).await?;
        }
        self.conn
            .execute(
                "UPDATE secure_retained SET records=records-1,bytes=bytes-?",
                [size],
            )
            .await?;
        if let Some(id) = self.find_scope_id(scope).await? {
            self.reseed_ledger(scope, id).await?;
        }
        Ok(())
    }
    /// Author counters include voids and held frames of the log even when a
    /// checkpoint replaced the applied tip.
    pub(super) async fn author_tip(
        &self,
        scope: ResourceScope,
        id: i64,
        author: PublicKey,
    ) -> Result<Option<checkpoint::Log>, Error> {
        let tip = self.consumed_tip(scope, id, author).await?;
        let mut found = self
            .conn
            .query(
                "SELECT header FROM secure_operations WHERE scope=? AND author=? AND status='held' ORDER BY sequence DESC LIMIT 1",
                [encode(&scope)?, author.as_bytes().to_vec()],
            )
            .await?;
        let held: Option<Header<Extensions>> = match found.next().await? {
            Some(row) => Some(decode(&row.get::<Vec<u8>>(0)?)?),
            None => None,
        };
        match held {
            Some(held)
                if tip
                    .as_ref()
                    .is_none_or(|tip| held.seq_num as i64 > tip.sequence) =>
            {
                Ok(Some(checkpoint::Log {
                    sequence: held.seq_num as i64,
                    hash: held.hash(),
                    clock: held.timestamp,
                    pruned_prefix: tip.map_or(-1, |tip| tip.pruned_prefix),
                }))
            }
            _ => Ok(tip),
        }
    }
    async fn consumed_tip(
        &self,
        scope: ResourceScope,
        id: i64,
        author: PublicKey,
    ) -> Result<Option<checkpoint::Log>, Error> {
        let tip = self.log(id, author).await?;
        let Some(voided) = self.voided_tip(scope, author).await? else {
            return Ok(tip);
        };
        if tip
            .as_ref()
            .is_some_and(|tip| tip.sequence as u64 > voided.seq_num)
        {
            return Ok(tip);
        }
        if let Some(tip) = &tip
            && tip.sequence as u64 == voided.seq_num
            && tip.hash != voided.hash()
        {
            return Err(Error::Corrupt(
                "applied and voided author positions conflict".into(),
            ));
        }
        Ok(Some(checkpoint::Log {
            sequence: voided.seq_num as i64,
            hash: voided.hash(),
            clock: voided.timestamp,
            pruned_prefix: tip.map_or(-1, |tip| tip.pruned_prefix),
        }))
    }
    /// The last consumed position, independent of an imported checkpoint's frontier.
    async fn voided_tip(
        &self,
        scope: ResourceScope,
        author: PublicKey,
    ) -> Result<Option<Header<Extensions>>, Error> {
        let mut found = self.conn.query(
            "SELECT header FROM secure_voids WHERE scope=? AND author=? ORDER BY sequence DESC LIMIT 1",
            [encode(&scope)?, author.as_bytes().to_vec()],
        ).await?;
        match found.next().await? {
            Some(row) => decode(&row.get::<Vec<u8>>(0)?).map(Some),
            None => Ok(None),
        }
    }
    /// The voided header of `hash`, if a void consumed it.
    async fn voided_header(&self, hash: Hash) -> Result<Option<Header<Extensions>>, Error> {
        let mut found = self
            .conn
            .query(
                "SELECT header FROM secure_voids WHERE hash=?",
                [hash.as_bytes().to_vec()],
            )
            .await?;
        match found.next().await? {
            Some(row) => Ok(Some(decode(&row.get::<Vec<u8>>(0)?)?)),
            None => Ok(None),
        }
    }
    /// Whether `header`'s dependency `id` is a voided frame, and if so
    /// whether it is consumed: every frame of its log before it is applied,
    /// pruned or voided. None when no void names it.
    pub(super) async fn voided_dependency(
        &self,
        header: &Header<Extensions>,
        id: Hash,
    ) -> Result<Option<bool>, Error> {
        let Some(voided) = self.voided_header(id).await? else {
            return Ok(None);
        };
        if voided.extensions.scope != header.extensions.scope
            || voided.timestamp >= header.timestamp
        {
            return Err(denied("wrong encrypted dependency scope/clock"));
        }
        if header.backlink == Some(id) {
            p2panda_core::validate_backlink(&voided, header)
                .map_err(|_| denied("invalid log predecessor"))?;
        }
        let mut current = voided;
        loop {
            let Some(previous) = current.backlink else {
                return Ok(Some(true));
            };
            if self.frame(previous).await?.is_some() {
                return Ok(Some(self.status(previous).await? == ReceiveStatus::Applied));
            }
            if let Some(earlier) = self.voided_header(previous).await? {
                current = earlier;
                continue;
            }
            return Ok(Some(self.pruned_log_position(&current, previous).await?));
        }
    }
    /// Whether the voided position of `header` is the next one at a log
    /// whose frames up to `previous` are pruned.
    async fn pruned_log_position(
        &self,
        header: &Header<Extensions>,
        previous: Hash,
    ) -> Result<bool, Error> {
        let Some(scope) = self.find_scope_id(header.extensions.scope).await? else {
            return Ok(false);
        };
        let Some(log) = self.log(scope, header.public_key).await? else {
            return Ok(false);
        };
        let predecessor = header.seq_num as i64 - 1;
        Ok((predecessor == log.sequence && log.hash == previous)
            || predecessor <= log.pruned_prefix)
    }
    /// The void records a reader of `frames` needs: those consuming each
    /// frame's voided backlinks, oldest last.
    pub(super) async fn voids_before(
        &self,
        frames: &[EncryptedFrame],
    ) -> Result<Vec<SignedVoid>, Error> {
        let mut digests = BTreeSet::new();
        let mut records = Vec::new();
        for frame in frames {
            let mut next = frame.operation_ref()?.header.backlink;
            while let Some(hash) = next {
                let found = collect_rows(
                    self.conn
                        .query(
                            "SELECT v.header,r.digest,r.record FROM secure_voids v JOIN secure_void_records r ON r.digest=v.record WHERE v.hash=?",
                            [hash.as_bytes().to_vec()],
                        )
                        .await?,
                )
                .await?;
                let Some(
                    [
                        SqlValue::Blob(header),
                        SqlValue::Blob(digest),
                        SqlValue::Blob(record),
                    ],
                ) = found.first().map(Vec::as_slice)
                else {
                    break;
                };
                if digests.insert(digest.clone()) {
                    records.push(decode(record)?);
                }
                next = decode::<Header<Extensions>>(header)?.backlink;
            }
        }
        Ok(records)
    }
    /// Admits one void record inside the caller's transaction. A record
    /// covering a frame this replica holds, a forked position or one its
    /// log already passed is refused whole.
    pub(super) async fn admit_void(
        &self,
        record: &SignedVoid,
        time: u64,
    ) -> Result<ReceiveStatus, Error> {
        let voided = record.verify()?;
        let scope = voided[0].1.extensions.scope;
        let local = self.local_grants(time)?;
        if !local.iter().any(|grant| {
            grant.scope == scope
                && grant.rows == RowSelection::All
                && (grant.rights.contains(&Right::Custody) || grant.rights.contains(&Right::Read))
        }) {
            return Err(denied("incoming custody denied"));
        }
        let author = voided[0].1.public_key;
        let log = match self.find_scope_id(scope).await? {
            Some(id) => self.log(id, author).await?,
            None => None,
        };
        let mut fresh = false;
        for (hash, header, _) in &voided {
            let position = collect_rows(
                self.conn
                    .query(
                        "SELECT hash FROM secure_operations WHERE scope=?1 AND author=?2 AND sequence=?3 UNION ALL SELECT hash FROM secure_voids WHERE scope=?1 AND author=?2 AND sequence=?3",
                        bindings(vec![
                            SqlValue::Blob(encode(&scope)?),
                            SqlValue::Blob(author.as_bytes().to_vec()),
                            SqlValue::Integer(header.seq_num as i64),
                        ]),
                    )
                    .await?,
            )
            .await?;
            let voided_here = self.voided_header(*hash).await?.is_some();
            if self.frame(*hash).await?.is_some()
                || (!voided_here && !position.is_empty())
                || (voided_here && position.len() != 1)
            {
                return Ok(ReceiveStatus::Rejected);
            }
            if !voided_here {
                if log
                    .as_ref()
                    .is_some_and(|log| log.sequence >= header.seq_num as i64)
                {
                    return Ok(ReceiveStatus::Rejected);
                }
                fresh = true;
            }
        }
        if !fresh {
            return Ok(ReceiveStatus::Duplicate);
        }
        for (_, header, _) in &voided {
            self.no_frames_intake(header).await?;
        }
        let digest = record.digest()?;
        self.conn
            .execute(
                "INSERT OR IGNORE INTO secure_void_records VALUES(?,?)",
                [digest.to_vec(), encode(record)?],
            )
            .await?;
        for (hash, header, bytes) in voided {
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO secure_voids VALUES(?,?,?,?,?,?)",
                    bindings(vec![
                        SqlValue::Blob(encode(&scope)?),
                        SqlValue::Blob(author.as_bytes().to_vec()),
                        SqlValue::Integer(header.seq_num as i64),
                        SqlValue::Blob(hash.as_bytes().to_vec()),
                        SqlValue::Blob(bytes),
                        SqlValue::Blob(digest.to_vec()),
                    ]),
                )
                .await?;
            positions::insert(&self.conn, &header, 1, false, true).await?;
            self.settle_placement(&header).await?;
        }
        Ok(ReceiveStatus::Applied)
    }
    /// Whether a void consumed this log position.
    pub(super) async fn voided_position(
        &self,
        scope: ResourceScope,
        author: PublicKey,
        sequence: u64,
    ) -> Result<bool, Error> {
        let mut found = self
            .conn
            .query(
                "SELECT 1 FROM secure_voids WHERE scope=? AND author=? AND sequence=?",
                bindings(vec![
                    SqlValue::Blob(encode(&scope)?),
                    SqlValue::Blob(author.as_bytes().to_vec()),
                    SqlValue::Integer(sequence as i64),
                ]),
            )
            .await?;
        Ok(found.next().await?.is_some())
    }
    /// The void record consuming each position of `scope`'s log by
    /// `author` from `start`, by position, at most `limit`.
    pub(super) async fn voids_from(
        &self,
        scope: ResourceScope,
        author: PublicKey,
        start: u64,
        limit: usize,
    ) -> Result<Vec<(u64, Commitment, SignedVoid)>, Error> {
        let mut voids = Vec::new();
        for record in collect_rows(
            self.conn
                .query(
                    "SELECT v.sequence,r.digest,r.record FROM secure_voids v JOIN secure_void_records r ON r.digest=v.record WHERE v.scope=? AND v.author=? AND v.sequence>=? ORDER BY v.sequence LIMIT ?",
                    bindings(vec![
                        SqlValue::Blob(encode(&scope)?),
                        SqlValue::Blob(author.as_bytes().to_vec()),
                        SqlValue::Integer(start as i64),
                        SqlValue::Integer(limit as i64),
                    ]),
                )
                .await?,
        )
        .await?
        {
            let [SqlValue::Integer(sequence), SqlValue::Blob(digest), SqlValue::Blob(bytes)] =
                record.as_slice()
            else {
                return Err(Error::Corrupt("void record".into()));
            };
            voids.push((
                *sequence as u64,
                digest
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Corrupt("void record".into()))?,
                decode(bytes)?,
            ));
        }
        Ok(voids)
    }
    /// Removes a held change inside the caller's transaction; fails when
    /// it is not held.
    pub(super) async fn resolve_held(&self, id: Commitment) -> Result<(), Error> {
        let mut found = self
            .conn
            .query("SELECT 1 FROM secure_held WHERE id=?", [id.to_vec()])
            .await?;
        if found.next().await?.is_none() {
            return Err(denied("no such held change"));
        }
        drop(found);
        self.record_held_resolution(id, &self.local_grants(now()?)?)
            .await
    }
    async fn held_row(&self, row: StoredRow) -> Result<HeldRow, Error> {
        let removed = !self.tables.contains(&row.scope.table);
        let current = match removed {
            true => None,
            false => self
                .row(row.scope, row.row)
                .await?
                .filter(|row| !row.deleted),
        };
        Ok(HeldRow {
            scope: row.scope,
            table: row.table,
            removed,
            row: row.row,
            kind: row.kind,
            fields: row
                .fields
                .into_iter()
                .map(|(field, name, value, written)| {
                    let removed = removed || !self.fields.contains(&field);
                    HeldField {
                        current: (written && !removed)
                            .then(|| {
                                current.as_ref().and_then(|current| {
                                    let stamp = current.stamps.get(&field)?;
                                    Some(CurrentValue {
                                        value: current.fields.get(&field).cloned(),
                                        time: stamp.clock,
                                        author: *current.authors.get(&stamp.author)?,
                                    })
                                })
                            })
                            .flatten(),
                        field,
                        name,
                        value: value.into_vec(),
                        written,
                        removed,
                    }
                })
                .collect(),
        })
    }
}

/// Unoffered frames by bundle, keeping only bundles whose every member is
/// unoffered.
fn whole_bundles(frames: &[Unoffered]) -> BTreeMap<Vec<u8>, Vec<usize>> {
    let mut bundles: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
    for (index, frame) in frames.iter().enumerate() {
        bundles.entry(frame.bundle.clone()).or_default().push(index);
    }
    bundles.retain(|_, members| members.len() == frames[members[0]].members);
    bundles
}

fn stored_row(
    write: &RowWrite,
    row: Commitment,
    names: &BTreeMap<Commitment, String>,
) -> StoredRow {
    let change = &write.change;
    let kind = match (&change.before, &change.after) {
        (None, _) => HeldKind::Insert,
        (Some(_), None) => HeldKind::Delete,
        (Some(_), Some(_)) => HeldKind::Update,
    };
    let written = write.published_fields();
    let image = change.after.as_ref().or(change.before.as_ref());
    let name = |id: &Commitment| {
        names
            .get(id)
            .cloned()
            .unwrap_or_else(|| id.iter().map(|byte| format!("{byte:02x}")).collect())
    };
    StoredRow {
        scope: change.scope,
        table: name(&change.scope.table),
        row,
        kind,
        fields: image
            .into_iter()
            .flatten()
            .map(|(field, value)| {
                (
                    *field,
                    name(field),
                    serde_bytes::ByteBuf::from(value.clone()),
                    kind != HeldKind::Delete && written.contains(field),
                )
            })
            .collect(),
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// Local changes held because a newer generation removed what they
    /// write, each with the current values of the fields it writes.
    pub async fn held_changes(&self) -> Result<Vec<HeldChange>, Error> {
        self.refresh_closed_held(None).await?;
        self.list_held_changes().await
    }
    /// Drops a held change; fails when it is not held.
    pub async fn drop_held(&self, id: Commitment) -> Result<(), Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        transaction!(inner, |inner| inner.resolve_held(id).await)?;
        inner.publish_revision().await
    }
    /// Admits void records that arrived together, then applies the frames
    /// that waited for them. Each record is admitted or refused whole.
    pub async fn receive_voids(&self, records: &[SignedVoid]) -> Vec<Result<ReceiveStatus, Error>> {
        if records.is_empty() {
            return Vec::new();
        }
        let results = {
            let mut inner = self.inner.lock(crate::replica::Class::Background).await;
            let time = match now() {
                Ok(time) => time,
                Err(error) => return records.iter().map(|_| Err(shared(&error))).collect(),
            };
            let admitted = transaction!(inner, |inner| {
                let mut results = Vec::with_capacity(records.len());
                for record in records {
                    inner.conn.execute("SAVEPOINT void", ()).await?;
                    let result = inner.admit_void(record, time).await;
                    if result.is_err() {
                        inner.conn.execute("ROLLBACK TO void", ()).await?;
                        inner.invalidate_context();
                    }
                    inner.conn.execute("RELEASE void", ()).await?;
                    results.push(result);
                }
                Ok(results)
            });
            match admitted {
                Ok(results) => results,
                Err(error) => return records.iter().map(|_| Err(shared(&error))).collect(),
            }
        };
        if let Err(error) = self.settle().await {
            return records.iter().map(|_| Err(shared(&error))).collect();
        }
        results
    }
}

fn shared(error: &Error) -> Error {
    Error::Rejected(error.to_string())
}
