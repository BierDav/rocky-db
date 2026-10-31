use super::*;
mod creations;
mod shapes;
pub(in crate::replica) use shapes::SCHEMA as SHAPE_SCHEMA;

pub(super) const SCHEMA: &[&str] = &[
    "CREATE VIEW IF NOT EXISTS secure_row_records AS SELECT s.scope,r.row,r.fields FROM secure_rows r JOIN secure_scope_state s ON s.id=r.scope",
    "CREATE TRIGGER IF NOT EXISTS secure_records_insert INSTEAD OF INSERT ON secure_row_records BEGIN SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM secure_scope_state WHERE scope=NEW.scope) THEN RAISE(ABORT,'unknown stored row scope') END; INSERT INTO secure_rows VALUES((SELECT id FROM secure_scope_state WHERE scope=NEW.scope),NEW.row,NEW.fields) ON CONFLICT(scope,row) DO UPDATE SET fields=excluded.fields; END",
    "CREATE TRIGGER IF NOT EXISTS secure_records_update INSTEAD OF UPDATE ON secure_row_records BEGIN UPDATE secure_rows SET fields=NEW.fields WHERE scope=(SELECT id FROM secure_scope_state WHERE scope=OLD.scope) AND row=OLD.row; END",
    "CREATE TRIGGER IF NOT EXISTS secure_records_delete INSTEAD OF DELETE ON secure_row_records BEGIN DELETE FROM secure_rows WHERE scope=(SELECT id FROM secure_scope_state WHERE scope=OLD.scope) AND row=OLD.row; END",
    "CREATE TABLE IF NOT EXISTS secure_field_names(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL UNIQUE)",
    "CREATE TABLE IF NOT EXISTS secure_row_creations(id INTEGER PRIMARY KEY AUTOINCREMENT,hash BLOB NOT NULL UNIQUE)",
    "CREATE TABLE IF NOT EXISTS secure_row_origins(id INTEGER PRIMARY KEY AUTOINCREMENT,origin BLOB NOT NULL UNIQUE)",
];

#[derive(Default)]
pub(super) struct Dictionary {
    fields: HashMap<Commitment, i64>,
    names: HashMap<i64, Commitment>,
    texts: HashMap<Commitment, String>,
    creation_ids: HashMap<Hash, i64>,
    creations: HashMap<i64, Hash>,
    origins: HashMap<i64, moves::Origin>,
    origin_ids: HashMap<Vec<u8>, i64>,
    shape_ids: BTreeMap<Vec<Commitment>, i64>,
    shapes: HashMap<i64, Vec<Commitment>>,
    /// Interned scope ids by encoded scope; ids are never reassigned.
    scope_ids: HashMap<Vec<u8>, i64>,
}

type Field = (i64, Option<serde_bytes::ByteBuf>, Option<usize>);

/// Local ids never enter a row's canonical commitment or a peer's file.
#[derive(Serialize, Deserialize)]
pub(super) struct Record<C = u32>(
    Option<(i64, serde_bytes::ByteArray<32>)>,
    Option<serde_bytes::ByteBuf>,
    Vec<Field>,
    Vec<Stamp>,
    bool,
    C,
    Option<i64>,
    Option<serde_bytes::ByteArray<32>>,
    Option<usize>,
    i64,
);

impl<A> Inner<A> {
    pub(super) fn invalidate_records(&self) {
        *self
            .record_dictionary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Default::default();
        *self
            .author_sets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Default::default();
        self.stamp_authors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
    fn dictionary(&self) -> std::sync::MutexGuard<'_, Dictionary> {
        self.record_dictionary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub(super) fn cached_scope_id(&self, scope: &[u8]) -> Option<i64> {
        self.dictionary().scope_ids.get(scope).copied()
    }
    pub(super) fn cache_scope_id(&self, scope: Vec<u8>, id: i64) {
        self.dictionary().scope_ids.insert(scope, id);
    }
}

impl<A: RowApplication> Inner<A> {
    async fn field_number(&self, field: Commitment, allocate: bool) -> Result<i64, Error> {
        if let Some(id) = self.dictionary().fields.get(&field).copied() {
            return Ok(id);
        }
        let name = self
            .definition
            .fields
            .iter()
            .chain(
                self.catalog
                    .values()
                    .flat_map(|definition| &definition.fields),
            )
            .find(|item| item.id == field)
            .map(|item| item.name.clone());
        if let Some(name) = name {
            let mut rows = self
                .conn
                .query(
                    "SELECT id FROM secure_field_names WHERE name=?",
                    [name.clone()],
                )
                .await?;
            let id: Option<i64> = match rows.next().await? {
                Some(row) => Some(row.get(0)?),
                None => None,
            };
            drop(rows);
            let id = match id {
                Some(id) => id,
                None if allocate => {
                    self.conn
                        .execute(
                            "INSERT INTO secure_field_names(name) VALUES(?)",
                            [name.clone()],
                        )
                        .await?;
                    let mut rows = self
                        .conn
                        .query(
                            "SELECT id FROM secure_field_names WHERE name=?",
                            [name.clone()],
                        )
                        .await?;
                    rows.next()
                        .await?
                        .ok_or_else(|| Error::Corrupt("interned field name".into()))?
                        .get(0)?
                }
                None => return Err(Error::Corrupt("stored field has no name".into())),
            };
            let mut dictionary = self.dictionary();
            dictionary.texts.insert(field, name);
            dictionary.fields.insert(field, id);
            dictionary.names.insert(id, field);
            return Ok(id);
        }
        let mut rows = self
            .conn
            .query("SELECT id,name FROM secure_field_names", ())
            .await?;
        while let Some(row) = rows.next().await? {
            let id = row.get(0)?;
            let name: String = row.get(1)?;
            let found = self.definition.item_id("field", &name);
            let mut dictionary = self.dictionary();
            dictionary.texts.insert(found, name);
            dictionary.fields.insert(found, id);
            dictionary.names.insert(id, found);
        }
        self.dictionary()
            .fields
            .get(&field)
            .copied()
            .ok_or_else(|| Error::Corrupt("stored field has no name".into()))
    }

    pub(super) async fn record_name(&self, field: Commitment) -> Result<String, Error> {
        if let Some(name) = self.dictionary().texts.get(&field).cloned() {
            return Ok(name);
        }
        let id = self.field_number(field, false).await?;
        let mut rows = self
            .conn
            .query("SELECT name FROM secure_field_names WHERE id=?", [id])
            .await?;
        let name: String = rows
            .next()
            .await?
            .ok_or_else(|| Error::Corrupt("unknown stored field name".into()))?
            .get(0)?;
        self.dictionary().texts.insert(field, name.clone());
        Ok(name)
    }

    async fn named_field(&self, id: i64) -> Result<Commitment, Error> {
        if let Some(field) = self.dictionary().names.get(&id).copied() {
            return Ok(field);
        }
        let mut rows = self
            .conn
            .query("SELECT name FROM secure_field_names WHERE id=?", [id])
            .await?;
        let name: String = rows
            .next()
            .await?
            .ok_or_else(|| Error::Corrupt("unknown stored field id".into()))?
            .get(0)?;
        let field = self.definition.item_id("field", &name);
        let mut dictionary = self.dictionary();
        dictionary.texts.insert(field, name);
        dictionary.fields.insert(field, id);
        dictionary.names.insert(id, field);
        Ok(field)
    }

    async fn origin_number(&self, origin: moves::Origin, allocate: bool) -> Result<i64, Error> {
        let bytes = encode(&origin)?;
        if let Some(id) = self.dictionary().origin_ids.get(&bytes).copied() {
            return Ok(id);
        }
        let mut rows = self
            .conn
            .query(
                "SELECT id FROM secure_row_origins WHERE origin=?",
                [bytes.clone()],
            )
            .await?;
        let id: Option<i64> = match rows.next().await? {
            Some(row) => Some(row.get(0)?),
            None => None,
        };
        drop(rows);
        let id = match id {
            Some(id) => id,
            None if allocate => {
                self.conn
                    .execute(
                        "INSERT INTO secure_row_origins(origin) VALUES(?)",
                        [bytes.clone()],
                    )
                    .await?;
                let mut rows = self
                    .conn
                    .query(
                        "SELECT id FROM secure_row_origins WHERE origin=?",
                        [bytes.clone()],
                    )
                    .await?;
                rows.next()
                    .await?
                    .ok_or_else(|| Error::Corrupt("stored creation origin".into()))?
                    .get(0)?
            }
            None => return Err(Error::Corrupt("stored creation origin is missing".into())),
        };
        let mut dictionary = self.dictionary();
        dictionary.origins.insert(id, origin);
        dictionary.origin_ids.insert(bytes, id);
        Ok(id)
    }

    async fn origin(&self, id: i64) -> Result<moves::Origin, Error> {
        if let Some(origin) = self.dictionary().origins.get(&id).cloned() {
            return Ok(origin);
        }
        let mut rows = self
            .conn
            .query("SELECT origin FROM secure_row_origins WHERE id=?", [id])
            .await?;
        let bytes: Vec<u8> = rows
            .next()
            .await?
            .ok_or_else(|| Error::Corrupt("unknown stored creation origin".into()))?
            .get(0)?;
        let origin = decode::<moves::Origin>(&bytes)?;
        let mut dictionary = self.dictionary();
        dictionary.origins.insert(id, origin.clone());
        dictionary.origin_ids.insert(bytes, id);
        Ok(origin)
    }

    pub(super) async fn encode_record(&self, row: &Materialized) -> Result<Vec<u8>, Error> {
        self.encode_record_with(row, true).await
    }
    pub(super) async fn encode_existing_record(
        &self,
        row: &Materialized,
    ) -> Result<Vec<u8>, Error> {
        self.encode_record_with(row, false).await
    }
    async fn encode_record_with(
        &self,
        row: &Materialized,
        allocate: bool,
    ) -> Result<Vec<u8>, Error> {
        let mut canonical = row.clone();
        canonical.trim_authors()?;
        let row = &canonical;
        let origin = match &row.proof {
            Some(proof) => Some(self.origin_number(proof.origin(), allocate).await?),
            None => None,
        };
        let mut fields = BTreeMap::new();
        for field in row.fields.keys().chain(row.stamps.keys()) {
            fields.insert(*field, self.field_number(*field, allocate).await?);
        }
        let authors = self.intern_author_set(&row.authors, allocate).await?;
        let creation = self.creation_number(row.creation, allocate).await?;
        let shape = self
            .record_shape(row.fields.keys().copied().collect(), allocate)
            .await?;
        let mut bytes = vec![u8::from(!row.deleted)];
        bytes.extend(encode(&shape)?);
        bytes.extend(encode(&Record::pack(
            row, &fields, origin, authors, creation,
        )?)?);
        Ok(bytes)
    }

    pub(crate) async fn decode_record(&self, bytes: &[u8]) -> Result<Materialized, Error> {
        let shape_bytes = match bytes.get(1) {
            Some(0..=23) => 1,
            Some(24) => 2,
            Some(25) => 3,
            Some(26) => 5,
            Some(27) => 9,
            _ => return Err(Error::Corrupt("stored row shape encoding".into())),
        };
        let (prefix, bytes) = bytes
            .split_at_checked(1 + shape_bytes)
            .ok_or_else(|| Error::Corrupt("truncated stored record".into()))?;
        let live = prefix[0];
        let shape = self.shape_fields(&prefix[1..]).await?;
        let record: Record<i64> = decode(bytes)?;
        if live > 1 || (live == 0) != record.4 {
            return Err(Error::Corrupt("stored record liveness".into()));
        }
        let mut fields = BTreeMap::new();
        for id in record.field_ids() {
            fields.insert(id, self.named_field(id).await?);
        }
        let origin = match record.origin_id() {
            Some(id) => Some(self.origin(id).await?),
            None => None,
        };
        let authors = self.stored_author_set(record.9).await?;
        let creation = self.creation_hash(record.5).await?;
        let row = record.unpack(&fields, origin, &authors, creation)?;
        if row.fields.keys().copied().collect::<Vec<_>>() != shape {
            return Err(Error::Corrupt("stored row differs from its shape".into()));
        }
        Ok(row)
    }

    pub(super) async fn canonical_record(&self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        encode(&self.decode_record(bytes).await?)
    }
    pub(super) async fn strip_stored_record(
        &self,
        fields: &schemas::PathFields,
        table: Commitment,
        bytes: &[u8],
    ) -> Result<Option<Vec<u8>>, Error> {
        if !fields.tables.contains(&table) {
            return Ok(None);
        }
        if bytes.is_empty() {
            return Ok(Some(Vec::new()));
        }
        let mut row = self.decode_record(bytes).await?;
        if fields.strip(table, &mut row) {
            Ok(Some(self.encode_record(&row).await?))
        } else {
            Ok(Some(bytes.to_vec()))
        }
    }
    pub(super) async fn optional_record(
        &self,
        bytes: Option<&[u8]>,
    ) -> Result<Option<Materialized>, Error> {
        match bytes {
            Some(bytes) => Ok(Some(self.decode_record(bytes).await?)),
            None => Ok(None),
        }
    }
}

impl checkpoint::Sets {
    pub(super) async fn replace_stored<A: RowApplication>(
        &mut self,
        inner: &Inner<A>,
        row: &Commitment,
        old: Option<&[u8]>,
        new: &[u8],
    ) -> Result<(), Error> {
        let old = match old {
            Some(bytes) => Some(inner.canonical_record(bytes).await?),
            None => None,
        };
        self.replace(row, old.as_deref(), &inner.canonical_record(new).await?)
    }
    pub(super) async fn remove_stored<A: RowApplication>(
        &mut self,
        inner: &Inner<A>,
        row: &Commitment,
        old: &[u8],
    ) -> Result<(), Error> {
        self.remove(row, &inner.canonical_record(old).await?)
    }
}

impl Record {
    pub(super) fn creation_index(&self) -> u32 {
        self.5
    }
    pub(super) fn wire_weight(row: &Materialized) -> Result<usize, Error> {
        let fields: BTreeMap<_, _> = row
            .fields
            .keys()
            .chain(row.stamps.keys())
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .enumerate()
            .map(|(id, field)| (field, id as i64))
            .collect();
        let packed = Self::pack(row, &fields, row.proof.as_ref().map(|_| 0), 0, 0)?;
        // Page legend and stamp indices can use two more bytes than local indices.
        Ok(encode(&packed)?.len() + 4 * fields.len() + 4)
    }
}

impl<C> Record<C> {
    pub(super) fn field_ids(&self) -> impl Iterator<Item = i64> + '_ {
        self.2.iter().map(|field| field.0)
    }
    pub(super) fn author_set_id(&self) -> i64 {
        self.9
    }
    pub(super) fn origin_id(&self) -> Option<i64> {
        self.0.as_ref().map(|proof| proof.0)
    }

    pub(super) fn pack(
        row: &Materialized,
        ids: &BTreeMap<Commitment, i64>,
        origin: Option<i64>,
        authors: i64,
        creation: C,
    ) -> Result<Self, Error> {
        let proof = match &row.proof {
            Some(proof) => {
                if Some(proof.identity().integer()) != row.identity {
                    return Err(Error::Corrupt(
                        "record identity differs from its origin".into(),
                    ));
                }
                Some((
                    origin.ok_or_else(|| Error::Corrupt("missing record origin".into()))?,
                    serde_bytes::ByteArray::new(proof.provenance()?),
                ))
            }
            None => None,
        };
        let mut keys = Vec::new();
        for field in row
            .fields
            .keys()
            .chain(row.stamps.keys())
            .copied()
            .collect::<BTreeSet<_>>()
        {
            keys.push((
                *ids.get(&field)
                    .ok_or_else(|| Error::Corrupt("missing record field name".into()))?,
                field,
            ));
        }
        keys.sort_unstable();
        let mut stamps = Vec::new();
        let mut index = |stamp: &Stamp| match stamps.iter().position(|held| held == stamp) {
            Some(index) => index,
            None => {
                stamps.push(stamp.clone());
                stamps.len() - 1
            }
        };
        let fields = keys
            .into_iter()
            .map(|(id, field)| {
                (
                    id,
                    row.fields.get(&field).cloned().map(Into::into),
                    row.stamps.get(&field).map(&mut index),
                )
            })
            .collect();
        let created = match &row.proof {
            Some(proof) => {
                if row.created.as_ref() != Some(proof.stamp()) {
                    return Err(denied("creation stamp differs from its proof"));
                }
                None
            }
            None => row.created.as_ref().map(index),
        };
        Ok(Self(
            proof,
            row.moved_from.clone().map(Into::into),
            fields,
            stamps,
            row.deleted,
            creation,
            row.identity,
            row.key.map(Into::into),
            created,
            authors,
        ))
    }

    pub(super) fn unpack(
        self,
        names: &BTreeMap<i64, Commitment>,
        origin: Option<moves::Origin>,
        authors: &stamp_authors::Authors,
        creation: Hash,
    ) -> Result<Materialized, Error> {
        let Self(proof, moved_from, fields, stamps, deleted, _, identity, key, created, _) = self;
        if fields.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            || stamps.iter().collect::<BTreeSet<_>>().len() != stamps.len()
        {
            return Err(denied("invalid compact record field or stamp order"));
        }
        let stamp = |index: usize| {
            stamps
                .get(index)
                .cloned()
                .ok_or_else(|| denied("invalid compact record stamp index"))
        };
        let mut values = BTreeMap::new();
        let mut field_stamps = BTreeMap::new();
        let mut used = BTreeSet::new();
        for (id, value, index) in fields {
            let field = *names
                .get(&id)
                .ok_or_else(|| denied("compact record lacks a field legend entry"))?;
            if value.is_none() && index.is_none() {
                return Err(denied("empty compact record field"));
            }
            if let Some(value) = value {
                values.insert(field, value.into_vec());
            }
            if let Some(index) = index {
                used.insert(index);
                field_stamps.insert(field, stamp(index)?);
            }
        }
        if let Some(index) = created {
            used.insert(index);
        }
        if used.len() != stamps.len() {
            return Err(denied("compact record carries unused stamps"));
        }
        let proof = match proof {
            Some((_, provenance)) => {
                let id = rocky_core::RowIdentity::from_integer(
                    identity.ok_or_else(|| denied("compact birth lacks its identity"))?,
                )
                .map_err(|error| denied(&error.to_string()))?;
                let proof = moves::StoredProof::from_origin(
                    origin.ok_or_else(|| denied("compact record lacks its origin"))?,
                    id,
                    provenance.into_array(),
                );
                proof.provenance()?;
                Some(proof)
            }
            None => None,
        };
        let created = match &proof {
            Some(proof) => {
                if created.is_some() {
                    return Err(denied("compact proof repeats its creation stamp"));
                }
                Some(proof.stamp().clone())
            }
            None => created.map(stamp).transpose()?,
        };
        let mut record = Materialized {
            authors: authors.clone(),
            proof,
            moved_from: moved_from.map(|bytes| bytes.into_vec()),
            fields: values,
            stamps: field_stamps,
            deleted,
            creation,
            identity,
            key: key.map(|key| key.into_array()),
            created,
        };
        record.trim_authors()?;
        Ok(record)
    }
}

#[cfg(test)]
impl<A: RowApplication> Inner<A> {
    pub(crate) async fn fixed_row_digest(
        &self,
        domain: rocky_core::Scope,
        rows: u64,
    ) -> Result<Commitment, Error> {
        let field = self.definition.fields[0].id;
        let signer = self.config.node.public_key();
        self.keep_stamp_author(domain, 1, signer).await?;
        let mut sets = checkpoint::Sets::new();
        for index in 0..rows {
            let row = rocky_core::commitment("rocky.phase9.fixture-row", &index.to_le_bytes());
            let stamp = Stamp {
                clock: 1_700_000_000_000_000 + index,
                author: 1,
                sequence: index + 1,
            };
            let record = Materialized {
                proof: None,
                moved_from: None,
                fields: BTreeMap::from([(field, format!("item {index:06}").into_bytes())]),
                stamps: BTreeMap::from([(field, stamp.clone())]),
                authors: BTreeMap::from([(1, signer)]),
                deleted: false,
                creation: Hash::new(b"rocky.phase9.fixture-creation"),
                identity: None,
                key: Some(row),
                created: Some(stamp),
            };
            let stored = self.encode_record(&record).await?;
            let canonical = self.canonical_record(&stored).await?;
            assert_eq!(canonical, encode(&record)?);
            sets.replace(&row, None, &canonical)?;
        }
        Ok(sets.rows_summary().digest)
    }
}
