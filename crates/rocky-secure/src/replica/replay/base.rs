//! A replayed scope's rows at a seal: its replay base. Replayed tables keep
//! no row records, so a checkpoint of one carries `(row id, image)` pairs
//! committed by an LtHash, and a rebuild starts from them. An image keys
//! each value by its field id, so it outlives the seal's schema.
use super::*;
use crate::replica::checkpoint::Sets;

pub(in crate::replica) const SCHEMA: &[&str] = &[
    // Rows at each finalized, uncompacted seal; `secure_replayed_seals`
    // marks the seals a scope's rows were taken at, empty ones included.
    // They stay while the seal leaves the path and comes back.
    "CREATE TABLE IF NOT EXISTS secure_replayed_seals(scope INTEGER NOT NULL,seal BLOB NOT NULL,PRIMARY KEY(scope,seal)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_replayed_seal_rows(scope INTEGER NOT NULL,seal BLOB NOT NULL,row BLOB NOT NULL,image BLOB NOT NULL,PRIMARY KEY(scope,seal,row)) WITHOUT ROWID",
    // Rows at the scope's checkpoint, and those of an import in progress.
    "CREATE TABLE IF NOT EXISTS secure_replayed_base(scope INTEGER NOT NULL,row BLOB NOT NULL,image BLOB NOT NULL,PRIMARY KEY(scope,row)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_replayed_staged(scope INTEGER NOT NULL,row BLOB NOT NULL,image BLOB NOT NULL,PRIMARY KEY(scope,row)) WITHOUT ROWID",
];

const ROW_LABEL: &str = "rocky.replayed-row.v1";

/// Each field id followed by its encoded value, in field order.
fn fields_blob(fields: &RowFields) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (field, value) in fields {
        bytes.extend_from_slice(field);
        bytes.extend_from_slice(value);
    }
    bytes
}

fn blob_fields(mut bytes: &[u8]) -> Result<RowFields, Error> {
    let corrupt = || Error::Corrupt("replayed base image".into());
    let mut fields = RowFields::new();
    while !bytes.is_empty() {
        let (field, rest) = bytes.split_first_chunk::<32>().ok_or_else(corrupt)?;
        let mut value = rest;
        SqlValue::decode(&mut value).map_err(|_| corrupt())?;
        let (encoded, rest) = rest.split_at(rest.len() - value.len());
        if fields.insert(*field, encoded.to_vec()).is_some() {
            return Err(corrupt());
        }
        bytes = rest;
    }
    Ok(fields)
}

/// Adds one base row to `sets`.
pub(in crate::replica) fn add_row(sets: &mut Sets, row: &Commitment, image: &[u8]) {
    sets.rows += 1;
    sets.digest
        .add(ROW_LABEL, &[row.as_slice(), image].concat());
}

/// The summary of `rows`, as a checkpoint statement commits it.
pub(in crate::replica) fn base_sets(rows: &[(Commitment, Vec<u8>)]) -> Sets {
    let mut sets = Sets::new();
    for (row, image) in rows {
        add_row(&mut sets, row, image);
    }
    sets
}

impl<A: RowApplication> Inner<A> {
    /// The live rows of replayed scope `scope`, by row id.
    pub(in crate::replica) async fn replayed_images(
        &self,
        scope: ResourceScope,
    ) -> Result<Vec<(Commitment, Vec<u8>)>, Error> {
        self.scanned_images(scope, None)
            .await?
            .ok_or_else(|| Error::Corrupt("replayed scope".into()))
    }
    /// The rows of replayed scope `scope` at kept `seal`, marked `mark`,
    /// by row id; none when the seal kept its table under other columns.
    pub(in crate::replica) async fn kept_images(
        &self,
        scope: ResourceScope,
        kept: (Commitment, i64),
    ) -> Result<Option<Vec<(Commitment, Vec<u8>)>>, Error> {
        self.scanned_images(scope, Some(kept)).await
    }
    async fn scanned_images(
        &self,
        scope: ResourceScope,
        kept: Option<(Commitment, i64)>,
    ) -> Result<Option<Vec<(Commitment, Vec<u8>)>>, Error> {
        let corrupt = || Error::Corrupt("replayed scope".into());
        let typed = self.workspace.typed.as_ref().ok_or_else(corrupt)?;
        let projected = typed.by_scope(scope).ok_or_else(corrupt)?;
        let table = typed
            .plan(&BTreeSet::from([scope]))?
            .tables
            .into_iter()
            .find(|table| table.name.eq_ignore_ascii_case(&projected.table.sql_name))
            .ok_or_else(corrupt)?;
        let scan = match kept {
            None => table.scan.clone(),
            Some(kept) => {
                let logical = typed
                    .rows
                    .schema()
                    .table(&projected.table.sql_name)
                    .ok_or_else(corrupt)?;
                let columns: Vec<String> =
                    logical.columns.iter().map(|c| c.sql_name.clone()).collect();
                match self.kept_scan(kept, &logical.sql_name, &columns).await? {
                    Some(scan) => scan,
                    None => return Ok(None),
                }
            }
        };
        let mut images = Vec::new();
        for values in self
            .conn
            .connection()
            .rows(&scan, Vec::new())
            .map_err(Error::from)?
        {
            let image = table
                .image(&values)
                .map_err(|_| Error::Corrupt("replayed row image".into()))?;
            if typed.row_scope(projected, &image)? != scope {
                continue;
            }
            let row = typed
                .rows
                .row_id(typed.domain.domain, &projected.table, &image)
                .map_err(|_| Error::Corrupt("replayed row key".into()))?;
            let fields = typed
                .rows
                .fields(&projected.table, &image)
                .map_err(|_| Error::Corrupt("replayed row image".into()))?;
            images.push((row, fields_blob(&fields)));
        }
        images.sort_unstable();
        Ok(Some(images))
    }

    /// Takes the rows of every replayed scope of `scopes` at `seal`, just
    /// finalized: the live rows with every open member undone.
    pub(in crate::replica) async fn take_seal_rows(
        &self,
        seal: Commitment,
        scopes: &[(ResourceScope, i64)],
    ) -> Result<(), Error> {
        let scopes: Vec<_> = scopes
            .iter()
            .copied()
            .filter(|(scope, _)| self.replayed_scope(*scope) && self.has_scope_key(*scope))
            .collect();
        if scopes.is_empty() {
            return Ok(());
        }
        let mut starts = Vec::new();
        for record in collect_rows(
            self.conn
                .query(
                    "SELECT DISTINCT scope FROM secure_replayed WHERE sealed=0",
                    (),
                )
                .await?,
        )
        .await?
        {
            let [SqlValue::Integer(scope)] = record.as_slice() else {
                return Err(Error::Corrupt("replayed member".into()));
            };
            if let Some(first) = self.first_open(*scope).await? {
                starts.push((*scope, first));
            }
        }
        let taken = if starts.is_empty() {
            self.images_of(&scopes).await?
        } else {
            // The rewind only reads the rows at the seal; it rolls back.
            self.conn.execute("SAVEPOINT seal_rows", ()).await?;
            let touched = self.take_oracle_state();
            let taken = async {
                self.rewind(starts).await?;
                self.images_of(&scopes).await
            }
            .await;
            self.restore_oracle_state(touched);
            self.conn.execute("ROLLBACK TO seal_rows", ()).await?;
            self.conn.execute("RELEASE seal_rows", ()).await?;
            taken?
        };
        for (id, images) in taken {
            self.conn
                .execute(
                    "INSERT OR REPLACE INTO secure_replayed_seals VALUES(?,?)",
                    bindings(vec![SqlValue::Integer(id), SqlValue::Blob(seal.to_vec())]),
                )
                .await?;
            self.conn
                .execute(
                    "DELETE FROM secure_replayed_seal_rows WHERE scope=? AND seal=?",
                    bindings(vec![SqlValue::Integer(id), SqlValue::Blob(seal.to_vec())]),
                )
                .await?;
            for (row, image) in images {
                self.conn
                    .execute(
                        "INSERT INTO secure_replayed_seal_rows VALUES(?,?,?,?)",
                        bindings(vec![
                            SqlValue::Integer(id),
                            SqlValue::Blob(seal.to_vec()),
                            SqlValue::Blob(row.to_vec()),
                            SqlValue::Blob(image),
                        ]),
                    )
                    .await?;
            }
        }
        Ok(())
    }
    async fn first_open(&self, scope: i64) -> Result<Option<Order>, Error> {
        collect_rows(
            self.conn
                .query(
                    "SELECT era,clock,author,sequence FROM secure_replayed WHERE scope=? AND sealed=0 ORDER BY era,clock,author,sequence LIMIT 1",
                    [scope],
                )
                .await?,
        )
        .await?
        .first()
        .map(|row| order_of(row))
        .transpose()
    }
    #[allow(clippy::type_complexity)]
    async fn images_of(
        &self,
        scopes: &[(ResourceScope, i64)],
    ) -> Result<Vec<(i64, Vec<(Commitment, Vec<u8>)>)>, Error> {
        let mut taken = Vec::with_capacity(scopes.len());
        for (scope, id) in scopes {
            taken.push((*id, self.replayed_images(*scope).await?));
        }
        Ok(taken)
    }

    /// The rows taken at `seal`; none when they were not taken.
    pub(in crate::replica) async fn seal_rows(
        &self,
        id: i64,
        seal: Commitment,
    ) -> Result<Option<Vec<(Commitment, Vec<u8>)>>, Error> {
        if collect_rows(
            self.conn
                .query(
                    "SELECT 1 FROM secure_replayed_seals WHERE scope=? AND seal=?",
                    bindings(vec![SqlValue::Integer(id), SqlValue::Blob(seal.to_vec())]),
                )
                .await?,
        )
        .await?
        .is_empty()
        {
            return Ok(None);
        }
        self.stored_images("secure_replayed_seal_rows", id, Some(seal))
            .await
            .map(Some)
    }
    /// The rows of `table`, `secure_replayed_base` or
    /// `secure_replayed_staged`, or of a seal, ordered by row id.
    pub(in crate::replica) async fn stored_images(
        &self,
        table: &str,
        id: i64,
        seal: Option<Commitment>,
    ) -> Result<Vec<(Commitment, Vec<u8>)>, Error> {
        let (sql, params) = match seal {
            Some(seal) => (
                format!("SELECT row,image FROM {table} WHERE scope=? AND seal=? ORDER BY row"),
                vec![SqlValue::Integer(id), SqlValue::Blob(seal.to_vec())],
            ),
            None => (
                format!("SELECT row,image FROM {table} WHERE scope=? ORDER BY row"),
                vec![SqlValue::Integer(id)],
            ),
        };
        collect_rows(self.conn.query(sql, bindings(params)).await?)
        .await?
        .into_iter()
        .map(|record| match record.as_slice() {
            [SqlValue::Blob(row), SqlValue::Blob(image)] => {
                Ok((super::super::checkpoint::row_of(row)?, image.clone()))
            }
            _ => Err(Error::Corrupt("replayed base row".into())),
        })
        .collect()
    }
    /// Makes `rows` the scope's replay base and forgets the seal rows of
    /// seals not finalized after `depth`.
    pub(in crate::replica) async fn store_base(
        &self,
        id: i64,
        rows: &[(Commitment, Vec<u8>)],
        depth: Option<i64>,
    ) -> Result<(), Error> {
        self.conn
            .execute("DELETE FROM secure_replayed_base WHERE scope=?", [id])
            .await?;
        for (row, image) in rows {
            self.conn
                .execute(
                    "INSERT INTO secure_replayed_base VALUES(?,?,?)",
                    bindings(vec![
                        SqlValue::Integer(id),
                        SqlValue::Blob(row.to_vec()),
                        SqlValue::Blob(image.clone()),
                    ]),
                )
                .await?;
        }
        self.forget_seal_rows(id, depth.unwrap_or(i64::MAX)).await
    }
    pub(in crate::replica) async fn forget_seal_rows(
        &self,
        id: i64,
        through: i64,
    ) -> Result<(), Error> {
        for table in ["secure_replayed_seals", "secure_replayed_seal_rows"] {
            self.conn
                .execute(
                    format!("DELETE FROM {table} WHERE scope=? AND seal NOT IN (SELECT seal FROM secure_finalized WHERE depth>?)"),
                    [id, through],
                )
                .await?;
        }
        Ok(())
    }
    /// `rows`, a base at a seal of tip `source`, as the scope's current
    /// typed rows: a field the table lacks, or one some tip since `source`
    /// lacked, takes its default.
    fn current_images(
        &self,
        scope: ResourceScope,
        source: TipId,
        rows: &[(Commitment, Vec<u8>)],
    ) -> Result<Vec<(Commitment, Vec<SqlValue>)>, Error> {
        let corrupt = || Error::Corrupt("replayed base image".into());
        let typed = self.workspace.typed.as_ref().ok_or_else(corrupt)?;
        let projected = typed.by_scope(scope).ok_or_else(corrupt)?;
        let columns = self.restored_columns(scope, source)?;
        rows.iter()
            .map(|(row, image)| {
                let fields = blob_fields(image)?;
                let image = columns
                    .iter()
                    .map(
                        |(id, kept, default)| match fields.get(id).filter(|_| *kept) {
                            Some(bytes) => {
                                SqlValue::decode(&mut bytes.as_slice()).map_err(|_| corrupt())
                            }
                            None => Ok(default.clone()),
                        },
                    )
                    .collect::<Result<Vec<_>, Error>>()?;
                if typed.row_scope(projected, &image)? != scope
                    || typed
                        .rows
                        .row_id(typed.domain.domain, &projected.table, &image)
                        .map_err(|_| corrupt())?
                        != *row
                {
                    return Err(denied("replayed base row differs from its scope"));
                }
                Ok((*row, image))
            })
            .collect()
    }
    /// Each column of scope `scope`'s table with its field id, whether rows
    /// at a seal of tip `source` keep it, and its default.
    fn restored_columns(
        &self,
        scope: ResourceScope,
        source: TipId,
    ) -> Result<Vec<(Commitment, bool, SqlValue)>, Error> {
        let corrupt = || Error::Corrupt("replayed base image".into());
        let typed = self.workspace.typed.as_ref().ok_or_else(corrupt)?;
        let projected = typed.by_scope(scope).ok_or_else(corrupt)?;
        let schema = typed.rows.schema();
        let logical = schema
            .table(&projected.table.sql_name)
            .ok_or_else(corrupt)?;
        let path = self
            .path_fields_to(scope.domain, source, self.workspace.tip)
            .ok();
        let declared: BTreeSet<_> = self
            .definition
            .fields
            .iter()
            .map(|field| field.id)
            .collect();
        Ok(logical
            .columns
            .iter()
            .map(|column| {
                let id = schema.field_id(logical, column);
                let kept = !declared.contains(&id)
                    || path.as_ref().is_none_or(|path| path.fields.contains(&id));
                let default = rocky_core::default_value(column).unwrap_or(SqlValue::Null);
                (id, kept, default)
            })
            .collect())
    }
    /// Whether `rows`, at a seal of tip `source`, carry every field the
    /// current table keeps from them. Rows taken under a schema off the
    /// path, as after an owner's rollback, may lack one.
    pub(in crate::replica) fn images_serve(
        &self,
        scope: ResourceScope,
        source: TipId,
        rows: &[(Commitment, Vec<u8>)],
    ) -> Result<bool, Error> {
        let kept: Vec<_> = self
            .restored_columns(scope, source)?
            .into_iter()
            .filter_map(|(id, kept, _)| kept.then_some(id))
            .collect();
        for (_, image) in rows {
            let fields = blob_fields(image)?;
            if kept.iter().any(|id| !fields.contains_key(id)) {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// Refuses base rows, at a seal of tip `source`, whose identity a
    /// signed mark does not cover.
    pub(in crate::replica) fn check_base_identities(
        &self,
        scope: ResourceScope,
        source: TipId,
        rows: &[(Commitment, Vec<u8>)],
        marks: &[crate::replica::checkpoint::CoveredMark],
    ) -> Result<(), Error> {
        let corrupt = || Error::Corrupt("replayed scope".into());
        let typed = self.workspace.typed.as_ref().ok_or_else(corrupt)?;
        let projected = typed.by_scope(scope).ok_or_else(corrupt)?;
        for (row, image) in self.current_images(scope, source, rows)? {
            let change = RowChange {
                scope,
                row,
                before: None,
                after: Some(
                    typed
                        .rows
                        .fields(&projected.table, &image)
                        .map_err(|_| corrupt())?,
                ),
            };
            if let Some(identity) = self
                .app
                .row_identity(&change)
                .map_err(|error| denied(&error))?
                && !marks.iter().any(|mark| {
                    mark.author == identity.author()
                        && mark.sequence >= identity.sequence()
                        && mark.own >= identity.sequence()
                })
            {
                return Err(denied("checkpoint identity exceeds its permanent mark"));
            }
        }
        Ok(())
    }
    /// Writes `rows`, a base at a seal of tip `source`, into the scope's
    /// replayed table, emptied first.
    pub(in crate::replica) async fn restore_images(
        &self,
        scope: ResourceScope,
        source: TipId,
        rows: &[(Commitment, Vec<u8>)],
    ) -> Result<(), Error> {
        let corrupt = || Error::Corrupt("replayed scope".into());
        let typed = self.workspace.typed.as_ref().ok_or_else(corrupt)?;
        let projected = typed.by_scope(scope).ok_or_else(corrupt)?;
        let table = typed
            .plan(&BTreeSet::from([scope]))?
            .tables
            .into_iter()
            .find(|table| table.name.eq_ignore_ascii_case(&projected.table.sql_name))
            .ok_or_else(corrupt)?;
        let images = self.current_images(scope, source, rows)?;
        self.touch(&table.name);
        self.conn
            .execute("PRAGMA defer_foreign_keys=ON", ())
            .await?;
        for (_, image) in images {
            self.conn
                .execute(&table.insert_image(), bindings(table.stored(&image)))
                .await?;
        }
        Ok(())
    }
}
