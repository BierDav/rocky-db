//! Local row counts and workspace filtering; signed replay bases stay immutable.
use super::checkpoint::Sets;
use super::*;

pub(super) const SCHEMA: &[&str] =
    &["CREATE TABLE IF NOT EXISTS secure_rebuild_scopes(scope BLOB PRIMARY KEY) WITHOUT ROWID"];

/// Each named projection table's stored row count.
pub async fn local_row_counts(
    path: &Path,
    tables: &[&str],
) -> Result<BTreeMap<String, u64>, Error> {
    super::check_replica_format(path).await?;
    let file = crate::sqlite::Connection::open_read_only(path)?;
    let mut counts = BTreeMap::new();
    for table in tables {
        let rows = file.rows(
            &format!("SELECT count(*) FROM {}", typed::quoted(table)),
            (),
        )?;
        let [crate::sqlite::Value::Integer(count)] =
            rows.first().map(Vec::as_slice).unwrap_or_default()
        else {
            return Err(Error::Corrupt("local row count".into()));
        };
        let count = u64::try_from(*count).map_err(|_| Error::Corrupt("local row count".into()))?;
        counts.insert((*table).to_owned(), count);
    }
    Ok(counts)
}

/// Each named projection table's row count and LtHash digest of its rows,
/// every column included in name order: replicas holding the same rows,
/// identities included, have equal digests whatever their history.
pub async fn local_table_digests(
    path: &Path,
    tables: &[&str],
) -> Result<BTreeMap<String, SetSummary>, Error> {
    super::check_replica_format(path).await?;
    let file = crate::sqlite::Connection::open_read_only(path)?;
    let mut digests = BTreeMap::new();
    for table in tables {
        let mut digest = super::checkpoint::Lt::new();
        let mut count = 0;
        let mut columns = Vec::new();
        for column in file.rows(
            &format!(
                "SELECT name FROM pragma_table_info({})",
                typed::quoted(table)
            ),
            (),
        )? {
            let [crate::sqlite::Value::Text(name)] = column.as_slice() else {
                return Err(Error::Corrupt("projection column".into()));
            };
            columns.push(typed::quoted(name));
        }
        columns.sort();
        for row in file.rows(
            &format!("SELECT {} FROM {}", columns.join(","), typed::quoted(table)),
            (),
        )? {
            let mut bytes = Vec::new();
            for value in row {
                storage::sql_value(value)?.encode(&mut bytes);
            }
            digest.add(super::checkpoint::ROW_LABEL, &bytes);
            count += 1;
        }
        digests.insert(
            (*table).to_owned(),
            SetSummary {
                count,
                digest: digest.digest(),
            },
        );
    }
    Ok(digests)
}

impl<A: RowApplication> Inner<A> {
    pub(super) async fn keep_current(
        &self,
        id: i64,
        scope: ResourceScope,
        project: bool,
    ) -> Result<bool, Error> {
        let source = self
            .checkpoint_record(id, true)
            .await?
            .and_then(|record| record.signed)
            .map_or(self.workspace.tip, |signed| signed.statement.tip);
        let fields = self.path_fields(scope.domain, source)?;
        let mut after = Vec::new();
        let mut changed = false;
        loop {
            let records = collect_rows(self.conn.query("SELECT row,fields FROM secure_row_records WHERE scope=? AND row>? ORDER BY row LIMIT 256", [encode(&scope)?, after.clone()]).await?).await?;
            for record in &records {
                let [SqlValue::Blob(key), SqlValue::Blob(bytes)] = record.as_slice() else {
                    return Err(Error::Corrupt("stored row".into()));
                };
                after = key.clone();
                let mut row = self.decode_record(bytes).await?;
                if !fields.tables.contains(&scope.table) {
                    self.conn
                        .execute(
                            "DELETE FROM secure_row_records WHERE scope=? AND row=?",
                            [encode(&scope)?, key.clone()],
                        )
                        .await?;
                    changed = true;
                } else if fields.strip(scope.table, &mut row) {
                    self.conn
                        .execute(
                            "UPDATE secure_row_records SET fields=? WHERE scope=? AND row=?",
                            [
                                self.encode_record(&row).await?,
                                encode(&scope)?,
                                key.clone(),
                            ],
                        )
                        .await?;
                    changed = true;
                }
            }
            if records.len() < 256 {
                break;
            }
        }
        if changed {
            self.recount(id, scope).await?;
            if project {
                self.reproject(scope).await?;
            }
        }
        Ok(changed)
    }
    /// Recomputes a scope's row counts and digest from its stored rows.
    pub(super) async fn recount(&self, id: i64, scope: ResourceScope) -> Result<(), Error> {
        let blob = encode(&scope)?;
        let mut sets = Sets::new();
        let mut after = Vec::new();
        loop {
            let page = collect_rows(
                self.conn
                    .query(
                        "SELECT row,fields FROM secure_row_records WHERE scope=? AND row>? ORDER BY row LIMIT 256",
                        bindings(vec![SqlValue::Blob(blob.clone()), SqlValue::Blob(after.clone())]),
                    )
                    .await?,
            )
            .await?;
            for record in &page {
                let [SqlValue::Blob(row), SqlValue::Blob(bytes)] = record.as_slice() else {
                    return Err(Error::Corrupt("stored row".into()));
                };
                after = row.clone();
                sets.replace_stored(self, &checkpoint::row_of(row)?, None, bytes)
                    .await?;
            }
            if page.len() < 256 {
                break;
            }
        }
        let applied = self.scope_state(id).await?.3;
        self.store_scope_state(id, sets.rows, sets.tombstones, &sets.digest, applied)
            .await
    }
    pub(super) async fn rebuild_voided_in_transaction(&self) -> Result<(), Error> {
        for row in rows(&self.conn, "SELECT scope FROM secure_rebuild_scopes").await? {
            let [SqlValue::Blob(bytes)] = row.as_slice() else {
                return Err(Error::Corrupt("voided scope".into()));
            };
            let scope: ResourceScope = decode(bytes)?;
            if !self.config.keys.iter().any(|key| key.scope == scope) {
                continue;
            }
            self.conn
                .execute(
                    "DELETE FROM secure_rebuild_scopes WHERE scope=?",
                    [bytes.clone()],
                )
                .await?;
            if self.tables.contains(&scope.table) {
                self.rebuild_rows(scope).await?;
            }
            if let Some(id) = self.find_scope_id(scope).await? {
                self.reseed_ledger(scope, id).await?;
            }
        }
        Ok(())
    }
    pub(super) async fn rebuild_voided(&mut self) -> Result<(), Error> {
        transaction!(self, |inner| inner.rebuild_voided_in_transaction().await)
    }
}
