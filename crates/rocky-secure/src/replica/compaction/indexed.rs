//! Indexed seal cuts and projection differences.
use super::*;

pub(in crate::replica) async fn check_schema(conn: &ScopedConnection) -> Result<(), Error> {
    for sql in crate::store::SCHEMA
        .iter()
        .chain(records::SCHEMA)
        .chain(records::SHAPE_SCHEMA)
        .chain(checkpoint::SCHEMA)
        .filter(|sql| {
            sql.contains("secure_shapes_")
                || sql.contains("secure_scope_shapes")
                || sql.contains("secure_record_shapes")
                || sql.contains("secure_record_shape_fields")
                || sql.contains("secure_rows_shape")
                || sql.contains("secure_birth_position")
                || sql.contains("secure_rows(")
                || sql.contains("secure_rows_dead ")
                || sql.contains("secure_row_positions")
                || sql.contains("secure_row_position_operations")
                || sql.contains("secure_finalization_rows")
                || sql.contains("secure_seal_operation_positions")
        })
    {
        let sql = sql.replace(" IF NOT EXISTS", "");
        let name = sql
            .split_whitespace()
            .nth(2)
            .unwrap_or_default()
            .split('(')
            .next()
            .unwrap_or_default();
        let actual = collect_rows(
            conn.query("SELECT sql FROM sqlite_schema WHERE name=?", [name])
                .await?,
        )
        .await?;
        if actual != vec![vec![SqlValue::Text(sql.clone())]] {
            return Err(Error::Corrupt(format!(
                "incremental finalization schema differs: {name}"
            )));
        }
    }
    Ok(())
}

impl<A: RowApplication> Inner<A> {
    /// Clips affine log runs against the seal before looking up applied positions.
    pub(super) async fn indexed_seal_cut(
        &self,
        scope: ResourceScope,
        id: i64,
        bound: i64,
        seal: &SignedSeal,
    ) -> Result<(i64, Vec<(i64, Vec<u8>)>), Error> {
        let last = collect_rows(
            self.conn
                .query(
                    "SELECT COALESCE(MAX(position),0) FROM secure_applied WHERE scope=?",
                    [id],
                )
                .await?,
        )
        .await?;
        let Some([SqlValue::Integer(last)]) = last.first().map(Vec::as_slice) else {
            return Err(Error::Corrupt("applied scope positions".into()));
        };
        if *last <= bound {
            return Ok((bound, Vec::new()));
        }
        let graph = self.graph_for(scope.domain)?;
        let blob = encode(&scope)?;
        let runs = collect_rows(self.conn.query("SELECT tip,domain_author,min(start+delta),max(end+delta) FROM secure_log_ranges WHERE scope=? AND applied=1 GROUP BY tip,domain_author", [blob.clone()]).await?).await?;
        let mut excluded = BTreeMap::new();
        for run in runs {
            let [
                SqlValue::Blob(tip),
                SqlValue::Integer(author),
                SqlValue::Integer(start),
                SqlValue::Integer(end),
            ] = run.as_slice()
            else {
                return Err(Error::Corrupt("seal position run".into()));
            };
            let source = TipId(checkpoint::row_of(tip)?);
            let path = Self::frame_path(graph, source, seal.statement.tip)?;
            let author_number = u32::try_from(*author)
                .map_err(|_| Error::Corrupt("seal position author".into()))?;
            if *start < 0 || end < start {
                return Err(Error::Corrupt("seal position run bounds".into()));
            }
            let admits = |sequence: i64| path.admits(author_number, sequence as u64);
            let cut = if !admits(*start)? {
                start - 1
            } else if admits(*end)? {
                *end
            } else {
                let (mut low, mut high) = (*start, *end);
                while low < high {
                    let distance = high - low;
                    let mid = low + distance / 2 + distance % 2;
                    if admits(mid)? {
                        low = mid;
                    } else {
                        high = mid - 1;
                    }
                }
                low
            };
            let params = vec![
                SqlValue::Blob(blob.clone()),
                SqlValue::Blob(tip.clone()),
                SqlValue::Integer(*author),
                SqlValue::Integer(cut),
                SqlValue::Integer(id),
                SqlValue::Integer(bound),
            ];
            if cut >= *end {
                continue;
            }
            for row in collect_rows(self.conn.query("SELECT a.position,a.hash FROM secure_position_sources p JOIN secure_applied a ON a.hash=p.hash WHERE p.scope=?1 AND p.tip=?2 AND p.author=?3 AND p.sequence>?4 AND p.kind=0 AND a.scope=?5 AND a.position>?6", bindings(params)).await?).await? {
                let [SqlValue::Integer(position), SqlValue::Blob(hash)] = row.as_slice() else { return Err(Error::Corrupt("seal excluded position".into())) };
                excluded.insert(*position, hash.clone());
            }
        }
        let latest = collect_rows(self.conn.query("SELECT position FROM secure_applied WHERE scope=? AND position>? ORDER BY position DESC LIMIT ?", [id, bound, i64::try_from(excluded.len()).map_err(|_| Error::Corrupt("excluded position count".into()))?.saturating_add(1)]).await?).await?;
        let mut through = bound;
        for row in latest {
            let [SqlValue::Integer(position)] = row.as_slice() else {
                return Err(Error::Corrupt("seal included position".into()));
            };
            if !excluded.contains_key(position) {
                through = *position;
                break;
            }
        }
        Ok((through, excluded.into_iter().collect()))
    }
}

impl<A: RowApplication> Inner<A> {
    /// Whether the scope stored as `id` holds a tombstone to drop.
    pub(super) async fn has_indexed_seal_drops(&self, id: i64) -> Result<bool, Error> {
        Ok(!collect_rows(
            self.conn
                .query(
                    "SELECT 1 FROM secure_rows WHERE scope=? AND live=0 LIMIT 1",
                    [id],
                )
                .await?,
        )
        .await?
        .is_empty())
    }
}
