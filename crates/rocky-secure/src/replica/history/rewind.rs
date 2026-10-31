//! Stored rows' history and the switch that restores from it. While a seal
//! is kept, a change to a stored row writes the version it replaces, as the
//! live tables' history does; a tip whose path passes a kept seal then
//! starts from that seal's rows plus the operations after it. See
//! `docs/runtime/kept-seals.md#switching-tips`.
use super::*;
use checkpoint::{Overlay, STEP_OPERATIONS, STEP_ROWS, Sets};

/// A scope's id and the last applied position a kept seal includes.
pub(in crate::replica) type KeptBound = (i64, i64);

macro_rules! clock {
    () => {
        "COALESCE((SELECT version FROM secure_kept_clock WHERE id=1),1)"
    };
}
macro_rules! active {
    () => {
        "EXISTS(SELECT 1 FROM secure_kept_marks) AND COALESCE((SELECT rows_paused FROM secure_kept_clock WHERE id=1),0)=0"
    };
}
/// Whether a kept seal may still see the version at `$image`'s key.
macro_rules! needed {
    ($image:literal) => {
        concat!(
            "EXISTS(SELECT 1 FROM secure_kept_marks WHERE mark>=COALESCE((SELECT MAX(p.version) FROM secure_stored_history AS p WHERE p.scope=(SELECT scope FROM secure_scope_state WHERE id=",
            $image,
            ".scope) AND p.row=",
            $image,
            ".row),-1))"
        )
    };
}

/// A stored row's replaced versions; no `fields` where it was absent.
pub(super) const ROWS: &str = "CREATE TABLE IF NOT EXISTS secure_stored_history(scope BLOB NOT NULL,row BLOB NOT NULL,version INTEGER NOT NULL,fields BLOB,PRIMARY KEY(scope,row,version)) WITHOUT ROWID";
pub(super) const ROWS_BY_VERSION: &str = "CREATE INDEX IF NOT EXISTS secure_stored_history_version ON secure_stored_history(scope,version)";
pub(super) const ROWS_DELETE: &str = concat!(
    "CREATE TRIGGER IF NOT EXISTS secure_kept_rows_delete BEFORE DELETE ON secure_rows FOR EACH ROW WHEN ",
    active!(),
    " BEGIN INSERT OR IGNORE INTO secure_stored_history SELECT (SELECT scope FROM secure_scope_state WHERE id=OLD.scope),OLD.row,",
    clock!(),
    ",OLD.fields WHERE ",
    needed!("OLD"),
    "; END"
);
pub(super) const ROWS_UPDATE: &str = concat!(
    "CREATE TRIGGER IF NOT EXISTS secure_kept_rows_update BEFORE UPDATE OF fields ON secure_rows FOR EACH ROW WHEN ",
    active!(),
    " AND OLD.fields IS NOT NEW.fields BEGIN INSERT OR IGNORE INTO secure_stored_history SELECT (SELECT scope FROM secure_scope_state WHERE id=OLD.scope),OLD.row,",
    clock!(),
    ",OLD.fields WHERE ",
    needed!("OLD"),
    "; END"
);
// An upsert or a replace changes the row at the key without an update or
// delete trigger of its own.
pub(super) const ROWS_INSERT: &str = concat!(
    "CREATE TRIGGER IF NOT EXISTS secure_kept_rows_insert BEFORE INSERT ON secure_rows FOR EACH ROW WHEN ",
    active!(),
    " BEGIN INSERT OR IGNORE INTO secure_stored_history SELECT (SELECT scope FROM secure_scope_state WHERE id=NEW.scope),NEW.row,",
    clock!(),
    ",NULL WHERE NOT EXISTS(SELECT 1 FROM secure_rows AS r WHERE r.scope=NEW.scope AND r.row=NEW.row) AND ",
    needed!("NEW"),
    "; INSERT OR IGNORE INTO secure_stored_history SELECT (SELECT scope FROM secure_scope_state WHERE id=r.scope),r.row,",
    clock!(),
    ",r.fields FROM secure_rows AS r WHERE r.scope=NEW.scope AND r.row=NEW.row AND r.fields IS NOT NEW.fields AND ",
    needed!("r"),
    "; END"
);
/// Deletes the stored versions no kept seal needs any more.
pub(super) const PRUNE_ROWS: &str = "DELETE FROM secure_stored_history WHERE NOT EXISTS(SELECT 1 FROM secure_kept_marks AS k WHERE k.mark<secure_stored_history.version AND k.mark>=COALESCE((SELECT MAX(p.version) FROM secure_stored_history AS p WHERE p.scope=secure_stored_history.scope AND p.row=secure_stored_history.row AND p.version<secure_stored_history.version),-1))";


const BEFORE: &str = "secure_stored_history_before";

/// A kept seal stored rows rebuild from.
pub(in crate::replica) struct Rewind {
    seal: Commitment,
    mark: i64,
    bounds: Vec<KeptBound>,
}
impl Rewind {
    pub(in crate::replica) fn mark(&self) -> (Commitment, i64) {
        (self.seal, self.mark)
    }
    /// The seal's mark and scope `id`'s bound there.
    pub(in crate::replica) fn at(&self, id: i64) -> Option<(i64, i64)> {
        self.bounds
            .iter()
            .find(|(known, _)| *known == id)
            .map(|(_, bound)| (self.mark, *bound))
    }
}

impl<A: RowApplication> Inner<A> {
    /// Runs `work`, a bulk replacement of `scope`'s stored rows, recording
    /// what it changes in history at the end rather than row by row.
    pub(in crate::replica) async fn in_rows_bulk<T>(
        &self,
        scope: ResourceScope,
        work: impl std::future::Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        let blob = encode(&scope)?;
        let active = self.begin_rows_bulk(&blob).await?;
        let result = work.await;
        if active {
            match &result {
                Ok(_) => self.end_rows_bulk(&blob, true).await?,
                // The failed replacement's transaction rolls the copy back.
                Err(_) => {
                    let _ = self.end_rows_bulk(&blob, false).await;
                }
            }
        }
        result
    }
    async fn begin_rows_bulk(&self, blob: &[u8]) -> Result<bool, Error> {
        let paused = rows(
            &self.conn,
            "SELECT 1 FROM secure_kept_marks WHERE COALESCE((SELECT rows_paused FROM secure_kept_clock WHERE id=1),0)=0 LIMIT 1",
        )
        .await?;
        // Nothing is kept, or an enclosing replacement records.
        if paused.is_empty() {
            return Ok(false);
        }
        for sql in [
            format!("DROP TABLE IF EXISTS temp.{BEFORE}"),
            format!(
                "CREATE TEMP TABLE {BEFORE}(scope BLOB NOT NULL,row BLOB NOT NULL,fields BLOB,PRIMARY KEY(scope,row)) WITHOUT ROWID"
            ),
        ] {
            self.conn.execute(sql, ()).await?;
        }
        self.conn
            .execute(
                format!("INSERT INTO temp.{BEFORE} SELECT scope,row,fields FROM main.secure_row_records WHERE scope=?"),
                [blob.to_vec()],
            )
            .await?;
        self.conn
            .execute(
                "INSERT INTO secure_kept_clock(id,version,paused,rows_paused) VALUES(1,1,0,1) ON CONFLICT(id) DO UPDATE SET rows_paused=1",
                (),
            )
            .await?;
        Ok(true)
    }
    async fn end_rows_bulk(&self, blob: &[u8], record: bool) -> Result<(), Error> {
        if record {
            for sql in [
                concat!(
                    "INSERT OR IGNORE INTO main.secure_stored_history SELECT b.scope,b.row,",
                    clock!(),
                    ",b.fields FROM temp.secure_stored_history_before AS b WHERE NOT EXISTS(SELECT 1 FROM main.secure_row_records AS a WHERE a.scope=b.scope AND a.row=b.row AND a.fields IS b.fields) AND ",
                    needed!("b")
                ),
                concat!(
                    "INSERT OR IGNORE INTO main.secure_stored_history SELECT a.scope,a.row,",
                    clock!(),
                    ",NULL FROM main.secure_row_records AS a WHERE a.scope=?1 AND NOT EXISTS(SELECT 1 FROM temp.secure_stored_history_before AS b WHERE b.scope=a.scope AND b.row=a.row) AND ",
                    needed!("a")
                ),
            ] {
                let parameters = if sql.contains("?1") {
                    vec![SqlValue::Blob(blob.to_vec())]
                } else {
                    Vec::new()
                };
                self.conn.execute(sql, bindings(parameters)).await?;
            }
        }
        self.conn
            .execute(format!("DROP TABLE IF EXISTS temp.{BEFORE}"), ())
            .await?;
        self.conn
            .execute("UPDATE secure_kept_clock SET rows_paused=0 WHERE id=1", ())
            .await?;
        Ok(())
    }
    /// Kept `seal`'s mark and bounds, when it was kept under the installed
    /// schema.
    pub(in crate::replica) async fn kept_rewind(
        &self,
        seal: Commitment,
    ) -> Result<Option<Rewind>, Error> {
        self.kept_at(seal, Some(self.manifest)).await
    }
    /// Kept `seal`'s mark and bounds under `manifest`, or under any schema:
    /// views read its frozen copies, whichever schema kept them.
    pub(in crate::replica) async fn kept_at(
        &self,
        seal: Commitment,
        manifest: Option<Commitment>,
    ) -> Result<Option<Rewind>, Error> {
        match collect_rows(
            self.conn
                .query(
                    "SELECT mark,bounds FROM secure_kept_marks WHERE seal=?1 AND (?2 IS NULL OR manifest=?2)",
                    bindings(vec![
                        SqlValue::Blob(seal.to_vec()),
                        manifest.map_or(SqlValue::Null, |manifest| SqlValue::Blob(manifest.to_vec())),
                    ]),
                )
                .await?,
        )
        .await?
        .first()
        .map(Vec::as_slice)
        {
            Some([SqlValue::Integer(mark), SqlValue::Blob(bounds)]) => Ok(Some(Rewind {
                seal,
                mark: *mark,
                bounds: decode(bounds)?,
            })),
            None => Ok(None),
            _ => Err(Error::Corrupt("kept seal".into())),
        }
    }
    /// The kept seal a switch to the followed tip restores, with its mark
    /// and bounds: the newest finalized on the tip's path that was kept
    /// under the installed schema.
    pub(in crate::replica) async fn rewind_seal(
        &self,
        domain: Scope,
    ) -> Result<Option<Rewind>, Error> {
        let path = self
            .path_seals(domain)?
            .iter()
            .map(|seal| seal.id().map_err(credential))
            .collect::<Result<BTreeSet<_>, _>>()?;
        for record in rows(
            &self.conn,
            "SELECT seal,mark,manifest,bounds FROM secure_kept_marks ORDER BY mark DESC",
        )
        .await?
        {
            let [
                SqlValue::Blob(seal),
                SqlValue::Integer(mark),
                SqlValue::Blob(manifest),
                SqlValue::Blob(bounds),
            ] = record.as_slice()
            else {
                return Err(Error::Corrupt("kept seal".into()));
            };
            let seal = checkpoint::row_of(seal)?;
            // Its rows are restored unfiltered: a path that removed a field
            // since, even one re-added in the same schema, replays instead.
            if path.contains(&seal)
                && manifest.as_slice() == self.manifest.as_slice()
                && !self
                    .path_fields(
                        domain,
                        self.graph_for(domain)?
                            .seal_by_id(seal)
                            .map_err(credential)?
                            .statement
                            .tip,
                    )?
                    .strips(&self.definition)
                && self.finalized_depth(domain, seal).await?.is_some()
            {
                return Ok(Some(Rewind {
                    seal,
                    mark: *mark,
                    bounds: decode(bounds)?,
                }));
            }
        }
        Ok(None)
    }
    /// Whether scope `id` rebuilds from a kept seal of the followed path:
    /// its replay base, if any, lies on the path before it.
    pub(in crate::replica) async fn rewinds(
        &self,
        scope: ResourceScope,
        id: i64,
    ) -> Result<bool, Error> {
        Ok(match self.checkpoint_record(id, true).await? {
            None => true,
            Some(record) => record
                .signed
                .and_then(|signed| signed.statement.seal)
                .is_some_and(|seal| {
                    self.path_index(scope.domain, seal)
                        .is_ok_and(|at| at.is_some())
                }),
        })
    }
    /// Inside the caller's transaction, rebuilds scope `id`'s stored rows
    /// from the kept seal marked `mark`, whose state included its applied
    /// positions through `bound`: rows changed since are restored from
    /// history, the operations in `(bound, through]` replay on top, those
    /// of the followed tip only for a `tip` switch, and only rows that
    /// differ from the live ones are written and projected. `ledger` holds
    /// the identity marks of the kept state. Returns the row ids of every
    /// row it looked at.
    pub(in crate::replica) async fn rewind_rows(
        &mut self,
        scope: ResourceScope,
        id: i64,
        (mark, bound): (i64, i64),
        through: i64,
        tip: bool,
        mut ledger: identity::IdentityLedger,
    ) -> Result<BTreeSet<i64>, Error> {
        let blob = encode(&scope)?;
        self.conn
            .execute("DELETE FROM secure_checkpoint_scratch WHERE scope=?", [id])
            .await?;
        self.conn
            .execute(
                "INSERT INTO secure_checkpoint_scratch SELECT ?1,h.row,COALESCE(h.fields,X'') FROM secure_stored_history AS h WHERE h.scope=?2 AND h.version>?3 AND h.version=(SELECT MIN(p.version) FROM secure_stored_history AS p WHERE p.scope=h.scope AND p.row=h.row AND p.version>?3)",
                bindings(vec![
                    SqlValue::Integer(id),
                    SqlValue::Blob(blob.clone()),
                    SqlValue::Integer(mark),
                ]),
            )
            .await?;
        // The replay's own fold is not used: the difference below is.
        let mut fold = Sets {
            rows: u64::MAX / 2,
            tombstones: u64::MAX / 2,
            ..Sets::new()
        };
        let rebuilding = std::mem::replace(&mut self.rebuilding_tip, tip);
        let replayed = async {
            let mut cursor = bound;
            while let Some(last) = self
                .replay_sealed(
                    scope,
                    id,
                    Overlay::Rewind,
                    self.workspace.tip,
                    (cursor, through),
                    STEP_OPERATIONS,
                    &mut fold,
                    &mut ledger,
                    checkpoint::ReplayMode::Mint,
                )
                .await?
            {
                cursor = last;
            }
            Ok::<_, Error>(())
        }
        .await;
        self.rebuilding_tip = rebuilding;
        replayed?;
        let (count, tombstones, digest, applied) = self.scope_state(id).await?;
        let mut sets = Sets::new();
        (sets.rows, sets.tombstones, sets.digest) = (count, tombstones, digest);
        let mut touched = BTreeSet::new();
        let mut after = Vec::new();
        loop {
            let chunk = collect_rows(
                self.conn
                    .query(
                        "SELECT s.row,s.fields,r.fields FROM secure_checkpoint_scratch AS s LEFT JOIN secure_row_records AS r ON r.scope=?1 AND r.row=s.row WHERE s.scope=?2 AND s.row>?3 ORDER BY s.row LIMIT ?4",
                        bindings(vec![
                            SqlValue::Blob(blob.clone()),
                            SqlValue::Integer(id),
                            SqlValue::Blob(after.clone()),
                            SqlValue::Integer(STEP_ROWS as i64),
                        ]),
                    )
                    .await?,
            )
            .await?;
            for record in &chunk {
                let (row, new, old) = match record.as_slice() {
                    [SqlValue::Blob(row), SqlValue::Blob(new), old] => (
                        row.clone(),
                        (!new.is_empty()).then(|| new.clone()),
                        match old {
                            SqlValue::Blob(old) => Some(old.clone()),
                            SqlValue::Null => None,
                            _ => return Err(Error::Corrupt("stored row".into())),
                        },
                    ),
                    _ => return Err(Error::Corrupt("rewound row".into())),
                };
                after = row.clone();
                for record in [&old, &new].into_iter().flatten() {
                    touched.extend(self.decode_record(record).await?.identity);
                }
                if new == old {
                    continue;
                }
                let key = checkpoint::row_of(&row)?;
                match (&old, &new) {
                    (Some(old), None) => {
                        sets.remove_stored(self, &key, old).await?;
                        for sql in [
                            "DELETE FROM secure_row_records WHERE scope=? AND row=?",
                            "DELETE FROM secure_move_rows WHERE scope=? AND row=?",
                        ] {
                            self.conn.execute(sql, [blob.clone(), row.clone()]).await?;
                        }
                    }
                    (old, Some(new)) => {
                        sets.replace_stored(self, &key, old.as_deref(), new).await?;
                        self.conn
                            .execute(
                                "INSERT INTO secure_row_records VALUES(?,?,?)",
                                [blob.clone(), row.clone(), new.clone()],
                            )
                            .await?;
                        self.index_row_key(&blob, &row, None, &self.decode_record(new).await?)
                            .await?;
                    }
                    (None, None) => continue,
                }
            }
            if chunk.len() < STEP_ROWS {
                break;
            }
        }
        self.store_scope_state(id, sets.rows, sets.tombstones, &sets.digest, applied)
            .await?;
        self.conn
            .execute("DELETE FROM secure_checkpoint_scratch WHERE scope=?", [id])
            .await?;
        self.conn
            .execute(
                "UPDATE secure_metadata SET revision=revision+1 WHERE id=1",
                (),
            )
            .await?;
        Ok(touched)
    }
}
