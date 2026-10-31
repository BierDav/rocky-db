//! Restore affected rows and replay the excluded tail.
use super::*;

impl<A: RowApplication> Inner<A> {
    /// Replaces one authoritative row and its digest contribution together.
    pub(super) async fn replace_seal_row(
        &self,
        scope: ResourceScope,
        row: Commitment,
        next: Option<&[u8]>,
    ) -> Result<(), Error> {
        let id = self.scope_id(scope).await?;
        let old = self.row(scope, row).await?;
        let new = self.optional_record(next).await?;
        if old.as_ref().map(encode).transpose()? == new.as_ref().map(encode).transpose()? {
            return Ok(());
        }
        let (rows, tombstones, digest, applied) = self.scope_state(id).await?;
        let mut sets = Sets::new();
        (sets.rows, sets.tombstones, sets.digest) = (rows, tombstones, digest);
        let old_bytes = old.as_ref().map(encode).transpose()?;
        match &new {
            Some(new) => {
                sets.replace(&row, old_bytes.as_deref(), &encode(new)?)?;
                self.conn
                    .execute(
                        "INSERT INTO secure_row_records VALUES(?,?,?)",
                        [
                            encode(&scope)?,
                            row.to_vec(),
                            next.ok_or_else(|| Error::Corrupt("replacement row".into()))?
                                .to_vec(),
                        ],
                    )
                    .await?;
                self.index_row_key(&encode(&scope)?, &row, None, new)
                    .await?;
            }
            None => {
                if let Some(old) = &old_bytes {
                    sets.remove(&row, old)?;
                }
                self.conn
                    .execute(
                        "DELETE FROM secure_row_records WHERE scope=? AND row=?",
                        [encode(&scope)?, row.to_vec()],
                    )
                    .await?;
            }
        }
        self.store_scope_state(id, sets.rows, sets.tombstones, &sets.digest, applied)
            .await?;
        Ok(())
    }

    /// Replays only selected rows, starting at their checkpoint records.
    pub(super) async fn restore_seal_rows(
        &self,
        scope: ResourceScope,
        through: i64,
    ) -> Result<(), Error> {
        let id = self.scope_id(scope).await?;
        let selected = collect_rows(
            self.conn
                .query(
                    "SELECT row FROM secure_finalization_rows WHERE scope=? ORDER BY row",
                    [id],
                )
                .await?,
        )
        .await?;
        if selected.is_empty() {
            return Ok(());
        }
        self.conn
            .execute("DELETE FROM secure_checkpoint_scratch WHERE scope=?", [id])
            .await?;
        let base = self.checkpoint_record(id, true).await?;
        let (mut cursor, mut ledger) = match &base {
            Some(base) => {
                let signed = self.verify_record(scope, base)?;
                (
                    base.position,
                    identity::IdentityLedger::based(&signed.statement.identities)?,
                )
            }
            None => (0, identity::IdentityLedger::default()),
        };
        let fields = match &base {
            Some(base) => Some(self.path_fields_to(
                scope.domain,
                self.verify_record(scope, base)?.statement.tip,
                self.workspace.tip,
            )?),
            None => None,
        };
        let mut sets = Sets::new();
        for record in &selected {
            let [SqlValue::Blob(row)] = record.as_slice() else {
                return Err(Error::Corrupt("selected seal row".into()));
            };
            let row = checkpoint::row_of(row)?;
            let mut bytes = self.replay_row(Overlay::Scratch, id, row).await?;
            if let (Some(fields), Some(old)) = (&fields, &bytes) {
                bytes = self.strip_stored_record(fields, scope.table, old).await?;
            }
            if let Some(bytes) = &bytes {
                sets.replace_stored(self, &row, None, bytes).await?;
            }
            self.conn
                .execute(
                    "INSERT INTO secure_checkpoint_scratch VALUES(?,?,?)",
                    bindings(vec![
                        SqlValue::Integer(id),
                        SqlValue::Blob(row.to_vec()),
                        SqlValue::Blob(bytes.unwrap_or_default()),
                    ]),
                )
                .await?;
        }
        let mut bounds = self.seal_bounds(id).await?;
        bounds.retain(|(_, bound)| *bound >= cursor && *bound <= through);
        // The final segment also runs when there are no earlier seal bounds.
        bounds.push((i64::MAX, through));
        for (depth, end) in bounds {
            while let Some(last) = self
                .replay(
                    scope,
                    id,
                    Overlay::Scratch,
                    self.workspace.tip,
                    (cursor, end),
                    STEP_OPERATIONS,
                    &mut sets,
                    &mut ledger,
                    checkpoint::ReplayMode::Rows,
                )
                .await?
            {
                cursor = last;
            }
            cursor = end;
            if depth != i64::MAX {
                let drops = collect_rows(self.conn.query("SELECT d.row,d.fields FROM secure_seal_drops d JOIN secure_finalization_rows r ON r.scope=d.scope AND r.row=d.row WHERE d.scope=? AND d.depth=?", [id, depth]).await?).await?;
                for drop in drops {
                    let [SqlValue::Blob(row), fields] = drop.as_slice() else {
                        return Err(Error::Corrupt("selected seal drop".into()));
                    };
                    let key = checkpoint::row_of(row)?;
                    let old = self.replay_row(Overlay::Scratch, id, key).await?;
                    let next = match fields {
                        SqlValue::Blob(bytes) => bytes.clone(),
                        SqlValue::Null => Vec::new(),
                        _ => return Err(Error::Corrupt("selected seal drop".into())),
                    };
                    if next.is_empty() {
                        if let Some(old) = old {
                            sets.remove_stored(self, &key, &old).await?;
                        }
                    } else {
                        sets.replace_stored(self, &key, old.as_deref(), &next)
                            .await?;
                    }
                    self.conn
                        .execute(
                            "INSERT OR REPLACE INTO secure_checkpoint_scratch VALUES(?,?,?)",
                            bindings(vec![
                                SqlValue::Integer(id),
                                SqlValue::Blob(row.clone()),
                                SqlValue::Blob(next),
                            ]),
                        )
                        .await?;
                }
            }
        }
        for record in selected {
            let [SqlValue::Blob(row)] = record.as_slice() else {
                return Err(Error::Corrupt("selected seal row".into()));
            };
            let key = checkpoint::row_of(row)?;
            let next = self.replay_row(Overlay::Scratch, id, key).await?;
            self.replace_seal_row(scope, key, next.as_deref()).await?;
        }
        self.conn
            .execute("DELETE FROM secure_checkpoint_scratch WHERE scope=?", [id])
            .await?;
        Ok(())
    }
}
impl<A: RowApplication> Inner<A> {
    /// The sealed records are already installed; only excluded operations follow.
    pub(super) async fn replay_seal_tail(
        &self,
        scope: ResourceScope,
        through: i64,
    ) -> Result<(), Error> {
        let id = self.scope_id(scope).await?;
        self.conn
            .execute("DELETE FROM secure_checkpoint_scratch WHERE scope=?", [id])
            .await?;
        self.conn.execute("INSERT INTO secure_checkpoint_scratch SELECT r.scope,r.row,COALESCE(s.fields,X'') FROM secure_finalization_rows r LEFT JOIN secure_rows s ON s.scope=r.scope AND s.row=r.row WHERE r.scope=?", [id]).await?;
        let mut sets = Sets::new();
        let records = collect_rows(self.conn.query("SELECT row,fields FROM secure_checkpoint_scratch WHERE scope=? AND fields<>X''", [id]).await?).await?;
        for record in records {
            let [SqlValue::Blob(row), SqlValue::Blob(bytes)] = record.as_slice() else {
                return Err(Error::Corrupt("sealed tail row".into()));
            };
            sets.replace_stored(self, &checkpoint::row_of(row)?, None, bytes)
                .await?;
        }
        let mut ledger = identity::IdentityLedger::default();
        let mut cursor = through;
        while let Some(last) = self
            .replay(
                scope,
                id,
                Overlay::Scratch,
                self.workspace.tip,
                (cursor, i64::MAX),
                STEP_OPERATIONS,
                &mut sets,
                &mut ledger,
                checkpoint::ReplayMode::Rows,
            )
            .await?
        {
            cursor = last;
        }
        let selected = collect_rows(
            self.conn
                .query(
                    "SELECT row FROM secure_finalization_rows WHERE scope=?",
                    [id],
                )
                .await?,
        )
        .await?;
        for row in selected {
            let [SqlValue::Blob(row)] = row.as_slice() else {
                return Err(Error::Corrupt("tail row position".into()));
            };
            let key = checkpoint::row_of(row)?;
            let next = self.replay_row(Overlay::Scratch, id, key).await?;
            self.replace_seal_row(scope, key, next.as_deref()).await?;
        }
        self.conn
            .execute("DELETE FROM secure_checkpoint_scratch WHERE scope=?", [id])
            .await?;
        Ok(())
    }
}
