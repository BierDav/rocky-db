use super::*;

pub(super) const SCHEMA: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS secure_operation_scope_hash ON secure_operations(scope,hash)",
    "CREATE INDEX IF NOT EXISTS secure_operation_status_hash ON secure_operations(status,hash)",
    // Serves the pending check of every read and the replay scan.
    "CREATE INDEX IF NOT EXISTS secure_operation_scope_status ON secure_operations(scope,status,hash)",
    // Covers header scans such as the frontier: reading `status` from the
    // table walks each frame's body overflow pages.
    "CREATE INDEX IF NOT EXISTS secure_operation_headers ON secure_operations(scope,status,hash,header)",
    // A complete header scan need not carry the encoded scope in each index entry.
    "CREATE INDEX IF NOT EXISTS secure_operation_scan_headers ON secure_operations(status,hash,header)",
    // An author's latest frame of one status, such as its newest held write.
    "CREATE INDEX IF NOT EXISTS secure_operation_author_status ON secure_operations(author,scope,status,sequence)",
];

impl<A: RowApplication> EncryptedReplica<A> {
    /// Rebuilds one local row projection from the verified checkpoint and the
    /// original signed bytes after it. This does not migrate application
    /// generations.
    pub async fn rebuild_projection(&self, scope: ResourceScope) -> Result<(), Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        if !inner.can_read_key(scope, &inner.local_grants(now()?)?) {
            return Err(denied("projection rebuild denied"));
        }
        if !inner.config.keys.iter().any(|key| key.scope == scope) {
            return Err(denied("projection rebuild key unavailable"));
        }
        if inner.has_pending(scope).await? {
            return Err(denied("projection rebuild has unresolved inputs"));
        }
        transaction!(inner, |inner| {
            inner.rebuild_rows(scope).await?;
            #[cfg(test)]
            if inner.fail_before_commit > 0 {
                inner.fail_before_commit -= 1;
                return Err(Error::InjectedFailure);
            }
            Ok(())
        })?;
        inner.publish_revision().await
    }
}

impl<A: RowApplication> Inner<A> {
    /// Replaces a scope's stored rows, inside the caller's transaction, with
    /// its verified checkpoint rows and a replay of the operations after
    /// them, in application order. Nothing but one batch is held in memory.
    pub(super) async fn rebuild_rows(&self, scope: ResourceScope) -> Result<(), Error> {
        if self.replayed_scope(scope) {
            self.replay_from_frames(now()?).await?;
        } else {
            self.restore_rows(scope, i64::MAX).await?;
            self.reproject(scope).await?;
        }
        self.conn
            .execute(
                "UPDATE secure_metadata SET revision=revision+1 WHERE id=1",
                (),
            )
            .await?;
        Ok(())
    }
    /// Replaces a scope's stored rows with its replay base and the applied
    /// operations through position `through`, applying what each finalized
    /// seal changed on the way, and stores their counts and digest. The
    /// typed projection is the caller's to refresh.
    pub(super) async fn restore_rows(
        &self,
        scope: ResourceScope,
        through: i64,
    ) -> Result<(), Error> {
        let id = self.scope_id(scope).await?;
        let base = if self.ignores_base() {
            None
        } else {
            self.checkpoint_record(id, true).await?
        };
        let (mut cursor, mut sets, mut ledger) = match base {
            Some(record) => {
                let signed = self.verify_record(scope, &record)?;
                (
                    record.position,
                    record.sets,
                    identity::IdentityLedger::based(&signed.statement.identities)?,
                )
            }
            None => (
                0,
                checkpoint::Sets::new(),
                identity::IdentityLedger::default(),
            ),
        };
        self.conn
            .execute("DELETE FROM secure_checkpoint_scratch WHERE scope=?", [id])
            .await?;
        sets = self
            .prime_path_base(
                scope,
                id,
                checkpoint::Overlay::Scratch,
                self.workspace.tip,
                sets,
            )
            .await?;
        while let Some(last) = self
            .replay_sealed(
                scope,
                id,
                checkpoint::Overlay::Scratch,
                self.workspace.tip,
                (cursor, through),
                checkpoint::STEP_OPERATIONS,
                &mut sets,
                &mut ledger,
                checkpoint::ReplayMode::Mint,
            )
            .await?
        {
            cursor = last;
        }
        let blob = encode(&scope)?;
        self.in_rows_bulk(scope, async {
            self.conn
                .execute("DELETE FROM secure_row_records WHERE scope=?", [blob.clone()])
                .await?;
            for table in ["secure_checkpoint_rows", "secure_checkpoint_scratch"] {
                if self.ignores_base() && table == "secure_checkpoint_rows" {
                    continue;
                }
                self.conn
                    .execute(
                        format!("INSERT OR REPLACE INTO secure_row_records SELECT ?,row,fields FROM {table} WHERE scope=? AND fields<>X''"),
                        bindings(vec![SqlValue::Blob(blob.clone()), SqlValue::Integer(id)]),
                    )
                    .await?;
            }
            // A row a finalized seal dropped from the base.
            self.conn
                .execute(
                    "DELETE FROM secure_row_records WHERE scope=? AND row IN (SELECT row FROM secure_checkpoint_scratch WHERE scope=? AND fields=X'')",
                    bindings(vec![SqlValue::Blob(blob.clone()), SqlValue::Integer(id)]),
                )
                .await?;
            self.conn.execute(checkpoint::SHARE_BASE, [id]).await?;
            Ok(())
        })
        .await?;
        self.conn
            .execute("DELETE FROM secure_checkpoint_scratch WHERE scope=?", [id])
            .await?;
        let applied = self.scope_state(id).await?.3;
        self.store_scope_state(id, sets.rows, sets.tombstones, &sets.digest, applied)
            .await?;
        if through == i64::MAX {
            self.replace_ledger(scope, ledger).await?;
        }
        Ok(())
    }
}
