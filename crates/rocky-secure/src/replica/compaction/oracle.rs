//! Independent full-rebuild comparisons for tests and explicit audits.
use super::*;

impl<A: RowApplication> Inner<A> {
    pub(super) async fn finalize_seal(
        &mut self,
        domain: Scope,
        seal: &SignedSeal,
        scopes: &[(ResourceScope, Option<i64>)],
        keep: bool,
    ) -> Result<(), Error> {
        #[cfg(test)]
        let expected = if self.compare_finalization {
            let started = std::time::Instant::now();
            self.conn
                .execute("SAVEPOINT finalization_oracle", ())
                .await?;
            let state = self.take_oracle_state();
            let result = async {
                self.finalize_seal_impl(domain, seal, scopes, keep, false)
                    .await?;
                self.finalization_snapshot().await
            }
            .await;
            self.restore_oracle_state(state);
            self.conn
                .execute("ROLLBACK TO finalization_oracle", ())
                .await?;
            self.conn.execute("RELEASE finalization_oracle", ()).await?;
            self.invalidate_context();
            self.finalization_oracle_time += started.elapsed();
            Some(result?)
        } else {
            None
        };
        #[cfg(test)]
        let started = std::time::Instant::now();
        self.finalize_seal_impl(domain, seal, scopes, keep, true)
            .await?;
        #[cfg(test)]
        if self.fail_before_commit > 0 {
            self.fail_before_commit -= 1;
            return Err(Error::InjectedFailure);
        }

        #[cfg(test)]
        {
            self.finalization_time += started.elapsed();
            if let Some(expected) = expected {
                let started = std::time::Instant::now();
                let actual = self.finalization_snapshot().await?;
                self.finalization_oracle_time += started.elapsed();
                if actual != expected {
                    return Err(Error::Corrupt(format!(
                        "incremental finalization differs from full rebuild: {}",
                        snapshot_difference(&expected, &actual)
                    )));
                }
            }
        }
        Ok(())
    }
}

type Snapshot = BTreeMap<String, Vec<Vec<SqlValue>>>;

fn snapshot_difference(expected: &Snapshot, actual: &Snapshot) -> String {
    expected
        .iter()
        .filter(|(key, value)| actual.get(*key) != Some(*value))
        .map(|(key, _)| key.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

impl<A: RowApplication> Inner<A> {
    async fn finalization_snapshot(&self) -> Result<Snapshot, Error> {
        let mut snapshot = BTreeMap::new();
        let records = rows(
            &self.conn,
            "SELECT scope,row,fields FROM secure_rows ORDER BY scope,row",
        )
        .await?;
        let mut canonical = Vec::new();
        for record in records {
            let [scope, row, SqlValue::Blob(bytes)] = record.as_slice() else {
                return Err(Error::Corrupt("snapshot row".into()));
            };
            canonical.push(vec![
                scope.clone(),
                row.clone(),
                SqlValue::Blob(self.canonical_record(bytes).await?),
            ]);
        }
        snapshot.insert("rows".into(), canonical);
        snapshot.insert("scope digests".into(), rows(&self.conn, "SELECT scope,rows,tombstones,digest,applied FROM secure_scope_state ORDER BY scope").await?);
        for table in [
            "secure_applied",
            "secure_scope_shapes",
            "secure_row_positions",
            "secure_birth_positions",
            "secure_identity_marks",
            "secure_identity_own",
            "secure_identity_summary",
        ] {
            snapshot.insert(
                table.into(),
                rows(&self.conn, &format!("SELECT * FROM {table} ORDER BY 1,2")).await?,
            );
        }
        // Queued ledgers are unavailable; audit verifies that lifecycle separately.
        snapshot.insert("usable identity ledger".into(), rows(&self.conn,"SELECT l.* FROM secure_identity_ledger l WHERE NOT EXISTS(SELECT 1 FROM secure_rebuild_scopes q WHERE q.scope=l.scope) ORDER BY l.scope,l.author").await?);
        let mut drops = Vec::new();
        for record in rows(
            &self.conn,
            "SELECT scope,depth,row,fields FROM secure_seal_drops ORDER BY scope,depth,row",
        )
        .await?
        {
            let [scope, depth, row, fields] = record.as_slice() else {
                return Err(Error::Corrupt("snapshot seal drop".into()));
            };
            let fields = match fields {
                SqlValue::Blob(bytes) => SqlValue::Blob(self.canonical_record(bytes).await?),
                SqlValue::Null => SqlValue::Null,
                _ => return Err(Error::Corrupt("snapshot seal drop".into())),
            };
            drops.push(vec![scope.clone(), depth.clone(), row.clone(), fields]);
        }
        snapshot.insert("seal drops".into(), drops);
        if let Some(typed) = &self.workspace.typed {
            for table in &typed.tables {
                let order = (1..=table.table.fields.len())
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let sql = format!(
                    "SELECT * FROM {} ORDER BY {order}",
                    typed::quoted(&table.table.sql_name)
                );
                snapshot.insert(table.table.sql_name.clone(), rows(&self.conn, &sql).await?);
            }
        }
        Ok(snapshot)
    }

    /// The explicit audit retains the full restoration as an independent oracle.
    pub(in crate::replica) async fn audit_rebuilt_projection(
        &self,
        scope: ResourceScope,
    ) -> Result<(), Error> {
        // An interrupted installation has an explicitly partial typed image;
        // verify_tail still checks all of its staged canonical row transforms.
        if self.schema_switching().await? || self.plan_status().await?.is_some() {
            return Ok(());
        }
        if self
            .workspace
            .typed
            .as_ref()
            .is_none_or(|typed| typed.by_scope(scope).is_none())
        {
            return Ok(());
        }
        let canonical_drops = |drops: Vec<(Commitment, Option<Materialized>)>| {
            drops
                .into_iter()
                .map(|(row, record)| Ok((row, record.as_ref().map(encode).transpose()?)))
                .collect::<Result<Vec<_>, Error>>()
        };
        let full_drops = canonical_drops(self.seal_drops(scope, false).await?)?;
        let indexed_drops = canonical_drops(self.seal_drops(scope, true).await?)?;
        if full_drops != indexed_drops {
            return Err(Error::Corrupt(
                "seal drop index differs from full scan".into(),
            ));
        }
        let expected = self.finalization_snapshot().await?;
        self.conn.execute("SAVEPOINT projection_oracle", ()).await?;
        let state = self.take_oracle_state();
        let actual = async {
            // verify_tail already compared the canonical full replay, including
            // staged schema transforms, with these authoritative stored rows.
            if self.replayed_scope(scope) {
                self.replay_from_frames(now()?).await?;
            } else {
                self.reproject(scope).await?;
            }
            self.finalization_snapshot().await
        }
        .await;
        self.restore_oracle_state(state);
        self.conn
            .execute("ROLLBACK TO projection_oracle", ())
            .await?;
        self.conn.execute("RELEASE projection_oracle", ()).await?;
        self.invalidate_context();
        let actual = actual?;
        if expected != actual {
            return Err(Error::Corrupt(format!(
                "projection differs from full rebuild: {}",
                snapshot_difference(&expected, &actual)
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
impl<A: RowApplication> EncryptedReplica<A> {
    pub(crate) async fn defer_finalization_for_test(&self, scope: ResourceScope, deferred: bool) {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        if deferred {
            inner.direct.insert(scope);
        } else {
            inner.direct.remove(&scope);
        }
    }
}

impl<A> Inner<A> {
    pub(in crate::replica) fn take_oracle_state(&self) -> queries::Touched {
        std::mem::take(
            &mut *self
                .workspace
                .queries
                .touched
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
    pub(in crate::replica) fn restore_oracle_state(&self, touched: queries::Touched) {
        *self
            .workspace
            .queries
            .touched
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = touched;
    }
}
