//! Open-time verification of the retained suffix and the explicit full audit.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditReport {
    /// Retained operations of the scope whose signatures and bindings verified.
    pub operations: u64,
    /// Stored rows compared with the scope's digest, or a replayed scope's
    /// table rows; zero without the key.
    pub rows: u64,
    /// The verified checkpoint the stored rows were checked against.
    pub checkpoint: Option<Commitment>,
    /// Applied operations after it that were replayed.
    pub replayed: u64,
}

fn mismatch() -> Error {
    denied("projection differs from signed encrypted history")
}

impl<A: RowApplication> Inner<A> {
    /// Streams the stored rows of one table and scope into their digest.
    /// With `stubs`, every row's creation operation must still be known.
    async fn row_sets(
        &self,
        sql: &str,
        scope: SqlValue,
        stubs: Option<i64>,
    ) -> Result<Sets, Error> {
        let resource: ResourceScope = match &scope {
            SqlValue::Blob(bytes) => decode(bytes)?,
            SqlValue::Integer(id) => {
                let mut rows = self
                    .conn
                    .query("SELECT scope FROM secure_scope_state WHERE id=?", [*id])
                    .await?;
                let bytes: Vec<u8> = rows
                    .next()
                    .await?
                    .ok_or_else(|| Error::Corrupt("row set scope missing".into()))?
                    .get(0)?;
                decode(&bytes)?
            }
            _ => return Err(Error::Corrupt("row set scope".into())),
        };
        let mut witnessed = BTreeSet::new();
        let mut sets = Sets::new();
        let mut cursor = Vec::new();
        loop {
            let chunk = collect_rows(
                self.conn
                    .query(
                        sql,
                        bindings(vec![
                            scope.clone(),
                            SqlValue::Blob(cursor.clone()),
                            SqlValue::Integer(STEP_ROWS as i64),
                        ]),
                    )
                    .await?,
            )
            .await?;
            let exhausted = chunk.len() < STEP_ROWS;
            for record in chunk {
                let [SqlValue::Blob(row), SqlValue::Blob(fields)] = record.as_slice() else {
                    return Err(Error::Corrupt("stored row".into()));
                };
                let record = self.decode_record(fields).await?;
                if let Some(proof) = &record.proof
                    && witnessed.insert((proof.header(), proof.bindings()))
                {
                    self.stored_creation_header(proof.header()).await?;
                    self.stored_bindings(proof.bindings()).await?;
                }
                for (author, signer) in &record.authors {
                    if self.stamp_author(resource.domain, *author).await? != *signer {
                        return Err(Error::Corrupt(
                            "stamp author differs from its committed signer".into(),
                        ));
                    }
                }
                sets.replace(&row_of(row)?, None, &encode(&record)?)?;
                if let Some(id) = stubs {
                    let creation = record.creation;
                    if !self.retains(creation).await?
                        && self.stub(creation).await?.is_none_or(|stub| stub.0 != id)
                    {
                        return Err(Error::Corrupt(
                            "a stored row's creation operation is unknown".into(),
                        ));
                    }
                }
                cursor = row.clone();
            }
            if exhausted {
                return Ok(sets);
            }
        }
    }
    /// Verifies every keyed scope's operations after its checkpoint. History
    /// a verified checkpoint covers is left to `audit`; the key records are
    /// checked by `adopt_keys` before.
    pub(in crate::replica) async fn verify_open(&mut self) -> Result<(), Error> {
        if !rows(&self.conn, "SELECT 1 FROM secure_row_positions p LEFT JOIN secure_applied a ON a.position=p.position WHERE a.position IS NULL OR a.scope<>p.scope UNION ALL SELECT 1 FROM secure_birth_positions p LEFT JOIN secure_applied a ON a.position=p.position WHERE a.position IS NULL OR a.scope<>p.scope LIMIT 1").await?.is_empty() {
            return Err(Error::Corrupt("orphaned row or birth position".into()));
        }
        let shapes = "SELECT scope,shape,records FROM secure_scope_shapes ORDER BY scope,shape";
        let actual = "SELECT scope,shape,count(*) FROM secure_rows GROUP BY scope,shape ORDER BY scope,shape";
        if rows(&self.conn, shapes).await? != rows(&self.conn, actual).await? {
            return Err(Error::Corrupt(
                "scope shape counts differ from stored rows".into(),
            ));
        }
        self.audit_positions().await?;
        self.audit_migration_accounts().await?;
        self.verify_admission_head().await?;
        self.verify_identity_ledgers().await?;
        self.verify_no_frames_records().await?;
        let scopes: Vec<_> = self.config.keys.iter().map(|key| key.scope).collect();
        for scope in scopes {
            self.verify_tail(scope).await?;
        }
        Ok(())
    }
    /// Replays scope `id`'s applied operations after `cursor` over `sets`
    /// into the scratch overlay.
    async fn audit_replay(
        &mut self,
        scope: ResourceScope,
        id: i64,
        mut cursor: i64,
        mut sets: Sets,
        mut ledger: identity::IdentityLedger,
    ) -> Result<Sets, Error> {
        loop {
            // Both advance only with a committed page.
            let (last, next, marks) = transaction!(@commit self, |inner| {
                let mut next = sets.clone();
                let mut marks = ledger.clone();
                let last = inner
                    .replay_sealed(
                        scope,
                        id,
                        Overlay::Scratch,
                        inner.workspace.tip,
                        (cursor, i64::MAX),
                        STEP_OPERATIONS,
                        &mut next,
                        &mut marks,
                        checkpoint::ReplayMode::Check,
                    )
                    .await?;
                Ok((last, next, marks))
            })?;
            let Some(last) = last else {
                break;
            };
            cursor = last;
            sets = next;
            ledger = marks;
            #[cfg(test)]
            self.fault(Stage::AuditReplay)?;
        }
        Ok(sets)
    }
    async fn audit_staged_rows(
        &mut self,
        scope: ResourceScope,
        id: i64,
        sets: Sets,
    ) -> Result<(Sets, bool), Error> {
        let Some(fields) = self.staged_row_fields(scope.domain).await? else {
            return Ok((sets, false));
        };
        let sets = transaction!(@commit self, |inner| {
            inner.transform_audit_overlay(scope,id,&fields).await
        })?;
        #[cfg(test)]
        self.fault(Stage::AuditStaged)?;
        Ok((sets, true))
    }
    async fn transform_audit_overlay(
        &self,
        scope: ResourceScope,
        id: i64,
        fields: &schemas::PathFields,
    ) -> Result<Sets, Error> {
        self.conn.execute(
            "INSERT OR IGNORE INTO secure_checkpoint_scratch SELECT scope,row,fields FROM secure_checkpoint_rows WHERE scope=?",
            [id],
        ).await?;
        let mut after = Vec::new();
        loop {
            let records = collect_rows(self.conn.query(
                "SELECT row,fields FROM secure_checkpoint_scratch WHERE scope=? AND row>? ORDER BY row LIMIT ?",
                bindings(vec![SqlValue::Integer(id), SqlValue::Blob(after.clone()), SqlValue::Integer(STEP_ROWS as i64)]),
            ).await?).await?;
            for record in &records {
                let [SqlValue::Blob(row), SqlValue::Blob(bytes)] = record.as_slice() else {
                    return Err(Error::Corrupt("switch audit row".into()));
                };
                after = row.clone();
                match self.strip_stored_record(fields, scope.table, bytes).await? {
                    None => {
                        self.conn
                            .execute(
                                "DELETE FROM secure_checkpoint_scratch WHERE scope=? AND row=?",
                                bindings(vec![SqlValue::Integer(id), SqlValue::Blob(row.clone())]),
                            )
                            .await?;
                    }
                    Some(stripped) if stripped != *bytes => {
                        self.conn.execute(
                            "UPDATE secure_checkpoint_scratch SET fields=? WHERE scope=? AND row=?",
                            bindings(vec![SqlValue::Blob(stripped), SqlValue::Integer(id), SqlValue::Blob(row.clone())]),
                        ).await?;
                    }
                    Some(_) => {}
                }
            }
            if records.len() < STEP_ROWS {
                break;
            }
        }
        self.row_sets(
            "SELECT row,fields FROM secure_checkpoint_scratch WHERE scope=? AND row>? ORDER BY row LIMIT ?",
            SqlValue::Integer(id), None,
        ).await
    }
    /// `verify_tail` for a replayed scope: its base rows match the signed
    /// checkpoint. The audit's rebuild oracle checks the rows replayed on top.
    async fn verify_replayed_tail(
        &self,
        scope: ResourceScope,
        id: i64,
        record: Option<Record>,
    ) -> Result<(Option<SignedCheckpoint>, u64), Error> {
        let (signed, cursor) = match record {
            Some(record) => {
                let signed = self.verify_record(scope, &record)?;
                let rows = self.stored_images("secure_replayed_base", id, None).await?;
                if replay::base_sets(&rows).rows_summary() != signed.statement.rows {
                    return Err(mismatch());
                }
                (Some(signed), record.position)
            }
            None => (None, 0),
        };
        match collect_rows(
            self.conn
                .query(
                    "SELECT COUNT(*) FROM secure_applied WHERE scope=? AND position>?",
                    [id, cursor],
                )
                .await?,
        )
        .await?
        .first()
        .map(Vec::as_slice)
        {
            Some([SqlValue::Integer(count)]) => Ok((signed, *count as u64)),
            _ => Err(Error::Corrupt("applied positions".into())),
        }
    }
    /// Replays the applied operations after the scope's verified checkpoint
    /// over it and compares the result with the stored rows. Returns the
    /// checkpoint and the operations replayed.
    async fn verify_tail(
        &mut self,
        scope: ResourceScope,
    ) -> Result<(Option<SignedCheckpoint>, u64), Error> {
        let Some(id) = self.find_scope_id(scope).await? else {
            return Ok((None, 0));
        };
        let record = self.checkpoint_record(id, true).await?;
        // A base signed off the followed path, such as one imported while
        // the owner followed a branch, is replaced by a rebootstrap before
        // the rows are this path's: its blockers answer instead.
        if let Some(signed) = record.as_ref().and_then(|record| record.signed.as_ref())
            && self
                .path_fields_to(scope.domain, signed.statement.tip, self.workspace.tip)
                .is_err()
        {
            super::super::blockers::refuse(self.readable_blockers(scope).await?)?;
        }
        if self.replayed_scope(scope) {
            return self.verify_replayed_tail(scope, id, record).await;
        }
        let (signed, cursor, mut sets, ledger) = match record {
            Some(record) => {
                let signed = self.verify_record(scope, &record)?;
                let ledger = identity::IdentityLedger::based(&signed.statement.identities)?;
                (Some(signed), record.position, record.sets, ledger)
            }
            // The pages a direct import stored so far are the base that
            // local writes applied over; its statement names their marks.
            None => match self.staging(id).await?.filter(|staging| staging.direct) {
                Some(staging) => {
                    let ledger =
                        identity::IdentityLedger::based(&staging.signed.statement.identities)?;
                    (None, 0, staging.sets, ledger)
                }
                None => (None, 0, Sets::new(), identity::IdentityLedger::default()),
            },
        };
        let clear = "DELETE FROM secure_checkpoint_scratch WHERE scope=?";
        let (rebuilding, based) = (self.rebuilding_tip, self.tip_base);
        let verified = async {
        sets = transaction!(@commit self, |inner| {
            inner.conn.execute(clear, [id]).await?;
            inner.prime_path_base(scope, id, Overlay::Scratch, inner.workspace.tip, sets.clone()).await
        })?;
        let replayed = match collect_rows(
            self.conn
                .query(
                    "SELECT COUNT(*) FROM secure_applied WHERE scope=? AND position>?",
                    [id, cursor],
                )
                .await?,
        )
        .await?
        .first()
        .map(Vec::as_slice)
        {
            Some([SqlValue::Integer(count)]) => *count as u64,
            _ => return Err(Error::Corrupt("applied positions".into())),
        };
        // Positions applied on another tip stay stored; the replay reads
        // only what the workspace sees, over the base it keeps.
        (self.rebuilding_tip, self.tip_base) = (true, true);
        let replay = self.audit_replay(scope, id, cursor, sets, ledger).await;
        (self.rebuilding_tip, self.tip_base) = (rebuilding, based);
        let (sets, transformed) = self.audit_staged_rows(scope, id, replay?).await?;
        let (rows, tombstones, digest, _) = self.scope_state(id).await?;
        // A staged transform's scratch holds every expected row, its base
        // rows included: a stored row it lacks differs.
        let unchanged = if transformed {
            ""
        } else {
            " AND (b.row IS NULL OR b.fields<>r.fields)"
        };
        let differing = collect_rows(
            self.conn
                .query(
                    format!("SELECT 1 FROM secure_checkpoint_scratch s LEFT JOIN secure_row_records r ON r.scope=?1 AND r.row=s.row WHERE s.scope=?2 AND (s.fields=X'' AND r.fields IS NOT NULL OR s.fields<>X'' AND (r.fields IS NULL OR r.fields<>s.fields)) UNION ALL SELECT 1 FROM secure_row_records r LEFT JOIN secure_checkpoint_scratch s ON s.scope=?2 AND s.row=r.row LEFT JOIN secure_checkpoint_rows b ON b.scope=?2 AND b.row=r.row WHERE r.scope=?1 AND s.row IS NULL{unchanged} LIMIT 1"),
                    bindings(vec![SqlValue::Blob(encode(&scope)?), SqlValue::Integer(id)]),
                )
                .await?,
        )
        .await?;
        if !differing.is_empty()
            || sets.rows != rows
            || sets.tombstones != tombstones
            || sets.digest != digest
        {
            return Err(mismatch());
        }
        Ok((signed, replayed))
        }.await;
        (self.rebuilding_tip, self.tip_base) = (rebuilding, based);
        let cleanup = transaction!(@commit self, |inner| {
            inner.conn.execute(clear, [id]).await?;
            Ok(())
        });
        match verified {
            Err(error) => Err(error),
            Ok(report) => cleanup.map(|()| report),
        }
    }
    /// Verifies every retained operation of a scope in batches.
    async fn audit_operations(&self, scope: ResourceScope, id: Option<i64>) -> Result<u64, Error> {
        let mut cursor = Vec::new();
        let mut count = 0;
        let mut applied = 0;
        loop {
            let records = collect_rows(self.conn.query(
                "SELECT hash,header,body,status,EXISTS(SELECT 1 FROM secure_applied a WHERE a.hash=o.hash) FROM secure_operations o WHERE scope=? AND hash>? ORDER BY hash LIMIT 32",
                [encode(&scope)?, cursor.clone()],
            ).await?).await?;
            if records.is_empty() {
                break;
            }
            for record in records {
                let [
                    SqlValue::Blob(hash),
                    SqlValue::Blob(header),
                    SqlValue::Blob(body),
                    SqlValue::Text(status),
                    SqlValue::Integer(positioned),
                ] = record.as_slice()
                else {
                    return Err(denied("corrupt retained operation"));
                };
                cursor = hash.clone();
                count += 1;
                // Every retained operation has the chain its header names.
                let frame = self.stored_frame(header.clone(), body.clone()).await?;
                let operation = frame.operation_ref()?;
                if operation.hash.as_bytes().as_slice() != hash
                    || self
                        .manifest_of_tip(operation.header.extensions.tip)
                        .and_then(|manifest| self.known(manifest))
                        .is_err()
                    || operation.header.extensions.scope != scope
                    || !["applied", "pending", "rejected", "held", "abandoned"]
                        .contains(&status.as_str())
                    // A held or abandoned frame keeps the position it had.
                    || (status == "applied" && *positioned != 1)
                    || (["pending", "rejected"].contains(&status.as_str()) && *positioned == 1)
                {
                    return Err(denied("corrupt retained history binding"));
                }
                if *positioned == 1 {
                    applied += 1;
                    if self.has_scope_key(scope) {
                        let payload = self.row_payload(&frame)?;
                        let (expected, births) = self.frame_positions(&frame, &payload)?;
                        let actual = collect_rows(self.conn.query("SELECT p.row FROM secure_row_positions p JOIN secure_applied a ON a.position=p.position WHERE a.hash=? ORDER BY p.row", [operation.hash.as_bytes().to_vec()]).await?).await?;
                        let actual = actual
                            .into_iter()
                            .map(|row| match row.as_slice() {
                                [SqlValue::Blob(row)] => row_of(row),
                                _ => Err(Error::Corrupt("row position".into())),
                            })
                            .collect::<Result<BTreeSet<_>, _>>()?;
                        let mut expected_births = BTreeMap::new();
                        for birth in births {
                            expected_births
                                .entry(birth.author)
                                .and_modify(|mark: &mut IdentityMark| {
                                    mark.sequence = mark.sequence.max(birth.sequence)
                                })
                                .or_insert(birth);
                        }
                        let actual_births = collect_rows(self.conn.query("SELECT b.author,b.signer,b.sequence FROM secure_birth_positions b JOIN secure_applied a ON a.position=b.position WHERE a.hash=? ORDER BY b.author", [operation.hash.as_bytes().to_vec()]).await?).await?;
                        let expected_births = expected_births
                            .into_values()
                            .map(|birth| {
                                vec![
                                    SqlValue::Integer(i64::from(birth.author)),
                                    SqlValue::Blob(birth.signer.as_bytes().to_vec()),
                                    SqlValue::Integer(i64::from(birth.sequence)),
                                ]
                            })
                            .collect::<Vec<_>>();
                        if actual_births != expected_births {
                            return Err(Error::Corrupt(
                                "birth positions differ from applied writes".into(),
                            ));
                        }
                        if actual != expected {
                            return Err(Error::Corrupt(
                                "row positions differ from applied writes".into(),
                            ));
                        }
                    }
                }
                if status == "applied"
                    && !self
                        .dependencies_ready(&frame, &BTreeSet::new(), None)
                        .await?
                {
                    return Err(denied("applied encrypted dependency missing"));
                }
            }
        }
        let positions = match id {
            Some(id) => {
                collect_rows(
                    self.conn
                        .query("SELECT COUNT(*) FROM secure_applied WHERE scope=?", [id])
                        .await?,
                )
                .await?
            }
            None => vec![vec![SqlValue::Integer(0)]],
        };
        if positions != vec![vec![SqlValue::Integer(applied)]] {
            return Err(Error::Corrupt(
                "applied positions differ from retained operations".into(),
            ));
        }
        Ok(count)
    }
}

impl<A: RowApplication> Inner<A> {
    async fn audit_global_start(&mut self) -> Result<(), Error> {
        #[cfg(test)]
        {
            self.audit_global_passes += 1;
        }
        if !rows(&self.conn, "SELECT 1 FROM secure_row_positions p LEFT JOIN secure_applied a ON a.position=p.position WHERE a.position IS NULL OR a.scope<>p.scope UNION ALL SELECT 1 FROM secure_birth_positions p LEFT JOIN secure_applied a ON a.position=p.position WHERE a.position IS NULL OR a.scope<>p.scope LIMIT 1").await?.is_empty() {
            return Err(Error::Corrupt("orphaned row or birth position".into()));
        }
        let shapes = "SELECT scope,shape,records FROM secure_scope_shapes ORDER BY scope,shape";
        let actual = "SELECT scope,shape,count(*) FROM secure_rows GROUP BY scope,shape ORDER BY scope,shape";
        if rows(&self.conn, shapes).await? != rows(&self.conn, actual).await? {
            return Err(Error::Corrupt(
                "scope shape counts differ from stored rows".into(),
            ));
        }
        self.audit_positions().await?;
        self.audit_migration_accounts().await
    }
    async fn audit_history(
        &self,
        scope: ResourceScope,
    ) -> Result<(Option<i64>, AuditReport), Error> {
        let id = self.find_scope_id(scope).await?;
        Ok((
            id,
            AuditReport {
                operations: self.audit_operations(scope, id).await?,
                rows: 0,
                checkpoint: None,
                replayed: 0,
            },
        ))
    }
    async fn audit_witnesses(&self) -> Result<(), Error> {
        for (table, column, is_header) in [
            ("secure_creation_headers", "header", true),
            ("secure_author_bindings", "bindings", false),
        ] {
            let mut after = Vec::new();
            loop {
                let records = collect_rows(self.conn.query(format!("SELECT digest,{column} FROM {table} WHERE digest>? ORDER BY digest LIMIT ?"), bindings(vec![SqlValue::Blob(after.clone()), SqlValue::Integer(STEP_ROWS as i64)])).await?).await?;
                for record in &records {
                    let [SqlValue::Blob(digest), SqlValue::Blob(bytes)] = record.as_slice() else {
                        return Err(Error::Corrupt("stored witness".into()));
                    };
                    let actual = if is_header {
                        crate::wire::verified_header(bytes)?;
                        moves::header_digest(bytes)
                    } else {
                        decode::<Vec<rocky_credentials::AuthorBinding>>(bytes)?;
                        moves::bindings_digest(bytes)
                    };
                    if actual.as_slice() != digest {
                        return Err(Error::Corrupt("stored witness digest mismatch".into()));
                    }
                    after = digest.clone();
                }
                if records.len() < STEP_ROWS {
                    break;
                }
            }
        }
        Ok(())
    }
    async fn audit_global_remaining(&self) -> Result<(), Error> {
        self.audit_witnesses().await?;
        let counters = rows(
            &self.conn,
            "SELECT (SELECT COUNT(*) FROM secure_operations)=records AND (SELECT COALESCE(SUM(LENGTH(header)+LENGTH(body)),0) FROM secure_operations)=bytes AND (SELECT COUNT(*) FROM secure_handles)=handles FROM secure_retained",
        )
        .await?;
        if counters != vec![vec![SqlValue::Integer(1)]] {
            return Err(Error::Corrupt("retained history counters".into()));
        }
        let mut handles = Lt::new();
        let mut cursor = Vec::new();
        loop {
            let chunk = collect_rows(
                self
                    .conn
                    .query(
                        "SELECT handle,input,hash FROM secure_handles WHERE handle>? ORDER BY handle LIMIT 256",
                        [cursor.clone()],
                    )
                    .await?,
            )
            .await?;
            let Some(last) = chunk.last() else {
                break;
            };
            if let Some(SqlValue::Blob(handle)) = last.first() {
                cursor = handle.clone();
            }
            for record in &chunk {
                let [
                    SqlValue::Blob(handle),
                    SqlValue::Blob(input),
                    SqlValue::Blob(hash),
                ] = record.as_slice()
                else {
                    return Err(Error::Corrupt("mutation handle".into()));
                };
                handles.add(HANDLE_LABEL, &handle_item(handle, input, hash));
            }
        }
        if handles != self.handle_set().await?.1 {
            return Err(Error::Corrupt("mutation handle digest".into()));
        }
        self.audit_admission().await?;
        self.verify_identity_ledgers().await?;
        // Keyless records are checked before the key decides the rest.
        self.verify_no_frames_records().await?;
        Ok(())
    }
    async fn audit_projection(
        &mut self,
        scope: ResourceScope,
        id: Option<i64>,
        mut report: AuditReport,
    ) -> Result<AuditReport, Error> {
        let (Some(id), Ok(_)) = (id, self.scope_key(scope)) else {
            return Ok(report);
        };
        // A replayed scope's rows are its table's; `verify_tail` checks its base.
        let replayed = self.replayed_scope(scope);
        let live = self
            .row_sets(
                "SELECT row,fields FROM secure_row_records WHERE scope=? AND row>? ORDER BY row LIMIT ?",
                SqlValue::Blob(encode(&scope)?),
                Some(id),
            )
            .await?;
        let (rows, tombstones, digest, _) = self.scope_state(id).await?;
        if live.rows != rows || live.tombstones != tombstones || live.digest != digest {
            return Err(mismatch());
        }
        report.rows = rows;
        if replayed {
            report.rows = self.replayed_images(scope).await?.len() as u64;
        } else if let Some(record) = self.checkpoint_record(id, true).await? {
            let signed = self.verify_record(scope, &record)?;
            let base = self
                .row_sets(
                    "SELECT row,fields FROM secure_checkpoint_rows WHERE scope=? AND row>? ORDER BY row LIMIT ?",
                    SqlValue::Integer(id),
                    Some(id),
                )
                .await?;
            if base.rows_summary() != signed.statement.rows
                || base.tombstones != signed.statement.tombstones
            {
                return Err(Error::Corrupt(
                    "checkpoint rows differ from the signed checkpoint".into(),
                ));
            }
            for log in &signed.statement.frontier {
                if self
                    .log(id, log.author)
                    .await?
                    .is_none_or(|local| local.sequence < log.sequence as i64)
                {
                    return Err(Error::Corrupt(
                        "a log is behind the checkpoint frontier".into(),
                    ));
                }
            }
        }
        let (signed, replayed) = self.verify_tail(scope).await?;
        report.checkpoint = signed.map(|signed| signed.id()).transpose()?;
        report.replayed = replayed;
        self.audit_rebuilt_projection(scope).await?;
        Ok(report)
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// Fresh verification of retained history and global admission evidence,
    /// plus keyed rows, base and suffix replay. Holds the replica lock throughout.
    pub async fn audit(&self, scope: ResourceScope) -> Result<AuditReport, Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        inner.invalidate_records();
        inner.audit_global_start().await?;
        let (id, report) = inner.audit_history(scope).await?;
        inner.audit_global_remaining().await?;
        inner.audit_projection(scope, id, report).await
    }

    #[cfg(test)]
    pub(crate) async fn audit_scratch_flags(&self) -> (bool, bool) {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        (inner.rebuilding_tip, inner.tip_base)
    }

    /// Fixture-only composition of the production checks under one guard.
    /// Keyless/unknown slots retain the single audit's partial report meaning.
    #[cfg(any(test, feature = "qualification"))]
    #[doc(hidden)]
    pub async fn audit_scopes(
        &self,
        scopes: &[ResourceScope],
    ) -> Result<Vec<(ResourceScope, AuditReport)>, Error> {
        let Some((first, rest)) = scopes.split_first() else {
            return Err(denied("audit scopes must be nonempty"));
        };
        let mut unique = BTreeSet::new();
        if scopes.iter().any(|scope| !unique.insert(*scope)) {
            return Err(denied("audit scopes must be unique"));
        }
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        inner.invalidate_records();
        inner.audit_global_start().await?;
        let (id, report) = inner.audit_history(*first).await?;
        inner.audit_global_remaining().await?;
        let mut reports = Vec::with_capacity(scopes.len());
        reports.push((*first, inner.audit_projection(*first, id, report).await?));
        for scope in rest {
            let (id, report) = inner.audit_history(*scope).await?;
            reports.push((*scope, inner.audit_projection(*scope, id, report).await?));
        }
        inner.invalidate_records();
        inner.audit_global_start().await?;
        inner.audit_global_remaining().await?;
        Ok(reports)
    }
}
