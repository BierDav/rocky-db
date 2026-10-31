//! Original signed frames held after a line closes.
use super::*;
use crate::replica::incoming::Outcome;

/// Metadata rows examined per refresh step. Provisional until the separated
/// phone costs are recorded in docs/features_12/02-bounded-holds-evidence.md.
const REFRESH_RECORDS: usize = 64;
#[derive(Clone, Default)]
struct Refresh {
    generation: Option<Commitment>,
    signer: Vec<u8>,
    sequence: i64,
    discover: bool,
    records: std::collections::VecDeque<Vec<SqlValue>>,
    version: Option<u64>,
}
const TOKEN_RECORDS: usize = 64;
const PAGE_RECORDS: usize = 32;

/// Definite CBOR array header; hashing it and the encoded elements preserves
/// the existing held-token encoding without assembling the whole array.
fn token_array_header(count: u64) -> Vec<u8> {
    match count {
        0..=23 => vec![0x80 | count as u8],
        24..=0xff => vec![0x98, count as u8],
        0x100..=0xffff => [vec![0x99], (count as u16).to_be_bytes().to_vec()].concat(),
        0x1_0000..=0xffff_ffff => [vec![0x9a], (count as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![0x9b], count.to_be_bytes().to_vec()].concat(),
    }
}

struct TokenSource {
    writes: Arc<crate::sqlite::Writes>,
    tables: [String; 2],
    versions: [u64; 2],
    authority: u64,
    tip: TipId,
}
impl TokenSource {
    fn check<A: RowApplication>(&self, inner: &Inner<A>) -> Result<(), Error> {
        if self.authority != inner.authority
            || self.tip != inner.workspace.tip
            || self
                .tables
                .iter()
                .zip(self.versions)
                .any(|(table, version)| self.writes.table_count(table) != version)
        {
            return Err(Error::RetryExhausted);
        }
        Ok(())
    }
}
impl<A: RowApplication> Inner<A> {
    /// Stores already authenticated held members in the caller's transaction.
    pub(in crate::replica) async fn hold_members(
        &self,
        frames: &[(EncryptedFrame, RowPayload)],
        time: u64,
    ) -> Result<(), Error> {
        let Some((first, payload)) = frames.first() else {
            return Err(denied("empty held bundle"));
        };
        let id = payload.membership().map_or_else(
            || first.id().map(|hash| *hash.as_bytes()),
            |membership| Ok(membership.transaction),
        )?;
        #[cfg(any(test, feature = "qualification"))]
        {
            self.flusher.measurements.work(
                crate::replica::lock::WorkUnit::HeldMemberFrame,
                frames.len() as u64,
            );
            self.flusher.measurements.work(
                crate::replica::lock::WorkUnit::HeldMemberRow,
                frames
                    .iter()
                    .map(|(_, payload)| payload.writes().len() as u64)
                    .sum(),
            );
        }
        let names = self.item_names().await?;
        let local = self.local_grants(time)?;
        let mut stored = Stored {
            time: first.operation_ref()?.header.timestamp,
            rows: Vec::new(),
        };
        for (frame, payload) in frames {
            let operation = frame.operation_ref()?;
            let scope = operation.header.extensions.scope;
            let grants = self.verify_frame_authority(frame, time)?;
            if !self.can_read_key(scope, &local) || !self.holds(scope).await? {
                return Err(denied("held change requires a readable held scope"));
            }
            // An intent is held whole: it has no rows for the application
            // to re-author.
            if payload.intent().is_some() {
                continue;
            }
            let writes = payload.clone().into_writes();
            if writes.is_empty() || writes.len() > ROWS_PER_FRAME {
                return Err(denied("held row change quota"));
            }
            let source = self
                .graph_for(scope.domain)?
                .schema_any(operation.header.extensions.tip)
                .map_err(credential)?;
            let definition = self.definition_at(&source).ok_or_else(|| {
                Error::Incompatible("held source tip schema is not installed".into())
            })?;
            let source_fields: BTreeSet<_> =
                definition.fields.iter().map(|field| field.id).collect();
            if definition.publisher != *self.config.publisher.as_bytes()
                || definition.app != scope.domain.app
                || !definition
                    .domains
                    .iter()
                    .any(|domain| domain.domain == scope.domain.domain)
                || !definition
                    .entities
                    .iter()
                    .any(|table| table.id == scope.table)
                || writes.iter().any(|write| {
                    write
                        .change
                        .before
                        .iter()
                        .chain(&write.change.after)
                        .any(|image| image.keys().any(|field| !source_fields.contains(field)))
                })
            {
                return Err(denied(
                    "held frame fields are outside its source tip schema",
                ));
            }
            let owned;
            let application: &dyn RowApplication = if source == self.manifest {
                self.app.as_ref()
            } else {
                owned = self
                    .app
                    .source_application(definition)
                    .map_err(Error::Incompatible)?;
                if owned.manifest().hash() != source {
                    return Err(Error::Incompatible(
                        "held source validator has a different manifest".into(),
                    ));
                }
                owned.as_ref()
            };
            let source_permissions = if source == self.manifest {
                BTreeSet::new()
            } else {
                application.permission_fields()
            };
            for write in &writes {
                if !write.valid()
                    || write.change.scope != scope
                    || !write.permitted_by(&grants)
                    || write.published_fields().iter().any(|field| {
                        self.permission_fields.contains(field) || source_permissions.contains(field)
                    })
                    || application
                        .row_partition(&write.change)
                        .map_err(|error| denied(&error))?
                        != operation.header.extensions.partition
                {
                    return Err(denied("held row/field transition denied"));
                }
                application
                    .validate_write(write)
                    .map_err(|error| denied(&error))?;
                let row = match application
                    .row_identity(&write.change)
                    .map_err(|error| denied(&error))?
                {
                    Some(id) => rocky_core::commitment(
                        "rocky.row-incarnation.v2",
                        &id.integer().to_le_bytes(),
                    ),
                    None => write.change.row,
                };
                stored.rows.push(stored_row(write, row, &names));
            }
            stored.time = stored.time.min(operation.header.timestamp);
        }
        let mut migration = false;
        let mut ledger_scopes = BTreeSet::new();
        for (frame, _) in frames {
            ledger_scopes.insert(frame.operation_ref()?.header.extensions.scope);
            migration |= !collect_rows(
                self.conn
                    .query(
                        "SELECT 1 FROM secure_migration_frames WHERE hash=?",
                        [frame.id()?.as_bytes().to_vec()],
                    )
                    .await?,
            )
            .await?
            .is_empty();
        }
        let resolved = collect_rows(
            self.conn
                .query(
                    "SELECT authority FROM secure_held_resolved WHERE id=?",
                    [id.to_vec()],
                )
                .await?,
        )
        .await?;
        let resolved = match resolved.first().map(Vec::as_slice) {
            Some([SqlValue::Blob(bytes)]) => {
                let grants: Vec<rocky_core::ResourceGrant> = decode(bytes)?;
                stored
                    .rows
                    .iter()
                    .all(|row| self.can_read_key(row.scope, &grants))
            }
            None => false,
            _ => return Err(Error::Corrupt("held resolution authority".into())),
        };
        if !resolved && !migration && !stored.rows.is_empty() {
            self.conn
                .execute(
                    "INSERT OR REPLACE INTO secure_held VALUES(?,?)",
                    [id.to_vec(), encode(&stored)?],
                )
                .await?;
        }
        for (frame, _) in frames {
            let operation = frame.operation_ref()?;
            if !migration {
                self.conn
                    .execute(
                        "INSERT OR IGNORE INTO secure_held_frames VALUES(?,?,?,?)",
                        [
                            operation.hash.as_bytes().to_vec(),
                            id.to_vec(),
                            encode(&operation.header.extensions.scope)?,
                            encode(frame)?,
                        ],
                    )
                    .await?;
            }
            self.conn
                .execute(
                    "UPDATE secure_operations SET status='held' WHERE hash=?",
                    [operation.hash.as_bytes().to_vec()],
                )
                .await?;
            self.conn
                .execute(
                    "DELETE FROM secure_outbox WHERE hash=?",
                    [operation.hash.as_bytes().to_vec()],
                )
                .await?;
        }
        for scope in ledger_scopes {
            if let Some(id) = self.find_scope_id(scope).await? {
                self.reseed_ledger(scope, id).await?;
            }
        }
        self.conn
            .execute(
                "UPDATE secure_metadata SET revision=revision+1 WHERE id=1",
                (),
            )
            .await?;
        self.frames_written
            .fetch_add(frames.len() as u64, Ordering::Relaxed);
        self.rows_written
            .fetch_add(stored.rows.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    pub(in crate::replica) async fn hold_closed_frame(
        &self,
        frame: &EncryptedFrame,
        time: u64,
    ) -> Result<Outcome, Error> {
        let payload = self.row_payload(frame)?;
        if let Some(membership) = payload.membership() {
            return self.hold_closed_bundle(frame, membership, time).await;
        }
        self.hold_members(&[(frame.clone(), payload)], time).await?;
        Ok(Outcome::Applied)
    }

    fn closed_held_generation(
        &self,
        scope: ResourceScope,
        time: u64,
    ) -> Result<(Commitment, bool), Error> {
        let grants = self.local_grants(time)?;
        let graph = self.graph_for(scope.domain)?;
        let keys: Vec<_> = self
            .config
            .keys
            .iter()
            .chain(&self.history)
            .filter(|key| key.scope == scope)
            .map(|key| key.generation)
            .collect();
        let local: Vec<_> = grants.iter().filter(|grant| grant.scope == scope).collect();
        let generation = rocky_core::commitment(
            "rocky.held-refresh.v1",
            &encode(&(
                self.workspace.tip,
                self.manifest,
                keys,
                local,
                self.can_read_key(scope, &grants),
                self.config.revocations.digest(time).map_err(credential)?,
                graph.seals.len(),
                graph.openings.len(),
                graph.moves.len(),
                graph.genesis_lines.len(),
                graph.finalities.len(),
                graph.checkpoints.len(),
                &graph.revoked,
            ))?,
        );
        Ok((
            generation,
            graph
                .seals
                .iter()
                .any(|seal| seal.statement.recovery.is_some()),
        ))
    }
    /// One signer discovery, bounded metadata page, or indivisible held frame.
    async fn refresh_closed_held_step(
        &self,
        scope: ResourceScope,
        time: u64,
        pass: &mut Refresh,
    ) -> Result<bool, Error> {
        let (generation, recovery) = self.closed_held_generation(scope, time)?;
        if self
            .held_refresh
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&scope)
            == Some(&generation)
        {
            return Ok(false);
        }
        if pass.generation != Some(generation) {
            *pass = Refresh {
                generation: Some(generation),
                sequence: -1,
                discover: true,
                ..Refresh::default()
            };
        }
        let table = self
            .conn
            .names()
            .physical("secure_operations")
            .unwrap_or("secure_operations")
            .to_owned();
        let writes = self
            .conn
            .connection()
            .watch_writes([(table.clone(), true)])?;
        let version = writes.table_count(&table);
        if pass
            .version
            .replace(version)
            .is_some_and(|previous| previous != version)
        {
            if !pass.records.is_empty() {
                pass.discover = false;
            }
            pass.records.clear();
        }
        if pass.records.is_empty() {
            if pass.discover {
                let found = collect_rows(self.conn.query(
                    "SELECT signer FROM secure_position_sources WHERE scope=? AND signer>? ORDER BY signer LIMIT 1",
                    [encode(&scope)?, pass.signer.clone()],
                ).await?).await?;
                let Some(record) = found.first() else {
                    self.held_refresh
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(scope, generation);
                    return Ok(false);
                };
                let [SqlValue::Blob(signer)] = record.as_slice() else {
                    return Err(Error::Corrupt("held refresh signer".into()));
                };
                pass.signer = signer.clone();
                pass.sequence = -1;
                pass.discover = false;
                return Ok(true);
            }
            // The operation's unique (author,scope,sequence) index preserves the
            // original signer/log order without sorting the whole scope.
            pass.records = collect_rows(self.conn.query(
                "SELECT o.hash,p.scope,p.tip,p.author,p.sequence,o.sequence,o.status FROM secure_operations o LEFT JOIN secure_position_sources p ON p.hash=o.hash AND p.kind=0 WHERE o.author=? AND o.scope=? AND o.sequence>? ORDER BY o.sequence LIMIT ?",
                bindings(vec![SqlValue::Blob(pass.signer.clone()), SqlValue::Blob(encode(&scope)?), SqlValue::Integer(pass.sequence), SqlValue::Integer(REFRESH_RECORDS as i64)]),
            ).await?).await?.into();
            #[cfg(any(test, feature = "qualification"))]
            self.flusher.measurements.work(
                crate::replica::lock::WorkUnit::HeldRefreshRecord,
                pass.records.len() as u64,
            );
            // A short page already proves this signer's end. Keep its buffered
            // records, then discover the next signer without an empty query.
            pass.discover = pass.records.len() < REFRESH_RECORDS;
            if pass.records.is_empty() {
                return Ok(true);
            }
        }
        let mut context = tips::refresh::RefreshGraphContext::new(&self.graphs, self.workspace.tip);
        while let Some(record) = pass.records.pop_front() {
            let [
                SqlValue::Blob(hash),
                _,
                _,
                _,
                _,
                SqlValue::Integer(log_sequence),
                SqlValue::Text(status),
            ] = record.as_slice()
            else {
                return Err(Error::Corrupt("closed source frame".into()));
            };
            pass.sequence = *log_sequence;
            if !matches!(status.as_str(), "applied" | "pending") {
                continue;
            }
            let [
                SqlValue::Blob(encoded_scope),
                SqlValue::Blob(tip),
                SqlValue::Integer(author),
                SqlValue::Integer(sequence),
            ] = &record[1..5]
            else {
                return Err(Error::Corrupt("closed source frame".into()));
            };
            if !recovery {
                let scope: ResourceScope = decode(encoded_scope)?;
                let tip = TipId(
                    tip.as_slice()
                        .try_into()
                        .map_err(|_| Error::Corrupt("closed source tip".into()))?,
                );
                let author = u32::try_from(*author)
                    .map_err(|_| Error::Corrupt("closed source author".into()))?;
                let sequence = u64::try_from(*sequence)
                    .map_err(|_| Error::Corrupt("closed source sequence".into()))?;
                if self.frame_reach_at_using(
                    scope.domain,
                    tip,
                    author,
                    sequence,
                    0,
                    Some(&mut context),
                )? != tips::FrameReach::Held
                {
                    continue;
                }
            }
            #[cfg(any(test, feature = "qualification"))]
            self.flusher
                .measurements
                .work(crate::replica::lock::WorkUnit::HeldRefreshFrame, 1);
            let (header, body) = match collect_rows(
                self.conn
                    .query(
                        "SELECT header,body FROM secure_operations WHERE hash=?",
                        [hash.clone()],
                    )
                    .await?,
            )
            .await?
            .pop()
            .as_deref()
            {
                Some([SqlValue::Blob(header), SqlValue::Blob(body)]) => {
                    (header.clone(), body.clone())
                }
                _ => return Err(Error::Corrupt("closed source frame".into())),
            };
            let frame = self.stored_frame(header, body).await?;
            let operation = frame.operation_ref()?;
            let extension = &operation.header.extensions;
            if self.stored_status(operation.hash).await?.as_deref() == Some("held") {
                return Ok(true);
            }
            if self.frame_reach(&frame)? == tips::FrameReach::Held
                && self.can_read_key(extension.scope, &self.local_grants(time)?)
                && self
                    .opening_key(extension.scope, extension.generation)
                    .is_some()
            {
                self.hold_closed_frame(&frame, time).await?;
            }

            return Ok(true);
        }
        Ok(true)
    }
    /// Holds the writes the workspace at `source` applied that `target`
    /// does not see, before a moved bookmark's workspace rebuild.
    pub(in crate::replica) async fn hold_line_writes(
        &self,
        scope: rocky_core::Scope,
        source: TipId,
        target: TipId,
    ) -> Result<usize, Error> {
        let graph = self.graph_for(scope)?;
        let mut line = BTreeSet::new();
        let mut cursor = source;
        while line.insert(cursor) {
            match Self::tip_parent(graph, cursor)? {
                Some((parent, _)) => cursor = parent,
                None => break,
            }
        }
        let records = rows(&self.conn,
            "SELECT header,body FROM secure_operations WHERE status IN ('applied','pending') ORDER BY scope,author,sequence",
        ).await?;
        let mut paths = BTreeMap::new();
        let mut held = 0;
        for record in records {
            let [SqlValue::Blob(header), SqlValue::Blob(body)] = record.as_slice() else {
                return Err(Error::Corrupt("held line frame".into()));
            };
            let frame = self.stored_frame(header.clone(), body.clone()).await?;
            let operation = frame.operation_ref()?;
            let extension = &operation.header.extensions;
            if extension.scope.domain != scope || !line.contains(&extension.tip) {
                continue;
            }
            let author = extension
                .author
                .ok_or_else(|| denied("node author number missing"))?;
            let path = match paths.entry(extension.tip) {
                std::collections::btree_map::Entry::Occupied(path) => path.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(Self::frame_path(graph, extension.tip, target)?)
                }
            };
            if !path.admits(author, extension.author_sequence)?
                && self.stored_status(operation.hash).await?.as_deref() != Some("held")
            {
                match self.hold_closed_frame(&frame, now()?).await? {
                    Outcome::Applied => held += 1,
                    Outcome::Waiting(_) => {
                        return Err(denied("cannot leave an incomplete held bundle"));
                    }
                    Outcome::Rejected(reason) => return Err(denied(&reason)),
                }
            }
        }
        Ok(held)
    }

    pub(in crate::replica) async fn record_held_resolution(
        &self,
        id: Commitment,
        authority: &[rocky_core::ResourceGrant],
    ) -> Result<(), Error> {
        let held = collect_rows(
            self.conn
                .query("SELECT change FROM secure_held WHERE id=?", [id.to_vec()])
                .await?,
        )
        .await?;
        if let Some([SqlValue::Blob(bytes)]) = held.first().map(Vec::as_slice) {
            let stored: Stored = decode_bounded(bytes, MAX_BUNDLE_BYTES * 2)?;
            if stored
                .rows
                .iter()
                .any(|row| !self.can_read_key(row.scope, authority))
            {
                return Err(denied(
                    "held resolution requires read authority for every held scope",
                ));
            }
        }
        self.conn.execute("INSERT INTO secure_held_resolved VALUES(?,?) ON CONFLICT(id) DO UPDATE SET authority=excluded.authority", [id.to_vec(), encode(&authority)?]).await?;
        self.conn
            .execute("DELETE FROM secure_held WHERE id=?", [id.to_vec()])
            .await?;
        Ok(())
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    pub(in crate::replica) async fn refresh_closed_held(
        &self,
        only: Option<ResourceScope>,
    ) -> Result<(), Error> {
        let mut after = 0;
        loop {
            let scope = match only {
                Some(scope) => scope,
                None => {
                    let inner = self.inner.lock(Class::Background).await;
                    let found = collect_rows(inner.conn.query("SELECT id,scope FROM secure_scope_state WHERE id>? ORDER BY id LIMIT 1", [after]).await?).await?;
                    let Some(record) = found.first() else {
                        return Ok(());
                    };
                    let [SqlValue::Integer(id), SqlValue::Blob(scope)] = record.as_slice() else {
                        return Err(Error::Corrupt("held refresh scope".into()));
                    };
                    after = *id;
                    decode(scope)?
                }
            };
            let mut pass = Refresh::default();
            loop {
                tokio::task::yield_now().await;
                let mut inner = self.inner.lock(Class::Background).await;
                let saved = pass.clone();
                let more = transaction!(@commit inner, |inner| {
                    pass = saved.clone();
                    inner.refresh_closed_held_step(scope, now()?, &mut pass).await
                })?;
                if !more {
                    break;
                }
            }
            if only.is_some() {
                return Ok(());
            }
        }
    }
    #[cfg(test)]
    pub(crate) async fn pause_held_token_for_test(
        &self,
        reached: tokio::sync::oneshot::Sender<()>,
        resume: tokio::sync::oneshot::Receiver<()>,
    ) {
        self.inner.lock(Class::Background).await.held_token_pause = Some((reached, resume));
    }
    /// Checks read authority independently of the peer's followed tip.
    pub(crate) async fn authorize_held_reader(
        &self,
        peer: PublicKey,
        chain: &CredentialChain,
        scope: ResourceScope,
    ) -> Result<(), Error> {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        let grants = inner.verify_chain_scopes(chain, peer, now()?, &[scope])?;
        if !inner.can_read_key(scope, &grants) {
            return Err(denied("held changes require whole-scope read authority"));
        }
        Ok(())
    }
    pub(crate) async fn held_exchange_allowed(
        &self,
        peer: PublicKey,
        chain: &CredentialChain,
        scope: ResourceScope,
    ) -> Result<bool, Error> {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        let time = now()?;
        let grants = inner.verify_chain_scopes(chain, peer, time, &[scope])?;
        Ok(inner.can_read_key(scope, &grants)
            && inner.can_read_key(scope, &inner.local_grants(time)?)
            && inner.holds(scope).await?)
    }

    /// Original signed frames of unresolved held changes, ordered by hash.
    pub(crate) async fn held_token(
        &self,
        peer: PublicKey,
        chain: &CredentialChain,
        scope: ResourceScope,
    ) -> Result<Commitment, Error> {
        self.authorize_held_reader(peer, chain, scope).await?;
        self.refresh_closed_held(Some(scope)).await?;
        let mut inner = self.inner.lock(Class::Background).await;
        inner = flush_guard(inner, &self.inner).await?;
        let tables = ["secure_held", "secure_held_frames"].map(|table| {
            inner
                .conn
                .names()
                .physical(table)
                .unwrap_or(table)
                .to_owned()
        });
        let writes = inner
            .conn
            .connection()
            .watch_writes(tables.iter().map(|table| (table.clone(), true)))?;
        let source = TokenSource {
            versions: tables.each_ref().map(|table| writes.table_count(table)),
            writes,
            tables,
            authority: inner.authority,
            tip: inner.workspace.tip,
        };
        drop(inner);
        let mut count = 0u64;
        let mut hash = rocky_core::CommitmentBuilder::new("rocky.held-token.v1");
        for hashing in [false, true] {
            if hashing {
                hash.update(&token_array_header(count));
            }
            let mut after = Vec::new();
            loop {
                tokio::task::yield_now().await;
                let inner = self.inner.lock(Class::Background).await;
                source.check(&inner)?;
                let records = collect_rows(inner.conn.query(
                    "SELECT f.hash,h.id FROM secure_held_frames f LEFT JOIN secure_held h ON h.id=f.id WHERE f.scope=? AND f.hash>? ORDER BY f.hash LIMIT ?",
                    bindings(vec![SqlValue::Blob(encode(&scope)?), SqlValue::Blob(after.clone()), SqlValue::Integer(TOKEN_RECORDS as i64)]),
                ).await?).await?;
                #[cfg(any(test, feature = "qualification"))]
                inner.flusher.measurements.work(
                    crate::replica::lock::WorkUnit::HeldTokenRecord,
                    records.len() as u64,
                );
                drop(inner);
                if records.is_empty() {
                    break;
                }
                for record in records {
                    let [SqlValue::Blob(key), present] = record.as_slice() else {
                        return Err(Error::Corrupt("held token row".into()));
                    };
                    if key.len() != 32 {
                        return Err(Error::Corrupt("held frame hash".into()));
                    }
                    after = key.clone();
                    if matches!(present, SqlValue::Blob(_)) {
                        if hashing {
                            hash.update(&encode(key)?);
                        } else {
                            count = count.checked_add(1).ok_or(Error::Quota {
                                resource: "held token rows",
                                limit: usize::MAX,
                            })?;
                        }
                    } else if !matches!(present, SqlValue::Null) {
                        return Err(Error::Corrupt("held token header".into()));
                    }
                }
                #[cfg(test)]
                {
                    let pause = self
                        .inner
                        .lock(Class::Background)
                        .await
                        .held_token_pause
                        .take();
                    if let Some((reached, resume)) = pause {
                        let _ = reached.send(());
                        let _ = resume.await;
                    }
                }
            }
        }
        let inner = self.inner.lock(Class::Background).await;
        source.check(&inner)?;
        let grants = inner.verify_chain_scopes(chain, peer, now()?, &[scope])?;
        if !inner.can_read_key(scope, &grants) {
            return Err(denied("held changes require whole-scope read authority"));
        }
        Ok(hash.finish())
    }
    pub async fn held_frame_page(
        &self,
        peer: PublicKey,
        chain: &CredentialChain,
        scope: ResourceScope,
        after: Option<Hash>,
        quota: usize,
    ) -> Result<(Vec<EncryptedFrame>, Option<Hash>), Error> {
        if quota == 0 || quota > MAX_SECURE_FRAME {
            return Err(denied("held frame page quota"));
        }
        self.authorize_held_reader(peer, chain, scope).await?;
        self.refresh_closed_held(Some(scope)).await?;
        let mut inner = self.inner.lock(Class::Background).await;
        inner = flush_guard(inner, &self.inner).await?;
        let grants = inner.verify_chain_scopes(chain, peer, now()?, &[scope])?;
        if !inner.can_read_key(scope, &grants) {
            return Err(denied("held changes require whole-scope read authority"));
        }
        let records = collect_rows(inner.conn.query(
            "SELECT f.hash,h.id FROM secure_held_frames f LEFT JOIN secure_held h ON h.id=f.id WHERE f.scope=? AND f.hash>? ORDER BY f.hash LIMIT ?",
            bindings(vec![SqlValue::Blob(encode(&scope)?), SqlValue::Blob(after.map(|hash| hash.as_bytes().to_vec()).unwrap_or_default()), SqlValue::Integer(PAGE_RECORDS as i64 + 1)]),
        ).await?).await?;
        #[cfg(any(test, feature = "qualification"))]
        inner.flusher.measurements.work(
            crate::replica::lock::WorkUnit::HeldPageRecord,
            records.len() as u64,
        );
        let mut frames: Vec<EncryptedFrame> = Vec::new();
        let mut size = 1024;
        let mut scanned = after;
        for (index, record) in records.into_iter().enumerate() {
            if index == PAGE_RECORDS {
                return Ok((frames, scanned));
            }
            let [SqlValue::Blob(key), present] = record.as_slice() else {
                return Err(Error::Corrupt("held source frame".into()));
            };
            let id = Hash::from_bytes(
                key.as_slice()
                    .try_into()
                    .map_err(|_| Error::Corrupt("held frame hash".into()))?,
            );
            if matches!(present, SqlValue::Null) {
                scanned = Some(id);
                continue;
            }
            if !matches!(present, SqlValue::Blob(_)) {
                return Err(Error::Corrupt("held source header".into()));
            }
            let bytes = collect_rows(
                inner
                    .conn
                    .query(
                        "SELECT frame FROM secure_held_frames WHERE hash=?",
                        [key.clone()],
                    )
                    .await?,
            )
            .await?;
            let Some([SqlValue::Blob(bytes)]) = bytes.first().map(Vec::as_slice) else {
                return Err(Error::Corrupt("held source frame".into()));
            };
            let frame: EncryptedFrame = decode_bounded(bytes, MAX_SECURE_FRAME)?;
            if frame.id()? != id {
                return Err(Error::Corrupt("held frame hash".into()));
            }
            if size + frame.weight() > quota {
                if frames.is_empty() {
                    return Err(denied("held frame does not fit the page quota"));
                }
                return Ok((frames, scanned));
            }
            size += frame.weight();
            frames.push(frame);
            scanned = Some(id);
        }
        Ok((frames, None))
    }
    /// Accepts only original frames whose line is closed. Ordinary live frames
    /// use `receive`; a relay never replaces their author's signature.
    pub async fn receive_held_frames(&self, frames: Vec<EncryptedFrame>) -> Result<(), Error> {
        {
            let inner = self.inner.lock(crate::replica::Class::Background).await;
            for frame in &frames {
                inner.verify_frame_authority(frame, now()?)?;
                if inner.frame_reach(frame)? != tips::FrameReach::Held {
                    return Err(denied("held transfer names a live or unrelated frame"));
                }
            }
        }
        for status in self.receive_all(frames).await {
            match status? {
                ReceiveStatus::Held
                | ReceiveStatus::Duplicate
                | ReceiveStatus::PendingDependencies => {}
                _ => return Err(denied("held transfer was not held")),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod token_encoding_tests {
    use super::*;
    #[test]
    fn token_array_headers_match_the_current_encoding_at_length_boundaries() {
        for count in [0, 1, 23, 24, 255, 256, 65_535, 65_536] {
            let encoded = encode(&vec![Vec::<u8>::new(); count]).unwrap();
            let header = token_array_header(count as u64);
            assert!(encoded.starts_with(&header));
            assert_eq!(encoded.len(), header.len() + count);
        }
        assert_eq!(
            token_array_header(1u64 << 32),
            vec![0x9b, 0, 0, 0, 1, 0, 0, 0, 0]
        );
    }
}
