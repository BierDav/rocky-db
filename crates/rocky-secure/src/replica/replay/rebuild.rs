//! Replayed tables keep no row records: their frames are their history, so
//! a rebuild empties them and replays every visible member again.
use super::*;
use rocky_credentials::SignedSeal;

impl<A: RowApplication> Inner<A> {
    /// Forgets replayed scope `scope`'s replay, as its history restarts:
    /// its rows (its partition's, or the whole unpartitioned table) and
    /// where its members stood.
    pub(in crate::replica) async fn reset_replayed(
        &self,
        scope: ResourceScope,
    ) -> Result<(), Error> {
        if let Some(id) = self.find_scope_id(scope).await? {
            self.conn
                .execute("DELETE FROM secure_replayed WHERE scope=?", [id])
                .await?;
        }
        let corrupt = || Error::Corrupt("replayed scope".into());
        let typed = self.workspace.typed.as_ref().ok_or_else(corrupt)?;
        let projected = typed.by_scope(scope).ok_or_else(corrupt)?;
        let schema = typed.rows.schema();
        let logical = schema
            .table(&projected.table.sql_name)
            .ok_or_else(corrupt)?;
        let name = typed::quoted(&logical.sql_name);
        self.touch(&logical.sql_name);
        if logical.partition_by.is_empty() {
            self.conn.execute(format!("DELETE FROM {name}"), ()).await?;
            return Ok(());
        }
        let tuple = self.partitions.get(&scope).ok_or_else(corrupt)?;
        let filter = logical
            .partition_by
            .iter()
            .map(|column| format!("{}=?", typed::quoted(column)))
            .collect::<Vec<_>>()
            .join(" AND ");
        self.conn
            .execute(
                format!("DELETE FROM {name} WHERE {filter}"),
                bindings(super::super::partition::partition_values(
                    schema, logical, tuple,
                )?),
            )
            .await?;
        Ok(())
    }

    /// Rebuilds every replayed table from its frames inside the caller's
    /// transaction: the tables empty and each visible applied intent member
    /// replays again in `(era, stamp)` order, admitted as it was recorded.
    /// A member's era is one below the first finalized seal whose bound
    /// covers it, else the open era; members those bounds cover end sealed
    /// again.
    pub(in crate::replica) async fn replay_from_frames(&self, time: u64) -> Result<(), Error> {
        self.replay_from(time, None).await
    }

    /// `replay_from_frames`, each scope starting from the newest rows the
    /// followed path passes that it holds, so that no member a seal covers
    /// replays under a later schema: kept seal `kept`'s rows when given,
    /// which every table returns to, else the rows taken at a finalized
    /// seal, else its replay base. Members the start covers keep their
    /// record; the rest replay.
    pub(in crate::replica) async fn replay_from(
        &self,
        time: u64,
        kept: Option<&history::Rewind>,
    ) -> Result<(), Error> {
        let corrupt = || Error::Corrupt("replayed history".into());
        let Some(typed) = self.workspace.typed.as_ref() else {
            return Ok(());
        };
        let domain = typed.domain;
        let mut scopes = Vec::new();
        for record in rows(&self.conn, "SELECT id,scope FROM secure_scope_state").await? {
            let [SqlValue::Integer(id), SqlValue::Blob(scope)] = record.as_slice() else {
                return Err(corrupt());
            };
            let scope: ResourceScope = decode(scope)?;
            if scope.domain == domain && self.replayed_scope(scope) {
                scopes.push((*id, scope));
            }
        }
        let open = self.open_era(domain).await?;
        let path = self.path_seals(domain)?;
        let mut members = Vec::new();
        let mut bounds = BTreeMap::new();
        let mut restored = Vec::new();
        let mut covered_members = BTreeMap::new();
        let mut based = BTreeMap::new();
        for (id, scope) in &scopes {
            let mut start = match kept {
                Some(kept) => Start {
                    floor: kept.at(*id).map_or(0, |(_, bound)| bound),
                    based: self
                        .path_base(*id, &path)
                        .await?
                        .map(|(_, signed)| signed.statement.identities)
                        .unwrap_or_default(),
                    ..Start::default()
                },
                None => self.replay_start(*id, &path).await?,
            };
            let mut covered: Vec<(i64, i64)> = Vec::new();
            for record in collect_rows(
                self.conn
                    .query(
                        "SELECT depth,position FROM secure_seal_bounds WHERE scope=? ORDER BY depth",
                        [*id],
                    )
                    .await?,
            )
            .await?
            {
                let [SqlValue::Integer(depth), SqlValue::Integer(position)] = record.as_slice()
                else {
                    return Err(corrupt());
                };
                covered.push((*depth, *position));
            }
            let recorded: BTreeSet<Hash> = collect_rows(
                self.conn
                    .query("SELECT hash FROM secure_replayed WHERE scope=?", [*id])
                    .await?,
            )
            .await?
            .iter()
            .map(|record| match record.as_slice() {
                [SqlValue::Blob(hash)] => super::super::checkpoint::hash_of(hash),
                _ => Err(corrupt()),
            })
            .collect::<Result<_, _>>()?;
            // A start whose covered members lost their record, as when they
            // left the path, cannot say how they ended: the scope starts
            // from the next older rows instead.
            // So does one whose rows lack a field the path keeps.
            let scanned = loop {
                let serves = match &start.rows {
                    Some((tip, rows)) => self.images_serve(*scope, *tip, rows)?,
                    None => true,
                };
                match serves {
                    true => match self
                        .scan_members(*id, &start, &covered, &recorded, open)
                        .await?
                    {
                        Some(scanned) => break scanned,
                        None => start = self.older_start(*id, &path, &start).await?,
                    },
                    false => start = self.older_start(*id, &path, &start).await?,
                }
            };
            eprintln!("DBG start {id} floor={} seal={} rows={:?} base={} members={}", start.floor, start.seal.is_some(), start.rows.as_ref().map(|r| r.1.len()), start.base, scanned.0.len());
            members.extend(scanned.0);
            covered_members.insert(*id, (start.floor, scanned.1));
            based.insert(*id, std::mem::take(&mut start.based));
            if let Some((tip, rows)) = start.rows {
                restored.push((*scope, tip, rows));
            }
            if let Some((_, bound)) = covered.last() {
                bounds.insert(*id, *bound);
            }
        }
        // Every replayed table empties, or returns to the kept seal's rows:
        // a cascade reaches only rows cleared anyway.
        if let Some(kept) = kept {
            self.rewind_live(kept.mark()).await?;
        }
        for table in typed.tables.iter().filter(|_| kept.is_none()) {
            if typed
                .rows
                .schema()
                .table(&table.table.sql_name)
                .is_some_and(|logical| logical.class == TableClass::Replayed)
            {
                self.touch(&table.table.sql_name);
                self.conn
                    .execute(
                        format!("DELETE FROM {}", typed::quoted(&table.table.sql_name)),
                        (),
                    )
                    .await?;
            }
        }
        // Members keep the admission they were recorded with.
        let mut recorded = BTreeMap::new();
        for (id, _) in &scopes {
            let (floor, kept_members) = covered_members.remove(id).unwrap_or_default();
            for record in collect_rows(
                self.conn
                    .query(
                        "SELECT r.hash,r.dropped,r.sealed=0 OR a.position IS NULL OR a.position>? FROM secure_replayed r LEFT JOIN secure_applied a ON a.hash=r.hash WHERE r.scope=?",
                        [floor, *id],
                    )
                    .await?,
            )
            .await?
            {
                let [SqlValue::Blob(bytes), dropped, SqlValue::Integer(after)] = record.as_slice()
                else {
                    return Err(corrupt());
                };
                let hash = super::super::checkpoint::hash_of(bytes)?;
                let admitted = !matches!(dropped, SqlValue::Text(reason) if reason == "admission");
                recorded.insert(hash, admitted);
                // Members the start covers stay as they ended.
                if *after != 0 && !kept_members.contains(&hash) {
                    self.conn
                        .execute(
                            "DELETE FROM secure_replayed WHERE hash=?",
                            [bytes.clone()],
                        )
                        .await?;
                }
            }
        }
        for (id, _) in &scopes {
            self.reset_replay_ledger(*id, based.get(id).map_or(&[][..], Vec::as_slice))
                .await?;
        }
        for (scope, source, rows) in &restored {
            self.restore_images(*scope, *source, rows).await?;
        }
        members.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
        let mut redo: Vec<Redo> = Vec::new();
        for (order, _, transaction, member) in members {
            match redo.iter_mut().find(|redo| redo.transaction == transaction) {
                Some(redo) => redo.members.push(member),
                None => redo.push(Redo {
                    transaction,
                    members: vec![member],
                    order,
                }),
            }
        }
        self.redo_recorded(redo, time, Some(&recorded)).await?;
        for (id, bound) in bounds {
            self.seal_replayed(id, bound).await?;
        }
        Ok(())
    }

    /// The newest rows on `path` scope `id` holds: rows taken at a
    /// finalized seal, or its replay base, else none.
    async fn replay_start(&self, id: i64, path: &[SignedSeal]) -> Result<Start, Error> {
        self.start_before(id, path, path.len()).await
    }
    /// The start after `start` fails: the next older one, and after the
    /// base every frame, which a pruned scope no longer holds.
    async fn older_start(
        &self,
        id: i64,
        path: &[SignedSeal],
        start: &Start,
    ) -> Result<Start, Error> {
        if start.base {
            return Ok(Start::default());
        }
        match start.seal.as_ref().and_then(|seal| {
            path.iter()
                .position(|known| known.id().ok() == Some(seal.0))
        }) {
            Some(index) => self.start_before(id, path, index).await,
            None => Err(Error::Corrupt(
                "a replayed scope's covered members are missing".into(),
            )),
        }
    }
    /// Scope `id`'s replay base when its seal is on `path`: its index there
    /// and the signed checkpoint, with the base's applied position.
    async fn path_base(
        &self,
        id: i64,
        path: &[SignedSeal],
    ) -> Result<Option<((usize, i64), SignedCheckpoint)>, Error> {
        Ok(self.checkpoint_record(id, true).await?.and_then(|record| {
            let signed = record.signed?;
            let seal = signed.statement.seal?;
            let index = path
                .iter()
                .position(|known| known.id().ok() == Some(seal))?;
            Some(((index, record.position), signed))
        }))
    }
    /// The newest start at a seal of `path` before index `end`.
    async fn start_before(
        &self,
        id: i64,
        path: &[SignedSeal],
        end: usize,
    ) -> Result<Start, Error> {
        let base = self
            .path_base(id, path)
            .await?
            .filter(|((index, _), _)| *index < end);
        let floor = base.as_ref().map_or(0, |((_, position), _)| *position);
        let based = base
            .as_ref()
            .map(|(_, signed)| signed.statement.identities.clone())
            .unwrap_or_default();
        for index in (0..end).rev() {
            if base.as_ref().is_some_and(|((at, _), _)| *at >= index) {
                break;
            }
            let seal = &path[index];
            let seal_id = seal.id().map_err(credential)?;
            if let Some(rows) = self.seal_rows(id, seal_id).await? {
                return Ok(Start {
                    floor,
                    seal: Some((seal_id, seal.clone())),
                    rows: Some((seal.statement.tip, rows)),
                    based,
                    base: false,
                });
            }
        }
        Ok(match base {
            Some((_, signed)) => Start {
                floor,
                seal: None,
                rows: Some((
                    signed.statement.tip,
                    self.stored_images("secure_replayed_base", id, None)
                        .await?,
                )),
                based,
                base: true,
            },
            None => Start::default(),
        })
    }
    /// Resets scope `id`'s replay ledger to where its replay starts: the
    /// `based` marks and the births of the members it keeps.
    pub(in crate::replica) async fn reset_replay_ledger(
        &self,
        id: i64,
        based: &[checkpoint::CoveredMark],
    ) -> Result<(), Error> {
        let corrupt = || Error::Corrupt("replayed births".into());
        let mut ledger = identity::IdentityLedger::based(based)?;
        for record in collect_rows(
            self.conn
                .query(
                    "SELECT births FROM secure_replayed WHERE scope=? AND births IS NOT NULL",
                    [id],
                )
                .await?,
        )
        .await?
        {
            let [SqlValue::Blob(births)] = record.as_slice() else {
                return Err(corrupt());
            };
            for mark in decode::<Vec<checkpoint::IdentityMark>>(births)? {
                ledger.merge(mark)?;
            }
        }
        let scope = match rows(
            &self.conn,
            &format!("SELECT scope FROM secure_scope_state WHERE id={id}"),
        )
        .await?
        .first()
        .map(Vec::as_slice)
        {
            Some([SqlValue::Blob(scope)]) => decode(scope)?,
            _ => return Err(corrupt()),
        };
        self.replace_ledger(scope, ledger).await
    }
    /// The members of scope `id` after `start` that the path shows, in
    /// replay order, and those the start's seal covers; none when a
    /// covered member has no record.
    #[allow(clippy::type_complexity)]
    async fn scan_members(
        &self,
        id: i64,
        start: &Start,
        covered: &[(i64, i64)],
        recorded: &BTreeSet<Hash>,
        open: i64,
    ) -> Result<Option<(Vec<Member>, BTreeSet<Hash>)>, Error> {
        let corrupt = || Error::Corrupt("replayed history".into());
        let mut members = Vec::new();
        let mut kept = BTreeSet::new();
        for record in collect_rows(
            self.conn
                .query(
                    "SELECT position,hash FROM secure_applied WHERE scope=? AND position>? ORDER BY position",
                    [id, start.floor],
                )
                .await?,
        )
        .await?
        {
            let [SqlValue::Integer(position), SqlValue::Blob(hash)] = record.as_slice() else {
                return Err(corrupt());
            };
            let hash = super::super::checkpoint::hash_of(hash)?;
            let frame = self
                .frame(hash)
                .await?
                .ok_or_else(|| Error::Corrupt("replayed history is pruned".into()))?;
            let operation = frame.operation()?;
            if !self.visible_in_workspace(&operation)? {
                continue;
            }
            let payload = self.row_payload(&frame)?;
            let (Some(_), Some(membership)) = (payload.intent(), payload.membership()) else {
                continue;
            };
            if let Some((_, seal)) = &start.seal {
                let extension = &operation.header.extensions;
                let author = extension.author.ok_or_else(corrupt)?;
                if Self::covers_exact(
                    self.graph_for(extension.scope.domain)?,
                    extension.tip,
                    author,
                    extension.author_sequence,
                    seal,
                )? {
                    if !recorded.contains(&hash) {
                        return Ok(None);
                    }
                    kept.insert(hash);
                    continue;
                }
            }
            let era = covered
                .iter()
                .find(|(_, bound)| *position <= *bound)
                .map_or(open, |(depth, _)| depth - 1);
            members.push((
                (era, stamp(&operation.header)),
                id,
                membership.transaction,
                (hash, membership.index),
            ));
        }
        Ok(Some((members, kept)))
    }
}

/// A member to replay: its order, scope, transaction and `(frame, index)`.
type Member = (Order, i64, Commitment, (Hash, u16));

/// Where a replayed scope's rebuild starts: rows at a seal of the path and
/// the last applied position below which nothing replays.
#[derive(Default)]
struct Start {
    floor: i64,
    /// The seal the rows were taken at, when not the replay base's.
    seal: Option<(Commitment, SignedSeal)>,
    rows: Option<(TipId, Vec<(Commitment, Vec<u8>)>)>,
    /// The identity marks the replay base on the path signs.
    based: Vec<checkpoint::CoveredMark>,
    /// The rows are the replay base: no older start exists.
    base: bool,
}
