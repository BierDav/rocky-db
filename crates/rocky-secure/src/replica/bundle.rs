//! Transaction bundles: one local transaction over several resource scopes
//! and frames, applied atomically by each reader of the partitions it holds.
use super::incoming::Outcome;
use super::*;
use rocky_core::replay::IntentStatement;

/// Frames of one bundle. Each frame holds at most `ROWS_PER_FRAME` rows of
/// one scope, which bounds a bundle's rows.
pub const MAX_BUNDLE_FRAMES: usize = 64;
pub const ROWS_PER_FRAME: usize = 32;
pub const MAX_BUNDLE_ROWS: usize = MAX_BUNDLE_FRAMES * ROWS_PER_FRAME;
/// Encoded writes of one bundle.
pub const MAX_BUNDLE_BYTES: usize = 4 * 1024 * 1024;

pub(super) const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS secure_bundle_handles(handle BLOB NOT NULL,member INTEGER NOT NULL,hash BLOB NOT NULL,PRIMARY KEY(handle,member))",
];

/// What a sealed member entry reveals to a holder of its scope key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Opening {
    scope: ResourceScope,
    sequence: u64,
    author: Option<PublicKey>,
}

fn member_aad(
    transaction: &Commitment,
    index: usize,
    count: usize,
    scope: ResourceScope,
) -> Result<Vec<u8>, Error> {
    encode(&(
        "rocky.secure-bundle.member.v2",
        transaction,
        index as u64,
        count as u64,
        scope,
    ))
}

/// What a bundle handle commits to: a retry with the same handle must
/// repeat exactly this input.
pub(super) fn input_bytes(
    writes: &[RowWrite],
    dependencies: &[Hash],
    intents: &BTreeMap<ResourceScope, Vec<IntentStatement>>,
) -> Result<Vec<u8>, Error> {
    encode(&(writes, dependencies, intents))
}

/// The durable identity of the transaction a node commits under `handle`.
pub(super) fn transaction_id(node: PublicKey, handle: &Commitment) -> Commitment {
    rocky_core::commitment(
        "rocky.secure-bundle.v1",
        &[node.as_bytes().as_slice(), handle.as_slice()].concat(),
    )
}

/// Splits writes into frames: per scope in scope order, at most
/// `ROWS_PER_FRAME` rows each. A row appears once per bundle.
fn partition<A: RowApplication>(writes: &[RowWrite], app: &A) -> Result<Vec<Vec<RowWrite>>, Error> {
    if writes.is_empty() {
        return Err(denied("empty mutation"));
    }
    if writes.len() > MAX_BUNDLE_ROWS {
        return Err(Error::Quota {
            resource: "bundle rows",
            limit: MAX_BUNDLE_ROWS,
        });
    }
    let mut scopes: BTreeMap<ResourceScope, Vec<RowWrite>> = BTreeMap::new();
    let mut rows = BTreeSet::new();
    for write in writes {
        if !write.valid()
            || !rows.insert((
                write.change.scope,
                write.change.row,
                app.row_identity(&write.change)
                    .map_err(|message| denied(&message))?,
            ))
        {
            return Err(denied("a bundle writes each row once, with a valid mask"));
        }
        scopes
            .entry(write.change.scope)
            .or_default()
            .push(write.clone());
    }
    let frames: Vec<Vec<RowWrite>> = scopes
        .into_values()
        .flat_map(|writes| {
            writes
                .chunks(ROWS_PER_FRAME)
                .map(<[RowWrite]>::to_vec)
                .collect::<Vec<_>>()
        })
        .collect();
    if frames.len() > MAX_BUNDLE_FRAMES {
        return Err(Error::Quota {
            resource: "bundle frames",
            limit: MAX_BUNDLE_FRAMES,
        });
    }
    Ok(frames)
}

/// One bundle member as the author plans it.
enum Frame {
    Rows(Vec<RowWrite>),
    Intent(Vec<IntentStatement>, Vec<super::replay::Undo>),
}

/// A SQL transaction's statements per partition its replayed writes
/// reached, with the prior images of the rows they changed there.
pub(super) type Intents = BTreeMap<ResourceScope, (Vec<IntentStatement>, Vec<super::replay::Undo>)>;

/// A required member as this replica holds it.
enum Member {
    /// Not received yet.
    Missing,
    /// Applied; None once pruned or covered by a checkpoint.
    Settled(Option<EncryptedFrame>),
    Rejected,
    Pending(EncryptedFrame),
}

impl<A: RowApplication> Inner<A> {
    /// Authors every frame of a bundle inside the caller's savepoint. All
    /// frames commit or none do; the handle returns all of them.
    pub(super) async fn author_bundle(
        &mut self,
        handle: Commitment,
        input: Commitment,
        writes: &[RowWrite],
        dependencies: &[Hash],
        time: u64,
    ) -> Result<Vec<EncryptedFrame>, Error> {
        Box::pin(self.author_bundle_carried(
            (handle, input),
            writes,
            dependencies,
            time,
            &BTreeMap::new(),
        ))
        .await
    }
    /// The bundle is named by its handle and the commitment to its input.
    pub(super) async fn author_bundle_carried(
        &mut self,
        (handle, input): (Commitment, Commitment),
        writes: &[RowWrite],
        dependencies: &[Hash],
        time: u64,
        carried: &BTreeMap<(ResourceScope, Commitment), moves::Carried>,
    ) -> Result<Vec<EncryptedFrame>, Error> {
        Box::pin(self.author_bundle_resolving(
            (handle, input),
            (writes, BTreeMap::new()),
            dependencies,
            time,
            carried,
        ))
        .await
    }
    /// A SQL transaction's bundle: one intent frame per partition its
    /// replayed writes reached.
    pub(super) async fn author_sql_bundle(
        &mut self,
        (handle, input): (Commitment, Commitment),
        intents: Intents,
        time: u64,
    ) -> Result<Vec<EncryptedFrame>, Error> {
        Box::pin(self.author_bundle_resolving(
            (handle, input),
            (&[], intents),
            &[],
            time,
            &BTreeMap::new(),
        ))
        .await
    }
    async fn author_bundle_resolving(
        &mut self,
        (handle, input): (Commitment, Commitment),
        (writes, intents): (&[RowWrite], Intents),
        dependencies: &[Hash],
        time: u64,
        carried: &BTreeMap<(ResourceScope, Commitment), moves::Carried>,
    ) -> Result<Vec<EncryptedFrame>, Error> {
        let mut births = BTreeMap::<Commitment, Vec<rocky_core::RowIdentity>>::new();
        for write in writes.iter().filter(|write| {
            write.change.before.is_none()
                && !carried.contains_key(&(write.change.scope, write.change.row))
        }) {
            if let Some(id) = self
                .app
                .row_identity(&write.change)
                .map_err(|error| denied(&error))?
            {
                births.entry(write.change.scope.table).or_default().push(id);
            }
        }
        for (table, mut ids) in births {
            ids.sort();
            let author = self
                .node_author
                .as_ref()
                .ok_or_else(|| denied("birth requires a table author"))?;
            let scope = writes
                .iter()
                .find(|write| write.change.scope.table == table)
                .ok_or_else(|| denied("birth table missing"))?
                .change
                .scope;
            let mut highest = self
                .highest_identity(self.identity_allocation_scope(scope), author.number)
                .await?;
            for id in ids {
                if rocky_core::RowIdentity::next(author.number, highest)
                    .map_err(|error| denied(&error.to_string()))?
                    != id
                {
                    return Err(denied(&format!(
                        "insert id must continue the device's own table creation log: author {}, highest {}, received {}",
                        author.number, highest, id
                    )));
                }
                highest = id.sequence();
            }
        }
        let mut ordered = writes
            .iter()
            .map(|write| {
                let identity = self
                    .app
                    .row_identity(&write.change)
                    .map_err(|message| denied(&message))?;
                Ok((
                    write.change.scope,
                    identity.filter(|_| write.change.before.is_none()),
                    write.clone(),
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        ordered.sort_by_key(|(scope, identity, _)| (*scope, *identity));
        let writes: Vec<_> = ordered.into_iter().map(|(_, _, write)| write).collect();
        let mut frames: Vec<_> = match writes.is_empty() && !intents.is_empty() {
            true => Vec::new(),
            false => partition(&writes, self.app.as_ref())?
                .into_iter()
                .map(|writes| (writes[0].change.scope, Frame::Rows(writes)))
                .collect(),
        };
        frames.extend(
            intents
                .into_iter()
                .map(|(scope, (statements, undo))| (scope, Frame::Intent(statements, undo))),
        );
        frames.sort_by_key(|(scope, _)| *scope);
        if frames.len() > MAX_BUNDLE_FRAMES {
            return Err(Error::Quota {
                resource: "bundle frames",
                limit: MAX_BUNDLE_FRAMES,
            });
        }
        // The application sees the exact transaction once, across scopes.
        if !writes.is_empty() {
            self.app
                .validate_changes(&apply::exact(&writes))
                .map_err(|message| denied(&message))?;
        }
        let node = self
            .node_author
            .as_ref()
            .ok_or_else(|| denied("node author credential missing"))?
            .key
            .public_key();
        let transaction = transaction_id(node, &handle);
        let mut plan = Vec::with_capacity(frames.len());
        let mut next = BTreeMap::new();
        // An intent scope has one member, which continues this tip.
        let mut tips = BTreeMap::new();
        for (scope, _) in &frames {
            let scope = *scope;
            let author = Some(node);
            let sequence = match next.get(&scope) {
                Some(sequence) => *sequence,
                None => {
                    let id = self.scope_id(scope).await?;
                    let tip = self.author_tip(scope, id, node).await?;
                    let sequence = tip.as_ref().map_or(0, |log| log.sequence as u64 + 1);
                    tips.insert(scope, tip);
                    sequence
                }
            };
            next.insert(scope, sequence + 1);
            plan.push(Opening {
                scope,
                sequence,
                author,
            });
        }
        let count = plan.len();
        let mut members = Vec::with_capacity(count);
        for (index, opening) in plan.iter().enumerate() {
            let key = self
                .config
                .keys
                .iter()
                .find(|key| key.scope == opening.scope)
                .ok_or_else(|| denied("author needs an authorized row key"))?;
            members.push(super::super::wire::encrypt(
                &key.key,
                &member_aad(&transaction, index, count, opening.scope)?,
                &encode(&(opening.sequence, opening.author))?,
            )?);
        }
        let mut routed = self.route_dependencies(dependencies, &plan).await?;
        let mut authored = Vec::with_capacity(count);
        let mut replayed = Vec::new();
        for (index, ((_, frame), opening)) in frames.into_iter().zip(&plan).enumerate() {
            // External dependencies go to the first frame of their scope; the
            // later frames of a scope follow it in the author's log.
            let dependencies = routed.remove(&opening.scope).unwrap_or_default();
            let membership = Membership {
                transaction,
                index: index as u16,
                members: members.clone(),
            };
            let writes = match frame {
                Frame::Rows(writes) => writes,
                Frame::Intent(statements, undo) => {
                    if !dependencies.is_empty() {
                        return Err(denied("an intent names no dependencies"));
                    }
                    let recorded = (
                        membership.transaction,
                        membership.index,
                        membership.members.len() as u16,
                    );
                    self.refuse_intent_blockers(opening.scope).await?;
                    let frame = self
                        .author_log_frame(
                            (opening.scope, tips.remove(&opening.scope).flatten()),
                            time,
                            |sequence, base| {
                                if sequence != opening.sequence {
                                    return Err(Error::Corrupt("bundle sequence plan".into()));
                                }
                                let intent = rocky_core::replay::Intent { base, statements };
                                intent.check().map_err(denied)?;
                                RowPayload::intent_bundle(membership, intent)
                            },
                        )
                        .await?;
                    // The author's execution is the transaction's local replay.
                    self.record_replayed(&frame, recorded, None, &undo, None)
                        .await?;
                    replayed.push(authored.len());
                    authored.push(frame);
                    continue;
                }
            };
            let writes = &writes;
            let stamped = writes
                .iter()
                .filter_map(|write| {
                    carried
                        .get(&(write.change.scope, write.change.row))
                        .map(|carried| (write.change.row, carried.clone()))
                })
                .collect();
            let frame = Box::pin(self.author_frame_carried(
                writes,
                &dependencies,
                time,
                &stamped,
                true,
                |sequence| {
                    if sequence != opening.sequence {
                        return Err(Error::Corrupt("bundle sequence plan".into()));
                    }
                    RowPayload::bundle(membership, writes.clone())
                },
            ))
            .await?;
            authored.push(frame);
        }
        self.record_bundle(transaction, &authored).await?;
        self.put_handle(&handle, &input, authored[0].id()?.as_bytes())
            .await?;
        for (index, frame) in authored.iter().enumerate() {
            self.conn
                .execute(
                    "INSERT INTO secure_bundle_handles VALUES(?,?,?)",
                    bindings(vec![
                        SqlValue::Blob(handle.to_vec()),
                        SqlValue::Integer(index as i64),
                        SqlValue::Blob(frame.id()?.as_bytes().to_vec()),
                    ]),
                )
                .await?;
        }
        // The author holds every member: its record lets replicas holding
        // only some of them follow, and lets a seal cover the transaction.
        // A publication's records follow its migration's initial run.
        if count > 1 && !replayed.is_empty() && !self.publishing {
            let held: Vec<_> = replayed
                .iter()
                .map(|index| (&authored[*index], *index as u16))
                .collect();
            self.publish_outcome(transaction, &held, None, time).await?;
        }
        self.injected_commit_fault()?;
        Ok(authored)
    }
    /// Each dependency belongs to exactly one scope of the bundle.
    async fn route_dependencies(
        &self,
        dependencies: &[Hash],
        plan: &[Opening],
    ) -> Result<BTreeMap<ResourceScope, Vec<Hash>>, Error> {
        if dependencies.len() > 62 {
            return Err(denied("mutation quota"));
        }
        let mut routed: BTreeMap<ResourceScope, Vec<Hash>> = BTreeMap::new();
        for dependency in dependencies {
            let scope = match self.frame(*dependency).await? {
                Some(frame) => Some(frame.scope()?),
                None => {
                    let Some((id, _)) = self.stub(*dependency).await? else {
                        return Err(denied("missing encrypted dependency"));
                    };
                    let mut found = None;
                    for opening in plan {
                        if self.find_scope_id(opening.scope).await? == Some(id) {
                            found = Some(opening.scope);
                        }
                    }
                    found
                }
            };
            match scope.filter(|scope| plan.iter().any(|opening| opening.scope == *scope)) {
                Some(scope) => routed.entry(scope).or_default().push(*dependency),
                None => {
                    return Err(denied(
                        "dependency must be applied in the same encryption scope",
                    ));
                }
            }
        }
        Ok(routed)
    }
    /// The frames a bundle handle committed, or the first member's id once
    /// any member is pruned.
    pub(super) async fn lookup_bundle(
        &self,
        handle: Commitment,
        input: Commitment,
    ) -> Result<Option<Result<Vec<EncryptedFrame>, Hash>>, Error> {
        let first = match self.lookup_handle(handle, input).await? {
            None => return Ok(None),
            Some(Err(hash)) => return Ok(Some(Err(hash))),
            Some(Ok(frame)) => frame,
        };
        let records = collect_rows(
            self.conn
                .query(
                    "SELECT hash FROM secure_bundle_handles WHERE handle=? ORDER BY member",
                    [handle.to_vec()],
                )
                .await?,
        )
        .await?;
        if records.is_empty() {
            // A handle restored from a recovery package: find the members
            // through the first frame's sealed entries.
            return self.members_of(&first).await.map(Some);
        }
        let mut frames = Vec::with_capacity(records.len());
        for record in records {
            let [SqlValue::Blob(hash)] = record.as_slice() else {
                return Err(Error::Corrupt("bundle handle".into()));
            };
            let hash = Hash::try_from(hash.as_slice())
                .map_err(|_| Error::Corrupt("bundle handle".into()))?;
            match self.frame(hash).await? {
                Some(frame) => frames.push(frame),
                None => return Ok(Some(Err(first.id()?))),
            }
        }
        Ok(Some(Ok(frames)))
    }

    /// Every member of the bundle `first` belongs to, by its own openings.
    pub(super) async fn members_of(
        &self,
        first: &EncryptedFrame,
    ) -> Result<Result<Vec<EncryptedFrame>, Hash>, Error> {
        let operation = first.operation_ref()?;
        let payload = self.row_payload(first)?;
        let membership = payload
            .membership()
            .ok_or_else(|| Error::Corrupt("bundle handle names a batch".into()))?;
        let count = membership.members.len();
        let mut frames = Vec::with_capacity(count);
        for (index, sealed) in membership.members.iter().enumerate() {
            let mut opened = None;
            for key in self.opening_keys() {
                let aad = member_aad(&membership.transaction, index, count, key.scope)?;
                if let Ok(bytes) = decrypt(&key.key, &aad, sealed) {
                    let (sequence, author) = decode(&bytes)?;
                    opened = Some(Opening {
                        scope: key.scope,
                        sequence,
                        author,
                    });
                    break;
                }
            }
            let opening = opened.ok_or_else(|| denied("bundle member key unavailable"))?;
            match self
                .member(
                    opening.author.unwrap_or(operation.header.public_key),
                    &opening,
                )
                .await?
            {
                Member::Settled(Some(frame)) => frames.push(frame),
                _ => return Ok(Err(operation.hash)),
            }
        }
        Ok(Ok(frames))
    }
    /// Applies a bundle when every member this replica must hold is present
    /// and ready: the members it can open with a key it may read and whose
    /// scope it holds. Members of other partitions do not block it. Applies
    /// them in one savepoint, or rejects every pending one when any of them
    /// is invalid.
    pub(super) async fn apply_bundle(
        &self,
        trigger: &p2panda_core::Operation<Extensions>,
        membership: &Membership,
        time: u64,
    ) -> Result<Outcome, Error> {
        let author = trigger.header.public_key;
        let scope = trigger.header.extensions.scope;
        let required = match self.required_members(membership, scope, time).await {
            Ok(required) => required,
            Err(error) => {
                self.reject(trigger.hash).await?;
                {
                    return Ok(Outcome::Rejected(error.to_string()));
                }
            }
        };
        let own = Opening {
            scope: trigger.header.extensions.scope,
            sequence: trigger.header.seq_num,
            author: trigger
                .header
                .extensions
                .author
                .map(|_| trigger.header.public_key),
        };
        if !required.contains(&(usize::from(membership.index), own)) {
            self.reject(trigger.hash).await?;
            return Ok(Outcome::Rejected("frame is not its bundle member".into()));
        }
        let mut pending = Vec::new();
        let mut settled = Vec::new();
        let mut rejected = false;
        for (index, opening) in &required {
            match self
                .member(opening.author.unwrap_or(author), opening)
                .await?
            {
                Member::Missing => return Ok(Outcome::Waiting(WaitReason::Dependencies)),
                Member::Settled(frame) => settled.extend(frame.map(|frame| (*index, frame))),
                Member::Rejected => rejected = true,
                Member::Pending(frame) => pending.push((*index, frame)),
            }
        }
        let hashes = pending
            .iter()
            .map(|(_, frame)| frame.id())
            .collect::<Result<BTreeSet<_>, _>>()?;
        if rejected {
            return self
                .reject_members(&hashes, "a bundle member was rejected")
                .await;
        }
        // An applied member still retained must be of this same transaction.
        for (index, frame) in &settled {
            if !self.member_opens(frame)? {
                return Ok(Outcome::Waiting(WaitReason::OpeningKey));
            }
            if let Err(error) = self.membership_of(frame, *index, membership) {
                return self.reject_members(&hashes, &error.to_string()).await;
            }
        }
        let mut members = Vec::with_capacity(pending.len());
        for (index, frame) in &pending {
            match self
                .open_member(frame, *index, membership, &hashes, time)
                .await
            {
                Ok(Ok(member)) => members.push(member),
                Ok(Err(reason)) => return Ok(Outcome::Waiting(reason)),
                Err(error) => return self.reject_members(&hashes, &error.to_string()).await,
            }
        }
        if members
            .iter()
            .any(|(_, payload, _)| payload.intent().is_some() != members[0].1.intent().is_some())
        {
            return self
                .reject_members(&hashes, "a bundle mixes intents and rows")
                .await;
        }
        self.conn.execute("SAVEPOINT bundle", ()).await?;
        let result = async {
            Box::pin(self.replay_members(&members, membership, time)).await?;
            let mut actual = Vec::new();
            for (frame, payload, grants) in members
                .iter()
                .filter(|(_, payload, _)| payload.intent().is_none())
            {
                let (rows, admission) = self
                    .materialize(frame, payload.writes(), grants, Some(payload))
                    .await?;
                actual.extend(
                    rows.iter()
                        .map(|(change, ..)| change.clone())
                        .filter(apply::changes),
                );
                let key = self.member_key(&frame.operation_ref()?.header.extensions)?;
                self.record_key(key).await?;
                self.write_materialized(frame, rows, admission, Some(payload))
                    .await?;
            }
            // The candidate of every held partition together.
            self.app
                .validate_changes(&actual)
                .map_err(|message| denied(&message))
        }
        .await;
        match result {
            Ok(()) => {
                self.conn.execute("RELEASE bundle", ()).await?;
                Ok(Outcome::Applied)
            }
            Err(error) => {
                self.conn.execute("ROLLBACK TO bundle", ()).await?;
                self.invalidate_context();
                self.conn.execute("RELEASE bundle", ()).await?;
                match error {
                    Error::Rejected(reason) if reason == identity::LEDGER_WAITS => {
                        Ok(Outcome::Waiting(WaitReason::Ledger))
                    }
                    Error::Rejected(reason) if reason == super::replay::KEY_WAITS => {
                        Ok(Outcome::Waiting(WaitReason::OpeningKey))
                    }
                    error if identity::receipts::semantic_refusal(&error) => {
                        self.reject_members(&hashes, &error.to_string()).await
                    }
                    error => Err(error),
                }
            }
        }
    }
    /// Replays a bundle's intent members in their partitions' canonical
    /// order and keeps them as applied log entries, whatever their outcome.
    async fn replay_members(
        &self,
        members: &[BundleMember],
        membership: &Membership,
        time: u64,
    ) -> Result<(), Error> {
        let mut intents = Vec::new();
        for (frame, payload, grants) in members {
            if let Some(intent) = payload.intent() {
                let member = payload
                    .membership()
                    .ok_or_else(|| denied("an intent carries no membership"))?
                    .index;
                intents.push((frame, intent, grants.as_slice(), member));
            }
        }
        if intents.is_empty() {
            return Ok(());
        }
        let transaction = (membership.transaction, membership.members.len() as u16);
        Box::pin(self.replay_arrival(transaction, &intents, time)).await?;
        for (frame, payload, _) in members
            .iter()
            .filter(|(_, payload, _)| payload.intent().is_some())
        {
            let key = self.member_key(&frame.operation_ref()?.header.extensions)?;
            self.record_key(key).await?;
            self.write_materialized(frame, Vec::new(), Default::default(), Some(payload))
                .await?;
        }
        Ok(())
    }
    pub(super) async fn hold_closed_bundle(
        &self,
        trigger: &EncryptedFrame,
        membership: &Membership,
        time: u64,
    ) -> Result<Outcome, Error> {
        let operation = trigger.operation_ref()?;
        let required = self
            .required_members(membership, operation.header.extensions.scope, time)
            .await?;
        if !required.iter().any(|(index, opening)| {
            *index == usize::from(membership.index)
                && opening.scope == operation.header.extensions.scope
                && opening.sequence == operation.header.seq_num
                && opening.author.unwrap_or(operation.header.public_key)
                    == operation.header.public_key
        }) {
            return Err(denied("held frame is not its bundle member"));
        }
        let mut members = Vec::with_capacity(required.len());
        for (index, opening) in required {
            let frame = match self
                .member(
                    opening.author.unwrap_or(operation.header.public_key),
                    &opening,
                )
                .await?
            {
                Member::Missing => return Ok(Outcome::Waiting(WaitReason::Dependencies)),
                Member::Rejected => return Err(denied("a held bundle member was rejected")),
                Member::Settled(None) => {
                    return Err(denied("held bundle member history was pruned"));
                }
                Member::Settled(Some(frame)) | Member::Pending(frame) => frame,
            };
            if frame.operation_ref()?.header.public_key != operation.header.public_key {
                return Err(denied("held bundle members have different authors"));
            }
            let payload = self.membership_of(&frame, index, membership)?;
            members.push((frame, payload));
        }
        self.hold_members(&members, time).await?;
        Ok(Outcome::Applied)
    }
    /// Member entries this replica opens with a readable key of a held scope,
    /// in scope and sequence order.
    /// The members to hold, found by trying the held keys on each sealed
    /// opening. Only one key opens a member, so the order of trial only
    /// saves time: the trigger's `scope` first, then the scopes with its
    /// partition values, as the other tables of a partition group, which a
    /// bundle usually spans, then every other key.
    async fn required_members(
        &self,
        membership: &Membership,
        scope: ResourceScope,
        time: u64,
    ) -> Result<Vec<(usize, Opening)>, Error> {
        let count = membership.members.len();
        if count == 0 || count > MAX_BUNDLE_FRAMES || usize::from(membership.index) >= count {
            return Err(denied("invalid bundle membership"));
        }
        let grants = self.local_grants(time).unwrap_or_default();
        let values = |scope| {
            self.partitions
                .get(scope)
                .map(|tuple| tuple.values().values().collect::<Vec<_>>())
        };
        let own = values(&scope);
        let mut keys: Vec<_> = self.opening_keys().collect();
        keys.sort_by_cached_key(|key| {
            (
                key.scope != scope,
                own.is_none() || values(&key.scope) != own,
            )
        });
        let mut required = Vec::new();
        for (index, sealed) in membership.members.iter().enumerate() {
            for key in &keys {
                let aad = member_aad(&membership.transaction, index, count, key.scope)?;
                let Ok(bytes) = decrypt(&key.key, &aad, sealed) else {
                    continue;
                };
                let (sequence, author) = decode(&bytes)?;
                let opening = Opening {
                    scope: key.scope,
                    sequence,
                    author,
                };
                if self.can_read_key(key.scope, &grants) && self.holds(key.scope).await? {
                    required.push((index, opening));
                }
                break;
            }
        }
        required.sort_by_key(|(index, opening)| (opening.scope, opening.sequence, *index));
        Ok(required)
    }
    async fn member(&self, author: PublicKey, opening: &Opening) -> Result<Member, Error> {
        let mut result = self
            .conn
            .query(
                "SELECT header,body,status FROM secure_operations WHERE author=? AND scope=? AND sequence=?",
                bindings(vec![
                    SqlValue::Blob(author.as_bytes().to_vec()),
                    SqlValue::Blob(encode(&opening.scope)?),
                    SqlValue::Integer(opening.sequence as i64),
                ]),
            )
            .await?;
        if let Some(row) = result.next().await? {
            let (header, body, status) = (
                row.get::<Vec<u8>>(0)?,
                row.get::<Vec<u8>>(1)?,
                row.get::<String>(2)?,
            );
            drop(result);
            let frame = self.stored_frame(header, body).await?;
            return Ok(match status.as_str() {
                "applied" | "abandoned" => Member::Settled(Some(frame)),
                "rejected" => Member::Rejected,
                _ => Member::Pending(frame),
            });
        }
        // Logs apply in order: a sequence at or behind the tip was applied
        // and has since been pruned or covered by a checkpoint.
        if let Some(id) = self.find_scope_id(opening.scope).await?
            && let Some(log) = self.log(id, author).await?
            && opening.sequence as i64 <= log.sequence.max(log.pruned_prefix)
        {
            return Ok(Member::Settled(None));
        }
        Ok(Member::Missing)
    }
    /// Verifies one pending member against the trigger's membership: its
    /// credentials, its own membership and dependencies outside the bundle.
    /// None while a dependency is not applied yet.
    async fn open_member(
        &self,
        frame: &EncryptedFrame,
        index: usize,
        expected: &Membership,
        bundle: &BTreeSet<Hash>,
        time: u64,
    ) -> Result<Result<BundleMember, WaitReason>, Error> {
        if !self.frame_schema_ready(frame)? {
            return Ok(Err(WaitReason::Schema));
        }
        if !self.member_opens(frame)? {
            return Ok(Err(WaitReason::OpeningKey));
        }
        let grants = self.verify_frame(frame, time)?;
        let payload = self.membership_of(frame, index, expected)?;
        if !self
            .own_chain_ready(&frame.operation_ref()?.header, bundle)
            .await?
        {
            return Ok(Err(WaitReason::OwnChain));
        }
        if !self
            .dependencies_ready(frame, bundle, Some(&payload))
            .await?
        {
            return Ok(Err(WaitReason::Dependencies));
        }
        Ok(Ok((frame.clone(), payload, grants)))
    }
    /// Whether this replica holds the key that sealed a member; a held
    /// member waits for it, as a single frame does.
    fn member_opens(&self, frame: &EncryptedFrame) -> Result<bool, Error> {
        let extension = &frame.operation_ref()?.header.extensions;
        Ok(self
            .opening_key(extension.scope, extension.generation)
            .is_some())
    }
    /// Decrypts a member and checks it carries `expected` at `index`.
    fn membership_of(
        &self,
        frame: &EncryptedFrame,
        index: usize,
        expected: &Membership,
    ) -> Result<RowPayload, Error> {
        let payload = self.row_payload(frame)?;
        match payload.membership() {
            Some(membership)
                if usize::from(membership.index) == index
                    && membership.transaction == expected.transaction
                    && membership.members == expected.members =>
            {
                Ok(payload)
            }
            _ => Err(denied("bundle members disagree")),
        }
    }
    /// The key epoch that sealed a member frame.
    fn member_key(&self, extension: &Extensions) -> Result<&KeyMaterial, Error> {
        self.opening_key(extension.scope, extension.generation)
            .ok_or_else(|| denied("bundle member key unavailable"))
    }
    async fn reject_members(
        &self,
        hashes: &BTreeSet<Hash>,
        reason: &str,
    ) -> Result<Outcome, Error> {
        for hash in hashes {
            self.reject(*hash).await?;
        }
        Ok(Outcome::Rejected(reason.into()))
    }
}

type BundleMember = (EncryptedFrame, RowPayload, Vec<rocky_core::ResourceGrant>);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_openings_bind_scope_even_when_scopes_share_a_secret() {
        let scope = ResourceScope {
            domain: rocky_core::Scope {
                mesh: rocky_core::MeshId([1; 16]),
                app: rocky_core::AppId([2; 16]),
                domain: rocky_core::DomainId([3; 16]),
            },
            encryption: [2; 32],
            table: [3; 32],
        };
        let other = ResourceScope {
            table: [4; 32],
            ..scope
        };
        let transaction = [5; 32];
        let key = [6; 32];
        let plaintext = encode(&(17_u64, Some(PrivateKey::new().public_key()))).unwrap();
        let sealed = super::super::super::wire::encrypt(
            &key,
            &member_aad(&transaction, 0, 64, scope).unwrap(),
            &plaintext,
        )
        .unwrap();
        assert_eq!(
            decrypt(
                &key,
                &member_aad(&transaction, 0, 64, scope).unwrap(),
                &sealed
            )
            .unwrap(),
            plaintext
        );
        for aad in [
            member_aad(&transaction, 0, 64, other).unwrap(),
            member_aad(&transaction, 1, 64, scope).unwrap(),
            member_aad(&transaction, 0, 63, scope).unwrap(),
            member_aad(&[7; 32], 0, 64, scope).unwrap(),
        ] {
            assert!(decrypt(&key, &aad, &sealed).is_err());
        }
    }
}
