//! Lazy compaction at seals, in a domain with a tip graph. Every device
//! finalizes the state at each seal of its followed path once it holds every
//! frame through the seal's frontier: rows dead there stay dead. Compacting
//! moves the replay base to a finalized seal and releases the evidence
//! behind it.
use super::checkpoint::{
    CHECKPOINT_FORMAT, CheckpointStatement, LogPosition, Overlay, PruneBlock, STEP_OPERATIONS,
    STEP_ROWS, SetSummary, Sets,
};
use super::*;
use rocky_core::Scope;
use rocky_credentials::SignedSeal;
mod anchors;
mod incremental;
mod indexed;
mod oracle;
mod row_positions;
pub(super) use indexed::check_schema as check_incremental_schema;
mod readiness;
mod rebootstrap;
pub use rebootstrap::{FrameReplay, SealRebootstrap};

pub(super) const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS secure_seal_anchors(scope INTEGER PRIMARY KEY,frontier BLOB NOT NULL) WITHOUT ROWID",
    // Seals of the followed path this replica finalized, oldest first. The
    // last compacted one is its scopes' replay base.
    "CREATE TABLE IF NOT EXISTS secure_finalized(domain BLOB NOT NULL,depth INTEGER NOT NULL,seal BLOB NOT NULL,compacted INTEGER NOT NULL,PRIMARY KEY(domain,depth)) WITHOUT ROWID",
    // Per scope and uncompacted finalized seal: the last applied position
    // it includes. Applied positions it excludes follow every included one.
    "CREATE TABLE IF NOT EXISTS secure_seal_bounds(scope INTEGER NOT NULL,depth INTEGER NOT NULL,position INTEGER NOT NULL,PRIMARY KEY(scope,depth)) WITHOUT ROWID",
    // What finalizing at that seal changed: a row without fields is dropped.
    "CREATE TABLE IF NOT EXISTS secure_seal_drops(scope INTEGER NOT NULL,depth INTEGER NOT NULL,row BLOB NOT NULL,fields BLOB,PRIMARY KEY(scope,depth,row)) WITHOUT ROWID",
    // Domains whose compacted seal lost a race: their base must be rebuilt
    // at the winner.
    "CREATE TABLE IF NOT EXISTS secure_compaction_lost(domain BLOB PRIMARY KEY,seal BLOB NOT NULL) WITHOUT ROWID",
];

/// One finalized seal of a domain's followed path.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Finalized {
    depth: i64,
    seal: Commitment,
    compacted: bool,
}

/// What a `compact` call finalized, compacted and released.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompactReport {
    /// The newest seal whose state this replica finalized.
    pub finalized: Option<Commitment>,
    /// The seal the domain's replay base sits at.
    pub compacted: Option<Commitment>,
    /// Retained operations released behind it.
    pub pruned: u64,
    /// Why the next seal of the followed path is not finalized yet.
    pub waiting: Option<String>,
    /// What stopped releasing a scope's operations.
    pub blocked: Vec<(ResourceScope, PruneBlock)>,
}

/// Where a domain's compaction stands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompactionStatus {
    pub finalized: Option<Commitment>,
    pub compacted: Option<Commitment>,
    /// Finalized seals whose evidence is still retained, oldest first.
    pub uncompacted: Vec<Commitment>,
    /// Why the next seal of the followed path is not finalized yet.
    pub waiting: Option<String>,
    /// The compacted seal lost a race; the base must be rebuilt at the
    /// winning seal from a checkpoint or replayed frames.
    pub rebootstrap: Option<Commitment>,
}

impl<A: RowApplication> Inner<A> {
    /// The seals the followed tip's state passes through, oldest first: the
    /// canonical seal leaving each tip of its ancestry, through openings,
    /// then the followed tip's own once sealed.
    pub(super) fn path_seals(&self, domain: Scope) -> Result<Vec<SignedSeal>, Error> {
        let Some(graph) = self.graphs.get(&domain) else {
            return Ok(Vec::new());
        };
        if self.workspace.followed.as_ref().map(|(scope, _)| *scope) != Some(domain) {
            return Ok(Vec::new());
        }
        let mut cache = self
            .graph_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (domain, self.workspace.tip);
        if let Some(path) = cache.paths.get(&key) {
            return Ok(path.clone());
        }
        let path = tip_path_seals(graph, self.workspace.tip)?;
        cache.paths.insert(key, path.clone());
        Ok(path)
    }
    /// Where `seal` lies on the followed path; none off it.
    pub(super) fn path_index(
        &self,
        domain: Scope,
        seal: Commitment,
    ) -> Result<Option<usize>, Error> {
        Ok(self
            .path_seals(domain)?
            .iter()
            .position(|known| known.id().is_ok_and(|id| id == seal)))
    }
    async fn finalized(&self, domain: Scope) -> Result<Vec<Finalized>, Error> {
        let records = collect_rows(
            self.conn
                .query(
                    "SELECT depth,seal,compacted FROM secure_finalized WHERE domain=? ORDER BY depth",
                    [encode(&domain)?],
                )
                .await?,
        )
        .await?;
        records
            .into_iter()
            .map(|record| match record.as_slice() {
                [
                    SqlValue::Integer(depth),
                    SqlValue::Blob(seal),
                    SqlValue::Integer(compacted),
                ] => Ok(Finalized {
                    depth: *depth,
                    seal: checkpoint::row_of(seal)?,
                    compacted: *compacted != 0,
                }),
                _ => Err(Error::Corrupt("finalized seal".into())),
            })
            .collect()
    }
    /// The depth `seal` was finalized at, while it is recorded.
    pub(super) async fn finalized_depth(
        &self,
        domain: Scope,
        seal: Commitment,
    ) -> Result<Option<i64>, Error> {
        Ok(self
            .finalized(domain)
            .await?
            .into_iter()
            .find(|known| known.seal == seal)
            .map(|known| known.depth))
    }
    /// Per uncompacted finalized seal of scope `id`, in order: its depth and
    /// the last applied position it includes.
    async fn seal_bounds(&self, id: i64) -> Result<Vec<(i64, i64)>, Error> {
        let records = collect_rows(
            self.conn
                .query(
                    "SELECT depth,position FROM secure_seal_bounds WHERE scope=? ORDER BY depth",
                    [id],
                )
                .await?,
        )
        .await?;
        records
            .into_iter()
            .map(|record| match record.as_slice() {
                [SqlValue::Integer(depth), SqlValue::Integer(position)] => Ok((*depth, *position)),
                _ => Err(Error::Corrupt("seal bound".into())),
            })
            .collect()
    }
    /// Inside the caller's transaction, forgets scope `id`'s seal bounds
    /// through `position` and their drops.
    pub(super) async fn drop_seal_bounds(&self, id: i64, position: i64) -> Result<(), Error> {
        self.conn
            .execute(
                "DELETE FROM secure_seal_drops WHERE scope=?1 AND depth IN(SELECT depth FROM secure_seal_bounds WHERE scope=?1 AND position<=?2)",
                [id, position],
            )
            .await?;
        self.conn
            .execute(
                "DELETE FROM secure_seal_bounds WHERE scope=? AND position<=?",
                [id, position],
            )
            .await?;
        Ok(())
    }
    /// Whether a scope's state passed a seal: some rows may be absent
    /// because they were dead there.
    pub(super) async fn seal_finalized(&self, scope: ResourceScope) -> Result<bool, Error> {
        if !self.graphs.contains_key(&scope.domain) {
            return Ok(false);
        }
        let Some(id) = self.find_scope_id(scope).await? else {
            return Ok(false);
        };
        if !self.seal_bounds(id).await?.is_empty() {
            return Ok(true);
        }
        Ok(self
            .checkpoint_record(id, true)
            .await?
            .and_then(|record| record.signed)
            .is_some_and(|signed| signed.statement.seal.is_some()))
    }
    /// A tip rebuild that keeps no seal base replays from nothing.
    pub(super) fn ignores_base(&self) -> bool {
        self.rebuilding_tip && !self.tip_base
    }
    /// `replay`, applying what finalizing a seal changed once the replay
    /// passes the last position the seal includes.
    // The scope, its base, the view and target replayed, and the bounds.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn replay_sealed(
        &self,
        scope: ResourceScope,
        id: i64,
        overlay: Overlay,
        target: TipId,
        (after, through): (i64, i64),
        limit: usize,
        sets: &mut Sets,
        ledger: &mut identity::IdentityLedger,
        mode: checkpoint::ReplayMode,
    ) -> Result<Option<i64>, Error> {
        let bounds = self.seal_bounds(id).await?;
        let end = bounds
            .iter()
            .map(|(_, position)| *position)
            .filter(|position| *position > after && *position <= through)
            .min()
            .unwrap_or(through);
        let last = self
            .replay(
                scope,
                id,
                overlay,
                target,
                (after, end),
                limit,
                sets,
                ledger,
                mode,
            )
            .await?;
        if last == Some(end) {
            for (depth, _) in bounds.iter().filter(|(_, position)| *position == end) {
                self.apply_drops(id, *depth, overlay, sets).await?;
            }
        }
        Ok(last)
    }
    async fn apply_drops(
        &self,
        id: i64,
        depth: i64,
        overlay: Overlay,
        sets: &mut Sets,
    ) -> Result<(), Error> {
        let drops = collect_rows(
            self.conn
                .query(
                    "SELECT row,fields FROM secure_seal_drops WHERE scope=? AND depth=? ORDER BY row",
                    [id, depth],
                )
                .await?,
        )
        .await?;
        for record in drops {
            let (row, fields) = match record.as_slice() {
                [SqlValue::Blob(row), SqlValue::Null] => (checkpoint::row_of(row)?, Vec::new()),
                [SqlValue::Blob(row), SqlValue::Blob(fields)] => {
                    (checkpoint::row_of(row)?, fields.clone())
                }
                _ => return Err(Error::Corrupt("seal drop".into())),
            };
            let old = self.replay_row(overlay, id, row).await?;
            match (&old, fields.is_empty()) {
                (Some(old), true) => sets.remove_stored(self, &row, old).await?,
                (old, false) => {
                    sets.replace_stored(self, &row, old.as_deref(), &fields)
                        .await?
                }
                (None, true) => continue,
            }
            self.conn
                .execute(
                    format!("INSERT OR REPLACE INTO {} VALUES(?,?,?)", overlay.table()),
                    bindings(vec![
                        SqlValue::Integer(id),
                        SqlValue::Blob(row.to_vec()),
                        SqlValue::Blob(fields),
                    ]),
                )
                .await?;
        }
        Ok(())
    }
    /// The position the replay of scope `id` has passed the last finalized
    /// seal at: its bound, else its base's.
    async fn last_bound(&self, id: i64) -> Result<i64, Error> {
        if let Some((_, position)) = self.seal_bounds(id).await?.last() {
            return Ok(*position);
        }
        Ok(self
            .checkpoint_record(id, true)
            .await?
            .filter(|record| {
                record
                    .signed
                    .as_ref()
                    .is_some_and(|signed| signed.statement.seal.is_some())
            })
            .map_or(0, |record| record.position))
    }
    /// The positions `blocking_gaps` checks, over `scopes` (open) of
    /// `domain`; a placement counts only outside every held scope.
    #[cfg(test)]
    pub(super) async fn scan_held_positions(
        &self,
        domain: Scope,
        scopes: &[(ResourceScope, Option<i64>)],
        held_scopes: &BTreeSet<ResourceScope>,
    ) -> Result<Positions, Error> {
        let mut held = BTreeMap::<u32, BTreeSet<u64>>::new();
        let mut last = BTreeMap::<(ResourceScope, u32), u64>::new();
        let ready: BTreeSet<ResourceScope> = scopes.iter().map(|(scope, _)| *scope).collect();
        // A pending frame of a scope this replica does not hold, one whose
        // key it lacks, still places its signed position in that scope; so
        // does a peer's signed header of a scope it cannot hold.
        for record in rows(
            &self.conn,
            "SELECT header,status='pending',0 FROM secure_operations UNION ALL SELECT header,0,0 FROM secure_voids UNION ALL SELECT header,0,1 FROM secure_placements",
        )
        .await?
        {
            let [SqlValue::Blob(bytes), SqlValue::Integer(pending), SqlValue::Integer(placed)] =
                record.as_slice()
            else {
                return Err(Error::Corrupt("frame header".into()));
            };
            let e = self.oracle_header(bytes)?;
            if e.scope.domain != domain
                || (*pending != 0 && ready.contains(&e.scope) && self.has_scope_key(e.scope))
                || (*placed != 0 && held_scopes.contains(&e.scope))
            {
                continue;
            }
            let Some(author) = e.author else { continue };
            held.entry(author).or_default().insert(e.author_sequence);
            if *placed != 0 {
                continue;
            }
            if ready.contains(&e.scope) {
                let mark = last.entry((e.scope, author)).or_insert(e.author_sequence);
                *mark = (*mark).max(e.author_sequence);
            }
        }
        Ok((held, last))
    }
    #[cfg(test)]
    pub(crate) async fn scan_positions_for_test(
        &self,
        domain: Scope,
        scopes: &[(ResourceScope, Option<i64>)],
        held: &BTreeSet<ResourceScope>,
    ) -> Result<Positions, Error> {
        let _oracle = self.position_oracles.start();
        self.scan_held_positions(domain, scopes, held).await
    }
    #[cfg(test)]
    pub(crate) async fn seal_waits_for_test(
        &self,
        seal: &SignedSeal,
        scopes: &[(ResourceScope, Option<i64>)],
    ) -> Result<Option<String>, Error> {
        self.seal_waits(seal.statement.scope, seal, None, scopes)
            .await
    }
    /// Why `seal` cannot be finalized yet, after `previous` on the path: a
    /// held scope misses a frame through the frontier, or its state cannot
    /// be rebuilt there.
    pub(in crate::replica) async fn seal_waits(
        &self,
        domain: Scope,
        seal: &SignedSeal,
        previous: Option<&SignedSeal>,
        scopes: &[(ResourceScope, Option<i64>)],
    ) -> Result<Option<String>, Error> {
        for (scope, _) in scopes {
            if self.direct.contains(scope) || self.importing(*scope).await? {
                return Ok(Some("a scope is being imported".into()));
            }
        }
        self.seal_coverage_waits(domain, seal, previous, scopes)
            .await
    }
    /// Checks retained history independently of an owner's future import intent.
    pub(in crate::replica) async fn seal_coverage_waits(
        &self,
        domain: Scope,
        seal: &SignedSeal,
        previous: Option<&SignedSeal>,
        scopes: &[(ResourceScope, Option<i64>)],
    ) -> Result<Option<String>, Error> {
        let at = self.path_index(domain, seal.id().map_err(credential)?)?;
        let mut open = Vec::new();
        for (scope, id) in scopes {
            if let Some(id) = id {
                // Only an installed base stands in for live coverage.
                let state = self.base_seal(*id).await?;
                if let Some(base) = state
                    && self.path_index(domain, base)? >= at
                {
                    continue;
                }
                if state.is_none() && self.has_pruned_prefix(*scope).await? {
                    return Ok(Some(Self::unverified_reason(*scope)));
                }
            }
            open.push((*scope, *id));
        }
        let unverified: BTreeSet<_> = self
            .unverified_scopes(domain)
            .await?
            .into_iter()
            .map(|(scope, _)| scope)
            .collect();
        let held_scopes = self.custody_scopes(now()?)?;
        let (held, last) = self.held_positions(domain, &open, &held_scopes).await?;
        for (scope, id) in &open {
            let previous = if unverified.contains(scope) {
                None
            } else {
                previous
            };
            if let Some((author, _)) = blocking_gaps(
                seal,
                &self.seal_starts(*id, previous).await?,
                &[(*scope, *id)],
                &held,
                &last,
                1,
            )
            .into_iter()
            .next()
            {
                return Ok(Some(
                    if unverified.contains(scope)
                        || match id {
                            Some(id) => self.has_seal_anchor(*id).await?,
                            None => false,
                        }
                    {
                        Self::unverified_reason(*scope)
                    } else {
                        format!("missing frames of author {author} through the seal's frontier")
                    },
                ));
            }
            if self.has_pruned_prefix(*scope).await? && id.is_none() {
                return Ok(Some(Self::unverified_reason(*scope)));
            }
        }
        Ok(None)
    }
    /// What finalizing drops from a scope's stored rows: its tombstones.
    /// A replayed scope keeps no row records; its replay records its drops.
    async fn seal_drops(
        &self,
        scope: ResourceScope,
        indexed: bool,
    ) -> Result<Vec<(Commitment, Option<Materialized>)>, Error> {
        if self.replayed_scope(scope) {
            return Ok(Vec::new());
        }
        let sql = if indexed {
            "SELECT row,fields FROM secure_rows WHERE scope=(SELECT id FROM secure_scope_state WHERE scope=?1) AND row>?2 AND live=0 ORDER BY row LIMIT ?3"
        } else {
            "SELECT row,fields FROM secure_row_records WHERE scope=?1 AND row>?2 ORDER BY row LIMIT ?3"
        };
        let blob = encode(&scope)?;
        let mut drops = Vec::new();
        let mut after = Vec::new();
        loop {
            let records = collect_rows(
                self.conn
                    .query(
                        sql,
                        bindings(vec![
                            SqlValue::Blob(blob.clone()),
                            SqlValue::Blob(after.clone()),
                            SqlValue::Integer(STEP_ROWS as i64),
                        ]),
                    )
                    .await?,
            )
            .await?;
            if records.is_empty() {
                return Ok(drops);
            }
            for record in records {
                let [SqlValue::Blob(key), SqlValue::Blob(fields)] = record.as_slice() else {
                    return Err(Error::Corrupt("stored row".into()));
                };
                after = key.clone();
                if self.decode_record(fields).await?.deleted {
                    drops.push((checkpoint::row_of(key)?, None));
                }
            }
        }
    }
    /// Per held scope: its applied positions after its last bound that
    /// `seal` excludes and the last one it includes. Pending drops and
    /// constraint dependencies also make a scope participate.
    async fn seal_changes(
        &self,
        domain: Scope,
        seal: &SignedSeal,
        scopes: &[(ResourceScope, i64)],
        indexed: bool,
    ) -> Result<Vec<SealChange>, Error> {
        let graph = self.graph_for(domain)?;
        let mut changes = Vec::new();
        for (scope, id) in scopes {
            let bound = self.last_bound(*id).await?;
            let mut change = SealChange {
                scope: *scope,
                id: *id,
                through: bound,
                excluded: Vec::new(),
                changed: false,
                replayed: self.replayed_scope(*scope),
            };
            if indexed {
                (change.through, change.excluded) =
                    self.indexed_seal_cut(*scope, *id, bound, seal).await?;
            } else {
                let records = collect_rows(
                self.conn
                    .query(
                        "SELECT a.position,a.hash,o.header FROM secure_applied a LEFT JOIN secure_operations o ON o.hash=a.hash WHERE a.scope=? AND a.position>? ORDER BY a.position",
                        [*id, bound],
                    )
                    .await?,
            )
            .await?;
                for record in records {
                    let [
                        SqlValue::Integer(position),
                        SqlValue::Blob(hash),
                        SqlValue::Blob(header),
                    ] = record.as_slice()
                    else {
                        return Err(Error::Corrupt(
                            "an applied operation after the last finalized seal is not retained"
                                .into(),
                        ));
                    };
                    let header: p2panda_core::Header<Extensions> = decode(header)?;
                    let e = &header.extensions;
                    let author = e.author.ok_or_else(|| denied("node author missing"))?;
                    if self.visible_frame(
                        graph,
                        e.tip,
                        author,
                        e.author_sequence,
                        seal.statement.tip,
                    )? {
                        change.through = *position;
                    } else {
                        change.excluded.push((*position, hash.clone()));
                    }
                }
            }
            change.changed = change.through > bound || !change.excluded.is_empty();
            if !change.changed && !change.replayed {
                change.changed = if indexed {
                    self.has_indexed_seal_drops(*id).await?
                } else {
                    !self.seal_drops(*scope, false).await?.is_empty()
                };
            }
            changes.push(change);
        }
        Ok(changes)
    }
}

/// How a seal changes one held scope.
struct SealChange {
    scope: ResourceScope,
    id: i64,
    /// The last position this seal includes.
    through: i64,
    /// Positions after `bound` it excludes, in order, with their hashes.
    excluded: Vec<(i64, Vec<u8>)>,
    changed: bool,
    /// A replayed scope keeps no row records: replay orders its rows.
    replayed: bool,
}

/// Where the finalized seals start on the path: only the latest compacted
/// one is kept of those before. None when the oldest left the path.
fn offset(path: &[SignedSeal], finalized: &[Finalized]) -> Option<usize> {
    match finalized.first() {
        None => Some(0),
        Some(first) => path
            .iter()
            .position(|seal| seal.id().is_ok_and(|id| id == first.seal)),
    }
}

/// The highest position in `from..=to` that `positions` lacks.
/// Positions of every node's frames, voids and placements a replica holds:
/// per node, and per open scope's last frame.
#[cfg(test)]
type Positions = (
    BTreeMap<u32, BTreeSet<u64>>,
    BTreeMap<(ResourceScope, u32), u64>,
);
/// Up to `limit` positions of `seal`'s frontier at each author's start that keep it
/// from being finalized: missing from `held`, and at or after some open
/// scope's last frame of the node, so they may be that scope's.
pub(super) fn blocking_gaps(
    seal: &SignedSeal,
    starts: &BTreeMap<u32, u64>,
    scopes: &[(ResourceScope, Option<i64>)],
    held: &BTreeMap<u32, positions::Runs>,
    last: &BTreeMap<(ResourceScope, u32), u64>,
    limit: usize,
) -> Vec<(u32, u64)> {
    let mut gaps = Vec::new();
    if scopes.is_empty() {
        return gaps;
    }
    for mark in &seal.statement.frontier {
        let from = starts.get(&mark.author).copied().unwrap_or(0);
        if from > mark.sequence
            || highest_missing(held.get(&mark.author), from, mark.sequence).is_none()
        {
            continue;
        }
        // A missing position below every open scope's last frame of the node
        // is in another scope: each scope's log is contiguous.
        let threshold = scopes
            .iter()
            .map(|(scope, _)| last.get(&(*scope, mark.author)).copied().unwrap_or(0))
            .min()
            .unwrap_or(0)
            .max(from);
        if threshold > mark.sequence {
            continue;
        }
        let positions = held.get(&mark.author);
        let mut expected = threshold;
        for (start, end) in positions.into_iter().flat_map(|p| p.0.iter()) {
            if *end < expected {
                continue;
            }
            if *start > mark.sequence {
                break;
            }
            while expected < *start && expected <= mark.sequence {
                gaps.push((mark.author, expected));
                if gaps.len() >= limit {
                    return gaps;
                }
                expected += 1;
            }
            expected = expected.max(end.saturating_add(1));
        }
        while expected <= mark.sequence {
            gaps.push((mark.author, expected));
            if gaps.len() >= limit {
                return gaps;
            }
            let Some(next) = expected.checked_add(1) else {
                break;
            };
            expected = next;
        }
    }
    gaps
}
fn highest_missing(positions: Option<&positions::Runs>, from: u64, to: u64) -> Option<u64> {
    let mut expected = to;
    if let Some(positions) = positions {
        for (start, end) in positions.0.iter().rev() {
            if *start > expected {
                continue;
            }
            if *end < expected {
                return Some(expected);
            }
            if *start <= from {
                return None;
            }
            expected = start - 1;
        }
    }
    Some(expected)
}

impl<A: RowApplication> Inner<A> {
    /// Finalizes the domain's state at `seal`, inside the caller's
    /// transaction. Excluded operations move after included ones; frontier
    /// drops are recorded before replaying the tail. Tests also run the
    /// full scope rebuild through this transaction boundary.
    async fn finalize_seal_impl(
        &mut self,
        domain: Scope,
        seal: &SignedSeal,
        scopes: &[(ResourceScope, Option<i64>)],
        keep: bool,
        incremental: bool,
    ) -> Result<(), Error> {
        let mut materialized = Vec::new();
        for (scope, _) in scopes {
            if self.deferred_at(*scope, seal).await? {
                continue;
            }
            let id = self.scope_id(*scope).await?;
            materialized.push((*scope, id));
            let ordinary = self
                .checkpoint_record(id, false)
                .await?
                .is_some_and(|record| {
                    record
                        .signed
                        .as_ref()
                        .is_none_or(|signed| signed.statement.seal.is_none())
                });
            if ordinary {
                self.clear_checkpoints(*scope, id).await?;
            }
        }
        let changes = self
            .seal_changes(domain, seal, &materialized, incremental)
            .await?;
        let depth = match self
            .finalized_depth(domain, seal.id().map_err(credential)?)
            .await?
        {
            Some(depth) => depth,
            None => match collect_rows(
                self.conn
                    .query(
                        "SELECT COALESCE(MAX(depth),0)+1 FROM secure_finalized WHERE domain=?",
                        [encode(&domain)?],
                    )
                    .await?,
            )
            .await?
            .first()
            .map(Vec::as_slice)
            {
                Some([SqlValue::Integer(depth)]) => *depth,
                _ => return Err(Error::Corrupt("finalized depth".into())),
            },
        };
        let changed: Vec<&SealChange> = changes.iter().filter(|change| change.changed).collect();
        // Rows of replayed scopes follow their replay order, not records.
        let restored: Vec<&SealChange> = changed
            .iter()
            .copied()
            .filter(|change| !change.replayed)
            .collect();
        // Application order stays causal: every operation the seal
        // excludes, in order, after every one it includes.
        self.conn
            .execute("DELETE FROM secure_finalization_rows", ())
            .await?;
        for change in &changed {
            for (position, hash) in &change.excluded {
                let births = collect_rows(self.conn.query("SELECT author,signer,sequence FROM secure_birth_positions WHERE scope=? AND position=?", [change.id, *position]).await?).await?;
                let touched = collect_rows(
                    self.conn
                        .query(
                            "SELECT row FROM secure_row_positions WHERE position=?",
                            [*position],
                        )
                        .await?,
                )
                .await?;
                for row in &touched {
                    let [SqlValue::Blob(row)] = row.as_slice() else {
                        return Err(Error::Corrupt("row position".into()));
                    };
                    self.conn
                        .execute(
                            "INSERT OR IGNORE INTO secure_finalization_rows VALUES(?,?)",
                            bindings(vec![
                                SqlValue::Integer(change.id),
                                SqlValue::Blob(row.clone()),
                            ]),
                        )
                        .await?;
                }
                self.conn
                    .execute("DELETE FROM secure_applied WHERE position=?", [*position])
                    .await?;
                self.conn
                    .execute(
                        "INSERT INTO secure_applied(scope,hash) VALUES(?,?)",
                        bindings(vec![
                            SqlValue::Integer(change.id),
                            SqlValue::Blob(hash.clone()),
                        ]),
                    )
                    .await?;
                for birth in births {
                    let [author, signer, sequence] = birth.as_slice() else {
                        return Err(Error::Corrupt("birth position".into()));
                    };
                    self.conn.execute("INSERT INTO secure_birth_positions SELECT ?,position,?,?,? FROM secure_applied WHERE hash=?", bindings(vec![SqlValue::Integer(change.id), author.clone(), signer.clone(), sequence.clone(), SqlValue::Blob(hash.clone())])).await?;
                }
                for row in touched {
                    let [SqlValue::Blob(row)] = row.as_slice() else {
                        return Err(Error::Corrupt("row position".into()));
                    };
                    self.conn.execute("INSERT INTO secure_row_positions SELECT ?,?,position FROM secure_applied WHERE hash=?", bindings(vec![SqlValue::Integer(change.id), SqlValue::Blob(row.clone()), SqlValue::Blob(hash.clone())])).await?;
                }
            }
        }
        // A scope whose every applied operation the seal includes already
        // holds the seal's state: rebuilding it would rewrite every row.
        let mut whole = BTreeSet::new();
        for change in &restored {
            let last = match collect_rows(
                self.conn
                    .query(
                        "SELECT COALESCE(MAX(position),0) FROM secure_applied WHERE scope=?",
                        [change.id],
                    )
                    .await?,
            )
            .await?
            .first()
            .map(Vec::as_slice)
            {
                Some([SqlValue::Integer(last)]) => *last,
                _ => return Err(Error::Corrupt("applied positions".into())),
            };
            if (incremental || !self.has_scope_key(change.scope))
                && change.excluded.is_empty()
                && change.through >= last
            {
                whole.insert(change.id);
            }
        }
        for change in restored.iter().filter(|change| !whole.contains(&change.id)) {
            if incremental {
                self.restore_seal_rows(change.scope, change.through).await?;
            } else {
                self.restore_rows(change.scope, change.through).await?;
            }
        }
        for change in restored.iter().filter(|change| !whole.contains(&change.id)) {
            if !incremental {
                self.reproject(change.scope).await?;
            }
        }
        let mut drops = Vec::new();
        for change in &restored {
            let mut rows = Vec::new();
            for (row, record) in self.seal_drops(change.scope, incremental).await? {
                let fields = match record {
                    Some(record) => Some(self.encode_record(&record).await?),
                    None => None,
                };
                rows.push((row, fields));
            }
            drops.push((change.scope, change.id, rows));
        }
        let unchanged: BTreeSet<i64> = drops
            .iter()
            .filter(|(_, id, rows)| whole.contains(id) && rows.is_empty())
            .map(|(_, id, _)| *id)
            .collect();
        // The live tables hold the seal's state now. Its stored rows take
        // what finalizing changes, which no live table shows, so that they
        // are what a replay through the seal leaves.
        if keep || incremental {
            for (scope, id, rows) in &drops {
                let blob = encode(scope)?;
                for (row, fields) in rows {
                    if incremental {
                        self.conn
                            .execute(
                                "INSERT OR IGNORE INTO secure_finalization_rows VALUES(?,?)",
                                bindings(vec![
                                    SqlValue::Integer(*id),
                                    SqlValue::Blob(row.to_vec()),
                                ]),
                            )
                            .await?;
                        self.replace_seal_row(*scope, *row, fields.as_deref())
                            .await?;
                        continue;
                    }
                    match fields {
                        Some(fields) => self
                            .conn
                            .execute(
                                "UPDATE secure_row_records SET fields=? WHERE scope=? AND row=?",
                                [fields.clone(), blob.clone(), row.to_vec()],
                            )
                            .await?,
                        None => {
                            self.conn
                                .execute(
                                    "DELETE FROM secure_row_records WHERE scope=? AND row=?",
                                    [blob.clone(), row.to_vec()],
                                )
                                .await?
                        }
                    };
                }
            }
        }
        self.conn
            .execute(
                "INSERT OR IGNORE INTO secure_finalized VALUES(?,?,?,0)",
                bindings(vec![
                    SqlValue::Blob(encode(&domain)?),
                    SqlValue::Integer(depth),
                    SqlValue::Blob(seal.id().map_err(credential)?.to_vec()),
                ]),
            )
            .await?;
        let cuts: Vec<_> = changes
            .iter()
            .filter(|change| change.replayed)
            .map(|change| (change.id, change.through))
            .collect();
        let bounds: Vec<history::KeptBound> = changes
            .iter()
            .map(|change| (change.id, change.through))
            .collect();
        let seal_id = seal.id().map_err(credential)?;
        self.order_behind_seal(
            &cuts,
            depth,
            now()?,
            keep.then_some((seal_id, bounds.as_slice())),
        )
        .await?;
        for change in &changes {
            self.conn
                .execute(
                    "INSERT OR REPLACE INTO secure_seal_bounds VALUES(?,?,?)",
                    [change.id, depth, change.through],
                )
                .await?;
            self.seal_replayed(change.id, change.through).await?;
        }
        let taken: Vec<_> = changes
            .iter()
            .filter(|change| change.replayed)
            .map(|change| (change.scope, change.id))
            .collect();
        self.take_seal_rows(seal_id, &taken).await?;
        for (_, id, rows) in drops {
            for (row, fields) in rows {
                self.conn
                    .execute(
                        "INSERT INTO secure_seal_drops VALUES(?,?,?,?)",
                        bindings(vec![
                            SqlValue::Integer(id),
                            SqlValue::Integer(depth),
                            SqlValue::Blob(row.to_vec()),
                            fields.map_or(SqlValue::Null, SqlValue::Blob),
                        ]),
                    )
                    .await?;
            }
        }
        // Rebuilt with every operation, applying the seal's diff; a whole
        // scope the seal drops nothing of is that state already.
        for change in restored
            .iter()
            .filter(|change| !unchanged.contains(&change.id))
        {
            if incremental {
                self.replay_seal_tail(change.scope, change.through).await?;
                let ledger = self
                    .row_replay_ledger(change.scope, change.id, i64::MAX, self.workspace.tip)
                    .await?;
                self.replace_ledger(change.scope, ledger).await?;
            } else {
                self.restore_rows(change.scope, i64::MAX).await?;
                self.reproject(change.scope).await?;
            }
        }
        self.conn
            .execute("DELETE FROM secure_finalization_rows", ())
            .await?;
        self.conn
            .execute(
                "UPDATE secure_metadata SET revision=revision+1 WHERE id=1",
                (),
            )
            .await?;
        Ok(())
    }
    /// Finalizes the followed path's seals in order while this replica
    /// holds every frame through the next one. Returns how many it
    /// finalized and why the next waits.
    pub(super) async fn finalize_ready(
        &mut self,
        domain: Scope,
    ) -> Result<(usize, Option<String>), Error> {
        self.finalize_at_most(domain, usize::MAX).await
    }
    /// Like `finalize_ready`, but finalizes at most `limit` seals.
    pub(super) async fn finalize_at_most(
        &mut self,
        domain: Scope,
        limit: usize,
    ) -> Result<(usize, Option<String>), Error> {
        let span = tracing::debug_span!(
            "finalize",
            domain = rocky_core::domain_label(&domain),
            finalized = tracing::field::Empty,
            waiting = tracing::field::Empty,
            outcome = tracing::field::Empty
        );
        let result =
            tracing::Instrument::instrument(self.finalize_ready_inner(domain, limit), span.clone())
                .await;
        if let Ok((count, waiting)) = &result {
            span.record("finalized", *count as u64);
            span.record("waiting", waiting.is_some());
        }
        crate::network::trace::outcome(&span, &result);
        result
    }
    async fn finalize_ready_inner(
        &mut self,
        domain: Scope,
        limit: usize,
    ) -> Result<(usize, Option<String>), Error> {
        let mut count = 0;
        if self.schema_switching().await? {
            return Ok((0, Some("the schema switch is unfinished".into())));
        }
        // A pulled state a scope needs becomes its base before readiness is
        // judged; until installed it covers nothing.
        if !rows(&self.conn, "SELECT 1 FROM secure_pulled LIMIT 1")
            .await?
            .is_empty()
            && self.compaction_lost(domain).await?.is_none()
        {
            transaction!(self, |inner| inner.install_needed_pulled(domain).await)?;
        }
        loop {
            if count >= limit {
                return Ok((count, None));
            }
            if self.compaction_lost(domain).await?.is_some() {
                return Ok((count, Some("the compacted seal lost a race".into())));
            }
            let path = self.path_seals(domain)?;
            let finalized = self.finalized(domain).await?;
            let Some(start) = offset(&path, &finalized) else {
                return Ok((count, Some("the finalized seals left the path".into())));
            };
            let next = start + finalized.len();
            let Some(seal) = path.get(next).cloned() else {
                let unverified = self.unverified_scopes(domain).await?;
                if !unverified.is_empty()
                    && let Some(known) = finalized.last()
                {
                    let seal = self
                        .graph_for(domain)?
                        .seal_by_id(known.seal)
                        .map_err(credential)?
                        .clone();
                    if let Some(reason) = self.seal_waits(domain, &seal, None, &unverified).await? {
                        return Ok((count, Some(reason)));
                    }
                    transaction!(self, |inner| inner
                        .finalize_seal(domain, &seal, &unverified, false)
                        .await)?;
                }
                return Ok((count, None));
            };
            let previous = next
                .checked_sub(1)
                .and_then(|index| path.get(index))
                .cloned();
            let scopes = self.readiness_scopes(domain).await?;
            if let Some(reason) = self
                .seal_waits(domain, &seal, previous.as_ref(), &scopes)
                .await?
            {
                return Ok((count, Some(reason)));
            }
            transaction!(self, |inner| {
                let keep = inner
                    .keeps_finalized(domain, seal.id().map_err(credential)?)
                    .await?;
                inner.finalize_seal(domain, &seal, &scopes, keep).await?;
                inner.retain_kept(domain).await
            })?;
            count += 1;
        }
    }
    /// The checkpoints of `scope` the graph lists at seals of the followed
    /// path from the next one to finalize, newest first, signed by another
    /// node, when that seal's coverage waits on this scope: history it
    /// never holds, such as a revoked author's frames or an epoch it is not
    /// given, comes with one of them.
    pub(super) async fn listed_replacements(
        &self,
        scope: ResourceScope,
    ) -> Result<Vec<Commitment>, Error> {
        let domain = scope.domain;
        let none = Vec::new();
        if self
            .workspace
            .followed
            .as_ref()
            .map(|(followed, _)| *followed)
            != Some(domain)
        {
            return Ok(none);
        }
        let (Some(graph), Some(id)) = (self.graphs.get(&domain), self.find_scope_id(scope).await?)
        else {
            return Ok(none);
        };
        let path = self.path_seals(domain)?;
        let finalized = self.finalized(domain).await?;
        let Some(next) = offset(&path, &finalized).map(|start| start + finalized.len()) else {
            return Ok(none);
        };
        let Some(seal) = path.get(next) else {
            return Ok(none);
        };
        let previous = next.checked_sub(1).and_then(|index| path.get(index));
        if !self.waits_for_key(scope).await?
            && self
                .seal_coverage_waits(domain, seal, previous, &[(scope, Some(id))])
                .await?
                .is_none()
        {
            return Ok(none);
        }
        let seals = path[next..]
            .iter()
            .rev()
            .map(|seal| seal.id().map_err(credential))
            .collect::<Result<Vec<_>, _>>()?;
        self.listed_at(graph, scope, &seals)
    }
    /// Whether a frame of `scope` waits for a key epoch this replica lacks.
    async fn waits_for_key(&self, scope: ResourceScope) -> Result<bool, Error> {
        let blob = encode(&scope)?;
        for (hash, reason) in &self.waits {
            if *reason == WaitReason::OpeningKey
                && rows(
                    &self.conn,
                    &format!(
                        "SELECT scope FROM secure_operations WHERE hash=x'{}'",
                        hash.to_hex()
                    ),
                )
                .await?
                .first()
                .is_some_and(|record| record.as_slice() == [SqlValue::Blob(blob.clone())])
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// Why the next seal of the followed path is not finalized yet.
    pub(super) async fn finalization_waits(&self, domain: Scope) -> Result<Option<String>, Error> {
        let finalized = self.finalized(domain).await?;
        let path = self.path_seals(domain)?;
        let next = offset(&path, &finalized).map(|start| start + finalized.len());
        Ok(match next.and_then(|next| path.get(next)) {
            Some(seal) => {
                let previous = next
                    .and_then(|next| next.checked_sub(1))
                    .and_then(|index| path.get(index))
                    .cloned();
                let scopes = self.readiness_scopes(domain).await?;
                self.seal_waits(domain, seal, previous.as_ref(), &scopes)
                    .await?
            }
            None => {
                let unverified = self.unverified_scopes(domain).await?;
                match (unverified.first(), finalized.last()) {
                    (Some(_), Some(last)) => {
                        let seal = self
                            .graph_for(domain)?
                            .seal_by_id(last.seal)
                            .map_err(credential)?;
                        self.seal_waits(domain, seal, None, &unverified).await?
                    }
                    _ => None,
                }
            }
        })
    }
    pub(in crate::replica) async fn clear_checkpoints(
        &mut self,
        _scope: ResourceScope,
        id: i64,
    ) -> Result<(), Error> {
        for table in [
            "secure_checkpoints",
            "secure_checkpoint_base",
            "secure_checkpoint_overlay",
            "secure_checkpoint_scratch",
            "secure_checkpoint_pages",
            "secure_checkpoint_stubs",
        ] {
            self.conn
                .execute(format!("DELETE FROM {table} WHERE scope=?"), [id])
                .await?;
        }
        self.verified_at.remove(&id);
        Ok(())
    }
    pub(super) async fn compaction_lost(&self, domain: Scope) -> Result<Option<Commitment>, Error> {
        let records = collect_rows(
            self.conn
                .query(
                    "SELECT seal FROM secure_compaction_lost WHERE domain=?",
                    [encode(&domain)?],
                )
                .await?,
        )
        .await?;
        match records.first().map(Vec::as_slice) {
            Some([SqlValue::Blob(seal)]) => Ok(Some(checkpoint::row_of(seal)?)),
            None => Ok(None),
            _ => Err(Error::Corrupt("lost compaction".into())),
        }
    }
    /// Inside the caller's transaction, forgets the finalized seals no
    /// longer on the followed path after a race resolved again or the
    /// bookmark moved, and with `restore` rebuilds the scopes they changed.
    /// Returns whether replayed members reopened; without `restore` the
    /// caller replays them.
    /// A compacted seal that left the path cannot be undone: the domain
    /// waits for a rebootstrap.
    pub(super) async fn revalidate_finalized(
        &mut self,
        domain: Scope,
        restore: bool,
    ) -> Result<bool, Error> {
        if !self.graphs.contains_key(&domain) {
            return Ok(false);
        }
        let path = self.path_seals(domain)?;
        let finalized = self.finalized(domain).await?;
        let mut valid = 0;
        let start = offset(&path, &finalized).unwrap_or(path.len());
        for (known, seal) in finalized.iter().zip(&path[start..]) {
            if known.seal != seal.id().map_err(credential)? {
                break;
            }
            valid += 1;
        }
        let Some(first) = finalized.get(valid) else {
            // The compacted seal is on the path again.
            self.conn
                .execute(
                    "DELETE FROM secure_compaction_lost WHERE domain=?",
                    [encode(&domain)?],
                )
                .await?;
            return Ok(false);
        };
        if let Some(compacted) = finalized[valid..]
            .iter()
            .rev()
            .find(|known| known.compacted)
        {
            self.conn
                .execute(
                    "INSERT OR REPLACE INTO secure_compaction_lost VALUES(?,?)",
                    bindings(vec![
                        SqlValue::Blob(encode(&domain)?),
                        SqlValue::Blob(compacted.seal.to_vec()),
                    ]),
                )
                .await?;
            return Ok(false);
        }
        self.conn
            .execute(
                "DELETE FROM secure_finalized WHERE domain=? AND depth>=?",
                bindings(vec![
                    SqlValue::Blob(encode(&domain)?),
                    SqlValue::Integer(first.depth),
                ]),
            )
            .await?;
        let mut reopened = false;
        for (scope, id) in self.domain_scopes(domain).await? {
            // Members the forgotten seals sealed reopen, with their undo.
            if self.replayed_scope(scope) {
                reopened |= !collect_rows(
                    self.conn
                        .query(
                            "SELECT 1 FROM secure_seal_bounds WHERE scope=? AND depth>=? LIMIT 1",
                            [id, first.depth],
                        )
                        .await?,
                )
                .await?
                .is_empty();
            }
            let dropped = collect_rows(
                self.conn
                    .query(
                        "SELECT 1 FROM secure_seal_drops WHERE scope=? AND depth>=? LIMIT 1",
                        [id, first.depth],
                    )
                    .await?,
            )
            .await?;
            for table in ["secure_seal_bounds", "secure_seal_drops"] {
                self.conn
                    .execute(
                        format!("DELETE FROM {table} WHERE scope=? AND depth>=?"),
                        [id, first.depth],
                    )
                    .await?;
            }
            if restore && !dropped.is_empty() {
                self.restore_rows(scope, i64::MAX).await?;
                self.reproject(scope).await?;
            }
        }
        if reopened && restore {
            self.replay_from_frames(now()?).await?;
        }
        Ok(reopened)
    }
    /// The newest finalized seal that is final, or has at least `keep`
    /// seals after it on the path, with every uncompacted one before it so.
    async fn compaction_target(
        &self,
        domain: Scope,
        keep: usize,
    ) -> Result<Option<(Finalized, SignedSeal)>, Error> {
        let graph = self.graph_for(domain)?;
        let path = self.path_seals(domain)?;
        let kept: BTreeSet<Commitment> = self
            .kept_marks()
            .await?
            .into_iter()
            .map(|(seal, _)| seal)
            .collect();
        let mut target = None;
        for known in self.finalized(domain).await? {
            if known.compacted {
                // The replay base never passes a kept seal: this node can
                // rebuild and serve every seal it keeps.
                if kept.contains(&known.seal) {
                    break;
                }
                continue;
            }
            let Some(index) = path
                .iter()
                .position(|seal| seal.id().is_ok_and(|id| id == known.seal))
            else {
                break;
            };
            if graph.is_final(known.seal).map_err(credential)? || path.len() - 1 - index >= keep {
                let stop = kept.contains(&known.seal);
                target = Some((known, path[index].clone()));
                if stop {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(target)
    }
    /// The compacted seal of the followed path, where the replay base sits.
    async fn compacted_target(
        &self,
        domain: Scope,
    ) -> Result<Option<(Finalized, SignedSeal)>, Error> {
        let path = self.path_seals(domain)?;
        let Some(known) = self
            .finalized(domain)
            .await?
            .into_iter()
            .rev()
            .find(|known| known.compacted)
        else {
            return Ok(None);
        };
        Ok(path
            .iter()
            .find(|seal| seal.id().is_ok_and(|id| id == known.seal))
            .cloned()
            .map(|seal| (known, seal)))
    }
    /// Makes `seal`'s state each held scope's replay base, signed by this
    /// node, and forgets the finalized seals up to it. Creation stubs of
    /// rows no longer stored go with it.
    async fn compact_to(
        &mut self,
        domain: Scope,
        (target, seal): &(Finalized, SignedSeal),
    ) -> Result<(), Error> {
        let at = self.path_index(domain, target.seal)?;
        // A scope granted after this seal was finalized may have no state
        // yet. Account for it only after retained history proves its cut.
        for (scope, id) in self.readiness_scopes(domain).await? {
            if id.is_none()
                && self
                    .seal_waits(domain, seal, None, &[(scope, id)])
                    .await?
                    .is_none()
            {
                transaction!(self, |inner| inner
                    .finalize_seal_impl(domain, seal, &[(scope, id)], false, true,)
                    .await)?;
            }
        }
        let mut scopes = Vec::new();
        for (scope, id) in self.domain_scopes(domain).await? {
            // A base imported at a later seal stays.
            if let Some(base) = self.base_seal(id).await?
                && self.path_index(domain, base)? > at
            {
                continue;
            }
            scopes.push((scope, id));
        }
        // The seal is marked compacted with the last scope, never apart.
        let last = scopes.len().checked_sub(1);
        for (index, (scope, id)) in scopes.into_iter().enumerate() {
            transaction!(self, |inner| {
                inner.compact_scope(scope, id, target, seal).await?;
                inner.fault(checkpoint::Stage::Compact)?;
                if Some(index) == last {
                    inner.mark_compacted(domain, target.depth).await?;
                }
                Ok(())
            })?;
            let commit = self.commit;
            self.verified_at.insert(id, commit);
        }
        if last.is_none() {
            transaction!(self, |inner| inner
                .mark_compacted(domain, target.depth)
                .await)?;
        }
        self.prune_placements(domain).await
    }
    /// `compact_scope` for a replayed scope: its rows at the seal, taken
    /// when the seal was finalized, become its signed replay base.
    async fn compact_replayed(
        &mut self,
        scope: ResourceScope,
        id: i64,
        target: &Finalized,
        seal: &SignedSeal,
        previous: Option<&(i64, SignedCheckpoint)>,
        through: i64,
    ) -> Result<bool, Error> {
        let base = previous.filter(|(_, signed)| signed.statement.seal.is_some());
        // A base nothing applied after stays, signed as it is.
        if let Some((position, signed)) = base
            && *position == through
            && signed.statement.key_epoch() == Some(self.scope_key(scope)?.0)
            && signed.statement.revocations == self.revocation_digest()?
        {
            self.conn
                .execute(
                    "DELETE FROM secure_seal_bounds WHERE scope=? AND depth<?",
                    [id, target.depth],
                )
                .await?;
            self.forget_seal_rows(id, target.depth).await?;
            return Ok(false);
        }
        let rows = match self.seal_rows(id, target.seal).await? {
            Some(rows) => rows,
            // Already the base: nothing was finalized since.
            None if base.is_some_and(|(_, signed)| signed.statement.seal == Some(target.seal)) => {
                return Ok(false);
            }
            // Finalized before its rows were readable: the live rows are the
            // seal's while nothing applied after it.
            None if collect_rows(
                self.conn
                    .query(
                        "SELECT 1 FROM secure_applied WHERE scope=? AND position>? LIMIT 1",
                        [id, through],
                    )
                    .await?,
            )
            .await?
            .is_empty() =>
            {
                self.replayed_images(scope).await?
            }
            None => {
                return Err(Error::Corrupt(
                    "a replayed scope's rows at its seal are missing".into(),
                ));
            }
        };
        let sets = replay::base_sets(&rows);
        let (frontier, operations) = self.covered_frontier(id, base, through).await?;
        let tip = seal.statement.tip;
        let schema = self
            .generation_of(self.manifest_of_tip(tip)?, false)?
            .schema;
        let (handles, handle_digest) = self.handle_set().await?;
        let identities = self
            .covered_identity_marks(
                id,
                base.map_or(&[][..], |(_, signed)| &signed.statement.identities),
                &frontier,
            )
            .await?
            .ok_or_else(|| Error::Corrupt("a covered operation is unavailable".into()))?;
        let frontier: Vec<LogPosition> = frontier.into_values().collect();
        let statement = CheckpointStatement {
            format: CHECKPOINT_FORMAT,
            seal: Some(target.seal),
            partition: self.partitions.get(&scope).cloned(),
            identities,
            // Replayed rows never move.
            moves: checkpoint::SetSummary {
                count: 0,
                digest: [0; 32],
            },
            tip,
            schema,
            revocations: self.revocation_digest()?,
            scope,
            state: checkpoint::CheckpointState::Keyed {
                key_epoch: self.scope_key(scope)?.0,
            },
            sequence: previous.map_or(0, |(_, signed)| signed.statement.sequence) + 1,
            previous: previous.map(|(_, signed)| signed.id()).transpose()?,
            clock: frontier.iter().map(|log| log.clock).max().unwrap_or(0),
            frontier,
            operations,
            rows: sets.rows_summary(),
            tombstones: 0,
            creations: sets.creations_summary(),
            handles: SetSummary {
                count: handles,
                digest: handle_digest.digest(),
            },
            custody: self.custody_summary(id, through).await?,
        };
        let signed = self.sign_checkpoint(statement)?;
        self.clear_seal_anchor(id).await?;
        for table in [
            "secure_checkpoints",
            "secure_checkpoint_pages",
            "secure_checkpoint_stubs",
        ] {
            self.conn
                .execute(format!("DELETE FROM {table} WHERE scope=?"), [id])
                .await?;
        }
        self.conn
            .execute(
                "INSERT INTO secure_checkpoints VALUES(?,?,?,?,?)",
                bindings(vec![
                    SqlValue::Integer(id),
                    SqlValue::Integer(signed.statement.sequence as i64),
                    SqlValue::Integer(through),
                    SqlValue::Blob(sets.to_bytes()),
                    SqlValue::Blob(signed.to_bytes()?),
                ]),
            )
            .await?;
        for table in ["secure_seal_bounds", "secure_seal_drops"] {
            self.conn
                .execute(
                    format!("DELETE FROM {table} WHERE scope=? AND depth<=?"),
                    [id, target.depth],
                )
                .await?;
        }
        self.store_base(id, &rows, Some(target.depth)).await?;
        for mark in &signed.statement.identities {
            self.put_identity_mark(
                scope,
                &mark.mark(),
                identity::Raise::Statement { own: mark.own },
            )
            .await?;
        }
        self.reseed_ledger(scope, id).await?;
        Ok(true)
    }
    /// The operations a base through applied position `through` covers,
    /// on top of `base`: its frontier per log, and their count.
    pub(super) async fn covered_frontier(
        &self,
        id: i64,
        base: Option<&(i64, SignedCheckpoint)>,
        through: i64,
    ) -> Result<(BTreeMap<PublicKey, LogPosition>, u64), Error> {
        let mut frontier = BTreeMap::<PublicKey, LogPosition>::new();
        let mut operations = base.map_or(0, |(_, signed)| signed.statement.operations);
        if let Some((_, signed)) = base {
            for log in &signed.statement.frontier {
                frontier.insert(log.author, log.clone());
            }
        }
        let from = base.map_or(0, |(position, _)| *position);
        for record in collect_rows(
            self.conn
                .query(
                    "SELECT a.hash,o.header FROM secure_applied a JOIN secure_operations o ON o.hash=a.hash WHERE a.scope=? AND a.position>? AND a.position<=? ORDER BY a.position",
                    [id, from, through],
                )
                .await?,
        )
        .await?
        {
            let [SqlValue::Blob(hash), SqlValue::Blob(header)] = record.as_slice() else {
                return Err(Error::Corrupt("covered operation".into()));
            };
            let header: p2panda_core::Header<Extensions> = decode(header)?;
            operations += 1;
            let log = LogPosition {
                author: header.public_key,
                sequence: header.seq_num,
                hash: checkpoint::hash_of(hash)?,
                clock: header.timestamp,
            };
            if frontier
                .get(&log.author)
                .is_none_or(|known| known.sequence < log.sequence)
            {
                frontier.insert(log.author, log);
            }
        }
        Ok((frontier, operations))
    }
    /// Keeps only the replay base's seal of the compacted ones.
    async fn mark_compacted(&self, domain: Scope, depth: i64) -> Result<(), Error> {
        for sql in [
            "UPDATE secure_finalized SET compacted=1 WHERE domain=? AND depth=?",
            "DELETE FROM secure_finalized WHERE domain=? AND depth<?",
        ] {
            self.conn
                .execute(
                    sql,
                    bindings(vec![
                        SqlValue::Blob(encode(&domain)?),
                        SqlValue::Integer(depth),
                    ]),
                )
                .await?;
        }
        Ok(())
    }
    async fn compact_scope(
        &mut self,
        scope: ResourceScope,
        id: i64,
        target: &Finalized,
        seal: &SignedSeal,
    ) -> Result<bool, Error> {
        let previous = self
            .checkpoint_record(id, true)
            .await?
            .and_then(|record| record.signed.map(|signed| (record.position, signed)));
        let base = previous
            .as_ref()
            .filter(|(_, signed)| signed.statement.seal.is_some());
        let mut cursor = base.map_or(0, |(position, _)| *position);
        // A deferred scope has no applied state at intervening seals.
        let bound = self
            .seal_bounds(id)
            .await?
            .into_iter()
            .filter(|(depth, _)| *depth == target.depth)
            .map(|(_, position)| position)
            .next_back();
        if bound.is_none()
            && base.is_none_or(|(_, signed)| signed.statement.seal != Some(target.seal))
        {
            return Ok(false);
        }
        if self
            .seal_waits(scope.domain, seal, Some(seal), &[(scope, Some(id))])
            .await?
            .is_some()
        {
            return Ok(false);
        }
        // Without a key only a scope with no frame history signs its base.
        if self.scope_key(scope).is_err() {
            return self
                .compact_no_frames(scope, id, (target.depth, target.seal), seal, bound)
                .await;
        }
        let through = bound.unwrap_or(cursor);
        if self.replayed_scope(scope) {
            return self
                .compact_replayed(scope, id, target, seal, previous.as_ref(), through)
                .await;
        }
        // Empty partitions need current coverage even with unchanged rows:
        // a newly granted reader may never have held the other scopes' frames.
        let reusable = match base {
            Some((_, signed)) => {
                signed.statement.key_epoch() == Some(self.scope_key(scope)?.0)
                    && signed.statement.revocations == self.revocation_digest()?
            }
            None => false,
        };
        let empty_partition = base.is_some_and(|(_, signed)| {
            signed.statement.partition.is_some()
                && signed.statement.frontier.is_empty()
                && signed.statement.seal != Some(target.seal)
        });
        if reusable && through == cursor && !empty_partition {
            let mut drops = self
                .conn
                .query(
                    "SELECT 1 FROM secure_seal_drops WHERE scope=? AND depth<=? LIMIT 1",
                    [id, target.depth],
                )
                .await?;
            if drops.next().await?.is_none() {
                self.conn
                    .execute(
                        "DELETE FROM secure_seal_bounds WHERE scope=? AND depth<?",
                        [id, target.depth],
                    )
                    .await?;
                return Ok(false);
            }
        }
        let mut sets = match self.checkpoint_record(id, true).await? {
            Some(record) if base.is_some() => record.sets,
            _ => Sets::new(),
        };
        self.conn
            .execute("DELETE FROM secure_checkpoint_overlay WHERE scope=?", [id])
            .await?;
        // The base keeps its own tip's fields; readers filter it to theirs.
        let target_tip = seal.statement.tip;
        sets = self
            .prime_path_base(scope, id, Overlay::Build, target_tip, sets)
            .await?;
        // Seeded from the signed base the overlay starts from, or nothing.
        let mut ledger = identity::IdentityLedger::based(
            base.map_or(&[][..], |(_, signed)| &signed.statement.identities),
        )?;
        while let Some(last) = self
            .replay_sealed(
                scope,
                id,
                Overlay::Build,
                target_tip,
                (cursor, through),
                STEP_OPERATIONS,
                &mut sets,
                &mut ledger,
                checkpoint::ReplayMode::Mint,
            )
            .await?
        {
            cursor = last;
        }
        let (frontier, operations) = self.covered_frontier(id, base, through).await?;
        // The overlay becomes the base rows.
        for sql in [
            "DELETE FROM secure_checkpoint_base WHERE scope=?1 AND row IN (SELECT row FROM secure_checkpoint_overlay WHERE scope=?1)",
            "INSERT INTO secure_checkpoint_rows SELECT scope,row,fields FROM secure_checkpoint_overlay WHERE scope=?1 AND fields<>X''",
            "DELETE FROM secure_checkpoint_overlay WHERE scope=?1",
        ] {
            self.conn.execute(sql, [id]).await?;
        }
        // The base names the creations of the rows it stores, as an import
        // rebuilds them; rows dropped at a seal take theirs along.
        sets.creations = 0;
        sets.creation_digest = checkpoint::Lt::new();
        let base_creations = self
            .index_page_headers(id, &checkpoint::Served::Base)
            .await?;
        for creation in base_creations.iter().copied() {
            let (_, clock) = self
                .stub(creation)
                .await?
                .ok_or_else(|| Error::Corrupt("base row creation is unknown".into()))?;
            sets.create(creation, clock);
        }
        let tip = seal.statement.tip;
        let schema = self
            .generation_of(self.manifest_of_tip(tip)?, false)?
            .schema;
        let (handles, handle_digest) = self.handle_set().await?;
        let identities = self
            .covered_identity_marks(
                id,
                base.map_or(&[][..], |(_, signed)| &signed.statement.identities),
                &frontier,
            )
            .await?
            .ok_or_else(|| Error::Corrupt("a covered operation is unavailable".into()))?;
        self.check_covered_identities("secure_checkpoint_rows", id, &identities)
            .await?;
        let frontier: Vec<LogPosition> = frontier.into_values().collect();
        let statement = CheckpointStatement {
            format: CHECKPOINT_FORMAT,
            seal: Some(target.seal),
            partition: self.partitions.get(&scope).cloned(),
            identities,
            moves: self.imported_moves(id).await?,
            tip,
            schema,
            revocations: self.revocation_digest()?,
            scope,
            state: checkpoint::CheckpointState::Keyed {
                key_epoch: self.scope_key(scope)?.0,
            },
            sequence: previous
                .as_ref()
                .map_or(0, |(_, signed)| signed.statement.sequence)
                + 1,
            previous: previous
                .as_ref()
                .map(|(_, signed)| signed.id())
                .transpose()?,
            clock: frontier.iter().map(|log| log.clock).max().unwrap_or(0),
            frontier,
            operations,
            rows: sets.rows_summary(),
            tombstones: sets.tombstones,
            creations: sets.creations_summary(),
            handles: SetSummary {
                count: handles,
                digest: handle_digest.digest(),
            },
            custody: self.custody_summary(id, through).await?,
        };
        let signed = self.sign_checkpoint(statement)?;
        self.clear_seal_anchor(id).await?;
        for table in [
            "secure_checkpoints",
            "secure_checkpoint_pages",
            "secure_checkpoint_stubs",
        ] {
            self.conn
                .execute(format!("DELETE FROM {table} WHERE scope=?"), [id])
                .await?;
        }
        self.conn
            .execute(
                "INSERT INTO secure_checkpoints VALUES(?,?,?,?,?)",
                bindings(vec![
                    SqlValue::Integer(id),
                    SqlValue::Integer(signed.statement.sequence as i64),
                    SqlValue::Integer(through),
                    SqlValue::Blob(sets.to_bytes()),
                    SqlValue::Blob(signed.to_bytes()?),
                ]),
            )
            .await?;
        for table in ["secure_seal_bounds", "secure_seal_drops"] {
            self.conn
                .execute(
                    format!("DELETE FROM {table} WHERE scope=? AND depth<=?"),
                    [id, target.depth],
                )
                .await?;
        }
        // Stubs witness creations of stored rows and pruned dependencies;
        // past the seal only the creations of stored and base rows are needed.
        self.conn
            .execute(
                "DELETE FROM secure_compaction_live_creations WHERE scope=?",
                [id],
            )
            .await?;
        for creation in base_creations {
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO secure_compaction_live_creations VALUES(?,?)",
                    bindings(vec![
                        SqlValue::Integer(id),
                        SqlValue::Blob(creation.as_bytes().to_vec()),
                    ]),
                )
                .await?;
        }
        let blob = encode(&scope)?;
        let mut after = Vec::new();
        loop {
            let records = collect_rows(
                self.conn
                    .query(
                        "SELECT row,fields FROM secure_row_records WHERE scope=? AND row>? ORDER BY row LIMIT ?",
                        bindings(vec![SqlValue::Blob(blob.clone()), SqlValue::Blob(after.clone()), SqlValue::Integer(STEP_ROWS as i64)]),
                    )
                    .await?,
            )
            .await?;
            if records.is_empty() {
                break;
            }
            for record in records {
                let [SqlValue::Blob(key), SqlValue::Blob(fields)] = record.as_slice() else {
                    return Err(Error::Corrupt("stored row".into()));
                };
                after = key.clone();
                let record = self.decode_record(fields).await?;
                self.conn
                    .execute(
                        "INSERT OR IGNORE INTO secure_compaction_live_creations VALUES(?,?)",
                        bindings(vec![
                            SqlValue::Integer(id),
                            SqlValue::Blob(record.creation.as_bytes().to_vec()),
                        ]),
                    )
                    .await?;
            }
        }
        self.conn
            .execute(
                "DELETE FROM secure_stubs WHERE scope=?1 AND (creation=0 OR hash NOT IN (SELECT hash FROM secure_compaction_live_creations WHERE scope=?1))",
                [id],
            )
            .await?;
        self.conn
            .execute(
                "DELETE FROM secure_compaction_live_creations WHERE scope=?",
                [id],
            )
            .await?;
        for mark in &signed.statement.identities {
            self.put_identity_mark(
                scope,
                &mark.mark(),
                identity::Raise::Statement { own: mark.own },
            )
            .await?;
        }
        self.reseed_ledger(scope, id).await?;
        Ok(true)
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// Whether a held scope needs a served replay base, including empty
    /// concrete partitions learned after the newest seal was finalized.
    pub async fn unserved_bases(&self, domain: Scope) -> Result<bool, Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        inner.graph_for(domain)?;
        for (scope, _) in inner.readiness_scopes(domain).await? {
            if inner.served_checkpoint(scope).await?.is_none() {
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// See `Inner::listed_replacements`.
    pub async fn listed_replacements(
        &self,
        scope: ResourceScope,
    ) -> Result<Vec<Commitment>, Error> {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .listed_replacements(scope)
            .await
    }
    /// Finalizes every seal of the followed path whose frames this replica
    /// holds, then makes the newest finalized seal that is final, or has at
    /// least `keep` seals after it on the path, the replay base, and
    /// releases the operations behind it as far as retention allows. A
    /// seal that loses after compaction needs a rebootstrap; `keep` trades
    /// storage against that chance.
    pub async fn compact(&self, domain: Scope, keep: usize) -> Result<CompactReport, Error> {
        let span = tracing::debug_span!(
            "compact",
            domain = rocky_core::domain_label(&domain),
            pruned = tracing::field::Empty,
            outcome = tracing::field::Empty
        );
        let result =
            tracing::Instrument::instrument(self.compact_inner(domain, keep), span.clone()).await;
        if let Ok(report) = &result {
            span.record("pruned", report.pruned);
        }
        crate::network::trace::outcome(&span, &result);
        result
    }
    async fn compact_inner(&self, domain: Scope, keep: usize) -> Result<CompactReport, Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        inner.graph_for(domain)?;
        let (_, waiting) = inner.finalize_ready(domain).await?;
        // Without a newer seal, the base is signed again where it stands
        // when a learned revocation or key epoch left it stale.
        let target = match inner.compaction_target(domain, keep).await? {
            Some(target) => Some(target),
            None => inner.compacted_target(domain).await?,
        };
        if let Some(target) = target {
            inner.compact_to(domain, &target).await?;
        }
        let mut report = CompactReport {
            waiting,
            ..CompactReport::default()
        };
        inner = flush_guard(inner, &self.inner).await?;
        for (scope, _) in inner.domain_scopes(domain).await? {
            loop {
                inner = flush_guard(inner, &self.inner).await?;
                let step = inner.prune_step(scope).await?;
                report.pruned += step.pruned;
                if let Some(block) = step.blocked {
                    if !matches!(block, PruneBlock::NoPolicy) {
                        report.blocked.push((scope, block));
                    }
                    break;
                }
                if !step.more {
                    break;
                }
            }
        }
        let finalized = inner.finalized(domain).await?;
        report.finalized = finalized.last().map(|known| known.seal);
        report.compacted = finalized
            .iter()
            .rev()
            .find(|known| known.compacted)
            .map(|known| known.seal);
        inner = flush_guard(inner, &self.inner).await?;
        inner.publish_revision().await?;
        Ok(report)
    }
    /// Finalizes every seal of the followed path whose frames this replica
    /// holds, as maintenance does, and keeps those the configuration names.
    pub async fn finalize_path(&self, domain: Scope) -> Result<(), Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        inner.graph_for(domain)?;
        inner.finalize_ready(domain).await?;
        inner = flush_guard(inner, &self.inner).await?;
        inner.publish_revision().await
    }
    /// Whether any held scope still needs a replay base at `seal`.
    pub async fn needs_base_at(&self, domain: Scope, seal: Commitment) -> Result<bool, Error> {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        for (_, id) in inner.domain_scopes(domain).await? {
            if inner.base_seal(id).await? != Some(seal) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub async fn compaction_status(&self, domain: Scope) -> Result<CompactionStatus, Error> {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        inner.graph_for(domain)?;
        let finalized = inner.finalized(domain).await?;
        let waiting = inner.finalization_waits(domain).await?;
        let rebootstrap = inner.compaction_lost(domain).await?;
        Ok(CompactionStatus {
            finalized: finalized.last().map(|known| known.seal),
            compacted: finalized
                .iter()
                .rev()
                .find(|known| known.compacted)
                .map(|known| known.seal),
            uncompacted: finalized
                .iter()
                .filter(|known| !known.compacted)
                .map(|known| known.seal)
                .collect(),
            waiting,
            rebootstrap,
        })
    }
}

/// The seals `tip`'s state passes through, oldest first, as `path_seals`.
pub(super) fn tip_path_seals(
    graph: &rocky_credentials::TipGraph,
    tip: TipId,
) -> Result<Vec<SignedSeal>, Error> {
    let mut seals = Vec::new();
    if let Some(own) = graph.seal(tip).map_err(credential)? {
        seals.push(own.clone());
    }
    let mut cursor = tip;
    let mut visited = BTreeSet::new();
    while visited.insert(cursor) {
        let mut parent = None;
        for seal in &graph.seals {
            if seal.successor().map_err(credential)? == Some(cursor) {
                parent = Some(seal.clone());
                break;
            }
        }
        if parent.is_none() {
            for opening in &graph.openings {
                if opening.tip().map_err(credential)? == cursor {
                    parent = Some(
                        graph
                            .seal_by_id(opening.statement.seal)
                            .map_err(credential)?
                            .clone(),
                    );
                    break;
                }
            }
        }
        let Some(seal) = parent else { break };
        cursor = seal.statement.tip;
        seals.push(seal);
    }
    seals.reverse();
    Ok(seals)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gap_at_the_maximum_sequence_terminates() {
        use rocky_core::{AppId, DomainId, MeshId};
        use rocky_credentials::{AuthorMark, SEAL_FORMAT, SealAction, SealStatement};
        let domain = Scope {
            mesh: MeshId([1; 16]),
            app: AppId([2; 16]),
            domain: DomainId([3; 16]),
        };
        let scope = ResourceScope {
            domain,
            encryption: [4; 32],
            table: [5; 32],
        };
        let mut seal = SignedSeal::sign(
            SealStatement {
                format: SEAL_FORMAT,
                scope: domain,
                tip: TipId([6; 32]),
                frontier: vec![AuthorMark {
                    author: 1,
                    sequence: 1,
                }],
                action: SealAction::Continue { schema: [7; 32] },
                recovery: None,
            },
            &PrivateKey::new(),
        )
        .unwrap();
        seal.statement.frontier[0].sequence = u64::MAX;
        assert_eq!(
            blocking_gaps(
                &seal,
                &BTreeMap::from([(1, u64::MAX)]),
                &[(scope, None)],
                &BTreeMap::new(),
                &BTreeMap::new(),
                32
            ),
            vec![(1, u64::MAX)]
        );
    }
}
