//! The pruned prefix: how far it may move, what is deleted behind it,
//! and what a peer that asks for operations gets.
use super::retention::*;
use super::*;
use crate::checkpoint::{Catchup, PrunedNotice, Step};
use crate::replication::{SyncState, TRANSFER_PAGE_SIZE, TransferPage};
use std::collections::BTreeSet;

impl<A> Worker<A>
where
    A: StoredApplication,
    A::State: Clone,
{
    /// Moves the pruned prefix and deletes behind it; one bounded transaction.
    pub(super) async fn prune_step(&mut self) -> Result<Step, Error> {
        let (stored, step, released) = self
            .transaction(async |worker| {
                let mut stored = worker.retention.stored.clone();
                let moved = worker.advance_pruned_prefix(&mut stored).await?;
                let (released, more) = worker.delete_behind(&stored).await?;
                if moved {
                    worker.persist(&stored).await?;
                }
                worker.inject_fault().await?;
                let step = if moved || more {
                    Step::More
                } else {
                    Step::Done
                };
                Ok((stored, step, released))
            })
            .await?;
        self.retention.adopt(stored)?;
        self.retained = self.retained.saturating_sub(released.0);
        self.retained_bytes = self
            .retained_bytes
            .saturating_sub(released.1)
            .saturating_sub(released.0.saturating_mul(RECORD_OVERHEAD));
        self.retention.prune_wanted = step == Step::More;
        Ok(step)
    }
    /// The pruned prefix follows the durable checkpoint, less the retained window,
    /// as far as every delivery target has acknowledged or is declared behind.
    /// With `behind_after`, a target that holds it back that long is declared
    /// behind.
    pub(super) async fn advance_pruned_prefix(&self, stored: &mut Stored) -> Result<bool, Error> {
        let Some((record, _)) = &self.retention.record else {
            return Ok(false);
        };
        if !self.retention.record_flushed || stored.import.is_some() {
            return Ok(false);
        }
        let window = self.retention.policy.window as u64;
        let timed = self.retention.policy.behind_after;
        let mut moved = false;
        let mut holding = BTreeSet::new();
        for (node, covered) in marks(&record.frontier) {
            let current = at(&stored.pruned_prefix, node);
            let wanted = covered
                .saturating_sub(window)
                .min(current + PRUNE_BATCH as u64);
            let mut limit = wanted;
            let custody = self.retention.policy.custody;
            if custody > 0 {
                // Only full nodes that applied count; other targets
                // rebootstrap from them once they fall behind.
                let mut covered = Vec::new();
                for target in &self.config.full_nodes {
                    let peer = stored
                        .peers
                        .iter()
                        .find(|(peer, _)| peer == target)
                        .map(|(_, mark)| mark);
                    if peer.is_some_and(|mark| mark.behind) {
                        continue;
                    }
                    if *target == node {
                        covered.push(u64::MAX);
                        continue;
                    }
                    let mut acknowledged =
                        current.max(peer.map_or(0, |mark| at(&mark.applied, node)));
                    let mut receipts = self
                        .conn()
                        .query(
                            "SELECT sequence FROM rocky_peer_ack WHERE peer=? AND node=? AND sequence>? AND applied=1 ORDER BY sequence LIMIT ?",
                            crate::sqlite::params![
                                target.0.to_vec(),
                                node.0.to_vec(),
                                acknowledged as i64,
                                PRUNE_BATCH as i64
                            ],
                        )
                        .await?;
                    while let Some(row) = receipts.next().await? {
                        if row.get::<i64>(0)? as u64 != acknowledged + 1 {
                            break;
                        }
                        acknowledged += 1;
                    }
                    if acknowledged < wanted {
                        holding.insert(*target);
                    }
                    covered.push(acknowledged);
                }
                covered.sort_unstable_by(|a, b| b.cmp(a));
                limit = limit.min(covered.get(custody - 1).copied().unwrap_or(current));
                if limit > current {
                    set(&mut stored.pruned_prefix, node, limit);
                    moved = true;
                }
                continue;
            }
            for target in &self.config.delivery_targets {
                // Without a time limit, which target holds it back is moot.
                if limit <= current && timed.is_none() {
                    break;
                }
                let peer = stored
                    .peers
                    .iter()
                    .find(|(peer, _)| peer == target)
                    .map(|(_, mark)| mark);
                if *target == node || peer.is_some_and(|mark| mark.behind) {
                    continue;
                }
                // Acknowledged: reported applied or held, or a receipt for each one.
                let mut acknowledged = current
                    .max(peer.map_or(0, |mark| at(&mark.applied, node).max(at(&mark.held, node))));
                let mut receipts = self
                    .conn()
                    .query(
                        "SELECT sequence FROM rocky_peer_ack WHERE peer=? AND node=? AND sequence>? ORDER BY sequence LIMIT ?",
                        crate::sqlite::params![
                            target.0.to_vec(),
                            node.0.to_vec(),
                            acknowledged as i64,
                            PRUNE_BATCH as i64
                        ],
                    )
                    .await?;
                while let Some(row) = receipts.next().await? {
                    if row.get::<i64>(0)? as u64 != acknowledged + 1 {
                        break;
                    }
                    acknowledged += 1;
                }
                if acknowledged < wanted {
                    holding.insert(*target);
                }
                limit = limit.min(acknowledged);
            }
            if limit > current {
                set(&mut stored.pruned_prefix, node, limit);
                moved = true;
            }
        }
        if let Some(after) = timed {
            moved |= self.time_holding(stored, &holding, after);
        }
        Ok(moved)
    }
    /// Records since when each target holds back the pruned prefix and declares
    /// it behind after `after`. True if a mark changed.
    fn time_holding(
        &self,
        stored: &mut Stored,
        holding: &BTreeSet<NodeId>,
        after: std::time::Duration,
    ) -> bool {
        let now = now_millis();
        let mut changed = false;
        for target in &self.config.delivery_targets {
            let held = holding.contains(target);
            if !held
                && !stored
                    .peers
                    .iter()
                    .any(|(peer, mark)| peer == target && mark.holding_since.is_some())
            {
                continue;
            }
            let mark = mark(stored, *target);
            if mark.behind {
                continue;
            }
            if !held {
                mark.holding_since = None;
                changed = true;
                continue;
            }
            let since = *mark.holding_since.get_or_insert_with(|| {
                changed = true;
                now
            });
            if now.saturating_sub(since) >= after.as_millis() as i64 {
                mark.behind = true;
                mark.holding_since = None;
                changed = true;
            }
        }
        changed
    }
    /// Deletes operations, acknowledgments, outgoing entries and forgotten
    /// handles behind the pruned prefix. Returns the released records and bytes,
    /// and whether rows remain.
    pub(super) async fn delete_behind(
        &self,
        stored: &Stored,
    ) -> Result<((usize, usize), bool), Error> {
        let batch = PRUNE_BATCH as i64;
        let mut released = (0, 0);
        let mut more = false;
        for (node, pruned_prefix) in &stored.pruned_prefix {
            let key = crate::sqlite::params![node.0.to_vec(), *pruned_prefix as i64, batch];
            let mut deleted = self
                .conn()
                .query(
                    "DELETE FROM rocky_operations WHERE rowid IN (SELECT rowid FROM rocky_operations WHERE node=? AND sequence<=? LIMIT ?) RETURNING LENGTH(bytes)",
                    key.clone(),
                )
                .await?;
            let mut count = 0;
            while let Some(row) = deleted.next().await? {
                count += 1;
                released.1 += row.get::<i64>(0)? as usize;
            }
            released.0 += count;
            more |= count == PRUNE_BATCH;
            for peer in &self.config.delivery_targets {
                let removed = self
                    .conn()
                    .execute(
                        "DELETE FROM rocky_peer_ack WHERE rowid IN (SELECT rowid FROM rocky_peer_ack WHERE peer=? AND node=? AND sequence<=? LIMIT ?)",
                        crate::sqlite::params![
                            peer.0.to_vec(),
                            node.0.to_vec(),
                            *pruned_prefix as i64,
                            batch
                        ],
                    )
                    .await?;
                more |= removed == PRUNE_BATCH as u64;
            }
            let removed = self
                .conn()
                .execute(
                    "DELETE FROM rocky_outbox WHERE rowid IN (SELECT rowid FROM rocky_outbox WHERE node=? AND sequence<=? LIMIT ?)",
                    key,
                )
                .await?;
            more |= removed == PRUNE_BATCH as u64;
        }
        // A handle outlives its operation by the retry window.
        let local = self.identity.node;
        let forgotten = at(&stored.pruned_prefix, local).min(
            self.sequence
                .saturating_sub(self.retention.policy.handles as u64),
        );
        if forgotten > 0 {
            let removed = self
                .conn()
                .execute(
                    "DELETE FROM rocky_mutation_handles WHERE rowid IN (SELECT rowid FROM rocky_mutation_handles WHERE node=? AND sequence<=? LIMIT ?)",
                    crate::sqlite::params![local.0.to_vec(), forgotten as i64, batch],
                )
                .await?;
            more |= removed == PRUNE_BATCH as u64;
        }
        Ok((released, more))
    }
    /// The operations `state` lacks after `after`, or the notice that it is
    /// behind the pruned prefix. A named target's held and applied frontiers are
    /// kept as acknowledgment, and clear the outgoing work they cover.
    pub(super) async fn catch_up(
        &mut self,
        peer: Option<NodeId>,
        state: &SyncState,
        after: Option<OperationId>,
    ) -> Result<(Option<Stored>, Catchup), Error> {
        let applied = marks(&state.applied);
        let held = marks(&state.held);
        let retention = &self.retention;
        if retention
            .stored
            .pruned_prefix
            .iter()
            .any(|(node, sequence)| at(&applied, *node) < *sequence)
        {
            let Some((record, commitment)) = &retention.record else {
                return Err(Error::Corrupt("pruned_prefix without a checkpoint".into()));
            };
            return Ok((
                None,
                Catchup::BehindPruned(PrunedNotice {
                    scope: self.identity.scope,
                    node: self.identity.node,
                    pruned_prefix: frontier(&retention.stored.pruned_prefix)?,
                    checkpoint: *commitment,
                    sequence: record.sequence,
                }),
            ));
        }
        let mut changed = None;
        if let Some(peer) = peer {
            let mut stored = retention.stored.clone();
            let mark = mark(&mut stored, peer);
            let mut advanced = mark.behind || mark.holding_since.is_some();
            mark.behind = false;
            // A peer in contact is not silent; its holding time restarts.
            mark.holding_since = None;
            for (target, source) in [(&mut mark.applied, &applied), (&mut mark.held, &held)] {
                for (node, sequence) in source {
                    if *sequence > at(target, *node) {
                        set(target, *node, *sequence);
                        advanced = true;
                    }
                }
            }
            if advanced {
                self.persist(&stored).await?;
                self.clear_delivered(&stored).await?;
                changed = Some(stored);
            }
        }
        let known: BTreeSet<_> = state.received.iter().copied().collect();
        let mut records = Vec::new();
        let mut bytes = 0;
        let mut next = None;
        let mut full = false;
        let mut nodes: Vec<_> = self.config.authors.iter().map(|(node, _)| *node).collect();
        nodes.dedup();
        'authors: for node in nodes {
            let mut from = at(&applied, node)
                .max(at(&held, node))
                .max(self.retention.pruned_prefix(node));
            if let Some(after) = after {
                if node < after.node {
                    continue;
                }
                if node == after.node {
                    from = from.max(after.sequence.get());
                }
            }
            loop {
                let mut page = self
                    .conn()
                    .query(
                        "SELECT sequence,bytes FROM rocky_operations WHERE node=? AND sequence>? AND status<>'rejected' ORDER BY sequence LIMIT 64",
                        crate::sqlite::params![node.0.to_vec(), from as i64],
                    )
                    .await?;
                let mut empty = true;
                while let Some(row) = page.next().await? {
                    empty = false;
                    from = row.get::<i64>(0)? as u64;
                    let id = OperationId {
                        node,
                        sequence: AuthorSequence::new(from)?,
                    };
                    if known.contains(&id) {
                        continue;
                    }
                    let encoded: Vec<u8> = row.get(1)?;
                    if records.len() == TRANSFER_PAGE_SIZE
                        || bytes + encoded.len() > crate::MAX_FRAME_BYTES
                    {
                        full = true;
                        break 'authors;
                    }
                    bytes += encoded.len();
                    records.push(encoded);
                    next = Some(id);
                }
                if empty {
                    break;
                }
            }
        }
        // A page that ran to the end of every log ends the pass.
        if !full {
            next = None;
        }
        self.inject_fault().await?;
        Ok((changed, Catchup::Operations(TransferPage { records, next })))
    }
    /// Deletes outgoing entries every delivery target holds, by its
    /// reported frontier or a receipt for the entry.
    async fn clear_delivered(&self, stored: &Stored) -> Result<(), Error> {
        let local = self.identity.node;
        if self.config.delivery_targets.is_empty() {
            return Ok(());
        }
        let mut sql = String::from("DELETE FROM rocky_outbox WHERE node=?");
        let mut values = vec![crate::sqlite::Value::Blob(local.0.to_vec())];
        for target in &self.config.delivery_targets {
            let held = stored
                .peers
                .iter()
                .find(|(peer, _)| peer == target)
                .map_or(0, |(_, mark)| at(&mark.held, local));
            sql.push_str(" AND (sequence<=? OR EXISTS(SELECT 1 FROM rocky_peer_ack a WHERE a.peer=? AND a.node=rocky_outbox.node AND a.sequence=rocky_outbox.sequence))");
            values.push(crate::sqlite::Value::Integer(held as i64));
            values.push(crate::sqlite::Value::Blob(target.0.to_vec()));
        }
        self.conn().execute(sql, values).await?;
        Ok(())
    }
}
