//! Retained per-scope accounting survives a losing seal without claiming its state.
use super::*;
use rocky_credentials::AuthorMark;

impl<A: RowApplication> Inner<A> {
    pub(in crate::replica) async fn seal_anchor(&self, id: i64) -> Result<Vec<AuthorMark>, Error> {
        let records = collect_rows(
            self.conn
                .query(
                    "SELECT frontier FROM secure_seal_anchors WHERE scope=?",
                    [id],
                )
                .await?,
        )
        .await?;
        match records.first().map(Vec::as_slice) {
            Some([SqlValue::Blob(bytes)]) => decode(bytes),
            None => Ok(Vec::new()),
            _ => Err(Error::Corrupt("seal anchor".into())),
        }
    }
    pub(in crate::replica) async fn has_seal_anchor(&self, id: i64) -> Result<bool, Error> {
        Ok(!collect_rows(
            self.conn
                .query("SELECT 1 FROM secure_seal_anchors WHERE scope=?", [id])
                .await?,
        )
        .await?
        .is_empty())
    }
    pub(in crate::replica) async fn clear_seal_anchor(&self, id: i64) -> Result<(), Error> {
        self.conn
            .execute("DELETE FROM secure_seal_anchors WHERE scope=?", [id])
            .await?;
        Ok(())
    }
    /// Before deleting verified accounting, retain it only while all scope frames remain.
    pub(in crate::replica) async fn anchor_seal_coverage(
        &self,
        scope: ResourceScope,
        id: i64,
    ) -> Result<(), Error> {
        if self.has_pruned_prefix(scope).await? {
            return Ok(());
        }
        let Some(frontier) = self.verified_scope_frontier(scope, id).await? else {
            return Ok(());
        };
        let mut merged: BTreeMap<u32, u64> = self
            .seal_anchor(id)
            .await?
            .into_iter()
            .map(|mark| (mark.author, mark.sequence))
            .collect();
        for mark in &frontier {
            merged
                .entry(mark.author)
                .and_modify(|sequence| *sequence = (*sequence).max(mark.sequence))
                .or_insert(mark.sequence);
        }
        let frontier: Vec<_> = merged
            .into_iter()
            .map(|(author, sequence)| AuthorMark { author, sequence })
            .collect();
        self.conn
            .execute(
                "INSERT OR REPLACE INTO secure_seal_anchors VALUES(?,?)",
                bindings(vec![
                    SqlValue::Integer(id),
                    SqlValue::Blob(encode(&frontier)?),
                ]),
            )
            .await?;
        Ok(())
    }
    async fn verified_scope_frontier(
        &self,
        scope: ResourceScope,
        id: i64,
    ) -> Result<Option<Vec<AuthorMark>>, Error> {
        let bounds = collect_rows(self.conn.query(
            "SELECT f.seal FROM secure_seal_bounds b JOIN secure_finalized f ON f.depth=b.depth WHERE b.scope=? AND f.domain=? ORDER BY b.depth DESC LIMIT 1",
            bindings(vec![SqlValue::Integer(id), SqlValue::Blob(encode(&scope.domain)?)]),
        ).await?).await?;
        let seal = match bounds.first().map(Vec::as_slice) {
            Some([SqlValue::Blob(bytes)]) => Some(checkpoint::row_of(bytes)?),
            None => self.base_seal(id).await?,
            _ => return Err(Error::Corrupt("seal anchor bound".into())),
        };
        let Some(seal) = seal else {
            return Ok(None);
        };
        let frontier = &self
            .graph_for(scope.domain)?
            .seal_by_id(seal)
            .map_err(credential)?
            .statement
            .frontier;
        Ok(Some(frontier.clone()))
    }
    pub(in crate::replica) async fn replay_has_gaps(
        &self,
        scope: ResourceScope,
        id: i64,
        seal: &SignedSeal,
    ) -> Result<bool, Error> {
        let mut starts = self.seal_starts(Some(id), None).await?;
        if !self.has_pruned_prefix(scope).await? {
            for mark in self
                .verified_scope_frontier(scope, id)
                .await?
                .into_iter()
                .flatten()
            {
                starts
                    .entry(mark.author)
                    .and_modify(|from| *from = (*from).max(mark.sequence.saturating_add(1)))
                    .or_insert(mark.sequence.saturating_add(1));
            }
        }
        let (held, last) = self
            .held_positions(
                scope.domain,
                &[(scope, Some(id))],
                &self.custody_scopes(now()?)?,
            )
            .await?;
        Ok(!blocking_gaps(seal, &starts, &[(scope, Some(id))], &held, &last, 1).is_empty())
    }
    pub(in crate::replica) async fn seal_starts(
        &self,
        id: Option<i64>,
        previous: Option<&SignedSeal>,
    ) -> Result<BTreeMap<u32, u64>, Error> {
        let mut starts = BTreeMap::new();
        for mark in previous
            .into_iter()
            .flat_map(|seal| &seal.statement.frontier)
        {
            starts.insert(mark.author, mark.sequence.saturating_add(1));
        }
        if let Some(id) = id {
            // A verified no-frames base at a seal of the path accounts for
            // this scope's own positions through that seal.
            let mut covered = self.seal_anchor(id).await?;
            if let Some(signed) = self
                .checkpoint_record(id, true)
                .await?
                .and_then(|record| record.signed)
                .filter(|signed| signed.statement.no_frames())
                && let Some(sealed) = signed.statement.seal
                && let domain = signed.statement.scope.domain
                && self.path_index(domain, sealed)?.is_some()
            {
                covered.extend(
                    self.graph_for(domain)?
                        .seal_by_id(sealed)
                        .map_err(credential)?
                        .statement
                        .frontier
                        .iter()
                        .cloned(),
                );
            }
            for mark in covered {
                starts
                    .entry(mark.author)
                    .and_modify(|start| *start = (*start).max(mark.sequence.saturating_add(1)))
                    .or_insert(mark.sequence.saturating_add(1));
            }
        }
        Ok(starts)
    }
}
