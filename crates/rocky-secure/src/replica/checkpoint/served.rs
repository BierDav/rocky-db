//! Checkpoints this node signs of seals it keeps, for a node that pulls
//! one: the kept seal's stored rows, restored from history, and the
//! operations through its bound. See `docs/runtime/kept-seals.md`.
use super::*;

pub(crate) const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS secure_served(scope INTEGER PRIMARY KEY,seal BLOB NOT NULL,signed BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS secure_served_rows(scope INTEGER NOT NULL,row BLOB NOT NULL,fields BLOB NOT NULL,PRIMARY KEY(scope,row)) WITHOUT ROWID",
];

/// Where a served checkpoint's rows are.
pub(in crate::replica) enum Served {
    /// The scope's replay base.
    Base,
    /// A kept seal's rows, signed on request.
    Kept,
}
impl Served {
    pub(super) fn rows(&self) -> &'static str {
        match self {
            Self::Base => "secure_checkpoint_rows",
            Self::Kept => "secure_served_rows",
        }
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// The checkpoint of `scope` at `seal` this node serves a peer that
    /// pulls the seal's state: its replay base there, else one it signs of
    /// the seal it keeps. None when it holds neither.
    pub async fn seal_checkpoint_offer(
        &self,
        peer: PublicKey,
        credentials: &CredentialChain,
        scope: ResourceScope,
        seal: Commitment,
    ) -> Result<Option<SignedCheckpoint>, Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        inner = flush_guard(inner, &self.inner).await?;
        inner.authorize_seal_peer(peer, credentials, scope)?;
        // A no-frames base needs no key: its original statement is served.
        if !inner.importing.contains(&scope)
            && !inner.importing(scope).await?
            && let Some(signed) = inner.no_frames_base(scope).await?
            && signed.statement.seal == Some(seal)
        {
            return Ok(inner
                .served_checkpoint(scope)
                .await?
                .map(|(_, signed)| signed)
                .filter(|signed| signed.signer() != peer));
        }
        if inner.scope_key(scope).is_err()
            || inner.importing.contains(&scope)
            || inner.importing(scope).await?
            || (inner.partitioned(scope) && !inner.partitions.contains_key(&scope))
        {
            return Ok(None);
        }
        let Some(id) = inner.find_scope_id(scope).await? else {
            return Ok(None);
        };
        if let Some((_, signed, _)) = inner.seal_served(scope, id, seal).await? {
            return Ok(Some(signed).filter(|signed| signed.signer() != peer));
        }
        let signed = transaction!(inner, |inner| inner.sign_kept(scope, id, seal).await)?;
        drop(flush_guard(inner, &self.inner).await?);
        Ok(signed)
    }
}

impl<A: RowApplication> Inner<A> {
    /// The checkpoint of scope `id` at `seal` this node can serve, signed
    /// under the current policy, and where its rows are.
    pub(super) async fn seal_served(
        &self,
        scope: ResourceScope,
        id: i64,
        seal: Commitment,
    ) -> Result<Option<(i64, SignedCheckpoint, Served)>, Error> {
        let current = |signed: &SignedCheckpoint| -> Result<bool, Error> {
            Ok(signed.statement.seal == Some(seal)
                && (signed.statement.no_frames()
                    || signed.statement.key_epoch() == Some(self.scope_key(scope)?.0))
                && signed.verify_authority(self, now()?).is_ok())
        };
        if let Some(record) = self.checkpoint_record(id, true).await?
            && let Ok(signed) = self.verify_record(scope, &record)
            && current(&signed)?
        {
            return Ok(Some((id, signed, Served::Base)));
        }
        match collect_rows(
            self.conn
                .query("SELECT seal,signed FROM secure_served WHERE scope=?", [id])
                .await?,
        )
        .await?
        .first()
        .map(Vec::as_slice)
        {
            Some([SqlValue::Blob(_), SqlValue::Blob(signed)]) => {
                let signed = SignedCheckpoint::from_bytes(signed)?;
                Ok((current(&signed)?
                    && signed.statement.revocations == self.revocation_digest()?)
                .then_some((id, signed, Served::Kept)))
            }
            None => Ok(None),
            _ => Err(Error::Corrupt("served checkpoint".into())),
        }
    }
    /// The seal checkpoint `checkpoint` of `scope` this node serves.
    pub(super) async fn served_seal_checkpoint(
        &self,
        scope: ResourceScope,
        checkpoint: Commitment,
    ) -> Result<Option<(i64, SignedCheckpoint, Served)>, Error> {
        let Some(id) = self.find_scope_id(scope).await? else {
            return Ok(None);
        };
        let mut seals = Vec::new();
        if let Some(signed) = self
            .checkpoint_record(id, true)
            .await?
            .and_then(|record| record.signed)
        {
            seals.push(signed);
        }
        if let Some([SqlValue::Blob(signed)]) = collect_rows(
            self.conn
                .query("SELECT signed FROM secure_served WHERE scope=?", [id])
                .await?,
        )
        .await?
        .first()
        .map(Vec::as_slice)
        {
            seals.push(SignedCheckpoint::from_bytes(signed)?);
        }
        for signed in seals {
            if signed.id()? == checkpoint
                && let Some(seal) = signed.statement.seal
                && let Some(served) = self.seal_served(scope, id, seal).await?
                && served.1.id()? == checkpoint
            {
                return Ok(Some(served));
            }
        }
        Ok(None)
    }
    /// Inside the caller's transaction, signs replayed scope `id`'s rows at
    /// kept `seal` and keeps them to serve. None when the seal is not kept
    /// under the installed schema, the replay base lies past it, or the
    /// covered identities are no longer known.
    async fn sign_kept(
        &mut self,
        scope: ResourceScope,
        id: i64,
        seal: Commitment,
    ) -> Result<Option<SignedCheckpoint>, Error> {
        let Some(kept) = self.kept_rewind(seal).await? else {
            return Ok(None);
        };
        let Some((mark, through)) = kept.at(id) else {
            return Ok(None);
        };
        let tip = self
            .graph_for(scope.domain)?
            .seal_by_id(seal)
            .map_err(credential)?
            .statement
            .tip;
        let previous = self
            .checkpoint_record(id, true)
            .await?
            .and_then(|record| record.signed.map(|signed| (record.position, signed)));
        if let Some((position, signed)) = &previous
            && (*position > through || signed.statement.seal.is_none())
        {
            return Ok(None);
        }
        let Some(rows) = self.kept_images(scope, (seal, mark)).await? else {
            return Ok(None);
        };
        let (frontier, operations) = self.covered_frontier(id, previous.as_ref(), through).await?;
        let previous_marks = previous
            .as_ref()
            .map_or(&[][..], |(_, signed)| &signed.statement.identities);
        let Some(identities) = self
            .covered_identity_marks(id, previous_marks, &frontier)
            .await?
            .filter(|marks| self.check_base_identities(scope, tip, &rows, marks).is_ok())
        else {
            return Ok(None);
        };
        for sql in [
            "DELETE FROM secure_served WHERE scope=?",
            "DELETE FROM secure_served_rows WHERE scope=?",
        ] {
            self.conn.execute(sql, [id]).await?;
        }
        for (row, image) in &rows {
            self.conn
                .execute(
                    "INSERT INTO secure_served_rows VALUES(?,?,?)",
                    bindings(vec![
                        SqlValue::Integer(id),
                        SqlValue::Blob(row.to_vec()),
                        SqlValue::Blob(image.clone()),
                    ]),
                )
                .await?;
        }
        let sets = replay::base_sets(&rows);
        let (handles, handle_digest) = self.handle_set().await?;
        let frontier: Vec<LogPosition> = frontier.into_values().collect();
        let statement = CheckpointStatement {
            format: CHECKPOINT_FORMAT,
            seal: Some(seal),
            partition: self.partitions.get(&scope).cloned(),
            identities,
            // Replayed rows never move.
            moves: SetSummary {
                count: 0,
                digest: [0; 32],
            },
            tip,
            schema: self
                .generation_of(self.manifest_of_tip(tip)?, false)?
                .schema,
            revocations: self.revocation_digest()?,
            scope,
            state: CheckpointState::Keyed {
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
            tombstones: 0,
            creations: sets.creations_summary(),
            handles: SetSummary {
                count: handles,
                digest: handle_digest.digest(),
            },
            custody: self.custody_summary(id, through).await?,
        };
        let signed = self.sign_checkpoint(statement)?;
        self.conn
            .execute(
                "INSERT INTO secure_served VALUES(?,?,?)",
                bindings(vec![
                    SqlValue::Integer(id),
                    SqlValue::Blob(seal.to_vec()),
                    SqlValue::Blob(signed.to_bytes()?),
                ]),
            )
            .await?;
        Ok(Some(signed))
    }
    /// Inside the caller's transaction, forgets what was served of `seal`.
    pub(in crate::replica) async fn drop_served(&self, seal: Commitment) -> Result<(), Error> {
        self.conn
            .execute(
                "DELETE FROM secure_served_rows WHERE scope IN (SELECT scope FROM secure_served WHERE seal=?)",
                [seal.to_vec()],
            )
            .await?;
        self.conn
            .execute("DELETE FROM secure_served WHERE seal=?", [seal.to_vec()])
            .await?;
        Ok(())
    }
}
