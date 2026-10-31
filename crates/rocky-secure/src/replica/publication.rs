//! Staged publications: one local SQL transaction of any size whose writes
//! leave as consecutive ordinary bundles. A migration of replayed tables
//! publishes its program instead; see [`intents`].
use super::*;
mod intents;
#[cfg(feature = "qualification")]
pub use intents::CHUNK_PAGES;
pub use intents::PUBLICATION_CHUNK_BUNDLES;
pub(super) use intents::SCHEMA as INTENT_SCHEMA;

pub(super) const SCHEMA: &[&str] = &[
    // `published` counts the leading bundles some peer holds.
    "CREATE TABLE IF NOT EXISTS secure_publications(publication BLOB PRIMARY KEY,bundles INTEGER NOT NULL,published INTEGER NOT NULL) WITHOUT ROWID",
    // Retained frames of publications, outside the retained-history bound
    // until they are pruned.
    "CREATE TABLE IF NOT EXISTS secure_publication_frames(hash BLOB PRIMARY KEY,bytes INTEGER NOT NULL) WITHOUT ROWID",
];

/// How far a staged publication has left this replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Publication {
    pub id: Commitment,
    /// Bundles the transaction committed.
    pub bundles: u64,
    /// Leading bundles every frame of which a peer reported holding.
    pub published: u64,
}

/// The handle of a publication's bundle at `position`.
#[cfg(test)]
pub(crate) fn handle(publication: &Commitment, position: u64) -> Commitment {
    bundle_handle(publication, position)
}
/// The handle of a publication's bundle at `position`.
pub(super) fn bundle_handle(publication: &Commitment, position: u64) -> Commitment {
    rocky_core::commitment(
        "rocky.secure-publication.v1",
        &[publication.as_slice(), &position.to_le_bytes()].concat(),
    )
}

impl<A: RowApplication> Inner<A> {
    async fn publication_record(
        &self,
        publication: &Commitment,
    ) -> Result<Option<(u64, u64)>, Error> {
        let stored = collect_rows(
            self.conn
                .query(
                    "SELECT bundles,published FROM secure_publications WHERE publication=?",
                    [publication.to_vec()],
                )
                .await?,
        )
        .await?;
        match stored.first().map(Vec::as_slice) {
            None => Ok(None),
            Some([SqlValue::Integer(bundles), SqlValue::Integer(published)]) => {
                Ok(Some((*bundles as u64, *published as u64)))
            }
            Some(_) => Err(Error::Corrupt("publication record".into())),
        }
    }
    /// The frames a publication committed, in bundle order.
    async fn publication_frames(
        &self,
        publication: &Commitment,
        bundles: u64,
    ) -> Result<Vec<EncryptedFrame>, Error> {
        let mut frames = Vec::new();
        for position in 0..bundles {
            for frame in self
                .bundle_frames(&bundle_handle(publication, position))
                .await?
            {
                frames.extend(frame);
            }
        }
        Ok(frames)
    }
    /// Each member of the bundle under `handle`; None once pruned.
    pub(crate) async fn bundle_frames(
        &self,
        handle: &Commitment,
    ) -> Result<Vec<Option<EncryptedFrame>>, Error> {
        let mut frames = Vec::new();
        for record in collect_rows(
            self.conn
                .query(
                    "SELECT hash FROM secure_bundle_handles WHERE handle=? ORDER BY member",
                    [handle.to_vec()],
                )
                .await?,
        )
        .await?
        {
            let [SqlValue::Blob(hash)] = record.as_slice() else {
                return Err(Error::Corrupt("bundle handle".into()));
            };
            let hash = Hash::try_from(hash.as_slice())
                .map_err(|_| Error::Corrupt("bundle handle".into()))?;
            frames.push(self.frame(hash).await?);
        }
        Ok(frames)
    }
    /// Records `publication`, whose transaction changed no replayed row,
    /// inside the caller's open engine transaction. A recorded publication
    /// returns its frames again; the caller rolls back.
    pub(super) async fn stage_publication(
        &mut self,
        publication: Commitment,
    ) -> Result<(Vec<EncryptedFrame>, bool), Error> {
        if let Some((bundles, _)) = self.publication_record(&publication).await? {
            return Ok((self.publication_frames(&publication, bundles).await?, true));
        }
        let migration = self.migration_stage(publication).await?;
        self.record_publication(publication, 0, &[], migration)
            .await?;
        Ok((Vec::new(), false))
    }
    /// Records the authored `bundles` of `publication`, its migration
    /// intent for a migration stage, and commits its schema stage.
    async fn record_publication(
        &self,
        publication: Commitment,
        bundles: u64,
        frames: &[EncryptedFrame],
        migration: Option<SchemaStage>,
    ) -> Result<(), Error> {
        for position in 0..bundles {
            self.conn
                .execute(
                    "INSERT INTO secure_publication_frames SELECT o.hash,length(o.header)+length(o.body) FROM secure_bundle_handles h JOIN secure_operations o ON o.hash=h.hash WHERE h.handle=?",
                    [bundle_handle(&publication, position).to_vec()],
                )
                .await?;
        }
        self.conn
            .execute(
                "INSERT INTO secure_publications VALUES(?,?,0)",
                bindings(vec![
                    SqlValue::Blob(publication.to_vec()),
                    SqlValue::Integer(bundles as i64),
                ]),
            )
            .await?;
        if let Some(stage) = migration {
            self.build_migration_intent(&stage, frames).await?;
        }
        self.commit_schema_stage(publication).await
    }
    /// Whether some peer reported holding every member of the bundle.
    async fn bundle_published(&self, handle: &Commitment) -> Result<bool, Error> {
        for frame in self.bundle_frames(handle).await? {
            // Pruning waits for the copies retention requires.
            let Some(frame) = frame else { continue };
            let header = frame.operation_ref()?.header.clone();
            let (held, _) = self
                .covering_peers(&encode(&frame.scope()?)?, header.public_key, header.seq_num)
                .await?;
            if held.is_empty() {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// Whether this publisher listed its closing base. Graph records remain
    /// the completion journal after bases advance or new scopes are held.
    pub async fn migration_checkpoint_listed(
        &self,
        publication: Commitment,
    ) -> Result<bool, Error> {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        let Some((migration, _, _)) = inner.migration_record(publication).await? else {
            return Ok(true);
        };
        let path = inner.path_seals(migration.scope)?;
        let Some(start) = path
            .iter()
            .position(|seal| seal.statement.tip == migration.tip)
        else {
            // A losing branch is retained, but is not this workspace's to close.
            return Ok(inner.workspace.tip != migration.tip);
        };
        let graph = inner.graph_for(migration.scope)?;
        for seal in &path[start..] {
            if seal.statement.action
                != (rocky_credentials::SealAction::Continue {
                    schema: graph.schema(seal.statement.tip).map_err(credential)?,
                })
            {
                continue;
            }
            let seal = seal.id().map_err(credential)?;
            for record in graph.checkpoints_at(seal).map_err(credential)? {
                let signer = record.statement.signer;
                let owned = signer == inner.config.node.public_key()
                    || inner
                        .credential_signer
                        .as_ref()
                        .is_some_and(|key| key.public_key() == signer)
                    || inner
                        .node_author
                        .as_ref()
                        .is_some_and(|author| author.key.public_key() == signer)
                    || inner
                        .line_nodes
                        .values()
                        .any(|author| author.key.public_key() == signer);
                // Compaction moves all held bases atomically; listing publishes
                // their records together. A retained own record proves completion.
                if owned {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Every staged publication this replica committed, with how many of
    /// its leading bundles a peer reported holding. Reads one publication,
    /// or checks one bundle, per acquisition, and records a publication's
    /// progress in one transaction once its checks end. The count only
    /// grows, so a check made against older state never lowers it.
    pub async fn publications(&self) -> Result<Vec<Publication>, Error> {
        let mut publications = Vec::new();
        let mut after = Vec::new();
        // The publication being checked, with the count stored for it.
        let mut current: Option<(Publication, u64)> = None;
        let mut first = true;
        loop {
            if !std::mem::take(&mut first) {
                tokio::task::yield_now().await;
            }
            let mut inner = self.inner.lock(crate::replica::Class::Background).await;
            let Some((publication, stored)) = current.as_mut() else {
                let records = collect_rows(
                    inner
                        .conn
                        .query(
                            "SELECT publication,bundles,published FROM secure_publications WHERE publication>? ORDER BY publication LIMIT 1",
                            [after.clone()],
                        )
                        .await?,
                )
                .await?;
                let Some(record) = records.first() else {
                    return Ok(publications);
                };
                let [
                    SqlValue::Blob(id),
                    SqlValue::Integer(bundles),
                    SqlValue::Integer(published),
                ] = record.as_slice()
                else {
                    return Err(Error::Corrupt("publication record".into()));
                };
                after.clone_from(id);
                let id: Commitment = id
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Corrupt("publication record".into()))?;
                // A publication on a tip that lost its race stays retained on
                // its branch; it is not this workspace's to publish.
                if let Some(Some(frame)) = inner
                    .bundle_frames(&bundle_handle(&id, 0))
                    .await?
                    .into_iter()
                    .next()
                    && matches!(
                        inner.frame_reach(&frame)?,
                        super::tips::FrameReach::Held | super::tips::FrameReach::Unfollowed
                    )
                {
                    continue;
                }
                current = Some((
                    Publication {
                        id,
                        bundles: *bundles as u64,
                        published: *published as u64,
                    },
                    *published as u64,
                ));
                continue;
            };
            if publication.published < publication.bundles
                && inner
                    .bundle_published(&bundle_handle(&publication.id, publication.published))
                    .await?
            {
                publication.published += 1;
                continue;
            }
            if publication.published != *stored {
                let (id, published) = (publication.id, publication.published);
                transaction!(&mut inner, |inner| {
                    inner
                        .conn
                        .execute(
                            "UPDATE secure_publications SET published=max(published,?) WHERE publication=?",
                            bindings(vec![
                                SqlValue::Integer(published as i64),
                                SqlValue::Blob(id.to_vec()),
                            ]),
                        )
                        .await?;
                    Ok(())
                })?;
            }
            publications.extend(current.take().map(|(publication, _)| publication));
        }
    }
}
