//! Checkpoint offers and paged imports: bootstrap and rebootstrap of a scope.
use super::*;
use rows::{CatchUp, ScopeSync};

/// Bytes of one checkpoint page: the largest a frame holds, leaving room
/// for the framing.
pub(super) const CHECKPOINT_PAGE: usize = MAX_SECURE_FRAME - 8192;

#[derive(Serialize, Deserialize)]
pub(super) enum CheckpointMessage {
    Pruned {
        scope: ResourceScope,
        after: Option<PublicKey>,
    },
    PrunedLogs {
        page: PrunedPage,
    },
    ArchiveProgress {
        after: Option<Commitment>,
        complete: bool,
    },
    ArchiveBegin {
        signed: Box<SignedCheckpoint>,
    },
    ArchivePage {
        page: Box<CheckpointPage>,
    },
    CheckpointOffer {
        scope: ResourceScope,
    },
    /// The peer's checkpoint of a scope at a seal it keeps.
    SealOffer {
        scope: ResourceScope,
        seal: Commitment,
    },
    Checkpoint {
        signed: Option<Box<SignedCheckpoint>>,
    },
    CheckpointPull {
        scope: ResourceScope,
        checkpoint: Commitment,
        after: Option<Commitment>,
        quota: usize,
        window: u8,
    },
    CheckpointRows {
        page: Box<CheckpointPage>,
        last: bool,
    },
}

/// How pulling a seal's state from one peer ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealPull {
    /// This node holds the seal's state now.
    Held,
    /// The peer keeps no state there for some scope.
    Unavailable,
    /// The session's byte budget ran low; staged pages remain.
    Exhausted,
}

impl NativeSession {
    /// Pulls `seal`'s state from the peer for every held scope of the
    /// followed domain that lacks it: the peer's base there, or a
    /// checkpoint it signs of the seal it keeps. Scopes the peer cannot
    /// serve are left to another peer. Nothing changes in the rows;
    /// following a tip whose path passes the seal installs it.
    pub async fn pull_seal<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        seal: Commitment,
    ) -> Result<SealPull, Error> {
        self.pull_seal_scopes(replica, seal, &[]).await
    }
    async fn pull_seal_scopes<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        seal: Commitment,
        selected: &[ResourceScope],
    ) -> Result<SealPull, Error> {
        let Some((domain, _)) = replica.followed_bookmark().await else {
            return Err(denied("follow a bookmark before pulling a seal"));
        };
        let scopes: Vec<_> = replica
            .seal_pull_scopes(domain, seal)
            .await?
            .into_iter()
            .filter(|scope| selected.is_empty() || selected.contains(scope))
            .collect();
        let mut missing = false;
        for scope in scopes {
            match replica
                .authorize_held_reader(self.peer, &self.credentials, scope)
                .await
            {
                Ok(()) => {}
                Err(Error::Rejected(_)) => {
                    missing = true;
                    continue;
                }
                Err(error) => return Err(error),
            }
            if !self.try_scoped_holding(replica, &[scope], true).await? {
                missing = true;
                continue;
            }
            self.send(CheckpointMessage::SealOffer { scope, seal })
                .await?;
            let Some(signed) = self.offered(scope).await? else {
                missing = true;
                continue;
            };
            if signed.statement.seal != Some(seal) {
                return Err(denied("the peer offers another seal's checkpoint"));
            }
            let checkpoint = signed.id()?;
            let (after, complete) = match replica.rebootstrap_progress(scope).await? {
                Some((staged, cursor, complete)) if staged == checkpoint => (cursor, complete),
                _ => {
                    replica.begin_seal_pull(*signed).await?;
                    staged_progress(replica, scope).await?
                }
            };
            if !self
                .fetch_pages(
                    replica,
                    scope,
                    checkpoint,
                    (after, complete),
                    CHECKPOINT_PAGE,
                )
                .await?
            {
                return Ok(SealPull::Exhausted);
            }
            replica.finish_seal_pull(scope).await?;
        }
        Ok(if missing {
            SealPull::Unavailable
        } else {
            SealPull::Held
        })
    }
    /// Pulls from the peer every seal this replica wants. Returns false
    /// once the session's budget runs low.
    pub async fn pull_wanted_seals<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
    ) -> Result<bool, Error> {
        self.pull_wanted_seals_for_scopes(replica, &[]).await
    }
    /// Pulls wanted checkpoint state only for the selected request scopes.
    pub async fn pull_wanted_seals_for_scopes<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scopes: &[ResourceScope],
    ) -> Result<bool, Error> {
        let Some((domain, _)) = replica.followed_bookmark().await else {
            return Ok(true);
        };
        for seal in replica.wanted_seals(domain).await? {
            if self.pull_seal_scopes(replica, seal, scopes).await? == SealPull::Exhausted {
                return Ok(false);
            }
        }
        replica.finish_seal_rebootstrap(domain).await?;
        Ok(true)
    }
    /// Imports the peer's checkpoint of a scope and switches to it. An
    /// interrupted import of the same checkpoint continues where it stopped.
    pub async fn rebootstrap<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scope: ResourceScope,
        quota: usize,
    ) -> Result<RebootstrapReport, Error> {
        self.rebootstrap_within(replica, scope, quota)
            .await?
            .ok_or_else(|| {
                denied("native session byte budget exhausted; continue on a new session")
            })
    }
    /// Like `rebootstrap`, but returns `None` once the session's budget runs
    /// low; the staged pages remain and a new session continues.
    async fn rebootstrap_within<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scope: ResourceScope,
        quota: usize,
    ) -> Result<Option<RebootstrapReport>, Error> {
        self.ensure_holding(replica, &[scope]).await?;
        let signed = self
            .checkpoint_offer(scope)
            .await?
            .ok_or_else(|| denied("the peer offers no checkpoint"))?;
        self.import_within(replica, signed, quota).await
    }
    /// Moves every held scope of the followed domain whose replay base left
    /// the followed path, or was pruned at another cut, to a seal of the
    /// path: it imports the peer's checkpoint when the graph lists it
    /// there, else replays frames, from the peer when it pruned them and the
    /// peer pruned none. A scope neither can rebuild waits. Returns false
    /// once the session's budget runs low.
    pub async fn rebootstrap_at_seals<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
    ) -> Result<bool, Error> {
        self.rebootstrap_scopes_at_seals(replica, &[]).await
    }
    /// Limits recovery to the selected scopes; an empty selection means every scope.
    pub async fn rebootstrap_scopes_at_seals<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scopes: &[ResourceScope],
    ) -> Result<bool, Error> {
        let Some((domain, _)) = replica.followed_bookmark().await else {
            return Ok(true);
        };
        let needs: Vec<_> = replica
            .seal_rebootstraps(domain)
            .await?
            .into_iter()
            .filter(|need| scopes.is_empty() || scopes.contains(&need.scope))
            .collect();
        if needs.is_empty()
            && replica
                .compaction_status(domain)
                .await?
                .rebootstrap
                .is_none()
        {
            return Ok(true);
        }
        // A peer on another tip or outside a scope leaves its recovery to another peer.
        let shared = replica
            .peer_holds(
                self.peer,
                &self.credentials,
                &needs.iter().map(|need| need.scope).collect::<Vec<_>>(),
            )
            .await?;
        // A scope that fails leaves the others to recover; the first
        // failure is returned once every scope ran.
        let mut failed = None;
        for need in needs {
            match self.rebootstrap_need(replica, &shared, need).await {
                Ok(true) => {}
                Ok(false) => return Ok(false),
                Err(error) => {
                    failed.get_or_insert(error);
                }
            }
        }
        replica.finish_seal_rebootstrap(domain).await?;
        failed.map_or(Ok(true), Err)
    }
    /// One scope of `rebootstrap_scopes_at_seals`; false once the session's
    /// budget runs low.
    async fn rebootstrap_need<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        shared: &[ResourceScope],
        need: SealRebootstrap,
    ) -> Result<bool, Error> {
        let scope = need.scope;
        let shared =
            shared.contains(&scope) && self.try_scoped_holding(replica, &[scope], false).await?;

        if !need.listed.is_empty()
            && shared
            && let Some(signed) = self.checkpoint_offer(scope).await?
            && need.listed.contains(&signed.id()?)
        {
            return Ok(self
                .import_within(replica, signed, CHECKPOINT_PAGE)
                .await?
                .is_some());
        }
        match need.replay {
            FrameReplay::Local => replica.replay_at_seals(scope, false).await?,
            FrameReplay::Peers if shared && self.retains_history(replica, scope).await? => {
                replica.replay_at_seals(scope, true).await?
            }
            FrameReplay::Peers => {}
        }
        Ok(true)
    }
    /// Imports the peer's checkpoint of `scope` when the graph lists it at
    /// a seal of the followed path that the scope cannot finalize from the
    /// history it caught up: a revoked author's rows, for one, come only so.
    /// Returns false once the session's budget runs low.
    pub async fn replace_with_listed<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scope: ResourceScope,
    ) -> Result<bool, Error> {
        let listed = replica.listed_replacements(scope).await?;
        if listed.is_empty() || !self.try_scoped_holding(replica, &[scope], false).await? {
            return Ok(true);
        }
        let Some(signed) = self.checkpoint_offer(scope).await? else {
            return Ok(true);
        };
        if !listed.contains(&signed.id()?) {
            return Ok(true);
        }
        Ok(self
            .import_within(replica, signed, CHECKPOINT_PAGE)
            .await?
            .is_some())
    }
    /// Whether the peer pruned no frame of `scope`.
    async fn retains_history<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scope: ResourceScope,
    ) -> Result<bool, Error> {
        self.ensure_holding(replica, &[scope]).await?;
        self.send(CheckpointMessage::Pruned { scope, after: None })
            .await?;
        let CheckpointMessage::PrunedLogs { page } = self.reply::<CheckpointMessage>().await?
        else {
            return Err(denied("unexpected pruned_prefix response"));
        };
        if page.scope != scope {
            return Err(denied("pruned_prefix outside subscription"));
        }
        Ok(page.logs.is_empty())
    }
    /// The checkpoint the peer offers for each scope, in order, with its
    /// stored rows; `None` where it offers none this replica may import:
    /// what a bootstrap plans with before it imports anything.
    pub async fn offered_rows<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scopes: &[ResourceScope],
    ) -> Result<Vec<Option<(Commitment, u64)>>, Error> {
        self.ensure_holding(replica, scopes).await?;
        let mut offered = Vec::with_capacity(scopes.len());
        for scope in scopes {
            offered.push(match self.checkpoint_offer(*scope).await? {
                Some(signed)
                    if signed.statement.seal.is_some()
                        || !replica.owns_checkpoint_signer(&signed).await =>
                {
                    Some((signed.id()?, signed.statement.rows.count))
                }
                _ => None,
            });
        }
        Ok(offered)
    }
    /// The peer's current checkpoint of `scope`, if it offers one.
    async fn checkpoint_offer(
        &mut self,
        scope: ResourceScope,
    ) -> Result<Option<Box<SignedCheckpoint>>, Error> {
        self.send(CheckpointMessage::CheckpointOffer { scope })
            .await?;
        self.offered(scope).await
    }
    /// The answer to an offer of `scope`.
    async fn offered(
        &mut self,
        scope: ResourceScope,
    ) -> Result<Option<Box<SignedCheckpoint>>, Error> {
        let CheckpointMessage::Checkpoint { signed } = self.reply::<CheckpointMessage>().await?
        else {
            return Err(denied("unexpected checkpoint offer response"));
        };
        if signed
            .as_ref()
            .is_some_and(|signed| signed.statement.scope != scope)
        {
            return Err(denied("checkpoint outside subscription"));
        }
        Ok(signed)
    }
    async fn import_within<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        signed: Box<SignedCheckpoint>,
        quota: usize,
    ) -> Result<Option<RebootstrapReport>, Error> {
        let scope = signed.statement.scope;
        let checkpoint = signed.id()?;
        let progress = match replica.rebootstrap_progress(scope).await? {
            Some((staged, cursor, complete)) if staged == checkpoint => (cursor, complete),
            _ => {
                replica.begin_rebootstrap(*signed).await?;
                staged_progress(replica, scope).await?
            }
        };
        if !self
            .fetch_pages(replica, scope, checkpoint, progress, quota)
            .await?
        {
            return Ok(None);
        }
        let report = replica.finish_rebootstrap(scope).await?;
        Ok(Some(report))
    }
    /// Stages the pages of `checkpoint` after `after` until it is
    /// complete. Returns false once the session's budget runs low.
    async fn fetch_pages<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scope: ResourceScope,
        checkpoint: Commitment,
        (mut after, mut complete): (Option<Commitment>, bool),
        quota: usize,
    ) -> Result<bool, Error> {
        if !(4096..=CHECKPOINT_PAGE).contains(&quota) {
            return Err(denied("native page quota"));
        }
        let mut left = 0;
        while !complete {
            if left == 0 {
                let window = self.checkpoint_window(quota);
                if window == 0 {
                    return Ok(false);
                }
                self.send(CheckpointMessage::CheckpointPull {
                    scope,
                    checkpoint,
                    after,
                    quota,
                    window,
                })
                .await?;
                left = window;
            }
            let CheckpointMessage::CheckpointRows { page, last } =
                self.reply::<CheckpointMessage>().await?
            else {
                return Err(denied("unexpected checkpoint response"));
            };
            if page.scope != scope || page.checkpoint != checkpoint || page.after != after {
                return Err(denied("checkpoint page outside request"));
            }
            left -= 1;
            if !last && (left == 0 || page.next.is_none()) {
                return Err(denied("checkpoint window outside request"));
            }
            (after, complete) = (page.next, page.next.is_none());
            if last {
                left = 0;
            }
            // Request the next window before storing the end of this one.
            let window = self.checkpoint_window(quota);
            if last && !complete && window > 0 {
                self.send(CheckpointMessage::CheckpointPull {
                    scope,
                    checkpoint,
                    after,
                    quota,
                    window,
                })
                .await?;
                left = window;
            }
            replica.stage_checkpoint_page(*page).await?;
        }
        Ok(true)
    }
    fn checkpoint_window(&self, quota: usize) -> u8 {
        if self.low(quota) {
            return 0;
        }
        ((self.remaining.saturating_sub(64 * 1024) / (quota + 8192)).min(4)) as u8
    }
    /// Serves until the session ends or an answer fails; returns how many
    /// checkpoint pages the peer asked for.
    #[cfg(test)]
    pub(crate) async fn serve_counting_pages<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
    ) -> usize {
        let mut pages = 0;
        while let Ok(message) = self.answered().await {
            pages += usize::from(matches!(
                message,
                Message::Checkpoints(CheckpointMessage::CheckpointPull { .. })
            ));
            if self.answer(replica, message).await.is_err() {
                break;
            }
        }
        pages
    }
    /// Starts from a verified checkpoint even when the peer has retained history,
    /// then catches up. Exhausted sessions leave durable import progress.
    /// `None` when the peer offers no checkpoint, as a peer without
    /// whole-scope read does not.
    pub async fn bootstrap_scope<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scope: ResourceScope,
        quota: usize,
    ) -> Result<Option<ScopeSync>, Error> {
        self.bootstrap_advised_scope(replica, scope, quota, None)
            .await
    }

    /// Imports only the exact advised offer; a replaced offer is retried later.
    pub async fn bootstrap_advised_scope<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scope: ResourceScope,
        quota: usize,
        advice: Option<&crate::StateAdvice>,
    ) -> Result<Option<ScopeSync>, Error> {
        if self.low(MAX_SECURE_FRAME) {
            return Ok(Some(ScopeSync {
                rebootstrap: None,
                catch_up: CatchUp {
                    exhausted: true,
                    ..Default::default()
                },
            }));
        }
        self.ensure_holding(replica, &[scope]).await?;
        let Some(signed) = self.checkpoint_offer(scope).await? else {
            return Ok(None);
        };
        if let Some(advice) = advice
            && (signed.id()? != advice.checkpoint
                || signed.signer() != advice.signer
                || signed.statement.seal != Some(advice.seal)
                || signed.statement.rows.count != advice.rows)
        {
            return Err(denied("checkpoint superseded since state advice"));
        }
        if signed.statement.seal.is_none() && replica.owns_checkpoint_signer(&signed).await {
            return Ok(None);
        }
        // Switching to the installed checkpoint again would only rewrite its rows.
        let installed = replica.checkpoint_installed(&signed).await?;
        let rebootstrap = match installed {
            true => None,
            false => self.import_within(replica, signed, CHECKPOINT_PAGE).await?,
        };
        let catch_up = if installed || rebootstrap.is_some() {
            self.catch_up(replica, scope, quota).await?
        } else {
            CatchUp {
                exhausted: true,
                ..Default::default()
            }
        };
        if catch_up.behind {
            return Err(denied(
                "still behind the peer's pruned_prefix after bootstrap",
            ));
        }
        Ok(Some(ScopeSync {
            rebootstrap,
            catch_up,
        }))
    }
    /// Rebootstraps `scope` from the peer if this replica is behind its
    /// pruned_prefix, then catches up.
    pub async fn sync_scope<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scope: ResourceScope,
        quota: usize,
    ) -> Result<ScopeSync, Error> {
        let held_exhausted = if replica.tip_statements(None, 1).await?.is_empty() {
            false
        } else {
            self.sync_held_changes(replica, scope, quota).await?
        };
        let mut catch_up = self.catch_up(replica, scope, quota).await?;
        catch_up.exhausted |= held_exhausted;
        let mut rebootstrap = None;
        if catch_up.behind && self.low(MAX_SECURE_FRAME) {
            catch_up.exhausted = true;
        } else if catch_up.behind {
            rebootstrap = self
                .rebootstrap_within(replica, scope, CHECKPOINT_PAGE)
                .await?;
            if rebootstrap.is_none() {
                catch_up.exhausted = true;
                return Ok(ScopeSync {
                    rebootstrap,
                    catch_up,
                });
            }
            catch_up = self.catch_up(replica, scope, quota).await?;
            if catch_up.behind {
                return Err(denied(
                    "still behind the peer's pruned_prefix after rebootstrap",
                ));
            }
        }
        Ok(ScopeSync {
            rebootstrap,
            catch_up,
        })
    }
    pub(super) async fn answer_checkpoints<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        message: CheckpointMessage,
    ) -> Result<(), Error> {
        if replica.private_schema().await? {
            return Err(denied("schema publication is private"));
        }
        match message {
            CheckpointMessage::Pruned { scope, after } => {
                let page = replica
                    .pruned_page(self.peer, &self.credentials, scope, after)
                    .await?;
                self.send(CheckpointMessage::PrunedLogs { page }).await
            }
            CheckpointMessage::ArchiveBegin { signed } => {
                let (after, complete) = replica
                    .begin_checkpoint_archive(self.peer, &self.credentials, *signed)
                    .await?;
                self.send(CheckpointMessage::ArchiveProgress { after, complete })
                    .await
            }
            CheckpointMessage::ArchivePage { page } => {
                replica
                    .archive_checkpoint_page(self.peer, &self.credentials, *page)
                    .await?;
                self.send(Message::Acknowledged).await
            }
            CheckpointMessage::CheckpointOffer { scope } => {
                let signed = replica
                    .checkpoint_offer(self.peer, &self.credentials, scope)
                    .await?;
                self.send(CheckpointMessage::Checkpoint {
                    signed: signed.map(Box::new),
                })
                .await
            }
            CheckpointMessage::SealOffer { scope, seal } => {
                let signed = replica
                    .seal_checkpoint_offer(self.peer, &self.credentials, scope, seal)
                    .await?;
                self.send(CheckpointMessage::Checkpoint {
                    signed: signed.map(Box::new),
                })
                .await
            }
            CheckpointMessage::CheckpointPull {
                scope,
                checkpoint,
                mut after,
                quota,
                window,
            } => {
                if quota > CHECKPOINT_PAGE || !(1..=4).contains(&window) {
                    return Err(denied("native page quota"));
                }
                for index in 0..window {
                    let page = replica
                        .checkpoint_page(
                            self.peer,
                            &self.credentials,
                            scope,
                            checkpoint,
                            after,
                            quota,
                        )
                        .await?;
                    after = page.next;
                    let last = after.is_none() || index + 1 == window || self.low(quota);
                    self.send(CheckpointMessage::CheckpointRows {
                        page: Box::new(page),
                        last,
                    })
                    .await?;
                    if last {
                        break;
                    }
                }
                Ok(())
            }
            _ => Err(denied("unexpected native request")),
        }
    }
}

/// Where a just-begun import stands: a no-frames checkpoint stages complete.
async fn staged_progress<A: RowApplication>(
    replica: &EncryptedReplica<A>,
    scope: ResourceScope,
) -> Result<(Option<Commitment>, bool), Error> {
    Ok(replica
        .rebootstrap_progress(scope)
        .await?
        .map_or((None, false), |(_, cursor, complete)| (cursor, complete)))
}

#[cfg(test)]
mod format_tests {
    use super::*;
    #[test]
    fn a_parent_checkpoint_offer_with_removed_metadata_is_refused() {
        #[derive(Serialize)]
        enum Parent {
            Checkpoint {
                signed: Option<Box<SignedCheckpoint>>,
                cuts: Vec<()>,
            },
        }
        let bytes = encode(&Parent::Checkpoint {
            signed: None,
            cuts: vec![],
        })
        .unwrap();
        assert!(decode_bounded::<CheckpointMessage>(&bytes, MAX_SECURE_FRAME).is_err());
    }
}
