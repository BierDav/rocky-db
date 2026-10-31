//! Seals, tips and bookmarks: the developer calls over the replica's tip
//! graph. See `docs/runtime/tips-and-bookmarks.md`.
use super::*;
use crate::tips::{
    Bookmark, BookmarkMove, KeptSeals, LosingMove, TipAuthorMark, TipCheckpoint, TipCompaction,
    TipDevice, TipFrontierLog, TipInspection, TipNode, TipOpening, TipPruneBlock, TipRecovery,
    TipScopeFrontier, TipSeal, TipStatus,
};
use rocky_core::{Scope, TipId};
use rocky_credentials::{
    BOOKMARK_MOVE_FORMAT, BookmarkMoveStatement, CredentialChain, GENESIS_LINE_FORMAT,
    GenesisLineStatement, IdentityProvider, SEAL_FORMAT, SealAction, SealStatement,
    SignedBookmarkMove, SignedGenesisLine, SignedSeal, SignedTipOpening, TIP_OPENING_FORMAT,
    TipGraph, TipOpeningStatement,
};
use rocky_secure::TipStatement;

fn hex(digest: &rocky_core::Commitment) -> String {
    HEXLOWER.encode(digest)
}
fn authority(authority: rocky_credentials::TipAuthority) -> String {
    match authority {
        rocky_credentials::TipAuthority::Owner => "owner",
        rocky_credentials::TipAuthority::Trusted => "trusted",
        rocky_credentials::TipAuthority::Issuer => "issuer",
    }
    .into()
}
fn digest(request: &Value, name: &str) -> Result<rocky_core::Commitment, Failure> {
    request[name]
        .as_str()
        .and_then(|hex| HEXLOWER.decode(hex.as_bytes()).ok())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| refused(format!("{name} must be a hex digest")))
}
fn text<'a>(request: &'a Value, name: &str) -> Result<&'a str, Failure> {
    request[name]
        .as_str()
        .ok_or_else(|| refused(format!("{name} must be a string")))
}

/// Who signs tip statements: the identity and the links its authority
/// comes through.
pub(super) struct Signer {
    pub(super) identity: Arc<dyn IdentityProvider>,
    pub(super) links: CredentialChain,
    /// The owner or a trusted identity, which open tips.
    opens: bool,
}

impl Node {
    pub(super) async fn tips(&self, request: &Value) -> Result<Value, Failure> {
        let action = request["action"].as_str().unwrap_or_default();
        let scope = self.domain().scope;
        match action {
            "status" => {}
            "inspect" => return Ok(serde_json::to_value(self.inspect_tips(scope).await?)?),
            "kept" => return Ok(serde_json::to_value(self.kept_seals().await?)?),
            "keep" => {
                let config: KeptSeals =
                    serde_json::from_value(request.get("kept").cloned().unwrap_or(Value::Null))
                        .map_err(|error| {
                            refused(format!("kept must name the seals to keep: {error}"))
                        })?;
                self.replica
                    .keep_seals(rocky_secure::KeptSeals {
                        bookmarked: config.bookmarked,
                        latest: config.latest,
                        every: config.every,
                    })
                    .await?;
                self.observations.touch();
                return Ok(serde_json::to_value(self.kept_seals().await?)?);
            }
            "compaction" => {
                return Ok(serde_json::to_value(
                    self.compaction(scope, 0, Vec::new()).await?,
                )?);
            }
            "compact" => {
                let keep = match &request["keep"] {
                    Value::Null => 0,
                    keep => keep
                        .as_u64()
                        .and_then(|keep| usize::try_from(keep).ok())
                        .ok_or_else(|| refused("keep must be a non-negative number"))?,
                };
                let report = self.replica.compact(scope, keep).await?;
                self.list_checkpoints(scope).await?;
                self.replica.drop_unrequired_schemas().await?;
                self.observations.touch();
                let blocked = report
                    .blocked
                    .iter()
                    .map(|(scope, block)| {
                        Ok(TipPruneBlock {
                            scope: serde_json::to_string(scope)?,
                            reason: format!("{block:?}"),
                        })
                    })
                    .collect::<Result<_, Failure>>()?;
                return Ok(serde_json::to_value(
                    self.compaction(scope, report.pruned, blocked).await?,
                )?);
            }
            "seal" => {
                let close = match &request["close"] {
                    Value::Null => false,
                    Value::Bool(close) => *close,
                    _ => return Err(refused("close must be a boolean")),
                };
                self.seal_followed(scope, close).await?;
            }
            "recover" => self.recover_followed(scope).await?,
            "pull" => {
                self.replica
                    .want_seal(scope, digest(request, "seal")?)
                    .await
                    .map_err(refused)?;
                self.wake_sync();
            }
            "open" => {
                let minimum = request["minimum_in_sync"]
                    .as_u64()
                    .and_then(|minimum| u32::try_from(minimum).ok())
                    .ok_or_else(|| refused("minimum_in_sync must be a positive number"))?;
                let tip = self
                    .open_tip(scope, digest(request, "seal")?, minimum)
                    .await?;
                return Ok(json!({"tip": hex(&tip.0)}));
            }
            "genesis_minimum" => {
                let minimum = request["minimum_in_sync"]
                    .as_u64()
                    .and_then(|minimum| u32::try_from(minimum).ok())
                    .ok_or_else(|| refused("minimum_in_sync must be a positive number"))?;
                self.sign_genesis_minimum(scope, minimum).await?;
            }
            "create" => {
                let tip = match request.get("tip") {
                    None | Some(Value::Null) => None,
                    Some(_) => Some(TipId(digest(request, "tip")?)),
                };
                self.create_bookmark(scope, text(request, "name")?, tip)
                    .await?;
            }
            "move" => {
                let tip = TipId(digest(request, "tip")?);
                self.move_bookmark(scope, text(request, "name")?, Some(tip))
                    .await?;
            }
            "delete" => {
                self.move_bookmark(scope, text(request, "name")?, None)
                    .await?;
            }
            "follow_when_ready" => {
                let name = text(request, "name")?;
                let inspection = self.inspect_tips(scope).await?;
                if !inspection
                    .bookmarks
                    .iter()
                    .any(|bookmark| bookmark.name == name && bookmark.tip.is_some())
                {
                    return Err(refused("unknown or deleted bookmark"));
                }
                self.configure(|settings| {
                    settings.pending_follow = Some(name.into());
                    Ok(())
                })
                .await?;
                self.complete_pending_follow().await?;
                self.wake_sync();
            }
            "follow" => {
                let before = self.replica.followed_tip().await;
                self.replica
                    .follow_bookmark(scope, text(request, "name")?)
                    .await
                    .map_err(refused)?;
                self.configure(|settings| {
                    settings.pending_follow = None;
                    Ok(())
                })
                .await?;
                self.followed_tip_changed(before).await;
                self.ensure_tip_node().await?;
                self.observations.touch();
            }
            "drop" => {
                self.replica
                    .drop_tip(TipId(digest(request, "tip")?))
                    .await
                    .map_err(refused)?;
                self.observations.touch();
            }
            "trust" => {
                let identity: PublicKey = text(request, "identity")?
                    .parse()
                    .map_err(|_| refused("identity must be a hex key"))?;
                let registry = self.registry().await?;
                let link = self
                    .settings
                    .lock()
                    .await
                    .issue_trust(&self.vault, &registry, identity)
                    .map_err(refused)?;
                return Ok(json!({
                    "identity": identity.to_hex(),
                    "capability": hex(&link.id()?),
                    "grant": HEXLOWER.encode(&rocky_credentials::encode(&link)?),
                }));
            }
            "install_trust" => {
                let link = HEXLOWER
                    .decode(text(request, "grant")?.as_bytes())
                    .ok()
                    .and_then(|bytes| {
                        rocky_credentials::decode_bounded::<rocky_credentials::SignedCapability>(
                            &bytes,
                            rocky_credentials::MAX_CREDENTIAL_BYTES,
                        )
                        .ok()
                    })
                    .ok_or_else(|| refused("grant must be a hex trusted grant"))?;
                let mut settings = self.settings.lock().await;
                let mut draft = (**settings).clone();
                draft.install_trust(&self.path, link).map_err(refused)?;
                *settings = Shared::new(draft);
                drop(settings);
                self.observations.touch();
            }
            _ => return Err(refused("unknown tips action")),
        }
        Ok(serde_json::to_value(self.tip_status(scope).await?)?)
    }

    pub(super) async fn complete_pending_follow(&self) -> Result<(), Failure> {
        let Some(name) = self.settings.lock().await.pending_follow.clone() else {
            return Ok(());
        };
        let scope = self.domain().scope;
        let inspection = self.inspect_tips(scope).await?;
        let Some(tip) = inspection
            .bookmarks
            .iter()
            .find(|bookmark| bookmark.name == name)
            .and_then(|bookmark| bookmark.tip.as_ref())
        else {
            self.configure(|settings| {
                settings.pending_follow = None;
                Ok(())
            })
            .await?;
            self.activity.record(
                "bookmark_follow_failed",
                json!({"name": name, "reason": "deleted"}),
            );
            return Ok(());
        };
        let seal = inspection
            .seals
            .iter()
            .find(|seal| seal.id == *tip && seal.canonical && !seal.revoked)
            .or_else(|| {
                inspection
                    .openings
                    .iter()
                    .find(|opening| opening.id == *tip)
                    .and_then(|opening| {
                        inspection
                            .seals
                            .iter()
                            .find(|seal| seal.id == opening.seal && seal.canonical && !seal.revoked)
                    })
            });
        if let Some(seal) = seal
            && seal.held.is_none()
        {
            let digest = HEXLOWER
                .decode(seal.id.as_bytes())?
                .try_into()
                .map_err(|_| refused("invalid seal digest"))?;
            self.replica.want_seal(scope, digest).await?;
            return Ok(());
        }
        let before = self.replica.followed_tip().await;
        self.replica.follow_bookmark(scope, &name).await?;
        self.configure(|settings| {
            if settings.pending_follow.as_deref() == Some(&name) {
                settings.pending_follow = None;
            }
            Ok(())
        })
        .await?;
        self.followed_tip_changed(before).await;
        self.ensure_tip_node().await?;
        self.observations.touch();
        Ok(())
    }

    async fn tip_status(&self, scope: Scope) -> Result<TipStatus, Failure> {
        let observed = self.replica.tip_observation(scope).await?;
        Ok(TipStatus {
            bookmark: observed.bookmark,
            pending_follow: self.settings.lock().await.pending_follow.clone(),
            tip: hex(&observed.tip.0),
            operations_since_seal: observed.operations_since_seal,
            evidence_releasable: None,
            devices: observed
                .devices
                .into_iter()
                .map(|device| {
                    Ok(TipDevice {
                        node: device.node.to_hex(),
                        tip: device.tip.map(|tip| hex(&tip.0)),
                        frontiers: device
                            .frontiers
                            .into_iter()
                            .map(|frontier| {
                                Ok(TipScopeFrontier {
                                    scope: serde_json::to_string(&frontier.scope)?,
                                    logs: frontier
                                        .logs
                                        .into_iter()
                                        .map(|log| TipFrontierLog {
                                            author: log.author.to_hex(),
                                            held: log.held,
                                            applied: log.applied,
                                        })
                                        .collect(),
                                })
                            })
                            .collect::<Result<_, Failure>>()?,
                    })
                })
                .collect::<Result<_, Failure>>()?,
        })
    }

    async fn compaction(
        &self,
        scope: Scope,
        pruned: u64,
        blocked: Vec<TipPruneBlock>,
    ) -> Result<TipCompaction, Failure> {
        let status = self.replica.compaction_status(scope).await?;
        Ok(TipCompaction {
            finalized: status.finalized.as_ref().map(hex),
            compacted: status.compacted.as_ref().map(hex),
            uncompacted: status.uncompacted.iter().map(hex).collect(),
            waiting: status.waiting,
            rebootstrap: status.rebootstrap.as_ref().map(hex),
            pruned,
            blocked,
        })
    }

    async fn kept_seals(&self) -> Result<KeptSeals, Failure> {
        let config = self.replica.kept_seal_config().await?;
        Ok(KeptSeals {
            bookmarked: config.bookmarked,
            latest: config.latest,
            every: config.every,
        })
    }

    async fn inspect_tips(&self, scope: Scope) -> Result<TipInspection, Failure> {
        let graph = self.replica.tip_graph(scope).await?;
        let mut held = std::collections::BTreeMap::new();
        for seal in &graph.seals {
            let id = seal.id()?;
            if let Some(how) = self.replica.held_seal(scope, id).await? {
                held.insert(id, how);
            }
        }
        let seals = graph
            .seals
            .iter()
            .map(|seal| {
                let statement = &seal.statement;
                Ok(TipSeal {
                    id: hex(&seal.id()?),
                    tip: hex(&statement.tip.0),
                    frontier: statement
                        .frontier
                        .iter()
                        .map(|mark| TipAuthorMark {
                            author: mark.author,
                            sequence: mark.sequence,
                        })
                        .collect(),
                    action: match statement.action {
                        SealAction::Continue { .. } => "continue",
                        SealAction::Close => "close",
                    }
                    .into(),
                    schema: match statement.action {
                        SealAction::Continue { schema } => Some(hex(&schema)),
                        SealAction::Close => None,
                    },
                    canonical: graph.seal(statement.tip)? == Some(seal),
                    authority: authority(graph.authority(seal.endorsement())),
                    revoked: graph.revoked.contains(&seal.id()?),
                    finalized: graph.is_final(seal.id()?)?,
                    checkpoints: graph
                        .checkpoints_at(seal.id()?)?
                        .into_iter()
                        .map(|record| {
                            Ok(TipCheckpoint {
                                id: hex(&record.id()?),
                                scope: serde_json::to_string(&record.statement.table)?,
                                checkpoint: hex(&record.statement.checkpoint),
                                signer: record.statement.signer.to_hex(),
                                authority: authority(graph.authority(record.endorsement())),
                                rows: record.statement.rows,
                            })
                        })
                        .collect::<Result<_, Failure>>()?,
                    held: held.get(&seal.id()?).map(|how| {
                        match how {
                            rocky_secure::HeldSeal::Kept => "kept",
                            rocky_secure::HeldSeal::Checkpoint => "checkpoint",
                            rocky_secure::HeldSeal::Live => "live",
                        }
                        .into()
                    }),
                    recovery: statement.recovery.map(|recovery| TipRecovery {
                        retained: recovery.retained.position,
                        replaced: recovery.replaced.position,
                    }),
                })
            })
            .collect::<Result<_, Failure>>()?;
        let openings = graph
            .openings
            .iter()
            .map(|opening| {
                Ok(TipOpening {
                    id: hex(&opening.id()?),
                    seal: hex(&opening.statement.seal),
                    schema: hex(&opening.statement.schema),
                    minimum_in_sync: opening.statement.minimum_in_sync,
                })
            })
            .collect::<Result<_, Failure>>()?;
        let names = graph
            .moves
            .iter()
            .map(|movement| movement.statement.name.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let bookmarks = names
            .into_iter()
            .map(|name| {
                Ok(Bookmark {
                    tip: graph.bookmark(&name)?.map(|tip| hex(&tip.0)),
                    moves: graph
                        .moves
                        .iter()
                        .filter(|movement| movement.statement.name == name)
                        .map(|movement| {
                            Ok(BookmarkMove {
                                id: hex(&movement.id()?),
                                from: movement.statement.from.map(|tip| hex(&tip.0)),
                                to: movement.statement.to.map(|tip| hex(&tip.0)),
                                authority: authority(graph.authority(movement.endorsement())),
                                revoked: graph.revoked.contains(&movement.id()?),
                            })
                        })
                        .collect::<Result<_, Failure>>()?,
                    losers: graph
                        .losing_moves(&name)?
                        .into_iter()
                        .enumerate()
                        .map(|(index, movement)| {
                            Ok(LosingMove {
                                name: format!("{name}/{}", index + 1),
                                movement: hex(&movement.id()?),
                                tip: movement.statement.to.map(|tip| hex(&tip.0)),
                            })
                        })
                        .collect::<Result<_, Failure>>()?,
                    name,
                })
            })
            .collect::<Result<_, Failure>>()?;
        let nodes = self
            .replica
            .tip_nodes(scope)
            .await?
            .into_iter()
            .map(|node| TipNode {
                node: node.node.to_hex(),
                followed_tip: node.followed_tip.map(|tip| hex(&tip.0)),
                kept_tips: node
                    .kept_tips
                    .map(|tips| tips.iter().map(|tip| hex(&tip.0)).collect()),
                kept_seals: node.kept_seals.map(|seals| seals.iter().map(hex).collect()),
            })
            .collect();
        Ok(TipInspection {
            scope: serde_json::to_string(&scope)?,
            genesis: hex(&graph.genesis().0),
            schema: hex(&graph.genesis_schema),
            genesis_minimum: graph
                .line_minimum(graph.genesis())?
                .and_then(|minimum| u32::try_from(minimum).ok()),
            seals,
            openings,
            bookmarks,
            nodes,
        })
    }

    /// A device on another tip syncs again soon; the next pass retries the
    /// peers whose links refused the earlier tip.
    async fn followed_tip_changed(&self, before: TipId) {
        if self.replica.followed_tip().await != before {
            self.wake_sync();
        }
    }

    /// Lists this device's checkpoints at seals in the graph when it may
    /// sign tip statements, so devices whose compacted seal lost can
    /// rebootstrap from them.
    pub(super) async fn list_checkpoints(&self, scope: Scope) -> Result<(), Failure> {
        let unlisted = self.replica.unlisted_checkpoints(scope).await?;
        if unlisted.is_empty() {
            return Ok(());
        }
        let Ok(signer) = self.tip_signer(scope).await else {
            return Ok(());
        };
        let records = unlisted
            .into_iter()
            .map(|statement| {
                Ok(TipStatement::Checkpoint(Box::new(
                    rocky_credentials::SignedCheckpointRecord::endorse(
                        statement,
                        &*signer.identity,
                        &signer.links,
                    )?,
                )))
            })
            .collect::<Result<Vec<_>, Failure>>()?;
        self.replica.publish_tip_statements(&records).await?;
        self.wake_sync();
        Ok(())
    }

    /// The owner signs as itself, a trusted identity through its trusted
    /// grant and an issuer through its issuer links.
    pub(super) async fn tip_signer(&self, scope: Scope) -> Result<Signer, Failure> {
        let settings = self.settings.lock().await.clone();
        let identity = settings.identity(&self.vault)?;
        let links = settings.identity_links();
        let trusted =
            links.0.len() == 1 && links.0[0].capability.extended()?.trusted == Some(scope);
        let (links, opens) = if settings.owner() {
            (CredentialChain::default(), true)
        } else if let Some(trusted) = settings.trusted_links() {
            (trusted, true)
        } else if trusted {
            (links, true)
        } else if settings.issuer() {
            (settings.issuer_links(), false)
        } else {
            return Err(refused(
                "only the owner, a trusted identity or an issuer signs tip statements",
            ));
        };
        Ok(Signer {
            identity,
            links,
            opens,
        })
    }

    /// Publishes `statements` once they have the effect `expected` checks
    /// on the graph they extend; a statement that would lose to a lower
    /// digest is refused rather than published.
    async fn publish_tips(
        &self,
        scope: Scope,
        statements: Vec<TipStatement>,
        expected: impl FnOnce(&TipGraph) -> Result<(), Failure>,
    ) -> Result<(), Failure> {
        let mut graph = self.replica.tip_graph(scope).await?;
        for statement in &statements {
            statement.append(&mut graph);
        }
        expected(&graph)?;
        // The replica's codes stay: `sealed`, `coordinator_unavailable`.
        let before = self.replica.followed_tip().await;
        self.prepare_terminal_credentials().await?;
        let published = self.replica.publish_tip_statements(&statements).await;
        self.wake_sync();
        published?;
        self.finalize_seals().await;
        self.followed_tip_changed(before).await;
        // A move of the followed bookmark may have switched lines.
        self.ensure_tip_node().await?;
        self.observations.touch();
        Ok(())
    }

    pub(super) fn bookmark_move(
        signer: &Signer,
        scope: Scope,
        name: &str,
        from: Option<TipId>,
        to: Option<TipId>,
    ) -> Result<TipStatement, Failure> {
        Ok(TipStatement::Bookmark(SignedBookmarkMove::endorse(
            BookmarkMoveStatement {
                format: BOOKMARK_MOVE_FORMAT,
                scope,
                name: name.into(),
                from,
                to,
            },
            &*signer.identity,
            &signer.links,
        )?))
    }

    /// Seals the followed tip at its locally known frontier. The tip
    /// leaving through the move, `tip`, must be the followed one.
    async fn seal_statement(
        &self,
        signer: &Signer,
        scope: Scope,
        tip: TipId,
        close: bool,
    ) -> Result<SignedSeal, Failure> {
        let graph = self.replica.tip_graph(scope).await?;
        if self.replica.followed_tip().await != tip {
            return Err(refused(
                "only a device following a tip seals it; follow its bookmark first",
            ));
        }
        if graph.seal(tip)?.is_some() {
            return Err(refused("this tip is already sealed"));
        }
        let action = if close {
            SealAction::Close
        } else {
            SealAction::Continue {
                schema: graph.schema(tip)?,
            }
        };
        let frontier = self
            .replica
            .seal_frontier(scope, close)
            .await
            .map_err(refused)?;
        Ok(SignedSeal::endorse(
            SealStatement {
                format: SEAL_FORMAT,
                scope,
                tip,
                frontier,
                action,
                recovery: None,
            },
            &*signer.identity,
            &signer.links,
        )?)
    }

    /// `continue` seals the followed tip and moves its bookmark on, in one
    /// batch; `close` ends it and leaves the bookmark read-only.
    pub(super) async fn seal_followed(&self, scope: Scope, close: bool) -> Result<(), Failure> {
        let (followed, name) = self
            .replica
            .followed_bookmark()
            .await
            .filter(|(followed, _)| *followed == scope)
            .ok_or_else(|| refused("follow a bookmark before sealing"))?;
        let tip = self.replica.followed_tip().await;
        if self.replica.tip_graph(followed).await?.bookmark(&name)? != Some(tip) {
            return Err(refused(
                "the followed bookmark no longer points to the followed tip",
            ));
        }
        let signer = self.tip_signer(scope).await?;
        // Records for transactions only this replica holds whole let the
        // seal cover them.
        self.replica.publish_missing_outcomes().await?;
        let seal = self.seal_statement(&signer, scope, tip, close).await?;
        let mut statements = vec![TipStatement::Seal(seal.clone())];
        let successor = seal.successor()?;
        if let Some(next) = successor {
            statements.push(Self::bookmark_move(
                &signer,
                scope,
                &name,
                Some(tip),
                Some(next),
            )?);
        }
        self.publish_tips(scope, statements, |graph| {
            if graph.bookmark(&name)? != successor.or(Some(tip)) {
                return Err(refused("another move of this bookmark takes precedence"));
            }
            Ok(())
        })
        .await
    }

    /// Seals the followed bookmark and makes the seal this node's listed
    /// base, after a revocation or once writes of an earlier key epoch
    /// arrived past the last seal: members, which refuse a revoked author's
    /// frames and get only the current epoch, import those rows with it.
    pub(super) async fn seal_for_members(&self) -> Result<(), Failure> {
        let scope = self.domain().scope;
        if self.replica.followed_bookmark().await.is_none() || self.tip_signer(scope).await.is_err()
        {
            return Ok(());
        }
        self.seal_followed(scope, false).await?;
        self.replica.compact(scope, 0).await?;
        self.list_checkpoints(scope).await
    }

    /// The owner recovers the followed tip when no ordinary seal can end its
    /// log: it seals the tip with `continue`, replacing the log's exact
    /// head. Bookmarks on the tip follow the seal.
    async fn recover_followed(&self, scope: Scope) -> Result<(), Failure> {
        let settings = self.settings.lock().await.clone();
        if !settings.owner() {
            return Err(refused("only the owner recovers a stuck tip"));
        }
        let coordinator = self
            .replica
            .domain_log()
            .ok_or_else(|| refused("recovering needs this device's coordinated log composed"))?;
        let tip = self.replica.followed_tip().await;
        let graph = self.replica.tip_graph(scope).await?;
        if graph.seal(tip)?.is_some() {
            return Err(refused("this tip is already sealed"));
        }
        let log = rocky_core::TipLog { scope, tip };
        if graph.line_minimum(tip)?.is_none() {
            return Err(refused(
                "set the genesis line's owner-signed minimum before recovery",
            ));
        }
        let recovery = self
            .replica
            .recovery_proposal(log, coordinator.as_ref())
            .await?;
        let frontier = self
            .replica
            .seal_frontier(scope, false)
            .await
            .map_err(refused)?;
        let identity = settings.identity(&self.vault)?;
        let seal = SignedSeal::sign(
            SealStatement {
                format: SEAL_FORMAT,
                scope,
                tip,
                frontier,
                action: SealAction::Continue {
                    schema: graph.schema(tip)?,
                },
                recovery: Some(recovery),
            },
            &*identity,
        )?;
        let id = seal.id()?;
        self.publish_tips(scope, vec![TipStatement::Seal(seal)], |graph| {
            match graph.seal(tip)? {
                Some(winner) if winner.id()? == id => Ok(()),
                _ => Err(refused("another seal of this tip takes precedence")),
            }
        })
        .await
    }

    /// The owner signs the minimum of trusted acknowledgments that makes a
    /// seal on the genesis line final.
    async fn sign_genesis_minimum(&self, scope: Scope, minimum: u32) -> Result<(), Failure> {
        let settings = self.settings.lock().await.clone();
        if !settings.owner() {
            return Err(refused("only the owner signs the genesis line's minimum"));
        }
        let identity = settings.identity(&self.vault)?;
        let line = SignedGenesisLine::sign(
            GenesisLineStatement {
                format: GENESIS_LINE_FORMAT,
                scope,
                minimum_in_sync: minimum,
            },
            &*identity,
        )?;
        self.publish_tips(scope, vec![TipStatement::GenesisLine(line)], |_| Ok(()))
            .await
    }

    async fn prepare_terminal_credentials(&self) -> Result<(), Failure> {
        if self.replica.domain_log().is_none() {
            return Ok(());
        }
        let settings = self.settings.lock().await.clone();
        let Some(links) = settings.trusted_links() else {
            return Ok(());
        };
        let author = self.replica.terminal_author().await?;
        let identity = settings.identity(&self.vault)?;
        let chain = settings.certify_node(&*identity, links, &self.domain(), author)?;
        self.replica.install_terminal_credentials(chain).await?;
        Ok(())
    }

    /// On a trusted node with a composed log, ends the logs of journaled
    /// seals, acknowledges the terminal entries of
    /// its line and publishes the finality records they reach. A failure
    /// leaves the seals to the next call.
    pub(super) async fn finalize_seals(&self) {
        if self.replica.domain_log().is_some() {
            if let Err(error) = self.prepare_terminal_credentials().await {
                self.activity.record(
                    "terminal_credentials_failed",
                    json!({"error":error.to_string()}),
                );
            }
            let before = self.replica.followed_tip().await;
            match self.replica.settle_tip_statements().await {
                Ok(0) => {}
                Ok(_) => {
                    self.followed_tip_changed(before).await;
                    if let Err(error) = self.ensure_tip_node().await {
                        self.activity
                            .record("line_node_failed", json!({"error": error.to_string()}));
                    }
                    self.observations.touch();
                }
                Err(error) => {
                    self.activity.record(
                        "seal_settlement_failed",
                        json!({"error": error.to_string()}),
                    );
                }
            }
            match self.replica.finalize_seals(self.domain().scope).await {
                Ok(0) => {}
                Ok(_) => self.observations.touch(),
                Err(error) => {
                    self.activity
                        .record("finality_failed", json!({"error": error.to_string()}));
                }
            }
        }
        if let Err(error) = self.compact_final_seal().await {
            self.activity.record(
                "final_compaction_failed",
                json!({"error": error.to_string()}),
            );
        }
    }

    /// Finality permits automatic compaction; nonfinal seals still require
    /// the application's compact call (or migration completion).
    async fn compact_final_seal(&self) -> Result<(), Failure> {
        let scope = self.domain().scope;
        let graph = self.replica.tip_graph(scope).await?;
        if graph.finalities.is_empty() {
            return Ok(());
        }
        self.replica.finalize_path(scope).await?;
        let status = self.replica.compaction_status(scope).await?;
        let Some(seal) = status.finalized else {
            return Ok(());
        };
        if !graph.is_final(seal)? {
            return Ok(());
        }
        if status.compacted != Some(seal) || self.replica.needs_base_at(scope, seal).await? {
            self.replica.compact(scope, 0).await?;
        }
        self.list_checkpoints(scope).await?;
        Ok(())
    }

    /// Opens a tip on `seal`; only the owner and trusted identities may.
    async fn open_tip(
        &self,
        scope: Scope,
        seal: rocky_core::Commitment,
        minimum_in_sync: u32,
    ) -> Result<TipId, Failure> {
        let graph = self.replica.tip_graph(scope).await?;
        let parent = graph.seal_by_id(seal).map_err(refused)?;
        let schema = graph.schema(parent.statement.tip).map_err(refused)?;
        let signer = self.tip_signer(scope).await?;
        if !signer.opens {
            return Err(refused("only the owner or a trusted identity opens tips"));
        }
        // A branch starts from the seal's state, which this device must hold.
        self.replica.finalize_path(scope).await?;
        if self.replica.held_seal(scope, seal).await?.is_none() {
            return Err(refused(
                "this device does not hold the seal's state; pull it from a device that keeps it with the tips action pull, or seal now",
            ));
        }
        let opening = SignedTipOpening::endorse(
            TipOpeningStatement {
                format: TIP_OPENING_FORMAT,
                schema,
                scope,
                seal,
                minimum_in_sync,
            },
            &*signer.identity,
            &signer.links,
        )?;
        let tip = opening.tip()?;
        self.publish_tips(scope, vec![TipStatement::Opening(opening)], |_| Ok(()))
            .await?;
        Ok(tip)
    }

    /// Creates `name` on `tip`, by default the followed tip.
    async fn create_bookmark(
        &self,
        scope: Scope,
        name: &str,
        tip: Option<TipId>,
    ) -> Result<(), Failure> {
        let graph = self.replica.tip_graph(scope).await?;
        if graph.bookmark(name)?.is_some() {
            return Err(refused("this bookmark exists; move it instead"));
        }
        let tip = match tip {
            Some(tip) => tip,
            None => self.replica.followed_tip().await,
        };
        let target = graph.canonical_tip(tip).map_err(refused)?;
        let signer = self.tip_signer(scope).await?;
        let statement = Self::bookmark_move(&signer, scope, name, None, Some(tip))?;
        self.publish_tips(scope, vec![statement], |graph| {
            if graph.bookmark(name)? != Some(target) {
                return Err(refused(
                    "this bookmark name was used before; choose another name",
                ));
            }
            Ok(())
        })
        .await
    }

    /// Moves `name` to `to`, or deletes it. Moving backward or sideways
    /// off an open tip closes that tip in the same batch.
    async fn move_bookmark(
        &self,
        scope: Scope,
        name: &str,
        to: Option<TipId>,
    ) -> Result<(), Failure> {
        let graph = self.replica.tip_graph(scope).await?;
        let from = graph
            .bookmark(name)?
            .ok_or_else(|| refused("this bookmark does not exist"))?;
        let target = to
            .map(|tip| graph.canonical_tip(tip))
            .transpose()
            .map_err(refused)?;
        if target == Some(from) {
            return Err(refused("the bookmark already points to this tip"));
        }
        let signer = self.tip_signer(scope).await?;
        let mut statements = Vec::new();
        if let Some(to) = to
            && !graph.continues_any(from, to)?
            && graph.seal(from)?.is_none()
        {
            let close = self.seal_statement(&signer, scope, from, true).await?;
            statements.push(TipStatement::Seal(close));
        }
        statements.push(Self::bookmark_move(&signer, scope, name, Some(from), to)?);
        self.publish_tips(scope, statements, |graph| {
            if graph.bookmark(name)? != target {
                return Err(refused("another move of this bookmark takes precedence"));
            }
            Ok(())
        })
        .await
    }
}
