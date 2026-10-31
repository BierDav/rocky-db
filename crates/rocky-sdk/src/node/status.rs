use super::*;
use crate::status::*;

impl Node {
    pub(super) fn status_time(&self) -> Result<u64, Failure> {
        #[cfg(test)]
        if let Some((time, anchor)) = *self
            .status_clock
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
        {
            return Ok(time.saturating_add(anchor.elapsed().as_secs()));
        }
        now()
    }
    pub(super) fn observed_scope(&self, scope: ResourceScope) -> crate::ScopeStatus {
        let domain = self.domain();
        let root = domain.scopes().find(|(_, root)| root.table == scope.table);
        crate::ScopeStatus {
            table: root.map(|(name, _)| name.to_owned()),
            table_id: HEXLOWER.encode(&scope.table),
            encryption: HEXLOWER.encode(&scope.encryption),
            partition: root.is_some_and(|(_, root)| root != scope),
        }
    }
    pub(super) async fn observed_peers(&self) -> Result<Vec<crate::Peer>, Failure> {
        let observations = self.observations.snapshot();
        let mut peers = Vec::new();
        for value in self.peers().await {
            let node = value["node"]
                .as_str()
                .ok_or("missing peer node")?
                .to_owned();
            let link = &value["link"];
            fn count(value: &Value, key: &str) -> Result<u64, Failure> {
                Ok(value[key].as_str().ok_or("missing path count")?.parse()?)
            }
            let paths = link["paths"]
                .as_array()
                .ok_or("missing paths")?
                .iter()
                .map(|path| {
                    Ok(crate::LinkPath {
                        selected: path["selected"].as_bool().ok_or("missing selected path")?,
                        kind: path["kind"].as_str().ok_or("missing path kind")?.into(),
                        remote: path["remote"].as_str().ok_or("missing remote path")?.into(),
                        local: path["local"].as_str().map(str::to_owned),
                        round_trip_micros: count(path, "rtt_us")?,
                        mtu: u32::try_from(count(path, "mtu")?)?,
                        window: count(path, "window")?,
                        sent_bytes: count(path, "sent_bytes")?,
                        sent_datagrams: count(path, "sent_datagrams")?,
                        received_bytes: count(path, "received_bytes")?,
                        received_datagrams: count(path, "received_datagrams")?,
                        lost_packets: count(path, "lost_packets")?,
                        lost_bytes: count(path, "lost_bytes")?,
                        congestion_events: count(path, "congestion_events")?,
                    })
                })
                .collect::<Result<Vec<_>, Failure>>()?;
            let key: PublicKey = node.parse()?;
            let retry = self
                .retries
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&key)
                .map(|retry| RetryStatus {
                    pending: retry.pending,
                    reconciliation_retry_at_epoch_millis: retry.retry.deadline_epoch_millis(),
                    link_retry_at_epoch_millis: retry.link_retry.deadline_epoch_millis(),
                });
            peers.push(crate::Peer {
                node: node.clone(),
                is_issuer: value["issuer"].as_bool().ok_or("missing issuer")?,
                is_configured: value["configured"]
                    .as_bool()
                    .ok_or("missing configured peer")?,
                source: value["source"]
                    .as_str()
                    .ok_or("missing peer source")?
                    .into(),
                choice: value["choice"]
                    .as_str()
                    .ok_or("missing peer choice")?
                    .into(),
                routes: serde_json::from_value(value["routes"].clone())?,
                is_local: value["local"].as_bool().ok_or("missing locality")?,
                link: PeerLink {
                    state: serde_json::from_value(link["state"].clone())?,
                    opened_at_epoch_seconds: link["opened"].as_str().map(str::parse).transpose()?,
                    round_trip_millis: link["round_trip_ms"]
                        .as_str()
                        .map(str::parse)
                        .transpose()?,
                    paths,
                },
                attempts: observations
                    .iter()
                    .filter(|attempt| attempt.target == node)
                    .cloned()
                    .collect(),
                last_authenticated_exchange_at_epoch_seconds: self
                    .met
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(&key)
                    .copied(),
                retry,
                last_sync: self
                    .last_syncs
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(&node)
                    .cloned(),
            });
        }
        Ok(peers)
    }
    pub(super) async fn observed_network(&self) -> Result<crate::NetworkStatus, Failure> {
        let service = self.current();
        let discovery = self.discovery_status();
        let path = |name: &str| -> Result<DiscoveryPath, Failure> {
            let path = &discovery["paths"][name];
            Ok(DiscoveryPath {
                state: serde_json::from_value(path["state"].clone())?,
                reason: path["reason"].as_str().map(str::to_owned),
            })
        };
        let peers = self.observed_peers().await?;
        let connected_peer_count = peers
            .iter()
            .filter(|peer| peer.link.state == LinkState::Open)
            .count() as u64;
        Ok(crate::NetworkStatus {
            attachment: match &service {
                None => AttachmentState::Detached,
                Some(service) if *service.stage.borrow() != Stage::Open => {
                    AttachmentState::Draining
                }
                Some(_) => AttachmentState::Attached,
            },
            kind: service
                .as_ref()
                .map(|service| service.transport.kind().into()),
            ownership: service.as_ref().map(|service| {
                if service.owned {
                    NetworkOwnership::Rocky
                } else {
                    NetworkOwnership::Application
                }
            }),
            networking_enabled: self.online.load(Ordering::SeqCst),
            foreground: self.foreground.load(Ordering::SeqCst),
            worker_enabled: self.automatic.load(Ordering::SeqCst),
            worker_running: *self.worker_running.borrow(),
            reconciling: *self.sync_state.borrow() != "idle",
            inbound: service.as_ref().map(|service| InboundStatus {
                active: (INBOUND - service.active.available_permits()) as u64,
                limit: INBOUND as u64,
                served: service.served.load(Ordering::Relaxed),
                refused: service.refused.load(Ordering::Relaxed),
            }),
            peers,
            connected_peer_count,
            contact_resolutions: self
                .observations
                .snapshot()
                .into_iter()
                .filter(|attempt| attempt.operation == AttemptOperation::ResolveContact)
                .collect(),
            discovery: DiscoveryStatus {
                announcing: discovery["announcing"]
                    .as_bool()
                    .ok_or("missing announcement state")?,
                local: path("local")?,
                topic: path("topic")?,
            },
            last_reconciliation: self
                .last_reconciliation
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
            relay: RelayObservation {
                initial_configuration: service
                    .as_ref()
                    .and_then(|service| service.transport.initial_relay_configuration()),
                relays: service
                    .as_ref()
                    .and_then(|service| service.transport.relays())
                    .map(|relays| {
                        relays
                            .into_iter()
                            .map(|relay| crate::RelayStatus {
                                url: relay.url,
                                connected: relay.connected,
                                last_error: relay.last_error,
                                auth_denied_reason: relay.auth_denied_reason,
                            })
                            .collect()
                    }),
            },
        })
    }
    pub(super) async fn observed_status(&self) -> Result<DatabaseStatus, Failure> {
        let settings = self.settings.lock().await.clone();
        let generation = self.replica.generations().await?;
        let mut imports = Vec::new();
        for scope in self.scopes() {
            let staging = self.replica.rebootstrap_progress(scope).await?;
            imports.push(ScopeImportStatus {
                scope: self.observed_scope(scope),
                checkpoint: staging.map(|(id, _, _)| HEXLOWER.encode(&id)),
                cursor: staging
                    .and_then(|(_, cursor, _)| cursor.map(|cursor| HEXLOWER.encode(&cursor))),
                pages_complete: staging.map(|(_, _, complete)| complete),
            });
        }
        let bootstrap_pending = self.path.with_file_name("bootstrap.json").exists()
            || imports.iter().any(|scope| scope.checkpoint.is_some());
        let renewal_routes = settings.renewal_routes();
        let profile = serde_json::to_value(&settings.profile)?;
        // Drop the watch read guard before any replica calls can publish a commit.
        let revision = *self.replica.observe_revision().borrow();
        let mut status = DatabaseStatus {
            token: String::new(),
            observed_at_epoch_millis: epoch_millis(),
            authority: AuthorityStatus {
                principal: settings.identity.to_hex(),
                node: self
                    .node_identity
                    .clone()
                    .map_err(|error| -> Failure { error.into() })?,
                is_issuer: settings.issuer(),
                expires_at_epoch_seconds: settings.expires(),
                expired: settings.expires() <= self.status_time()?,
                logged_out: self.ended.lock().await.is_some() || settings.logged_out,
                verified_revocation: settings
                    .revocation(&self.path)?
                    .map(|notice| {
                        Ok::<_, Failure>(VerifiedRevocation {
                            id: HEXLOWER.encode(&notice.id()?),
                            statement: serde_json::to_vec(&notice)?,
                        })
                    })
                    .transpose()?,
                revocations: serde_json::from_value(settings.revocation_status()?)?,
                profile: AuthorityProfile {
                    kind: profile["kind"]
                        .as_str()
                        .ok_or("missing grant profile kind")?
                        .into(),
                    scopes: profile
                        .get("scopes")
                        .map(|scopes| serde_json::from_value(scopes.clone()))
                        .transpose()?
                        .unwrap_or_default(),
                    grants: profile
                        .get("grants")
                        .map(|grants| serde_json::from_value(grants.clone()))
                        .transpose()?
                        .unwrap_or_default(),
                },
                renewal_routes,
            },
            data: DataStatus {
                revision,
                generation: crate::GenerationStatus {
                    manifest: HEXLOWER.encode(&generation.manifest),
                    current: crate::Generation {
                        schema: generation.current.schema,
                    },
                    pending: self.replica.pending_schema().await?.map(|pending| {
                        PendingGeneration {
                            tip: HEXLOWER.encode(&pending.tip.0),
                            manifest: HEXLOWER.encode(&pending.manifest),
                        }
                    }),
                    application: self.application(&settings).await?,
                    migration: self.migration(&settings).await?,
                    waiting_for_issuer: !settings.issuer()
                        && self.application(&settings).await? == crate::DeclaredSchema::Ahead,
                    rebuilding: generation.plan.map(|plan| RebuildProgress {
                        schema: HEXLOWER.encode(&plan.schema),
                        tables: plan.tables as u64,
                    }),
                },
                blockers: self.blockers().await?,
                bootstrap_pending,
                bootstrap: serde_json::from_value(self.bootstrap_progress().await?)?,
                imports,
                key_epochs: settings
                    .keys
                    .iter()
                    .map(|(collection, epochs)| KeyEpochStatus {
                        collection: collection.clone(),
                        epochs: epochs
                            .iter()
                            .map(|epoch| EncryptionEpoch {
                                generation: epoch.generation,
                                secret_hash: HEXLOWER.encode(&epoch.secret_hash),
                            })
                            .collect(),
                        current: epochs.iter().max().map(|epoch| EncryptionEpoch {
                            generation: epoch.generation,
                            secret_hash: HEXLOWER.encode(&epoch.secret_hash),
                        }),
                    })
                    .collect(),
            },
            network: self.observed_network().await?,
            coordination: CoordinationStatus {
                mode: if self.service.is_some() {
                    CoordinationMode::Service
                } else {
                    CoordinationMode::NotConfigured
                },
                attempts: self
                    .observations
                    .snapshot()
                    .into_iter()
                    .filter(|attempt| attempt.target == "coordinator")
                    .collect(),
            },
        };
        let mut token_status = status.clone();
        token_status.observed_at_epoch_millis = None;
        for peer in &mut token_status.network.peers {
            peer.link.paths.clear();
            peer.link.round_trip_millis = None;
        }
        status.token = HEXLOWER
            .encode(&commitment("rocky.sdk.status.v2", &serde_json::to_vec(&token_status)?)[..16]);
        Ok(status)
    }
}

impl Node {
    /// The replica's blockers and the bootstrap intent's: scopes it still
    /// imports and the inviter a joined device waits for.
    pub(crate) async fn blockers(&self) -> Result<Vec<rocky_core::Blocker>, Failure> {
        use rocky_core::{Blocker, BlockerKind, ClearsBy, domain_label, scope_label};
        let mut blockers = self.replica.blockers().await?;
        for ((peer, scope), failure) in self
            .sync_failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            blockers.push(Blocker {
                scope: scope_label(scope),
                kind: BlockerKind::SyncRequest {
                    refused: failure.refused,
                },
                clears_by: ClearsBy::Peer {
                    node: peer.to_hex(),
                },
                since: failure.since,
            });
        }
        let marker = self.path.with_file_name("bootstrap.json");
        let intent: Value = match std::fs::read(&marker) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(blockers),
            Err(error) => return Err(error.into()),
        };
        let since = std::fs::metadata(&marker)
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|elapsed| elapsed.as_secs());
        for scope in self.bootstrap_pending(&intent).await.unwrap_or_default() {
            blockers.push(Blocker {
                scope: scope_label(&scope),
                kind: BlockerKind::BootstrapMarker,
                clears_by: ClearsBy::AnyPeer,
                since,
            });
        }
        if let Some(inviter) = intent.get("inviter").and_then(Value::as_str)
            && let Ok(key) = inviter.parse::<PublicKey>()
            && !self.settings.lock().await.revocations.revokes(&key)
        {
            blockers.push(Blocker {
                scope: domain_label(&self.domain().scope),
                kind: BlockerKind::AwaitingInviter,
                clears_by: ClearsBy::Peer {
                    node: inviter.to_owned(),
                },
                since,
            });
        }
        blockers.sort();
        Ok(blockers)
    }
    pub(super) fn skipped_peer(node: String, skip: SkipReason) -> PeerReconciliation {
        PeerReconciliation {
            node,
            skip: Some(skip),
            attempts: Vec::new(),
            transfers: Vec::new(),
            refused: Vec::new(),
            waiting: Vec::new(),
            upgrade_required: false,
            retry_pending: false,
            scopes: Vec::new(),
            timeouts: Vec::new(),
        }
    }
    pub(super) fn peer_reconciliation(
        &self,
        peer: PublicKey,
        result: &Result<(bool, sync::Transfer), Failure>,
        first_attempt_id: u64,
    ) -> PeerReconciliation {
        let node = peer.to_hex();
        let mut report = PeerReconciliation {
            node: node.clone(),
            skip: None,
            attempts: self
                .observations
                .snapshot()
                .into_iter()
                .filter(|attempt| attempt.target == node && attempt.id >= first_attempt_id)
                .collect(),
            transfers: Vec::new(),
            refused: Vec::new(),
            waiting: Vec::new(),
            upgrade_required: false,
            retry_pending: result.is_err(),
            scopes: Vec::new(),
            timeouts: Vec::new(),
        };
        report.timeouts = timeouts(&report.attempts);
        let partial = if result.is_err() {
            self.observations.partial_transfer(&node)
        } else {
            None
        };
        let transfer = match result {
            Ok((retry, transfer)) => {
                report.retry_pending = *retry;
                Some(transfer)
            }
            Err(_) => partial.as_ref(),
        };
        if let Some(transfer) = transfer {
            report.refused = transfer
                .refused
                .iter()
                .map(|scope| self.observed_scope(*scope))
                .collect();
            report.waiting = transfer
                .waiting
                .iter()
                .map(|scope| self.observed_scope(*scope))
                .collect();
            report.transfers = transfer
                .scopes
                .iter()
                .map(|(scope, moved)| ScopeReconciliationTransfer {
                    scope: self.observed_scope(*scope),
                    pulled: moved.pulled as u64,
                    pushed: moved.pushed as u64,
                    received_bytes: moved.bytes as u64,
                    sent_bytes: moved.sent as u64,
                    checkpoint: moved.checkpoint.map(|(id, _)| HEXLOWER.encode(&id)),
                    superseded: moved.checkpoint.map(|(_, rows)| rows),
                })
                .collect();
            report.scopes = scope_outcomes(transfer)
                .into_iter()
                .map(|(scope, outcome)| ScopeOutcome {
                    scope: self.observed_scope(scope),
                    outcome,
                })
                .collect();
        }
        report
    }
    pub(super) async fn reconciliation_pass(
        &self,
        transport: Option<&dyn Transport>,
        automatic: bool,
        retry_only: bool,
    ) -> Result<(ReconciliationReport, Value, bool), Failure> {
        let _syncing = self.syncing.lock().await;
        if let Some(statement) = self.settings.lock().await.revocation(&self.path)? {
            return Err(Box::new(crate::enrollment::Revoked(statement)));
        }
        let started_at_epoch_millis = epoch_millis();
        let first_attempt_id = self.observations.next_id();
        let peers = std::sync::Mutex::new(Vec::new());
        let skip = if !self.online.load(Ordering::SeqCst) {
            Some(SkipReason::NetworkingDisabled)
        } else if !self.foreground.load(Ordering::SeqCst) {
            Some(SkipReason::Suspended)
        } else {
            None
        };
        let result = if skip.is_some() {
            Ok((json!({"state":"idle"}), false))
        } else {
            let transport = transport.ok_or(ServiceError::NetworkRequired("sync"))?;
            let span = tracing::info_span!(
                "sync_pass",
                automatic,
                retry_only,
                peers = tracing::field::Empty,
                outcome = tracing::field::Empty
            );
            let result = tracing::Instrument::instrument(
                async {
                    let before = self.replica.followed_tip().await;
                    let result = self
                        .run_sync_pass(transport, automatic, retry_only, &peers, first_attempt_id)
                        .await;
                    // A pass that switched the followed tip syncs the new tip once more.
                    if result.is_ok() && self.replica.followed_tip().await != before {
                        self.run_sync_pass(
                            transport,
                            automatic,
                            retry_only,
                            &peers,
                            first_attempt_id,
                        )
                        .await
                    } else {
                        result
                    }
                },
                span.clone(),
            )
            .await;
            span.record(
                "peers",
                peers.lock().unwrap_or_else(PoisonError::into_inner).len() as u64,
            );
            span.record("outcome", if result.is_ok() { "ok" } else { "error" });
            result
        };
        // A received move may have switched this device to another line.
        if result.is_ok() {
            self.try_ensure_tip_node().await;
        }
        let peers = peers.into_inner().unwrap_or_else(PoisonError::into_inner);
        let report = ReconciliationReport {
            contact_resolutions: self
                .observations
                .snapshot()
                .into_iter()
                .filter(|attempt| {
                    attempt.operation == AttemptOperation::ResolveContact
                        && attempt.id >= first_attempt_id
                })
                .collect(),
            started_at_epoch_millis,
            ended_at_epoch_millis: epoch_millis(),
            skip,
            peers,
        };
        {
            let mut last = self
                .last_syncs
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for peer in report.peers.iter().filter(|peer| peer.skip.is_none()) {
                last.insert(peer.node.clone(), peer.clone());
            }
        }
        *self
            .last_reconciliation
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(report.clone());
        self.observations.touch();
        result.map(|(status, retry)| (report, status, retry))
    }
}

impl Node {
    pub(super) fn add_peer_report(
        reports: &std::sync::Mutex<Vec<PeerReconciliation>>,
        mut next: PeerReconciliation,
    ) {
        let mut reports = reports.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(prior) = reports.iter_mut().find(|prior| prior.node == next.node) {
            if next.skip.is_some() {
                return;
            }
            prior.skip = None;
            for attempt in next.attempts.drain(..) {
                if !prior.attempts.iter().any(|old| old.id == attempt.id) {
                    prior.attempts.push(attempt);
                }
            }
            prior.transfers.extend(next.transfers);
            prior.refused = next.refused;
            prior.waiting = next.waiting;
            prior.retry_pending = next.retry_pending;
            prior.scopes = next.scopes;
            for timeout in next.timeouts {
                match prior
                    .timeouts
                    .iter_mut()
                    .find(|known| known.kind == timeout.kind)
                {
                    Some(known) => known.count += timeout.count,
                    None => prior.timeouts.push(timeout),
                }
            }
        } else {
            reports.push(next);
        }
    }
}

/// Each scope an exchange reached and how it ended.
fn scope_outcomes(transfer: &crate::sync::Transfer) -> Vec<(ResourceScope, ScopeSyncOutcome)> {
    let mut outcomes: Vec<(ResourceScope, ScopeSyncOutcome)> = Vec::new();
    let mut set = |scope: ResourceScope, outcome: ScopeSyncOutcome| match outcomes
        .iter_mut()
        .find(|(known, _)| *known == scope)
    {
        Some((_, known)) => *known = outcome,
        None => outcomes.push((scope, outcome)),
    };
    for scope in transfer
        .held
        .iter()
        .chain(transfer.scopes.iter().map(|(scope, _)| scope))
    {
        set(*scope, ScopeSyncOutcome::Synced);
    }
    for scope in &transfer.refused {
        set(*scope, ScopeSyncOutcome::Refused);
    }
    for scope in &transfer.waiting {
        set(*scope, ScopeSyncOutcome::PeerImporting);
    }
    for scope in &transfer.failed {
        set(*scope, ScopeSyncOutcome::Failed);
    }
    outcomes
}
/// Timed-out attempts by the kind of timeout their failure names.
fn timeouts(attempts: &[AttemptObservation]) -> Vec<TimeoutCount> {
    let mut counts: Vec<TimeoutCount> = Vec::new();
    for failure in attempts
        .iter()
        .filter_map(|attempt| attempt.failure.as_ref())
    {
        if failure.kind != FailureKind::Timeout {
            continue;
        }
        let kind = failure
            .detail
            .rsplit(": ")
            .next()
            .filter(|last| last.ends_with("timeout"))
            .unwrap_or("timeout")
            .replace(' ', "_");
        match counts.iter_mut().find(|known| known.kind == kind) {
            Some(known) => known.count += 1,
            None => counts.push(TimeoutCount { kind, count: 1 }),
        }
    }
    counts
}
