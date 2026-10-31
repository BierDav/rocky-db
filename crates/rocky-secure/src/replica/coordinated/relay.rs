//! Private, exact closing-seal relays. These records never enter graph settlement.
use super::*;
use rocky_credentials::{SealAction, SealFinality, SignedSeal, TipGraph};

pub(in crate::replica) const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS secure_close_relays(seal BLOB PRIMARY KEY,bytes BLOB NOT NULL,dispatched INTEGER NOT NULL CHECK(dispatched IN(0,1)),proof BLOB) WITHOUT ROWID",
];
const MAX_INCOMING_RELAYS: usize = 64;

/// Only verified finality establishes the outcome of a private candidate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StagedCloseStatus {
    Pending,
    Finality(SealFinality),
    Conflict {
        seal: Box<SignedSeal>,
        finality: SealFinality,
    },
}

impl<A: RowApplication> Inner<A> {
    /// Reconstructs the exported graph, without any private staged records.
    pub(super) async fn public_graph(&self, scope: Scope) -> Result<TipGraph, Error> {
        let root = self.graph_for(scope)?.genesis_schema;
        let mut graph = TipGraph::new(scope, root);
        for row in rows(
            &self.conn,
            "SELECT statement FROM secure_tip_statements WHERE staged=0",
        )
        .await?
        {
            let [SqlValue::Blob(bytes)] = row.as_slice() else {
                return Err(Error::Corrupt("public tip statement".into()));
            };
            let statement: TipStatement = decode(bytes)?;
            if statement.scope() == scope {
                statement.append(&mut graph);
            }
        }
        graph
            .exclude_revoked(&self.config.revocations)
            .map_err(credential)?;
        Ok(graph)
    }
    async fn relay_graph(&self, seal: &SignedSeal) -> Result<TipGraph, Error> {
        if seal.statement.action != SealAction::Close || seal.statement.recovery.is_some() {
            return Err(denied("a staged relay requires an ordinary close"));
        }
        let mut graph = self.public_graph(seal.statement.scope).await?;
        seal.verify_current(
            self.config.publisher,
            &graph,
            &self.config.revocations,
            now()?,
        )
        .map_err(credential)?;
        graph.schema(seal.statement.tip).map_err(credential)?;
        if !graph.seals.iter().any(|held| held == seal) {
            graph.seals.push(seal.clone());
        }
        Ok(graph)
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// Journals only the signed close before attempting its ordinary source terminal.
    /// No opening, move, schema, or migration frames are admitted by this API.
    pub async fn relay_staged_close(&self, bytes: &[u8]) -> Result<StagedCloseStatus, Error> {
        let seal = SignedSeal::from_bytes(bytes).map_err(credential)?;
        let id = seal.id().map_err(credential)?;
        {
            let inner = self.inner.lock(crate::replica::Class::Background).await;
            let graph = inner.relay_graph(&seal).await?;
            if graph
                .line_minimum(seal.statement.tip)
                .map_err(credential)?
                .is_none()
            {
                return Ok(StagedCloseStatus::Pending);
            }
        }
        // A retained proof remains usable even after coordinator retention.
        let known = self.staged_close_finality(bytes).await?;
        if !matches!(known, StagedCloseStatus::Pending) {
            return Ok(known);
        }
        let Some(coordinator) = self.domain_log() else {
            return Ok(StagedCloseStatus::Pending);
        };
        let log = TipLog {
            scope: seal.statement.scope,
            tip: seal.statement.tip,
        };
        if log != self.followed_log(log.scope).await {
            return Ok(StagedCloseStatus::Pending);
        }
        {
            let inner = self.inner.lock(crate::replica::Class::Background).await;
            let author = inner
                .node_author
                .as_ref()
                .filter(|a| *a.key.public_key().as_bytes() == coordinator.node());
            let node =
                author.map_or_else(|| inner.config.node.public_key(), |a| a.key.public_key());
            if *node.as_bytes() != coordinator.node() {
                return Err(denied("relay log belongs to another node"));
            }
            let chain = inner
                .terminal_credentials(
                    node,
                    author.map_or(&inner.config.credentials, |a| &a.credentials),
                )
                .await?;
            chain
                .trusted_node(
                    inner.config.publisher,
                    log.scope,
                    node,
                    Some((&inner.config.revocations, now()?)),
                )
                .map_err(credential)?;
        }
        {
            let mut inner = self.inner.lock(crate::replica::Class::Background).await;
            transaction!(inner, |inner| {
                let records = rows(&inner.conn, "SELECT seal FROM secure_close_relays").await?;
                if records.len() >= MAX_INCOMING_RELAYS
                    && !records
                        .iter()
                        .any(|row| row.as_slice() == [SqlValue::Blob(id.to_vec())])
                {
                    return Err(Error::Quota {
                        resource: "incoming staged close relays",
                        limit: MAX_INCOMING_RELAYS,
                    });
                }
                inner
                    .conn
                    .execute(
                        "INSERT OR IGNORE INTO secure_close_relays VALUES(?,?,0,NULL)",
                        [id.to_vec(), bytes.to_vec()],
                    )
                    .await?;
                Ok(())
            })?;
            drop(flush_guard(inner, &self.inner).await?);
        }
        // A genesis-looking head after a previous dispatch may be forgotten
        // evidence. Never recreate that source log on a retry.
        let head = match coordinator.log_head(log).await {
            Ok(head) => head,
            Err(_) => return Ok(StagedCloseStatus::Pending),
        };
        let dispatched = {
            let inner = self.inner.lock(crate::replica::Class::Background).await;
            let records = collect_rows(
                inner
                    .conn
                    .query(
                        "SELECT dispatched FROM secure_close_relays WHERE seal=?",
                        [id.to_vec()],
                    )
                    .await?,
            )
            .await?;
            matches!(
                records.first().map(Vec::as_slice),
                Some([SqlValue::Integer(1)])
            )
        };
        if head.terminal.is_some() || (dispatched && head.epoch == 0) {
            return self.staged_close_finality(bytes).await;
        }
        {
            let mut inner = self.inner.lock(crate::replica::Class::Background).await;
            // Recheck authority before marking dispatch durable.
            inner.relay_graph(&seal).await?;
            transaction!(inner, |inner| {
                inner
                    .conn
                    .execute(
                        "UPDATE secure_close_relays SET dispatched=1 WHERE seal=?",
                        [id.to_vec()],
                    )
                    .await?;
                Ok(())
            })?;
            drop(flush_guard(inner, &self.inner).await?);
        }
        let _ = coordinator
            .seal(
                log,
                rocky_core::LogTerminal {
                    digest: id,
                    continuation: None,
                },
            )
            .await;
        self.staged_close_finality(bytes).await
    }

    /// Acknowledges only an exact committed terminal, without admitting its seal.
    /// A verified rival proof is evidence of conflict; a reply alone is not.
    pub async fn staged_close_finality(&self, bytes: &[u8]) -> Result<StagedCloseStatus, Error> {
        let seal = SignedSeal::from_bytes(bytes).map_err(credential)?;
        let id = seal.id().map_err(credential)?;
        let (graph, stored) = {
            let inner = self.inner.lock(crate::replica::Class::Background).await;
            let graph = inner.relay_graph(&seal).await?;
            let records = collect_rows(
                inner
                    .conn
                    .query(
                        "SELECT proof FROM secure_close_relays WHERE seal=?",
                        [id.to_vec()],
                    )
                    .await?,
            )
            .await?;
            let stored = match records.first().map(Vec::as_slice) {
                Some([SqlValue::Blob(bytes)]) => Some(decode::<SealFinality>(bytes)?),
                _ => None,
            };
            if let Some(proof) = &stored {
                graph
                    .verify_finality(
                        proof,
                        inner.config.publisher,
                        Some((&inner.config.revocations, now()?)),
                    )
                    .map_err(credential)?;
            }
            (graph, stored)
        };
        if let Some(proof) = stored {
            return Ok(StagedCloseStatus::Finality(proof));
        }
        let Some(coordinator) = self.domain_log() else {
            return Ok(StagedCloseStatus::Pending);
        };
        if let Some(proof) = self
            .terminal_finality(&seal, &graph, coordinator.as_ref())
            .await?
        {
            let mut inner = self.inner.lock(crate::replica::Class::Background).await;
            let graph = inner.relay_graph(&seal).await?;
            graph
                .verify_finality(
                    &proof,
                    inner.config.publisher,
                    Some((&inner.config.revocations, now()?)),
                )
                .map_err(credential)?;
            transaction!(inner, |inner| {
                // Proof-only contacts do not consume submission journal slots.
                inner
                    .conn
                    .execute(
                        "UPDATE secure_close_relays SET proof=? WHERE seal=?",
                        [encode(&proof)?, id.to_vec()],
                    )
                    .await?;
                Ok(())
            })?;
            drop(flush_guard(inner, &self.inner).await?);
            return Ok(StagedCloseStatus::Finality(proof));
        }
        let log = TipLog {
            scope: seal.statement.scope,
            tip: seal.statement.tip,
        };
        if let Ok(head) = coordinator.log_head(log).await
            && let Some(terminal) = head.terminal
            && terminal.digest != id
            && let Ok(rival) = graph.seal_by_id(terminal.digest)
            && let Some(finality) = self
                .terminal_finality(rival, &graph, coordinator.as_ref())
                .await?
        {
            return Ok(StagedCloseStatus::Conflict {
                seal: Box::new(rival.clone()),
                finality,
            });
        }
        Ok(StagedCloseStatus::Pending)
    }
}
