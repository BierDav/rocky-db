//! Session-bound partition proofs; decision 0052 defines the wire contract.
use super::*;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use std::collections::BTreeSet;

const HOLDING_DENIED: &str = "ciphertext custody denied";
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct HoldingProof {
    pub epoch: rocky_core::KeyEpoch,
    pub value: [u8; 16],
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) enum HoldingMessage {
    Prove {
        scopes: Vec<ResourceScope>,
        proofs: Vec<(ResourceScope, Vec<HoldingProof>)>,
        partitions: Vec<(ResourceScope, rocky_core::PartitionTuple)>,
    },
    Proved {
        scopes: Vec<ResourceScope>,
    },
}
fn proof_cipher(key: &KeyMaterial, binding: Commitment) -> Result<ChaCha20Poly1305, Error> {
    let bytes = encode(&(key.key, key.scope, key.generation, binding))?;
    let derived = rocky_core::commitment("rocky.holding-proof-key.v1", &bytes);
    Ok(ChaCha20Poly1305::new((&derived).into()))
}
pub(crate) fn key_proof(key: &KeyMaterial, binding: Commitment) -> Result<[u8; 16], Error> {
    proof_cipher(key, binding)?
        .encrypt_in_place_detached((&[0; 12]).into(), b"rocky.holding-proof.v1", &mut [])
        .map(Into::into)
        .map_err(|_| denied(HOLDING_DENIED))
}
pub(crate) fn verify_key_proof(
    key: &KeyMaterial,
    binding: Commitment,
    value: &[u8; 16],
) -> Result<bool, Error> {
    Ok(proof_cipher(key, binding)?
        .decrypt_in_place_detached(
            (&[0; 12]).into(),
            b"rocky.holding-proof.v1",
            &mut [],
            value.into(),
        )
        .is_ok())
}

impl NativeSession {
    pub(super) async fn accept_proofs<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scopes: &[ResourceScope],
        proofs: &[(ResourceScope, Vec<HoldingProof>)],
        partitions: &[(ResourceScope, rocky_core::PartitionTuple)],
    ) -> Result<(), Error> {
        self.accept_proofs_for(replica, scopes, proofs, partitions, false)
            .await
    }
    pub(super) async fn accept_link_proofs<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scopes: &[ResourceScope],
        proofs: &[(ResourceScope, Vec<HoldingProof>)],
        partitions: &[(ResourceScope, rocky_core::PartitionTuple)],
    ) -> Result<(), Error> {
        self.accept_proofs_for(replica, scopes, proofs, partitions, true)
            .await
    }
    async fn accept_proofs_for<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scopes: &[ResourceScope],
        proofs: &[(ResourceScope, Vec<HoldingProof>)],
        partitions: &[(ResourceScope, rocky_core::PartitionTuple)],
        link: bool,
    ) -> Result<(), Error> {
        let distinct: BTreeSet<_> = scopes.iter().copied().collect();
        let valid = |members: Vec<ResourceScope>| {
            members.len() <= scopes.len()
                && members.iter().all(|scope| distinct.contains(scope))
                && members.iter().copied().collect::<BTreeSet<_>>().len() == members.len()
        };
        if scopes.is_empty()
            || scopes.len() > 64
            || distinct.len() != scopes.len()
            || !valid(proofs.iter().map(|(scope, _)| *scope).collect())
            || !valid(partitions.iter().map(|(scope, _)| *scope).collect())
            || proofs.iter().any(|(_, values)| values.len() > 4)
        {
            return Err(denied(HOLDING_DENIED));
        }
        let mut accepted = Vec::new();
        for scope in scopes {
            let values = proofs
                .iter()
                .find(|(s, _)| s == scope)
                .map_or(&[][..], |(_, p)| p.as_slice());
            let tuple = partitions.iter().find(|(s, _)| s == scope).map(|(_, t)| t);
            if replica
                .verify_holding(
                    self.peer,
                    &self.credentials,
                    self.binding,
                    *scope,
                    values,
                    tuple,
                )
                .await?
            {
                accepted.push(*scope);
            }
        }
        // Registration is only for tuples whose proof and grants verified.
        let offers: Vec<_> = partitions
            .iter()
            .filter(|(scope, _)| accepted.contains(scope))
            .cloned()
            .collect();
        if link {
            replica
                .accept_link_custody_offers(self.peer, &self.credentials, scopes, &offers)
                .await?;
        } else {
            replica
                .accept_custody_offers(self.peer, &self.credentials, scopes, &offers)
                .await?;
        }
        self.proved.extend(accepted);
        Ok(())
    }

    pub(super) async fn require_holding<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scope: ResourceScope,
    ) -> Result<(), Error> {
        if replica.holding_required(scope).await && !self.proved.contains(&scope) {
            return Err(denied(HOLDING_DENIED));
        }
        Ok(())
    }

    /// Proves named partitions before scope enumeration or a custom transfer.
    /// Ordinary scoped client calls and frontier batches do this automatically.
    pub async fn prove_scopes<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scopes: &[ResourceScope],
    ) -> Result<(), Error> {
        self.ensure_holding(replica, scopes).await
    }

    pub(super) async fn ensure_holding<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scopes: &[ResourceScope],
    ) -> Result<(), Error> {
        if !self.try_scoped_holding(replica, scopes, false).await? {
            return Err(denied(HOLDING_DENIED));
        }
        Ok(())
    }

    pub(super) async fn ensure_held_holding<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scope: ResourceScope,
    ) -> Result<(), Error> {
        if !self.try_scoped_holding(replica, &[scope], true).await? {
            return Err(denied(HOLDING_DENIED));
        }
        Ok(())
    }

    /// A peer without a partition's key can refuse its proof without ending recovery of other scopes.
    pub(super) async fn try_scoped_holding<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        scopes: &[ResourceScope],
        held: bool,
    ) -> Result<bool, Error> {
        let mut missing = Vec::new();
        for scope in scopes {
            if !self.offered.contains(scope) && replica.holding_required(*scope).await {
                missing.push(*scope);
            }
        }
        for batch in missing.chunks(64) {
            // Retain the existing rule against disclosing metadata to an ungranted server.
            let allowed = if held {
                for scope in batch {
                    replica
                        .authorize_held_reader(self.peer, &self.credentials, *scope)
                        .await?;
                }
                batch.to_vec()
            } else {
                replica
                    .peer_holds(self.peer, &self.credentials, batch)
                    .await?
            };
            if allowed.len() != batch.len() {
                return Err(denied(HOLDING_DENIED));
            }
            let proofs = replica.holding_proofs(self.binding, batch).await?;
            let partitions = replica
                .tuple_proofs(self.peer, &self.credentials, batch)
                .await?;
            for message in prove_pages(batch, &proofs, &partitions)? {
                let HoldingMessage::Prove { ref scopes, .. } = message else {
                    return Err(denied(HOLDING_DENIED));
                };
                let requested = scopes.clone();
                self.send(message).await?;
                let HoldingMessage::Proved { scopes: accepted } =
                    self.reply::<HoldingMessage>().await?
                else {
                    return Err(denied(HOLDING_DENIED));
                };
                if accepted.iter().any(|scope| !requested.contains(scope))
                    || accepted.iter().collect::<BTreeSet<_>>().len() != accepted.len()
                {
                    return Err(denied(HOLDING_DENIED));
                }
                let complete = accepted.len() == requested.len();
                self.offered.extend(accepted);
                if !complete {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    pub(super) async fn answer_holdings<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        message: HoldingMessage,
    ) -> Result<(), Error> {
        let HoldingMessage::Prove {
            scopes,
            proofs,
            partitions,
        } = message
        else {
            return Err(denied(HOLDING_DENIED));
        };
        self.accept_proofs(replica, &scopes, &proofs, &partitions)
            .await?;
        let mut accepted = Vec::new();
        for scope in scopes {
            if self.require_holding(replica, scope).await.is_ok()
                && (replica
                    .authorize_scope_peer(self.peer, &self.credentials, scope)
                    .await
                    .is_ok()
                    || replica
                        .authorize_held_reader(self.peer, &self.credentials, scope)
                        .await
                        .is_ok())
            {
                accepted.push(scope);
            }
        }
        self.send(HoldingMessage::Proved { scopes: accepted }).await
    }

    pub(super) async fn guard_message<A: RowApplication>(
        &mut self,
        replica: &EncryptedReplica<A>,
        message: &Message,
    ) -> Result<(), Error> {
        let scopes = match message {
            Message::Rows(message) => match message {
                RowMessage::Range { frontier, .. } | RowMessage::Held { frontier } => {
                    vec![frontier.scope]
                }
                RowMessage::FrontierQuery { scope }
                | RowMessage::Push { scope, .. }
                | RowMessage::Read { scope, .. } => vec![*scope],
                _ => Vec::new(),
            },
            Message::HeldChanges(
                held::HeldMessage::Pull { scope, .. } | held::HeldMessage::Push { scope, .. },
            ) => vec![*scope],
            Message::Checkpoints(
                CheckpointMessage::Pruned { scope, .. }
                | CheckpointMessage::CheckpointOffer { scope }
                | CheckpointMessage::SealOffer { scope, .. }
                | CheckpointMessage::CheckpointPull { scope, .. },
            ) => vec![*scope],
            Message::Checkpoints(CheckpointMessage::ArchiveBegin { signed }) => {
                vec![signed.statement.scope]
            }
            Message::Checkpoints(CheckpointMessage::ArchivePage { page }) => vec![page.scope],
            _ => Vec::new(),
        };
        for scope in scopes {
            self.require_holding(replica, scope).await?;
        }
        Ok(())
    }
}

pub(super) fn prove_pages(
    scopes: &[ResourceScope],
    proofs: &[(ResourceScope, Vec<HoldingProof>)],
    partitions: &[(ResourceScope, rocky_core::PartitionTuple)],
) -> Result<Vec<HoldingMessage>, Error> {
    let mut result = Vec::new();
    let mut remaining = scopes;
    while !remaining.is_empty() {
        let mut count = remaining.len().min(64);
        let message = loop {
            let batch = &remaining[..count];
            let message = HoldingMessage::Prove {
                scopes: batch.to_vec(),
                proofs: proofs
                    .iter()
                    .filter(|(scope, _)| batch.contains(scope))
                    .cloned()
                    .collect(),
                partitions: partitions
                    .iter()
                    .filter(|(scope, _)| batch.contains(scope))
                    .cloned()
                    .collect(),
            };
            if encode(&message)?.len() <= SECURE_MESSAGE_BYTES {
                break message;
            }
            if count == 1 {
                return Err(Error::Quota {
                    resource: "holding proof",
                    limit: SECURE_MESSAGE_BYTES,
                });
            }
            count -= 1;
        };
        result.push(message);
        remaining = &remaining[count..];
    }
    Ok(result)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod primitives {
    use super::*;
    #[test]
    fn proof_binds_key_scope_epoch_and_session() {
        let scope = ResourceScope {
            domain: rocky_core::Scope {
                mesh: rocky_core::MeshId([1; 16]),
                app: rocky_core::AppId([2; 16]),
                domain: rocky_core::DomainId([3; 16]),
            },
            table: [4; 32],
            encryption: [5; 32],
        };
        let key = KeyMaterial::new(scope, 1, [6; 32]);
        let proof = key_proof(&key, [7; 32]).unwrap();
        assert!(verify_key_proof(&key, [7; 32], &proof).unwrap());
        assert!(!verify_key_proof(&key, [8; 32], &proof).unwrap());
        assert!(!verify_key_proof(&KeyMaterial::new(scope, 2, [6; 32]), [7; 32], &proof).unwrap());
        assert!(!verify_key_proof(&KeyMaterial::new(scope, 1, [9; 32]), [7; 32], &proof).unwrap());
        let other = ResourceScope {
            encryption: [10; 32],
            ..scope
        };
        assert!(
            !verify_key_proof(
                &KeyMaterial::at(other, key.generation, key.key),
                [7; 32],
                &proof
            )
            .unwrap()
        );
    }
}
