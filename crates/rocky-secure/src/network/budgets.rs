//! Encoded limits, including worst-width integers and the signed envelope.
use super::*;
use rocky_core::{
    AppId, DomainId, FieldSelection, MeshId, PrincipalKind, ResourceGrant, Right, RowSelection,
    Scope, TipId,
};
use rocky_credentials::{
    Extended, Extension, SealFinality, SignedCapability, TerminalAck, TerminalAckStatement,
};

fn scope(index: u8) -> ResourceScope {
    ResourceScope {
        domain: Scope {
            mesh: MeshId([255; 16]),
            app: AppId([255; 16]),
            domain: DomainId([255; 16]),
        },
        table: [index; 32],
        encryption: [255; 32],
    }
}
fn eight_links(grants: usize) -> CredentialChain {
    let key = PrivateKey::from_bytes(&[7; 32]);
    CredentialChain(
        (0..MAX_CREDENTIAL_DEPTH)
            .map(|index| {
                SignedCapability::sign(
                    Capability {
                        subject: key.public_key(),
                        kind: PrincipalKind::Node,
                        grants: (0..grants)
                            .map(|index| ResourceGrant {
                                scope: scope(index as u8),
                                rows: RowSelection::All,
                                fields: FieldSelection::All,
                                rights: [Right::Read, Right::Insert, Right::Update, Right::Delete]
                                    .into(),
                            })
                            .collect(),
                        not_before: u64::MAX - 1,
                        expires: u64::MAX,
                        delegations: index as u8,
                        extension: Extension::new(Extended::default()).unwrap(),
                    },
                    &key,
                )
                .unwrap()
            })
            .collect(),
    )
}
fn ack(credentials: CredentialChain) -> Result<TerminalAck, rocky_credentials::Error> {
    TerminalAck::sign(
        TerminalAckStatement {
            format: rocky_credentials::TERMINAL_ACK_FORMAT,
            scope: scope(1).domain,
            tip: TipId([255; 32]),
            position: u64::MAX,
            running: [255; 32],
            seal: [255; 32],
            continuation: Some(TipId([255; 32])),
        },
        &PrivateKey::from_bytes(&[7; 32]),
        credentials,
    )
}
fn fits(message: Message) {
    let key = PrivateKey::from_bytes(&[7; 32]);
    let bytes = encode(&message).unwrap();
    assert!(
        bytes.len() <= SECURE_MESSAGE_BYTES,
        "{}: {}",
        message.family(),
        bytes.len()
    );
    let frame = encode(&SignedMessage {
        sequence: u64::MAX,
        bytes,
        signature: key.sign(b"bound"),
    })
    .unwrap();
    assert!(frame.len() <= MAX_SECURE_FRAME);
}
#[test]
fn tip_pages_and_candidates_fit_with_the_largest_permitted_eight_link_acknowledgment() {
    let mut largest = None;
    for grants in 1..=rocky_credentials::MAX_GRANTS {
        match ack(eight_links(grants)) {
            Ok(ack) => largest = Some(ack),
            Err(_) => break,
        }
    }
    let ack = largest.unwrap();
    let ack_bytes = ack.to_bytes().unwrap().len();
    assert!(ack_bytes <= rocky_credentials::MAX_TERMINAL_ACK_BYTES);
    let finality = SealFinality {
        format: rocky_credentials::SEAL_FINALITY_FORMAT,
        scope: scope(1).domain,
        seal: [255; 32],
        acknowledgments: vec![ack; rocky_credentials::MAX_FINALITY_ACKS],
    };
    let statement = crate::TipStatement::Finality(finality);
    assert!(statement.id().is_ok());
    let input = vec![statement.clone(); 32];
    let pages = tips::statement_pages(input.clone()).unwrap();
    assert!(pages.len() > 1);
    assert_eq!(pages.iter().map(Vec::len).sum::<usize>(), input.len());
    for page in pages {
        fits(
            tips::TipMessage::Statements {
                statements: page.clone(),
                last: false,
            }
            .into(),
        );
        fits(
            tips::TipMessage::Push {
                statements: page,
                last: false,
            }
            .into(),
        );
    }
    let candidates = tips::candidate_pages(vec![input]).unwrap();
    assert_eq!(candidates.iter().filter(|(_, last)| *last).count(), 1);
    for (statements, last) in candidates {
        fits(tips::TipMessage::CandidatePush { statements, last }.into());
    }
    let mut oversized = statement;
    let crate::TipStatement::Finality(ref mut finality) = oversized else {
        unreachable!()
    };
    finality
        .acknowledgments
        .resize(64, finality.acknowledgments[0].clone());
    assert!(matches!(
        oversized.id(),
        Err(Error::Quota {
            resource: "tip statement",
            ..
        })
    ));
    eprintln!(
        "eight-link ack={ack_bytes}; finality bound={}; message budget={SECURE_MESSAGE_BYTES}",
        rocky_credentials::MAX_FINALITY_BYTES
    );
}
#[test]
fn maximal_frontier_batches_are_split_in_both_directions() {
    use crate::replica::roles::{FrontierReply, FrontierState, MAX_FRONTIER_SCOPES};
    let author = PrivateKey::from_bytes(&[7; 32]).public_key();
    let frontiers: Vec<_> = (0..MAX_FRONTIER_SCOPES)
        .map(|index| ScopeFrontier {
            scope: scope(index as u8),
            logs: vec![
                FrontierLog {
                    author,
                    held: u64::MAX,
                    applied: u64::MAX
                };
                MAX_CHECKPOINT_LOGS
            ],
        })
        .collect();
    let mut remaining = frontiers.as_slice();
    let mut sent = 0;
    while !remaining.is_empty() {
        let query = frontiers::frontier_query(remaining.to_vec(), &[], &[]).unwrap();
        let frontiers::FrontierMessage::FrontiersQuery {
            frontiers: selected,
            ..
        } = &query
        else {
            unreachable!()
        };
        let count = selected.len();
        let mut states: Vec<_> = selected
            .iter()
            .map(|frontier| {
                FrontierReply::Held(FrontierState {
                    frontier: frontier.clone(),
                    importing: true,
                })
            })
            .collect();
        states.truncate(page_len(&states, MAX_FRONTIER_SCOPES).unwrap());
        let returned = states.len();
        fits(query.into());
        fits(frontiers::FrontierMessage::Frontiers { states }.into());
        assert!(returned > 0 && returned <= count);
        remaining = &remaining[returned..];
        sent += 1;
    }
    assert!(sent > 1);
}
#[test]
fn holdings_proofs_fit_with_maximal_tuples_and_four_epochs() {
    use rocky_core::{Affinity, Collation, KeyColumn, PartitionTuple, PartitionValue, SqlValue};
    let value = PartitionValue::new(
        KeyColumn {
            affinity: Affinity::Blob,
            collation: Collation::Binary,
        },
        SqlValue::Blob(vec![255; 900]),
    )
    .unwrap();
    let tuple = PartitionTuple::new([([255; 32], value)]).unwrap();
    let scopes: Vec<_> = (0..64).map(scope).collect();
    let proofs: Vec<_> = scopes
        .iter()
        .map(|scope| {
            (
                *scope,
                vec![
                    holdings::HoldingProof {
                        epoch: rocky_core::KeyEpoch {
                            generation: i64::MAX as u64,
                            secret_hash: [255; 32]
                        },
                        value: [255; 16]
                    };
                    4
                ],
            )
        })
        .collect();
    let partitions: Vec<_> = scopes.iter().map(|scope| (*scope, tuple.clone())).collect();
    let pages = holdings::prove_pages(&scopes, &proofs, &partitions).unwrap();
    let mut count = 0;
    for message in pages {
        let HoldingMessage::Prove { scopes, .. } = &message else {
            unreachable!()
        };
        count += scopes.len();
        fits(message.into());
    }
    assert_eq!(count, scopes.len());
}
