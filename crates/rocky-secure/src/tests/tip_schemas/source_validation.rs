//! Resealing a held original and the statements that close its line.
use super::*;
use crate::wire::{Chain, RowPayload};

pub(in crate::tests) fn reseal(
    frame: &EncryptedFrame,
    node: &PrivateKey,
    key: &[u8; 32],
    chain: Chain,
    writes: Vec<RowWrite>,
    original: &RowPayload,
) -> EncryptedFrame {
    let operation = frame.operation_ref().unwrap();
    let body = match original.membership() {
        Some(membership) => RowPayload::bundle(membership.clone(), writes).unwrap(),
        None => RowPayload::rows(
            &writes
                .into_iter()
                .map(|write| write.change)
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    };
    let proofs = original
        .writes()
        .iter()
        .filter_map(|write| {
            original
                .proof(&write.change.row)
                .map(|proof| (write.change.row, proof.clone()))
        })
        .collect();
    let carried = original
        .writes()
        .iter()
        .filter_map(|write| {
            original
                .carried(&write.change.row)
                .map(|proof| (write.change.row, proof.clone()))
        })
        .collect();
    let body = RowPayload::stamp_body(&body, proofs, carried).unwrap();
    let plaintext = original
        .compact_test(
            &RowPayload::witness(body, original.creations().to_vec()).unwrap(),
            operation.header.extensions.scope,
        )
        .unwrap();
    let mut extension = operation.header.extensions.clone();
    extension.chain = chain.digest();
    extension.births = original.rebound_births_for_test(&chain).unwrap();
    crate::wire::author(
        node,
        extension,
        chain,
        key,
        (
            operation.header.seq_num,
            operation.header.backlink,
            operation.header.timestamp,
        ),
        operation.header.previous.clone(),
        &plaintext,
    )
    .unwrap()
}

pub(in crate::tests) fn closed_statements(
    scope: rocky_core::Scope,
    source: rocky_core::TipId,
    manifest: Commitment,
    publisher: &PrivateKey,
) -> Vec<TipStatement> {
    let close = SignedSeal::sign(
        rocky_credentials::SealStatement {
            format: rocky_credentials::SEAL_FORMAT,
            scope,
            tip: source,
            frontier: vec![],
            action: SealAction::Close,
            recovery: None,
        },
        publisher,
    )
    .unwrap();
    let opening = rocky_credentials::SignedTipOpening::sign(
        rocky_credentials::TipOpeningStatement {
            format: rocky_credentials::TIP_OPENING_FORMAT,
            scope,
            seal: close.id().unwrap(),
            schema: manifest,
            minimum_in_sync: 1,
        },
        publisher,
    )
    .unwrap();
    let tip = opening.tip().unwrap();
    vec![
        TipStatement::Seal(close),
        TipStatement::Opening(opening),
        TipStatement::Bookmark(
            rocky_credentials::SignedBookmarkMove::sign(
                rocky_credentials::BookmarkMoveStatement {
                    format: rocky_credentials::BOOKMARK_MOVE_FORMAT,
                    scope,
                    name: "main".into(),
                    from: None,
                    to: Some(tip),
                },
                publisher,
            )
            .unwrap(),
        ),
    ]
}
