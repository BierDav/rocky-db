//! A private close is certified without admitting or exporting its candidate graph.
use super::*;
use crate::StagedCloseStatus;
use rocky_credentials::{SealAction, SignedSeal};

async fn trusted(fixture: &Fixture, name: &str) -> (PrivateKey, Replica) {
    let (identity, node) = (PrivateKey::new(), PrivateKey::new());
    let replica = fixture
        .lineage
        .open_trusted(
            &fixture.dir.path().join(format!("{name}.db")),
            (&identity, &node),
            3,
            None,
        )
        .await
        .unwrap();
    let node = (node, replica);
    seals::join_main(fixture, &node).await;
    node
}

async fn close(fixture: &Fixture) -> SignedSeal {
    let mut statement = seals::seal(
        &fixture.lineage,
        &fixture.alice.1,
        tip_log(&fixture.lineage).tip,
    )
    .await
    .statement;
    statement.action = SealAction::Close;
    SignedSeal::sign(statement, fixture.lineage.publisher()).unwrap()
}

#[tokio::test]
async fn a_relay_certifies_only_the_exact_private_close() {
    let fixture = Fixture::new(1).await;
    seals::follow_main(&fixture).await;
    let relay = trusted(&fixture, "relay").await;
    let close = close(&fixture).await;
    let bytes = close.to_bytes().unwrap();
    let graph_before = relay.1.tip_graph(fixture.lineage.domain).await.unwrap();
    let log = tip_log(&fixture.lineage);
    let proof = match relay.1.relay_staged_close(&bytes).await.unwrap() {
        StagedCloseStatus::Finality(proof) => proof,
        other => panic!("{other:?}"),
    };
    assert_eq!(proof.seal, close.id().unwrap());
    assert_eq!(
        relay.1.tip_graph(fixture.lineage.domain).await.unwrap(),
        graph_before
    );
    assert!(
        !relay
            .1
            .tip_statements(None, 32)
            .await
            .unwrap()
            .iter()
            .any(|statement| statement.id().unwrap() == close.id().unwrap())
    );
    assert!(relay.1.pending_tip_candidates().await.unwrap().is_empty());
    assert!(matches!(
        relay.1.staged_close_finality(&bytes).await.unwrap(),
        StagedCloseStatus::Finality(_)
    ));
    assert_eq!(
        fixture.mesh.log.head(log).unwrap().terminal.unwrap().digest,
        close.id().unwrap()
    );
}

#[tokio::test]
async fn an_unknown_rival_terminal_never_certifies_the_private_candidate() {
    let fixture = Fixture::new(1).await;
    seals::follow_main(&fixture).await;
    let relay = trusted(&fixture, "relay").await;
    let candidate = close(&fixture).await;
    let mut statement = candidate.statement.clone();
    statement.frontier.push(rocky_credentials::AuthorMark {
        author: rocky_credentials::MAX_AUTHOR,
        sequence: 1,
    });
    let rival = SignedSeal::sign(statement, fixture.lineage.publisher()).unwrap();
    assert_ne!(rival.id().unwrap(), candidate.id().unwrap());
    let log = tip_log(&fixture.lineage);
    fixture
        .mesh
        .client(&fixture.alice.0)
        .seal(
            log,
            rocky_core::LogTerminal {
                digest: rival.id().unwrap(),
                continuation: None,
            },
        )
        .await
        .unwrap();
    let bytes = candidate.to_bytes().unwrap();
    assert!(matches!(
        relay.1.relay_staged_close(&bytes).await.unwrap(),
        StagedCloseStatus::Pending
    ));
    assert!(matches!(
        relay.1.staged_close_finality(&bytes).await.unwrap(),
        StagedCloseStatus::Pending
    ));
    assert!(relay.1.tip_graph(log.scope).await.unwrap().seals.is_empty());
}

#[tokio::test]
async fn relays_refuse_continuations_and_recovery_candidates() {
    let fixture = Fixture::new(1).await;
    seals::follow_main(&fixture).await;
    let relay = trusted(&fixture, "relay").await;
    let continuation = seals::seal(
        &fixture.lineage,
        &fixture.alice.1,
        tip_log(&fixture.lineage).tip,
    )
    .await;
    assert!(
        relay
            .1
            .relay_staged_close(&continuation.to_bytes().unwrap())
            .await
            .is_err()
    );
    assert!(relay.1.staged_close_finality(&[1, 2, 3]).await.is_err());
}

#[tokio::test]
async fn a_committed_relay_resumes_exact_bytes_after_reopen_without_admitting_the_close() {
    let fixture = Fixture::new(2).await;
    seals::follow_main(&fixture).await;
    let close = close(&fixture).await;
    let bytes = close.to_bytes().unwrap();
    assert!(matches!(
        fixture.alice.1.relay_staged_close(&bytes).await.unwrap(),
        StagedCloseStatus::Pending
    ));
    let head = fixture.mesh.log.head(tip_log(&fixture.lineage)).unwrap();
    assert_eq!(head.terminal.unwrap().digest, close.id().unwrap());
    let records = crate::storage::rows(
        &fixture
            .alice
            .1
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .conn,
        "SELECT bytes,dispatched FROM secure_close_relays",
    )
    .await
    .unwrap();
    assert_eq!(
        records,
        vec![vec![SqlValue::Blob(bytes.clone()), SqlValue::Integer(1)]]
    );
    let fixture = fixture.restart_alice().await;
    seals::compose(&fixture, &fixture.alice);
    assert!(matches!(
        fixture.alice.1.staged_close_finality(&bytes).await.unwrap(),
        StagedCloseStatus::Pending
    ));
    assert!(matches!(
        fixture.bob.1.staged_close_finality(&bytes).await.unwrap(),
        StagedCloseStatus::Finality(_)
    ));
    let proof = match fixture.alice.1.relay_staged_close(&bytes).await.unwrap() {
        StagedCloseStatus::Finality(proof) => proof,
        other => panic!("{other:?}"),
    };
    assert_eq!(proof.seal, close.id().unwrap());
    assert_eq!(
        fixture
            .mesh
            .log
            .head(tip_log(&fixture.lineage))
            .unwrap()
            .commit,
        head.commit
    );
    assert!(
        fixture
            .alice
            .1
            .tip_graph(fixture.lineage.domain)
            .await
            .unwrap()
            .seals
            .is_empty()
    );
    assert!(
        fixture
            .alice
            .1
            .pending_tip_candidates()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_pending_relay_uses_the_raised_signed_minimum_and_distinct_acknowledgers() {
    let fixture = Fixture::new(2).await;
    seals::follow_main(&fixture).await;
    let relay = trusted(&fixture, "minimum-relay").await;
    let close = close(&fixture).await;
    let bytes = close.to_bytes().unwrap();
    assert!(matches!(
        relay.1.relay_staged_close(&bytes).await.unwrap(),
        StagedCloseStatus::Pending
    ));
    let raised = TipStatement::GenesisLine(
        rocky_credentials::SignedGenesisLine::sign(
            rocky_credentials::GenesisLineStatement {
                format: rocky_credentials::GENESIS_LINE_FORMAT,
                scope: fixture.lineage.domain,
                minimum_in_sync: 3,
            },
            fixture.lineage.publisher(),
        )
        .unwrap(),
    );
    relay.1.receive_tip_statements(&[raised]).await.unwrap();
    fixture.alice.1.staged_close_finality(&bytes).await.unwrap();
    for _ in 0..2 {
        assert!(matches!(
            relay.1.staged_close_finality(&bytes).await.unwrap(),
            StagedCloseStatus::Pending
        ));
    }
    fixture.bob.1.staged_close_finality(&bytes).await.unwrap();
    assert!(matches!(
        relay.1.staged_close_finality(&bytes).await.unwrap(),
        StagedCloseStatus::Finality(_)
    ));
    let head = fixture.mesh.log.head(tip_log(&fixture.lineage)).unwrap();
    assert_eq!(head.acknowledgments.len(), 3);
    assert_eq!(head.terminal.unwrap().digest, close.id().unwrap());
    assert!(
        relay
            .1
            .tip_graph(fixture.lineage.domain)
            .await
            .unwrap()
            .seals
            .is_empty()
    );
}
