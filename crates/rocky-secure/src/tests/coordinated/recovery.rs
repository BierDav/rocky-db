//! The owner's recovery seal ends a tip's log with the exact head it
//! replaces, and enters the graph only once enough trusted nodes
//! acknowledged it. Rocky writes no entries, so a recovery abandons none.
use super::seals::{compose, follow_main, seal, share};
use super::*;
use crate::TipStatement;
use rocky_credentials::{
    GENESIS_LINE_FORMAT, GenesisLineStatement, LogPoint, Recovery, SealStatement,
    SignedGenesisLine, SignedSeal,
};

/// The owner's `continue` seal of `tip` that replaces `recovery`'s head.
async fn recovery_seal(
    lineage: &Lineage,
    node: &Replica,
    tip: rocky_core::TipId,
    recovery: Recovery,
) -> SignedSeal {
    let ordinary = seal(lineage, node, tip).await;
    SignedSeal::sign(
        SealStatement {
            recovery: Some(recovery),
            ..ordinary.statement
        },
        lineage.publisher(),
    )
    .unwrap()
}

#[tokio::test]
async fn a_recovery_proposal_replaces_the_exact_head_and_abandons_nothing() {
    let f = Fixture::new(1).await;
    follow_main(&f).await;
    let log = tip_log(&f.lineage);
    let head = f.mesh.log.head(log).unwrap();
    let recovery = f
        .alice
        .1
        .recovery_proposal(log, &f.mesh.client(&f.alice.0))
        .await
        .unwrap();
    assert_eq!(recovery.retained, recovery.replaced);
    assert_eq!(
        recovery.replaced,
        LogPoint {
            position: head.commit,
            running: head.running_hash,
        }
    );
    f.mesh
        .log
        .set_owner(log.scope, f.lineage.publisher().public_key());
    let sealed = recovery_seal(&f.lineage, &f.alice.1, log.tip, recovery).await;
    f.alice
        .1
        .publish_tip_statements(&[TipStatement::Seal(sealed.clone())])
        .await
        .unwrap();
    let head = f.mesh.log.head(log).unwrap();
    assert_eq!(head.terminal.unwrap().digest, sealed.id().unwrap());
    assert_eq!(head.commit, 1);
    assert_eq!(
        f.alice.1.followed_tip().await,
        sealed.successor().unwrap().unwrap()
    );
    // An ended log has no recovery to propose.
    let error = f
        .alice
        .1
        .recovery_proposal(log, &f.mesh.client(&f.alice.0))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("sealed"), "{error}");
}

#[tokio::test]
async fn recovery_candidates_wait_for_two_trusted_nodes() {
    let f = Fixture::new(1).await;
    follow_main(&f).await;
    let main = tip_log(&f.lineage);
    let line = TipStatement::GenesisLine(
        SignedGenesisLine::sign(
            GenesisLineStatement {
                format: GENESIS_LINE_FORMAT,
                scope: main.scope,
                minimum_in_sync: 2,
            },
            f.lineage.publisher(),
        )
        .unwrap(),
    );
    f.alice.1.publish_tip_statements(&[line]).await.unwrap();
    share(&f.alice.1, &f.bob.1).await;
    f.mesh
        .log
        .set_owner(main.scope, f.lineage.publisher().public_key());
    let recovery = f
        .alice
        .1
        .recovery_proposal(main, &f.mesh.client(&f.alice.0))
        .await
        .unwrap();
    let sealed = recovery_seal(&f.lineage, &f.alice.1, main.tip, recovery).await;
    let error = f
        .alice
        .1
        .publish_tip_statements(&[TipStatement::Seal(sealed.clone())])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("recovery_pending"), "{error}");
    assert_eq!(f.alice.1.followed_tip().await, main.tip);
    assert_eq!(f.mesh.log.head(main).unwrap().acknowledgments.len(), 1);
    assert!(
        f.alice
            .1
            .tip_statements(None, 32)
            .await
            .unwrap()
            .iter()
            .all(|s| !matches!(s, TipStatement::Seal(s) if s.statement.recovery.is_some()))
    );
    // Another trusted node acknowledges the pending candidate it receives.
    compose(&f, &f.bob);
    for batch in f.alice.1.pending_tip_candidates().await.unwrap() {
        f.bob.1.receive_tip_statements(&batch).await.unwrap();
    }
    assert_eq!(f.mesh.log.head(main).unwrap().acknowledgments.len(), 2);
    let next = sealed.successor().unwrap().unwrap();
    assert_eq!(f.bob.1.followed_tip().await, next);
    f.alice.1.settle_tip_statements().await.unwrap();
    assert_eq!(f.alice.1.followed_tip().await, next);
}

#[tokio::test]
async fn an_ordinary_terminal_cannot_confirm_a_recovery_at_another_head() {
    let f = Fixture::new(1).await;
    follow_main(&f).await;
    let log = tip_log(&f.lineage);
    // A head the log never had.
    let point = LogPoint {
        position: 0,
        running: [9; 32],
    };
    let seal = recovery_seal(
        &f.lineage,
        &f.alice.1,
        log.tip,
        Recovery {
            retained: point,
            replaced: point,
        },
    )
    .await;
    f.mesh
        .client(&f.alice.0)
        .seal(
            log,
            rocky_core::LogTerminal {
                digest: seal.id().unwrap(),
                continuation: seal.successor().unwrap(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        f.bob
            .1
            .receive_tip_statements(&[TipStatement::Seal(seal)])
            .await
            .unwrap(),
        0
    );
    assert_eq!(f.bob.1.followed_tip().await, log.tip);
}
