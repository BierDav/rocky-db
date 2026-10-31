use super::*;

#[tokio::test]
async fn failed_incremental_finalization_rolls_back_rows_positions_drops_and_revision() {
    let lineage = Lineage::pinned(205);
    let dir = TempDir::new().unwrap();
    let replica = open(
        &lineage,
        &dir,
        "rollback",
        &PrivateKey::from_bytes(&[206; 32]),
    )
    .await;
    follow_main(&lineage, &replica).await;
    insert(&replica, "live", "original").await;
    insert(&replica, "dead", "original").await;
    delete(&replica, "dead").await;
    let frontier = replica.seal_frontier(lineage.domain, false).await.unwrap();
    let tip = replica.followed_tip().await;
    update(&replica, "live", "excluded").await;
    let scope = lineage.scope("items");
    replica.defer_finalization_for_test(scope, true).await;
    publish_seal(&lineage, &replica, sign_seal(&lineage, tip, frontier)).await;
    replica.defer_finalization_for_test(scope, false).await;
    let before = super::audit::snapshot(&replica).await;
    replica.inject_failure(0, 1).await;
    assert!(matches!(
        replica.finalize_path(lineage.domain).await,
        Err(Error::InjectedFailure)
    ));
    assert_eq!(super::audit::snapshot(&replica).await, before);
    replica.finalize_path(lineage.domain).await.unwrap();
    assert_eq!(
        titles(&replica).await,
        vec![vec![text("live"), text("excluded")]]
    );
    assert_eq!(
        scalar(&replica, "SELECT count(*) FROM secure_finalization_rows").await,
        0
    );
    replica.audit(scope).await.unwrap();
}
