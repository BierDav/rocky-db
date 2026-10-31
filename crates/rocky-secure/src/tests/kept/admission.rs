//! Re-signing kept history uses its covered inputs while live evidence grows.
use super::*;

async fn resigned_bytes(
    lineage: &Lineage,
    keeper: &Replica,
    peer: &PrivateKey,
    sealed: Commitment,
) -> (Vec<u8>, Vec<Vec<SqlValue>>) {
    // Invalidate only the serving cache, so the offer must run sign_kept.
    let scope = lineage.scope("items");
    keeper
        .admit_peer(
            peer.public_key(),
            &lineage.credentials(3, peer),
            keeper.followed_tip().await,
        )
        .await
        .unwrap();
    let inner = keeper.inner.lock(crate::replica::Class::Background).await;
    for table in ["secure_served", "secure_served_rows"] {
        inner.conn.execute(format!("DELETE FROM {table} WHERE scope=(SELECT id FROM secure_scope_state WHERE scope=?)"),[encode(&scope).unwrap()]).await.unwrap();
    }
    drop(inner);
    let offered = keeper
        .seal_checkpoint_offer(
            peer.public_key(),
            &lineage.credentials(3, peer),
            scope,
            sealed,
        )
        .await
        .unwrap()
        .unwrap();
    let rows = crate::storage::rows(
        &keeper
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .conn,
        "SELECT * FROM secure_served_rows ORDER BY scope,row",
    )
    .await
    .unwrap();
    (offered.to_bytes().unwrap(), rows)
}

#[tokio::test]
async fn kept_rows_and_newly_signed_statement_bytes_survive_live_admission_growth() {
    let lineage = Lineage::pinned(229);
    let dir = TempDir::new().unwrap();
    let keys = [230, 231, 232].map(|seed| PrivateKey::from_bytes(&[seed; 32]));
    let keeper = open(&lineage, &dir, "keeper", &keys[0]).await;
    let writer = open(&lineage, &dir, "writer", &keys[1]).await;
    follow_main(&lineage, &keeper).await;
    crate::tests::exchange_graphs(&keeper, &writer, lineage.domain).await;
    keeper
        .keep_seals(KeptSeals {
            every: true,
            ..Default::default()
        })
        .await
        .unwrap();
    insert(&writer, "one", "historical").await;
    let first = crate::tests::stored_frames(
        &writer,
        "SELECT header,body FROM secure_operations ORDER BY hash",
    )
    .await
    .remove(0);
    assert_eq!(keeper.receive(first).await.unwrap(), ReceiveStatus::Applied);
    let sealed = seal(&lineage, &keeper).await.id().unwrap();
    keeper.finalize_path(lineage.domain).await.unwrap();
    let expected = at_seal(&keeper, sealed, TITLES).await;
    keeper
        .admit_peer(
            keys[2].public_key(),
            &lineage.credentials(3, &keys[2]),
            keeper.followed_tip().await,
        )
        .await
        .unwrap();
    let signed = resigned_bytes(&lineage, &keeper, &keys[2], sealed).await;
    crate::tests::exchange_graphs(&keeper, &writer, lineage.domain).await;
    insert(&writer, "two", "live").await;
    let frames = crate::tests::stored_frames(
        &writer,
        "SELECT header,body FROM secure_operations ORDER BY hash",
    )
    .await;
    for frame in frames {
        keeper.receive(frame).await.unwrap();
    }
    assert_eq!(
        scalar(&keeper, "SELECT max(sequence) FROM secure_identity_own").await,
        2
    );
    assert_eq!(at_seal(&keeper, sealed, TITLES).await, expected);
    assert_eq!(
        resigned_bytes(&lineage, &keeper, &keys[2], sealed).await,
        signed
    );
    drop(keeper);
    let keeper = open(&lineage, &dir, "keeper", &keys[0]).await;
    keeper.audit(lineage.scope("items")).await.unwrap();
    assert_eq!(at_seal(&keeper, sealed, TITLES).await, expected);
    assert_eq!(
        resigned_bytes(&lineage, &keeper, &keys[2], sealed).await,
        signed
    );
}
