//! Replayed tables across a schema change: a late transaction replays in
//! the successor against its schema, or drops as `Schema`.
use super::*;

async fn outcomes(replica: &EncryptedReplica<TypedRows>) -> Vec<Vec<SqlValue>> {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    rows(
        &inner.conn,
        "SELECT era,dropped,sealed FROM secure_replayed ORDER BY era,clock,author,sequence",
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn a_late_write_of_a_removed_column_drops_as_schema_in_the_successor() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let (alice_key, carol_key) = (PrivateKey::new(), PrivateKey::new());
    let alice = lineage
        .open(
            &dir.path().join("alice.db"),
            &alice_key,
            3,
            Some(lineage.projection(3)),
        )
        .await
        .unwrap();
    let carol = lineage
        .open(
            &dir.path().join("carol.db"),
            &carol_key,
            3,
            Some(lineage.projection(3)),
        )
        .await
        .unwrap();
    let items = lineage.scope("items");
    identity_insert(
        &session(&alice).await,
        "INSERT INTO items VALUES('0001','one',NULL,NULL)",
        vec![],
    )
    .await
    .unwrap();
    super::sync(&alice, &carol, &carol_key, &lineage, 3, items).await;
    // Offline from the owner, carol writes the column the successor removes,
    // then a column it keeps.
    write(&carol, "UPDATE items SET note='late' WHERE key='0001'").await;
    write(&carol, "UPDATE items SET title='kept' WHERE key='0001'").await;

    let statements = lineage.publish(&alice, 4).await.unwrap();
    for (replica, key) in [(&alice, &alice_key), (&carol, &carol_key)] {
        let mut config = lineage.config(4, key);
        config.credentials = lineage.credentials(3, key);
        assert!(
            lineage
                .follow(replica, config, 4, &statements)
                .await
                .unwrap()
        );
        replica.finalize_path(lineage.domain).await.unwrap();
    }
    super::sync(&carol, &alice, &alice_key, &lineage, 4, items).await;
    for replica in [&alice, &carol] {
        assert!(replica.held_changes().await.unwrap().is_empty());
        assert_eq!(
            select(replica, "SELECT key,title FROM items").await,
            vec![vec![text("0001"), text("kept")]]
        );
        assert_eq!(
            outcomes(replica).await,
            vec![
                vec![SqlValue::Integer(0), SqlValue::Null, SqlValue::Integer(1)],
                vec![SqlValue::Integer(1), text("schema"), SqlValue::Integer(0)],
                vec![SqlValue::Integer(1), SqlValue::Null, SqlValue::Integer(0)],
            ]
        );
    }
}
