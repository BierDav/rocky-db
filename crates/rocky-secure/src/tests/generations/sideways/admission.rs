//! A write to a table the target removed waits; restoring the source path
//! applies it once.
use super::*;

#[tokio::test]
async fn a_write_to_a_removed_table_applies_once_its_path_returns() {
    let lineage = Lineage::pinned(131);
    let dir = TempDir::new().unwrap();
    let identity = PrivateKey::from_bytes(&[132; 32]);
    let keys = [133, 134].map(|seed| PrivateKey::from_bytes(&[seed; 32]));
    let path = dir.path().join("alice.db");
    let mut alice = lineage
        .open_certified(&path, (&identity, &keys[0]), 3, Some(lineage.projection(3)))
        .await
        .unwrap();
    let dave = lineage
        .open(
            &dir.path().join("dave.db"),
            &keys[1],
            3,
            Some(lineage.projection(3)),
        )
        .await
        .unwrap();
    follow_main(&lineage, &alice).await;
    crate::tests::exchange_graphs(&alice, &dave, lineage.domain).await;
    identity_insert(
        &session(&dave).await,
        "INSERT INTO tags(key,label) VALUES('late','restored')",
        vec![],
    )
    .await
    .unwrap();
    let frames = super::super::switches::authored(&dave, &keys[1]).await;
    assert_eq!(frames.len(), 1);
    let frame = &frames[0];
    let op = frame.operation().unwrap();
    let author = op.header.extensions.author.unwrap();
    assert_eq!(
        (op.header.seq_num, op.header.extensions.author_sequence),
        (0, 0)
    );
    let first = super::super::super::compaction::sign_seal(
        &lineage,
        alice.followed_tip().await,
        vec![rocky_credentials::AuthorMark {
            author,
            sequence: 0,
        }],
    );
    let first_id = first.id().unwrap();
    let next = first.successor().unwrap().unwrap();
    let from = alice.followed_tip().await;
    alice
        .publish_tip_statements(&[
            TipStatement::Seal(first),
            bookmark(&lineage, Some(from), next),
        ])
        .await
        .unwrap();
    alice
        .publish_tip_statements(&open_dev(&lineage, first_id, 4))
        .await
        .unwrap();
    alice.follow_bookmark(lineage.domain, "dev").await.unwrap();
    lineage.install_required(&alice).await;
    let dev = alice
        .tip_graph(lineage.domain)
        .await
        .unwrap()
        .bookmark("dev")
        .unwrap()
        .unwrap();
    let security = || {
        let mut config = lineage.config(4, &keys[0]);
        // Removing a local table need not discard already granted reader authority.
        config.credentials = lineage.certified(3, &identity, &keys[0]);
        config.manifest = lineage.manifest(3);
        config
            .keys
            .push(crate::KeyMaterial::new(lineage.scope("tags"), 1, [41; 32]));
        config
    };
    alice
        .switch_schema(
            dev,
            lineage.app(4),
            crate::SchemaConfig {
                security: security(),
                tables: Some(lineage.projection(4)),
            },
        )
        .await
        .unwrap();
    let scope = lineage.scope("tags");
    alice.receive(frame.clone()).await.unwrap();
    drop(alice);
    alice = lineage.open_with(&path, security(), 4, None).await.unwrap();
    alice.audit(lineage.scope("items")).await.unwrap();
    follow(&lineage, &alice, (&identity, &keys[0]), "main", 3).await;
    let restored = vec![vec![text("late"), text("restored")]];
    assert_eq!(select(&alice, "SELECT key,label FROM tags").await, restored);
    alice.rebuild_projection(scope).await.unwrap();
    alice.audit(scope).await.unwrap();
    // A duplicate changes nothing.
    alice.receive(frame.clone()).await.unwrap();
    assert_eq!(select(&alice, "SELECT key,label FROM tags").await, restored);
    drop(alice);
    let alice = lineage.reopen(&path, &keys[0], 3, 3).await.unwrap();
    alice.audit(scope).await.unwrap();
    assert_eq!(select(&alice, "SELECT key,label FROM tags").await, restored);
}
