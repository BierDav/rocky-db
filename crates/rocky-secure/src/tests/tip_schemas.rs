//! Graph receipt persists a schema switch intent without installing unrelated schemas.
use super::compaction::{bookmark, follow_main, insert, sign_seal};
use super::generations::{Lineage, session};
use super::*;
use rocky_credentials::{SealAction, SignedSeal};

mod employees;
mod source_availability;
pub(in crate::tests) mod source_validation;
mod staging;

#[tokio::test]
async fn withdrawing_a_private_stage_discards_cached_schema_paths_and_frontiers() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let replica = lineage
        .open(&dir.path().join("withdraw.db"), &key, 2, None)
        .await
        .unwrap();
    follow_main(&lineage, &replica).await;
    insert(&replica, "one", "retained").await;
    let scope = lineage.scope("items");
    let original = replica.frontier(scope).await.unwrap();
    let source = replica.followed_tip().await;
    let mut statement = sign_seal(
        &lineage,
        source,
        replica.seal_frontier(lineage.domain, false).await.unwrap(),
    )
    .statement;
    statement.action = SealAction::Continue {
        schema: lineage.definition(3).hash(),
    };
    let seal = SignedSeal::sign(statement, lineage.publisher()).unwrap();
    let target = seal.successor().unwrap().unwrap();
    let statements = vec![
        TipStatement::Seal(seal),
        bookmark(&lineage, Some(source), target),
    ];
    let publication = rocky_core::commitment("cache.stage", &target.0);
    replica
        .stage_schema(crate::SchemaStage {
            publication,
            scope: lineage.domain,
            bookmark: "main".into(),
            source,
            target,
            from_version: 2,
            coordinated: false,
            statements: statements.clone(),
            program: vec![],
            parents: vec![],
        })
        .await
        .unwrap();
    replica
        .install_tip_schema(target, lineage.definition(3), b"verified".to_vec())
        .await
        .unwrap();
    let mut security = lineage.config(3, &key);
    security.manifest = lineage.config(2, &key).manifest;
    replica
        .switch_schema(
            target,
            lineage.app(3),
            crate::SchemaConfig {
                security,
                tables: Some(lineage.projection(3)),
            },
        )
        .await
        .unwrap();
    assert_eq!(replica.frontier(scope).await.unwrap(), original);
    let before = replica
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .frontier_cache_stats()
        .0;
    // The schema is private, including after its local switch.
    assert!(replica.tip_statements(None, 32).await.is_err());
    let peer = PrivateKey::new();
    let credentials = lineage.credentials(3, &peer);
    replica
        .admit_peer(peer.public_key(), &credentials, target)
        .await
        .unwrap();
    let request = ScopeFrontier {
        scope,
        logs: vec![],
    };
    assert!(
        replica
            .range_page(
                peer.public_key(),
                &credentials,
                &request,
                None,
                MAX_SECURE_FRAME
            )
            .await
            .unwrap()
            .frames
            .is_empty()
    );
    replica
        .withdraw_staged_schema(
            publication,
            lineage.app(2),
            crate::SchemaConfig {
                security: lineage.config(2, &key),
                tables: Some(lineage.projection(2)),
            },
        )
        .await
        .unwrap();
    assert_eq!(replica.followed_tip().await, source);
    assert!(replica.staged_schema().await.unwrap().is_none());
    assert!(
        replica
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .frontier_cache_stats()
            .0
            > before
    );
    let restored = replica.frontier(scope).await.unwrap();
    assert_eq!(restored, original);
    assert_eq!(
        restored,
        replica
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .compute_tip_frontier(scope)
            .await
            .unwrap()
    );
    assert_eq!(
        super::generations::select(&replica, "SELECT title FROM items").await,
        vec![vec![rocky_core::SqlValue::Text("retained".into())]]
    );
}

#[tokio::test]
async fn a_followed_unknown_schema_is_pending_read_only_and_survives_reopen() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("pending.db");
    let key = PrivateKey::new();
    let replica = lineage.open(&path, &key, 3, None).await.unwrap();
    follow_main(&lineage, &replica).await;
    insert(&replica, "one", "before the schema change").await;
    let original = replica.followed_tip().await;
    let mut statement = sign_seal(
        &lineage,
        original,
        replica.seal_frontier(lineage.domain, false).await.unwrap(),
    )
    .statement;
    statement.action = SealAction::Continue {
        schema: lineage.definition(4).hash(),
    };
    let seal = SignedSeal::sign(statement, lineage.publisher()).unwrap();
    let target = seal.successor().unwrap().unwrap();
    replica
        .receive_tip_statements(&[
            TipStatement::Seal(seal),
            bookmark(&lineage, Some(original), target),
        ])
        .await
        .unwrap();
    let pending = replica.pending_schema().await.unwrap().unwrap();
    assert_eq!(pending.tip, target);
    assert_eq!(pending.manifest, lineage.definition(4).hash());
    assert_eq!(replica.followed_tip().await, original);
    assert!(
        session(&replica)
            .await
            .run("UPDATE items SET title='refused'", vec![])
            .await
            .is_err()
    );
    assert!(
        replica
            .required_schemas()
            .await
            .unwrap()
            .contains(&(target, lineage.definition(4).hash()))
    );
    assert!(
        replica
            .install_tip_schema(target, lineage.definition(5), b"forged".to_vec())
            .await
            .is_err()
    );
    assert!(
        replica
            .tip_schema(lineage.definition(5).hash())
            .await
            .unwrap()
            .is_none()
    );
    replica
        .install_tip_schema(
            target,
            lineage.definition(4),
            b"verified-adapter-record".to_vec(),
        )
        .await
        .unwrap();
    assert_eq!(
        replica
            .tip_schema(lineage.definition(4).hash())
            .await
            .unwrap(),
        Some(b"verified-adapter-record".to_vec())
    );
    drop(replica);
    let reopened = lineage.open(&path, &key, 3, None).await.unwrap();
    assert_eq!(reopened.pending_schema().await.unwrap(), Some(pending));
    assert_eq!(reopened.followed_tip().await, original);
    assert!(
        session(&reopened)
            .await
            .run("UPDATE items SET title='refused'", vec![])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn an_additive_switch_preserves_rows_observers_cursors_and_existing_sessions() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("additive.db");
    let key = PrivateKey::new();
    let identity = PrivateKey::new();
    let replica = lineage
        .open_certified(&path, (&identity, &key), 2, None)
        .await
        .unwrap();
    follow_main(&lineage, &replica).await;
    insert(&replica, "one", "retained").await;
    let old = session(&replica).await;
    let mut cursor = old
        .cursor(
            "SELECT title FROM items",
            vec![],
            crate::cursor::CursorLimits::default(),
        )
        .await
        .unwrap();
    let original = replica.followed_tip().await;
    let mut statement = sign_seal(
        &lineage,
        original,
        replica.seal_frontier(lineage.domain, false).await.unwrap(),
    )
    .statement;
    statement.action = SealAction::Continue {
        schema: lineage.definition(3).hash(),
    };
    let seal = SignedSeal::sign(statement, lineage.publisher()).unwrap();
    let target = seal.successor().unwrap().unwrap();
    replica
        .receive_tip_statements(&[
            TipStatement::Seal(seal),
            bookmark(&lineage, Some(original), target),
        ])
        .await
        .unwrap();
    replica
        .install_tip_schema(target, lineage.definition(3), b"new-schema".to_vec())
        .await
        .unwrap();
    let mut observer = replica.observe_tables(None).await.unwrap();
    let mut config = lineage.config(3, &key);
    config.credentials = lineage.certified(3, &identity, &key);
    config.manifest = lineage.config(2, &key).manifest;
    replica
        .switch_schema(
            target,
            lineage.app(3),
            crate::SchemaConfig {
                security: config,
                tables: Some(lineage.projection(3)),
            },
        )
        .await
        .unwrap();
    assert_eq!(replica.followed_tip().await, target);
    assert_eq!(replica.pending_schema().await.unwrap(), None);
    assert_eq!(observer.try_next().unwrap(), None);
    assert_eq!(
        cursor.next().await.unwrap().rows,
        vec![vec![super::generations::text("retained")]]
    );
    old.run("BEGIN", vec![]).await.unwrap();
    old.run("UPDATE items SET rank=7", vec![]).await.unwrap();
    old.run("COMMIT", vec![]).await.unwrap();
    assert!(observer.try_next().unwrap().is_some());
    drop(cursor);
    drop(old);
    drop(observer);
    drop(replica);
    let mut config = lineage.config(3, &key);
    config.credentials = lineage.certified(3, &identity, &key);
    config.manifest = lineage.config(2, &key).manifest;
    let reopened = EncryptedReplica::open(&path, lineage.app(3), config)
        .await
        .unwrap();
    assert_eq!(reopened.followed_tip().await, target);
}

/// Storage changes an additive switch of `rows` stored rows makes, counted
/// by SQLite over the switch alone, with the switch's observer events.
async fn additive_switch_changes(rows: usize) -> (i64, usize) {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let identity = PrivateKey::new();
    let replica = lineage
        .open_certified(&dir.path().join("rows.db"), (&identity, &key), 2, None)
        .await
        .unwrap();
    follow_main(&lineage, &replica).await;
    let writer = session(&replica).await;
    // A transaction holds at most 256 intent statements.
    for row in 0..rows {
        if row % 200 == 0 {
            if row > 0 {
                let handle = rocky_core::commitment("switch rows", &row.to_be_bytes());
                writer.commit(handle).await.unwrap();
            }
            writer.run("BEGIN IMMEDIATE", vec![]).await.unwrap();
        }
        super::generations::identity_insert(
            &writer,
            "INSERT INTO items(key,title) VALUES(?,?)",
            vec![
                super::generations::text(&format!("{row:06}")),
                super::generations::text("row"),
            ],
        )
        .await
        .unwrap();
    }
    writer.commit([8; 32]).await.unwrap();
    drop(writer);
    let original = replica.followed_tip().await;
    let mut statement = sign_seal(
        &lineage,
        original,
        replica.seal_frontier(lineage.domain, false).await.unwrap(),
    )
    .statement;
    statement.action = SealAction::Continue {
        schema: lineage.definition(3).hash(),
    };
    let seal = SignedSeal::sign(statement, lineage.publisher()).unwrap();
    let target = seal.successor().unwrap().unwrap();
    replica
        .receive_tip_statements(&[
            TipStatement::Seal(seal),
            bookmark(&lineage, Some(original), target),
        ])
        .await
        .unwrap();
    replica
        .install_tip_schema(target, lineage.definition(3), b"new-schema".to_vec())
        .await
        .unwrap();
    let mut observer = replica.observe_tables(None).await.unwrap();
    let mut config = lineage.config(3, &key);
    config.credentials = lineage.certified(3, &identity, &key);
    config.manifest = lineage.config(2, &key).manifest;
    let total = |replica: &crate::EncryptedReplica<rocky_core::TypedRows>| {
        let replica = replica.clone();
        async move {
            match crate::storage::rows(
                &replica
                    .inner
                    .lock(crate::replica::Class::Background)
                    .await
                    .conn,
                "SELECT total_changes()",
            )
            .await
            .unwrap()[0][..]
            {
                [rocky_core::SqlValue::Integer(changes)] => changes,
                _ => panic!("total_changes"),
            }
        }
    };
    let before = total(&replica).await;
    replica
        .switch_schema(
            target,
            lineage.app(3),
            crate::SchemaConfig {
                security: config,
                tables: Some(lineage.projection(3)),
            },
        )
        .await
        .unwrap();
    let changes = total(&replica).await - before;
    let mut events = 0;
    while observer.try_next().unwrap().is_some() {
        events += 1;
    }
    assert_eq!(
        super::generations::select(&replica, "SELECT count(*), count(rank) FROM items").await,
        vec![vec![
            rocky_core::SqlValue::Integer(rows as i64),
            rocky_core::SqlValue::Integer(0)
        ]]
    );
    (changes, events)
}

#[tokio::test]
async fn an_additive_switch_changes_the_same_storage_for_ten_or_a_thousand_rows() {
    // Only metadata changes: SQLite counts no row inserted, updated or
    // deleted by the switch, so the count does not grow with the rows.
    let (small, small_events) = additive_switch_changes(10).await;
    let (large, large_events) = additive_switch_changes(1000).await;
    assert_eq!(small, large);
    assert_eq!((small_events, large_events), (0, 0));
}
