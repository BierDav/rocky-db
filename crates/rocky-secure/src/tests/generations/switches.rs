//! Schema changes as seals: a `continue` names the successor's schema, a
//! follower switches when its bookmark reaches it, and every write reaches
//! the live tip through the fields each tip on the path has.
use super::super::compaction::sync;
use super::*;
use crate::tests::stored_frames;

/// Every frame `source` authored, for a test to deliver late.
pub(super) async fn authored(
    source: &EncryptedReplica<TypedRows>,
    key: &PrivateKey,
) -> Vec<EncryptedFrame> {
    stored_frames(source, "SELECT header,body FROM secure_operations")
        .await
        .into_iter()
        .filter(|frame| frame.operation().unwrap().header.public_key == key.public_key())
        .collect()
}
/// Imports `source`'s base of `scope` into `target`, page by page.
async fn import(
    lineage: &Lineage,
    source: &EncryptedReplica<TypedRows>,
    target: &EncryptedReplica<TypedRows>,
    key: &PrivateKey,
    scope: ResourceScope,
) -> crate::SignedCheckpoint {
    let credentials = lineage.credentials(3, key);
    source
        .admit_peer(key.public_key(), &credentials, target.followed_tip().await)
        .await
        .unwrap();
    let offered = source
        .checkpoint_offer(key.public_key(), &credentials, scope)
        .await
        .unwrap()
        .expect("a base");
    let checkpoint = offered.id().unwrap();
    target.begin_rebootstrap(offered.clone()).await.unwrap();
    // The base's tip and every tip after it on the path need their schemas.
    lineage.install_required(target).await;
    let mut after = None;
    loop {
        let page = source
            .checkpoint_page(
                key.public_key(),
                &credentials,
                scope,
                checkpoint,
                after,
                64 * 1024,
            )
            .await
            .unwrap();
        after = page.next;
        target.stage_checkpoint_page(page).await.unwrap();
        if after.is_none() {
            break;
        }
    }
    target.finish_rebootstrap(scope).await.unwrap();
    offered
}

#[tokio::test]
async fn a_seal_to_a_new_schema_keeps_local_work_and_a_follower_switches_only_with_it() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let (alice_key, bob_key) = (PrivateKey::new(), PrivateKey::new());
    let alice = lineage
        .open(&dir.path().join("alice.db"), &alice_key, 1, None)
        .await
        .unwrap();
    let bob = lineage
        .open(&dir.path().join("bob.db"), &bob_key, 1, None)
        .await
        .unwrap();
    let items = lineage.scope("items");
    super::super::compaction::follow_main(&lineage, &alice).await;
    crate::tests::exchange_graphs(&alice, &bob, lineage.domain).await;
    insert(&alice, 0..2).await;
    sync(&lineage, &alice, &bob, &bob_key).await;
    // Alice's third row has not left her device when the schema changes.
    insert(&alice, 2..3).await;
    let original = alice.followed_tip().await;
    let statements = lineage.publish(&alice, 2).await.unwrap();
    let target = alice
        .tip_graph(lineage.domain)
        .await
        .unwrap()
        .bookmark("main")
        .unwrap()
        .unwrap();
    // Until the switch, the workspace waits read-only at the old tip.
    let pending = alice.pending_schema().await.unwrap().unwrap();
    assert_eq!(
        (pending.tip, pending.manifest),
        (target, lineage.definition(2).hash())
    );
    assert!(
        session(&alice)
            .await
            .run("UPDATE items SET title='refused'", vec![])
            .await
            .is_err()
    );
    // A projection other than the tip's schema activates nothing.
    alice
        .install_tip_schema(target, lineage.definition(2), b"checked".to_vec())
        .await
        .unwrap();
    let mut projection = lineage.projection(2);
    projection.0.tables[0].columns[2].not_null = true;
    let mut config = lineage.config(2, &alice_key);
    config.manifest = lineage.config(1, &alice_key).manifest;
    assert!(
        alice
            .switch_schema(
                target,
                lineage.app(2),
                crate::SchemaConfig {
                    security: config,
                    tables: Some(projection)
                },
            )
            .await
            .is_err()
    );
    assert_eq!(alice.followed_tip().await, original);
    assert!(
        lineage
            .follow(&alice, lineage.config(2, &alice_key), 2, &statements)
            .await
            .unwrap()
    );
    assert_eq!(alice.followed_tip().await, target);
    // Existing rows gained the new column, empty; the new table exists.
    assert_eq!(
        select(&alice, "SELECT key,title,note FROM items ORDER BY key").await,
        (0..3)
            .map(|id| vec![
                text(&format!("{id:04}")),
                text(&format!("title {id}")),
                SqlValue::Null
            ])
            .collect::<Vec<_>>()
    );
    let writer = session(&alice).await;
    identity_insert(
        &writer,
        "INSERT INTO items VALUES('0100','new','with a note')",
        vec![],
    )
    .await
    .unwrap();
    identity_insert(&writer, "INSERT INTO tags VALUES('t','label')", vec![])
        .await
        .unwrap();
    drop(writer);

    // Bob, still at the old tip, is served nothing across the tips.
    let credentials = lineage.credentials(1, &bob_key);
    alice
        .admit_peer(bob_key.public_key(), &credentials, bob.followed_tip().await)
        .await
        .unwrap();
    assert!(matches!(
        alice
            .transfer_page(
                bob_key.public_key(),
                &credentials,
                &[items],
                None,
                MAX_SECURE_FRAME
            )
            .await,
        Err(Error::Rejected(_))
    ));
    assert_eq!(
        select(&bob, "SELECT count(*) FROM items").await,
        vec![vec![SqlValue::Integer(2)]]
    );
    // Following the bookmark switches Bob with it, and then he catches up.
    assert!(
        lineage
            .follow(&bob, lineage.config(2, &bob_key), 2, &statements)
            .await
            .unwrap()
    );
    sync(&lineage, &alice, &bob, &bob_key).await;
    assert_eq!(
        select(&bob, "SELECT key,note FROM items ORDER BY key").await,
        vec![
            vec![text("0000"), SqlValue::Null],
            vec![text("0001"), SqlValue::Null],
            vec![text("0002"), SqlValue::Null],
            vec![text("0100"), text("with a note")],
        ]
    );
    alice.audit(items).await.unwrap();
    bob.audit(items).await.unwrap();
}

#[tokio::test]
async fn a_base_at_a_seal_of_the_previous_schema_rebootstraps_typed_rows_and_tombstones() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let (alice_key, bob_key, carol_key) = (PrivateKey::new(), PrivateKey::new(), PrivateKey::new());
    let alice = lineage
        .open(&dir.path().join("alice.db"), &alice_key, 1, None)
        .await
        .unwrap();
    let bob = lineage
        .open(&dir.path().join("bob.db"), &bob_key, 1, None)
        .await
        .unwrap();
    let items = lineage.scope("items");
    super::super::compaction::follow_main(&lineage, &alice).await;
    crate::tests::exchange_graphs(&alice, &bob, lineage.domain).await;
    insert(&alice, 0..40).await;
    write(&alice, "DELETE FROM items WHERE key='0003'").await;
    write(&alice, "UPDATE items SET title='kept' WHERE key='0004'").await;
    sync(&lineage, &alice, &bob, &bob_key).await;
    alice
        .acknowledge_frontier(
            bob_key.public_key(),
            &lineage.credentials(3, &bob_key),
            &bob.frontier(items).await.unwrap(),
        )
        .await
        .unwrap();
    // The schema change is the seal; Alice compacts at it and prunes.
    assert!(
        lineage
            .advance(&alice, lineage.config(2, &alice_key), 2)
            .await
            .unwrap()
    );
    alice
        .set_retention_policy(
            items,
            RetentionPolicy {
                required: [rocky_credentials::PeerId::of(bob_key.public_key())].into(),
                behind: [rocky_credentials::PeerId::of(carol_key.public_key())].into(),
                copies: 1,
                window: 0,
            },
        )
        .await
        .unwrap();
    let report = alice.compact(lineage.domain, 0).await.unwrap();
    assert!(report.pruned > 0);
    let base = alice.checkpoint(items).await.unwrap();
    // The base sits at the seal of the first schema's tip.
    assert_eq!(base.statement.seal, report.compacted);
    assert_eq!(
        alice
            .tip_graph(lineage.domain)
            .await
            .unwrap()
            .schema(base.statement.tip)
            .unwrap(),
        lineage.definition(1).hash()
    );
    identity_insert(
        &session(&alice).await,
        "INSERT INTO items VALUES('0100','after','noted')",
        vec![],
    )
    .await
    .unwrap();

    // Carol joins at the domain root, follows `main` to the second schema
    // and imports the first schema's base through the path's fields.
    let carol = lineage
        .open(&dir.path().join("carol.db"), &carol_key, 1, None)
        .await
        .unwrap();
    let statements = crate::tests::all_tip_statements(&alice).await;
    assert!(
        lineage
            .follow(&carol, lineage.config(2, &carol_key), 2, &statements)
            .await
            .unwrap()
    );
    let offered = import(&lineage, &alice, &carol, &carol_key, items).await;
    assert_eq!(offered.id().unwrap(), base.id().unwrap());
    // The empty `tags` scope has no state Carol verified: Alice's signed
    // empty base at the seal, once listed, is what Carol imports.
    let needs = carol.seal_rebootstraps(lineage.domain).await.unwrap();
    assert_eq!(
        needs.iter().map(|need| need.scope).collect::<Vec<_>>(),
        vec![lineage.scope("tags")]
    );
    super::super::compaction::list_checkpoints(&lineage, &alice).await;
    crate::tests::exchange_graphs(&alice, &carol, lineage.domain).await;
    let tags = import(&lineage, &alice, &carol, &carol_key, lineage.scope("tags")).await;
    super::super::compaction::assert_empty_checkpoint(&tags, report.compacted.unwrap());
    assert!(
        carol
            .seal_rebootstraps(lineage.domain)
            .await
            .unwrap()
            .is_empty()
    );
    carol.audit(items).await.unwrap();
    sync(&lineage, &alice, &carol, &carol_key).await;
    carol.audit(items).await.unwrap();
    assert_eq!(
        select(&carol, "SELECT count(*) FROM items").await,
        vec![vec![SqlValue::Integer(40)]]
    );
    assert_eq!(
        select(&carol, "SELECT title,note FROM items WHERE key='0004'").await,
        vec![vec![text("kept"), SqlValue::Null]]
    );
    assert_eq!(
        select(&carol, "SELECT note FROM items WHERE key='0100'").await,
        vec![vec![text("noted")]]
    );
    // The base keeps the old numeric identity's sequence mark.
    let number = (u32::from_le_bytes(
        rocky_core::commitment("items", alice_key.as_bytes())[..4]
            .try_into()
            .unwrap(),
    ) & 0x7fff_ffff)
        .max(1);
    let old_id = rocky_core::RowIdentity::new(number, 4).unwrap();
    assert!(
        session(&carol)
            .await
            .run(
                "INSERT INTO items(key,title,note,id) VALUES('0003','again',NULL,?)",
                vec![SqlValue::Integer(old_id.integer())]
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn an_open_replica_follows_an_additive_schema_in_place() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let (alice_key, bob_key) = (PrivateKey::new(), PrivateKey::new());
    let alice_path = dir.path().join("alice.db");
    let alice = lineage
        .open(&alice_path, &alice_key, 1, None)
        .await
        .unwrap();
    let bob = lineage
        .open(&dir.path().join("bob.db"), &bob_key, 1, None)
        .await
        .unwrap();
    let (items, tags) = (lineage.scope("items"), lineage.scope("tags"));
    super::super::compaction::follow_main(&lineage, &alice).await;
    crate::tests::exchange_graphs(&alice, &bob, lineage.domain).await;
    insert(&alice, 0..3).await;
    let statements = lineage.publish(&alice, 3).await.unwrap();
    let target = alice.pending_schema().await.unwrap().unwrap().tip;
    // Bob switches first and writes on the new tip.
    assert!(
        lineage
            .follow(&bob, lineage.config(3, &bob_key), 3, &statements)
            .await
            .unwrap()
    );
    identity_insert(
        &session(&bob).await,
        "INSERT INTO items VALUES('0100','ranked',NULL,7)",
        vec![],
    )
    .await
    .unwrap();
    let newer = authored(&bob, &bob_key).await;
    assert!(!newer.is_empty());
    let mut observer = alice.observe_tables(None).await.unwrap();
    let before = session(&alice).await;
    // A record that does not derive the tip's schema is refused; nothing is saved.
    assert!(
        alice
            .install_tip_schema(target, lineage.definition(5), b"forged".to_vec())
            .await
            .is_err()
    );
    assert!(
        alice
            .tip_schema(lineage.definition(5).hash())
            .await
            .unwrap()
            .is_none()
    );

    assert!(
        lineage
            .follow(&alice, lineage.config(3, &alice_key), 3, &statements)
            .await
            .unwrap()
    );
    assert_eq!(alice.followed_tip().await, target);
    // An additive switch keeps sessions and notifies no observer.
    assert!(before.run("SELECT 1", vec![]).await.is_ok());
    assert_eq!(observer.try_next().unwrap(), None);
    for frame in newer {
        let _ = alice.receive(frame).await;
    }
    assert_eq!(
        select(&alice, "SELECT key,note,rank FROM items ORDER BY key").await,
        (0..3)
            .map(|id| vec![text(&format!("{id:04}")), SqlValue::Null, SqlValue::Null])
            .chain([vec![text("0100"), SqlValue::Null, SqlValue::Integer(7)]])
            .collect::<Vec<_>>()
    );
    // Following the current schema again changes nothing.
    assert!(
        !lineage
            .follow(&alice, lineage.config(3, &alice_key), 3, &statements)
            .await
            .unwrap()
    );
    // Its writes reach the peer on the same tip, and the file reopens there.
    identity_insert(
        &session(&alice).await,
        "INSERT INTO tags VALUES('t','label')",
        vec![],
    )
    .await
    .unwrap();
    for frame in frames(&alice, &bob, tags).await {
        bob.receive(frame).await.unwrap();
    }
    assert_eq!(
        select(&bob, "SELECT label FROM tags").await,
        vec![vec![text("label")]]
    );
    drop(before);
    drop(observer);
    drop(alice);
    let alice = lineage.reopen(&alice_path, &alice_key, 1, 3).await.unwrap();
    assert_eq!(alice.followed_tip().await, target);
    alice.audit(items).await.unwrap();
    assert_eq!(
        select(&alice, "SELECT count(*) FROM items").await,
        vec![vec![SqlValue::Integer(4)]]
    );
}

#[tokio::test]
async fn a_schema_removes_a_field_and_a_table_on_every_replica_that_follows_it() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let (alice_key, carol_key) = (PrivateKey::new(), PrivateKey::new());
    let alice_path = dir.path().join("alice.db");
    let alice = lineage
        .open(&alice_path, &alice_key, 3, None)
        .await
        .unwrap();
    let carol = lineage
        .open(&dir.path().join("carol.db"), &carol_key, 3, None)
        .await
        .unwrap();
    let items = lineage.scope("items");
    super::super::compaction::follow_main(&lineage, &alice).await;
    crate::tests::exchange_graphs(&alice, &carol, lineage.domain).await;
    for (key, title) in [("0001", "one"), ("0002", "two")] {
        identity_insert(
            &session(&alice).await,
            &format!("INSERT INTO items VALUES('{key}','{title}','noted',NULL)"),
            vec![],
        )
        .await
        .unwrap();
    }
    identity_insert(
        &session(&alice).await,
        "INSERT INTO tags VALUES('t','label')",
        vec![],
    )
    .await
    .unwrap();
    sync(&lineage, &alice, &carol, &carol_key).await;

    assert!(
        lineage
            .advance(&alice, lineage.config(4, &alice_key), 4)
            .await
            .unwrap()
    );
    // Exactly the new schema, every remaining row visible.
    let reader = session(&alice).await;
    assert!(reader.run("SELECT note FROM items", vec![]).await.is_err());
    assert!(reader.run("SELECT * FROM tags", vec![]).await.is_err());
    drop(reader);
    let expected = vec![
        vec![text("0001"), text("one")],
        vec![text("0002"), text("two")],
    ];
    assert_eq!(
        select(&alice, "SELECT key,title FROM items ORDER BY key").await,
        expected
    );
    alice.compact(lineage.domain, 0).await.unwrap();
    alice.audit(items).await.unwrap();

    // Carol, offline at the old tip, edits a kept and a removed field and
    // the removed table. Across the `continue` her transaction replays on
    // the new schema, which lacks `note`: all of it drops.
    write(
        &carol,
        "UPDATE items SET title='uno', note='carol' WHERE key='0001'",
    )
    .await;
    write(&carol, "UPDATE tags SET label='other'").await;
    for frame in authored(&carol, &carol_key).await {
        let _ = alice.receive(frame).await;
    }
    assert_eq!(
        select(&alice, "SELECT title FROM items WHERE key='0001'").await,
        vec![vec![text("one")]]
    );
    alice.audit(items).await.unwrap();
    // The removal survives reopening and dropping schemas nothing needs.
    drop(alice);
    let alice = lineage.reopen(&alice_path, &alice_key, 3, 4).await.unwrap();
    alice.audit(items).await.unwrap();
    alice.drop_unrequired_schemas().await.unwrap();
    drop(alice);
    let alice = lineage.reopen(&alice_path, &alice_key, 3, 4).await.unwrap();
    alice.audit(items).await.unwrap();
    let kept = vec![
        vec![text("0001"), text("one")],
        vec![text("0002"), text("two")],
    ];
    assert_eq!(
        select(&alice, "SELECT key,title FROM items ORDER BY key").await,
        kept
    );
    write(&carol, "UPDATE items SET note='again' WHERE key='0002'").await;
    for frame in authored(&carol, &carol_key).await {
        let _ = alice.receive(frame).await;
    }
    assert_eq!(
        select(&alice, "SELECT key,title FROM items ORDER BY key").await,
        kept
    );
    alice.audit(items).await.unwrap();
}

#[tokio::test]
async fn a_readded_field_never_receives_a_value_written_before_its_removal() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys: Vec<_> = (0..4).map(|_| PrivateKey::new()).collect();
    let mut replicas = Vec::new();
    for (index, key) in keys.iter().enumerate() {
        replicas.push(
            lineage
                .open(&dir.path().join(format!("{index}.db")), key, 3, None)
                .await
                .unwrap(),
        );
    }
    let [alice, bob, dave, erin] = &replicas[..] else {
        unreachable!()
    };
    let [alice_key, bob_key, dave_key, erin_key] = &keys[..] else {
        unreachable!()
    };
    let items = lineage.scope("items");
    super::super::compaction::follow_main(&lineage, alice).await;
    for replica in [bob, dave, erin] {
        crate::tests::exchange_graphs(alice, replica, lineage.domain).await;
    }
    // A: notes written while the field exists.
    for (key, note) in [("0001", "old"), ("0002", "stale")] {
        identity_insert(
            &session(alice).await,
            &format!("INSERT INTO items VALUES('{key}','title','{note}',NULL)"),
            vec![],
        )
        .await
        .unwrap();
    }
    for (target, key) in [(bob, bob_key), (dave, dave_key)] {
        sync(&lineage, alice, target, key).await;
    }
    // Dave, offline at A, writes the field late, beyond every seal.
    write(dave, "UPDATE items SET note='late at A' WHERE key='0002'").await;
    // A -> B (no `note`) -> C (`note` again). Alice walks each step.
    crate::tests::check_frontier_cache(alice, items).await;
    crate::tests::check_frontier_cache(bob, items).await;
    let removed = lineage.publish(alice, 4).await.unwrap();
    assert!(
        lineage
            .follow(alice, lineage.config(4, alice_key), 4, &removed)
            .await
            .unwrap()
    );
    crate::tests::check_frontier_cache(alice, items).await;
    alice.compact(lineage.domain, 0).await.unwrap();
    crate::tests::check_frontier_cache(alice, items).await;
    let readded = lineage.publish(alice, 5).await.unwrap();
    assert!(
        lineage
            .follow(alice, lineage.config(5, alice_key), 5, &readded)
            .await
            .unwrap()
    );
    // Bob follows A -> C at once: B's schema is needed for the path.
    assert!(
        lineage
            .follow(bob, lineage.config(5, bob_key), 5, &readded)
            .await
            .unwrap()
    );
    assert!(
        bob.tip_schema(lineage.definition(4).hash())
            .await
            .unwrap()
            .is_some()
    );
    let notes = "SELECT key,note FROM items ORDER BY key";
    let empty = vec![
        vec![text("0001"), SqlValue::Null],
        vec![text("0002"), SqlValue::Null],
    ];
    assert_eq!(select(alice, notes).await, empty);
    assert_eq!(select(bob, notes).await, empty);
    crate::tests::check_frontier_cache(alice, items).await;
    crate::tests::check_frontier_cache(bob, items).await;
    // Dave's late write at A crosses B: its `note` never reaches C.
    for replica in [alice, bob] {
        for frame in authored(dave, dave_key).await {
            let _ = replica.receive(frame).await;
        }
        assert_eq!(select(replica, notes).await, empty);
        replica.audit(items).await.unwrap();
    }
    // A write at C carries the field again.
    write(alice, "UPDATE items SET note='at C' WHERE key='0001'").await;
    for frame in authored(alice, alice_key).await {
        let _ = bob.receive(frame).await;
    }
    let written = vec![
        vec![text("0001"), text("at C")],
        vec![text("0002"), SqlValue::Null],
    ];
    assert_eq!(select(bob, notes).await, written);
    // A base at A's seal, imported at C, carries no earlier note either.
    let statements = crate::tests::all_tip_statements(alice).await;
    assert!(
        lineage
            .follow(erin, lineage.config(5, erin_key), 5, &statements)
            .await
            .unwrap()
    );
    import(&lineage, alice, erin, erin_key, items).await;
    crate::tests::check_frontier_cache(erin, items).await;
    sync(&lineage, alice, erin, erin_key).await;
    assert_eq!(select(erin, notes).await, written);
    erin.audit(items).await.unwrap();
}
