//! Unknown payloads never become empty state by inspecting or compacting them.
use super::super::generations::{identity_insert, session};
use super::*;
use crate::KeptSeals;

async fn count_scope(replica: &Replica, scope: ResourceScope) -> i64 {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    let rows = crate::storage::collect_rows(
        inner
            .conn
            .query(
                "SELECT count(*) FROM secure_scope_state WHERE scope=?",
                [encode(&scope).unwrap()],
            )
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    match rows[0].as_slice() {
        [SqlValue::Integer(count)] => *count,
        _ => panic!("scope count"),
    }
}
async fn snapshot(replica: &Replica) -> (Vec<Vec<SqlValue>>, i64) {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    let state = crate::storage::rows(&inner.conn, "SELECT * FROM secure_scope_state ORDER BY id")
        .await
        .unwrap();
    let changes = crate::storage::rows(&inner.conn, "SELECT total_changes()")
        .await
        .unwrap();
    let [SqlValue::Integer(changes)] = changes[0].as_slice() else {
        panic!("changes")
    };
    (state, *changes)
}

#[tokio::test]
async fn readiness_inspection_never_materializes_an_unknown_scope() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new()];
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    let b = open(&lineage, &dir, "b", &keys[1]).await;
    follow_main(&lineage, &a).await;
    insert(&a, "one", "one").await;
    let seal = seal(&lineage, &a).await.id().unwrap();
    crate::tests::exchange_graphs(&a, &b, lineage.domain).await;
    b.follow_bookmark(lineage.domain, "main").await.unwrap();
    let before = snapshot(&b).await;
    assert_eq!(count_scope(&b, lineage.scope("tags")).await, 0);
    assert!(
        b.compaction_status(lineage.domain)
            .await
            .unwrap()
            .waiting
            .is_some()
    );
    assert!(!b.wanted_placements().await.unwrap().is_empty());
    b.held_seal(lineage.domain, seal).await.unwrap();
    b.seal_rebootstraps(lineage.domain).await.unwrap();
    b.seal_pull_scopes(lineage.domain, seal).await.unwrap();
    b.unlisted_checkpoints(lineage.domain).await.unwrap();
    assert_eq!(snapshot(&b).await, before);
}

#[tokio::test]
async fn a_missing_granted_key_does_not_turn_an_unknown_payload_into_empty_state() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new()];
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    let b = open(&lineage, &dir, "b", &keys[1]).await;
    follow_main(&lineage, &a).await;
    insert(&a, "one", "one").await;
    let sealed = seal(&lineage, &a).await.id().unwrap();
    crate::tests::exchange_graphs(&a, &b, lineage.domain).await;
    b.follow_bookmark(lineage.domain, "main").await.unwrap();
    b.inner
        .lock(crate::replica::Class::Background)
        .await
        .config
        .keys
        .clear();
    let report = b.compact(lineage.domain, 0).await.unwrap();
    assert!(report.waiting.is_some());
    assert_eq!(report.finalized, None);
    assert_eq!(count_scope(&b, lineage.scope("items")).await, 0);
    assert_eq!(b.held_seal(lineage.domain, sealed).await.unwrap(), None);
}

#[tokio::test]
async fn a_joiner_imports_the_signed_empty_scope_after_importing_another_scopes_base() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new()];
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    follow_main(&lineage, &a).await;
    insert(&a, "one", "one").await;
    let sealed = seal(&lineage, &a).await.id().unwrap();
    a.compact(lineage.domain, 0).await.unwrap();
    let b = open(&lineage, &dir, "b", &keys[1]).await;
    crate::tests::exchange_graphs(&a, &b, lineage.domain).await;
    b.follow_bookmark(lineage.domain, "main").await.unwrap();
    import_checkpoint(&lineage, &a, &b, &keys[1], lineage.scope("items")).await;
    let waiting = b
        .compaction_status(lineage.domain)
        .await
        .unwrap()
        .waiting
        .unwrap();
    assert!(
        waiting.contains("has no verified state at a seal of the path"),
        "{waiting}"
    );
    let needs = b.seal_rebootstraps(lineage.domain).await.unwrap();
    let tags = needs
        .iter()
        .find(|need| need.scope == lineage.scope("tags"))
        .unwrap();
    assert!(tags.listed.is_empty());
    assert_eq!(tags.replay, crate::FrameReplay::Peers);
    assert_eq!(b.compact(lineage.domain, 0).await.unwrap().finalized, None);
    list_checkpoints(&lineage, &a).await;
    crate::tests::exchange_graphs(&a, &b, lineage.domain).await;
    let needs = b.seal_rebootstraps(lineage.domain).await.unwrap();
    let tags = needs
        .iter()
        .find(|need| need.scope == lineage.scope("tags"))
        .unwrap();
    assert_eq!(tags.listed.len(), 1);
    let offered = a
        .checkpoint_offer(
            keys[1].public_key(),
            &lineage.credentials(3, &keys[1]),
            lineage.scope("tags"),
        )
        .await
        .unwrap()
        .unwrap();
    assert_empty_checkpoint(&offered, sealed);
    import_checkpoint(&lineage, &a, &b, &keys[1], lineage.scope("tags")).await;
    b.finalize_path(lineage.domain).await.unwrap();
    assert_eq!(
        b.compaction_status(lineage.domain).await.unwrap().finalized,
        Some(sealed)
    );
    assert!(
        b.seal_rebootstraps(lineage.domain)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(scalar(&b, "SELECT count(*) FROM tags").await, 0);
}

#[tokio::test]
async fn a_late_grant_never_signs_an_unchecked_empty_base() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new()];
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    let b = lineage
        .open_scoped(&dir.path().join("b.db"), &keys[1], false, &["items"])
        .await
        .unwrap();
    follow_main(&lineage, &a).await;
    identity_insert(
        &session(&a).await,
        "INSERT INTO tags(key,label) VALUES('tag','not empty')",
        vec![],
    )
    .await
    .unwrap();
    insert(&a, "one", "later held frame").await;
    seal(&lineage, &a).await;
    crate::tests::exchange_graphs(&a, &b, lineage.domain).await;
    b.follow_bookmark(lineage.domain, "main").await.unwrap();
    sync(&lineage, &a, &b, &keys[1]).await;
    b.compact(lineage.domain, 0).await.unwrap();
    b.renew_credentials(lineage.credentials(3, &keys[1]))
        .await
        .unwrap();
    b.install_key_epoch(
        lineage
            .config(3, &keys[1])
            .keys
            .into_iter()
            .find(|key| key.scope == lineage.scope("tags"))
            .unwrap(),
    )
    .await
    .unwrap();
    let report = b.compact(lineage.domain, 0).await.unwrap();
    assert!(
        report
            .waiting
            .as_deref()
            .unwrap()
            .contains("has no verified state")
    );
    assert!(
        b.seal_rebootstraps(lineage.domain)
            .await
            .unwrap()
            .iter()
            .any(|need| need.scope == lineage.scope("tags"))
    );
    assert!(
        b.unlisted_checkpoints(lineage.domain)
            .await
            .unwrap()
            .iter()
            .all(|record| record.table != lineage.scope("tags"))
    );
}

#[tokio::test]
async fn a_kept_empty_scope_stays_empty_before_during_and_after_a_branch_switch() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let a = open(&lineage, &dir, "a", &key).await;
    follow_main(&lineage, &a).await;
    a.keep_seals(KeptSeals {
        every: true,
        ..KeptSeals::default()
    })
    .await
    .unwrap();
    let sealed = seal(&lineage, &a).await.id().unwrap();
    a.finalize_path(lineage.domain).await.unwrap();
    let query = "SELECT key FROM tags";
    assert!(
        super::super::kept::at_seal(&a, sealed, query)
            .await
            .is_empty()
    );
    identity_insert(
        &session(&a).await,
        "INSERT INTO tags(key,label) VALUES('live','later')",
        vec![],
    )
    .await
    .unwrap();
    assert!(
        super::super::kept::at_seal(&a, sealed, query)
            .await
            .is_empty()
    );
    let opening = rocky_credentials::SignedTipOpening::sign(
        rocky_credentials::TipOpeningStatement {
            format: rocky_credentials::TIP_OPENING_FORMAT,
            schema: lineage.definition(3).hash(),
            scope: lineage.domain,
            seal: sealed,
            minimum_in_sync: 1,
        },
        lineage.publisher(),
    )
    .unwrap();
    let dev = opening.tip().unwrap();
    let movement = rocky_credentials::SignedBookmarkMove::sign(
        rocky_credentials::BookmarkMoveStatement {
            format: rocky_credentials::BOOKMARK_MOVE_FORMAT,
            scope: lineage.domain,
            name: "dev".into(),
            from: None,
            to: Some(dev),
        },
        lineage.publisher(),
    )
    .unwrap();
    a.publish_tip_statements(&[
        TipStatement::Opening(opening),
        TipStatement::Bookmark(movement),
    ])
    .await
    .unwrap();
    a.follow_bookmark(lineage.domain, "dev").await.unwrap();
    assert!(
        super::super::kept::at_seal(&a, sealed, query)
            .await
            .is_empty()
    );
    a.follow_bookmark(lineage.domain, "main").await.unwrap();
    assert_eq!(scalar(&a, "SELECT count(*) FROM tags").await, 1);
    assert!(
        super::super::kept::at_seal(&a, sealed, query)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn retained_keyless_ciphertext_satisfies_custody_without_marking_rows_applied() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new()];
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    let b = open(&lineage, &dir, "b", &keys[1]).await;
    follow_main(&lineage, &a).await;
    insert(&a, "one", "one").await;
    let frames = crate::tests::stored_frames(&a, "SELECT header,body FROM secure_operations").await;
    let sealed = seal(&lineage, &a).await.id().unwrap();
    crate::tests::exchange_graphs(&a, &b, lineage.domain).await;
    b.follow_bookmark(lineage.domain, "main").await.unwrap();
    let user = PrivateKey::from_bytes(&rocky_core::commitment(
        "lineage.user",
        keys[1].public_key().as_bytes(),
    ));
    let mut chain = lineage.credentials(3, &keys[1]);
    for (index, link) in chain.0.iter_mut().enumerate() {
        let mut capability = link.capability.clone();
        for grant in &mut capability.grants {
            grant.rights = [Right::Custody].into();
        }
        *link = rocky_credentials::SignedCapability::sign(
            capability,
            if index == 0 {
                lineage.publisher()
            } else {
                &user
            },
        )
        .unwrap();
    }
    b.renew_credentials(chain).await.unwrap();
    assert!(
        b.inner
            .lock(crate::replica::Class::Background)
            .await
            .config
            .keys
            .is_empty()
    );
    for frame in frames {
        b.receive(frame).await.unwrap();
    }
    b.finalize_path(lineage.domain).await.unwrap();
    assert_eq!(
        b.compaction_status(lineage.domain).await.unwrap().finalized,
        Some(sealed)
    );
    assert_eq!(
        scalar(
            &b,
            "SELECT COALESCE(SUM(applied),0) FROM secure_scope_state"
        )
        .await,
        0
    );
    assert_eq!(
        scalar(
            &b,
            "SELECT count(*) FROM secure_operations WHERE status='pending'"
        )
        .await,
        1
    );
    b.compact(lineage.domain, 0).await.unwrap();
    assert!(
        b.unlisted_checkpoints(lineage.domain)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_late_key_with_pending_payload_cannot_sign_an_empty_base() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new()];
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    let b = open(&lineage, &dir, "b", &keys[1]).await;
    follow_main(&lineage, &a).await;
    insert(&a, "one", "one").await;
    let frames = crate::tests::stored_frames(&a, "SELECT header,body FROM secure_operations").await;
    seal(&lineage, &a).await;
    crate::tests::exchange_graphs(&a, &b, lineage.domain).await;
    b.follow_bookmark(lineage.domain, "main").await.unwrap();
    let held_keys = std::mem::take(
        &mut b
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .config
            .keys,
    );
    for frame in frames {
        b.receive(frame).await.unwrap();
    }
    assert_eq!(scalar(&b, "SELECT count(*) FROM secure_applied").await, 0);
    // Stop between installing crypto state and applying its pending payload.
    b.inner
        .lock(crate::replica::Class::Background)
        .await
        .config
        .keys = held_keys;
    let report = b.compact(lineage.domain, 0).await.unwrap();
    assert!(report.waiting.is_some());
    assert!(
        b.unlisted_checkpoints(lineage.domain)
            .await
            .unwrap()
            .is_empty()
    );
    b.settle().await.unwrap();
    b.finalize_path(lineage.domain).await.unwrap();
    assert!(
        b.compaction_status(lineage.domain)
            .await
            .unwrap()
            .waiting
            .is_none()
    );
    assert_eq!(scalar(&b, "SELECT count(*) FROM items").await, 1);
}

#[tokio::test]
async fn an_interrupted_schema_switch_does_not_finalize_future_scope_state() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let path = dir.path().join("a.db");
    let a = lineage.open(&path, &key, 3, None).await.unwrap();
    follow_main(&lineage, &a).await;
    insert(&a, "one", "one").await;
    identity_insert(
        &session(&a).await,
        "INSERT INTO tags(key,label) VALUES('tag','removed')",
        vec![],
    )
    .await
    .unwrap();
    let statements = lineage.publish(&a, 4).await.unwrap();
    a.fail_next_plan_switch().await;
    let result = lineage
        .follow(&a, lineage.config(4, &key), 4, &statements)
        .await;
    assert!(matches!(result, Err(Error::InjectedFailure)), "{result:?}");
    let before = snapshot(&a).await;
    let finalized = scalar(&a, "SELECT count(*) FROM secure_finalized").await;
    a.finalize_path(lineage.domain).await.unwrap();
    assert_eq!(
        scalar(&a, "SELECT count(*) FROM secure_finalized").await,
        finalized
    );
    assert_eq!(snapshot(&a).await, before);
    drop(a);
    let bytes = std::fs::read(&path).unwrap();
    let refused = lineage.reopen(&path, &key, 3, 4).await.err().unwrap();
    assert!(
        refused
            .to_string()
            .contains("installed application differs"),
        "{refused}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let a = lineage.reopen(&path, &key, 3, 3).await.unwrap();
    for name in ["items", "tags"] {
        a.audit(lineage.scope(name)).await.unwrap();
    }
    assert!(a.projection_plan().await.unwrap().is_some());
    lineage
        .follow(&a, lineage.config(4, &key), 4, &statements)
        .await
        .unwrap();
    assert!(a.projection_plan().await.unwrap().is_none());
    assert_eq!(scalar(&a, "SELECT count(*) FROM items").await, 1);
    drop(a);
    let a = lineage.reopen(&path, &key, 3, 4).await.unwrap();
    a.audit(lineage.scope("items")).await.unwrap();
}

#[tokio::test]
async fn a_key_arriving_after_keyless_finalization_verifies_the_scope_at_the_last_seal() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new()];
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    let b = open(&lineage, &dir, "b", &keys[1]).await;
    follow_main(&lineage, &a).await;
    insert(&a, "one", "one").await;
    let frames = crate::tests::stored_frames(&a, "SELECT header,body FROM secure_operations").await;
    let sealed = seal(&lineage, &a).await.id().unwrap();
    crate::tests::exchange_graphs(&a, &b, lineage.domain).await;
    b.follow_bookmark(lineage.domain, "main").await.unwrap();
    let held_keys = std::mem::take(
        &mut b
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .config
            .keys,
    );
    for frame in frames {
        b.receive(frame).await.unwrap();
    }
    b.finalize_path(lineage.domain).await.unwrap();
    assert_eq!(
        b.compaction_status(lineage.domain).await.unwrap().finalized,
        Some(sealed)
    );
    assert_eq!(scalar(&b, "SELECT count(*) FROM secure_applied").await, 0);
    assert_eq!(scalar(&b,"SELECT count(*) FROM secure_seal_bounds b JOIN secure_scope_state s ON s.id=b.scope WHERE s.scope=(SELECT scope FROM secure_operations LIMIT 1)").await,0);
    assert!(
        b.compaction_status(lineage.domain)
            .await
            .unwrap()
            .waiting
            .is_none()
    );
    assert!(
        b.seal_rebootstraps(lineage.domain)
            .await
            .unwrap()
            .is_empty()
    );
    let before = snapshot(&b).await;
    let revision = b.stored_and_memory_revision().await;
    for _ in 0..3 {
        b.finalize_path(lineage.domain).await.unwrap();
    }
    assert_eq!(snapshot(&b).await, before);
    assert_eq!(b.stored_and_memory_revision().await, revision);
    b.inner
        .lock(crate::replica::Class::Background)
        .await
        .config
        .keys = held_keys;
    let pending = b.compact(lineage.domain, 0).await.unwrap();
    assert!(
        b.unlisted_checkpoints(lineage.domain)
            .await
            .unwrap()
            .iter()
            .all(|record| record.table != lineage.scope("items"))
    );
    b.settle().await.unwrap();
    b.finalize_path(lineage.domain).await.unwrap();
    assert_eq!(scalar(&b,"SELECT b.position FROM secure_seal_bounds b JOIN secure_scope_state s ON s.id=b.scope WHERE s.scope=(SELECT scope FROM secure_operations LIMIT 1)").await,1);
    b.compact(lineage.domain, 0).await.unwrap();
    b.admit_peer(
        keys[0].public_key(),
        &lineage.credentials(3, &keys[0]),
        a.followed_tip().await,
    )
    .await
    .unwrap();
    let offered = b
        .checkpoint_offer(
            keys[0].public_key(),
            &lineage.credentials(3, &keys[0]),
            lineage.scope("items"),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(offered.statement.operations, 1);
    assert_eq!(offered.statement.rows.count, 1);
    assert!(pending.waiting.is_some());
}
