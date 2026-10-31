//! A durable switch changes the audit transform, never whether history is audited.
use super::*;

/// `version`'s configuration under the domain root of generation 3.
fn rooted(lineage: &Lineage, version: u32, key: &PrivateKey) -> crate::SecureConfig {
    let mut config = lineage.config(version, key);
    config.manifest = lineage.config(3, key).manifest;
    config
}

async fn interrupt(
    lineage: &Lineage,
    dir: &TempDir,
    key: &PrivateKey,
) -> (Replica, Vec<TipStatement>) {
    let a = open(lineage, dir, "a", key).await;
    follow_main(lineage, &a).await;
    insert(&a, "one", "signed title").await;
    identity_insert(
        &session(&a).await,
        "INSERT INTO tags(key,label) VALUES('tag','removed')",
        vec![],
    )
    .await
    .unwrap();
    let statements = lineage.publish(&a, 4).await.unwrap();
    a.fail_next_plan_switch().await;
    assert!(matches!(
        lineage
            .follow(&a, lineage.config(4, key), 4, &statements)
            .await,
        Err(Error::InjectedFailure)
    ));
    (a, statements)
}

#[tokio::test]
async fn a_different_staged_target_is_refused_before_writes() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let (a, _) = interrupt(&lineage, &dir, &key).await;
    let staged = a.pending_schema().await.unwrap().unwrap().tip;
    let seal = SignedSeal::sign(
        SealStatement {
            format: SEAL_FORMAT,
            scope: lineage.domain,
            tip: staged,
            frontier: vec![],
            action: SealAction::Continue {
                schema: lineage.definition(4).hash(),
            },
            recovery: None,
        },
        lineage.publisher(),
    )
    .unwrap();
    let next = seal.successor().unwrap().unwrap();
    a.receive_tip_statements(&[
        TipStatement::Seal(seal),
        bookmark(&lineage, Some(staged), next),
    ])
    .await
    .unwrap();
    let before = crate::storage::rows(
        &a.inner.lock(crate::replica::Class::Background).await.conn,
        "SELECT total_changes()",
    )
    .await
    .unwrap();
    let revision = a.stored_and_memory_revision().await;
    let intent = crate::storage::rows(
        &a.inner.lock(crate::replica::Class::Background).await.conn,
        "SELECT scope,bookmark,source,target FROM secure_schema_switch",
    )
    .await
    .unwrap();
    let error = a
        .switch_schema(
            next,
            lineage.app(4),
            crate::SchemaConfig {
                security: lineage.config(4, &key),
                tables: Some(lineage.projection(4)),
            },
        )
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("different schema switch is staged"),
        "{error}"
    );
    assert_eq!(
        crate::storage::rows(
            &a.inner.lock(crate::replica::Class::Background).await.conn,
            "SELECT total_changes()"
        )
        .await
        .unwrap(),
        before
    );
    assert_eq!(a.stored_and_memory_revision().await, revision);
    assert_eq!(
        crate::storage::rows(
            &a.inner.lock(crate::replica::Class::Background).await.conn,
            "SELECT scope,bookmark,source,target FROM secure_schema_switch"
        )
        .await
        .unwrap(),
        intent
    );
}

#[tokio::test]
async fn a_moved_bookmark_after_a_switch_crash_can_resume_the_saved_target() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let (a, _) = interrupt(&lineage, &dir, &key).await;
    let staged = a.pending_schema().await.unwrap().unwrap().tip;
    drop(a);
    let a = lineage
        .reopen(&dir.path().join("a.db"), &key, 3, 3)
        .await
        .unwrap();
    let seal = SignedSeal::sign(
        SealStatement {
            format: SEAL_FORMAT,
            scope: lineage.domain,
            tip: staged,
            frontier: vec![],
            action: SealAction::Continue {
                schema: lineage.definition(4).hash(),
            },
            recovery: None,
        },
        lineage.publisher(),
    )
    .unwrap();
    let next = seal.successor().unwrap().unwrap();
    a.receive_tip_statements(&[
        TipStatement::Seal(seal),
        bookmark(&lineage, Some(staged), next),
    ])
    .await
    .unwrap();
    a.switch_schema(
        staged,
        lineage.app(4),
        crate::SchemaConfig {
            security: rooted(&lineage, 4, &key),
            tables: Some(lineage.projection(4)),
        },
    )
    .await
    .unwrap();
    // It finished at the staged target and advanced with the bookmark.
    assert!(a.projection_plan().await.unwrap().is_none());
    assert_eq!(scalar(&a, "SELECT count(*) FROM items").await, 1);
    assert_eq!(a.followed_tip().await, next);
    assert!(a.pending_schema().await.unwrap().is_none());
    assert_eq!(intents(&a).await, 0);
    assert_eq!(
        a.followed_bookmark().await.map(|(_, name)| name).as_deref(),
        Some("main")
    );
    drop(a);
    let a = lineage
        .reopen(&dir.path().join("a.db"), &key, 3, 4)
        .await
        .unwrap();
    a.audit(lineage.scope("items")).await.unwrap();
    assert_eq!(a.followed_tip().await, next);
}

#[tokio::test]
async fn a_sideways_switch_audits_with_the_stored_target_definition() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let a = open(&lineage, &dir, "a", &key).await;
    follow_main(&lineage, &a).await;
    insert(&a, "one", "one").await;
    let sealed = seal(&lineage, &a).await.id().unwrap();
    let opening = rocky_credentials::SignedTipOpening::sign(
        rocky_credentials::TipOpeningStatement {
            format: rocky_credentials::TIP_OPENING_FORMAT,
            scope: lineage.domain,
            seal: sealed,
            schema: lineage.definition(4).hash(),
            minimum_in_sync: 1,
        },
        lineage.publisher(),
    )
    .unwrap();
    let dev = opening.tip().unwrap();
    a.publish_tip_statements(&[
        TipStatement::Opening(opening),
        TipStatement::Bookmark(
            SignedBookmarkMove::sign(
                BookmarkMoveStatement {
                    format: BOOKMARK_MOVE_FORMAT,
                    scope: lineage.domain,
                    name: "dev".into(),
                    from: None,
                    to: Some(dev),
                },
                lineage.publisher(),
            )
            .unwrap(),
        ),
    ])
    .await
    .unwrap();
    a.follow_bookmark(lineage.domain, "dev").await.unwrap();
    lineage.install_required(&a).await;
    a.fail_next_plan_switch().await;
    let mut config = lineage.config(4, &key);
    config.manifest = lineage.config(3, &key).manifest;
    assert!(matches!(
        a.switch_schema(
            dev,
            lineage.app(4),
            crate::SchemaConfig {
                security: config,
                tables: Some(lineage.projection(4))
            }
        )
        .await,
        Err(Error::InjectedFailure)
    ));
    drop(a);
    let a = lineage
        .reopen(&dir.path().join("a.db"), &key, 3, 3)
        .await
        .unwrap();
    a.audit(lineage.scope("items")).await.unwrap();
    let mut config = lineage.config(4, &key);
    config.manifest = lineage.config(3, &key).manifest;
    a.switch_schema(
        dev,
        lineage.app(4),
        crate::SchemaConfig {
            security: config,
            tables: Some(lineage.projection(4)),
        },
    )
    .await
    .unwrap();
    assert_eq!(scalar(&a, "SELECT count(*) FROM items").await, 1);
    assert_eq!(
        a.followed_bookmark().await.map(|(_, name)| name).as_deref(),
        Some("dev")
    );
}

/// Rows of the staged switch intent.
async fn intents(a: &Replica) -> usize {
    crate::storage::rows(
        &a.inner.lock(crate::replica::Class::Background).await.conn,
        "SELECT 1 FROM secure_schema_switch",
    )
    .await
    .unwrap()
    .len()
}
async fn changes(a: &Replica) -> Vec<Vec<SqlValue>> {
    crate::storage::rows(
        &a.inner.lock(crate::replica::Class::Background).await.conn,
        "SELECT total_changes()",
    )
    .await
    .unwrap()
}
/// Switches `a` to `tip` with `version`'s schema.
async fn switch(
    lineage: &Lineage,
    a: &Replica,
    key: &PrivateKey,
    tip: TipId,
    version: u32,
) -> Result<bool, Error> {
    lineage.install_required(a).await;
    a.switch_schema(
        tip,
        lineage.app(version),
        crate::SchemaConfig {
            security: rooted(lineage, version, key),
            tables: Some(lineage.projection(version)),
        },
    )
    .await
}
/// A v3 replica with an item and a tag whose switch to the v4 target,
/// which removes `tags`, stopped before its final transaction. Returns
/// the replica, the source tip and the staged target.
async fn interrupted(
    lineage: &Lineage,
    dir: &TempDir,
    key: &PrivateKey,
) -> (Replica, TipId, TipId) {
    interrupted_offering(lineage, dir, key, true).await
}
/// [`interrupted`]; with `offered`, a peer was served both writes before
/// the switch, so no unsent bundle is held.
async fn interrupted_offering(
    lineage: &Lineage,
    dir: &TempDir,
    key: &PrivateKey,
    offered: bool,
) -> (Replica, TipId, TipId) {
    let a = open(lineage, dir, "a", key).await;
    follow_main(lineage, &a).await;
    insert(&a, "one", "signed title").await;
    identity_insert(
        &session(&a).await,
        "INSERT INTO tags(key,label) VALUES('tag','removed')",
        vec![],
    )
    .await
    .unwrap();
    let source = a.followed_tip().await;
    if offered {
        offer(lineage, &a).await;
    }
    let statements = lineage.publish(&a, 4).await.unwrap();
    a.fail_next_plan_switch().await;
    assert!(matches!(
        lineage
            .follow(&a, lineage.config(4, key), 4, &statements)
            .await,
        Err(Error::InjectedFailure)
    ));
    let target = a.pending_schema().await.unwrap().unwrap().tip;
    (a, source, target)
}
/// Serves `a`'s item and tag writes to a peer: they are no longer unsent.
async fn offer(lineage: &Lineage, a: &Replica) {
    let peer = PrivateKey::new();
    let credentials = lineage.credentials(3, &peer);
    a.admit_peer(peer.public_key(), &credentials, a.followed_tip().await)
        .await
        .unwrap();
    for scope in [lineage.scope("items"), lineage.scope("tags")] {
        let page = a
            .range_page(
                peer.public_key(),
                &credentials,
                &ScopeFrontier {
                    scope,
                    logs: vec![],
                },
                None,
                MAX_SECURE_FRAME,
            )
            .await
            .unwrap();
        assert_eq!(page.frames.len(), 1);
    }
}
/// The owner's `continue` seal of `tip` to `version`'s schema.
fn continued(lineage: &Lineage, tip: TipId, version: u32) -> SignedSeal {
    SignedSeal::sign(
        SealStatement {
            format: SEAL_FORMAT,
            scope: lineage.domain,
            tip,
            frontier: vec![],
            action: SealAction::Continue {
                schema: lineage.definition(version).hash(),
            },
            recovery: None,
        },
        lineage.publisher(),
    )
    .unwrap()
}
/// The source is installed again, its removed rows are back and nothing
/// of the switch remains.
async fn withdrawn(a: &Replica) {
    assert_eq!(intents(a).await, 0);
    assert!(a.projection_plan().await.unwrap().is_none());
    assert!(a.pending_schema().await.unwrap().is_none());
    assert_eq!(scalar(a, "SELECT count(*) FROM tags").await, 1);
    assert_eq!(scalar(a, "SELECT count(*) FROM items").await, 1);
    assert_ne!(
        a.compaction_status(a.followed_bookmark().await.unwrap().0)
            .await
            .unwrap()
            .waiting
            .as_deref(),
        Some("the schema switch is unfinished")
    );
}

#[tokio::test]
async fn in_process_the_staged_intent_stays_the_only_authority_until_resumed() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let (a, source, target) = interrupted(&lineage, &dir, &key).await;
    // A failed plan leaves the source installed.
    assert_eq!(a.followed_tip().await, source);
    let seal = continued(&lineage, target, 4);
    let next = seal.successor().unwrap().unwrap();
    a.receive_tip_statements(&[
        TipStatement::Seal(seal),
        bookmark(&lineage, Some(target), next),
    ])
    .await
    .unwrap();
    // The move continues from the target: admission keeps the intent.
    assert_eq!(a.followed_tip().await, source);
    assert_eq!(a.pending_schema().await.unwrap().unwrap().tip, target);
    assert_eq!(intents(&a).await, 1);
    assert!(switch(&lineage, &a, &key, target, 4).await.unwrap());
    assert_eq!(a.followed_tip().await, next);
    assert!(a.pending_schema().await.unwrap().is_none());
    assert_eq!(intents(&a).await, 0);
    assert_eq!(scalar(&a, "SELECT count(*) FROM items").await, 1);
    drop(a);
    let a = lineage
        .reopen(&dir.path().join("a.db"), &key, 3, 4)
        .await
        .unwrap();
    a.audit(lineage.scope("items")).await.unwrap();
}

#[tokio::test]
async fn a_descendant_with_another_schema_finishes_at_the_target_then_waits_for_its_own() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let (a, _, target) = interrupted(&lineage, &dir, &key).await;
    let seal = continued(&lineage, target, 3);
    let next = seal.successor().unwrap().unwrap();
    a.receive_tip_statements(&[
        TipStatement::Seal(seal),
        bookmark(&lineage, Some(target), next),
    ])
    .await
    .unwrap();
    assert!(switch(&lineage, &a, &key, target, 4).await.unwrap());
    assert_eq!(a.followed_tip().await, target);
    assert_eq!(intents(&a).await, 0);
    let pending = a.pending_schema().await.unwrap().unwrap();
    assert_eq!(pending.tip, next);
    assert_eq!(pending.manifest, lineage.definition(3).hash());
    assert!(switch(&lineage, &a, &key, next, 3).await.unwrap());
    assert_eq!(a.followed_tip().await, next);
    assert!(a.pending_schema().await.unwrap().is_none());
    assert_eq!(scalar(&a, "SELECT count(*) FROM items").await, 1);
}

#[tokio::test]
async fn a_sideways_move_with_a_close_seal_withdraws_the_staged_switch() {
    for reopened in [false, true] {
        let lineage = Lineage::new();
        let dir = TempDir::new().unwrap();
        let key = PrivateKey::new();
        let (a, source, target) = interrupted(&lineage, &dir, &key).await;
        let a = if reopened {
            drop(a);
            lineage
                .reopen(&dir.path().join("a.db"), &key, 3, 3)
                .await
                .unwrap()
        } else {
            a
        };
        let graph = a.tip_graph(lineage.domain).await.unwrap();
        let sealed = graph.seal(source).unwrap().unwrap().id().unwrap();
        let opening = rocky_credentials::SignedTipOpening::sign(
            rocky_credentials::TipOpeningStatement {
                format: rocky_credentials::TIP_OPENING_FORMAT,
                scope: lineage.domain,
                seal: sealed,
                schema: lineage.definition(3).hash(),
                minimum_in_sync: 1,
            },
            lineage.publisher(),
        )
        .unwrap();
        let sideways = opening.tip().unwrap();
        let close = SignedSeal::sign(
            SealStatement {
                format: SEAL_FORMAT,
                scope: lineage.domain,
                tip: target,
                frontier: vec![],
                action: SealAction::Close,
                recovery: None,
            },
            lineage.publisher(),
        )
        .unwrap();
        a.receive_tip_statements(&[
            TipStatement::Opening(opening),
            TipStatement::Seal(close),
            bookmark(&lineage, Some(target), sideways),
        ])
        .await
        .unwrap();
        withdrawn(&a).await;
        assert_eq!(a.followed_tip().await, sideways);
        // The withdrawn target is refused like any other non-followed tip.
        let before = changes(&a).await;
        assert!(switch(&lineage, &a, &key, target, 4).await.is_err());
        assert_eq!(changes(&a).await, before);
        drop(a);
        let a = lineage
            .reopen(&dir.path().join("a.db"), &key, 3, 3)
            .await
            .unwrap();
        a.audit(lineage.scope("items")).await.unwrap();
        a.audit(lineage.scope("tags")).await.unwrap();
        assert_eq!(scalar(&a, "SELECT count(*) FROM tags").await, 1);
    }
}

#[tokio::test]
async fn a_deleted_bookmark_withdraws_the_staged_switch_and_stays_at_the_source() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let (a, source, target) = interrupted(&lineage, &dir, &key).await;
    delete_main(&lineage, &a, target).await;
    withdrawn(&a).await;
    assert_eq!(a.followed_tip().await, source);
    assert_eq!(
        a.followed_bookmark().await.map(|(_, name)| name).as_deref(),
        Some("main")
    );
    drop(a);
    let a = lineage
        .reopen(&dir.path().join("a.db"), &key, 3, 3)
        .await
        .unwrap();
    a.audit(lineage.scope("tags")).await.unwrap();
}

/// The owner deletes `main`, which pointed at `target`.
async fn delete_main(lineage: &Lineage, a: &Replica, target: TipId) {
    let deleted = TipStatement::Bookmark(
        SignedBookmarkMove::sign(
            BookmarkMoveStatement {
                format: BOOKMARK_MOVE_FORMAT,
                scope: lineage.domain,
                name: "main".into(),
                from: Some(target),
                to: None,
            },
            lineage.publisher(),
        )
        .unwrap(),
    );
    a.receive_tip_statements(&[deleted]).await.unwrap();
}

#[tokio::test]
async fn a_revoked_target_withdraws_the_staged_switch() {
    use rocky_credentials::{Authority, CredentialChain};
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let a = open(&lineage, &dir, "a", &key).await;
    follow_main(&lineage, &a).await;
    insert(&a, "one", "signed title").await;
    identity_insert(
        &session(&a).await,
        "INSERT INTO tags(key,label) VALUES('tag','removed')",
        vec![],
    )
    .await
    .unwrap();
    offer(&lineage, &a).await;
    let source = a.followed_tip().await;
    // An issuer, later revoked, seals the source and moves `main`.
    let issuer = PrivateKey::new();
    let chain = CredentialChain(vec![
        Authority::owner(lineage.publisher())
            .issue_issuer(issuer.public_key(), None, crate::tests::validity())
            .unwrap(),
    ]);
    let seal = SignedSeal::endorse(
        SealStatement {
            format: SEAL_FORMAT,
            scope: lineage.domain,
            tip: source,
            frontier: a.seal_frontier(lineage.domain, false).await.unwrap(),
            action: SealAction::Continue {
                schema: lineage.definition(4).hash(),
            },
            recovery: None,
        },
        &issuer,
        &chain,
    )
    .unwrap();
    let target = seal.successor().unwrap().unwrap();
    let TipStatement::Bookmark(unsigned) = bookmark(&lineage, Some(source), target) else {
        unreachable!()
    };
    let moved = SignedBookmarkMove::endorse(unsigned.statement, &issuer, &chain).unwrap();
    a.receive_tip_statements(&[TipStatement::Seal(seal), TipStatement::Bookmark(moved)])
        .await
        .unwrap();
    a.fail_next_plan_switch().await;
    assert!(matches!(
        switch(&lineage, &a, &key, target, 4).await,
        Err(Error::InjectedFailure)
    ));
    assert_eq!(intents(&a).await, 1);
    let revoked = crate::tests::revoking(
        lineage.publisher(),
        lineage.domain.app,
        &[issuer.public_key()],
        &[],
    );
    a.learn_revocations(&revoked).await.unwrap();
    withdrawn(&a).await;
    assert_eq!(a.followed_tip().await, source);
}

#[tokio::test]
async fn an_own_publication_withdraws_with_its_staged_switch() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let a = open(&lineage, &dir, "a", &key).await;
    follow_main(&lineage, &a).await;
    insert(&a, "one", "signed title").await;
    identity_insert(
        &session(&a).await,
        "INSERT INTO tags(key,label) VALUES('tag','removed')",
        vec![],
    )
    .await
    .unwrap();
    offer(&lineage, &a).await;
    let source = a.followed_tip().await;
    let mut statement = sign_seal(
        &lineage,
        source,
        a.seal_frontier(lineage.domain, false).await.unwrap(),
    )
    .statement;
    statement.action = SealAction::Continue {
        schema: lineage.definition(4).hash(),
    };
    let seal = SignedSeal::sign(statement, lineage.publisher()).unwrap();
    let target = seal.successor().unwrap().unwrap();
    let publication = rocky_core::commitment("own.stage", &target.0);
    a.stage_schema(crate::SchemaStage {
        publication,
        scope: lineage.domain,
        bookmark: "main".into(),
        source,
        target,
        from_version: 3,
        coordinated: false,
        statements: vec![
            TipStatement::Seal(seal),
            bookmark(&lineage, Some(source), target),
        ],
        program: vec![],
        parents: vec![],
    })
    .await
    .unwrap();
    a.install_tip_schema(target, lineage.definition(4), b"verified".to_vec())
        .await
        .unwrap();
    a.fail_next_plan_switch().await;
    assert!(matches!(
        switch(&lineage, &a, &key, target, 4).await,
        Err(Error::InjectedFailure)
    ));
    assert_eq!(intents(&a).await, 1);
    let graph = encode(&a.tip_graph(lineage.domain).await.unwrap()).unwrap();
    let context = a.schema_context().await;
    let before = super::audit::snapshot(&a).await;
    let revision = a.stored_and_memory_revision().await;
    let error = a
        .withdraw_staged_schema(
            publication,
            lineage.app(4),
            crate::SchemaConfig {
                security: rooted(&lineage, 4, &key),
                tables: Some(lineage.projection(4)),
            },
        )
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("needs its source schema installed"),
        "{error}"
    );
    assert_eq!(
        encode(&a.tip_graph(lineage.domain).await.unwrap()).unwrap(),
        graph
    );
    assert_eq!(a.schema_context().await, context);
    assert_eq!(a.stored_and_memory_revision().await, revision);
    assert_eq!(super::audit::snapshot(&a).await, before);
    // A failure after withdrawal has begun must restore the same live context.
    a.inner.lock(crate::replica::Class::Background).await.conn.execute(
        "CREATE TEMP TRIGGER fail_withdraw AFTER DELETE ON secure_projection_plan BEGIN SELECT RAISE(ABORT,'withdraw rollback'); END", ()
    ).await.unwrap();
    let error = a
        .withdraw_staged_schema(
            publication,
            lineage.app(3),
            crate::SchemaConfig {
                security: rooted(&lineage, 3, &key),
                tables: Some(lineage.projection(3)),
            },
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("withdraw rollback"), "{error}");
    assert_eq!(
        encode(&a.tip_graph(lineage.domain).await.unwrap()).unwrap(),
        graph
    );
    assert_eq!(a.schema_context().await, context);
    assert_eq!(a.stored_and_memory_revision().await, revision);
    assert_eq!(super::audit::snapshot(&a).await, before);
    a.inner
        .lock(crate::replica::Class::Background)
        .await
        .conn
        .execute("DROP TRIGGER fail_withdraw", ())
        .await
        .unwrap();
    a.withdraw_staged_schema(
        publication,
        lineage.app(3),
        crate::SchemaConfig {
            security: rooted(&lineage, 3, &key),
            tables: Some(lineage.projection(3)),
        },
    )
    .await
    .unwrap();
    withdrawn(&a).await;
    assert_eq!(a.followed_tip().await, source);
    assert!(a.staged_schema().await.unwrap().is_none());
    drop(a);
    let a = lineage
        .reopen(&dir.path().join("a.db"), &key, 3, 3)
        .await
        .unwrap();
    a.audit(lineage.scope("tags")).await.unwrap();
}
