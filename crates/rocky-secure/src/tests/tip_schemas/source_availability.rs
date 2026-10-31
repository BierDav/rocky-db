//! An unrelated exact source definition is acquired through the normal catalog API.
use super::super::generations::identity_insert;
use super::*;
use rocky_core::RowApplication;
use rocky_credentials::{SignedTipOpening, TipOpeningStatement};

#[tokio::test]
async fn a_missing_held_source_catalog_refuses_then_retries_its_exact_definition() {
    let lineage = Lineage::pinned(190);
    let dir = TempDir::new().unwrap();
    let source_key = PrivateKey::from_bytes(&[191; 32]);
    let target_key = PrivateKey::from_bytes(&[192; 32]);
    let source = lineage
        .open_certified(
            &dir.path().join("source.db"),
            (lineage.publisher(), &source_key),
            2,
            None,
        )
        .await
        .unwrap();
    let target = lineage
        .open(&dir.path().join("target.db"), &target_key, 2, None)
        .await
        .unwrap();
    let root = source.followed_tip().await;
    let close = SignedSeal::sign(
        rocky_credentials::SealStatement {
            format: rocky_credentials::SEAL_FORMAT,
            scope: lineage.domain,
            tip: root,
            frontier: vec![],
            action: SealAction::Close,
            recovery: None,
        },
        lineage.publisher(),
    )
    .unwrap();
    let opening = |version| {
        SignedTipOpening::sign(
            TipOpeningStatement {
                format: rocky_credentials::TIP_OPENING_FORMAT,
                scope: lineage.domain,
                seal: close.id().unwrap(),
                schema: lineage.definition(version).hash(),
                minimum_in_sync: 1,
            },
            lineage.publisher(),
        )
        .unwrap()
    };
    let source_opening = opening(3);
    let target_opening = opening(4);
    let source_tip = source_opening.tip().unwrap();
    let target_tip = target_opening.tip().unwrap();
    let bookmark = |name: &str, tip| {
        TipStatement::Bookmark(
            rocky_credentials::SignedBookmarkMove::sign(
                rocky_credentials::BookmarkMoveStatement {
                    format: rocky_credentials::BOOKMARK_MOVE_FORMAT,
                    scope: lineage.domain,
                    name: name.into(),
                    from: None,
                    to: Some(tip),
                },
                lineage.publisher(),
            )
            .unwrap(),
        )
    };
    let minimum = TipStatement::GenesisLine(
        rocky_credentials::SignedGenesisLine::sign(
            rocky_credentials::GenesisLineStatement {
                format: 1,
                scope: lineage.domain,
                minimum_in_sync: 1,
            },
            lineage.publisher(),
        )
        .unwrap(),
    );
    let mut statements = vec![
        minimum.clone(),
        TipStatement::Seal(close.clone()),
        TipStatement::Opening(source_opening.clone()),
        TipStatement::Opening(target_opening),
        bookmark("dev", source_tip),
        bookmark("main", target_tip),
    ];
    source
        .publish_tip_statements(&[minimum, bookmark("dev", root)])
        .await
        .unwrap();
    source.follow_bookmark(lineage.domain, "dev").await.unwrap();
    let publication = rocky_core::commitment("rocky.sdk.migration.v3", &source_tip.0);
    source
        .stage_schema(crate::SchemaStage {
            publication,
            scope: lineage.domain,
            bookmark: "dev".into(),
            source: root,
            target: source_tip,
            from_version: 2,
            coordinated: false,
            statements: vec![
                TipStatement::Seal(close),
                TipStatement::Opening(source_opening),
                TipStatement::Bookmark(
                    rocky_credentials::SignedBookmarkMove::sign(
                        rocky_credentials::BookmarkMoveStatement {
                            format: rocky_credentials::BOOKMARK_MOVE_FORMAT,
                            scope: lineage.domain,
                            name: "dev".into(),
                            from: Some(root),
                            to: Some(source_tip),
                        },
                        lineage.publisher(),
                    )
                    .unwrap(),
                ),
            ],
            program: vec![],
            parents: vec![],
        })
        .await
        .unwrap();
    source
        .install_tip_schema(source_tip, lineage.definition(3), b"verified".to_vec())
        .await
        .unwrap();
    let mut config = lineage.config(3, &source_key);
    config.credentials = lineage.certified(3, lineage.publisher(), &source_key);
    config.manifest = lineage.config(2, &source_key).manifest;
    source
        .switch_schema(
            source_tip,
            lineage.app(3),
            crate::SchemaConfig {
                security: config,
                tables: Some(lineage.projection(3)),
            },
        )
        .await
        .unwrap();
    let writer = PrivateKey::from_bytes(&[198; 32]);
    source
        .register_line_node(crate::LineNode {
            credentials: lineage.certified(3, lineage.publisher(), &writer),
            key: writer,
        })
        .await
        .unwrap();
    let migration = source
        .session([lineage.scope("items")].into())
        .await
        .unwrap()
        .migration_sql(publication, crate::sql::SqlOptions::default())
        .await
        .unwrap();
    migration.run("BEGIN", vec![]).await.unwrap();
    assert!(
        migration
            .commit_publication(publication)
            .await
            .unwrap()
            .committed
            .unwrap()
            .frames
            .is_empty()
    );
    drop(migration);
    let (intent, writer) = source.migration_intent(publication).await.unwrap().unwrap();
    let descriptor = rocky_credentials::SignedMigrationPublication::endorse(
        intent,
        lineage.publisher(),
        &CredentialChain::default(),
        writer,
    )
    .unwrap();
    source
        .admit_migration_publication(descriptor.clone())
        .await
        .unwrap();
    source
        .release_uncoordinated_schema(publication)
        .await
        .unwrap();
    let frames = identity_insert(
        &session(&source).await,
        "INSERT INTO items(key,title,note) VALUES('held','source3','exact source note')",
        vec![],
    )
    .await
    .unwrap()
    .committed
    .unwrap()
    .frames;
    let close_source = SignedSeal::sign(
        rocky_credentials::SealStatement {
            format: rocky_credentials::SEAL_FORMAT,
            scope: lineage.domain,
            tip: source_tip,
            frontier: vec![],
            action: SealAction::Close,
            recovery: None,
        },
        lineage.publisher(),
    )
    .unwrap();
    let reopened = SignedTipOpening::sign(
        TipOpeningStatement {
            format: rocky_credentials::TIP_OPENING_FORMAT,
            scope: lineage.domain,
            seal: close_source.id().unwrap(),
            schema: lineage.definition(3).hash(),
            minimum_in_sync: 1,
        },
        lineage.publisher(),
    )
    .unwrap();
    let dev = reopened.tip().unwrap();
    statements.extend([
        TipStatement::Seal(close_source),
        TipStatement::Opening(reopened),
        TipStatement::Bookmark(
            rocky_credentials::SignedBookmarkMove::sign(
                rocky_credentials::BookmarkMoveStatement {
                    format: rocky_credentials::BOOKMARK_MOVE_FORMAT,
                    scope: lineage.domain,
                    name: "dev".into(),
                    from: Some(source_tip),
                    to: Some(dev),
                },
                lineage.publisher(),
            )
            .unwrap(),
        ),
    ]);
    target.receive_tip_statements(&statements).await.unwrap();
    target
        .follow_bookmark(lineage.domain, "main")
        .await
        .unwrap();
    target
        .install_tip_schema(target_tip, lineage.definition(4), b"verified".to_vec())
        .await
        .unwrap();
    let mut config = lineage.config(4, &target_key);
    config.manifest = lineage.config(2, &target_key).manifest;
    target
        .switch_schema(
            target_tip,
            lineage.app(4),
            crate::SchemaConfig {
                security: config,
                tables: Some(lineage.projection(4)),
            },
        )
        .await
        .unwrap();
    assert!(
        target
            .tip_schema(lineage.definition(3).hash())
            .await
            .unwrap()
            .is_none()
    );
    let before = super::super::compaction::audit::snapshot(&target).await;
    let error = target
        .receive_held_frames(frames.clone())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("held source schema is not installed"),
        "{error}"
    );
    assert_eq!(
        super::super::compaction::audit::snapshot(&target).await,
        before
    );
    // Acquisition remains scoped: explicitly follow the source branch to require its catalog.
    target.follow_bookmark(lineage.domain, "dev").await.unwrap();
    assert!(
        target
            .required_schemas()
            .await
            .unwrap()
            .contains(&(source_tip, lineage.definition(3).hash()))
    );
    let acquisition = super::super::compaction::audit::snapshot(&target).await;
    let mut wrong = lineage.definition(3);
    wrong.projection += 1;
    assert_eq!(wrong.schema, 3);
    assert_ne!(wrong.hash(), lineage.definition(3).hash());
    assert!(
        target
            .install_tip_schema(source_tip, wrong, b"wrong same version".to_vec())
            .await
            .is_err()
    );
    assert_eq!(
        super::super::compaction::audit::snapshot(&target).await,
        acquisition
    );
    target
        .install_tip_schema(
            source_tip,
            lineage.definition(3),
            b"verified exact source".to_vec(),
        )
        .await
        .unwrap();
    target
        .admit_migration_publication(descriptor)
        .await
        .unwrap();
    target
        .follow_bookmark(lineage.domain, "main")
        .await
        .unwrap();
    assert_eq!(
        target
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .app
            .manifest()
            .hash(),
        lineage.definition(4).hash()
    );
    target.receive_held_frames(frames.clone()).await.unwrap();
    // An intent is held whole, with no rows to re-author.
    assert!(target.held_changes().await.unwrap().is_empty());
    target.audit(lineage.scope("items")).await.unwrap();
}
