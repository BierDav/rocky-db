//! Final admission binds the frozen parent to the original signed frontier.
use super::*;
use crate::{SchemaConfig, SchemaStage};
use rocky_credentials::{SignedTipOpening, TipOpeningStatement};

async fn candidate(lineage: &Lineage, replica: &super::super::compaction::Replica) -> SchemaStage {
    candidate_at(lineage, replica, 2, 3).await
}

async fn candidate_at(
    lineage: &Lineage,
    replica: &super::super::compaction::Replica,
    source_version: u32,
    target_version: u32,
) -> SchemaStage {
    replica
        .publish_tip_statements(&[TipStatement::GenesisLine(
            rocky_credentials::SignedGenesisLine::sign(
                rocky_credentials::GenesisLineStatement {
                    format: 1,
                    scope: lineage.domain,
                    minimum_in_sync: 2,
                },
                lineage.publisher(),
            )
            .unwrap(),
        )])
        .await
        .unwrap();
    let source = replica.followed_tip().await;
    let close = SignedSeal::sign(
        rocky_credentials::SealStatement {
            format: rocky_credentials::SEAL_FORMAT,
            scope: lineage.domain,
            tip: source,
            frontier: replica.seal_frontier(lineage.domain, true).await.unwrap(),
            action: SealAction::Close,
            recovery: None,
        },
        lineage.publisher(),
    )
    .unwrap();
    let opening = SignedTipOpening::sign(
        TipOpeningStatement {
            format: 2,
            scope: lineage.domain,
            seal: close.id().unwrap(),
            schema: lineage.definition(target_version).hash(),
            minimum_in_sync: 2,
        },
        lineage.publisher(),
    )
    .unwrap();
    let target = opening.tip().unwrap();
    SchemaStage {
        publication: rocky_core::commitment("rocky.sdk.migration.v3", &target.0),
        scope: lineage.domain,
        bookmark: "main".into(),
        source,
        target,
        from_version: source_version,
        coordinated: false,
        statements: vec![
            TipStatement::Seal(close),
            TipStatement::Opening(opening),
            bookmark(lineage, Some(source), target),
        ],
        program: vec![],
        parents: vec!["items".into()],
    }
}

async fn graph(replica: &super::super::compaction::Replica, lineage: &Lineage) -> Vec<u8> {
    encode(&replica.tip_graph(lineage.domain).await.unwrap()).unwrap()
}

#[tokio::test]
async fn a_source_write_between_preflight_and_admission_refuses_the_stage_atomically() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let a = lineage
        .open(&dir.path().join("a.db"), &key, 2, None)
        .await
        .unwrap();
    follow_main(&lineage, &a).await;
    insert(&a, "one", "sealed parent").await;
    let stage = candidate(&lineage, &a).await;
    let signed_bytes = encode(&stage).unwrap();
    let (ready, resume) = a.pause_schema_staging().await;
    let mut staging = {
        let a = a.clone();
        let stage = stage.clone();
        tokio::spawn(async move { a.stage_schema(stage).await })
    };
    tokio::select! {
        ready = ready => ready.unwrap(),
        result = &mut staging => panic!("stage completed before preflight pause: {result:?}"),
    }
    // Another task commits through ordinary SQL while staging is outside its guard.
    let write = super::super::generations::identity_insert(
        &session(&a).await,
        "INSERT INTO items(key,title,note) VALUES('late','beyond the signed close','original non-NULL source note')",
        vec![],
    )
    .await
    .unwrap()
    .committed
    .unwrap()
    .frames;
    assert_eq!(write.len(), 1);
    let original = write[0].clone();
    let applied = applied_binding(&a, &original).await;
    assert_eq!(applied.len(), 1);
    assert_ne!(
        a.seal_frontier(lineage.domain, true).await.unwrap(),
        match &stage.statements[0] {
            TipStatement::Seal(seal) => seal.statement.frontier.clone(),
            _ => unreachable!(),
        }
    );
    let before = super::super::compaction::audit::snapshot(&a).await;
    let before_graph = graph(&a, &lineage).await;
    let context = a.schema_context().await;
    let revision = a.stored_and_memory_revision().await;
    resume.send(()).unwrap();
    let error = staging.await.unwrap().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("source frontier changed before schema staging"),
        "{error}"
    );
    assert_eq!(super::super::compaction::audit::snapshot(&a).await, before);
    assert_eq!(graph(&a, &lineage).await, before_graph);
    assert_eq!(a.schema_context().await, context);
    assert_eq!(a.stored_and_memory_revision().await, revision);
    assert!(a.staged_schema().await.unwrap().is_none());
    assert_eq!(encode(&stage).unwrap(), signed_bytes);
}

async fn applied_binding(
    replica: &super::super::compaction::Replica,
    original: &EncryptedFrame,
) -> Vec<Vec<rocky_core::SqlValue>> {
    crate::storage::collect_rows(
        replica
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .conn
            .query(
                "SELECT scope,hash FROM secure_applied WHERE hash=?",
                [original.id().unwrap().as_bytes().to_vec()],
            )
            .await
            .unwrap(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn racing_stages_recheck_private_state_before_admission() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let a = lineage
        .open(&dir.path().join("a.db"), &key, 2, None)
        .await
        .unwrap();
    follow_main(&lineage, &a).await;
    let stage = candidate(&lineage, &a).await;
    let (ready, resume) = a.pause_schema_staging().await;
    let mut first = {
        let a = a.clone();
        let stage = stage.clone();
        tokio::spawn(async move { a.stage_schema(stage).await })
    };
    tokio::select! {
        ready = ready => ready.unwrap(),
        result = &mut first => panic!("stage completed before preflight pause: {result:?}"),
    }
    a.stage_schema(stage.clone()).await.unwrap();
    let before = super::super::compaction::audit::snapshot(&a).await;
    let before_graph = graph(&a, &lineage).await;
    let context = a.schema_context().await;
    resume.send(()).unwrap();
    let error = first.await.unwrap().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("a schema publication is already pending"),
        "{error}"
    );
    assert_eq!(super::super::compaction::audit::snapshot(&a).await, before);
    assert_eq!(graph(&a, &lineage).await, before_graph);
    assert_eq!(a.schema_context().await, context);
    assert_eq!(
        a.staged_schema().await.unwrap().unwrap().0.publication,
        stage.publication
    );
    a.withdraw_staged_schema(
        stage.publication,
        lineage.app(2),
        SchemaConfig {
            security: lineage.config(2, &key),
            tables: Some(lineage.projection(2)),
        },
    )
    .await
    .unwrap();
    a.audit(lineage.scope("items")).await.unwrap();
}

#[tokio::test]
async fn a_source_move_between_preflight_and_admission_refuses_the_stage_atomically() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let a = lineage
        .open(&dir.path().join("a.db"), &key, 2, None)
        .await
        .unwrap();
    follow_main(&lineage, &a).await;
    let stage = candidate(&lineage, &a).await;
    let (ready, resume) = a.pause_schema_staging().await;
    let mut staging = {
        let a = a.clone();
        let stage = stage.clone();
        tokio::spawn(async move { a.stage_schema(stage).await })
    };
    tokio::select! {
        ready = ready => ready.unwrap(),
        result = &mut staging => panic!("stage completed before preflight pause: {result:?}"),
    }
    let seal = SignedSeal::sign(
        rocky_credentials::SealStatement {
            format: rocky_credentials::SEAL_FORMAT,
            scope: lineage.domain,
            tip: stage.source,
            frontier: a.seal_frontier(lineage.domain, false).await.unwrap(),
            action: SealAction::Continue {
                schema: lineage.definition(2).hash(),
            },
            recovery: None,
        },
        lineage.publisher(),
    )
    .unwrap();
    let target = seal.successor().unwrap().unwrap();
    a.publish_tip_statements(&[
        TipStatement::Seal(seal),
        bookmark(&lineage, Some(stage.source), target),
    ])
    .await
    .unwrap();
    assert_eq!(a.followed_tip().await, target);
    let before = super::super::compaction::audit::snapshot(&a).await;
    let before_graph = graph(&a, &lineage).await;
    let context = a.schema_context().await;
    resume.send(()).unwrap();
    let error = staging.await.unwrap().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("schema publication must leave its followed open tip"),
        "{error}"
    );
    assert_eq!(super::super::compaction::audit::snapshot(&a).await, before);
    assert_eq!(graph(&a, &lineage).await, before_graph);
    assert_eq!(a.schema_context().await, context);
    assert!(a.staged_schema().await.unwrap().is_none());
    a.audit(lineage.scope("items")).await.unwrap();
}
