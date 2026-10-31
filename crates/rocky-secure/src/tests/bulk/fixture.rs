use super::*;
type Candidate = (
    Lineage,
    TempDir,
    PrivateKey,
    EncryptedReplica<TypedRows>,
    SignedMigrationPublication,
);
pub(super) async fn candidate(n: usize) -> Candidate {
    candidate_tables(n, false).await
}
pub(super) async fn candidate_tables(n: usize, tags: bool) -> Candidate {
    candidate_kind(n, tags, false).await.0
}
pub(super) async fn issuer_candidate() -> (Candidate, PrivateKey) {
    let (candidate, issuer) = candidate_kind(1, false, true).await;
    (candidate, issuer.unwrap())
}
async fn candidate_kind(n: usize, tags: bool, issuer: bool) -> (Candidate, Option<PrivateKey>) {
    let l = if issuer {
        Lineage::pinned(139)
    } else {
        Lineage::new()
    };
    let issuer = issuer.then(|| PrivateKey::from_bytes(&[140; 32]));
    let signer = issuer.as_ref().unwrap_or(l.publisher());
    let endorsement = issuer
        .as_ref()
        .map_or_else(CredentialChain::default, |issuer| {
            let (start, end) = lifetime();
            CredentialChain(vec![
                rocky_credentials::Authority::owner(l.publisher())
                    .issue_issuer(issuer.public_key(), None, (start, end - start, 0))
                    .unwrap(),
            ])
        });
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let replica = l
        .open_certified(&dir.path().join("source.db"), (signer, &key), 2, None)
        .await
        .unwrap();
    follow_main(&l, &replica).await;
    replica
        .publish_tip_statements(&[TipStatement::GenesisLine(
            SignedGenesisLine::sign(
                GenesisLineStatement {
                    format: 1,
                    scope: l.domain,
                    minimum_in_sync: 2,
                },
                l.publisher(),
            )
            .unwrap(),
        )])
        .await
        .unwrap();
    let source = replica.followed_tip().await;
    let close = SignedSeal::sign(
        SealStatement {
            format: rocky_credentials::SEAL_FORMAT,
            scope: l.domain,
            tip: source,
            frontier: vec![],
            action: SealAction::Close,
            recovery: None,
        },
        l.publisher(),
    )
    .unwrap();
    let opening = SignedTipOpening::endorse(
        TipOpeningStatement {
            format: 2,
            scope: l.domain,
            seal: close.id().unwrap(),
            schema: l.definition(3).hash(),
            minimum_in_sync: 2,
        },
        signer,
        &endorsement,
    )
    .unwrap();
    let target = opening.tip().unwrap();
    let publication = rocky_core::commitment("rocky.sdk.migration.v3", &target.0);
    replica
        .stage_schema(SchemaStage {
            publication,
            scope: l.domain,
            bookmark: "main".into(),
            source,
            target,
            from_version: 2,
            coordinated: false,
            statements: vec![
                TipStatement::Seal(close),
                TipStatement::Opening(opening),
                bookmark(&l, Some(source), target),
            ],
            program: vec![],
            parents: vec![],
        })
        .await
        .unwrap();
    replica
        .install_tip_schema(target, l.definition(3), b"verified".to_vec())
        .await
        .unwrap();
    let mut config = l.config(3, &key);
    config.manifest = l.config(2, &key).manifest;
    config.credentials = l.certified(3, signer, &key);
    replica
        .switch_schema(
            target,
            l.app(3),
            SchemaConfig {
                security: config,
                tables: Some(l.projection(3)),
            },
        )
        .await
        .unwrap();
    let writer = PrivateKey::new();
    let credentials = l.certified(3, signer, &writer);
    let author = credentials.author_number().unwrap();
    replica
        .register_line_node(LineNode {
            key: writer,
            credentials,
        })
        .await
        .unwrap();
    let scopes = [l.scope("items"), l.scope("tags")].into();
    let sql = replica
        .session(scopes)
        .await
        .unwrap()
        .migration_sql(publication, crate::sql::SqlOptions::default())
        .await
        .unwrap();
    sql.run("BEGIN", vec![]).await.unwrap();
    for i in 0..n {
        sql.run(
            "INSERT INTO items(key,title,id) VALUES(?,?,?)",
            vec![
                SqlValue::Text(format!("k{i}")),
                SqlValue::Text(format!("item{i}")),
                SqlValue::Integer(RowIdentity::new(author, (i + 1) as u32).unwrap().integer()),
            ],
        )
        .await
        .unwrap();
    }
    if tags && n > 0 {
        sql.run(
            "INSERT INTO tags(key,label,id) VALUES('tag','private companion',?)",
            vec![SqlValue::Integer(
                RowIdentity::new(author, 1).unwrap().integer(),
            )],
        )
        .await
        .unwrap();
    }
    sql.commit_publication(publication).await.unwrap();
    replica
        .author_staged_publication(publication)
        .await
        .unwrap();
    let (s, writer) = replica
        .migration_intent(publication)
        .await
        .unwrap()
        .unwrap();
    let signed = SignedMigrationPublication::endorse(s, signer, &endorsement, writer).unwrap();
    ((l, dir, key, replica, signed), issuer)
}
pub(super) async fn release(
    replica: &EncryptedReplica<TypedRows>,
    signed: &SignedMigrationPublication,
) {
    replica
        .admit_migration_publication(signed.clone())
        .await
        .unwrap();
    replica
        .release_uncoordinated_schema(signed.statement.publication)
        .await
        .unwrap();
}
/// The migration frames `replica` stores, in sequence order.
pub(super) async fn frames(replica: &EncryptedReplica<TypedRows>) -> Vec<EncryptedFrame> {
    stored_frames(
        replica,
        "SELECT header,body FROM secure_operations ORDER BY sequence",
    )
    .await
    .into_iter()
    .filter(|frame| frame.migration.is_some())
    .collect()
}
