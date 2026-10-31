//! A migration of replayed tables publishes its program: the execution
//! commits with the program staged, bounded transactions author it, and no
//! frame of it leaves before the last one records the publication.
use super::super::generations::{select, text};
use super::*;
use crate::{LineNode, SchemaConfig, SchemaStage};

/// A replayed lineage whose generation 3 migration inserts `n` items and
/// retitles them, committed with its program staged and nothing authored.
/// With `labels`, `tags` is partitioned and the program also inserts one
/// tag in each of `labels` partitions, each its own bundle after the items'.
pub(super) struct Staged {
    pub(super) l: Lineage,
    pub(super) dir: TempDir,
    pub(super) key: PrivateKey,
    pub(super) replica: EncryptedReplica<TypedRows>,
    pub(super) publication: Commitment,
    /// The migration writer's credentials.
    pub(super) writer: CredentialChain,
}

pub(super) async fn staged(n: usize) -> Staged {
    staged_tags(n, 0).await
}

pub(super) async fn staged_tags(n: usize, labels: usize) -> Staged {
    let mut l = Lineage::new();
    l.partitioned = labels > 0;
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let replica = l
        .open_certified(
            &dir.path().join("source.db"),
            (l.publisher(), &key),
            2,
            None,
        )
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
    let opening = SignedTipOpening::sign(
        TipOpeningStatement {
            format: 2,
            scope: l.domain,
            seal: close.id().unwrap(),
            schema: l.definition(3).hash(),
            minimum_in_sync: 2,
        },
        l.publisher(),
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
    config.credentials = l.certified(3, l.publisher(), &key);
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
    let credentials = l.certified(3, l.publisher(), &writer);
    let author = credentials.author_number().unwrap();
    replica
        .register_line_node(LineNode {
            key: writer,
            credentials: credentials.clone(),
        })
        .await
        .unwrap();
    let mut scopes: std::collections::BTreeSet<_> = [l.scope("items")].into();
    if labels == 0 {
        scopes.insert(l.scope("tags"));
    }
    scopes.extend(hold_tags(&l, &replica, labels).await);
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
    for label in 0..labels {
        sql.run(
            "INSERT INTO tags(label,key,id) VALUES(?,'tag',?)",
            vec![
                SqlValue::Text(format!("t{label}")),
                SqlValue::Integer(
                    RowIdentity::new(author, (n + label + 1) as u32)
                        .unwrap()
                        .integer(),
                ),
            ],
        )
        .await
        .unwrap();
    }
    sql.run("UPDATE items SET title = title || '!'", vec![])
        .await
        .unwrap();
    let committed = sql.commit_publication(publication).await.unwrap();
    assert!(committed.committed.unwrap().frames.is_empty());
    Staged {
        l,
        dir,
        key,
        replica,
        publication,
        writer: credentials,
    }
}

/// Registers and keys the tag partitions `t0`… `t{labels - 1}`; returns
/// their scopes.
async fn hold_tags(
    l: &Lineage,
    replica: &EncryptedReplica<TypedRows>,
    labels: usize,
) -> Vec<ResourceScope> {
    let mut scopes = Vec::new();
    for label in 0..labels {
        let (scope, tuple) = l.tag_partition(&format!("t{label}"));
        replica.register_partition(scope, tuple).await.unwrap();
        replica
            .install_key(KeyMaterial::new(scope, 1, [60 + label as u8; 32]))
            .await
            .unwrap();
        scopes.push(scope);
    }
    scopes
}

/// Tag partitions of the multi-chunk fixtures: 17 bundles, three chunks.
const LABELS: usize = 16;

/// The frames a publication's bundles hold so far, in position order.
async fn authored(replica: &EncryptedReplica<TypedRows>, publication: Commitment) -> Vec<Hash> {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    let mut hashes = Vec::new();
    for position in 0.. {
        let frames = inner
            .bundle_frames(&crate::replica::publication::handle(&publication, position))
            .await
            .unwrap();
        if frames.is_empty() {
            return hashes;
        }
        hashes.extend(
            frames
                .into_iter()
                .flatten()
                .map(|frame| frame.id().unwrap()),
        );
    }
    hashes
}

#[tokio::test]
async fn the_execution_commits_staged_and_authoring_records_it_once() {
    let s = staged(3).await;
    let items =
        |replica| async move { select(replica, "SELECT key,title FROM items ORDER BY key").await };
    // The issuer's execution is its result before anything is authored.
    assert_eq!(
        items(&s.replica).await,
        (0..3)
            .map(|i| vec![text(&format!("k{i}")), text(&format!("item{i}!"))])
            .collect::<Vec<_>>()
    );
    assert!(s.replica.publication_staged(s.publication).await.unwrap());
    assert!(authored(&s.replica, s.publication).await.is_empty());
    assert!(
        s.replica
            .migration_intent(s.publication)
            .await
            .unwrap()
            .is_none()
    );
    // One unpartitioned partition: one bundle, then the record.
    assert!(
        s.replica
            .author_publication_step(s.publication)
            .await
            .unwrap()
    );
    let frames = authored(&s.replica, s.publication).await;
    assert_eq!(frames.len(), 1);
    assert!(
        !s.replica
            .author_publication_step(s.publication)
            .await
            .unwrap()
    );
    assert!(!s.replica.publication_staged(s.publication).await.unwrap());
    let (statement, _) = s
        .replica
        .migration_intent(s.publication)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(statement.frames, 1);
    assert_eq!(authored(&s.replica, s.publication).await, frames);
    // Nothing is left to author or record again.
    s.replica
        .author_staged_publication(s.publication)
        .await
        .unwrap();
    assert_eq!(
        s.replica.publications().await.unwrap(),
        vec![crate::Publication {
            id: s.publication,
            bundles: 1,
            published: 0,
        }]
    );
}

/// Asserts that a link starting now on the issuer's tip is served none of
/// `unsent`, by range or by transfer, and that none of it is offered.
/// Returns the frames it was served.
async fn link_withholds(
    s: &Staged,
    member: &EncryptedReplica<TypedRows>,
    member_key: &PrivateKey,
    scopes: &[ResourceScope],
    unsent: &[Hash],
) -> usize {
    let credentials = s.l.credentials(3, member_key);
    s.replica
        .admit_peer(
            member_key.public_key(),
            &credentials,
            s.replica.followed_tip().await,
        )
        .await
        .unwrap();
    let mut served = Vec::new();
    for scope in scopes {
        let frontier = member.frontier(*scope).await.unwrap();
        let page = s
            .replica
            .range_page(
                member_key.public_key(),
                &credentials,
                &frontier,
                None,
                MAX_SECURE_FRAME / 2,
            )
            .await
            .unwrap();
        served.extend(page.frames);
    }
    let page = s
        .replica
        .transfer_page(
            member_key.public_key(),
            &credentials,
            scopes,
            None,
            MAX_SECURE_FRAME / 2,
        )
        .await
        .unwrap();
    served.extend(page.frames);
    assert!(
        served
            .iter()
            .all(|frame| !unsent.contains(&frame.id().unwrap()))
    );
    let mut inner = s
        .replica
        .inner
        .lock(crate::replica::Class::Background)
        .await;
    let refused = inner.offer(unsent).await.unwrap_err();
    assert!(
        refused.to_string().contains("still being authored"),
        "{refused}"
    );
    served.len()
}

#[tokio::test]
async fn a_staged_publication_is_neither_offered_nor_served_before_its_record() {
    let s = staged_tags(3, LABELS).await;
    let member_key = PrivateKey::new();
    let member =
        s.l.open(&s.dir.path().join("member.db"), &member_key, 2, None)
            .await
            .unwrap();
    let scopes: Vec<_> = std::iter::once(s.l.scope("items"))
        .chain((0..LABELS).map(|label| s.l.tag_partition(&format!("t{label}")).0))
        .collect();
    // A link starts after each chunk, before the record.
    for authored_bundles in [8, 16, 17] {
        assert!(
            s.replica
                .author_publication_step(s.publication)
                .await
                .unwrap()
        );
        let unsent = authored(&s.replica, s.publication).await;
        assert_eq!(unsent.len(), authored_bundles);
        link_withholds(&s, &member, &member_key, &scopes, &unsent).await;
        let held = s
            .replica
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .unsent()
            .await
            .unwrap();
        assert!(unsent.iter().all(|frame| held.contains(frame)));
    }
    // Recorded, released and endorsed, the frames reach the member.
    s.replica
        .author_staged_publication(s.publication)
        .await
        .unwrap();
    assert!(
        s.replica
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .unsent()
            .await
            .unwrap()
            .is_empty()
    );
    let (statement, writer) = s
        .replica
        .migration_intent(s.publication)
        .await
        .unwrap()
        .unwrap();
    let signed = SignedMigrationPublication::endorse(
        statement,
        s.l.publisher(),
        &CredentialChain::default(),
        writer,
    )
    .unwrap();
    release(&s.replica, &signed).await;
    let mut config = s.l.config(3, &member_key);
    config.credentials = s.l.credentials(3, &member_key);
    s.l.follow(&member, config, 3, &all_tip_statements(&s.replica).await)
        .await
        .unwrap();
    hold_tags(&s.l, &member, LABELS).await;
    member.admit_migration_publication(signed).await.unwrap();
    for status in member.receive_migration_all(frames(&s.replica).await).await {
        status.unwrap();
    }
    for table in ["items", "tags"] {
        let state = format!("SELECT * FROM {table} ORDER BY id");
        assert_eq!(
            select(&member, &state).await,
            select(&s.replica, &state).await
        );
    }
    assert_eq!(
        select(&member, "SELECT count(*) FROM tags").await,
        vec![vec![SqlValue::Integer(LABELS as i64)]]
    );
    let _ = s.key;
}

#[tokio::test]
async fn a_revoked_writer_between_chunks_names_its_blocker_and_releases_nothing() {
    let s = staged_tags(3, LABELS).await;
    assert!(
        s.replica
            .author_publication_step(s.publication)
            .await
            .unwrap()
    );
    let first = authored(&s.replica, s.publication).await;
    assert_eq!(first.len(), 8);
    // The writer's own capability; the issuer's identity keeps its others.
    let capability = s.writer.0.last().unwrap().id().unwrap();
    let revoked =
        crate::tests::revoking(s.l.publisher(), s.l.definition(3).app, &[], &[capability]);
    assert_eq!(
        s.replica.learn_revocations(&revoked).await.unwrap().len(),
        1
    );
    let line_node = s
        .replica
        .blockers()
        .await
        .unwrap()
        .into_iter()
        .find(|blocker| blocker.kind == crate::BlockerKind::LineNode)
        .unwrap();
    assert_eq!(line_node.clears_by, rocky_core::ClearsBy::Application);
    let refused = s
        .replica
        .author_staged_publication(s.publication)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        refused.starts_with(
            "replication data rejected: the staged publication stopped at bundle 8 of 17: "
        ) && refused.contains(&format!("blockers: [{line_node}]")),
        "{refused}"
    );
    // The stage stays at its cursor, private, for the next attempt.
    for _ in 0..2 {
        assert!(
            s.replica
                .author_publication_step(s.publication)
                .await
                .is_err()
        );
    }
    assert!(s.replica.publication_staged(s.publication).await.unwrap());
    assert_eq!(authored(&s.replica, s.publication).await, first);
    let unsent = s
        .replica
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .unsent()
        .await
        .unwrap();
    assert_eq!(unsent, first.iter().copied().collect());
    assert!(s.replica.private_schema().await.unwrap());
    assert_eq!(
        s.replica
            .staged_schema()
            .await
            .unwrap()
            .map(|(_, committed)| committed),
        Some(false)
    );
    assert!(
        s.replica
            .migration_intent(s.publication)
            .await
            .unwrap()
            .is_none()
    );
    assert!(s.replica.publications().await.unwrap().is_empty());
}

#[tokio::test]
async fn each_authoring_transaction_writes_at_most_one_chunk() {
    let s = staged_tags(3, LABELS).await;
    let mut bundles = Vec::new();
    while s
        .replica
        .author_publication_step(s.publication)
        .await
        .unwrap()
    {
        bundles.push(authored(&s.replica, s.publication).await.len());
    }
    assert_eq!(bundles, [8, 16, 17]);
    let frames = authored(&s.replica, s.publication).await;
    assert_eq!(
        frames
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        frames.len()
    );
    assert_eq!(s.replica.publications().await.unwrap()[0].bundles, 17);
}
