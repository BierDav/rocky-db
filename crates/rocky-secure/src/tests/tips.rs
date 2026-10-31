//! Graph admission, constant-row-cost sealing and line isolation.
use super::*;
mod frontiers;
mod refresh;
use crate::storage::rows;
use rocky_core::TipId;
use rocky_credentials::{
    AuthorMark, Authority, BOOKMARK_MOVE_FORMAT, BookmarkMoveStatement, SEAL_FORMAT, SealAction,
    SealStatement, SignedBookmarkMove, SignedSeal, SignedTipOpening, TIP_OPENING_FORMAT,
    TipOpeningStatement,
};
use std::{collections::BTreeMap, path::Path, sync::Arc};

type Replica = EncryptedReplica<Employees>;

#[tokio::test]
async fn following_a_branch_replays_initially_held_history_in_causal_order() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let source = open(&f, &dir.path().join("held-source.db"), &PrivateKey::new()).await;
    let target = open(&f, &dir.path().join("held-target.db"), &PrivateKey::new()).await;
    main(&f, &source).await;
    let genesis = source.followed_tip().await;
    let common = insert(&f, &source, 1, "Common").await;
    target.receive(common).await.unwrap();
    advance(&f, &source).await;
    let first = insert(&f, &source, 2, "Inherited first").await;
    let second = insert(&f, &source, 3, "Inherited dependent").await;
    let from = source.followed_tip().await;
    let signed = seal(&f, &source).await;
    let (_, mut records) = branch(&f, &signed);
    records.push(TipStatement::Seal(signed));
    records.push(bookmark(&f, "main", Some(from), Some(genesis)));
    source.receive_tip_statements(&records).await.unwrap();
    target
        .receive_tip_statements(&source.tip_statements(None, 32).await.unwrap())
        .await
        .unwrap();
    target
        .follow_bookmark(f.public.domain, "main")
        .await
        .unwrap();
    target
        .receive_held_frames(vec![second, first])
        .await
        .unwrap();
    assert_eq!(target.snapshot(f.public).await.unwrap().rows.len(), 1);
    assert_eq!(
        scalar(&target, "SELECT count(*) FROM secure_applied").await,
        1
    );
    target
        .follow_bookmark(f.public.domain, "dev")
        .await
        .unwrap();
    assert_eq!(target.snapshot(f.public).await.unwrap().rows.len(), 3);
    assert_eq!(
        scalar(&target, "SELECT count(*) FROM secure_applied").await,
        3
    );
    assert_eq!(
        scalar(&target, "SELECT max(sequence) FROM secure_logs").await,
        0
    );
    assert_eq!(target.frontier(f.public).await.unwrap().logs[0].applied, 3);
    target
        .follow_bookmark(f.public.domain, "main")
        .await
        .unwrap();
    assert_eq!(target.snapshot(f.public).await.unwrap().rows.len(), 1);
}

#[tokio::test]
async fn returning_to_a_branch_preserves_its_inherited_held_snapshot() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let replica = open(&f, &dir.path().join("held-snapshot.db"), &PrivateKey::new()).await;
    main(&f, &replica).await;
    let genesis = replica.followed_tip().await;
    insert(&f, &replica, 1, "Common").await;
    advance(&f, &replica).await;
    insert(&f, &replica, 2, "Inherited first").await;
    insert(&f, &replica, 3, "Inherited dependent").await;
    let from = replica.followed_tip().await;
    let signed = seal(&f, &replica).await;
    let (dev, mut records) = branch(&f, &signed);
    records.push(TipStatement::Seal(signed));
    replica.receive_tip_statements(&records).await.unwrap();
    replica
        .follow_bookmark(f.public.domain, "dev")
        .await
        .unwrap();
    assert_eq!(replica.snapshot(f.public).await.unwrap().rows.len(), 3);
    replica
        .follow_bookmark(f.public.domain, "main")
        .await
        .unwrap();
    replica
        .receive_tip_statements(&[bookmark(&f, "main", Some(from), Some(genesis))])
        .await
        .unwrap();
    assert_eq!(replica.snapshot(f.public).await.unwrap().rows.len(), 1);
    assert_eq!(replica.held_changes().await.unwrap().len(), 2);
    replica
        .follow_bookmark(f.public.domain, "dev")
        .await
        .unwrap();
    assert_eq!(replica.followed_tip().await, dev);
    assert_eq!(replica.snapshot(f.public).await.unwrap().rows.len(), 3);
    let frontier = replica.frontier(f.public).await.unwrap();
    assert_eq!(frontier.logs.len(), 1);
    assert_eq!(frontier.logs[0].held, 3);
    assert_eq!(frontier.logs[0].applied, 3);
}

#[tokio::test]
async fn late_frames_on_a_previously_continued_abandoned_line_are_held() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let a = open(&f, &dir.path().join("abandoned-a.db"), &PrivateKey::new()).await;
    let b = open(&f, &dir.path().join("abandoned-b.db"), &PrivateKey::new()).await;
    main(&f, &a).await;
    let genesis = a.followed_tip().await;
    advance(&f, &a).await;
    b.receive_tip_statements(&a.tip_statements(None, 32).await.unwrap())
        .await
        .unwrap();
    b.follow_bookmark(f.public.domain, "main").await.unwrap();
    let offline = insert(&f, &b, 9, "Abandoned offline").await;
    let from = a.followed_tip().await;
    let continued = seal(&f, &a).await;
    a.receive_tip_statements(&[
        TipStatement::Seal(continued),
        bookmark(&f, "main", Some(from), Some(genesis)),
    ])
    .await
    .unwrap();
    assert_eq!(a.receive(offline).await.unwrap(), ReceiveStatus::Held);
    assert!(a.snapshot(f.public).await.unwrap().rows.is_empty());
    assert_eq!(a.held_changes().await.unwrap().len(), 1);
}

async fn open(f: &Fixture, path: &Path, node: &PrivateKey) -> Replica {
    EncryptedReplica::open(path, f.app(), f.config(node, f.full(), &[f.public]))
        .await
        .unwrap()
}
fn bookmark(f: &Fixture, name: &str, from: Option<TipId>, to: Option<TipId>) -> TipStatement {
    TipStatement::Bookmark(
        SignedBookmarkMove::sign(
            BookmarkMoveStatement {
                format: BOOKMARK_MOVE_FORMAT,
                scope: f.public.domain,
                name: name.into(),
                from,
                to,
            },
            &f.publisher,
        )
        .unwrap(),
    )
}
async fn main(f: &Fixture, replica: &Replica) {
    let genesis = replica.followed_tip().await;
    replica
        .receive_tip_statements(&[bookmark(f, "main", None, Some(genesis))])
        .await
        .unwrap();
    assert_eq!(
        replica
            .follow_bookmark(f.public.domain, "main")
            .await
            .unwrap(),
        genesis
    );
}
async fn insert(f: &Fixture, replica: &Replica, row: u8, value: &str) -> EncryptedFrame {
    replica
        .author(
            [row; 32],
            vec![change(f.public, row, None, Some(f.app().name(value)))],
            vec![],
        )
        .await
        .unwrap()
}
async fn frontier(replica: &Replica, tip: TipId, scope: rocky_core::Scope) -> Vec<AuthorMark> {
    let frames = stored_frames(replica, "SELECT header,body FROM secure_operations").await;
    let graph = replica.tip_graph(scope).await.unwrap();
    let mut authors = BTreeMap::<u32, u64>::new();
    for frame in frames {
        let operation = frame.operation().unwrap();
        let e = &operation.header.extensions;
        if e.tip == tip || graph.continues_any(e.tip, tip).unwrap_or(false) {
            authors
                .entry(e.author.unwrap())
                .and_modify(|sequence| *sequence = (*sequence).max(e.author_sequence))
                .or_insert(e.author_sequence);
        }
    }
    authors
        .into_iter()
        .map(|(author, sequence)| AuthorMark { author, sequence })
        .collect()
}
async fn seal(f: &Fixture, replica: &Replica) -> SignedSeal {
    let tip = replica.followed_tip().await;
    SignedSeal::sign(
        SealStatement {
            format: SEAL_FORMAT,
            scope: f.public.domain,
            tip,
            frontier: frontier(replica, tip, f.public.domain).await,
            action: SealAction::Continue {
                schema: f.app().definition().hash(),
            },
            recovery: None,
        },
        &f.publisher,
    )
    .unwrap()
}
async fn advance(f: &Fixture, replica: &Replica) -> Vec<TipStatement> {
    let signed = seal(f, replica).await;
    let records = vec![
        TipStatement::Seal(signed.clone()),
        bookmark(
            f,
            "main",
            Some(signed.statement.tip),
            signed.successor().unwrap(),
        ),
    ];
    replica.receive_tip_statements(&records).await.unwrap();
    records
}
fn branch(f: &Fixture, seal: &SignedSeal) -> (TipId, Vec<TipStatement>) {
    let opening = SignedTipOpening::sign(
        TipOpeningStatement {
            format: TIP_OPENING_FORMAT,
            schema: f.manifest.verify(f.publisher.public_key()).unwrap().hash(),
            scope: f.public.domain,
            seal: seal.id().unwrap(),
            minimum_in_sync: 1,
        },
        &f.publisher,
    )
    .unwrap();
    let tip = opening.tip().unwrap();
    (
        tip,
        vec![
            TipStatement::Opening(opening),
            bookmark(f, "dev", None, Some(tip)),
        ],
    )
}
async fn scalar(replica: &Replica, sql: &str) -> i64 {
    match rows(
        &replica
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .conn,
        sql,
    )
    .await
    .unwrap()[0][0]
    {
        rocky_core::SqlValue::Integer(value) => value,
        _ => panic!("integer query"),
    }
}
async fn raw_rows(replica: &Replica) -> Vec<Vec<rocky_core::SqlValue>> {
    rows(
        &replica
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .conn,
        "SELECT scope,row,fields FROM secure_row_records ORDER BY scope,row",
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn adopting_a_seal_changes_no_row_and_writes_the_same_metadata_with_ten_or_ten_thousand_rows()
{
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let mut costs = Vec::new();
    for count in [10, 10_000] {
        let key = PrivateKey::new();
        let replica = open(&f, &dir.path().join(format!("{count}.db")), &key).await;
        insert(&f, &replica, 1, "Retained").await;
        // Clone valid stored row materialization, excluding row capture and
        // encryption cost from this graph-metadata scaling assertion.
        replica.inner.lock(crate::replica::Class::Background).await.conn.execute(
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?) INSERT INTO secure_row_records SELECT scope,CAST(printf('%032d',i) AS BLOB),fields FROM secure_row_records,n",
            [count - 1],
        ).await.unwrap();
        assert_eq!(
            scalar(&replica, "SELECT count(*) FROM secure_row_records").await,
            count
        );
        let before = raw_rows(&replica).await;
        let signed = seal(&f, &replica).await;
        let before_changes = scalar(&replica, "SELECT total_changes()").await;
        assert_eq!(
            replica
                .receive_tip_statements(&[TipStatement::Seal(signed.clone())])
                .await
                .unwrap(),
            1
        );
        costs.push(scalar(&replica, "SELECT total_changes()").await - before_changes);
        assert_eq!(raw_rows(&replica).await, before);
        assert_eq!(
            replica
                .receive_tip_statements(&[TipStatement::Seal(signed)])
                .await
                .unwrap(),
            0
        );
        assert!(
            replica
                .author(
                    [2; 32],
                    vec![change(f.public, 2, None, Some(f.app().name("Sealed")))],
                    vec![]
                )
                .await
                .is_err()
        );
    }
    assert_eq!(
        costs[0], costs[1],
        "seal storage work must not grow with rows"
    );
    assert!(costs[0] > 0);
}

#[tokio::test]
async fn graph_admission_rolls_back_its_database_and_memory_and_survives_reopen() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("graph.db");
    let key = PrivateKey::new();
    let replica = open(&f, &path, &key).await;
    let signed = seal(&f, &replica).await;
    let record = TipStatement::Seal(signed.clone());
    replica.inner.lock(crate::replica::Class::Background).await.conn.execute(
        "CREATE TEMP TRIGGER fail_tip_statement BEFORE INSERT ON secure_tip_statements BEGIN SELECT RAISE(ABORT,'injected graph storage failure'); END",(),
    ).await.unwrap();
    assert!(
        replica
            .receive_tip_statements(std::slice::from_ref(&record))
            .await
            .is_err()
    );
    assert!(
        replica
            .tip_graph(f.public.domain)
            .await
            .unwrap()
            .seals
            .is_empty()
    );
    assert_eq!(
        scalar(&replica, "SELECT count(*) FROM secure_tip_statements").await,
        0
    );
    replica
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .conn
        .execute("DROP TRIGGER fail_tip_statement", ())
        .await
        .unwrap();
    replica
        .receive_tip_statements(std::slice::from_ref(&record))
        .await
        .unwrap();
    let authority = replica.observe_authority().await;
    let before = *authority.borrow();
    assert_eq!(replica.receive_tip_statements(&[record]).await.unwrap(), 0);
    assert_eq!(replica.receive_tip_statements(&[]).await.unwrap(), 0);
    assert_eq!(*authority.borrow(), before);
    drop(replica);
    let reopened = open(&f, &path, &key).await;
    assert_eq!(
        reopened.tip_graph(f.public.domain).await.unwrap().seals,
        vec![signed]
    );
}

#[tokio::test]
async fn offline_writes_cross_two_continue_seals_without_changing_their_author() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let (a_key, b_key) = (PrivateKey::new(), PrivateKey::new());
    let a = open(&f, &dir.path().join("a.db"), &a_key).await;
    let b = open(&f, &dir.path().join("b.db"), &b_key).await;
    main(&f, &a).await;
    b.receive_tip_statements(&a.tip_statements(None, 32).await.unwrap())
        .await
        .unwrap();
    b.follow_bookmark(f.public.domain, "main").await.unwrap();
    let offline = insert(&f, &b, 2, "Offline").await;
    let original = offline.to_bytes().unwrap();
    advance(&f, &a).await;
    let intervening = insert(&f, &a, 1, "Online").await;
    advance(&f, &a).await;
    let all = a.tip_statements(None, 32).await.unwrap();
    b.receive_tip_statements(&all).await.unwrap();
    assert_eq!(a.followed_tip().await, b.followed_tip().await);
    a.receive(offline.clone()).await.unwrap();
    b.receive(intervening).await.unwrap();
    assert_eq!(offline.to_bytes().unwrap(), original);
    assert_eq!(
        a.snapshot(f.public).await.unwrap().rows,
        b.snapshot(f.public).await.unwrap().rows
    );
    assert_eq!(a.snapshot(f.public).await.unwrap().rows.len(), 2);
}

#[tokio::test]
async fn concurrent_issuer_seals_choose_the_lower_continuation_on_every_device() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let a = open(&f, &dir.path().join("a.db"), &PrivateKey::new()).await;
    let b = open(&f, &dir.path().join("b.db"), &PrivateKey::new()).await;
    main(&f, &a).await;
    let created = a.tip_statements(None, 32).await.unwrap();
    b.receive_tip_statements(&created).await.unwrap();
    b.follow_bookmark(f.public.domain, "main").await.unwrap();
    let common = insert(&f, &a, 1, "Common").await;
    b.receive(common.clone()).await.unwrap();
    let statement = seal(&f, &a).await.statement;
    let mut variants = Vec::new();
    for replica in [&a, &b] {
        let issuer = PrivateKey::new();
        let chain = CredentialChain(vec![
            Authority::owner(&f.publisher)
                .issue_issuer(issuer.public_key(), None, validity())
                .unwrap(),
        ]);
        let signed = SignedSeal::endorse(statement.clone(), &issuer, &chain).unwrap();
        let records = vec![
            TipStatement::Seal(signed.clone()),
            bookmark(&f, "main", Some(statement.tip), signed.successor().unwrap()),
        ];
        replica.receive_tip_statements(&records).await.unwrap();
        variants.push((signed, records));
    }
    let a_write = insert(&f, &a, 2, "A continuation").await;
    let b_write = insert(&f, &b, 3, "B continuation").await;
    let expected = variants
        .iter()
        .min_by_key(|(signed, _)| signed.id().unwrap())
        .unwrap()
        .0
        .successor()
        .unwrap()
        .unwrap();
    a.receive_tip_statements(&variants[1].1).await.unwrap();
    b.receive_tip_statements(&variants[0].1).await.unwrap();
    a.receive(b_write.clone()).await.unwrap();
    b.receive(a_write.clone()).await.unwrap();
    assert_eq!(a.followed_tip().await, expected);
    assert_eq!(b.followed_tip().await, expected);
    assert_eq!(
        a.snapshot(f.public).await.unwrap().rows,
        b.snapshot(f.public).await.unwrap().rows
    );
    assert_eq!(a.snapshot(f.public).await.unwrap().rows.len(), 2);
    assert_eq!(a.held_changes().await.unwrap().len(), 1);
    assert_eq!(b.held_changes().await.unwrap().len(), 1);
    let loser = if a_write.operation().unwrap().header.extensions.tip == expected {
        b_write
    } else {
        a_write
    };
    let third = open(&f, &dir.path().join("third.db"), &PrivateKey::new()).await;
    third.receive(common).await.unwrap();
    third
        .receive_tip_statements(&a.tip_statements(None, 32).await.unwrap())
        .await
        .unwrap();
    third
        .follow_bookmark(f.public.domain, "main")
        .await
        .unwrap();
    let losing_tip = loser.operation().unwrap().header.extensions.tip;
    third.receive_held_frames(vec![loser]).await.unwrap();
    assert_eq!(third.held_changes().await.unwrap().len(), 1);
    let (losing_replica, winning_replica) =
        if variants[0].0.successor().unwrap().unwrap() == losing_tip {
            (&a, &b)
        } else {
            (&b, &a)
        };
    assert!(
        losing_replica
            .author(
                [4; 32],
                vec![change(f.public, 4, None, Some(f.app().name("Must enroll")))],
                vec![]
            )
            .await
            .is_err()
    );
    let next = insert(&f, winning_replica, 4, "Canonical next").await;
    losing_replica.receive(next).await.unwrap();
    assert_eq!(
        losing_replica.snapshot(f.public).await.unwrap().rows,
        winning_replica.snapshot(f.public).await.unwrap().rows
    );
}

#[tokio::test]
async fn a_coordinated_seal_enters_the_graph_only_after_ending_its_tips_log() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let replica = open(&f, &dir.path().join("coordinated.db"), &key).await;
    main(&f, &replica).await;
    let tip = replica.followed_tip().await;
    let log = rocky_core::TipLog {
        scope: f.public.domain,
        tip,
    };
    let signed = seal(&f, &replica).await;
    let records = vec![
        TipStatement::Seal(signed.clone()),
        bookmark(&f, "main", Some(tip), signed.successor().unwrap()),
    ];
    let coordinator = rocky_coordinator::coordinated::MemoryLog::new();
    replica.set_domain_log(Some(Arc::new(coordinator.client(key.public_key()))));
    // A seal admission refuses never ends the log.
    let mut forged = signed.statement.clone();
    forged.frontier.clear();
    let forged = SignedSeal::sign(forged, &PrivateKey::new()).unwrap();
    assert!(
        replica
            .receive_tip_statements(&[TipStatement::Seal(forged)])
            .await
            .is_err()
    );
    assert_eq!(coordinator.head(log).unwrap().terminal, None);
    // Unconfirmed, a received seal and the move riding on it wait outside
    // the graph; this node's own publication fails.
    coordinator.set_available(false);
    assert_eq!(replica.receive_tip_statements(&records).await.unwrap(), 0);
    let message = replica
        .publish_tip_statements(&records)
        .await
        .unwrap_err()
        .to_string();
    assert!(message.contains("did not confirm"), "{message}");
    assert!(
        replica
            .tip_graph(f.public.domain)
            .await
            .unwrap()
            .seals
            .is_empty()
    );
    assert_eq!(replica.followed_tip().await, tip);
    coordinator.set_available(true);
    assert_eq!(replica.publish_tip_statements(&records).await.unwrap(), 2);
    let head = coordinator.head(log).unwrap();
    let terminal = head.terminal.unwrap();
    assert_eq!(
        (terminal.digest, terminal.continuation),
        (signed.id().unwrap(), signed.successor().unwrap())
    );
    assert_eq!(
        replica.followed_tip().await,
        signed.successor().unwrap().unwrap()
    );
    // The log ended with a seal this node holds: a concurrent one of its
    // own is not published, but one received is, and the graph decides.
    let mut late = signed.statement.clone();
    late.action = SealAction::Close;
    let late = SignedSeal::sign(late, &f.publisher).unwrap();
    let message = replica
        .publish_tip_statements(&[TipStatement::Seal(late.clone())])
        .await
        .unwrap_err()
        .to_string();
    assert!(message.contains("first"), "{message}");
    assert_eq!(
        replica
            .tip_graph(f.public.domain)
            .await
            .unwrap()
            .seals
            .len(),
        1
    );
    assert_eq!(
        replica
            .receive_tip_statements(&[TipStatement::Seal(late)])
            .await
            .unwrap(),
        1
    );
    assert_eq!(coordinator.head(log).unwrap().terminal, Some(terminal));
}

async fn identity_replica(
    f: &Fixture,
    path: &Path,
    identity: &PrivateKey,
    node: &PrivateKey,
) -> (Replica, CredentialChain) {
    let root = Authority::owner(&f.publisher)
        .issue(
            identity.public_key(),
            f.full(),
            rocky_credentials::AuthorRange::ALL,
            validity(),
        )
        .unwrap();
    let identity_chain = CredentialChain(vec![root]);
    let mut config = f.config(node, f.full(), &[f.public]);
    config.credentials = identity_chain
        .clone()
        .complete(identity, node.public_key(), 1)
        .unwrap();
    (
        EncryptedReplica::open(path, f.app(), config).await.unwrap(),
        identity_chain,
    )
}

#[tokio::test]
async fn returning_to_main_can_serve_a_checkpoint_signed_by_its_saved_branch_node() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let identity = PrivateKey::new();
    let original = PrivateKey::new();
    let (replica, identity_chain) = identity_replica(
        &f,
        &dir.path().join("checkpoint-lines.db"),
        &identity,
        &original,
    )
    .await;
    main(&f, &replica).await;
    insert(&f, &replica, 1, "Base").await;
    let continued = advance(&f, &replica).await;
    let TipStatement::Seal(seal) = &continued[0] else {
        panic!("seal")
    };
    let (_, records) = branch(&f, seal);
    replica.receive_tip_statements(&records).await.unwrap();
    replica
        .follow_bookmark(f.public.domain, "dev")
        .await
        .unwrap();
    let branch_node = PrivateKey::new();
    let line = LineNode {
        credentials: identity_chain
            .clone()
            .complete(&identity, branch_node.public_key(), 2)
            .unwrap(),
        key: branch_node.clone(),
    };
    replica.register_line_node(line.clone()).await.unwrap();
    replica.compact(f.public.domain, 0).await.unwrap();
    let signed = replica.checkpoint(f.public).await.unwrap();
    assert_eq!(signed.signer(), branch_node.public_key());
    replica
        .follow_bookmark(f.public.domain, "main")
        .await
        .unwrap();
    let mut config = f.config(&original, f.full(), &[f.public]);
    config.credentials = identity_chain
        .complete(&identity, original.public_key(), 1)
        .unwrap();
    drop(replica);
    let replica = EncryptedReplica::open(&dir.path().join("checkpoint-lines.db"), f.app(), config)
        .await
        .unwrap();
    replica.restore_line_node(line).await.unwrap();
    assert_eq!(
        insert(&f, &replica, 2, "Main after restore")
            .await
            .operation()
            .unwrap()
            .header
            .public_key,
        original.public_key()
    );
    let peer = PrivateKey::new();
    let target = open(&f, &dir.path().join("checkpoint-joiner.db"), &peer).await;
    exchange_graphs(&replica, &target, f.public.domain).await;
    let credentials = target
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .config
        .credentials
        .clone();
    replica
        .admit_peer(peer.public_key(), &credentials, target.followed_tip().await)
        .await
        .unwrap();
    let offered = replica
        .checkpoint_offer(peer.public_key(), &credentials, f.public)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(offered.id().unwrap(), signed.id().unwrap());
    target.begin_rebootstrap(offered).await.unwrap();
    let page = replica
        .checkpoint_page(
            peer.public_key(),
            &credentials,
            f.public,
            signed.id().unwrap(),
            None,
            MAX_SECURE_FRAME,
        )
        .await
        .unwrap();
    target.stage_checkpoint_page(page).await.unwrap();
    target.finish_rebootstrap(f.public).await.unwrap();
    assert_eq!(target.snapshot(f.public).await.unwrap().rows.len(), 1);
    assert_eq!(replica.snapshot(f.public).await.unwrap().rows.len(), 2);
}

#[tokio::test]
async fn following_a_branch_requires_its_own_node_and_returns_to_the_main_node() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let identity = PrivateKey::new();
    let original = PrivateKey::new();
    let (replica, identity_chain) =
        identity_replica(&f, &dir.path().join("lines.db"), &identity, &original).await;
    main(&f, &replica).await;
    insert(&f, &replica, 1, "Base").await;
    let continued = advance(&f, &replica).await;
    let TipStatement::Seal(signed) = &continued[0] else {
        panic!("seal")
    };
    let main_tip = replica.followed_tip().await;
    let (dev, records) = branch(&f, signed);
    replica.receive_tip_statements(&records).await.unwrap();
    replica
        .follow_bookmark(f.public.domain, "dev")
        .await
        .unwrap();
    assert_eq!(replica.followed_tip().await, dev);
    assert!(
        replica
            .author(
                [2; 32],
                vec![change(f.public, 2, None, Some(f.app().name("Wrong node")))],
                vec![]
            )
            .await
            .is_err()
    );
    let branch_node = PrivateKey::new();
    replica
        .register_line_node(LineNode {
            credentials: identity_chain
                .complete(&identity, branch_node.public_key(), 2)
                .unwrap(),
            key: branch_node.clone(),
        })
        .await
        .unwrap();
    let dev_frame = insert(&f, &replica, 3, "Dev only").await;
    assert_eq!(
        dev_frame.operation().unwrap().header.public_key,
        branch_node.public_key()
    );
    assert_eq!(replica.snapshot(f.public).await.unwrap().rows.len(), 2);
    replica
        .follow_bookmark(f.public.domain, "main")
        .await
        .unwrap();
    assert_eq!(replica.followed_tip().await, main_tip);
    assert_eq!(replica.snapshot(f.public).await.unwrap().rows.len(), 1);
    let returned = insert(&f, &replica, 4, "Main again").await;
    assert_eq!(
        returned.operation().unwrap().header.public_key,
        original.public_key()
    );
    assert_eq!(
        returned.operation().unwrap().header.extensions.tip,
        main_tip
    );
}

#[tokio::test]
async fn branch_snapshot_inherits_late_writes_already_inside_its_opening_seal() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let a = open(&f, &dir.path().join("a.db"), &PrivateKey::new()).await;
    let b = open(&f, &dir.path().join("b.db"), &PrivateKey::new()).await;
    main(&f, &a).await;
    let late = insert(&f, &b, 2, "Late before branch").await;
    advance(&f, &a).await;
    a.receive(late).await.unwrap();
    let continued = advance(&f, &a).await;
    let TipStatement::Seal(signed) = &continued[0] else {
        panic!("seal")
    };
    let (_, records) = branch(&f, signed);
    a.receive_tip_statements(&records).await.unwrap();
    a.follow_bookmark(f.public.domain, "dev").await.unwrap();
    let snapshot = a.snapshot(f.public).await.unwrap();
    assert_eq!(snapshot.rows.len(), 1);
    assert_eq!(
        snapshot.rows.values().next().unwrap(),
        &f.app().name("Late before branch")
    );
}

#[tokio::test]
async fn reopening_a_branch_waits_for_its_saved_line_node_and_returns_to_main() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("restart.db");
    let identity = PrivateKey::new();
    let original = PrivateKey::new();
    let (replica, identity_chain) = identity_replica(&f, &path, &identity, &original).await;
    let config = {
        let inner = replica.inner.lock(crate::replica::Class::Background).await;
        SecureConfig {
            publisher: inner.config.publisher,
            manifest: inner.config.manifest.clone(),
            revocations: inner.config.revocations.clone(),
            node: inner.config.node.clone(),
            credentials: inner.config.credentials.clone(),
            keys: inner
                .config
                .keys
                .iter()
                .map(|key| KeyMaterial::at(key.scope, key.generation, key.key))
                .collect(),
        }
    };
    main(&f, &replica).await;
    insert(&f, &replica, 1, "Base").await;
    let continued = advance(&f, &replica).await;
    let TipStatement::Seal(signed) = &continued[0] else {
        panic!("seal")
    };
    let main_tip = replica.followed_tip().await;
    let (dev, records) = branch(&f, signed);
    replica.receive_tip_statements(&records).await.unwrap();
    replica
        .follow_bookmark(f.public.domain, "dev")
        .await
        .unwrap();
    let branch_node = PrivateKey::new();
    let line = LineNode {
        credentials: identity_chain
            .complete(&identity, branch_node.public_key(), 2)
            .unwrap(),
        key: branch_node.clone(),
    };
    replica.register_line_node(line.clone()).await.unwrap();
    insert(&f, &replica, 2, "Dev before restart").await;
    drop(replica);
    let reopened = EncryptedReplica::open(&path, f.app(), config)
        .await
        .unwrap();
    assert_eq!(reopened.followed_tip().await, dev);
    let refusal = super::blockers::refused(
        reopened
            .author(
                [3; 32],
                vec![change(f.public, 3, None, Some(f.app().name("Unsaved key")))],
                vec![],
            )
            .await,
    );
    let line_node = |kind: &crate::BlockerKind| *kind == crate::BlockerKind::LineNode;
    let domain = crate::domain_label(&f.public.domain);
    super::blockers::assert_named(&refusal, &domain, line_node, crate::ClearsBy::LocalWork);
    super::blockers::assert_named(
        &reopened.blockers().await.unwrap(),
        &domain,
        line_node,
        crate::ClearsBy::LocalWork,
    );
    reopened.register_line_node(line).await.unwrap();
    assert!(
        super::blockers::named(&reopened.blockers().await.unwrap(), &domain, line_node).is_none()
    );
    let frame = insert(&f, &reopened, 4, "Dev after restart").await;
    assert_eq!(
        frame.operation().unwrap().header.public_key,
        branch_node.public_key()
    );
    reopened
        .follow_bookmark(f.public.domain, "main")
        .await
        .unwrap();
    assert_eq!(reopened.followed_tip().await, main_tip);
    assert_eq!(reopened.snapshot(f.public).await.unwrap().rows.len(), 1);
    assert_eq!(
        insert(&f, &reopened, 5, "Main after restart")
            .await
            .operation()
            .unwrap()
            .header
            .public_key,
        original.public_key()
    );
}

#[tokio::test]
async fn backward_bookmark_close_and_move_roll_back_together_then_hold_abandoned_writes() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let replica = open(&f, &dir.path().join("rollback.db"), &key).await;
    main(&f, &replica).await;
    let genesis = replica.followed_tip().await;
    let kept = insert(&f, &replica, 1, "Kept").await;
    advance(&f, &replica).await;
    let abandoned = insert(&f, &replica, 2, "Abandoned").await;
    let peer = open(&f, &dir.path().join("rollback-peer.db"), &PrivateKey::new()).await;
    peer.receive(kept).await.unwrap();
    peer.receive_tip_statements(&replica.tip_statements(None, 32).await.unwrap())
        .await
        .unwrap();
    peer.follow_bookmark(f.public.domain, "main").await.unwrap();
    peer.receive(abandoned.clone()).await.unwrap();
    let old = replica.followed_tip().await;
    let mut close = seal(&f, &replica).await.statement;
    close.action = SealAction::Close;
    let records = vec![
        TipStatement::Seal(SignedSeal::sign(close, &f.publisher).unwrap()),
        bookmark(&f, "main", Some(old), Some(genesis)),
    ];
    replica.inner.lock(crate::replica::Class::Background).await.conn.execute(
        "CREATE TEMP TRIGGER fail_follow BEFORE UPDATE ON secure_followed_tip BEGIN SELECT RAISE(ABORT,'injected follow failure'); END",(),
    ).await.unwrap();
    assert!(replica.receive_tip_statements(&records).await.is_err());
    assert_eq!(replica.followed_tip().await, old);
    assert_eq!(replica.snapshot(f.public).await.unwrap().rows.len(), 2);
    assert!(
        replica
            .tip_graph(f.public.domain)
            .await
            .unwrap()
            .seal(old)
            .unwrap()
            .is_none()
    );
    assert!(replica.held_changes().await.unwrap().is_empty());
    replica
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .conn
        .execute("DROP TRIGGER fail_follow", ())
        .await
        .unwrap();
    replica.receive_tip_statements(&records).await.unwrap();
    assert_eq!(replica.followed_tip().await, genesis);
    assert_eq!(replica.snapshot(f.public).await.unwrap().rows.len(), 1);
    let held = replica.held_changes().await.unwrap();
    assert_eq!(held.len(), 1);
    let credentials = replica
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .config
        .credentials
        .clone();
    let (frames, _) = replica
        .held_frame_page(
            key.public_key(),
            &credentials,
            f.public,
            None,
            MAX_SECURE_FRAME,
        )
        .await
        .unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].to_bytes().unwrap(), abandoned.to_bytes().unwrap());
    peer.receive_tip_statements(&replica.tip_statements(None, 32).await.unwrap())
        .await
        .unwrap();
    assert_eq!(peer.followed_tip().await, genesis);
    assert_eq!(
        peer.snapshot(f.public).await.unwrap().rows,
        replica.snapshot(f.public).await.unwrap().rows
    );
    assert_eq!(peer.held_changes().await.unwrap().len(), 1);
}

#[tokio::test]
async fn offline_across_close_is_held_and_relayed_unchanged_by_every_holder() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let identity = PrivateKey::new();
    let (a_key, b_key, c_key) = (PrivateKey::new(), PrivateKey::new(), PrivateKey::new());
    let (a, _) = identity_replica(&f, &dir.path().join("a.db"), &identity, &a_key).await;
    let b = open(&f, &dir.path().join("b.db"), &b_key).await;
    let c = open(&f, &dir.path().join("c.db"), &c_key).await;
    main(&f, &a).await;
    let created = a.tip_statements(None, 32).await.unwrap();
    for replica in [&b, &c] {
        replica.receive_tip_statements(&created).await.unwrap();
        replica
            .follow_bookmark(f.public.domain, "main")
            .await
            .unwrap();
    }
    let offline = insert(&f, &b, 2, "Offline held").await;
    let mut close = seal(&f, &a).await.statement;
    close.action = SealAction::Close;
    let close = SignedSeal::sign(close, &f.publisher).unwrap();
    let (next, mut records) = branch(&f, &close);
    records.push(TipStatement::Seal(close.clone()));
    records.push(bookmark(&f, "main", Some(close.statement.tip), Some(next)));
    for replica in [&a, &b, &c] {
        replica.receive_tip_statements(&records).await.unwrap();
    }
    a.receive(offline.clone()).await.unwrap();
    let c_credentials = c
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .config
        .credentials
        .clone();
    let (relayed, next) = a
        .held_frame_page(
            c_key.public_key(),
            &c_credentials,
            f.public,
            None,
            MAX_SECURE_FRAME,
        )
        .await
        .unwrap();
    assert!(next.is_none());
    assert_eq!(relayed.len(), 1);
    assert_eq!(relayed[0].to_bytes().unwrap(), offline.to_bytes().unwrap());
    c.receive_held_frames(relayed).await.unwrap();
    for replica in [&a, &b, &c] {
        assert_eq!(replica.held_changes().await.unwrap().len(), 1);
        let (offered, _) = replica
            .held_frame_page(
                c_key.public_key(),
                &c_credentials,
                f.public,
                None,
                MAX_SECURE_FRAME,
            )
            .await
            .unwrap();
        assert_eq!(offered.len(), 1);
        assert_eq!(offered[0].to_bytes().unwrap(), offline.to_bytes().unwrap());
        assert!(replica.snapshot(f.public).await.unwrap().rows.is_empty());
    }
}

#[tokio::test]
async fn native_sessions_exchange_original_held_frames_across_followed_tips() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let (a_key, b_key) = (PrivateKey::new(), PrivateKey::new());
    let a = open(&f, &dir.path().join("held-server.db"), &a_key).await;
    let b = open(&f, &dir.path().join("held-client.db"), &b_key).await;
    main(&f, &a).await;
    let genesis = a.followed_tip().await;
    a.receive_tip_statements(&[bookmark(&f, "closed", None, Some(genesis))])
        .await
        .unwrap();
    let original = insert(&f, &b, 1, "Offline").await;
    let mut statement = seal(&f, &a).await.statement;
    statement.action = SealAction::Close;
    let closed = SignedSeal::sign(statement, &f.publisher).unwrap();
    let (_, mut records) = branch(&f, &closed);
    let TipStatement::Opening(opening) = &records[0] else {
        panic!("opening");
    };
    let live = opening.tip().unwrap();
    records.push(TipStatement::Seal(closed));
    records.push(bookmark(&f, "main", Some(genesis), Some(live)));
    a.receive_tip_statements(&records).await.unwrap();
    let (mut client, mut server) = crate::network::link::testing::sessions(
        (&b, b_key.clone(), f.credentials(&b_key, f.full())),
        (&a, a_key.clone(), f.credentials(&a_key, f.full())),
    )
    .await
    .unwrap();
    b.follow_bookmark(f.public.domain, "closed").await.unwrap();
    assert_ne!(a.followed_tip().await, b.followed_tip().await);
    let (served, exchanged) = tokio::join!(server.serve_to_end(&a), async {
        assert!(
            !client
                .sync_held_changes(&b, f.public, MAX_SECURE_FRAME / 2)
                .await
                .unwrap()
        );
        let before = client.sent_counts.held_frames;
        assert!(
            !client
                .sync_held_changes(&b, f.public, MAX_SECURE_FRAME / 2)
                .await
                .unwrap()
        );
        assert_eq!(
            client.sent_counts.held_frames, before,
            "unchanged held frames were resent"
        );
        client.close().await.unwrap();
    });
    served.unwrap();
    let () = exchanged;
    assert_eq!(a.held_changes().await.unwrap().len(), 1);
    assert_eq!(b.held_changes().await.unwrap().len(), 1);
    let held = a
        .held_frame_page(
            b_key.public_key(),
            &f.credentials(&b_key, f.full()),
            f.public,
            None,
            MAX_SECURE_FRAME,
        )
        .await
        .unwrap()
        .0;
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].to_bytes().unwrap(), original.to_bytes().unwrap());
    // Evicting the declaration must not reinterpret this peer as following main.
    a.inner
        .lock(crate::replica::Class::Background)
        .await
        .peer_tips
        .clear();
    assert!(
        a.transfer_page(
            b_key.public_key(),
            &f.credentials(&b_key, f.full()),
            &[f.public],
            None,
            MAX_SECURE_FRAME
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn two_branch_devices_sync_without_main_and_switching_back_drops_branch_frames() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let main_key = PrivateKey::new();
    let main_replica = open(&f, &dir.path().join("main.db"), &main_key).await;
    let (b_identity, c_identity) = (PrivateKey::new(), PrivateKey::new());
    let (b_key, c_key) = (PrivateKey::new(), PrivateKey::new());
    let (b, b_chain) =
        identity_replica(&f, &dir.path().join("dev-b.db"), &b_identity, &b_key).await;
    let (c, c_chain) =
        identity_replica(&f, &dir.path().join("dev-c.db"), &c_identity, &c_key).await;
    main(&f, &main_replica).await;
    let base = insert(&f, &main_replica, 1, "Base").await;
    for replica in [&b, &c] {
        replica.receive(base.clone()).await.unwrap();
        replica
            .receive_tip_statements(&main_replica.tip_statements(None, 32).await.unwrap())
            .await
            .unwrap();
        replica
            .follow_bookmark(f.public.domain, "main")
            .await
            .unwrap();
    }
    let continued = advance(&f, &main_replica).await;
    let TipStatement::Seal(sealed) = &continued[0] else {
        panic!("seal")
    };
    let (dev, opened) = branch(&f, sealed);
    main_replica.receive_tip_statements(&opened).await.unwrap();
    let main_tip = main_replica.followed_tip().await;
    for (replica, identity, chain, number) in [
        (&b, &b_identity, &b_chain, 2),
        (&c, &c_identity, &c_chain, 3),
    ] {
        replica.receive_tip_statements(&continued).await.unwrap();
        replica.receive_tip_statements(&opened).await.unwrap();
        replica
            .follow_bookmark(f.public.domain, "dev")
            .await
            .unwrap();
        let node = PrivateKey::new();
        replica
            .register_line_node(LineNode {
                credentials: chain
                    .clone()
                    .complete(identity, node.public_key(), number)
                    .unwrap(),
                key: node,
            })
            .await
            .unwrap();
    }
    let b_write = insert(&f, &b, 2, "B dev").await;
    let c_write = insert(&f, &c, 3, "C dev").await;
    b.receive(c_write.clone()).await.unwrap();
    c.receive(b_write.clone()).await.unwrap();
    assert_eq!(
        b.snapshot(f.public).await.unwrap().rows,
        c.snapshot(f.public).await.unwrap().rows
    );
    for frame in [&b_write, &c_write] {
        assert!(main_replica.receive(frame.clone()).await.is_err());
    }
    assert_eq!(main_replica.snapshot(f.public).await.unwrap().rows.len(), 1);
    b.admit_peer(
        main_key.public_key(),
        &f.credentials(&main_key, f.full()),
        main_tip,
    )
    .await
    .unwrap();
    assert!(
        b.transfer_page(
            main_key.public_key(),
            &f.credentials(&main_key, f.full()),
            &[f.public],
            None,
            MAX_SECURE_FRAME
        )
        .await
        .is_err()
    );
    let c_credentials = c_chain
        .complete(&c_identity, c_key.public_key(), 1)
        .unwrap();
    b.admit_peer(c_key.public_key(), &c_credentials, dev)
        .await
        .unwrap();
    let offered = b
        .transfer_page(
            c_key.public_key(),
            &c_credentials,
            &[f.public],
            None,
            MAX_SECURE_FRAME,
        )
        .await
        .unwrap();
    for frame in offered.frames {
        b.acknowledge(
            c_key.public_key(),
            &c_credentials,
            frame.id().unwrap(),
            true,
        )
        .await
        .unwrap();
    }
    b.follow_bookmark(f.public.domain, "main").await.unwrap();
    assert_eq!(b.drop_tip(dev).await.unwrap(), 2);
    assert_eq!(b.snapshot(f.public).await.unwrap().rows.len(), 1);
    let main_write = insert(&f, &b, 4, "Main again").await;
    assert_eq!(
        main_write.operation().unwrap().header.public_key,
        b_key.public_key()
    );
    main_replica.receive(main_write.clone()).await.unwrap();
    assert!(c.receive(main_write).await.is_err());
    assert_eq!(
        b.snapshot(f.public).await.unwrap().rows,
        main_replica.snapshot(f.public).await.unwrap().rows
    );
    assert_eq!(c.snapshot(f.public).await.unwrap().rows.len(), 3);
}

#[tokio::test]
async fn the_owners_backward_move_beats_an_issuers_forward_move_and_revocation_resolves_again() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let a_key = PrivateKey::new();
    let a = open(&f, &dir.path().join("a.db"), &a_key).await;
    let b = open(&f, &dir.path().join("b.db"), &PrivateKey::new()).await;
    main(&f, &a).await;
    b.receive_tip_statements(&a.tip_statements(None, 32).await.unwrap())
        .await
        .unwrap();
    b.follow_bookmark(f.public.domain, "main").await.unwrap();
    let common = insert(&f, &a, 1, "Common").await;
    b.receive(common).await.unwrap();
    let advanced = advance(&f, &a).await;
    b.receive_tip_statements(&advanced).await.unwrap();
    let TipStatement::Seal(earlier) = &advanced[0] else {
        panic!("seal first")
    };
    let tip = a.followed_tip().await;
    assert_eq!(b.followed_tip().await, tip);
    let issuers: Vec<_> = (0..2)
        .map(|_| {
            let key = PrivateKey::new();
            let chain = CredentialChain(vec![
                Authority::owner(&f.publisher)
                    .issue_issuer(key.public_key(), None, validity())
                    .unwrap(),
            ]);
            (key, chain)
        })
        .collect();
    let endorse_move = |chain: &CredentialChain, key: &PrivateKey, from, to| {
        let TipStatement::Bookmark(unsigned) = bookmark(&f, "main", from, to) else {
            unreachable!()
        };
        TipStatement::Bookmark(SignedBookmarkMove::endorse(unsigned.statement, key, chain).unwrap())
    };

    // Two issuers seal main's tip at once; among equals the lower digest wins.
    let statement = seal(&f, &a).await.statement;
    let mut variants = Vec::new();
    for (replica, (key, chain)) in [&a, &b].into_iter().zip(&issuers) {
        let signed = SignedSeal::endorse(statement.clone(), key, chain).unwrap();
        let records = vec![
            TipStatement::Seal(signed.clone()),
            endorse_move(chain, key, Some(tip), signed.successor().unwrap()),
        ];
        replica.receive_tip_statements(&records).await.unwrap();
        variants.push((signed, records));
    }
    a.receive_tip_statements(&variants[1].1).await.unwrap();
    b.receive_tip_statements(&variants[0].1).await.unwrap();
    let winner = usize::from(variants[1].0.id().unwrap() < variants[0].0.id().unwrap());
    let winning = variants[winner].0.successor().unwrap().unwrap();
    let next = variants[1 - winner].0.successor().unwrap().unwrap();
    assert_eq!(a.followed_tip().await, winning);
    assert_eq!(b.followed_tip().await, winning);
    let on_winner = insert(&f, &a, 2, "On the winner").await;
    b.receive(on_winner).await.unwrap();
    assert_eq!(b.snapshot(f.public).await.unwrap().rows.len(), 2);

    // Revoking the winning issuer leaves its seal and move out of
    // resolution: both follow the next winner, and the write on the
    // revoked line returns as a held change.
    let revoked = crate::tests::revoking(
        &f.publisher,
        f.public.domain.app,
        &[issuers[winner].0.public_key()],
        &[],
    );
    for replica in [&a, &b] {
        replica.learn_revocations(&revoked).await.unwrap();
        assert_eq!(replica.followed_tip().await, next);
        let graph = replica.tip_graph(f.public.domain).await.unwrap();
        assert!(graph.revoked.contains(&variants[winner].0.id().unwrap()));
        assert_eq!(graph.seal(tip).unwrap(), Some(&variants[1 - winner].0));
        assert_eq!(replica.snapshot(f.public).await.unwrap().rows.len(), 1);
        assert_eq!(replica.held_changes().await.unwrap().len(), 1);
    }

    // Apart: the remaining issuer on b seals main's tip and moves main
    // forward; the owner on a closes it and moves main back to a tip on
    // the earlier seal.
    let (key, chain) = &issuers[1 - winner];
    let forward = SignedSeal::endorse(seal(&f, &b).await.statement, key, chain).unwrap();
    let forward_tip = forward.successor().unwrap().unwrap();
    let forward_records = vec![
        TipStatement::Seal(forward.clone()),
        endorse_move(chain, key, Some(next), Some(forward_tip)),
    ];
    b.receive_tip_statements(&forward_records).await.unwrap();
    let forward_write = insert(&f, &b, 3, "Forward").await;
    let mut close = seal(&f, &a).await.statement;
    close.action = SealAction::Close;
    let close = SignedSeal::sign(close, &f.publisher).unwrap();
    let (back, mut back_records) = branch(&f, earlier);
    back_records.pop();
    back_records.insert(0, TipStatement::Seal(close.clone()));
    back_records.push(bookmark(&f, "main", Some(next), Some(back)));
    a.receive_tip_statements(&back_records).await.unwrap();
    assert_eq!(a.followed_tip().await, back);

    // Whatever the digests and order, both end on the owner's move; the
    // issuer's is listed as a loser and its write is held.
    a.receive_tip_statements(&forward_records).await.unwrap();
    b.receive_tip_statements(&back_records).await.unwrap();
    a.receive(forward_write).await.unwrap();
    for replica in [&a, &b] {
        assert_eq!(replica.followed_tip().await, back);
        let graph = replica.tip_graph(f.public.domain).await.unwrap();
        assert_eq!(graph.seal(next).unwrap(), Some(&close));
        let losers = graph.losing_moves("main").unwrap();
        assert_eq!(losers.len(), 1);
        assert_eq!(losers[0].statement.to, Some(forward_tip));
        assert_eq!(replica.snapshot(f.public).await.unwrap().rows.len(), 1);
        assert_eq!(replica.held_changes().await.unwrap().len(), 2);
    }
    // The resolution survives reopening.
    drop(a);
    let a = open(&f, &dir.path().join("a.db"), &a_key).await;
    assert_eq!(a.followed_tip().await, back);
    assert!(
        a.tip_graph(f.public.domain)
            .await
            .unwrap()
            .revoked
            .contains(&variants[winner].0.id().unwrap())
    );
}
