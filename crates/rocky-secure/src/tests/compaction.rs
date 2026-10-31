//! Lazy compaction at seals: finalizing drops what is dead at a seal's
//! frontier on every device; compacting moves the replay base there.
use super::generations::{Lineage, identity_insert, select, session, text};
use super::*;
use crate::TipStatement;
use rocky_core::{Commitment, ResourceScope, SqlValue, TipId, TypedRows};
use rocky_credentials::{
    AuthorMark, BOOKMARK_MOVE_FORMAT, BookmarkMoveStatement, SEAL_FORMAT, SealAction,
    SealStatement, SignedBookmarkMove, SignedCheckpointRecord, SignedSeal,
};

pub(super) type Replica = EncryptedReplica<TypedRows>;

/// Empty state is a signed fact at this seal, with no invented operations.
pub(super) fn assert_empty_checkpoint(signed: &crate::SignedCheckpoint, seal: Commitment) {
    signed.verify_signature().unwrap();
    let statement = &signed.statement;
    assert_eq!(statement.seal, Some(seal));
    assert_eq!(statement.operations, 0);
    assert_eq!(statement.rows.count, 0);
    assert_eq!(statement.tombstones, 0);
    assert_eq!(statement.creations.count, 0);
    assert_eq!(
        statement.key_epoch(),
        Some(rocky_core::KeyEpoch::new(1, &[41; 32]))
    );
}

pub(super) async fn open(
    lineage: &Lineage,
    dir: &TempDir,
    name: &str,
    key: &PrivateKey,
) -> Replica {
    lineage
        .open(
            &dir.path().join(format!("{name}.db")),
            key,
            3,
            Some(lineage.projection(3)),
        )
        .await
        .unwrap()
}
pub(super) fn bookmark(lineage: &Lineage, from: Option<TipId>, to: TipId) -> TipStatement {
    TipStatement::Bookmark(
        SignedBookmarkMove::sign(
            BookmarkMoveStatement {
                format: BOOKMARK_MOVE_FORMAT,
                scope: lineage.domain,
                name: "main".into(),
                from,
                to: Some(to),
            },
            lineage.publisher(),
        )
        .unwrap(),
    )
}
/// Creates `main` on the genesis tip and follows it.
pub(super) async fn follow_main(lineage: &Lineage, replica: &Replica) {
    let genesis = replica.followed_tip().await;
    replica
        .publish_tip_statements(&[bookmark(lineage, None, genesis)])
        .await
        .unwrap();
    replica
        .follow_bookmark(lineage.domain, "main")
        .await
        .unwrap();
}
/// The owner seals the followed tip at what `replica` holds and moves
/// `main` on; returns the seal.
pub(super) fn sign_seal(lineage: &Lineage, tip: TipId, frontier: Vec<AuthorMark>) -> SignedSeal {
    SignedSeal::sign(
        SealStatement {
            format: SEAL_FORMAT,
            scope: lineage.domain,
            tip,
            frontier,
            action: SealAction::Continue {
                schema: lineage.definition(3).hash(),
            },
            recovery: None,
        },
        lineage.publisher(),
    )
    .unwrap()
}
pub(super) async fn seal(lineage: &Lineage, replica: &Replica) -> SignedSeal {
    let tip = replica.followed_tip().await;
    let frontier = replica.seal_frontier(lineage.domain, false).await.unwrap();
    publish_seal(lineage, replica, sign_seal(lineage, tip, frontier)).await
}
async fn publish_seal(lineage: &Lineage, replica: &Replica, seal: SignedSeal) -> SignedSeal {
    let tip = seal.statement.tip;
    let next = seal.successor().unwrap().unwrap();
    replica
        .publish_tip_statements(&[
            TipStatement::Seal(seal.clone()),
            bookmark(lineage, Some(tip), next),
        ])
        .await
        .unwrap();
    seal
}
pub(super) async fn insert(replica: &Replica, key: &str, title: &str) {
    identity_insert(
        &session(replica).await,
        "INSERT INTO items(key,title) VALUES(?,?)",
        vec![text(key), text(title)],
    )
    .await
    .unwrap();
}
pub(super) async fn delete(replica: &Replica, key: &str) {
    session(replica)
        .await
        .run("DELETE FROM items WHERE key=?", vec![text(key)])
        .await
        .unwrap();
}
/// Inserts and deletes `cycles` rows.
async fn churn(replica: &Replica, cycles: usize, prefix: &str) {
    for cycle in 0..cycles {
        let key = format!("{prefix}{cycle}");
        insert(replica, &key, "churn").await;
        delete(replica, &key).await;
    }
}
pub(super) async fn scalar(replica: &Replica, sql: &str) -> i64 {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    match crate::storage::rows(&inner.conn, sql)
        .await
        .unwrap()
        .first()
        .map(Vec::as_slice)
    {
        Some([SqlValue::Integer(value)]) => *value,
        other => panic!("{other:?}"),
    }
}
/// Rows of the replay bases and how many are tombstones: replayed bases
/// hold live rows only.
async fn stored(replica: &Replica) -> (i64, i64) {
    (
        scalar(replica, "SELECT count(*) FROM secure_replayed_base").await,
        0,
    )
}
pub(super) async fn titles(replica: &Replica) -> Vec<Vec<SqlValue>> {
    select(replica, "SELECT key,title FROM items ORDER BY key").await
}

#[tokio::test]
async fn compacting_at_a_seal_leaves_only_live_rows_and_survives_reopen() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let replica = open(&lineage, &dir, "alice", &key).await;
    follow_main(&lineage, &replica).await;
    insert(&replica, "live", "kept").await;
    churn(&replica, 8, "a").await;
    assert_eq!(stored(&replica).await, (0, 0));
    let first = seal(&lineage, &replica).await;
    // Sealing alone changes no row; the next maintenance step finalizes.
    let report = replica.compact(lineage.domain, 0).await.unwrap();
    assert_eq!(report.waiting, None);
    assert_eq!(report.finalized, Some(first.id().unwrap()));
    assert_eq!(report.compacted, Some(first.id().unwrap()));
    assert_eq!(stored(&replica).await, (1, 0));
    assert_eq!(
        titles(&replica).await,
        vec![vec![text("live"), text("kept")]]
    );

    // Writes after the seal: the next seal finalizes and compacts them too.
    churn(&replica, 8, "b").await;
    insert(&replica, "later", "after the seal").await;
    let second = seal(&lineage, &replica).await;
    let report = replica.compact(lineage.domain, 0).await.unwrap();
    assert_eq!(report.compacted, Some(second.id().unwrap()));
    assert_eq!(stored(&replica).await, (2, 0));
    let expected = vec![
        vec![text("later"), text("after the seal")],
        vec![text("live"), text("kept")],
    ];
    assert_eq!(titles(&replica).await, expected);
    drop(replica);
    let replica = open(&lineage, &dir, "alice", &key).await;
    assert_eq!(titles(&replica).await, expected);
    let status = replica.compaction_status(lineage.domain).await.unwrap();
    assert_eq!(status.compacted, Some(second.id().unwrap()));
    assert!(status.uncompacted.is_empty());
}

/// Hands `source`'s graph and the items frames `target` lacks to `target`,
/// whose node key is `key`.
pub(super) async fn sync(lineage: &Lineage, source: &Replica, target: &Replica, key: &PrivateKey) {
    target
        .receive_tip_statements(&source.tip_statements(None, 32).await.unwrap())
        .await
        .unwrap();
    let scope = lineage.scope("items");
    let credentials = lineage.credentials(3, key);
    source
        .admit_peer(key.public_key(), &credentials, target.followed_tip().await)
        .await
        .unwrap();
    let mut after = None;
    loop {
        let frontier = target.frontier(scope).await.unwrap();
        let page = source
            .range_page(
                key.public_key(),
                &credentials,
                &frontier,
                after,
                MAX_SECURE_FRAME,
            )
            .await
            .unwrap();
        for status in target.receive_voids(&page.voids).await {
            status.unwrap();
        }
        for status in target.receive_all(page.frames).await {
            status.unwrap();
        }
        after = page.next;
        if after.is_none() {
            return;
        }
    }
}
async fn update(replica: &Replica, key: &str, title: &str) {
    session(replica)
        .await
        .run(
            "UPDATE items SET title=? WHERE key=?",
            vec![text(title), text(key)],
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn compacted_and_uncompacted_devices_apply_late_frames_across_two_seals_alike() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new(), PrivateKey::new()];
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    let b = open(&lineage, &dir, "b", &keys[1]).await;
    let c = open(&lineage, &dir, "c", &keys[2]).await;
    follow_main(&lineage, &a).await;
    insert(&a, "x", "original").await;
    insert(&a, "y", "doomed").await;
    for (replica, key) in [(&b, &keys[1]), (&c, &keys[2])] {
        sync(&lineage, &a, replica, key).await;
        replica
            .follow_bookmark(lineage.domain, "main")
            .await
            .unwrap();
    }
    // C writes offline on the genesis tip; none of it reaches the seals.
    update(&c, "x", "late edit").await;
    update(&c, "y", "edit of a deleted row").await;
    insert(&c, "z", "late insert").await;
    // A deletes y, seals, writes and seals again.
    delete(&a, "y").await;
    seal(&lineage, &a).await;
    insert(&a, "w", "between the seals").await;
    seal(&lineage, &a).await;
    sync(&lineage, &a, &b, &keys[1]).await;
    let compacted = a.compact(lineage.domain, 0).await.unwrap();
    assert_eq!(compacted.waiting, None);
    assert!(compacted.compacted.is_some());
    // Each maintenance step finalizes at most one seal. Finish the path
    // explicitly for the comparison with a device that compacted it.
    b.finalize_path(lineage.domain).await.unwrap();
    let status = b.compaction_status(lineage.domain).await.unwrap();
    assert_eq!(status.finalized, compacted.finalized);
    assert_eq!(status.compacted, None);
    assert_eq!(status.uncompacted.len(), 2);
    // C comes online: it learns the seals and follows main on; its late
    // frames walk both seals and apply alike on A and B.
    c.receive_tip_statements(&a.tip_statements(None, 32).await.unwrap())
        .await
        .unwrap();
    sync(&lineage, &c, &a, &keys[0]).await;
    sync(&lineage, &c, &b, &keys[1]).await;
    let expected = vec![
        vec![text("w"), text("between the seals")],
        vec![text("x"), text("late edit")],
        vec![text("z"), text("late insert")],
    ];
    assert_eq!(titles(&a).await, expected);
    assert_eq!(titles(&b).await, expected);
    // C, back online, follows main to the same rows.
    sync(&lineage, &a, &c, &keys[2]).await;
    assert_eq!(titles(&c).await, expected);
}

/// A seal of `seal`'s tip with a lower digest, and the move of `main` onto
/// its continuation.
/// A seal of `seal`'s tip with a lower digest that leaves out some of the
/// sealer's latest frames, which then walk on as late frames.
fn lower_rival(lineage: &Lineage, seal: &SignedSeal) -> Option<SignedSeal> {
    let latest = seal.statement.frontier.last()?.sequence;
    (1..=latest)
        .map(|fewer| {
            let mut statement = seal.statement.clone();
            statement.frontier.last_mut().unwrap().sequence = latest - fewer;
            SignedSeal::sign(statement, lineage.publisher()).unwrap()
        })
        .find(|rival| rival.id().unwrap() < seal.id().unwrap())
}
/// Seals the followed tip where a lower-digest rival exists; signatures are
/// deterministic, so another write changes the digest until one does.
async fn rivalled_seal(lineage: &Lineage, replica: &Replica) -> SignedSeal {
    for attempt in 0.. {
        let tip = replica.followed_tip().await;
        let frontier = replica.seal_frontier(lineage.domain, false).await.unwrap();
        let seal = sign_seal(lineage, tip, frontier);
        if lower_rival(lineage, &seal).is_some() {
            return publish_seal(lineage, replica, seal).await;
        }
        churn(replica, 1, &format!("rival{attempt}-")).await;
    }
    unreachable!()
}
fn rival(lineage: &Lineage, seal: &SignedSeal) -> (SignedSeal, Vec<TipStatement>) {
    let rival = lower_rival(lineage, seal).expect("a rival with a lower digest");
    let next = rival.successor().unwrap().unwrap();
    let statements = vec![
        TipStatement::Seal(rival.clone()),
        bookmark(lineage, Some(seal.statement.tip), next),
    ];
    (rival, statements)
}

#[tokio::test]
async fn a_seal_left_uncompacted_that_loses_is_rebuilt_and_a_compacted_one_rebootstraps() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let replica = open(&lineage, &dir, "keep", &key).await;
    follow_main(&lineage, &replica).await;
    insert(&replica, "a", "first").await;
    // Enough frames that some rival frontier has a lower digest.
    churn(&replica, 12, "c").await;
    let first = seal(&lineage, &replica).await;
    insert(&replica, "b", "second").await;
    let second = rivalled_seal(&lineage, &replica).await;
    let report = replica.compact(lineage.domain, 1).await.unwrap();
    assert_eq!(report.finalized, Some(second.id().unwrap()));
    assert_eq!(report.compacted, Some(first.id().unwrap()));
    // A concurrent seal of the second's tip wins; the device rebuilds from
    // its base at the first seal and ends on the winner.
    let (winner, statements) = rival(&lineage, &second);
    replica.receive_tip_statements(&statements).await.unwrap();
    assert_eq!(
        replica.followed_tip().await,
        winner.successor().unwrap().unwrap()
    );
    let status = replica.compaction_status(lineage.domain).await.unwrap();
    assert_eq!(status.rebootstrap, None);
    assert_eq!(status.compacted, Some(first.id().unwrap()));
    assert_eq!(
        titles(&replica).await,
        vec![
            vec![text("a"), text("first")],
            vec![text("b"), text("second")]
        ]
    );
    let report = replica.compact(lineage.domain, 0).await.unwrap();
    assert_eq!(report.compacted, Some(winner.id().unwrap()));

    // With nothing left uncompacted, a winning rival needs a rebootstrap:
    // the device follows the winner, its rows wait and writes are refused.
    insert(&replica, "c", "third").await;
    churn(&replica, 12, "d").await;
    let third = rivalled_seal(&lineage, &replica).await;
    replica.compact(lineage.domain, 0).await.unwrap();
    let (winner, statements) = rival(&lineage, &third);
    replica.receive_tip_statements(&statements).await.unwrap();
    assert_eq!(
        replica.followed_tip().await,
        winner.successor().unwrap().unwrap()
    );
    let status = replica.compaction_status(lineage.domain).await.unwrap();
    assert_eq!(status.rebootstrap, Some(third.id().unwrap()));
    let refused = session(&replica)
        .await
        .run("DELETE FROM items WHERE key=?", vec![text("a")])
        .await;
    assert!(
        refused
            .as_ref()
            .is_err_and(|error| error.to_string().contains("rebootstrap")),
        "{refused:?}"
    );
    // The graph lists no checkpoint at the winner; the device holds every
    // frame, so it replays them.
    let scope = lineage.scope("items");
    let needs = replica.seal_rebootstraps(lineage.domain).await.unwrap();
    assert_eq!(
        needs,
        vec![crate::SealRebootstrap {
            scope,
            listed: Vec::new(),
            replay: crate::FrameReplay::Local,
        }]
    );
    // A reset must replay retained frames without waiting for another incoming frame.
    replica.replay_at_seals(scope, true).await.unwrap();
    let status = replica.compaction_status(lineage.domain).await.unwrap();
    assert_eq!((status.rebootstrap, status.compacted), (None, None));
    let expected = vec![
        vec![text("a"), text("first")],
        vec![text("b"), text("second")],
        vec![text("c"), text("third")],
    ];
    assert_eq!(titles(&replica).await, expected);
    let report = replica.compact(lineage.domain, 0).await.unwrap();
    assert_eq!(report.compacted, Some(winner.id().unwrap()));
    insert(&replica, "d", "after the rebootstrap").await;
    assert_eq!(titles(&replica).await.len(), 4);
}

/// Imports `source`'s replay base of `scope` into `target`, whose node key
/// is `key`, page by page.
pub(super) async fn import_checkpoint(
    lineage: &Lineage,
    source: &Replica,
    target: &Replica,
    key: &PrivateKey,
    scope: ResourceScope,
) -> Commitment {
    import_checkpoint_report(lineage, source, target, key, scope)
        .await
        .checkpoint
}
/// [`import_checkpoint`], returning the import's report.
pub(super) async fn import_checkpoint_report(
    lineage: &Lineage,
    source: &Replica,
    target: &Replica,
    key: &PrivateKey,
    scope: ResourceScope,
) -> crate::RebootstrapReport {
    let credentials = lineage.credentials(3, key);
    source
        .admit_peer(key.public_key(), &credentials, target.followed_tip().await)
        .await
        .unwrap();
    let offered = source
        .checkpoint_offer(key.public_key(), &credentials, scope)
        .await
        .unwrap()
        .expect("a checkpoint at a seal");
    let checkpoint = offered.id().unwrap();
    target.begin_rebootstrap(offered).await.unwrap();
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
    let report = target.finish_rebootstrap(scope).await.unwrap();
    assert_eq!(report.checkpoint, checkpoint);
    report
}
/// The highest-sequence retained operation of `scope`.
pub(super) async fn last_operation(replica: &Replica, scope: ResourceScope) -> Hash {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    let records = crate::storage::collect_rows(
        inner
            .conn
            .query(
                "SELECT hash FROM secure_operations WHERE scope=? ORDER BY sequence DESC LIMIT 1",
                [encode(&scope).unwrap()],
            )
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    let [SqlValue::Blob(hash)] = records[0].as_slice() else {
        panic!("operation");
    };
    Hash::from_bytes(hash.as_slice().try_into().unwrap())
}
/// `replica`'s live identity mark of `author` in `scope`.
pub(super) async fn live_mark(replica: &Replica, scope: ResourceScope, author: u32) -> u32 {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    let records = crate::storage::collect_rows(
        inner
            .conn
            .query(
                "SELECT sequence FROM secure_identity_marks WHERE scope=? AND author=?",
                crate::storage::bindings(vec![
                    SqlValue::Blob(encode(&scope).unwrap()),
                    SqlValue::Integer(author.into()),
                ]),
            )
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    match records.first().map(Vec::as_slice) {
        Some([SqlValue::Integer(sequence)]) => u32::try_from(*sequence).unwrap(),
        None => 0,
        other => panic!("{other:?}"),
    }
}
/// The owner lists `replica`'s replay bases at seals in the graph.
pub(super) async fn list_checkpoints(lineage: &Lineage, replica: &Replica) -> Vec<TipStatement> {
    let records: Vec<TipStatement> = replica
        .unlisted_checkpoints(lineage.domain)
        .await
        .unwrap()
        .into_iter()
        .map(|statement| {
            TipStatement::Checkpoint(Box::new(
                SignedCheckpointRecord::sign(statement, lineage.publisher()).unwrap(),
            ))
        })
        .collect();
    replica.publish_tip_statements(&records).await.unwrap();
    assert!(
        replica
            .unlisted_checkpoints(lineage.domain)
            .await
            .unwrap()
            .is_empty()
    );
    records
}

#[tokio::test]
async fn a_compacted_seal_that_loses_rebootstraps_from_a_checkpoint_the_graph_lists() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new()];
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    let b = open(&lineage, &dir, "b", &keys[1]).await;
    follow_main(&lineage, &a).await;
    insert(&a, "x", "kept").await;
    churn(&a, 12, "c").await;
    sync(&lineage, &a, &b, &keys[1]).await;
    b.follow_bookmark(lineage.domain, "main").await.unwrap();
    // A compacts its seal at once; B receives the frames and then a rival
    // seal that wins, compacts there and lists its checkpoint.
    insert(&a, "y", "late").await;
    // Keep the last frame a birth: the rival must exclude a newer identity,
    // rather than only the delete at the end of the helper's churn.
    let sealed = loop {
        let tip = a.followed_tip().await;
        let frontier = a.seal_frontier(lineage.domain, false).await.unwrap();
        let signed = sign_seal(&lineage, tip, frontier);
        if lower_rival(&lineage, &signed).is_some() {
            break publish_seal(&lineage, &a, signed).await;
        }
        delete(&a, "y").await;
        insert(&a, "y", "late").await;
    };
    a.compact(lineage.domain, 0).await.unwrap();
    sync(&lineage, &a, &b, &keys[1]).await;
    let (winner, statements) = rival(&lineage, &sealed);
    b.receive_tip_statements(&statements).await.unwrap();
    let report = b.compact(lineage.domain, 0).await.unwrap();
    assert_eq!(report.compacted, Some(winner.id().unwrap()));
    let records = list_checkpoints(&lineage, &b).await;
    assert_eq!(records.len(), 2);

    // A learns the winner and the record: its compacted seal lost.
    a.receive_tip_statements(&b.tip_statements(None, 32).await.unwrap())
        .await
        .unwrap();
    let status = a.compaction_status(lineage.domain).await.unwrap();
    assert_eq!(status.rebootstrap, Some(sealed.id().unwrap()));
    let graph = a.tip_graph(lineage.domain).await.unwrap();
    let listed = graph.checkpoints_at(winner.id().unwrap()).unwrap();
    assert_eq!(listed.len(), 2);
    assert!(
        listed
            .iter()
            .all(|record| record.statement.signer == keys[1].public_key())
    );
    let scope = lineage.scope("items");
    let needs = a.seal_rebootstraps(lineage.domain).await.unwrap();
    assert_eq!(needs.len(), 2);
    for need in &needs {
        let record = listed
            .iter()
            .find(|record| record.statement.table == need.scope)
            .unwrap();
        assert_eq!(need.listed, vec![record.statement.checkpoint]);
    }
    let listed_items = listed
        .iter()
        .find(|record| record.statement.table == scope)
        .unwrap();
    let tags = lineage.scope("tags");
    b.admit_peer(
        keys[0].public_key(),
        &lineage.credentials(3, &keys[0]),
        a.followed_tip().await,
    )
    .await
    .unwrap();
    let empty = b
        .checkpoint_offer(
            keys[0].public_key(),
            &lineage.credentials(3, &keys[0]),
            tags,
        )
        .await
        .unwrap()
        .unwrap();
    assert_empty_checkpoint(&empty, winner.id().unwrap());
    let imported_empty = import_checkpoint(&lineage, &b, &a, &keys[0], tags).await;
    assert_eq!(imported_empty, empty.id().unwrap());
    assert_eq!(scalar(&a, "SELECT count(*) FROM tags").await, 0);

    // The winner's marks cover only the identities its own state created,
    // below y's, which A still holds and has applied.
    let offered = b
        .checkpoint_offer(
            keys[0].public_key(),
            &lineage.credentials(3, &keys[0]),
            scope,
        )
        .await
        .unwrap()
        .unwrap();
    let [mark] = offered.statement.identities.as_slice() else {
        panic!("{:?}", offered.statement.identities);
    };
    let late = live_mark(&a, scope, mark.author).await;
    assert!(mark.sequence < late, "{mark:?} {late}");
    let y = last_operation(&a, scope).await;
    // It imports the listed checkpoint; its frames the winner left out
    // apply again on top as late frames.
    let report = import_checkpoint_report(&lineage, &b, &a, &keys[0], scope).await;
    assert_eq!(report.checkpoint, listed_items.statement.checkpoint);
    assert!(report.rejected.is_empty(), "{:?}", report.rejected);
    assert!(report.reapplied.contains(&y), "{report:?}");
    assert_eq!(live_mark(&a, scope, mark.author).await, late);
    assert!(a.finish_seal_rebootstrap(lineage.domain).await.unwrap());
    let status = a.compaction_status(lineage.domain).await.unwrap();
    assert_eq!(status.rebootstrap, None);
    assert_eq!(titles(&a).await, titles(&b).await);
    assert_eq!(
        titles(&a).await,
        vec![vec![text("x"), text("kept")], vec![text("y"), text("late")]]
    );
    // It finalizes from the imported base and compacts at the winner.
    let report = a.compact(lineage.domain, 0).await.unwrap();
    assert_eq!(report.waiting, None);
    assert_eq!(report.compacted, Some(winner.id().unwrap()));
    insert(&a, "z", "after").await;
    assert_eq!(titles(&a).await.len(), 3);
}

#[tokio::test]
async fn a_pruned_device_whose_compacted_seal_loses_replays_frames_from_a_peer() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new()];
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    let b = open(&lineage, &dir, "b", &keys[1]).await;
    follow_main(&lineage, &a).await;
    sync(&lineage, &a, &b, &keys[1]).await;
    b.follow_bookmark(lineage.domain, "main").await.unwrap();
    let scope = lineage.scope("items");
    a.set_retention_policy(
        scope,
        crate::RetentionPolicy {
            required: BTreeSet::from([rocky_credentials::PeerId::of(keys[1].public_key())]),
            behind: BTreeSet::new(),
            copies: 1,
            window: 0,
        },
    )
    .await
    .unwrap();
    insert(&a, "x", "kept").await;
    churn(&a, 12, "c").await;
    insert(&a, "y", "late").await;
    let sealed = rivalled_seal(&lineage, &a).await;
    sync(&lineage, &a, &b, &keys[1]).await;
    a.acknowledge_frontier(
        keys[1].public_key(),
        &lineage.credentials(3, &keys[1]),
        &b.frontier(scope).await.unwrap(),
    )
    .await
    .unwrap();
    let report = a.compact(lineage.domain, 0).await.unwrap();
    assert!(report.pruned > 0);
    // B, which compacts nothing and lists nothing, takes the winner.
    let (_, statements) = rival(&lineage, &sealed);
    b.receive_tip_statements(&statements).await.unwrap();
    a.receive_tip_statements(&statements).await.unwrap();
    let needs = a.seal_rebootstraps(lineage.domain).await.unwrap();
    assert_eq!(needs.len(), 2);
    assert_eq!(
        needs
            .iter()
            .find(|need| need.scope == scope)
            .unwrap()
            .replay,
        crate::FrameReplay::Peers
    );
    let tags = lineage.scope("tags");
    assert_eq!(
        needs.iter().find(|need| need.scope == tags).unwrap().replay,
        crate::FrameReplay::Local
    );
    a.replay_at_seals(tags, false).await.unwrap();
    assert!(
        a.seal_rebootstraps(lineage.domain)
            .await
            .unwrap()
            .iter()
            .all(|need| need.scope != tags)
    );
    drop(a);
    let a = lineage
        .reopen(&dir.path().join("a.db"), &keys[0], 3, 3)
        .await
        .unwrap();
    assert!(
        a.seal_rebootstraps(lineage.domain)
            .await
            .unwrap()
            .iter()
            .all(|need| need.scope != tags)
    );
    assert_eq!(scalar(&a, "SELECT count(*) FROM tags").await, 0);
    assert!(
        a.replay_at_seals(scope, false)
            .await
            .is_err_and(|error| error.to_string().contains("peer"))
    );
    // A keeps what it holds and takes the pruned frames from B again.
    a.replay_at_seals(scope, true).await.unwrap();
    let label = crate::scope_label(&scope);
    let waiting = a.blockers().await.unwrap();
    use super::blockers::assert_named;
    assert_named(
        &waiting,
        &label,
        |kind| *kind == crate::BlockerKind::RestorationGuard,
        crate::ClearsBy::AnyPeer,
    );
    let refusal = super::blockers::refused(
        identity_insert(
            &session(&a).await,
            "INSERT INTO items(key,title) VALUES(?,?)",
            vec![text("r"), text("refused")],
        )
        .await,
    );
    // The write is refused for the scope's own rebootstrap, among the rest.
    assert_named(
        &refusal,
        &label,
        |kind| matches!(kind, crate::BlockerKind::SealRebootstrap { .. }),
        crate::ClearsBy::AnyPeer,
    );
    assert!(
        refusal.iter().all(|blocker| waiting.contains(blocker)) && !refusal.is_empty(),
        "{refusal:?} in {waiting:?}"
    );
    assert_eq!(scalar(&a,"SELECT count(*) FROM secure_seal_anchors a JOIN secure_scope_state s ON s.id=a.scope WHERE s.scope=(SELECT scope FROM secure_evicted_logs LIMIT 1)").await,0);
    assert!(
        a.compaction_status(lineage.domain)
            .await
            .unwrap()
            .waiting
            .is_some()
    );
    sync(&lineage, &b, &a, &keys[0]).await;
    a.restored(scope).await.unwrap();
    assert_eq!(
        a.compaction_status(lineage.domain)
            .await
            .unwrap()
            .rebootstrap,
        None
    );
    let cleared = a.blockers().await.unwrap();
    assert!(
        cleared.iter().all(|blocker| !matches!(
            blocker.kind,
            crate::BlockerKind::RestorationGuard
                | crate::BlockerKind::LostCompaction
                | crate::BlockerKind::SealRebootstrap { .. }
                | crate::BlockerKind::PendingFrames { .. }
        )),
        "{cleared:?}"
    );
    assert_eq!(titles(&a).await, titles(&b).await);
    assert_eq!(
        titles(&a).await,
        vec![vec![text("x"), text("kept")], vec![text("y"), text("late")]]
    );
}

#[tokio::test]
async fn compaction_at_seals_plateaus_under_insert_delete_churn() {
    let lineage = Lineage::pinned(121);
    let dir = TempDir::new().unwrap();
    let keys = [122, 123].map(|seed| PrivateKey::from_bytes(&[seed; 32]));
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    let b = open(&lineage, &dir, "b", &keys[1]).await;
    follow_main(&lineage, &a).await;
    sync(&lineage, &a, &b, &keys[1]).await;
    b.follow_bookmark(lineage.domain, "main").await.unwrap();
    let scope = lineage.scope("items");
    let mut limits = a.retention_limits().await;
    limits.handles = 4;
    a.set_retention_limits(limits).await.unwrap();
    a.set_retention_policy(
        scope,
        crate::RetentionPolicy {
            required: BTreeSet::from([rocky_credentials::PeerId::of(keys[1].public_key())]),
            behind: BTreeSet::new(),
            copies: 1,
            window: 0,
        },
    )
    .await
    .unwrap();
    let empty_seal = seal(&lineage, &a).await.id().unwrap();
    a.compact(lineage.domain, 0).await.unwrap();
    insert(&a, "live", "kept").await;
    let mut plateau = None;
    let mut admission: Option<receipts::Accounting> = None;
    for cycle in 1..=64 {
        churn(&a, 1, &format!("cycle{cycle}-")).await;
        if ![16, 64].contains(&cycle) {
            continue;
        }
        seal(&lineage, &a).await;
        sync(&lineage, &a, &b, &keys[1]).await;
        a.acknowledge_frontier(
            keys[1].public_key(),
            &lineage.credentials(3, &keys[1]),
            &b.frontier(scope).await.unwrap(),
        )
        .await
        .unwrap();
        let report = a.compact(lineage.domain, 0).await.unwrap();
        assert_eq!(report.blocked, Vec::new());
        assert!(report.pruned > 0);
        let verified = crate::storage::collect_rows(
            a.inner
                .lock(crate::replica::Class::Background)
                .await
                .conn
                .query(
                    "SELECT s.scope,b.position,f.seal,c.signed FROM secure_seal_bounds b JOIN secure_scope_state s ON s.id=b.scope JOIN secure_finalized f ON f.depth=b.depth JOIN secure_checkpoints c ON c.scope=s.id",
                    (),
                )
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        let [record] = verified.as_slice() else {
            panic!("one current verification bound for the unchanged empty scope")
        };
        assert_eq!(
            record[0],
            SqlValue::Blob(encode(&lineage.scope("tags")).unwrap())
        );
        assert_eq!(record[1], SqlValue::Integer(0));
        assert_eq!(
            record[2],
            SqlValue::Blob(report.compacted.unwrap().to_vec())
        );
        let SqlValue::Blob(bytes) = &record[3] else {
            panic!("signed empty base")
        };
        let empty = crate::SignedCheckpoint::from_bytes(bytes).unwrap();
        assert_eq!(empty.statement.scope, lineage.scope("tags"));
        assert_empty_checkpoint(&empty, empty_seal);
        let counts = (
            stored(&a).await,
            scalar(&a, "SELECT count(*) FROM secure_stubs").await,
            scalar(&a, "SELECT count(*) FROM secure_operations").await,
            scalar(&a, "SELECT count(*) FROM secure_applied").await,
            scalar(&a, "SELECT count(*) FROM secure_handles").await,
            scalar(&a, "SELECT count(*) FROM secure_finalized").await,
            scalar(
                &a,
                "SELECT (SELECT count(*) FROM secure_seal_bounds)+(SELECT count(*) FROM secure_seal_drops)",
            )
            .await,
        );
        println!("seal compaction churn: cycles={cycle}; {counts:?}");
        // One live base row and the latest empty-scope proof.
        assert_eq!(counts, ((1, 0), 0, 0, 0, 4, 1, 1));
        if let Some(previous) = plateau {
            assert_eq!(previous, counts);
        }
        plateau = Some(counts);
        let measured = receipts::accounting(&a, &dir.path().join("a.db"), cycle).await;
        // Replayed inserts are no births: admission evidence does not grow.
        if let Some(previous) = admission {
            assert_eq!(measured.entries, previous.entries);
            assert_eq!(measured.grants, previous.grants);
            assert_eq!(measured.chains, previous.chains);
            assert_eq!(measured.bounded, previous.bounded);
            assert_eq!(measured.logical_bytes, previous.logical_bytes);
        }
        admission = Some(measured);
    }
    assert_eq!(titles(&a).await, vec![vec![text("live"), text("kept")]]);
}

#[tokio::test]
async fn changing_one_table_keeps_the_other_base_observer_and_session_untouched() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let replica = open(&lineage, &dir, "alice", &PrivateKey::new()).await;
    follow_main(&lineage, &replica).await;
    insert(&replica, "a", "before").await;
    identity_insert(
        &session(&replica).await,
        "INSERT INTO tags(key,label) VALUES('tag','kept')",
        vec![],
    )
    .await
    .unwrap();
    seal(&lineage, &replica).await;
    replica.compact(lineage.domain, 0).await.unwrap();
    let tags = lineage.scope("tags");
    let before = replica.checkpoint(tags).await.unwrap();
    update(&replica, "a", "after").await;
    seal(&lineage, &replica).await;
    let session = session(&replica).await;
    let mut observer = replica.observe_tables(Some(&["tags"])).await.unwrap();
    replica.compact(lineage.domain, 0).await.unwrap();
    assert_eq!(
        replica.checkpoint(tags).await.unwrap().to_bytes().unwrap(),
        before.to_bytes().unwrap()
    );
    assert_eq!(observer.try_next().unwrap(), None);
    let rows = session.run("SELECT label FROM tags", vec![]).await.unwrap();
    assert_eq!(rows.rows, vec![vec![text("kept")]]);
}

mod anchors;
pub(in crate::tests) mod audit;
mod deferred;
mod eligibility;
mod identities;
mod own;
mod partial_reads;
mod readiness;
mod receipts;
mod scope_local;
mod staged_switches;

mod restoration;

mod state_advice;

mod incremental;
