//! Late transactions continue in the successor tip: two devices that
//! exchanged transactions while the owner sealed without them replay them
//! after the seal's members, with their original identity and stamp.
use super::*;
use crate::CrashPoint;
use rocky_credentials::{BOOKMARK_MOVE_FORMAT, BookmarkMoveStatement, SignedBookmarkMove};

/// Creates `main` at the genesis tip on the owner's device and follows it.
async fn follow_main(f: &Fixture, replica: &EncryptedReplica<TypedRows>) {
    let created = TipStatement::Bookmark(
        SignedBookmarkMove::sign(
            BookmarkMoveStatement {
                format: BOOKMARK_MOVE_FORMAT,
                scope: f.domain,
                name: "main".into(),
                from: None,
                to: Some(replica.followed_tip().await),
            },
            &f.publisher,
        )
        .unwrap(),
    );
    replica.publish_tip_statements(&[created]).await.unwrap();
    replica.follow_bookmark(f.domain, "main").await.unwrap();
}

fn raise(by: i64) -> (&'static str, Vec<SqlValue>) {
    (
        "UPDATE items SET amount=amount+? WHERE list='A' AND key='x'",
        vec![SqlValue::Integer(by)],
    )
}

/// Intent frames of `frames`, as delivered to the owner.
fn intents(f: &Fixture, frames: &[EncryptedFrame]) -> usize {
    frames
        .iter()
        .filter(|frame| payload(frame, key_of(f, frame), f).intent().is_some())
        .count()
}

/// The owner and two devices that exchanged transactions offline while
/// the owner sealed `main` without them.
struct Offline {
    owner: Author,
    a: Author,
    b: Author,
    /// The owner's transactions, which its seal covers.
    sealed: Vec<EncryptedFrame>,
    /// A's raise, then B's raise and B's create of `k`.
    offline: Vec<Vec<EncryptedFrame>>,
}

/// The owner creates `x`. Offline from it, A raises `x` by 1; B, having
/// seen that, raises it by 10 and creates `k`; A receives B's. The owner
/// meanwhile doubles `x`, creates its own `k`, seals and finalizes.
async fn offline_history(f: &Fixture, root: &Path) -> Offline {
    let mut owner = Author::open(f, root, 1).await;
    let mut a = Author::open(f, root, 2).await;
    let mut b = Author::open(f, root, 3).await;
    follow_main(f, &owner.replica).await;
    for device in [&a, &b] {
        exchange_graphs(&owner.replica, &device.replica, f.domain).await;
    }
    owner.create(f, &[("A", "x", 1)], 1).await;
    let created = owner.fresh().await;
    a.receive(&created).await;
    b.receive(&created).await;

    a.run(f, &[raise(1)], 1).await;
    let a1 = a.fresh().await;
    b.receive(&a1).await;
    b.run(f, &[raise(10)], 1).await;
    let b1 = b.fresh().await;
    b.create(f, &[("A", "k", 3)], 2).await;
    let b2 = b.fresh().await;
    a.receive(&b1).await;
    a.receive(&b2).await;
    assert_eq!(
        keys(f, &a.replica, &["A"]).await,
        vec![
            vec![text("A"), text("k"), SqlValue::Integer(3)],
            vec![text("A"), text("x"), SqlValue::Integer(12)],
        ]
    );

    owner
        .run(
            f,
            &[(
                "UPDATE items SET amount=amount*2 WHERE list='A' AND key='x'",
                vec![],
            )],
            2,
        )
        .await;
    owner.create(f, &[("A", "k", 5)], 3).await;
    let sealed = created.iter().cloned().chain(owner.fresh().await).collect();
    seal_main(&owner.replica, &f.publisher, f.domain).await;
    owner.replica.finalize_path(f.domain).await.unwrap();
    Offline {
        owner,
        a,
        b,
        sealed,
        offline: vec![a1, b1, b2],
    }
}

impl Offline {
    fn offline(&self) -> Vec<EncryptedFrame> {
        self.offline.iter().flatten().cloned().collect()
    }

    /// The reference: the seal's members, then the rest in stamp order.
    fn expected(&self, f: &Fixture) -> Canonical {
        canonical_sealed(f, &[&self.sealed, &self.offline()], 1)
    }

    /// A follows the successor and receives the owner's transactions.
    async fn reconnect_a(&self, f: &Fixture) {
        exchange_graphs(&self.owner.replica, &self.a.replica, f.domain).await;
        self.a.receive(&self.sealed).await;
    }
}

fn outcome(dropped: Option<DropReason>, sealed: bool) -> TransactionOutcome {
    match dropped {
        None => TransactionOutcome::Applied,
        Some(reason) => TransactionOutcome::Dropped { reason, sealed },
    }
}

#[tokio::test]
async fn offline_peers_transactions_replay_after_the_seal_in_its_successor() {
    let f = Fixture::build_class(false, PrivateKey::new(), "replayed");
    let root = tempfile::tempdir().unwrap();
    let mut h = offline_history(&f, root.path()).await;
    let late_k = transaction(&h.offline[2][0], [1; 32], &f);
    assert_eq!(
        h.a.replica.transaction_outcome(late_k).await.unwrap(),
        Some(outcome(None, false))
    );

    // A reconnects and finalizes the seal: its own and B's transactions
    // replay after the seal's members, and B's `k`, applied before, now
    // drops behind the owner's.
    h.reconnect_a(&f).await;
    h.a.replica.finalize_path(f.domain).await.unwrap();
    let expected = h.expected(&f);
    assert_eq!(
        expected.rows,
        vec![
            vec![text("A"), text("k"), SqlValue::Integer(5)],
            vec![text("A"), text("x"), SqlValue::Integer(13)],
        ]
    );
    assert_eq!(
        expected.outcomes[&late_k],
        outcome(Some(DropReason::Constraint), false)
    );
    assert_eq!(state(&f, &h.a.replica, &expected).await, expected);
    // A reauthors nothing: what it relays are B's original frames.
    assert_eq!(intents(&f, &h.a.fresh().await), 0);
    assert!(h.a.replica.held_changes().await.unwrap().is_empty());

    // The owner gets them from A, twice; B has not reconnected.
    let offline = h.offline();
    for _ in 0..2 {
        h.owner.receive(&offline).await;
        assert_eq!(state(&f, &h.owner.replica, &expected).await, expected);
    }
    // A restart keeps it.
    let node = h.a.node.clone();
    drop(h.a);
    h.a = Author::at(&f, root.path(), 2, node).await;
    assert_eq!(state(&f, &h.a.replica, &expected).await, expected);

    // The owner's next seal covers them: B's drop becomes final. B, back at
    // last, gets the same without authoring anything again.
    seal_main(&h.owner.replica, &f.publisher, f.domain).await;
    h.owner.replica.finalize_path(f.domain).await.unwrap();
    let last = canonical_sealed(&f, &[&h.sealed, &offline], 2);
    assert_eq!(
        last.outcomes[&late_k],
        outcome(Some(DropReason::Constraint), true)
    );
    exchange_graphs(&h.owner.replica, &h.b.replica, f.domain).await;
    h.b.receive(&h.sealed).await;
    h.b.replica.finalize_path(f.domain).await.unwrap();
    for replica in [&h.owner.replica, &h.b.replica] {
        assert_eq!(state(&f, replica, &last).await, last);
        assert_eq!(replica.unsealed_replayed_transactions().await.unwrap(), 0);
    }
    assert_eq!(intents(&f, &h.b.fresh().await), 0);
}

/// Every order of the owner's and the offline transactions, with the
/// successor learned before, between or after them, converges once the
/// receiver finalizes the seal.
#[tokio::test]
async fn every_order_around_the_successor_converges_to_the_sealed_replay() {
    let f = Fixture::build_class(false, PrivateKey::new(), "replayed");
    let root = tempfile::tempdir().unwrap();
    let h = offline_history(&f, root.path()).await;
    let expected = h.expected(&f);
    let units: Vec<Vec<EncryptedFrame>> = std::iter::once(h.sealed.clone())
        .chain(h.offline.iter().cloned())
        .collect();
    let mut index = 0;
    for order in permutations(units.len()) {
        for graph in 0..=units.len() {
            let path = root.path().join(format!("r{index}.sqlite"));
            index += 1;
            let node = PrivateKey::new();
            let replica = receiver(&f, &path, &node).await;
            for (position, unit) in order.iter().enumerate() {
                if position == graph {
                    exchange_graphs(&h.owner.replica, &replica, f.domain).await;
                }
                for status in replica.receive_all(units[*unit].clone()).await {
                    assert_ne!(status.unwrap(), ReceiveStatus::Rejected);
                }
            }
            if graph == units.len() {
                exchange_graphs(&h.owner.replica, &replica, f.domain).await;
            }
            replica.finalize_path(f.domain).await.unwrap();
            assert_eq!(
                state(&f, &replica, &expected).await,
                expected,
                "{order:?} {graph}"
            );
            drop(replica);
            std::fs::remove_file(&path).ok();
        }
    }
}

/// A, killed at `point` while it finalizes the seal it reconnects to,
/// reopens with nothing of the finalization done and converges once it
/// receives the seal's members again.
async fn finalization_crash(point: CrashPoint) {
    let f = Fixture::build_class(false, PrivateKey::new(), "replayed");
    let root = tempfile::tempdir().unwrap();
    let mut h = offline_history(&f, root.path()).await;
    let unsealed = h.a.replica.unsealed_replayed_transactions().await.unwrap();
    h.a.replica.arm_crash(Some(point)).await;
    // The receive that completes the seal's members finalizes it, after
    // its group commits; that maintenance step fails at the point.
    h.reconnect_a(&f).await;
    assert_eq!(h.a.replica.crashed().await, Some(point));
    let node = h.a.node.clone();
    drop(h.a);

    h.a = Author::at(&f, root.path(), 2, node).await;
    assert!(
        h.a.replica
            .compaction_status(f.domain)
            .await
            .unwrap()
            .finalized
            .is_none()
    );
    // Every received transaction is open, in stamp order.
    let provisional = canonical(
        &f,
        &h.sealed
            .iter()
            .cloned()
            .chain(h.offline())
            .collect::<Vec<_>>(),
    );
    assert_eq!(state(&f, &h.a.replica, &provisional).await, provisional);
    assert_eq!(
        h.a.replica.unsealed_replayed_transactions().await.unwrap(),
        unsealed + 2
    );
    h.a.replica.finalize_path(f.domain).await.unwrap();
    let expected = h.expected(&f);
    assert_eq!(state(&f, &h.a.replica, &expected).await, expected);
    // Only the transactions the seal left out keep undo records.
    assert_eq!(
        h.a.replica.unsealed_replayed_transactions().await.unwrap(),
        3
    );
}

#[tokio::test]
async fn a_crash_while_a_seal_deletes_undo_records_reopens_and_converges() {
    finalization_crash(CrashPoint::UndoDeletion).await;
}

#[tokio::test]
async fn a_crash_while_a_seal_rewinds_its_late_transactions_reopens_and_converges() {
    finalization_crash(CrashPoint::Rewind).await;
}

#[tokio::test]
async fn a_crash_while_a_seal_redoes_its_late_transactions_reopens_and_converges() {
    finalization_crash(CrashPoint::Redo).await;
}

/// Compaction signs a replayed partition's rows at the seal as its base;
/// with every frame still retained, a member joining after it replays
/// them instead of installing the base.
#[tokio::test]
async fn compaction_signs_a_replayed_base_and_a_later_member_replays_the_frames() {
    let f = Fixture::build_class(false, PrivateKey::new(), "replayed");
    let root = tempfile::tempdir().unwrap();
    let mut owner = Author::open(&f, root.path(), 1).await;
    follow_main(&f, &owner.replica).await;
    owner.create(&f, &[("A", "x", 1)], 1).await;
    owner.run(&f, &[raise(4)], 2).await;
    let frames = owner.fresh().await;
    seal_main(&owner.replica, &f.publisher, f.domain).await;
    let report = owner.replica.compact(f.domain, 0).await.unwrap();
    assert!(report.compacted.is_some());
    assert_eq!(
        owner.replica.prune(f.scope("A")).await.unwrap().blocked,
        Some(crate::PruneBlock::NoPolicy)
    );
    let later = Author::open(&f, root.path(), 2).await;
    exchange_graphs(&owner.replica, &later.replica, f.domain).await;
    later.receive(&frames).await;
    assert!(
        later
            .replica
            .seal_rebootstraps(f.domain)
            .await
            .unwrap()
            .is_empty()
    );
    let expected = canonical_sealed(&f, &[&frames], 1);
    for replica in [&owner.replica, &later.replica] {
        assert_eq!(state(&f, replica, &expected).await, expected);
    }
}
