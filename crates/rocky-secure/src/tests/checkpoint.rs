//! Checkpoints, pruning, the pruned_prefix signal and rebootstrap.
use super::super::replica::checkpoint::Stage;
use super::*;
use crate::storage::rows;
use network::NativeSession;
use rocky_core::SqlValue;
use std::collections::BTreeMap;
use std::path::Path;

type Replica = EncryptedReplica<Employees>;

fn id(index: u16) -> [u8; 32] {
    let mut row = [7; 32];
    row[..2].copy_from_slice(&index.to_be_bytes());
    row
}
fn handle(index: u16) -> [u8; 32] {
    let mut handle = [9; 32];
    handle[..2].copy_from_slice(&index.to_be_bytes());
    handle
}
fn insert(f: &Fixture, index: u16, name: &str) -> Vec<RowChange> {
    vec![RowChange {
        scope: f.public,
        row: id(index),
        before: None,
        after: Some(f.app().name(name)),
    }]
}
fn update(f: &Fixture, index: u16, before: &str, after: Option<&str>) -> Vec<RowChange> {
    vec![RowChange {
        scope: f.public,
        row: id(index),
        before: Some(f.app().name(before)),
        after: after.map(|name| f.app().name(name)),
    }]
}
async fn open(f: &Fixture, path: &Path, node: &PrivateKey) -> (Replica, CredentialChain) {
    let config = f.config(node, f.full(), &[f.public]);
    let credentials = config.credentials.clone();
    (
        EncryptedReplica::open(path, f.app(), config).await.unwrap(),
        credentials,
    )
}
/// Exchanges tip graphs as a link does: each side follows `main` once it
/// exists, and `source` learns which tip `target` follows.
async fn share_graph(
    f: &Fixture,
    source: &Replica,
    (target, key, credentials): (&Replica, &PrivateKey, &CredentialChain),
) {
    exchange_graphs(source, target, f.public.domain).await;
    source
        .admit_peer(key.public_key(), credentials, target.followed_tip().await)
        .await
        .unwrap();
}
/// Tells `server` which tip `client`, whose node key is `key`, follows.
async fn introduce(
    server: &Replica,
    client: &Replica,
    key: &PrivateKey,
    credentials: &CredentialChain,
) {
    server
        .admit_peer(key.public_key(), credentials, client.followed_tip().await)
        .await
        .unwrap();
}
/// One complete pass from `source` to `target`; the target acknowledges what it applied.
async fn sync(
    f: &Fixture,
    source: &Replica,
    target: (&Replica, &PrivateKey, &CredentialChain),
) -> Vec<ResourceScope> {
    share_graph(f, source, target).await;
    let (replica, key, credentials) = target;
    let mut cursor = None;
    loop {
        let page = source
            .transfer_page(
                key.public_key(),
                credentials,
                &[f.public],
                cursor,
                MAX_SECURE_FRAME,
            )
            .await
            .unwrap();
        let pruned = page.pruned;
        let ids: Vec<_> = page
            .frames
            .iter()
            .map(|frame| frame.id().unwrap())
            .collect();
        for (id, status) in ids.into_iter().zip(replica.receive_all(page.frames).await) {
            // A duplicate was acknowledged by the pass that delivered it.
            let applied = match status.unwrap() {
                ReceiveStatus::Duplicate => continue,
                status => matches!(status, ReceiveStatus::Applied | ReceiveStatus::Pruned),
            };
            source
                .acknowledge(key.public_key(), credentials, id, applied)
                .await
                .unwrap();
        }
        cursor = page.next;
        if cursor.is_none() {
            return pruned;
        }
    }
}
async fn all_rows(f: &Fixture, replica: &Replica) -> BTreeMap<Commitment, RowFields> {
    let mut rows = BTreeMap::new();
    let mut cursor = None;
    loop {
        let page = replica
            .snapshot_page(f.public, cursor, MAX_SNAPSHOT_ROWS)
            .await
            .unwrap();
        // An unfinished import never reads as complete.
        let importing = replica
            .rebootstrap_progress(f.public)
            .await
            .unwrap()
            .is_some();
        assert_eq!(page.complete, !importing);
        rows.extend(page.rows);
        cursor = page.next;
        if cursor.is_none() {
            return rows;
        }
    }
}
/// Seals what `replica` holds and compacts there; returns the base.
async fn compacted(f: &Fixture, replica: &Replica) -> SignedCheckpoint {
    seal_and_compact(replica, &f.publisher, f.public.domain).await;
    replica.checkpoint(f.public).await.unwrap()
}
async fn count(replica: &Replica, sql: &str) -> i64 {
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
        rocky_core::SqlValue::Integer(count) => count,
        _ => panic!("not a count"),
    }
}
fn policy(required: &[&PrivateKey], behind: &[&PrivateKey]) -> RetentionPolicy {
    RetentionPolicy {
        required: required
            .iter()
            .map(|key| rocky_credentials::PeerId::of(key.public_key()))
            .collect(),
        behind: behind
            .iter()
            .map(|key| rocky_credentials::PeerId::of(key.public_key()))
            .collect(),
        copies: 1,
        window: 0,
    }
}

async fn finalized_compacted<A: rocky_core::RowApplication>(
    replica: &EncryptedReplica<A>,
) -> Vec<Vec<SqlValue>> {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    rows(&inner.conn, "SELECT compacted FROM secure_finalized")
        .await
        .unwrap()
}

#[tokio::test]
async fn a_base_at_a_seal_binds_the_scope_and_survives_a_failed_compaction() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a.db");
    let node = PrivateKey::new();
    let (mut replica, _) = open(&f, &path, &node).await;
    for index in 0..40 {
        replica
            .author_buffered(handle(index), insert(&f, index, "new"), vec![])
            .await
            .unwrap();
    }
    replica
        .author_buffered(handle(1000), update(&f, 3, "new", Some("edited")), vec![])
        .await
        .unwrap();
    replica
        .author(handle(1001), update(&f, 4, "new", None), vec![])
        .await
        .unwrap();
    let expected = all_rows(&f, &replica).await;
    // No base forms anywhere but at a seal.
    assert!(matches!(
        replica.checkpoint(f.public).await,
        Err(Error::Rejected(_))
    ));
    let genesis = replica.followed_tip().await;
    seal_main(&replica, &f.publisher, f.public.domain).await;
    // The fault rolls the scope's compaction back; the file must reopen,
    // pass the audit and compact again.
    replica.inject_stage_fault(Stage::Compact, 0).await;
    assert!(matches!(
        replica.compact(f.public.domain, 0).await,
        Err(Error::InjectedFailure)
    ));
    drop(replica);
    replica = open(&f, &path, &node).await.0;
    replica.audit(f.public).await.unwrap();
    assert_eq!(all_rows(&f, &replica).await, expected);
    assert!(replica.checkpoint(f.public).await.is_err());
    // The seal is marked compacted with its last scope: still pending.
    assert_eq!(
        finalized_compacted(&replica).await,
        [vec![SqlValue::Integer(0)]]
    );
    replica.compact(f.public.domain, 0).await.unwrap();
    assert_eq!(
        finalized_compacted(&replica).await,
        [vec![SqlValue::Integer(1)]]
    );
    let signed = replica.checkpoint(f.public).await.unwrap();
    let statement = &signed.statement;
    assert_eq!(signed.signer(), node.public_key());
    assert_eq!(statement.tip, genesis);
    assert!(statement.seal.is_some());
    assert_eq!(statement.schema, 1);
    assert_eq!(statement.revocations, crate::tests::unrevoked());
    assert_eq!(statement.key_epoch().unwrap().generation, 1);
    assert_eq!((statement.sequence, statement.previous), (1, None));
    assert_eq!(statement.frontier.len(), 1);
    assert_eq!(statement.frontier[0].author, node.public_key());
    assert_eq!(statement.frontier[0].sequence, 41);
    // Stamps are hybrid time: the checkpoint's clock is its last frame's.
    assert_eq!(statement.operations, 42);
    assert_eq!(statement.clock, statement.frontier[0].clock);
    // Compaction keeps live rows only; the deleted row is dead at the seal.
    assert_eq!((statement.rows.count, statement.tombstones), (39, 0));
    assert_eq!(statement.creations.count, 39);
    assert_eq!(statement.handles.count, 42);
    // Nobody acknowledged anything: every covered operation is a sole copy.
    assert_eq!(statement.custody.superseded, 0);
    assert_eq!(statement.custody.sole.count, 42);
    let report = replica.audit(f.public).await.unwrap();
    assert_eq!(report.checkpoint, Some(signed.id().unwrap()));
    assert_eq!((report.rows, report.replayed), (39, 0));
    // Nothing new: the same base. One more operation replays over it, and
    // the next seal's base follows it in the chain.
    replica.compact(f.public.domain, 0).await.unwrap();
    assert_eq!(
        replica.checkpoint(f.public).await.unwrap().id().unwrap(),
        signed.id().unwrap()
    );
    replica
        .author(handle(1002), insert(&f, 400, "later"), vec![])
        .await
        .unwrap();
    assert_eq!(replica.audit(f.public).await.unwrap().replayed, 1);
    seal_and_compact(&replica, &f.publisher, f.public.domain).await;
    let next = replica.checkpoint(f.public).await.unwrap();
    assert_eq!(next.statement.sequence, 2);
    assert_eq!(next.statement.previous, Some(signed.id().unwrap()));
    assert_eq!(next.statement.rows.count, 40);
    drop(replica);
    let replica = open(&f, &path, &node).await.0;
    assert_eq!(replica.audit(f.public).await.unwrap().replayed, 0);
    assert_eq!(all_rows(&f, &replica).await.len(), 40);
    // The deleted row was dead at the seal: compaction released it.
    assert_eq!(
        replica.companion(f.public, id(4)).await.unwrap(),
        Companion::Unavailable
    );
}

/// Imports `source`'s no-frames base of the keyless private scope into
/// `target`: signed, canonical, no pages, no key installed.
async fn import_no_frames(
    f: &Fixture,
    source: &Replica,
    (target, key, credentials): (&Replica, &PrivateKey, &CredentialChain),
) -> SignedCheckpoint {
    source
        .admit_peer(key.public_key(), credentials, target.followed_tip().await)
        .await
        .unwrap();
    let offered = source
        .checkpoint_offer(key.public_key(), credentials, f.private)
        .await
        .unwrap()
        .expect("a no-frames base");
    assert!(offered.statement.no_frames());
    assert_eq!(offered.statement.key_epoch(), None);
    crate::tests::assert_signed_empty(&offered);
    target.begin_rebootstrap(offered.clone()).await.unwrap();
    let (_, cursor, complete) = target
        .rebootstrap_progress(f.private)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((cursor, complete), (None, true));
    let report = target.finish_rebootstrap(f.private).await.unwrap();
    assert_eq!(report.checkpoint, offered.id().unwrap());
    assert_eq!(report.superseded, 0);
    assert!(target.key_epochs(f.private).await.is_empty());
    offered
}

/// The public scope's base row: the first scope state of these fixtures.
const PUBLIC_BASE: &str = "scope=(SELECT MIN(id) FROM secure_scope_state)";

#[tokio::test]
async fn pruning_needs_a_verified_checkpoint_acknowledgments_and_custody() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a.db");
    let (a_key, b_key) = (PrivateKey::new(), PrivateKey::new());
    let (mut a, _) = open(&f, &path, &a_key).await;
    let (b, b_credentials) = open(&f, &dir.path().join("b.db"), &b_key).await;
    for index in 0..20 {
        a.author_buffered(handle(index), insert(&f, index, "new"), vec![])
            .await
            .unwrap();
    }
    let blocked = |block| PruneReport {
        pruned: 0,
        blocked: Some(block),
    };
    assert_eq!(
        a.prune(f.public).await.unwrap(),
        blocked(PruneBlock::NoCheckpoint)
    );
    compacted(&f, &a).await;
    // The base is flushed before any operation it covers may go.
    let (commit, durable, _) = a.watermark().await;
    assert_eq!(commit, durable);
    assert_eq!(
        a.prune(f.public).await.unwrap(),
        blocked(PruneBlock::NoPolicy)
    );
    // Missing custody evidence: nobody holds another copy.
    a.set_retention_policy(f.public, policy(&[], &[]))
        .await
        .unwrap();
    assert!(matches!(
        a.prune(f.public).await.unwrap(),
        PruneReport {
            pruned: 0,
            blocked: Some(PruneBlock::SoleCopy { .. })
        }
    ));
    a.set_retention_policy(f.public, policy(&[&b_key], &[]))
        .await
        .unwrap();
    assert!(matches!(
        a.prune(f.public).await.unwrap().blocked,
        Some(PruneBlock::Unacknowledged { peer, .. }) if peer == rocky_credentials::PeerId::of(b_key.public_key())
    ));
    assert!(sync(&f, &a, (&b, &b_key, &b_credentials)).await.is_empty());
    // A checkpoint that no longer verifies blocks pruning.
    let signed = {
        let inner = a.inner.lock(crate::replica::Class::Background).await;
        // The public base; the keyless private scope has its own.
        let stored = rows(
            &inner.conn,
            &format!("SELECT signed FROM secure_checkpoints WHERE {PUBLIC_BASE}"),
        )
        .await
        .unwrap();
        let rocky_core::SqlValue::Blob(signed) = stored[0][0].clone() else {
            panic!("missing checkpoint");
        };
        let mut tampered = SignedCheckpoint::from_bytes(&signed).unwrap();
        tampered.statement.operations += 1;
        inner
            .conn
            .execute(
                format!("UPDATE secure_checkpoints SET signed=?1 WHERE {PUBLIC_BASE}"),
                [tampered.to_bytes().unwrap()],
            )
            .await
            .unwrap();
        signed
    };
    assert!(matches!(a.prune(f.public).await, Err(Error::Corrupt(_))));
    assert!(matches!(a.audit(f.public).await, Err(Error::Corrupt(_))));
    assert_eq!(
        count(&a, "SELECT COUNT(*) FROM secure_operations").await,
        20
    );
    a.inner
        .lock(crate::replica::Class::Background)
        .await
        .conn
        .execute(
            format!("UPDATE secure_checkpoints SET signed=?1 WHERE {PUBLIC_BASE}"),
            [signed],
        )
        .await
        .unwrap();
    // A failure in the second batch keeps the first one pruned and the file whole.
    let measurements = a.lock_measurements();
    measurements.start();
    a.inject_stage_fault(Stage::Prune, 1).await;
    assert!(matches!(
        a.prune(f.public).await,
        Err(Error::InjectedFailure)
    ));
    let measured = measurements.stop();
    let candidates: Vec<_> = measured
        .holders
        .values()
        .flat_map(|holder| {
            holder
                .units
                .get("prune_candidate")
                .into_iter()
                .flatten()
                .map(|(count, _)| *count)
        })
        .collect();
    assert_eq!(candidates, [8, 8]);
    drop(a);
    a = open(&f, &path, &a_key).await.0;
    assert_eq!(
        count(&a, "SELECT COUNT(*) FROM secure_operations").await,
        12
    );
    a.audit(f.public).await.unwrap();
    assert_eq!(
        a.prune(f.public).await.unwrap(),
        PruneReport {
            pruned: 12,
            blocked: None
        }
    );
    assert_eq!(
        a.prune(f.public).await.unwrap(),
        PruneReport {
            pruned: 0,
            blocked: None
        }
    );
    for table in [
        "secure_operations",
        "secure_outbox",
        "secure_ack",
        "secure_applied",
    ] {
        assert_eq!(count(&a, &format!("SELECT COUNT(*) FROM {table}")).await, 0);
    }
    let status = a.checkpoint_status(f.public).await.unwrap();
    assert_eq!(status.pruned_prefix, vec![(a_key.public_key(), 19)]);
    assert_eq!(
        (status.covered, status.uncovered, status.retained_bytes),
        (0, 0, 0)
    );
    // The pruned file reopens, audits, keeps its rows and continues its log.
    drop(a);
    a = open(&f, &path, &a_key).await.0;
    assert_eq!(a.audit(f.public).await.unwrap().operations, 0);
    assert_eq!(all_rows(&f, &a).await.len(), 20);
    let frame = a
        .author(handle(500), update(&f, 7, "new", Some("after")), vec![])
        .await
        .unwrap();
    assert_eq!(frame.operation().unwrap().header.seq_num, 20);
    let late = frame.id().unwrap();
    assert_eq!(b.receive(frame).await.unwrap(), ReceiveStatus::Applied);
    a.acknowledge(b_key.public_key(), &b_credentials, late, true)
        .await
        .unwrap();
    assert_eq!(all_rows(&f, &a).await, all_rows(&f, &b).await);
    a.rebuild_projection(f.public).await.unwrap();
    assert_eq!(all_rows(&f, &a).await, all_rows(&f, &b).await);
    a.audit(f.public).await.unwrap();
    // The retained window keeps the newest covered operations.
    let mut windowed = policy(&[], &[]);
    windowed.window = 1;
    a.set_retention_policy(f.public, windowed).await.unwrap();
    a.author(handle(501), update(&f, 8, "new", Some("after")), vec![])
        .await
        .unwrap();
    sync(&f, &a, (&b, &b_key, &b_credentials)).await;
    seal_main(&a, &f.publisher, f.public.domain).await;
    assert_eq!(a.compact(f.public.domain, 0).await.unwrap().pruned, 1);
    assert_eq!(count(&a, "SELECT COUNT(*) FROM secure_operations").await, 1);
    a.audit(f.public).await.unwrap();
}

#[tokio::test]
async fn late_frames_and_retried_handles_from_before_the_pruned_prefix_do_nothing() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let (a_key, b_key) = (PrivateKey::new(), PrivateKey::new());
    let (a, a_credentials) = open(&f, &dir.path().join("a.db"), &a_key).await;
    let (b, b_credentials) = open(&f, &dir.path().join("b.db"), &b_key).await;
    let created = a
        .author(handle(1), insert(&f, 1, "alive"), vec![])
        .await
        .unwrap();
    a.author(handle(2), insert(&f, 2, "kept"), vec![])
        .await
        .unwrap();
    sync(&f, &a, (&b, &b_key, &b_credentials)).await;
    // B edits the row while A deletes it; B's edit reaches A only after the prune.
    let concurrent = b
        .author(handle(3), update(&f, 1, "alive", Some("edited")), vec![])
        .await
        .unwrap();
    let deleted = a
        .author(handle(4), update(&f, 1, "alive", None), vec![])
        .await
        .unwrap();
    sync(&f, &a, (&b, &b_key, &b_credentials)).await;
    compacted(&f, &a).await;
    a.set_retention_policy(f.public, policy(&[&b_key], &[]))
        .await
        .unwrap();
    assert_eq!(a.prune(f.public).await.unwrap().pruned, 3);
    let before = a.snapshot(f.public).await.unwrap().rows;
    // The original creation and deletion frames come back late.
    for frame in [&created, &deleted] {
        assert_eq!(
            a.receive(frame.clone()).await.unwrap(),
            ReceiveStatus::Pruned
        );
    }
    // An edit that predates the deletion names a creation compaction
    // released with the dead row: it waits, and changes nothing.
    assert_eq!(
        a.receive(concurrent).await.unwrap(),
        ReceiveStatus::PendingDependencies
    );
    assert_eq!(a.snapshot(f.public).await.unwrap().rows, before);
    assert_eq!(count(&a, "SELECT COUNT(*) FROM secure_operations").await, 1);
    // A retried handle from before the pruned_prefix never authors again.
    let operations = count(&a, "SELECT COUNT(*) FROM secure_handles").await;
    assert!(matches!(
        a.author(handle(1), insert(&f, 1, "alive"), vec![]).await,
        Err(Error::Rejected(message)) if message.contains("before the pruned prefix")
    ));
    assert_eq!(
        a.author_buffered(handle(1), insert(&f, 1, "alive"), vec![])
            .await
            .unwrap()
            .value,
        created.id().unwrap()
    );
    assert_eq!(
        a.lookup_mutation(handle(1)).await.unwrap(),
        Some(created.id().unwrap())
    );
    assert!(matches!(
        a.author_buffered(handle(1), insert(&f, 1, "other"), vec![])
            .await,
        Err(Error::Conflict)
    ));
    assert_eq!(
        count(&a, "SELECT COUNT(*) FROM secure_handles").await,
        operations
    );
    assert_eq!(count(&a, "SELECT COUNT(*) FROM secure_operations").await, 1);
    assert_eq!(a.snapshot(f.public).await.unwrap().rows, before);
    // An acknowledgment for a pruned operation is accepted and records nothing.
    a.acknowledge(
        b_key.public_key(),
        &b_credentials,
        created.id().unwrap(),
        true,
    )
    .await
    .unwrap();
    // B converges with the pruned replica.
    sync(&f, &b, (&a, &a_key, &a_credentials)).await;
    assert_eq!(all_rows(&f, &a).await, all_rows(&f, &b).await);
    a.audit(f.public).await.unwrap();
}

/// Serves `source` until the client closes the session.
#[tokio::test]
async fn handles_beyond_the_window_are_forgotten_once_pruned() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let (a_key, b_key) = (PrivateKey::new(), PrivateKey::new());
    let (a, _) = open(&f, &dir.path().join("a.db"), &a_key).await;
    let (b, b_credentials) = open(&f, &dir.path().join("b.db"), &b_key).await;
    a.set_retention_limits(RetentionLimits {
        handles: 1,
        ..RetentionLimits::default()
    })
    .await
    .unwrap();
    a.author(handle(1), insert(&f, 1, "first"), vec![])
        .await
        .unwrap();
    a.author(handle(2), insert(&f, 2, "second"), vec![])
        .await
        .unwrap();
    // Both handles stay while their operations are retained.
    a.author(handle(3), insert(&f, 3, "third"), vec![])
        .await
        .unwrap();
    assert_eq!(count(&a, "SELECT COUNT(*) FROM secure_handles").await, 3);
    sync(&f, &a, (&b, &b_key, &b_credentials)).await;
    compacted(&f, &a).await;
    a.set_retention_policy(f.public, policy(&[&b_key], &[]))
        .await
        .unwrap();
    assert_eq!(a.prune(f.public).await.unwrap().pruned, 3);
    // Only the newest handle survives; the audit checks the handle digest.
    assert_eq!(count(&a, "SELECT COUNT(*) FROM secure_handles").await, 1);
    a.audit(f.public).await.unwrap();
    assert_eq!(a.lookup_mutation(handle(1)).await.unwrap(), None);
    assert!(matches!(
        a.author(handle(3), insert(&f, 3, "third"), vec![]).await,
        Err(Error::Rejected(message)) if message.contains("before the pruned prefix")
    ));
    // A forgotten handle authors again.
    a.author(handle(1), insert(&f, 4, "fourth"), vec![])
        .await
        .unwrap();
    assert_eq!(count(&a, "SELECT COUNT(*) FROM secure_operations").await, 1);
}

async fn serve(mut session: NativeSession, source: &Replica) {
    while session.serve_once(source).await.is_ok() {}
}

#[tokio::test]
async fn offline_replica_learns_it_is_behind_and_rebootstraps_with_its_local_edits() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new(), PrivateKey::new()];
    let (a, a_credentials) = open(&f, &dir.path().join("a.db"), &keys[0]).await;
    let (b, b_credentials) = open(&f, &dir.path().join("b.db"), &keys[1]).await;
    let c_path = dir.path().join("c.db");
    let (mut c, c_credentials) = open(&f, &c_path, &keys[2]).await;
    for index in 0..5 {
        a.author_buffered(handle(index), insert(&f, index, "base"), vec![])
            .await
            .unwrap();
    }
    sync(&f, &a, (&b, &keys[1], &b_credentials)).await;
    sync(&f, &a, (&c, &keys[2], &c_credentials)).await;
    // C is offline from here. A moves on, checkpoints and prunes.
    for index in 5..45 {
        a.author_buffered(handle(index), insert(&f, index, "base"), vec![])
            .await
            .unwrap();
    }
    a.author_buffered(handle(101), insert(&f, 300, "from a"), vec![])
        .await
        .unwrap();
    sync(&f, &a, (&b, &keys[1], &b_credentials)).await;
    let signed = compacted(&f, &a).await;
    a.set_retention_policy(f.public, policy(&[&keys[1]], &[&keys[2]]))
        .await
        .unwrap();
    assert_eq!(a.prune(f.public).await.unwrap().pruned, 46);
    a.author(handle(102), update(&f, 0, "base", Some("after")), vec![])
        .await
        .unwrap();
    // Deleted after the seal, so its tombstone is still held.
    a.author(handle(100), update(&f, 2, "base", None), vec![])
        .await
        .unwrap();
    // C's unsent edits: an update, a new row, an edit of a row A deleted, and
    // an insert that collides with a row A created meanwhile.
    let kept: Vec<_> = [
        (handle(200), update(&f, 3, "base", Some("local"))),
        (handle(201), insert(&f, 301, "from c")),
        (handle(202), update(&f, 2, "base", Some("lost"))),
    ]
    .into_iter()
    .collect();
    let mut local = Vec::new();
    for (handle, changes) in kept {
        local.push(
            c.author(handle, changes, vec![])
                .await
                .unwrap()
                .id()
                .unwrap(),
        );
    }
    let collision = c
        .author(handle(203), insert(&f, 300, "from c"), vec![])
        .await
        .unwrap()
        .id()
        .unwrap();
    // B was online and acknowledged everything: it is not behind and converges.
    share_graph(&f, &a, (&b, &keys[1], &b_credentials)).await;
    let pruned_prefix = a
        .pruned_page(keys[1].public_key(), &b_credentials, f.public, None)
        .await
        .unwrap();
    assert_eq!(pruned_prefix.logs, vec![(keys[0].public_key(), 45)]);
    assert!(!b.behind_pruned(&pruned_prefix).await.unwrap());
    assert_eq!(
        sync(&f, &a, (&b, &keys[1], &b_credentials)).await,
        vec![f.public]
    );
    assert_eq!(all_rows(&f, &a).await, all_rows(&f, &b).await);
    assert!(c.behind_pruned(&pruned_prefix).await.unwrap());
    // Over the link C is told so, and no frame is received into a gap.
    let quota = 8192;
    let before = all_rows(&f, &c).await;
    for fault in [Some((Stage::Import, 1)), Some((Stage::Switch, 0)), None] {
        let (near, far) = network::link::testing::tcp().await;
        let (session, served) = network::link::testing::sessions_over(
            near,
            far,
            (&c, keys[2].clone(), c_credentials.clone()),
            (&a, keys[0].clone(), a_credentials.clone()),
        )
        .await
        .unwrap();
        let client = async {
            let mut session = session;
            // C learns the seal and follows `main` on, then says so.
            session.sync_tip_graph(&c).await.unwrap();
            if c.followed_bookmark().await.is_none() {
                c.follow_bookmark(f.public.domain, "main").await.unwrap();
            }
            session.sync_tip_graph(&c).await.unwrap();
            let pulled = session
                .catch_up(&c, f.public, MAX_SECURE_FRAME / 2)
                .await
                .unwrap();
            assert!(pulled.behind);
            assert_eq!(all_rows(&f, &c).await, before);
            if let Some((stage, skip)) = fault {
                c.inject_stage_fault(stage, skip).await;
            }
            session.rebootstrap(&c, f.public, quota).await
        };
        let (report, ()) = tokio::join!(client, serve(served, &a));
        let Some(_) = fault else {
            let report = report.unwrap();
            assert_eq!(report.checkpoint, signed.id().unwrap());
            assert_eq!(report.superseded, 5);
            assert_eq!(report.reapplied, local);
            assert_eq!(report.pending, vec![]);
            assert_eq!(report.rejected.len(), 1);
            assert_eq!(report.rejected[0].0, collision);
            // A created the row before the seal C's insert comes late to.
            assert!(report.rejected[0].1.contains("behind the finalized seal"));
            break;
        };
        // A failed import leaves the old state; the file reopens and audits.
        assert!(matches!(report, Err(Error::InjectedFailure)));
        drop(c);
        c = open(&f, &c_path, &keys[2]).await.0;
        c.audit(f.public).await.unwrap();
        assert_eq!(all_rows(&f, &c).await, before);
        assert!(c.rebootstrap_progress(f.public).await.unwrap().is_some());
    }
    assert_eq!(c.rebootstrap_progress(f.public).await.unwrap(), None);
    c.audit(f.public).await.unwrap();
    import_no_frames(&f, &a, (&c, &keys[2], &c_credentials)).await;
    // C now syncs the frames after the checkpoint and A receives C's edits.
    assert!(!c.behind_pruned(&pruned_prefix).await.unwrap());
    sync(&f, &a, (&c, &keys[2], &c_credentials)).await;
    sync(&f, &c, (&a, &keys[0], &a_credentials)).await;
    let rows = all_rows(&f, &a).await;
    assert_eq!(rows, all_rows(&f, &c).await);
    assert_eq!(rows.len(), 46);
    assert_eq!(rows[&id(0)], f.app().name("after"));
    assert_eq!(rows[&id(3)], f.app().name("local"));
    assert_eq!(rows[&id(301)], f.app().name("from c"));
    assert_eq!(rows[&id(300)], f.app().name("from a"));
    assert!(!rows.contains_key(&id(2)));
    // C's handles survive: none of its local edits can be authored twice.
    assert_eq!(
        c.author_buffered(handle(200), update(&f, 3, "base", Some("local")), vec![])
            .await
            .unwrap()
            .value,
        local[0]
    );
    assert_eq!(
        c.lookup_mutation(handle(203)).await.unwrap(),
        Some(collision)
    );
    drop(c);
    let c = open(&f, &c_path, &keys[2]).await.0;
    c.audit(f.public).await.unwrap();
    a.audit(f.public).await.unwrap();
    assert_eq!(all_rows(&f, &c).await, rows);
    // C checkpoints on top of the imported one and can prune in turn.
    let next = compacted(&f, &c).await;
    assert_eq!(next.statement.sequence, 2);
    assert_eq!(next.statement.previous, Some(signed.id().unwrap()));
    assert_eq!(next.signer(), keys[2].public_key());
}

#[tokio::test]
async fn an_imported_base_is_served_onward_but_never_back_to_its_signer() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let (a_key, b_key) = (PrivateKey::new(), PrivateKey::new());
    let (a, a_credentials) = open(&f, &dir.path().join("a.db"), &a_key).await;
    let (b, b_credentials) = open(&f, &dir.path().join("b.db"), &b_key).await;
    a.author(handle(1), insert(&f, 1, "retained"), vec![])
        .await
        .unwrap();
    let original = compacted(&f, &a).await;
    share_graph(&f, &a, (&b, &b_key, &b_credentials)).await;
    b.begin_rebootstrap(original.clone()).await.unwrap();
    let page = a
        .checkpoint_page(
            b_key.public_key(),
            &b_credentials,
            f.public,
            original.id().unwrap(),
            None,
            MAX_SECURE_FRAME,
        )
        .await
        .unwrap();
    assert!(page.next.is_none());
    b.stage_checkpoint_page(page).await.unwrap();
    b.finish_rebootstrap(f.public).await.unwrap();
    introduce(&b, &a, &a_key, &a_credentials).await;
    // A base is signed where it forms, at a seal: its signer is not offered
    // its own signature back.
    assert!(
        b.checkpoint_offer(a_key.public_key(), &a_credentials, f.public)
            .await
            .unwrap()
            .is_none()
    );
    let c_key = PrivateKey::new();
    let reader_grants = f
        .full()
        .into_iter()
        .map(|mut grant| {
            grant
                .rights
                .retain(|right| matches!(right, Right::Read | Right::Custody));
            grant
        })
        .collect();
    let config = f.config(&c_key, reader_grants, &[f.public]);
    let c_credentials = config.credentials.clone();
    let c = EncryptedReplica::open(dir.path().join("c.db"), f.app(), config)
        .await
        .unwrap();
    share_graph(&f, &a, (&c, &c_key, &c_credentials)).await;
    c.begin_rebootstrap(original.clone()).await.unwrap();
    let page = a
        .checkpoint_page(
            c_key.public_key(),
            &c_credentials,
            f.public,
            original.id().unwrap(),
            None,
            MAX_SECURE_FRAME,
        )
        .await
        .unwrap();
    c.stage_checkpoint_page(page).await.unwrap();
    c.finish_rebootstrap(f.public).await.unwrap();
    introduce(&c, &a, &a_key, &a_credentials).await;
    share_graph(&f, &b, (&c, &b_key, &b_credentials)).await;
    introduce(&c, &b, &b_key, &b_credentials).await;
    // Holders serve it onward, a read-only one too, unchanged.
    assert!(
        c.checkpoint_offer(a_key.public_key(), &a_credentials, f.public)
            .await
            .unwrap()
            .is_none()
    );
    let forwarded = c
        .checkpoint_offer(b_key.public_key(), &b_credentials, f.public)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(forwarded.id().unwrap(), original.id().unwrap());
    assert!(a.begin_rebootstrap(original).await.is_err());
}

#[tokio::test]
async fn rebootstrap_refuses_unverifiable_checkpoints() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let (a_key, c_key) = (PrivateKey::new(), PrivateKey::new());
    let (a, _) = open(&f, &dir.path().join("a.db"), &a_key).await;
    let (c, c_credentials) = open(&f, &dir.path().join("c.db"), &c_key).await;
    for index in 0..40 {
        a.author_buffered(handle(index), insert(&f, index, "base"), vec![])
            .await
            .unwrap();
    }
    c.author(handle(50), insert(&f, 50, "mine"), vec![])
        .await
        .unwrap();
    let signed = compacted(&f, &a).await;
    share_graph(&f, &a, (&c, &c_key, &c_credentials)).await;
    let before = all_rows(&f, &c).await;
    // A statement that was changed after signing.
    let mut forged = signed.clone();
    forged.statement.rows.count += 1;
    assert!(c.begin_rebootstrap(forged).await.is_err());
    // Its own checkpoint, and a page that belongs to no import.
    assert!(a.begin_rebootstrap(signed.clone()).await.is_err());
    let checkpoint = signed.id().unwrap();
    let page = a
        .checkpoint_page(
            c_key.public_key(),
            &c_credentials,
            f.public,
            checkpoint,
            None,
            4096,
        )
        .await
        .unwrap();
    assert!(page.next.is_some());
    assert!(c.stage_checkpoint_page(page.clone()).await.is_err());
    c.begin_rebootstrap(signed.clone()).await.unwrap();
    assert!(c.finish_rebootstrap(f.public).await.is_err());
    // A page out of order, then a row set that stops early.
    let mut skipped = page.clone();
    skipped.after = page.next;
    assert!(c.stage_checkpoint_page(skipped).await.is_err());
    let mut truncated = page.clone();
    truncated.next = None;
    assert!(c.stage_checkpoint_page(truncated).await.is_err());
    c.stage_checkpoint_page(page).await.unwrap();
    assert!(c.finish_rebootstrap(f.public).await.is_err());
    assert_eq!(all_rows(&f, &c).await, before);
    c.audit(f.public).await.unwrap();
    // A superseded checkpoint is not served any more.
    a.author(handle(60), insert(&f, 60, "newer"), vec![])
        .await
        .unwrap();
    compacted(&f, &a).await;
    assert!(
        a.checkpoint_page(
            c_key.public_key(),
            &c_credentials,
            f.public,
            checkpoint,
            None,
            4096
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn compaction_at_seals_keeps_retained_bytes_bounded_then_backpressure() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let (a_key, b_key) = (PrivateKey::new(), PrivateKey::new());
    let (a, _) = open(&f, &dir.path().join("a.db"), &a_key).await;
    let (b, b_credentials) = open(&f, &dir.path().join("b.db"), &b_key).await;
    let frame = a
        .author(handle(0), insert(&f, 0, "first"), vec![])
        .await
        .unwrap();
    let size = frame.operation().unwrap().header.to_bytes().len() + frame.body_bytes().len();
    a.set_retention_limits(RetentionLimits {
        hard_bytes: 40 * size,
        ..RetentionLimits::default()
    })
    .await
    .unwrap();
    a.set_retention_policy(f.public, policy(&[&b_key], &[]))
        .await
        .unwrap();
    // With an acknowledging peer, compacting at a seal now and then keeps
    // history inside the bound.
    let mut peak = 0;
    crate::tests::check_frontier_cache(&a, f.public).await;
    for index in 1..80 {
        a.author_buffered(handle(index), insert(&f, index, "row"), vec![])
            .await
            .unwrap();
        if index % 10 == 0 {
            sync(&f, &a, (&b, &b_key, &b_credentials)).await;
            seal_and_compact(&a, &f.publisher, f.public.domain).await;
        }
        peak = peak.max(a.checkpoint_status(f.public).await.unwrap().retained_bytes);
    }
    let status = a.checkpoint_status(f.public).await.unwrap();
    assert_eq!(status.maintenance_error, None);
    assert!(peak <= 40 * size as u64, "{peak}");
    assert!(status.checkpoint.unwrap().statement.operations > 60);
    assert!(!status.pruned_prefix.is_empty());
    crate::tests::check_frontier_cache(&a, f.public).await;
    assert!(count(&a, "SELECT COUNT(*) FROM secure_operations").await < 40);
    a.audit(f.public).await.unwrap();
    // Without acknowledgments nothing may be pruned: the hard bound answers
    // with a retryable error instead of losing anything.
    let mut refused = None;
    for index in 80..200 {
        if let Err(error) = a
            .author_buffered(handle(index), insert(&f, index, "row"), vec![])
            .await
        {
            refused = Some((index, error));
            break;
        }
    }
    let (index, error) = refused.expect("backpressure");
    assert!(matches!(error, Error::Backpressure) && error.is_retryable());
    assert_eq!(a.lookup_mutation(handle(index)).await.unwrap(), None);
    crate::tests::check_frontier_cache(&a, f.public).await;
    assert!(a.checkpoint_status(f.public).await.unwrap().retained_bytes <= 40 * size as u64);
    // Acknowledgments release it; the same handle then commits once.
    sync(&f, &a, (&b, &b_key, &b_credentials)).await;
    seal_main(&a, &f.publisher, f.public.domain).await;
    assert!(a.compact(f.public.domain, 0).await.unwrap().pruned > 0);
    a.author(handle(index), insert(&f, index, "row"), vec![])
        .await
        .unwrap();
    sync(&f, &a, (&b, &b_key, &b_credentials)).await;
    assert_eq!(all_rows(&f, &a).await, all_rows(&f, &b).await);
    assert_eq!(all_rows(&f, &a).await.len(), index as usize + 1);
    a.audit(f.public).await.unwrap();
    b.audit(f.public).await.unwrap();
}

#[tokio::test]
async fn late_copy_of_a_pruned_dependency_releases_a_waiting_frame() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let (a_key, b_key) = (PrivateKey::new(), PrivateKey::new());
    let (a, a_credentials) = open(&f, &dir.path().join("a.db"), &a_key).await;
    let (b, b_credentials) = open(&f, &dir.path().join("b.db"), &b_key).await;
    a.author(handle(1), insert(&f, 1, "one"), vec![])
        .await
        .unwrap();
    let named = a
        .author(handle(2), update(&f, 1, "one", Some("two")), vec![])
        .await
        .unwrap();
    a.author(handle(3), insert(&f, 2, "tip"), vec![])
        .await
        .unwrap();
    sync(&f, &a, (&b, &b_key, &b_credentials)).await;
    // B, which keeps its history, names an ordinary old operation explicitly.
    let dependent = b
        .author(
            handle(4),
            insert(&f, 3, "depends"),
            vec![named.id().unwrap()],
        )
        .await
        .unwrap();
    compacted(&f, &a).await;
    a.set_retention_policy(f.public, policy(&[&b_key], &[]))
        .await
        .unwrap();
    assert_eq!(a.prune(f.public).await.unwrap().pruned, 3);
    // A cannot tell a pruned dependency from a missing one: the frame waits.
    assert_eq!(
        a.receive(dependent).await.unwrap(),
        ReceiveStatus::PendingDependencies
    );
    assert_eq!(a.checkpoint_status(f.public).await.unwrap().pending, 1);
    // A pass from the peer that still holds it settles the frame.
    sync(&f, &b, (&a, &a_key, &a_credentials)).await;
    assert_eq!(a.checkpoint_status(f.public).await.unwrap().pending, 0);
    assert_eq!(all_rows(&f, &a).await, all_rows(&f, &b).await);
    a.audit(f.public).await.unwrap();
}

const CRASH_STEPS: [&str; 4] = ["compact", "prune", "import", "switch"];
/// Fixed keys, so that the parent reopens what the child wrote.
fn crash_keys() -> (Fixture, [PrivateKey; 3]) {
    (
        Fixture::with_publisher(PrivateKey::from_bytes(&[41; 32])),
        [42, 43, 44].map(|byte| PrivateKey::from_bytes(&[byte; 32])),
    )
}
/// Imports `source`'s checkpoint into `target`, resuming a staged import as
/// the native session does.
async fn crash_rebootstrap(
    f: &Fixture,
    source: &Replica,
    target: (&Replica, &PrivateKey, &CredentialChain),
) -> Result<RebootstrapReport, Error> {
    share_graph(f, source, target).await;
    let (replica, key, credentials) = target;
    let signed = source.checkpoint(f.public).await?;
    let checkpoint = signed.id()?;
    let (mut after, mut complete) = match replica.rebootstrap_progress(f.public).await? {
        Some((staged, cursor, complete)) if staged == checkpoint => (cursor, complete),
        _ => {
            replica.begin_rebootstrap(signed).await?;
            (None, false)
        }
    };
    while !complete {
        let page = source
            .checkpoint_page(
                key.public_key(),
                credentials,
                f.public,
                checkpoint,
                after,
                4096,
            )
            .await?;
        (after, complete) = (page.next, page.next.is_none());
        replica.stage_checkpoint_page(page).await?;
    }
    replica.finish_rebootstrap(f.public).await
}

#[tokio::test]
#[ignore = "invoked by process_exit_inside_any_checkpoint_step_leaves_a_file_that_opens_and_audits"]
async fn checkpoint_crash_child() {
    let dir = std::env::var("ROCKY_CHECKPOINT_CRASH_DIR").unwrap();
    let step = std::env::var("ROCKY_CHECKPOINT_CRASH_STEP").unwrap();
    let dir = Path::new(&dir);
    let (f, keys) = crash_keys();
    let (a, _) = open(&f, &dir.join("a.db"), &keys[0]).await;
    let (b, b_credentials) = open(&f, &dir.join("b.db"), &keys[1]).await;
    let (c, c_credentials) = open(&f, &dir.join("c.db"), &keys[2]).await;
    for index in 0..40 {
        a.author_buffered(handle(index), insert(&f, index, "base"), vec![])
            .await
            .unwrap();
    }
    a.author(handle(100), update(&f, 3, "base", Some("edited")), vec![])
        .await
        .unwrap();
    sync(&f, &a, (&b, &keys[1], &b_credentials)).await;
    a.set_retention_policy(f.public, policy(&[&keys[1]], &[&keys[2]]))
        .await
        .unwrap();
    c.author(handle(900), insert(&f, 900, "unsent"), vec![])
        .await
        .unwrap();
    let target = (&c, &keys[2], &c_credentials);
    match step.as_str() {
        "compact" => {
            seal_main(&a, &f.publisher, f.public.domain).await;
            a.inject_stage_exit(Stage::Compact, 0).await;
            let _ = a.compact(f.public.domain, 0).await;
        }
        "prune" => {
            seal_main(&a, &f.publisher, f.public.domain).await;
            a.inject_stage_exit(Stage::Prune, 1).await;
            let _ = a.compact(f.public.domain, 0).await;
        }
        "import" | "switch" => {
            compacted(&f, &a).await;
            if step == "import" {
                c.inject_stage_exit(Stage::Import, 1).await;
            } else {
                c.inject_stage_exit(Stage::Switch, 0).await;
            }
            let _ = crash_rebootstrap(&f, &a, target).await;
        }
        other => panic!("unknown crash step {other}"),
    }
    // The fault exits the process; reaching this line is a failure.
    std::process::exit(1);
}

/// Process exit inside each step of checkpoint creation, pruning and
/// rebootstrap: the step's transaction is gone, every file opens and passes
/// the audit, and the work completes afterwards.
#[tokio::test]
async fn process_exit_inside_any_checkpoint_step_leaves_a_file_that_opens_and_audits() {
    for step in CRASH_STEPS {
        let dir = TempDir::new().unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::checkpoint::checkpoint_crash_child",
                "--ignored",
            ])
            .env("ROCKY_CHECKPOINT_CRASH_DIR", dir.path())
            .env("ROCKY_CHECKPOINT_CRASH_STEP", step)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(77), "{step}");
        let (f, keys) = crash_keys();
        let (a, a_credentials) = open(&f, &dir.path().join("a.db"), &keys[0]).await;
        let (c, c_credentials) = open(&f, &dir.path().join("c.db"), &keys[2]).await;
        for replica in [&a, &c] {
            replica.audit(f.public).await.unwrap();
        }
        let rows = all_rows(&f, &a).await;
        assert_eq!(rows.len(), 40, "{step}");
        assert_eq!(rows[&id(3)], f.app().name("edited"), "{step}");
        assert_eq!(all_rows(&f, &c).await.len(), 1, "{step}");
        assert_eq!(
            c.rebootstrap_progress(f.public).await.unwrap().is_some(),
            matches!(step, "import" | "switch"),
            "{step}"
        );
        // The interrupted work completes from what was committed.
        compacted(&f, &a).await;
        assert_eq!(a.prune(f.public).await.unwrap().blocked, None, "{step}");
        assert_eq!(
            count(&a, "SELECT COUNT(*) FROM secure_operations").await,
            0,
            "{step}"
        );
        let report = crash_rebootstrap(&f, &a, (&c, &keys[2], &c_credentials))
            .await
            .unwrap();
        assert_eq!(report.reapplied.len(), 1, "{step}");
        assert!(report.rejected.is_empty(), "{step}");
        import_no_frames(&f, &a, (&c, &keys[2], &c_credentials)).await;
        sync(&f, &c, (&a, &keys[0], &a_credentials)).await;
        let rows = all_rows(&f, &a).await;
        assert_eq!(rows.len(), 41, "{step}");
        assert_eq!(rows, all_rows(&f, &c).await, "{step}");
        for replica in [&a, &c] {
            replica.audit(f.public).await.unwrap();
        }
    }
}

#[tokio::test]
async fn bootstrap_refuses_a_valid_checkpoint_signed_by_a_read_only_device() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let writer_key = PrivateKey::new();
    let reader_key = PrivateKey::new();
    let target_key = PrivateKey::new();
    let (writer, _) = open(&f, &dir.path().join("writer.db"), &writer_key).await;
    writer
        .author(handle(1), insert(&f, 1, "base"), vec![])
        .await
        .unwrap();
    let reader_config = f.config(
        &reader_key,
        vec![grant(f.public, &[Right::Read, Right::Custody], &[])],
        &[f.public],
    );
    let reader_credentials = reader_config.credentials.clone();
    let reader = EncryptedReplica::open(dir.path().join("reader.db"), f.app(), reader_config)
        .await
        .unwrap();
    sync(&f, &writer, (&reader, &reader_key, &reader_credentials)).await;
    let signed = compacted(&f, &reader).await;
    assert_eq!(signed.signer(), reader_key.public_key());
    assert_eq!(signed.statement.rows.count, 1);
    let (target, target_credentials) = open(&f, &dir.path().join("target.db"), &target_key).await;
    share_graph(&f, &reader, (&target, &target_key, &target_credentials)).await;
    let error = target.begin_rebootstrap(signed).await.unwrap_err();
    assert!(error.to_string().contains("write authority"));
    assert!(
        target
            .rebootstrap_progress(f.public)
            .await
            .unwrap()
            .is_none()
    );
    assert!(all_rows(&f, &target).await.is_empty());
    // Nor does the reader offer a base it lacks the authority to sign.
    assert!(
        reader
            .checkpoint_offer(target_key.public_key(), &target_credentials, f.public)
            .await
            .unwrap()
            .is_none()
    );
    // The same rows from a writer pass authority and stage normally.
    let signed = compacted(&f, &writer).await;
    share_graph(&f, &writer, (&target, &target_key, &target_credentials)).await;
    target.begin_rebootstrap(signed).await.unwrap();
    assert!(
        target
            .rebootstrap_progress(f.public)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn checkpoint_signer_expiry_is_checked_at_the_controlled_admission_clock() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let writer_key = PrivateKey::new();
    let target_key = PrivateKey::new();
    let (writer, _) = open(&f, &dir.path().join("writer.db"), &writer_key).await;
    let (target, _) = open(&f, &dir.path().join("target.db"), &target_key).await;
    writer
        .author(handle(1), insert(&f, 1, "base"), vec![])
        .await
        .unwrap();
    let signed = compacted(&f, &writer).await;
    let expires = writer
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .config
        .credentials
        .expires();
    target
        .verify_checkpoint_at_for_test(&signed, expires - 1)
        .await
        .unwrap();
    assert!(
        target
            .verify_checkpoint_at_for_test(&signed, expires)
            .await
            .is_err()
    );
    assert!(
        target
            .rebootstrap_progress(f.public)
            .await
            .unwrap()
            .is_none()
    );
}

/// A scope being imported from a checkpoint makes none of its own until the
/// switch: the database thread serves the import instead.
#[tokio::test]
async fn maintenance_waits_for_a_scope_being_imported() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let (a, _) = open(&f, &dir.path().join("a.db"), &PrivateKey::new()).await;
    let (b, _) = open(&f, &dir.path().join("b.db"), &PrivateKey::new()).await;
    a.author(handle(0), insert(&f, 0, "source"), vec![])
        .await
        .unwrap();
    let signed = compacted(&f, &a).await;
    b.author(handle(1), insert(&f, 1, "held"), vec![])
        .await
        .unwrap();
    b.begin_rebootstrap(signed).await.unwrap();
    for index in 2..6 {
        b.author(handle(index), insert(&f, index, "row"), vec![])
            .await
            .unwrap();
    }
    b.maintain_checkpoint_for_test(f.public).await;
    let status = b.checkpoint_status(f.public).await.unwrap();
    assert!(status.checkpoint.is_none());
    // The owner's intent holds back a scope that holds no rows yet.
    let (c, _) = open(&f, &dir.path().join("c.db"), &PrivateKey::new()).await;
    c.set_importing([f.public].into()).await;
    assert!(
        c.inner
            .lock(crate::replica::Class::Background)
            .await
            .importing(f.public)
            .await
            .unwrap()
    );
    c.author(handle(7), insert(&f, 7, "own"), vec![])
        .await
        .unwrap();
    assert!(
        !c.inner
            .lock(crate::replica::Class::Background)
            .await
            .importing(f.public)
            .await
            .unwrap()
    );
}

/// The page of `signed` after `after`, as `source` serves it to `peer`.
async fn page_of(
    source: &Replica,
    peer: (&PrivateKey, &CredentialChain),
    signed: &SignedCheckpoint,
    after: Option<Commitment>,
) -> CheckpointPage {
    source
        .checkpoint_page(
            peer.0.public_key(),
            peer.1,
            signed.statement.scope,
            signed.id().unwrap(),
            after,
            4096,
        )
        .await
        .unwrap()
}

/// A replica that holds nothing of a scope reads each verified page as it
/// commits; an interrupted import resumes at the next page and ends as the
/// source's rows, verified like any switch.
#[tokio::test]
async fn a_fresh_import_shows_each_verified_page_and_resumes_after_reopen() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let (a_key, b_key) = (PrivateKey::new(), PrivateKey::new());
    let (a, _) = open(&f, &dir.path().join("a.db"), &a_key).await;
    for index in 0..40 {
        a.author_buffered(handle(index), insert(&f, index, "base"), vec![])
            .await
            .unwrap();
    }
    let signed = compacted(&f, &a).await;
    let path = dir.path().join("b.db");
    let (b, b_credentials) = open(&f, &path, &b_key).await;
    share_graph(&f, &a, (&b, &b_key, &b_credentials)).await;
    b.begin_rebootstrap(signed.clone()).await.unwrap();
    let revisions = b.observe_revision();
    let first = page_of(&a, (&b_key, &b_credentials), &signed, None).await;
    let next = first.next;
    b.stage_checkpoint_page(first).await.unwrap();
    assert!(revisions.has_changed().unwrap());
    let shown = all_rows(&f, &b).await;
    assert!(!shown.is_empty() && shown.len() < 40, "{}", shown.len());
    let source = all_rows(&f, &a).await;
    assert!(
        shown
            .iter()
            .all(|(row, fields)| source.get(row) == Some(fields))
    );
    b.audit(f.public).await.unwrap();
    drop(b);
    let (b, _) = open(&f, &path, &b_key).await;
    let (_, cursor, complete) = b.rebootstrap_progress(f.public).await.unwrap().unwrap();
    assert_eq!((cursor, complete), (next, false));
    assert_eq!(all_rows(&f, &b).await, shown);
    let mut after = cursor;
    while let Some(cursor) = after {
        let page = page_of(&a, (&b_key, &b_credentials), &signed, Some(cursor)).await;
        after = page.next;
        b.stage_checkpoint_page(page).await.unwrap();
    }
    let report = b.finish_rebootstrap(f.public).await.unwrap();
    assert_eq!(report.checkpoint, signed.id().unwrap());
    // With the public base installed the keyless scope needs its own.
    import_no_frames(&f, &a, (&b, &b_key, &b_credentials)).await;
    assert_eq!(all_rows(&f, &b).await, all_rows(&f, &a).await);
    let status = b.checkpoint_status(f.public).await.unwrap();
    assert_eq!(
        status.checkpoint.unwrap().id().unwrap(),
        signed.id().unwrap()
    );
    b.audit(f.public).await.unwrap();
    drop(b);
    open(&f, &path, &b_key)
        .await
        .0
        .audit(f.public)
        .await
        .unwrap();
}

/// A page whose rows a key holder changed, dropped or reordered, or one
/// moved to another place, is refused before anything is stored.
#[tokio::test]
async fn a_tampered_checkpoint_page_is_refused_before_anything_is_stored() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let (a_key, b_key) = (PrivateKey::new(), PrivateKey::new());
    let (a, _) = open(&f, &dir.path().join("a.db"), &a_key).await;
    for index in 0..40 {
        a.author_buffered(handle(index), insert(&f, index, "base"), vec![])
            .await
            .unwrap();
    }
    let signed = compacted(&f, &a).await;
    let (b, b_credentials) = open(&f, &dir.path().join("b.db"), &b_key).await;
    share_graph(&f, &a, (&b, &b_key, &b_credentials)).await;
    b.begin_rebootstrap(signed.clone()).await.unwrap();
    let first = page_of(&a, (&b_key, &b_credentials), &signed, None).await;
    let second = page_of(&a, (&b_key, &b_credentials), &signed, first.next).await;
    let key = [11; 32];
    let mut changed = first.clone();
    crate::replica::checkpoint::forge_page(&mut changed, &key, |rows| {
        rows[0].1 = rows[1].1.clone();
    });
    let mut dropped = first.clone();
    crate::replica::checkpoint::forge_page(&mut dropped, &key, |rows| {
        rows.remove(1);
    });
    let mut reordered = first.clone();
    crate::replica::checkpoint::forge_page(&mut reordered, &key, |rows| rows.swap(0, 1));
    // The second page's sealed rows under the first page's place.
    let mut moved = first.clone();
    moved.rows = second.rows.clone();
    for forged in [changed, dropped, reordered, moved] {
        assert!(b.stage_checkpoint_page(forged).await.is_err());
        assert!(all_rows(&f, &b).await.is_empty());
        let (_, cursor, _) = b.rebootstrap_progress(f.public).await.unwrap().unwrap();
        assert_eq!(cursor, None);
    }
    let before = crate::tests::compaction::audit::snapshot(&b).await;
    for defect in 0..7 {
        let mut malformed = first.clone();
        crate::replica::checkpoint::forge_page_legend(
            &mut malformed,
            &key,
            &a_key,
            |legend, creations, _origins| match defect {
                0 => legend.clear(),
                1 => legend.push(legend[0].clone()),
                2 => legend.push("a".into()),
                3 => creations.clear(),
                4 => creations.push(creations[0]),
                5 => creations.swap(0, 1),
                _ => {
                    creations.push(Hash::new(b"unused page creation"));
                    creations.sort();
                }
            },
        );
        assert!(
            b.stage_checkpoint_page(malformed).await.is_err(),
            "legend defect {defect}"
        );
        assert_eq!(crate::tests::compaction::audit::snapshot(&b).await, before);
    }
    b.stage_checkpoint_page(first).await.unwrap();
    assert!(!all_rows(&f, &b).await.is_empty());
}

/// A direct import refuses any row already stored, including one late in a page.
#[tokio::test]
async fn a_direct_page_never_overwrites_an_existing_row() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let (a_key, b_key) = (PrivateKey::new(), PrivateKey::new());
    let (a, _) = open(&f, &dir.path().join("a.db"), &a_key).await;
    for index in 0..20 {
        a.author_buffered(handle(index), insert(&f, index, "base"), vec![])
            .await
            .unwrap();
    }
    let signed = compacted(&f, &a).await;
    let (b, b_credentials) = open(&f, &dir.path().join("b.db"), &b_key).await;
    share_graph(&f, &a, (&b, &b_key, &b_credentials)).await;
    b.begin_rebootstrap(signed.clone()).await.unwrap();
    let first = page_of(&a, (&b_key, &b_credentials), &signed, None).await;
    let cursor = first.next;
    assert!(cursor.is_some());
    b.stage_checkpoint_page(first).await.unwrap();
    let mut page = page_of(&a, (&b_key, &b_credentials), &signed, cursor).await;
    let mut duplicate = Vec::new();
    crate::replica::checkpoint::forge_page(&mut page, &[11; 32], |rows| {
        duplicate = rows.last().unwrap().0.clone();
    });
    {
        let inner = b.inner.lock(crate::replica::Class::Background).await;
        // Simulate a conflicting stored row without touching the import cursor.
        inner
            .conn
            .execute(
                "INSERT INTO secure_rows SELECT scope,?,fields FROM secure_rows WHERE scope=(SELECT id FROM secure_scope_state WHERE scope=?) LIMIT 1",
                crate::storage::bindings(vec![
                    SqlValue::Blob(duplicate),
                    SqlValue::Blob(encode(&f.public).unwrap()),
                ]),
            )
            .await
            .unwrap();
    }
    let before = crate::tests::compaction::audit::snapshot(&b).await;
    assert!(matches!(
        b.stage_checkpoint_page(page).await,
        Err(Error::Corrupt(_))
    ));
    assert_eq!(crate::tests::compaction::audit::snapshot(&b).await, before);
    assert_eq!(
        b.rebootstrap_progress(f.public).await.unwrap().unwrap().1,
        cursor
    );
}

/// Shared creations count once; conflicting clocks in or across pages roll back.
#[tokio::test]
async fn checkpoint_creation_clocks_agree_within_and_across_pages() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let (a_key, b_key) = (PrivateKey::new(), PrivateKey::new());
    let (a, _) = open(&f, &dir.path().join("a.db"), &a_key).await;
    a.author_buffered(
        handle(0),
        (0..24)
            .flat_map(|index| insert(&f, index, "base"))
            .collect(),
        vec![],
    )
    .await
    .unwrap();
    let signed = compacted(&f, &a).await;
    for direct in [true, false] {
        let (b, credentials) = open(&f, &dir.path().join(format!("b-{direct}.db")), &b_key).await;
        if !direct {
            b.author_buffered(handle(100), insert(&f, 100, "local"), vec![])
                .await
                .unwrap();
        }
        share_graph(&f, &a, (&b, &b_key, &credentials)).await;
        b.begin_rebootstrap(signed.clone()).await.unwrap();
        let first = page_of(&a, (&b_key, &credentials), &signed, None).await;
        assert!(first.next.is_some());
        let mut conflicting = first.clone();
        crate::replica::checkpoint::forge_page_clocks(&mut conflicting, &[11; 32], &a_key, false);
        let before = crate::tests::compaction::audit::snapshot(&b).await;
        assert!(
            b.stage_checkpoint_page(conflicting)
                .await
                .unwrap_err()
                .to_string()
                .contains("checkpoint creation clocks disagree")
        );
        assert_eq!(crate::tests::compaction::audit::snapshot(&b).await, before);
        let cursor = first.next;
        b.stage_checkpoint_page(first).await.unwrap();
        let mut second = page_of(&a, (&b_key, &credentials), &signed, cursor).await;
        crate::replica::checkpoint::forge_page_clocks(&mut second, &[11; 32], &a_key, true);
        let before = crate::tests::compaction::audit::snapshot(&b).await;
        assert!(
            b.stage_checkpoint_page(second)
                .await
                .unwrap_err()
                .to_string()
                .contains("checkpoint creation clocks disagree")
        );
        assert_eq!(crate::tests::compaction::audit::snapshot(&b).await, before);
        let mut after = cursor;
        while let Some(cursor) = after {
            let page = page_of(&a, (&b_key, &credentials), &signed, Some(cursor)).await;
            after = page.next;
            b.stage_checkpoint_page(page).await.unwrap();
        }
        b.finish_rebootstrap(f.public).await.unwrap();
        b.audit(f.public).await.unwrap();
        assert_eq!(
            count(&b, "SELECT count(*) FROM secure_checkpoint_stubs").await,
            1
        );
    }
}

/// A failed first page leaves no durable cursor. Its already requested
/// window is discarded with the channel, and a later session resumes it.
#[tokio::test]
async fn an_import_asks_for_the_next_page_while_it_stores_the_current_one() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let (a_key, b_key) = (PrivateKey::new(), PrivateKey::new());
    let (a, a_credentials) = open(&f, &dir.path().join("a.db"), &a_key).await;
    for index in 0..40 {
        a.author_buffered(handle(index), insert(&f, index, "base"), vec![])
            .await
            .unwrap();
    }
    compacted(&f, &a).await;
    let (b, b_credentials) = open(&f, &dir.path().join("b.db"), &b_key).await;
    // Enrollment hands the joiner the graph and the bookmark to follow.
    share_graph(&f, &a, (&b, &b_key, &b_credentials)).await;
    let (mut session, mut serving) = network::link::testing::sessions(
        (&b, b_key.clone(), b_credentials),
        (&a, a_key.clone(), a_credentials),
    )
    .await
    .unwrap();
    b.inject_stage_fault(Stage::Import, 0).await;
    let (pages, imported) = tokio::join!(serving.serve_counting_pages(&a), async {
        let imported = session.bootstrap_scope(&b, f.public, 4096).await;
        // As a failed sync does: the answer on its way is never read.
        drop(session);
        imported
    });
    assert!(
        matches!(imported, Err(Error::InjectedFailure)),
        "{:?}",
        imported.err()
    );
    assert_eq!(pages, 1);
    assert!(all_rows(&f, &b).await.is_empty());
    // The failed page was not stored: the import resumes from it.
    let (_, cursor, _) = b.rebootstrap_progress(f.public).await.unwrap().unwrap();
    assert_eq!(cursor, None);
}

/// Frames for a scope its import fills wait and apply after the switch; a
/// local write meanwhile is replayed over the imported rows.
#[tokio::test]
async fn writes_during_a_fresh_import_apply_over_its_rows_after_the_switch() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let (a_key, b_key) = (PrivateKey::new(), PrivateKey::new());
    let (a, _) = open(&f, &dir.path().join("a.db"), &a_key).await;
    for index in 0..40 {
        a.author_buffered(handle(index), insert(&f, index, "base"), vec![])
            .await
            .unwrap();
    }
    let signed = compacted(&f, &a).await;
    let later = a
        .author(handle(41), insert(&f, 41, "later"), vec![])
        .await
        .unwrap();
    let (b, b_credentials) = open(&f, &dir.path().join("b.db"), &b_key).await;
    share_graph(&f, &a, (&b, &b_key, &b_credentials)).await;
    b.begin_rebootstrap(signed.clone()).await.unwrap();
    let mut after = None;
    let first = page_of(&a, (&b_key, &b_credentials), &signed, after).await;
    after = first.next;
    b.stage_checkpoint_page(first).await.unwrap();
    // The source's later frame waits, so reads report the scope
    // incomplete; a local write applies at once.
    b.receive(later).await.unwrap();
    let shown = b
        .snapshot_page(f.public, None, MAX_SNAPSHOT_ROWS)
        .await
        .unwrap();
    assert!(!shown.complete && !shown.rows.contains_key(&id(41)));
    b.author(handle(50), insert(&f, 50, "local"), vec![])
        .await
        .unwrap();
    let shown = b
        .snapshot_page(f.public, None, MAX_SNAPSHOT_ROWS)
        .await
        .unwrap();
    assert!(shown.rows.contains_key(&id(50)));
    while let Some(cursor) = after {
        let page = page_of(&a, (&b_key, &b_credentials), &signed, Some(cursor)).await;
        after = page.next;
        b.stage_checkpoint_page(page).await.unwrap();
    }
    let report = b.finish_rebootstrap(f.public).await.unwrap();
    assert_eq!(report.reapplied.len(), 1);
    import_no_frames(&f, &a, (&b, &b_key, &b_credentials)).await;
    let rows = all_rows(&f, &b).await;
    assert_eq!(rows.len(), 42);
    assert!(rows.contains_key(&id(41)) && rows.contains_key(&id(50)));
    b.audit(f.public).await.unwrap();
}

/// A holder of an imported checkpoint serves the pages its signer cut and
/// signed; a third replica verifies them like the signer's own.
#[tokio::test]
async fn an_imported_checkpoint_is_served_onward_with_its_signer_pages() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new(), PrivateKey::new()];
    let (a, _) = open(&f, &dir.path().join("a.db"), &keys[0]).await;
    let (b, b_credentials) = open(&f, &dir.path().join("b.db"), &keys[1]).await;
    let (c, c_credentials) = open(&f, &dir.path().join("c.db"), &keys[2]).await;
    for index in 0..40 {
        a.author_buffered(handle(index), insert(&f, index, "base"), vec![])
            .await
            .unwrap();
    }
    let signed = compacted(&f, &a).await;
    for (source, target, peer) in [
        (&a, &b, (&keys[1], &b_credentials)),
        (&b, &c, (&keys[2], &c_credentials)),
    ] {
        share_graph(&f, source, (target, peer.0, peer.1)).await;
        target.begin_rebootstrap(signed.clone()).await.unwrap();
        let mut after = None;
        loop {
            let page = page_of(source, peer, &signed, after).await;
            after = page.next;
            target.stage_checkpoint_page(page).await.unwrap();
            if after.is_none() {
                break;
            }
        }
        target.finish_rebootstrap(f.public).await.unwrap();
        // B relays A's original no-frames statement without a key.
        let empty = import_no_frames(&f, source, (target, peer.0, peer.1)).await;
        assert_eq!(
            empty.id().unwrap(),
            a.checkpoint(f.private).await.unwrap().id().unwrap()
        );
    }
    assert_eq!(all_rows(&f, &c).await, all_rows(&f, &a).await);
    c.audit(f.public).await.unwrap();
    c.audit(f.private).await.unwrap();
}

#[tokio::test]
async fn an_unpartitioned_checkpoint_preserves_other_tables_selector_grants() {
    let fixture = Fixture::new();
    let directory = TempDir::new().unwrap();
    let node = PrivateKey::new();
    let principal = PrivateKey::new();
    let root = crate::credentials::Authority::owner(&fixture.publisher)
        .issue_partition_terms(
            principal.public_key(),
            fixture.full(),
            vec![crate::credentials::PartitionGrant {
                domain: fixture.private.domain,
                table: fixture.private.table,
                selector: rocky_core::PartitionSelector(
                    [(
                        fixture.app().field("salary"),
                        rocky_core::PartitionSelection::Any,
                    )]
                    .into(),
                ),
                rows: RowSelection::All,
                rights: [Right::Read].into(),
                fields: [fixture.app().field("salary")].into_iter().collect(),
            }],
            (1, Some(crate::credentials::AuthorRange::new(1, 2).unwrap())),
            crate::tests::validity(),
        )
        .unwrap();
    let mut config = fixture.config(&node, fixture.full(), &[fixture.public]);
    config.credentials = CredentialChain(vec![root])
        .complete(&principal, node.public_key(), 1)
        .unwrap();
    let replica =
        EncryptedReplica::open(directory.path().join("mixed.sqlite"), fixture.app(), config)
            .await
            .unwrap();
    replica
        .author(handle(1), insert(&fixture, 1, "base"), vec![])
        .await
        .unwrap();
    let signed = compacted(&fixture, &replica).await;
    replica
        .verify_checkpoint_at_for_test(&signed, now().unwrap())
        .await
        .unwrap();
    assert_eq!(signed.signer(), node.public_key());
}

mod no_frames;

mod audit;

#[tokio::test]
async fn checkpoint_pages_travel_in_windows_of_four_and_install_in_order() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let (a_key, b_key) = (PrivateKey::new(), PrivateKey::new());
    let (a, a_credentials) = open(&f, &dir.path().join("window-a.db"), &a_key).await;
    let name = "w".repeat(200);
    for index in 0..48 {
        a.author_buffered(handle(index), insert(&f, index, &name), vec![])
            .await
            .unwrap();
    }
    compacted(&f, &a).await;
    let (b, b_credentials) = open(&f, &dir.path().join("window-b.db"), &b_key).await;
    share_graph(&f, &a, (&b, &b_key, &b_credentials)).await;
    let (mut client, mut server) = network::link::testing::sessions(
        (&b, b_key.clone(), b_credentials),
        (&a, a_key, a_credentials),
    )
    .await
    .unwrap();
    let ((pulled, requests), served) = tokio::join!(
        async {
            let report = client.rebootstrap(&b, f.public, 4096).await.unwrap();
            let requests = client.sent_counts.checkpoint_requests;
            client.close().await.unwrap();
            (report, requests)
        },
        server.serve_to_end(&a)
    );
    served.unwrap();
    assert!(
        server.sent_counts.checkpoint_pages > 4,
        "{:?}",
        server.sent_counts
    );
    assert_eq!(requests, server.sent_counts.checkpoint_pages.div_ceil(4));
    assert_eq!(
        a.checkpoint_offer(
            b_key.public_key(),
            &f.credentials(&b_key, f.full()),
            f.public
        )
        .await
        .unwrap()
        .unwrap()
        .id()
        .unwrap(),
        pulled.checkpoint
    );
    assert_eq!(all_rows(&f, &a).await, all_rows(&f, &b).await);
}

#[tokio::test]
async fn a_partial_page_resumes_with_smaller_pages_and_is_served_onward() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new(), PrivateKey::new()];
    let (a, _) = open(&f, &dir.path().join("prefix-a.db"), &keys[0]).await;
    let name = "prefix".repeat(32);
    for index in 1..=24 {
        a.author(handle(index), insert(&f, index, &name), vec![])
            .await
            .unwrap();
    }
    let signed = compacted(&f, &a).await;
    let checkpoint = signed.id().unwrap();
    let (b, credentials) = open(&f, &dir.path().join("prefix-b.db"), &keys[1]).await;
    share_graph(&f, &a, (&b, &keys[1], &credentials)).await;
    b.begin_rebootstrap(signed.clone()).await.unwrap();
    let page = a
        .checkpoint_page(
            keys[1].public_key(),
            &credentials,
            f.public,
            checkpoint,
            None,
            MAX_SECURE_FRAME,
        )
        .await
        .unwrap();
    assert!(page.next.is_none_or(|next| next > id(8)));
    b.inject_stage_fault(Stage::Import, 1).await;
    assert!(matches!(
        b.stage_checkpoint_page(page).await,
        Err(Error::InjectedFailure)
    ));
    assert_eq!(b.imported_rows(f.public, checkpoint).await.unwrap(), 8);
    assert_eq!(
        b.rebootstrap_progress(f.public).await.unwrap().unwrap().1,
        None
    );
    let mut cursor = None;
    loop {
        let page = a
            .checkpoint_page(
                keys[1].public_key(),
                &credentials,
                f.public,
                checkpoint,
                cursor,
                4096,
            )
            .await
            .unwrap();
        if cursor.is_none() {
            assert!(page.next.is_some_and(|next| next < id(8)));
        }
        cursor = page.next;
        b.stage_checkpoint_page(page).await.unwrap();
        if cursor.is_none() {
            break;
        }
    }
    b.finish_rebootstrap(f.public).await.unwrap();
    assert_eq!(all_rows(&f, &b).await, all_rows(&f, &a).await);
    b.audit(f.public).await.unwrap();
    let (c, credentials) = open(&f, &dir.path().join("prefix-c.db"), &keys[2]).await;
    share_graph(&f, &b, (&c, &keys[2], &credentials)).await;
    c.begin_rebootstrap(signed).await.unwrap();
    let mut cursor = None;
    loop {
        let page = b
            .checkpoint_page(
                keys[2].public_key(),
                &credentials,
                f.public,
                checkpoint,
                cursor,
                MAX_SECURE_FRAME,
            )
            .await
            .unwrap();
        cursor = page.next;
        c.stage_checkpoint_page(page).await.unwrap();
        if cursor.is_none() {
            break;
        }
    }
    c.finish_rebootstrap(f.public).await.unwrap();
    assert_eq!(all_rows(&f, &c).await, all_rows(&f, &a).await);
    c.audit(f.public).await.unwrap();
}

#[tokio::test]
async fn checkpoint_export_validates_its_source_between_pages() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let source_key = PrivateKey::new();
    let (a, _) = open(&f, &dir.path().join("export-a.db"), &source_key).await;
    for index in 1..=12 {
        a.author(handle(index), insert(&f, index, "export"), vec![])
            .await
            .unwrap();
    }
    let signed = compacted(&f, &a).await;
    let peer = PrivateKey::new();
    let (b, credentials) = open(&f, &dir.path().join("export-b.db"), &peer).await;
    share_graph(&f, &a, (&b, &peer, &credentials)).await;
    let (reached, waiting) = tokio::sync::oneshot::channel();
    let (resume, paused) = tokio::sync::oneshot::channel();
    a.pause_checkpoint_export_for_test(reached, paused).await;
    let export = a.checkpoint_page(
        peer.public_key(),
        &credentials,
        f.public,
        signed.id().unwrap(),
        None,
        MAX_SECURE_FRAME,
    );
    let change = async {
        waiting.await.unwrap();
        let mut inner = a.inner.lock(crate::replica::Class::Background).await;
        inner
            .conn
            .execute("UPDATE secure_checkpoints SET signed=signed", ())
            .await
            .unwrap();
        inner.note_commit().await;
        drop(inner);
        resume.send(()).unwrap();
    };
    let (exported, ()) = tokio::join!(export, change);
    assert!(
        matches!(exported, Err(Error::Rejected(message)) if message.contains("checkpoint source changed"))
    );
    a.audit(f.public).await.unwrap();
}

#[tokio::test]
async fn checkpoint_preflight_validates_only_its_scope_and_authority() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let (a, _) = open(
        &f,
        &dir.path().join("preflight-source.db"),
        &PrivateKey::new(),
    )
    .await;
    for index in 1..=12 {
        a.author(handle(index), insert(&f, index, "preflight"), vec![])
            .await
            .unwrap();
    }
    let signed = compacted(&f, &a).await;
    for interference in ["metadata", "scope", "authority"] {
        let peer = PrivateKey::new();
        let (b, credentials) = open(
            &f,
            &dir.path().join(format!("preflight-{interference}.db")),
            &peer,
        )
        .await;
        share_graph(&f, &a, (&b, &peer, &credentials)).await;
        b.begin_rebootstrap(signed.clone()).await.unwrap();
        let page = a
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
        let (reached, waiting) = tokio::sync::oneshot::channel();
        let (resume, paused) = tokio::sync::oneshot::channel();
        b.pause_checkpoint_store_for_test(reached, paused).await;
        let staging = b.stage_checkpoint_page(page.clone());
        let change = async {
            waiting.await.unwrap();
            let mut inner = b.inner.lock(crate::replica::Class::Background).await;
            match interference {
                "scope" => {
                    inner
                        .conn
                        .execute("UPDATE secure_rebootstrap SET sets=sets", ())
                        .await
                        .unwrap();
                }
                "authority" => {
                    inner.authority += 1;
                }
                _ => {
                    inner
                        .conn
                        .execute(
                            "UPDATE secure_metadata SET revision=revision+1 WHERE id=1",
                            (),
                        )
                        .await
                        .unwrap();
                    inner.invalidate_context();
                }
            }
            inner.note_commit().await;
            drop(inner);
            resume.send(()).unwrap();
        };
        let (result, ()) = tokio::join!(staging, change);
        if interference != "metadata" {
            assert!(matches!(result, Err(Error::RetryExhausted)));
            assert_eq!(
                b.imported_rows(f.public, signed.id().unwrap())
                    .await
                    .unwrap(),
                0
            );
            b.stage_checkpoint_page(page).await.unwrap();
        } else {
            result.unwrap();
        }
        b.finish_rebootstrap(f.public).await.unwrap();
        assert_eq!(all_rows(&f, &b).await, all_rows(&f, &a).await);
        b.audit(f.public).await.unwrap();
    }
}
