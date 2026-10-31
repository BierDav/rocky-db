//! Stored-header syntax reuse never caches live coverage decisions.
use super::*;
use rocky_core::SqlValue;
use std::collections::BTreeSet;

type Positions = (
    BTreeMap<u32, BTreeSet<u64>>,
    BTreeMap<(ResourceScope, u32), u64>,
);

#[tokio::test]
async fn the_optional_scan_index_tracks_rows_and_is_not_backfilled_at_open() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("optional-index.db");
    let key = PrivateKey::new();
    let replica = open(&f, &path, &key).await;
    replica
        .author_bundle(
            [23; 32],
            vec![RowWrite::changed(change(
                f.public,
                1,
                None,
                Some(f.app().name("one")),
            ))],
            vec![],
        )
        .await
        .unwrap();
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    assert_eq!(rows(&inner.conn, "SELECT count(*) FROM sqlite_schema WHERE type='index' AND name='secure_operation_scan_headers'").await.unwrap(), vec![vec![SqlValue::Integer(1)]]);
    let query =
        "SELECT status,header FROM secure_operations INDEXED BY secure_operation_scan_headers";
    let original = rows(&inner.conn, query).await.unwrap();
    assert_eq!(original.len(), 1);
    assert_eq!(original[0][0], SqlValue::Text("applied".into()));
    inner
        .conn
        .execute("SAVEPOINT index_rows", ())
        .await
        .unwrap();
    inner
        .conn
        .execute("UPDATE secure_operations SET status='pending'", ())
        .await
        .unwrap();
    assert_eq!(
        rows(&inner.conn, query).await.unwrap()[0][0],
        SqlValue::Text("pending".into())
    );
    inner
        .conn
        .execute("DELETE FROM secure_operations", ())
        .await
        .unwrap();
    assert!(rows(&inner.conn, query).await.unwrap().is_empty());
    inner
        .conn
        .execute("ROLLBACK TO index_rows", ())
        .await
        .unwrap();
    inner.conn.execute("RELEASE index_rows", ()).await.unwrap();
    assert_eq!(rows(&inner.conn, query).await.unwrap(), original);
    drop(inner);
    let backup = dir.path().join("retained-backup.db");
    replica.backup_into(&backup).await.unwrap();
    let mut inner = replica.inner.lock(crate::replica::Class::Background).await;
    inner.flush().unwrap();
    let operation_pages = if rows(
        &inner.conn,
        "SELECT name FROM pragma_module_list WHERE name='dbstat'",
    )
    .await
    .unwrap()
    .is_empty()
    {
        Vec::new()
    } else {
        rows(&inner.conn, "SELECT name,sum(pgsize) FROM dbstat WHERE name IN (SELECT name FROM sqlite_schema WHERE tbl_name='secure_operations') GROUP BY name ORDER BY name").await.unwrap()
    };
    let pages = rows(&inner.conn, "PRAGMA page_count").await.unwrap();
    let free = rows(&inner.conn, "PRAGMA freelist_count").await.unwrap();
    let wal_path = path.with_extension("db-wal");
    let wal_before = std::fs::metadata(&wal_path).map_or(0, |metadata| metadata.len());
    rows(&inner.conn, "PRAGMA wal_checkpoint(TRUNCATE)")
        .await
        .unwrap();
    let wal_after = std::fs::metadata(&wal_path).map_or(0, |metadata| metadata.len());
    println!(
        "operation index accounting retained=1: operation objects={operation_pages:?}; pages/free={pages:?}/{free:?}; main={}B; WAL before/after={wal_before}/{wal_after}B; compact backup={}B",
        std::fs::metadata(&path).unwrap().len(),
        std::fs::metadata(&backup).unwrap().len()
    );
    drop(inner);
    drop(replica);
    let replica = open(&f, &path, &key).await;
    assert_eq!(
        rows(
            &replica
                .inner
                .lock(crate::replica::Class::Background)
                .await
                .conn,
            query
        )
        .await
        .unwrap(),
        original
    );
    replica
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .conn
        .execute("DROP INDEX secure_operation_scan_headers", ())
        .await
        .unwrap();
    drop(replica);
    let replica = open(&f, &path, &key).await;
    assert_eq!(
        rows(
            &replica
                .inner
                .lock(crate::replica::Class::Background)
                .await
                .conn,
            "SELECT count(*) FROM sqlite_schema WHERE name='secure_operation_scan_headers'"
        )
        .await
        .unwrap(),
        vec![vec![SqlValue::Integer(0)]]
    );
    assert_eq!(
        scan(&replica, f.public.domain, &[f.public], &[f.public])
            .await
            .unwrap()
            .0
            .values()
            .map(BTreeSet::len)
            .sum::<usize>(),
        1
    );
    replica.audit(f.public).await.unwrap();
}

async fn pending() -> (Fixture, TempDir, Replica, Vec<EncryptedFrame>) {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let source = open(&f, &dir.path().join("source.db"), &PrivateKey::new()).await;
    let target = open(&f, &dir.path().join("target.db"), &PrivateKey::new()).await;
    let frames = source
        .author_bundle(
            [7; 32],
            (1..=40)
                .map(|row| {
                    RowWrite::changed(change(f.public, row, None, Some(f.app().name("row"))))
                })
                .collect(),
            vec![],
        )
        .await
        .unwrap();
    assert_eq!(frames.len(), 2);
    assert_eq!(
        target.receive(frames[0].clone()).await.unwrap(),
        ReceiveStatus::PendingDependencies
    );
    (f, dir, target, frames)
}

async fn scan(
    replica: &Replica,
    domain: rocky_core::Scope,
    ready: &[ResourceScope],
    held: &[ResourceScope],
) -> Result<Positions, Error> {
    replica
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .scan_positions_for_test(
            domain,
            &ready.iter().map(|scope| (*scope, None)).collect::<Vec<_>>(),
            &held.iter().copied().collect(),
        )
        .await
}

async fn state(replica: &Replica) -> Vec<Vec<Vec<SqlValue>>> {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    let mut snapshot = Vec::new();
    for table in [
        "secure_finalized",
        "secure_seal_bounds",
        "secure_checkpoints",
        "secure_kept_marks",
        "secure_applied",
        "secure_scope_state",
        "secure_row_records",
        "secure_metadata",
        "secure_identity_marks",
        "secure_identity_own",
        "secure_identity_summary",
        "secure_identity_ledger",
        "secure_admission_context",
        "secure_admission_entries",
        "secure_admission_claims",
        "secure_admission_carries",
    ] {
        snapshot.push(
            rows(&inner.conn, &format!("SELECT * FROM {table} ORDER BY 1"))
                .await
                .unwrap(),
        );
    }
    snapshot
}

async fn replace_header(replica: &Replica, bytes: &[u8]) {
    replica
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .conn
        .execute("UPDATE secure_operations SET header=?", [bytes.to_vec()])
        .await
        .unwrap();
}

fn rejected<T>(result: Result<T, Error>, expected: &str) {
    match result {
        Err(Error::Rejected(message)) => assert_eq!(message, expected),
        Err(error) => panic!("expected rejection {expected:?}, got {error:?}"),
        Ok(_) => panic!("expected rejection {expected:?}, got success"),
    }
}

#[tokio::test]
async fn excluded_and_other_domain_headers_still_decode_after_warming() {
    let (f, _dir, target, frames) = pending().await;
    let original = frames[0].header_bytes();
    let empty = scan(&target, f.public.domain, &[f.public], &[f.public])
        .await
        .unwrap();
    assert_eq!(empty, (BTreeMap::new(), BTreeMap::new()));
    target
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .compute_tip_frontier(f.public)
        .await
        .unwrap();
    let peer = PrivateKey::new();
    let credentials = f.credentials(&peer, f.full());
    let held = target
        .held_frame_page(
            peer.public_key(),
            &credentials,
            f.public,
            None,
            MAX_SECURE_FRAME,
        )
        .await
        .unwrap();
    assert!(held.0.is_empty());
    assert!(held.1.is_none());
    let before = state(&target).await;
    assert!((0x80..0x98).contains(&original[0]));
    let mut indefinite = vec![0x9f];
    indefinite.extend_from_slice(&original[1..]);
    indefinite.push(0xff);
    // Prove this is decodable CBOR with the same fields, but not canonical.
    let _: p2panda_core::Header<crate::wire::Extensions> =
        p2panda_core::cbor::decode_cbor(indefinite.as_slice()).unwrap();
    for (bytes, message) in [
        (vec![0xff], "invalid secure frame"),
        (indefinite, "non-canonical secure frame"),
    ] {
        replace_header(&target, &bytes).await;
        rejected(
            scan(&target, f.public.domain, &[f.public], &[f.public]).await,
            message,
        );
        rejected(
            target
                .inner
                .lock(crate::replica::Class::Background)
                .await
                .compute_tip_frontier(f.public)
                .await,
            message,
        );
        // Held lookup classifies by the transactional position index and
        // never loads this live pending frame. Audit still checks its bytes.
        let held = target
            .held_frame_page(
                peer.public_key(),
                &credentials,
                f.public,
                None,
                MAX_SECURE_FRAME,
            )
            .await
            .unwrap();
        assert!(held.0.is_empty());
        assert!(held.1.is_none());
        assert!(target.audit(f.public).await.is_err());
        assert_eq!(state(&target).await, before);
    }
    // A cold excluded row and a different requested domain also fail before filtering.
    target
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .stored_header_memo_limits(1, 1);
    replace_header(&target, &[0xff]).await;
    rejected(
        scan(&target, f.public.domain, &[f.public], &[]).await,
        "invalid secure frame",
    );
    let mut other = f.public.domain;
    other.app.0[0] ^= 1;
    rejected(scan(&target, other, &[], &[]).await, "invalid secure frame");
    assert_eq!(state(&target).await, before);
    replace_header(&target, original).await;
    assert_eq!(
        scan(&target, f.public.domain, &[f.public], &[f.public])
            .await
            .unwrap(),
        empty
    );
    assert!(
        target
            .held_frame_page(
                peer.public_key(),
                &credentials,
                f.public,
                None,
                MAX_SECURE_FRAME
            )
            .await
            .unwrap()
            .0
            .is_empty()
    );
    target.receive(frames[1].clone()).await.unwrap();
    target.audit(f.public).await.unwrap();
}

#[tokio::test]
async fn warm_syntax_keeps_pending_key_ready_and_status_predicates_live() {
    let (f, _dir, target, frames) = pending().await;
    let header: p2panda_core::Header<crate::wire::Extensions> =
        crate::decode(frames[0].header_bytes()).unwrap();
    let author = header.extensions.author.unwrap();
    let position = header.extensions.author_sequence;
    let scopes = [(f.public, None)];
    let held = BTreeSet::from([f.public]);
    let mut inner = target.inner.lock(crate::replica::Class::Background).await;
    inner.stored_header_memo_limits(8, 1 << 20);
    let first = inner
        .scan_positions_for_test(f.public.domain, &scopes, &held)
        .await
        .unwrap();
    assert!(first.0.is_empty());
    let warmed = inner.stored_header_memo_stats();
    assert_eq!(warmed.0, 1);
    assert_eq!(warmed.1, frames[0].header_bytes().len());
    assert_eq!(
        inner
            .scan_positions_for_test(f.public.domain, &scopes, &held)
            .await
            .unwrap(),
        first
    );
    assert_eq!(
        inner.stored_header_memo_stats(),
        warmed,
        "second scan must reuse parsing"
    );
    let keys = std::mem::take(&mut inner.config.keys);
    let counted = inner
        .scan_positions_for_test(f.public.domain, &scopes, &held)
        .await
        .unwrap();
    assert_eq!(counted.0[&author], BTreeSet::from([position]));
    assert_eq!(counted.1[&(f.public, author)], position);
    inner.config.keys = keys;
    assert_eq!(
        inner
            .scan_positions_for_test(f.public.domain, &scopes, &held)
            .await
            .unwrap(),
        first
    );
    let not_ready = inner
        .scan_positions_for_test(f.public.domain, &[], &held)
        .await
        .unwrap();
    assert_eq!(not_ready.0, counted.0);
    assert!(not_ready.1.is_empty());
    inner
        .conn
        .execute("SAVEPOINT header_status", ())
        .await
        .unwrap();
    inner
        .conn
        .execute("UPDATE secure_operations SET status='applied'", ())
        .await
        .unwrap();
    assert_eq!(
        inner
            .scan_positions_for_test(f.public.domain, &scopes, &held)
            .await
            .unwrap(),
        counted
    );
    inner
        .conn
        .execute("ROLLBACK TO header_status", ())
        .await
        .unwrap();
    inner
        .conn
        .execute("RELEASE header_status", ())
        .await
        .unwrap();
    assert_eq!(
        inner
            .scan_positions_for_test(f.public.domain, &scopes, &held)
            .await
            .unwrap(),
        first
    );
    assert_eq!(inner.stored_header_memo_stats(), warmed);
    drop(inner);
    target.receive(frames[1].clone()).await.unwrap();
    let applied = scan(&target, f.public.domain, &[f.public], &[f.public])
        .await
        .unwrap();
    assert_eq!(applied.0[&author].len(), 2);
    assert_eq!(target.snapshot(f.public).await.unwrap().rows.len(), 40);
    target.audit(f.public).await.unwrap();
}

#[tokio::test]
async fn warm_void_and_placement_headers_keep_distinct_coverage_powers() {
    let (f, _dir, target, frames) = pending().await;
    let header: p2panda_core::Header<crate::wire::Extensions> =
        crate::decode(frames[0].header_bytes()).unwrap();
    let author = header.extensions.author.unwrap();
    let sequence = header.extensions.author_sequence;
    let hash = frames[0].id().unwrap();
    assert!(
        scan(&target, f.public.domain, &[f.public], &[f.public])
            .await
            .unwrap()
            .0
            .is_empty()
    );
    let inner = target.inner.lock(crate::replica::Class::Background).await;
    inner
        .conn
        .execute("SAVEPOINT header_kinds", ())
        .await
        .unwrap();
    inner.conn.execute("INSERT INTO secure_voids(scope,author,sequence,hash,header) SELECT scope,author,sequence,hash,header FROM secure_operations", ()).await.unwrap();
    inner
        .conn
        .execute("DELETE FROM secure_operations", ())
        .await
        .unwrap();
    drop(inner);
    let void = scan(&target, f.public.domain, &[f.public], &[f.public])
        .await
        .unwrap();
    assert_eq!(void.0[&author], BTreeSet::from([sequence]));
    assert_eq!(void.1[&(f.public, author)], sequence);
    let inner = target.inner.lock(crate::replica::Class::Background).await;
    inner
        .conn
        .execute("DELETE FROM secure_voids", ())
        .await
        .unwrap();
    inner
        .conn
        .execute(
            "INSERT INTO secure_placements VALUES(?,?,?,?,?,?)",
            crate::storage::bindings(vec![
                SqlValue::Blob(crate::encode(&f.public.domain).unwrap()),
                SqlValue::Integer(i64::from(author)),
                SqlValue::Integer(sequence as i64),
                SqlValue::Blob(crate::encode(&f.public).unwrap()),
                SqlValue::Blob(hash.as_bytes().to_vec()),
                SqlValue::Blob(frames[0].header_bytes().to_vec()),
            ]),
        )
        .await
        .unwrap();
    drop(inner);
    let placed = scan(&target, f.public.domain, &[f.public], &[])
        .await
        .unwrap();
    assert_eq!(placed.0, void.0);
    assert!(placed.1.is_empty());
    assert!(
        scan(&target, f.public.domain, &[f.public], &[f.public])
            .await
            .unwrap()
            .0
            .is_empty()
    );
    let inner = target.inner.lock(crate::replica::Class::Background).await;
    inner
        .conn
        .execute("ROLLBACK TO header_kinds", ())
        .await
        .unwrap();
    inner
        .conn
        .execute("RELEASE header_kinds", ())
        .await
        .unwrap();
    drop(inner);
    target.receive(frames[1].clone()).await.unwrap();
    target.audit(f.public).await.unwrap();
}

#[tokio::test]
async fn fresh_rows_rollback_and_bounded_fallback_never_reuse_position_results() {
    let (f, _dir, target, frames) = pending().await;
    let first = scan(&target, f.public.domain, &[], &[]).await.unwrap();
    assert_eq!(first.0.values().map(BTreeSet::len).sum::<usize>(), 1);
    target.receive(frames[1].clone()).await.unwrap();
    let both = scan(&target, f.public.domain, &[], &[]).await.unwrap();
    assert_eq!(both.0.values().map(BTreeSet::len).sum::<usize>(), 2);
    let mut inner = target.inner.lock(crate::replica::Class::Background).await;
    inner
        .conn
        .execute(
            "CREATE TEMP TABLE removed_header AS SELECT * FROM secure_operations WHERE sequence=0",
            (),
        )
        .await
        .unwrap();
    inner
        .conn
        .execute("DELETE FROM secure_operations WHERE sequence=0", ())
        .await
        .unwrap();
    assert_eq!(
        inner
            .scan_positions_for_test(f.public.domain, &[], &BTreeSet::new())
            .await
            .unwrap()
            .0
            .values()
            .map(BTreeSet::len)
            .sum::<usize>(),
        1
    );
    inner
        .conn
        .execute(
            "INSERT INTO secure_operations SELECT * FROM removed_header",
            (),
        )
        .await
        .unwrap();
    crate::replica::positions::insert(
        &inner.conn,
        &frames[0].operation().unwrap().header,
        0,
        false,
        true,
    )
    .await
    .unwrap();
    let mut attempts = 0;
    transaction!(inner, |inner| {
        attempts += 1;
        inner
            .conn
            .execute("UPDATE secure_operations SET status='pending'", ())
            .await?;
        assert!(
            inner
                .scan_positions_for_test(
                    f.public.domain,
                    &[(f.public, None)],
                    &BTreeSet::from([f.public])
                )
                .await?
                .0
                .is_empty()
        );
        if attempts == 1 {
            return Err(Error::from(crate::sqlite::Error::Busy(
                "header predicate retry".into(),
            )));
        }
        inner
            .conn
            .execute("UPDATE secure_operations SET status='applied'", ())
            .await?;
        Ok(())
    })
    .unwrap();
    assert_eq!(attempts, 2);
    for (capacity, bytes) in [(1, 1 << 20), (8, 1), (0, 0)] {
        inner.stored_header_memo_limits(capacity, bytes);
        for _ in 0..2 {
            assert_eq!(
                inner
                    .scan_positions_for_test(f.public.domain, &[], &BTreeSet::new())
                    .await
                    .unwrap(),
                both
            );
            let stats = inner.stored_header_memo_stats();
            assert!(stats.0 <= capacity);
            assert!(stats.1 <= bytes);
        }
    }
    drop(inner);
    target.audit(f.public).await.unwrap();
}

#[tokio::test]
async fn shared_parsing_keeps_frontier_hash_author_and_live_status_checks() {
    let (f, _dir, target, frames) = pending().await;
    let original = frames[0].header_bytes();
    scan(&target, f.public.domain, &[f.public], &[])
        .await
        .unwrap();
    let inner = target.inner.lock(crate::replica::Class::Background).await;
    let frontier = inner.compute_tip_frontier(f.public).await.unwrap();
    assert_eq!((frontier.logs[0].held, frontier.logs[0].applied), (1, 0));
    inner
        .conn
        .execute("SAVEPOINT header_frontier", ())
        .await
        .unwrap();
    inner
        .conn
        .execute("UPDATE secure_operations SET hash=?", [vec![19u8; 32]])
        .await
        .unwrap();
    assert!(
        matches!(inner.compute_tip_frontier(f.public).await, Err(Error::Corrupt(message)) if message == "frontier header hash")
    );
    let mut header: p2panda_core::Header<crate::wire::Extensions> =
        crate::decode(original).unwrap();
    header.extensions.author = None;
    let bytes = crate::encode(&header).unwrap();
    inner
        .conn
        .execute(
            "UPDATE secure_operations SET hash=?,header=?",
            crate::storage::bindings(vec![
                SqlValue::Blob(Hash::new(&bytes).as_bytes().to_vec()),
                SqlValue::Blob(bytes),
            ]),
        )
        .await
        .unwrap();
    assert!(
        inner
            .scan_positions_for_test(f.public.domain, &[], &BTreeSet::new())
            .await
            .unwrap()
            .0
            .is_empty()
    );
    rejected(
        inner.compute_tip_frontier(f.public).await,
        "node author missing",
    );
    inner
        .conn
        .execute("ROLLBACK TO header_frontier", ())
        .await
        .unwrap();
    inner
        .conn
        .execute("RELEASE header_frontier", ())
        .await
        .unwrap();
    inner.compute_tip_frontier(f.public).await.unwrap();
    inner
        .conn
        .execute("SAVEPOINT frontier_status", ())
        .await
        .unwrap();
    inner
        .conn
        .execute("UPDATE secure_operations SET status='held'", ())
        .await
        .unwrap();
    assert_eq!(
        inner.compute_tip_frontier(f.public).await.unwrap().logs[0].applied,
        1
    );
    assert_eq!(
        inner
            .scan_positions_for_test(f.public.domain, &[(f.public, None)], &BTreeSet::new())
            .await
            .unwrap()
            .0
            .values()
            .map(BTreeSet::len)
            .sum::<usize>(),
        1
    );
    inner
        .conn
        .execute("ROLLBACK TO frontier_status", ())
        .await
        .unwrap();
    inner
        .conn
        .execute("RELEASE frontier_status", ())
        .await
        .unwrap();
    assert_eq!(
        inner.compute_tip_frontier(f.public).await.unwrap(),
        frontier
    );
    drop(inner);
    target.receive(frames[1].clone()).await.unwrap();
    target.audit(f.public).await.unwrap();
}

#[tokio::test]
async fn a_pending_frame_names_why_it_waits_until_it_applies() {
    let (f, _dir, target, frames) = pending().await;
    let blockers = target.blockers().await.unwrap();
    let pending: Vec<_> = blockers
        .iter()
        .filter_map(|blocker| match blocker.kind {
            crate::BlockerKind::PendingFrames { reason, count } => Some((
                blocker.scope.clone(),
                reason,
                count,
                blocker.clears_by.clone(),
            )),
            _ => None,
        })
        .collect();
    assert_eq!(
        pending,
        vec![(
            crate::scope_label(&f.public),
            crate::WaitReason::Dependencies,
            1,
            crate::ClearsBy::AnyPeer
        )]
    );
    target.receive(frames[1].clone()).await.unwrap();
    assert!(
        target
            .blockers()
            .await
            .unwrap()
            .iter()
            .all(|blocker| !matches!(blocker.kind, crate::BlockerKind::PendingFrames { .. }))
    );
}
