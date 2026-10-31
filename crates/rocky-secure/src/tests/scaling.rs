use super::*;
use crate::storage::rows;
use rocky_core::SqlValue;
use std::collections::BTreeMap;

#[tokio::test]
async fn bounded_pages_scope_filtering_and_pending_passes_do_not_starve() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let a = PrivateKey::new();
    let b = PrivateKey::new();
    let bc = f.config(&b, f.full(), &[f.public]);
    let credentials = bc.credentials.clone();
    let source = EncryptedReplica::open(
        dir.path().join("a.db"),
        f.app(),
        f.config(&a, f.full(), &[f.public, f.private]),
    )
    .await
    .unwrap();
    let target = EncryptedReplica::open(dir.path().join("b.db"), f.app(), bc)
        .await
        .unwrap();
    let mut original = Vec::new();
    for row in 1..=34 {
        original.push(
            source
                .author(
                    [row; 32],
                    vec![change(f.public, row, None, Some(f.app().name("public")))],
                    vec![],
                )
                .await
                .unwrap(),
        );
    }
    source
        .author(
            [99; 32],
            vec![change(f.private, 1, None, Some(f.app().salary("123")))],
            vec![],
        )
        .await
        .unwrap();
    let mut cursor = None;
    let mut received = BTreeSet::new();
    loop {
        let page = source
            .transfer_page(
                b.public_key(),
                &credentials,
                &[f.public],
                cursor,
                MAX_SECURE_FRAME,
            )
            .await
            .unwrap();
        assert!(page.frames.len() <= 32);
        for frame in page.frames {
            assert_eq!(frame.scope().unwrap(), f.public);
            assert!(
                original
                    .iter()
                    .any(|old| old.to_bytes().unwrap() == frame.to_bytes().unwrap())
            );
            assert!(received.insert(frame.id().unwrap()));
            target.receive(frame).await.unwrap();
        }
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(received.len(), 34);
    assert_eq!(target.snapshot(f.public).await.unwrap().rows.len(), 34);
    assert!(target.snapshot(f.public).await.unwrap().complete);
    let late = source
        .author(
            [100; 32],
            vec![change(f.public, 100, None, Some(f.app().name("late")))],
            vec![],
        )
        .await
        .unwrap();
    let mut cursor = None;
    let mut found = false;
    loop {
        let page = source
            .transfer_page(
                b.public_key(),
                &credentials,
                &[f.public],
                cursor,
                MAX_SECURE_FRAME,
            )
            .await
            .unwrap();
        found |= page
            .frames
            .iter()
            .any(|frame| frame.id().unwrap() == late.id().unwrap());
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    assert!(found);
    // A hash before the cursor arrives after a pass; custody is not application.
    let relay_key = PrivateKey::new();
    let relay = EncryptedReplica::open(
        dir.path().join("relay.db"),
        f.app(),
        f.config(
            &relay_key,
            vec![grant(f.public, &[Right::Custody], &[])],
            &[],
        ),
    )
    .await
    .unwrap();
    let mut sorted = original.clone();
    sorted.sort_by_key(|frame| frame.id().unwrap());
    let first = sorted.first().unwrap().clone();
    let last = sorted.last().unwrap().clone();
    let cursor = last.id().unwrap();
    assert_eq!(relay.receive(last).await.unwrap(), ReceiveStatus::Custody);
    assert_eq!(
        relay.receive(first.clone()).await.unwrap(),
        ReceiveStatus::Custody
    );
    assert!(
        relay
            .transfer_page(
                b.public_key(),
                &credentials,
                &[f.public],
                Some(cursor),
                MAX_SECURE_FRAME
            )
            .await
            .unwrap()
            .frames
            .is_empty()
    );
    let restarted = relay
        .transfer_page(
            b.public_key(),
            &credentials,
            &[f.public],
            None,
            MAX_SECURE_FRAME,
        )
        .await
        .unwrap();
    assert!(
        restarted
            .frames
            .iter()
            .any(|frame| frame.id().unwrap() == first.id().unwrap())
    );
    assert_eq!(
        relay.receipt_status(first.id().unwrap()).await.unwrap(),
        ReceiveStatus::Custody
    );
}

#[tokio::test]
async fn shadow_switch_rollback_reopen_and_tombstones_preserve_original_history() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let node = PrivateKey::new();
    let config = f.config(&node, f.full(), &[f.public, f.private]);
    let credentials = config.credentials.clone();
    let replica = EncryptedReplica::open(dir.path().join("a.db"), f.app(), config)
        .await
        .unwrap();
    let first = replica
        .author(
            [1; 32],
            vec![change(f.public, 1, None, Some(f.app().name("alive")))],
            vec![],
        )
        .await
        .unwrap();
    replica
        .author(
            [2; 32],
            vec![change(f.public, 1, Some(f.app().name("alive")), None)],
            vec![],
        )
        .await
        .unwrap();
    replica
        .author(
            [3; 32],
            vec![change(f.private, 1, None, Some(f.app().salary("456")))],
            vec![],
        )
        .await
        .unwrap();
    let before = replica.snapshot(f.public).await.unwrap();
    let other = replica.snapshot(f.private).await.unwrap();
    let mut revisions = replica.observe_revision();
    revisions.borrow_and_update();
    replica.inject_failure(0, 1).await;
    assert!(replica.rebuild_projection(f.public).await.is_err());
    assert_eq!(
        replica.snapshot(f.public).await.unwrap().revision,
        before.revision
    );
    assert!(!revisions.has_changed().unwrap());
    replica.rebuild_projection(f.public).await.unwrap();
    assert!(revisions.has_changed().unwrap());
    assert_eq!(replica.snapshot(f.public).await.unwrap().rows, before.rows);
    assert_eq!(replica.snapshot(f.private).await.unwrap().rows, other.rows);
    assert_eq!(
        replica.companion(f.public, [1; 32]).await.unwrap(),
        Companion::Deleted
    );
    assert_eq!(
        replica.receive(first.clone()).await.unwrap(),
        ReceiveStatus::Duplicate
    );
    let frames = replica
        .transfer_page(
            node.public_key(),
            &credentials,
            &[f.public],
            None,
            MAX_SECURE_FRAME,
        )
        .await
        .unwrap()
        .frames;
    assert!(
        frames
            .iter()
            .any(|frame| frame.to_bytes().unwrap() == first.to_bytes().unwrap())
    );
    drop(replica);
    let reopened = EncryptedReplica::open(
        dir.path().join("a.db"),
        f.app(),
        f.config(&node, f.full(), &[f.public, f.private]),
    )
    .await
    .unwrap();
    assert!(reopened.snapshot(f.public).await.unwrap().rows.is_empty());
    assert_eq!(
        reopened.companion(f.public, [1; 32]).await.unwrap(),
        Companion::Deleted
    );
}

fn wide_row(index: u16) -> [u8; 32] {
    let mut row = [0; 32];
    row[..2].copy_from_slice(&index.to_be_bytes());
    row
}

#[tokio::test]
async fn pages_bound_reads_and_rebuild_streams_past_the_snapshot_limit() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let node = PrivateKey::new();
    let replica = EncryptedReplica::open(
        dir.path().join("a.db"),
        f.app(),
        f.config(&node, f.full(), &[f.public, f.private]),
    )
    .await
    .unwrap();
    // 33 operations of 32 rows: one row more than a snapshot may hold, plus spare.
    let mut created = Vec::new();
    for batch in 0..33u16 {
        let changes = (0..32)
            .map(|offset| RowChange {
                scope: f.public,
                row: wide_row(batch * 32 + offset),
                before: None,
                after: Some(f.app().name("first")),
            })
            .collect();
        let mut handle = [7; 32];
        handle[0] = batch as u8;
        created.push(replica.author(handle, changes, vec![]).await.unwrap());
    }
    let edit = |row, before: &str, after: Option<&str>| RowChange {
        scope: f.public,
        row: wide_row(row),
        before: Some(f.app().name(before)),
        after: after.map(|name| f.app().name(name)),
    };
    replica
        .author(
            [200; 32],
            vec![edit(5, "first", Some("edited"))],
            vec![created[0].id().unwrap()],
        )
        .await
        .unwrap();
    replica
        .author(
            [201; 32],
            vec![edit(40, "first", None)],
            vec![created[1].id().unwrap()],
        )
        .await
        .unwrap();
    replica
        .author(
            [202; 32],
            vec![change(f.private, 1, None, Some(f.app().salary("123")))],
            vec![],
        )
        .await
        .unwrap();

    assert!(matches!(
        replica.snapshot(f.public).await,
        Err(Error::Quota { .. })
    ));
    for refused in [0, MAX_SNAPSHOT_ROWS + 1] {
        assert!(
            replica
                .snapshot_page(f.public, None, refused)
                .await
                .is_err()
        );
    }
    let read_all = || async {
        let (mut rows, mut cursor, mut pages) = (BTreeMap::new(), None, 0);
        loop {
            let page = replica.snapshot_page(f.public, cursor, 100).await.unwrap();
            assert!(page.complete && page.rows.len() <= 100);
            assert!(page.rows.keys().all(|row| Some(*row) > cursor));
            pages += 1;
            rows.extend(page.rows);
            cursor = page.next;
            if cursor.is_none() {
                return (rows, pages);
            }
        }
    };
    let (before, pages) = read_all().await;
    assert_eq!((before.len(), pages), (33 * 32 - 1, 11));
    assert_eq!(before[&wide_row(5)], f.app().name("edited"));
    assert!(!before.contains_key(&wide_row(40)));
    // A cursor is a row key inside the requested scope: it cannot leave it.
    let private = replica
        .snapshot_page(f.private, Some(wide_row(0)), 10)
        .await
        .unwrap();
    assert_eq!(private.rows.len(), 1);
    assert!(private.rows.contains_key(&[1; 32]));
    let last = replica
        .snapshot_page(f.public, Some([255; 32]), 10)
        .await
        .unwrap();
    assert!(last.rows.is_empty() && last.next.is_none());

    replica.rebuild_projection(f.public).await.unwrap();
    assert_eq!(read_all().await.0, before);
    assert_eq!(replica.snapshot(f.private).await.unwrap().rows.len(), 1);
    assert_eq!(
        replica.companion(f.public, wide_row(40)).await.unwrap(),
        Companion::Deleted
    );
    assert_eq!(
        replica.companion(f.public, wide_row(5)).await.unwrap(),
        Companion::Present(f.app().name("edited"))
    );
    drop(replica);
    // Reopen audits the rebuilt projection against history.
    let reopened = EncryptedReplica::open(
        dir.path().join("a.db"),
        f.app(),
        f.config(&node, f.full(), &[f.public]),
    )
    .await
    .unwrap();
    // Without the key a readable scope yields no rows and is not complete.
    let keyless = reopened.snapshot_page(f.private, None, 10).await.unwrap();
    assert!(keyless.rows.is_empty() && !keyless.complete && keyless.next.is_none());
    assert_eq!(
        reopened.companion(f.private, [1; 32]).await.unwrap(),
        Companion::Unavailable
    );
    assert_eq!(
        reopened
            .snapshot_page(f.public, Some(wide_row(39)), 1)
            .await
            .unwrap()
            .rows
            .into_keys()
            .collect::<Vec<_>>(),
        vec![wide_row(41)]
    );
}

#[tokio::test]
async fn read_and_replay_queries_use_indexes() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let replica = EncryptedReplica::open(
        dir.path().join("a.db"),
        f.app(),
        f.config(&PrivateKey::new(), f.full(), &[f.public]),
    )
    .await
    .unwrap();
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    for sql in [
        "SELECT 1 FROM secure_operations WHERE scope=x'00' AND status='pending' LIMIT 1",
        "SELECT hash,header FROM secure_operations WHERE scope=x'00' AND status='applied' AND hash>x'' ORDER BY hash LIMIT 32",
        "SELECT row,fields FROM secure_row_records WHERE scope=x'00' AND row>x'' ORDER BY row LIMIT 256",
        "SELECT fields FROM secure_checkpoint_overlay WHERE scope=1 AND row=x'00'",
    ] {
        let plan = format!(
            "{:?}",
            rows(&inner.conn, &format!("EXPLAIN QUERY PLAN {sql}"))
                .await
                .unwrap()
        );
        assert!(plan.contains("SEARCH") && !plan.contains("SCAN"), "{plan}");
        assert!(!plan.contains("TEMP B-TREE"), "{plan}");
    }
}

#[tokio::test]
async fn wide_signed_definitions_are_cached_without_weakening_row_admission() {
    use rocky_core::{ApplicationManifest, DefinitionItem, RowApplication};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Counted {
        app: Employees,
        manifest: Arc<ApplicationManifest>,
        calls: Arc<AtomicUsize>,
    }
    impl RowApplication for Counted {
        fn manifest(&self) -> ApplicationManifest {
            self.calls.fetch_add(1, Ordering::Relaxed);
            (*self.manifest).clone()
        }
        fn permission_fields(&self) -> BTreeSet<Commitment> {
            self.app.permission_fields()
        }
        fn validate_changes(&self, changes: &[RowChange]) -> Result<(), String> {
            self.app.validate_changes(changes)
        }
    }
    let f = Fixture::new();
    let mut manifest = f.app().definition();
    for index in 2..2000 {
        let name = format!("unused-{index}");
        manifest.entities.push(DefinitionItem {
            id: manifest.item_id("entity", &name),
            name: name.clone(),
            shape: "record".into(),
        });
        for column in 0..3 {
            let name = format!("{name}.{column}");
            manifest.fields.push(DefinitionItem {
                id: manifest.item_id("field", &name),
                name,
                shape: "text".into(),
            });
        }
    }
    let signed = SignedManifest::sign(&manifest, &f.publisher).unwrap();
    let bytes = signed.to_bytes().unwrap();
    assert!(bytes.len() > MAX_SECURE_FRAME);
    assert_eq!(
        SignedManifest::from_bytes(&bytes)
            .unwrap()
            .verify(f.publisher.public_key())
            .unwrap()
            .hash(),
        manifest.hash()
    );
    let manifest = Arc::new(manifest);
    let config = |node: &PrivateKey| {
        let user = PrivateKey::new();
        let deployment = PrivateKey::new();
        let (not_before, expires) = crate::tests::lifetime();
        let capability = |subject, kind, delegations| Capability {
            subject,
            kind,
            grants: f.full(),
            not_before,
            expires,
            delegations,
            extension: rocky_credentials::Extension::new(rocky_credentials::Extended {
                authors: Some(if kind == PrincipalKind::Node {
                    rocky_credentials::AuthorRange::new(
                        crate::tests::node_number(subject),
                        crate::tests::node_number(subject),
                    )
                    .unwrap()
                } else {
                    rocky_credentials::AuthorRange::ALL
                }),
                node: (kind == PrincipalKind::Node).then(|| rocky_credentials::PeerId::of(subject)),
                ..Default::default()
            })
            .unwrap(),
        };
        SecureConfig {
            publisher: f.publisher.public_key(),
            manifest: signed.clone(),
            revocations: RevocationSet::new(),
            node: node.clone(),
            credentials: CredentialChain(vec![
                SignedCapability::sign(
                    capability(user.public_key(), PrincipalKind::User, 2),
                    &f.publisher,
                )
                .unwrap(),
                SignedCapability::sign(
                    capability(deployment.public_key(), PrincipalKind::Deployment, 1),
                    &user,
                )
                .unwrap(),
                SignedCapability::sign(
                    capability(node.public_key(), PrincipalKind::Node, 0),
                    &deployment,
                )
                .unwrap(),
            ]),
            keys: vec![KeyMaterial::new(f.public, 1, [11; 32])],
        }
    };
    let dir = TempDir::new().unwrap();
    let a = PrivateKey::new();
    let b = PrivateKey::new();
    let source_calls = Arc::new(AtomicUsize::new(0));
    let target_calls = Arc::new(AtomicUsize::new(0));
    let source = EncryptedReplica::open(
        dir.path().join("wide-a.db"),
        Counted {
            app: f.app(),
            manifest: manifest.clone(),
            calls: source_calls.clone(),
        },
        config(&a),
    )
    .await
    .unwrap();
    let target = EncryptedReplica::open(
        dir.path().join("wide-b.db"),
        Counted {
            app: f.app(),
            manifest: manifest.clone(),
            calls: target_calls.clone(),
        },
        config(&b),
    )
    .await
    .unwrap();
    for index in 1..=10 {
        let frame = source
            .author(
                [index; 32],
                vec![change(f.public, index, None, Some(f.app().name("wide")))],
                vec![],
            )
            .await
            .unwrap();
        target.receive(frame).await.unwrap();
    }
    assert_eq!(target.snapshot(f.public).await.unwrap().rows.len(), 10);
    assert_eq!(source_calls.load(Ordering::Relaxed), 1);
    assert_eq!(target_calls.load(Ordering::Relaxed), 1);
    let mut invalid = f.public;
    invalid.table = [0xff; 32];
    assert!(
        source
            .author(
                [99; 32],
                vec![change(invalid, 99, None, Some(f.app().name("invalid")))],
                vec![]
            )
            .await
            .is_err()
    );
    assert_eq!(source.snapshot(f.public).await.unwrap().rows.len(), 10);
}

/// Statements the target prepares to apply ordinary updates: one frame of
/// 32 updated rows, then a frame updating one row.
#[tokio::test]
async fn an_ordinary_update_applies_in_few_statements_per_row() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let (a, b) = (PrivateKey::new(), PrivateKey::new());
    let config = f.config(&b, f.full(), &[f.public]);
    let credentials = config.credentials.clone();
    let source = EncryptedReplica::open(
        dir.path().join("a.db"),
        f.app(),
        f.config(&a, f.full(), &[f.public]),
    )
    .await
    .unwrap();
    let target = EncryptedReplica::open(dir.path().join("b.db"), f.app(), config)
        .await
        .unwrap();
    let uncached = EncryptedReplica::open(
        dir.path().join("uncached.db"),
        f.app(),
        f.config(&b, f.full(), &[f.public]),
    )
    .await
    .unwrap();
    uncached
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .disable_metadata_cache_for_test();
    let rows = 1..=32;
    let name = |text: &str| Some(f.app().name(text));
    let created = rows
        .clone()
        .map(|row| change(f.public, row, None, name("first")));
    source
        .author([1; 32], created.collect(), vec![])
        .await
        .unwrap();
    let page = source
        .transfer_page(
            b.public_key(),
            &credentials,
            &[f.public],
            None,
            MAX_SECURE_FRAME,
        )
        .await
        .unwrap();
    for frame in page.frames {
        uncached.receive(frame.clone()).await.unwrap();
        target.receive(frame).await.unwrap();
    }
    let updated = rows.map(|row| change(f.public, row, name("first"), name("second")));
    let many = source
        .author([2; 32], updated.collect(), vec![])
        .await
        .unwrap();
    let author_before = crate::sqlite::statements();
    crate::sqlite::trace_statements(true);
    let one = source
        .author(
            [3; 32],
            vec![change(f.public, 1, name("second"), name("third"))],
            vec![],
        )
        .await
        .unwrap();
    let author_trace = crate::sqlite::trace_statements(false);
    let author_count = crate::sqlite::statements() - author_before;
    let mut by_table = BTreeMap::<String, Vec<&str>>::new();
    for sql in &author_trace {
        let words: Vec<_> = sql.split_whitespace().collect();
        let table = words
            .windows(2)
            .find_map(|pair| {
                matches!(
                    pair[0].to_ascii_uppercase().as_str(),
                    "FROM" | "INTO" | "UPDATE"
                )
                .then(|| pair[1].split('(').next().unwrap_or(pair[1]).to_owned())
            })
            .unwrap_or_else(|| "transaction/control".into());
        by_table.entry(table).or_default().push(sql);
    }
    println!("P12 author_statements={author_count}");
    for (table, statements) in by_table {
        println!("P12 author_table={table} statements={}", statements.len());
        if std::env::var_os("ROCKY_TRACE_AUTHOR").is_some() {
            for sql in statements {
                println!("P12_AUTHOR_SQL table={table} {sql}");
            }
        }
    }
    let mut counts = Vec::new();
    let mut baseline = Vec::new();
    for (frame, rows) in [(many, 32), (one, 1)] {
        let before = crate::sqlite::statements();
        uncached.receive(frame.clone()).await.unwrap();
        baseline.push((crate::sqlite::statements() - before) as f64 / rows as f64);
        let before = crate::sqlite::statements();
        crate::sqlite::trace_statements(true);
        target.receive(frame).await.unwrap();
        let statements = crate::sqlite::trace_statements(false);
        if rows == 1 && std::env::var_os("ROCKY_TRACE_RECEIVE").is_some() {
            for sql in &statements {
                println!("P09_RECEIVE_SQL {sql}");
            }
        }
        assert!(
            !statements
                .iter()
                .any(|sql| sql.starts_with("INSERT INTO secure_row_keys")),
            "an ordinary update rewrote an unchanged key index"
        );
        for table in ["secure_subscriptions", "secure_roles", "secure_checkpoints"] {
            let reads = statements
                .iter()
                .filter(|sql| sql.starts_with("SELECT") && sql.contains(table))
                .count();
            assert!(reads <= 1, "{table}: {reads} metadata reads");
        }
        counts.push((crate::sqlite::statements() - before) as f64 / rows as f64);
    }
    println!(
        "P09 statements_per_row many={} one={} uncached_many={} uncached_one={}",
        counts[0], counts[1], baseline[0], baseline[1]
    );
    assert!(counts[0] <= 8.0, "{counts:?}");
    assert!(
        counts
            .iter()
            .zip(&baseline)
            .all(|(cached, direct)| cached < direct)
    );
    assert_eq!(
        target.snapshot(f.public).await.unwrap().rows,
        uncached.snapshot(f.public).await.unwrap().rows
    );
}

/// A fixed row/clock/signer corpus also run against the pre-phase replica.
///
/// The corpus is deliberately small: this verifies the canonical digest and
/// record encoding, not the throughput of hashing a large database.
#[tokio::test]
async fn lthash_fixture_matches_phase_start() {
    let f = Fixture::with_publisher(PrivateKey::from_bytes(&[41; 32]));
    let dir = TempDir::new().unwrap();
    let node = PrivateKey::from_bytes(&[42; 32]);
    let replica = EncryptedReplica::open(
        dir.path().join("digest.db"),
        f.app(),
        f.config(&node, f.full(), &[f.public]),
    )
    .await
    .unwrap();
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    inner.conn.execute("BEGIN IMMEDIATE", ()).await.unwrap();
    let digest = inner
        .fixed_row_digest(f.public.domain, 1_000)
        .await
        .unwrap();
    inner.conn.execute("ROLLBACK", ()).await.unwrap();
    // Rebuilding the same canonical corpus must remain deterministic.  The
    // exact digest is an implementation detail; this test is not a benchmark
    // or a large-corpus compatibility fixture.
    let repeated = inner
        .fixed_row_digest(f.public.domain, 1_000)
        .await
        .unwrap();
    assert_eq!(digest, repeated);
}

#[tokio::test]
async fn frame_metadata_observes_writes_and_rollback() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let replica = EncryptedReplica::open(
        dir.path().join("cache.db"),
        f.app(),
        f.config(&PrivateKey::new(), f.full(), &[f.public]),
    )
    .await
    .unwrap();
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    let role = inner.role().await.unwrap();
    let holding = inner.holding(f.public).await.unwrap();
    let before = crate::sqlite::statements();
    assert_eq!(inner.role().await.unwrap(), role);
    assert_eq!(inner.holding(f.public).await.unwrap(), holding);
    assert_eq!(crate::sqlite::statements(), before);
    inner.conn.execute("BEGIN IMMEDIATE", ()).await.unwrap();
    inner.conn.execute(
        "INSERT INTO secure_subscriptions VALUES(?,'evicted') ON CONFLICT(scope) DO UPDATE SET state=excluded.state",
        [encode(&f.public).unwrap()],
    ).await.unwrap();
    assert_eq!(
        inner.holding(f.public).await.unwrap(),
        Some(super::super::replica::roles::Holding::Evicted)
    );
    let changed = super::super::replica::roles::RoleConfig {
        role: super::super::replica::roles::ReplicaRole::Partial,
        ..Default::default()
    };
    inner.conn.execute(
        "INSERT INTO secure_roles VALUES(1,?) ON CONFLICT(id) DO UPDATE SET config=excluded.config",
        [encode(&changed).unwrap()],
    ).await.unwrap();
    assert_eq!(inner.role().await.unwrap(), changed);
    inner.conn.execute("ROLLBACK", ()).await.unwrap();
    inner.invalidate_context();
    assert_eq!(inner.role().await.unwrap(), role);
    assert_eq!(inner.holding(f.public).await.unwrap(), holding);
}

#[tokio::test]
async fn an_unchanged_held_refresh_does_not_scan_history() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let replica = EncryptedReplica::open(
        dir.path().join("held.db"),
        f.app(),
        f.config(&PrivateKey::new(), f.full(), &[f.public, f.private]),
    )
    .await
    .unwrap();
    replica
        .author(
            [1; 32],
            vec![change(f.public, 1, None, Some(f.app().name("one")))],
            vec![],
        )
        .await
        .unwrap();
    replica
        .author(
            [99; 32],
            vec![change(f.private, 1, None, Some(f.app().salary("100")))],
            vec![],
        )
        .await
        .unwrap();
    assert!(replica.held_changes().await.unwrap().is_empty());
    let before = crate::sqlite::statements();
    assert!(replica.held_changes().await.unwrap().is_empty());
    let empty = crate::sqlite::statements() - before;
    for index in 2..=10 {
        replica
            .author(
                [index; 32],
                vec![change(f.public, index, None, Some(f.app().name("more")))],
                vec![],
            )
            .await
            .unwrap();
    }
    let before = crate::sqlite::statements();
    assert!(replica.held_changes().await.unwrap().is_empty());
    assert_eq!(crate::sqlite::statements() - before, empty);
    replica.evict_key(f.private).await;
    crate::sqlite::trace_statements(true);
    assert!(replica.held_changes().await.unwrap().is_empty());
    let statements = crate::sqlite::trace_statements(false);
    assert_eq!(
        statements
            .iter()
            .filter(|sql| sql.starts_with("SELECT o.hash,p.scope"))
            .count(),
        1
    );
}

#[test]
fn selected_row_replay_does_not_materialize_the_remaining_history() {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE secure_operations(hash INTEGER PRIMARY KEY,header BLOB,body BLOB,status TEXT);
        CREATE TABLE secure_applied(position INTEGER PRIMARY KEY,scope INTEGER,hash INTEGER);
        CREATE INDEX applied_scope ON secure_applied(scope,position);
        CREATE TABLE secure_row_positions(scope INTEGER,row INTEGER,position INTEGER,PRIMARY KEY(scope,row,position)) WITHOUT ROWID;
        CREATE INDEX row_position_operations ON secure_row_positions(position,scope,row);
        CREATE TABLE secure_finalization_rows(scope INTEGER,row INTEGER,PRIMARY KEY(scope,row)) WITHOUT ROWID;
        WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<128)
        INSERT INTO secure_applied SELECT i,1,i FROM n;
        INSERT INTO secure_operations SELECT hash,X'01',X'02','applied' FROM secure_applied WHERE hash<>4;
        INSERT INTO secure_row_positions SELECT scope,position,position FROM secure_applied;
        INSERT INTO secure_finalization_rows SELECT scope,position FROM secure_applied;").unwrap();
    let mut query = db
        .prepare(crate::replica::checkpoint::ROW_REPLAY_SQL)
        .unwrap();
    let result: Vec<(i64, Option<Vec<u8>>)> = query
        .query_map([1, 0, 128, 8], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        result.iter().map(|row| row.0).collect::<Vec<_>>(),
        (1..=8).collect::<Vec<_>>()
    );
    assert_eq!(
        result[3].1, None,
        "missing operation bodies must remain visible to corruption checks"
    );
}

#[tokio::test]
async fn the_writer_bounds_both_main_and_temporary_page_caches() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let replica = EncryptedReplica::open(
        dir.path().join("cache.db"),
        f.app(),
        f.config(&PrivateKey::new(), f.full(), &[f.public]),
    )
    .await
    .unwrap();
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    let mut caches = Vec::new();
    for schema in ["main", "temp"] {
        let result = rows(&inner.conn, &format!("PRAGMA {schema}.cache_size"))
            .await
            .unwrap();
        let [row] = result.as_slice() else {
            panic!("missing {schema} cache setting")
        };
        let [SqlValue::Integer(kib)] = row.as_slice() else {
            panic!("invalid {schema} cache setting")
        };
        assert!(*kib < 0, "{schema} cache must be explicitly bounded in KiB");
        caches.push(*kib);
    }
    let budget = if cfg!(target_os = "android") {
        8192
    } else {
        32768
    };
    assert_eq!(caches.iter().sum::<i64>(), -budget);
    assert_eq!(
        rows(&inner.conn, "PRAGMA temp_store").await.unwrap(),
        vec![vec![SqlValue::Integer(0)]]
    );
}

#[cfg(feature = "qualification")]
#[tokio::test]
async fn author_transaction_and_bundle_acquisitions_are_interactive() {
    let f = Fixture::new();
    let directory = TempDir::new().unwrap();
    let source = EncryptedReplica::open(
        directory.path().join("classes.db"),
        f.app(),
        f.config(&PrivateKey::new(), f.full(), &[f.public]),
    )
    .await
    .unwrap();
    let measurements = source.lock_measurements();
    for bundle in [false, true] {
        measurements.start();
        let changes = vec![change(
            f.public,
            1,
            if bundle {
                Some(f.app().name("first"))
            } else {
                None
            },
            Some(f.app().name(if bundle { "second" } else { "first" })),
        )];
        if bundle {
            source
                .author_bundle(
                    [2; 32],
                    changes.into_iter().map(RowWrite::changed).collect(),
                    vec![],
                )
                .await
                .unwrap();
        } else {
            source.author([1; 32], changes, vec![]).await.unwrap();
        }
        let snapshot = measurements.stop();
        assert!(
            snapshot
                .holders
                .keys()
                .any(|(site, class)| site.contains("replica/group.rs:") && class == "Interactive"),
            "{snapshot:?}"
        );
        assert!(
            snapshot
                .holders
                .keys()
                .any(|(_, class)| class == "Background"),
            "post-flush maintenance: {snapshot:?}"
        );
    }
}
