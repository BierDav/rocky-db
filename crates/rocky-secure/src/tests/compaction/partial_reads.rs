//! Reads and writes need only the scopes they touch; finality needs the
//! whole domain. A missing scope is refused, never read as empty.
use super::*;
use crate::MAX_SNAPSHOT_ROWS;

/// `a` holds two items and three tags, sealed and compacted.
async fn source(lineage: &Lineage, dir: &TempDir, key: &PrivateKey) -> Replica {
    let a = open(lineage, dir, "a", key).await;
    follow_main(lineage, &a).await;
    insert(&a, "x", "first").await;
    insert(&a, "y", "second").await;
    // More tags than one page holds, in transactions of at most 256
    // statements.
    let sql = session(&a).await;
    for tag in 0..300 {
        if tag % 150 == 0 {
            if tag > 0 {
                sql.run("COMMIT", vec![]).await.unwrap();
            }
            sql.run("BEGIN", vec![]).await.unwrap();
        }
        identity_insert(
            &sql,
            "INSERT INTO tags(key,label) VALUES(?,?)",
            vec![text(&format!("t{tag:03}")), text("label")],
        )
        .await
        .unwrap();
    }
    sql.run("COMMIT", vec![]).await.unwrap();
    seal(lineage, &a).await;
    assert!(
        a.compact(lineage.domain, 0)
            .await
            .unwrap()
            .compacted
            .is_some()
    );
    a
}
/// A joiner of `a` that imported its items base only.
async fn items_only(lineage: &Lineage, dir: &TempDir, a: &Replica, key: &PrivateKey) -> Replica {
    let j = open(lineage, dir, "j", key).await;
    crate::tests::exchange_graphs(a, &j, lineage.domain).await;
    j.follow_bookmark(lineage.domain, "main").await.unwrap();
    import_checkpoint(lineage, a, &j, key, lineage.scope("items")).await;
    j
}
async fn read(replica: &Replica, sql: &str) -> Result<Vec<Vec<SqlValue>>, Error> {
    session(replica)
        .await
        .run(sql, vec![])
        .await
        .map(|rows| rows.rows)
}
/// Persistent readiness state and the stored and in-memory revisions.
async fn state(replica: &Replica) -> (Vec<Vec<SqlValue>>, (u64, u64)) {
    let rows = crate::storage::rows(
        &replica.inner.lock(crate::replica::Class::Background).await.conn,
        "SELECT (SELECT count(*) FROM secure_scope_state),(SELECT count(*) FROM secure_seal_anchors),(SELECT count(*) FROM secure_rebootstrap),(SELECT count(*) FROM secure_evicted_logs),(SELECT count(*) FROM secure_seal_bounds),(SELECT count(*) FROM secure_checkpoints)",
    )
    .await
    .unwrap();
    (rows, replica.stored_and_memory_revision().await)
}
/// Authoring in the waiting `tags` scope is refused.
async fn author_refused(replica: &Replica) {
    let error = identity_insert(
        &session(replica).await,
        "INSERT INTO tags(key,label) VALUES(?,?)",
        vec![text("w"), text("refused")],
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("seal rebootstrap (replay="),
        "{error}"
    );
}
/// What a joiner with verified items and unverified tags may and may not do.
async fn scoped(lineage: &Lineage, j: &Replica) {
    let before = state(j).await;
    assert_eq!(
        titles(j).await,
        vec![
            vec![text("x"), text("first")],
            vec![text("y"), text("second")]
        ]
    );
    let page = j
        .snapshot_page(lineage.scope("items"), None, MAX_SNAPSHOT_ROWS)
        .await
        .unwrap();
    assert!(page.complete);
    assert_eq!(
        read(j, "SELECT 1").await.unwrap(),
        vec![vec![SqlValue::Integer(1)]]
    );
    for sql in [
        "SELECT key FROM tags",
        "SELECT items.key FROM items LEFT JOIN tags ON tags.key=items.key",
        "SELECT key FROM items WHERE key IN (SELECT key FROM tags)",
    ] {
        assert!(read(j, sql).await.is_err(), "{sql}");
    }
    assert!(
        j.snapshot_page(lineage.scope("tags"), None, MAX_SNAPSHOT_ROWS)
            .await
            .is_err()
    );
    // Reads change nothing.
    assert_eq!(state(j).await, before);
    author_refused(j).await;
    let status = j.compaction_status(lineage.domain).await.unwrap();
    assert!(status.finalized.is_none() && status.waiting.is_some());
}

#[tokio::test]
async fn a_verified_scope_reads_and_writes_while_an_unbegun_one_waits() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new()];
    let a = source(&lineage, &dir, &keys[0]).await;
    let j = items_only(&lineage, &dir, &a, &keys[1]).await;
    scoped(&lineage, &j).await;
    // The same after a reopen without any network.
    drop(j);
    let j = open(&lineage, &dir, "j", &keys[1]).await;
    scoped(&lineage, &j).await;
    insert(&j, "z", "authored while tags waits").await;
    assert_eq!(titles(&j).await.len(), 3);
}

/// A direct import in progress: its verified pages show, incomplete.
async fn partial(a: &Replica, j: &Replica) {
    let shown = read(j, "SELECT key FROM tags").await.unwrap().len();
    assert!(shown >= 1);
    assert!(shown < read(a, "SELECT key FROM tags").await.unwrap().len());
    author_refused(j).await;
}

#[tokio::test]
async fn a_direct_import_shows_its_verified_pages_incomplete_until_it_finishes() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new()];
    let a = source(&lineage, &dir, &keys[0]).await;
    let j = items_only(&lineage, &dir, &a, &keys[1]).await;
    let tags = lineage.scope("tags");
    let credentials = lineage.credentials(3, &keys[1]);
    a.admit_peer(keys[1].public_key(), &credentials, j.followed_tip().await)
        .await
        .unwrap();
    let offered = a
        .checkpoint_offer(keys[1].public_key(), &credentials, tags)
        .await
        .unwrap()
        .unwrap();
    let checkpoint = offered.id().unwrap();
    j.begin_rebootstrap(offered).await.unwrap();
    // A page holds at most 256 rows.
    let first = a
        .checkpoint_page(
            keys[1].public_key(),
            &credentials,
            tags,
            checkpoint,
            None,
            64 * 1024,
        )
        .await
        .unwrap();
    assert!(first.next.is_some());
    let next = first.next;
    j.stage_checkpoint_page(first).await.unwrap();
    partial(&a, &j).await;
    drop(j);
    let j = open(&lineage, &dir, "j", &keys[1]).await;
    partial(&a, &j).await;
    let mut after = next;
    while let Some(cursor) = after {
        let page = a
            .checkpoint_page(
                keys[1].public_key(),
                &credentials,
                tags,
                checkpoint,
                Some(cursor),
                64 * 1024,
            )
            .await
            .unwrap();
        after = page.next;
        j.stage_checkpoint_page(page).await.unwrap();
    }
    j.finish_rebootstrap(tags).await.unwrap();
    assert!(
        j.snapshot_page(tags, None, MAX_SNAPSHOT_ROWS)
            .await
            .unwrap()
            .complete
    );
    assert_eq!(read(&j, "SELECT key FROM tags").await.unwrap().len(), 300);
    insert(&j, "w", "authored once whole").await;
}

#[tokio::test]
async fn an_unauthenticated_staged_statement_proves_nothing_for_its_scope() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new()];
    let a = source(&lineage, &dir, &keys[0]).await;
    let j = items_only(&lineage, &dir, &a, &keys[1]).await;
    let tags = lineage.scope("tags");
    let credentials = lineage.credentials(3, &keys[1]);
    a.admit_peer(keys[1].public_key(), &credentials, j.followed_tip().await)
        .await
        .unwrap();
    let offered = a
        .checkpoint_offer(keys[1].public_key(), &credentials, tags)
        .await
        .unwrap()
        .unwrap();
    j.begin_rebootstrap(offered.clone()).await.unwrap();
    for tamper in [
        (|s: &mut crate::CheckpointStatement| s.sequence += 1) as fn(&mut _),
        |s| s.seal = Some([7; 32]),
        |s| s.schema += 1,
    ] {
        let mut forged = offered.clone();
        tamper(&mut forged.statement);
        j.inner
            .lock(crate::replica::Class::Background)
            .await
            .conn
            .execute(
                "UPDATE secure_rebootstrap SET signed=?",
                [forged.to_bytes().unwrap()],
            )
            .await
            .unwrap();
        assert!(read(&j, "SELECT key FROM tags").await.is_err());
        assert!(
            j.snapshot_page(tags, None, MAX_SNAPSHOT_ROWS)
                .await
                .is_err()
        );
        // The verified items scope stays readable.
        assert_eq!(titles(&j).await.len(), 2);
    }
}
