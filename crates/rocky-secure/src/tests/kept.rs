//! Kept seals: history tables keep what a seal's rows were, read through
//! views shaped like the live tables.
use super::compaction::{Replica, delete, follow_main, insert, open, scalar, seal, sync, titles};
use super::generations::{Lineage, session, text};
use super::*;
use crate::KeptSeals;
use rocky_core::{Commitment, SqlValue};

/// The rows `sql` reads through a session bound to `seal`.
pub(super) async fn at_seal(replica: &Replica, seal: Commitment, sql: &str) -> Vec<Vec<SqlValue>> {
    let mut bound = session(replica).await;
    bound.bind_seal(seal).await.unwrap();
    let mut cursor = bound
        .cursor(sql, vec![], crate::cursor::CursorLimits::default())
        .await
        .unwrap();
    let mut rows = Vec::new();
    loop {
        let page = cursor.next().await.unwrap();
        rows.extend(page.rows);
        if page.done {
            return rows;
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
fn rows(pairs: &[(&str, &str)]) -> Vec<Vec<SqlValue>> {
    pairs
        .iter()
        .map(|(key, title)| vec![text(key), text(title)])
        .collect()
}
const TITLES: &str = "SELECT key,title FROM items ORDER BY key";

mod admission;

/// Inserts items `000000` up to `rows`, a transaction per 200.
async fn numbered_items(replica: &Replica, rows: i64) {
    let sql = session(replica).await;
    for chunk in (0..rows).collect::<Vec<_>>().chunks(200) {
        sql.run("BEGIN", vec![]).await.unwrap();
        for i in chunk {
            let id = sql.next_id("items").await.unwrap().integer();
            sql.run(
                "INSERT INTO items(key,title,id) VALUES(printf('%06d',?1),printf('item number %06d',?1),?2)",
                vec![SqlValue::Integer(*i), SqlValue::Integer(id)],
            )
            .await
            .unwrap();
        }
        sql.run("COMMIT", vec![]).await.unwrap();
    }
}

#[tokio::test]
async fn kept_seals_show_their_rows_while_the_live_tables_move_on() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let replica = open(&lineage, &dir, "alice", &key).await;
    follow_main(&lineage, &replica).await;
    replica
        .keep_seals(KeptSeals {
            every: true,
            ..KeptSeals::default()
        })
        .await
        .unwrap();
    for (key, title) in [("a", "one"), ("b", "two"), ("c", "three")] {
        insert(&replica, key, title).await;
    }
    let first = seal(&lineage, &replica).await.id().unwrap();
    replica.compact(lineage.domain, 100).await.unwrap();
    update(&replica, "a", "one again").await;
    delete(&replica, "b").await;
    insert(&replica, "d", "four").await;
    let second = seal(&lineage, &replica).await.id().unwrap();
    replica.compact(lineage.domain, 100).await.unwrap();
    update(&replica, "a", "one more").await;
    insert(&replica, "e", "five").await;
    delete(&replica, "c").await;
    insert(&replica, "b", "two again").await;

    assert_eq!(replica.kept_seals().await.unwrap(), vec![first, second]);
    assert_eq!(
        at_seal(&replica, first, TITLES).await,
        rows(&[("a", "one"), ("b", "two"), ("c", "three")])
    );
    assert_eq!(
        at_seal(&replica, second, TITLES).await,
        rows(&[("a", "one again"), ("c", "three"), ("d", "four")])
    );
    assert_eq!(
        titles(&replica).await,
        rows(&[
            ("a", "one more"),
            ("b", "two again"),
            ("d", "four"),
            ("e", "five")
        ])
    );
    // Only versions a kept seal needs are stored: a's first two, b's
    // first and its absence at the second seal, c's, and d's absence at
    // the first seal; e was absent at both and is recorded once.
    assert_eq!(
        scalar(&replica, "SELECT count(*) FROM secure_history_items").await,
        7
    );

    // Keeping only the latest releases the first seal and what only it
    // needed.
    replica
        .keep_seals(KeptSeals {
            latest: 1,
            ..KeptSeals::default()
        })
        .await
        .unwrap();
    assert_eq!(replica.kept_seals().await.unwrap(), vec![second]);
    assert_eq!(
        at_seal(&replica, second, TITLES).await,
        rows(&[("a", "one again"), ("c", "three"), ("d", "four")])
    );
    assert!(replica.seal_views(first).await.is_err());
    // An unbound session names history explicitly, by seal or bookmark.
    let hex: String = second.iter().map(|byte| format!("{byte:02x}")).collect();
    for name in [format!("items@{hex}"), "items@main".into()] {
        let mut cursor = session(&replica)
            .await
            .cursor(
                &format!("SELECT key,title FROM \"{name}\" ORDER BY key"),
                vec![],
                crate::cursor::CursorLimits::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            cursor.next().await.unwrap().rows,
            rows(&[("a", "one again"), ("c", "three"), ("d", "four")]),
            "{name}"
        );
    }
    // A bound session only reads; its seal's release ends its reads.
    let mut bound = session(&replica).await;
    bound.bind_seal(second).await.unwrap();
    assert!(
        bound
            .run("UPDATE items SET title='x'", vec![])
            .await
            .is_err()
    );
    replica.keep_seals(KeptSeals::default()).await.unwrap();
    assert!(matches!(
        bound
            .cursor(TITLES, vec![], crate::cursor::CursorLimits::default())
            .await
            .err(),
        Some(Error::Sql(crate::sql::SqlError::Unavailable {
            reason: crate::sql::Unavailable::Released,
            ..
        }))
    ));
    assert_eq!(
        scalar(&replica, "SELECT count(*) FROM secure_history_items").await,
        0
    );
}

#[tokio::test]
async fn a_seal_learned_before_its_frames_is_shallow_until_they_arrive() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new()];
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    let b = open(&lineage, &dir, "b", &keys[1]).await;
    follow_main(&lineage, &a).await;
    insert(&a, "a", "one").await;
    sync(&lineage, &a, &b, &keys[1]).await;
    b.follow_bookmark(lineage.domain, "main").await.unwrap();
    b.keep_seals(KeptSeals {
        every: true,
        ..KeptSeals::default()
    })
    .await
    .unwrap();
    update(&a, "a", "sealed").await;
    insert(&a, "b", "two").await;
    let sealed = seal(&lineage, &a).await.id().unwrap();
    // B learns the seal without its frames: it is shallow there.
    b.receive_tip_statements(&a.tip_statements(None, 32).await.unwrap())
        .await
        .unwrap();
    b.finalize_path(lineage.domain).await.unwrap();
    assert_eq!(b.held_seal(lineage.domain, sealed).await.unwrap(), None);
    assert!(b.kept_seals().await.unwrap().is_empty());
    assert!(
        b.compaction_status(lineage.domain)
            .await
            .unwrap()
            .waiting
            .is_some()
    );
    // A writes on after the seal; once B holds the frames, it keeps the
    // seal's state, not the later write.
    update(&a, "b", "after the seal").await;
    sync(&lineage, &a, &b, &keys[1]).await;
    b.finalize_path(lineage.domain).await.unwrap();
    assert_eq!(
        b.held_seal(lineage.domain, sealed).await.unwrap(),
        Some(crate::HeldSeal::Kept)
    );
    assert_eq!(
        at_seal(&b, sealed, TITLES).await,
        rows(&[("a", "sealed"), ("b", "two")])
    );
    assert_eq!(
        titles(&b).await,
        rows(&[("a", "sealed"), ("b", "after the seal")])
    );
}

/// Bytes `table` and its indexes store, from the engine's page statistics.
async fn stored_bytes(replica: &Replica, table: &str) -> i64 {
    scalar(
        replica,
        &format!(
            "SELECT SUM(d.payload) FROM dbstat AS d JOIN sqlite_schema AS s ON s.name=d.name WHERE s.tbl_name='{table}'"
        ),
    )
    .await
}

#[tokio::test]
async fn five_kept_seals_of_one_percent_changes_add_about_five_percent() {
    const ROWS: i64 = 500;
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let replica = open(&lineage, &dir, "alice", &key).await;
    follow_main(&lineage, &replica).await;
    replica
        .keep_seals(KeptSeals {
            latest: 5,
            ..KeptSeals::default()
        })
        .await
        .unwrap();
    numbered_items(&replica, ROWS).await;
    let mut kept = Vec::new();
    for round in 0..6i64 {
        kept.push(seal(&lineage, &replica).await.id().unwrap());
        replica.finalize_path(lineage.domain).await.unwrap();
        // One percent of the rows change before the next seal.
        session(&replica).await.run(
            "UPDATE items SET title=printf('edit %d of %s',?,key) WHERE CAST(key AS INTEGER)%100=?",
            vec![SqlValue::Integer(round), SqlValue::Integer(round)],
        )
        .await
        .unwrap();
    }
    assert_eq!(replica.kept_seals().await.unwrap(), kept[1..].to_vec());
    let history = scalar(&replica, "SELECT count(*) FROM secure_history_items").await;
    assert_eq!(history, 25);
    let (live, added) = (
        stored_bytes(&replica, "items").await,
        stored_bytes(&replica, "secure_history_items").await,
    );
    let percent = added as f64 * 100.0 / live as f64;
    eprintln!("live {live} B, history {added} B: {percent:.2}%");
    assert!((4.0..=7.0).contains(&percent), "{percent:.2}%");
    // The oldest kept seal still shows its rows.
    assert_eq!(
        at_seal(
            &replica,
            kept[1],
            "SELECT count(*) FROM items WHERE title LIKE 'edit 0 of%'"
        )
        .await,
        vec![vec![SqlValue::Integer(5)]]
    );
}

#[tokio::test]
async fn a_seal_before_a_removal_still_shows_the_removed_field_and_table() {
    use super::generations::identity_insert;
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    // Generation 3 has items(key,title,note,rank) and tags; 4 removes both
    // `note` and `tags`.
    let replica = lineage
        .open(
            &dir.path().join("alice.db"),
            &key,
            3,
            Some(lineage.projection(3)),
        )
        .await
        .unwrap();
    follow_main(&lineage, &replica).await;
    replica
        .keep_seals(KeptSeals {
            every: true,
            ..KeptSeals::default()
        })
        .await
        .unwrap();
    for sql in [
        "INSERT INTO items VALUES('0001','one','noted',NULL)",
        "INSERT INTO items VALUES('0002','two',NULL,2)",
        "INSERT INTO tags VALUES('t','label')",
    ] {
        identity_insert(&session(&replica).await, sql, vec![])
            .await
            .unwrap();
    }
    let sealed = seal(&lineage, &replica).await.id().unwrap();
    replica.finalize_path(lineage.domain).await.unwrap();
    session(&replica)
        .await
        .run("UPDATE items SET note='changed' WHERE key='0001'", vec![])
        .await
        .unwrap();
    // An additive change keeps history: the seal shows its own columns.
    let before = at_seal(&replica, sealed, "SELECT * FROM items ORDER BY key").await;
    assert_eq!(
        before[0][..4],
        [text("0001"), text("one"), text("noted"), SqlValue::Null]
    );

    assert!(
        lineage
            .advance(&replica, lineage.config(4, &key), 4)
            .await
            .unwrap()
    );
    assert!(
        session(&replica)
            .await
            .run("SELECT note FROM items", vec![])
            .await
            .is_err()
    );
    // The seal before the removal still shows the field and the table,
    // from frozen copies of only the affected tables.
    assert_eq!(
        at_seal(&replica, sealed, "SELECT * FROM items ORDER BY key").await,
        before
    );
    assert_eq!(
        at_seal(&replica, sealed, "SELECT key,label FROM tags").await,
        vec![vec![text("t"), text("label")]]
    );
    assert_eq!(
        scalar(
            &replica,
            "SELECT count(*) FROM sqlite_schema WHERE name LIKE 'secure_frozen_%'"
        )
        .await,
        2
    );
    // Releasing the seal drops its frozen copies.
    replica.keep_seals(KeptSeals::default()).await.unwrap();
    assert_eq!(
        scalar(
            &replica,
            "SELECT count(*) FROM sqlite_schema WHERE name LIKE 'secure_frozen_%'"
        )
        .await,
        0
    );
}

/// Pulls `source`'s checkpoint of items, which must sit at `seal`, into
/// `target` as held state.
async fn pull_seal(
    lineage: &Lineage,
    source: &Replica,
    target: &Replica,
    key: &PrivateKey,
    seal: Commitment,
) {
    for scope in target.seal_pull_scopes(lineage.domain, seal).await.unwrap() {
        let credentials = lineage.credentials(3, key);
        source
            .admit_peer(key.public_key(), &credentials, target.followed_tip().await)
            .await
            .unwrap();
        let offered = source
            .checkpoint_offer(key.public_key(), &credentials, scope)
            .await
            .unwrap()
            .expect("a checkpoint");
        assert_eq!(offered.statement.seal, Some(seal));
        if scope == lineage.scope("tags") {
            super::compaction::assert_empty_checkpoint(&offered, seal);
        }
        let checkpoint = offered.id().unwrap();
        target.begin_seal_pull(offered).await.unwrap();
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
        assert_eq!(target.finish_seal_pull(scope).await.unwrap(), seal);
    }
}

#[tokio::test]
async fn a_node_holds_a_seal_it_compacted_past_once_it_pulls_it_from_a_node_that_keeps_it() {
    use crate::TipStatement;
    use rocky_credentials::{
        BOOKMARK_MOVE_FORMAT, BookmarkMoveStatement, SignedBookmarkMove, SignedTipOpening,
        TIP_OPENING_FORMAT, TipOpeningStatement,
    };
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new()];
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    let b = open(&lineage, &dir, "b", &keys[1]).await;
    follow_main(&lineage, &a).await;
    a.keep_seals(KeptSeals {
        every: true,
        ..KeptSeals::default()
    })
    .await
    .unwrap();
    insert(&a, "a", "one").await;
    sync(&lineage, &a, &b, &keys[1]).await;
    b.follow_bookmark(lineage.domain, "main").await.unwrap();
    let first = seal(&lineage, &a).await.id().unwrap();
    update(&a, "a", "after the first seal").await;
    insert(&a, "b", "two").await;
    let second = seal(&lineage, &a).await.id().unwrap();
    sync(&lineage, &a, &b, &keys[1]).await;
    // A acknowledges custody before B releases bytes.
    b.admit_peer(
        keys[0].public_key(),
        &lineage.credentials(3, &keys[0]),
        a.followed_tip().await,
    )
    .await
    .unwrap();
    b.acknowledge_frontier(
        keys[0].public_key(),
        &lineage.credentials(3, &keys[0]),
        &a.frontier(lineage.scope("items")).await.unwrap(),
    )
    .await
    .unwrap();
    // Pruned history requires the held seal rather than local replay.
    b.set_retention_policy(
        lineage.scope("items"),
        crate::RetentionPolicy {
            required: BTreeSet::from([rocky_credentials::PeerId::of(keys[0].public_key())]),
            behind: BTreeSet::new(),
            copies: 1,
            window: 0,
        },
    )
    .await
    .unwrap();
    // B compacts at the latest seal; A keeps both and never compacts past
    // the oldest, so its replay base sits there.
    let report = b.compact(lineage.domain, 0).await.unwrap();
    assert_eq!(report.compacted, Some(second));
    assert!(report.pruned > 0, "{report:?}");
    assert_eq!(
        a.compact(lineage.domain, 0).await.unwrap().compacted,
        Some(first)
    );
    assert_eq!(b.held_seal(lineage.domain, first).await.unwrap(), None);
    assert_eq!(
        a.held_seal(lineage.domain, first).await.unwrap(),
        Some(crate::HeldSeal::Kept)
    );

    let main_tip = b.followed_tip().await;
    let opening = SignedTipOpening::sign(
        TipOpeningStatement {
            format: TIP_OPENING_FORMAT,
            schema: lineage.definition(3).hash(),
            scope: lineage.domain,
            seal: first,
            minimum_in_sync: 1,
        },
        lineage.publisher(),
    )
    .unwrap();
    let dev = opening.tip().unwrap();
    let bookmark = SignedBookmarkMove::sign(
        BookmarkMoveStatement {
            format: BOOKMARK_MOVE_FORMAT,
            scope: lineage.domain,
            name: "dev".into(),
            from: None,
            to: Some(dev),
        },
        lineage.publisher(),
    )
    .unwrap();
    b.publish_tip_statements(&[
        TipStatement::Opening(opening),
        TipStatement::Bookmark(bookmark),
    ])
    .await
    .unwrap();
    // Following a branch on a seal B does not hold is refused.
    let refused = b.follow_bookmark(lineage.domain, "dev").await.unwrap_err();
    assert!(refused.to_string().contains("does not hold"), "{refused}");
    assert_eq!(b.followed_tip().await, main_tip);

    pull_seal(&lineage, &a, &b, &keys[1], first).await;
    assert_eq!(
        b.held_seal(lineage.domain, first).await.unwrap(),
        Some(crate::HeldSeal::Checkpoint)
    );
    // Its rows did not change; following the branch now starts from the
    // pulled seal's state.
    assert_eq!(
        titles(&b).await,
        rows(&[("a", "after the first seal"), ("b", "two")])
    );
    assert_eq!(scalar(&b, "SELECT count(*) FROM secure_pulled").await, 2);
    assert!(at_seal(&a, first, "SELECT key FROM tags").await.is_empty());
    b.follow_bookmark(lineage.domain, "dev").await.unwrap();
    // The pulled state became the replay base: no rebootstrap waits.
    assert_eq!(scalar(&b, "SELECT count(*) FROM secure_pulled").await, 0);
    assert_eq!(titles(&b).await, rows(&[("a", "one")]));
    let status = b.compaction_status(lineage.domain).await.unwrap();
    assert_eq!(status.rebootstrap, None);
}

/// What a switch must reproduce: scope digests and the table.
async fn workspace_state(replica: &Replica) -> Vec<Vec<Vec<SqlValue>>> {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    let mut state = Vec::new();
    for sql in [
        "SELECT scope,rows,tombstones,digest FROM secure_scope_state ORDER BY scope",
        "SELECT key,title FROM items ORDER BY key",
    ] {
        state.push(crate::storage::rows(&inner.conn, sql).await.unwrap());
    }
    state
}
fn same_state(left: &[Vec<Vec<SqlValue>>], right: &[Vec<Vec<SqlValue>>]) {
    for (index, (left, right)) in left.iter().zip(right).enumerate() {
        let only_left: Vec<_> = left.iter().filter(|row| !right.contains(row)).collect();
        let only_right: Vec<_> = right.iter().filter(|row| !left.contains(row)).collect();
        assert!(
            only_left.is_empty() && only_right.is_empty(),
            "part {index}: {} rows only here, {} only there",
            only_left.len(),
            only_right.len(),
        );
    }
}
/// Rows the engine changed while following `bookmark`.
async fn follow_changing(lineage: &Lineage, replica: &Replica, bookmark: &str) -> u64 {
    let changes = async || {
        let inner = replica.inner.lock(crate::replica::Class::Background).await;
        inner.conn.connection().total_changes().unwrap()
    };
    let before = changes().await;
    replica
        .follow_bookmark(lineage.domain, bookmark)
        .await
        .unwrap();
    changes().await - before
}

#[tokio::test]
async fn switching_to_a_branch_two_seals_back_and_back_costs_the_rows_changed_since() {
    use crate::TipStatement;
    use rocky_credentials::{
        BOOKMARK_MOVE_FORMAT, BookmarkMoveStatement, SignedBookmarkMove, SignedTipOpening,
        TIP_OPENING_FORMAT, TipOpeningStatement,
    };
    const ROWS: i64 = 400;
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let replica = open(&lineage, &dir, "alice", &key).await;
    follow_main(&lineage, &replica).await;
    replica
        .keep_seals(KeptSeals {
            latest: 2,
            ..KeptSeals::default()
        })
        .await
        .unwrap();
    numbered_items(&replica, ROWS).await;
    let first = seal(&lineage, &replica).await.id().unwrap();
    replica.finalize_path(lineage.domain).await.unwrap();
    update(&replica, "000001", "changed after the first seal").await;
    update(&replica, "000002", "changed after the first seal").await;
    delete(&replica, "000003").await;
    insert(&replica, "new", "added after the first seal").await;
    seal(&lineage, &replica).await;
    replica.finalize_path(lineage.domain).await.unwrap();
    update(&replica, "000001", "changed after the second seal").await;
    delete(&replica, "000004").await;
    let main_tip = replica.followed_tip().await;
    let on_main = workspace_state(&replica).await;

    let opening = SignedTipOpening::sign(
        TipOpeningStatement {
            format: TIP_OPENING_FORMAT,
            schema: lineage.definition(3).hash(),
            scope: lineage.domain,
            seal: first,
            minimum_in_sync: 1,
        },
        lineage.publisher(),
    )
    .unwrap();
    let bookmark = SignedBookmarkMove::sign(
        BookmarkMoveStatement {
            format: BOOKMARK_MOVE_FORMAT,
            scope: lineage.domain,
            name: "dev".into(),
            from: None,
            to: Some(opening.tip().unwrap()),
        },
        lineage.publisher(),
    )
    .unwrap();
    replica
        .publish_tip_statements(&[
            TipStatement::Opening(opening),
            TipStatement::Bookmark(bookmark),
        ])
        .await
        .unwrap();
    let to_dev = follow_changing(&lineage, &replica, "dev").await;
    assert_eq!(
        titles(&replica).await,
        at_seal(&replica, first, TITLES).await
    );
    let on_dev = workspace_state(&replica).await;
    let to_main = follow_changing(&lineage, &replica, "main").await;
    assert_eq!(replica.followed_tip().await, main_tip);
    let back = workspace_state(&replica).await;
    assert_eq!(back[1], on_main[1]);

    // A rebuild from the replay base reaches the same states, writing
    // every row.
    replica
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .rebuild_switches = true;
    let rebuilt_dev = follow_changing(&lineage, &replica, "dev").await;
    same_state(&workspace_state(&replica).await, &on_dev);
    let rebuilt_main = follow_changing(&lineage, &replica, "main").await;
    same_state(&workspace_state(&replica).await, &back);
    eprintln!(
        "rows changed: {to_dev} to the branch, {to_main} back; rebuilt {rebuilt_dev} and {rebuilt_main}"
    );
    assert!(rebuilt_dev > 2 * ROWS as u64 && rebuilt_main > 2 * ROWS as u64);
    assert!(to_dev < 64 && to_main < 64, "{to_dev} and {to_main}");
    // Finalizing again the seal the branch did not pass drops what it
    // dropped before.
    replica.finalize_path(lineage.domain).await.unwrap();
    same_state(&workspace_state(&replica).await, &on_main);
}

#[tokio::test]
async fn a_branch_on_a_kept_seal_keeps_its_own_writes_across_switches() {
    branch_writes_across_switches(Lineage::new()).await;
}

async fn branch_writes_across_switches(lineage: Lineage) {
    use crate::{LineNode, TipStatement};
    use rocky_credentials::{
        BOOKMARK_MOVE_FORMAT, BookmarkMoveStatement, SignedBookmarkMove, SignedTipOpening,
        TIP_OPENING_FORMAT, TipOpeningStatement,
    };
    let dir = TempDir::new().unwrap();
    let (identity, node) = (PrivateKey::new(), PrivateKey::new());
    let replica = lineage
        .open_certified(
            &dir.path().join("alice.db"),
            (&identity, &node),
            3,
            Some(lineage.projection(3)),
        )
        .await
        .unwrap();
    follow_main(&lineage, &replica).await;
    replica
        .keep_seals(KeptSeals {
            every: true,
            ..KeptSeals::default()
        })
        .await
        .unwrap();
    for (key, title) in [("a", "one"), ("b", "two"), ("c", "three")] {
        insert(&replica, key, title).await;
    }
    let first = seal(&lineage, &replica).await.id().unwrap();
    replica.finalize_path(lineage.domain).await.unwrap();
    update(&replica, "a", "main after the seal").await;
    insert(&replica, "d", "main only").await;
    let opening = SignedTipOpening::sign(
        TipOpeningStatement {
            format: TIP_OPENING_FORMAT,
            schema: lineage.definition(3).hash(),
            scope: lineage.domain,
            seal: first,
            minimum_in_sync: 1,
        },
        lineage.publisher(),
    )
    .unwrap();
    let bookmark = SignedBookmarkMove::sign(
        BookmarkMoveStatement {
            format: BOOKMARK_MOVE_FORMAT,
            scope: lineage.domain,
            name: "dev".into(),
            from: None,
            to: Some(opening.tip().unwrap()),
        },
        lineage.publisher(),
    )
    .unwrap();
    replica
        .publish_tip_statements(&[
            TipStatement::Opening(opening),
            TipStatement::Bookmark(bookmark),
        ])
        .await
        .unwrap();
    replica
        .follow_bookmark(lineage.domain, "dev")
        .await
        .unwrap();
    let branch_node = PrivateKey::new();
    replica
        .register_line_node(LineNode {
            credentials: lineage.certified(3, &identity, &branch_node),
            key: branch_node,
        })
        .await
        .unwrap();
    update(&replica, "b", "dev").await;
    delete(&replica, "c").await;
    insert(&replica, "e", "dev only").await;
    let dev = rows(&[("a", "one"), ("b", "dev"), ("e", "dev only")]);
    assert_eq!(titles(&replica).await, dev);
    let main = rows(&[
        ("a", "main after the seal"),
        ("b", "two"),
        ("c", "three"),
        ("d", "main only"),
    ]);
    let mut fast = Vec::new();
    for (bookmark, expected) in [("main", &main), ("dev", &dev), ("main", &main)] {
        replica
            .follow_bookmark(lineage.domain, bookmark)
            .await
            .unwrap();
        assert_eq!(&titles(&replica).await, expected, "{bookmark}");
        fast.push(workspace_state(&replica).await);
    }
    replica
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .rebuild_switches = true;
    for (bookmark, fast) in ["dev", "main"].into_iter().zip(&fast[1..]) {
        replica
            .follow_bookmark(lineage.domain, bookmark)
            .await
            .unwrap();
        same_state(&workspace_state(&replica).await, fast);
    }
}

#[tokio::test]
async fn a_node_pulls_a_seal_another_keeps_over_a_session_and_opens_a_branch_on_it() {
    use crate::TipStatement;
    use rocky_credentials::{
        BOOKMARK_MOVE_FORMAT, BookmarkMoveStatement, SignedBookmarkMove, SignedTipOpening,
        TIP_OPENING_FORMAT, TipOpeningStatement,
    };
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new()];
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    let b = open(&lineage, &dir, "b", &keys[1]).await;
    follow_main(&lineage, &a).await;
    a.keep_seals(KeptSeals {
        every: true,
        ..KeptSeals::default()
    })
    .await
    .unwrap();
    insert(&a, "a", "one").await;
    insert(&a, "b", "two").await;
    sync(&lineage, &a, &b, &keys[1]).await;
    b.follow_bookmark(lineage.domain, "main").await.unwrap();
    let first = seal(&lineage, &a).await.id().unwrap();
    update(&a, "a", "after the first seal").await;
    delete(&a, "b").await;
    let second = seal(&lineage, &a).await.id().unwrap();
    a.finalize_path(lineage.domain).await.unwrap();
    sync(&lineage, &a, &b, &keys[1]).await;
    // A keeps both seals and never compacted: it has no replay base, so
    // what it serves of the first comes from its history tables.
    assert_eq!(
        b.compact(lineage.domain, 0).await.unwrap().compacted,
        Some(second)
    );
    assert_eq!(
        b.seal_frontier(lineage.domain, true).await.unwrap(),
        b.seal_frontier(lineage.domain, false).await.unwrap(),
        "pruned history covered by an inherited seal still permits closing"
    );
    assert_eq!(a.kept_seals().await.unwrap(), vec![first, second]);
    assert_eq!(
        scalar(&a, "SELECT count(*) FROM secure_checkpoints").await,
        0
    );
    assert_eq!(b.held_seal(lineage.domain, first).await.unwrap(), None);

    // The provider already follows another branch while serving the retained seal.
    let opening = SignedTipOpening::sign(
        TipOpeningStatement {
            format: TIP_OPENING_FORMAT,
            schema: lineage.definition(3).hash(),
            scope: lineage.domain,
            seal: first,
            minimum_in_sync: 1,
        },
        lineage.publisher(),
    )
    .unwrap();
    let bookmark = SignedBookmarkMove::sign(
        BookmarkMoveStatement {
            format: BOOKMARK_MOVE_FORMAT,
            scope: lineage.domain,
            name: "dev".into(),
            from: None,
            to: Some(opening.tip().unwrap()),
        },
        lineage.publisher(),
    )
    .unwrap();
    a.publish_tip_statements(&[
        TipStatement::Opening(opening),
        TipStatement::Bookmark(bookmark),
    ])
    .await
    .unwrap();
    a.follow_bookmark(lineage.domain, "dev").await.unwrap();
    b.want_seal(lineage.domain, first).await.unwrap();
    assert_eq!(b.wanted_seals(lineage.domain).await.unwrap(), vec![first]);
    let (near, far) = crate::network::link::testing::tcp().await;
    let (session, mut served) = crate::network::link::testing::sessions_over(
        near,
        far,
        (&b, keys[1].clone(), lineage.credentials(3, &keys[1])),
        (&a, keys[0].clone(), lineage.credentials(3, &keys[0])),
    )
    .await
    .unwrap();
    let pull = async {
        let mut session = session;
        session.pull_wanted_seals(&b).await.unwrap()
    };
    let (pulled, ()) = tokio::join!(pull, async { while served.serve_once(&a).await.is_ok() {} });
    assert!(pulled);
    assert_eq!(
        b.held_seal(lineage.domain, first).await.unwrap(),
        Some(crate::HeldSeal::Checkpoint)
    );
    assert!(b.wanted_seals(lineage.domain).await.unwrap().is_empty());
    assert_eq!(scalar(&a, "SELECT count(*) FROM secure_served").await, 2);
    let served = crate::storage::rows(
        &a.inner.lock(crate::replica::Class::Background).await.conn,
        "SELECT s.scope,v.signed FROM secure_served v JOIN secure_scope_state s ON s.id=v.scope",
    )
    .await
    .unwrap();
    assert_eq!(served.len(), 2);
    for name in ["items", "tags"] {
        let record = served
            .iter()
            .find(|record| record[0] == SqlValue::Blob(encode(&lineage.scope(name)).unwrap()))
            .unwrap();
        let SqlValue::Blob(bytes) = &record[1] else {
            panic!("served checkpoint")
        };
        let signed = crate::SignedCheckpoint::from_bytes(bytes).unwrap();
        assert_eq!(signed.statement.scope, lineage.scope(name));
        assert_eq!(signed.statement.seal, Some(first));
        signed.verify_signature().unwrap();
        if name == "tags" {
            super::compaction::assert_empty_checkpoint(&signed, first);
        }
    }

    let opening = SignedTipOpening::sign(
        TipOpeningStatement {
            format: TIP_OPENING_FORMAT,
            schema: lineage.definition(3).hash(),
            scope: lineage.domain,
            seal: first,
            minimum_in_sync: 1,
        },
        lineage.publisher(),
    )
    .unwrap();
    let bookmark = SignedBookmarkMove::sign(
        BookmarkMoveStatement {
            format: BOOKMARK_MOVE_FORMAT,
            scope: lineage.domain,
            name: "dev".into(),
            from: None,
            to: Some(opening.tip().unwrap()),
        },
        lineage.publisher(),
    )
    .unwrap();
    b.publish_tip_statements(&[
        TipStatement::Opening(opening),
        TipStatement::Bookmark(bookmark),
    ])
    .await
    .unwrap();
    b.follow_bookmark(lineage.domain, "dev").await.unwrap();
    assert_eq!(titles(&b).await, rows(&[("a", "one"), ("b", "two")]));
    // Releasing the seal forgets what A served of it.
    a.keep_seals(KeptSeals::default()).await.unwrap();
    assert_eq!(scalar(&a, "SELECT count(*) FROM secure_served").await, 0);
}
