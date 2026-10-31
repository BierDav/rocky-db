//! A checkpoint's identity marks cover exactly the births its state covers.
use super::*;
use crate::KeptSeals;

/// `replica`'s only identity author in `scope` and its live mark.
async fn own_mark(replica: &Replica, scope: ResourceScope) -> (u32, u32) {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    let records = crate::storage::collect_rows(
        inner
            .conn
            .query(
                "SELECT author,sequence FROM secure_identity_marks WHERE scope=?",
                [encode(&scope).unwrap()],
            )
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    let [record] = records.as_slice() else {
        panic!("one identity author: {records:?}");
    };
    let [SqlValue::Integer(author), SqlValue::Integer(sequence)] = record.as_slice() else {
        panic!("{record:?}");
    };
    (
        u32::try_from(*author).unwrap(),
        u32::try_from(*sequence).unwrap(),
    )
}
/// Corrupts the attacker's local allocation evidence so it can sign a reuse.
/// Receivers keep their complete journal and all original refusal assertions.
async fn rewind_mark(replica: &Replica, scope: ResourceScope, sequence: u32) {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    inner
        .conn
        .execute(
            "UPDATE secure_identity_marks SET sequence=? WHERE scope=?",
            crate::storage::bindings(vec![
                SqlValue::Integer(sequence.into()),
                SqlValue::Blob(encode(&scope).unwrap()),
            ]),
        )
        .await
        .unwrap();
    inner
        .conn
        .execute(
            "UPDATE secure_identity_own SET sequence=? WHERE scope=?",
            crate::storage::bindings(vec![
                SqlValue::Integer(sequence.into()),
                SqlValue::Blob(encode(&scope).unwrap()),
            ]),
        )
        .await
        .unwrap();
    inner
        .conn
        .execute(
            "DELETE FROM secure_identity_ledger WHERE scope=?",
            [encode(&scope).unwrap()],
        )
        .await
        .unwrap();
}
/// Why `replica` dropped the transaction of `hash`, if it did.
async fn dropped(replica: &Replica, hash: Hash) -> Option<String> {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    match crate::storage::collect_rows(
        inner
            .conn
            .query(
                "SELECT dropped FROM secure_replayed WHERE hash=?",
                [hash.as_bytes().to_vec()],
            )
            .await
            .unwrap(),
    )
    .await
    .unwrap()
    .first()
    .map(Vec::as_slice)
    {
        Some([SqlValue::Text(reason)]) => Some(reason.clone()),
        _ => None,
    }
}
/// `server` holds `writer`'s frames, finalizes and compacts the seal the
/// writer signs; the writer itself never finalizes.
async fn compacted_seal(
    lineage: &Lineage,
    writer: &Replica,
    server: &Replica,
    key: &PrivateKey,
) -> Commitment {
    sync(lineage, writer, server, key).await;
    server
        .follow_bookmark(lineage.domain, "main")
        .await
        .unwrap();
    let sealed = seal(lineage, writer).await.id().unwrap();
    crate::tests::exchange_graphs(writer, server, lineage.domain).await;
    assert_eq!(
        server.compact(lineage.domain, 0).await.unwrap().compacted,
        Some(sealed)
    );
    sealed
}
/// The forger seals and compacts its own frames, so the rows they retired
/// are gone from its state too.
async fn compact_own(lineage: &Lineage, forger: &Replica) -> Commitment {
    let sealed = seal(lineage, forger).await.id().unwrap();
    assert_eq!(
        forger.compact(lineage.domain, 0).await.unwrap().compacted,
        Some(sealed)
    );
    sealed
}
/// `target`, following `main`, imports `server`'s bases of every table.
async fn import_all(
    lineage: &Lineage,
    server: &Replica,
    target: &Replica,
    key: &PrivateKey,
) -> (crate::SignedCheckpoint, crate::RebootstrapReport) {
    crate::tests::exchange_graphs(server, target, lineage.domain).await;
    target
        .follow_bookmark(lineage.domain, "main")
        .await
        .unwrap();
    import_checkpoint(lineage, server, target, key, lineage.scope("tags")).await;
    let credentials = lineage.credentials(3, key);
    server
        .admit_peer(key.public_key(), &credentials, target.followed_tip().await)
        .await
        .unwrap();
    let offered = server
        .checkpoint_offer(key.public_key(), &credentials, lineage.scope("items"))
        .await
        .unwrap()
        .unwrap();
    let report =
        import_checkpoint_report(lineage, server, target, key, lineage.scope("items")).await;
    (offered, report)
}
fn marks(signed: &crate::SignedCheckpoint) -> Vec<(u32, u32)> {
    signed
        .statement
        .identities
        .iter()
        .map(|mark| (mark.author, mark.sequence))
        .collect()
}

#[tokio::test]
async fn a_reused_identity_beyond_the_seal_applies_once() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new(), PrivateKey::new()];
    let scope = lineage.scope("items");
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    let s = open(&lineage, &dir, "s", &keys[1]).await;
    follow_main(&lineage, &a).await;
    insert(&a, "x", "covered").await;
    compacted_seal(&lineage, &a, &s, &keys[1]).await;
    let (author, covered) = own_mark(&a, scope).await;

    // Beyond the seal y takes the next identity. The forger then drops y's
    // tombstone at its own seal and rewinds its allocator: z is a second
    // birth of y's identity.
    insert(&a, "y", "first").await;
    let y = last_operation(&a, scope).await;
    delete(&a, "y").await;
    compact_own(&lineage, &a).await;
    rewind_mark(&a, scope, covered).await;
    insert(&a, "z", "reused").await;
    let z = last_operation(&a, scope).await;
    assert_eq!(own_mark(&a, scope).await, (author, covered + 1));

    // J holds every frame, then imports the first seal's base: y beyond it
    // reapplies and z's transaction drops.
    let j = open(&lineage, &dir, "j", &keys[2]).await;
    crate::tests::exchange_graphs(&a, &j, lineage.domain).await;
    sync(&lineage, &a, &j, &keys[2]).await;
    let (offered, report) = import_all(&lineage, &s, &j, &keys[2]).await;
    assert_eq!(marks(&offered), vec![(author, covered)]);
    assert!(report.reapplied.contains(&y), "{report:?}");
    assert_eq!(dropped(&j, z).await.as_deref(), Some("admission"));
    assert_eq!(titles(&j).await, vec![vec![text("x"), text("covered")]]);
    assert_eq!(own_mark(&j, scope).await, (author, covered + 1));
}

#[tokio::test]
async fn a_retired_covered_birth_cannot_be_reused_after_an_import() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new(), PrivateKey::new()];
    let scope = lineage.scope("items");
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    let s = open(&lineage, &dir, "s", &keys[1]).await;
    follow_main(&lineage, &a).await;
    insert(&a, "x", "kept").await;
    let (author, kept) = own_mark(&a, scope).await;
    insert(&a, "r", "retired").await;
    delete(&a, "r").await;
    compacted_seal(&lineage, &a, &s, &keys[1]).await;
    let j = open(&lineage, &dir, "j", &keys[2]).await;
    let (offered, _) = import_all(&lineage, &s, &j, &keys[2]).await;
    // The deleted row's birth is covered, so the mark reaches past it.
    let retired = kept + 1;
    assert_eq!(marks(&offered), vec![(author, retired)]);
    assert_eq!(offered.statement.rows.count, 1);
    assert_eq!(own_mark(&j, scope).await, (author, retired));

    // The forger drops r's tombstone and signs a second birth of r's identity.
    compact_own(&lineage, &a).await;
    rewind_mark(&a, scope, kept).await;
    insert(&a, "r2", "reused").await;
    let reused = last_operation(&a, scope).await;
    sync(&lineage, &a, &j, &keys[2]).await;
    // The importer's covered mark refuses the reused identity, exactly as a
    // device that applied the retired birth itself would.
    assert_eq!(dropped(&j, reused).await.as_deref(), Some("admission"));
    assert_eq!(own_mark(&j, scope).await, (author, retired));
    assert_eq!(titles(&j).await, vec![vec![text("x"), text("kept")]]);
}

/// `target` imports `source`'s kept checkpoint of `scope` at `sealed`.
async fn import_kept(
    lineage: &Lineage,
    source: &Replica,
    target: &Replica,
    key: &PrivateKey,
    scope: ResourceScope,
    sealed: Commitment,
) -> (crate::SignedCheckpoint, crate::RebootstrapReport) {
    let credentials = lineage.credentials(3, key);
    source
        .admit_peer(key.public_key(), &credentials, target.followed_tip().await)
        .await
        .unwrap();
    let offered = source
        .seal_checkpoint_offer(key.public_key(), &credentials, scope, sealed)
        .await
        .unwrap()
        .expect("a kept checkpoint");
    assert_eq!(offered.statement.seal, Some(sealed));
    let checkpoint = offered.id().unwrap();
    target.begin_rebootstrap(offered.clone()).await.unwrap();
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
    (offered, report)
}

#[tokio::test]
async fn a_kept_checkpoint_signs_the_covered_marks_and_later_births_apply_on_top() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new()];
    let scope = lineage.scope("items");
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    follow_main(&lineage, &a).await;
    a.keep_seals(KeptSeals {
        every: true,
        ..KeptSeals::default()
    })
    .await
    .unwrap();
    insert(&a, "x", "kept").await;
    let (author, covered) = own_mark(&a, scope).await;
    let sealed = seal(&lineage, &a).await.id().unwrap();
    // Births after the seal raise the live mark, not the kept seal's.
    insert(&a, "y", "later").await;
    a.flush().await.unwrap();
    assert!(a.maintain().await);
    assert_eq!(own_mark(&a, scope).await, (author, covered + 1));
    let b = open(&lineage, &dir, "b", &keys[1]).await;
    crate::tests::exchange_graphs(&a, &b, lineage.domain).await;
    b.follow_bookmark(lineage.domain, "main").await.unwrap();
    import_kept(&lineage, &a, &b, &keys[1], lineage.scope("tags"), sealed).await;
    let (offered, report) = import_kept(&lineage, &a, &b, &keys[1], scope, sealed).await;
    assert_eq!(marks(&offered), vec![(author, covered)]);
    assert!(report.rejected.is_empty(), "{report:?}");
    // The importer takes it as its base and applies y beyond it.
    sync(&lineage, &a, &b, &keys[1]).await;
    assert_eq!(titles(&b).await, titles(&a).await);
    assert_eq!(titles(&b).await.len(), 2);
    assert_eq!(own_mark(&b, scope).await, (author, covered + 1));
}

/// Rows of items with their identity, by key.
async fn identified(replica: &Replica) -> Vec<Vec<SqlValue>> {
    super::super::generations::select(replica, "SELECT key,id,title FROM items ORDER BY key").await
}
/// Commits `statements` in one transaction of `replica`; an insert takes
/// `id` when given, else the next identity.
async fn transaction(replica: &Replica, statements: &[(&str, Option<i64>)]) -> Result<(), Error> {
    let sql = session(replica).await;
    sql.run("BEGIN", vec![]).await?;
    for (statement, id) in statements {
        match id {
            Some(id) => {
                sql.run(&statement.replace("?id", &id.to_string()), vec![])
                    .await?;
            }
            None if statement.contains("?id") => {
                let id = sql.next_id("items").await?.integer();
                sql.run(&statement.replace("?id", &id.to_string()), vec![])
                    .await?;
            }
            None => {
                sql.run(statement, vec![]).await?;
            }
        }
    }
    sql.run("COMMIT", vec![]).await.map(|_| ())
}

#[tokio::test]
async fn births_of_one_frame_compare_with_the_marks_it_entered_with() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new()];
    let scope = lineage.scope("items");
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    let s = open(&lineage, &dir, "s", &keys[1]).await;
    follow_main(&lineage, &a).await;
    insert(&a, "x", "first").await;
    // Two births in descending sequence order in one frame both stand.
    let (higher, lower) = {
        let sql = session(&a).await;
        sql.run("BEGIN", vec![]).await.unwrap();
        let lower = sql.next_id("items").await.unwrap().integer();
        let higher = sql.next_id("items").await.unwrap().integer();
        sql.run("ROLLBACK", vec![]).await.unwrap();
        (higher, lower)
    };
    transaction(
        &a,
        &[
            (
                "INSERT INTO items(key,title,id) VALUES('h','higher',?id)",
                Some(higher),
            ),
            (
                "INSERT INTO items(key,title,id) VALUES('l','lower',?id)",
                Some(lower),
            ),
        ],
    )
    .await
    .unwrap();
    // A duplicate identity in one frame stays refused.
    let duplicate = transaction(
        &a,
        &[
            (
                "INSERT INTO items(key,title,id) VALUES('d1','one',?id)",
                None,
            ),
            (
                "INSERT INTO items(key,title,id) VALUES('d2','two',?id)",
                Some(higher),
            ),
        ],
    )
    .await;
    assert!(duplicate.is_err());
    sync(&lineage, &a, &s, &keys[1]).await;
    s.follow_bookmark(lineage.domain, "main").await.unwrap();
    let expected = identified(&a).await;
    assert_eq!(expected.len(), 3);
    assert_eq!(identified(&s).await, expected);
    // Finalizing and compacting replays the frame through the ledger.
    seal(&lineage, &a).await;
    crate::tests::exchange_graphs(&a, &s, lineage.domain).await;
    assert!(
        s.compact(lineage.domain, 0)
            .await
            .unwrap()
            .compacted
            .is_some()
    );
    s.rebuild_projection(scope).await.unwrap();
    assert_eq!(identified(&s).await, expected);
    s.audit(scope).await.unwrap();
}

#[tokio::test]
async fn a_signed_empty_base_carries_its_retired_marks() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new(), PrivateKey::new()];
    let scope = lineage.scope("items");
    let a = open(&lineage, &dir, "a", &keys[0]).await;
    let s = open(&lineage, &dir, "s", &keys[1]).await;
    follow_main(&lineage, &a).await;
    insert(&a, "r", "retired").await;
    let (author, retired) = own_mark(&a, scope).await;
    delete(&a, "r").await;
    compacted_seal(&lineage, &a, &s, &keys[1]).await;
    let j = open(&lineage, &dir, "j", &keys[2]).await;
    let (offered, _) = import_all(&lineage, &s, &j, &keys[2]).await;
    assert_eq!(offered.statement.rows.count, 0);
    assert_eq!(marks(&offered), vec![(author, retired)]);
    compact_own(&lineage, &a).await;
    rewind_mark(&a, scope, retired - 1).await;
    insert(&a, "r2", "reused").await;
    let reused = last_operation(&a, scope).await;
    sync(&lineage, &a, &j, &keys[2]).await;
    assert_eq!(dropped(&j, reused).await.as_deref(), Some("admission"));
    j.rebuild_projection(scope).await.unwrap();
    assert!(titles(&j).await.is_empty());
    j.audit(scope).await.unwrap();
}

#[tokio::test]
async fn a_kept_prefix_seed_counts_retired_births_and_is_unavailable_once_pruned() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::new();
    let scope = lineage.scope("items");
    let a = open(&lineage, &dir, "a", &key).await;
    follow_main(&lineage, &a).await;
    a.keep_seals(KeptSeals {
        every: true,
        ..KeptSeals::default()
    })
    .await
    .unwrap();
    insert(&a, "x", "kept").await;
    insert(&a, "y", "retired").await;
    let (author, retired) = own_mark(&a, scope).await;
    delete(&a, "y").await;
    let sealed = seal(&lineage, &a).await.id().unwrap();
    a.finalize_path(lineage.domain).await.unwrap();
    insert(&a, "w", "later").await;
    // Through the kept bound: y's retired birth, not w's later one.
    assert_eq!(
        a.kept_prefix_marks(scope, sealed).await,
        Some(vec![(author, retired)])
    );
    // Once the prefix is pruned without a base at or before the bound,
    // the seed is unavailable rather than empty.
    {
        let inner = a.inner.lock(crate::replica::Class::Background).await;
        inner
            .conn
            .execute(
                "DELETE FROM secure_operations WHERE hash=(SELECT a.hash FROM secure_applied a JOIN secure_scope_state s ON s.id=a.scope WHERE s.scope=? ORDER BY a.position LIMIT 1)",
                [encode(&scope).unwrap()],
            )
            .await
            .unwrap();
    }
    assert_eq!(a.kept_prefix_marks(scope, sealed).await, None);
}
