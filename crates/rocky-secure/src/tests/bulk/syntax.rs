//! Privileged retained-store mutations test fresh reconstruction, never admissible ingress.
use super::*;
use crate::replica::Inner;
use crate::storage::rows;

pub(super) async fn reconstruct(
    inner: &Inner<TypedRows>,
    frame: &EncryptedFrame,
) -> Result<EncryptedFrame, Error> {
    inner
        .stored_frame(frame.header_bytes().to_vec(), frame.body_bytes().to_vec())
        .await
}
pub(super) fn descriptor(frame: &EncryptedFrame) -> &SignedMigrationPublication {
    frame
        .migration
        .as_ref()
        .unwrap()
        .descriptor
        .as_deref()
        .unwrap()
}
pub(super) async fn signed_bytes(inner: &Inner<TypedRows>, bytes: Vec<u8>) {
    inner
        .conn
        .execute("UPDATE secure_migration_publications SET signed=?", [bytes])
        .await
        .unwrap();
}
pub(super) async fn save(inner: &Inner<TypedRows>) {
    inner
        .conn
        .execute("SAVEPOINT syntax_fixture", ())
        .await
        .unwrap();
}
pub(super) async fn restore(inner: &Inner<TypedRows>) {
    inner
        .conn
        .execute("ROLLBACK TO syntax_fixture", ())
        .await
        .unwrap();
    inner
        .conn
        .execute("RELEASE syntax_fixture", ())
        .await
        .unwrap();
}
pub(super) async fn snapshot(inner: &Inner<TypedRows>) -> Vec<(String, Vec<Vec<SqlValue>>)> {
    let mut state = Vec::new();
    for table in rows(&inner.conn, "SELECT name FROM sqlite_schema WHERE type='table' AND name<>'secure_checkpoint_scratch' AND name NOT LIKE 'sqlite_%' ORDER BY name").await.unwrap() {
        let SqlValue::Text(name) = &table[0] else { panic!("table name") };
        let columns = rows(&inner.conn, &format!("PRAGMA table_info(\"{name}\")")).await.unwrap().len();
        let order = (1..=columns).map(|n| n.to_string()).collect::<Vec<_>>().join(",");
        state.push((name.clone(), rows(&inner.conn, &format!("SELECT * FROM \"{name}\" ORDER BY {order}")).await.unwrap()));
    }
    state
}
pub(super) fn same_frame(actual: &EncryptedFrame, expected: &EncryptedFrame) {
    assert_eq!(actual.header_bytes(), expected.header_bytes());
    assert_eq!(actual.body_bytes(), expected.body_bytes());
    assert_eq!(
        actual.chain().unwrap().credentials(),
        expected.chain().unwrap().credentials()
    );
    assert_eq!(
        encode(&actual.migration).unwrap(),
        encode(&expected.migration).unwrap()
    );
}
pub(super) fn same_error(actual: Error, expected: Error) {
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
}

#[tokio::test]
async fn stored_reconstruction_reuses_only_owned_syntax_and_reopens_cold() {
    let (l, dir, key, replica, signed) = candidate(1).await;
    release(&replica, &signed).await;
    let frame = frames(&replica).await.remove(0);
    let storage = replica.migration_storage().await.unwrap();
    {
        let inner = replica.inner.lock(crate::replica::Class::Background).await;
        let before = snapshot(&inner).await;
        inner.migration_syntax_capacity(32768);
        let mut first = reconstruct(&inner, &frame).await.unwrap();
        same_frame(&first, &frame);
        same_frame(&reconstruct(&inner, &frame).await.unwrap(), &frame);
        assert_eq!(
            inner.migration_syntax_stats(),
            (1, 1, 1, signed.to_bytes().unwrap().len())
        );
        first
            .migration
            .as_mut()
            .unwrap()
            .descriptor
            .as_mut()
            .unwrap()
            .statement
            .bytes += 1;
        same_frame(&reconstruct(&inner, &frame).await.unwrap(), &frame);
        assert_eq!(inner.migration_syntax_stats().0, 1);
        assert_eq!(inner.migration_syntax_stats().1, 2);
        println!(
            "actual stored-frame syntax (parses,hits,entries,raw_bytes)={:?}",
            inner.migration_syntax_stats()
        );
        assert_eq!(snapshot(&inner).await, before);
        save(&inner).await;
        inner
            .conn
            .execute("UPDATE secure_migration_publications SET signed=NULL", ())
            .await
            .unwrap();
        let unsigned = reconstruct(&inner, &frame).await.unwrap();
        assert!(unsigned.migration.unwrap().descriptor.is_none());
        inner
            .conn
            .execute("DELETE FROM secure_migration_frames", ())
            .await
            .unwrap();
        assert!(
            reconstruct(&inner, &frame)
                .await
                .unwrap()
                .migration
                .is_none()
        );
        restore(&inner).await;
        same_frame(&reconstruct(&inner, &frame).await.unwrap(), &frame);
        assert_eq!(snapshot(&inner).await, before);
    }
    replica.audit(l.scope("items")).await.unwrap();
    let sql = super::super::generations::session(&replica).await;
    let ordinary = sql
        .run("UPDATE items SET title='ordinary'", vec![])
        .await
        .unwrap()
        .committed
        .unwrap()
        .frames
        .remove(0);
    same_frame(
        &stored_frames(&replica, "SELECT header,body FROM secure_operations")
            .await
            .into_iter()
            .find(|f| f.id().unwrap() == ordinary.id().unwrap())
            .unwrap(),
        &ordinary,
    );
    assert!(ordinary.migration.is_none());
    drop(sql);
    drop(replica);
    let mut config = l.config(3, &key);
    config.manifest = l.config(2, &key).manifest;
    config.credentials = l.certified(3, l.publisher(), &key);
    let replica = EncryptedReplica::open(&dir.path().join("source.db"), l.app(3), config)
        .await
        .unwrap();
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    // Opening replays no row records, so the first reconstruction on the
    // new Inner parses cold and the next one reuses it.
    assert_eq!(inner.migration_syntax_stats(), (0, 0, 0, 0));
    same_frame(&reconstruct(&inner, &frame).await.unwrap(), &frame);
    assert_eq!(
        inner.migration_syntax_stats(),
        (1, 0, 1, signed.to_bytes().unwrap().len())
    );
    same_frame(&reconstruct(&inner, &frame).await.unwrap(), &frame);
    assert_eq!(inner.migration_syntax_stats().0, 1);
    assert_eq!(inner.migration_syntax_stats().1, 1);
    drop(inner);
    assert_eq!(replica.migration_storage().await.unwrap(), storage);
    replica.audit(l.scope("items")).await.unwrap();
}

#[tokio::test]
async fn warm_reconstruction_preserves_sql_shapes_and_first_errors() {
    let (l, _, _, replica, signed) = candidate(1).await;
    release(&replica, &signed).await;
    let frame = frames(&replica).await.remove(0);
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    let before = snapshot(&inner).await;
    for (sql, error) in [
        (
            "UPDATE secure_migration_publications SET conflict=X'00',signed=X'FF'",
            denied("migration publication equivocated"),
        ),
        (
            "UPDATE secure_migration_publications SET signed=7",
            Error::Corrupt("migration descriptor record".into()),
        ),
        (
            "UPDATE secure_migration_frames SET proof=7",
            Error::Corrupt("migration proof record".into()),
        ),
        (
            "UPDATE secure_migration_publications SET signed=NULL; UPDATE secure_migration_frames SET proof=X'FF'",
            denied("invalid secure frame"),
        ),
    ] {
        inner.migration_syntax_capacity(32768);
        reconstruct(&inner, &frame).await.unwrap();
        save(&inner).await;
        for statement in sql.split(';') {
            inner.conn.execute(statement, ()).await.unwrap();
        }
        let warm = reconstruct(&inner, &frame).await.unwrap_err();
        let expected = format!("{error:?}");
        same_error(warm, error);
        inner.migration_syntax_capacity(0);
        let cold = reconstruct(&inner, &frame).await.unwrap_err();
        assert_eq!(format!("{cold:?}"), expected);
        // Repeat unchanged SQL: no shape/NULL/conflict result is memoized.
        same_error(reconstruct(&inner, &frame).await.unwrap_err(), cold);
        restore(&inner).await;
    }
    assert_eq!(snapshot(&inner).await, before);
    drop(inner);
    replica.audit(l.scope("items")).await.unwrap();
}

#[tokio::test]
async fn warm_reconstruction_keeps_parser_validation_and_uncached_errors() {
    let (l, _, _, replica, signed) = candidate(1).await;
    release(&replica, &signed).await;
    let frame = frames(&replica).await.remove(0);
    let mut noncanonical = signed.to_bytes().unwrap();
    assert_eq!(noncanonical.remove(0), 0xa3);
    noncanonical.insert(0, 0xbf);
    noncanonical.push(0xff);
    let mut format = signed.clone();
    format.statement.format += 1;
    let mut extent = signed.clone();
    extent.statement.bytes = 0;
    let cases = [
        vec![0xff],
        noncanonical,
        vec![0; 32769],
        format.to_bytes().unwrap(),
        extent.to_bytes().unwrap(),
    ];
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    let before = snapshot(&inner).await;
    for bytes in cases {
        inner.migration_syntax_capacity(32768);
        reconstruct(&inner, &frame).await.unwrap();
        save(&inner).await;
        signed_bytes(&inner, bytes.clone()).await;
        // Malformed descriptor wins over bad proof, even after a successful warm parse.
        inner
            .conn
            .execute("UPDATE secure_migration_frames SET proof=X'FF'", ())
            .await
            .unwrap();
        for _ in 0..2 {
            same_error(
                reconstruct(&inner, &frame).await.unwrap_err(),
                crate::credential(SignedMigrationPublication::from_bytes(&bytes).unwrap_err()),
            );
        }
        assert_eq!(inner.migration_syntax_stats().0, 3);
        assert_eq!(inner.migration_syntax_stats().2, 1);
        assert_eq!(
            inner.migration_syntax_stats().3,
            signed.to_bytes().unwrap().len()
        );
        inner.migration_syntax_capacity(0);
        same_error(
            reconstruct(&inner, &frame).await.unwrap_err(),
            crate::credential(SignedMigrationPublication::from_bytes(&bytes).unwrap_err()),
        );
        restore(&inner).await;
    }
    assert_eq!(snapshot(&inner).await, before);
    drop(inner);
    replica.audit(l.scope("items")).await.unwrap();
}

#[tokio::test]
async fn warm_reconstruction_observes_publication_and_actual_proof_refusals() {
    let (l, _, _, replica, signed) = candidate_tables(2, true).await;
    release(&replica, &signed).await;
    let frame = frames(&replica).await.remove(0);
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    inner.migration_syntax_capacity(32768);
    reconstruct(&inner, &frame).await.unwrap();
    let before = snapshot(&inner).await;
    inner
        .check_stored_migration_for_test(&frame, now().unwrap())
        .await
        .unwrap();
    save(&inner).await;
    inner
        .conn
        .execute("PRAGMA defer_foreign_keys=ON", ())
        .await
        .unwrap();
    inner
        .conn
        .execute(
            "UPDATE secure_migration_publications SET publication=X'01'",
            (),
        )
        .await
        .unwrap();
    inner
        .conn
        .execute(
            "UPDATE secure_migration_frames SET publication=X'01',proof=X'FF'",
            (),
        )
        .await
        .unwrap();
    same_error(
        reconstruct(&inner, &frame).await.unwrap_err(),
        denied("migration publication id"),
    );
    inner
        .conn
        .execute("UPDATE secure_migration_publications SET signed=NULL", ())
        .await
        .unwrap();
    same_error(
        reconstruct(&inner, &frame).await.unwrap_err(),
        denied("migration publication id"),
    );
    restore(&inner).await;
    save(&inner).await;
    inner
        .conn
        .execute("UPDATE secure_migration_frames SET proof=X'FF'", ())
        .await
        .unwrap();
    same_error(
        reconstruct(&inner, &frame).await.unwrap_err(),
        denied("invalid secure frame"),
    );
    restore(&inner).await;
    for root in [false, true] {
        save(&inner).await;
        let mut proof = frame.migration.as_ref().unwrap().proof.clone();
        assert!(!proof.siblings.is_empty());
        if root {
            proof.siblings[0].hash[0] ^= 1;
        } else {
            proof.index += 1;
        }
        inner
            .conn
            .execute(
                "UPDATE secure_migration_frames SET proof=? WHERE hash=?",
                [
                    encode(&proof).unwrap(),
                    frame.id().unwrap().as_bytes().to_vec(),
                ],
            )
            .await
            .unwrap();
        let changed = reconstruct(&inner, &frame).await.unwrap();
        assert_eq!(changed.migration.as_ref().unwrap().proof, proof);
        same_error(
            inner
                .check_stored_migration_for_test(&changed, now().unwrap())
                .await
                .unwrap_err(),
            denied(if root {
                "migration inclusion mismatch"
            } else {
                "migration frame is outside the endorsed initial run"
            }),
        );
        restore(&inner).await;
    }
    assert!(inner.migration_syntax_stats().1 > 0);
    assert_eq!(snapshot(&inner).await, before);
    drop(inner);
    replica.audit(l.scope("items")).await.unwrap();
}
