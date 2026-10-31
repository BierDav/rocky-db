//! Replayed transactions across partitions: a replica holding only some
//! members follows the outcome records of replicas that hold the rest.
use super::*;
use rocky_core::replay::{DropReason, TransactionOutcome};

mod convergence;

async fn keys(
    f: &Fixture,
    replica: &EncryptedReplica<TypedRows>,
    names: &[&str],
) -> Vec<Vec<SqlValue>> {
    sql_on(f, replica, names)
        .await
        .run(
            &format!(
                "SELECT list,key,amount FROM items WHERE list IN ({}) ORDER BY list,key",
                names
                    .iter()
                    .map(|name| format!("'{name}'"))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            vec![],
        )
        .await
        .unwrap()
        .rows
}

/// Frames `replica` authored in `name`'s partition that carry no intent.
async fn records(
    f: &Fixture,
    replica: &EncryptedReplica<TypedRows>,
    node: &PrivateKey,
    name: &str,
) -> Vec<EncryptedFrame> {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    let rows = crate::storage::rows(
        &inner.conn,
        &format!(
            "SELECT header,body FROM secure_operations WHERE author=x'{}' ORDER BY sequence",
            node.public_key()
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ),
    )
    .await
    .unwrap();
    let mut frames = Vec::new();
    for row in rows {
        let [SqlValue::Blob(header), SqlValue::Blob(body)] = row.as_slice() else {
            panic!("stored operation");
        };
        let frame = inner
            .stored_frame(header.clone(), body.clone())
            .await
            .unwrap();
        if frame.scope().unwrap() == f.scope(name)
            && payload(&frame, [if name == "A" { 1 } else { 2 }; 32], f)
                .outcome()
                .is_some()
        {
            frames.push(frame);
        }
    }
    frames
}

fn payload(frame: &EncryptedFrame, key: [u8; 32], f: &Fixture) -> crate::wire::RowPayload {
    let plaintext = crate::wire::decrypt(
        &key,
        &encode(&frame.operation_ref().unwrap().header.extensions).unwrap(),
        frame.body_bytes(),
    )
    .unwrap();
    crate::wire::RowPayload::decode_test(&plaintext, frame, &f.app()).unwrap()
}

fn transaction(frame: &EncryptedFrame, key: [u8; 32], f: &Fixture) -> rocky_core::Commitment {
    payload(frame, key, f).membership().unwrap().transaction
}

#[tokio::test]
async fn a_partial_holder_drops_its_member_when_a_full_holders_record_says_so() {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::build_class(false, PrivateKey::new(), "replayed");
    let open =
        |name: &'static str, node: &PrivateKey, held: Option<&'static [&'static str]>, number| {
            let (f, root, node) = (&f, &root, node.clone());
            async move {
                let replica = f
                    .open(
                        &root.path().join(name),
                        node.clone(),
                        f.grant(held, &all()),
                        Some((node, number)),
                    )
                    .await;
                for (list, key) in [("A", [1; 32]), ("B", [2; 32])] {
                    if held.is_none_or(|held| held.contains(&list)) {
                        f.key(&replica, list, key).await;
                    }
                }
                replica
            }
        };
    let (w, x, r) = (PrivateKey::new(), PrivateKey::new(), PrivateKey::new());
    let writer = open("w.sqlite", &w, None, 1).await;
    let full = open("x.sqlite", &x, None, 2).await;
    let partial = open("r.sqlite", &r, Some(&["A"]), 3).await;

    // X creates `k` in B; the writer, not having seen it, creates `a` in A
    // and `k` in B in one transaction, which X must drop.
    let [earlier] = insert(&f, &full, &["A", "B"], &[("B", "k", 1)], 1)
        .await
        .try_into()
        .unwrap();
    let later = insert(&f, &writer, &["A", "B"], &[("A", "a", 1), ("B", "k", 2)], 2).await;
    assert_eq!(later.len(), 2);
    let member = |name| {
        later
            .iter()
            .find(|frame| frame.scope().unwrap() == f.scope(name))
            .unwrap()
            .clone()
    };
    // A bundle applies once every member this replica holds is present.
    let mut statuses = Vec::new();
    for frame in &later {
        statuses.push(full.receive(frame.clone()).await.unwrap());
    }
    assert_eq!(
        statuses,
        [ReceiveStatus::PendingDependencies, ReceiveStatus::Applied]
    );
    assert_eq!(
        keys(&f, &full, &["A", "B"]).await,
        vec![vec![
            SqlValue::Text("B".into()),
            SqlValue::Text("k".into()),
            SqlValue::Integer(1)
        ]]
    );
    let txn = transaction(&member("A"), [1; 32], &f);
    let dropped = Some(TransactionOutcome::Dropped {
        reason: DropReason::Constraint,
        sealed: false,
    });
    assert_eq!(full.transaction_outcome(txn).await.unwrap(), dropped);

    // R holds only A: its member applies provisionally.
    assert_eq!(
        partial.receive(member("A")).await.unwrap(),
        ReceiveStatus::Applied
    );
    assert_eq!(keys(&f, &partial, &["A"]).await.len(), 1);
    assert_eq!(
        partial.transaction_outcome(txn).await.unwrap(),
        Some(TransactionOutcome::Applied)
    );
    // X's record in A's log names B, which R does not hold: R drops too.
    let [record] = records(&f, &full, &x, "A").await.try_into().unwrap();
    assert_eq!(
        partial.receive(record).await.unwrap(),
        ReceiveStatus::Applied
    );
    assert!(keys(&f, &partial, &["A"]).await.is_empty());
    assert_eq!(partial.transaction_outcome(txn).await.unwrap(), dropped);

    // The writer learns of the earlier create: its own transaction rewinds
    // and drops the same way, so its record agrees with X's.
    assert_eq!(
        writer.receive(earlier).await.unwrap(),
        ReceiveStatus::Applied
    );
    assert_eq!(writer.transaction_outcome(txn).await.unwrap(), dropped);
    for record in records(&f, &full, &x, "A").await {
        assert_eq!(
            writer.receive(record).await.unwrap(),
            ReceiveStatus::Applied
        );
    }
}

#[tokio::test]
async fn a_seal_covers_a_transaction_once_every_member_has_a_record() {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::build_class(false, PrivateKey::new(), "replayed");
    let (w, r) = (PrivateKey::new(), PrivateKey::new());
    let writer = f
        .open(
            &root.path().join("w.sqlite"),
            w.clone(),
            f.grant(None, &all()),
            Some((w.clone(), 1)),
        )
        .await;
    let partial = f
        .open(
            &root.path().join("r.sqlite"),
            r.clone(),
            f.grant(Some(&["A"]), &all()),
            Some((r.clone(), 3)),
        )
        .await;
    f.key(&writer, "A", [1; 32]).await;
    f.key(&writer, "B", [2; 32]).await;
    f.key(&partial, "A", [1; 32]).await;
    let both = insert(&f, &writer, &["A", "B"], &[("A", "a", 1), ("B", "b", 1)], 1).await;
    // The author records its transaction in every member's log at commit.
    let [record] = records(&f, &writer, &w, "A").await.try_into().unwrap();
    let member = both
        .iter()
        .find(|frame| frame.scope().unwrap() == f.scope("A"))
        .unwrap()
        .clone();
    assert_eq!(
        partial.receive(member).await.unwrap(),
        ReceiveStatus::Applied
    );
    // Only its own record names member 0: B has none here yet.
    partial.seal_replayed_for_test(f.scope("A")).await.unwrap();
    assert_eq!(partial.unsealed_replayed_transactions().await.unwrap(), 1);
    assert_eq!(
        partial.receive(record).await.unwrap(),
        ReceiveStatus::Applied
    );
    partial.seal_replayed_for_test(f.scope("A")).await.unwrap();
    assert_eq!(partial.unsealed_replayed_transactions().await.unwrap(), 0);

    // A replica holding the transaction whole fills in a lost record.
    {
        let inner = writer.inner.lock(crate::replica::Class::Background).await;
        for table in ["secure_outcomes", "secure_outcome_members"] {
            inner
                .conn
                .execute(&format!("DELETE FROM {table}"), ())
                .await
                .unwrap();
        }
    }
    writer.publish_missing_outcomes().await.unwrap();
    assert_eq!(records(&f, &writer, &w, "A").await.len(), 2);
    assert_eq!(records(&f, &writer, &w, "B").await.len(), 2);
    writer.publish_missing_outcomes().await.unwrap();
    assert_eq!(records(&f, &writer, &w, "A").await.len(), 2);
}

#[tokio::test]
async fn a_rewind_waits_for_its_partition_keys_and_records_only_changed_outcomes() {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::build_class(false, PrivateKey::new(), "replayed");
    let (w, x, r) = (PrivateKey::new(), PrivateKey::new(), PrivateKey::new());
    let open = |name: &'static str, node: &PrivateKey, number| {
        let (f, root, node) = (&f, &root, node.clone());
        async move {
            f.open(
                &root.path().join(name),
                node.clone(),
                f.grant(None, &all()),
                Some((node, number)),
            )
            .await
        }
    };
    let writer = open("w.sqlite", &w, 1).await;
    let other = open("x.sqlite", &x, 2).await;
    let reader = open("r.sqlite", &r, 3).await;
    for replica in [&writer, &other, &reader] {
        f.key(replica, "A", [1; 32]).await;
        f.key(replica, "B", [2; 32]).await;
    }
    let [earlier] = insert(&f, &other, &["A", "B"], &[("A", "e", 1)], 1)
        .await
        .try_into()
        .unwrap();
    let both = insert(&f, &writer, &["A", "B"], &[("A", "a", 1), ("B", "b", 1)], 2).await;
    assert_eq!(records(&f, &writer, &w, "A").await.len(), 1);
    for status in reader.receive_all(both).await {
        assert_eq!(status.unwrap(), ReceiveStatus::Applied);
    }

    // Reopened with only A's key, the reader cannot redo the transaction's
    // member in B: the earlier arrival waits instead of being rejected.
    drop(reader);
    let reader = open("r.sqlite", &r, 3).await;
    f.key(&reader, "A", [1; 32]).await;
    assert_ne!(
        reader.receive(earlier.clone()).await.unwrap(),
        ReceiveStatus::Rejected
    );
    assert!(matches!(
        sql_on(&f, &reader, &["A"])
            .await
            .run("SELECT key FROM items WHERE list='A'", vec![])
            .await,
        Err(Error::Sql(crate::sql::SqlError::Unavailable {
            reason: crate::sql::Unavailable::Incomplete,
            ..
        }))
    ));
    f.key(&reader, "B", [2; 32]).await;
    assert_eq!(keys(&f, &reader, &["A", "B"]).await.len(), 3);

    // The writer rewinds too; its transaction redoes with the same outcome,
    // so it publishes no new record.
    assert_eq!(
        writer.receive(earlier).await.unwrap(),
        ReceiveStatus::Applied
    );
    assert_eq!(keys(&f, &writer, &["A", "B"]).await.len(), 3);
    assert_eq!(records(&f, &writer, &w, "A").await.len(), 1);
}

#[tokio::test]
async fn a_disagreeing_outcome_record_is_refused_as_divergence_naming_both_engines() {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::build_class(false, PrivateKey::new(), "replayed");
    let (w, x, r) = (PrivateKey::new(), PrivateKey::new(), PrivateKey::new());
    let open = |name: &'static str, node: &PrivateKey, number| {
        let (f, root, node) = (&f, &root, node.clone());
        async move {
            let replica = f
                .open(
                    &root.path().join(name),
                    node.clone(),
                    f.grant(None, &all()),
                    Some((node, number)),
                )
                .await;
            f.key(&replica, "A", [1; 32]).await;
            f.key(&replica, "B", [2; 32]).await;
            replica
        }
    };
    let (writer, forger, reader) = (
        open("w.sqlite", &w, 1).await,
        open("x.sqlite", &x, 2).await,
        open("r.sqlite", &r, 3).await,
    );
    let both = insert(&f, &writer, &["A", "B"], &[("A", "a", 1), ("B", "b", 1)], 1).await;
    for status in forger.receive_all(both.clone()).await {
        assert_eq!(status.unwrap(), ReceiveStatus::Applied);
    }
    let member = both
        .iter()
        .find(|frame| frame.scope().unwrap() == f.scope("A"))
        .unwrap();
    let txn = transaction(member, [1; 32], &f);
    // The forger signs again that the transaction dropped, as another
    // engine would decide after the same prefixes.
    forger
        .forge_outcome_for_test(
            txn,
            Some(DropReason::Constraint),
            "forged engine",
            &[f.scope("A"), f.scope("B")],
        )
        .await
        .unwrap();
    let [honest, forged] = records(&f, &forger, &x, "A").await.try_into().unwrap();
    let [authored] = records(&f, &writer, &w, "A").await.try_into().unwrap();

    for status in reader.receive_all(both).await {
        assert_eq!(status.unwrap(), ReceiveStatus::Applied);
    }
    for record in [authored, honest] {
        assert_eq!(
            reader.receive(record).await.unwrap(),
            ReceiveStatus::Applied
        );
    }
    assert_eq!(
        reader.receive(forged).await.unwrap(),
        ReceiveStatus::Rejected
    );
    let [divergence] = reader
        .outcome_divergences()
        .await
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(divergence.transaction, txn);
    assert_eq!(divergence.publisher, x.public_key());
    assert!(
        divergence.stored.starts_with("rocky-secure "),
        "{divergence:?}"
    );
    assert_eq!(divergence.refused, "forged engine");
    // The refused record changes nothing.
    assert_eq!(
        reader.transaction_outcome(txn).await.unwrap(),
        Some(TransactionOutcome::Applied)
    );
    assert_eq!(keys(&f, &reader, &["A", "B"]).await.len(), 2);
}
