use super::*;

async fn buffered(
    replica: &EncryptedReplica<TypedRows>,
    scope: ResourceScope,
) -> SecureSql<TypedRows> {
    replica
        .session([scope].into())
        .await
        .unwrap()
        .sql(SqlOptions {
            acknowledge: crate::CommitClass::Buffered,
            ..SqlOptions::default()
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn failed_flush_keeps_sql_maintenance_queued_until_retry() {
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let replica = t
        .open(
            &dir.path().join("failed.db"),
            &PrivateKey::new(),
            t.full(),
            &[t.items],
        )
        .await;
    let sql = buffered(&replica, t.items).await;
    insert(&sql, "INSERT INTO items VALUES('a','first',0)", vec![])
        .await
        .unwrap();
    replica.fail_flushes(1).await;
    assert!(replica.flush().await.is_err());
    assert!(!replica.maintain().await);
    assert!(replica.maintenance_queued(t.items).await);
    replica.flush().await.unwrap();
    assert!(replica.maintain().await);
    assert!(!replica.maintenance_queued(t.items).await);
}

#[tokio::test]
async fn commit_during_flush_keeps_current_state_out_of_maintenance() {
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let replica = t
        .open(
            &dir.path().join("concurrent.db"),
            &PrivateKey::new(),
            t.full(),
            &[t.items],
        )
        .await;
    let sql = buffered(&replica, t.items).await;
    insert(&sql, "INSERT INTO items VALUES('a','first',0)", vec![])
        .await
        .unwrap();
    let (entered, resume) = replica.pause_flush().await;
    let flush = replica.flush();
    tokio::pin!(flush);
    tokio::select! {
        result = &mut flush => panic!("flush did not pause: {result:?}"),
        result = entered => result.unwrap(),
    }
    let write = sql
        .run("UPDATE items SET title='second' WHERE key='a'", vec![])
        .await;
    resume.send(()).unwrap();
    write.unwrap();
    flush.await.unwrap();
    assert!(!replica.maintain().await);
    assert!(replica.maintenance_queued(t.items).await);
    replica.flush().await.unwrap();
    assert!(replica.maintain().await);
    assert!(!replica.maintenance_queued(t.items).await);
    assert_eq!(
        select(&sql, "SELECT title FROM items").await,
        vec![vec![text("second")]]
    );
}

#[tokio::test]
async fn flushed_commit_defers_maintenance_until_driver_runs() {
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let replica = t
        .open(
            &dir.path().join("flushed.db"),
            &PrivateKey::new(),
            t.full(),
            &[t.items],
        )
        .await;
    let sql = sql(&replica, &[t.items]).await;
    insert(&sql, "INSERT INTO items VALUES('a','first',0)", vec![])
        .await
        .unwrap();
    assert!(replica.maintenance_queued(t.items).await);
    assert!(replica.maintain().await);
    assert!(!replica.maintenance_queued(t.items).await);
}

#[tokio::test]
async fn failed_flushed_commit_retains_maintenance_for_driver_retry() {
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let replica = t
        .open(
            &dir.path().join("failed-flushed.db"),
            &PrivateKey::new(),
            t.full(),
            &[t.items],
        )
        .await;
    let sql = sql(&replica, &[t.items]).await;
    replica.fail_flushes(1).await;
    assert!(
        insert(&sql, "INSERT INTO items VALUES('a','first',0)", vec![])
            .await
            .is_err()
    );
    assert!(replica.maintenance_queued(t.items).await);
    assert!(!replica.maintain().await);
    replica.flush().await.unwrap();
    assert!(replica.maintain().await);
    assert!(!replica.maintenance_queued(t.items).await);
    assert_eq!(
        select(&sql, "SELECT title FROM items").await,
        vec![vec![text("first")]]
    );
}

#[cfg(feature = "qualification")]
#[tokio::test]
async fn sql_status_checks_use_interactive_acquisitions() {
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let replica = t
        .open(
            &dir.path().join("status.db"),
            &PrivateKey::new(),
            t.full(),
            &[t.items],
        )
        .await;
    let session = replica.session([t.items].into()).await.unwrap();
    let sql = session.sql(SqlOptions::default()).await.unwrap();
    let measurements = replica.lock_measurements();
    for interactive in [false, true] {
        measurements.start();
        let status = if interactive {
            sql.status().await
        } else {
            session.status().await
        }
        .unwrap();
        assert!(status.writable.contains(&t.items));
        let snapshot = measurements.stop();
        assert_eq!(snapshot.holders.len(), 1, "{snapshot:?}");
        assert_eq!(
            snapshot.holders.keys().next().unwrap().1,
            if interactive {
                "Interactive"
            } else {
                "Background"
            }
        );
    }
}

#[tokio::test]
async fn orphaned_pulled_payload_cleanup_is_bounded_and_resumes_after_reopen() {
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("orphaned-pull.db");
    let node = PrivateKey::new();
    let mut replica = t.open(&path, &node, t.full(), &[t.items]).await;
    {
        let mut inner = replica.inner.lock(crate::replica::Class::Background).await;
        transaction!(@commit inner, |inner| {
            for key in 1..=9u8 {
                inner.conn.execute("INSERT INTO secure_pulled_rows VALUES(999,?,?)", [vec![key; 32], vec![]]).await?;
                inner.conn.execute("INSERT INTO secure_pulled_stubs VALUES(999,?,0)", [vec![key; 32]]).await?;
                inner.conn.execute("INSERT INTO secure_pulled_pages VALUES(999,?,NULL,?)", [vec![key; 32], vec![0; 64]]).await?;
            }
            Ok(())
        }).unwrap();
    }
    let count = |replica: EncryptedReplica<TypedRows>| async move {
        let inner = replica.inner.lock(crate::replica::Class::Background).await;
        let records = crate::storage::rows(&inner.conn, "SELECT (SELECT count(*) FROM secure_pulled_rows)+(SELECT count(*) FROM secure_pulled_stubs)+(SELECT count(*) FROM secure_pulled_pages)").await.unwrap();
        match records.as_slice() {
            [row] => match row.as_slice() {
                [SqlValue::Integer(count)] => *count,
                _ => panic!("count"),
            },
            _ => panic!("count"),
        }
    };
    let mut before = 27;
    let mut reopened = false;
    let mut steps = 0;
    loop {
        let measurements = replica.lock_measurements();
        measurements.start();
        let more = replica.maintenance_step_for_test().await.unwrap();
        let measured = measurements.stop();
        let work: u64 = measured
            .holders
            .values()
            .flat_map(|holder| holder.units.get("maintenance_record").into_iter().flatten())
            .map(|(rows, _)| rows)
            .sum();
        assert!(work <= 1, "one input record per acquisition");
        let after = count(replica.clone()).await;
        assert!(before - after <= 1, "one payload deletion per acquisition");
        before = after;
        steps += 1;
        assert!(steps < 100);
        if !reopened && after == 23 {
            drop(replica);
            replica = t.open(&path, &node, t.full(), &[t.items]).await;
            reopened = true;
        }
        if !more {
            break;
        }
    }
    assert!(reopened);
    assert_eq!(before, 0);
    replica.audit(t.items).await.unwrap();
}
