use rocky_sdk::{Affinity, Column, Configuration, Failure, Schema, Table, params};

fn schema() -> Result<Schema, Failure> {
    Schema::builder("rust_application", 1)
        .table(
            Table::replayed("notes")
                .column(Column::new("body", Affinity::Text).required())
                .column(Column::new("optional", Affinity::Text)),
        )
        .build()
}

#[tokio::test]
async fn transactions_observe_commits_and_reopen_without_json() -> Result<(), Failure> {
    let directory = tempfile::tempdir()?;
    let config = Configuration::new(directory.path(), &schema()?)?;
    let db = config.create().await?.database;
    assert!(config.create().await.is_err());
    let events = db.observe_tables(Some(vec!["notes".into()])).await?;
    let mut tx = db.transaction().await?;
    assert!(tx.execute("COMMIT", params![]).await.is_err());
    let id = tx.next_id("notes", vec![]).await?;
    let body = "quoted ' text".to_owned();
    tx.execute(
        "INSERT INTO notes(id,body,optional) VALUES(?,?,?)",
        params![id, &body, None::<String>],
    )
    .await?;
    tx.commit().await?;
    assert_eq!(events.next().await?.tables, ["notes"]);
    let mut tx = db.transaction().await?;
    tx.execute("UPDATE notes SET body='rolled back'", params![])
        .await?;
    tx.rollback().await?;
    db.close().await?;
    let db = config.open().await?.database;
    let rows = db
        .query("SELECT id,body,optional FROM notes", params![])
        .await?
        .collect()
        .await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<i64>("id")?, id);
    assert_eq!(rows[0].get::<String>("body")?, "quoted ' text");
    assert_eq!(rows[0].get::<Option<String>>("optional")?, None);
    assert!(rows[0].get::<String>("optional").is_err());
    assert!(rows[0].get::<i64>("body").is_err());
    assert!(rows[0].get::<i64>("missing").is_err());
    db.close().await
}

#[tokio::test]
async fn dropped_and_cancelled_transactions_release_the_writer() -> Result<(), Failure> {
    let directory = tempfile::tempdir()?;
    let db = Configuration::new(directory.path(), &schema()?)?
        .create()
        .await?
        .database;
    let mut tx = db.transaction().await?;
    let id = tx.next_id("notes", vec![]).await?;
    tx.execute(
        "INSERT INTO notes(id,body) VALUES(?,?)",
        params![id, "discarded"],
    )
    .await?;
    drop(tx);
    let (written, ready) = tokio::sync::oneshot::channel();
    let task_db = db.clone();
    let task = tokio::spawn(async move {
        let mut tx = task_db.transaction().await?;
        let id = tx.next_id("notes", vec![]).await?;
        tx.execute(
            "INSERT INTO notes(id,body) VALUES(?,?)",
            params![id, "cancelled"],
        )
        .await?;
        written.send(()).map_err(|_| "receiver closed")?;
        std::future::pending::<()>().await;
        tx.commit().await?;
        Ok::<_, Failure>(())
    });
    ready.await?;
    task.abort();
    assert!(task.await.expect_err("cancelled").is_cancelled());
    // The next write deterministically waits for rollback, without a sleep.
    let mut tx = db.transaction().await?;
    let id = tx.next_id("notes", vec![]).await?;
    tx.execute(
        "INSERT INTO notes(id,body) VALUES(?,?)",
        params![id, "kept"],
    )
    .await?;
    tx.commit().await?;
    let rows = db
        .query("SELECT body FROM notes", params![])
        .await?
        .collect()
        .await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<String>("body")?, "kept");
    db.close().await
}

#[tokio::test]
async fn paged_reads_hold_a_snapshot_and_decode_aliases() -> Result<(), Failure> {
    let directory = tempfile::tempdir()?;
    let schema = Schema::builder("paging", 1)
        .table(Table::replayed("cache").column(Column::new("n", Affinity::Integer).required()))
        .build()?;
    let db = Configuration::new(directory.path(), &schema)?
        .create()
        .await?
        .database;
    // Two transactions, each under the intent statement quota.
    for batch in [1..=150_i64, 151..=300] {
        let mut tx = db.transaction().await?;
        for n in batch {
            let id = tx.next_id("cache", params![]).await?;
            tx.execute("INSERT INTO cache(id,n) VALUES(?,?)", params![id, n])
                .await?;
        }
        tx.commit().await?;
    }
    let mut snapshot = db
        .query("SELECT n FROM cache ORDER BY n", params![])
        .await?;
    assert_eq!(
        snapshot
            .next()
            .await?
            .ok_or("missing first")?
            .get::<i64>("n")?,
        1
    );
    let mut tx = db.transaction().await?;
    tx.execute("DELETE FROM cache", params![]).await?;
    tx.commit().await?;
    let rows = snapshot.collect().await?;
    assert_eq!(rows.len(), 299);
    assert_eq!(rows[298].get_at::<i64>(0)?, 300);
    let mut rows = db
        .query(
            "SELECT 1 AS duplicate, 2 AS duplicate, NULL AS optional, 2 AS bad_boolean",
            params![],
        )
        .await?;
    let row = rows.next().await?.ok_or("missing row")?;
    assert!(row.get::<i64>("duplicate").is_err());
    assert_eq!(row.get_at::<i64>(1)?, 2);
    assert_eq!(row.get::<Option<i64>>("optional")?, None);
    assert!(row.get::<bool>("bad_boolean").is_err());
    drop(rows);
    db.close().await
}

#[test]
fn invalid_schema_is_refused_before_installation() {
    assert!(
        Schema::builder("bad", 0)
            .table(Table::replayed("notes").column(Column::new("body", Affinity::Text)))
            .build()
            .is_err()
    );
    assert!(Schema::parse(r#"{"format":0}"#).is_err());
}

#[tokio::test]
async fn configured_peers_enroll_and_sync_through_the_rust_api() -> Result<(), Failure> {
    use rocky_sdk::{GrantProfile, Network, transport::memory::Hub};
    use std::sync::Arc;
    let hub = Arc::new(Hub::default());
    let issuer_directory = tempfile::tempdir()?;
    let member_directory = tempfile::tempdir()?;
    let issuer = Configuration::new(issuer_directory.path(), &schema()?)?
        .network(Network::Owned(hub.connector("issuer")))
        .create()
        .await?
        .database;
    let session = issuer.session();
    let invitation = session
        .pairing(GrantProfile::Writer {
            scopes: ["notes".into()].into(),
        })
        .await?;
    assert!(invitation.expires_at_epoch_seconds > 0);
    let member_configuration = Configuration::new(member_directory.path(), &schema()?)?
        .network(Network::Owned(hub.connector("member")));
    let member = member_configuration.join(&invitation.uri).await?.database;
    let member_session = member.session();
    member_session.set_automatic_sync(false).await?;
    session.set_automatic_sync(false).await?;
    member_session.sync_once().await?;
    let mut tx = issuer.transaction().await?;
    let id = tx.next_id("notes", vec![]).await?;
    tx.execute(
        "INSERT INTO notes(id,body) VALUES(?,?)",
        params![id, "from issuer"],
    )
    .await?;
    tx.commit().await?;
    member_session.sync_once().await?;
    let rows = member
        .query("SELECT body FROM notes", params![])
        .await?
        .collect()
        .await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<String>("body")?, "from issuer");
    let contact = member_session.contact().await?;
    let peer = session.add_peer(&contact).await?;
    assert!(!peer.is_empty());
    member.close().await?;
    let reopened = member_configuration.open().await?.database;
    assert_eq!(
        reopened
            .query("SELECT body FROM notes", params![])
            .await?
            .collect()
            .await?
            .len(),
        1
    );
    reopened.close().await?;
    issuer.close().await
}

#[test]
fn configuration_without_a_tokio_runtime_returns_an_error() -> Result<(), Failure> {
    let configuration = Configuration::new("unused", &schema()?)?;
    let mut creating = std::pin::pin!(configuration.create());
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        std::future::Future::poll(creating.as_mut(), &mut context),
        std::task::Poll::Ready(Err(_))
    ));
    Ok(())
}
