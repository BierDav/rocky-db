//! The SQL connections a database driver uses: a writer as a secure SQL
//! session, readers as snapshot cursors, typed values and SQLite codes.
//! See `docs/runtime/sql-driver.md`.
mod support;
use rocky_sdk::{
    Connection, ConnectionOptions, Database, Network, Open, Page, Profile, SqlValue,
    transport::memory::Hub,
};
use serde_json::{Value, json};
use sqlparser::{
    ast::{Expr, Ident, SelectItem, SetExpr, Statement},
    dialect::SQLiteDialect,
    parser::Parser,
};
use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};

type Failure = Box<dyn std::error::Error + Send + Sync>;

const SHOPPING: &str = r#"{"format":6,"application":"shopping","version":3,"tables":[
 {"name":"lists","class":"replayed","columns":[
   {"name":"key","type":"text","not_null":true},{"name":"title","type":"text","not_null":true}],
  "primary_key":["key"]},
 {"name":"items","class":"replayed","columns":[
   {"name":"key","type":"text","not_null":true},{"name":"list","type":"text","not_null":true},
   {"name":"title","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},
   {"name":"note","type":"blob"}],
  "primary_key":["key"],
  "indexes":[{"name":"items_by_list","columns":[{"name":"list","descending":false},{"name":"title","descending":true}]}]}
]}"#;

fn open<'a>(directory: &'a Path, network: Option<Network>) -> Open<'a> {
    Open {
        identity: None,
        directory,
        schema: SHOPPING,
        secrets: Some(support::secrets::keys(directory)),
        network,
        coordination: None,
    }
}
async fn create(open: Open<'_>, ttl: Option<u64>) -> Result<rocky_sdk::Opened, Failure> {
    let opened = Database::create(open, ttl)?;
    let database = &opened.database;

    let scope: Value = serde_json::from_str(&database.scope())?;
    // Check the allocator's starting identities, then release the reservations.
    let session = database.session();
    let request = |request: Value| json!({"version":1,"scope":scope,"request":request}).to_string();
    session
        .call(request(json!({"type":"sql","sql":"BEGIN"})))
        .await?;
    for table in ["lists", "items"] {
        let allocated: Value = serde_json::from_str(
            &session
                .call(request(json!({"type":"next_id","table":table})))
                .await?,
        )?;
        assert_eq!(allocated["value"]["id"], "4294967297", "{table}");
    }
    session
        .call(request(json!({"type":"sql","sql":"ROLLBACK"})))
        .await?;
    session.close().await;
    Ok(opened)
}
fn expression(sql: &str) -> Expr {
    let Statement::Query(query) = Parser::parse_sql(&SQLiteDialect {}, &format!("SELECT {sql}"))
        .unwrap()
        .remove(0)
    else {
        panic!("fixture expression")
    };
    let SetExpr::Select(select) = *query.body else {
        panic!("fixture select")
    };
    let SelectItem::UnnamedExpr(expr) = select.projection.into_iter().next().unwrap() else {
        panic!("fixture expression")
    };
    expr
}
// The fixture adapter obtains each inserted identity through the public SQL allocator.
async fn identity_insert(connection: &Connection, sql: &str) -> Result<String, Failure> {
    let Ok(mut statements) = Parser::parse_sql(&SQLiteDialect {}, sql) else {
        return Ok(sql.into());
    };
    if statements.len() != 1 {
        return Ok(sql.into());
    }
    let statement = match &mut statements[0] {
        Statement::Query(query) => match query.body.as_mut() {
            SetExpr::Insert(statement) => statement,
            _ => return Ok(sql.into()),
        },
        statement => statement,
    };
    let Statement::Insert(insert) = statement else {
        return Ok(sql.into());
    };
    let table = insert.table.to_string();
    if !["lists", "items"].contains(&table.as_str()) {
        return Ok(sql.into());
    }
    insert.columns.push(Ident::new("id").into());
    let source = insert.source.as_mut().unwrap();
    match source.body.as_mut() {
        SetExpr::Values(values) => {
            for row in &mut values.rows {
                let id = allocated_identity(connection, &table).await?;
                row.push(expression(&id.to_string()));
            }
        }
        SetExpr::Select(select) => {
            let base = allocated_identity(connection, &table).await? - 1;
            select
                .projection
                .push(SelectItem::UnnamedExpr(expression(&format!(
                    "{base} + row_number() OVER ()"
                ))));
        }
        _ => panic!("fixture insert"),
    }
    Ok(statements[0].to_string())
}
fn text(value: &str) -> SqlValue {
    SqlValue::Text(value.into())
}
const WRITER: ConnectionOptions = ConnectionOptions {
    read_only: false,
    durability: rocky_sdk::Durability::Buffered,
    profile: None,
    transaction_timeout: None,
    binding: None,
};
const READER: ConnectionOptions = ConnectionOptions {
    read_only: true,
    durability: rocky_sdk::Durability::Buffered,
    profile: None,
    transaction_timeout: None,
    binding: None,
};

/// Runs `sql` to its end and returns every row.
async fn all(
    connection: &Connection,
    sql: &str,
    params: Vec<SqlValue>,
) -> Result<Vec<Vec<SqlValue>>, Failure> {
    let statement = connection.statement();
    let mut page: Page = connection
        .execute(statement, identity_insert(connection, sql).await?, params)
        .await?;
    let mut rows = std::mem::take(&mut page.rows);
    while !page.done {
        page = connection.next(statement).await?;
        rows.append(&mut page.rows);
    }
    Ok(rows)
}
async fn allocated_identity(connection: &Connection, table: &str) -> Result<i64, Failure> {
    let statement = connection.statement();
    let mut page = connection
        .execute(
            statement,
            format!("SELECT rocky_next_id('{table}')"),
            vec![],
        )
        .await?;
    let id = match page.rows.first().and_then(|row| row.first()) {
        Some(SqlValue::Integer(id)) => *id,
        _ => return Err("allocator returned no identity".into()),
    };
    while !page.done {
        page = connection.next(statement).await?;
    }
    Ok(id)
}
async fn run(connection: &Connection, sql: &str) -> Result<(), Failure> {
    all(connection, sql, Vec::new()).await.map(drop)
}
async fn count(connection: &Connection, table: &str) -> Result<i64, Failure> {
    match all(
        connection,
        &format!("SELECT count(*) FROM {table}"),
        Vec::new(),
    )
    .await?[..]
    {
        [ref row] => match row[..] {
            [SqlValue::Integer(count)] => Ok(count),
            _ => Err("count".into()),
        },
        _ => Err("count".into()),
    }
}
/// Bundles and frames this device authored, read with ordinary SQLite.
fn published(directory: &Path) -> Result<(i64, i64), Failure> {
    let file = rusqlite::Connection::open_with_flags(
        directory.join("rocky.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let bundles = file.query_row(
        "SELECT count(DISTINCT handle) FROM secure_bundle_handles",
        [],
        |row| row.get(0),
    )?;
    let frames = file.query_row("SELECT count(*) FROM secure_operations", [], |row| {
        row.get(0)
    })?;
    Ok((bundles, frames))
}

#[tokio::test]
async fn a_writer_transaction_is_one_bundle_and_savepoints_nest() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let database = create(open(root.path(), None), None).await?.database;
    let writer = database.connect(WRITER).await?;
    let reader = database.connect(READER).await?;
    let before = published(root.path())?;

    run(&writer, "BEGIN IMMEDIATE TRANSACTION").await?;
    assert!(writer.in_transaction().await?);
    all(
        &writer,
        "INSERT INTO lists(key,title) VALUES(?,?)",
        vec![text("l1"), text("Groceries")],
    )
    .await?;
    for (key, title) in [("i1", "Milk"), ("i2", "Eggs"), ("i3", "Jam")] {
        all(
            &writer,
            "INSERT INTO items(key,list,title,completed,note) VALUES(?,?,?,0,?)",
            vec![
                text(key),
                text("l1"),
                text(title),
                SqlValue::Blob(vec![1, 2]),
            ],
        )
        .await?;
    }
    // Nested savepoints, as Room nests transactions: the inner one rolls back.
    run(&writer, "SAVEPOINT 'outer'").await?;
    run(&writer, "SAVEPOINT 'inner'").await?;
    run(&writer, "DELETE FROM items WHERE key = 'i3'").await?;
    run(&writer, "ROLLBACK TRANSACTION TO SAVEPOINT 'inner'").await?;
    run(&writer, "RELEASE SAVEPOINT 'inner'").await?;
    run(&writer, "UPDATE items SET completed = 1 WHERE key = 'i1'").await?;
    run(&writer, "RELEASE SAVEPOINT 'outer'").await?;
    // The writer reads its own writes. A reader's statement would wait for
    // the commit: readers never hold the writer, the writer holds the replica.
    assert_eq!(count(&writer, "items").await?, 3);
    run(&writer, "END TRANSACTION").await?;
    assert!(!writer.in_transaction().await?);
    assert_eq!(count(&reader, "items").await?, 3);
    let rows = all(
        &reader,
        "SELECT title, completed, note FROM items ORDER BY key",
        Vec::new(),
    )
    .await?;
    assert_eq!(
        rows[0],
        vec![
            text("Milk"),
            SqlValue::Integer(1),
            SqlValue::Blob(vec![1, 2])
        ]
    );
    // Parent and children: one bundle, one frame for each table's scope,
    // and the outcome record each member's log carries.
    let after = published(root.path())?;
    assert_eq!((after.0 - before.0, after.1 - before.1), (1, 4));

    // Inserted and deleted in one transaction: its statements still
    // replicate, since another replica's replay may differ.
    run(&writer, "BEGIN IMMEDIATE TRANSACTION").await?;
    all(
        &writer,
        "INSERT INTO lists(key,title) VALUES('gone','Temporary')",
        Vec::new(),
    )
    .await?;
    run(&writer, "DELETE FROM lists WHERE key = 'gone'").await?;
    run(&writer, "END TRANSACTION").await?;
    let after = published(root.path())?;
    assert_eq!(after, (before.0 + 2, before.1 + 5));
    // A transaction that only began and ended never took the file.
    run(&writer, "BEGIN IMMEDIATE TRANSACTION").await?;
    run(&writer, "END TRANSACTION").await?;
    assert_eq!(published(root.path())?, after);

    // Engine errors keep SQLite's extended codes; the transaction goes on.
    run(&writer, "BEGIN IMMEDIATE TRANSACTION").await?;
    let duplicate = all(
        &writer,
        "INSERT INTO lists(key,title) VALUES('l1','again')",
        Vec::new(),
    )
    .await
    .err()
    .ok_or("duplicate key")?;
    let duplicate = duplicate
        .downcast::<rocky_sdk::SqlFailure>()
        .map_err(|_| "code")?;
    assert_eq!(duplicate.code, 1555, "{duplicate}");
    assert!(writer.in_transaction().await?);
    run(&writer, "ROLLBACK TRANSACTION").await?;
    // The engine catalog and pragmas stay denied without a profile.
    for sql in [
        "PRAGMA user_version",
        "SELECT * FROM sqlite_master",
        "SELECT * FROM secure_operations",
    ] {
        let error = all(&writer, sql, Vec::new()).await.err().ok_or(sql)?;
        let error = error
            .downcast::<rocky_sdk::SqlFailure>()
            .map_err(|_| "code")?;
        assert_eq!(error.code, 23, "{sql}: {error}");
    }
    writer.close().await;
    reader.close().await;
    database.close().await?;
    Ok(())
}

/// Runs `sql` as given, without the fixture's identity rewrite.
async fn exact(
    connection: &Connection,
    sql: &str,
    params: Vec<SqlValue>,
) -> Result<Vec<Vec<SqlValue>>, rocky_sdk::SqlFailure> {
    let page = connection
        .execute(connection.statement(), sql.into(), params)
        .await?;
    assert!(page.done);
    Ok(page.rows)
}

#[tokio::test]
async fn a_row_id_is_reserved_before_its_insert_in_the_same_transaction() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let database = create(open(root.path(), None), None).await?.database;
    let writer = database.connect(WRITER).await?;
    let reader = database.connect(READER).await?;
    let before = published(root.path())?;
    let id = |rows: Vec<Vec<SqlValue>>| match rows[..] {
        [ref row] => match row[..] {
            [SqlValue::Integer(id)] => Ok(id),
            _ => Err("one integer"),
        },
        _ => Err("one row"),
    };

    // Reserved, then inserted, in one transaction: one bundle.
    exact(&writer, "BEGIN IMMEDIATE TRANSACTION", vec![]).await?;
    let first = id(exact(&writer, "SELECT rocky_next_id('items')", vec![]).await?)?;
    let second = id(exact(&writer, "select ROCKY_NEXT_ID(?);", vec![text("items")]).await?)?;
    assert_eq!((first, second), (4294967297, 4294967298));
    for (key, id) in [("i1", first), ("i2", second)] {
        exact(
            &writer,
            "INSERT INTO items(key,list,title,completed,id) VALUES(?,'l1',?,0,?)",
            vec![text(key), text(key), SqlValue::Integer(id)],
        )
        .await?;
    }
    exact(&writer, "COMMIT", vec![]).await?;
    assert_eq!(
        all(&reader, "SELECT key, id FROM items ORDER BY key", vec![]).await?,
        vec![
            vec![text("i1"), SqlValue::Integer(first)],
            vec![text("i2"), SqlValue::Integer(second)]
        ]
    );
    let after = published(root.path())?;
    assert_eq!(after.0 - before.0, 1);

    // A rollback releases the reservation: the next transaction gets it again.
    for _ in 0..2 {
        exact(&writer, "BEGIN IMMEDIATE TRANSACTION", vec![]).await?;
        let third = id(exact(&writer, "SELECT rocky_next_id('items')", vec![]).await?)?;
        assert_eq!(third, 4294967299);
        exact(&writer, "ROLLBACK", vec![]).await?;
    }
    assert_eq!(published(root.path())?, after);

    // Only a write transaction reserves ids.
    let outside = exact(&writer, "SELECT rocky_next_id('items')", vec![])
        .await
        .err()
        .ok_or("outside a transaction")?;
    assert_eq!(outside.code, 1, "{outside}");
    assert!(outside.message.contains("open transaction"), "{outside}");
    let read = exact(&reader, "SELECT rocky_next_id('items')", vec![])
        .await
        .err()
        .ok_or("on a reader")?;
    assert_eq!(read.code, 8, "{read}");
    exact(&writer, "BEGIN IMMEDIATE TRANSACTION", vec![]).await?;
    for (sql, params) in [
        ("SELECT rocky_next_id(7)", vec![]),
        ("SELECT rocky_next_id(?)", vec![SqlValue::Integer(7)]),
        ("SELECT rocky_next_id('items')", vec![text("items")]),
        ("SELECT rocky_next_id('absent')", vec![]),
    ] {
        let refused = exact(&writer, sql, params).await.err().ok_or(sql)?;
        assert_ne!(refused.code, 0, "{sql}");
        assert!(writer.in_transaction().await?, "{sql}");
    }
    exact(&writer, "ROLLBACK", vec![]).await?;
    assert_eq!(published(root.path())?, after);
    writer.close().await;
    reader.close().await;
    database.close().await?;
    Ok(())
}

#[tokio::test]
async fn bundle_limits_and_the_lease_fail_the_transaction_without_splitting_it()
-> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let database = create(open(root.path(), None), None).await?.database;
    let writer = database.connect(WRITER).await?;
    let before = published(root.path())?;
    let code = |error: Failure| {
        error
            .downcast::<rocky_sdk::SqlFailure>()
            .map(|failure| *failure)
    };

    // Seeds of 32 and 64 rows; a statement crossing them replays 2,048.
    run(&writer, "BEGIN IMMEDIATE TRANSACTION").await?;
    for key in 0..65 {
        all(
            &writer,
            "INSERT INTO lists(key,title) VALUES(?,?)",
            vec![
                text(&format!("s{key:02}")),
                text(if key < 32 { "a" } else { "b" }),
            ],
        )
        .await?;
    }
    run(&writer, "END TRANSACTION").await?;
    let seeded = published(root.path())?;
    // 2,049 replayed rows: the commit fails as a whole.
    run(&writer, "BEGIN IMMEDIATE TRANSACTION").await?;
    all(
        &writer,
        "INSERT INTO lists(key,title) SELECT x.key || y.key, 'list' FROM lists x, lists y \
         WHERE x.title = 'a' AND y.title IN ('a','b')",
        Vec::new(),
    )
    .await?;
    let refused = code(
        all(&writer, "END TRANSACTION", Vec::new())
            .await
            .err()
            .ok_or("rows")?,
    )
    .map_err(|_| "code")?;
    assert_eq!(refused.code, 18, "{refused}");
    assert!(!writer.in_transaction().await?);
    assert_eq!(count(&writer, "lists").await?, 65);
    // An intent frame over a range page's bytes fails the same way.
    run(&writer, "BEGIN IMMEDIATE TRANSACTION").await?;
    all(
        &writer,
        "INSERT INTO lists(key,title) VALUES(?,?)",
        vec![text("big"), text(&"x".repeat(256 * 1024))],
    )
    .await?;
    let refused = code(
        all(&writer, "END TRANSACTION", Vec::new())
            .await
            .err()
            .ok_or("bytes")?,
    )
    .map_err(|_| "code")?;
    assert!(refused.message.contains("quota"), "{refused}");
    assert_eq!(count(&writer, "lists").await?, 65);
    // Exactly the limit commits as one bundle of one intent frame.
    run(&writer, "BEGIN IMMEDIATE TRANSACTION").await?;
    all(
        &writer,
        "INSERT INTO lists(key,title) SELECT x.key || y.key, 'list' FROM lists x, lists y \
         WHERE x.title = 'a' AND y.title = 'b'",
        Vec::new(),
    )
    .await?;
    run(&writer, "END TRANSACTION").await?;
    let after = published(root.path())?;
    assert_eq!((after.0 - seeded.0, after.1 - seeded.1), (1, 1));
    assert!(seeded.0 > before.0);
    writer.close().await;
    database.close().await?;
    Ok(())
}

#[tokio::test]
async fn the_write_lease_times_out_and_aborts_until_acknowledged() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let database = create(open(root.path(), None), None).await?.database;
    let writer = database
        .connect(ConnectionOptions {
            transaction_timeout: Some(Duration::from_millis(200)),
            ..WRITER
        })
        .await?;
    run(&writer, "BEGIN IMMEDIATE TRANSACTION").await?;
    run(&writer, "INSERT INTO lists(key,title) VALUES('l1','held')").await?;
    // The lease ends on its own; wait for that, at most a few seconds.
    let error = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match all(&writer, "SELECT count(*) FROM lists", Vec::new()).await {
                Ok(_) => tokio::time::sleep(Duration::from_millis(20)).await,
                Err(error) => return error,
            }
        }
    })
    .await?;
    let error = error
        .downcast::<rocky_sdk::SqlFailure>()
        .map_err(|_| "code")?;
    assert_eq!(error.code, 4, "{error}");
    assert!(error.message.contains("Timeout"), "{error}");
    // Still a transaction for the driver, until it rolls back.
    assert!(writer.in_transaction().await?);
    run(&writer, "ROLLBACK TRANSACTION").await?;
    assert!(!writer.in_transaction().await?);
    assert_eq!(count(&writer, "lists").await?, 0);
    writer.close().await;
    database.close().await?;
    Ok(())
}

#[tokio::test]
async fn readers_page_snapshots_and_never_hold_the_writer() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let database = create(open(root.path(), None), None).await?.database;
    let writer = database.connect(WRITER).await?;
    let reader = database.connect(READER).await?;
    // 600 lists, in transactions under the intent statement quota.
    for batch in 0..3 {
        run(&writer, "BEGIN IMMEDIATE TRANSACTION").await?;
        for i in 1..=200 {
            all(
                &writer,
                "INSERT INTO lists(key,title) VALUES(?,'list')",
                vec![text(&format!("l{:04}", batch * 200 + i))],
            )
            .await?;
        }
        run(&writer, "END TRANSACTION").await?;
    }

    // An open cursor and an open read transaction do not stop a commit.
    let streaming = reader.statement();
    let first = reader
        .execute(
            streaming,
            "SELECT key FROM lists ORDER BY key".into(),
            Vec::new(),
        )
        .await?;
    assert_eq!(
        (first.columns.clone(), first.rows.len(), first.done),
        (vec!["key".to_string()], 256, false)
    );
    let transaction = database.connect(READER).await?;
    run(&transaction, "BEGIN DEFERRED TRANSACTION").await?;
    assert_eq!(count(&transaction, "lists").await?, 600);
    let delete_started = std::time::Instant::now();
    // A blocked writer never finishes; the bound only has to outlast a loaded CI host.
    tokio::time::timeout(Duration::from_secs(60), async {
        run(&writer, "BEGIN IMMEDIATE TRANSACTION").await?;
        run(&writer, "DELETE FROM lists WHERE key > 'l0100'").await?;
        run(&writer, "END TRANSACTION").await
    })
    .await
    .map_err(|_| "a reader blocked the writer")??;
    eprintln!("500-row delete and commit: {:?}", delete_started.elapsed());
    // Both still read their snapshot; a new statement reads the commit.
    let mut seen = first.rows.len();
    loop {
        let page = reader.next(streaming).await?;
        seen += page.rows.len();
        if page.done {
            break;
        }
    }
    assert_eq!(seen, 600);
    assert_eq!(count(&transaction, "lists").await?, 600);
    run(&transaction, "END TRANSACTION").await?;
    assert_eq!(count(&transaction, "lists").await?, 100);
    assert_eq!(count(&reader, "lists").await?, 100);
    // Readers refuse writes with SQLite's read-only code.
    for sql in ["DELETE FROM lists", "BEGIN IMMEDIATE TRANSACTION"] {
        let error = all(&reader, sql, Vec::new()).await.err().ok_or(sql)?;
        let error = error
            .downcast::<rocky_sdk::SqlFailure>()
            .map_err(|_| "code")?;
        assert_eq!(error.code, 8, "{sql}: {error}");
    }
    // `query_only` switches a connection's kind between transactions, as in SQLite.
    run(&writer, "PRAGMA query_only = 1").await?;
    let flag = all(&writer, "PRAGMA query_only", Vec::new()).await?;
    assert_eq!(flag, vec![vec![SqlValue::Integer(1)]]);
    assert!(all(&writer, "DELETE FROM lists", Vec::new()).await.is_err());
    run(&writer, "PRAGMA query_only = 0").await?;
    run(&writer, "BEGIN IMMEDIATE TRANSACTION").await?;
    assert!(
        all(&writer, "PRAGMA query_only = 1", Vec::new())
            .await
            .is_err()
    );
    run(&writer, "DELETE FROM lists WHERE key = 'l0001'").await?;
    run(&writer, "END TRANSACTION").await?;
    assert_eq!(count(&reader, "lists").await?, 99);
    for connection in [writer, reader, transaction] {
        connection.close().await;
    }
    database.close().await?;
    Ok(())
}

async fn call(database: &Database, request: Value) -> Result<Value, Failure> {
    let scope: Value = serde_json::from_str(&database.scope())?;
    let reply = database
        .session()
        .call(json!({"version": 1, "scope": scope, "request": request}).to_string())
        .await?;
    let reply: Value = serde_json::from_str(&reply)?;
    if reply["status"] == "ok" {
        Ok(reply["value"].clone())
    } else {
        Err(reply["error"].to_string().into())
    }
}

#[tokio::test]
async fn peers_apply_a_transaction_as_one_bundle_and_see_only_changed_columns()
-> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let hub = Arc::new(Hub::default());
    let a = create(
        open(
            &root.path().join("a"),
            Some(Network::Owned(hub.connector("a"))),
        ),
        None,
    )
    .await?
    .database;
    let invitation = call(
        &a,
        json!({"type": "pairing", "profile": {"kind": "writer", "scopes": ["lists", "items"]}}),
    )
    .await?;
    let b = Database::join(
        open(
            &root.path().join("b"),
            Some(Network::Owned(hub.connector("b"))),
        ),
        invitation["uri"].as_str().ok_or("uri")?,
    )?
    .database;
    call(&b, json!({"type": "sync"})).await?;
    let _scope: Value = serde_json::from_str(&b.scope())?;
    let (writer_a, writer_b) = (a.connect(WRITER).await?, b.connect(WRITER).await?);
    let reader_b = b.connect(READER).await?;
    let events = b.observe_tables(None).await?;

    run(&writer_a, "BEGIN IMMEDIATE TRANSACTION").await?;
    run(
        &writer_a,
        "INSERT INTO lists(key,title) VALUES('l1','Groceries')",
    )
    .await?;
    run(
        &writer_a,
        "INSERT INTO items(key,list,title,completed) VALUES('i1','l1','Milk',0)",
    )
    .await?;
    run(
        &writer_a,
        "INSERT INTO items(key,list,title,completed) VALUES('i2','l1','Eggs',0)",
    )
    .await?;
    run(&writer_a, "END TRANSACTION").await?;
    call(&b, json!({"type": "sync"})).await?;
    // One change covers both tables: the bundle applied as a whole.
    let change = tokio::time::timeout(Duration::from_secs(5), events.next()).await??;
    assert_eq!(
        change.tables,
        vec!["items".to_string(), "lists".to_string()]
    );
    assert!(change.causes.contains(&"sync".to_string()), "{change:?}");
    assert_eq!(count(&reader_b, "items").await?, 2);

    // A whole-row update that changes only the title, concurrent with a
    // change of `completed` elsewhere: under `changed` both survive.
    run(&writer_a, "UPDATE items SET key = 'i1', list = 'l1', title = 'Oat milk', completed = 0, note = NULL WHERE key = 'i1'").await?;
    run(&writer_b, "UPDATE items SET completed = 1 WHERE key = 'i1'").await?;
    call(&b, json!({"type": "sync"})).await?;
    call(&a, json!({"type": "sync"})).await?;
    for writer in [&writer_a, &writer_b] {
        let rows = all(
            writer,
            "SELECT title, completed FROM items WHERE key = 'i1'",
            Vec::new(),
        )
        .await?;
        assert_eq!(rows, vec![vec![text("Oat milk"), SqlValue::Integer(1)]]);
    }
    for connection in [writer_a, writer_b, reader_b] {
        connection.close().await;
    }
    b.close().await?;
    a.close().await?;
    Ok(())
}

/// Rows of a pragma read from the file with ordinary SQLite.
fn engine_pragma(directory: &Path, pragma: &str) -> Result<Vec<Vec<SqlValue>>, Failure> {
    let file = rusqlite::Connection::open_with_flags(
        directory.join("rocky.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut statement = file.prepare(pragma)?;
    let columns = statement.column_count();
    let rows = statement.query_map([], |row| {
        (0..columns)
            .map(|index| {
                Ok(match row.get_ref(index)? {
                    rusqlite::types::ValueRef::Null => SqlValue::Null,
                    rusqlite::types::ValueRef::Integer(value) => SqlValue::Integer(value),
                    rusqlite::types::ValueRef::Real(value) => {
                        SqlValue::real(value).unwrap_or(SqlValue::Null)
                    }
                    rusqlite::types::ValueRef::Text(bytes) => text(&String::from_utf8_lossy(bytes)),
                    rusqlite::types::ValueRef::Blob(blob) => SqlValue::Blob(blob.to_vec()),
                })
            })
            .collect::<Result<Vec<_>, rusqlite::Error>>()
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

#[tokio::test]
async fn room_schema_reads_refresh_authority_before_a_deferred_transaction_uses_the_file()
-> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let database = create(open(root.path(), None), None).await?.database;
    let writer = database
        .connect(ConnectionOptions {
            profile: Some(Profile::Room284),
            ..WRITER
        })
        .await?;
    run(&writer, "BEGIN DEFERRED TRANSACTION").await?;
    call(&database, json!({"type": "renew"})).await?;
    assert!(
        !all(&writer, "PRAGMA table_info(`items`)", vec![])
            .await?
            .is_empty()
    );
    assert!(
        !all(&writer, "PRAGMA index_list(`items`)", vec![])
            .await?
            .is_empty()
    );
    run(&writer, "ROLLBACK").await?;
    // The first real statement must use the refreshed session too.
    run(&writer, "BEGIN DEFERRED TRANSACTION").await?;
    call(&database, json!({"type": "renew"})).await?;
    assert_eq!(count(&writer, "items").await?, 0);
    run(&writer, "ROLLBACK").await?;
    writer.close().await;
    database.close().await?;
    Ok(())
}

#[tokio::test]
async fn room_housekeeping_is_answered_from_the_catalog_and_the_file() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let database = create(open(root.path(), None), None).await?.database;
    assert!("room-2.7.0".parse::<Profile>().is_err());
    let room = ConnectionOptions {
        profile: Some("room-2.8.4".parse()?),
        ..WRITER
    };
    let writer = database.connect(room.clone()).await?;
    let reader = database
        .connect(ConnectionOptions {
            read_only: true,
            durability: rocky_sdk::Durability::Buffered,
            ..room.clone()
        })
        .await?;
    let one = |rows: Vec<Vec<SqlValue>>| {
        rows.into_iter()
            .next()
            .and_then(|row| row.into_iter().next())
    };
    let failure = |error: Failure| {
        error
            .downcast::<rocky_sdk::SqlFailure>()
            .map(|failure| *failure)
    };

    // Connection setup, as Room 2.8.4 sends it.
    assert_eq!(
        one(all(&writer, "PRAGMA journal_mode = WAL", vec![]).await?),
        Some(text("wal"))
    );
    run(&writer, "PRAGMA synchronous = NORMAL").await?;
    assert_eq!(
        one(all(&writer, "PRAGMA busy_timeout", vec![]).await?),
        Some(SqlValue::Integer(5000))
    );
    assert_eq!(
        one(all(&writer, "PRAGMA query_only", vec![]).await?),
        Some(SqlValue::Integer(0))
    );
    run(&reader, "PRAGMA query_only = 1").await?;
    assert_eq!(
        one(all(&reader, "PRAGMA query_only", vec![]).await?),
        Some(SqlValue::Integer(1))
    );
    // The schema's version is Room's database version.
    assert_eq!(
        one(all(&writer, "PRAGMA user_version", vec![]).await?),
        Some(SqlValue::Integer(3))
    );
    run(&writer, "PRAGMA user_version = 3").await?;
    let moved = failure(
        all(&writer, "PRAGMA user_version = 4", vec![])
            .await
            .err()
            .ok_or("version")?,
    )
    .map_err(|_| "code")?;
    assert!(
        moved.message.contains("application's schema version 3"),
        "{moved}"
    );

    // The identity table lives with the connection; validation runs first.
    let exists = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'room_master_table'";
    assert!(all(&writer, exists, vec![]).await?.is_empty());
    run(&writer, "BEGIN EXCLUSIVE TRANSACTION").await?;
    run(
        &writer,
        "CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)",
    )
    .await?;
    run(
        &writer,
        "INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, 'abc123')",
    )
    .await?;
    run(&writer, "END TRANSACTION").await?;
    assert_eq!(all(&writer, exists, vec![]).await?.len(), 1);
    assert_eq!(
        one(all(
            &writer,
            "SELECT identity_hash FROM room_master_table WHERE id = 42 LIMIT 1",
            vec![]
        )
        .await?),
        Some(text("abc123"))
    );
    // Room's own table statements for an installed table and index change nothing.
    run(
        &writer,
        "CREATE TABLE IF NOT EXISTS `items` (`key` TEXT NOT NULL, `id` INTEGER NOT NULL, PRIMARY KEY(`key`))",
    )
    .await?;
    // An entity must carry Rocky's id field and leave its ids to Rocky.
    for (sql, reason) in [
        (
            "CREATE TABLE IF NOT EXISTS `items` (`key` TEXT NOT NULL, `note` TEXT, PRIMARY KEY(`key`, `note`))",
            "must declare Rocky's id",
        ),
        (
            "CREATE TABLE IF NOT EXISTS `items` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL)",
            "autoGenerate = true is refused",
        ),
    ] {
        let refused =
            failure(all(&writer, sql, vec![]).await.err().ok_or(sql)?).map_err(|_| "code")?;
        assert_eq!(refused.code, 1, "{sql}");
        assert!(refused.message.contains(reason), "{refused}");
    }
    run(
        &writer,
        "CREATE INDEX IF NOT EXISTS `items_by_list` ON `items` (`list`, `title` DESC)",
    )
    .await?;
    for sql in [
        "CREATE TABLE IF NOT EXISTS `extra` (`id` TEXT NOT NULL, PRIMARY KEY(`id`))",
        "CREATE INDEX IF NOT EXISTS `index_items_title` ON `items` (`title`)",
    ] {
        let refused =
            failure(all(&writer, sql, vec![]).await.err().ok_or(sql)?).map_err(|_| "code")?;
        assert_eq!(refused.code, 1, "{sql}");
        assert!(
            refused.message.contains("installed Rocky schema"),
            "{refused}"
        );
    }

    // Schema validation reads the real table: the answers are the file's.
    for (asked, engine) in [
        ("PRAGMA table_info(`items`)", "PRAGMA table_info(\"items\")"),
        ("PRAGMA index_list(`items`)", "PRAGMA index_list(\"items\")"),
        (
            "PRAGMA index_xinfo(`items_by_list`)",
            "PRAGMA index_xinfo(\"items_by_list\")",
        ),
        (
            "PRAGMA foreign_key_list(`items`)",
            "PRAGMA foreign_key_list(\"items\")",
        ),
    ] {
        let answered = all(&reader, asked, vec![]).await?;
        assert_eq!(answered, engine_pragma(root.path(), engine)?, "{asked}");
    }
    let columns = all(&reader, "PRAGMA table_info(`items`)", vec![]).await?;
    assert_eq!(columns.len(), 6);
    assert_eq!(
        columns[0][1..],
        [
            text("key"),
            text("TEXT"),
            SqlValue::Integer(1),
            SqlValue::Null,
            SqlValue::Integer(1)
        ]
    );
    let id = columns
        .iter()
        .find(|row| row[1] == text("id"))
        .ok_or("id")?;
    assert_eq!(id[2], text("INTEGER"));
    assert_eq!(id[3], SqlValue::Integer(1));
    let indexes = all(&reader, "PRAGMA index_list(`items`)", vec![]).await?;
    assert!(
        indexes
            .iter()
            .any(|row| row[1] == text("items_by_list") && row[3] == text("c")),
        "{indexes:?}"
    );
    // Protocol tables and unknown names answer nothing.
    assert!(
        all(&reader, "PRAGMA table_info(`secure_operations`)", vec![])
            .await?
            .is_empty()
    );
    assert!(
        all(
            &reader,
            "PRAGMA index_xinfo(`sqlite_autoindex_items_1`)",
            vec![]
        )
        .await?
        .is_empty()
    );
    assert!(
        all(
            &writer,
            "SELECT name FROM sqlite_master WHERE type = 'trigger'",
            vec![]
        )
        .await?
        .is_empty()
    );
    // Anything Room 2.8.4 does not send stays denied.
    for sql in [
        "PRAGMA foreign_keys = OFF",
        "PRAGMA wal_checkpoint(TRUNCATE)",
        "SELECT * FROM sqlite_master",
    ] {
        assert_eq!(
            failure(all(&writer, sql, vec![]).await.err().ok_or(sql)?)
                .map_err(|_| "code")?
                .code,
            23,
            "{sql}"
        );
    }
    writer.close().await;
    reader.close().await;
    database.close().await?;
    Ok(())
}

#[tokio::test]
async fn room_reads_each_reference_action_when_references_share_a_partition_column()
-> Result<(), Failure> {
    const GROUPED: &str = r#"{"format":6,"application":"grouped","version":1,"tables":[
 {"name":"lists","class":"replayed","columns":[{"name":"title","type":"text","not_null":true}],
  "primary_key":["id"],"partition_by":["id"],"partition_group":"list"},
 {"name":"categories","class":"replayed","columns":[{"name":"list","type":"integer","not_null":true}],
  "primary_key":["list","id"],"partition_by":["list"],"partition_group":"list"},
 {"name":"items","class":"replayed","columns":[
   {"name":"list","type":"integer","not_null":true},{"name":"category","type":"integer"}],
  "primary_key":["list","id"],"partition_by":["list"],"partition_group":"list",
  "foreign_keys":[{"columns":["list","category"],"table":"categories","on_delete":"set_null"},
   {"columns":["list"],"table":"lists","on_delete":"cascade"}]}
]}"#;
    let root = tempfile::tempdir()?;
    let database = Database::create(
        Open {
            identity: None,
            directory: root.path(),
            schema: GROUPED,
            secrets: None,
            network: None,
            coordination: None,
        },
        None,
    )?
    .database;
    let reader = database
        .connect(ConnectionOptions {
            profile: Some("room-2.8.4".parse()?),
            ..READER
        })
        .await?;
    // Rows of one key share its id: (id, seq, table, from, to, on_update, on_delete, match).
    let mut keys = BTreeMap::<i64, (SqlValue, Vec<SqlValue>, SqlValue)>::new();
    for row in all(&reader, "PRAGMA foreign_key_list(`items`)", vec![]).await? {
        let SqlValue::Integer(id) = row[0] else {
            return Err("foreign key id".into());
        };
        let key = keys
            .entry(id)
            .or_insert_with(|| (row[2].clone(), Vec::new(), row[6].clone()));
        key.1.push(row[3].clone());
    }
    let mut keys: Vec<_> = keys.into_values().collect();
    keys.sort_by_key(|(table, _, _)| format!("{table:?}"));
    assert_eq!(
        keys,
        [
            (
                text("categories"),
                vec![text("list"), text("category")],
                text("SET NULL")
            ),
            (text("lists"), vec![text("list")], text("CASCADE")),
        ]
    );
    database.close().await?;
    Ok(())
}

#[tokio::test]
async fn a_member_installs_only_its_readable_tables_even_after_reopen() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let hub = Arc::new(Hub::default());
    let mut schema: Value = serde_json::from_str(SHOPPING)?;
    schema["tables"][0]["indexes"] = json!([{"name":"list_by_title", "unique":false,
        "columns":[{"name":"title","descending":false}]}]);
    schema["tables"]
        .as_array_mut()
        .ok_or("tables")?
        .push(json!({
            "name":"devices", "class":"replayed",
            "columns":[{"name":"key","type":"text","not_null":true},
                {"name":"name","type":"text","not_null":true}], "primary_key":["key"], "indexes":[{"name":"devices_by_name", "columns":[{"name":"name","descending":false}]}]
        }));
    let schema = schema.to_string();
    let a_path = root.path().join("a");
    let b_path = root.path().join("b");
    let setup = |directory, name| Open {
        identity: None,
        directory,
        schema: &schema,
        secrets: None,
        network: Some(Network::Owned(hub.connector(name))),
        coordination: None,
    };
    let a = Database::create(setup(&a_path, "a"), None)?.database;
    let invitation = call(
        &a,
        json!({"type":"pairing", "profile":{"kind":"reader", "scopes":["lists"]}}),
    )
    .await?;
    let b = Database::join(
        setup(&b_path, "b"),
        invitation["uri"].as_str().ok_or("uri")?,
    )?
    .database;
    {
        let reader = b.connect(READER).await?;
        all(&reader, "SELECT * FROM lists", vec![]).await?;
        for table in ["devices", "items", "issuer_registry", "keys", "identities"] {
            let error = all(&reader, &format!("SELECT * FROM {table}"), vec![])
                .await
                .unwrap_err();
            assert!(error.to_string().contains("no such table"), "{error}");
            let file = rusqlite::Connection::open_with_flags(
                b_path.join("rocky.sqlite"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            let count: i64 = file.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?",
                [table],
                |row| row.get(0),
            )?;
            assert_eq!(count, 0, "{table}");
        }
        reader.close().await;
    }
    b.close().await?;
    let b = Database::open(setup(&b_path, "b"))?.database;
    let reader = b.connect(READER).await?;
    assert!(
        all(&reader, "SELECT * FROM devices", vec![])
            .await
            .unwrap_err()
            .to_string()
            .contains("no such table")
    );
    all(&reader, "SELECT * FROM lists", vec![]).await?;
    reader.close().await;
    b.close().await?;
    a.close().await?;
    Ok(())
}

#[tokio::test]
async fn an_older_room_application_validates_the_schema_it_declares() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let created = create(open(root.path(), None), None).await?.database;
    for action in ["create", "follow"] {
        call(
            &created,
            json!({"type": "tips", "action": action, "name": "main"}),
        )
        .await?;
    }
    created.close().await?;
    // The issuer's next application version adds a nullable rank.
    let newer = SHOPPING
        .replace(r#""version":3"#, r#""version":4"#)
        .replace(
            r#"{"name":"note","type":"blob"}"#,
            r#"{"name":"note","type":"blob"},{"name":"rank","type":"integer"}"#,
        );
    let database = Database::open(Open {
        schema: &newer,
        ..open(root.path(), None)
    })?
    .database;
    let room = ConnectionOptions {
        profile: Some("room-2.8.4".parse()?),
        ..WRITER
    };
    let columns = |rows: Vec<Vec<SqlValue>>| -> Vec<String> {
        rows.into_iter()
            .filter_map(|row| match row.get(1) {
                Some(SqlValue::Text(name)) => Some(name.clone()),
                _ => None,
            })
            .collect()
    };
    let writer = database.connect(room.clone()).await?;
    let current = columns(all(&writer, "PRAGMA table_info(items)", vec![]).await?);
    assert!(current.contains(&"rank".to_string()), "{current:?}");
    let indexes = all(&writer, "PRAGMA index_list(items)", vec![]).await?;
    writer.close().await;
    database.close().await?;

    // The version 3 application opens the version 4 database: Room sees
    // its own version and tables as it declares them.
    let database = Database::open(open(root.path(), None))?.database;
    assert_eq!(
        call(&database, json!({"type": "generation"})).await?["application"],
        "behind"
    );
    let writer = database.connect(room.clone()).await?;
    assert_eq!(
        all(&writer, "PRAGMA user_version", vec![]).await?,
        vec![vec![SqlValue::Integer(3)]]
    );
    let declared = columns(all(&writer, "PRAGMA table_info(items)", vec![]).await?);
    assert_eq!(
        declared,
        current
            .iter()
            .filter(|name| *name != "rank")
            .cloned()
            .collect::<Vec<_>>()
    );
    assert_eq!(
        all(&writer, "PRAGMA index_list(items)", vec![]).await?,
        indexes
    );
    // An unchanged table is the installed one.
    assert!(!columns(all(&writer, "PRAGMA table_info(lists)", vec![]).await?).is_empty());
    assert_eq!(count(&writer, "items").await?, 0);
    writer.close().await;
    database.close().await?;
    Ok(())
}

/// The SQLite code `sql` fails with.
async fn failing(connection: &Connection, sql: &str) -> Result<i32, Failure> {
    match all(connection, sql, Vec::new()).await {
        Ok(_) => Err(format!("{sql} succeeded").into()),
        Err(error) => Ok(error
            .downcast::<rocky_sdk::SqlFailure>()
            .map_err(|_| "code")?
            .code),
    }
}
fn titles(rows: Vec<Vec<SqlValue>>) -> Vec<String> {
    rows.into_iter()
        .filter_map(|row| match row.into_iter().next() {
            Some(SqlValue::Text(title)) => Some(title),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn a_connection_bound_to_a_kept_seal_reads_it_and_never_writes() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let database = create(open(root.path(), None), None).await?.database;
    let tips = |action: &str, body: Value| {
        let mut request = json!({"type": "tips", "action": action});
        for (key, value) in body.as_object().into_iter().flatten() {
            request[key] = value.clone();
        }
        call(&database, request)
    };
    tips("create", json!({"name": "main"})).await?;
    tips("follow", json!({"name": "main"})).await?;
    tips("keep", json!({"kept": {"every": true}})).await?;
    let writer = database.connect(WRITER).await?;
    run(&writer, "BEGIN IMMEDIATE TRANSACTION").await?;
    run(
        &writer,
        "INSERT INTO lists(key,title) VALUES('l1','Groceries')",
    )
    .await?;
    run(
        &writer,
        "INSERT INTO items(key,list,title,completed) VALUES('i1','l1','Milk',0)",
    )
    .await?;
    run(&writer, "END TRANSACTION").await?;
    // A continue seal's id is its successor tip.
    let first = tips("seal", json!({})).await?["tip"].clone();
    run(&writer, "BEGIN IMMEDIATE TRANSACTION").await?;
    run(&writer, "UPDATE items SET title='Oat milk' WHERE key='i1'").await?;
    run(
        &writer,
        "INSERT INTO items(key,list,title,completed) VALUES('i2','l1','Eggs',0)",
    )
    .await?;
    run(&writer, "END TRANSACTION").await?;
    let second = tips("seal", json!({})).await?["tip"].clone();
    run(&writer, "DELETE FROM items WHERE key='i1'").await?;
    let seal = |value: &Value| -> Result<rocky_core::Commitment, Failure> {
        let hex = value.as_str().ok_or("seal")?;
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16))
            .collect::<Result<_, _>>()?;
        Ok(bytes.try_into().map_err(|_| "seal")?)
    };
    let kept = tips("inspect", json!({})).await?;
    for id in [&first, &second] {
        let held = kept["seals"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|known| known["id"] == *id)
            .map(|known| known["held"].clone());
        assert_eq!(held, Some(json!("kept")), "{id}");
    }

    let bound = |binding| ConnectionOptions {
        binding: Some(binding),
        ..WRITER
    };
    let at_first = database
        .connect(bound(rocky_sdk::Binding::Seal(seal(&first)?)))
        .await?;
    let items = "SELECT title FROM items ORDER BY key";
    assert_eq!(titles(all(&at_first, items, vec![]).await?), ["Milk"]);
    // The bookmark's tip is open: it shows the seal it starts from.
    let at_main = database
        .connect(bound(rocky_sdk::Binding::Bookmark("main".into())))
        .await?;
    assert_eq!(
        titles(all(&at_main, items, vec![]).await?),
        ["Oat milk", "Eggs"]
    );
    assert_eq!(titles(all(&writer, items, vec![]).await?), ["Eggs"]);
    // Writes fail with SQLite's read-only code, in or outside a transaction.
    for sql in [
        "INSERT INTO items(key,list,title,completed) VALUES('i9','l1','x',0)",
        "UPDATE items SET title='x'",
        "DELETE FROM items",
        "PRAGMA query_only = 0",
    ] {
        assert_eq!(failing(&at_first, sql).await?, 8, "{sql}");
    }
    run(&at_first, "BEGIN IMMEDIATE TRANSACTION").await?;
    assert_eq!(titles(all(&at_first, items, vec![]).await?), ["Milk"]);
    assert_eq!(failing(&at_first, "DELETE FROM items").await?, 8);
    run(&at_first, "END TRANSACTION").await?;
    // Unlimited bound connections may be open at once.
    let mut many = Vec::new();
    for _ in 0..8 {
        many.push(
            database
                .connect(bound(rocky_sdk::Binding::Seal(seal(&second)?)))
                .await?,
        );
    }
    for connection in &many {
        assert_eq!(count(connection, "items").await?, 2);
    }
    // A seal this device does not keep cannot be bound.
    assert!(
        database
            .connect(bound(rocky_sdk::Binding::Seal([7; 32])))
            .await
            .is_err()
    );
    Ok(())
}
