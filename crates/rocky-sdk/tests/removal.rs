//! Removal: a generation drops tables and fields on every device that
//! follows it. A removed-and-readded name filters earlier values through
//! the schema path; an unsent change it would split is held. See
//! `docs/runtime/removal.md` and `docs/runtime/held-changes.md`.
mod common;
use common::{Device, Failure, introduce};
use rocky_sdk::{Database, Network, Open, transport::memory::Hub};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

/// Items with a uniquely indexed `category` and a `shelf` referencing
/// `shelves`.
const SHELVED: &str = r#"{"application":"shopping","version":1,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"title","type":"text","not_null":true},{"name":"category","type":"text"},{"name":"shelf","type":"integer"}],"primary_key":["key"],"indexes":[{"name":"items_category","unique":true,"columns":[{"name":"category","descending":false}]}],"foreign_keys":[{"columns":["shelf"],"table":"shelves","on_delete":"set_null"}]},{"name":"shelves","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"label","type":"text","not_null":true}],"primary_key":["key"]}]}"#;
/// `SHELVED` without `category`, its index, `shelf` and `shelves`.
const UNSHELVED: &str = r#"{"application":"shopping","version":2,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]}]}"#;
/// Items with a nullable `note`; the next version removes it and the one
/// after adds it again.
const NOTED: &str = r#"{"application":"shopping","version":1,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"note","type":"text"},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]}]}"#;

fn open<'a>(directory: &'a Path, schema: &'a str, network: Option<Network>) -> Open<'a> {
    Open {
        identity: None,
        directory,
        schema,
        secrets: None,
        network,
        coordination: None,
    }
}
fn version(schema: &str, version: u32) -> String {
    schema.replace(r#""version":1"#, &format!(r#""version":{version}"#))
}
async fn rows(device: &Device, sql: &str) -> Value {
    device
        .ok(json!({"type": "read", "query": {"sql": sql, "values": [], "max_rows": 1024}}))
        .await["rows"]
        .clone()
}
fn text(value: &str) -> Value {
    json!({"type": "text", "value": value})
}
async fn generation(device: &Device) -> Value {
    device.ok(json!({"type": "generation"})).await
}
/// Creates a row of `collection`; returns its key.
async fn create(device: &Device, handle: u8, collection: &str, values: Value) -> String {
    let reply = device
        .ok(json!({
            "type": "mutate",
            "handle": vec![handle; 32],
            "payload": json!({"type": "create", "collection": collection, "values": values}).to_string().into_bytes(),
            "entity": null,
            "baseline": null,
        }))
        .await;
    reply["id"].as_str().unwrap_or_default().to_owned()
}
/// Runs `sql` as one transaction: one frame.
async fn write(device: &Device, _collection: &str, handle: u8, sql: &str) {
    let _scope: Value = serde_json::from_str(&device.database.scope()).expect("scope");

    device.ok(json!({"type": "sql", "sql": "BEGIN"})).await;
    device.ok(json!({"type": "sql", "sql": sql})).await;
    device
        .ok(json!({"type": "sql", "sql": "COMMIT", "handle": vec![handle; 32]}))
        .await;
}
/// The id of `items.<field>` in the domain at `directory`.
/// Whether a stored or checkpoint row references the file's interned field id.
fn holds(directory: &Path, field: &str) -> Result<bool, Failure> {
    use serde::de::IgnoredAny;
    type StoredRecord = (
        IgnoredAny,
        IgnoredAny,
        Vec<(i64, IgnoredAny, IgnoredAny)>,
        IgnoredAny,
        IgnoredAny,
        IgnoredAny,
        IgnoredAny,
        IgnoredAny,
        IgnoredAny,
        IgnoredAny,
    );
    let file = rusqlite::Connection::open_with_flags(
        directory.join("rocky.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut names = file.prepare("SELECT id FROM secure_field_names WHERE name=?")?;
    let mut names = names.query([format!("items.{field}")])?;
    let Some(name) = names.next()? else {
        return Ok(false);
    };
    let id: i64 = name.get(0)?;
    for table in ["secure_rows", "secure_checkpoint_rows"] {
        let mut statement = file.prepare(&format!("SELECT fields FROM {table}"))?;
        let blobs = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for blob in blobs {
            let blob = blob?;
            // Replica 35 prefixes local records with liveness and a shape id.
            let shape_bytes = match blob.get(1) {
                Some(0..=23) => 1,
                Some(24) => 2,
                Some(25) => 3,
                Some(26) => 5,
                Some(27) => 9,
                _ => return Err("invalid local shape id".into()),
            };
            let record: StoredRecord = p2panda_core::cbor::decode_cbor(
                blob.get(1 + shape_bytes..)
                    .ok_or("truncated local record")?,
            )?;
            if record.2.iter().any(|field| field.0 == id) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
/// The application tables, indexes and `items` columns of the file.
fn schema_of(directory: &Path) -> Result<(Vec<String>, Vec<String>), Failure> {
    let file = rusqlite::Connection::open_with_flags(
        directory.join("rocky.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut statement = file.prepare(
        "SELECT name FROM sqlite_schema WHERE type IN ('table','index') AND name NOT LIKE 'secure_%' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'issuer_registry%' ORDER BY name",
    )?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<_, _>>()?;
    let mut statement =
        file.prepare("SELECT name FROM pragma_table_info('items') ORDER BY name")?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<_, _>>()?;
    Ok((names, columns))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_generation_removes_a_field_its_unique_index_and_a_referenced_table()
-> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::new(Database::create(open(&a_dir, SHELVED, network("a")), None)?)?;
    a.follow_main_migrating().await;
    let b = Device::new(Database::join(
        open(&b_dir, SHELVED, network("b")),
        &a.invite_as(json!({"kind": "writer", "scopes": ["items", "shelves"]}))
            .await,
    )?)?;
    introduce(&a, &b).await;
    create(&a, 1, "shelves", json!({"label": "pantry"})).await;
    let shelf = rows(&a, "SELECT id FROM shelves").await[0][0]["value"]
        .as_str()
        .ok_or("shelf id")?
        .parse::<i64>()?;
    create(
        &a,
        2,
        "items",
        json!({"title": "apples", "completed": false, "category": "fruit", "shelf": shelf}),
    )
    .await;
    create(
        &a,
        3,
        "items",
        json!({"title": "bread", "completed": false, "category": "bakery"}),
    )
    .await;
    b.sync().await.expect("sync");
    assert_eq!(b.titles().await, ["apples", "bread"]);
    // The member, still at the first generation, writes a removed and a
    // kept field in one frame and sends it.
    write(
        &b,
        "items",
        4,
        "UPDATE items SET title='green apples', category='produce' WHERE title='apples'",
    )
    .await;
    b.sync().await.expect("sync");

    a.close().await;
    let a = Device::new(common::confirmed(open(&a_dir, UNSHELVED, network("a")))?)?;
    assert_eq!(generation(&a).await["current"]["schema"], 2);
    assert_eq!(a.titles().await, ["bread", "green apples"]);
    // Explicitly open the signed schema; its sent frame keeps its authority.
    b.close().await;
    let b = Device::new(Database::open(open(&b_dir, UNSHELVED, network("b")))?)?;
    b.sync().await.expect("sync");
    b.sync().await.expect("sync");
    for device in [&a, &b] {
        assert_eq!(generation(device).await["current"]["schema"], 2);
        assert_eq!(device.titles().await, ["bread", "green apples"]);
    }
    // The member's application declares the removed column: its reads of
    // it fail with an ordinary SQLite error.
    let failed = b
        .call(json!({"type": "read", "query": {"sql": "SELECT category FROM items", "values": [], "max_rows": 8}}))
        .await
        .expect_err("removed column");
    assert!(
        failed["message"]
            .as_str()
            .is_some_and(|message| message.contains("no such column")),
        "{failed}"
    );
    a.close().await;
    b.close().await;
    // Each file holds exactly the new schema and no removed field.
    for directory in [&a_dir, &b_dir] {
        let (names, columns) = schema_of(directory)?;
        assert!(
            !names.iter().any(|name| name.contains("shelves")),
            "{names:?}"
        );
        assert!(!names.contains(&"items_category".to_string()), "{names:?}");
        assert!(names.contains(&"items".to_string()), "{names:?}");
        assert!(
            !columns
                .iter()
                .any(|name| name == "category" || name == "shelf"),
            "{columns:?}"
        );
        for field in ["category", "shelf"] {
            assert!(!holds(directory, field)?, "{field}");
        }
        assert!(holds(directory, "title")?);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_readded_field_never_receives_a_value_written_before_its_removal() -> Result<(), Failure>
{
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let directory = |name: &str| root.path().join(name);
    let a = Device::new(Database::create(
        open(&directory("a"), NOTED, network("a")),
        None,
    )?)?;
    a.follow_main_migrating().await;
    let join = |name: &str, invitation: &str| -> Result<Device, Failure> {
        Device::new(Database::join(
            open(&directory(name), NOTED, network(name)),
            invitation,
        )?)
    };
    // c is a second issuer; d writes offline; e keeps the first rows.
    let c = join("c", &a.invite_as(json!({"kind": "issuer"})).await)?;
    let d = join("d", &a.invite().await)?;
    let e = join("e", &a.invite().await)?;
    for member in [&c, &d, &e] {
        introduce(&a, member).await;
    }
    introduce(&c, &d).await;
    let apples = create(
        &a,
        1,
        "items",
        json!({"title": "apples", "completed": false, "note": "old"}),
    )
    .await;
    create(
        &a,
        2,
        "items",
        json!({"title": "bread", "completed": false, "note": "stale"}),
    )
    .await;
    for member in [&c, &d, &e] {
        member.sync().await.expect("sync");
    }
    for member in [&c, &d, &e] {
        member
            .ok(json!({"type": "networking_control", "enabled": false}))
            .await;
    }
    // A (note) -> B (no note) -> C (note again), each a `continue` seal.
    a.close().await;
    let removed = Device::new(common::confirmed(open(
        &directory("a"),
        &version(common::SCHEMA, 2),
        None,
    ))?)?;
    let removed_manifest = generation(&removed).await["manifest"]
        .as_str()
        .ok_or("manifest")?
        .to_owned();
    removed.close().await;
    let a = Device::new(Database::open(open(
        &directory("a"),
        &version(NOTED, 3),
        network("a"),
    ))?)?;
    assert_eq!(generation(&a).await["current"]["schema"], 3);
    let notes = "SELECT title, note FROM items ORDER BY title";
    let empty = json!([[text("apples"), {"type": "null"}], [text("bread"), {"type": "null"}]]);
    assert_eq!(rows(&a, notes).await, empty);
    // d, still at A, writes the note after the removal was sealed.
    d.set(3, &apples, "note", json!("late")).await;

    // c follows `main` from A to C at once: B's schema is on the path.
    hub.record("c");
    c.ok(json!({"type":"networking_control", "enabled":true}))
        .await;
    c.sync().await.expect("sync");
    assert_eq!(generation(&c).await["current"]["schema"], 3);
    let request = serde_json::to_vec(
        &json!({"manifest":data_encoding::HEXLOWER.decode(removed_manifest.as_bytes())?}),
    )?;
    assert!(
        hub.transcript("c")
            .windows(request.len())
            .any(|bytes| bytes == request),
        "B must be fetched from the only provider, which follows C"
    );

    assert_eq!(rows(&c, notes).await, empty);
    // d's late write crosses B: its note reaches no device, d's included.
    d.ok(json!({"type": "networking_control", "enabled": true}))
        .await;
    d.sync().await.expect("sync");
    assert_eq!(generation(&d).await["current"]["schema"], 3);
    // The unsent write touched only the removed field: it is held whole,
    // for d's application, and dropping it writes nothing.
    let held = d.ok(json!({"type": "held_changes"})).await;
    assert_eq!(held["count"], 1, "{held}");
    assert_eq!(held_field(&held, "items", "note")["value"], text("late"));
    d.ok(json!({"type": "drop_held", "id": held["changes"][0]["id"]}))
        .await;
    assert_eq!(generation(&d).await["held"], 0);
    for device in [&a, &c, &d] {
        device.sync().await.expect("sync");
        assert_eq!(rows(device, notes).await, empty);
    }
    // A write at C carries the field again.
    a.set(4, &apples, "note", json!("current")).await;
    let expected = json!([[text("apples"), text("current")], [text("bread"), {"type": "null"}]]);
    // e held the first rows with their notes; following strips them.
    e.ok(json!({"type": "networking_control", "enabled": true}))
        .await;
    for device in [&c, &d, &e] {
        device.sync().await.expect("sync");
    }
    for device in [&a, &c, &d, &e] {
        assert_eq!(generation(device).await["current"]["schema"], 3);
        assert_eq!(rows(device, notes).await, expected);
    }
    for device in [&c, &d, &e, &a] {
        device.close().await;
    }
    Ok(())
}

/// Runs `statements` as one transaction committed under `handle`, with
/// `extra` fields on the COMMIT request.
async fn transaction(device: &Device, handle: u8, statements: &[&str], extra: Value) -> Value {
    let _scope: Value = serde_json::from_str(&device.database.scope()).expect("scope");

    device.ok(json!({"type": "sql", "sql": "BEGIN"})).await;
    for sql in statements {
        device.ok(json!({"type": "sql", "sql": sql})).await;
    }
    let mut commit = json!({"type": "sql", "sql": "COMMIT", "handle": vec![handle; 32]});
    if let (Some(commit), Some(extra)) = (commit.as_object_mut(), extra.as_object()) {
        commit.extend(extra.clone());
    }
    device.ok(commit).await
}
/// The held change's row of `table` and its field `name`.
fn held_field<'a>(held: &'a Value, table: &str, name: &str) -> &'a Value {
    held["changes"][0]["rows"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["table"] == table))
        .and_then(|row| row["fields"].as_array())
        .and_then(|fields| fields.iter().find(|field| field["name"] == name))
        .unwrap_or(&Value::Null)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unsent_change_a_removal_splits_is_held_and_reauthored_after_the_update()
-> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::new(Database::create(open(&a_dir, SHELVED, network("a")), None)?)?;
    a.follow_main_migrating().await;
    let b = Device::new(Database::join(
        open(&b_dir, SHELVED, network("b")),
        &a.invite_as(json!({"kind": "writer", "scopes": ["items", "shelves"]}))
            .await,
    )?)?;
    introduce(&a, &b).await;
    create(
        &a,
        1,
        "items",
        json!({"title": "apples", "completed": false}),
    )
    .await;
    create(
        &a,
        2,
        "items",
        json!({"title": "bread", "completed": false}),
    )
    .await;
    b.sync().await.expect("sync");
    // Offline, the member edits a kept table and the table the next
    // version removes in one transaction, and never sends it.
    let _scope: Value = serde_json::from_str(&b.database.scope())?;

    b.ok(json!({"type": "sql", "sql": "BEGIN"})).await;
    b.ok(
        json!({"type": "sql", "sql": "UPDATE items SET title='green apples' WHERE title='apples'"}),
    )
    .await;
    let id = b.ok(json!({"type": "next_id", "table": "shelves"})).await["id"].clone();
    b.ok(json!({
        "type": "sql",
        "sql": "INSERT INTO shelves(key,label,id) VALUES('cellar','cellar',?)",
        "values": [{"type": "integer", "value": id.to_string().trim_matches('"')}],
    }))
    .await;
    b.ok(json!({"type": "sql", "sql": "COMMIT", "handle": vec![3; 32]}))
        .await;
    assert_eq!(b.titles().await, ["bread", "green apples"]);

    a.close().await;
    let a = Device::new(common::confirmed(open(&a_dir, UNSHELVED, network("a")))?)?;
    b.close().await;
    let b = Device::new(Database::open(open(&b_dir, UNSHELVED, network("b")))?)?;
    b.sync().await.expect("sync");
    b.sync().await.expect("sync");
    // Held whole: its kept edit is rolled back at once, on both.
    assert_eq!(generation(&b).await["current"]["schema"], 2);
    assert_eq!(generation(&b).await["held"], 1);
    a.sync().await.expect("sync");
    for device in [&a, &b] {
        assert_eq!(device.titles().await, ["apples", "bread"]);
    }
    let held = b.ok(json!({"type": "held_changes"})).await;
    assert_eq!(held["count"], 1);
    let title = held_field(&held, "items", "title");
    assert_eq!(
        (&title["written"], &title["value"]),
        (&json!(true), &text("green apples"))
    );
    assert_eq!(title["current"]["value"], text("apples"));
    assert_eq!(held_field(&held, "shelves", "label")["removed"], true);

    // Its frames are voided: the member's later edits reach the issuer.
    write(
        &b,
        "items",
        4,
        "UPDATE items SET completed=1 WHERE title='bread'",
    )
    .await;
    b.sync().await.expect("sync");
    let completed = "SELECT title, completed FROM items WHERE completed=1";
    assert_eq!(
        rows(&a, completed).await,
        json!([[text("bread"), {"type": "integer", "value": "1"}]])
    );

    // The issuer writes meanwhile; after the update the held change lists
    // that newer value, and re-authoring wins over it on every device.
    write(
        &a,
        "items",
        5,
        "UPDATE items SET title='red apples' WHERE title='apples'",
    )
    .await;
    b.close().await;
    let b = Device::new(Database::open(open(&b_dir, UNSHELVED, network("b")))?)?;
    b.sync().await.expect("sync");
    let held = b.ok(json!({"type": "held_changes"})).await;
    let current = &held_field(&held, "items", "title")["current"];
    assert_eq!(current["value"], text("red apples"));
    assert!(current["time"].as_u64() > held["changes"][0]["time"].as_u64());
    let id = held["changes"][0]["id"].clone();
    transaction(
        &b,
        6,
        &["UPDATE items SET title='green apples' WHERE title='red apples'"],
        json!({"reauthors": id}),
    )
    .await;
    assert_eq!(b.ok(json!({"type": "held_changes"})).await["count"], 0);
    b.sync().await.expect("sync");
    for device in [&a, &b] {
        assert_eq!(device.titles().await, ["bread", "green apples"]);
    }
    a.close().await;
    b.close().await;
    Ok(())
}

fn confirmation(
    result: Result<rocky_sdk::Opened, Failure>,
) -> rocky_sdk::RolloutConfirmationRequired {
    *result
        .err()
        .expect("confirmation required")
        .downcast::<rocky_sdk::RolloutConfirmationRequired>()
        .expect("structured report")
}

struct NeverStarts(std::sync::atomic::AtomicBool);
impl rocky_sdk::transport::Connector for NeverStarts {
    fn start(
        &self,
        _: bool,
        _: [u8; 32],
    ) -> rocky_sdk::transport::BoxFuture<
        '_,
        Result<Arc<dyn rocky_sdk::transport::Transport>, Failure>,
    > {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Err("network must not start before confirmation".into()) })
    }
}
fn files(path: &Path) -> Result<Vec<(std::path::PathBuf, String)>, Failure> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let path = entry?.path();
        if path.is_dir() {
            found.extend(files(&path)?);
        } else if !path.file_name().is_some_and(|name| {
            name == "rocky.sqlite-shm"
                || (name == "rocky.sqlite-wal" && path.metadata().is_ok_and(|file| file.len() == 0))
        }) {
            found.push((
                path.clone(),
                data_encoding::HEXLOWER
                    .encode(&rocky_core::commitment("test.file", &std::fs::read(path)?)),
            ));
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(found)
}

#[tokio::test(flavor = "multi_thread")]
async fn removing_open_changes_nothing_and_only_the_current_report_can_sign() -> Result<(), Failure>
{
    let root = common::identity::small_directory()?;
    let directory = root.path();
    let a = Device::new(Database::create(open(directory, SHELVED, None), None)?)?;
    a.follow_main_migrating().await;
    create(&a, 1, "shelves", json!({"label": "pantry"})).await;
    create(
        &a,
        2,
        "items",
        json!({"title": "apples", "completed": false, "category": "fruit"}),
    )
    .await;
    a.close().await;
    let identity = std::fs::read(directory.join("identity.json"))?;
    let database = std::fs::read(directory.join("rocky.sqlite"))?;
    let before = files(directory)?;
    let network = Arc::new(NeverStarts(std::sync::atomic::AtomicBool::new(false)));
    let required = confirmation(Database::open(open(
        directory,
        UNSHELVED,
        Some(Network::Owned(network.clone())),
    )));
    assert!(!network.0.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(files(directory)?, before);
    assert!(!required.mismatch);
    assert_eq!(
        required.report.tables,
        [rocky_sdk::RemovalImpact {
            name: "shelves".into(),
            rows: 1
        }]
    );
    assert_eq!(
        required.report.fields,
        [
            rocky_sdk::RemovalImpact {
                name: "items.category".into(),
                rows: 1
            },
            rocky_sdk::RemovalImpact {
                name: "items.shelf".into(),
                rows: 1
            },
        ]
    );
    assert_eq!(std::fs::read(directory.join("identity.json"))?, identity);
    assert_eq!(std::fs::read(directory.join("rocky.sqlite"))?, database);
    let changed = UNSHELVED.replace(r#""version":2"#, r#""version":3"#);
    let stale = confirmation(Database::open_confirmed(
        open(directory, &changed, None),
        &required.report.digest,
    ));
    assert!(stale.mismatch);
    assert_ne!(stale.report.digest, required.report.digest);
    assert_eq!(std::fs::read(directory.join("identity.json"))?, identity);
    assert_eq!(std::fs::read(directory.join("rocky.sqlite"))?, database);
    // Opening the old schema remains possible after cancellation.
    let a = Device::new(Database::open(open(directory, SHELVED, None))?)?;
    create(
        &a,
        3,
        "items",
        json!({"title": "bread", "completed": false}),
    )
    .await;
    a.close().await;
    let stale = confirmation(Database::open_confirmed(
        open(directory, UNSHELVED, None),
        &required.report.digest,
    ));
    assert!(stale.mismatch);
    assert_eq!(stale.report.fields[0].rows, 2);
    let a = Device::new(Database::open_confirmed(
        open(directory, UNSHELVED, None),
        &stale.report.digest,
    )?)?;
    assert_eq!(generation(&a).await["current"]["schema"], 2);
    a.close().await;
    let (_, columns) = schema_of(directory)?;
    assert!(!columns.contains(&"category".into()));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_member_cannot_confirm_an_unsigned_removal_and_waits_for_an_issuer() -> Result<(), Failure>
{
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::new(Database::create(open(&a_dir, SHELVED, network("a")), None)?)?;
    a.follow_main_migrating().await;
    let b = Device::new(Database::join(
        open(&b_dir, SHELVED, network("b")),
        &a.invite_as(json!({"kind": "writer", "scopes": ["items", "shelves"]}))
            .await,
    )?)?;
    b.close().await;
    let b = Device::new(Database::open_confirmed(
        open(&b_dir, UNSHELVED, None),
        "arbitrary",
    )?)?;
    let status = generation(&b).await;
    assert_eq!(status["current"]["schema"], 1);
    assert_eq!(status["application"], "ahead");
    assert_eq!(status["waiting_for_issuer"], true);
    assert!(
        b.database
            .session()
            .status()
            .await?
            .data
            .generation
            .waiting_for_issuer
    );
    b.close().await;
    a.close().await;
    assert!(schema_of(&b_dir)?.1.contains(&"category".into()));
    let a = Device::new(common::confirmed(open(&a_dir, UNSHELVED, network("a")))?)?;
    let b = Device::new(Database::open(open(&b_dir, UNSHELVED, network("b")))?)?;
    introduce(&a, &b).await;
    b.sync().await.expect("follow the issuer's removal");
    assert_eq!(generation(&b).await["current"]["schema"], 2);
    assert_eq!(generation(&b).await["waiting_for_issuer"], false);
    a.close().await;
    b.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_impact_report_counts_constraint_suppressed_rows_and_all_local_partitions()
-> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let a_dir = root.path().join("unique");
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let a = Device::new(Database::create(open(&a_dir, SHELVED, network("a")), None)?)?;
    a.follow_main_migrating().await;
    let peer_dir = root.path().join("peer");
    let peer = Device::new(Database::join(
        open(&peer_dir, SHELVED, network("peer")),
        &a.invite_as(json!({"kind":"writer", "scopes":["items", "shelves"]}))
            .await,
    )?)?;
    introduce(&a, &peer).await;
    create(
        &a,
        1,
        "items",
        json!({"title":"apples", "completed":false, "category":"same"}),
    )
    .await;
    create(
        &peer,
        2,
        "items",
        json!({"title":"bread", "completed":false, "category":"same"}),
    )
    .await;
    peer.sync().await.expect("conflicting writes sync");
    assert_eq!(a.titles().await.len(), 1);
    peer.close().await;
    a.close().await;
    let report = confirmation(Database::open(open(&a_dir, UNSHELVED, None))).report;
    assert_eq!(report.fields[0].rows, 2);

    let b_dir = root.path().join("partitioned");
    let mut schema: Value = serde_json::from_str(NOTED)?;
    schema["tables"][0]["columns"]
        .as_array_mut()
        .ok_or("columns")?
        .push(json!({"name":"list", "type":"text", "not_null":true}));
    schema["tables"][0]["partition_by"] = json!(["list"]);
    schema["tables"][0]["primary_key"] = json!(["list", "key"]);
    let before = schema.to_string();
    let b = Device::new(Database::create(open(&b_dir, &before, None), None)?)?;
    b.follow_main_migrating().await;
    for (handle, list) in [(1, "first"), (2, "second")] {
        b.ok(json!({"type":"partition_create", "table":"items", "values":[text(list)]}))
            .await;
        let _scope: Value = serde_json::from_str(&b.database.scope())?;

        b.ok(json!({"type":"sql", "sql":"BEGIN"})).await;
        let id = b
            .ok(json!({"type":"next_id", "table":"items", "partition_values":[text(list)]}))
            .await["id"]
            .clone();
        b.ok(json!({"type":"sql", "sql":"INSERT INTO items(list,key,title,completed,note,id) VALUES(?,?,?,?,?,?)",
            "values":[text(list), text("key"), text(list), {"type":"integer", "value":"0"}, text("old"), {"type":"integer", "value":id}]})).await;
        b.ok(json!({"type":"sql", "sql":"COMMIT", "handle":vec![handle; 32]}))
            .await;
    }
    b.close().await;
    schema["version"] = json!(2);
    schema["tables"][0]["columns"]
        .as_array_mut()
        .ok_or("columns")?
        .retain(|column| column["name"] != "note");
    let report = confirmation(Database::open(open(&b_dir, &schema.to_string(), None))).report;
    assert_eq!(
        report.fields,
        [rocky_sdk::RemovalImpact {
            name: "items.note".into(),
            rows: 2
        }]
    );
    Ok(())
}
