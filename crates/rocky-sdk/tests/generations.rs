//! Schema changes as seals: an issuer publishes the schema its application
//! declares on the followed bookmark, and every device switches when its
//! bookmark reaches it. See `docs/runtime/generations.md`.
mod common;
use common::{Device, Failure, SCHEMA, introduce};
use rocky_sdk::{Database, Network, Open, transport::memory::Hub};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

/// The shopping schema with a nullable note and a tags collection.
const SECOND: &str = r#"{"application":"shopping","version":2,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"note","type":"text","not_null":false},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]},{"name":"tags","granted_like":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"label","type":"text","not_null":true}],"primary_key":["key"]}]}"#;
/// The second schema, with `tags` granted like `items`.
const GRANTED: &str = r#"{"application":"shopping","version":2,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"note","type":"text","not_null":false},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]},{"name":"tags","granted_like":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"label","type":"text","not_null":true}],"primary_key":["key"]}]}"#;
/// Requires `position`, which a migration computes from the titles.
const REQUIRED: &str = r#"{"application":"shopping","version":2,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"position","type":"text","not_null":true,"default":""},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]}],"migrations":[{"version":2,"statements":["UPDATE items SET position = printf('%04d', (SELECT count(*) FROM items AS earlier WHERE earlier.title < items.title))"]}]}"#;
/// `position` nullable, and `BARE` requiring it without a migration.
const NULLABLE: &str = r#"{"application":"shopping","version":1,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"position","type":"text","not_null":false},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]}]}"#;
const BARE: &str = r#"{"application":"shopping","version":2,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"position","type":"text","not_null":true,"default":""},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]}]}"#;
/// Titles are unique, the later write winning: requiring a field rebuilds
/// a constrained projection.
const UNIQUE: &str = r#"{"application":"shopping","version":1,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"title","type":"text","not_null":true}],"primary_key":["key"],"indexes":[{"name":"items_title","unique":true,"columns":[{"name":"title","descending":false}]}]}]}"#;
const UNIQUE_REQUIRED: &str = r#"{"application":"shopping","version":2,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"position","type":"text","not_null":true,"default":""},{"name":"title","type":"text","not_null":true}],"primary_key":["key"],"indexes":[{"name":"items_title","unique":true,"columns":[{"name":"title","descending":false}]}]}],"migrations":[{"version":2,"statements":["UPDATE items SET position = upper(title)"]}]}"#;
/// The second schema with a nullable `rank`.
const THIRD: &str = r#"{"application":"shopping","version":3,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"note","type":"text","not_null":false},{"name":"rank","type":"integer","not_null":false},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]},{"name":"tags","granted_like":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"label","type":"text","not_null":true}],"primary_key":["key"]}]}"#;

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
async fn generation(device: &Device) -> Value {
    device.ok(json!({"type": "generation"})).await
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

/// Hex of the followed tip a device reports.
async fn tip(device: &Device) -> Value {
    device.ok(json!({"type": "tips", "action": "status"})).await["tip"].clone()
}
/// Mutates a `tags` row of `label`.
async fn tag(device: &Device, handle: u8, label: &str) {
    device
        .ok(json!({
            "type": "mutate",
            "handle": vec![handle; 32],
            "payload": json!({"type": "create", "collection": "tags", "values": {"label": label}}).to_string().into_bytes(),
            "entity": null,
            "baseline": null,
        }))
        .await;
}
/// Re-authors the held change `held` as one insert into `table`, with the
/// next id of `table` bound to `sql`'s one parameter.
async fn reauthor(device: &Device, handle: u8, table: &str, sql: &str, held: Value) {
    device.ok(json!({"type": "sql", "sql": "BEGIN"})).await;
    let id = device.ok(json!({"type": "next_id", "table": table})).await["id"].clone();
    device
        .ok(json!({
            "type": "sql",
            "sql": sql,
            "values": [{"type": "integer", "value": id.to_string().trim_matches('"')}],
        }))
        .await;
    device
        .ok(json!({"type": "sql", "sql": "COMMIT", "handle": vec![handle; 32], "reauthors": held}))
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_old_member_follows_main_to_a_published_schema_and_reports_behind() -> Result<(), Failure>
{
    let root = tempfile::tempdir()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::create(&a_dir, network("a"))?;
    a.follow_main_migrating().await;
    let b = Device::join(
        &b_dir,
        &a.invite().await,
        Network::Owned(hub.connector("b")),
    )?;
    introduce(&a, &b).await;
    b.sync().await.expect("initial idle sync");
    let before = tip(&b).await;
    a.close().await;
    // The issuer's application declares the second schema: it publishes
    // a `continue` seal naming it and moves `main`.
    let a = Device::new(Database::open(open(&a_dir, SECOND, network("a")))?)?;
    assert_eq!(generation(&a).await["current"]["schema"], 2);
    let published = tip(&a).await;
    assert_ne!(published, before);
    // The member's application still declares the first: following
    // `main` installs the second, which it reads as an older application.
    b.sync().await.expect("follow the published schema");
    let status = generation(&b).await;
    assert_eq!(status["current"]["schema"], 2, "{status}");
    assert_eq!(status["application"], "behind");
    assert_eq!(status["pending"], Value::Null);
    assert_eq!(tip(&b).await, published);
    b.add(1, "apples").await;
    b.sync().await.expect("sync");
    assert_eq!(
        rows(&a, "SELECT title, note FROM items").await,
        json!([[text("apples"), {"type": "null"}]])
    );
    b.close().await;
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_member_ahead_waits_for_the_issuer_and_its_unsent_writes_cross_the_seal()
-> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::create(&a_dir, network("a"))?;
    a.follow_main_migrating().await;
    let b = Device::join(
        &b_dir,
        &a.invite().await,
        Network::Owned(hub.connector("b")),
    )?;
    introduce(&a, &b).await;
    let apples = b.add(1, "apples").await;
    b.sync().await.expect("sync");
    assert_eq!(a.titles().await, ["apples"]);
    // Bread has not left the member when the issuer publishes.
    b.add(2, "bread").await;
    a.close().await;

    let a = Device::new(Database::open(open(&a_dir, SECOND, network("a")))?)?;
    let status = generation(&a).await;
    assert_eq!(status["current"], json!({"schema": 2}));
    assert_eq!(status["application"], "current");
    assert_eq!(status["rebuilding"], Value::Null);
    assert!(status.get("previous").is_none() && status.get("baseline").is_none());
    assert_eq!(
        rows(&a, "SELECT title, note FROM items").await,
        json!([[text("apples"), {"type": "null"}]])
    );
    a.set(3, &apples, "note", json!("fresh")).await;
    tag(&a, 4, "fruit").await;

    // A member whose application declares the newer schema waits for its
    // bookmark to reach it; it never publishes.
    b.close().await;
    let ahead = Device::new(Database::open(open(&b_dir, SECOND, None))?)?;
    let status = generation(&ahead).await;
    assert_eq!(status["current"]["schema"], 1);
    assert_eq!(status["application"], "ahead");
    assert_eq!(status["waiting_for_issuer"], true);
    assert_eq!(ahead.titles().await, ["apples", "bread"]);
    ahead.close().await;

    // Following `main` switches it. Bread, written before the seal, is a
    // late frame across a `continue` and applies on every device.
    let b = Device::new(Database::open(open(&b_dir, SECOND, network("b")))?)?;
    b.sync().await.expect("sync");
    let status = generation(&b).await;
    assert_eq!(status["current"]["schema"], 2);
    assert_eq!(status["application"], "current");
    assert_eq!(status["waiting_for_issuer"], false);
    b.sync().await.expect("sync");
    for device in [&a, &b] {
        assert_eq!(device.titles().await, ["apples", "bread"]);
    }
    assert_eq!(
        rows(&b, "SELECT note FROM items WHERE title='apples'").await,
        json!([[text("fresh")]])
    );
    b.close().await;
    let b = Device::new(Database::open(open(&b_dir, SECOND, network("b")))?)?;
    assert_eq!(generation(&b).await["application"], "current");
    // Its profile names `items`; `tags` is granted like `items`.
    assert_eq!(
        rows(&b, "SELECT label FROM tags").await,
        json!([[text("fruit")]])
    );
    b.close().await;

    // A change no seal can carry is refused before anything changes.
    a.close().await;
    let retyped = RETYPED.replace(r#""version":2"#, r#""version":3"#);
    let refused = Database::open(open(&a_dir, &retyped, network("a")));
    let error = refused.err().expect("refused").to_string();
    assert!(error.contains("changed type"), "{error}");
    let a = Device::new(Database::open(open(&a_dir, SECOND, network("a")))?)?;
    assert_eq!(generation(&a).await["current"]["schema"], 2);
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_table_granted_like_another_reaches_existing_members() -> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::create(&a_dir, network("a"))?;
    a.follow_main_migrating().await;
    // Raw grants name `items` alone, as an application's device kinds do.
    let invitation = a
        .invite_as(json!({"kind": "grants", "grants": [{"scope": "items", "rights": ["read", "insert", "update", "delete"]}]}))
        .await;
    let b = Device::join(&b_dir, &invitation, Network::Owned(hub.connector("b")))?;
    introduce(&a, &b).await;
    b.close().await;
    a.close().await;

    let a = Device::new(Database::open(open(&a_dir, GRANTED, network("a")))?)?;
    let b = Device::new(Database::open(open(&b_dir, GRANTED, network("b")))?)?;
    // Adopting renews nothing; the next sync asks the issuer once for the
    // grant and key of the table that follows `items`.
    let before = chain(&b_dir)?;
    b.sync().await.expect("sync");
    assert_ne!(chain(&b_dir)?, before);
    b.ok(json!({
        "type": "mutate",
        "handle": vec![5; 32],
        "payload": json!({"type": "create", "collection": "tags", "values": {"label": "fruit"}}).to_string().into_bytes(),
        "entity": null,
        "baseline": null,
    }))
    .await;
    b.sync().await.expect("sync");
    assert_eq!(
        rows(&a, "SELECT label FROM tags").await,
        json!([[text("fruit")]])
    );
    b.close().await;
    a.close().await;

    // Changing whom an existing table is granted like would change what
    // earlier grants mean: the next version is refused before anything.
    let ungranted = GRANTED
        .replace(r#""version":2"#, r#""version":3"#)
        .replace(r#""granted_like":"items","#, "");
    let error = Database::open(open(&a_dir, &ungranted, network("a")))
        .err()
        .expect("refused")
        .to_string();
    assert!(error.contains("changed whom it is granted like"), "{error}");
    let a = Device::new(Database::open(open(&a_dir, GRANTED, network("a")))?)?;
    assert_eq!(generation(&a).await["current"]["schema"], 2);
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_old_device_offline_across_a_migration_gets_its_writes_back_and_reauthors_them()
-> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let dirs = |name: &str| root.path().join(name);
    let a = Device::create(&dirs("a"), network("a"))?;
    a.follow_main_migrating().await;
    let b = Device::join(
        &dirs("b"),
        &a.invite().await,
        Network::Owned(hub.connector("b")),
    )?;
    let c = Device::join(
        &dirs("c"),
        &a.invite().await,
        Network::Owned(hub.connector("c")),
    )?;
    introduce(&a, &b).await;
    introduce(&a, &c).await;
    a.add(1, "cherries").await;
    a.add(2, "apples").await;
    b.add(3, "bread").await;
    b.sync().await.expect("sync");
    c.sync().await.expect("sync");
    b.close().await;
    a.close().await;

    // The issuer closes `main`, opens the migration's tip and migrates
    // there: the migration is the new tip's first signed write.
    let a = Device::new(Database::open(open(&dirs("a"), REQUIRED, network("a")))?)?;
    let status = generation(&a).await;
    assert_eq!(status["current"]["schema"], 2, "{status}");
    assert_eq!(status["application"], "current");
    let positions = json!([
        [text("apples"), text("0000")],
        [text("bread"), text("0001")],
        [text("cherries"), text("0002")]
    ]);
    assert_eq!(
        rows(&a, "SELECT title, position FROM items ORDER BY position").await,
        positions
    );

    // An old application, offline, writes the closed tip. A migration
    // admits no late frames: its write returns to it as a held change.
    c.add(6, "stale").await;
    c.sync().await.expect("sync");
    c.sync().await.expect("sync");
    let status = generation(&c).await;
    assert_eq!(status["current"]["schema"], 2, "{status}");
    assert_eq!(status["application"], "behind");
    assert_eq!(status["held"], 1);
    assert_eq!(a.titles().await, ["apples", "bread", "cherries"]);
    assert_eq!(
        rows(&c, "SELECT title, position FROM items ORDER BY position").await,
        positions
    );
    let held = c.ok(json!({"type": "held_changes"})).await;
    assert_eq!(held["count"], 1);
    // Its application re-authors the write on the new tip; it converges.
    let id = held["changes"][0]["id"].clone();
    reauthor(
        &c,
        7,
        "items",
        "INSERT INTO items(key,completed,position,title,id) VALUES('stale',0,'','stale',?)",
        id,
    )
    .await;
    assert_eq!(c.ok(json!({"type": "held_changes"})).await["count"], 0);
    c.sync().await.expect("sync");
    assert_eq!(a.titles().await, ["apples", "bread", "cherries", "stale"]);
    c.close().await;

    // A member updated to the new application writes the new tip directly.
    let b = Device::new(Database::open(open(&dirs("b"), REQUIRED, network("b")))?)?;
    b.sync().await.expect("sync");
    assert_eq!(generation(&b).await["application"], "current");
    b.ok(json!({
        "type": "mutate",
        "handle": vec![5; 32],
        "payload": json!({"type": "create", "collection": "items", "values": {"title": "dates", "completed": false, "position": "0003"}}).to_string().into_bytes(),
        "entity": null,
        "baseline": null,
    }))
    .await;
    b.sync().await.expect("sync");
    assert_eq!(
        a.titles().await,
        ["apples", "bread", "cherries", "dates", "stale"]
    );
    // The migration's rows were written once.
    assert_eq!(
        rows(&b, "SELECT count(*) FROM items").await,
        json!([[{"type": "integer", "value": "5"}]])
    );
    b.close().await;
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn requiring_a_nullable_field_converts_retained_nulls_on_every_follower()
-> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let dirs = |name: &str| root.path().join(name);
    let a = Device::new(Database::create(
        open(&dirs("a"), NULLABLE, network("a")),
        None,
    )?)?;
    a.follow_main_migrating().await;
    let b = Device::new(Database::join(
        open(&dirs("b"), NULLABLE, network("b")),
        &a.invite().await,
    )?)?;
    let c = Device::new(Database::join(
        open(&dirs("c"), NULLABLE, network("c")),
        &a.invite().await,
    )?)?;
    introduce(&a, &b).await;
    introduce(&a, &c).await;
    a.add(1, "apples").await;
    b.sync().await.expect("sync");
    c.sync().await.expect("sync");
    b.add(2, "bread").await;
    b.sync().await.expect("sync");
    c.sync().await.expect("sync");
    a.close().await;

    // Requiring a field that was nullable rewrites its stored NULLs as the
    // default in the switch, without a migration.
    let a = Device::new(Database::open(open(&dirs("a"), BARE, network("a")))?)?;
    assert_eq!(generation(&a).await["current"]["schema"], 2);
    assert_eq!(
        rows(&a, "SELECT title, position FROM items ORDER BY title").await,
        json!([[text("apples"), text("")], [text("bread"), text("")]])
    );

    // The retained generation 1 NULL reads as the default on each device
    // that follows the bookmark to the new schema.
    assert_eq!(
        rows(&b, "SELECT position FROM items WHERE title='bread'").await,
        json!([[{"type": "null"}]])
    );
    b.close().await;
    c.close().await;
    let b = Device::new(Database::open(open(&dirs("b"), BARE, network("b")))?)?;
    let c = Device::new(Database::open(open(&dirs("c"), BARE, network("c")))?)?;
    b.sync().await.expect("sync");
    c.sync().await.expect("sync");
    for device in [&a, &b, &c] {
        assert_eq!(generation(device).await["current"]["schema"], 2);
        assert_eq!(
            rows(device, "SELECT title, position FROM items ORDER BY title").await,
            json!([[text("apples"), text("")], [text("bread"), text("")]])
        );
    }
    c.close().await;
    b.close().await;
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn requiring_a_field_rebuilds_tables_with_unique_indexes() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let a = Device::new(Database::create(open(root.path(), UNIQUE, None), None)?)?;
    a.follow_main_migrating().await;
    a.add(1, "apples").await;
    a.add(2, "bread").await;
    a.close().await;
    let a = Device::new(Database::open(open(root.path(), UNIQUE_REQUIRED, None))?)?;
    assert_eq!(generation(&a).await["current"]["schema"], 2);
    assert_eq!(
        rows(&a, "SELECT title, position FROM items ORDER BY position").await,
        json!([
            [text("apples"), text("APPLES")],
            [text("bread"), text("BREAD")]
        ])
    );
    // The rebuilt index still refuses a local duplicate, and the table takes new rows.
    let duplicate = a
        .call(json!({
            "type": "mutate",
            "handle": vec![3; 32],
            "payload": json!({"type": "create", "collection": "items", "values": {"title": "apples", "completed": false, "position": "Z"}}).to_string().into_bytes(),
            "entity": null,
            "baseline": null,
        }))
        .await
        .expect_err("unique");
    assert!(
        duplicate["message"]
            .as_str()
            .is_some_and(|message| message.contains("UNIQUE"))
    );
    a.ok(json!({
        "type": "mutate",
        "handle": vec![4; 32],
        "payload": json!({"type": "create", "collection": "items", "values": {"title": "cherries", "completed": false, "position": "CHERRIES"}}).to_string().into_bytes(),
        "entity": null,
        "baseline": null,
    }))
    .await;
    assert_eq!(a.titles().await, ["apples", "bread", "cherries"]);
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_local_schema_change_rebuilds_tables_and_keeps_the_generation() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let a = Device::create(root.path(), None)?;
    a.follow_main_migrating().await;
    a.add(1, "apples").await;
    a.close().await;
    // The application's own version is local: the manifest stays.
    let bumped = SCHEMA.replace(r#""version":1"#, r#""version":7"#);
    let bumped: &'static str = Box::leak(bumped.into_boxed_str());
    let a = Device::new(Database::open(open(root.path(), bumped, None))?)?;
    let status = generation(&a).await;
    assert_eq!(status["current"], json!({"schema": 1}));
    assert_eq!(a.titles().await, ["apples"]);
    a.close().await;
    Ok(())
}

/// The first schema with `title` an integer: the same name, another type.
const RETYPED: &str = r#"{"application":"shopping","version":2,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"title","type":"integer","not_null":true}],"primary_key":["key"]}]}"#;
/// The first schema with `title` renamed `label`: another field.
const RENAMED: &str = r#"{"application":"shopping","version":2,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"label","type":"text","not_null":true}],"primary_key":["key"]}]}"#;

#[tokio::test(flavor = "multi_thread")]
async fn a_name_keeps_its_type_and_a_rename_is_another_field() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let a = Device::create(root.path(), None)?;
    a.follow_main_migrating().await;
    a.add(1, "apples").await;
    a.close().await;
    // A rename removes the old field and adds a new one, which a required
    // field cannot be without a default.
    for (schema, refusal) in [(RETYPED, "changed type"), (RENAMED, "needs a default")] {
        let error = Database::open(open(root.path(), schema, None))
            .err()
            .expect("refused")
            .to_string();
        assert!(error.contains(refusal), "{error}");
    }
    let a = Device::new(Database::open(open(root.path(), SCHEMA, None))?)?;
    assert_eq!(generation(&a).await["current"]["schema"], 1);
    assert_eq!(a.titles().await, ["apples"]);
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_older_application_follows_two_published_schemas_and_keeps_its_unsent_rows()
-> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::create(&a_dir, network("a"))?;
    a.follow_main_migrating().await;
    let b = Device::join(
        &b_dir,
        &a.invite().await,
        Network::Owned(hub.connector("b")),
    )?;
    introduce(&a, &b).await;
    let apples = b.add(1, "apples").await;
    b.sync().await.expect("sync");
    a.close().await;
    // The issuer publishes two schemas while the member's application
    // stays at version 1 and writes offline.
    Device::new(Database::open(open(&a_dir, SECOND, None))?)?
        .close()
        .await;
    let a = Device::new(Database::open(open(&a_dir, THIRD, network("a")))?)?;
    assert_eq!(generation(&a).await["current"]["schema"], 3);
    a.set(2, &apples, "rank", json!(7)).await;
    b.add(3, "bread").await;

    // Following `main` walks both seals at once; the row written before
    // them crosses both `continue` seals.
    b.sync().await.expect("sync");
    let status = generation(&b).await;
    assert_eq!(status["current"], json!({"schema": 3}), "{status}");
    assert_eq!(status["rebuilding"], Value::Null);
    assert_eq!(status["application"], "behind");
    b.sync().await.expect("sync");
    for device in [&a, &b] {
        assert_eq!(device.titles().await, ["apples", "bread"]);
    }
    assert_eq!(
        rows(&b, "SELECT rank FROM items WHERE title='apples'").await,
        json!([[{"type": "integer", "value": "7"}]])
    );
    b.close().await;
    let b = Device::new(Database::open(open(&b_dir, SCHEMA, network("b")))?)?;
    assert_eq!(generation(&b).await["current"]["schema"], 3);
    assert_eq!(b.titles().await, ["apples", "bread"]);
    b.close().await;
    a.close().await;
    Ok(())
}

/// The first schema with a nullable note: a switch that changes no grant.
const NOTED: &str = r#"{"application":"shopping","version":2,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"note","type":"text","not_null":false},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]}]}"#;
/// Copies the replica's files of `from` to `to`.
fn copy_replica(from: &Path, to: &Path) -> Result<(), Failure> {
    for name in ["rocky.sqlite", "rocky.sqlite-wal", "rocky.sqlite-shm"] {
        let _ = std::fs::remove_file(to.join(name));
        if from.join(name).exists() {
            std::fs::copy(from.join(name), to.join(name))?;
        }
    }
    Ok(())
}
/// `identity.json` with a pending switch to `tip` and `manifest`, as the
/// follower saves it before switching.
fn with_pending(identity: &[u8], tip: &Value, manifest: &Value) -> Result<Vec<u8>, Failure> {
    let bytes = |hex: &Value| -> Result<Value, Failure> {
        Ok(json!(
            data_encoding::HEXLOWER.decode(hex.as_str().ok_or("hex")?.as_bytes())?
        ))
    };
    let mut saved: Value = serde_json::from_slice(identity)?;
    saved["pending"] = json!({"tip": bytes(tip)?, "manifest": bytes(manifest)?});
    Ok(serde_json::to_vec(&saved)?)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_crash_on_either_side_of_the_switch_resumes_on_the_followed_schema() -> Result<(), Failure>
{
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::create(&a_dir, network("a"))?;
    a.follow_main_migrating().await;
    let b = Device::join(
        &b_dir,
        &a.invite().await,
        Network::Owned(hub.connector("b")),
    )?;
    introduce(&a, &b).await;
    b.add(1, "apples").await;
    b.sync().await.expect("sync");
    b.close().await;
    a.close().await;
    let a = Device::new(Database::open(open(&a_dir, NOTED, network("a")))?)?;
    let target = (tip(&a).await, generation(&a).await["manifest"].clone());
    // The member's files before it meets the published schema.
    let saved = root.path().join("saved");
    std::fs::create_dir(&saved)?;
    copy_replica(&b_dir, &saved)?;
    let identity = std::fs::read(b_dir.join("identity.json"))?;
    let b = Device::new(Database::open(open(&b_dir, NOTED, network("b")))?)?;
    b.sync().await.expect("sync");
    assert_eq!(generation(&b).await["current"]["schema"], 2);
    b.close().await;
    let switched = root.path().join("switched");
    std::fs::create_dir(&switched)?;
    copy_replica(&b_dir, &switched)?;

    // The intent was saved, then the replica committed the switch, then
    // the device stopped before saving its settings: it resumes there.
    std::fs::write(
        b_dir.join("identity.json"),
        with_pending(&identity, &target.0, &target.1)?,
    )?;
    let b = Device::new(Database::open(open(&b_dir, SCHEMA, None))?)?;
    let status = generation(&b).await;
    assert_eq!(status["current"]["schema"], 2, "{status}");
    assert_eq!(status["application"], "behind");
    assert_eq!(status["pending"], Value::Null);
    assert_eq!(
        rows(&b, "SELECT title, note FROM items").await,
        json!([[text("apples"), {"type": "null"}]])
    );
    b.close().await;

    // The intent was saved, the replica not yet switched: the next pass
    // switches; nothing is lost and the workspace waits meanwhile.
    copy_replica(&saved, &b_dir)?;
    std::fs::write(
        b_dir.join("identity.json"),
        with_pending(&identity, &target.0, &target.1)?,
    )?;
    let b = Device::new(Database::open(open(&b_dir, SCHEMA, network("b")))?)?;
    assert_eq!(generation(&b).await["current"]["schema"], 1);
    b.sync().await.expect("sync");
    let status = generation(&b).await;
    assert_eq!(status["current"]["schema"], 2, "{status}");
    assert_eq!(status["pending"], Value::Null);
    b.add(2, "bread").await;
    b.sync().await.expect("sync");
    assert_eq!(a.titles().await, ["apples", "bread"]);
    b.close().await;
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_crash_after_the_switch_and_a_same_schema_advance_reopens_on_the_target_schema()
-> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::create(&a_dir, network("a"))?;
    a.follow_main_migrating().await;
    let b = Device::join(
        &b_dir,
        &a.invite().await,
        Network::Owned(hub.connector("b")),
    )?;
    introduce(&a, &b).await;
    b.add(1, "apples").await;
    b.sync().await.expect("sync");
    b.close().await;
    a.close().await;
    let a = Device::new(Database::open(open(&a_dir, NOTED, network("a")))?)?;
    let target = (tip(&a).await, generation(&a).await["manifest"].clone());
    let identity = std::fs::read(b_dir.join("identity.json"))?;
    let b = Device::new(Database::open(open(&b_dir, NOTED, network("b")))?)?;
    b.sync().await.expect("sync");
    assert_eq!(tip(&b).await, target.0);
    // The owner seals the target with the same schema; the member's
    // replica follows main past it in the same commit as its switch.
    a.ok(json!({"type": "tips", "action": "seal"})).await;
    let advanced = tip(&a).await;
    assert_ne!(advanced, target.0);
    b.sync().await.expect("sync");
    assert_eq!(tip(&b).await, advanced);
    b.close().await;

    // The settings file still names the pending target: the committed
    // tip continues from it on its schema, so the reopen adopts it.
    std::fs::write(
        b_dir.join("identity.json"),
        with_pending(&identity, &target.0, &target.1)?,
    )?;
    let b = Device::new(Database::open(open(&b_dir, SCHEMA, None))?)?;
    let status = generation(&b).await;
    assert_eq!(status["current"]["schema"], 2, "{status}");
    assert_eq!(status["pending"], Value::Null);
    assert_eq!(tip(&b).await, advanced);
    assert_eq!(
        rows(&b, "SELECT title, note FROM items").await,
        json!([[text("apples"), {"type": "null"}]])
    );
    b.close().await;
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_older_application_joins_at_the_households_generation() -> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::create(&a_dir, network("a"))?;
    a.follow_main_migrating().await;
    let apples = a.add(1, "apples").await;
    a.close().await;
    let a = Device::new(Database::open(open(&a_dir, SECOND, network("a")))?)?;
    a.set(2, &apples, "note", json!("fresh")).await;
    // A device whose application declares version 1 joins: its database
    // starts at generation 2.
    let b = Device::new(Database::join(
        open(&b_dir, SCHEMA, network("b")),
        &a.invite().await,
    )?)?;
    introduce(&a, &b).await;
    b.sync().await.expect("sync");
    let status = generation(&b).await;
    assert_eq!(status["current"]["schema"], 2);
    assert_eq!(status["application"], "behind");
    assert_eq!(
        rows(&b, "SELECT title, note FROM items").await,
        json!([[text("apples"), text("fresh")]])
    );
    b.add(3, "bread").await;
    b.sync().await.expect("sync");
    assert_eq!(a.titles().await, ["apples", "bread"]);
    b.close().await;
    let b = Device::new(Database::open(open(&b_dir, SCHEMA, network("b")))?)?;
    assert_eq!(generation(&b).await["current"]["schema"], 2);
    b.close().await;
    a.close().await;
    Ok(())
}

/// The credential chain a device's identity holds.
fn chain(directory: &Path) -> Result<Value, Failure> {
    let identity: Value = serde_json::from_slice(&std::fs::read(directory.join("identity.json"))?)?;
    Ok(identity["credentials"].clone())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_member_fetches_a_required_schema_from_another_member_with_no_issuer_reachable()
-> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir, c_dir) = (
        root.path().join("a"),
        root.path().join("b"),
        root.path().join("c"),
    );
    let a = Device::create(&a_dir, network("a"))?;
    a.follow_main_migrating().await;
    let b = Device::join(
        &b_dir,
        &a.invite().await,
        Network::Owned(hub.connector("b")),
    )?;
    let c = Device::join(
        &c_dir,
        &a.invite().await,
        Network::Owned(hub.connector("c")),
    )?;
    introduce(&a, &b).await;
    introduce(&a, &c).await;
    introduce(&b, &c).await;
    let principal = b.ok(json!({"type":"session"})).await["principal"].clone();
    let trusted = a
        .ok(json!({"type":"tips", "action":"trust", "identity":principal}))
        .await;
    b.ok(json!({"type":"tips", "action":"install_trust", "grant":trusted["grant"]}))
        .await;
    let apples = c.add(1, "apples").await;
    c.sync().await.expect("sync");
    b.sync().await.expect("sync");
    a.close().await;
    // The issuer publishes the second schema and meets only `b` before it
    // leaves.
    let a = Device::new(Database::open(open(&a_dir, SECOND, network("a")))?)?;
    a.set(2, &apples, "note", json!("fresh")).await;
    b.sync().await.expect("sync");
    assert_eq!(generation(&b).await["current"]["schema"], 2);
    assert_eq!(
        rows(&b, "SELECT note FROM items WHERE title='apples'").await,
        json!([[text("fresh")]])
    );
    a.close().await;

    // The only reachable catalog holder now follows an unrelated dev tip,
    // opened on its own seal, whose state it holds live.
    b.ok(json!({"type":"tips", "action":"seal", "close": false}))
        .await;
    let inspected = b.ok(json!({"type":"tips", "action":"inspect"})).await;
    let seal = inspected["seals"]
        .as_array()
        .and_then(|seals| {
            seals
                .iter()
                .find(|seal| seal["canonical"] == true && seal["authority"] == "trusted")
        })
        .ok_or("seal")?["id"]
        .clone();
    let dev = b
        .ok(json!({"type":"tips", "action":"open", "seal":seal, "minimum_in_sync":1}))
        .await["tip"]
        .clone();
    b.ok(json!({"type":"tips", "action":"create", "name":"dev", "tip":dev}))
        .await;
    b.ok(json!({"type":"tips", "action":"follow", "name":"dev"}))
        .await;
    b.close().await;
    let b = Device::new(Database::open(open(&b_dir, THIRD, network("b")))?)?;
    assert_eq!(generation(&b).await["current"]["schema"], 3);
    let unrelated = generation(&b).await["manifest"].clone();

    // `c`'s application declares the first schema, and only `b` is
    // reachable: `c` learns the graph from `b` and fetches the record it
    // requires from `b`, without renewing anything.
    let before = chain(&c_dir)?;
    hub.record("c");
    c.sync().await.expect("sync");
    let requested = hub.transcript("c");
    assert!(
        requested
            .windows(b"rocky.sdk.tip-schema.v1".len())
            .any(|window| window == b"rocky.sdk.tip-schema.v1"),
        "the record was requested by its commitment"
    );
    let status = generation(&c).await;
    assert_eq!(status["current"]["schema"], 2, "{status}");
    assert_eq!(status["application"], "behind");
    assert_eq!(chain(&c_dir)?, before);
    let file = rusqlite::Connection::open(c_dir.join("rocky.sqlite"))?;
    let stored: i64 = file.query_row(
        "SELECT count(*) FROM secure_tip_schemas WHERE hex(manifest)=upper(?)",
        [unrelated.as_str().ok_or("manifest")?],
        |row| row.get(0),
    )?;
    assert_eq!(
        stored, 0,
        "the provider's unrelated schema grants no requirement"
    );
    drop(file);
    // Back on `main`, `b`'s next pass completes its pending switch.
    b.ok(json!({"type":"tips", "action":"follow", "name":"main"}))
        .await;
    b.sync().await.expect("sync");
    assert_eq!(generation(&b).await["pending"], Value::Null);

    c.close().await;
    let c = Device::new(Database::open(open(&c_dir, SECOND, network("c")))?)?;
    assert_eq!(generation(&c).await["application"], "current");
    let bread = c.add(3, "bread").await;
    c.sync().await.expect("sync");
    assert_eq!(b.titles().await, ["apples", "bread"]);
    c.set(4, &bread, "note", json!("rye")).await;
    c.sync().await.expect("sync");
    assert_eq!(
        rows(&b, "SELECT note FROM items WHERE title='bread'").await,
        json!([[text("rye")]])
    );
    c.close().await;
    b.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invitation_created_before_a_schema_change_enrolls_a_device_after_it()
-> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::create(&a_dir, network("a"))?;
    a.follow_main_migrating().await;
    let invitation = a.invite().await;
    a.add(1, "apples").await;
    a.close().await;
    let a = Device::new(Database::open(open(&a_dir, SECOND, network("a")))?)?;
    assert_eq!(generation(&a).await["current"]["schema"], 2);
    // The invitation names tables, not a generation: it enrolls into the
    // one the issuer runs now.
    let b = Device::new(Database::join(
        open(&b_dir, SECOND, network("b")),
        &invitation,
    )?)?;
    introduce(&a, &b).await;
    b.sync().await.expect("sync");
    let status = generation(&b).await;
    assert_eq!(status["current"]["schema"], 2);
    assert_eq!(status["application"], "current");
    let bread = b.add(2, "bread").await;
    b.set(3, &bread, "note", json!("rye")).await;
    b.sync().await.expect("sync");
    assert_eq!(a.titles().await, ["apples", "bread"]);
    assert_eq!(
        rows(&a, "SELECT note FROM items WHERE title='bread'").await,
        json!([[text("rye")]])
    );
    b.close().await;
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn issuers_that_publish_one_schema_apart_end_on_one_tip() -> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::create(&a_dir, network("a"))?;
    a.follow_main_migrating().await;
    let b = Device::new(Database::join(
        open(&b_dir, SCHEMA, network("b")),
        &a.invite_as(json!({"kind": "issuer"})).await,
    )?)?;
    introduce(&a, &b).await;
    b.add(1, "apples").await;
    b.sync().await.expect("sync");
    a.close().await;
    b.close().await;
    // Each issuer seals `main` with the second schema on its own.
    let a = Device::new(Database::open(open(&a_dir, SECOND, None))?)?;
    let b = Device::new(Database::open(open(&b_dir, SECOND, None))?)?;
    let (left, right) = (generation(&a).await, generation(&b).await);
    assert_eq!(left["manifest"], right["manifest"]);
    assert_ne!(tip(&a).await, tip(&b).await);
    a.close().await;
    b.close().await;
    // Both derived the first reader key of `tags` from the publisher key.
    let tags = |directory: &Path| -> Result<Value, Failure> {
        let identity: Value =
            serde_json::from_slice(&std::fs::read(directory.join("identity.json"))?)?;
        Ok(identity["keys"]["tags"].clone())
    };
    assert_eq!(tags(&a_dir)?, tags(&b_dir)?);
    assert_eq!(tags(&a_dir)?.as_array().map(Vec::len), Some(1));
    let a = Device::new(Database::open(open(&a_dir, SECOND, network("a")))?)?;
    let b = Device::new(Database::open(open(&b_dir, SECOND, network("b")))?)?;
    a.add(2, "bread").await;
    tag(&a, 5, "fruit").await;
    tag(&b, 5, "dairy").await;
    b.sync().await.expect("sync");
    a.sync().await.expect("sync");
    // The owner's seal wins: both devices end on its tip. The issuer's tip
    // stays a branch, listed as `main/1`, and its write on it returns as a
    // held change for its application.
    assert_eq!(tip(&a).await, tip(&b).await);
    let inspected = b.ok(json!({"type": "tips", "action": "inspect"})).await;
    let losers = inspected["bookmarks"][0]["losers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(losers.len(), 1, "{inspected}");
    assert_eq!(losers[0]["name"], "main/1");
    for device in [&a, &b] {
        assert_eq!(
            rows(device, "SELECT label FROM tags ORDER BY label").await,
            json!([[text("fruit")]])
        );
        assert_eq!(device.titles().await, ["apples", "bread"]);
    }
    let held = b.ok(json!({"type": "held_changes"})).await;
    assert_eq!(held["count"], 1, "{held}");
    let id = held["changes"][0]["id"].clone();
    reauthor(
        &b,
        6,
        "tags",
        "INSERT INTO tags(key,label,id) VALUES('dairy','dairy',?)",
        id,
    )
    .await;
    b.sync().await.expect("sync");
    for device in [&a, &b] {
        assert_eq!(
            rows(device, "SELECT label FROM tags ORDER BY label").await,
            json!([[text("dairy")], [text("fruit")]])
        );
        let status = generation(device).await;
        assert_eq!(status["manifest"], left["manifest"]);
        assert_eq!(status["current"]["schema"], 2);
    }
    assert_eq!(tags(&a_dir)?, tags(&b_dir)?);
    b.close().await;
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_on_main_never_fetches_or_installs_a_dev_branch_schema() -> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::create(&a_dir, network("a"))?;
    a.follow_main_migrating().await;
    let b = Device::join(
        &b_dir,
        &a.invite().await,
        Network::Owned(hub.connector("b")),
    )?;
    introduce(&a, &b).await;
    a.add(1, "apples").await;
    b.sync().await.expect("sync");
    // The owner tries the second schema on `dev`, opened on a seal of `main`.
    let sealed = a
        .ok(json!({"type": "tips", "action": "seal", "close": false}))
        .await;
    let _ = sealed;
    let inspected = a.ok(json!({"type": "tips", "action": "inspect"})).await;
    let seal = inspected["seals"]
        .as_array()
        .and_then(|seals| seals.iter().find(|seal| seal["canonical"] == true))
        .ok_or("seal")?["id"]
        .clone();
    let dev = a
        .ok(json!({"type": "tips", "action": "open", "seal": seal, "minimum_in_sync": 1}))
        .await["tip"]
        .clone();
    a.ok(json!({"type": "tips", "action": "create", "name": "dev", "tip": dev}))
        .await;
    a.ok(json!({"type": "tips", "action": "follow", "name": "dev"}))
        .await;
    a.close().await;
    let a = Device::new(Database::open(open(&a_dir, SECOND, network("a")))?)?;
    assert_eq!(generation(&a).await["current"]["schema"], 2);
    let dev_manifest = generation(&a).await["manifest"].clone();
    tag(&a, 2, "on dev").await;

    // `b` follows `main`: the graph names dev's tip and schema, but `b`
    // requests and stores nothing of it.
    hub.record("b");
    b.sync().await.expect("sync");
    let transcript = hub.transcript("b");
    assert!(
        !transcript
            .windows(b"rocky.sdk.tip-schema.v1".len())
            .any(|window| window == b"rocky.sdk.tip-schema.v1"),
        "a device on main requested a dev schema"
    );
    let status = generation(&b).await;
    assert_eq!(status["current"]["schema"], 1);
    assert_eq!(status["pending"], Value::Null);
    assert_ne!(status["manifest"], dev_manifest);
    assert_eq!(b.titles().await, ["apples"]);
    let file = rusqlite::Connection::open(b_dir.join("rocky.sqlite"))?;
    let stored: i64 = file.query_row(
        "SELECT count(*) FROM secure_tip_schemas WHERE hex(manifest)=upper(?)",
        [dev_manifest.as_str().ok_or("manifest")?],
        |row| row.get(0),
    )?;
    assert_eq!(stored, 0);
    drop(file);
    b.close().await;
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_issuer_migrating_offline_publishes_on_reconnect_and_meanwhile_writes_are_held()
-> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::create(&a_dir, network("a"))?;
    a.follow_main_migrating().await;
    let b = Device::join(
        &b_dir,
        &a.invite().await,
        Network::Owned(hub.connector("b")),
    )?;
    introduce(&a, &b).await;
    a.add(1, "cherries").await;
    a.add(2, "apples").await;
    b.sync().await.expect("sync");
    a.close().await;
    // Networking off, the issuer closes `main`, opens the migration's tip
    // and migrates; nothing has left it.
    let a = Device::new(Database::open(open(&a_dir, REQUIRED, None))?)?;
    assert_eq!(generation(&a).await["current"]["schema"], 2);
    // Meanwhile the member writes `main`, past the closing seal's frontier.
    b.add(3, "bread").await;
    a.close().await;
    let a = Device::new(Database::open(open(&a_dir, REQUIRED, network("a")))?)?;
    introduce(&a, &b).await;
    b.sync().await.expect("sync");
    b.sync().await.expect("sync");
    // The member is on the new schema with the migration's rows; its write
    // made meanwhile is held, never merged across the migration.
    let status = generation(&b).await;
    assert_eq!(status["current"]["schema"], 2, "{status}");
    assert_eq!(status["held"], 1);
    let positions = json!([
        [text("apples"), text("0000")],
        [text("cherries"), text("0001")]
    ]);
    for device in [&a, &b] {
        assert_eq!(
            rows(
                device,
                "SELECT title, position FROM items ORDER BY position"
            )
            .await,
            positions
        );
    }
    b.close().await;
    a.close().await;
    Ok(())
}

/// A node that keeps every seal migrates its database: the history of a
/// table the migration adds a field to gains the field, and the kept seal
/// still reads the table as it was.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_keeping_every_seal_publishes_a_migration_adding_a_field() -> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let directory = root.path().join("a");
    let a = Device::create(&directory, None)?;
    a.follow_main_migrating().await;
    a.ok(json!({"type": "tips", "action": "keep", "kept": {"every": true}}))
        .await;
    a.add(1, "cherries").await;
    a.add(2, "apples").await;
    let kept = a.ok(json!({"type": "tips", "action": "seal"})).await["tip"].clone();
    a.ok(json!({"type": "tips", "action": "compact", "keep": 1}))
        .await;
    a.close().await;
    let a = Device::new(Database::open(open(&directory, REQUIRED, None))?)?;
    assert_eq!(generation(&a).await["current"]["schema"], 2);
    assert_eq!(
        rows(&a, "SELECT title, position FROM items ORDER BY position").await,
        json!([
            [text("apples"), text("0000")],
            [text("cherries"), text("0001")]
        ])
    );
    let inspected = a.ok(json!({"type": "tips", "action": "inspect"})).await;
    let held = inspected["seals"]
        .as_array()
        .and_then(|seals| seals.iter().find(|seal| seal["id"] == kept))
        .map(|seal| seal["held"].clone());
    assert_eq!(held, Some(json!("kept")), "{inspected}");
    a.close().await;
    Ok(())
}

/// The second schema with a nullable `rank` instead of `note` and `tags`:
/// another version 2 an issuer may publish at the same time.
const RIVAL: &str = r#"{"application":"shopping","version":2,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"rank","type":"integer","not_null":false},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]}]}"#;

/// Issuers that publish different schemas apart end on one tip: the losing
/// issuer's database switches to the winner's schema, which its own
/// application does not declare.
#[tokio::test(flavor = "multi_thread")]
async fn issuers_that_publish_different_schemas_apart_end_on_the_winners() -> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::create(&a_dir, network("a"))?;
    a.follow_main_migrating().await;
    let b = Device::new(Database::join(
        open(&b_dir, SCHEMA, network("b")),
        &a.invite_as(json!({"kind": "issuer"})).await,
    )?)?;
    introduce(&a, &b).await;
    b.add(1, "apples").await;
    b.sync().await.expect("sync");
    a.close().await;
    b.close().await;
    let a = Device::new(Database::open(open(&a_dir, SECOND, None))?)?;
    let b = Device::new(Database::open(open(&b_dir, RIVAL, None))?)?;
    let winner = generation(&a).await["manifest"].clone();
    assert_ne!(winner, generation(&b).await["manifest"]);
    a.close().await;
    b.close().await;
    let a = Device::new(Database::open(open(&a_dir, SECOND, network("a")))?)?;
    let b = Device::new(Database::open(open(&b_dir, RIVAL, network("b")))?)?;
    introduce(&a, &b).await;
    for _ in 0..4 {
        b.sync().await.expect("sync");
        a.sync().await.expect("sync");
    }
    // The owner's tip wins; the issuer's database follows it to the owner's schema.
    let status = generation(&b).await;
    assert_eq!(tip(&a).await, tip(&b).await, "{status}");
    assert_eq!(status["manifest"], winner, "{status}");
    assert_eq!(status["pending"], Value::Null, "{status}");
    assert_eq!(b.titles().await, ["apples"]);
    b.close().await;
    a.close().await;
    Ok(())
}

/// An owner tries a migration on a branch, returns to `main` and keeps
/// sealing and compacting there: finalizing replays only frames on the
/// seal's own path.
#[tokio::test(flavor = "multi_thread")]
async fn an_owner_returns_from_a_migrated_branch_and_compacts_main() -> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::create(&a_dir, network("a"))?;
    a.follow_main_migrating().await;
    a.ok(json!({"type": "tips", "action": "keep", "kept": {"every": true}}))
        .await;
    let b = Device::join(
        &b_dir,
        &a.invite().await,
        Network::Owned(hub.connector("b")),
    )?;
    introduce(&a, &b).await;
    a.add(1, "cherries").await;
    b.sync().await.expect("sync");
    let seal = a.ok(json!({"type": "tips", "action": "seal"})).await["tip"].clone();
    let dev = a
        .ok(json!({"type": "tips", "action": "open", "seal": seal, "minimum_in_sync": 1}))
        .await["tip"]
        .clone();
    a.ok(json!({"type": "tips", "action": "create", "name": "dev", "tip": dev}))
        .await;
    a.ok(json!({"type": "tips", "action": "follow", "name": "dev"}))
        .await;
    a.close().await;
    let a = Device::new(Database::open(open(&a_dir, REQUIRED, network("a")))?)?;
    assert_eq!(generation(&a).await["current"]["schema"], 2);
    introduce(&a, &b).await;
    a.ok(json!({"type": "tips", "action": "follow", "name": "main"}))
        .await;
    // A sync pass switches the database to main's schema.
    for _ in 0..3 {
        let _ = a.sync().await;
        let _ = b.sync().await;
    }
    assert_eq!(
        generation(&a).await["pending"],
        Value::Null,
        "{}",
        generation(&a).await
    );
    assert_eq!(generation(&a).await["current"]["schema"], 1);
    a.add(2, "apples").await;
    let back = a.ok(json!({"type": "tips", "action": "seal"})).await["tip"].clone();
    a.add(3, "bread").await;
    a.ok(json!({"type": "tips", "action": "seal"})).await;
    // Finalizing main's seals replays no frame of the branch.
    let compacted = a
        .ok(json!({"type": "tips", "action": "compact", "keep": 1}))
        .await;
    assert!(compacted["compacted"].is_string(), "{compacted}");
    // The owner holds main's seals and may roll back to one.
    a.ok(json!({"type": "tips", "action": "open", "seal": back, "minimum_in_sync": 1}))
        .await;
    b.close().await;
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reopening_main_restores_the_branch_signer_of_its_shared_checkpoint() -> Result<(), Failure>
{
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let a_dir = root.path().join("a");
    let a = Device::create(&a_dir, network("a"))?;
    a.follow_main_migrating().await;
    a.add(1, "common").await;
    let seal = a.ok(json!({"type":"tips", "action":"seal"})).await["tip"].clone();
    let dev = a
        .ok(json!({"type":"tips", "action":"open", "seal":seal, "minimum_in_sync":1}))
        .await["tip"]
        .clone();
    a.ok(json!({"type":"tips", "action":"create", "name":"dev", "tip":dev}))
        .await;
    a.ok(json!({"type":"tips", "action":"follow", "name":"dev"}))
        .await;
    a.ok(json!({"type":"tips", "action":"compact"})).await;
    a.ok(json!({"type":"tips", "action":"follow", "name":"main"}))
        .await;
    let main = tip(&a).await;
    a.close().await;
    let a = Device::new(Database::open(open(&a_dir, SCHEMA, network("a")))?)?;
    assert_eq!(tip(&a).await, main);
    let b = Device::join(
        &root.path().join("b"),
        &a.invite().await,
        Network::Owned(hub.connector("b")),
    )?;
    introduce(&a, &b).await;
    b.sync()
        .await
        .expect("checkpoint transfer after issuer restart");
    assert_eq!(b.titles().await, ["common"]);
    b.add(2, "incremental").await;
    b.sync().await.expect("incremental sync after checkpoint");
    assert_eq!(a.titles().await, ["common", "incremental"]);
    assert_eq!(tip(&a).await, main);
    b.close().await;
    a.close().await;
    Ok(())
}
