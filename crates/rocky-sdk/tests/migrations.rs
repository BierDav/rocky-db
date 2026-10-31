//! Schema migrations of any size: the issuer signs the generation, runs its
//! migrations in one local transaction and publishes the result as many
//! bundles. See `docs/runtime/generations.md#migrations`.
mod common;
#[path = "migrations/prepared_pull.rs"]
mod prepared_pull;
#[path = "migrations/replayed.rs"]
mod replayed;
use common::{Device, Failure, introduce};
use rocky_sdk::{Database, Network, Open, transport::memory::Hub};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

/// Requires `position`, which the migration fills from the title, and adds
/// `tags`, keyed by name, with one row per item. Running it twice would
/// double each position.
const POSITIONED: &str = r#"{"application":"shopping","version":2,"format":6,"tables":[
 {"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"position","type":"text","not_null":true,"default":""},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]},
 {"name":"tags","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"label","type":"text","not_null":true}],"primary_key":["key"]}],
 "migrations":[{"version":2,"statements":["UPDATE items SET position = position || title",
  {"insert":"tags","select":"SELECT 'tag-' || key AS key, title AS label FROM items"}]}]}"#;
/// `POSITIONED` whose migration asks for an id, which no migration may.
const ASKS_FOR_IDS: &str = r#"{"application":"shopping","version":2,"format":6,"tables":[
 {"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"position","type":"text","not_null":true,"default":""},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]},
 {"name":"tags","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"label","type":"text","not_null":true}],"primary_key":["key"]}],
 "migrations":[{"version":2,"statements":["UPDATE items SET position = rocky_next_id('items')"]}]}"#;
/// The fixed release after `ASKS_FOR_IDS`: the same tables, the version 2
/// migration of `POSITIONED`.
const FIXED: &str = r#"{"application":"shopping","version":3,"format":6,"tables":[
 {"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"position","type":"text","not_null":true,"default":""},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]},
 {"name":"tags","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"label","type":"text","not_null":true}],"primary_key":["key"]}],
 "migrations":[{"version":2,"statements":["UPDATE items SET position = position || title",
  {"insert":"tags","select":"SELECT 'tag-' || key AS key, title AS label FROM items"}]}]}"#;

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
async fn sync(device: &Device) {
    let report = device.sync().await.expect("sync");
    if std::env::var_os("ROCKY_TRACE_MIGRATION").is_some() {
        eprintln!("migration report: {report}");
    }
    for peer in report["peers"].as_array().into_iter().flatten() {
        for attempt in peer["attempts"].as_array().into_iter().flatten() {
            if !attempt["failure"].is_null() {
                eprintln!("migration synchronization: {}", attempt["failure"]);
            }
        }
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
const POSITIONS: &str = "SELECT title, position FROM items ORDER BY title";
const TAGS: &str = "SELECT key, label FROM tags ORDER BY key";

/// `POSITIONED` whose migration inserts one tag key twice: it fails while
/// it runs, after the seal and opening were signed and staged.
const DUPLICATES: &str = r#"{"application":"shopping","version":2,"format":6,"tables":[
 {"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"position","type":"text","not_null":true,"default":""},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]},
 {"name":"tags","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"label","type":"text","not_null":true}],"primary_key":["key"]}],
 "migrations":[{"version":2,"statements":["UPDATE items SET position = position || title",
  {"insert":"tags","select":"SELECT 'same' AS key, title AS label FROM items"}]}]}"#;

/// The followed tip and the number of seals in the graph.
async fn graph(device: &Device) -> (Value, usize) {
    let tip = device.ok(json!({"type": "tips", "action": "status"})).await["tip"].clone();
    let seals = device
        .ok(json!({"type": "tips", "action": "inspect"}))
        .await["seals"]
        .as_array()
        .map_or(0, Vec::len);
    (tip, seals)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_migration_runs_again_and_a_committed_one_never() -> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let a = Device::create(root.path(), None)?;
    a.follow_main_migrating().await;
    a.add(1, "apples").await;
    a.add(2, "bread").await;
    let before = graph(&a).await;
    a.close().await;

    // A migration asking for an id is refused before anything is signed.
    let refused = Database::open(open(root.path(), ASKS_FOR_IDS, None))
        .err()
        .ok_or("a migration asking for ids opened")?;
    assert!(refused.to_string().contains("rocky_next_id"), "{refused}");
    // One failing while it runs withdraws its private seal and opening:
    // nothing of it left the device, and the workspace is the source tip's.
    let failed = Database::open(open(root.path(), DUPLICATES, None))
        .err()
        .ok_or("a failing migration opened")?;
    assert!(
        failed
            .to_string()
            .contains("migration to version 2 failed at statement 2"),
        "{failed}"
    );
    let a = Device::new(Database::open(open(root.path(), common::SCHEMA, None))?)?;
    let status = generation(&a).await;
    assert_eq!(status["current"]["schema"], 1, "{status}");
    assert_eq!(status["application"], "current");
    assert_eq!(graph(&a).await, before);
    assert_eq!(a.titles().await, ["apples", "bread"]);
    a.close().await;

    // The fixed release runs the migration again, once.
    let a = Device::new(Database::open(open(root.path(), FIXED, None))?)?;
    let status = generation(&a).await;
    assert_eq!(status["current"]["schema"], 3, "{status}");
    assert_eq!(
        status["migration"],
        json!({"state": "publishing", "bundles": 1, "published": 0})
    );
    let positions = json!([
        [text("apples"), text("apples")],
        [text("bread"), text("bread")]
    ]);
    let tags = rows(&a, TAGS).await;
    assert_eq!(rows(&a, POSITIONS).await, positions);
    assert_eq!(tags.as_array().map(Vec::len), Some(2));
    a.close().await;

    // Its publication is recorded with its rows: reopening repeats nothing.
    let a = Device::new(Database::open(open(root.path(), FIXED, None))?)?;
    assert_eq!(rows(&a, POSITIONS).await, positions);
    assert_eq!(rows(&a, TAGS).await, tags);
    assert_eq!(
        generation(&a).await["migration"],
        json!({"state": "publishing", "bundles": 1, "published": 0})
    );
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn issuers_that_cannot_reach_each_other_both_migrate_and_converge() -> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::create(&a_dir, network("a"))?;
    a.follow_main_migrating().await;
    let b = Device::new(Database::join(
        open(&b_dir, common::SCHEMA, network("b")),
        &a.invite_as(json!({"kind": "issuer"})).await,
    )?)?;
    introduce(&a, &b).await;
    a.add(1, "apples").await;
    b.add(2, "bread").await;
    sync(&b).await;
    a.close().await;
    b.close().await;

    // Apart, each signs the generation and migrates what it holds.
    for directory in [&a_dir, &b_dir] {
        let device = Device::new(Database::open(open(directory, POSITIONED, None))?)?;
        assert_eq!(generation(&device).await["current"]["schema"], 2);
        device.close().await;
    }
    let a = Device::new(Database::open(open(&a_dir, POSITIONED, network("a")))?)?;
    let b = Device::new(Database::open(open(&b_dir, POSITIONED, network("b")))?)?;
    sync(&b).await;
    sync(&a).await;
    sync(&b).await;
    // The owner's close wins: the issuer's migration tip stays a branch and
    // its migration is never merged, so no row is there twice.
    for device in [&a, &b] {
        assert_eq!(
            rows(device, POSITIONS).await,
            json!([
                [text("apples"), text("apples")],
                [text("bread"), text("bread")]
            ])
        );
        let tags = rows(device, TAGS).await;
        assert_eq!(tags.as_array().map(Vec::len), Some(2), "{tags}");
        assert_eq!(generation(device).await["migration"], Value::Null);
    }
    assert_eq!(rows(&a, TAGS).await, rows(&b, TAGS).await);
    let (tip, _) = graph(&a).await;
    assert_eq!(graph(&b).await.0, tip);
    let inspected = b.ok(json!({"type": "tips", "action": "inspect"})).await;
    let losers = inspected["bookmarks"][0]["losers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(losers.len(), 1, "{inspected}");
    assert_eq!(losers[0]["name"], "main/1");
    assert_eq!(b.ok(json!({"type":"held_changes"})).await["count"], 0);
    b.close().await;
    a.close().await;
    Ok(())
}

const LISTS: &str = r#"{"format":6,"application":"lists","version":1,"tables":[
 {"name":"lists","class":"replayed","columns":[{"name":"title","type":"text","not_null":true}],
  "primary_key":["id"],"partition_by":["id"],"partition_group":"list"}]}"#;
/// Requires `position` of every list, which a migration fills.
const POSITIONED_LISTS: &str = r#"{"format":6,"application":"lists","version":2,"tables":[
 {"name":"lists","class":"replayed","columns":[{"name":"title","type":"text","not_null":true},{"name":"position","type":"text","not_null":true,"default":""}],
  "primary_key":["id"],"partition_by":["id"],"partition_group":"list"}],
 "migrations":[{"version":2,"statements":["UPDATE lists SET position = title"]}]}"#;

/// Creates a list in its own partition; returns its id.
async fn list(device: &Device, title: &str) -> Result<String, Failure> {
    device
        .ok(json!({"type": "partition_next", "table": "lists"}))
        .await;
    device.ok(json!({"type": "sql", "sql": "BEGIN"})).await;
    let id = device
        .ok(json!({"type": "next_id", "table": "lists"}))
        .await["id"]
        .clone();
    device
        .ok(json!({"type": "sql", "sql": format!("INSERT INTO lists(id,title) VALUES(?,'{title}')"), "values": [{"type": "integer", "value": id}]}))
        .await;
    device.ok(json!({"type": "sql", "sql": "COMMIT"})).await;
    Ok(id.as_str().ok_or("id")?.to_owned())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_issuer_without_a_partitions_key_keeps_the_households_generation() -> Result<(), Failure>
{
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::new(Database::create(open(&a_dir, LISTS, network("a")), None)?)?;
    a.follow_main_migrating().await;
    let b = Device::new(Database::join(
        open(&b_dir, LISTS, network("b")),
        &a.invite_as(json!({"kind": "issuer"})).await,
    )?)?;
    introduce(&a, &b).await;
    list(&a, "From a").await?;
    let theirs = list(&b, "From b").await?;
    // `a` learns of `b`'s list before the list's key reached it.
    a.ok(json!({"type": "partition_register", "group": "list", "values": [{"type": "integer", "value": theirs}]}))
        .await;
    a.close().await;

    // Holding no key of that list, `a` does not sign.
    let a = Device::new(Database::open(open(
        &a_dir,
        POSITIONED_LISTS,
        network("a"),
    ))?)?;
    let status = generation(&a).await;
    assert_eq!(status["current"]["schema"], 1, "{status}");
    assert_eq!(status["application"], "ahead");
    assert_eq!(
        status["migration"],
        json!({"state": "full_access_required"})
    );
    let query = a
        .call(json!({"type": "read", "query": {"sql": "SELECT position FROM lists", "values": [], "max_rows": 8}}))
        .await
        .err()
        .ok_or("a query on the new field answered")?;
    assert!(query.to_string().contains("no such column"), "{query}");

    // Issuers pass each other their group keys: once `a` holds it, it
    // signs and migrates.
    sync(&b).await;
    sync(&a).await;
    a.close().await;
    let a = Device::new(Database::open(open(
        &a_dir,
        POSITIONED_LISTS,
        network("a"),
    ))?)?;
    assert_eq!(generation(&a).await["current"]["schema"], 2);
    assert_eq!(
        rows(
            &a,
            "SELECT title, position FROM lists ORDER BY title"
        )
        .await,
        json!([
            [text("From a"), text("From a")],
            [text("From b"), text("From b")]
        ])
    );
    // An explicit schema open installs the signed generation before sync.
    b.close().await;
    let b = Device::new(Database::open(open(
        &b_dir,
        POSITIONED_LISTS,
        network("b"),
    ))?)?;
    sync(&b).await;
    sync(&b).await;
    assert_eq!(
        rows(
            &b,
            "SELECT title, position FROM lists ORDER BY title"
        )
        .await,
        json!([
            [text("From a"), text("From a")],
            [text("From b"), text("From b")]
        ])
    );
    b.close().await;
    a.close().await;
    Ok(())
}

/// Adds a nullable note and seeds `LARGE` items with a migration.
const SEEDED: &str = r#"{"application":"shopping","version":2,"format":6,"tables":[
 {"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"note","type":"text"},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]}],
 "migrations":[{"version":2,"statements":[{"insert":"items","select":"WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 100000) SELECT printf('k%06d', i) AS key, 0 AS completed, printf('item %06d', i) AS title FROM n"}]}]}"#;
/// `SEEDED` with a nullable tag: an additive switch in place.
const TAGGED: &str = r#"{"application":"shopping","version":3,"format":6,"tables":[
 {"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"note","type":"text"},{"name":"tag","type":"text"},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]}],
 "migrations":[{"version":2,"statements":[{"insert":"items","select":"WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 100000) SELECT printf('k%06d', i) AS key, 0 AS completed, printf('item %06d', i) AS title FROM n"}]}]}"#;
/// Requires `position` of every item, filled from its title.
const FILLED: &str = r#"{"application":"shopping","version":4,"format":6,"tables":[
 {"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"note","type":"text"},{"name":"position","type":"text","not_null":true,"default":""},{"name":"tag","type":"text"},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]}],
 "migrations":[{"version":2,"statements":[{"insert":"items","select":"WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 100000) SELECT printf('k%06d', i) AS key, 0 AS completed, printf('item %06d', i) AS title FROM n"}]},
  {"version":4,"statements":["UPDATE items SET position = title"]}]}"#;
const FILLED_COUNT: &str =
    "SELECT count(*), count(CASE WHEN position = title THEN 1 END) FROM items";

/// The member needs the first migration's frames, signed under the
/// generation before the one both devices open, to apply the second's.
#[tokio::test(flavor = "multi_thread")]
async fn a_two_step_migration_converges_on_every_member() -> Result<(), Failure> {
    converges_on_every_member(8, 0).await
}

/// A returning member skips the covered history at the newest listed base.
#[tokio::test(flavor = "multi_thread")]
async fn returning_member_uses_the_newest_checkpoint_across_migration_bundles()
-> Result<(), Failure> {
    converges_on_every_member(rocky_secure::MAX_BUNDLE_ROWS + 1, 2).await
}

struct MemberFixture {
    root: common::identity::Directory,
    large: usize,
    multi_step: bool,
    fill: String,
    hub: Arc<Hub>,
    a: Device,
}

async fn converges_on_every_member(large: usize, history: usize) -> Result<(), Failure> {
    pull_member_fixture(prepare_member_fixture(large, history).await?).await
}

async fn prepare_member_fixture(large: usize, history: usize) -> Result<MemberFixture, Failure> {
    let root = common::identity::small_directory()?;
    // The returning member crosses a bundle boundary; other cases exercise
    // the additive switch and second migration as well.
    let multi_step = history == 0;
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
    sync(&b).await;
    let history_clock = std::time::Instant::now();
    for index in 0..history {
        a.ok(json!({"type":"tips", "action":"seal"})).await;
        if index == 0 {
            a.ok(json!({"type":"tips", "action":"compact"})).await;
        }
    }
    if history > 1 {
        // Finish the empty historical states before authoring the migration.
        // Their seals and listed records remain on the returning member's path.
        a.ok(json!({"type":"tips", "action":"compact"})).await;
    }
    let history_time = history_clock.elapsed();
    eprintln!("STAGE rows={large} history={history_time:?}");
    a.close().await;

    let size =
        |directory: &Path| std::fs::metadata(directory.join("rocky.sqlite")).map(|m| m.len());
    b.close().await;
    // One publication peer durably acknowledges the migration bundles before
    // the measured returning member takes the issuer's closing base.
    let c_dir = root.path().join("publication-peer");
    let before = size(&a_dir)?;
    let clock = std::time::Instant::now();
    let seed = SEEDED.replace("100000", &large.to_string());
    let fill = if multi_step {
        FILLED.replace("100000", &large.to_string())
    } else {
        seed.clone()
    };
    let a = Device::new(Database::open(open(&a_dir, &seed, None))?)?;
    let seeded = clock.elapsed();
    eprintln!("STAGE rows={large} seed_open={seeded:?}");
    a.close().await;
    let between = size(&a_dir)?;
    if multi_step {
        let tagged_schema = TAGGED.replace("100000", &large.to_string());
        let a = Device::new(Database::open(open(&a_dir, &tagged_schema, None))?)?;
        assert_eq!(generation(&a).await["current"]["schema"], 3);
        a.close().await;
    }
    let clock = std::time::Instant::now();
    let a = Device::new(Database::open(open(&a_dir, &fill, network("a")))?)?;
    let filled = clock.elapsed();
    let open_stage = if multi_step {
        "fill_open"
    } else {
        "publisher_open"
    };
    eprintln!("STAGE rows={large} {open_stage}={filled:?}");
    let status = generation(&a).await;
    assert_eq!(
        status["current"]["schema"],
        if multi_step { 4 } else { 2 },
        "{status}"
    );
    let bundles = large.div_ceil(rocky_secure::MAX_BUNDLE_ROWS) as u64;
    let migrations = if multi_step { 2 } else { 1 };
    assert_eq!(
        status["migration"],
        json!({"state": "publishing", "bundles": migrations * bundles, "published": 0})
    );
    {
        let db = rusqlite::Connection::open_with_flags(
            a_dir.join("rocky.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let (frames, bytes, maximum): (i64, i64, i64) = db.query_row(
            "SELECT count(*),coalesce(sum(length(body)),0),coalesce(max(length(body)),0) FROM secure_operations", [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let average = bytes.checked_div(frames).unwrap_or(0);
        eprintln!(
            "FRAMES rows={large} stage={open_stage} count={frames} body_bytes={bytes} body_average={average} body_maximum={maximum}"
        );
    }
    let (ready_query, ready_rows) = if multi_step {
        (
            FILLED_COUNT,
            json!([[{"type": "integer", "value": large.to_string()}, {"type": "integer", "value": large.to_string()}]]),
        )
    } else {
        (
            "SELECT count(*) FROM items",
            json!([[{"type": "integer", "value": large.to_string()}]]),
        )
    };
    assert_eq!(rows(&a, ready_query).await, ready_rows);

    let network_bytes = hub.written();
    let publication_wire_start = *network_bytes.borrow();
    let clock = std::time::Instant::now();
    let c = Device::new(Database::join(
        open(&c_dir, &fill, network("publication-peer")),
        &a.invite().await,
    )?)?;
    sync(&c).await;
    let published = clock.elapsed();
    eprintln!("STAGE rows={large} publication={published:?}");
    let closing_wire_start = *network_bytes.borrow();
    eprintln!(
        "WIRE rows={large} publication_bytes={}",
        closing_wire_start - publication_wire_start
    );
    let clock = std::time::Instant::now();
    sync(&a).await;
    let closed = clock.elapsed();
    eprintln!("STAGE rows={large} closing_compaction={closed:?}");
    eprintln!(
        "WIRE rows={large} closing_compaction_bytes={}",
        *network_bytes.borrow() - closing_wire_start
    );
    assert_eq!(generation(&a).await["migration"], Value::Null);
    if history > 0 {
        let inspection = a.ok(json!({"type":"tips", "action":"inspect"})).await;
        let seals = inspection["seals"].as_array().ok_or("missing seals")?;
        assert!(seals.len() >= history + 2, "only {} seals", seals.len());
        assert!(
            seals
                .iter()
                .filter(|seal| seal["checkpoints"]
                    .as_array()
                    .is_some_and(|records| !records.is_empty()))
                .count()
                >= 2,
            "the newest base must compete with an older listed base"
        );
    }
    c.close().await;
    eprintln!(
        "PREPARED rows={large} history={history_time:?} seed_open={seeded:?}  {open_stage}={filled:?} file_before={before} file_seeded={between} issuer_file={} publication={published:?} closing_compaction={closed:?}",
        size(&a_dir)?,
    );
    Ok(MemberFixture {
        root,
        large,
        multi_step,
        fill,
        hub,
        a,
    })
}

async fn pull_member_fixture(fixture: MemberFixture) -> Result<(), Failure> {
    let MemberFixture {
        root,
        large,
        multi_step,
        fill,
        hub,
        a,
    } = fixture;
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (ready_query, ready_rows) = if multi_step {
        (
            FILLED_COUNT,
            json!([[{"type": "integer", "value": large.to_string()}, {"type": "integer", "value": large.to_string()}]]),
        )
    } else {
        (
            "SELECT count(*) FROM items",
            json!([[{"type": "integer", "value": large.to_string()}]]),
        )
    };
    let network_bytes = hub.written();
    // The returning member takes the listed closing checkpoint and the tail.
    let member_wire_start = *network_bytes.borrow();
    let clock = std::time::Instant::now();
    let b = Device::new(Database::open(open(&b_dir, &fill, network("b")))?)?;
    let member_open = clock.elapsed();
    eprintln!("STAGE rows={large} member_open={member_open:?}");
    let clock = std::time::Instant::now();
    let mut syncs = 0;
    let mut transfers = Vec::new();
    // A table whose frames are still arriving reads as unavailable.
    while b
        .call(json!({"type": "read", "query": {"sql": ready_query, "values": [], "max_rows": 1}}))
        .await
        .ok()
        .map(|page| page["rows"].clone())
        != Some(ready_rows.clone())
    {
        syncs += 1;
        assert!(syncs <= 64, "the member did not converge");
        let report = b.sync().await.map_err(|error| error.to_string())?;
        transfers.extend(
            report["peers"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|peer| peer["transfers"].as_array().into_iter().flatten().cloned()),
        );
    }
    let pulled = clock.elapsed();
    eprintln!("STAGE rows={large} member_pull={pulled:?}");

    let member_wire_bytes = *network_bytes.borrow() - member_wire_start;
    eprintln!("WIRE rows={large} member_open_and_pull_bytes={member_wire_bytes}");
    sync(&a).await;
    assert_eq!(generation(&a).await["migration"], Value::Null);
    let fingerprint = "SELECT count(*), min(title), max(title), sum(length(title)) FROM items";
    assert_eq!(rows(&a, fingerprint).await, rows(&b, fingerprint).await);
    // Every key/value is checked, including the seed range, rather than relying
    // on extrema alone. Both files must hold the closing seal's base.
    let filled_fields = if multi_step {
        " OR position != title OR tag IS NOT NULL"
    } else {
        ""
    };
    let exact = format!(
        "SELECT count(*) FROM items WHERE key != printf('k%06d', CAST(substr(key,2) AS INTEGER)) OR CAST(substr(key,2) AS INTEGER) NOT BETWEEN 1 AND {large} OR title != printf('item %06d', CAST(substr(key,2) AS INTEGER)) OR completed != 0 OR note IS NOT NULL{filled_fields}"
    );
    for device in [&a, &b] {
        assert_eq!(
            rows(device, &exact).await,
            json!([[{"type":"integer","value":"0"}]])
        );
    }
    let mut closing = None;
    for directory in [&a_dir, &b_dir] {
        let db = rusqlite::Connection::open_with_flags(
            directory.join("rocky.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let (total,migration):(i64,i64)=db.query_row("SELECT bytes,(SELECT coalesce(sum(retained_bytes),0) FROM secure_migration_publications) FROM secure_retained",[],|row|Ok((row.get(0)?,row.get(1)?)))?;
        let ordinary = total
            .checked_sub(migration)
            .ok_or("invalid migration accounting")?;
        assert!((0..=67_108_864).contains(&ordinary));
        if !multi_step {
            let mut query = db.prepare("SELECT signed FROM secure_checkpoints c WHERE sequence=(SELECT max(sequence) FROM secure_checkpoints WHERE scope=c.scope)")?;
            let mut items_base = None;
            for record in query.query_map([], |row| row.get::<_, Vec<u8>>(0))? {
                let signed = rocky_secure::SignedCheckpoint::from_bytes(&record?)?;
                if signed.statement.rows.count == large as u64 {
                    assert!(signed.statement.seal.is_some());
                    items_base = Some((signed.statement.seal, signed.id()?));
                }
            }
            let (seal, checkpoint) = items_base.ok_or("missing closing items base")?;
            let seal = seal.ok_or("closing items base has no seal")?;
            let checkpoint = data_encoding::HEXLOWER.encode(&checkpoint);
            assert!(
            transfers
                .iter()
                .any(|transfer| transfer["checkpoint"] == checkpoint && transfer["pulled"] == 0),
            "member transfer does not name {checkpoint}: {transfers:?}"
        );
            if directory == &a_dir {
                closing = Some(seal);
            } else {
                assert_eq!(Some(seal), closing);
            }
            eprintln!(
                "BASE rows={large} directory={} seal={} checkpoint={checkpoint}",
                directory.display(),
                data_encoding::HEXLOWER.encode(&seal)
            );
        } else {
            assert!(
                transfers
                    .iter()
                    .all(|transfer| transfer["checkpoint"].is_null())
            );
        }
        eprintln!(
            "ACCOUNT rows={large} directory={} total={total} migration={migration} ordinary={ordinary}",
            directory.display()
        );
    }
    assert_eq!(syncs, 1);

    b.close().await;
    a.close().await;
    if large == 8 {
        let mut later: Value = serde_json::from_str(&fill)?;
        later["version"] = json!(5);
        later["tables"][0]["columns"]
            .as_array_mut()
            .ok_or("columns")?
            .push(json!({"name":"later", "type":"text"}));
        let later = later.to_string();
        let a = Device::new(Database::open(open(&a_dir, &later, None))?)?;
        assert_eq!(
            generation(&a).await["migration"],
            Value::Null,
            "a completed migration reopened after a later schema switch"
        );
        a.close().await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_member_writes_its_shared_partition_after_following_a_migration() -> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, b_dir) = (root.path().join("a"), root.path().join("b"));
    let a = Device::new(Database::create(open(&a_dir, LISTS, network("a")), None)?)?;
    a.follow_main_migrating().await;
    let b = Device::new(Database::join(
        open(&b_dir, LISTS, network("b")),
        &a.invite_as(json!({"kind": "grants", "grants": [{"scope": "lists", "rights": ["read", "insert", "update", "delete"]}]})).await,
    )?)?;
    introduce(&a, &b).await;
    let id = list(&a, "Weekly").await?;
    let node = b.node().await;
    a.ok(json!({"type": "partition_share", "group": "list", "values": [{"type": "integer", "value": id}], "recipients": [node]}))
        .await;
    sync(&b).await;
    a.close().await;
    // The issuer migrates; the member follows `main` onto the migration's
    // line, where it writes under another node of its identity.
    let a = Device::new(Database::open(open(
        &a_dir,
        POSITIONED_LISTS,
        network("a"),
    ))?)?;
    // The member's application stays at the first version.
    b.close().await;
    let b = Device::new(Database::open(open(&b_dir, LISTS, network("b")))?)?;
    introduce(&a, &b).await;
    sync(&b).await;
    assert_eq!(generation(&b).await["current"]["schema"], 2);
    assert_eq!(generation(&b).await["application"], "behind");
    b.ok(json!({"type": "sql", "sql": "BEGIN"})).await;
    b.ok(json!({"type": "sql", "sql": format!("UPDATE lists SET title='Monthly' WHERE id={id}")}))
        .await;
    b.ok(json!({"type": "sql", "sql": "COMMIT"})).await;
    sync(&b).await;
    assert_eq!(
        rows(&a, "SELECT title, position FROM lists").await,
        json!([[text("Monthly"), text("Weekly")]])
    );
    b.close().await;
    a.close().await;
    Ok(())
}

struct DescriptorIdentity {
    provider: rocky_sdk::FileIdentityProvider,
    database: std::path::PathBuf,
    refuse: std::sync::atomic::AtomicBool,
    attempts: std::sync::Mutex<Vec<Vec<u8>>>,
}
impl rocky_sdk::IdentityProvider for DescriptorIdentity {
    fn public_key(
        &self,
    ) -> Result<rocky_sdk::credentials::PublicKey, rocky_sdk::credentials::Error> {
        self.provider.public_key()
    }
    fn reserve_author(
        &self,
        range: rocky_sdk::credentials::AuthorRange,
    ) -> Result<u32, rocky_sdk::credentials::Error> {
        self.provider.reserve_author(range)
    }
    fn sign(
        &self,
        purpose: rocky_sdk::Purpose,
        message: &[u8],
    ) -> Result<rocky_sdk::credentials::Signature, rocky_sdk::credentials::Error> {
        let label = b"rocky.migration-publication.v1";
        if message.windows(label.len()).any(|part| part == label) {
            // An external provider can access the file: no replica SQL transaction is held.
            let db = rusqlite::Connection::open(&self.database).unwrap();
            db.execute_batch("BEGIN IMMEDIATE; ROLLBACK")
                .expect("identity called in a write transaction");
            self.attempts.lock().unwrap().push(message.to_vec());
            if self.refuse.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(rocky_sdk::credentials::Error::Provider(
                    "signer unavailable".into(),
                ));
            }
        }
        self.provider.sign(purpose, message)
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn an_external_identity_resumes_the_exact_committed_descriptor_without_rerunning_sql()
-> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let directory = root.path().join("database");
    let identity = Arc::new(DescriptorIdentity {
        provider: rocky_sdk::FileIdentityProvider::open(root.path().join("identity"))?,
        database: directory.join("rocky.sqlite"),
        refuse: std::sync::atomic::AtomicBool::new(false),
        attempts: Default::default(),
    });
    let options = |schema| Open {
        identity: Some(identity.clone() as Arc<dyn rocky_sdk::IdentityProvider>),
        ..open(&directory, schema, None)
    };
    let a = Device::new(Database::create(options(common::SCHEMA), None)?)?;
    a.follow_main_migrating().await;
    a.add(1, "once").await;
    a.close().await;
    identity
        .refuse
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let error = Database::open(options(POSITIONED))
        .err()
        .ok_or("unavailable signer released the migration")?;
    assert!(error.to_string().contains("signer unavailable"), "{error}");
    {
        let db = rusqlite::Connection::open(&identity.database)?;
        let state: String = db.query_row(
            "SELECT state FROM secure_staged_schema WHERE state!='released'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(state, "committed");
        let public: i64 = db.query_row(
            "SELECT count(*) FROM secure_tip_statements WHERE staged=1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(public, 3);
    }
    identity
        .refuse
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let a = Device::new(Database::open(options(POSITIONED))?)?;
    assert_eq!(
        rows(&a, POSITIONS).await,
        json!([[text("once"), text("once")]])
    );
    a.close().await;
    let attempts = identity.attempts.lock().unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0], attempts[1]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_member_replays_a_migration_from_its_implicit_genesis_base() -> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let source = root.path().join("source");
    let a = Device::create(&source, network("a"))?;
    a.follow_main_migrating().await;
    a.add(1, "inherited").await;
    a.close().await;
    let a = Device::new(Database::open(open(&source, POSITIONED, network("a")))?)?;
    let invitation = a.invite().await;
    let b = Device::new(Database::join(
        open(&root.path().join("member"), POSITIONED, network("b")),
        &invitation,
    )?)?;
    introduce(&a, &b).await;
    for _ in 0..4 {
        b.sync().await.map_err(|e| e.to_string())?;
        if rows(&b, POSITIONS).await == json!([[text("inherited"), text("inherited")]]) {
            break;
        }
    }
    assert_eq!(
        rows(&b, POSITIONS).await,
        json!([[text("inherited"), text("inherited")]])
    );
    b.close().await;
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_migration_open_drives_maintenance_before_the_first_request() -> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let a = Device::create(root.path(), None)?;
    a.follow_main_migrating().await;
    a.add(1, "apples").await;
    a.close().await;
    let finalized = || -> Result<i64, Failure> {
        let db = rusqlite::Connection::open_with_flags(
            root.path().join("rocky.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        Ok(
            db.query_row("SELECT count(*) FROM secure_finalized", [], |row| {
                row.get(0)
            })?,
        )
    };
    let before = finalized()?;
    let database = Database::open(open(root.path(), POSITIONED, None))?;
    assert!(
        finalized()? > before,
        "open left its migration seal for a later request"
    );
    let a = Device::new(database)?;
    assert_eq!(
        rows(&a, POSITIONS).await,
        json!([[text("apples"), text("apples")]])
    );
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_member_imports_an_earlier_schemas_checkpoint_before_the_migration_tail()
-> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let source = root.path().join("source");
    let a = Device::create(&source, None)?;
    a.follow_main_migrating().await;
    a.close().await;
    let a = Device::new(Database::open(open(
        &source,
        &SEEDED.replace("100000", "8"),
        None,
    ))?)?;
    a.close().await;
    let a = Device::new(Database::open(open(
        &source,
        &TAGGED.replace("100000", "8"),
        None,
    ))?)?;
    a.ok(json!({"type":"tips","action":"compact","keep":0}))
        .await;
    a.close().await;
    let hub = Arc::new(Hub::default());
    let schema = FILLED.replace("100000", "8");
    let a = Device::new(Database::open(open(
        &source,
        &schema,
        Some(Network::Owned(hub.connector("a"))),
    ))?)?;
    let c = Device::new(Database::join(
        open(
            &root.path().join("member"),
            &schema,
            Some(Network::Owned(hub.connector("c"))),
        ),
        &a.invite().await,
    )?)?;
    c.sync().await.map_err(|e| e.to_string())?;
    assert_eq!(
        rows(&c, FILLED_COUNT).await,
        json!([[{"type":"integer","value":"8"},{"type":"integer","value":"8"}]])
    );
    c.close().await;
    a.close().await;
    Ok(())
}
