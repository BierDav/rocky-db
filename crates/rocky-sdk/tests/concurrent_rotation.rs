//! Phase 8: sibling histories and writer convergence through the in-process hub.
use common::{Device, Failure};
use rocky_sdk::{Database, Network, Open, credentials::PrivateKey, transport::memory::Hub};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};
mod common;
#[allow(dead_code)]
#[path = "registry_revocation/fixture.rs"]
mod fixture;
const SCHEMA: &str = r#"{"application":"siblings","version":1,"format":6,"tables":[
 {"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]},
 {"name":"parts","class":"replayed","columns":[{"name":"list","type":"text","not_null":true},{"name":"key","type":"text","not_null":true}],"primary_key":["list","key"],"partition_by":["list"],"partition_group":"list"},
 {"name":"labels","class":"replayed","columns":[{"name":"list","type":"text","not_null":true},{"name":"key","type":"text","not_null":true}],"primary_key":["list","key"],"partition_by":["list"],"partition_group":"list"},
 {"name":"attachments","class":"replayed","columns":[{"name":"list","type":"text","not_null":true},{"name":"key","type":"text","not_null":true}],"primary_key":["list","key"],"partition_by":["list"],"partition_group":"list"}]}"#;
fn open<'a>(root: &'a Path, hub: &Arc<Hub>, name: &str) -> Open<'a> {
    Open {
        identity: None,
        directory: root,
        schema: SCHEMA,
        secrets: Some(fixture::keys(root)),
        network: Some(Network::Owned(hub.connector(name))),
        coordination: None,
    }
}
async fn join(
    root: &Path,
    hub: &Arc<Hub>,
    name: &str,
    a: &Device,
    profile: Value,
    schema: &'static str,
) -> Result<Device, Failure> {
    let invitation = a.invite_as(profile).await;
    let directory = root.join(name);
    let mut options = open(&directory, hub, name);
    options.schema = schema;
    let device = Device::new(Database::join(options, &invitation)?)?;
    fixture::settle(&device).await;
    Ok(device)
}
fn identity(root: &Path, name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(root.join(name).join("identity.json")).unwrap()).unwrap()
}
fn winner(root: &Path, name: &str, collection: &str) -> rocky_core::KeyEpoch {
    let epochs: Vec<rocky_core::KeyEpoch> =
        serde_json::from_value(identity(root, name)["keys"][collection].clone()).unwrap();
    *epochs.iter().max().unwrap()
}
fn values() -> Value {
    json!([{"type":"text","value":"L"}])
}
async fn partition(device: &Device, kind: &str) -> Value {
    device
        .ok(json!({"type":kind,"group":"list","values":values()}))
        .await
}
async fn write_group(device: &Device, prefix: &str) {
    let _scope: Value = serde_json::from_str(&device.database.scope()).unwrap();

    device.ok(json!({"type":"sql","sql":"BEGIN"})).await;
    for table in ["parts", "labels", "attachments"] {
        let id = device
            .ok(json!({"type":"next_id","table":table,"partition_values":values()}))
            .await;
        device.ok(json!({"type":"sql","sql":format!("INSERT INTO {table}(list,key,id) VALUES ('L', '{prefix}', ?)"),"values":[{"type":"integer","value":id["id"]}]})).await;
    }
    device.ok(json!({"type":"sql","sql":"COMMIT"})).await;
}
async fn rows(device: &Device, table: &str) -> Vec<String> {
    let page = device.ok(json!({"type":"read","query":{"sql":format!("SELECT key FROM {table} WHERE list='L' ORDER BY key"),"values":[],"max_rows":16}})).await;
    page["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row[0]["value"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn concurrent_group_creation_opens_every_table_and_converges_after_one_sync_each()
-> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let root = root.path();
    let hub = Arc::new(Hub::default());
    let a = Device::new(Database::create(open(&root.join("a"), &hub, "a"), None)?)?;
    let b = join(root, &hub, "b", &a, json!({"kind":"issuer"}), SCHEMA).await?;
    let ea = partition(&a, "partition_create").await["epoch"].clone();
    let eb = partition(&b, "partition_create").await["epoch"].clone();
    assert_ne!(ea, eb);
    write_group(&a, "a").await;
    write_group(&b, "b").await;
    a.sync().await.map_err(|e| e.to_string())?;
    b.sync().await.map_err(|e| e.to_string())?;
    let left = partition(&a, "partition_status").await;
    let right = partition(&b, "partition_status").await;
    assert_eq!(left["current"], right["current"]);
    assert_eq!(left["epochs"].as_array().unwrap().len(), 2);
    for device in [&a, &b] {
        let status = partition(device, "partition_status").await;
        for table in status["tables"].as_array().unwrap() {
            assert_eq!(table["current"], status["current"]);
            assert_eq!(table["epochs"], status["epochs"]);
            assert_eq!(
                rows(device, table["table"].as_str().unwrap()).await,
                ["a", "b"]
            );
        }
    }
    write_group(&a, "c").await;
    write_group(&b, "d").await;
    for device in [&a, &b] {
        device.close().await;
    }
    Ok(())
}

#[tokio::test]
async fn concurrent_collection_rotations_open_both_rows_and_an_offline_writer_renews_once()
-> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let root = root.path();
    let hub = Arc::new(Hub::default());
    let directory = root.join("a");
    let mut options = open(&directory, &hub, "a");
    options.schema = common::SCHEMA;
    let a = Device::new(Database::create(options, None)?)?;
    let b = join(
        root,
        &hub,
        "b",
        &a,
        json!({"kind":"issuer"}),
        common::SCHEMA,
    )
    .await?;
    let offline = join(
        root,
        &hub,
        "offline",
        &a,
        json!({"kind":"writer","scopes":["items"]}),
        common::SCHEMA,
    )
    .await?;
    offline.close().await;
    for device in [&a, &b] {
        device
            .ok(json!({"type":"revoke","node":PrivateKey::new().public_key().to_hex()}))
            .await;
    }
    let before_a = winner(root, "a", "items");
    let before_b = winner(root, "b", "items");
    assert_eq!(before_a.generation, 2);
    assert_eq!(before_b.generation, 2);
    assert_ne!(before_a, before_b);
    a.add(1, "a sibling").await;
    b.add(2, "b sibling").await;
    a.sync().await.map_err(|e| e.to_string())?;
    b.sync().await.map_err(|e| e.to_string())?;
    let current = winner(root, "b", "items");
    assert_eq!(current.generation, 3);
    assert_eq!(winner(root, "a", "items"), current);
    for device in [&a, &b] {
        assert_eq!(device.titles().await, ["a sibling", "b sibling"]);
    }
    for _ in 0..10 {
        a.sync().await.map_err(|e| e.to_string())?;
        b.sync().await.map_err(|e| e.to_string())?;
        assert_eq!(winner(root, "a", "items"), current);
        assert_eq!(winner(root, "b", "items"), current);
    }
    let directory = root.join("offline");
    let mut options = open(&directory, &hub, "offline");
    options.schema = common::SCHEMA;
    let offline = Device::new(Database::open(options)?)?;
    offline.ok(json!({"type":"renew"})).await;
    assert_eq!(winner(root, "offline", "items"), current);
    offline.add(3, "after renewal").await;
    for device in [&a, &b, &offline] {
        device.close().await;
    }
    Ok(())
}

#[tokio::test]
async fn two_revoked_list_readers_open_the_opposite_sibling_but_not_the_superseding_rows()
-> Result<(), Failure> {
    const LIST_SCHEMA: &str = r#"{"application":"exposure","version":1,"format":6,"tables":[{"name":"parts","class":"replayed","columns":[{"name":"list","type":"text","not_null":true},{"name":"key","type":"text","not_null":true}],"primary_key":["list","key"],"partition_by":["list"],"partition_group":"list"}]}"#;
    async fn write(device: &Device, key: &str) {
        let _scope: Value = serde_json::from_str(&device.database.scope()).unwrap();

        device.ok(json!({"type":"sql","sql":"BEGIN"})).await;
        let id = device
            .ok(json!({"type":"next_id","table":"parts","partition_values":values()}))
            .await;
        device.ok(json!({"type":"sql","sql":"INSERT INTO parts(list,key,id) VALUES ('L', ?, ?)","values":[{"type":"text","value":key},{"type":"integer","value":id["id"]}]})).await;
        device.ok(json!({"type":"sql","sql":"COMMIT"})).await;
    }
    let root = common::identity::small_directory()?;
    let root = root.path();
    let hub = Arc::new(Hub::default());
    let directory = root.join("a");
    let mut options = open(&directory, &hub, "a");
    options.schema = LIST_SCHEMA;
    let a = Device::new(Database::create(options, None)?)?;
    a.follow_main().await;
    partition(&a, "partition_create").await;
    write(&a, "before").await;
    let b = join(root, &hub, "b", &a, json!({"kind":"issuer"}), LIST_SCHEMA).await?;
    let reader = json!({"kind":"reader","scopes":["parts"]});
    let carol = join(root, &hub, "carol", &a, reader.clone(), LIST_SCHEMA).await?;
    let dave = join(root, &hub, "dave", &b, reader, LIST_SCHEMA).await?;
    a.sync()
        .await
        .map_err(|e| format!("a sync before revocations: {e}"))?;
    b.sync()
        .await
        .map_err(|e| format!("b sync before revocations: {e}"))?;
    for (device, other, original) in [(&carol, &b, &a), (&dave, &a, &b)] {
        common::introduce(device, other).await;
        device
            .ok(json!({"type":"peer_remove","node":original.node().await}))
            .await;
    }
    a.ok(json!({"type":"revoke","node":carol.node().await}))
        .await;
    b.ok(json!({"type":"revoke","node":dave.node().await}))
        .await;
    write(&a, "a").await;
    write(&b, "b").await;
    // Each issuer's base after its own rotation is what its reader
    // imports; their two seals race and resolve when they meet. Sealing
    // offline keeps the issuers apart, as the rotations were.
    for issuer in [&a, &b] {
        issuer
            .ok(json!({"type":"networking_control","enabled":false}))
            .await;
        issuer.seal_and_compact().await;
    }
    for issuer in [&a, &b] {
        issuer
            .ok(json!({"type":"networking_control","enabled":true}))
            .await;
    }
    for (device, original) in [(&carol, &a), (&dave, &b)] {
        // A reader that switched tips retries every issuer; the one that
        // revoked it stays out of reach here, as the scenario requires.
        original
            .ok(json!({"type":"networking_control","enabled":false}))
            .await;
        device.ok(json!({"type":"renew"})).await;
        device
            .ok(json!({"type":"peer_remove","node":original.node().await}))
            .await;
        device
            .sync()
            .await
            .map_err(|e| format!("reader sync: {e}"))?;
        original
            .ok(json!({"type":"networking_control","enabled":true}))
            .await;
    }
    assert_eq!(rows(&carol, "parts").await, ["b", "before"]);
    assert_eq!(rows(&dave, "parts").await, ["a", "before"]);
    a.sync()
        .await
        .map_err(|e| format!("a sync after revocations: {e}"))?;
    b.sync()
        .await
        .map_err(|e| format!("b sync after revocations: {e}"))?;
    let current = partition(&a, "partition_status").await["current"].clone();
    assert_eq!(current["generation"], 3);
    assert_eq!(partition(&b, "partition_status").await["current"], current);
    write(&a, "after").await;
    for device in [&carol, &dave] {
        let held = partition(device, "partition_status").await;
        assert!(
            held["epochs"]
                .as_array()
                .unwrap()
                .iter()
                .all(|epoch| epoch["generation"].as_u64().unwrap() < 3)
        );
        let _ = device.sync().await;
    }
    assert_eq!(rows(&carol, "parts").await, ["b", "before"]);
    assert_eq!(rows(&dave, "parts").await, ["a", "before"]);
    for device in [&a, &b, &carol, &dave] {
        device.close().await;
    }
    Ok(())
}
