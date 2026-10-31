//! Seals of a tip with a composed coordinated log through the JSON
//! contract: a private close ends the source tip's log only once relayed,
//! and its finality releases the staged migration.
mod common;
use common::{Device, Failure, introduce};
use rocky_coordinator::coordinated::MemoryLog;
use rocky_sdk::{Database, Network, Open, transport::memory::Hub};
use serde_json::json;
use std::sync::Arc;

fn open<'a>(directory: &'a std::path::Path, network: Option<Network>) -> Open<'a> {
    Open {
        identity: None,
        directory,
        schema: common::SCHEMA,
        secrets: None,
        network,
        coordination: None,
    }
}
fn domain(device: &Device) -> rocky_core::Scope {
    serde_json::from_str(&device.database.scope()).expect("scope")
}
/// The log of the tip `device` follows.
async fn tip_log(device: &Device) -> rocky_core::TipLog {
    let status = device.ok(json!({"type": "coordinated"})).await;
    let tip: [u8; 32] = data_encoding::HEXLOWER
        .decode(status["tip"].as_str().expect("tip").as_bytes())
        .expect("tip hex")
        .try_into()
        .expect("tip");
    rocky_core::TipLog {
        scope: domain(device),
        tip: rocky_core::TipId(tip),
    }
}
async fn node_key(device: &Device) -> rocky_sdk::credentials::PublicKey {
    let hex = device.node().await;
    let bytes: [u8; 32] = data_encoding::HEXLOWER
        .decode(hex.as_bytes())
        .expect("node hex")
        .try_into()
        .expect("node key");
    rocky_sdk::credentials::PublicKey::from_bytes(&bytes).expect("node key")
}
/// Writes the next numbered invoice as an ordinary transaction.
async fn invoice(device: &Device, handle: u8) {
    device.ok(json!({"type": "sql", "sql": "BEGIN"})).await;
    let count = device
        .ok(json!({"type": "sql", "sql": "SELECT COUNT(*) FROM items"}))
        .await["rows"][0][0]["value"]
        .as_str()
        .expect("count")
        .parse::<u64>()
        .expect("count");
    let id = device
        .ok(json!({"type": "next_id", "table": "items"}))
        .await["id"]
        .clone();
    device
        .ok(json!({
            "type": "sql",
            "sql": "INSERT INTO items(key,completed,title,id) VALUES(?,0,?,?)",
            "values": [
                {"type": "text", "value": format!("{:04}", count + 1)},
                {"type": "text", "value": format!("invoice {}", count + 1)},
                {"type": "integer", "value": id},
            ],
        }))
        .await;
    device
        .ok(json!({"type": "sql", "sql": "COMMIT", "handle": vec![handle; 32]}))
        .await;
}
/// The invoice numbers once every frame they depend on arrived by sync.
async fn keys(device: &Device) -> Vec<String> {
    let query = json!({"type": "read", "query": {"sql": "SELECT key FROM items ORDER BY key", "values": [], "max_rows": 1024}});
    let mut page = device.call(query.clone()).await;
    for _ in 0..200 {
        match &page {
            Err(error) if error["retryable"] == true => {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                page = device.call(query.clone()).await;
            }
            _ => break,
        }
    }
    page.expect("keys")["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|row| row[0]["value"].as_str().expect("key").to_owned())
        .collect()
}

const POSITIONED: &str = r#"{"application":"shopping","version":2,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"position","type":"text","not_null":true,"default":""},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]}],"migrations":[{"version":2,"statements":["UPDATE items SET position = title"]}]}"#;

/// The owner closes, opens and migrates
/// offline. Its stage stays private until a trusted node that follows the
/// source tip ends that tip's log with exactly the close and acknowledges
/// it; the owner then releases. The source tip's writes past the close
/// are held on the device that made them.
#[tokio::test(flavor = "multi_thread")]
async fn an_offline_migration_is_released_by_the_exact_close_s_finality() -> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let (a_dir, c_dir) = (root.path().join("a"), root.path().join("c"));
    let a = Device::new(Database::create(open(&a_dir, network("a")), None)?)?;
    a.follow_main_migrating().await;
    let log = MemoryLog::new();
    log.configure(domain(&a), 1)?;
    let owner = a.ok(json!({"type": "session"})).await["principal"]
        .as_str()
        .expect("owner")
        .to_owned();
    let owner: [u8; 32] = data_encoding::HEXLOWER
        .decode(owner.as_bytes())?
        .try_into()
        .map_err(|_| "owner key")?;
    log.set_owner(
        domain(&a),
        rocky_sdk::credentials::PublicKey::from_bytes(&owner)?,
    );
    let c = Device::new(Database::join(
        open(&c_dir, network("c")),
        &a.invite_as(json!({"kind":"writer","scopes":["items"]}))
            .await,
    )?)?;
    introduce(&a, &c).await;
    let principal = c.ok(json!({"type":"session"})).await["principal"].clone();
    let grant = a
        .ok(json!({"type":"tips","action":"trust","identity":principal}))
        .await;
    c.ok(json!({"type":"tips","action":"install_trust","grant":grant["grant"]}))
        .await;
    c.sync().await.expect("trusted sync");
    let a_node = node_key(&a).await;
    for device in [&a, &c] {
        device
            .database
            .coordinate(Some(Arc::new(log.client(node_key(device).await))))
            .await?;
    }
    invoice(&c, 1).await;
    a.sync().await.expect("the first invoice");
    let source = tip_log(&a).await;
    a.close().await;
    // While the owner is away, the trusted node writes a second invoice.
    invoice(&c, 2).await;

    // Offline, the owner stages its close, opening and move and migrates.
    let a = Device::new(Database::open(Open {
        schema: POSITIONED,
        coordination: Some(rocky_sdk::Coordination::Composed(Arc::new(
            log.client(a_node),
        ))),
        ..open(&a_dir, None)
    })?)?;
    let status = a.ok(json!({"type": "generation"})).await;
    assert_eq!(status["current"]["schema"], 2, "{status}");
    // Nothing of the stage left the device: the source log is open.
    assert!(log.head(source)?.terminal.is_none());
    a.close().await;

    // The candidate already fixed its parent. Source writes still commit
    // while its successor remains private.
    invoice(&c, 3).await;
    c.add(4, "ordinary meanwhile").await;

    // Reconnected, it relays the exact close; the trusted node ends the
    // log with it and acknowledges, and the owner releases.
    let a = Device::new(Database::open(Open {
        schema: POSITIONED,
        coordination: Some(rocky_sdk::Coordination::Composed(Arc::new(
            log.client(a_node),
        ))),
        ..open(&a_dir, network("a"))
    })?)?;
    introduce(&a, &c).await;
    for _ in 0..4 {
        let _ = a.sync().await;
        let _ = c.sync().await;
    }
    let head = log.head(source)?;
    let inspected = a.ok(json!({"type": "tips", "action": "inspect"})).await;
    let close = inspected["seals"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|seal| seal["action"] == "close")
        .expect("the close")
        .clone();
    assert_eq!(
        data_encoding::HEXLOWER.encode(&head.terminal.expect("ended").digest),
        close["id"]
    );
    // The trusted node follows `main` to the migration's tip. Its invoice
    // made after the close is held; the migration's rows are everyone's.
    let status = c.ok(json!({"type": "generation"})).await;
    assert_eq!(status["current"]["schema"], 2, "{status}");
    assert_eq!(status["held"], 3, "{status}");
    for device in [&a, &c] {
        assert_eq!(keys(device).await, ["0001"]);
        let rows = device
            .ok(json!({"type": "read", "query": {"sql": "SELECT title, position FROM items", "values": [], "max_rows": 8}}))
            .await["rows"]
            .clone();
        assert_eq!(
            rows,
            json!([[{"type":"text","value":"invoice 1"}, {"type":"text","value":"invoice 1"}]])
        );
    }
    // Those durably held post-frontier frames do not block the successor.
    invoice(&c, 5).await;
    a.sync().await.expect("the successor invoice");
    assert_eq!(keys(&a).await, ["0001", "0002"]);
    c.close().await;
    a.close().await;
    Ok(())
}
