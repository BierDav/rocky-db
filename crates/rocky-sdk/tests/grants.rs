//! Credential primitives through the call contract: raw grants to a device
//! that is not an issuer. See `docs/runtime/credentials.md`.
use common::{Device, Failure};
use rocky_sdk::{Database, Network, Open, transport::memory::Hub};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

mod common;

const SCHEMA: &str = r#"{"application":"shopping","version":1,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]},{"name":"notes","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"text","type":"text","not_null":true}],"primary_key":["key"]}]}"#;

fn open<'a>(directory: &'a Path, hub: &Arc<Hub>, name: &str) -> Open<'a> {
    Open {
        identity: None,
        directory,
        schema: SCHEMA,
        secrets: None,
        network: Some(Network::Owned(hub.connector(name))),
        coordination: None,
    }
}
fn create(root: &Path, hub: &Arc<Hub>, name: &str) -> Result<Device, Failure> {
    Device::new(Database::create(open(&root.join(name), hub, name), None)?)
}
/// The secret of `role` in a device's file key store, if any.
fn secret(root: &Path, name: &str, role: &str) -> Result<bool, Failure> {
    let identity: Value =
        serde_json::from_slice(&std::fs::read(root.join(name).join("identity.json"))?)?;
    let installation = identity["installation"].as_str().ok_or("installation")?;
    Ok(
        std::fs::read_dir(root.join(name).join("secrets"))?.any(|entry| {
            entry.is_ok_and(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!("rocky.{installation}.{role}."))
            })
        }),
    )
}
async fn mutate(
    device: &Device,
    handle: u8,
    payload: Value,
    entity: Value,
) -> Result<Value, Value> {
    device
        .call(json!({
            "type": "mutate",
            "handle": vec![handle; 32],
            "payload": payload.to_string().into_bytes(),
            "entity": entity,
            "baseline": null,
        }))
        .await
}
async fn insert(device: &Device, handle: u8, title: &str) -> Result<Value, Value> {
    let values = json!({"title": title, "completed": false});
    let payload = json!({"type": "create", "collection": "items", "values": values});
    mutate(device, handle, payload, Value::Null).await
}
async fn set(
    device: &Device,
    handle: u8,
    id: &Value,
    field: &str,
    value: Value,
) -> Result<Value, Value> {
    let payload = json!({"type": "set", "collection": "items", "field": field, "value": value});
    mutate(device, handle, payload, json!({"id": id})).await
}
async fn rows(device: &Device, sql: &str) -> Vec<Vec<String>> {
    let page = device
        .call(json!({"type": "read", "query": {"sql": sql, "values": [], "max_rows": 64}}))
        .await
        .unwrap_or_default();
    page["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|row| {
            row.as_array()
                .into_iter()
                .flatten()
                .map(|cell| cell["value"].as_str().unwrap_or_default().to_owned())
                .collect()
        })
        .collect()
}

#[tokio::test]
async fn raw_grants_reach_a_device_that_is_not_an_issuer() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let root = root.path();
    let hub = Arc::new(Hub::default());
    let a = create(root, &hub, "a")?;
    let directory = root.join("s");
    let keys = Database::device(&directory, None)?;
    let grant = |grants: Value| json!({"type": "grant", "device": keys, "grants": grants});
    // Command rights where no command is, unknown names and empty sets.
    for refused in [
        json!([{"scope": "items", "rights": ["execute"]}]),
        json!([{"scope": "items", "rights": ["invoke"]}]),
        json!([{"scope": "items", "rights": ["read"], "columns": ["missing"]}]),
        json!([{"scope": "missing", "rights": ["read"]}]),
        json!([{"scope": "items", "rights": ["publish_schema"]}]),
        json!([{"scope": "items", "rights": ["fly"]}]),
        json!([{"scope": "items", "rights": []}]),
        json!([]),
    ] {
        assert!(a.call(grant(refused.clone())).await.is_err(), "{refused}");
    }
    let granted = json!([
        {"scope": "items", "rights": ["read", "update", "custody"], "columns": ["completed"]},
        {"scope": "notes", "rights": ["custody"]},
    ]);
    let supplied = a.ok(grant(granted.clone())).await["supplied"].clone();
    let s = Device::new(Database::install(
        open(&directory, &hub, "s"),
        serde_json::from_value(supplied)?,
    )?)?;
    let status = s.ok(json!({"type": "session"})).await;
    assert_eq!(status["issuer"], json!(false));
    assert_eq!(
        status["profile"],
        json!({"kind": "grants", "grants": granted})
    );
    // Custody alone holds no reader key.
    assert!(secret(root, "s", "reader.items")?);
    assert!(!secret(root, "s", "reader.notes")?);

    let milk = insert(&a, 1, "Milk").await.map_err(|e| e.to_string())?["id"].clone();
    s.sync().await.map_err(|e| e.to_string())?;
    let items = "SELECT title, completed FROM items ORDER BY title";
    assert_eq!(rows(&s, items).await, [["Milk", "0"]]);
    // Exactly the granted rights: no insert, no other column.
    assert!(insert(&s, 2, "Eggs").await.is_err());
    assert!(set(&s, 3, &milk, "title", json!("Bread")).await.is_err());
    set(&s, 4, &milk, "completed", json!(true))
        .await
        .map_err(|e| e.to_string())?;
    s.sync().await.map_err(|e| e.to_string())?;
    assert_eq!(rows(&a, items).await, [["Milk", "1"]]);
    assert!(rows(&s, "SELECT text FROM notes").await.is_empty());

    // The issuer lists the device with its raw grants and can revoke it.
    let devices = a.ok(json!({"type": "devices"})).await;
    assert_eq!(devices["devices"][0]["profile"]["kind"], "grants");
    a.ok(json!({"type": "revoke", "node": keys.node.to_hex()}))
        .await;
    assert!(a.call(grant(granted)).await.is_err());
    for device in [&a, &s] {
        device.close().await;
    }
    Ok(())
}

#[tokio::test]
async fn an_invitation_carries_raw_grants() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let root = root.path();
    let hub = Arc::new(Hub::default());
    let a = create(root, &hub, "a")?;
    let profile = json!({"kind": "grants", "grants": [{"scope": "notes", "rights": ["read", "insert", "custody"]}]});
    let invitation = a.ok(json!({"type": "pairing", "profile": profile})).await["uri"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let j = Device::new(Database::join(
        open(&root.join("j"), &hub, "j"),
        &invitation,
    )?)?;
    assert_eq!(j.ok(json!({"type": "session"})).await["profile"], profile);
    let note = json!({"type": "create", "collection": "notes", "values": {"text": "Hello"}});
    mutate(&j, 1, note, Value::Null)
        .await
        .map_err(|e| e.to_string())?;
    assert!(insert(&j, 2, "Milk").await.is_err());
    j.sync().await.map_err(|e| e.to_string())?;
    assert_eq!(rows(&a, "SELECT text FROM notes").await, [["Hello"]]);
    // A renewal keeps exactly the raw grants.
    j.ok(json!({"type": "renew"})).await;
    assert_eq!(j.ok(json!({"type": "session"})).await["profile"], profile);
    for device in [&a, &j] {
        device.close().await;
    }
    Ok(())
}

/// Installs what `supplied` carries in a fresh directory `name`.
fn install(root: &Path, hub: &Arc<Hub>, name: &str, supplied: &Value) -> Result<Device, Failure> {
    Device::new(Database::install(
        open(&root.join(name), hub, name),
        serde_json::from_value(supplied.clone())?,
    )?)
}

#[tokio::test]
async fn a_delegate_never_holds_more_than_its_delegator() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let root = root.path();
    let hub = Arc::new(Hub::default());
    let a = create(root, &hub, "a")?;
    let s_keys = Database::device(&root.join("s"), None)?;
    let held = json!([
        {"scope": "items", "rights": ["read", "insert", "update", "delete", "custody"]},
        {"scope": "notes", "rights": ["read", "custody"]},
    ]);
    let supplied = a
        .ok(json!({"type": "grant", "device": s_keys, "grants": held, "delegations": 2}))
        .await["supplied"]
        .clone();
    let s = install(root, &hub, "s", &supplied)?;
    let d_keys = Database::device(&root.join("d"), None)?;
    let delegate = |grants: Value, extra: Value| {
        let mut request = json!({"type": "delegate", "device": d_keys, "grants": grants});
        for (name, value) in extra.as_object().into_iter().flatten() {
            request[name] = value.clone();
        }
        request
    };
    // No right, scope, column or depth the delegator lacks.
    let insert_only = json!([{"scope": "items", "rights": ["read", "insert", "custody"]}]);
    for (grants, extra) in [
        (
            json!([{"scope": "notes", "rights": ["read", "insert"]}]),
            json!({}),
        ),
        (
            json!([{"scope": "items", "rights": ["read", "invoke"]}]),
            json!({}),
        ),
        (insert_only.clone(), json!({"delegations": 2})),
        (insert_only.clone(), json!({"delegations": 0})),
    ] {
        assert!(
            s.call(delegate(grants.clone(), extra)).await.is_err(),
            "{grants}"
        );
    }
    // A device whose capability allows no further link delegates nothing;
    // an issuer grants instead.
    assert!(
        a.call(delegate(insert_only.clone(), json!({})))
            .await
            .is_err()
    );
    let plain_keys = Database::device(&root.join("p"), None)?;
    let plain = a
        .ok(json!({"type": "grant", "device": plain_keys, "grants": insert_only}))
        .await["supplied"]
        .clone();
    let p = install(root, &hub, "p", &plain)?;
    assert!(
        p.call(delegate(insert_only.clone(), json!({})))
            .await
            .is_err()
    );

    let supplied = s.ok(delegate(insert_only.clone(), json!({}))).await["supplied"].clone();
    let d = install(root, &hub, "d", &supplied)?;
    let status = d.ok(json!({"type": "session"})).await;
    assert_eq!(
        status["profile"],
        json!({"kind": "grants", "grants": insert_only})
    );
    // The delegate's chain is a link longer, valid no longer than its delegator's.
    assert!(
        status["expires"].as_str() <= s.ok(json!({"type": "session"})).await["expires"].as_str()
    );
    assert!(!secret(root, "d", "reader.notes")?);
    // Anyone who configured it serves it; its frames verify on arrival.
    for (left, right) in [(&a, &d)] {
        left.add_peer(&right.contact().await)
            .await
            .map_err(|e| e.to_string())?;
        right
            .add_peer(&left.contact().await)
            .await
            .map_err(|e| e.to_string())?;
    }
    let eggs = insert(&d, 1, "Eggs").await.map_err(|e| e.to_string())?["id"].clone();
    let delete = json!({"type": "delete", "collection": "items"});
    assert!(mutate(&d, 2, delete, json!({"id": eggs})).await.is_err());
    d.sync().await.map_err(|e| e.to_string())?;
    assert_eq!(rows(&a, "SELECT title FROM items").await, [["Eggs"]]);
    // Reopening the delegator preserves its recipient range for later grants.
    s.close().await;
    let s = Device::new(Database::open(open(&root.join("s"), &hub, "s"))?)?;
    // An issuer renews no delegated chain; the delegator delegates again.
    assert!(d.call(json!({"type": "renew"})).await.is_err());
    let narrower = json!([{"scope": "items", "rights": ["read", "custody"]}]);
    let renewed = s.ok(delegate(narrower.clone(), json!({}))).await["supplied"].clone();
    let renewed = d.ok(json!({"type": "install", "supplied": renewed})).await;
    assert_eq!(renewed["author"], status["author"]);
    let status = renewed;
    // Raw grants that are exactly a starter profile are shown as one.
    assert_eq!(
        status["profile"],
        json!({"kind": "reader", "scopes": ["items"]})
    );
    assert!(insert(&d, 3, "Jam").await.is_err());
    // Credentials of another device or wider than the delegator's are refused.
    assert!(
        d.call(json!({"type": "install", "supplied": plain}))
            .await
            .is_err()
    );
    for device in [&a, &s, &d, &p] {
        device.close().await;
    }
    Ok(())
}
