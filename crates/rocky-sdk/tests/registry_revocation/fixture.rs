//! The Phase 7 hub, registry and group-key fixtures.
use super::{Device, Failure};
use rocky_sdk::{Database, Network, Open, SecretStore, transport::memory::Hub};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
};

pub(super) const SCHEMA: &str = r#"{"application":"revocation","version":1,"format":6,"tables":[
 {"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]},
 {"name":"notes","class":"replayed","columns":[{"name":"key","type":"text","not_null":true}],"primary_key":["key"]},
 {"name":"parts","class":"replayed","columns":[{"name":"list","type":"text","not_null":true},{"name":"key","type":"text","not_null":true}],"primary_key":["list","key"],"partition_by":["list"],"partition_group":"list"},
 {"name":"labels","class":"replayed","columns":[{"name":"list","type":"text","not_null":true},{"name":"key","type":"text","not_null":true}],"primary_key":["list","key"],"partition_by":["list"],"partition_group":"list"}]}"#;

/// Keys in memory: the file store syncs every key, which dominated these
/// tests. A device keeps its keys across reopens of the same directory.
#[derive(Default)]
struct Keys(Mutex<HashMap<String, Vec<u8>>>);
impl SecretStore for Keys {
    fn load(&self, name: &str) -> Result<Option<Vec<u8>>, Failure> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "poisoned keys")?
            .get(name)
            .cloned())
    }
    fn store(&self, name: &str, secret: &[u8]) -> Result<(), Failure> {
        self.0
            .lock()
            .map_err(|_| "poisoned keys")?
            .insert(name.into(), secret.to_vec());
        Ok(())
    }
    fn delete(&self, name: &str) -> Result<(), Failure> {
        self.0.lock().map_err(|_| "poisoned keys")?.remove(name);
        Ok(())
    }
}
static KEYS: LazyLock<Mutex<HashMap<PathBuf, Arc<Keys>>>> = LazyLock::new(Default::default);

/// The key store of the device in `directory`.
pub(super) fn keys(directory: &Path) -> Arc<dyn SecretStore> {
    KEYS.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(directory.to_path_buf())
        .or_default()
        .clone()
}
pub(super) fn open<'a>(root: &'a Path, hub: &Arc<Hub>, name: &str) -> Open<'a> {
    Open {
        identity: None,
        directory: root,
        schema: SCHEMA,
        secrets: Some(keys(root)),
        network: Some(Network::Owned(hub.connector(name))),
        coordination: None,
    }
}
pub(super) fn identity(root: &Path, name: &str) -> Result<Value, Failure> {
    let mut identity: Value =
        serde_json::from_slice(&std::fs::read(root.join(name).join("identity.json"))?)?;
    for epochs in identity["keys"].as_object_mut().ok_or("keys")?.values_mut() {
        for epoch in epochs.as_array_mut().ok_or("epochs")? {
            *epoch = epoch["generation"].clone();
        }
    }
    Ok(identity)
}
pub(super) async fn sync(device: &Device) -> Result<(), Failure> {
    device.sync().await.map_err(|error| error.to_string())?;
    Ok(())
}
pub(super) async fn settle(device: &Device) {
    let mut status = device.ok(json!({"type":"status"})).await;
    while status["data"]["bootstrap_pending"] == true {
        status = device
            .ok(json!({"type":"status_next","after":status["token"]}))
            .await;
    }
}
pub(super) async fn join(
    root: &Path,
    hub: &Arc<Hub>,
    name: &str,
    issuer: &Device,
    profile: Value,
) -> Result<Device, Failure> {
    let invite = issuer.invite_as(profile).await;
    let device = Device::new(Database::join(open(&root.join(name), hub, name), &invite)?)?;
    settle(&device).await;
    Ok(device)
}
pub(super) async fn listed(device: &Device, node: &str) -> Value {
    device.ok(json!({"type":"devices"})).await["devices"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|record| record["node"] == node)
        .cloned()
        .unwrap_or_default()
}
pub(super) fn values(list: &str) -> Value {
    json!([{"type":"text","value":list}])
}
pub(super) async fn epoch(device: &Device, list: &str) -> Value {
    let status = device
        .ok(json!({"type":"partition_status","group":"list","values":values(list)}))
        .await;
    for table in status["tables"].as_array().into_iter().flatten() {
        assert_eq!(table["epochs"], status["epochs"], "{status}");
    }
    json!(
        status["epochs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|epoch| epoch["generation"].clone())
            .collect::<Vec<_>>()
    )
}
pub(super) async fn grant(device: &Device, list: &str) -> Value {
    let address = device
        .ok(json!({"type":"partition_address","table":"parts","values":values(list)}))
        .await;
    let part = &address["tuple"][0];
    json!({"domain":address["scope"]["domain"],"table":address["scope"]["table"],
        "selector":[[part[0],{"Only":[part[1]]}]],"rows":"All","rights":["Read"],"fields":[]})
}
pub(super) struct Domain {
    pub(super) a: Device,
    pub(super) b: Device,
}
impl Domain {
    pub(super) async fn new(root: &Path, hub: &Arc<Hub>) -> Result<Self, Failure> {
        let a = Device::new(Database::create(open(&root.join("a"), hub, "a"), None)?)?;
        a.follow_main().await;
        let b = join(root, hub, "b", &a, json!({"kind":"issuer"})).await?;
        for list in ["L", "M"] {
            a.ok(json!({"type":"partition_create","group":"list","values":values(list)}))
                .await;
            a.ok(json!({"type":"partition_share","group":"list","values":values(list),"recipients":[b.node().await]})).await;
        }
        // B collects both envelopes from A.
        sync(&b).await?;
        Ok(Self { a, b })
    }
}
