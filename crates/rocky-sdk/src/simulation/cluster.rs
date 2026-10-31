//! The simulated nodes: databases hosted on the simulation's thread, each
//! with its directory, its secrets and its name on the hub.
use crate::{
    Database, Failure, Network, Open, SecretStore, Session, database::Install,
    enrollment::DEFAULT_TTL, node::Node, transport::memory::Hub,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError, Weak},
};

fn text(value: &str) -> Value {
    json!({"type": "text", "value": value})
}

pub(super) const SCHEMA: &str = r#"{"application":"simulation","version":1,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]},{"name":"parts","class":"replayed","columns":[{"name":"list","type":"text","not_null":true},{"name":"key","type":"text","not_null":true}],"primary_key":["list","key"],"partition_by":["list"],"partition_group":"list"}]}"#;

/// Keys in memory, kept across restarts and crashes of one node.
#[derive(Default)]
pub(super) struct Keys(Mutex<BTreeMap<String, Vec<u8>>>);
impl SecretStore for Keys {
    fn load(&self, name: &str) -> Result<Option<Vec<u8>>, Failure> {
        Ok(self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name)
            .cloned())
    }
    fn store(&self, name: &str, secret: &[u8]) -> Result<(), Failure> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(name.into(), secret.to_vec());
        Ok(())
    }
    fn delete(&self, name: &str) -> Result<(), Failure> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(name);
        Ok(())
    }
}

/// An open node.
pub(super) struct Running {
    pub(super) database: Arc<Database>,
    session: Session,
    scope: Value,
    pub(super) node: Weak<Node>,
}
/// One simulated device, open or not.
pub(super) struct Member {
    pub(super) name: String,
    pub(super) directory: PathBuf,
    keys: Arc<Keys>,
    pub(super) running: Option<Running>,
    /// Its node key, once known.
    pub(super) node_key: Option<String>,
    /// Revoked members never open again.
    pub(super) revoked: bool,
}

impl Member {
    pub(super) fn new(root: &Path, name: &str) -> Self {
        Self {
            name: name.into(),
            directory: root.join(name),
            keys: Arc::default(),
            running: None,
            node_key: None,
            revoked: false,
        }
    }
    /// Starts the node: creating, joining or opening its directory.
    pub(super) async fn start(&mut self, hub: &Arc<Hub>, install: Install) -> Result<(), Failure> {
        let secrets: Arc<dyn SecretStore> = self.keys.clone();
        let hosted = Database::host(
            Open {
                directory: &self.directory,
                schema: SCHEMA,
                secrets: Some(secrets),
                identity: None,
                network: Some(Network::Owned(hub.connector(&self.name))),
                coordination: None,
            },
            install,
        )
        .await?;
        let database = hosted.opened.database;
        self.running = Some(Running {
            session: database.session(),
            scope: serde_json::from_str(&database.scope())?,
            database,
            node: hosted.node,
        });
        if self.node_key.is_none() {
            self.node_key = self.call(json!({"type": "session"})).await?["node"]
                .as_str()
                .map(String::from);
        }
        Ok(())
    }
    pub(super) async fn create(&mut self, hub: &Arc<Hub>) -> Result<(), Failure> {
        self.start(hub, Install::Create { ttl: DEFAULT_TTL }).await
    }
    pub(super) async fn join(&mut self, hub: &Arc<Hub>, invitation: &str) -> Result<(), Failure> {
        self.start(
            hub,
            Install::Join {
                invitation: invitation.into(),
            },
        )
        .await
    }
    pub(super) async fn open(&mut self, hub: &Arc<Hub>) -> Result<(), Failure> {
        self.start(hub, Install::Installed).await
    }
    /// Closes the node as an application does.
    pub(super) async fn close(&mut self) -> Result<(), Failure> {
        if let Some(running) = self.running.take() {
            running.session.close().await;
            running.database.close().await?;
        }
        Ok(())
    }
    /// Stops the node as a process death does.
    pub(super) async fn crash(&mut self) {
        if let Some(running) = self.running.take() {
            running.database.crash().await;
        }
    }
    /// The value of a call, or its error object as an error.
    pub(super) async fn call(&self, request: Value) -> Result<Value, Failure> {
        let running = self.running.as_ref().ok_or("the node is not running")?;
        let call = json!({"version": 1, "scope": running.scope, "request": request});
        let reply: Value = serde_json::from_str(&running.session.call(call.to_string()).await?)?;
        if reply["status"] == "ok" {
            Ok(reply["value"].clone())
        } else {
            Err(reply["error"].to_string().into())
        }
    }
    /// One transaction of two rows, `key-a` and `key-b`, under a handle
    /// that makes a retry safe.
    pub(super) async fn write(&self, key: &str, handle: u64) -> Result<(), Failure> {
        let rows = ["a", "b"].map(|half| vec![text(&format!("{key}-{half}")), text(key)]);
        self.insert("items", "key, title", &rows, handle, 0).await
    }
    /// One row of the partition `list`.
    pub(super) async fn write_part(
        &self,
        list: &str,
        key: &str,
        handle: u64,
    ) -> Result<(), Failure> {
        self.insert(
            "parts",
            "list, key",
            &[vec![text(list), text(key)]],
            handle,
            1,
        )
        .await
    }
    /// Inserts `rows` of `table` in one transaction; `kind` keeps the
    /// handles of different writes of one step apart.
    async fn insert(
        &self,
        table: &str,
        columns: &str,
        rows: &[Vec<Value>],
        handle: u64,
        kind: u8,
    ) -> Result<(), Failure> {
        self.call(json!({"type": "sql", "sql": "BEGIN"})).await?;
        let result = async {
            for values in rows {
                let id = self
                    .call(json!({"type": "next_id", "table": table}))
                    .await?["id"]
                    .clone();
                let mut values = values.clone();
                values.push(json!({"type": "integer", "value": id}));
                let places = vec!["?"; values.len()].join(", ");
                self.call(json!({
                    "type": "sql",
                    "sql": format!("INSERT INTO {table}({columns}, id) VALUES({places})"),
                    "values": values,
                }))
                .await?;
            }
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&handle.to_be_bytes());
            bytes[8] = kind;
            self.call(json!({"type": "sql", "sql": "COMMIT", "handle": bytes.to_vec()}))
                .await
        }
        .await;
        if result.is_err() {
            let _ = self.call(json!({"type": "sql", "sql": "ROLLBACK"})).await;
        }
        result.map(drop)
    }
    /// Every item key, sorted.
    pub(super) async fn keys(&self) -> Result<Vec<String>, Failure> {
        let mut keys = Vec::new();
        let mut after = String::new();
        loop {
            let page = self
                .call(json!({"type": "read", "query": {
                    "sql": "SELECT key FROM items WHERE key > ? ORDER BY key",
                    "values": [{"type": "text", "value": after}],
                    "max_rows": 512,
                }}))
                .await?;
            let rows = page["rows"].as_array().ok_or("rows")?;
            for row in rows {
                keys.push(row[0]["value"].as_str().ok_or("key")?.to_owned());
            }
            match keys.last() {
                Some(last) if rows.len() == 512 => after = last.clone(),
                _ => return Ok(keys),
            }
        }
    }
    pub(super) async fn contact(&self) -> Result<String, Failure> {
        Ok(self.call(json!({"type": "contact"})).await?["uri"]
            .as_str()
            .ok_or("contact")?
            .to_owned())
    }
}
