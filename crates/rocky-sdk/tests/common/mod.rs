//! One device of the peer, fault and iroh suites: a database, a session
//! and the calls the suites repeat.
#![allow(dead_code)]
use rocky_sdk::{Database, Network, NetworkService, Open, Opened, Session};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

#[path = "../support/mod.rs"]
pub mod identity;

pub type Failure = Box<dyn std::error::Error + Send + Sync>;

pub const SCHEMA: &str = r#"{"application":"shopping","version":1,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]}]}"#;

pub struct Device {
    pub database: Arc<Database>,
    pub network: Option<NetworkService>,
    session: Session,
    scope: Value,
}
fn open(directory: &Path, network: Option<Network>) -> Open<'_> {
    Open {
        identity: None,
        directory,
        schema: SCHEMA,
        secrets: None,
        network,
        coordination: None,
    }
}
impl Device {
    /// Wraps a database opened some other way.
    pub fn new(opened: Opened) -> Result<Self, Failure> {
        Ok(Self {
            session: opened.database.session(),
            scope: serde_json::from_str(&opened.database.scope())?,
            database: opened.database,
            network: opened.network,
        })
    }
    pub fn create(directory: &Path, network: Option<Network>) -> Result<Self, Failure> {
        Self::new(Database::create(open(directory, network), None)?)
    }
    pub fn join(directory: &Path, invitation: &str, network: Network) -> Result<Self, Failure> {
        Self::new(Database::join(open(directory, Some(network)), invitation)?)
    }
    pub fn open(directory: &Path, network: Option<Network>) -> Result<Self, Failure> {
        Self::new(Database::open(open(directory, network))?)
    }
    /// The value of a successful call, or its error object.
    pub async fn call(&self, request: Value) -> Result<Value, Value> {
        identity::call(&self.scope, request, |request| self.raw_call(request)).await
    }
    async fn raw_call(&self, request: Value) -> Result<Value, Value> {
        let call = json!({"version": 1, "scope": self.scope, "request": request});
        let reply = self
            .session
            .call(call.to_string())
            .await
            .map_err(|error| json!(error.to_string()))?;
        let reply: Value =
            serde_json::from_str(&reply).map_err(|error| json!(error.to_string()))?;
        if reply["status"] == "ok" {
            Ok(reply["value"].clone())
        } else {
            Err(reply["error"].clone())
        }
    }
    pub async fn ok(&self, request: Value) -> Value {
        match self.call(request.clone()).await {
            Ok(value) => value,
            Err(error) => panic!("{request} failed: {error}"),
        }
    }
    pub async fn add(&self, handle: u8, title: &str) -> String {
        let reply = self
            .ok(json!({
                "type": "mutate",
                "handle": vec![handle; 32],
                "payload": json!({"type": "create", "collection": "items", "values": {"title": title, "completed": false}}).to_string().into_bytes(),
                "entity": null,
                "baseline": null,
            }))
            .await;
        reply["id"].as_str().unwrap_or_default().to_owned()
    }
    pub async fn set(&self, handle: u8, id: &str, field: &str, value: Value) {
        self.ok(json!({
            "type": "mutate",
            "handle": vec![handle; 32],
            "payload": json!({"type": "set", "collection": "items", "field": field, "value": value}).to_string().into_bytes(),
            "entity": {"id": id},
            "baseline": null,
        }))
        .await;
    }
    /// Every item as `title/completed`, sorted. Both fields are written
    /// by one transaction, so neither is ever missing.
    pub async fn items(&self) -> Vec<String> {
        let page = self
            .ok(json!({"type": "read", "query": {"sql": "SELECT title, completed FROM items ORDER BY title", "values": [], "max_rows": 1024}}))
            .await;
        page["rows"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|row| {
                let text = |cell: &Value| cell["value"].as_str().map(String::from);
                format!(
                    "{}/{}",
                    text(&row[0]).expect("title"),
                    text(&row[1]).expect("completed")
                )
            })
            .collect()
    }
    pub async fn titles(&self) -> Vec<String> {
        let items = self.items().await;
        items
            .iter()
            .filter_map(|item| item.split('/').next().map(String::from))
            .collect()
    }
    pub async fn sync(&self) -> Result<Value, Value> {
        let result = self.call(json!({"type": "sync"})).await?;

        Ok(result)
    }
    /// An invitation for a writer of the schema's one collection.
    pub async fn invite(&self) -> String {
        self.invite_as(json!({"kind": "writer", "scopes": ["items"]}))
            .await
    }
    pub async fn invite_as(&self, profile: Value) -> String {
        self.ok(json!({"type": "pairing", "profile": profile}))
            .await["uri"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }
    pub async fn contact(&self) -> String {
        self.text("contact", "uri").await
    }
    pub async fn node(&self) -> String {
        self.text("session", "node").await
    }
    async fn text(&self, request: &str, field: &str) -> String {
        self.ok(json!({"type": request})).await[field]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }
    pub async fn add_peer(&self, contact: &str) -> Result<Value, Value> {
        self.call(json!({"type": "peer_add", "contact": contact}))
            .await
    }
    /// The state the last sync left for the peer `node`.
    pub async fn peer(&self, node: &str) -> Value {
        let peers = self.ok(json!({"type": "peers"})).await;
        peers["peers"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|peer| peer["node"] == node)
            .cloned()
            .unwrap_or_default()
    }
    pub async fn close(&self) {
        self.database.close().await.expect("close");
    }
    /// The owner's application creates and follows `main` once; Rocky
    /// defines no bookmark.
    pub async fn follow_main(&self) {
        self.ok(json!({"type": "tips", "action": "create", "name": "main"}))
            .await;
        self.ok(json!({"type": "tips", "action": "follow", "name": "main"}))
            .await;
    }
    /// `follow_main` with the genesis line's signed minimum, which an
    /// issuer's migration opening inherits.
    pub async fn follow_main_migrating(&self) {
        self.follow_main().await;
        self.ok(json!({"type": "tips", "action": "genesis_minimum", "minimum_in_sync": 1}))
            .await;
    }
    /// Seals the followed tip and compacts at the seal: the base a joining
    /// or pruned peer imports.
    pub async fn seal_and_compact(&self) -> Value {
        self.ok(json!({"type": "tips", "action": "seal"})).await;
        self.ok(json!({"type": "tips", "action": "compact"})).await
    }
}
/// Configures each device as the other's peer.
pub async fn introduce(left: &Device, right: &Device) {
    left.add_peer(&right.contact().await).await.expect("peer");
    right.add_peer(&left.contact().await).await.expect("peer");
}

pub fn reconciled(report: &Value) -> bool {
    identity::reconciled(report)
}
#[allow(dead_code)]
pub fn exchange_failed(result: &Result<Value, Value>) -> bool {
    match result {
        Err(_) => true,
        Ok(report) => report["peers"].as_array().is_some_and(|peers| {
            peers.iter().any(|peer| {
                peer["skip"] == "backoff"
                    || peer["attempts"].as_array().is_some_and(|attempts| {
                        attempts
                            .iter()
                            .any(|attempt| attempt["outcome"] == "failed")
                    })
            })
        }),
    }
}

/// Confirms a removal after inspecting its report in a test.
pub fn confirmed(open: Open<'_>) -> Result<Opened, Failure> {
    let directory = open.directory;
    let schema = open.schema;
    let secrets = open.secrets.clone();
    let report = Database::open(Open {
        identity: None,
        directory,
        schema,
        secrets,
        network: None,
        coordination: None,
    })
    .err()
    .ok_or("expected removal confirmation")?
    .downcast::<rocky_sdk::RolloutConfirmationRequired>()?;
    Database::open_confirmed(open, &report.report.digest)
}
