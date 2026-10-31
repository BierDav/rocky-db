//! The secure SDK engine end to end: enrollment, sync over iroh,
//! durable mutations, observation, renewal, revocation and logout.
use rocky_sdk::{Engine, Network, transport::memory::Hub};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

mod support;

type Failure = Box<dyn std::error::Error + Send + Sync>;

const SCHEMA: &str = r#"{"application":"shopping","version":1,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]},{"name":"notes","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"body","type":"text","not_null":false}],"primary_key":["key"]}]}"#;

fn iroh() -> Value {
    iroh_at(0)
}
/// Loopback only: no relay, no address lookup.
fn iroh_at(port: u16) -> Value {
    json!({"kind": "iroh", "relay": "disabled", "lookup": "disabled", "topic": false, "local": false, "bind": format!("127.0.0.1:{port}")})
}
/// A port free now, so a restarted creator listens where members look.
#[cfg(feature = "iroh")]
fn free_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("udp");
    socket.local_addr().expect("addr").port()
}

struct Db {
    engine: Arc<Engine>,
    scope: Value,
}
impl Db {
    fn open(directory: &Path, mode: Value, transport: Value) -> Result<Self, Failure> {
        Self::with_secrets(directory, mode, transport, None)
    }
    fn with_secrets(
        directory: &Path,
        mode: Value,
        transport: Value,
        secrets: Option<Arc<dyn rocky_sdk::SecretStore>>,
    ) -> Result<Self, Failure> {
        let mut options = mode;
        options["directory"] = json!(directory);
        options["transport"] = transport;
        let engine = Engine::open(&options.to_string(), SCHEMA, secrets)?;
        let scope = serde_json::from_str(&engine.scope())?;

        Ok(Self { engine, scope })
    }
    #[cfg(feature = "iroh")]
    fn create(directory: &Path, transport: Value) -> Result<Self, Failure> {
        Self::open(directory, json!({"mode": "create"}), transport)
    }
    fn join(directory: &Path, invitation: &str, transport: Value) -> Result<Self, Failure> {
        Self::open(
            directory,
            json!({"mode": "join", "invitation": invitation}),
            transport,
        )
    }
    #[cfg(feature = "iroh")]
    fn resume(directory: &Path, transport: Value) -> Result<Self, Failure> {
        Self::open(directory, json!({"mode": "resume"}), transport)
    }
    /// The value of a successful call, or its error object.
    async fn call(&self, request: Value) -> Result<Value, Value> {
        support::call(&self.scope, request, |request| self.raw_call(request)).await
    }
    async fn raw_call(&self, request: Value) -> Result<Value, Value> {
        let call = json!({"version": 1, "scope": self.scope, "request": request});
        let reply: Value = serde_json::from_str(
            &self
                .engine
                .call(call.to_string())
                .await
                .map_err(|error| json!(error.to_string()))?,
        )
        .map_err(|error| json!(error.to_string()))?;
        if reply["status"] == "ok" {
            Ok(reply["value"].clone())
        } else {
            Err(reply["error"].clone())
        }
    }
    async fn ok(&self, request: Value) -> Value {
        match self.call(request.clone()).await {
            Ok(value) => value,
            Err(error) => panic!("{request} failed: {error}"),
        }
    }
    async fn invite(&self) -> String {
        self.ok(json!({"type": "pairing", "profile": {"kind": "writer", "scopes": ["items"]}}))
            .await["uri"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }
    async fn sync(&self) -> Value {
        self.ok(json!({"type": "sync"})).await
    }
    async fn mutate(&self, handle: u8, payload: Value, id: Option<&str>) -> Result<Value, Value> {
        self.call(json!({
            "type": "mutate",
            "handle": vec![handle; 32],
            "payload": payload.to_string().into_bytes(),
            "entity": id.map(|id| json!({"id": id})),
            "baseline": null,
        }))
        .await
    }
    async fn add(&self, handle: u8, title: &str) -> String {
        let reply = self
            .mutate(
                handle,
                json!({"type": "create", "collection": "items", "values": {"title": title, "completed": false}}),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("create failed: {error}"));
        reply["id"].as_str().unwrap_or_default().to_owned()
    }
    /// Titles and completion of every item, by id.
    async fn items(&self) -> Vec<(String, String, i64)> {
        let page = self
            .ok(json!({"type": "read", "query": {"sql": "SELECT key, title, completed FROM items ORDER BY key", "values": [], "max_rows": 1024}}))
            .await;
        page["rows"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|row| {
                (
                    row[0]["value"].as_str().unwrap_or_default().to_owned(),
                    row[1]["value"].as_str().unwrap_or_default().to_owned(),
                    row[2]["value"]
                        .as_str()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(-1),
                )
            })
            .collect()
    }
    async fn close(&self) {
        self.engine.close().await.expect("close");
    }
}
fn titles(items: &[(String, String, i64)]) -> Vec<&str> {
    let mut titles: Vec<&str> = items.iter().map(|(_, title, _)| title.as_str()).collect();
    titles.sort();
    titles
}

#[cfg(feature = "iroh")]
async fn converge(at: fn(u16) -> Value) -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    // The creator keeps its port across the restart.
    let port = free_port();
    let transport = || at(port);
    let a_keys = Arc::new(support::secrets::Keys::default());
    let b_keys = Arc::new(support::secrets::Keys::default());
    let creator = Db::with_secrets(
        &root.path().join("a"),
        json!({"mode":"create"}),
        transport(),
        Some(a_keys.clone()),
    )?;
    assert_eq!(
        creator.ok(json!({"type": "domain"})).await["issuer"],
        json!(true)
    );
    let member = Db::with_secrets(
        &root.path().join("b"),
        json!({"mode":"join", "invitation":creator.invite().await}),
        at(0),
        Some(b_keys.clone()),
    )?;
    assert_eq!(
        member.ok(json!({"type": "domain"})).await["issuer"],
        json!(false)
    );
    assert_eq!(member.scope, creator.scope);

    let milk = creator.add(1, "Milk").await;
    assert!(support::reconciled(&member.sync().await));
    assert_eq!(titles(&member.items().await), ["Milk"]);

    // Offline edits of different fields converge; a delete is permanent.
    member
        .ok(json!({"type": "networking_control", "enabled": false}))
        .await;
    assert_eq!(member.sync().await["skip"], "networking_disabled");
    creator
        .mutate(
            2,
            json!({"type": "set", "collection": "items", "field": "title", "value": "Oat milk"}),
            Some(&milk),
        )
        .await
        .map_err(|error| error.to_string())?;
    member
        .mutate(
            3,
            json!({"type": "set", "collection": "items", "field": "completed", "value": true}),
            Some(&milk),
        )
        .await
        .map_err(|error| error.to_string())?;
    member.add(4, "Eggs").await;
    member
        .ok(json!({"type": "networking_control", "enabled": true}))
        .await;
    member.sync().await;
    assert_eq!(creator.items().await, member.items().await);
    assert!(
        creator
            .items()
            .await
            .contains(&(milk.clone(), "Oat milk".into(), 1))
    );
    creator
        .mutate(
            5,
            json!({"type": "delete", "collection": "items"}),
            Some(&milk),
        )
        .await
        .map_err(|error| error.to_string())?;
    member
        .mutate(
            6,
            json!({"type": "set", "collection": "items", "field": "title", "value": "Late"}),
            Some(&milk),
        )
        .await
        .map_err(|error| error.to_string())?;
    member.sync().await;
    assert_eq!(titles(&member.items().await), ["Eggs"]);
    assert_eq!(creator.items().await, member.items().await);

    // Both sides survive a restart and keep syncing.
    tokio::join!(member.close(), creator.close());
    let creator = Db::with_secrets(
        &root.path().join("a"),
        json!({"mode":"resume"}),
        transport(),
        Some(a_keys),
    )?;
    let member = Db::with_secrets(
        &root.path().join("b"),
        json!({"mode":"resume"}),
        at(0),
        Some(b_keys),
    )?;
    member.add(7, "Bread").await;
    creator.add(8, "Jam").await;
    member.sync().await;
    assert_eq!(titles(&creator.items().await), ["Bread", "Eggs", "Jam"]);
    assert_eq!(creator.items().await, member.items().await);
    tokio::join!(member.close(), creator.close());
    Ok(())
}

#[cfg(feature = "iroh")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn devices_converge_over_iroh() -> Result<(), Failure> {
    converge(iroh_at).await
}

#[cfg(feature = "iroh")]
#[tokio::test]
async fn mutations_are_durable_once_and_definite_rejections_are_final() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let db = Db::create(root.path(), iroh())?;
    let id = db.add(9, "Tea").await;
    assert_eq!(id.len(), 64);
    // The same handle reports its earlier commit and creates nothing else.
    let replay = db
        .mutate(9, json!({"type": "create", "collection": "items", "values": {"title": "Tea", "completed": false}}), None)
        .await
        .map_err(|error| error.to_string())?;
    assert_eq!(replay["replayed"], json!(true));
    assert_eq!(
        db.ok(json!({"type": "mutation_progress", "handle": vec![9u8; 32]}))
            .await["committed"],
        json!(true)
    );
    db.close().await;
    let db = Db::resume(root.path(), iroh())?;
    let replay = db
        .mutate(9, json!({"type": "create", "collection": "items", "values": {"title": "Tea", "completed": false}}), None)
        .await
        .map_err(|error| error.to_string())?;
    assert_eq!(replay["replayed"], json!(true));
    assert_eq!(db.items().await.len(), 1);
    // Rows of another collection, invalid values and unknown fields are definite.
    for (payload, entity) in [
        (
            json!({"type": "set", "collection": "notes", "field": "body", "value": "x"}),
            Some(id.as_str()),
        ),
        (
            json!({"type": "set", "collection": "items", "field": "completed", "value": "yes"}),
            Some(id.as_str()),
        ),
        (
            json!({"type": "set", "collection": "items", "field": "missing", "value": "x"}),
            Some(id.as_str()),
        ),
        (
            json!({"type": "create", "collection": "items", "values": {"title": "Only"}}),
            None,
        ),
    ] {
        let error = db
            .mutate(10, payload, entity)
            .await
            .err()
            .ok_or("mutation should fail")?;
        assert_eq!(error["retryable"], json!(false), "{error}");
    }
    // Reads cannot reach protocol tables or write.
    for sql in ["SELECT * FROM secure_rows", "DELETE FROM items"] {
        assert!(
            db.call(json!({"type": "read", "query": {"sql": sql, "values": [], "max_rows": 10}}))
                .await
                .is_err()
        );
    }
    db.close().await;
    Ok(())
}

#[cfg(feature = "iroh")]
#[tokio::test]
async fn pages_and_subscriptions_follow_committed_revisions() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let db = Db::create(root.path(), iroh())?;
    for handle in 1..=5 {
        db.add(handle, &format!("Item {handle}")).await;
    }
    let query =
        json!({"sql": "SELECT title FROM items ORDER BY title", "values": [], "max_rows": 2});
    let mut titles = Vec::new();
    let mut page = db.ok(json!({"type": "read", "query": query})).await;
    loop {
        titles.extend(
            page["rows"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|row| row[0]["value"].clone()),
        );
        let Some(cursor) = page["next"].as_str() else {
            break;
        };
        let mut next = query.clone();
        next["cursor"] = json!(cursor);
        page = db.ok(json!({"type": "read", "query": next})).await;
    }
    assert_eq!(titles.len(), 5);

    let subscription =
        db.ok(json!({"type": "subscribe", "query": query})).await["subscription"].clone();
    let first = db
        .ok(json!({"type": "next", "subscription": subscription}))
        .await;
    let waiting = {
        let engine = db.engine.clone();
        let call = json!({"version": 1, "scope": db.scope, "request": {"type": "next", "subscription": subscription}});
        tokio::spawn(async move { engine.call(call.to_string()).await })
    };
    tokio::task::yield_now().await;
    assert!(!waiting.is_finished());
    db.add(6, "A first").await;
    let changed: Value = serde_json::from_str(&waiting.await??)?;
    assert_ne!(changed["value"]["revision"], first["revision"]);
    assert_eq!(changed["value"]["rows"][0][0]["value"], "A first");
    db.ok(json!({"type": "unsubscribe", "subscription": subscription}))
        .await;
    db.close().await;
    Ok(())
}

#[cfg(feature = "iroh")]
#[tokio::test]
async fn renewal_revocation_and_logout_need_no_application_code() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let creator = Db::create(&root.path().join("a"), iroh())?;
    let alice = Db::join(&root.path().join("b"), &creator.invite().await, iroh())?;
    let invitation = creator.invite().await;
    // A wrong application schema does not consume the invitation.
    let mut wrong = json!({"mode": "join", "invitation": invitation});
    wrong["directory"] = json!(root.path().join("wrong"));
    wrong["transport"] = iroh();
    let other = SCHEMA.replace("shopping", "other");
    assert!(Engine::open(&wrong.to_string(), &other, None).is_err());
    let bob = Db::join(&root.path().join("c"), &invitation, iroh())?;
    // A used invitation enrolls nobody else.
    assert!(Db::join(&root.path().join("d"), &invitation, iroh()).is_err());

    let status = alice.ok(json!({"type": "session"})).await;
    assert_eq!(status["revocations"]["statements"], 0);
    assert_ne!(status["principal"], status["node"]);
    let renewed = alice.ok(json!({"type": "renew"})).await;
    assert!(renewed["expires"].as_str() >= status["expires"].as_str());

    // Revoking Bob adds a statement; Alice learns it on her next sync.
    let devices = creator.ok(json!({"type": "devices"})).await;
    assert_eq!(devices["devices"].as_array().map(Vec::len), Some(2));
    let bob_node = bob.ok(json!({"type": "session"})).await["node"].clone();
    assert_eq!(
        creator
            .ok(json!({"type": "revoke", "node": bob_node}))
            .await["revocations"]["statements"],
        1
    );
    creator.add(1, "After revocation").await;
    alice.sync().await;
    assert_eq!(
        alice.ok(json!({"type": "session"})).await["revocations"]["statements"],
        1
    );
    assert_eq!(titles(&alice.items().await), ["After revocation"]);
    // A refused link need not carry the signed revocation. Renewal fetches
    // that statement before checking local sync refusal and revoked reads.
    assert!(bob.call(json!({"type": "renew"})).await.is_err());
    assert!(bob.call(json!({"type": "sync"})).await.is_err());
    assert!(bob.items().await.is_empty());

    // The creator cannot log out; a member can, and purging removes its data.
    assert!(creator.call(json!({"type": "logout"})).await.is_err());
    alice.ok(json!({"type": "logout", "purge": true})).await;
    assert!(
        alice
            .call(
                json!({"type": "read", "query": {"sql": "SELECT 1", "values": [], "max_rows": 1}})
            )
            .await
            .is_err()
    );
    alice.close().await;
    assert!(!root.path().join("b/identity.json").exists());
    assert!(!root.path().join("b/secrets").exists());
    assert!(Db::resume(&root.path().join("b"), iroh()).is_err());
    bob.ok(json!({"type": "logout"})).await;
    bob.close().await;
    assert!(Db::resume(&root.path().join("c"), iroh()).is_err());
    creator.close().await;
    Ok(())
}

#[tokio::test]
async fn an_application_transport_carries_enrollment_and_sync() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let hub = Arc::new(Hub::default());
    let open = |directory: &str, mode: Value, name: &'static str| -> Result<Db, Failure> {
        let mut options = mode;
        options["directory"] = json!(root.path().join(directory));
        let network = Network::Owned(hub.connector(name));
        let engine = Engine::open_with(&options.to_string(), SCHEMA, None, Some(network))?;
        let scope = serde_json::from_str(&engine.scope())?;

        Ok(Db { engine, scope })
    };
    let creator = open("a", json!({"mode": "create"}), "a")?;
    assert_eq!(
        creator.ok(json!({"type": "domain"})).await["transport"],
        "memory"
    );
    let invitation = creator.invite().await;
    // A transport of another kind has no route in the invitation.
    assert!(Db::join(&root.path().join("other"), &invitation, iroh()).is_err());
    let member = open("b", json!({"mode": "join", "invitation": invitation}), "b")?;
    creator.add(1, "Milk").await;
    member.add(2, "Eggs").await;
    assert!(support::reconciled(&member.sync().await));
    assert_eq!(titles(&creator.items().await), ["Eggs", "Milk"]);
    assert_eq!(creator.items().await, member.items().await);

    // Both resume over it. Another kind opens too; see the peers suite.
    member.close().await;
    creator.close().await;
    let creator = open("a", json!({"mode": "resume"}), "a")?;
    let member = open("b", json!({"mode": "resume"}), "b")?;
    creator.add(3, "Jam").await;
    assert!(support::reconciled(&member.sync().await));
    assert_eq!(titles(&member.items().await), ["Eggs", "Jam", "Milk"]);
    member.close().await;
    creator.close().await;
    Ok(())
}
