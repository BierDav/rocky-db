//! Services composed without the starter engine: a database that opens with
//! no network, sessions sharing it, and network services that own or borrow
//! their transport. See `docs/runtime/sdk-composition.md`.
use rocky_sdk::{
    Database, Engine, Network, NetworkService, Open, Opened, ServiceError, Session,
    transport::{
        Connector, Transport,
        memory::{Hub, Memory},
    },
};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{Arc, atomic::Ordering},
};
type Failure = Box<dyn std::error::Error + Send + Sync>;

mod support;

const SCHEMA: &str = r#"{"application":"shopping","version":1,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]}]}"#;

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
fn service(error: &Failure) -> Option<&ServiceError> {
    error.downcast_ref()
}

/// One session and the scope its calls name.
struct Client {
    session: Session,
    scope: Value,
}
impl Client {
    fn new(database: &Arc<Database>) -> Result<Self, Failure> {
        Ok(Self {
            session: database.session(),
            scope: serde_json::from_str(&database.scope())?,
        })
    }
    fn frame(&self, request: Value) -> String {
        json!({"version": 1, "scope": self.scope, "request": request}).to_string()
    }
    /// The value of a successful call, or its error object.
    async fn call(&self, request: Value) -> Result<Value, Value> {
        support::call(&self.scope, request, |request| self.raw_call(request)).await
    }
    async fn raw_call(&self, request: Value) -> Result<Value, Value> {
        let reply = self
            .session
            .call(self.frame(request))
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
    async fn ok(&self, request: Value) -> Value {
        match self.call(request.clone()).await {
            Ok(value) => value,
            Err(error) => panic!("{request} failed: {error}"),
        }
    }
    async fn add(&self, handle: u8, title: &str) {
        self.ok(json!({
            "type": "mutate",
            "handle": vec![handle; 32],
            "payload": json!({"type": "create", "collection": "items", "values": {"title": title, "completed": false}}).to_string().into_bytes(),
            "entity": null,
            "baseline": null,
        }))
        .await;
    }
    async fn titles(&self) -> Vec<String> {
        let page = self
            .ok(json!({"type": "read", "query": {"sql": "SELECT title FROM items ORDER BY title", "values": [], "max_rows": 64}}))
            .await;
        page["rows"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|row| row[0]["value"].as_str().map(String::from))
            .collect()
    }
    async fn sync(&self) -> Result<Value, Value> {
        self.call(json!({"type": "sync"})).await
    }
}

fn memory(hub: &Arc<Hub>, name: &'static str) -> Arc<Memory> {
    hub.connector(name)
}

#[tokio::test]
async fn status_observation_does_not_block_commits_or_shutdown() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let Opened { database, .. } = Database::create(open(root.path(), None), None)?;
    let writer = Client::new(&database)?;
    let observer = Client::new(&database)?;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let writes = async {
            for id in 1..=4 {
                writer.add(id, "Milk").await;
            }
        };
        let observations = async {
            for _ in 0..8 {
                observer.ok(json!({"type": "status"})).await;
            }
        };
        tokio::join!(writes, observations);
        assert_eq!(writer.titles().await.len(), 4);
        database.close().await
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn a_database_opens_reads_writes_and_reopens_without_a_network() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let directory = root.path().join("a");
    let Opened { database, network } = Database::create(open(&directory, None), None)?;
    assert!(network.is_none());
    let client = Client::new(&database)?;
    let domain = client.ok(json!({"type": "domain"})).await;
    assert_eq!(domain["issuer"], json!(true));
    assert_eq!(domain["transport"], "");
    client.add(1, "Milk").await;
    assert_eq!(client.titles().await, ["Milk"]);
    // The creator issues its own credentials; nothing else works offline.
    client.ok(json!({"type": "renew"})).await;
    let writer = json!({"kind": "writer", "scopes": ["items"]});
    for request in [
        json!({"type": "sync"}),
        json!({"type": "pairing", "profile": writer}),
    ] {
        let error = client.call(request).await.err().ok_or("needs a network")?;
        assert_eq!(error["code"], "network_required", "{error}");
        assert_eq!(error["retryable"], json!(false));
    }
    database.close().await?;
    database.close().await?;

    let Opened { database, .. } = Database::open(open(&directory, None))?;
    let client = Client::new(&database)?;
    client.add(2, "Eggs").await;
    assert_eq!(client.titles().await, ["Eggs", "Milk"]);
    database.close().await?;

    // Combinations that cannot work are refused before anything is stored.
    let error = Database::join(open(&root.path().join("b"), None), "rocky://join/x")
        .err()
        .ok_or("join needs a network")?;
    assert_eq!(
        service(&error),
        Some(&ServiceError::NetworkRequired("join"))
    );
    assert!(!root.path().join("b").exists());
    assert!(Database::open(open(&root.path().join("b"), None)).is_err());
    assert!(Database::create(open(&directory, None), None).is_err());
    Ok(())
}

#[tokio::test]
async fn a_domain_enrolled_over_a_network_reopens_without_dialing() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let hub = Arc::new(Hub::default());
    let engine = |directory: &str, mode: Value, name| -> Result<Arc<Engine>, Failure> {
        let mut options = mode;
        options["directory"] = json!(root.path().join(directory));
        let network = Network::Owned(memory(&hub, name));
        Engine::open_with(&options.to_string(), SCHEMA, None, Some(network))
    };
    let call = async |engine: &Engine, request: Value| -> Result<Value, Failure> {
        let scope: Value = serde_json::from_str(&engine.scope())?;
        let call = json!({"version": 1, "scope": scope, "request": request});
        Ok(serde_json::from_str(&engine.call(call.to_string()).await?)?)
    };
    let creator = engine("a", json!({"mode": "create"}), "a")?;
    let invitation = call(
        &creator,
        json!({"type": "pairing", "profile": {"kind": "writer", "scopes": ["items"]}}),
    )
    .await?["value"]["uri"]
        .as_str()
        .ok_or("invitation")?
        .to_owned();
    let member = engine("b", json!({"mode": "join", "invitation": invitation}), "b")?;
    // Finish checkpoint-first enrollment before measuring network-free reopen.
    assert_eq!(
        call(&member, json!({"type": "sync"})).await?["status"],
        "ok"
    );

    member.close().await?;
    creator.close().await?;
    let enrolled = hub.counts();
    // Bootstrap and rows share a link; enrollment already supplies the node number.
    assert_eq!(enrolled, [2, 3, 2]);
    assert!(!hub.listens("a"));

    // Both devices open, write and reopen with no factory at all.
    for (directory, handle) in [("a", 1), ("b", 2)] {
        let directory = root.path().join(directory);
        for round in 0..2 {
            let Opened { database, network } = Database::open(open(&directory, None))?;
            assert!(network.is_none());
            let client = Client::new(&database)?;
            // No network is attached, and the domain is bound to none.
            assert_eq!(client.ok(json!({"type": "domain"})).await["transport"], "");
            client
                .add(handle + 10 * round, &format!("{handle}.{round}"))
                .await;
            assert_eq!(client.titles().await.len(), usize::from(round) + 1);
            assert_eq!(
                client.sync().await.err().ok_or("offline")?["code"],
                "network_required"
            );
            database.close().await?;
        }
    }
    assert_eq!(hub.counts(), enrolled);

    // The same encrypted sync path, attached to databases opened locally.
    let Opened {
        database: creator, ..
    } = Database::open(open(&root.path().join("a"), None))?;
    let Opened {
        database: member, ..
    } = Database::open(open(&root.path().join("b"), None))?;
    let serving = creator.attach(Network::Owned(memory(&hub, "a"))).await?;
    let syncing = member.attach(Network::Owned(memory(&hub, "b"))).await?;
    let (creator_client, member_client) = (Client::new(&creator)?, Client::new(&member)?);
    assert!(support::reconciled(
        &member_client.sync().await.map_err(|e| e.to_string())?
    ));
    assert_eq!(member_client.titles().await, ["1.0", "1.1", "2.0", "2.1"]);
    assert_eq!(creator_client.titles().await, member_client.titles().await);
    syncing.close().await;
    serving.close().await;
    member.close().await?;
    creator.close().await?;
    Ok(())
}

#[tokio::test]
async fn sessions_share_a_database_and_close_independently() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let Opened { database, .. } = Database::create(open(root.path(), None), None)?;
    let (first, second) = (Client::new(&database)?, Client::new(&database)?);
    let query =
        json!({"sql": "SELECT title FROM items ORDER BY title", "values": [], "max_rows": 8});
    let subscribe = async |client: &Client| {
        let token = client
            .ok(json!({"type": "subscribe", "query": query}))
            .await["subscription"]
            .clone();
        client
            .ok(json!({"type": "next", "subscription": token}))
            .await;
        token
    };
    let (first_token, second_token) = (subscribe(&first).await, subscribe(&second).await);
    // Tokens belong to their session.
    assert_eq!(first_token, second_token);
    let first = Arc::new(first);
    let waiting = {
        let first = first.clone();
        let token = first_token.clone();
        tokio::spawn(async move {
            first
                .call(json!({"type": "next", "subscription": token}))
                .await
        })
    };
    tokio::task::yield_now().await;
    assert!(!waiting.is_finished());

    // Closing one session ends its wait and nothing else.
    first.session.close().await;
    first.session.close().await;
    let ended = waiting.await?.err().ok_or("the wait ends")?;
    assert_eq!(ended["code"], "closed", "{ended}");
    let error = first
        .session
        .call(first.frame(json!({"type": "domain"})))
        .await
        .err()
        .ok_or("closed session")?;
    assert_eq!(service(&error), Some(&ServiceError::Closed("session")));

    second.add(1, "Milk").await;
    let page = second
        .ok(json!({"type": "next", "subscription": second_token}))
        .await;
    assert_eq!(page["rows"][0][0]["value"], "Milk");
    let third = Client::new(&database)?;
    assert_eq!(third.titles().await, ["Milk"]);

    // The owner closes the sessions that remain.
    database.close().await?;
    let error = second
        .session
        .call(second.frame(json!({"type": "domain"})))
        .await
        .err()
        .ok_or("closed database")?;
    assert_eq!(service(&error), Some(&ServiceError::Closed("database")));
    Ok(())
}

#[tokio::test]
async fn borrowed_networks_outlive_their_service_and_owned_ones_are_released() -> Result<(), Failure>
{
    let root = tempfile::tempdir()?;
    let hub = Arc::new(Hub::default());
    // The application starts and keeps these two.
    let listening: Arc<dyn Transport> = memory(&hub, "a").start(true, [0; 32]).await?;
    let dialing: Arc<dyn Transport> = memory(&hub, "b").start(false, [0; 32]).await?;

    let Opened {
        database: creator, ..
    } = Database::create(open(&root.path().join("a"), None), None)?;
    let creator_client = Client::new(&creator)?;
    let serving = creator.attach(Network::Borrowed(listening.clone())).await?;
    let error = creator
        .attach(Network::Borrowed(listening.clone()))
        .await
        .err()
        .ok_or("one network at a time")?;
    assert_eq!(service(&error), Some(&ServiceError::NetworkAttached));
    // The status names the attached network's kind.
    assert_eq!(
        creator_client.ok(json!({"type": "domain"})).await["transport"],
        "memory"
    );
    let invitation = creator_client
        .ok(json!({"type": "pairing", "profile": {"kind": "writer", "scopes": ["items"]}}))
        .await["uri"]
        .as_str()
        .ok_or("invitation")?
        .to_owned();

    let member_directory = root.path().join("b");
    let Opened {
        database: member,
        network,
    } = Database::join(
        open(&member_directory, Some(Network::Borrowed(dialing.clone()))),
        &invitation,
    )?;
    let syncing: NetworkService = network.ok_or("the joining network stays attached")?;
    let member_client = Client::new(&member)?;
    creator_client.add(1, "Milk").await;
    member_client.sync().await.map_err(|e| e.to_string())?;
    assert_eq!(member_client.titles().await, ["Milk"]);

    // Closing the services leaves both databases and both transports open.
    syncing.close().await;
    syncing.close().await;
    serving.close().await;
    assert_eq!(hub.counts()[2], 0);
    assert!(hub.listens("a"));
    assert_eq!(
        member_client.sync().await.err().ok_or("detached")?["code"],
        "network_required"
    );
    member_client.add(2, "Eggs").await;
    creator_client.add(3, "Jam").await;

    // The same transports serve again once attached again.
    let serving = creator.attach(Network::Borrowed(listening.clone())).await?;
    let syncing = member.attach(Network::Borrowed(dialing.clone())).await?;
    member_client.sync().await.map_err(|e| e.to_string())?;
    assert_eq!(member_client.titles().await, ["Eggs", "Jam", "Milk"]);
    assert_eq!(creator_client.titles().await, member_client.titles().await);
    drop((serving, syncing));

    // Closing a database detaches its service; a borrowed transport stays.
    member.close().await?;
    creator.close().await?;
    assert_eq!(hub.counts()[2], 0);
    assert!(hub.listens("a"));
    listening.close().await;
    dialing.close().await;
    assert_eq!(hub.counts()[2], 2);

    // A service that started its transport closes it, once.
    let Opened {
        database: creator,
        network,
    } = Database::open(open(
        &root.path().join("a"),
        Some(Network::Owned(memory(&hub, "a"))),
    ))?;
    let serving = network.ok_or("attached at open")?;
    assert!(hub.listens("a"));
    serving.close().await;
    assert!(!hub.listens("a"));
    assert_eq!(hub.counts()[2], 3);
    assert_eq!(Client::new(&creator)?.titles().await.len(), 3);
    creator.close().await?;
    assert_eq!(hub.counts()[2], 3);
    Ok(())
}

#[tokio::test]
async fn a_closing_service_cancels_work_that_outlasts_its_drain() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let hub = Arc::new(Hub::default());
    let Opened {
        database: creator, ..
    } = Database::create(
        open(
            &root.path().join("a"),
            Some(Network::Owned(memory(&hub, "a"))),
        ),
        None,
    )?;
    let creator_client = Client::new(&creator)?;
    let invitation = creator_client
        .ok(json!({"type": "pairing", "profile": {"kind": "writer", "scopes": ["items"]}}))
        .await["uri"]
        .as_str()
        .ok_or("invitation")?
        .to_owned();
    let member_directory = root.path().join("b");
    let Opened {
        database: member,
        network,
    } = Database::join(
        open(&member_directory, Some(Network::Owned(memory(&hub, "b")))),
        &invitation,
    )?;
    let syncing = network.ok_or("attached")?;
    let member_client = Arc::new(Client::new(&member)?);
    member_client.add(1, "Milk").await;

    // A dial that never completes holds the sync until the service closes.
    hub.stalled.store(true, Ordering::SeqCst);
    let stuck = {
        let client = member_client.clone();
        tokio::spawn(async move { client.sync().await })
    };
    while hub.counts()[1] < 2 {
        tokio::task::yield_now().await;
    }
    let started = std::time::Instant::now();
    syncing.close().await;
    assert!(started.elapsed().as_secs() >= 4);
    assert_eq!(stuck.await?.err().ok_or("cancelled")?["code"], "closed");
    assert_eq!(hub.counts()[2], 1);

    // The database is intact and the interrupted sync is safe to repeat.
    member_client.add(2, "Eggs").await;
    hub.stalled.store(false, Ordering::SeqCst);
    member.attach(Network::Owned(memory(&hub, "b"))).await?;
    member_client.sync().await.map_err(|e| e.to_string())?;
    assert_eq!(creator_client.titles().await, ["Eggs", "Milk"]);
    member.close().await?;
    creator.close().await?;
    assert_eq!(hub.counts()[2], 3);
    Ok(())
}
