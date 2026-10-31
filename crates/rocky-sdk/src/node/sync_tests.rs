mod state_advice;
mod status;
use super::*;
use crate::{
    FileSecretStore,
    schema::Schema,
    transport::{Connector, memory::Hub},
};

const SCHEMA: &str = r#"{"application":"sync","version":1,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]}]}"#;

/// A request session of `dialer` and the session of `acceptor` answering it,
/// on a link over an in-memory pipe that the test drives instead of a service.
async fn link_sessions(
    dialer: &Node,
    acceptor: &Node,
) -> Result<
    (
        rocky_secure::network::NativeSession,
        rocky_secure::network::NativeSession,
    ),
    Failure,
> {
    let (dialed, accepted) = opened_links(dialer, acceptor).await?;
    let handle = dialed.channels.handle.clone();
    let (served, mut incoming) = tokio::sync::mpsc::channel(1);
    tokio::task::spawn_local(dialed.drive(tokio::sync::mpsc::channel(1).0));
    tokio::task::spawn_local(accepted.drive(served));
    let session = handle.open().await?;
    let answering = incoming.recv().await.ok_or("link ended")?;
    Ok((session, answering))
}

async fn opened_links(
    dialer: &Node,
    acceptor: &Node,
) -> Result<
    (
        rocky_secure::network::link::Link,
        rocky_secure::network::link::Link,
    ),
    Failure,
> {
    use rocky_secure::network::link::Link;
    let (near, far) = tokio::io::duplex(64 * 1024);
    let accepting = PrivateKey::from_bytes(&acceptor.vault.get("node")?);
    let expected = accepting.public_key();
    let (near_credentials, far_credentials) = (
        dialer.settings.lock().await.credentials.clone(),
        acceptor.settings.lock().await.credentials.clone(),
    );
    let (dialed, accepted) = tokio::join!(
        Link::open(
            near,
            &dialer.replica,
            PrivateKey::from_bytes(&dialer.vault.get("node")?),
            near_credentials,
            Some(expected),
        ),
        Link::open(far, &acceptor.replica, accepting, far_credentials, None),
    );
    let (mut dialed, mut accepted) = (dialed?, accepted?);
    let (near, far) = tokio::join!(dialed.ready(false), accepted.ready(false));
    near?;
    far?;
    Ok((dialed, accepted))
}

async fn node(
    root: &std::path::Path,
    settings: Settings,
    vault: Vault,
    transport: Arc<dyn Transport>,
) -> Result<Arc<Node>, Failure> {
    let domain = settings.domain()?;
    let replica = EncryptedReplica::open(
        root.join("rocky.sqlite"),
        domain.app.clone(),
        settings.config(&vault, &domain)?,
    )
    .await?;
    replica
        .register_credential_signer(PrivateKey::from_bytes(&vault.get("node")?))
        .await?;
    replica
        .install_readable_tables(domain.logical().clone(), domain.scope, domain.readers())
        .await?;
    let node = Arc::new(Node::new(
        replica,
        domain,
        vault,
        settings,
        root.join("identity.json"),
    ));
    node.link(transport, true).await;
    Ok(node)
}
async fn enrolled(
    root: &std::path::Path,
    hub: &Arc<Hub>,
    name: &str,
    issuer: Option<(&Arc<Node>, Profile)>,
) -> Result<Arc<Node>, Failure> {
    enrolled_schema(root, hub, name, issuer, &Schema::parse(SCHEMA)?).await
}
#[derive(Default)]
struct TestSecrets(std::sync::Mutex<BTreeMap<String, Vec<u8>>>);
impl crate::SecretStore for TestSecrets {
    fn load(&self, name: &str) -> Result<Option<Vec<u8>>, Failure> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "secret store poisoned")?
            .get(name)
            .cloned())
    }
    fn store(&self, name: &str, bytes: &[u8]) -> Result<(), Failure> {
        self.0
            .lock()
            .map_err(|_| "secret store poisoned")?
            .insert(name.into(), bytes.to_vec());
        Ok(())
    }
    fn delete(&self, name: &str) -> Result<(), Failure> {
        self.0
            .lock()
            .map_err(|_| "secret store poisoned")?
            .remove(name);
        Ok(())
    }
}
async fn enrolled_schema(
    root: &std::path::Path,
    hub: &Arc<Hub>,
    name: &str,
    issuer: Option<(&Arc<Node>, Profile)>,
    schema: &Schema,
) -> Result<Arc<Node>, Failure> {
    std::fs::create_dir_all(root)?;
    let store: Arc<dyn crate::SecretStore> = Arc::new(TestSecrets::default());
    let path = root.join("identity.json");
    if let Some((issuer, profile)) = issuer {
        let link = issuer.network.read().await;
        let registry = issuer.registry().await?;
        let (invite, _) = issuer
            .settings
            .lock()
            .await
            .invite(
                &issuer.path,
                &issuer.vault,
                &*link.as_ref().ok_or("link")?.transport,
                (profile, None),
                &registry,
            )
            .await?;
        let joining = Settings::prepare_join(&path, &invite, &store, None)?;
        let transport = hub
            .connector(name)
            .start(false, Settings::transport_key(&joining.vault)?)
            .await?;
        let settings = joining.enroll(&path, schema, &*transport).await?;
        let vault = settings.vault(&store);
        node(root, settings, vault, transport).await
    } else {
        let settings = Settings::create(schema, &store, crate::enrollment::DEFAULT_TTL, None)?;
        settings.save(&path)?;
        let vault = settings.vault(&store);
        let transport = hub
            .connector(name)
            .start(true, Settings::transport_key(&vault)?)
            .await?;
        node(root, settings, vault, transport).await
    }
}
async fn enable(node: &Node) -> Result<(), Failure> {
    let mut statuses = node.sync_status.subscribe();
    let before = statuses.borrow_and_update()["token"].clone();
    node.automatic.store(true, Ordering::SeqCst);
    node.wake_sync();
    statuses
        .wait_for(|status| status["token"] != before && status["state"] == "connected")
        .await?;
    assert_eq!(statuses.borrow()["state"], "connected");
    Ok(())
}

async fn add(node: &Node, handle: u8) -> Result<(), Failure> {
    let client = node.client(1)?;
    node.dispatch(&client, &json!({"type":"sql","sql":"BEGIN"}))
        .await?;
    let id = node
        .dispatch(&client, &json!({"type":"next_id","table":"items"}))
        .await?["id"]
        .clone();
    node.dispatch(&client, &json!({"type":"sql","sql":"INSERT INTO items(key,title,id) VALUES(?,'Milk',?)","values":[{"type":"text","value":handle.to_string()},{"type":"integer","value":id}]})).await?;
    node.dispatch(
        &client,
        &json!({"type":"sql","sql":"COMMIT","handle":vec![handle;32]}),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn idle_has_no_poll_and_a_commit_reaches_the_peer_without_time_advancing()
-> Result<(), Failure> {
    tokio::task::LocalSet::new().run_until(async {
        let root = tempfile::tempdir()?;
        let hub = Arc::new(Hub::default());
        let a = enrolled(&root.path().join("a"), &hub, "a", None).await?;
        let b = enrolled(&root.path().join("b"), &hub, "b", Some((&a, Profile::Writer {scopes:["items".into()].into()}))).await?;
        let contact = {
            let link = b.network.read().await;
            b.settings.lock().await.contact(&b.vault, &*link.as_ref().ok_or("link")?.transport).await?.0
        };
        a.configure(|settings| settings.add_peer(&a.vault, &contact)).await?;
        enable(&a).await?;
        enable(&b).await?;
        assert_eq!(a.sync_status.borrow()["retry"], false);
        assert_eq!(b.sync_status.borrow()["retry"], false);
        while !a.current().is_some_and(|service| service.live.len() == 1)
            || !b.current().is_some_and(|service| service.live.len() == 1)
            || *a.worker_running.borrow()
            || *b.worker_running.borrow()
        {
            tokio::task::yield_now().await;
        }
        let dials = hub.counts()[1];
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(86400)).await;
        tokio::task::yield_now().await;
        assert_eq!(hub.counts()[1], dials, "successful idle service must not dial on a timer");
        tokio::time::resume();
        let mut revisions = b.replica.observe_revision();
        add(&a, 1).await?;
        tokio::time::timeout(Duration::from_secs(5), revisions.changed()).await??;
        let client = b.client(1)?;
        let page = b.dispatch(&client, &json!({"type":"read", "query":{"sql":"SELECT title FROM items", "max_rows":64}})).await?;
        assert_eq!(page["rows"][0][0]["value"], "Milk");
        a.detach(None).await;
        b.detach(None).await;
        Ok(())
    }).await
}

/// Requests share a link that is not persistent: it closes when the last of
/// them ends, not under the others when the first does.
#[tokio::test]
async fn a_short_link_stays_open_until_its_last_request_ends() -> Result<(), Failure> {
    tokio::task::LocalSet::new()
        .run_until(async {
            let root = tempfile::tempdir()?;
            let hub = Arc::new(Hub::default());
            let a = enrolled(&root.path().join("a"), &hub, "a", None).await?;
            let profile = Profile::Writer {
                scopes: ["items".into()].into(),
            };
            let b = enrolled(&root.path().join("b"), &hub, "b", Some((&a, profile))).await?;
            let contact = {
                let link = b.network.read().await;
                let transport = &*link.as_ref().ok_or("link")?.transport;
                b.settings
                    .lock()
                    .await
                    .contact(&b.vault, transport)
                    .await?
                    .0
            };
            a.configure(|settings| settings.add_peer(&a.vault, &contact))
                .await?;
            let (peer, contact) = a
                .settings
                .lock()
                .await
                .targets()
                .into_iter()
                .next()
                .ok_or("peer")?;
            let service = a.current().ok_or("service")?;
            a.request_link(&*service.transport, peer, &contact).await?;
            let (first, second) = (service.live.short(peer), service.live.short(peer));
            drop(first);
            assert!(service.live.handle(peer).is_some());
            drop(second);
            assert!(service.live.handle(peer).is_none());
            a.detach(None).await;
            b.detach(None).await;
            Ok(())
        })
        .await
}

#[tokio::test]
async fn incoming_keyless_custody_wakes_forwarding_and_connectivity_wakes_catch_up()
-> Result<(), Failure> {
    tokio::task::LocalSet::new()
        .run_until(async {
            let root = tempfile::tempdir()?;
            let hub = Arc::new(Hub::default());
            let a = enrolled(&root.path().join("a"), &hub, "a", None).await?;
            let relay = enrolled(
                &root.path().join("relay"),
                &hub,
                "relay",
                Some((
                    &a,
                    Profile::Custody {
                        scopes: ["items".into()].into(),
                    },
                )),
            )
            .await?;
            let b = enrolled(
                &root.path().join("b"),
                &hub,
                "b",
                Some((
                    &a,
                    Profile::Writer {
                        scopes: ["items".into()].into(),
                    },
                )),
            )
            .await?;
            let contact = {
                let link = b.network.read().await;
                b.settings
                    .lock()
                    .await
                    .contact(&b.vault, &*link.as_ref().ok_or("link")?.transport)
                    .await?
                    .0
            };
            relay
                .configure(|settings| settings.add_peer(&relay.vault, &contact))
                .await?;
            let contact = {
                let link = relay.network.read().await;
                relay
                    .settings
                    .lock()
                    .await
                    .contact(&relay.vault, &*link.as_ref().ok_or("link")?.transport)
                    .await?
                    .0
            };
            b.configure(|settings| settings.add_peer(&b.vault, &contact))
                .await?;
            enable(&relay).await?;
            let mut revisions = b.replica.observe_revision();
            add(&a, 1).await?;
            // a's manual push is the only source; relay's committed receipt wakes its worker.
            let contact = {
                let settings = relay.settings.lock().await;
                let link = relay.network.read().await;
                settings
                    .contact(&relay.vault, &*link.as_ref().ok_or("link")?.transport)
                    .await?
                    .0
            };
            a.configure(|settings| settings.add_peer(&a.vault, &contact))
                .await?;
            let transport = a
                .network
                .read()
                .await
                .as_ref()
                .ok_or("link")?
                .transport
                .clone();
            a.sync(&*transport).await?;
            tokio::time::timeout(Duration::from_secs(5), revisions.changed()).await??;
            assert_eq!(
                *relay.replica.observe_revision().borrow(),
                0,
                "custody cannot apply rows"
            );
            let mut statuses = relay.sync_status.subscribe();
            let before = statuses.borrow_and_update()["token"].clone();
            hub.network_changed();
            tokio::time::timeout(
                Duration::from_secs(5),
                statuses
                    .wait_for(|status| status["token"] != before && status["state"] == "connected"),
            )
            .await??;
            assert_eq!(
                statuses.borrow()["retry"],
                false,
                "keyless custody owes no key retry"
            );
            for node in [&a, &relay, &b] {
                node.detach(None).await;
            }
            Ok(())
        })
        .await
}

#[tokio::test]
async fn failed_work_retries_on_clock_and_connectivity_interrupts_backoff() -> Result<(), Failure> {
    tokio::task::LocalSet::new()
        .run_until(async {
            let root = tempfile::tempdir()?;
            let hub = Arc::new(Hub::default());
            let a = enrolled(&root.path().join("a"), &hub, "a", None).await?;
            let b = enrolled(
                &root.path().join("b"),
                &hub,
                "b",
                Some((
                    &a,
                    Profile::Writer {
                        scopes: ["items".into()].into(),
                    },
                )),
            )
            .await?;
            let contact = {
                let link = b.network.read().await;
                b.settings
                    .lock()
                    .await
                    .contact(&b.vault, &*link.as_ref().ok_or("link")?.transport)
                    .await?
                    .0
            };
            a.configure(|settings| settings.add_peer(&a.vault, &contact))
                .await?;
            add(&a, 2).await?;
            b.detach(None).await;
            let mut status = a.sync_status.subscribe();
            a.automatic.store(true, Ordering::SeqCst);
            a.wake_sync();
            status.wait_for(|status| status["retry"] == true).await?;
            assert_eq!(status.borrow()["retry"], true);
            let dials = hub.counts()[1];
            tokio::time::pause();
            tokio::time::advance(Duration::from_millis(500)).await;
            tokio::task::yield_now().await;
            assert_eq!(hub.counts()[1], dials);
            tokio::time::advance(Duration::from_millis(500)).await;
            status.changed().await?;
            assert!(hub.counts()[1] > dials);
            // Explicit connectivity wakes the retry now, despite its two-second deadline.
            tokio::time::resume();
            b.attach(Network::Owned(hub.connector("b"))).await?;
            let before = status.borrow_and_update()["token"].clone();
            hub.network_changed();
            tokio::time::timeout(
                Duration::from_secs(5),
                status
                    .wait_for(|status| status["token"] != before && status["state"] == "connected"),
            )
            .await??;
            assert_eq!(status.borrow()["state"], "connected");
            assert_eq!(status.borrow()["retry"], false);
            a.detach(None).await;
            b.detach(None).await;
            Ok(())
        })
        .await
}

#[tokio::test]
async fn consumer_sql_allocates_string_ids_with_node_author() -> Result<(), Failure> {
    tokio::task::LocalSet::new().run_until(async {
    let root = tempfile::tempdir()?;
    let schema = Schema::parse(
        r#"{"format":6,"application":"numeric_consumer","version":1,"tables":[{"name":"items","class":"replayed","columns":[{"name":"title","type":"text","not_null":true}],"primary_key":["id"]}]}"#,
    )?;
    let store: Arc<dyn crate::SecretStore> =
        Arc::new(FileSecretStore::new(root.path().join("secrets")));
    let settings = Settings::create(&schema, &store, crate::enrollment::DEFAULT_TTL, None)?;
    let vault = settings.vault(&store);
    let hub = Arc::new(Hub::default());
    let transport = hub
        .connector("numeric")
        .start(true, Settings::transport_key(&vault)?)
        .await?;
    let node = node(root.path(), settings, vault, transport).await?;
    let client = node.client(1)?;
    node.dispatch(&client, &json!({"type":"sql","sql":"BEGIN"}))
        .await?;
    let identity = node
        .dispatch(&client, &json!({"type":"next_id","table":"items"}))
        .await?;
    let id = identity["id"].as_str().ok_or("id is not a string")?;
    let rows = node.dispatch(&client, &json!({"type":"sql","sql":"INSERT INTO items(title,id) VALUES('first',?) RETURNING id", "values":[{"type":"integer","value":id}]})).await?;
    assert_eq!(rows["rows"][0][0]["value"], id);
    node.dispatch(&client, &json!({"type":"sql","sql":"COMMIT"}))
        .await?;
    let rows = node.dispatch(&client, &json!({"type":"read","query":{"sql":"SELECT id FROM items","max_rows":64}})).await?;
    assert_eq!(rows["rows"][0][0]["value"], id);
    node.detach(None).await;
    Ok(())
    }).await
}

mod admission;
mod change_driven;
mod discovery;
mod mesh;

/// A renewal holds the settings while it teaches the replica. A Room write
/// that holds the replica must not wait for the settings: that cycle lasted
/// until the transaction timed out with code 4 on the emulator pair.
#[tokio::test]
async fn a_room_write_commits_while_a_renewal_waits_for_the_replica() -> Result<(), Failure> {
    use crate::connection::{Call, ConnectionOptions, Profile, Registry, Reply, serve};
    tokio::task::LocalSet::new().run_until(async {
        let root = tempfile::tempdir()?;
        let hub = Arc::new(Hub::default());
        let node = enrolled(&root.path().join("a"), &hub, "a", None).await?;

        let connections = Registry::default();
        let options = ConnectionOptions {
            read_only: false,
            durability: crate::Durability::Buffered,
            profile: Some(Profile::Room284),
            transaction_timeout: Some(Duration::from_secs(1)),
            binding: None,
        };
        let writer = connections.get(connections.connect(node.clone(), options).await?)?;
        let execute = |sql: &str, params: Vec<SqlValue>| {
            let call = Call::Execute { statement: 1, sql: sql.into(), params };
            serve(writer.clone(), call)
        };
        execute("BEGIN IMMEDIATE TRANSACTION", Vec::new()).await?;
        let Reply::Page(page) = execute("SELECT rocky_next_id('items')", Vec::new()).await? else {
            return Err("no row id".into());
        };
        let id = page.rows[0][0].clone();
        // The transaction holds the replica: the renewal takes the settings
        // and waits for the replica.
        let renewal = node.renew(None, false, None, false);
        tokio::pin!(renewal);
        tokio::select! {
            biased;
            renewed = &mut renewal => return Err(format!("renewal did not wait: {renewed:?}").into()),
            () = std::future::ready(()) => {}
        }
        assert!(node.settings.try_lock().is_err(), "the renewal holds the settings");
        let write = async {
            execute("INSERT INTO items(key,title,id) VALUES('k','Milk',?)", vec![id]).await?;
            execute("COMMIT", Vec::new()).await
        };
        let (renewed, written) = tokio::join!(renewal, write);
        written?;
        renewed?;
        node.detach(None).await;
        Ok(())
    }).await
}

/// A peer importing a scope from a checkpoint takes none of its history:
/// the frontier exchange names the scope as importing, not changed, and
/// the session goes on.
#[tokio::test]
async fn a_peer_importing_a_scope_is_not_fed_its_history() -> Result<(), Failure> {
    tokio::task::LocalSet::new()
        .run_until(async {
            let root = tempfile::tempdir()?;
            let hub = Arc::new(Hub::default());
            let a = enrolled(&root.path().join("a"), &hub, "a", None).await?;
            let b = enrolled(
                &root.path().join("b"),
                &hub,
                "b",
                Some((
                    &a,
                    Profile::Writer {
                        scopes: ["items".into()].into(),
                    },
                )),
            )
            .await?;
            add(&a, 1).await?;
            let scopes = a.app_scopes();
            b.replica
                .set_importing(scopes.iter().copied().collect())
                .await;
            let (mut session, mut answering) = link_sessions(&a, &b).await?;
            let server = b.clone();
            let serving = async move {
                let deliveries = delivery::Port {
                    node: &server,
                    serving: true,
                };
                answering
                    .serve_all(&server.replica, &deliveries, None)
                    .await
            };
            let exchanging = async {
                let exchange = session.changed_scopes(&a.replica, &scopes).await?;
                session.close().await?;
                Ok::<_, Failure>(exchange)
            };
            let (served, exchange) = tokio::join!(serving, exchanging);
            served?;
            let exchange = exchange?;
            assert_eq!(exchange.importing, scopes);
            assert!(exchange.changed.is_empty());
            b.replica
                .set_importing(std::collections::BTreeSet::new())
                .await;
            let (mut session, mut answering) = link_sessions(&a, &b).await?;
            let server = b.clone();
            let serving = async move {
                let deliveries = delivery::Port {
                    node: &server,
                    serving: true,
                };
                answering
                    .serve_all(&server.replica, &deliveries, None)
                    .await
            };
            let exchanging = async {
                let exchange = session.changed_scopes(&a.replica, &scopes).await?;
                session.close().await?;
                Ok::<_, Failure>(exchange)
            };
            let (served, exchange) = tokio::join!(serving, exchanging);
            served?;
            assert_eq!(exchange?.changed, scopes);
            a.detach(None).await;
            b.detach(None).await;
            Ok(())
        })
        .await
}

fn completed_peers(report: &Value) -> usize {
    report["peers"]
        .as_array()
        .expect("native peer reports")
        .iter()
        .filter(|peer| {
            peer["attempts"]
                .as_array()
                .expect("native attempts")
                .iter()
                .any(|attempt| {
                    attempt["operation"] == "reconcile" && attempt["outcome"] == "completed"
                })
        })
        .count()
}

pub(super) fn small_directory() -> std::io::Result<crate::test_directory::Directory> {
    crate::test_directory::small()
}
