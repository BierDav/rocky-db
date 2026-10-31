//! The replicated issuer registry: records reach every issuer, any issuer
//! renews, only issuers open it, concurrent writers converge, answers commit
//! their record first and the bound holds. See
//! `docs/decisions/0048-replicated-issuer-registry.md`.
use common::{Device, Failure, introduce};
use rocky_sdk::{
    Database, Network, Open,
    credentials::{CredentialChain, PrivateKey},
    transport::{
        BoxFuture, Connector, Protocol, Stream, Transport,
        memory::{Hub, Memory},
    },
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Instant,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

mod common;

/// The shared items collection and a partitioned one for partition grants.
const SCHEMA: &str = r#"{"application":"shopping","version":1,"format":6,"tables":[
 {"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]},
 {"name":"parts","class":"replayed","columns":[{"name":"list","type":"text","not_null":true},{"name":"key","type":"text","not_null":true}],"primary_key":["list","key"],"partition_by":["list"]}]}"#;

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
fn memory(hub: &Arc<Hub>, name: &str) -> Network {
    Network::Owned(hub.connector(name))
}
fn create(root: &Path, network: Network) -> Result<Device, Failure> {
    Device::new(Database::create(open(root, Some(network)), None)?)
}
fn join(directory: &Path, network: Network, invitation: &str) -> Result<Device, Failure> {
    Device::new(Database::join(open(directory, Some(network)), invitation)?)
}
fn identity(directory: &Path) -> Result<Value, Failure> {
    Ok(serde_json::from_slice(&std::fs::read(
        directory.join("identity.json"),
    )?)?)
}
fn issuer() -> Value {
    json!({"kind": "issuer"})
}
/// Every other device an issuer's registry lists, by node key.
async fn devices(issuer: &Device) -> BTreeMap<String, Value> {
    issuer.ok(json!({"type": "devices"})).await["devices"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|device| {
            (
                device["node"].as_str().unwrap_or_default().to_owned(),
                device.clone(),
            )
        })
        .collect()
}
/// Waits, by status events and without sleeping, until a device's
/// automatic first sync has finished.
async fn settle(device: &Device) -> Value {
    let mut status = device.ok(json!({"type": "status"})).await;
    while status["data"]["bootstrap_pending"] == true {
        status = device
            .ok(json!({"type": "status_next", "after": status["token"]}))
            .await;
    }
    status
}
async fn online(device: &Device, online: bool) {
    device
        .ok(json!({"type": "networking_control", "enabled": online}))
        .await;
}
async fn synced(device: &Device) -> Result<Value, Failure> {
    device
        .sync()
        .await
        .map_err(|error| error.to_string().into())
}
/// The capability ID at the root of a device's stored chain.
fn chain_capability(directory: &Path) -> Result<String, Failure> {
    let chain: CredentialChain =
        serde_json::from_value(identity(directory)?["credentials"].clone())?;
    let root = chain.0.first().ok_or("empty chain")?;
    Ok(data_encoding::HEXLOWER.encode(&root.id()?))
}
/// Rows of the registry's typed table in a device's file.
fn registry_rows(directory: &Path, entry: &str) -> Result<i64, Failure> {
    let file = rusqlite::Connection::open_with_flags(
        directory.join("rocky.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    Ok(file.query_row(
        "SELECT COUNT(*) FROM issuer_registry WHERE entry LIKE ?",
        [entry],
        |row| row.get(0),
    )?)
}

#[tokio::test]
async fn invitation_availability_survives_reopen_and_tracks_replacement_and_use()
-> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let hub = Arc::new(Hub::default());
    let path = root.path().join("issuer");
    let a = create(&path, memory(&hub, "issuer"))?;
    let first = a.invite().await;
    assert_eq!(
        a.ok(json!({"type":"invitation_open", "uri":first})).await["open"],
        true
    );
    let second = a.invite().await;
    assert_eq!(
        a.ok(json!({"type":"invitation_open", "uri":first})).await["open"],
        false
    );
    a.close().await;
    let a = Device::new(Database::open(open(&path, Some(memory(&hub, "issuer"))))?)?;
    assert_eq!(
        a.ok(json!({"type":"invitation_open", "uri":second})).await["open"],
        true
    );
    let b = join(&root.path().join("member"), memory(&hub, "member"), &second)?;
    assert_eq!(
        a.ok(json!({"type":"invitation_open", "uri":second})).await["open"],
        false
    );
    assert!(
        b.call(json!({"type":"invitation_open", "uri":second}))
            .await
            .is_err()
    );
    a.close().await;
    let a = Device::new(Database::open(open(&path, None))?)?;
    assert_eq!(
        a.ok(json!({"type":"invitation_open", "uri":second})).await["open"],
        false
    );
    b.close().await;
    a.close().await;
    Ok(())
}

#[tokio::test]
async fn a_device_enrolled_at_one_issuer_is_listed_at_another_after_one_sync() -> Result<(), Failure>
{
    let root = tempfile::tempdir()?;
    let root = root.path();
    let hub = Arc::new(Hub::default());
    let a = create(&root.join("a"), memory(&hub, "a"))?;
    let b = join(
        &root.join("b"),
        memory(&hub, "b"),
        &a.invite_as(issuer()).await,
    )?;
    settle(&b).await;
    // B stays out of reach until the member's first sync settled.
    online(&b, false).await;
    let m = join(&root.join("m"), memory(&hub, "m"), &a.invite().await)?;
    settle(&m).await;
    let m_node = m.node().await;
    let user = devices(&a).await[&m_node]["user"].clone();
    let address = a
        .ok(json!({"type": "partition_address", "table": "parts", "values": [{"type": "text", "value": "L"}]}))
        .await;
    let part = &address["tuple"][0];
    let grant = json!({"domain": serde_json::from_str::<Value>(&a.database.scope())?, "table": address["scope"]["table"],
        "selector": [[part[0], {"Only": [part[1]]}]], "rows": "All", "rights": ["Read"], "fields": []});
    a.ok(json!({"type": "partition_grant", "device": {"user": user, "node": m_node}, "partitions": [grant], "delegations": 2}))
        .await;
    a.ok(json!({"type": "device_label", "node": m_node, "label": [7, 8, 9]}))
        .await;

    let at_a = devices(&a).await[&m_node].clone();
    assert_eq!(
        at_a["profile"],
        json!({"kind": "writer", "scopes": ["items"]})
    );
    assert_eq!(at_a["kind"], "paired");
    assert_eq!(at_a["partitions"][0]["delegations"], 2);
    assert_eq!(at_a["label"], json!([7, 8, 9]));
    // The recorded partition capability can outlive the original enrollment.
    let enrolled_expiry = m.ok(json!({"type": "session"})).await["expires"]
        .as_str()
        .ok_or("enrollment expiry")?
        .parse::<u64>()?;
    assert!(
        at_a["expires"]
            .as_str()
            .ok_or("record expiry")?
            .parse::<u64>()?
            >= enrolled_expiry
    );
    online(&b, true).await;
    assert!(!devices(&b).await.contains_key(&m_node));

    synced(&b).await?;
    let listed = devices(&b).await;
    assert_eq!(listed[&m_node], at_a);
    // The enrolling issuer's own record arrived too.
    assert_eq!(listed[&a.node().await]["profile"], issuer());
    assert!(!listed.contains_key(&b.node().await));
    for device in [&a, &b, &m] {
        device.close().await;
    }
    Ok(())
}

/// Acceptance 4 of the mesh scope, on the in-process hub.
#[tokio::test]
async fn a_member_renews_at_an_issuer_it_never_met_and_removes_the_lost_one() -> Result<(), Failure>
{
    let root = tempfile::tempdir()?;
    let root = root.path();
    let hub = Arc::new(Hub::default());
    let a = create(&root.join("a"), memory(&hub, "a"))?;
    let b = join(
        &root.join("b"),
        memory(&hub, "b"),
        &a.invite_as(issuer()).await,
    )?;
    settle(&b).await;
    // B is out of reach while the member joins: it never meets it and
    // never receives its record.
    online(&b, false).await;
    let m = join(&root.join("m"), memory(&hub, "m"), &a.invite().await)?;
    settle(&m).await;
    let (a_node, m_node) = (a.node().await, m.node().await);
    a.close().await;
    drop(a);
    std::fs::remove_dir_all(root.join("a"))?;
    online(&b, true).await;
    assert!(!devices(&b).await.contains_key(&m_node));

    m.ok(json!({"type": "renew"})).await;
    let after = m.ok(json!({"type": "session"})).await;
    // Renewed through B's chain, it expires no later than B does.
    assert_eq!(
        after["expires"],
        b.ok(json!({"type": "session"})).await["expires"]
    );
    let record = devices(&b).await[&m_node].clone();
    assert_eq!(record["kind"], "renewed");
    assert_eq!(
        record["profile"],
        json!({"kind": "writer", "scopes": ["items"]})
    );
    assert_eq!(record["expires"], after["expires"]);

    m.ok(json!({"type": "peer_remove", "node": a_node})).await;
    assert!(
        !m.ok(json!({"type": "peers"})).await["renewal_routes"]
            .as_array()
            .ok_or("routes")?
            .is_empty()
    );
    m.add(1, "Milk").await;
    let report = synced(&m).await?;
    assert_eq!(
        common::identity::completed_peers(&report),
        1,
        "{report}; activity: {}",
        m.ok(json!({"type":"activity", "after":"0"})).await
    );
    assert_eq!(b.titles().await, ["Milk"]);
    for device in [&b, &m] {
        device.close().await;
    }
    Ok(())
}

#[tokio::test]
async fn only_issuers_open_the_registry_and_custody_relays_it_sealed() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let root = root.path();
    let hub = Arc::new(Hub::default());
    let a = create(&root.join("a"), memory(&hub, "a"))?;
    let b = join(
        &root.join("b"),
        memory(&hub, "b"),
        &a.invite_as(issuer()).await,
    )?;
    let custody = json!({"kind": "custody", "scopes": ["items"]});
    let c = join(
        &root.join("c"),
        memory(&hub, "c"),
        &a.invite_as(custody).await,
    )?;
    let reader = json!({"kind": "reader", "scopes": ["items"]});
    let r = join(
        &root.join("r"),
        memory(&hub, "r"),
        &a.invite_as(reader).await,
    )?;
    let w = join(&root.join("w"), memory(&hub, "w"), &a.invite().await)?;
    synced(&r).await?;
    synced(&w).await?;
    // The two issuers meet only through the custody peer from now on.
    let (a_node, b_node) = (a.node().await, b.node().await);
    a.ok(json!({"type": "peer_remove", "node": b_node})).await;
    b.ok(json!({"type": "peer_remove", "node": a_node})).await;
    introduce(&a, &c).await;
    introduce(&b, &c).await;
    let keys = Database::device(&root.join("d"), None)?;
    a.ok(json!({"type": "grant", "device": keys, "profile": {"kind": "writer", "scopes": ["items"]}}))
        .await;
    synced(&a).await?;
    synced(&b).await?;
    assert!(devices(&b).await.contains_key(&keys.node.to_hex()));

    for name in ["c", "r", "w"] {
        let directory = root.join(name);
        let held = identity(&directory)?["keys"].clone();
        assert!(held.get("issuer_registry").is_none(), "{name}: {held}");
        for entry in std::fs::read_dir(directory.join("secrets"))? {
            let file = entry?.file_name().to_string_lossy().into_owned();
            assert!(!file.contains("issuer_registry"), "{name}: {file}");
        }
        let file = rusqlite::Connection::open_with_flags(
            directory.join("rocky.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let tables: i64 = file.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name='issuer_registry'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(tables, 0, "{name}");
    }
    for device in [&c, &r, &w] {
        assert!(device.call(json!({"type": "devices"})).await.is_err());
        let query = json!({"sql": "SELECT * FROM issuer_registry", "values": [], "max_rows": 8});
        assert!(
            device
                .call(json!({"type": "read", "query": query}))
                .await
                .is_err()
        );
    }
    // Neither do an issuer's application sessions open it.
    let query = json!({"sql": "SELECT * FROM issuer_registry", "values": [], "max_rows": 8});
    assert!(
        a.call(json!({"type": "read", "query": query}))
            .await
            .is_err()
    );
    assert!(registry_rows(&root.join("b"), "device")? >= 6);
    for device in [&a, &b, &c, &r, &w] {
        device.close().await;
    }
    Ok(())
}

#[tokio::test]
async fn concurrent_enrollments_and_renewals_at_two_issuers_converge() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let root = root.path().to_path_buf();
    let hub = Arc::new(Hub::default());
    let a = create(&root.join("a"), memory(&hub, "a"))?;
    let b = join(
        &root.join("b"),
        memory(&hub, "b"),
        &a.invite_as(issuer()).await,
    )?;
    // Two issuers enroll an issuer each at once.
    let started = |name: &str, invitation: String| {
        let (directory, network) = (root.join(name), memory(&hub, name));
        tokio::task::spawn_blocking(move || {
            join(&directory, network, &invitation).map_err(|e| e.to_string())
        })
    };
    let (x, y) = tokio::join!(
        started("x", a.invite_as(issuer()).await),
        started("y", b.invite_as(issuer()).await)
    );
    let (x, y) = (x??, y??);
    // Their first syncs end before anything else is recorded, so no issuer
    // relays a record that the steps below expect to stay apart.
    settle(&x).await;
    settle(&y).await;
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for name in ["a", "b", "x", "y"] {
        let range = identity(&root.join(name))?["minting"]["range"].clone();
        ranges.push((
            range["first"].as_u64().ok_or("first")?,
            range["last"].as_u64().ok_or("last")?,
        ));
    }
    ranges.sort_unstable();
    assert!(
        ranges.windows(2).all(|pair| pair[0].1 < pair[1].0),
        "{ranges:?}"
    );
    synced(&a).await?;
    let (x_node, y_node) = (x.node().await, y.node().await);
    for issuer in [&a, &b] {
        let listed = devices(issuer).await;
        assert!(listed.contains_key(&x_node) && listed.contains_key(&y_node));
    }

    // Two issuers renew one device before either hears of the other.
    for issuer in [&a, &b] {
        issuer
            .ok(json!({"type": "sync_start", "enabled": false}))
            .await;
    }
    // The extra issuers above tested range allocation; keep them from
    // answering the renewal intended for b when a is offline.
    online(&x, false).await;
    online(&y, false).await;
    online(&b, false).await;
    let m = join(&root.join("m"), memory(&hub, "m"), &a.invite().await)?;
    settle(&m).await;
    m.ok(json!({"type": "sync_start", "enabled": false})).await;
    let m_node = m.node().await;
    m.ok(json!({"type": "renew"})).await;
    a.ok(json!({"type": "networking_control", "enabled": false}))
        .await;
    online(&b, true).await;
    m.ok(json!({"type": "renew"})).await;
    a.ok(json!({"type": "networking_control", "enabled": true}))
        .await;
    assert_eq!(devices(&b).await[&m_node]["kind"], "renewed");
    synced(&a).await?;
    let (at_a, at_b) = (devices(&a).await, devices(&b).await);
    assert_eq!(at_a[&m_node], at_b[&m_node]);
    // The record keeps the later renewal; a chain through the second
    // issuer expires no later than that issuer's own.
    let expires =
        |value: &Value| -> Result<u64, Failure> { Ok(value.as_str().ok_or("expires")?.parse()?) };
    assert!(
        expires(&m.ok(json!({"type": "session"})).await["expires"])?
            <= expires(&at_a[&m_node]["expires"])?
    );
    // One visible device entry per node in either file.
    for name in ["a", "b"] {
        let file = rusqlite::Connection::open_with_flags(
            root.join(name).join("rocky.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let entries: i64 = file.query_row(
            "SELECT COUNT(*) FROM issuer_registry WHERE node = ? AND entry = 'device'",
            [&m_node],
            |row| row.get(0),
        )?;
        assert_eq!(entries, 1, "{name}");
    }
    for device in [&a, &b, &x, &y, &m] {
        device.close().await;
    }
    Ok(())
}

/// One-shot faults on a node's streams of one protocol.
#[derive(Default)]
struct Faults {
    /// The next inbound stream reads its request and cannot write the answer.
    answer: Mutex<Option<Protocol>>,
    /// The next outbound stream receives the answer, which is never read.
    receipt: Mutex<Option<Protocol>>,
}
impl Faults {
    fn take(slot: &Mutex<Option<Protocol>>, protocol: Protocol) -> bool {
        let mut slot = slot.lock().unwrap();
        let armed = *slot == Some(protocol);
        if armed {
            *slot = None;
        }
        armed
    }
}
struct Faulty {
    inner: Arc<Memory>,
    faults: Arc<Faults>,
}
impl Connector for Faulty {
    fn start(
        &self,
        accepts: bool,
        secret: [u8; 32],
    ) -> BoxFuture<'_, Result<Arc<dyn Transport>, Failure>> {
        Box::pin(async move {
            let inner = self.inner.start(accepts, secret).await?;
            Ok(Arc::new(FaultyTransport {
                inner,
                faults: self.faults.clone(),
            }) as Arc<dyn Transport>)
        })
    }
}
struct FaultyTransport {
    inner: Arc<dyn Transport>,
    faults: Arc<Faults>,
}
impl Transport for FaultyTransport {
    fn kind(&self) -> &str {
        self.inner.kind()
    }
    fn address(&self) -> BoxFuture<'_, Result<String, Failure>> {
        self.inner.address()
    }
    fn connect<'a>(
        &'a self,
        address: &'a str,
        protocol: Protocol,
    ) -> BoxFuture<'a, Result<Stream, Failure>> {
        Box::pin(async move {
            let stream = self.inner.connect(address, protocol).await?;
            Ok(if Faults::take(&self.faults.receipt, protocol) {
                Stream::new(Unread(stream))
            } else {
                stream
            })
        })
    }
    fn accept(&self) -> BoxFuture<'_, Option<(Protocol, Stream)>> {
        Box::pin(async move {
            let (protocol, stream) = self.inner.accept().await?;
            Some(if Faults::take(&self.faults.answer, protocol) {
                (protocol, Stream::new(Mute(stream)))
            } else {
                (protocol, stream)
            })
        })
    }
    fn listen(&self, listening: bool) {
        self.inner.listen(listening);
    }
    fn close(&self) -> BoxFuture<'_, ()> {
        self.inner.close()
    }
}
/// The answering side stops after its work and before the answer leaves.
struct Mute(Stream);
impl AsyncRead for Mute {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl AsyncWrite for Mute {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
/// The requester receives the whole answer and stops before storing it.
struct Unread(Stream);
impl AsyncRead for Unread {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut scratch = [0; 4096];
        loop {
            let mut buffer = ReadBuf::new(&mut scratch);
            match Pin::new(&mut self.0).poll_read(cx, &mut buffer) {
                Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
                    return Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()));
                }
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
        }
    }
}
impl AsyncWrite for Unread {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
fn faulty(hub: &Arc<Hub>, name: &str, faults: &Arc<Faults>) -> Network {
    Network::Owned(Arc::new(Faulty {
        inner: hub.connector(name),
        faults: faults.clone(),
    }))
}

/// Pairing, renewal and `grant` stopped after the registry commit: before
/// the answer is written, and after it is written but before the requester
/// stores it. A record exists without a usable chain, and the retry is the
/// same device.
#[tokio::test]
async fn interrupted_answers_leave_a_record_and_retry_as_the_same_device() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let root = root.path();
    let hub = Arc::new(Hub::default());
    let issuing = Arc::new(Faults::default());
    let a = create(&root.join("a"), faulty(&hub, "a", &issuing))?;
    let mut members = Vec::new();
    for (name, issuer_side) in [("m", true), ("n", false)] {
        let directory = root.join(name);
        let requesting = Arc::new(Faults::default());
        let invitation = a.invite().await;
        if issuer_side {
            *issuing.answer.lock().unwrap() = Some(Protocol::Pair);
        } else {
            *requesting.receipt.lock().unwrap() = Some(Protocol::Pair);
        }
        assert!(join(&directory, faulty(&hub, name, &requesting), &invitation).is_err());
        let recorded = devices(&a).await;
        let fresh: Vec<&String> = recorded
            .keys()
            .filter(|node| {
                !members
                    .iter()
                    .any(|(_, known, _): &(Device, String, Arc<Faults>)| known == *node)
            })
            .collect();
        assert_eq!(fresh.len(), 1, "{name}: {recorded:?}");
        let node = fresh[0].clone();
        assert!(!directory.join("identity.json").exists(), "{name}");
        let member = join(&directory, faulty(&hub, name, &requesting), &invitation)?;
        assert_eq!(member.node().await, node, "{name}");
        assert_eq!(devices(&a).await.len(), recorded.len(), "{name}");
        members.push((member, node, requesting));
    }
    // A granted bundle lost after its record committed is issued again.
    // Short-lived chains make each renewal's capability a new one.
    let profile = json!({"kind": "writer", "scopes": ["items"]});
    let mut granted = Vec::new();
    for name in ["g", "h"] {
        let keys = Database::device(&root.join(name), None)?;
        let grant = json!({"type": "grant", "device": keys, "profile": profile, "ttl": 60});
        a.ok(grant.clone()).await;
        let recorded = devices(&a).await;
        assert!(recorded.contains_key(&keys.node.to_hex()));
        let supplied = a.ok(grant).await["supplied"].clone();
        let requesting = Arc::new(Faults::default());
        let device = Device::new(Database::install(
            open(&root.join(name), Some(faulty(&hub, name, &requesting))),
            serde_json::from_value(supplied)?,
        )?)?;
        assert_eq!(device.node().await, keys.node.to_hex());
        let listed = devices(&a).await;
        assert_eq!(listed.len(), recorded.len());
        assert_eq!(
            listed[&keys.node.to_hex()]["capability"],
            json!(chain_capability(&root.join(name))?)
        );
        granted.push((device, keys.node.to_hex(), requesting));
    }
    // Renewal stopped before its answer is written, then after.
    for (index, (device, node, requesting)) in granted.iter().enumerate() {
        let directory = root.join(["g", "h"][index]);
        let held = chain_capability(&directory)?;
        if index == 0 {
            *issuing.answer.lock().unwrap() = Some(Protocol::Renew);
        } else {
            *requesting.receipt.lock().unwrap() = Some(Protocol::Renew);
        }
        assert!(device.call(json!({"type": "renew"})).await.is_err());
        let record = devices(&a).await[node].clone();
        assert_ne!(
            record["capability"],
            json!(held),
            "a newer capability is recorded"
        );
        assert_eq!(chain_capability(&directory)?, held, "no chain was stored");
        device.ok(json!({"type": "renew"})).await;
        assert_eq!(
            devices(&a).await[node]["capability"],
            json!(chain_capability(&directory)?)
        );
    }
    for (device, _, _) in &granted {
        device.close().await;
    }
    a.close().await;
    for (member, _, _) in &members {
        member.close().await;
    }
    Ok(())
}

fn random_device() -> Value {
    json!({"user": PrivateKey::new().public_key(), "node": PrivateKey::new().public_key()})
}

/// A full registry refuses the 257th device and syncs to a new issuer; the
/// enrollment guide records both times.
#[tokio::test]
async fn a_full_registry_refuses_the_257th_device_and_syncs_to_a_new_issuer() -> Result<(), Failure>
{
    let root = tempfile::tempdir()?;
    let root: PathBuf = root.path().to_path_buf();
    let hub = Arc::new(Hub::default());
    let a = create(&root.join("a"), memory(&hub, "a"))?;
    let b = join(
        &root.join("b"),
        memory(&hub, "b"),
        &a.invite_as(issuer()).await,
    )?;
    settle(&b).await;
    let reader = json!({"kind": "reader", "scopes": ["items"]});
    // A pending invitation, then 253 granted devices: 256 with A, B and it.
    let invitation = a.invite_as(reader.clone()).await;
    let filled = Instant::now();
    for _ in 0..253 {
        a.ok(json!({"type": "grant", "device": random_device(), "profile": reader}))
            .await;
    }
    let filled = filled.elapsed();
    let joined = join(&root.join("j"), memory(&hub, "j"), &invitation)?;
    assert_eq!(devices(&a).await.len(), 255);

    // The 257th fails with the named error and writes nothing.
    let before = (
        std::fs::read(root.join("a/identity.json"))?,
        registry_rows(&root.join("a"), "%")?,
    );
    let refused = a
        .call(json!({"type": "grant", "device": random_device(), "profile": reader}))
        .await
        .err()
        .ok_or("granted a 257th device")?;
    assert_eq!(refused["code"], "registry_full", "{refused}");
    let refused = a
        .call(json!({"type": "pairing", "profile": reader}))
        .await
        .err()
        .ok_or("invited a 257th device")?;
    assert_eq!(refused["code"], "registry_full", "{refused}");
    let after = (
        std::fs::read(root.join("a/identity.json"))?,
        registry_rows(&root.join("a"), "%")?,
    );
    assert_eq!(before, after);
    assert_eq!(devices(&a).await.len(), 255);

    let start = Instant::now();
    synced(&b).await?;
    let sync = start.elapsed();
    assert_eq!(devices(&b).await.len(), 255);
    b.close().await;
    drop(b);
    let start = Instant::now();
    let b = Device::new(Database::open(open(
        &root.join("b"),
        Some(memory(&hub, "b")),
    ))?)?;
    let reopen = start.elapsed();
    assert_eq!(devices(&b).await.len(), 255);
    eprintln!(
        "registry of 256 devices: 253 grants {filled:?}, sync to a new issuer {sync:?}, reopen {reopen:?}"
    );
    for device in [&a, &b, &joined] {
        device.close().await;
    }
    Ok(())
}

/// A join whose answer was lost, after which the issuer replaced its
/// invitation: the directory does not open, the spent invitation is refused,
/// and the newer one enrolls a new device.
#[tokio::test]
async fn a_newer_invitation_supersedes_an_interrupted_join() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let root = root.path();
    let hub = Arc::new(Hub::default());
    let a = create(&root.join("a"), memory(&hub, "a"))?;
    let directory = root.join("m");
    let requesting = Arc::new(Faults::default());
    let spent = a.invite().await;
    *requesting.receipt.lock().unwrap() = Some(Protocol::Pair);
    assert!(join(&directory, faulty(&hub, "m", &requesting), &spent).is_err());
    let ghosts = devices(&a).await;
    let Err(unfinished) = Database::open(open(&directory, None)) else {
        panic!("an unfinished join opened");
    };
    assert!(
        unfinished.to_string().contains("unfinished"),
        "{unfinished}"
    );
    let newer = a.invite().await;
    assert!(join(&directory, faulty(&hub, "m", &requesting), &spent).is_err());
    let member = join(&directory, faulty(&hub, "m", &requesting), &newer)?;
    let node = member.node().await;
    assert!(!ghosts.contains_key(&node));
    assert!(devices(&a).await.contains_key(&node));
    a.add(1, "after").await;
    synced(&member).await?;
    assert_eq!(member.titles().await, ["after"]);
    member.close().await;
    a.close().await;
    Ok(())
}

#[tokio::test]
async fn invitation_identity_and_label_survive_replacement_and_reopen() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let hub = Arc::new(Hub::default());
    let path = root.path().join("issuer");
    let owner = create(&path, memory(&hub, "issuer"))?;
    let label = b"application-defined label";
    let invitation = owner
        .ok(json!({"type":"pairing", "profile":issuer(), "label":label}))
        .await;
    let member = join(
        &root.path().join("member"),
        memory(&hub, "member"),
        invitation["uri"].as_str().ok_or("uri")?,
    )?;
    let node = member.ok(json!({"type":"session"})).await["node"]
        .as_str()
        .ok_or("node")?
        .to_owned();
    let record = devices(&owner).await.remove(&node).ok_or("record")?;
    assert_eq!(record["invitation"], invitation["id"]);
    assert_eq!(record["label"], json!(label));
    // The next invitation cannot erase the association of the earlier enrollment.
    owner
        .ok(json!({"type":"pairing", "profile":issuer()}))
        .await;
    member.database.close().await?;
    owner.database.close().await?;
    let reopened = Device::new(Database::open(open(&path, None))?)?;
    let record = devices(&reopened)
        .await
        .remove(&node)
        .ok_or("reopened record")?;
    assert_eq!(record["invitation"], invitation["id"]);
    assert_eq!(record["label"], json!(label));
    reopened.database.close().await?;
    Ok(())
}
