//! Concurrent revocations by two issuers merge: the acceptance of
//! `docs/features_07/06-revocation-set.md` on the in-process hub. See
//! `docs/decisions/0049-mergeable-revocation-set.md`.
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
async fn join(
    root: &Path,
    hub: &Arc<Hub>,
    name: &str,
    issuer: &Device,
    profile: Value,
) -> Result<Device, Failure> {
    let invitation = issuer.invite_as(profile).await;
    Device::new(Database::join(
        open(&root.join(name), hub, name),
        &invitation,
    )?)
}
fn identity(root: &Path, name: &str) -> Result<Value, Failure> {
    let mut identity: Value =
        serde_json::from_slice(&std::fs::read(root.join(name).join("identity.json"))?)?;
    for epochs in identity["keys"].as_object_mut().ok_or("keys")?.values_mut() {
        for epoch in epochs.as_array_mut().ok_or("epochs")? {
            *epoch = epoch["generation"].clone();
        }
    }
    Ok(identity)
}
async fn revocations(device: &Device) -> Value {
    device.ok(json!({"type": "session"})).await["revocations"].clone()
}
async fn create_row(device: &Device, handle: u8, collection: &str, values: Value) {
    device
        .ok(json!({
            "type": "mutate",
            "handle": vec![handle; 32],
            "payload": json!({"type": "create", "collection": collection, "values": values}).to_string().into_bytes(),
            "entity": null,
            "baseline": null,
        }))
        .await;
}
async fn texts(device: &Device, sql: &str) -> Vec<String> {
    let page = device
        .ok(json!({"type": "read", "query": {"sql": sql, "values": [], "max_rows": 64}}))
        .await;
    page["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| row[0]["value"].as_str().map(String::from))
        .collect()
}

/// Issuers A and B, each enrolling a reader it later revokes and a writer
/// of both collections; the readers read disjoint collections.
struct Domain {
    a: Device,
    b: Device,
    /// Reads `items`; A revokes it.
    x: Device,
    /// Reads `notes`; B revokes it.
    y: Device,
    /// Writers enrolled by A and by B, each the other's peer.
    m: Device,
    n: Device,
}
impl Domain {
    async fn new(root: &Path, hub: &Arc<Hub>) -> Result<Self, Failure> {
        let a = create(root, hub, "a")?;
        let b = join(root, hub, "b", &a, json!({"kind": "issuer"})).await?;
        let reader = |scope: &str| json!({"kind": "reader", "scopes": [scope]});
        let writer = json!({"kind": "writer", "scopes": ["items", "notes"]});
        let x = join(root, hub, "x", &a, reader("items")).await?;
        let y = join(root, hub, "y", &b, reader("notes")).await?;
        let m = join(root, hub, "m", &a, writer.clone()).await?;
        let n = join(root, hub, "n", &b, writer).await?;
        common::introduce(&m, &n).await;
        create_row(
            &a,
            1,
            "items",
            json!({"title": "before", "completed": false}),
        )
        .await;
        create_row(&b, 2, "notes", json!({"text": "before"})).await;
        for device in [&b, &a, &x, &y, &m, &n] {
            device.sync().await.map_err(|error| error.to_string())?;
        }
        Ok(Self { a, b, x, y, m, n })
    }
    async fn close(self) {
        for device in [&self.a, &self.b, &self.x, &self.y, &self.m, &self.n] {
            device.close().await;
        }
    }
}

/// Two issuers, partitioned, each revoke a device; they meet with
/// `a_first` choosing who syncs first. Every remaining device ends with both
/// statements and one digest, and no device refuses either statement.
async fn partitioned_revocations_merge(a_first: bool) -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let root = root.path();
    let hub = Arc::new(Hub::default());
    let Domain { a, b, x, y, m, n } = Domain::new(root, &hub).await?;
    let empty = revocations(&a).await;
    assert_eq!(empty["statements"], 0);

    // Partitioned: neither issuer syncs while both revoke.
    let by_a = a
        .ok(json!({"type": "revoke", "node": x.node().await}))
        .await;
    let by_b = b
        .ok(json!({"type": "revoke", "node": y.node().await}))
        .await;
    assert_ne!(by_a["statement"], by_b["statement"]);
    assert_eq!(by_a["revocations"]["statements"], 1);
    assert_eq!(by_b["revocations"]["statements"], 1);
    assert_ne!(by_a["revocations"]["digest"], by_b["revocations"]["digest"]);
    // Each rotated only the collection its device read: the scopes are
    // disjoint, so the two key epochs never meet in one scope.
    assert_eq!(
        identity(root, "a")?["keys"],
        json!({"issuer_registry": [1], "items": [1, 2], "notes": [1]})
    );
    assert_eq!(
        identity(root, "b")?["keys"],
        json!({"issuer_registry": [1], "items": [1], "notes": [1, 2]})
    );

    // They meet. The handshake gives each the other's statement; each
    // then renews once for the other's rotated key, the first while it
    // syncs, the second on its next sync. The first's checkpoint import
    // fails until the second holds its key too.
    let (first, second) = if a_first { (&a, &b) } else { (&b, &a) };
    let _ = first.sync().await;
    assert_eq!(revocations(first).await["statements"], 2);
    assert_eq!(revocations(second).await["statements"], 2);
    second.sync().await.map_err(|error| error.to_string())?;
    first.sync().await.map_err(|error| error.to_string())?;
    let both = revocations(&a).await;
    assert_eq!(both["statements"], 2);
    assert_eq!(revocations(&b).await, both);
    for issuer in ["a", "b"] {
        assert_eq!(
            identity(root, issuer)?["keys"],
            json!({"issuer_registry": [1], "items": [1, 2], "notes": [1, 2]}),
            "{issuer}"
        );
    }

    // A member learns both from its issuer's handshake and renews once for
    // the keys. Its peer learns both from the member's handshake, before
    // it ever met an issuer again, and renews on its next sync.
    m.sync().await.map_err(|error| error.to_string())?;
    assert_eq!(revocations(&m).await, both);
    assert_eq!(revocations(&n).await, both);
    n.sync().await.map_err(|error| error.to_string())?;
    m.sync().await.map_err(|error| error.to_string())?;
    assert_eq!(
        m.peer(&n.node().await).await["attempts"]
            .as_array()
            .ok_or("attempts")?
            .iter()
            .rev()
            .find(|attempt| attempt["operation"] == "reconcile")
            .ok_or("reconciliation")?["outcome"],
        "completed"
    );
    for (name, device) in [("m", &m), ("n", &n)] {
        assert_eq!(
            identity(root, name)?["keys"],
            json!({"items": [1, 2], "notes": [1, 2]}),
            "{name}"
        );
        assert_eq!(
            device.ok(json!({"type": "status"})).await["data"]["bootstrap_pending"],
            false
        );
    }
    // Rows flow under both new epochs, through either issuer's members.
    create_row(
        &m,
        3,
        "items",
        json!({"title": "after", "completed": false}),
    )
    .await;
    create_row(&n, 4, "notes", json!({"text": "after"})).await;
    for device in [&m, &n, &m] {
        device.sync().await.map_err(|error| error.to_string())?;
    }
    assert_eq!(
        texts(&n, "SELECT title FROM items ORDER BY title").await,
        ["after", "before"]
    );
    assert_eq!(
        texts(&m, "SELECT text FROM notes ORDER BY text").await,
        ["after", "before"]
    );
    // Each revoked device is told why by its own issuer and reads no more.
    for device in [&x, &y] {
        assert!(common::exchange_failed(&device.sync().await));
        assert!(
            !device.ok(json!({"type": "status"})).await["authority"]["verified_revocation"]
                .is_null()
        );
    }
    assert_eq!(
        texts(&x, "SELECT title FROM items ORDER BY title").await,
        ["before"]
    );
    Domain { a, b, x, y, m, n }.close().await;
    Ok(())
}

#[tokio::test]
async fn partitioned_issuers_revocations_merge_when_a_syncs_first() -> Result<(), Failure> {
    partitioned_revocations_merge(true).await
}

#[tokio::test]
async fn partitioned_issuers_revocations_merge_when_b_syncs_first() -> Result<(), Failure> {
    partitioned_revocations_merge(false).await
}
