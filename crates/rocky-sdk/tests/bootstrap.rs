mod common;
#[path = "bootstrap/link_gate.rs"]
mod link_gate;
use common::{Device, Failure};
use rocky_sdk::{Network, transport::memory::Hub};
use serde_json::json;
use std::sync::Arc;

#[tokio::test(flavor = "multi_thread")]
async fn retention_defaults_preserve_sole_copies_and_configuration_survives_reopen()
-> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let device = Device::create(root.path(), None)?;
    let default = device
        .ok(json!({"type": "retention", "collection": "items"}))
        .await;
    assert_eq!(
        default["policy"],
        json!({"required": [], "behind": [], "copies": 1, "window": 256})
    );
    device.follow_main().await;
    device.add(1, "sole copy").await;
    device.seal_and_compact().await;
    let policy = json!({"required": [], "behind": [], "copies": 1, "window": 0});
    let status = device
        .ok(json!({"type": "retention", "collection": "items", "policy": policy, "maintain": true}))
        .await;
    assert_eq!(status["covered"], 1);
    assert_eq!(status["pruned_prefix"], json!([]));
    assert!(
        device
            .call(json!({"type": "retention", "collection": "missing", "policy": policy}))
            .await
            .is_err()
    );
    assert!(
        device
            .call(json!({"type": "retention_limits", "limits": {"hard_bytes": 0, "handles": 1}}))
            .await
            .is_err()
    );
    device.close().await;
    let device = Device::open(root.path(), None)?;
    assert_eq!(
        device
            .ok(json!({"type": "retention", "collection": "items"}))
            .await["policy"],
        policy
    );
    assert_eq!(device.titles().await, ["sole copy"]);
    device.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn behind_pruned_sync_restores_the_base_and_preserves_unsent_work() -> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let a = Device::create(
        &root.path().join("a"),
        Some(Network::Owned(hub.connector("a"))),
    )?;
    a.follow_main().await;
    a.add(1, "base").await;
    let b = Device::join(
        &root.path().join("b"),
        &a.invite().await,
        Network::Owned(hub.connector("b")),
    )?;
    let c = Device::join(
        &root.path().join("c"),
        &a.invite().await,
        Network::Owned(hub.connector("c")),
    )?;
    b.sync().await.expect("initial sync");
    c.sync().await.expect("initial sync");
    c.add(99, "unsent").await;
    for handle in 2..=12 {
        a.add(handle, &format!("row {handle}")).await;
    }
    b.sync().await.expect("custody sync");
    a.seal_and_compact().await;
    let status = a
        .ok(
            json!({"type": "retention", "collection": "items", "policy": {
        "required": [], "behind": [], "copies": 1, "window": 0
    }, "maintain": true}),
        )
        .await;
    assert!(
        !status["pruned_prefix"]
            .as_array()
            .expect("pruned_prefix")
            .is_empty()
    );
    a.add(13, "tail").await;
    // Pushing to a peer behind the pruned_prefix skips the scope; the pass succeeds.
    common::introduce(&a, &c).await;
    a.sync().await.expect("push to a behind peer");
    let behind = c.node().await;
    assert_eq!(
        a.peer(&behind).await["attempts"]
            .as_array()
            .ok_or("attempts")?
            .iter()
            .rev()
            .find(|attempt| attempt["operation"] == "reconcile")
            .ok_or("reconciliation")?["outcome"],
        "completed"
    );
    let activity = a.ok(json!({"type": "activity"})).await;
    assert!(
        activity["events"]
            .as_array()
            .ok_or("events")?
            .iter()
            .any(|event| event["kind"] == "scopes_waiting"
                && event["peer"] == behind
                && event["scopes"][0]["table"] == "items"),
        "{activity}"
    );
    c.sync().await.expect("rebootstrap and publish");
    assert_eq!(a.items().await, c.items().await);
    assert!(c.titles().await.contains(&"unsent".to_owned()));
    assert!(c.titles().await.contains(&"tail".to_owned()));
    let status = c
        .ok(json!({"type": "retention", "collection": "items"}))
        .await;
    assert!(
        !status["pruned_prefix"]
            .as_array()
            .expect("imported pruned_prefix")
            .is_empty()
    );
    c.add(99, "unsent").await;
    assert_eq!(a.items().await, c.items().await);
    c.close().await;
    let c = Device::open(&root.path().join("c"), None)?;
    assert_eq!(a.items().await, c.items().await);
    c.close().await;
    b.close().await;
    a.close().await;
    Ok(())
}

/// Checkpoint pages take a whole frame; large rows still split so each page's
/// plaintext fits one package.
#[tokio::test(flavor = "multi_thread")]
async fn join_restores_large_rows_across_checkpoint_pages() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let hub = Arc::new(Hub::default());
    let a = Device::create(
        &root.path().join("a"),
        Some(Network::Owned(hub.connector("a"))),
    )?;
    a.follow_main().await;
    for handle in 0..40 {
        a.add(handle, &format!("{handle}:{}", "x".repeat(12_000)))
            .await;
    }
    a.seal_and_compact().await;
    let b = Device::join(
        &root.path().join("b"),
        &a.invite().await,
        Network::Owned(hub.connector("b")),
    )?;
    b.sync().await.expect("join sync");
    assert_eq!(b.titles().await.len(), 40);
    b.close().await;
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn post_revocation_join_reads_earlier_rows_without_rotated_out_keys() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let hub = Arc::new(Hub::default());
    let a = Device::create(
        &root.path().join("a"),
        Some(Network::Owned(hub.connector("a"))),
    )?;
    a.follow_main().await;
    a.add(1, "before revocation").await;
    let revoked = Device::join(
        &root.path().join("revoked"),
        &a.invite().await,
        Network::Owned(hub.connector("revoked")),
    )?;
    revoked.sync().await.expect("initial bootstrap");
    a.ok(json!({"type": "revoke", "node": revoked.node().await}))
        .await;
    // The base a joiner imports sits at a seal after the rotation.
    a.seal_and_compact().await;
    let member_path = root.path().join("member");
    let member = Device::join(
        &member_path,
        &a.invite_as(json!({"kind": "reader", "scopes": ["items"]}))
            .await,
        Network::Owned(hub.connector("member")),
    )?;
    member
        .sync()
        .await
        .expect("checkpoint join under current policy");
    assert_eq!(member.titles().await, ["before revocation"]);
    assert!(!member_path.join("bootstrap.json").exists());
    let identity: serde_json::Value =
        serde_json::from_slice(&std::fs::read(member_path.join("identity.json"))?)?;
    assert_eq!(
        identity["keys"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|epoch| epoch["generation"].clone())
            .collect::<Vec<_>>(),
        vec![json!(2)]
    );
    let file = rusqlite::Connection::open(member_path.join("rocky.sqlite"))?;
    let imported: i64 =
        file.query_row("SELECT COUNT(*) FROM secure_checkpoint_rows", [], |row| {
            row.get(0)
        })?;
    assert_eq!(imported, 1);
    let history: i64 = file.query_row("SELECT COUNT(*) FROM secure_operations", [], |row| {
        row.get(0)
    })?;
    assert_eq!(
        history, 0,
        "earlier ciphertext was replaced by the checkpoint"
    );
    member.ok(json!({"type": "renew"})).await;
    let renewed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(member_path.join("identity.json"))?)?;
    assert_eq!(
        renewed["keys"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|epoch| epoch["generation"].clone())
            .collect::<Vec<_>>(),
        vec![json!(2)]
    );
    a.add(2, "tail").await;
    member.sync().await.expect("ordinary tail sync");
    assert_eq!(member.titles().await, ["before revocation", "tail"]);
    assert!(common::exchange_failed(&revoked.sync().await));
    member.close().await;
    let member = Device::open(&member_path, None)?;
    assert_eq!(member.titles().await, ["before revocation", "tail"]);
    member.close().await;
    revoked.close().await;
    a.close().await;
    Ok(())
}

/// Controls sync admission independently of enrollment, without wall-clock sleeps.
struct Gate {
    inner: Arc<dyn rocky_sdk::transport::Transport>,
    allowed: tokio::sync::watch::Sender<bool>,
    attempts: tokio::sync::watch::Sender<u64>,
    refuse: Arc<std::sync::atomic::AtomicBool>,
    max_attempts: Arc<std::sync::atomic::AtomicU64>,
    pause_on_attempt: Arc<std::sync::atomic::AtomicU64>,
}
impl rocky_sdk::transport::Transport for Gate {
    fn kind(&self) -> &str {
        self.inner.kind()
    }
    fn address(&self) -> rocky_sdk::transport::BoxFuture<'_, Result<String, Failure>> {
        self.inner.address()
    }
    fn connect<'a>(
        &'a self,
        address: &'a str,
        protocol: rocky_sdk::transport::Protocol,
    ) -> rocky_sdk::transport::BoxFuture<'a, Result<rocky_sdk::transport::Stream, Failure>> {
        Box::pin(async move {
            let stream = self.inner.connect(address, protocol).await?;
            if protocol == rocky_sdk::transport::Protocol::Link {
                return Ok(rocky_sdk::transport::Stream::new(link_gate::LinkGate::new(
                    stream, self,
                )));
            }
            Ok(stream)
        })
    }
    fn accept(
        &self,
    ) -> rocky_sdk::transport::BoxFuture<
        '_,
        Option<(rocky_sdk::transport::Protocol, rocky_sdk::transport::Stream)>,
    > {
        self.inner.accept()
    }
    fn listen(&self, listening: bool) {
        self.inner.listen(listening);
    }
    fn close(&self) -> rocky_sdk::transport::BoxFuture<'_, ()> {
        self.inner.close()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn status_separates_bootstrap_progress_and_reconciliation_and_resumes_a_failed_join()
-> Result<(), Failure> {
    use rocky_sdk::transport::{Connector, Transport};
    let root = tempfile::tempdir()?;
    let hub = Arc::new(Hub::default());
    let a = Device::create(
        &root.path().join("a"),
        Some(Network::Owned(hub.connector("a"))),
    )?;
    a.add(1, "base").await;
    let gate = Arc::new(Gate {
        inner: hub.connector("member").start(false, [7; 32]).await?,
        allowed: tokio::sync::watch::channel(false).0,
        attempts: tokio::sync::watch::channel(0).0,
        refuse: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        max_attempts: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
        pause_on_attempt: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
    });
    let mut attempts = gate.attempts.subscribe();
    let path = root.path().join("member");
    let member = Device::join(&path, &a.invite().await, Network::Borrowed(gate.clone()))?;
    attempts.wait_for(|count| *count > 0).await?;
    let status = member.ok(json!({"type": "status"})).await;
    assert_eq!(status["data"]["bootstrap_pending"], true);
    gate.allowed.send_replace(true);
    member.sync().await.expect("finish join");
    let ready = member
        .ok(json!({"type": "status_next", "after": status["token"]}))
        .await;
    assert_eq!(ready["data"]["bootstrap_pending"], false);
    gate.allowed.send_replace(false);
    let previous = *attempts.borrow_and_update();
    let sync = member.sync();
    let observe = async {
        attempts.wait_for(|count| *count > previous).await?;
        let status = member.ok(json!({"type": "status"})).await;
        assert_eq!(status["network"]["reconciling"], true);
        gate.allowed.send_replace(true);
        Ok::<_, Failure>(())
    };
    let (synced, observed) = tokio::join!(sync, observe);
    synced.expect("ordinary sync");
    observed?;
    member.close().await;
    gate.close().await;

    // Enrollment succeeds, but every sync fails: checkpoint intent survives reopen.
    let gate = Arc::new(Gate {
        inner: hub.connector("retry").start(false, [8; 32]).await?,
        allowed: tokio::sync::watch::channel(true).0,
        attempts: tokio::sync::watch::channel(0).0,
        refuse: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        max_attempts: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
        pause_on_attempt: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
    });
    let path = root.path().join("retry");
    let retry = Device::join(&path, &a.invite().await, Network::Borrowed(gate.clone()))?;
    assert!(common::exchange_failed(&retry.sync().await));
    assert_eq!(
        retry.ok(json!({"type": "status"})).await["data"]["bootstrap_pending"],
        true
    );
    retry.close().await;
    let retry = Device::open(&path, None)?;
    assert_eq!(
        retry.ok(json!({"type": "status"})).await["data"]["bootstrap_pending"],
        true
    );
    gate.refuse
        .store(false, std::sync::atomic::Ordering::SeqCst);
    retry
        .database
        .attach(Network::Borrowed(gate.clone()))
        .await?;
    retry.sync().await.expect("resume checkpoint-first join");
    assert_eq!(
        retry.ok(json!({"type": "status"})).await["data"]["bootstrap_pending"],
        false
    );
    assert_eq!(retry.titles().await, ["base"]);
    retry.close().await;
    gate.close().await;
    a.close().await;
    Ok(())
}

/// Envelopes shared after enrollment wait at the inviter, so another peer's
/// checkpoint completes the import but not the join.
#[tokio::test(flavor = "multi_thread")]
async fn a_join_stays_pending_until_it_meets_its_inviter() -> Result<(), Failure> {
    use rocky_sdk::transport::{Connector, Transport};
    let root = tempfile::tempdir()?;
    let hub = Arc::new(Hub::default());
    let a_path = root.path().join("a");
    let a = Device::create(&a_path, Some(Network::Owned(hub.connector("a"))))?;
    a.add(1, "base").await;
    let b = Device::join(
        &root.path().join("b"),
        &a.invite().await,
        Network::Owned(hub.connector("b")),
    )?;
    b.sync().await.expect("b joins");
    // Enrolled by A, but no exchange with it before A goes away.
    let gate = Arc::new(Gate {
        inner: hub.connector("gated").start(false, [9; 32]).await?,
        allowed: tokio::sync::watch::channel(true).0,
        attempts: tokio::sync::watch::channel(0).0,
        refuse: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        max_attempts: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
        pause_on_attempt: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
    });
    let c_path = root.path().join("c");
    let c = Device::join(&c_path, &a.invite().await, Network::Borrowed(gate.clone()))?;
    c.close().await;
    gate.close().await;
    a.close().await;
    let c = Device::open(&c_path, Some(Network::Owned(hub.connector("c"))))?;
    c.add_peer(&b.contact().await).await.expect("c knows b");
    let _ = c.sync().await;
    assert_eq!(c.titles().await, ["base"]);
    let status = c.ok(json!({"type": "status"})).await;
    assert_eq!(status["data"]["bootstrap_pending"], true);

    let a = Device::open(&a_path, Some(Network::Owned(hub.connector("a"))))?;
    c.sync().await.expect("c meets its inviter");
    assert_eq!(
        c.ok(json!({"type": "status"})).await["data"]["bootstrap_pending"],
        false
    );
    for device in [c, b, a] {
        device.close().await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn renewal_after_missed_key_epochs_uses_a_checkpoint_without_acquiring_old_keys()
-> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let a = Device::create(
        &root.path().join("a"),
        Some(Network::Owned(hub.connector("a"))),
    )?;
    a.follow_main().await;
    a.add(1, "epoch one").await;
    let b_path = root.path().join("b");
    let b = Device::join(
        &b_path,
        &a.invite().await,
        Network::Owned(hub.connector("b")),
    )?;
    b.sync().await.expect("initial join");
    for (name, handle, title) in [("c", 2, "epoch two"), ("d", 3, "epoch three")] {
        let revoked = Device::join(
            &root.path().join(name),
            &a.invite().await,
            Network::Owned(hub.connector(name)),
        )?;
        revoked.sync().await.expect("join");
        a.ok(json!({"type": "revoke", "node": revoked.node().await}))
            .await;
        a.add(handle, title).await;
        revoked.close().await;
    }
    a.seal_and_compact().await;
    b.ok(json!({"type": "renew"})).await;
    assert_eq!(
        b.ok(json!({"type": "status"})).await["data"]["bootstrap_pending"],
        true
    );
    let identity: serde_json::Value =
        serde_json::from_slice(&std::fs::read(b_path.join("identity.json"))?)?;
    assert_eq!(
        identity["keys"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|epoch| epoch["generation"].clone())
            .collect::<Vec<_>>(),
        vec![json!(1), json!(3)]
    );
    b.sync().await.expect("checkpoint refresh after renewal");
    assert_eq!(a.items().await, b.items().await);
    assert_eq!(b.titles().await.len(), 3);
    assert_eq!(
        b.ok(json!({"type": "status"})).await["data"]["bootstrap_pending"],
        false
    );
    b.close().await;
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn interrupted_parallel_join_preserves_pending_scopes_after_reopen() -> Result<(), Failure> {
    use rocky_sdk::{
        Database, Open,
        transport::{Connector, Transport},
    };
    use std::sync::atomic::Ordering;
    let root = tempfile::tempdir()?;
    let hub = Arc::new(Hub::default());
    let schema = r#"{"application":"shopping","version":1,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]},{"name":"notes","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"body","type":"text","not_null":true}],"primary_key":["key"]}]}"#;
    let a_path = root.path().join("a");
    let a = Device::new(Database::create(
        Open {
            identity: None,
            directory: &a_path,
            schema,
            secrets: None,
            network: Some(Network::Owned(hub.connector("a"))),
            coordination: None,
        },
        None,
    )?)?;
    a.follow_main().await;
    a.add(1, "first scope").await;
    // Each scope has a base at the seal, so each is its own import.
    a.ok(json!({
        "type": "mutate",
        "handle": vec![2; 32],
        "payload": json!({"type": "create", "collection": "notes", "values": {"body": "second scope"}}).to_string().into_bytes(),
        "entity": null,
        "baseline": null,
    }))
    .await;
    a.seal_and_compact().await;
    let gate = Arc::new(Gate {
        inner: hub.connector("member").start(false, [9; 32]).await?,
        allowed: tokio::sync::watch::channel(true).0,
        attempts: tokio::sync::watch::channel(0).0,
        refuse: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        max_attempts: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        pause_on_attempt: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
    });
    let mut attempts = gate.attempts.subscribe();
    let path = root.path().join("member");
    let invitation = a
        .invite_as(json!({"kind": "writer", "scopes": ["items", "notes"]}))
        .await;
    let member = Device::new(Database::join(
        Open {
            identity: None,
            directory: &path,
            schema,
            secrets: None,
            network: Some(Network::Borrowed(gate.clone())),
            coordination: None,
        },
        &invitation,
    )?)?;
    attempts.wait_for(|count| *count >= 2).await?;
    assert!(common::exchange_failed(&member.sync().await));
    let progress: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path.join("bootstrap.json"))?)?;
    let pending = progress["pending"]
        .as_array()
        .expect("pending scopes")
        .clone();
    // Losing the transport while imports overlap can interrupt either or
    // both scopes. Keep exactly that durable set across an offline reopen.
    assert!((1..=2).contains(&pending.len()));
    member.close().await;
    let member = Device::new(Database::open(Open {
        identity: None,
        directory: &path,
        schema,
        secrets: None,
        network: None,
        coordination: None,
    })?)?;
    assert_eq!(
        member.ok(json!({"type": "status"})).await["data"]["bootstrap_pending"],
        true
    );
    let reopened: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path.join("bootstrap.json"))?)?;
    assert_eq!(reopened["pending"].as_array(), Some(&pending));
    let before = *attempts.borrow_and_update();
    gate.max_attempts.store(u64::MAX, Ordering::SeqCst);
    member
        .database
        .attach(Network::Borrowed(gate.clone()))
        .await?;
    let resumed = member.sync().await.expect("resume the remaining scopes");
    assert!(*attempts.borrow() > before);
    assert_eq!(
        member.ok(json!({"type": "status"})).await["data"]["bootstrap_pending"],
        false,
        "resume report: {resumed:?}"
    );
    assert!(!path.join("bootstrap.json").exists());
    assert_eq!(member.titles().await, ["first scope"]);
    member.close().await;
    gate.close().await;
    a.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_old_bootstrap_cannot_clear_newer_authority_intent() -> Result<(), Failure> {
    use rocky_sdk::{
        Database, Open,
        transport::{Connector, Transport},
    };
    let root = tempfile::tempdir()?;
    let hub = Arc::new(Hub::default());
    let schema = r#"{"application":"shopping","version":1,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]},{"name":"notes","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"body","type":"text","not_null":true}],"primary_key":["key"]}]}"#;
    let a_path = root.path().join("a");
    let a = Device::new(Database::create(
        Open {
            identity: None,
            directory: &a_path,
            schema,
            secrets: None,
            network: Some(Network::Owned(hub.connector("a"))),
            coordination: None,
        },
        None,
    )?)?;
    a.add(1, "base").await;
    let gate = Arc::new(Gate {
        inner: hub.connector("member").start(false, [10; 32]).await?,
        allowed: tokio::sync::watch::channel(true).0,
        attempts: tokio::sync::watch::channel(0).0,
        refuse: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        max_attempts: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
        pause_on_attempt: Arc::new(std::sync::atomic::AtomicU64::new(2)),
    });
    let mut attempts = gate.attempts.subscribe();
    let path = root.path().join("member");
    let invitation = a
        .invite_as(json!({"kind": "writer", "scopes": ["items", "notes"]}))
        .await;
    let member = Device::new(Database::join(
        Open {
            identity: None,
            directory: &path,
            schema,
            secrets: None,
            network: Some(Network::Borrowed(gate.clone())),
            coordination: None,
        },
        &invitation,
    )?)?;
    attempts.wait_for(|count| *count >= 2).await?;
    // Fault at the renewal durability boundary: intent is newer than the identity.
    rocky_credentials::write_private(&path.join("bootstrap.json"), b"2")?;
    gate.allowed.send_replace(true);
    assert!(common::exchange_failed(&member.sync().await));
    assert_eq!(std::fs::read(path.join("bootstrap.json"))?, b"2");
    assert_eq!(
        member.ok(json!({"type": "status"})).await["data"]["bootstrap_pending"],
        true
    );
    // Once the issuer supplies epoch 2, renewal resets all scopes and catches up.
    let c_path = root.path().join("revoked");
    let invitation = a
        .invite_as(json!({"kind": "reader", "scopes": ["notes"]}))
        .await;
    let c = Device::new(Database::join(
        Open {
            identity: None,
            directory: &c_path,
            schema,
            secrets: None,
            network: Some(Network::Owned(hub.connector("revoked"))),
            coordination: None,
        },
        &invitation,
    )?)?;
    c.sync().await.expect("join");
    a.ok(json!({"type": "revoke", "node": c.node().await}))
        .await;
    member.ok(json!({"type": "renew"})).await;
    // Retry after restoring authority explicitly signals connectivity again.
    member
        .ok(json!({"type": "networking_control", "enabled": true}))
        .await;
    member.sync().await.expect("fresh intent under epoch 2");
    assert_eq!(
        member.ok(json!({"type": "status"})).await["data"]["bootstrap_pending"],
        false
    );
    assert_eq!(member.titles().await, ["base"]);
    member.close().await;
    c.close().await;
    gate.close().await;
    a.close().await;
    Ok(())
}

/// An intent no peer offered a checkpoint for has no progress to report.
#[tokio::test(flavor = "multi_thread")]
async fn an_intent_without_offers_reports_no_progress() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    Device::create(root.path(), None)?.close().await;
    rocky_credentials::write_private(
        &root.path().join("bootstrap.json"),
        br#"{"intent":true,"pending":[],"totals":[]}"#,
    )?;
    let device = Device::open(root.path(), None)?;
    let status = device.ok(json!({"type": "status"})).await;
    assert_eq!(status["data"]["bootstrap_pending"], true);
    assert!(status["data"]["bootstrap"].is_null(), "{status}");
    device.close().await;
    Ok(())
}

/// Bootstrap progress counts the stored rows of the offered checkpoints: it
/// only grows, with a stable total, and the pending intent clears on completion.
#[tokio::test(flavor = "multi_thread")]
async fn join_progress_grows_page_by_page_to_its_total() -> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let a = Device::create(
        &root.path().join("a"),
        Some(Network::Owned(hub.connector("a"))),
    )?;
    a.follow_main().await;
    for handle in 0..40 {
        a.add(handle, &format!("{handle}:{}", "x".repeat(12_000)))
            .await;
    }
    a.seal_and_compact().await;
    let b = Arc::new(Device::join(
        &root.path().join("b"),
        &a.invite().await,
        Network::Owned(hub.connector("b")),
    )?);
    let observer = {
        let b = b.clone();
        tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut status = b.ok(json!({"type": "status"})).await;
            while status["data"]["bootstrap_pending"] == true {
                seen.push(status["data"]["bootstrap"].clone());
                status = b
                    .ok(json!({"type": "status_next", "after": status["token"]}))
                    .await;
            }
            (seen, status)
        })
    };
    b.sync().await.expect("join sync");
    let (seen, ready) = observer.await?;
    assert!(ready["data"]["bootstrap"].is_null(), "{ready}");
    let progress: Vec<_> = seen.iter().filter(|progress| !progress.is_null()).collect();
    assert!(progress.len() > 2, "{seen:?}");
    let total = progress[0]["rows_total"].clone();
    assert!(total.as_u64().is_some_and(|total| total >= 40), "{total}");
    for pair in progress.windows(2) {
        assert_eq!(pair[1]["rows_total"], total);
        assert!(pair[0]["rows_done"].as_u64() <= pair[1]["rows_done"].as_u64());
        assert!(pair[1]["rows_done"].as_u64() <= total.as_u64());
    }
    assert!(progress.iter().any(|progress| {
        progress["rows_done"].as_u64() > Some(0) && progress["rows_done"] != total
    }));
    assert_eq!(b.titles().await.len(), 40);
    b.close().await;
    a.close().await;
    Ok(())
}

/// A join cut mid-import, with edits on both sides meanwhile, resumes at the
/// page it reached instead of starting over, and keeps both edits.
#[tokio::test(flavor = "multi_thread")]
async fn a_cut_join_resumes_its_pages_and_keeps_edits_from_both_sides() -> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let hub = Arc::new(Hub::default());
    let a = Device::create(
        &root.path().join("a"),
        Some(Network::Owned(hub.connector("a"))),
    )?;
    a.follow_main().await;
    for handle in 0..60 {
        a.add(handle, &format!("{handle}:{}", "x".repeat(12_000)))
            .await;
    }
    a.seal_and_compact().await;
    let b = Arc::new(Device::join(
        &root.path().join("b"),
        &a.invite().await,
        Network::Owned(hub.connector("b")),
    )?);
    let mut status = b.ok(json!({"type": "status"})).await;
    while status["data"]["bootstrap"]["rows_done"]
        .as_u64()
        .unwrap_or(0)
        == 0
    {
        status = b
            .ok(json!({"type": "status_next", "after": status["token"]}))
            .await;
    }
    hub.cut_after(Some(0));
    a.add(200, "edited on a while cut").await;
    b.add(201, "edited on b while cut").await;
    let paused = b.ok(json!({"type": "status"})).await;
    assert_eq!(paused["data"]["bootstrap_pending"], true);
    let done = paused["data"]["bootstrap"]["rows_done"]
        .as_u64()
        .expect("progress");
    assert!(done > 0, "{paused}");
    hub.cut_after(None);
    let observer = {
        let b = b.clone();
        tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut status = b.ok(json!({"type": "status"})).await;
            while status["data"]["bootstrap_pending"] == true {
                seen.push(status["data"]["bootstrap"].clone());
                status = b
                    .ok(json!({"type": "status_next", "after": status["token"]}))
                    .await;
            }
            seen
        })
    };
    // Going online again ends the backoff the cut caused.
    b.ok(json!({"type": "networking_control", "enabled": false}))
        .await;
    b.ok(json!({"type": "networking_control", "enabled": true}))
        .await;
    b.sync().await.expect("resume the join");
    for progress in observer
        .await?
        .iter()
        .filter(|progress| !progress.is_null())
    {
        assert!(
            progress["rows_done"].as_u64() >= Some(done),
            "restarted: {progress}"
        );
        assert_eq!(
            progress["rows_total"],
            paused["data"]["bootstrap"]["rows_total"]
        );
    }
    a.sync().await.expect("a pulls b's edit");
    let edits = json!({"type": "read", "query": {"sql": "SELECT title FROM items WHERE length(title) < 100 ORDER BY title", "values": [], "max_rows": 16}});
    for device in [&*b, &a] {
        let rows = device.ok(edits.clone()).await["rows"].clone();
        let titles: Vec<_> = rows
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|row| row[0]["value"].as_str())
            .collect();
        assert_eq!(titles, ["edited on a while cut", "edited on b while cut"]);
    }
    b.close().await;
    a.close().await;
    Ok(())
}
