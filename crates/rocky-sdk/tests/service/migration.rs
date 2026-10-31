use super::{fixture::*, inspection::*, *};

const MIGRATING: &str = r#"{"application":"counter","version":2,"format":6,"tables":[{"name":"counts","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"value","type":"integer","not_null":true},{"name":"position","type":"text","not_null":true,"default":""}],"primary_key":["key"]}],"migrations":[{"version":2,"statements":["UPDATE counts SET position=key"]}]}"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_voters_release_a_private_migration_without_reopening_the_publisher()
-> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let (bundle, _admin) = service(root.path()).await?;
    let (a, t) = household(root.path(), &bundle).await?;
    t.write("included", 41).await?;
    a.sync().await?;
    let latest = a.tips("seal", json!({})).await?["tip"].clone();
    final_on_both(&a, &t, &latest).await?;
    a.close().await?;
    t.write("before close but unknown", 42).await?;
    let a_dir = root.path().join("a");
    let a = Peer::start(&a_dir, MIGRATING, Some(&bundle), None, false).await?;
    a.session.set_networking_enabled(false).await?;
    assert_eq!(a.sync().await?["skip"], "networking_disabled");
    assert_eq!(
        a.call(json!({"type":"coordinated"})).await?["trusted"],
        true
    );
    let graph = a.tips("inspect", json!({})).await?;
    let close = graph["seals"]
        .as_array()
        .ok_or("seals")?
        .iter()
        .find(|seal| seal["tip"] == latest && seal["action"] == "close")
        .ok_or("private close")?
        .clone();
    let target = a.tips("status", json!({})).await?["tip"].clone();
    let (staged, state) = stage(&a_dir)?;
    assert!(staged.coordinated);
    assert_eq!(state, "committed");
    assert_eq!(serde_json::to_value(staged.scope)?, a.scope);
    assert_eq!(data_encoding::HEXLOWER.encode(&staged.source.0), latest);
    assert_eq!(data_encoding::HEXLOWER.encode(&staged.target.0), target);
    assert!(staged.statements.iter().any(|statement| matches!(statement, rocky_secure::TipStatement::Seal(sealed) if sealed.id().is_ok_and(|id| data_encoding::HEXLOWER.encode(&id) == close["id"]))));
    let staged_bytes = rocky_sdk::credentials::encode(&staged)?;
    assert_ne!(close["final"], true);
    // This write is genuinely after A signed the close, on T's source tip.
    t.write("after close", 43).await?;
    t.close().await?;
    a.session.set_networking_enabled(true).await?;
    let pending = a.sync().await?;
    assert!(
        pending["peers"].as_array().is_some_and(Vec::is_empty),
        "{pending}"
    );
    let (still_staged, state) = stage(&a_dir)?;
    assert_eq!(state, "committed");
    assert!(still_staged.coordinated);
    assert_eq!(rocky_sdk::credentials::encode(&still_staged)?, staged_bytes);
    let t = Peer::start(&root.path().join("t"), SCHEMA, Some(&bundle), None, false).await?;
    let before = t.tips("inspect", json!({})).await?;
    assert!(
        !before["openings"]
            .as_array()
            .ok_or("openings")?
            .iter()
            .any(|opening| opening["id"] == target)
    );
    introduce(&a, &t).await?;
    a.session.set_automatic_sync(true).await?;
    t.session.set_automatic_sync(true).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let generation = t.call(json!({"type":"generation"})).await?;
        let a_graph = a.tips("inspect", json!({})).await?;
        let t_graph = t.tips("inspect", json!({})).await?;
        if generation["current"]["schema"] == 2
            && seal(&a_graph, &close["id"])["final"] == true
            && seal(&t_graph, &close["id"])["final"] == true
        {
            assert_eq!(generation["held"], 2, "{generation}");
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "automatic release failed: generation={generation} A={a_graph} T={t_graph}"
        );
        tokio::task::yield_now().await;
    }
    let (_, state) = stage(&a_dir)?;
    assert_eq!(state, "released");
    let ended = head(&bundle, &root.path().join("t"), &t.scope, &latest).await?;
    assert_eq!(
        data_encoding::HEXLOWER.encode(&ended.terminal.ok_or("terminal")?.digest),
        close["id"]
    );
    assert!(!ended.acknowledgments.is_empty());
    for ack in ended.acknowledgments {
        let ack = rocky_sdk::credentials::TerminalAck::from_bytes(&ack.record)?;
        assert_eq!(
            data_encoding::HEXLOWER.encode(&ack.statement.seal),
            close["id"]
        );
    }
    loop {
        let mut complete = true;
        for peer in [&a, &t] {
            assert_eq!(peer.tips("status", json!({})).await?["tip"], target);
            let rows = peer.call(json!({"type":"read","query":{"sql":"SELECT key,position FROM counts","values":[],"max_rows":10}})).await?;
            complete &= rows["rows"]
                == json!([[{"type":"text","value":"included"},{"type":"text","value":"included"}]]);
        }
        if complete {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "migration frames did not arrive automatically"
        );
        tokio::task::yield_now().await;
    }
    t.close().await?;
    a.close().await?;
    Ok(())
}
