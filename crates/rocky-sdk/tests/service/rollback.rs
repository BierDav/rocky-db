use super::{fixture::*, inspection::*, *};
#[path = "rollback/diagnostics.rs"]
mod diagnostics;
#[path = "rollback/evidence.rs"]
mod evidence;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_compacted_member_waits_for_the_owners_kept_rollback_seal() -> Result<(), Failure> {
    let mut trace = diagnostics::Trace::new(tempfile::tempdir()?);
    let root = trace.path().to_owned();
    macro_rules! step {
        ($label:expr, $result:expr, $peers:expr) => {{
            trace.before($label);
            match $result {
                Ok(value) => {
                    trace.after();
                    value
                }
                Err(error) => {
                    let error: Failure = error.into();
                    trace.failure(&error, $peers).await;
                    return Err(error);
                }
            }
        }};
    }
    let (bundle, _admin) = step!("setup.service", service(root.as_path()).await, &[]);
    let (a, t) = step!(
        "setup.household",
        household(root.as_path(), &bundle).await,
        &[]
    );
    let m_dir = root.as_path().join("m");
    let invitation = step!(
        "setup.member.invite",
        a.invite("writer").await,
        &[("a", &a), ("t", &t)]
    );
    let m = step!(
        "setup.member.open",
        Peer::start(&m_dir, SCHEMA, None, Some(invitation), false).await,
        &[("a", &a), ("t", &t)]
    );
    step!(
        "setup.member.introduce_a",
        introduce(&a, &m).await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    step!(
        "setup.member.introduce_t",
        introduce(&t, &m).await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    step!(
        "setup.seed.write",
        a.write("kept", 51).await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    trace.m_sync = Some(step!(
        "setup.seed.m_sync",
        m.sync().await,
        &[("m", &m), ("a", &a), ("t", &t)]
    ));
    assert_eq!(
        step!(
            "setup.seed.m_read",
            m.keys().await,
            &[("m", &m), ("a", &a), ("t", &t)]
        ),
        json!([[{"type":"text","value":"kept"}]])
    );
    step!(
        "setup.seed.t_sync",
        t.sync().await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    let earlier = step!(
        "setup.earlier.seal",
        a.tips("seal", json!({})).await,
        &[("m", &m), ("a", &a), ("t", &t)]
    )["tip"]
        .clone();
    step!(
        "setup.earlier.finality",
        final_on_both(&a, &t, &earlier).await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    trace.m_sync = Some(step!(
        "setup.after_earlier.m_sync",
        m.sync().await,
        &[("m", &m), ("a", &a), ("t", &t)]
    ));
    // Cross the SDK's real 256-operation retention window before compacting.
    // These routine writes do not need per-operation diagnostics; failures are
    // still returned by the test and the phase remains traceable.
    trace.before("setup.retention.writes");
    for index in 0..257 {
        a.write(&format!("later {index:03}"), 1000 + index).await?;
    }
    trace.after();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        trace.m_sync = Some(step!(
            "setup.retention.m_sync",
            m.sync().await,
            &[("m", &m), ("a", &a), ("t", &t)]
        ));
        let rows = step!(
            "setup.retention.m_read",
            m.keys().await,
            &[("m", &m), ("a", &a), ("t", &t)]
        );
        if rows.as_array().ok_or("rows")?.len() == 258 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "member did not converge before compaction: {rows}"
        );
    }
    step!(
        "setup.retention.t_sync",
        t.sync().await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    let latest = step!(
        "setup.latest.seal",
        a.tips("seal", json!({})).await,
        &[("m", &m), ("a", &a), ("t", &t)]
    )["tip"]
        .clone();
    step!(
        "setup.latest.finality",
        final_on_both(&a, &t, &latest).await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        trace.m_sync = Some(step!(
            "setup.latest.member_frontier.m_sync",
            m.sync().await,
            &[("m", &m), ("a", &a), ("t", &t)]
        ));
        let graph = step!(
            "setup.latest.member_frontier.inspect",
            m.tips("inspect", json!({})).await,
            &[("m", &m), ("a", &a), ("t", &t)]
        );
        if seal(&graph, &latest)["final"] == true
            && step!(
                "setup.latest.member_frontier.status",
                m.tips("status", json!({})).await,
                &[("m", &m), ("a", &a), ("t", &t)]
            )["tip"]
                == latest
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "member did not acquire the final seal: {graph}"
        );
    }
    eprintln!("rollback: final seals and 258 rows received");
    for peer in [&m, &t] {
        let compacted = step!(
            &format!(
                "compaction[{}]",
                if std::ptr::eq(peer, &m) { "m" } else { "t" }
            ),
            peer.tips("compaction", json!({})).await,
            &[("m", &m), ("a", &a), ("t", &t)]
        );
        assert_eq!(compacted["compacted"], latest, "{compacted}");
        let retention = step!(
            "compaction.retention",
            peer.call(json!({"type":"retention", "collection":"counts"}))
                .await,
            &[("m", &m), ("a", &a), ("t", &t)]
        );
        assert!(
            retention["pruned_prefix"]
                .as_array()
                .is_some_and(|logs| !logs.is_empty()),
            "{retention}"
        );
        assert_eq!(
            seal(
                &step!(
                    "compaction.inspect",
                    peer.tips("inspect", json!({})).await,
                    &[("m", &m), ("a", &a), ("t", &t)]
                ),
                &earlier
            )["held"],
            Value::Null
        );
    }
    eprintln!("rollback: member and relay compacted");
    // T carries only the graph of main's rollback; its own bookmark stays here.
    step!(
        "park.create",
        a.tips("create", json!({"name":"park"})).await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    step!(
        "park.t_sync",
        t.sync().await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    step!(
        "park.follow",
        t.tips("follow", json!({"name":"park"})).await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    step!(
        "offline.disable",
        m.session.set_networking_enabled(false).await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    step!(
        "offline.write",
        m.write("after latest seal", 53).await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    let original_endpoint = step!(
        "offline.original_endpoint",
        evidence::endpoint(&m_dir),
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    let back = step!(
        "rollback.open",
        a.tips("open", json!({"seal":earlier,"minimum_in_sync":1}))
            .await,
        &[("m", &m), ("a", &a), ("t", &t)]
    )["tip"]
        .clone();
    eprintln!("rollback: opened earlier seal, moving main");
    step!(
        "rollback.move",
        a.tips("move", json!({"name":"main","tip":back})).await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    step!(
        "rollback.relay.t_sync",
        t.sync().await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    assert_eq!(
        seal(
            &step!(
                "rollback.owner.inspect",
                a.tips("inspect", json!({})).await,
                &[("m", &m), ("a", &a), ("t", &t)]
            ),
            &earlier
        )["held"],
        "kept"
    );
    eprintln!("rollback: relay has move; closing keeper");
    step!(
        "rollback.keeper.close",
        a.close().await,
        &[("m", &m), ("t", &t)]
    );
    eprintln!("rollback: keeper closed; acquiring graph from relay");
    step!(
        "rollback.member.enable",
        m.session.set_networking_enabled(true).await,
        &[("m", &m), ("t", &t)]
    );
    trace.m_sync = Some(step!(
        "rollback.member.m_sync",
        m.sync().await,
        &[("m", &m), ("t", &t)]
    ));
    eprintln!("rollback: member sync finished");
    let wanted_file = step!(
        "rollback.wanted.file",
        inspect_file(&m_dir),
        &[("m", &m), ("t", &t)]
    );
    let wanted: String = step!(
        "rollback.wanted.query",
        wanted_file.query_row(
            "SELECT lower(hex(seal)) FROM secure_wanted_seals",
            [],
            |row| row.get(0)
        ),
        &[("m", &m), ("t", &t)]
    );
    drop(wanted_file);
    assert_eq!(json!(wanted), earlier);
    trace.before("rollback.wanted.read_refusal");
    let refused_read = m.keys().await;
    eprintln!(
        "rollback diagnostic: expected read refusal={refused_read:?} preceding_m_sync={:?}",
        trace.m_sync
    );
    assert!(
        refused_read.is_err(),
        "unavailable rollback state was readable"
    );
    trace.after();
    trace.before("rollback.wanted.write_refusal");
    let refused = m.write("must wait", 54).await;
    eprintln!("rollback diagnostic: expected write refusal={refused:?}");
    trace.after();
    assert!(
        refused.is_err(),
        "unavailable rollback state accepted a write"
    );
    let guarded = step!(
        "rollback.guarded",
        evidence::guarded(&m_dir, &original_endpoint),
        &[("m", &m), ("t", &t)]
    );
    eprintln!("rollback: read/write gates passed; restoring keeper");
    let a = step!(
        "keeper_return.open",
        Peer::start(
            &root.as_path().join("a"),
            SCHEMA,
            Some(&bundle),
            None,
            false
        )
        .await,
        &[("m", &m), ("t", &t)]
    );
    step!(
        "keeper_return.introduce",
        introduce(&a, &m).await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    step!(
        "keeper_return.owner.automatic",
        a.session.set_automatic_sync(true).await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    step!(
        "keeper_return.member.automatic",
        m.session.set_automatic_sync(true).await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let wanted_file = step!(
            "automatic_observation.file",
            inspect_file(&m_dir),
            &[("m", &m), ("a", &a), ("t", &t)]
        );
        let count: i64 = step!(
            "automatic_observation.wanted",
            wanted_file.query_row("SELECT count(*) FROM secure_wanted_seals", [], |row| row
                .get(0)),
            &[("m", &m), ("a", &a), ("t", &t)]
        );
        drop(wanted_file);
        trace.before("automatic_observation.read");
        let read = m.keys().await;
        eprintln!(
            "rollback diagnostic: automatic_observation.read={read:?} preceding_m_sync={:?}",
            trace.m_sync
        );
        trace.after();
        if count == 0
            && let Ok(rows) = &read
        {
            assert_eq!(*rows, json!([[{"type":"text","value":"kept"}]]));
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            eprintln!("rollback automatic failure: wanted={count}, read={read:?}");
            eprintln!("member status={}", m.call(json!({"type":"status"})).await?);
            eprintln!(
                "member compaction={}",
                m.tips("compaction", json!({})).await?
            );
            eprintln!("owner status={}", a.call(json!({"type":"status"})).await?);
            trace.retain();
            return Err("rollback state was not acquired automatically".into());
        }
        tokio::task::yield_now().await;
    }
    eprintln!("rollback: member restored");
    assert_eq!(
        step!(
            "restored.status",
            m.tips("status", json!({})).await,
            &[("m", &m), ("a", &a), ("t", &t)]
        )["tip"],
        back
    );
    let held = step!(
        "restored.held",
        m.call(json!({"type":"held_changes"})).await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    assert!(
        held["changes"]
            .as_array()
            .ok_or("held changes")?
            .iter()
            .any(|change| change["rows"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row["fields"]
                    .as_array()
                    .is_some_and(|fields| fields.iter().any(|field| field["name"] == "key"
                        && field["value"]["value"] == "after latest seal")))))
    );
    step!(
        "restored.original",
        evidence::restored(&m_dir, &guarded),
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    step!(
        "restored.write",
        m.write("after restoration", 55).await,
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    step!(
        "restored.after_write.original",
        evidence::restored(&m_dir, &guarded),
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    step!(
        "reopen.member.close",
        m.close().await,
        &[("a", &a), ("t", &t)]
    );
    let m = step!(
        "reopen.member.open",
        Peer::start(&m_dir, SCHEMA, None, None, false).await,
        &[("a", &a), ("t", &t)]
    );
    assert_eq!(
        step!(
            "reopen.member.status",
            m.tips("status", json!({})).await,
            &[("m", &m), ("a", &a), ("t", &t)]
        )["tip"],
        back
    );
    assert_eq!(
        step!(
            "reopen.member.read",
            m.keys().await,
            &[("m", &m), ("a", &a), ("t", &t)]
        ),
        json!([[{"type":"text","value":"after restoration"}],[{"type":"text","value":"kept"}]])
    );
    step!(
        "reopen.member.original",
        evidence::restored(&m_dir, &guarded),
        &[("m", &m), ("a", &a), ("t", &t)]
    );
    step!(
        "cleanup.member.close",
        m.close().await,
        &[("a", &a), ("t", &t)]
    );
    step!("cleanup.relay.close", t.close().await, &[("a", &a)]);
    eprintln!("rollback: relay has move; closing keeper");
    step!("cleanup.owner.close", a.close().await, &[]);
    Ok(())
}
