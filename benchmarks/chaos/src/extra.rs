//! Niche topologies, local file damage and request fuzzing.
use crate::scenarios::{
    Failure, ITEMS, LISTS, NOTES, Slot, author_all, finding, heal, integrity, join_full, populate,
    report_divergence, root, short, status_data, writer_all,
};
use rand::{Rng, SeedableRng, rngs::StdRng, seq::SliceRandom};
use serde_json::{Value, json};
use std::time::Duration;

/// A new full node's only reachable peer is a partial replica: does it
/// claim completion from a subset, and does it complete once the issuer returns?
pub async fn bootstrap_from_partial() -> Result<(), Failure> {
    let root = root("from-partial");
    let mut a = Slot::new("a", &root);
    a.start(json!({"mode":"create"})).await?;
    author_all(a.n(), a.n()).await;
    let lists = populate(a.n(), "a", 200, 100, 3, 20).await;
    let mut p = Slot::new("p", &root);
    p.start(json!({"mode":"join","invitation": a.n().invite(writer_all()).await}))
        .await?;
    let a_node = a.n().node_id().await;
    p.n().call(json!({"type":"partition_role","role":{"role":"Partial","full_nodes":[a_node],"custody":1}})).await.ok();
    author_all(p.n(), a.n()).await;
    let _ = a.n().share(&lists[0], &[p.n().node_id().await]).await;
    crate::cluster::mesh(&[a.n(), p.n()]).await;
    for _ in 0..2 {
        let _ = p.n().sync().await;
    }
    // F joins; A shares all lists, then dies before F syncs anything.
    let mut f = Slot::new("f", &root);
    join_full(a.n(), &mut f, &lists).await?;
    a.kill().await;
    crate::cluster::mesh(&[f.n(), p.n()]).await;
    for _ in 0..3 {
        let _ = f.n().sync().await;
    }
    let data = status_data(f.n()).await;
    let notes = f.n().dump(NOTES).await.map(|r| r.len());
    let items = f.n().dump(ITEMS).await.map(|r| r.len());
    println!(
        "  f from partial only: pending={} notes {notes:?} items {items:?}",
        data["bootstrap_pending"]
    );
    if data["bootstrap_pending"] == false && items.as_ref().is_ok_and(|n| *n < 60) {
        finding(
            "a full node that could only reach a partial peer reports bootstrap complete with a subset of the lists",
        );
    }
    a.resume().await?;
    let ok = heal(&[a.n(), f.n(), p.n()], &[a.n(), f.n()], 6).await;
    if !ok {
        finding(
            "full node bootstrapped from a partial peer never completes after the issuer returns",
        );
        report_divergence(&[a.n(), f.n()]).await;
    }
    let healed = status_data(f.n()).await;
    println!(
        "  f after the issuer returned: pending={}",
        healed["bootstrap_pending"]
    );
    if healed["bootstrap_pending"] != false {
        finding("full node keeps bootstrap pending after meeting its inviter");
    }
    for s in [&mut a, &mut f, &mut p] {
        s.close().await?;
    }
    Ok(())
}

/// A revoked writer keeps writing and pushes through a full peer that has
/// not yet learned of the revocation; that peer then meets the issuer.
pub async fn revoked_via_stale_peer() -> Result<(), Failure> {
    let root = root("revoked-stale");
    let mut a = Slot::new("a", &root);
    a.start(json!({"mode":"create"})).await?;
    author_all(a.n(), a.n()).await;
    let lists = populate(a.n(), "a", 20, 10, 1, 5).await;
    let mut b = Slot::new("b", &root);
    let mut c = Slot::new("c", &root);
    join_full(a.n(), &mut b, &lists).await?;
    join_full(a.n(), &mut c, &lists).await?;
    crate::cluster::mesh(&[a.n(), b.n(), c.n()]).await;
    for n in [b.n(), c.n(), a.n()] {
        let _ = n.sync().await;
    }
    // Cut A off, then revoke B on A only.
    let _ = b
        .n()
        .call(json!({"type":"peer_remove","node": a.n().node_id().await}))
        .await;
    let _ = c
        .n()
        .call(json!({"type":"networking_control","enabled":false}))
        .await;
    let bid = b.n().node_id().await;
    println!(
        "  revoke b on a: {}",
        short(
            &a.n()
                .call(json!({"type":"revoke","node":bid}))
                .await
                .is_ok()
        )
    );
    let _ = a
        .n()
        .call(json!({"type":"peer_remove","node": bid.clone()}))
        .await;
    for i in 0..10 {
        let _ = b.n().add_note(&format!("b-revoked{i}"), "x").await;
        let _ = b
            .n()
            .add_item(&lists[0], &format!("b-revoked-item{i}"))
            .await;
    }
    let _ = c
        .n()
        .call(json!({"type":"networking_control","enabled":true}))
        .await;
    let _ = c
        .n()
        .call(json!({"type":"peer_remove","node": a.n().node_id().await}))
        .await;
    let _ = b.n().sync().await;
    let _ = c.n().sync().await;
    let on_c = c
        .n()
        .dump("SELECT key FROM notes WHERE key LIKE 'b-revoked%'")
        .await
        .map(|r| r.len());
    println!("  c accepted rows written by b after its revocation (c unaware): {on_c:?}");
    // C meets A and learns the revocation.
    crate::cluster::mesh(&[a.n(), c.n()]).await;
    for _ in 0..3 {
        let _ = c.n().sync().await;
        let _ = a.n().sync().await;
    }
    let on_c = c
        .n()
        .dump("SELECT key FROM notes WHERE key LIKE 'b-revoked%'")
        .await
        .map(|r| r.len());
    let on_a = a
        .n()
        .dump("SELECT key FROM notes WHERE key LIKE 'b-revoked%'")
        .await
        .map(|r| r.len());
    println!("  after c meets a: on c {on_c:?}, on a {on_a:?}");
    let (va, vc) = (a.n().dump(NOTES).await, c.n().dump(NOTES).await);
    let (ia, ic) = (a.n().dump(ITEMS).await, c.n().dump(ITEMS).await);
    if va != vc || ia != ic {
        finding(
            "rows a revoked writer pushed through an unaware peer leave that peer permanently diverged from the issuer",
        );
        report_divergence(&[a.n(), c.n()]).await;
    }
    let sync = c.n().sync().await;
    println!(
        "  c sync health afterwards: {}",
        short(&sync.map(|r| r["peers"].as_array().map(|p| {
            p.iter()
                .map(|p| {
                    p["attempts"]
                        .as_array()
                        .map(|a| a.iter().map(|a| a["outcome"].clone()).collect::<Vec<_>>())
                })
                .collect::<Vec<_>>()
        })))
    );
    let new = c.n().add_note("c-after", "x").await;
    println!(
        "  c write after: {} (a={}, b={})",
        short(&new.is_ok()),
        &a.n().node_id().await[..8],
        &bid[..8]
    );
    let mut arrived = false;
    for round in 0..8 {
        let r = c.n().sync().await;
        let _ = a.n().sync().await;
        let on_a = a
            .n()
            .dump("SELECT key FROM notes WHERE key = 'c-after'")
            .await
            .map(|r| r.len())
            .unwrap_or(0);
        let attempts: Vec<String> = r
            .as_ref()
            .ok()
            .and_then(|r| r["peers"].as_array().cloned())
            .unwrap_or_default()
            .iter()
            .map(|p| {
                format!(
                    "{}:{}:{}",
                    &p["node"].as_str().unwrap_or("?")
                        [..8.min(p["node"].as_str().unwrap_or("?").len())],
                    p["skip"],
                    p["attempts"]
                        .as_array()
                        .map(|a| a
                            .iter()
                            .map(|a| format!(
                                "{}={}{}",
                                a["operation"].as_str().unwrap_or(""),
                                a["outcome"].as_str().unwrap_or(""),
                                a["failure"]
                                    .as_object()
                                    .map(|f| format!(
                                        "({})",
                                        f.get("message").and_then(|m| m.as_str()).unwrap_or("")
                                    ))
                                    .unwrap_or_default()
                            ))
                            .collect::<Vec<_>>()
                            .join(","))
                        .unwrap_or_default()
                )
            })
            .collect();
        println!("    round {round}: on a {on_a}; c attempts {attempts:?}");
        if let Some(failed) = r
            .as_ref()
            .ok()
            .and_then(|r| r["peers"].as_array().cloned())
            .unwrap_or_default()
            .iter()
            .flat_map(|p| p["attempts"].as_array().cloned().unwrap_or_default())
            .find(|a| a["outcome"] == "failed")
        {
            println!("    failed attempt: {}", failed);
        }
        if on_a == 1 && round >= 3 {
            arrived = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let events = a
        .n()
        .call(json!({"type":"activity"}))
        .await
        .unwrap_or_default();
    let tail: Vec<_> = events["events"]
        .as_array()
        .into_iter()
        .flatten()
        .rev()
        .filter(|e| {
            e.to_string().contains("fail")
                || e.to_string().contains("refus")
                || e.to_string().contains("revok")
        })
        .take(4)
        .map(|e| short(e))
        .collect();
    println!("    issuer activity (failures): {tail:?}");
    c.close().await?;
    c.resume().await?;
    crate::cluster::mesh(&[a.n(), c.n()]).await;
    let _ = c.n().add_note("c-after-restart", "x").await;
    let r = c.n().sync().await;
    let outcomes: Vec<_> = r
        .as_ref()
        .ok()
        .and_then(|r| r["peers"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .flat_map(|p| p["attempts"].as_array().cloned().unwrap_or_default())
        .map(|a| {
            format!(
                "{}={}",
                a["operation"].as_str().unwrap_or(""),
                a["outcome"].as_str().unwrap_or("")
            )
        })
        .collect();
    println!("    after c restart: {outcomes:?}");
    if outcomes.iter().any(|o| o == "reconcile=failed") {
        finding(
            "a peer that received (then purged) a revoked writer's rows can no longer reconcile toward the issuer; every attempt ends with a mislabelled 'local storage I/O: unexpected end of file', also after restart",
        );
    }
    if !arrived {
        let events = c
            .n()
            .call(json!({"type":"activity"}))
            .await
            .unwrap_or_default();
        let tail: Vec<_> = events["events"]
            .as_array()
            .into_iter()
            .flatten()
            .rev()
            .take(12)
            .map(|e| {
                format!(
                    "{} {}",
                    e["kind"].as_str().unwrap_or(""),
                    short(
                        &e.get("error")
                            .or(e.get("reason"))
                            .cloned()
                            .unwrap_or(Value::Null)
                    )
                )
            })
            .collect();
        println!("    c activity: {tail:?}");
        finding(
            "after purging a revoked writer's rows, the peer's own new writes no longer reach the issuer",
        );
    }
    for s in [&mut a, &mut b, &mut c] {
        let _ = s.close().await;
    }
    Ok(())
}

/// Two processes open the same directory.
pub async fn double_open() -> Result<(), Failure> {
    let root = root("double-open");
    let mut a = Slot::new("a", &root);
    a.start(json!({"mode":"create"})).await?;
    author_all(a.n(), a.n()).await;
    populate(a.n(), "a", 10, 10, 0, 0).await;
    let mut twin = Slot::new("a", &root);
    let second = twin.resume().await;
    println!(
        "  second open of the same directory: {}",
        short(&second.as_ref().map(|_| "OPENED"))
    );
    if second.is_ok() {
        finding("the same directory opens twice concurrently");
        let _ = twin.n().add_note("twin", "x").await;
        let _ = twin.close().await;
    }
    println!(
        "  first still writes: {}",
        short(&a.n().add_note("after-twin", "x").await.is_ok())
    );
    a.kill().await;
    // Stale lock files after SIGKILL must not block reopen.
    println!(
        "  reopen after kill with lock files left: {}",
        short(&a.resume().await.map(|_| "ok"))
    );
    a.close().await?;
    Ok(())
}

/// After SIGKILL, the WAL is lost (power-loss-like) or identity.json is
/// rolled back to an older copy: do the stores still agree?
pub async fn file_damage() -> Result<(), Failure> {
    let root = root("damage");
    let mut a = Slot::new("a", &root);
    a.start(json!({"mode":"create"})).await?;
    author_all(a.n(), a.n()).await;
    let lists = populate(a.n(), "a", 100, 100, 2, 10).await;
    let mut b = Slot::new("b", &root);
    join_full(a.n(), &mut b, &lists).await?;
    crate::cluster::mesh(&[a.n(), b.n()]).await;
    let old_identity = std::fs::read(root.join("b/identity.json"))?;
    for _ in 0..2 {
        let _ = b.n().sync().await;
    }
    // New list shared after the identity snapshot: a key arrives later.
    let late = a.n().add_list("late").await.map_err(|e| e.to_string())?;
    for i in 0..10 {
        let _ = a.n().add_item(&late, &format!("late{i}")).await;
    }
    let _ = a.n().share(&late, &[b.n().node_id().await]).await;
    let _ = b.n().sync().await;
    for i in 0..20 {
        let _ = b.n().add_note(&format!("b-unsynced{i}"), "x").await;
        let _ = b.n().add_item(&late, &format!("b-late{i}")).await;
    }
    b.kill().await;
    // 1. WAL gone.
    let wal = root.join("b/rocky.sqlite-wal");
    let wal_len = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(root.join("b/rocky.sqlite-shm"));
    let reopened = b.resume().await;
    println!(
        "  reopen after deleting a {wal_len}-byte WAL: {}",
        short(&reopened.as_ref().map(|_| "ok"))
    );
    if reopened.is_ok() {
        let ok = heal(&[a.n(), b.n()], &[a.n(), b.n()], 5).await;
        if !ok {
            finding("a replica whose WAL was lost (post-kill power-loss model) never re-converges");
            report_divergence(&[a.n(), b.n()]).await;
        }
        b.close().await?;
    } else {
        finding(format!(
            "replica does not reopen after WAL loss: {}",
            reopened.err().unwrap_or_default()
        ));
    }
    println!("  integrity after WAL loss: {}", integrity(&root.join("b")));
    // 2. identity.json rolled back to before the late key arrived.
    std::fs::write(root.join("b/identity.json"), &old_identity)?;
    let reopened = b.resume().await;
    println!(
        "  reopen with an older identity.json: {}",
        short(&reopened.as_ref().map(|_| "ok"))
    );
    match reopened {
        Ok(_) => {
            let ok = heal(&[a.n(), b.n()], &[a.n(), b.n()], 5).await;
            let read = b
                .n()
                .dump(&format!("SELECT title FROM items WHERE list = {late}"))
                .await
                .map(|r| r.len());
            println!("  late list on b: {read:?}");
            if !ok {
                finding(
                    "replica with a rolled-back identity.json (SQLite newer than settings) does not re-converge",
                );
                report_divergence(&[a.n(), b.n()]).await;
            }
            b.close().await?;
        }
        Err(e) => finding(format!(
            "replica refuses to open when identity.json is older than its database: {e}"
        )),
    }
    a.close().await?;
    let _ = LISTS;
    Ok(())
}

/// Random and malformed native requests; the node must answer each with an
/// error or a value, and remain usable.
pub async fn request_fuzz() -> Result<(), Failure> {
    let root = root("request-fuzz");
    let mut a = Slot::new("a", &root);
    a.start(json!({"mode":"create"})).await?;
    author_all(a.n(), a.n()).await;
    let lists = populate(a.n(), "a", 20, 10, 1, 5).await;
    let mut b = Slot::new("b", &root);
    join_full(a.n(), &mut b, &lists).await?;
    crate::cluster::mesh(&[a.n(), b.n()]).await;
    let _ = b.n().sync().await;
    const TYPES: &[&str] = &[
        "sql",
        "next_id",
        "read",
        "subscribe",
        "next",
        "unsubscribe",
        "mutation_progress",
        "partition_role",
        "partition_share",
        "partition_subscribe",
        "partition_bootstrap",
        "partition_evict",
        "partition_unsubscribe",
        "partition_install",
        "partition_status",
        "partition_next",
        "partition_create",
        "partition_register",
        "partition_grant",
        "partition_delegate",
        "partition_address",
        "partition_complete",
        "retention",
        "retention_limits",
        "pseudonym_request",
        "pseudonym_install",
        "pseudonym_assign",
        "pseudonym_owner",
        "pseudonym_range",
        "grant",
        "delegate",
        "install",
        "peer_add",
        "peer_remove",
        "revoke",
        "device_label",
        "invitation_open",
        "enrollment_route",
        "enrollment_upstream",
        "contact_request",
        "status_next",
        "activity_next",
        "backup",
        "sync_start",
        "networking_control",
        "generation",
        "command_submit",
        "command_ticket",
        "command_cancel",
        "command_run",
        "command_rows",
        "renew",
        "authors",
    ];
    let mut rng = StdRng::seed_from_u64(
        std::env::var("CHAOS_SEED")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(7),
    );
    let mut unhealthy = 0;
    let mut slow = 0;
    for i in 0..600 {
        let kind = *TYPES.choose(&mut rng).ok_or("types")?;
        let mut request = json!({"type": kind});
        for _ in 0..rng.gen_range(0..5) {
            let field = *[
                "sql",
                "values",
                "table",
                "collection",
                "group",
                "policy",
                "limits",
                "role",
                "handle",
                "query",
                "node",
                "contact",
                "recipients",
                "envelope",
                "pseudonym",
                "request",
                "device",
                "grants",
                "uri",
                "path",
                "enabled",
                "after",
                "subscription",
                "partition_values",
                "action",
                "maintain",
                "id",
                "label",
            ]
            .choose(&mut rng)
            .ok_or("fields")?;
            request[field] = random_value(&mut rng, 0, &lists[0]);
        }
        if kind == "logout" || (kind == "revoke") {
            continue;
        }
        let r = b
            .n()
            .call_for(request.clone(), Duration::from_secs(20))
            .await;
        if let Err(e) = &r
            && e.get("harness").is_some()
        {
            slow += 1;
            println!("  [{i}] {} -> {e}", short(&request));
        }
        if i % 25 == 0 {
            let _ = b.n().sql("ROLLBACK", json!([])).await;
            let _ = b
                .n()
                .call(json!({"type":"networking_control","enabled":true}))
                .await;
            let _ = b
                .n()
                .call(json!({"type":"sync_start","enabled":true}))
                .await;
            let health = b
                .n()
                .call_for(json!({"type":"session"}), Duration::from_secs(10))
                .await;
            if health.is_err() {
                unhealthy += 1;
                finding(format!(
                    "node unresponsive after request #{i} {}: {}",
                    short(&request),
                    short(&health)
                ));
                b.kill().await;
                b.resume().await?;
            }
        }
    }
    println!("  600 random requests: {slow} timed out, {unhealthy} left the node unresponsive");
    let _ = b.n().sql("ROLLBACK", json!([])).await;
    let ok = heal(&[a.n(), b.n()], &[a.n(), b.n()], 5).await;
    if !ok {
        finding("random native requests left the replicas unable to converge");
        report_divergence(&[a.n(), b.n()]).await;
    }
    b.close().await?;
    a.close().await?;
    println!("  b integrity: {}", integrity(&root.join("b")));
    let mut b = Slot::new("b", &root);
    if let Err(e) = b.resume().await {
        finding(format!("node does not reopen after request fuzzing: {e}"));
    } else {
        b.close().await?;
    }
    Ok(())
}

fn random_value(rng: &mut StdRng, depth: u32, list: &str) -> Value {
    match rng.gen_range(0..14) {
        0 => Value::Null,
        1 => json!(rng.gen_bool(0.5)),
        2 => json!(rng.gen_range(-5i64..5)),
        3 => json!(u64::MAX),
        4 => json!(i64::MIN),
        5 => json!("x".repeat(rng.gen_range(0..70_000))),
        6 => json!("0".repeat(64)),
        7 => json!(
            [
                "SELECT 1",
                "notes",
                "items",
                "list",
                "Partial",
                "Full",
                "\u{0000}",
                "../../etc"
            ][rng.gen_range(0..8)]
        ),
        8 => json!([{"type":"integer","value":list}]),
        9 => json!({"role":"Partial","full_nodes":["zz"],"custody":99}),
        10 => json!(vec![rng.gen_range(0u8..255); rng.gen_range(0..40)]),
        11 => json!({"sql":"SELECT * FROM notes","values":[],"max_rows":rng.gen_range(0..2000)}),
        12 if depth < 3 => Value::Array(
            (0..rng.gen_range(0..4))
                .map(|_| random_value(rng, depth + 1, list))
                .collect(),
        ),
        _ if depth < 3 => {
            let mut map = serde_json::Map::new();
            for _ in 0..rng.gen_range(0..4) {
                map.insert(
                    ["type", "value", "kind", "scopes", "id"][rng.gen_range(0..5)].into(),
                    random_value(rng, depth + 1, list),
                );
            }
            Value::Object(map)
        }
        _ => json!(1.5e308),
    }
}

/// A second trusted device is killed mid-bootstrap; with the original issuer
/// offline it enrolls a new device and serves it its incomplete state.
pub async fn half_bootstrapped_source() -> Result<(), Failure> {
    let root = root("half-source");
    let mut a = Slot::new("a", &root);
    a.start(json!({"mode":"create"})).await?;
    author_all(a.n(), a.n()).await;
    let lists = populate(a.n(), "a", 1500, 2000, 2, 30).await;
    let mut t = Slot::new("t", &root);
    t.start(json!({"mode":"join","invitation": a.n().invite(json!({"kind":"issuer"})).await}))
        .await?;
    let tid = t.n().node_id().await;
    for list in &lists {
        let _ = a.n().share(list, std::slice::from_ref(&tid)).await;
    }
    let data = crate::scenarios::until_imported(t.n(), 300, Duration::from_secs(30)).await;
    println!("  t killed at {}", short(&data["bootstrap"]));
    t.kill().await;
    a.kill().await;
    t.resume().await?;
    author_all(t.n(), t.n()).await;
    let held = t.n().dump(NOTES).await.map(|r| r.len());
    println!(
        "  t (issuer offline) holds notes {held:?}, pending={}",
        status_data(t.n()).await["bootstrap_pending"]
    );
    let t_note = t.n().add_note("t-while-half", "x").await;
    println!(
        "  t writes while half-bootstrapped: {}",
        short(&t_note.is_ok())
    );
    let mut n = Slot::new("n", &root);
    let joined = n
        .start(json!({"mode":"join","invitation": t.n().invite(writer_all()).await}))
        .await;
    println!(
        "  n joins via half-bootstrapped t: {}",
        short(&joined.as_ref().map(|_| "ok"))
    );
    if joined.is_err() {
        a.resume().await?;
        let _ = t.close().await;
        let _ = a.close().await;
        return Ok(());
    }
    author_all(n.n(), t.n()).await;
    let nid = n.n().node_id().await;
    for list in &lists {
        let r = t.n().share(list, std::slice::from_ref(&nid)).await;
        if let Err(e) = r {
            println!("  t share {list}: {}", short(&e));
        }
    }
    for _ in 0..3 {
        let _ = n.n().sync().await;
    }
    let data = status_data(n.n()).await;
    println!(
        "  n from t: pending={} notes {:?}",
        data["bootstrap_pending"],
        n.n().dump(NOTES).await.map(|r| r.len())
    );
    a.resume().await?;
    let ok = heal(&[a.n(), t.n(), n.n()], &[a.n(), t.n(), n.n()], 8).await;
    if !ok {
        finding(
            "a device bootstrapped from a half-bootstrapped trusted peer never converges once the original issuer returns",
        );
        report_divergence(&[a.n(), t.n(), n.n()]).await;
    }
    for s in [&mut a, &mut t, &mut n] {
        let _ = s.close().await;
    }
    Ok(())
}

/// Trusted T creates a list and shares it with trusted A. Can A share it
/// with a full device enrolled later, while T is offline?
pub async fn cross_issuer_share() -> Result<(), Failure> {
    let root = root("cross-issuer");
    let mut a = Slot::new("a", &root);
    a.start(json!({"mode":"create"})).await?;
    author_all(a.n(), a.n()).await;
    let mut t = Slot::new("t", &root);
    t.start(json!({"mode":"join","invitation": a.n().invite(json!({"kind":"issuer"})).await}))
        .await?;
    author_all(t.n(), a.n()).await;
    crate::cluster::mesh(&[a.n(), t.n()]).await;
    let _ = t.n().sync().await;
    let list = t.n().add_list("by-t").await.map_err(|e| e.to_string())?;
    for i in 0..5 {
        let _ = t.n().add_item(&list, &format!("t{i}")).await;
    }
    let a_id = a.n().node_id().await;
    let offline = std::env::var("CHAOS_A_OFFLINE").is_ok();
    if offline {
        a.kill().await;
    }
    let shared = t.n().share(&list, &[a_id]).await;
    println!(
        "  t shares its list with a (a offline: {offline}): {}",
        short(&shared.is_ok())
    );
    if offline {
        a.resume().await?;
        crate::cluster::mesh(&[a.n(), t.n()]).await;
    }
    for _ in 0..3 {
        let _ = t.n().sync().await;
        let _ = a.n().sync().await;
    }
    let on_a = a
        .n()
        .dump(&format!("SELECT title FROM items WHERE list = {list}"))
        .await
        .map(|r| r.len());
    println!("  a reads t's list: {on_a:?}");
    t.kill().await;
    let mut f = Slot::new("f", &root);
    f.start(json!({"mode":"join","invitation": a.n().invite(writer_all()).await}))
        .await?;
    let r = a.n().share(&list, &[f.n().node_id().await]).await;
    println!(
        "  a shares t's list with new full f (t offline): {}",
        short(&r)
    );
    if r.is_err() {
        finding(
            "a trusted device can read but not re-share a list another trusted device created; full devices enrolled while the creator is away never receive it",
        );
    }
    let status = a.n().call(json!({"type":"partition_status","group":"list","values":[{"type":"integer","value":list}]})).await;
    println!(
        "  a partition status: {}",
        short(&status.map(|s| (s["current"].clone(), s["recipients"].clone())))
    );
    let _ = f.close().await;
    let _ = a.close().await;
    Ok(())
}

/// The sharer is SIGKILLed during the sync that would deliver an envelope
/// to an offline trusted recipient; can the recipient share it onward later?
pub async fn envelope_kill() -> Result<(), Failure> {
    let root = root("envelope-kill");
    let mut a = Slot::new("a", &root);
    a.start(json!({"mode":"create"})).await?;
    author_all(a.n(), a.n()).await;
    let mut t = Slot::new("t", &root);
    t.start(json!({"mode":"join","invitation": a.n().invite(json!({"kind":"issuer"})).await}))
        .await?;
    author_all(t.n(), a.n()).await;
    let mut f = Slot::new("f", &root);
    f.start(json!({"mode":"join","invitation": a.n().invite(writer_all()).await}))
        .await?;
    crate::cluster::mesh(&[a.n(), t.n(), f.n()]).await;
    let _ = t.n().sync().await;
    let (a_id, f_id) = (a.n().node_id().await, f.n().node_id().await);
    let mut lost = Vec::new();
    for (round, delay) in [0u64, 5, 15, 30, 60, 120, 250].into_iter().enumerate() {
        let list = t
            .n()
            .add_list(&format!("L{round}"))
            .await
            .map_err(|e| e.to_string())?;
        let _ = t.n().add_item(&list, "x").await;
        a.kill().await;
        let _ = t.n().share(&list, &[a_id.clone(), f_id.clone()]).await;
        let n = t.n().clone();
        let sync = tokio::spawn(async move { n.sync().await });
        tokio::time::sleep(Duration::from_millis(delay)).await;
        t.kill().await;
        let _ = sync.await;
        a.resume().await?;
        t.resume().await?;
        crate::cluster::mesh(&[a.n(), t.n(), f.n()]).await;
        for _ in 0..3 {
            let _ = a.n().sync().await;
            let _ = t.n().sync().await;
            let _ = f.n().sync().await;
        }
        let reads = a
            .n()
            .dump(&format!("SELECT title FROM lists WHERE id = {list}"))
            .await
            .map(|r| r.len());
        let status = a.n().call(json!({"type":"partition_status","group":"list","values":[{"type":"integer","value":list}]})).await;
        let held = status
            .as_ref()
            .map(|s| !s["current"].is_null())
            .unwrap_or(false);
        let mut g = Slot::new(&format!("g{round}"), &root);
        g.start(json!({"mode":"join","invitation": a.n().invite(writer_all()).await}))
            .await?;
        let reshare = a.n().share(&list, &[g.n().node_id().await]).await;
        println!(
            "  kill t {delay}ms into delivery: a reads {reads:?}, a holds secret {held}, a re-shares: {}",
            short(&reshare.as_ref().err())
        );
        if reshare.is_err() {
            lost.push(delay);
        }
        let _ = g.close().await;
    }
    if !lost.is_empty() {
        finding(format!(
            "trusted recipient never obtains the group secret after the sharer was killed during delivery at {lost:?} ms"
        ));
    }
    for s in [&mut a, &mut t, &mut f] {
        let _ = s.close().await;
    }
    Ok(())
}

/// A second trusted device whose bootstrap did not finish before the
/// original issuer vanished: can it still enroll devices?
pub async fn orphaned_second_issuer() -> Result<(), Failure> {
    let root = root("orphan-issuer");
    let mut a = Slot::new("a", &root);
    a.start(json!({"mode":"create"})).await?;
    author_all(a.n(), a.n()).await;
    let lists = populate(a.n(), "a", 1500, 2000, 2, 20).await;
    let mut f = Slot::new("f", &root);
    join_full(a.n(), &mut f, &lists).await?;
    crate::cluster::mesh(&[a.n(), f.n()]).await;
    for _ in 0..2 {
        let _ = f.n().sync().await;
    }
    for (variant, kill_t) in [
        ("t killed mid-import", true),
        ("a gone right after t joined", false),
    ] {
        let name = if kill_t { "t1" } else { "t2" };
        let mut t = Slot::new(name, &root);
        if a.node.is_none() {
            a.resume().await?;
        }
        t.start(json!({"mode":"join","invitation": a.n().invite(json!({"kind":"issuer"})).await}))
            .await?;
        if kill_t {
            let _ = crate::scenarios::until_imported(t.n(), 200, Duration::from_secs(30)).await;
            t.kill().await;
        }
        a.kill().await;
        if kill_t {
            t.resume().await?;
        }
        crate::cluster::mesh(&[t.n(), f.n()]).await;
        let mut outcome = String::new();
        for round in 0..6 {
            let _ = t.n().sync().await;
            let r = t
                .n()
                .call(json!({"type":"pairing","profile":writer_all()}))
                .await;
            outcome = format!(
                "round {round}: pending={} pairing {}",
                status_data(t.n()).await["bootstrap_pending"],
                short(&r.as_ref().map(|_| "ok"))
            );
            if r.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        println!("  {variant}: {outcome}");
        if !outcome.contains("pairing Ok") {
            finding(format!(
                "second trusted device cannot invite while the original issuer is gone ({variant}): {outcome}"
            ));
            let renew = t
                .n()
                .call(json!({"type":"revoke","node": f.n().node_id().await}))
                .await;
            println!("    revoke from it: {}", short(&renew.map(|_| "ok")));
        }
        let _ = t.close().await;
    }
    let _ = f.close().await;
    Ok(())
}
