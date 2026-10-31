//! Release-only interactive write measurements on a replayed and a
//! mergeable table side by side: L0 idle, and L2 while a peer authors a
//! small write every 20 ms that this device keeps receiving. Diagnostic;
//! run with `cargo test --release -p rocky-sdk --test write_latency --
//! --ignored --nocapture --test-threads=1`.
use common::{Device, Failure, introduce};
use rocky_sdk::{Database, Network, Open, SqlValue, transport::memory::Hub};
use serde_json::json;
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::watch,
    time::{MissedTickBehavior, interval},
};

mod common;

const SCHEMA: &str = r#"{"application":"counters","version":1,"format":6,"tables":[{"name":"counters","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"amount","type":"integer","not_null":true}],"primary_key":["key"]},{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"amount","type":"integer","not_null":true}],"primary_key":["key"]}]}"#;
const TABLES: [&str; 2] = ["counters", "items"];
const WARM_UP: usize = 50;
const SAMPLES: usize = 600;

fn open<'a>(directory: &'a Path, network: Option<Network>) -> Open<'a> {
    Open {
        identity: None,
        directory,
        schema: SCHEMA,
        secrets: None,
        network,
        coordination: None,
    }
}

async fn write(database: &Database, sql: &str) -> Result<(), Failure> {
    let mut tx = database.transaction().await?;
    tx.execute(sql, Vec::new()).await?;
    tx.commit().await?;
    Ok(())
}

async fn seed(database: &Database, keys: &[&str]) -> Result<(), Failure> {
    for table in TABLES {
        let mut tx = database.transaction().await?;
        for key in keys {
            let id = tx.next_id(table, Vec::new()).await?;
            tx.execute(
                &format!("INSERT INTO {table}(key,amount,id) VALUES(?,0,?)"),
                vec![SqlValue::Text((*key).into()), SqlValue::Integer(id)],
            )
            .await?;
        }
        tx.commit().await?;
    }
    Ok(())
}

/// p50, p95, p99 and max of `samples`, in milliseconds.
fn quantiles(mut samples: Vec<Duration>) -> [f64; 4] {
    samples.sort();
    let at = |q: f64| samples[((samples.len() - 1) as f64 * q).round() as usize];
    [at(0.5), at(0.95), at(0.99), at(1.0)].map(|sample| sample.as_secs_f64() * 1e3)
}

/// Single-row interactive writes to `table` every `period`, after warm-up:
/// commit latency, and the local observer notification after it returns.
async fn probe(
    scenario: &str,
    database: &Database,
    table: &str,
    period: Duration,
) -> Result<(), Failure> {
    let events = database.observe_tables(Some(vec![table.into()])).await?;
    let (mut written, mut observed) = (Vec::new(), Vec::new());
    let mut ticks = interval(period);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    for sample in 0..WARM_UP + SAMPLES {
        ticks.tick().await;
        let started = Instant::now();
        write(
            database,
            &format!("UPDATE {table} SET amount=amount+1 WHERE key='probe'"),
        )
        .await?;
        let committed = Instant::now();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let change = events.next().await?;
                if change.tables.iter().any(|name| name == table)
                    && change.causes.iter().any(|cause| cause == "local")
                {
                    return Ok::<_, Failure>(());
                }
            }
        })
        .await??;
        if sample >= WARM_UP {
            written.push(committed - started);
            observed.push(committed.elapsed());
        }
    }
    for (name, samples) in [("write", written), ("observed", observed)] {
        let [p50, p95, p99, max] = quantiles(samples);
        println!(
            "P4 {scenario} {table} {name} samples={SAMPLES} p50={p50:.2} p95={p95:.2} p99={p99:.2} max={max:.2} ms"
        );
    }
    Ok(())
}

fn release() -> Result<(), Failure> {
    if cfg!(debug_assertions) {
        return Err("run measurements with --release".into());
    }
    Ok(())
}

#[tokio::test]
#[ignore = "measurement"]
async fn l0_idle_interactive_writes() -> Result<(), Failure> {
    release()?;
    let root = tempfile::tempdir()?;
    let database = Database::create(open(root.path(), None), None)?.database;
    seed(&database, &["probe"]).await?;
    for table in TABLES {
        probe("L0", &database, table, Duration::from_millis(10)).await?;
    }
    database.close().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement"]
async fn l2_interactive_writes_while_receiving_small_writes() -> Result<(), Failure> {
    release()?;
    let root = tempfile::tempdir()?;
    let hub = Arc::new(Hub::default());
    let network = |name: &str| Some(Network::Owned(hub.connector(name)));
    let a = Device::new(Database::create(
        open(&root.path().join("a"), network("a")),
        None,
    )?)?;
    seed(&a.database, &["probe", "pressure"]).await?;
    let invitation = a
        .invite_as(json!({"kind": "writer", "scopes": TABLES}))
        .await;
    let b = Device::new(Database::join(
        open(&root.path().join("b"), network("b")),
        &invitation,
    )?)?;
    introduce(&a, &b).await;
    for device in [&b, &a, &b] {
        device.sync().await.map_err(|error| error.to_string())?;
    }
    for table in TABLES {
        let (stop, stopping) = watch::channel(false);
        let author = async {
            let mut stopping = stopping.clone();
            let mut ticks = interval(Duration::from_millis(20));
            ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let mut authored = 0u64;
            while !*stopping.borrow() {
                tokio::select! { _ = ticks.tick() => {}, _ = stopping.changed() => break }
                write(
                    &b.database,
                    &format!("UPDATE {table} SET amount=amount+1 WHERE key='pressure'"),
                )
                .await?;
                authored += 1;
            }
            Ok::<_, Failure>(authored)
        };
        let receiver = async {
            let mut syncs = 0u64;
            while !*stopping.borrow() {
                a.sync().await.map_err(|error| error.to_string())?;
                syncs += 1;
                tokio::task::yield_now().await;
            }
            Ok::<_, Failure>(syncs)
        };
        let measured = async {
            let result = probe("L2", &a.database, table, Duration::from_millis(100)).await;
            let _ = stop.send(true);
            result
        };
        let (measured, authored, syncs) = tokio::join!(measured, author, receiver);
        measured?;
        println!("P4 L2 {table} load authored={} syncs={}", authored?, syncs?);
    }
    a.close().await;
    b.close().await;
    Ok(())
}
