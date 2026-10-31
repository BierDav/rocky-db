//! One device in its own process, so the orchestrator can SIGKILL it at any
//! moment. Requests arrive as JSON lines on stdin and run concurrently.
use rocky_sdk::Engine;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

pub const SCHEMA: &str = r#"{"format":6,"application":"chaos","version":1,"tables":[
 {"name":"lists","class":"replayed","columns":[{"name":"title","type":"text","not_null":true}],
  "primary_key":["id"],"partition_by":["id"],"partition_group":"list"},
 {"name":"items","class":"replayed","columns":[{"name":"list","type":"integer","not_null":true},{"name":"title","type":"text","not_null":true},{"name":"done","type":"integer","not_null":true}],
  "primary_key":["list","id"],"partition_by":["list"],"partition_group":"list",
  "foreign_keys":[{"columns":["list"],"table":"lists","on_delete":"cascade"}]},
 {"name":"notes","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"body","type":"text","not_null":true}],"primary_key":["key"]}
]}"#;

pub fn options(dir: &str, port: u16, mode: Value) -> Value {
    let mut options = json!({
        "directory": dir,
        "transport": {"kind":"iroh","relay":"disabled","lookup":"disabled","topic":false,"local":false,
                      "bind": format!("127.0.0.1:{port}")},
    });
    for (key, value) in mode.as_object().cloned().unwrap_or_default() {
        options[key] = value;
    }
    options
}

/// `node <options-json>`: opens, prints `{"opened":scope}` or `{"open_failed":..}`, then serves.
pub async fn run(options: String) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let out = Arc::new(Mutex::new(tokio::io::stdout()));
    let emit = |out: Arc<Mutex<tokio::io::Stdout>>, value: Value| async move {
        let mut out = out.lock().await;
        let _ = out.write_all(format!("{value}\n").as_bytes()).await;
        let _ = out.flush().await;
    };
    let opened = tokio::task::spawn_blocking(move || Engine::open(&options, SCHEMA, None)).await?;
    let engine = match opened {
        Ok(engine) => engine,
        Err(error) => {
            emit(out.clone(), json!({"open_failed": error.to_string()})).await;
            return Ok(());
        }
    };
    let scope: Value = serde_json::from_str(&engine.scope())?;
    emit(out.clone(), json!({"opened": scope})).await;
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        let message: Value = serde_json::from_str(&line)?;
        let id = message["id"].clone();
        if message["close"] == true {
            let result = engine.close().await;
            emit(
                out.clone(),
                json!({"id": id, "closed": result.map_err(|e| e.to_string()).err()}),
            )
            .await;
            return Ok(());
        }
        let engine = engine.clone();
        let scope = scope.clone();
        let out = out.clone();
        tokio::spawn(async move {
            let frame = json!({"version":1,"scope":scope,"request":message["call"]});
            let reply = match engine.call(frame.to_string()).await {
                Ok(text) => serde_json::from_str::<Value>(&text).unwrap_or_else(
                    |e| json!({"status":"error","error":format!("bad reply json: {e}")}),
                ),
                Err(error) => {
                    json!({"status":"error","error":{"transport_failure": error.to_string()}})
                }
            };
            emit(out, json!({"id": id, "reply": reply})).await;
        });
    }
    // stdin closed: the orchestrator went away; close gracefully.
    let _ = engine.close().await;
    Ok(())
}
