use rocky_sdk::{Database, Network, Open, Session, transport::memory::Hub};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};
const SCHEMA: &str = r#"{"format":6,"application":"partitionsdk","version":1,"tables":[{"name":"items","class":"replayed","columns":[{"name":"list","type":"text","not_null":true},{"name":"key","type":"text","not_null":true},{"name":"amount","type":"integer","not_null":true}],"primary_key":["list","key"],"partition_by":["list"]}],"views":[{"name":"partial_items","create_sql":"CREATE VIEW partial_items AS SELECT * FROM items WHERE amount>=0"}]}"#;
fn open<'a>(directory: &'a Path, hub: &Arc<Hub>) -> Open<'a> {
    let name = directory.file_name().unwrap().to_str().unwrap();
    Open {
        identity: None,
        directory,
        schema: SCHEMA,
        secrets: None,
        network: Some(Network::Owned(hub.connector(name))),
        coordination: None,
    }
}
async fn reply(session: &Session, scope: &Value, request: Value) -> Value {
    serde_json::from_str(
        &session
            .call(json!({"version":1,"scope":scope,"request":request}).to_string())
            .await
            .unwrap(),
    )
    .unwrap()
}
async fn call(session: &Session, scope: &Value, request: Value) -> Value {
    let reply = reply(session, scope, request).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    reply["value"].clone()
}
fn values(name: &str) -> Value {
    json!([{"type":"text","value":name}])
}
#[tokio::test]
async fn public_partition_schema_keys_sql_identity_and_reopen() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("writer");
    let hub = Arc::new(Hub::default());
    let db = Database::create(open(&path, &hub), None).unwrap().database;
    let scope: Value = serde_json::from_str(&db.scope()).unwrap();
    let session = db.session();
    for name in ["A", "B"] {
        call(
            &session,
            &scope,
            json!({"type":"partition_create","table":"items","values":values(name)}),
        )
        .await;
    }
    let mut ids = Vec::new();
    for (name, amount) in [("A", "10"), ("B", "20")] {
        call(&session, &scope, json!({"type":"sql","sql":"BEGIN"})).await;
        let id = call(
            &session,
            &scope,
            json!({"type":"next_id","table":"items","partition_values":values(name)}),
        )
        .await["id"]
            .clone();
        ids.push(id.clone());
        call(&session,&scope,json!({"type":"sql","sql":"INSERT INTO items(list,key,amount,id) VALUES(?,?,?,?)","values":[{"type":"text","value":name},{"type":"text","value":"key"},{"type":"integer","value":amount},{"type":"integer","value":id}]})).await;
        call(&session, &scope, json!({"type":"sql","sql":"COMMIT"})).await;
    }
    assert_ne!(ids[0], ids[1], "one creation log per author and table");
    let driver = db
        .connect(rocky_sdk::ConnectionOptions {
            read_only: false,
            durability: rocky_sdk::Durability::Buffered,
            profile: None,
            transaction_timeout: None,
            binding: None,
        })
        .await
        .unwrap();
    driver
        .execute(driver.statement(), "BEGIN".into(), vec![])
        .await
        .unwrap();
    let a_id = driver
        .execute(
            driver.statement(),
            "SELECT rocky_next_id('items', ?)".into(),
            vec![rocky_sdk::SqlValue::Text("A".into())],
        )
        .await
        .unwrap();
    let b_id = driver
        .execute(
            driver.statement(),
            "SELECT rocky_next_id('items', ?)".into(),
            vec![rocky_sdk::SqlValue::Text("B".into())],
        )
        .await
        .unwrap();
    assert_ne!(a_id.rows, b_id.rows);
    driver
        .execute(driver.statement(), "ROLLBACK".into(), vec![])
        .await
        .unwrap();

    let data=call(&session,&scope,json!({"type":"read","query":{"sql":"SELECT SUM(amount) FROM partial_items","values":[],"max_rows":1}})).await;
    assert_eq!(data["rows"][0][0]["value"], "30");
    let address = call(
        &session,
        &scope,
        json!({"type":"partition_address","table":"items","values":values("A")}),
    )
    .await;
    let parts = address["tuple"].as_array().unwrap();
    let selector = json!([[parts[0][0],{"Only":[parts[0][1]]}]]);
    let reader_path = root.path().join("reader");
    let device = Database::device(&reader_path, None).unwrap();
    let supplied=call(&session,&scope,json!({"type":"partition_grant","device":device,"partitions":[{"domain":scope,"table":address["scope"]["table"],"selector":selector,"rows":"All","rights":["Read"],"fields":[]}]})).await;
    let reader = Database::install(
        open(&reader_path, &hub),
        serde_json::from_value(supplied["supplied"].clone()).unwrap(),
    )
    .unwrap()
    .database;
    let reader_session = reader.session();
    call(&session,&scope,json!({"type":"partition_share","table":"items","values":values("A"),"recipients":[device.node]})).await;
    // The reader receives the envelope by syncing with its sender.
    let contact = call(&session, &scope, json!({"type":"contact"})).await;
    call(
        &reader_session,
        &scope,
        json!({"type":"peer_add","contact":contact["uri"]}),
    )
    .await;
    call(&reader_session, &scope, json!({"type":"sync"})).await;
    assert_eq!(
        call(
            &reader_session,
            &scope,
            json!({"type":"partition_status","table":"items","values":values("A")})
        )
        .await["epochs"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_ne!(
        reply(
            &reader_session,
            &scope,
            json!({"type":"partition_register","table":"items","values":values("B")})
        )
        .await["status"],
        "ok"
    );
    assert!(
        !call(
            &reader_session,
            &scope,
            json!({"type":"partition_complete","table":"items","values":values("A")})
        )
        .await["complete"]
            .as_bool()
            .unwrap()
    );
    call(
        &reader_session,
        &scope,
        json!({"type":"install","supplied":supplied["supplied"]}),
    )
    .await;
    reader.close().await.unwrap();
    Database::open(open(&reader_path, &hub))
        .unwrap()
        .database
        .close()
        .await
        .unwrap();
    db.close().await.unwrap();
    let db = Database::open(open(&path, &hub)).unwrap().database;
    let session = db.session();
    call(&session, &scope, json!({"type":"sql","sql":"BEGIN"})).await;
    let id = call(
        &session,
        &scope,
        json!({"type":"next_id","table":"items","partition_values":values("A")}),
    )
    .await;
    assert_eq!(
        id["id"].as_str().unwrap().parse::<i64>().unwrap(),
        ids[0].as_str().unwrap().parse::<i64>().unwrap() + 2
    );
    call(&session, &scope, json!({"type":"sql","sql":"ROLLBACK"})).await;
    call(
        &session,
        &scope,
        json!({"type":"partition_create","table":"items","values":values("C")}),
    )
    .await;
    let revoked = call(
        &session,
        &scope,
        json!({"type":"revoke","node":device.node.to_string()}),
    )
    .await;
    assert_eq!(revoked["revocations"]["statements"], 1);
    call(&session, &scope, json!({"type":"sql","sql":"BEGIN"})).await;
    let id = call(
        &session,
        &scope,
        json!({"type":"next_id","table":"items","partition_values":values("A")}),
    )
    .await;
    call(&session,&scope,json!({"type":"sql","sql":"INSERT INTO items(list,key,amount,id) VALUES('A','next',7,?)","values":[{"type":"integer","value":id["id"]}]})).await;
    call(&session, &scope, json!({"type":"sql","sql":"COMMIT"})).await;
    db.close().await.unwrap();
    Database::open(open(&path, &hub))
        .unwrap()
        .database
        .close()
        .await
        .unwrap();
}

#[tokio::test]
async fn own_id_partitions_continue_the_table_log() {
    let root = tempfile::tempdir().unwrap();
    let schema = r#"{"format":6,"application":"ownid","version":1,"tables":[{"name":"lists","class":"replayed","columns":[{"name":"title","type":"text","not_null":true}],"primary_key":["id"],"partition_by":["id"]}]}"#;
    let options = || Open {
        identity: None,
        directory: root.path(),
        schema,
        secrets: None,
        network: None,
        coordination: None,
    };
    let mut db = Database::create(options(), None).unwrap().database;
    let scope: Value = serde_json::from_str(&db.scope()).unwrap();
    let _session = db.session();
    let mut previous = 0;
    for index in 0..3 {
        if index == 2 {
            db.close().await.unwrap();
            db = Database::open(options()).unwrap().database;
        }
        let session = db.session();
        let prepared = call(
            &session,
            &scope,
            json!({"type":"partition_next","table":"lists"}),
        )
        .await;
        call(&session, &scope, json!({"type":"sql","sql":"BEGIN"})).await;
        let allocated = call(&session, &scope, json!({"type":"next_id","table":"lists"})).await;
        assert_eq!(allocated["id"], prepared["id"]);
        let id = allocated["id"].as_str().unwrap().parse::<i64>().unwrap();
        if previous != 0 {
            assert_eq!(id, previous + 1);
        }
        previous = id;
        call(&session,&scope,json!({"type":"sql","sql":"INSERT INTO lists(id,title) VALUES(?,?)","values":[{"type":"integer","value":id.to_string()},{"type":"text","value":"list"}]})).await;
        call(&session, &scope, json!({"type":"sql","sql":"COMMIT"})).await;
    }
    db.close().await.unwrap();
}
