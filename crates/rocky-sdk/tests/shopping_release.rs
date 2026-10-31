//! The shopping release gate on the group schema: two phones that are never
//! online together share lists through a keyless custody peer. A duplicate
//! title converges by policy, a deleted list cascades, a deleted category
//! nulls only its reference, and a moved item keeps an offline tick. See `docs/runtime/shopping-qualification.md`.
use rocky_sdk::{Database, Network, Open, Session, transport::memory::Hub};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

const SCHEMA: &str = r#"{"format":6,"application":"shopping","version":3,"tables":[
 {"name":"lists","class":"replayed","columns":[{"name":"title","type":"text","not_null":true}],
  "primary_key":["id"],"partition_by":["id"],"partition_group":"list"},
 {"name":"categories","class":"replayed","columns":[{"name":"list","type":"integer","not_null":true},{"name":"name","type":"text","not_null":true}],
  "primary_key":["list","id"],"partition_by":["list"],"partition_group":"list",
  "foreign_keys":[{"columns":["list"],"table":"lists","on_delete":"cascade"}]},
 {"name":"items","class":"replayed","columns":[
   {"name":"list","type":"integer","not_null":true},{"name":"title","type":"text","not_null":true},
   {"name":"completed","type":"integer","not_null":true},{"name":"category","type":"integer"}],
  "primary_key":["list","id"],"partition_by":["list"],"partition_group":"list",
  "indexes":[{"name":"index_items_list_title","unique":true,"columns":[{"name":"list","descending":false},{"name":"title","descending":false}]}],
  "foreign_keys":[{"columns":["list"],"table":"lists","on_delete":"cascade"},
   {"columns":["list","category"],"table":"categories","on_delete":"set_null"}]}
]}"#;
const TABLES: [&str; 3] = ["lists", "categories", "items"];

type Failure = Box<dyn std::error::Error + Send + Sync>;

struct Peer {
    database: Arc<Database>,
    session: Session,
    scope: Value,
}
impl Peer {
    fn new(database: Arc<Database>) -> Result<Self, Failure> {
        Ok(Self {
            session: database.session(),
            scope: serde_json::from_str(&database.scope())?,
            database,
        })
    }
    async fn call(&self, request: Value) -> Result<Value, Failure> {
        let reply: Value = serde_json::from_str(
            &self
                .session
                .call(json!({"version":1,"scope":self.scope,"request":request}).to_string())
                .await?,
        )?;
        if reply["status"] == "ok" {
            Ok(reply["value"].clone())
        } else {
            Err(format!("{request}: {}", reply["error"]).into())
        }
    }
    async fn invite(&self, profile: Value) -> Result<String, Failure> {
        Ok(self
            .call(json!({"type":"pairing","profile":profile}))
            .await?["uri"]
            .as_str()
            .ok_or("uri")?
            .to_owned())
    }

    async fn node(&self) -> Result<Value, Failure> {
        Ok(self.call(json!({"type":"session"})).await?["node"].clone())
    }
    async fn online(&self, online: bool) -> Result<(), Failure> {
        self.call(json!({"type":"networking_control","enabled":online}))
            .await
            .map(drop)
    }
    async fn sync(&self) -> Result<(), Failure> {
        let status = self.call(json!({"type":"sync"})).await?;
        if !status["peers"].as_array().is_some_and(|peers| {
            peers.iter().any(|peer| {
                peer["attempts"].as_array().is_some_and(|attempts| {
                    attempts.iter().any(|attempt| {
                        attempt["operation"] == "reconcile" && attempt["outcome"] == "completed"
                    })
                })
            })
        }) {
            return Err(format!("sync: {status}").into());
        }
        Ok(())
    }
    /// Inserts one row in one transaction; `?` is the next own id.
    async fn insert(&self, table: &str, list: Option<&str>, sql: &str) -> Result<String, Failure> {
        self.call(json!({"type":"sql","sql":"BEGIN"})).await?;
        let mut next = json!({"type":"next_id","table":table});
        if let Some(list) = list {
            next["partition_values"] = values(list);
        }
        let id = self.call(next).await?["id"].clone();
        self.call(json!({"type":"sql","sql":sql,"values":[{"type":"integer","value":id}]}))
            .await?;
        self.call(json!({"type":"sql","sql":"COMMIT"})).await?;
        Ok(id.as_str().ok_or("id")?.to_owned())
    }
    async fn create_list(&self, title: &str) -> Result<String, Failure> {
        self.call(json!({"type":"partition_next","table":"lists"}))
            .await?;
        self.insert(
            "lists",
            None,
            &format!("INSERT INTO lists(id,title) VALUES(?,'{title}')"),
        )
        .await
    }
    async fn add(
        &self,
        list: &str,
        title: &str,
        category: Option<&str>,
    ) -> Result<String, Failure> {
        let category = category.unwrap_or("NULL");
        self.insert(
            "items",
            Some(list),
            &format!(
                "INSERT INTO items(id,list,title,completed,category) VALUES(?,{list},'{title}',0,{category})"
            ),
        )
        .await
    }
    /// Moves item `id` to list `to` in one transaction: a new row there
    /// with the values read here, and the old one deleted.
    async fn move_item(&self, from: &str, id: &str, to: &str) -> Result<String, Failure> {
        self.call(json!({"type":"sql","sql":"BEGIN"})).await?;
        let moved = self
            .call(json!({"type":"next_id","table":"items","partition_values":values(to)}))
            .await?["id"]
            .clone();
        self.call(json!({"type":"sql","sql":format!("INSERT INTO items(id,list,title,completed) SELECT ?,{to},title,completed FROM items WHERE list={from} AND id={id}"),"values":[{"type":"integer","value":moved}]}))
            .await?;
        self.execute(&format!("DELETE FROM items WHERE list={from} AND id={id}"))
            .await?;
        self.call(json!({"type":"sql","sql":"COMMIT"})).await?;
        Ok(moved.as_str().ok_or("id")?.to_owned())
    }
    async fn execute(&self, sql: &str) -> Result<(), Failure> {
        self.call(json!({"type":"sql","sql":sql})).await.map(drop)
    }
    async fn rows(&self, sql: &str) -> Result<Vec<Vec<Value>>, Failure> {
        let page = self
            .call(json!({"type":"read","query":{"sql":sql,"values":[],"max_rows":256}}))
            .await?;
        Ok(page["rows"]
            .as_array()
            .ok_or("rows")?
            .iter()
            .map(|row| {
                row.as_array()
                    .map(|cells| cells.iter().map(|cell| cell["value"].clone()).collect())
                    .unwrap_or_default()
            })
            .collect())
    }
    /// `(list, title, completed, category)` of every visible item.
    async fn items(&self) -> Result<Vec<Vec<Value>>, Failure> {
        self.rows("SELECT list,title,completed,category FROM items ORDER BY list,title")
            .await
    }
    /// Saves `list`'s envelope for `reader`; a later sync delivers it.
    async fn share(&self, list: &str, reader: &Peer) -> Result<(), Failure> {
        self.call(json!({"type":"partition_share","group":"list","values":values(list),"recipients":[reader.node().await?]}))
            .await
            .map(drop)
    }
}
fn values(list: &str) -> Value {
    json!([{"type":"integer","value":list}])
}
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
async fn introduce(left: &Peer, right: &Peer) -> Result<(), Failure> {
    let l = left.call(json!({"type":"contact"})).await?["uri"].clone();
    let r = right.call(json!({"type":"contact"})).await?["uri"].clone();
    left.call(json!({"type":"peer_add","contact":r})).await?;
    right.call(json!({"type":"peer_add","contact":l})).await?;
    Ok(())
}

/// Phone A issues; B is an enrolled writer; custody holds frames without keys.
struct Topology {
    _root: tempfile::TempDir,
    hub: Arc<Hub>,
    a: Peer,
    b: Peer,
    custody: Peer,
}
async fn topology() -> Result<Topology, Failure> {
    let root = tempfile::tempdir()?;
    let hub = Arc::new(Hub::default());
    let a = Peer::new(Database::create(open(&root.path().join("a"), &hub, "a"), None)?.database)?;
    let custody = Peer::new(
        Database::join(
            open(&root.path().join("custody"), &hub, "custody"),
            &a.invite(json!({"kind":"custody","scopes":TABLES})).await?,
        )?
        .database,
    )?;
    let b = Peer::new(
        Database::join(
            open(&root.path().join("b"), &hub, "b"),
            &a.invite(json!({"kind":"grants","grants":[
                {"scope":"lists","rights":["read"]},
                {"scope":"categories","rights":["read","insert","update","delete"]},
                {"scope":"items","rights":["read","insert","update","delete"]}
            ]}))
            .await?,
        )?
        .database,
    )?;
    introduce(&a, &custody).await?;
    introduce(&b, &custody).await?;
    Ok(Topology {
        _root: root,
        hub,
        a,
        b,
        custody,
    })
}
/// `from` publishes to custody while `to` is offline, then the reverse.
async fn relay(from: &Peer, to: &Peer) -> Result<(), Failure> {
    to.online(false).await?;
    from.online(true).await?;
    from.sync().await?;
    from.online(false).await?;
    to.online(true).await?;
    to.sync().await
}

#[tokio::test(flavor = "multi_thread")]
async fn two_phones_never_online_together_pass_the_release_gate_through_custody()
-> Result<(), Failure> {
    let Topology { a, b, custody, .. } = &topology().await?;
    let weekly = a.create_list("Weekly").await?;
    let weekend = a.create_list("Weekend").await?;
    let party = a.create_list("Party").await?;
    let dairy = a
        .insert(
            "categories",
            Some(&weekly),
            &format!("INSERT INTO categories(id,list,name) VALUES(?,{weekly},'Dairy')"),
        )
        .await?;
    let milk = a.add(&weekly, "Milk", Some(&dairy)).await?;
    a.add(&weekly, "Butter", Some(&dairy)).await?;
    a.add(&party, "Cake", None).await?;
    // One envelope per list; B receives all three while it only meets
    // custody, which holds them as a mailbox.
    for list in [&weekly, &weekend, &party] {
        a.share(list, b).await?;
    }
    relay(a, b).await?;
    assert_eq!(b.items().await?, a.items().await?);
    assert_eq!(b.items().await?.len(), 3);
    // Custody holds every list's frames but cannot read them.
    assert!(
        custody
            .rows("SELECT title FROM items")
            .await
            .map_or(true, |rows| rows.is_empty())
    );

    // Offline from each other: B ticks Milk and adds Bread; A adds Bread too
    // and moves Milk to the weekend without having seen the tick.
    b.execute(&format!(
        "UPDATE items SET completed = 1 WHERE list = {weekly} AND id = {milk}"
    ))
    .await?;
    b.add(&weekly, "Bread", None).await?;
    b.sync().await?;
    b.online(false).await?;
    a.add(&weekly, "Bread", None).await?;
    a.move_item(&weekly, &milk, &weekend).await?;
    relay(a, b).await?;
    relay(b, a).await?;
    let converged = vec![
        vec![json!(weekly), json!("Bread"), json!("0"), Value::Null],
        vec![json!(weekly), json!("Butter"), json!("0"), json!(dairy)],
        // The move wrote the values A read: B's tick changed the old row.
        vec![json!(weekend), json!("Milk"), json!("0"), Value::Null],
        vec![json!(party), json!("Cake"), json!("0"), Value::Null],
    ];
    assert_eq!(a.items().await?, converged);
    assert_eq!(b.items().await?, converged);

    // Deleting the category nulls only the reference; deleting a list cascades.
    a.online(true).await?;
    a.execute(&format!(
        "DELETE FROM categories WHERE list = {weekly} AND id = {dairy}"
    ))
    .await?;
    a.execute(&format!("DELETE FROM lists WHERE id = {party}"))
        .await?;
    relay(a, b).await?;
    let deleted = vec![
        vec![json!(weekly), json!("Bread"), json!("0"), Value::Null],
        vec![json!(weekly), json!("Butter"), json!("0"), Value::Null],
        vec![json!(weekend), json!("Milk"), json!("0"), Value::Null],
    ];
    assert_eq!(b.items().await?, deleted);
    assert_eq!(
        b.rows("SELECT title FROM lists ORDER BY title").await?,
        [[json!("Weekend")], [json!("Weekly")]]
    );

    b.add(&weekend, "Eggs", None).await?;
    relay(b, a).await?;
    assert_eq!(a.items().await?, b.items().await?);
    for peer in [a, b, custody] {
        peer.database.close().await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_joining_after_a_move_starts_the_list_from_a_checkpoint() -> Result<(), Failure> {
    let Topology {
        _root,
        hub,
        a,
        b,
        custody,
    } = topology().await?;
    let weekly = a.create_list("Weekly").await?;
    let weekend = a.create_list("Weekend").await?;
    let milk = a.add(&weekly, "Milk", None).await?;
    a.move_item(&weekly, &milk, &weekend).await?;
    // The weekly checkpoint no longer holds the moved row.
    let c = Peer::new(
        Database::join(
            open(&_root.path().join("c"), &hub, "c"),
            &a.invite(json!({"kind":"writer","scopes":TABLES})).await?,
        )?
        .database,
    )?;
    c.sync().await?;
    for list in [&weekly, &weekend] {
        a.share(list, &c).await?;
    }
    c.sync().await?;
    assert_eq!(c.items().await?, a.items().await?);
    assert_eq!(
        c.items().await?,
        [[json!(weekend), json!("Milk"), json!("0"), Value::Null]]
    );
    for peer in [a, b, c, custody] {
        peer.database.close().await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn custody_keeps_offered_partitions_across_restart() -> Result<(), Failure> {
    let Topology {
        _root,
        hub,
        a,
        b,
        custody,
    } = topology().await?;
    let list = a.create_list("Weekly").await?;
    a.share(&list, &b).await?;
    a.add(&list, "Milk", None).await?;
    b.online(false).await?;
    a.sync().await?;
    a.online(false).await?;
    // The custody peer registered the list from A's offer and persists it.
    custody.database.close().await?;
    let custody =
        Peer::new(Database::open(open(&_root.path().join("custody"), &hub, "custody"))?.database)?;
    b.online(true).await?;
    b.sync().await?;
    assert_eq!(
        b.items().await?,
        [[json!(list), json!("Milk"), json!("0"), Value::Null]]
    );
    for peer in [a, b, custody] {
        peer.database.close().await?;
    }
    Ok(())
}
