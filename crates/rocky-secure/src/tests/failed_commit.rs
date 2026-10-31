//! A SQL commit that fails after sealing leaves nothing behind.
use super::compaction::{Replica, follow_main, open};
use super::generations::{Lineage, select, session, text};
use super::*;
use rocky_core::SqlValue;

async fn begin_two(sql: &crate::SecureSql<rocky_core::TypedRows>) -> Vec<i64> {
    sql.run("BEGIN", vec![]).await.unwrap();
    let mut identities = Vec::new();
    for name in ["one", "two"] {
        let id = sql.next_id("items").await.unwrap();
        identities.push(id.integer());
        sql.run(
            "INSERT INTO items(key,title,id) VALUES(?,?,?)",
            vec![text(name), text(name), SqlValue::Integer(id.integer())],
        )
        .await
        .unwrap();
    }
    identities
}
async fn snapshot(replica: &Replica) -> Vec<(String, Vec<Vec<SqlValue>>)> {
    super::compaction::audit::snapshot(replica).await
}

#[tokio::test]
async fn a_failed_sql_commit_changes_nothing_and_the_same_handle_retries_once() {
    let lineage = Lineage::pinned(199);
    let dir = TempDir::new().unwrap();
    let node = PrivateKey::from_bytes(&[200; 32]);
    let replica = open(&lineage, &dir, "author", &node).await;
    follow_main(&lineage, &replica).await;
    let before = snapshot(&replica).await;
    let revision = replica.stored_and_memory_revision().await;
    let context = replica.schema_context().await;
    let observer = replica.observe_revision();
    let mut tables = replica.observe_tables(Some(&["items"])).await.unwrap();
    replica.fail_next_sql_commit().await;
    let sql = session(&replica).await;
    let ids = begin_two(&sql).await;
    assert!(matches!(
        sql.commit([201; 32]).await,
        Err(Error::InjectedFailure)
    ));
    assert_eq!(snapshot(&replica).await, before);
    assert_eq!(replica.stored_and_memory_revision().await, revision);
    assert_eq!(replica.schema_context().await, context);
    assert!(!observer.has_changed().unwrap());
    assert_eq!(tables.try_next().unwrap(), None);
    assert_eq!(begin_two(&sql).await, ids);
    let committed = sql.commit([201; 32]).await.unwrap().committed.unwrap();
    assert_eq!(committed.handle, [201; 32]);
    assert_eq!(committed.frames.len(), 1);
    assert!(observer.has_changed().unwrap());
    assert!(tables.try_next().unwrap().is_some());
    let rows = vec![
        vec![SqlValue::Integer(ids[0]), text("one")],
        vec![SqlValue::Integer(ids[1]), text("two")],
    ];
    assert_eq!(
        select(&replica, "SELECT id,title FROM items ORDER BY key").await,
        rows
    );
    replica.audit(lineage.scope("items")).await.unwrap();
    drop(sql);
    drop(replica);
    let reopened = lineage
        .reopen(&dir.path().join("author.db"), &node, 3, 3)
        .await
        .unwrap();
    assert_eq!(
        select(&reopened, "SELECT id,title FROM items ORDER BY key").await,
        rows
    );
    reopened.audit(lineage.scope("items")).await.unwrap();
}
