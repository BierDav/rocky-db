//! Deleting a business key stays within its concrete partition after an additive switch.
use super::*;
use crate::sql::SqlOptions;
use rocky_core::{Affinity, Collation, ColumnClass, LogicalColumn, RowApplication};

async fn insert(
    replica: &EncryptedReplica<TypedRows>,
    f: &Fixture,
    partition: &str,
    title: &str,
    handle: u8,
) -> Vec<EncryptedFrame> {
    let sql = replica
        .session([f.scope("A"), f.scope("B")].into())
        .await
        .unwrap()
        .sql(SqlOptions::default())
        .await
        .unwrap();
    sql.run("BEGIN", vec![]).await.unwrap();
    let id = sql
        .next_id_partition("items", &[SqlValue::Text(partition.into())])
        .await
        .unwrap();
    sql.run(
        "INSERT INTO items(list,key,amount,title,id) VALUES(?,'shared',1,?,?)",
        vec![
            SqlValue::Text(partition.into()),
            SqlValue::Text(title.into()),
            SqlValue::Integer(id.integer()),
        ],
    )
    .await
    .unwrap();
    sql.commit([handle; 32])
        .await
        .unwrap()
        .committed
        .unwrap()
        .frames
}

async fn b_rows(replica: &EncryptedReplica<TypedRows>, f: &Fixture) -> Vec<Vec<SqlValue>> {
    replica
        .session([f.scope("A"), f.scope("B")].into())
        .await
        .unwrap()
        .sql(SqlOptions::default())
        .await
        .unwrap()
        .run(
            "SELECT list,key,title,id,rank FROM items WHERE list='B'",
            vec![],
        )
        .await
        .unwrap()
        .rows
}

#[tokio::test]
async fn an_additive_sql_delete_covers_both_live_ids_and_preserves_the_other_partition() {
    let dir = TempDir::new().unwrap();
    let f = Fixture::build_with(true, PrivateKey::from_bytes(&[210; 32]));
    let mut schema = f.schema.clone();
    let table = &mut schema.tables[0];
    table.columns.push(LogicalColumn {
        sql_name: "rank".into(),
        affinity: Affinity::Integer,
        not_null: false,
        default: None,
        collation: Collation::Binary,
        class: ColumnClass::Replicated,
    });
    table.create_sql = table
        .create_sql
        .replace(", PRIMARY KEY", ", \"rank\" INTEGER, PRIMARY KEY");
    // The authors may write the column the switch adds, so their earlier
    // transactions replay under the new schema too.
    let mut grant = f.grant(None, &all());
    grant.fields = rocky_core::FieldSelection::All;
    let a = keyed(&f, &dir.path().join("a"), [211; 32], 1, grant.clone()).await;
    let b = keyed(&f, &dir.path().join("b"), [212; 32], 2, grant).await;
    insert(&a, &f, "A", "first", 149).await;
    insert(&a, &f, "B", "unrelated partition", 150).await;
    let concurrent = insert(&b, &f, "A", "second", 151).await;
    for frame in concurrent {
        a.receive(frame).await.unwrap();
    }
    for frame in stored_frames(
        &a,
        "SELECT header,body FROM secure_operations ORDER BY author,sequence",
    )
    .await
    {
        b.receive(frame).await.unwrap();
    }
    let app = TypedRows::new(schema.clone(), vec![f.domain.domain])
        .unwrap()
        .at_generation(2)
        .unwrap();
    let source = a.followed_tip().await;
    let seal = SignedSeal::sign(
        SealStatement {
            format: SEAL_FORMAT,
            scope: f.domain,
            tip: source,
            frontier: a.seal_frontier(f.domain, false).await.unwrap(),
            action: SealAction::Continue {
                schema: app.manifest().hash(),
            },
            recovery: None,
        },
        &f.publisher,
    )
    .unwrap();
    let target = seal.successor().unwrap().unwrap();
    let statements = [
        bookmark(&f, "main", None, source),
        TipStatement::Seal(seal),
        bookmark(&f, "main", Some(source), target),
    ];
    for replica in [&a, &b] {
        replica.receive_tip_statements(&statements).await.unwrap();
        replica.follow_bookmark(f.domain, "main").await.unwrap();
        replica
            .install_tip_schema(target, app.manifest(), b"verified additive".to_vec())
            .await
            .unwrap();
        replica
            .switch_schema(
                target,
                app.clone(),
                crate::SchemaConfig {
                    security: security(&f, replica).await,
                    tables: Some((schema.clone(), f.domain, [("items".into(), [9; 32])].into())),
                },
            )
            .await
            .unwrap();
    }
    let before_b = b_rows(&a, &f).await;
    assert_eq!(before_b.len(), 1);
    let sql = a
        .session([f.scope("A"), f.scope("B")].into())
        .await
        .unwrap()
        .sql(SqlOptions::default())
        .await
        .unwrap();
    let deletion = sql
        .run("DELETE FROM items WHERE list='A' AND key='shared'", vec![])
        .await
        .unwrap()
        .committed
        .unwrap()
        .frames;
    // One intent frame, of partition A only, deletes both live ids.
    let [frame] = deletion.as_slice() else {
        panic!("{deletion:?}")
    };
    assert_eq!(frame.scope().unwrap(), f.scope("A"));
    for frame in deletion {
        b.receive(frame).await.unwrap();
    }
    for replica in [&a, &b] {
        assert_eq!(b_rows(replica, &f).await, before_b);
        assert_eq!(items(&f, replica).await.len(), 1);
        replica.rebuild_projection(f.scope("A")).await.unwrap();
        replica
            .audit_scopes(&[f.scope("A"), f.scope("B")])
            .await
            .unwrap();
    }
    let config = security(&f, &a).await;
    drop(sql);
    drop(a);
    let a = EncryptedReplica::open(dir.path().join("a"), app, config)
        .await
        .unwrap();
    assert_eq!(b_rows(&a, &f).await, before_b);
    assert_eq!(items(&f, &a).await.len(), 1);
    a.audit_scopes(&[f.scope("A"), f.scope("B")]).await.unwrap();
}
