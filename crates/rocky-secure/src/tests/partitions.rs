use super::*;
use rocky_core::{
    DomainId, PartitionSelection, PartitionSelector, PartitionTuple, PartitionValue,
    SchemaDefinition, SqlValue, TypedRows,
};
use rocky_credentials::{AuthorRange, Authority, PartitionGrant};
use std::path::Path;

struct Fixture {
    publisher: PrivateKey,
    schema: rocky_core::LogicalSchema,
    domain: rocky_core::Scope,
    manifest: SignedManifest,
    revocations: RevocationSet,
}
impl Fixture {
    fn new() -> Self {
        Self::build(false)
    }
    fn constrained() -> Self {
        Self::build(true)
    }
    fn build(constrained: bool) -> Self {
        Self::build_with(constrained, PrivateKey::new())
    }
    fn build_with(constrained: bool, publisher: PrivateKey) -> Self {
        Self::build_class(constrained, publisher, "replayed")
    }
    fn build_class(constrained: bool, publisher: PrivateKey, class: &str) -> Self {
        let mut definition = serde_json::json!({"format":6,"publisher":publisher.public_key().as_bytes().iter().map(|byte|format!("{byte:02x}")).collect::<String>(),"application":"partition-test","tables":[{"name":"items","class":class,"columns":[{"name":"list","type":"text","not_null":true},{"name":"key","type":"text","not_null":true},{"name":"amount","type":"integer","not_null":true}],"primary_key":["list","key"],"partition_by":["list"]}]});
        if constrained {
            definition["tables"][0]["columns"].as_array_mut().unwrap().push(serde_json::json!({"name":"title","type":"text","not_null":true,"collation":"nocase"}));
            definition["tables"][0]["indexes"] = serde_json::json!([{"name":"items_title","columns":[{"name":"list","descending":false},{"name":"title","descending":false}],"unique":true}]);
        }
        let mut schema = SchemaDefinition::parse(&serde_json::to_vec(&definition).unwrap())
            .unwrap()
            .build()
            .unwrap();
        schema.views.push(rocky_core::LogicalView {
            name: "partial_items".into(),
            create_sql: "CREATE VIEW partial_items AS SELECT * FROM items WHERE amount>=0".into(),
        });
        schema.views.push(rocky_core::LogicalView {
            name: "nested_items".into(),
            create_sql: "CREATE VIEW nested_items AS SELECT * FROM partial_items".into(),
        });
        let manifest = schema.manifest(&[DomainId([1; 16])]);
        let domain = rocky_core::Scope {
            mesh: MeshId([1; 16]),
            app: schema.app_id(),
            domain: DomainId([1; 16]),
        };
        let revocations = RevocationSet::new();
        Self {
            manifest: SignedManifest::sign(&manifest, &publisher).unwrap(),
            publisher,
            schema,
            domain,
            revocations,
        }
    }
    fn app(&self) -> TypedRows {
        TypedRows::new(self.schema.clone(), vec![self.domain.domain]).unwrap()
    }
    fn tuple(&self, name: &str) -> PartitionTuple {
        let table = self.schema.table("items").unwrap();
        PartitionTuple::new([(
            self.schema.field_id(table, table.column("list").unwrap()),
            PartitionValue::new(
                rocky_core::KeyColumn {
                    affinity: rocky_core::Affinity::Text,
                    collation: rocky_core::Collation::Binary,
                },
                SqlValue::Text(name.into()),
            )
            .unwrap(),
        )])
        .unwrap()
    }
    fn scope(&self, name: &str) -> ResourceScope {
        self.tuple(name)
            .scope(
                self.domain,
                self.schema.table_id(self.schema.table("items").unwrap()),
            )
            .unwrap()
    }
    fn grant(&self, names: Option<&[&str]>, rights: &[Right]) -> PartitionGrant {
        let table = self.schema.table("items").unwrap();
        let column = self.schema.field_id(table, table.column("list").unwrap());
        PartitionGrant {
            domain: self.domain,
            table: self.schema.table_id(table),
            selector: PartitionSelector(
                [(
                    column,
                    names.map_or(PartitionSelection::Any, |names| {
                        PartitionSelection::Only(
                            names
                                .iter()
                                .map(|name| self.tuple(name).values()[&column].clone())
                                .collect(),
                        )
                    }),
                )]
                .into(),
            ),
            rows: RowSelection::All,
            rights: rights.iter().copied().collect(),
            fields: table
                .columns
                .iter()
                .map(|column| self.schema.field_id(table, column))
                .collect(),
        }
    }
    async fn open(
        &self,
        path: &Path,
        node: PrivateKey,
        grant: PartitionGrant,
        signer: Option<(PrivateKey, u32)>,
    ) -> EncryptedReplica<TypedRows> {
        let user = PrivateKey::new();
        let time = now().unwrap();
        let root = Authority::owner(&self.publisher)
            .issue_partition_terms(
                user.public_key(),
                vec![],
                vec![grant.clone()],
                (1, Some(AuthorRange::new(1, 1000).unwrap())),
                (time, 3600, 5),
            )
            .unwrap();
        let prefix = CredentialChain(vec![root]);
        let recorded = if path.exists() {
            let (owner, conn) = crate::database::DatabaseOwner::open(path).await.unwrap();
            let mut rows = conn
                .query(
                    "SELECT number FROM secure_node_authors WHERE node=?",
                    [node.public_key().as_bytes().to_vec()],
                )
                .await
                .unwrap();
            let number = rows
                .next()
                .await
                .unwrap()
                .map(|row| row.get::<i64>(0).unwrap() as u32);
            drop(rows);
            drop(conn);
            drop(owner);
            number
        } else {
            None
        };
        let credentials = prefix
            .clone()
            .complete(
                &user,
                node.public_key(),
                recorded.unwrap_or_else(|| signer.as_ref().map_or(999, |(_, number)| *number)),
            )
            .unwrap();
        let replica = EncryptedReplica::open(
            path,
            self.app(),
            SecureConfig {
                publisher: self.publisher.public_key(),
                manifest: self.manifest.clone(),
                revocations: self.revocations.clone(),
                node: node.clone(),
                credentials,
                keys: vec![],
            },
        )
        .await
        .unwrap();
        replica
            .install_tables(
                self.schema.clone(),
                self.domain,
                [("items".into(), [9; 32])].into(),
            )
            .await
            .unwrap();
        replica
    }
    async fn key(&self, replica: &EncryptedReplica<TypedRows>, name: &str, key: [u8; 32]) {
        replica
            .register_partition(self.scope(name), self.tuple(name))
            .await
            .unwrap();
        replica
            .install_key(KeyMaterial::new(self.scope(name), 1, key))
            .await
            .unwrap();
    }
}
mod admission;
mod replayed;

async fn sql_on(
    f: &Fixture,
    replica: &EncryptedReplica<TypedRows>,
    names: &[&str],
) -> crate::SecureSql<TypedRows> {
    replica
        .session(names.iter().map(|name| f.scope(name)).collect())
        .await
        .unwrap()
        .sql(Default::default())
        .await
        .unwrap()
}

/// Inserts `(list, key, amount)` rows in one transaction.
async fn insert(
    f: &Fixture,
    replica: &EncryptedReplica<TypedRows>,
    names: &[&str],
    rows: &[(&str, &str, i64)],
    handle: u8,
) -> Vec<EncryptedFrame> {
    let sql = sql_on(f, replica, names).await;
    sql.run("BEGIN", vec![]).await.unwrap();
    for (list, key, amount) in rows {
        let id = sql
            .next_id_partition("items", &[SqlValue::Text((*list).into())])
            .await
            .unwrap()
            .integer();
        sql.run(
            "INSERT INTO items(list,key,amount,id) VALUES(?,?,?,?)",
            vec![
                SqlValue::Text((*list).into()),
                SqlValue::Text((*key).into()),
                SqlValue::Integer(*amount),
                SqlValue::Integer(id),
            ],
        )
        .await
        .unwrap();
    }
    sql.commit([handle; 32])
        .await
        .unwrap()
        .committed
        .unwrap()
        .frames
}

fn all() -> Vec<Right> {
    vec![
        Right::Read,
        Right::Insert,
        Right::Update,
        Right::Delete,
        Right::Custody,
    ]
}

#[tokio::test]
async fn a_future_import_does_not_make_verified_empty_partition_history_missing() {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let replica = f
        .open(
            &root.path().join("writer.sqlite"),
            PrivateKey::new(),
            f.grant(None, &all()),
            Some((PrivateKey::new(), 1)),
        )
        .await;
    replica
        .set_role(crate::RoleConfig {
            role: crate::ReplicaRole::Full,
            full_nodes: Default::default(),
            custody: 0,
        })
        .await
        .unwrap();
    f.key(&replica, "A", [1; 32]).await;
    let frame = insert(&f, &replica, &["A"], &[("A", "one", 10)], 1)
        .await
        .remove(0);
    seal_main(&replica, &f.publisher, f.domain).await;
    replica.finalize_path(f.domain).await.unwrap();
    assert!(
        replica
            .compaction_status(f.domain)
            .await
            .unwrap()
            .finalized
            .is_some()
    );
    f.key(&replica, "B", [2; 32]).await;
    replica.set_importing([f.scope("B")].into()).await;
    assert!(
        replica
            .seal_rebootstraps(f.domain)
            .await
            .unwrap()
            .is_empty()
    );
    // The intent is named as an import, never as missing history.
    let blockers = replica.blockers().await.unwrap();
    super::blockers::assert_named(
        &blockers,
        &crate::scope_label(&f.scope("B")),
        |kind| *kind == crate::BlockerKind::Importing,
        crate::ClearsBy::AnyPeer,
    );
    assert!(
        blockers
            .iter()
            .all(|blocker| !matches!(blocker.kind, crate::BlockerKind::SealRebootstrap { .. })),
        "{blockers:?}"
    );
    let session = replica
        .session([f.scope("A"), f.scope("B")].into())
        .await
        .unwrap();
    let sql = session.sql(Default::default()).await.unwrap();
    assert_eq!(
        sql.run("SELECT count(*) FROM items", vec![])
            .await
            .unwrap()
            .rows[0][0],
        SqlValue::Integer(1)
    );
    let missing = f
        .open(
            &root.path().join("missing.sqlite"),
            PrivateKey::new(),
            f.grant(None, &all()),
            None,
        )
        .await;
    missing
        .set_role(crate::RoleConfig {
            role: crate::ReplicaRole::Full,
            full_nodes: Default::default(),
            custody: 0,
        })
        .await
        .unwrap();
    f.key(&missing, "A", [1; 32]).await;
    missing.receive(frame).await.unwrap();
    exchange_graphs(&replica, &missing, f.domain).await;
    missing.finalize_path(f.domain).await.unwrap();
    assert!(
        missing
            .compaction_status(f.domain)
            .await
            .unwrap()
            .finalized
            .is_some()
    );
    f.key(&replica, "C", [3; 32]).await;
    insert(&f, &replica, &["C"], &[("C", "two", 20)], 2).await;
    seal_main(&replica, &f.publisher, f.domain).await;
    exchange_graphs(&replica, &missing, f.domain).await;
    f.key(&missing, "B", [2; 32]).await;
    missing.set_importing([f.scope("B")].into()).await;
    assert!(
        missing
            .seal_rebootstraps(f.domain)
            .await
            .unwrap()
            .iter()
            .any(|need| need.scope == f.scope("B")),
        "missing author history cannot establish an empty partition"
    );
}

#[tokio::test]
async fn unrelated_partition_recovery_does_not_block_constant_queries() {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let replica = f
        .open(
            &root.path().join("waiting.sqlite"),
            PrivateKey::new(),
            f.grant(None, &all()),
            None,
        )
        .await;
    f.key(&replica, "A", [1; 32]).await;
    replica
        .set_role(crate::RoleConfig {
            role: crate::ReplicaRole::Full,
            full_nodes: Default::default(),
            custody: 0,
        })
        .await
        .unwrap();
    let session = replica.session([f.scope("A")].into()).await.unwrap();
    let sql = session.sql(Default::default()).await.unwrap();
    {
        let inner = replica.inner.lock(crate::replica::Class::Background).await;
        inner
            .conn
            .execute(
                "INSERT INTO secure_compaction_lost VALUES(?,?)",
                [crate::encode(&f.domain).unwrap(), vec![7; 32]],
            )
            .await
            .unwrap();
    }
    assert_eq!(
        sql.run("SELECT 42", vec![]).await.unwrap().rows[0][0],
        SqlValue::Integer(42)
    );
    for query in [
        "SELECT * FROM items",
        "SELECT * FROM nested_items",
    ] {
        assert!(sql.run(query, vec![]).await.is_err(), "{query}");
    }
}

#[tokio::test]
async fn partition_frames_keys_custody_sql_and_checkpoints_are_isolated() {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let author = PrivateKey::new();
    let a = f
        .open(
            &root.path().join("writer.sqlite"),
            PrivateKey::new(),
            f.grant(None, &all()),
            Some((author.clone(), 1)),
        )
        .await;
    f.key(&a, "A", [1; 32]).await;
    f.key(&a, "B", [2; 32]).await;
    let reader = f
        .open(
            &root.path().join("reader.sqlite"),
            PrivateKey::new(),
            f.grant(Some(&["A"]), &[Right::Read]),
            None,
        )
        .await;
    f.key(&reader, "A", [1; 32]).await;
    let custody = f
        .open(
            &root.path().join("custody.sqlite"),
            PrivateKey::new(),
            f.grant(Some(&["A"]), &[Right::Custody]),
            None,
        )
        .await;

    let fa = insert(&f, &a, &["A"], &[("A", "one", 10)], 1)
        .await
        .remove(0);
    let fb = insert(&f, &a, &["B"], &[("B", "two", 20)], 2)
        .await
        .remove(0);
    assert_eq!(
        fa.operation().unwrap().header.extensions.row_format,
        crate::wire::ROW_FORMAT
    );
    assert_eq!(
        reader.receive(fa.clone()).await.unwrap(),
        ReceiveStatus::Applied
    );
    assert!(reader.receive(fb.clone()).await.is_err());
    assert_eq!(
        custody.receive(fa.clone()).await.unwrap(),
        ReceiveStatus::Custody
    );
    assert!(custody.receive(fb.clone()).await.is_err());
    // A valid author signature cannot downgrade a partitioned table to a legacy frame.
    let legacy = {
        let mut operation = fa.operation().unwrap();
        operation.header.extensions.partition = None;
        operation.header.extensions.row_format = 2;
        operation.header.sign(&author);
        fa.with_header(operation.header.to_bytes())
    };
    assert!(legacy.operation().is_err());
    assert!(custody.receive(legacy).await.is_err());

    assert!(!reader.table_complete(f.scope("A").table).await.unwrap());
    assert!(a.table_complete(f.scope("A").table).await.unwrap());
    let sql = reader
        .session([f.scope("A")].into())
        .await
        .unwrap()
        .sql(crate::sql::SqlOptions::default())
        .await
        .unwrap();
    assert_eq!(
        sql.run(
            "SELECT SUM(amount) FROM items WHERE list=?",
            vec![SqlValue::Text("A".into())]
        )
        .await
        .unwrap()
        .rows[0][0],
        SqlValue::Integer(10)
    );
    assert!(
        sql.run(
            "SELECT * FROM items WHERE list=?",
            vec![SqlValue::Text("B".into())]
        )
        .await
        .is_err()
    );
    assert_eq!(
        sql.run("SELECT SUM(amount) FROM items", vec![])
            .await
            .unwrap()
            .rows[0][0],
        SqlValue::Integer(10)
    );
    assert_eq!(
        sql.run("SELECT SUM(amount) FROM nested_items", vec![])
            .await
            .unwrap()
            .rows[0][0],
        SqlValue::Integer(10)
    );
    let full = a
        .session([f.scope("A"), f.scope("B")].into())
        .await
        .unwrap()
        .sql(crate::sql::SqlOptions::default())
        .await
        .unwrap();
    assert_eq!(
        full.run("SELECT SUM(amount) FROM items", vec![])
            .await
            .unwrap()
            .rows[0][0],
        SqlValue::Integer(30)
    );
    let (peer, credentials) = {
        let inner = reader.inner.lock(crate::replica::Class::Background).await;
        (
            inner.config.node.public_key(),
            inner.config.credentials.clone(),
        )
    };
    assert!(
        a.range_page(
            peer,
            &credentials,
            &crate::ScopeFrontier {
                scope: f.scope("B"),
                logs: vec![],
            },
            None,
            65536
        )
        .await
        .is_err()
    );
    let permitted = a
        .range_page(
            peer,
            &credentials,
            &crate::ScopeFrontier {
                scope: f.scope("A"),
                logs: vec![],
            },
            None,
            65536,
        )
        .await
        .unwrap();
    assert_eq!(permitted.frames.len(), 1);
    let cp = compacted_base(&a, &f.publisher, f.scope("A")).await;
    custody
        .verify_checkpoint_at_for_test(&cp, now().unwrap())
        .await
        .unwrap();
    let legacy_checkpoint = {
        let inner = a.inner.lock(crate::replica::Class::Background).await;
        let mut legacy = cp.clone();
        legacy.statement.format = 3;
        legacy.statement.partition = None;
        let signature = inner.config.node.sign(
            &signing_bytes(
                "rocky.encrypted-checkpoint.v3",
                &(
                    &legacy.statement,
                    inner.config.node.public_key(),
                    &inner.config.credentials,
                ),
            )
            .unwrap(),
        );
        let mut value = serde_json::to_value(&legacy).unwrap();
        value["signature"] = serde_json::to_value(signature).unwrap();
        legacy = serde_json::from_value(value).unwrap();
        legacy
    };
    assert!(
        custody
            .verify_checkpoint_at_for_test(&legacy_checkpoint, now().unwrap())
            .await
            .is_err()
    );

    let restored = f
        .open(
            &root.path().join("restored.sqlite"),
            PrivateKey::new(),
            f.grant(None, &[Right::Read]),
            None,
        )
        .await;
    f.key(&restored, "A", [1; 32]).await;
    f.key(&restored, "B", [2; 32]).await;
    restored.receive(fb).await.unwrap();
    let (peer, credentials) = {
        let inner = restored.inner.lock(crate::replica::Class::Background).await;
        (
            inner.config.node.public_key(),
            inner.config.credentials.clone(),
        )
    };
    link_up(&a, &restored, f.scope("A").domain).await;
    restored.begin_rebootstrap(cp.clone()).await.unwrap();
    let mut after = None;
    loop {
        let page = a
            .checkpoint_page(
                peer,
                &credentials,
                f.scope("A"),
                cp.id().unwrap(),
                after,
                65536,
            )
            .await
            .unwrap();
        after = page.next;
        restored.stage_checkpoint_page(page).await.unwrap();
        if after.is_none() {
            break;
        }
    }
    restored.finish_rebootstrap(f.scope("A")).await.unwrap();
    let restored_sql = restored
        .session([f.scope("A"), f.scope("B")].into())
        .await
        .unwrap()
        .sql(Default::default())
        .await
        .unwrap();
    assert_eq!(
        restored_sql
            .run("SELECT SUM(amount) FROM items", vec![])
            .await
            .unwrap()
            .rows[0][0],
        SqlValue::Integer(30)
    );
    let (full_node, full_credentials) = {
        let inner = a.inner.lock(crate::replica::Class::Background).await;
        (
            inner.config.node.public_key(),
            inner.config.credentials.clone(),
        )
    };
    restored
        .set_role(crate::RoleConfig {
            role: crate::ReplicaRole::Partial,
            full_nodes: [rocky_credentials::PeerId::of(full_node)].into(),
            custody: 1,
        })
        .await
        .unwrap();
    restored.subscribe(f.scope("A")).await.unwrap();
    restored.subscribe(f.scope("B")).await.unwrap();
    restored
        .acknowledge_frontier(
            full_node,
            &full_credentials,
            &a.frontier(f.scope("A")).await.unwrap(),
        )
        .await
        .unwrap();
    restored.unsubscribe(f.scope("A")).await.unwrap();
    restored.evict(f.scope("A")).await.unwrap();
    assert!(!restored.table_complete(f.scope("A").table).await.unwrap());
    let remaining = restored
        .session([f.scope("B")].into())
        .await
        .unwrap()
        .sql(Default::default())
        .await
        .unwrap();
    assert_eq!(
        remaining
            .run("SELECT SUM(amount) FROM items", vec![])
            .await
            .unwrap()
            .rows[0][0],
        SqlValue::Integer(20)
    );
    assert!(
        remaining
            .run("SELECT * FROM items WHERE list='A'", vec![])
            .await
            .is_err()
    );
    assert_eq!(cp.statement.format, 17);
    assert_eq!(cp.statement.partition, Some(f.tuple("A")));
    reader.rebuild_projection(f.scope("A")).await.unwrap();
    assert_eq!(
        sql.run("SELECT count(*) FROM items", vec![])
            .await
            .unwrap()
            .rows[0][0],
        SqlValue::Integer(1)
    );
}

#[tokio::test]
async fn partitioned_sql_refuses_local_duplicates_and_keeps_other_partition_atomic() {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::constrained();
    let a = f
        .open(
            &root.path().join("a.sqlite"),
            PrivateKey::new(),
            f.grant(None, &all()),
            Some((PrivateKey::new(), 1)),
        )
        .await;
    for name in ["A", "B"] {
        f.key(&a, name, [if name == "A" { 1 } else { 2 }; 32]).await;
    }
    let sql = a
        .session([f.scope("A"), f.scope("B")].into())
        .await
        .unwrap()
        .sql(Default::default())
        .await
        .unwrap();
    sql.run("BEGIN", vec![]).await.unwrap();
    for name in ["A", "B"] {
        let id = sql
            .next_id_partition("items", &[SqlValue::Text(name.into())])
            .await
            .unwrap()
            .integer();
        sql.run(
            "INSERT INTO items(list,key,amount,title,id) VALUES(?, 'one',10,'milk',?)",
            vec![SqlValue::Text(name.into()), SqlValue::Integer(id)],
        )
        .await
        .unwrap();
    }
    sql.commit([1; 32]).await.unwrap();
    let b_rows = async || {
        sql.run("SELECT * FROM items WHERE list='B'", vec![])
            .await
            .unwrap()
            .rows
    };
    let before_b = b_rows().await;
    sql.run("BEGIN", vec![]).await.unwrap();
    let id = sql
        .next_id_partition("items", &[SqlValue::Text("A".into())])
        .await
        .unwrap()
        .integer();
    assert!(matches!(
        sql.run(
            "INSERT INTO items(list,key,amount,title,id) VALUES('A','two',10,'MILK',?)",
            vec![SqlValue::Integer(id)]
        )
        .await,
        Err(Error::Sql(crate::sql::SqlError::Statement {
            code: 2067,
            ..
        }))
    ));
    sql.run("ROLLBACK", vec![]).await.unwrap();
    assert_eq!(b_rows().await, before_b);
    sql.run("BEGIN", vec![]).await.unwrap();
    sql.run("UPDATE items SET title='bread' WHERE list='A'", vec![])
        .await
        .unwrap();
    sql.commit([2; 32]).await.unwrap();
    assert_eq!(b_rows().await, before_b);
}

#[tokio::test]
async fn an_unproved_partition_requires_custody_without_disclosing_its_header_or_tuple() {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let writer = f
        .open(
            &root.path().join("writer.sqlite"),
            PrivateKey::new(),
            f.grant(None, &all()),
            Some((PrivateKey::new(), 1)),
        )
        .await;
    let reader_key = PrivateKey::new();
    let reader = f
        .open(
            &root.path().join("reader.sqlite"),
            reader_key.clone(),
            f.grant(Some(&["A"]), &[Right::Read]),
            None,
        )
        .await;
    f.key(&writer, "A", [1; 32]).await;
    f.key(&writer, "secret-partition", [2; 32]).await;
    f.key(&reader, "A", [1; 32]).await;
    let visible = insert(&f, &writer, &["A"], &[("A", "one", 10)], 1)
        .await
        .remove(0);
    let hidden = insert(
        &f,
        &writer,
        &["secret-partition"],
        &[("secret-partition", "two", 20)],
        2,
    )
    .await
    .remove(0);
    assert_eq!(
        reader.receive(visible).await.unwrap(),
        ReceiveStatus::Applied
    );
    seal_main(&writer, &f.publisher, f.domain).await;
    exchange_graphs(&writer, &reader, f.domain).await;
    let requests = reader.wanted_placements().await.unwrap();
    let [request] = requests.as_slice() else {
        panic!("{requests:?}")
    };
    let operation = hidden.operation().unwrap();
    assert_eq!(request.author, operation.header.extensions.author.unwrap());
    assert_eq!(request.from, operation.header.extensions.author_sequence);
    assert_eq!(request.to, request.from);
    let credentials = reader
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .config
        .credentials
        .clone();
    let page = writer
        .placement_page(
            reader_key.public_key(),
            &credentials,
            &[f.scope("A")].into(),
            *request,
        )
        .await
        .unwrap();
    // This variant carries neither signed headers nor credential chains or tuples.
    assert!(matches!(page, crate::PlacementPage::CustodyRequired));
    assert_eq!(reader.receive_placements(*request, page).await.unwrap(), 0);
    let inner = reader.inner.lock(crate::replica::Class::Background).await;
    assert!(
        crate::storage::rows(&inner.conn, "SELECT 1 FROM secure_placements")
            .await
            .unwrap()
            .is_empty()
    );
    let tuples = crate::storage::rows(&inner.conn, "SELECT tuple FROM secure_partitions")
        .await
        .unwrap();
    assert_eq!(tuples.len(), 1);
    assert_eq!(
        tuples[0],
        vec![SqlValue::Blob(encode(&f.tuple("A")).unwrap())]
    );
}

#[tokio::test]
async fn reads_across_held_partitions_agree_inside_and_after_transactions() {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let writer = f
        .open(
            &root.path().join("writer.sqlite"),
            PrivateKey::new(),
            f.grant(None, &all()),
            Some((PrivateKey::new(), 1)),
        )
        .await;
    let names: Vec<String> = (1..=64).map(|index| format!("p{index:02}")).collect();
    for (index, name) in names.iter().enumerate() {
        f.key(&writer, name, [index as u8 + 1; 32]).await;
    }
    let scopes: Vec<_> = names.iter().map(String::as_str).collect();
    for (handle, key) in [(1, "one"), (2, "two")] {
        let rows: Vec<_> = scopes.iter().map(|name| (*name, key, 1)).collect();
        insert(&f, &writer, &scopes, &rows, handle).await;
    }

    let sql = writer
        .session(names.iter().map(|name| f.scope(name)).collect())
        .await
        .unwrap()
        .sql(crate::sql::SqlOptions::default())
        .await
        .unwrap();
    let count = "SELECT count(*) FROM items";
    sql.run("BEGIN", vec![]).await.unwrap();
    for _ in 0..4 {
        assert_eq!(
            sql.run(count, vec![]).await.unwrap().rows,
            vec![vec![SqlValue::Integer(128)]]
        );
    }
    sql.run("ROLLBACK", vec![]).await.unwrap();
    for name in &names {
        assert_eq!(
            sql.run(
                "SELECT count(*) FROM items WHERE list=?",
                vec![SqlValue::Text(name.clone())]
            )
            .await
            .unwrap()
            .rows,
            vec![vec![SqlValue::Integer(2)]]
        );
    }
}
