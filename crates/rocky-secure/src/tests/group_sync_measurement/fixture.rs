use super::*;

pub(crate) struct Fixture {
    pub(crate) publisher: PrivateKey,
    pub(crate) schema: rocky_core::LogicalSchema,
    pub(crate) domain: rocky_core::Scope,
    pub(crate) manifest: SignedManifest,
    pub(crate) revocations: RevocationSet,
}
impl Fixture {
    pub(crate) fn new(tables: usize) -> Self {
        let publisher = PrivateKey::new();
        let mut members = vec![
            serde_json::json!({"name":"customers","class":"replayed","columns":[{"name":"customer","type":"integer","not_null":true},{"name":"title","type":"text"}],"primary_key":["customer","id"],"partition_by":["customer"],"partition_group":"erp"}),
        ];
        for (name, parent) in [
            ("orders", "customers"),
            ("order_lines", "orders"),
            ("attachments", "order_lines"),
        ]
        .into_iter()
        .take(tables - 1)
        {
            members.push(serde_json::json!({"name":name,"class":"replayed","columns":[{"name":"customer","type":"integer","not_null":true},{"name":"parent","type":"integer","not_null":true},{"name":"title","type":"text"}],"primary_key":["customer","id"],"partition_by":["customer"],"partition_group":"erp","foreign_keys":[{"columns":["customer","parent"],"table":parent,"on_delete":"cascade"}]}));
        }
        members.push(serde_json::json!({"name":"products","class":"replayed","columns":[{"name":"title","type":"text"}],"primary_key":["id"]}));
        let definition = serde_json::json!({"format":6,"publisher":publisher.public_key().to_string(),"application":"erp-measurement","tables":members});
        let schema = SchemaDefinition::parse(&serde_json::to_vec(&definition).unwrap())
            .unwrap()
            .build()
            .unwrap();
        schema.installable().unwrap();
        let domain = rocky_core::Scope {
            mesh: MeshId([1; 16]),
            app: schema.app_id(),
            domain: DomainId([1; 16]),
        };
        let manifest = schema.manifest(&[domain.domain]);
        let revocations = RevocationSet::new();
        Self {
            manifest: SignedManifest::sign(&manifest, &publisher).unwrap(),
            publisher,
            schema,
            domain,
            revocations,
        }
    }
    pub(crate) fn app(&self) -> TypedRows {
        TypedRows::new(self.schema.clone(), vec![self.domain.domain]).unwrap()
    }
    pub(crate) fn tuple(&self, name: &str, partition: i64) -> PartitionTuple {
        let table = self.schema.table(name).unwrap();
        PartitionTuple::new([(
            self.schema
                .field_id(table, table.column(&table.partition_by[0]).unwrap()),
            PartitionValue::new(
                rocky_core::KeyColumn {
                    affinity: rocky_core::Affinity::Integer,
                    collation: rocky_core::Collation::Binary,
                },
                SqlValue::Integer(partition),
            )
            .unwrap(),
        )])
        .unwrap()
    }
    pub(crate) fn scope(&self, name: &str, partition: i64) -> ResourceScope {
        let table = self.schema.table(name).unwrap();
        if table.partition_by.is_empty() {
            return ResourceScope {
                domain: self.domain,
                table: self.schema.table_id(table),
                encryption: [9; 32],
            };
        }
        self.tuple(name, partition)
            .scope(
                self.domain,
                self.schema.table_id(self.schema.table(name).unwrap()),
            )
            .unwrap()
    }
    pub(crate) fn grants(
        &self,
        partitions: Option<&[i64]>,
        rights: &[Right],
    ) -> Vec<PartitionGrant> {
        self.schema
            .tables
            .iter()
            .filter(|table| !table.partition_by.is_empty())
            .map(|table| {
                let column = self
                    .schema
                    .field_id(table, table.column(&table.partition_by[0]).unwrap());
                PartitionGrant {
                    domain: self.domain,
                    table: self.schema.table_id(table),
                    selector: PartitionSelector(
                        [(
                            column,
                            partitions.map_or(PartitionSelection::Any, |values| {
                                PartitionSelection::Only(
                                    values
                                        .iter()
                                        .map(|value| {
                                            self.tuple(&table.sql_name, *value).values()[&column]
                                                .clone()
                                        })
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
            })
            .collect()
    }
    pub(crate) async fn open(
        &self,
        path: &Path,
        node: PrivateKey,
        grants: Vec<PartitionGrant>,
        signer: Option<(PrivateKey, u32)>,
        keys: Vec<KeyMaterial>,
    ) -> EncryptedReplica<TypedRows> {
        let user = PrivateKey::new();
        let time = now().unwrap();
        let raw: Vec<_> = self
            .schema
            .tables
            .iter()
            .filter(|table| table.partition_by.is_empty())
            .map(|table| {
                grant(
                    self.scope(&table.sql_name, 0),
                    &[Right::Read, Right::Insert, Right::Update, Right::Delete],
                    &table
                        .columns
                        .iter()
                        .map(|column| self.schema.field_id(table, column))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        let root = Authority::owner(&self.publisher)
            .issue_partition_terms(
                user.public_key(),
                raw.clone(),
                grants.clone(),
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
                keys,
            },
        )
        .await
        .unwrap();
        replica
            .install_tables(
                self.schema.clone(),
                self.domain,
                self.schema
                    .tables
                    .iter()
                    .map(|table| (table.sql_name.clone(), [9; 32]))
                    .collect(),
            )
            .await
            .unwrap();
        replica
    }

    pub(crate) async fn keys(
        &self,
        replica: &EncryptedReplica<TypedRows>,
        partition: i64,
        tables: &[&str],
    ) {
        for name in tables {
            replica
                .register_partition(self.scope(name, partition), self.tuple(name, partition))
                .await
                .unwrap();
            replica
                .install_key(self.key(name, partition))
                .await
                .unwrap();
        }
    }
    pub(crate) fn key(&self, name: &str, partition: i64) -> KeyMaterial {
        if name == "products" {
            return KeyMaterial::new(self.scope(name, 0), 1, [8; 32]);
        }
        KeyMaterial::new(
            self.scope(name, partition),
            1,
            rocky_credentials::derive_table_key(
                &[7; 32],
                self.domain,
                self.schema
                    .group_address(self.domain, name, &[SqlValue::Integer(partition)])
                    .unwrap()
                    .commitment,
                self.scope(name, partition).table,
                1,
            )
            .unwrap(),
        )
    }
    /// Inserts one row into each of `tables` in one SQL transaction; the
    /// rows of a partition reference the previous table's row.
    pub(crate) async fn insert(
        &self,
        replica: &EncryptedReplica<TypedRows>,
        partition: i64,
        tables: &[&str],
        handle: [u8; 32],
    ) -> Vec<EncryptedFrame> {
        let sql = replica
            .session(
                tables
                    .iter()
                    .map(|name| self.scope(name, partition))
                    .collect(),
            )
            .await
            .unwrap()
            .sql(Default::default())
            .await
            .unwrap();
        sql.run("BEGIN", vec![]).await.unwrap();
        let mut parent = None;
        for name in tables {
            let (statement, mut values) = if *name == "products" {
                let id = sql.next_id(name).await.unwrap();
                (
                    "INSERT INTO products(title,id) VALUES(?,?)".to_string(),
                    vec![
                        SqlValue::Text("Product".into()),
                        SqlValue::Integer(id.integer()),
                    ],
                )
            } else {
                let partition = SqlValue::Integer(partition);
                let id = sql
                    .next_id_partition(name, std::slice::from_ref(&partition))
                    .await
                    .unwrap()
                    .integer();
                let statement = match parent {
                    None => format!("INSERT INTO {name}(customer,title,id) VALUES(?,?,?)"),
                    Some(_) => {
                        format!("INSERT INTO {name}(customer,parent,title,id) VALUES(?,?,?,?)")
                    }
                };
                let mut values = vec![partition];
                values.extend(parent.map(SqlValue::Integer));
                values.push(SqlValue::Text((*name).into()));
                values.push(SqlValue::Integer(id));
                parent = Some(id);
                (statement, values)
            };
            sql.run(&statement, std::mem::take(&mut values))
                .await
                .unwrap();
        }
        sql.commit(handle).await.unwrap().committed.unwrap().frames
    }
}
