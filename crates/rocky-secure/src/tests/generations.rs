//! Schema fixtures and local projection plans. Replicated changes use seals.
use super::*;
use crate::sql::SqlOptions;
use crate::storage::rows;
use rocky_core::{
    Affinity, Collation, ColumnClass, DomainId, Generation, IndexColumn, LOGICAL_SCHEMA_FORMAT,
    LogicalColumn, LogicalIndex, LogicalSchema, LogicalTable, RowApplication, SchemaSource, Scope,
    SqlValue, TableClass, TypedRows,
};
use std::collections::BTreeMap;

const DOMAIN: DomainId = DomainId([1; 16]);

fn column(name: &str, affinity: Affinity, not_null: bool) -> LogicalColumn {
    LogicalColumn {
        sql_name: name.into(),
        affinity,
        not_null,
        default: None,
        collation: Collation::Binary,
        class: ColumnClass::Replicated,
    }
}
fn table(name: &str, mut columns: Vec<LogicalColumn>) -> LogicalTable {
    columns.push(column("id", Affinity::Integer, true));
    let sql: Vec<String> = columns
        .iter()
        .map(|column| {
            let kind = if column.affinity == Affinity::Integer {
                "INTEGER"
            } else {
                "TEXT"
            };
            let null = if column.not_null { " NOT NULL" } else { "" };
            let key = if column.sql_name == "key" {
                " PRIMARY KEY"
            } else {
                ""
            };
            format!(
                "{} {kind}{null}{key}{}",
                column.sql_name,
                column
                    .default
                    .as_ref()
                    .map(|value| format!(" DEFAULT {value}"))
                    .unwrap_or_default()
            )
        })
        .collect();
    LogicalTable {
        sql_name: name.into(),
        granted_like: None,
        class: TableClass::Replayed,
        create_sql: format!("CREATE TABLE {name}({})", sql.join(",")),
        auto_generate: false,
        columns,
        primary_key: vec!["key".into()],
        partition_by: Vec::new(),
        partition_group: None,
        indexes: vec![LogicalIndex {
            name: format!("{name}_identity"),
            unique: true,
            columns: vec![IndexColumn {
                name: "id".into(),
                descending: false,
            }],
            create_sql: format!("CREATE UNIQUE INDEX {name}_identity ON {name}(id)"),
            expressions: Vec::new(),
            predicate: None,
        }],
        foreign_keys: Vec::new(),
    }
}
pub(super) fn text(value: &str) -> SqlValue {
    SqlValue::Text(value.into())
}

/// Generation 1 has `items(id,title)`; 2 adds a nullable `note` and a
/// `tags` table; 3 adds a nullable `rank`; 4 removes `note` and `tags`;
/// 5 adds `note` again.
pub(super) struct Lineage {
    publisher: PrivateKey,
    pub(super) domain: Scope,
    /// `tags` is partitioned by `label`.
    pub(super) partitioned: bool,
}
impl Lineage {
    /// The domain root a replica's tip graph starts from.
    pub(super) async fn root(&self, replica: &EncryptedReplica<TypedRows>) -> Result<u32, Error> {
        let root = replica.tip_graph(self.domain).await?.genesis_schema;
        (1..=5)
            .find(|version| self.definition(*version).hash() == root)
            .ok_or_else(|| Error::Incompatible("fixture root".into()))
    }
    /// Has the owner seal `replica`'s followed tip with `continue` to
    /// `version`'s schema and move `main` on, creating and following `main`
    /// first. Returns the graph statements peers receive.
    pub(super) async fn publish(
        &self,
        replica: &EncryptedReplica<TypedRows>,
        version: u32,
    ) -> Result<Vec<crate::TipStatement>, Error> {
        if replica.followed_bookmark().await.is_none() {
            super::compaction::follow_main(self, replica).await;
        }
        let source = replica.followed_tip().await;
        let seal = rocky_credentials::SignedSeal::sign(
            rocky_credentials::SealStatement {
                format: rocky_credentials::SEAL_FORMAT,
                scope: self.domain,
                tip: source,
                frontier: replica.seal_frontier(self.domain, false).await?,
                action: rocky_credentials::SealAction::Continue {
                    schema: self.definition(version).hash(),
                },
                recovery: None,
            },
            self.publisher(),
        )
        .map_err(credential)?;
        let target = seal
            .successor()
            .map_err(credential)?
            .ok_or_else(|| denied("fixture continuation"))?;
        replica
            .receive_tip_statements(&[
                crate::TipStatement::Seal(seal),
                super::compaction::bookmark(self, Some(source), target),
            ])
            .await?;
        Ok(crate::tests::all_tip_statements(replica).await)
    }
    /// Admits `statements`, follows `main` and switches to the schema of
    /// `version` its target has, with `config` under the domain root.
    pub(super) async fn follow(
        &self,
        replica: &EncryptedReplica<TypedRows>,
        mut config: SecureConfig,
        version: u32,
        statements: &[crate::TipStatement],
    ) -> Result<bool, Error> {
        replica.receive_tip_statements(statements).await?;
        if replica.followed_bookmark().await.is_none() {
            replica.follow_bookmark(self.domain, "main").await?;
        }
        config.manifest = self.manifest(self.root(replica).await?);
        let target = replica
            .tip_graph(self.domain)
            .await?
            .bookmark("main")
            .map_err(credential)?
            .ok_or_else(|| denied("fixture bookmark"))?;
        self.install_required(replica).await;
        replica
            .switch_schema(
                target,
                self.app(version),
                crate::SchemaConfig {
                    security: config,
                    tables: Some(self.projection(version)),
                },
            )
            .await
    }
    /// Installs every schema the replica requires that the fixture knows:
    /// those between the oldest retained tip and the target.
    pub(super) async fn install_required(&self, replica: &EncryptedReplica<TypedRows>) {
        for (tip, manifest) in replica.required_schemas().await.unwrap() {
            if let Some(known) = (1..=5).find(|known| self.definition(*known).hash() == manifest)
                && replica.tip_schema(manifest).await.unwrap().is_none()
            {
                replica
                    .install_tip_schema(
                        tip,
                        self.definition(known),
                        b"checked native test schema".to_vec(),
                    )
                    .await
                    .unwrap();
            }
        }
    }
    /// [`Self::publish`] and [`Self::follow`] on one replica.
    pub(super) async fn advance(
        &self,
        replica: &EncryptedReplica<TypedRows>,
        config: SecureConfig,
        version: u32,
    ) -> Result<bool, Error> {
        let statements = self.publish(replica, version).await?;
        self.follow(replica, config, version, &statements).await
    }
    /// Reopens a replica whose domain root is `root` at `version`'s schema.
    pub(super) async fn reopen(
        &self,
        path: &std::path::Path,
        node: &PrivateKey,
        root: u32,
        version: u32,
    ) -> Result<EncryptedReplica<TypedRows>, Error> {
        let mut config = self.config(version, node);
        config.manifest = self.manifest(root);
        EncryptedReplica::open(path, self.app(version), config).await
    }
    /// The publisher key, which also owns the domain.
    pub(super) fn publisher(&self) -> &PrivateKey {
        &self.publisher
    }
    pub(super) fn new() -> Self {
        Self::with_publisher(PrivateKey::new())
    }
    pub(super) fn pinned(seed: u8) -> Self {
        Self::with_publisher(PrivateKey::from_bytes(&[seed; 32]))
    }
    fn with_publisher(publisher: PrivateKey) -> Self {
        let domain = Scope {
            mesh: MeshId([1; 16]),
            app: rocky_core::ApplicationManifest::app_id(
                *publisher.public_key().as_bytes(),
                "lineage",
            ),
            domain: DOMAIN,
        };
        Self {
            publisher,
            domain,
            partitioned: false,
        }
    }
    fn schema(&self, generation: u32) -> LogicalSchema {
        let mut items = vec![
            column("key", Affinity::Text, true),
            column("title", Affinity::Text, true),
        ];
        if matches!(generation, 2 | 3 | 5) {
            items.push(column("note", Affinity::Text, false));
        }
        if generation >= 3 {
            items.push(column("rank", Affinity::Integer, false));
        }
        let mut tables = vec![table("items", items)];
        if matches!(generation, 2 | 3) {
            tables.push(table(
                "tags",
                vec![
                    column("key", Affinity::Text, true),
                    column("label", Affinity::Text, true),
                ],
            ));
        }
        for tags in tables
            .iter_mut()
            .filter(|table| self.partitioned && table.sql_name == "tags")
        {
            tags.partition_by = vec!["label".into()];
            tags.primary_key = vec!["label".into(), "key".into()];
            tags.create_sql = tags
                .create_sql
                .replace(" PRIMARY KEY", "")
                .replace("DEFAULT 0)", "DEFAULT 0,PRIMARY KEY(label,key))");
            tags.indexes[0].columns.insert(
                0,
                IndexColumn {
                    name: "label".into(),
                    descending: false,
                },
            );
            tags.indexes[0].create_sql =
                "CREATE UNIQUE INDEX tags_identity ON tags(label,id)".into();
        }
        LogicalSchema {
            format: LOGICAL_SCHEMA_FORMAT,
            publisher: *self.publisher.public_key().as_bytes(),
            application: "lineage".into(),
            source: SchemaSource {
                kind: "test".into(),
                version: generation,
                identity: "lineage".into(),
            },
            tables,
            views: Vec::new(),
            assertions: Vec::new(),
        }
    }
    /// Generation 1 with a local `drafts` table indexed on `body`: a local
    /// change.
    fn indexed(&self) -> LogicalSchema {
        let mut schema = self.schema(1);
        let mut drafts = table(
            "drafts",
            vec![
                column("key", Affinity::Text, true),
                column("body", Affinity::Text, false),
            ],
        );
        drafts.class = TableClass::LocalOnly;
        drafts.indexes.push(LogicalIndex {
            name: "drafts_body".into(),
            unique: false,
            columns: vec![IndexColumn {
                name: "body".into(),
                descending: false,
            }],
            create_sql: "CREATE INDEX drafts_body ON drafts(body)".into(),
            expressions: Vec::new(),
            predicate: None,
        });
        schema.tables.insert(0, drafts);
        schema
    }
    pub(super) fn app(&self, generation: u32) -> TypedRows {
        TypedRows::new(self.schema(generation), vec![DOMAIN])
            .unwrap()
            .at_generation(generation)
            .unwrap()
    }
    pub(super) fn definition(&self, generation: u32) -> rocky_core::ApplicationManifest {
        self.app(generation).manifest()
    }
    fn manifest(&self, generation: u32) -> SignedManifest {
        SignedManifest::sign(&self.definition(generation), &self.publisher).unwrap()
    }
    pub(super) fn scope(&self, name: &str) -> ResourceScope {
        let schema = self.schema(3);
        ResourceScope {
            domain: self.domain,
            encryption: rocky_core::commitment("lineage.readers", name.as_bytes()),
            table: schema.table_id(schema.table(name).unwrap()),
        }
    }
    /// The scope of the `tags` partition `label`.
    pub(super) fn tag_partition(&self, label: &str) -> (ResourceScope, rocky_core::PartitionTuple) {
        let schema = self.schema(3);
        let tags = schema.table("tags").unwrap();
        let tuple = rocky_core::PartitionTuple::new([(
            schema.field_id(tags, tags.column("label").unwrap()),
            rocky_core::PartitionValue::new(
                rocky_core::KeyColumn {
                    affinity: Affinity::Text,
                    collation: Collation::Binary,
                },
                text(label),
            )
            .unwrap(),
        )])
        .unwrap();
        (
            tuple.scope(self.domain, schema.table_id(tags)).unwrap(),
            tuple,
        )
    }
    fn readers(&self, generation: u32) -> BTreeMap<String, Commitment> {
        self.schema(generation)
            .tables
            .iter()
            .map(|table| {
                (
                    table.sql_name.clone(),
                    self.scope(&table.sql_name).encryption,
                )
            })
            .collect()
    }
    /// The grants of `generation`, only for `tables` when named.
    fn grants_of(&self, generation: u32, tables: Option<&[&str]>) -> Vec<ResourceGrant> {
        let schema = self.schema(generation);
        schema
            .tables
            .iter()
            .filter(|table| tables.is_none_or(|tables| tables.contains(&table.sql_name.as_str())))
            .filter(|table| table.partition_by.is_empty())
            .map(|table| {
                let fields: Vec<_> = table
                    .columns
                    .iter()
                    .map(|column| schema.field_id(table, column))
                    .collect();
                grant(
                    self.scope(&table.sql_name),
                    &[
                        Right::Read,
                        Right::Insert,
                        Right::Update,
                        Right::Delete,
                        Right::Custody,
                    ],
                    &fields,
                )
            })
            .collect()
    }
    /// Every partition of each partitioned table of `generation`.
    fn partition_grants_of(&self, generation: u32) -> Vec<rocky_credentials::PartitionGrant> {
        let schema = self.schema(generation);
        schema
            .tables
            .iter()
            .filter_map(|table| {
                let column = table.column(table.partition_by.first()?)?;
                Some(rocky_credentials::PartitionGrant {
                    domain: self.domain,
                    table: schema.table_id(table),
                    selector: rocky_core::PartitionSelector(
                        [(
                            schema.field_id(table, column),
                            rocky_core::PartitionSelection::Any,
                        )]
                        .into(),
                    ),
                    rows: RowSelection::All,
                    rights: [
                        Right::Read,
                        Right::Insert,
                        Right::Update,
                        Right::Delete,
                        Right::Custody,
                    ]
                    .into(),
                    fields: table
                        .columns
                        .iter()
                        .map(|column| schema.field_id(table, column))
                        .collect(),
                })
            })
            .collect()
    }
    /// A chain under one user per node, so every generation keeps its principal.
    pub(super) fn credentials(&self, generation: u32, node: &PrivateKey) -> CredentialChain {
        let user = rocky_core::commitment("lineage.user", node.public_key().as_bytes());
        self.certified(generation, &PrivateKey::from_bytes(&user), node)
    }
    /// `credentials` of a node `user`'s identity certified.
    pub(super) fn certified(
        &self,
        generation: u32,
        user: &PrivateKey,
        node: &PrivateKey,
    ) -> CredentialChain {
        self.certified_as(generation, user, node, None)
    }
    /// `certified` under an owner-direct trusted grant for the domain.
    pub(super) fn trusted(
        &self,
        generation: u32,
        user: &PrivateKey,
        node: &PrivateKey,
    ) -> CredentialChain {
        self.certified_as(generation, user, node, Some(self.domain))
    }
    fn certified_as(
        &self,
        generation: u32,
        user: &PrivateKey,
        node: &PrivateKey,
        trusted: Option<rocky_core::Scope>,
    ) -> CredentialChain {
        self.certified_for(generation, user, node, trusted, None)
    }
    /// `certified_as`, granting only `tables` when named.
    fn certified_for(
        &self,
        generation: u32,
        user: &PrivateKey,
        node: &PrivateKey,
        trusted: Option<rocky_core::Scope>,
        tables: Option<&[&str]>,
    ) -> CredentialChain {
        let (not_before, expires) = crate::tests::lifetime();
        let capability = |subject, kind, delegations| Capability {
            subject,
            kind,
            grants: self.grants_of(generation, tables),
            not_before,
            expires,
            delegations,
            extension: rocky_credentials::Extension::new(rocky_credentials::Extended {
                authors: Some(if kind == PrincipalKind::Node {
                    rocky_credentials::AuthorRange::new(
                        crate::tests::node_number(subject),
                        crate::tests::node_number(subject),
                    )
                    .unwrap()
                } else {
                    rocky_credentials::AuthorRange::ALL
                }),
                node: (kind == PrincipalKind::Node).then(|| rocky_credentials::PeerId::of(subject)),
                partitions: self.partition_grants_of(generation),
                trusted: trusted.filter(|_| kind == PrincipalKind::User),
                ..Default::default()
            })
            .unwrap(),
        };
        CredentialChain(vec![
            SignedCapability::sign(
                capability(user.public_key(), PrincipalKind::User, 1),
                &self.publisher,
            )
            .unwrap(),
            SignedCapability::sign(capability(node.public_key(), PrincipalKind::Node, 0), user)
                .unwrap(),
        ])
    }
    pub(super) fn config(&self, generation: u32, node: &PrivateKey) -> SecureConfig {
        let keys = ["items", "tags"]
            .iter()
            .take(if matches!(generation, 2 | 3) && !self.partitioned {
                2
            } else {
                1
            })
            .enumerate()
            .map(|(index, name)| KeyMaterial::new(self.scope(name), 1, [40 + index as u8; 32]))
            .collect();
        SecureConfig {
            publisher: self.publisher.public_key(),
            manifest: self.manifest(generation),
            revocations: RevocationSet::new(),
            node: node.clone(),
            credentials: self.credentials(generation, node),
            keys,
        }
    }
    pub(super) fn projection(
        &self,
        generation: u32,
    ) -> (LogicalSchema, Scope, BTreeMap<String, Commitment>) {
        (
            self.schema(generation),
            self.domain,
            self.readers(generation),
        )
    }
    pub(super) async fn open(
        &self,
        path: &std::path::Path,
        node: &PrivateKey,
        generation: u32,
        upgrade: Option<(LogicalSchema, Scope, BTreeMap<String, Commitment>)>,
    ) -> Result<EncryptedReplica<TypedRows>, Error> {
        self.open_with(path, self.config(generation, node), generation, upgrade)
            .await
    }
    /// `open` for a node `identity` certified, which enrolls line nodes.
    pub(super) async fn open_certified(
        &self,
        path: &std::path::Path,
        (identity, node): (&PrivateKey, &PrivateKey),
        generation: u32,
        upgrade: Option<(LogicalSchema, Scope, BTreeMap<String, Commitment>)>,
    ) -> Result<EncryptedReplica<TypedRows>, Error> {
        let mut config = self.config(generation, node);
        config.credentials = self.certified(generation, identity, node);
        self.open_with(path, config, generation, upgrade).await
    }
    /// `open_certified` as a node of a trusted identity.
    pub(super) async fn open_trusted(
        &self,
        path: &std::path::Path,
        (identity, node): (&PrivateKey, &PrivateKey),
        generation: u32,
        upgrade: Option<(LogicalSchema, Scope, BTreeMap<String, Commitment>)>,
    ) -> Result<EncryptedReplica<TypedRows>, Error> {
        let mut config = self.config(generation, node);
        config.credentials = self.trusted(generation, identity, node);
        self.open_with(path, config, generation, upgrade).await
    }
    /// A node of its own identity, trusted when `trusted`, granted and
    /// keyed only for `tables` of generation 3.
    pub(super) async fn open_scoped(
        &self,
        path: &std::path::Path,
        node: &PrivateKey,
        trusted: bool,
        tables: &[&str],
    ) -> Result<EncryptedReplica<TypedRows>, Error> {
        let mut config = self.config(3, node);
        let user = PrivateKey::from_bytes(&rocky_core::commitment(
            "lineage.user",
            node.public_key().as_bytes(),
        ));
        config.credentials =
            self.certified_for(3, &user, node, trusted.then_some(self.domain), Some(tables));
        config
            .keys
            .retain(|key| tables.iter().any(|table| self.scope(table) == key.scope));
        self.open_with(path, config, 3, None).await
    }
    async fn open_with(
        &self,
        path: &std::path::Path,
        config: SecureConfig,
        generation: u32,
        upgrade: Option<(LogicalSchema, Scope, BTreeMap<String, Commitment>)>,
    ) -> Result<EncryptedReplica<TypedRows>, Error> {
        let replica = EncryptedReplica::open(path, self.app(generation), config).await?;
        if let Some((schema, scope, readers)) = upgrade {
            replica.install_tables(schema, scope, readers).await?;
        }
        replica
            .install_tables(
                self.schema(generation),
                self.domain,
                self.readers(generation),
            )
            .await?;
        Ok(replica)
    }
}
pub(super) async fn session(replica: &EncryptedReplica<TypedRows>) -> SecureSql<TypedRows> {
    let scopes = {
        let inner = replica.inner.lock(crate::replica::Class::Background).await;
        inner.config.keys.iter().map(|key| key.scope).collect()
    };
    replica
        .session(scopes)
        .await
        .unwrap()
        .sql(SqlOptions::default())
        .await
        .unwrap()
}
pub(super) async fn write(replica: &EncryptedReplica<TypedRows>, sql: &str) {
    session(replica).await.run(sql, vec![]).await.unwrap();
}
pub(super) async fn select(replica: &EncryptedReplica<TypedRows>, sql: &str) -> Vec<Vec<SqlValue>> {
    match session(replica).await.run(sql, vec![]).await {
        Ok(result) => result.rows,
        Err(error) => panic!(
            "read {sql}: {error}; blockers: {:?}",
            replica.blockers().await
        ),
    }
}
pub(super) async fn identity_insert(
    session: &SecureSql<TypedRows>,
    sql: &str,
    mut values: Vec<SqlValue>,
) -> Result<SecureRows, Error> {
    let implicit = session.state().await == crate::sql::SqlState::Idle;
    if implicit {
        session.run("BEGIN", vec![]).await?;
    }
    let result = async {
        let (head, tail) = sql.split_once(" VALUES").unwrap();
        let name = head
            .trim_start_matches("INSERT INTO ")
            .split('(')
            .next()
            .unwrap();
        let columns = match head.split_once('(') {
            Some((_, columns)) => columns.trim_end_matches(')').to_string(),
            None => session
                .catalog()
                .into_iter()
                .find(|table| table.name == name)
                .unwrap()
                .columns
                .iter()
                .filter(|column| column.name != "id")
                .map(|column| column.name.clone())
                .collect::<Vec<_>>()
                .join(","),
        };
        let id = session.next_id(name).await?;
        let tail = tail.trim().trim_end_matches(')');
        // The allocator value is a checked integer; embed it without changing positional bindings.
        let rewritten = format!(
            "INSERT INTO {name}({columns},id) VALUES{tail},{})",
            id.integer()
        );
        session.run(&rewritten, std::mem::take(&mut values)).await
    }
    .await;
    if implicit {
        match result {
            Ok(mut result) => {
                result.committed = session.run("COMMIT", vec![]).await?.committed;
                Ok(result)
            }
            Err(error) => {
                let _ = session.run("ROLLBACK", vec![]).await;
                Err(error)
            }
        }
    } else {
        result
    }
}
async fn insert(replica: &EncryptedReplica<TypedRows>, ids: std::ops::Range<usize>) {
    let session = session(replica).await;
    session.run("BEGIN IMMEDIATE", vec![]).await.unwrap();
    for id in ids.clone() {
        identity_insert(
            &session,
            "INSERT INTO items(key,title) VALUES(?,?)",
            vec![text(&format!("{id:04}")), text(&format!("title {id}"))],
        )
        .await
        .unwrap();
    }
    session
        .commit(rocky_core::commitment(
            "generations.insert",
            format!("{ids:?}").as_bytes(),
        ))
        .await
        .unwrap();
}
/// Every frame `target` may receive from `source`, page by page.
async fn frames(
    source: &EncryptedReplica<TypedRows>,
    target: &EncryptedReplica<TypedRows>,
    scope: ResourceScope,
) -> Vec<EncryptedFrame> {
    let (node, credentials, tip) = {
        let inner = target.inner.lock(crate::replica::Class::Background).await;
        (
            inner.config.node.public_key(),
            inner.config.credentials.clone(),
            inner.workspace.tip,
        )
    };
    // As the target's session hello declares its followed tip.
    source.admit_peer(node, &credentials, tip).await.unwrap();
    frames_as(source, node, &credentials, scope).await
}
/// Every frame a node presenting `credentials` may receive from `source`.
async fn frames_as(
    source: &EncryptedReplica<TypedRows>,
    node: PublicKey,
    credentials: &CredentialChain,
    scope: ResourceScope,
) -> Vec<EncryptedFrame> {
    let mut frames = Vec::new();
    let mut after = None;
    loop {
        let page = source
            .transfer_page(node, credentials, &[scope], after, MAX_SECURE_FRAME)
            .await
            .unwrap();
        frames.extend(page.frames);
        match page.next {
            Some(next) => after = Some(next),
            None => return frames,
        }
    }
}

#[tokio::test]
async fn an_interrupted_local_plan_finishes_when_the_replica_opens() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let node = PrivateKey::new();
    let path = dir.path().join("a.db");
    let replica = lineage.open(&path, &node, 1, None).await.unwrap();
    insert(&replica, 0..150).await;
    insert(&replica, 150..300).await;
    replica.fail_next_plan_switch().await;
    let failed = replica
        .install_tables(lineage.indexed(), lineage.domain, lineage.readers(1))
        .await;
    assert!(matches!(failed, Err(Error::InjectedFailure)), "{failed:?}");
    assert_eq!(replica.projection_plan().await.unwrap().unwrap().tables, 1);
    // The installed tables still answer.
    assert_eq!(
        select(&replica, "SELECT count(*) FROM items").await,
        vec![vec![SqlValue::Integer(300)]]
    );
    // Another plan waits for this one.
    let mut other = lineage.indexed();
    other.tables[0].indexes[1].name = "drafts_by_body".into();
    other.tables[0].indexes[1].create_sql = "CREATE INDEX drafts_by_body ON drafts(body)".into();
    let other = replica
        .install_tables(other, lineage.domain, lineage.readers(1))
        .await;
    assert!(matches!(other, Err(Error::Incompatible(_))), "{other:?}");
    // Writes before the switch keep their rows.
    let writer = session(&replica).await;
    writer
        .run("UPDATE items SET title='changed' WHERE key='0001'", vec![])
        .await
        .unwrap();
    writer
        .run("DELETE FROM items WHERE key='0299'", vec![])
        .await
        .unwrap();
    identity_insert(&writer, "INSERT INTO items VALUES('9999','late')", vec![])
        .await
        .unwrap();
    drop(writer);
    drop(replica);
    // Reopening finishes the same plan before anything else runs.
    let replica = EncryptedReplica::open(&path, lineage.app(1), lineage.config(1, &node))
        .await
        .unwrap();
    assert_eq!(replica.projection_plan().await.unwrap(), None);
    replica
        .install_tables(lineage.indexed(), lineage.domain, lineage.readers(1))
        .await
        .unwrap();
    assert_eq!(
        select(&replica, "SELECT count(*), max(key) FROM items").await,
        vec![vec![SqlValue::Integer(300), text("9999")]]
    );
    assert_eq!(
        select(&replica, "SELECT title FROM items WHERE key='0001'").await,
        vec![vec![text("changed")]]
    );
    let indexes = {
        let inner = replica.inner.lock(crate::replica::Class::Background).await;
        rows(
            &inner.conn,
            "SELECT name FROM sqlite_schema WHERE type='index' AND tbl_name='drafts' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .await
        .unwrap()
    };
    assert_eq!(
        indexes,
        vec![vec![text("drafts_body")], vec![text("drafts_identity")]]
    );
    let status = replica.generations().await.unwrap();
    assert_eq!(status.current, Generation { schema: 1 });
}

#[tokio::test]
async fn an_uninterrupted_local_plan_switches_while_reads_continue() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let replica = lineage
        .open(&dir.path().join("a.db"), &PrivateKey::new(), 1, None)
        .await
        .unwrap();
    insert(&replica, 0..10).await;
    let mut events = replica.observe_revision();
    let before = *events.borrow_and_update();
    replica
        .install_tables(lineage.indexed(), lineage.domain, lineage.readers(1))
        .await
        .unwrap();
    assert!(*events.borrow() > before, "the switch is announced");
    assert_eq!(
        select(&replica, "SELECT count(*) FROM items").await,
        vec![vec![SqlValue::Integer(10)]]
    );
    let plan = {
        let inner = replica.inner.lock(crate::replica::Class::Background).await;
        rows(
            &inner.conn,
            "EXPLAIN QUERY PLAN SELECT key FROM drafts WHERE body='body 3'",
        )
        .await
        .unwrap()
    };
    assert!(format!("{plan:?}").contains("drafts_body"), "{plan:?}");
    // A renamed field is another field: refused before a plan.
    let mut renamed = lineage.schema(1);
    renamed.tables[0].columns[1].sql_name = "name".into();
    assert!(matches!(
        replica
            .install_tables(renamed, lineage.domain, lineage.readers(1))
            .await,
        Err(Error::Incompatible(_))
    ));
    assert_eq!(replica.projection_plan().await.unwrap(), None);
}

#[tokio::test]
async fn a_backup_copy_opens_only_under_a_fresh_identity_and_keeps_its_history() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let (old_key, new_key) = (PrivateKey::new(), PrivateKey::new());
    let alice = lineage
        .open(&dir.path().join("alice.db"), &old_key, 1, None)
        .await
        .unwrap();
    insert(&alice, 0..3).await;
    let copy = dir.path().join("copy.db");
    alice.backup_into(&copy).await.unwrap();
    assert!(alice.backup_into(&copy).await.is_err(), "never overwritten");
    let restore = |node: &PrivateKey, predecessor: PublicKey| {
        EncryptedReplica::open_restored(&copy, lineage.app(1), lineage.config(1, node), predecessor)
    };
    assert!(restore(&old_key, old_key.public_key()).await.is_err());
    assert!(
        restore(&new_key, PrivateKey::new().public_key())
            .await
            .is_err()
    );
    // Copying a file is not opening it: its identity is the old node's.
    assert!(
        EncryptedReplica::open(&copy, lineage.app(1), lineage.config(1, &new_key))
            .await
            .is_err()
    );
    let restored = restore(&new_key, old_key.public_key()).await.unwrap();
    restored
        .install_tables(lineage.schema(1), lineage.domain, lineage.readers(1))
        .await
        .unwrap();
    assert_eq!(
        restored.predecessors().await.unwrap(),
        [old_key.public_key()]
    );
    assert_eq!(
        select(&restored, "SELECT count(*) FROM items").await,
        vec![vec![SqlValue::Integer(3)]]
    );
    insert(&restored, 3..4).await;
    let items = lineage.scope("items");
    let authors: BTreeSet<_> = frames(&restored, &alice, items)
        .await
        .iter()
        .map(|frame| frame.operation().unwrap().header.public_key)
        .collect();
    assert_eq!(
        authors,
        [old_key.clone().public_key(), new_key.clone().public_key()].into()
    );
    restored.audit(items).await.unwrap();
    drop(restored);
    // Rebinding happened once; reopening is ordinary.
    let reopened = restore(&new_key, old_key.public_key()).await.unwrap();
    assert_eq!(
        reopened.predecessors().await.unwrap(),
        [old_key.public_key()]
    );
}

/// Catches `target` up on `scope` from `source` by range pages, voids
/// first, as a session does.
async fn sync(
    source: &EncryptedReplica<TypedRows>,
    target: &EncryptedReplica<TypedRows>,
    target_key: &PrivateKey,
    lineage: &Lineage,
    generation: u32,
    scope: ResourceScope,
) {
    let credentials = lineage.credentials(generation, target_key);
    // As the target's session hello declares its followed tip.
    let tip = target.followed_tip().await;
    source
        .admit_peer(target_key.public_key(), &credentials, tip)
        .await
        .unwrap();
    let mut after = None;
    loop {
        let frontier = target.frontier(scope).await.unwrap();
        let page = source
            .range_page(
                target_key.public_key(),
                &credentials,
                &frontier,
                after,
                MAX_SECURE_FRAME,
            )
            .await
            .unwrap();
        for status in target.receive_voids(&page.voids).await {
            status.unwrap();
        }
        for status in target.receive_all(page.frames).await {
            status.unwrap();
        }
        after = page.next;
        if after.is_none() {
            return;
        }
    }
}

mod replayed;
mod sideways;
mod switches;
