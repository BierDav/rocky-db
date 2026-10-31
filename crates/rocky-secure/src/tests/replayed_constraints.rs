//! Replayed tables keep their SQL constraints. A transaction that violates a
//! `CHECK`, unique index, foreign key or assertion where it replays drops
//! with reason `Constraint` everywhere; at its author it is a commit error
//! and publishes nothing. Every test compares replicas with a from-scratch
//! replay of the canonical order in plain SQLite.
use super::*;
use crate::sql::{SqlError, SqlOptions};
use rocky_core::replay::{DropReason, IntentStatement, TransactionOutcome};
use rocky_core::{
    DomainId, LogicalSchema, PartitionSelection, PartitionSelector, PartitionTuple, PartitionValue,
    SchemaDefinition, Scope, SqlValue, TypedRows,
};
use rocky_credentials::{Authority, PartitionGrant};
use std::collections::BTreeMap;
use std::path::Path;

mod convergence;

/// `teams` own `members` (cascade, immediate) and `orders` own `lines`
/// (cascade, deferred). `team_cap` bounds a team's members by its `cap`;
/// `order_total` keeps an order's total equal to its lines.
fn definition() -> serde_json::Value {
    serde_json::json!({
        "format": 6,
        "application": "replayed-constraints",
        "tables": [
            {"name": "teams", "class": "replayed",
             "columns": [{"name": "name", "type": "text", "not_null": true},
                         {"name": "cap", "type": "integer", "not_null": true}],
             "checks": ["cap BETWEEN 1 AND 3"],
             "primary_key": ["id"]},
            {"name": "members", "class": "replayed",
             "columns": [{"name": "team", "type": "integer", "not_null": true},
                         {"name": "email", "type": "text", "not_null": true},
                         {"name": "role", "type": "text"}],
             "checks": ["role IS NULL OR role IN ('lead', 'member')"],
             "primary_key": ["id"],
             "indexes": [{"name": "members_email", "unique": true,
                          "columns": [{"name": "email", "descending": false}]}],
             "foreign_keys": [{"columns": ["team"], "table": "teams", "on_delete": "cascade"}]},
            {"name": "orders", "class": "replayed",
             "columns": [{"name": "total", "type": "integer", "not_null": true}],
             "primary_key": ["id"]},
            {"name": "lines", "class": "replayed",
             "columns": [{"name": "parent", "type": "integer", "not_null": true},
                         {"name": "amount", "type": "integer", "not_null": true}],
             "checks": ["amount > 0"],
             "primary_key": ["id"],
             "foreign_keys": [{"columns": ["parent"], "table": "orders",
                               "on_delete": "cascade", "deferred": true}]},
            {"name": "ranges", "class": "replayed",
             "columns": [{"name": "lo", "type": "integer", "not_null": true},
                         {"name": "hi", "type": "integer", "not_null": true},
                         {"name": "width", "type": "integer"}],
             "checks": ["lo <= hi", "width > 0"],
             "primary_key": ["id"]}
        ],
        "assertions": [
            {"name": "team_cap",
             "select_sql": "SELECT t.id FROM teams t JOIN members m ON m.team = t.id GROUP BY t.id HAVING COUNT(*) > MIN(t.cap)"},
            {"name": "order_total",
             "select_sql": "SELECT o.id FROM orders o WHERE o.total <> (SELECT COALESCE(SUM(l.amount), 0) FROM lines l WHERE l.parent = o.id)"}
        ]
    })
}

/// A schema of replayed tables, each its own reader scope, every one held
/// by every device.
struct Constrained {
    publisher: PrivateKey,
    schema: LogicalSchema,
    manifest: SignedManifest,
    domain: Scope,
    /// The one partition of a schema of tables partitioned by `tenant`.
    tenant: Option<i64>,
}

impl Constrained {
    fn new() -> Self {
        Self::with(definition(), |_| {})
    }
    /// Builds `json`, then lets `edit` change the descriptor.
    fn with(json: serde_json::Value, edit: impl FnOnce(&mut LogicalSchema)) -> Self {
        Self::build(json, None, edit)
    }
    fn build(
        mut json: serde_json::Value,
        tenant: Option<i64>,
        edit: impl FnOnce(&mut LogicalSchema),
    ) -> Self {
        let publisher = PrivateKey::new();
        json["publisher"] = publisher
            .public_key()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
            .into();
        let mut schema = SchemaDefinition::parse(&serde_json::to_vec(&json).unwrap())
            .unwrap()
            .build()
            .unwrap();
        edit(&mut schema);
        schema.supported_on(rocky_core::Profile::Secure).unwrap();
        let manifest = schema.manifest(&[DomainId([1; 16])]);
        Self {
            manifest: SignedManifest::sign(&manifest, &publisher).unwrap(),
            domain: Scope {
                mesh: MeshId([1; 16]),
                app: schema.app_id(),
                domain: DomainId([1; 16]),
            },
            schema,
            publisher,
            tenant,
        }
    }
    fn app(&self) -> TypedRows {
        TypedRows::new(self.schema.clone(), vec![self.domain.domain]).unwrap()
    }
    fn names(&self) -> Vec<&str> {
        self.schema
            .tables
            .iter()
            .map(|table| table.sql_name.as_str())
            .collect()
    }
    /// The tenant column of table `name` and the tenant's value in it.
    fn tenant_of(&self, name: &str, tenant: i64) -> (Commitment, PartitionValue) {
        let table = self.schema.table(name).unwrap();
        (
            self.schema.field_id(table, table.column("tenant").unwrap()),
            PartitionValue::new(
                rocky_core::KeyColumn {
                    affinity: rocky_core::Affinity::Integer,
                    collation: rocky_core::Collation::Binary,
                },
                SqlValue::Integer(tenant),
            )
            .unwrap(),
        )
    }
    fn tuple(&self, name: &str, tenant: i64) -> PartitionTuple {
        PartitionTuple::new([self.tenant_of(name, tenant)]).unwrap()
    }
    fn scope(&self, name: &str) -> ResourceScope {
        if let Some(tenant) = self.tenant {
            let table = self.schema.table_id(self.schema.table(name).unwrap());
            return self.tuple(name, tenant).scope(self.domain, table).unwrap();
        }
        ResourceScope {
            domain: self.domain,
            encryption: rocky_core::commitment("replayed-constraints.readers", name.as_bytes()),
            table: self.schema.table_id(self.schema.table(name).unwrap()),
        }
    }
    fn key(&self, scope: ResourceScope) -> [u8; 32] {
        let index = self
            .names()
            .iter()
            .position(|name| self.scope(name) == scope)
            .unwrap();
        [40 + index as u8; 32]
    }
    fn grants(&self) -> Vec<ResourceGrant> {
        self.names()
            .into_iter()
            .map(|name| {
                let table = self.schema.table(name).unwrap();
                let fields: Vec<_> = table
                    .columns
                    .iter()
                    .map(|column| self.schema.field_id(table, column))
                    .collect();
                grant(
                    self.scope(name),
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
    fn partition_grants(&self, tenant: i64) -> Vec<PartitionGrant> {
        self.names()
            .into_iter()
            .map(|name| {
                let table = self.schema.table(name).unwrap();
                let (column, value) = self.tenant_of(name, tenant);
                PartitionGrant {
                    domain: self.domain,
                    table: self.schema.table_id(table),
                    selector: PartitionSelector(
                        [(column, PartitionSelection::Only([value].into()))].into(),
                    ),
                    rows: RowSelection::All,
                    rights: [
                        Right::Read,
                        Right::Insert,
                        Right::Update,
                        Right::Delete,
                        Right::Custody,
                    ]
                    .into_iter()
                    .collect(),
                    fields: table
                        .columns
                        .iter()
                        .map(|column| self.schema.field_id(table, column))
                        .collect(),
                }
            })
            .collect()
    }
    fn credentials(&self, node: &PrivateKey) -> CredentialChain {
        let number = node_number(node.public_key());
        let user = PrivateKey::new();
        if let Some(tenant) = self.tenant {
            let root = Authority::owner(&self.publisher)
                .issue_partition_terms(
                    user.public_key(),
                    vec![],
                    self.partition_grants(tenant),
                    (1, Some(rocky_credentials::AuthorRange::ALL)),
                    (now().unwrap(), 3600, 5),
                )
                .unwrap();
            return CredentialChain(vec![root])
                .complete(&user, node.public_key(), number)
                .unwrap();
        }
        let capability = |subject, kind, delegations| Capability {
            subject,
            kind,
            grants: self.grants(),
            not_before: lifetime().0,
            expires: lifetime().1,
            delegations,
            extension: rocky_credentials::Extension::new(rocky_credentials::Extended {
                authors: Some(if kind == PrincipalKind::Node {
                    rocky_credentials::AuthorRange::new(number, number).unwrap()
                } else {
                    rocky_credentials::AuthorRange::ALL
                }),
                node: (kind == PrincipalKind::Node).then(|| rocky_credentials::PeerId::of(subject)),
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
            SignedCapability::sign(capability(node.public_key(), PrincipalKind::Node, 0), &user)
                .unwrap(),
        ])
    }
    async fn open(&self, path: &Path) -> Device {
        let node = PrivateKey::new();
        let replica = EncryptedReplica::open(
            path,
            self.app(),
            SecureConfig {
                publisher: self.publisher.public_key(),
                manifest: self.manifest.clone(),
                revocations: RevocationSet::new(),
                node: node.clone(),
                credentials: self.credentials(&node),
                keys: if self.tenant.is_some() {
                    Vec::new()
                } else {
                    self.names()
                        .into_iter()
                        .map(|name| {
                            KeyMaterial::new(self.scope(name), 1, self.key(self.scope(name)))
                        })
                        .collect()
                },
            },
        )
        .await
        .unwrap();
        replica
            .install_tables(
                self.schema.clone(),
                self.domain,
                self.names()
                    .into_iter()
                    .map(|name| (name.to_string(), self.scope(name).encryption))
                    .collect(),
            )
            .await
            .unwrap();
        if let Some(tenant) = self.tenant {
            for name in self.names() {
                let scope = self.scope(name);
                replica
                    .register_partition(scope, self.tuple(name, tenant))
                    .await
                    .unwrap();
                replica
                    .install_key(KeyMaterial::new(scope, 1, self.key(scope)))
                    .await
                    .unwrap();
            }
        }
        Device {
            replica,
            node,
            seen: BTreeSet::new(),
        }
    }
    fn payload(&self, frame: &EncryptedFrame) -> crate::wire::RowPayload {
        let plaintext = crate::wire::decrypt(
            &self.key(frame.scope().unwrap()),
            &encode(&frame.operation_ref().unwrap().header.extensions).unwrap(),
            frame.body_bytes(),
        )
        .unwrap();
        crate::wire::RowPayload::decode_test(&plaintext, frame, &self.app()).unwrap()
    }
    /// The transaction a frame of a commit belongs to.
    fn transaction(&self, frames: &[EncryptedFrame]) -> Commitment {
        self.payload(&frames[0]).membership().unwrap().transaction
    }
}

/// A device holding every table.
struct Device {
    replica: EncryptedReplica<TypedRows>,
    node: PrivateKey,
    seen: BTreeSet<p2panda_core::Hash>,
}

impl Device {
    async fn session(&self, c: &Constrained) -> crate::SecureSql<TypedRows> {
        self.replica
            .session(c.names().into_iter().map(|name| c.scope(name)).collect())
            .await
            .unwrap()
            .sql(SqlOptions::default())
            .await
            .unwrap()
    }
    /// Runs `statements` as one transaction. `#id` in an INSERT takes a
    /// fresh identity of its table; they are returned in order.
    /// `#next(table)` reserves the identity `table`'s next `#id` takes.
    async fn commit(&self, c: &Constrained, statements: &[&str]) -> Result<Vec<i64>, Error> {
        let session = self.session(c).await;
        let next_id = async |table: &str| match c.tenant {
            Some(tenant) => session
                .next_id_partition(table, &[SqlValue::Integer(tenant)])
                .await
                .map(|id| id.integer()),
            None => session.next_id(table).await.map(|id| id.integer()),
        };
        session.run("BEGIN", vec![]).await?;
        let (mut ids, mut reserved) = (Vec::new(), BTreeMap::new());
        for statement in statements {
            let mut sql = statement.to_string();
            while let Some(start) = sql.find("#next(") {
                let end = start + sql[start..].find(')').unwrap();
                let table = sql[start + 6..end].to_string();
                let id = next_id(&table).await?;
                reserved.insert(table, id);
                sql.replace_range(start..=end, &id.to_string());
            }
            if sql.contains("#id") {
                let table = sql
                    .trim_start_matches("INSERT INTO ")
                    .split(['(', ' '])
                    .next()
                    .unwrap()
                    .to_string();
                let id = match reserved.remove(&table) {
                    Some(id) => id,
                    None => next_id(&table).await?,
                };
                sql = sql.replace("#id", &id.to_string());
                ids.push(id);
            }
            if let Err(error) = session.run(&sql, vec![]).await {
                let _ = session.run("ROLLBACK", vec![]).await;
                return Err(error);
            }
        }
        session.run("COMMIT", vec![]).await?;
        Ok(ids)
    }
    /// Every frame this device authored since the last call: intents and
    /// the outcome records its commits and rewinds published.
    async fn fresh(&mut self) -> Vec<EncryptedFrame> {
        let author = self
            .node
            .public_key()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let frames = stored_frames(
            &self.replica,
            &format!(
                "SELECT header,body FROM secure_operations WHERE author=x'{author}' ORDER BY sequence"
            ),
        )
        .await;
        frames
            .into_iter()
            .filter(|frame| self.seen.insert(frame.operation_ref().unwrap().hash))
            .collect()
    }
    async fn receive(&self, frames: &[EncryptedFrame]) {
        for status in self.replica.receive_all(frames.to_vec()).await {
            assert_ne!(status.unwrap(), ReceiveStatus::Rejected);
        }
    }
    /// Every table's rows, ordered by `id`.
    async fn rows(&self, c: &Constrained) -> BTreeMap<String, Vec<Vec<SqlValue>>> {
        let session = self.session(c).await;
        let filter = c
            .tenant
            .map_or(String::new(), |tenant| format!("WHERE tenant={tenant}"));
        let mut tables = BTreeMap::new();
        for name in c.names() {
            tables.insert(
                name.to_string(),
                session
                    .run(
                        &format!("SELECT * FROM {name} {filter} ORDER BY id"),
                        vec![],
                    )
                    .await
                    .unwrap()
                    .rows,
            );
        }
        tables
    }
    async fn state(&self, c: &Constrained, expected: &Canonical) -> Canonical {
        let mut outcomes = BTreeMap::new();
        for transaction in expected.outcomes.keys() {
            outcomes.insert(
                *transaction,
                self.replica
                    .transaction_outcome(*transaction)
                    .await
                    .unwrap()
                    .expect("every transaction replayed"),
            );
        }
        Canonical {
            rows: self.rows(c).await,
            outcomes,
        }
    }
}

/// Rows and drop map of a from-scratch replay in canonical order.
#[derive(Debug, PartialEq)]
struct Canonical {
    rows: BTreeMap<String, Vec<Vec<SqlValue>>>,
    outcomes: BTreeMap<Commitment, TransactionOutcome>,
}

impl Canonical {
    fn dropped(&self) -> usize {
        self.outcomes
            .values()
            .filter(|outcome| **outcome != TransactionOutcome::Applied)
            .count()
    }
}

fn sql_value(value: &SqlValue) -> rusqlite::types::Value {
    use rusqlite::types::Value;
    match value {
        SqlValue::Null => Value::Null,
        SqlValue::Integer(value) => Value::Integer(*value),
        SqlValue::Text(value) => Value::Text(value.clone()),
        SqlValue::Blob(value) => Value::Blob(value.clone()),
        SqlValue::Real(value) => Value::Real(value.get()),
    }
}

/// Replays every intent in `frames` in plain SQLite: transactions in stamp
/// order, each in a savepoint with its keys deferred when it has several
/// members; a statement, foreign key or assertion that fails drops it.
fn canonical(c: &Constrained, frames: &[EncryptedFrame]) -> Canonical {
    let mut members = Vec::new();
    for frame in frames {
        let payload = c.payload(frame);
        let Some(intent) = payload.intent() else {
            continue;
        };
        let membership = payload.membership().unwrap();
        let header = &frame.operation_ref().unwrap().header;
        members.push((
            (
                header.timestamp,
                header.extensions.author.unwrap(),
                header.extensions.author_sequence,
            ),
            membership.transaction,
            membership.members.len(),
            intent.statements.clone(),
        ));
    }
    members.sort_by_key(|member| member.0);
    let mut order: Vec<Commitment> = Vec::new();
    for (_, transaction, ..) in &members {
        if !order.contains(transaction) {
            order.push(*transaction);
        }
    }
    let db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    for table in &c.schema.tables {
        db.execute_batch(&table.create_sql).unwrap();
        for index in &table.indexes {
            db.execute_batch(&index.create_sql).unwrap();
        }
    }
    db.execute_batch("BEGIN").unwrap();
    let mut outcomes = BTreeMap::new();
    for transaction in order {
        let held: Vec<&Vec<IntentStatement>> = members
            .iter()
            .filter(|member| member.1 == transaction)
            .map(|member| &member.3)
            .collect();
        let several = members
            .iter()
            .find(|member| member.1 == transaction)
            .unwrap()
            .2
            > 1;
        db.execute_batch("SAVEPOINT t").unwrap();
        if several {
            db.execute_batch("PRAGMA defer_foreign_keys=ON").unwrap();
        }
        let failed = held.iter().copied().flatten().any(|statement| {
            let params: Vec<_> = statement.params.iter().map(sql_value).collect();
            db.execute(&statement.sql, rusqlite::params_from_iter(params))
                .is_err()
        }) || db
            .prepare("PRAGMA foreign_key_check")
            .unwrap()
            .query([])
            .unwrap()
            .next()
            .unwrap()
            .is_some()
            || c.schema.assertions.iter().any(|assertion| {
                db.prepare(&assertion.select_sql)
                    .unwrap()
                    .query([])
                    .unwrap()
                    .next()
                    .unwrap()
                    .is_some()
            });
        if failed {
            db.execute_batch("ROLLBACK TO t").unwrap();
        }
        db.execute_batch("PRAGMA defer_foreign_keys=OFF; RELEASE t")
            .unwrap();
        outcomes.insert(
            transaction,
            if failed {
                TransactionOutcome::Dropped {
                    reason: DropReason::Constraint,
                    sealed: false,
                }
            } else {
                TransactionOutcome::Applied
            },
        );
    }
    let mut rows = BTreeMap::new();
    for name in c.names() {
        let mut statement = db
            .prepare(&format!("SELECT * FROM {name} ORDER BY id"))
            .unwrap();
        let width = statement.column_count();
        rows.insert(
            name.to_string(),
            statement
                .query_map([], |row| {
                    (0..width)
                        .map(|index| {
                            Ok(match row.get::<_, rusqlite::types::Value>(index)? {
                                rusqlite::types::Value::Null => SqlValue::Null,
                                rusqlite::types::Value::Integer(value) => SqlValue::Integer(value),
                                rusqlite::types::Value::Text(value) => SqlValue::Text(value),
                                rusqlite::types::Value::Blob(value) => SqlValue::Blob(value),
                                rusqlite::types::Value::Real(value) => {
                                    SqlValue::real(value).unwrap()
                                }
                            })
                        })
                        .collect()
                })
                .unwrap()
                .map(Result::unwrap)
                .collect(),
        );
    }
    Canonical { rows, outcomes }
}

/// Frames ordered latest stamp first, so a receiver rewinds at every step.
fn latest_first(frames: &[EncryptedFrame]) -> Vec<EncryptedFrame> {
    let mut frames = frames.to_vec();
    frames.sort_by_key(|frame| {
        let header = &frame.operation_ref().unwrap().header;
        std::cmp::Reverse((
            header.timestamp,
            header.extensions.author,
            header.extensions.author_sequence,
        ))
    });
    frames
}

fn constraint_error(error: Error) -> String {
    match error {
        Error::Sql(SqlError::Statement { code, message }) if code & 0xff == 19 => message,
        other => panic!("not a constraint error: {other:?}"),
    }
}

/// Opens `count` devices that all hold `setup`'s rows.
async fn devices(
    c: &Constrained,
    root: &Path,
    count: usize,
    setup: &[&str],
) -> (Vec<Device>, Vec<i64>, Vec<EncryptedFrame>) {
    let mut devices = Vec::new();
    for index in 0..count {
        devices.push(c.open(&root.join(format!("d{index}.db"))).await);
    }
    let ids = if setup.is_empty() {
        Vec::new()
    } else {
        devices[0].commit(c, setup).await.unwrap()
    };
    let frames = devices[0].fresh().await;
    for device in &devices[1..] {
        device.receive(&frames).await;
    }
    (devices, ids, frames)
}

/// Has every device receive the whole history until none publishes
/// anything new, then `receiver` receive it latest first; all must agree
/// with the canonical replay.
async fn exchange(
    c: &Constrained,
    devices: &mut [Device],
    receiver: &Device,
    history: &mut Vec<EncryptedFrame>,
) -> Canonical {
    loop {
        let mut fresh = Vec::new();
        for device in devices.iter_mut() {
            device.receive(history).await;
            // Commits, and the records rewinds publish.
            fresh.extend(device.fresh().await);
        }
        if fresh.is_empty() {
            break;
        }
        history.extend(fresh);
    }
    receiver.receive(&latest_first(history)).await;
    let expected = canonical(c, history);
    for (index, device) in devices.iter().chain([receiver]).enumerate() {
        assert_eq!(device.state(c, &expected).await, expected, "device {index}");
    }
    expected
}

#[tokio::test]
async fn unique_and_check_violations_drop_the_later_transaction_everywhere() {
    let c = Constrained::new();
    let root = tempfile::tempdir().unwrap();
    let (mut devices, ids, mut history) = devices(
        &c,
        root.path(),
        3,
        &["INSERT INTO teams(name,cap,id) VALUES('red',2,#id)"],
    )
    .await;
    let receiver = devices.pop().unwrap();
    let red = ids[0];
    // Neither author has seen the other: each insert and each raise holds
    // locally, but not after the other's.
    for device in &devices {
        device
            .commit(
                &c,
                &[&format!(
                    "INSERT INTO members(team,email,id) VALUES({red},'x@example',#id)"
                )],
            )
            .await
            .unwrap();
        device
            .commit(&c, &[&format!("UPDATE teams SET cap=cap+1 WHERE id={red}")])
            .await
            .unwrap();
    }
    let expected = exchange(&c, &mut devices, &receiver, &mut history).await;
    assert_eq!(expected.dropped(), 2);
    let mut violations = Vec::new();
    for (transaction, outcome) in &expected.outcomes {
        if *outcome != TransactionOutcome::Applied {
            violations.push(
                receiver
                    .replica
                    .transaction_violation(*transaction)
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
    }
    violations.sort();
    assert!(
        violations[0].starts_with("CHECK constraint failed"),
        "{violations:?}"
    );
    assert!(
        violations[1].starts_with("UNIQUE constraint failed: members.email"),
        "{violations:?}"
    );
    // A local violation is the statement's error.
    assert!(
        constraint_error(
            devices[0]
                .commit(&c, &[&format!("UPDATE teams SET cap=9 WHERE id={red}")])
                .await
                .unwrap_err()
        )
        .starts_with("CHECK constraint failed")
    );
    assert!(devices[0].fresh().await.is_empty());
}

#[tokio::test]
async fn checks_pass_null_and_hold_after_every_statement() {
    let c = Constrained::new();
    let root = tempfile::tempdir().unwrap();
    let (mut devices, ids, mut history) = devices(
        &c,
        root.path(),
        2,
        // A NULL check passes.
        &["INSERT INTO ranges(lo,hi,width,id) VALUES(1,2,NULL,#id)"],
    )
    .await;
    let receiver = devices.pop().unwrap();
    let range = ids[0];
    // The final state would be valid, the intermediate row is not.
    let error = devices[0]
        .commit(
            &c,
            &[
                &format!("UPDATE ranges SET lo=5 WHERE id={range}"),
                &format!("UPDATE ranges SET hi=6 WHERE id={range}"),
            ],
        )
        .await
        .unwrap_err();
    assert!(constraint_error(error).starts_with("CHECK constraint failed"));
    devices[0]
        .commit(
            &c,
            &[&format!("UPDATE ranges SET lo=5, hi=6 WHERE id={range}")],
        )
        .await
        .unwrap();
    let expected = exchange(&c, &mut devices, &receiver, &mut history).await;
    assert_eq!(expected.dropped(), 0);
    assert_eq!(
        expected.rows["ranges"],
        vec![vec![
            SqlValue::Integer(5),
            SqlValue::Integer(6),
            SqlValue::Null,
            SqlValue::Integer(range),
            SqlValue::Integer(0),
        ]]
    );
}

#[tokio::test]
async fn foreign_keys_drop_orphans_and_cascades_rewind_with_their_transaction() {
    let c = Constrained::new();
    let root = tempfile::tempdir().unwrap();
    let (mut devices, ids, mut history) = devices(
        &c,
        root.path(),
        3,
        &[
            "INSERT INTO teams(name,cap,id) VALUES('red',2,#id)",
            "INSERT INTO teams(name,cap,id) VALUES('blue',2,#id)",
            "INSERT INTO teams(name,cap,id) VALUES('green',2,#id)",
            // Deferred: the line precedes its order in the transaction.
            "INSERT INTO lines(parent,amount,id) VALUES(#next(orders),5,#id)",
            "INSERT INTO orders(total,id) VALUES(5,#id)",
        ],
    )
    .await;
    let receiver = devices.pop().unwrap();
    let (red, blue, green, order) = (ids[0], ids[1], ids[2], ids[4]);
    devices[0]
        .commit(
            &c,
            &[
                &format!("INSERT INTO members(team,email,id) VALUES({blue},'b@example',#id)"),
                &format!("INSERT INTO members(team,email,id) VALUES({green},'g@example',#id)"),
            ],
        )
        .await
        .unwrap();
    history.extend(devices[0].fresh().await);
    devices[1].receive(&history).await;
    // An immediate key refuses the statement; a dangling deferred one the
    // commit.
    assert!(
        constraint_error(
            devices[0]
                .commit(
                    &c,
                    &["INSERT INTO members(team,email,id) VALUES(12345,'n@example',#id)"]
                )
                .await
                .unwrap_err()
        )
        .starts_with("FOREIGN KEY constraint failed")
    );
    assert_eq!(
        constraint_error(
            devices[0]
                .commit(
                    &c,
                    &["INSERT INTO lines(parent,amount,id) VALUES(12345,1,#id)"]
                )
                .await
                .unwrap_err()
        ),
        "FOREIGN KEY constraint failed: lines"
    );
    // The first author deletes blue, cascading to its member, and the order
    // with its line; the second, not having seen that, adds to both. Its
    // children of deleted parents drop, whatever order replicas see.
    devices[0]
        .commit(&c, &[&format!("DELETE FROM teams WHERE id={blue}")])
        .await
        .unwrap();
    devices[0]
        .commit(&c, &[&format!("DELETE FROM orders WHERE id={order}")])
        .await
        .unwrap();
    devices[1]
        .commit(
            &c,
            &[&format!(
                "INSERT INTO members(team,email,id) VALUES({blue},'late@example',#id)"
            )],
        )
        .await
        .unwrap();
    devices[1]
        .commit(
            &c,
            &[
                &format!("INSERT INTO lines(parent,amount,id) VALUES({order},2,#id)"),
                &format!("UPDATE orders SET total=total+2 WHERE id={order}"),
            ],
        )
        .await
        .unwrap();
    // A cascade rolls back with its transaction: the later raise of red
    // beyond its cap drops the delete of green beside it.
    devices[1]
        .commit(&c, &[&format!("UPDATE teams SET cap=cap+1 WHERE id={red}")])
        .await
        .unwrap();
    devices[0]
        .commit(
            &c,
            &[
                &format!("DELETE FROM teams WHERE id={green}"),
                &format!("UPDATE teams SET cap=cap+1 WHERE id={red}"),
            ],
        )
        .await
        .unwrap();
    let expected = exchange(&c, &mut devices, &receiver, &mut history).await;
    let ids_of = |table: &str| -> Vec<SqlValue> {
        expected.rows[table]
            .iter()
            .map(|row| row[row.len() - 2].clone())
            .collect()
    };
    assert_eq!(ids_of("teams"), [red, green].map(SqlValue::Integer));
    assert_eq!(expected.rows["members"].len(), 1);
    assert!(expected.rows["lines"].is_empty() && expected.rows["orders"].is_empty());
    assert_eq!(expected.dropped(), 3, "{expected:?}");
    // A transaction whose delete action reaches another of its members
    // could replay in another order: it is refused.
    let error = devices[0]
        .commit(
            &c,
            &[
                &format!("INSERT INTO members(team,email,id) VALUES({red},'o@example',#id)"),
                &format!("DELETE FROM teams WHERE id={red}"),
            ],
        )
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Rejected(_)), "{error:?}");
}

#[tokio::test]
async fn assertions_refuse_local_commits_and_drop_replays_until_a_rewind_releases_them() {
    let c = Constrained::new();
    let root = tempfile::tempdir().unwrap();
    let (mut devices, ids, mut history) = devices(
        &c,
        root.path(),
        3,
        &[
            "INSERT INTO teams(name,cap,id) VALUES('red',1,#id)",
            "INSERT INTO lines(parent,amount,id) VALUES(#next(orders),10,#id)",
            "INSERT INTO orders(total,id) VALUES(10,#id)",
        ],
    )
    .await;
    let receiver = devices.pop().unwrap();
    let (red, line, order) = (ids[0], ids[1], ids[2]);
    // An insert, an update and a delete can each break the header total.
    for statements in [
        vec![format!(
            "INSERT INTO lines(parent,amount,id) VALUES({order},1,#id)"
        )],
        vec![format!("UPDATE lines SET amount=9 WHERE id={line}")],
        vec![format!("DELETE FROM lines WHERE id={line}")],
    ] {
        let statements: Vec<&str> = statements.iter().map(String::as_str).collect();
        assert_eq!(
            constraint_error(devices[0].commit(&c, &statements).await.unwrap_err()),
            "assertion order_total failed"
        );
    }
    assert!(devices[0].fresh().await.is_empty());
    devices[0]
        .commit(
            &c,
            &[
                &format!("UPDATE lines SET amount=9 WHERE id={line}"),
                &format!("UPDATE orders SET total=9 WHERE id={order}"),
            ],
        )
        .await
        .unwrap();
    // The first author adds a member to red and removes it again; the
    // second, seeing neither, adds another. Received in arrival order, the
    // second's waits on the cap until the removal ordered before it
    // arrives and the rewind places it after.
    devices[0]
        .commit(
            &c,
            &[&format!(
                "INSERT INTO members(team,email,id) VALUES({red},'one@example',#id)"
            )],
        )
        .await
        .unwrap();
    let added = devices[0].fresh().await;
    devices[0]
        .commit(&c, &["DELETE FROM members WHERE email='one@example'"])
        .await
        .unwrap();
    let removed = devices[0].fresh().await;
    devices[1]
        .commit(
            &c,
            &[&format!(
                "INSERT INTO members(team,email,id) VALUES({red},'two@example',#id)"
            )],
        )
        .await
        .unwrap();
    let second = devices[1].fresh().await;
    let stamp = |frames: &[EncryptedFrame]| frames[0].operation_ref().unwrap().header.timestamp;
    assert!(stamp(&added) < stamp(&removed) && stamp(&removed) < stamp(&second));
    let late = c.transaction(&second);
    receiver.receive(&added).await;
    receiver.receive(&second).await;
    assert_eq!(
        receiver.replica.transaction_outcome(late).await.unwrap(),
        Some(TransactionOutcome::Dropped {
            reason: DropReason::Constraint,
            sealed: false,
        })
    );
    assert_eq!(
        receiver
            .replica
            .transaction_violation(late)
            .await
            .unwrap()
            .as_deref(),
        Some("assertion team_cap failed")
    );
    let before = crate::sqlite::statements();
    receiver.receive(&removed).await;
    let rewind = crate::sqlite::statements() - before;
    assert_eq!(
        receiver.replica.transaction_outcome(late).await.unwrap(),
        Some(TransactionOutcome::Applied)
    );
    assert_eq!(
        receiver.replica.transaction_violation(late).await.unwrap(),
        None
    );
    println!("P5 assertion rewind_receive_statements={rewind}");
    history.extend(added);
    history.extend(removed);
    history.extend(second);
    let expected = exchange(&c, &mut devices, &receiver, &mut history).await;
    assert_eq!(expected.dropped(), 0);
    assert_eq!(expected.rows["members"].len(), 1);
}

/// Statements one replayed single-row insert costs its receiver, by what
/// it must check. Printed for the phase evidence; not a budget.
#[tokio::test]
async fn statements_per_assertion_are_recorded() {
    let c = Constrained::new();
    let root = tempfile::tempdir().unwrap();
    let (mut devices, ids, _) = devices(
        &c,
        root.path(),
        2,
        &[
            "INSERT INTO teams(name,cap,id) VALUES('red',3,#id)",
            "INSERT INTO orders(total,id) VALUES(0,#id)",
        ],
    )
    .await;
    let (red, order) = (ids[0], ids[1]);
    let mut counts = Vec::new();
    for (label, statements) in [
        // No assertion and no deferred key.
        (
            "plain",
            vec!["INSERT INTO ranges(lo,hi,width,id) VALUES(1,2,3,#id)".to_string()],
        ),
        // team_cap.
        (
            "one_assertion",
            vec![format!(
                "INSERT INTO members(team,email,id) VALUES({red},'s@example',#id)"
            )],
        ),
        // A deferred key and order_total.
        (
            "deferred_key_and_assertion",
            vec![
                format!("INSERT INTO lines(parent,amount,id) VALUES({order},4,#id)"),
                format!("UPDATE orders SET total=4 WHERE id={order}"),
            ],
        ),
    ] {
        let statements: Vec<&str> = statements.iter().map(String::as_str).collect();
        devices[0].commit(&c, &statements).await.unwrap();
        let frames = devices[0].fresh().await;
        let before = crate::sqlite::statements();
        devices[1].receive(&frames).await;
        counts.push((label, crate::sqlite::statements() - before));
    }
    println!("P5 receive_statements {counts:?}");
    // Replayed rows keep no record: the undo of an unsealed member is all
    // a replayed row stores beside the table.
    let inner = devices[1]
        .replica
        .inner
        .lock(crate::replica::Class::Background)
        .await;
    let sizes = crate::storage::rows(
        &inner.conn,
        "SELECT (SELECT COUNT(*) FROM secure_rows), MAX(length(undo)) FROM secure_replayed",
    )
    .await
    .unwrap();
    println!("P5 replayed_row_records/max_undo_bytes {sizes:?}");
    assert_eq!(sizes[0][0], SqlValue::Integer(0));
}
