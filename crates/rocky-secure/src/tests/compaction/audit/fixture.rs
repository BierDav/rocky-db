use super::*;

pub(super) struct AuditFixture {
    pub directory: TempDir,
    pub lineage: Lineage,
    pub node: PrivateKey,
    pub replica: Replica,
}
impl AuditFixture {
    pub async fn new(based: bool) -> Self {
        let directory = TempDir::new().unwrap();
        let lineage = Lineage::new();
        let node = PrivateKey::new();
        let replica = open(&lineage, &directory, "audit", &node).await;
        follow_main(&lineage, &replica).await;
        write_both(&replica, "base").await;
        if based {
            seal(&lineage, &replica).await;
            replica
                .set_role(crate::RoleConfig {
                    role: crate::ReplicaRole::Partial,
                    ..Default::default()
                })
                .await
                .unwrap();
            replica.subscribe(lineage.scope("items")).await.unwrap();
            replica.compact(lineage.domain, 0).await.unwrap();
            replica
                .set_role(crate::RoleConfig::default())
                .await
                .unwrap();
        }
        write_both(&replica, "suffix").await;
        Self {
            directory,
            lineage,
            node,
            replica,
        }
    }
}
pub(super) async fn write_both(replica: &Replica, key: &str) {
    insert(replica, key, key).await;
    identity_insert(
        &session(replica).await,
        "INSERT INTO tags(key,label) VALUES(?,?)",
        vec![text(key), text(key)],
    )
    .await
    .unwrap();
}
pub(super) async fn singles(
    replica: &Replica,
    scopes: &[ResourceScope],
) -> Vec<(ResourceScope, crate::AuditReport)> {
    let mut reports = Vec::new();
    for scope in scopes {
        reports.push((*scope, replica.audit(*scope).await.unwrap()));
    }
    reports
}
/// Every authoritative SQL table; scratch and SQLite allocation counters are not evidence.
pub(in crate::tests) async fn snapshot<A: rocky_core::RowApplication>(
    replica: &EncryptedReplica<A>,
) -> Vec<(String, Vec<Vec<SqlValue>>)> {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    let tables = rows(&inner.conn, "SELECT name FROM sqlite_schema WHERE type='table' AND name<>'secure_checkpoint_scratch' AND name NOT LIKE 'sqlite_%' ORDER BY name").await.unwrap();
    let mut state = Vec::new();
    for table in tables {
        let SqlValue::Text(name) = &table[0] else {
            panic!("table name")
        };
        let columns = rows(&inner.conn, &format!("PRAGMA table_info(\"{name}\")"))
            .await
            .unwrap()
            .len();
        let order = (1..=columns)
            .map(|index| index.to_string())
            .collect::<Vec<_>>()
            .join(",");
        state.push((
            name.clone(),
            rows(
                &inner.conn,
                &format!("SELECT * FROM \"{name}\" ORDER BY {order}"),
            )
            .await
            .unwrap(),
        ));
    }
    state
}
pub(super) async fn assert_clean(replica: &Replica) {
    assert_eq!(replica.audit_scratch_flags().await, (false, false));
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    assert!(
        rows(&inner.conn, "SELECT 1 FROM secure_checkpoint_scratch")
            .await
            .unwrap()
            .is_empty()
    );
}
