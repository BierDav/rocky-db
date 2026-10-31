//! Local admission evidence survives row reclamation and fresh-node adoption.
use super::*;
use crate::storage::rows;

async fn records(replica: &Replica, sql: &str) -> Vec<Vec<SqlValue>> {
    rows(
        &replica
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .conn,
        sql,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn a_revoked_fresh_restore_config_does_not_rebind_the_backup() {
    let lineage = Lineage::pinned(249);
    let dir = TempDir::new().unwrap();
    let keys = [250, 251, 252].map(|seed| PrivateKey::from_bytes(&[seed; 32]));
    let source = open(&lineage, &dir, "source", &keys[0]).await;
    insert(&source, "one", "before backup").await;
    let path = dir.path().join("restored.db");
    source.backup_into(&path).await.unwrap();
    let mut rejected = lineage.config(3, &keys[1]);
    rejected.revocations = crate::tests::revoking(
        lineage.publisher(),
        lineage.domain.app,
        &[keys[1].public_key()],
        &[],
    );
    let result =
        EncryptedReplica::open_restored(&path, lineage.app(3), rejected, keys[0].public_key())
            .await;
    let error = match result {
        Ok(_) => panic!("revoked fresh identity cannot adopt a backup"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("revoked"), "{error}");
    // A different qualified fresh node can still adopt the untouched identity.
    let restored = EncryptedReplica::open_restored(
        &path,
        lineage.app(3),
        lineage.config(3, &keys[2]),
        keys[0].public_key(),
    )
    .await
    .unwrap();
    assert_eq!(
        restored.predecessors().await.unwrap(),
        vec![keys[0].public_key()]
    );
    assert_eq!(
        titles(&restored).await,
        vec![vec![text("one"), text("before backup")]]
    );
    restored.audit(lineage.scope("items")).await.unwrap();
}

#[derive(Debug)]
pub(super) struct Accounting {
    pub entries: i64,
    pub grants: i64,
    pub chains: i64,
    pub bounded: Vec<i64>,
    pub logical_bytes: usize,
}

pub(super) async fn accounting(
    replica: &Replica,
    path: &std::path::Path,
    cycle: usize,
) -> Accounting {
    let tables = [
        "secure_admission_entries",
        "secure_admission_claims",
        "secure_admission_carries",
        "secure_admission_context",
        "secure_identity_marks",
        "secure_identity_ledger",
        "secure_identity_summary",
        "secure_identity_own",
        "secure_identity_tables",
        "secure_identity_partitions",
    ];
    let mut logical_bytes = 0;
    // Logical integer fields count eight bytes; blobs count their encoded length.
    for table in tables {
        let query = if table == "secure_admission_entries" {
            "SELECT bytes,signature,chain FROM secure_admission_entries".to_string()
        } else {
            format!("SELECT * FROM {table}")
        };
        for row in records(replica, &query).await {
            for value in row {
                logical_bytes += match value {
                    SqlValue::Integer(_) | SqlValue::Real(_) => 8,
                    SqlValue::Blob(bytes) => bytes.len(),
                    SqlValue::Text(text) => text.len(),
                    SqlValue::Null => 0,
                };
            }
        }
    }
    let mut bounded = Vec::new();
    for table in [
        "secure_identity_marks",
        "secure_identity_summary",
        "secure_identity_own",
        "secure_identity_ledger",
        "secure_identity_tables",
        "secure_identity_partitions",
    ] {
        bounded.push(scalar(replica, &format!("SELECT count(*) FROM {table}")).await);
    }
    let mut inner = replica.inner.lock(crate::replica::Class::Background).await;
    inner.flush().unwrap();
    let modules = rows(
        &inner.conn,
        "SELECT name FROM pragma_module_list WHERE name='dbstat'",
    )
    .await
    .unwrap();
    let allocated = if modules.is_empty() {
        rows(&inner.conn, "PRAGMA page_count").await.unwrap()
    } else {
        rows(&inner.conn, "SELECT name,sum(pgsize) FROM dbstat WHERE name IN (SELECT name FROM sqlite_schema WHERE tbl_name LIKE 'secure_admission_%' OR tbl_name LIKE 'secure_identity_%') GROUP BY name ORDER BY name").await.unwrap()
    };
    let operation_pages = if modules.is_empty() {
        Vec::new()
    } else {
        rows(&inner.conn, "SELECT name,sum(pgsize) FROM dbstat WHERE name IN (SELECT name FROM sqlite_schema WHERE tbl_name='secure_operations') GROUP BY name ORDER BY name").await.unwrap()
    };
    let pages = rows(&inner.conn, "PRAGMA page_count").await.unwrap();
    let free = rows(&inner.conn, "PRAGMA freelist_count").await.unwrap();
    let mut wal_path = path.as_os_str().to_owned();
    wal_path.push("-wal");
    let wal_path = std::path::PathBuf::from(wal_path);
    let wal_bytes = || match std::fs::metadata(&wal_path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => panic!("WAL accounting: {error}"),
    };
    let wal_before = wal_bytes();
    rows(&inner.conn, "PRAGMA wal_checkpoint(TRUNCATE)")
        .await
        .unwrap();
    drop(inner);
    let main = std::fs::metadata(path).unwrap().len();
    let wal = wal_bytes();
    let graph = scalar(
        replica,
        "SELECT COALESCE(sum(length(statement)),0) FROM secure_tip_statements",
    )
    .await;
    println!(
        "admission accounting cycles={cycle}: logical={logical_bytes}B; allocated={allocated:?}; operation objects={operation_pages:?}; pages/free={pages:?}/{free:?}; main={main}B; WAL before/after truncate={wal_before}/{wal}B; graph={graph}B (separate)"
    );
    Accounting {
        entries: scalar(
            replica,
            "SELECT count(*) FROM secure_admission_entries WHERE kind=0",
        )
        .await,
        grants: scalar(
            replica,
            "SELECT count(*) FROM secure_admission_claims WHERE kind=0",
        )
        .await,
        chains: scalar(replica, "SELECT count(chain) FROM secure_admission_entries").await,
        bounded,
        logical_bytes,
    }
}
