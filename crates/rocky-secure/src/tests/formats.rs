use super::*;
use crate::storage::rows;
use std::collections::BTreeMap;

async fn format_template() -> (Fixture, TempDir, std::path::PathBuf, PrivateKey) {
    let f = Fixture::new();
    let template = TempDir::new().unwrap();
    let source = template.path().join("template.sqlite");
    let node = PrivateKey::new();
    let replica = EncryptedReplica::open(&source, f.app(), f.config(&node, f.full(), &[f.public]))
        .await
        .unwrap();
    replica
        .author(
            [1; 32],
            vec![change(f.public, 1, None, Some(f.app().name("base")))],
            vec![],
        )
        .await
        .unwrap();
    compacted_base(&replica, &f.publisher, f.public).await;
    replica
        .backup_into(&template.path().join("base.sqlite"))
        .await
        .unwrap();
    drop(replica);
    let source = template.path().join("base.sqlite");
    (f, template, source, node)
}

#[tokio::test]
async fn unsupported_checkpoint_formats_refuse_before_writes() {
    let (f, _template, source, node) = format_template().await;
    for version in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18] {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("replica.sqlite");
        std::fs::copy(&source, &path).unwrap();
        let replica =
            EncryptedReplica::open(&path, f.app(), f.config(&node, f.full(), &[f.public]))
                .await
                .unwrap();
        {
            let mut inner = replica.inner.lock(crate::replica::Class::Background).await;
            let records = rows(
                &inner.conn,
                "SELECT signed FROM secure_checkpoints WHERE signed IS NOT NULL",
            )
            .await
            .unwrap();
            let [rocky_core::SqlValue::Blob(bytes)] = records[0].as_slice() else {
                panic!("checkpoint");
            };
            let mut signed = SignedCheckpoint::from_bytes(bytes).unwrap();
            signed.statement.format = version;
            inner
                .conn
                .execute(
                    "UPDATE secure_checkpoints SET signed=? WHERE signed IS NOT NULL",
                    [encode(&signed).unwrap()],
                )
                .await
                .unwrap();
            inner.flush().unwrap();
        }
        drop(replica);
        let before = std::fs::read(&path).unwrap();
        let error = EncryptedReplica::open(&path, f.app(), f.config(&node, f.full(), &[f.public]))
            .await
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("unsupported checkpoint format"),
            "{error}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

#[tokio::test]
async fn unsupported_replica_formats_refuse_before_writes() {
    let (f, _template, source, node) = format_template().await;
    for version in (0..41).chain([42]) {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("replica.sqlite");
        std::fs::copy(&source, &path).unwrap();
        let replica =
            EncryptedReplica::open(&path, f.app(), f.config(&node, f.full(), &[f.public]))
                .await
                .unwrap();
        {
            let mut inner = replica.inner.lock(crate::replica::Class::Background).await;
            inner
                .conn
                .execute(
                    "UPDATE secure_metadata SET identity=?",
                    [encode(&(
                        format!("rocky.encrypted-replica.v{version}"),
                        rocky_credentials::genesis_tip(f.app().definition().hash()),
                        node.public_key(),
                    ))
                    .unwrap()],
                )
                .await
                .unwrap();
            inner.flush().unwrap();
        }
        drop(replica);
        let before = std::fs::read(&path).unwrap();
        let error = EncryptedReplica::open(&path, f.app(), f.config(&node, f.full(), &[f.public]))
            .await
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("unsupported encrypted replica format"),
            "{error}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

#[tokio::test]
async fn damaged_replica_schema_refuses_before_writes() {
    let (f, _template, source, node) = format_template().await;
    for damaged in [
        "DROP INDEX secure_rows_dead",
        "DROP INDEX secure_rows_shape",
        "DROP TABLE secure_record_shapes",
        "DROP TABLE secure_scope_shapes",
        "DROP TRIGGER secure_shapes_update",
        "DROP TABLE secure_row_positions",
        "DROP TABLE secure_birth_positions",
        "DROP TRIGGER secure_row_positions_delete",
        "DROP INDEX secure_row_position_operations",
    ] {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("replica.sqlite");
        std::fs::copy(&source, &path).unwrap();
        let replica =
            EncryptedReplica::open(&path, f.app(), f.config(&node, f.full(), &[f.public]))
                .await
                .unwrap();
        {
            let mut inner = replica.inner.lock(crate::replica::Class::Background).await;
            inner.conn.execute(damaged, ()).await.unwrap();
            inner.flush().unwrap();
        }
        drop(replica);
        let before = std::fs::read(&path).unwrap();
        let error = EncryptedReplica::open(&path, f.app(), f.config(&node, f.full(), &[f.public]))
            .await
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("secure") || error.to_string().contains("incremental"),
            "{damaged}: {error}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before, "{damaged}");
    }
}

#[tokio::test]
async fn unsupported_frames_leave_operation_projection_and_revision_unchanged() {
    let f = Fixture::new();
    let directory = TempDir::new().unwrap();
    let node = PrivateKey::new();
    let replica = EncryptedReplica::open(
        directory.path().join("replica.sqlite"),
        f.app(),
        f.config(&node, f.full(), &[f.public]),
    )
    .await
    .unwrap();
    let change = RowChange {
        scope: f.public,
        row: [7; 32],
        before: None,
        after: Some(f.app().name("kept")),
    };
    let frame = replica
        .author([1; 32], vec![change], Vec::new())
        .await
        .unwrap();
    let before = replica.snapshot(f.public).await.unwrap();
    let operations = rows(
        &replica
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .conn,
        "SELECT hash FROM secure_operations",
    )
    .await
    .unwrap();
    for version in (0..crate::wire::ROW_FORMAT).chain([crate::wire::ROW_FORMAT + 1]) {
        let mut operation = frame.operation().unwrap();
        operation.header.extensions.row_format = version;
        operation.header.sign(&node);
        let altered = frame.with_header(operation.header.to_bytes());
        let error = replica.receive(altered).await.unwrap_err();
        assert!(
            error.to_string().contains("unsupported row frame format"),
            "{error}"
        );
        let after = replica.snapshot(f.public).await.unwrap();
        assert_eq!(
            (after.revision, after.rows, after.complete),
            (before.revision, before.rows.clone(), before.complete)
        );
        assert_eq!(
            rows(
                &replica
                    .inner
                    .lock(crate::replica::Class::Background)
                    .await
                    .conn,
                "SELECT hash FROM secure_operations"
            )
            .await
            .unwrap(),
            operations
        );
    }
}

#[tokio::test]
async fn unsupported_payload_formats_refuse_before_custody_writes() {
    #[derive(Serialize)]
    struct Body {
        version: u8,
        proofs: BTreeMap<Commitment, crate::replica::moves::CreationProof>,
        carried: BTreeMap<Commitment, crate::replica::moves::Carried>,
        membership: Option<crate::wire::Membership>,
        writes: Vec<RowWrite>,
    }
    #[derive(Serialize)]
    struct Envelope {
        version: u8,
        #[serde(with = "serde_bytes")]
        body: Vec<u8>,
        creations: Vec<(Commitment, Commitment)>,
    }
    let f = Fixture::new();
    let directory = TempDir::new().unwrap();
    let node = PrivateKey::new();
    let replica = EncryptedReplica::open(
        directory.path().join("replica.sqlite"),
        f.app(),
        f.config(&node, f.full(), &[f.public]),
    )
    .await
    .unwrap();
    let sender = PrivateKey::new();
    let chain = crate::wire::Chain::new(f.credentials(&sender, f.full())).unwrap();
    let extensions = crate::wire::Extensions {
        tip: rocky_credentials::genesis_tip(f.app().definition().hash()),
        scope: f.public,
        generation: rocky_core::KeyEpoch::new(1, &[11; 32]),
        chain: chain.digest(),
        author: Some(
            f.config(&sender, f.full(), &[f.public])
                .credentials
                .author_number()
                .unwrap(),
        ),
        author_sequence: 0,
        row_format: crate::wire::ROW_FORMAT,
        births: Vec::new(),
        partition: None,
    };
    for (envelope_version, body_version, message) in [
        (0, 5, "unsupported creation witness format"),
        (2, 5, "unsupported creation witness format"),
        (1, 0, "unsupported bundle version"),
        (1, 1, "unsupported bundle version"),
        (1, 2, "unsupported bundle version"),
        (1, 3, "unsupported bundle version"),
        (1, 4, "unsupported bundle version"),
        (1, 5, "unsupported bundle version"),
        (1, 7, "unsupported bundle version"),
    ] {
        let plaintext = encode(&Envelope {
            version: envelope_version,
            body: encode(&Body {
                version: body_version,
                proofs: BTreeMap::new(),
                carried: BTreeMap::new(),
                membership: None,
                writes: vec![],
            })
            .unwrap(),
            creations: vec![],
        })
        .unwrap();
        let frame = crate::wire::author(
            &sender,
            extensions.clone(),
            chain.clone(),
            &[11; 32],
            (0, None, 1),
            vec![],
            &plaintext,
        )
        .unwrap();
        let error = replica.receive(frame).await.unwrap_err();
        assert!(error.to_string().contains(message), "{error}");
        assert!(
            rows(
                &replica
                    .inner
                    .lock(crate::replica::Class::Background)
                    .await
                    .conn,
                "SELECT hash FROM secure_operations"
            )
            .await
            .unwrap()
            .is_empty()
        );
        let snapshot = replica.snapshot(f.public).await.unwrap();
        assert_eq!(snapshot.revision, 0);
        assert!(snapshot.rows.is_empty());
    }
}

#[tokio::test]
async fn seal_author_positions_span_resource_logs_and_survive_reopen() {
    let f = Fixture::new();
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("replica.sqlite");
    let node = PrivateKey::new();
    let replica = EncryptedReplica::open(
        &path,
        f.app(),
        f.config(&node, f.full(), &[f.public, f.private]),
    )
    .await
    .unwrap();
    let first = replica
        .author(
            [31; 32],
            vec![change(f.public, 31, None, Some(f.app().name("first")))],
            vec![],
        )
        .await
        .unwrap();
    let second = replica
        .author(
            [32; 32],
            vec![change(f.private, 32, None, Some(f.app().salary("42")))],
            vec![],
        )
        .await
        .unwrap();
    let a = first.operation().unwrap().header;
    let b = second.operation().unwrap().header;
    assert_eq!((a.seq_num, b.seq_num), (0, 0));
    assert_eq!(
        (a.extensions.author_sequence, b.extensions.author_sequence),
        (0, 1)
    );
    drop(replica);
    let replica = EncryptedReplica::open(
        &path,
        f.app(),
        f.config(&node, f.full(), &[f.public, f.private]),
    )
    .await
    .unwrap();
    let third = replica
        .author(
            [33; 32],
            vec![change(f.public, 33, None, Some(f.app().name("third")))],
            vec![],
        )
        .await
        .unwrap();
    assert_eq!(
        third.operation().unwrap().header.extensions.author_sequence,
        2
    );
}

#[tokio::test]
async fn a_parent_checkpoint_binding_is_refused_even_with_the_same_version_label() {
    #[derive(Serialize)]
    struct Binding {
        cuts: u64,
        cut: Option<Commitment>,
        highest: u64,
    }
    #[derive(Serialize)]
    struct ParentStatement<'a> {
        #[serde(flatten)]
        current: &'a crate::CheckpointStatement,
        coordinated: Binding,
    }
    #[derive(Serialize)]
    struct ParentCheckpoint<'a> {
        statement: ParentStatement<'a>,
        node: PublicKey,
        credentials: CredentialChain,
        signature: p2panda_core::Signature,
    }
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let node = PrivateKey::new();
    let replica = EncryptedReplica::open(
        dir.path().join("parent.db"),
        f.app(),
        f.config(&node, f.full(), &[f.public]),
    )
    .await
    .unwrap();
    replica
        .author(
            [1; 32],
            vec![change(f.public, 1, None, Some(f.app().name("base")))],
            vec![],
        )
        .await
        .unwrap();
    let signed = compacted_base(&replica, &f.publisher, f.public).await;
    let credentials = f.credentials(&node, f.full());
    let parent = ParentCheckpoint {
        statement: ParentStatement {
            current: &signed.statement,
            coordinated: Binding {
                cuts: 0,
                cut: None,
                highest: 0,
            },
        },
        node: node.public_key(),
        credentials,
        signature: node.sign(b"parent fixture"),
    };
    let bytes = encode(&parent).unwrap();
    assert!(SignedCheckpoint::from_bytes(&bytes).is_err());
}
