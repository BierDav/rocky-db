use super::*;
use crate::replica::roles::FrontierReply;
use crate::tests::group_sync_measurement::fixture::Fixture;
use rocky_core::{Right, TypedRows};

type Replica = EncryptedReplica<TypedRows>;

async fn pair<C: RowApplication, S: RowApplication>(
    client: &EncryptedReplica<C>,
    server: &EncryptedReplica<S>,
) -> (NativeSession, NativeSession) {
    let (cn, cc) = {
        let i = client.inner.lock(crate::replica::Class::Background).await;
        (i.config.node.clone(), i.config.credentials.clone())
    };
    let (sn, sc) = {
        let i = server.inner.lock(crate::replica::Class::Background).await;
        (i.config.node.clone(), i.config.credentials.clone())
    };
    super::link::testing::sessions((client, cn, cc), (server, sn, sc))
        .await
        .unwrap()
}

async fn open(f: &Fixture, dir: &std::path::Path, name: &str, rights: &[Right]) -> Replica {
    f.open(
        &dir.join(name),
        PrivateKey::new(),
        f.grants(None, rights),
        None,
        vec![],
    )
    .await
}

#[tokio::test]
async fn an_unshared_partition_does_not_end_held_recovery_of_other_scopes() {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::new(1);
    let client = open(&f, root.path(), "client.db", &[Right::Read]).await;
    let server = open(&f, root.path(), "server.db", &[Right::Read]).await;
    let private = f.scope("customers", 1);
    let shared = f.scope("customers", 2);
    for value in [1, 2] {
        for replica in [&client, &server] {
            replica
                .register_partition(f.scope("customers", value), f.tuple("customers", value))
                .await
                .unwrap();
        }
        client.install_key(f.key("customers", value)).await.unwrap();
    }
    server.install_key(f.key("customers", 2)).await.unwrap();
    let (mut c, mut s) = pair(&client, &server).await;
    let ((), served) = tokio::join!(
        async {
            assert!(!c.sync_held_changes(&client, private, 8192).await.unwrap());
            assert!(!c.offered.contains(&private));
            assert!(!c.sync_held_changes(&client, shared, 8192).await.unwrap());
            assert!(c.offered.contains(&shared));
            c.close().await.unwrap();
        },
        s.serve_to_end(&server)
    );
    served.unwrap();
}

#[tokio::test]
async fn held_partition_proofs_cross_tips_without_admitting_current_rows() {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::new(1);
    let client = open(&f, root.path(), "client.db", &[Right::Read]).await;
    let server = open(&f, root.path(), "server.db", &[Right::Read]).await;
    let scope = f.scope("customers", 1);
    for replica in [&client, &server] {
        replica
            .register_partition(scope, f.tuple("customers", 1))
            .await
            .unwrap();
        replica.install_key(f.key("customers", 1)).await.unwrap();
    }
    let (mut c, mut s) = pair(&client, &server).await;
    assert!(c.follows_same_tip(&client).await);
    let (node, credentials) = {
        let inner = client.inner.lock(crate::replica::Class::Background).await;
        (
            inner.config.node.public_key(),
            inner.config.credentials.clone(),
        )
    };
    // A link's reported tip may differ while its metadata is being reconciled.
    server
        .admit_peer(node, &credentials, rocky_core::TipId([71; 32]))
        .await
        .unwrap();
    let (node, credentials) = {
        let inner = server.inner.lock(crate::replica::Class::Background).await;
        (
            inner.config.node.public_key(),
            inner.config.credentials.clone(),
        )
    };
    client
        .admit_peer(node, &credentials, rocky_core::TipId([71; 32]))
        .await
        .unwrap();
    assert!(!c.follows_same_tip(&client).await);
    let ((), served) = tokio::join!(
        async {
            assert!(!c.sync_held_changes(&client, scope, 8192).await.unwrap());
            assert!(c.catch_up(&client, scope, 8192).await.is_err());
            c.close().await.unwrap();
        },
        s.serve_to_end(&server)
    );
    served.unwrap();
}

async fn refusal(client: &Replica, server: &Replica, message: Message) -> (String, u64, u64) {
    let (mut c, mut s) = pair(client, server).await;
    c.send(message).await.unwrap();
    let before = s.sent;
    s.serve_once(server).await.unwrap();
    let messages = s.sent - before;
    let error = c.answered().await.err().expect("refusal").to_string();
    let count = c.received;
    let (left, right) = tokio::join!(s.close(), c.close());
    left.unwrap();
    right.unwrap();
    (error, messages, count)
}

fn requests(scope: ResourceScope) -> Vec<Message> {
    let frontier = ScopeFrontier {
        scope,
        logs: Vec::new(),
    };
    vec![
        RowMessage::Range {
            frontier: frontier.clone(),
            after: None,
            quota: 1024,
        }
        .into(),
        RowMessage::Held { frontier }.into(),
        RowMessage::Push {
            scope,
            frames: Vec::new(),
            voids: Vec::new(),
        }
        .into(),
        RowMessage::FrontierQuery { scope }.into(),
        CheckpointMessage::Pruned { scope, after: None }.into(),
        CheckpointMessage::CheckpointOffer { scope }.into(),
        CheckpointMessage::SealOffer {
            scope,
            seal: [0; 32],
        }
        .into(),
        CheckpointMessage::CheckpointPull {
            scope,
            checkpoint: [0; 32],
            after: None,
            quota: 1024,
            window: 4,
        }
        .into(),
        RowMessage::Read {
            scope,
            after: None,
            max_rows: 1,
        }
        .into(),
    ]
}

async fn transcript_case(custody: bool) {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::new(1);
    let server = open(
        &f,
        root.path(),
        "server.db",
        if custody {
            &[Right::Custody]
        } else {
            &[Right::Read]
        },
    )
    .await;
    let member = open(&f, root.path(), "member.db", &[Right::Read]).await;
    let scope = f.scope("customers", 1);
    server
        .register_partition(scope, f.tuple("customers", 1))
        .await
        .unwrap();
    if !custody {
        server.install_key(f.key("customers", 1)).await.unwrap();
    }
    server.subscribe(scope).await.unwrap();
    server.subscribe(f.scope("products", 0)).await.unwrap();
    // A reader server: the member even knows the tuple, yet lacks the reader
    // key. Keyless custody accepts the tuple as proof, which a link offers at
    // open, so there the member must not know it.
    if !custody {
        member
            .register_partition(scope, f.tuple("customers", 1))
            .await
            .unwrap();
    }
    let unknown = ResourceScope {
        encryption: [203; 32],
        ..scope
    };
    let (node, credentials) = {
        let inner = member.inner.lock(crate::replica::Class::Background).await;
        (inner.config.node.clone(), inner.config.credentials.clone())
    };
    for (known, missing) in requests(scope).into_iter().zip(requests(unknown)) {
        let known = refusal(&member, &server, known).await;
        let missing = refusal(&member, &server, missing).await;
        assert_eq!(known, missing);
        assert!(known.0.contains("request not permitted"));
        assert_eq!(known.1, 1);
    }
    assert!(
        server
            .held_scopes(node.public_key(), &credentials, None)
            .await
            .unwrap()
            .0
            .contains(&scope)
    );
    let (mut c, mut s) = pair(&member, &server).await;
    c.send(RowMessage::ScopesQuery { after: None })
        .await
        .unwrap();
    s.serve_once(&server).await.unwrap();
    let RowMessage::Scopes { scopes, next } = c.reply().await.unwrap() else {
        panic!("scopes reply")
    };
    assert_eq!(scopes, vec![f.scope("products", 0)]);
    assert!(next.is_none());
    for asked in [scope, unknown] {
        c.send(FrontierMessage::FrontiersQuery {
            frontiers: vec![ScopeFrontier {
                scope: asked,
                logs: vec![],
            }],
            partitions: vec![],
            proofs: vec![],
        })
        .await
        .unwrap();
        s.serve_once(&server).await.unwrap();
        let FrontierMessage::Frontiers { states } = c.reply().await.unwrap() else {
            panic!("frontiers reply")
        };
        assert!(matches!(states.as_slice(), [FrontierReply::Refused(scope)] if *scope == asked));
    }
}

#[tokio::test]
async fn every_reader_request_hides_an_unproved_partition() {
    transcript_case(false).await;
}
#[tokio::test]
async fn every_custody_request_hides_an_unproved_partition() {
    transcript_case(true).await;
}

#[tokio::test]
async fn proofs_are_session_bound_bounded_and_remembered() {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::new(1);
    let server = open(&f, root.path(), "server.db", &[Right::Read]).await;
    let member = open(&f, root.path(), "member.db", &[Right::Read]).await;
    let scope = f.scope("customers", 1);
    f.keys(&server, 1, &["customers"]).await;
    // Opened before the member holds the partition, so its open proves nothing.
    let second = pair(&member, &server).await;
    f.keys(&member, 1, &["customers"]).await;
    server.subscribe(scope).await.unwrap();
    f.keys(&server, 2, &["customers"]).await;
    server.subscribe(f.scope("customers", 2)).await.unwrap();
    let (mut c, mut s) = pair(&member, &server).await;
    let captured = member.holding_proofs(c.binding, &[scope]).await.unwrap();
    let (mut c2, mut s2) = second;
    let query = |proofs| FrontierMessage::FrontiersQuery {
        frontiers: vec![ScopeFrontier {
            scope,
            logs: vec![],
        }],
        partitions: vec![],
        proofs,
    };
    c.send(query(captured.clone())).await.unwrap();
    s.serve_once(&server).await.unwrap();
    let FrontierMessage::Frontiers { states } = c.reply().await.unwrap() else {
        panic!("frontiers")
    };
    assert!(matches!(states.as_slice(), [FrontierReply::Held(_)]));
    // A later raw scoped request needs no proof or extra message.
    let before = s.sent;
    c.send(RowMessage::FrontierQuery { scope }).await.unwrap();
    s.serve_once(&server).await.unwrap();
    assert!(matches!(
        c.reply::<RowMessage>().await.unwrap(),
        RowMessage::Frontier { .. }
    ));
    assert_eq!(s.sent - before, 1);
    c.send(RowMessage::ScopesQuery { after: None })
        .await
        .unwrap();
    s.serve_once(&server).await.unwrap();
    let RowMessage::Scopes { scopes, next } = c.reply().await.unwrap() else {
        panic!("scopes")
    };
    assert_eq!(scopes, vec![scope]);
    assert!(next.is_none());
    c2.send(query(captured.clone())).await.unwrap();
    s2.serve_once(&server).await.unwrap();
    let FrontierMessage::Frontiers { states } = c2.reply().await.unwrap() else {
        panic!("frontiers")
    };
    assert!(matches!(states.as_slice(), [FrontierReply::Refused(_)]));
    let proof = captured[0].1[0].clone();
    c2.send(query(vec![(scope, vec![proof; 5])])).await.unwrap();
    s2.serve_once(&server).await.unwrap();
    assert!(matches!(c2.reply::<FrontierMessage>().await,
        Err(Error::Application(cause)) if cause.downcast_ref::<RequestRefusal>() == Some(&RequestRefusal::NotPermitted)));
}

#[tokio::test]
async fn retained_siblings_and_previous_generations_prove_but_fresh_peers_refuse() {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::new(1);
    let retained = open(&f, root.path(), "retained.db", &[Right::Read]).await;
    let fresh = open(&f, root.path(), "fresh.db", &[Right::Read]).await;
    let member = open(&f, root.path(), "member.db", &[Right::Read]).await;
    let scope = f.scope("customers", 1);
    for replica in [&retained, &fresh, &member] {
        replica
            .register_partition(scope, f.tuple("customers", 1))
            .await
            .unwrap();
    }
    let mut sibling_keys = [[11; 32], [12; 32]];
    sibling_keys.sort_by_key(|key| rocky_core::KeyEpoch::new(2, key));
    let newest = sibling_keys[1];
    for (generation, key) in [(1, [10; 32]), (2, sibling_keys[0]), (2, newest)] {
        retained
            .install_key_epoch(KeyMaterial::new(scope, generation, key))
            .await
            .unwrap();
    }
    fresh
        .install_key_epoch(KeyMaterial::new(scope, 2, newest))
        .await
        .unwrap();
    // Only the previous generation, then only the losing sibling.
    for (generation, key) in [(1, [10; 32]), (2, sibling_keys[0])] {
        member
            .install_key_epoch(KeyMaterial::new(scope, generation, key))
            .await
            .unwrap();
        if generation == 2 {
            member
                .retire_key_epoch(scope, rocky_core::KeyEpoch::new(1, &[10; 32]))
                .await
                .unwrap();
        }
        for (server, accepted) in [(&retained, true), (&fresh, false)] {
            let (mut c, mut s) = pair(&member, server).await;
            let serve = s.serve_to_end(server);
            let ask = async {
                let exchange = c.changed_scopes(&member, &[scope]).await.unwrap();
                assert_eq!(exchange.refused.is_empty(), accepted);
                c.close().await.unwrap();
            };
            let (served, ()) = tokio::join!(serve, ask);
            served.unwrap();
        }
    }
    for generation in 3..=7 {
        member
            .install_key_epoch(KeyMaterial::new(scope, generation, [generation as u8; 32]))
            .await
            .unwrap();
    }
    let proofs = member.holding_proofs([1; 32], &[scope]).await.unwrap();
    assert_eq!(proofs[0].1.len(), 4);
    assert!(proofs[0].1.windows(2).all(|p| p[0].epoch > p[1].epoch));
}

#[tokio::test]
async fn custody_tuple_offers_relay_only_with_both_grants() {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::new(1);
    let writer = f
        .open(
            &root.path().join("writer.db"),
            PrivateKey::new(),
            f.grants(None, &[Right::Read, Right::Insert]),
            Some((PrivateKey::new(), 1)),
            vec![],
        )
        .await;
    let custody = open(&f, root.path(), "custody.db", &[Right::Custody]).await;
    let stranger = f
        .open(
            &root.path().join("stranger.db"),
            PrivateKey::new(),
            f.grants(Some(&[2]), &[Right::Custody]),
            None,
            vec![],
        )
        .await;
    let scope = f.scope("customers", 1);
    f.keys(&writer, 1, &["customers"]).await;
    f.insert(&writer, 1, &["customers"], [1; 32]).await;
    let (mut c, mut s) = pair(&writer, &custody).await;
    let serve = s.serve_to_end(&custody);
    let ask = async {
        c.changed_scopes(&writer, &[scope]).await.unwrap();
        assert_eq!(
            c.push(&writer, scope, MAX_SECURE_FRAME / 2)
                .await
                .unwrap()
                .frames,
            1
        );
        c.close().await.unwrap();
    };
    let (served, ()) = tokio::join!(serve, ask);
    served.unwrap();
    assert!(custody.key_epochs(scope).await.is_empty());
    // Custody asks the reader with its tuple and grant, without any reader key.
    let (mut c, mut s) = pair(&custody, &writer).await;
    let serve = s.serve_to_end(&writer);
    let ask = async {
        assert!(
            c.changed_scopes(&custody, &[scope])
                .await
                .unwrap()
                .refused
                .is_empty()
        );
        c.close().await.unwrap();
    };
    let (served, ()) = tokio::join!(serve, ask);
    served.unwrap();
    let (mut c, mut s) = pair(&writer, &stranger).await;
    let serve = s.serve_to_end(&stranger);
    let ask = async {
        assert_eq!(
            c.changed_scopes(&writer, &[scope]).await.unwrap().refused,
            vec![scope]
        );
        c.close().await.unwrap();
    };
    let (served, ()) = tokio::join!(serve, ask);
    served.unwrap();
    for server in [&writer, &custody] {
        let (mut c, mut s) = pair(&stranger, server).await;
        let key = f.key("customers", 1);
        c.send(FrontierMessage::FrontiersQuery {
            frontiers: vec![ScopeFrontier {
                scope,
                logs: vec![],
            }],
            partitions: vec![(scope, f.tuple("customers", 1))],
            proofs: vec![(
                scope,
                vec![HoldingProof {
                    epoch: key.generation,
                    value: key_proof(&key, c.binding).unwrap(),
                }],
            )],
        })
        .await
        .unwrap();
        s.serve_once(server).await.unwrap();
        let FrontierMessage::Frontiers { states } = c.reply().await.unwrap() else {
            panic!("frontiers")
        };
        assert!(matches!(states.as_slice(), [FrontierReply::Refused(_)]));
    }
    let inner = stranger.inner.lock(crate::replica::Class::Background).await;
    let registered = crate::storage::rows(&inner.conn, "SELECT scope FROM secure_partitions")
        .await
        .unwrap();
    assert!(registered.is_empty());
}

#[tokio::test]
async fn frontier_acknowledgments_require_proved_custody() {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::new(1);
    let writer = f
        .open(
            &root.path().join("writer.db"),
            PrivateKey::new(),
            f.grants(None, &[Right::Read, Right::Insert]),
            Some((PrivateKey::new(), 1)),
            vec![],
        )
        .await;
    let member = open(&f, root.path(), "member.db", &[Right::Read]).await;
    f.keys(&writer, 1, &["customers"]).await;
    member
        .register_partition(f.scope("customers", 1), f.tuple("customers", 1))
        .await
        .unwrap();
    f.insert(&writer, 1, &["customers"], [1; 32]).await;
    let scope = f.scope("customers", 1);
    let frontier = member.frontier(scope).await.unwrap();
    let refused = refusal(&member, &writer, RowMessage::Held { frontier }.into()).await;
    assert_eq!(refused.1, 1);
    // A reader that proves the partition receives and acknowledges its frontier.
    f.keys(&member, 1, &["customers"]).await;
    let (mut c, mut s) = pair(&member, &writer).await;
    let (served, ()) = tokio::join!(s.serve_to_end(&writer), async {
        assert_eq!(
            c.catch_up(&member, scope, 16 * 1024).await.unwrap().frames,
            1
        );
        c.close().await.unwrap();
    });
    served.unwrap();
    assert_eq!(
        member.frontier(scope).await.unwrap(),
        writer.frontier(scope).await.unwrap()
    );
}

#[tokio::test]
async fn saved_peer_resolution_proves_the_pinned_reference_without_opening_a_session() {
    let f = Fixture::new(1);
    let root = tempfile::tempdir().unwrap();
    let server = open(&f, root.path(), "resolver", &[Right::Read]).await;
    let (node, credentials) = {
        let inner = server.inner.lock(crate::replica::Class::Background).await;
        (inner.config.node.clone(), inner.config.credentials.clone())
    };
    for expected in [node.public_key(), PrivateKey::new().public_key()] {
        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let (resolved, accepted) = tokio::join!(
            NativeSession::resolve_peer(
                rocky_core::net::Stream::new(client_stream),
                rocky_credentials::PeerId::of(expected)
            ),
            super::link::Link::accept_or_resolve(
                server_stream,
                &server,
                node.clone(),
                credentials.clone(),
            )
        );
        assert!(accepted.unwrap().is_none());
        if expected == node.public_key() {
            assert_eq!(resolved.unwrap(), expected);
        } else {
            assert!(resolved.is_err());
        }
    }
}

/// A no-frames base of a concrete partition moves to a custodian that
/// proves its tuple, while an unproved reader's offers of it get the
/// common refusal; a partitioned table's own scope signs none.
#[tokio::test]
async fn a_no_frames_partition_base_moves_by_its_tuple_and_stays_hidden() {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::new(1);
    // The server reads the partition without its key and holds no history.
    let server = open(&f, root.path(), "server.db", &[Right::Read, Right::Insert]).await;
    let scope = f.scope("customers", 1);
    server
        .register_partition(scope, f.tuple("customers", 1))
        .await
        .unwrap();
    server.install_key(f.key("products", 0)).await.unwrap();
    crate::tests::seal_and_compact(&server, &f.publisher, f.domain).await;
    let base = server.checkpoint(scope).await.unwrap();
    assert!(base.statement.no_frames());
    assert_eq!(base.statement.partition, Some(f.tuple("customers", 1)));
    let sealed = base.statement.seal.unwrap();
    let no_frames: Vec<_> = crate::storage::rows(
        &server
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .conn,
        "SELECT signed FROM secure_checkpoints",
    )
    .await
    .unwrap()
    .into_iter()
    .filter_map(|row| match &row[0] {
        rocky_core::SqlValue::Blob(bytes) => Some(SignedCheckpoint::from_bytes(bytes).unwrap()),
        _ => None,
    })
    .filter(|signed| signed.statement.no_frames())
    .map(|signed| signed.statement.scope)
    .collect();
    assert_eq!(no_frames, vec![scope]);
    // A custodian that proves the tuple imports it, by either offer.
    let custodian = open(&f, root.path(), "custodian.db", &[Right::Custody]).await;
    custodian
        .register_partition(scope, f.tuple("customers", 1))
        .await
        .unwrap();
    crate::tests::exchange_graphs(&server, &custodian, f.domain).await;
    let (node, credentials) = {
        let inner = custodian
            .inner
            .lock(crate::replica::Class::Background)
            .await;
        (
            inner.config.node.public_key(),
            inner.config.credentials.clone(),
        )
    };
    server
        .admit_peer(node, &credentials, custodian.followed_tip().await)
        .await
        .unwrap();
    let offered = server
        .checkpoint_offer(node, &credentials, scope)
        .await
        .unwrap()
        .expect("a no-frames partition base");
    assert_eq!(offered.id().unwrap(), base.id().unwrap());
    let at_seal = server
        .seal_checkpoint_offer(node, &credentials, scope, sealed)
        .await
        .unwrap()
        .expect("the same base at its seal");
    assert_eq!(at_seal.id().unwrap(), base.id().unwrap());
    custodian.begin_rebootstrap(offered).await.unwrap();
    custodian.finish_rebootstrap(scope).await.unwrap();
    assert_eq!(
        custodian.checkpoint(scope).await.unwrap().id().unwrap(),
        base.id().unwrap()
    );
    assert!(custodian.key_epochs(scope).await.is_empty());
    // A reader that guesses the tuple learns nothing a missing scope hides.
    let member = open(&f, root.path(), "member.db", &[Right::Read]).await;
    let unknown = ResourceScope {
        encryption: [203; 32],
        ..scope
    };
    for (known, missing) in [
        (
            CheckpointMessage::CheckpointOffer { scope }.into(),
            CheckpointMessage::CheckpointOffer { scope: unknown }.into(),
        ),
        (
            CheckpointMessage::SealOffer {
                scope,
                seal: sealed,
            }
            .into(),
            CheckpointMessage::SealOffer {
                scope: unknown,
                seal: sealed,
            }
            .into(),
        ),
    ] {
        let known = refusal(&member, &server, known).await;
        let missing = refusal(&member, &server, missing).await;
        assert_eq!(known, missing);
        assert!(known.0.contains("request not permitted"));
        assert_eq!(known.1, 1);
    }
}

#[tokio::test]
async fn a_refused_scope_does_not_end_the_request_channel() {
    let root = tempfile::tempdir().unwrap();
    let f = Fixture::new(1);
    let server = open(&f, root.path(), "server.db", &[Right::Read, Right::Insert]).await;
    let client = open(&f, root.path(), "client.db", &[Right::Read]).await;
    f.keys(&server, 1, &["customers"]).await;
    f.keys(&client, 1, &["customers"]).await;
    let allowed = f.scope("customers", 1);
    let refused = f.scope("customers", 2);
    let (mut c, mut s) = pair(&client, &server).await;
    let (served, ()) = tokio::join!(s.serve_to_end(&server), async {
        c.send(RowMessage::Range {
            frontier: ScopeFrontier {
                scope: refused,
                logs: vec![],
            },
            after: None,
            quota: 8192,
        })
        .await
        .unwrap();
        let error = c.answered().await.err().unwrap();
        assert!(matches!(error, Error::Application(cause) if cause.is::<RequestRefusal>()));
        assert!(!c.catch_up(&client, allowed, 8192).await.unwrap().behind);
        c.close().await.unwrap();
    });
    served.unwrap();
}
