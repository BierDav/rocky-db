use super::*;
use crate::storage::rows;

fn public(f: &Fixture, row: u8, name: &str) -> RowWrite {
    RowWrite::changed(change(f.public, row, None, Some(f.app().name(name))))
}
fn private(f: &Fixture, row: u8, salary: &str) -> RowWrite {
    RowWrite::changed(change(f.private, row, None, Some(f.app().salary(salary))))
}
/// 40 public names and one private salary: two public frames and one private.
fn hiring(f: &Fixture) -> Vec<RowWrite> {
    let mut writes: Vec<RowWrite> = (1..=40)
        .map(|row| public(f, row, &format!("employee-{row}")))
        .collect();
    writes.push(private(f, 1, "987654321"));
    writes
}
async fn open(
    f: &Fixture,
    path: &std::path::Path,
    node: &PrivateKey,
    grants: Vec<ResourceGrant>,
    keys: &[ResourceScope],
) -> EncryptedReplica<Employees> {
    EncryptedReplica::open(path, f.app(), f.config(node, grants, keys))
        .await
        .unwrap()
}
async fn live(replica: &EncryptedReplica<Employees>, scope: ResourceScope) -> usize {
    replica.snapshot(scope).await.unwrap().rows.len()
}
async fn operations(replica: &EncryptedReplica<Employees>) -> usize {
    rows(
        &replica
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .conn,
        "SELECT hash FROM secure_operations",
    )
    .await
    .unwrap()
    .len()
}
fn public_reader(f: &Fixture) -> Vec<ResourceGrant> {
    vec![grant(
        f.public,
        &[Right::Read, Right::Custody],
        &[f.app().field("display_name")],
    )]
}

#[tokio::test]
async fn a_bundle_spans_scopes_and_frames_and_each_reader_applies_its_partitions_atomically() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let both = [f.public, f.private];
    let alice = PrivateKey::new();
    let source = open(&f, &dir.path().join("a.db"), &alice, f.full(), &both).await;
    let frames = source
        .author_bundle([1; 32], hiring(&f), vec![])
        .await
        .unwrap();
    assert_eq!(frames.len(), 3);
    assert_eq!(
        frames
            .iter()
            .map(|frame| frame.scope().unwrap())
            .filter(|scope| *scope == f.private)
            .count(),
        1
    );
    assert_eq!(live(&source, f.public).await, 40);
    assert_eq!(live(&source, f.private).await, 1);
    // Only the private frame carries the salary, and only as ciphertext.
    for frame in &frames {
        assert!(
            !frame
                .to_bytes()
                .unwrap()
                .windows(9)
                .any(|bytes| bytes == b"987654321")
        );
    }

    // A full reader waits for every partition, in any order, across a restart.
    let carol = PrivateKey::new();
    let path = dir.path().join("c.db");
    let reader = open(&f, &path, &carol, f.full(), &both).await;
    let (private_frame, public_frames): (Vec<_>, Vec<_>) = frames
        .iter()
        .cloned()
        .partition(|frame| frame.scope().unwrap() == f.private);
    for frame in public_frames.iter().rev() {
        assert_eq!(
            reader.receive(frame.clone()).await.unwrap(),
            ReceiveStatus::PendingDependencies
        );
    }
    let page = reader.snapshot(f.public).await.unwrap();
    assert!(page.rows.is_empty() && !page.complete);
    let revision = page.revision;
    drop(reader);
    let reader = open(&f, &path, &carol, f.full(), &both).await;
    assert_eq!(live(&reader, f.public).await, 0);
    assert_eq!(
        reader.receive(private_frame[0].clone()).await.unwrap(),
        ReceiveStatus::Applied
    );
    for frame in &frames {
        assert_eq!(
            reader.receipt_status(frame.id().unwrap()).await.unwrap(),
            ReceiveStatus::Applied
        );
    }
    let page = reader.snapshot(f.public).await.unwrap();
    assert_eq!((page.rows.len(), page.complete), (40, true));
    // Both partitions became visible in the same commit.
    assert!(page.revision > revision);
    assert_eq!(
        reader.snapshot(f.private).await.unwrap().revision,
        page.revision
    );
    assert_eq!(
        reader.companion(f.private, [1; 32]).await.unwrap(),
        Companion::Present(f.app().salary("987654321"))
    );

    // A public reader cannot open the private member and does not wait for it.
    let bob = PrivateKey::new();
    let public_only = open(
        &f,
        &dir.path().join("b.db"),
        &bob,
        public_reader(&f),
        &[f.public],
    )
    .await;
    assert!(public_only.receive(private_frame[0].clone()).await.is_err());
    for frame in &public_frames {
        public_only.receive(frame.clone()).await.unwrap();
    }
    let page = public_only.snapshot(f.public).await.unwrap();
    assert_eq!((page.rows.len(), page.complete), (40, true));

    // A full reader whose private key is evicted applies the public view;
    // the private partition follows once the key is back.
    let dave = PrivateKey::new();
    let late = open(&f, &dir.path().join("d.db"), &dave, f.full(), &[f.public]).await;
    late.receive(private_frame[0].clone()).await.unwrap();
    for frame in &public_frames {
        late.receive(frame.clone()).await.unwrap();
    }
    assert_eq!(live(&late, f.public).await, 40);
    assert!(!late.snapshot(f.private).await.unwrap().complete);
    late.install_key(KeyMaterial::new(f.private, 1, [22; 32]))
        .await
        .unwrap();
    assert_eq!(live(&late, f.private).await, 1);
}

#[tokio::test]
async fn bundle_handles_return_the_same_frames_and_failures_commit_nothing() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let both = [f.public, f.private];
    let alice = PrivateKey::new();
    let path = dir.path().join("a.db");
    let source = open(&f, &path, &alice, f.full(), &both).await;

    // An injected failure before commit and a busy file leave no trace.
    source.inject_failure(1, 1).await;
    assert!(
        source
            .author_bundle([1; 32], hiring(&f), vec![])
            .await
            .is_err()
    );
    assert_eq!(operations(&source).await, 0);
    assert_eq!(live(&source, f.public).await, 0);
    let frames = source
        .author_bundle([1; 32], hiring(&f), vec![])
        .await
        .unwrap();
    let ids: Vec<_> = frames.iter().map(|frame| frame.id().unwrap()).collect();
    assert_eq!(operations(&source).await, 3);

    // The same handle returns the committed frames, also after a restart;
    // other writes under it conflict.
    let again = source
        .author_bundle([1; 32], hiring(&f), vec![])
        .await
        .unwrap();
    assert_eq!(
        again
            .iter()
            .map(|frame| frame.id().unwrap())
            .collect::<Vec<_>>(),
        ids
    );
    assert!(matches!(
        source
            .author_bundle([1; 32], vec![public(&f, 99, "other")], vec![])
            .await,
        Err(Error::Conflict)
    ));
    drop(source);
    let source = open(&f, &path, &alice, f.full(), &both).await;
    let reopened = source
        .author_bundle([1; 32], hiring(&f), vec![])
        .await
        .unwrap();
    assert_eq!(
        reopened
            .iter()
            .map(|frame| frame.id().unwrap())
            .collect::<Vec<_>>(),
        ids
    );

    // A handle restored by a recovery import has no member records; the
    // members are found through the first frame's sealed entries.
    source
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .conn
        .execute("DELETE FROM secure_bundle_handles", ())
        .await
        .unwrap();
    let recovered = source
        .author_bundle([1; 32], hiring(&f), vec![])
        .await
        .unwrap();
    assert_eq!(
        recovered
            .iter()
            .map(|frame| frame.id().unwrap())
            .collect::<Vec<_>>(),
        ids
    );

    // One denied member rolls back the whole bundle, including frames
    // already signed for other scopes.
    let public_writer = vec![grant(
        f.public,
        &[Right::Read, Right::Insert, Right::Update, Right::Custody],
        &[f.app().field("display_name")],
    )];
    let mixed = open(
        &f,
        &dir.path().join("m.db"),
        &PrivateKey::new(),
        [public_writer, vec![grant(f.private, &[Right::Read], &[])]].concat(),
        &both,
    )
    .await;
    assert!(
        mixed
            .author_bundle([2; 32], hiring(&f), vec![])
            .await
            .is_err()
    );
    assert_eq!(operations(&mixed).await, 0);
    assert_eq!(live(&mixed, f.public).await, 0);
    // The rolled back sequences are free: the next bundle starts at zero.
    let frames = mixed
        .author_bundle([3; 32], vec![public(&f, 1, "only")], vec![])
        .await
        .unwrap();
    assert_eq!(frames[0].operation().unwrap().header.seq_num, 0);

    // An invalid row in any scope fails the application's check of the
    // exact transaction; a row may appear only once.
    let mut invalid = hiring(&f);
    invalid.push(private(&f, 2, "not a number"));
    assert!(
        source
            .author_bundle([4; 32], invalid, vec![])
            .await
            .is_err()
    );
    let twice = vec![public(&f, 50, "a"), public(&f, 50, "b")];
    assert!(source.author_bundle([5; 32], twice, vec![]).await.is_err());
    let too_many: Vec<RowWrite> = (0..=MAX_BUNDLE_ROWS)
        .map(|row| {
            RowWrite::changed(RowChange {
                scope: f.public,
                row: rocky_core::commitment("row", &row.to_le_bytes()),
                before: None,
                after: Some(f.app().name("x")),
            })
        })
        .collect();
    assert!(matches!(
        source.author_bundle([6; 32], too_many, vec![]).await,
        Err(Error::Quota { .. })
    ));
}

#[tokio::test]
async fn members_that_disagree_reject_every_held_partition() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let both = [f.public, f.private];
    // Two files with one signing identity fork its private log: the private
    // sequence zero of one bundle is another bundle's member.
    let mallory = PrivateKey::new();
    let first = open(&f, &dir.path().join("m1.db"), &mallory, f.full(), &both).await;
    let second = open(&f, &dir.path().join("m2.db"), &mallory, f.full(), &both).await;
    let bundle = first
        .author_bundle(
            [1; 32],
            vec![public(&f, 5, "five"), private(&f, 5, "5")],
            vec![],
        )
        .await
        .unwrap();
    let other = second
        .author_bundle([1; 32], vec![private(&f, 6, "6")], vec![])
        .await
        .unwrap();
    let public_member = bundle
        .iter()
        .find(|frame| frame.scope().unwrap() == f.public)
        .unwrap()
        .clone();

    let reader = open(
        &f,
        &dir.path().join("c.db"),
        &PrivateKey::new(),
        f.full(),
        &both,
    )
    .await;
    reader.receive(public_member.clone()).await.unwrap();
    reader.receive(other[0].clone()).await.unwrap();
    assert_eq!(
        reader
            .receipt_status(public_member.id().unwrap())
            .await
            .unwrap(),
        ReceiveStatus::Rejected
    );
    assert_eq!(live(&reader, f.public).await, 0);
    // The other bundle is complete by itself, but never with this member.
    let reversed = open(
        &f,
        &dir.path().join("d.db"),
        &PrivateKey::new(),
        f.full(),
        &both,
    )
    .await;
    reversed.receive(other[0].clone()).await.unwrap();
    assert_eq!(live(&reversed, f.private).await, 1);
    reversed.receive(public_member.clone()).await.unwrap();
    assert_eq!(
        reversed
            .receipt_status(public_member.id().unwrap())
            .await
            .unwrap(),
        ReceiveStatus::Rejected
    );
    assert_eq!(live(&reversed, f.public).await, 0);
}

#[tokio::test]
async fn a_session_is_bound_to_its_authority_and_ends_when_it_changes() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let both = [f.public, f.private];
    let alice = PrivateKey::new();
    let replica = open(&f, &dir.path().join("a.db"), &alice, f.full(), &both).await;
    let session = replica.session(both.into()).await.unwrap();
    let status = session.status().await.unwrap();
    assert_eq!(status.node, alice.public_key());
    assert_ne!(status.principal, status.node);
    assert_eq!(status.readable, both.into());
    assert_eq!(status.writable, both.into());
    assert_eq!(status.revocations, crate::tests::unrevoked());
    assert_eq!(status.revoked, 0);

    // A transaction reads its own writes and commits them as one bundle.
    let mut transaction = session.transaction();
    transaction
        .insert(f.public, [1; 32], f.app().name("Alice"))
        .await
        .unwrap();
    transaction
        .insert(f.private, [1; 32], f.app().salary("100"))
        .await
        .unwrap();
    assert_eq!(
        transaction.get(f.public, [1; 32]).await.unwrap(),
        Companion::Present(f.app().name("Alice"))
    );
    assert_eq!(
        session.read(f.public, [1; 32]).await.unwrap(),
        Companion::Unavailable
    );
    let frames = transaction.commit([1; 32]).await.unwrap();
    assert_eq!(frames.len(), 2);
    assert_eq!(
        session.read(f.private, [1; 32]).await.unwrap(),
        Companion::Present(f.app().salary("100"))
    );

    // A narrower session cannot reach outside its set.
    let narrow = replica.session([f.public].into()).await.unwrap();
    assert!(narrow.read(f.private, [1; 32]).await.is_err());
    assert!(narrow.transaction().get(f.private, [1; 32]).await.is_err());

    // A concurrent writer makes the stale before image conflict.
    let mut stale = session.transaction();
    stale
        .update(
            f.public,
            [1; 32],
            f.app().name("Stale"),
            UpdateMode::Changed,
        )
        .await
        .unwrap();
    let mut fresh = session.transaction();
    fresh
        .update(
            f.public,
            [1; 32],
            f.app().name("Fresh"),
            UpdateMode::Changed,
        )
        .await
        .unwrap();
    fresh.commit([2; 32]).await.unwrap();
    assert!(matches!(stale.commit([3; 32]).await, Err(Error::Conflict)));

    // Attenuated credentials evict keys the new grants cannot read and end
    // every session, including a transaction staged before.
    let mut pending = session.transaction();
    pending
        .update(
            f.public,
            [1; 32],
            f.app().name("Pending"),
            UpdateMode::Changed,
        )
        .await
        .unwrap();
    let attenuated = vec![grant(
        f.public,
        &[Right::Read, Right::Update, Right::Custody],
        &[f.app().field("display_name")],
    )];
    replica
        .renew_credentials(f.credentials(&alice, attenuated))
        .await
        .unwrap();
    let before = operations(&replica).await;
    assert!(pending.commit([4; 32]).await.is_err());
    assert!(session.status().await.is_err());
    assert!(session.read(f.public, [1; 32]).await.is_err());
    assert_eq!(operations(&replica).await, before);
    assert!(replica.session(both.into()).await.is_err());
    let renewed = replica.session([f.public].into()).await.unwrap();
    assert_eq!(
        renewed.read(f.public, [1; 32]).await.unwrap(),
        Companion::Present(f.app().name("Fresh"))
    );
    assert!(replica.companion(f.private, [1; 32]).await.is_err());

    // A learned revocation ends sessions; one of the session's own links
    // ends its credentials.
    let mut racing = renewed.transaction();
    racing
        .update(
            f.public,
            [1; 32],
            f.app().name("Racing"),
            UpdateMode::Changed,
        )
        .await
        .unwrap();
    let root = replica
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .config
        .credentials
        .0[0]
        .id()
        .unwrap();
    replica
        .learn_revocations(&crate::tests::revoking(
            &f.publisher,
            f.app().definition().app,
            &[],
            &[root],
        ))
        .await
        .unwrap();
    assert!(racing.commit([5; 32]).await.is_err());
    assert!(replica.session([f.public].into()).await.is_err());
    assert_eq!(operations(&replica).await, before);
}

#[tokio::test]
async fn logout_drops_keys_and_ends_sessions() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let both = [f.public, f.private];
    let replica = open(
        &f,
        &dir.path().join("a.db"),
        &PrivateKey::new(),
        f.full(),
        &both,
    )
    .await;
    let session = replica.session(both.into()).await.unwrap();
    let mut transaction = session.transaction();
    transaction
        .insert(f.public, [1; 32], f.app().name("Alice"))
        .await
        .unwrap();
    transaction.commit([1; 32]).await.unwrap();
    replica.logout().await;
    assert!(session.read(f.public, [1; 32]).await.is_err());
    let after = replica.session(both.into()).await.unwrap();
    assert!(after.status().await.unwrap().readable.is_empty());
    assert_eq!(
        after.read(f.public, [1; 32]).await.unwrap(),
        Companion::Unavailable
    );
    assert!(
        after
            .transaction()
            .insert(f.public, [2; 32], f.app().name("Bob"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn field_limited_and_read_only_principals_cannot_widen_their_writes() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let both = [f.public, f.private];
    let alice = open(
        &f,
        &dir.path().join("a.db"),
        &PrivateKey::new(),
        f.full(),
        &both,
    )
    .await;
    let seed = alice
        .author_bundle([1; 32], vec![public(&f, 1, "Alice")], vec![])
        .await
        .unwrap();

    // Bob may update names only; the owner field controls permissions and
    // no row write changes it.
    let names = vec![grant(
        f.public,
        &[Right::Read, Right::Update, Right::Custody],
        &[f.app().field("display_name")],
    )];
    let bob = open(
        &f,
        &dir.path().join("b.db"),
        &PrivateKey::new(),
        names,
        &[f.public],
    )
    .await;
    bob.receive_all(seed).await;
    let session = bob.session([f.public].into()).await.unwrap();
    let mut transaction = session.transaction();
    transaction
        .update(
            f.public,
            [1; 32],
            f.app().name("Bobby"),
            UpdateMode::Assigned,
        )
        .await
        .unwrap();
    // Setting the owner, inserting and deleting are refused, and the
    // refused edits leave the staged row as it was.
    for refused in [
        transaction
            .update(
                f.public,
                [1; 32],
                [(f.app().field("owner"), b"bob".to_vec())].into(),
                UpdateMode::Changed,
            )
            .await,
        transaction
            .insert(f.public, [2; 32], f.app().name("New"))
            .await,
        transaction.delete(f.public, [1; 32]).await,
    ] {
        assert!(refused.is_err());
    }
    let writes = transaction.writes().await.unwrap();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].assigned, [f.app().field("display_name")].into());
    assert_eq!(writes[0].change.after, Some(f.app().name("Bobby")));
    let frames = transaction.commit([2; 32]).await.unwrap();
    assert_eq!(
        alice.receive(frames[0].clone()).await.unwrap(),
        ReceiveStatus::Applied
    );
    assert_eq!(
        alice.companion(f.public, [1; 32]).await.unwrap(),
        Companion::Present(f.app().name("Bobby"))
    );

    // Reading and custody rights are not write rights.
    let reader = vec![grant(
        f.public,
        &[Right::Read, Right::Custody],
        &[f.app().field("display_name"), f.app().field("owner")],
    )];
    let carol = open(
        &f,
        &dir.path().join("c.db"),
        &PrivateKey::new(),
        reader,
        &[f.public],
    )
    .await;
    let session = carol.session([f.public].into()).await.unwrap();
    assert!(session.status().await.unwrap().writable.is_empty());
    assert!(
        session
            .transaction()
            .update(
                f.public,
                [1; 32],
                f.app().name("Carol"),
                UpdateMode::Changed
            )
            .await
            .is_err()
    );
    // Changed values publish nothing for an equal write; assigned values do.
    let session = alice.session([f.public].into()).await.unwrap();
    let mut equal = session.transaction();
    let current = f.app().name("Bobby");
    equal
        .update(f.public, [1; 32], current.clone(), UpdateMode::Changed)
        .await
        .unwrap();
    assert!(equal.writes().await.unwrap().is_empty());
    assert!(equal.commit([3; 32]).await.unwrap().is_empty());
    let mut assigned = session.transaction();
    assigned
        .update(f.public, [1; 32], current, UpdateMode::Assigned)
        .await
        .unwrap();
    assert_eq!(assigned.commit([4; 32]).await.unwrap().len(), 1);
}

#[tokio::test]
async fn checkpoints_prune_held_partitions_and_a_late_partition_still_applies() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let both = [f.public, f.private];
    let source = open(
        &f,
        &dir.path().join("a.db"),
        &PrivateKey::new(),
        f.full(),
        &both,
    )
    .await;
    let frames = source
        .author_bundle([1; 32], hiring(&f), vec![])
        .await
        .unwrap();

    // Dave may read both scopes but holds only the public key for now.
    let dave = open(
        &f,
        &dir.path().join("d.db"),
        &PrivateKey::new(),
        f.full(),
        &[f.public],
    )
    .await;
    for status in dave.receive_all(frames.clone()).await {
        status.unwrap();
    }
    assert_eq!(live(&dave, f.public).await, 40);
    // Replay of bundle members reproduces the checkpointed projection.
    compacted_base(&dave, &f.publisher, f.public).await;
    assert_eq!(dave.audit(f.public).await.unwrap().replayed, 0);

    // Another node's custody lets the public members be pruned.
    let bob = PrivateKey::new();
    let custody = f.credentials(&bob, vec![grant(f.public, &[Right::Custody], &[])]);
    for frame in frames
        .iter()
        .filter(|frame| frame.scope().unwrap() == f.public)
    {
        dave.acknowledge(bob.public_key(), &custody, frame.id().unwrap(), false)
            .await
            .unwrap();
    }
    dave.set_retention_policy(
        f.public,
        RetentionPolicy {
            required: BTreeSet::new(),
            behind: BTreeSet::new(),
            copies: 1,
            window: 0,
        },
    )
    .await
    .unwrap();
    assert_eq!(dave.prune(f.public).await.unwrap().pruned, 2);

    // The private partition finds its pruned partners settled by the log.
    dave.install_key(KeyMaterial::new(f.private, 1, [22; 32]))
        .await
        .unwrap();
    assert_eq!(live(&dave, f.private).await, 1);
    assert_eq!(live(&dave, f.public).await, 40);
}

#[tokio::test]
async fn link_sessions_carry_bundles_and_each_peer_applies_its_partitions() {
    use network::{NativeSession, link};
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let both = [f.public, f.private];
    let (hub, carol, bob) = (PrivateKey::new(), PrivateKey::new(), PrivateKey::new());
    let hub_config = f.config(&hub, f.full(), &both);
    let hub_credentials = hub_config.credentials.clone();
    let source = EncryptedReplica::open(dir.path().join("hub.db"), f.app(), hub_config)
        .await
        .unwrap();
    let frames = source
        .author_bundle([1; 32], hiring(&f), vec![])
        .await
        .unwrap();
    let carol_config = f.config(&carol, f.full(), &both);
    let carol_credentials = carol_config.credentials.clone();
    let full = EncryptedReplica::open(dir.path().join("c.db"), f.app(), carol_config)
        .await
        .unwrap();
    let bob_config = f.config(&bob, public_reader(&f), &[f.public]);
    let bob_credentials = bob_config.credentials.clone();
    let public_only = EncryptedReplica::open(dir.path().join("b.db"), f.app(), bob_config)
        .await
        .unwrap();

    // The hub learns its peer from the link handshake; the stream is an
    // in-memory pipe, as any reliable ordered transport would be.
    let hub_end = || (&source, hub.clone(), hub_credentials.clone());
    let serve = |mut session: NativeSession| {
        let source = source.clone();
        async move { session.serve(&source).await }
    };

    // A full reader pulls the public partition first; nothing shows until
    // the private member arrives, then both apply in one commit.
    let (session, served) =
        link::testing::sessions((&full, carol.clone(), carol_credentials.clone()), hub_end())
            .await
            .unwrap();
    let client = async {
        let mut session = session;
        let public = session
            .sync_scope(&full, f.public, MAX_SECURE_FRAME / 2)
            .await
            .unwrap();
        assert_eq!(public.catch_up.frames, 2);
        assert_eq!(live(&full, f.public).await, 0);
        assert!(!full.snapshot(f.public).await.unwrap().complete);
        let private = session
            .sync_scope(&full, f.private, MAX_SECURE_FRAME / 2)
            .await
            .unwrap();
        assert_eq!(private.catch_up.frames, 1);
    };
    let (served, ()) = tokio::join!(serve(served), client);
    served.unwrap();
    let page = full.snapshot(f.public).await.unwrap();
    assert_eq!((page.rows.len(), page.complete), (40, true));
    assert_eq!(
        full.snapshot(f.private).await.unwrap().revision,
        page.revision
    );
    for frame in &frames {
        assert_eq!(
            full.receipt_status(frame.id().unwrap()).await.unwrap(),
            ReceiveStatus::Applied
        );
    }

    // A public reader receives and applies its partition alone; the hub
    // never sends it the private member.
    let (session, served) = link::testing::sessions(
        (&public_only, bob.clone(), bob_credentials.clone()),
        hub_end(),
    )
    .await
    .unwrap();
    let client = async {
        let mut session = session;
        session
            .sync_scope(&public_only, f.public, MAX_SECURE_FRAME / 2)
            .await
            .unwrap();
        assert!(
            session
                .sync_scope(&public_only, f.private, MAX_SECURE_FRAME / 2)
                .await
                .is_err()
        );
    };
    let (served, ()) = tokio::join!(serve(served), client);
    served.unwrap();
    let page = public_only.snapshot(f.public).await.unwrap();
    assert_eq!((page.rows.len(), page.complete), (40, true));
    assert!(public_only.companion(f.private, [1; 32]).await.is_err());

    // A bundle authored by a peer is pushed scope by scope and applies at
    // the hub once complete.
    let mut raise = hiring(&f);
    raise.truncate(1);
    raise[0] = RowWrite::changed(change(
        f.public,
        41,
        None,
        Some(f.app().name("employee-41")),
    ));
    raise.push(RowWrite::changed(change(
        f.private,
        41,
        None,
        Some(f.app().salary("123")),
    )));
    full.author_bundle([2; 32], raise, vec![]).await.unwrap();
    let (session, served) =
        link::testing::sessions((&full, carol.clone(), carol_credentials.clone()), hub_end())
            .await
            .unwrap();
    let client = async {
        let mut session = session;
        for scope in both {
            assert_eq!(
                session
                    .push(&full, scope, MAX_SECURE_FRAME / 2)
                    .await
                    .unwrap()
                    .frames,
                1
            );
        }
    };
    let (served, ()) = tokio::join!(serve(served), client);
    served.unwrap();
    assert_eq!(live(&source, f.public).await, 41);
    assert_eq!(
        source.companion(f.private, [41; 32]).await.unwrap(),
        Companion::Present(f.app().salary("123"))
    );

    // A peer the hub does not admit fails the handshake.
    let (near, far) = tokio::io::duplex(MAX_SECURE_FRAME * 2);
    let stranger = PrivateKey::new();
    let (dialed, accepted) =
        link::testing::links(near, far, (&full, stranger, carol_credentials), hub_end()).await;
    assert!(accepted.is_err());
    assert!(dialed.is_err());
}
