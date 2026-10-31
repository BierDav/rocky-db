//! Transferable migration capacity never comes from a caller's quota claim.
use super::compaction::{bookmark, follow_main};
use super::generations::Lineage;
use super::*;
use rocky_core::{RowIdentity, SqlValue, TypedRows};
use rocky_credentials::{
    GenesisLineStatement, SealAction, SealStatement, SignedGenesisLine, SignedMigrationPublication,
    SignedSeal, SignedTipOpening, TipOpeningStatement,
};

mod fixture;
mod intents;
mod storage;
mod syntax;
mod syntax_authority;
mod syntax_bounds;
use fixture::{candidate, candidate_tables, frames, release};

#[tokio::test]
async fn migration_provenance_is_private_until_endorsed_and_survives_reopen() {
    let (l, dir, key, replica, signed) = candidate(3).await;
    let before = replica.migration_storage().await.unwrap();
    assert!(before.frames > 0 && before.bytes > 0 && before.support_bytes > 0);
    assert!(replica.private_schema().await.unwrap());
    assert!(
        replica
            .migration_publication(signed.statement.publication)
            .await
            .unwrap()
            .is_none()
    );
    assert!(replica.tip_statements(None, 32).await.is_err());
    drop(replica);
    let mut config = l.config(3, &key);
    config.manifest = l.config(2, &key).manifest;
    config.credentials = l.certified(3, l.publisher(), &key);
    let replica = EncryptedReplica::open(&dir.path().join("source.db"), l.app(3), config)
        .await
        .unwrap();
    assert_eq!(replica.migration_storage().await.unwrap(), before);
    let intent = replica
        .migration_intent(signed.statement.publication)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(intent.0, signed.statement);
    release(&replica, &signed).await;
    assert!(!replica.private_schema().await.unwrap());
    assert_eq!(
        replica
            .migration_publication(signed.statement.publication)
            .await
            .unwrap(),
        Some(signed)
    );
    replica.audit(l.scope("items")).await.unwrap();
}

#[tokio::test]
async fn verified_membership_bypasses_only_ordinary_history_and_debits_atomically() {
    // Items and tags: two frames.
    let (l, dir, _, source, signed) = candidate_tables(40, true).await;
    release(&source, &signed).await;
    let key = PrivateKey::new();
    let target = l
        .open(&dir.path().join("target.db"), &key, 2, None)
        .await
        .unwrap();
    l.follow(
        &target,
        l.config(3, &key),
        3,
        &all_tip_statements(&source).await,
    )
    .await
    .unwrap();
    let payload = frames(&source).await;
    assert!(payload.len() > 1);
    target
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .limits
        .hard_bytes = 0;
    assert!(target.receive(payload[0].clone()).await.is_err());
    let mut forged = payload[0].clone();
    forged.migration.as_mut().unwrap().proof.index += 1;
    assert!(
        target
            .receive_migration_all(vec![forged])
            .await
            .remove(0)
            .is_err()
    );
    assert_eq!(target.migration_storage().await.unwrap().frames, 0);
    for r in target.receive_migration_all(payload[1..].to_vec()).await {
        r.unwrap();
    }
    let partial = target.migration_storage().await.unwrap();
    assert!(partial.frames < signed.statement.frames && partial.bytes < signed.statement.bytes);
    assert!(
        target
            .frontier(l.scope("items"))
            .await
            .unwrap()
            .logs
            .iter()
            .all(|log| log.applied == 0)
    );
    let (left, right) = tokio::join!(
        target.receive_migration_all(payload.clone()),
        target.receive_migration_all(payload.clone())
    );
    for r in left.into_iter().chain(right) {
        r.unwrap();
    }

    let totals = target.migration_storage().await.unwrap();
    assert_eq!(totals.bytes, signed.statement.bytes);
    assert_eq!(totals.frames, signed.statement.frames);
    for r in target.receive_migration_all(payload.clone()).await {
        r.unwrap();
    }
    assert_eq!(target.migration_storage().await.unwrap(), totals);
    // Neither a later sequence nor a generic local publication acquires capacity.
    let sql = super::generations::session(&source).await;
    let edit = sql
        .run("UPDATE items SET title='ordinary' WHERE key='k0'", vec![])
        .await
        .unwrap()
        .committed
        .unwrap()
        .frames;
    assert!(edit.iter().all(|f| f.migration.is_none()));
    assert!(
        target
            .receive_migration_all(edit)
            .await
            .into_iter()
            .all(|r| matches!(r, Err(Error::Backpressure)))
    );
    source
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .limits
        .hard_bytes = 0;
    sql.run("BEGIN", vec![]).await.unwrap();
    sql.run("UPDATE items SET title='not exempt' WHERE key='k0'", vec![])
        .await
        .unwrap();
    assert!(sql.commit_publication([77; 32]).await.is_err());
    target.audit(l.scope("items")).await.unwrap();
    let hash = payload[0].id().unwrap();
    {
        let mut inner = target.inner.lock(crate::replica::Class::Background).await;
        let failed: Result<(), Error> = transaction!(inner, |inner| {
            inner
                .conn
                .execute(
                    "DELETE FROM secure_operations WHERE hash=?",
                    [hash.as_bytes().to_vec()],
                )
                .await?;
            Err(denied("injected after debit"))
        });
        assert!(failed.is_err());
    }
    assert_eq!(target.migration_storage().await.unwrap(), totals);
    {
        let mut inner = target.inner.lock(crate::replica::Class::Background).await;
        inner
            .conn
            .execute(
                "CREATE TEMP TABLE ledger_parent(id INTEGER PRIMARY KEY)",
                (),
            )
            .await
            .unwrap();
        inner.conn.execute("CREATE TEMP TABLE ledger_child(id INTEGER REFERENCES ledger_parent(id) DEFERRABLE INITIALLY DEFERRED)",()).await.unwrap();
        let failed: Result<(), Error> = transaction!(inner, |inner| {
            inner
                .conn
                .execute(
                    "DELETE FROM secure_operations WHERE hash=?",
                    [hash.as_bytes().to_vec()],
                )
                .await?;
            inner
                .conn
                .execute("INSERT INTO ledger_child VALUES(1)", ())
                .await?;
            Ok(())
        });
        assert!(failed.is_err());
    }
    assert_eq!(target.migration_storage().await.unwrap(), totals);
    {
        let mut inner = target.inner.lock(crate::replica::Class::Background).await;
        transaction!(inner, |inner| {
            inner
                .conn
                .execute(
                    "DELETE FROM secure_operations WHERE hash=?",
                    [hash.as_bytes().to_vec()],
                )
                .await?;
            Ok(())
        })
        .unwrap();
    }
    let remaining = target.migration_storage().await.unwrap();
    assert_eq!(remaining.frames, totals.frames - 1);
    assert_eq!(
        remaining.bytes,
        totals.bytes - payload[0].stored_bytes().unwrap()
    );
    // Each retained proof remains self-contained after its neighbor is removed.
    for frame in frames(&target).await {
        let proof = frame.migration.as_ref().unwrap();
        signed
            .statement
            .verify(
                &proof.proof,
                *frame.id().unwrap().as_bytes(),
                frame.stored_bytes().unwrap(),
            )
            .unwrap();
    }
    target
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .audit_migration_accounts()
        .await
        .unwrap();
}

#[tokio::test]
async fn an_empty_migration_has_a_signed_canonical_zero_extent() {
    let (_, _, _, replica, signed) = candidate(0).await;
    assert_eq!(signed.statement.frames, 0);
    assert_eq!(signed.statement.bytes, 0);
    assert_eq!(signed.statement.root, signed.statement.empty().hash);
    release(&replica, &signed).await;
    assert_eq!(replica.migration_storage().await.unwrap().frames, 0);
}

#[tokio::test]
async fn equivocation_stops_acquisition_without_allocating_another_extent() {
    let (l, dir, _, source, signed) = candidate(2).await;
    release(&source, &signed).await;
    let key = PrivateKey::new();
    let target = l
        .open(&dir.path().join("conflict.db"), &key, 2, None)
        .await
        .unwrap();
    l.follow(
        &target,
        l.config(3, &key),
        3,
        &all_tip_statements(&source).await,
    )
    .await
    .unwrap();
    target
        .admit_migration_publication(signed.clone())
        .await
        .unwrap();
    let mut other = signed.statement.clone();
    other.bytes += 1;
    let other = SignedMigrationPublication::endorse(
        other,
        l.publisher(),
        &CredentialChain::default(),
        frames(&source).await[0]
            .chain()
            .unwrap()
            .credentials()
            .clone(),
    )
    .unwrap();
    assert!(
        target
            .admit_migration_publication(other.clone())
            .await
            .is_err()
    );
    assert!(target.admit_migration_publication(other).await.is_err());
    for r in target.receive_migration_all(frames(&source).await).await {
        assert!(r.is_err());
    }
    assert_eq!(target.migration_storage().await.unwrap().frames, 0);
    let inner = target.inner.lock(crate::replica::Class::Background).await;
    assert_eq!(
        crate::storage::rows(
            &inner.conn,
            "SELECT count(*) FROM secure_migration_publications"
        )
        .await
        .unwrap(),
        vec![vec![SqlValue::Integer(1)]]
    );
}

#[tokio::test]
async fn keyless_custody_verifies_and_relays_proofs_without_claiming_application() {
    let (l, dir, _, source, signed) = candidate(2).await;
    release(&source, &signed).await;
    let key = PrivateKey::new();
    let mut config = l.config(2, &key);
    config.keys.clear();
    let target = EncryptedReplica::open(&dir.path().join("custody.db"), l.app(2), config)
        .await
        .unwrap();
    let (schema, domain, readers) = l.projection(2);
    target
        .install_tables(schema, domain, readers)
        .await
        .unwrap();
    let mut config = l.config(3, &key);
    config.keys.clear();
    l.follow(&target, config, 3, &all_tip_statements(&source).await)
        .await
        .unwrap();
    for result in target.receive_migration_all(frames(&source).await).await {
        assert!(!matches!(result.unwrap(), ReceiveStatus::Applied));
    }
    assert_eq!(
        target.migration_storage().await.unwrap().bytes,
        signed.statement.bytes
    );
    let frontier = target.frontier(l.scope("items")).await.unwrap();
    assert!(frontier.logs.iter().all(|log| log.applied < log.held));
    for frame in frames(&target).await {
        assert!(frame.migration.as_ref().unwrap().descriptor.is_some());
    }
    target.audit(l.scope("items")).await.unwrap();
}

#[tokio::test]
async fn failed_flush_retains_exact_classification_and_retry_acknowledges_it_once() {
    let (l, dir, _, source, signed) = candidate(4).await;
    release(&source, &signed).await;
    let key = PrivateKey::new();
    let target = l
        .open(&dir.path().join("flush.db"), &key, 2, None)
        .await
        .unwrap();
    l.follow(
        &target,
        l.config(3, &key),
        3,
        &all_tip_statements(&source).await,
    )
    .await
    .unwrap();
    target
        .admit_migration_publication(signed.clone())
        .await
        .unwrap();
    let before = target.durable_commit().await;
    target.fail_flushes(1).await;
    let payload = frames(&source).await;
    assert!(
        target
            .receive_migration_all(payload.clone())
            .await
            .into_iter()
            .all(|r| r.is_err())
    );
    assert_eq!(target.durable_commit().await, before);
    let stored = target.migration_storage().await.unwrap();
    assert_eq!(stored.bytes, signed.statement.bytes);
    for r in target.receive_migration_all(payload).await {
        r.unwrap();
    }
    assert!(target.durable_commit().await > before);
    assert_eq!(target.migration_storage().await.unwrap(), stored);
    target.audit(l.scope("items")).await.unwrap();
}

#[tokio::test]
async fn enormous_advertised_extent_reserves_no_frame_storage() {
    let (l, dir, _, source, signed) = candidate(1).await;
    release(&source, &signed).await;
    let key = PrivateKey::new();
    let target = l
        .open(&dir.path().join("huge.db"), &key, 2, None)
        .await
        .unwrap();
    l.follow(
        &target,
        l.config(3, &key),
        3,
        &all_tip_statements(&source).await,
    )
    .await
    .unwrap();
    let payload = frames(&source).await;
    let mut huge = signed.statement;
    huge.frames = u64::MAX;
    huge.bytes = u64::MAX;
    let huge = SignedMigrationPublication::endorse(
        huge,
        l.publisher(),
        &CredentialChain::default(),
        payload[0].chain().unwrap().credentials().clone(),
    )
    .unwrap();
    target.admit_migration_publication(huge).await.unwrap();
    let storage = target.migration_storage().await.unwrap();
    assert_eq!(storage.frames, 0);
    assert_eq!(storage.bytes, 0);
    assert!(storage.support_bytes < 32768);
}

#[tokio::test]
async fn partial_reader_applies_only_its_encrypted_bundle_members() {
    let (l, dir, _, source, signed) = candidate_tables(2, true).await;
    release(&source, &signed).await;
    let key = PrivateKey::new();
    let mut config = l.config(2, &key);
    let user = PrivateKey::from_bytes(&rocky_core::commitment(
        "lineage.user",
        key.public_key().as_bytes(),
    ));
    let restricted = |version| {
        let mut chain = l.credentials(version, &key);
        for (index, link) in chain.0.iter_mut().enumerate() {
            let mut cap = link.capability.clone();
            cap.grants
                .retain(|g| g.scope.table == l.scope("items").table);
            *link = SignedCapability::sign(cap, if index == 0 { l.publisher() } else { &user })
                .unwrap();
        }
        chain
    };
    config.credentials = restricted(2);
    config
        .keys
        .retain(|k| k.scope.table == l.scope("items").table);
    let target = EncryptedReplica::open(&dir.path().join("partial.db"), l.app(2), config)
        .await
        .unwrap();
    let (schema, scope, readers) = l.projection(2);
    target.install_tables(schema, scope, readers).await.unwrap();
    let mut config = l.config(3, &key);
    config.credentials = restricted(3);
    config
        .keys
        .retain(|k| k.scope.table == l.scope("items").table);
    l.follow(&target, config, 3, &all_tip_statements(&source).await)
        .await
        .unwrap();
    let payload = frames(&source).await;
    for (frame, result) in payload
        .iter()
        .zip(target.receive_migration_all(payload.clone()).await)
    {
        if frame.scope().unwrap().table == l.scope("items").table {
            result.unwrap();
        } else {
            assert!(result.is_err());
        }
    }
    let storage = target.migration_storage().await.unwrap();
    assert!(storage.frames > 0 && storage.frames < signed.statement.frames);
    assert_eq!(
        super::generations::select(&target, "SELECT title FROM items ORDER BY key")
            .await
            .len(),
        2
    );
    target.audit(l.scope("items")).await.unwrap();
}

#[tokio::test]
async fn seal_pruning_and_interrupted_checkpoint_import_debit_and_preserve_proofs() {
    let (l, dir, _, source, signed) = candidate_tables(40, true).await;
    release(&source, &signed).await;
    let key = PrivateKey::new();
    let target = l
        .open(&dir.path().join("import.db"), &key, 2, None)
        .await
        .unwrap();
    l.follow(
        &target,
        l.config(3, &key),
        3,
        &all_tip_statements(&source).await,
    )
    .await
    .unwrap();
    let payload = frames(&source).await;
    assert!(payload.len() > 1);
    // A member prunes with its whole transaction and outcome records: the
    // target holds them all.
    for result in target.receive_migration_all(payload.clone()).await {
        result.unwrap();
    }
    for frame in stored_frames(
        &source,
        "SELECT header,body FROM secure_operations ORDER BY sequence",
    )
    .await
    .into_iter()
    .filter(|frame| frame.migration.is_none())
    {
        target.receive(frame).await.unwrap();
    }
    let checkpoint = compacted_base(&source, l.publisher(), l.scope("items")).await;
    l.follow(
        &target,
        l.config(3, &key),
        3,
        &all_tip_statements(&source).await,
    )
    .await
    .unwrap();
    let credentials = l.credentials(3, &key);
    source
        .admit_peer(key.public_key(), &credentials, target.followed_tip().await)
        .await
        .unwrap();
    source
        .set_retention_policy(
            l.scope("items"),
            RetentionPolicy {
                required: [rocky_credentials::PeerId::of(key.public_key())].into(),
                behind: Default::default(),
                copies: 1,
                window: 0,
            },
        )
        .await
        .unwrap();
    source
        .acknowledge_frontier(
            key.public_key(),
            &credentials,
            &target.frontier(l.scope("items")).await.unwrap(),
        )
        .await
        .unwrap();
    let report = source.prune(l.scope("items")).await.unwrap();
    assert!(report.pruned > 0, "{report:?}");
    let remaining = source.migration_storage().await.unwrap();
    assert_eq!(remaining.frames, signed.statement.frames - 1);
    for frame in frames(&source).await {
        let membership = frame.migration.as_ref().unwrap();
        signed
            .statement
            .verify(
                &membership.proof,
                *frame.id().unwrap().as_bytes(),
                frame.stored_bytes().unwrap(),
            )
            .unwrap();
    }
    source.audit(l.scope("items")).await.unwrap();
    target.begin_rebootstrap(checkpoint.clone()).await.unwrap();
    // Staging a page does not debit retained operations before the atomic import.
    let before = target.migration_storage().await.unwrap();
    let mut after = None;
    loop {
        let page = source
            .checkpoint_page(
                key.public_key(),
                &credentials,
                l.scope("items"),
                checkpoint.id().unwrap(),
                after,
                64 * 1024,
            )
            .await
            .unwrap();
        after = page.next;
        target.stage_checkpoint_page(page).await.unwrap();
        assert_eq!(target.migration_storage().await.unwrap(), before);
        if after.is_none() {
            break;
        }
    }
    drop(target);
    let target = l
        .reopen(&dir.path().join("import.db"), &key, 2, 3)
        .await
        .unwrap();
    assert_eq!(target.migration_storage().await.unwrap(), before);
    target.finish_rebootstrap(l.scope("items")).await.unwrap();
    // The import debits the items member; the tags member stays.
    assert_eq!(
        target.migration_storage().await.unwrap().frames,
        signed.statement.frames - 1
    );
    assert!(
        target
            .migration_publication(signed.statement.publication)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        super::generations::select(&target, "SELECT title FROM items")
            .await
            .len(),
        40
    );
    target.audit(l.scope("items")).await.unwrap();
}

