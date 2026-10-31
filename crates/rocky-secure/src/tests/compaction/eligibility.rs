//! Open-time graph exclusion changes L without retiring permanent evidence.
use super::*;
use rocky_credentials::Authority;

fn configured_revocations(lineage: &Lineage, issuer: &PrivateKey) -> RevocationSet {
    crate::tests::revoking(
        lineage.publisher(),
        lineage.domain.app,
        &[issuer.public_key()],
        &[],
    )
}

#[tokio::test]
async fn an_open_revocation_loader_retry_keeps_supplied_statements_past_expired_stored_ones() {
    let lineage = Lineage::pinned(253);
    let dir = TempDir::new().unwrap();
    let key = PrivateKey::from_bytes(&[254; 32]);
    let issuer = PrivateKey::from_bytes(&[255; 32]);
    let replica = open(&lineage, &dir, "node", &key).await;
    follow_main(&lineage, &replica).await;
    let expired = rocky_credentials::Revocation {
        app: lineage.domain.app,
        issuer: lineage.publisher().public_key(),
        time: 0,
        nodes: BTreeSet::new(),
        identities: [PrivateKey::from_bytes(&[252; 32]).public_key()].into(),
        capabilities: BTreeSet::new(),
    };
    assert!(!expired.live(now().unwrap()));
    let expired = RevocationSet::try_from(vec![
        rocky_credentials::SignedRevocation::sign(
            expired,
            lineage.publisher(),
            &CredentialChain::default(),
        )
        .unwrap(),
    ])
    .unwrap();
    replica
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .conn
        .execute(
            "UPDATE secure_metadata SET revocations=?",
            [expired.to_bytes().unwrap()],
        )
        .await
        .unwrap();
    let before_revision =
        crate::tests::compaction::scalar(&replica, "SELECT revision FROM secure_metadata").await;
    let supplied = configured_revocations(&lineage, &issuer);
    replica.inject_failure(1, 0).await;
    // The actual E1 loader runs twice through transaction!'s Busy retry.
    let pending = replica
        .retry_open_revocations_for_test(supplied.clone())
        .await
        .unwrap();
    assert_eq!(pending, supplied);
    assert_eq!(
        crate::tests::compaction::scalar(&replica, "SELECT revision FROM secure_metadata").await,
        before_revision
    );
    replica.learn_revocations(&pending).await.unwrap();
    assert_eq!(replica.revocations().await, supplied);
    let tip = replica.followed_tip().await;
    let chain = CredentialChain(vec![
        Authority::owner(lineage.publisher())
            .issue_issuer(issuer.public_key(), None, crate::tests::validity())
            .unwrap(),
    ]);
    let sealed =
        SignedSeal::endorse(sign_seal(&lineage, tip, vec![]).statement, &issuer, &chain).unwrap();
    let error = replica
        .receive_tip_statements(&[TipStatement::Seal(sealed.clone())])
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("invalid or revoked credential"),
        "{error}"
    );
    assert!(
        replica
            .tip_graph(lineage.domain)
            .await
            .unwrap()
            .seal(tip)
            .unwrap()
            .is_none()
    );
    assert_eq!(replica.followed_tip().await, tip);
    replica.audit(lineage.scope("items")).await.unwrap();
}
