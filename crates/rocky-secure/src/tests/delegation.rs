//! A validly signed delegation that widens any dimension is refused by
//! every boundary that admits a chain, not only where it was issued.
use super::*;
use crate::wire::{Extensions, author};
use rocky_core::FieldSelection;

/// Changes one dimension of a link.
type Widen = dyn Fn(&mut Capability, &Fixture);

/// Publisher, user, a deployment `widen` changed, node: every link signed
/// by its parent's subject.
fn delegated(
    f: &Fixture,
    node: &PrivateKey,
    held: &[ResourceGrant],
    widen: &Widen,
) -> CredentialChain {
    let user = PrivateKey::new();
    let deployment = PrivateKey::new();
    let root = Capability {
        subject: user.public_key(),
        kind: PrincipalKind::User,
        grants: held.to_vec(),
        not_before: crate::tests::lifetime().0,
        expires: crate::tests::lifetime().1,
        delegations: 2,
        extension: rocky_credentials::Extension::new(rocky_credentials::Extended {
            trusted: None,
            partitions: Vec::new(),
            authors: Some(rocky_credentials::AuthorRange::new(10, 20).unwrap()),
            node: None,
            issues: false,
        })
        .unwrap(),
    };
    let mut middle = Capability {
        subject: deployment.public_key(),
        kind: PrincipalKind::Deployment,
        delegations: 1,
        ..root.clone()
    };
    widen(&mut middle, f);
    let leaf = Capability {
        subject: node.public_key(),
        kind: PrincipalKind::Node,
        delegations: 0,
        extension: rocky_credentials::Extension::new(rocky_credentials::Extended {
            trusted: None,
            authors: Some(rocky_credentials::AuthorRange::new(12, 12).unwrap()),
            node: Some(rocky_credentials::PeerId::of(node.public_key())),
            ..Default::default()
        })
        .unwrap(),
        ..middle.clone()
    };
    CredentialChain(vec![
        SignedCapability::sign(root, &f.publisher).unwrap(),
        SignedCapability::sign(middle, &user).unwrap(),
        SignedCapability::sign(leaf, &deployment).unwrap(),
    ])
}
fn widened(error: Error) -> bool {
    matches!(error, Error::Rejected(message) if message == "delegation expands authority")
}

#[tokio::test]
async fn widening_delegations_are_refused_at_every_admitting_boundary() {
    let f = Fixture::new();
    let dir = TempDir::new().unwrap();
    let writer = PrivateKey::new();
    let held = vec![grant(
        f.public,
        &[Right::Read, Right::Insert, Right::Update, Right::Custody],
        &[f.app().field("display_name")],
    )];
    let widenings: [&Widen; 7] = [
        &|link, _| {
            link.grants[0].rights.insert(Right::Delete);
        },
        &|link, f| {
            if let FieldSelection::Only(fields) = &mut link.grants[0].fields {
                fields.insert(f.app().field("salary"));
            }
        },
        &|link, f| link.grants[0].scope = f.private,
        &|link, _| link.expires += 1,
        &|link, _| link.not_before -= 1,
        &|link, _| link.delegations = 2,
        &|link, _| {
            link.extension = rocky_credentials::Extension::new(rocky_credentials::Extended {
                trusted: None,
                partitions: Vec::new(),
                authors: Some(rocky_credentials::AuthorRange::new(10, 21).unwrap()),
                node: None,
                issues: false,
            })
            .unwrap()
        },
    ];
    // The narrowing chain is admitted everywhere below.
    let narrow = delegated(&f, &writer, &held, &|_, _| {});
    let config = |credentials| SecureConfig {
        credentials,
        ..f.config(&writer, held.clone(), &[f.public])
    };
    let source = EncryptedReplica::open(dir.path().join("source.db"), f.app(), config(narrow))
        .await
        .unwrap();
    let reader = PrivateKey::new();
    let target = EncryptedReplica::open(
        dir.path().join("target.db"),
        f.app(),
        f.config(&reader, f.full(), &[f.public]),
    )
    .await
    .unwrap();
    let frame = source
        .author(
            [1; 32],
            vec![change(f.public, 1, None, Some(f.app().name("Ann")))],
            vec![],
        )
        .await
        .unwrap();
    let frame_id = frame.id().unwrap();
    target.receive(frame).await.unwrap();
    source
        .transfer_page(
            writer.public_key(),
            &delegated(&f, &writer, &held, &|_, _| {}),
            &[f.public],
            None,
            MAX_SECURE_FRAME,
        )
        .await
        .unwrap();

    for (index, widen) in widenings.into_iter().enumerate() {
        let chain = delegated(&f, &writer, &held, widen);
        // Opening and renewing with it.
        let opened = EncryptedReplica::open(
            dir.path().join(format!("widened-{index}.db")),
            f.app(),
            config(chain.clone()),
        )
        .await;
        assert!(opened.is_err_and(widened), "open {index}");
        assert!(
            source
                .renew_credentials(chain.clone())
                .await
                .is_err_and(widened),
            "renew {index}"
        );
        // A frame its node signed under it.
        let forged = author(
            &writer,
            Extensions {
                author: Some(12),
                author_sequence: 0,
                row_format: crate::wire::ROW_FORMAT,
                births: Vec::new(),
                partition: None,
                tip: rocky_credentials::genesis_tip(f.app().definition().hash()),
                scope: f.public,
                generation: rocky_core::KeyEpoch::new(1, &[11; 32]),
                chain: crate::wire::Chain::new(chain.clone()).unwrap().digest(),
            },
            crate::wire::Chain::new(chain.clone()).unwrap(),
            &[11; 32],
            (0, None, 1),
            Vec::new(),
            b"rows",
        )
        .unwrap();
        assert!(
            target.receive(forged).await.is_err_and(widened),
            "frame {index}"
        );
        // A sync page, an acknowledgment and a remote read for it.
        assert!(
            source
                .acknowledge(writer.public_key(), &chain, frame_id, true)
                .await
                .is_err_and(widened),
            "ack {index}"
        );
        assert!(
            source
                .transfer_page(
                    writer.public_key(),
                    &chain,
                    &[f.public],
                    None,
                    MAX_SECURE_FRAME
                )
                .await
                .is_err_and(widened),
            "page {index}"
        );
        assert!(
            source
                .remote_read(writer.public_key(), &chain, f.public, None, 16)
                .await
                .is_err_and(widened),
            "read {index}"
        );
    }
}
