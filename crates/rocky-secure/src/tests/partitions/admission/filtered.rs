//! A replayed partition after an additive schema switch.
use super::*;
use rocky_core::TipId;
use rocky_credentials::{
    BOOKMARK_MOVE_FORMAT, BookmarkMoveStatement, SEAL_FORMAT, SealAction, SealStatement,
    SignedBookmarkMove, SignedSeal,
};

mod delete;

fn bookmark(f: &Fixture, name: &str, from: Option<TipId>, to: TipId) -> TipStatement {
    TipStatement::Bookmark(
        SignedBookmarkMove::sign(
            BookmarkMoveStatement {
                format: BOOKMARK_MOVE_FORMAT,
                scope: f.domain,
                name: name.into(),
                from,
                to: Some(to),
            },
            &f.publisher,
        )
        .unwrap(),
    )
}

pub(super) async fn security(f: &Fixture, replica: &EncryptedReplica<TypedRows>) -> SecureConfig {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    SecureConfig {
        publisher: f.publisher.public_key(),
        manifest: f.manifest.clone(),
        revocations: inner.config.revocations.clone(),
        node: inner.config.node.clone(),
        credentials: inner.config.credentials.clone(),
        keys: vec![
            KeyMaterial::new(f.scope("A"), 1, [1; 32]),
            KeyMaterial::new(f.scope("B"), 1, [2; 32]),
        ],
    }
}
