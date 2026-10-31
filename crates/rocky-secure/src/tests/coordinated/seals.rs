//! Seals, openings and bookmarks the terminal tests publish.
use super::*;
use crate::TipStatement;
use rocky_core::TipId;
use rocky_credentials::{
    AuthorMark, BOOKMARK_MOVE_FORMAT, BookmarkMoveStatement, SEAL_FORMAT, SealAction,
    SealStatement, SignedBookmarkMove, SignedSeal,
};
use std::collections::BTreeMap;

type Node = (PrivateKey, Replica);

pub(super) fn bookmark(
    lineage: &Lineage,
    name: &str,
    from: Option<TipId>,
    to: Option<TipId>,
) -> TipStatement {
    TipStatement::Bookmark(
        SignedBookmarkMove::sign(
            BookmarkMoveStatement {
                format: BOOKMARK_MOVE_FORMAT,
                scope: lineage.domain,
                name: name.into(),
                from,
                to,
            },
            lineage.publisher(),
        )
        .unwrap(),
    )
}
/// A `continue` seal of `tip` at the frontier of `tip`'s frames `node` holds.
pub(super) async fn seal(lineage: &Lineage, node: &Replica, tip: TipId) -> SignedSeal {
    let mut authors = BTreeMap::<u32, u64>::new();
    for frame in stored_frames(node, "SELECT header,body FROM secure_operations").await {
        let operation = frame.operation().unwrap();
        let extensions = &operation.header.extensions;
        if extensions.tip == tip {
            let sequence = authors.entry(extensions.author.unwrap()).or_default();
            *sequence = (*sequence).max(extensions.author_sequence);
        }
    }
    SignedSeal::sign(
        SealStatement {
            format: SEAL_FORMAT,
            scope: lineage.domain,
            tip,
            frontier: authors
                .into_iter()
                .map(|(author, sequence)| AuthorMark { author, sequence })
                .collect(),
            action: SealAction::Continue {
                schema: lineage.definition(3).hash(),
            },
            recovery: None,
        },
        lineage.publisher(),
    )
    .unwrap()
}
/// Composes `node` with the mesh's log, which it relays seals to.
pub(super) fn compose(fixture: &Fixture, node: &Node) {
    node.1
        .set_domain_log(Some(Arc::new(fixture.mesh.client(&node.0))));
}
/// Composes alice and bob, creates `main` on the genesis tip and has both
/// follow it.
pub(super) async fn follow_main(fixture: &Fixture) {
    let (alice, bob) = (&fixture.alice, &fixture.bob);
    let main = bookmark(
        &fixture.lineage,
        "main",
        None,
        Some(tip_log(&fixture.lineage).tip),
    );
    let minimum = fixture
        .mesh
        .log
        .head(tip_log(&fixture.lineage))
        .unwrap()
        .minimum as u32;
    let line = TipStatement::GenesisLine(
        rocky_credentials::SignedGenesisLine::sign(
            rocky_credentials::GenesisLineStatement {
                format: rocky_credentials::GENESIS_LINE_FORMAT,
                scope: fixture.lineage.domain,
                minimum_in_sync: minimum,
            },
            fixture.lineage.publisher(),
        )
        .unwrap(),
    );
    alice.1.publish_tip_statements(&[main, line]).await.unwrap();
    for node in [alice, bob] {
        compose(fixture, node);
        share(&alice.1, &node.1).await;
        node.1
            .follow_bookmark(fixture.lineage.domain, "main")
            .await
            .unwrap();
    }
}
/// A trusted node `node` that joins later, learns the graph from alice and
/// follows `main`.
pub(super) async fn join_main(fixture: &Fixture, node: &Node) {
    compose(fixture, node);
    share(&fixture.alice.1, &node.1).await;
    node.1
        .follow_bookmark(fixture.lineage.domain, "main")
        .await
        .unwrap();
}
/// Hands every graph statement `from` holds to `to`; returns those admitted.
pub(super) async fn share(from: &Replica, to: &Replica) -> usize {
    to.receive_tip_statements(&from.tip_statements(None, 32).await.unwrap())
        .await
        .unwrap()
}
