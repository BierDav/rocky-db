//! Final seals: trusted nodes acknowledge the terminal entry that ended a
//! tip's log, and the record they publish makes that seal win on every
//! device, the owner's later seal included.
use super::seals::{bookmark, join_main, seal, share};
use super::*;
use crate::TipStatement;
use rocky_credentials::{
    AuthorMark, GENESIS_LINE_FORMAT, GenesisLineStatement, SignedGenesisLine, SignedSeal,
};

async fn trusted(fixture: &Fixture, name: &str) -> (PrivateKey, Replica) {
    let (identity, key) = (PrivateKey::new(), PrivateKey::new());
    let replica = fixture
        .lineage
        .open_trusted(
            &fixture.dir.path().join(format!("{name}.db")),
            (&identity, &key),
            3,
            None,
        )
        .await
        .unwrap();
    (key, replica)
}

#[tokio::test]
async fn a_seal_its_log_ended_becomes_final_and_beats_a_later_owner_seal() {
    let fixture = Fixture::new(1).await;
    let alice = &fixture.alice;
    super::seals::follow_main(&fixture).await;
    let main = tip_log(&fixture.lineage);
    let line = TipStatement::GenesisLine(
        SignedGenesisLine::sign(
            GenesisLineStatement {
                format: GENESIS_LINE_FORMAT,
                scope: fixture.lineage.domain,
                minimum_in_sync: 2,
            },
            fixture.lineage.publisher(),
        )
        .unwrap(),
    );
    alice.1.publish_tip_statements(&[line]).await.unwrap();
    let (tess, tom) = (
        trusted(&fixture, "tess").await,
        trusted(&fixture, "tom").await,
    );
    for node in [&tess, &tom] {
        join_main(&fixture, node).await;
    }
    let committed = seal(&fixture.lineage, &alice.1, main.tip).await;
    let next = committed.successor().unwrap().unwrap();
    // An owner seal of the same tip with a lower digest, which the log
    // never committed.
    let rival = (1..)
        .map(|sequence| {
            let mut statement = committed.statement.clone();
            statement.frontier.push(AuthorMark {
                author: rocky_credentials::MAX_AUTHOR,
                sequence,
            });
            SignedSeal::sign(statement, fixture.lineage.publisher()).unwrap()
        })
        .find(|rival| rival.id().unwrap() < committed.id().unwrap())
        .unwrap();
    let statements = [
        TipStatement::Seal(committed.clone()),
        bookmark(&fixture.lineage, "main", Some(main.tip), Some(next)),
    ];
    // Tess ends `main`'s log with the seal.
    tess.1.publish_tip_statements(&statements).await.unwrap();
    let head = fixture.mesh.log.head(main).unwrap();
    assert_eq!(head.terminal.unwrap().digest, committed.id().unwrap());
    // A member learns the rival first: by digest it wins there.
    let key = PrivateKey::new();
    let carol = open(&fixture.lineage, &fixture.dir, "carol", &key).await;
    share(&tess.1, &carol).await;
    carol
        .receive_tip_statements(&[TipStatement::Seal(rival.clone())])
        .await
        .unwrap();
    let graph = carol.tip_graph(fixture.lineage.domain).await.unwrap();
    assert_eq!(graph.seal(main.tip).unwrap(), Some(&rival));

    // One acknowledgment is below the genesis line's minimum of two.
    assert_eq!(
        tess.1.finalize_seals(fixture.lineage.domain).await.unwrap(),
        0
    );
    share(&tess.1, &tom.1).await;
    assert_eq!(
        tom.1.finalize_seals(fixture.lineage.domain).await.unwrap(),
        1
    );
    assert_eq!(
        fixture.mesh.log.head(main).unwrap().acknowledgments.len(),
        2
    );
    // A node outside the trusted identities acknowledges nothing.
    assert_eq!(
        alice
            .1
            .finalize_seals(fixture.lineage.domain)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        fixture.mesh.log.head(main).unwrap().acknowledgments.len(),
        2
    );

    // The record reaches the member without any coordinator call.
    assert_eq!(share(&tom.1, &carol).await, 1);
    let graph = carol.tip_graph(fixture.lineage.domain).await.unwrap();
    assert!(graph.is_final(committed.id().unwrap()).unwrap());
    assert_eq!(graph.seal(main.tip).unwrap(), Some(&committed));
    assert_eq!(graph.bookmark("main").unwrap(), Some(next));
    // A trusted node that admits the rival afterwards keeps the final seal.
    tom.1
        .receive_tip_statements(&[TipStatement::Seal(rival)])
        .await
        .unwrap();
    let graph = tom.1.tip_graph(fixture.lineage.domain).await.unwrap();
    assert_eq!(graph.seal(main.tip).unwrap(), Some(&committed));
    // A node holding every frame through the final seal compacts there at
    // once, whatever count of seals it leaves uncompacted.
    share(&tom.1, &alice.1).await;
    let report = alice.1.compact(fixture.lineage.domain, 5).await.unwrap();
    assert_eq!(report.waiting, None);
    assert_eq!(report.compacted, Some(committed.id().unwrap()));
    // Reopening verifies the stored record again.
    drop(carol);
    let carol = open(&fixture.lineage, &fixture.dir, "carol", &key).await;
    let graph = carol.tip_graph(fixture.lineage.domain).await.unwrap();
    assert!(graph.is_final(committed.id().unwrap()).unwrap());
}
