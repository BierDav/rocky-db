//! Terminal entries of tips' coordinated logs: seals end them, trusted nodes
//! acknowledge them into finality records, private closes are relayed and
//! the owner's recovery ends a log no ordinary seal can.
use super::generations::Lineage;
use super::*;
use rocky_coordinator::coordinated::{MemoryLog, MemoryLogClient};
use rocky_core::{DomainLog, Scope, SqlValue, TipLog, TypedRows};
use std::sync::Arc;

mod finality;
mod recovery;
mod relay;
mod seals;

type Replica = EncryptedReplica<TypedRows>;

/// The log of the tip the fixtures' replicas follow: generation 3's.
fn tip_log(lineage: &Lineage) -> TipLog {
    TipLog {
        scope: lineage.domain,
        tip: rocky_credentials::genesis_tip(lineage.definition(3).hash()),
    }
}

/// The coordinator the fixtures' trusted nodes share.
struct Mesh {
    log: MemoryLog,
}
impl Mesh {
    fn new(minimum: usize, domain: Scope) -> Self {
        let log = MemoryLog::new();
        log.configure(domain, minimum).unwrap();
        Self { log }
    }
    fn client(&self, key: &PrivateKey) -> MemoryLogClient {
        self.log.client(key.public_key())
    }
}

/// Two trusted nodes, alice and bob.
struct Fixture {
    lineage: Lineage,
    dir: TempDir,
    mesh: Mesh,
    alice: (PrivateKey, Replica),
    bob: (PrivateKey, Replica),
}
impl Fixture {
    async fn new(minimum: usize) -> Self {
        let lineage = Lineage::new();
        let dir = TempDir::new().unwrap();
        let mesh = Mesh::new(minimum, lineage.domain);
        let (alice_key, bob_key) = (PrivateKey::new(), PrivateKey::new());
        let alice = open(&lineage, &dir, "alice", &alice_key).await;
        let bob = open(&lineage, &dir, "bob", &bob_key).await;
        Self {
            lineage,
            dir,
            mesh,
            alice: (alice_key, alice),
            bob: (bob_key, bob),
        }
    }
    /// Crashes alice: every handle is dropped, then the file reopens.
    async fn restart_alice(self) -> Self {
        let Self {
            lineage,
            dir,
            mesh,
            alice: (key, replica),
            bob,
        } = self;
        drop(replica);
        let replica = open(&lineage, &dir, "alice", &key).await;
        Self {
            lineage,
            dir,
            mesh,
            alice: (key, replica),
            bob,
        }
    }
}
async fn open(lineage: &Lineage, dir: &TempDir, name: &str, key: &PrivateKey) -> Replica {
    lineage
        .open_trusted(
            &dir.path().join(format!("{name}.db")),
            (&PrivateKey::new(), key),
            3,
            None,
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn a_seal_ends_its_log_once_and_a_retry_answers_the_same_position() {
    let fixture = Fixture::new(1).await;
    let log = tip_log(&fixture.lineage);
    let client = fixture.mesh.client(&fixture.alice.0);
    let terminal = rocky_core::LogTerminal {
        digest: [5; 32],
        continuation: None,
    };
    let position = fixture
        .alice
        .1
        .seal_log(log, terminal, &client)
        .await
        .unwrap();
    assert_eq!(position, 1);
    assert_eq!(
        fixture
            .alice
            .1
            .seal_log(log, terminal, &client)
            .await
            .unwrap(),
        position
    );
    let other = rocky_core::LogTerminal {
        digest: [6; 32],
        continuation: None,
    };
    assert!(matches!(
        fixture
            .bob
            .1
            .seal_log(log, other, &fixture.mesh.client(&fixture.bob.0))
            .await,
        Err(Error::Coordination(rocky_core::CoordinationError::Sealed))
    ));
    assert_eq!(fixture.mesh.log.head(log).unwrap().terminal, Some(terminal));
}
