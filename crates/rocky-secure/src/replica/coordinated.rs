//! Terminal entries of tips' coordinated logs: a seal of a tip or a bookmark
//! move off it ends the tip's log, and trusted nodes acknowledge that entry
//! into the seal's finality record. Rocky appends no other entries;
//! applications coordinate their own writes.
use super::*;
use rocky_core::{DomainLog, Scope, TipLog, coordinated_chain};

mod finality;
pub(super) mod relay;
pub use relay::StagedCloseStatus;
pub(super) mod statements;
mod terminal;
pub use statements::Refusal;
pub(in crate::replica) use statements::{Unconfirmed, refusal};

impl<A: RowApplication> Inner<A> {
    /// The log of `domain`'s tip this replica follows.
    pub(in crate::replica) fn tip_log(&self, domain: Scope) -> TipLog {
        TipLog {
            scope: domain,
            tip: self.workspace.tip,
        }
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// The log of `domain`'s tip this replica follows.
    pub async fn followed_log(&self, domain: Scope) -> TipLog {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .tip_log(domain)
    }
}
