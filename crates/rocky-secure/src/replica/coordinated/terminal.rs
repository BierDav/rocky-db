//! Terminal entries: a seal of a tip or a bookmark move off it ends the
//! tip's log; the owner's recovery seal ends a log no ordinary seal can.
use super::*;
use rocky_core::{LogResult, LogTerminal};
use rocky_credentials::{LogPoint, Recovery};

impl<A: RowApplication> EncryptedReplica<A> {
    /// Ends `log` with `terminal`, the digest of a seal of its tip or of a
    /// bookmark move off it. A retry of the same terminal answers the same
    /// position; another terminal already ended the log with `Sealed`.
    pub async fn seal_log(
        &self,
        log: TipLog,
        terminal: LogTerminal,
        coordinator: &dyn DomainLog,
    ) -> Result<u64, Error> {
        match coordinator.seal(log, terminal).await {
            Ok(LogResult::Committed { position, .. }) => Ok(position),
            Ok(LogResult::Acknowledged) => Err(Error::Corrupt(
                "the coordinator did not commit a seal".into(),
            )),
            Err(error) => Err(Error::Coordination(error)),
        }
    }
    /// The recovery of `log` that ends the coordinator's exact head, for the
    /// owner to sign into a `continue` seal of the tip. Rocky writes no
    /// entries, so it abandons none. Nothing is stored.
    pub async fn recovery_proposal(
        &self,
        log: TipLog,
        coordinator: &dyn DomainLog,
    ) -> Result<Recovery, Error> {
        let head = coordinator
            .log_head(log)
            .await
            .map_err(Error::Coordination)?;
        if head.terminal.is_some() {
            return Err(refusal("sealed", "a terminal entry ended the tip's log"));
        }
        let point = LogPoint {
            position: head.commit,
            running: head.running_hash,
        };
        Ok(Recovery {
            retained: point,
            replaced: point,
        })
    }
}
