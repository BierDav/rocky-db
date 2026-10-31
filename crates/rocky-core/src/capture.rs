//! Caller-chosen transaction tokens and the precise actions applications
//! author for their own follows.
use crate::{Commitment, OperationId};

/// Chosen by the caller before a commit. The runtime stores it with the
/// commit, so a caller that lost the acknowledgment can ask for the outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransactionToken(pub Commitment);

/// A precise application action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    /// None targets the operation this intent becomes.
    pub entity: Option<OperationId>,
    pub payload: Vec<u8>,
}
