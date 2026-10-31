//! Why a replica cannot read, write or import a scope yet. Blockers are
//! derived from stored state on demand; they never name row values, keys or
//! credentials.
use crate::{ResourceScope, Scope, commitment};
use serde::{Deserialize, Serialize};
use std::fmt;

/// One reason a scope, or a whole domain, waits.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Blocker {
    /// `scope_label` of the waiting scope, or `domain_label` of a domain.
    pub scope: String,
    pub kind: BlockerKind,
    pub clears_by: ClearsBy,
    /// Epoch seconds of the earliest stored time that explains it.
    pub since: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BlockerKind {
    /// The bootstrap intent still imports this scope from a checkpoint.
    BootstrapMarker,
    /// The latest request for this scope failed or was refused.
    SyncRequest { refused: bool },
    /// A joined device waits for one exchange with its inviter.
    AwaitingInviter,
    /// The owner imports the scope and it holds no rows yet.
    Importing,
    /// A checkpoint import is staged; `sealed` is false for one outside a
    /// seal, which holds back the whole domain.
    StagedImport { sealed: bool, pages_complete: bool },
    /// The domain's compacted seal lost a race.
    LostCompaction,
    /// The scope's replay base must move to a seal of the followed path.
    SealRebootstrap { replay: FrameReplay, listed: u64 },
    /// Frames this node authored before an eviction must come back first.
    RestorationGuard,
    /// Frames of a dropped tip on the followed path are missing.
    DroppedTipFrames { count: u64 },
    /// The followed line has no node of this identity to author with, or
    /// its node's credentials no longer verify.
    LineNode,
    /// Received frames wait to apply.
    PendingFrames { reason: WaitReason, count: u64 },
    /// A frame failed to apply and its log waits behind it; `reason` is the
    /// failure's category, `count` the frames of those logs.
    Quarantined { reason: String, count: u64 },
    /// The next seal of the followed path is not finalized yet.
    FinalizationWaiting { reason: String },
}

/// How a scope without a listed checkpoint is rebuilt from frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameReplay {
    /// It holds every frame it applied: its rows are rebuilt from them.
    Local,
    /// Frames were pruned: it keeps the ones it holds and the rest come
    /// again from a peer that retains them.
    Peers,
}

/// Who can clear a blocker.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClearsBy {
    AnyPeer,
    /// The peer with this hex node key.
    Peer {
        node: String,
    },
    LocalWork,
    Application,
    /// No peer this device may reach can serve it yet: a trusted peer must
    /// list a base for it first.
    NoPeer,
}

/// Why a received frame does not apply yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitReason {
    /// Its source tip's schema is not installed or not on the path.
    Schema,
    /// A direct checkpoint import is filling its scope.
    DirectImport,
    /// The key epoch it was sealed under is not held.
    OpeningKey,
    /// This device may not read its scope now.
    ReadGrant,
    /// This node's own earlier frames must be restored first.
    OwnChain,
    /// A dependency is not applied yet.
    Dependencies,
    /// It does not decrypt under the held key.
    Undecryptable,
    /// Its scope's replay ledger waits for a base.
    Ledger,
    /// Applying it failed with an error that is not a refusal.
    Failed,
    /// It is quarantined after a failure; it is retried on change or after
    /// a backoff.
    Quarantined,
    /// No apply pass of this process examined it yet.
    Unexamined,
}

impl WaitReason {
    pub fn clears_by(self) -> ClearsBy {
        match self {
            Self::Schema | Self::ReadGrant => ClearsBy::Application,
            Self::Ledger | Self::Failed | Self::Quarantined | Self::Unexamined => {
                ClearsBy::LocalWork
            }
            Self::DirectImport
            | Self::OpeningKey
            | Self::OwnChain
            | Self::Dependencies
            | Self::Undecryptable => ClearsBy::AnyPeer,
        }
    }
}

/// The short, stable label of a resource scope in diagnostics.
pub fn scope_label(scope: &ResourceScope) -> String {
    label("rocky.blocker.scope.v1", serde_json::to_vec(scope))
}
/// The short label of a whole domain in diagnostics.
pub fn domain_label(domain: &Scope) -> String {
    label("rocky.blocker.domain.v1", serde_json::to_vec(domain))
}
fn label(prefix: &str, bytes: Result<Vec<u8>, serde_json::Error>) -> String {
    let hash = commitment(prefix, &bytes.unwrap_or_default());
    hash[..6].iter().map(|byte| format!("{byte:02x}")).collect()
}

impl fmt::Display for Blocker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match &self.kind {
            BlockerKind::SyncRequest { refused } => format!(
                "sync request {}",
                if *refused { "refused" } else { "failed" }
            ),
            BlockerKind::BootstrapMarker => "bootstrap marker".into(),
            BlockerKind::AwaitingInviter => "awaiting inviter".into(),
            BlockerKind::Importing => "importing".into(),
            BlockerKind::StagedImport {
                sealed,
                pages_complete,
            } => format!("staged import (sealed={sealed}, pages complete={pages_complete})"),
            BlockerKind::LostCompaction => "lost compaction".into(),
            BlockerKind::SealRebootstrap { replay, listed } => {
                format!("seal rebootstrap (replay={replay:?}, listed={listed})")
            }
            BlockerKind::RestorationGuard => "restoration guard".into(),
            BlockerKind::DroppedTipFrames { count } => format!("{count} dropped tip frames"),
            BlockerKind::LineNode => "no node of this identity on the followed line".into(),
            BlockerKind::PendingFrames { reason, count } => {
                format!("{count} pending frames ({reason:?})")
            }
            BlockerKind::Quarantined { reason, count } => {
                format!("{count} quarantined frames ({reason})")
            }
            BlockerKind::FinalizationWaiting { reason } => {
                format!("finalization waiting ({reason})")
            }
        };
        let clears = match &self.clears_by {
            ClearsBy::AnyPeer => "any permitted peer".into(),
            ClearsBy::Peer { node } => format!("peer {}", node.get(..12).unwrap_or(node)),
            ClearsBy::LocalWork => "local work".into(),
            ClearsBy::Application => "the application".into(),
            ClearsBy::NoPeer => return write!(f, "{} {kind}: no peer can serve", self.scope),
        };
        write!(f, "{} {kind}, cleared by {clears}", self.scope)
    }
}

/// Renders a refusal's blockers on one line.
pub fn describe_blockers(blockers: &[Blocker]) -> String {
    let list: Vec<String> = blockers.iter().map(ToString::to_string).collect();
    format!(
        "the workspace waits for {} blockers: {}",
        blockers.len(),
        list.join("; ")
    )
}
