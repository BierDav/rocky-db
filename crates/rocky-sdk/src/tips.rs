//! The JSON contract of seals, tips and bookmarks. Digests and tips are
//! lowercase hex; see `docs/runtime/tips-and-bookmarks.md`.
use serde::{Deserialize, Serialize};

/// The followed bookmark and tip, progress since the last seal and each
/// peer's last reported frontier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipStatus {
    /// None until this device follows a bookmark.
    pub bookmark: Option<String>,
    pub pending_follow: Option<String>,
    pub tip: String,
    pub operations_since_seal: u64,
    /// An optional estimate of what compaction would release.
    pub evidence_releasable: Option<TipEvidence>,
    pub devices: Vec<TipDevice>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipEvidence {
    pub operations: u64,
    pub bytes: u64,
}
/// A peer: the tip its open link claims, if any, and its last frontiers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipDevice {
    pub node: String,
    pub tip: Option<String>,
    pub frontiers: Vec<TipScopeFrontier>,
}
/// One resource scope, as its JSON encoding, and per-author log positions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipScopeFrontier {
    pub scope: String,
    pub logs: Vec<TipFrontierLog>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipFrontierLog {
    pub author: String,
    pub held: u64,
    pub applied: u64,
}
/// The last included global position of one author number.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipAuthorMark {
    pub author: u32,
    pub sequence: u64,
}
/// The coordinated log positions the owner's recovery seal retains and
/// replaces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipRecovery {
    pub retained: u64,
    pub replaced: u64,
}
/// A seal; a `continue` seal's id is also its successor tip.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipSeal {
    pub id: String,
    pub tip: String,
    pub frontier: Vec<TipAuthorMark>,
    /// `continue` or `close`.
    pub action: String,
    /// The successor's schema of a `continue` seal.
    pub schema: Option<String>,
    /// False for a concurrent seal of the same tip that lost.
    pub canonical: bool,
    /// Who signed it: `owner`, `trusted` or `issuer`; races resolve in
    /// that order, then by the lower digest.
    pub authority: String,
    /// A revocation ended its signer; it takes part in no race.
    pub revoked: bool,
    /// Its tip's coordinated log committed it and enough trusted nodes
    /// acknowledged that: it beats every other seal of its tip.
    #[serde(rename = "final")]
    pub finalized: bool,
    /// Checkpoints of this seal's state the graph lists, by digest.
    pub checkpoints: Vec<TipCheckpoint>,
    /// How this device holds the seal's state: `kept`, `checkpoint` or
    /// `live`; null when it is shallow here.
    pub held: Option<String>,
    /// The owner's recovery of a stuck tip; null for any other seal.
    pub recovery: Option<TipRecovery>,
}
/// The seals a device keeps, among those of the tips it follows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeptSeals {
    /// The seal each bookmarked tip starts from, or a closed tip's own.
    #[serde(default)]
    pub bookmarked: bool,
    /// The latest this many kept seals.
    #[serde(default)]
    pub latest: u32,
    /// Every seal.
    #[serde(default)]
    pub every: bool,
}
/// A checkpoint of one scope at a seal; its body moves only on request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipCheckpoint {
    /// The listing record's digest.
    pub id: String,
    pub scope: String,
    pub checkpoint: String,
    /// The node that signed the checkpoint.
    pub signer: String,
    /// Who listed it: `owner`, `trusted` or `issuer`.
    pub authority: String,
    /// Its size in stored rows.
    pub rows: u64,
}
/// An opened tip; its id is the tip.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipOpening {
    pub id: String,
    pub seal: String,
    pub schema: String,
    pub minimum_in_sync: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookmarkMove {
    pub id: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub authority: String,
    pub revoked: bool,
}
/// A move that lost a race along its bookmark's path, named in the manner
/// of jj: `main/1`, `main/2`. Its tip stays a branch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LosingMove {
    pub name: String,
    #[serde(rename = "move")]
    pub movement: String,
    pub tip: Option<String>,
}
/// A bookmark's resolved tip, none once deleted, every move of it and the
/// moves that lost.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bookmark {
    pub name: String,
    pub tip: Option<String>,
    pub moves: Vec<BookmarkMove>,
    pub losers: Vec<LosingMove>,
}
/// What a node follows and keeps; null where this device cannot know.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipNode {
    pub node: String,
    pub followed_tip: Option<String>,
    pub kept_tips: Option<Vec<String>>,
    pub kept_seals: Option<Vec<String>>,
}
/// The owner's trusted grant to an identity: `grant` is opaque hex the
/// identity's device installs; `capability` is what revocation names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustGrant {
    pub identity: String,
    pub capability: String,
    pub grant: String,
}
/// The domain's complete graph, for developers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipInspection {
    /// The domain scope, as its JSON encoding.
    pub scope: String,
    pub genesis: String,
    /// The genesis tip's schema digest.
    pub schema: String,
    /// The owner's minimum of trusted acknowledgments that makes a seal on
    /// the genesis line final; none while unsigned.
    pub genesis_minimum: Option<u32>,
    pub seals: Vec<TipSeal>,
    pub openings: Vec<TipOpening>,
    pub bookmarks: Vec<Bookmark>,
    pub nodes: Vec<TipNode>,
}
/// Where this device's compaction of the followed path stands. Seals are
/// hex digests; see `docs/runtime/lazy-compaction.md`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipCompaction {
    /// The newest seal whose state this device finalized.
    pub finalized: Option<String>,
    /// The seal the replay base sits at.
    pub compacted: Option<String>,
    /// Finalized seals whose evidence is still retained, oldest first.
    pub uncompacted: Vec<String>,
    /// Why the next seal of the followed path is not finalized yet.
    pub waiting: Option<String>,
    /// The compacted seal lost a race; the base must be rebuilt at this one.
    pub rebootstrap: Option<String>,
    /// Operations this call released; zero for status.
    pub pruned: u64,
    /// What stopped releasing a scope's operations in this call.
    pub blocked: Vec<TipPruneBlock>,
}
/// One resource scope, as its JSON encoding, and why it kept operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipPruneBlock {
    pub scope: String,
    pub reason: String,
}
