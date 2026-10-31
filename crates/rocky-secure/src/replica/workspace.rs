//! The live workspace of a replica: the typed tables that hold the followed
//! tip under their plain names, the tip they hold and their observers. The
//! runtime keeps exactly one; code reaches the live tables only through it.
//! See `docs/runtime/kept-seals.md`.
use super::*;

pub(crate) struct Workspace {
    /// The bookmark this workspace follows, if any.
    pub(crate) followed: Option<(rocky_core::Scope, String)>,
    /// The tip whose state the live tables hold.
    pub(crate) tip: TipId,
    /// Installed typed tables that stored rows project into.
    pub(super) typed: Option<Arc<typed::Typed>>,
    /// Cursors, table events and the authority mirror of the live tables.
    pub(crate) queries: queries::Queries,
    /// Bulk rebuilds of the live tables in progress.
    pub(super) bulk: history::Bulk,
}
impl Workspace {
    pub(super) fn new(tip: TipId) -> Self {
        Self {
            followed: None,
            tip,
            typed: None,
            queries: Default::default(),
            bulk: Default::default(),
        }
    }
}
