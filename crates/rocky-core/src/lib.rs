//! Canonical operation protocol and the application boundary for pure reducers.
mod blocker;
pub use blocker::*;
mod capture;
mod codec;
mod coordinated;
pub use coordinated::*;
mod definition;
pub use definition::*;
mod generation;
pub use generation::{Generation, Removed, SchemaChange, Unsupported, classify, removed};
mod manifest;
pub use manifest::*;
mod secure_row;
pub use secure_row::{CreationStatement, SecureStamp};
mod field_ordinals;
pub use field_ordinals::FieldOrdinals;
mod history;
mod key;
mod key_epoch;
pub use key_epoch::KeyEpoch;
mod deterministic;
pub use deterministic::DETERMINISTIC_FUNCTIONS;
mod logical;
mod migration;
pub use migration::*;
pub mod net;
pub mod replay;
mod storage;
mod types;
mod value;

pub use capture::{Intent, TransactionToken};
pub use history::{AppliedOperations, Delivery};
pub use key::{KeyColumn, MAX_KEY_BYTES, bound_key, key_components, key_values};
pub use logical::*;
pub use storage::{
    ApplicationDescriptor, AuthoredFollow, CompiledSchema, InstalledSchema, ProjectionSchema,
    ProjectionStatement, ReadView, Sql, StoredApplication, columns, installed_definition,
};
pub use types::*;
pub use value::{Real, SqlValue};

/// Authorization uses the installed current policy; historical replay bypasses it.
#[derive(Clone, Copy, Debug)]
pub struct AdmissionContext {
    pub scope: Scope,
    pub caller: PrincipalId,
    pub policy_version: u64,
    pub boundary: AdmissionBoundary,
}
/// Applications own validation, admission, and projection meaning. The runtime
/// checks readiness and commits history and projection together before publishing.
pub trait Application {
    type State: Default;
    type Error: std::error::Error + Send + Sync + 'static;
    type Policy;

    fn validate(&self, envelope: &Envelope) -> Result<(), Self::Error>;
    fn admit(&self, envelope: &Envelope, policy: &Self::Policy) -> Result<(), Self::Error>;
    fn policy_version(&self, _policy: &Self::Policy) -> u64 {
        1
    }
    /// Check the whole candidate transition, including paired row/field grants
    /// on both before and after state. A runtime passes windows holding only
    /// the rows the operation touches. Rejection discards all candidate changes.
    fn admit_candidate(
        &self,
        _before: &Self::State,
        _after: &Self::State,
        envelope: &Envelope,
        _context: AdmissionContext,
        policy: &Self::Policy,
    ) -> Result<(), Self::Error> {
        self.admit(envelope, policy)
    }
    /// Classifies an effect-free operation on an incarnation covered by a runtime pruned prefix.
    /// Admission still runs; implementations must identify only absent/retired rows or insert conflicts.
    fn definite_drop(&self, _state: &Self::State, _envelope: &Envelope) -> bool {
        false
    }
    /// Caller must first admit the operation and establish readiness with
    /// `AppliedOperations::classify`. Local business checks run before mutation.
    fn apply_ready(
        &self,
        state: &mut Self::State,
        envelope: &Envelope,
        boundary: AdmissionBoundary,
    ) -> Result<(), Self::Error>;
}

mod coordination;
pub use coordination::*;
mod tip;
pub use tip::TipId;

mod partition_groups;
pub use partition_groups::{GroupAddress, PartitionGroup};
mod partition;
pub use partition::{
    MAX_PARTITION_BYTES, PartitionError, PartitionSelection, PartitionSelector, PartitionTuple,
    PartitionValue,
};
mod permissions;
pub use permissions::*;

mod row_identity;
pub use row_identity::{RowIdentity, RowIdentityError};

mod typed_rows;
pub use typed_rows::{TypedRows, TypedTable, default_value};
