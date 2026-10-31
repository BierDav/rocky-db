#![recursion_limit = "256"]
//! Rocky DB's official Rust application SDK.
//!
//! Add `rocky-sdk = "<release version>"` to your dependencies.
//! Disable default features for storage without iroh. No ORM or native binding
//! generator is needed. Run async SDK methods inside a Tokio runtime.
//!
//! ```no_run
//! use rocky_sdk::{Affinity, Column, Configuration, Failure, Schema, Table, params};
//!
//! # async fn application() -> Result<(), Failure> {
//! let schema = Schema::builder("notes", 1)
//!     .table(Table::replayed("notes")
//!         .column(Column::new("body", Affinity::Text).required()))
//!     .build()?;
//! let configuration = Configuration::new("notes-data", &schema)?;
//! let database = configuration.create().await?.database;
//! let mut transaction = database.transaction().await?;
//! let id = transaction.next_id("notes", params![]).await?;
//! transaction.execute("INSERT INTO notes(id,body) VALUES(?,?)", params![id, "Hello Rocky"])
//!     .await?;
//! transaction.commit().await?;
//! let mut rows = database.query("SELECT body FROM notes WHERE id=?", params![id]).await?;
//! if let Some(row) = rows.next().await? {
//!     println!("{}", row.get::<String>("body")?);
//! }
//! drop(rows);
//! database.close().await?;
//! # Ok(()) }
//! ```
//!
//! Reuse configuration with `open().await` for an existing installation or
//! `join(invitation).await` to enroll. Networking is opt-in through
//! [`Configuration::network`]; [`Network::Borrowed`] keeps ownership with the app.
//! [`Session::pairing`] requires an explicit [`GrantProfile`].
//!
//! Queries buffer one page; collect only results that fit in memory. Register
//! [`Database::observe_tables`] before querying to avoid missing invalidations.
//! Transactions roll back on drop and acknowledge local durability on commit.
//! They never retry application work automatically. Cancellation during commit
//! can leave its outcome uncertain; reconcile before repeating the write.
//!
//! Call [`Database::close`] at shutdown to await cleanup. See the `notes` example
//! for a complete executable application.
mod activity;
mod backup;
mod configuration;
mod connection;
mod custody;
mod database;
mod delivery;
mod domain;
mod engine;
mod enrollment;
mod generation;
mod groups;
mod identities;
mod mesh;
mod node;
mod owner;
mod reactor;
mod registry;
mod rollout;
mod scheduling;
mod schema;
mod secrets;
mod self_enrollment;
mod service;
mod session;
#[cfg(test)]
mod simulation;
mod sql;
mod status;
mod sync;
#[cfg(test)]
mod test_directory;
mod tip_schemas;
mod tips;
pub mod transport;

pub use backup::{Entry as BackupEntry, Inventory as BackupInventory};
pub use configuration::Configuration;
pub use connection::{
    Binding, ConnectionOptions, Durability, Page, Profile, SqlFailure, TableChange, TableEvents,
};
pub use custody::CustodyPeer;
pub use database::{Connection, Coordination, Database, NetworkService, Open, Opened, Session};
pub use engine::Engine;
pub use enrollment::{DeviceKeys, Supplied, route_enrollment};
#[cfg(feature = "qualification")]
pub use reactor::{ReactorMeasurements, ReactorSnapshot, SqlCallTiming};
/// The client of a coordination service and the bundle that pins it.
#[cfg(feature = "iroh")]
pub use rocky_coordinator::{certified::TrustBundle, service::NetworkCoordinator};
pub use rocky_core::replay::{DropReason, TransactionOutcome};
pub use rocky_core::{
    Affinity, Collation, ColumnDefinition, DeleteAction, ForeignKeyDefinition, IndexColumn,
    IndexDefinition, LogicalView, TableClass, TableDefinition,
};
pub use rocky_core::{NodeId, PrincipalId, Scope, SqlValue, TransactionToken};
/// Signed credentials, grant profiles and the key provider contract.
pub use rocky_credentials as credentials;
pub use rocky_credentials::Profile as GrantProfile;
/// The identity port an application supplies, and a file-backed provider.
pub use rocky_credentials::{FileIdentityProvider, IdentityProvider, Purpose};
pub use rollout::{RemovalImpact, RolloutConfirmationRequired, RolloutImpact};
pub use schema::{Column, Migration, MigrationStep, Schema, SchemaBuilder, Table};
pub use secrets::{FileSecretStore, SecretStore};
pub use service::{Network, ServiceError};
pub use session::Invitation;
pub use sql::{DecodeError, FromSqlValue, IntoSqlValue, Row, Rows, Transaction};
pub use status::*;
pub use tips::*;
pub type Failure = Box<dyn std::error::Error + Send + Sync>;
/// Rocky's handlers for an application-owned iroh endpoint, and the iroh
/// version they attach to.
#[cfg(feature = "iroh")]
pub use rocky_iroh as iroh;
