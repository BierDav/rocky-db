//! One open secure database: its replica, identity, sessions and optional
//! network service, and the JSON calls of the native ABI. See
//! `docs/runtime/sdk-composition.md` and `docs/runtime/sdk-enrollment.md`.
mod coordinated;
mod delivery;
mod discovery;
mod held;
mod live_links;
mod mesh;
mod partition;
mod recovery;
mod registry;
mod schema_publication;
mod schemas;
mod shared;
mod status;
mod tip_nodes;
mod tips;
use crate::{
    Failure,
    domain::Domain,
    enrollment::{Contact, Settings, Terms, answer, exchange, now},
    secrets::Vault,
    service::{Network, ServiceError},
    sync::{self, Upstream},
    transport::{Protocol, Stream, Transport},
};
use data_encoding::HEXLOWER;
use futures_util::{StreamExt, stream};
use rocky_core::{ResourceScope, SqlValue, TypedRows, commitment};
use rocky_credentials::Profile;
use rocky_secure::{
    CredentialChain, EncryptedReplica, Error, KeyMaterial, PrivateKey, PublicKey, RevocationSet,
    SecureSession, SecureSql, SqlError, SqlOptions, Unavailable, secure_node_id,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub(crate) use shared::Shared;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, RwLock, Semaphore, watch};

const MAX_ROWS: usize = 1024;
const MAX_SQL: usize = 64 * 1024;
const MAX_SUBSCRIPTIONS: usize = 64;
const MAX_SESSIONS: usize = 64;
/// Concurrent inbound streams a node serves; more are dropped.
const INBOUND: usize = 32;
/// Peers met without a contact that `peers` lists.
const MET: usize = 64;
/// How long a closing network service lets its work finish before it
/// cancels what remains.
const DRAIN: Duration = Duration::from_secs(5);
/// How long a staged checkpoint import waits for its linked signer without
/// a new page before another peer may restart it from its own checkpoint.
const IMPORT_SOURCE: Duration = Duration::from_secs(180);

/// A definite refusal: retrying the same call cannot succeed.
#[derive(Debug)]
pub struct Refused(pub String);
impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Refused {}
fn refused(error: impl std::fmt::Display) -> Failure {
    Box::new(Refused(error.to_string()))
}
/// A refusal that keeps a named error, such as a full registry.
fn named(error: Failure) -> Failure {
    if error.is::<crate::registry::RegistryFull>() {
        error
    } else {
        refused(error)
    }
}

/// A bound SQL value as the JSON contract spells it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub(crate) enum Cell {
    Null,
    Integer(String),
    /// The 16 hexadecimal digits of the double's bits.
    Real(String),
    Text(String),
    Blob(Vec<u8>),
}
impl Cell {
    pub(crate) fn sql(self) -> Result<SqlValue, Failure> {
        Ok(match self {
            Self::Null => SqlValue::Null,
            Self::Integer(value) => SqlValue::Integer(value.parse()?),
            Self::Real(bits) => SqlValue::Real(
                u64::from_str_radix(&bits, 16)
                    .ok()
                    .filter(|_| bits.len() == 16)
                    .and_then(rocky_core::Real::from_bits)
                    .ok_or("invalid REAL bits")?,
            ),
            Self::Text(value) => SqlValue::Text(value),
            Self::Blob(value) => SqlValue::Blob(value),
        })
    }
}
impl From<SqlValue> for Cell {
    fn from(value: SqlValue) -> Self {
        match value {
            SqlValue::Null => Self::Null,
            SqlValue::Integer(value) => Self::Integer(value.to_string()),
            SqlValue::Real(value) => Self::Real(format!("{:016x}", value.bits())),
            SqlValue::Text(value) => Self::Text(value),
            SqlValue::Blob(value) => Self::Blob(value),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    sql: String,
    #[serde(default)]
    values: Vec<Cell>,
    max_rows: usize,
    /// Encoded page budget, capped at the native frame limit.
    #[serde(default)]
    max_bytes: Option<usize>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Clone)]
struct Reader {
    session: SecureSession<TypedRows>,
    sql: Arc<SecureSql<TypedRows>>,
}
struct Subscription {
    query: Query,
    delivered: Option<String>,
}

/// One session's reader and subscriptions. Sessions share the database.
pub(crate) struct Client {
    reader: Mutex<Option<Reader>>,
    cursor_key: [u8; 32],
    subscriptions: std::sync::Mutex<BTreeMap<u64, Subscription>>,
    next: AtomicU64,
    closing: watch::Sender<bool>,
    subscriptions_changed: watch::Sender<()>,
}
impl Client {
    fn subscriptions(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, BTreeMap<u64, Subscription>>, Failure> {
        self.subscriptions
            .lock()
            .map_err(|_| "subscriptions poisoned".into())
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Stage {
    Open,
    /// Accepts nothing new; admitted work finishes.
    Draining,
    Cancelled,
}
/// The attached network service.
struct Link {
    id: u64,
    transport: Arc<dyn Transport>,
    owned: bool,
    stage: watch::Sender<Stage>,
    server: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    synchronizer: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    publisher: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// What the transport finds peers with, and the worker announcing on it.
    discovery: Option<Arc<dyn crate::transport::Discovery>>,
    discoverer: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Inbound streams being served, served so far and dropped over budget.
    active: Arc<Semaphore>,
    live_budget: Arc<Semaphore>,
    live_handshakes: Arc<Semaphore>,
    live: live_links::Registry,
    served: AtomicU64,
    refused: AtomicU64,
}
/// Signals when an automatic pass has been dropped.
struct WorkerActivity(watch::Sender<bool>);
impl Drop for WorkerActivity {
    fn drop(&mut self) {
        self.0.send_replace(false);
    }
}
struct SyncActivity(watch::Sender<&'static str>);
impl Drop for SyncActivity {
    fn drop(&mut self) {
        self.0.send_replace("idle");
    }
}
#[derive(Default)]
struct PeerRetry {
    short: bool,
    retry: crate::scheduling::Retry,
    pending: bool,
    link: bool,
    link_retry: crate::scheduling::Retry,
    generation: u64,
}
struct SyncFailure {
    refused: bool,
    since: Option<u64>,
}
struct Reached {
    at: u64,
    error: Option<String>,
    /// Scopes the last successful sync with the peer did not exchange.
    refused: Vec<ResourceScope>,
    /// Scopes the peer restores from a checkpoint instead of this device's history.
    waiting: Vec<ResourceScope>,
    held: Vec<ResourceScope>,
}

/// How long the sync worker lets a committed change settle before its pass:
/// local observers read first on the shared reactor, and a burst of commits
/// becomes one pass. The crate's own tests freeze the clock and run without it.
const LOCAL_SETTLE: std::time::Duration =
    std::time::Duration::from_millis(if cfg!(test) { 0 } else { 20 });
/// Waits `LOCAL_SETTLE`; with none there is no timer at all.
async fn settle() {
    if !LOCAL_SETTLE.is_zero() {
        tokio::time::sleep(LOCAL_SETTLE).await;
    }
}

pub(crate) struct Node {
    owner: std::sync::OnceLock<std::sync::Weak<Node>>,
    pub replica: EncryptedReplica<TypedRows>,
    /// The installed generation's domain; replaced when the database adopts
    /// a newer generation.
    domain: std::sync::RwLock<Arc<Domain>>,
    /// The scopes this device's credentials name. A renewal keeps them.
    granted: std::sync::Mutex<Vec<ResourceScope>>,
    pub vault: Vault,
    pub settings: Mutex<Shared<Settings>>,
    schema_fetch: Mutex<()>,
    schema_acquisition: std::sync::Mutex<schemas::Acquisition>,
    pub path: PathBuf,
    pub online: AtomicBool,
    /// Set by logout; `purge` also removes local data at close.
    pub ended: Mutex<Option<bool>>,
    /// Calls that use the network hold it shared; attach and detach replace it.
    network: RwLock<Option<Arc<Link>>>,
    /// The attached link for status calls, which never wait for the network.
    current: std::sync::Mutex<Option<Arc<Link>>>,
    detaching: Mutex<()>,
    links: AtomicU64,
    clients: std::sync::Mutex<BTreeMap<u64, Arc<Client>>>,
    syncing: Mutex<()>,
    bootstrap: Mutex<()>,
    retry_seed: u64,
    retries: std::sync::Mutex<BTreeMap<PublicKey, PeerRetry>>,
    /// The followed tip the peers' backoff was earned on.
    backoff_tip: std::sync::Mutex<Option<rocky_core::TipId>>,
    resolution_retries:
        std::sync::Mutex<BTreeMap<rocky_credentials::PeerId, crate::scheduling::Retry>>,
    sync_control: watch::Sender<u64>,
    worker_running: watch::Sender<bool>,
    sync_state: watch::Sender<&'static str>,
    automatic: AtomicBool,
    foreground: AtomicBool,
    sync_events: watch::Sender<u64>,
    link_events: watch::Sender<()>,
    sync_status: watch::Sender<Value>,
    link_revision: AtomicU64,
    /// What the node did in the background, for applications to show.
    pub(crate) activity: crate::activity::Activity,
    backups: Mutex<()>,
    reached: std::sync::Mutex<BTreeMap<PublicKey, Reached>>,
    /// Peers whose sessions this device served, with the last time; at
    /// most `MET` are kept.
    met: std::sync::Mutex<BTreeMap<PublicKey, u64>>,
    /// A session brought statements since the last renewal. Rotated keys
    /// still arrive by renewal, so the next sync pass renews once.
    learned: AtomicBool,
    handover: std::sync::Mutex<std::collections::BTreeSet<PublicKey>>,
    /// By scope, the last staged row of an import another peer would
    /// restart and when it was last seen to move.
    import_sources: std::sync::Mutex<
        BTreeMap<ResourceScope, (Option<rocky_core::Commitment>, tokio::time::Instant)>,
    >,
    sync_failures: std::sync::Mutex<BTreeMap<(PublicKey, ResourceScope), SyncFailure>>,
    choices: std::sync::Mutex<BTreeMap<PublicKey, &'static str>>,
    /// Signals that the discovery topics may have changed.
    topics: watch::Sender<u64>,
    /// Whether this device announces under a topic now.
    announcing: AtomicBool,
    /// Moves the discovery clock forward, for the topic window.
    #[cfg(test)]
    pub(crate) discovery_skew: AtomicU64,
    observations: crate::status::Observations,
    node_identity: Result<String, String>,
    #[cfg(test)]
    status_clock: std::sync::Mutex<Option<(u64, tokio::time::Instant)>>,
    last_reconciliation: std::sync::Mutex<Option<crate::ReconciliationReport>>,
    /// Each peer's last exchange that was not skipped.
    last_syncs: std::sync::Mutex<BTreeMap<String, crate::PeerReconciliation>>,
    /// The coordination service this database is composed with, for its owner.
    service: Option<crate::owner::Service>,
    /// Deposits held as a mailbox, loaded at first use.
    mailbox: Mutex<Option<crate::delivery::Mailbox>>,
    /// The schema the application declares, which may be older or newer
    /// than the installed generation's.
    declared: crate::schema::Schema,
    /// Generations whose wider profile grants this process asked an issuer
    /// for once.
    widened: std::sync::Mutex<std::collections::BTreeSet<String>>,
}

impl Node {
    /// The domain of the installed generation.
    pub fn domain(&self) -> Arc<Domain> {
        self.domain
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
    pub fn new(
        replica: EncryptedReplica<TypedRows>,
        domain: Domain,
        vault: Vault,
        settings: Settings,
        path: PathBuf,
    ) -> Self {
        let settings_schema = settings.schema.clone();
        let observations = crate::status::Observations::default();
        Self {
            #[cfg(test)]
            status_clock: Default::default(),
            node_identity: vault
                .get("node")
                .map(|key| PrivateKey::from_bytes(&key).public_key().to_hex())
                .map_err(|error| error.to_string()),
            last_reconciliation: Default::default(),
            last_syncs: Default::default(),
            observations,
            owner: Default::default(),
            replica,
            granted: std::sync::Mutex::new(settings.granted(&domain)),
            domain: std::sync::RwLock::new(Arc::new(domain)),
            vault,
            settings: Mutex::new(Shared::new(settings)),
            path,
            online: AtomicBool::new(true),
            ended: Mutex::new(None),
            network: RwLock::new(None),
            current: std::sync::Mutex::new(None),
            detaching: Mutex::new(()),
            links: AtomicU64::new(1),
            clients: std::sync::Mutex::new(BTreeMap::new()),
            syncing: Mutex::new(()),
            bootstrap: Mutex::new(()),
            retry_seed: rand::random(),
            retries: std::sync::Mutex::new(BTreeMap::new()),
            backoff_tip: std::sync::Mutex::new(None),
            resolution_retries: std::sync::Mutex::new(BTreeMap::new()),
            sync_control: watch::channel(0).0,
            worker_running: watch::channel(false).0,
            sync_state: watch::channel("idle").0,
            automatic: AtomicBool::new(false),
            foreground: AtomicBool::new(true),
            sync_events: watch::channel(0).0,
            link_events: watch::channel(()).0,
            link_revision: AtomicU64::new(0),
            sync_status: watch::channel(json!({"token": "0", "state": "idle", "retry": false})).0,
            activity: crate::activity::Activity::new(),
            backups: Mutex::new(()),
            reached: std::sync::Mutex::new(BTreeMap::new()),
            met: std::sync::Mutex::new(BTreeMap::new()),
            learned: AtomicBool::new(false),
            handover: std::sync::Mutex::new(Default::default()),
            import_sources: std::sync::Mutex::new(Default::default()),
            sync_failures: Default::default(),
            choices: std::sync::Mutex::new(BTreeMap::new()),
            topics: watch::channel(0).0,
            announcing: AtomicBool::new(false),
            #[cfg(test)]
            discovery_skew: AtomicU64::new(0),
            service: None,
            mailbox: Mutex::new(None),
            declared: settings_schema,
            schema_fetch: Mutex::new(()),
            schema_acquisition: Default::default(),
            widened: Default::default(),
        }
    }
    /// Lets the owner control its domain on this coordination service.
    pub fn with_service(mut self, service: Option<crate::owner::Service>) -> Self {
        self.service = service;
        self
    }
    /// The schema the application declared at open.
    pub fn with_declared(mut self, schema: crate::schema::Schema) -> Self {
        self.declared = schema;
        self
    }
    /// The version the application declares: Room's database version.
    pub fn declared_version(&self) -> u32 {
        self.declared.version
    }
    /// The tables the application declares differently from the installed
    /// generation, as it declares them; none while they are the same.
    pub fn declared_differences(&self) -> Result<Vec<rocky_core::LogicalTable>, Failure> {
        let domain = self.domain();
        let installed = domain.logical();
        let declared = crate::domain::logical(&self.declared, installed.publisher)?;
        Ok(declared
            .tables
            .into_iter()
            .filter(|table| installed.table(&table.sql_name) != Some(table))
            .collect())
    }
    /// How the application's schema stands to the installed generation's.
    pub async fn application(&self, settings: &Settings) -> Result<crate::DeclaredSchema, Failure> {
        if self.replica.followed_bookmark().await.is_none() {
            return Ok(crate::DeclaredSchema::Ahead);
        }
        settings.application(&self.declared)
    }
    /// The migration this device publishes, or waits for while the
    /// application declares migrations it may not run.
    pub(crate) async fn migration(
        &self,
        settings: &Settings,
    ) -> Result<Option<crate::MigrationStatus>, Failure> {
        let (mut bundles, mut published) = (0, 0);
        let mut pending = false;
        for publication in self.replica.publications().await? {
            if publication.published < publication.bundles
                || !self
                    .replica
                    .migration_checkpoint_listed(publication.id)
                    .await?
            {
                pending = true;
                bundles += publication.bundles;
                published += publication.published;
            }
        }
        if pending {
            return Ok(Some(crate::MigrationStatus::Publishing {
                bundles,
                published,
            }));
        }
        Ok(
            (self.application(settings).await? == crate::DeclaredSchema::Ahead
                && crate::generation::migrates(&self.declared, settings.generation)
                && !settings.may_migrate(&self.domain())?)
            .then_some(crate::MigrationStatus::FullAccessRequired),
        )
    }
    /// Every granted scope, the registry's included: what sync covers.
    pub(crate) fn scopes(&self) -> Vec<ResourceScope> {
        self.granted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
    /// The granted scopes the application's sessions open: the registry is
    /// the SDK's own.
    fn app_scopes(&self) -> Vec<ResourceScope> {
        let registry = self.domain().registry();
        self.scopes()
            .into_iter()
            .filter(|scope| *scope != registry)
            .collect()
    }

    fn clients(&self) -> Vec<Arc<Client>> {
        self.clients
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }
    /// The state of session `id`, created by its first call. Resolved as
    /// a call arrives, so a session's end never precedes its earlier calls.
    pub fn client(&self, id: u64) -> Result<Arc<Client>, Failure> {
        let mut clients = self.clients.lock().map_err(|_| "sessions poisoned")?;
        if let Some(client) = clients.get(&id) {
            return Ok(client.clone());
        }
        if clients.len() >= MAX_SESSIONS {
            return Err("session quota".into());
        }
        let client = Arc::new(Client {
            reader: Mutex::new(None),
            cursor_key: rand::random(),
            subscriptions: std::sync::Mutex::new(BTreeMap::new()),
            next: AtomicU64::new(1),
            closing: watch::channel(false).0,
            subscriptions_changed: watch::channel(()).0,
        });
        clients.insert(id, client.clone());
        Ok(client)
    }
    /// Ends session `id`, or every session: pending waits stop, admitted
    /// calls finish. Other sessions and the database stay open.
    pub fn end_sessions(&self, id: Option<u64>) {
        let mut clients = self.clients.lock().unwrap_or_else(PoisonError::into_inner);
        let ended: Vec<_> = match id {
            Some(id) => clients.remove(&id).into_iter().collect(),
            None => std::mem::take(&mut *clients).into_values().collect(),
        };
        for client in ended {
            client.closing.send_replace(true);
        }
    }
    /// A session over every collection, opened again after an authority
    /// change ended the previous one.
    async fn reader(&self, client: &Client) -> Result<Reader, Failure> {
        let mut cached = client.reader.lock().await;
        if let Some(reader) = &*cached
            && reader.session.status().await.is_ok()
        {
            return Ok(reader.clone());
        }
        *cached = None;
        let session = self
            .replica
            .session(self.app_scopes().into_iter().collect())
            .await?;
        let sql = Arc::new(session.sql(SqlOptions::default()).await?);
        let reader = Reader { session, sql };
        *cached = Some(reader.clone());
        Ok(reader)
    }
    /// A SQL session over every granted table, for a driver connection.
    pub(crate) async fn sql_session(
        &self,
        options: SqlOptions,
    ) -> Result<SecureSql<TypedRows>, Failure> {
        if self.ended.lock().await.is_some() {
            return Err(refused("this device logged out of the domain"));
        }
        let session = self
            .replica
            .session(self.app_scopes().into_iter().collect())
            .await?;
        Ok(session.sql(options).await?)
    }
    async fn forget_readers(&self) {
        for client in self.clients() {
            *client.reader.lock().await = None;
        }
    }

    /// Serves `transport` as the network service in the empty `slot`.
    fn install(
        self: &Arc<Self>,
        slot: &mut Option<Arc<Link>>,
        transport: Arc<dyn Transport>,
        owned: bool,
    ) -> u64 {
        let _ = self.owner.set(Arc::downgrade(self));
        let link = Arc::new(Link {
            id: self.links.fetch_add(1, Ordering::Relaxed),
            owned,
            stage: watch::channel(Stage::Open).0,
            server: std::sync::Mutex::new(None),
            synchronizer: std::sync::Mutex::new(None),
            publisher: std::sync::Mutex::new(None),
            discovery: transport.discovery(),
            transport,
            discoverer: std::sync::Mutex::new(None),
            active: Arc::new(Semaphore::new(INBOUND)),
            live_budget: Arc::new(Semaphore::new(live_links::BUDGET)),
            live_handshakes: Arc::new(Semaphore::new(live_links::BUDGET)),
            live: live_links::Registry::default(),
            served: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        });
        link.transport.listen(true);
        let publisher =
            crate::reactor::spawn_local("publish_links", self.clone().publish_links(link.clone()));
        *link
            .publisher
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(publisher);
        let synchronizer =
            crate::reactor::spawn_local("synchronize", self.clone().synchronize(link.clone()));
        *link
            .synchronizer
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(synchronizer);
        let server = crate::reactor::spawn_local("accept", self.clone().accept(link.clone()));
        *link.server.lock().unwrap_or_else(PoisonError::into_inner) = Some(server);
        if let Some(discovery) = link.discovery.clone() {
            let discoverer = crate::reactor::spawn_local(
                "discover",
                self.clone().discover(link.clone(), discovery),
            );
            *link
                .discoverer
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(discoverer);
        }
        let id = link.id;
        *self.current.lock().unwrap_or_else(PoisonError::into_inner) = Some(link.clone());
        *slot = Some(link);
        self.wake_sync();
        id
    }
    /// Installs the transport the database opened with.
    pub async fn link(self: &Arc<Self>, transport: Arc<dyn Transport>, owned: bool) -> u64 {
        self.install(&mut *self.network.write().await, transport, owned)
    }
    /// Attaches a network service of any transport kind: routes of that
    /// kind are dialed, and the domain's identity does not depend on it.
    pub async fn attach(self: &Arc<Self>, network: Network) -> Result<u64, Failure> {
        let mut slot = self.network.write().await;
        if slot.is_some() {
            return Err(ServiceError::NetworkAttached.into());
        }
        if self.ended.lock().await.is_some() {
            return Err(refused("this device logged out of the domain"));
        }
        let issuer = self.settings.lock().await.issuer();
        let key = Settings::transport_key(&self.vault)?;
        let (transport, owned) = network.start(issuer, key).await?;
        Ok(self.install(&mut slot, transport, owned))
    }
    /// Detaches network service `id`, or whichever is attached. Admitted
    /// work has `DRAIN` to finish; an owned transport is then closed, a
    /// borrowed one is left as it was. Does nothing once detached.
    pub async fn detach(&self, id: Option<u64>) {
        let _detaching = self.detaching.lock().await;
        let attached = self.network.read().await.clone();
        let Some(link) = attached.filter(|link| id.is_none_or(|id| link.id == id)) else {
            return;
        };
        link.stage.send_replace(Stage::Draining);
        link.transport.listen(false);
        let mut slot = match tokio::time::timeout(DRAIN, self.network.write()).await {
            Ok(slot) => slot,
            Err(_) => {
                link.stage.send_replace(Stage::Cancelled);
                self.network.write().await
            }
        };
        *slot = None;
        self.synced(json!({"state": "idle", "retry": false}));
        *self.current.lock().unwrap_or_else(PoisonError::into_inner) = None;
        drop(slot);
        // The accept loop holds the transport's inbound queue until it ends.
        let server = link
            .server
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(server) = server {
            let _ = server.await;
        }
        let synchronizer = link
            .synchronizer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(synchronizer) = synchronizer {
            let _ = synchronizer.await;
        }
        let publisher = link
            .publisher
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(publisher) = publisher {
            let _ = publisher.await;
        }
        let discoverer = link
            .discoverer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(discoverer) = discoverer {
            let _ = discoverer.await;
        }
        link.live.wait_empty().await;
        if link.owned {
            link.transport.close().await;
        }
    }
    /// Serves inbound streams until the service drains or the transport ends.
    async fn accept(self: Arc<Self>, link: Arc<Link>) {
        let mut tasks = tokio::task::JoinSet::new();
        let mut stage = link.stage.subscribe();
        loop {
            let inbound = tokio::select! {
                inbound = link.transport.accept() => inbound,
                _ = stage.wait_for(|stage| *stage != Stage::Open) => None,
            };
            let Some((protocol, stream)) = inbound else {
                break;
            };
            let budget = if protocol == Protocol::Link {
                &link.live_handshakes
            } else {
                &link.active
            };
            let Ok(permit) = budget.clone().try_acquire_owned() else {
                link.refused.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            link.served.fetch_add(1, Ordering::Relaxed);
            let node = self.clone();
            let service = link.clone();
            crate::reactor::spawn_in(&mut tasks, "inbound", async move {
                if protocol == Protocol::Link {
                    let settings = node.settings.lock().await.clone();
                    if let Err(error) = node
                        .admit_link(service, stream, None, settings, Some(permit))
                        .await
                    {
                        let _ = node.absorb_revocations(Some(&error)).await;
                        node.activity.record_changed(
                            "link_admission_failed",
                            json!({"error": error.to_string()}),
                        );
                    }
                } else {
                    let _permit = permit;
                    let _ = node.serve(protocol, stream).await;
                }
            });
            while tasks.try_join_next().is_some() {}
        }
        let _ =
            tokio::time::timeout(DRAIN, async { while tasks.join_next().await.is_some() {} }).await;
        tasks.shutdown().await;
    }
    /// Runs a call that uses the network. A closing service cancels it once
    /// its drain bound passes.
    async fn networked(
        &self,
        client: &Client,
        kind: &str,
        request: &Value,
    ) -> Result<Value, Failure> {
        let attached = self.network.read().await;
        let transport = attached.as_ref().map(|link| &*link.transport);
        let work = async {
            match kind {
                "pairing" => {
                    // There is no default grant: the issuer names a profile.
                    let profile: Profile = serde_json::from_value(request["profile"].clone())
                        .map_err(|_| {
                            refused("pairing needs a grant profile: reader, writer or issuer")
                        })?;
                    let label: Option<Vec<u8>> = request
                        .get("label")
                        .map(|label| serde_json::from_value(label.clone()))
                        .transpose()?;
                    if label
                        .as_ref()
                        .is_some_and(|label| label.len() > crate::registry::MAX_LABEL)
                    {
                        return Err(refused("invitation label exceeds 256 bytes"));
                    }
                    let transport = transport.ok_or(ServiceError::NetworkRequired("pairing"))?;
                    let registry = self.registry().await?;
                    let mut settings = self.settings.lock().await;
                    let (uri, expires) = settings
                        .invite(
                            &self.path,
                            &self.vault,
                            transport,
                            (profile.clone(), label),
                            &registry,
                        )
                        .await
                        .map_err(named)?;
                    let sequence = self.activity.record(
                        "invitation_created",
                        json!({"profile": profile, "expires": expires.to_string()}),
                    );
                    Ok(
                        json!({"uri": uri, "expires": expires.to_string(), "profile": profile, "sequence": sequence.to_string(),
                            "id": HEXLOWER.encode(&rocky_core::commitment("rocky.sdk.invitation.v1", &self.vault.get("invitation")?))}),
                    )
                }
                "renew" => {
                    self.renew(transport, true, None, false).await?;
                    self.status(client).await
                }
                "contact" => {
                    let transport = transport.ok_or(ServiceError::NetworkRequired("contact"))?;
                    let settings = self.settings.lock().await.clone();
                    let (uri, node, routes) = settings.contact(&self.vault, transport).await?;
                    Ok(json!({"uri": uri, "node": node.to_hex(), "routes": routes}))
                }
                _ => self
                    .sync_optional(transport)
                    .await
                    .map(|(report, _)| report),
            }
        };
        let Some(link) = attached.as_ref() else {
            return work.await;
        };
        let mut stage = link.stage.subscribe();
        tokio::select! {
            result = work => result,
            _ = stage.wait_for(|stage| *stage == Stage::Cancelled) => {
                Err(ServiceError::Closed("network service").into())
            }
        }
    }

    /// Handles one call of the native ABI for a session.
    pub async fn dispatch(&self, client: &Client, request: &Value) -> Result<Value, Failure> {
        let kind = request["type"].as_str().unwrap_or_default();
        if self.ended.lock().await.is_some()
            && !matches!(
                kind,
                "domain"
                    | "network"
                    | "peers"
                    | "status"
                    | "status_next"
                    | "activity"
                    | "activity_next"
            )
        {
            return Err(refused("this device logged out of the domain"));
        }
        match kind {
            "domain" => {
                let settings = self.settings.lock().await;
                Ok(json!({
                    "scope": self.domain().scope,
                    "issuer": settings.issuer(),
                    "profile": settings.profile,
                    "collections": settings.schema.names(),
                    "durable_mutations": true,
                    "transport": self.kind(),
                }))
            }
            "session" => self.status(client).await,
            "invitation_state" => {
                let uri = request["uri"]
                    .as_str()
                    .ok_or_else(|| refused("uri must be an invitation"))?;
                let (id, expires) = Settings::invitation_identity(uri)?;
                let open = self.settings.lock().await.invitation_open(uri)?;
                let registry = self.registry().await?;
                let enrolled = registry
                    .records
                    .iter()
                    .find(|(_, record)| {
                        record
                            .device
                            .as_ref()
                            .is_some_and(|device| device.invitation.as_deref() == Some(&id))
                    })
                    .map(|(node, _)| node.to_hex());
                Ok(
                    json!({"id": id, "expires": expires.to_string(), "open": open, "enrolled": enrolled}),
                )
            }
            "invitation_open" => {
                let uri = request["uri"]
                    .as_str()
                    .ok_or_else(|| refused("uri must be an invitation"))?;
                Ok(json!({"open": self.settings.lock().await.invitation_open(uri)?}))
            }
            "generation" => self.generation().await,
            "tips" => self.tips(request).await,
            "held_changes" => self.held_changes().await,
            "coordinated" => self.coordinated_status().await,
            "drop_held" => self.drop_held(request).await,
            "retention" => self.retention(request).await,
            "retention_limits" => {
                if let Some(limits) = request.get("limits") {
                    self.replica
                        .set_retention_limits(serde_json::from_value(limits.clone())?)
                        .await?;
                }
                Ok(serde_json::to_value(self.replica.retention_limits().await)?)
            }
            "status" => self.readiness().await,
            "activity" => Ok(self.activity.after(token(request)?)),
            "activity_next" => {
                let mut closing = client.closing.subscribe();
                self.activity
                    .next(token(request)?, &mut closing)
                    .await
                    .ok_or_else(|| ServiceError::Closed("session").into())
            }
            "status_next" => {
                let after = request["after"]
                    .as_str()
                    .ok_or_else(|| refused("after must be a status token"))?;
                self.readiness_after(client, after).await
            }
            "backup" => {
                let target = request["path"]
                    .as_str()
                    .ok_or_else(|| refused("path must be a string"))?;
                self.backup(std::path::Path::new(target)).await
            }
            "sync_start" => {
                let enabled = request
                    .get("enabled")
                    .map(|enabled| {
                        enabled
                            .as_bool()
                            .ok_or_else(|| refused("enabled must be boolean"))
                    })
                    .transpose()?
                    .unwrap_or(true);
                self.automatic.store(enabled, Ordering::SeqCst);
                if enabled {
                    self.reset_retry(None);
                }
                self.control_sync();
                if !enabled {
                    if let Some(service) = self.current() {
                        service
                            .live
                            .close(rocky_secure::network::link::CloseReason::WorkerDisabled);
                    }
                    // Acknowledge only after the worker has dropped its pass.
                    let mut running = self.worker_running.subscribe();
                    running.wait_for(|running| !running).await?;
                    if let Some(service) = self.current() {
                        service.live.wait_empty().await;
                    }
                    self.synced(json!({"state": "idle", "retry": false}));
                }
                Ok(json!({"enabled": enabled}))
            }
            #[cfg(feature = "qualification")]
            "network_fault_close" => {
                let attached = self.network.read().await;
                let link = attached
                    .as_ref()
                    .ok_or(ServiceError::NetworkRequired("fault injection"))?;
                link.transport.fault_close_sockets().await?;
                Ok(json!({}))
            }
            "network_foreground" => {
                if let Some(link) = self.network.read().await.as_ref() {
                    link.transport
                        .foreground()
                        .await
                        .map_err(|error| ServiceError::Unreachable(error.to_string()))?;
                }
                self.foreground.store(true, Ordering::SeqCst);
                self.discovery_foreground(true).await;
                self.reset_retry(None);
                self.wake_sync();
                Ok(json!({}))
            }
            "network_background" => {
                self.foreground.store(false, Ordering::SeqCst);
                self.control_sync();
                let mut running = self.worker_running.subscribe();
                running.wait_for(|running| !running).await?;
                if let Some(service) = self.current() {
                    service
                        .live
                        .close(rocky_secure::network::link::CloseReason::Suspended);
                    service.live.wait_empty().await;
                }
                self.discovery_foreground(false).await;
                Ok(json!({}))
            }
            "network" => Ok(serde_json::to_value(self.observed_network().await?)?),
            "pairing" | "renew" | "sync" | "contact" => self.networked(client, kind, request).await,
            "sql" | "next_id" => {
                let begins = kind == "sql"
                    && request["sql"]
                        .as_str()
                        .is_some_and(|sql| sql.trim().to_ascii_uppercase().starts_with("BEGIN"));
                match self.sql_call(client, kind, request).await {
                    // An authority change ends the cached session; nothing
                    // is open before a transaction begins, so begin again.
                    Err(error) if begins && is_authority(&error) => {
                        *client.reader.lock().await = None;
                        self.sql_call(client, kind, request).await
                    }
                    other => other,
                }
            }
            kind if kind.starts_with("partition_") => self.partition_call(kind, request).await,
            "devices" => self.devices().await,
            "device_label" => self.label(request).await,
            "grant" | "delegate" => self.grant(request).await,

            "install" => self.install_supplied(client, request).await,
            "contact_request" => {
                let encoded = request["id"]
                    .as_str()
                    .ok_or_else(|| refused("id must be a 16-byte node ID"))?;
                let id: [u8; 16] = HEXLOWER
                    .decode(encoded.as_bytes())?
                    .try_into()
                    .map_err(|_| refused("id must be a 16-byte node ID"))?;
                let network = self.network.read().await;
                self.request_contact(
                    &*network
                        .as_ref()
                        .ok_or_else(|| refused("no network attached"))?
                        .transport,
                    rocky_core::NodeId(id),
                )
                .await
            }
            "discovery_topics" => {
                let settings = self.settings.lock().await;
                let (current, previous) = settings.discovery_topics(&self.vault, now()?)?;
                Ok(
                    json!({"current": HEXLOWER.encode(&current), "previous": previous.map(|topic| HEXLOWER.encode(&topic))}),
                )
            }
            "peers" => {
                let network = self.observed_network().await?;
                Ok(json!({
                    "peers": network.peers,
                    "discovery": network.discovery,
                    "renewal_routes": self.settings.lock().await.renewal_routes(),
                }))
            }
            "enrollment_route" => Ok(json!({"uri": crate::route_enrollment(
                request["uri"].as_str().ok_or_else(|| refused("uri must be an invitation or issuer contact"))?,
                request["contact"].as_str().ok_or_else(|| refused("contact must name the custody peer"))?,
            )?})),
            "enrollment_upstream" => {
                let contact = request["contact"].as_str();
                if !request["contact"].is_null() && contact.is_none() {
                    return Err(refused("contact must be an issuer contact or null"));
                }
                self.configure(|settings| {
                    if !matches!(settings.profile, Profile::Custody { .. }) || settings.issuer() {
                        return Err("enrollment forwarding requires a custody-only node".into());
                    }
                    settings.enrollment_upstream = match contact {
                        Some(contact) => {
                            let node = settings.add_peer(&self.vault, contact)?;
                            if !settings.issuers.contains(&node) {
                                return Err("upstream must name an issuer".into());
                            }
                            Some(node)
                        }
                        None => None,
                    };
                    Ok(())
                })
                .await?;
                self.wake_sync();
                Ok(json!({}))
            }
            "peer_add" => {
                let contact = request["contact"]
                    .as_str()
                    .ok_or("contact must be a contact URI")?;
                let registry = self.registry().await?;
                let node = self
                    .configure(|settings| {
                        let node = settings.add_peer(&self.vault, contact)?;
                        if registry.revoked(&node) {
                            return Err("the contact names a revoked device".into());
                        }
                        Ok(node)
                    })
                    .await?;
                self.reset_retry(Some(node));
                self.activity
                    .record("peer_added", json!({"peer": node.to_hex()}));
                self.wake_sync();
                Ok(json!({"node": node.to_hex()}))
            }
            "peer_remove" => {
                let node: PublicKey = request["node"]
                    .as_str()
                    .ok_or("node must be a public key")?
                    .parse()?;
                self.configure(|settings| {
                    if settings.enrollment_upstream == Some(node) {
                        return Err("clear enrollment forwarding before removing its issuer".into());
                    }
                    settings.remove_peer(node)
                })
                .await?;
                self.reached()?.remove(&node);
                self.met
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&node);
                if let Some(service) = self.current() {
                    service.live.close_peer(node);
                }
                self.retries
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&node);
                self.activity
                    .record("peer_removed", json!({"peer": node.to_hex()}));
                self.wake_sync();
                Ok(json!({}))
            }
            "revoke" => {
                // One node's certificate, or an identity and all its nodes.
                let key = |name: &str| -> Result<Option<PublicKey>, Failure> {
                    match request[name].as_str() {
                        Some(key) => Ok(Some(key.parse()?)),
                        None => Ok(None),
                    }
                };
                let trust = match request["trust"].as_str() {
                    Some(id) => Some(
                        HEXLOWER
                            .decode(id.as_bytes())
                            .ok()
                            .and_then(|bytes| bytes.try_into().ok())
                            .ok_or_else(|| refused("trust must be a hex capability id"))?,
                    ),
                    None => None,
                };
                let target = match (key("node")?, key("identity")?, trust) {
                    (Some(node), None, None) => crate::enrollment::Revoke::Node(node),
                    (None, Some(identity), None) => crate::enrollment::Revoke::Identity(identity),
                    (None, None, Some(trust)) => crate::enrollment::Revoke::Trust(trust),
                    _ => {
                        return Err(refused(
                            "revoke names one node, one identity or one trusted grant",
                        ));
                    }
                };
                let revoked = self.revoke(target).await?;
                self.activity.record(
                    "device_revoked",
                    match target {
                        crate::enrollment::Revoke::Node(node) => json!({"node": node.to_hex()}),
                        crate::enrollment::Revoke::Identity(identity) => {
                            json!({"identity": identity.to_hex()})
                        }
                        crate::enrollment::Revoke::Trust(trust) => {
                            json!({"trust": HEXLOWER.encode(&trust)})
                        }
                    },
                );
                Ok(revoked)
            }
            "logout" => {
                self.logout(request["purge"].as_bool().unwrap_or(false))
                    .await
            }
            "networking_control" => {
                let enabled = request["enabled"]
                    .as_bool()
                    .ok_or("enabled must be boolean")?;
                if self.online.swap(enabled, Ordering::SeqCst) != enabled {
                    self.activity.record(
                        if enabled {
                            "networking_enabled"
                        } else {
                            "networking_disabled"
                        },
                        json!({}),
                    );
                }
                if enabled {
                    self.reset_retry(None);
                    // A pass with nothing to dial republishes the current status.
                    if self.sync_status.borrow()["state"] == "networking_disabled" {
                        self.synced(json!({"state": "idle", "retry": false}));
                    }
                }
                if !enabled && let Some(service) = self.current() {
                    service
                        .live
                        .close(rocky_secure::network::link::CloseReason::NetworkingDisabled);
                }
                self.control_sync();
                if !enabled && let Some(service) = self.current() {
                    service.live.wait_empty().await;
                }
                Ok(json!({"enabled": enabled}))
            }

            "mutation_progress" => {
                let handle: Vec<u8> = serde_json::from_value(request["handle"].clone())?;
                let handle: [u8; 32] = handle.try_into().map_err(|_| refused("handle"))?;
                Ok(
                    json!({"committed": self.replica.handle_committed(secure_handle(&handle)).await?}),
                )
            }
            "read" => {
                self.read(client, serde_json::from_value(request["query"].clone())?)
                    .await
            }
            "subscribe" => {
                let query: Query = serde_json::from_value(request["query"].clone())?;
                let mut subscriptions = client.subscriptions()?;
                if subscriptions.len() >= MAX_SUBSCRIPTIONS {
                    return Err("subscription quota".into());
                }
                let id = client.next.fetch_add(1, Ordering::Relaxed);
                subscriptions.insert(
                    id,
                    Subscription {
                        query,
                        delivered: None,
                    },
                );
                Ok(json!({"subscription": id.to_string()}))
            }
            kind if kind.starts_with("coordination_") => self.coordination(kind, request).await,
            "next" => self.next(client, subscription(request)?).await,
            "unsubscribe" => {
                client.subscriptions()?.remove(&subscription(request)?);
                client.subscriptions_changed.send_replace(());
                Ok(json!({}))
            }
            other => Err(refused(format!("unsupported request {other}"))),
        }
    }

    fn reached(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<PublicKey, Reached>>, Failure> {
        self.reached
            .lock()
            .map_err(|_| "peer status poisoned".into())
    }
    /// Applies a change of the configured peers, saving it when what is
    /// persisted changed.
    async fn configure<T>(
        &self,
        change: impl FnOnce(&mut Settings) -> Result<T, Failure>,
    ) -> Result<T, Failure> {
        let mut settings = self.settings.lock().await;
        let mut draft = settings.clone();
        let result = change(&mut draft).map_err(named)?;
        if !draft.persisted_eq(&settings) {
            draft.save(&self.path)?;
        }
        *self.granted.lock().map_err(|_| "scope catalog poisoned")? = draft.granted(&self.domain());
        *settings = draft;
        self.observations.touch();
        Ok(result)
    }
    /// Issues raw grants or a profile to a prepared device, as the
    /// credentials it installs: signed by the publisher on an issuer, or
    /// delegated from this device's own chain.
    async fn grant(&self, request: &Value) -> Result<Value, Failure> {
        let device: crate::DeviceKeys = serde_json::from_value(request["device"].clone())
            .map_err(|_| refused("device must be the keys a prepared device reports"))?;
        let profile = match (&request["grants"], &request["profile"]) {
            (Value::Null, profile) => serde_json::from_value(profile.clone()),
            (grants, Value::Null) => {
                serde_json::from_value(grants.clone()).map(|grants| Profile::Grants { grants })
            }
            _ => return Err(refused("name grants or a profile, not both")),
        }
        .map_err(|error| refused(format!("invalid grants: {error}")))?;
        let terms: Terms = serde_json::from_value(json!({
            "ttl": request["ttl"],
            "delegations": request["delegations"],
            "authors": request["authors"],
        }))
        .map_err(|_| refused("ttl must be seconds, delegations 1 to 7 and authors a count"))?;
        let delegate = request["type"] == "delegate";
        let contact = match self.current() {
            Some(link) if !delegate => {
                let settings = self.settings.lock().await.clone();
                Some(settings.contact(&self.vault, &*link.transport).await?.0)
            }
            _ => None,
        };
        let supplied =
            Box::pin(self.answer_grant(device, (profile, terms), delegate, contact)).await?;
        Ok(json!({"supplied": supplied}))
    }

    /// Replaces this device's credentials with supplied ones and teaches
    /// the replica, as a renewal does.
    async fn install_supplied(&self, client: &Client, request: &Value) -> Result<Value, Failure> {
        let supplied: crate::Supplied = serde_json::from_value(request["supplied"].clone())
            .map_err(|error| refused(format!("invalid supplied credentials: {error}")))?;
        let current = self.settings.lock().await.clone();
        let renewed = current
            .supplied_renewal(&self.vault, &supplied)
            .map_err(refused)?;
        let registry = self.registry().await?;
        let mut settings = self.settings.lock().await;
        let (mut keys, _) = settings.adopt(&self.path, &self.vault, &renewed)?;
        if settings.begin_exposure_rotation(&registry)? {
            settings.save(&self.path)?;
            keys.extend(
                settings
                    .rotate(&self.vault)?
                    .ok_or("exposure rotation intent disappeared")?,
            );
            settings.save(&self.path)?;
        }
        let fresh = keys.len();
        self.apply(&mut settings, keys).await?;
        self.activity.record(
            "renewed",
            json!({
                "revocations": settings.revocation_status()?,
                "expires": settings.expires().to_string(),
                "keys": fresh,
            }),
        );
        // New grants may make more members of a held group readable.
        for partition in settings.partitions(&self.domain())? {
            self.hold_keys(&settings, &partition).await?;
        }
        *self.granted.lock().map_err(|_| "scope catalog poisoned")? =
            settings.granted(&self.domain());
        drop(settings);
        self.forget_readers().await;
        self.status(client).await
    }
    /// Contacts, retained peer history and current link resources.
    /// Link resources remain visible after their history is evicted.
    async fn peers(&self) -> Vec<Value> {
        let settings = self.settings.lock().await;
        let reached = self.reached.lock().unwrap_or_else(PoisonError::into_inner);
        let met = self.met.lock().unwrap_or_else(PoisonError::into_inner);
        let live_nodes = self
            .current()
            .map(|service| service.live.nodes())
            .unwrap_or_default();
        let nodes: std::collections::BTreeSet<PublicKey> = settings
            .peers
            .keys()
            .chain(met.keys())
            .chain(live_nodes.iter())
            .filter(|node| live_nodes.contains(node) || !settings.revocations.revokes(node))
            .copied()
            .collect();
        nodes
            .into_iter()
            .map(|node| {
                let contact = settings.peers.get(&node);
                let last = reached.get(&node);
                let state = match (last, met.get(&node)) {
                    (Some(Reached { error: None, .. }), _) | (None, Some(_)) => "connected",
                    (Some(_), _) => "unreachable",
                    (None, None) => "unknown",
                };
                let checked = last.map(|last| last.at).or_else(|| met.get(&node).copied());
                json!({
                    "node": node.to_hex(),
                    "issuer": settings.issuers.contains(&node),
                    "configured": contact.is_some(),
                    "local": settings.contact_meta.get(&node).is_some_and(|meta| meta.local),
                    "source": settings.contact_meta.get(&node).map_or(if contact.is_some() { "enrollment" } else if met.contains_key(&node) { "session" } else { "link" }, |meta| meta.source.as_str()),
                    "choice": self.choices.lock().unwrap_or_else(PoisonError::into_inner).get(&node).copied().unwrap_or("not_considered"),
                    "routes": contact.map(|contact| contact.routes.clone()).unwrap_or_default(),
                    "link": self.current().map_or_else(|| json!({"state":"closed","opened":null,"round_trip_ms":null,"paths":[]}), |service| service.live.status(node)),
                    "state": state,
                    "checked": checked.map(|at| at.to_string()),
                    "error": last.and_then(|last| last.error.clone()),
                })
            })
            .collect()
    }
    fn current(&self) -> Option<Arc<Link>> {
        self.current
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
    /// The attached network's transport kind, empty without one.
    fn kind(&self) -> String {
        self.current()
            .map(|link| link.transport.kind().to_owned())
            .unwrap_or_default()
    }
    async fn retention(&self, request: &Value) -> Result<Value, Failure> {
        let collection = request["collection"]
            .as_str()
            .ok_or("collection must be a table name")?;
        let scope = self
            .domain()
            .scopes()
            .find(|(name, _)| *name == collection)
            .map(|(_, scope)| scope)
            .filter(|scope| self.scopes().contains(scope))
            .ok_or_else(|| refused("retention scope is not granted"))?;
        if let Some(policy) = request.get("policy") {
            self.replica
                .set_retention_policy(scope, serde_json::from_value(policy.clone())?)
                .await?;
        }
        // A base forms only at a seal, through `compact`; this prunes behind it.
        if request["maintain"] == true {
            self.replica.prune(scope).await?;
        }
        let status = self.replica.checkpoint_status(scope).await?;
        Ok(
            json!({"policy": self.replica.retention_policy(scope).await?,
            "covered": status.covered, "uncovered": status.uncovered,
            "pruned_prefix": status.pruned_prefix, "maintenance_error": status.maintenance_error}),
        )
    }
    async fn status(&self, client: &Client) -> Result<Value, Failure> {
        let reader = self.reader(client).await?;
        let status = reader.session.status().await?;
        let settings = self.settings.lock().await;
        Ok(json!({
            "principal": status.principal.to_hex(),
            "node": status.node.to_hex(),
            "revocations": {"digest": HEXLOWER.encode(&status.revocations), "statements": status.revoked},
            "expires": status.expires.to_string(),
            "issuer": settings.issuer(),
            "profile": settings.profile,
            "transport": self.kind(),
            "readable": status.readable.len(),
            "writable": status.writable.len(),
            "author": settings.credentials.author_number()?,
            "authors": settings.minting,
        }))
    }
    async fn readiness(&self) -> Result<Value, Failure> {
        Ok(serde_json::to_value(self.observed_status().await?)?)
    }
    /// How far the bootstrap intent has imported, in the stored rows of the
    /// checkpoints its peer offered; `null` until a peer offered one.
    async fn bootstrap_progress(&self) -> Result<Value, Failure> {
        let intent: Value = match std::fs::read(self.path.with_file_name("bootstrap.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Value::Null),
            Err(error) => return Err(error.into()),
        };
        let Some(totals) = intent.get("totals") else {
            return Ok(Value::Null);
        };
        let totals: Vec<sync::Planned> = serde_json::from_value(totals.clone())?;
        if totals.is_empty() {
            return Ok(Value::Null);
        }
        let pending: Vec<ResourceScope> = serde_json::from_value(intent["pending"].clone())?;
        let (mut rows_done, mut scopes_done) = (0, 0);
        for planned in &totals {
            if pending.contains(&planned.scope) {
                rows_done += self
                    .replica
                    .imported_rows(planned.scope, planned.checkpoint)
                    .await?
                    .min(planned.rows);
            } else {
                rows_done += planned.rows;
                scopes_done += 1;
            }
        }
        Ok(json!({
            "rows_done": rows_done,
            "rows_total": totals.iter().map(|planned| planned.rows).sum::<u64>(),
            "scopes_done": scopes_done,
            "scopes_total": totals.len(),
        }))
    }
    /// The status once it differs from the one `after` named.
    async fn readiness_after(&self, client: &Client, after: &str) -> Result<Value, Failure> {
        let mut revisions = self.replica.observe_revision();
        let mut imports = self.replica.observe_imports().await;
        let mut authority = self.replica.observe_authority().await;
        let mut sync_state = self.sync_state.subscribe();
        let mut closing = client.closing.subscribe();
        let mut events = self.sync_events.subscribe();
        let mut network = self.sync_status.subscribe();
        let mut observations = self.observations.subscribe();
        let mut worker = self.worker_running.subscribe();
        let mut control = self.sync_control.subscribe();
        loop {
            let mut transport = self
                .current()
                .and_then(|service| service.transport.connectivity());
            // Read before the status and anchored to that instant: an expiry
            // while the status is computed must still wake this wait.
            let (time, read) = (self.status_time()?, tokio::time::Instant::now());
            let status = self.readiness().await?;
            if status["token"] != after {
                return Ok(status);
            }
            tokio::select! {
                changed = revisions.changed() => {
                    changed.map_err(|_| ServiceError::Closed("database"))?
                }
                _ = closing.wait_for(|closing| *closing) => {
                    return Err(ServiceError::Closed("session").into());
                }
                changed = sync_state.changed() => {
                    changed.map_err(|_| ServiceError::Closed("database"))?
                }
                _ = events.changed() => {},
                _ = network.changed() => {},
                _ = observations.changed() => {},
                _ = worker.changed() => {},
                _ = authority.changed() => {},
                _ = control.changed() => {},
                _ = async { match transport.as_mut() { Some(events) => { let _ = events.changed().await; }, None => std::future::pending().await } } => {},
                changed = imports.changed() => {
                    changed.map_err(|_| ServiceError::Closed("database"))?
                }
                _ = async {
                    let settings = self.settings.lock().await;
                    let expires = std::iter::once(settings.expires()).chain(settings.revocations.statements().map(|notice| notice.statement.expiry_day().saturating_mul(rocky_credentials::DAY))).filter(|expires| *expires > time).min();
                    drop(settings);
                    if let Some(expires) = expires {
                        tokio::time::sleep_until(read + Duration::from_secs(expires - time)).await;
                    } else {
                        std::future::pending().await
                    }
                    Ok::<_, Failure>(())
                } => {},
            }
        }
    }
    /// Writes a signed backup archive to `target`: a coherent copy of the
    /// file and the identity, which holds no
    /// key. See `docs/runtime/backup-and-restore.md`.
    async fn backup(&self, target: &std::path::Path) -> Result<Value, Failure> {
        let _backup = self.backups.lock().await;
        if target.exists() {
            return Err(refused("the backup target exists"));
        }
        let directory = self
            .path
            .parent()
            .ok_or("the identity has no data directory")?
            .to_path_buf();
        let staging = directory.join(format!(
            "backup-{}",
            HEXLOWER.encode(
                &commitment(
                    "rocky.sdk.backup-staging.v1",
                    target.as_os_str().as_encoded_bytes()
                )[..8]
            )
        ));
        let _ = std::fs::remove_dir_all(&staging);
        std::fs::create_dir_all(&staging)?;
        let result = async {
            let settings = self.settings.lock().await;
            let database = staging.join("rocky.sqlite");
            let revision = self.replica.backup_into(&database).await?;
            let snapshot = settings.clone();
            drop(settings);
            let settings = snapshot;
            let identity = staging.join("identity.json");
            std::fs::write(&identity, serde_json::to_vec(&*settings)?)?;
            let staged = vec![("identity.json", identity), ("rocky.sqlite", database)];
            let node = PrivateKey::from_bytes(&self.vault.get("node")?);
            let scope = serde_json::to_value(self.domain().scope)?;
            let target = target.to_path_buf();
            let inventory = tokio::task::spawn_blocking(move || {
                crate::backup::write(&target, &staged, &settings, scope, revision, &node, now()?)
            })
            .await??;
            Ok::<_, Failure>(serde_json::to_value(inventory)?)
        }
        .await;
        let _ = std::fs::remove_dir_all(&staging);
        result
    }
    /// The definition generation, the earlier ones still admitted and a
    /// table rebuild under way.
    async fn generation(&self) -> Result<Value, Failure> {
        let settings = self.settings.lock().await;
        let application = self.application(&settings).await?;
        let migration = self.migration(&settings).await?;
        let followed = self.replica.followed_bookmark().await.is_some();
        let waiting_for_issuer =
            followed && !settings.issuer() && application == crate::DeclaredSchema::Ahead;
        drop(settings);
        let status = self.replica.generations().await?;
        let generation = |generation: rocky_core::Generation| json!({"schema": generation.schema});
        Ok(json!({
            "manifest": HEXLOWER.encode(&status.manifest),
            "current": generation(status.current),
            "pending": self.replica.pending_schema().await?.map(|pending| json!({"tip": HEXLOWER.encode(&pending.tip.0), "manifest": HEXLOWER.encode(&pending.manifest)})),
            "reason": (!followed).then_some("follow_required"),
            "rebuilding": status.plan.map(|plan| json!({"tables": plan.tables})),
            "application": application,
            "waiting_for_issuer": waiting_for_issuer,
            "held": self.replica.held_changes().await?.len(),
            "migration": migration,
        }))
    }
    /// Revokes a node, or an identity with every node of it, and rotates
    /// the keys they could read. The intent, the new keys and the identity
    /// are saved before the replica learns them, so an interruption
    /// completes at the next open.
    async fn revoke(&self, target: crate::enrollment::Revoke) -> Result<Value, Failure> {
        let registry = self.registry().await?;
        let mut settings = self.settings.lock().await;
        let mut draft = settings.clone();
        draft
            .begin_revocation(target, &registry)
            .map_err(|error| -> Failure {
                if error.is::<crate::enrollment::RevocationSetFull>() {
                    error
                } else {
                    refused(error)
                }
            })?;
        draft.save(&self.path)?;
        *settings = draft.clone();
        let rotation = draft
            .authority
            .as_ref()
            .and_then(|authority| authority.rotation.clone())
            .ok_or("the revocation was not begun")?;
        let keys = draft.rotate(&self.vault)?.unwrap_or_default();
        draft.drop_revoked_deliveries();
        draft.save(&self.path)?;
        *settings = draft;
        self.apply(&mut settings, keys).await?;
        for partition in settings.partitions(&self.domain())? {
            let address = crate::groups::record_key(&partition.record.address);
            if rotation.groups.contains_key(&address) {
                self.hold_keys(&settings, &partition).await?;
            }
        }
        let status = settings.revocation_status()?;
        drop(settings);
        self.forget_readers().await;
        // Rotated first: the statement refuses the device even if this fails.
        Box::pin(self.complete_revocation()).await?;
        // Members no longer accept the revoked author's frames, nor open
        // the earlier epoch's; a checkpoint at a seal after them carries
        // those rows instead.
        if !matches!(target, crate::enrollment::Revoke::Trust(_))
            && let Err(error) = self.seal_for_members().await
        {
            self.activity.record(
                "revocation_seal_failed",
                json!({"error": error.to_string()}),
            );
        }
        Ok(json!({
            "statement": HEXLOWER.encode(&rotation.statement.id()?),
            "revocations": status,
        }))
    }
    /// Teaches the replica what the identity already records: the
    /// revocations, this device's chain and new key epochs, earlier ones
    /// first.
    async fn apply(
        &self,
        settings: &mut Shared<Settings>,
        mut keys: Vec<(String, rocky_core::KeyEpoch, [u8; 32])>,
    ) -> Result<(), Failure> {
        let chain = settings.credentials.clone();
        self.replica
            .learn_revocations(&settings.revocations)
            .await?;
        self.replica.renew_credentials(chain.clone()).await?;
        if let Some(service) = &self.service {
            service.certify(&chain);
        }
        // A line node is certified again from the renewed identity links,
        // under the settings the caller holds.
        if let Err(error) = self.refresh_line_node(settings).await {
            self.activity
                .record_changed("line_node_failed", json!({"error": error.to_string()}));
        }
        keys.sort_by_key(|(_, epoch, _)| *epoch);
        for (name, generation, key) in keys {
            let scope = self
                .domain()
                .scopes()
                .find(|(collection, _)| *collection == name)
                .map(|(_, scope)| scope)
                .ok_or("unknown collection")?;
            self.replica
                .install_key_epoch(KeyMaterial::at(scope, generation, key))
                .await?;
        }
        Ok(())
    }
    /// Renews this device's credentials: from its issuers on a member,
    /// self-signed on an issuer, which asks the other issuers first when
    /// `learn` is set. New reader keys arrive with the renewal. Returns
    /// whether anything changed.
    async fn renew(
        &self,
        transport: Option<&dyn Transport>,
        learn: bool,
        first: Option<PublicKey>,
        epochs_only: bool,
    ) -> Result<bool, Failure> {
        let attached = self.current();
        let transport = transport.or_else(|| attached.as_ref().map(|link| &*link.transport));
        if let Some(transport) = transport {
            Box::pin(self.resolve_saved_contacts(transport)).await;
        }
        let current = self.settings.lock().await.clone();
        let request = async {
            if epochs_only {
                current
                    .request_epochs(
                        &self.vault,
                        transport.ok_or(ServiceError::NetworkRequired("epoch delivery"))?,
                        first,
                    )
                    .await
            } else {
                current
                    .request_renewal(&self.vault, transport, learn, first)
                    .await
            }
        };
        let mut renewed = match request.await {
            Ok(renewed) => renewed,
            Err(error) => {
                if let Some(revoked) = error.downcast_ref::<crate::enrollment::Revoked>() {
                    current.record_revocation(&self.path, revoked.0.clone())?;
                    let node = current
                        .credentials
                        .0
                        .last()
                        .ok_or("missing device credential")?
                        .capability
                        .subject;
                    self.activity
                        .record("device_revoked", json!({"node": node.to_hex()}));
                    self.wake_sync();
                }
                return Err(error);
            }
        };
        if let Some(peer) = renewed.contacted {
            self.inbound_sync(peer);
        }
        self.learned.store(false, Ordering::SeqCst);
        let mut settings = self.settings.lock().await;
        // A member restores newly revoked authors by checkpoint, however it
        // learned of them.
        if (!epochs_only || !settings.issuer()) && settings.lacks(&renewed.revocations)? {
            rocky_credentials::write_private(&self.path.with_file_name("bootstrap.json"), b"true")?;
        }
        if epochs_only {
            renewed.chain = settings.credentials.clone();
        }
        let (keys, adopted) = settings.adopt(&self.path, &self.vault, &renewed)?;
        let mut changed = !epochs_only || adopted;
        if changed {
            let readable = self
                .granted
                .lock()
                .map_err(|_| "scope catalog poisoned")?
                .len();
            self.apply(&mut settings, keys).await?;
            for partition in settings.partitions(&self.domain())? {
                self.hold_keys(&settings, &partition).await?;
            }
            // A table granted like a held one is projected, and held where
            // its group partitions are, once granted.
            if settings.granted(&self.domain()).len() > readable {
                let domain = self.domain();
                let mut widened = (**settings).clone();
                crate::database::attach(
                    &self.replica,
                    &mut widened,
                    &self.vault,
                    &domain,
                    &self.path,
                )
                .await?;
                *settings = Shared::new(widened);
            }
        }
        if settings.issuer() {
            drop(settings);
            let registry = self.registry().await?;
            settings = self.settings.lock().await;
            if settings.begin_exposure_rotation(&registry)? {
                changed = true;
                settings.save(&self.path)?;
                let keys = settings
                    .rotate(&self.vault)?
                    .ok_or("exposure rotation intent disappeared")?;
                settings.save(&self.path)?;
                self.apply(&mut settings, keys).await?;
                for partition in settings.partitions(&self.domain())? {
                    self.hold_keys(&settings, &partition).await?;
                }
            }
        }
        if !changed {
            return Ok(false);
        }
        *self.granted.lock().map_err(|_| "scope catalog poisoned")? =
            settings.granted(&self.domain());
        drop(settings);
        self.refresh_importing().await?;
        self.forget_readers().await;
        if self.settings.lock().await.issuer() {
            Box::pin(self.complete_revocation()).await?;
        }
        // An issuer's own record names its current capability.
        if !epochs_only && let Err(error) = Box::pin(self.record_self()).await {
            self.activity
                .record("registry_failed", json!({"error": error.to_string()}));
        }
        self.wake_sync();
        Ok(true)
    }
    async fn logout(&self, purge: bool) -> Result<Value, Failure> {
        let registry = self.registry().await?;
        let own = PrivateKey::from_bytes(&self.vault.get("node")?).public_key();
        let mut settings = self.settings.lock().await;
        if settings.issuer() && !settings.another_issuer(&registry, own) {
            return Err(refused(
                "this device holds the only known copy of the domain's publisher key and cannot log out",
            ));
        }
        self.replica.logout().await;
        settings.logged_out = true;
        settings.save(&self.path)?;
        *self.ended.lock().await = Some(purge);
        self.forget_readers().await;
        for client in self.clients() {
            client.subscriptions()?.clear();
            client.subscriptions_changed.send_replace(());
        }
        self.automatic.store(false, Ordering::SeqCst);
        self.wake_sync();
        self.vault.forget(settings.roles())?;
        Ok(json!({"logged_out": true, "purge": purge}))
    }

    pub(crate) async fn initial_sync(&self) -> Result<(), Failure> {
        let network = self.network.read().await;
        let link = network
            .as_ref()
            .ok_or(ServiceError::NetworkRequired("bootstrap"))?;
        let mut stage = link.stage.subscribe();
        tokio::select! {
            result = self.sync_optional(Some(&*link.transport)) => result.map(|_| ()),
            _ = stage.wait_for(|stage| *stage == Stage::Cancelled) => Err(ServiceError::Closed("network service").into()),
        }
    }

    /// Records a peer's reachability when it changed and what a sync moved.
    fn record_reach(
        &self,
        peer: PublicKey,
        before: Option<Reached>,
        result: &Result<(bool, sync::Transfer), Failure>,
    ) {
        let peer_hex = peer.to_hex();
        let (before, refused_before, waiting_before) = match before {
            Some(reached) => (Some(reached.error), reached.refused, reached.waiting),
            None => (None, Vec::new(), Vec::new()),
        };
        match result {
            Err(error) => {
                let error = error.to_string();
                if before.flatten().as_ref() != Some(&error) {
                    self.activity.record(
                        "peer_attempt_failed",
                        json!({"peer": peer_hex, "error": error}),
                    );
                }
            }
            Ok((_, transfer)) => {
                if !matches!(before, Some(None)) {
                    self.activity
                        .record("peer_reconciliation_completed", json!({"peer": peer_hex}));
                }
                // Recorded when the set changes, not on every sync.
                if transfer.refused != refused_before {
                    let scopes: Vec<Value> = transfer
                        .refused
                        .iter()
                        .map(|scope| self.scope_label(scope))
                        .collect();
                    self.activity.record(
                        "scopes_refused",
                        json!({"peer": peer_hex, "scopes": scopes}),
                    );
                }
                if transfer.waiting != waiting_before {
                    let scopes: Vec<Value> = transfer
                        .waiting
                        .iter()
                        .map(|scope| self.scope_label(scope))
                        .collect();
                    self.activity.record(
                        "scopes_waiting",
                        json!({"peer": peer_hex, "scopes": scopes}),
                    );
                }
                if transfer.scopes.is_empty() {
                    return;
                }
                let scopes: Vec<Value> = transfer
                    .scopes
                    .iter()
                    .map(|(scope, moved)| {
                        let mut label = self.scope_label(scope);
                        label["pulled"] = json!(moved.pulled);
                        label["pushed"] = json!(moved.pushed);
                        label["bytes"] = json!(moved.bytes);
                        label
                    })
                    .collect();
                let (pulled, pushed) = transfer
                    .scopes
                    .iter()
                    .fold((0, 0), |(pulled, pushed), (_, moved)| {
                        (pulled + moved.pulled, pushed + moved.pushed)
                    });
                if pulled + pushed > 0 {
                    self.activity.record(
                        "synced",
                        json!({"peer": peer_hex, "pulled": pulled, "pushed": pushed, "scopes": scopes}),
                    );
                }
                for (scope, moved) in &transfer.scopes {
                    if let Some((checkpoint, superseded)) = moved.checkpoint {
                        let mut event = self.scope_label(scope);
                        event["peer"] = json!(peer_hex);
                        event["checkpoint"] = json!(HEXLOWER.encode(&checkpoint));
                        event["superseded"] = json!(superseded);
                        self.activity.record("checkpoint_imported", event);
                    }
                }
            }
        }
    }
    /// A scope as events name it: its table, and for a partition its
    /// encryption commitment, which `partition_address` also reports.
    fn scope_label(&self, scope: &ResourceScope) -> Value {
        let domain = self.domain();
        let own = domain.scopes().find(|(_, own)| own.table == scope.table);
        json!({
            "table": own.map(|(name, _)| name),
            "partition": own.is_some_and(|(_, own)| own != *scope).then(|| HEXLOWER.encode(&scope.encryption)),
        })
    }
    fn wake_sync(&self) {
        self.sync_events
            .send_modify(|event| *event = event.wrapping_add(1));
    }
    fn synced(&self, mut status: Value) {
        self.sync_status.send_modify(|current| {
            let token = current["token"]
                .as_str()
                .and_then(|token| token.parse::<u64>().ok())
                .unwrap_or(0);
            status["token"] = json!(token.wrapping_add(1).to_string());
            *current = status;
        });
    }
    fn control_sync(&self) {
        self.sync_control
            .send_modify(|event| *event = event.wrapping_add(1));
        self.wake_sync();
    }
    fn peer_retry(&self, peer: PublicKey) -> PeerRetry {
        let identity = format!(
            "{}:{peer}",
            self.node_identity.as_deref().unwrap_or("unavailable")
        );
        PeerRetry {
            retry: crate::scheduling::Retry::seeded(self.retry_seed, identity.as_bytes()),
            link_retry: crate::scheduling::Retry::seeded(self.retry_seed, identity.as_bytes()),
            ..PeerRetry::default()
        }
    }
    pub(super) fn reset_retry(&self, peer: Option<PublicKey>) {
        let mut retries = self.retries.lock().unwrap_or_else(PoisonError::into_inner);
        for (node, state) in retries.iter_mut() {
            if peer.is_none_or(|peer| peer == *node) {
                state.retry.wake();
                state.link_retry.wake();
                state.short = false;
                state.generation = state.generation.wrapping_add(1);
            }
        }
    }
    fn inbound_sync(&self, peer: PublicKey) {
        if let Ok(at) = now() {
            let mut met = self.met.lock().unwrap_or_else(PoisonError::into_inner);
            met.insert(peer, at);
            if met.len() > MET
                && let Some(oldest) = met.iter().min_by_key(|(_, at)| **at).map(|(node, _)| *node)
            {
                met.remove(&oldest);
            }
        }
        let backed_off = self
            .retries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&peer)
            .is_some_and(|state| state.retry.deadline().is_some());
        if backed_off {
            self.reset_retry(Some(peer));
            self.wake_sync();
        }
    }
    fn pending_sync(&self) {
        for state in self
            .retries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values_mut()
        {
            state.pending = true;
        }
    }
    fn pending_without_links(&self, service: &Link) {
        for (peer, state) in self
            .retries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter_mut()
        {
            if !service.live.contains(*peer) {
                state.pending = true;
            }
        }
    }
    fn retry_deadline(&self) -> Option<tokio::time::Instant> {
        self.retries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .flat_map(|state| {
                [
                    if state.pending {
                        state.retry.deadline()
                    } else {
                        None
                    },
                    if state.link {
                        state.link_retry.deadline()
                    } else {
                        None
                    },
                ]
            })
            .flatten()
            .chain(
                self.resolution_retries
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .values()
                    .filter_map(crate::scheduling::Retry::deadline),
            )
            .chain(
                self.schema_acquisition
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .retry
                    .deadline(),
            )
            .min()
    }
    /// One worker per link; only pending work has a retry timer.
    async fn synchronize(self: Arc<Self>, link: Arc<Link>) {
        let mut stage = link.stage.subscribe();
        let mut events = self.sync_events.subscribe();
        let mut control = self.sync_control.subscribe();
        let mut frames = self.replica.observe_frames().await;
        let mut revisions = self.replica.observe_revision();
        let mut connectivity = link.transport.connectivity();
        let mut link_events = self.link_events.subscribe();
        let mut retry_only = false;
        loop {
            if *stage.borrow() != Stage::Open {
                break;
            }
            control.borrow_and_update();
            // Another watch may have won the select while explicit work was queued.
            if events.has_changed().unwrap_or(false) {
                self.pending_sync();
                retry_only = false;
            }
            events.borrow_and_update();
            if self.automatic.load(Ordering::SeqCst)
                && self.online.load(Ordering::SeqCst)
                && self.foreground.load(Ordering::SeqCst)
            {
                self.worker_running.send_replace(true);
                let running = WorkerActivity(self.worker_running.clone());
                let result = tokio::select! {
                    biased;
                    _ = stage.wait_for(|stage| *stage != Stage::Open) => break,
                    _ = control.changed() => continue,
                    result = async {
                        let attached = self.network.read().await;
                        if attached.as_ref().is_none_or(|current| current.id != link.id) {
                            return Ok((json!({"state": "idle"}), false));
                        }
                        let result = self.sync_pass(&*link.transport, true, retry_only).await;
                        self.open_links(&link).await;
                        result
                    } => result,
                };
                drop(running);
                self.topics_changed();
                let status = match result {
                    Ok((mut status, retry)) => {
                        status["retry"] = json!(retry);
                        status
                    }
                    Err(error) if error.is::<crate::enrollment::Revoked>() => {
                        json!({"state": "revoked", "error": error.to_string(), "retry": false})
                    }
                    Err(error) => {
                        json!({"state": "unavailable", "error": error.to_string(), "retry": self.retry_deadline().is_some()})
                    }
                };
                self.synced(status);
            } else if !self.online.load(Ordering::SeqCst) {
                self.synced(json!({"state": "networking_disabled", "retry": false}));
            }
            retry_only = false;
            let deadline = self.retry_deadline();
            tokio::select! {
                _ = stage.wait_for(|stage| *stage != Stage::Open) => break,
                _ = control.changed() => {},
                changed = events.changed() => { if changed.is_err() { break; } self.pending_sync(); }
                changed = frames.changed() => { if changed.is_err() { break; } settle().await; self.pending_without_links(&link); retry_only = true; }
                changed = revisions.changed() => { if changed.is_err() { break; } settle().await; self.pending_without_links(&link); retry_only = true; }
                changed = link_events.changed() => { if changed.is_err() { break; } retry_only = true; }
                () = async {
                    match &mut connectivity {
                        Some(events) => { if events.changed().await.is_err() { connectivity = None; } },
                        None => std::future::pending().await,
                    }
                } => { self.reset_retry(None); }
                () = async {
                    match deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                }, if self.automatic.load(Ordering::SeqCst) && self.online.load(Ordering::SeqCst) && self.foreground.load(Ordering::SeqCst) => { retry_only = true; }
            }
        }
    }

    /// Reconciles selected peers and records each attempted exchange.
    async fn sync_optional(
        &self,
        transport: Option<&dyn Transport>,
    ) -> Result<(Value, bool), Failure> {
        let result = self.reconciliation_pass(transport, false, false).await;
        self.topics_changed();
        let (report, _, retry) = result?;
        Ok((serde_json::to_value(report)?, retry))
    }
    #[cfg(test)]
    async fn sync(&self, transport: &dyn Transport) -> Result<(Value, bool), Failure> {
        self.sync_optional(Some(transport)).await
    }
    async fn sync_pass(
        &self,
        transport: &dyn Transport,
        automatic: bool,
        retry_only: bool,
    ) -> Result<(Value, bool), Failure> {
        self.reconciliation_pass(Some(transport), automatic, retry_only)
            .await
            .map(|(_, status, retry)| (status, retry))
    }
    async fn run_sync_pass(
        &self,
        transport: &dyn Transport,
        automatic: bool,
        retry_only: bool,
        report: &std::sync::Mutex<Vec<crate::PeerReconciliation>>,
        first_attempt_id: u64,
    ) -> Result<(Value, bool), Failure> {
        if let Some(statement) = self.settings.lock().await.revocation(&self.path)? {
            return Err(Box::new(crate::enrollment::Revoked(statement)));
        }
        if !self.online.load(Ordering::SeqCst) {
            return Ok((json!({"state": "networking_disabled"}), false));
        }
        if self.replica.private_schema().await? {
            let released = self.relay_schema_publication(transport).await?;
            if !released {
                return Ok((json!({"state":"schema_publication_pending"}), true));
            }
        }
        if automatic
            && retry_only
            && {
                let targets = self.dialed(&*self.settings.lock().await);
                let retries = self.retries.lock().unwrap_or_else(PoisonError::into_inner);
                targets.iter().all(|(peer, _)| retries.contains_key(peer))
                    && !retries
                        .values()
                        .any(|state| state.pending && state.retry.ready())
            }
            && self
                .resolution_retries
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty()
            && !self
                .schema_acquisition
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .retry
                .ready()
        {
            return Ok((
                self.sync_status.borrow().clone(),
                self.retry_deadline().is_some(),
            ));
        }
        let _activity = SyncActivity(self.sync_state.clone());
        self.sync_state.send_replace("syncing");
        // Finality records and member seals reach peers in this pass's
        // graph exchange.
        self.seal_routinely().await;
        self.finalize_seals().await;
        self.publish_for_members().await;
        self.close_migrations().await?;
        Box::pin(self.resolve_saved_contacts(transport)).await;
        let saved = self.settings.lock().await.clone();
        if !automatic && self.dialed(&saved).is_empty() && !saved.unresolved_contacts().is_empty() {
            if saved
                .unresolved_contacts()
                .iter()
                .all(|(_, contact)| contact.addresses(transport.kind()).is_empty())
            {
                return Err(ServiceError::NoRoute {
                    peer: "a saved peer",
                    network: transport.kind().into(),
                }
                .into());
            }
            return Ok((
                json!({"state":"unavailable", "error":"saved contact resolution produced no route"}),
                true,
            ));
        }
        let settings = self.settings.lock().await.clone();
        let member = !settings.issuer();
        // Adopting a generation renews nothing. A table it granted like one
        // this member holds joins its grants at a renewal, asked for once
        // per generation while an issuer is reachable.
        let widen = member
            && settings.profile_widens(&self.domain())?
            && self
                .widened
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(HEXLOWER.encode(&settings.domain()?.manifest().hash()));
        if widen || settings.expires() < now()?.saturating_add(settings.ttl / 2) {
            let renewed = self.renew(Some(transport), false, None, false).await;
            if let Err(error) = &renewed {
                self.activity
                    .record("renewal_failed", json!({"error": error.to_string()}));
            }
            if !member {
                renewed?;
            } else if renewed.is_err() && settings.expires() <= now()? {
                return Err("credentials expired; an issuer must be reachable to renew".into());
            }
        }
        let renewable = member || !settings.issuers.is_empty();
        // A served session brought statements, or frames wait for a key
        // epoch this device lacks, as after a restart that forgot the
        // statements were new: renew for the rotated keys before moving rows.
        if renewable && (self.learned.load(Ordering::SeqCst) || self.awaits_key_epoch().await) {
            let _ = self.renew(Some(transport), true, None, true).await;
            if let Some(statement) = self.settings.lock().await.revocation(&self.path)? {
                return Err(Box::new(crate::enrollment::Revoked(statement)));
            }
        }
        // Links refused while peers followed other tips are retried at once
        // after this device follows another tip, however it moved.
        let tip = self.replica.followed_tip().await;
        if self
            .backoff_tip
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .replace(tip)
            .is_some_and(|earlier| earlier != tip)
        {
            self.reset_retry(None);
        }
        let targets = self.dialed(&*self.settings.lock().await);
        self.replica.configure_peers(settings.kept()).await;
        let needs_initial = {
            let retries = self.retries.lock().unwrap_or_else(PoisonError::into_inner);
            targets.iter().any(|(peer, _)| !retries.contains_key(peer))
        };
        let mut has_frames = false;
        if needs_initial {
            let node = PrivateKey::from_bytes(&self.vault.get("node")?).public_key();
            let mut after = None;
            loop {
                let (scopes, next) = self
                    .replica
                    .held_scopes(node, &settings.credentials, after)
                    .await?;
                for scope in scopes {
                    has_frames |= !self.replica.frontier(scope).await?.logs.is_empty();
                }
                if has_frames || next.is_none() {
                    break;
                }
                after = next;
            }
        }
        let targets: Vec<_> = {
            let mut retries = self.retries.lock().unwrap_or_else(PoisonError::into_inner);
            retries.retain(|peer, _| targets.iter().any(|(node, _)| node == peer));
            targets
                .into_iter()
                .filter_map(|(peer, contact)| {
                    let state = retries.entry(peer).or_insert_with(|| PeerRetry {
                        pending: has_frames,
                        ..self.peer_retry(peer)
                    });
                    let skip = if !state.retry.ready() {
                        Some(crate::SkipReason::Backoff)
                    } else if automatic && retry_only && !state.pending {
                        Some(crate::SkipReason::NoPendingWork)
                    } else if automatic
                        && self
                            .current()
                            .is_some_and(|service| service.live.inbound_short(peer))
                    {
                        Some(crate::SkipReason::InboundReconciliation)
                    } else {
                        None
                    };
                    if let Some(skip) = skip {
                        Self::add_peer_report(report, Self::skipped_peer(peer.to_hex(), skip));
                        None
                    } else {
                        Some((peer, contact, state.generation))
                    }
                })
                .collect()
        };
        if targets.is_empty() {
            return Ok((
                self.sync_status.borrow().clone(),
                self.retry_deadline().is_some(),
            ));
        }
        let needed: Vec<_> = self
            .scopes()
            .into_iter()
            .filter(|scope| !self.domain().partitioned_table(scope))
            .collect();
        // A pass that failed after importing checkpoint pages goes on soon.
        let imports = self.replica.observe_imports().await;
        let imported = *imports.borrow();
        let mut covered = std::collections::BTreeSet::new();
        let mut targets = targets;
        let mut results = Vec::new();
        for round in 0..2 {
            let local_first = targets.first().is_some_and(|(peer, _, _)| {
                settings
                    .contact_meta
                    .get(peer)
                    .is_some_and(|meta| meta.local)
            });
            let mut remaining = targets.into_iter();
            let mut first_batch = true;
            loop {
                let width = if local_first && first_batch { 1 } else { 4 };
                first_batch = false;
                let mut batch: Vec<_> = remaining.by_ref().take(width).collect();
                if batch.is_empty() {
                    break;
                }
                if !needed.is_empty() && needed.iter().all(|scope| covered.contains(scope)) {
                    // Coverage by others never stands in for the one
                    // exchange a joined device owes its inviter.
                    let inviter = self.awaited_inviter();
                    let mut choices = self.choices.lock().unwrap_or_else(PoisonError::into_inner);
                    let mut owed = Vec::new();
                    for target in batch.into_iter().chain(remaining.by_ref()) {
                        if Some(target.0) == inviter {
                            owed.push(target);
                            continue;
                        }
                        choices.insert(target.0, "covered");
                        Self::add_peer_report(
                            report,
                            Self::skipped_peer(target.0.to_hex(), crate::SkipReason::Covered),
                        );
                    }
                    if owed.is_empty() {
                        break;
                    }
                    batch = owed;
                }
                let attempts = stream::iter(batch)
                    .map(|(peer, contact, generation)| async move {
                        let mut result = self.reconcile(transport, peer, &contact).await;
                        let settings = self.settings.lock().await.clone();
                        if settings.issuer()
                            && settings.issuers.contains(&peer)
                            && !result
                                .as_ref()
                                .is_err_and(|error| error.is::<ServiceError>())
                        {
                            match self.renew(Some(transport), true, Some(peer), true).await {
                                Ok(true) => {
                                    result = self.reconcile(transport, peer, &contact).await;
                                }
                                Ok(false) => {}
                                Err(error) => self.activity.record_changed(
                                    "epoch_delivery_failed",
                                    json!({"peer": peer.to_hex(), "error": error.to_string()}),
                                ),
                            }
                        }
                        (peer, contact, generation, result)
                    })
                    .buffer_unordered(4);
                tokio::pin!(attempts);
                while let Some((peer, contact, generation, result)) = attempts.next().await {
                    Self::add_peer_report(
                        report,
                        self.peer_reconciliation(peer, &result, first_attempt_id),
                    );
                    let error = result.as_ref().err().map(ToString::to_string);
                    let (refused, waiting) = match &result {
                        Ok((_, transfer)) => (transfer.refused.clone(), transfer.waiting.clone()),
                        Err(_) => (Vec::new(), Vec::new()),
                    };
                    let before = self.reached()?.insert(
                        peer,
                        Reached {
                            at: now()?,
                            error,
                            refused,
                            waiting,
                            held: result
                                .as_ref()
                                .map(|(_, transfer)| transfer.held.clone())
                                .unwrap_or_default(),
                        },
                    );
                    if let Ok((_, transfer)) = &result {
                        covered.extend(transfer.held.iter().copied());
                    }
                    self.record_reach(peer, before, &result);
                    results.push((peer, contact, generation, result));
                }
            }
            // A peer told this device of its own revocation.
            if let Some(statement) = self.settings.lock().await.revocation(&self.path)? {
                return Err(Box::new(crate::enrollment::Revoked(statement)));
            }
            let failed = |result: &Result<(bool, sync::Transfer), Failure>| {
                result
                    .as_ref()
                    .is_err_and(|error| !error.is::<ServiceError>())
            };
            // Renewing cannot repair a broken or stalled stream, or a replaced
            // checkpoint, and would cancel other active links.
            let renewal_peer = results
                .iter()
                .filter(|(_, _, _, result)| {
                    failed(result)
                        && !result.as_ref().is_err_and(|error| {
                            matches!(error.downcast_ref::<Error>(), Some(Error::Io(_)))
                                || matches!(error.downcast_ref::<Error>(), Some(Error::Rejected(reason)) if reason.starts_with("link ") || reason.ends_with(" timeout") || reason.starts_with("checkpoint superseded"))
                        })
                })
                .min_by_key(|(peer, _, _, _)| !settings.issuers.contains(peer))
                .map(|(peer, _, _, _)| *peer);
            if round == 0
                && renewable
                && let Some(peer) = renewal_peer
            {
                // Finish old-authority sessions before renewing once. Even a successful
                // old handshake must be checked again against the learned revocations.
                let renewed = self
                    .renew(Some(transport), true, Some(peer), false)
                    .await
                    .is_ok();
                if let Some(statement) = self.settings.lock().await.revocation(&self.path)? {
                    return Err(Box::new(crate::enrollment::Revoked(statement)));
                }
                // Without a renewal, a sync that stopped for learned
                // statements still moves its rows; new keys wait.
                let learned = |result: &Result<(bool, sync::Transfer), Failure>| {
                    result
                        .as_ref()
                        .is_err_and(|error| error.is::<sync::Learned>())
                };
                if renewed || results.iter().any(|(_, _, _, result)| learned(result)) {
                    let admitted: std::collections::BTreeSet<_> = self
                        .settings
                        .lock()
                        .await
                        .targets()
                        .into_iter()
                        .map(|(peer, _)| peer)
                        .collect();
                    results.retain(|(peer, _, _, _)| admitted.contains(peer));
                    // Coverage from the previous authority cannot skip its replacement pass.
                    covered.clear();
                    let again = |result: &Result<_, Failure>| match renewed {
                        true => result.is_ok() || failed(result),
                        false => learned(result),
                    };
                    targets = results
                        .iter()
                        .filter(|(_, _, _, result)| again(result))
                        .map(|(peer, contact, generation, _)| (*peer, contact.clone(), *generation))
                        .collect();
                    results.retain(|(_, _, _, result)| !again(result));
                    continue;
                }
            }
            break;
        }
        let catalog_changed = self.acquire_schemas(transport).await?;
        let schema_changed = self.follow_schema().await?;
        self.finalize_seals().await;
        self.close_migrations().await?;
        let (mut connected, mut first, mut retry) = (0, None, catalog_changed || schema_changed);
        for (peer, _, generation, result) in results {
            {
                let mut retries = self.retries.lock().unwrap_or_else(PoisonError::into_inner);
                if let Some(state) = retries.get_mut(&peer)
                    && state.generation == generation
                {
                    match &result {
                        Ok((false, _)) => {
                            state.retry.reset();
                            state.link_retry.reset();
                            state.pending = false;
                        }
                        Ok((true, _)) => {
                            state.pending = true;
                            state.retry.failed();
                        }
                        Err(_) if *imports.borrow() != imported => {
                            state.pending = true;
                            state.retry.soon();
                        }
                        Err(_) => state.retry.failed(),
                    }
                }
            }
            match result {
                Ok((pending, _)) => {
                    connected += 1;
                    retry |= pending;
                }
                Err(error) => {
                    first.get_or_insert(error);
                }
            }
        }
        retry |= first.is_some();
        match first {
            Some(error) if connected == 0 => Ok((
                json!({"state":"unavailable", "error":error.to_string()}),
                true,
            )),
            _ => Ok((json!({"state": "connected", "peers": connected}), retry)),
        }
    }
    /// Local routes, observed holdings and trusted contacts, with backed-off peers last.
    fn dialed(&self, settings: &Settings) -> Vec<(PublicKey, Contact)> {
        let reached = self.reached.lock().unwrap_or_else(PoisonError::into_inner);
        let retries = self.retries.lock().unwrap_or_else(PoisonError::into_inner);
        let needed: Vec<_> = self
            .scopes()
            .into_iter()
            .filter(|scope| !self.domain().partitioned_table(scope))
            .collect();
        let mut targets = settings.targets();
        targets.sort_by_key(|(node, _)| {
            let meta = settings.contact_meta.get(node);
            (
                retries.get(node).is_some_and(|state| !state.retry.ready()),
                !meta.is_some_and(|meta| meta.local),
                !reached.get(node).is_some_and(|last| {
                    last.error.is_none() && needed.iter().any(|scope| last.held.contains(scope))
                }),
                !(settings.issuers.contains(node) || meta.is_some_and(|meta| meta.trusted)),
                reached.get(node).map(|last| last.at),
            )
        });
        let mut choices = self.choices.lock().unwrap_or_else(PoisonError::into_inner);
        choices.clear();
        for (index, (node, _)) in targets.iter().enumerate() {
            let meta = settings.contact_meta.get(node);
            let reason = if retries.get(node).is_some_and(|state| !state.retry.ready()) {
                "backoff"
            } else if index >= crate::enrollment::MAX_DIALED {
                "pass_limit"
            } else if meta.is_some_and(|meta| meta.local) {
                "selected_local"
            } else if reached.get(node).is_some_and(|last| {
                last.error.is_none() && needed.iter().any(|scope| last.held.contains(scope))
            }) {
                "selected_holding"
            } else if settings.issuers.contains(node) || meta.is_some_and(|meta| meta.trusted) {
                "selected_trusted"
            } else {
                "selected_probe"
            };
            choices.insert(*node, reason);
        }
        targets.truncate(crate::enrollment::MAX_DIALED);
        targets
    }
    /// Keeps the statements the replica learned in sessions in this
    /// identity. One that revokes this device, which the replica does not
    /// keep, is recorded as after a refused renewal; rows of a newly revoked
    /// author arrive by checkpoint.
    async fn absorb_revocations(&self, outcome: Option<&Failure>) -> Result<(), Failure> {
        let held = self.replica.revocations().await;
        let revoking = outcome.and_then(revoked_by);
        let mut settings = self.settings.lock().await;
        if !settings.lacks(&held)? && revoking.is_none() {
            return Ok(());
        }
        let mut draft = settings.clone();
        if draft.lacks(&held)? {
            draft.learn_revocations(&held)?;
            draft.forget_revoked();
            draft.drop_revoked_deliveries();
            self.learned.store(true, Ordering::SeqCst);
            // Issuers retain sibling epochs; members restore newly revoked authors by checkpoint.
            if !draft.issuer() {
                rocky_credentials::write_private(
                    &self.path.with_file_name("bootstrap.json"),
                    b"true",
                )?;
            }
            draft.save(&self.path)?;
        }
        if let Some(statement) = revoking
            && draft.revocation(&self.path)?.is_none()
        {
            draft.record_revocation(&self.path, statement)?;
            let node = PrivateKey::from_bytes(&self.vault.get("node")?).public_key();
            self.activity
                .record("device_revoked", json!({"node": node.to_hex()}));
        }
        *settings = draft;
        drop(settings);
        self.refresh_importing().await?;
        self.sweep_deliveries().await
    }
    /// The scopes a bootstrap intent still imports from a checkpoint.
    async fn bootstrap_pending(&self, intent: &Value) -> Result<Vec<ResourceScope>, Failure> {
        let token = intent.get("intent").unwrap_or(intent);
        if token != &json!(true) {
            return Err(refused("invalid bootstrap authority intent"));
        }
        let pending: Vec<ResourceScope> = match intent.get("pending") {
            Some(pending) => serde_json::from_value(pending.clone())?,
            None => self.scopes(),
        };
        if pending.iter().any(|scope| !self.scopes().contains(scope)) {
            return Err(refused("bootstrap intent names an ungranted scope"));
        }
        // Keyless custody scopes cannot import a checkpoint; they sync rows.
        // Nor can a partitioned table's own scope, which holds no rows.
        let settings = self.settings.lock().await;
        Ok(pending
            .into_iter()
            .filter(|scope| {
                settings.reads_whole(&self.domain(), scope)
                    && !self.domain().partitioned_table(scope)
            })
            .collect())
    }
    /// Whether received frames wait for a key epoch this device lacks.
    async fn awaits_key_epoch(&self) -> bool {
        self.replica.blockers().await.is_ok_and(|blockers| {
            blockers.iter().any(|blocker| {
                matches!(
                    blocker.kind,
                    rocky_core::BlockerKind::PendingFrames {
                        reason: rocky_core::WaitReason::OpeningKey,
                        ..
                    }
                )
            })
        })
    }
    /// The inviter a joined device still owes one exchange, if any.
    fn awaited_inviter(&self) -> Option<PublicKey> {
        let bytes = std::fs::read(self.path.with_file_name("bootstrap.json")).ok()?;
        serde_json::from_slice::<Value>(&bytes)
            .ok()?
            .get("inviter")?
            .as_str()?
            .parse()
            .ok()
    }
    /// The intent to keep instead of clearing a completed `intent` with
    /// `peer`: a joined device waits for one exchange with its inviter, which
    /// holds the envelopes shared with it after enrollment, unless revoked.
    async fn awaits_inviter(
        &self,
        peer: PublicKey,
        intent: &[u8],
    ) -> Result<Option<Vec<u8>>, Failure> {
        let mut intent: Value = serde_json::from_slice(intent)?;
        let Some(inviter) = intent.get("inviter").and_then(Value::as_str) else {
            return Ok(None);
        };
        let inviter: PublicKey = inviter.parse()?;
        if inviter == peer || self.settings.lock().await.revocations.revokes(&inviter) {
            return Ok(None);
        }
        intent["pending"] = json!([]);
        Ok(Some(serde_json::to_vec(&intent)?))
    }
    /// Tells the replica which scopes the bootstrap intent imports, so
    /// peers hold back their history for them.
    pub(crate) async fn refresh_importing(&self) -> Result<(), Failure> {
        // An intent the bootstrap itself refuses holds nothing back; the
        // bootstrap reports it.
        let pending = match std::fs::read(self.path.with_file_name("bootstrap.json")) {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(intent) => self.bootstrap_pending(&intent).await.unwrap_or_default(),
                Err(_) => Vec::new(),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        self.replica
            .set_importing(pending.into_iter().collect())
            .await;
        Ok(())
    }
    /// Whether a staged import of `signer`'s checkpoint, at `cursor`, goes on
    /// with that signer rather than restarting from another peer's
    /// checkpoint: while the signer is linked and the import moved within
    /// `IMPORT_SOURCE`.
    fn keeps_import_source(
        &self,
        scope: ResourceScope,
        signer: PublicKey,
        cursor: Option<rocky_core::Commitment>,
    ) -> bool {
        let linked = self
            .current()
            .is_some_and(|service| service.live.contains(signer));
        let mut sources = self
            .import_sources
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !linked {
            sources.remove(&scope);
            return false;
        }
        let now = tokio::time::Instant::now();
        let seen = sources.entry(scope).or_insert((cursor, now));
        if seen.0 != cursor {
            *seen = (cursor, now);
        }
        now.duration_since(seen.1) < IMPORT_SOURCE
    }
    /// Syncs with one peer, then keeps the revocations its sessions brought.
    async fn reconcile(
        &self,
        transport: &dyn Transport,
        peer: PublicKey,
        contact: &Contact,
    ) -> Result<(bool, sync::Transfer), Failure> {
        let _ = self.observations.partial_transfer(&peer.to_hex());
        let mut result = self.reconcile_observed(transport, peer, contact).await;
        if let Ok((_, transfer)) = &mut result
            && let Some(partial) = self.observations.partial_transfer(&peer.to_hex())
        {
            transfer.extend(partial);
        }
        if let Ok((_, transfer)) = &result {
            let mut failures = self
                .sync_failures
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let unanswered =
                |scope| transfer.failed.contains(scope) || transfer.denied.contains(scope);
            for scope in transfer
                .held
                .iter()
                .chain(transfer.scopes.iter().map(|(scope, _)| scope))
            {
                if !unanswered(scope) {
                    failures.retain(|(_, known), _| known != scope);
                }
            }
            // A scope the peer does not share was never its to serve.
            for scope in &transfer.refused {
                if !unanswered(scope) {
                    failures.remove(&(peer, *scope));
                }
            }
            for scope in transfer.failed.iter().chain(&transfer.denied) {
                failures
                    .entry((peer, *scope))
                    .and_modify(|failure| failure.refused = transfer.denied.contains(scope))
                    .or_insert_with(|| SyncFailure {
                        refused: transfer.denied.contains(scope),
                        since: now().ok(),
                    });
            }
        }
        if let Ok((retry, transfer)) = &mut result
            && !*retry
        {
            *retry = self.owes_retry(peer, transfer).await;
        }
        result
    }
    /// Whether another exchange with `peer` is owed: a blocker that this
    /// peer or any permitted peer clears remains for a scope the peer
    /// served, or for the domain whose scopes it served. The backoff spaces
    /// the retries.
    async fn owes_retry(&self, peer: PublicKey, transfer: &sync::Transfer) -> bool {
        use rocky_core::{ClearsBy, domain_label, scope_label};
        let Ok(blockers) = self.blockers().await else {
            return false;
        };
        let served: std::collections::BTreeSet<String> = transfer
            .held
            .iter()
            .chain(transfer.scopes.iter().map(|(scope, _)| scope))
            .filter(|scope| !transfer.refused.contains(scope))
            .map(scope_label)
            .collect();
        let domain = domain_label(&self.domain().scope);
        let node = peer.to_hex();
        blockers.iter().any(|blocker| {
            let clears = match &blocker.clears_by {
                ClearsBy::AnyPeer => true,
                ClearsBy::Peer { node: by } => *by == node,
                ClearsBy::LocalWork | ClearsBy::Application | ClearsBy::NoPeer => false,
            };
            clears
                && (served.contains(&blocker.scope)
                    || (blocker.scope == domain && !served.is_empty()))
        })
    }
    async fn reconcile_observed(
        &self,
        transport: &dyn Transport,
        peer: PublicKey,
        contact: &Contact,
    ) -> Result<(bool, sync::Transfer), Failure> {
        let mut result = Err("link authority kept changing during reconciliation".into());
        for _ in 0..4 {
            let revocations = self.replica.revocation_digest().await?;
            let first_attempt_id = self.observations.next_id();
            let mut attempt = self.observations.begin(
                peer.to_hex(),
                crate::AttemptOperation::Reconcile,
                crate::AttemptStage::ResolveRoute,
            );
            result = self.exchange(transport, peer, contact, &mut attempt).await;
            if result.is_err()
                && attempt.current_stage() == crate::AttemptStage::ResolveRoute
                && let Some(link) = self
                    .observations
                    .snapshot()
                    .into_iter()
                    .filter(|item| {
                        item.target == peer.to_hex()
                            && item.operation == crate::AttemptOperation::OpenLink
                            && item.id >= first_attempt_id
                    })
                    .max_by_key(|item| item.id)
            {
                attempt.stage(link.stage);
            }
            let failure = result
                .as_ref()
                .err()
                .map(|error| crate::status::failure(error, &attempt.current_stage()));
            attempt.finish(failure);
            self.absorb_revocations(result.as_ref().err()).await?;
            if result.is_err() && self.replica.revocation_digest().await? != revocations {
                result = Err(Box::new(sync::Learned));
                break;
            }
            let interrupted = result.as_ref().err().is_some_and(|error| match error
                .downcast_ref::<rocky_secure::Error>(
            ) {
                Some(rocky_secure::Error::Io(error)) => matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                ),
                Some(rocky_secure::Error::Rejected(reason)) => reason.starts_with("link ended"),
                Some(rocky_secure::Error::Application(cause)) => {
                    cause.is::<rocky_secure::network::link::AuthorityChanged>()
                }
                _ => false,
            });
            if result.is_ok() || !interrupted {
                break;
            }
        }
        let transfer = result?;
        let met = self.met.lock().unwrap_or_else(PoisonError::into_inner);
        let mut handover = self.handover.lock().unwrap_or_else(PoisonError::into_inner);
        handover.insert(peer);
        if handover.len() > 16
            && let Some(oldest) = handover
                .iter()
                .min_by_key(|node| (met.get(node).copied().unwrap_or_default(), **node))
                .copied()
        {
            handover.remove(&oldest);
        }
        Ok(transfer)
    }
    pub(super) async fn request_link(
        &self,
        transport: &dyn Transport,
        peer: PublicKey,
        contact: &Contact,
    ) -> Result<rocky_secure::network::link::channels::Handle, Failure> {
        let mut attempt = None;
        let result = self
            .request_link_observed(transport, peer, contact, &mut attempt)
            .await;
        if let Some(attempt) = attempt {
            let failure = result
                .as_ref()
                .err()
                .map(|error| crate::status::failure(error, &attempt.current_stage()));
            attempt.finish(failure);
        }
        result
    }
    async fn request_link_observed(
        &self,
        transport: &dyn Transport,
        peer: PublicKey,
        contact: &Contact,
        attempt: &mut Option<crate::status::Attempt>,
    ) -> Result<rocky_secure::network::link::channels::Handle, Failure> {
        if !self.foreground.load(Ordering::SeqCst) {
            return Err("live links are disabled in the background".into());
        }
        let addresses = contact.addresses(transport.kind());
        let service = self
            .current()
            .ok_or(ServiceError::NetworkRequired("sync"))?;
        if addresses.is_empty() && !service.live.contains(peer) {
            return Err(ServiceError::NoRoute {
                peer: "the peer",
                network: transport.kind().into(),
            }
            .into());
        }
        for _ in 0..4 {
            service.live.wait_inbound_short(peer).await?;
            if let Some(open) = service.live.handle(peer) {
                return Ok(open);
            }
            let _opening = self.opening(&service, peer);
            let current_attempt = attempt.insert(self.observations.begin(
                peer.to_hex(),
                crate::AttemptOperation::OpenLink,
                crate::AttemptStage::Dial,
            ));
            let stream = crate::enrollment::dial(transport, &addresses, Protocol::Link).await?;
            let owner = self
                .owner
                .get()
                .and_then(std::sync::Weak::upgrade)
                .ok_or("network owner ended")?;
            let link_settings = self.settings.lock().await.clone();
            current_attempt.stage(crate::AttemptStage::Admission);
            let admitted = Box::pin(owner.admit_link(
                service.clone(),
                stream,
                Some(peer),
                link_settings,
                None,
            ))
            .await;
            if let Err(error) = admitted {
                let changed = error.downcast_ref::<rocky_secure::Error>().is_some_and(|error| {
                    matches!(error, rocky_secure::Error::Application(cause) if cause.is::<rocky_secure::network::link::AuthorityChanged>())
                });
                if changed {
                    if let Some(attempt) = attempt.take() {
                        let failure = crate::status::failure(&error, &attempt.current_stage());
                        attempt.finish(Some(failure));
                    }
                    self.absorb_revocations(Some(&error)).await?;
                    continue;
                }
                // A refusal, a full link budget included, backs off; nothing else syncs.
                return Err(error);
            }
            if let Some(open) = service.live.handle(peer) {
                return Ok(open);
            }
        }
        Err(Box::new(rocky_secure::Error::Application(Box::new(
            rocky_secure::network::link::AuthorityChanged,
        ))))
    }
    async fn exchange(
        &self,
        transport: &dyn Transport,
        peer: PublicKey,
        contact: &Contact,
        attempt: &mut crate::status::Attempt,
    ) -> Result<(bool, sync::Transfer), Failure> {
        let mut node = peer.to_hex();
        node.truncate(12);
        let span = tracing::info_span!("exchange", peer = node, outcome = tracing::field::Empty);
        let result = tracing::Instrument::instrument(
            self.exchange_inner(transport, peer, contact, attempt),
            span.clone(),
        )
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "error" });
        result
    }
    async fn exchange_inner(
        &self,
        transport: &dyn Transport,
        peer: PublicKey,
        contact: &Contact,
        attempt: &mut crate::status::Attempt,
    ) -> Result<(bool, sync::Transfer), Failure> {
        let service = self
            .current()
            .ok_or(ServiceError::NetworkRequired("sync"))?;
        let revocations = self.replica.revocation_digest().await?;
        let link = self.request_link(transport, peer, contact).await?;
        attempt.stage(crate::AttemptStage::Reconciliation);
        let _short = service.live.short(peer);
        let renewable = {
            let settings = self.settings.lock().await;
            !settings.issuer() || !settings.issuers.is_empty()
        };
        let keep = |scope, signer, cursor| self.keeps_import_source(scope, signer, cursor);
        let upstream = Upstream {
            observations: &self.observations,
            link,
            peer,
            contacts: Some(self),
            renew_from: match renewable {
                true => Some(revocations),
                false => None,
            },
            keep: Some(&keep),
        };
        let reconcile = upstream.link.begin_reconcile().await?;
        // Envelopes first, on the exchange's first session: a list a
        // delivery opens syncs in this exchange. A stalled dial must not
        // hold the shared checkpoint import slot.
        let mut first = match self.deliver(&upstream).await {
            Ok(delivered) => Some(delivered),
            Err(error) => {
                let _ = reconcile.close().await;
                let _ = upstream.link.drain().await;
                return Err(error);
            }
        };
        // Recovery during ordinary sync shares the same staged checkpoint state as bootstrap.
        let _bootstrap = self.bootstrap.lock().await;
        let marker = self.path.with_file_name("bootstrap.json");
        let mut bootstrapped = sync::Transfer::default();
        let mut importing = Vec::new();
        let mut bootstrap_retry = false;
        if marker.exists() {
            self.sync_state.send_replace("bootstrapping");
            // An ancestor checkpoint needs its verified schema before import;
            // learning it after this exchange would back off a usable peer.
            self.acquire_schemas(transport).await?;
            let expected = std::fs::read(&marker)?;
            let pending = self
                .bootstrap_pending(&serde_json::from_slice(&expected)?)
                .await?;
            self.replica
                .set_importing(pending.iter().copied().collect())
                .await;
            self.activity.record_changed(
                "bootstrap_started",
                json!({"peer": peer.to_hex(), "scopes": pending.len()}),
            );
            // `None`: this peer offers no checkpoint; intent stays for another.
            let completed = sync::bootstrap(
                &self.replica,
                &upstream,
                &pending,
                &marker,
                expected,
                &mut bootstrapped,
                first.take(),
            )
            .await;
            let completed = match completed {
                Err(_) => {
                    bootstrap_retry = true;
                    None
                }
                Ok(completed) => completed,
            };
            if completed.is_none() {
                bootstrap_retry = true;
                importing = self
                    .bootstrap_pending(&serde_json::from_slice(&std::fs::read(&marker)?)?)
                    .await?;
            }
            if let Some(completed) = completed {
                self.replica.flush().await?;
                if std::fs::read(&marker)? != completed {
                    return Err("bootstrap authority changed; retry with the new intent".into());
                }
                self.replica
                    .set_importing(std::collections::BTreeSet::new())
                    .await;
                if let Some(waiting) = self.awaits_inviter(peer, &completed).await? {
                    rocky_credentials::write_private(&marker, &waiting)?;
                } else {
                    std::fs::remove_file(&marker)?;
                    #[cfg(unix)]
                    std::fs::File::open(
                        marker.parent().ok_or("bootstrap marker has no directory")?,
                    )?
                    .sync_all()?;
                    self.activity
                        .record("bootstrap_finished", json!({"peer": peer.to_hex()}));
                }
            }
        }
        self.sync_state.send_replace("syncing");
        // Table roots remain in the SQL catalog; only concrete holdings sync.
        let scopes: Vec<_> = self
            .scopes()
            .into_iter()
            .filter(|scope| !self.domain().partitioned_table(scope) && !importing.contains(scope))
            .collect();
        let reconciled = sync::reconcile(
            &self.replica,
            &upstream,
            &scopes,
            |bootstrap| {
                self.sync_state.send_replace(if bootstrap {
                    "bootstrapping"
                } else {
                    "syncing"
                });
            },
            first,
        )
        .await;
        // Draining waits for the peer's reverse exchange, which may need
        // this node's import slot through another peer. Release it first.
        drop(_bootstrap);
        let (retry, transfer) = match reconciled {
            Err(error) => {
                self.observations
                    .record_partial(peer.to_hex(), bootstrapped);
                let _ = reconcile.close().await;
                let _ = upstream.link.drain().await;
                return Err(error);
            }
            Ok(reconciled) => reconciled,
        };
        bootstrapped.extend(transfer);
        if let Err(error) = reconcile.close().await {
            self.observations
                .record_partial(peer.to_hex(), bootstrapped);
            return Err(error.into());
        }
        if let Err(error) = upstream.link.drain().await {
            self.observations
                .record_partial(peer.to_hex(), bootstrapped);
            return Err(error.into());
        }
        Ok((retry || bootstrap_retry, bootstrapped))
    }
    /// Serves one inbound one-shot stream: pairing and renewal on an issuer,
    /// and enrollment. Synchronization runs on live links.
    pub async fn serve(&self, protocol: Protocol, stream: Stream) -> Result<(), Failure> {
        if !self.online.load(Ordering::SeqCst) || self.ended.lock().await.is_some() {
            return Err("networking is disabled or this device logged out".into());
        }
        match protocol {
            Protocol::Pair => {
                let mut enrolled = false;
                let answered = answer(stream, async |request| {
                    if let Some(reply) = self.forward_enrollment(Protocol::Pair, &request).await? {
                        return Ok(reply);
                    }
                    let reply = Box::pin(self.answer_pair(&request)).await?;
                    enrolled = true;
                    Ok(reply)
                })
                .await;
                // The joining peer must receive enrollment before we dial its return routes.
                if answered.is_ok() && enrolled {
                    self.wake_sync();
                }
                answered
            }
            Protocol::Renew => {
                answer(stream, async |request| {
                    if let Some(bytes) = request.strip_prefix(b"rocky.sdk.staged-close.v1\n") {
                        let outcome = self.replica.relay_staged_close(bytes).await?;
                        return Ok(serde_json::to_vec(&outcome)?);
                    }
                    if let Some(bytes) = request.strip_prefix(crate::tip_schemas::PROTOCOL) {
                        if self.replica.private_schema().await? {
                            return Ok(b"null".to_vec());
                        }
                        let request: crate::tip_schemas::Request = serde_json::from_slice(bytes)?;
                        return Ok(self
                            .replica
                            .tip_schema(request.manifest)
                            .await?
                            .unwrap_or_else(|| b"null".to_vec()));
                    }
                    if let Some(reply) = self.forward_enrollment(Protocol::Renew, &request).await? {
                        return Ok(reply);
                    }
                    if let Some(reply) =
                        rocky_secure::network::NativeSession::peer_resolution_reply(
                            &request,
                            &PrivateKey::from_bytes(&self.vault.get("node")?),
                        )?
                    {
                        return Ok(reply);
                    }
                    let mut settings = self.settings.lock().await.clone();
                    settings.bootstrap = Some(self.enrollment_bootstrap().await?);
                    // Any node answers another node of its own identity.
                    if let Some(asked) = request.strip_prefix(crate::enrollment::IDENTITY) {
                        let reply = settings.answer_identity(&self.vault, asked)?;
                        self.activity.record("identity_node_enrolled", json!({}));
                        return Ok(reply);
                    }
                    if !settings.issuer() {
                        return Err(refused("only an issuer renews devices"));
                    }
                    if let Some(bytes) = request.strip_prefix(crate::enrollment::EPOCHS) {
                        let request: crate::enrollment::EpochRequest =
                            serde_json::from_slice(bytes)?;
                        let signed = rocky_credentials::RenewRequest::from_bytes(&request.request)?;
                        signed.verify(
                            PrivateKey::from_bytes(&self.vault.get("node")?).public_key(),
                            settings.publisher,
                            (now()?, 300),
                        )?;
                        let registry = self.registry().await?;
                        let mut current = self.settings.lock().await;
                        let mut draft = current.clone();
                        let added = draft.learn_revocations(&request.revocations)?;
                        if !added.is_empty() {
                            draft.save(&self.path)?;
                            *current = draft;
                            self.apply(&mut current, Vec::new()).await?;
                            for partition in current.partitions(&self.domain())? {
                                self.hold_keys(&current, &partition).await?;
                            }
                        }
                        let reply =
                            current.answer_epochs(&self.vault, &request.request, &registry)?;
                        drop(current);
                        return Ok(reply);
                    }
                    if request == crate::enrollment::POLICY {
                        return Ok(serde_json::to_vec(&settings.revocations)?);
                    }
                    Box::pin(self.answer_renewal(&request)).await
                })
                .await
            }
            Protocol::Link => Err("links require network-service ownership".into()),
            Protocol::Coordinate => Err("a database serves no coordinator requests".into()),
        }
    }

    /// Relays bytes only; the issuer and caller still verify the original request/answer.
    async fn forward_enrollment(
        &self,
        protocol: Protocol,
        request: &[u8],
    ) -> Result<Option<Vec<u8>>, Failure> {
        let settings = self.settings.lock().await.clone();
        if !settings.has_enrollment_upstream() {
            return Ok(None);
        }
        if settings.issuer() || !matches!(settings.profile, Profile::Custody { .. }) {
            return Err(refused(
                "enrollment forwarding requires a custody-only node",
            ));
        }
        let attached = self.network.read().await;
        let link = attached
            .as_ref()
            .ok_or(ServiceError::NetworkRequired("enrollment forwarding"))?;
        if settings.enrollment_upstream.is_none()
            && let Some(node) = settings.resolve_saved_upstream(&*link.transport).await?
        {
            self.settings.lock().await.bind_saved_contact(node);
        }
        let settings = self.settings.lock().await.clone();
        let upstream = settings
            .enrollment_upstream
            .ok_or_else(|| refused("enrollment upstream could not be resolved"))?;
        let contact = settings
            .peers
            .get(&upstream)
            .ok_or_else(|| refused("enrollment upstream is not configured"))?;
        let addresses = contact.addresses(link.transport.kind());
        if addresses.is_empty() {
            return Err(ServiceError::NoRoute {
                peer: "enrollment upstream",
                network: link.transport.kind().into(),
            }
            .into());
        }
        Ok(Some(
            exchange(&*link.transport, &addresses, protocol, request).await?,
        ))
    }

    #[cfg(feature = "iroh")]
    async fn service_call(
        &self,
        service: &crate::owner::Service,
        kind: &str,
        request: &Value,
        publisher: Option<Arc<dyn rocky_credentials::IdentityProvider>>,
    ) -> Result<Value, Failure> {
        let transport = self
            .network
            .read()
            .await
            .as_ref()
            .map(|link| link.transport.clone());
        let manifest = self.domain().manifest();
        let domain = crate::owner::Domain {
            scope: self.domain().scope,
            application: manifest.name.clone(),
            anchor: self.settings.lock().await.publisher,
            publisher,
            transport,
            request,
        };
        let operation = match kind {
            "coordination_register" => crate::AttemptOperation::CoordinatorRegister,
            "coordination_control" => crate::AttemptOperation::CoordinatorControl,
            "coordination_close" => crate::AttemptOperation::CoordinatorClose,
            "coordination_usage" => crate::AttemptOperation::CoordinatorUsage,
            _ => return Err(refused("unknown coordination service request")),
        };
        let attempt = self.observations.begin(
            "coordinator".into(),
            operation,
            crate::AttemptStage::CoordinatorRequest,
        );
        let result = service.call(kind, domain).await;
        attempt.finish(
            result.as_ref().err().map(|error| {
                crate::status::failure(error, &crate::AttemptStage::CoordinatorRequest)
            }),
        );
        result
    }
    #[cfg(not(feature = "iroh"))]
    async fn service_call(
        &self,
        service: &crate::owner::Service,
        _: &str,
        _: &Value,
        _: Option<Arc<dyn rocky_credentials::IdentityProvider>>,
    ) -> Result<Value, Failure> {
        match *service {}
    }
    /// The owner's calls on its coordination service: register or control
    /// the domain's trusted nodes with its tenant key, which stays in this
    /// process, close the domain or read usage; and the publisher's grant
    /// that lets a tenant register the application's domains.
    async fn coordination(&self, kind: &str, request: &Value) -> Result<Value, Failure> {
        match kind {
            "coordination_register"
            | "coordination_control"
            | "coordination_close"
            | "coordination_usage" => {
                let service = self.service.as_ref().ok_or_else(|| {
                    refused("this database is not composed with a coordination service")
                })?;
                let settings = self.settings.lock().await.clone();
                if kind == "coordination_register" && !settings.issuer() {
                    return Err(refused(
                        "registering a domain's trusted nodes needs an issuer",
                    ));
                }
                // Only the owner's identity signs a coordination grant here.
                let publisher = if settings.owner() {
                    Some(settings.identity(&self.vault)?)
                } else {
                    None
                };
                self.service_call(service, kind, request, publisher).await
            }
            "coordination_grant" => {
                let owner = {
                    let settings = self.settings.lock().await;
                    if !settings.owner() {
                        return Err(refused("only the owner's identity holds the publisher key"));
                    }
                    settings.identity(&self.vault)?
                };
                // The tenant's public key, or its secret in this process.
                let hex32 = |name: &str| -> Option<[u8; 32]> {
                    HEXLOWER
                        .decode(request[name].as_str()?.as_bytes())
                        .ok()?
                        .try_into()
                        .ok()
                };
                let tenant = match (hex32("tenant"), hex32("tenant_secret")) {
                    (Some(public), None) => public,
                    (None, Some(secret)) => {
                        *PrivateKey::from_bytes(&secret).public_key().as_bytes()
                    }
                    _ => return Err(refused("tenant must be a 64-digit hexadecimal key")),
                };
                let lifetime = request["lifetime"]
                    .as_u64()
                    .filter(|seconds| (1..=366 * 86_400).contains(seconds))
                    .ok_or_else(|| refused("lifetime must be 1 s to 366 days"))?;
                let time = now()?;
                let grant = rocky_credentials::SignedCoordinationGrant::sign(
                    rocky_credentials::CoordinationGrant {
                        publisher: rocky_credentials::Publisher(owner.public_key()?),
                        application: self.domain().manifest().name,
                        tenant: rocky_credentials::CoordinatorControl(
                            PublicKey::from_bytes(&tenant)
                                .map_err(|_| refused("tenant is not a valid key"))?,
                        ),
                        not_before: time.saturating_sub(60),
                        expires: time.saturating_add(lifetime),
                    },
                    &*owner,
                )?;
                Ok(json!({ "grant": grant }))
            }
            other => Err(refused(format!("unsupported request {other}"))),
        }
    }

    async fn sql_call(
        &self,
        client: &Client,
        kind: &str,
        request: &Value,
    ) -> Result<Value, Failure> {
        // An active SQL lease checks authority itself. Asking session status
        // would wait for the replica lock the lease already owns.
        let cached = client.reader.lock().await.clone();
        let reader = match cached {
            Some(reader) => reader,
            None => self.reader(client).await?,
        };
        if kind == "next_id" {
            let table = request["table"]
                .as_str()
                .ok_or_else(|| refused("table must be a string"))?;
            let id = if let Some(values) = request.get("partition_values") {
                let values: Vec<Cell> = serde_json::from_value(values.clone())?;
                reader
                    .sql
                    .next_id_partition(
                        table,
                        &values
                            .into_iter()
                            .map(Cell::sql)
                            .collect::<Result<Vec<_>, _>>()?,
                    )
                    .await?
            } else {
                reader.sql.next_id(table).await?
            };
            return Ok(json!({"id":id}));
        }
        let sql = request["sql"]
            .as_str()
            .filter(|sql| sql.len() <= MAX_SQL)
            .ok_or_else(|| refused("sql must be a bounded string"))?;
        let values: Vec<Cell> =
            serde_json::from_value(request.get("values").cloned().unwrap_or_else(|| json!([])))
                .map_err(refused)?;
        if values.len() > 256 {
            return Err(refused("SQL parameter quota"));
        }
        // Rocky orders no writes through a coordinated log; applications
        // coordinate their own.
        if request.get("coordinated").is_some() {
            return Err(refused("coordinated writes are not supported"));
        }
        let result = if sql.trim().eq_ignore_ascii_case("COMMIT") && request.get("handle").is_some()
        {
            if !values.is_empty() {
                return Err(refused("COMMIT takes no SQL parameters"));
            }
            let handle: Vec<u8> =
                serde_json::from_value(request["handle"].clone()).map_err(refused)?;
            let handle: [u8; 32] = handle
                .try_into()
                .map_err(|_| refused("handle must be 32 bytes"))?;
            reader.sql.commit(secure_handle(&handle)).await?
        } else {
            reader
                .sql
                .run(
                    sql,
                    values
                        .into_iter()
                        .map(Cell::sql)
                        .collect::<Result<_, _>>()?,
                )
                .await?
        };
        let rows: Vec<Vec<Cell>> = result
            .rows
            .into_iter()
            .map(|row| row.into_iter().map(Cell::from).collect())
            .collect();
        Ok(
            json!({"columns": result.columns, "rows": rows, "changes": result.changes.to_string(), "committed": result.committed.map(|commit| json!({"handle": HEXLOWER.encode(&commit.handle), "frames": commit.frames.len()}))}),
        )
    }
    async fn read(&self, client: &Client, query: Query) -> Result<Value, Failure> {
        match self.read_once(client, query.clone()).await {
            // An authority change ends the cached session; read again once.
            Err(error) if is_authority(&error) => {
                *client.reader.lock().await = None;
                self.read_once(client, query).await
            }
            other => other,
        }
    }
    async fn read_once(&self, client: &Client, query: Query) -> Result<Value, Failure> {
        let max_bytes = query.max_bytes.unwrap_or(rocky_runtime::MAX_FRAME_BYTES);
        if query.max_rows == 0
            || query.max_rows > MAX_ROWS
            || query.sql.len() > MAX_SQL
            || query.values.len() > 256
            || !(256..=rocky_runtime::MAX_FRAME_BYTES).contains(&max_bytes)
        {
            return Err(refused("query quota"));
        }
        let settings = self.settings.lock().await;
        let authority = (settings.revocations.digest(now()?)?, settings.expires());
        drop(settings);
        let mut descriptor = query.clone();
        descriptor.cursor = None;
        let token = |offset: usize| -> Result<String, Failure> {
            let bytes = serde_json::to_vec(&(
                client.cursor_key,
                self.domain().manifest().hash(),
                authority,
                &descriptor,
                offset,
            ))?;
            Ok(format!(
                "page.v1:{offset}:{}",
                HEXLOWER.encode(&commitment("rocky.sdk.cursor.v1", &bytes))
            ))
        };
        let offset: usize = match &query.cursor {
            Some(cursor) => {
                let offset = cursor
                    .strip_prefix("page.v1:")
                    .and_then(|rest| rest.split_once(':'))
                    .and_then(|(offset, _)| offset.parse().ok())
                    .ok_or_else(|| refused("invalid cursor"))?;
                if *cursor != token(offset)? {
                    return Err(refused(
                        "cursor belongs to another session, query or authority generation",
                    ));
                }
                offset
            }
            None => 0,
        };
        let reader = self.reader(client).await?;
        let revision = *self.replica.observe_revision().borrow();
        let mut values = query
            .values
            .into_iter()
            .map(Cell::sql)
            .collect::<Result<Vec<_>, _>>()?;
        values.push(SqlValue::Integer(i64::try_from(query.max_rows + 1)?));
        values.push(SqlValue::Integer(i64::try_from(offset)?));
        let sql = format!(
            "SELECT * FROM ({}) LIMIT ? OFFSET ?",
            query.sql.trim().trim_end_matches(';')
        );
        let mut result = reader.sql.run(&sql, values).await?;
        let more = result.rows.len() > query.max_rows;
        result.rows.truncate(query.max_rows);
        let mut rows = Vec::new();
        let mut used = serde_json::to_vec(&json!({
            "scope": self.domain().scope,
            "revision": revision.to_string(),
            "columns": result.columns,
            "rows": [],
            "next": token(usize::MAX)?,
            "next_kind": "offset",
        }))?
        .len()
            + 64;
        let mut limited = false;
        for row in result.rows {
            let row: Vec<Cell> = row.into_iter().map(Cell::from).collect();
            let size = serde_json::to_vec(&row)?.len() + 1;
            if used + size > max_bytes {
                if rows.is_empty() {
                    return Err(refused("one row exceeds the page byte quota"));
                }
                limited = true;
                break;
            }
            used += size;
            rows.push(row);
        }
        let next = if more || limited {
            Some(token(
                offset
                    .checked_add(rows.len())
                    .ok_or_else(|| refused("cursor quota"))?,
            )?)
        } else {
            None
        };
        Ok(json!({
            "scope": self.domain().scope,
            "revision": revision.to_string(),
            "columns": result.columns,
            "rows": rows,
            "next": next,
            "next_kind": "offset",
        }))
    }
    /// The first page of a subscription's query once the committed
    /// revision differs from the one it last delivered.
    async fn next(&self, client: &Client, id: u64) -> Result<Value, Failure> {
        let mut revisions = self.replica.observe_revision();
        let mut closing = client.closing.subscribe();
        let mut subscriptions = client.subscriptions_changed.subscribe();
        loop {
            let (query, delivered) = {
                let subscriptions = client.subscriptions()?;
                let subscription = subscriptions
                    .get(&id)
                    .ok_or_else(|| refused("unknown subscription"))?;
                (subscription.query.clone(), subscription.delivered.clone())
            };
            let current = revisions.borrow_and_update().to_string();
            if delivered.as_deref() != Some(current.as_str()) {
                let page = self.read(client, query).await?;
                if let Some(subscription) = client.subscriptions()?.get_mut(&id) {
                    subscription.delivered = page["revision"].as_str().map(String::from);
                }
                return Ok(page);
            }
            tokio::select! {
                changed = revisions.changed() => {
                    changed.map_err(|_| ServiceError::Closed("database"))?
                }
                _ = closing.wait_for(|closing| *closing) => {
                    return Err(ServiceError::Closed("session").into());
                }
                _ = subscriptions.changed() => {}
            }
        }
    }
}

/// The secure handle of a mutation handle.
fn secure_handle(handle: &[u8; 32]) -> rocky_core::Commitment {
    commitment("rocky.sdk.mutation.v1", handle)
}
/// The `after` token of an activity call; absent starts at the beginning.
fn token(request: &Value) -> Result<u64, Failure> {
    match &request["after"] {
        Value::Null => Ok(0),
        after => Ok(after
            .as_str()
            .ok_or_else(|| refused("after must be an activity token"))?
            .parse()?),
    }
}
fn subscription(request: &Value) -> Result<u64, Failure> {
    Ok(request["subscription"]
        .as_str()
        .ok_or("subscription must be a string")?
        .parse()?)
}
/// The statement that revokes this device, when a session ended on it.
fn revoked_by(error: &Failure) -> Option<rocky_credentials::SignedRevocation> {
    match error.downcast_ref::<Error>()? {
        Error::Application(error) => error
            .downcast_ref::<rocky_secure::network::Revoked>()
            .map(|revoked| (*revoked.0).clone()),
        _ => None,
    }
}
/// A replica refusal that names its own code: `sealed`,
/// `coordinator_unavailable`, `behind`, `stale_recovery` and `abandoned`.
fn replica_refusal(error: &Failure) -> Option<&rocky_secure::Refusal> {
    match error.downcast_ref::<Error>()? {
        Error::Application(error) => error.downcast_ref(),
        _ => None,
    }
}
fn is_authority(error: &Failure) -> bool {
    matches!(
        error.downcast_ref::<Error>(),
        Some(Error::Sql(SqlError::Unavailable {
            reason: Unavailable::Revoked,
            ..
        }))
    )
}

/// The error object of a failed call: its code and whether retrying the
/// same call may succeed.
pub fn error(error: &Failure) -> Value {
    let (code, retryable) = if error.is::<crate::enrollment::Revoked>() {
        ("revoked", false)
    } else if error.is::<crate::registry::RegistryFull>() {
        ("registry_full", false)
    } else if error.is::<crate::enrollment::RevocationSetFull>() {
        ("revocation_set_full", false)
    } else if error.is::<Refused>() {
        ("rejected", false)
    } else if let Some(refusal) = replica_refusal(error) {
        (
            refusal.code,
            matches!(
                refusal.code,
                "coordinator_unavailable" | "behind" | "recovery_pending"
            ),
        )
    } else if let Some(coordination) = error.downcast_ref::<rocky_core::CoordinationError>() {
        coordination_code(coordination)
    } else if let Some(service) = error.downcast_ref::<ServiceError>() {
        (service.code(), service.retryable())
    } else if let Some(credentials) = error.downcast_ref::<rocky_credentials::Error>() {
        match credentials {
            rocky_credentials::Error::Provider(_) => ("storage", false),
            _ => ("denied", false),
        }
    } else {
        match error.downcast_ref::<Error>() {
            Some(Error::Rejected(_) | Error::Protocol(_)) => ("rejected", false),
            // Blocked work proceeds once its blockers clear.
            Some(Error::Blocked(_)) => ("blocked", true),
            Some(Error::Incompatible(_)) => ("unsupported_generation", false),
            Some(Error::Sql(SqlError::Denied)) => ("denied", false),
            Some(Error::Sql(
                SqlError::Capture(_) | SqlError::Statement { .. } | SqlError::Unsupported(_),
            )) => ("rejected", false),
            // Missing rows or keys arrive by sync; a scope this device does
            // not hold needs a subscription first.
            Some(Error::Sql(SqlError::Unavailable { reason, .. })) => match reason {
                Unavailable::Incomplete | Unavailable::KeyMissing => ("missing_dependencies", true),
                Unavailable::NotHeld => ("rejected", false),
                Unavailable::Revoked => ("authority_changed", true),
                Unavailable::Released => ("rejected", false),
            },
            Some(Error::Conflict) => ("conflict", true),
            Some(Error::Backpressure) => ("quota", true),
            Some(Error::Coordination(coordination)) => coordination_code(coordination),
            _ => ("storage", true),
        }
    };
    let mut value = json!({"code": code, "retryable": retryable, "message": error.to_string()});
    let clock = match error
        .downcast_ref::<rocky_core::CoordinationError>()
        .or_else(|| match error.downcast_ref::<Error>() {
            Some(Error::Coordination(error)) => Some(error),
            _ => None,
        }) {
        Some(rocky_core::CoordinationError::ClockSkew { coordinator_time }) => {
            Some(*coordinator_time)
        }
        _ => None,
    };
    if let Some(time) = clock {
        value["coordinator_time"] = json!(time);
    }
    if let Some(Error::Blocked(blockers)) = error.downcast_ref::<Error>() {
        value["blockers"] = json!(blockers);
    }
    value
}
/// A coordination service's refusal as a call's error code.
fn coordination_code(error: &rocky_core::CoordinationError) -> (&'static str, bool) {
    use rocky_core::CoordinationError::{Backpressure, Denied, Sealed, Unavailable};
    match error {
        Unavailable => ("coordinator_unavailable", true),
        rocky_core::CoordinationError::ClockSkew { .. } => ("clock_skew", false),
        Backpressure => ("quota", true),
        Denied => ("denied", false),
        Sealed => ("sealed", false),
        _ => ("rejected", false),
    }
}

#[cfg(test)]
mod error_tests {
    use super::*;

    fn code(failure: Failure) -> (String, bool) {
        let value = error(&failure);
        (
            value["code"].as_str().unwrap_or_default().to_owned(),
            value["retryable"].as_bool().unwrap_or_default(),
        )
    }
    fn refusal(code: &'static str) -> Failure {
        Box::new(Error::Application(Box::new(rocky_secure::Refusal {
            code,
            message: "refused".into(),
        })))
    }

    #[test]
    fn clock_skew_reports_authority_time_through_every_error_path() {
        let time = 1_900_000_000;
        let errors: [Failure; 2] = [
            Box::new(rocky_core::CoordinationError::ClockSkew {
                coordinator_time: time,
            }),
            Box::new(Error::Coordination(
                rocky_core::CoordinationError::ClockSkew {
                    coordinator_time: time,
                },
            )),
        ];
        for failure in errors {
            let reported = error(&failure);
            assert_eq!(reported["code"], "clock_skew");
            assert_eq!(reported["coordinator_time"], time);
            assert_eq!(reported["retryable"], false);
        }
    }

    #[test]
    fn replica_refusals_keep_their_codes() {
        assert_eq!(code(refusal("sealed")), ("sealed".into(), false));
        assert_eq!(
            code(refusal("coordinator_unavailable")),
            ("coordinator_unavailable".into(), true)
        );
        let sealed: Failure = Box::new(rocky_core::CoordinationError::Sealed);
        assert_eq!(code(sealed), ("sealed".into(), false));
    }
}
#[cfg(test)]
mod delivery_tests;
#[cfg(test)]
mod revocation_tests;
#[cfg(test)]
mod sync_tests;
