//! The database owner and the handles composed on it: sessions and an
//! optional network service. See `docs/runtime/sdk-composition.md`.
use crate::{
    Failure,
    connection::{self, ConnectionOptions, Page, SqlFailure, TableEvents},
    enrollment::{DEFAULT_TTL, DeviceKeys, Settings, Supplied, now},
    node::{self, Client, Node},
    schema::Schema,
    secrets::{FileSecretStore, SecretStore},
    service::{Network, ServiceError},
    transport::Transport,
};
use rocky_secure::{EncryptedReplica, PrivateKey};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
};
use tokio::sync::{Mutex, Semaphore, mpsc, oneshot};

/// What opening a database takes. Without `secrets`, keys are owner-only
/// files in the data directory. Without `identity`, the node's identity is
/// made in, and kept in, the secret store. Without `network`, nothing is
/// dialed or listened on.
pub struct Open<'a> {
    pub directory: &'a Path,
    pub schema: &'a str,
    pub secrets: Option<Arc<dyn SecretStore>>,
    /// The application's identity provider. A database installed under one
    /// needs it at every open.
    pub identity: Option<Arc<dyn crate::IdentityProvider>>,
    pub network: Option<Network>,
    /// Optional metadata log or coordination service.
    pub coordination: Option<Coordination>,
}
/// Optional coordination, independent of database and network ownership.
#[derive(Clone)]
pub enum Coordination {
    Composed(Arc<dyn rocky_core::DomainLog>),
    #[cfg(feature = "iroh")]
    Service(Box<crate::TrustBundle>),
}
/// An open database and the network service it opened with, if any.
pub struct Opened {
    pub database: Arc<Database>,
    pub network: Option<NetworkService>,
}

pub(crate) enum Install {
    Create {
        ttl: u64,
    },
    Join {
        invitation: String,
    },
    Supplied(Box<Supplied>),
    /// Another node of the identity `open.identity` supplies, from a node
    /// of that identity.
    Identity {
        contact: String,
    },
    Installed,
    /// A backup archive, under a fresh identity the invitation enrolls.
    Restore {
        archive: PathBuf,
        invitation: String,
    },
}
struct Setup {
    directory: PathBuf,
    schema: Schema,
    secrets: Arc<dyn SecretStore>,
    identity: Option<Arc<dyn crate::IdentityProvider>>,
    install: Install,
    coordination: Option<Coordination>,
    confirmation: Option<String>,
    /// Where a hosted database hands out its node.
    #[cfg(test)]
    expose: Option<std::sync::mpsc::Sender<std::sync::Weak<Node>>>,
}
enum Command {
    #[cfg(all(test, feature = "qualification"))]
    BlockReactor(
        oneshot::Sender<()>,
        std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    ),
    Call {
        session: u64,
        bytes: Vec<u8>,
        ending: Arc<AtomicBool>,
        reply: oneshot::Sender<Vec<u8>>,
    },
    End(u64, oneshot::Sender<()>),
    Attach(Network, oneshot::Sender<Result<u64, Failure>>),
    Detach(u64, oneshot::Sender<()>),
    Close(oneshot::Sender<Result<(), String>>),
    Connect {
        options: ConnectionOptions,
        shared: Arc<Shared>,
        #[cfg(feature = "qualification")]
        queued: std::time::Instant,
        reply: oneshot::Sender<Result<Connection, Failure>>,
    },
    Sql {
        connection: u64,
        call: connection::Call,
        #[cfg(feature = "qualification")]
        queued: std::time::Instant,
        reply: oneshot::Sender<Result<connection::Reply, SqlFailure>>,
    },
    Disconnect {
        connection: u64,
        #[cfg(feature = "qualification")]
        queued: std::time::Instant,
        reply: oneshot::Sender<()>,
    },
    Coordinate(Option<Arc<dyn rocky_core::DomainLog>>, oneshot::Sender<()>),
    #[cfg(feature = "qualification")]
    LockMeasurements(oneshot::Sender<rocky_secure::LockMeasurements>),
    #[cfg(feature = "qualification")]
    ReactorMeasurements(oneshot::Sender<Option<crate::ReactorMeasurements>>),
    Observe(
        Option<Vec<String>>,
        oneshot::Sender<Result<rocky_runtime::TableObserver, Failure>>,
    ),
    Outcome(
        rocky_core::TransactionToken,
        oneshot::Sender<Result<Option<rocky_core::replay::TransactionOutcome>, Failure>>,
    ),
}
/// The scope and the network service a database opened with.
type Greeting = Result<(String, Option<u64>), Failure>;
/// Where `run` reports how opening went: to the opener blocked on the
/// database's thread, or to a hosting task that awaits it.
enum Hello {
    Thread(std::sync::mpsc::SyncSender<Greeting>),
    #[cfg(test)]
    Task(std::sync::Mutex<Option<oneshot::Sender<Greeting>>>),
}
impl Hello {
    fn send(&self, greeting: Greeting) -> Result<(), Failure> {
        match self {
            Self::Thread(sender) => sender
                .send(greeting)
                .map_err(|_| "database opener abandoned")?,
            #[cfg(test)]
            Self::Task(sender) => sender
                .lock()
                .map_err(|_| "greeting poisoned")?
                .take()
                .ok_or("greeted twice")?
                .send(greeting)
                .map_err(|_| "database opener abandoned")?,
        }
        Ok(())
    }
}

struct Shared {
    input: mpsc::Sender<Command>,
    cleanup: mpsc::UnboundedSender<Command>,
    budget: Semaphore,
    closed: AtomicBool,
    sessions: AtomicU64,
}
impl Shared {
    async fn request<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<T>) -> Command,
    ) -> Result<T, ServiceError> {
        let (reply, result) = oneshot::channel();
        self.input
            .send(command(reply))
            .await
            .map_err(|_| ServiceError::Closed("database"))?;
        result.await.map_err(|_| ServiceError::Closed("database"))
    }
}

/// Owns one secure database: its file, its installed credentials and the
/// reactor thread that serves its sessions. It owns no network.
pub struct Database {
    shared: Arc<Shared>,
    scope: String,
    worker: Mutex<Option<Worker>>,
}
/// What serves a database: its own thread, or in a simulation a task on
/// the caller's thread.
enum Worker {
    Thread(JoinHandle<()>),
    #[cfg(test)]
    Task(tokio::task::JoinHandle<()>),
}
impl Worker {
    async fn join(self) -> Result<(), Failure> {
        match self {
            Self::Thread(thread) => thread.join().map_err(|_| "database thread failed")?,
            #[cfg(test)]
            Self::Task(task) => task.await.map_err(|_| "database task failed")?,
        }
        Ok(())
    }
}
impl Database {
    /// Replica-local measurement support for release qualification probes.
    #[cfg(feature = "qualification")]
    pub async fn lock_measurements(&self) -> Result<rocky_secure::LockMeasurements, Failure> {
        Ok(self.shared.request(Command::LockMeasurements).await?)
    }
    #[cfg(feature = "qualification")]
    pub async fn reactor_measurements(&self) -> Result<crate::ReactorMeasurements, Failure> {
        self.shared
            .request(Command::ReactorMeasurements)
            .await?
            .ok_or_else(|| "reactor measurement context missing".into())
    }
    /// Creates a domain in an empty directory, owned by this node's
    /// identity, whose key is the publisher key. Credentials last
    /// `credential_ttl` seconds, 30 days by default.
    pub fn create(open: Open<'_>, credential_ttl: Option<u64>) -> Result<Opened, Failure> {
        let ttl = credential_ttl.unwrap_or(DEFAULT_TTL);
        if !(60..=366 * 24 * 60 * 60).contains(&ttl) {
            return Err("credential lifetime must be between a minute and a year".into());
        }
        Self::start(open, Install::Create { ttl })
    }
    /// Enrolls this device with the issuer an invitation names, as the
    /// grant profile it names, over `open.network`, which stays attached.
    pub fn join(open: Open<'_>, invitation: &str) -> Result<Opened, Failure> {
        if open.network.is_none() {
            return Err(ServiceError::NetworkRequired("join").into());
        }
        Self::start(
            open,
            Install::Join {
                invitation: invitation.into(),
            },
        )
    }
    /// Installs another node of the identity `open.identity` supplies: a
    /// node of that identity, which `contact` names, hands it what the
    /// identity holds over `open.network`, and its provider certifies this
    /// node. No issuer and no invitation is involved.
    pub fn enroll_identity(open: Open<'_>, contact: &str) -> Result<Opened, Failure> {
        if open.network.is_none() {
            return Err(ServiceError::NetworkRequired("enroll an identity's node").into());
        }
        if open.identity.is_none() {
            return Err("another node of an identity needs that identity's provider".into());
        }
        Self::start(
            open,
            Install::Identity {
                contact: contact.into(),
            },
        )
    }
    /// Makes the keys of a device that will receive credentials from
    /// outside the SDK, and returns their public halves for whoever issues
    /// them. Asking again returns the same keys. Nothing is contacted.
    pub fn device(
        directory: &Path,
        secrets: Option<Arc<dyn SecretStore>>,
    ) -> Result<DeviceKeys, Failure> {
        Self::device_of(directory, secrets, None)
    }
    /// As `device`, for a node of the identity `identity` supplies.
    pub fn device_of(
        directory: &Path,
        secrets: Option<Arc<dyn SecretStore>>,
        identity: Option<Arc<dyn crate::IdentityProvider>>,
    ) -> Result<DeviceKeys, Failure> {
        std::fs::create_dir_all(directory)?;
        let path = directory.join("identity.json");
        if path.exists() {
            return Err("a domain exists in this directory: open it instead".into());
        }
        let secrets =
            secrets.unwrap_or_else(|| Arc::new(FileSecretStore::new(directory.join("secrets"))));
        Settings::prepare_install(&path, &secrets, identity)
    }
    /// Installs credentials and reader keys supplied for the device that
    /// `device` prepared. They are verified like any others; no issuer is
    /// contacted and no network is needed.
    pub fn install(open: Open<'_>, supplied: Supplied) -> Result<Opened, Failure> {
        Self::start(open, Install::Supplied(Box::new(supplied)))
    }
    /// Opens the domain installed in the directory. A member whose
    /// credentials expired renews them over `open.network` first.
    pub fn open(open: Open<'_>) -> Result<Opened, Failure> {
        Self::start(open, Install::Installed)
    }
    /// Opens after the application confirms the exact removal impact report.
    pub fn open_confirmed(open: Open<'_>, digest: &str) -> Result<Opened, Failure> {
        Self::start_confirmed(open, Install::Installed, Some(digest.into()))
    }
    /// Restores a backup archive into an empty directory under a fresh
    /// signing identity, which `invitation` enrolls over `open.network`.
    /// The archive's operations, handles, tickets, results and effects keep
    /// their original identities; nothing is sent again as new work. An
    /// interrupted restore continues when called again. See
    /// `docs/runtime/backup-and-restore.md`.
    pub fn restore(open: Open<'_>, archive: &Path, invitation: &str) -> Result<Opened, Failure> {
        if open.network.is_none() {
            return Err(ServiceError::NetworkRequired("restore").into());
        }
        Self::start(
            open,
            Install::Restore {
                archive: archive.to_path_buf(),
                invitation: invitation.into(),
            },
        )
    }
    /// Writes a signed backup archive of this database to `target`; see
    /// `restore`. It returns the archive's inventory as JSON.
    pub async fn backup(&self, target: &Path) -> Result<String, Failure> {
        let session = self.session();
        let call = json!({
            "version": 1,
            "scope": serde_json::from_str::<Value>(&self.scope)?,
            "request": {"type": "backup", "path": target.to_str().ok_or("the backup path is not UTF-8")?},
        });
        let reply: Value = serde_json::from_str(&session.call(call.to_string()).await?)?;
        session.close().await;
        if reply["status"] != "ok" {
            return Err(reply["error"]["message"]
                .as_str()
                .unwrap_or("backup failed")
                .to_string()
                .into());
        }
        Ok(reply["value"].to_string())
    }
    fn start(open: Open<'_>, install: Install) -> Result<Opened, Failure> {
        Self::start_confirmed(open, install, None)
    }
    fn start_confirmed(
        open: Open<'_>,
        install: Install,
        confirmation: Option<String>,
    ) -> Result<Opened, Failure> {
        let (setup, network) = Self::setup(open, install, confirmation)?;
        let (input, receiver) = mpsc::channel(32);
        let (cleanup, cleanups) = mpsc::unbounded_channel();
        let (hello, greeting) = std::sync::mpsc::sync_channel::<Greeting>(1);
        let hello = Hello::Thread(hello);
        let thread = std::thread::Builder::new()
            .name("rocky-sdk".into())
            .spawn(move || {
                let result = (|| -> Result<(), Failure> {
                    // Transports run their tasks on the workers; the
                    // database's tasks stay on this thread.
                    let runtime = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .thread_name("rocky-sdk-io")
                        .enable_all()
                        .build()?;
                    let local = tokio::task::LocalSet::new();
                    runtime
                        .block_on(local.run_until(run(setup, network, receiver, cleanups, &hello)))
                })();
                if let Err(error) = result {
                    let _ = hello.send(Err(error));
                }
            })?;
        let greeting = greeting.recv().map_err(|_| "database failed to start")?;
        Self::opened(greeting, input, cleanup, Worker::Thread(thread))
    }
    fn setup(
        open: Open<'_>,
        install: Install,
        confirmation: Option<String>,
    ) -> Result<(Setup, Option<Network>), Failure> {
        let directory = open.directory.to_path_buf();
        if let Install::Join { invitation } = &install {
            crate::enrollment::Invite::parse(invitation)?;
        }
        let setup = Setup {
            schema: Schema::parse(open.schema)?,
            secrets: open
                .secrets
                .unwrap_or_else(|| Arc::new(FileSecretStore::new(directory.join("secrets")))),
            identity: open.identity,
            directory,
            install,
            coordination: open.coordination,
            confirmation,
            #[cfg(test)]
            expose: None,
        };
        Ok((setup, open.network))
    }
    fn opened(
        greeting: Greeting,
        input: mpsc::Sender<Command>,
        cleanup: mpsc::UnboundedSender<Command>,
        worker: Worker,
    ) -> Result<Opened, Failure> {
        match greeting {
            Ok((scope, network)) => {
                let shared = Arc::new(Shared {
                    input,
                    cleanup,
                    budget: Semaphore::new(128),
                    closed: AtomicBool::new(false),
                    sessions: AtomicU64::new(1),
                });
                Ok(Opened {
                    network: network.map(|id| NetworkService::new(&shared, id)),
                    database: Arc::new(Self {
                        shared,
                        scope,
                        worker: Mutex::new(Some(worker)),
                    }),
                })
            }
            Err(error) => {
                match worker {
                    Worker::Thread(thread) => drop(thread.join()),
                    // The task ends with the error it sent.
                    #[cfg(test)]
                    Worker::Task(_) => {}
                }
                Err(error)
            }
        }
    }
    /// The domain's scope as the call contract spells it.
    pub fn scope(&self) -> String {
        self.scope.clone()
    }
    /// A session on this database. Sessions are independent: each has its
    /// own subscriptions, and closing one leaves the others open.
    pub fn session(&self) -> Session {
        Session {
            shared: self.shared.clone(),
            scope: self.scope.clone(),
            id: self.shared.sessions.fetch_add(1, Ordering::Relaxed),
            closed: Arc::new(AtomicBool::new(false)),
        }
    }
    /// Attaches a network service: enrollment, renewal and sync use it, and
    /// the creator serves its peers on it. One can be attached at a time.
    pub async fn attach(&self, network: Network) -> Result<NetworkService, Failure> {
        let id = self
            .shared
            .request(|reply| Command::Attach(network, reply))
            .await??;
        Ok(NetworkService::new(&self.shared, id))
    }
    /// Makes this device a trusted node of its domain's coordinated logs,
    /// which it ends with seals and whose terminal entries it acknowledges;
    /// `None` ends that. The log is the application's and
    /// is never closed by Rocky. A database composed with a coordination
    /// service uses that service's log.
    pub async fn coordinate(
        &self,
        log: Option<Arc<dyn rocky_core::DomainLog>>,
    ) -> Result<(), Failure> {
        self.shared
            .request(|reply| Command::Coordinate(log, reply))
            .await?;
        Ok(())
    }
    /// A SQL connection for a database driver: the writer is a secure SQL
    /// session, a reader steps snapshot cursors. See
    /// `docs/runtime/sql-driver.md`.
    pub async fn connect(&self, options: ConnectionOptions) -> Result<Connection, Failure> {
        self.shared
            .request(|reply| Command::Connect {
                options,
                shared: self.shared.clone(),
                #[cfg(feature = "qualification")]
                queued: std::time::Instant::now(),
                reply,
            })
            .await?
    }
    /// How a committed transaction with replayed writes stands here:
    /// `None` until one of its writes replayed. A local commit stays
    /// visible until replay drops it; a drop is final once a seal covers
    /// it.
    pub async fn transaction_outcome(
        &self,
        token: rocky_core::TransactionToken,
    ) -> Result<Option<rocky_core::replay::TransactionOutcome>, Failure> {
        self.shared
            .request(|reply| Command::Outcome(token, reply))
            .await?
    }
    /// Committed changes of `tables`, or of every table. Register before
    /// reading what the changes invalidate.
    pub async fn observe_tables(
        &self,
        tables: Option<Vec<String>>,
    ) -> Result<TableEvents, Failure> {
        let observer = self
            .shared
            .request(|reply| Command::Observe(tables, reply))
            .await??;
        Ok(TableEvents::new(observer))
    }
    /// Ends every session, detaches the network service, flushes and
    /// closes the file. Admitted calls finish first. Closing again does
    /// nothing.
    pub async fn close(&self) -> Result<(), Failure> {
        let mut worker = self.worker.lock().await;
        if let Some(worker) = worker.take() {
            self.shared.closed.store(true, Ordering::SeqCst);
            let result = self.shared.request(Command::Close).await;
            worker.join().await?;
            if let Ok(result) = result {
                result.map_err(|message| -> Failure { message.into() })?;
            }
        }
        Ok(())
    }
}

/// A database a simulation serves on its own thread, and its node.
#[cfg(test)]
pub(crate) struct Hosted {
    pub(crate) opened: Opened,
    /// Upgrade only for a check; a held node outlives a crash.
    pub(crate) node: std::sync::Weak<Node>,
}
#[cfg(test)]
impl Database {
    /// Serves the database on a `LocalSet` of the calling task's thread
    /// instead of its own thread, so a paused clock and one thread drive
    /// every node of a simulation. Call it inside a `LocalSet`.
    pub(crate) async fn host(open: Open<'_>, install: Install) -> Result<Hosted, Failure> {
        let (mut setup, network) = Self::setup(open, install, None)?;
        let (expose, exposed) = std::sync::mpsc::channel();
        setup.expose = Some(expose);
        let (input, receiver) = mpsc::channel(32);
        let (cleanup, cleanups) = mpsc::unbounded_channel();
        let (hello, greeting) = oneshot::channel();
        let hello = Hello::Task(std::sync::Mutex::new(Some(hello)));
        let task = crate::reactor::spawn_local("host", async move {
            let local = tokio::task::LocalSet::new();
            let result = local
                .run_until(run(setup, network, receiver, cleanups, &hello))
                .await;
            if let Err(error) = result {
                let _ = hello.send(Err(error));
            }
        });
        let greeting = greeting
            .await
            .unwrap_or_else(|_| Err("database failed to start".into()));
        let opened = Self::opened(greeting, input, cleanup, Worker::Task(task))?;
        let node = exposed
            .try_recv()
            .map_err(|_| "the database exposed no node")?;
        Ok(Hosted { opened, node })
    }
    /// Ends a hosted database at once: its tasks are dropped mid-step, as
    /// a process death would stop them; nothing flushes or closes first.
    pub(crate) async fn crash(&self) {
        self.shared.closed.store(true, Ordering::SeqCst);
        if let Some(Worker::Task(task)) = self.worker.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

/// One SQL connection of a database. Statements are numbered by the
/// caller's handles; each keeps the undelivered rest of its result.
pub struct Connection {
    shared: Arc<Shared>,
    id: u64,
    statements: AtomicU64,
    closed: AtomicBool,
}
impl Connection {
    #[cfg(feature = "qualification")]
    pub fn measurement_id(&self) -> u64 {
        self.id
    }
    /// A number for a new statement handle of this connection.
    pub fn statement(&self) -> u64 {
        self.statements.fetch_add(1, Ordering::Relaxed)
    }
    async fn call(&self, call: connection::Call) -> Result<connection::Reply, SqlFailure> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(connection::failure(
                connection::code::MISUSE,
                "the connection is closed",
            ));
        }
        let connection = self.id;
        self.shared
            .request(|reply| Command::Sql {
                connection,
                call,
                #[cfg(feature = "qualification")]
                queued: std::time::Instant::now(),
                reply,
            })
            .await
            .map_err(|error| connection::failure(connection::code::MISUSE, error.to_string()))?
    }
    /// Runs `sql` as statement `statement` and returns its first page; a
    /// result `statement` still held is dropped first.
    pub async fn execute(
        &self,
        statement: u64,
        sql: String,
        params: Vec<rocky_core::SqlValue>,
    ) -> Result<Page, SqlFailure> {
        match self
            .call(connection::Call::Execute {
                statement,
                sql,
                params,
            })
            .await?
        {
            connection::Reply::Page(page) => Ok(page),
            _ => Err(connection::failure(connection::code::MISUSE, "no page")),
        }
    }
    /// The next page of `statement`'s result.
    pub async fn next(&self, statement: u64) -> Result<Page, SqlFailure> {
        match self.call(connection::Call::Next { statement }).await? {
            connection::Reply::Page(page) => Ok(page),
            _ => Err(connection::failure(connection::code::MISUSE, "no page")),
        }
    }
    pub(crate) fn discard(&self, statement: u64) {
        let _ = self.shared.cleanup.send(Command::Sql {
            connection: self.id,
            call: connection::Call::Finish { statement },
            #[cfg(feature = "qualification")]
            queued: std::time::Instant::now(),
            reply: oneshot::channel().0,
        });
    }
    /// Drops the rest of `statement`'s result.
    pub async fn finish(&self, statement: u64) -> Result<(), SqlFailure> {
        self.call(connection::Call::Finish { statement })
            .await
            .map(drop)
    }
    /// The transaction this connection's last `COMMIT` published, as
    /// `Database::transaction_outcome` and table changes name it; `None`
    /// when it published nothing.
    pub async fn committed(&self) -> Result<Option<rocky_core::TransactionToken>, SqlFailure> {
        match self.call(connection::Call::Committed).await? {
            connection::Reply::Token(token) => Ok(token),
            _ => Err(connection::failure(connection::code::MISUSE, "no token")),
        }
    }
    pub async fn in_transaction(&self) -> Result<bool, SqlFailure> {
        match self.call(connection::Call::InTransaction).await? {
            connection::Reply::Flag(flag) => Ok(flag),
            _ => Err(connection::failure(connection::code::MISUSE, "no state")),
        }
    }
    /// Closes the connection: an open transaction rolls back, its cursors
    /// end. Closing again does nothing.
    pub async fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let _ = self
                .shared
                .request(|reply| Command::Disconnect {
                    connection: self.id,
                    #[cfg(feature = "qualification")]
                    queued: std::time::Instant::now(),
                    reply,
                })
                .await;
        }
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let _ = self.shared.cleanup.send(Command::Disconnect {
                connection: self.id,
                #[cfg(feature = "qualification")]
                queued: std::time::Instant::now(),
                reply: oneshot::channel().0,
            });
        }
    }
}

/// One caller's view of a shared database: the JSON calls of the native ABI.
pub struct Session {
    shared: Arc<Shared>,
    scope: String,
    id: u64,
    closed: Arc<AtomicBool>,
}
impl Session {
    pub(crate) async fn request(&self, request: Value) -> Result<Value, Failure> {
        let call = json!({"version":1,"scope":serde_json::from_str::<Value>(&self.scope)?,"request":request});
        let response: Value = serde_json::from_str(&self.call(call.to_string()).await?)?;
        if response["status"] != "ok" {
            return Err(Box::new(crate::CallFailure {
                code: response["error"]["code"]
                    .as_str()
                    .ok_or("missing failure code")?
                    .into(),
                retryable: response["error"]["retryable"]
                    .as_bool()
                    .ok_or("missing retryability")?,
                detail: response["error"]["message"]
                    .as_str()
                    .ok_or("missing failure detail")?
                    .into(),
            }));
        }
        Ok(response["value"].clone())
    }
    pub async fn network(&self) -> Result<crate::NetworkStatus, Failure> {
        Ok(serde_json::from_value(
            self.request(json!({"type":"network"})).await?,
        )?)
    }
    pub async fn peers(&self) -> Result<Vec<crate::Peer>, Failure> {
        let response = self.request(json!({"type":"peers"})).await?;
        Ok(serde_json::from_value(response["peers"].clone())?)
    }
    pub async fn discovery(&self) -> Result<crate::DiscoveryStatus, Failure> {
        Ok(self.network().await?.discovery)
    }
    /// Observes owned runtime facts without dialing or starting a worker.
    pub async fn status(&self) -> Result<crate::DatabaseStatus, Failure> {
        Ok(serde_json::from_value(
            self.request(json!({"type":"status"})).await?,
        )?)
    }
    /// Waits for a changed snapshot; closing this session ends only its waits.
    pub async fn status_after(&self, token: String) -> Result<crate::DatabaseStatus, Failure> {
        Ok(serde_json::from_value(
            self.request(json!({"type":"status_next","after":token}))
                .await?,
        )?)
    }
    /// Reconciles selected peers and preserves each attempt's outcome.
    pub async fn sync_once(&self) -> Result<crate::ReconciliationReport, Failure> {
        Ok(serde_json::from_value(
            self.request(json!({"type":"sync"})).await?,
        )?)
    }
    pub async fn set_networking_enabled(&self, enabled: bool) -> Result<(), Failure> {
        self.request(json!({"type":"networking_control","enabled":enabled}))
            .await
            .map(drop)
    }
    pub async fn set_automatic_sync(&self, enabled: bool) -> Result<(), Failure> {
        self.request(json!({"type":"sync_start","enabled":enabled}))
            .await
            .map(drop)
    }
    async fn tips<T: serde::de::DeserializeOwned>(&self, mut request: Value) -> Result<T, Failure> {
        request["type"] = json!("tips");
        Ok(serde_json::from_value(self.request(request).await?)?)
    }
    /// The followed bookmark and tip; see `docs/runtime/tips-and-bookmarks.md`.
    pub async fn tip_status(&self) -> Result<crate::TipStatus, Failure> {
        self.tips(json!({"action":"status"})).await
    }
    /// The domain's graph and what each node follows or keeps.
    pub async fn inspect_tips(&self) -> Result<crate::TipInspection, Failure> {
        self.tips(json!({"action":"inspect"})).await
    }
    /// Seals the followed tip: `continue` moves its bookmark to the
    /// successor, `close` leaves the bookmark read-only.
    pub async fn seal(&self, close: bool) -> Result<crate::TipStatus, Failure> {
        self.tips(json!({"action":"seal","close":close})).await
    }
    /// The owner recovers the followed tip when no ordinary seal can end its
    /// coordinated log: one `continue` seal replacing the log's exact head.
    pub async fn recover(&self) -> Result<crate::TipStatus, Failure> {
        self.tips(json!({"action":"recover"})).await
    }
    /// The owner signs the minimum of trusted acknowledgments that makes a
    /// seal on the genesis line final.
    pub async fn set_genesis_minimum(
        &self,
        minimum_in_sync: u32,
    ) -> Result<crate::TipStatus, Failure> {
        self.tips(json!({"action":"genesis_minimum","minimum_in_sync":minimum_in_sync}))
            .await
    }
    /// Finalizes ready seals of the followed path and compacts at the newest
    /// one that is final or has `keep` seals after it.
    pub async fn compact(&self, keep: usize) -> Result<crate::TipCompaction, Failure> {
        self.tips(json!({"action":"compact","keep":keep})).await
    }
    /// Where this device's compaction of the followed path stands.
    pub async fn compaction(&self) -> Result<crate::TipCompaction, Failure> {
        self.tips(json!({"action":"compaction"})).await
    }
    /// Opens a tip on `seal` and returns it.
    pub async fn open_tip(&self, seal: &str, minimum_in_sync: u32) -> Result<String, Failure> {
        let opened: Value = self
            .tips(json!({"action":"open","seal":seal,"minimum_in_sync":minimum_in_sync}))
            .await?;
        Ok(opened["tip"].as_str().ok_or("missing opened tip")?.into())
    }
    /// Creates `name` on `tip`, by default the followed tip.
    pub async fn create_bookmark(
        &self,
        name: &str,
        tip: Option<&str>,
    ) -> Result<crate::TipStatus, Failure> {
        self.tips(json!({"action":"create","name":name,"tip":tip}))
            .await
    }
    pub async fn move_bookmark(&self, name: &str, tip: &str) -> Result<crate::TipStatus, Failure> {
        self.tips(json!({"action":"move","name":name,"tip":tip}))
            .await
    }
    pub async fn delete_bookmark(&self, name: &str) -> Result<crate::TipStatus, Failure> {
        self.tips(json!({"action":"delete","name":name})).await
    }
    /// Follows `name`: writes go to its tip from now on.
    pub async fn follow(&self, name: &str) -> Result<crate::TipStatus, Failure> {
        self.tips(json!({"action":"follow","name":name})).await
    }
    /// The owner grants `identity` trust for this domain: it opens tips and
    /// moves bookmarks backward or sideways.
    pub async fn trust(&self, identity: &str) -> Result<crate::TrustGrant, Failure> {
        self.tips(json!({"action":"trust","identity":identity}))
            .await
    }
    /// Installs a trusted grant the owner issued to this device's identity.
    pub async fn install_trust(&self, grant: &str) -> Result<crate::TipStatus, Failure> {
        self.tips(json!({"action":"install_trust","grant":grant}))
            .await
    }
    /// Drops the local frames of a tip this device no longer follows.
    pub async fn drop_tip(&self, tip: &str) -> Result<crate::TipStatus, Failure> {
        self.tips(json!({"action":"drop","tip":tip})).await
    }

    pub async fn call(&self, request: String) -> Result<String, Failure> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(ServiceError::Closed("session").into());
        }
        if self.shared.closed.load(Ordering::SeqCst) {
            return Err(ServiceError::Closed("database").into());
        }
        if request.len() > rocky_runtime::MAX_FRAME_BYTES {
            return Err("call frame quota".into());
        }
        let _permit = self
            .shared
            .budget
            .try_acquire()
            .map_err(|_| "pending call quota")?;
        let session = self.id;
        let bytes = request.into_bytes();
        let reply = self
            .shared
            .request(|reply| Command::Call {
                session,
                bytes,
                ending: self.closed.clone(),
                reply,
            })
            .await?;
        Ok(String::from_utf8(reply)?)
    }
    /// Ends this session: its waits stop and its subscriptions are
    /// released. The database and its other sessions stay open.
    pub async fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let _ = self
                .shared
                .request(|reply| Command::End(self.id, reply))
                .await;
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let _ = self
                .shared
                .cleanup
                .send(Command::End(self.id, oneshot::channel().0));
        }
    }
}

/// The network service attached to a database. Dropping the handle leaves
/// it attached until the database closes.
pub struct NetworkService {
    shared: Arc<Shared>,
    id: u64,
    closed: AtomicBool,
}
impl NetworkService {
    fn new(shared: &Arc<Shared>, id: u64) -> Self {
        Self {
            shared: shared.clone(),
            id,
            closed: AtomicBool::new(false),
        }
    }
    /// Stops serving and syncing. Admitted work has a few seconds to
    /// finish; what remains is cancelled and is safe to repeat. A transport
    /// the service started is closed, a borrowed one is not. The database
    /// stays open. Closing again does nothing.
    pub async fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let _ = self
                .shared
                .request(|reply| Command::Detach(self.id, reply))
                .await;
        }
    }
}

type Link = (Arc<dyn Transport>, bool);

/// The installation of the data directory, created, joined or loaded, and
/// the started transport of `network`.
async fn identity(
    path: &Path,
    setup: &Setup,
    network: Option<Network>,
) -> Result<(Settings, Option<Link>), Failure> {
    let Setup {
        directory,
        schema,
        secrets,
        install,
        ..
    } = setup;
    let exists = path.exists();
    // A restore interrupted after it enrolled continues.
    let resuming = matches!(install, Install::Restore { .. })
        && directory.join(crate::backup::MARKER).exists();
    if exists && !matches!(install, Install::Installed) && !resuming {
        return Err("a domain exists in this directory: open it instead".into());
    }
    if !exists && matches!(install, Install::Installed) {
        return Err("no domain in this directory: create or join one".into());
    }
    if exists && !resuming && !directory.join("rocky.sqlite").exists() {
        return Err("existing identity has no runtime database; recovery is required".into());
    }
    match install {
        Install::Create { ttl } => {
            let settings = Settings::create(schema, secrets, *ttl, setup.identity.clone())?;
            let vault = settings.vault(secrets);
            let started = async {
                let Some(network) = network else {
                    return Ok(None);
                };
                let key = Settings::transport_key(&vault)?;
                Ok::<_, Failure>(Some(network.start(true, key).await?))
            }
            .await;
            match started {
                Ok(link) => Ok((settings, link)),
                Err(error) => {
                    let _ = vault.forget(settings.roles());
                    Err(error)
                }
            }
        }
        Install::Join { invitation } => {
            let network = network.ok_or(ServiceError::NetworkRequired("join"))?;
            let joining =
                Settings::prepare_join(path, invitation, secrets, setup.identity.clone())?;
            let key = Settings::transport_key(&joining.vault)?;
            let (transport, owned) = network.start(false, key).await?;
            match joining.enroll(path, schema, &*transport).await {
                Ok(settings) => Ok((settings, Some((transport, owned)))),
                Err(error) => {
                    if owned {
                        transport.close().await;
                    }
                    Err(error)
                }
            }
        }
        Install::Identity { contact } => {
            let network =
                network.ok_or(ServiceError::NetworkRequired("enroll an identity's node"))?;
            let provider = setup
                .identity
                .clone()
                .ok_or("another node of an identity needs that identity's provider")?;
            let prepared = Settings::prepare_identity(path, secrets, &provider, contact)?;
            let key = Settings::transport_key(&prepared.1)?;
            let (transport, owned) = network.start(false, key).await?;
            match Settings::enroll_identity(path, prepared, provider, contact, &*transport).await {
                Ok(settings) => Ok((settings, Some((transport, owned)))),
                Err(error) => {
                    if owned {
                        transport.close().await;
                    }
                    Err(error)
                }
            }
        }
        Install::Supplied(supplied) => {
            let settings =
                Settings::install(path, schema, secrets, supplied, setup.identity.clone())?;
            let Some(network) = network else {
                return Ok((settings, None));
            };
            let key = Settings::transport_key(&settings.vault(secrets))?;
            Ok((settings, Some(network.start(false, key).await?)))
        }
        Install::Restore {
            archive,
            invitation,
        } => {
            let network = network.ok_or(ServiceError::NetworkRequired("restore"))?;
            restore(
                path, directory, secrets, schema, archive, invitation, network,
            )
            .await
        }
        Install::Installed => {
            let mut settings = Settings::load(path)?;
            settings.provider = setup.identity.clone();
            if settings.logged_out {
                return Err("this device logged out; join the domain again".into());
            }
            let vault = settings.vault(secrets);
            let link = match network {
                Some(network) => {
                    let key = Settings::transport_key(&vault)?;
                    Some(network.start(settings.issuer(), key).await?)
                }
                None => None,
            };
            if settings.application(schema)? == crate::DeclaredSchema::Current
                && settings.schema != *schema
            {
                settings.schema = schema.clone();
                settings.save(path)?;
            }
            Ok((settings, link))
        }
    }
}

/// Readies an opened replica for this identity: its readable tables,
/// group keys and the node credential.
pub(crate) async fn attach(
    replica: &EncryptedReplica<rocky_core::TypedRows>,
    settings: &mut Settings,
    vault: &crate::secrets::Vault,
    domain: &crate::domain::Domain,
    path: &Path,
) -> Result<(), Failure> {
    replica
        .install_readable_tables(domain.logical().clone(), domain.scope, domain.readers())
        .await?;
    // A settings file restored on its own may have lost groups the
    // replica holds; the vault still keeps their secrets.
    if settings.recover_groups(vault, domain, &replica.retained_partitions().await?)? {
        settings.save(path)?;
    }
    // Every readable member's key derives from its group secret,
    // including a table that joined the group in a later generation.
    let granted = settings.granted(domain);
    for partition in settings.partitions(domain)? {
        for member in &partition.members {
            if granted.contains(&member.scope) {
                replica
                    .register_partition(member.scope, member.tuple.clone())
                    .await?;
            }
            // Newest first: earlier epochs then join its history.
            if settings.reads_partition(member) {
                for epoch in partition.record.epochs.iter().rev() {
                    replica
                        .install_key_epoch(partition.key(vault, member, *epoch)?)
                        .await?;
                }
            }
        }
    }
    // On a partial replica, a table that joined a group in a later
    // generation is held wherever its group partition is.
    if replica.role().await?.role == rocky_secure::ReplicaRole::Partial {
        for partition in settings.partitions(domain)? {
            let mut held = false;
            let mut unrecorded = Vec::new();
            for member in &partition.members {
                match replica.subscription(member.scope).await? {
                    Some(rocky_secure::Holding::Held) => held = true,
                    None if settings.reads_partition(member) => unrecorded.push(member.scope),
                    _ => {}
                }
            }
            for scope in unrecorded.into_iter().filter(|_| held) {
                replica.subscribe(scope).await?;
            }
        }
    }
    replica
        .register_credential_signer(rocky_credentials::PrivateKey::from_bytes(
            &vault.get("node")?,
        ))
        .await?;
    Ok(())
}

/// Gives every granted scope without one the default retention policy.
pub(crate) async fn retain(
    replica: &EncryptedReplica<rocky_core::TypedRows>,
    settings: &Settings,
    domain: &crate::domain::Domain,
) -> Result<(), Failure> {
    for scope in settings.granted(domain) {
        if replica.retention_policy(scope).await?.is_none() {
            replica
                .set_retention_policy(
                    scope,
                    rocky_secure::RetentionPolicy {
                        copies: 1,
                        window: 256,
                        ..Default::default()
                    },
                )
                .await?;
        }
    }
    Ok(())
}

/// Rows one statement inserts into a replayed table: its intent carries
/// them as bound values, and a partition's intent holds at most
/// `MAX_INTENT_STATEMENTS` statements.
const REPLAYED_INSERT_ROWS: usize = 1024;

/// Inserts a row of `table` for each row of `select`, with the next id of
/// its partition, inside the open transaction.
pub(crate) async fn insert_rows(
    sql: &rocky_secure::SecureSql<rocky_core::TypedRows>,
    schema: &rocky_core::LogicalSchema,
    table: &str,
    select: &str,
) -> Result<(), rocky_secure::Error> {
    let refused = |reason: String| rocky_secure::Error::Incompatible(reason);
    let logical = schema
        .table(table)
        .ok_or_else(|| refused(format!("{table} is not a table")))?;
    let rows = sql.run(select, Vec::new()).await?;
    let partition = logical
        .partition_by
        .iter()
        .map(|name| {
            rows.columns
                .iter()
                .position(|column| column.eq_ignore_ascii_case(name))
                .ok_or_else(|| {
                    refused(format!(
                        "the rows for {table} lack its partition column {name}"
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let quoted = |name: &str| format!("\"{}\"", name.replace('"', "\"\""));
    let width = rows.columns.len() + 1;
    let row = format!("({})", vec!["?"; width].join(","));
    let insert = |count: usize| {
        format!(
            "INSERT INTO {}({},\"id\") VALUES{}",
            quoted(table),
            rows.columns
                .iter()
                .map(|column| quoted(column))
                .collect::<Vec<_>>()
                .join(","),
            vec![row.as_str(); count].join(",")
        )
    };
    // Mergeable tables keep one statement per row.
    let batch = if logical.class == rocky_core::TableClass::Replayed {
        REPLAYED_INSERT_ROWS.min(32_766 / width).max(1)
    } else {
        1
    };
    let mut values = Vec::new();
    let mut pending = 0;
    let total = rows.rows.len();
    for (index, row) in rows.rows.into_iter().enumerate() {
        let id = if partition.is_empty() {
            sql.next_id(table).await?
        } else {
            let values: Vec<_> = partition.iter().map(|index| row[*index].clone()).collect();
            sql.next_id_partition(table, &values).await?
        };
        values.extend(row);
        values.push(rocky_core::SqlValue::Integer(id.integer()));
        pending += 1;
        if pending == batch || index + 1 == total {
            sql.run(&insert(pending), std::mem::take(&mut values))
                .await?;
            pending = 0;
        }
    }
    Ok(())
}
/// Verifies the archive, enrolls a fresh identity with the invitation's
/// issuer and puts the archive's files in place. The marker, written
/// before enrolling, names the predecessor whose file is rebound at open.
async fn restore(
    path: &Path,
    directory: &Path,
    secrets: &Arc<dyn SecretStore>,
    schema: &Schema,
    archive: &Path,
    invitation: &str,
    network: Network,
) -> Result<(Settings, Option<Link>), Failure> {
    use crate::backup::{MARKER, Marker};
    let staging = directory.join("restore");
    let opened = crate::backup::open(archive, &staging)?;
    let marker = directory.join(MARKER);
    if marker.exists() {
        let saved: Marker = serde_json::from_slice(&std::fs::read(&marker)?)?;
        if saved.archive != opened.id {
            return Err("another restore is unfinished in this directory".into());
        }
    } else {
        if Settings::invitation_publisher(invitation)? != opened.inventory.publisher {
            return Err("the invitation is for another domain than the backup".into());
        }
        crate::secrets::write_private(
            &marker,
            &serde_json::to_vec(&Marker {
                predecessor: opened.inventory.node,
                archive: opened.id.clone(),
            })?,
        )?;
    }
    let (settings, link) = if path.exists() {
        let settings = Settings::load(path)?;
        let vault = settings.vault(secrets);
        let key = Settings::transport_key(&vault)?;
        let link = network.start(settings.issuer(), key).await?;
        (settings, link)
    } else {
        // A restored node's identity is made in the secret store.
        let joining = Settings::prepare_join(path, invitation, secrets, None)?;
        let key = Settings::transport_key(&joining.vault)?;
        let (transport, owned) = network.start(false, key).await?;
        match joining.enroll(path, schema, &*transport).await {
            Ok(mut settings) => {
                let node = PrivateKey::from_bytes(&settings.vault(secrets).get("node")?);
                settings.learn_contacts(
                    &opened.identity,
                    &[node.public_key(), opened.inventory.node],
                );
                settings.save(path)?;
                (settings, (transport, owned))
            }
            Err(error) => {
                if owned {
                    transport.close().await;
                }
                return Err(error);
            }
        }
    };
    if (settings.mesh, settings.domain) != (opened.identity.mesh, opened.identity.domain) {
        return Err("the enrolled domain differs from the backup's".into());
    }
    for (name, staged) in &opened.files {
        if name != "identity.json" {
            std::fs::rename(staged, directory.join(name))?;
        }
    }
    std::fs::remove_dir_all(&staging)?;
    Ok((settings, Some(link)))
}

async fn run(
    setup: Setup,
    network: Option<Network>,
    input: mpsc::Receiver<Command>,
    cleanups: mpsc::UnboundedReceiver<Command>,
    hello: &Hello,
) -> Result<(), Failure> {
    let serving = run_inner(setup, network, input, cleanups, hello);
    #[cfg(feature = "qualification")]
    let serving = crate::reactor::scope(crate::ReactorMeasurements::default(), serving);
    serving.await
}

async fn run_inner(
    setup: Setup,
    network: Option<Network>,
    mut input: mpsc::Receiver<Command>,
    mut cleanups: mpsc::UnboundedReceiver<Command>,
    hello: &Hello,
) -> Result<(), Failure> {
    let directory = setup.directory.clone();
    if matches!(setup.install, Install::Installed) && directory.join("identity.json").exists() {
        Settings::load(&directory.join("identity.json"))?;
    }
    rocky_secure::check_replica_format(&directory.join("rocky.sqlite")).await?;
    if matches!(setup.install, Install::Installed) {
        if !directory.join("identity.json").exists() {
            return Err(if directory.join("identity.join.json").exists() {
                "a join in this directory is unfinished: join again with its or a newer invitation"
            } else {
                "no domain in this directory: create or join one"
            }
            .into());
        }
        Settings::load(&directory.join("identity.json"))?;
    }
    std::fs::create_dir_all(&directory)?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(directory.join("sdk.lock"))?;
    lock.try_lock()
        .map_err(|_| "data directory is already in use")?;
    rocky_secure::check_replica_format(&directory.join("rocky.sqlite")).await?;
    let path = directory.join("identity.json");
    // Record checkpoint-first intent before enrollment can persist the identity.
    if matches!(
        setup.install,
        Install::Join { .. } | Install::Identity { .. }
    ) && !path.exists()
    {
        rocky_credentials::write_private(&directory.join("bootstrap.json"), b"true")?;
    }
    // A removal is confirmed before the network starts or anything changes.
    if matches!(setup.install, Install::Installed) {
        let settings = Settings::load(&path)?;
        if rocky_secure::installed_tip_schema(
            &directory.join("rocky.sqlite"),
            settings.domain()?.scope,
            settings.publisher,
            None,
        )
        .await?
        .is_some()
        {
            crate::rollout::confirm(
                &settings,
                &path,
                &setup.schema,
                setup.confirmation.as_deref(),
            )
            .await?;
        }
    }
    let (mut settings, link) = identity(&path, &setup, network).await?;
    // Envelopes shared after enrollment wait at the inviter: the intent
    // stays until one exchange with it.
    if let (Install::Join { .. }, Some(inviter)) = (&setup.install, settings.issuers.first()) {
        rocky_credentials::write_private(
            &directory.join("bootstrap.json"),
            &serde_json::to_vec(&serde_json::json!({"intent": true, "inviter": inviter.to_hex()}))?,
        )?;
    }
    let vault = settings.vault(&setup.secrets);
    let opened = async {
        // A revocation interrupted after its intent was saved completes
        // here; the replica adopts its revocations and keys as it opens.
        if settings.rotate(&vault)?.is_some() {
            settings.save(&path)?;
        }
        // Expired credentials cannot open the replica: renew them first.
        if settings.expires() <= now()? {
            let transport = link.as_ref().map(|(transport, _)| &**transport);
            if transport.is_none() && !settings.issuer() {
                return Err(ServiceError::CredentialsExpired.into());
            }
            let renewed = settings
                .request_renewal(&vault, transport, false, None)
                .await?;
            if path.exists() {
                // Rows of a newly revoked author arrive by checkpoint.
                if settings.lacks(&renewed.revocations)? {
                    rocky_credentials::write_private(&directory.join("bootstrap.json"), b"true")?;
                }
                settings.adopt(&path, &vault, &renewed)?;
            } else {
                settings.learn_revocations(&renewed.revocations)?;
                settings.credentials = renewed.chain;
            }
        }
        // The commit may also have advanced the bookmark past the pending
        // tip on the same schema.
        if let Some(pending) = settings.pending.clone()
            && let Some(installed) = rocky_secure::installed_tip_schema(
                &directory.join("rocky.sqlite"),
                settings.domain()?.scope,
                settings.publisher,
                Some(pending.tip),
            )
            .await?
            && (installed.tip == pending.tip
                || (installed.continues && installed.manifest == pending.manifest))
        {
            let manifest = installed.manifest;
            if manifest != pending.manifest {
                return Err("pending schema differs from committed workspace".into());
            }
            let record = crate::tip_schemas::Record::parse(&installed.record)?;
            let domain = record.domain(&settings, manifest)?;
            settings.schema = record.schema;
            settings.generation = record.generation;
            settings.prepare_schema(&vault, &domain)?;
            settings.pending = None;
            settings.save(&path)?;
        }
        let domain = settings.domain()?;
        // A restored file is rebound to this device's identity first.
        let marker = directory.join(crate::backup::MARKER);
        let replica = if marker.exists() {
            let restored: crate::backup::Marker = serde_json::from_slice(&std::fs::read(&marker)?)?;
            let replica = EncryptedReplica::open_restored(
                directory.join("rocky.sqlite"),
                domain.app.clone(),
                settings.config(&vault, &domain)?,
                restored.predecessor,
            )
            .await?;
            std::fs::remove_file(&marker)?;
            replica
        } else if let Some(bootstrap) = &settings.bootstrap {
            bootstrap.verify(&settings)?;
            EncryptedReplica::open_following(
                directory.join("rocky.sqlite"),
                domain.app.clone(),
                settings.config(&vault, &domain)?,
                bootstrap.graph.clone(),
                bootstrap.followed.clone(),
            )
            .await?
        } else {
            EncryptedReplica::open(
                directory.join("rocky.sqlite"),
                domain.app.clone(),
                settings.config(&vault, &domain)?,
            )
            .await?
        };
        attach(&replica, &mut settings, &vault, &domain, &path).await?;
        replica
            .record_current_schema(
                crate::tip_schemas::Record::new(&settings.schema, settings.generation).bytes()?,
            )
            .await?;
        settings.bootstrap = None;
        retain(&replica, &settings, &domain).await?;
        #[cfg_attr(not(feature = "iroh"), allow(unused_mut))]
        let mut service: Option<crate::owner::Service> = None;
        let log: Option<Arc<dyn rocky_core::DomainLog>> = match &setup.coordination {
            None => None,
            Some(Coordination::Composed(log)) => Some(log.clone()),
            #[cfg(feature = "iroh")]
            Some(Coordination::Service(bundle)) => {
                let transport = link
                    .as_ref()
                    .map(|(transport, _)| transport.clone())
                    .ok_or("a coordination service needs the database's network")?;
                let key = rocky_credentials::PrivateKey::from_bytes(&vault.get("node")?);
                let client = Arc::new(rocky_coordinator::service::NetworkCoordinator::connect(
                    bundle, key, transport,
                )?);
                let composed =
                    crate::owner::Service::new((**bundle).clone(), directory.to_path_buf())
                        .with_client(client.clone());
                composed.certify(&settings.credentials);
                service = Some(composed);
                Some(client)
            }
        };
        settings.save(&path)?;
        Ok::<_, Failure>((domain, replica, service, log))
    }
    .await;
    let (domain, replica, service, log) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            if let Some((transport, true)) = &link {
                transport.close().await;
            }
            if matches!(setup.install, Install::Create { .. }) {
                let _ = vault.forget(settings.roles());
            }
            return Err(error);
        }
    };
    let scope = serde_json::to_string(&domain.scope)?;
    let node = Arc::new(
        Node::new(replica.clone(), domain, vault, settings, path.clone())
            .with_service(service)
            .with_declared(setup.schema.clone()),
    );
    #[cfg(test)]
    if let Some(expose) = &setup.expose {
        let _ = expose.send(Arc::downgrade(&node));
    }
    node.coordinate(log);
    if let Err(error) = async {
        node.restore_line_signers().await?;
        node.complete_revocation().await?;
        node.refresh_importing().await?;
        node.try_ensure_tip_node().await;
        if matches!(setup.install, Install::Installed) {
            node.publish_schema_at_open(setup.confirmation.as_deref())
                .await?;
        }
        Ok::<_, Failure>(())
    }
    .await
    {
        if let Some((transport, true)) = &link {
            transport.close().await;
        }
        return Err(error);
    }
    // Migration commits precede the revision subscription. Drain their work
    // before enrollment or the first reconciliation can trigger it instead.
    replica.flush().await?;
    replica.maintain().await;
    replica.finalize_path(node.domain().scope).await?;
    let network = match link {
        Some((transport, owned)) => Some(node.link(transport, owned).await),
        None => None,
    };
    hello
        .send(Ok((scope, network)))
        .map_err(|_| "database opener abandoned")?;
    if directory.join("bootstrap.json").exists() && network.is_some() {
        let joining = node.clone();
        crate::reactor::spawn_local("bootstrap", async move {
            // Failure leaves the durable bootstrap intent for the next sync/open.
            let _ = joining.initial_sync().await;
        });
    }
    let budget = Arc::new(Semaphore::new(128));
    let connections = Arc::new(connection::Registry::default());
    let mut tasks = tokio::task::JoinSet::new();
    let mut shutdown = None;
    let settling = crate::reactor::spawn_local("settle_commits", settle_commits(replica.clone()));
    let recovering = crate::reactor::spawn_local("recovery", node.clone().drive_recovery());
    loop {
        let command = tokio::select! {
            command = input.recv() => match command { Some(command) => command, None => break },
            Some(command) = cleanups.recv() => command,
        };
        let node = node.clone();
        match command {
            #[cfg(all(test, feature = "qualification"))]
            Command::BlockReactor(entered, resume) => {
                crate::reactor::spawn_in(&mut tasks, "test_blocking", async move {
                    let _ = entered.send(());
                    let _ = resume.lock().unwrap().recv();
                });
            }
            Command::Call {
                session,
                bytes,
                ending,
                mut reply,
            } => {
                let Ok(permit) = budget.clone().try_acquire_owned() else {
                    let _ = reply.send(json!({
                        "version": 1, "status": "error",
                        "error": {"code": "quota", "retryable": true, "message": "active call quota"},
                    }).to_string().into_bytes());
                    continue;
                };
                // Only a subscription's wait stops when its caller goes
                // away; admitted mutations run to completion.
                let waits = serde_json::from_slice::<Value>(&bytes).is_ok_and(|call| {
                    ["next", "status_next", "activity_next"]
                        .contains(&call["request"]["type"].as_str().unwrap_or(""))
                });
                let client = if waits && ending.load(Ordering::SeqCst) {
                    Err(ServiceError::Closed("session").into())
                } else {
                    node.client(session)
                };
                crate::reactor::spawn_in(&mut tasks, "call", async move {
                    let _permit = permit;
                    let response = if waits {
                        tokio::select! {
                            response = dispatch(&bytes, client, &node) => response,
                            () = reply.closed() => return,
                        }
                    } else {
                        dispatch(&bytes, client, &node).await
                    };
                    if ending.load(Ordering::SeqCst) {
                        node.end_sessions(Some(session));
                    }
                    let _ = reply.send(response);
                });
            }
            Command::End(session, reply) => {
                node.end_sessions(Some(session));
                let _ = reply.send(());
            }
            Command::Attach(network, reply) => {
                crate::reactor::spawn_in(&mut tasks, "attach", async move {
                    let _ = reply.send(node.attach(network).await);
                });
            }
            Command::Detach(id, reply) => {
                crate::reactor::spawn_in(&mut tasks, "detach", async move {
                    node.detach(Some(id)).await;
                    let _ = reply.send(());
                });
            }
            Command::Close(reply) => {
                shutdown = Some(reply);
                break;
            }
            Command::Connect {
                options,
                shared,
                #[cfg(feature = "qualification")]
                queued,
                reply,
            } => {
                let connections = connections.clone();
                crate::reactor::spawn_in(&mut tasks, "connect", async move {
                    #[cfg(feature = "qualification")]
                    let timing = crate::reactor::CallTimer::start(queued);
                    let result = connections
                        .connect(node, options)
                        .await
                        .map(|id| Connection {
                            shared,
                            id,
                            statements: AtomicU64::new(1),
                            closed: AtomicBool::new(false),
                        });
                    #[cfg(feature = "qualification")]
                    if let Ok(connection) = &result {
                        timing.finish(connection.id);
                    }
                    // The reply owns the handle, so dropping an unread reply also disconnects.
                    let _ = reply.send(result);
                });
            }
            Command::Sql {
                connection,
                call,
                #[cfg(feature = "qualification")]
                queued,
                reply,
            } => match connections.get(connection) {
                Ok(state) => {
                    crate::reactor::spawn_in(&mut tasks, "sql", async move {
                        #[cfg(feature = "qualification")]
                        let timing = crate::reactor::CallTimer::start(queued);
                        let statement = match &call {
                            connection::Call::Execute { statement, .. }
                            | connection::Call::Next { statement } => Some(*statement),
                            _ => None,
                        };
                        let serving = connection::serve(state.clone(), call);
                        #[cfg(feature = "qualification")]
                        let serving =
                            rocky_secure::with_measurement_connection(connection, serving);
                        let result = serving.await;
                        #[cfg(feature = "qualification")]
                        timing.finish(connection);
                        if reply.send(result).is_err()
                            && let Some(statement) = statement
                        {
                            let _ =
                                connection::serve(state, connection::Call::Finish { statement })
                                    .await;
                        }
                    });
                }
                Err(error) => {
                    #[cfg(feature = "qualification")]
                    crate::reactor::CallTimer::start(queued).finish(connection);
                    drop(reply.send(Err(connection::sql_failure(error))));
                }
            },
            Command::Disconnect {
                connection,
                #[cfg(feature = "qualification")]
                queued,
                reply,
            } => {
                #[cfg(feature = "qualification")]
                let timing = crate::reactor::CallTimer::start(queued);
                connections.close(Some(connection));
                #[cfg(feature = "qualification")]
                timing.finish(connection);
                let _ = reply.send(());
            }
            Command::Coordinate(log, reply) => {
                node.coordinate(log);
                let _ = reply.send(());
            }
            #[cfg(feature = "qualification")]
            Command::LockMeasurements(reply) => {
                let _ = reply.send(node.replica.lock_measurements());
            }
            #[cfg(feature = "qualification")]
            Command::ReactorMeasurements(reply) => {
                let _ = reply.send(crate::reactor::current());
            }
            Command::Observe(tables, reply) => {
                crate::reactor::spawn_in(&mut tasks, "observe", async move {
                    let tables: Option<Vec<&str>> = tables
                        .as_ref()
                        .map(|tables| tables.iter().map(String::as_str).collect());
                    let observed = node
                        .replica
                        .observe_tables(tables.as_deref())
                        .await
                        .map_err(Failure::from);
                    let _ = reply.send(observed);
                });
            }
            Command::Outcome(token, reply) => {
                crate::reactor::spawn_in(&mut tasks, "outcome", async move {
                    let outcome = node
                        .replica
                        .transaction_outcome(token.0)
                        .await
                        .map_err(Failure::from);
                    let _ = reply.send(outcome);
                });
            }
        }
        while tasks.try_join_next().is_some() {}
    }
    recovering.abort();
    let _ = recovering.await;
    node.end_sessions(None);
    // Open transactions roll back and cursors end before the file closes.
    connections.close(None);
    // Calls that use the network end within its drain bound; an attach
    // still pending is detached by the second pass.
    node.detach(None).await;
    while tasks.join_next().await.is_some() {}
    node.detach(None).await;
    let purge = *node.ended.lock().await == Some(true);
    drop(node);
    settling.abort();
    let _ = settling.await;
    // Dropping the last handle closes the file.
    let mut result = replica.flush().await.map(drop).map_err(|e| e.to_string());
    replica.optimize().await;
    drop(replica);
    if purge && result.is_ok() {
        result = purge_directory(&directory).map_err(|e| e.to_string());
    }
    if let Some(reply) = shutdown {
        let _ = reply.send(result);
    }
    Ok(())
}
/// Flushes buffered SQL commits and runs their queued maintenance after
/// they answer. The flush runs on a blocking thread and covers every
/// commit that arrived during the previous flush. A flush failure surfaces
/// at the next call that exposes data, which flushes itself. Failed background
/// flushes retain maintenance and retry with backoff.
async fn settle_commits(replica: EncryptedReplica<rocky_core::TypedRows>) {
    let mut revisions = replica.observe_revision();
    revisions.mark_changed();
    let mut retry = crate::scheduling::Retry::default();
    loop {
        let deadline = retry.deadline();
        tokio::select! {
            changed = revisions.changed() => if changed.is_err() { break },
            () = async {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            } => {},
        }
        match replica.flush().await {
            Ok(_) if replica.maintain().await => retry.reset(),
            // A concurrent commit leaves its revision pending too. The timer
            // also covers work present before this driver's subscription.
            Ok(_) => retry.soon(),
            Err(error) => {
                tracing::warn!(%error, "background flush failed; maintenance remains queued");
                retry.failed();
            }
        }
    }
}
fn purge_directory(directory: &Path) -> Result<(), Failure> {
    for name in [
        "identity.json",
        "rocky.sqlite",
        "rocky.sqlite-wal",
        "rocky.sqlite-shm",
    ] {
        match std::fs::remove_file(directory.join(name)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
    }
    match std::fs::remove_dir_all(directory.join("secrets")) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}
async fn dispatch(bytes: &[u8], client: Result<Arc<Client>, Failure>, node: &Node) -> Vec<u8> {
    let result: Result<Value, Failure> = async {
        let call: Value = serde_json::from_slice(bytes)?;
        if call["version"] != 1 || call["scope"] != serde_json::to_value(node.domain().scope)? {
            return Err("foreign scope or SDK version".into());
        }
        Box::pin(node.dispatch(&*client?, &call["request"])).await
    }
    .await;
    let response = match result {
        Ok(value) => json!({"version": 1, "status": "ok", "value": value}),
        Err(error) => json!({"version": 1, "status": "error", "error": node::error(&error)}),
    };
    response.to_string().into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "qualification")]
    #[tokio::test(flavor = "multi_thread")]
    async fn blocking_reactor_task_and_queued_sql_call_are_attributed() -> Result<(), Failure> {
        let directory = tempfile::tempdir()?;
        let schema = crate::Schema::builder("reactor_timing", 1)
            .table(
                crate::Table::replayed("items")
                    .column(crate::Column::new("title", crate::Affinity::Text)),
            )
            .build()?;
        let schema = serde_json::to_string(&schema)?;
        let database = Database::create(
            Open {
                directory: directory.path(),
                schema: &schema,
                secrets: None,
                identity: None,
                network: None,
                coordination: None,
            },
            None,
        )?
        .database;
        let connection = database
            .connect(ConnectionOptions {
                read_only: true,
                durability: connection::Durability::Buffered,
                profile: None,
                transaction_timeout: None,
                binding: None,
            })
            .await?;
        let measurements = database.reactor_measurements().await?;
        measurements.start();
        let (entered, waiting) = oneshot::channel();
        let (resume, resumed) = std::sync::mpsc::channel();
        database
            .shared
            .input
            .send(Command::BlockReactor(
                entered,
                std::sync::Mutex::new(resumed),
            ))
            .await?;
        waiting.await?;
        let queued = std::time::Instant::now();
        let (reply, result) = oneshot::channel();
        database
            .shared
            .input
            .send(Command::Sql {
                connection: connection.id,
                call: connection::Call::InTransaction,
                queued,
                reply,
            })
            .await?;
        // Deliberately block the reactor, while a real connection call is queued.
        while queued.elapsed() < std::time::Duration::from_millis(2) {
            std::hint::spin_loop();
        }
        resume.send(())?;
        assert!(matches!(result.await??, connection::Reply::Flag(false)));
        let snapshot = measurements.stop();
        assert!(snapshot.polls["test_blocking"].iter().any(|us| *us >= 2000));
        assert!(
            snapshot.calls[&connection.id]
                .iter()
                .any(|call| call.queue_us >= 2000)
        );
        connection.close().await;
        database.close().await?;
        Ok(())
    }

    #[test]
    fn unread_connection_reply_cleans_up_with_a_full_request_queue() -> Result<(), Failure> {
        let (input, _requests) = mpsc::channel(1);
        input.try_send(Command::Disconnect {
            connection: 99,
            #[cfg(feature = "qualification")]
            queued: std::time::Instant::now(),
            reply: oneshot::channel().0,
        })?;
        let (cleanup, mut cleanups) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            input,
            cleanup,
            budget: Semaphore::new(1),
            closed: AtomicBool::new(false),
            sessions: AtomicU64::new(1),
        });
        let connection = Connection {
            shared,
            id: 7,
            statements: AtomicU64::new(1),
            closed: AtomicBool::new(false),
        };
        let (reply, unread) = oneshot::channel::<Result<Connection, Failure>>();
        assert!(reply.send(Ok(connection)).is_ok());
        drop(unread);
        assert!(matches!(
            cleanups.try_recv()?,
            Command::Disconnect { connection: 7, .. }
        ));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn old_database_is_refused_before_enrollment_or_database_writes() -> Result<(), Failure> {
        const SCHEMA: &str = r#"{"format":6,"application":"refusal","version":1,"tables":[{"name":"items","class":"replayed","columns":[{"name":"title","type":"text","not_null":true}],"primary_key":["id"]}]}"#;
        for format in [0, 1, 2, 3, 5] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("rocky.sqlite");
            let conn = rocky_storage::sqlite::Connection::open(&path)?;
            conn.execute("CREATE TABLE secure_typed(descriptor BLOB NOT NULL)", ())
                .await?;
            conn.execute("CREATE TABLE secure_metadata(identity BLOB)", ())
                .await?;
            conn.execute(
                "INSERT INTO secure_typed VALUES(?)",
                [format!("{{\"format\":{format}}}").into_bytes()],
            )
            .await?;
            conn.execute("CREATE TABLE sentinel(value TEXT)", ())
                .await?;
            conn.execute("INSERT INTO sentinel VALUES('retained')", ())
                .await?;
            drop(conn);
            let before = std::fs::read(&path)?;
            for create in [false, true] {
                let options = Open {
                    identity: None,
                    directory: directory.path(),
                    schema: SCHEMA,
                    secrets: None,
                    network: None,
                    coordination: None,
                };
                let error = if create {
                    Database::create(options, None)
                } else {
                    Database::open(options)
                }
                .err()
                .ok_or("old database admitted")?
                .to_string();
                assert!(error.contains("unsupported Rocky file format"), "{error}");
                assert_eq!(std::fs::read(&path)?, before);
                for name in [
                    "sdk.lock",
                    "identity.json",
                    "bootstrap.json",
                    "secrets",
                    "rocky.sqlite-wal",
                ] {
                    assert!(!directory.path().join(name).exists(), "{name}");
                }
            }
        }
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn populated_numeric_consumer_continues_node_author_after_reopen() -> Result<(), Failure>
    {
        const SCHEMA: &str = r#"{"format":6,"application":"reopen_numeric","version":1,"tables":[{"name":"items","class":"replayed","columns":[{"name":"title","type":"text","not_null":true}],"primary_key":["id"]}]}"#;
        async fn call(
            database: &Database,
            session: &Session,
            request: Value,
        ) -> Result<Value, Failure> {
            let reply: Value = serde_json::from_str(&session.call(json!({
                "version": 1, "scope": serde_json::from_str::<Value>(&database.scope())?,
                "request": request,
            }).to_string()).await?)?;
            if reply["status"] != "ok" {
                return Err(format!("consumer request refused: {reply}").into());
            }
            Ok(reply["value"].clone())
        }
        let directory = tempfile::tempdir()?;
        let options = || Open {
            identity: None,
            directory: directory.path(),
            schema: SCHEMA,
            secrets: None,
            network: None,
            coordination: None,
        };
        let database = Database::create(options(), None)?.database;
        let session = database.session();
        call(&database, &session, json!({"type":"sql","sql":"BEGIN"})).await?;
        let first = call(
            &database,
            &session,
            json!({"type":"next_id","table":"items"}),
        )
        .await?["id"]
            .as_str()
            .ok_or("missing id")?
            .to_owned();
        call(&database, &session, json!({"type":"sql","sql":"INSERT INTO items(id,title) VALUES(?,'first')","values":[{"type":"integer","value":first}]})).await?;
        call(&database, &session, json!({"type":"sql","sql":"COMMIT"})).await?;
        session.close().await;
        database.close().await?;

        let database = Database::open(options())?.database;
        let session = database.session();
        let rows = call(
            &database,
            &session,
            json!({"type":"read","query":{"sql":"SELECT id FROM items","max_rows":8}}),
        )
        .await?;
        assert_eq!(rows["rows"][0][0]["value"], first);
        call(&database, &session, json!({"type":"sql","sql":"BEGIN"})).await?;
        let second = call(
            &database,
            &session,
            json!({"type":"next_id","table":"items"}),
        )
        .await?["id"]
            .as_str()
            .ok_or("missing id")?
            .to_owned();
        assert_eq!(second.parse::<i64>()?, first.parse::<i64>()? + 1);
        call(&database, &session, json!({"type":"sql","sql":"INSERT INTO items(id,title) VALUES(?,'second')","values":[{"type":"integer","value":second}]})).await?;
        call(&database, &session, json!({"type":"sql","sql":"COMMIT"})).await?;
        let rows = call(
            &database,
            &session,
            json!({"type":"read","query":{"sql":"SELECT id FROM items ORDER BY id","max_rows":8}}),
        )
        .await?;
        assert_eq!(rows["rows"].as_array().ok_or("missing rows")?.len(), 2);
        assert_eq!(rows["rows"][1][0]["value"], second);
        session.close().await;
        database.close().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn saturated_waits_cannot_block_session_shutdown() -> Result<(), Failure> {
        let directory = tempfile::tempdir()?;
        let opened = Database::create(
            Open {
                identity: None,
                directory: directory.path(),
                schema: r#"{"application":"saturation","version":1,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]}]}"#,
                secrets: None,
                network: None,
                coordination: None,
            },
            None,
        )?;
        let database = opened.database;
        let session = database.session();
        let scope: Value = serde_json::from_str(&database.scope())?;
        let status: Value = serde_json::from_str(
            &session
                .call(
                    json!({
                        "version": 1, "scope": scope, "request": {"type": "status"},
                    })
                    .to_string(),
                )
                .await?,
        )?;
        let bytes = json!({
            "version": 1, "scope": scope,
            "request": {"type": "status_next", "after": status["value"]["token"]},
        })
        .to_string()
        .into_bytes();
        let mut replies = Vec::new();
        // Queue every wait before End, without sleeps or scheduler assumptions.
        for _ in 0..129 {
            let (reply, receiver) = oneshot::channel();
            database
                .shared
                .input
                .send(Command::Call {
                    session: session.id,
                    bytes: bytes.clone(),
                    ending: session.closed.clone(),
                    reply,
                })
                .await?;
            replies.push(receiver);
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), session.close()).await?;
        drop(replies);
        database.close().await?;
        Ok(())
    }
}
