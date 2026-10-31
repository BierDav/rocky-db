//! Private SQLite adapter. Calls are synchronous and complete before they
//! return; the `async` signatures only let storage code share one shape with
//! its async callers. See `docs/runtime/write-concurrency.md`.
use std::{cell::Cell, collections::VecDeque, path::Path, sync::Mutex, time::Instant};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// The file is held by another connection; the whole transaction may retry.
    Busy(String),
    /// A read transaction outlived its deadline and was interrupted.
    Deadline,
    /// A statement reached beyond the tables its read may use.
    Denied,
    /// A statement outside the supported surface; it was never compiled.
    Unsupported(String),
    /// A shared group commit failed; the original error went to one waiter.
    Group(String),
    Sqlite(rusqlite::Error),
    Type(String),
}
/// The SQLite library this build runs, as replicas report it.
pub fn engine() -> String {
    format!("sqlite {}", rusqlite::version())
}

impl Error {
    /// The engine refused a statement for violating a constraint.
    pub fn is_constraint(&self) -> bool {
        matches!(self, Self::Sqlite(error)
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation))
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy(message) => write!(f, "database is busy: {message}"),
            Self::Deadline => write!(f, "read transaction exceeded its time bound"),
            Self::Denied => write!(f, "statement is not authorized"),
            Self::Unsupported(reason) => write!(f, "unsupported statement: {reason}"),
            Self::Group(message) => write!(f, "group commit failed: {message}"),
            Self::Sqlite(error) => error.fmt(f),
            Self::Type(message) => write!(f, "unexpected column value: {message}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}
impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        match error.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
                Self::Busy(error.to_string())
            }
            Some(rusqlite::ErrorCode::OperationInterrupted) => Self::Deadline,
            Some(rusqlite::ErrorCode::AuthorizationForStatementDenied) => Self::Denied,
            _ => Self::Sqlite(error),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}
impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}
impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}
impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::Text(value.into())
    }
}
impl From<Vec<u8>> for Value {
    fn from(value: Vec<u8>) -> Self {
        Self::Blob(value)
    }
}
impl rusqlite::ToSql for Value {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        use rusqlite::types::{ToSqlOutput, ValueRef};
        Ok(ToSqlOutput::Borrowed(match self {
            Self::Null => ValueRef::Null,
            Self::Integer(value) => ValueRef::Integer(*value),
            Self::Real(value) => ValueRef::Real(*value),
            Self::Text(value) => ValueRef::Text(value.as_bytes()),
            Self::Blob(value) => ValueRef::Blob(value),
        }))
    }
}

pub trait IntoParams {
    fn into_params(self) -> Vec<Value>;
}
impl IntoParams for () {
    fn into_params(self) -> Vec<Value> {
        Vec::new()
    }
}
impl IntoParams for Vec<Value> {
    fn into_params(self) -> Vec<Value> {
        self
    }
}
impl<T: Into<Value>, const N: usize> IntoParams for [T; N] {
    fn into_params(self) -> Vec<Value> {
        self.into_iter().map(Into::into).collect()
    }
}
impl<A: Into<Value>, B: Into<Value>, C: Into<Value>> IntoParams for (A, B, C) {
    fn into_params(self) -> Vec<Value> {
        vec![self.0.into(), self.1.into(), self.2.into()]
    }
}
/// Positional parameters of mixed types.
#[macro_export]
macro_rules! params {
    ($($value:expr),* $(,)?) => {
        vec![$($crate::sqlite::Value::from($value)),*]
    };
}
pub use params;

pub trait FromValue: Sized {
    fn from_value(value: Value) -> Result<Self>;
}
impl FromValue for i64 {
    fn from_value(value: Value) -> Result<Self> {
        match value {
            Value::Integer(value) => Ok(value),
            other => Err(Error::Type(format!("expected INTEGER, found {other:?}"))),
        }
    }
}
impl FromValue for String {
    fn from_value(value: Value) -> Result<Self> {
        match value {
            Value::Text(value) => Ok(value),
            _ => Err(Error::Type("expected TEXT".into())),
        }
    }
}
impl FromValue for Vec<u8> {
    fn from_value(value: Value) -> Result<Self> {
        match value {
            Value::Blob(value) => Ok(value),
            _ => Err(Error::Type("expected BLOB".into())),
        }
    }
}

impl Value {
    /// Bytes a value counts towards a result's byte limit.
    pub fn weight(&self) -> usize {
        match self {
            Self::Text(text) => text.len(),
            Self::Blob(bytes) => bytes.len(),
            _ => 8,
        }
    }
}
/// One bounded page of a result.
pub struct Page {
    pub rows: Vec<Vec<Value>>,
    /// The statement had at least one more row.
    pub more: bool,
    /// The first row alone exceeds the byte limit; `rows` is empty.
    pub oversized: bool,
}
pub struct Row(Vec<Value>);
impl Row {
    pub fn column_count(&self) -> usize {
        self.0.len()
    }
    pub fn get_value(&self, column: usize) -> Result<Value> {
        self.0
            .get(column)
            .cloned()
            .ok_or_else(|| Error::Type(format!("missing column {column}")))
    }
    pub fn get<T: FromValue>(&self, column: usize) -> Result<T> {
        T::from_value(self.get_value(column)?)
    }
}
/// A fully read result. The statement is reset before `query` returns, so no
/// cursor outlives the call or pins a read snapshot.
pub struct Rows(VecDeque<Row>);
impl Rows {
    pub async fn next(&mut self) -> Result<Option<Row>> {
        Ok(self.0.pop_front())
    }
}

/// The row hook's consumers: checkpoint digests, session capture and
/// watched-table counts.
#[derive(Clone)]
struct Hooks {
    tracker: std::sync::Arc<Mutex<crate::digest::Tracker>>,
    capture: std::sync::Arc<Mutex<crate::capture::Sink>>,
    writes: std::sync::Arc<Writes>,
}
/// Counts row changes to watched tables of `main`, so a cache derived from
/// them can tell it is stale, also inside one transaction.
#[derive(Default)]
pub struct Writes {
    /// Each table, and whether an update counts or only rows added or
    /// removed.
    tables: std::sync::RwLock<Vec<(String, bool)>>,
    count: std::sync::atomic::AtomicU64,
    counts: Mutex<std::collections::HashMap<String, TableCount>>,
    rows: std::sync::RwLock<RowCounters>,
    row_failures: std::sync::atomic::AtomicU64,
}
#[derive(Default)]
struct TableCount {
    all: u64,
    structural: u64,
}
type RowCounters = std::collections::HashMap<
    String,
    std::collections::BTreeMap<
        i32,
        std::collections::HashMap<i64, std::sync::Weak<std::sync::atomic::AtomicU64>>,
    >,
>;
type WatchedInteger = (
    String,
    i32,
    i64,
    std::sync::Arc<std::sync::atomic::AtomicU64>,
);
/// Changes to physical rows selected by integer columns, including rolled
/// back writes. Unrelated keys do not invalidate the watch.
pub struct RowWrites {
    keys: Vec<WatchedInteger>,
    owner: std::sync::Arc<Writes>,
}
impl RowWrites {
    pub fn count(&self) -> u64 {
        self.owner
            .row_failures
            .load(std::sync::atomic::Ordering::Acquire)
            + self
                .keys
                .iter()
                .map(|(_, _, _, counter)| counter.load(std::sync::atomic::Ordering::Acquire))
                .sum::<u64>()
    }
}
impl Drop for RowWrites {
    fn drop(&mut self) {
        let mut rows = self
            .owner
            .rows
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (table, column, key, counter) in &self.keys {
            if std::sync::Arc::strong_count(counter) != 1 {
                continue;
            }
            if let Some(columns) = rows.get_mut(table) {
                if let Some(keys) = columns.get_mut(column) {
                    keys.remove(key);
                    if keys.is_empty() {
                        columns.remove(column);
                    }
                }
                if columns.is_empty() {
                    rows.remove(table);
                }
            }
        }
    }
}
impl Writes {
    /// Changes so far; it only grows.
    pub fn count(&self) -> u64 {
        self.count.load(std::sync::atomic::Ordering::Acquire)
    }
    /// Changes to one watched table, including changes within a transaction.
    pub fn table_count(&self, table: &str) -> u64 {
        self.selected_count([(table, true)])
    }
    /// A watch's own table/mutation selection, independent of other consumers.
    pub fn selected_count<'a>(&self, tables: impl IntoIterator<Item = (&'a str, bool)>) -> u64 {
        let counts = self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tables.into_iter().fold(0u64, |total, (table, updates)| {
            let count =
                counts.get(table).map_or(
                    0,
                    |count| if updates { count.all } else { count.structural },
                );
            total.wrapping_add(count)
        })
    }
    fn observe(&self, table: &str, case: &rusqlite::hooks::PreUpdateCase) {
        let update = matches!(case, rusqlite::hooks::PreUpdateCase::Update { .. });
        let rows = self
            .rows
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(columns) = rows.get(table) {
            use rusqlite::{hooks::PreUpdateCase, types::ValueRef};
            let integer = |value: rusqlite::Result<ValueRef<'_>>| {
                value.map(|value| match value {
                    ValueRef::Integer(value) => Some(value),
                    _ => None,
                })
            };
            for (column, keys) in columns {
                let values = match case {
                    PreUpdateCase::Insert(added) => {
                        integer(added.get_new_column_value(*column)).map(|new| (None, new))
                    }
                    PreUpdateCase::Delete(removed) => {
                        integer(removed.get_old_column_value(*column)).map(|old| (old, None))
                    }
                    PreUpdateCase::Update {
                        old_value_accessor,
                        new_value_accessor,
                    } => {
                        integer(old_value_accessor.get_old_column_value(*column)).and_then(|old| {
                            integer(new_value_accessor.get_new_column_value(*column))
                                .map(|new| (old, new))
                        })
                    }
                    PreUpdateCase::Unknown => {
                        Err(rusqlite::Error::InvalidColumnIndex(*column as usize))
                    }
                };
                let Ok((old, new)) = values else {
                    self.row_failures
                        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    continue;
                };
                for key in old.into_iter().chain(new.filter(|new| Some(*new) != old)) {
                    if let Some(counter) = keys.get(&key).and_then(std::sync::Weak::upgrade) {
                        counter.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    }
                }
            }
        }
        if self.tables.read().is_ok_and(|tables| {
            tables
                .iter()
                .any(|(watched, updates)| watched == table && (*updates || !update))
        }) {
            self.count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let mut counts = self
                .counts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let count = counts.entry(table.to_owned()).or_default();
            count.all = count.all.wrapping_add(1);
            if !update {
                count.structural = count.structural.wrapping_add(1);
            }
        }
    }
}
/// What a session statement observes of its own earlier statements. The
/// runtime's protocol writes share the connection and must not show here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Observed {
    pub changes: i64,
    pub last_insert_rowid: i64,
    pub total_changes: i64,
}
/// Session state of a write connection: its authorizer and what the SQL
/// functions `changes`, `total_changes` and `last_insert_rowid` return.
#[derive(Clone)]
pub struct Session {
    pub gate: std::sync::Arc<Mutex<crate::capture::Gate>>,
    pub observed: std::sync::Arc<Mutex<Observed>>,
}
/// A session statement's result.
pub struct Ran {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    pub read_only: bool,
    pub changes: u64,
    /// Rows this statement changed, triggers included.
    pub total_changes: u64,
    pub last_insert_rowid: i64,
}
pub enum Run {
    Done(Ran),
    /// The statement writes and was not stepped.
    Writes,
    /// The result exceeded its byte bound; `true` if the statement writes,
    /// in which case its changes are in place.
    Oversized(bool),
}
/// What compiling a session statement reports, without stepping it.
pub struct Described {
    pub columns: Vec<String>,
    pub parameters: usize,
    pub read_only: bool,
}
pub struct Connection(
    Mutex<rusqlite::Connection>,
    std::sync::OnceLock<Hooks>,
    std::sync::OnceLock<Session>,
    /// The session gate.
    std::sync::Arc<Mutex<crate::capture::Gate>>,
);
/// The name prefix of the runtime's history triggers, which a session's
/// statements fire.
pub const HISTORY_TRIGGERS: &str = "secure_kept_";
/// The name prefix of the history tables those triggers write.
pub const HISTORY_TABLES: &str = "secure_history_";
impl Connection {
    pub fn open(path: &Path) -> Result<Self> {
        Self::configure(rusqlite::Connection::open(path)?)
    }
    pub fn open_read_only(path: &Path) -> Result<Self> {
        use rusqlite::OpenFlags;
        let connection = Self::configure(rusqlite::Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?)?;
        connection.rows("PRAGMA mmap_size=67108864", ())?;
        // SQLite loads the file's schema lazily. Do that during connection
        // setup, before a bounded application snapshot starts its deadline.
        connection.rows("SELECT name FROM sqlite_schema LIMIT 0", ())?;
        Ok(connection)
    }
    /// A private database that lives as long as the connection.
    pub fn open_in_memory() -> Result<Self> {
        Self::configure(rusqlite::Connection::open_in_memory()?)
    }
    fn configure(raw: rusqlite::Connection) -> Result<Self> {
        raw.set_prepared_statement_cache_capacity(512);
        // Busy files are retried by whole transactions with bounded backoff.
        raw.busy_timeout(std::time::Duration::ZERO)?;
        Ok(Self(
            Mutex::new(raw),
            std::sync::OnceLock::new(),
            std::sync::OnceLock::new(),
            Default::default(),
        ))
    }
    /// The connection's row tracker. The first call installs the engine hook
    /// that feeds it; connections that never ask pay nothing.
    pub fn tracker(&self) -> Result<std::sync::Arc<Mutex<crate::digest::Tracker>>> {
        Ok(self.hooks()?.tracker)
    }
    /// The capture sink fed by the same hook as the tracker.
    pub fn capture(&self) -> Result<std::sync::Arc<Mutex<crate::capture::Sink>>> {
        Ok(self.hooks()?.capture)
    }
    /// Adds physical `tables` to the watched set and returns its counter;
    /// each table counts updates too, or only rows added or removed.
    pub fn watch_writes(
        &self,
        tables: impl IntoIterator<Item = (String, bool)>,
    ) -> Result<std::sync::Arc<Writes>> {
        let writes = self.hooks()?.writes;
        {
            let mut watched = writes
                .tables
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (table, updates) in tables {
                if let Some((_, existing)) = watched.iter_mut().find(|(name, _)| *name == table) {
                    *existing |= updates;
                } else {
                    watched.push((table, updates));
                }
            }
        }
        Ok(writes)
    }
    /// Watches physical rows with any matching (table, zero-based integer
    /// column, value). Counters include triggers and rolled back writes.
    pub fn watch_integer_rows(
        &self,
        keys: impl IntoIterator<Item = (String, i32, i64)>,
    ) -> Result<std::sync::Arc<RowWrites>> {
        let keys: Vec<_> = keys.into_iter().collect();
        if keys.iter().any(|(_, column, _)| *column < 0) {
            return Err(Error::Type("negative watched column".into()));
        }
        let writes = self.hooks()?.writes;
        let mut rows = writes
            .rows
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut watched = Vec::new();
        for (table, column, key) in keys.into_iter().collect::<std::collections::BTreeSet<_>>() {
            let entry = rows
                .entry(table.clone())
                .or_default()
                .entry(column)
                .or_default()
                .entry(key)
                .or_default();
            let counter = entry.upgrade().unwrap_or_else(|| {
                let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                *entry = std::sync::Arc::downgrade(&counter);
                counter
            });
            watched.push((table, column, key, counter));
        }
        drop(rows);
        Ok(std::sync::Arc::new(RowWrites {
            keys: watched,
            owner: writes,
        }))
    }
    /// One hook per connection: it reads a changed row once and hands it to
    /// the digest tracker and to the capture sink.
    fn hooks(&self) -> Result<Hooks> {
        use rusqlite::hooks::PreUpdateCase;
        if let Some(hooks) = self.1.get() {
            return Ok(hooks.clone());
        }
        let hooks = Hooks {
            tracker: Default::default(),
            capture: Default::default(),
            writes: Default::default(),
        };
        let shared = hooks.clone();
        self.raw()?.preupdate_hook(Some(
            move |_, database: &str, table: &str, case: &PreUpdateCase| {
                if database == "main" {
                    shared.writes.observe(table, case);
                }
                let (Ok(mut tracker), Ok(mut capture)) =
                    (shared.tracker.lock(), shared.capture.lock())
                else {
                    return;
                };
                let main = database == "main";
                if let PreUpdateCase::Insert(added) = case
                    && main
                    && added.get_query_depth() == 0
                {
                    capture.inserted(table);
                }
                let tracked = tracker
                    .table(table)
                    .filter(|_| main)
                    .map(|(slot, logical)| (slot, logical.to_string()));
                let captured = capture.wants(main, table);
                if tracked.is_none() && !captured {
                    return;
                }
                let old = |accessor: &rusqlite::hooks::PreUpdateOldValueAccessor| {
                    (0..accessor.get_column_count())
                        .map(|column| value(accessor.get_old_column_value(column)?))
                        .collect::<Result<Vec<_>>>()
                };
                let new = |accessor: &rusqlite::hooks::PreUpdateNewValueAccessor| {
                    (0..accessor.get_column_count())
                        .map(|column| value(accessor.get_new_column_value(column)?))
                        .collect::<Result<Vec<_>>>()
                };
                let rows = match case {
                    PreUpdateCase::Insert(added) => new(added).map(|added| (None, Some(added))),
                    PreUpdateCase::Delete(removed) => {
                        old(removed).map(|removed| (Some(removed), None))
                    }
                    PreUpdateCase::Update {
                        old_value_accessor,
                        new_value_accessor,
                    } => old(old_value_accessor)
                        .and_then(|removed| Ok((Some(removed), Some(new(new_value_accessor)?)))),
                    PreUpdateCase::Unknown => Err(Error::Type("unknown row change".into())),
                };
                match rows {
                    Ok((removed, added)) => {
                        if let Some((slot, logical)) = tracked {
                            let hash =
                                |row: &Vec<Value>| crate::digest::row_hash(&logical, row.iter());
                            tracker.record(
                                slot,
                                removed.as_ref().map(hash),
                                added.as_ref().map(hash),
                            );
                        }
                        if captured {
                            capture.observe(table, removed, added);
                        }
                    }
                    Err(_) => {
                        if tracked.is_some() {
                            tracker.fail();
                        }
                        capture.fail("a changed row could not be read");
                    }
                }
            },
        ))?;
        Ok(self.1.get_or_init(|| hooks).clone())
    }
    /// The connection's session state. The first call installs the statement
    /// authorizer and the SQL functions that report a session's own counts.
    pub fn session(&self) -> Result<Session> {
        use rusqlite::functions::FunctionFlags;
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
        if let Some(session) = self.2.get() {
            return Ok(session.clone());
        }
        let session = Session {
            gate: self.3.clone(),
            observed: Default::default(),
        };
        let raw = self.raw()?;
        let gate = session.gate.clone();
        raw.authorizer(Some(move |context: AuthContext<'_>| {
            use crate::capture::Access;
            let access = match context.action {
                AuthAction::Select | AuthAction::Function { .. } | AuthAction::Recursive => {
                    Access::Neutral
                }
                AuthAction::Read {
                    table_name,
                    column_name,
                } => Access::Read(table_name, column_name),
                AuthAction::Insert { table_name } => Access::Insert(table_name),
                AuthAction::Delete { table_name } => Access::Delete(table_name),
                AuthAction::Update {
                    table_name,
                    column_name,
                } => Access::Update(table_name, column_name),
                _ => Access::Other,
            };
            // The runtime's history triggers write what a session's change
            // replaces; the session never names their tables.
            if context
                .accessor
                .is_some_and(|trigger| trigger.starts_with(HISTORY_TRIGGERS))
            {
                return Authorization::Allow;
            }
            // Statements of another schema, such as `temp`, are never a session's.
            let foreign = context.database_name.is_some_and(|name| name != "main");
            let Ok(mut gate) = gate.lock() else {
                return Authorization::Deny;
            };
            if gate.allows(access) && !(foreign && gate.armed()) {
                Authorization::Allow
            } else {
                Authorization::Deny
            }
        }))?;
        type Read = fn(&Observed) -> i64;
        let functions: [(&str, Read); 3] = [
            ("changes", |observed| observed.changes),
            ("total_changes", |observed| observed.total_changes),
            ("last_insert_rowid", |observed| observed.last_insert_rowid),
        ];
        for (name, read) in functions {
            let observed = session.observed.clone();
            raw.create_scalar_function(name, 0, FunctionFlags::SQLITE_UTF8, move |_| {
                Ok(observed.lock().map(|observed| read(&observed)).unwrap_or(0))
            })?;
        }
        drop(raw);
        Ok(self.2.get_or_init(|| session).clone())
    }
    /// Compiles a session statement under the armed gate. The engine reports
    /// a table from which no column is read, as in `count(*)`, by a bare
    /// name that may also be a common table expression or a subquery. Such
    /// a name must not be any stored table, or the statement is refused.
    fn compile<'c>(
        &self,
        raw: &'c rusqlite::Connection,
        sql: &str,
    ) -> Result<rusqlite::Statement<'c>> {
        let statement = raw.prepare(sql)?;
        let Some(session) = self.2.get() else {
            return Ok(statement);
        };
        let poisoned = || Error::Type("session gate poisoned".into());
        let (plan, unresolved) = {
            let mut gate = session.gate.lock().map_err(|_| poisoned())?;
            (gate.suspend(), gate.unresolved())
        };
        let stored = unresolved.iter().try_fold(false, |found, name| {
            let mut lookup =
                raw.prepare_cached("SELECT 1 FROM pragma_table_list WHERE name=?1 COLLATE NOCASE")?;
            Ok::<_, Error>(found || lookup.exists([name])?)
        });
        session.gate.lock().map_err(|_| poisoned())?.resume(plan);
        if stored? {
            return Err(Error::Denied);
        }
        Ok(statement)
    }
    /// Compiles a session statement under the armed gate without stepping it.
    pub fn describe(&self, sql: &str) -> Result<Described> {
        let raw = self.raw()?;
        let statement = self.compile(&raw, sql)?;
        Ok(Described {
            columns: statement
                .column_names()
                .into_iter()
                .map(String::from)
                .collect(),
            parameters: statement.parameter_count(),
            read_only: statement.readonly(),
        })
    }
    /// Compiles and steps one session statement. It is compiled anew, so the
    /// armed gate authorizes this text and reports its assignments. With
    /// `write` unset a writing statement is not stepped.
    pub fn session_run(
        &self,
        sql: &str,
        params: Vec<Value>,
        max_bytes: usize,
        write: bool,
    ) -> Result<Run> {
        let raw = self.raw()?;
        let mut statement = self.compile(&raw, sql)?;
        let read_only = statement.readonly();
        if !read_only && !write {
            return Ok(Run::Writes);
        }
        let names: Vec<String> = statement
            .column_names()
            .into_iter()
            .map(String::from)
            .collect();
        let before = raw.total_changes();
        let mut result = Vec::new();
        let mut bytes = 0usize;
        let mut rows = statement.query(rusqlite::params_from_iter(params))?;
        while let Some(row) = rows.next()? {
            let mut values = Vec::with_capacity(names.len());
            for column in 0..names.len() {
                values.push(value(row.get_ref(column)?)?);
            }
            bytes = bytes.saturating_add(values.iter().map(Value::weight).sum::<usize>());
            if bytes > max_bytes {
                return Ok(Run::Oversized(!read_only));
            }
            result.push(values);
        }
        drop(rows);
        drop(statement);
        Ok(Run::Done(Ran {
            columns: names,
            rows: result,
            read_only,
            changes: raw.changes(),
            total_changes: raw.total_changes().saturating_sub(before),
            last_insert_rowid: raw.last_insert_rowid(),
        }))
    }
    /// Interrupts statements once `deadline` passes or `cancelled` is set.
    pub fn set_interrupt(
        &self,
        deadline: Instant,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<()> {
        self.raw()?.progress_handler(
            1000,
            Some(move || {
                cancelled.load(std::sync::atomic::Ordering::Relaxed) || Instant::now() >= deadline
            }),
        )?;
        Ok(())
    }
    /// Steps a statement and hands each row to `visit` without collecting
    /// the result.
    pub fn scan(
        &self,
        sql: &str,
        params: Vec<Value>,
        mut visit: impl FnMut(&[Value]) -> Result<()>,
    ) -> Result<()> {
        let raw = self.raw()?;
        let mut statement = raw.prepare_cached(sql)?;
        #[cfg(any(test, feature = "test-support"))]
        {
            STATEMENTS.with(|cell| cell.set(cell.get() + 1));
            STATEMENT_TRACE.with(|trace| {
                if let Some(statements) = trace.borrow_mut().as_mut() {
                    statements.push(sql.to_owned());
                }
            });
        }
        let columns = statement.column_count();
        let mut rows = statement.query(rusqlite::params_from_iter(params))?;
        let mut values = Vec::with_capacity(columns);
        while let Some(row) = rows.next()? {
            values.clear();
            for column in 0..columns {
                values.push(value(row.get_ref(column)?)?);
            }
            visit(&values)?;
        }
        Ok(())
    }
    /// Runs `serve` with the engine connection. A cursor's thread holds it
    /// for the cursor's whole life.
    pub(crate) fn hold<T>(&self, serve: impl FnOnce(&rusqlite::Connection) -> T) -> Result<T> {
        let raw = self.raw()?;
        Ok(serve(&raw))
    }
    fn raw(&self) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>> {
        self.0
            .lock()
            .map_err(|_| Error::Type("connection poisoned".into()))
    }
    /// Interrupts statements once `deadline` passes, so an open reader cannot
    /// pin the WAL indefinitely. `None` removes the bound.
    pub fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        let raw = self.raw()?;
        match deadline {
            Some(deadline) => {
                raw.progress_handler(1000, Some(move || Instant::now() >= deadline))?
            }
            None => raw.progress_handler(0, None::<fn() -> bool>)?,
        }
        Ok(())
    }
    pub fn set_busy_timeout(&self, timeout: std::time::Duration) -> Result<()> {
        self.raw()?.busy_timeout(timeout)?;
        Ok(())
    }
    pub fn set_query_only(&self) -> Result<()> {
        self.raw()?.pragma_update(None, "query_only", 1)?;
        Ok(())
    }
    /// Records the WAL size after each commit on this thread; see `wal_frames`.
    pub fn track_wal(&self) -> Result<()> {
        fn record(_: &rusqlite::hooks::Wal, frames: std::ffi::c_int) -> rusqlite::Result<()> {
            WAL_FRAMES.with(|cell| cell.set(i64::from(frames)));
            Ok(())
        }
        self.raw()?.wal_hook(Some(record));
        Ok(())
    }
    /// Qualification hook: exit from SQLite's callback while COMMIT is executing.
    #[cfg(feature = "qualification")]
    pub fn qualification_exit_in_commit(&self) -> Result<()> {
        let raw = self.raw()?;
        raw.commit_hook(Some(|| std::process::exit(87)))?;
        let result = raw.execute_batch("COMMIT");
        raw.commit_hook(None::<fn() -> bool>)?;
        result?;
        Err(Error::Type(
            "qualification COMMIT returned without invoking its callback".into(),
        ))
    }
    /// Test hook: kill the process when SQLite would wait for another connection.
    #[cfg(any(test, feature = "test-support"))]
    pub fn abort_when_busy(&self) -> Result<()> {
        fn abort(_: i32) -> bool {
            std::process::abort()
        }
        self.raw()?.busy_handler(Some(abort))?;
        Ok(())
    }
    /// While `tables` is set, statements compile only if they are plain
    /// `SELECT`s that read no table outside it. `None` lifts the restriction.
    pub fn restrict_reads(&self, tables: Option<Vec<String>>) -> Result<()> {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
        let raw = self.raw()?;
        match tables {
            Some(tables) => {
                raw.authorizer(Some(move |context: AuthContext<'_>| match context.action {
                    AuthAction::Select | AuthAction::Function { .. } => Authorization::Allow,
                    AuthAction::Read { table_name, .. }
                        if tables.iter().any(|table| table == table_name) =>
                    {
                        Authorization::Allow
                    }
                    _ => Authorization::Deny,
                }))?
            }
            None => raw.authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?,
        }
        Ok(())
    }
    /// Steps a statement until `max_rows` rows or `max_bytes` bytes are read
    /// and reports whether a further row exists. The last `unweighed` columns
    /// of a row do not count towards the bytes. The statement is reset before
    /// returning.
    pub fn page(
        &self,
        sql: &str,
        params: Vec<Value>,
        max_rows: usize,
        max_bytes: usize,
        unweighed: usize,
    ) -> Result<Page> {
        let raw = self.raw()?;
        let mut statement = raw.prepare_cached(sql)?;
        #[cfg(any(test, feature = "test-support"))]
        {
            STATEMENTS.with(|cell| cell.set(cell.get() + 1));
            STATEMENT_TRACE.with(|trace| {
                if let Some(statements) = trace.borrow_mut().as_mut() {
                    statements.push(sql.to_owned());
                }
            });
        }
        let columns = statement.column_count();
        let mut page = Page {
            rows: Vec::new(),
            more: false,
            oversized: false,
        };
        let mut bytes = 0usize;
        let mut rows = statement.query(rusqlite::params_from_iter(params))?;
        while let Some(row) = rows.next()? {
            if page.rows.len() == max_rows {
                page.more = true;
                break;
            }
            let mut values = Vec::with_capacity(columns);
            for column in 0..columns {
                values.push(value(row.get_ref(column)?)?);
            }
            let weighed = &values[..columns.saturating_sub(unweighed)];
            bytes = bytes.saturating_add(weighed.iter().map(Value::weight).sum::<usize>());
            if bytes > max_bytes {
                page.more = true;
                page.oversized = page.rows.is_empty();
                break;
            }
            page.rows.push(values);
        }
        Ok(page)
    }
    /// `query` for callers outside an async context.
    pub fn rows(&self, sql: &str, params: impl IntoParams) -> Result<Vec<Vec<Value>>> {
        let (rows, _) = self.run(sql, params.into_params())?;
        Ok(rows.into_iter().map(|row| row.0).collect())
    }
    /// `execute` for callers outside an async context.
    pub fn run_now(&self, sql: &str) -> Result<()> {
        self.run(sql, Vec::new()).map(|_| ())
    }
    fn run(&self, sql: &str, params: Vec<Value>) -> Result<(VecDeque<Row>, u64)> {
        let raw = self.raw()?;
        let mut statement = raw.prepare_cached(sql)?;
        #[cfg(any(test, feature = "test-support"))]
        {
            STATEMENTS.with(|cell| cell.set(cell.get() + 1));
            STATEMENT_TRACE.with(|trace| {
                if let Some(statements) = trace.borrow_mut().as_mut() {
                    statements.push(sql.to_owned());
                }
            });
        }
        let columns = statement.column_count();
        let mut result = VecDeque::new();
        let mut rows = statement.query(rusqlite::params_from_iter(params))?;
        while let Some(row) = rows.next()? {
            let mut values = Vec::with_capacity(columns);
            for column in 0..columns {
                values.push(value(row.get_ref(column)?)?);
            }
            result.push_back(Row(values));
        }
        drop(rows);
        drop(statement);
        Ok((result, raw.changes()))
    }
    pub async fn query(&self, sql: impl AsRef<str>, params: impl IntoParams) -> Result<Rows> {
        Ok(Rows(self.run(sql.as_ref(), params.into_params())?.0))
    }
    /// Returns the rows changed by the statement.
    pub async fn execute(&self, sql: impl AsRef<str>, params: impl IntoParams) -> Result<u64> {
        Ok(self.run(sql.as_ref(), params.into_params())?.1)
    }
    pub fn is_autocommit(&self) -> Result<bool> {
        Ok(self.raw()?.is_autocommit())
    }
    /// Rows inserted, updated or deleted on this connection since it opened.
    pub fn total_changes(&self) -> Result<u64> {
        Ok(self.raw()?.total_changes())
    }
}

pub(crate) fn value(value: rusqlite::types::ValueRef<'_>) -> Result<Value> {
    use rusqlite::types::ValueRef;
    Ok(match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(value) => Value::Integer(value),
        ValueRef::Real(value) => Value::Real(value),
        ValueRef::Text(value) => Value::Text(
            std::str::from_utf8(value)
                .map_err(|_| Error::Type("TEXT is not UTF-8".into()))?
                .into(),
        ),
        ValueRef::Blob(value) => Value::Blob(value.to_vec()),
    })
}

thread_local! {
    /// WAL frames after the latest commit on this thread. The file writer owns
    /// its connection on one thread, so the value belongs to that file.
    static WAL_FRAMES: Cell<i64> = const { Cell::new(0) };
}
pub fn wal_frames() -> i64 {
    WAL_FRAMES.with(Cell::get)
}
#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static STATEMENTS: Cell<u64> = const { Cell::new(0) };
    static STATEMENT_TRACE: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
}
/// Statements prepared on this thread, for tests that count them per row.
#[cfg(any(test, feature = "test-support"))]
pub fn statements() -> u64 {
    STATEMENTS.with(Cell::get)
}

/// Starts or stops collecting statement text on this test thread; returns the previous trace.
#[cfg(any(test, feature = "test-support"))]
pub fn trace_statements(enabled: bool) -> Vec<String> {
    STATEMENT_TRACE.with(|trace| trace.replace(enabled.then(Vec::new)).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_table_watches_share_one_registration_and_keep_update_tracking() {
        let conn = Connection::open_in_memory().unwrap();
        conn.run_now("CREATE TABLE watched(id INTEGER PRIMARY KEY,value INTEGER)")
            .unwrap();
        let writes = conn.watch_writes([("watched".into(), false)]).unwrap();
        conn.watch_writes([("watched".into(), true)]).unwrap();
        conn.watch_writes([("watched".into(), false)]).unwrap();
        assert_eq!(writes.tables.read().unwrap().len(), 1);
        conn.run_now("INSERT INTO watched VALUES(1,0)").unwrap();
        conn.run_now("UPDATE watched SET value=1 WHERE id=1")
            .unwrap();
        assert_eq!(writes.table_count("watched"), 2);
        assert_eq!(writes.selected_count([("watched", false)]), 1);
        assert_eq!(writes.selected_count([("unwatched", true)]), 0);
    }

    #[test]
    fn integer_row_watches_isolate_scopes_and_include_moves_and_rollback() {
        let conn = Connection::open_in_memory().unwrap();
        conn.raw().unwrap().execute_batch("CREATE TABLE rows(scope INTEGER, id INTEGER PRIMARY KEY, value TEXT); CREATE TABLE copies(scope INTEGER, id INTEGER PRIMARY KEY);
            CREATE TRIGGER copy_row AFTER INSERT ON rows BEGIN INSERT INTO copies VALUES(NEW.scope,NEW.id); END;
            INSERT INTO rows VALUES(2,1,'other')").unwrap();
        let watch = conn
            .watch_integer_rows([("rows".into(), 0, 1), ("copies".into(), 0, 1)])
            .unwrap();
        conn.run_now("UPDATE rows SET value='unrelated' WHERE id=1")
            .unwrap();
        assert_eq!(watch.count(), 0);
        conn.run_now("INSERT INTO rows VALUES(1,2,'own')").unwrap();
        assert_eq!(watch.count(), 2, "the trigger counts too");
        conn.run_now("UPDATE rows SET scope=2 WHERE id=2").unwrap();
        conn.run_now("UPDATE rows SET scope=1 WHERE id=1").unwrap();
        assert_eq!(watch.count(), 4, "both sides of a scope move invalidate");
        conn.raw()
            .unwrap()
            .execute_batch("BEGIN; DELETE FROM rows WHERE scope=1; ROLLBACK")
            .unwrap();
        assert_eq!(
            watch.count(),
            5,
            "rollback never rewinds validation counters"
        );
        drop(watch);
        let next = conn.watch_integer_rows([("rows".into(), 0, 1)]).unwrap();
        assert_eq!(conn.hooks().unwrap().writes.rows.read().unwrap().len(), 1);
        assert_eq!(next.count(), 0);
    }

    #[test]
    fn a_wide_read_only_connection_keeps_first_reads_bounded_and_read_only() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wide.db");
        let writer = Connection::open(&path).unwrap();
        let mut schema = String::from(
            "BEGIN; CREATE TABLE marker(value INTEGER); INSERT INTO marker VALUES(7);",
        );
        for table in 0..2000 {
            schema.push_str(&format!("CREATE TABLE t{table}(id INTEGER PRIMARY KEY);"));
        }
        schema.push_str("COMMIT;");
        writer.raw().unwrap().execute_batch(&schema).unwrap();
        drop(writer);

        let reader = Connection::open_read_only(&path).unwrap();
        assert!(reader.is_autocommit().unwrap());
        reader
            .set_deadline(Some(Instant::now() + std::time::Duration::from_millis(20)))
            .unwrap();
        assert_eq!(
            reader.rows("SELECT value FROM marker", ()).unwrap(),
            vec![vec![Value::Integer(7)]]
        );
        reader
            .set_deadline(Some(Instant::now() + std::time::Duration::from_millis(20)))
            .unwrap();
        assert!(matches!(reader.rows("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<1000000000) SELECT COUNT(*) FROM c", ()), Err(Error::Deadline)));
        reader.set_deadline(None).unwrap();
        assert_eq!(
            reader.rows("SELECT value FROM marker", ()).unwrap(),
            vec![vec![Value::Integer(7)]]
        );
        assert!(
            matches!(reader.run_now("INSERT INTO marker VALUES(8)"), Err(Error::Sqlite(error)) if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ReadOnly))
        );
    }

    #[tokio::test]
    async fn a_deadline_interrupts_a_long_read_with_a_typed_error() {
        let conn = Connection::open_in_memory().unwrap();
        let count = |limit: i64| {
            format!(
                "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<{limit}) \
                 SELECT COUNT(*) FROM c"
            )
        };
        conn.set_deadline(Some(Instant::now() + std::time::Duration::from_millis(20)))
            .unwrap();
        assert!(matches!(
            conn.query(count(1_000_000_000), ()).await,
            Err(Error::Deadline)
        ));
        conn.set_deadline(None).unwrap();
        let mut rows = conn.query(count(1000), ()).await.unwrap();
        assert_eq!(
            rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
            1000
        );
        let error = crate::Error::from(Error::Deadline);
        assert!(error.is_retryable() && !crate::storage::retryable(&error));
    }
}
