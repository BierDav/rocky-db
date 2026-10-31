//! Bound reads against stored rows. A read names one authorized view; the
//! view's `SELECT` replaces that name as a subquery, so the filter runs in the
//! engine with the table's indexes and no row is copied. Reads use a pool of
//! read-only connections beside the file's writer. See
//! `docs/runtime/local-replica.md`.
use crate::{
    BoundQuery, Completeness, Error, ReadCursor, ReadOptions, ReadSnapshot,
    scoped_connection::{Names, tokens},
    sqlite, storage,
};
use rocky_core::{Commitment, LocalRevision, ReadView, Scope, SqlValue};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Condvar, Mutex, Weak},
};
use tokio::sync::watch;

/// Read connections one file keeps beside its writer.
const POOL_CONNECTIONS: usize = 4;
/// Result bytes one read may return.
pub(crate) const MAX_READ_BYTES: usize = crate::MAX_FRAME_BYTES;
/// Ordering and key columns one keyset cursor may hold.
pub(crate) const MAX_KEYSET_COLUMNS: usize = 16;

struct View {
    /// The view's `SELECT` over physical tables, with its values inlined.
    subquery: String,
    /// Physical tables the subquery reads.
    tables: Vec<String>,
    /// Declared unique, never-NULL columns; empty disables keyset cursors.
    key: Vec<String>,
    /// Columns declared never NULL, the key included.
    not_null: Vec<String>,
}
/// A read rewritten onto its view.
#[derive(Clone)]
struct Rewritten {
    sql: String,
    view: Option<usize>,
    /// Trailing result columns added for the cursor; `None` if the query can
    /// only continue by offset.
    hidden: Option<usize>,
}
/// The ordering of a query that can continue by key.
struct Keyset {
    /// Ordering columns as written, then the key columns that complete them.
    terms: Vec<String>,
    /// How many of `terms` the query's own `ORDER BY` names.
    ordered: usize,
    descending: bool,
    /// Token indexes of `WHERE`, if present, and of `ORDER`.
    filter: Option<usize>,
    order: usize,
}
fn wrong_cursor() -> Error {
    Error::Rejected("read cursor belongs to another query".into())
}
/// One domain's authorized views and the statements for a read's metadata.
pub(crate) struct ReadPlan {
    views: Vec<View>,
    by_name: HashMap<String, usize>,
    by_source: HashMap<String, Vec<usize>>,
    rewritten: Mutex<HashMap<(String, Option<usize>), Rewritten>>,
    revision: String,
    pending: String,
}
fn denied() -> Error {
    Error::Rejected("read queries require a single bounded SELECT over authorized tables".into())
}
fn invalid_view() -> Error {
    Error::Incompatible("invalid authorized read view".into())
}
fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !name.as_bytes()[0].is_ascii_digit()
}
fn reserved(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.starts_with("rocky_") || name.starts_with("sqlite_")
}
fn unquoted(token: &str) -> &str {
    token.trim_matches(['"', '`', '[', ']'])
}
/// A value as an SQL literal. Only installed view values are inlined.
fn literal(value: &SqlValue) -> Result<String, Error> {
    Ok(match value {
        SqlValue::Null => "NULL".into(),
        SqlValue::Integer(value) => value.to_string(),
        // The shortest text that reads back as the same double.
        SqlValue::Real(value) if value.get().is_finite() => format!("{:?}", value.get()),
        SqlValue::Real(value) if value.get() > 0.0 => "9e999".into(),
        SqlValue::Real(_) => "-9e999".into(),
        SqlValue::Text(text) if text.contains('\0') => return Err(invalid_view()),
        SqlValue::Text(text) => format!("'{}'", text.replace('\'', "''")),
        SqlValue::Blob(bytes) => {
            let mut hex = String::with_capacity(bytes.len() * 2 + 3);
            hex.push_str("X'");
            for byte in bytes {
                use std::fmt::Write;
                let _ = write!(hex, "{byte:02X}");
            }
            hex.push('\'');
            hex
        }
    })
}
impl ReadPlan {
    pub(crate) fn compile(names: &Names, views: Vec<ReadView>) -> Result<Self, Error> {
        let mut compiled: Vec<View> = Vec::new();
        let mut by_name = HashMap::new();
        let mut by_source: HashMap<String, Vec<usize>> = HashMap::new();
        for view in views {
            let name = view.name.to_ascii_lowercase();
            if !identifier(&name) || reserved(&name) || by_name.contains_key(&name) {
                return Err(invalid_view());
            }
            let key: Vec<String> = view.key.iter().map(|c| c.to_ascii_lowercase()).collect();
            let mut not_null = key.clone();
            not_null.extend(view.not_null.iter().map(|c| c.to_ascii_lowercase()));
            if key.len() > MAX_KEYSET_COLUMNS || !not_null.iter().all(|column| identifier(column)) {
                return Err(invalid_view());
            }
            let mut tokens = tokens(&view.sql);
            let significant: Vec<usize> = (0..tokens.len())
                .filter(|index| !tokens[*index].trim().is_empty())
                .collect();
            if !significant
                .first()
                .is_some_and(|index| tokens[*index].eq_ignore_ascii_case("SELECT"))
            {
                return Err(invalid_view());
            }
            let (mut tables, mut sources) = (Vec::new(), Vec::new());
            let mut values = view.values.iter();
            for (position, index) in significant.iter().enumerate() {
                let next = significant
                    .get(position + 1)
                    .map(|next| tokens[*next].as_str());
                let token = tokens[*index].as_str();
                if token == ";" {
                    return Err(invalid_view());
                }
                if token == "?" {
                    // Numbered parameters would not follow `values` in order.
                    if next.is_some_and(|next| next.as_bytes()[0].is_ascii_digit()) {
                        return Err(invalid_view());
                    }
                    tokens[*index] = literal(values.next().ok_or_else(invalid_view)?)?;
                    continue;
                }
                let source =
                    token.eq_ignore_ascii_case("FROM") || token.eq_ignore_ascii_case("JOIN");
                if let (true, Some(table)) = (source, next.filter(|next| *next != "(")) {
                    let logical = unquoted(table).to_ascii_lowercase();
                    let physical = names.physical(&logical).filter(|_| !reserved(&logical));
                    let physical = physical.ok_or_else(invalid_view)?.to_string();
                    if !tables.contains(&physical) {
                        tables.push(physical);
                        sources.push(logical);
                    }
                }
            }
            if values.next().is_some() {
                return Err(invalid_view());
            }
            by_name.insert(name.clone(), compiled.len());
            for source in &sources {
                by_source
                    .entry(source.clone())
                    .or_default()
                    .push(compiled.len());
            }
            compiled.push(View {
                subquery: names.sql(&tokens.concat()),
                tables,
                key,
                not_null,
            });
        }
        Ok(Self {
            views: compiled,
            by_name,
            by_source,
            rewritten: Mutex::new(HashMap::new()),
            revision: names.sql("SELECT revision FROM rocky_replica WHERE id=1"),
            pending: names.sql(
                "SELECT COUNT(*) FROM rocky_operations WHERE status<>'applied' AND status='pending'",
            ),
        })
    }
    pub(crate) fn views(&self) -> usize {
        self.views.len()
    }
    /// Views that read the logical table `table`.
    pub(crate) fn reading<'a>(&'a self, table: &'a str) -> impl Iterator<Item = usize> + 'a {
        self.by_source.get(table).into_iter().flatten().copied()
    }
    /// The read with its table replaced by the authorized view. A query that
    /// can continue by key also returns its ordering columns after its own
    /// and is ordered by the view's key last; `seek` then starts it after the
    /// row with those ordering values, which are bound before the query's own.
    fn rewrite(&self, sql: &str, seek: Option<usize>) -> Result<Rewritten, Error> {
        let key = (sql.to_string(), seek);
        let mut cache = self
            .rewritten
            .lock()
            .map_err(|_| Error::Corrupt("read statement cache".into()))?;
        if let Some(rewritten) = cache.get(&key) {
            return Ok(rewritten.clone());
        }
        let rewritten = self.rewrite_uncached(sql, seek)?;
        if cache.len() >= 256 {
            cache.clear();
        }
        cache.insert(key, rewritten.clone());
        Ok(rewritten)
    }
    fn rewrite_uncached(&self, sql: &str, seek: Option<usize>) -> Result<Rewritten, Error> {
        validate(sql)?;
        let mut tokens = tokens(sql);
        let significant: Vec<usize> = (0..tokens.len())
            .filter(|index| !tokens[*index].trim().is_empty())
            .collect();
        let Some(from) = significant
            .iter()
            .position(|index| tokens[*index].eq_ignore_ascii_case("FROM"))
        else {
            return match seek {
                Some(_) => Err(wrong_cursor()),
                None => Ok(Rewritten {
                    sql: sql.to_string(),
                    view: None,
                    hidden: None,
                }),
            };
        };
        let table = *significant.get(from + 1).ok_or_else(denied)?;
        let name = unquoted(&tokens[table]).to_ascii_lowercase();
        let view = *self.by_name.get(&name).ok_or_else(denied)?;
        // The view keeps its name unless the query gives the table an alias.
        let aliased = significant.get(from + 2).is_some_and(|next| {
            !["WHERE", "GROUP", "ORDER", "LIMIT", "HAVING"]
                .iter()
                .any(|word| tokens[*next].eq_ignore_ascii_case(word))
        });
        let keyset = keyset(&tokens, &significant, from, &self.views[view]);
        let subquery = &self.views[view].subquery;
        tokens[table] = if aliased {
            format!("({subquery})")
        } else {
            format!("({subquery}) AS \"{name}\"")
        };
        let Some(keyset) = keyset else {
            return match seek {
                Some(_) => Err(wrong_cursor()),
                None => Ok(Rewritten {
                    sql: tokens.concat(),
                    view: Some(view),
                    hidden: None,
                }),
            };
        };
        let columns = keyset.terms.join(",");
        tokens[significant[from]] = format!(",{columns} FROM");
        if let Some(values) = seek {
            if values != keyset.terms.len() {
                return Err(wrong_cursor());
            }
            // A row value comparison is one index range, unlike its OR form.
            // It comes first: of two lower bounds on an indexed column the
            // engine seeks with the first, and the query may hold its own.
            let after = format!(
                "({columns}){}({})",
                if keyset.descending { "<" } else { ">" },
                vec!["?"; values].join(",")
            );
            match keyset.filter {
                Some(filter) => {
                    tokens[filter] = format!("WHERE {after} AND (");
                    tokens[keyset.order] = ") ORDER".into();
                }
                None => tokens[keyset.order] = format!(" WHERE {after} ORDER"),
            }
        }
        let direction = if keyset.descending { " DESC" } else { "" };
        for tiebreak in &keyset.terms[keyset.ordered..] {
            tokens.push(format!(",{tiebreak}{direction}"));
        }
        Ok(Rewritten {
            sql: tokens.concat(),
            view: Some(view),
            hidden: Some(keyset.terms.len()),
        })
    }
    /// The view a query reads, if it is valid and names one.
    pub(crate) fn view(&self, sql: &str) -> Option<usize> {
        self.rewrite(sql, None).ok().and_then(|read| read.view)
    }
}
/// The ordering of a query whose pages can continue by key: a plain column
/// list, no grouping or limit, and an `ORDER BY` of plain columns in one
/// direction. Descending orders must name only columns declared never NULL,
/// because the engine sorts NULL last there and a seek would drop those rows.
fn keyset(tokens: &[String], significant: &[usize], from: usize, view: &View) -> Option<Keyset> {
    if view.key.is_empty() {
        return None;
    }
    let token = |position: usize| {
        significant
            .get(position)
            .map(|index| tokens[*index].as_str())
    };
    let column = |token: &str| {
        (!token.starts_with('\'') && identifier(unquoted(token)))
            .then(|| unquoted(token).to_ascii_lowercase())
    };
    let is =
        |position: usize, word: &str| token(position).is_some_and(|t| t.eq_ignore_ascii_case(word));
    // The cursor's values are bound before the query's own, by position.
    if (0..significant.len()).any(|at| {
        is(at, "?") && token(at + 1).is_some_and(|next| next.as_bytes()[0].is_ascii_digit())
    }) {
        return None;
    }
    // `*`, or columns without aliases or expressions: an alias could shadow
    // a column the ordering names.
    let selected = 1..from;
    let star = selected.len() == 1 && is(1, "*");
    let columns = selected.len() % 2 == 1
        && selected.clone().all(|at| match (at - 1) % 2 {
            0 => token(at).and_then(column).is_some(),
            _ => is(at, ","),
        });
    if !star && !columns {
        return None;
    }
    let mut at = from + 2;
    if is(at, "AS") {
        at += 2;
    } else if !is(at, "WHERE") && !is(at, "ORDER") {
        at += 1;
    }
    let filter = is(at, "WHERE").then(|| significant[at]);
    if (at..significant.len()).any(|at| {
        ["GROUP", "HAVING", "LIMIT", "OFFSET"]
            .iter()
            .any(|word| is(at, word))
    }) {
        return None;
    }
    let order = (at..significant.len()).find(|at| is(*at, "ORDER"))?;
    if filter.is_none() && order != at {
        return None;
    }
    if !is(order + 1, "BY") {
        return None;
    }
    let (mut terms, mut names, mut directions) = (Vec::new(), Vec::new(), Vec::new());
    let mut at = order + 2;
    loop {
        let written = token(at)?;
        let name = column(written)?;
        if names.contains(&name) {
            return None;
        }
        terms.push(written.to_string());
        names.push(name);
        at += 1;
        let descending = is(at, "DESC");
        if descending || is(at, "ASC") {
            at += 1;
        }
        directions.push(descending);
        match token(at) {
            None => break,
            Some(",") => at += 1,
            Some(_) => return None,
        }
    }
    let descending = directions[0];
    if directions.iter().any(|direction| *direction != descending)
        || (descending && !names.iter().all(|name| view.not_null.contains(name)))
    {
        return None;
    }
    let ordered = terms.len();
    terms.extend(view.key.iter().filter(|key| !names.contains(key)).cloned());
    (terms.len() <= MAX_KEYSET_COLUMNS).then_some(Keyset {
        terms,
        ordered,
        descending,
        filter,
        order: significant[order],
    })
}
/// The statement restrictions for dynamic reads; see `docs/runtime/app-runtime.md`.
fn validate(sql: &str) -> Result<(), Error> {
    let tokens: Vec<_> = tokens(sql)
        .into_iter()
        .filter(|token| !token.trim().is_empty())
        .collect();
    if !tokens
        .first()
        .is_some_and(|token| token.eq_ignore_ascii_case("SELECT"))
    {
        return Err(denied());
    }
    let mut selects = 0;
    for (index, token) in tokens.iter().enumerate() {
        let word = token
            .trim_matches(['\'', '"', '`', '[', ']'])
            .to_ascii_uppercase();
        if word == "SELECT" {
            selects += 1;
        }
        if token == ";"
            || token == "."
            || word.starts_with("ROCKY_")
            || word.starts_with("SQLITE_")
            || [
                "INSERT",
                "UPDATE",
                "DELETE",
                "CREATE",
                "DROP",
                "ALTER",
                "ATTACH",
                "DETACH",
                "PRAGMA",
                "WITH",
                "JOIN",
                "UNION",
                "INTERSECT",
                "EXCEPT",
                "LOAD_EXTENSION",
                "READFILE",
                "WRITEFILE",
            ]
            .contains(&word.as_str())
        {
            return Err(denied());
        }
        if (token == "-" && tokens.get(index + 1).is_some_and(|next| next == "-"))
            || (token == "/" && tokens.get(index + 1).is_some_and(|next| next == "*"))
        {
            return Err(denied());
        }
        if identifier(&word)
            && tokens.get(index + 1).is_some_and(|next| next == "(")
            && ![
                "COUNT", "SUM", "MIN", "MAX", "LENGTH", "COALESCE", "IN", "NOT", "AND", "OR",
            ]
            .contains(&word.as_str())
        {
            return Err(denied());
        }
    }
    if selects != 1 {
        return Err(denied());
    }
    // Multiple FROM sources can produce an unbounded Cartesian evaluation.
    if let Some(start) = tokens
        .iter()
        .position(|token| token.eq_ignore_ascii_case("FROM"))
    {
        if start + 1 >= tokens.len() {
            return Err(denied());
        }
        for token in tokens.get(start + 2..).unwrap_or(&[]) {
            if ["WHERE", "ORDER", "GROUP", "LIMIT"]
                .iter()
                .any(|word| token.eq_ignore_ascii_case(word))
            {
                break;
            }
            if token == "," || token == "(" {
                return Err(denied());
            }
        }
    }
    Ok(())
}

struct Pooled {
    path: Option<PathBuf>,
    idle: Vec<sqlite::Connection>,
    /// Connections handed to running reads.
    out: usize,
    closed: bool,
}
/// Read-only connections of one file. The file's writer attaches the path
/// once the file is installed and closes the pool before releasing the file.
pub(crate) struct ReadPool {
    permits: tokio::sync::Semaphore,
    state: Mutex<Pooled>,
    returned: Condvar,
}
impl ReadPool {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            permits: tokio::sync::Semaphore::new(POOL_CONNECTIONS),
            state: Mutex::new(Pooled {
                path: None,
                idle: Vec::new(),
                out: 0,
                closed: false,
            }),
            returned: Condvar::new(),
        })
    }
    pub(crate) fn attach(&self, path: PathBuf) {
        if let Ok(mut state) = self.state.lock() {
            state.path = Some(path);
        }
    }
    /// Refuses new reads, waits for running ones and closes every connection.
    /// A running read is bounded by `READ_TRANSACTION_BOUND`.
    pub(crate) fn close(&self) {
        self.permits.close();
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.closed = true;
        while state.out > 0 {
            match self.returned.wait(state) {
                Ok(next) => state = next,
                Err(_) => return,
            }
        }
        state.idle.clear();
    }
    fn checkout(&self) -> Result<sqlite::Connection, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Closed)?;
        if state.closed {
            return Err(Error::Closed);
        }
        let connection = match state.idle.pop() {
            Some(connection) => connection,
            None => {
                let path = state.path.as_ref().ok_or(Error::Closed)?;
                let connection = sqlite::Connection::open_read_only(path)?;
                connection.set_query_only()?;
                connection
            }
        };
        state.out += 1;
        Ok(connection)
    }
    fn checkin(&self, connection: sqlite::Connection) {
        if let Ok(mut state) = self.state.lock() {
            state.out -= 1;
            if !state.closed {
                state.idle.push(connection);
            }
        }
        self.returned.notify_all();
    }
    /// Runs `read` on a blocking thread with one pooled connection.
    async fn run<T: Send + 'static>(
        self: &Arc<Self>,
        read: impl FnOnce(&sqlite::Connection) -> Result<T, Error> + Send + 'static,
    ) -> Result<T, Error> {
        let _permit = self.permits.acquire().await.map_err(|_| Error::Closed)?;
        let pool = self.clone();
        tokio::task::spawn_blocking(move || {
            let connection = pool.checkout()?;
            let result = read(&connection);
            pool.checkin(connection);
            result
        })
        .await
        .map_err(|_| Error::Closed)?
    }
}

/// A validated read, ready to run on any connection of the file.
struct Prepared {
    sql: String,
    tables: Vec<String>,
    binding: Commitment,
    offset: u64,
    /// Trailing ordering columns to strip from every row.
    hidden: Option<usize>,
    /// The cursor's key, bound before the query's values.
    seek: Vec<SqlValue>,
}
type Versions = (u64, u64);
/// The latest result of one observed query, shared by its observers.
#[derive(Default)]
pub(crate) struct SharedRead {
    latest: tokio::sync::Mutex<Option<(Versions, ReadSnapshot)>>,
}
type SharedKey = (Commitment, usize, usize, Option<String>);
/// One domain's read side: its views, their change counters and the file's pool.
pub(crate) struct Reads {
    scope: Scope,
    plan: Arc<ReadPlan>,
    pool: Arc<ReadPool>,
    views: Vec<watch::Receiver<u64>>,
    meta: watch::Receiver<u64>,
    shared: Mutex<HashMap<SharedKey, Weak<SharedRead>>>,
    audit: crate::checkpoint::RowAudit,
    /// The descriptor verified against the installed tables at open.
    logical: std::sync::OnceLock<Arc<rocky_core::LogicalSchema>>,
    /// The worker's table events; gone once the domain closes.
    events: std::sync::OnceLock<Weak<crate::observe::TableEvents>>,
    /// Test hook: reads executed for observers.
    #[cfg(test)]
    pub(crate) executed: std::sync::atomic::AtomicUsize,
}
fn binding(scope: Scope, query: &BoundQuery) -> Commitment {
    let mut bytes = Vec::new();
    for id in [scope.mesh.0, scope.app.0, scope.domain.0] {
        bytes.extend(id);
    }
    bytes.extend((query.sql.len() as u64).to_le_bytes());
    bytes.extend(query.sql.as_bytes());
    for value in &query.values {
        let (tag, content): (u8, &[u8]) = match value {
            SqlValue::Null => (0, &[]),
            SqlValue::Integer(value) => {
                bytes.push(1);
                bytes.extend(value.to_le_bytes());
                continue;
            }
            SqlValue::Text(text) => (2, text.as_bytes()),
            SqlValue::Blob(blob) => (3, blob),
            SqlValue::Real(value) => {
                bytes.push(4);
                bytes.extend(value.bits().to_le_bytes());
                continue;
            }
        };
        bytes.push(tag);
        bytes.extend((content.len() as u64).to_le_bytes());
        bytes.extend(content);
    }
    rocky_core::commitment("rocky.read.cursor.v1", &bytes)
}
impl Reads {
    pub(crate) fn new(
        scope: Scope,
        plan: Arc<ReadPlan>,
        pool: Arc<ReadPool>,
        views: Vec<watch::Receiver<u64>>,
        meta: watch::Receiver<u64>,
        audit: crate::checkpoint::RowAudit,
    ) -> Self {
        Self {
            scope,
            plan,
            pool,
            views,
            meta,
            shared: Mutex::new(HashMap::new()),
            audit,
            logical: Default::default(),
            events: Default::default(),
            #[cfg(test)]
            executed: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    pub(crate) fn logical(&self) -> Option<Arc<rocky_core::LogicalSchema>> {
        self.logical.get().cloned()
    }
    pub(crate) fn bind_events(&self, events: &Arc<crate::observe::TableEvents>) {
        let _ = self.events.set(Arc::downgrade(events));
    }
    /// The domain's table events while it is open.
    pub(crate) fn events(&self) -> Result<Arc<crate::observe::TableEvents>, Error> {
        self.events
            .get()
            .and_then(Weak::upgrade)
            .ok_or(Error::Closed)
    }
    pub(crate) fn bind_logical(&self, schema: rocky_core::LogicalSchema) {
        let _ = self.logical.set(Arc::new(schema));
    }
    /// Compares the stored rows of the projection and of the checkpoint copy
    /// with their digests, in one read snapshot and without holding rows.
    /// Returns the projection's row count. The scan has no time bound; while
    /// it runs the WAL cannot be reset.
    pub(crate) async fn audit_rows(self: &Arc<Self>) -> Result<u64, Error> {
        let audit = self.audit.clone();
        self.pool
            .run(move |conn| {
                let quoted = |name: &str| format!("\"{}\"", name.replace('"', "\"\""));
                conn.set_deadline(None)?;
                conn.run_now("BEGIN")?;
                let result = (|| {
                    let stored = conn.rows(
                        &format!(
                            "SELECT live,shadow FROM {} WHERE id=1",
                            quoted(&audit.marker)
                        ),
                        (),
                    )?;
                    let digest = |column: usize| match stored
                        .first()
                        .and_then(|row| row.get(column))
                    {
                        Some(sqlite::Value::Blob(bytes)) => crate::digest::SetDigest::decode(bytes)
                            .ok_or_else(|| Error::Corrupt("checkpoint state".into())),
                        _ => Err(Error::Corrupt("checkpoint state".into())),
                    };
                    let mut scanned = [crate::digest::SetDigest::default(); 2];
                    for (logical, live, shadow) in &audit.tables {
                        for (digest, table) in scanned.iter_mut().zip([live, shadow]) {
                            conn.scan(
                                &format!("SELECT * FROM {}", quoted(table)),
                                Vec::new(),
                                |row| {
                                    digest.add(&crate::digest::row_hash(logical, row.iter()));
                                    Ok(())
                                },
                            )?;
                        }
                    }
                    if scanned[0] != digest(0)? {
                        return Err(Error::Corrupt(
                            "projection rows differ from their digest".into(),
                        ));
                    }
                    if scanned[1] != digest(1)? {
                        return Err(Error::Corrupt(
                            "checkpoint rows differ from their digest".into(),
                        ));
                    }
                    Ok(scanned[0].count)
                })();
                let ended = conn.run_now("COMMIT");
                let rows = result?;
                ended?;
                Ok(rows)
            })
            .await
    }
    /// Test hook: the change counters an observer of `sql` waits on.
    #[cfg(test)]
    pub(crate) fn counters(&self, sql: &str) -> Versions {
        self.versions(self.plan.view(sql))
    }
    fn prepare(&self, query: &BoundQuery, options: &ReadOptions) -> Result<Prepared, Error> {
        if options.scope != self.scope {
            return Err(rocky_core::ProtocolError::ForeignScope.into());
        }
        if options.max_rows == 0 || options.max_rows > 1024 || query.sql.len() > 8192 {
            return Err(Error::Quota {
                resource: "read query",
                limit: 1024,
            });
        }
        if options.max_bytes == 0 || options.max_bytes > MAX_READ_BYTES {
            return Err(Error::Quota {
                resource: "read result bytes",
                limit: MAX_READ_BYTES,
            });
        }
        let binding = binding(self.scope, query);
        let (offset, seek) = match &options.cursor {
            Some(cursor) if cursor.binding != binding => return Err(wrong_cursor()),
            Some(cursor) => (cursor.offset, cursor.key.clone()),
            None => (0, None),
        };
        let read = self.plan.rewrite(&query.sql, seek.as_ref().map(Vec::len))?;
        Ok(Prepared {
            // Without a key, skipping inside the engine decodes no skipped row.
            sql: if seek.is_none() && offset > 0 {
                format!("SELECT * FROM ({}) LIMIT -1 OFFSET {offset}", read.sql)
            } else {
                read.sql
            },
            tables: read
                .view
                .map_or_else(Vec::new, |view| self.plan.views[view].tables.clone()),
            binding,
            offset,
            hidden: read.hidden,
            seek: seek.unwrap_or_default(),
        })
    }
    pub(crate) async fn read(
        self: &Arc<Self>,
        query: BoundQuery,
        options: ReadOptions,
    ) -> Result<ReadSnapshot, Error> {
        let prepared = self.prepare(&query, &options)?;
        let reads = self.clone();
        self.pool
            .run(move |conn| {
                let values = [prepared.seek.clone(), query.values].concat();
                retried(|| reads.snapshot(conn, &prepared, &values, &options))
            })
            .await
    }
    /// The engine's plan for a read, one line per step.
    pub(crate) async fn explain(
        self: &Arc<Self>,
        query: BoundQuery,
        options: ReadOptions,
    ) -> Result<Vec<String>, Error> {
        let prepared = self.prepare(&query, &options)?;
        self.pool
            .run(move |conn| {
                conn.restrict_reads(Some(prepared.tables))?;
                let plan = conn.rows(
                    &format!("EXPLAIN QUERY PLAN {}", prepared.sql),
                    storage::bindings([prepared.seek, query.values].concat()),
                );
                conn.restrict_reads(None)?;
                plan.map_err(read_error)?
                    .into_iter()
                    .map(|row| match row.into_iter().nth(3) {
                        Some(sqlite::Value::Text(step)) => Ok(step),
                        _ => Err(Error::Corrupt("query plan".into())),
                    })
                    .collect()
            })
            .await
    }
    /// One read transaction: the revision, head and backlog it reports are
    /// those of the snapshot its rows come from.
    fn snapshot(
        &self,
        conn: &sqlite::Connection,
        prepared: &Prepared,
        values: &[SqlValue],
        options: &ReadOptions,
    ) -> Result<ReadSnapshot, Error> {
        conn.set_deadline(Some(
            std::time::Instant::now() + storage::READ_TRANSACTION_BOUND,
        ))?;
        let result = (|| {
            conn.run_now("BEGIN")?;
            let result = (|| {
                let single = |sql: &str| -> Result<Vec<SqlValue>, Error> {
                    let row = conn.rows(sql, ())?.into_iter().next();
                    sql_values(row.ok_or_else(|| Error::Corrupt("read metadata".into()))?)
                };
                let revision = match single(&self.plan.revision)?.as_slice() {
                    [SqlValue::Integer(revision)] => LocalRevision::new(*revision as u64)?,
                    _ => return Err(Error::Corrupt("missing revision".into())),
                };
                let pending_operations = match single(&self.plan.pending)?.as_slice() {
                    [SqlValue::Integer(pending)] => *pending as usize,
                    _ => return Err(Error::Corrupt("pending operations".into())),
                };
                conn.restrict_reads(Some(prepared.tables.clone()))?;
                let page = conn.page(
                    &prepared.sql,
                    storage::bindings(values.to_vec()),
                    options.max_rows,
                    options.max_bytes,
                    prepared.hidden.unwrap_or(0),
                );
                conn.restrict_reads(None)?;
                let page = page.map_err(read_error)?;
                if page.oversized {
                    return Err(Error::Quota {
                        resource: "read result bytes",
                        limit: options.max_bytes,
                    });
                }
                let mut rows = page.rows;
                // The ordering values of the last row. NULL sorts before every
                // value, so such a row continues by offset.
                let mut key = None;
                if let Some(hidden) = prepared.hidden {
                    for row in &mut rows {
                        let visible = row
                            .len()
                            .checked_sub(hidden)
                            .ok_or_else(|| Error::Corrupt("read ordering columns".into()))?;
                        key = Some(row.split_off(visible));
                    }
                }
                let key = key.and_then(|key| {
                    sql_values(key)
                        .ok()
                        .filter(|key| !key.contains(&SqlValue::Null))
                });
                let next = page.more.then_some(ReadCursor {
                    binding: prepared.binding,
                    offset: prepared.offset + rows.len() as u64,
                    key,
                });
                Ok(ReadSnapshot {
                    rows: rows.into_iter().map(sql_values).collect::<Result<_, _>>()?,
                    scope: self.scope,
                    revision,
                    completeness: Completeness::Local { pending_operations },
                    next,
                })
            })();
            // A read transaction has nothing to commit; always end it.
            if !conn.is_autocommit()? {
                conn.run_now("ROLLBACK")?;
            }
            result
        })();
        conn.set_deadline(None)?;
        result
    }
    fn versions(&self, view: Option<usize>) -> Versions {
        (
            view.and_then(|view| self.views.get(view))
                .map_or(0, |view| *view.borrow()),
            *self.meta.borrow(),
        )
    }
    /// Change counters for an observer of `query`: its view's and the domain's.
    pub(crate) fn subscribe(
        &self,
        query: &BoundQuery,
    ) -> (Option<watch::Receiver<u64>>, watch::Receiver<u64>) {
        let view = self.plan.view(&query.sql);
        (
            view.and_then(|view| self.views.get(view)).cloned(),
            self.meta.clone(),
        )
    }
    /// The slot observers of the same query and options share.
    pub(crate) fn share(&self, query: &BoundQuery, options: &ReadOptions) -> Arc<SharedRead> {
        let key = (
            binding(self.scope, query),
            options.max_rows,
            options.max_bytes,
            options.cursor.as_ref().map(ReadCursor::encode),
        );
        let Ok(mut shared) = self.shared.lock() else {
            return Arc::default();
        };
        if let Some(existing) = shared.get(&key).and_then(Weak::upgrade) {
            return existing;
        }
        shared.retain(|_, slot| slot.strong_count() > 0);
        let slot = Arc::<SharedRead>::default();
        shared.insert(key, Arc::downgrade(&slot));
        slot
    }
    /// The query's result at the current change counters. Observers that ask
    /// while nothing changed since the last execution share that result.
    pub(crate) async fn observed(
        self: &Arc<Self>,
        shared: &SharedRead,
        query: &BoundQuery,
        options: ReadOptions,
    ) -> Result<(Versions, ReadSnapshot), Error> {
        let mut latest = shared.latest.lock().await;
        // Sampled before the read starts: its snapshot is at least this new.
        let now = self.versions(self.plan.view(&query.sql));
        if let Some((as_of, snapshot)) = latest.as_ref()
            && *as_of == now
        {
            return Ok((now, snapshot.clone()));
        }
        let snapshot = self.read(query.clone(), options).await?;
        #[cfg(test)]
        self.executed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        *latest = Some((now, snapshot.clone()));
        Ok((now, snapshot))
    }
}
/// Reruns a read while another process briefly holds the file.
fn retried<T>(mut read: impl FnMut() -> Result<T, Error>) -> Result<T, Error> {
    for attempt in 0..storage::TRANSACTION_ATTEMPTS {
        match read() {
            Err(error) if storage::retryable(&error) => {
                if attempt + 1 < storage::TRANSACTION_ATTEMPTS {
                    std::thread::sleep(storage::backoff(attempt));
                }
            }
            result => return result,
        }
    }
    Err(Error::RetryExhausted)
}
fn read_error(error: sqlite::Error) -> Error {
    match error {
        sqlite::Error::Denied => denied(),
        error => error.into(),
    }
}
fn sql_values(row: Vec<sqlite::Value>) -> Result<Vec<SqlValue>, Error> {
    row.into_iter().map(storage::sql_value).collect()
}
/// The logical table a projection statement writes, if it names one.
pub(crate) fn written_table(sql: &str) -> Option<String> {
    let tokens: Vec<_> = tokens(sql)
        .into_iter()
        .filter(|token| !token.trim().is_empty())
        .collect();
    let after = |word: &str| {
        let position = tokens
            .iter()
            .position(|token| token.eq_ignore_ascii_case(word))?;
        tokens.get(position + 1)
    };
    let first = tokens.first()?.to_ascii_uppercase();
    let table = match first.as_str() {
        "INSERT" | "REPLACE" => after("INTO")?,
        "DELETE" => after("FROM")?,
        "UPDATE" => tokens.iter().skip(1).find(|token| {
            !["OR", "ROLLBACK", "ABORT", "REPLACE", "FAIL", "IGNORE"]
                .iter()
                .any(|word| token.eq_ignore_ascii_case(word))
        })?,
        _ => return None,
    };
    Some(unquoted(table).to_ascii_lowercase())
}
/// View change counters and changed tables to publish after a commit.
#[derive(Default)]
pub(crate) struct Changed {
    views: std::collections::BTreeSet<usize>,
    /// Logical tables written, lowercase.
    tables: std::collections::BTreeSet<String>,
    /// A statement's target was not recognized: every view and table may
    /// have changed.
    all: bool,
}
impl Changed {
    /// `views` are those reading the table a statement wrote; `None` if the
    /// statement's target is unknown.
    pub(crate) fn record(&mut self, views: Option<&[usize]>) {
        match views {
            Some(views) => self.views.extend(views),
            None => self.all = true,
        }
    }
    /// A written table; protocol tables are never an observer's.
    pub(crate) fn table(&mut self, table: &str) {
        let table = table.to_ascii_lowercase();
        if !table.starts_with("rocky_") {
            self.tables.insert(table);
        }
    }
    pub(crate) fn merge(&mut self, other: Self) {
        self.views.extend(other.views);
        self.tables.extend(other.tables);
        self.all |= other.all;
    }
    /// Whether any table or view may have changed.
    pub(crate) fn any(&self) -> bool {
        self.all || !self.tables.is_empty() || !self.views.is_empty()
    }
    /// The changed tables; None for every table.
    pub(crate) fn tables(&self) -> Option<&std::collections::BTreeSet<String>> {
        (!self.all).then_some(&self.tables)
    }
    pub(crate) fn publish(&self, views: &[watch::Sender<u64>]) {
        let advance = |view: &watch::Sender<u64>| {
            view.send_modify(|version| *version = version.wrapping_add(1));
        };
        if self.all {
            views.iter().for_each(advance);
        } else {
            self.views
                .iter()
                .filter_map(|index| views.get(*index))
                .for_each(advance);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> Names {
        Names::new(
            Some("ns"),
            &[
                "CREATE TABLE notes(id INTEGER PRIMARY KEY,owner TEXT,body TEXT)",
                "CREATE TABLE tags(id INTEGER PRIMARY KEY,note INTEGER)",
            ],
        )
    }
    fn view(name: &'static str, sql: &'static str, values: Vec<SqlValue>) -> ReadView {
        ReadView {
            name: name.into(),
            sql: sql.into(),
            values,
            ..ReadView::default()
        }
    }
    #[test]
    fn views_inline_their_values_and_map_only_their_own_tables() {
        let plan = ReadPlan::compile(
            &names(),
            vec![view(
                "notes",
                "SELECT id,body FROM notes WHERE owner=? AND body<>?",
                vec![
                    SqlValue::Text("o'brien".into()),
                    SqlValue::Blob(vec![1, 171]),
                ],
            )],
        )
        .unwrap();
        let Rewritten { sql, view, .. } = plan
            .rewrite(
                "SELECT body, 'notes' FROM notes WHERE id=? ORDER BY id",
                None,
            )
            .unwrap();
        assert_eq!(view, Some(0));
        assert_eq!(
            sql,
            "SELECT body, 'notes' FROM (SELECT id,body FROM \"ns_notes\" WHERE owner='o''brien' AND body<>X'01AB') AS \"notes\" WHERE id=? ORDER BY id"
        );
        assert_eq!(plan.views[0].tables, ["ns_notes"]);
        assert_eq!(plan.reading("notes").collect::<Vec<_>>(), [0]);
        assert_eq!(plan.reading("tags").count(), 0);
        // A query's own alias replaces the view's name.
        let sql = plan.rewrite("SELECT n FROM notes AS n", None).unwrap().sql;
        assert!(sql.ends_with(") AS n"), "{sql}");
        // Without a table there is nothing to authorize.
        let bare = plan.rewrite("SELECT 1", None).unwrap();
        assert_eq!((bare.sql.as_str(), bare.view), ("SELECT 1", None));
    }
    fn keyed() -> ReadPlan {
        ReadPlan::compile(
            &names(),
            vec![ReadView {
                name: "notes".into(),
                sql: "SELECT id,owner,body FROM notes WHERE owner<>?".into(),
                values: vec![SqlValue::Text("x".into())],
                key: rocky_core::columns(&["id"]),
                not_null: rocky_core::columns(&["owner"]),
            }],
        )
        .unwrap()
    }
    #[test]
    fn ordered_plain_reads_continue_by_key_and_other_shapes_by_offset() {
        let plan = keyed();
        let source = "(SELECT id,owner,body FROM \"ns_notes\" WHERE owner<>'x') AS \"notes\"";
        // The ordering columns follow the query's own; the key breaks ties.
        let first = plan
            .rewrite("SELECT body FROM notes WHERE body<>? ORDER BY owner", None)
            .unwrap();
        assert_eq!(
            (first.sql, first.hidden),
            (
                format!("SELECT body ,owner,id FROM {source} WHERE body<>? ORDER BY owner,id"),
                Some(2)
            )
        );
        let next = plan
            .rewrite(
                "SELECT body FROM notes WHERE body<>? ORDER BY owner",
                Some(2),
            )
            .unwrap();
        assert_eq!(
            next.sql,
            format!(
                "SELECT body ,owner,id FROM {source} WHERE (owner,id)>(?,?) AND ( body<>? ) ORDER BY owner,id"
            )
        );
        let descending = plan
            .rewrite("SELECT * FROM notes ORDER BY owner DESC, id DESC", Some(2))
            .unwrap();
        assert_eq!(
            descending.sql,
            format!(
                "SELECT * ,owner,id FROM {source}  WHERE (owner,id)<(?,?) ORDER BY owner DESC, id DESC"
            )
        );
        for (sql, keyset) in [
            ("SELECT * FROM notes ORDER BY id", true),
            (
                "SELECT id, body FROM notes n WHERE id>? ORDER BY \"body\" ASC, id",
                true,
            ),
            ("SELECT body FROM notes AS n ORDER BY id DESC", true),
            ("SELECT body FROM notes ORDER BY owner DESC", true),
            // No order, or one the runtime cannot seek in.
            ("SELECT body FROM notes", false),
            ("SELECT body FROM notes WHERE id>?", false),
            ("SELECT body FROM notes ORDER BY id LIMIT 5", false),
            ("SELECT body FROM notes ORDER BY owner, id DESC", false),
            ("SELECT body FROM notes ORDER BY LENGTH(body)", false),
            ("SELECT body FROM notes ORDER BY id, id", false),
            ("SELECT body FROM notes ORDER BY 1", false),
            ("SELECT body FROM notes ORDER BY body COLLATE NOCASE", false),
            // `body` may be NULL, which a descending seek would drop.
            ("SELECT id FROM notes ORDER BY body DESC", false),
            // Aliases, expressions, aggregates and groups.
            ("SELECT body AS id FROM notes ORDER BY id", false),
            ("SELECT body id FROM notes ORDER BY id", false),
            ("SELECT COUNT(*) FROM notes ORDER BY id", false),
            ("SELECT DISTINCT body FROM notes ORDER BY id", false),
            (
                "SELECT owner FROM notes GROUP BY owner ORDER BY owner",
                false,
            ),
            ("SELECT body FROM notes WHERE id>?1 ORDER BY id", false),
        ] {
            let read = plan.rewrite(sql, None).unwrap();
            assert_eq!(read.hidden.is_some(), keyset, "{sql}");
            // A key cursor is refused where only an offset can continue.
            let values = read.hidden.unwrap_or(1);
            assert_eq!(plan.rewrite(sql, Some(values)).is_ok(), keyset, "{sql}");
        }
        assert!(plan.rewrite("SELECT 1", Some(1)).is_err());
        // A cursor with another number of values is not this query's.
        assert!(
            plan.rewrite("SELECT * FROM notes ORDER BY owner", Some(1))
                .is_err()
        );
        // A view without a key pages by offset only.
        let unkeyed = ReadPlan::compile(
            &names(),
            vec![view("notes", "SELECT id FROM notes", vec![])],
        )
        .unwrap();
        let read = unkeyed
            .rewrite("SELECT * FROM notes ORDER BY id", None)
            .unwrap();
        assert_eq!(read.hidden, None);
        for (key, not_null) in [(&["no-name"][..], &[][..]), (&["id"], &["a b"])] {
            let invalid = ReadView {
                key: rocky_core::columns(key),
                not_null: rocky_core::columns(not_null),
                ..view("notes", "SELECT id FROM notes", vec![])
            };
            assert!(ReadPlan::compile(&names(), vec![invalid]).is_err());
        }
    }
    /// NULL sorts first ascending: those rows page by offset, then by key.
    #[tokio::test]
    async fn pages_through_null_ordering_values_cover_the_result_once() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("reads.db");
        let conn = sqlite::Connection::open(&path).unwrap();
        for sql in [
            "PRAGMA journal_mode=wal",
            "CREATE TABLE rocky_replica(id INTEGER PRIMARY KEY,revision INTEGER)",
            "CREATE TABLE rocky_operations(status TEXT)",
            "CREATE TABLE notes(id INTEGER PRIMARY KEY,owner TEXT,body TEXT)",
            "INSERT INTO rocky_replica VALUES(1,7)",
        ] {
            conn.rows(sql, ()).unwrap();
        }
        // Ids 1..=9; every third body is NULL, the others repeat two values.
        for id in 1..=9i64 {
            let body = match id % 3 {
                0 => "NULL",
                1 => "'a'",
                _ => "'b'",
            };
            conn.rows(&format!("INSERT INTO notes VALUES({id},'o',{body})"), ())
                .unwrap();
        }
        let schema = ["CREATE TABLE notes(id INTEGER PRIMARY KEY,owner TEXT,body TEXT)"];
        let plan = ReadPlan::compile(
            &Names::new(None, &schema),
            vec![ReadView {
                name: "notes".into(),
                sql: "SELECT id,body FROM notes".into(),
                values: Vec::new(),
                key: rocky_core::columns(&["id"]),
                not_null: rocky_core::columns(&[]),
            }],
        )
        .unwrap();
        let pool = ReadPool::new();
        pool.attach(path);
        let scope = Scope {
            mesh: rocky_core::MeshId([1; 16]),
            app: rocky_core::AppId([2; 16]),
            domain: rocky_core::DomainId([3; 16]),
        };
        let (_, meta) = watch::channel(0);
        let reads = Arc::new(Reads::new(
            scope,
            Arc::new(plan),
            pool.clone(),
            Vec::new(),
            meta,
            crate::checkpoint::RowAudit {
                marker: "rocky_checkpoint".into(),
                tables: Vec::new(),
            },
        ));
        let query = BoundQuery {
            sql: "SELECT id FROM notes WHERE id<? ORDER BY body".into(),
            values: vec![SqlValue::Integer(100)],
        };
        let (mut ids, mut kinds) = (Vec::new(), Vec::new());
        let mut options = ReadOptions::new(scope, 2);
        loop {
            let page = reads.read(query.clone(), options.clone()).await.unwrap();
            assert_eq!(page.revision.get(), 7);
            // Only the selected column is returned.
            assert!(page.rows.iter().all(|row| row.len() == 1));
            ids.extend(page.rows.into_iter().flatten());
            let Some(cursor) = page.next else { break };
            kinds.push(cursor.kind());
            assert_eq!(ReadCursor::decode(&cursor.encode()).unwrap(), cursor);
            options = options.after(cursor);
        }
        assert_eq!(
            ids,
            [3, 6, 9, 1, 4, 7, 2, 5, 8].map(SqlValue::Integer).to_vec()
        );
        use crate::CursorKind::{Keyset, Offset};
        assert_eq!(kinds, [Offset, Keyset, Keyset, Keyset]);
        pool.close();
    }
    #[test]
    fn a_read_can_name_only_a_view() {
        let plan = ReadPlan::compile(
            &names(),
            vec![view("notes", "SELECT id FROM notes", vec![])],
        )
        .unwrap();
        for sql in [
            "SELECT * FROM tags",
            "SELECT * FROM ns_notes",
            "SELECT * FROM \"ns_notes\"",
            "SELECT * FROM ns_rocky_operations",
            "SELECT * FROM rocky_operations",
            "SELECT * FROM notes, notes",
            "SELECT * FROM (SELECT * FROM notes)",
            "SELECT * FROM notes WHERE id IN (SELECT id FROM tags)",
            "SELECT * FROM notes UNION SELECT * FROM notes",
            "SELECT * FROM main.notes",
        ] {
            assert!(
                matches!(plan.rewrite(sql, None), Err(Error::Rejected(_))),
                "{sql}"
            );
        }
    }
    #[test]
    fn views_over_protocol_or_unknown_tables_and_miscounted_values_are_refused() {
        for (sql, values) in [
            ("SELECT * FROM rocky_operations", vec![]),
            ("SELECT * FROM sqlite_schema", vec![]),
            ("SELECT * FROM elsewhere", vec![]),
            ("SELECT id FROM notes JOIN rocky_replica", vec![]),
            ("SELECT id FROM notes WHERE owner=?", vec![]),
            ("SELECT id FROM notes", vec![SqlValue::Integer(1)]),
            (
                "SELECT id FROM notes WHERE owner=?1",
                vec![SqlValue::Integer(1)],
            ),
            ("SELECT id FROM notes; DELETE FROM notes", vec![]),
            ("DELETE FROM notes", vec![]),
        ] {
            assert!(
                matches!(
                    ReadPlan::compile(&names(), vec![view("notes", sql, values)]),
                    Err(Error::Incompatible(_))
                ),
                "{sql}"
            );
        }
        for name in ["rocky_x", "sqlite_x", "no-name", ""] {
            assert!(
                ReadPlan::compile(&names(), vec![view(name, "SELECT id FROM notes", vec![])])
                    .is_err()
            );
        }
    }
    #[test]
    fn projection_statements_name_the_table_they_write() {
        for (sql, table) in [
            ("INSERT INTO Notes VALUES(?,?)", Some("notes")),
            (
                "INSERT OR REPLACE INTO \"notes\"(id) VALUES(?)",
                Some("notes"),
            ),
            ("UPDATE OR IGNORE notes SET body=?", Some("notes")),
            ("DELETE FROM tags WHERE id=?", Some("tags")),
            ("SELECT 1", None),
        ] {
            assert_eq!(written_table(sql).as_deref(), table, "{sql}");
        }
    }
    #[tokio::test]
    async fn the_engine_refuses_tables_outside_a_restricted_read() {
        let conn = sqlite::Connection::open_in_memory().unwrap();
        for sql in [
            "CREATE TABLE a(x)",
            "CREATE TABLE b(x)",
            "INSERT INTO a VALUES(1)",
        ] {
            conn.execute(sql, ()).await.unwrap();
        }
        conn.restrict_reads(Some(vec!["a".into()])).unwrap();
        assert_eq!(
            conn.rows("SELECT COUNT(*),MAX(x) FROM a", ())
                .unwrap()
                .len(),
            1
        );
        for sql in [
            "SELECT * FROM b",
            "SELECT (SELECT x FROM b) FROM a",
            "SELECT * FROM sqlite_schema",
            "INSERT INTO a VALUES(2)",
            "DELETE FROM a",
            "PRAGMA table_info(a)",
            "ATTACH ':memory:' AS other",
        ] {
            assert!(
                matches!(conn.rows(sql, ()), Err(sqlite::Error::Denied)),
                "{sql}"
            );
        }
        conn.restrict_reads(None).unwrap();
        assert!(conn.rows("SELECT * FROM b", ()).unwrap().is_empty());
    }
}
