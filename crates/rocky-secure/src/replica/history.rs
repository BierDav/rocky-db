//! History tables of the live workspace. A change to a live row writes its
//! previous version to the table's history, in the same transaction, while
//! a kept seal still needs it; a kept seal's state is the live rows unchanged
//! since its mark plus the history rows valid at it. See
//! `docs/runtime/kept-seals.md`.
use super::typed::{Typed, quoted};
use super::*;
use rocky_core::Scope;

mod rewind;
pub(super) use rewind::{KeptBound, Rewind};

pub(super) const SCHEMA: &[&str] = &[
    // The live tables' change counter. A change made at `version` records
    // the version it replaces with that number; `paused` while a bulk
    // rebuild records its difference itself, `rows_paused` for stored rows.
    "CREATE TABLE IF NOT EXISTS secure_kept_clock(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,paused INTEGER NOT NULL,rows_paused INTEGER NOT NULL DEFAULT 0)",
    // Kept seals: the counter's value while the live tables held each one,
    // the schema then and each scope's last applied position the seal
    // includes.
    "CREATE TABLE IF NOT EXISTS secure_kept_marks(seal BLOB PRIMARY KEY,mark INTEGER NOT NULL UNIQUE,manifest BLOB NOT NULL,bounds BLOB NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_kept_config(id INTEGER PRIMARY KEY CHECK(id=1),bookmarked INTEGER NOT NULL,latest INTEGER NOT NULL,every INTEGER NOT NULL)",
    // Each kept seal's tables as they were: their columns, and the frozen
    // copy a later removal or migration left in their place.
    "CREATE TABLE IF NOT EXISTS secure_kept_tables(seal BLOB NOT NULL,tab TEXT NOT NULL,columns BLOB NOT NULL,frozen TEXT,PRIMARY KEY(seal,tab)) WITHOUT ROWID",
    rewind::ROWS,
    rewind::ROWS_BY_VERSION,
    rewind::ROWS_DELETE,
    rewind::ROWS_UPDATE,
    rewind::ROWS_INSERT,
];

/// The seals a node keeps, among those of the tips it follows. A seal is
/// kept only once this node finalized it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeptSeals {
    /// The seal each bookmarked tip starts from, or a closed tip's own.
    pub bookmarked: bool,
    /// The latest this many kept seals.
    pub latest: u32,
    /// Every seal.
    pub every: bool,
}

/// Why this node holds a seal's state: it may open a branch there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeldSeal {
    /// History tables keep its state.
    Kept,
    /// Every held scope's replay base sits there, or its state there was
    /// pulled from a node that keeps it.
    Checkpoint,
    /// The live tables hold its state now.
    Live,
}

/// The counter's current value, as triggers read it.
const CLOCK: &str = "COALESCE((SELECT version FROM secure_kept_clock WHERE id=1),1)";
/// Triggers record only while a seal is kept and no bulk rebuild runs.
const ACTIVE: &str = "EXISTS(SELECT 1 FROM secure_kept_marks) AND COALESCE((SELECT paused FROM secure_kept_clock WHERE id=1),0)=0";

pub(super) fn history_name(table: &str) -> String {
    format!("secure_history_{table}")
}
pub(super) fn migration_parent_name(publication: Commitment, index: usize) -> String {
    let hex: String = publication
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("secure_frozen_migration_{hex}_{index}")
}

/// One live table and its history table.
pub(super) struct History {
    pub(super) live: String,
    pub(super) history: String,
    before: String,
    /// Quoted column names, in declaration order.
    pub(super) columns: Vec<String>,
    /// Quoted primary key columns.
    key: Vec<String>,
    /// What each unique index compares.
    uniques: Vec<Unique>,
}
/// One unique index: its quoted columns, then its expressions and predicate
/// as rules over logical column names.
struct Unique {
    columns: Vec<String>,
    expressions: Vec<String>,
    predicate: Option<String>,
}

impl Unique {
    /// `rule` over `image`'s columns. Installed rules always bind.
    fn bound(rule: &str, image: &str) -> Option<String> {
        rocky_core::bind_rule(rule, |name| Some(format!("{image}.{}", quoted(name))))
    }
    /// Whether rows `a` and `b` clash on this index. An unbound rule widens
    /// it, and recording a row that did not clash is harmless.
    fn clash(&self, a: &str, b: &str) -> String {
        let mut terms: Vec<String> = self
            .columns
            .iter()
            .map(|column| format!("{a}.{column} IS {b}.{column}"))
            .collect();
        for rule in &self.expressions {
            if let (Some(left), Some(right)) = (Self::bound(rule, a), Self::bound(rule, b)) {
                terms.push(format!("({left}) IS ({right})"));
            }
        }
        if let Some(rule) = &self.predicate
            && let (Some(left), Some(right)) = (Self::bound(rule, a), Self::bound(rule, b))
        {
            terms.push(format!("({left}) AND ({right})"));
        }
        if terms.is_empty() {
            return "1".into();
        }
        terms.join(" AND ")
    }
}

impl History {
    pub(super) fn of(typed: &Typed) -> Vec<Self> {
        typed
            .tables
            .iter()
            .filter_map(|projected| {
                let logical = typed.rows.schema().table(&projected.table.sql_name)?;
                let column = |name: &str| quoted(name);
                Some(Self {
                    live: quoted(&logical.sql_name),
                    history: quoted(&history_name(&logical.sql_name)),
                    before: quoted(&format!("secure_history_before_{}", logical.sql_name)),
                    columns: logical
                        .columns
                        .iter()
                        .map(|c| column(&c.sql_name))
                        .collect(),
                    key: logical.primary_key.iter().map(|k| column(k)).collect(),
                    uniques: logical
                        .indexes
                        .iter()
                        .filter(|index| index.unique)
                        .map(|index| Unique {
                            columns: index.columns.iter().map(|c| column(&c.name)).collect(),
                            expressions: index.expressions.clone(),
                            predicate: index.predicate.clone(),
                        })
                        .collect(),
                })
            })
            .collect()
    }
    fn list(columns: &[String], image: &str) -> String {
        columns
            .iter()
            .map(|column| format!("{image}.{column}"))
            .collect::<Vec<_>>()
            .join(",")
    }
    fn same(columns: &[String], a: &str, b: &str) -> String {
        columns
            .iter()
            .map(|column| format!("{a}.{column} IS {b}.{column}"))
            .collect::<Vec<_>>()
            .join(" AND ")
    }
    fn differs(&self, a: &str, b: &str) -> String {
        self.columns
            .iter()
            .map(|column| format!("{a}.{column} IS NOT {b}.{column}"))
            .collect::<Vec<_>>()
            .join(" OR ")
    }
    /// Whether a kept seal may still see the version at `image`'s key: one
    /// is marked since that key last changed, as far as history shows.
    fn needed(&self, image: &str) -> String {
        format!(
            "EXISTS(SELECT 1 FROM secure_kept_marks WHERE mark>=COALESCE((SELECT MAX(p.rocky_version) FROM {} AS p WHERE {}),-1))",
            self.history,
            Self::same(&self.key, "p", image)
        )
    }
    fn columns(&self) -> String {
        self.columns.join(",")
    }
    /// Records `image`, a trigger's `OLD`, as replaced now.
    fn record_image(&self, image: &str) -> String {
        format!(
            "INSERT OR IGNORE INTO {}({},rocky_version,rocky_absent) SELECT {},{CLOCK},0 WHERE {};",
            self.history,
            self.columns(),
            Self::list(&self.columns, image),
            self.needed(image)
        )
    }
    /// Records the live rows `filter` selects as replaced now.
    fn record_rows(&self, filter: &str) -> String {
        format!(
            "INSERT OR IGNORE INTO {}({},rocky_version,rocky_absent) SELECT {},{CLOCK},0 FROM {} AS r WHERE ({filter}) AND {};",
            self.history,
            self.columns(),
            Self::list(&self.columns, "r"),
            self.live,
            self.needed("r")
        )
    }
    /// Records that no row was at `image`'s key until now.
    fn record_absent(&self, image: &str) -> String {
        format!(
            "INSERT OR IGNORE INTO {}({},rocky_version,rocky_absent) SELECT {},{CLOCK},1 WHERE NOT EXISTS(SELECT 1 FROM {} AS r WHERE {}) AND {};",
            self.history,
            self.key.join(","),
            Self::list(&self.key, image),
            self.live,
            Self::same(&self.key, "r", image),
            self.needed(image)
        )
    }
    /// The live rows a write of `image` would replace through a unique
    /// index, other than the row at `own`'s key.
    fn conflicts(&self, image: &str, own: &str) -> Vec<String> {
        self.uniques
            .iter()
            .map(|unique| {
                self.record_rows(&format!(
                    "{} AND NOT ({})",
                    unique.clash("r", image),
                    Self::same(&self.key, "r", own)
                ))
            })
            .collect()
    }
    fn trigger(&self, event: &str) -> String {
        let name = self.live.trim_matches('"').replace("\"\"", "\"");
        quoted(&format!("secure_kept_{event}_{name}"))
    }
    pub(super) fn statements(&self) -> Vec<String> {
        let mut statements = vec![format!(
            "CREATE TABLE IF NOT EXISTS {}({},rocky_version INTEGER NOT NULL,rocky_absent INTEGER NOT NULL,PRIMARY KEY({},rocky_version))",
            self.history,
            self.columns(),
            self.key.join(",")
        )];
        statements.push(format!(
            "CREATE TRIGGER IF NOT EXISTS {} BEFORE DELETE ON {} FOR EACH ROW WHEN {ACTIVE} BEGIN {} END",
            self.trigger("delete"),
            self.live,
            self.record_image("OLD")
        ));
        let mut update = vec![
            self.record_image("OLD"),
            self.record_absent("NEW"),
            self.record_rows(&format!(
                "{} AND NOT ({})",
                Self::same(&self.key, "r", "NEW"),
                Self::same(&self.key, "r", "OLD")
            )),
        ];
        update.extend(self.conflicts("NEW", "OLD"));
        statements.push(format!(
            "CREATE TRIGGER IF NOT EXISTS {} BEFORE UPDATE ON {} FOR EACH ROW WHEN {ACTIVE} AND ({}) BEGIN {} END",
            self.trigger("update"),
            self.live,
            self.differs("OLD", "NEW"),
            update.join(" ")
        ));
        // An upsert or a replace changes the row at the key without an
        // update or delete trigger of its own.
        let mut insert = vec![
            self.record_absent("NEW"),
            self.record_rows(&format!(
                "{} AND ({})",
                Self::same(&self.key, "r", "NEW"),
                self.differs("r", "NEW")
            )),
        ];
        insert.extend(self.conflicts("NEW", "NEW"));
        statements.push(format!(
            "CREATE TRIGGER IF NOT EXISTS {} BEFORE INSERT ON {} FOR EACH ROW WHEN {ACTIVE} BEGIN {} END",
            self.trigger("insert"),
            self.live,
            insert.join(" ")
        ));
        statements
    }
    /// Deletes the versions no kept seal needs any more.
    fn prune(&self) -> String {
        format!(
            "DELETE FROM {h} WHERE rowid IN (SELECT h.rowid FROM {h} AS h WHERE NOT EXISTS(SELECT 1 FROM secure_kept_marks AS k WHERE k.mark<h.rocky_version AND k.mark>=COALESCE((SELECT MAX(p.rocky_version) FROM {h} AS p WHERE {} AND p.rocky_version<h.rocky_version),-1)))",
            Self::same(&self.key, "p", "h"),
            h = self.history,
        )
    }
    /// Whether `version` is the version at `mark` of the key `image` names.
    fn at_mark(&self, version: &str, image: &str, mark: i64) -> String {
        format!(
            "{version}.rocky_version=(SELECT MIN(p.rocky_version) FROM main.{h} AS p WHERE {} AND p.rocky_version>{mark})",
            Self::same(&self.key, "p", image),
            h = self.history,
        )
    }
    /// Deletes the live rows that changed since `mark` and differ from
    /// their version then.
    fn rewind_deletes(&self, mark: i64) -> String {
        format!(
            "DELETE FROM main.{live} WHERE EXISTS(SELECT 1 FROM main.{h} AS r WHERE {} AND {} AND (r.rocky_absent=1 OR {}))",
            Self::same(&self.key, "r", &self.live),
            self.at_mark("r", &self.live, mark),
            self.differs("r", &self.live),
            live = self.live,
            h = self.history,
        )
    }
    /// Inserts the versions at `mark` of the keys no live row holds.
    fn rewind_inserts(&self, mark: i64) -> String {
        format!(
            "INSERT INTO main.{live}({}) SELECT {} FROM main.{h} AS r WHERE r.rocky_absent=0 AND {} AND NOT EXISTS(SELECT 1 FROM main.{live} AS l WHERE {})",
            self.columns(),
            Self::list(&self.columns, "r"),
            self.at_mark("r", "r", mark),
            Self::same(&self.key, "l", "r"),
            live = self.live,
            h = self.history,
        )
    }
    /// The table's SQL name.
    pub(super) fn name(&self) -> String {
        unquoted(&self.live)
    }
    /// This table's rows at `mark`, showing `columns`.
    fn select(&self, mark: i64, columns: &[String]) -> String {
        format!(
            "SELECT {} FROM main.{live} AS l WHERE NOT EXISTS(SELECT 1 FROM main.{h} AS p WHERE {} AND p.rocky_version>{mark}) UNION ALL SELECT {} FROM main.{h} AS r WHERE r.rocky_absent=0 AND r.rocky_version=(SELECT MIN(p.rocky_version) FROM main.{h} AS p WHERE {} AND p.rocky_version>{mark})",
            Self::list(columns, "l"),
            Self::same(&self.key, "p", "l"),
            Self::list(columns, "r"),
            Self::same(&self.key, "p", "r"),
            live = self.live,
            h = self.history,
        )
    }
}

/// Whether a schema switch rebuilds the live tables.
#[derive(Default)]
pub(crate) struct Bulk {
    /// A schema switch records its own difference: a rebuild inside it
    /// records nothing, since the new tables' history is not installed yet.
    switching: std::sync::atomic::AtomicBool,
}

impl<A: RowApplication> Inner<A> {
    pub(super) async fn freeze_migration_parents(
        &self,
        stage: &super::staging::SchemaStage,
    ) -> Result<(), Error> {
        let typed = self
            .workspace
            .typed
            .as_ref()
            .ok_or_else(|| denied("migration parents require typed tables"))?;
        for (index, table) in stage.parents.iter().enumerate() {
            let table = typed
                .by_name(table)
                .ok_or_else(|| denied("unknown migration parent table"))?;
            let frozen = migration_parent_name(stage.publication, index);
            self.conn
                .execute(
                    format!(
                        "CREATE TABLE {} AS SELECT * FROM {}",
                        quoted(&frozen),
                        quoted(&table.table.sql_name)
                    ),
                    (),
                )
                .await?;
        }
        Ok(())
    }
    pub(super) async fn drop_migration_parents(
        &self,
        stage: &super::staging::SchemaStage,
    ) -> Result<(), Error> {
        for index in 0..stage.parents.len() {
            self.conn
                .execute(
                    format!(
                        "DROP TABLE IF EXISTS {}",
                        quoted(&migration_parent_name(stage.publication, index))
                    ),
                    (),
                )
                .await?;
        }
        Ok(())
    }
    fn histories(&self) -> Vec<History> {
        self.workspace
            .typed
            .as_deref()
            .map(History::of)
            .unwrap_or_default()
    }
    /// Creates the history table and triggers of every live table, inside
    /// the caller's transaction.
    pub(super) async fn install_history(&self) -> Result<(), Error> {
        match self.workspace.typed.clone() {
            Some(typed) => self.install_history_for(&typed).await,
            None => Ok(()),
        }
    }
    /// `install_history` for the live tables of `typed`.
    pub(super) async fn install_history_for(&self, typed: &Typed) -> Result<(), Error> {
        for history in History::of(typed) {
            // A history table keeps the columns of earlier schemas and
            // gains those a later one adds.
            let known: BTreeSet<String> = collect_rows(
                self.conn
                    .query(
                        "SELECT name FROM pragma_table_info(?)",
                        [history.history.trim_matches('"').replace("\"\"", "\"")],
                    )
                    .await?,
            )
            .await?
            .into_iter()
            .filter_map(|record| match record.as_slice() {
                [SqlValue::Text(name)] => Some(quoted(name).to_ascii_lowercase()),
                _ => None,
            })
            .collect();
            if !known.is_empty() {
                for column in &history.columns {
                    if !known.contains(&column.to_ascii_lowercase()) {
                        self.conn
                            .execute(
                                format!("ALTER TABLE {} ADD COLUMN {column}", history.history),
                                (),
                            )
                            .await?;
                    }
                }
            }
            for sql in history.statements() {
                self.conn.execute(sql, ()).await?;
            }
        }
        Ok(())
    }
    /// Refreshes capture after additive DDL without copying any history rows.
    pub(super) async fn refresh_history_for(&self, typed: &Typed) -> Result<(), Error> {
        for history in History::of(typed) {
            for event in ["insert", "update", "delete"] {
                self.conn
                    .execute(
                        format!("DROP TRIGGER IF EXISTS {}", history.trigger(event)),
                        (),
                    )
                    .await?;
            }
        }
        self.install_history_for(typed).await
    }
    async fn kept(&self) -> Result<bool, Error> {
        Ok(!rows(&self.conn, "SELECT 1 FROM secure_kept_marks LIMIT 1")
            .await?
            .is_empty())
    }
    pub(super) async fn kept_config(&self) -> Result<KeptSeals, Error> {
        let records = rows(
            &self.conn,
            "SELECT bookmarked,latest,every FROM secure_kept_config WHERE id=1",
        )
        .await?;
        match records.first().map(Vec::as_slice) {
            None => Ok(KeptSeals::default()),
            Some(
                [
                    SqlValue::Integer(bookmarked),
                    SqlValue::Integer(latest),
                    SqlValue::Integer(every),
                ],
            ) => Ok(KeptSeals {
                bookmarked: *bookmarked != 0,
                latest: u32::try_from(*latest)
                    .map_err(|_| Error::Corrupt("kept seal count".into()))?,
                every: *every != 0,
            }),
            _ => Err(Error::Corrupt("kept seal configuration".into())),
        }
    }
    /// Kept seals with their marks, oldest first.
    pub(super) async fn kept_marks(&self) -> Result<Vec<(Commitment, i64)>, Error> {
        rows(
            &self.conn,
            "SELECT seal,mark FROM secure_kept_marks ORDER BY mark",
        )
        .await?
        .into_iter()
        .map(|record| match record.as_slice() {
            [SqlValue::Blob(seal), SqlValue::Integer(mark)] => Ok((
                seal.as_slice()
                    .try_into()
                    .map_err(|_| Error::Corrupt("kept seal".into()))?,
                *mark,
            )),
            _ => Err(Error::Corrupt("kept seal".into())),
        })
        .collect()
    }
    /// The seals bookmarks show: a sealed tip's own seal, else the seal its
    /// tip starts from.
    pub(super) fn bookmarked_seals(&self, domain: Scope) -> Result<BTreeSet<Commitment>, Error> {
        let Some(graph) = self.graphs.get(&domain) else {
            return Ok(BTreeSet::new());
        };
        let names: BTreeSet<&str> = graph
            .moves
            .iter()
            .map(|movement| movement.statement.name.as_str())
            .collect();
        let mut seals = BTreeSet::new();
        for name in names {
            let Some(tip) = graph.bookmark(name).map_err(credential)? else {
                continue;
            };
            if let Some(seal) = bookmark_seal(graph, tip)? {
                seals.insert(seal);
            }
        }
        Ok(seals)
    }
    /// Inside the caller's transaction, records that the live tables hold
    /// `seal`'s state now, which includes each scope's applied positions
    /// through its bound.
    pub(super) async fn mark_seal(
        &self,
        seal: Commitment,
        bounds: &[KeptBound],
    ) -> Result<(), Error> {
        if self.workspace.typed.is_none() {
            return Ok(());
        }
        self.conn
            .execute(
                format!("INSERT OR IGNORE INTO secure_kept_marks VALUES(?,{CLOCK},?,?)"),
                [seal.to_vec(), self.manifest.to_vec(), encode(&bounds)?],
            )
            .await?;
        for history in self.histories() {
            let columns: Vec<String> = history.columns.iter().map(|c| unquoted(c)).collect();
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO secure_kept_tables VALUES(?,?,?,NULL)",
                    bindings(vec![
                        SqlValue::Blob(seal.to_vec()),
                        SqlValue::Text(history.name()),
                        SqlValue::Blob(encode(&columns)?),
                    ]),
                )
                .await?;
        }
        self.conn
            .execute(
                "INSERT INTO secure_kept_clock(id,version,paused) VALUES(1,2,0) ON CONFLICT(id) DO UPDATE SET version=version+1",
                (),
            )
            .await?;
        Ok(())
    }
    /// Whether the configuration keeps `seal`, about to be finalized as the
    /// newest seal of the followed path.
    pub(super) async fn keeps_finalized(
        &self,
        domain: Scope,
        seal: Commitment,
    ) -> Result<bool, Error> {
        let config = self.kept_config().await?;
        Ok(self.workspace.typed.is_some()
            && (config.every
                || config.latest > 0
                || (config.bookmarked && self.bookmarked_seals(domain)?.contains(&seal))))
    }
    /// Inside the caller's transaction, releases the kept seals the
    /// configuration no longer names, deleting the versions only they
    /// needed, and keeps a newly named one the live tables hold now.
    pub(super) async fn retain_kept(&self, domain: Scope) -> Result<(), Error> {
        let config = self.kept_config().await?;
        let bookmarked = if config.bookmarked {
            self.bookmarked_seals(domain)?
        } else {
            BTreeSet::new()
        };
        let marks = self.kept_marks().await?;
        let latest = usize::try_from(config.latest).unwrap_or(usize::MAX);
        let mut released = false;
        for (index, (seal, _)) in marks.iter().enumerate() {
            let named = config.every || marks.len() - index <= latest || bookmarked.contains(seal);
            if !named {
                self.release_seal(*seal).await?;
                released = true;
            }
        }
        if released {
            self.prune_history().await?;
        }
        for seal in bookmarked {
            if !marks.iter().any(|(known, _)| *known == seal)
                && let Some(bounds) = self.live_bounds(domain, seal).await?
            {
                self.mark_seal(seal, &bounds).await?;
            }
        }
        Ok(())
    }
    /// Inside the caller's transaction, returns every replayed table to
    /// its rows at kept `seal`, marked `mark`, writing only rows changed
    /// since; a table a switch froze since refills from its copy. Deletes
    /// go first, until a cascade leaves nothing to delete, so every insert
    /// meets the rows the mark saw.
    pub(super) async fn rewind_live(&self, (seal, mark): (Commitment, i64)) -> Result<(), Error> {
        let Some(typed) = self.workspace.typed.as_deref() else {
            return Ok(());
        };
        let frozen: BTreeMap<String, KeptTable> = self
            .kept_tables(seal)
            .await?
            .into_iter()
            .filter(|table| table.frozen.is_some())
            .map(|table| (table.table.to_ascii_lowercase(), table))
            .collect();
        let histories: Vec<History> = History::of(typed)
            .into_iter()
            .filter(|history| {
                typed
                    .rows
                    .schema()
                    .table(&history.name())
                    .is_some_and(|logical| logical.class == rocky_core::TableClass::Replayed)
            })
            .collect();
        for history in &histories {
            self.touch(&history.name());
        }
        self.conn
            .execute("PRAGMA defer_foreign_keys=ON", ())
            .await?;
        let copy = |history: &History| frozen.get(&history.name().to_ascii_lowercase());
        loop {
            let mut deleted = 0;
            for history in &histories {
                let sql = match copy(history) {
                    Some(_) => format!("DELETE FROM main.{}", history.live),
                    None => history.rewind_deletes(mark),
                };
                deleted += self.conn.execute(sql, ()).await?;
            }
            if deleted == 0 {
                break;
            }
        }
        for history in &histories {
            let sql = match copy(history).and_then(|table| table.frozen.as_ref().map(|name| (table, name))) {
                Some((table, name)) => {
                    let columns: Vec<String> = table
                        .columns
                        .iter()
                        .map(|column| quoted(column))
                        .filter(|column| history.columns.contains(column))
                        .collect();
                    format!(
                        "INSERT INTO main.{}({columns}) SELECT {columns} FROM main.{}",
                        history.live,
                        quoted(name),
                        columns = columns.join(",")
                    )
                }
                None => history.rewind_inserts(mark),
            };
            self.conn.execute(sql, ()).await?;
        }
        Ok(())
    }
    /// Deletes the versions of live tables and stored rows that no kept
    /// seal needs.
    async fn prune_history(&self) -> Result<(), Error> {
        for history in self.histories() {
            self.conn.execute(history.prune(), ()).await?;
        }
        self.conn.execute(rewind::PRUNE_ROWS, ()).await?;
        Ok(())
    }
    /// Forgets kept `seal` and drops its frozen copies; the caller prunes
    /// the history it alone needed.
    pub(super) async fn release_seal(&self, seal: Commitment) -> Result<(), Error> {
        for table in self.kept_tables(seal).await? {
            if let Some(frozen) = table.frozen {
                self.conn
                    .execute(format!("DROP TABLE IF EXISTS {}", quoted(&frozen)), ())
                    .await?;
            }
        }
        for sql in [
            "DELETE FROM secure_kept_marks WHERE seal=?",
            "DELETE FROM secure_kept_tables WHERE seal=?",
        ] {
            self.conn.execute(sql, [seal.to_vec()]).await?;
        }
        self.drop_served(seal).await?;
        Ok(())
    }
    /// The tables kept `seal` shows, as they were there.
    async fn kept_tables(&self, seal: Commitment) -> Result<Vec<KeptTable>, Error> {
        collect_rows(
            self.conn
                .query(
                    "SELECT tab,columns,frozen FROM secure_kept_tables WHERE seal=? ORDER BY tab",
                    [seal.to_vec()],
                )
                .await?,
        )
        .await?
        .into_iter()
        .map(|record| match record.as_slice() {
            [SqlValue::Text(table), SqlValue::Blob(columns), frozen] => Ok(KeptTable {
                table: table.clone(),
                columns: decode(columns)?,
                frozen: match frozen {
                    SqlValue::Text(frozen) => Some(frozen.clone()),
                    _ => None,
                },
            }),
            _ => Err(Error::Corrupt("kept table".into())),
        })
        .collect()
    }
    /// Selects every row table `name` showed at kept `seal`, marked
    /// `mark`, its columns in declared order; none when the seal kept it
    /// under other columns.
    pub(super) async fn kept_scan(
        &self,
        (seal, mark): (Commitment, i64),
        name: &str,
        columns: &[String],
    ) -> Result<Option<String>, Error> {
        let histories = self.histories();
        Ok(self
            .kept_tables(seal)
            .await?
            .into_iter()
            .find(|table| table.table.eq_ignore_ascii_case(name))
            .filter(|table| {
                table.columns.len() == columns.len()
                    && table
                        .columns
                        .iter()
                        .zip(columns)
                        .all(|(kept, column)| kept.eq_ignore_ascii_case(column))
            })
            .and_then(|table| Self::kept_select(&histories, mark, &table))
            .map(|(select, _)| select))
    }
    /// The rows `table` showed at the kept seal marked `mark`, and the
    /// tables that holds them.
    fn kept_select(
        histories: &[History],
        mark: i64,
        table: &KeptTable,
    ) -> Option<(String, String)> {
        let columns: Vec<String> = table.columns.iter().map(|c| quoted(c)).collect();
        match &table.frozen {
            Some(frozen) => Some((
                format!("SELECT {} FROM main.{}", columns.join(","), quoted(frozen)),
                frozen.clone(),
            )),
            None => histories
                .iter()
                .find(|history| history.name().eq_ignore_ascii_case(&table.table))
                .map(|history| (history.select(mark, &columns), unquoted(&history.history))),
        }
    }
    /// Whether the live tables hold `seal`'s state: it is finalized on the
    /// followed path and no held scope applied anything it excludes.
    pub(super) async fn live_at(&self, domain: Scope, seal: Commitment) -> Result<bool, Error> {
        Ok(self.live_bounds(domain, seal).await?.is_some())
    }
    /// `live_at`, with each held scope's last position the seal includes.
    async fn live_bounds(
        &self,
        domain: Scope,
        seal: Commitment,
    ) -> Result<Option<Vec<KeptBound>>, Error> {
        let Some(depth) = self.finalized_depth(domain, seal).await? else {
            return Ok(None);
        };
        let mut bounds = Vec::new();
        for (scope, id) in self.domain_scopes(domain).await? {
            if !self.has_scope_key(scope) {
                continue;
            }
            let bound = match collect_rows(
                self.conn
                    .query(
                        "SELECT position FROM secure_seal_bounds WHERE scope=? AND depth=?",
                        [id, depth],
                    )
                    .await?,
            )
            .await?
            .first()
            .map(Vec::as_slice)
            {
                Some([SqlValue::Integer(position)]) => *position,
                // A compacted seal: its replay base holds the position.
                None => match self.checkpoint_record(id, true).await? {
                    Some(record)
                        if record
                            .signed
                            .as_ref()
                            .and_then(|signed| signed.statement.seal)
                            == Some(seal) =>
                    {
                        record.position
                    }
                    _ => return Ok(None),
                },
                _ => return Err(Error::Corrupt("seal bound".into())),
            };
            bounds.push((id, bound));
            let beyond = collect_rows(
                self.conn
                    .query(
                        "SELECT 1 FROM secure_applied WHERE scope=? AND position>? LIMIT 1",
                        [id, bound],
                    )
                    .await?,
            )
            .await?;
            if !beyond.is_empty() {
                return Ok(None);
            }
        }
        Ok(Some(bounds))
    }
    /// How this node holds `seal`'s state, if it does.
    pub(super) async fn held_seal(
        &self,
        domain: Scope,
        seal: Commitment,
    ) -> Result<Option<HeldSeal>, Error> {
        if self
            .kept_marks()
            .await?
            .iter()
            .any(|(known, _)| *known == seal)
            && self.kept_covers(domain, seal).await?
        {
            return Ok(Some(HeldSeal::Kept));
        }
        if self.live_at(domain, seal).await? {
            return Ok(Some(HeldSeal::Live));
        }
        // A replay base there, or a state pulled from a node that keeps it
        // that still passes the import checks.
        let scopes = self.domain_scopes(domain).await?;
        let mut based = !scopes.is_empty();
        for (_, id) in scopes {
            based &= self.base_seal(id).await? == Some(seal)
                || self.available_pulled_seal(id).await? == Some(seal);
        }
        Ok(based.then_some(HeldSeal::Checkpoint))
    }
    async fn kept_covers(&self, domain: Scope, seal: Commitment) -> Result<bool, Error> {
        let Some(kept) = self.kept_at(seal, None).await? else {
            return Ok(false);
        };
        for (scope, id) in self.domain_scopes(domain).await? {
            if self.has_scope_key(scope) && kept.at(id).is_none() {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// The statements that bind a read-only connection to kept `seal`:
    /// temporary views with the live tables' names and shape, and the
    /// application's views over them.
    pub(super) async fn seal_views(&self, seal: Commitment) -> Result<SealViews, Error> {
        let domain = self
            .graphs
            .iter()
            .find(|(_, graph)| graph.seal_by_id(seal).is_ok())
            .map(|(scope, _)| *scope)
            .ok_or_else(|| denied("unknown seal"))?;
        if !self.kept_covers(domain, seal).await? {
            return Err(denied(
                "this node does not keep every readable scope at that seal",
            ));
        }
        let mark = self
            .kept_marks()
            .await?
            .into_iter()
            .find(|(known, _)| *known == seal)
            .map(|(_, mark)| mark)
            .ok_or_else(|| denied("this node does not keep that seal"))?;
        let typed = self
            .workspace
            .typed
            .as_deref()
            .ok_or_else(|| Error::Incompatible("no typed tables are installed".into()))?;
        let histories = History::of(typed);
        let kept = self.kept_tables(seal).await?;
        let mut statements = Vec::new();
        let mut readable = Vec::new();
        for table in &kept {
            if let Some((select, holder)) = Self::kept_select(&histories, mark, table) {
                statements.push(format!(
                    "CREATE TEMP VIEW {} AS {select}",
                    quoted(&table.table)
                ));
                readable.push(holder);
            }
        }
        // A table added after the seal had no rows there.
        for history in &histories {
            if !kept
                .iter()
                .any(|table| table.table.eq_ignore_ascii_case(&history.name()))
            {
                statements.push(format!(
                    "CREATE TEMP VIEW {} AS SELECT {} FROM main.{} WHERE 0",
                    history.live,
                    history.columns(),
                    history.live
                ));
            }
        }
        for view in &typed.rows.schema().views {
            statements.push(temporary(&view.create_sql));
        }
        Ok(SealViews {
            seal,
            needs: vec![seal],
            statements,
            readable,
        })
    }
}

/// Live tables a projection switch replaces, by name with the columns
/// they had, copied to record what the switch changes in them.
pub(super) struct Switching {
    copied: Vec<(String, Vec<String>)>,
}

/// A table as a kept seal shows it.
#[derive(Clone)]
struct KeptTable {
    table: String,
    /// Its columns there, unquoted.
    columns: Vec<String>,
    /// The copy holding its rows since a removal or migration replaced it.
    frozen: Option<String>,
}

fn unquoted(name: &str) -> String {
    name.strip_prefix('"')
        .and_then(|name| name.strip_suffix('"'))
        .unwrap_or(name)
        .replace("\"\"", "\"")
}

impl SealViews {
    /// Returns a row inside a snapshot while every needed seal is kept.
    pub(super) fn requires(&self) -> String {
        let seals: Vec<String> = self
            .needs
            .iter()
            .map(|seal| {
                format!(
                    "X'{}'",
                    seal.iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                )
            })
            .collect();
        format!(
            "SELECT 1 WHERE (SELECT count(*) FROM secure_kept_marks WHERE seal IN ({}))={}",
            seals.join(","),
            seals.len()
        )
    }
}

impl<A: RowApplication> Inner<A> {
    /// Views for the tables a statement names as `table@seal`, with the
    /// seal in hex, or `table@bookmark`: the kept seal's rows of `table`.
    /// None when it names no history.
    pub(super) async fn history_snapshot(&self) -> Result<HistorySnapshot, Error> {
        let marks = self.kept_marks().await?;
        let mut kept = BTreeMap::new();
        for (seal, _) in &marks {
            kept.insert(*seal, self.kept_tables(*seal).await?);
        }
        Ok(HistorySnapshot {
            typed: self.workspace.typed.clone(),
            marks,
            kept,
            graph: self
                .workspace
                .followed
                .as_ref()
                .and_then(|(scope, _)| self.graphs.get(scope))
                .cloned(),
        })
    }
}
#[derive(Clone)]
pub(super) struct HistorySnapshot {
    typed: Option<Arc<Typed>>,
    marks: Vec<(Commitment, i64)>,
    kept: BTreeMap<Commitment, Vec<KeptTable>>,
    graph: Option<rocky_credentials::TipGraph>,
}
impl HistorySnapshot {
    pub(super) fn named_history<A: RowApplication>(
        &self,
        tables: &BTreeSet<String>,
    ) -> Result<Option<SealViews>, Error> {
        let named: Vec<&String> = tables.iter().filter(|name| name.contains('@')).collect();
        if named.is_empty() {
            return Ok(None);
        }
        let typed = self
            .typed
            .as_deref()
            .ok_or_else(|| Error::Incompatible("no typed tables are installed".into()))?;
        let histories = History::of(typed);
        let marks = &self.marks;
        let mut views = SealViews {
            seal: [0; 32],
            needs: Vec::new(),
            statements: Vec::new(),
            readable: Vec::new(),
        };
        let mut seals = BTreeSet::new();
        for name in named {
            let Some((table, reference)) = name.rsplit_once('@') else {
                continue;
            };
            let history = histories
                .iter()
                .find(|history| history.name().eq_ignore_ascii_case(table));
            let seal = match decode_hex(reference) {
                Some(seal) => seal,
                None => {
                    let graph = self
                        .graph
                        .as_ref()
                        .ok_or_else(|| denied("no bookmark is followed"))?;
                    let tip = graph
                        .bookmark(reference)
                        .map_err(credential)?
                        .ok_or_else(|| denied(&format!("{name} names no seal or bookmark")))?;
                    bookmark_seal(graph, tip)?
                        .ok_or_else(|| denied("the bookmark's tip starts from no seal"))?
                }
            };
            let mark = marks
                .iter()
                .find(|(known, _)| *known == seal)
                .map(|(_, mark)| *mark)
                .ok_or_else(|| denied(&format!("{name}: this node does not keep that seal")))?;
            seals.insert(seal);
            let kept = self.kept.get(&seal).map(Vec::as_slice).unwrap_or_default();
            let shown = kept
                .iter()
                .find(|kept| kept.table.eq_ignore_ascii_case(table))
                .and_then(|kept| Inner::<A>::kept_select(&histories, mark, kept));
            let (select, holder) = match shown {
                Some(shown) => shown,
                None => {
                    let history = history
                        .ok_or_else(|| denied(&format!("{name} names no table's history")))?;
                    (
                        format!(
                            "SELECT {} FROM main.{} WHERE 0",
                            history.columns(),
                            history.live
                        ),
                        unquoted(&history.history),
                    )
                }
            };
            views
                .statements
                .push(format!("CREATE TEMP VIEW {} AS {select}", quoted(name)));
            views.readable.push(holder);
        }
        views.seal = seals.first().copied().unwrap_or_default();
        views.needs = seals.into_iter().collect();
        Ok(Some(views))
    }
}

fn decode_hex(text: &str) -> Option<Commitment> {
    if text.len() != 64 {
        return None;
    }
    (0..64)
        .step_by(2)
        .map(|index| u8::from_str_radix(text.get(index..index + 2)?, 16).ok())
        .collect::<Option<Vec<u8>>>()?
        .try_into()
        .ok()
}

/// Makes an application's `CREATE VIEW` temporary, so its names resolve to
/// the seal's views first.
fn temporary(sql: &str) -> String {
    let trimmed = sql.trim_start();
    match trimmed.get(..12) {
        Some(head) if head.eq_ignore_ascii_case("CREATE VIEW ") => {
            format!("CREATE TEMP VIEW {}", &trimmed[12..])
        }
        _ => trimmed.to_string(),
    }
}

/// The seal a tip's bookmark shows: the tip's own seal once sealed, else
/// the seal it starts from.
pub(super) fn bookmark_seal(
    graph: &rocky_credentials::TipGraph,
    tip: TipId,
) -> Result<Option<Commitment>, Error> {
    if let Some(seal) = graph.seal(tip).map_err(credential)? {
        return Ok(Some(seal.id().map_err(credential)?));
    }
    for seal in &graph.seals {
        if seal.successor().map_err(credential)? == Some(tip) {
            return Ok(Some(seal.id().map_err(credential)?));
        }
    }
    for opening in &graph.openings {
        if opening.tip().map_err(credential)? == tip {
            return Ok(Some(opening.statement.seal));
        }
    }
    Ok(None)
}

/// What binds a read-only connection to a kept seal.
#[derive(Clone, Debug)]
pub struct SealViews {
    pub seal: Commitment,
    /// Every kept seal the views read.
    pub needs: Vec<Commitment>,
    /// Run on the connection before its first read.
    pub statements: Vec<String>,
    /// History tables the views read.
    pub readable: Vec<String>,
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// Names the seals this node keeps from now on. Seals it no longer names
    /// are released at once; a newly named one is kept only if its state is
    /// still at hand: the live tables hold it.
    pub async fn keep_seals(&self, config: KeptSeals) -> Result<(), Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        let domain = inner.workspace.followed.as_ref().map(|(scope, _)| *scope);
        transaction!(inner, |inner| {
            inner
                .conn
                .execute(
                    "INSERT INTO secure_kept_config VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET bookmarked=excluded.bookmarked,latest=excluded.latest,every=excluded.every",
                    [
                        i64::from(config.bookmarked),
                        i64::from(config.latest),
                        i64::from(config.every),
                    ],
                )
                .await?;
            if let Some(domain) = domain {
                inner.retain_kept(domain).await?;
                if config.every || config.latest > 0 {
                    let path = inner.path_seals(domain)?;
                    if let Some(newest) = path.last() {
                        let newest = newest.id().map_err(credential)?;
                        if !inner
                            .kept_marks()
                            .await?
                            .iter()
                            .any(|(seal, _)| *seal == newest)
                            && let Some(bounds) = inner.live_bounds(domain, newest).await?
                        {
                            inner.mark_seal(newest, &bounds).await?;
                        }
                    }
                }
            } else {
                inner.retain_kept_without_graph().await?;
            }
            Ok(())
        })?;
        drop(flush_guard(inner, &self.inner).await?);
        Ok(())
    }
    pub async fn kept_seal_config(&self) -> Result<KeptSeals, Error> {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .kept_config()
            .await
    }
    /// The seals this node keeps, oldest first.
    pub async fn kept_seals(&self) -> Result<Vec<Commitment>, Error> {
        Ok(self
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .kept_marks()
            .await?
            .into_iter()
            .map(|(seal, _)| seal)
            .collect())
    }
    /// How this node holds `seal`'s state; none when it is shallow here.
    pub async fn held_seal(
        &self,
        domain: Scope,
        seal: Commitment,
    ) -> Result<Option<HeldSeal>, Error> {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        inner.graph_for(domain)?;
        inner.held_seal(domain, seal).await
    }
    /// The seal `bookmark` shows: its tip's own seal once sealed, else the
    /// seal its tip starts from.
    pub async fn bookmark_seal(&self, domain: Scope, bookmark: &str) -> Result<Commitment, Error> {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        let graph = inner.graph_for(domain)?;
        let tip = graph
            .bookmark(bookmark)
            .map_err(credential)?
            .ok_or_else(|| denied("no such bookmark"))?;
        bookmark_seal(graph, tip)?.ok_or_else(|| denied("the bookmark's tip starts from no seal"))
    }
    /// What binds a read-only connection to kept `seal`.
    pub async fn seal_views(&self, seal: Commitment) -> Result<SealViews, Error> {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .seal_views(seal)
            .await
    }
}

impl<A: RowApplication> Inner<A> {
    /// Without a followed bookmark there is no seal to keep.
    async fn retain_kept_without_graph(&self) -> Result<(), Error> {
        if self.kept().await? {
            for (seal, _) in self.kept_marks().await? {
                self.release_seal(seal).await?;
            }
            self.prune_history().await?;
        }
        Ok(())
    }
    /// Inside a projection switch's transaction, before the live tables of
    /// `old` make way for those of `new`: each kept seal keeps a frozen
    /// copy of a table the switch removes or narrows, whose history goes;
    /// the other tables are copied to record what the switch changes.
    pub(super) async fn begin_switch_history(
        &self,
        old: &Typed,
        new: &Typed,
    ) -> Result<Option<Switching>, Error> {
        if !self.kept().await? {
            return Ok(None);
        }
        let marks = self.kept_marks().await?;
        let mut copied = Vec::new();
        for history in History::of(old) {
            let name = history.name();
            let remaining: Option<BTreeSet<String>> = new
                .by_name(&name)
                .and_then(|_| new.rows.schema().table(&name))
                .map(|table| {
                    table
                        .columns
                        .iter()
                        .map(|column| column.sql_name.to_ascii_lowercase())
                        .collect()
                });
            let narrowed = remaining.as_ref().is_none_or(|remaining| {
                history
                    .columns
                    .iter()
                    .any(|column| !remaining.contains(&unquoted(column).to_ascii_lowercase()))
            });
            if !narrowed {
                self.copy_before(&history).await?;
                copied.push((name, history.columns.clone()));
                continue;
            }
            for (seal, mark) in &marks {
                for table in self.kept_tables(*seal).await? {
                    if table.frozen.is_some() || !table.table.eq_ignore_ascii_case(&name) {
                        continue;
                    }
                    let Some((select, _)) =
                        Self::kept_select(std::slice::from_ref(&history), *mark, &table)
                    else {
                        continue;
                    };
                    let frozen = format!("secure_frozen_{mark}_{name}");
                    self.conn
                        .execute(format!("CREATE TABLE {} AS {select}", quoted(&frozen)), ())
                        .await?;
                    self.conn
                        .execute(
                            "UPDATE secure_kept_tables SET frozen=? WHERE seal=? AND tab=?",
                            bindings(vec![
                                SqlValue::Text(frozen),
                                SqlValue::Blob(seal.to_vec()),
                                SqlValue::Text(table.table.clone()),
                            ]),
                        )
                        .await?;
                }
            }
            self.conn
                .execute(format!("DROP TABLE IF EXISTS {}", history.history), ())
                .await?;
        }
        self.conn
            .execute(
                "INSERT INTO secure_kept_clock(id,version,paused) VALUES(1,1,1) ON CONFLICT(id) DO UPDATE SET paused=1",
                (),
            )
            .await?;
        self.workspace.bulk.switching.store(true, Ordering::SeqCst);
        Ok(Some(Switching { copied }))
    }
    /// Ends a switch that failed before `end_switch_history`; its
    /// transaction rolls the copies back.
    pub(super) fn abandon_switch_history(&self) {
        self.workspace.bulk.switching.store(false, Ordering::SeqCst);
    }
    /// After the switch installed `new`'s live tables and their history:
    /// records, over the columns they kept, what the switch changed.
    pub(super) async fn end_switch_history(
        &self,
        new: &Typed,
        switching: Option<Switching>,
    ) -> Result<(), Error> {
        let Some(switching) = switching else {
            return Ok(());
        };
        let histories = History::of(new);
        for (name, columns) in switching.copied {
            if let Some(history) = histories
                .iter()
                .find(|history| history.name().eq_ignore_ascii_case(&name))
            {
                self.record_difference(history, &columns).await?;
            }
            self.conn
                .execute(
                    format!(
                        "DROP TABLE IF EXISTS temp.{}",
                        quoted(&format!("secure_history_before_{name}"))
                    ),
                    (),
                )
                .await?;
        }
        self.conn
            .execute("UPDATE secure_kept_clock SET paused=0 WHERE id=1", ())
            .await?;
        self.workspace.bulk.switching.store(false, Ordering::SeqCst);
        Ok(())
    }
    /// Copies `history`'s live rows before a bulk change.
    async fn copy_before(&self, history: &History) -> Result<(), Error> {
        self.conn
            .execute(format!("DROP TABLE IF EXISTS temp.{}", history.before), ())
            .await?;
        self.conn
            .execute(
                format!(
                    "CREATE TEMP TABLE {}({},PRIMARY KEY({}))",
                    history.before,
                    history.columns(),
                    history.key.join(",")
                ),
                (),
            )
            .await?;
        self.conn
            .execute(
                format!(
                    "INSERT INTO temp.{}({cols}) SELECT {cols} FROM main.{}",
                    history.before,
                    history.live,
                    cols = history.columns()
                ),
                (),
            )
            .await?;
        Ok(())
    }
    /// Records, from `history`'s copy, the versions a bulk change replaced
    /// in `columns` and the keys it added.
    async fn record_difference(&self, history: &History, columns: &[String]) -> Result<(), Error> {
        let mut identical = vec![History::same(&history.key, "a", "b")];
        identical.extend(
            columns
                .iter()
                .map(|column| format!("a.{column} IS b.{column}")),
        );
        for sql in [
            format!(
                "INSERT OR IGNORE INTO main.{}({},rocky_version,rocky_absent) SELECT {},{CLOCK},0 FROM temp.{} AS b WHERE NOT EXISTS(SELECT 1 FROM main.{} AS a WHERE {}) AND {}",
                history.history,
                columns.join(","),
                History::list(columns, "b"),
                history.before,
                history.live,
                identical.join(" AND "),
                history.needed("b")
            ),
            format!(
                "INSERT OR IGNORE INTO main.{}({},rocky_version,rocky_absent) SELECT {},{CLOCK},1 FROM main.{} AS a WHERE NOT EXISTS(SELECT 1 FROM temp.{} AS b WHERE {}) AND {}",
                history.history,
                history.key.join(","),
                History::list(&history.key, "a"),
                history.live,
                history.before,
                History::same(&history.key, "b", "a"),
                history.needed("a")
            ),
        ] {
            self.conn.execute(sql, ()).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod unique_tests {
    use super::Unique;

    #[test]
    fn expression_and_partial_indexes_clash_on_their_own_terms() {
        let unique = Unique {
            columns: vec!["\"team\"".into()],
            expressions: vec!["lower(handle)".into()],
            predicate: Some("lead = 1".into()),
        };
        assert_eq!(
            unique.clash("r", "NEW"),
            "r.\"team\" IS NEW.\"team\" AND (lower(r.\"handle\")) IS (lower(NEW.\"handle\")) AND (r.\"lead\" = 1) AND (NEW.\"lead\" = 1)"
        );
    }
}
