//! Row capture for SQL sessions. The write connection's one row hook feeds
//! this sink beside the digest tracker; its statement authorizer asks the
//! gate. Both know tables by their installed classification.
//! See `docs/runtime/sql-sessions.md`.
use crate::{Error, scoped_connection::Names, sqlite::Value, storage};
use rocky_core::{
    Affinity, ColumnClass, KeyColumn, LogicalSchema, SqlValue, TableClass, key_components,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

pub struct Column {
    pub affinity: Affinity,
    pub derived: bool,
    /// SQLite computes it, so an image never writes it.
    pub generated: bool,
}
/// One column as a session's catalog describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogColumn {
    pub name: String,
    pub affinity: Affinity,
    pub not_null: bool,
    pub collation: rocky_core::Collation,
    /// Position in the primary key.
    pub key: Option<usize>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogIndex {
    pub name: String,
    pub columns: Vec<String>,
}
/// A table a session may name, under the name the session uses. The
/// catalog never lists protocol tables, other domains or physical names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogTable {
    pub name: String,
    pub class: TableClass,
    pub writable: bool,
    pub columns: Vec<CatalogColumn>,
    pub indexes: Vec<CatalogIndex>,
}
pub struct Table {
    /// SQL name in the logical schema.
    pub name: String,
    pub physical: String,
    pub class: TableClass,
    /// Position of the owning domain among the plan's parts.
    pub owner: usize,
    without_rowid: bool,
    identity: Option<usize>,
    pub columns: Vec<Column>,
    names: Vec<String>,
    capture_order: Vec<usize>,
    /// Column positions of the primary key, in key order.
    pub key: Vec<usize>,
    key_columns: Vec<KeyColumn>,
    /// Selects one row by its key, every column in declared order.
    pub select: String,
    /// Selects every row, every column in declared order.
    pub scan: String,
    /// Sets the derived columns of one row, then names its key.
    pub restore: Option<String>,
    /// The table as a catalog lists it, under its schema name.
    pub described: CatalogTable,
}
impl Table {
    fn new(table: &rocky_core::LogicalTable, names: &Names, owner: usize) -> Result<Self, Error> {
        let position = |name: &str| {
            table
                .columns
                .iter()
                .position(|column| column.sql_name.eq_ignore_ascii_case(name))
                .ok_or_else(|| Error::Incompatible(format!("missing row {name}")))
        };
        Self::with_identity(
            table,
            names,
            owner,
            Some(position("id")?),
        )
    }
    fn with_identity(
        table: &rocky_core::LogicalTable,
        names: &Names,
        owner: usize,
        identity: Option<usize>,
    ) -> Result<Self, Error> {
        let installed = names
            .physical(&table.sql_name)
            .ok_or_else(|| Error::Incompatible(format!("{} is not installed", table.sql_name)))?
            .to_string();
        let key: Vec<usize> = table
            .primary_key
            .iter()
            .filter_map(|key| {
                table
                    .columns
                    .iter()
                    .position(|c| c.sql_name.eq_ignore_ascii_case(key))
            })
            .collect();
        if key.len() != table.primary_key.len() {
            return Err(Error::Incompatible(format!(
                "primary key of {}",
                table.sql_name
            )));
        }
        let column = |index: &usize| quoted(&table.columns[*index].sql_name);
        let by_key: Vec<String> = key
            .iter()
            .map(|index| format!("{}=?", column(index)))
            .collect();
        let selected: Vec<String> = table.columns.iter().map(|c| quoted(&c.sql_name)).collect();
        let generated = |column: &rocky_core::LogicalColumn| {
            table.class == TableClass::Replayed
                && matches!(column.class, ColumnClass::Derived { .. })
        };
        let derived: Vec<String> = table
            .columns
            .iter()
            .filter(|column| {
                matches!(column.class, ColumnClass::Derived { .. }) && !generated(column)
            })
            .map(|column| format!("{}=?", quoted(&column.sql_name)))
            .collect();
        let without_rowid = crate::scoped_connection::tables(&[&table.create_sql])
            .first()
            .is_some_and(|(_, without_rowid)| *without_rowid);
        let described = CatalogTable {
            name: table.sql_name.clone(),
            class: table.class,
            writable: true,
            columns: table
                .columns
                .iter()
                .map(|column| CatalogColumn {
                    name: column.sql_name.clone(),
                    affinity: column.affinity,
                    not_null: column.not_null,
                    collation: column.collation,
                    key: table
                        .primary_key
                        .iter()
                        .position(|key| key.eq_ignore_ascii_case(&column.sql_name)),
                })
                .collect(),
            indexes: table
                .indexes
                .iter()
                .map(|index| CatalogIndex {
                    name: index.name.clone(),
                    columns: index
                        .columns
                        .iter()
                        .map(|column| column.name.clone())
                        .collect(),
                })
                .collect(),
        };
        Ok(Self {
            described,
            name: table.sql_name.clone(),
            class: table.class,
            owner,
            without_rowid,
            identity,
            columns: table
                .columns
                .iter()
                .map(|column| Column {
                    affinity: column.affinity,
                    derived: matches!(column.class, ColumnClass::Derived { .. })
                        && !generated(column),
                    generated: generated(column),
                })
                .collect(),
            names: table.columns.iter().map(|c| c.sql_name.clone()).collect(),
            capture_order: (0..table.columns.len()).collect(),
            key_columns: key
                .iter()
                .map(|index| KeyColumn {
                    affinity: table.columns[*index].affinity,
                    collation: table.columns[*index].collation,
                })
                .collect(),
            select: format!(
                "SELECT {} FROM {} WHERE {}",
                selected.join(","),
                quoted(&installed),
                by_key.join(" AND ")
            ),
            scan: format!("SELECT {} FROM {}", selected.join(","), quoted(&installed)),
            restore: (!derived.is_empty()).then(|| {
                format!(
                    "UPDATE {} SET {} WHERE {}",
                    quoted(&installed),
                    derived.join(","),
                    by_key.join(" AND ")
                )
            }),
            key,
            physical: installed,
        })
    }
    fn captured(&self) -> bool {
        self.class.typed()
    }
    /// Removes one row by its key.
    pub fn delete_by_key(&self) -> String {
        let by_key: Vec<String> = self
            .key
            .iter()
            .map(|index| format!("{}=?", quoted(&self.names[*index])))
            .collect();
        format!(
            "DELETE FROM {} WHERE {}",
            quoted(&self.physical),
            by_key.join(" AND ")
        )
    }
    fn written(&self) -> impl Iterator<Item = &String> {
        self.names
            .iter()
            .zip(&self.columns)
            .filter(|(_, column)| !column.generated)
            .map(|(name, _)| name)
    }
    /// The values of `image` that `update_image` and `insert_image` bind.
    pub fn stored(&self, image: &[SqlValue]) -> Vec<SqlValue> {
        image
            .iter()
            .zip(&self.columns)
            .filter(|(_, column)| !column.generated)
            .map(|(value, _)| value.clone())
            .collect()
    }
    /// Sets the row of a key to an image in declared column order, without
    /// its generated columns; binds `stored`, then the key.
    pub fn update_image(&self) -> String {
        let columns: Vec<String> = self
            .written()
            .map(|name| format!("{}=?", quoted(name)))
            .collect();
        let by_key: Vec<String> = self
            .key
            .iter()
            .map(|index| format!("{}=?", quoted(&self.names[*index])))
            .collect();
        format!(
            "UPDATE {} SET {} WHERE {}",
            quoted(&self.physical),
            columns.join(","),
            by_key.join(" AND ")
        )
    }
    /// Inserts one row image in declared column order.
    pub fn insert_image(&self) -> String {
        let columns: Vec<String> = self.written().map(|name| quoted(name)).collect();
        format!(
            "INSERT INTO {}({}) VALUES({})",
            quoted(&self.physical),
            columns.join(","),
            vec!["?"; columns.len()].join(",")
        )
    }
    /// A hook or read row as the application sees it: one strict stored
    /// value per declared column.
    pub fn image(&self, values: &[Value]) -> Result<Vec<SqlValue>, String> {
        if values.len() != self.columns.len() {
            return Err(format!("{} changed its columns", self.name));
        }
        values
            .iter()
            .zip(self.columns.iter().zip(&self.names))
            .map(|(value, (column, name))| {
                storage::sql_value(value.clone())
                    .ok()
                    .and_then(|value| column.affinity.store(value).ok())
                    .ok_or_else(|| {
                        format!(
                            "{}.{name} holds a value outside its declared type",
                            self.name
                        )
                    })
            })
            .collect()
    }
    pub fn key_values(&self, image: &[SqlValue]) -> Vec<SqlValue> {
        self.key
            .iter()
            .filter_map(|column| image.get(*column).cloned())
            .collect()
    }
    fn key_bytes(&self, image: &[SqlValue]) -> Result<Vec<u8>, String> {
        key_components(&self.key_columns, &self.key_values(image))
            .map_err(|error| format!("key of {}: {error}", self.name))
    }
    /// The derived columns of `image`, in declared order.
    pub fn derived(&self, image: &[SqlValue]) -> Vec<SqlValue> {
        self.columns
            .iter()
            .zip(image)
            .filter(|(column, _)| column.derived)
            .map(|(_, value)| value.clone())
            .collect()
    }
}

/// The tables a session may name, by physical name. A bound database's plan
/// holds tables of several domains of one file.
pub struct Plan {
    pub tables: Vec<Table>,
    physical: HashMap<String, usize>,
    views: HashSet<String>,
}
/// One domain's tables in a plan. `tables` picks them by SQL name; None
/// takes the whole schema.
pub struct Part<'a> {
    pub schema: &'a LogicalSchema,
    pub names: &'a Names,
    pub tables: Option<Vec<&'a str>>,
}
fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
impl Plan {
    /// Additive DDL may append columns in a different order from the logical
    /// declaration. Capture maps physical hook images back to that declaration.
    pub fn bind_physical_columns(
        &mut self,
        connection: &crate::sqlite::Connection,
    ) -> Result<(), Error> {
        for table in &mut self.tables {
            let rows = connection.rows(
                // Stored generated columns are in hook images.
                "SELECT name FROM pragma_table_xinfo(?) WHERE hidden<>1 ORDER BY cid",
                vec![Value::Text(table.physical.clone())],
            )?;
            let names: Vec<_> = rows
                .iter()
                .filter_map(|row| match row.as_slice() {
                    [Value::Text(name)] => Some(name),
                    _ => None,
                })
                .collect();
            table.capture_order = table
                .names
                .iter()
                .map(|name| {
                    names
                        .iter()
                        .position(|physical| physical.eq_ignore_ascii_case(name))
                        .ok_or_else(|| {
                            Error::Incompatible(format!("{}.{} is not installed", table.name, name))
                        })
                })
                .collect::<Result<_, _>>()?;
        }
        Ok(())
    }
    /// Runtime-owned frozen tables may only be read in this plan.
    pub fn allow_read_only(&mut self, tables: impl IntoIterator<Item = String>) {
        self.views
            .extend(tables.into_iter().map(|name| name.to_ascii_lowercase()));
    }
    pub fn new(schema: &LogicalSchema, names: &Names) -> Result<Self, Error> {
        Self::bound(&[Part {
            schema,
            names,
            tables: None,
        }])
    }
    /// `Table::owner` is the position of a table's part.
    pub fn bound(parts: &[Part<'_>]) -> Result<Self, Error> {
        let mut tables = Vec::new();
        let mut physical = HashMap::new();
        let mut views = HashSet::new();
        for (owner, part) in parts.iter().enumerate() {
            part.schema
                .require_row_identity()
                .map_err(|error| Error::Incompatible(error.to_string()))?;
            let picked: Vec<&rocky_core::LogicalTable> = match &part.tables {
                None => part.schema.tables.iter().collect(),
                Some(names) => names
                    .iter()
                    .map(|name| {
                        part.schema.table(name).ok_or_else(|| {
                            Error::Incompatible(format!("{name} is not a table of its domain"))
                        })
                    })
                    .collect::<Result<_, _>>()?,
            };
            for view in &part.schema.views {
                if let Some(name) = part.names.physical(&view.name) {
                    views.insert(name.to_ascii_lowercase());
                }
            }
            for table in picked {
                let table = Table::new(table, part.names, owner)?;
                physical.insert(table.physical.to_ascii_lowercase(), tables.len());
                tables.push(table);
            }
        }
        Ok(Self {
            tables,
            physical,
            views,
        })
    }
    fn table(&self, physical: &str) -> Option<usize> {
        self.physical.get(&physical.to_ascii_lowercase()).copied()
    }
    /// The session's catalog: each table under the name `visible` gives
    /// it, writable where `writable` allows. Sorted by name.
    pub fn catalog(
        &self,
        visible: impl Fn(&Table) -> Option<String>,
        writable: impl Fn(usize) -> bool,
    ) -> Vec<CatalogTable> {
        let mut catalog: Vec<CatalogTable> = self
            .tables
            .iter()
            .enumerate()
            .filter_map(|(index, table)| {
                let mut described = table.described.clone();
                described.name = visible(table)?;
                described.writable &= writable(index);
                Some(described)
            })
            .collect();
        catalog.sort_by(|a, b| a.name.cmp(&b.name));
        catalog
    }
}

/// What a statement being compiled asks to do.
pub enum Access<'a> {
    Read(&'a str, &'a str),
    Insert(&'a str),
    Delete(&'a str),
    Update(&'a str, &'a str),
    /// Selecting, calling a function or recursing: no table is named.
    Neutral,
    /// Schema changes, pragmas, attachments and transaction control.
    Other,
}
/// The statement authorizer's state. Unarmed, the runtime's own statements
/// compile freely. Armed, a statement may read the session's tables and
/// write the writable ones; anything else is refused.
#[derive(Default)]
pub struct Gate {
    plan: Option<Arc<Plan>>,
    /// Columns the statement assigns, as (table, column).
    assigned: Vec<(usize, usize)>,
    /// Names read without a column that are no session table. The engine
    /// reports a counted common table expression or subquery this way, and
    /// a real table too; see `Connection::compile`.
    unresolved: Vec<String>,
}
impl Gate {
    pub fn arm(&mut self, plan: Option<Arc<Plan>>) {
        self.plan = plan;
        self.assigned.clear();
        self.unresolved.clear();
    }
    pub fn unresolved(&mut self) -> Vec<String> {
        std::mem::take(&mut self.unresolved)
    }
    /// Lets the runtime's own lookup compile while a statement is checked.
    pub fn suspend(&mut self) -> Option<Arc<Plan>> {
        self.plan.take()
    }
    pub fn resume(&mut self, plan: Option<Arc<Plan>>) {
        self.plan = plan;
    }
    pub fn armed(&self) -> bool {
        self.plan.is_some()
    }
    pub fn assigned(&mut self) -> Vec<(usize, usize)> {
        std::mem::take(&mut self.assigned)
    }
    pub fn allows(&mut self, access: Access<'_>) -> bool {
        let Some(plan) = &self.plan else {
            return true;
        };
        let writable = |table: &str| plan.table(table);
        match access {
            Access::Neutral => true,
            Access::Other => false,
            Access::Read(table, column) => {
                let known =
                    plan.table(table).is_some() || plan.views.contains(&table.to_ascii_lowercase());
                if !known && column.is_empty() {
                    self.unresolved.push(table.to_string());
                }
                known || column.is_empty()
            }
            Access::Insert(table) | Access::Delete(table) => writable(table).is_some(),
            Access::Update(table, column) => {
                let Some(index) = writable(table) else {
                    return false;
                };
                if let Some(column) = plan.tables[index]
                    .names
                    .iter()
                    .position(|name| name.eq_ignore_ascii_case(column))
                {
                    self.assigned.push((index, column));
                }
                true
            }
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Mode {
    /// The runtime's own statements: nothing is captured.
    #[default]
    Off,
    /// A session's statement: row changes are the transaction's writes.
    User,
    /// The commit's projection: it must leave the session's rows as they are.
    Reconcile,
}
struct Event {
    table: usize,
    old: Option<Vec<Value>>,
    new: Option<Vec<Value>>,
    /// Columns the statement assigned.
    assigned: Vec<usize>,
    /// The statement failed: its changes may have been undone.
    uncertain: bool,
    bytes: usize,
}
/// One key a transaction touched, folded from its surviving events.
pub struct Touched {
    pub table: usize,
    pub key: Vec<SqlValue>,
    /// The row at the transaction's start.
    pub before: Option<Vec<SqlValue>>,
    /// A surviving statement removed the row from this key.
    pub deleted: bool,
    pub assigned: Vec<bool>,
}
/// Old and new row images of a session's transaction, in statement order.
/// A savepoint rollback truncates them. A failure is latched until the
/// session is disarmed, and the transaction must not commit.
#[derive(Default)]
pub struct Sink {
    mode: Mode,
    plan: Option<Arc<Plan>>,
    events: Vec<Event>,
    bytes: usize,
    /// Most events and bytes one transaction may hold.
    limits: (usize, usize),
    failed: Option<String>,
    /// The running statement inserted a rowid-table row itself.
    inserted: bool,
    /// First event of the running statement.
    statement: usize,
    /// Tables without capture that a statement changed.
    local: Vec<usize>,
}
impl Sink {
    pub fn arm(&mut self, plan: Arc<Plan>, limits: (usize, usize)) {
        *self = Self {
            plan: Some(plan),
            limits,
            ..Self::default()
        };
    }
    pub fn disarm(&mut self) {
        *self = Self::default();
    }
    pub fn begin_statement(&mut self) {
        self.mode = Mode::User;
        self.statement = self.events.len();
        self.inserted = false;
    }
    /// Ends the statement and returns whether it inserted a row itself.
    /// `assigned` is its assignment mask.
    pub fn end_statement(&mut self, failed: bool, assigned: &[(usize, usize)]) -> bool {
        self.mode = Mode::Off;
        for event in self.events.iter_mut().skip(self.statement) {
            event.uncertain = failed;
            event.assigned = assigned
                .iter()
                .filter(|(table, _)| *table == event.table)
                .map(|(_, column)| *column)
                .collect();
        }
        self.inserted
    }
    pub fn mark(&self) -> usize {
        self.events.len()
    }
    /// Tables of the events after `mark`.
    pub fn tables_since(&self, mark: usize) -> Vec<usize> {
        self.events
            .iter()
            .skip(mark)
            .map(|event| event.table)
            .collect()
    }
    /// Forgets the events after `mark`, as a savepoint rollback undid them.
    pub fn truncate(&mut self, mark: usize) {
        self.events.truncate(mark);
        self.bytes = self.events.iter().map(|event| event.bytes).sum();
    }
    pub fn reconcile(&mut self, active: bool) {
        self.mode = if active { Mode::Reconcile } else { Mode::Off };
    }
    pub fn failure(&self) -> Option<String> {
        self.failed.clone()
    }
    pub fn local_tables(&self) -> Vec<usize> {
        self.local.clone()
    }
    pub fn fail(&mut self, reason: impl Into<String>) {
        if self.mode != Mode::Off && self.failed.is_none() {
            self.failed = Some(reason.into());
        }
    }
    /// The hook saw a top-level insert into `table`.
    pub fn inserted(&mut self, table: &str) {
        if self.mode == Mode::User
            && let Some(plan) = &self.plan
            && plan
                .table(table)
                .is_some_and(|index| !plan.tables[index].without_rowid)
        {
            self.inserted = true;
        }
    }
    /// Whether the hook should read the changed row of `table` for `observe`.
    pub fn wants(&mut self, main: bool, table: &str) -> bool {
        let Some(plan) = self.plan.clone().filter(|_| self.mode != Mode::Off) else {
            return false;
        };
        let target = plan.table(table).filter(|_| main);
        // What the runtime's history triggers write is no session's change.
        if main
            && target.is_none()
            && table
                .get(..crate::sqlite::HISTORY_TABLES.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(crate::sqlite::HISTORY_TABLES))
        {
            return false;
        }
        if self.mode == Mode::Reconcile {
            return target.is_some_and(|index| plan.tables[index].captured());
        }
        match target {
            Some(index) if plan.tables[index].captured() => true,
            Some(index) => {
                if !self.local.contains(&index) {
                    self.local.push(index);
                }
                plan.tables[index].identity.is_some()
            }
            _ => {
                self.fail(format!("a statement wrote the unclassified table {table}"));
                false
            }
        }
    }
    pub fn observe(&mut self, table: &str, old: Option<Vec<Value>>, new: Option<Vec<Value>>) {
        let Some(plan) = self.plan.clone() else {
            return;
        };
        let Some(index) = plan.table(table) else {
            return;
        };
        let logical = |image: Option<Vec<Value>>| -> Option<Vec<Value>> {
            image.map(|image| {
                plan.tables[index]
                    .capture_order
                    .iter()
                    .filter_map(|position| image.get(*position).cloned())
                    .collect()
            })
        };
        let (old, new) = (logical(old), logical(new));
        if self.mode == Mode::User
            && let Some(id) = plan.tables[index].identity
        {
            for image in old.iter().chain(&new) {
                if !matches!(image.get(id), Some(Value::Integer(id)) if rocky_core::RowIdentity::from_integer(*id).is_ok())
                {
                    self.fail("application rows require a positive id");
                    return;
                }
            }
            if let (Some(old), Some(new)) = (&old, &new)
                && old.get(id) != new.get(id)
            {
                self.fail("a row's id cannot change");
                return;
            }
            if !plan.tables[index].captured() {
                return;
            }
        }
        if self.mode == Mode::Reconcile {
            let same = match (&old, &new) {
                (Some(old), Some(new)) => {
                    old.len() == new.len()
                        && plan.tables[index]
                            .columns
                            .iter()
                            .zip(old.iter().zip(new))
                            .all(|(column, (old, new))| column.derived || old == new)
                }
                _ => false,
            };
            if !same {
                self.fail(format!(
                    "the projection of {} differs from the transaction's rows",
                    plan.tables[index].name
                ));
            }
            return;
        }
        let bytes = old
            .iter()
            .chain(&new)
            .flatten()
            .map(|value| value.weight() + 8)
            .sum::<usize>()
            + 64;
        if self.events.len() >= self.limits.0 || self.bytes.saturating_add(bytes) > self.limits.1 {
            self.fail("the transaction changed more rows than a session may capture");
            return;
        }
        self.bytes += bytes;
        self.events.push(Event {
            table: index,
            old,
            new,
            assigned: Vec::new(),
            uncertain: false,
            bytes,
        });
    }
    /// The keys the surviving events touched, each with its first state.
    /// Events of a failed statement count as touches only: the final rows
    /// are read from the tables, never taken from an event.
    pub fn freeze(&self) -> Result<Vec<Touched>, String> {
        let Some(plan) = &self.plan else {
            return Ok(Vec::new());
        };
        let mut touched: BTreeMap<(usize, Vec<u8>), Touched> = BTreeMap::new();
        for event in &self.events {
            let table = &plan.tables[event.table];
            let image = |values: &Option<Vec<Value>>| {
                values
                    .as_ref()
                    .map(|values| {
                        let image = table.image(values)?;
                        Ok::<_, String>((table.key_bytes(&image)?, image))
                    })
                    .transpose()
            };
            let (old, new) = (image(&event.old)?, image(&event.new)?);
            let moved = match (&old, &new) {
                (Some((old, _)), Some((new, _))) => old != new,
                (Some(_), None) => true,
                _ => false,
            };
            for (current, (key, image)) in [(true, old), (false, new)]
                .into_iter()
                .filter_map(|(first, image)| image.map(|image| (first, image)))
            {
                let entry = touched
                    .entry((event.table, key))
                    .or_insert_with(|| Touched {
                        table: event.table,
                        key: table.key_values(&image),
                        // The first event of a key shows its first state.
                        before: current.then_some(image),
                        deleted: false,
                        assigned: vec![false; table.columns.len()],
                    });
                if event.uncertain {
                    continue;
                }
                if current && moved {
                    entry.deleted = true;
                }
                if !moved && !current && event.old.is_some() {
                    for column in &event.assigned {
                        if let Some(assigned) = entry.assigned.get_mut(*column) {
                            *assigned = true;
                        }
                    }
                }
            }
        }
        Ok(touched.into_values().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::{Connection, Run};
    use rocky_core::{
        Collation, LOGICAL_SCHEMA_FORMAT, LogicalColumn, LogicalTable, SchemaSource,
    };

    fn column(name: &str, affinity: Affinity, collation: Collation) -> LogicalColumn {
        LogicalColumn {
            sql_name: name.into(),
            affinity,
            not_null: false,
            default: None,
            collation,
            class: ColumnClass::Replicated,
        }
    }
    fn table(name: &str, sql: &str, columns: Vec<LogicalColumn>, key: &[&str]) -> LogicalTable {
        LogicalTable {
            sql_name: name.into(),
            granted_like: None,
            class: TableClass::Replayed,
            create_sql: sql.into(),
            auto_generate: false,
            columns,
            primary_key: key.iter().map(|key| key.to_string()).collect(),
            partition_by: Vec::new(),
            partition_group: None,
            indexes: Vec::new(),
            foreign_keys: Vec::new(),

        }
    }
    const PLAIN: &str = "CREATE TABLE plain(a INTEGER PRIMARY KEY NOT NULL,b TEXT,c REAL)";
    const KEYED: &str = "CREATE TABLE keyed(a TEXT NOT NULL COLLATE NOCASE,b INTEGER NOT NULL,c TEXT,PRIMARY KEY(a,b)) WITHOUT ROWID";
    const CHILD: &str = "CREATE TABLE child(id INTEGER PRIMARY KEY NOT NULL,parent INTEGER REFERENCES plain(a) ON DELETE CASCADE ON UPDATE CASCADE)";
    const LOCAL: &str =
        "CREATE TABLE local(id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,body TEXT)";

    /// A connection with the hook, the gate and four classified tables. The
    /// descriptor is not installable: it only classifies what the raw
    /// engine does, triggers and cascades included.
    fn setup() -> (Connection, Arc<Plan>) {
        let conn = Connection::open_in_memory().unwrap();
        let integer = |name| column(name, Affinity::Integer, Collation::Binary);
        let text = |name| column(name, Affinity::Text, Collation::Binary);
        let mut local = table("local", LOCAL, vec![integer("id"), text("body")], &["id"]);
        local.class = TableClass::LocalOnly;
        let schema = LogicalSchema {
            format: LOGICAL_SCHEMA_FORMAT,
            publisher: [1; 32],
            application: "capture".into(),
            source: SchemaSource {
                kind: "test".into(),
                version: 1,
                identity: "t".into(),
            },
            tables: vec![
                table(
                    "plain",
                    PLAIN,
                    vec![
                        integer("a"),
                        text("b"),
                        column("c", Affinity::Real, Collation::Binary),
                    ],
                    &["a"],
                ),
                table(
                    "keyed",
                    KEYED,
                    vec![
                        column("a", Affinity::Text, Collation::Nocase),
                        integer("b"),
                        text("c"),
                    ],
                    &["a", "b"],
                ),
                table(
                    "child",
                    CHILD,
                    vec![integer("id"), integer("parent")],
                    &["id"],
                ),
                local,
            ],
            views: Vec::new(),
            assertions: Vec::new(),
        };
        let statements = [PLAIN, KEYED, CHILD, LOCAL];
        for sql in statements.iter().chain(&[
            "CREATE TABLE secret(a)",
            "PRAGMA foreign_keys=ON",
            "CREATE TRIGGER mirror AFTER UPDATE OF b ON plain BEGIN \
             INSERT OR REPLACE INTO keyed VALUES(new.b,new.a,'mirrored'); END",
        ]) {
            conn.run_now(sql).unwrap();
        }
        let names = Names::new(None, &statements);
        let tables: Vec<_> = schema
            .tables
            .iter()
            .map(|table| Table::with_identity(table, &names, 0, None).unwrap())
            .collect();
        let physical = tables
            .iter()
            .enumerate()
            .map(|(index, table)| (table.physical.to_ascii_lowercase(), index))
            .collect();
        let plan = Arc::new(Plan {
            tables,
            physical,
            views: HashSet::new(),
        });
        conn.session().unwrap();
        conn.capture()
            .unwrap()
            .lock()
            .unwrap()
            .arm(plan.clone(), (1024, 1 << 20));
        (conn, plan)
    }
    /// Runs one session statement and returns whether it failed.
    fn run(conn: &Connection, plan: &Arc<Plan>, sql: &str) -> bool {
        let session = conn.session().unwrap();
        let capture = conn.capture().unwrap();
        session.gate.lock().unwrap().arm(Some(plan.clone()));
        capture.lock().unwrap().begin_statement();
        let result = conn.session_run(sql, Vec::new(), 1 << 20, true);
        let assigned = session.gate.lock().unwrap().assigned();
        session.gate.lock().unwrap().arm(None);
        let failed = !matches!(result, Ok(Run::Done(_)));
        capture.lock().unwrap().end_statement(failed, &assigned);
        failed
    }
    /// Table, key, whether a first state exists, deleted, assigned columns.
    type Frozen = (usize, Vec<SqlValue>, bool, bool, Vec<bool>);
    fn frozen(conn: &Connection) -> Vec<Frozen> {
        let capture = conn.capture().unwrap();
        let sink = capture.lock().unwrap();
        assert_eq!(sink.failure(), None);
        sink.freeze()
            .unwrap()
            .into_iter()
            .map(|touched| {
                (
                    touched.table,
                    touched.key,
                    touched.before.is_some(),
                    touched.deleted,
                    touched.assigned,
                )
            })
            .collect()
    }
    fn text(value: &str) -> SqlValue {
        SqlValue::Text(value.into())
    }

    #[test]
    fn capture_follows_triggers_cascades_key_changes_and_rollback() {
        let (conn, plan) = setup();
        conn.run_now("INSERT INTO plain VALUES(1,'one',1.5),(2,'two',2.0)")
            .unwrap();
        conn.run_now("INSERT INTO child VALUES(10,1),(11,2)")
            .unwrap();
        conn.run_now("BEGIN").unwrap();
        // A trigger's replace into a WITHOUT ROWID table is captured.
        assert!(!run(&conn, &plan, "UPDATE plain SET b='uno' WHERE a=1"));
        // A key change touches both keys and cascades to the child row.
        assert!(!run(&conn, &plan, "UPDATE plain SET a=3 WHERE a=2"));
        assert_eq!(
            frozen(&conn),
            vec![
                (
                    0,
                    vec![SqlValue::Integer(1)],
                    true,
                    false,
                    vec![false, true, false]
                ),
                (0, vec![SqlValue::Integer(2)], true, true, vec![false; 3]),
                (0, vec![SqlValue::Integer(3)], false, false, vec![false; 3]),
                (
                    1,
                    vec![text("uno"), SqlValue::Integer(1)],
                    false,
                    false,
                    vec![false; 3]
                ),
                (
                    2,
                    vec![SqlValue::Integer(11)],
                    true,
                    false,
                    vec![false, true]
                ),
            ]
        );
        // A savepoint rollback removes exactly its events.
        let mark = conn.capture().unwrap().lock().unwrap().mark();
        conn.run_now("SAVEPOINT s").unwrap();
        assert!(!run(&conn, &plan, "DELETE FROM plain WHERE a=1"));
        assert!(!run(
            &conn,
            &plan,
            "INSERT OR REPLACE INTO keyed VALUES('UNO',1,'again')"
        ));
        assert_eq!(frozen(&conn).len(), 6);
        conn.run_now("ROLLBACK TO s").unwrap();
        conn.capture().unwrap().lock().unwrap().truncate(mark);
        assert_eq!(frozen(&conn).len(), 5);
        // A failed statement's events stay as touches without evidence.
        assert!(run(
            &conn,
            &plan,
            "INSERT INTO plain VALUES(9,'nine',0),(1,'dup',0)"
        ));
        let rows = frozen(&conn);
        assert_eq!(rows.len(), 6);
        assert!(rows.contains(&(0, vec![SqlValue::Integer(9)], false, false, vec![false; 3])));
        // Replacing a key under another spelling is a delete and an insert.
        assert!(!run(
            &conn,
            &plan,
            "INSERT OR REPLACE INTO keyed VALUES('UNO',1,'again')"
        ));
        assert!(frozen(&conn).contains(&(
            1,
            vec![text("uno"), SqlValue::Integer(1)],
            false,
            true,
            vec![false; 3]
        )));
        conn.run_now("ROLLBACK").unwrap();
    }

    #[test]
    fn the_gate_refuses_everything_outside_the_session_tables() {
        let (conn, plan) = setup();
        for refused in [
            "SELECT * FROM secret",
            "INSERT INTO secret VALUES(1)",
            "SELECT name FROM sqlite_schema",
            "SELECT count(*) FROM secret",
            "SELECT count(*) FROM main.secret",
            "WITH secret AS (SELECT 1) SELECT (SELECT count(*) FROM main.secret)",
            "SELECT count(*) FROM sqlite_schema",
            "SELECT name FROM pragma_table_list",
            "SELECT * FROM pragma_table_info('secret')",
            "INSERT INTO plain SELECT a,a,a FROM secret",
            "UPDATE plain SET b=(SELECT a FROM secret)",
            "DELETE FROM sqlite_sequence",
            "CREATE TEMP TABLE scratch(a)",
            "VACUUM",
            "CREATE TABLE other(a)",
            "DROP TABLE plain",
            "PRAGMA user_version=3",
            "ATTACH ':memory:' AS other",
            "BEGIN",
            "CREATE TEMP TRIGGER t AFTER INSERT ON plain BEGIN SELECT 1; END",
        ] {
            let session = conn.session().unwrap();
            session.gate.lock().unwrap().arm(Some(plan.clone()));
            let result = conn.session_run(refused, Vec::new(), 1 << 20, true);
            session.gate.lock().unwrap().arm(None);
            assert!(
                matches!(result, Err(crate::sqlite::Error::Denied)),
                "{refused}"
            );
        }
        assert!(!run(
            &conn,
            &plan,
            "WITH n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<3) INSERT INTO local(body) SELECT x FROM n"
        ));
        assert!(!run(
            &conn,
            &plan,
            "SELECT count(*),random(),datetime('now') FROM plain JOIN keyed ON keyed.b=plain.a"
        ));
        // Counting a subquery or a common table expression names no stored table.
        assert!(!run(
            &conn,
            &plan,
            "SELECT count(*) FROM (SELECT a FROM plain) AS page"
        ));
        assert!(!run(
            &conn,
            &plan,
            "WITH n AS (SELECT a FROM plain) SELECT count(*) FROM n"
        ));
        assert!(!run(&conn, &plan, "SELECT count(*) FROM plain"));
        // A local table is written without capture; an unclassified one latches.
        let capture = conn.capture().unwrap();
        assert_eq!(capture.lock().unwrap().local_tables(), vec![3]);
        assert!(frozen(&conn).is_empty());
        capture.lock().unwrap().begin_statement();
        conn.run_now("INSERT INTO secret VALUES(2)").unwrap();
        capture.lock().unwrap().end_statement(false, &[]);
        assert!(capture.lock().unwrap().failure().is_some());
    }

    #[test]
    fn a_capture_budget_and_an_untyped_value_latch_a_failure() {
        let (conn, plan) = setup();
        conn.capture()
            .unwrap()
            .lock()
            .unwrap()
            .arm(plan.clone(), (2, 1 << 20));
        assert!(!run(
            &conn,
            &plan,
            "INSERT INTO plain VALUES(1,'a',0),(2,'b',0)"
        ));
        assert_eq!(conn.capture().unwrap().lock().unwrap().failure(), None);
        assert!(!run(&conn, &plan, "INSERT INTO plain VALUES(3,'c',0)"));
        assert!(conn.capture().unwrap().lock().unwrap().failure().is_some());
        let capture = conn.capture().unwrap();
        capture.lock().unwrap().arm(plan.clone(), (16, 1 << 20));
        // The engine keeps text a REAL column cannot convert.
        assert!(!run(&conn, &plan, "INSERT INTO plain VALUES(5,'e','abc')"));
        assert!(capture.lock().unwrap().freeze().is_err());
        // The projection may rewrite a row only to the same replicated values.
        capture.lock().unwrap().arm(plan.clone(), (16, 1 << 20));
        capture.lock().unwrap().reconcile(true);
        conn.run_now("UPDATE plain SET c=c WHERE a=1").unwrap();
        assert_eq!(capture.lock().unwrap().failure(), None);
        conn.run_now("UPDATE plain SET c=9.5 WHERE a=1").unwrap();
        assert!(capture.lock().unwrap().failure().is_some());
    }
}
