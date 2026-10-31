//! Intents of replayed tables: a write is checked for deterministic replay
//! and split into one copy per held partition it reaches. Reads of other
//! partitions are evaluated once by the author and bound as values.
use super::{
    Bindings, Checked, Filter, Proof, Refusal, TablePartitions, normalize, parse, prepare, proof,
    propagate, table, table_name, value,
};
use crate::sql::Unavailable;
use rocky_core::{PartitionValue, SqlValue};
use sqlparser::ast::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::ControlFlow,
};

/// Partitions one statement may reach. Each is one frame of the
/// transaction's bundle, so this equals rocky-secure's `MAX_BUNDLE_FRAMES`.
pub const MAX_INTENT_PARTITIONS: usize = 64;

pub use rocky_core::DETERMINISTIC_FUNCTIONS;
/// Date and time functions: deterministic only when every argument is
/// bound and none reads the clock or the local time zone.
const CLOCK_FUNCTIONS: &[&str] = &[
    "date",
    "datetime",
    "julianday",
    "strftime",
    "time",
    "timediff",
    "unixepoch",
];
const CLOCK_KEYWORDS: &[&str] = &["current_date", "current_time", "current_timestamp"];
const CLOCK_ARGUMENTS: &[&str] = &["now", "localtime", "utc"];
const RANDOM_FUNCTIONS: &[&str] = &["random", "randomblob"];
/// Connection state; every `sqlite_` function reads the engine build.
const ENVIRONMENT_FUNCTIONS: &[&str] = &["changes", "last_insert_rowid", "total_changes"];
const TABLE_FUNCTIONS: &[&str] = &["json_each", "json_tree"];
const COLLATIONS: &[&str] = &["binary", "nocase", "rtrim"];
/// Names SQLite may resolve to the rowid, a key each replica assigns itself.
const ROWID: &[&str] = &["rowid", "_rowid_", "oid"];

/// Why a statement cannot replicate as an intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntentRefusal {
    /// A read, or anything else that is not INSERT, UPDATE or DELETE.
    NotAWrite,
    /// CREATE, DROP or ALTER.
    Schema,
    Pragma,
    /// ATTACH or DETACH.
    Attachment,
    /// `load_extension` or a function only an extension provides.
    Extension(String),
    /// A date or time function that may read the clock or the time zone.
    Clock(String),
    Random(String),
    /// A function that reads the connection or the engine build.
    Environment(String),
    /// A function outside [`DETERMINISTIC_FUNCTIONS`].
    UnknownFunction(String),
    UnknownCollation(String),
    RowId,
    /// AUTOINCREMENT in a replayed table's schema.
    Autoincrement,
    /// A write to a partition column would move its row between partitions.
    PartitionMove {
        table: String,
        column: String,
    },
    /// A read of other partitions that refers to the outer statement, so it
    /// cannot be evaluated once.
    CorrelatedSubquery,
    Unavailable {
        table: String,
        reason: Unavailable,
    },
    /// The statement reaches more than [`MAX_INTENT_PARTITIONS`] partitions.
    TooManyPartitions(usize),
    Unsupported(String),
}
impl std::fmt::Display for IntentRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAWrite => f.write_str("only INSERT, UPDATE and DELETE replay"),
            Self::Schema => f.write_str("schema statement"),
            Self::Pragma => f.write_str("pragma"),
            Self::Attachment => f.write_str("attachment"),
            Self::Extension(name) => write!(f, "extension function {name}"),
            Self::Clock(name) => write!(f, "{name} may read the clock or the time zone"),
            Self::Random(name) => write!(f, "random function {name}"),
            Self::Environment(name) => write!(f, "{name} reads the connection or the engine"),
            Self::UnknownFunction(name) => write!(f, "function {name} is not deterministic"),
            Self::UnknownCollation(name) => write!(f, "collation {name}"),
            Self::RowId => f.write_str("rowid keys are assigned per replica"),
            Self::Autoincrement => f.write_str("AUTOINCREMENT keys are assigned per replica"),
            Self::PartitionMove { table, column } => {
                write!(f, "writing {table}.{column} moves the row")
            }
            Self::CorrelatedSubquery => {
                f.write_str("a read of other partitions refers to the outer statement")
            }
            Self::Unavailable { table, reason } => {
                write!(f, "{table} is not available: {reason:?}")
            }
            Self::TooManyPartitions(count) => write!(
                f,
                "the statement reaches {count} partitions, at most {MAX_INTENT_PARTITIONS}"
            ),
            Self::Unsupported(reason) => f.write_str(reason),
        }
    }
}
impl From<Refusal> for IntentRefusal {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::Unsupported(reason) => Self::Unsupported(reason),
            Refusal::Unavailable { table, reason } => Self::Unavailable { table, reason },
        }
    }
}
/// A refused statement, or the caller's failure to evaluate a read.
#[derive(Debug)]
pub enum SplitError<E> {
    Refused(IntentRefusal),
    Evaluate(E),
}
impl<E> From<IntentRefusal> for SplitError<E> {
    fn from(refusal: IntentRefusal) -> Self {
        Self::Refused(refusal)
    }
}
impl<E> From<Refusal> for SplitError<E> {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal.into())
    }
}

/// One copy of a statement, limited to one held partition.
#[derive(Debug)]
pub struct PartitionStatement {
    /// The partition as listed in [`TablePartitions::held`]; empty for an
    /// unpartitioned table.
    pub partition: Vec<SqlValue>,
    pub statement: Checked,
}

/// The table a write names as its target, lowercase; `None` for anything
/// `split_intent` would refuse before looking at a target.
pub fn written_table(sql: &str, views: &[rocky_core::LogicalView]) -> Option<String> {
    target(&prepare(sql, views).ok()?.statement)
        .ok()
        .map(|(name, _)| name)
}

/// Checks an assertion: one deterministic `SELECT` reading only `tables`,
/// each filtered to its held partitions whether or not the `SELECT` names
/// them, so that it sees exactly the transaction's partition.
pub fn check_assertion(
    sql: &str,
    views: &[rocky_core::LogicalView],
    tables: &BTreeMap<String, TablePartitions>,
) -> Result<Checked, IntentRefusal> {
    let prepared = prepare(sql, views)?;
    let statement = &prepared.statement;
    if !matches!(statement, Statement::Query(_)) {
        return Err(IntentRefusal::Unsupported(
            "an assertion is one SELECT".into(),
        ));
    }
    let mut bindings = Bindings {
        params: &[],
        placeholders: BTreeMap::new(),
        values: BTreeMap::new(),
        numbers: BTreeMap::new(),
    };
    if let ControlFlow::Break(error) = statement.visit(&mut bindings) {
        return Err(IntentRefusal::Unsupported(error));
    }
    if bindings.bind().map_err(IntentRefusal::Unsupported)? != 0 {
        return Err(IntentRefusal::Unsupported(
            "an assertion binds no parameters".into(),
        ));
    }
    if let ControlFlow::Break(refusal) = statement.visit(&mut Determinism {
        bindings: &bindings,
    }) {
        return Err(refusal);
    }
    if let Some(name) = prepared
        .tables()
        .iter()
        .find(|name| !tables.contains_key(*name))
    {
        return Err(IntentRefusal::Unsupported(format!(
            "the assertion reads {name}, which is not one of its tables"
        )));
    }
    Ok(prepared.check_assertion(&[], tables)?)
}

/// Refuses a replayed table's schema whose keys replicas would assign.
pub fn check_replayed_table(create_sql: &str) -> Result<(), IntentRefusal> {
    if crate::scoped_connection::tokens(create_sql)
        .iter()
        .any(|token| token.eq_ignore_ascii_case("autoincrement"))
    {
        return Err(IntentRefusal::Autoincrement);
    }
    Ok(())
}

/// Checks a write to a replayed table and splits it into one copy per held
/// partition it reaches, in `held` order; no copy means it changes nothing
/// held here. `evaluate` runs a read of other partitions on the snapshot
/// the statement executed on and returns its rows. Each distinct read runs
/// once and its result is bound into every copy.
pub fn split_intent<E>(
    sql: &str,
    params: &[SqlValue],
    views: &[rocky_core::LogicalView],
    tables: &BTreeMap<String, TablePartitions>,
    evaluate: impl FnMut(&Checked) -> Result<Rows, E>,
) -> Result<Vec<PartitionStatement>, SplitError<E>> {
    split_intent_within(sql, params, views, tables, MAX_INTENT_PARTITIONS, evaluate)
}

/// [`split_intent`] reaching at most `limit` partitions. A migration
/// replays each partition's copy as its own transaction, so it is not
/// bound by one bundle's frames.
pub fn split_intent_within<E>(
    sql: &str,
    params: &[SqlValue],
    views: &[rocky_core::LogicalView],
    tables: &BTreeMap<String, TablePartitions>,
    limit: usize,
    mut evaluate: impl FnMut(&Checked) -> Result<Rows, E>,
) -> Result<Vec<PartitionStatement>, SplitError<E>> {
    let prepared = prepare(sql, views).map_err(|refusal| keyword(sql).unwrap_or(refusal.into()))?;
    let mut statement = prepared.statement.clone();
    if !matches!(
        statement,
        Statement::Insert(_) | Statement::Update(_) | Statement::Delete(_)
    ) {
        let refusal = keyword(sql).unwrap_or_else(|| {
            IntentRefusal::Unsupported(format!(
                "{} statements",
                statement
                    .to_string()
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
            ))
        });
        return Err(refusal.into());
    }
    let mut bindings = Bindings {
        params,
        placeholders: BTreeMap::new(),
        values: BTreeMap::new(),
        numbers: BTreeMap::new(),
    };
    if let ControlFlow::Break(error) = statement.visit(&mut bindings) {
        return Err(IntentRefusal::Unsupported(error).into());
    }
    let used = bindings.bind().map_err(IntentRefusal::Unsupported)?;
    if used != params.len() {
        return Err(IntentRefusal::Unsupported(format!(
            "the statement uses {used} parameters, {} were given",
            params.len()
        ))
        .into());
    }
    if let ControlFlow::Break(refusal) = statement.visit(&mut Determinism {
        bindings: &bindings,
    }) {
        return Err(refusal.into());
    }
    // Numbered parameters keep their places wherever values are added.
    let unfiltered = BTreeMap::new();
    let _ = VisitMut::visit(
        &mut statement,
        &mut Filter {
            tables: &unfiltered,
            reads: Vec::new(),
            numbers: &bindings.numbers,
            params: Vec::new(),
        },
    );
    let (name, seed) = target(&statement)?;
    let rule = tables.get(&name).cloned().unwrap_or(TablePartitions {
        columns: Vec::new(),
        complete: true,
        held: Vec::new(),
        waiting: Vec::new(),
    });
    if rule.columns.is_empty() && !rule.complete {
        return Err(IntentRefusal::Unavailable {
            table: name,
            reason: Unavailable::NotHeld,
        }
        .into());
    }
    writes(&statement, &name, &rule)?;
    let normalized = |tuples: &[Vec<SqlValue>]| {
        tuples
            .iter()
            .map(|tuple| {
                rule.columns
                    .iter()
                    .zip(tuple)
                    .map(|(column, value)| normalize(column, value))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(IntentRefusal::Unsupported)
    };
    let mut split = Split {
        held: normalized(&rule.held)?,
        waiting: normalized(&rule.waiting)?,
        tables,
        name,
        seed,
        rule: &rule,
        bindings: &bindings,
        values: params.to_vec(),
        reads: BTreeMap::new(),
        copy: Vec::new(),
        partition: Vec::new(),
        evaluate: &mut evaluate,
    };
    let reached = match &mut statement {
        Statement::Insert(insert) => split.insert(insert)?,
        Statement::Update(update) => split.pinned(update.selection.as_ref())?,
        Statement::Delete(delete) => split.pinned(delete.selection.as_ref())?,
        _ => Vec::new(),
    };
    if reached.len() > limit {
        return Err(IntentRefusal::TooManyPartitions(reached.len()).into());
    }
    let mut copies = Vec::with_capacity(reached.len());
    for (index, rows) in reached {
        let mut copy = statement.clone();
        if let (Some(rows), Statement::Insert(insert)) = (rows, &mut copy)
            && let Some(source) = &mut insert.source
            && let SetExpr::Values(values) = &mut *source.body
        {
            let mut row = 0;
            values.rows.retain(|_| {
                row += 1;
                rows.binary_search(&(row - 1)).is_ok()
            });
        }
        let partition = index.map_or_else(Vec::new, |index| rule.held[index].clone());
        split.partition = index.map_or_else(Vec::new, |index| split.held[index].clone());
        split.copy = partition.clone();
        if let ControlFlow::Break(error) = VisitMut::visit(&mut copy, &mut split) {
            return Err(error);
        }
        let only = BTreeMap::from([(
            split.name.clone(),
            TablePartitions {
                columns: rule.columns.clone(),
                complete: rule.columns.is_empty(),
                held: vec![partition.clone()],
                waiting: Vec::new(),
            },
        )]);
        let mut filter = Filter {
            tables: &only,
            reads: Vec::new(),
            numbers: &BTreeMap::new(),
            params: split.values.clone(),
        };
        if let ControlFlow::Break(error) = VisitMut::visit(&mut copy, &mut filter) {
            return Err(IntentRefusal::Unsupported(error).into());
        }
        let params = compact(&mut copy, &filter.params)?;
        copies.push(PartitionStatement {
            partition,
            statement: Checked {
                sql: copy.to_string(),
                params,
            },
        });
    }
    Ok(copies)
}

/// The refusal a statement's leading keyword names, if any.
fn keyword(sql: &str) -> Option<IntentRefusal> {
    let tokens = crate::scoped_connection::tokens(sql);
    let word = tokens.iter().find(|token| !token.trim().is_empty())?;
    Some(match word.to_ascii_uppercase().as_str() {
        "CREATE" | "DROP" | "ALTER" => IntentRefusal::Schema,
        "PRAGMA" => IntentRefusal::Pragma,
        "ATTACH" | "DETACH" => IntentRefusal::Attachment,
        "SELECT" | "VALUES" => IntentRefusal::NotAWrite,
        _ => return None,
    })
}

/// The written table and, for UPDATE and DELETE, the name its row goes by.
fn target(statement: &Statement) -> Result<(String, Option<String>), IntentRefusal> {
    let unsupported = |what: &str| {
        Err(IntentRefusal::Unsupported(format!(
            "{what} in a replayed statement"
        )))
    };
    match statement {
        Statement::Insert(insert) => {
            if !insert.assignments.is_empty() {
                return unsupported("INSERT … SET");
            }
            if matches!(insert.on, Some(OnInsert::DuplicateKeyUpdate(_))) {
                return unsupported("ON DUPLICATE KEY");
            }
            match &insert.table {
                TableObject::TableName(name) => match table_name(name) {
                    Some(name) => Ok((name, None)),
                    None => unsupported("a qualified table"),
                },
                _ => unsupported("a table function target"),
            }
        }
        Statement::Update(update) => {
            if update.from.is_some() {
                return unsupported("UPDATE … FROM");
            }
            if update.limit.is_some() || !update.order_by.is_empty() {
                return unsupported("UPDATE … LIMIT");
            }
            match table(&update.table.relation) {
                Some((name, alias)) if update.table.joins.is_empty() => Ok((name, Some(alias))),
                _ => unsupported("this UPDATE target"),
            }
        }
        Statement::Delete(delete) => {
            if !delete.tables.is_empty() || delete.using.is_some() {
                return unsupported("DELETE from several tables");
            }
            if delete.limit.is_some() || !delete.order_by.is_empty() {
                return unsupported("DELETE … LIMIT");
            }
            let (FromTable::WithFromKeyword(from) | FromTable::WithoutKeyword(from)) = &delete.from;
            match from.as_slice() {
                [item] if item.joins.is_empty() => match table(&item.relation) {
                    Some((name, alias)) => Ok((name, Some(alias))),
                    None => unsupported("this DELETE target"),
                },
                _ => unsupported("this DELETE target"),
            }
        }
        _ => Err(IntentRefusal::NotAWrite),
    }
}

/// Refuses written columns that are rowids or partition columns.
fn writes(statement: &Statement, table: &str, rule: &TablePartitions) -> Result<(), IntentRefusal> {
    let mut columns: Vec<&ObjectName> = Vec::new();
    let mut assignments: Vec<&Assignment> = Vec::new();
    match statement {
        Statement::Insert(insert) => {
            columns.extend(&insert.columns);
            if let Some(OnInsert::OnConflict(OnConflict {
                action: OnConflictAction::DoUpdate(update),
                ..
            })) = &insert.on
            {
                assignments.extend(&update.assignments);
            }
        }
        Statement::Update(update) => assignments.extend(&update.assignments),
        _ => {}
    }
    let named = |name: &ObjectName| match name.0.last() {
        Some(ObjectNamePart::Identifier(ident)) => ident.value.to_ascii_lowercase(),
        _ => name.to_string().to_ascii_lowercase(),
    };
    for column in columns.iter().map(|name| named(name)) {
        if ROWID.contains(&column.as_str()) {
            return Err(IntentRefusal::RowId);
        }
    }
    for assignment in assignments {
        let targets = match &assignment.target {
            AssignmentTarget::ColumnName(name) => std::slice::from_ref(name),
            AssignmentTarget::Tuple(names) => names.as_slice(),
        };
        for column in targets.iter().map(named) {
            if ROWID.contains(&column.as_str()) {
                return Err(IntentRefusal::RowId);
            }
            if rule
                .columns
                .iter()
                .any(|partition| partition.name.eq_ignore_ascii_case(&column))
            {
                return Err(IntentRefusal::PartitionMove {
                    table: table.into(),
                    column,
                });
            }
        }
    }
    Ok(())
}

/// The determinism rules over every expression and table source.
struct Determinism<'a> {
    bindings: &'a Bindings<'a>,
}
impl Determinism<'_> {
    fn function(&self, function: &Function) -> Result<(), IntentRefusal> {
        let name = match function.name.0.as_slice() {
            [ObjectNamePart::Identifier(name)] => name.value.to_ascii_lowercase(),
            _ => return Err(IntentRefusal::UnknownFunction(function.name.to_string())),
        };
        if CLOCK_KEYWORDS.contains(&name.as_str()) {
            return Err(IntentRefusal::Clock(name));
        }
        if CLOCK_FUNCTIONS.contains(&name.as_str()) {
            let FunctionArguments::List(list) = &function.args else {
                return Err(IntentRefusal::Clock(name));
            };
            let bound = |arg: &FunctionArg| match arg {
                FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)) => {
                    match value(expr, self.bindings) {
                        Some(SqlValue::Text(text)) => !CLOCK_ARGUMENTS
                            .iter()
                            .any(|word| text.trim().eq_ignore_ascii_case(word)),
                        Some(_) => true,
                        None => false,
                    }
                }
                _ => false,
            };
            if list.args.is_empty() || !list.args.iter().all(bound) {
                return Err(IntentRefusal::Clock(name));
            }
            return Ok(());
        }
        if RANDOM_FUNCTIONS.contains(&name.as_str()) {
            return Err(IntentRefusal::Random(name));
        }
        if ENVIRONMENT_FUNCTIONS.contains(&name.as_str()) || name.starts_with("sqlite_") {
            return Err(IntentRefusal::Environment(name));
        }
        if crate::statement::DENIED_FUNCTIONS.contains(&name.as_str()) {
            return Err(IntentRefusal::Extension(name));
        }
        if DETERMINISTIC_FUNCTIONS.contains(&name.as_str()) {
            return Ok(());
        }
        Err(IntentRefusal::UnknownFunction(name))
    }
}
impl Visitor for Determinism<'_> {
    type Break = IntentRefusal;
    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<IntentRefusal> {
        if query.with.is_some() {
            return ControlFlow::Break(IntentRefusal::Unsupported(
                "WITH in a replayed statement".into(),
            ));
        }
        ControlFlow::Continue(())
    }
    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<IntentRefusal> {
        let refused = match factor {
            TableFactor::Table { name, args, .. } => {
                let last = match name.0.last() {
                    Some(ObjectNamePart::Identifier(ident)) => ident.value.to_ascii_lowercase(),
                    _ => name.to_string(),
                };
                if args.is_some() && !TABLE_FUNCTIONS.contains(&last.as_str()) {
                    Some(IntentRefusal::UnknownFunction(last))
                } else if crate::statement::reserved(&last) {
                    Some(IntentRefusal::Environment(last))
                } else {
                    None
                }
            }
            TableFactor::Derived { .. } | TableFactor::NestedJoin { .. } => None,
            other => Some(IntentRefusal::Unsupported(format!("table source {other}"))),
        };
        match refused {
            Some(refusal) => ControlFlow::Break(refusal),
            None => ControlFlow::Continue(()),
        }
    }
    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<IntentRefusal> {
        let rowid = |ident: &Ident| {
            ROWID
                .iter()
                .any(|name| ident.value.eq_ignore_ascii_case(name))
        };
        let refused = match expr {
            Expr::Function(function) => self.function(function).err(),
            Expr::Identifier(ident)
                if ident.quote_style.is_none()
                    && CLOCK_KEYWORDS
                        .iter()
                        .any(|word| ident.value.eq_ignore_ascii_case(word)) =>
            {
                Some(IntentRefusal::Clock(ident.value.to_ascii_lowercase()))
            }
            Expr::Identifier(ident) if rowid(ident) => Some(IntentRefusal::RowId),
            Expr::CompoundIdentifier(parts) if parts.last().is_some_and(rowid) => {
                Some(IntentRefusal::RowId)
            }
            Expr::Collate { collation, .. } => match collation.0.as_slice() {
                [ObjectNamePart::Identifier(name)]
                    if COLLATIONS
                        .iter()
                        .any(|known| name.value.eq_ignore_ascii_case(known)) =>
                {
                    None
                }
                _ => Some(IntentRefusal::UnknownCollation(collation.to_string())),
            },
            _ => None,
        };
        match refused {
            Some(refusal) => ControlFlow::Break(refusal),
            None => ControlFlow::Continue(()),
        }
    }
}

/// Result rows of an evaluated read.
type Rows = Vec<Vec<SqlValue>>;
/// Each reached held partition (None when unpartitioned) and, for an
/// INSERT of several partitions, its rows.
type Reached = Vec<(Option<usize>, Option<Vec<usize>>)>;
/// Splits one statement; as a visitor, binds the reads of one copy that
/// leave its partition.
struct Split<'a, E> {
    tables: &'a BTreeMap<String, TablePartitions>,
    name: String,
    /// The outer row's name, which a subquery may equate partition columns to.
    seed: Option<String>,
    rule: &'a TablePartitions,
    held: Vec<Vec<PartitionValue>>,
    waiting: Vec<Vec<PartitionValue>>,
    bindings: &'a Bindings<'a>,
    /// The caller's parameters, then each bound value.
    values: Vec<SqlValue>,
    /// Evaluated reads by their text.
    reads: BTreeMap<String, Rows>,
    /// The current copy's partition, as held and normalized.
    copy: Vec<SqlValue>,
    partition: Vec<PartitionValue>,
    evaluate: &'a mut dyn FnMut(&Checked) -> Result<Rows, E>,
}
impl<E> Split<'_, E> {
    /// The held partition of a tuple, refusing one that waits or is not held.
    fn locate(&self, tuple: &[SqlValue]) -> Result<usize, IntentRefusal> {
        let tuple = self
            .rule
            .columns
            .iter()
            .zip(tuple)
            .map(|(column, value)| normalize(column, value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(IntentRefusal::Unsupported)?;
        if let Some(index) = self.held.iter().position(|held| *held == tuple) {
            return Ok(index);
        }
        Err(IntentRefusal::Unavailable {
            table: self.name.clone(),
            reason: if self.waiting.contains(&tuple) {
                Unavailable::Incomplete
            } else {
                Unavailable::NotHeld
            },
        })
    }
    /// The held partitions an UPDATE or DELETE reaches: those its filter
    /// pins, or every held one. One that waits refuses the write.
    fn pinned(&self, selection: Option<&Expr>) -> Result<Reached, IntentRefusal> {
        if self.rule.columns.is_empty() {
            return Ok(vec![(None, None)]);
        }
        let alias = self.seed.clone().unwrap_or_else(|| self.name.clone());
        let mut found = Proof::default();
        if let Some(selection) = selection {
            proof(
                selection,
                &[(self.name.clone(), alias.clone())],
                self.bindings,
                &mut found,
            );
        }
        propagate(&mut found);
        let pins = self
            .rule
            .columns
            .iter()
            .map(|column| {
                found
                    .values
                    .get(&(alias.clone(), column.name.to_ascii_lowercase()))
                    .map(|values| {
                        values
                            .iter()
                            .map(|value| normalize(column, value))
                            .collect::<Result<BTreeSet<_>, _>>()
                    })
                    .transpose()
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(IntentRefusal::Unsupported)?;
        let matches = |tuple: &&Vec<PartitionValue>| {
            pins.iter()
                .zip(tuple.iter())
                .all(|(pin, value)| pin.as_ref().is_none_or(|pin| pin.contains(value)))
        };
        if self.waiting.iter().any(|tuple| matches(&tuple)) {
            return Err(IntentRefusal::Unavailable {
                table: self.name.clone(),
                reason: Unavailable::Incomplete,
            });
        }
        let reached: Reached = self
            .held
            .iter()
            .enumerate()
            .filter(|(_, tuple)| matches(tuple))
            .map(|(index, _)| (Some(index), None))
            .collect();
        let named = pins.iter().try_fold(1usize, |count, pin| {
            Some(count.saturating_mul(pin.as_ref()?.len()))
        });
        if named.is_some_and(|named| reached.len() < named) {
            return Err(IntentRefusal::Unavailable {
                table: self.name.clone(),
                reason: Unavailable::NotHeld,
            });
        }
        Ok(reached)
    }
    /// The held partitions an INSERT's rows go to, with the rows of each.
    /// A SELECT of its own partition's rows stays SQL; any other is
    /// evaluated and its rows bound.
    fn insert(&mut self, insert: &mut Insert) -> Result<Reached, SplitError<E>> {
        let unpartitioned = self.rule.columns.is_empty();
        let positions = self
            .rule
            .columns
            .iter()
            .map(|column| {
                insert
                    .columns
                    .iter()
                    .position(|name| {
                        matches!(name.0.last(), Some(ObjectNamePart::Identifier(ident))
                            if ident.value.eq_ignore_ascii_case(&column.name))
                    })
                    .ok_or_else(|| {
                        IntentRefusal::Unsupported(format!(
                            "INSERT into {} must name its partition column {}",
                            self.name, column.name
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let Some(source) = &mut insert.source else {
            if unpartitioned {
                return Ok(vec![(None, None)]);
            }
            return Err(IntentRefusal::Unsupported("INSERT without rows".into()).into());
        };
        let tuples = match &*source.body {
            SetExpr::Values(values) => values
                .rows
                .iter()
                .map(|row| {
                    positions
                        .iter()
                        .map(|&index| row.get(index).and_then(|expr| value(expr, self.bindings)))
                        .collect::<Option<Vec<_>>>()
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| {
                    IntentRefusal::Unsupported(
                        "a partition value must be a literal or a bound parameter".into(),
                    )
                })?,
            body => {
                let pinned = match body {
                    SetExpr::Select(select) => positions
                        .iter()
                        .map(|&index| match select.projection.get(index)? {
                            SelectItem::UnnamedExpr(expr)
                            | SelectItem::ExprWithAlias { expr, .. } => value(expr, self.bindings),
                            _ => None,
                        })
                        .collect::<Option<Vec<_>>>(),
                    _ => None,
                };
                if let Some(tuple) = pinned {
                    let index = (!unpartitioned).then(|| self.locate(&tuple)).transpose()?;
                    if let Some(index) = index {
                        self.partition = self.held[index].clone();
                        self.copy = self.rule.held[index].clone();
                    }
                    if self.local(source) {
                        return Ok(vec![(index, None)]);
                    }
                }
                self.bind_rows(source, &positions)?
            }
        };
        if unpartitioned {
            return Ok(if tuples.is_empty() {
                Vec::new()
            } else {
                vec![(None, None)]
            });
        }
        let mut groups = BTreeMap::<usize, Vec<usize>>::new();
        for (row, tuple) in tuples.iter().enumerate() {
            groups.entry(self.locate(tuple)?).or_default().push(row);
        }
        Ok(groups
            .into_iter()
            .map(|(index, rows)| (Some(index), Some(rows)))
            .collect())
    }
    /// Evaluates an INSERT source and replaces it with its rows as bound
    /// values; returns each row's partition values.
    fn bind_rows(
        &mut self,
        source: &mut Query,
        positions: &[usize],
    ) -> Result<Rows, SplitError<E>> {
        let rows = self.rows(source.to_string())?;
        let tuples = rows
            .iter()
            .map(|row| {
                positions
                    .iter()
                    .map(|&index| row.get(index).cloned())
                    .collect::<Option<Vec<_>>>()
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| IntentRefusal::Unsupported("INSERT source width".into()))?;
        let rows = rows
            .into_iter()
            .map(|row| {
                Parens::with_empty_span(row.into_iter().map(|value| self.bind(value)).collect())
            })
            .collect();
        *source = Query {
            with: None,
            body: Box::new(SetExpr::Values(Values {
                explicit_row: false,
                value_keyword: false,
                rows,
            })),
            order_by: None,
            limit_clause: None,
            fetch: None,
            locks: Vec::new(),
            for_clause: None,
            settings: None,
            format_clause: None,
            pipe_operators: Vec::new(),
        };
        Ok(tuples)
    }
    /// Whether a query reads only the current copy's partition, so replicas
    /// holding it can replay the read.
    fn local(&self, query: &Query) -> bool {
        let mut selects = Vec::new();
        query.with.is_none()
            && blocks(&query.body, &mut selects)
            && selects.iter().all(|select| self.local_block(select))
    }
    fn local_block(&self, select: &Select) -> bool {
        let mut references = Vec::new();
        for item in &select.from {
            sources(item, &mut references);
        }
        if references.iter().any(|(name, _)| *name != self.name) {
            return false;
        }
        if references.is_empty() || self.rule.columns.is_empty() {
            return true;
        }
        let mut found = Proof::default();
        if let Some(seed) = &self.seed
            && !references.iter().any(|(_, alias)| alias == seed)
        {
            for (column, value) in self.rule.columns.iter().zip(&self.copy) {
                found.values.insert(
                    (seed.clone(), column.name.to_ascii_lowercase()),
                    vec![value.clone()],
                );
            }
        }
        if let Some(selection) = &select.selection {
            proof(selection, &references, self.bindings, &mut found);
        }
        for item in &select.from {
            for join in &item.joins {
                if let JoinOperator::Join(JoinConstraint::On(on))
                | JoinOperator::Inner(JoinConstraint::On(on)) = &join.join_operator
                {
                    proof(on, &references, self.bindings, &mut found);
                }
            }
        }
        propagate(&mut found);
        references.iter().all(|(_, alias)| {
            self.rule
                .columns
                .iter()
                .zip(&self.partition)
                .all(|(column, expected)| {
                    found
                        .values
                        .get(&(alias.clone(), column.name.to_ascii_lowercase()))
                        .is_some_and(|values| {
                            !values.is_empty()
                                && values
                                    .iter()
                                    .all(|value| normalize(column, value).as_ref() == Ok(expected))
                        })
                })
        })
    }
    fn bind(&mut self, value: SqlValue) -> Expr {
        self.values.push(value);
        Expr::Value(Value::Placeholder(format!("?{}", self.values.len())).with_empty_span())
    }
    /// The rows of a read, evaluated once with the held filters applied.
    fn rows(&mut self, sql: String) -> Result<Rows, SplitError<E>> {
        if let Some(rows) = self.reads.get(&sql) {
            return Ok(rows.clone());
        }
        let mut read = parse(&sql).map_err(IntentRefusal::Unsupported)?;
        let params = compact(&mut read, &self.values)?;
        let checked = prepare(&read.to_string(), &[])?.check(&params, self.tables)?;
        let rows = (self.evaluate)(&checked).map_err(SplitError::Evaluate)?;
        self.reads.insert(sql, rows.clone());
        Ok(rows)
    }
    /// A one-value read as a bound value.
    fn scalar(&mut self, sql: String) -> Result<Expr, SplitError<E>> {
        match <[Vec<SqlValue>; 1]>::try_from(self.rows(sql)?) {
            Ok([row]) => match <[SqlValue; 1]>::try_from(row) {
                Ok([value]) => Ok(self.bind(value)),
                Err(_) => Err(IntentRefusal::Unsupported("a row-value subquery".into()).into()),
            },
            Err(_) => {
                Err(IntentRefusal::Unsupported("a scalar read returned no row".into()).into())
            }
        }
    }
    fn replace(&mut self, expr: &mut Expr) -> Result<(), SplitError<E>> {
        *expr = match expr {
            Expr::Subquery(query) => self.scalar(format!("SELECT ({query})"))?,
            Expr::Exists { subquery, negated } => self.scalar(format!(
                "SELECT {}EXISTS ({subquery})",
                if *negated { "NOT " } else { "" }
            ))?,
            Expr::InSubquery {
                expr: left,
                subquery,
                negated,
            } => {
                let negated = *negated;
                let left = left.clone();
                let list = self
                    .rows(subquery.to_string())?
                    .into_iter()
                    .map(|row| match <[SqlValue; 1]>::try_from(row) {
                        Ok([value]) => Ok(self.bind(value)),
                        Err(_) => Err(IntentRefusal::Unsupported(
                            "an IN subquery must return one column".into(),
                        )),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Expr::InList {
                    expr: left,
                    list,
                    negated,
                }
            }
            _ => return Ok(()),
        };
        Ok(())
    }
}
impl<E> VisitorMut for Split<'_, E> {
    type Break = SplitError<E>;
    fn pre_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<SplitError<E>> {
        let (Expr::Subquery(query)
        | Expr::InSubquery {
            subquery: query, ..
        }
        | Expr::Exists {
            subquery: query, ..
        }) = &*expr
        else {
            return ControlFlow::Continue(());
        };
        if self.local(query) {
            return ControlFlow::Continue(());
        }
        if correlated(query) {
            return ControlFlow::Break(IntentRefusal::CorrelatedSubquery.into());
        }
        match self.replace(expr) {
            Ok(()) => ControlFlow::Continue(()),
            Err(error) => ControlFlow::Break(error),
        }
    }
}

/// The SELECT blocks of a query body and its derived tables, without
/// expression subqueries; false for a shape that is never local.
fn blocks<'q>(body: &'q SetExpr, out: &mut Vec<&'q Select>) -> bool {
    fn derived<'q>(factor: &'q TableFactor, out: &mut Vec<&'q Select>) -> bool {
        match factor {
            TableFactor::Table { .. } => true,
            TableFactor::Derived { subquery, .. } => {
                subquery.with.is_none() && blocks(&subquery.body, out)
            }
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => {
                derived(&table_with_joins.relation, out)
                    && table_with_joins
                        .joins
                        .iter()
                        .all(|join| derived(&join.relation, out))
            }
            _ => false,
        }
    }
    match body {
        SetExpr::Select(select) => {
            out.push(select);
            select.from.iter().all(|item| {
                derived(&item.relation, out)
                    && item.joins.iter().all(|join| derived(&join.relation, out))
            })
        }
        SetExpr::SetOperation { left, right, .. } => blocks(left, out) && blocks(right, out),
        SetExpr::Query(query) => query.with.is_none() && blocks(&query.body, out),
        SetExpr::Values(_) => true,
        _ => false,
    }
}
/// Tables a FROM item reads directly, as `(name, alias)`.
fn sources(item: &TableWithJoins, out: &mut Vec<(String, String)>) {
    fn factor(factor: &TableFactor, out: &mut Vec<(String, String)>) {
        match factor {
            TableFactor::Table { name, args, .. } => out.push(match table(factor) {
                Some(reference) if args.is_none() => reference,
                // A table function or another database is never the target.
                _ => (name.to_string(), String::new()),
            }),
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => sources(table_with_joins, out),
            _ => {}
        }
    }
    factor(&item.relation, out);
    for join in &item.joins {
        factor(&join.relation, out);
    }
}
/// Whether a query names a table or alias it does not define itself.
fn correlated(query: &Query) -> bool {
    #[derive(Default)]
    struct Names {
        defined: BTreeSet<String>,
        used: BTreeSet<String>,
    }
    impl Visitor for Names {
        type Break = ();
        fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<()> {
            match factor {
                TableFactor::Table { name, alias, .. } => {
                    if let Some(alias) = alias {
                        self.defined.insert(alias.name.value.to_ascii_lowercase());
                    } else if let Some(ObjectNamePart::Identifier(name)) = name.0.last() {
                        self.defined.insert(name.value.to_ascii_lowercase());
                    }
                }
                TableFactor::Derived {
                    alias: Some(alias), ..
                } => {
                    self.defined.insert(alias.name.value.to_ascii_lowercase());
                }
                _ => {}
            }
            ControlFlow::Continue(())
        }
        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
            if let Expr::CompoundIdentifier(parts) = expr
                && let [.., qualifier, _] = parts.as_slice()
            {
                self.used.insert(qualifier.value.to_ascii_lowercase());
            }
            ControlFlow::Continue(())
        }
    }
    let mut names = Names::default();
    let _ = query.visit(&mut names);
    names.used.iter().any(|name| !names.defined.contains(name))
}
/// Renumbers the parameters a statement uses to `?1..` in order, returning
/// their values.
fn compact(statement: &mut Statement, values: &[SqlValue]) -> Result<Vec<SqlValue>, IntentRefusal> {
    fn number(value: &Value) -> Option<usize> {
        match value {
            Value::Placeholder(name) => name.strip_prefix('?')?.parse().ok(),
            _ => None,
        }
    }
    struct Used(BTreeSet<usize>);
    impl Visitor for Used {
        type Break = ();
        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
            if let Expr::Value(value) = expr
                && let Some(number) = number(&value.value)
            {
                self.0.insert(number);
            }
            ControlFlow::Continue(())
        }
    }
    struct Renumber(BTreeMap<usize, usize>);
    impl VisitorMut for Renumber {
        type Break = ();
        fn pre_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<()> {
            if let Expr::Value(value) = expr
                && let Some(number) = number(&value.value)
                && let Some(next) = self.0.get(&number)
            {
                value.value = Value::Placeholder(format!("?{next}"));
            }
            ControlFlow::Continue(())
        }
    }
    let mut used = Used(BTreeSet::new());
    let _ = Visit::visit(&*statement, &mut used);
    let params = used
        .0
        .iter()
        .map(|number| {
            number
                .checked_sub(1)
                .and_then(|index| values.get(index))
                .cloned()
                .ok_or_else(|| {
                    IntentRefusal::Unsupported(format!("parameter ?{number} is unbound"))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let _ = VisitMut::visit(
        statement,
        &mut Renumber(
            used.0
                .iter()
                .zip(1..)
                .map(|(&old, new)| (old, new))
                .collect(),
        ),
    );
    Ok(params)
}

#[cfg(test)]
mod tests;
