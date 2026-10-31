//! Completeness proofs for each resolved SQL table reference.
mod intent;
pub use intent::{
    DETERMINISTIC_FUNCTIONS, IntentRefusal, MAX_INTENT_PARTITIONS, PartitionStatement, SplitError,
    check_assertion, check_replayed_table, split_intent, split_intent_within, written_table,
};
use rocky_core::{KeyColumn, PartitionValue, SqlValue};
use sqlparser::ast::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::ControlFlow,
    sync::Arc,
};

#[derive(Clone)]
pub struct PartitionColumn {
    pub name: String,
    pub key: KeyColumn,
}
#[derive(Clone)]
pub struct TablePartitions {
    pub columns: Vec<PartitionColumn>,
    pub complete: bool,
    /// Values in partition declaration order; only readable, held scopes.
    pub held: Vec<Vec<SqlValue>>,
    /// Held partitions whose rows are not all here: a read that may reach
    /// one is refused as incomplete, never answered as absence.
    pub waiting: Vec<Vec<SqlValue>>,
}
impl TablePartitions {
    /// Whether reads of the table are rewritten to a filtered subquery.
    fn filtered(&self) -> bool {
        !self.complete && !self.columns.is_empty()
    }
}
/// Why a statement is refused: outside the supported surface, or a table
/// it reads is not available on this device.
#[derive(Debug)]
pub enum Refusal {
    Unsupported(String),
    Unavailable {
        table: String,
        reason: crate::sql::Unavailable,
    },
}
impl From<String> for Refusal {
    fn from(reason: String) -> Self {
        Self::Unsupported(reason)
    }
}
impl From<&str> for Refusal {
    fn from(reason: &str) -> Self {
        Self::Unsupported(reason.into())
    }
}
impl From<Refusal> for crate::sql::SqlError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::Unsupported(reason) => Self::Unsupported(reason),
            Refusal::Unavailable { table, reason } => Self::Unavailable { table, reason },
        }
    }
}
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(reason) => f.write_str(reason),
            Self::Unavailable { table, reason } => {
                write!(f, "{table} is not available: {reason:?}")
            }
        }
    }
}
fn parse(sql: &str) -> Result<Statement, String> {
    match &*crate::parsed::parse(sql)? {
        [statement] => Ok(statement.clone()),
        _ => Err("one statement required".into()),
    }
}
/// A checked statement and its parameters: the caller's, then the values
/// of the held partitions a partial read is filtered to.
#[derive(Debug)]
pub struct Checked {
    pub sql: String,
    pub params: Vec<SqlValue>,
}
/// A table named plainly or in `main`, lowercase.
fn table_name(name: &ObjectName) -> Option<String> {
    match name.0.as_slice() {
        [ObjectNamePart::Identifier(name)] => Some(name.value.to_ascii_lowercase()),
        [
            ObjectNamePart::Identifier(database),
            ObjectNamePart::Identifier(name),
        ] if database.value.eq_ignore_ascii_case("main") => Some(name.value.to_ascii_lowercase()),
        _ => None,
    }
}
fn table(factor: &TableFactor) -> Option<(String, String)> {
    let TableFactor::Table { name, alias, .. } = factor else {
        return None;
    };
    let name = table_name(name)?;
    let alias = alias.as_ref().map_or_else(
        || name.clone(),
        |alias| alias.name.value.to_ascii_lowercase(),
    );
    Some((name, alias))
}
fn unnest(expr: &Expr) -> &Expr {
    if let Expr::Nested(expr) = expr {
        unnest(expr)
    } else {
        expr
    }
}
type Column = (String, String);
fn column(expr: &Expr, aliases: &[(String, String)]) -> Option<Column> {
    match unnest(expr) {
        Expr::Identifier(name) if aliases.len() == 1 => {
            Some((aliases[0].1.clone(), name.value.to_ascii_lowercase()))
        }
        Expr::CompoundIdentifier(parts) if parts.len() == 2 => Some((
            parts[0].value.to_ascii_lowercase(),
            parts[1].value.to_ascii_lowercase(),
        )),
        _ => None,
    }
}
struct Bindings<'a> {
    params: &'a [SqlValue],
    placeholders: BTreeMap<(u64, u64), String>,
    values: BTreeMap<(u64, u64), SqlValue>,
    /// The number of each anonymous `?`.
    numbers: BTreeMap<(u64, u64), usize>,
}
impl Bindings<'_> {
    /// Binds each placeholder; returns the highest parameter number.
    fn bind(&mut self) -> Result<usize, String> {
        let mut next = 0usize;
        for (span, name) in &self.placeholders {
            let index = if name == "?" {
                self.numbers.insert(*span, next + 1);
                next + 1
            } else {
                name.strip_prefix('?')
                    .and_then(|name| name.parse::<usize>().ok())
                    .ok_or("partition proof needs positional parameters")?
            };
            next = next.max(index);
            if let Some(param) = index
                .checked_sub(1)
                .and_then(|index| self.params.get(index))
            {
                self.values.insert(*span, param.clone());
            }
        }
        Ok(next)
    }
}
impl Visitor for Bindings<'_> {
    type Break = String;
    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<String> {
        if let Expr::Value(value) = expr
            && let Value::Placeholder(name) = &value.value
        {
            self.placeholders.insert(
                (value.span.start.line, value.span.start.column),
                name.clone(),
            );
        }
        ControlFlow::Continue(())
    }
}
fn value(expr: &Expr, bindings: &Bindings<'_>) -> Option<SqlValue> {
    match unnest(expr) {
        Expr::Value(value) => match &value.value {
            Value::SingleQuotedString(text) => Some(SqlValue::Text(text.clone())),
            Value::Number(number, _) => number
                .parse::<i64>()
                .ok()
                .map(SqlValue::Integer)
                .or_else(|| number.parse::<f64>().ok().and_then(SqlValue::real)),
            Value::Placeholder(_) => bindings
                .values
                .get(&(value.span.start.line, value.span.start.column))
                .cloned(),
            Value::Boolean(value) => Some(SqlValue::Integer(i64::from(*value))),
            _ => None,
        },
        Expr::UnaryOp {
            op: UnaryOperator::Minus,
            expr,
        } => match value(expr, bindings)? {
            SqlValue::Integer(number) => number.checked_neg().map(SqlValue::Integer),
            SqlValue::Real(bits) => SqlValue::real(-bits.get()),
            _ => None,
        },
        _ => None,
    }
}
#[derive(Default)]
struct Proof {
    values: BTreeMap<Column, Vec<SqlValue>>,
    equal: Vec<(Column, Column)>,
}
fn proof(expr: &Expr, aliases: &[(String, String)], bindings: &Bindings<'_>, to: &mut Proof) {
    match unnest(expr) {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            proof(left, aliases, bindings, to);
            proof(right, aliases, bindings, to);
        }
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => {
            match (
                column(left, aliases),
                column(right, aliases),
                value(left, bindings),
                value(right, bindings),
            ) {
                (Some(left), Some(right), _, _) => to.equal.push((left, right)),
                (Some(column), None, _, Some(value)) | (None, Some(column), Some(value), _) => {
                    to.values.insert(column, vec![value]);
                }
                _ => {}
            }
        }
        Expr::InList {
            expr,
            list,
            negated: false,
        } => {
            if let Some(column) = column(expr, aliases)
                && let Some(values) = list
                    .iter()
                    .map(|expr| value(expr, bindings))
                    .collect::<Option<Vec<_>>>()
            {
                to.values.insert(column, values);
            }
        }
        _ => {}
    }
}
fn propagate(proof: &mut Proof) {
    for _ in 0..proof.equal.len() + 1 {
        let mut changed = false;
        for (left, right) in &proof.equal {
            if !proof.values.contains_key(right)
                && let Some(values) = proof.values.get(left).cloned()
            {
                proof.values.insert(right.clone(), values);
                changed = true;
            }
            if !proof.values.contains_key(left)
                && let Some(values) = proof.values.get(right).cloned()
            {
                proof.values.insert(left.clone(), values);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}
fn normalize(column: &PartitionColumn, value: &SqlValue) -> Result<PartitionValue, String> {
    PartitionValue::new(column.key, value.clone()).map_err(|error| error.to_string())
}
struct Checker<'a> {
    tables: &'a BTreeMap<String, TablePartitions>,
    bindings: &'a Bindings<'a>,
    assertion: bool,
}
impl Checker<'_> {
    fn body(&self, body: &SetExpr) -> Result<(), Refusal> {
        match body {
            SetExpr::Select(select) => self.references(&select.from, select.selection.as_ref()),
            SetExpr::SetOperation { left, right, .. } => {
                self.body(left)?;
                self.body(right)
            }
            _ => Ok(()),
        }
    }
    fn references(&self, from: &[TableWithJoins], selection: Option<&Expr>) -> Result<(), Refusal> {
        let mut references = Vec::new();
        for item in from {
            if let Some(reference) = table(&item.relation) {
                references.push(reference);
            }
            for join in &item.joins {
                if let Some(reference) = table(&join.relation) {
                    references.push(reference);
                }
            }
        }
        let mut where_proof = Proof::default();
        if let Some(selection) = selection {
            proof(selection, &references, self.bindings, &mut where_proof);
        }
        // Inner join conditions constrain all participants. Outer ON clauses only constrain the non-preserved input.
        for item in from {
            for join in &item.joins {
                if let JoinOperator::Join(JoinConstraint::On(on))
                | JoinOperator::Inner(JoinConstraint::On(on)) = &join.join_operator
                {
                    proof(on, &references, self.bindings, &mut where_proof);
                }
            }
        }
        propagate(&mut where_proof);
        for (name, alias) in &references {
            let Some(rule) = self.tables.get(name) else {
                continue;
            };
            if rule.complete || rule.columns.is_empty() {
                continue;
            }
            let mut effective = Proof {
                values: where_proof.values.clone(),
                equal: where_proof.equal.clone(),
            };
            for item in from {
                for join in &item.joins {
                    if table(&join.relation).is_some_and(|(_, target)| &target == alias)
                        && let JoinOperator::Left(JoinConstraint::On(on))
                        | JoinOperator::LeftOuter(JoinConstraint::On(on)) = &join.join_operator
                    {
                        proof(on, &references, self.bindings, &mut effective);
                    }
                }
            }
            propagate(&mut effective);
            let incomplete = || Refusal::Unavailable {
                table: name.clone(),
                reason: crate::sql::Unavailable::Incomplete,
            };
            let mut tuples = vec![Vec::new()];
            for column in &rule.columns {
                let Some(values) = effective
                    .values
                    .get(&(alias.clone(), column.name.to_ascii_lowercase()))
                else {
                    // Every partition may be read: one that waits refuses
                    // it, and the filter hides those not held.
                    if !rule.waiting.is_empty() && !self.assertion {
                        return Err(incomplete());
                    }
                    tuples.clear();
                    break;
                };
                if tuples.len().saturating_mul(values.len()) > 4096 {
                    return Err("partition proof quota".into());
                }
                let mut next = Vec::new();
                for tuple in tuples {
                    for value in values {
                        let mut tuple = tuple.clone();
                        tuple.push(normalize(column, value)?);
                        next.push(tuple);
                    }
                }
                tuples = next;
            }
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
            };
            let waiting = normalized(&rule.waiting)?;
            if !self.assertion && tuples.iter().any(|tuple| waiting.contains(tuple)) {
                return Err(incomplete());
            }
            let held = normalized(&rule.held)?;
            if !self.assertion && tuples.iter().any(|tuple| !held.contains(tuple)) {
                return Err(Refusal::Unavailable {
                    table: name.clone(),
                    reason: crate::sql::Unavailable::NotHeld,
                });
            }
        }
        Ok(())
    }
}
impl Visitor for Checker<'_> {
    type Break = Refusal;
    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<Refusal> {
        if let TableFactor::NestedJoin {
            table_with_joins, ..
        } = factor
            && let Err(error) = self.references(std::slice::from_ref(table_with_joins), None)
        {
            return ControlFlow::Break(error);
        }
        ControlFlow::Continue(())
    }
    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Refusal> {
        if let Err(error) = self.body(&query.body) {
            return ControlFlow::Break(error);
        }
        ControlFlow::Continue(())
    }
    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<Refusal> {
        let result = match statement {
            Statement::Update(update) => {
                let mut sources = vec![update.table.clone()];
                if let Some(
                    UpdateTableFromKind::BeforeSet(from) | UpdateTableFromKind::AfterSet(from),
                ) = &update.from
                {
                    sources.extend(from.iter().cloned());
                }
                self.references(&sources, update.selection.as_ref())
            }
            Statement::Delete(delete) => {
                let (FromTable::WithFromKeyword(from) | FromTable::WithoutKeyword(from)) =
                    &delete.from;
                self.references(from, delete.selection.as_ref())
            }
            _ => Ok(()),
        };
        match result {
            Ok(()) => ControlFlow::Continue(()),
            Err(error) => ControlFlow::Break(error),
        }
    }
}
/// A statement with its views expanded, and the tables it may reference.
pub struct Prepared {
    statement: Statement,
    tables: BTreeSet<String>,
}
impl Prepared {
    /// Conservative table references, after expanding views, for loading
    /// only the readiness proofs a statement can use. CTE names may also be
    /// returned.
    pub fn tables(&self) -> &BTreeSet<String> {
        &self.tables
    }
    /// Checks every query block separately. The returned statement filters
    /// partial reads to held scopes, whose values it binds after `params`.
    pub fn check(
        &self,
        params: &[SqlValue],
        tables: &BTreeMap<String, TablePartitions>,
    ) -> Result<Checked, Refusal> {
        self.check_mode(params, tables, false)
    }
    /// Checks an assertion query and appends the held-partition filters
    /// without requiring the assertion to state the partition predicate.
    fn check_assertion(
        &self,
        params: &[SqlValue],
        tables: &BTreeMap<String, TablePartitions>,
    ) -> Result<Checked, Refusal> {
        self.check_mode(params, tables, true)
    }
    fn check_mode(
        &self,
        params: &[SqlValue],
        tables: &BTreeMap<String, TablePartitions>,
        assertion: bool,
    ) -> Result<Checked, Refusal> {
        let mut statement = self.statement.clone();
        let mut bindings = Bindings {
            params,
            placeholders: BTreeMap::new(),
            values: BTreeMap::new(),
            numbers: BTreeMap::new(),
        };
        if let ControlFlow::Break(error) = statement.visit(&mut bindings) {
            return Err(error.into());
        }
        let used = bindings.bind()?;
        let mut checker = Checker {
            tables,
            bindings: &bindings,
            assertion,
        };
        if let ControlFlow::Break(error) = statement.visit(&mut checker) {
            return Err(error);
        }
        let mut filter = Filter {
            tables,
            reads: Vec::new(),
            numbers: &bindings.numbers,
            params: params.to_vec(),
        };
        if let ControlFlow::Break(error) = VisitMut::visit(&mut statement, &mut filter) {
            return Err(error.into());
        }
        if filter.params.len() > params.len() && used != params.len() {
            return Err(format!(
                "the statement uses {used} parameters, {} were given",
                params.len()
            )
            .into());
        }
        Ok(Checked {
            sql: statement.to_string(),
            params: filter.params,
        })
    }
}
/// Expands `sql`'s views. Statements and their expansions are prepared
/// once while they stay in use.
pub fn prepare(sql: &str, views: &[rocky_core::LogicalView]) -> Result<Arc<Prepared>, Refusal> {
    let key = prepared_key(sql, views);
    if let Some((text, prepared)) = PREPARED.get(&key)
        && *text == *sql
    {
        return Ok(prepared);
    }
    let (mut statement, expanded) = expand_views(sql, views)?;
    if expanded {
        // Spans identify placeholders and reads: an expanded statement
        // takes them from its own text.
        statement = parse(&statement.to_string())?;
    }
    struct References(BTreeSet<String>);
    impl Visitor for References {
        type Break = ();
        fn pre_visit_relation(&mut self, name: &ObjectName) -> ControlFlow<()> {
            if let Some(ObjectNamePart::Identifier(name)) = name.0.last() {
                self.0.insert(name.value.to_ascii_lowercase());
            }
            ControlFlow::Continue(())
        }
    }
    let mut references = References(BTreeSet::new());
    let _ = statement.visit(&mut references);
    let prepared = Arc::new(Prepared {
        statement,
        tables: references.0,
    });
    if sql.len() <= crate::parsed::CACHED_BYTES {
        PREPARED.put(key, (sql.into(), prepared.clone()));
    }
    Ok(prepared)
}
/// Prepared statements by a digest of their text and views; a hit is
/// compared with the text.
static PREPARED: crate::parsed::Recent<u64, (Arc<str>, Arc<Prepared>)> =
    crate::parsed::Recent::new();
fn prepared_key(sql: &str, views: &[rocky_core::LogicalView]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    sql.hash(&mut hasher);
    for view in views {
        (&view.name, &view.create_sql).hash(&mut hasher);
    }
    hasher.finish()
}
#[cfg(test)]
fn check(
    sql: &str,
    params: &[SqlValue],
    tables: &BTreeMap<String, TablePartitions>,
) -> Result<String, Refusal> {
    let checked = prepare(sql, &[])?.check(params, tables)?;
    Ok(inline(&checked))
}
/// The checked statement with its parameters written in, for tests that
/// run it.
#[cfg(test)]
fn inline(checked: &Checked) -> String {
    let mut sql = checked.sql.clone();
    for (index, value) in checked.params.iter().enumerate().rev() {
        sql = sql.replace(&format!("?{}", index + 1), &literal(value));
    }
    sql
}

fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
#[cfg(test)]
fn literal(value: &SqlValue) -> String {
    match value {
        SqlValue::Null => "NULL".into(),
        SqlValue::Integer(value) => value.to_string(),
        SqlValue::Real(value) => value.get().to_string(),
        SqlValue::Text(value) => format!("'{}'", value.replace('\'', "''")),
        SqlValue::Blob(value) => format!(
            "X'{}'",
            value
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ),
    }
}
/// Rows of the held partitions; their values bind as parameters after
/// `params`, so the text depends only on how many there are.
fn held_partitions(
    rule: &TablePartitions,
    alias: Option<&str>,
    params: &mut Vec<SqlValue>,
) -> String {
    if rule.held.is_empty() || rule.columns.is_empty() {
        return "0".into();
    }
    let names = rule
        .columns
        .iter()
        .map(|column| match alias {
            Some(alias) => format!("{}.{}", quoted(alias), quoted(&column.name)),
            None => quoted(&column.name),
        })
        .collect::<Vec<_>>();
    let values = rule
        .held
        .iter()
        .map(|tuple| {
            let values = tuple
                .iter()
                .map(|value| {
                    params.push(value.clone());
                    format!("?{}", params.len())
                })
                .collect::<Vec<_>>()
                .join(",");
            if names.len() > 1 {
                format!("({values})")
            } else {
                values
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    let names = if names.len() > 1 {
        format!("({})", names.join(","))
    } else {
        names[0].clone()
    };
    format!("{names} IN ({values})")
}
fn filter_expr(
    rule: &TablePartitions,
    alias: Option<&str>,
    params: &mut Vec<SqlValue>,
) -> Result<Expr, String> {
    let Statement::Query(query) = parse(&format!(
        "SELECT 1 WHERE {}",
        held_partitions(rule, alias, params)
    ))?
    else {
        return Err("partition filter".into());
    };
    let SetExpr::Select(select) = *query.body else {
        return Err("partition filter".into());
    };
    select.selection.ok_or_else(|| "partition filter".into())
}
fn append(selection: &mut Option<Expr>, filter: Expr) {
    *selection = Some(match selection.take() {
        Some(old) => Expr::BinaryOp {
            left: Box::new(Expr::Nested(Box::new(old))),
            op: BinaryOperator::And,
            right: Box::new(Expr::Nested(Box::new(filter))),
        },
        None => filter,
    });
}
struct Filter<'a> {
    tables: &'a BTreeMap<String, TablePartitions>,
    reads: Vec<(u64, u64)>,
    numbers: &'a BTreeMap<(u64, u64), usize>,
    /// The caller's parameters, then the held values of each filter.
    params: Vec<SqlValue>,
}
impl Filter<'_> {
    fn read_factor(&mut self, factor: &TableFactor) {
        match factor {
            TableFactor::Table { name, .. } => {
                if let Some(ObjectNamePart::Identifier(name)) = name.0.last() {
                    self.reads
                        .push((name.span.start.line, name.span.start.column));
                }
            }
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => self.sources(std::slice::from_ref(table_with_joins)),
            _ => {}
        }
    }
    fn sources(&mut self, from: &[TableWithJoins]) {
        for item in from {
            self.read_factor(&item.relation);
            for join in &item.joins {
                self.read_factor(&join.relation);
            }
        }
    }
    fn body(&mut self, body: &SetExpr) {
        match body {
            SetExpr::Select(select) => self.sources(&select.from),
            SetExpr::SetOperation { left, right, .. } => {
                self.body(left);
                self.body(right);
            }
            _ => {}
        }
    }
}
impl VisitorMut for Filter<'_> {
    type Break = String;
    /// Numbers each anonymous `?`, so the parameters a filter adds keep
    /// their places wherever it is inserted.
    fn pre_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<String> {
        if let Expr::Value(value) = expr
            && let Value::Placeholder(name) = &mut value.value
            && name == "?"
            && let Some(number) = self
                .numbers
                .get(&(value.span.start.line, value.span.start.column))
        {
            *name = format!("?{number}");
        }
        ControlFlow::Continue(())
    }
    fn pre_visit_query(&mut self, query: &mut Query) -> ControlFlow<String> {
        self.body(&query.body);
        ControlFlow::Continue(())
    }
    fn post_visit_table_factor(&mut self, factor: &mut TableFactor) -> ControlFlow<String> {
        let Some((name, alias_name)) = table(factor) else {
            return ControlFlow::Continue(());
        };
        let Some(rule) = self.tables.get(&name).filter(|rule| rule.filtered()) else {
            return ControlFlow::Continue(());
        };
        let TableFactor::Table {
            name: object,
            alias,
            ..
        } = factor
        else {
            return ControlFlow::Continue(());
        };
        let Some(ObjectNamePart::Identifier(ident)) = object.0.last() else {
            return ControlFlow::Continue(());
        };
        if !self
            .reads
            .contains(&(ident.span.start.line, ident.span.start.column))
        {
            return ControlFlow::Continue(());
        }
        let query = match parse(&format!(
            "SELECT * FROM {} WHERE {}",
            quoted(&name),
            held_partitions(rule, None, &mut self.params)
        )) {
            Ok(Statement::Query(query)) => query,
            _ => return ControlFlow::Break("partition filter".into()),
        };
        let alias = alias.clone().or_else(|| {
            Some(TableAlias {
                explicit: true,
                name: Ident::new(alias_name),
                columns: Vec::new(),
                at: None,
            })
        });
        *factor = TableFactor::Derived {
            lateral: false,
            sample: None,
            subquery: query,
            alias,
        };
        ControlFlow::Continue(())
    }
    fn pre_visit_statement(&mut self, statement: &mut Statement) -> ControlFlow<String> {
        if let Statement::Update(update) = statement
            && let Some(UpdateTableFromKind::BeforeSet(from) | UpdateTableFromKind::AfterSet(from)) =
                &update.from
        {
            self.sources(from);
        }
        let target = match statement {
            Statement::Update(update) => {
                table(&update.table.relation).map(|reference| (reference, &mut update.selection))
            }
            Statement::Delete(delete) => {
                let (FromTable::WithFromKeyword(from) | FromTable::WithoutKeyword(from)) =
                    &delete.from;
                from.first()
                    .and_then(|item| table(&item.relation))
                    .map(|reference| (reference, &mut delete.selection))
            }
            _ => None,
        };
        if let Some(((name, alias), selection)) = target
            && let Some(rule) = self.tables.get(&name).filter(|rule| rule.filtered())
        {
            match filter_expr(rule, Some(&alias), &mut self.params) {
                Ok(filter) => append(selection, filter),
                Err(error) => return ControlFlow::Break(error),
            }
        }
        ControlFlow::Continue(())
    }
}

pub fn check_with_views(
    sql: &str,
    params: &[SqlValue],
    tables: &BTreeMap<String, TablePartitions>,
    views: &[rocky_core::LogicalView],
) -> Result<Checked, Refusal> {
    prepare(sql, views)?.check(params, tables)
}

/// The statement with its views expanded, and whether it named any.
fn expand_views(
    sql: &str,
    views: &[rocky_core::LogicalView],
) -> Result<(Statement, bool), Refusal> {
    struct Expand<'a> {
        views: &'a [rocky_core::LogicalView],
        changed: bool,
    }
    impl VisitorMut for Expand<'_> {
        type Break = String;
        fn post_visit_table_factor(&mut self, factor: &mut TableFactor) -> ControlFlow<String> {
            let Some((name, alias_name)) = table(factor) else {
                return ControlFlow::Continue(());
            };
            let Some(view) = self
                .views
                .iter()
                .find(|view| view.name.eq_ignore_ascii_case(&name))
            else {
                return ControlFlow::Continue(());
            };
            let query = match parse(&view.create_sql) {
                Ok(Statement::CreateView(view)) if view.columns.is_empty() => view.query,
                _ => return ControlFlow::Break(format!("unsupported view {name}")),
            };
            let TableFactor::Table { alias, .. } = factor else {
                return ControlFlow::Continue(());
            };
            let alias = alias.clone().or_else(|| {
                Some(TableAlias {
                    explicit: true,
                    name: Ident::new(alias_name),
                    columns: Vec::new(),
                    at: None,
                })
            });
            *factor = TableFactor::Derived {
                lateral: false,
                subquery: query,
                alias,
                sample: None,
            };
            self.changed = true;
            ControlFlow::Continue(())
        }
    }
    let mut statement = parse(sql)?;
    for round in 0..16 {
        let mut expand = Expand {
            views,
            changed: false,
        };
        if let ControlFlow::Break(error) = VisitMut::visit(&mut statement, &mut expand) {
            return Err(error.into());
        }
        if !expand.changed {
            return Ok((statement, round > 0));
        }
    }
    Err("view expansion cycle or depth quota".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn readiness_references_include_nested_views_subqueries_and_write_targets() {
        let views = vec![
            rocky_core::LogicalView {
                name: "inner_items".into(),
                create_sql: "CREATE VIEW inner_items AS SELECT * FROM main.items".into(),
            },
            rocky_core::LogicalView {
                name: "outer_items".into(),
                create_sql: "CREATE VIEW outer_items AS SELECT * FROM inner_items".into(),
            },
        ];
        for sql in [
            "SELECT * FROM metadata WHERE EXISTS(SELECT 1 FROM outer_items)",
            "UPDATE metadata SET value=(SELECT count(*) FROM outer_items)",
            "INSERT INTO metadata SELECT * FROM outer_items",
            "DELETE FROM metadata WHERE EXISTS(SELECT 1 FROM outer_items)",
        ] {
            assert_eq!(
                prepare(sql, &views).unwrap().tables().clone(),
                ["items".into(), "metadata".into()].into(),
                "{sql}"
            );
        }
        assert!(prepare("SELECT 1", &views).unwrap().tables().is_empty());
        assert_eq!(
            prepare("SELECT * FROM metadata", &views)
                .unwrap()
                .tables()
                .clone(),
            ["metadata".into()].into()
        );
    }

    fn rules() -> BTreeMap<String, TablePartitions> {
        [(
            "items".into(),
            TablePartitions {
                columns: vec![PartitionColumn {
                    name: "list".into(),
                    key: KeyColumn {
                        affinity: rocky_core::Affinity::Text,
                        collation: rocky_core::Collation::Nocase,
                    },
                }],
                complete: false,
                held: vec![vec![SqlValue::Text("A".into())]],
                waiting: Vec::new(),
            },
        )]
        .into()
    }
    #[test]
    fn aliases_in_bindings_or_and_outer_join_proofs_are_checked() {
        let rules = rules();
        for sql in [
            "SELECT * FROM items WHERE list='a'",
            "SELECT * FROM items WHERE list IN ('a','A')",
            "UPDATE items SET amount=1 WHERE list='A'",
            "DELETE FROM items",
            "SELECT SUM(amount) FROM main.items",
            "SELECT amount FROM items WHERE list='A' UNION ALL SELECT amount FROM items",
            "SELECT a.amount,b.amount FROM items a JOIN items b ON a.list=b.list WHERE a.list='A'",
            "SELECT * FROM items WHERE list='A' OR amount=1",
        ] {
            check(sql, &[], &rules).unwrap_or_else(|error| panic!("{sql}: {error}"));
        }
        for sql in [
            "SELECT * FROM items WHERE list IN ('A','B')",
            "DELETE FROM items WHERE list='B'",
            "SELECT a.amount,b.amount FROM items a LEFT JOIN items b ON b.list='B' WHERE a.list='A'",
        ] {
            assert!(check(sql, &[], &rules).is_err(), "{sql}");
        }
        check(
            "SELECT ?2 FROM items WHERE list=?1",
            &[SqlValue::Text("A".into()), SqlValue::Integer(4)],
            &rules,
        )
        .unwrap();
        assert!(
            check(
                "SELECT ? FROM items WHERE list=?",
                &[SqlValue::Text("A".into()), SqlValue::Text("B".into())],
                &rules
            )
            .is_err()
        );
    }
    #[test]
    fn partial_reads_filter_cached_unheld_rows_without_changing_left_join_semantics() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE items(list TEXT,amount INTEGER); INSERT INTO items VALUES('A',10),('B',20);",
        )
        .unwrap();
        for read in ["SELECT SUM(amount) FROM items", "SELECT SUM(amount) FROM main.items"] {
            let sql = check(read, &[], &rules()).unwrap();
            assert_eq!(
                conn.query_row(&sql, [], |row| row.get::<_, i64>(0)).unwrap(),
                10
            );
        }
        let union = check(
            "SELECT amount FROM items UNION ALL SELECT amount FROM items",
            &[],
            &rules(),
        )
        .unwrap();
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM ({union})"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 2);
        let sql = check(
            "SELECT a.amount,b.amount FROM items a LEFT JOIN items b ON b.amount=20 WHERE a.list='A'",
            &[],
            &rules(),
        )
        .unwrap();
        assert_eq!(
            conn.query_row(&sql, [], |row| Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?
            )))
            .unwrap(),
            (10, None)
        );
    }
    #[test]
    fn only_a_waiting_partition_a_read_may_reach_is_incomplete() {
        let mut rules = rules();
        rules.get_mut("items").unwrap().waiting = vec![vec![SqlValue::Text("B".into())]];
        let incomplete = |sql: &str| {
            matches!(
                check(sql, &[], &rules),
                Err(Refusal::Unavailable {
                    reason: crate::sql::Unavailable::Incomplete,
                    ..
                })
            )
        };
        check("SELECT * FROM items WHERE list='A'", &[], &rules).unwrap();
        for sql in [
            "SELECT * FROM items WHERE list='b'",
            "SELECT * FROM items WHERE list IN ('A','B')",
            "SELECT SUM(amount) FROM items",
        ] {
            assert!(incomplete(sql), "{sql}");
        }
        // A partition neither held nor waiting is not here at all.
        assert!(check("SELECT * FROM items WHERE list='C'", &[], &rules).is_err());
        assert!(!incomplete("SELECT * FROM items WHERE list='C'"));
    }
    #[test]
    fn held_values_bind_after_the_callers_parameters_and_keep_the_text_stable() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE items(list TEXT,amount INTEGER); INSERT INTO items VALUES('A',10),('B',20);").unwrap();
        let sql = "SELECT ? + SUM(amount) FROM items WHERE amount>?";
        let checked = check_with_views(
            sql,
            &[SqlValue::Integer(1), SqlValue::Integer(5)],
            &rules(),
            &[],
        )
        .unwrap();
        assert!(!checked.sql.contains("'A'"), "{}", checked.sql);
        assert_eq!(
            checked.params,
            [1, 5]
                .map(SqlValue::Integer)
                .into_iter()
                .chain([SqlValue::Text("A".into())])
                .collect::<Vec<_>>()
        );
        let params: Vec<rusqlite::types::Value> = checked
            .params
            .iter()
            .map(|value| match value {
                SqlValue::Integer(value) => (*value).into(),
                SqlValue::Text(value) => value.clone().into(),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(
            conn.query_row(&checked.sql, rusqlite::params_from_iter(params), |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            11
        );
        // Another held set of the same size reads the same text.
        let mut other = rules();
        other.get_mut("items").unwrap().held = vec![vec![SqlValue::Text("B".into())]];
        let again = check_with_views(
            sql,
            &[SqlValue::Integer(1), SqlValue::Integer(5)],
            &other,
            &[],
        )
        .unwrap();
        assert_eq!(again.sql, checked.sql);
        assert!(Arc::ptr_eq(
            &prepare(sql, &[]).unwrap(),
            &prepare(sql, &[]).unwrap()
        ));
        // Too few parameters for a filtered statement is refused, not padded.
        assert!(check_with_views(sql, &[SqlValue::Integer(1)], &rules(), &[]).is_err());
    }
    #[test]
    fn nested_views_are_expanded_and_cycles_refused() {
        let views = vec![
            rocky_core::LogicalView {
                name: "partial_items".into(),
                create_sql: "CREATE VIEW partial_items AS SELECT * FROM items WHERE amount>0"
                    .into(),
            },
            rocky_core::LogicalView {
                name: "nested".into(),
                create_sql: "CREATE VIEW nested AS SELECT * FROM partial_items".into(),
            },
        ];
        check_with_views("SELECT SUM(amount) FROM nested", &[], &rules(), &views).unwrap();
        let views = vec![rocky_core::LogicalView {
            name: "cycle".into(),
            create_sql: "CREATE VIEW cycle AS SELECT * FROM cycle".into(),
        }];
        assert!(check_with_views("SELECT * FROM cycle", &[], &rules(), &views).is_err());
    }
}
