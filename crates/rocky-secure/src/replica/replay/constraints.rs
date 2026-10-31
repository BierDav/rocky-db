//! What SQLite cannot check before a replayed transaction's savepoint is
//! released: its deferred foreign keys, which SQLite checks only at the
//! outermost `COMMIT`, and the schema's assertions. Both run at the end of
//! each replayed transaction and at author commit.
use super::*;

/// A replayed row a transaction changed: its table, lowercase, and its
/// partition values in `partition_by` order (empty when unpartitioned).
pub(in crate::replica) type Written = (String, Vec<SqlValue>);

/// Adds `row` to `written` unless it is there.
pub(in crate::replica) fn note(written: &mut Vec<Written>, row: Written) {
    if !written.contains(&row) {
        written.push(row);
    }
}

/// The partition values of a row image of `logical`.
pub(in crate::replica) fn written(
    logical: &rocky_core::LogicalTable,
    image: &[SqlValue],
) -> Result<Written, Error> {
    let partition = logical
        .partition_by
        .iter()
        .map(|name| {
            logical
                .columns
                .iter()
                .position(|column| column.sql_name.eq_ignore_ascii_case(name))
                .and_then(|position| image.get(position).cloned())
                .ok_or_else(|| Error::Corrupt("replayed partition column".into()))
        })
        .collect::<Result<_, _>>()?;
    Ok((logical.sql_name.to_ascii_lowercase(), partition))
}

/// Replayed tables whose rows a write to `table` may change through delete
/// actions, `table` included.
pub(in crate::replica) fn cascades(
    schema: &rocky_core::LogicalSchema,
    table: &str,
) -> BTreeSet<String> {
    let mut reached = BTreeSet::from([table.to_ascii_lowercase()]);
    let mut work = vec![table.to_ascii_lowercase()];
    while let Some(parent) = work.pop() {
        for child in &schema.tables {
            let acts = child
                .foreign_keys
                .iter()
                .any(|key| key.table.eq_ignore_ascii_case(&parent) && key.on_delete != "NO ACTION");
            let name = child.sql_name.to_ascii_lowercase();
            if child.class == TableClass::Replayed && acts && reached.insert(name.clone()) {
                work.push(name);
            }
        }
    }
    reached
}

/// Replayed tables whose replay order can change `table`'s outcomes,
/// `table` included: those a foreign key joins to it either way, or an
/// assertion reads with it, transitively.
pub(in crate::replica) fn linked(
    schema: &rocky_core::LogicalSchema,
    table: &str,
) -> BTreeSet<String> {
    let replayed = |name: &str| {
        schema
            .table(name)
            .is_some_and(|table| table.class == TableClass::Replayed)
    };
    let mut reached = BTreeSet::from([table.to_ascii_lowercase()]);
    let mut work = vec![table.to_ascii_lowercase()];
    while let Some(name) = work.pop() {
        let mut next = Vec::new();
        for child in schema
            .tables
            .iter()
            .filter(|child| child.class == TableClass::Replayed)
        {
            let child_name = child.sql_name.to_ascii_lowercase();
            for key in &child.foreign_keys {
                if child_name == name {
                    next.push(key.table.to_ascii_lowercase());
                } else if key.table.eq_ignore_ascii_case(&name) {
                    next.push(child_name.clone());
                }
            }
        }
        for assertion in &schema.assertions {
            let tables = assertion.tables();
            if tables.iter().any(|read| read.eq_ignore_ascii_case(&name)) {
                next.extend(tables.iter().map(|read| read.to_ascii_lowercase()));
            }
        }
        for name in next {
            if replayed(&name) && reached.insert(name.clone()) {
                work.push(name);
            }
        }
    }
    reached
}

/// The tables SQLite reads when replaying writes to `changed`: those and
/// the parents their foreign keys check.
pub(in crate::replica) fn checked(
    schema: &rocky_core::LogicalSchema,
    changed: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut read = changed.clone();
    for name in changed {
        if let Some(table) = schema.table(name) {
            read.extend(
                table
                    .foreign_keys
                    .iter()
                    .map(|key| key.table.to_ascii_lowercase()),
            );
        }
    }
    read
}

/// Refuses a transaction of several replayed members that deletes from a
/// table whose delete actions reach another member's table: members replay
/// in scope order, so the action could meet that member's rows in another
/// order than the author's.
pub(in crate::replica) fn check_member_order<'a>(
    schema: &rocky_core::LogicalSchema,
    members: impl IntoIterator<Item = (&'a str, &'a [rocky_core::replay::IntentStatement])> + Clone,
) -> Result<(), Error> {
    let deletes = |sql: &str| {
        let words: Vec<String> = sql
            .split_whitespace()
            .take(3)
            .map(str::to_ascii_uppercase)
            .collect();
        matches!(
            words.first().map(String::as_str),
            Some("DELETE" | "REPLACE")
        ) || words.windows(2).any(|pair| pair == ["OR", "REPLACE"])
    };
    for (table, statements) in members.clone() {
        if !statements.iter().any(|statement| deletes(&statement.sql)) {
            continue;
        }
        let reached = cascades(schema, table);
        if let Some((other, _)) = members.clone().into_iter().find(|(other, _)| {
            !other.eq_ignore_ascii_case(table) && reached.contains(&other.to_ascii_lowercase())
        }) {
            return Err(denied(&format!(
                "deleting from {table} changes {other}, which the transaction also writes; commit them apart"
            )));
        }
    }
    Ok(())
}

impl<A: RowApplication> Inner<A> {
    /// The first constraint the rows `written` leave violated, by name:
    /// a deferred foreign key (with `deferred_all`, any key), then each
    /// assertion reading a written table, once per written partition.
    pub(in crate::replica) async fn replayed_violation(
        &self,
        written: &[Written],
        deferred_all: bool,
    ) -> Result<Option<String>, Error> {
        let Some(typed) = self.workspace.typed.as_ref() else {
            return Ok(None);
        };
        let schema = typed.rows.schema();
        let wrote = |name: &str| {
            written
                .iter()
                .any(|(table, _)| table.eq_ignore_ascii_case(name))
        };
        for table in &schema.tables {
            let checked = table.class == TableClass::Replayed
                && table.foreign_keys.iter().any(|key| {
                    (key.deferred || deferred_all) && (wrote(&table.sql_name) || wrote(&key.table))
                });
            if !checked {
                continue;
            }
            let mut rows = self
                .conn
                .query(
                    "SELECT 1 FROM pragma_foreign_key_check(?) LIMIT 1",
                    [table.sql_name.clone()],
                )
                .await?;
            if rows.next().await?.is_some() {
                return Ok(Some(format!(
                    "FOREIGN KEY constraint failed: {}",
                    table.sql_name
                )));
            }
        }
        for assertion in &schema.assertions {
            let tables = assertion.tables();
            let mut partitions: Vec<&Vec<SqlValue>> = Vec::new();
            for (_, partition) in written.iter().filter(|(table, _)| tables.contains(table)) {
                if !partitions.contains(&partition) {
                    partitions.push(partition);
                }
            }
            for partition in partitions {
                let mut rules = BTreeMap::new();
                for name in &tables {
                    let logical = schema
                        .table(name)
                        .ok_or_else(|| Error::Corrupt("assertion table".into()))?;
                    let partitioned = !logical.partition_by.is_empty();
                    rules.insert(
                        name.clone(),
                        TablePartitions {
                            columns: super::super::partition::partition_columns(logical)?,
                            complete: !partitioned,
                            held: if partitioned {
                                vec![partition.clone()]
                            } else {
                                Vec::new()
                            },
                            waiting: Vec::new(),
                        },
                    );
                }
                let checked = rocky_storage::partition_sql::check_assertion(
                    &assertion.select_sql,
                    &schema.views,
                    &rules,
                )
                .map_err(|refusal| {
                    Error::Corrupt(format!("assertion {}: {refusal}", assertion.name))
                })?;
                let mut rows = self
                    .conn
                    .query(&checked.sql, storage::bindings(checked.params))
                    .await?;
                if rows.next().await?.is_some() {
                    return Ok(Some(format!("assertion {} failed", assertion.name)));
                }
            }
        }
        Ok(None)
    }
}
