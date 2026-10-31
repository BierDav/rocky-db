//! Binds an installed domain to its logical schema: the descriptor is stored
//! once, a different one is refused, and the physical tables must match it.
use crate::{Error, scoped_connection::ScopedConnection, storage};
use rocky_core::{Affinity, Collation, LogicalSchema, LogicalTable, SqlValue};

const TABLE: &str = "CREATE TABLE IF NOT EXISTS rocky_logical_schema(id INTEGER PRIMARY KEY CHECK(id=1),descriptor BLOB NOT NULL)";

fn differs(table: &str, what: impl std::fmt::Display) -> Error {
    Error::Incompatible(format!(
        "installed table {table} differs from its logical schema: {what}"
    ))
}
fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
async fn pragma(
    conn: &ScopedConnection,
    name: &str,
    object: &str,
) -> Result<Vec<Vec<SqlValue>>, Error> {
    storage::rows(conn, &format!("PRAGMA {name}({})", quoted(object))).await
}
fn text(value: Option<&SqlValue>) -> &str {
    match value {
        Some(SqlValue::Text(text)) => text,
        _ => "",
    }
}
fn integer(value: Option<&SqlValue>) -> i64 {
    match value {
        Some(SqlValue::Integer(value)) => *value,
        _ => -1,
    }
}
#[derive(Default, PartialEq, Eq, PartialOrd, Ord)]
struct ForeignKey {
    table: String,
    columns: Vec<String>,
    references: Vec<String>,
    on_update: String,
    on_delete: String,
}
/// Key columns of an index as `(name, descending, collation)`.
async fn index_columns(
    conn: &ScopedConnection,
    index: &str,
) -> Result<Vec<(String, bool, String)>, Error> {
    Ok(pragma(conn, "index_xinfo", index)
        .await?
        .iter()
        .filter(|row| integer(row.get(5)) == 1)
        .map(|row| {
            (
                text(row.get(2)).to_string(),
                integer(row.get(3)) == 1,
                text(row.get(4)).to_string(),
            )
        })
        .collect())
}
async fn verify_table(
    conn: &ScopedConnection,
    schema: &LogicalSchema,
    table: &LogicalTable,
) -> Result<(), Error> {
    let name = table.sql_name.as_str();
    let physical = |logical: &str| {
        conn.names()
            .physical(logical)
            .map(str::to_string)
            .ok_or_else(|| differs(name, format!("{logical} is not installed")))
    };
    let installed = physical(name)?;
    let columns = pragma(conn, "table_xinfo", &installed).await?;
    if columns.len() != table.columns.len() {
        return Err(differs(name, "column count"));
    }
    for (row, column) in columns.iter().zip(&table.columns) {
        let default = match row.get(4) {
            Some(SqlValue::Text(default)) => Some(default.as_str()),
            _ => None,
        };
        let key = table
            .primary_key
            .iter()
            .position(|key| *key == column.sql_name)
            .map_or(0, |position| position as i64 + 1);
        if text(row.get(1)) != column.sql_name
            || Affinity::of_declared(text(row.get(2))) != column.affinity
            || integer(row.get(3)) != i64::from(column.not_null)
            || default != column.default.as_deref()
            || integer(row.get(5)) != key
            || integer(row.get(6)) != 0
        {
            return Err(differs(name, format!("column {}", column.sql_name)));
        }
    }
    let mut created = 0;
    for row in pragma(conn, "index_list", &installed).await? {
        let index = text(row.get(1));
        let unique = integer(row.get(2)) == 1;
        let actual = index_columns(conn, index).await?;
        match text(row.get(3)) {
            "c" => {
                let mut declared = None;
                for candidate in &table.indexes {
                    if physical(&candidate.name)? == index {
                        declared = Some(candidate);
                    }
                }
                let declared = declared.ok_or_else(|| differs(name, format!("index {index}")))?;
                let expected: Vec<_> = declared
                    .columns
                    .iter()
                    .map(|column| (column.name.as_str(), column.descending))
                    .collect();
                let found: Vec<_> = actual
                    .iter()
                    .map(|(column, descending, _)| (column.as_str(), *descending))
                    .collect();
                if unique != declared.unique || integer(row.get(4)) != 0 || expected != found {
                    return Err(differs(name, format!("index {}", declared.name)));
                }
                created += 1;
            }
            "pk" => {
                let expected: Vec<_> = table
                    .key()
                    .map(|column| (column.sql_name.as_str(), Some(column.collation)))
                    .collect();
                let found: Vec<_> = actual
                    .iter()
                    .map(|(column, _, collation)| (column.as_str(), Collation::named(collation)))
                    .collect();
                if expected != found {
                    return Err(differs(name, "primary key collation"));
                }
            }
            _ => {}
        }
    }
    if created != table.indexes.len() {
        return Err(differs(name, "missing index"));
    }
    // Rows of one key share its id and arrive together, in column order.
    let (mut found, mut current) = (Vec::<ForeignKey>::new(), None);
    for row in pragma(conn, "foreign_key_list", &installed).await? {
        let id = integer(row.first());
        if current != Some(id) {
            current = Some(id);
            found.push(ForeignKey {
                table: text(row.get(2)).to_string(),
                on_update: text(row.get(5)).to_string(),
                on_delete: text(row.get(6)).to_string(),
                ..ForeignKey::default()
            });
        }
        if let Some(key) = found.last_mut() {
            key.columns.push(text(row.get(3)).to_string());
            key.references.push(text(row.get(4)).to_string());
        }
    }
    let mut expected = Vec::new();
    for key in &table.foreign_keys {
        let target = match schema
            .tables
            .iter()
            .find(|table| table.sql_name.eq_ignore_ascii_case(&key.table))
        {
            Some(target) => physical(&target.sql_name)?,
            None => key.table.clone(),
        };
        expected.push(ForeignKey {
            table: target,
            columns: key.columns.clone(),
            references: key.references.clone(),
            on_update: key.on_update.to_ascii_uppercase(),
            on_delete: key.on_delete.to_ascii_uppercase(),
        });
    }
    expected.sort();
    found.sort();
    if expected != found {
        return Err(differs(name, "foreign keys"));
    }
    Ok(())
}
/// Runs inside the open transaction, after the application's tables exist.
pub(crate) async fn bind(conn: &ScopedConnection, schema: &LogicalSchema) -> Result<(), Error> {
    schema
        .supported_on(rocky_core::Profile::Trusted)
        .map_err(|error| Error::Incompatible(error.to_string()))?;
    let descriptor = schema
        .canonical()
        .map_err(|error| Error::Incompatible(error.to_string()))?;
    conn.execute(TABLE, ()).await?;
    let stored = storage::rows(
        conn,
        "SELECT descriptor FROM rocky_logical_schema WHERE id=1",
    )
    .await?;
    match stored.as_slice() {
        [] => {
            conn.execute(
                "INSERT INTO rocky_logical_schema VALUES(1,?)",
                [crate::sqlite::Value::Blob(descriptor)],
            )
            .await?;
        }
        [row] if row.as_slice() == [SqlValue::Blob(descriptor)] => {}
        [row] => {
            let known = matches!(row.as_slice(), [SqlValue::Blob(bytes)] if LogicalSchema::parse(bytes).is_ok());
            return Err(if known {
                Error::Incompatible(
                    "this file is bound to another logical schema; a migration is required".into(),
                )
            } else {
                Error::Corrupt("stored logical schema descriptor".into())
            });
        }
        _ => return Err(Error::Corrupt("logical schema binding".into())),
    }
    for table in &schema.tables {
        verify_table(conn, schema, table).await?;
    }
    Ok(())
}
