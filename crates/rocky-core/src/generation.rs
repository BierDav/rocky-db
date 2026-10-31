//! Generations of an application definition: whether a new schema changes
//! what replicas agree on. See `docs/runtime/generations.md`.
use crate::{ColumnClass, LogicalSchema};
use std::collections::BTreeSet;

/// How a new schema relates to the installed one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaChange {
    /// The same installed schema.
    Unchanged,
    /// Local tables or SQL spelling: replicas agree as before. Only the
    /// local projection is rebuilt.
    Local,
    /// Replicated tables changed: a signed transition and a migration
    /// replay them in the new schema.
    Replicated,
}
impl SchemaChange {
    pub fn replicated(&self) -> bool {
        matches!(self, Self::Replicated)
    }
}

/// A change no transition can make: replicas holding data of the installed
/// schema would no longer agree on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unsupported {
    /// Another publisher or application name.
    Application,
}
impl std::fmt::Display for Unsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Application => f.write_str("another publisher or application"),
        }
    }
}
impl std::error::Error for Unsupported {}

/// Replicated tables and fields a new schema no longer has. Every device
/// that adopts it drops their data.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Removed {
    pub tables: BTreeSet<String>,
    /// `table.field` of tables that remain.
    pub fields: BTreeSet<String>,
}
impl Removed {
    pub fn is_empty(&self) -> bool {
        self.tables.is_empty() && self.fields.is_empty()
    }
}
/// What `new` removes of the installed `old`'s replicated data.
pub fn removed(old: &LogicalSchema, new: &LogicalSchema) -> Removed {
    let mut removed = Removed::default();
    for before in old.typed() {
        let Some(after) = new.typed().find(|table| table.sql_name == before.sql_name) else {
            removed.tables.insert(before.sql_name.clone());
            continue;
        };
        removed.fields.extend(
            before
                .columns
                .iter()
                .filter(|column| {
                    column.class == ColumnClass::Replicated
                        && after.column(&column.sql_name).is_none()
                })
                .map(|column| format!("{}.{}", before.sql_name, column.sql_name)),
        );
    }
    removed
}

/// Classifies `new` against the installed `old`.
pub fn classify(old: &LogicalSchema, new: &LogicalSchema) -> Result<SchemaChange, Unsupported> {
    if old.publisher != new.publisher || old.application != new.application {
        return Err(Unsupported::Application);
    }
    Ok(if old == new {
        SchemaChange::Unchanged
    } else if old.replicated_fingerprint() == new.replicated_fingerprint() {
        SchemaChange::Local
    } else {
        SchemaChange::Replicated
    })
}

/// The schema generation of a definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation {
    pub schema: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Affinity, Collation, ColumnClass, LOGICAL_SCHEMA_FORMAT, LogicalColumn, LogicalTable,
        SchemaSource, TableClass,
    };

    fn column(name: &str, not_null: bool) -> LogicalColumn {
        LogicalColumn {
            sql_name: name.into(),
            affinity: if name == "id" {
                Affinity::Integer
            } else {
                Affinity::Text
            },
            not_null,
            default: None,
            collation: Collation::Binary,
            class: ColumnClass::Replicated,
        }
    }
    fn table(name: &str, columns: Vec<LogicalColumn>) -> LogicalTable {
        let sql: Vec<String> = columns
            .iter()
            .map(|column| {
                let null = if column.not_null { " NOT NULL" } else { "" };
                let key = if column.sql_name == "id" {
                    " PRIMARY KEY"
                } else {
                    ""
                };
                format!(
                    "{} {}{null}{key}",
                    column.sql_name,
                    if column.affinity == Affinity::Integer {
                        "INTEGER"
                    } else {
                        "TEXT"
                    }
                )
            })
            .collect();
        LogicalTable {
            sql_name: name.into(),
            granted_like: None,
            class: TableClass::Replayed,
            create_sql: format!("CREATE TABLE {name}({})", sql.join(",")),
            auto_generate: false,
            columns,
            primary_key: vec!["id".into()],
            partition_by: Vec::new(),
            partition_group: None,
            indexes: Vec::new(),
            foreign_keys: Vec::new(),
        }
    }
    fn schema(tables: Vec<LogicalTable>) -> LogicalSchema {
        LogicalSchema {
            format: LOGICAL_SCHEMA_FORMAT,
            publisher: [1; 32],
            application: "app".into(),
            source: SchemaSource {
                kind: "test".into(),
                version: 1,
                identity: "app".into(),
            },
            tables,
            views: Vec::new(),
            assertions: Vec::new(),
        }
    }
    fn items(columns: &[(&str, bool)]) -> LogicalTable {
        let mut all = vec![column("id", true)];
        all.extend(
            columns
                .iter()
                .map(|(name, required)| column(name, *required)),
        );
        table("items", all)
    }

    #[test]
    fn local_and_replicated_changes_are_told_apart() {
        let old = schema(vec![items(&[("name", true)])]);
        assert_eq!(classify(&old, &old), Ok(SchemaChange::Unchanged));
        let mut spelled = old.clone();
        spelled.source.identity = "other".into();
        assert_eq!(classify(&old, &spelled), Ok(SchemaChange::Local));
        let added = schema(vec![items(&[("name", true), ("note", false)])]);
        assert_eq!(classify(&old, &added), Ok(SchemaChange::Replicated));
        let mut renamed = old.clone();
        renamed.application = "other".into();
        assert_eq!(classify(&old, &renamed), Err(Unsupported::Application));
    }
}
