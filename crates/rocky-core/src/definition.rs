//! Portable schema definitions: the ORM-neutral way to construct a
//! `LogicalSchema` from data a host language can write, without Room or Rust.
//! See `docs/runtime/schema-definitions.md`.
use crate::{
    Affinity, Collation, ColumnClass, IndexColumn, LOGICAL_SCHEMA_FORMAT, LogicalAssertion,
    LogicalColumn, LogicalForeignKey, LogicalIndex, LogicalSchema, LogicalTable, SchemaError,
    SchemaSource, TableClass, commitment,
};
use serde::{Deserialize, Serialize};

/// The `SchemaSource::kind` of descriptors built from a definition.
pub const DEFINITION_SOURCE: &str = "rocky.definition";
/// Format 6: names are the identities of tables and fields, with no
/// separate entry. It builds `LOGICAL_SCHEMA_FORMAT` descriptors.
pub const DEFINITION_FORMAT: u32 = 6;
/// Largest definition document `SchemaDefinition::parse` accepts.
pub const MAX_DEFINITION_BYTES: usize = 1024 * 1024;

/// What an application declares about its tables. `build` generates the
/// statements and the canonical descriptor; nothing is written twice.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaDefinition {
    pub format: u32,
    /// 64 hexadecimal digits.
    pub publisher: String,
    pub application: String,
    pub tables: Vec<TableDefinition>,
    #[serde(default)]
    pub views: Vec<crate::LogicalView>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertions: Vec<LogicalAssertion>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TableDefinition {
    pub name: String,
    /// The replayed table whose grants this table follows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_like: Option<String>,
    pub class: TableClass,
    pub columns: Vec<ColumnDefinition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<String>,
    pub primary_key: Vec<String>,
    #[serde(default)]
    pub partition_by: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition_group: Option<String>,
    #[serde(default)]
    pub indexes: Vec<IndexDefinition>,
    /// References to the identity of another replayed table.
    #[serde(default)]
    pub foreign_keys: Vec<ForeignKeyDefinition>,
}
/// What deleting a parent does to its children, inside the same transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteAction {
    Cascade,
    SetNull,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignKeyDefinition {
    /// The child's columns, one per column of the parent's identity.
    pub columns: Vec<String>,
    /// The parent table.
    pub table: String,
    pub on_delete: DeleteAction,
    /// Checked when the transaction ends, as SQLite checks
    /// a deferred key at `COMMIT`, instead of after each statement.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deferred: bool,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColumnDefinition {
    pub name: String,
    #[serde(rename = "type")]
    pub affinity: Affinity,
    #[serde(default)]
    pub not_null: bool,
    /// A literal: string, number, boolean or null.
    #[serde(default)]
    pub default: Option<serde_json::Value>,
    #[serde(default = "binary")]
    pub collation: Collation,
    /// An expression over the row's replicated columns: a stored SQLite
    /// generated column.
    #[serde(default)]
    pub derived: Option<String>,
    #[serde(default)]
    pub local_only: bool,
}
fn binary() -> Collation {
    Collation::Binary
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexDefinition {
    pub name: String,
    pub columns: Vec<IndexColumn>,
    #[serde(default)]
    pub unique: bool,
    /// Terms indexed after `columns`, such as `lower(name)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expressions: Vec<String>,
    /// Indexes just the rows this expression holds for.
    #[serde(default, rename = "where", skip_serializing_if = "Option::is_none")]
    pub predicate: Option<String>,
}

fn invalid<T>(reason: impl Into<String>) -> Result<T, SchemaError> {
    Err(SchemaError::Invalid(reason.into()))
}
fn quoted(name: &str) -> String {
    format!("\"{name}\"")
}
fn publisher(hex: &str) -> Result<[u8; 32], SchemaError> {
    let digits = hex.as_bytes();
    if digits.len() != 64 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return invalid("publisher must be 64 hexadecimal digits");
    }
    let mut bytes = [0; 32];
    for (byte, pair) in bytes.iter_mut().zip(digits.chunks(2)) {
        let pair = std::str::from_utf8(pair).unwrap_or("00");
        *byte = u8::from_str_radix(pair, 16).unwrap_or(0);
    }
    Ok(bytes)
}
/// A JSON scalar as the SQL literal of a column default.
fn literal(value: &serde_json::Value) -> Result<String, SchemaError> {
    use serde_json::Value;
    Ok(match value {
        Value::Null => "NULL".into(),
        Value::Bool(value) => i64::from(*value).to_string(),
        Value::Number(number) if number.is_i64() || number.is_u64() => number.to_string(),
        Value::Number(number) => match number.as_f64() {
            Some(real) if real.is_finite() => format!("{real:?}"),
            _ => return invalid("default number"),
        },
        Value::String(text) if !text.contains('\0') => format!("'{}'", text.replace('\'', "''")),
        _ => return invalid("a default must be a string, number, boolean or null"),
    })
}
fn declared(affinity: Affinity) -> &'static str {
    match affinity {
        Affinity::Integer => "INTEGER",
        Affinity::Real => "REAL",
        Affinity::Text => "TEXT",
        Affinity::Blob => "BLOB",
        Affinity::Numeric => "NUMERIC",
    }
}
fn collation(collation: Collation) -> &'static str {
    match collation {
        Collation::Binary => "",
        Collation::Nocase => " COLLATE NOCASE",
        Collation::Rtrim => " COLLATE RTRIM",
    }
}

impl SchemaDefinition {
    /// Parses a definition document and builds its descriptor.
    pub fn parse(json: &[u8]) -> Result<Self, SchemaError> {
        if json.len() > MAX_DEFINITION_BYTES {
            return invalid("definition quota");
        }
        #[derive(Deserialize)]
        struct Format {
            format: u32,
        }
        let version: Format = serde_json::from_slice(json)
            .map_err(|error| SchemaError::Invalid(error.to_string()))?;
        if version.format != DEFINITION_FORMAT {
            return invalid("unsupported schema definition format");
        }
        serde_json::from_slice(json).map_err(|error| SchemaError::Invalid(error.to_string()))
    }
    /// The canonical descriptor. It is structurally valid; whether a
    /// profile can install it is `LogicalSchema::supported_on`. The same
    /// definition always builds the same descriptor.
    pub fn build(&self) -> Result<LogicalSchema, SchemaError> {
        if self.format != DEFINITION_FORMAT {
            return invalid("unsupported schema definition format");
        }
        let mut tables = self
            .tables
            .iter()
            .map(|table| table.build())
            .collect::<Result<Vec<_>, _>>()?;
        // References name the parent's identity, known once every table is built.
        let identities: Vec<(String, Vec<String>)> = tables
            .iter()
            .map(|table| (table.sql_name.clone(), table.identity_columns()))
            .collect();
        for (table, definition) in tables.iter_mut().zip(&self.tables) {
            // Declaration order does not matter, as for tables and indexes.
            let mut keys: Vec<_> = definition.foreign_keys.iter().collect();
            keys.sort_by(|a, b| a.columns.cmp(&b.columns));
            for key in keys {
                let references = identities
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(&key.table))
                    .map(|(_, columns)| columns.clone())
                    .ok_or_else(|| {
                        SchemaError::Invalid(format!(
                            "{} references unknown table {}",
                            table.sql_name, key.table
                        ))
                    })?;
                let key = LogicalForeignKey {
                    table: key.table.clone(),
                    columns: key.columns.clone(),
                    references,
                    on_delete: match key.on_delete {
                        DeleteAction::Cascade => crate::DELETE_CASCADE,
                        DeleteAction::SetNull => crate::DELETE_SET_NULL,
                    }
                    .into(),
                    on_update: "NO ACTION".into(),
                    deferred: key.deferred,
                };
                let clause = table.foreign_key_sql(&key);
                table.create_sql.pop();
                table.create_sql.push_str(&format!(", {clause})"));
                table.foreign_keys.push(key);
            }
        }
        tables.sort_by(|a, b| a.sql_name.cmp(&b.sql_name));
        let identity =
            serde_json::to_vec(self).map_err(|error| SchemaError::Invalid(error.to_string()))?;
        let schema = LogicalSchema {
            format: LOGICAL_SCHEMA_FORMAT,
            publisher: publisher(&self.publisher)?,
            application: self.application.clone(),
            source: SchemaSource {
                kind: DEFINITION_SOURCE.into(),
                version: self.format,
                identity: commitment("rocky.schema-definition.v1", &identity)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            },
            tables,
            views: self.views.clone(),
            assertions: self.assertions.clone(),
        };
        schema.validate()?;
        Ok(schema)
    }
}
impl TableDefinition {
    fn build(&self) -> Result<LogicalTable, SchemaError> {
        let name = &self.name;
        if !crate::identifier(name) {
            return invalid(format!("table name {name}"));
        }
        let mut columns = Vec::new();
        let mut parts = Vec::new();
        for column in &self.columns {
            if column.name == "id" {
                return invalid(format!(
                    "{name}.{} is supplied by Rocky; do not declare it",
                    column.name
                ));
            }
            if !crate::identifier(&column.name) {
                return invalid(format!("{name} column {}", column.name));
            }
            let class = match (&column.derived, column.local_only) {
                (Some(rule), false) => ColumnClass::Derived { rule: rule.clone() },
                (None, true) => ColumnClass::LocalOnly,
                (None, false) => ColumnClass::Replicated,
                (Some(_), true) => {
                    return invalid(format!(
                        "{name}.{} cannot be both derived and local-only",
                        column.name
                    ));
                }
            };
            let default = column.default.as_ref().map(literal).transpose()?;
            let mut part = format!("{} {}", quoted(&column.name), declared(column.affinity));
            if let (Some(rule), TableClass::Replayed) = (&column.derived, self.class) {
                if default.is_some() || !crate::logical::single_expression(rule) {
                    return invalid(format!("{name}.{} generated column", column.name));
                }
                part.push_str(&format!(" GENERATED ALWAYS AS ({rule}) STORED"));
            }
            if column.not_null {
                part.push_str(" NOT NULL");
            }
            if let Some(default) = &default {
                part.push_str(" DEFAULT ");
                part.push_str(default);
            }
            part.push_str(collation(column.collation));
            parts.push(part);
            columns.push(LogicalColumn {
                sql_name: column.name.clone(),
                affinity: column.affinity,
                not_null: column.not_null,
                default,
                collation: column.collation,
                class,
            });
        }
        parts.push(format!("{} INTEGER NOT NULL", quoted("id")));
        columns.push(LogicalColumn {
            sql_name: "id".into(),
            affinity: Affinity::Integer,
            not_null: true,
            default: None,
            collation: Collation::Binary,
            class: ColumnClass::Replicated,
        });
        // Table constraints follow every column.
        for check in &self.checks {
            if !crate::logical::single_expression(check) {
                return invalid(format!("{name} check constraint"));
            }
            parts.push(format!("CHECK ({check})"));
        }
        let key: Vec<String> = self
            .primary_key
            .iter()
            .map(|column| quoted(column))
            .collect();
        if !key.is_empty() {
            parts.push(format!("PRIMARY KEY({})", key.join(",")));
        }
        let mut indexes = Vec::new();
        for index in &self.indexes {
            if !crate::identifier(&index.name) {
                return invalid(format!("{name} index {}", index.name));
            }
            let mut terms: Vec<String> = index
                .columns
                .iter()
                .map(|column| {
                    let order = if column.descending { " DESC" } else { "" };
                    format!("{}{order}", quoted(&column.name))
                })
                .collect();
            let names: Vec<&str> = columns.iter().map(|c| c.sql_name.as_str()).collect();
            let mut fragments = index.expressions.iter().chain(&index.predicate).peekable();
            if fragments.peek().is_some()
                && (self.class != TableClass::Replayed
                    || !fragments.all(|sql| crate::logical::derived_rule(sql, &names)))
            {
                return invalid(format!(
                    "{name} index {}: expressions and predicates need a replayed table and one expression each",
                    index.name
                ));
            }
            terms.extend(index.expressions.iter().cloned());
            let predicate = index
                .predicate
                .as_ref()
                .map_or(String::new(), |sql| format!(" WHERE {sql}"));
            let unique = if index.unique { "UNIQUE " } else { "" };
            let create_sql = format!(
                "CREATE {unique}INDEX IF NOT EXISTS {} ON {} ({}){predicate}",
                quoted(&index.name),
                quoted(name),
                terms.join(",")
            );
            indexes.push(LogicalIndex {
                name: index.name.clone(),
                unique: index.unique,
                columns: index.columns.clone(),
                create_sql,
                expressions: index.expressions.clone(),
                predicate: index.predicate.clone(),
            });
        }
        let mut identity = self.partition_by.clone();
        if !identity.iter().any(|name| name == "id") {
            identity.push("id".into());
        }
        if self.primary_key != identity {
            if indexes.iter().any(|index| {
                index.unique
                    && index
                        .columns
                        .iter()
                        .map(|column| &column.name)
                        .eq(identity.iter())
            }) {
                return invalid(format!("{name}: Rocky supplies the identity index"));
            }
            let index_name = format!("{}_identity", self.name);
            indexes.push(LogicalIndex {
                name: index_name.clone(),
                unique: true,
                columns: identity
                    .iter()
                    .map(|name| IndexColumn {
                        name: name.clone(),
                        descending: false,
                    })
                    .collect(),
                create_sql: format!(
                    "CREATE UNIQUE INDEX IF NOT EXISTS {} ON {} ({})",
                    quoted(&index_name),
                    quoted(name),
                    identity
                        .iter()
                        .map(|name| quoted(name))
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                expressions: Vec::new(),
                predicate: None,
            });
        }
        indexes.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(LogicalTable {
            sql_name: name.clone(),
            granted_like: self.granted_like.clone(),
            class: self.class,
            create_sql: format!("CREATE TABLE {} ({})", quoted(name), parts.join(", ")),
            auto_generate: false,
            columns,
            primary_key: self.primary_key.clone(),
            partition_by: self.partition_by.clone(),
            partition_group: self.partition_group.clone(),
            indexes,
            foreign_keys: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Incompatibility, Profile};

    pub(super) const DEFINITION: &str = r#"{
        "format":6,
        "publisher": "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        "application": "notes",
        "tables": [
            {
                "name": "notes",
                "class": "replayed",
                "columns": [
                    {"name": "key", "type": "text", "not_null": true},
                    {"name": "folder", "type": "text", "not_null": true, "default": "inbox", "collation": "nocase"},
                    {"name": "body", "type": "text"},
                    {"name": "pinned", "type": "integer", "not_null": true, "default": false}
                ],
                "primary_key": ["key"],
                "indexes": [{"name": "notes_by_folder", "columns": [{"name": "folder", "descending": false}]}]
            },
            {
                "name": "drafts",
                "class": "local_only",
                "columns": [{"name": "key", "type": "integer", "not_null": true}],
                "primary_key": ["key"]
            }
        ]
    }"#;

    #[test]
    fn a_definition_builds_one_descriptor_only_the_secure_profile_replays() {
        let definition = SchemaDefinition::parse(DEFINITION.as_bytes()).unwrap();
        let schema = definition.build().unwrap();
        assert_eq!(schema, definition.build().unwrap());
        assert_eq!(schema.source.kind, DEFINITION_SOURCE);
        assert_eq!(
            schema
                .tables
                .iter()
                .map(|t| t.sql_name.as_str())
                .collect::<Vec<_>>(),
            ["drafts", "notes"]
        );
        let notes = schema.table("notes").unwrap();
        assert_eq!(
            notes.create_sql,
            "CREATE TABLE \"notes\" (\"key\" TEXT NOT NULL, \"folder\" TEXT NOT NULL DEFAULT 'inbox' COLLATE NOCASE, \"body\" TEXT, \"pinned\" INTEGER NOT NULL DEFAULT 0, \"id\" INTEGER NOT NULL, PRIMARY KEY(\"key\"))"
        );
        assert_eq!(notes.column("folder").unwrap().collation, Collation::Nocase);
        assert_eq!(
            crate::declared_collations(&notes.create_sql),
            vec![("folder".to_string(), "NOCASE".to_string())]
        );
        schema.supported_on(Profile::Secure).unwrap();
        assert_eq!(
            schema.supported_on(Profile::Trusted),
            Err(SchemaError::Incompatible {
                table: "notes".into(),
                reason: Incompatibility::Unsupported(TableClass::Replayed),
            })
        );
        let bytes = schema.canonical().unwrap();
        assert_eq!(LogicalSchema::parse(&bytes).unwrap(), schema);
    }

    #[test]
    fn unsupported_definition_and_descriptor_versions_are_refused() {
        // Definitions and the descriptors they build use the current format.
        for format in [0, 1, 2, 3, 4, 5, 7] {
            let mut definition = SchemaDefinition::parse(DEFINITION.as_bytes()).unwrap();
            definition.format = format;
            let error = definition.build().unwrap_err().to_string();
            assert_eq!(
                error,
                SchemaError::Invalid("unsupported schema definition format".into()).to_string()
            );
        }
        for format in [0, 1, 2, 3, 4, 5, 7] {
            let mut descriptor = SchemaDefinition::parse(DEFINITION.as_bytes())
                .unwrap()
                .build()
                .unwrap();
            descriptor.format = format;
            assert!(crate::TypedRows::new(descriptor.clone(), vec![]).is_err());
            assert!(descriptor.supported_on(crate::Profile::Secure).is_err());
        }
    }

    #[test]
    fn malformed_definitions_are_refused() {
        let mut definition = SchemaDefinition::parse(DEFINITION.as_bytes()).unwrap();
        definition.publisher = "zz".into();
        assert!(definition.build().is_err());
        let mut definition = SchemaDefinition::parse(DEFINITION.as_bytes()).unwrap();
        definition.tables[0].columns[0].name = "id; DROP".into();
        assert!(definition.build().is_err());
        let mut definition = SchemaDefinition::parse(DEFINITION.as_bytes()).unwrap();
        definition.tables[0].columns[2].default = Some(serde_json::json!([1]));
        assert!(definition.build().is_err());
        let mut definition = SchemaDefinition::parse(DEFINITION.as_bytes()).unwrap();
        definition.tables[0].primary_key = vec!["absent".into()];
        assert!(definition.build().is_err());
        assert!(SchemaDefinition::parse(br#"{"format":1,"unknown":true}"#).is_err());
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    #[test]
    fn identity_columns_are_implicit_on_every_table_and_fingerprinted() {
        let mut definition = SchemaDefinition::parse(super::tests::DEFINITION.as_bytes()).unwrap();
        definition.format = DEFINITION_FORMAT;
        for table in &mut definition.tables {
            table.columns[0].name = "key".into();
            table.primary_key = vec!["key".into()];
        }
        let schema = definition.build().unwrap();
        assert_eq!(schema.format, crate::LOGICAL_SCHEMA_FORMAT);
        for table in &schema.tables {
            assert_eq!(table.column("id").unwrap().affinity, Affinity::Integer);
            assert!(
                table
                    .indexes
                    .iter()
                    .any(|index| table.is_identity_index(index))
            );
        }
        schema.supported_on(crate::Profile::Secure).unwrap();
        let mut invalid = schema.clone();
        invalid.tables[0].indexes.clear();
        assert!(
            invalid
                .validate()
                .unwrap_err()
                .to_string()
                .contains("identity index")
        );
        let mut reserved = definition.clone();
        reserved.tables[0].columns[0].name = "id".into();
        assert!(
            reserved
                .build()
                .unwrap_err()
                .to_string()
                .contains("do not declare")
        );
        definition.tables[0].primary_key = vec!["id".into()];
        let id_key = definition.build().unwrap();
        let notes = id_key.table("notes").unwrap();
        assert!(
            !notes
                .indexes
                .iter()
                .any(|index| index.name == "notes_identity")
        );
        assert_ne!(
            schema.replicated_fingerprint(),
            id_key.replicated_fingerprint()
        );
    }
}

#[cfg(test)]
mod partition_tests {
    use super::*;
    fn definition() -> SchemaDefinition {
        SchemaDefinition::parse(br#"{"format":6,"publisher":"1111111111111111111111111111111111111111111111111111111111111111","application":"partitions","tables":[{"name":"items","class":"replayed","columns":[{"name":"list","type":"text","not_null":true,"collation":"nocase"},{"name":"key","type":"text","not_null":true}],"primary_key":["list","key"],"partition_by":["list"]}]}"#).unwrap()
    }
    #[test]
    fn partition_shape_identity_and_manifest_are_bound() {
        let schema = definition().build().unwrap();
        let table = schema.table("items").unwrap();
        assert_eq!(table.partition_by, ["list"]);
        assert_eq!(table.identity_columns(), ["list", "id"]);
        assert!(
            table
                .indexes
                .iter()
                .any(|index| table.is_identity_index(index))
        );
        assert_eq!(
            table.indexes[0].create_sql,
            "CREATE UNIQUE INDEX IF NOT EXISTS \"items_identity\" ON \"items\" (\"list\",\"id\")"
        );
        schema.supported_on(crate::Profile::Secure).unwrap();
        assert_eq!(
            LogicalSchema::parse(&schema.canonical().unwrap()).unwrap(),
            schema
        );
        let mut unpartitioned = definition();
        unpartitioned.tables[0].partition_by.clear();
        assert_ne!(
            schema.manifest(&[]).hash(),
            unpartitioned.build().unwrap().manifest(&[]).hash()
        );
        let mut legacy = schema.clone();
        legacy.format = 2;
        assert!(legacy.validate().is_err());
        let mut wrong_index = schema.clone();
        wrong_index.tables[0].indexes[0].columns.remove(0);
        assert!(wrong_index.validate().is_err());
    }
    #[test]
    fn partitioned_tables_refuse_incomplete_indexes_and_references() {
        let reason = |json: &str| match SchemaDefinition::parse(json.as_bytes())
            .unwrap()
            .build()
            .unwrap()
            .supported_on(crate::Profile::Secure)
        {
            Err(SchemaError::Incompatible { reason, .. }) => reason,
            other => panic!("{other:?}"),
        };
        let items = |extra: &str| {
            format!(
                r#"{{"format":6,"publisher":"1111111111111111111111111111111111111111111111111111111111111111","application":"partitions","tables":[{{"name":"lists","class":"replayed","columns":[{{"name":"title","type":"text"}}],"primary_key":["id"]}},{{"name":"items","class":"replayed","columns":[{{"name":"list","type":"text","not_null":true}},{{"name":"key","type":"text","not_null":true}},{{"name":"code","type":"text"}},{{"name":"parent","type":"integer"}}],"primary_key":["list","key"],"partition_by":["list"],"partition_group":"list"{extra}}}]}}"#
            )
        };
        assert_eq!(
            reason(&items(
                r#","foreign_keys":[{"columns":["parent"],"table":"lists","on_delete":"set_null"}]"#
            )),
            crate::Incompatibility::CrossScopeReference(
                "a partitioned child cannot reference an unpartitioned parent".into()
            )
        );
        // A unique index of a partitioned table is checked within the
        // partition it replays in.
        let unique = items(
            r#","indexes":[{"name":"items_code","columns":[{"name":"list","descending":false},{"name":"code","descending":false}],"unique":true}]"#,
        );
        SchemaDefinition::parse(unique.as_bytes())
            .unwrap()
            .build()
            .unwrap()
            .supported_on(crate::Profile::Secure)
            .unwrap();
    }
    #[test]
    fn a_set_null_reference_with_a_partition_column_nulls_only_its_nullable_columns() {
        let json = r#"{"format":6,"publisher":"1111111111111111111111111111111111111111111111111111111111111111","application":"shop","tables":[{"name":"categories","class":"replayed","columns":[{"name":"list","type":"integer","not_null":true}],"primary_key":["list","id"],"partition_by":["list"],"partition_group":"list"},{"name":"items","class":"replayed","columns":[{"name":"list","type":"integer","not_null":true},{"name":"category","type":"integer"}],"primary_key":["list","id"],"partition_by":["list"],"partition_group":"list","foreign_keys":[{"columns":["list","category"],"table":"categories","on_delete":"set_null"}]}]}"#;
        let schema = SchemaDefinition::parse(json.as_bytes())
            .unwrap()
            .build()
            .unwrap();
        schema.supported_on(crate::Profile::Secure).unwrap();
        let items = schema.table("items").unwrap();
        assert!(items.create_sql.contains(
            "FOREIGN KEY(\"list\",\"category\") REFERENCES \"categories\"(\"list\",\"id\") ON DELETE NO ACTION"
        ));
        assert_eq!(
            schema.delete_triggers(|_| true),
            ["CREATE TRIGGER \"rocky_set_null_items_0\" AFTER DELETE ON \"categories\" FOR EACH ROW BEGIN UPDATE \"items\" SET \"category\"=NULL WHERE \"list\"=OLD.\"list\" AND \"category\"=OLD.\"id\"; END"]
        );
        assert!(schema.delete_triggers(|name| name == "items").is_empty());
    }
    #[test]
    fn removed_table_classes_are_refused() {
        let json = |class: &str| {
            format!(
                r#"{{"format":6,"publisher":"1111111111111111111111111111111111111111111111111111111111111111","application":"stock","tables":[{{"name":"stock","class":"{class}","columns":[{{"name":"item","type":"text","not_null":true}}],"primary_key":["item"]}}]}}"#
            )
        };
        SchemaDefinition::parse(json("replayed").as_bytes()).unwrap();
        for class in ["mergeable", "command_controlled", "confirmed_read_only"] {
            assert!(SchemaDefinition::parse(json(class).as_bytes()).is_err());
        }
    }
    #[test]
    fn invalid_and_legacy_partition_declarations_are_refused() {
        for columns in [vec!["absent"], vec!["list", "list"], vec!["id"]] {
            let mut definition = definition();
            definition.tables[0].partition_by = columns.into_iter().map(String::from).collect();
            assert!(definition.build().is_err());
        }
        let mut nullable = definition();
        nullable.tables[0].columns[0].not_null = false;
        assert!(nullable.build().is_err());
        let mut legacy = definition();
        legacy.format = 2;
        assert!(legacy.build().is_err());
        let mut own_id = definition();
        own_id.tables[0].primary_key = vec!["id".into()];
        own_id.tables[0].partition_by = vec!["id".into()];
        let schema = own_id.build().unwrap();
        assert!(schema.table("items").unwrap().indexes.is_empty());
        schema.validate().unwrap();
    }
}

#[cfg(test)]
mod replayed_tests {
    use super::*;
    use crate::{Incompatibility, Profile};

    /// `teams` and its `members` replay in partition group `org`; `notes`
    /// is unpartitioned.
    fn definition(extra: serde_json::Value) -> SchemaDefinition {
        let mut json = serde_json::json!({
            "format": 6,
            "publisher": "1111111111111111111111111111111111111111111111111111111111111111",
            "application": "replayed",
            "tables": [
                {"name": "teams", "class": "replayed",
                 "columns": [{"name": "org", "type": "text", "not_null": true},
                             {"name": "name", "type": "text", "not_null": true},
                             {"name": "cap", "type": "integer", "not_null": true}],
                 "checks": ["cap BETWEEN 1 AND 10"],
                 "primary_key": ["org", "id"], "partition_by": ["org"], "partition_group": "org"},
                {"name": "members", "class": "replayed",
                 "columns": [{"name": "org", "type": "text", "not_null": true},
                             {"name": "team", "type": "integer", "not_null": true},
                             {"name": "email", "type": "text", "not_null": true}],
                 "primary_key": ["org", "id"], "partition_by": ["org"], "partition_group": "org",
                 "indexes": [{"name": "members_email", "unique": true,
                              "columns": [{"name": "org", "descending": false},
                                          {"name": "email", "descending": false}]}],
                 "foreign_keys": [{"columns": ["org", "team"], "table": "teams",
                                   "on_delete": "cascade", "deferred": true}]},
                {"name": "notes", "class": "replayed",
                 "columns": [{"name": "body", "type": "text"}], "primary_key": ["id"]}
            ],
            "assertions": [{"name": "team_cap",
                            "select_sql": "SELECT t.id FROM teams t JOIN members m ON m.org = t.org AND m.team = t.id GROUP BY t.id HAVING COUNT(*) > MIN(t.cap)"}]
        });
        if let serde_json::Value::Object(extra) = extra {
            for (key, value) in extra {
                json[key] = value;
            }
        }
        SchemaDefinition::parse(&serde_json::to_vec(&json).unwrap()).unwrap()
    }
    fn refusal(definition: &SchemaDefinition) -> Option<(String, Incompatibility)> {
        match definition.build().unwrap().supported_on(Profile::Secure) {
            Ok(()) => None,
            Err(SchemaError::Incompatible { table, reason }) => Some((table, reason)),
            Err(error) => panic!("{error}"),
        }
    }
    fn table<'a>(definition: &'a mut SchemaDefinition, name: &str) -> &'a mut TableDefinition {
        definition
            .tables
            .iter_mut()
            .find(|table| table.name == name)
            .unwrap()
    }

    #[test]
    fn replayed_tables_install_checks_unique_indexes_and_their_declared_references() {
        let schema = definition(serde_json::Value::Null).build().unwrap();
        schema.supported_on(Profile::Secure).unwrap();
        let teams = schema.table("teams").unwrap();
        assert!(teams.create_sql.contains(
            "\"id\" INTEGER NOT NULL, CHECK (cap BETWEEN 1 AND 10), PRIMARY KEY"
        ));
        let members = schema.table("members").unwrap();
        assert!(members.create_sql.ends_with(
            "FOREIGN KEY(\"org\",\"team\") REFERENCES \"teams\"(\"org\",\"id\") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED)"
        ));
        assert!(members.foreign_keys[0].deferred);
        // An immediate key is checked per statement.
        let mut immediate = definition(serde_json::Value::Null);
        table(&mut immediate, "members").foreign_keys[0].deferred = false;
        let immediate = immediate.build().unwrap();
        assert!(
            immediate
                .table("members")
                .unwrap()
                .create_sql
                .ends_with("ON DELETE CASCADE)")
        );
        // What replays is what replicas agree on.
        assert_ne!(
            schema.replicated_fingerprint(),
            immediate.replicated_fingerprint()
        );
        let mut capped = definition(serde_json::Value::Null);
        table(&mut capped, "teams").checks = vec!["cap BETWEEN 1 AND 20".into()];
        assert_ne!(
            schema.manifest(&[]).hash(),
            capped.build().unwrap().manifest(&[]).hash()
        );
        let mut uncapped = schema.clone();
        uncapped.assertions.clear();
        assert_ne!(
            schema.replicated_fingerprint(),
            uncapped.replicated_fingerprint()
        );
        // A descriptor's references must match its statement.
        let mut hidden = schema.clone();
        let members = hidden
            .tables
            .iter_mut()
            .find(|table| table.sql_name == "members")
            .unwrap();
        members.create_sql = members.create_sql.replace(" ON DELETE CASCADE", "");
        assert_eq!(
            hidden.installable(),
            Err(SchemaError::Incompatible {
                table: "members".into(),
                reason: Incompatibility::Reference("org".into()),
            })
        );
    }

    #[test]
    fn replayed_tables_declare_generated_columns_and_index_terms() {
        let parsed = |edit: &dyn Fn(&mut serde_json::Value)| {
            let mut json = serde_json::json!({
                "format": 6, "publisher": "00".repeat(32), "application": "terms",
                "tables": [{"name": "items", "class": "replayed", "primary_key": ["id"],
                    "columns": [{"name": "name", "type": "text", "not_null": true},
                                {"name": "cap", "type": "integer", "not_null": true},
                                {"name": "double", "type": "integer", "derived": "cap * 2"}],
                    "checks": ["double < 10"],
                    "indexes": [{"name": "by_name", "unique": true, "columns": [],
                                 "expressions": ["lower(name)"], "where": "cap > 0"}]}]
            });
            edit(&mut json);
            SchemaDefinition::parse(&serde_json::to_vec(&json).unwrap())?.build()
        };
        let schema = parsed(&|_| {}).unwrap();
        schema.supported_on(Profile::Secure).unwrap();
        let items = schema.table("items").unwrap();
        assert!(
            items
                .create_sql
                .contains("GENERATED ALWAYS AS (cap * 2) STORED")
        );
        assert!(
            items.indexes[0]
                .create_sql
                .ends_with("(lower(name)) WHERE cap > 0")
        );
        for (pointer, sql) in [
            ("/tables/0/indexes/0/where", "cap > random()"),
            ("/tables/0/indexes/0/expressions/0", "lower(absent)"),
            ("/tables/0/indexes/0/where", "cap > 0; DROP TABLE items"),
            ("/tables/0/indexes/0/where", "cap > (SELECT 1)"),
            (
                "/tables/0/columns/2/derived",
                "cap) STORED, x INTEGER AS (1",
            ),
            ("/tables/0/checks/0", "cap > 0) CHECK (1"),
        ] {
            let refused = parsed(&|json| *json.pointer_mut(pointer).unwrap() = sql.into());
            assert!(matches!(refused, Err(SchemaError::Invalid(_))), "{sql}");
        }
        let refused = parsed(&|json| json["tables"][0]["class"] = "local_only".into());
        assert!(matches!(refused, Err(SchemaError::Invalid(_))));
    }

    #[test]
    fn replayed_checks_accept_deterministic_expressions_and_name_other_functions() {
        let mut complex = definition(serde_json::Value::Null);
        table(&mut complex, "teams").checks = vec![
            "CASE WHEN cap > 5 THEN length(name) > 3 ELSE name <> '' END".into(),
            "name NOT IN ('admin', 'root') AND name NOT LIKE '%!%' AND name GLOB '[a-z]*'".into(),
            "coalesce(nullif(trim(name), ''), 'x') <> 'x' OR cap * 2 + 1 BETWEEN 3 AND 21".into(),
            "json_valid(json_object('n', name)) AND substr(upper(name), 1, 1) <> 'Z'".into(),
        ];
        assert_eq!(refusal(&complex), None);
        for function in ["random", "sqlite_version", "date", "sin"] {
            let mut refused = definition(serde_json::Value::Null);
            table(&mut refused, "teams").checks = vec![format!("cap < {function}()")];
            assert_eq!(
                refusal(&refused),
                Some(("teams".into(), Incompatibility::Function(function.into()))),
                "{function}"
            );
        }
    }

    #[test]
    fn conflict_policies_existence_logs_and_update_policies_are_refused() {
        let parsed = |edit: &dyn Fn(&mut serde_json::Value)| {
            let mut json = serde_json::json!({
                "format": 6, "publisher": "00".repeat(32), "application": "removed",
                "tables": [{"name": "items", "class": "replayed", "primary_key": ["id"],
                    "columns": [{"name": "name", "type": "text", "not_null": true}],
                    "indexes": [{"name": "by_name", "unique": true,
                                 "columns": [{"name": "name", "descending": false}]}]}]
            });
            edit(&mut json);
            SchemaDefinition::parse(&serde_json::to_vec(&json).unwrap())
        };
        parsed(&|_| {}).unwrap();
        assert!(
            parsed(&|json| json["tables"][0]["indexes"][0]["on_conflict"] = "latest_wins".into())
                .is_err()
        );
        assert!(parsed(&|json| json["tables"][0]["existence_log"] = true.into()).is_err());
        assert!(parsed(&|json| json["update_policy"] = "assigned".into()).is_err());
    }

    #[test]
    fn assertions_read_replayed_tables_of_one_partition_group() {
        let assertion = |sql: &str| {
            definition(serde_json::json!({
                "assertions": [{"name": "rule", "select_sql": sql}]
            }))
        };
        let refused = |sql: &str| {
            refusal(&assertion(sql)).map(|(name, reason)| {
                assert_eq!(name, "rule");
                reason
            })
        };
        assert_eq!(
            refused("SELECT team FROM members GROUP BY team HAVING COUNT(*) > 3"),
            None
        );
        let other = |reason: &str| Some(Incompatibility::Assertion(reason.into()));
        assert_eq!(
            refused("SELECT * FROM members m, notes n WHERE n.body = m.email"),
            other("tables must share one partition group")
        );
        assert_eq!(
            refused("SELECT * FROM absent"),
            other("absent is not a table")
        );
        assert_eq!(
            refused("SELECT * FROM members WHERE email = random()"),
            Some(Incompatibility::Function("random".into()))
        );
        assert!(
            assertion("WITH m AS (SELECT * FROM members) SELECT * FROM m")
                .build()
                .is_err()
        );
        // Another partition group cannot be checked where the partition is.
        let mut regrouped = assertion("SELECT * FROM teams JOIN members USING (org)");
        table(&mut regrouped, "teams").partition_group = Some("teams".into());
        table(&mut regrouped, "members").foreign_keys.clear();
        assert_eq!(
            refusal(&regrouped),
            Some((
                "rule".into(),
                other("tables must share one partition group").unwrap()
            ))
        );
        // Names are identifiers and unique.
        let mut duplicate = definition(serde_json::Value::Null);
        duplicate.assertions.push(duplicate.assertions[0].clone());
        assert!(duplicate.build().is_err());
    }
}
