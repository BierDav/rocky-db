//! Typed tables as secure rows: one row per business key, one field per
//! replicated column. The row contract that `EncryptedReplica` admits and a
//! secure SQL session commits. See `docs/runtime/secure-sql.md`.
use crate::{
    ApplicationManifest, Commitment, DomainId, KeyColumn, LogicalSchema, RowApplication, RowChange,
    RowFields, RowWrite, SchemaError, SqlValue, commitment, key_components,
};
use std::collections::{BTreeMap, BTreeSet};

/// One replayed table: its field per column, in declared order.
#[derive(Clone, Debug)]
pub struct TypedTable {
    pub sql_name: String,
    pub id: Commitment,
    pub fields: Vec<Commitment>,
    /// Column positions of the primary key, in key order.
    pub key: Vec<usize>,
    key_columns: Vec<KeyColumn>,
}
/// A logical schema's typed tables as a `RowApplication`.
#[derive(Clone, Debug)]
pub struct TypedRows {
    schema: LogicalSchema,
    domains: Vec<DomainId>,
    tables: BTreeMap<Commitment, TypedTable>,
    /// The schema generation of the signed manifest; 1 until a transition.
    generation: u32,
}
impl TypedRows {
    /// The schema must be supported on the secure profile.
    pub fn new(schema: LogicalSchema, domains: Vec<DomainId>) -> Result<Self, SchemaError> {
        schema.supported_on(crate::Profile::Secure)?;
        let mut tables = BTreeMap::new();
        for table in schema.typed() {
            let key: Vec<usize> = table
                .primary_key
                .iter()
                .filter_map(|name| {
                    table
                        .columns
                        .iter()
                        .position(|c| c.sql_name.eq_ignore_ascii_case(name))
                })
                .collect();
            let id = schema.table_id(table);
            tables.insert(
                id,
                TypedTable {
                    sql_name: table.sql_name.clone(),
                    id,
                    fields: table
                        .columns
                        .iter()
                        .map(|column| schema.field_id(table, column))
                        .collect(),
                    key_columns: key
                        .iter()
                        .map(|index| KeyColumn {
                            affinity: table.columns[*index].affinity,
                            collation: table.columns[*index].collation,
                        })
                        .collect(),
                    key,
                },
            );
        }
        Ok(Self {
            schema,
            domains,
            tables,
            generation: 1,
        })
    }
    /// These tables at schema generation `generation`.
    pub fn at_generation(mut self, generation: u32) -> Result<Self, SchemaError> {
        if generation == 0 {
            return Err(SchemaError::Invalid("generations start at 1".into()));
        }
        self.generation = generation;
        Ok(self)
    }
    pub fn generation(&self) -> u32 {
        self.generation
    }
    pub fn schema(&self) -> &LogicalSchema {
        &self.schema
    }
    pub fn table(&self, id: &Commitment) -> Option<&TypedTable> {
        self.tables.get(id)
    }
    pub fn tables(&self) -> impl Iterator<Item = &TypedTable> {
        self.tables.values()
    }
    /// The stable row identity of a key, bound to its domain and table.
    pub fn row_id(
        &self,
        domain: DomainId,
        table: &TypedTable,
        values: &[SqlValue],
    ) -> Result<Commitment, String> {
        let key: Vec<SqlValue> = table
            .key
            .iter()
            .filter_map(|index| values.get(*index).cloned())
            .collect();
        bound_row(domain, table.id, &table.key_columns, &key)
            .map_err(|error| format!("key of {}: {error}", table.sql_name))
    }

    /// Row fields of a typed row, in declared column order.
    pub fn fields(&self, table: &TypedTable, values: &[SqlValue]) -> Result<RowFields, String> {
        if values.len() != table.fields.len() {
            return Err(format!(
                "{} has {} columns",
                table.sql_name,
                table.fields.len()
            ));
        }
        Ok(table
            .fields
            .iter()
            .zip(values)
            .map(|(field, value)| {
                let mut bytes = Vec::new();
                value.encode(&mut bytes);
                (*field, bytes)
            })
            .collect())
    }
    /// The typed row of `fields`: every column present, in stored form.
    pub fn values(&self, table: &TypedTable, fields: &RowFields) -> Result<Vec<SqlValue>, String> {
        let logical = self
            .schema
            .tables
            .iter()
            .find(|candidate| candidate.sql_name == table.sql_name)
            .ok_or_else(|| format!("{} is not installed", table.sql_name))?;
        let absent = table
            .fields
            .iter()
            .filter(|field| !fields.contains_key(*field))
            .count();
        if fields.len() + absent != table.fields.len() {
            return Err(format!("{} row holds a foreign field", table.sql_name));
        }
        table
            .fields
            .iter()
            .zip(&logical.columns)
            .map(|(field, column)| {
                column_value(
                    &table.sql_name,
                    &column.sql_name,
                    column.affinity,
                    column.not_null,
                    fields.get(field).map(Vec::as_slice),
                )
            })
            .collect()
    }
    /// The immutable incarnation carried in both signed row images.
    pub fn identity(&self, change: &RowChange) -> Result<Option<crate::RowIdentity>, String> {
        let table = self
            .tables
            .get(&change.scope.table)
            .ok_or("unknown typed table")?;
        let logical = self
            .schema
            .table(&table.sql_name)
            .ok_or("unknown typed table")?;
        let id_index = logical
            .columns
            .iter()
            .position(|column| column.sql_name.eq_ignore_ascii_case("id"))
            .ok_or("missing identity column")?;
        let mut identity = None;
        for fields in change.before.iter().chain(change.after.iter()) {
            let values = self.values(table, fields)?;
            let SqlValue::Integer(id) = values[id_index] else {
                return Err("id must be an integer".into());
            };
            let id = crate::RowIdentity::from_integer(id).map_err(|error| error.to_string())?;
            if identity.is_some_and(|previous| previous != id) {
                return Err("a row's id cannot change".into());
            }
            identity = Some(id);
        }
        identity
            .map(Some)
            .ok_or_else(|| "identity row has no image".into())
    }
    pub fn partition(
        &self,
        table: &TypedTable,
        values: &[SqlValue],
    ) -> Result<Option<crate::PartitionTuple>, String> {
        let logical = self
            .schema
            .table(&table.sql_name)
            .ok_or("unknown typed table")?;
        if logical.partition_by.is_empty() {
            return Ok(None);
        }
        crate::PartitionTuple::new(
            logical
                .partition_by
                .iter()
                .map(|name| {
                    let position = logical
                        .columns
                        .iter()
                        .position(|column| column.sql_name.eq_ignore_ascii_case(name))
                        .ok_or("unknown partition column")?;
                    let column = &logical.columns[position];
                    let value = values
                        .get(position)
                        .ok_or("missing partition value")?
                        .clone();
                    let value = crate::PartitionValue::new(
                        KeyColumn {
                            affinity: column.affinity,
                            collation: column.collation,
                        },
                        value,
                    )
                    .map_err(|error| error.to_string())?;
                    Ok((self.schema.field_id(logical, column), value))
                })
                .collect::<Result<Vec<_>, String>>()?,
        )
        .map(Some)
        .map_err(|error| error.to_string())
    }
    pub fn change_partition(
        &self,
        change: &RowChange,
    ) -> Result<Option<crate::PartitionTuple>, String> {
        let table = self
            .tables
            .get(&change.scope.table)
            .ok_or("unknown typed table")?;
        let mut tuple = None;
        for fields in change.before.iter().chain(change.after.iter()) {
            let next = self.partition(table, &self.values(table, fields)?)?;
            if next.as_ref().is_some_and(|tuple| {
                tuple.scope(change.scope.domain, table.id).ok() != Some(change.scope)
            }) {
                return Err("row image differs from its partition scope".into());
            }
            if tuple.is_some() && tuple != next {
                return Err("partition columns cannot change".into());
            }
            tuple = next;
        }
        Ok(tuple)
    }
}
impl RowApplication for TypedRows {
    fn manifest(&self) -> ApplicationManifest {
        self.schema.manifest_at(&self.domains, self.generation)
    }
    fn permission_fields(&self) -> BTreeSet<Commitment> {
        BTreeSet::new()
    }
    fn row_partition(&self, change: &RowChange) -> Result<Option<crate::PartitionTuple>, String> {
        self.change_partition(change)
    }
    fn row_identity(&self, change: &RowChange) -> Result<Option<crate::RowIdentity>, String> {
        self.identity(change)
    }
    /// Typed tables replicate intents, never row images.
    fn validate_changes(&self, changes: &[RowChange]) -> Result<(), String> {
        if changes.is_empty() {
            Ok(())
        } else {
            Err("typed tables replicate intents, never rows".into())
        }
    }
    fn validate_write(&self, _write: &RowWrite) -> Result<(), String> {
        Err("typed tables replicate intents, never rows".into())
    }
}

/// The value of a column's default literal, as the definition writes it:
/// an integer, a real or a quoted string. NULL and anything else is none.
pub fn default_value(column: &crate::LogicalColumn) -> Option<SqlValue> {
    default_literal(column.affinity, column.default.as_deref()?)
}
fn default_literal(affinity: crate::Affinity, literal: &str) -> Option<SqlValue> {
    let value = if let Some(text) = literal
        .strip_prefix('\'')
        .and_then(|rest| rest.strip_suffix('\''))
    {
        SqlValue::Text(text.replace("''", "'"))
    } else if let Ok(integer) = literal.parse::<i64>() {
        SqlValue::Integer(integer)
    } else {
        SqlValue::real(
            literal
                .parse::<f64>()
                .ok()
                .filter(|real| real.is_finite())?,
        )?
    };
    affinity.store(value).ok()
}

fn bound_row(
    domain: DomainId,
    table: Commitment,
    columns: &[KeyColumn],
    values: &[SqlValue],
) -> Result<Commitment, String> {
    let components = key_components(columns, values).map_err(|error| error.to_string())?;
    Ok(commitment(
        "rocky.secure-row.v1",
        &crate::bound_key(domain, &table, &components),
    ))
}
fn column_value(
    table: &str,
    column: &str,
    affinity: crate::Affinity,
    not_null: bool,
    bytes: Option<&[u8]>,
) -> Result<SqlValue, String> {
    let mut bytes = bytes.ok_or_else(|| format!("{table}.{column} is missing"))?;
    let value = SqlValue::decode(&mut bytes)
        .ok()
        .filter(|_| bytes.is_empty())
        .ok_or_else(|| format!("{table}.{column} is not one value"))?;
    if affinity.store(value.clone()).ok().as_ref() != Some(&value)
        || (not_null && value == SqlValue::Null)
    {
        return Err(format!(
            "{table}.{column} holds a value outside its declared type"
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Affinity, Collation, ColumnClass, LOGICAL_SCHEMA_FORMAT, LogicalColumn, LogicalTable,
        MeshId, ResourceScope, SchemaSource, Scope, TableClass,
    };

    fn column(name: &str, affinity: Affinity, collation: Collation) -> LogicalColumn {
        LogicalColumn {
            sql_name: name.into(),
            affinity,
            not_null: true,
            default: None,
            collation,
            class: ColumnClass::Replicated,
        }
    }
    fn rows() -> TypedRows {
        let schema = LogicalSchema {
            format: LOGICAL_SCHEMA_FORMAT,
            publisher: [1; 32],
            application: "typed".into(),
            source: SchemaSource {
                kind: "test".into(),
                version: 1,
                identity: "t".into(),
            },
            tables: vec![LogicalTable {
                sql_name: "items".into(),
            granted_like: None,
                class: TableClass::Replayed,
                create_sql: "CREATE TABLE items(key TEXT NOT NULL COLLATE NOCASE PRIMARY KEY,n INTEGER NOT NULL,id INTEGER NOT NULL)".into(),
                auto_generate: false,
                columns: vec![
                    column("key", Affinity::Text, Collation::Nocase),
                    column("n", Affinity::Integer, Collation::Binary),
                    column("id", Affinity::Integer, Collation::Binary),
                ],
                primary_key: vec!["key".into()],
                partition_by: Vec::new(),
            partition_group: None,
                indexes: vec![crate::LogicalIndex { name: "items_identity".into(), unique: true, columns: vec![crate::IndexColumn { name: "id".into(), descending: false }], create_sql: "CREATE UNIQUE INDEX items_identity ON items(id)".into(), expressions: Vec::new(), predicate: None }],
                foreign_keys: Vec::new(),
            }],
            views: Vec::new(),
            assertions: Vec::new(),
        };
        TypedRows::new(schema, vec![DomainId([2; 16])]).unwrap()
    }

    #[test]
    fn a_row_is_named_by_its_key_and_holds_every_column_in_its_type() {
        let rows = rows();
        let table = rows.tables().next().unwrap().clone();
        let scope = ResourceScope {
            domain: Scope {
                mesh: MeshId([3; 16]),
                app: rows.schema().app_id(),
                domain: DomainId([2; 16]),
            },
            encryption: [4; 32],
            table: table.id,
        };
        let image = |id: &str, n: i64| {
            vec![
                SqlValue::Text(id.into()),
                SqlValue::Integer(n),
                SqlValue::Integer(4294967297),
            ]
        };
        let row = |id: &str| {
            rows.row_id(DomainId([2; 16]), &table, &image(id, 1))
                .unwrap()
        };
        // A respelled NOCASE key names the same row; another key does not.
        assert_eq!(row("a"), row("A"));
        assert_ne!(row("a"), row("b"));
        let fields = |id: &str, n: i64| rows.fields(&table, &image(id, n)).unwrap();
        assert_eq!(rows.values(&table, &fields("a", 1)).unwrap(), image("a", 1));
        let change = RowChange {
            scope,
            row: row("a"),
            before: None,
            after: Some(fields("a", 1)),
        };
        assert_eq!(
            rows.row_identity(&change).unwrap(),
            Some(crate::RowIdentity::from_integer(4294967297).unwrap())
        );
        // Typed tables replicate intents: no row image is admitted.
        assert!(
            rows.validate_changes(std::slice::from_ref(&change))
                .is_err()
        );
        assert!(rows.validate_write(&RowWrite::changed(change)).is_err());
        // Every column, each in its declared type.
        let mut missing = fields("a", 1);
        missing.pop_last();
        let mut text = fields("a", 1);
        let mut bytes = Vec::new();
        SqlValue::Text("one".into()).encode(&mut bytes);
        text.insert(table.fields[1], bytes);
        for invalid in [missing, text] {
            assert!(rows.values(&table, &invalid).is_err());
        }
    }

    #[test]
    fn partition_values_bind_a_row_to_its_scope() {
        let definition = serde_json::json!({"format":6,"publisher":"01".repeat(32),"application":"partitions","tables":[{"name":"items","class":"replayed","columns":[{"name":"list","type":"text","not_null":true,"collation":"nocase"},{"name":"key","type":"text","not_null":true}],"primary_key":["list","key"],"partition_by":["list"]}]});
        let schema = crate::SchemaDefinition::parse(&serde_json::to_vec(&definition).unwrap())
            .unwrap()
            .build()
            .unwrap();
        let rows = TypedRows::new(schema, vec![DomainId([2; 16])]).unwrap();
        let table = rows.tables().next().unwrap();
        let values = vec![
            SqlValue::Text("A".into()),
            SqlValue::Text("key".into()),
            SqlValue::Integer(4294967297),
        ];
        let domain = Scope {
            mesh: MeshId([3; 16]),
            app: rows.manifest().app,
            domain: DomainId([2; 16]),
        };
        let tuple = rows.partition(table, &values).unwrap().unwrap();
        let mut change = RowChange {
            scope: tuple.scope(domain, table.id).unwrap(),
            row: rows.row_id(domain.domain, table, &values).unwrap(),
            before: None,
            after: Some(rows.fields(table, &values).unwrap()),
        };
        assert_eq!(rows.row_partition(&change), Ok(Some(tuple)));
        let mut wrong = values.clone();
        wrong[0] = SqlValue::Text("B".into());
        change.after = Some(rows.fields(table, &wrong).unwrap());
        assert!(rows.row_partition(&change).is_err());
    }
}
