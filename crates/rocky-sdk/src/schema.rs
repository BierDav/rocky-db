use crate::Failure;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schema {
    pub format: u32,
    pub application: String,
    pub version: u32,
    pub tables: Vec<rocky_core::TableDefinition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub views: Vec<rocky_core::LogicalView>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertions: Vec<rocky_core::LogicalAssertion>,
    /// SQL the first issuer to sign the schema's generation runs once, after
    /// signing it; see `docs/runtime/generations.md#migrations`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub migrations: Vec<Migration>,
}
/// Statements leading to application schema `version`, run in order in
/// one transaction.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Migration {
    pub version: u32,
    pub statements: Vec<MigrationStep>,
}
/// One statement of a migration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum MigrationStep {
    /// SQL run as it is.
    Sql(String),
    /// A row of table `insert` for each row `select` returns, its columns
    /// named like the table's, with an `id` Rocky issues.
    Insert { insert: String, select: String },
}
fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && name.as_bytes()[0].is_ascii_alphabetic()
}
impl Schema {
    pub fn parse(json: &str) -> Result<Self, Failure> {
        if json.len() > rocky_core::MAX_DEFINITION_BYTES {
            return Err("schema quota".into());
        }
        #[derive(Deserialize)]
        struct Format {
            format: u32,
        }
        let version: Format = serde_json::from_str(json)?;
        if version.format != rocky_core::DEFINITION_FORMAT {
            return Err("unsupported schema definition format".into());
        }
        let mut schema: Self = serde_json::from_str(json)?;
        schema.validate()?;
        {
            let tables = &mut schema.tables;
            tables.sort_by(|a, b| a.name.cmp(&b.name));
            for table in tables {
                table.indexes.sort_by(|a, b| a.name.cmp(&b.name));
            }
        }
        Ok(schema)
    }
    fn validate(&self) -> Result<(), Failure> {
        if !identifier(&self.application) || self.version == 0 {
            return Err("invalid application schema".into());
        }
        if self.format != rocky_core::DEFINITION_FORMAT {
            return Err("unsupported schema definition format".into());
        }
        {
            let tables = &self.tables;
            if tables.is_empty()
                || tables.len() > 64
                || tables
                    .iter()
                    .any(|table| table.columns.is_empty() || table.columns.len() > 128)
            {
                return Err("definition table or column quota".into());
            }
            if tables
                .iter()
                .any(|table| table.name.eq_ignore_ascii_case(crate::domain::REGISTRY))
            {
                return Err(format!(
                    "{} is reserved for the SDK's issuer registry",
                    crate::domain::REGISTRY
                )
                .into());
            }
            self.definition([0; 32])?
                .build()?
                .supported_on(rocky_core::Profile::Secure)?;
            self.validate_granted_like()?;
            if let Some(table) = self
                .migrations
                .iter()
                .flat_map(|migration| &migration.statements)
                .find_map(|step| match step {
                    MigrationStep::Insert { insert, .. }
                        if !self.tables.iter().any(|table| {
                            table.name == *insert && table.class == rocky_core::TableClass::Replayed
                        }) =>
                    {
                        Some(insert)
                    }
                    _ => None,
                })
            {
                return Err(format!(
                    "a migration inserts into {table}, which is no replayed table"
                )
                .into());
            }
            if self.migrations.len() > 64
                || self
                    .migrations
                    .windows(2)
                    .any(|pair| pair[0].version >= pair[1].version)
                || self.migrations.iter().any(|migration| {
                    migration.version == 0
                        || migration.version > self.version
                        || migration.statements.is_empty()
                        || migration.statements.len() > 64
                })
            {
                return Err(
                    "migrations name ascending versions up to the schema's, each with 1 to 64 statements"
                        .into(),
                );
            }
            Ok(())
        }
    }

    pub(crate) fn granted_like(&self) -> BTreeMap<String, String> {
        self.tables
            .iter()
            .filter_map(|table| {
                table
                    .granted_like
                    .as_ref()
                    .map(|like| (table.name.clone(), like.clone()))
            })
            .collect()
    }
    /// Each table follows one replayed table that follows none.
    fn validate_granted_like(&self) -> Result<(), Failure> {
        let replayed = |name: &str| {
            self.tables
                .iter()
                .any(|table| table.name == name && table.class == rocky_core::TableClass::Replayed)
        };
        let followers = self.granted_like();
        for (table, like) in &followers {
            if table == like || !replayed(table) || !replayed(like) || followers.contains_key(like)
            {
                return Err(format!(
                    "{table} cannot be granted like {like}: both must be distinct replayed tables, and {like} granted like none"
                )
                .into());
            }
        }
        Ok(())
    }
    pub fn definition(&self, publisher: [u8; 32]) -> Result<rocky_core::SchemaDefinition, Failure> {
        Ok(rocky_core::SchemaDefinition {
            format: self.format,
            publisher: data_encoding::HEXLOWER.encode(&publisher),
            application: self.application.clone(),
            views: self.views.clone(),
            assertions: self.assertions.clone(),
            tables: self.tables.clone(),
        })
    }
    pub(crate) fn names(&self) -> Vec<&str> {
        self.tables
            .iter()
            .map(|table| table.name.as_str())
            .collect()
    }
}

/// Schema construction uses the same validated definition as every other SDK.
pub struct SchemaBuilder(Schema);
impl Schema {
    pub fn builder(application: impl Into<String>, version: u32) -> SchemaBuilder {
        SchemaBuilder(Self {
            format: rocky_core::DEFINITION_FORMAT,
            application: application.into(),
            version,
            tables: Vec::new(),
            views: Vec::new(),
            assertions: Vec::new(),
            migrations: Vec::new(),
        })
    }
}
impl SchemaBuilder {
    #[must_use]
    pub fn table(mut self, table: impl Into<rocky_core::TableDefinition>) -> Self {
        self.0.tables.push(table.into());
        self
    }
    #[must_use]
    pub fn view(mut self, view: rocky_core::LogicalView) -> Self {
        self.0.views.push(view);
        self
    }
    /// An invariant across rows or tables of one partition group, run at the
    /// end of each transaction writing a table it reads.
    #[must_use]
    pub fn assertion(mut self, assertion: rocky_core::LogicalAssertion) -> Self {
        self.0.assertions.push(assertion);
        self
    }
    pub fn build(self) -> Result<Schema, Failure> {
        Schema::parse(&serde_json::to_string(&self.0)?)
    }
}

/// A typed table has a Rocky-managed `id` column. Use
/// `primary_key` to declare a natural key instead.
pub struct Table(rocky_core::TableDefinition);
impl Table {
    /// Replicates each transaction's statements; replicas replay them in
    /// canonical order and drop a transaction whose replay fails.
    pub fn replayed(name: impl Into<String>) -> Self {
        Self::of(name, rocky_core::TableClass::Replayed)
    }
    fn of(name: impl Into<String>, class: rocky_core::TableClass) -> Self {
        Self(rocky_core::TableDefinition {
            name: name.into(),
            granted_like: None,
            class,
            columns: Vec::new(),
            checks: Vec::new(),
            primary_key: vec!["id".into()],
            partition_by: Vec::new(),
            partition_group: None,
            indexes: Vec::new(),
            foreign_keys: Vec::new(),
        })
    }
    #[must_use]
    pub fn column(mut self, column: impl Into<rocky_core::ColumnDefinition>) -> Self {
        self.0.columns.push(column.into());
        self
    }
    #[must_use]
    pub fn primary_key(mut self, columns: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.0.primary_key = columns.into_iter().map(Into::into).collect();
        self
    }
    #[must_use]
    pub fn partition_by(mut self, columns: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.0.partition_by = columns.into_iter().map(Into::into).collect();
        self
    }
    #[must_use]
    pub fn index(mut self, index: rocky_core::IndexDefinition) -> Self {
        self.0.indexes.push(index);
        self
    }
    /// A `CHECK` of a replayed table, using deterministic functions only.
    /// SQLite's semantics apply: it holds after each statement, so assign
    /// columns that must change together in one `UPDATE`, and a NULL result
    /// passes, so add `IS NOT NULL` where absence is invalid.
    #[must_use]
    pub fn check(mut self, expression: impl Into<String>) -> Self {
        self.0.checks.push(expression.into());
        self
    }
    /// Access the complete language-neutral definition for advanced schema settings.
    pub fn definition(self) -> rocky_core::TableDefinition {
        self.0
    }
}
impl From<Table> for rocky_core::TableDefinition {
    fn from(table: Table) -> Self {
        table.0
    }
}

/// A nullable column by default; `required` adds NOT NULL.
pub struct Column(rocky_core::ColumnDefinition);
impl Column {
    pub fn new(name: impl Into<String>, affinity: rocky_core::Affinity) -> Self {
        Self(rocky_core::ColumnDefinition {
            name: name.into(),
            affinity,
            not_null: false,
            default: None,
            collation: rocky_core::Collation::Binary,
            derived: None,
            local_only: false,
        })
    }
    #[must_use]
    pub fn required(mut self) -> Self {
        self.0.not_null = true;
        self
    }
    #[must_use]
    pub fn default(mut self, value: impl Into<serde_json::Value>) -> Self {
        self.0.default = Some(value.into());
        self
    }
    pub fn definition(self) -> rocky_core::ColumnDefinition {
        self.0
    }
}
impl From<Column> for rocky_core::ColumnDefinition {
    fn from(column: Column) -> Self {
        column.0
    }
}
