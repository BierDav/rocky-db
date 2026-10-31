//! Additive physical changes that preserve every stored and projected row.
use super::typed::{Typed, quoted};
use super::*;
use rocky_core::{ColumnClass, LogicalColumn, LogicalSchema, TableClass};

fn column_sql(column: &LogicalColumn) -> String {
    let affinity = match column.affinity {
        rocky_core::Affinity::Integer => "INTEGER",
        rocky_core::Affinity::Real => "REAL",
        rocky_core::Affinity::Text => "TEXT",
        rocky_core::Affinity::Blob => "BLOB",
        rocky_core::Affinity::Numeric => "NUMERIC",
    };
    let required = if column.not_null { " NOT NULL" } else { "" };
    let default = column
        .default
        .as_ref()
        .map(|value| format!(" DEFAULT {value}"))
        .unwrap_or_default();
    let collation = match column.collation {
        rocky_core::Collation::Binary => "BINARY",
        rocky_core::Collation::Nocase => "NOCASE",
        rocky_core::Collation::Rtrim => "RTRIM",
    };
    format!(
        "{} {affinity}{required}{default} COLLATE {collation}",
        quoted(&column.sql_name)
    )
}

pub(super) fn qualifies(before: &LogicalSchema, after: &LogicalSchema) -> bool {
    if before.views != after.views {
        return false;
    }
    before.tables.iter().all(|old| {
        let Some(new) = after.table(&old.sql_name) else {
            return false;
        };
        if old.class != new.class
            || old.primary_key != new.primary_key
            || old.partition_by != new.partition_by
            || old.partition_group != new.partition_group
            || old.foreign_keys != new.foreign_keys
            || old.granted_like != new.granted_like
            || old.auto_generate != new.auto_generate
            || old.indexes.iter().any(|index| !new.indexes.contains(index))
            || new
                .indexes
                .iter()
                .any(|index| index.unique && !old.indexes.contains(index))
            || old
                .columns
                .iter()
                .any(|column| new.column(&column.sql_name) != Some(column))
        {
            return false;
        }
        if old.class == TableClass::LocalOnly {
            return old == new;
        }
        new.columns
            .iter()
            .filter(|column| old.column(&column.sql_name).is_none())
            .all(|column| {
                column.class == ColumnClass::Replicated
                    && (!column.not_null
                        || rocky_core::default_value(column)
                            .is_some_and(|value| value != SqlValue::Null))
                    && !new.indexes.iter().any(|index| {
                        index.unique
                            && index
                                .columns
                                .iter()
                                .any(|term| term.name.eq_ignore_ascii_case(&column.sql_name))
                    })
            })
    })
}

impl<A: RowApplication> Inner<A> {
    /// Caller owns the follow transaction. This performs DDL and replaces
    /// descriptor metadata; it neither scans rows nor emits an event.
    pub(super) async fn switch_in_place(
        &mut self,
        schema: LogicalSchema,
        domain: rocky_core::Scope,
        readers: &BTreeMap<String, Commitment>,
    ) -> Result<bool, Error> {
        let Some((before, installed_domain, installed_readers)) = self.installed_typed().await?
        else {
            return Ok(false);
        };
        if domain != installed_domain
            || !qualifies(&before, &schema)
            || installed_readers
                .iter()
                .any(|(name, reader)| readers.get(name) != Some(reader))
        {
            return Ok(false);
        }
        let projected = Arc::new(
            self.authorized_projection(Typed::new(schema.clone(), domain, readers)?)
                .await?,
        );
        for table in &projected.tables {
            let logical = schema
                .table(&table.table.sql_name)
                .ok_or_else(|| Error::Corrupt("additive table descriptor".into()))?;
            match before.table(&logical.sql_name) {
                Some(old) => {
                    // History tables gain missing columns when capture is refreshed;
                    // they may still hold one an earlier schema removed.
                    for column in logical
                        .columns
                        .iter()
                        .filter(|column| old.column(&column.sql_name).is_none())
                    {
                        let declaration = column_sql(column);
                        self.conn
                            .execute(
                                format!(
                                    "ALTER TABLE {} ADD COLUMN {declaration}",
                                    quoted(&logical.sql_name)
                                ),
                                (),
                            )
                            .await?;
                    }
                    for index in logical
                        .indexes
                        .iter()
                        .filter(|index| !old.indexes.contains(index))
                    {
                        self.conn.execute(index.create_sql.clone(), ()).await?;
                    }
                }
                None => {
                    self.conn.execute(logical.create_sql.clone(), ()).await?;
                    for index in &logical.indexes {
                        self.conn.execute(index.create_sql.clone(), ()).await?;
                    }
                }
            }
        }
        self.reshape_undo(&before, &schema).await?;
        self.record_projection_access(&projected).await?;
        self.refresh_history_for(&projected).await?;
        self.conn
            .execute(
                "UPDATE secure_typed SET descriptor=?,domain=?,readers=? WHERE id=1",
                [
                    schema
                        .canonical()
                        .map_err(|error| Error::Incompatible(error.to_string()))?,
                    encode(&domain)?,
                    encode(readers)?,
                ],
            )
            .await?;
        self.workspace.typed = Some(projected);
        Ok(true)
    }
}
