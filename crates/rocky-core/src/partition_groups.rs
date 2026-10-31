//! Schema-level partition slots; table scopes remain independent.
use crate::{
    Commitment, KeyColumn, LOGICAL_SCHEMA_FORMAT, LogicalSchema, LogicalTable, PartitionValue,
    SchemaError, Scope, SqlValue, commitment, identifier,
};
use std::collections::BTreeMap;

/// A group name is unique, including the implicit group of an ungrouped table.
#[derive(Clone, Debug)]
pub struct PartitionGroup<'a> {
    pub name: &'a str,
    pub tables: Vec<&'a LogicalTable>,
    /// In `partition_by` declaration order, independent of column names.
    pub slots: Vec<KeyColumn>,
}

/// The shared address of a group partition, distinct from its table scopes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupAddress {
    pub domain: Scope,
    pub group: String,
    pub values: Vec<PartitionValue>,
    pub commitment: Commitment,
}

impl LogicalSchema {
    /// Validates group declarations and exposes their positional slots and members.
    pub fn partition_groups(&self) -> Result<Vec<PartitionGroup<'_>>, SchemaError> {
        let mut groups: BTreeMap<&str, PartitionGroup<'_>> = BTreeMap::new();
        for table in &self.tables {
            if let Some(name) = &table.partition_group
                && (!identifier(name)
                    || table.partition_by.is_empty()
                    || self.format != LOGICAL_SCHEMA_FORMAT)
            {
                return Err(SchemaError::Invalid(format!(
                    "{}: group {name} requires a valid name and partition columns in format 5",
                    table.sql_name
                )));
            }
            if table.partition_by.is_empty() {
                continue;
            }
            let name = table.partition_group.as_deref().unwrap_or(&table.sql_name);
            let slots = table
                .partition_by
                .iter()
                .map(|name| {
                    table
                        .column(name)
                        .map(|column| KeyColumn {
                            affinity: column.affinity,
                            collation: column.collation,
                        })
                        .ok_or_else(|| {
                            SchemaError::Invalid(format!(
                                "{}: absent partition column {name}",
                                table.sql_name
                            ))
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            if let Some(group) = groups.get_mut(name) {
                let first = group.tables[0];
                if first.partition_group.is_none() || table.partition_group.is_none() {
                    return Err(SchemaError::Invalid(format!(
                        "{} and {}: group {name} is reserved for its ungrouped table",
                        first.sql_name, table.sql_name
                    )));
                }
                if group.slots != slots {
                    return Err(SchemaError::Invalid(format!(
                        "{} and {}: group {name} partition slot counts, affinities and collations must match",
                        first.sql_name, table.sql_name
                    )));
                }
                group.tables.push(table);
            } else {
                groups.insert(
                    name,
                    PartitionGroup {
                        name,
                        tables: vec![table],
                        slots,
                    },
                );
            }
        }
        Ok(groups.into_values().collect())
    }

    /// Maps a table's partition values to its group's slots by position.
    pub fn group_address(
        &self,
        domain: Scope,
        table: &str,
        values: &[SqlValue],
    ) -> Result<GroupAddress, SchemaError> {
        self.validate()?;
        let group = self
            .partition_groups()?
            .into_iter()
            .find(|group| group.tables.iter().any(|member| member.sql_name == table))
            .ok_or_else(|| SchemaError::Invalid(format!("{table}: no partition group")))?;
        if values.len() != group.slots.len() {
            return Err(SchemaError::Invalid(format!(
                "{table}: partition slot count"
            )));
        }
        let values = group
            .slots
            .iter()
            .zip(values)
            .map(|(slot, value)| PartitionValue::new(*slot, value.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| SchemaError::Invalid(error.to_string()))?;
        let mut bytes = Vec::new();
        bytes.extend(domain.mesh.0);
        bytes.extend(domain.app.0);
        bytes.extend(domain.domain.0);
        bytes.extend((group.name.len() as u32).to_be_bytes());
        bytes.extend(group.name.as_bytes());
        bytes.push(values.len() as u8);
        for value in &values {
            let value = value.canonical_bytes();
            bytes.extend((value.len() as u32).to_be_bytes());
            bytes.extend(value);
        }
        if bytes.len() > crate::MAX_PARTITION_BYTES {
            return Err(SchemaError::Invalid("group address quota".into()));
        }
        Ok(GroupAddress {
            domain,
            group: group.name.into(),
            values,
            commitment: commitment("rocky.partition-group.v1", &bytes),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AppId, DomainId, MeshId, Profile, SchemaChange, SchemaDefinition, classify};
    fn definition() -> SchemaDefinition {
        serde_json::from_value(serde_json::json!({"format":6,"publisher":"11".repeat(32),"application":"groups","tables":[
            {"name":"lists","class":"replayed","columns":[{"name":"title","type":"text"}],"primary_key":["id"],"partition_by":["id"],"partition_group":"list"},
            {"name":"items","class":"replayed","columns":[{"name":"list","type":"integer","not_null":true},{"name":"key","type":"text","not_null":true}],"primary_key":["list","key"],"partition_by":["list"],"partition_group":"list"}
        ]})).unwrap()
    }
    fn domain() -> Scope {
        Scope {
            mesh: MeshId([1; 16]),
            app: AppId([2; 16]),
            domain: DomainId([3; 16]),
        }
    }
    #[test]
    fn different_column_identities_share_group_address_and_install() {
        let schema = definition().build().unwrap();
        schema.supported_on(Profile::Secure).unwrap();
        crate::TypedRows::new(schema.clone(), Vec::new()).unwrap();
        let a = schema
            .group_address(domain(), "lists", &[SqlValue::Integer(42)])
            .unwrap();
        let b = schema
            .group_address(domain(), "items", &[SqlValue::Integer(42)])
            .unwrap();
        assert_eq!(a, b);
        assert_ne!(
            a,
            schema
                .group_address(domain(), "items", &[SqlValue::Integer(43)])
                .unwrap()
        );
        assert_ne!(
            a,
            schema
                .group_address(
                    Scope {
                        domain: DomainId([9; 16]),
                        ..domain()
                    },
                    "items",
                    &[SqlValue::Integer(42)]
                )
                .unwrap()
        );
        let groups = schema.partition_groups().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "list");
        assert_eq!(groups[0].tables.len(), 2);
        assert!(schema.group_address(domain(), "items", &[]).is_err());
        assert!(
            schema
                .group_address(domain(), "items", &[SqlValue::Null])
                .is_err()
        );
        let mut renamed = definition();
        for table in &mut renamed.tables {
            table.partition_group = Some("another".into());
        }
        assert_ne!(
            a,
            renamed
                .build()
                .unwrap()
                .group_address(domain(), "lists", &[SqlValue::Integer(42)])
                .unwrap()
        );
    }
    #[test]
    fn compound_slots_use_declaration_order_and_sql_collations() {
        let mut def = definition();
        // Neither column identity nor the column's physical position defines its slot.
        def.tables[0] = def.tables[1].clone();
        def.tables[0].name = "lists".into();
        def.tables[0].columns[0].name = "customer".into();
        for table in &mut def.tables {
            table.columns[0].affinity = crate::Affinity::Text;
            table.columns[0].collation = crate::Collation::Nocase;
            table.columns[1].collation = crate::Collation::Rtrim;
            table.primary_key = table
                .columns
                .iter()
                .map(|column| column.name.clone())
                .collect();
            table.partition_by = table.primary_key.clone();
        }
        def.tables[0].columns.reverse();
        let schema = def.build().unwrap();
        assert_eq!(
            schema
                .group_address(
                    domain(),
                    "lists",
                    &[SqlValue::Text("ACME".into()), SqlValue::Text("x  ".into())]
                )
                .unwrap(),
            schema
                .group_address(
                    domain(),
                    "items",
                    &[SqlValue::Text("acme".into()), SqlValue::Text("x".into())]
                )
                .unwrap()
        );
        assert_ne!(
            schema
                .group_address(
                    domain(),
                    "items",
                    &[SqlValue::Text("a".into()), SqlValue::Text("b".into())]
                )
                .unwrap(),
            schema
                .group_address(
                    domain(),
                    "items",
                    &[SqlValue::Text("b".into()), SqlValue::Text("a".into())]
                )
                .unwrap()
        );
    }
    #[test]
    fn slot_mismatches_refuse_build_and_installation_naming_both_tables() {
        for mismatch in 0..3 {
            let mut def = definition();
            match mismatch {
                0 => def.tables[1].partition_by.push("key".into()),
                1 => def.tables[1].columns[0].affinity = crate::Affinity::Text,
                _ => def.tables[1].columns[0].collation = crate::Collation::Nocase,
            }
            let message = def.build().unwrap_err().to_string();
            assert!(
                message.contains("lists") && message.contains("items"),
                "{message}"
            );
            let mut descriptor = definition().build().unwrap();
            match mismatch {
                0 => descriptor.tables[0].partition_by.push("key".into()),
                1 => descriptor.tables[0].columns[0].affinity = crate::Affinity::Text,
                _ => descriptor.tables[0].columns[0].collation = crate::Collation::Nocase,
            }
            let message = descriptor.installable().unwrap_err().to_string();
            assert!(
                message.contains("lists") && message.contains("items"),
                "{message}"
            );
        }
    }
    #[test]
    fn implicit_groups_are_private_and_names_cannot_be_ambiguous() {
        let mut def = definition();
        for table in &mut def.tables {
            table.partition_group = None;
        }
        assert_eq!(def.build().unwrap().partition_groups().unwrap().len(), 2);
        def.tables[1].partition_group = Some("lists".into());
        let message = def.build().unwrap_err().to_string();
        assert!(
            message.contains("lists") && message.contains("items") && message.contains("reserved")
        );
        def.tables[1].partition_group = Some("".into());
        assert!(def.build().is_err());
        def.tables[1].partition_group = Some("list".into());
        def.tables[1].partition_by.clear();
        assert!(def.build().is_err());
    }
    #[test]
    fn group_changes_and_new_tables_are_replicated_changes() {
        let old = definition().build().unwrap();
        let mut def = definition();
        for table in &mut def.tables {
            table.partition_group = Some("renamed".into());
        }
        assert_eq!(
            classify(&old, &def.build().unwrap()),
            Ok(SchemaChange::Replicated)
        );
        let mut def = definition();
        let mut child = def.tables[1].clone();
        child.name = "categories".into();
        def.tables.push(child);
        assert_eq!(
            classify(&old, &def.build().unwrap()),
            Ok(SchemaChange::Replicated)
        );
    }
    #[test]
    fn descriptor_round_trip_and_previous_partition_format_refusal() {
        let schema = definition().build().unwrap();
        let bytes = schema.canonical().unwrap();
        assert_eq!(LogicalSchema::parse(&bytes).unwrap(), schema);
        let mut def = definition();
        def.format = 3;
        assert!(def.build().is_err());
        let mut old = schema;
        old.format = 3;
        assert!(old.installable().is_err());
        assert!(
            LogicalSchema::check_stored_row_identity(&serde_json::to_vec(&old).unwrap()).is_err()
        );
    }
}
