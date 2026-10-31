//! Format-2 typed secure tables of a consumer schema in one domain.
use crate::{Failure, schema::Schema};
use rocky_core::{
    ApplicationManifest, Commitment, DomainId, FieldSelection, LogicalSchema, MeshId,
    ResourceScope, RowApplication, Scope, TypedRows,
};
use rocky_credentials::{Grant, Profile, Resource};
use std::collections::{BTreeMap, BTreeSet};

/// The reserved collection of issuer records; see
/// `docs/decisions/0048-replicated-issuer-registry.md`.
pub(crate) const REGISTRY: &str = "issuer_registry";

pub(crate) struct Domain {
    /// The typed tables.
    pub app: TypedRows,
    pub scope: Scope,
    tables: BTreeMap<String, ResourceScope>,
    granted_like: BTreeMap<String, String>,
}
impl Domain {
    pub fn new(
        schema: &Schema,
        publisher: [u8; 32],
        mesh: MeshId,
        domain: DomainId,
    ) -> Result<Self, Failure> {
        Self::at(schema, publisher, mesh, domain, schema.version)
    }
    /// The domain at schema generation `generation`.
    pub fn at(
        schema: &Schema,
        publisher: [u8; 32],
        mesh: MeshId,
        domain: DomainId,
        generation: u32,
    ) -> Result<Self, Failure> {
        let logical = logical(schema, publisher)?;
        let scope = Scope {
            mesh,
            app: logical.app_id(),
            domain,
        };
        // Reference-connected tables share the phase-12 reader scope. Table grants
        // and encryption keys remain separate ResourceScopes.
        let mut readers: BTreeMap<String, String> = logical
            .tables
            .iter()
            .map(|table| (table.sql_name.clone(), table.sql_name.clone()))
            .collect();
        loop {
            let mut changed = false;
            for table in &logical.tables {
                for key in &table.foreign_keys {
                    let left = readers
                        .get(&table.sql_name)
                        .ok_or("missing child reader scope")?
                        .clone();
                    let right = readers
                        .get(&key.table)
                        .ok_or("missing parent reader scope")?
                        .clone();
                    let first = left.min(right);
                    for name in [&table.sql_name, &key.table] {
                        let reader = readers.get_mut(name).ok_or("missing reader scope")?;
                        if *reader != first {
                            *reader = first.clone();
                            changed = true;
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }
        let tables: BTreeMap<String, ResourceScope> = logical
            .tables
            .iter()
            .map(|table| {
                (
                    table.sql_name.clone(),
                    ResourceScope {
                        domain: scope,
                        encryption: rocky_core::commitment(
                            "rocky.sdk.readers.v1",
                            readers
                                .get(&table.sql_name)
                                .map_or(table.sql_name.as_bytes(), |name| name.as_bytes()),
                        ),
                        table: logical.table_id(table),
                    },
                )
            })
            .collect();
        Ok(Self {
            app: TypedRows::new(logical, vec![domain])?.at_generation(generation)?,
            scope,
            tables,
            granted_like: schema.granted_like(),
        })
    }
    fn removed(&self, name: &str) -> bool {
        match name.split_once('.') {
            Some((table, column)) => self
                .logical()
                .table(table)
                .is_none_or(|table| table.column(column).is_none()),
            None => self.logical().table(name).is_none(),
        }
    }
    /// Partition grants as this generation reads them: with the schema's
    /// `granted_like`, a whole-row grant on a followed table also selects
    /// the same partitions of the table following it, slot by slot.
    pub fn effective_partitions(
        &self,
        grants: &[rocky_credentials::PartitionGrant],
    ) -> Vec<rocky_credentials::PartitionGrant> {
        let logical = self.logical();
        let slots = |table: &rocky_core::LogicalTable| -> Vec<Commitment> {
            table
                .partition_by
                .iter()
                .filter_map(|name| table.column(name))
                .map(|column| logical.field_id(table, column))
                .collect()
        };
        // Grants on tables a later generation removed are dropped.
        let grants: Vec<_> = grants
            .iter()
            .filter(|grant| {
                logical
                    .tables
                    .iter()
                    .any(|table| logical.table_id(table) == grant.table)
            })
            .cloned()
            .collect();
        let mut all = grants.clone();
        for (name, like) in &self.granted_like {
            let (Some(table), Some(parent)) = (logical.table(name), logical.table(like)) else {
                continue;
            };
            let (id, parent_id) = (logical.table_id(table), logical.table_id(parent));
            let (own, parents) = (slots(table), slots(parent));
            if own.len() != parents.len() || grants.iter().any(|grant| grant.table == id) {
                continue;
            }
            for grant in grants.iter().filter(|grant| {
                grant.table == parent_id
                    && grant.rows == rocky_core::RowSelection::All
                    && grant.fields == FieldSelection::All
            }) {
                let selector: BTreeMap<_, _> = grant
                    .selector
                    .0
                    .iter()
                    .filter_map(|(slot, selection)| {
                        let index = parents.iter().position(|parent| parent == slot)?;
                        Some((own[index], selection.clone()))
                    })
                    .collect();
                if selector.len() != grant.selector.0.len() {
                    continue;
                }
                all.push(rocky_credentials::PartitionGrant {
                    domain: grant.domain,
                    table: id,
                    selector: rocky_core::PartitionSelector(selector),
                    rows: rocky_core::RowSelection::All,
                    rights: grant.rights.clone(),
                    fields: FieldSelection::All,
                });
            }
        }
        all
    }
    /// `profile` as this generation reads it: without the tables and
    /// columns a later generation removed, and with the schema's
    /// `granted_like` applied: a table granted like another receives the
    /// same rights wherever the profile names that one in whole rows and is
    /// silent on it. Every interpretation of a profile goes through here.
    pub fn effective(&self, profile: &Profile) -> Profile {
        let profile = &self.current(profile);
        let follow = |scopes: &std::collections::BTreeSet<String>| {
            let mut scopes = scopes.clone();
            for (table, like) in &self.granted_like {
                if scopes.contains(like) {
                    scopes.insert(table.clone());
                }
            }
            scopes
        };
        match profile {
            Profile::Issuer => Profile::Issuer,
            Profile::Custody { scopes } => Profile::Custody {
                scopes: follow(scopes),
            },
            Profile::Reader { scopes } => Profile::Reader {
                scopes: follow(scopes),
            },
            Profile::Writer { scopes } => Profile::Writer {
                scopes: follow(scopes),
            },
            Profile::Grants { grants } => {
                let mut all = grants.clone();
                for (table, like) in &self.granted_like {
                    if grants.iter().any(|grant| grant.scope == *table) {
                        continue;
                    }
                    all.extend(
                        grants
                            .iter()
                            .filter(|grant| {
                                grant.scope == *like
                                    && grant
                                        .columns
                                        .as_ref()
                                        .is_none_or(|columns| columns.is_empty())
                            })
                            .map(|grant| Grant {
                                scope: table.clone(),
                                rights: grant.rights.clone(),
                                columns: grant.columns.clone(),
                            }),
                    );
                }
                Profile::Grants { grants: all }
            }
        }
    }
    /// Stored grants retain names; the current schema resolves only those it has.
    fn current(&self, profile: &Profile) -> Profile {
        let named = |scopes: &BTreeSet<String>| -> BTreeSet<String> {
            scopes
                .iter()
                .filter(|name| !self.removed(name))
                .cloned()
                .collect()
        };
        match profile {
            Profile::Issuer => Profile::Issuer,
            Profile::Custody { scopes } => Profile::Custody {
                scopes: named(scopes),
            },
            Profile::Reader { scopes } => Profile::Reader {
                scopes: named(scopes),
            },
            Profile::Writer { scopes } => Profile::Writer {
                scopes: named(scopes),
            },
            Profile::Grants { grants } => Profile::Grants {
                grants: grants
                    .iter()
                    .filter(|grant| !self.removed(&grant.scope))
                    .cloned()
                    .map(|mut grant| {
                        if let Some(columns) = &mut grant.columns {
                            columns
                                .retain(|name| !self.removed(&format!("{}.{name}", grant.scope)));
                        }
                        grant
                    })
                    .collect(),
            },
        }
    }
    pub fn logical(&self) -> &LogicalSchema {
        self.app.schema()
    }
    /// The signed definition of the tables.
    pub fn manifest(&self) -> ApplicationManifest {
        self.app.manifest()
    }
    /// Collections and their resource scopes, in name order.
    pub fn scopes(&self) -> impl Iterator<Item = (&str, ResourceScope)> {
        self.tables
            .iter()
            .map(|(name, scope)| (name.as_str(), *scope))
    }
    /// Whether `scope` is a partitioned table's own scope, which holds no
    /// rows: each partition has its own scope and checkpoint.
    pub fn partitioned_table(&self, scope: &ResourceScope) -> bool {
        let logical = self.logical();
        self.scopes().any(|(name, own)| {
            own == *scope
                && logical
                    .table(name)
                    .is_some_and(|table| !table.partition_by.is_empty())
        })
    }
    pub fn readers(&self) -> BTreeMap<String, Commitment> {
        self.tables
            .iter()
            .map(|(name, scope)| (name.clone(), scope.encryption))
            .collect()
    }
    /// The registry's resource scope.
    pub fn registry(&self) -> ResourceScope {
        self.tables[REGISTRY]
    }

    /// What an issuer can grant: every application collection, its scope
    /// and columns. The registry is no grantable resource.
    pub fn resources(&self) -> Vec<Resource> {
        self.all_resources()
            .into_iter()
            .filter(|resource| resource.name != REGISTRY)
            .collect()
    }
    /// The registry as a resource, for the grants the SDK adds itself.
    pub fn registry_resource(&self) -> Vec<Resource> {
        self.all_resources()
            .into_iter()
            .filter(|resource| resource.name == REGISTRY)
            .collect()
    }
    fn all_resources(&self) -> Vec<Resource> {
        let logical = self.logical();
        logical
            .tables
            .iter()
            .map(|table| Resource {
                name: table.sql_name.clone(),
                scope: self.tables[&table.sql_name],
                columns: table
                    .columns
                    .iter()
                    .map(|column| (column.sql_name.clone(), logical.field_id(table, column)))
                    .collect(),
            })
            .collect()
    }
}
/// The format-3 typed tables of `schema` under `publisher`, with the
/// reserved registry table every SDK domain carries.
pub(crate) fn logical(schema: &Schema, publisher: [u8; 32]) -> Result<LogicalSchema, Failure> {
    let mut definition = schema.definition(publisher)?;
    definition.tables.push(registry_table()?);
    Ok(definition.build()?)
}
/// One row per entry of a device's record, keyed by node and entry.
pub(crate) fn registry_table() -> Result<rocky_core::TableDefinition, Failure> {
    Ok(serde_json::from_value(serde_json::json!({
        "name": REGISTRY,
        "class": "replayed",
        "columns": [
            {"name": "node", "type": "text", "not_null": true},
            {"name": "entry", "type": "text", "not_null": true},
            {"name": "value", "type": "text", "not_null": true},
        ],
        "primary_key": ["node", "entry"],
    }))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocky_core::Affinity;
    #[test]
    fn typed_app_and_sdk_definitions_refuse_historical_formats() {
        let json = r#"{"format":6,"application":"refusal","version":1,"tables":[{"name":"items","class":"replayed","columns":[{"name":"title","type":"text"}],"primary_key":["id"]}]}"#;
        // The portable builder supplies both required columns.
        let mut definition = Schema::parse(json).unwrap().definition([1; 32]).unwrap();
        let descriptor = definition.build().unwrap();
        // Definitions and descriptors use the current format.
        for format in [0, 1, 2, 3, 4, 5, 7] {
            definition.format = format;
            assert!(
                definition
                    .build()
                    .unwrap_err()
                    .to_string()
                    .contains("unsupported schema definition format")
            );
            let input = json.replace("\"format\":6", &format!("\"format\":{format}"));
            let error = Schema::parse(&input).unwrap_err().to_string();
            assert!(error.contains("unsupported schema"), "{error}");
        }
        assert_eq!(descriptor.format, rocky_core::LOGICAL_SCHEMA_FORMAT);
        for format in [0, 1, 2, 3, 4, 5, 7] {
            let mut old = descriptor.clone();
            old.format = format;
            let error = rocky_core::TypedRows::new(old, vec![])
                .err()
                .unwrap()
                .to_string();
            assert!(error.contains("unsupported schema"), "{error}");
        }
    }

    #[test]
    fn definition_tables_keep_keys_indexes_and_scalar_types() -> Result<(), Failure> {
        let schema = Schema::parse(
            r#"{"format":6,"application":"measurements","version":1,"tables":[{
            "name":"samples","class":"replayed",
            "columns":[{"name":"sensor","type":"text","not_null":true},
                       {"name":"sequence","type":"integer","not_null":true},
                       {"name":"reading","type":"real"},{"name":"raw","type":"blob"}],
            "primary_key":["sensor","sequence"],
            "indexes":[{"name":"samples_by_reading","columns":[{"name":"reading","descending":true}]}]
        }]}"#,
        )?;
        let domain = Domain::new(&schema, [9; 32], MeshId([1; 16]), DomainId([2; 16]))?;
        let logical = domain.logical();
        let table = logical.table("samples").ok_or("table")?;
        assert_eq!(table.primary_key, ["sensor", "sequence"]);
        assert!(
            table
                .create_sql
                .contains("PRIMARY KEY(\"sensor\",\"sequence\")")
        );
        assert_eq!(
            table.column("reading").ok_or("reading")?.affinity,
            Affinity::Real
        );
        assert_eq!(table.column("raw").ok_or("raw")?.affinity, Affinity::Blob);
        assert!(table.indexes[0].create_sql.contains("\"reading\" DESC"));
        assert_eq!(logical, &super::logical(&schema, [9; 32])?);
        logical.supported_on(rocky_core::Profile::Secure)?;
        logical.supported_on(rocky_core::Profile::Secure)?;
        assert_eq!(schema.names(), ["samples"]);
        Ok(())
    }

    #[test]
    fn identity_references_share_readers_but_keep_table_resources() -> Result<(), Failure> {
        let schema = Schema::parse(
            r#"{"format":6,"application":"references","version":1,"tables":[
            {"name":"parents","class":"replayed","columns":[{"name":"next","type":"integer"}],"primary_key":["id"],
             "foreign_keys":[{"columns":["next"],"table":"children","on_delete":"set_null"}]},
            {"name":"children","class":"replayed","columns":[{"name":"parent","type":"integer"}],"primary_key":["id"],
             "foreign_keys":[{"columns":["parent"],"table":"parents","on_delete":"cascade"}]},
            {"name":"other","class":"replayed","columns":[{"name":"title","type":"text"}],"primary_key":["id"]}
        ]}"#,
        )?;
        let domain = Domain::new(&schema, [9; 32], MeshId([1; 16]), DomainId([2; 16]))?;
        let resources: BTreeMap<_, _> = domain.scopes().collect();
        let child = resources.get("children").ok_or("child")?;
        let parent = resources.get("parents").ok_or("parent")?;
        assert_eq!(child.encryption, parent.encryption);
        assert_ne!(child.table, parent.table);
        assert_eq!(
            child.encryption,
            rocky_core::commitment("rocky.sdk.readers.v1", b"children")
        );
        assert_eq!(
            resources.get("other").ok_or("other")?.encryption,
            rocky_core::commitment("rocky.sdk.readers.v1", b"other")
        );
        let mut reordered = schema.clone();
        reordered.tables.reverse();
        assert_eq!(
            domain.readers(),
            Domain::new(&reordered, [9; 32], MeshId([1; 16]), DomainId([2; 16]))?.readers()
        );
        Ok(())
    }

    #[test]
    fn removed_command_definitions_are_refused() {
        let json = r#"{"format":6,"application":"market","version":1,"tables":[{"name":"stock","class":"command_controlled","columns":[{"name":"item","type":"text","not_null":true}],"primary_key":["item"]}]}"#;
        assert!(Schema::parse(json).is_err());
        let confirmed = json.replace("command_controlled", "confirmed_read_only");
        assert!(Schema::parse(&confirmed).is_err());
        let ordinary = json.replace("command_controlled", "replayed");
        assert!(Schema::parse(&ordinary).is_ok());
        let commands = ordinary.replace(
            "\"version\":1",
            "\"version\":1,\"commands\":{\"format\":1,\"handler\":1,\"commands\":[]}",
        );
        assert!(Schema::parse(&commands).is_err());
    }
}
