//! Application classification and the keys needed by a tip schema.
use crate::{
    Failure,
    domain::Domain,
    enrollment::{Settings, key_role},
    schema::Schema,
    secrets::Vault,
};

pub(crate) fn migrates(schema: &Schema, from: u32) -> bool {
    schema
        .migrations
        .iter()
        .any(|step| step.version > from && step.version <= schema.version)
}

impl Settings {
    pub(crate) fn application(&self, declared: &Schema) -> Result<crate::DeclaredSchema, Failure> {
        let version = declared.version;
        let declared = Domain::at(
            declared,
            *self.publisher.as_bytes(),
            self.mesh,
            self.domain,
            self.generation,
        )?;
        if declared.manifest().hash() == self.domain()?.manifest().hash() {
            Ok(crate::DeclaredSchema::Current)
        } else if version > self.generation {
            Ok(crate::DeclaredSchema::Ahead)
        } else {
            Ok(crate::DeclaredSchema::Behind)
        }
    }
    pub(crate) fn may_migrate(&self, domain: &Domain) -> Result<bool, Failure> {
        Ok(self.issuer()
            && self.partitions(domain)?.iter().all(|partition| {
                !partition.record.epochs.is_empty()
                    && partition
                        .members
                        .iter()
                        .all(|member| self.owns_partition(member))
            }))
    }
    pub(crate) fn prepare_schema(&mut self, vault: &Vault, domain: &Domain) -> Result<(), Failure> {
        if !self.issuer() {
            return Ok(());
        }
        let registry = self.registry_key(vault)?;
        for (name, _) in domain.scopes() {
            if !self.keys.contains_key(name) {
                let key = reader_key(&registry, self.domain, name);
                let epoch = rocky_core::KeyEpoch::new(1, &key);
                let role = key_role(name, epoch);
                if vault.find(&role)?.is_none() {
                    vault.put(&role, &key)?;
                }
                let mut ids = self
                    .revocations
                    .statements()
                    .map(|signed| signed.statement.id())
                    .collect::<Result<Vec<_>, _>>()?;
                ids.sort_unstable();
                self.epoch_statements.insert(role, ids);
                self.keys.insert(name.to_owned(), vec![epoch]);
            }
        }
        self.credentials = self.issue_own(vault)?;
        Ok(())
    }
    /// The registry's current key: its highest epoch, the lowest of
    /// siblings, as writers choose it.
    fn registry_key(&self, vault: &Vault) -> Result<[u8; 32], Failure> {
        let epoch = self
            .keys
            .get(crate::domain::REGISTRY)
            .and_then(|epochs| {
                epochs.iter().copied().max_by(|a, b| {
                    a.generation
                        .cmp(&b.generation)
                        .then(b.secret_hash.cmp(&a.secret_hash))
                })
            })
            .ok_or("an issuer holds the registry key")?;
        Ok(vault.get(&key_role(crate::domain::REGISTRY, epoch))?)
    }
}
fn reader_key(registry: &[u8; 32], domain: rocky_core::DomainId, table: &str) -> [u8; 32] {
    let mut input = registry.to_vec();
    input.extend(domain.0);
    input.extend(table.as_bytes());
    rocky_core::commitment("rocky.sdk.generation-reader.v1", &input)
}
