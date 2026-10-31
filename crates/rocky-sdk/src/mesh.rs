//! Local contact hints and secret-store discovery state; see decision 0056.
use crate::{
    Failure,
    enrollment::{Contact, Route, Settings, now},
    secrets::Vault,
};
use data_encoding::HEXLOWER;
use rocky_core::{Commitment, Scope, commitment};
use rocky_credentials::{DiscoverySecret, PrivateKey, PublicKey, Revocation};
use rocky_secure::network::{
    ContactHandler, ContactHint, ContactRequest, ContactResponse, NativeSession,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactMeta {
    pub source: String,
    pub learned: u64,
    pub trusted: bool,
    pub local: bool,
}
const AGE: u64 = 30 * 24 * 60 * 60;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Discovery {
    version: u32,
    root: Option<DiscoverySecret>,
    values: BTreeMap<String, DiscoverySecret>,
    current: Option<Commitment>,
    previous: Option<(Commitment, u64)>,
}
impl Discovery {
    fn load(vault: &Vault) -> Result<Self, Failure> {
        match vault.load_bytes("discovery")? {
            None => Ok(Self {
                version: 1,
                root: None,
                values: BTreeMap::new(),
                current: None,
                previous: None,
            }),
            Some(bytes) => {
                let state: Self = serde_json::from_slice(&bytes)?;
                if state.version != 1
                    || state.values.len() > rocky_credentials::MAX_LIVE_REVOCATIONS
                {
                    return Err("unsupported or overfull discovery state".into());
                }
                Ok(state)
            }
        }
    }
    fn save(&self, vault: &Vault) -> Result<(), Failure> {
        if self.values.len() > rocky_credentials::MAX_LIVE_REVOCATIONS {
            return Err("discovery value capacity reached".into());
        }
        vault.store_bytes("discovery", &serde_json::to_vec(self)?)?;
        Ok(())
    }
}
/// The owner, or an issuer through its chain, signs discovery values.
pub(crate) type Signer<'a> = (
    &'a dyn rocky_credentials::IdentityProvider,
    &'a rocky_credentials::CredentialChain,
);
pub(crate) fn create_root(vault: &Vault, signer: Signer<'_>, scope: Scope) -> Result<(), Failure> {
    let mut state = Discovery::load(vault)?;
    state.root = Some(DiscoverySecret::sign(
        scope,
        None,
        crate::enrollment::random(),
        signer,
    )?);
    state.save(vault)
}
pub(crate) fn mint_value(
    vault: &Vault,
    signer: Signer<'_>,
    scope: Scope,
    set: &rocky_credentials::RevocationSet,
    statement: &Revocation,
) -> Result<(), Failure> {
    let mut state = Discovery::load(vault)?;
    let id = HEXLOWER.encode(&statement.id()?);
    let time = now()?;
    state.values.retain(|named, value| {
        named == &id
            || value
                .statement
                .and_then(|id| set.get(&id))
                .is_some_and(|signed| signed.statement.live(time))
    });
    if let std::collections::btree_map::Entry::Vacant(entry) = state.values.entry(id) {
        entry.insert(DiscoverySecret::sign(
            scope,
            Some(statement.id()?),
            crate::enrollment::random(),
            signer,
        )?);
        state.save(vault)?;
    }
    Ok(())
}
impl Settings {
    pub(crate) fn learn_contact(
        &mut self,
        vault: &Vault,
        hint: ContactHint,
        source: &str,
        time: u64,
    ) -> Result<bool, Failure> {
        hint.validate()?;
        if hint.node == PrivateKey::from_bytes(&vault.get("node")?).public_key()
            || self.revocations.revokes(&hint.node)
        {
            return Ok(false);
        }
        self.bind_saved_contact(hint.node);
        if self
            .contact_meta
            .get(&hint.node)
            .is_some_and(|meta| meta.source == "application")
        {
            return Ok(false);
        }
        let expired: Vec<_> = self
            .contact_meta
            .iter()
            .filter(|(node, meta)| {
                self.enrollment_upstream != Some(**node)
                    && meta.source != "application"
                    && meta.learned.saturating_add(AGE) < time
            })
            .map(|(node, _)| *node)
            .collect();
        for node in expired {
            self.remove_peer(node)?;
            self.contact_meta.remove(&node);
        }
        if !self.peers.contains_key(&hint.node)
            && self.contact_count() >= crate::enrollment::MAX_CONTACTS
        {
            let oldest = self
                .peers
                .keys()
                .filter(|node| {
                    self.enrollment_upstream != Some(**node)
                        && self
                            .contact_meta
                            .get(node)
                            .is_none_or(|meta| meta.source != "application")
                })
                .min_by_key(|node| self.contact_meta.get(node).map_or(0, |meta| meta.learned))
                .copied();
            let Some(oldest) = oldest else {
                return Ok(false);
            };
            self.remove_peer(oldest)?;
            self.contact_meta.remove(&oldest);
        }
        self.peers.insert(
            hint.node,
            Contact {
                routes: hint
                    .routes
                    .into_iter()
                    .map(|(transport, address)| Route { transport, address })
                    .collect(),
            },
        );
        self.contact_meta.insert(
            hint.node,
            ContactMeta {
                source: source.into(),
                learned: time,
                trusted: hint.trusted,
                local: false,
            },
        );
        Ok(true)
    }
    /// Whether a found route or local mark is news, so that repeated
    /// announcements cost no write.
    pub(crate) fn would_learn(
        &self,
        node: PublicKey,
        kind: &str,
        address: &str,
        local: bool,
    ) -> bool {
        if self.revocations.revokes(&node) {
            return false;
        }
        let meta = self.contact_meta.get(&node);
        let marked = !local || meta.is_some_and(|meta| meta.local);
        let known = self.peers.get(&node).is_some_and(|contact| {
            meta.is_some_and(|meta| meta.source == "application")
                || contact
                    .routes
                    .iter()
                    .any(|route| route.transport == kind && route.address == address)
        });
        !(known && marked)
    }
    /// Keeps a contact discovery found. A known contact gains the route
    /// and, found locally, its mark; one the application added keeps its
    /// routes.
    pub(crate) fn learn_found(
        &mut self,
        vault: &Vault,
        node: PublicKey,
        kind: &str,
        address: String,
        local: bool,
        time: u64,
    ) -> Result<bool, Failure> {
        let hint = ContactHint {
            node,
            routes: vec![(kind.to_owned(), address.clone())],
            trusted: false,
        };
        hint.validate()?;
        if !self.would_learn(node, kind, &address, local)
            || node == PrivateKey::from_bytes(&vault.get("node")?).public_key()
        {
            return Ok(false);
        }
        let Some(contact) = self.peers.get_mut(&node) else {
            let learned = self.learn_contact(vault, hint, "discovery", time)?;
            if let Some(meta) = self.contact_meta.get_mut(&node).filter(|_| learned) {
                meta.local = local;
            }
            return Ok(learned);
        };
        let meta = self
            .contact_meta
            .entry(node)
            .or_insert_with(|| ContactMeta {
                source: "enrollment".into(),
                learned: time,
                trusted: false,
                local: false,
            });
        meta.local |= local;
        if meta.source != "application" {
            contact.learn(vec![Route {
                transport: kind.to_owned(),
                address,
            }]);
        }
        Ok(true)
    }
    pub(crate) fn contact_hint(&self, node: PublicKey) -> Option<ContactHint> {
        if self.revocations.revokes(&node) {
            return None;
        }
        let contact = self.peers.get(&node)?;
        if contact.routes.is_empty() {
            return None;
        }
        Some(ContactHint {
            node,
            routes: contact
                .routes
                .iter()
                .map(|route| (route.transport.clone(), route.address.clone()))
                .collect(),
            trusted: self.issuers.contains(&node)
                || self
                    .contact_meta
                    .get(&node)
                    .is_some_and(|meta| meta.trusted),
        })
    }
    pub(crate) fn discovery_exchange(
        &self,
        vault: &Vault,
        root: Option<Box<DiscoverySecret>>,
        values: Vec<DiscoverySecret>,
        after: Option<Commitment>,
    ) -> Result<ContactResponse, Failure> {
        let scope = self.domain()?.scope;
        let mut state = Discovery::load(vault)?;
        let previous = state.clone();
        if let Some(root) = root {
            let root = *root;
            root.verify(self.publisher, scope)?;
            if root.statement.is_some() || state.root.as_ref().is_some_and(|held| held != &root) {
                return Err("discovery root mismatch".into());
            }
            state.root = Some(root);
        }
        let time = now()?;
        state.values.retain(|id, _| {
            self.revocations.statements().any(|signed| {
                signed.statement.live(time)
                    && signed.id().is_ok_and(|held| HEXLOWER.encode(&held) == *id)
            })
        });
        for value in values {
            value.verify(self.publisher, scope)?;
            let id = value.statement.ok_or("discovery value lacks statement")?;
            let Some(statement) = self.revocations.get(&id) else {
                return Err("discovery value names an unknown statement".into());
            };
            if !statement.statement.live(time) {
                continue;
            }
            let id = HEXLOWER.encode(&id);
            if state.values.get(&id).is_some_and(|held| held != &value) {
                return Err("discovery value substitution".into());
            }
            state.values.insert(id, value);
        }
        if state != previous {
            state.save(vault)?;
        }
        let mut page = state
            .values
            .values()
            .filter(|value| after.is_none_or(|after| value.statement.is_some_and(|id| id > after)));
        let values: Vec<_> = page.by_ref().take(32).cloned().collect();
        let next = if page.next().is_some() {
            values.last().and_then(|value| value.statement)
        } else {
            None
        };
        Ok(ContactResponse::Discovery {
            root: state.root.map(Box::new),
            values,
            next,
        })
    }
    /// Current and previous topics. The previous one expires 24 hours after a change.
    pub(crate) fn discovery_topics(
        &self,
        vault: &Vault,
        time: u64,
    ) -> Result<(Commitment, Option<Commitment>), Failure> {
        let mut state = Discovery::load(vault)?;
        let loaded = state.clone();
        let root = state
            .root
            .as_ref()
            .ok_or("discovery root not received in an admitted session")?;
        let scope = self.domain()?.scope;
        root.verify(self.publisher, scope)?;
        for (id, value) in &state.values {
            value.verify(self.publisher, scope)?;
            if value
                .statement
                .is_none_or(|statement| HEXLOWER.encode(&statement) != *id)
            {
                return Err("invalid stored discovery value".into());
            }
        }
        let mut bytes = root.value.to_vec();
        for signed in self
            .revocations
            .statements()
            .filter(|signed| signed.statement.live(time))
        {
            let id = signed.id()?;
            bytes.extend(id);
            match state.values.get(&HEXLOWER.encode(&id)) {
                Some(value) => {
                    bytes.push(1);
                    bytes.extend(value.value);
                }
                None => bytes.push(0),
            }
        }
        let topic = commitment("rocky.discovery-topic.v1", &bytes);
        if state.current != Some(topic) {
            state.previous = state.current.map(|old| (old, time.saturating_add(86400)));
            state.current = Some(topic);
        }
        state.previous = state.previous.filter(|(_, until)| time < *until);
        if state != loaded {
            state.save(vault)?;
        }
        Ok((topic, state.previous.map(|(topic, _)| topic)))
    }
}
/// Bidirectional handover and paged discovery material after successful admission.
pub(crate) async fn exchange(
    session: &mut NativeSession,
    handler: &dyn ContactHandler,
) -> Result<(), Failure> {
    let peer = session.peer();
    let ContactResponse::Handover { contacts } = handler
        .answer(
            peer,
            ContactRequest::Handover {
                contacts: Vec::new(),
            },
        )
        .await?
    else {
        return Err("invalid local contact response".into());
    };
    let ContactResponse::Handover { contacts } = session
        .exchange_contacts(ContactRequest::Handover { contacts })
        .await?
    else {
        return Err("invalid handover response".into());
    };
    handler
        .answer(peer, ContactRequest::Handover { contacts })
        .await?;
    let (mut after, mut own_after) = (None, None);
    for _ in 0..=rocky_credentials::MAX_LIVE_REVOCATIONS / 32 {
        let ContactResponse::Discovery {
            root,
            values,
            next: own_next,
        } = handler
            .answer(
                peer,
                ContactRequest::Discovery {
                    root: None,
                    values: Vec::new(),
                    after: own_after,
                },
            )
            .await?
        else {
            return Err("invalid local discovery response".into());
        };
        let ContactResponse::Discovery { root, values, next } = session
            .exchange_contacts(ContactRequest::Discovery {
                root,
                values,
                after,
            })
            .await?
        else {
            return Err("invalid discovery response".into());
        };
        handler
            .answer(
                peer,
                ContactRequest::Discovery {
                    root,
                    values,
                    after: None,
                },
            )
            .await?;
        if next.is_none() && own_next.is_none() {
            return Ok(());
        }
        after = next.or(after);
        own_after = own_next.or(own_after);
    }
    Err("discovery exchange exceeds live bound".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileSecretStore, SecretStore, schema::Schema};
    use rocky_credentials::{Revocation, SignedRevocation};
    use std::{collections::BTreeSet, sync::Arc};
    const SCHEMA: &str = r#"{"application":"contacts","version":1,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"title","type":"text","not_null":true}],"primary_key":["id"]}]}"#;
    #[test]
    fn equal_sets_derive_equal_topics_missing_values_differ_and_substitution_is_refused()
    -> Result<(), Failure> {
        let dir = tempfile::tempdir()?;
        let store: Arc<dyn SecretStore> = Arc::new(FileSecretStore::new(dir.path()));
        let mut a = Settings::create(
            &Schema::parse(SCHEMA)?,
            &store,
            crate::enrollment::DEFAULT_TTL,
            None,
        )?;
        let av = a.vault(&store);
        let publisher = PrivateKey::from_bytes(&av.get("identity")?);
        let owner = rocky_credentials::CredentialChain::default();
        let old = a.discovery_topics(&av, now()?)?.0;
        let statement = Revocation {
            app: a.domain()?.manifest().app,
            issuer: publisher.public_key(),
            time: now()?,
            nodes: [rocky_credentials::PeerId::of(
                PrivateKey::new().public_key(),
            )]
            .into(),
            identities: BTreeSet::new(),
            capabilities: BTreeSet::new(),
        };
        let signed = SignedRevocation::sign(statement.clone(), &publisher, &owner)?;
        a.revocations.merge(
            &rocky_credentials::RevocationSet::try_from(vec![signed])?,
            a.publisher,
            statement.app,
            now()?,
        )?;
        mint_value(
            &av,
            (&publisher, &owner),
            a.domain()?.scope,
            &a.revocations,
            &statement,
        )?;
        let mut b = a.clone();
        b.installation = "other".into();
        let bv = b.vault(&store);
        let a_state = Discovery::load(&av)?;
        b.discovery_exchange(&bv, a_state.root.clone().map(Box::new), Vec::new(), None)?;
        let missing = b.discovery_topics(&bv, now()?)?.0;
        let (new, previous) = a.discovery_topics(&av, now()?)?;
        assert_ne!(missing, new);
        assert_ne!(old, new);
        assert_eq!(previous, Some(old));
        b.discovery_exchange(&bv, None, a_state.values.values().cloned().collect(), None)?;
        assert_eq!(b.discovery_topics(&bv, now()?)?.0, new);
        let mut wrong = a_state.values.values().next().ok_or("value")?.clone();
        wrong.value[0] ^= 1;
        assert!(b.discovery_exchange(&bv, None, vec![wrong], None).is_err());
        let mut missing_statement = b.clone();
        missing_statement.revocations = Default::default();
        assert_ne!(missing_statement.discovery_topics(&bv, now()?)?.0, new);
        assert_eq!(a.discovery_topics(&av, now()? + 86400)?.1, None);
        assert_eq!(Discovery::load(&av)?.values, a_state.values);
        Ok(())
    }
    #[test]
    fn a_full_list_evicts_the_oldest_learned_contact_and_preserves_application_routes()
    -> Result<(), Failure> {
        let dir = tempfile::tempdir()?;
        let store: Arc<dyn SecretStore> = Arc::new(FileSecretStore::new(dir.path()));
        let mut settings = Settings::create(
            &Schema::parse(SCHEMA)?,
            &store,
            crate::enrollment::DEFAULT_TTL,
            None,
        )?;
        let vault = settings.vault(&store);
        let configured = PrivateKey::new().public_key();
        settings.peers.insert(
            configured,
            Contact {
                routes: vec![Route {
                    transport: "memory".into(),
                    address: "configured".into(),
                }],
            },
        );
        settings.contact_meta.insert(
            configured,
            ContactMeta {
                source: "application".into(),
                learned: 0,
                trusted: false,
                local: false,
            },
        );
        let oldest = PrivateKey::new().public_key();
        let hint = |node| ContactHint {
            node,
            routes: vec![("memory".into(), "learned".into())],
            trusted: false,
        };
        settings.learn_contact(&vault, hint(oldest), "handover", 1)?;
        for at in 2..64 {
            settings.learn_contact(&vault, hint(PrivateKey::new().public_key()), "handover", at)?;
        }
        assert_eq!(settings.peers.len(), 64);
        settings.enrollment_upstream = Some(oldest);
        let newest = PrivateKey::new().public_key();
        settings.learn_contact(&vault, hint(newest), "request", 64)?;
        assert!(settings.peers.contains_key(&oldest));
        assert!(!settings.contact_meta.values().any(|meta| meta.learned == 2));
        assert!(settings.peers.contains_key(&newest));
        assert_eq!(settings.peers[&configured].routes[0].address, "configured");
        assert!(!settings.learn_contact(&vault, hint(configured), "handover", 65)?);
        settings.learn_contact(
            &vault,
            hint(PrivateKey::new().public_key()),
            "handover",
            AGE + 66,
        )?;
        assert_eq!(settings.peers.len(), 3);
        assert!(settings.peers.contains_key(&oldest));
        assert!(settings.peers.contains_key(&configured));
        Ok(())
    }
}
