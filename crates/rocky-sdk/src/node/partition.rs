//! SDK-owned group partitions: addresses, the group secret in the external
//! vault, derived table keys, sharing and the holding rule.
use super::*;
use crate::groups::{GroupPartition, record_key, secret_role};
use rocky_core::{PartitionTuple, TableClass};
use rocky_credentials::{GroupSecretEnvelope, PartitionGrant};
use std::collections::BTreeSet;
impl Node {
    fn group_partition(&self, request: &Value) -> Result<GroupPartition, Failure> {
        let values: Vec<Cell> = serde_json::from_value(request["values"].clone())?;
        GroupPartition::resolve(
            &self.domain(),
            request["group"].as_str(),
            request["table"].as_str(),
            values
                .into_iter()
                .map(Cell::sql)
                .collect::<Result<_, _>>()?,
        )
    }
    pub(super) fn partition_address(
        &self,
        request: &Value,
    ) -> Result<(ResourceScope, PartitionTuple), Failure> {
        let name = request["table"]
            .as_str()
            .ok_or("partition table must be a string")?;
        self.domain()
            .logical()
            .table(name)
            .filter(|table| table.class == TableClass::Replayed && !table.partition_by.is_empty())
            .ok_or("table is not partitioned")?;
        let partition =
            self.group_partition(&json!({"table": name, "values": request["values"]}))?;
        let member = partition.member(name).ok_or("table is not partitioned")?;
        Ok((member.scope, member.tuple.clone()))
    }
    /// Verifies whole-partition read on every member, as a group secret
    /// reveals every member's key.
    fn reads_group(&self, settings: &Settings, partition: &GroupPartition) -> Result<(), Failure> {
        let node = PrivateKey::from_bytes(&self.vault.get("node")?).public_key();
        let time = now()?;
        for member in &partition.members {
            let grants = settings
                .credentials
                .verify_partition(
                    settings.publisher,
                    node,
                    member.scope,
                    &member.tuple,
                    &settings.revocations,
                    time,
                )
                .unwrap_or_default();
            if !grants.iter().any(|grant| {
                grant.rows == rocky_core::RowSelection::All
                    && grant.rights.contains(&rocky_core::Right::Read)
            }) {
                return Err(refused(format!(
                    "a group secret needs whole-partition read on every table of group {}; {} lacks it",
                    partition.record.group, member.table
                )));
            }
        }
        Ok(())
    }
    /// Registers the readable members and installs every held epoch's
    /// derived key; installing an installed key again does nothing.
    pub(super) async fn hold_keys(
        &self,
        settings: &Settings,
        partition: &GroupPartition,
    ) -> Result<(), Failure> {
        for member in &partition.members {
            if !settings.reads_partition(member) {
                continue;
            }
            self.replica
                .register_partition(member.scope, member.tuple.clone())
                .await?;
            for epoch in partition.record.epochs.iter().rev() {
                self.replica
                    .install_key_epoch(partition.key(&self.vault, member, *epoch)?)
                    .await?;
            }
            crate::enrollment::fault::check(crate::enrollment::fault::Stage::Table)?;
        }
        Ok(())
    }
    /// Records the group partition, without a key unless it holds one.
    async fn know(&self, partition: &GroupPartition) -> Result<(), Failure> {
        let key = record_key(&partition.record.address);
        if self.settings.lock().await.groups.contains_key(&key) {
            return Ok(());
        }
        let record = partition.record.clone();
        self.configure(|settings| {
            settings.groups.entry(key).or_insert(record);
            Ok(())
        })
        .await
    }
    async fn issue_partitions(&self, kind: &str, request: &Value) -> Result<Value, Failure> {
        let device: crate::DeviceKeys = serde_json::from_value(request["device"].clone())?;
        let grants: Vec<PartitionGrant> = serde_json::from_value(request["partitions"].clone())?;
        let registry = self.registry().await?;
        let settings = self.settings.lock().await.clone();
        let delegations: u8 = request["delegations"].as_u64().unwrap_or(1).try_into()?;
        let validity = (now()?, settings.ttl, 300);
        if settings.revoked_device(&device.node, &registry) {
            return Err(refused("the device was revoked"));
        }
        if settings.issuer() {
            settings.holder_changes(&self.vault, &device, &grants, delegations, &registry)?;
        }
        let chain = self
            .configure(|settings| {
                if kind != "partition_delegate" && !settings.issuer() {
                    return Err("partition grant requires an issuer".into());
                }
                let authors = settings.reserve_authors(device.user, Some(&registry), None)?;
                let terms = (delegations, Some(authors));
                let identity = settings.identity(&self.vault)?;
                if kind == "partition_delegate" && !settings.issuer() {
                    Ok(settings.credentials.delegable().delegate_partitions(
                        &*identity,
                        device.user,
                        rocky_core::PrincipalKind::User,
                        vec![],
                        grants.clone(),
                        terms,
                        validity,
                    )?)
                } else {
                    // An issuer grants and delegates through its authority.
                    let links = settings.issuer_links();
                    let authority = settings.authority(&*identity, &links)?;
                    Ok(authority.chain_of(authority.issue_partition_terms(
                        device.user,
                        vec![],
                        grants.clone(),
                        terms,
                        validity,
                    )?))
                }
            })
            .await?;
        // An issuer records the holder durably before the chain leaves it.
        if settings.issuer() {
            Box::pin(self.record_holder(&device, &grants, delegations, &chain)).await?;
        }
        let supplied = crate::Supplied {
            epoch_statements: BTreeMap::new(),
            mesh: settings.mesh,
            domain: settings.domain,
            manifest: settings.manifest()?,
            credentials: rocky_credentials::Credentials {
                publisher: settings.publisher,
                revocations: settings.revocations.clone(),
                chain,
            },
            keys: vec![],
            issuers: vec![],
        };
        Ok(json!({"supplied":supplied}))
    }
    /// Prepares the group secret after issuer or own-id insert authorization: the current epoch of a known
    /// partition, otherwise the first.
    async fn create_group(&self, partition: GroupPartition) -> Result<Value, Failure> {
        let mut settings = self.settings.lock().await;
        self.reads_group(&settings, &partition)?;
        let key = record_key(&partition.record.address);
        let mut record = settings
            .groups
            .get(&key)
            .cloned()
            .unwrap_or_else(|| partition.record.clone());
        let epoch = match record.current() {
            Some(epoch) => epoch,
            None => {
                let slot = format!("prepared.partition.{}", record_key(&record.address));
                let secret = match self.vault.find(&slot)? {
                    Some(secret) => secret,
                    None => self.vault.create(&slot)?,
                };
                let epoch = rocky_core::KeyEpoch::new(1, &secret);
                record.admit(epoch)?;
                self.vault
                    .put(&secret_role(&record.address, epoch), &secret)?;
                epoch
            }
        };
        record.hold(epoch)?;
        let mut draft = settings.clone();
        draft.groups.insert(key, record.clone());
        let ids = settings
            .revocations
            .statements()
            .map(|signed| signed.statement.id())
            .collect::<Result<Vec<_>, _>>()?;
        draft
            .epoch_statements
            .entry(secret_role(&record.address, epoch))
            .or_insert(ids);
        draft.save(&self.path)?;
        let granted = draft.granted(&self.domain());
        *settings = draft;
        let partition = GroupPartition::of(&self.domain(), &record)?;
        self.hold_keys(&settings, &partition).await?;
        // Sessions name the partition only once the replica grants it.
        *self.granted.lock().map_err(|_| "scope catalog poisoned")? = granted;
        Ok(json!({"address": record_key(&record.address), "epoch": epoch}))
    }
    /// Accepts one group envelope after it opens and the device reads every
    /// member in whole; only then is anything registered or stored. Returns
    /// whether it was new: an epoch already held installs nothing again.
    pub(super) async fn install_envelope(
        &self,
        partition: GroupPartition,
        envelope: &GroupSecretEnvelope,
        sender: Option<&CredentialChain>,
        bootstrap: bool,
    ) -> Result<bool, Failure> {
        let epoch = envelope.epoch();
        let mut settings = self.settings.lock().await;
        let signer = match sender {
            None => settings.publisher,
            Some(chain) => {
                let signer = envelope.issuer();
                for member in &partition.members {
                    let grants = chain.verify_partition(
                        settings.publisher,
                        signer,
                        member.scope,
                        &member.tuple,
                        &settings.revocations,
                        now()?,
                    )?;
                    if !grants.iter().any(|grant| {
                        grant.rows == rocky_core::RowSelection::All
                            && grant.rights.contains(&rocky_core::Right::Read)
                    }) {
                        return Err(refused("envelope signer lacks whole-group read"));
                    }
                }
                signer
            }
        };
        let secret = envelope.open(
            &PrivateKey::from_bytes(&self.vault.get("node")?),
            signer,
            partition.record.address,
            epoch,
        )?;
        self.reads_group(&settings, &partition)?;
        let key = record_key(&partition.record.address);
        let mut record = settings
            .groups
            .get(&key)
            .cloned()
            .unwrap_or_else(|| partition.record.clone());
        record.admit(epoch)?;
        let role = secret_role(&record.address, epoch);
        let held = self.vault.find(&role)?;
        if held.is_some_and(|held| held != secret) {
            return Err(refused(
                "group secret epoch already holds different material",
            ));
        }
        if held.is_some()
            && record.epochs.contains(&epoch)
            && settings.epoch_statements.get(&role).map(Vec::as_slice)
                == Some(envelope.statements())
        {
            return Ok(false);
        }
        if bootstrap {
            self.save_bootstrap(
                partition
                    .members
                    .iter()
                    .map(|member| member.scope)
                    .collect(),
            )?;
        }
        crate::delivery::fault::check(
            PrivateKey::from_bytes(&self.vault.get("node")?).public_key(),
            crate::delivery::fault::Stage::Prepared,
        )?;
        if held.is_none() {
            self.vault.put(&role, &secret)?;
        }
        record.hold(epoch)?;
        let mut draft = settings.clone();
        draft.groups.insert(key, record.clone());
        if draft
            .epoch_statements
            .get(&role)
            .is_some_and(|held| held != envelope.statements())
        {
            return Err("group epoch revocation IDs differ from retained metadata".into());
        }
        draft
            .epoch_statements
            .insert(role, envelope.statements().to_vec());
        draft.save(&self.path)?;
        let granted = draft.granted(&self.domain());
        *settings = draft;
        let partition = GroupPartition::of(&self.domain(), &record)?;
        self.hold_keys(&settings, &partition).await?;
        // Sessions name the partition only once the replica grants it.
        *self.granted.lock().map_err(|_| "scope catalog poisoned")? = granted;
        Ok(true)
    }
    /// Seals the current epoch's group secret to each recipient and saves
    /// the deliveries before any network call; sync delivers them.
    async fn share(&self, partition: GroupPartition, request: &Value) -> Result<Value, Failure> {
        let registry = self.registry().await?;
        let mut settings = self.settings.lock().await;
        self.reads_group(&settings, &partition)?;
        if settings
            .authority
            .as_ref()
            .is_some_and(|authority| authority.rotation.is_some())
        {
            return Err(refused("a revocation is unfinished; reopen to complete it"));
        }
        let record = settings
            .groups
            .get(&record_key(&partition.record.address))
            .filter(|record| record.current().is_some())
            .cloned()
            .ok_or_else(|| refused("no group secret is held here; create or install it first"))?;
        let current = record.current().ok_or("no group secret epoch")?;
        let epoch = request
            .get("epoch")
            .filter(|value| !value.is_null())
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()?
            .unwrap_or(current);
        if epoch != current {
            return Err(refused(format!(
                "only the current epoch {current:?} of a group secret is shared"
            )));
        }
        let recipients: BTreeSet<PublicKey> =
            serde_json::from_value(request["recipients"].clone())?;
        if recipients.len() > 256 {
            return Err(refused("share with at most 256 recipients at once"));
        }
        let own = PrivateKey::from_bytes(&self.vault.get("node")?).public_key();
        if let Some(revoked) = recipients
            .iter()
            .find(|recipient| settings.revoked_device(recipient, &registry))
        {
            return Err(refused(format!(
                "recipient {} was revoked",
                revoked.to_hex()
            )));
        }
        if recipients.contains(&own) {
            return Err(refused("this device holds the group secret already"));
        }
        let statements = settings
            .epoch_statements
            .get(&secret_role(&record.address, epoch))
            .cloned()
            .unwrap_or_default();
        // Every sharer, an issuer too, signs with its node key under its chain.
        let sender = Some(settings.credentials.clone());
        let signer = PrivateKey::from_bytes(&self.vault.get("node")?);
        let secret = self.vault.get(&secret_role(&record.address, epoch))?;
        let mut draft = settings.clone();
        let mut envelopes = Vec::new();
        for recipient in &recipients {
            let envelope = GroupSecretEnvelope::seal_recorded(
                &signer,
                record.address,
                epoch.generation,
                secret,
                *recipient,
                statements.clone(),
            )?;
            envelopes.push(json!({
                "recipient": envelope.recipient().to_hex(),
                "envelope": envelope.to_bytes()?,
            }));
            let delivery = crate::delivery::Contents::seal(
                *recipient,
                crate::delivery::Reason::Share,
                &record,
                envelope.to_bytes()?,
                sender.clone(),
            )?;
            draft.queue(*recipient, &record, epoch, &delivery, true)?;
        }
        draft.save(&self.path)?;
        *settings = draft;
        Ok(json!({
            "epoch": epoch,
            "recipients": recipients.iter().map(PublicKey::to_hex).collect::<Vec<_>>(),
            "envelopes": envelopes,
            "sender": sender,
        }))
    }
    async fn group_status(&self, partition: GroupPartition) -> Result<Value, Failure> {
        let address = record_key(&partition.record.address);
        let registry = if self.settings.lock().await.issuer() {
            Some(self.registry().await?)
        } else {
            None
        };
        let (epochs, recipients) = {
            let settings = self.settings.lock().await;
            // Only the sharer holds its deliveries: no other device sees them.
            let recipients: Vec<Value> = settings
                .deliveries
                .values()
                .filter(|pending| pending.address == address)
                .map(|pending| {
                    json!({
                        "node": settings.delivery_nodes.values().chain(settings.peers.keys()).chain(registry.iter().flat_map(|registry| registry.records.keys()))
                            .find(|node| rocky_credentials::PeerId::of(**node) == pending.recipient)
                            .map(PublicKey::to_hex),
                        "reference": pending.recipient.to_hex(),
                        "epoch": pending.epoch,
                        "state": pending.state(),
                    })
                })
                .collect();
            let epochs = settings
                .groups
                .get(&address)
                .map(|record| record.epochs.clone())
                .unwrap_or_default();
            (epochs, recipients)
        };
        let holding: BTreeMap<ResourceScope, rocky_secure::Holding> =
            self.replica.subscriptions().await?.into_iter().collect();
        let mut tables = Vec::new();
        for member in &partition.members {
            tables.push(json!({
                "table": member.table,
                "scope": member.scope,
                // As activity events name the partition.
                "partition": data_encoding::HEXLOWER.encode(&member.scope.encryption),
                "epochs": self.replica.key_epochs(member.scope).await,
                "current": self.replica.key_epochs(member.scope).await.into_iter().max(),
                "holding": holding
                    .get(&member.scope)
                    .map(|state| format!("{state:?}").to_lowercase()),
            }));
        }
        Ok(json!({
            "group": partition.record.group,
            "address": record_key(&partition.record.address),
            "current": epochs.iter().max(),
            "epochs": epochs,
            "tables": tables,
            "recipients": recipients,
        }))
    }
    pub(super) async fn partition_call(
        &self,
        kind: &str,
        request: &Value,
    ) -> Result<Value, Failure> {
        match kind {
            "partition_role" => {
                let role: rocky_secure::RoleConfig =
                    serde_json::from_value(request["role"].clone())?;
                let partial = role.role == rocky_secure::ReplicaRole::Partial;
                self.replica.set_role(role).await?;
                // Partial concerns partitions: every whole unpartitioned table read here stays held.
                if partial {
                    let settings = self.settings.lock().await.clone();
                    for (_, scope) in self.domain().scopes() {
                        if !self.domain().partitioned_table(&scope)
                            && settings.reads_whole(&self.domain(), &scope)
                        {
                            self.replica.subscribe(scope).await?;
                        }
                    }
                }
                self.activity
                    .record("role_changed", json!({"partial": partial}));
                self.forget_readers().await;
                self.wake_sync();
                return Ok(json!({}));
            }
            "partition_grant" | "partition_delegate" => {
                return self.issue_partitions(kind, request).await;
            }
            "partition_address" => {
                let (scope, tuple) = self.partition_address(request)?;
                let partition = self.group_partition(request)?;
                return Ok(json!({
                    "scope": scope,
                    "tuple": tuple,
                    "group": partition.record.group,
                    "address": record_key(&partition.record.address),
                }));
            }
            "partition_complete" => {
                let (scope, _) = self.partition_address(request)?;
                return Ok(json!({"complete": self.replica.table_complete(scope.table).await?}));
            }
            "partition_next" => {
                let table = request["table"]
                    .as_str()
                    .ok_or("partition table must be a string")?;
                let identity = self.replica.next_partition_identity(table).await?;
                let partition = self.group_partition(&json!({
                    "table": table,
                    "values": [{"type": "integer", "value": identity.to_string()}],
                }))?;
                let (scope, _) = partition
                    .member(table)
                    .map(|member| (member.scope, ()))
                    .ok_or("table is not partitioned")?;
                let mut created = self.create_group(partition).await?;
                created["id"] = identity.to_string().into();
                created["scope"] = json!(scope);
                self.activity.record(
                    "partition_created",
                    json!({"table": table, "id": identity.to_string()}),
                );
                self.forget_readers().await;
                self.wake_sync();
                return Ok(created);
            }
            _ => {}
        }
        let partition = self.group_partition(request)?;
        let named = json!({"group": request["group"], "values": request["values"]});
        let omit: BTreeSet<String> = match &request["omit"] {
            Value::Null => BTreeSet::new(),
            omit => serde_json::from_value(omit.clone())?,
        };
        let result = match kind {
            "partition_create" => {
                if !self.settings.lock().await.issuer() {
                    return Err(refused("explicit partition creation requires an issuer"));
                }
                self.create_group(partition).await?
            }
            "partition_install" => {
                let bytes: Vec<u8> = serde_json::from_value(request["envelope"].clone())?;
                let envelope = GroupSecretEnvelope::from_bytes(&bytes)?;
                // The sharer's chain proves it reads the whole group.
                let sender: CredentialChain = serde_json::from_value(request["sender"].clone())
                    .map_err(|_| refused("an envelope installs with its sender's chain"))?;
                let address = record_key(&partition.record.address);
                let epoch = envelope.epoch();
                self.install_envelope(partition, &envelope, Some(&sender), false)
                    .await?;
                json!({"address": address, "epoch": epoch})
            }
            "partition_share" => {
                let shared = self.share(partition, request).await?;
                let mut event = named.clone();
                event["recipients"] = json!(shared["recipients"].as_array().map_or(0, Vec::len));
                self.activity.record("partition_shared", event);
                self.wake_sync();
                return Ok(shared);
            }
            "partition_status" => return self.group_status(partition).await,
            "partition_register" => {
                for member in partition.covered(&omit).map_err(refused)? {
                    self.replica
                        .register_partition(member.scope, member.tuple.clone())
                        .await?;
                }
                self.know(&partition).await?;
                json!({})
            }
            "partition_subscribe" | "partition_bootstrap" => {
                self.hold(&partition, &omit, kind == "partition_bootstrap")
                    .await?
            }
            "partition_unsubscribe" => {
                for member in partition.released(&omit).map_err(refused)? {
                    self.replica.unsubscribe(member.scope).await?;
                }
                json!({})
            }
            "partition_evict" => {
                let (mut rows, mut operations) = (0u64, 0u64);
                for member in partition.released(&omit).map_err(refused)? {
                    let report = self.replica.evict(member.scope).await?;
                    rows += report.rows as u64;
                    operations += report.operations as u64;
                }
                json!({"rows": rows, "operations": operations})
            }
            _ => return Err(refused("unsupported partition request")),
        };
        let event = match kind {
            "partition_create" => Some("partition_created"),
            "partition_install" => Some("partition_key_installed"),
            "partition_bootstrap" => Some("partition_bootstrap"),
            "partition_subscribe" => Some("partition_subscribed"),
            "partition_unsubscribe" => Some("partition_unsubscribed"),
            "partition_evict" => Some("partition_evicted"),
            _ => None,
        };
        if let Some(event) = event {
            self.activity.record(event, named);
        }
        self.forget_readers().await;
        self.wake_sync();
        Ok(result)
    }
    /// Holds the group partition but the tables left out; with `bootstrap`
    /// it starts from a peer's checkpoint at the next sync.
    pub(super) async fn hold(
        &self,
        partition: &GroupPartition,
        omit: &BTreeSet<String>,
        bootstrap: bool,
    ) -> Result<Value, Failure> {
        let covered = partition.covered(omit).map_err(refused)?;
        for member in &covered {
            self.replica
                .register_partition(member.scope, member.tuple.clone())
                .await?;
        }
        self.know(partition).await?;
        for member in &covered {
            self.replica.subscribe(member.scope).await?;
        }
        for member in partition
            .members
            .iter()
            .filter(|member| omit.contains(&member.table))
        {
            self.replica.unsubscribe(member.scope).await?;
        }
        if bootstrap {
            self.bootstrap_partition(&covered).await
        } else {
            Ok(json!({}))
        }
    }
    /// Saves a checkpoint-first intent for the covered members this device
    /// reads; the next sync imports them before catching up.
    async fn bootstrap_partition(
        &self,
        covered: &[&crate::groups::Member],
    ) -> Result<Value, Failure> {
        let added: Vec<ResourceScope> = {
            let settings = self.settings.lock().await;
            covered
                .iter()
                .filter(|member| settings.reads_partition(member))
                .map(|member| member.scope)
                .collect()
        };
        self.save_bootstrap(added)
    }
    fn save_bootstrap(&self, added: Vec<ResourceScope>) -> Result<Value, Failure> {
        let marker = self.path.with_file_name("bootstrap.json");
        // A pending intent waits for a peer that offers checkpoints, which a
        // keyless custody peer never does: later partitions join it.
        let mut intent = if marker.exists() {
            serde_json::from_slice::<Value>(&std::fs::read(&marker)?)?
        } else {
            json!({"intent": true, "pending": []})
        };
        let Some(pending) = intent.get_mut("pending").and_then(Value::as_array_mut) else {
            // An intent without a scope list covers every granted scope.
            return Ok(json!({"pending": added.len()}));
        };
        for scope in &added {
            let scope = serde_json::to_value(scope)?;
            if !pending.contains(&scope) {
                pending.push(scope);
            }
        }
        let count = pending.len();
        rocky_credentials::write_private(&marker, &serde_json::to_vec(&intent)?)?;
        Ok(json!({"pending": count}))
    }
}
