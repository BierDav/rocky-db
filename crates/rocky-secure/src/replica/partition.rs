//! Concrete partition addresses and selector resolution (`docs/runtime/partitioned-scopes.md`).
use super::*;
use rocky_core::{PartitionSelection, PartitionTuple};

pub(super) const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS secure_partitions(scope BLOB PRIMARY KEY,tuple BLOB NOT NULL) WITHOUT ROWID",
];

impl<A: RowApplication> Inner<A> {
    pub(super) fn resolve_chain_at(
        &self,
        chain: &CredentialChain,
        key: PublicKey,
        policy: &RevocationSet,
        time: u64,
    ) -> Result<Vec<rocky_core::ResourceGrant>, Error> {
        let (mut grants, selectors) = self
            .verified_chain(chain, policy, time)?
            .selectors(key, time)
            .map_err(credential)?;
        for (scope, tuple) in &self.partitions {
            for selector in &selectors {
                if let Some(grant) = selector
                    .resolve(scope.domain, scope.table, tuple)
                    .map_err(credential)?
                {
                    grants.push(grant);
                }
            }
        }
        Ok(grants)
    }
    pub(super) fn resolve_chain_scopes_at(
        &self,
        chain: &CredentialChain,
        key: PublicKey,
        policy: &RevocationSet,
        time: u64,
        scopes: &[ResourceScope],
    ) -> Result<Vec<rocky_core::ResourceGrant>, Error> {
        let (mut grants, selectors) = self
            .verified_chain(chain, policy, time)?
            .selectors(key, time)
            .map_err(credential)?;
        grants.retain(|grant| scopes.contains(&grant.scope));
        for scope in scopes {
            if let Some(tuple) = self.partitions.get(scope) {
                for selector in &selectors {
                    if let Some(grant) = selector
                        .resolve(scope.domain, scope.table, tuple)
                        .map_err(credential)?
                    {
                        grants.push(grant);
                    }
                }
            }
        }
        Ok(grants)
    }
    pub(super) fn resolve_chain(
        &self,
        chain: &CredentialChain,
        key: PublicKey,
        policy: &RevocationSet,
        time: u64,
    ) -> Result<Vec<rocky_core::ResourceGrant>, Error> {
        self.resolve_chain_at(chain, key, policy, time)
    }
    pub(super) fn check_authenticated_partition(
        &self,
        scope: ResourceScope,
        tuple: Option<&PartitionTuple>,
    ) -> Result<(), Error> {
        if let Some(tuple) = tuple {
            return self.check_retained_tuple(scope, tuple);
        }
        if self.partitioned(scope) {
            return Err(denied(
                "partitioned table requires an authenticated partition tuple",
            ));
        }
        Ok(())
    }
    /// Whether `scope` names a partitioned table; its rows live only in
    /// the scopes of its partitions, never in the table's own scope.
    pub(super) fn partitioned(&self, scope: ResourceScope) -> bool {
        self.workspace.typed.as_ref().is_some_and(|typed| {
            typed.rows.table(&scope.table).is_some_and(|table| {
                typed
                    .rows
                    .schema()
                    .table(&table.sql_name)
                    .is_some_and(|logical| !logical.partition_by.is_empty())
            })
        })
    }
    pub(super) fn check_tuple(
        &self,
        scope: ResourceScope,
        tuple: &PartitionTuple,
    ) -> Result<(), Error> {
        if tuple
            .scope(scope.domain, scope.table)
            .map_err(|error| denied(&error.to_string()))?
            != scope
            || !self.tables.contains(&scope.table)
            || !self.domains.contains(&scope.domain.domain)
            || scope.domain.app != self.definition.app
        {
            return Err(denied("invalid partition address"));
        }
        if let Some(typed) = &self.workspace.typed {
            let table = typed
                .rows
                .table(&scope.table)
                .ok_or_else(|| denied("unknown partition table"))?;
            let logical = typed
                .rows
                .schema()
                .table(&table.sql_name)
                .ok_or_else(|| denied("unknown partition table"))?;
            let columns: BTreeSet<_> = logical
                .partition_by
                .iter()
                .filter_map(|name| logical.column(name))
                .map(|column| typed.rows.schema().field_id(logical, column))
                .collect();
            if columns.is_empty() || columns != tuple.values().keys().copied().collect() {
                return Err(denied("partition tuple differs from the schema"));
            }
            for name in &logical.partition_by {
                let column = logical
                    .column(name)
                    .ok_or_else(|| denied("unknown partition column"))?;
                let value = tuple
                    .values()
                    .get(&typed.rows.schema().field_id(logical, column))
                    .ok_or_else(|| denied("missing partition value"))?;
                let stored = rocky_core::PartitionValue::new(
                    rocky_core::KeyColumn {
                        affinity: column.affinity,
                        collation: column.collation,
                    },
                    value.value().map_err(|error| denied(&error.to_string()))?,
                )
                .map_err(|error| denied(&error.to_string()))?;
                if &stored != value {
                    return Err(denied("partition value is not canonical for the schema"));
                }
            }
        }
        Ok(())
    }
    /// A removed table has no current descriptor. Its authenticated address
    /// stays structural; restoring its descriptor checks the columns again.
    fn check_retained_tuple(
        &self,
        scope: ResourceScope,
        tuple: &PartitionTuple,
    ) -> Result<(), Error> {
        if self.tables.contains(&scope.table) {
            return self.check_tuple(scope, tuple);
        }
        if tuple
            .scope(scope.domain, scope.table)
            .map_err(|error| denied(&error.to_string()))?
            != scope
            || !self.domains.contains(&scope.domain.domain)
            || scope.domain.app != self.definition.app
        {
            return Err(denied("invalid retained partition address"));
        }
        Ok(())
    }
    pub(super) async fn load_partitions(&mut self) -> Result<(), Error> {
        for row in rows(&self.conn, "SELECT scope,tuple FROM secure_partitions").await? {
            let [SqlValue::Blob(scope), SqlValue::Blob(tuple)] = row.as_slice() else {
                return Err(Error::Corrupt("partition address".into()));
            };
            let scope = decode(scope)?;
            let tuple = decode(tuple)?;
            self.check_retained_tuple(scope, &tuple)?;
            self.partitions.insert(scope, tuple);
        }
        Ok(())
    }
}
impl<A: RowApplication> EncryptedReplica<A> {
    pub(super) async fn discover_partition(&self, frame: &EncryptedFrame) -> Result<(), Error> {
        let operation = frame.operation()?;
        let Some(tuple) = operation.header.extensions.partition else {
            return Ok(());
        };
        let scope = operation.header.extensions.scope;
        self.register_partition_address(scope, tuple, Some(frame))
            .await
    }
    /// Prepares the next own-id partition before its key can leave this node.
    /// The write transaction still allocates and verifies the identity.
    pub async fn next_partition_identity(
        &self,
        name: &str,
    ) -> Result<rocky_core::RowIdentity, Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        let typed = inner
            .workspace
            .typed
            .as_ref()
            .ok_or_else(|| denied("no typed tables"))?;
        let table = typed.by_name(name).ok_or_else(|| denied("unknown table"))?;
        let logical = typed
            .rows
            .schema()
            .table(name)
            .filter(|table| table.partition_by == ["id"])
            .ok_or_else(|| denied("table must be partitioned by its own id"))?;
        let author = inner
            .node_author
            .as_ref()
            .ok_or_else(|| denied("node author credential missing"))?;
        let identity = rocky_core::RowIdentity::next(
            author.number,
            inner.highest_identity(table.scope, author.number).await?,
        )
        .map_err(|error| denied(&error.to_string()))?;
        let mut values = vec![SqlValue::Null; logical.columns.len()];
        let position = logical
            .columns
            .iter()
            .position(|column| column.sql_name.eq_ignore_ascii_case("id"))
            .ok_or_else(|| denied("missing id column"))?;
        values[position] = SqlValue::Integer(identity.integer());
        let tuple = typed
            .rows
            .partition(&table.table, &values)
            .map_err(|error| denied(&error))?
            .ok_or_else(|| denied("missing partition tuple"))?;
        let scope = tuple
            .scope(typed.domain, table.table.id)
            .map_err(|error| denied(&error.to_string()))?;
        let grants = author
            .credentials
            .verify_partition_author(
                inner.config.publisher,
                author.key.public_key(),
                author.number,
                scope,
                &tuple,
                &inner.config.revocations,
                now()?,
            )
            .map_err(credential)?;
        if !grants
            .iter()
            .any(|grant| grant.rights.contains(&Right::Insert))
        {
            return Err(denied("own-id partition requires an insert grant"));
        }
        if inner.graphs.contains_key(&scope.domain) {
            // Known positions predate this unused own identity, including
            // those a later checkpoint will summarize before the first seal.
            let frontier = encode(&inner.seal_frontier(scope.domain, false).await?)?;
            let logical = typed.rows.schema();
            let address = logical
                .group_address(typed.domain, name, &[SqlValue::Integer(identity.integer())])
                .map_err(|error| denied(&error.to_string()))?;
            let group = logical
                .partition_groups()
                .map_err(|error| denied(&error.to_string()))?
                .into_iter()
                .find(|group| group.name == address.group)
                .ok_or_else(|| denied("unknown partition group"))?;
            let mut empty = BTreeSet::from([name]);
            loop {
                let before = empty.len();
                for table in &group.tables {
                    if table.foreign_keys.iter().any(|key| {
                        empty.contains(key.table.as_str())
                            && logical.table(&key.table).is_some_and(|parent| {
                                key.columns.iter().zip(&key.references).any(
                                    |(child, referenced)| {
                                        table.partition_by.first() == Some(child)
                                            && parent.partition_by.first() == Some(referenced)
                                    },
                                )
                            })
                    }) {
                        empty.insert(table.sql_name.as_str());
                    }
                }
                if before == empty.len() {
                    break;
                }
            }
            let scopes = group
                .tables
                .iter()
                .filter(|table| empty.contains(table.sql_name.as_str()))
                .map(|table| {
                    let tuple = PartitionTuple::new(
                        table
                            .partition_by
                            .iter()
                            .zip(&address.values)
                            .map(|(name, value)| {
                                let column = table
                                    .column(name)
                                    .ok_or_else(|| denied("unknown partition column"))?;
                                Ok((logical.field_id(table, column), value.clone()))
                            })
                            .collect::<Result<Vec<_>, Error>>()?,
                    )
                    .map_err(|error| denied(&error.to_string()))?;
                    tuple
                        .scope(typed.domain, logical.table_id(table))
                        .map_err(|error| denied(&error.to_string()))
                })
                .collect::<Result<Vec<_>, Error>>()?;
            transaction!(inner, |inner| {
                for scope in scopes.iter().copied() {
                    // A repeated preparation preserves materialized state.
                    if inner.find_scope_id(scope).await?.is_none() {
                        let id = inner.scope_id(scope).await?;
                        inner
                            .conn
                            .execute(
                                "INSERT INTO secure_seal_anchors VALUES(?,?)",
                                bindings(vec![
                                    SqlValue::Integer(id),
                                    SqlValue::Blob(frontier.clone()),
                                ]),
                            )
                            .await?;
                    }
                }
                inner
                    .require_domain_ready(scope.domain, scopes.iter().copied())
                    .await?;
                let mut blocked = Vec::new();
                for scope in &scopes {
                    blocked.extend(inner.scope_blockers(*scope).await?);
                }
                blockers::refuse(blocked)
            })?;
            inner = flush_guard(inner, &self.inner).await?;
            inner.publish_revision().await?;
        }
        Ok(identity)
    }
    /// Registers an authorized concrete scope before subscribing or installing its key.
    pub async fn register_partition(
        &self,
        scope: ResourceScope,
        tuple: PartitionTuple,
    ) -> Result<(), Error> {
        self.register_partition_address(scope, tuple, None).await
    }
    async fn register_partition_address(
        &self,
        scope: ResourceScope,
        tuple: PartitionTuple,
        frame: Option<&EncryptedFrame>,
    ) -> Result<(), Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        if let Some(frame) = frame {
            if inner.partitions.get(&scope) == Some(&tuple) {
                return Ok(());
            }
            inner.verify_frame(frame, now()?)?;
            inner.check_retained_tuple(scope, &tuple)?;
        } else {
            inner.check_tuple(scope, &tuple)?;
        }
        inner
            .config
            .credentials
            .verify_partition(
                inner.config.publisher,
                inner.config.node.public_key(),
                scope,
                &tuple,
                &inner.config.revocations,
                now()?,
            )
            .map_err(credential)?;
        if inner.partitions.get(&scope) == Some(&tuple) {
            return Ok(());
        }
        if inner.partitions.len() >= 4096 {
            return Err(Error::Backpressure);
        }
        transaction!(inner, |inner| {
            inner
                .conn
                .execute(
                    "INSERT INTO secure_partitions VALUES(?,?)",
                    [encode(&scope)?, encode(&tuple)?],
                )
                .await?;
            Ok(())
        })?;
        inner.partitions.insert(scope, tuple);
        inner.bump_authority();
        Ok(())
    }
    pub async fn table_complete(&self, table: Commitment) -> Result<bool, Error> {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .table_complete(table)
            .await
    }
}
impl<A: RowApplication> Inner<A> {
    pub(super) async fn table_complete(&self, table: Commitment) -> Result<bool, Error> {
        let selectors = self.local_selectors(now()?)?;
        let Some(typed) = &self.workspace.typed else {
            return Ok(false);
        };
        let Some(projected) = typed
            .tables
            .iter()
            .find(|projected| projected.table.id == table)
        else {
            return Ok(false);
        };
        let Some(logical) = typed.rows.schema().table(&projected.table.sql_name) else {
            return Ok(false);
        };
        let columns: BTreeSet<_> = logical
            .partition_by
            .iter()
            .filter_map(|name| logical.column(name))
            .map(|column| typed.rows.schema().field_id(logical, column))
            .collect();
        let covers = selectors.iter().any(|grant| {
            grant.domain == typed.domain
                && !columns.is_empty()
                && grant.selector.0.keys().copied().collect::<BTreeSet<_>>() == columns
                && grant.table == table
                && grant.rows == RowSelection::All
                && grant.rights.contains(&Right::Read)
                && grant
                    .selector
                    .0
                    .values()
                    .all(|selection| matches!(selection, PartitionSelection::Any))
        });
        if !covers || self.role().await?.role != ReplicaRole::Full {
            return Ok(false);
        }
        let readiness = self.readiness(typed.domain).await?;
        for scope in self.partitions.keys().filter(|scope| scope.table == table) {
            if !self.holds(*scope).await?
                || !self.can_read_key(*scope, &self.local_grants(now()?)?)
                || !self.config.keys.iter().any(|key| key.scope == *scope)
                || self.partition_waits(&readiness, *scope).await?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
impl<A: RowApplication> Inner<A> {
    /// A held partition whose rows are not all here yet.
    async fn partition_waits(
        &self,
        readiness: &blockers::DomainReadiness,
        scope: ResourceScope,
    ) -> Result<bool, Error> {
        Ok(self.has_pending(scope).await?
            || self.restoring(scope).await?
            || !self.readable_in(readiness, scope).await?.is_empty())
    }
    pub(super) async fn partition_rules(
        &self,
        referenced: Option<&BTreeSet<String>>,
        status: &SessionStatus,
    ) -> Result<BTreeMap<String, rocky_storage::partition_sql::TablePartitions>, Error> {
        let Some(typed) = &self.workspace.typed else {
            return Ok(BTreeMap::new());
        };
        let mut rules = BTreeMap::new();
        for projected in &typed.tables {
            if referenced.is_some_and(|names| {
                !names.contains(&projected.table.sql_name.to_ascii_lowercase())
            }) {
                continue;
            }
            let logical = typed
                .rows
                .schema()
                .table(&projected.table.sql_name)
                .ok_or_else(|| denied("unknown table"))?;
            if logical.partition_by.is_empty() {
                continue;
            }
            let readiness = self.readiness(typed.domain).await?;
            let mut held = Vec::new();
            let mut waiting = Vec::new();
            let mut complete = self.table_complete(projected.table.id).await?;
            for (scope, tuple) in self.partitions.iter().filter(|(scope, _)| {
                scope.table == projected.table.id && scope.domain == typed.domain
            }) {
                if !status.readable.contains(scope) || !self.holds(*scope).await? {
                    complete = false;
                    continue;
                }
                let values = partition_values(typed.rows.schema(), logical, tuple)?;
                // Only this partition's own state holds it back.
                if self.partition_waits(&readiness, *scope).await? {
                    complete = false;
                    waiting.push(values);
                } else {
                    held.push(values);
                }
            }
            rules.insert(
                logical.sql_name.to_ascii_lowercase(),
                rocky_storage::partition_sql::TablePartitions {
                    columns: partition_columns(logical)?,
                    complete,
                    held,
                    waiting,
                },
            );
        }
        Ok(rules)
    }
    pub(super) async fn partition_statement(
        &self,
        sql: &str,
        params: &[SqlValue],
        status: &SessionStatus,
    ) -> Result<rocky_storage::partition_sql::Checked, Error> {
        let unchanged = || rocky_storage::partition_sql::Checked {
            sql: sql.into(),
            params: params.to_vec(),
        };
        let Some(typed) = &self.workspace.typed else {
            return Ok(unchanged());
        };
        let schema = typed.rows.schema();
        if schema.views.is_empty()
            && schema
                .tables
                .iter()
                .all(|table| table.partition_by.is_empty())
        {
            return Ok(unchanged());
        }
        let refused = |error: rocky_storage::partition_sql::Refusal| Error::Sql(error.into());
        let prepared =
            rocky_storage::partition_sql::prepare(sql, &schema.views).map_err(refused)?;
        let rules = self
            .partition_rules(Some(prepared.tables()), status)
            .await?;
        if rules.is_empty() && schema.views.is_empty() {
            return Ok(unchanged());
        }
        prepared.check(params, &rules).map_err(refused)
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// Packs complete selected group partitions into bounded frontier exchanges.
    pub(crate) async fn frontier_batches(
        &self,
        scopes: &[ResourceScope],
        limit: usize,
    ) -> Result<Vec<Vec<ResourceScope>>, Error> {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        let mut groups = BTreeMap::<(rocky_core::Scope, Commitment), Vec<ResourceScope>>::new();
        for scope in scopes {
            let address = if let (Some(typed), Some(tuple)) =
                (&inner.workspace.typed, inner.partitions.get(scope))
            {
                let table = typed
                    .rows
                    .table(&scope.table)
                    .ok_or_else(|| denied("unknown partition table"))?;
                let schema = typed.rows.schema();
                let logical = schema
                    .table(&table.sql_name)
                    .ok_or_else(|| denied("unknown partition table"))?;
                let values = logical
                    .partition_by
                    .iter()
                    .map(|name| {
                        let column = logical
                            .column(name)
                            .ok_or_else(|| denied("unknown partition column"))?;
                        tuple
                            .values()
                            .get(&schema.field_id(logical, column))
                            .ok_or_else(|| denied("missing partition value"))?
                            .value()
                            .map_err(|error| denied(&error.to_string()))
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                schema
                    .group_address(scope.domain, &table.sql_name, &values)
                    .map_err(|error| denied(&error.to_string()))?
                    .commitment
            } else {
                rocky_core::commitment("rocky.frontier-single-scope", &encode(scope)?)
            };
            groups
                .entry((scope.domain, address))
                .or_default()
                .push(*scope);
        }
        let mut batches = Vec::new();
        let mut batch = Vec::new();
        for group in groups.into_values() {
            if group.len() > limit {
                return Err(denied("partition group exceeds frontier batch limit"));
            }
            if batch.len() + group.len() > limit {
                batches.push(std::mem::take(&mut batch));
            }
            batch.extend(group);
        }
        if !batch.is_empty() {
            batches.push(batch);
        }
        Ok(batches)
    }
}

/// Custody of a partition without read: the grants of a keyless custody node.
fn custody_only(grants: &[rocky_core::ResourceGrant]) -> bool {
    grants
        .iter()
        .any(|grant| grant.rights.contains(&Right::Custody))
        && !grants
            .iter()
            .any(|grant| grant.rights.contains(&Right::Read))
}

impl<A: RowApplication> Inner<A> {
    /// `chain`'s grants on one concrete partition under the held revocations.
    pub(super) fn partition_grants(
        &self,
        chain: &CredentialChain,
        key: PublicKey,
        scope: ResourceScope,
        tuple: &PartitionTuple,
    ) -> Result<Vec<rocky_core::ResourceGrant>, Error> {
        chain
            .verify_partition(
                self.config.publisher,
                key,
                scope,
                tuple,
                &self.config.revocations,
                now()?,
            )
            .map_err(credential)
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// The partition tuples of `scopes` that `peer` may hold only as keyless
    /// custody. Revealed to that peer alone, so it can register partitions
    /// created after it enrolled (`docs/decisions/0045-custody-partition-offers.md`).
    pub(crate) async fn custody_offers(
        &self,
        peer: PublicKey,
        credentials: &CredentialChain,
        scopes: &[ResourceScope],
    ) -> Result<Vec<(ResourceScope, PartitionTuple)>, Error> {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        // One chain verification per batch. A peer without custody gets no
        // offer.
        let Ok((_, selectors)) = credentials.verify_selectors(
            inner.config.publisher,
            peer,
            &inner.config.revocations,
            now()?,
        ) else {
            return Ok(Vec::new());
        };
        if !selectors
            .iter()
            .any(|selector| selector.rights.contains(&Right::Custody))
        {
            return Ok(Vec::new());
        }
        let mut offers = Vec::new();
        for scope in scopes {
            let Some(tuple) = inner.partitions.get(scope) else {
                continue;
            };
            let mut grants = Vec::new();
            for selector in &selectors {
                if let Ok(Some(grant)) = selector.resolve(scope.domain, scope.table, tuple) {
                    grants.push(grant);
                }
            }
            if custody_only(&grants) {
                offers.push((*scope, tuple.clone()));
            }
        }
        Ok(offers)
    }
    /// Peer holdings on a link do not subscribe a reader to an unknown partition.
    pub(crate) async fn accept_link_custody_offers(
        &self,
        peer: PublicKey,
        credentials: &CredentialChain,
        scopes: &[ResourceScope],
        offers: &[(ResourceScope, PartitionTuple)],
    ) -> Result<(), Error> {
        let offered = {
            let inner = self.inner.lock(crate::replica::Class::Background).await;
            let own = inner.config.node.public_key();
            let mut offered = Vec::new();
            for (scope, tuple) in offers {
                inner.check_tuple(*scope, tuple)?;
                let held = inner.partition_grants(&inner.config.credentials, own, *scope, tuple)?;
                if inner.partitions.contains_key(scope) || custody_only(&held) {
                    offered.push((*scope, tuple.clone()));
                }
            }
            offered
        };
        self.accept_custody_offers(peer, credentials, scopes, &offered)
            .await
    }
    /// Registers offered partitions this node holds only as keyless custody,
    /// from a peer authorized to read or keep each of them. Other offers are
    /// refused; a known partition is unchanged.
    pub(crate) async fn accept_custody_offers(
        &self,
        peer: PublicKey,
        credentials: &CredentialChain,
        scopes: &[ResourceScope],
        offers: &[(ResourceScope, PartitionTuple)],
    ) -> Result<(), Error> {
        if offers.len() > scopes.len() {
            return Err(denied("partition offers outside the frontier batch"));
        }
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        let mut accepted = Vec::new();
        for (scope, tuple) in offers {
            if !scopes.contains(scope) {
                return Err(denied("partition offers outside the frontier batch"));
            }
            inner.check_tuple(*scope, tuple)?;
            let sender = inner.partition_grants(credentials, peer, *scope, tuple)?;
            if !sender.iter().any(|grant| {
                grant.rows == RowSelection::All
                    && (grant.rights.contains(&Right::Read)
                        || grant.rights.contains(&Right::Custody))
            }) {
                return Err(denied(
                    "partition offer from a peer without read or custody",
                ));
            }
            if inner.partitions.contains_key(scope) {
                continue;
            }
            let own = inner.config.node.public_key();
            let held = inner.partition_grants(&inner.config.credentials, own, *scope, tuple)?;
            if !custody_only(&held) {
                return Err(denied(
                    "only a keyless custody node registers offered partitions",
                ));
            }
            accepted.push((*scope, tuple.clone()));
        }
        if accepted.is_empty() {
            return Ok(());
        }
        if inner.partitions.len() + accepted.len() > 4096 {
            return Err(Error::Backpressure);
        }
        transaction!(inner, |inner| {
            for (scope, tuple) in &accepted {
                inner
                    .conn
                    .execute(
                        "INSERT INTO secure_partitions VALUES(?,?)",
                        [encode(scope)?, encode(tuple)?],
                    )
                    .await?;
            }
            Ok(())
        })?;
        inner.partitions.extend(accepted);
        inner.bump_authority();
        Ok(())
    }
}

/// A partition's values in `partition_by` order, as SQL sees them.
pub(super) fn partition_values(
    schema: &rocky_core::LogicalSchema,
    logical: &rocky_core::LogicalTable,
    tuple: &rocky_core::PartitionTuple,
) -> Result<Vec<SqlValue>, Error> {
    logical
        .partition_by
        .iter()
        .map(|name| {
            let column = logical
                .column(name)
                .ok_or_else(|| denied("unknown partition column"))?;
            tuple
                .values()
                .get(&schema.field_id(logical, column))
                .ok_or_else(|| denied("missing partition column"))?
                .value()
                .map_err(|error| denied(&error.to_string()))
        })
        .collect()
}

/// A table's partition columns as the SQL rewriter compares them.
pub(super) fn partition_columns(
    logical: &rocky_core::LogicalTable,
) -> Result<Vec<rocky_storage::partition_sql::PartitionColumn>, Error> {
    logical
        .partition_by
        .iter()
        .map(|name| {
            let column = logical
                .column(name)
                .ok_or_else(|| denied("unknown partition column"))?;
            Ok(rocky_storage::partition_sql::PartitionColumn {
                name: name.clone(),
                key: rocky_core::KeyColumn {
                    affinity: column.affinity,
                    collation: column.collation,
                },
            })
        })
        .collect()
}
