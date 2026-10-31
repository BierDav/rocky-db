//! Node author credentials and transaction-local identity reservations.
use super::*;

pub(super) mod receipts;

/// A re-admission that needs a waiting scope's replay ledger.
pub(super) const LEDGER_WAITS: &str = "the scope waits for its base before this frame reapplies";

pub(super) const SCHEMA: &[&str] = &[
    receipts::SCHEMA[0],
    receipts::SCHEMA[1],
    receipts::SCHEMA[2],
    receipts::SCHEMA[3],
    receipts::SCHEMA[4],
    receipts::SCHEMA[5],
    receipts::SCHEMA[6],
    receipts::SCHEMA[7],
    receipts::SCHEMA[8],
    receipts::SCHEMA[9],
    receipts::SCHEMA[10],
    receipts::SCHEMA[11],
    receipts::SCHEMA[12],
    "CREATE TABLE IF NOT EXISTS secure_author_sequences(node BLOB PRIMARY KEY,sequence INTEGER NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_node_authors(node BLOB PRIMARY KEY,number INTEGER NOT NULL) WITHOUT ROWID",
    // `key` is a 16-byte digest of the business key, keyed by the interned
    // scope id; lookups confirm the full key from the row.
    "CREATE TABLE IF NOT EXISTS secure_row_keys(scope INTEGER NOT NULL,row BLOB NOT NULL,key BLOB NOT NULL,PRIMARY KEY(scope,row)) WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS secure_row_keys_key ON secure_row_keys(scope,key,row)",
    "CREATE TRIGGER IF NOT EXISTS secure_row_keys_delete AFTER DELETE ON secure_rows BEGIN DELETE FROM secure_row_keys WHERE scope=OLD.scope AND row=OLD.row; END",
];

#[derive(Clone)]
pub(super) struct NodeAuthor {
    pub(super) key: PrivateKey,
    pub(super) credentials: CredentialChain,
    /// `credentials` with the digest this author's frames name.
    pub(super) chain: Chain,
    pub(super) number: u32,
}

pub(super) struct BirthMark {
    pub mark: checkpoint::IdentityMark,
    pub carried: bool,
}
#[derive(Clone, Copy)]
pub(crate) enum Raise {
    Carried,
    Own,
    Statement { own: u32 },
}

/// The identity marks one replay has passed: seeded from exactly the state
/// it starts over, raised by eligible own births, never by carries or live maxima.
#[derive(Clone, Debug, Default)]
pub(super) struct IdentityLedger(BTreeMap<u32, checkpoint::IdentityMark>);

impl IdentityLedger {
    pub(super) fn based(marks: &[checkpoint::CoveredMark]) -> Result<Self, Error> {
        let mut ledger = Self::default();
        for mark in marks.iter().filter_map(checkpoint::CoveredMark::own_mark) {
            ledger.merge(mark)?;
        }
        Ok(ledger)
    }
    pub(super) fn seeded(marks: &[checkpoint::IdentityMark]) -> Result<Self, Error> {
        let mut ledger = Self::default();
        for mark in marks {
            ledger.merge(mark.clone())?;
        }
        Ok(ledger)
    }
    /// Raises `mark.author`'s mark; one author number has one signer.
    pub(super) fn merge(&mut self, mark: checkpoint::IdentityMark) -> Result<(), Error> {
        match self.0.get_mut(&mark.author) {
            Some(held) if held.signer != mark.signer => {
                Err(Error::Corrupt("an identity author has two signers".into()))
            }
            Some(held) => {
                held.sequence = held.sequence.max(mark.sequence);
                Ok(())
            }
            None => {
                self.0.insert(mark.author, mark);
                Ok(())
            }
        }
    }
    pub(super) fn get(&self, author: u32) -> Option<&checkpoint::IdentityMark> {
        self.0.get(&author)
    }
    pub(super) fn into_marks(self) -> Vec<checkpoint::IdentityMark> {
        self.0.into_values().collect()
    }
}

impl NodeAuthor {
    pub(super) fn new(config: &SecureConfig) -> Result<Self, Error> {
        Ok(Self {
            key: config.node.clone(),
            credentials: config.credentials.clone(),
            chain: Chain::new(config.credentials.clone())?,
            number: config.credentials.author_number().map_err(credential)?,
        })
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// Registers the local node key for credential-bound control signatures.
    pub async fn register_credential_signer(&self, key: PrivateKey) -> Result<(), Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        inner
            .config
            .credentials
            .verify_node_alias(
                inner.config.publisher,
                rocky_credentials::PeerId::of(inner.config.node.public_key()),
                key.public_key(),
            )
            .map_err(credential)?;
        inner.credential_signer = Some(key);
        Ok(())
    }
}
impl<A: RowApplication> Inner<A> {
    /// The same status and visibility predicate used by replay and L.
    /// Persisted L always describes the selected workspace.
    pub(super) fn replay_eligible(
        &self,
        status: &str,
        operation: &p2panda_core::Operation<Extensions>,
        workspace: bool,
    ) -> Result<bool, Error> {
        Ok(status != "abandoned"
            && (status != "held" || self.visible_held_in_workspace(operation)?)
            && (!workspace
                || !self
                    .graphs
                    .contains_key(&operation.header.extensions.scope.domain)
                || self.visible_in_workspace(operation)?))
    }

    pub(super) async fn reserve_author_sequence(&self, node: PublicKey) -> Result<u64, Error> {
        let mut reserved = self.conn.query(
            "INSERT INTO secure_author_sequences VALUES(?,0) ON CONFLICT(node) DO UPDATE SET sequence=sequence+1 WHERE sequence<9223372036854775807 RETURNING sequence",
            [node.as_bytes().to_vec()],
        ).await?;
        let row = reserved
            .next()
            .await?
            .ok_or_else(|| denied("author sequence exhausted"))?;
        Ok(row.get::<i64>(0)? as u64)
    }
    /// A node's number cannot change across renewal, scopes, or restart.
    pub(super) async fn bind_node_author(&self, chain: &CredentialChain) -> Result<(), Error> {
        let leaf = chain
            .0
            .last()
            .ok_or_else(|| denied("node credential missing"))?;
        let node = leaf.capability.subject;
        let number = chain.author_number().map_err(credential)?;
        let mut stored = self
            .conn
            .query(
                "SELECT number FROM secure_node_authors WHERE node=?",
                [node.as_bytes().to_vec()],
            )
            .await?;
        if let Some(row) = stored.next().await? {
            if row.get::<i64>(0)? != i64::from(number) {
                return Err(denied("a node cannot claim different author numbers"));
            }
        } else {
            self.conn
                .execute(
                    "INSERT INTO secure_node_authors VALUES(?,?)",
                    vec![
                        crate::sqlite::Value::Blob(node.as_bytes().to_vec()),
                        crate::sqlite::Value::Integer(i64::from(number)),
                    ],
                )
                .await?;
        }
        Ok(())
    }
    pub(super) fn storage_row(&self, change: &RowChange) -> Result<Commitment, Error> {
        Ok(
            match self
                .app
                .row_identity(change)
                .map_err(|message| denied(&message))?
            {
                Some(id) => {
                    rocky_core::commitment("rocky.row-incarnation.v2", &id.integer().to_le_bytes())
                }
                None => change.row,
            },
        )
    }
    pub(super) async fn key_row(
        &self,
        scope: ResourceScope,
        key: Commitment,
    ) -> Result<Option<Materialized>, Error> {
        if self.workspace.typed.is_some() {
            self.winner(scope, key).await
        } else {
            self.row(scope, key).await
        }
    }
    pub(super) async fn winner(
        &self,
        scope: ResourceScope,
        key: Commitment,
    ) -> Result<Option<Materialized>, Error> {
        let mut cursor = Vec::new();
        let mut winner: Option<Materialized> = None;
        loop {
            let chunk = collect_rows(self.conn.query(
                "SELECT r.row,r.fields FROM secure_row_keys k JOIN secure_rows r ON r.scope=k.scope AND r.row=k.row WHERE k.scope=(SELECT id FROM secure_scope_state WHERE scope=?) AND k.key=? AND k.row>? ORDER BY k.row LIMIT 256",
                [encode(&scope)?, key_digest(&key), cursor.clone()],
            ).await?).await?;
            for row in &chunk {
                let [SqlValue::Blob(id), SqlValue::Blob(bytes)] = row.as_slice() else {
                    return Err(Error::Corrupt("incarnation row".into()));
                };
                cursor = id.clone();
                let record = self.decode_record(bytes).await?;
                if !record.deleted
                    && record.key == Some(key)
                    && winner.as_ref().is_none_or(|held| {
                        (record.created.as_ref(), record.identity)
                            > (held.created.as_ref(), held.identity)
                    })
                {
                    winner = Some(record);
                }
            }
            if chunk.len() < 256 {
                return Ok(winner);
            }
        }
    }
    /// Indexes `record` stored at `row`; a known `old` avoids rewriting
    /// unchanged move and natural-key entries.
    pub(super) async fn index_row_key(
        &self,
        scope: &[u8],
        row: &[u8],
        old: Option<&Materialized>,
        record: &Materialized,
    ) -> Result<(), Error> {
        let marked = |record: &Materialized| record.moved_from.is_some() && !record.deleted;
        if marked(record) {
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO secure_move_rows VALUES(?,?)",
                    [scope.to_vec(), row.to_vec()],
                )
                .await?;
        } else if old.is_none_or(marked) {
            self.conn
                .execute(
                    "DELETE FROM secure_move_rows WHERE scope=? AND row=?",
                    [scope.to_vec(), row.to_vec()],
                )
                .await?;
        }

        let key = record.key.as_ref().map_or(row, |key| key.as_slice());
        if old.is_some_and(|old| old.key.as_ref().map_or(row, |key| key.as_slice()) == key) {
            return Ok(());
        }
        let key = key_digest(key);
        self.conn.execute(
            "INSERT INTO secure_row_keys VALUES((SELECT id FROM secure_scope_state WHERE scope=?),?,?) ON CONFLICT(scope,row) DO UPDATE SET key=excluded.key",
            [scope.to_vec(), row.to_vec(), key],
        ).await?;
        Ok(())
    }
    /// Backfills the derived index after open or a bulk restore, in bounded pages.
    pub(super) async fn index_row_keys(&self) -> Result<(), Error> {
        // A key cursor, so no page scans the rows an earlier one indexed.
        let mut after = (0, Vec::new());
        loop {
            let chunk = collect_rows(self.conn.query(
                "SELECT r.scope,s.scope,r.row,r.fields FROM secure_rows r JOIN secure_scope_state s ON s.id=r.scope LEFT JOIN secure_row_keys k ON k.scope=r.scope AND k.row=r.row WHERE k.row IS NULL AND (r.scope,r.row)>(?,?) ORDER BY r.scope,r.row LIMIT 256",
                bindings(vec![SqlValue::Integer(after.0), SqlValue::Blob(after.1.clone())]),
            ).await?).await?;
            for row in &chunk {
                let [
                    SqlValue::Integer(id),
                    SqlValue::Blob(scope),
                    SqlValue::Blob(row),
                    SqlValue::Blob(bytes),
                ] = row.as_slice()
                else {
                    return Err(Error::Corrupt("incarnation index row".into()));
                };
                self.index_row_key(scope, row, None, &self.decode_record(bytes).await?)
                    .await?;
                after = (*id, row.clone());
            }
            if chunk.len() < 256 {
                return Ok(());
            }
        }
    }
    /// The allocation scope the installed schema derives for `scope`: a
    /// partitioned table's template scope, else the scope itself. None when
    /// a typed schema no longer describes it.
    fn derived_allocation(&self, scope: ResourceScope) -> Option<ResourceScope> {
        let Some(typed) = self.workspace.typed.as_ref() else {
            return Some(scope);
        };
        let table = typed.declared_by_scope(scope)?;
        Some(
            match typed
                .rows
                .schema()
                .table(&table.table.sql_name)
                .is_some_and(|logical| !logical.partition_by.is_empty())
            {
                true => table.scope,
                false => scope,
            },
        )
    }
    /// The scope whose permanent marks local allocation reads for `scope`.
    pub(super) fn identity_allocation_scope(&self, scope: ResourceScope) -> ResourceScope {
        self.derived_allocation(scope).unwrap_or(scope)
    }
    /// The stored, immutable allocation binding of `scope`, checked against
    /// what the installed schema derives.
    pub(super) async fn allocation_binding(
        &self,
        scope: ResourceScope,
    ) -> Result<Option<(i64, ResourceScope)>, Error> {
        let records = collect_rows(
            self.conn
                .query(
                    "SELECT t.id,t.scope FROM secure_identity_partitions p JOIN secure_identity_tables t ON t.id=p.allocation WHERE p.scope=?",
                    [encode(&scope)?],
                )
                .await?,
        )
        .await?;
        let Some([SqlValue::Integer(id), SqlValue::Blob(allocation)]) =
            records.first().map(Vec::as_slice)
        else {
            return Ok(None);
        };
        let allocation: ResourceScope = decode(allocation)?;
        if self
            .derived_allocation(scope)
            .is_some_and(|derived| derived != allocation)
        {
            return Err(Error::Corrupt(
                "an identity allocation binding differs from the schema".into(),
            ));
        }
        Ok(Some((*id, allocation)))
    }
    /// The bound allocation of `scope`, which admission evidence needs.
    pub(super) async fn bound_allocation(
        &self,
        scope: ResourceScope,
    ) -> Result<(i64, ResourceScope), Error> {
        self.allocation_binding(scope)
            .await?
            .ok_or_else(|| Error::Corrupt("an identity allocation binding is missing".into()))
    }
    /// Inside a write transaction: the allocation id and scope `scope`'s
    /// identities share, binding them once from the installed schema. Table
    /// removal, eviction or a new base never change a binding.
    pub(super) async fn allocation_of(
        &self,
        scope: ResourceScope,
    ) -> Result<(i64, ResourceScope), Error> {
        if let Some(bound) = self.allocation_binding(scope).await? {
            return Ok(bound);
        }
        let allocation = self
            .derived_allocation(scope)
            .ok_or_else(|| denied("the schema no longer describes this table"))?;
        self.conn
            .execute(
                "INSERT OR IGNORE INTO secure_identity_tables(scope) VALUES(?)",
                [encode(&allocation)?],
            )
            .await?;
        self.conn
            .execute(
                "INSERT INTO secure_identity_partitions SELECT ?,id FROM secure_identity_tables WHERE scope=?",
                [encode(&scope)?, encode(&allocation)?],
            )
            .await?;
        self.bound_allocation(scope).await
    }
    pub(super) async fn optional_allocation_of(
        &self,
        scope: ResourceScope,
    ) -> Result<Option<(i64, ResourceScope)>, Error> {
        match self.allocation_binding(scope).await? {
            Some(binding) => Ok(Some(binding)),
            None if self.derived_allocation(scope).is_some() => {
                self.allocation_of(scope).await.map(Some)
            }
            None => Ok(None),
        }
    }
    pub(super) async fn highest_identity(
        &self,
        scope: ResourceScope,
        author: u32,
    ) -> Result<u32, Error> {
        Ok(self
            .identity_marks(scope)
            .await?
            .into_iter()
            .find(|mark| mark.author == author)
            .map_or(0, |mark| mark.sequence))
    }
    pub(super) async fn identity_marks(
        &self,
        scope: ResourceScope,
    ) -> Result<Vec<checkpoint::IdentityMark>, Error> {
        self.marks_in("secure_identity_marks", scope).await
    }
    async fn marks_in(
        &self,
        table: &str,
        scope: ResourceScope,
    ) -> Result<Vec<checkpoint::IdentityMark>, Error> {
        let records = collect_rows(
            self.conn
                .query(
                    format!(
                        "SELECT author,signer,sequence FROM {table} WHERE scope=? ORDER BY author"
                    ),
                    [encode(&scope)?],
                )
                .await?,
        )
        .await?;
        records
            .into_iter()
            .map(|row| {
                let [
                    SqlValue::Integer(author),
                    SqlValue::Blob(signer),
                    SqlValue::Integer(sequence),
                ] = row.as_slice()
                else {
                    return Err(Error::Corrupt("row identity mark".into()));
                };
                Ok(checkpoint::IdentityMark {
                    author: u32::try_from(*author)
                        .map_err(|_| denied("invalid identity author"))?,
                    signer: PublicKey::from_bytes(
                        signer
                            .as_slice()
                            .try_into()
                            .map_err(|_| denied("invalid identity signer"))?,
                    )
                    .map_err(|error| denied(&error.to_string()))?,
                    sequence: u32::try_from(*sequence)
                        .map_err(|_| denied("invalid identity sequence"))?,
                })
            })
            .collect()
    }
    /// Raises the permanent mark of `mark.author` at the concrete and the
    /// allocation scope, and the own/summary floors according to its source. A signer
    /// other than the one either scope holds for that author is refused
    /// before anything is written. Marks are never lowered or deleted.
    pub(crate) async fn put_identity_mark(
        &self,
        scope: ResourceScope,
        mark: &checkpoint::IdentityMark,
        raise: Raise,
    ) -> Result<(), Error> {
        let own = match raise {
            Raise::Carried => 0,
            Raise::Own => mark.sequence,
            Raise::Statement { own } if own <= mark.sequence => own,
            Raise::Statement { .. } => return Err(denied("own-birth mark exceeds covered mark")),
        };
        let (_, allocation) = self.allocation_of(scope).await?;
        let scopes = BTreeSet::from([scope, allocation]);
        for scope in &scopes {
            if self
                .identity_marks(*scope)
                .await?
                .iter()
                .any(|held| held.author == mark.author && held.signer != mark.signer)
            {
                return Err(denied(
                    "checkpoint author number belongs to another signing key",
                ));
            }
        }
        for scope in scopes {
            self.conn.execute(
                "INSERT INTO secure_identity_marks VALUES(?,?,?,?) ON CONFLICT(scope,author) DO UPDATE SET sequence=MAX(sequence,excluded.sequence)",
                bindings(vec![SqlValue::Blob(encode(&scope)?), SqlValue::Integer(i64::from(mark.author)), SqlValue::Blob(mark.signer.as_bytes().to_vec()), SqlValue::Integer(i64::from(mark.sequence))]),
            ).await?;
        }
        if own > 0 {
            self.conn.execute(
                "INSERT INTO secure_identity_own VALUES(?,?,?) ON CONFLICT(scope,author) DO UPDATE SET sequence=MAX(sequence,excluded.sequence)",
                bindings(vec![SqlValue::Blob(encode(&scope)?), SqlValue::Integer(i64::from(mark.author)), SqlValue::Integer(i64::from(own))]),
            ).await?;
        }
        // S records only the statement's own-birth maximum in this partition.
        if matches!(raise, Raise::Statement { .. }) && own > 0 {
            self.conn.execute(
                "INSERT INTO secure_identity_summary VALUES(?,?,?) ON CONFLICT(scope,author) DO UPDATE SET sequence=MAX(sequence,excluded.sequence)",
                bindings(vec![SqlValue::Blob(encode(&scope)?), SqlValue::Integer(i64::from(mark.author)), SqlValue::Integer(i64::from(own))]),
            ).await?;
        }
        Ok(())
    }
    /// Raises scope `scope`'s replay ledger with `mark`.
    pub(super) async fn fold_ledger(
        &self,
        scope: ResourceScope,
        mark: &checkpoint::IdentityMark,
    ) -> Result<(), Error> {
        if self
            .ledger_marks(scope)
            .await?
            .iter()
            .any(|held| held.author == mark.author && held.signer != mark.signer)
        {
            return Err(Error::Corrupt("an identity author has two signers".into()));
        }
        self.conn.execute(
            "INSERT INTO secure_identity_ledger VALUES(?,?,?,?) ON CONFLICT(scope,author) DO UPDATE SET sequence=MAX(sequence,excluded.sequence)",
            bindings(vec![SqlValue::Blob(encode(&scope)?), SqlValue::Integer(i64::from(mark.author)), SqlValue::Blob(mark.signer.as_bytes().to_vec()), SqlValue::Integer(i64::from(mark.sequence))]),
        ).await?;
        Ok(())
    }
    /// The replay ledger a re-admission compares with. A scope waiting for
    /// its seal has none, and the decision waits instead of reading it as
    /// empty.
    pub(super) async fn ledger_entry(
        &self,
        scope: ResourceScope,
    ) -> Result<Vec<checkpoint::IdentityMark>, Error> {
        if self.ledger_waits(scope).await? {
            return Err(Error::Rejected(LEDGER_WAITS.into()));
        }
        self.ledger_marks(scope).await
    }
    /// Whether `scope` waits for a base at a seal of the path: pruned
    /// history and no installed base there, so no replay ledger.
    pub(super) async fn ledger_waits(&self, scope: ResourceScope) -> Result<bool, Error> {
        if matches!(
            self.holding(scope).await?,
            Some(roles::Holding::Evicting | roles::Holding::Evicted)
        ) || !self.ledger_readable(scope)
            || self.ledger_queued(scope).await?
        {
            return Ok(true);
        }
        // A rebootstrap need alone does not: a reset replay refills from
        // nothing, and its returning frames must fold into an empty L.
        if !self.has_pruned_prefix(scope).await? {
            return Ok(false);
        }
        let Some(id) = self.find_scope_id(scope).await? else {
            return Ok(true);
        };
        Ok(self.base_seal(id).await?.is_none() || self.base_off_path(scope, id).await?)
    }
    /// Reconstructs only the current workspace's eligible suffix over its
    /// exact installed base. A waiting scope has no usable ledger.
    pub(super) async fn recomputed_ledger(
        &self,
        scope: ResourceScope,
        id: i64,
    ) -> Result<IdentityLedger, Error> {
        if self.ledger_waits(scope).await? {
            return Ok(IdentityLedger::default());
        }
        let (mut after, mut ledger) = match self.checkpoint_record(id, true).await? {
            Some(record) => {
                let signed = self.verify_record(scope, &record)?;
                (
                    record.position,
                    IdentityLedger::based(&signed.statement.identities)?,
                )
            }
            None => (0, IdentityLedger::default()),
        };
        loop {
            let records = collect_rows(self.conn.query(
                "SELECT a.position,o.header,o.body,o.status FROM secure_applied a LEFT JOIN secure_operations o ON o.hash=a.hash WHERE a.scope=? AND a.position>? ORDER BY a.position LIMIT 256",
                [id, after],
            ).await?).await?;
            for record in &records {
                let [
                    SqlValue::Integer(position),
                    SqlValue::Blob(header),
                    SqlValue::Blob(body),
                    SqlValue::Text(status),
                ] = record.as_slice()
                else {
                    return Err(Error::Corrupt(
                        "an applied ledger frame is not retained".into(),
                    ));
                };
                after = *position;
                let frame = self.chained_frame(header.clone(), body.clone()).await?;
                if self.replay_eligible(status, frame.operation_ref()?, true)? {
                    for birth in self.birth_marks(&frame)? {
                        if !birth.carried {
                            ledger.merge(birth.mark)?;
                        }
                    }
                    for mark in self.replayed_births(frame.id()?).await? {
                        ledger.merge(mark)?;
                    }
                }
            }
            if records.len() < 256 {
                return Ok(ledger);
            }
        }
    }
    pub(super) async fn replace_ledger(
        &self,
        scope: ResourceScope,
        ledger: IdentityLedger,
    ) -> Result<(), Error> {
        let marks = ledger.into_marks();
        // An unchanged ledger writes nothing, so in-place switches stay row-free.
        if self.ledger_marks(scope).await? == marks {
            return Ok(());
        }
        self.conn
            .execute(
                "DELETE FROM secure_identity_ledger WHERE scope=?",
                [encode(&scope)?],
            )
            .await?;
        for mark in marks {
            self.fold_ledger(scope, &mark).await?;
        }
        Ok(())
    }
    /// Without the scope's keys its suffix cannot be read: L is dropped and
    /// the scope queued, so it waits until a keyed open or rebuild reseeds it.
    pub(super) async fn reseed_ledger(&self, scope: ResourceScope, id: i64) -> Result<(), Error> {
        if !self.ledger_readable(scope) {
            self.replace_ledger(scope, IdentityLedger::default())
                .await?;
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO secure_rebuild_scopes VALUES(?)",
                    [encode(&scope)?],
                )
                .await?;
            return Ok(());
        }
        self.replace_ledger(scope, self.recomputed_ledger(scope, id).await?)
            .await
    }
    fn ledger_readable(&self, scope: ResourceScope) -> bool {
        self.opening_keys().any(|key| key.scope == scope)
    }
    async fn ledger_queued(&self, scope: ResourceScope) -> Result<bool, Error> {
        Ok(!collect_rows(
            self.conn
                .query(
                    "SELECT 1 FROM secure_rebuild_scopes WHERE scope=?",
                    [encode(&scope)?],
                )
                .await?,
        )
        .await?
        .is_empty())
    }
    /// Includes removed-table and off-custody scopes that readiness omits.
    pub(super) async fn reseed_domain_ledgers(
        &self,
        domain: rocky_core::Scope,
    ) -> Result<(), Error> {
        for record in rows(&self.conn, "SELECT id,scope FROM secure_scope_state").await? {
            let [SqlValue::Integer(id), SqlValue::Blob(scope)] = record.as_slice() else {
                return Err(Error::Corrupt("identity ledger scope".into()));
            };
            let scope: ResourceScope = decode(scope)?;
            if scope.domain == domain {
                self.reseed_ledger(scope, *id).await?;
            }
        }
        Ok(())
    }
    pub(super) async fn verify_identity_ledgers(&self) -> Result<(), Error> {
        if !rows(&self.conn, "SELECT 1 FROM secure_identity_own o LEFT JOIN secure_identity_marks p ON p.scope=o.scope AND p.author=o.author WHERE p.author IS NULL OR o.sequence<0 OR o.sequence>p.sequence OR EXISTS(SELECT 1 FROM secure_identity_tables t JOIN secure_identity_partitions b ON b.allocation=t.id WHERE t.scope=o.scope AND b.scope<>o.scope) LIMIT 1").await?.is_empty() {
            return Err(Error::Corrupt("own-birth floor exceeds permanent marks or names a template scope".into()));
        }
        if !rows(&self.conn, "SELECT 1 FROM secure_identity_ledger l LEFT JOIN secure_identity_marks p ON p.scope=l.scope AND p.author=l.author LEFT JOIN secure_identity_own o ON o.scope=l.scope AND o.author=l.author LEFT JOIN secure_scope_state s ON s.scope=l.scope WHERE s.id IS NULL OR p.author IS NULL OR o.author IS NULL OR l.sequence<0 OR l.sequence>o.sequence OR l.sequence>p.sequence OR l.signer<>p.signer LIMIT 1").await?.is_empty() {
            return Err(Error::Corrupt("identity ledger exceeds its permanent marks or scope".into()));
        }
        if !rows(&self.conn, "SELECT 1 FROM secure_identity_summary s LEFT JOIN secure_identity_own o ON o.scope=s.scope AND o.author=s.author WHERE o.author IS NULL OR s.sequence<0 OR s.sequence>o.sequence OR EXISTS(SELECT 1 FROM secure_identity_tables t JOIN secure_identity_partitions b ON b.allocation=t.id WHERE t.scope=s.scope AND b.scope<>s.scope) LIMIT 1").await?.is_empty() {
            return Err(Error::Corrupt("identity summary exceeds permanent marks or names a template scope".into()));
        }
        for record in rows(&self.conn, "SELECT id,scope FROM secure_scope_state").await? {
            let [SqlValue::Integer(id), SqlValue::Blob(scope)] = record.as_slice() else {
                return Err(Error::Corrupt("identity ledger scope".into()));
            };
            let scope: ResourceScope = decode(scope)?;
            let permanent = self.identity_marks(scope).await?;
            let ledger = self.ledger_marks(scope).await?;
            // A queued scope reseeds before use; a keyless one cannot be replayed.
            let queued = self.ledger_queued(scope).await?;
            if (queued && !ledger.is_empty())
                || (!queued
                    && self.ledger_readable(scope)
                    && ledger != self.recomputed_ledger(scope, *id).await?.into_marks())
                || ledger.iter().any(|mark| {
                    !permanent.iter().any(|held| {
                        held.author == mark.author
                            && held.signer == mark.signer
                            && held.sequence >= mark.sequence
                    })
                })
                || self
                    .summary_marks(scope)
                    .await?
                    .iter()
                    .any(|(author, sequence)| {
                        !permanent
                            .iter()
                            .any(|held| held.author == *author && held.sequence >= *sequence)
                    })
            {
                return Err(Error::Corrupt(
                    "identity ledger or summary differs from its history".into(),
                ));
            }
        }
        Ok(())
    }
    /// The persisted replay ledger L of `scope`.
    pub(super) async fn ledger_marks(
        &self,
        scope: ResourceScope,
    ) -> Result<Vec<checkpoint::IdentityMark>, Error> {
        self.marks_in("secure_identity_ledger", scope).await
    }
    /// The summary floor S of `scope`, per author.
    pub(super) async fn summary_marks(
        &self,
        scope: ResourceScope,
    ) -> Result<BTreeMap<u32, u32>, Error> {
        self.sequence_marks("secure_identity_summary", scope).await
    }
    pub(super) async fn own_marks(
        &self,
        scope: ResourceScope,
    ) -> Result<BTreeMap<u32, u32>, Error> {
        self.sequence_marks("secure_identity_own", scope).await
    }
    async fn sequence_marks(
        &self,
        table: &str,
        scope: ResourceScope,
    ) -> Result<BTreeMap<u32, u32>, Error> {
        let records = collect_rows(
            self.conn
                .query(
                    format!("SELECT author,sequence FROM {table} WHERE scope=?"),
                    [encode(&scope)?],
                )
                .await?,
        )
        .await?;
        records
            .into_iter()
            .map(|row| match row.as_slice() {
                [SqlValue::Integer(author), SqlValue::Integer(sequence)] => Ok((
                    u32::try_from(*author).map_err(|_| Error::Corrupt("summary author".into()))?,
                    u32::try_from(*sequence)
                        .map_err(|_| Error::Corrupt("summary sequence".into()))?,
                )),
                _ => Err(Error::Corrupt("summary mark".into())),
            })
            .collect()
    }
    /// The identities `frame` creates: each write without a before image
    /// that names a row identity, signed by its carried proof's stamp author
    /// or else the frame author. Writes are read through the installed
    /// schema's fields, whatever schema signed them.
    pub(super) fn birth_marks(&self, frame: &EncryptedFrame) -> Result<Vec<BirthMark>, Error> {
        let payload = self.row_payload(frame)?;
        self.payload_birth_marks(frame, &payload)
    }
    pub(super) fn payload_birth_marks(
        &self,
        frame: &EncryptedFrame,
        payload: &RowPayload,
    ) -> Result<Vec<BirthMark>, Error> {
        let operation = frame.operation_ref()?;
        let mut marks = Vec::new();
        for write in payload.writes() {
            if !self.tables.contains(&write.change.scope.table) {
                continue;
            }
            let mut write = write.clone();
            for fields in [&mut write.change.before, &mut write.change.after]
                .into_iter()
                .flatten()
            {
                fields.retain(|field, _| self.fields.contains(field));
            }
            if write.change.before.is_none()
                && let Some(identity) = self
                    .app
                    .row_identity(&write.change)
                    .map_err(|message| denied(&message))?
            {
                marks.push(BirthMark {
                    carried: payload.carried(&write.change.row).is_some(),
                    mark: checkpoint::IdentityMark {
                        author: identity.author(),
                        signer: match payload.carried(&write.change.row) {
                            Some(carried) => carried.proof.signer()?,
                            None => operation.header.public_key,
                        },
                        sequence: identity.sequence(),
                    },
                });
            }
        }
        Ok(marks)
    }
    /// The identity marks a checkpoint at `frontier` signs: `previous` merged
    /// with the births of the scope's applied or consumed operations the
    /// frontier covers, never the live maxima of later writes. None when a
    /// covered operation is no longer retained.
    pub(super) async fn covered_identity_marks(
        &self,
        id: i64,
        previous: &[checkpoint::CoveredMark],
        frontier: &BTreeMap<PublicKey, LogPosition>,
    ) -> Result<Option<Vec<checkpoint::CoveredMark>>, Error> {
        let mut marks = IdentityLedger::default();
        for mark in previous {
            marks.merge(mark.mark())?;
        }
        let mut own = IdentityLedger::based(previous)?;
        let mut after = 0i64;
        loop {
            let records = collect_rows(
                self.conn
                    .query(
                        "SELECT a.position,o.header,o.body FROM secure_applied a LEFT JOIN secure_operations o ON o.hash=a.hash WHERE a.scope=? AND a.position>? ORDER BY a.position LIMIT 256",
                        [id, after],
                    )
                    .await?,
            )
            .await?;
            for record in &records {
                let (position, header, body) = match record.as_slice() {
                    [
                        SqlValue::Integer(position),
                        SqlValue::Blob(header),
                        SqlValue::Blob(body),
                    ] => (*position, header, body),
                    [SqlValue::Integer(_), SqlValue::Null, SqlValue::Null] => return Ok(None),
                    _ => return Err(Error::Corrupt("covered operation".into())),
                };
                after = position;
                let decoded: p2panda_core::Header<Extensions> = decode(header)?;
                if frontier
                    .get(&decoded.public_key)
                    .is_none_or(|log| log.sequence < decoded.seq_num)
                {
                    continue;
                }
                let frame = self.chained_frame(header.clone(), body.clone()).await?;
                let Ok(births) = self.birth_marks(&frame) else {
                    return Ok(None);
                };
                for birth in births {
                    if !birth.carried {
                        own.merge(birth.mark.clone())?;
                    }
                    marks.merge(birth.mark)?;
                }
                // A replayed member's own births, as its replay recorded them.
                for mark in self.replayed_births(frame.id()?).await? {
                    own.merge(mark.clone())?;
                    marks.merge(mark)?;
                }
            }
            if records.len() < 256 {
                break;
            }
        }
        Ok(Some(
            marks
                .into_marks()
                .into_iter()
                .map(|mark| checkpoint::CoveredMark {
                    own: own.get(mark.author).map_or(0, |own| own.sequence),
                    author: mark.author,
                    signer: mark.signer,
                    sequence: mark.sequence,
                })
                .collect(),
        ))
    }
    async fn replayed_births(&self, hash: Hash) -> Result<Vec<checkpoint::IdentityMark>, Error> {
        match collect_rows(
            self.conn
                .query(
                    "SELECT births FROM secure_replayed WHERE hash=? AND births IS NOT NULL",
                    [hash.as_bytes().to_vec()],
                )
                .await?,
        )
        .await?
        .first()
        .map(Vec::as_slice)
        {
            Some([SqlValue::Blob(births)]) => decode(births),
            Some(_) => Err(Error::Corrupt("replayed births".into())),
            None => Ok(Vec::new()),
        }
    }
    /// The identity marks of scope `id`'s state through applied position
    /// `through`, as a kept seal's replay starts from: a verified signed
    /// base at or before it, else nothing with complete history, then every
    /// retained applied birth up to it, retired and consumed ones included.
    /// None when that prefix is no longer retained.
    pub(super) async fn prefix_identity_ledger(
        &self,
        scope: ResourceScope,
        id: i64,
        through: i64,
    ) -> Result<Option<IdentityLedger>, Error> {
        let base = self
            .checkpoint_record(id, true)
            .await?
            .filter(|record| record.position <= through);
        let (mut after, mut ledger) = match base {
            Some(record) => {
                let signed = self.verify_record(scope, &record)?;
                (
                    record.position,
                    IdentityLedger::based(&signed.statement.identities)?,
                )
            }
            None if self.has_pruned_prefix(scope).await? => return Ok(None),
            None => (0, IdentityLedger::default()),
        };
        loop {
            let records = collect_rows(
                self.conn
                    .query(
                        "SELECT a.position,o.header,o.body,o.status FROM secure_applied a LEFT JOIN secure_operations o ON o.hash=a.hash WHERE a.scope=? AND a.position>? AND a.position<=? ORDER BY a.position LIMIT 256",
                        [id, after, through],
                    )
                    .await?,
            )
            .await?;
            for record in &records {
                let (position, header, body, status) = match record.as_slice() {
                    [
                        SqlValue::Integer(position),
                        SqlValue::Blob(header),
                        SqlValue::Blob(body),
                        SqlValue::Text(status),
                    ] => (*position, header, body, status),
                    [
                        SqlValue::Integer(_),
                        SqlValue::Null,
                        SqlValue::Null,
                        SqlValue::Null,
                    ] => return Ok(None),
                    _ => return Err(Error::Corrupt("covered operation".into())),
                };
                after = position;
                let frame = self.chained_frame(header.clone(), body.clone()).await?;
                if !self.replay_eligible(status, frame.operation_ref()?, true)? {
                    continue;
                }
                for birth in self.birth_marks(&frame)? {
                    if !birth.carried {
                        ledger.merge(birth.mark)?;
                    }
                }
                for mark in self.replayed_births(frame.id()?).await? {
                    ledger.merge(mark)?;
                }
            }
            if records.len() < 256 {
                return Ok(Some(ledger));
            }
        }
    }
    /// Refuses to sign rows whose identity no covered mark reaches: the
    /// importer's check, run before signing.
    pub(super) async fn check_covered_identities(
        &self,
        rows: &str,
        id: i64,
        marks: &[checkpoint::CoveredMark],
    ) -> Result<(), Error> {
        let mut after = Vec::new();
        loop {
            let records = collect_rows(
                self.conn
                    .query(
                        format!("SELECT row,fields FROM {rows} WHERE scope=? AND row>? ORDER BY row LIMIT 256"),
                        bindings(vec![SqlValue::Integer(id), SqlValue::Blob(after.clone())]),
                    )
                    .await?,
            )
            .await?;
            for record in &records {
                let [SqlValue::Blob(row), SqlValue::Blob(fields)] = record.as_slice() else {
                    return Err(Error::Corrupt("checkpoint row".into()));
                };
                after = row.clone();
                let record = self.decode_record(fields).await?;
                if let Some(identity) = record.identity {
                    let identity = rocky_core::RowIdentity::from_integer(identity)
                        .map_err(|error| Error::Corrupt(error.to_string()))?;
                    if !marks.iter().any(|mark| {
                        mark.author == identity.author()
                            && mark.sequence >= identity.sequence()
                            && (record.moved_from.is_some() || mark.own >= identity.sequence())
                    }) {
                        return Err(Error::Corrupt(
                            "checkpoint row identity exceeds its covered mark".into(),
                        ));
                    }
                }
            }
            if records.len() < 256 {
                return Ok(());
            }
        }
    }
}

// Checkpoint row identities use the same canonical string boundary as callers.
pub(super) mod decimal {
    use serde::{Deserialize, Serialize};
    pub fn serialize<S: serde::Serializer>(
        identity: &Option<i64>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        identity
            .map(rocky_core::RowIdentity::from_integer)
            .transpose()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<i64>, D::Error> {
        Ok(
            Option::<rocky_core::RowIdentity>::deserialize(deserializer)?
                .map(rocky_core::RowIdentity::integer),
        )
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// Test access: the `(author, sequence)` marks a replay of kept `seal`
    /// starts from, or None when that prefix is unavailable.
    #[cfg(test)]
    pub(crate) async fn kept_prefix_marks(
        &self,
        scope: ResourceScope,
        seal: Commitment,
    ) -> Option<Vec<(u32, u32)>> {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        let id = inner.find_scope_id(scope).await.unwrap()?;
        let (_, bound) = inner.kept_rewind(seal).await.unwrap()?.at(id)?;
        inner
            .prefix_identity_ledger(scope, id, bound)
            .await
            .unwrap()
            .map(|ledger| {
                ledger
                    .into_marks()
                    .into_iter()
                    .map(|mark| (mark.author, mark.sequence))
                    .collect()
            })
    }
}

/// The lookup digest `secure_row_keys` holds for a business key.
pub(super) fn key_digest(key: &[u8]) -> Vec<u8> {
    key[..key.len().min(16)].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_covered_mark_seeds_only_own_births_and_requires_the_signed_own_field() {
        let key = PrivateKey::from_bytes(&[221; 32]).public_key();
        let marks = [
            checkpoint::CoveredMark {
                author: 7,
                signer: key,
                sequence: 9,
                own: 3,
            },
            checkpoint::CoveredMark {
                author: 8,
                signer: key,
                sequence: 8,
                own: 0,
            },
        ];
        let ledger = IdentityLedger::based(&marks).unwrap();
        assert_eq!(ledger.get(7).unwrap().sequence, 3);
        assert!(ledger.get(8).is_none());
        let mut unsigned_own = serde_json::to_value(&marks[0]).unwrap();
        unsigned_own.as_object_mut().unwrap().remove("own");
        assert!(serde_json::from_value::<checkpoint::CoveredMark>(unsigned_own).is_err());
    }

    #[test]
    fn an_identity_author_with_two_signers_fails_closed() {
        let (one, two) = (PrivateKey::new(), PrivateKey::new());
        let mark = |key: &PrivateKey, sequence| checkpoint::IdentityMark {
            author: 7,
            signer: key.public_key(),
            sequence,
        };
        assert!(IdentityLedger::seeded(&[mark(&one, 3), mark(&two, 1)]).is_err());
        let mut ledger = IdentityLedger::seeded(&[mark(&one, 3)]).unwrap();
        assert!(ledger.merge(mark(&two, 9)).is_err());
        ledger.merge(mark(&one, 2)).unwrap();
        assert_eq!(ledger.get(7).unwrap().sequence, 3);
    }
}
