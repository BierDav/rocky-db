//! Replay of received intents. A partition's transactions run in canonical
//! stamp order, each in its own savepoint; one whose statements fail or
//! whose effects its author may not write is dropped with its reason. An
//! arrival ordered before applied transactions rewinds them through their
//! undo records, applies, then redoes them. A seal ends rewinds behind it.
//! Order is `(era, stamp)`: a transaction a finalized seal leaves out
//! moves to the next era, after every transaction the seal covers.
use super::*;
use rocky_core::TableClass;
use rocky_core::replay::{DropReason, Intent, TransactionOutcome};
use rocky_storage::partition_sql::{TablePartitions, split_intent};

mod base;
mod constraints;
pub(crate) mod outcomes;
mod rebuild;
pub(super) use base::{SCHEMA as BASE_SCHEMA, add_row, base_sets};
pub(super) use constraints::{
    Written, cascades, check_member_order, checked, linked, note, written,
};

pub(super) const SCHEMA: &[&str] = &[
    // `violated` names the constraint or assertion a `constraint` drop broke;
    // `births` the identities an applied member created, for checkpoints.
    "CREATE TABLE IF NOT EXISTS secure_replayed(scope INTEGER NOT NULL,era INTEGER NOT NULL,clock INTEGER NOT NULL,author INTEGER NOT NULL,sequence INTEGER NOT NULL,hash BLOB NOT NULL UNIQUE,txn BLOB NOT NULL,member INTEGER NOT NULL,members INTEGER NOT NULL,dropped TEXT,sealed INTEGER NOT NULL,undo BLOB,violated TEXT,births BLOB,PRIMARY KEY(scope,era,clock,author,sequence)) WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS secure_replayed_txn ON secure_replayed(txn)",
];

/// A row as it stood before a replayed transaction changed it. An applied,
/// unsealed member keeps these until a seal covers it; they never leave
/// the device.
pub(super) struct Undo {
    pub(super) table: String,
    pub(super) key: Vec<SqlValue>,
    pub(super) before: Option<Vec<SqlValue>>,
}

/// What one member's replay changed: the rows' prior images, the
/// identities of the rows it created and the partitions it wrote.
pub(super) struct Replayed {
    undo: Vec<Undo>,
    births: Vec<checkpoint::IdentityMark>,
    written: Vec<Written>,
}

/// Why a transaction dropped, and for `Constraint` what it violated.
pub(super) struct Dropped {
    pub(super) reason: DropReason,
    pub(super) violated: Option<String>,
}
impl From<DropReason> for Dropped {
    fn from(reason: DropReason) -> Self {
        Self {
            reason,
            violated: None,
        }
    }
}

/// A partition's replay position: the era, then the stamp.
pub(super) type Order = (i64, Stamp);

/// A rewound transaction's members here, to redo in canonical order.
struct Redo {
    transaction: Commitment,
    members: Vec<(Hash, u16)>,
    /// Where its earliest member stood.
    order: Order,
}

/// One held intent member of a transaction: its frame, statements, its
/// author's grants and its member index.
pub(super) type Replaying<'a> = (
    &'a EncryptedFrame,
    &'a Intent,
    &'a [rocky_core::ResourceGrant],
    u16,
);

fn values_blob(values: &[SqlValue]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in values {
        value.encode(&mut bytes);
    }
    bytes
}

fn blob_values(mut bytes: &[u8]) -> Result<Vec<SqlValue>, Error> {
    let mut values = Vec::new();
    while !bytes.is_empty() {
        values
            .push(SqlValue::decode(&mut bytes).map_err(|_| Error::Corrupt("undo record".into()))?);
    }
    Ok(values)
}

/// A member's undo column: `NULL` when it changed nothing.
pub(super) fn undo_blob(undo: &[Undo]) -> Result<SqlValue, Error> {
    if undo.is_empty() {
        return Ok(SqlValue::Null);
    }
    let rows: Vec<_> = undo
        .iter()
        .map(|undo| {
            (
                undo.table.as_str(),
                serde_bytes::ByteBuf::from(values_blob(&undo.key)),
                undo.before
                    .as_deref()
                    .map(|before| serde_bytes::ByteBuf::from(values_blob(before))),
            )
        })
        .collect();
    Ok(SqlValue::Blob(encode(&rows)?))
}

pub(super) fn undo_of(bytes: &[u8]) -> Result<Vec<Undo>, Error> {
    let rows: Vec<(String, serde_bytes::ByteBuf, Option<serde_bytes::ByteBuf>)> =
        decode_bounded(bytes, usize::MAX)?;
    rows.into_iter()
        .map(|(table, key, before)| {
            Ok(Undo {
                table,
                key: blob_values(&key)?,
                before: before.map(|before| blob_values(&before)).transpose()?,
            })
        })
        .collect()
}

/// A row's leading `era,clock,author,sequence`.
fn order_of(row: &[SqlValue]) -> Result<Order, Error> {
    match row {
        [
            SqlValue::Integer(era),
            SqlValue::Integer(clock),
            SqlValue::Integer(author),
            SqlValue::Integer(sequence),
            ..,
        ] => Ok((
            *era,
            Stamp {
                clock: *clock as u64,
                author: *author as u32,
                sequence: *sequence as u64,
            },
        )),
        _ => Err(Error::Corrupt("replayed order".into())),
    }
}

fn order_bindings(scope: i64, (era, stamp): &Order) -> Vec<SqlValue> {
    vec![
        SqlValue::Integer(scope),
        SqlValue::Integer(*era),
        SqlValue::Integer(stamp.clock as i64),
        SqlValue::Integer(i64::from(stamp.author)),
        SqlValue::Integer(stamp.sequence as i64),
    ]
}

/// The era an arrival joins: one past the domain's last finalized seal.
const OPEN_ERA: &str = "(SELECT COALESCE(MAX(depth),0) FROM secure_finalized WHERE domain=?)";

/// Why an arrival waits: a transaction it rewinds has a member in a
/// partition whose key this replica does not hold yet.
pub(super) const KEY_WAITS: &str = "a rewound transaction waits for its partition key";

/// Events one replayed transaction may capture.
const REPLAY_CAPTURE: (usize, usize) = (MAX_BUNDLE_ROWS, MAX_BUNDLE_BYTES);

/// A frame's canonical position in its partition.
pub(super) fn stamp(header: &p2panda_core::Header<Extensions>) -> Stamp {
    Stamp {
        clock: header.timestamp,
        author: header.extensions.author.unwrap_or(0),
        sequence: header.extensions.author_sequence,
    }
}

fn reason_name(reason: DropReason) -> &'static str {
    match reason {
        DropReason::Constraint => "constraint",
        DropReason::Admission => "admission",
        DropReason::Schema => "schema",
        DropReason::Engine => "engine",
    }
}

/// Unsealed replayed transactions at which an owner seals routinely. This
/// does not cap a rewind: it covers every unsealed transaction its closure
/// reaches, more while no owner seals.
pub const ROUTINE_SEAL_TRANSACTIONS: u64 = 128;

impl<A: RowApplication> EncryptedReplica<A> {
    /// Replayed transactions no seal covers yet: what an early arrival may
    /// rewind.
    pub async fn unsealed_replayed_transactions(&self) -> Result<u64, Error> {
        let inner = self.inner.lock(Class::Background).await;
        let rows = collect_rows(
            inner
                .conn
                .query(
                    "SELECT COUNT(DISTINCT txn) FROM secure_replayed WHERE sealed=0",
                    (),
                )
                .await?,
        )
        .await?;
        match rows.first().map(Vec::as_slice) {
            Some([SqlValue::Integer(count)]) => Ok(*count as u64),
            _ => Err(Error::Corrupt("unsealed replayed count".into())),
        }
    }

    /// The identity of the transaction this replica committed under
    /// `handle`, as outcomes and observers name it.
    pub async fn transaction_of(&self, handle: Commitment) -> Commitment {
        let inner = self.inner.lock(Class::Interactive).await;
        super::bundle::transaction_id(inner.config.node.public_key(), &handle)
    }

    /// The constraint or assertion whose violation dropped `transaction`
    /// here, as SQLite or the assertion names it.
    pub async fn transaction_violation(
        &self,
        transaction: Commitment,
    ) -> Result<Option<String>, Error> {
        let inner = self.inner.lock(Class::Interactive).await;
        let rows = collect_rows(
            inner
                .conn
                .query(
                    "SELECT violated FROM secure_replayed WHERE txn=? AND violated IS NOT NULL LIMIT 1",
                    [transaction.to_vec()],
                )
                .await?,
        )
        .await?;
        match rows.first().map(Vec::as_slice) {
            None => Ok(None),
            Some([SqlValue::Text(violated)]) => Ok(Some(violated.clone())),
            Some(_) => Err(Error::Corrupt("replayed violation".into())),
        }
    }

    /// How a transaction with replayed writes stands here: `None` until a
    /// member of it has replayed. A drop is final once a seal covers it.
    pub async fn transaction_outcome(
        &self,
        transaction: Commitment,
    ) -> Result<Option<TransactionOutcome>, Error> {
        let inner = self.inner.lock(Class::Interactive).await;
        let rows = collect_rows(
            inner
                .conn
                .query(
                    "SELECT dropped,sealed FROM secure_replayed WHERE txn=? ORDER BY dropped IS NULL,sealed LIMIT 1",
                    [transaction.to_vec()],
                )
                .await?,
        )
        .await?;
        rows.first()
            .map(|row| match row.as_slice() {
                [SqlValue::Null, _] => Ok(TransactionOutcome::Applied),
                [SqlValue::Text(name), SqlValue::Integer(sealed)] => {
                    Ok(TransactionOutcome::Dropped {
                        reason: reason_named(name)?,
                        sealed: *sealed != 0,
                    })
                }
                _ => Err(Error::Corrupt("replayed outcome".into())),
            })
            .transpose()
    }
}

#[cfg(test)]
impl<A: RowApplication> EncryptedReplica<A> {
    /// Seals everything `scope` applied so far, as a finalized seal would,
    /// inside one transaction as seal finalization runs it.
    pub(crate) async fn seal_replayed_for_test(&self, scope: ResourceScope) -> Result<(), Error> {
        let mut inner = self.inner.lock(Class::Background).await;
        let id = inner.find_scope_id(scope).await?.ok_or(Error::Closed)?;
        transaction!(inner, |inner| inner.seal_replayed(id, i64::MAX).await)
    }
}

fn reason_named(name: &str) -> Result<DropReason, Error> {
    Ok(match name {
        "constraint" => DropReason::Constraint,
        "admission" => DropReason::Admission,
        "schema" => DropReason::Schema,
        "engine" => DropReason::Engine,
        _ => return Err(Error::Corrupt("replayed drop reason".into())),
    })
}

impl<A: RowApplication> Inner<A> {
    /// The other stored scopes whose order can change `scope`'s outcomes:
    /// partitions of its linked tables holding the same partition values,
    /// or every partition when only one side is partitioned.
    async fn linked_scopes(&self, scope: i64) -> Result<Vec<i64>, Error> {
        let Some(typed) = self.workspace.typed.as_ref() else {
            return Ok(Vec::new());
        };
        let schema = typed.rows.schema();
        let links = schema
            .assertions
            .iter()
            .any(|assertion| assertion.tables().len() > 1)
            || schema
                .tables
                .iter()
                .any(|table| table.class == TableClass::Replayed && !table.foreign_keys.is_empty());
        if !links {
            return Ok(Vec::new());
        }
        let corrupt = || Error::Corrupt("replayed scope".into());
        let stored = collect_rows(
            self.conn
                .query("SELECT scope FROM secure_scope_state WHERE id=?", [scope])
                .await?,
        )
        .await?;
        let Some([SqlValue::Blob(blob)]) = stored.first().map(Vec::as_slice) else {
            return Err(corrupt());
        };
        let own: ResourceScope = decode(blob)?;
        let Some(logical) = typed
            .rows
            .table(&own.table)
            .and_then(|table| schema.table(&table.sql_name))
        else {
            return Ok(Vec::new());
        };
        let tables = linked(schema, &logical.sql_name);
        if tables.len() == 1 {
            return Ok(Vec::new());
        }
        let values = |logical, scope| {
            self.partitions
                .get(scope)
                .map(|tuple| super::partition::partition_values(schema, logical, tuple))
                .transpose()
        };
        let own_values = if logical.partition_by.is_empty() {
            None
        } else {
            values(logical, &own)?
        };
        let mut scopes = Vec::new();
        for name in tables
            .iter()
            .filter(|name| !name.eq_ignore_ascii_case(&logical.sql_name))
        {
            // A linked table this projection does not install has no rows
            // here to order.
            let (Some(projected), Some(other)) = (typed.by_name(name), schema.table(name)) else {
                continue;
            };
            if other.partition_by.is_empty() {
                scopes.push(projected.scope);
                continue;
            }
            for candidate in self.partitions.keys().filter(|candidate| {
                candidate.domain == projected.scope.domain
                    && candidate.table == projected.scope.table
            }) {
                if own_values.is_none() || values(other, candidate)? == own_values {
                    scopes.push(*candidate);
                }
            }
        }
        let mut ids = Vec::with_capacity(scopes.len());
        for scope in scopes {
            if let Some(id) = self.find_scope_id(scope).await? {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    /// Undoes every unsealed transaction ordered at or after `starts` in
    /// its partition and the partitions linked to it, and every
    /// transaction sharing a member with one, latest first. Returns them
    /// for redo in canonical order.
    async fn rewind(&self, starts: Vec<(i64, Order)>) -> Result<Vec<Redo>, Error> {
        let corrupt = || Error::Corrupt("replayed member".into());
        let mut work = starts;
        let mut rewound = BTreeMap::new();
        let mut visited = BTreeSet::new();
        let mut links: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
        while let Some((scope, from)) = work.pop() {
            if !visited.insert((scope, from.clone())) {
                continue;
            }
            if let std::collections::btree_map::Entry::Vacant(entry) = links.entry(scope) {
                entry.insert(self.linked_scopes(scope).await?);
            }
            for linked in links.get(&scope).into_iter().flatten() {
                work.push((*linked, from.clone()));
            }
            let later = collect_rows(
                self.conn
                    .query(
                        "SELECT era,clock,author,sequence,hash,txn,member,undo FROM secure_replayed WHERE scope=? AND sealed=0 AND (era,clock,author,sequence)>=(?,?,?,?)",
                        bindings(order_bindings(scope, &from)),
                    )
                    .await?,
            )
            .await?;
            for row in later {
                let order = order_of(&row)?;
                let [
                    ..,
                    SqlValue::Blob(hash),
                    SqlValue::Blob(txn),
                    SqlValue::Integer(member),
                    undo,
                ] = row.as_slice()
                else {
                    return Err(corrupt());
                };
                let hash = Hash::try_from(hash.as_slice()).map_err(|_| corrupt())?;
                let transaction: Commitment = txn.as_slice().try_into().map_err(|_| corrupt())?;
                let undo = match undo {
                    SqlValue::Null => Vec::new(),
                    SqlValue::Blob(undo) => undo_of(undo)?,
                    _ => return Err(corrupt()),
                };
                if rewound
                    .insert((order, scope), (hash, transaction, *member as u16, undo))
                    .is_some()
                {
                    continue;
                }
                // Its other members rewind with it, and what follows them.
                for other in collect_rows(
                    self.conn
                        .query(
                            "SELECT era,clock,author,sequence,scope FROM secure_replayed WHERE txn=? AND sealed=0",
                            [transaction.to_vec()],
                        )
                        .await?,
                )
                .await?
                {
                    let [.., SqlValue::Integer(other_scope)] = other.as_slice() else {
                        return Err(corrupt());
                    };
                    let order = order_of(&other)?;
                    if !rewound.contains_key(&(order.clone(), *other_scope)) {
                        work.push((*other_scope, order));
                    }
                }
            }
        }
        for (hash, _, _, undo) in rewound.values().rev() {
            self.undo(undo).await?;
            self.conn
                .execute(
                    "DELETE FROM secure_replayed WHERE hash=?",
                    [hash.as_bytes().to_vec()],
                )
                .await?;
            #[cfg(any(test, feature = "qualification"))]
            self.crash_at(|point| point == CrashPoint::Rewind)?;
        }
        // Their births are made again when they redo.
        let scopes: BTreeSet<i64> = rewound.keys().map(|(_, scope)| *scope).collect();
        for id in scopes {
            let based = self
                .checkpoint_record(id, true)
                .await?
                .and_then(|record| record.signed)
                .map(|signed| signed.statement.identities)
                .unwrap_or_default();
            self.reset_replay_ledger(id, &based).await?;
        }
        let mut redo: Vec<Redo> = Vec::new();
        for ((order, _), (hash, transaction, member, _)) in rewound {
            match redo.iter_mut().find(|redo| redo.transaction == transaction) {
                Some(redo) => redo.members.push((hash, member)),
                None => redo.push(Redo {
                    transaction,
                    members: vec![(hash, member)],
                    order,
                }),
            }
        }
        Ok(redo)
    }

    /// Restores the rows one member changed to their state before it.
    async fn undo(&self, undo: &[Undo]) -> Result<(), Error> {
        if undo.is_empty() {
            return Ok(());
        }
        let corrupt = || Error::Corrupt("undo record".into());
        let typed = self.workspace.typed.as_ref().ok_or_else(corrupt)?;
        let mut tables = Vec::with_capacity(undo.len());
        for undo in undo {
            let projected = typed.by_name(&undo.table).ok_or_else(corrupt)?;
            tables.push(
                typed
                    .plan(&BTreeSet::from([projected.scope]))?
                    .tables
                    .into_iter()
                    .find(|table| table.name.eq_ignore_ascii_case(&undo.table))
                    .ok_or_else(corrupt)?,
            );
        }
        // References settle at commit. Rows the member created go first, so
        // a restored image never collides with one of them.
        self.conn
            .execute("PRAGMA defer_foreign_keys=ON", ())
            .await?;
        for (table, undo) in tables.iter().zip(undo) {
            self.touch(&table.name);
            if undo.before.is_none() {
                self.conn
                    .execute(&table.delete_by_key(), bindings(undo.key.clone()))
                    .await?;
            }
        }
        // A row that stands is set back in place: deleting it would run its
        // delete actions on rows outside this undo.
        let mut collided = Vec::new();
        for (table, undo) in tables.iter().zip(undo) {
            let Some(before) = &undo.before else {
                continue;
            };
            let mut values = table.stored(before);
            values.extend(undo.key.iter().cloned());
            let restored = match self
                .conn
                .execute(&table.update_image(), bindings(values))
                .await
            {
                Ok(0) => {
                    self.conn
                        .execute(&table.insert_image(), bindings(table.stored(before)))
                        .await
                }
                other => other,
            };
            match restored {
                Ok(_) => {}
                Err(error) if error.is_constraint() => collided.push((table, undo, before)),
                Err(error) => return Err(error.into()),
            }
        }
        // Rows that held each other's unique values, as after a swap.
        for (table, undo, _) in &collided {
            self.conn
                .execute(&table.delete_by_key(), bindings(undo.key.clone()))
                .await?;
        }
        for (table, _, before) in &collided {
            self.conn
                .execute(&table.insert_image(), bindings(table.stored(before)))
                .await?;
        }
        self.conn
            .execute("PRAGMA defer_foreign_keys=OFF", ())
            .await?;
        Ok(())
    }

    /// Rebuilds the replayed `tables` of a schema switch from their live
    /// rows, which are their only copy: columns both schemas name keep their
    /// values unless a tip on the switch's `path` lacks them, new ones take
    /// their defaults. Inside the switch transaction. Every old table is
    /// renamed before any new one exists: SQLite rewrites references to a
    /// renamed table, so the old tables only name each other.
    pub(super) async fn rebuild_replayed(
        &self,
        installed: &rocky_core::LogicalSchema,
        schema: &rocky_core::LogicalSchema,
        tables: &[&rocky_core::LogicalTable],
        path: Option<&super::schemas::PathFields>,
    ) -> Result<(), Error> {
        let old = |name: &str| typed::quoted(&format!("secure_rebuild_{name}"));
        let mut copies = Vec::new();
        for table in tables {
            let name = &table.sql_name;
            // A table of the installed schema this projection never created
            // starts empty.
            let created = !rows(
                &self.conn,
                &format!(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='{}'",
                    name.replace('\'', "''")
                ),
            )
            .await?
            .is_empty();
            let Some(before) = installed.table(name).filter(|_| created) else {
                continue;
            };
            let on_path = |column: &rocky_core::LogicalColumn| {
                path.is_none_or(|path| {
                    path.tables.contains(&schema.table_id(table))
                        && path.fields.contains(&schema.field_id(table, column))
                })
            };
            let kept: Vec<String> = before
                .columns
                .iter()
                .filter(|column| {
                    table.column(&column.sql_name).is_some_and(|kept| {
                        !matches!(kept.class, rocky_core::ColumnClass::Derived { .. })
                            && on_path(kept)
                    })
                })
                .map(|column| typed::quoted(&column.sql_name))
                .collect();
            self.conn
                .execute(
                    format!("ALTER TABLE {} RENAME TO {}", typed::quoted(name), old(name)),
                    (),
                )
                .await?;
            copies.push((*table, before, kept));
        }
        for table in tables {
            self.conn.execute(table.create_sql.clone(), ()).await?;
        }
        self.conn
            .execute("PRAGMA defer_foreign_keys=ON", ())
            .await?;
        for (table, _, kept) in &copies {
            if !kept.is_empty() {
                self.conn
                    .execute(
                        format!(
                            "INSERT INTO {}({columns}) SELECT {columns} FROM {}",
                            typed::quoted(&table.sql_name),
                            old(&table.sql_name),
                            columns = kept.join(",")
                        ),
                        (),
                    )
                    .await?;
            }
        }
        // Children first, so that no old row is left referencing a dropped
        // parent.
        let mut left: Vec<_> = copies.iter().map(|(_, before, _)| *before).collect();
        while !left.is_empty() {
            let leaf = left
                .iter()
                .position(|table| {
                    !left.iter().any(|child| {
                        child.sql_name != table.sql_name
                            && child
                                .foreign_keys
                                .iter()
                                .any(|key| key.table.eq_ignore_ascii_case(&table.sql_name))
                    })
                })
                .unwrap_or(0);
            let table = left.remove(leaf);
            self.conn
                .execute(format!("DROP TABLE {}", old(&table.sql_name)), ())
                .await?;
        }
        self.conn
            .execute("PRAGMA defer_foreign_keys=OFF", ())
            .await?;
        for table in tables {
            for index in &table.indexes {
                self.conn.execute(index.create_sql.clone(), ()).await?;
            }
            self.touch(&table.sql_name);
        }
        Ok(())
    }

    /// Rewrites the undo images of replayed tables whose columns a schema
    /// switch changed into the new column order, so that a rewind across
    /// the switch restores rows the new tables can hold.
    pub(super) async fn reshape_undo(
        &self,
        before: &rocky_core::LogicalSchema,
        after: &rocky_core::LogicalSchema,
    ) -> Result<(), Error> {
        let mut changed = BTreeMap::new();
        for table in after
            .tables
            .iter()
            .filter(|table| table.class == TableClass::Replayed)
        {
            let Some(old) = before.table(&table.sql_name) else {
                continue;
            };
            let names = |table: &rocky_core::LogicalTable| -> Vec<String> {
                table
                    .columns
                    .iter()
                    .map(|column| column.sql_name.to_ascii_lowercase())
                    .collect()
            };
            if names(old) == names(table) {
                continue;
            }
            let sources: Vec<Result<usize, SqlValue>> = table
                .columns
                .iter()
                .map(|column| {
                    old.columns
                        .iter()
                        .position(|o| o.sql_name.eq_ignore_ascii_case(&column.sql_name))
                        .ok_or_else(|| rocky_core::default_value(column).unwrap_or(SqlValue::Null))
                })
                .collect();
            changed.insert(table.sql_name.to_ascii_lowercase(), sources);
        }
        // A removed table's rows are gone: a rewind restores none of them.
        let removed: BTreeSet<String> = before
            .tables
            .iter()
            .filter(|table| {
                table.class == TableClass::Replayed && after.table(&table.sql_name).is_none()
            })
            .map(|table| table.sql_name.to_ascii_lowercase())
            .collect();
        if changed.is_empty() && removed.is_empty() {
            return Ok(());
        }
        let corrupt = || Error::Corrupt("undo record".into());
        for row in collect_rows(
            self.conn
                .query(
                    "SELECT hash,undo FROM secure_replayed WHERE sealed=0 AND undo IS NOT NULL",
                    (),
                )
                .await?,
        )
        .await?
        {
            let [SqlValue::Blob(hash), SqlValue::Blob(undo)] = row.as_slice() else {
                return Err(corrupt());
            };
            let mut undo = undo_of(undo)?;
            let kept = undo.len();
            undo.retain(|entry| !removed.contains(&entry.table.to_ascii_lowercase()));
            let mut touched = undo.len() != kept;
            for entry in &mut undo {
                let Some(sources) = changed.get(&entry.table.to_ascii_lowercase()) else {
                    continue;
                };
                if let Some(before) = &entry.before {
                    entry.before = Some(
                        sources
                            .iter()
                            .map(|source| match source {
                                Ok(index) => before.get(*index).cloned().ok_or_else(corrupt),
                                Err(default) => Ok(default.clone()),
                            })
                            .collect::<Result<_, _>>()?,
                    );
                    touched = true;
                }
            }
            if touched {
                self.conn
                    .execute(
                        "UPDATE secure_replayed SET undo=? WHERE hash=?",
                        bindings(vec![undo_blob(&undo)?, SqlValue::Blob(hash.clone())]),
                    )
                    .await?;
            }
        }
        Ok(())
    }

    /// Whether `scope` is a partition of a replayed table.
    pub(super) fn replayed_scope(&self, scope: ResourceScope) -> bool {
        self.workspace.typed.as_ref().is_some_and(|typed| {
            typed.by_scope(scope).is_some_and(|projected| {
                typed
                    .rows
                    .schema()
                    .table(&projected.table.sql_name)
                    .is_some_and(|table| table.class == TableClass::Replayed)
            })
        })
    }

    /// Whether the scope stored as `id` replayed exactly the transactions
    /// of the workspace's path after its base, so its rows are the path's
    /// state. A replayed scope keeps no row records to rebuild from.
    pub(super) async fn replayed_on_path(&self, id: i64) -> Result<bool, Error> {
        let dbg = self.checkpoint_record(id, true).await?;
        eprintln!("DBG on_path {id} record={:?} path={:?}", dbg.as_ref().map(|r| (r.position, r.signed.as_ref().map(|s| s.statement.seal))), self.workspace.typed.as_ref().map(|t| self.path_seals(t.domain).map(|p| p.iter().map(|k| k.id().ok()).collect::<Vec<_>>())));
        let floor = match self.checkpoint_record(id, true).await? {
            None => 0,
            Some(record) => {
                // A base at a seal the path leaves holds another line's rows.
                if let Some(seal) = record.signed.as_ref().and_then(|signed| signed.statement.seal)
                    && let Some(typed) = &self.workspace.typed
                    && !self
                        .path_seals(typed.domain)?
                        .iter()
                        .any(|known| known.id().ok() == Some(seal))
                {
                    return Ok(false);
                }
                record.position
            }
        };
        for record in collect_rows(
            self.conn
                .query(
                    "SELECT a.hash,r.hash IS NOT NULL FROM secure_applied a LEFT JOIN secure_replayed r ON r.hash=a.hash WHERE a.scope=? AND (r.hash IS NOT NULL OR a.position>?)",
                    [id, floor],
                )
                .await?,
        )
        .await?
        {
            let [SqlValue::Blob(hash), SqlValue::Integer(replayed)] = record.as_slice() else {
                return Err(Error::Corrupt("replayed transaction".into()));
            };
            let frame = self.frame(super::checkpoint::hash_of(hash)?).await?;
            let visible = match &frame {
                Some(frame) => {
                    self.visible_in_workspace(&frame.operation()?)?
                        && self.row_payload(frame)?.intent().is_some()
                }
                None => false,
            };
            eprintln!("DBG member {id} {:?} visible={visible} replayed={replayed}", &hash[..4]);
            if visible != (*replayed != 0) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// A seal finalized at depth `era` leaves out the unsealed transactions
    /// applied after each `(scope, through)` cut: they rewind, with what
    /// follows them, and redo in the new era, after every transaction the
    /// seal covers. Their identity and stamp stay; outcomes may change.
    /// A kept seal is marked once the live tables hold exactly its state,
    /// so its history records what the transactions behind it replace.
    pub(super) async fn order_behind_seal(
        &self,
        cuts: &[(i64, i64)],
        era: i64,
        time: u64,
        kept: Option<(Commitment, &[history::KeptBound])>,
    ) -> Result<(), Error> {
        let mark = async || match kept {
            Some((seal, bounds)) => self.mark_seal(seal, bounds).await,
            None => Ok(()),
        };
        let corrupt = || Error::Corrupt("replayed member".into());
        let mut starts = Vec::new();
        let mut moved = BTreeSet::new();
        for (scope, through) in cuts {
            let rows = collect_rows(
                self.conn
                    .query(
                        "SELECT era,clock,author,sequence,hash FROM secure_replayed WHERE scope=? AND sealed=0 AND era<? AND hash IN (SELECT hash FROM secure_applied WHERE scope=? AND position>?) ORDER BY era,clock,author,sequence",
                        [*scope, era, *scope, *through],
                    )
                    .await?,
            )
            .await?;
            if let Some(first) = rows.first() {
                starts.push((*scope, order_of(first)?));
            }
            for row in rows {
                let [.., SqlValue::Blob(hash)] = row.as_slice() else {
                    return Err(corrupt());
                };
                moved.insert(Hash::try_from(hash.as_slice()).map_err(|_| corrupt())?);
            }
        }
        if starts.is_empty() {
            return mark().await;
        }
        let mut redo = self.rewind(starts).await?;
        for redo in &mut redo {
            if redo.members.iter().any(|(hash, _)| moved.contains(hash)) {
                redo.order.0 = era;
            }
        }
        redo.sort_by(|a, b| a.order.cmp(&b.order));
        let behind = redo.partition_point(|redo| redo.order.0 < era);
        let later = redo.split_off(behind);
        self.redo(redo, time).await?;
        mark().await?;
        self.redo(later, time).await
    }

    /// A seal finalized `scope` through `through`: the transactions it
    /// covers never rewind again, their drops are final and their undo
    /// records go. One of several members stays open until a record names
    /// each of them.
    pub(super) async fn seal_replayed(&self, scope: i64, through: i64) -> Result<(), Error> {
        self.conn
            .execute(
                "UPDATE secure_replayed SET sealed=1,undo=NULL WHERE scope=? AND sealed=0 AND hash IN (SELECT hash FROM secure_applied WHERE scope=? AND position<=?) AND (members=1 OR members=(SELECT COUNT(*) FROM secure_outcome_members m WHERE m.txn=secure_replayed.txn))",
                [scope, scope, through],
            )
            .await?;
        #[cfg(any(test, feature = "qualification"))]
        self.crash_at(|point| point == CrashPoint::UndoDeletion)?;
        Ok(())
    }

    /// Replays one transaction's held intent members together: one that
    /// drops drops the transaction in every partition held here, and so
    /// does another replica's record of a member not held here. Records
    /// the outcome and, when it applied, the undo of each member; a
    /// transaction of several members gets this replica's record.
    async fn replay_transaction(
        &self,
        (transaction, members): (Commitment, u16),
        intents: &[Replaying<'_>],
        era: Option<i64>,
        time: u64,
    ) -> Result<(), Error> {
        if members > 1 {
            let held: Vec<u16> = intents.iter().map(|(.., member)| *member).collect();
            if let Some(reason) = self.remote_drop(transaction, &held).await? {
                for (frame, .., member) in intents {
                    self.record_replayed(
                        frame,
                        (transaction, *member, members),
                        Some(&reason.into()),
                        &[],
                        era,
                    )
                    .await?;
                }
                return Ok(());
            }
        }
        self.conn.execute("SAVEPOINT intents", ()).await?;
        // Members replay in scope order, not in the order the author ran
        // their statements: references between them settle at the end.
        let several = intents.len() > 1;
        if several {
            self.conn
                .execute("PRAGMA defer_foreign_keys=ON", ())
                .await?;
        }
        let mut replayed = Vec::with_capacity(intents.len());
        let mut dropped = None;
        for (frame, intent, grants, _) in intents {
            match self.replay_intent(frame, intent, grants)? {
                Ok(changed) => replayed.push(changed),
                Err(reason) => {
                    dropped = Some(reason);
                    break;
                }
            }
        }
        if dropped.is_none() {
            let mut written = Vec::new();
            for row in replayed.iter().flat_map(|replayed| &replayed.written) {
                note(&mut written, row.clone());
            }
            if let Some(violated) = self.replayed_violation(&written, several).await? {
                dropped = Some(Dropped {
                    reason: DropReason::Constraint,
                    violated: Some(violated),
                });
            }
        }
        if several {
            self.conn
                .execute("PRAGMA defer_foreign_keys=OFF", ())
                .await?;
        }
        if dropped.is_some() {
            self.conn.execute("ROLLBACK TO intents", ()).await?;
            replayed.clear();
        }
        self.conn.execute("RELEASE intents", ()).await?;
        for (index, (frame, _, _, member)) in intents.iter().enumerate() {
            let (undo, births) = replayed.get(index).map_or((&[][..], &[][..]), |replayed| {
                (replayed.undo.as_slice(), replayed.births.as_slice())
            });
            self.record_replayed(
                frame,
                (transaction, *member, members),
                dropped.as_ref(),
                undo,
                era,
            )
            .await?;
            // A created identity stays reserved, whatever later rewinds do.
            let scope = frame.scope()?;
            self.record_births(frame, births).await?;
            for birth in births {
                self.put_identity_mark(scope, birth, identity::Raise::Own)
                    .await?;
            }
            if dropped.is_none()
                && let Some(table) = self
                    .workspace
                    .typed
                    .as_ref()
                    .and_then(|typed| typed.rows.table(&frame.scope().ok()?.table))
            {
                self.touch(&table.sql_name);
            }
        }
        if members > 1 {
            let held: Vec<_> = intents
                .iter()
                .map(|(frame, .., member)| (*frame, *member))
                .collect();
            self.publish_outcome(
                transaction,
                &held,
                dropped.as_ref().map(|dropped| dropped.reason),
                time,
            )
            .await?;
        }
        #[cfg(any(test, feature = "qualification"))]
        self.crash_at(|point| point == CrashPoint::Apply)?;
        Ok(())
    }

    /// Replays an arrival's intent members. Unsealed transactions of their
    /// partitions ordered after them rewind first and redo after, so every
    /// partition holds its canonical order; a late arrival behind a seal
    /// orders after the seal's members.
    pub(super) async fn replay_arrival(
        &self,
        transaction: (Commitment, u16),
        intents: &[Replaying<'_>],
        time: u64,
    ) -> Result<(), Error> {
        let mut starts = Vec::with_capacity(intents.len());
        let mut era = None;
        for (frame, ..) in intents {
            let header = &frame.operation_ref()?.header;
            let scope = header.extensions.scope;
            let era = match era {
                Some(era) => era,
                None => *era.insert(self.open_era(scope.domain).await?),
            };
            starts.push((self.scope_id(scope).await?, (era, stamp(header))));
        }
        let redo = self.rewind(starts).await?;
        self.replay_transaction(transaction, intents, era, time)
            .await?;
        self.redo(redo, time).await
    }

    async fn open_era(&self, domain: rocky_core::Scope) -> Result<i64, Error> {
        match collect_rows(
            self.conn
                .query(format!("SELECT {OPEN_ERA}"), [encode(&domain)?])
                .await?,
        )
        .await?
        .first()
        .map(Vec::as_slice)
        {
            Some([SqlValue::Integer(era)]) => Ok(*era),
            _ => Err(Error::Corrupt("replay era".into())),
        }
    }

    /// Replays rewound transactions again, in canonical order.
    async fn redo(&self, redo: Vec<Redo>, time: u64) -> Result<(), Error> {
        self.redo_recorded(redo, time, None).await
    }
    /// `redo`; a member `recorded` names keeps the admission it was
    /// recorded with, under the authority it was admitted with.
    async fn redo_recorded(
        &self,
        redo: Vec<Redo>,
        time: u64,
        recorded: Option<&BTreeMap<Hash, bool>>,
    ) -> Result<(), Error> {
        for (index, redo) in redo.into_iter().enumerate() {
            #[cfg(any(test, feature = "qualification"))]
            if index > 0 {
                self.crash_at(|point| point == CrashPoint::Redo)?;
            }
            #[cfg(not(any(test, feature = "qualification")))]
            let _ = index;
            let mut opened = Vec::with_capacity(redo.members.len());
            for (hash, member) in redo.members {
                let frame = self
                    .frame(hash)
                    .await?
                    .ok_or_else(|| Error::Corrupt("rewound frame is missing".into()))?;
                // The caller's savepoint undoes the rewind; the arrival retries
                // once the key is back.
                let extension = &frame.operation_ref()?.header.extensions;
                if self
                    .opening_key(extension.scope, extension.generation)
                    .is_none()
                {
                    return Err(Error::Rejected(KEY_WAITS.into()));
                }
                let payload = self.row_payload(&frame)?;
                // A rewind never carries admission across a grant change.
                let grants = match recorded.and_then(|recorded| recorded.get(&hash)) {
                    Some(true) => self.historical_frame_authority(&frame).ok(),
                    Some(false) => None,
                    None => self.verify_frame(&frame, time).ok(),
                };
                opened.push((frame, payload, grants, member));
            }
            let mut intents = Vec::with_capacity(opened.len());
            let mut members = 1;
            for (frame, payload, grants, member) in &opened {
                let intent = payload
                    .intent()
                    .ok_or_else(|| Error::Corrupt("rewound frame carries no intent".into()))?;
                members = payload
                    .membership()
                    .map_or(1, |membership| membership.members.len() as u16);
                intents.push((frame, intent, grants, *member));
            }
            let transaction = (redo.transaction, members);
            let era = Some(redo.order.0);
            if intents.iter().any(|(_, _, grants, _)| grants.is_none()) {
                for (frame, _, _, member) in &intents {
                    self.record_replayed(
                        frame,
                        (redo.transaction, *member, members),
                        Some(&DropReason::Admission.into()),
                        &[],
                        era,
                    )
                    .await?;
                }
                continue;
            }
            let intents: Vec<Replaying<'_>> = intents
                .iter()
                .map(|(frame, intent, grants, member)| {
                    (*frame, *intent, grants.as_deref().unwrap_or(&[]), *member)
                })
                .collect();
            self.replay_transaction(transaction, &intents, era, time)
                .await?;
        }
        Ok(())
    }

    /// Records where a transaction's member stands in its partition's order
    /// and how it replayed: `None` with its undo when it applied. Without
    /// an `era` it joins the open one.
    pub(super) async fn record_replayed(
        &self,
        frame: &EncryptedFrame,
        (transaction, member, members): (Commitment, u16, u16),
        dropped: Option<&Dropped>,
        undo: &[Undo],
        era: Option<i64>,
    ) -> Result<(), Error> {
        let operation = frame.operation_ref()?;
        let header = &operation.header;
        let stamp = stamp(header);
        let id = self.scope_id(header.extensions.scope).await?;
        if dropped.is_some() {
            self.touch_dropped(transaction);
        }
        self.conn
            .execute(
                format!("INSERT INTO secure_replayed VALUES(?,COALESCE(?,{OPEN_ERA}),?,?,?,?,?,?,?,?,0,?,?,NULL)"),
                bindings(vec![
                    SqlValue::Integer(id),
                    era.map_or(SqlValue::Null, SqlValue::Integer),
                    SqlValue::Blob(encode(&header.extensions.scope.domain)?),
                    SqlValue::Integer(stamp.clock as i64),
                    SqlValue::Integer(i64::from(stamp.author)),
                    SqlValue::Integer(stamp.sequence as i64),
                    SqlValue::Blob(operation.hash.as_bytes().to_vec()),
                    SqlValue::Blob(transaction.to_vec()),
                    SqlValue::Integer(i64::from(member)),
                    SqlValue::Integer(i64::from(members)),
                    dropped.map_or(SqlValue::Null, |dropped| {
                        SqlValue::Text(reason_name(dropped.reason).into())
                    }),
                    undo_blob(undo)?,
                    dropped
                        .and_then(|dropped| dropped.violated.clone())
                        .map_or(SqlValue::Null, SqlValue::Text),
                ]),
            )
            .await?;
        Ok(())
    }

    /// Notes the identities a recorded member created and raises the
    /// scope's replay ledger with them.
    pub(super) async fn record_births(
        &self,
        frame: &EncryptedFrame,
        births: &[checkpoint::IdentityMark],
    ) -> Result<(), Error> {
        if births.is_empty() {
            return Ok(());
        }
        self.conn
            .execute(
                "UPDATE secure_replayed SET births=? WHERE hash=?",
                [encode(&births)?, frame.id()?.as_bytes().to_vec()],
            )
            .await?;
        let scope = frame.scope()?;
        for birth in births {
            self.fold_ledger(scope, birth).await?;
        }
        Ok(())
    }
    /// Runs one member's statements on its partition inside the caller's
    /// savepoint and admits their effects against the author's grants.
    /// Returns what it changed, or why the transaction drops; the caller
    /// rolls back then.
    fn replay_intent(
        &self,
        frame: &EncryptedFrame,
        intent: &Intent,
        grants: &[rocky_core::ResourceGrant],
    ) -> Result<Result<Replayed, Dropped>, Error> {
        let header = &frame.operation_ref()?.header;
        let scope = header.extensions.scope;
        let typed = self
            .workspace
            .typed
            .as_ref()
            .ok_or_else(|| denied("no typed tables"))?;
        let schema = typed.rows.schema();
        // A table the installed schema removed no longer compiles; another
        // tip may hold it again.
        let Some(table) = typed.rows.table(&scope.table) else {
            return Ok(Err(DropReason::Schema.into()));
        };
        let logical = schema
            .table(&table.sql_name)
            .filter(|logical| logical.class == TableClass::Replayed)
            .ok_or_else(|| denied("an intent names a table that is not replayed"))?;
        // Each statement is checked and confined to the frame's own
        // partition again: a receiver runs only what its own split yields.
        let held = match &header.extensions.partition {
            Some(tuple) => vec![super::partition::partition_values(schema, logical, tuple)?],
            None => Vec::new(),
        };
        let rules = BTreeMap::from([(
            logical.sql_name.to_ascii_lowercase(),
            TablePartitions {
                columns: super::partition::partition_columns(logical)?,
                complete: held.is_empty(),
                held,
                waiting: Vec::new(),
            },
        )]);
        let mut copies = Vec::with_capacity(intent.statements.len());
        for statement in &intent.statements {
            match split_intent(
                &statement.sql,
                &statement.params,
                &schema.views,
                &rules,
                |_| Err::<Vec<Vec<SqlValue>>, _>(()),
            ) {
                Ok(split) if split.len() <= 1 => copies.extend(split),
                _ => return Ok(Err(DropReason::Schema.into())),
            }
        }
        // A delete action changes rows of other replayed tables in the same
        // transaction: they are captured, admitted and undone with it. The
        // parents of what changes are read for its foreign keys.
        let reached = cascades(schema, &logical.sql_name);
        let off_path = self.off_path(header, schema, logical);
        let mut scopes = BTreeSet::from([scope]);
        scopes.extend(
            checked(schema, &reached)
                .iter()
                .filter_map(|name| typed.by_name(name).map(|projected| projected.scope)),
        );
        let mut plan = typed.plan(&scopes)?;
        let conn = self.conn.connection();
        plan.bind_physical_columns(conn)?;
        let plan = Arc::new(plan);
        let capture = conn.capture()?;
        let state = conn.session()?;
        let poisoned = || Error::Corrupt("capture poisoned".into());
        capture
            .lock()
            .map_err(|_| poisoned())?
            .arm(plan.clone(), REPLAY_CAPTURE);
        let ran = (|| {
            for copy in copies {
                state
                    .gate
                    .lock()
                    .map_err(|_| poisoned())?
                    .arm(Some(plan.clone()));
                capture.lock().map_err(|_| poisoned())?.begin_statement();
                let result = conn.session_run(
                    &copy.statement.sql,
                    storage::bindings(copy.statement.params),
                    0,
                    true,
                );
                let assigned = {
                    let mut gate = state.gate.lock().map_err(|_| poisoned())?;
                    let assigned = gate.assigned();
                    gate.arm(None);
                    assigned
                };
                let failed = !matches!(result, Ok(sqlite::Run::Done(_)));
                capture
                    .lock()
                    .map_err(|_| poisoned())?
                    .end_statement(failed, &assigned);
                match result {
                    Ok(sqlite::Run::Done(_)) => {}
                    Err(error) if error.is_constraint() => {
                        return Ok(Some(Dropped {
                            reason: DropReason::Constraint,
                            violated: Some(error.to_string()),
                        }));
                    }
                    Err(sqlite::Error::Denied | sqlite::Error::Unsupported(_)) => {
                        return Ok(Some(DropReason::Schema.into()));
                    }
                    // A statement that no longer compiles against the schema.
                    Err(_) if conn.describe(&copy.statement.sql).is_err() => {
                        return Ok(Some(DropReason::Schema.into()));
                    }
                    _ => return Ok(Some(DropReason::Engine.into())),
                }
            }
            Ok::<_, Error>(None)
        })();
        let touched = {
            let mut sink = capture.lock().map_err(|_| poisoned())?;
            let touched = match (&ran, sink.failure()) {
                (Ok(None), None) => sink
                    .freeze()
                    .map_err(|_| Error::Corrupt("replay capture".into())),
                _ => Ok(Vec::new()),
            };
            sink.disarm();
            touched
        };
        if let Some(reason) = ran? {
            return Ok(Err(reason));
        }
        // Admission runs on the rows this replay produced.
        let (mut undo, mut births, mut written) = (Vec::new(), Vec::new(), Vec::new());
        for touched in touched? {
            let captured = &plan.tables[touched.table];
            let own = captured.name.eq_ignore_ascii_case(&logical.sql_name);
            let Some(changed) = schema
                .table(&captured.name)
                .filter(|_| reached.contains(&captured.name.to_ascii_lowercase()))
            else {
                return Ok(Err(DropReason::Engine.into()));
            };
            if own && !off_path.is_empty() {
                keep_off_path(conn, captured, &touched, &off_path)?;
            }
            let Some((change, image)) = replayed_change(conn, typed, captured, &touched)? else {
                continue;
            };
            // A delete action follows from the parent's change, which the
            // author's grants admitted, as it is derived for mergeable rows.
            let mut named = change.clone();
            if let Some(after) = named.after.as_mut().filter(|_| named.before.is_none()) {
                after.retain(|field, _| !off_path.iter().any(|(_, id, _)| id == field));
            }
            if own && (change.scope != scope || !named.permitted_by(grants)) {
                return Ok(Err(DropReason::Admission.into()));
            }
            match self.replayed_birth(&change, header.extensions.author) {
                Ok(Some(identity)) => births.push(checkpoint::IdentityMark {
                    author: identity.author(),
                    signer: header.public_key,
                    sequence: identity.sequence(),
                }),
                Ok(None) => {}
                Err(_) => return Ok(Err(DropReason::Admission.into())),
            }
            note(&mut written, constraints::written(changed, &image)?);
            undo.push(Undo {
                table: captured.name.clone(),
                key: touched.key,
                before: touched.before,
            });
        }
        Ok(Ok(Replayed {
            undo,
            births,
            written,
        }))
    }

    /// The current fields of `logical` missing at some tip between the
    /// frame's and the workspace's, by column position, with their
    /// defaults: the frame cannot have written them.
    fn off_path(
        &self,
        header: &p2panda_core::Header<Extensions>,
        schema: &rocky_core::LogicalSchema,
        logical: &rocky_core::LogicalTable,
    ) -> Vec<(usize, Commitment, SqlValue)> {
        let extension = &header.extensions;
        let Ok(path) = self.path_fields(extension.scope.domain, extension.tip) else {
            return Vec::new();
        };
        let declared: BTreeSet<_> = self
            .definition
            .fields
            .iter()
            .map(|field| field.id)
            .collect();
        logical
            .columns
            .iter()
            .enumerate()
            .filter_map(|(index, column)| {
                let id = schema.field_id(logical, column);
                (declared.contains(&id) && !path.fields.contains(&id)).then(|| {
                    let default = rocky_core::default_value(column).unwrap_or(SqlValue::Null);
                    (index, id, default)
                })
            })
            .collect()
    }
    /// The identity a replayed change creates. Only its author's own
    /// number may create one, as `next_id` allocates them.
    pub(super) fn replayed_birth(
        &self,
        change: &RowChange,
        author: Option<u32>,
    ) -> Result<Option<rocky_core::RowIdentity>, Error> {
        if change.before.is_some() {
            return Ok(None);
        }
        let Some(identity) = self
            .app
            .row_identity(change)
            .map_err(|error| denied(&error))?
        else {
            return Ok(None);
        };
        if Some(identity.author()) != author {
            return Err(denied("a replayed insert names another author's identity"));
        }
        // The scope's history created this identity before, retired or not.
        if !self
            .conn
            .connection()
            .rows(
                "SELECT 1 FROM secure_identity_ledger WHERE scope=? AND author=? AND sequence>=?",
                storage::bindings(vec![
                    SqlValue::Blob(encode(&change.scope)?),
                    SqlValue::Integer(i64::from(identity.author())),
                    SqlValue::Integer(i64::from(identity.sequence())),
                ]),
            )?
            .is_empty()
        {
            return Err(denied("a replayed insert reuses an identity"));
        }
        Ok(Some(identity))
    }
}

/// Sets a touched row's fields that are off the frame's path back to
/// their value before it, or their default in a row it inserted.
fn keep_off_path(
    conn: &sqlite::Connection,
    captured: &rocky_storage::capture::Table,
    touched: &rocky_storage::capture::Touched,
    off_path: &[(usize, Commitment, SqlValue)],
) -> Result<(), Error> {
    let corrupt = || Error::Corrupt("replayed row image".into());
    let Some(values) = conn
        .rows(&captured.select, storage::bindings(touched.key.clone()))?
        .into_iter()
        .next()
    else {
        return Ok(());
    };
    let mut image = captured.image(&values).map_err(|_| corrupt())?;
    let mut changed = false;
    for (index, _, default) in off_path {
        let kept = touched
            .before
            .as_ref()
            .map_or(Some(default), |before| before.get(*index))
            .ok_or_else(corrupt)?;
        let value = image.get_mut(*index).ok_or_else(corrupt)?;
        if value != kept {
            *value = kept.clone();
            changed = true;
        }
    }
    if changed {
        let mut values = captured.stored(&image);
        values.extend(touched.key.iter().cloned());
        conn.rows(&captured.update_image(), storage::bindings(values))?;
    }
    Ok(())
}

/// The change a replayed table's captured row went through, as grants see
/// it, with its latest image; `None` when it changed nothing, such as an
/// update to equal values, which needs no right.
pub(super) fn replayed_change(
    conn: &sqlite::Connection,
    typed: &typed::Typed,
    captured: &rocky_storage::capture::Table,
    touched: &rocky_storage::capture::Touched,
) -> Result<Option<(RowChange, Vec<SqlValue>)>, Error> {
    let corrupt = |what: &str| Error::Corrupt(format!("replayed row {what}"));
    let projected = typed
        .by_name(&captured.name)
        .ok_or_else(|| corrupt("table"))?;
    let after = match conn
        .rows(&captured.select, storage::bindings(touched.key.clone()))?
        .first()
    {
        Some(values) => Some(captured.image(values).map_err(|_| corrupt("image"))?),
        None => None,
    };
    let Some(anchor) = after.as_ref().or(touched.before.as_ref()) else {
        return Ok(None);
    };
    let fields = |image: &Vec<SqlValue>| {
        typed
            .rows
            .fields(&projected.table, image)
            .map_err(|_| corrupt("fields"))
    };
    let change = RowChange {
        scope: typed.row_scope(projected, anchor)?,
        row: typed
            .rows
            .row_id(typed.domain.domain, &projected.table, anchor)
            .map_err(|_| corrupt("key"))?,
        before: touched.before.as_ref().map(fields).transpose()?,
        after: after.as_ref().map(fields).transpose()?,
    };
    let image = anchor.clone();
    Ok(change.right().is_some().then_some((change, image)))
}
