//! Authoring writes to replayed tables: each statement is split per held
//! partition on the snapshot it executes on, and the transaction publishes
//! the copies as intents instead of row images.
use super::*;
use rocky_core::TableClass;
use rocky_core::replay::{BaseMark, IntentStatement};
use rocky_storage::partition_sql::{IntentRefusal, SplitError, split_intent_within, written_table};

/// One partition's copy of a statement the transaction ran.
#[derive(Clone, Debug)]
pub(crate) struct Recorded {
    pub scope: ResourceScope,
    pub statement: IntentStatement,
}

impl<A: RowApplication> Inner<A> {
    /// The copies of a write to a replayed table, one per held partition it
    /// reaches, split before it executes. `None` when it writes no replayed
    /// table; empty when it reaches no held partition. A statement reaches
    /// at most `limit` partitions.
    pub(super) async fn intent_copies(
        &self,
        sql: &str,
        params: &[SqlValue],
        status: &SessionStatus,
        limit: usize,
    ) -> Result<Option<Vec<Recorded>>, Error> {
        let Some(typed) = &self.workspace.typed else {
            return Ok(None);
        };
        let schema = typed.rows.schema();
        let replayed = |name: &str| {
            schema
                .table(name)
                .is_some_and(|table| table.class == TableClass::Replayed)
        };
        let name = match written_table(sql, &schema.views) {
            Some(name) if replayed(&name) => name,
            Some(_) => return Ok(None),
            // A write the splitter cannot name gets its refusal below when it
            // names a replayed table.
            None => match crate::statement::analyze(sql, |_| None) {
                Ok(analyzed)
                    if analyzed.kind != crate::statement::Kind::Read
                        && analyzed.tables.iter().any(|name| replayed(name)) =>
                {
                    String::new()
                }
                _ => return Ok(None),
            },
        };
        let rules = self.partition_rules(None, status).await?;
        let conn = self.conn.connection();
        let split = split_intent_within(sql, params, &schema.views, &rules, limit, |read| {
            conn.rows(&read.sql, storage::bindings(read.params.clone()))?
                .into_iter()
                .map(|row| row.into_iter().map(storage::sql_value).collect())
                .collect::<Result<Vec<Vec<_>>, Error>>()
        });
        let copies = match split {
            Ok(copies) => copies,
            Err(SplitError::Evaluate(error)) => return Err(error),
            Err(SplitError::Refused(refusal)) => {
                // A table that waits names what it waits for.
                if let IntentRefusal::Unavailable {
                    table,
                    reason: crate::sql::Unavailable::Incomplete,
                } = &refusal
                    && let Some(projected) = typed.by_name(table)
                {
                    let mut blocked = self.scope_blockers(projected.scope).await?;
                    for scope in self
                        .partitions
                        .keys()
                        .filter(|scope| scope.table == projected.table.id)
                    {
                        blocked.extend(self.scope_blockers(*scope).await?);
                    }
                    blockers::refuse(blocked)?;
                }
                return Err(Error::Sql(SqlError::Unsupported(format!(
                    "a replayed write was refused: {refusal}"
                ))));
            }
        };
        let logical = schema
            .table(&name)
            .ok_or_else(|| Error::Corrupt("replayed write target".into()))?;
        let projected = typed
            .by_name(&logical.sql_name)
            .ok_or_else(|| Error::Corrupt(format!("{} is not typed", logical.sql_name)))?;
        let mut scopes = Vec::new();
        if logical.partition_by.is_empty() {
            scopes.push((Vec::new(), projected.scope));
        } else {
            for (scope, tuple) in self.partitions.iter().filter(|(scope, _)| {
                scope.table == projected.table.id && scope.domain == typed.domain
            }) {
                scopes.push((
                    super::partition::partition_values(schema, logical, tuple)?,
                    *scope,
                ));
            }
        }
        copies
            .into_iter()
            .map(|copy| {
                let scope = scopes
                    .iter()
                    .find(|(values, _)| *values == copy.partition)
                    .map(|(_, scope)| *scope)
                    .ok_or_else(|| Error::Corrupt("split partition has no scope".into()))?;
                if !status.writable.contains(&scope) {
                    return Err(Error::Sql(SqlError::Denied));
                }
                Ok(Recorded {
                    scope,
                    statement: IntentStatement {
                        sql: copy.statement.sql,
                        params: copy.statement.params,
                    },
                })
            })
            .collect::<Result<_, _>>()
            .map(Some)
    }

    /// Signs and stores one frame of a replayed table's log for `scope`
    /// that changes no rows itself: an intent, whose rows the author's
    /// execution already wrote, or an outcome record. The frame follows
    /// every author's last applied frame in the scope; `payload` gets its
    /// sequence and that base. `tip` is the author's own log tip there.
    /// The caller refuses what blocks authoring in the scope.
    pub(super) async fn author_log_frame(
        &self,
        (scope, tip): (ResourceScope, Option<checkpoint::Log>),
        time: u64,
        payload: impl FnOnce(u64, Vec<BaseMark>) -> Result<Vec<u8>, Error>,
    ) -> Result<EncryptedFrame, Error> {
        self.ensure_tip_writable(scope.domain)?;
        let partition = self.partitions.get(&scope).cloned();
        let signer = self
            .node_author
            .as_ref()
            .ok_or_else(|| denied("a replayed table's log needs a table author"))?;
        let signing_key = &signer.key;
        match &partition {
            Some(tuple) => signer
                .credentials
                .verify_partition_author(
                    self.config.publisher,
                    signing_key.public_key(),
                    signer.number,
                    scope,
                    tuple,
                    &self.config.revocations,
                    time,
                )
                .map_err(credential)?,
            None => signer
                .credentials
                .verify_author(
                    self.config.publisher,
                    signing_key.public_key(),
                    signer.number,
                    scope.table,
                    &self.config.revocations,
                    time,
                )
                .map_err(credential)?,
        };
        let key = self
            .config
            .keys
            .iter()
            .find(|key| key.scope == scope)
            .ok_or_else(|| denied("author needs an authorized row key"))?;
        self.admit_author(scope, tip.as_ref().map(|log| log.sequence))
            .await?;
        let (sequence, backlink, mut clock) = match tip {
            Some(log) => (
                (log.sequence as u64)
                    .checked_add(1)
                    .filter(|seq| *seq <= i64::MAX as u64)
                    .ok_or_else(|| denied("author counter exhausted"))?,
                Some(log.hash),
                log.clock,
            ),
            None => (0, None, 0),
        };
        let heads = self.applied_heads(scope).await?;
        if heads.len() > 64 {
            return Err(denied("dependency quota"));
        }
        let mut base = Vec::with_capacity(heads.len());
        let mut previous = BTreeSet::new();
        for (hash, header) in &heads {
            base.push(BaseMark {
                author: header
                    .extensions
                    .author
                    .ok_or_else(|| Error::Corrupt("intent base author".into()))?,
                sequence: header.extensions.author_sequence,
            });
            clock = clock.max(header.timestamp);
            if Some(*hash) != backlink {
                previous.insert(*hash);
            }
        }
        base.sort();
        // Canonical order puts the transaction after everything it read.
        let clock = clock
            .checked_add(1)
            .ok_or_else(|| denied("logical clock exhausted"))?
            .max(micros()?);
        let author_sequence = self
            .reserve_author_sequence(signing_key.public_key())
            .await?;
        let frame = author(
            signing_key,
            Extensions {
                author: Some(signer.number),
                author_sequence,
                row_format: ROW_FORMAT,
                births: Vec::new(),
                partition,
                tip: self.workspace.tip,
                scope,
                generation: key.generation,
                chain: signer.chain.digest(),
            },
            signer.chain.clone(),
            &key.key,
            (sequence, backlink, clock),
            previous.into_iter().collect(),
            &RowPayload::compact(
                &RowPayload::witness(payload(sequence, base)?, Vec::new())?,
                &self.definition,
                scope,
            )?,
        )?;
        self.verify_frame(&frame, time)?;
        // A range page carries at most this much; a larger frame could
        // never reach another replica.
        if frame.weight() > crate::network::MAX_PAGE_BYTES {
            return Err(Error::Quota {
                resource: "intent frame bytes",
                limit: crate::network::MAX_PAGE_BYTES,
            });
        }
        let operation = frame.operation_ref()?;
        self.check_budget(
            usize::try_from(frame.stored_bytes()?).map_err(|_| denied("stored frame size"))?,
        )
        .await?;
        self.keep_chain(frame.chain()?).await?;
        self.no_frames_intake(&operation.header).await?;
        TransactionStore(self.conn.clone())
            .insert_operation(
                operation.hash,
                &operation.header,
                operation.body.as_ref(),
                frame.header_bytes(),
                &scope,
            )
            .await?;
        self.write_materialized(&frame, Vec::new(), Default::default(), None)
            .await?;
        self.conn
            .execute(
                "INSERT INTO secure_outbox VALUES(?)",
                [operation.hash.as_bytes().to_vec()],
            )
            .await?;
        self.conn.execute("INSERT INTO secure_node_tips VALUES(?,?,?) ON CONFLICT(scope,node) DO UPDATE SET tip=excluded.tip", [encode(&scope.domain)?, signing_key.public_key().as_bytes().to_vec(), encode(&self.workspace.tip)?]).await?;
        self.record_key(key).await?;
        Ok(frame)
    }

    /// Refuses authoring an intent in `scope` while something blocks it.
    pub(super) async fn refuse_intent_blockers(&self, scope: ResourceScope) -> Result<(), Error> {
        let mut blocked = self.scope_blockers(scope).await?;
        blocked.extend(self.dropped_tip_blockers().await?);
        blocked.extend(self.line_node_blockers()?);
        blockers::refuse(blocked)
    }

    /// Per author, the last applied frame of the scope's log that the
    /// workspace sees: frames of other lines are no base for this one.
    async fn applied_heads(
        &self,
        scope: ResourceScope,
    ) -> Result<Vec<(Hash, p2panda_core::Header<Extensions>)>, Error> {
        let corrupt = || Error::Corrupt("applied head".into());
        let decoded = |row: &[SqlValue]| -> Result<(Hash, p2panda_core::Header<Extensions>), Error> {
            let [SqlValue::Blob(hash), SqlValue::Blob(header)] = row else {
                return Err(corrupt());
            };
            Ok((
                Hash::try_from(hash.as_slice()).map_err(|_| corrupt())?,
                decode(header)?,
            ))
        };
        let graph = self.graph_for(scope.domain)?;
        let visible = |header: &p2panda_core::Header<Extensions>| -> Result<bool, Error> {
            let extension = &header.extensions;
            self.visible_frame(
                graph,
                extension.tip,
                extension.author.ok_or_else(corrupt)?,
                extension.author_sequence,
                self.workspace.tip,
            )
        };
        let mut heads = Vec::new();
        for row in collect_rows(
            self.conn
                .query(
                    "SELECT o.hash,o.header FROM secure_operations o WHERE o.scope=? AND o.status='applied' AND o.sequence=(SELECT MAX(sequence) FROM secure_operations WHERE scope=o.scope AND author=o.author AND status='applied')",
                    [encode(&scope)?],
                )
                .await?,
        )
        .await?
        {
            let (hash, header) = decoded(&row)?;
            if visible(&header)? {
                heads.push((hash, header));
                continue;
            }
            // An author's later frames on another line: its newest frame
            // here, if any.
            let mut before = header.seq_num as i64;
            'author: loop {
                let older = collect_rows(
                    self.conn
                        .query(
                            "SELECT hash,header FROM secure_operations WHERE scope=? AND author=? AND status='applied' AND sequence<? ORDER BY sequence DESC LIMIT 64",
                            bindings(vec![
                                SqlValue::Blob(encode(&scope)?),
                                SqlValue::Blob(header.public_key.as_bytes().to_vec()),
                                SqlValue::Integer(before),
                            ]),
                        )
                        .await?,
                )
                .await?;
                if older.is_empty() {
                    break;
                }
                for row in &older {
                    let (hash, header) = decoded(row)?;
                    before = header.seq_num as i64;
                    if visible(&header)? {
                        heads.push((hash, header));
                        break 'author;
                    }
                }
            }
        }
        Ok(heads)
    }
}

/// The transaction's statements grouped per partition scope, in the order
/// they ran.
pub(super) fn grouped(
    recorded: &[Recorded],
) -> Result<BTreeMap<ResourceScope, Vec<IntentStatement>>, Error> {
    let mut intents = BTreeMap::<ResourceScope, Vec<IntentStatement>>::new();
    for recorded in recorded {
        intents
            .entry(recorded.scope)
            .or_default()
            .push(recorded.statement.clone());
    }
    if intents
        .values()
        .any(|statements| statements.len() > rocky_core::replay::MAX_INTENT_STATEMENTS)
    {
        return Err(Error::Quota {
            resource: "intent statements",
            limit: rocky_core::replay::MAX_INTENT_STATEMENTS,
        });
    }
    Ok(intents)
}
