use super::*;
use identity::receipts;
use std::borrow::Cow;

/// A merged write, its new record and the previous decoded record.
pub(super) type MergedRow = (RowChange, Materialized, Option<Materialized>);
pub(super) struct Materialization<'p> {
    pub rows: Vec<MergedRow>,
    pub admission: Admission,
    pub payload: Cow<'p, RowPayload>,
}

/// What admitting one frame adds to the admission evidence: a first
/// admission's receipt, and restorations minted on re-admission.
#[derive(Default)]
pub(super) struct Admission {
    receipt: Option<receipts::FrameReceipt>,
    restorations: Vec<receipts::Restoration>,
    observations: Vec<receipts::CarryObservation>,
}
/// How a birth is admitted.
enum Class {
    /// Not a numeric birth.
    Plain,
    /// A first admission's original creation.
    Created(rocky_core::RowIdentity, Commitment),
    /// A first admission's carried creation.
    Carried(rocky_core::RowIdentity, Commitment, PublicKey),
    /// An original assignment or carry this file admitted before.
    Exact,
    Observe(receipts::CarryObservation),
    /// A withheld birth restored now, with its receipt.
    Restore(u64, rocky_core::RowIdentity, Commitment),
}

impl<A: RowApplication> Inner<A> {
    /// Admits one frame's exact writes against `grants` and merges each with
    /// the stored row. The application validates the signed transition and
    /// the actual candidate.
    pub(super) async fn materialize(
        &self,
        frame: &EncryptedFrame,
        writes: &[RowWrite],
        grants: &[rocky_core::ResourceGrant],
        opened_payload: Option<&RowPayload>,
    ) -> Result<(Vec<MergedRow>, Admission), Error> {
        let Materialization {
            rows, admission, ..
        } = self
            .materialize_retaining(frame, writes, grants, opened_payload)
            .await?;
        Ok((rows, admission))
    }
    pub(super) async fn materialize_retaining<'p>(
        &self,
        frame: &EncryptedFrame,
        writes: &[RowWrite],
        grants: &[rocky_core::ResourceGrant],
        opened_payload: Option<&'p RowPayload>,
    ) -> Result<Materialization<'p>, Error> {
        if writes.is_empty() || writes.len() > 32 {
            return Err(denied("row change quota"));
        }
        let operation = frame.operation_ref()?;
        let scope = operation.header.extensions.scope;
        if let Some(graph) = self.graphs.get(&scope.domain) {
            let source = graph
                .schema_any(operation.header.extensions.tip)
                .map_err(credential)?;
            let definition = self
                .catalog
                .get(&source)
                .ok_or_else(|| denied("source tip schema is not installed"))?;
            let fields: BTreeSet<_> = definition.fields.iter().map(|field| field.id).collect();
            if !definition
                .entities
                .iter()
                .any(|table| table.id == scope.table)
                || writes.iter().any(|write| {
                    write
                        .change
                        .before
                        .iter()
                        .chain(&write.change.after)
                        .any(|image| image.keys().any(|field| !fields.contains(field)))
                })
            {
                return Err(denied("frame fields are outside its source tip schema"));
            }
        }
        // Authority covers the writes as signed; the current generation
        // applies what it still names, the same way on every device.
        for write in writes {
            if write.change.scope != scope
                || !write.permitted_by(grants)
                || write
                    .published_fields()
                    .iter()
                    .any(|field| self.permission_fields.contains(field))
            {
                return Err(denied(
                    "row/field transition denied; permission fields never change by row writes",
                ));
            }
        }
        let fields = self.path_fields(scope.domain, operation.header.extensions.tip)?;
        // Admission evidence names each birth by its place in the signed
        // write list, so ordinals survive the path filter.
        let mut current = Vec::new();
        let mut withheld = Vec::new();
        for (ordinal, write) in writes.iter().enumerate() {
            let ordinal = u8::try_from(ordinal).map_err(|_| denied("row change quota"))?;
            match fields.current(write) {
                Some(kept) => current.push((ordinal, kept)),
                None if write.change.before.is_none() => withheld.push(ordinal),
                None => {}
            }
        }
        let mut changed = BTreeSet::new();
        self.app
            .validate_changes(
                &current
                    .iter()
                    .map(|(_, write)| write.change.clone())
                    .collect::<Vec<_>>(),
            )
            .map_err(|message| denied(&message))?;
        let mut result = Vec::new();
        let mut identities = BTreeSet::new();
        let extension = &operation.header.extensions;
        // Every comparison uses the marks the frame entered with.
        let marks = self.identity_marks(scope).await?;
        let own = self.own_marks(scope).await?;
        let allocation = self.optional_allocation_of(scope).await?;
        let allocation_marks = match allocation {
            Some((_, allocation)) if allocation != scope => self.identity_marks(allocation).await?,
            _ => marks.clone(),
        };
        let prior = self.receipt_of(operation.hash).await?;
        let payload = match opened_payload {
            Some(payload) => Cow::Borrowed(payload),
            None => Cow::Owned(self.row_payload(frame)?),
        };
        let (rows, admission) = {
            let payload = payload.as_ref();
            if let Some((_, receipt)) = &prior {
                self.check_frame_receipt(receipt, frame, writes, payload)
                    .await?;
            }
            let mut bindings = moves::FrameBindings::default();
            let mut snapshot = receipts::BirthSnapshot {
                permanent: marks.clone(),
                own: own.clone(),
                allocation: allocation_marks,
                ledger: if current.is_empty() {
                    identity::IdentityLedger::default()
                } else if prior.is_some() {
                    identity::IdentityLedger::seeded(&self.ledger_entry(scope).await?)?
                } else {
                    identity::IdentityLedger::seeded(&self.ledger_marks(scope).await?)?
                },
                summary: self.summary_marks(scope).await?,
                receipt: prior.clone(),
                claims: Default::default(),
            };
            let mut births: Vec<receipts::Birth> = withheld
                .iter()
                .map(|ordinal| receipts::Birth {
                    ordinal: *ordinal,
                    disposition: receipts::Disposition::Filtered,
                })
                .collect();
            let mut restorations = Vec::new();
            let mut observations = Vec::new();
            let finalized = self.seal_finalized(scope).await?;
            let ceiling = Stamp {
                clock: operation.header.timestamp,
                author: operation.header.extensions.author.unwrap_or(0),
                sequence: operation.header.extensions.author_sequence,
            };
            for (ordinal, write) in &current {
                let change = &write.change;
                let carried = payload.carried(&change.row);
                let stored = self.row(scope, self.storage_row(change)?).await?;
                let current = stored.clone();
                let birth = match change.before {
                    None => self
                        .app
                        .row_identity(change)
                        .map_err(|message| denied(&message))?,
                    Some(_) => None,
                };
                let mut class = Class::Plain;
                if let Some(identity) = birth {
                    if !identities.insert(identity) {
                        return Err(denied("forged row author or reused identity sequence"));
                    }
                    let signer = match carried {
                        Some(carried) => carried.proof.signer()?,
                        None => operation.header.public_key,
                    };
                    let provenance = match carried {
                        Some(carried) => carried.proof.provenance()?,
                        None => payload
                            .proof(&change.row)
                            .ok_or_else(|| denied("numeric birth requires a creation proof"))?
                            .provenance()?,
                    };
                    let decision = self
                        .classify_birth(
                            allocation.ok_or_else(|| denied("identity allocation unavailable"))?,
                            &mut snapshot,
                            receipts::BirthInput {
                                frame: operation.hash,
                                ordinal: *ordinal,
                                identity,
                                provenance,
                                signer,
                                author: extension.author,
                                carried: carried.is_some(),
                                existing: current.is_some(),
                                finalized,
                                target: self.workspace.tip,
                                first: true,
                            },
                        )
                        .await?;
                    class = match decision {
                        receipts::BirthClass::Created => Class::Created(identity, provenance),
                        receipts::BirthClass::Carried => {
                            Class::Carried(identity, provenance, signer)
                        }
                        receipts::BirthClass::Exact => Class::Exact,
                        receipts::BirthClass::Observe(observation) => Class::Observe(observation),
                        receipts::BirthClass::Restore(restoration) => {
                            Class::Restore(restoration.receipt, identity, provenance)
                        }
                        receipts::BirthClass::Suppressed(reason) => {
                            if let Some(reason) = reason {
                                self.consume(operation.hash, reason).await?;
                            }
                            if prior.is_none() {
                                births.push(receipts::Birth {
                                    ordinal: *ordinal,
                                    disposition: receipts::Disposition::Consumed { identity },
                                });
                            }
                            continue;
                        }
                    };
                }
                let restoring = matches!(class, Class::Restore(..));
                // A restored birth that fails a creation check stays withheld;
                // its frame was admitted already.
                let checked = self
                    .check_write(write, scope, &mut changed, extension.partition.clone())
                    .await;
                match checked {
                    Ok(()) => {}
                    Err(error) if restoring && receipts::semantic_refusal(&error) => continue,
                    Err(error) => return Err(error),
                }
                if let Some(carried) = carried {
                    if payload.membership().is_none() {
                        return Err(denied("a move or follow requires a transaction bundle"));
                    }
                    self.check_carried(write, carried, &ceiling)?;
                }
                if finalized
                    && ((change.before.is_some() && current.is_none())
                        || (change.before.is_none() && current.is_some()))
                {
                    if carried.is_some() {
                        return Err(denied("move or follow is behind the pruned_prefix"));
                    }
                    self.consume(
                        operation.hash,
                        "row is unavailable behind the finalized seal",
                    )
                    .await?;
                    if let (Class::Created(identity, _), None) = (&class, &prior) {
                        births.push(receipts::Birth {
                            ordinal: *ordinal,
                            disposition: receipts::Disposition::Consumed {
                                identity: *identity,
                            },
                        });
                    }
                    continue;
                }
                let (actual, mut record) = merge_row(write, current, operation, carried)?;
                if change.before.is_none()
                    && carried.is_none()
                    && let Some(identity) = birth
                {
                    let proof = payload
                        .proof(&change.row)
                        .ok_or_else(|| denied("numeric birth requires a creation proof"))?;
                    let verified = proof
                        .verify_with_bindings(
                            self.config.publisher,
                            self.manifest_of_tip(extension.tip)?,
                            scope.table,
                            identity,
                            &ceiling,
                            Some(&mut bindings),
                        )
                        .and_then(|()| match proof.stamp() == &ceiling {
                            true => Ok(()),
                            false => Err(denied("birth proof must name its creating frame stamp")),
                        });
                    match verified {
                        Ok(()) => {}
                        Err(error) if restoring && receipts::semantic_refusal(&error) => continue,
                        Err(error) => return Err(error),
                    }
                    record.proof = Some(proof.stored()?);
                }
                record.key = Some(change.row);
                record.identity = birth
                    .or(self
                        .app
                        .row_identity(change)
                        .map_err(|message| denied(&message))?)
                    .map(|identity| identity.integer());
                // Validate both the signed transition and the actual candidate under concurrent merges.
                if changes(&actual) {
                    let valid = self
                        .app
                        .validate_changes(std::slice::from_ref(&actual))
                        .map_err(|message| denied(&message));
                    match valid {
                        Ok(()) => {}
                        Err(error) if restoring && receipts::semantic_refusal(&error) => continue,
                        Err(error) => return Err(error),
                    }
                }
                match class {
                    Class::Created(identity, provenance) if prior.is_none() => {
                        births.push(receipts::Birth {
                            ordinal: *ordinal,
                            disposition: receipts::Disposition::Created {
                                identity,
                                provenance,
                            },
                        })
                    }
                    Class::Carried(identity, provenance, signer) => births.push(receipts::Birth {
                        ordinal: *ordinal,
                        disposition: receipts::Disposition::Carried {
                            identity,
                            provenance,
                            signer,
                        },
                    }),
                    Class::Restore(receipt, identity, provenance) => {
                        restorations.push(receipts::Restoration {
                            receipt,
                            frame: operation.hash,
                            ordinal: *ordinal,
                            identity,
                            allocation: allocation
                                .ok_or_else(|| denied("identity allocation unavailable"))?
                                .1,
                            provenance,
                            target: self.workspace.tip,
                        })
                    }
                    Class::Observe(observation) => observations.push(observation),
                    Class::Created(..) | Class::Exact | Class::Plain => {}
                }
                result.push((actual, record, stored));
            }
            self.app
                .validate_changes(
                    &result
                        .iter()
                        .map(|(change, ..)| change.clone())
                        .filter(changes)
                        .collect::<Vec<_>>(),
                )
                .map_err(|message| denied(&message))?;
            births.sort_by_key(|birth| birth.ordinal);
            let receipt = match (&prior, births.is_empty()) {
                (None, false) => {
                    let target = (!withheld.is_empty()).then_some(self.workspace.tip);
                    Some(receipts::FrameReceipt {
                        frame: operation.hash,
                        signer: operation.header.public_key,
                        author: extension.author,
                        scope,
                        allocation: allocation
                            .map_or(receipts::ReceiptAllocation::Unresolved, |(_, scope)| {
                                receipts::ReceiptAllocation::Bound(scope)
                            }),
                        sequence: operation.header.seq_num,
                        author_sequence: extension.author_sequence,
                        tip: extension.tip,
                        schema: self.manifest_of_tip(extension.tip)?,
                        target,
                        floor: target.map(|_| {
                            extension
                                .author
                                .and_then(|author| own.get(&author).copied())
                                .unwrap_or(0)
                        }),
                        writes: u8::try_from(writes.len())
                            .map_err(|_| denied("row change quota"))?,
                        births,
                    })
                }
                _ => None,
            };
            (
                result,
                Admission {
                    receipt,
                    restorations,
                    observations,
                },
            )
        };
        Ok(Materialization {
            rows,
            admission,
            payload,
        })
    }
    /// The checks every applied write passes: its partition, the
    /// application's write rule, its scope, one write per row and the
    /// installed fields.
    pub(super) async fn check_write(
        &self,
        write: &RowWrite,
        scope: ResourceScope,
        changed: &mut BTreeSet<Commitment>,
        partition: Option<rocky_core::PartitionTuple>,
    ) -> Result<(), Error> {
        if self
            .app
            .row_partition(&write.change)
            .map_err(|error| denied(&error))?
            != partition
        {
            return Err(denied("row image differs from authenticated partition"));
        }
        let change = &write.change;
        self.app
            .validate_write(write)
            .map_err(|message| denied(&message))?;
        if change.scope != scope
            || !changed.insert(self.storage_row(change)?)
            || change
                .before
                .iter()
                .chain(change.after.iter())
                .any(|fields| {
                    fields.len() > 256 || fields.keys().any(|field| !self.fields.contains(field))
                })
        {
            return Err(denied(
                "row/field transition denied; permission fields never change by row writes",
            ));
        }
        Ok(())
    }
    pub(super) async fn write_materialized(
        &self,
        frame: &EncryptedFrame,
        materialized: Vec<MergedRow>,
        admission: Admission,
        opened_payload: Option<&RowPayload>,
    ) -> Result<(), Error> {
        self.rows_written
            .fetch_add(materialized.len() as u64, Ordering::Relaxed);
        self.frames_written.fetch_add(1, Ordering::Relaxed);
        let operation = frame.operation_ref()?;
        let decoded;
        let payload = match opened_payload {
            Some(payload) => payload,
            None => {
                decoded = self.row_payload(frame)?;
                &decoded
            }
        };
        let scope = operation.header.extensions.scope;
        let id = self.scope_id(scope).await?;
        if let Some(author) = operation.header.extensions.author {
            self.keep_stamp_author(scope.domain, author, operation.header.public_key)
                .await?;
        }
        for write in payload.writes() {
            if let Some(carried) = payload.carried(&write.change.row) {
                for (author, signer) in &carried.authors {
                    self.keep_stamp_author(scope.domain, *author, *signer)
                        .await?;
                }
            }
        }
        // Consumed births reserve identities even when their row is
        // definitely dropped; the frame is replay-eligible here, so the
        // ledger folds them too.
        for birth in self.payload_birth_marks(frame, payload)? {
            self.put_identity_mark(
                scope,
                &birth.mark,
                if birth.carried {
                    identity::Raise::Carried
                } else {
                    identity::Raise::Own
                },
            )
            .await?;
            if !birth.carried {
                self.fold_ledger(scope, &birth.mark).await?;
            }
        }
        if let Some(receipt) = admission.receipt {
            self.append_admission(receipts::EntryKind::Frame(receipt))
                .await?;
        }
        for restoration in admission.restorations {
            self.append_admission(receipts::EntryKind::Restoration(restoration))
                .await?;
        }
        for observation in admission.observations {
            self.append_admission(receipts::EntryKind::CarryObservation(observation))
                .await?;
        }
        // The scope digest follows every stored row in the same transaction.
        let (rows, tombstones, digest, applied) = self.scope_state(id).await?;
        let mut sets = checkpoint::Sets::new();
        (sets.rows, sets.tombstones, sets.digest) = (rows, tombstones, digest);
        for (change, record, old_record) in materialized {
            let row = match record.identity {
                Some(id) => rocky_core::commitment("rocky.row-incarnation.v2", &id.to_le_bytes()),
                None => change.row,
            };
            if record.creation == operation.hash
                && payload.carried(&change.row).is_none()
                && let Some(identity) = record.identity
            {
                let identity = rocky_core::RowIdentity::from_integer(identity)
                    .map_err(|error| denied(&error.to_string()))?;
                self.put_identity_mark(
                    scope,
                    &checkpoint::IdentityMark {
                        author: identity.author(),
                        signer: operation.header.public_key,
                        sequence: identity.sequence(),
                    },
                    identity::Raise::Own,
                )
                .await?;
            }
            // The record names its proof's bindings by digest.
            if let Some(proof) = payload
                .carried(&change.row)
                .map(|carried| &carried.proof)
                .or_else(|| payload.proof(&change.row))
                .filter(|_| record.proof.is_some())
            {
                self.keep_bindings(proof).await?;
            }
            let new = self.encode_record(&record).await?;
            sets.replace_materialized(&row, old_record.as_ref(), &record)?;
            self.conn
                .execute(
                    "INSERT INTO secure_row_records VALUES(?,?,?)",
                    [encode(&change.scope)?, row.to_vec(), new],
                )
                .await?;
            self.index_row_key(&encode(&change.scope)?, &row, old_record.as_ref(), &record)
                .await?;
        }
        self.store_scope_state(id, sets.rows, sets.tombstones, &sets.digest, applied + 1)
            .await?;
        self.note_applied(id, operation).await?;
        self.note_row_positions(id, frame, payload).await?;
        self.conn
            .execute(
                "UPDATE secure_operations SET status='applied' WHERE hash=?",
                [frame.id()?.as_bytes().to_vec()],
            )
            .await?;
        self.conn
            .execute(
                "UPDATE secure_metadata SET revision=revision+1 WHERE id=1",
                (),
            )
            .await?;
        Ok(())
    }
}

/// Whether a merged candidate changes anything. An edit merged into a
/// permanent tombstone has neither image: the delete wins and the edit
/// still applies, so its author's log continues.
pub(super) fn changes(change: &RowChange) -> bool {
    change.before.is_some() || change.after.is_some()
}

pub(super) fn exact(writes: &[RowWrite]) -> Vec<RowChange> {
    writes.iter().map(|write| write.change.clone()).collect()
}

/// Merges one write into the stored row: every published field whose
/// register this operation's stamp wins takes the after value.
pub(super) fn merge_row(
    write: &RowWrite,
    current: Option<Materialized>,
    operation: &p2panda_core::Operation<Extensions>,
    carried: Option<&moves::Carried>,
) -> Result<(RowChange, Materialized), Error> {
    let change = &write.change;
    if change.before.is_some() {
        let creation = current
            .as_ref()
            .ok_or_else(|| denied("row creation unavailable"))?
            .creation;
        if operation.header.backlink != Some(creation)
            && !operation.header.previous.contains(&creation)
        {
            return Err(denied("missing row creation dependency"));
        }
    }
    let mut record = current.clone().unwrap_or(Materialized {
        proof: None,
        moved_from: None,
        fields: BTreeMap::new(),
        stamps: BTreeMap::new(),
        authors: BTreeMap::new(),
        deleted: false,
        creation: operation.hash,
        identity: None,
        key: Some(change.row),
        created: Some(Stamp {
            clock: operation.header.timestamp,
            author: operation.header.extensions.author.unwrap_or(0),
            sequence: operation.header.extensions.author_sequence,
        }),
    });
    if current.is_some() && change.before.is_none() {
        return Err(denied("row identity already exists"));
    }
    let before = if record.deleted {
        None
    } else if current.is_some() {
        Some(record.fields.clone())
    } else {
        None
    };
    if change.after.is_none() {
        record.deleted = true;
        record.fields.clear();
        record.stamps.clear();
    } else if !record.deleted {
        let stamp = Stamp {
            clock: operation.header.timestamp,
            author: operation.header.extensions.author.unwrap_or(0),
            sequence: operation.header.extensions.author_sequence,
        };
        let after = change
            .after
            .as_ref()
            .ok_or_else(|| denied("missing after image"))?;
        for field in write.published_fields() {
            let stamp = carried
                .and_then(|carried| carried.stamps.get(&field))
                .unwrap_or(&stamp);
            if record.stamps.get(&field).is_none_or(|old| stamp > old) {
                record.stamps.insert(field, stamp.clone());
                if let Some(value) = after.get(&field) {
                    record.fields.insert(field, value.clone());
                } else {
                    record.fields.remove(&field);
                }
            }
        }
    }
    if let Some(carried) = carried
        && change.before.is_none()
    {
        record.proof = Some(carried.proof.stored()?);
        record.created = Some(carried.proof.stamp().clone());
        record.moved_from = carried.moved_from.clone();
    }
    let author = operation.header.extensions.author.unwrap_or(0);
    if let Some(old) = record.authors.insert(author, operation.header.public_key)
        && old != operation.header.public_key
    {
        return Err(denied("a row stamp author names another signer"));
    }
    if let Some(carried) = carried {
        for (author, signer) in &carried.authors {
            if let Some(old) = record.authors.insert(*author, *signer)
                && old != *signer
            {
                return Err(denied("a carried stamp author names another signer"));
            }
        }
        let signer = carried.proof.signer()?;
        if let Some(old) = record.authors.insert(carried.proof.stamp().author, signer)
            && old != signer
        {
            return Err(denied("creation stamp signer differs from its proof"));
        }
    }
    record.trim_authors()?;
    let actual = RowChange {
        scope: change.scope,
        row: change.row,
        before,
        after: if record.deleted {
            None
        } else {
            Some(record.fields.clone())
        },
    };
    Ok((actual, record))
}
