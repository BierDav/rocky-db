//! Source row identities and global birth order at applied positions.
use super::*;

impl<A: RowApplication> Inner<A> {
    /// Global birth order matters even when a replay visits only a few rows.
    pub(in crate::replica) async fn row_replay_ledger(
        &self,
        scope: ResourceScope,
        id: i64,
        through: i64,
        target: TipId,
    ) -> Result<identity::IdentityLedger, Error> {
        let base = self.checkpoint_record(id, true).await?;
        let base_position = base.as_ref().map_or(0, |base| base.position);
        // Births only accumulate: a later replay step extends the last ledger.
        let cached = self
            .tip_frontiers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replay_ledger
            .take()
            .filter(|cached| {
                (cached.id, cached.target, cached.base) == (id, target, base_position)
                    && cached.through <= through
            });
        let (after, mut ledger) = match (cached, base) {
            (Some(cached), _) => (cached.through, cached.ledger),
            (None, Some(base)) => (
                base.position,
                identity::IdentityLedger::based(
                    &self.verify_record(scope, &base)?.statement.identities,
                )?,
            ),
            (None, None) => (0, identity::IdentityLedger::default()),
        };
        if !self.tables.contains(&scope.table) {
            return Ok(ledger);
        }
        // The walk depends only on the frame's tip, and each signer recurs.
        let mut paths = HashMap::new();
        let mut signers = HashMap::new();
        let records = collect_rows(self.conn.query(
            "SELECT b.author,b.signer,MAX(b.sequence),p.tip,p.author,MAX(p.sequence) FROM secure_birth_positions b JOIN secure_applied a ON a.position=b.position JOIN secure_operations o ON o.hash=a.hash JOIN secure_position_sources p ON p.hash=a.hash AND p.kind=0 WHERE b.scope=? AND b.position>? AND b.position<=? AND o.status='applied' GROUP BY b.author,b.signer,p.tip,p.author,p.sequence",
            [id, after, through],
        ).await?).await?;
        for record in records {
            let [
                SqlValue::Integer(author),
                SqlValue::Blob(signer),
                SqlValue::Integer(sequence),
                SqlValue::Blob(tip),
                SqlValue::Integer(frame_author),
                SqlValue::Integer(frame_sequence),
            ] = record.as_slice()
            else {
                return Err(Error::Corrupt("birth position prefix".into()));
            };
            // As replay sees it: a frame written on an ancestor tip past
            // the seal the path leaves it at is not in the target's state.
            if let Some(graph) = self.graphs.get(&scope.domain) {
                let source = TipId(checkpoint::row_of(tip)?);
                let path = match paths.entry(source) {
                    std::collections::hash_map::Entry::Occupied(path) => path.into_mut(),
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(Self::frame_path(graph, source, target)?)
                    }
                };
                if !path.admits(
                    u32::try_from(*frame_author)
                        .map_err(|_| Error::Corrupt("birth position frame author".into()))?,
                    u64::try_from(*frame_sequence)
                        .map_err(|_| Error::Corrupt("birth position frame sequence".into()))?,
                )? {
                    continue;
                }
            }
            let signer = match signers.get(signer) {
                Some(key) => *key,
                None => {
                    let key = checkpoint::key_of(signer)?;
                    signers.insert(signer.clone(), key);
                    key
                }
            };
            ledger.merge(checkpoint::IdentityMark {
                author: u32::try_from(*author)
                    .map_err(|_| Error::Corrupt("birth position author".into()))?,
                signer,
                sequence: u32::try_from(*sequence)
                    .map_err(|_| Error::Corrupt("birth position sequence".into()))?,
            })?;
        }
        for record in collect_rows(self.conn.query(
            "SELECT b.author,b.signer,b.sequence,o.header,o.body FROM secure_birth_positions b JOIN secure_applied a ON a.position=b.position JOIN secure_operations o ON o.hash=a.hash WHERE b.scope=? AND b.position>? AND b.position<=? AND o.status='held'", [id,after,through],
        ).await?).await? {
            let [SqlValue::Integer(author), SqlValue::Blob(signer), SqlValue::Integer(sequence), SqlValue::Blob(header), SqlValue::Blob(body)] = record.as_slice() else { return Err(Error::Corrupt("held birth position".into())) };
            let frame = self.chained_frame(header.clone(), body.clone()).await?;
            let operation = frame.operation_ref()?;
            let e = &operation.header.extensions;
            let visible = match self.graphs.get(&scope.domain) {
                Some(graph) => self.visible_frame(graph, e.tip, e.author.ok_or_else(|| Error::Corrupt("held frame author".into()))?, e.author_sequence, target)?,
                None => true,
            };
            if !self.replay_eligible("held", operation, false)? || !visible { continue; }
            ledger.merge(checkpoint::IdentityMark {
                author: u32::try_from(*author).map_err(|_| Error::Corrupt("birth position author".into()))?,
                signer: checkpoint::key_of(signer)?,
                sequence: u32::try_from(*sequence).map_err(|_| Error::Corrupt("birth position sequence".into()))?,
            })?;
        }
        self.tip_frontiers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replay_ledger = Some(frontiers::ReplayLedger {
            id,
            target,
            base: base_position,
            through,
            ledger: ledger.clone(),
        });
        Ok(ledger)
    }
}
impl<A: RowApplication> Inner<A> {
    /// Storage identities are read in the authenticated source schema, even
    /// while this workspace filters its table or fields out.
    pub(in crate::replica) fn frame_positions(
        &self,
        frame: &EncryptedFrame,
        payload: &RowPayload,
    ) -> Result<(BTreeSet<Commitment>, Vec<checkpoint::IdentityMark>), Error> {
        // An intent writes no row images.
        if payload.writes().is_empty() {
            return Ok(Default::default());
        }
        let manifest = self.manifest_of_tip(frame.operation_ref()?.header.extensions.tip)?;
        let owned;
        let application: &dyn RowApplication = if manifest == self.manifest {
            self.app.as_ref()
        } else {
            let definition = self
                .catalog
                .get(&manifest)
                .ok_or_else(|| denied("source tip schema is not installed"))?;
            owned = self
                .app
                .source_application(definition)
                .map_err(Error::Incompatible)?;
            if owned.manifest().hash() != manifest {
                return Err(Error::Incompatible(
                    "source validator has a different manifest".into(),
                ));
            }
            owned.as_ref()
        };
        let mut rows = BTreeSet::new();
        let mut births = Vec::new();
        for write in payload.writes() {
            let identity = application
                .row_identity(&write.change)
                .map_err(|message| denied(&message))?;
            rows.insert(match identity {
                Some(id) => {
                    rocky_core::commitment("rocky.row-incarnation.v2", &id.integer().to_le_bytes())
                }
                None => write.change.row,
            });
            if write.change.before.is_none()
                && payload.carried(&write.change.row).is_none()
                && let Some(identity) = identity
            {
                births.push(checkpoint::IdentityMark {
                    author: identity.author(),
                    signer: frame.operation_ref()?.header.public_key,
                    sequence: identity.sequence(),
                });
            }
        }
        Ok((rows, births))
    }
}

impl<A: RowApplication> Inner<A> {
    pub(in crate::replica) async fn note_row_positions(
        &self,
        id: i64,
        frame: &EncryptedFrame,
        payload: &RowPayload,
    ) -> Result<(), Error> {
        let operation = frame.operation_ref()?;
        let (positions, births) = self.frame_positions(frame, payload)?;
        for birth in births {
            self.conn.execute("INSERT INTO secure_birth_positions SELECT ?,position,?,?,? FROM secure_applied WHERE hash=? ON CONFLICT(scope,position,author) DO UPDATE SET sequence=MAX(sequence,excluded.sequence)", bindings(vec![SqlValue::Integer(id), SqlValue::Integer(i64::from(birth.author)), SqlValue::Blob(birth.signer.as_bytes().to_vec()), SqlValue::Integer(i64::from(birth.sequence)), SqlValue::Blob(operation.hash.as_bytes().to_vec())])).await?;
        }

        for row in positions {
            self.conn.execute(
                "INSERT OR IGNORE INTO secure_row_positions SELECT ?,?,position FROM secure_applied WHERE hash=?",
                bindings(vec![SqlValue::Integer(id), SqlValue::Blob(row.to_vec()), SqlValue::Blob(operation.hash.as_bytes().to_vec())]),
            ).await?;
        }
        Ok(())
    }
}
