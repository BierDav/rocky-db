//! Eager local schema publication; migration programs never enter the catalog.
use super::*;
use crate::{
    schema::{MigrationStep, Schema},
    tip_schemas::Record,
};
use rocky_credentials::{
    SEAL_FORMAT, SealAction, SealStatement, SignedSeal, SignedTipOpening, TIP_OPENING_FORMAT,
    TipOpeningStatement,
};
use rocky_secure::{SchemaStage, TipStatement};
use std::collections::BTreeSet;

impl Node {
    pub(crate) async fn publish_schema_at_open(
        &self,
        confirmation: Option<&str>,
    ) -> Result<(), Failure> {
        if self.replica.staged_schema().await?.is_some() {
            self.follow_schema().await?;
            return self.run_staged_migration().await;
        }
        let Some((scope, bookmark)) = self.replica.followed_bookmark().await else {
            return Ok(());
        };
        let settings = self.settings.lock().await.clone();
        if settings.application(&self.declared)? != crate::DeclaredSchema::Ahead {
            return Ok(());
        }
        let Ok(signer) = self.tip_signer(scope).await else {
            return Ok(());
        };
        let source = self.replica.followed_tip().await;
        let graph = self.replica.tip_graph(scope).await?;
        if graph.bookmark(&bookmark)? != Some(source) || graph.seal(source)?.is_some() {
            return Ok(());
        }
        crate::rollout::confirm(&settings, &self.path, &self.declared, confirmation).await?;
        let migrates = crate::generation::migrates(&self.declared, settings.generation);
        if migrates && !settings.may_migrate(&self.domain())? {
            return Ok(());
        }
        let domain = crate::domain::Domain::at(
            &self.declared,
            *settings.publisher.as_bytes(),
            settings.mesh,
            settings.domain,
            self.declared.version,
        )?;
        let seal = SignedSeal::endorse(
            SealStatement {
                format: SEAL_FORMAT,
                scope,
                tip: source,
                frontier: self.replica.seal_frontier(scope, migrates).await?,
                action: if migrates {
                    SealAction::Close
                } else {
                    SealAction::Continue {
                        schema: domain.manifest().hash(),
                    }
                },
                recovery: None,
            },
            &*signer.identity,
            &signer.links,
        )?;
        let mut statements = vec![TipStatement::Seal(seal.clone())];
        let target = if migrates {
            let minimum = graph
                .line_minimum(source)?
                .ok_or("set the source line's signed minimum before migration")?;
            let opening = SignedTipOpening::endorse(
                TipOpeningStatement {
                    format: TIP_OPENING_FORMAT,
                    scope,
                    seal: seal.id()?,
                    schema: domain.manifest().hash(),
                    minimum_in_sync: u32::try_from(minimum)?,
                },
                &*signer.identity,
                &signer.links,
            )?;
            let target = opening.tip()?;
            statements.push(TipStatement::Opening(opening));
            target
        } else {
            seal.successor()?.ok_or("continuation has no successor")?
        };
        statements.push(Self::bookmark_move(
            &signer,
            scope,
            &bookmark,
            Some(source),
            Some(target),
        )?);
        if !migrates && self.replica.domain_log().is_some() {
            // A continue carries no migration rows. Its ordinary terminal
            // settles while the original workspace still follows the source.
            match self.replica.publish_tip_statements(&statements).await {
                Ok(_) => {}
                Err(error)
                    if error.to_string().contains("unconfirmed")
                        || error.to_string().contains("behind:")
                        || error.to_string().contains("coordinator_unavailable") =>
                {
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            }
            self.replica
                .install_tip_schema(
                    target,
                    domain.manifest(),
                    Record::new(&self.declared, self.declared.version).bytes()?,
                )
                .await?;
            self.follow_schema().await?;
            self.finalize_seals().await;
            return Ok(());
        }
        let mut parents = BTreeSet::new();
        for migration in self.declared.migrations.iter().filter(|migration| {
            migration.version > settings.generation && migration.version <= self.declared.version
        }) {
            for step in &migration.statements {
                let sql = match step {
                    MigrationStep::Sql(sql) => sql,
                    MigrationStep::Insert { select, .. } => select,
                };
                let analyzed = rocky_storage::statement::analyze_migration(sql, |name| {
                    name.strip_prefix("parent.").map(str::to_owned)
                })
                .map_err(|error| format!("migration statement: {error:?}"))?;
                parents.extend(
                    analyzed
                        .tables
                        .into_iter()
                        .filter_map(|name| name.strip_prefix("parent.").map(str::to_owned)),
                );
            }
        }
        let publication = rocky_core::commitment("rocky.sdk.migration.v3", &target.0);
        self.replica
            .stage_schema(SchemaStage {
                publication,
                scope,
                bookmark,
                source,
                target,
                from_version: settings.generation,
                coordinated: self.replica.domain_log().is_some(),
                statements,
                program: serde_json::to_vec(&self.declared)?,
                parents: parents.into_iter().collect(),
            })
            .await?;
        self.replica
            .install_tip_schema(
                target,
                domain.manifest(),
                Record::new(&self.declared, self.declared.version).bytes()?,
            )
            .await?;
        self.follow_schema().await?;
        self.run_staged_migration().await
    }

    /// Finish publication only after the closing base is signed and listed.
    /// Persisted graph statements and bases are the retry journal.
    pub(super) async fn close_migrations(&self) -> Result<(), Failure> {
        let publications = self.replica.publications().await?;
        if publications.is_empty()
            || publications
                .iter()
                .any(|publication| publication.published < publication.bundles)
        {
            return Ok(());
        }
        let scope = self.domain().scope;
        let graph = self.replica.tip_graph(scope).await?;
        let followed = self.replica.followed_tip().await;
        // A losing publication must first adopt the bookmark's winner.
        // Sealing its old workspace would prevent the sync that fetches it.
        if let Some((_, name)) = self.replica.followed_bookmark().await
            && graph.bookmark(&name)? != Some(followed)
        {
            return Ok(());
        }
        let mut pending = false;
        let mut needs_seal = false;
        for publication in publications {
            if self
                .replica
                .migration_checkpoint_listed(publication.id)
                .await?
            {
                continue;
            }
            let Some(migration) = self.replica.migration_publication(publication.id).await? else {
                continue;
            };
            if migration.statement.tip != followed
                && !graph.succeeds(migration.statement.tip, followed)?
            {
                continue;
            }
            pending = true;
            let mut covered = false;
            for seal in &graph.seals {
                if seal.successor()? != Some(followed) {
                    continue;
                }
                if graph.schema(seal.statement.tip).is_err() {
                    continue;
                }
                if seal.statement.action
                    != (SealAction::Continue {
                        schema: graph.schema(seal.statement.tip)?,
                    })
                {
                    continue;
                }
                if graph
                    .seal(seal.statement.tip)?
                    .is_some_and(|winner| winner.id().ok() == seal.id().ok())
                    && (migration.statement.tip == seal.statement.tip
                        || graph.succeeds(migration.statement.tip, seal.statement.tip)?)
                    && (seal.statement.tip == followed
                        || graph.succeeds(seal.statement.tip, followed)?)
                {
                    covered = true;
                    break;
                }
            }
            needs_seal |= !covered;
        }
        if !pending {
            return Ok(());
        }
        if needs_seal {
            self.seal_followed(scope, false).await?;
        }
        self.replica.finalize_path(scope).await?;
        self.replica.compact(scope, 0).await?;
        self.list_checkpoints(scope).await?;
        self.observations.touch();
        Ok(())
    }

    async fn run_staged_migration(&self) -> Result<(), Failure> {
        let Some((stage, committed)) = self.replica.staged_schema().await? else {
            return Ok(());
        };
        if committed {
            return self.endorse_migration(&stage).await;
        }
        self.ensure_tip_node().await?;
        // The program of replayed tables ran and committed; its bundles
        // continue from their cursor and it never runs again.
        if self.replica.publication_staged(stage.publication).await? {
            self.replica
                .author_staged_publication(stage.publication)
                .await?;
            return self.endorse_migration(&stage).await;
        }
        let program = Schema::parse(std::str::from_utf8(&stage.program)?)?;
        // Every granted scope but the registry: the migration may read and
        // write every partition the issuer holds.
        let scopes = {
            let settings = self.settings.lock().await;
            let domain = self.domain();
            settings
                .granted(&domain)
                .into_iter()
                .filter(|scope| *scope != domain.registry())
                .collect()
        };
        let sql = self
            .replica
            .session(scopes)
            .await?
            .migration_sql(
                stage.publication,
                rocky_storage::sql::SqlOptions {
                    captured_rows: usize::MAX,
                    captured_bytes: usize::MAX,
                    statement_budget: rocky_storage::sql::MAX_TRANSACTION_TIMEOUT,
                    transaction_timeout: rocky_storage::sql::MAX_TRANSACTION_TIMEOUT,
                    ..Default::default()
                },
            )
            .await?;
        sql.run("BEGIN", vec![]).await?;
        for migration in program.migrations.iter().filter(|migration| {
            migration.version > stage.from_version && migration.version <= program.version
        }) {
            for (number, step) in migration.statements.iter().enumerate() {
                let ran = match step {
                    MigrationStep::Sql(statement) => sql.run(statement, vec![]).await.map(|_| ()),
                    MigrationStep::Insert { insert, select } => {
                        crate::database::insert_rows(&sql, self.domain().logical(), insert, select)
                            .await
                    }
                };
                if let Err(error) = ran {
                    sql.cancel().await;
                    drop(sql);
                    // Nothing of the stage left the device: it is withdrawn,
                    // and a later application stages its own.
                    self.withdraw_stage(&stage).await?;
                    return Err(format!(
                        "migration to version {} failed at statement {}: {error}",
                        migration.version,
                        number + 1
                    )
                    .into());
                }
            }
        }
        sql.commit_publication(stage.publication).await?;
        drop(sql);
        self.replica
            .author_staged_publication(stage.publication)
            .await?;
        self.endorse_migration(&stage).await
    }

    async fn endorse_migration(&self, stage: &SchemaStage) -> Result<(), Failure> {
        if let Some((statement, writer)) = self.replica.migration_intent(stage.publication).await? {
            let signer = self.tip_signer(stage.scope).await?;
            let signed = rocky_credentials::SignedMigrationPublication::endorse(
                statement,
                &*signer.identity,
                &signer.links,
                writer,
            )?;
            self.replica.admit_migration_publication(signed).await?;
        }
        if !stage.coordinated {
            self.replica
                .release_uncoordinated_schema(stage.publication)
                .await?;
            self.finalize_seals().await;
        }
        Ok(())
    }

    /// Switches back to the stage's source tip and its schema, saving the
    /// intent first so a crash resumes on whichever side committed.
    async fn withdraw_stage(&self, stage: &SchemaStage) -> Result<(), Failure> {
        let manifest = self
            .replica
            .tip_graph(stage.scope)
            .await?
            .schema(stage.source)?;
        let bytes = self
            .replica
            .tip_schema(manifest)
            .await?
            .ok_or("the source tip's schema record is missing")?;
        let record = Record::parse(&bytes)?;
        let mut settings = self.settings.lock().await;
        let domain = record.domain(&settings, manifest)?;
        let mut draft = (**settings).clone();
        draft.pending = Some(crate::tip_schemas::Pending {
            tip: stage.source,
            manifest,
        });
        draft.save(&self.path)?;
        draft.schema = record.schema;
        draft.generation = record.generation;
        draft.prepare_schema(&self.vault, &domain)?;
        self.replica
            .withdraw_staged_schema(
                stage.publication,
                domain.app.clone(),
                rocky_secure::SchemaConfig {
                    security: draft.config(&self.vault, &domain)?,
                    tables: Some((domain.logical().clone(), domain.scope, domain.readers())),
                },
            )
            .await?;
        crate::database::attach(&self.replica, &mut draft, &self.vault, &domain, &self.path)
            .await?;
        crate::database::retain(&self.replica, &draft, &domain).await?;
        draft.pending = None;
        draft.save(&self.path)?;
        *self.granted.lock().map_err(|_| "scope catalog poisoned")? = draft.granted(&domain);
        *self.domain.write().map_err(|_| "domain catalog poisoned")? = Arc::new(domain);
        *settings = Shared::new(draft);
        drop(settings);
        self.try_ensure_tip_node().await;
        Ok(())
    }
}
