//! Projection plans: a typed schema change is recorded, then recreates its
//! replayed tables from the installed rows in one transaction. A plan
//! interrupted before its switch finishes when the replica opens again.
use super::typed::{Typed, quoted};
use super::*;
use rocky_core::{LogicalSchema, SchemaChange, Scope, TableClass};

pub(super) const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS secure_projection_plan(id INTEGER PRIMARY KEY CHECK(id=1),descriptor BLOB NOT NULL,domain BLOB NOT NULL,readers BLOB NOT NULL)",
];

/// A pending projection plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionPlan {
    /// The fingerprint of the schema being installed.
    pub schema: Commitment,
    pub tables: usize,
}

struct Record {
    schema: LogicalSchema,
    domain: Scope,
    readers: BTreeMap<String, Commitment>,
}

impl<A: RowApplication> Inner<A> {
    async fn plan_record(&self) -> Result<Option<Record>, Error> {
        let stored = rows(
            &self.conn,
            "SELECT descriptor,domain,readers FROM secure_projection_plan WHERE id=1",
        )
        .await?;
        let Some(row) = stored.first() else {
            return Ok(None);
        };
        let [
            SqlValue::Blob(descriptor),
            SqlValue::Blob(domain),
            SqlValue::Blob(readers),
        ] = row.as_slice()
        else {
            return Err(Error::Corrupt("projection plan record".into()));
        };
        Ok(Some(Record {
            schema: LogicalSchema::parse(descriptor)
                .map_err(|_| Error::Corrupt("projection plan descriptor".into()))?,
            domain: decode(domain)?,
            readers: decode(readers)?,
        }))
    }
    /// The installed typed descriptor, domain and readers.
    pub(super) async fn installed_typed(
        &self,
    ) -> Result<Option<(LogicalSchema, Scope, BTreeMap<String, Commitment>)>, Error> {
        let stored = rows(
            &self.conn,
            "SELECT descriptor,domain,readers FROM secure_typed WHERE id=1",
        )
        .await?;
        let Some(row) = stored.first() else {
            return Ok(None);
        };
        let [
            SqlValue::Blob(descriptor),
            SqlValue::Blob(domain),
            SqlValue::Blob(readers),
        ] = row.as_slice()
        else {
            return Err(Error::Corrupt("typed table record".into()));
        };
        Ok(Some((
            LogicalSchema::parse(descriptor)
                .map_err(|_| Error::Corrupt("typed table descriptor".into()))?,
            decode(domain)?,
            decode(readers)?,
        )))
    }
    /// Checks that `schema` may replace the installed typed tables and
    /// records the plan, inside the caller's transaction. The identical plan
    /// is kept with its progress; another one pending is refused.
    pub(super) async fn record_plan(
        &self,
        schema: &LogicalSchema,
        domain: Scope,
        readers: &BTreeMap<String, Commitment>,
    ) -> Result<(), Error> {
        self.record_plan_as(schema, domain, readers, false).await
    }
    /// `record_plan`; `rebuild` projects again an unchanged schema, as after
    /// a tip switch whose path filtered stored rows.
    pub(super) async fn record_plan_as(
        &self,
        schema: &LogicalSchema,
        domain: Scope,
        readers: &BTreeMap<String, Commitment>,
        rebuild: bool,
    ) -> Result<(), Error> {
        let incompatible = |reason: String| Error::Incompatible(reason);
        let descriptor = schema
            .canonical()
            .map_err(|error| incompatible(error.to_string()))?;
        if let Some(pending) = self.plan_record().await? {
            if pending.schema == *schema && pending.domain == domain && pending.readers == *readers
            {
                return Ok(());
            }
            return Err(incompatible(
                "another projection plan is pending; reopen to finish it first".into(),
            ));
        }
        let Some((installed, installed_domain, installed_readers)) = self.installed_typed().await?
        else {
            return Err(incompatible("no typed tables are installed".into()));
        };
        // A removed table leaves; every table that stays keeps its reader.
        if installed_domain != domain
            || installed_readers.iter().any(|(name, reader)| {
                readers.get(name).is_some_and(|new| new != reader)
                    || (readers.get(name).is_none() && schema.table(name).is_some())
            })
        {
            return Err(incompatible(
                "a projection plan keeps the domain and reader scopes".into(),
            ));
        }
        match rocky_core::classify(&installed, schema)
            .map_err(|refusal| incompatible(refusal.to_string()))?
        {
            SchemaChange::Unchanged if !rebuild => return Ok(()),
            SchemaChange::Unchanged => {}
            SchemaChange::Local | SchemaChange::Replicated => {}
        }
        // Local tables hold application data no stored row restores: they
        // stay in place.
        for table in installed
            .tables
            .iter()
            .filter(|table| table.class == TableClass::LocalOnly)
        {
            if schema
                .table(&table.sql_name)
                .is_none_or(|new| new.class != table.class || new.create_sql != table.create_sql)
            {
                return Err(incompatible(format!(
                    "local table {} must stay as it is; only its indexes may change",
                    table.sql_name
                )));
            }
        }
        self.conn
            .execute(
                "INSERT INTO secure_projection_plan VALUES(1,?,?,?)",
                bindings(vec![
                    SqlValue::Blob(descriptor),
                    SqlValue::Blob(encode(&domain)?),
                    SqlValue::Blob(encode(readers)?),
                ]),
            )
            .await?;
        Ok(())
    }
    /// Whether a table of `typed`, the authorized projection of the
    /// installed schema, is not projected yet: a widened grant or an
    /// adopted generation made it readable.
    pub(super) async fn projection_grew(&self, typed: &Typed) -> Result<bool, Error> {
        for table in &typed.tables {
            let mut found = self
                .conn
                .query(
                    "SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1 COLLATE NOCASE",
                    [table.table.sql_name.clone()],
                )
                .await?;
            if found.next().await?.is_none() {
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// Records a plan that rebuilds the installed schema, inside the
    /// caller's transaction, so that tables its grants now cover are
    /// projected; a plan already pending covers them too.
    pub(super) async fn record_growth(&self) -> Result<(), Error> {
        if self.plan_record().await?.is_some() {
            return Ok(());
        }
        self.conn
            .execute(
                "INSERT INTO secure_projection_plan SELECT 1,descriptor,domain,readers FROM secure_typed WHERE id=1",
                (),
            )
            .await?;
        Ok(())
    }
    /// Drops the pending plan inside the caller's transaction.
    pub(super) async fn discard_plan(&mut self) -> Result<(), Error> {
        self.conn
            .execute("DELETE FROM secure_projection_plan", ())
            .await?;
        Ok(())
    }
    /// The pending plan's progress.
    pub(super) async fn plan_status(&self) -> Result<Option<ProjectionPlan>, Error> {
        let Some(record) = self.plan_record().await? else {
            return Ok(None);
        };
        Ok(Some(ProjectionPlan {
            schema: record
                .schema
                .fingerprint()
                .map_err(|error| Error::Corrupt(error.to_string()))?,
            tables: record.schema.typed().count(),
        }))
    }
    /// Switches to the pending plan's tables in one transaction.
    pub(super) async fn finish_plan(&mut self) -> Result<(), Error> {
        let Some(record) = self.plan_record().await? else {
            return Ok(());
        };
        let intent = self.schema_switch_intent().await?;
        if let Some((scope, _, _, target)) = intent
            && self
                .graph_for(scope)?
                .schema_any(target)
                .map_err(credential)?
                != self.manifest
        {
            return Err(denied(
                "a staged schema switch resumes only with its target schema",
            ));
        }
        // Values of fields some tip on the switch's path lacks are gone.
        let path = match intent {
            Some((scope, ..)) => self.staged_row_fields(scope).await?,
            None => None,
        };
        let installed = self
            .installed_typed()
            .await?
            .ok_or_else(|| Error::Corrupt("a projection plan without typed tables".into()))?
            .0;
        #[cfg(test)]
        if std::mem::take(&mut self.plan_fault) {
            return Err(Error::InjectedFailure);
        }
        let projected = Arc::new(
            self.authorized_projection(Typed::new(
                record.schema.clone(),
                record.domain,
                &record.readers,
            )?)
            .await?,
        );
        // Resolution reads the installed projection.
        let previous = self.workspace.typed.replace(projected.clone());
        let switched = transaction!(self, |inner| {
            let switching = match &previous {
                Some(old) => inner.begin_switch_history(old, &projected).await?,
                None => None,
            };
            for table in removed_replayed(&installed, &record.schema) {
                inner.touch(&table.sql_name);
                inner
                    .conn
                    .execute(
                        format!("DROP TABLE IF EXISTS {}", quoted(&table.sql_name)),
                        (),
                    )
                    .await?;
            }
            inner.record_projection_access(&projected).await?;
            let mut replayed = Vec::new();
            for table in record.schema.tables.iter().filter(|table| {
                table.class == TableClass::LocalOnly || projected.by_name(&table.sql_name).is_some()
            }) {
                inner.touch(&table.sql_name);
                match table.class {
                    TableClass::Replayed => replayed.push(table),
                    TableClass::LocalOnly => inner.replace_indexes(&installed, table).await?,
                }
            }
            inner
                .rebuild_replayed(&installed, &record.schema, &replayed, path.as_ref())
                .await?;
            inner.install_delete_triggers(&projected).await?;
            inner.reshape_undo(&installed, &record.schema).await?;
            inner.install_history().await?;
            inner.end_switch_history(&projected, switching).await?;
            inner.finish_switch(&record).await
        });
        if let Err(error) = switched {
            self.abandon_switch_history();
            self.workspace.typed = previous;
            return Err(error);
        }
        self.start_events();
        self.bump_authority();
        self.publish_revision().await?;
        Ok(())
    }
    /// A local table keeps its rows; only its indexes
    /// follow the new schema.
    async fn replace_indexes(
        &self,
        installed: &LogicalSchema,
        table: &rocky_core::LogicalTable,
    ) -> Result<(), Error> {
        let before = installed.table(&table.sql_name);
        if before.is_none() {
            self.conn.execute(table.create_sql.clone(), ()).await?;
        }
        let had = |name: &str, sql: &str| {
            before.is_some_and(|before| {
                before
                    .indexes
                    .iter()
                    .any(|index| index.name == name && index.create_sql == sql)
            })
        };
        for index in before.iter().flat_map(|before| &before.indexes) {
            if !table
                .indexes
                .iter()
                .any(|new| new.name == index.name && new.create_sql == index.create_sql)
            {
                self.conn
                    .execute(format!("DROP INDEX {}", quoted(&index.name)), ())
                    .await?;
            }
        }
        for index in &table.indexes {
            if !had(&index.name, &index.create_sql) {
                self.conn.execute(index.create_sql.clone(), ()).await?;
            }
        }
        Ok(())
    }
    /// Records the new tables as installed and ends the plan.
    async fn finish_switch(&mut self, record: &Record) -> Result<(), Error> {
        let descriptor = record
            .schema
            .canonical()
            .map_err(|error| Error::Incompatible(error.to_string()))?;
        self.conn
            .execute(
                "UPDATE secure_typed SET descriptor=?,domain=?,readers=? WHERE id=1",
                bindings(vec![
                    SqlValue::Blob(descriptor),
                    SqlValue::Blob(encode(&record.domain)?),
                    SqlValue::Blob(encode(&record.readers)?),
                ]),
            )
            .await?;
        self.conn
            .execute("DELETE FROM secure_projection_plan", ())
            .await?;
        self.conn
            .execute(
                "UPDATE secure_metadata SET revision=revision+1 WHERE id=1",
                (),
            )
            .await?;
        self.cause(crate::observe::Cause::Rebuild);
        self.finish_schema_switch().await?;
        Ok(())
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// The pending projection plan, if a typed schema change is under way.
    pub async fn projection_plan(&self) -> Result<Option<ProjectionPlan>, Error> {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .plan_status()
            .await
    }
    pub(crate) async fn run_plan(&self) -> Result<(), Error> {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .finish_plan()
            .await
    }
    #[cfg(test)]
    /// Fails the next plan switch before its transaction.
    pub(crate) async fn fail_next_plan_switch(&self) {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .plan_fault = true;
    }
}

/// Replayed tables of `installed` that `schema` no longer declares.
fn removed_replayed<'a>(
    installed: &'a LogicalSchema,
    schema: &'a LogicalSchema,
) -> impl Iterator<Item = &'a rocky_core::LogicalTable> {
    installed.tables.iter().filter(|table| {
        table.class == TableClass::Replayed && schema.table(&table.sql_name).is_none()
    })
}
