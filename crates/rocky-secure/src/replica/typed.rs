//! Typed tables of a secure replica: the generated SQL storage that
//! authorized secure rows project into, in the same transaction as every
//! row change. See `docs/runtime/secure-sql.md`.
use super::*;
use crate::{capture::Plan, scoped_connection::Names};
use rocky_core::{LogicalSchema, Scope, TableClass, TypedRows, TypedTable};

pub(super) const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS secure_projection_access(id INTEGER PRIMARY KEY CHECK(id=1),tables BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS secure_typed(id INTEGER PRIMARY KEY CHECK(id=1),descriptor BLOB NOT NULL,domain BLOB NOT NULL,readers BLOB NOT NULL)",
];

/// One typed table and the resource scope its rows belong to.
#[derive(Clone)]
pub(super) struct Projected {
    pub(super) table: TypedTable,
    pub(super) scope: ResourceScope,
}
/// The installed typed tables of a replica.
pub(super) struct Typed {
    pub(super) rows: TypedRows,
    pub(super) domain: Scope,
    pub(super) tables: Vec<Projected>,
    /// Full signed declarations, including tables with no physical projection.
    pub(super) declarations: Vec<Projected>,
    pub(super) names: Names,
}
pub(super) fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
impl Typed {
    pub(super) fn new(
        schema: LogicalSchema,
        domain: Scope,
        readers: &BTreeMap<String, Commitment>,
    ) -> Result<Self, Error> {
        let incompatible = |reason: String| Error::Incompatible(reason);
        let rows = TypedRows::new(schema.clone(), vec![domain.domain])
            .map_err(|error| incompatible(error.to_string()))?;
        let mut tables = Vec::new();
        let typed: Vec<_> = rows.tables().collect();
        for table in typed.iter() {
            if schema.table(&table.sql_name).is_none() {
                return Err(incompatible(format!(
                    "{} is not in the schema",
                    table.sql_name
                )));
            }
            let encryption = readers
                .get(&table.sql_name)
                .ok_or_else(|| incompatible(format!("{} has no reader scope", table.sql_name)))?;
            tables.push(Projected {
                scope: ResourceScope {
                    domain,
                    encryption: *encryption,
                    table: table.id,
                },
                table: (*table).clone(),
            });
        }
        if readers.len() != typed.len() {
            return Err(incompatible("a reader scope names no typed table".into()));
        }
        let statements = statements(&schema);
        Ok(Self {
            names: Names::new(None, &statements),
            rows,
            domain,
            declarations: tables.clone(),
            tables,
        })
    }
    fn restrict(mut self, allowed: &BTreeSet<String>) -> Self {
        self.tables
            .retain(|table| allowed.contains(&table.table.sql_name));
        self
    }
    pub(super) fn statements(&self) -> Vec<String> {
        let schema = self.rows.schema();
        let mut statements: Vec<_> = schema
            .tables
            .iter()
            .filter(|table| self.installs(&table.sql_name))
            .flat_map(|table| {
                std::iter::once(table.create_sql.clone())
                    .chain(table.indexes.iter().map(|index| index.create_sql.clone()))
            })
            .collect();
        statements.extend(schema.delete_triggers(|name| self.installs(name)));
        statements
    }
    /// Whether this projection installs table `name`.
    pub(super) fn installs(&self, name: &str) -> bool {
        self.rows.schema().table(name).is_some_and(|table| {
            table.class == TableClass::LocalOnly || self.by_name(&table.sql_name).is_some()
        })
    }
    pub(super) fn partitioned(&self, table: &Projected) -> bool {
        self.rows
            .schema()
            .table(&table.table.sql_name)
            .is_some_and(|logical| !logical.partition_by.is_empty())
    }
    pub(super) fn row_scope(
        &self,
        table: &Projected,
        values: &[SqlValue],
    ) -> Result<ResourceScope, Error> {
        match self
            .rows
            .partition(&table.table, values)
            .map_err(|error| denied(&error))?
        {
            Some(tuple) => tuple
                .scope(self.domain, table.table.id)
                .map_err(|error| denied(&error.to_string())),
            None => Ok(table.scope),
        }
    }
    pub(super) fn by_scope(&self, scope: ResourceScope) -> Option<&Projected> {
        self.tables.iter().find(|table| {
            table.scope == scope
                || (self.partitioned(table)
                    && table.scope.domain == scope.domain
                    && table.scope.table == scope.table)
        })
    }
    pub(super) fn by_name(&self, sql_name: &str) -> Option<&Projected> {
        self.tables
            .iter()
            .find(|table| table.table.sql_name.eq_ignore_ascii_case(sql_name))
    }
    pub(super) fn declared_by_scope(&self, scope: ResourceScope) -> Option<&Projected> {
        self.declarations.iter().find(|table| {
            table.scope == scope
                || (self.partitioned(table)
                    && table.scope.domain == scope.domain
                    && table.scope.table == scope.table)
        })
    }
    /// The tables a session may name: every local table and the replayed
    /// tables of `scopes`.
    pub(super) fn plan(&self, scopes: &BTreeSet<ResourceScope>) -> Result<Plan, Error> {
        let schema = self.rows.schema();
        let named = |table: &rocky_core::LogicalTable| match self.by_name(&table.sql_name) {
            Some(projected) => {
                scopes.contains(&projected.scope)
                    || (self.partitioned(projected)
                        && scopes.iter().any(|scope| {
                            scope.domain == projected.scope.domain
                                && scope.table == projected.scope.table
                        }))
            }
            None => table.class == TableClass::LocalOnly,
        };
        let tables: Vec<&str> = schema
            .tables
            .iter()
            .filter(|table| named(table))
            .map(|table| table.sql_name.as_str())
            .collect();
        Plan::bound(&[crate::capture::Part {
            schema,
            names: &self.names,
            tables: Some(tables),
        }])
    }
}
pub(super) fn statements(schema: &LogicalSchema) -> Vec<String> {
    schema
        .tables
        .iter()
        .flat_map(|table| {
            std::iter::once(table.create_sql.clone())
                .chain(table.indexes.iter().map(|index| index.create_sql.clone()))
        })
        .collect()
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// Installs only tables covered by local read grants or partition selectors.
    /// The complete descriptor still has to match the signed manifest.
    pub async fn install_readable_tables(
        &self,
        schema: LogicalSchema,
        domain: Scope,
        readers: BTreeMap<String, Commitment>,
    ) -> Result<(), Error> {
        {
            let mut inner = self.inner.lock(crate::replica::Class::Background).await;
            inner.validate_typed(&schema, domain)?;
            let typed = Typed::new(schema.clone(), domain, &readers)?;
            let allowed = inner.readable_names(&typed)?;
            transaction!(inner, |inner| {
                let previous = inner.projection_access().await?;
                if previous.is_none() && inner.installed_typed().await?.is_some() {
                    return Err(Error::Incompatible("a complete projection cannot become a readable projection; reinstall the database".into()));
                }
                // Grants may widen, as a renewal adds a table granted like a
                // held one; the plan below projects it. They never narrow.
                if let Some(previous) = previous.as_ref()
                    && !previous.is_subset(&allowed)
                {
                    return Err(Error::Incompatible(
                        "projection grants changed; reinstall the database".into(),
                    ));
                }
                inner.conn.execute("INSERT INTO secure_projection_access VALUES(1,?) ON CONFLICT(id) DO UPDATE SET tables=excluded.tables", [encode(&allowed)?]).await?;
                Ok(())
            })?;
        }
        self.install_tables(schema, domain, readers).await
    }
    /// Installs typed tables for `schema` in `domain`; `readers` names the
    /// encryption scope of every mergeable table. The schema's manifest must
    /// be the replica's signed manifest. Existing rows project at once;
    /// reopening keeps the installation. Another schema of the same signed
    /// definition, such as new indexes, replaces it through a projection
    /// plan: shadow tables fill in bounded steps and switch in one verified
    /// transaction. Changes the definition does not allow are refused.
    pub async fn install_tables(
        &self,
        schema: LogicalSchema,
        domain: Scope,
        readers: BTreeMap<String, Commitment>,
    ) -> Result<(), Error> {
        schema
            .require_row_identity()
            .map_err(|error| Error::Incompatible(error.to_string()))?;
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        inner.validate_typed(&schema, domain)?;
        let typed = inner
            .authorized_projection(Typed::new(schema.clone(), domain, &readers)?)
            .await?;
        let record = [
            schema
                .canonical()
                .map_err(|error| Error::Incompatible(error.to_string()))?,
            encode(&domain)?,
            encode(&readers)?,
        ];
        let planned = transaction!(inner, |inner| {
            let stored = rows(
                &inner.conn,
                "SELECT descriptor,domain,readers FROM secure_typed WHERE id=1",
            )
            .await?;
            let expected: Vec<SqlValue> = record.iter().cloned().map(SqlValue::Blob).collect();
            match stored.first() {
                // Grants that widened over the same schema project the
                // tables they add through a plan, as another schema does.
                Some(row) if *row == expected => {
                    if inner.projection_grew(&typed).await? {
                        inner.record_growth().await?;
                        return Ok(true);
                    }
                    return Ok(false);
                }
                // Another schema of the same definition: rebuild the tables
                // through a projection plan.
                Some(_) => {
                    inner.record_plan(&schema, domain, &readers).await?;
                    return Ok(true);
                }
                None => {}
            }
            for sql in typed.statements() {
                inner.conn.execute(sql, ()).await?;
            }
            inner
                .conn
                .execute(
                    "INSERT INTO secure_typed VALUES(1,?,?,?)",
                    bindings(expected),
                )
                .await?;
            Ok(false)
        })?;
        if planned {
            drop(inner);
            return self.run_plan().await;
        }
        inner.workspace.typed = Some(Arc::new(typed));
        transaction!(inner, |inner| inner.install_history().await)?;
        inner.start_events();
        Ok(())
    }
}

impl<A: RowApplication> Inner<A> {
    fn validate_typed(&self, schema: &LogicalSchema, domain: Scope) -> Result<(), Error> {
        schema
            .require_row_identity()
            .map_err(|error| Error::Incompatible(error.to_string()))?;
        let domains: Vec<_> = self
            .definition
            .domains
            .iter()
            .map(|rule| rule.domain)
            .collect();
        if domain.app != self.definition.app || !domains.contains(&domain.domain) {
            return Err(denied("typed tables need a domain of the signed manifest"));
        }
        // The generation is the installed application's; the tables must be
        // exactly the signed ones.
        let expected = schema.manifest_at(&domains, self.definition.schema);
        if expected.hash() != self.manifest {
            return Err(Error::Incompatible(
                "the schema's definition differs from the signed manifest".into(),
            ));
        }
        if schema
            .tables
            .iter()
            .any(|table| table.sql_name.to_ascii_lowercase().starts_with("secure_"))
        {
            return Err(Error::Incompatible("secure_ names are reserved".into()));
        }
        Ok(())
    }
    async fn projection_access(&self) -> Result<Option<BTreeSet<String>>, Error> {
        let mut rows = self
            .conn
            .query("SELECT tables FROM secure_projection_access WHERE id=1", ())
            .await?;
        rows.next()
            .await?
            .map(|row| decode(&row.get::<Vec<u8>>(0)?))
            .transpose()
    }
    pub(super) fn readable_names(&self, typed: &Typed) -> Result<BTreeSet<String>, Error> {
        let (grants, selectors) = self
            .config
            .credentials
            .verify_selectors(
                self.config.publisher,
                self.config.node.public_key(),
                &self.config.revocations,
                now()?,
            )
            .map_err(credential)?;
        Ok(typed
            .tables
            .iter()
            .filter(|table| {
                grants
                    .iter()
                    .any(|grant| grant.scope == table.scope && grant.rights.contains(&Right::Read))
                    || selectors.iter().any(|grant| {
                        grant.domain == typed.domain
                            && grant.table == table.scope.table
                            && grant.rights.contains(&Right::Read)
                    })
            })
            .map(|table| table.table.sql_name.clone())
            .collect())
    }
    pub(super) async fn authorized_projection(&self, typed: Typed) -> Result<Typed, Error> {
        match self.projection_access().await? {
            Some(_) => {
                let allowed = self.readable_names(&typed)?;
                Ok(typed.restrict(&allowed))
            }
            None => Ok(typed),
        }
    }
    pub(super) async fn record_projection_access(&self, typed: &Typed) -> Result<(), Error> {
        if self.projection_access().await?.is_some() {
            let allowed: BTreeSet<String> = typed
                .tables
                .iter()
                .map(|table| table.table.sql_name.clone())
                .collect();
            self.conn
                .execute(
                    "UPDATE secure_projection_access SET tables=? WHERE id=1",
                    [encode(&allowed)?],
                )
                .await?;
        }
        Ok(())
    }
    /// Loads the installed typed tables at open.
    pub(super) async fn load_typed(&mut self) -> Result<(), Error> {
        let stored = rows(
            &self.conn,
            "SELECT descriptor,domain,readers FROM secure_typed WHERE id=1",
        )
        .await?;
        let Some(row) = stored.first() else {
            return Ok(());
        };
        let [
            SqlValue::Blob(descriptor),
            SqlValue::Blob(domain),
            SqlValue::Blob(readers),
        ] = row.as_slice()
        else {
            return Err(Error::Corrupt("typed table record".into()));
        };
        let schema = LogicalSchema::parse(descriptor)
            .map_err(|_| Error::Corrupt("typed table descriptor".into()))?;
        let typed = self
            .authorized_projection(Typed::new(schema, decode(domain)?, &decode(readers)?)?)
            .await?;
        self.workspace.typed = Some(Arc::new(typed));
        transaction!(self, |inner| inner.install_history().await)?;
        self.start_events();
        Ok(())
    }
    /// Empties a scope's typed table, as its rows are evicted.
    /// Replaces the `SET NULL` triggers with `typed`'s: a rebuilt parent
    /// drops its own.
    pub(super) async fn install_delete_triggers(&self, typed: &Typed) -> Result<(), Error> {
        for record in rows(
            &self.conn,
            &format!(
                "SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE '{}%'",
                rocky_core::DELETE_TRIGGERS
            ),
        )
        .await?
        {
            let [SqlValue::Text(name)] = record.as_slice() else {
                return Err(Error::Corrupt("delete trigger".into()));
            };
            self.conn
                .execute(format!("DROP TRIGGER IF EXISTS {}", quoted(name)), ())
                .await?;
        }
        for sql in typed
            .rows
            .schema()
            .delete_triggers(|name| typed.installs(name))
        {
            self.conn.execute(sql, ()).await?;
        }
        Ok(())
    }
    pub(crate) async fn clear_typed(&self, scope: ResourceScope) -> Result<(), Error> {
        if self.replayed_scope(scope) {
            return self.reset_replayed(scope).await;
        }
        self.require_declared(scope, "eviction")
    }
    /// Reindexes a scope's stored rows after a bulk change of
    /// `secure_row_records`. A replayed table's rows are its only copy.
    pub(super) async fn reproject(&self, scope: ResourceScope) -> Result<(), Error> {
        if self.replayed_scope(scope) {
            return Ok(());
        }
        self.index_row_keys().await?;
        self.reindex_move_scope(scope).await?;
        self.require_declared(scope, "rebuild")
    }
    /// Typed tables are replayed: a stored-row scope of a typed schema is
    /// one whose table this replica may not read.
    fn require_declared(&self, scope: ResourceScope, purpose: &str) -> Result<(), Error> {
        if self
            .workspace
            .typed
            .as_ref()
            .is_some_and(|typed| typed.declared_by_scope(scope).is_none())
        {
            return Err(Error::Corrupt(format!("missing typed scope for {purpose}")));
        }
        Ok(())
    }
}
