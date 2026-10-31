//! Tip-authenticated schema definitions and the records supplied by a language adapter.
use super::headers::HeaderSource;
use super::*;
use rocky_core::{ApplicationManifest, Scope};
use rocky_credentials::TipGraph;

pub(super) const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS secure_tip_schemas(manifest BLOB PRIMARY KEY,definition BLOB NOT NULL,record BLOB NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_schema_switch(id INTEGER PRIMARY KEY CHECK(id=1),scope BLOB NOT NULL,bookmark TEXT NOT NULL,source BLOB NOT NULL,target BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS secure_pending_schema(id INTEGER PRIMARY KEY CHECK(id=1),scope BLOB NOT NULL,bookmark TEXT NOT NULL,tip BLOB NOT NULL,manifest BLOB NOT NULL,moved INTEGER NOT NULL CHECK(moved IN (0,1)))",
];

/// Rows SQLite inserted, updated or deleted in the last in-place switch's
/// transaction, for the zero-rewrite gate; -1 before any.
static IN_PLACE_SWITCH_CHANGES: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(-1);
/// Test instrumentation: the row changes of this process's last in-place
/// schema switch, which must not grow with the stored rows.
#[doc(hidden)]
pub fn last_in_place_switch_changes() -> i64 {
    IN_PLACE_SWITCH_CHANGES.load(std::sync::atomic::Ordering::SeqCst)
}
async fn total_changes(conn: &ScopedConnection) -> Result<i64, Error> {
    match rows(conn, "SELECT total_changes()")
        .await?
        .first()
        .map(Vec::as_slice)
    {
        Some([SqlValue::Integer(changes)]) => Ok(*changes),
        _ => Err(Error::Corrupt("total changes".into())),
    }
}
/// A durable intent to switch the live workspace after obtaining its schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingSchema {
    pub scope: Scope,
    pub bookmark: String,
    pub tip: TipId,
    pub manifest: Commitment,
}

/// The followed tip a replica file committed, with its authenticated schema.
#[derive(Clone, Debug)]
pub struct InstalledTipSchema {
    pub tip: TipId,
    pub manifest: Commitment,
    pub record: Vec<u8>,
    /// Whether `tip` is the asked-for tip or continues from it along the
    /// winning seal chain.
    pub continues: bool,
}

/// Reads the authenticated installed tip record before an adapter resumes a
/// switch whose database commit preceded its settings-file commit; `from`
/// is the tip the adapter's pending switch named.
pub async fn installed_tip_schema(
    path: &Path,
    scope: Scope,
    publisher: PublicKey,
    from: Option<TipId>,
) -> Result<Option<InstalledTipSchema>, Error> {
    check_replica_format(path).await?;
    if !path.exists() {
        return Ok(None);
    }
    let conn = ScopedConnection::new(
        crate::sqlite::Connection::open_read_only(path)?,
        None,
        SCHEMA,
    );
    let records = rows(
        &conn,
        "SELECT scope,tip FROM secure_followed_tip WHERE id=1",
    )
    .await?;
    let Some([SqlValue::Blob(domain), SqlValue::Blob(tip)]) = records.first().map(Vec::as_slice)
    else {
        return Ok(None);
    };
    if decode::<Scope>(domain)? != scope {
        return Err(denied("installed tip scope mismatch"));
    }
    let tip: TipId = decode(tip)?;
    let roots = collect_rows(
        conn.query(
            "SELECT genesis FROM secure_tip_graphs WHERE scope=?",
            [domain.clone()],
        )
        .await?,
    )
    .await?;
    let Some([SqlValue::Blob(root)]) = roots.first().map(Vec::as_slice) else {
        return Err(Error::Corrupt("installed tip root".into()));
    };
    let root = checkpoint::row_of(root)?;
    let mut graph = rocky_credentials::TipGraph::new(scope, root);
    let mut statements = Vec::new();
    for row in rows(&conn, "SELECT statement FROM secure_tip_statements").await? {
        let [SqlValue::Blob(bytes)] = row.as_slice() else {
            return Err(Error::Corrupt("installed tip statement".into()));
        };
        let statement: TipStatement = decode(bytes)?;
        if statement.scope() == scope {
            statement.append(&mut graph);
            statements.push(statement);
        }
    }
    for statement in statements {
        statement.verify(publisher, &graph, None)?;
    }
    let manifest = graph.schema_any(tip).map_err(credential)?;
    let records = collect_rows(
        conn.query(
            "SELECT definition,record FROM secure_tip_schemas WHERE manifest=?",
            [manifest.to_vec()],
        )
        .await?,
    )
    .await?;
    let Some([SqlValue::Blob(definition), SqlValue::Blob(record)]) =
        records.first().map(Vec::as_slice)
    else {
        return Err(Error::Corrupt("installed tip schema".into()));
    };
    if ApplicationManifest::from_body(definition)
        .map_err(|error| Error::Corrupt(error.to_string()))?
        .hash()
        != manifest
    {
        return Err(Error::Corrupt("installed tip commitment".into()));
    }
    let continues =
        from.is_some_and(|from| from == tip || graph.continues(from, tip).unwrap_or(false));
    Ok(Some(InstalledTipSchema {
        tip,
        manifest,
        record: record.clone(),
        continues,
    }))
}

/// Fields present at every tip between a source and the live workspace.
#[derive(Clone, Debug)]
pub(super) struct PathFields {
    pub tables: BTreeSet<Commitment>,
    pub fields: BTreeSet<Commitment>,
}
impl PathFields {
    pub(super) fn strips(&self, definition: &ApplicationManifest) -> bool {
        definition
            .entities
            .iter()
            .any(|table| !self.tables.contains(&table.id))
            || definition
                .fields
                .iter()
                .any(|field| !self.fields.contains(&field.id))
    }
    fn of(definition: &ApplicationManifest) -> Self {
        Self {
            tables: definition.entities.iter().map(|item| item.id).collect(),
            fields: definition.fields.iter().map(|item| item.id).collect(),
        }
    }
    fn intersect(&mut self, definition: &ApplicationManifest) {
        let next = Self::of(definition);
        self.tables.retain(|table| next.tables.contains(table));
        self.fields.retain(|field| next.fields.contains(field));
    }
    pub fn current(&self, write: &RowWrite) -> Option<RowWrite> {
        let kept = self.project(write)?;
        if kept.change.before.is_some()
            && kept.change.after.is_some()
            && kept.published_fields().is_empty()
        {
            return None;
        }
        Some(kept)
    }
    /// `write` with only these fields, even when none of its own remain.
    pub fn project(&self, write: &RowWrite) -> Option<RowWrite> {
        if !self.tables.contains(&write.change.scope.table) {
            return None;
        }
        let mut kept = write.clone();
        for fields in [&mut kept.change.before, &mut kept.change.after]
            .into_iter()
            .flatten()
        {
            fields.retain(|field, _| self.fields.contains(field));
        }
        kept.assigned.retain(|field| self.fields.contains(field));
        Some(kept)
    }
    pub fn strip(&self, table: Commitment, row: &mut Materialized) -> bool {
        let before = (row.fields.len(), row.stamps.len());
        row.fields
            .retain(|field, _| self.fields.contains(field) && self.tables.contains(&table));
        row.stamps
            .retain(|field, _| self.fields.contains(field) && self.tables.contains(&table));
        before != (row.fields.len(), row.stamps.len())
    }
}

impl<A: RowApplication> Inner<A> {
    pub(super) fn frame_schema_ready(&self, frame: &EncryptedFrame) -> Result<bool, Error> {
        let header = frame.operation()?.header;
        let e = &header.extensions;
        let source = self
            .graph_for(e.scope.domain)?
            .schema_any(e.tip)
            .map_err(credential)?;
        if !self.catalog.contains_key(&source) {
            return Ok(false);
        }
        if matches!(
            self.frame_reach(frame)?,
            tips::FrameReach::Held | tips::FrameReach::Unfollowed
        ) {
            return Ok(true);
        }
        match self.path_fields(e.scope.domain, e.tip) {
            Ok(_) => Ok(true),
            Err(Error::Incompatible(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }
    pub(super) async fn load_schemas(&mut self) -> Result<(), Error> {
        self.invalidate_context();
        let mut catalog = BTreeMap::new();
        for row in rows(
            &self.conn,
            "SELECT manifest,definition FROM secure_tip_schemas",
        )
        .await?
        {
            let [SqlValue::Blob(hash), SqlValue::Blob(body)] = row.as_slice() else {
                return Err(Error::Corrupt("tip schema record".into()));
            };
            let definition = ApplicationManifest::from_body(body)
                .map_err(|error| Error::Corrupt(error.to_string()))?;
            if definition.hash().as_slice() != hash
                || definition.publisher != *self.config.publisher.as_bytes()
                || definition.app != self.definition.app
            {
                return Err(Error::Corrupt("tip schema commitment".into()));
            }
            catalog.insert(definition.hash(), definition);
        }
        self.catalog = catalog;
        self.invalidate_context();
        Ok(())
    }
    pub(super) async fn store_schema(
        &self,
        definition: &ApplicationManifest,
        record: &[u8],
    ) -> Result<(), Error> {
        definition
            .validate()
            .map_err(|error| denied(&error.to_string()))?;
        if record.len() > rocky_core::MAX_DEFINITION_BYTES
            || definition.publisher != *self.config.publisher.as_bytes()
            || definition.app != self.definition.app
        {
            return Err(denied("invalid tip schema"));
        }
        self.conn.execute(
            "INSERT INTO secure_tip_schemas VALUES(?,?,?) ON CONFLICT(manifest) DO UPDATE SET record=CASE WHEN length(excluded.record)>0 THEN excluded.record ELSE record END",
            [definition.hash().to_vec(), definition.canonical_body(), record.to_vec()],
        ).await?;
        Ok(())
    }
    /// The pending switch's domain, bookmark and whether that bookmark moved
    /// away from the workspace, as opposed to the device following it.
    pub(super) async fn pending_intent(&self) -> Result<Option<(Scope, String, bool)>, Error> {
        match rows(
            &self.conn,
            "SELECT scope,bookmark,moved FROM secure_pending_schema WHERE id=1",
        )
        .await?
        .first()
        .map(Vec::as_slice)
        {
            Some(
                [
                    SqlValue::Blob(scope),
                    SqlValue::Text(bookmark),
                    SqlValue::Integer(moved),
                ],
            ) => Ok(Some((decode(scope)?, bookmark.clone(), *moved == 1))),
            None => Ok(None),
            _ => Err(Error::Corrupt("pending schema switch".into())),
        }
    }
    /// Whether `tip` is the workspace's tip or one of its ancestors.
    pub(super) fn on_workspace_path(&self, scope: Scope, tip: TipId) -> Result<bool, Error> {
        let graph = self.graph_for(scope)?;
        let mut cursor = self.workspace.tip;
        let mut visited = BTreeSet::new();
        while visited.insert(cursor) {
            if cursor == tip {
                return Ok(true);
            }
            match Self::tip_parent(graph, cursor)? {
                Some((parent, _)) => cursor = parent,
                None => return Ok(false),
            }
        }
        Err(denied("cyclic tip path"))
    }
    /// The installed or cataloged definition of `manifest`.
    pub(super) fn definition_at(&self, manifest: &Commitment) -> Option<&ApplicationManifest> {
        if *manifest == self.manifest {
            Some(&self.definition)
        } else {
            self.catalog.get(manifest)
        }
    }
    pub(super) fn path_fields(&self, scope: Scope, source: TipId) -> Result<PathFields, Error> {
        self.path_fields_to(scope, source, self.workspace.tip)
    }
    /// Fields present at every tip from `source` through `target`, an
    /// ancestor-or-self path: a base at a seal keeps its own tip's fields.
    pub(super) fn path_fields_to(
        &self,
        scope: Scope,
        source: TipId,
        target: TipId,
    ) -> Result<PathFields, Error> {
        let key = (source, target);
        if let Some(fields) = self
            .path_fields
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .cloned()
        {
            return Ok(fields);
        }
        let graph = self.graph_for(scope)?;
        let mut path = Vec::new();
        let mut cursor = target;
        let mut visited = BTreeSet::new();
        while visited.insert(cursor) {
            path.push(cursor);
            if cursor == source {
                break;
            }
            let Some((parent, _)) = Self::tip_parent(graph, cursor)? else {
                return Err(denied("source tip is outside the workspace path"));
            };
            cursor = parent;
        }
        if path.last() != Some(&source) {
            return Err(denied("cyclic tip path"));
        }
        let mut fields = PathFields::of(&self.definition);
        if target != self.workspace.tip {
            let manifest = graph.schema_any(target).map_err(credential)?;
            if manifest != self.manifest {
                fields = PathFields::of(self.catalog.get(&manifest).ok_or_else(|| {
                    Error::Incompatible("a seal's schema is not installed".into())
                })?);
            }
        }
        for tip in path {
            let manifest = graph.schema_any(tip).map_err(credential)?;
            let definition = if manifest == self.manifest {
                &self.definition
            } else {
                self.catalog.get(&manifest).ok_or_else(|| {
                    Error::Incompatible("a schema on the followed path is not installed".into())
                })?
            };
            fields.intersect(definition);
        }
        self.path_fields
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, fields.clone());
        Ok(fields)
    }
    /// The followed path's requirement state, before any header is seen.
    fn requirement_start(&self) -> Result<Option<Requirements>, Error> {
        let Some((scope, name)) = &self.workspace.followed else {
            return Ok(None);
        };
        let graph = self.graph_for(*scope)?;
        let Some(target) = graph.bookmark(name).map_err(credential)? else {
            return Ok(None);
        };
        let mut path = vec![target];
        let mut cursor = target;
        let mut visited = BTreeSet::from([target]);
        while let Some((parent, _)) = Self::tip_parent(graph, cursor)? {
            if !visited.insert(parent) {
                return Err(denied("cyclic tip path"));
            }
            path.push(parent);
            cursor = parent;
        }
        Ok(Some(Requirements {
            domain: *scope,
            graph: graph.clone(),
            path,
            retained: BTreeSet::new(),
            required: BTreeSet::new(),
        }))
    }
    /// The schemas the followed path, kept seals and, when `historical`,
    /// held frames need. One unpaged scan, for transitions that act on it
    /// in the same transaction; `EncryptedReplica::schema_requirements`
    /// pages it.
    pub(super) async fn schema_requirements(
        &self,
        historical: bool,
    ) -> Result<BTreeSet<(TipId, Commitment)>, Error> {
        let Some(mut requirements) = self.requirement_start()? else {
            return Ok(BTreeSet::new());
        };
        let domain = requirements.domain;
        requirements.visit(HeaderSource::Retained, self.domain_headers(domain).await?)?;
        if historical {
            let mut frames = Vec::new();
            for row in rows(&self.conn, "SELECT frame FROM secure_held_frames").await? {
                let [SqlValue::Blob(bytes)] = row.as_slice() else {
                    return Err(Error::Corrupt("held schema reference".into()));
                };
                let frame: EncryptedFrame = decode(bytes)?;
                let header = &frame.operation_ref()?.header.extensions;
                if header.scope.domain == domain {
                    frames.push(header.clone());
                }
            }
            requirements.visit(HeaderSource::HeldFrame, frames)?;
        }
        self.finish_requirements(requirements, historical).await
    }
    async fn finish_requirements(
        &self,
        requirements: Requirements,
        historical: bool,
    ) -> Result<BTreeSet<(TipId, Commitment)>, Error> {
        let Requirements {
            domain,
            graph,
            path,
            mut retained,
            mut required,
        } = requirements;
        let scopes = self.domain_scopes(domain).await?;
        // Stored scopes hold the workspace tip's state until a switch filters it.
        if !scopes.is_empty() && path.contains(&self.workspace.tip) {
            retained.insert(self.workspace.tip);
        }
        // Until an authenticated base covers every stored scope, replay starts
        // at the implicit empty genesis base, including on a fresh enrollment.
        let mut genesis_base = scopes.is_empty();
        for (_, id) in scopes {
            if let Some(seal) = self.base_seal(id).await? {
                retained.insert(graph.seal_by_id(seal).map_err(credential)?.statement.tip);
            } else {
                genesis_base = true;
            }
            // A base being imported is read through the path from its tip.
            if let Some(staging) = self.staging(id).await? {
                retained.insert(staging.signed.statement.tip);
            }
        }
        if genesis_base {
            retained.insert(graph.genesis());
        }
        for (seal, _) in self.kept_marks().await? {
            if let Ok(seal) = graph.seal_by_id(seal) {
                retained.insert(seal.statement.tip);
                if historical {
                    required.insert((
                        seal.statement.tip,
                        graph.schema_any(seal.statement.tip).map_err(credential)?,
                    ));
                }
            }
        }
        let oldest = path
            .iter()
            .rposition(|tip| retained.contains(tip))
            .unwrap_or(0);
        for tip in path.into_iter().take(oldest + 1) {
            required.insert((tip, graph.schema_any(tip).map_err(credential)?));
        }
        Ok(required)
    }
    pub(super) async fn required_schemas(&self) -> Result<BTreeSet<(TipId, Commitment)>, Error> {
        self.schema_requirements(true).await
    }
    pub(super) async fn missing_live_schemas(&self) -> Result<BTreeSet<Commitment>, Error> {
        Ok(self.missing_of(self.schema_requirements(false).await?))
    }
    fn missing_of(&self, required: BTreeSet<(TipId, Commitment)>) -> BTreeSet<Commitment> {
        required
            .into_iter()
            .map(|(_, manifest)| manifest)
            .filter(|manifest| !self.catalog.contains_key(manifest))
            .collect()
    }
}

/// Requirement state accumulated over a domain's headers.
struct Requirements {
    domain: rocky_core::Scope,
    graph: TipGraph,
    path: Vec<TipId>,
    retained: BTreeSet<TipId>,
    required: BTreeSet<(TipId, Commitment)>,
}
impl Requirements {
    fn visit(&mut self, source: HeaderSource, headers: Vec<Extensions>) -> Result<(), Error> {
        for header in headers {
            match source {
                HeaderSource::Retained if self.path.contains(&header.tip) => {
                    self.retained.insert(header.tip);
                }
                HeaderSource::Retained => {}
                HeaderSource::HeldFrame => {
                    let schema = self.graph.schema_any(header.tip).map_err(credential)?;
                    self.required.insert((header.tip, schema));
                }
            }
        }
        Ok(())
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// `Inner::schema_requirements` read in validated pages; `act` runs
    /// on the result in the acquisition that validated it.
    pub(super) async fn schema_requirements<T>(
        &self,
        historical: bool,
        act: impl AsyncFnOnce(&mut Inner<A>, BTreeSet<(TipId, Commitment)>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let domain = {
            let inner = self.inner.lock(crate::replica::Class::Background).await;
            inner.workspace.followed.as_ref().map(|(scope, _)| *scope)
        };
        let Some(domain) = domain else {
            let mut inner = self.inner.lock(crate::replica::Class::Background).await;
            if inner.workspace.followed.is_some() {
                return Err(Error::RetryExhausted);
            }
            return act(&mut inner, BTreeSet::new()).await;
        };
        self.fold_scan(
            domain,
            historical,
            |inner| match inner.requirement_start()? {
                Some(requirements) if requirements.domain == domain => Ok(Some(requirements)),
                Some(_) => Err(Error::RetryExhausted),
                None => Ok(None),
            },
            async |_, requirements, source, headers| match requirements {
                Some(requirements) => requirements.visit(source, headers),
                None => Ok(()),
            },
            async |inner, requirements| {
                let required = match requirements {
                    Some(requirements) => {
                        inner.finish_requirements(requirements, historical).await?
                    }
                    None => BTreeSet::new(),
                };
                act(inner, required).await
            },
        )
        .await
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// Records the adapter's checked representation of the already installed schema.
    pub async fn record_current_schema(&self, record: Vec<u8>) -> Result<(), Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        transaction!(inner, |inner| inner
            .store_schema(&inner.definition, &record)
            .await)?;
        inner.load_schemas().await
    }
    /// Only schemas needed by the followed path, kept seals or held changes.
    pub async fn required_schemas(&self) -> Result<BTreeSet<(TipId, Commitment)>, Error> {
        self.schema_requirements(true, async |_, required| Ok(required))
            .await
    }
    /// Missing definitions needed by the live switch, excluding independent views.
    pub async fn missing_live_schemas(&self) -> Result<BTreeSet<Commitment>, Error> {
        self.schema_requirements(
            false,
            async |inner, required| Ok(inner.missing_of(required)),
        )
        .await
    }
    /// The adapter has authenticated `record` by deriving `definition` from it.
    /// The replica independently checks its commitment against the required tip.
    pub async fn install_tip_schema(
        &self,
        tip: TipId,
        definition: ApplicationManifest,
        record: Vec<u8>,
    ) -> Result<(), Error> {
        self.schema_requirements(true, async |inner, required| {
            if !required.contains(&(tip, definition.hash())) {
                return Err(denied("tip schema is not required"));
            }
            transaction!(inner, |inner| inner
                .store_schema(&definition, &record)
                .await)?;
            inner.load_schemas().await
        })
        .await?;
        // Frames that waited for this schema apply now.
        self.settle().await
    }
    pub async fn tip_schema(&self, manifest: Commitment) -> Result<Option<Vec<u8>>, Error> {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        let records = collect_rows(
            inner
                .conn
                .query(
                    "SELECT record FROM secure_tip_schemas WHERE manifest=? AND length(record)>0",
                    [manifest.to_vec()],
                )
                .await?,
        )
        .await?;
        match records.first().map(Vec::as_slice) {
            Some([SqlValue::Blob(record)]) => Ok(Some(record.clone())),
            None => Ok(None),
            _ => Err(Error::Corrupt("tip schema record".into())),
        }
    }
    pub async fn pending_schema(&self) -> Result<Option<PendingSchema>, Error> {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        let records = rows(
            &inner.conn,
            "SELECT scope,bookmark,tip,manifest FROM secure_pending_schema WHERE id=1",
        )
        .await?;
        match records.first().map(Vec::as_slice) {
            Some(
                [
                    SqlValue::Blob(scope),
                    SqlValue::Text(bookmark),
                    SqlValue::Blob(tip),
                    SqlValue::Blob(manifest),
                ],
            ) => Ok(Some(PendingSchema {
                scope: decode(scope)?,
                bookmark: bookmark.clone(),
                tip: decode(tip)?,
                manifest: checkpoint::row_of(manifest)?,
            })),
            None => Ok(None),
            _ => Err(Error::Corrupt("pending schema switch".into())),
        }
    }
}

/// Security and optional SQL projection for an authenticated tip schema.
pub struct SchemaConfig {
    pub security: SecureConfig,
    pub tables: Option<(
        rocky_core::LogicalSchema,
        Scope,
        BTreeMap<String, Commitment>,
    )>,
}

impl<A: RowApplication> Inner<A> {
    async fn switch_schema_now(
        &mut self,
        tip: TipId,
        app: A,
        config: SchemaConfig,
        withdraw: Option<&super::staging::SchemaStage>,
    ) -> Result<bool, Error> {
        IN_PLACE_SWITCH_CHANGES.store(-1, std::sync::atomic::Ordering::SeqCst);
        let inner = self;
        let manifest = app.manifest();
        let (scope, name) = inner
            .workspace
            .followed
            .clone()
            .ok_or_else(|| denied("schema switching requires following a bookmark"))?;
        // A staged intent the bookmark has left is withdrawn first.
        if withdraw.is_none() && inner.schema_switching().await? {
            transaction!(inner, |inner| inner.reconcile_staged_switch().await)?;
        }
        let staged = inner.schema_switch_intent().await?;
        if let Some((staged_scope, staged_name, staged_source, staged_target)) = &staged
            && (*staged_scope != scope
                || *staged_name != name
                || *staged_source != inner.workspace.tip
                || *staged_target != tip)
        {
            return Err(denied(
                "a different schema switch is staged; withdraw it before switching",
            ));
        }
        let graph = inner.graph_for(scope)?;
        // The staged target resumes while the bookmark continues from it.
        let followed = match graph.bookmark(&name).map_err(credential)? {
            Some(followed) if followed == tip => true,
            Some(followed) if staged.is_some() => graph.continues(tip, followed).unwrap_or(false),
            _ => false,
        };
        if !followed
            || graph.schema(tip).map_err(credential)? != manifest.hash()
            || config
                .security
                .manifest
                .verify(config.security.publisher)
                .map_err(credential)?
                .hash()
                != graph.genesis_schema
        {
            return Err(denied("schema does not authenticate the followed tip"));
        }
        if inner.manifest == manifest.hash() && inner.workspace.tip == tip {
            return Ok(false);
        }
        if inner.config.publisher != config.security.publisher
            || inner.config.node.public_key() != config.security.node.public_key()
            || inner.config.credentials.principal() != config.security.credentials.principal()
            || inner.definition.domains != manifest.domains
            || inner.definition.app != manifest.app
            || inner.definition.operations != manifest.operations
        {
            return Err(denied(
                "schema switch changed domain identity or operations",
            ));
        }
        let missing = inner.missing_live_schemas().await?;
        if !missing.is_empty() {
            return Err(Error::Incompatible(format!(
                "followed path schemas missing: {missing:?}"
            )));
        }
        check_config(&config.security, &manifest)?;
        let source = inner.workspace.tip;
        let mut security = config.security;
        let (current, mut history) = keys::split(std::mem::take(&mut security.keys));
        security.keys = current;
        // Keys installed after open, as partition epochs, stay current for
        // scopes the new configuration does not name.
        for key in &inner.config.keys {
            if manifest
                .entities
                .iter()
                .any(|table| table.id == key.scope.table)
                && !security.keys.iter().any(|held| held.scope == key.scope)
            {
                security.keys.push(key.clone());
            }
        }
        for key in inner.opening_keys() {
            if !security
                .keys
                .iter()
                .chain(&history)
                .any(|held| held.scope == key.scope && held.generation == key.generation)
            {
                history.push(key.clone());
            }
        }
        let permission_fields = app.permission_fields().into_iter().collect();
        let mut definition = generation::Definition {
            app: Arc::new(app),
            permission_fields,
            chain: Chain::new(security.credentials.clone())?,
            node_author: inner.node_author.clone(),
            config: security,
            history,
            manifest: manifest.hash(),
            tip,
            tables: manifest.entities.iter().map(|item| item.id).collect(),
            fields: manifest.fields.iter().map(|item| item.id).collect(),
            domains: manifest.domains.iter().map(|rule| rule.domain).collect(),
            definition: manifest,
        };
        let old_typed = inner.workspace.typed.clone();
        definition.swap(inner);
        inner.invalidate_context();
        let changes_before = total_changes(&inner.conn).await?;
        let staged = transaction!(inner, |inner| {
            if let Some(stage) = withdraw {
                inner.discard_schema_stage(stage).await?;
            }
            inner
                .conn
                .execute(
                    "INSERT INTO secure_schema_switch VALUES(1,?,?,?,?) ON CONFLICT(id) DO NOTHING",
                    bindings(vec![
                        SqlValue::Blob(encode(&scope)?),
                        SqlValue::Text(name.clone()),
                        SqlValue::Blob(encode(&source)?),
                        SqlValue::Blob(encode(&tip)?),
                    ]),
                )
                .await?;
            inner.store_schema(&inner.definition, &[]).await?;
            // Readiness omits removed tables. Strip all stored scopes before
            // projecting, even when the new schema retains none of them.
            inner.hold_removed(scope, tip).await?;
            let fields = inner.durable_switch_fields(scope, source, tip).await?;
            let stripped = inner.strip_rows(scope, source, &fields).await?;
            if let Some((schema, domain, readers)) = &config.tables {
                let expected = schema.manifest_at(
                    &inner
                        .definition
                        .domains
                        .iter()
                        .map(|rule| rule.domain)
                        .collect::<Vec<_>>(),
                    inner.definition.schema,
                );
                if expected.hash() != inner.manifest {
                    return Err(denied("projection differs from tip schema"));
                }
                // Stored rows the path filtered project again.
                if !stripped
                    && inner
                        .switch_in_place(schema.clone(), *domain, readers)
                        .await?
                {
                    inner.finish_schema_switch().await?;
                    return Ok(true);
                }
                inner.record_plan_as(schema, *domain, readers, true).await?;
                return Ok(false);
            }
            if inner.workspace.typed.is_some() {
                return Err(denied("schema switch must supply its SQL projection"));
            }
            inner.finish_schema_switch().await?;
            Ok(false)
        });
        let in_place = match staged {
            Ok(in_place) => in_place,
            Err(error) => {
                definition.swap(inner);
                inner.workspace.typed = old_typed;
                inner.load_schemas().await?;
                return Err(error);
            }
        };
        if in_place {
            let changes = total_changes(&inner.conn).await? - changes_before;
            IN_PLACE_SWITCH_CHANGES.store(changes, std::sync::atomic::Ordering::SeqCst);
        }
        // Once staged, the switch is durable: an interrupted plan resumes
        // under the new definition at the next open or run.
        if !in_place {
            inner.load_schemas().await?;
            if let Err(error) = inner.finish_plan().await {
                // The source stays installed while the switch is staged, as
                // after a reopen, so that withdrawal always has it.
                if inner.schema_switching().await? {
                    definition.swap(inner);
                    inner.workspace.typed = old_typed;
                    inner.load_schemas().await?;
                }
                return Err(error);
            }
        }
        inner.load_schemas().await?;
        inner.load_partitions().await?;
        inner.start_events();
        Ok(true)
    }
    pub(in crate::replica) async fn schema_switch_intent(
        &self,
    ) -> Result<Option<(Scope, String, TipId, TipId)>, Error> {
        let records = rows(
            &self.conn,
            "SELECT scope,bookmark,source,target FROM secure_schema_switch WHERE id=1",
        )
        .await?;
        match records.first().map(Vec::as_slice) {
            Some(
                [
                    SqlValue::Blob(scope),
                    SqlValue::Text(bookmark),
                    SqlValue::Blob(source),
                    SqlValue::Blob(target),
                ],
            ) => Ok(Some((
                decode(scope)?,
                bookmark.clone(),
                decode(source)?,
                decode(target)?,
            ))),
            None => Ok(None),
            _ => Err(Error::Corrupt("schema switch intent".into())),
        }
    }
    async fn stored_definition(&self, manifest: Commitment) -> Result<ApplicationManifest, Error> {
        let records = collect_rows(
            self.conn
                .query(
                    "SELECT definition FROM secure_tip_schemas WHERE manifest=?",
                    [manifest.to_vec()],
                )
                .await?,
        )
        .await?;
        let Some([SqlValue::Blob(bytes)]) = records.first().map(Vec::as_slice) else {
            return Err(denied("switch schema missing"));
        };
        ApplicationManifest::from_body(bytes).map_err(|error| Error::Corrupt(error.to_string()))
    }
    async fn durable_switch_fields(
        &self,
        scope: Scope,
        source: TipId,
        target: TipId,
    ) -> Result<PathFields, Error> {
        let graph = self.graph_for(scope)?;
        let target_definition = self
            .stored_definition(graph.schema_any(target).map_err(credential)?)
            .await?;
        let mut fields = PathFields::of(&target_definition);
        // A source on a losing line continues to nothing: the target's own fields apply.
        if source == target || graph.continues(source, target).unwrap_or(false) {
            let mut cursor = target;
            while cursor != source {
                cursor = Self::tip_parent(graph, cursor)?
                    .ok_or_else(|| denied("switch source is not an ancestor"))?
                    .0;
                fields.intersect(
                    &self
                        .stored_definition(graph.schema_any(cursor).map_err(credential)?)
                        .await?,
                );
            }
        }
        Ok(fields)
    }
    pub(in crate::replica) async fn staged_row_fields(
        &self,
        domain: Scope,
    ) -> Result<Option<PathFields>, Error> {
        let Some((scope, _, source, target)) = self.schema_switch_intent().await? else {
            return Ok(None);
        };
        if scope != domain {
            return Ok(None);
        }
        let fields = self.durable_switch_fields(scope, source, target).await?;
        let before = self
            .stored_definition(
                self.graph_for(scope)?
                    .schema_any(source)
                    .map_err(credential)?,
            )
            .await?;
        Ok(fields.strips(&before).then_some(fields))
    }
    /// Follows `name`'s current target inside the caller's transaction; a
    /// staged switch of that bookmark is reconciled instead.
    pub(super) async fn follow_resolved(&mut self, scope: Scope, name: &str) -> Result<(), Error> {
        if let Some((staged, bookmark, _, _)) = self.schema_switch_intent().await?
            && staged == scope
            && bookmark == name
        {
            return self.reconcile_staged_switch().await;
        }
        if let Some(target) = self.graph_for(scope)?.bookmark(name).map_err(credential)? {
            self.switch_tip(scope, name, target).await?;
        }
        Ok(())
    }
    /// Inside the caller's transaction, keeps a staged switch while its
    /// bookmark continues from the staged target, which stays the only
    /// authority, and withdraws it otherwise. This device's own uncommitted
    /// publication withdraws only through `withdraw_staged_schema`.
    pub(super) async fn reconcile_staged_switch(&mut self) -> Result<(), Error> {
        let Some((scope, bookmark, _, target)) = self.schema_switch_intent().await? else {
            return Ok(());
        };
        if self.own_staged_target(target).await? {
            return Ok(());
        }
        let graph = self.graph_for(scope)?;
        let followed = graph.bookmark(&bookmark).map_err(credential)?;
        let continues = graph.schema(target).is_ok()
            && followed.is_some_and(|followed| {
                followed == target || graph.continues(target, followed).unwrap_or(false)
            });
        if continues {
            return Ok(());
        }
        self.withdraw_schema_switch(scope, &bookmark).await
    }
    async fn own_staged_target(&self, target: TipId) -> Result<bool, Error> {
        for record in rows(
            &self.conn,
            "SELECT stage FROM secure_staged_schema WHERE state='staged'",
        )
        .await?
        {
            let [SqlValue::Blob(bytes)] = record.as_slice() else {
                return Err(Error::Corrupt("staged schema".into()));
            };
            if decode::<super::staging::SchemaStage>(bytes)?.target == target {
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// Inside the caller's transaction, ends a staged switch under the
    /// installed source definition: the intent and plan go, the domain's
    /// rows are rebuilt from their unstripped bases and history, and the
    /// bookmark is followed where it now resolves.
    pub(super) async fn withdraw_schema_switch(
        &mut self,
        scope: Scope,
        bookmark: &str,
    ) -> Result<(), Error> {
        let Some((_, _, source, _)) = self.schema_switch_intent().await? else {
            return Ok(());
        };
        if self.workspace.tip != source
            || self
                .graph_for(scope)?
                .schema_any(source)
                .map_err(credential)?
                != self.manifest
        {
            return Err(denied(
                "withdrawing a staged schema switch needs its source schema installed",
            ));
        }
        self.invalidate_context();
        self.conn
            .execute("DELETE FROM secure_schema_switch WHERE id=1", ())
            .await?;
        self.discard_plan().await?;
        let mut stored = Vec::new();
        for record in rows(
            &self.conn,
            "SELECT id,scope FROM secure_scope_state ORDER BY id",
        )
        .await?
        {
            let [SqlValue::Integer(_), SqlValue::Blob(bytes)] = record.as_slice() else {
                return Err(Error::Corrupt("scope state".into()));
            };
            let resource: ResourceScope = decode(bytes)?;
            if resource.domain == scope {
                stored.push(resource);
            }
        }
        // Staging stripped only stored rows, never bases or history.
        // Replayed scopes replay together once.
        let (replayed, stored): (Vec<_>, Vec<_>) = stored
            .into_iter()
            .partition(|resource| self.replayed_scope(*resource));
        for resource in stored {
            self.rebuild_rows(resource).await?;
        }
        if !replayed.is_empty() {
            self.replay_from_frames(now()?).await?;
        }
        // The pending row keeps whether the bookmark moved until the
        // follow below replaces it.
        match self
            .graph_for(scope)?
            .bookmark(bookmark)
            .map_err(credential)?
        {
            Some(followed) => self.switch_tip(scope, bookmark, followed).await,
            None => {
                self.conn
                    .execute("DELETE FROM secure_pending_schema WHERE id=1", ())
                    .await?;
                Ok(())
            }
        }
    }
    pub(super) async fn schema_switching(&self) -> Result<bool, Error> {
        Ok(
            !rows(&self.conn, "SELECT 1 FROM secure_schema_switch WHERE id=1")
                .await?
                .is_empty(),
        )
    }
    /// Strips stored rows of the workspace at `source` to `fields` before a
    /// plan projects them: a removed table's rows go. Returns whether
    /// anything was stripped.
    async fn strip_rows(
        &mut self,
        scope: Scope,
        source: TipId,
        fields: &PathFields,
    ) -> Result<bool, Error> {
        let before = self
            .stored_definition(
                self.graph_for(scope)?
                    .schema_any(source)
                    .map_err(credential)?,
            )
            .await?;
        if !fields.strips(&before) {
            return Ok(false);
        }
        // Every stored scope of the domain: a removed table's key may be gone.
        let mut stored = Vec::new();
        for record in rows(
            &self.conn,
            "SELECT id,scope FROM secure_scope_state ORDER BY id",
        )
        .await?
        {
            let [SqlValue::Integer(id), SqlValue::Blob(bytes)] = record.as_slice() else {
                return Err(Error::Corrupt("scope state".into()));
            };
            let resource: ResourceScope = decode(bytes)?;
            if resource.domain == scope {
                stored.push((resource, *id));
            }
        }
        for (resource, id) in stored {
            let mut after = Vec::new();
            loop {
                let records = collect_rows(self.conn.query("SELECT row,fields FROM secure_row_records WHERE scope=? AND row>? ORDER BY row LIMIT 256", [encode(&resource)?, after.clone()]).await?).await?;
                for row in &records {
                    let [SqlValue::Blob(key), SqlValue::Blob(bytes)] = row.as_slice() else {
                        return Err(Error::Corrupt("schema switch row".into()));
                    };
                    after = key.clone();
                    match self
                        .strip_stored_record(fields, resource.table, bytes)
                        .await?
                    {
                        None => {
                            self.conn
                                .execute(
                                    "DELETE FROM secure_row_records WHERE scope=? AND row=?",
                                    [encode(&resource)?, key.clone()],
                                )
                                .await?;
                        }
                        Some(stripped) if stripped != *bytes => {
                            self.conn
                                .execute(
                                    "UPDATE secure_row_records SET fields=? WHERE scope=? AND row=?",
                                    [stripped, encode(&resource)?, key.clone()],
                                )
                                .await?;
                        }
                        Some(_) => {}
                    }
                }
                if records.len() < 256 {
                    break;
                }
            }
            self.recount(id, resource).await?;
        }
        Ok(true)
    }
    /// The projection and follow change finish in the plan's final transaction.
    pub(super) async fn finish_schema_switch(&mut self) -> Result<(), Error> {
        let records = rows(
            &self.conn,
            "SELECT scope,bookmark,source,target FROM secure_schema_switch WHERE id=1",
        )
        .await?;
        let Some(
            [
                SqlValue::Blob(scope),
                SqlValue::Text(bookmark),
                SqlValue::Blob(source),
                SqlValue::Blob(target),
            ],
        ) = records.first().map(Vec::as_slice)
        else {
            if records.is_empty() {
                return Ok(());
            }
            return Err(Error::Corrupt("schema switch intent".into()));
        };
        let scope: Scope = decode(scope)?;
        let source: TipId = decode(source)?;
        let target: TipId = decode(target)?;
        let graph = self.graph_for(scope)?;
        let followed = graph.bookmark(bookmark).map_err(credential)?;
        if !followed.is_some_and(|followed| {
            followed == target || graph.continues(target, followed).unwrap_or(false)
        }) || graph.schema(target).map_err(credential)? != self.manifest
        {
            return Err(denied("schema switch target no longer resolves"));
        }
        // Removed tables' scopes leave readiness only once the switch lands.
        for record in rows(&self.conn, "SELECT id,scope FROM secure_scope_state").await? {
            let [SqlValue::Integer(id), SqlValue::Blob(bytes)] = record.as_slice() else {
                return Err(Error::Corrupt("scope state".into()));
            };
            let resource: ResourceScope = decode(bytes)?;
            if resource.domain == scope && !self.tables.contains(&resource.table) {
                self.clear_seal_anchor(*id).await?;
            }
        }
        self.invalidate_context();
        self.workspace.tip = source;
        self.switch_tip(scope, bookmark, target).await?;
        // A bookmark that moved on from the target advances with it.
        if let Some(followed) = followed
            && followed != target
        {
            self.switch_tip(scope, bookmark, followed).await?;
        }
        self.rebuild_voided_in_transaction().await?;
        self.conn
            .execute("DELETE FROM secure_schema_switch WHERE id=1", ())
            .await?;
        Ok(())
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// Installs the followed tip's authenticated schema. A plan may be
    /// interrupted; its final transaction swaps the projection and follow.
    pub async fn switch_schema(
        &self,
        tip: TipId,
        app: A,
        config: SchemaConfig,
    ) -> Result<bool, Error> {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .switch_schema_now(tip, app, config, None)
            .await
    }
    /// Withdraws a staged schema publication whose migration has not
    /// committed, and so never left this device, and switches the
    /// workspace back to its source tip with that tip's schema, atomically.
    pub async fn withdraw_staged_schema(
        &self,
        publication: Commitment,
        app: A,
        config: SchemaConfig,
    ) -> Result<(), Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        let records = collect_rows(
            inner
                .conn
                .query(
                    "SELECT stage FROM secure_staged_schema WHERE publication=? AND state='staged'",
                    [publication.to_vec()],
                )
                .await?,
        )
        .await?;
        let Some([SqlValue::Blob(bytes)]) = records.first().map(Vec::as_slice) else {
            return Err(denied(
                "only an uncommitted staged schema publication withdraws",
            ));
        };
        let stage: super::staging::SchemaStage = decode(bytes)?;
        if inner.publication_cursor(publication).await?.is_some() {
            return Err(denied(
                "a partially authored schema publication never withdraws",
            ));
        }
        // A staged switch to the publication's target, interrupted under
        // the source definition, is withdrawn with the stage.
        let staged = match inner.schema_switch_intent().await? {
            Some((scope, bookmark, source, target))
                if scope == stage.scope && source == stage.source && target == stage.target =>
            {
                if inner.manifest != app.manifest().hash()
                    || inner
                        .graph_for(stage.scope)?
                        .schema_any(stage.source)
                        .map_err(credential)?
                        != inner.manifest
                {
                    return Err(denied(
                        "withdrawing a staged schema switch needs its source schema installed",
                    ));
                }
                Some(bookmark)
            }
            _ => None,
        };
        let (graphs, tip) = (inner.graphs.clone(), inner.workspace.tip);
        let author = inner.node_author.clone();
        let nodes = inner.line_nodes.clone();
        let followed = inner.workspace.followed.clone();
        let ids: BTreeSet<Commitment> = stage
            .statements
            .iter()
            .map(TipStatement::id)
            .collect::<Result<_, _>>()?;
        inner.invalidate_context();
        if let Some(graph) = inner.graphs.get_mut(&stage.scope) {
            graph
                .seals
                .retain(|seal| seal.id().is_ok_and(|id| !ids.contains(&id)));
            graph
                .openings
                .retain(|opening| opening.id().is_ok_and(|id| !ids.contains(&id)));
            graph
                .moves
                .retain(|movement| movement.id().is_ok_and(|id| !ids.contains(&id)));
        }
        inner.workspace.tip = stage.source;
        inner.invalidate_context();
        let result = match staged {
            Some(bookmark) => transaction!(inner, |inner| {
                inner.discard_schema_stage(&stage).await?;
                inner.withdraw_schema_switch(stage.scope, &bookmark).await?;
                inner.load_tip_graphs().await
            })
            .map(|()| true),
            None => {
                inner
                    .switch_schema_now(stage.source, app, config, Some(&stage))
                    .await
            }
        };
        match result {
            Ok(_) => inner.publish_revision().await,
            Err(error) => {
                inner.graphs = graphs;
                inner.workspace.tip = tip;
                inner.node_author = author;
                inner.line_nodes = nodes;
                inner.workspace.followed = followed;
                inner.invalidate_context();
                Err(error)
            }
        }
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// Drops catalog entries no local reader, retained publication or workspace needs.
    pub async fn drop_unrequired_schemas(&self) -> Result<Vec<Commitment>, Error> {
        self.schema_requirements(true, async |inner, required| {
            inner.drop_unrequired_schemas(required).await
        })
        .await
    }
}

impl<A: RowApplication> Inner<A> {
    async fn drop_unrequired_schemas(
        &mut self,
        required: BTreeSet<(TipId, Commitment)>,
    ) -> Result<Vec<Commitment>, Error> {
        let inner = self;
        let mut kept: BTreeSet<_> = required.into_iter().map(|(_, manifest)| manifest).collect();
        kept.insert(inner.manifest);
        kept.insert(
            inner
                .config
                .manifest
                .verify(inner.config.publisher)
                .map_err(credential)?
                .hash(),
        );
        for row in rows(&inner.conn, "SELECT o.header FROM secure_operations o WHERE EXISTS(SELECT 1 FROM secure_publication_frames p WHERE p.hash=o.hash) OR EXISTS(SELECT 1 FROM secure_migration_frames m WHERE m.hash=o.hash)").await? {
            let [SqlValue::Blob(bytes)] = row.as_slice() else { return Err(Error::Corrupt("publication schema reference".into())) };
            let header: p2panda_core::Header<Extensions> = decode(bytes)?;
            kept.insert(inner.manifest_of_tip(header.extensions.tip)?);
        }
        let dropped: Vec<_> = inner
            .catalog
            .keys()
            .filter(|manifest| !kept.contains(*manifest))
            .copied()
            .collect();
        transaction!(inner, |inner| {
            for manifest in &dropped {
                inner
                    .conn
                    .execute(
                        "DELETE FROM secure_tip_schemas WHERE manifest=?",
                        [manifest.to_vec()],
                    )
                    .await?;
            }
            Ok(())
        })?;
        inner.load_schemas().await?;
        Ok(dropped)
    }
}

#[cfg(test)]
impl<A: RowApplication> EncryptedReplica<A> {
    pub(crate) async fn schema_context(&self) -> Vec<u8> {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        let author = |author: &identity::NodeAuthor| {
            (
                author.key.public_key(),
                author.credentials.clone(),
                author.number,
            )
        };
        encode(&(
            inner.manifest,
            inner.workspace.tip,
            &inner.workspace.followed,
            inner.node_author.as_ref().map(author),
            inner
                .line_nodes
                .iter()
                .map(|(tip, node)| (*tip, author(node)))
                .collect::<Vec<_>>(),
            inner.config.node.public_key(),
            &inner.config.credentials,
        ))
        .unwrap()
    }
}
