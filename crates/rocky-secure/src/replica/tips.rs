//! Durable, domain-scoped tip graph and the selected live workspace.
use super::*;
pub(super) mod refresh;
use rocky_core::Scope;
use rocky_credentials::{
    SealFinality, SignedBookmarkMove, SignedCheckpointRecord, SignedGenesisLine, SignedSeal,
    SignedTipOpening, TipGraph,
};

/// Largest stored or exchanged tip statement: a finality record.
pub(crate) const MAX_TIP_STATEMENT_BYTES: usize = SECURE_MESSAGE_BYTES - 1024;

pub(super) fn graph_statements(graph: &TipGraph) -> Vec<TipStatement> {
    graph
        .seals
        .iter()
        .cloned()
        .map(TipStatement::Seal)
        .chain(graph.openings.iter().cloned().map(TipStatement::Opening))
        .chain(graph.moves.iter().cloned().map(TipStatement::Bookmark))
        .chain(
            graph
                .genesis_lines
                .iter()
                .cloned()
                .map(TipStatement::GenesisLine),
        )
        .chain(graph.finalities.iter().cloned().map(TipStatement::Finality))
        .chain(
            graph
                .checkpoints
                .iter()
                .cloned()
                .map(|record| TipStatement::Checkpoint(Box::new(record))),
        )
        .collect()
}

pub(super) const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS secure_tip_graphs(scope BLOB PRIMARY KEY,genesis BLOB NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_tip_statements(digest BLOB PRIMARY KEY,statement BLOB NOT NULL,staged INTEGER NOT NULL DEFAULT 0 CHECK(staged IN(0,1))) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_followed_tip(id INTEGER PRIMARY KEY CHECK(id=1),scope BLOB NOT NULL,bookmark TEXT NOT NULL,tip BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS secure_node_tips(scope BLOB NOT NULL,node BLOB NOT NULL,tip BLOB NOT NULL,PRIMARY KEY(scope,node)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_line_nodes(line BLOB PRIMARY KEY,node BLOB NOT NULL UNIQUE) WITHOUT ROWID",
];

/// A graph record is always exchanged independently of row subscriptions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TipStatement {
    Seal(SignedSeal),
    Opening(SignedTipOpening),
    Bookmark(SignedBookmarkMove),
    GenesisLine(SignedGenesisLine),
    Finality(SealFinality),
    Checkpoint(Box<SignedCheckpointRecord>),
}
impl TipStatement {
    pub fn id(&self) -> Result<Commitment, Error> {
        if encode(self)?.len() > MAX_TIP_STATEMENT_BYTES {
            return Err(Error::Quota {
                resource: "tip statement",
                limit: MAX_TIP_STATEMENT_BYTES,
            });
        }
        match self {
            Self::Seal(s) => s.id(),
            Self::Opening(s) => s.id(),
            Self::Bookmark(s) => s.id(),
            Self::GenesisLine(s) => s.id(),
            Self::Finality(s) => s.id(),
            Self::Checkpoint(s) => s.id(),
        }
        .map_err(credential)
    }
    pub fn scope(&self) -> Scope {
        match self {
            Self::Seal(s) => s.statement.scope,
            Self::Opening(s) => s.statement.scope,
            Self::Bookmark(s) => s.statement.scope,
            Self::GenesisLine(s) => s.statement.scope,
            Self::Finality(s) => s.scope,
            Self::Checkpoint(s) => s.statement.scope,
        }
    }
    pub fn append(&self, graph: &mut TipGraph) {
        match self {
            Self::Seal(s) => graph.seals.push(s.clone()),
            Self::Opening(s) => graph.openings.push(s.clone()),
            Self::Bookmark(s) => graph.moves.push(s.clone()),
            Self::GenesisLine(s) => graph.genesis_lines.push(s.clone()),
            Self::Finality(s) => graph.finalities.push(s.clone()),
            Self::Checkpoint(s) => graph.checkpoints.push((**s).clone()),
        }
    }
    pub(in crate::replica) fn verify(
        &self,
        publisher: PublicKey,
        graph: &TipGraph,
        current: Option<(&RevocationSet, u64)>,
    ) -> Result<(), Error> {
        match (self, current) {
            (Self::Seal(s), Some((r, t))) => s.verify_current(publisher, graph, r, t),
            (Self::Opening(s), Some((r, t))) => s.verify_current(publisher, graph, r, t),
            (Self::Bookmark(s), Some((r, t))) => s.verify_current(publisher, graph, r, t),
            (Self::GenesisLine(s), Some((r, t))) => s.verify_current(publisher, graph, r, t),
            (Self::Checkpoint(s), Some((r, t))) => s.verify_current(publisher, graph, r, t),
            (Self::Seal(s), None) => s.verify(publisher, graph),
            (Self::Opening(s), None) => s.verify(publisher, graph),
            (Self::Bookmark(s), None) => s.verify(publisher, graph),
            (Self::GenesisLine(s), None) => s.verify(publisher, graph),
            (Self::Checkpoint(s), None) => s.verify(publisher, graph),
            // Acknowledgments are checked against the signers' validity
            // when admitted; a stored record keeps counting until revoked.
            (Self::Finality(s), current) => graph.verify_finality(s, publisher, current),
        }
        .map_err(credential)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameReach {
    Live,
    Sealed,
    Held,
    Unfollowed,
}

/// An enrolled node for one line; its key belongs in the caller's secret store.
#[derive(Clone)]
pub struct LineNode {
    pub key: PrivateKey,
    pub credentials: CredentialChain,
}

/// Resolved graph facts are valid only until context invalidation. Credentials
/// and workspace-base readiness are still checked for every authored frame.
#[derive(Default)]
pub(super) struct GraphCache {
    writable: Option<WritableContext>,
    manifests: HashMap<TipId, Commitment>,
    pub(super) paths: HashMap<(Scope, TipId), Vec<SignedSeal>>,
}

struct WritableContext {
    scope: Scope,
    tip: TipId,
    followed: Option<(Scope, String)>,
}

impl<A: RowApplication> Inner<A> {
    pub(crate) fn graph_for(&self, scope: Scope) -> Result<&TipGraph, Error> {
        self.graphs
            .get(&scope)
            .ok_or_else(|| denied("unknown tip graph"))
    }
    pub(crate) fn manifest_of_tip(&self, tip: TipId) -> Result<Commitment, Error> {
        let mut cache = self
            .graph_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(schema) = cache.manifests.get(&tip) {
            return Ok(*schema);
        }
        for graph in self.graphs.values() {
            if let Ok(schema) = graph.schema_any(tip) {
                cache.manifests.insert(tip, schema);
                return Ok(schema);
            }
        }
        Err(Error::Incompatible("unknown tip".into()))
    }
    pub(super) async fn offered(
        &self,
        header: &p2panda_core::Header<Extensions>,
    ) -> Result<bool, Error> {
        self.graph_for(header.extensions.scope.domain)?;
        Ok(!self.private_schema().await?)
    }
    pub(crate) fn same_tip_peer(&self, peer: PublicKey) -> Result<(), Error> {
        if self.peer_tip(peer) != Some(self.workspace.tip) {
            return Err(denied("peer follows another tip"));
        }
        Ok(())
    }
    pub(in crate::replica) fn scope_graph(&self, scope: Scope) -> Result<TipGraph, Error> {
        if scope.app != self.definition.app || !self.domains.contains(&scope.domain) {
            return Err(denied("tip graph belongs to another domain"));
        }
        self.graphs
            .get(&scope)
            .cloned()
            .ok_or_else(|| denied("domain has no installed tip graph"))
    }
    /// Where a stored or received frame belongs.
    pub(crate) fn frame_reach(&self, frame: &EncryptedFrame) -> Result<FrameReach, Error> {
        let operation = frame.operation_ref()?;
        let extension = &operation.header.extensions;
        self.frame_reach_at(
            extension.scope.domain,
            extension.tip,
            extension
                .author
                .ok_or_else(|| denied("node author number missing"))?,
            extension.author_sequence,
            operation.header.timestamp,
        )
    }
    pub(super) fn frame_reach_at(
        &self,
        scope: Scope,
        tip: TipId,
        author: u32,
        sequence: u64,
        _timestamp: u64,
    ) -> Result<FrameReach, Error> {
        self.frame_reach_at_using(scope, tip, author, sequence, _timestamp, None)
    }
    pub(super) fn frame_reach_at_using(
        &self,
        scope: Scope,
        tip: TipId,
        author: u32,
        sequence: u64,
        _timestamp: u64,
        mut context: Option<&mut refresh::RefreshGraphContext<'_>>,
    ) -> Result<FrameReach, Error> {
        let graph = self.graph_for(scope)?;
        let active = match context.as_mut() {
            Some(context) => context.schema_ok(scope, tip, true)?,
            None => graph.schema(tip).is_ok(),
        };
        if !active
            && match context.as_mut() {
                Some(context) => context.schema_ok(scope, tip, false)?,
                None => graph.schema_any(tip).is_ok(),
            }
        {
            return Ok(FrameReach::Held);
        }
        if !self.refresh_visible(graph, scope, tip, author, sequence, &mut context)?
            && match context.as_mut() {
                Some(context) => context.abandoned(self, scope, tip, author, sequence)?,
                None => self
                    .abandoned_bounds(scope, graph, tip)?
                    .iter()
                    .any(|common| {
                        !common
                            .iter()
                            .any(|mark| mark.author == author && sequence <= mark.sequence)
                    }),
            }
        {
            return Ok(FrameReach::Held);
        }
        // The active tip can be sealed while its bookmark waits for a move.
        if tip == self.workspace.tip {
            return Ok(
                match match context.as_mut() {
                    Some(context) => context.winner(scope, tip)?,
                    None => graph.seal(tip).map_err(credential)?,
                } {
                    None => FrameReach::Live,
                    Some(seal)
                        if seal
                            .statement
                            .frontier
                            .iter()
                            .any(|m| m.author == author && sequence <= m.sequence) =>
                    {
                        FrameReach::Sealed
                    }
                    Some(seal)
                        if matches!(
                            seal.statement.action,
                            rocky_credentials::SealAction::Close
                        ) =>
                    {
                        FrameReach::Held
                    }
                    Some(_) => FrameReach::Unfollowed,
                },
            );
        }
        let mut cursor = tip;
        let mut visited = BTreeSet::new();
        while visited.insert(cursor) {
            let Some(seal) = (match context.as_mut() {
                Some(context) => context.winner(scope, cursor)?,
                None => graph.seal(cursor).map_err(credential)?,
            }) else {
                return Ok(if cursor == self.workspace.tip {
                    FrameReach::Live
                } else {
                    FrameReach::Unfollowed
                });
            };
            let included = seal
                .statement
                .frontier
                .iter()
                .any(|m| m.author == author && sequence <= m.sequence);
            if included
                && self.refresh_visible(graph, scope, tip, author, sequence, &mut context)?
            {
                return Ok(FrameReach::Sealed);
            }
            match seal.successor().map_err(credential)? {
                Some(next) => cursor = next,
                None => return Ok(FrameReach::Held),
            }
        }
        Ok(FrameReach::Unfollowed)
    }
    fn refresh_visible(
        &self,
        graph: &TipGraph,
        scope: Scope,
        source: TipId,
        author: u32,
        sequence: u64,
        context: &mut Option<&mut refresh::RefreshGraphContext<'_>>,
    ) -> Result<bool, Error> {
        match context.as_mut() {
            Some(context) => context.visible::<A>(scope, source, author, sequence),
            None => self.visible_frame(graph, source, author, sequence, self.workspace.tip),
        }
    }
    fn abandoned_bounds(
        &self,
        scope: Scope,
        graph: &TipGraph,
        source: TipId,
    ) -> Result<Vec<Vec<rocky_credentials::AuthorMark>>, Error> {
        let Ok(source_line) = graph.line_root(source) else {
            return Ok(Vec::new());
        };
        let mut bounds = Vec::new();
        let names = graph
            .moves
            .iter()
            .map(|movement| &movement.statement.name)
            .collect::<BTreeSet<_>>();
        for name in names {
            for (from, to) in graph.bookmark_path(name).map_err(credential)? {
                if !graph.continues_any(from, to).map_err(credential)?
                    && graph.line_root(from).is_ok_and(|line| line == source_line)
                {
                    bounds.push(self.common_frontier(scope, from, to)?);
                }
            }
        }
        Ok(bounds)
    }
    /// A branch inherits only its opening seal's frontier. Continuations take late writes.
    pub(super) fn visible_frame(
        &self,
        graph: &TipGraph,
        source: TipId,
        author: u32,
        sequence: u64,
        target: TipId,
    ) -> Result<bool, Error> {
        Self::frame_path(graph, source, target)?.admits(author, sequence)
    }
    /// The walk from `target` back to `source` that `visible_frame` checks a
    /// frame against: the seal frontiers it must be inside, in order, and how
    /// the walk ends. It depends only on the tips, not the frame.
    pub(super) fn frame_path(
        graph: &TipGraph,
        source: TipId,
        target: TipId,
    ) -> Result<FramePath, Error> {
        let mut bounds = Vec::new();
        if let Some(seal) = graph.seal(target).map_err(credential)? {
            bounds.push(seal.statement.frontier.clone());
        }
        Self::walk_frame_path(graph, source, target, bounds, true)
    }
    /// Whether the state at exactly `seal` includes a frame: bounded by
    /// that seal's own frontier and walked along its tip's structural
    /// ancestry with the exact opening seals, whichever seal wins today.
    /// Recorded facts such as a no-frames base are judged by this, never by
    /// live visibility.
    pub(super) fn covers_exact(
        graph: &TipGraph,
        source: TipId,
        author: u32,
        sequence: u64,
        seal: &rocky_credentials::SignedSeal,
    ) -> Result<bool, Error> {
        let bounds = vec![seal.statement.frontier.clone()];
        Self::walk_frame_path(graph, source, seal.statement.tip, bounds, false)?
            .admits(author, sequence)
    }
    /// The walk back from `target` to `source`. With `canonical`, a
    /// continuation of a seal that does not win its tip hides the frame.
    fn walk_frame_path(
        graph: &TipGraph,
        source: TipId,
        target: TipId,
        mut bounds: Vec<Vec<rocky_credentials::AuthorMark>>,
        canonical: bool,
    ) -> Result<FramePath, Error> {
        let mut cursor = target;
        let mut visited = BTreeSet::new();
        while visited.insert(cursor) {
            if cursor == source {
                return Ok(FramePath {
                    bounds,
                    end: PathEnd::Visible,
                });
            }
            let mut parent = None;
            for seal in &graph.seals {
                if seal.successor().map_err(credential)? == Some(cursor) {
                    // Only the canonical continuation supplies live state.
                    if canonical
                        && graph
                            .seal(seal.statement.tip)
                            .map_err(credential)?
                            .is_none_or(|winner| winner != seal)
                    {
                        return Ok(FramePath {
                            bounds,
                            end: PathEnd::Hidden,
                        });
                    }

                    parent = Some(seal.statement.tip);
                    break;
                }
            }
            if let Some(tip) = parent {
                cursor = tip;
                continue;
            }
            for opening in &graph.openings {
                if opening.tip().map_err(credential)? == cursor {
                    let seal = graph
                        .seal_by_id(opening.statement.seal)
                        .map_err(credential)?;
                    bounds.push(seal.statement.frontier.clone());
                    parent = Some(seal.statement.tip);
                    break;
                }
            }
            match parent {
                Some(tip) => cursor = tip,
                None => {
                    return Ok(FramePath {
                        bounds,
                        end: PathEnd::Hidden,
                    });
                }
            }
        }
        Ok(FramePath {
            bounds,
            end: PathEnd::Cyclic,
        })
    }
    pub(super) fn ensure_tip_writable(&self, scope: Scope) -> Result<(), Error> {
        let mut cached = self
            .graph_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.node_author.is_some()
            && cached.writable.as_ref().is_some_and(|known| {
                known.scope == scope
                    && known.tip == self.workspace.tip
                    && known.followed == self.workspace.followed
            })
        {
            return Ok(());
        }
        if let Some((followed, name)) = &self.workspace.followed
            && *followed == scope
            && self.graph_for(scope)?.bookmark(name).map_err(credential)?
                != Some(self.workspace.tip)
        {
            return Err(denied(
                "followed bookmark moved or was deleted; workspace is read-only",
            ));
        }
        if let Some(graph) = self.graphs.get(&scope)
            && graph
                .seal(self.workspace.tip)
                .map_err(credential)?
                .is_some()
        {
            return Err(denied("followed bookmark points to a sealed tip"));
        }
        // Without a node of the identity the gate's `LineNode` blocker refuses.
        if self.node_author.is_none() {
            return Ok(());
        }
        cached.writable = Some(WritableContext {
            scope,
            tip: self.workspace.tip,
            followed: self.workspace.followed.clone(),
        });
        Ok(())
    }
    pub(super) async fn tip_frontier(&self, scope: ResourceScope) -> Result<ScopeFrontier, Error> {
        let committed = self.conn.connection().is_autocommit()?;
        if committed && let Some(frontier) = self.cached_frontier(scope) {
            return Ok(frontier);
        }
        let frontier = self.compute_tip_frontier(scope).await?;
        if committed && self.conn.connection().is_autocommit()? {
            self.cache_frontier(&frontier);
        }
        Ok(frontier)
    }
    #[cfg(test)]
    pub(super) async fn scan_tip_frontier(
        &self,
        scope: ResourceScope,
    ) -> Result<ScopeFrontier, Error> {
        let mut positions = BTreeMap::<PublicKey, BTreeMap<u64, bool>>::new();
        let records=collect_rows(self.conn.query("SELECT hash,header,status FROM secure_operations WHERE scope=?1 UNION ALL SELECT hash,header,'applied' FROM secure_voids WHERE scope=?1",[encode(&scope)?]).await?).await?;
        let graph = self.graph_for(scope.domain)?;
        let mut paths = BTreeMap::<TipId, FramePath>::new();
        for record in records {
            let [
                SqlValue::Blob(hash),
                SqlValue::Blob(bytes),
                SqlValue::Text(status),
            ] = record.as_slice()
            else {
                return Err(Error::Corrupt("frontier header".into()));
            };
            let hash = Hash::from_bytes(
                hash.as_slice()
                    .try_into()
                    .map_err(|_| Error::Corrupt("frontier hash".into()))?,
            );
            let header = self.oracle_header(bytes)?;
            if header.hash != hash {
                return Err(Error::Corrupt("frontier header hash".into()));
            }
            let author = header.author.ok_or_else(|| denied("node author missing"))?;
            let path = match paths.entry(header.tip) {
                std::collections::btree_map::Entry::Occupied(path) => path.into_mut(),
                std::collections::btree_map::Entry::Vacant(path) => {
                    path.insert(Self::frame_path(graph, header.tip, self.workspace.tip)?)
                }
            };
            if path.admits(author, header.author_sequence)? {
                positions.entry(header.public_key).or_default().insert(
                    header.seq_num,
                    matches!(status.as_str(), "applied" | "abandoned" | "held"),
                );
            }
        }
        let mut starts = BTreeMap::new();
        if let Some(id) = self.find_scope_id(scope).await? {
            for (log, pruned_prefix) in self.logs(id, None, false, MAX_CHECKPOINT_LOGS + 1).await? {
                if pruned_prefix >= 0 {
                    starts.insert(log.author, pruned_prefix as u64 + 1);
                }
            }
        }
        let mut logs = Vec::new();
        for author in positions
            .keys()
            .chain(starts.keys())
            .copied()
            .collect::<BTreeSet<_>>()
        {
            let mut held = starts.get(&author).copied().unwrap_or(0);
            let mut applied = held;
            if let Some(positions) = positions.get(&author) {
                while let Some(is_applied) = positions.get(&held) {
                    if *is_applied && applied == held {
                        applied += 1;
                    }
                    held += 1;
                }
            }
            if held > 0 {
                logs.push(FrontierLog {
                    author,
                    held,
                    applied,
                });
            }
        }
        if logs.len() > MAX_CHECKPOINT_LOGS {
            return Err(denied("logs per scope quota"));
        }
        Ok(ScopeFrontier { scope, logs })
    }
    pub(super) async fn load_tip_graphs(&mut self) -> Result<(), Error> {
        self.invalidate_context();
        let mut graphs = BTreeMap::new();
        for record in rows(&self.conn, "SELECT scope,genesis FROM secure_tip_graphs").await? {
            let [SqlValue::Blob(scope), SqlValue::Blob(genesis)] = record.as_slice() else {
                return Err(Error::Corrupt("tip graph".into()));
            };
            let scope: Scope = decode(scope)?;
            let schema: Commitment = genesis
                .as_slice()
                .try_into()
                .map_err(|_| Error::Corrupt("genesis schema".into()))?;
            if schema
                != self
                    .config
                    .manifest
                    .verify(self.config.publisher)
                    .map_err(credential)?
                    .hash()
            {
                return Err(Error::Corrupt(
                    "tip graph differs from the domain root".into(),
                ));
            }
            self.known(schema)?;
            graphs.insert(scope, TipGraph::new(scope, schema));
        }
        let mut statements = Vec::new();
        for record in rows(
            &self.conn,
            "SELECT digest,statement FROM secure_tip_statements ORDER BY digest",
        )
        .await?
        {
            let [SqlValue::Blob(digest), SqlValue::Blob(bytes)] = record.as_slice() else {
                return Err(Error::Corrupt("tip statement".into()));
            };
            let statement: TipStatement = decode_bounded(bytes, MAX_TIP_STATEMENT_BYTES)?;
            if statement.id()?.as_slice() != digest {
                return Err(Error::Corrupt("tip statement digest".into()));
            }
            statement.append(
                graphs
                    .get_mut(&statement.scope())
                    .ok_or_else(|| Error::Corrupt("tip statement graph".into()))?,
            );
            statements.push(statement);
        }
        for statement in statements {
            statement.verify(self.config.publisher, &graphs[&statement.scope()], None)?;
        }
        for graph in graphs.values_mut() {
            graph
                .exclude_revoked(&self.config.revocations)
                .map_err(credential)?;
        }
        self.graphs = graphs;
        self.invalidate_context();
        self.workspace.followed = None;
        let root = self
            .config
            .manifest
            .verify(self.config.publisher)
            .map_err(credential)?
            .hash();
        self.workspace.tip = rocky_credentials::genesis_tip(root);
        if let Some(record) = rows(
            &self.conn,
            "SELECT scope,bookmark,tip FROM secure_followed_tip WHERE id=1",
        )
        .await?
        .first()
        {
            let [
                SqlValue::Blob(scope),
                SqlValue::Text(name),
                SqlValue::Blob(tip),
            ] = record.as_slice()
            else {
                return Err(Error::Corrupt("followed tip".into()));
            };
            let scope: Scope = decode(scope)?;
            let tip: TipId = decode(tip)?;
            if self.graph_for(scope)?.schema_any(tip).map_err(credential)? != self.manifest {
                return Err(Error::Incompatible(
                    "installed application differs from workspace schema".into(),
                ));
            }
            self.workspace.followed = Some((scope, name.clone()));
            self.workspace.tip = tip;
        }
        let genesis = rocky_credentials::genesis_tip(root);
        let original = identity::NodeAuthor::new(&self.config)?;
        self.line_nodes.entry(genesis).or_insert(original);
        self.conn
            .execute(
                "INSERT OR IGNORE INTO secure_line_nodes VALUES(?,?)",
                [
                    encode(&genesis)?,
                    self.config.node.public_key().as_bytes().to_vec(),
                ],
            )
            .await?;
        if let Some((scope, _)) = self.workspace.followed.clone() {
            if self.graph_for(scope)?.schema(self.workspace.tip).is_ok() {
                self.select_line(scope, self.workspace.tip).await?;
            } else {
                self.node_author = None;
            }
        }
        Ok(())
    }
    /// Leaves the statements `revocations` ends out of every graph's
    /// resolution and, inside the caller's transaction, follows the
    /// bookmark to where it now resolves. Returns whether a graph changed.
    pub(in crate::replica) async fn resolve_revoked(
        &mut self,
        revocations: &rocky_credentials::RevocationSet,
    ) -> Result<bool, Error> {
        self.invalidate_context();
        let mut changed = false;
        for graph in self.graphs.values_mut() {
            changed |= graph.exclude_revoked(revocations).map_err(credential)?;
        }
        // A revoked signer's pulled states leave before any follow can
        // install them, whether or not a graph changed.
        self.revalidate_pulled().await?;
        if changed && let Some((scope, name)) = self.workspace.followed.clone() {
            self.follow_resolved(scope, &name).await?;
        }
        if changed {
            self.invalidate_context();
        }
        if changed && let Some((scope, _)) = self.workspace.followed.clone() {
            self.revalidate_finalized(scope, true).await?;
        }
        if changed {
            for domain in self.graphs.keys().copied().collect::<Vec<_>>() {
                self.reseed_domain_ledgers(domain).await?;
            }
        }
        Ok(changed)
    }
    pub(super) async fn store_followed(
        &self,
        scope: Scope,
        name: &str,
        tip: TipId,
    ) -> Result<(), Error> {
        self.conn.execute("INSERT INTO secure_followed_tip VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET scope=excluded.scope,bookmark=excluded.bookmark,tip=excluded.tip",bindings(vec![SqlValue::Blob(encode(&scope)?),SqlValue::Text(name.into()),SqlValue::Blob(encode(&tip)?)] )).await?;
        self.conn
            .execute(
                "UPDATE secure_metadata SET identity=? WHERE id=1",
                [generation::identity(tip, self.config.node.public_key())?],
            )
            .await?;
        Ok(())
    }
    async fn select_line(&mut self, scope: Scope, target: TipId) -> Result<(), Error> {
        let root = self
            .graph_for(scope)?
            .line_root(target)
            .map_err(credential)?;
        let records = collect_rows(
            self.conn
                .query(
                    "SELECT node FROM secure_line_nodes WHERE line=?",
                    [encode(&root)?],
                )
                .await?,
        )
        .await?;
        let mut selected = match records.first().map(Vec::as_slice) {
            Some([SqlValue::Blob(node)]) => self
                .line_nodes
                .get(&root)
                .filter(|author| author.key.public_key().as_bytes().as_slice() == node)
                .cloned(),
            None if root
                == rocky_credentials::genesis_tip(self.graph_for(scope)?.genesis_schema) =>
            {
                Some(identity::NodeAuthor::new(&self.config)?)
            }
            _ => None,
        };
        if selected
            .as_ref()
            .is_some_and(|author| author.key.public_key() == self.config.node.public_key())
        {
            selected = Some(identity::NodeAuthor::new(&self.config)?);
        }
        if let Some(author) = &selected
            && !self
                .node_continues(scope, target, author.key.public_key())
                .await?
        {
            selected = None;
        }
        if let Some(author) = &selected {
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO secure_line_nodes VALUES(?,?)",
                    [encode(&root)?, author.key.public_key().as_bytes().to_vec()],
                )
                .await?;
            self.line_nodes.insert(root, author.clone());
        }
        self.node_author = selected;
        Ok(())
    }
    /// Refuses following `target` onto a seal this node does not hold
    /// when no replay base lies on its path and a scope off it cannot
    /// rebuild from the frames it holds: the node pulls that seal's state
    /// from a node that keeps it first.
    async fn require_held_start(&self, domain: Scope, target: TipId) -> Result<(), Error> {
        let graph = self.graph_for(domain)?;
        if target == self.workspace.tip
            || graph
                .continues(self.workspace.tip, target)
                .is_ok_and(|continues| continues)
        {
            return Ok(());
        }
        let Some(start) = history::bookmark_seal(graph, target)? else {
            return Ok(());
        };
        let path = compaction::tip_path_seals(graph, target)?
            .iter()
            .map(|seal| seal.id().map_err(credential))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let mut based = true;
        for (scope, id) in self.domain_scopes(domain).await? {
            let on_path = match self.base_seal(id).await? {
                Some(seal) => path.contains(&seal),
                None => true,
            };
            // A scope that pruned nothing replays its own frames at a seal
            // of the new path; another imports a checkpoint the graph lists
            // at one.
            based &= on_path
                || (self.scope_key(scope).is_ok() && !self.has_pruned_prefix(scope).await?)
                || !self.listed_at(graph, scope, &path)?.is_empty();
        }
        if based || self.held_seal(domain, start).await?.is_some() {
            return Ok(());
        }
        Err(denied(
            "this node does not hold the seal the tip starts from; pull it from a node that keeps it",
        ))
    }
    async fn node_continues(
        &self,
        scope: Scope,
        target: TipId,
        node: PublicKey,
    ) -> Result<bool, Error> {
        let records = collect_rows(
            self.conn
                .query(
                    "SELECT tip FROM secure_node_tips WHERE scope=? AND node=?",
                    [encode(&scope)?, node.as_bytes().to_vec()],
                )
                .await?,
        )
        .await?;
        match records.first().map(Vec::as_slice) {
            None => Ok(true),
            Some([SqlValue::Blob(bytes)]) => {
                let previous: TipId = decode(bytes)?;
                Ok(previous == target
                    || self
                        .graph_for(scope)?
                        .continues(previous, target)
                        .unwrap_or(false))
            }
            _ => Err(Error::Corrupt("node tip".into())),
        }
    }

    async fn follow_target(
        &mut self,
        scope: Scope,
        name: &str,
        target: TipId,
    ) -> Result<(), Error> {
        self.invalidate_context();
        let tip = self.workspace.tip;
        let author = self.node_author.clone();
        let nodes = self.line_nodes.clone();
        let result = transaction!(self, |inner| {
            inner.workspace.tip = tip;
            inner.node_author = author.clone();
            inner.line_nodes = nodes.clone();
            match inner.schema_switch_intent().await? {
                Some((staged, bookmark, _, _)) if staged == scope && bookmark == name => {
                    inner.reconcile_staged_switch().await
                }
                Some(_) => Err(denied(
                    "a staged schema switch must finish or be withdrawn first",
                )),
                None => inner.switch_tip(scope, name, target).await,
            }
        });
        if let Err(error) = result {
            self.invalidate_context();
            self.workspace.tip = tip;
            self.node_author = author;
            self.line_nodes = nodes;
            return Err(error);
        }
        self.workspace.followed = Some((scope, name.into()));
        self.publish_revision().await?;
        Ok(())
    }
    pub(super) async fn switch_tip(
        &mut self,
        scope: Scope,
        name: &str,
        target: TipId,
    ) -> Result<(), Error> {
        self.invalidate_context();
        // Whether the workspace's own bookmark moved, rather than the device
        // following another bookmark: a pending switch keeps its intent.
        let moved = match self.pending_intent().await? {
            Some((pending, bookmark, moved)) => moved && pending == scope && bookmark == name,
            None => self
                .workspace
                .followed
                .as_ref()
                .is_some_and(|(followed, bookmark)| *followed == scope && bookmark == name),
        };
        let graph = self.graph_for(scope)?;
        let schema = graph.schema(target).map_err(credential)?;
        if schema != self.manifest || !self.missing_live_schemas().await?.is_empty() {
            self.conn.execute(
                "INSERT INTO secure_pending_schema VALUES(1,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET scope=excluded.scope,bookmark=excluded.bookmark,tip=excluded.tip,manifest=excluded.manifest,moved=excluded.moved",
                bindings(vec![SqlValue::Blob(encode(&scope)?), SqlValue::Text(name.into()), SqlValue::Blob(encode(&target)?), SqlValue::Blob(schema.to_vec()), SqlValue::Integer(i64::from(moved))]),
            ).await?;
            // The tip waits, but a caller may have changed the graph.
            self.reseed_domain_ledgers(scope).await?;
            return self.store_followed(scope, name, self.workspace.tip).await;
        }
        self.conn
            .execute("DELETE FROM secure_pending_schema WHERE id=1", ())
            .await?;
        self.invalidate_context();
        let forward = target == self.workspace.tip
            || graph
                .continues(self.workspace.tip, target)
                .is_ok_and(|continues| continues);
        let old_tip = self.workspace.tip;
        let old_author = self.node_author.clone();
        let old_nodes = self.line_nodes.clone();
        // A moved bookmark leaves behind what its new target does not see;
        // following another bookmark leaves the source line's writes on it.
        if moved && !forward {
            self.hold_line_writes(scope, self.workspace.tip, target)
                .await?;
        }
        self.workspace.tip = target;
        let result = async {
            self.select_line(scope, target).await?;
            if !forward {
                self.rebuild_tip_workspace(scope).await?;
            }
            self.store_followed(scope, name, target).await?;
            self.reseed_domain_ledgers(scope).await
        }
        .await;
        if result.is_err() {
            self.invalidate_context();
            self.workspace.tip = old_tip;
            self.node_author = old_author;
            self.line_nodes = old_nodes;
        }
        result
    }
    fn common_frontier(
        &self,
        scope: Scope,
        from: TipId,
        to: TipId,
    ) -> Result<Vec<rocky_credentials::AuthorMark>, Error> {
        let graph = self.graph_for(scope)?;
        let mut ancestors = BTreeSet::new();
        let mut cursor = from;
        while ancestors.insert(cursor) {
            match Self::tip_parent(graph, cursor)? {
                Some((parent, _)) => cursor = parent,
                None => break,
            }
        }
        let mut cursor = to;
        let mut visited = BTreeSet::new();
        while visited.insert(cursor) {
            if ancestors.contains(&cursor) {
                return Ok(graph
                    .seal(cursor)
                    .map_err(credential)?
                    .map(|seal| seal.statement.frontier.clone())
                    .unwrap_or_default());
            }
            match Self::tip_parent(graph, cursor)? {
                Some((parent, frontier)) => {
                    if ancestors.contains(&parent) {
                        return Ok(frontier);
                    }
                    cursor = parent;
                }
                None => break,
            }
        }
        Ok(Vec::new())
    }
    pub(super) fn tip_parent(
        graph: &TipGraph,
        tip: TipId,
    ) -> Result<Option<(TipId, Vec<rocky_credentials::AuthorMark>)>, Error> {
        for seal in &graph.seals {
            if seal.successor().map_err(credential)? == Some(tip) {
                return Ok(Some((seal.statement.tip, seal.statement.frontier.clone())));
            }
        }
        for opening in &graph.openings {
            if opening.tip().map_err(credential)? == tip {
                let seal = graph
                    .seal_by_id(opening.statement.seal)
                    .map_err(credential)?;
                return Ok(Some((seal.statement.tip, seal.statement.frontier.clone())));
            }
        }
        Ok(None)
    }
    pub(super) async fn rebuild_tip_workspace(&mut self, domain: Scope) -> Result<(), Error> {
        self.index_inherited_held(domain).await?;
        // Finalized seals off the new path are undone by the rebuild.
        let reopened = self.revalidate_finalized(domain, false).await?;
        let path = self
            .path_seals(domain)?
            .iter()
            .map(|seal| seal.id().map_err(credential))
            .collect::<Result<BTreeSet<_>, _>>()?;
        // A compacted seal off the new path cannot be undone: the rows wait
        // for a rebootstrap at a seal of the path, unless states pulled at
        // seals of the path replace every base that left it. Scopes whose
        // base stays on the path are rebuilt below like any other.
        let lost = self.compaction_lost(domain).await?.is_some();
        if lost {
            let mut installed = false;
            for (scope, id) in self.domain_scopes(domain).await? {
                if self.base_off_path(scope, id).await?
                    && self
                        .pulled_seal(id)
                        .await?
                        .is_some_and(|seal| path.contains(&seal))
                    && self.install_pulled(scope, id).await?
                        == checkpoint::pulled::PulledInstall::Installed
                {
                    installed = true;
                }
            }
            if installed {
                Box::pin(self.settle_seal_rebootstrap(domain)).await?;
            }
        }
        // A kept seal the new path passes: scopes start from its rows.
        let rewind = self.rewind_seal(domain).await?;
        #[cfg(test)]
        let rewind = rewind.filter(|_| !self.rebuild_switches);
        // A schema switch compiles every member again.
        let mut replay = reopened || self.schema_switch_intent().await?.is_some();
        let mut replayed = Vec::new();
        for (scope, id) in self.domain_scopes(domain).await? {
            if lost && self.base_off_path(scope, id).await? {
                continue;
            }
            // Replayed scopes replay together once. One whose transactions
            // all stay on the path, as across a migration's close, keeps its
            // rows.
            if self.replayed_scope(scope) {
                replay |= !self.replayed_on_path(id).await?;
                replayed.push((scope, id));
                continue;
            }
            // Restoring a kept seal's rows replays only what followed it.
            // Without the kept state's identity evidence it rebuilds instead.
            if let Some(rewind) = &rewind
                && let Some(at) = rewind.at(id)
                && self.rewinds(scope, id).await?
                && let Some(ledger) = self.prefix_identity_ledger(scope, id, at.1).await?
            {
                #[cfg(test)]
                {
                    self.rewound += 1;
                }
                self.rewind_rows(scope, id, at, i64::MAX, true, ledger)
                    .await?;
                continue;
            }
            // A base at a seal the new tip's state passes through stays.
            let kept = self
                .checkpoint_record(id, true)
                .await?
                .and_then(|record| record.signed)
                .and_then(|signed| signed.statement.seal)
                .is_some_and(|seal| path.contains(&seal));
            // A state pulled at a seal the new tip passes replaces pruned
            // history.
            let kept = kept
                || match self.pulled_seal(id).await? {
                    Some(seal) if path.contains(&seal) && self.has_pruned_prefix(scope).await? => {
                        // A refused state leaves the scope waiting.
                        self.install_pulled(scope, id).await?
                            == checkpoint::pulled::PulledInstall::Installed
                    }
                    _ => false,
                };
            if !kept && self.has_pruned_prefix(scope).await? {
                if let Some(seal) =
                    history::bookmark_seal(self.graph_for(domain)?, self.workspace.tip)?
                {
                    self.conn
                        .execute(
                            "INSERT OR IGNORE INTO secure_wanted_seals VALUES(?,?)",
                            [encode(&domain)?, seal.to_vec()],
                        )
                        .await?;
                }
                // Metadata is admitted while the unavailable workspace waits
                // for the target seal; reads and authoring remain gated.
                continue;
            }
            // Seals finalized over a base that leaves name positions inside
            // it: the rebuild replays from nothing past them.
            if !kept && let Some(base) = self.checkpoint_record(id, true).await? {
                self.drop_seal_bounds(id, base.position).await?;
            }
            self.rebuilding_tip = true;
            self.tip_base = kept;
            let rebuilt = self.rebuild_rows(scope).await;
            self.rebuilding_tip = false;
            self.tip_base = false;
            rebuilt?;
            if kept {
                continue;
            }
            for table in [
                "secure_checkpoints",
                "secure_checkpoint_base",
                "secure_checkpoint_overlay",
                "secure_checkpoint_scratch",
            ] {
                self.conn
                    .execute(format!("DELETE FROM {table} WHERE scope=?"), [id])
                    .await?;
            }
        }
        eprintln!("DBG rebuild replay={replay} reopened={reopened} replayed={replayed:?}");
        if replay {
            // A kept seal's rows serve when every replayed scope may start
            // there.
            let mut kept = rewind.as_ref();
            for (scope, id) in &replayed {
                if kept.is_some() && !self.rewinds(*scope, *id).await? {
                    kept = None;
                }
            }
            #[cfg(test)]
            if kept.is_some() {
                self.rewound += replayed.len();
            }
            self.replay_from(now()?, kept).await?;
        }
        // A scope that still misses coverage the path's pulled state gives,
        // pruned prefix or not, installs it now.
        self.install_needed_pulled(domain).await?;
        self.reseed_domain_ledgers(domain).await?;
        Ok(())
    }
    async fn index_inherited_held(&self, domain: Scope) -> Result<(), Error> {
        let records = rows(&self.conn, "SELECT o.header,o.body FROM secure_operations o LEFT JOIN secure_applied a ON a.hash=o.hash WHERE o.status='held' AND a.hash IS NULL").await?;
        let mut inherited = BTreeMap::new();
        for record in records {
            let [SqlValue::Blob(header), SqlValue::Blob(body)] = record.as_slice() else {
                return Err(Error::Corrupt("held replay history".into()));
            };
            let frame = self.stored_frame(header.clone(), body.clone()).await?;
            let operation = frame.operation()?;
            if operation.header.extensions.scope.domain == domain
                && self.visible_held_in_workspace(&operation)?
            {
                inherited.insert(
                    (operation.header.timestamp, *operation.hash.as_bytes()),
                    (operation, frame),
                );
            }
        }
        // Held custody has no applied-log tip. Index only the selected sealed
        // history, in causal clock order, without advancing any author log.
        for (_, (operation, frame)) in inherited {
            if !self
                .dependencies_ready(&frame, &BTreeSet::new(), None)
                .await?
            {
                return Err(denied("inherited held snapshot has missing dependencies"));
            }
            let scope = self.scope_id(operation.header.extensions.scope).await?;
            self.conn
                .execute(
                    "INSERT INTO secure_applied(scope,hash) VALUES(?,?)",
                    bindings(vec![
                        SqlValue::Integer(scope),
                        SqlValue::Blob(operation.hash.as_bytes().to_vec()),
                    ]),
                )
                .await?;
            self.note_row_positions(scope, &frame, &self.row_payload(&frame)?)
                .await?;
        }
        Ok(())
    }
    pub(super) fn visible_in_workspace(
        &self,
        operation: &p2panda_core::Operation<Extensions>,
    ) -> Result<bool, Error> {
        let e = &operation.header.extensions;
        match self.graphs.get(&e.scope.domain) {
            Some(graph) => self.visible_frame(
                graph,
                e.tip,
                e.author.ok_or_else(|| denied("node author missing"))?,
                e.author_sequence,
                self.workspace.tip,
            ),
            None => Err(denied("domain has no installed tip graph")),
        }
    }
    pub(super) fn visible_held_in_workspace(
        &self,
        operation: &p2panda_core::Operation<Extensions>,
    ) -> Result<bool, Error> {
        Ok(self
            .graphs
            .contains_key(&operation.header.extensions.scope.domain)
            && self.visible_in_workspace(operation)?)
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    pub async fn followed_tip(&self) -> TipId {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .workspace
            .tip
    }
    pub async fn followed_bookmark(&self) -> Option<(Scope, String)> {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .workspace
            .followed
            .clone()
    }
    pub async fn tip_graph(&self, scope: Scope) -> Result<TipGraph, Error> {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .scope_graph(scope)
    }
    /// Verified union; no row scan is needed for seals or forward bookmark
    /// moves. On a trusted node a seal or move whose terminal log entry
    /// lost, or is not confirmed yet, waits outside the graph.
    /// Received seals this node cannot confirm yet wait in the journal for
    /// `settle_tip_statements`; receipt never catches up through peers.
    pub async fn receive_tip_statements(
        &self,
        statements: &[TipStatement],
    ) -> Result<usize, Error> {
        let mut fresh = false;
        for statement in statements {
            fresh |= !self.holds_statement(statement.id()?).await?;
        }
        if !fresh {
            return self.admit_tip_statements(statements, None).await;
        }
        self.check_statements(statements).await?;
        let batch = self.journal_tips(statements, false).await?;
        let coordinated = self
            .coordinate_tip_statements(statements, false, false)
            .await?;
        self.admit_pending_tips(&coordinated.kept, Some(batch), &coordinated.deferred)
            .await
    }
    /// Admits verified statements; `journal` names the batch the admission
    /// settles, forgotten in the same transaction.
    pub(in crate::replica) async fn admit_tip_statements(
        &self,
        statements: &[TipStatement],
        journal: Option<Commitment>,
    ) -> Result<usize, Error> {
        self.admit_pending_tips(statements, journal, &[]).await
    }
    pub(in crate::replica) async fn admit_pending_tips(
        &self,
        statements: &[TipStatement],
        journal: Option<Commitment>,
        remainder: &[TipStatement],
    ) -> Result<usize, Error> {
        self.admit_tips_with_stage(statements, journal, remainder, None)
            .await
    }
    pub(in crate::replica) async fn admit_tips_with_stage(
        &self,
        statements: &[TipStatement],
        journal: Option<Commitment>,
        remainder: &[TipStatement],
        stage: Option<&super::staging::SchemaStage>,
    ) -> Result<usize, Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        if let Some(stage) = stage {
            inner.check_schema_stage(stage).await?;
        }
        let mut graphs = inner.graphs.clone();
        let mut new = Vec::new();
        for statement in statements {
            let scope = statement.scope();
            if let std::collections::btree_map::Entry::Vacant(entry) = graphs.entry(scope) {
                entry.insert(inner.scope_graph(scope)?);
            }
            let id = statement.id()?;
            let exists = collect_rows(
                inner
                    .conn
                    .query(
                        "SELECT 1 FROM secure_tip_statements WHERE digest=?",
                        [id.to_vec()],
                    )
                    .await?,
            )
            .await?;
            if !exists.is_empty() || new.iter().any(|(known, _)| *known == id) {
                continue;
            }
            statement.append(
                graphs
                    .get_mut(&scope)
                    .ok_or_else(|| denied("unknown graph"))?,
            );
            new.push((id, statement));
        }
        if new.is_empty() {
            transaction!(inner, |inner| {
                if let Some(batch) = journal {
                    inner.replace_pending_tips(batch, remainder).await?;
                }
                inner.prune_pending_tips().await
            })?;
            drop(flush_guard(inner, &self.inner).await?);
            return Ok(0);
        }
        // A finality record or a raised genesis minimum resolves again.
        for graph in graphs.values_mut() {
            graph
                .exclude_revoked(&inner.config.revocations)
                .map_err(credential)?;
        }
        for (_, statement) in &new {
            statement.verify(
                inner.config.publisher,
                &graphs[&statement.scope()],
                Some((&inner.config.revocations, now()?)),
            )?;
        }
        for (_, statement) in &new {
            if let TipStatement::Bookmark(movement) = statement
                && let (Some(from), Some(to)) = (movement.statement.from, movement.statement.to)
            {
                let graph = &graphs[&movement.statement.scope];
                if !graph.continues_any(from, to).map_err(credential)?
                    && graph.seal(from).map_err(credential)?.is_none()
                {
                    return Err(denied(
                        "backward or sideways move must include a close seal for the tip it leaves",
                    ));
                }
            }
        }
        let old_graphs = inner.graphs.clone();
        let old_tip = inner.workspace.tip;
        let old_author = inner.node_author.clone();
        let old_nodes = inner.line_nodes.clone();
        let old_followed = inner.workspace.followed.clone();
        let result = transaction!(inner, |inner| {
            inner.invalidate_context();
            inner.graphs = graphs.clone();
            inner.workspace.tip = old_tip;
            inner.node_author = old_author.clone();
            inner.line_nodes = old_nodes.clone();
            inner.workspace.followed = old_followed.clone();
            for (scope, graph) in &graphs {
                inner
                    .conn
                    .execute(
                        "INSERT OR IGNORE INTO secure_tip_graphs VALUES(?,?)",
                        [encode(scope)?, graph.genesis_schema.to_vec()],
                    )
                    .await?;
            }
            for (id, statement) in &new {
                inner
                    .conn
                    .execute(
                        "INSERT INTO secure_tip_statements(digest,statement,staged) VALUES(?,?,?)",
                        bindings(vec![
                            SqlValue::Blob(id.to_vec()),
                            SqlValue::Blob(encode(statement)?),
                            SqlValue::Integer(i64::from(stage.is_some())),
                        ]),
                    )
                    .await?;
            }
            if let Some(stage) = stage {
                inner.record_schema_stage(stage).await?;
            }
            if let Some((scope, name)) = old_followed.clone() {
                inner.follow_resolved(scope, &name).await?;
            }
            // A finalized seal that lost a race is undone.
            if let Some((scope, _)) = old_followed.clone() {
                if !inner.seal_rebootstraps(scope).await?.is_empty()
                    && let Some(seal) =
                        history::bookmark_seal(inner.graph_for(scope)?, inner.workspace.tip)?
                {
                    inner
                        .conn
                        .execute(
                            "INSERT OR IGNORE INTO secure_wanted_seals VALUES(?,?)",
                            [encode(&scope)?, seal.to_vec()],
                        )
                        .await?;
                }
                inner.revalidate_finalized(scope, true).await?;
                // Bookmarks may show other seals now.
                inner.retain_kept(scope).await?;
            }
            if let Some(batch) = journal {
                inner.replace_pending_tips(batch, remainder).await?;
            }
            inner.prune_pending_tips().await?;
            for domain in graphs.keys() {
                inner.reseed_domain_ledgers(*domain).await?;
            }
            inner.publication_fault(3)
        });
        if let Err(error) = result {
            inner.invalidate_context();
            inner.graphs = old_graphs;
            inner.workspace.tip = old_tip;
            inner.node_author = old_author;
            inner.line_nodes = old_nodes;
            inner.workspace.followed = old_followed;
            return Err(error);
        }
        if inner.workspace.tip != old_tip
            && old_followed.as_ref().is_some_and(|(scope, _)| {
                !inner.graphs[scope]
                    .continues_any(old_tip, inner.workspace.tip)
                    .unwrap_or(false)
            })
        {
            inner.bump_authority();
        }
        inner.publish_revision().await?;
        drop(flush_guard(inner, &self.inner).await?);
        Ok(new.len())
    }
    pub async fn tip_statements(
        &self,
        after: Option<Commitment>,
        limit: usize,
    ) -> Result<Vec<TipStatement>, Error> {
        if limit == 0 || limit > 32 {
            return Err(denied("tip graph page quota"));
        }
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        if inner.private_schema().await? {
            return Err(denied("schema publication is private"));
        }
        inner = flush_guard(inner, &self.inner).await?;
        let records=collect_rows(inner.conn.query("SELECT statement FROM secure_tip_statements WHERE staged=0 AND digest>? ORDER BY digest LIMIT ?",bindings(vec![SqlValue::Blob(after.map(|v|v.to_vec()).unwrap_or_default()),SqlValue::Integer(limit as i64)])).await?).await?;
        records
            .into_iter()
            .map(|record| match record.as_slice() {
                [SqlValue::Blob(bytes)] => decode_bounded(bytes, MAX_TIP_STATEMENT_BYTES),
                _ => Err(Error::Corrupt("tip statement".into())),
            })
            .collect()
    }
    pub async fn follow_bookmark(&self, scope: Scope, name: &str) -> Result<TipId, Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        let previous = inner.workspace.tip;
        let target = inner
            .graph_for(scope)?
            .bookmark(name)
            .map_err(credential)?
            .ok_or_else(|| denied("bookmark does not exist"))?;
        inner.require_held_start(scope, target).await?;
        inner.follow_target(scope, name, target).await?;
        if previous != inner.workspace.tip
            && !inner
                .graph_for(scope)?
                .continues_any(previous, inner.workspace.tip)
                .map_err(credential)?
        {
            inner.bump_authority();
        }
        drop(flush_guard(inner, &self.inner).await?);
        Ok(target)
    }
    /// Enrolls through the identity, outside any database transaction.
    pub async fn enroll_line_node(
        &self,
        identity: &dyn rocky_credentials::IdentityProvider,
    ) -> Result<LineNode, Error> {
        let mut chain = self
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .config
            .credentials
            .clone();
        if chain
            .0
            .last()
            .is_some_and(|leaf| leaf.capability.kind == rocky_core::PrincipalKind::Node)
        {
            chain.0.pop();
        }
        let range = chain
            .0
            .last()
            .ok_or_else(|| denied("identity credential missing"))?
            .capability
            .authors()
            .map_err(credential)?
            .ok_or_else(|| denied("identity author range missing"))?;
        let author = identity.reserve_author(range).map_err(credential)?;
        let key = PrivateKey::new();
        let credentials = chain
            .complete(identity, key.public_key(), author)
            .map_err(credential)?;
        Ok(LineNode { key, credentials })
    }
    /// Restores a saved line's signer without selecting it for writes. Checkpoints
    /// at a shared seal may still need its page signatures on another branch.
    pub async fn restore_line_node(&self, node: LineNode) -> Result<(), Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        if node.credentials.principal() != inner.config.credentials.principal() {
            return Err(denied("line node belongs to another identity"));
        }
        inner.verify_chain(&node.credentials, node.key.public_key(), now()?)?;
        let records = collect_rows(
            inner
                .conn
                .query(
                    "SELECT line FROM secure_line_nodes WHERE node=?",
                    [node.key.public_key().as_bytes().to_vec()],
                )
                .await?,
        )
        .await?;
        let line = match records.as_slice() {
            [] => return Err(denied("line node was not registered")),
            [record] => match record.as_slice() {
                [SqlValue::Blob(line)] => line,
                _ => return Err(Error::Corrupt("line node".into())),
            },
            _ => {
                return Err(Error::Corrupt(
                    "a node author log belongs to one line".into(),
                ));
            }
        };
        let root = decode(line)?;
        let author = identity::NodeAuthor {
            number: node.credentials.author_number().map_err(credential)?,
            chain: Chain::new(node.credentials.clone())?,
            credentials: node.credentials,
            key: node.key,
        };
        inner.bind_node_author(&author.credentials).await?;
        inner.line_nodes.insert(root, author);
        Ok(())
    }
    pub async fn register_line_node(&self, node: LineNode) -> Result<(), Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        let (scope, _) = inner
            .workspace
            .followed
            .as_ref()
            .ok_or_else(|| denied("follow a bookmark first"))?;
        if !inner
            .node_continues(*scope, inner.workspace.tip, node.key.public_key())
            .await?
        {
            return Err(denied(
                "a node author log cannot cross a fork; enroll another node",
            ));
        }
        let root = inner
            .graph_for(*scope)?
            .line_root(inner.workspace.tip)
            .map_err(credential)?;
        let owner = inner
            .config
            .credentials
            .principal()
            .ok_or_else(|| denied("identity credential missing"))?;
        if node
            .credentials
            .principal()
            .ok_or_else(|| denied("identity credential missing"))?
            != owner
        {
            return Err(denied("line node belongs to another identity"));
        }
        inner.verify_chain(&node.credentials, node.key.public_key(), now()?)?;
        let selected = identity::NodeAuthor {
            number: node.credentials.author_number().map_err(credential)?,
            chain: Chain::new(node.credentials.clone())?,
            credentials: node.credentials,
            key: node.key,
        };
        transaction!(inner, |inner| {
            inner.bind_node_author(&selected.credentials).await?;
            let existing = collect_rows(
                inner
                    .conn
                    .query(
                        "SELECT line FROM secure_line_nodes WHERE node=?",
                        [selected.key.public_key().as_bytes().to_vec()],
                    )
                    .await?,
            )
            .await?;
            let expected = vec![SqlValue::Blob(encode(&root)?)];
            if existing.iter().any(|row| row != &expected) {
                return Err(denied("a node author log belongs to one line"));
            }
            inner.conn.execute("INSERT INTO secure_line_nodes VALUES(?,?) ON CONFLICT(line) DO UPDATE SET node=excluded.node",[encode(&root)?,selected.key.public_key().as_bytes().to_vec()]).await?;
            Ok(())
        })?;
        inner.line_nodes.insert(root, selected.clone());
        inner.node_author = Some(selected);
        flush_guard(inner, &self.inner).await.map(|_| ())
    }
    /// Admits this node's own statements. With a composed log, a seal or a
    /// move off an open tip first commits its digest as the tip's terminal
    /// log entry; a lost entry fails with `sealed` and nothing is published.
    /// With a composed log the batch is journaled, flushed, before its seals
    /// reach the coordinator, and kept after a reply that may have been lost,
    /// so `settle_tip_statements` sends the same bytes again.
    pub async fn publish_tip_statements(
        &self,
        statements: &[TipStatement],
    ) -> Result<usize, Error> {
        let journaled = match self.domain_log().is_some()
            && statements
                .iter()
                .any(|s| matches!(s, TipStatement::Seal(_)))
        {
            true => {
                self.check_statements(statements).await?;
                Some(self.journal_tips(statements, true).await?)
            }
            false => None,
        };
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .publication_fault(1)?;
        let coordinated = match self.coordinate_tip_statements(statements, true, true).await {
            Ok(coordinated) => coordinated,
            Err(error) => {
                let unconfirmed = match &error {
                    Error::Application(inner) => inner.downcast_ref::<coordinated::Unconfirmed>(),
                    _ => None,
                };
                return Err(match unconfirmed {
                    Some(unconfirmed) => {
                        coordinated::refusal(unconfirmed.code, &unconfirmed.message)
                    }
                    None => error,
                });
            }
        };
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .publication_fault(2)?;
        self.admit_tip_statements(&coordinated.kept, journaled)
            .await
    }
}

#[cfg(test)]
const MAX_FRONTIER_HEADERS: usize = 1 << 18;
#[cfg(test)]
const MAX_STORED_HEADER_BYTES: usize = 32 * 1024 * 1024;

/// Syntax only: no live status, custody, graph or authority decisions.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(super) struct StoredHeader {
    hash: Hash,
    public_key: PublicKey,
    seq_num: u64,
    pub(super) tip: TipId,
    pub(super) scope: ResourceScope,
    pub(super) author: Option<u32>,
    pub(super) author_sequence: u64,
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct StoredHeaders {
    entries: HashMap<Hash, (Vec<u8>, StoredHeader)>,
    bytes: usize,
    limits: Option<(usize, usize)>,
}
#[cfg(test)]
impl StoredHeaders {
    fn insert(&mut self, bytes: &[u8], header: StoredHeader) {
        let (count_limit, byte_limit) = self
            .limits
            .unwrap_or((MAX_FRONTIER_HEADERS, MAX_STORED_HEADER_BYTES));
        if let Some((old, _)) = self.entries.remove(&header.hash) {
            self.bytes -= old.len();
        }
        if self.entries.len() >= count_limit || self.bytes.saturating_add(bytes.len()) > byte_limit
        {
            self.entries.clear();
            self.bytes = 0;
        }
        if count_limit != 0 && bytes.len() <= byte_limit {
            self.bytes += bytes.len();
            self.entries.insert(header.hash, (bytes.to_vec(), header));
        }
    }
}
#[cfg(test)]
impl<A: RowApplication> Inner<A> {
    pub(super) fn oracle_header(&self, bytes: &[u8]) -> Result<StoredHeader, Error> {
        let hash = Hash::new(bytes);
        {
            let memo = self
                .frontier_headers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some((original, header)) = memo.entries.get(&hash)
                && original == bytes
            {
                return Ok(*header);
            }
        }
        self.position_oracles
            .decodes
            .fetch_add(1, Ordering::Relaxed);
        let header: p2panda_core::Header<Extensions> = decode(bytes)?;
        let e = &header.extensions;
        let fields = StoredHeader {
            hash,
            public_key: header.public_key,
            seq_num: header.seq_num,
            tip: e.tip,
            scope: e.scope,
            author: e.author,
            author_sequence: e.author_sequence,
        };
        self.frontier_headers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(bytes, fields);
        Ok(fields)
    }
    pub(crate) fn stored_header_memo_limits(&self, count: usize, bytes: usize) {
        *self
            .frontier_headers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = StoredHeaders {
            limits: Some((count, bytes)),
            ..Default::default()
        };
    }
    pub(crate) fn stored_header_memo_stats(&self) -> (usize, usize, u64) {
        let memo = self
            .frontier_headers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (
            memo.entries.len(),
            memo.bytes,
            self.position_oracles.decodes.load(Ordering::Relaxed),
        )
    }
}

pub(super) enum PathEnd {
    Visible,
    Hidden,
    Cyclic,
}
/// See `Inner::frame_path`.
pub(super) struct FramePath {
    bounds: Vec<Vec<rocky_credentials::AuthorMark>>,
    end: PathEnd,
}
impl FramePath {
    pub(super) fn admits(&self, author: u32, sequence: u64) -> Result<bool, Error> {
        if !self.bounds.iter().all(|frontier| {
            frontier
                .iter()
                .any(|mark| mark.author == author && sequence <= mark.sequence)
        }) {
            return Ok(false);
        }
        match self.end {
            PathEnd::Visible => Ok(true),
            PathEnd::Hidden => Ok(false),
            PathEnd::Cyclic => Err(denied("cyclic tip graph")),
        }
    }
}

impl<A: RowApplication> Inner<A> {
    #[cfg(test)]
    pub(in crate::replica) fn publication_fault(&mut self, step: u8) -> Result<(), Error> {
        if self.publication_fault == Some(step) {
            self.publication_fault = None;
            return Err(Error::InjectedFailure);
        }
        Ok(())
    }
    #[cfg(not(test))]
    pub(in crate::replica) fn publication_fault(&mut self, _step: u8) -> Result<(), Error> {
        Ok(())
    }
}
impl<A: RowApplication> EncryptedReplica<A> {
    #[cfg(test)]
    pub(crate) async fn fail_publication_after(&self, step: u8) {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .publication_fault = Some(step);
    }
}
