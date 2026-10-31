//! Signed header placements: where a seal's frontier positions of scopes
//! this replica cannot hold lie, proved by each frame's author-signed header
//! without its body. See `docs/runtime/lazy-compaction.md`.
use super::*;
use rocky_core::Scope;

pub(super) const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS secure_placements(domain BLOB NOT NULL,author INTEGER NOT NULL,sequence INTEGER NOT NULL,scope BLOB NOT NULL,hash BLOB NOT NULL,header BLOB NOT NULL,PRIMARY KEY(domain,author,sequence)) WITHOUT ROWID",
    // Two signed headers of one node at one position: kept as evidence.
    "CREATE TABLE IF NOT EXISTS secure_equivocations(domain BLOB NOT NULL,author INTEGER NOT NULL,sequence INTEGER NOT NULL,first BLOB NOT NULL,second BLOB NOT NULL,PRIMARY KEY(domain,author,sequence)) WITHOUT ROWID",
];

/// Headers a placement page carries at most.
pub const MAX_PLACEMENTS: usize = 64;
// Leave room for the native message and its signature.
const PLACEMENT_BYTES: usize = MAX_SECURE_FRAME - 1024;
/// Placement requests one pass sends at most.
const MAX_REQUESTS: usize = 16;

/// Positions `from..=to` of node `author` through `seal`'s frontier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementRequest {
    pub seal: Commitment,
    pub author: u32,
    pub from: u64,
    pub to: u64,
}
/// One frame's signed header, without its body.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Placement(#[serde(with = "serde_bytes")] pub Vec<u8>);
/// A placement answer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PlacementPage {
    /// The headers and, once each, the credential chains they name.
    Headers {
        headers: Vec<Placement>,
        chains: Vec<CredentialChain>,
    },
    /// A position lies in a partition the requester did not prove: its
    /// tuple is not shown, and only that partition's custody can settle it.
    CustodyRequired,
}

struct PlacementPlan {
    authority: u64,
    tip: TipId,
    scopes: Vec<(ResourceScope, Option<i64>)>,
    held: BTreeMap<u32, super::positions::Runs>,
    last: BTreeMap<(ResourceScope, u32), u64>,
    checks: Vec<(
        rocky_credentials::SignedSeal,
        Option<rocky_credentials::SignedSeal>,
    )>,
    unverified: BTreeSet<ResourceScope>,
}

impl<A: RowApplication> Inner<A> {
    /// What this replica asks peers to place: the gaps that keep a seal of
    /// the followed path from being finalized, and those of the seal the
    /// followed line inherits. Planned in one acquisition; each (seal,
    /// scope) check then runs in its own.
    async fn placement_plan(&self, domain: Scope) -> Result<PlacementPlan, Error> {
        let path = self.path_seals(domain)?;
        let scopes = self.readiness_scopes(domain).await?;
        let held_scopes = self.custody_scopes(now()?)?;
        let (held, last) = self.held_positions(domain, &scopes, &held_scopes).await?;
        let mut checks = Vec::new();
        for (index, seal) in path.iter().enumerate() {
            let id = seal.id().map_err(credential)?;
            if self.finalized_depth(domain, id).await?.is_some() {
                continue;
            }
            checks.push((
                seal.clone(),
                index.checked_sub(1).map(|previous| path[previous].clone()),
            ));
        }
        let unverified: BTreeSet<_> = self
            .unverified_scopes(domain)
            .await?
            .into_iter()
            .map(|(scope, _)| scope)
            .collect();
        if !unverified.is_empty()
            && let Some(seal) = path.last()
        {
            checks.push((seal.clone(), None));
        }
        // A line's first coordinated slot checks its parent seal from the start.
        let graph = self.graph_for(domain)?;
        if let Some((parent, _)) = Self::tip_parent(graph, self.workspace.tip)?
            && let Some(seal) = path.iter().find(|seal| seal.statement.tip == parent)
        {
            checks.push((seal.clone(), None));
        }
        Ok(PlacementPlan {
            authority: self.authority,
            tip: self.workspace.tip,
            scopes,
            held,
            last,
            checks,
            unverified,
        })
    }
    /// Answers `request` from the frames and voids this replica holds:
    /// released positions through the seal's frontier, without bodies.
    async fn placement_page(
        &self,
        peer: PublicKey,
        credentials: &CredentialChain,
        proved: &BTreeSet<ResourceScope>,
        request: PlacementRequest,
    ) -> Result<PlacementPage, Error> {
        let time = now()?;
        self.admit_chain(peer, credentials, time)?;
        if self
            .config
            .revocations
            .revoking(credentials)
            .map_err(credential)?
            .is_some()
        {
            return Err(denied(crate::network::PEER_REVOKED));
        }
        if self.private_schema().await? {
            return Err(denied("schema publication is private"));
        }
        let Some((domain, seal)) = self.graphs.iter().find_map(|(domain, graph)| {
            graph
                .seal_by_id(request.seal)
                .ok()
                .map(|seal| (*domain, seal.clone()))
        }) else {
            // A peer that has not learned the seal has nothing to place.
            return Ok(PlacementPage::Headers {
                headers: Vec::new(),
                chains: Vec::new(),
            });
        };
        let (grants, selectors) = credentials
            .verify_selectors(self.config.publisher, peer, &self.config.revocations, time)
            .map_err(credential)?;
        if !grants.iter().any(|grant| grant.scope.domain == domain)
            && !selectors.iter().any(|grant| grant.domain == domain)
        {
            return Err(denied("placement requester is not a domain member"));
        }
        let mark = seal
            .statement
            .frontier
            .iter()
            .find(|mark| mark.author == request.author)
            .map(|mark| mark.sequence);
        if request.from > request.to
            || request.to - request.from >= MAX_PLACEMENTS as u64
            || mark.is_none_or(|mark| request.to > mark)
        {
            return Err(denied("placement request outside the seal's frontier"));
        }
        let staged = self.unsent().await?;
        let mut headers = BTreeSet::new();
        let mut chains = BTreeMap::new();
        let mut candidates = Vec::new();
        for (header, has_body) in self
            .headers_at(domain, request.author, request.from, request.to)
            .await?
        {
            let decoded: p2panda_core::Header<Extensions> = decode(&header)?;
            let e = &decoded.extensions;
            if e.scope.domain != domain
                || e.author != Some(request.author)
                || !(request.from..=request.to).contains(&e.author_sequence)
            {
                return Err(Error::Corrupt("indexed placement source".into()));
            }
            candidates.push((decoded, header, has_body));
        }
        // A short byte-bounded page must place the earliest missing positions first.
        candidates.sort_by(|a, b| {
            a.0.extensions
                .author_sequence
                .cmp(&b.0.extensions.author_sequence)
                .then_with(|| a.1.cmp(&b.1))
        });
        let mut bytes = 0usize;
        for (decoded, header, has_body) in candidates {
            let e = &decoded.extensions;
            if staged.contains(&decoded.hash()) {
                continue;
            }
            // A migration frame leaves only with its released publication.
            if has_body
                && !matches!(
                    self.migration_membership(decoded.hash()).await,
                    Ok(None
                        | Some(MigrationMembership {
                            descriptor: Some(_),
                            ..
                        }))
                )
            {
                continue;
            }
            // A revoked author's header is no evidence, as in range serving;
            // it is checked against the current set before any other gate.
            let chain = self.stored_chain(e.chain).await?;
            if self
                .config
                .revocations
                .revoking(chain.credentials())
                .map_err(credential)?
                .is_some()
            {
                continue;
            }
            if e.partition.is_some() && !proved.contains(&e.scope) {
                return Ok(PlacementPage::CustodyRequired);
            }
            if headers.len() == MAX_PLACEMENTS {
                break;
            }
            let placement = Placement(header);
            if headers.contains(&placement) {
                continue;
            }
            let size = encode(&placement)?
                .len()
                .saturating_add(if chains.contains_key(&e.chain) {
                    0
                } else {
                    encode(chain.credentials())?.len()
                });
            if bytes.saturating_add(size) > PLACEMENT_BYTES {
                if headers.is_empty() {
                    return Err(denied("one placement exceeds the native frame quota"));
                }
                break;
            }
            bytes += size;
            chains
                .entry(e.chain)
                .or_insert_with(|| chain.credentials().clone());
            headers.insert(placement);
        }
        Ok(PlacementPage::Headers {
            headers: headers.into_iter().collect(),
            chains: chains.into_values().collect(),
        })
    }
    /// Verifies and stores `placements` answering `request`, inside one
    /// transaction. A header of a scope this replica holds is not stored:
    /// that scope needs the frame itself. Returns how many it stored.
    async fn receive_placements(
        &mut self,
        request: PlacementRequest,
        placements: Vec<Placement>,
        chains: Vec<CredentialChain>,
    ) -> Result<usize, Error> {
        if placements.len() > MAX_PLACEMENTS || chains.len() > MAX_PLACEMENTS {
            return Err(denied("placement page quota"));
        }
        let chains = chains
            .into_iter()
            .map(|credentials| {
                crate::wire::Chain::new(credentials).map(|chain| (chain.digest(), chain))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let time = now()?;
        let (domain, seal) = self
            .graphs
            .iter()
            .find_map(|(domain, graph)| {
                graph
                    .seal_by_id(request.seal)
                    .ok()
                    .map(|seal| (*domain, seal.clone()))
            })
            .ok_or_else(|| denied("unknown seal"))?;
        let mark = seal
            .statement
            .frontier
            .iter()
            .find(|mark| mark.author == request.author)
            .map(|mark| mark.sequence)
            .ok_or_else(|| denied("placement outside the seal's frontier"))?;
        let held = self.custody_scopes(time)?;
        let mut verified = Vec::new();
        for Placement(bytes) in placements {
            let header = crate::wire::verified_header(&bytes)?;
            let e = &header.extensions;
            let chain = chains
                .get(&e.chain)
                .ok_or_else(|| denied(crate::wire::INCOMPLETE_FRAME))?;
            if e.scope.domain != domain
                || e.author != Some(request.author)
                || !(request.from..=request.to.min(mark)).contains(&e.author_sequence)
            {
                return Err(denied("placement outside its request"));
            }
            if !self.visible_frame(
                self.graph_for(domain)?,
                e.tip,
                request.author,
                e.author_sequence,
                seal.statement.tip,
            )? {
                return Err(denied("placement not inside the seal's state"));
            }
            self.verify_header_authority(&header, chain.credentials(), time)?;
            // A scope this node may take custody of needs the frame itself.
            if held.contains(&e.scope) {
                continue;
            }
            verified.push((header, bytes));
        }
        let mut stored = 0;
        transaction!(self, |inner| {
            stored = 0;
            for (header, bytes) in &verified {
                if inner.place(domain, header, bytes).await? {
                    stored += 1;
                }
            }
            Ok(())
        })?;
        Ok(stored)
    }
    /// Stores one verified placement unless a frame, void or placement
    /// holds its position already; another header there is equivocation.
    async fn place(
        &self,
        domain: Scope,
        header: &p2panda_core::Header<Extensions>,
        bytes: &[u8],
    ) -> Result<bool, Error> {
        let e = &header.extensions;
        let author = e
            .author
            .ok_or_else(|| denied("node author number missing"))?;
        let hash = header.hash();
        if let Some(known) = self
            .header_at(domain, author, e.author_sequence, hash)
            .await?
        {
            if known.hash() != hash {
                self.record_equivocation(domain, &known, header).await?;
            }
            return Ok(false);
        }
        self.no_frames_intake(header).await?;
        self.conn
            .execute(
                "INSERT OR IGNORE INTO secure_placements VALUES(?,?,?,?,?,?)",
                bindings(vec![
                    SqlValue::Blob(encode(&domain)?),
                    SqlValue::Integer(i64::from(author)),
                    SqlValue::Integer(e.author_sequence as i64),
                    SqlValue::Blob(encode(&e.scope)?),
                    SqlValue::Blob(hash.as_bytes().to_vec()),
                    SqlValue::Blob(bytes.to_vec()),
                ]),
            )
            .await?;
        positions::insert(&self.conn, header, 2, false, false).await?;
        self.custody_required
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&(domain, author, e.author_sequence));
        Ok(true)
    }
    /// The retained operation and void headers of `author` in `domain` from
    /// `from` through `to`, and whether each has a body, found through the
    /// position index without reading a body.
    async fn headers_at(
        &self,
        domain: Scope,
        author: u32,
        from: u64,
        to: u64,
    ) -> Result<Vec<(Vec<u8>, bool)>, Error> {
        let mut headers = Vec::new();
        let scopes = collect_rows(
            self.conn
                .query(
                    "SELECT DISTINCT scope FROM secure_position_ranges WHERE author=? AND kind<2",
                    [i64::from(author)],
                )
                .await?,
        )
        .await?;
        for scope in scopes {
            let [SqlValue::Blob(scope)] = scope.as_slice() else {
                return Err(Error::Corrupt("position scope".into()));
            };
            if decode::<ResourceScope>(scope)?.domain != domain {
                continue;
            }
            let found = collect_rows(self.conn.query(
                "SELECT o.header,length(o.body)>0 FROM secure_position_sources p JOIN secure_operations o ON o.hash=p.hash WHERE p.scope=?1 AND p.author=?2 AND p.sequence BETWEEN ?3 AND ?4 AND p.kind=0 UNION ALL SELECT v.header,0 FROM secure_position_sources p JOIN secure_voids v ON v.hash=p.hash WHERE p.scope=?1 AND p.author=?2 AND p.sequence BETWEEN ?3 AND ?4 AND p.kind=1",
                bindings(vec![
                    SqlValue::Blob(scope.clone()),
                    SqlValue::Integer(i64::from(author)),
                    SqlValue::Integer(i64::try_from(from).map_err(|_| denied("placement sequence"))?),
                    SqlValue::Integer(i64::try_from(to).map_err(|_| denied("placement sequence"))?),
                ]),
            ).await?).await?;
            for record in found {
                let [SqlValue::Blob(header), SqlValue::Integer(body)] = record.as_slice() else {
                    return Err(Error::Corrupt("placement header".into()));
                };
                headers.push((header.clone(), *body != 0));
            }
        }
        Ok(headers)
    }
    /// Prefers a conflicting retained header when the incoming placement is known.
    async fn header_at(
        &self,
        domain: Scope,
        author: u32,
        sequence: u64,
        incoming: Hash,
    ) -> Result<Option<p2panda_core::Header<Extensions>>, Error> {
        let records = collect_rows(
            self.conn
                .query(
                    "SELECT header FROM secure_placements WHERE domain=? AND author=? AND sequence=?",
                    bindings(vec![
                        SqlValue::Blob(encode(&domain)?),
                        SqlValue::Integer(i64::from(author)),
                        SqlValue::Integer(sequence as i64),
                    ]),
                )
                .await?,
        )
        .await?;
        if let Some([SqlValue::Blob(bytes)]) = records.first().map(Vec::as_slice) {
            return Ok(Some(decode(bytes)?));
        }
        let mut known = None;
        for (bytes, _) in self.headers_at(domain, author, sequence, sequence).await? {
            let header: p2panda_core::Header<Extensions> = decode(&bytes)?;
            let e = &header.extensions;
            // An equal match must not hide evidence of another signed header.
            if e.scope.domain == domain
                && e.author == Some(author)
                && e.author_sequence == sequence
                && known
                    .as_ref()
                    .is_none_or(|prior: &p2panda_core::Header<Extensions>| {
                        prior.hash() == incoming && header.hash() != incoming
                    })
            {
                known = Some(header);
            }
        }
        Ok(known)
    }
    #[cfg(test)]
    pub(crate) async fn place_verified_for_test(
        &self,
        header: &p2panda_core::Header<Extensions>,
    ) -> Result<bool, Error> {
        self.place(header.extensions.scope.domain, header, &header.to_bytes())
            .await
    }
    /// Inside the caller's transaction: a frame stored at a placed position
    /// replaces its placement; a different header there is equivocation.
    pub(super) async fn settle_placement(
        &self,
        header: &p2panda_core::Header<Extensions>,
    ) -> Result<(), Error> {
        let e = &header.extensions;
        let Some(author) = e.author else {
            return Ok(());
        };
        let domain = e.scope.domain;
        let records = collect_rows(
            self.conn
                .query(
                    "SELECT header FROM secure_placements WHERE domain=? AND author=? AND sequence=?",
                    bindings(vec![
                        SqlValue::Blob(encode(&domain)?),
                        SqlValue::Integer(i64::from(author)),
                        SqlValue::Integer(e.author_sequence as i64),
                    ]),
                )
                .await?,
        )
        .await?;
        let Some([SqlValue::Blob(bytes)]) = records.first().map(Vec::as_slice) else {
            return Ok(());
        };
        let placed: p2panda_core::Header<Extensions> = decode(bytes)?;
        if placed.hash() != header.hash() {
            self.record_equivocation(domain, &placed, header).await?;
        }
        self.conn
            .execute(
                "DELETE FROM secure_placements WHERE domain=? AND author=? AND sequence=?",
                bindings(vec![
                    SqlValue::Blob(encode(&domain)?),
                    SqlValue::Integer(i64::from(author)),
                    SqlValue::Integer(e.author_sequence as i64),
                ]),
            )
            .await?;
        Ok(())
    }
    async fn record_equivocation(
        &self,
        domain: Scope,
        first: &p2panda_core::Header<Extensions>,
        second: &p2panda_core::Header<Extensions>,
    ) -> Result<(), Error> {
        let e = &first.extensions;
        self.conn
            .execute(
                "INSERT OR IGNORE INTO secure_equivocations VALUES(?,?,?,?,?)",
                bindings(vec![
                    SqlValue::Blob(encode(&domain)?),
                    SqlValue::Integer(i64::from(e.author.unwrap_or_default())),
                    SqlValue::Integer(e.author_sequence as i64),
                    SqlValue::Blob(encode(first)?),
                    SqlValue::Blob(encode(second)?),
                ]),
            )
            .await?;
        Ok(())
    }
    /// Inside the caller's transaction: drops placements every held
    /// scope's base folded, through the oldest base seal of the path.
    pub(super) async fn prune_placements(&self, domain: Scope) -> Result<(), Error> {
        let path = self.path_seals(domain)?;
        let mut oldest: Option<usize> = None;
        for (_, id) in self.domain_scopes(domain).await? {
            let at = match self.base_seal(id).await? {
                Some(base) => self.path_index(domain, base)?,
                None => None,
            };
            let Some(at) = at else {
                return Ok(());
            };
            oldest = Some(oldest.map_or(at, |oldest| oldest.min(at)));
        }
        let Some(seal) = oldest.and_then(|at| path.get(at)) else {
            return Ok(());
        };
        for mark in &seal.statement.frontier {
            self.conn
                .execute(
                    "DELETE FROM secure_placements WHERE domain=? AND author=? AND sequence<=?",
                    bindings(vec![
                        SqlValue::Blob(encode(&domain)?),
                        SqlValue::Integer(i64::from(mark.author)),
                        SqlValue::Integer(mark.sequence as i64),
                    ]),
                )
                .await?;
        }
        Ok(())
    }
}

impl<A: RowApplication> EncryptedReplica<A> {
    /// The placement requests this replica wants answered. A receiver
    /// revalidates every request; a moved authority or tip ends the listing
    /// early with what it found, and the next pass asks again.
    pub async fn wanted_placements(&self) -> Result<Vec<PlacementRequest>, Error> {
        let plan = {
            let inner = self.inner.lock(crate::replica::Class::Background).await;
            let Some((domain, _)) = inner.workspace.followed.clone() else {
                return Ok(Vec::new());
            };
            inner.placement_plan(domain).await?
        };
        let mut requests: Vec<PlacementRequest> = Vec::new();
        for (seal, previous) in &plan.checks {
            let id = seal.id().map_err(credential)?;
            let mut gaps = BTreeSet::new();
            for (scope, scope_id) in &plan.scopes {
                tokio::task::yield_now().await;
                let inner = self.inner.lock(crate::replica::Class::Background).await;
                // A plan from another authority or tip only asks for placements the
                // peer refuses or this replica no longer needs.
                if (inner.authority, inner.workspace.tip) != (plan.authority, plan.tip) {
                    return Ok(requests);
                }
                let previous = previous
                    .as_ref()
                    .filter(|_| !plan.unverified.contains(scope));
                let starts = inner.seal_starts(*scope_id, previous).await?;
                gaps.extend(compaction::blocking_gaps(
                    seal,
                    &starts,
                    &[(*scope, *scope_id)],
                    &plan.held,
                    &plan.last,
                    MAX_REQUESTS * MAX_PLACEMENTS,
                ));
            }
            for (author, position) in gaps {
                if requests.iter().any(|request| {
                    request.author == author && (request.from..=request.to).contains(&position)
                }) {
                    continue;
                }
                if let Some(request) = requests.last_mut()
                    && request.seal == id
                    && request.author == author
                    && request.to + 1 == position
                    && position - request.from < MAX_PLACEMENTS as u64
                {
                    request.to = position;
                    continue;
                }
                if requests.len() == MAX_REQUESTS {
                    return Ok(requests);
                }
                requests.push(PlacementRequest {
                    seal: id,
                    author,
                    from: position,
                    to: position,
                });
            }
        }
        Ok(requests)
    }
    /// Answers a peer's placement request.
    pub async fn placement_page(
        &self,
        peer: PublicKey,
        credentials: &CredentialChain,
        proved: &BTreeSet<ResourceScope>,
        request: PlacementRequest,
    ) -> Result<PlacementPage, Error> {
        self.inner
            .lock(crate::replica::Class::Background)
            .await
            .placement_page(peer, credentials, proved, request)
            .await
    }
    /// Stores a peer's answer to `request`; a page the peer could not
    /// answer without showing a partition marks its positions as needing
    /// that partition's custody.
    pub async fn receive_placements(
        &self,
        request: PlacementRequest,
        page: PlacementPage,
    ) -> Result<usize, Error> {
        let mut inner = self.inner.lock(crate::replica::Class::Background).await;
        match page {
            PlacementPage::Headers { headers, chains } => {
                let stored = inner.receive_placements(request, headers, chains).await?;
                if stored > 0 {
                    inner.publish_revision().await?;
                }
                Ok(stored)
            }
            PlacementPage::CustodyRequired => {
                let domain = inner
                    .graphs
                    .iter()
                    .find_map(|(domain, graph)| {
                        graph.seal_by_id(request.seal).ok().map(|_| *domain)
                    })
                    .ok_or_else(|| denied("unknown seal"))?;
                let mut blocked = inner
                    .custody_required
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for sequence in request.from..=request.to {
                    blocked.insert((domain, request.author, sequence));
                }
                Ok(0)
            }
        }
    }
    /// Pairs of different signed headers seen at one node position.
    pub async fn equivocations(&self) -> Result<usize, Error> {
        let inner = self.inner.lock(crate::replica::Class::Background).await;
        match rows(&inner.conn, "SELECT count(*) FROM secure_equivocations")
            .await?
            .first()
            .map(Vec::as_slice)
        {
            Some([SqlValue::Integer(count)]) => Ok(*count as usize),
            _ => Err(Error::Corrupt("equivocations".into())),
        }
    }
}
