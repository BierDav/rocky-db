//! Transactional position indexes. Triggers cover bulk status and deletion writers too.
use super::*;
use rocky_core::Scope;
use rocky_credentials::SignedSeal;

pub(super) const SCHEMA: &[&str] = &[
    "CREATE TABLE secure_position_sources(hash BLOB NOT NULL,kind INTEGER NOT NULL,scope BLOB NOT NULL,author INTEGER NOT NULL,sequence INTEGER NOT NULL,signer BLOB NOT NULL,tip BLOB NOT NULL,log_sequence INTEGER NOT NULL,pending INTEGER NOT NULL,applied INTEGER NOT NULL,PRIMARY KEY(hash,kind)) WITHOUT ROWID",
    "CREATE INDEX secure_position_sources_seal ON secure_position_sources(scope,tip,author,sequence,kind,hash)",
    "CREATE INDEX secure_position_sources_domain ON secure_position_sources(scope,author,sequence,kind,pending)",
    "CREATE INDEX secure_position_sources_log ON secure_position_sources(scope,signer,tip,author,applied,log_sequence)",
    "CREATE TABLE secure_position_ranges(scope BLOB NOT NULL,author INTEGER NOT NULL,kind INTEGER NOT NULL,pending INTEGER NOT NULL,start INTEGER NOT NULL,end INTEGER NOT NULL,CHECK(start<=end),PRIMARY KEY(scope,author,kind,pending,start)) WITHOUT ROWID",
    "CREATE TABLE secure_log_ranges(scope BLOB NOT NULL,author BLOB NOT NULL,tip BLOB NOT NULL,applied INTEGER NOT NULL,domain_author INTEGER NOT NULL,delta INTEGER NOT NULL,start INTEGER NOT NULL,end INTEGER NOT NULL,CHECK(start<=end),PRIMARY KEY(scope,author,tip,applied,domain_author,delta,start)) WITHOUT ROWID",
];

/// These triggers are the only status/delete writers, including bulk SQL and cascades.
pub(super) fn triggers() -> Vec<String> {
    let mut statements = Vec::new();
    for event in ["INSERT", "DELETE", "UPDATE"] {
        for log in [false, true] {
            let mut body = String::new();
            if event != "INSERT" {
                body.push_str(&range_write(log, true));
            }
            if event != "DELETE" {
                body.push_str(&range_write(log, false));
            }
            let prefix = if log {
                "secure_position_logs"
            } else {
                "secure_positions"
            };
            let guard = if log {
                format!(
                    "WHEN {}.kind<>2",
                    if event == "DELETE" { "OLD" } else { "NEW" }
                )
            } else {
                String::new()
            };
            statements.push(format!("CREATE TRIGGER {prefix}_{} AFTER {event} ON secure_position_sources {guard} BEGIN {body} END",event.to_ascii_lowercase()));
        }
    }
    for (kind, table) in [
        (0, "secure_operations"),
        (1, "secure_voids"),
        (2, "secure_placements"),
    ] {
        statements.push(format!("CREATE TRIGGER secure_positions_delete_{kind} AFTER DELETE ON {table} BEGIN DELETE FROM secure_position_sources WHERE hash=OLD.hash AND kind={kind}; END"));
    }
    statements.push("CREATE TRIGGER secure_positions_status AFTER UPDATE OF status ON secure_operations WHEN OLD.status<>NEW.status BEGIN UPDATE secure_position_sources SET pending=(NEW.status='pending'),applied=(NEW.status IN ('applied','abandoned','held')) WHERE hash=NEW.hash AND kind=0; END".into());
    statements
}

pub(super) async fn check_schema(conn: &ScopedConnection) -> Result<(), Error> {
    let mut actual = BTreeMap::new();
    for row in rows(
        conn,
        "SELECT name,sql FROM sqlite_schema WHERE name GLOB 'secure_position*' OR name='secure_log_ranges'",
    )
    .await?
    {
        let [SqlValue::Text(name), SqlValue::Text(sql)] = row.as_slice() else {
            return Err(Error::Corrupt("position schema object".into()));
        };
        actual.insert(name.clone(), sql.clone());
    }
    let expected: BTreeMap<_, _> = SCHEMA
        .iter()
        .map(|sql| (*sql).to_owned())
        .chain(triggers())
        .map(|sql| {
            (
                sql.split_whitespace()
                    .nth(2)
                    .unwrap_or_default()
                    .split('(')
                    .next()
                    .unwrap_or_default()
                    .to_owned(),
                sql,
            )
        })
        .collect();
    if actual != expected {
        return Err(Error::Corrupt(
            "position schema differs from current format".into(),
        ));
    }
    Ok(())
}

fn range_write(log: bool, remove: bool) -> String {
    let r = if remove { "OLD" } else { "NEW" };
    let (table, coordinates, x) = if log {
        (
            "secure_log_ranges",
            vec![
                ("scope", "scope"),
                ("author", "signer"),
                ("tip", "tip"),
                ("applied", "applied"),
                ("domain_author", "author"),
                ("delta", "sequence-{r}.log_sequence"),
            ],
            "log_sequence",
        )
    } else {
        (
            "secure_position_ranges",
            vec![
                ("scope", "scope"),
                ("author", "author"),
                ("kind", "kind"),
                ("pending", "pending"),
            ],
            "sequence",
        )
    };
    let coordinates: Vec<_> = coordinates
        .into_iter()
        .map(|(column, field)| (column, format!("{r}.{}", field.replace("{r}", r))))
        .collect();
    let columns = coordinates
        .iter()
        .map(|(column, _)| *column)
        .collect::<Vec<_>>()
        .join(",");
    let values = coordinates
        .iter()
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let bucket = coordinates
        .iter()
        .map(|(column, value)| format!("{column}=({value})"))
        .collect::<Vec<_>>()
        .join(" AND ");
    let x = format!("{r}.{x}");
    if !remove {
        return format!(
            "INSERT OR REPLACE INTO {table}({columns},start,end) SELECT {values},min(coalesce(min(start),{x}),{x}),max(coalesce(max(end),{x}),{x}) FROM {table} WHERE {bucket} AND end>=({x})-1 AND start<=({x})+1; DELETE FROM {table} WHERE {bucket} AND start>({x}) AND start<=({x})+1;"
        );
    }
    let duplicate = if log {
        "scope=OLD.scope AND signer=OLD.signer AND tip=OLD.tip AND applied=OLD.applied AND author=OLD.author AND sequence-log_sequence=OLD.sequence-OLD.log_sequence AND log_sequence=OLD.log_sequence AND kind<>2"
    } else {
        "scope=OLD.scope AND author=OLD.author AND sequence=OLD.sequence AND kind=OLD.kind AND pending=OLD.pending"
    };
    let guard = format!(
        "NOT EXISTS(SELECT 1 FROM secure_position_sources WHERE {duplicate} AND NOT(hash=OLD.hash AND kind=OLD.kind))"
    );
    format!(
        "INSERT INTO {table}({columns},start,end) SELECT {values},({x})+1,end FROM {table} WHERE {bucket} AND start<=({x}) AND end>({x}) AND {guard}; UPDATE {table} SET end=({x})-1 WHERE {bucket} AND start<({x}) AND end>=({x}) AND {guard}; DELETE FROM {table} WHERE {bucket} AND start=({x}) AND {guard};"
    )
}

pub(crate) async fn insert(
    conn: &ScopedConnection,
    header: &p2panda_core::Header<Extensions>,
    kind: i64,
    pending: bool,
    applied: bool,
) -> Result<(), Error> {
    let e = &header.extensions;
    let author = e.author.ok_or_else(|| denied("node author missing"))?;
    let sequence =
        i64::try_from(e.author_sequence).map_err(|_| denied("author sequence overflow"))?;
    let log_sequence =
        i64::try_from(header.seq_num).map_err(|_| denied("log sequence overflow"))?;
    // OR IGNORE here would also suppress a trigger's range merge on conflict.
    conn.execute(
        "INSERT INTO secure_position_sources VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(hash,kind) DO NOTHING",
        bindings(vec![
            SqlValue::Blob(header.hash().as_bytes().to_vec()),
            SqlValue::Integer(kind),
            SqlValue::Blob(encode(&e.scope)?),
            SqlValue::Integer(i64::from(author)),
            SqlValue::Integer(sequence),
            SqlValue::Blob(header.public_key.as_bytes().to_vec()),
            SqlValue::Blob(e.tip.0.to_vec()),
            SqlValue::Integer(log_sequence),
            SqlValue::Integer(i64::from(pending)),
            SqlValue::Integer(i64::from(applied)),
        ]),
    )
    .await?;
    Ok(())
}

/// Sorted, disjoint, maximal inclusive intervals.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Runs(pub(super) BTreeMap<u64, u64>);
impl Runs {
    fn insert(&mut self, mut start: u64, mut end: u64) {
        if let Some((&a, &b)) = self.0.range(..=start).next_back()
            && b.saturating_add(1) >= start
        {
            start = a;
            end = end.max(b);
            self.0.remove(&a);
        }
        while let Some((&a, &b)) = self.0.range(start..).next() {
            if a > end.saturating_add(1) {
                break;
            }
            end = end.max(b);
            self.0.remove(&a);
        }
        self.0.insert(start, end);
    }
    fn through(&self, mut next: u64) -> u64 {
        for (&start, &end) in &self.0 {
            if start > next {
                break;
            }
            if end >= next {
                next = end.saturating_add(1);
            }
        }
        next
    }
    #[cfg(test)]
    fn expand(&self) -> BTreeSet<u64> {
        self.0.iter().flat_map(|(a, b)| *a..=*b).collect()
    }
}

type Positions = (BTreeMap<u32, Runs>, BTreeMap<(ResourceScope, u32), u64>);

impl<A: RowApplication> Inner<A> {
    pub(super) async fn held_positions(
        &self,
        domain: Scope,
        scopes: &[(ResourceScope, Option<i64>)],
        held_scopes: &BTreeSet<ResourceScope>,
    ) -> Result<Positions, Error> {
        let ready: BTreeSet<_> = scopes.iter().map(|(scope, _)| *scope).collect();
        let mut held = BTreeMap::<u32, Runs>::new();
        let mut last = BTreeMap::<(ResourceScope, u32), u64>::new();
        for row in rows(
            &self.conn,
            "SELECT scope,author,kind,pending,start,end FROM secure_position_ranges",
        )
        .await?
        {
            let [
                SqlValue::Blob(scope),
                SqlValue::Integer(author),
                SqlValue::Integer(kind),
                SqlValue::Integer(pending),
                SqlValue::Integer(start),
                SqlValue::Integer(end),
            ] = row.as_slice()
            else {
                return Err(Error::Corrupt("position range".into()));
            };
            let scope: ResourceScope = decode(scope)?;
            if scope.domain != domain
                || (*pending != 0 && ready.contains(&scope) && self.has_scope_key(scope))
                || (*kind == 2 && held_scopes.contains(&scope))
            {
                continue;
            }
            let author =
                u32::try_from(*author).map_err(|_| Error::Corrupt("position author".into()))?;
            let (start, end) = interval(*start, *end)?;
            held.entry(author).or_default().insert(start, end);
            if *kind != 2 && ready.contains(&scope) {
                last.entry((scope, author))
                    .and_modify(|n| *n = (*n).max(end))
                    .or_insert(end);
            }
        }
        let result = (held, last);
        #[cfg(test)]
        {
            let _oracle = self.position_oracles.start();
            let scan = self
                .scan_held_positions(domain, scopes, held_scopes)
                .await?;
            let expanded = (
                result.0.iter().map(|(a, r)| (*a, r.expand())).collect(),
                result.1.clone(),
            );
            if expanded != scan {
                return Err(Error::Corrupt("position index differs from headers".into()));
            }
        }
        Ok(result)
    }

    pub(in crate::replica) async fn deferred_at(
        &self,
        scope: ResourceScope,
        seal: &SignedSeal,
    ) -> Result<bool, Error> {
        let mut deferred = false;
        if !self.has_scope_key(scope) {
            for mark in &seal.statement.frontier {
                if !collect_rows(self.conn.query("SELECT 1 FROM secure_position_ranges WHERE scope=? AND author=? AND kind=0 AND start<=? LIMIT 1",bindings(vec![SqlValue::Blob(encode(&scope)?),SqlValue::Integer(i64::from(mark.author)),SqlValue::Integer(i64::try_from(mark.sequence).unwrap_or(i64::MAX))])).await?).await?.is_empty() { deferred=true; break; }
            }
        }
        #[cfg(test)]
        {
            let _oracle = self.position_oracles.start();
            if deferred != self.scan_deferred_at(scope, seal).await? {
                return Err(Error::Corrupt("deferred index differs from headers".into()));
            }
        }
        Ok(deferred)
    }

    pub(crate) async fn compute_tip_frontier(
        &self,
        scope: ResourceScope,
    ) -> Result<ScopeFrontier, Error> {
        #[cfg(test)]
        self.frontier_queries.fetch_add(1, Ordering::Relaxed);
        let mut positions = BTreeMap::<PublicKey, (Runs, Runs)>::new();
        let graph = self.graph_for(scope.domain)?;
        let mut paths = BTreeMap::new();
        for row in collect_rows(self.conn.query("SELECT author,tip,applied,domain_author,delta,start,end FROM secure_log_ranges WHERE scope=?", [encode(&scope)?]).await?).await? {
            let [SqlValue::Blob(author),SqlValue::Blob(tip),SqlValue::Integer(applied),SqlValue::Integer(domain_author),SqlValue::Integer(delta),SqlValue::Integer(start),SqlValue::Integer(end)] = row.as_slice() else { return Err(Error::Corrupt("log range".into())); };
            let author = PublicKey::from_bytes(author.as_slice().try_into().map_err(|_| Error::Corrupt("log range signer".into()))?).map_err(|_| Error::Corrupt("log range signer".into()))?;
            let tip = TipId(tip.as_slice().try_into().map_err(|_| Error::Corrupt("log range tip".into()))?);
            let domain_author = u32::try_from(*domain_author).map_err(|_| Error::Corrupt("log range author".into()))?;
            let (start, mut end) = interval(*start,*end)?;
            let path = match paths.entry(tip) {
                std::collections::btree_map::Entry::Occupied(p) => p.into_mut(),
                std::collections::btree_map::Entry::Vacant(p) => p.insert(Self::frame_path(graph,tip,self.workspace.tip)?),
            };
            let domain_sequence = |n:u64| -> Result<u64,Error> { u64::try_from(i128::from(n)+i128::from(*delta)).map_err(|_| Error::Corrupt("log range coordinates".into())) };
            if !path.admits(domain_author,domain_sequence(start)?)? { continue; }
            if !path.admits(domain_author,domain_sequence(end)?)? {
                // Admission is a prefix in domain coordinates. Clip the affine run.
                let mut low=start;
                let mut high=end;
                while low<high {
                    let middle=low+(high-low).div_ceil(2);
                    if path.admits(domain_author,domain_sequence(middle)?)? { low=middle; } else { high=middle-1; }
                }
                end=low;
            }
            let runs=positions.entry(author).or_default();
            runs.0.insert(start,end);
            if *applied != 0 { runs.1.insert(start,end); }
        }
        let mut starts = BTreeMap::new();
        if let Some(id) = self.find_scope_id(scope).await? {
            for (log, prefix) in self.logs(id, None, false, MAX_CHECKPOINT_LOGS + 1).await? {
                if prefix >= 0 {
                    starts.insert(log.author, prefix as u64 + 1);
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
            let start = starts.get(&author).copied().unwrap_or(0);
            let (held, applied) = positions
                .get(&author)
                .map_or((start, start), |(held, applied)| {
                    (held.through(start), applied.through(start))
                });
            if held > 0 {
                logs.push(FrontierLog {
                    author,
                    held,
                    applied: applied.min(held),
                });
            }
        }
        if logs.len() > MAX_CHECKPOINT_LOGS {
            return Err(denied("logs per scope quota"));
        }
        let frontier = ScopeFrontier { scope, logs };
        #[cfg(test)]
        {
            let _oracle = self.position_oracles.start();
            if frontier != self.scan_tip_frontier(scope).await? {
                return Err(Error::Corrupt("frontier index differs from headers".into()));
            }
        }
        Ok(frontier)
    }
}

fn interval(start: i64, end: i64) -> Result<(u64, u64), Error> {
    if start < 0 || end < start {
        return Err(Error::Corrupt("position interval".into()));
    }
    Ok((start as u64, end as u64))
}

impl<A: RowApplication> Inner<A> {
    /// Rebuilds the index independently from retained signed headers, never from indexes.
    pub(super) async fn audit_positions(&self) -> Result<(), Error> {
        check_schema(&self.conn).await?;
        #[cfg(test)]
        let _oracle = self.position_oracles.start();
        let mut sources = BTreeMap::new();
        for row in rows(&self.conn,"SELECT hash,header,0,status FROM secure_operations UNION ALL SELECT hash,header,1,'applied' FROM secure_voids UNION ALL SELECT hash,header,2,'placement' FROM secure_placements").await? {
            let [SqlValue::Blob(hash),SqlValue::Blob(bytes),SqlValue::Integer(kind),SqlValue::Text(status)] = row.as_slice() else { return Err(Error::Corrupt("position source header".into())); };
            #[cfg(test)]
            self.position_oracles.decodes.fetch_add(1,Ordering::Relaxed);
            let header: p2panda_core::Header<Extensions> = decode(bytes)?;
            if header.hash().as_bytes().as_slice() != hash { return Err(Error::Corrupt("position source hash".into())); }
            let e=&header.extensions;
            let author=e.author.ok_or_else(|| Error::Corrupt("position source author".into()))?;
            sources.insert((hash.clone(),*kind),vec![
                SqlValue::Blob(hash.clone()),SqlValue::Integer(*kind),SqlValue::Blob(encode(&e.scope)?),SqlValue::Integer(i64::from(author)),SqlValue::Integer(i64::try_from(e.author_sequence).map_err(|_| Error::Corrupt("position source sequence".into()))?),SqlValue::Blob(header.public_key.as_bytes().to_vec()),SqlValue::Blob(e.tip.0.to_vec()),SqlValue::Integer(i64::try_from(header.seq_num).map_err(|_| Error::Corrupt("position source log sequence".into()))?),SqlValue::Integer(i64::from(status=="pending")),SqlValue::Integer(i64::from(matches!(status.as_str(),"applied"|"held"|"abandoned"))),
            ]);
        }
        let actual = rows(
            &self.conn,
            "SELECT * FROM secure_position_sources ORDER BY hash,kind",
        )
        .await?;
        if actual != sources.values().cloned().collect::<Vec<_>>() {
            return Err(Error::Corrupt(
                "position sources differ from headers".into(),
            ));
        }
        let mut domain = BTreeMap::<Vec<IndexValue>, Runs>::new();
        let mut logs = BTreeMap::<Vec<IndexValue>, Runs>::new();
        for source in sources.values() {
            let [
                _,
                SqlValue::Integer(kind),
                scope,
                author,
                SqlValue::Integer(sequence),
                signer,
                tip,
                SqlValue::Integer(log_sequence),
                SqlValue::Integer(pending),
                applied,
            ] = source.as_slice()
            else {
                return Err(Error::Corrupt("position source".into()));
            };
            domain
                .entry(index_key(&[
                    scope.clone(),
                    author.clone(),
                    SqlValue::Integer(*kind),
                    SqlValue::Integer(*pending),
                ])?)
                .or_default()
                .insert(*sequence as u64, *sequence as u64);
            if *kind != 2 {
                logs.entry(index_key(&[
                    scope.clone(),
                    signer.clone(),
                    tip.clone(),
                    applied.clone(),
                    author.clone(),
                    SqlValue::Integer(sequence - log_sequence),
                ])?)
                .or_default()
                .insert(*log_sequence as u64, *log_sequence as u64);
            }
        }
        for (table, width, expected) in [
            ("secure_position_ranges", 4, domain),
            ("secure_log_ranges", 6, logs),
        ] {
            let mut actual = BTreeMap::new();
            for row in rows(&self.conn, &format!("SELECT * FROM {table}")).await? {
                if row.len() != width + 2 {
                    return Err(Error::Corrupt("position range columns".into()));
                }
                let [SqlValue::Integer(start), SqlValue::Integer(end)] = &row[width..] else {
                    return Err(Error::Corrupt("position audit interval".into()));
                };
                let (start, end) = interval(*start, *end)?;
                let runs = actual
                    .entry(index_key(&row[..width])?)
                    .or_insert_with(Runs::default);
                // Retain row boundaries: nonmaximal, overlapping runs are corrupt too.
                runs.0.insert(start, end);
            }
            if actual != expected {
                return Err(Error::Corrupt(format!("{table} differs from headers")));
            }
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum IndexValue {
    Integer(i64),
    Blob(Vec<u8>),
}
fn index_key(values: &[SqlValue]) -> Result<Vec<IndexValue>, Error> {
    values
        .iter()
        .map(|v| match v {
            SqlValue::Integer(n) => Ok(IndexValue::Integer(*n)),
            SqlValue::Blob(b) => Ok(IndexValue::Blob(b.clone())),
            _ => Err(Error::Corrupt("position index key".into())),
        })
        .collect()
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct OracleStats {
    pub(super) scans: AtomicU64,
    pub(super) decodes: AtomicU64,
    nanos: AtomicU64,
}
#[cfg(test)]
impl OracleStats {
    pub(super) fn start(&self) -> OracleTimer<'_> {
        self.scans.fetch_add(1, Ordering::Relaxed);
        OracleTimer {
            stats: self,
            start: std::time::Instant::now(),
        }
    }
}
#[cfg(test)]
pub(super) struct OracleTimer<'a> {
    stats: &'a OracleStats,
    start: std::time::Instant,
}
#[cfg(test)]
impl Drop for OracleTimer<'_> {
    fn drop(&mut self) {
        self.stats
            .nanos
            .fetch_add(self.start.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }
}

#[cfg(test)]
impl<A: RowApplication> Inner<A> {
    pub(crate) async fn audit_positions_for_test(&self) -> Result<(), Error> {
        self.audit_positions().await
    }
    pub(crate) async fn position_scope_id_for_test(
        &self,
        scope: ResourceScope,
    ) -> Result<Option<i64>, Error> {
        self.find_scope_id(scope).await
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn position_tables_have_one_writer_module() {
        fn check(dir: &std::path::Path) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    if path.file_name().unwrap() != "tests" {
                        check(&path);
                    }
                } else if path.extension().is_some_and(|e| e == "rs")
                    && path.file_name().unwrap() != "positions.rs"
                    && path.file_name().unwrap() != "tests.rs"
                {
                    let source = std::fs::read_to_string(&path).unwrap().to_ascii_uppercase();
                    for literal in source.split('"') {
                        for table in [
                            "SECURE_POSITION_RANGES",
                            "SECURE_EXISTENCE_COUNTS",
                            "SECURE_LOG_RANGES",
                            "SECURE_POSITION_SOURCES",
                        ] {
                            if !literal.contains(table) {
                                continue;
                            }
                            for verb in [
                                "INSERT INTO ",
                                "INSERT OR IGNORE INTO ",
                                "INSERT OR REPLACE INTO ",
                                "UPDATE ",
                                "DELETE FROM ",
                            ] {
                                assert!(
                                    !literal.contains(&format!("{verb}{table}")),
                                    "position write outside positions.rs: {}",
                                    path.display()
                                );
                            }
                        }
                    }
                }
            }
        }
        check(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"));
    }
}
