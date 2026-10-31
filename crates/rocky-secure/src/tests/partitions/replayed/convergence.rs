//! Replicas of replayed partitions converge whatever the delivery schedule:
//! every order and packet split of a history, with retransmissions and
//! restarts, ends in the rows and drops of a from-scratch replay of the
//! canonical order in plain SQLite.
use super::*;
use rand::{Rng, SeedableRng, rngs::StdRng};
use rocky_core::Commitment;
use std::collections::{BTreeMap, BTreeSet};

mod crashes;
mod successor;

const KEYS: [(&str, [u8; 32]); 2] = [("A", [1; 32]), ("B", [2; 32])];

fn key_of(f: &Fixture, frame: &EncryptedFrame) -> [u8; 32] {
    let scope = frame.scope().unwrap();
    KEYS.iter()
        .find(|(name, _)| f.scope(name) == scope)
        .unwrap()
        .1
}

/// A device that authors in both partitions.
struct Author {
    replica: EncryptedReplica<TypedRows>,
    node: PrivateKey,
    seen: BTreeSet<p2panda_core::Hash>,
}

impl Author {
    async fn open(f: &Fixture, root: &Path, number: u32) -> Self {
        Self::at(f, root, number, PrivateKey::new()).await
    }

    /// Opens author `number`'s database at `root` with node key `node`.
    async fn at(f: &Fixture, root: &Path, number: u32, node: PrivateKey) -> Self {
        let replica = f
            .open(
                &root.join(format!("author{number}.sqlite")),
                node.clone(),
                f.grant(None, &all()),
                Some((node.clone(), number)),
            )
            .await;
        for (name, key) in KEYS {
            f.key(&replica, name, key).await;
        }
        Self {
            replica,
            node,
            seen: BTreeSet::new(),
        }
    }

    /// Frames this device authored since the last call: intents and the
    /// outcome records its commits and rewinds published.
    async fn fresh(&mut self) -> Vec<EncryptedFrame> {
        let inner = self
            .replica
            .inner
            .lock(crate::replica::Class::Background)
            .await;
        let rows = crate::storage::rows(
            &inner.conn,
            &format!(
                "SELECT header,body FROM secure_operations WHERE author=x'{}' ORDER BY sequence",
                self.node
                    .public_key()
                    .as_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ),
        )
        .await
        .unwrap();
        let mut frames = Vec::new();
        for row in rows {
            let [SqlValue::Blob(header), SqlValue::Blob(body)] = row.as_slice() else {
                panic!("stored operation");
            };
            let frame = inner
                .stored_frame(header.clone(), body.clone())
                .await
                .unwrap();
            if self.seen.insert(frame.operation_ref().unwrap().hash) {
                frames.push(frame);
            }
        }
        frames
    }

    async fn run(&self, f: &Fixture, statements: &[(&str, Vec<SqlValue>)], handle: u8) {
        let sql = sql_on(f, &self.replica, &["A", "B"]).await;
        sql.run("BEGIN", vec![]).await.unwrap();
        for (statement, params) in statements {
            sql.run(statement, params.clone()).await.unwrap();
        }
        sql.commit([handle; 32]).await.unwrap();
    }

    async fn create(&self, f: &Fixture, rows: &[(&str, &str, i64)], handle: u8) {
        insert(f, &self.replica, &["A", "B"], rows, handle).await;
    }

    async fn receive(&self, frames: &[EncryptedFrame]) {
        for status in self.replica.receive_all(frames.to_vec()).await {
            assert_ne!(status.unwrap(), ReceiveStatus::Rejected);
        }
    }
}

fn text(value: &str) -> SqlValue {
    SqlValue::Text(value.into())
}

/// One replayed member as the reference sees it.
struct Member {
    scope: ResourceScope,
    stamp: (u64, u32, u64),
    transaction: Commitment,
    members: usize,
    statements: Vec<rocky_core::replay::IntentStatement>,
}

/// The rows and drop map of a from-scratch replay in canonical order.
#[derive(Debug, PartialEq)]
struct Canonical {
    rows: Vec<Vec<SqlValue>>,
    outcomes: BTreeMap<Commitment, TransactionOutcome>,
}

fn sql_value(value: &SqlValue) -> rusqlite::types::Value {
    use rusqlite::types::Value;
    match value {
        SqlValue::Null => Value::Null,
        SqlValue::Integer(value) => Value::Integer(*value),
        SqlValue::Text(value) => Value::Text(value.clone()),
        SqlValue::Blob(value) => Value::Blob(value.clone()),
        SqlValue::Real(_) => panic!("fixtures bind no reals"),
    }
}

/// Replays every intent member in `frames` in plain SQLite: transactions in
/// stamp order, each in its own savepoint; one whose statements fail drops
/// in every partition. Partition orders must agree on that order.
fn canonical(f: &Fixture, frames: &[EncryptedFrame]) -> Canonical {
    canonical_sealed(f, &[frames], 0)
}

/// [`canonical`] across seals: each era's transactions replay after every
/// earlier era's, and drops in the first `sealed` eras are final.
fn canonical_sealed(f: &Fixture, eras: &[&[EncryptedFrame]], sealed: usize) -> Canonical {
    let mut members = Vec::new();
    for (era, frames) in eras.iter().enumerate() {
        for frame in *frames {
            let payload = payload(frame, key_of(f, frame), f);
            let Some(intent) = payload.intent() else {
                continue;
            };
            let membership = payload.membership().unwrap();
            let header = &frame.operation_ref().unwrap().header;
            members.push((
                era,
                Member {
                    scope: frame.scope().unwrap(),
                    stamp: (
                        header.timestamp,
                        header.extensions.author.unwrap(),
                        header.extensions.author_sequence,
                    ),
                    transaction: membership.transaction,
                    members: membership.members.len(),
                    statements: intent.statements.clone(),
                },
            ));
        }
    }
    members.sort_by_key(|(era, member)| (*era, member.stamp));
    let era_of: BTreeMap<Commitment, usize> = members
        .iter()
        .map(|(era, member)| (member.transaction, *era))
        .collect();
    let members: Vec<Member> = members.into_iter().map(|(_, member)| member).collect();
    let mut order: Vec<Commitment> = Vec::new();
    for member in &members {
        if !order.contains(&member.transaction) {
            order.push(member.transaction);
        }
    }
    for scope in members
        .iter()
        .map(|member| member.scope)
        .collect::<BTreeSet<_>>()
    {
        let positions: Vec<_> = members
            .iter()
            .filter(|member| member.scope == scope)
            .map(|member| order.iter().position(|t| *t == member.transaction))
            .collect();
        assert!(positions.is_sorted(), "partition orders disagree");
    }
    let db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE items(list TEXT NOT NULL,key TEXT NOT NULL,amount INTEGER NOT NULL,id INTEGER NOT NULL,PRIMARY KEY(list,key));
         CREATE UNIQUE INDEX items_identity ON items(list,id);",
    )
    .unwrap();
    let mut outcomes = BTreeMap::new();
    for transaction in order {
        let held: Vec<_> = members
            .iter()
            .filter(|member| member.transaction == transaction)
            .collect();
        assert_eq!(held.len(), held[0].members, "every member is delivered");
        db.execute_batch("SAVEPOINT t").unwrap();
        let failed = held
            .iter()
            .flat_map(|member| &member.statements)
            .any(|statement| {
                let params: Vec<_> = statement.params.iter().map(sql_value).collect();
                db.execute(&statement.sql, rusqlite::params_from_iter(params))
                    .is_err()
            });
        if failed {
            db.execute_batch("ROLLBACK TO t").unwrap();
        }
        db.execute_batch("RELEASE t").unwrap();
        outcomes.insert(
            transaction,
            if failed {
                TransactionOutcome::Dropped {
                    reason: DropReason::Constraint,
                    sealed: era_of[&transaction] < sealed,
                }
            } else {
                TransactionOutcome::Applied
            },
        );
    }
    let mut statement = db
        .prepare("SELECT list,key,amount FROM items ORDER BY list,key")
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok(vec![
                text(&row.get::<_, String>(0)?),
                text(&row.get::<_, String>(1)?),
                SqlValue::Integer(row.get(2)?),
            ])
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    Canonical { rows, outcomes }
}

/// What `replica` holds, in the reference's terms.
async fn state(
    f: &Fixture,
    replica: &EncryptedReplica<TypedRows>,
    expected: &Canonical,
) -> Canonical {
    let mut outcomes = BTreeMap::new();
    for transaction in expected.outcomes.keys() {
        outcomes.insert(
            *transaction,
            replica
                .transaction_outcome(*transaction)
                .await
                .unwrap()
                .expect("every transaction replayed"),
        );
    }
    Canonical {
        rows: keys(f, replica, &["A", "B"]).await,
        outcomes,
    }
}

/// A fault injected into one delivery schedule.
#[derive(Clone, Copy, Debug)]
enum Fault {
    /// Close and reopen the receiver after this packet.
    Restart(usize),
    /// Deliver everything sent so far again after this packet.
    Retransmit(usize),
}

/// Opens a receiver holding both partitions that writes nothing itself.
async fn receiver(f: &Fixture, path: &Path, node: &PrivateKey) -> EncryptedReplica<TypedRows> {
    let replica = f
        .open(path, node.clone(), f.grant(None, &[Right::Read]), None)
        .await;
    // Keys come from the device's key store on every open.
    for (name, key) in KEYS {
        f.key(&replica, name, key).await;
    }
    replica
}

/// Receives one packet. Restarts here close cleanly, so packets skip the
/// flush; crashes are the crash tests' concern.
async fn receive(replica: &EncryptedReplica<TypedRows>, packet: &[EncryptedFrame], fault: Fault) {
    for status in replica.receive_buffered(packet.to_vec()).await {
        assert_ne!(status.unwrap().value, ReceiveStatus::Rejected, "{fault:?}");
    }
}

/// Delivers `packets` to a new receiver at `path` and checks it against
/// the reference.
async fn deliver(
    f: &Fixture,
    path: &Path,
    packets: &[Vec<EncryptedFrame>],
    fault: Fault,
    expected: &Canonical,
) {
    let node = PrivateKey::new();
    let mut replica = receiver(f, path, &node).await;
    let mut sent = Vec::new();
    for (index, packet) in packets.iter().enumerate() {
        receive(&replica, packet, fault).await;
        sent.extend(packet.iter().cloned());
        match fault {
            Fault::Restart(after) if after == index => {
                drop(replica);
                replica = receiver(f, path, &node).await;
            }
            Fault::Retransmit(after) if after == index => {
                receive(&replica, &sent, fault).await;
            }
            _ => {}
        }
    }
    assert_eq!(&state(f, &replica, expected).await, expected, "{fault:?}");
}

fn permutations(n: usize) -> Vec<Vec<usize>> {
    if n == 0 {
        return vec![Vec::new()];
    }
    let mut all = Vec::new();
    for rest in permutations(n - 1) {
        for at in 0..=rest.len() {
            let mut order = rest.clone();
            order.insert(at, n - 1);
            all.push(order);
        }
    }
    all
}

/// Every order of `units` and every split of it into consecutive packets,
/// each with one restart or retransmission.
fn schedules(units: &[Vec<EncryptedFrame>]) -> Vec<(Vec<Vec<EncryptedFrame>>, Fault)> {
    let mut all = Vec::new();
    for order in permutations(units.len()) {
        for cuts in 0..1usize << (units.len() - 1) {
            let mut packets = vec![Vec::new()];
            for (position, unit) in order.iter().enumerate() {
                if position > 0 && cuts & (1 << (position - 1)) != 0 {
                    packets.push(Vec::new());
                }
                packets
                    .last_mut()
                    .unwrap()
                    .extend(units[*unit].iter().cloned());
            }
            let index = all.len();
            let at = index / 2 % packets.len();
            let fault = if index % 2 == 0 {
                Fault::Restart(at)
            } else {
                Fault::Retransmit(at)
            };
            all.push((packets, fault));
        }
    }
    all
}

/// Runs every schedule on fresh receivers, spread over threads.
fn deliver_all(f: &Fixture, schedules: &[(Vec<Vec<EncryptedFrame>>, Fault)], expected: &Canonical) {
    let root = tempfile::tempdir().unwrap();
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get().min(8));
    std::thread::scope(|scope| {
        for thread in 0..threads {
            let root = root.path();
            scope.spawn(move || {
                runtime().block_on(async {
                    for (index, (packets, fault)) in
                        schedules.iter().enumerate().skip(thread).step_by(threads)
                    {
                        let path = root.join(format!("r{index}.sqlite"));
                        deliver(f, &path, packets, *fault, expected).await;
                        std::fs::remove_file(&path).ok();
                    }
                })
            });
        }
    });
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn amount(value: i64) -> Vec<SqlValue> {
    vec![SqlValue::Integer(value)]
}

/// Two authors over partitions A and B, neither seeing the other until the
/// fifth unit: W1 creates `x` in A; W2 concurrently creates `x` in A and `y`
/// in B in one transaction, which drops in both; W2 raises `x` in every
/// held partition; W1 doubles it. With `fifth`, W1 then receives W2's
/// transactions, rewinds, publishes their records and creates `y`.
async fn history(f: &Fixture, root: &Path, fifth: bool) -> Vec<Vec<EncryptedFrame>> {
    let mut w1 = Author::open(f, root, 1).await;
    let mut w2 = Author::open(f, root, 2).await;
    let mut units = Vec::new();
    w1.create(f, &[("A", "x", 10)], 1).await;
    units.push(w1.fresh().await);
    w2.create(f, &[("A", "x", 20), ("B", "y", 1)], 2).await;
    units.push(w2.fresh().await);
    w2.run(
        f,
        &[(
            "UPDATE items SET amount=amount+? WHERE key=?",
            vec![SqlValue::Integer(1), text("x")],
        )],
        3,
    )
    .await;
    units.push(w2.fresh().await);
    w1.run(
        f,
        &[(
            "UPDATE items SET amount=amount*2 WHERE list='A' AND key='x'",
            vec![],
        )],
        4,
    )
    .await;
    units.push(w1.fresh().await);
    if fifth {
        w1.receive(
            &units[1]
                .iter()
                .chain(&units[2])
                .cloned()
                .collect::<Vec<_>>(),
        )
        .await;
        w1.create(f, &[("B", "y", 7)], 5).await;
        units.push(w1.fresh().await);
    }
    units
}

fn exhaustive(transactions: usize) {
    let f = Fixture::build_class(false, PrivateKey::new(), "replayed");
    let root = tempfile::tempdir().unwrap();
    let units = runtime().block_on(history(&f, root.path(), transactions == 5));
    let frames: Vec<_> = units.iter().flatten().cloned().collect();
    let expected = canonical(&f, &frames);
    let mut rows = vec![vec![text("A"), text("x")]];
    rows[0].extend(amount(22));
    if transactions == 5 {
        rows.push(vec![text("B"), text("y"), SqlValue::Integer(7)]);
    }
    assert_eq!(expected.rows, rows);
    let dropped: Vec<_> = expected
        .outcomes
        .values()
        .filter(|outcome| **outcome != TransactionOutcome::Applied)
        .collect();
    assert_eq!(dropped.len(), 1);
    let schedules = schedules(&units);
    assert_eq!(
        schedules.len(),
        (1..=units.len()).product::<usize>() << (units.len() - 1)
    );
    deliver_all(&f, &schedules, &expected);
}

#[test]
fn every_schedule_of_four_transactions_converges_to_the_canonical_replay() {
    exhaustive(4);
}

#[test]
fn every_schedule_of_five_transactions_converges_to_the_canonical_replay() {
    exhaustive(5);
}

/// A random transaction over keys `k0`..`k3` in A and B, from what the
/// author holds: creates (some across both partitions, some colliding with
/// keys other authors may create), increments, assignments and deletes.
async fn random_transaction(f: &Fixture, author: &Author, rng: &mut StdRng, handle: u8) {
    let held = keys(f, &author.replica, &["A", "B"]).await;
    let has = |list: &str, key: &str| {
        held.iter()
            .any(|row| row[0] == text(list) && row[1] == text(key))
    };
    let list = ["A", "B"][rng.gen_range(0..2)];
    let key = format!("k{}", rng.gen_range(0..4));
    match rng.gen_range(0..6) {
        0 | 1 if !has(list, &key) => {
            let other = if list == "A" { "B" } else { "A" };
            let mut rows = vec![(list, key.as_str(), rng.gen_range(1..10))];
            if rng.gen_bool(0.4) && !has(other, &key) {
                rows.push((other, key.as_str(), rng.gen_range(1..10)));
            }
            author.create(f, &rows, handle).await;
        }
        2 => {
            author
                .run(
                    f,
                    &[(
                        "UPDATE items SET amount=amount+? WHERE key=?",
                        vec![SqlValue::Integer(rng.gen_range(1..5)), text(&key)],
                    )],
                    handle,
                )
                .await;
        }
        3 => {
            author
                .run(
                    f,
                    &[(
                        "UPDATE items SET amount=? WHERE list=? AND key=?",
                        vec![
                            SqlValue::Integer(rng.gen_range(0..100)),
                            text(list),
                            text(&key),
                        ],
                    )],
                    handle,
                )
                .await;
        }
        4 => {
            author
                .run(
                    f,
                    &[(
                        "DELETE FROM items WHERE list=? AND key=?",
                        vec![text(list), text(&key)],
                    )],
                    handle,
                )
                .await;
        }
        _ => {
            author
                .run(
                    f,
                    &[(
                        "UPDATE items SET amount=amount*2 WHERE list=? AND key=?",
                        vec![text(list), text(&key)],
                    )],
                    handle,
                )
                .await;
        }
    }
}

/// Frames one author published in one step: a commit's members and
/// records, or the records a rewind published.
struct Group {
    author: usize,
    frames: Vec<EncryptedFrame>,
}

/// Appends group `index` after the unreceived groups it depends on.
fn closure(
    index: usize,
    groups: &[Group],
    group_of: &BTreeMap<p2panda_core::Hash, usize>,
    received: &mut BTreeSet<usize>,
    out: &mut Vec<EncryptedFrame>,
) {
    if !received.insert(index) {
        return;
    }
    for frame in &groups[index].frames {
        let header = &frame.operation_ref().unwrap().header;
        for dependency in header.backlink.iter().chain(&header.previous) {
            if let Some(group) = group_of.get(dependency) {
                closure(*group, groups, group_of, received, out);
            }
        }
    }
    out.extend(groups[index].frames.iter().cloned());
}

/// Four authors commit 32 transactions, each first receiving a random part
/// of what the others published. A receiver gets every frame in a random
/// order and packet split, with retransmissions and a restart; then every
/// author receives what it lacks. All agree with the reference.
async fn seeded(seed: u64) {
    let f = Fixture::build_class(false, PrivateKey::new(), "replayed");
    let root = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut authors = Vec::new();
    for number in 1..=4 {
        authors.push(Author::open(&f, root.path(), number).await);
    }
    let mut groups: Vec<Group> = Vec::new();
    let mut group_of = BTreeMap::new();
    // Per author, the groups it holds: its own and those it received.
    let mut received: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); authors.len()];
    for transaction in 0..32u8 {
        let at = rng.gen_range(0..authors.len());
        let from: Vec<bool> = (0..authors.len()).map(|_| rng.gen_bool(0.5)).collect();
        // A partition with a causal gap or a partial bundle refuses reads
        // and writes, so an author receives whole groups with everything
        // they follow.
        let mut incoming = Vec::new();
        for index in 0..groups.len() {
            if groups[index].author != at && from[groups[index].author] && rng.gen_bool(0.7) {
                closure(index, &groups, &group_of, &mut received[at], &mut incoming);
            }
        }
        authors[at].receive(&incoming).await;
        random_transaction(&f, &authors[at], &mut rng, transaction + 1).await;
        for (index, author) in authors.iter_mut().enumerate() {
            let frames = author.fresh().await;
            if frames.is_empty() {
                continue;
            }
            for frame in &frames {
                group_of.insert(frame.operation_ref().unwrap().hash, groups.len());
            }
            received[index].insert(groups.len());
            groups.push(Group {
                author: index,
                frames,
            });
        }
    }
    let frames: Vec<_> = groups
        .iter()
        .flat_map(|group| group.frames.clone())
        .collect();
    let expected = canonical(&f, &frames);

    let mut shuffled = frames.clone();
    for index in (1..shuffled.len()).rev() {
        shuffled.swap(index, rng.gen_range(0..=index));
    }
    let mut packets = Vec::new();
    while !shuffled.is_empty() {
        let size = rng.gen_range(1..=8).min(shuffled.len());
        packets.push(shuffled.drain(..size).collect::<Vec<_>>());
    }
    for fault in [
        Fault::Restart(rng.gen_range(0..packets.len())),
        Fault::Retransmit(rng.gen_range(0..packets.len())),
    ] {
        let path = root.path().join(format!("receiver-{fault:?}.sqlite"));
        deliver(&f, &path, &packets, fault, &expected).await;
    }
    for (index, author) in authors.iter().enumerate() {
        let mut missing = Vec::new();
        for group in 0..groups.len() {
            closure(
                group,
                &groups,
                &group_of,
                &mut received[index],
                &mut missing,
            );
        }
        author.receive(&missing).await;
        assert_eq!(&state(&f, &author.replica, &expected).await, &expected);
    }
}

#[tokio::test]
async fn seeded_schedules_of_thirty_two_transactions_over_four_authors_converge() {
    for seed in 0..2 {
        seeded(seed).await;
    }
}

#[tokio::test]
async fn seeded_schedule_sweep_converges() {
    for seed in 2..16 {
        seeded(seed).await;
    }
}
