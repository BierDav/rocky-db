//! Writes to replayed tables commit as intent frames.
use super::*;

fn opened(
    t: &Typed,
    frame: &EncryptedFrame,
) -> (Vec<RowWrite>, Option<rocky_core::replay::Intent>) {
    let operation = frame.operation_ref().unwrap();
    let plaintext = crate::wire::decrypt(
        &t.key(frame.scope().unwrap()).key,
        &encode(&operation.header.extensions).unwrap(),
        frame.body_bytes(),
    )
    .unwrap();
    let payload = crate::wire::RowPayload::decode_test(&plaintext, frame, &t.app()).unwrap();
    (payload.writes().to_vec(), payload.intent().cloned())
}

#[tokio::test]
async fn replayed_writes_commit_as_intents() {
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let both = [t.items, t.salaries];
    let node = PrivateKey::new();
    let alice = t
        .open(&dir.path().join("a.db"), &node, t.full(), &both)
        .await;
    let session = sql(&alice, &both).await;
    session.run("BEGIN IMMEDIATE", vec![]).await.unwrap();
    insert(&session, "INSERT INTO salaries VALUES('ann',10)", vec![])
        .await
        .unwrap();
    session
        .run(
            "UPDATE salaries SET amount=amount+? WHERE key=?",
            vec![SqlValue::Integer(5), text("ann")],
        )
        .await
        .unwrap();
    // A savepoint rolled back takes its statements out of the intent.
    session.run("SAVEPOINT undo", vec![]).await.unwrap();
    session
        .run("UPDATE salaries SET amount=0", vec![])
        .await
        .unwrap();
    session.run("ROLLBACK TO undo", vec![]).await.unwrap();
    session.run("RELEASE undo", vec![]).await.unwrap();
    let frames = session
        .commit([1; 32])
        .await
        .unwrap()
        .committed
        .unwrap()
        .frames;
    assert_eq!(frames.len(), 1);

    // The author's execution is its local result.
    assert_eq!(
        select(&session, "SELECT key,amount FROM salaries").await,
        vec![vec![text("ann"), SqlValue::Integer(15)]]
    );
    let mut intents = Vec::new();
    for frame in &frames {
        let (writes, carried) = opened(&t, frame);
        assert_eq!(frame.scope().unwrap(), t.salaries);
        assert!(writes.is_empty());
        intents.push(carried.unwrap());
    }
    let [intent] = intents.as_slice() else {
        panic!("one intent frame");
    };
    assert!(intent.base.is_empty());
    let statements: Vec<_> = intent
        .statements
        .iter()
        .map(|statement| (statement.sql.as_str(), statement.params.clone()))
        .collect();
    assert_eq!(statements.len(), 2);
    assert!(statements[0].0.starts_with("INSERT INTO salaries"));
    assert!(
        statements[1]
            .0
            .starts_with("UPDATE salaries SET amount = amount + ?")
    );
    assert_eq!(statements[1].1, vec![SqlValue::Integer(5), text("ann")]);

    // The next intent reads the first: its base names the author's frame.
    session.run("BEGIN", vec![]).await.unwrap();
    session
        .run(
            "UPDATE salaries SET amount=amount+1 WHERE key='ann'",
            vec![],
        )
        .await
        .unwrap();
    let latest = session
        .commit([2; 32])
        .await
        .unwrap()
        .committed
        .unwrap()
        .frames;
    let [latest] = latest.as_slice() else {
        panic!("one intent frame");
    };
    let header = |frame: &EncryptedFrame| frame.operation_ref().unwrap().header.clone();
    let first = header(
        frames
            .iter()
            .find(|frame| frame.scope().unwrap() == t.salaries)
            .unwrap(),
    );
    let (_, next) = opened(&t, latest);
    assert_eq!(
        next.unwrap().base,
        vec![rocky_core::replay::BaseMark {
            author: first.extensions.author.unwrap(),
            sequence: first.extensions.author_sequence,
        }]
    );
    assert!(header(latest).timestamp > first.timestamp);
}

#[tokio::test]
async fn nondeterministic_replayed_writes_are_refused_before_they_run() {
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let both = [t.items, t.salaries];
    let alice = t
        .open(
            &dir.path().join("a.db"),
            &PrivateKey::new(),
            t.full(),
            &both,
        )
        .await;
    let session = sql(&alice, &both).await;
    insert(&session, "INSERT INTO salaries VALUES('ann',10)", vec![])
        .await
        .unwrap();
    for refused in [
        "UPDATE salaries SET amount=random()",
        "UPDATE salaries SET amount=amount WHERE rowid=1",
        "WITH raise AS (SELECT 1 AS x) UPDATE salaries SET amount=amount+(SELECT x FROM raise)",
    ] {
        assert!(
            matches!(
                sql_error(session.run(refused, vec![]).await),
                SqlError::Unsupported(_)
            ),
            "{refused}"
        );
    }
    assert_eq!(
        select(&session, "SELECT amount FROM salaries").await,
        vec![vec![SqlValue::Integer(10)]]
    );
}

#[tokio::test]
async fn a_single_row_intent_authors_within_its_statement_budget() {
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let both = [t.items, t.salaries];
    let alice = t
        .open(
            &dir.path().join("a.db"),
            &PrivateKey::new(),
            t.full(),
            &both,
        )
        .await;
    let session = sql(&alice, &both).await;
    insert(&session, "INSERT INTO salaries VALUES('ann',10)", vec![])
        .await
        .unwrap();
    let count = |sql: &'static str| {
        let session = &session;
        async move {
            let before = crate::sqlite::statements();
            crate::sqlite::trace_statements(true);
            session.run(sql, vec![]).await.unwrap();
            let trace = crate::sqlite::trace_statements(false);
            if std::env::var_os("ROCKY_TRACE_AUTHOR").is_some() {
                for statement in &trace {
                    println!("SQL {statement}");
                }
            }
            let total = crate::sqlite::statements() - before;
            // The transaction itself; session admission runs around it.
            let begin = trace
                .iter()
                .position(|sql| sql.starts_with("BEGIN"))
                .unwrap();
            let commit = trace.iter().position(|sql| sql == "COMMIT").unwrap();
            (total, commit - begin + 1)
        }
    };
    let replayed = count("UPDATE salaries SET amount=amount+1 WHERE key='ann'").await;
    println!("P4 author_statements total/transaction replayed={replayed:?}");
    assert!(replayed.1 <= 43, "{replayed:?} statements");
}

/// One update of `ann`'s amount, committed alone.
async fn raise(session: &SecureSql<TypedRows>, by: i64) -> EncryptedFrame {
    let [frame] = session
        .run(
            "UPDATE salaries SET amount=amount+? WHERE key='ann'",
            vec![SqlValue::Integer(by)],
        )
        .await
        .unwrap()
        .committed
        .unwrap()
        .frames
        .try_into()
        .unwrap();
    frame
}

async fn amounts(
    replica: &EncryptedReplica<TypedRows>,
    both: &[ResourceScope],
) -> Vec<Vec<SqlValue>> {
    select(
        &sql(replica, both).await,
        "SELECT key,amount FROM salaries ORDER BY key",
    )
    .await
}

/// Each replayed member's partition order and drop reason, in that order.
async fn outcomes(replica: &EncryptedReplica<TypedRows>) -> Vec<Option<String>> {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    collect_rows(
        inner
            .conn
            .query(
                "SELECT dropped FROM secure_replayed ORDER BY clock,author,sequence",
                (),
            )
            .await
            .unwrap(),
    )
    .await
    .unwrap()
    .into_iter()
    .map(|row| match &row[0] {
        SqlValue::Text(reason) => Some(reason.clone()),
        _ => None,
    })
    .collect()
}

#[tokio::test]
async fn concurrent_increments_replay_in_order_and_both_apply() {
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let both = [t.items, t.salaries];
    let open = |name: &'static str| {
        let (t, dir) = (&t, &dir);
        async move {
            t.open(&dir.path().join(name), &PrivateKey::new(), t.full(), &both)
                .await
        }
    };
    let (alice, bob, carol) = (open("a.db").await, open("b.db").await, open("c.db").await);
    let [created] = insert(
        &sql(&alice, &both).await,
        "INSERT INTO salaries VALUES('ann',10)",
        vec![],
    )
    .await
    .unwrap()
    .committed
    .unwrap()
    .frames
    .try_into()
    .unwrap();
    assert_eq!(
        bob.receive(created.clone()).await.unwrap(),
        ReceiveStatus::Applied
    );
    // Both raise the amount they read; neither has seen the other.
    let first = raise(&sql(&alice, &both).await, 1).await;
    let second = raise(&sql(&bob, &both).await, 1).await;
    assert!(replay_stamp(&first) < replay_stamp(&second));
    let ann = |amount| vec![vec![text("ann"), SqlValue::Integer(amount)]];
    for frame in [created, first.clone(), second.clone()] {
        assert_eq!(carol.receive(frame).await.unwrap(), ReceiveStatus::Applied);
    }
    assert_eq!(amounts(&carol, &both).await, ann(12));
    assert_eq!(alice.receive(second).await.unwrap(), ReceiveStatus::Applied);
    assert_eq!(amounts(&alice, &both).await, ann(12));
    // Bob already applied his later raise: it rewinds, the earlier one
    // applies, and his redoes on top.
    assert_eq!(bob.receive(first).await.unwrap(), ReceiveStatus::Applied);
    assert_eq!(amounts(&bob, &both).await, ann(12));
    for replica in [&alice, &bob, &carol] {
        assert_eq!(outcomes(replica).await, vec![None, None, None]);
        assert_eq!(undo_records(replica).await, 3);
    }
}

/// Before-images kept for unsealed applied members.
async fn undo_records(replica: &EncryptedReplica<TypedRows>) -> i64 {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    let rows = collect_rows(
        inner
            .conn
            .query(
                "SELECT COUNT(*) FROM secure_replayed WHERE undo IS NOT NULL",
                (),
            )
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    match rows[0][0] {
        SqlValue::Integer(count) => count,
        _ => unreachable!(),
    }
}

/// Inserts `ann` with `amount`, committed alone.
async fn create(
    replica: &EncryptedReplica<TypedRows>,
    both: &[ResourceScope],
    amount: i64,
) -> EncryptedFrame {
    let frames = insert(
        &sql(replica, both).await,
        &format!("INSERT INTO salaries VALUES('ann',{amount})"),
        vec![],
    )
    .await
    .unwrap()
    .committed
    .unwrap()
    .frames;
    frames.into_iter().next().unwrap()
}

#[tokio::test]
async fn an_earlier_arrival_rewinds_and_redo_reevaluates_later_outcomes() {
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let both = [t.items, t.salaries];
    let open = |name: &'static str| {
        let (t, dir) = (&t, &dir);
        async move {
            t.open(&dir.path().join(name), &PrivateKey::new(), t.full(), &both)
                .await
        }
    };
    let (alice, bob, carol) = (open("a.db").await, open("b.db").await, open("c.db").await);
    // Both create `ann`; Bob then raises his own row.
    let earlier = create(&alice, &both, 10).await;
    let later = create(&bob, &both, 20).await;
    let raised = raise(&sql(&bob, &both).await, 5).await;
    assert!(replay_stamp(&earlier) < replay_stamp(&later));
    assert_eq!(
        amounts(&bob, &both).await,
        vec![vec![text("ann"), SqlValue::Integer(25)]]
    );
    // Alice's earlier create reaches Bob last: his create now fails its
    // key and drops, and his raise replays on Alice's row.
    assert_eq!(
        bob.receive(earlier.clone()).await.unwrap(),
        ReceiveStatus::Applied
    );
    let ann = |amount| vec![vec![text("ann"), SqlValue::Integer(amount)]];
    assert_eq!(amounts(&bob, &both).await, ann(15));
    assert_eq!(
        outcomes(&bob).await,
        vec![None, Some("constraint".into()), None]
    );
    // A dropped member keeps no undo; Carol, in the opposite order, agrees.
    assert_eq!(undo_records(&bob).await, 2);
    for frame in [later, raised, earlier] {
        assert_eq!(carol.receive(frame).await.unwrap(), ReceiveStatus::Applied);
    }
    assert_eq!(amounts(&carol, &both).await, ann(15));
    assert_eq!(outcomes(&carol).await, outcomes(&bob).await);
}

#[tokio::test]
async fn a_seal_ends_rewinds_and_makes_drops_final() {
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let both = [t.items, t.salaries];
    let open = |name: &'static str| {
        let (t, dir) = (&t, &dir);
        async move {
            t.open(&dir.path().join(name), &PrivateKey::new(), t.full(), &both)
                .await
        }
    };
    let (alice, bob, carol) = (open("a.db").await, open("b.db").await, open("c.db").await);
    let earlier = create(&alice, &both, 10).await;
    let later = create(&bob, &both, 20).await;
    let raised = raise(&sql(&alice, &both).await, 1).await;
    for frame in [earlier.clone(), later.clone()] {
        assert_eq!(carol.receive(frame).await.unwrap(), ReceiveStatus::Applied);
    }
    // A seal finalizes everything Carol applied so far.
    carol.seal_replayed_for_test(t.salaries).await.unwrap();
    assert_eq!(undo_records(&carol).await, 0);
    use rocky_core::replay::{DropReason, TransactionOutcome};
    assert_eq!(
        carol
            .transaction_outcome(transaction(&t, &later))
            .await
            .unwrap(),
        Some(TransactionOutcome::Dropped {
            reason: DropReason::Constraint,
            sealed: true,
        })
    );
    // Alice's raise orders before nothing unsealed and applies on top.
    assert_eq!(carol.receive(raised).await.unwrap(), ReceiveStatus::Applied);
    assert_eq!(
        amounts(&carol, &both).await,
        vec![vec![text("ann"), SqlValue::Integer(11)]]
    );
    assert_eq!(undo_records(&carol).await, 1);
}

fn transaction(t: &Typed, frame: &EncryptedFrame) -> rocky_core::Commitment {
    crate::wire::RowPayload::decode_test(
        &crate::wire::decrypt(
            &t.key(frame.scope().unwrap()).key,
            &encode(&frame.operation_ref().unwrap().header.extensions).unwrap(),
            frame.body_bytes(),
        )
        .unwrap(),
        frame,
        &t.app(),
    )
    .unwrap()
    .membership()
    .unwrap()
    .transaction
}

fn replay_stamp(frame: &EncryptedFrame) -> (u64, u32, u64) {
    let header = &frame.operation_ref().unwrap().header;
    (
        header.timestamp,
        header.extensions.author.unwrap(),
        header.extensions.author_sequence,
    )
}

#[tokio::test]
async fn a_failing_replay_drops_its_transaction_and_the_log_continues() {
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let both = [t.items, t.salaries];
    let alice = t
        .open(
            &dir.path().join("a.db"),
            &PrivateKey::new(),
            t.full(),
            &both,
        )
        .await;
    let bob = t
        .open(
            &dir.path().join("b.db"),
            &PrivateKey::new(),
            t.full(),
            &both,
        )
        .await;
    let carol = t
        .open(
            &dir.path().join("c.db"),
            &PrivateKey::new(),
            t.full(),
            &both,
        )
        .await;
    // Both create the same key; the later one fails its primary key.
    let earlier = create(&alice, &both, 10).await;
    let later = create(&bob, &both, 20).await;
    let after = raise(&sql(&bob, &both).await, 5).await;
    for frame in [earlier.clone(), later.clone(), after] {
        assert_eq!(carol.receive(frame).await.unwrap(), ReceiveStatus::Applied);
    }
    // Bob's raise replays on Alice's row: a drop is not a tombstone.
    assert_eq!(
        amounts(&carol, &both).await,
        vec![vec![text("ann"), SqlValue::Integer(15)]]
    );
    assert_eq!(
        outcomes(&carol).await,
        vec![None, Some("constraint".into()), None]
    );
    let transaction = |frame| transaction(&t, frame);
    use rocky_core::replay::{DropReason, TransactionOutcome};
    assert_eq!(
        carol
            .transaction_outcome(transaction(&earlier))
            .await
            .unwrap(),
        Some(TransactionOutcome::Applied)
    );
    assert_eq!(
        carol
            .transaction_outcome(transaction(&later))
            .await
            .unwrap(),
        Some(TransactionOutcome::Dropped {
            reason: DropReason::Constraint,
            sealed: false,
        })
    );
    // Bob's own replay of his transaction applied; Carol's ordering dropped it.
    assert_eq!(
        bob.transaction_outcome(transaction(&later)).await.unwrap(),
        Some(TransactionOutcome::Applied)
    );
}

#[tokio::test]
async fn replayed_effects_outside_the_authors_grants_drop_as_admission() {
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let both = [t.items, t.salaries];
    let alice = t
        .open(
            &dir.path().join("a.db"),
            &PrivateKey::new(),
            t.full(),
            &both,
        )
        .await;
    // Bob may insert salaries but not change them.
    let inserter = grant(
        t.salaries,
        &[Right::Read, Right::Insert, Right::Custody],
        &t.every_field("salaries"),
    );
    let bob = t
        .open(
            &dir.path().join("b.db"),
            &PrivateKey::new(),
            vec![t.writer(t.items, "items"), inserter],
            &both,
        )
        .await;
    let [created] = insert(
        &sql(&alice, &both).await,
        "INSERT INTO salaries VALUES('ann',10)",
        vec![],
    )
    .await
    .unwrap()
    .committed
    .unwrap()
    .frames
    .try_into()
    .unwrap();
    assert_eq!(bob.receive(created).await.unwrap(), ReceiveStatus::Applied);
    let raise = "UPDATE salaries SET amount=amount+1 WHERE key='ann'";
    // The author's own commit admits its effects as every replica will.
    assert!(matches!(
        sql(&bob, &both).await.run(raise, vec![]).await,
        Err(Error::Rejected(_))
    ));
    // An author that skips that check still cannot change other replicas.
    bob.inner
        .lock(crate::replica::Class::Background)
        .await
        .unchecked_replayed_admission = true;
    let rows = sql(&bob, &both).await.run(raise, vec![]).await.unwrap();
    let [frame] = rows.committed.unwrap().frames.try_into().unwrap();
    assert_eq!(alice.receive(frame).await.unwrap(), ReceiveStatus::Applied);
    assert_eq!(
        amounts(&alice, &both).await,
        vec![vec![text("ann"), SqlValue::Integer(10)]]
    );
    assert_eq!(outcomes(&alice).await, vec![None, Some("admission".into())]);
}

#[tokio::test]
async fn a_single_row_intent_receives_within_its_statement_budget() {
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let both = [t.items, t.salaries];
    let alice = t
        .open(
            &dir.path().join("a.db"),
            &PrivateKey::new(),
            t.full(),
            &both,
        )
        .await;
    let bob = t
        .open(
            &dir.path().join("b.db"),
            &PrivateKey::new(),
            t.full(),
            &both,
        )
        .await;
    let session = sql(&alice, &both).await;
    let [created] = insert(&session, "INSERT INTO salaries VALUES('ann',10)", vec![])
        .await
        .unwrap()
        .committed
        .unwrap()
        .frames
        .try_into()
        .unwrap();
    bob.receive(created).await.unwrap();
    // The whole call, and the received frame's own application in it.
    let count = |frame: EncryptedFrame| {
        let bob = &bob;
        async move {
            let before = crate::sqlite::statements();
            crate::sqlite::trace_statements(true);
            assert_eq!(bob.receive(frame).await.unwrap(), ReceiveStatus::Applied);
            let trace = crate::sqlite::trace_statements(false);
            if std::env::var_os("ROCKY_TRACE_RECEIVE").is_some() {
                for statement in &trace {
                    println!("SQL {statement}");
                }
            }
            let at = |sql: &str| trace.iter().position(|traced| traced == sql).unwrap();
            (
                crate::sqlite::statements() - before,
                at("RELEASE received_application") - at("SAVEPOINT received_application") + 1,
            )
        }
    };
    let replayed = count(raise(&session, 1).await).await;
    println!("P4 receive_statements total/application replayed={replayed:?}");
    assert!(replayed.1 <= 45, "{replayed:?} statements");
}

/// Receiving a transaction that changed 32 rows costs at most 6.5
/// statements per row (the features_11 result was 6.40625), whether the
/// author wrote each row in its own statement or all in one.
#[tokio::test]
async fn a_thirty_two_row_intent_receives_within_its_statements_per_row() {
    const ROWS: usize = 32;
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let both = [t.items, t.salaries];
    let alice = t
        .open(
            &dir.path().join("a.db"),
            &PrivateKey::new(),
            t.full(),
            &both,
        )
        .await;
    let bob = t
        .open(
            &dir.path().join("b.db"),
            &PrivateKey::new(),
            t.full(),
            &both,
        )
        .await;
    let session = sql(&alice, &both).await;
    session.run("BEGIN", vec![]).await.unwrap();
    for row in 0..ROWS {
        insert(
            &session,
            "INSERT INTO salaries VALUES(?,0)",
            vec![text(&format!("k{row:02}"))],
        )
        .await
        .unwrap();
    }
    let [created] = session
        .commit([1; 32])
        .await
        .unwrap()
        .committed
        .unwrap()
        .frames
        .try_into()
        .unwrap();
    assert_eq!(bob.receive(created).await.unwrap(), ReceiveStatus::Applied);
    let commit = |statements: Vec<(String, Vec<SqlValue>)>, handle: u8| {
        let session = &session;
        async move {
            session.run("BEGIN", vec![]).await.unwrap();
            for (statement, params) in statements {
                session.run(&statement, params).await.unwrap();
            }
            let [frame] = session
                .commit([handle; 32])
                .await
                .unwrap()
                .committed
                .unwrap()
                .frames
                .try_into()
                .unwrap();
            frame
        }
    };
    let each = commit(
        (0..ROWS)
            .map(|row| {
                (
                    "UPDATE salaries SET amount=amount+1 WHERE key=?".to_owned(),
                    vec![text(&format!("k{row:02}"))],
                )
            })
            .collect(),
        2,
    )
    .await;
    let all = commit(
        vec![("UPDATE salaries SET amount=amount*2".to_owned(), vec![])],
        3,
    )
    .await;
    let mut per_row = Vec::new();
    for frame in [each, all] {
        // The counter sees Rocky's statements; the replayed application
        // statements run once each beside them.
        let replayed = opened(&t, &frame).1.unwrap().statements.len() as u64;
        let before = crate::sqlite::statements();
        assert_eq!(bob.receive(frame).await.unwrap(), ReceiveStatus::Applied);
        per_row.push((crate::sqlite::statements() - before + replayed) as f64 / ROWS as f64);
    }
    assert_eq!(
        select(&sql(&bob, &both).await, "SELECT sum(amount) FROM salaries").await,
        vec![vec![SqlValue::Integer(2 * ROWS as i64)]]
    );
    println!(
        "P4 receive_statements_per_row each={} all={}",
        per_row[0], per_row[1]
    );
    assert!(per_row.iter().all(|count| *count <= 6.5), "{per_row:?}");
}

#[tokio::test]
async fn a_rewind_across_the_open_tip_redoes_every_transaction() {
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let both = [t.items, t.salaries];
    let open = |name: &'static str| {
        let (t, dir) = (&t, &dir);
        async move {
            t.open(&dir.path().join(name), &PrivateKey::new(), t.full(), &both)
                .await
        }
    };
    let (alice, bob, carol) = (open("a.db").await, open("b.db").await, open("c.db").await);
    let created = create(&alice, &both, 0).await;
    assert_eq!(
        bob.receive(created.clone()).await.unwrap(),
        ReceiveStatus::Applied
    );
    let earliest = raise(&sql(&alice, &both).await, 1000).await;
    const LATER: i64 = 32;
    let session = sql(&bob, &both).await;
    let mut later = Vec::new();
    for _ in 0..LATER {
        later.push(raise(&session, 1).await);
    }
    for frame in std::iter::once(created).chain(later) {
        assert_eq!(carol.receive(frame).await.unwrap(), ReceiveStatus::Applied);
    }
    let started = std::time::Instant::now();
    assert_eq!(
        carol.receive(earliest).await.unwrap(),
        ReceiveStatus::Applied
    );
    let took = started.elapsed();
    // Diagnostic only: the routine seal constant is chosen from this.
    println!(
        "P4 rewind transactions={LATER} total={took:?} per_transaction={:?}",
        took / LATER as u32
    );
    assert_eq!(
        amounts(&carol, &both).await,
        vec![vec![text("ann"), SqlValue::Integer(1000 + LATER)]]
    );
    assert_eq!(
        carol.unsealed_replayed_transactions().await.unwrap(),
        LATER as u64 + 2
    );
}

#[tokio::test]
async fn replayed_inserts_take_their_authors_own_identities() {
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let both = [t.items, t.salaries];
    let (a, b) = (PrivateKey::new(), PrivateKey::new());
    let alice = t.open(&dir.path().join("a.db"), &a, t.full(), &both).await;
    let bob = t.open(&dir.path().join("b.db"), &b, t.full(), &both).await;
    // Replayed tables keep no row records; the allocator still advances.
    let session = sql(&bob, &both).await;
    let mut frames = Vec::new();
    for key in ["ann", "ben"] {
        frames.extend(
            insert(
                &session,
                &format!("INSERT INTO salaries VALUES('{key}',1)"),
                vec![],
            )
            .await
            .unwrap()
            .committed
            .unwrap()
            .frames,
        );
    }
    for frame in frames {
        assert_eq!(alice.receive(frame).await.unwrap(), ReceiveStatus::Applied);
    }
    // An id of another author's number is refused at commit, and a
    // replica drops it when the author skips that check.
    let alices = rocky_core::RowIdentity::next(crate::tests::node_number(a.public_key()), 100)
        .unwrap()
        .integer();
    let forged = format!("INSERT INTO salaries(key,amount,id) VALUES('cy',1,{alices})");
    assert!(matches!(
        session.run(&forged, vec![]).await,
        Err(Error::Rejected(_))
    ));
    bob.inner
        .lock(crate::replica::Class::Background)
        .await
        .unchecked_replayed_admission = true;
    let [frame] = session
        .run(&forged, vec![])
        .await
        .unwrap()
        .committed
        .unwrap()
        .frames
        .try_into()
        .unwrap();
    assert_eq!(
        alice.receive(frame.clone()).await.unwrap(),
        ReceiveStatus::Applied
    );
    use rocky_core::replay::{DropReason, TransactionOutcome};
    assert_eq!(
        alice
            .transaction_outcome(transaction(&t, &frame))
            .await
            .unwrap(),
        Some(TransactionOutcome::Dropped {
            reason: DropReason::Admission,
            sealed: false,
        })
    );
    assert_eq!(amounts(&alice, &both).await.len(), 2);
}

#[tokio::test]
async fn an_update_to_equal_values_needs_no_right() {
    let t = Typed::new();
    let dir = TempDir::new().unwrap();
    let both = [t.items, t.salaries];
    let alice = t
        .open(
            &dir.path().join("a.db"),
            &PrivateKey::new(),
            t.full(),
            &both,
        )
        .await;
    let bob = t
        .open(
            &dir.path().join("b.db"),
            &PrivateKey::new(),
            t.full(),
            &both,
        )
        .await;
    let created = create(&alice, &both, 10).await;
    let same = raise(&sql(&alice, &both).await, 0).await;
    for frame in [created, same.clone()] {
        assert_eq!(bob.receive(frame).await.unwrap(), ReceiveStatus::Applied);
    }
    assert_eq!(
        bob.transaction_outcome(transaction(&t, &same))
            .await
            .unwrap(),
        Some(rocky_core::replay::TransactionOutcome::Applied)
    );
    assert_eq!(undo_records(&bob).await, 1);
}
