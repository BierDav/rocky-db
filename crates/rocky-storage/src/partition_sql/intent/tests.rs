use super::*;
use crate::partition_sql::PartitionColumn;
use rocky_core::{Affinity, Collation, KeyColumn};
use rusqlite::{Connection, types::Value as Sql};

fn text(value: &str) -> SqlValue {
    SqlValue::Text(value.into())
}
fn int(value: i64) -> SqlValue {
    SqlValue::Integer(value)
}
/// `items` partitioned by a NOCASE `list`.
fn items(held: &[&str], waiting: &[&str]) -> BTreeMap<String, TablePartitions> {
    let tuples = |lists: &[&str]| lists.iter().map(|list| vec![text(list)]).collect();
    [(
        "items".into(),
        TablePartitions {
            columns: vec![PartitionColumn {
                name: "list".into(),
                key: KeyColumn {
                    affinity: Affinity::Text,
                    collation: Collation::Nocase,
                },
            }],
            complete: false,
            held: tuples(held),
            waiting: tuples(waiting),
        },
    )]
    .into()
}
fn held() -> BTreeMap<String, TablePartitions> {
    items(&["A", "B"], &[])
}
fn no_reads(checked: &Checked) -> Result<Rows, String> {
    Err(format!("unexpected read {}", checked.sql))
}
fn split(
    sql: &str,
    params: &[SqlValue],
    tables: &BTreeMap<String, TablePartitions>,
) -> Result<Vec<PartitionStatement>, SplitError<String>> {
    split_intent(sql, params, &[], tables, no_reads)
}
fn refusal(sql: &str, tables: &BTreeMap<String, TablePartitions>) -> IntentRefusal {
    match split(sql, &[], tables) {
        Err(SplitError::Refused(refusal)) => refusal,
        other => panic!("{sql}: {other:?}"),
    }
}
fn refused(sql: &str) -> IntentRefusal {
    refusal(sql, &held())
}

fn db(lists: &[&str]) -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE items(id INTEGER PRIMARY KEY, list TEXT NOT NULL COLLATE NOCASE,
             pos INTEGER NOT NULL, amount INTEGER NOT NULL);
         CREATE TABLE totals(name TEXT PRIMARY KEY, value INTEGER NOT NULL);
         INSERT INTO totals VALUES ('bonus', 5), ('limit', 25);",
    )
    .unwrap();
    for (id, list, pos, amount) in [
        (1, "A", 1, 10),
        (2, "A", 2, 20),
        (3, "B", 1, 30),
        (4, "C", 1, 40),
    ] {
        if lists.contains(&list) {
            conn.execute(
                "INSERT INTO items VALUES (?, ?, ?, ?)",
                rusqlite::params![id, list, pos, amount],
            )
            .unwrap();
        }
    }
    conn
}
fn sql(value: &SqlValue) -> Sql {
    match value {
        SqlValue::Null => Sql::Null,
        SqlValue::Integer(value) => Sql::Integer(*value),
        SqlValue::Real(value) => Sql::Real(value.get()),
        SqlValue::Text(value) => Sql::Text(value.clone()),
        SqlValue::Blob(value) => Sql::Blob(value.clone()),
    }
}
fn read(conn: &Connection, checked: &Checked) -> Result<Rows, String> {
    let mut statement = conn.prepare(&checked.sql).map_err(|e| e.to_string())?;
    let width = statement.column_count();
    statement
        .query_map(
            rusqlite::params_from_iter(checked.params.iter().map(sql)),
            |row| {
                (0..width)
                    .map(|index| {
                        Ok(match row.get::<_, Sql>(index)? {
                            Sql::Null => SqlValue::Null,
                            Sql::Integer(value) => SqlValue::Integer(value),
                            Sql::Real(value) => SqlValue::real(value).unwrap_or(SqlValue::Null),
                            Sql::Text(value) => SqlValue::Text(value),
                            Sql::Blob(value) => SqlValue::Blob(value),
                        })
                    })
                    .collect()
            },
        )
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())
}

#[test]
fn assertions_see_only_the_held_partition_of_their_own_tables() {
    // A holds two rows, B and C one each.
    let conn = db(&["A", "B", "C"]);
    let capped = |list: &str| {
        let checked = check_assertion(
            "SELECT list, COUNT(*) FROM items GROUP BY list HAVING COUNT(*) > 1",
            &[],
            &items(&[list], &[]),
        )
        .unwrap();
        assert_eq!(checked.params, vec![text(list)]);
        read(&conn, &checked).unwrap()
    };
    assert_eq!(capped("A"), vec![vec![text("A"), int(2)]]);
    assert_eq!(capped("B"), Rows::new());
    let rules = items(&["B"], &[]);
    for (sql, refusal) in [
        (
            "SELECT * FROM items i JOIN other o ON o.id = i.id",
            IntentRefusal::Unsupported(
                "the assertion reads other, which is not one of its tables".into(),
            ),
        ),
        (
            "SELECT * FROM items WHERE amount > random()",
            IntentRefusal::Random("random".into()),
        ),
        (
            "WITH x AS (SELECT * FROM items) SELECT * FROM x",
            IntentRefusal::Unsupported("WITH in a replayed statement".into()),
        ),
        (
            "SELECT * FROM items WHERE amount > ?",
            IntentRefusal::Unsupported("an assertion binds no parameters".into()),
        ),
        (
            "DELETE FROM items",
            IntentRefusal::Unsupported("an assertion is one SELECT".into()),
        ),
    ] {
        assert_eq!(
            check_assertion(sql, &[], &rules).unwrap_err(),
            refusal,
            "{sql}"
        );
    }
}
fn rows(conn: &Connection, filter: &str) -> Vec<(i64, String, i64, i64)> {
    conn.prepare(&format!(
        "SELECT id, list, pos, amount FROM items WHERE {filter} ORDER BY id"
    ))
    .unwrap()
    .query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}
/// Runs the statement once on the held partitions and, split, on a device
/// that also caches unheld `C`: both end equal and `C` is untouched.
/// Returns the copies and how many reads were evaluated.
fn equivalent(sql: &str, params: &[SqlValue]) -> (Vec<PartitionStatement>, usize) {
    let original = db(&["A", "B"]);
    original
        .execute(
            sql,
            rusqlite::params_from_iter(params.iter().map(super::tests::sql)),
        )
        .unwrap_or_else(|error| panic!("{sql}: {error}"));
    let device = db(&["A", "B", "C"]);
    let mut reads = 0;
    let copies = split_intent(sql, params, &[], &held(), |checked| {
        reads += 1;
        read(&device, checked)
    })
    .unwrap_or_else(|error| panic!("{sql}: {error:?}"));
    for copy in &copies {
        let statement = &copy.statement;
        device
            .execute(
                &statement.sql,
                rusqlite::params_from_iter(statement.params.iter().map(super::tests::sql)),
            )
            .unwrap_or_else(|error| panic!("{}: {error}", statement.sql));
    }
    assert_eq!(rows(&device, "list <> 'C'"), rows(&original, "1"), "{sql}");
    assert_eq!(
        rows(&device, "list = 'C'"),
        [(4, "C".into(), 1, 40)],
        "{sql}"
    );
    (copies, reads)
}
fn partitions(copies: &[PartitionStatement]) -> Vec<Vec<SqlValue>> {
    copies.iter().map(|copy| copy.partition.clone()).collect()
}

#[test]
fn clock_functions_refuse_unless_fully_bound_without_now() {
    for sql in [
        "UPDATE items SET amount = julianday('now') WHERE list = 'A'",
        "UPDATE items SET amount = unixepoch() WHERE list = 'A'",
        "UPDATE items SET amount = date() WHERE list = 'A'",
        "UPDATE items SET amount = CURRENT_TIMESTAMP WHERE list = 'A'",
        "UPDATE items SET amount = 1 WHERE list = 'A' AND CURRENT_DATE > '2000'",
        "UPDATE items SET amount = datetime('2024-01-01', 'localtime') WHERE list = 'A'",
        "UPDATE items SET amount = strftime('%s', pos) WHERE list = 'A'",
    ] {
        assert!(matches!(refused(sql), IntentRefusal::Clock(_)), "{sql}");
    }
    assert!(matches!(
        split("UPDATE items SET amount = date(?) WHERE list = 'A'", &[text(" NOW ")], &held()),
        Err(SplitError::Refused(IntentRefusal::Clock(name))) if name == "date"
    ));
    for (sql, params) in [
        (
            "UPDATE items SET amount = date('2024-01-01', '+1 day') WHERE list = 'A'",
            vec![],
        ),
        (
            "UPDATE items SET amount = unixepoch(?) WHERE list = 'A'",
            vec![text("2024-01-01")],
        ),
    ] {
        split(sql, &params, &held()).unwrap_or_else(|error| panic!("{sql}: {error:?}"));
    }
}

#[test]
fn random_functions_refuse() {
    assert_eq!(
        refused("UPDATE items SET amount = random() WHERE list = 'A'"),
        IntentRefusal::Random("random".into())
    );
    assert_eq!(
        refused("INSERT INTO items(id, list, pos, amount) VALUES (1, 'A', 1, randomblob(4))"),
        IntentRefusal::Random("randomblob".into())
    );
}

#[test]
fn environment_functions_and_engine_tables_refuse() {
    for (sql, name) in [
        (
            "UPDATE items SET amount = changes() WHERE list = 'A'",
            "changes",
        ),
        (
            "UPDATE items SET amount = last_insert_rowid() WHERE list = 'A'",
            "last_insert_rowid",
        ),
        (
            "UPDATE items SET amount = total_changes() WHERE list = 'A'",
            "total_changes",
        ),
        (
            "UPDATE items SET amount = sqlite_version() WHERE list = 'A'",
            "sqlite_version",
        ),
        (
            "UPDATE items SET amount = sqlite_source_id() WHERE list = 'A'",
            "sqlite_source_id",
        ),
        (
            "UPDATE items SET amount = (SELECT count(*) FROM sqlite_schema) WHERE list = 'A'",
            "sqlite_schema",
        ),
    ] {
        assert_eq!(
            refused(sql),
            IntentRefusal::Environment(name.into()),
            "{sql}"
        );
    }
}

#[test]
fn unknown_functions_and_collations_refuse() {
    for (sql, name) in [
        (
            "UPDATE items SET amount = my_udf(1) WHERE list = 'A'",
            "my_udf",
        ),
        ("UPDATE items SET amount = sin(1) WHERE list = 'A'", "sin"),
        (
            "UPDATE items SET amount = rocky_now() WHERE list = 'A'",
            "rocky_now",
        ),
        (
            "UPDATE items SET amount = 1 WHERE list = 'A' AND x IN (SELECT value FROM generate_series(1, 3))",
            "generate_series",
        ),
    ] {
        assert_eq!(
            refused(sql),
            IntentRefusal::UnknownFunction(name.into()),
            "{sql}"
        );
    }
    assert_eq!(
        refused("UPDATE items SET amount = 1 WHERE list = 'A' AND pos COLLATE my_order > 'x'"),
        IntentRefusal::UnknownCollation("my_order".into())
    );
    split(
        "UPDATE items SET amount = length(upper(coalesce(?, 'x') COLLATE NOCASE)) WHERE list = 'A'",
        &[text("y")],
        &held(),
    )
    .unwrap();
}

#[test]
fn extension_loading_refuses() {
    assert_eq!(
        refused("UPDATE items SET amount = load_extension('x') WHERE list = 'A'"),
        IntentRefusal::Extension("load_extension".into())
    );
    assert_eq!(
        refused("UPDATE items SET amount = readfile('x') WHERE list = 'A'"),
        IntentRefusal::Extension("readfile".into())
    );
}

#[test]
fn rowid_references_refuse() {
    for sql in [
        "UPDATE items SET amount = 1 WHERE list = 'A' AND rowid = 1",
        "DELETE FROM items WHERE list = 'A' AND items._rowid_ = 1",
        "UPDATE items SET amount = oid WHERE list = 'A'",
        "INSERT INTO items(rowid, list, pos, amount) VALUES (1, 'A', 1, 1)",
        "UPDATE items SET rowid = 9 WHERE list = 'A'",
    ] {
        assert_eq!(refused(sql), IntentRefusal::RowId, "{sql}");
    }
}

#[test]
fn autoincrement_schemas_refuse() {
    assert_eq!(
        check_replayed_table("CREATE TABLE t(id INTEGER PRIMARY KEY AUTOINCREMENT, a TEXT)"),
        Err(IntentRefusal::Autoincrement)
    );
    check_replayed_table("CREATE TABLE t(id INTEGER PRIMARY KEY, a TEXT DEFAULT 'autoincrement')")
        .unwrap();
}

#[test]
fn schema_statements_refuse() {
    for sql in [
        "CREATE TABLE t(a)",
        "CREATE INDEX i ON items(pos)",
        "DROP TABLE items",
        "ALTER TABLE items ADD COLUMN b",
        "CREATE TRIGGER t AFTER INSERT ON items BEGIN SELECT 1; END",
    ] {
        assert_eq!(refused(sql), IntentRefusal::Schema, "{sql}");
    }
}

#[test]
fn pragmas_and_attachments_refuse() {
    assert_eq!(refused("PRAGMA user_version = 3"), IntentRefusal::Pragma);
    assert_eq!(
        refused("ATTACH DATABASE 'x' AS y"),
        IntentRefusal::Attachment
    );
    assert_eq!(refused("DETACH DATABASE y"), IntentRefusal::Attachment);
}

#[test]
fn reads_are_not_writes() {
    assert_eq!(
        refused("SELECT * FROM items WHERE list = 'A'"),
        IntentRefusal::NotAWrite
    );
    assert_eq!(refused("VALUES (1)"), IntentRefusal::NotAWrite);
}

#[test]
fn partition_column_writes_refuse_as_moves() {
    let moved = IntentRefusal::PartitionMove {
        table: "items".into(),
        column: "list".into(),
    };
    for sql in [
        "UPDATE items SET list = 'B' WHERE list = 'A'",
        "UPDATE items SET (pos, list) = (1, 'B') WHERE id = 1",
        "INSERT INTO items(id, list, pos, amount) VALUES (1, 'B', 1, 1)
             ON CONFLICT(id) DO UPDATE SET list = excluded.list",
    ] {
        assert_eq!(refused(sql), moved, "{sql}");
    }
}

#[test]
fn a_filter_that_pins_one_partition_yields_one_copy() {
    let copies = split(
        "UPDATE items SET amount = ? WHERE list = ?",
        &[int(7), text("a")],
        &held(),
    )
    .unwrap();
    assert_eq!(partitions(&copies), [vec![text("A")]]);
    let statement = &copies[0].statement;
    assert_eq!(
        statement.sql,
        "UPDATE items SET amount = ?1 WHERE (list = ?2) AND (\"items\".\"list\" IN (?3))"
    );
    assert_eq!(statement.params, [int(7), text("a"), text("A")]);
    for sql in [
        "DELETE FROM items WHERE id = 3 AND list IN ('b')",
        "INSERT INTO items(id, list, pos, amount) VALUES (9, 'B', 1, 0)",
        "INSERT INTO items(id, list, pos, amount) VALUES (9, 'B', 1, 0), (10, 'b', 2, 0)",
    ] {
        assert_eq!(
            partitions(&split(sql, &[], &held()).unwrap()),
            [vec![text("B")]],
            "{sql}"
        );
    }
    // An unpartitioned table is one partition and needs no filter.
    let copies = split("UPDATE totals SET value = value + ?", &[int(1)], &held()).unwrap();
    assert_eq!(partitions(&copies), [Vec::<SqlValue>::new()]);
    assert_eq!(
        copies[0].statement.sql,
        "UPDATE totals SET value = value + ?1"
    );
}

#[test]
fn a_statement_reaching_several_partitions_splits_into_equivalent_copies() {
    for (sql, params) in [
        ("UPDATE items SET amount = amount + ?", vec![int(1)]),
        ("DELETE FROM items WHERE amount > ?", vec![int(15)]),
        (
            "INSERT INTO items(id, list, pos, amount) VALUES (?, ?, 1, 0), (?, ?, 2, 0), (?, 'a', 3, 0)",
            vec![int(10), text("A"), int(11), text("B"), int(12)],
        ),
        (
            "INSERT INTO items(id, list, pos, amount) VALUES (1, 'A', 9, 1), (3, 'B', 9, 1)
                 ON CONFLICT(id) DO UPDATE SET amount = amount + excluded.amount",
            vec![],
        ),
        // Reads within the row's own partition stay SQL.
        (
            "UPDATE items SET pos = (SELECT count(*) FROM items AS o
                 WHERE o.list = items.list AND o.id <= items.id) + ?",
            vec![int(100)],
        ),
    ] {
        let (copies, reads) = equivalent(sql, &params);
        assert_eq!(
            partitions(&copies),
            [vec![text("A")], vec![text("B")]],
            "{sql}"
        );
        assert_eq!(reads, 0, "{sql}");
    }
}

#[test]
fn reads_of_other_partitions_are_evaluated_once_and_bound() {
    for (sql, params) in [
        (
            "UPDATE items SET amount = amount + (SELECT value FROM totals WHERE name = ?)",
            vec![text("bonus")],
        ),
        (
            "UPDATE items SET amount = 0 WHERE amount IN (SELECT value * 4 FROM totals)",
            vec![],
        ),
        (
            "UPDATE items SET pos = pos + 1 WHERE NOT EXISTS (SELECT 1 FROM totals WHERE name = ?)",
            vec![text("missing")],
        ),
        (
            "INSERT INTO items(id, list, pos, amount)
                 SELECT 30 + id, list, pos, amount FROM items WHERE list IN ('A', 'B') AND amount < ?",
            vec![int(35)],
        ),
    ] {
        let (copies, reads) = equivalent(sql, &params);
        assert_eq!(reads, 1, "{sql}");
        assert_eq!(partitions(&copies), [vec![text("A")], vec![text("B")]], "{sql}");
        for copy in &copies {
            assert!(!copy.statement.sql.contains("totals"), "{}", copy.statement.sql);
            assert!(!copy.statement.sql.contains("SELECT"), "{}", copy.statement.sql);
        }
    }
    // Another partition of the same table is bound; the copy's own stays SQL.
    let (copies, reads) = equivalent(
        "UPDATE items SET amount = (SELECT max(amount) FROM items AS m WHERE m.list = 'B')
             + (SELECT max(pos) FROM items AS o WHERE o.list = 'A') WHERE list = 'A'",
        &[],
    );
    assert_eq!(reads, 1);
    assert_eq!(partitions(&copies), [vec![text("A")]]);
    assert!(
        copies[0].statement.sql.contains("max(pos)"),
        "{}",
        copies[0].statement.sql
    );
    assert!(
        !copies[0].statement.sql.contains("max(amount)"),
        "{}",
        copies[0].statement.sql
    );
    // Appending in the own partition keeps the read, so replay sees other appends.
    let (copies, reads) = equivalent(
        "INSERT INTO items(id, list, pos, amount)
             SELECT 20, ?, coalesce(max(pos), 0) + 1, 0 FROM items WHERE list = ?",
        &[text("B"), text("b")],
    );
    assert_eq!((partitions(&copies), reads), (vec![vec![text("B")]], 0));
    assert!(copies[0].statement.sql.contains("max(pos)"));
    // An unpartitioned table binds its reads of other tables, not its own.
    let device = db(&["A", "B", "C"]);
    let mut reads = 0;
    let copies = split_intent(
        "INSERT INTO totals(name, value)
             SELECT list, sum(amount) FROM items WHERE list IN ('A', 'B') GROUP BY list",
        &[],
        &[],
        &held(),
        |checked| {
            reads += 1;
            read(&device, checked)
        },
    )
    .unwrap();
    assert_eq!((partitions(&copies), reads), (vec![Vec::new()], 1));
    assert!(!copies[0].statement.sql.contains("items"));
    let copies = split(
        "INSERT INTO totals(name, value) SELECT 'all', sum(value) FROM totals",
        &[],
        &held(),
    )
    .unwrap();
    assert!(copies[0].statement.sql.contains("sum(value)"));
    // A read of other partitions that names the outer row has no single value.
    assert_eq!(
        refused(
            "UPDATE items SET amount = (SELECT value FROM totals WHERE totals.name = items.list)"
        ),
        IntentRefusal::CorrelatedSubquery
    );
}

#[test]
fn held_partitions_that_wait_refuse_the_write() {
    let tables = items(&["A"], &["B"]);
    let incomplete = IntentRefusal::Unavailable {
        table: "items".into(),
        reason: Unavailable::Incomplete,
    };
    for sql in [
        "UPDATE items SET amount = 1",
        "DELETE FROM items WHERE list IN ('A', 'b')",
        "INSERT INTO items(id, list, pos, amount) VALUES (9, 'B', 1, 0)",
        "UPDATE items SET amount = (SELECT max(amount) FROM items AS m WHERE m.list = 'B') WHERE list = 'A'",
    ] {
        let refusal = match split_intent(sql, &[], &[], &tables, |_| {
            Ok::<Rows, String>(vec![vec![int(1)]])
        }) {
            Err(SplitError::Refused(refusal)) => refusal,
            other => panic!("{sql}: {other:?}"),
        };
        assert_eq!(refusal, incomplete, "{sql}");
    }
    assert_eq!(
        partitions(&split("UPDATE items SET amount = 1 WHERE list = 'A'", &[], &tables).unwrap()),
        [vec![text("A")]]
    );
    assert_eq!(
        refusal("DELETE FROM items WHERE list = 'C'", &tables),
        IntentRefusal::Unavailable {
            table: "items".into(),
            reason: Unavailable::NotHeld,
        }
    );
}

#[test]
fn more_than_sixty_four_partitions_refuse_the_statement() {
    let lists: Vec<String> = (0..=MAX_INTENT_PARTITIONS)
        .map(|index| format!("p{index}"))
        .collect();
    let names: Vec<&str> = lists.iter().map(String::as_str).collect();
    let full = items(&names[..MAX_INTENT_PARTITIONS], &[]);
    assert_eq!(
        split("UPDATE items SET amount = 0", &[], &full)
            .unwrap()
            .len(),
        MAX_INTENT_PARTITIONS
    );
    let over = items(&names, &[]);
    assert_eq!(
        refusal("UPDATE items SET amount = 0", &over),
        IntentRefusal::TooManyPartitions(MAX_INTENT_PARTITIONS + 1)
    );
    let rows = names
        .iter()
        .enumerate()
        .map(|(id, list)| format!("({id}, '{list}', 1, 0)"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        refusal(
            &format!("INSERT INTO items(id, list, pos, amount) VALUES {rows}"),
            &over
        ),
        IntentRefusal::TooManyPartitions(MAX_INTENT_PARTITIONS + 1)
    );
}
