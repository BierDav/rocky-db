//! Durable placement migration: moves installed domains to another file
//! slot while nothing has them open. The catalog records the intent, then
//! the copy's switch, then the cleanup; an interrupted migration resumes
//! from whichever of the three it reached. The source stays authoritative
//! until the catalog assigns the domain to its target.
use crate::{
    DomainPlacement, Error, database::DatabaseOwner, layout, placement,
    scoped_connection::ScopedConnection, sqlite, storage,
};
use rocky_core::{AppId, DomainId, MeshId, Scope, SqlValue};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// Test hook: kill the process after this step: 1 intent recorded, 2 copy
/// committed, 3 assignment switched, 4 source dropped.
#[cfg(test)]
pub(crate) static ABORT_AFTER: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
fn reached(_step: usize) {
    #[cfg(test)]
    if ABORT_AFTER.load(std::sync::atomic::Ordering::Relaxed) == _step {
        std::process::abort();
    }
}

/// Moves each named domain to its new file slot and returns the complete
/// recorded assignment set. No runtime may have the catalog's affected files
/// open. Without moves it finishes an interrupted migration and reports the
/// recorded set.
pub async fn migrate_placement(
    path: impl AsRef<Path>,
    moves: Vec<DomainPlacement>,
) -> Result<Vec<DomainPlacement>, Error> {
    let path = path.as_ref().to_path_buf();
    let (done, result) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("rocky-relocation".into())
        .spawn(move || {
            let outcome = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(Error::Io)
                .and_then(|runtime| runtime.block_on(run(&path, moves)));
            let _ = done.send(outcome);
        })
        .map_err(Error::Io)?;
    result.await.map_err(|_| Error::Closed)?
}

fn scope(key: &[u8]) -> Result<Scope, Error> {
    let id = |range: std::ops::Range<usize>| {
        key.get(range)
            .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
            .ok_or_else(|| Error::Corrupt("placement scope".into()))
    };
    Ok(Scope {
        mesh: MeshId(id(0..16)?),
        app: AppId(id(16..32)?),
        domain: DomainId(id(32..48)?),
    })
}
fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
struct Migration {
    scope: Vec<u8>,
    source: usize,
    target: usize,
    copied: bool,
}

async fn run(path: &Path, moves: Vec<DomainPlacement>) -> Result<Vec<DomainPlacement>, Error> {
    let mut catalog_path = path.as_os_str().to_owned();
    catalog_path.push("-placement.sqlite");
    let catalog_path = PathBuf::from(catalog_path);
    if !catalog_path.exists() {
        return Err(Error::Incompatible("no placement catalog".into()));
    }
    let (_owner, raw) = DatabaseOwner::open(&catalog_path).await?;
    let catalog = ScopedConnection::new(raw, None, &[""; 0]);
    let (id, files) = match storage::rows(
        &catalog,
        "SELECT identity,files FROM rocky_placement WHERE id=1",
    )
    .await?
    .as_slice()
    {
        [row] => match row.as_slice() {
            [SqlValue::Blob(id), SqlValue::Integer(files)] => (id.clone(), *files as usize),
            _ => return Err(Error::Corrupt("placement metadata".into())),
        },
        _ => return Err(Error::Corrupt("placement metadata".into())),
    };
    storage::rows(&catalog, "PRAGMA journal_mode=wal").await?;
    catalog.execute("PRAGMA synchronous=FULL", ()).await?;
    catalog.execute("PRAGMA fullfsync=ON", ()).await?;
    write(&catalog, async |catalog| {
        catalog.execute(placement::MIGRATIONS, ()).await?;
        Ok(())
    })
    .await?;
    let mut pending = migrations(&catalog).await?;
    if pending.is_empty() {
        plan(&catalog, path, &id, files, &moves).await?;
        reached(1);
        pending = migrations(&catalog).await?;
    } else if !moves.is_empty()
        && (moves.len() != pending.len()
            || moves.iter().any(|item| {
                !pending.iter().any(|migration| {
                    migration.scope == placement::key(item.scope) && migration.target == item.file
                })
            }))
    {
        return Err(Error::Incompatible(
            "another placement migration is pending; finish it first".into(),
        ));
    }
    let binding = |slot: usize| {
        let mut binding = id.clone();
        binding.extend((slot as u32).to_le_bytes());
        binding
    };
    for migration in pending {
        let namespace = crate::runtime::namespace(scope(&migration.scope)?);
        let source = layout::file_path(path, migration.source);
        let target = layout::file_path(path, migration.target);
        if !migration.copied {
            copy(
                &source,
                &binding(migration.source),
                &target,
                &binding(migration.target),
                &namespace,
            )
            .await?;
            reached(2);
            // The switch: from here the target holds the domain.
            write(&catalog, async |catalog| {
                catalog
                    .execute(
                        "UPDATE rocky_assignments SET file=? WHERE scope=?",
                        sqlite::params![migration.target as i64, migration.scope.clone()],
                    )
                    .await?;
                catalog
                    .execute(
                        "UPDATE rocky_migrations SET phase=1 WHERE scope=?",
                        [migration.scope.clone()],
                    )
                    .await?;
                Ok(())
            })
            .await?;
            reached(3);
        }
        discard(&source, &namespace).await?;
        reached(4);
        write(&catalog, async |catalog| {
            catalog
                .execute(
                    "DELETE FROM rocky_migrations WHERE scope=?",
                    [migration.scope.clone()],
                )
                .await?;
            Ok(())
        })
        .await?;
    }
    let mut recorded = Vec::new();
    for (key, (file, _, _)) in assignments(&catalog).await? {
        recorded.push(DomainPlacement {
            scope: scope(&key)?,
            file,
        });
    }
    Ok(recorded)
}
async fn write(
    conn: &ScopedConnection,
    body: impl AsyncFnOnce(&ScopedConnection) -> Result<(), Error>,
) -> Result<(), Error> {
    conn.execute("BEGIN IMMEDIATE", ()).await?;
    let result = body(conn).await;
    storage::finish(conn, result).await
}
async fn migrations(catalog: &ScopedConnection) -> Result<Vec<Migration>, Error> {
    let rows = storage::rows(
        catalog,
        "SELECT scope,source,target,phase FROM rocky_migrations ORDER BY scope",
    )
    .await?;
    rows.iter()
        .map(|row| match row.as_slice() {
            [
                SqlValue::Blob(scope),
                SqlValue::Integer(source),
                SqlValue::Integer(target),
                SqlValue::Integer(phase),
            ] => Ok(Migration {
                scope: scope.clone(),
                source: *source as usize,
                target: *target as usize,
                copied: *phase != 0,
            }),
            _ => Err(Error::Corrupt("placement migration".into())),
        })
        .collect()
}
/// Scope to its slot, whether it was ever installed and whether it is ready.
type Assignments = BTreeMap<Vec<u8>, (usize, bool, bool)>;
async fn assignments(catalog: &ScopedConnection) -> Result<Assignments, Error> {
    let rows = storage::rows(
        catalog,
        "SELECT scope,file,identity IS NOT NULL,ready FROM rocky_assignments",
    )
    .await?;
    rows.iter()
        .map(|row| match row.as_slice() {
            [
                SqlValue::Blob(scope),
                SqlValue::Integer(file),
                SqlValue::Integer(installed),
                SqlValue::Integer(ready),
            ] => Ok((
                scope.clone(),
                (*file as usize, *installed != 0, *ready != 0),
            )),
            _ => Err(Error::Corrupt("placement assignment".into())),
        })
        .collect()
}
/// Validates the moves against the recorded assignments and records them. A domain that was never installed has no data and is
/// reassigned at once.
async fn plan(
    catalog: &ScopedConnection,
    path: &Path,
    id: &[u8],
    files: usize,
    moves: &[DomainPlacement],
) -> Result<(), Error> {
    let recorded = assignments(catalog).await?;
    let mut moving: Vec<(Vec<u8>, usize, usize, bool)> = Vec::new();
    for item in moves {
        let key = placement::key(item.scope);
        let Some((file, installed, ready)) = recorded.get(&key).copied() else {
            return Err(Error::Incompatible("unassigned scope".into()));
        };
        if item.file >= files || moving.iter().any(|(scope, ..)| *scope == key) {
            return Err(Error::Incompatible(
                "invalid or duplicate domain placement".into(),
            ));
        }
        if installed && !ready {
            return Err(Error::Incompatible(
                "finish the domain's interrupted installation before moving it".into(),
            ));
        }
        if file != item.file {
            moving.push((key, file, item.file, ready));
        }
    }
    // Nothing is recorded while a runtime holds a file or a target is foreign.
    for (_, source, target, ready) in &moving {
        if *ready {
            let marker = |slot: &usize| [id, &(*slot as u32).to_le_bytes()].concat();
            drop(open(&layout::file_path(path, *source), &marker(source), false).await?);
            drop(open(&layout::file_path(path, *target), &marker(target), true).await?);
        }
    }
    write(catalog, async |catalog| {
        for (scope, source, target, ready) in moving {
            if ready {
                catalog
                    .execute(
                        "INSERT INTO rocky_migrations VALUES(?,?,?,0)",
                        sqlite::params![scope, source as i64, target as i64],
                    )
                    .await?;
            } else {
                catalog
                    .execute(
                        "UPDATE rocky_assignments SET file=? WHERE scope=?",
                        sqlite::params![target as i64, scope],
                    )
                    .await?;
            }
        }
        Ok(())
    })
    .await
}

async fn text(
    conn: &ScopedConnection,
    sql: &str,
    value: &str,
) -> Result<Vec<Vec<SqlValue>>, Error> {
    storage::collect_rows(conn.query(sql, [value]).await?).await
}
/// Tables of `schema` in the domain's namespace, each with its statement.
async fn tables(
    conn: &ScopedConnection,
    schema: &str,
    namespace: &str,
) -> Result<Vec<(String, String)>, Error> {
    let prefix = format!("{namespace}_");
    let rows = storage::rows(
        conn,
        &format!("SELECT type,name,tbl_name,sql FROM {schema}.sqlite_schema ORDER BY name"),
    )
    .await?;
    let mut found = Vec::new();
    for row in rows {
        let [
            SqlValue::Text(kind),
            SqlValue::Text(name),
            SqlValue::Text(table),
            sql,
        ] = row.as_slice()
        else {
            continue;
        };
        if !table.starts_with(&prefix) {
            continue;
        }
        match (kind.as_str(), sql) {
            ("table", SqlValue::Text(sql)) => found.push((name.clone(), sql.clone())),
            // Indexes travel with their table; nothing else is installed.
            ("index", _) => {}
            _ => {
                return Err(Error::Incompatible(format!(
                    "{name} cannot be moved with its domain"
                )));
            }
        }
    }
    Ok(found)
}
/// A file of this catalog, with its marker checked against `binding`.
async fn open(
    path: &Path,
    binding: &[u8],
    fresh: bool,
) -> Result<(DatabaseOwner, ScopedConnection), Error> {
    let (owner, raw) = DatabaseOwner::open(path).await?;
    let conn = ScopedConnection::new(raw, None, &[""; 0]);
    let existing = storage::rows(
        &conn,
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    )
    .await?;
    let has = |table: &str| existing.contains(&vec![SqlValue::Text(table.into())]);
    if existing.is_empty() && fresh {
        return Ok((owner, conn));
    }
    if has("rocky_bootstrap") {
        return Err(Error::Incompatible(
            "finish the file's interrupted installation before moving a domain".into(),
        ));
    }
    if !has("rocky_runtime")
        || storage::rows(&conn, "SELECT binding FROM rocky_runtime WHERE id=1").await?
            != vec![vec![SqlValue::Blob(binding.to_vec())]]
    {
        return Err(Error::Incompatible(
            "file belongs to another placement catalog".into(),
        ));
    }
    Ok((owner, conn))
}
/// Copies the namespace's tables, rows and indexes into `target` in one
/// transaction. A copy left by an interrupted attempt is replaced: the
/// source is still the domain.
async fn copy(
    source: &Path,
    source_binding: &[u8],
    target: &Path,
    target_binding: &[u8],
    namespace: &str,
) -> Result<(), Error> {
    if !source.exists() {
        return Err(Error::Incompatible(
            "assigned runtime file is missing".into(),
        ));
    }
    // Holding the source's lock keeps every writer out while it is read.
    let (_source_owner, checked) = open(source, source_binding, false).await?;
    drop(checked);
    let (_target_owner, conn) = open(target, target_binding, true).await?;
    storage::rows(&conn, "PRAGMA journal_mode=wal").await?;
    conn.execute("PRAGMA synchronous=FULL", ()).await?;
    conn.execute("PRAGMA fullfsync=ON", ()).await?;
    let attached = source
        .to_str()
        .ok_or_else(|| Error::Incompatible("data path must be UTF-8".into()))?;
    conn.execute("ATTACH DATABASE ? AS source", [attached])
        .await?;
    let moved = tables(&conn, "source", namespace).await?;
    if moved.is_empty() {
        return Err(Error::Corrupt("assigned domain is missing".into()));
    }
    let indexes = storage::rows(
        &conn,
        "SELECT tbl_name,sql FROM source.sqlite_schema WHERE type='index' AND sql IS NOT NULL ORDER BY name",
    )
    .await?;
    let sequences = !text(
        &conn,
        "SELECT 1 FROM source.sqlite_schema WHERE name=?",
        "sqlite_sequence",
    )
    .await?
    .is_empty();
    let stale = tables(&conn, "main", namespace).await?;
    let target_binding = target_binding.to_vec();
    let copied = write(&conn, async |conn| {
        conn.execute("CREATE TABLE IF NOT EXISTS rocky_runtime(id INTEGER PRIMARY KEY CHECK(id=1),binding BLOB NOT NULL)", ()).await?;
        conn.execute(
            "INSERT OR IGNORE INTO rocky_runtime VALUES(1,?)",
            [target_binding],
        )
        .await?;
        for (name, _) in &stale {
            conn.execute(format!("DROP TABLE main.{}", quoted(name)), ())
                .await?;
        }
        for (name, sql) in &moved {
            conn.execute(sql, ()).await?;
            let table = quoted(name);
            let columns = text(
                conn,
                "SELECT name,type,pk FROM pragma_table_xinfo(?) WHERE hidden=0 ORDER BY cid",
                name,
            )
            .await?;
            let mut names = Vec::new();
            let mut keys = Vec::new();
            for column in &columns {
                let [SqlValue::Text(column), SqlValue::Text(kind), SqlValue::Integer(key)] =
                    column.as_slice()
                else {
                    return Err(Error::Corrupt(format!("columns of {name}")));
                };
                if *key != 0 {
                    keys.push(kind.eq_ignore_ascii_case("INTEGER"));
                }
                names.push(column.clone());
            }
            let rowid_table = text(
                conn,
                "SELECT wr FROM pragma_table_list WHERE schema='main' AND name=?",
                name,
            )
            .await?
                == vec![vec![SqlValue::Integer(0)]];
            // An INTEGER PRIMARY KEY already is the row id.
            let aliased = keys == [true]
                || names
                    .iter()
                    .any(|column| ["rowid", "oid", "_rowid_"].contains(&column.to_ascii_lowercase().as_str()));
            let mut list: Vec<String> = names.iter().map(|column| quoted(column)).collect();
            if rowid_table && !aliased {
                list.push("rowid".into());
            }
            let list = list.join(",");
            conn.execute(
                format!("INSERT INTO main.{table}({list}) SELECT {list} FROM source.{table}"),
                (),
            )
            .await?;
            if sequences && sql.to_ascii_uppercase().contains("AUTOINCREMENT") {
                conn.execute("DELETE FROM main.sqlite_sequence WHERE name=?", [name.as_str()])
                    .await?;
                conn.execute(
                    "INSERT INTO main.sqlite_sequence(name,seq) SELECT name,seq FROM source.sqlite_sequence WHERE name=?",
                    [name.as_str()],
                )
                .await?;
            }
            let equal = storage::rows(
                conn,
                &format!(
                    "SELECT (SELECT count(*) FROM main.{table})=(SELECT count(*) FROM source.{table})"
                ),
            )
            .await?;
            if equal != vec![vec![SqlValue::Integer(1)]] {
                return Err(Error::Corrupt(format!("copy of {name} is incomplete")));
            }
        }
        let prefix = format!("{namespace}_");
        for index in &indexes {
            if let [SqlValue::Text(table), SqlValue::Text(sql)] = index.as_slice()
                && table.starts_with(&prefix)
            {
                conn.execute(sql, ()).await?;
            }
        }
        Ok(())
    })
    .await;
    let detached = conn.execute("DETACH DATABASE source", ()).await;
    copied?;
    detached?;
    Ok(())
}
/// Drops the namespace's tables from the file the domain left.
async fn discard(source: &Path, namespace: &str) -> Result<(), Error> {
    if !source.exists() {
        return Ok(());
    }
    let (_owner, raw) = DatabaseOwner::open(source).await?;
    let conn = ScopedConnection::new(raw, None, &[""; 0]);
    let left = tables(&conn, "main", namespace).await?;
    if left.is_empty() {
        return Ok(());
    }
    storage::rows(&conn, "PRAGMA journal_mode=wal").await?;
    conn.execute("PRAGMA synchronous=FULL", ()).await?;
    conn.execute("PRAGMA fullfsync=ON", ()).await?;
    write(&conn, async |conn| {
        for (name, _) in &left {
            conn.execute(format!("DROP TABLE main.{}", quoted(name)), ())
                .await?;
        }
        Ok(())
    })
    .await
}
