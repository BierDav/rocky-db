use crate::{Error, sqlite};
use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};

/// File lifetime is separate from scoped reducer/author/revision scheduling.
/// `<file>.lock` beside the file: appended, so `a.db` and `a.sqlite` in one
/// directory do not share a lock.
fn lock_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}
/// The lock file excludes a second process, so one writer owns the file.
pub struct DatabaseOwner {
    path: PathBuf,
    _lock: File,
}
impl DatabaseOwner {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn connect(&self) -> Result<sqlite::Connection, Error> {
        Ok(sqlite::Connection::open(&self.path)?)
    }
    pub fn connect_read_only(&self) -> Result<sqlite::Connection, Error> {
        Ok(sqlite::Connection::open_read_only(&self.path)?)
    }
    pub async fn open(path: &Path) -> Result<(Self, sqlite::Connection), Error> {
        let path_string = path
            .to_str()
            .ok_or_else(|| Error::Incompatible("data path must be UTF-8".into()))?;
        if path_string == ":memory:" {
            return Err(Error::Incompatible("an on-disk file is required".into()));
        }
        check_file_format(path).await?;
        if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(Error::Io)?;
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path(path))
            .map_err(Error::Io)?;
        // A child process being spawned briefly shares a just-closed owner's
        // lock until it execs, so a reopen right after close waits a moment.
        let mut attempt = 0;
        while let Err(error) = lock.try_lock() {
            attempt += 1;
            if attempt == 10 {
                return Err(Error::Incompatible(format!(
                    "replica is already open or file lock unavailable: {error}"
                )));
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let owner = Self {
            path: path.to_path_buf(),
            _lock: lock,
        };
        check_file_format(path).await?;
        let connection = owner.connect()?;
        if !std::fs::metadata(path).is_ok_and(|file| file.len() > 0) {
            // Only an empty file takes `auto_vacuum`; maintenance reclaims
            // free pages in bounded steps.
            connection
                .execute("PRAGMA auto_vacuum=INCREMENTAL", ())
                .await?;
            connection
                .execute(format!("PRAGMA application_id={FILE_FORMAT}"), ())
                .await?;
        }
        Ok((owner, connection))
    }
}

/// Current Rocky SQLite file identity. Application schema generations are independent.
pub const FILE_FORMAT: i64 = 0x524b5902;

/// Read-only preflight, also used before SDK settings/enrollment writes.
pub async fn check_file_format(path: &Path) -> Result<(), Error> {
    if !std::fs::metadata(path).is_ok_and(|file| file.len() > 0) {
        return Ok(());
    }
    let conn = sqlite::Connection::open_read_only(path)?;
    let mut version = conn.query("PRAGMA application_id", ()).await?;
    if version
        .next()
        .await?
        .is_none_or(|row| row.get::<i64>(0).ok() != Some(FILE_FORMAT))
    {
        return Err(Error::Incompatible("unsupported Rocky file format".into()));
    }
    let mut tables = conn
        .query("SELECT name FROM sqlite_schema WHERE type='table'", ())
        .await?;
    while let Some(row) = tables.next().await? {
        let name = row.get::<String>(0)?;
        let scoped = name
            .strip_suffix("_rocky_logical_schema")
            .and_then(|prefix| prefix.strip_prefix('d'))
            .is_some_and(|hash| {
                hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
        if name != "rocky_logical_schema" && !scoped {
            continue;
        }
        let quoted = name.replace('"', "\"\"");
        let mut descriptors = conn
            .query(
                format!("SELECT descriptor FROM \"{quoted}\" WHERE id=1"),
                (),
            )
            .await?;
        while let Some(row) = descriptors.next().await? {
            rocky_core::LogicalSchema::check_stored_row_identity(&row.get::<Vec<u8>>(0)?)
                .map_err(|error| Error::Incompatible(error.to_string()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn unsupported_files_are_refused_before_any_write() {
        for version in [0, FILE_FORMAT - 1, FILE_FORMAT + 1] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("file.sqlite");
            let conn = sqlite::Connection::open(&path).unwrap();
            conn.execute("CREATE TABLE sentinel(value TEXT)", ())
                .await
                .unwrap();
            conn.execute("INSERT INTO sentinel VALUES('retained')", ())
                .await
                .unwrap();
            conn.execute(format!("PRAGMA application_id={version}"), ())
                .await
                .unwrap();
            drop(conn);
            let before = std::fs::read(&path).unwrap();
            let error = DatabaseOwner::open(&path).await.err().unwrap();
            assert_eq!(
                error.to_string(),
                Error::Incompatible("unsupported Rocky file format".into()).to_string()
            );
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert!(!lock_path(&path).exists());
            assert!(!directory.path().join("file.sqlite-wal").exists());
        }
    }
    #[tokio::test]
    async fn unsupported_stored_descriptors_refuse_before_any_write() {
        for table in [
            "rocky_logical_schema",
            "d0000000000000000000000000000000000000000000000000000000000000000_rocky_logical_schema",
        ] {
            for version in [0, 1, 2, 3, 4, 5, 7] {
                let directory = tempfile::tempdir().unwrap();
                let path = directory.path().join("file.sqlite");
                let conn = sqlite::Connection::open(&path).unwrap();
                conn.execute(format!("PRAGMA application_id={FILE_FORMAT}"), ())
                    .await
                    .unwrap();
                conn.execute(
                    format!("CREATE TABLE {table}(id INTEGER PRIMARY KEY,descriptor BLOB)"),
                    (),
                )
                .await
                .unwrap();
                conn.execute(
                    format!("INSERT INTO {table} VALUES(1,?)"),
                    [format!("{{\"format\":{version}}}").into_bytes()],
                )
                .await
                .unwrap();
                drop(conn);
                let before = std::fs::read(&path).unwrap();
                let error = DatabaseOwner::open(&path).await.err().unwrap();
                assert_eq!(
                    error.to_string(),
                    Error::Incompatible(
                        "invalid logical schema: unsupported schema descriptor format".into()
                    )
                    .to_string()
                );
                assert_eq!(std::fs::read(&path).unwrap(), before);
                assert!(!lock_path(&path).exists());
                assert!(!directory.path().join("file.sqlite-wal").exists());
            }
        }
    }
    #[tokio::test]
    async fn application_table_suffixes_are_not_schema_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("application.sqlite");
        let (owner, conn) = DatabaseOwner::open(&path).await.unwrap();
        conn.execute("CREATE TABLE notes_rocky_logical_schema(body TEXT)", ())
            .await
            .unwrap();
        conn.execute(
            "INSERT INTO notes_rocky_logical_schema VALUES('retained')",
            (),
        )
        .await
        .unwrap();
        drop(conn);
        drop(owner);
        let before = std::fs::read(&path).unwrap();
        check_file_format(&path).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    #[tokio::test]
    async fn a_new_file_reopens_with_the_current_tag() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("file.sqlite");
        let (owner, conn) = DatabaseOwner::open(&path).await.unwrap();
        conn.execute("CREATE TABLE sentinel(value TEXT)", ())
            .await
            .unwrap();
        drop(conn);
        drop(owner);
        check_file_format(&path).await.unwrap();
        let (owner, conn) = DatabaseOwner::open(&path).await.unwrap();
        drop(conn);
        drop(owner);
    }
}
