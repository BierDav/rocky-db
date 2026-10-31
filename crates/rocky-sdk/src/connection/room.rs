//! Room 2.8.4's housekeeping statements, answered from the session
//! catalog instead of reaching the engine, and its modification log,
//! emulated from committed table events. Statements are matched as Room
//! 2.8.4 writes them; anything else goes to the session, which denies
//! pragmas and schema changes. See `docs/runtime/sql-driver.md#room-284`.
use super::{Failure, Pending, code, failure};
use rocky_core::{SqlValue, TypedRows};
use rocky_runtime::TableObserver;
use rocky_secure::{Describe, SecureSql};
use std::collections::BTreeMap;

/// Room's identity row and table.
const MASTER: &str = "room_master_table";
const LOG: &str = "room_table_modification_log";
const TRIGGER: &str = "room_table_modification_trigger_";

/// What an answer may consult.
pub(super) struct Context<'a> {
    pub sql: &'a SecureSql<TypedRows>,
    /// The version the application declares, which is Room's database
    /// version whatever generation the database is at.
    pub version: u32,
    /// Tables the application declares otherwise than the installed
    /// generation: Room validates them as declared, and statements on what
    /// differs fail as SQLite fails them.
    pub declared: &'a [rocky_core::LogicalTable],
    pub read_only: bool,
    /// What `busy_timeout` reports: the writer's transaction timeout.
    pub busy_timeout: i64,
}

/// One connection's emulated Room state.
pub(super) struct Housekeeping {
    /// Committed changes since the log was last read; None without the
    /// Room profile.
    observer: Option<TableObserver>,
    /// The identity hash Room wrote this connection's life.
    identity: Option<String>,
    log: Option<Log>,
}
#[derive(Default)]
struct Log {
    /// Table ids Room tracks, and whether a commit invalidated them.
    invalidated: BTreeMap<i64, bool>,
    /// Tracked (lowercase table, operation) and the id their trigger sets.
    triggers: BTreeMap<(String, String), i64>,
}

impl Housekeeping {
    pub(super) fn new(observer: Option<TableObserver>) -> Self {
        Self {
            observer,
            identity: None,
            log: None,
        }
    }

    /// The answer to a housekeeping statement, or None for one the
    /// session runs.
    pub(super) async fn answer(
        &mut self,
        sql: &str,
        params: &[SqlValue],
        context: Context<'_>,
    ) -> Result<Option<Pending>, Failure> {
        if self.observer.is_none() {
            return Ok(None);
        }
        let words = words(sql);
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        // Room binds no parameter to any statement answered here.
        let answered = match words.as_slice() {
            ["PRAGMA", rest @ ..] => self.pragma(rest, &context).await?,
            ["SELECT", ..] | ["INSERT", ..] | ["UPDATE", ..] => self.query(&words, &context)?,
            ["CREATE", ..] | ["DROP", ..] => self.schema(&words, &context)?,
            _ => None,
        };
        if answered.is_some() && !params.is_empty() {
            return Err(failure(code::ERROR, "housekeeping statements take no parameters").into());
        }
        Ok(answered)
    }

    async fn pragma(
        &mut self,
        words: &[&str],
        context: &Context<'_>,
    ) -> Result<Option<Pending>, Failure> {
        let one =
            |name: &str, value: SqlValue| Some(Pending::rows(vec![name.into()], vec![vec![value]]));
        let none = || Some(Pending::rows(Vec::new(), Vec::new()));
        let lower = |word: &str| word.to_ascii_lowercase();
        Ok(match words {
            // Rocky's file is always in WAL mode; what Room asks for is
            // reported back as SQLite does when a mode cannot change.
            [name, "=", _] if lower(name) == "journal_mode" => {
                one("journal_mode", SqlValue::Text("wal".into()))
            }
            // Durability belongs to Rocky: it flushes before data leaves.
            [name, "=", "NORMAL" | "FULL"] if lower(name) == "synchronous" => none(),
            [name] if lower(name) == "busy_timeout" => {
                one("timeout", SqlValue::Integer(context.busy_timeout))
            }
            [name, "=", value] if lower(name) == "busy_timeout" => {
                let value: i64 = value
                    .parse()
                    .map_err(|_| failure(code::ERROR, "busy_timeout takes an integer"))?;
                one("timeout", SqlValue::Integer(value))
            }
            [name] if lower(name) == "user_version" => one(
                "user_version",
                SqlValue::Integer(i64::from(context.version)),
            ),
            [name, "=", value] if lower(name) == "user_version" => {
                if value.parse::<i64>().ok() != Some(i64::from(context.version)) {
                    return Err(failure(
                        code::ERROR,
                        format!(
                            "Room's database version {value} differs from the application's schema version {}; change the schema through Rocky",
                            context.version
                        ),
                    )
                    .into());
                }
                none()
            }
            [name, "=", "MEMORY"] if lower(name) == "temp_store" => none(),
            [name, "=", "1"] if lower(name) == "recursive_triggers" => none(),
            [name, "=", "ON"] if lower(name) == "foreign_keys" => none(),
            [name, "(", target, ")"] => {
                let pragma = match lower(name).as_str() {
                    "table_info" => Describe::TableInfo,
                    "index_list" => Describe::IndexList,
                    "index_info" => Describe::IndexInfo,
                    "index_xinfo" => Describe::IndexXinfo,
                    "foreign_key_list" => Describe::ForeignKeyList,
                    _ => return Ok(None),
                };
                let target = unquote(target);
                let index = matches!(pragma, Describe::IndexInfo | Describe::IndexXinfo);
                let declared = context.declared.iter().find(|table| {
                    if index {
                        table
                            .indexes
                            .iter()
                            .any(|index| index.name.eq_ignore_ascii_case(&target))
                    } else {
                        table.sql_name.eq_ignore_ascii_case(&target)
                    }
                });
                let rows = match declared {
                    Some(table) => {
                        context
                            .sql
                            .describe_declared(pragma, &target, table)
                            .await?
                    }
                    None => context.sql.describe(pragma, &target).await?,
                };
                let columns = rows.columns.into_iter().map(|column| column.name).collect();
                Some(Pending::rows(columns, rows.rows))
            }
            _ => None,
        })
    }

    fn query(&mut self, words: &[&str], context: &Context<'_>) -> Result<Option<Pending>, Failure> {
        let rows = |columns: &[&str], rows: Vec<Vec<SqlValue>>| {
            Some(Pending::rows(
                columns.iter().map(|column| (*column).into()).collect(),
                rows,
            ))
        };
        let catalog = context.sql.catalog();
        Ok(match words {
            [
                "SELECT",
                "1",
                "FROM",
                "sqlite_master",
                "WHERE",
                "type",
                "=",
                "'table'",
                "AND",
                "name",
                "=",
                "'room_master_table'",
            ] => {
                let found = self.identity.is_some().then(|| vec![SqlValue::Integer(1)]);
                rows(&["1"], found.into_iter().collect())
            }
            [
                "SELECT",
                "identity_hash",
                "FROM",
                MASTER,
                "WHERE",
                "id",
                "=",
                "42",
                "LIMIT",
                "1",
            ] => {
                let found = self.identity.clone().map(|hash| vec![SqlValue::Text(hash)]);
                rows(&["identity_hash"], found.into_iter().collect())
            }
            [
                "INSERT",
                "OR",
                "REPLACE",
                "INTO",
                MASTER,
                "(",
                "id",
                ",",
                "identity_hash",
                ")",
                "VALUES",
                "(",
                "42",
                ",",
                hash,
                ")",
            ] if hash.starts_with('\'') && !context.read_only => {
                self.identity = Some(unquote(hash));
                rows(&[], Vec::new())
            }
            [
                "SELECT",
                "count",
                "(",
                "*",
                ")",
                "FROM",
                "sqlite_master",
                "WHERE",
                "name",
                "!=",
                "'android_metadata'",
            ] => {
                let objects = catalog
                    .iter()
                    .map(|table| 1 + table.indexes.len())
                    .sum::<usize>();
                rows(
                    &["count(*)"],
                    vec![vec![SqlValue::Integer(i64::try_from(objects)?)]],
                )
            }
            [
                "SELECT",
                "name",
                ",",
                "type",
                "FROM",
                "sqlite_master",
                "WHERE",
                "type",
                "=",
                "'table'",
                "OR",
                "type",
                "=",
                "'view'",
            ] => rows(
                &["name", "type"],
                catalog
                    .iter()
                    .map(|table| {
                        vec![
                            SqlValue::Text(table.name.clone()),
                            SqlValue::Text("table".into()),
                        ]
                    })
                    .collect(),
            ),
            // Rocky's typed tables carry no trigger or view an ORM declared.
            [
                "SELECT",
                "name",
                "FROM",
                "sqlite_master",
                "WHERE",
                "type",
                "=",
                "'trigger'",
            ] => rows(&["name"], Vec::new()),
            [
                "SELECT",
                "name",
                ",",
                "sql",
                "FROM",
                "sqlite_master",
                "WHERE",
                "type",
                "=",
                "'view'",
                "AND",
                "name",
                "=",
                _,
            ] => rows(&["name", "sql"], Vec::new()),
            ["SELECT", "*", "FROM", LOG, "WHERE", "invalidated", "=", "1"] => {
                let log = self.log.as_mut().ok_or_else(|| missing(LOG))?;
                if let Some(observer) = &mut self.observer {
                    while let Some(change) = observer.try_next()? {
                        for ((table, _), id) in &log.triggers {
                            if change.tables.contains(table)
                                && let Some(invalidated) = log.invalidated.get_mut(id)
                            {
                                *invalidated = true;
                            }
                        }
                    }
                }
                rows(
                    &["table_id", "invalidated"],
                    log.invalidated
                        .iter()
                        .filter(|(_, invalidated)| **invalidated)
                        .map(|(id, _)| vec![SqlValue::Integer(*id), SqlValue::Integer(1)])
                        .collect(),
                )
            }
            [
                "UPDATE",
                LOG,
                "SET",
                "invalidated",
                "=",
                "0",
                "WHERE",
                "invalidated",
                "=",
                "1",
            ] => {
                let log = self.log.as_mut().ok_or_else(|| missing(LOG))?;
                log.invalidated
                    .values_mut()
                    .for_each(|invalidated| *invalidated = false);
                rows(&[], Vec::new())
            }
            [
                "INSERT",
                "OR",
                "IGNORE",
                "INTO",
                LOG,
                "VALUES",
                "(",
                id,
                ",",
                "0",
                ")",
            ] => {
                let log = self.log.as_mut().ok_or_else(|| missing(LOG))?;
                let id = id
                    .parse()
                    .map_err(|_| failure(code::ERROR, "table ids are integers"))?;
                log.invalidated.entry(id).or_insert(false);
                rows(&[], Vec::new())
            }
            _ => None,
        })
    }

    fn schema(
        &mut self,
        words: &[&str],
        context: &Context<'_>,
    ) -> Result<Option<Pending>, Failure> {
        let none = || Some(Pending::rows(Vec::new(), Vec::new()));
        let catalog = context.sql.catalog();
        let table = |name: &str| {
            let name = unquote(name);
            catalog
                .iter()
                .find(|table| table.name.eq_ignore_ascii_case(&name))
                .map(|table| table.name.to_ascii_lowercase())
                .ok_or_else(|| {
                    failure(
                        code::ERROR,
                        format!("table {name} is not part of the installed Rocky schema"),
                    )
                })
        };
        Ok(match words {
            [
                "CREATE",
                "TABLE",
                "IF",
                "NOT",
                "EXISTS",
                MASTER,
                "(",
                "id",
                "INTEGER",
                "PRIMARY",
                "KEY",
                ",",
                "identity_hash",
                "TEXT",
                ")",
            ] => none(),
            [
                "CREATE",
                "TEMP",
                "TABLE",
                "IF",
                "NOT",
                "EXISTS",
                LOG,
                "(",
                "table_id",
                "INTEGER",
                "PRIMARY",
                "KEY",
                ",",
                "invalidated",
                "INTEGER",
                "NOT",
                "NULL",
                "DEFAULT",
                "0",
                ")",
            ] => {
                self.log.get_or_insert_with(Log::default);
                none()
            }
            ["DROP", "TABLE", "IF", "EXISTS", LOG] => {
                self.log = None;
                none()
            }
            // As in SQLite, an existing table is left as it is; Room then
            // validates it against the catalog's answers. The entity must
            // still carry Rocky's identity and leave its ids to Rocky.
            [
                "CREATE",
                "TABLE",
                "IF",
                "NOT",
                "EXISTS",
                name,
                "(",
                columns @ ..,
            ] => {
                let owner = table(name)?;
                entity(&owner, columns)?;
                none()
            }
            ["CREATE", "INDEX" | "UNIQUE", ..] => {
                let unique = words[1] == "UNIQUE";
                let rest = &words[if unique { 2 } else { 1 }..];
                let ["INDEX", "IF", "NOT", "EXISTS", name, "ON", on, ..] = rest else {
                    return Ok(None);
                };
                let owner = table(on)?;
                let name = unquote(name);
                let listed = catalog.iter().any(|table| {
                    table.name.eq_ignore_ascii_case(&owner)
                        && table
                            .indexes
                            .iter()
                            .any(|index| index.name.eq_ignore_ascii_case(&name))
                });
                if !listed {
                    return Err(failure(
                        code::ERROR,
                        format!("index {name} is not part of the installed Rocky schema"),
                    )
                    .into());
                }
                none()
            }
            [
                "CREATE",
                "TEMP",
                "TRIGGER",
                "IF",
                "NOT",
                "EXISTS",
                name,
                "AFTER",
                operation,
                "ON",
                on,
                "BEGIN",
                "UPDATE",
                LOG,
                "SET",
                "invalidated",
                "=",
                "1",
                "WHERE",
                "table_id",
                "=",
                id,
                "AND",
                "invalidated",
                "=",
                "0",
                ";",
                "END",
            ] if unquote(name).starts_with(TRIGGER) => {
                let owner = table(on)?;
                let id = id
                    .parse()
                    .map_err(|_| failure(code::ERROR, "table ids are integers"))?;
                let log = self.log.as_mut().ok_or_else(|| missing(LOG))?;
                log.triggers
                    .insert((owner, operation.to_ascii_uppercase()), id);
                none()
            }
            ["DROP", "TRIGGER", "IF", "EXISTS", name] if unquote(name).starts_with(TRIGGER) => {
                let name = unquote(name);
                if let Some(log) = &mut self.log {
                    log.triggers.retain(|(table, operation), _| {
                        !name.eq_ignore_ascii_case(&format!("{TRIGGER}{table}_{operation}"))
                    });
                }
                none()
            }
            _ => None,
        })
    }
}

/// Refuses an entity Room would let assign row ids, or one without the
/// `id` field every Rocky table has. `columns` follow the
/// opening parenthesis of Room's `CREATE TABLE`.
fn entity(table: &str, columns: &[&str]) -> Result<(), Failure> {
    if columns
        .iter()
        .any(|word| word.eq_ignore_ascii_case("AUTOINCREMENT"))
    {
        return Err(failure(
            code::ERROR,
            format!(
                "Room entity {table}: autoGenerate = true is refused; Rocky issues row ids, reserve one with rocky_next_id"
            ),
        )
        .into());
    }
    let mut depth = 0;
    let mut declared = Vec::new();
    let mut starts = true;
    for word in columns {
        match *word {
            "(" => depth += 1,
            ")" => depth -= 1,
            "," if depth == 0 => {
                starts = true;
                continue;
            }
            _ if starts && depth == 0 => declared.push(unquote(word)),
            _ => {}
        }
        starts = false;
    }
    if !declared.iter().any(|name| name.eq_ignore_ascii_case("id")) {
        return Err(failure(
            code::ERROR,
            format!("Room entity {table} must declare Rocky's id field"),
        )
        .into());
    }
    Ok(())
}

fn missing(table: &str) -> Failure {
    failure(code::ERROR, format!("no such table: {table}")).into()
}

/// Strips the quotes of an identifier or string literal.
pub(super) fn unquote(word: &str) -> String {
    let quote = word.chars().next().unwrap_or(' ');
    let close = if quote == '[' { ']' } else { quote };
    if ['`', '"', '\'', '['].contains(&quote) && word.len() >= 2 && word.ends_with(close) {
        let inner = &word[1..word.len() - 1];
        inner.replace(&format!("{close}{close}"), &close.to_string())
    } else {
        word.to_string()
    }
}

/// The statement's words: names and keywords, quoted names and literals,
/// numbers and single punctuation, without whitespace and a final `;`.
pub(super) fn words(sql: &str) -> Vec<String> {
    let mut chars = sql.chars().peekable();
    let mut words = Vec::new();
    while let Some(first) = chars.next() {
        if first.is_whitespace() {
            continue;
        }
        let mut word = String::from(first);
        if ['\'', '"', '`', '['].contains(&first) {
            let end = if first == '[' { ']' } else { first };
            while let Some(next) = chars.next() {
                word.push(next);
                if next == end {
                    if chars.peek() == Some(&end) {
                        word.push(chars.next().unwrap_or(end));
                    } else {
                        break;
                    }
                }
            }
        } else if first.is_ascii_alphanumeric() || first == '_' {
            while let Some(next) = chars.peek().copied() {
                if !(next.is_ascii_alphanumeric() || next == '_') {
                    break;
                }
                word.push(next);
                chars.next();
            }
        } else if first == '!' && chars.peek() == Some(&'=') {
            word.push(chars.next().unwrap_or('='));
        }
        words.push(word);
    }
    if words.last().is_some_and(|word| word == ";") {
        words.pop();
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_keep_quoted_names_and_drop_the_final_semicolon() {
        assert_eq!(
            words("PRAGMA table_info(`my ``t```);"),
            ["PRAGMA", "table_info", "(", "`my ``t```", ")"]
        );
        assert_eq!(unquote("`my ``t```"), "my `t`");
        assert_eq!(
            words("SELECT count(*) FROM sqlite_master WHERE name != 'android_metadata'"),
            [
                "SELECT",
                "count",
                "(",
                "*",
                ")",
                "FROM",
                "sqlite_master",
                "WHERE",
                "name",
                "!=",
                "'android_metadata'"
            ]
        );
        // A trigger body keeps its inner semicolon.
        assert!(words("BEGIN UPDATE t SET a = 1; END").contains(&";".to_string()));
    }
}
