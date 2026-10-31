//! Process death in each step of a placement migration.
use super::*;
use crate::wide_schema_tests::{app, installation, options, test_scope};
use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;
use tempfile::TempDir;

const CASE: &str = "ROCKY_RELOCATION_CRASH_STEP";
const DIR: &str = "ROCKY_RELOCATION_CRASH_DIR";

/// Does nothing in an ordinary run; a parent test selects where to die.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_child() {
    let (Ok(step), Ok(dir)) = (std::env::var(CASE), std::env::var(DIR)) else {
        return;
    };
    let step = step.parse::<usize>().unwrap();
    crate::relocation::ABORT_AFTER.store(step, std::sync::atomic::Ordering::Relaxed);
    let moves = vec![DomainPlacement {
        scope: test_scope(0),
        file: 2,
    }];
    let _ = migrate_placement(Path::new(&dir).join("placed.db"), moves).await;
    panic!("the migration did not end the process");
}
fn crash(step: usize, dir: &Path) {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "relocation_tests::crash_child",
            "--exact",
            "--test-threads=1",
        ])
        .env(CASE, step.to_string())
        .env(DIR, dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(6), "step {step}: {status:?}");
}

#[tokio::test]
async fn an_interrupted_migration_resumes_from_every_step() {
    let placed = |file: usize| {
        vec![
            DomainPlacement {
                scope: test_scope(0),
                file,
            },
            DomainPlacement {
                scope: test_scope(1),
                file: 0,
            },
        ]
    };
    let serve = async |path: &Path, file: usize| {
        let domains = vec![installation(app(3), 0), installation(app(3), 1)];
        Runtime::open_placed(path, domains, placed(file), options()).await
    };
    let template = TempDir::new().unwrap();
    let source = template.path().join("placed.db");
    let runtime = serve(&source, 0).await.unwrap();
    for domain in 0..2 {
        let replica = runtime.domain(test_scope(domain)).unwrap();
        let text = format!("domain-{domain}");
        crate::wide_schema_tests::note(&replica, 1, &text)
            .committed()
            .await
            .unwrap();
    }
    runtime.close().await.unwrap();
    for step in 1..=4 {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("placed.db");
        for entry in std::fs::read_dir(template.path()).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), dir.path().join(entry.file_name())).unwrap();
        }
        crash(step, dir.path());
        // Neither assignment opens while the migration is pending.
        for file in [0, 2] {
            assert!(
                matches!(serve(&path, file).await, Err(Error::Incompatible(_))),
                "step {step}"
            );
        }
        let other = vec![DomainPlacement {
            scope: test_scope(0),
            file: 3,
        }];
        assert!(matches!(
            migrate_placement(&path, other).await,
            Err(Error::Incompatible(_))
        ));
        assert_eq!(
            migrate_placement(&path, Vec::new()).await.unwrap(),
            placed(2)
        );
        let runtime = serve(&path, 2).await.unwrap();
        for domain in 0..2 {
            let replica = runtime.domain(test_scope(domain)).unwrap();
            let snapshot = replica.query().await.unwrap();
            assert_eq!(snapshot.rows.len(), 1, "step {step}");
            assert_eq!(snapshot.rows[0].1, format!("domain-{domain}"));
            assert_eq!(snapshot.revision.get(), 1);
            crate::wide_schema_tests::note(&replica, 2, "after")
                .committed()
                .await
                .unwrap();
            replica.checkpoint().await.unwrap();
            assert!(replica.audit().await.unwrap().recomputed, "step {step}");
        }
        runtime.close().await.unwrap();
        // The file the domain left keeps only the other domain's tables.
        let left = crate::sqlite::Connection::open(&path).unwrap();
        let moved = format!("{}\\_%", crate::runtime::namespace(test_scope(0)));
        let stayed = format!("{}\\_%", crate::runtime::namespace(test_scope(1)));
        let count = |like: String| {
            let sql = "SELECT count(*) FROM sqlite_schema WHERE name LIKE ? ESCAPE '\\'";
            left.rows(sql, [like]).unwrap()
        };
        assert_eq!(count(moved), [[crate::sqlite::Value::Integer(0)]]);
        assert_ne!(count(stayed), [[crate::sqlite::Value::Integer(0)]]);
    }
}
