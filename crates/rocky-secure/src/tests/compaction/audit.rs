//! Guarded multi-scope audits use the production single-scope checks.
use super::*;
use crate::storage::rows;
mod fixture;
pub(in crate::tests) use fixture::snapshot;
use fixture::*;

#[tokio::test]
async fn reports_match_single_audits_with_bases_suffixes_and_no_base() {
    for based in [false, true] {
        let f = AuditFixture::new(based).await;
        let scopes = [f.lineage.scope("tags"), f.lineage.scope("items")];
        let expected = singles(&f.replica, &scopes).await;
        for (scope, report) in &expected {
            let has_base = based && *scope == f.lineage.scope("items");
            assert_eq!((report.operations, report.rows), (2, 2));
            assert_eq!(report.replayed, if has_base { 1 } else { 2 });
            assert_eq!(report.checkpoint.is_some(), has_base);
        }
        let before = snapshot(&f.replica).await;
        let passes = f
            .replica
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .audit_global_passes;
        assert_eq!(f.replica.audit_scopes(&scopes).await.unwrap(), expected);
        assert_eq!(
            f.replica
                .inner
                .lock(crate::replica::Class::Background)
                .await
                .audit_global_passes
                - passes,
            2
        );
        assert_clean(&f.replica).await;
        assert_eq!(snapshot(&f.replica).await, before);
        for (scope, report) in &expected {
            if report.checkpoint.is_some() {
                assert_eq!(
                    report.checkpoint,
                    Some(f.replica.checkpoint(*scope).await.unwrap().id().unwrap())
                );
            }
        }
        let AuditFixture {
            replica,
            lineage,
            directory,
            node,
        } = f;
        drop(replica);
        let reopened = lineage
            .reopen(&directory.path().join("audit.db"), &node, 3, 3)
            .await
            .unwrap();
        assert_eq!(singles(&reopened, &scopes).await, expected);
        assert_eq!(reopened.audit_scopes(&scopes).await.unwrap(), expected);
    }
}
