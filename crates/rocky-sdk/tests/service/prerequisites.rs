use super::{fixture::*, inspection::*, *};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_voters_finalize_an_owner_seal_after_a_trusted_write() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let (bundle, _admin) = service(root.path()).await?;
    let (a, t) = household(root.path(), &bundle).await?;
    assert!(!t.write("main", 11).await?["committed"].is_null());
    a.sync().await?;
    assert_eq!(a.keys().await?, t.keys().await?);
    let tip = a.tips("status", json!({})).await?["tip"].clone();
    let before = head(&bundle, &root.path().join("t"), &t.scope, &tip).await?;
    let owner = a.call(json!({"type":"session"})).await?["node"].clone();
    assert!(
        !before
            .members
            .iter()
            .any(|member| member.key.to_hex() == owner)
    );
    let sealed = a.tips("seal", json!({})).await?["tip"].clone();
    final_on_both(&a, &t, &sealed).await?;
    assert_eq!(a.keys().await?, t.keys().await?);
    t.close().await?;
    a.close().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_voters_keep_branch_logs_separate_from_main() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let (bundle, _admin) = service(root.path()).await?;
    let (a, t) = household(root.path(), &bundle).await?;
    assert!(!t.write("before", 21).await?["committed"].is_null());
    a.sync().await?;
    let latest = a.tips("seal", json!({})).await?["tip"].clone();
    final_on_both(&a, &t, &latest).await?;
    assert!(!t.write("main only", 22).await?["committed"].is_null());
    let main = t.call(json!({"type":"coordinated"})).await?;
    let main_rows = t.keys().await?;
    let main_head = head(&bundle, &root.path().join("t"), &t.scope, &main["tip"]).await?;
    let dev = a
        .tips("open", json!({"seal":latest,"minimum_in_sync":1}))
        .await?["tip"]
        .clone();
    a.tips("create", json!({"name":"dev","tip":dev})).await?;
    t.sync().await?;
    t.tips("pull", json!({"seal":latest})).await?;
    t.sync().await?;
    t.tips("follow", json!({"name":"dev"})).await?;
    assert!(!t.write("dev only", 23).await?["committed"].is_null());
    let branch = t.call(json!({"type":"coordinated"})).await?;
    assert_eq!(branch["tip"], dev);
    assert_ne!(branch["tip"], main["tip"]);
    t.tips("follow", json!({"name":"main"})).await?;
    assert_eq!(t.call(json!({"type":"coordinated"})).await?, main);
    assert_eq!(t.keys().await?, main_rows);
    let after = head(&bundle, &root.path().join("t"), &t.scope, &main["tip"]).await?;
    assert_eq!(
        (after.head, after.commit, after.running_hash, after.terminal),
        (
            main_head.head,
            main_head.commit,
            main_head.running_hash,
            main_head.terminal
        )
    );
    t.close().await?;
    a.close().await?;
    Ok(())
}
