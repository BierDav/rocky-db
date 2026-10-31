use rocky_sdk::{Affinity, Column, Configuration, Failure, Schema, Table, params};

#[tokio::main]
async fn main() -> Result<(), Failure> {
    let schema = Schema::builder("notes", 1)
        .table(
            Table::replayed("notes")
                .column(Column::new("body", Affinity::Text).required())
                .column(
                    Column::new("done", Affinity::Integer)
                        .required()
                        .default(false),
                ),
        )
        .build()?;
    // Use `open()` on subsequent runs; create refuses to overwrite an installation.
    let directory = std::env::args()
        .skip(1)
        .find(|arg| arg != "--create")
        .unwrap_or_else(|| "local/notes".into());
    let configuration = Configuration::new(directory, &schema)?;
    let opened = if std::env::args().any(|arg| arg == "--create") {
        configuration.create().await?
    } else {
        configuration.open().await?
    };
    let database = opened.database;
    let changes = database.observe_tables(Some(vec!["notes".into()])).await?;
    let mut transaction = database.transaction().await?;
    let id = transaction.next_id("notes", vec![]).await?;
    transaction
        .execute(
            "INSERT INTO notes(id,body,done) VALUES(?,?,?)",
            params![id, "Try Rocky from Rust", false],
        )
        .await?;
    transaction.commit().await?;
    println!("Committed changes: {:?}", changes.next().await?);
    let mut rows = database
        .query("SELECT id,body,done FROM notes ORDER BY id", params![])
        .await?;
    while let Some(row) = rows.next().await? {
        println!(
            "{}: {} (done: {})",
            row.get::<i64>("id")?,
            row.get::<String>("body")?,
            row.get::<bool>("done")?
        );
    }
    drop(rows);
    database.close().await
}
