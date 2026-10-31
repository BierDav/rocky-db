//! Application-confirmed removal before an issuer changes its installation.
use crate::{Failure, enrollment::Settings, schema::Schema};
use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A removed table or `table.field`, and the number of live stored local rows
/// affected (including NULL fields). Counts never describe other devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemovalImpact {
    pub name: String,
    pub rows: u64,
}
/// The complete report an application confirms by its digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutImpact {
    pub domain: String,
    pub installed_manifest: String,
    pub target_schema: String,
    pub tables: Vec<RemovalImpact>,
    pub fields: Vec<RemovalImpact>,
    pub digest: String,
}
/// Opening stopped before signing or changing data. A stale confirmation
/// returns the current report with `mismatch` set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RolloutConfirmationRequired {
    pub report: RolloutImpact,
    pub mismatch: bool,
}
impl std::fmt::Display for RolloutConfirmationRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.mismatch {
            "removal confirmation does not match the current impact report"
        } else {
            "removal requires application confirmation of the impact report"
        })
    }
}
impl std::error::Error for RolloutConfirmationRequired {}

pub(crate) async fn confirm(
    settings: &Settings,
    path: &Path,
    schema: &Schema,
    digest: Option<&str>,
) -> Result<(), Failure> {
    if !settings.issuer() || settings.application(schema)? != crate::DeclaredSchema::Ahead {
        return Ok(());
    }
    let (current, target) = (
        settings.domain()?.logical().clone(),
        crate::domain::logical(schema, *settings.publisher.as_bytes())?,
    );
    rocky_core::classify(&current, &target).map_err(|refusal| {
        format!("the application schema cannot replace the installed one: {refusal}")
    })?;
    let removed = rocky_core::removed(&current, &target);
    // Grants issued before would silently change meaning. An entry goes
    // with its table, or with the table it followed.
    let kept = |name: &str| schema.tables.iter().any(|table| table.name == name);
    let (installed, declared) = (settings.schema.granted_like(), schema.granted_like());
    if let Some(table) = settings.schema.tables.iter().find(|table| {
        let (before, after) = (installed.get(&table.name), declared.get(&table.name));
        kept(&table.name)
            && before != after
            && !(after.is_none() && before.is_some_and(|like| !kept(like)))
    }) {
        return Err(format!(
            "the application schema cannot replace the installed one: {} changed whom it is granted like; declare that only when adding a table",
            table.name
        )
        .into());
    }
    if removed.is_empty() {
        return Ok(());
    }
    let names: Vec<&str> = current
        .typed()
        .map(|table| table.sql_name.as_str())
        .collect();
    let counts =
        rocky_secure::local_row_counts(&path.with_file_name("rocky.sqlite"), &names).await?;
    let mut report = RolloutImpact {
        domain: HEXLOWER.encode(&settings.domain.0),
        installed_manifest: HEXLOWER.encode(&settings.domain()?.manifest().hash()),
        target_schema: HEXLOWER.encode(&rocky_core::commitment(
            "rocky.sdk.rollout-schema.v1",
            &serde_json::to_vec(schema)?,
        )),
        tables: removed
            .tables
            .iter()
            .map(|name| {
                Ok(RemovalImpact {
                    name: name.clone(),
                    rows: *counts.get(name).ok_or("removed table lacks its scope")?,
                })
            })
            .collect::<Result<_, Failure>>()?,
        fields: removed
            .fields
            .iter()
            .map(|name| {
                let table = name
                    .split_once('.')
                    .map(|(table, _)| table)
                    .ok_or("removed field lacks its table")?;
                Ok(RemovalImpact {
                    name: name.clone(),
                    rows: *counts
                        .get(table)
                        .ok_or("removed field lacks its table scope")?,
                })
            })
            .collect::<Result<_, Failure>>()?,
        digest: String::new(),
    };
    report.digest = HEXLOWER.encode(&rocky_core::commitment(
        "rocky.sdk.rollout-impact.v1",
        &serde_json::to_vec(&report)?,
    ));
    if digest == Some(report.digest.as_str()) {
        Ok(())
    } else {
        Err(RolloutConfirmationRequired {
            report,
            mismatch: digest.is_some(),
        }
        .into())
    }
}
