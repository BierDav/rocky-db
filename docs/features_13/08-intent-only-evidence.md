# 8. Intent only: evidence

Work on change `lpknkqrl` (parent `1b5ce604`, phase 7), macOS on an Apple M5
Pro (18 cores), 2026-10-31.

## Baseline

`rocky-secure` non-test source lines: every `*.rs` under
`crates/rocky-secure/src` except `tests.rs` files and `tests/` directories.

| Revision | Lines |
| --- | --- |
| features_13 start (`msuzknoo`, `469fc97e`, "plan features_13 replayed intents") | 62,627 |
| phase 8 start (`yonmmlnr`, `1b5ce604`) | 70,561 |

The gate needs at most 60,127 lines: 10,434 fewer than at phase start, since
phases 4–7 added 7,934.

## Resolved questions

The brief was written against the README's model, where replayed rows keep
row records with creation proofs and can move. The code differs: phase 5 made
replayed tables keep no row record (`secure_rows` holds none of their rows),
and replay refuses writes to partition columns. These decisions follow.

- **Typed tables have one replicated class.** `TableClass` is `Replayed` or
  `LocalOnly`. The name stays: it reads clearly against `LocalOnly`.
- **The generic row-frame contract stays.** `EncryptedReplica<A:
  RowApplication>` still admits row frames of applications that are not SQL
  schemas (`employees-app`, most `rocky-secure` suites). Those frames converge
  only through per-field registers, and the subsystems the brief keeps (moves,
  creation proofs, row-record checkpoints, compaction) exist for them alone,
  since replayed tables have no row records. So `merge_row`'s stamp comparison
  and `Materialized::{stamps, authors}` remain for that contract; typed tables
  never author or accept row frames. Retiring the contract is a separate
  decision about those kept subsystems.
- **Everything only typed mergeable tables needed goes:** conflict policies,
  the constraint resolver and its support and virtual rows, existence logs
  (only an unpartitioned mergeable table could declare one), generation
  removal holds (removals were computed for mergeable tables only), the update
  policy, row authoring of migrations, and the SDK's trusted `TypedApp`
  registers with `SqlWrites`, which only that adapter implemented.
- **`granted_like` applies to replayed tables.** It selects grants, not merge
  behavior, and the shopping app's `item_categories` follows `items`.
- **Column class** `mergeable` is renamed `replicated`.
- **Formats.** `LOGICAL_SCHEMA_FORMAT` 5 → 6 refuses stored register
  descriptors at open; `ROW_FORMAT` 14 → 15 refuses register-era frames.
- **Rollout confirmation.** Removal confirmation now compares
  replicated tables and fields (`rocky_core::removed`) and counts projection
  rows (`local_row_counts(path, tables)`), since replayed tables keep no row
  records.
- **Deleted beyond the brief, by user decision (2026-10-31):**
  - rocky-runtime's trusted SQL write path: `SqlWrites`, SQL sessions,
    `Database` bindings and `rocky_bindings` (about 3,200 lines). The trusted
    profile refuses replayed tables, so nothing could reach it.
  - Coordinated tables and coordinated writes ("stitching the database and
    coordination together happens in the application layer"): the
    `coordinated` table flag, write entries, carries, abandoned entries,
    `network/entries.rs`, `rocky-credentials` carries. Coordinated logs stay
    only for seal terminals, seal finality, recovery seals and openings.
    Shopping app approvals are ordinary writes now.
  - The phase 3 shapes classifier (`shapes.rs`, `intent-shapes` features,
    `scripts/intent-shapes`): it classified only mergeable tables.
  - The fan-out exception (`WorkUnit::DependentRow`, `dependent_fanout_us`).
  - Trusted-profile SDK suites `tests/{sql,typed,queries,domains}.rs` and their
    descriptor fixtures, which ran on the deleted `TypedApp`.

## Handover (2026-10-31)

Slice 2 is partly done; slices 3–6 are not started except the `compact_to`
fix. Nothing is committed: all work is in jj change `lpknkqrl`.

Builds: `cargo check --workspace --all-targets` and
`cargo check --manifest-path sdks/uniffi/Cargo.toml --all-targets` pass.
rocky-core, rocky-credentials, rocky-storage and rocky-runtime tests pass.
`./scripts/lint` and `./scripts/check` were not run.

`rocky-secure` non-test lines: 60,467 (gate ≤ 60,127).

`cargo nextest run -p rocky-secure`: 571 run, 366 pass, 199 fail, 6 time out.
Failure causes, by first panic:

- Fixtures still declaring `"class":"mergeable"`, `existence_log` or
  `on_conflict` (about 35): `tests/partitions.rs` (`build_with` defaults to
  `"mergeable"`), `tests/group_sync_measurement/fixture.rs` (used by
  `network::holdings::tests`), others. Switch to `replayed` and drop the
  register-only assertions; delete tests of register semantics (latest wins,
  equal stamps, conflict policies).
- Rebuilds from row records empty replayed tables (19, "projection differs
  from full rebuild"): `typed.rs` `reproject` through `rebuild_rows`,
  `rebuild_tip_workspace`, audits (`compaction/oracle.rs`), schema switches.
  This is slice 3's "replayed scopes never rebuild from records".
- Held intent frames refused ("held row change quota", 15):
  `replica/held/late.rs` `hold_members` requires row writes; a replayed intent
  frame held after a line closes is refused. Phase 4 says late transactions
  replay in the successor tip, so holding/relaying them must accept intent
  frames (or not hold them at all). Also breaks SDK migration tests.
- Tests asserting row records, row counts in checkpoints, births from row
  frames, pruning (`pruned > 0`) of typed scopes: compaction::*, bulk::*,
  kept::*, sql::*, author_payload, placements. Prune refuses replayed scopes
  (`checkpoint/prune.rs`) until slice 3 lands; either port these suites to
  `employees-app` (the generic row-frame contract still exists) or rewrite
  them for replayed semantics.
- "insert id must continue the device's own table creation log"
  (`tests/sql/catch_up.rs`), "intent statements" quota 256
  (`compaction/partial_reads.rs`, `sql/compact.rs`, `tip_schemas.rs`):
  fixtures inserting more than 256 statements per transaction or allocating
  ids by hand.
- Timeouts: replayed convergence schedules and two `roles` tests; check
  whether they are slow-tier tests or real hangs.

rocky-sdk tests were not run in full; the coordinated agent saw sync and tip
switch tests lose rows (likely the rebuild-from-records bug) and `on_conflict`
fixtures.

Remaining work, in order:

1. Finish slice 2: the rocky-secure and rocky-sdk suites above, then Kotlin
   (`sdks/kotlin`: `TableClass.Mergeable`, `Conflict`/`onConflict`,
   `existenceLog`, `update_policy` in `SchemaBuilder.kt`, `Schema.kt`,
   `References.kt`, qualification `SchemaQualification.kt`,
   `packaged-jvm/Consumer.kt`, `examples/shoppinglist-app/qualification/src/
   {AppSchemas,Device}.kt`). `qualify_schema_builder.rs` no longer reads the
   `existence-hand` pair; drop it from the Kotlin qualification too.
   Publish the Kotlin SDK to Maven local before building the example.
2. Slice 3. A design that fits the code: represent a replayed partition's rows
   at the seal as `(row id, RowFields)` pairs (`TypedRows::fields`,
   `row_id`), so the existing page transfer and LtHash `Sets` carry them.
   Rows at seal = current partition rows with the undo of every applied
   member not covered by the seal reverted in reverse `(era, stamp)` order;
   `seal_replayed` deletes undo at sealing, so keep it until compaction passes
   the member. Carry `secure_replayed` drops and outcome records of covered
   members. A record-free rebuild clears the replayed scopes of the domain,
   recomputes eras from the path's finalized seals (`era = covering depth − 1`,
   open era otherwise) and replays the visible frames through `redo`.
   `compact_to` already marks the seal compacted inside the last scope's
   transaction (`tests/checkpoint.rs` asserts it).
3. Slices 4–6: SDK/Kotlin docs, line counts, desktop sync and phase 4
   statement budgets.

## Session 2 (2026-11-01)

Decisions:

- **The row-frame contract stays; its typed-table tests go** (user decision,
  2026-11-01). Suites that only checked row records, births, creation
  proofs or receipts of typed tables are deleted; suites whose subject still
  holds for replayed tables author through SQL intents instead
  (`tests/partitions.rs` `insert`, `group_sync_measurement::Fixture::insert`).
  The generic `RowApplication` contract keeps its own coverage
  (`employees-app`, `tip_schemas::employees`).
- **Record-free rebuild** (`replica/replay/rebuild.rs`, slice 3's rebuild
  item). `replay_from_frames` empties every replayed table and replays each
  visible applied intent member again in `(era, stamp)` order; a member's
  era is one below the first finalized seal whose `secure_seal_bounds`
  position covers it, else the open era, and covered members end sealed.
  `rebuild_rows` (`rebuild_projection`, voided rebuilds), tip workspace
  rebuilds (once, when a replayed transaction left the path) and schema
  switch withdrawal use it; the audit oracle compares the projection with
  it. `reproject` leaves a replayed scope as it is (its rows are the only
  copy); resets (`clear_typed`, rebootstrap and staging resets) use
  `reset_replayed`, which also forgets the scope's `secure_replayed` rows.
  A member keeps the admission `secure_replayed` recorded for it: an
  admitted one replays under the authority it was admitted with (its
  chain at its own time, without later revocations or expiry), an
  admission drop stays dropped (session 3). Limit: without slice 3's
  checkpoint rows a rebuild replays sealed members under the current
  schema; a frame-pruned scope cannot rebuild ("replayed history is
  pruned").
- **Held intent frames.** A frame of a closed line that carries an intent is
  held whole (status `held`, kept for relay and restoration) with no held
  change: there are no rows for the application to re-author. Held row
  validation against the source schema (`tip_schemas::source_validation`,
  `matching_source`) applies to row frames only; those typed-table tests
  are deleted. `frame_positions` skips frames without row images.
- **Outcome records in sync.** A replica with write rights publishes an
  outcome record for each multi-member transaction it replays, so the sync
  after a catch-up carries them; the ERP measurement expects one more
  non-idle sync.

## Session 3 (2026-11-01)

`cargo nextest run -p rocky-secure`: 205 failing at the handover, 84 at
the start of this session, 46 now. The remaining failures all need slice 3:
checkpoints of replayed scopes carry no rows (bootstraps, rebootstraps,
direct imports, audits against a checkpoint, `pruned > 0`), and tip
switches past a kept seal or sideways cannot restore a replayed table's
rows at a seal. Six more time out only under the full run's load: the
partition convergence schedules pass in 8–12 s alone, and `roles::*` and
`composite_many_to_many_graph_converges_in_all_720_orders` are e2e-tier.

Decisions:

- **Projection plans switch in one transaction.** Shadow tables filled
  from row records, which replayed tables have none of, so their fill and
  verification did nothing and the switch rebuilt the tables from the
  installed rows anyway. Deleted: shadow tables (`Typed::shadow`,
  `workspace.shadow`, `secure_shadow_*`), `fill`, `verify_shadow`,
  `restart_plan`, `PLAN_ROWS`, `PlanStage::{Create, Fill}` and the plan's
  `position`/`cursor` columns. A recorded plan switches at once and an
  interrupted one finishes when the replica opens. `ProjectionPlan` and the
  SDK's `RebuildProgress` lose `filled`. Local plans keep LocalOnly
  changes; replayed tables sign their indexes since phase 5, so the
  generations local-plan tests add an indexed LocalOnly table instead.
- **Rebuild admission** (see Session 2's record-free rebuild): sealed
  members of a revoked author, and migration members whose writer was
  revoked, broke the audit oracle when replayed under current authority.
- **Deleted typed-table tests** whose subject was row frames, births or
  register incarnations: `author_payload.rs` (replaced by
  `failed_commit.rs`, the same failed-commit/retry contract for an intent),
  `tip_schemas/incarnations.rs`, the row-authoring migration races in
  `tip_schemas/staging.rs` (the preflight race test stays), the forged
  row-frame reuse in `sql::failed_identity_commit_…` and the
  `AUTHOR_PAYLOAD_TRACE`/`BINDING_TRACE` instrumentation only they read.
- **Rewritten for intents:** `sql::catch_up` authors through SQL;
  transactions above the 256-statement intent quota split (`tip_schemas`,
  `partial_reads`, `kept`); bulk migration fixtures that need two frames
  write both tables, and `bulk::fixture::frames` keeps migration frames
  only, since replicas now also publish outcome records.
- **Late intent frames of a closed line are held, not replayed in the
  successor.** The brief replaces held re-authoring with late
  transactions replaying in the successor tip; Session 2 stopped short of
  that, and `held_frame_page` serves only frames with a held change, so a
  held intent frame is not relayed. Open; see remaining work.

- **Replayed checkpoints carry a separate replayed base** (user decision,
  2026-11-01): a replayed partition's rows at a seal are `(row id, typed
  values)` pairs with their own LtHash and page payload, not row records
  pushed through the row-record checkpoint pipeline (creation stubs,
  headers, births), which replayed rows have none of.
- **Order.** Slice 3 runs before the rocky-sdk triage: of the 78 rocky-sdk
  failures most are bootstraps, checkpoints and tip switches. Kotlin runs
  in parallel.

Remaining work, in order:

1. rocky-sdk suites, then Kotlin (Handover item 1).
2. Slice 3 (Handover item 2), which the 46 rocky-secure failures wait
   for; identity marks of replayed checkpoints too
   (`compaction::identities`, `sql::failed_identity_commit_…` no longer
   checks the signed identity sequence).
3. Late intent frames of a closed line replay in the successor tip, and
   held re-authoring (`replica/held*`) goes for typed tables.
4. Delete typed-table register paths left in `typed.rs` (`project`,
   `project_into`, `verify_sql_projection`, `reproject` for non-replayed
   scopes): every typed table is replayed.
5. Slices 4–6.

## Session 4 (2026-11-01)

`cargo nextest run -p rocky-secure`: 46 failing at the start of slice 3,
21 now (476 pass), plus the same six load-only timeouts. `rocky-secure`
non-test lines: 60,155 (59,146 before slice 3; gate ≤ 60,127). Dead
register code still to delete (`strip_rows`, the row-record paths of
schema switches, audits and staging) brings it back under.

Slice 3 so far:

- **Replayed base** (`replica/replay/base.rs`). `secure_replayed_seals` /
  `secure_replayed_seal_rows` keep a replayed scope's rows at each
  finalized, uncompacted seal: finalization rewinds every open member in a
  savepoint, reads the rows and rolls back. Compaction signs a statement
  whose rows are those images (LtHash label `rocky.replayed-row.v1`, no
  tombstones or creations, identities from the covered marks and replay
  births) and keeps them in `secure_replayed_base`. A base whose position
  and key epoch are unchanged is reused. Pages serve base images; staged
  imports keep them in `secure_replayed_staged` and check each page's
  signature, order and identities. `replay_from_frames` restores the base
  and replays only the members after its position. Revalidation that
  forgets a seal's depth rebuilds the scope from frames.
- **Images key values by field id**, not position, so a base outlives its
  seal's schema. Restoring one fills the current table's columns: a field
  it lacks, or one some tip between the seal's and the workspace's lacked,
  takes its default.
- **Replay births** are stored per member (`secure_replayed.births`) and
  folded into the covered identity marks a replayed checkpoint signs.
- **Audits of replayed scopes** compare the base with its statement
  (`verify_replayed_tail`) and the projection with a full rebuild.
- **Imports keep the frontier's stubs.** Later intents name the frontier's
  frames as their base; once a log advances past its pruned tip, only the
  stub proves the dependency. An intent naming an older head behind a
  base still waits for a dependency it cannot get, as it did before.

Decisions:

- **A replayed frame never changes a field missing on its path.** A field
  of the current schema that some tip between the frame's and the
  workspace's lacks keeps its value before the statement, or its default
  in an inserted row, and needs no grant. A rebuild therefore reaches the
  rows a schema switch left: a field added since keeps its default, one
  removed and added again comes back empty, and a late write from before
  the removal never fills it. A statement naming a column the current
  schema lacks still drops its transaction (`schema`): an old-tip
  `UPDATE … SET title=…, note=…` replayed after `note` was removed drops
  as a whole, where registers kept `title`.
  `a_schema_removes_a_field_and_a_table_…` now expects that.
- **Schema switches carry only path fields.** `rebuild_replayed` copies a
  column only if every tip on the switch's path has it, and a table
  removed on the path comes back empty; `reshape_undo` drops the undo
  entries of removed tables, which a rewind cannot restore.
- **Register assertions removed from switch tests:** row-record and
  checkpoint-row field scans and `secure_field_names` ids, which replayed
  tables never write.

Remaining rocky-secure failures (21):

- Kept seals and sideways switches (`kept::*` 5,
  `generations::sideways::*` 7, `readiness::a_kept_empty_scope_…`):
  `Served::Kept` is denied for replayed scopes and a kept seal has no
  replayed rows.
- Identities (`compaction::identities::*` 5): kept prefixes, and replay
  does not refuse a reused, retired identity after an import.
- `partial_reads::a_direct_import_shows_…`: replayed pages stage rows and
  show nothing until the import finishes.
- `bulk::checkpoint_headers_…` and `bulk::seal_pruning_…`: record-page
  header and pruning accounting.

Remaining work, in order: the failures above (kept seals first), rocky-sdk
(78 failing before slice 3), dead register code, late frames of a closed
line (Session 3), slices 4–6.
