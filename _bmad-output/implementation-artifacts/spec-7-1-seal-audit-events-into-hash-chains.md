---
title: 'Story 7.1: Seal audit events into hash chains'
type: 'feature'
created: '2026-11-02'
status: 'done'
baseline_commit: 'b6d501e4f54f58b3ee564b74318318fad63464f9'
baseline_revision: 'b6d501e4f54f58b3ee564b74318318fad63464f9'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-7-context.md'
  - '{project-root}/docs/threat-model.md'
warnings: []
deferred:
  - summary: >-
      A chain whose every sealed row is deleted restarts at seq 1 with no prev_hash.
    evidence: |-
      The sealer takes its head from the highest sealed row. If retention deletes a whole chain, head included, before its checkpoint event is sealed, the next pass seals a new genesis that silently forks from the shipped history. Retention doesn't exist yet: Story 7.3 must keep a head (the checkpoint, or a durable head record) whenever it deletes a range.
    location: >-
      src/Modules/Audit/Core/AuditSealer.cs
    severity: medium
  - summary: >-
      A seal pass costs one transaction per Tenant, so with many Tenants it can outlast the 5-second target.
    evidence: |-
      AuditSealLoop lists every tenant row and opens a TenantScope for each, about once a second, even when nothing is unsealed. Unverified whether v1 deployments reach the Tenant count where this matters; settle it with a pass-duration measurement against Tenant count, and add the AD-16 60-second lag report (alerts story).
    location: >-
      src/Modules/Operations/Core/AuditSealLoop.cs
    severity: medium (unverified)
---

<intent-contract>

## Intent

**Problem:** Audit events are written but never sealed, so a changed or missing row can't be detected (FR-40, AR-27, AD-16, T-31).

**Approach:** Add an `epoch` seal column, an Audit sealer that seals one chain's unsealed events in ID order with `hash = SHA-256(prev_hash || RFC 8785 envelope)`, and an Operations sealer loop that `Host.Worker` runs under `gk_sealer` about once a second over every Tenant chain and the Deployment chain.

## Boundaries & Constraints

**Always:**
- Writers take no lock and read no chain head. Only the sealer touches seal columns, under `pg_advisory_xact_lock` on the chain, so two sealers can't fork a chain.
- One chain per Tenant (`audit_event`, sealed in that Tenant's `TenantScope`) and one Deployment chain (`deployment_audit_event`, in a `DeploymentScope`).
- `seq` starts at 1 per chain and rises by 1. The genesis row (`seq = 1`) has a null `prev_hash`, and its hash is over the envelope alone. Every other row's `prev_hash` is the previous row's `hash`.
- `epoch` is the previous sealed row's, or 1 for genesis. The canonical envelope and hash code live in Audit Core so Story 7.3's verify reuses them.
- The database still refuses any change to a sealed envelope, from every role, including `gk_sealer`.

**Never:**
- No verify command, retention, checkpoint, off-server shipping, alert enqueue or heartbeat (Stories 7.2, 7.3 and the alerts story).
- No restore or new-epoch logic (Epic 12). No change to `IAuditAppender` or to how writers insert.
- No third-party JSON canonicalisation package.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| First seal | 3 unsealed Tenant events | `seq` 1..3, `epoch` 1, genesis `prev_hash` null, each hash recomputes from the envelope | N/A |
| Later seal | Chain sealed to `seq` 3, 2 new events | `seq` 4, 5, `prev_hash` of 4 = hash of 3 | N/A |
| Two Tenants and Deployment | Events in each | Three independent chains, each from `seq` 1 | N/A |
| Concurrent sealers | Two passes on one chain at once | One chain, no gap, no duplicate `seq` | Second waits on the lock |
| Writers during a seal | Seal transaction open, 50 parallel appends | All appends commit before the seal ends | N/A |
| Nothing to seal | No unsealed rows | No update, no error | N/A |
| Change after seal | Any role updates any column of a sealed row | Refused | Trigger error |
| Epoch on insert or partial | `epoch` set on insert, or seal without `epoch` | Refused | Trigger error or `23514` |
| Canonical JSON | Keys out of order, control characters, non-ASCII | RFC 8785 output: sorted keys, no whitespace, minimal escaping | N/A |

</intent-contract>

## Code Map

- `src/Adapters/Postgres/Migrations/Migration20261102010000CreateAuditTables.cs` -- the existing tables, triggers and grants. `audit_guard_update` strips `seq, prev_hash, hash` from `to_jsonb`, and `audit_guard_insert` refuses those columns, so both must learn `epoch`.
- `src/Adapters/Postgres/Migrations/` -- add `Migration20261102070000SealAuditChains.cs`, same hand-written-SQL pattern, forward-only `Down`.
- `src/Adapters/Postgres/Schema/TableRegistry.cs:51` -- `SealColumns` gains `epoch`. `tenant` grants `gk_sealer` `SELECT` so the loop can list chains. The catalogue test compares the registry to the database.
- `src/Modules/Audit/Adapters/AuditAppender.cs` -- writer path, unchanged. Its IDs are UUIDv7, so ID order is time order.
- `src/Modules/Audit/Contracts/AuditContract.cs` -- add `CreateSealer()`. `src/Modules/Audit/Core/AuditCore.cs` is a placeholder to replace.
- `src/Modules/Operations/Core/JobScheduleRunner.cs` -- pattern for a loop over an `NpgsqlDataSource` with a logger. `OperationsContract.cs` -- factory pattern.
- `src/Gatekeep.Host.Worker/WorkerJobs.cs` -- `WorkerSettings.Sealer` connection exists. Add a hosted service beside `JobScheduleService`.
- `src/Gatekeep.Kernel/Persistence/TenantScope.cs`, `DeploymentScope.cs` -- one transaction per chain. `CommandScope` has `CommitAsync` and a `Context`.
- `tests/Isolation/AuditTests.cs:336-440` -- seal tests use `SET seq = 1, hash = ...`; they need `epoch = 1` once the pairing `CHECK` lands. Helpers `RunScopedAsync`, `SealAsync`, `TextAsync`.
- `tests/Isolation/Jobs/WorkerStartupTests.cs:43` -- real `Host.Worker` process test pattern with `Configured(database)` and a polling deadline.
- `tests/Isolation/PostgresFixture.cs` -- `NewMigratedDatabaseAsync`, `RoleConnection`, `SuperuserConnection`, `ScalarAsync`.
- `docs/threat-model.md:239` -- T-31 says sealing isn't built.

## Tasks & Acceptance

**Execution:**
- [x] `src/Adapters/Postgres/Migrations/Migration20261102070000SealAuditChains.cs` -- add nullable `epoch bigint` to both event tables, `CHECK ((seq IS NULL) = (epoch IS NULL))`, `CHECK (seq IS NULL OR (seq >= 1 AND epoch >= 1 AND (seq = 1) = (prev_hash IS NULL)))`, a partial index on unsealed rows by ID, `CREATE OR REPLACE` both guards to include `epoch`, `GRANT UPDATE (epoch)` and `GRANT SELECT ON tenant` to `gk_sealer` -- AD-16 seal columns.
- [x] `src/Adapters/Postgres/Schema/TableRegistry.cs` -- match the new grants.
- [x] `src/Modules/Audit/Core/CanonicalJson.cs` -- RFC 8785 writer for objects of string, integer and null values -- AD-16 canonical form.
- [x] `src/Modules/Audit/Core/ChainHash.cs` -- builds the envelope `{actor_id, actor_kind, epoch, id, occurred_at, seq, target_id, target_kind, tenant_id, type_code}` (UUIDs lower-case, time as `yyyy-MM-ddTHH:mm:ss.ffffffZ` UTC, `tenant_id` null on the Deployment chain) and computes the hash.
- [x] `src/Modules/Audit/Core/AuditSealer.cs`, `Contracts/IAuditSealer.cs`, `AuditContract.cs` -- `SealAsync(CommandContext, int maxEvents, CancellationToken)` takes the chain lock, reads the head, seals up to `maxEvents` unsealed rows in ID order, and returns the count.
- [x] `src/Modules/Operations/Core/AuditSealLoop.cs`, `Contracts/OperationsContract.cs` -- `CreateSealLoop(sealerDatabase, interval, logger)`: each pass seals the Deployment chain, then each Tenant from `tenant`, one scope each, logging failures by Tenant ID and continuing.
- [x] `src/Gatekeep.Host.Worker/WorkerJobs.cs` -- register the loop with a 1-second interval as a hosted service.
- [x] `tests/Isolation/Audit/CanonicalJsonTests.cs`, `SealerTests.cs` -- cover the matrix, recomputing every hash in C# from rows read back.
- [x] `tests/Isolation/AuditTests.cs`, `Jobs/WorkerStartupTests.cs` -- add `epoch` to existing seal statements, and add a test that a configured `Host.Worker` seals an appended event within 5 seconds.
- [x] `docs/threat-model.md` -- T-31 and TB-6: sealing built, with test names. The remaining gaps are verify, shipping and lag alerts.

**Acceptance Criteria:**
- Given a running `Host.Worker` and one appended Tenant event, when 5 seconds pass, then the row has `epoch`, `seq`, `hash`, and the hash matches a recomputation.
- Given the migrated database, when the catalogue test runs, then it matches the registry with `gk_sealer` updating only `epoch, seq, prev_hash, hash`.
- Given `gk_sealer` and a sealed row, when it updates `epoch`, `seq`, `hash` or any envelope column, then the database refuses it.

## Spec Change Log

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 30 findings — high 0, medium 3, low 16, false 6, maybe-false 5
- findings:
  - `[false]` `[reject]` Blind: epoch can't work with the epoch-blind unique keys and the genesis CHECK — `seq` continues across epochs, so a new epoch's first row links to the restored head and isn't a genesis; the head query by `seq` stays right. Epic 12 owns the epoch record.
  - `[false]` `[reject]` Blind: migration has no backfill for rows sealed before this story — no sealer existed before Story 7.1, so no production database holds a sealed row.
  - `[low]` `[reject]` Blind: no CHECK pins hash width to 32 bytes — a compromised `gk_sealer` can write a wrong 32-byte hash as easily, verify (7.3) detects both, and the fix rewrites many seal tests.
  - `[low]` `[reject]` Blind: the database doesn't enforce chain linkage — by design AD-16 puts linking in the sealer and detection in verify; T-31 records that nothing checks a chain yet.
  - `[low]` `[reject]` Blind: the sealer doesn't recompute the head hash before extending it — verify in Story 7.3 is the check; a partial check adds a second verifier.
  - `[low]` `[patch]` Blind: concurrency relies on READ COMMITTED, which nothing states — a stricter level fails loudly on the unique key, never forks; both doc comments now state the requirement.
  - `[maybe-false]` `[defer]` Blind: pass cost grows with Tenant count — deferred as medium (unverified); a pass-duration measurement against Tenant count settles it.
  - `[low]` `[reject]` Blind: a failing chain logs every pass with no backoff or health signal — seal-lag alerts and the heartbeat belong to the alerts story (AD-17).
  - `[low]` `[patch]` Blind: `gk_sealer` reads every `tenant` column — now a `SELECT (id)` column grant in the migration and registry.
  - `[low]` `[patch]` Blind: hash-change theory covers 3 of 10 members — now all ten, including `tenant_id`.
  - `[low]` `[reject]` Blind: no test seals an event with detail — the envelope is built only from event columns, so detail can't reach the hash; the detail update guard is unchanged in role order.
  - `[low]` `[patch]` Blind: loop failure paths untested and the wrong-role test accepts any `InvalidOperationException` — exact `WrongJobRoleException` asserted; failure tests added with the gap rows below.
  - `[low]` `[reject]` Blind: canonical helpers are public mainly for tests — Story 7.3's verify needs `CanonicalEnvelope` and `ChainHashOf` from outside Audit Core.
  - `[low]` `[reject]` Blind: `hashtext` lock keys can collide — a collision only makes two chains take turns, and can't fork either.
  - `[low]` `[patch]` Blind: Worker test waits on the job runner's start line and the loop logs no start — loop logs "Audit seal loop started." and the test times from it.
  - `[low]` `[reject]` Edge: a stuck lock holder blocks the pass — only sealers take the lock, in short transactions; a hung one is a bug that statement timeouts would surface.
  - `[low]` `[patch]` Edge: stale head under REPEATABLE READ — same fix as the Blind isolation row.
  - `[maybe-false]` `[defer]` Edge: retention deleting a whole chain restarts it at seq 1 — retention isn't built; recorded in `deferred` for Story 7.3.
  - `[low]` `[reject]` Edge: `ListTenantsAsync` failing discards the pass's count — only the returned count is lost; the rows stay sealed and the failure is logged.
  - `[false]` `[reject]` Edge: concurrent `PassAsync` calls race on `_roleChecked` — only `RunAsync` calls it in production, one at a time.
  - `[maybe-false]` `[defer]` Edge: the threat model's "no gap" claim may not survive retention — same root as the retention row; deferred with it.
  - `[low]` `[patch]` Edge: fresh-snapshot claim holds only at READ COMMITTED — same fix as the Blind isolation row.
  - `[medium]` `[patch]` Gap: a broken Deployment chain stopping every Tenant chain would go unnoticed — `Loop_logs_a_failing_Deployment_chain_and_seals_the_Tenants` added.
  - `[medium]` `[patch]` Gap: nothing shows the loop survives a failed pass — `Loop_logs_a_failed_pass_and_keeps_sealing` added.
  - `[maybe-false]` `[defer]` Intent: 5-second target tested with one event, not under load — same root as the pass-cost row; deferred with it.
  - `[false]` `[reject]` Intent: RFC 8785 is implemented for a subset of value types — the envelope holds only strings, integers and null, and other types are refused loudly.
  - `[medium]` `[patch]` Intent: "any role" is tested for three roles on one table — every runtime role but the sealer, plus `gk_migrator`, now runs against both tables.
  - `[false]` `[reject]` Intent: the flood is a 50-append stand-in — no sign-in path exists yet, and the guarantee is structural: the append path takes no lock and reads no head.
  - `[false]` `[reject]` Intent: nothing detects a change yet — the epic places verify in Story 7.3 and shipping in 7.2; T-31 says so.
  - `[maybe-false]` `[defer]` Intent: epoch is always 1 — new epochs belong to restore in Epic 12; the deferred retention row covers the only nearer risk.

## Design Notes

- Hash input is `prev_hash` bytes (none at genesis) followed by the UTF-8 canonical envelope. `seq` and `epoch` are inside the envelope, so a moved or renumbered row breaks the hash.
- Sealing order is the order in which the sealer finds rows. A writer that commits late with an older ID is sealed at the next pass, after newer rows. `occurred_at` keeps the true time.
- Listing chains reads `tenant` under `gk_sealer`. One transaction per Tenant per pass is fine at v1 scale. Each chain's pass seals at most 500 rows, so a flood drains over several passes.
- AD-17 enqueues alerts in the same transaction. `SealAsync` runs on the caller's context so the alerts story can add that without changing the sealer.

## Verification

**Commands:**
- `dotnet restore Gatekeep.slnx --locked-mode` -- expected: succeeds.
- `dotnet build Gatekeep.slnx --no-restore` -- expected: no warnings.
- `dotnet test tests/Architecture --no-build` -- expected: all pass.
- `dotnet test tests/Isolation --no-build` -- expected: all pass on `postgres:18.6`.
- `dotnet run --project tests/Architecture/Generator` -- expected: no diff.

## Auto Run Result

Status: done

**Summary:** audit events are now sealed into hash chains. A migration adds the `epoch` seal column, chain-shape CHECKs and an unsealed index. The Audit sealer seals one chain under an advisory lock with `hash = SHA-256(prev_hash || RFC 8785 envelope)`, and an Operations seal loop in `Host.Worker` runs it as `gk_sealer` about once a second over the Deployment chain and every Tenant chain.

**Files:**
- `src/Adapters/Postgres/Migrations/Migration20261102070000SealAuditChains.cs` -- `epoch`, CHECKs, index, guards that know `epoch`, sealer grants (`UPDATE (epoch)`, `SELECT (id) ON tenant`).
- `src/Adapters/Postgres/Schema/TableRegistry.cs` -- the matching grants.
- `src/Modules/Audit/Core/CanonicalJson.cs`, `ChainHash.cs`, `AuditSealer.cs` -- RFC 8785 writer, envelope and hash, the sealer.
- `src/Modules/Audit/Contracts/IAuditSealer.cs`, `ChainEnvelope.cs`, `AuditContract.cs` -- the public seal and hash surface Story 7.3 reuses.
- `src/Modules/Operations/Core/AuditSealLoop.cs`, `Contracts/IAuditSealLoop.cs`, `OperationsContract.cs` -- the loop.
- `src/Gatekeep.Host.Worker/WorkerJobs.cs` -- `AuditSealService`, 1-second interval.
- `tests/Isolation/Audit/*`, `AuditTests.cs`, `Jobs/WorkerStartupTests.cs`, `MigrateCommandTests.cs`, `TenantBehaviourTests.cs` -- matrix coverage and updated existing tests.
- `docs/threat-model.md` -- status line, TB-6 and T-31.

**Review:** 30 findings across four layers: 10 patched (8 fixes), 4 deferred into 2 frontmatter items, 16 rejected, each with its reason in the triage log.

**Follow-up review:** not recommended. No high was patched, and the three patched mediums are added tests that ran and passed, so no unverified risk can be named.

**Verification:** in the repo test image (`deploy/docker/tests.Dockerfile`, tagged `gatekeep/tests:epic7`): locked restore, build with 0 warnings, Architecture 275 of 275, Isolation 1010 of 1010 on `postgres:18.6`. One earlier run lost a single test to an IPv6 "network unreachable" while cloning a database, before any story code ran; the rerun passed. The diagram generator output differs only in line endings.

**Residual risks:** nothing checks a chain until Stories 7.2 and 7.3, so a superuser or `gk_migrator` that drops the triggers can rewrite a sealed row and recompute later hashes undetected. Pass cost grows with Tenant count (deferred). Retention must never delete a chain's head (deferred to 7.3). No seal-lag alert or heartbeat yet.
