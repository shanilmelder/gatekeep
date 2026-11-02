---
title: 'Story 1.8: Run Tenant-scoped jobs'
type: 'feature'
created: '2026-11-02'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/docs/threat-model.md'
warnings: [oversized]
deferred: []
---

<intent-contract>

## Intent

**Problem:** Background work has no path. AD-15 needs jobs that always carry an explicit Tenant or are explicitly Deployment-wide, can only be enqueued by the roles a code-owned registry lists, retry and stop as `dead`, and never keep a credential value after they finish.

**Approach:** Add `job` (control) and `job_payload` (tenant) with a check constraint and an insert trigger, a Kernel `IJobEnqueuer` port, an Operations job registry, runner and schedule, and wire the runner and schedule into `Host.Worker`.

## Boundaries & Constraints

**Always:**
- `job` CHECK: exactly one of `tenant_id` (FK `tenant`, `ON DELETE RESTRICT`) or `deployment_wide = true`. The insert trigger refuses a `tenant_id` that differs from `current_setting('gatekeep.tenant_id')` (unset raises, as elsewhere), refuses a Deployment-wide row while a Tenant is set, and refuses a `current_user` the registry doesn't list for the type.
- The registry is code in Operations: type code (`{domain}.{object}.{action}`), scope (Tenant or Deployment-wide), enqueuing roles, run-as role (`gk_worker`, `gk_sealer` or `gk_retention`), maximum attempts, whether it never goes `dead` (alert types), whether it may carry a credential, and for Deployment-wide types a recorded review (reviewer, date, reason). `gk_hosted` may enqueue only `notifications.*` types and `gk_sealer` only `alerts.*` types.
- The trigger's role check is generated SQL: one Operations function renders the guard from a registry, the migration holds the render of the production registry, and a test fails if the two differ. Tests render a test registry into their own database as `gk_migrator`.
- Enqueue runs in the caller's `CommandContext`. A Tenant job takes the Tenant from the context; a Deployment-wide job carries only an optional `operation_id` and no payload.
- `job_payload` holds IDs only, plus at most one Transit ciphertext under the Tenant's `payload` key when the type allows a credential. The runner deletes the payload row when a job succeeds, and nulls the ciphertext when it goes `dead`.
- The runner claims with `FOR UPDATE SKIP LOCKED` as `gk_dispatch`, which sees `job` only; `LISTEN/NOTIFY` wakes it, with a polling fallback. The body runs in its own `TenantScope` (or `DeploymentScope`) under the registry's run-as role. A claim expires, so a crashed run is claimed again (at-least-once).
- Failures back off exponentially. When attempts run out the job is `dead`, and the same transaction writes `operations.job.dead` with `Actor.System` through `IAuditAppender`. A never-dead type retries with capped backoff.
- Recurring work comes from a code-owned schedule in `Host.Worker` and is enqueued through `IJobEnqueuer`, so it runs through the same path. At most one pending or running job per scheduled type.
- Update `docs/threat-model.md` (TB-6, TB-8, T-26 and the payload rows) with the tests that prove them.

**Never:**
- No job type exists only for tests in the production registry.
- No error text, payload value or exception message stored in `job` or written to logs; a failure records an attempt count and a fixed reason code only.
- No Security Alert channel: `dead` writes the audit event only, and the threat model records alerting as open for the alerts story.
- No OpenBao wiring in `Host.Worker`; payload encryption and decryption go through `IKeyCustody`, faked in tests.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Neither or both | Insert with no `tenant_id` and `deployment_wide = false`, or both set | Refused | CHECK violation `23514` |
| Wrong Tenant | `TenantScope` for A inserts a job for B | Refused | Trigger raises `P0001` |
| Deployment-wide in a Tenant scope | `TenantScope` inserts a Deployment-wide job | Refused | Trigger raises `P0001` |
| Role not listed | Each runtime role enqueues each registry type | Listed roles succeed, others refused | `P0001` |
| Success | Tenant job whose handler succeeds | `done`; payload row gone | No error |
| Retries exhausted | Handler always fails, max 3 | 3 attempts with growing `run_after`, then `dead`; one `operations.job.dead` event, `system` Actor, in that Tenant's audit | Ciphertext nulled |
| Never-dead type | Alert-type handler always fails | Keeps retrying past max attempts, delay capped | Never `dead` |
| Credential payload | Type allows a credential, handler succeeds | Handler decrypts once; afterwards no ciphertext remains | — |
| IDs only | Type without credential given a credential | Refused before any insert | `ArgumentException` |
| Crash mid-run | Claim expires without finishing | Claimed again and run | At-least-once |
| Concurrent runners | Two runners, one pending job | Exactly one claims it | `SKIP LOCKED` |
| Schedule due | Due entry, no pending job of its type | One Deployment-wide job enqueued and run through the runner | Second tick enqueues nothing while one is pending |
| Unreviewed Deployment-wide type | Registry entry with no review | Architecture test fails | Build fails |

</intent-contract>

## Code Map

- `src/Adapters/Postgres/Schema/TableRegistry.cs:57-139` -- add `job` (Control, Operations) and `job_payload` (Tenant, Operations) with exact grants and `Triggers`. The registry generates no SQL: the migration must match it, and `tests/Isolation/CatalogueAudit.cs` compares both ways.
- `src/Adapters/Postgres/Migrations/Migration20261102010000CreateAuditTables.cs` -- pattern: one raw SQL `Up`, forward-only `Down`, RLS pair at :70-81 with the exact policy text, plpgsql trigger functions owned by `gk_migrator` with EXECUTE revoked from PUBLIC (:156-158), roles passed as trigger arguments (:132-147). New migration `20261102020000_CreateJobTables`.
- `CatalogueAudit.cs` rules: tenant tables need `tenant_id uuid NOT NULL` and the exact policies; control tables have no RLS; every FK `ON DELETE RESTRICT`; no `SECURITY DEFINER`, so the guard runs as invoker and reads `current_user`.
- `tests/Architecture/PersistenceRuleTests.cs` -- only `TenantScope.cs` and `ForEachTenant.cs` may call `set_config`; `[StateChanging]` methods take `CommandContext`; Contracts files can't name scopes or transactions; Kernel has no packages; module `Core/` and `Adapters/` declare no public top-level types.
- `src/Gatekeep.Kernel/Audit/IAuditAppender.cs:9-17`, `Actor.System`, `AuditTypeCode` -- `operations.job.dead` is valid. `AuditContract.CreateAppender()` picks the Tenant or Deployment audit table from `CommandContext.TenantId`.
- `src/Gatekeep.Kernel/Persistence/TenantScope.cs`, `DeploymentScope.cs`, `CommandScope.CreateCommandContext()/CommitAsync()`.
- `src/Gatekeep.Kernel/Secrets/IKeyCustody.cs`, `KeyName.ForTenant(TenantKeyClass.Payload, id)` -- payload key.
- `src/Modules/Operations/*` -- placeholders; references Audit already. Add `Npgsql` (centrally pinned) for `LISTEN`.
- `src/Gatekeep.Host.Worker/Program.cs` -- three lines today. Connection strings come from configuration (Story 1.10 supplies them); a missing one refuses startup naming only the setting. `tests/Isolation/HostLoggingTests` must keep passing.
- `tests/Architecture/module-edges.txt` -- add `dependency Tests.Isolation -> Operations` and `dependency Tests.Isolation -> Host.Worker` only if needed; regenerate the diagram.
- `tests/Isolation/AuditTests.cs:816-923` -- role data sources, scoped runs, expected `SqlState` helpers; `PostgresFixture.NewMigratedDatabaseAsync()`.
- `global.json` -- SDK 10.0.403 at `%LOCALAPPDATA%\Programs\dotnet-10.0.403` and Node 26.13.0 at `%LOCALAPPDATA%\Programs\node-v26.13.0-win-x64` first on `PATH` (pnpm shim in `C:\Users\esm\AppData\Local\Temp\claude\D--Projects-Personal-gatekeep\94ff8bc2-4a0e-49fa-a28e-6d3d0ecd048d\scratchpad\shims`), or `BuildEnforcementTests` fail.

## Tasks & Acceptance

**Execution:**
- [ ] `src/Gatekeep.Kernel/Jobs/IJobEnqueuer.cs`, `JobType.cs`, `JobPayload.cs` -- `[StateChanging] EnqueueAsync(CommandContext, JobType, JobPayload?, DateTimeOffset? runAfter, CancellationToken)` plus a Deployment-wide overload taking an optional `operationId`; `JobPayload` holds named IDs and an optional `Secret<byte[]>` credential.
- [ ] `src/Modules/Operations/Core/` -- registry types, the production registry (one Deployment-wide type, `operations.job.purge`, which deletes `done` jobs older than 30 days, with its review recorded as "Story 1.8 build review" and the reason), guard SQL renderer, enqueuer, runner (claim, run, back off, dead), schedule runner.
- [ ] `src/Modules/Operations/Contracts/OperationsContract.cs` -- factories for the enqueuer, runner and schedule runner, and the registry render for tests.
- [ ] `src/Adapters/Postgres/Migrations/Migration20261102020000CreateJobTables.cs`, `TableRegistry.cs` -- tables, CHECK, indexes, guard and notify triggers, grants.
- [ ] `src/Gatekeep.Host.Worker/Program.cs`, `JobSchedule.cs` -- code-owned schedule (purge daily) and hosted services for the runner and schedule.
- [ ] `tests/Isolation/Jobs/` -- every matrix row except the last, using a test registry and a fake `IKeyCustody`; a test that the migration's guard equals the production render; a role × type matrix against the production guard.
- [ ] `tests/Architecture/JobRegistryRuleTests.cs` -- Deployment-wide types need a review; `gk_hosted` only `notifications.*`, `gk_sealer` only `alerts.*`; type codes match the audit code pattern; run-as is one of the three roles.
- [ ] `docs/threat-model.md`, module diagram, edges -- record what is built and open.

**Acceptance Criteria:**
- Given `gk_dispatch`, when it reads `job_payload` or any tenant table, then permission is refused.
- Given a job body, when it runs, then it runs under the registry's run-as role in a scope for the job's own Tenant only.
- Given `Host.Worker` with its connection settings missing, when it starts, then it refuses, naming the setting and no value.

## Spec Change Log

## Review Triage Log

## Design Notes

- **Guard shape:** `job_guard_insert()` checks the Tenant, then `CASE NEW.type WHEN '...' THEN current_user::text = ANY (ARRAY[...])`, `ELSE` raise unknown type. The renderer escapes nothing it didn't validate: type codes and role names come from validated registry values.
- **Claim:** `UPDATE job SET status='running', attempts=attempts+1, locked_until=now()+lease WHERE id = (SELECT id FROM job WHERE (status='pending' AND run_after<=now()) OR (status='running' AND locked_until<now()) ORDER BY run_after FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING ...`.
- **Backoff:** `min(base * 2^(attempt-1), cap)`; defaults 10 s base, 1 h cap, 5 min cap for never-dead types.
- **Finishing:** the body commits in its own scope under its run-as role. Then one `gk_worker` scope for the job's Tenant (or the Deployment) finishes it: on success it marks `done` and deletes the payload row; on exhaustion it marks `dead`, nulls the ciphertext and appends `operations.job.dead`, so these commit together. `gk_worker` gets column `UPDATE` on `job` status and timing columns only. A crash between body and finish reruns the body, which is why handlers are idempotent. A retry (not exhausted) is a `gk_dispatch` update of `status` and `run_after`.

## Verification

**Commands:**
- `dotnet restore Gatekeep.slnx --locked-mode` -- expected: succeeds.
- `dotnet build Gatekeep.slnx --no-restore` -- expected: no warnings.
- `dotnet test tests/Architecture --no-build` -- expected: all pass.
- `dotnet test tests/Isolation --no-build` -- expected: all pass, including `Jobs`.
- `dotnet run --project tests/Architecture/Generator` -- expected: no diff after committing the diagram.
