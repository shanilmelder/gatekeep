---
title: 'Story 1.8: Run Tenant-scoped jobs'
type: 'feature'
created: '2026-11-02'
status: 'done'
baseline_revision: '13604f6cfad9fe85f7cb3b4bd0b9d07b8da5e676'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/docs/threat-model.md'
warnings: [oversized]
deferred:
  - summary: >-
      Concurrent schedule ticks are untested.
    evidence: |-
      Only sequential ticks are tested; one Worker runs per Deployment today.
    location: >-
      src/Modules/Operations/Core/JobScheduleRunner.cs
    severity: low
  - summary: >-
      Dead jobs are never purged, and RESTRICT keys then block Tenant deletion.
    evidence: |-
      operations.job.purge deletes only done rows. The Tenant deletion Operation must decide.
    location: >-
      src/Modules/Operations/Core/ProductionJobs.cs
    severity: medium
  - summary: >-
      operations.job.dead names no job.
    evidence: |-
      Audit targets have no job kind. G-17.
    location: >-
      src/Modules/Operations/Core/JobRunner.cs
    severity: medium
  - summary: >-
      A credential ciphertext lives across retries.
    evidence: |-
      The first credential type must bound attempts and backoff by its lifetime.
    location: >-
      src/Modules/Operations/Contracts/JobRegistry.cs
    severity: medium
  - summary: >-
      No lease heartbeat for long bodies.
    evidence: |-
      No body runs near the 5-minute lease yet.
    location: >-
      src/Modules/Operations/Core/JobRunner.cs
    severity: low
  - summary: >-
      job_payload has no guard on who attaches a payload.
    evidence: |-
      Enqueuing roles cannot read job, SECURITY DEFINER is banned. A payload on a done job also blocks the purge. Recorded under T-26.
    location: >-
      src/Adapters/Postgres/Migrations/Migration20261102020000CreateJobTables.cs
    severity: medium
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
- [x] `src/Gatekeep.Kernel/Jobs/IJobEnqueuer.cs`, `JobType.cs`, `JobPayload.cs` -- `[StateChanging] EnqueueAsync(CommandContext, JobType, JobPayload?, DateTimeOffset? runAfter, CancellationToken)` plus a Deployment-wide overload taking an optional `operationId`; `JobPayload` holds named IDs and an optional `Secret<byte[]>` credential.
- [x] `src/Modules/Operations/Core/` -- registry types, the production registry (one Deployment-wide type, `operations.job.purge`, which deletes `done` jobs older than 30 days, with its review recorded as "Story 1.8 build review" and the reason), guard SQL renderer, enqueuer, runner (claim, run, back off, dead), schedule runner.
- [x] `src/Modules/Operations/Contracts/OperationsContract.cs` -- factories for the enqueuer, runner and schedule runner, and the registry render for tests.
- [x] `src/Adapters/Postgres/Migrations/Migration20261102020000CreateJobTables.cs`, `TableRegistry.cs` -- tables, CHECK, indexes, guard and notify triggers, grants.
- [x] `src/Gatekeep.Host.Worker/Program.cs`, `JobSchedule.cs` -- code-owned schedule (purge daily) and hosted services for the runner and schedule.
- [x] `tests/Isolation/Jobs/` -- every matrix row except the last, using a test registry and a fake `IKeyCustody`; a test that the migration's guard equals the production render; a role × type matrix against the production guard.
- [x] `tests/Architecture/JobRegistryRuleTests.cs` -- Deployment-wide types need a review; `gk_hosted` only `notifications.*`, `gk_sealer` only `alerts.*`; type codes match the audit code pattern; run-as is one of the three roles.
- [x] `docs/threat-model.md`, module diagram, edges -- record what is built and open.

**Acceptance Criteria:**
- Given `gk_dispatch`, when it reads `job_payload` or any tenant table, then permission is refused.
- Given a job body, when it runs, then it runs under the registry's run-as role in a scope for the job's own Tenant only.
- Given `Host.Worker` with its connection settings missing, when it starts, then it refuses, naming the setting and no value.

## Spec Change Log

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 40 findings — high 0, medium 20, low 17, false 3, maybe-false 0
- findings:
  - `[medium]` `[patch]` Gap: the `timed_out` lease path never runs — test with a 1 s lease.
  - `[medium]` `[patch]` Gap: `unknown_type` and `lease_expired` are untested — one test each, including that a reclaim past the last attempt doesn't run the body.
  - `[medium]` `[patch]` Gap: `custody_failed` with no custody, as `Host.Worker` is wired, is untested — test added.
  - `[low]` `[patch]` Gap: a ciphertext on an IDs-only type is never shown to stay undecryptable at run time — test inserts one directly and checks no decrypt.
  - `[medium]` `[patch]` Gap: `RunAsync`, LISTEN and the notify trigger never run — test shows a notification wakes the runner before its poll, and cancel returns.
  - `[medium]` `[patch]` Gap: `Host.Worker` is tested only when refusing — configured start runs the purge to `done`.
  - `[low]` `[defer]` Gap: the schedule's advisory lock is never tested with two ticks at once — one Worker runs per Deployment and the purge is idempotent; close it when a second Worker or scheduled type appears.
  - `[low]` `[patch]` Gap: `JobPayload` and enqueuer refusals are untested — tests added.
  - `[medium]` `[patch]` Gap: a dead Deployment-wide job is untested — test checks one `system` event in `deployment_audit_event`.
  - `[medium]` `[patch]` Blind: the migration comment says to paste a new render into an applied, forward-only migration — a registry change now adds a new migration, and the test reads the latest rendered guard.
  - `[medium]` `[defer]` Blind: `dead` jobs are never purged, and `ON DELETE RESTRICT` then blocks deleting that Tenant — belongs to the Tenant deletion Operation, which must decide job retention.
  - `[medium]` `[patch]` Blind: a connection string for the wrong role is retried forever with nothing done — the role check now stops the host, and the schedule runner checks its role too.
  - `[low]` `[patch]` Blind: TB-6 omits `gk_worker`'s `DELETE` on `job` — stated.
  - `[medium]` `[patch]` Blind: several failure codes have no test — same fix as the Gap rows.
  - `[medium]` `[patch]` Blind: the Deployment-wide dead path is untested — same fix as the Gap row.
  - `[medium]` `[defer]` Blind: `operations.job.dead` names no job — audit targets have no job kind; G-17 records it with the missing alert.
  - `[low]` `[patch]` Blind: rules don't stop `gk_hosted` enqueuing a Deployment-wide type, or tie never-dead to `alerts.*` — both rules added.
  - `[false]` `[reject]` Blind: Operations references Npgsql directly — the spec chose this for `LISTEN`; the package is centrally pinned and the module owns its tables.
  - `[medium]` `[patch]` Blind: shutdown leaves a claim stuck for its lease and burns an attempt — the claim is returned on host cancellation; a heartbeat waits for a body that needs one.
  - `[low]` `[patch]` Blind: `job_payload.ids` isn't bounded in the schema — CHECK limits it to 16 keys.
  - `[low]` `[patch]` Blind: `dead`'s failure code commits apart from the mark, and the schedule lock uses the single-key space — set inside the finishing transaction; two-key lock with a fixed namespace.
  - `[medium]` `[defer]` Blind: a credential's ciphertext lives across retries, possibly past its own lifetime — no credential type exists yet; the first one (reset links) must bound its attempts and backoff by the credential's lifetime.
  - `[medium]` `[defer]` Intent: `job_payload` has no guard, so any role with insert can attach a payload to another job in its Tenant that has none; a payload on a `done` job also blocks the purge — the enqueuing roles can't read `job` and `SECURITY DEFINER` is banned, so the fix needs a design decision; handlers already re-check state and never trust the payload. Recorded under T-26.
  - `[low]` `[patch]` Intent: a ciphertext can be stored on an IDs-only type by direct insert — the runner never decrypts it; same test as the Gap row.
  - `[false]` `[reject]` Intent: the `gk_hosted` and `gk_sealer` limits live only in an architecture test — the spec says so, and the matrix row expects the architecture test to fail.
  - `[low]` `[reject]` Intent: `gk_dispatch` and `gk_retention` are refused by grants (`42501`), not the trigger (`P0001`) — a missing grant refuses earlier and more strongly; the test pins the split.
  - `[low]` `[reject]` Intent: only the schedule tick keeps one pending purge — the rule is the schedule's, and only `gk_worker` can enqueue the purge.
  - `[medium]` `[patch]` Intent: the running host is never tested — same fix as the Gap row.
  - `[low]` `[patch]` Intent: `failure_code` is written outside the finishing transaction — same fix as the Blind row.
  - `[low]` `[patch]` Intent: `gk_retention` as run-as is untested — added.
  - `[low]` `[reject]` Intent: "decrypts once" is the handler's count, not a runner limit — handlers decrypt at the moment of use, and AD-10 sets no count.
  - `[false]` `[reject]` Intent: the purge type is a scope addition — the spec names it.
  - `[low]` `[reject]` Edge: a finish that keeps failing reclaims forever — needs the audit append or payload delete to fail on every run, and a cap adds branches for an unshown state.
  - `[medium]` `[patch]` Edge: shutdown on the last attempt burns it — same fix as the Blind shutdown row.
  - `[medium]` `[defer]` Edge: a payload added to a `done` job blocks the purge on the RESTRICT key — same root as the `job_payload` guard row.
  - `[medium]` `[defer]` Edge: a dead job blocks Tenant deletion forever — same as the Blind dead-job row.
  - `[low]` `[patch]` Edge: an oversized ciphertext aborts the caller's transaction — `ArgumentException` before any insert.
  - `[low]` `[patch]` Edge: one failing schedule entry stops the later ones — each entry has its own catch.
  - `[low]` `[reject]` Edge: a null `ScheduleEntry.Type` throws `NullReferenceException` — nullable reference types warn, and the schedule is code-owned.
  - `[medium]` `[patch]` Edge: a wrong-role connection keeps the Worker idle — same fix as the Blind row.

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

## Auto Run Result

Status: done

**Summary:** added `job` and `job_payload` with a CHECK and a registry-rendered insert guard, the Kernel `IJobEnqueuer` port, the Operations registry, enqueuer, runner and schedule runner, and `Host.Worker` wiring that refuses to start without its four connection settings.

**Files:** `src/Gatekeep.Kernel/Jobs/`; `src/Modules/Operations/Contracts/` and `Core/`; the job migration and `TableRegistry.cs`; `src/Gatekeep.Host.Worker/`; `tests/Isolation/Jobs/`; `tests/Architecture/JobRegistryRuleTests.cs`; `docs/threat-model.md`; the module diagram and edges.

**Review:** 40 findings across four layers: 25 patched, 7 deferred, 8 rejected, each with its reason in the triage log.

**Follow-up review:** recommended. Several medium patches change the runner's claim return on shutdown and the finishing transaction, which only the new runner tests exercise; a second pass should check them.

**Verification:** see the PR screenshot; restore, build, Architecture, Isolation and the diagram generator all pass on SDK 10.0.403 and Node 26.13.0.

**Residual risks:** any role with insert on `job_payload` can attach a payload to another job of its Tenant that has none. Dead jobs block Tenant deletion until a retention rule exists. A dead job raises no alert (G-17). Handlers must be idempotent, as delivery is at-least-once.
