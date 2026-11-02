---
title: 'Story 1.9: Track long-running Operations'
type: 'feature'
created: '2026-11-02'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-8-run-tenant-scoped-jobs.md'
  - '{project-root}/docs/threat-model.md'
warnings: [oversized]
deferred: []
---

<intent-contract>

## Intent

**Problem:** Work spanning modules or Tenants has no record. AD-30 needs an Operation that is tracked step by step, refuses a second active run for the same scope and type, shows partial failure, and retries only what failed.

**Approach:** Add `operation` and `operation_step` (both `control`, owned by Operations), a code-owned Operation type registry naming each type's stage handlers, contract methods to start, read and retry, and two job types that run steps through the Story 1.8 job path.

## Boundaries & Constraints

**Always:**
- An Operation has a type (`{domain}.{object}.{action}`), a scope (one Tenant, FK `tenant` `ON DELETE RESTRICT`, or the Deployment), a status (`running`, `failed`, `succeeded`) and timestamps. Active means `running` or `failed`. A partial unique index refuses a second active Operation for the same type and scope, and start maps that to a typed refusal.
- `operation_step` has the Operation ID, a nullable Tenant ID (FK `tenant` `ON DELETE RESTRICT`), a stage code, a status (`pending`, `running`, `succeeded`, `failed`), a result code and an attempt count. No free-text column exists in either table: stage and result codes are CHECK-constrained to the code pattern `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`, at most 64 characters, so no personal data can be stored.
- Starting runs in the caller's `CommandContext` (a `DeploymentScope`): it writes the Operation, its planned steps (one per Tenant or stage), and enqueues the Deployment-wide job `operations.operation.run` carrying only the `operation_id`, all in one transaction. It returns the `operation` resource with every step.
- `operations.operation.run` fans out: it enqueues one Tenant job `operations.operation.step` per pending Tenant step and runs Deployment steps itself. Each step runs its registered handler, records `succeeded` or `failed` with a result code, and when no step is pending or running sets the Operation to `succeeded` or `failed`. Handlers are idempotent.
- Retry, in the caller's context, is allowed only on a `failed` Operation: it sets only `failed` steps back to `pending`, the Operation to `running`, and enqueues `operations.operation.run` again. Succeeded steps never run again.
- Reads: `GetAsync(operationId)` returns all steps; `GetForTenantAsync(operationId, tenantId)` returns only that Tenant's steps, and no Operation scoped to another Tenant.
- Grants: `gk_admin`, `gk_cli` and `gk_worker` may start and retry (insert and the needed column updates); `gk_worker` updates step and Operation status; `gk_hosted`, `gk_sealer` and `gk_retention` get nothing. Both new job types are added to the production job registry, `operations.operation.run` with its recorded review, and the guard is re-rendered in a new migration.
- An architecture test fails if a module owning `tenant` tables in `TableRegistry` has no `Operations ->` edge (AD-30).
- Update `docs/threat-model.md` with what is built.

**Never:**
- No production Operation type yet (Tenant creation and deletion arrive in their own stories); tests use a test registry.
- No HTTP endpoint and no `202` response; the contract returns the resource, and the hosts' routes come with their screens.
- No Tenant purge contracts and no fresh-assertion check on retry; record both as open for the stories that need them.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Start | Type with Tenant steps for A and B and one Deployment stage | `running` resource with three `pending` steps; one run job | No error |
| Second start | Same type and scope while the first is `running` or `failed` | Refused; nothing written | `OperationAlreadyActiveException` |
| Different scope | Same type, other Tenant scope | Starts | No error |
| All succeed | Handlers succeed | Every step `succeeded`, Operation `succeeded`; a new start is allowed | No error |
| Partial failure | B's handler fails | A and the stage `succeeded`, B `failed` with its result code, Operation `failed` | Visible in the resource |
| Retry | Retry the failed Operation, B now succeeds | Only B runs again (A's handler count unchanged); Operation `succeeded` | No error |
| Retry not failed | Retry a `running` or `succeeded` Operation | Refused | `InvalidOperationException` |
| Free text | Stage or result code with spaces, `@` or over 64 characters | Refused | CHECK `23514` |
| Tenant read | `GetForTenantAsync` for A on an Operation with A and B steps | Only A's steps | — |
| Other Tenant's Operation | `GetForTenantAsync` for B on an Operation scoped to A | Not found | Returns null |
| Role grants | `gk_hosted` inserts an Operation | Refused | `42501` |

</intent-contract>

## Code Map

- `src/Modules/Operations/Contracts/OperationsContract.cs`, `JobRegistry.cs`, `JobRun.cs` -- Story 1.8 job API. `JobDefinition` takes type, scope, enqueuing roles, run-as, max attempts, handler, never-dead, may-carry-credential and a `JobReview`. A `JobRun` gives the handler its `CommandContext`, Tenant, `OperationId` and payload IDs.
- `src/Modules/Operations/Core/ProductionJobs.cs` -- the production job registry (`operations.job.purge`); add the two new types here.
- `src/Modules/Operations/Core/JobGuardRenderer.cs`, `tests/Isolation/Jobs/JobGuardTests.cs` -- a registry change adds a new migration holding the new render between `-- BEGIN rendered guard` and `-- END rendered guard`; the test reads the latest such migration.
- `src/Adapters/Postgres/Migrations/Migration20261102020000CreateJobTables.cs` -- pattern for tables, CHECKs, grants and the guard block. New migration `20261102030000_CreateOperationTables`.
- `src/Adapters/Postgres/Schema/TableRegistry.cs` -- add both tables (Control, Operations) with exact grants; `tests/Isolation/CatalogueAudit.cs` compares both ways, requires RESTRICT FKs and no RLS on control tables.
- `tests/Isolation/MigrateCommandTests.cs` -- hard-coded migration count; raise it.
- `tests/Isolation/Jobs/JobTestSupport.cs` -- database, runner and test-registry helpers to reuse for running operation jobs.
- `tests/Architecture/module-edges.txt`, `tests/Architecture/ModuleEdgeTests.cs` -- edge list reading for the AD-30 rule; `TableRegistry` is reached by reflection or a project reference already used by Architecture tests.
- `tests/Architecture/PersistenceRuleTests.cs` -- `[StateChanging]` methods take `CommandContext`; Contracts files don't name scopes or transactions.
- `global.json` -- SDK 10.0.403 at `%LOCALAPPDATA%\Programs\dotnet-10.0.403` and Node 26.13.0 at `%LOCALAPPDATA%\Programs\node-v26.13.0-win-x64` first on `PATH` (pnpm shim in `C:\Users\esm\AppData\Local\Temp\claude\D--Projects-Personal-gatekeep\94ff8bc2-4a0e-49fa-a28e-6d3d0ecd048d\scratchpad\shims`), or `BuildEnforcementTests` fail.

## Tasks & Acceptance

**Execution:**
- [ ] `src/Modules/Operations/Contracts/` -- `OperationType`, `OperationRegistry` (type to stage handlers), `OperationStepPlan`, `OperationResource`/`OperationStepResource`, `OperationAlreadyActiveException`, and contract factories for an `IOperations` service with `[StateChanging] StartAsync`, `[StateChanging] RetryAsync`, `GetAsync`, `GetForTenantAsync`.
- [ ] `src/Modules/Operations/Core/` -- the service and the two job handlers; register `operations.operation.run` (Deployment-wide, enqueued by `gk_admin`, `gk_cli`, `gk_worker`, run as `gk_worker`, reviewed) and `operations.operation.step` (Tenant, enqueued by `gk_worker`, run as `gk_worker`) in the production job registry; the job runner looks up Operation types from a registry passed to it.
- [ ] `src/Adapters/Postgres/Migrations/Migration20261102030000CreateOperationTables.cs`, `TableRegistry.cs` -- tables, CHECKs, partial unique index, grants, and the re-rendered guard block.
- [ ] `tests/Isolation/Operations/` -- every matrix row with a test Operation registry, plus the cross-Tenant read.
- [ ] `tests/Architecture/OperationRuleTests.cs` -- the AD-30 edge rule, with a detection test on a made-up registry.
- [ ] `docs/threat-model.md`, module diagram -- record the tables, grants and tests, and the open Tenant purge and fresh-assertion items.

**Acceptance Criteria:**
- Given a started Operation, when its jobs run, then each Tenant step runs in that Tenant's own scope through `operations.operation.step`, and the Deployment-wide job touches only `control` tables.
- Given a step handler that throws, when the step finishes, then only a fixed result code is stored, never exception text.

## Spec Change Log

## Review Triage Log

## Design Notes

- **Unique active:** `CREATE UNIQUE INDEX operation_one_active ON operation (type, coalesce(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid)) WHERE status IN ('running', 'failed')`. Start catches `23505` on that index name only.
- **Step job payload:** `operations.operation.step` carries IDs `operation_id` and `step_id`; the handler re-reads the step and skips it unless it's `pending` or `running` for this Tenant.
- **Finishing the Operation:** whichever step finishes last sets the Operation's status, under a row lock on the Operation, so two Tenant steps finishing together can't both miss it.

## Verification

**Commands:**
- `dotnet restore Gatekeep.slnx --locked-mode` -- expected: succeeds.
- `dotnet build Gatekeep.slnx --no-restore` -- expected: no warnings.
- `dotnet test tests/Architecture --no-build` -- expected: all pass.
- `dotnet test tests/Isolation --no-build` -- expected: all pass, including `Operations`.
- `dotnet run --project tests/Architecture/Generator` -- expected: no diff after committing the diagram.
