---
title: 'Story 4.3: Purge expired sign-in state'
type: 'feature'
created: '2026-11-16'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-4-context.md'
warnings: []
deferred: []
---

<intent-contract>

## Intent

**Problem:** Expired sign-in transactions, expired tokens, dead Token Families and Sessions that nothing anchors stay in the database for ever. Today only a deleted Tenant or Application removes them. A transaction also keeps the email entered at Login (Story 4.2's `identifier`) until something deletes the row (FR-8, NFR-3, AD-13, AD-15).

**Approach:** a recurring Worker job sweeps every Tenant and enqueues one purge job per Tenant, run in that Tenant's own scope, following the audit-retention sweep and apply pattern. The purge deletes, in order:
1. expired tokens;
2. Token Families left with no token;
3. Sessions that are over and anchor no family;
4. transactions more than one hour past expiry.

## Boundaries & Constraints

**Always:**
- **Schedule:** a new Deployment-wide sweep job type runs hourly from `JobSchedule`. It reads only active Tenant IDs and the job table.
  - For each Tenant it enqueues one Tenant-scoped purge job in that Tenant's own scope, unless one is already waiting there.
  - It deletes nothing.
  - Both job types run as `gk_worker`, with a `JobReview` describing exactly what they read and delete.
- **Purge, per Tenant, in one `CommandContext`, children before parents.** "Now" is the job's clock read once.
  1. **Tokens:** delete `token` rows whose `expiration_date` ≤ now.
  2. **Families:** delete `authorization` rows (the Token Family) that no `token` row references any more.
  3. **Sessions:** delete `user_session` rows that are over and that no `authorization` references. Over means `ended_at` is set, or idle or absolute expiry ≤ now. A live Session is never deleted, and an over Session that still anchors a family stays (AD-13: natural expiry doesn't end a family).
  4. **Transactions:** delete `signin_transaction` rows whose `expires_at` ≤ now − `SecurityLimits.SignInRestartRetention` (1 h), whether completed or not. The kept email goes with the row.
- **Ownership:** each module deletes only its own tables (AD-1):
  - Sessions exposes the expired-state purge for `token`, `authorization` and `user_session`;
  - Authentication exposes the one for `signin_transaction`.
  - Operations orchestrates them, as Tenant deletion does with `ITenantPurge`.
- **Grants:** a new migration (`Migration20261124000000PurgeExpiredSignInState`, sorting after the latest; the migration count goes from 39 to 40) gives `gk_worker` column SELECT on what the purge reads:
  - `token.expiration_date`;
  - `authorization.id`;
  - `user_session` `id`, `ended_at`, `idle_expires_at` and `absolute_expires_at`;
  - `signin_transaction.expires_at`.

  It adds indexes where a purge predicate has none, e.g. `signin_transaction (tenant_id, expires_at)`. `TableRegistry` matches.
- **Idempotent:** a second run deletes nothing. A failed run rolls back whole and retries under the job's attempts.
- **Audit:** one Tenant event per run that deleted at least one row, `sessions.expired_state.purged`, with actor System and no target. A run that deletes nothing writes nothing. Add it to the catalogue and regenerate `docs/audit-events.md`.

**Never:**
- No deletion of a live Session, a family with any unexpired token, or a transaction less than an hour past expiry.
- No OpenIddict pruning: the architecture disables it and makes pruning a job.
- No cross-Tenant statement: each purge runs only in its Tenant's scope.
- No change to Tenant or Application deletion purges.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Expired token | refresh token `expiration_date` past; family has another unexpired token | token deleted; family and Session stay | No error expected |
| Dead family | all of a family's tokens expired | tokens, then the family deleted; its Session deleted only if over and no other family | No error expected |
| Live family, expired Session | Session idle-expired, family has an unexpired refresh token | Session stays (AD-13) | No error expected |
| Over Session, no family | Session ended or expired, nothing references it | deleted | No error expected |
| Live Session | Session within its expiry, no family | stays | No error expected |
| Transaction in retention | `expires_at` 30 min ago | stays (restart keeps email) | No error expected |
| Transaction past retention | `expires_at` 61 min ago, with `identifier` | deleted with its email | No error expected |
| Two Tenants | expired state in A and B | each purged by its own Tenant-scoped job; A's job touches no B row | No error expected |
| Second run | immediately after | deletes nothing, writes no event | No error expected |
| Sweep twice | a purge job already waiting for a Tenant | no second job enqueued | No error expected |

</intent-contract>

## Code Map

- `src/Gatekeep.Host.Worker/JobSchedule.cs` -- the code-owned schedule (AD-15). Add the hourly sweep.
- `src/Modules/Operations/Core/ProductionJobs.cs` L67-89 -- `SweepRetention` (Deployment-wide, enqueues per-Tenant `ApplyRetention` "unless one is already waiting") is the pattern, with its `JobReview`. `src/Modules/Operations/Core/AuditRetentionJobs.cs` holds the sweep and apply handlers to mirror. `OperationsContract.cs` exposes job types.
- `src/Modules/Sessions/Core/SessionsPurge.cs` and `src/Modules/Authentication/Core/AuthenticationPurge.cs` -- the Tenant-deletion purges (whole-Tenant `DELETE`s in the Tenant scope). Put the expired-state purges beside them and expose them through each module's contract.
- `src/Adapters/Postgres/Migrations/Migration20261102090000CreateSessionTables.cs` -- the `user_session`, `authorization`, `token` and `signin_transaction` shapes. `Migration20261123000000BindSignInTransactions.cs` is Story 4.2's columns.
- `src/Adapters/Postgres/Schema/TableRegistry.cs` L325-385 -- Worker grants: `Delete` on all four, column SELECTs on `authorization`/`token`/`signin_transaction`. Add the purge's columns.
- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs` -- `SignInRestartRetention` (1 h).
- `src/Modules/Sessions/Contracts/SessionsEvents.cs` -- event catalogue. `tests/Isolation/MigrateCommandTests.cs` holds the migration count (39). `tests/Architecture/AdminApiRuleTests.cs:162` pins `signin_transaction` grants; update if a pinned list changes.
- `tests/Isolation/Operations/**` and the audit retention job tests -- patterns for running a job handler against Postgres in a Tenant scope.

## Tasks & Acceptance

**Execution:**
- The migration and `TableRegistry` -- column grants and indexes; migration count 40.
- `src/Modules/Sessions/**` -- the expired-state purge (tokens, families, Sessions) and the event.
- `src/Modules/Authentication/**` -- the expired-transaction purge.
- `src/Modules/Operations/**` -- the sweep and purge job types, definitions with reviews, and the handlers calling both purges in one Tenant `CommandContext`.
- `src/Gatekeep.Host.Worker/JobSchedule.cs` -- hourly entry.
- `tests/Isolation/**` -- a new `ExpiredStatePurgeTests` covering every matrix row by seeding rows (backdated) in two Tenants and running the sweep and purge handlers. Update the migration count, the grant pins and the audit catalogue.

**Acceptance Criteria:**
- Given expired transactions and tokens, and Sessions with no live Token Family, when the recurring job runs, then they are purged one Tenant scope at a time.
- Given a transaction expired less than an hour ago, when the job runs, then it stays, so a restart keeps the email.

## Spec Change Log

## Review Triage Log

## Verification

**Commands:**
- **.NET build:** with `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors.
- **Isolation:** with Testcontainers, pinning the IPv4 as `deploy/docker/run-tests.sh` does, run `ExpiredStatePurgeTests`, `MigrateCommandTests`, `Operations*`, `Sessions/*`, `TenantPurge*`, the job-schedule tests and `AuditCatalogue*`, plus the Architecture suite. Don't run the full Isolation suite. The local-only `.claude/worktrees` Architecture failure is expected.
