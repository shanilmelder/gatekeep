---
title: 'Story 4.3: Purge expired sign-in state'
type: 'feature'
created: '2026-11-16'
status: 'done'
baseline_revision: 'dbf5bc40c43e0b94c29334496c6353627b02b845'
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

### 2026-11-16 — Review pass
- verdicts: 28 findings — high 0, medium 6, low 13, false 9, maybe-false 0
- findings:
  - `[false]` `[reject]` (blind) `docs/audit-events.md` and `LogCatalogue.Generated.cs` changed but aren't in the diff — they're generated by the catalogue generator and were left out of the review diff on purpose; `AuditCatalogueTests` checks them.
  - `[false]` `[reject]` (blind) The family delete has no guard, so it could remove permanent authorizations or a family before its first token — Gatekeep creates only ad-hoc authorizations (`AuthorizationTypes.AdHoc`, AD-13), and the authorize request writes the family and its code token in one transaction, which the purge can't see before commit; a racing insert fails the RESTRICT FK and retries.
  - `[low]` `[reject]` (blind) Deletes aren't batched — an hourly run deletes an hour's expiry; the first run's backlog is small because sign-in only now starts writing these rows.
  - `[low]` `[reject]` (blind) `CREATE INDEX` without `CONCURRENTLY` blocks writes — migrations are forward-only and run in one transaction at upgrade; the tables are new and small.
  - `[low]` `[reject]` (blind) The `user_session (tenant_id, idle_expires_at)` index won't serve the three-way OR — idle ≤ absolute, so idle expiry covers both expiry branches; ended Sessions are few.
  - `[low]` `[patch]` (blind) The purge reads `TimeProvider.System` directly — grouped with the boundary tests: the clock is injected so the cutoffs can be pinned.
  - `[low]` `[reject]` (blind) Sessions are deleted before transactions that name them — `authenticated_session_id` has no FK by design (Story 4.2, purges independent); a completed transaction's dangling ID is never read after completion.
  - `[false]` `[reject]` (blind) The `user_session` grants may have lost `PurgeColumns` entries — `PurgeColumns` holds only the Worker's `tenant_id` read, which the new grant keeps.
  - `[low]` `[reject]` (blind) "One hour" is repeated in prose beside `SignInRestartRetention` — descriptive text; the code reads the constant.
  - `[low]` `[reject]` (blind) The audit event carries no counts — the audit envelope holds no free-form values (AD-16); counts would need a detail change.
  - `[medium]` `[patch]` (blind) Missing tests: exact boundaries, a non-active Tenant, a running purge — added; token-less and cross-scope cases are rejected (no token-less family can exist; RLS and the statement's `tenant_id` are the same scope by construction).
  - `[low]` `[reject]` (blind) Parameters built two ways — style only.
  - `[low]` `[reject]` (blind) `sessions.`-named jobs and event run by Operations — Operations orchestrates purges for every module (as Tenant deletion does); the state purged is Sessions' and Authentication's.
  - `[false]` `[reject]` (blind) The spec front-matter records no build decisions — decisions are recorded in the Auto Run Result at finalization.
  - `[medium]` `[patch]` (verification) The hourly schedule entry isn't tested though a test's name claims it — the test now asserts the Worker's schedule holds the sweep every hour.
  - `[medium]` `[patch]` (verification) The sweep's active-Tenant filter is untested — a `deleting` Tenant gets no purge from the sweep, and a purge enqueued for it deletes nothing.
  - `[low]` `[patch]` (verification) Dedupe tested only for a pending purge — a `running` case added.
  - `[false]` `[reject]` (verification, other) The generated catalogue files are missing from the diff — same as the first row.
  - `[low]` `[reject]` (intent) "A restart keeps the email" is shown on the row, not at `/login` after a purge — the restart path and the purge share `SignInRestartRetention` and `<=`; the boundary test pins the purge side, and Story 4.2's tests the restart side.
  - `[medium]` `[patch]` (intent) "Recurring" and "hourly" untested — grouped with the schedule row; fixed.
  - `[false]` `[reject]` (intent) "One Tenant scope at a time" read as strictly serial — AD-15's scope rule is per-Tenant scope; each purge runs in exactly one scope.
  - `[false]` `[reject]` (intent) "Sessions with no live Token Family" read literally to include live Sessions — the story is about expired state; deleting a live Session would sign Users out.
  - `[low]` `[reject]` (intent) Revoked or redeemed tokens with a future expiry stay — they go at their expiry; the story names expired tokens.
  - `[false]` `[reject]` (intent) Deleting `authorization` rows goes beyond the AC — a Session can't be free of families while dead family rows anchor it; deleting them is required.
  - `[medium]` `[patch]` (edge) A Tenant moving to deleting between the sweep's read and its enqueue gets a purge — grouped with the next row: the purge now re-reads the status and stops unless active.
  - `[medium]` `[patch]` (edge) A pending purge runs after its Tenant entered deleting — the purge returns without deleting or writing an event unless the Tenant is `active`; tested.
  - `[low]` `[reject]` (edge) Two simultaneous sweeps could each enqueue a purge — one schedule entry runs one sweep at a time; a duplicate purge deletes nothing and writes no event.
  - `[false]` `[reject]` (edge) A family committed before its first token could be deleted mid-sign-in — the family and token are written in one request transaction (see the second row).

## Verification

**Commands:**
- **.NET build:** with `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors.
- **Isolation:** with Testcontainers, pinning the IPv4 as `deploy/docker/run-tests.sh` does, run `ExpiredStatePurgeTests`, `MigrateCommandTests`, `Operations*`, `Sessions/*`, `TenantPurge*`, the job-schedule tests and `AuditCatalogue*`, plus the Architecture suite. Don't run the full Isolation suite. The local-only `.claude/worktrees` Architecture failure is expected.

## Auto Run Result

**Summary:** An hourly Worker job, `sessions.expired_state.sweep`, reads the active Tenants and enqueues one `sessions.expired_state.purge` per Tenant in that Tenant's own scope, unless one is already pending or running. The purge stops unless its Tenant is still active, then in one transaction deletes expired tokens, Token Families left with no token, Sessions that are over and anchor no family, and transactions more than `SignInRestartRetention` (1 h) past expiry, with their kept email. A run that deleted something writes one `sessions.expired_state.purged` event.

**Files changed:**
- `src/Adapters/Postgres/Migrations/Migration20261124000000PurgeExpiredSignInState.cs` -- `gk_worker` column reads, three indexes, and the job guard re-rendered with the two new job types (migration 40).
- `src/Adapters/Postgres/Schema/TableRegistry.cs` -- the matching grants.
- `src/Modules/Sessions/{Contracts/SessionsContract.cs,Contracts/SessionsEvents.cs,Core/SessionsExpiredStatePurge.cs}` -- the tokens, families and Sessions purge and its event.
- `src/Modules/Authentication/{Contracts/AuthenticationContract.cs,Core/AuthenticationExpiredStatePurge.cs}` -- the transactions purge.
- `src/Modules/Operations/{Contracts/OperationsContract.cs,Contracts/JobRun.cs,Core/ExpiredStatePurgeJobs.cs,Core/ProductionJobs.cs,Core/OperationStore.cs}` -- the sweep and purge jobs with reviews, the active-Tenant guard, and an injectable job clock.
- `src/Gatekeep.Host.Worker/JobSchedule.cs` -- the hourly entry.
- `docs/audit-events.md`, `src/Gatekeep.Host.Admin/LogCatalogue.Generated.cs` -- regenerated.
- Tests: new `ExpiredStatePurgeTests`; updated `MigrateCommandTests`, `TenantTablesTests`, `AdminApiRuleTests`, `TenantKeyedTypes`, `CanaryFlows`.

**Review findings:** 28 findings (medium 6, low 13, false 9). Patched 5 entries (medium 3, low 2, counted by group): the purge stops for a Tenant that isn't active; the hourly schedule entry is asserted; a deleting Tenant gets no purge; a running purge blocks a second; the cutoffs are pinned at the job's injected clock. Deferred none. Rejected 23 with reasons in the Review Triage Log.

**Follow-up review:** not recommended. The medium patches were a status guard and tests, all run green; no unverified risk remains from them. Patched counts: high 0, medium 3, low 2.

**Verification:**
- .NET build: 0 warnings / 0 errors.
- Architecture: 794 of 795; the one failure is the known local-only `.claude/worktrees` check.
- Isolation `ExpiredStatePurgeTests`, `MigrateCommandTests`, `JobGuard*`, `TenantTablesTests`, `TenantPurge*`, `AuditCatalogue*`, `Canary*`, `Operations/*` and `Jobs/*`: 496 of 497 after the fixes. The one failure, `TenantDeletionOperationTests.Retry_reruns_only_the_failed_step_then_deletes_once` (and, on the earlier run, `OperationTests.Retry_runs_only_the_failed_step`), passed three times in a row alone; both are timing-sensitive under load and each test class uses its own database.

**Residual risks:**
- The purge isn't batched; an hourly run deletes one hour's expiry.
- Revoked or redeemed tokens wait for their expiry before the purge removes them, keeping their family and Session until then.
- The Operations retry tests above are timing-sensitive under a loaded local run.
