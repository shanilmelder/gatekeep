---
title: 'Story 1.5: Write an audit event with every state change'
type: 'feature'
created: '2026-11-02'
status: 'done'
baseline_commit: 'b59c480a565301578dfb020dac4408d28a413423'
baseline_revision: 'b59c480a565301578dfb020dac4408d28a413423'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-1-context.md'
  - '{project-root}/docs/threat-model.md'
warnings:
  - oversized
  - multiple-goals
deferred:
  - summary: >-
      Nothing fails a state change that skips IAuditAppender.
    evidence: |-
      No production command exists yet, so the AD-5 rule for every state change can't be enforced or tested until real handlers arrive from Story 1.21. T-31 records it.
    location: >-
      tests/Architecture/PersistenceRuleTests.cs
    severity: medium
---

<intent-contract>

## Intent

**Problem:** State changes can commit with no record, and an event could describe a change that rolled back (FR-40, AD-5).

**Approach:** Add the four audit tables with immutability enforced by the database, a Kernel `IAuditAppender` port implemented by the Audit module on the `CommandContext` connection, a Deployment-level scope, `FailureContext`, `Actor` and `Secret<T>`. Prove it on real PostgreSQL 18.6.

## Boundaries & Constraints

**Always:**
- The envelope has only a validated type code, `Actor`, and typed internal references. It has no free-form string or object field.
- Personal data goes only in `audit_detail` or `deployment_audit_detail`.
- `gk_hosted` has no access to `deployment_*` tables (AD-2).
- Grants are listed in the registry, per table and per column.
- `FailureContext` commits only after the failed transaction has rolled back, and the caller's cancellation can't stop it.

**Never:**
- No sealing, hashing, chain walking, retention, canonical JSON or `audit verify`: Epic 7 adds those. Seal columns exist so the trigger can guard them.
- No scrubbing sink, `RevealOnce<T>` or canary scan: Stories 1.6 and 7.8.
- No read API, event catalogue, HTTP or authorization code.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Tenant command commits | State write plus append | State, `audit_event` and `audit_detail` rows all exist | N/A |
| Tenant command rolls back | Same, scope disposed | None exist | N/A |
| Deployment command | `DeploymentScope`, with detail | `deployment_audit_event` row, personal data only in `deployment_audit_detail` | N/A |
| Tenant table in Deployment scope | No Tenant setting | Query refused | PostgreSQL error surfaces |
| Refused request | State write, then `FailureContext` | State gone, effect and its event committed | Effect failure surfaces |
| Failure on a committed scope | Scope already finished | Effect doesn't run | `InvalidOperationException` |
| Update or delete | Any role but `gk_sealer`, `gk_retention`, including `gk_migrator` | Refused | `42501` or trigger error |
| Sealer changes envelope | `UPDATE type_code` | Refused | `42501` |
| Sealer reseals | Seal columns already set | Refused | Trigger error |
| Bad type code | `Bad.Code`, or two segments | Refused in C#, and by a `CHECK` in SQL | `ArgumentException`, `23514` |
| Secret serialized | `Secret<string>` to JSON or `ToString` | No value appears | JSON throws `NotSupportedException` |

</intent-contract>

## Code Map

- `src/Gatekeep.Kernel/Persistence/TenantScope.cs` -- transaction logic moves to a shared base; `BeginAsync` and the failure cleanup stay.
- `src/Gatekeep.Kernel/Persistence/CommandContext.cs:10` -- bound to `TenantScope`; rebind to the base, `TenantId` becomes `Guid?`.
- `src/Adapters/Postgres/Schema/TableRegistry.cs:13` -- `TableEntry` needs column grants (deferred from 1.4).
- `src/Adapters/Postgres/Migrations/Migration20261102000000CreateTenantTables.cs` -- pattern for hand-written SQL and the RLS pair.
- `tests/Isolation/CatalogueAudit.cs:141` -- `expected` covers table grants only; `Grant()` already prints the column form. Add a function and default ACL check (deferred from 1.4).
- `tests/Isolation/PostgresFixture.cs` -- `NewMigratedDatabaseAsync`, `RoleConnection`, `ScalarAsync`.
- `tests/Architecture/PersistenceRuleTests.cs:22` -- `ForbiddenInContracts` needs the new scope names.
- `tests/Architecture/module-edges.txt:63` -- add `dependency Tests.Isolation -> Audit`, then run the generator.
- `src/Modules/Audit/Adapters/` -- empty; references only Kernel, which is enough over `DbCommand`.
- `docs/threat-model.md:5,100,236,252` -- status line, TB-6, T-31, T-42.
- Toolchain: `%LOCALAPPDATA%\Programs\dotnet-10.0.403\dotnet.exe`.

## Tasks & Acceptance

**Execution:**
- [x] `src/Gatekeep.Kernel/Persistence/CommandScope.cs`, `TenantScope.cs`, `DeploymentScope.cs`, `CommandContext.cs` -- extract the base and add the Deployment scope -- Deployment commands need a context with no Tenant setting.
- [x] `src/Gatekeep.Kernel/Persistence/FailureContext.cs` -- add `CommitAfterRollbackAsync(failedScope, effect)` -- AD-5.
- [x] `src/Gatekeep.Kernel/Audit/` -- add `Actor`, `AuditTypeCode`, `AuditEvent`, `AuditDetail`, `IAuditAppender` -- AD-16, AD-28.
- [x] `src/Gatekeep.Kernel/Secrets/Secret.cs` -- add `Secret<T>` with a throwing JSON converter -- AD-24.
- [x] `src/Modules/Audit/Adapters/AuditAppender.cs` -- choose the chain from `context.TenantId`, write event and detail through `context.CreateCommand()`.
- [x] `src/Adapters/Postgres/Migrations/Migration20261102010000CreateAuditTables.cs`, `Schema/TableRegistry.cs` -- add the four tables, triggers, grants and column grants.
- [x] `tests/Isolation/CatalogueAudit.cs`, `CatalogueTests.cs` -- check column grants, functions and default ACLs.
- [x] `tests/Isolation/AuditTests.cs`, `FailureContextTests.cs`, `SecretTests.cs` -- cover the matrix.
- [x] `tests/Architecture/PersistenceRuleTests.cs`, `module-edges.txt`, `tests/Isolation/*.csproj`, lockfiles, diagram -- ban the new scopes in `Contracts`, add the edge, and assert the envelope's property types.
- [x] `docs/threat-model.md` -- update the status line, TB-6, T-31 and T-42 with what exists and test names.

**Acceptance Criteria:**
- Given the migrated database, when the catalogue test runs, then it passes with exact column grants and refuses any function that `PUBLIC` can execute, is `SECURITY DEFINER` or isn't owned by `gk_migrator`, and any `pg_default_acl` row.
- Given `AuditEvent`, when reflection inspects its properties, then each is a `Guid`, `Guid?`, `Actor`, `AuditTypeCode` or `AuditTargetKind?`, so a `Secret<T>` can't enter it.
- Given `Contracts` source, when the rule runs, then naming `DeploymentScope`, `CommandScope` or `FailureContext` fails.
- Given `Secret<T>`, when reflection inspects it, then it has no public property or field.

## Spec Change Log

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 35 findings — high 1, medium 12, low 16, false 6, maybe-false 0
- findings:
  - `[medium]` `[patch]` Blind: inserting roles could set seal columns and `occurred_at` — `BEFORE INSERT` trigger refuses seal values and overwrites the time.
  - `[medium]` `[patch]` Blind: `gk_retention` could delete an unsealed event, against AD-16 — delete guard refuses it; retention tests now seal first.
  - `[medium]` `[patch]` Blind: partial seal left a row that could never be finished — two `CHECK`s added, tested with `23514`.
  - `[medium]` `[patch]` Blind: scoped IPv6 aborted the transaction, and mapped addresses were unnormalised — `StoredAddress` normalises, tested on both chains.
  - `[low]` `[reject]` Blind: unlimited, unsanitised `UserAgent` and `Email` — fails loudly and no caller exists; hosts validate input when real commands arrive, and the fix adds guards.
  - `[false]` `[reject]` Blind: a late event is skipped forever by a forward-only sealer — the AD-16 sealer selects `seq IS NULL`, so it is not forward-only.
  - `[medium]` `[patch]` Blind: triggers were not in the catalogue — `TableEntry.Triggers` added, `pg_trigger` compared, `tgenabled = O` required.
  - `[medium]` `[patch]` Blind: no cross-Tenant behaviour test on audit tables — role-driven test added.
  - `[low]` `[patch]` Blind: enum values not tied to `CHECK` lists — theory appends every value on both chains.
  - `[medium]` `[patch]` Blind: envelope rule stopped at `Actor` — members now walked.
  - `[low]` `[patch]` Blind: type code had no length limit — 128 in C# and SQL; T-42 softened.
  - `[low]` `[patch]` Blind: `AuditDetail` comment overclaimed and its test checked one value — comment corrected, all three asserted.
  - `[medium]` `[defer]` Blind: nothing fails a state change that skips the appender — no command exists until Story 1.21; recorded in `deferred` and T-31.
  - `[low]` `[reject]` Blind: null `TenantId` silently picks the Deployment chain — this is the designed selection; a mistake needs a wrong scope, and a guard adds surface.
  - `[low]` `[reject]` Blind: lost-connection test accepts any exception, and the effect is dropped — matches the intent's "only after the rollback"; the loss is recorded in T-31.
  - `[low]` `[patch]` Blind: Deployment update test did not assert the row unchanged — both update tests compare the whole row. Detail role matrix is covered by the catalogue, so not added.
  - `[high]` `[patch]` Edge: a stale dispose after commit rolled back another request's transaction on a reused connector — `_released` flag added; the `Maximum Pool Size=1` test fails without it.
  - `[medium]` `[patch]` Edge: scoped IPv6 aborts the transaction — same fix as the Blind row.
  - `[low]` `[reject]` Edge: NUL or oversized detail strings — same reason as the Blind row.
  - `[false]` `[reject]` Edge: IDs misstate event order — chain order is sealing order, and `occurred_at` holds the time.
  - `[medium]` `[patch]` Edge: partial seal cannot be finished — same fix as the Blind row.
  - `[medium]` `[patch]` Edge: unsealed event deleted — same fix as the Blind row.
  - `[medium]` `[patch]` Edge: dropped trigger passes the catalogue — same fix as the Blind row.
  - `[false]` `[reject]` Edge: `AppendAsync` with detail as `gk_retention` raises `42501` — retention writes only checkpoints, which hold no personal data, and a failure would be loud.
  - `[low]` `[patch]` Edge: `AuditDetail` serializes in full — comment now states only `ToString` is masked; the spec requires no refusing converter.
  - `[false]` `[reject]` Edge: JSON null bypasses the `Secret<T>` converter — null holds no secret, so nothing leaks.
  - `[low]` `[reject]` Edge: an effect failure hides the original exception — the failure stays loud, and combining them adds surface with no caller.
  - `[low]` `[patch]` Gap: actor and target `CHECK`s untested on `audit_event` — theory runs on both tables.
  - `[low]` `[patch]` Gap: enum mapping unverified — same fix as the Blind row.
  - `[low]` `[patch]` Gap: detail path ran with one IPv4 value — partial and IPv6 theory added.
  - `[low]` `[patch]` Gap: `[StateChanging]` rule never inspected Kernel — scan includes Kernel.
  - `[low]` `[patch]` Gap: envelope rule not transitive and columns unpinned — members walked, exact columns asserted.
  - `[low]` `[patch]` Gap: partial-seal branch unpinned — filed as defer, closed by the `CHECK`s and their test.
  - `[false]` `[reject]` Gap (other): scoped IPv6 — duplicate of the row above, already fixed.
  - `[false]` `[reject]` Intent: the diff covers one of 28 stories with no production caller — descriptive, and matches the story-by-story reading; the caller gap is the deferred row.

## Design Notes

- **Grants:** "S, I" means `SELECT, INSERT`.

  | Table | hosted | admin | worker | sealer | retention | cli |
  |---|---|---|---|---|---|---|
  | `audit_event` | I | S, I | S, I | S, `UPDATE(seq, prev_hash, hash)` | S, I, D | S, I |
  | `audit_detail` | I | S, I | S, I, D | none | S, D | S, I |
  | `deployment_audit_event` | none | S, I | S, I | as `audit_event` | S, I, D | S, I |
  | `deployment_audit_detail` | none | S, I | S, I, D | none | S, D | S, I |

  `gk_retention` deletes detail because `ON DELETE RESTRICT` would otherwise block deleting a range. AD-16 names only `gk_worker`; spine catch-up is a deferred item. `gk_hosted` gets `INSERT` only, as nothing on the public path reads the log.
- **Triggers:** one function each for update and delete, plus `BEFORE TRUNCATE`. Update needs `current_user = 'gk_sealer'`, unchanged envelope columns and null old seal columns. Delete needs `gk_retention`. Triggers stop the owner, which grants don't.
- **Keys:** `audit_event` PK `(tenant_id, id)`, `audit_detail` PK `(tenant_id, event_id)` with a composite foreign key. IDs are `Guid.CreateVersion7()`, as the sealer orders by ID. `UNIQUE (tenant_id, seq)`.
- **Actor kinds:** `system`, `anonymous`, `admin`, `user`, `client`. The first two have no ID, enforced by a `CHECK`. The spine names only `system`.
- **Envelope:** `AuditEvent(AuditTypeCode Type, Actor Actor, AuditTargetKind? TargetKind, Guid? TargetId)`, with an optional `AuditDetail(IpAddress, UserAgent, Email)` beside it. `AuditTargetKind` is a Kernel enum starting at `Tenant`, `Admin`, `User`, `Client`, stored in lower case with a `CHECK`. Kind and ID are both null or both set. `id` and `occurred_at` are assigned on append.
- **Failure shape:**
  ```csharp
  catch (RefusedException)
  {
      await FailureContext.CommitAfterRollbackAsync(scope, (context, ct) => Write(context, ct));
      throw;
  }
  ```
  It rolls back `scope`, opens a fresh scope of the same kind, runs the effect and commits, with its own 5-second limit.

## Verification

**Commands:**
- `dotnet restore Gatekeep.slnx --locked-mode` -- expected: succeeds.
- `dotnet build Gatekeep.slnx --no-restore` -- expected: no warnings.
- `dotnet test tests/Architecture --no-build` -- expected: all pass.
- `dotnet test tests/Isolation --no-build` -- expected: all pass on `postgres:18.6`.
- `dotnet run --project tests/Architecture/Generator` -- expected: no diff after committing the diagram.

## Auto Run Result

Status: done

**Summary:** added the four audit tables with database-enforced immutability, `IAuditAppender` and its Audit adapter, `DeploymentScope`, `FailureContext`, `Actor`, `AuditTypeCode` and `Secret<T>`.

**Files:** Kernel `Persistence/`, `Audit/` and `Secrets/`; `src/Modules/Audit/Adapters/AuditAppender.cs`; the audit migration and `TableRegistry`; `tests/Isolation` and the `tests/Architecture` rules; `docs/threat-model.md`; the module diagram.

**Review:** 35 findings across four layers: 23 patched, 1 deferred, 11 rejected, each with its reason in the triage log.

**Follow-up review:** not recommended. The one high is proved by a test that fails without the fix, so no unverified risk can be named.

**Verification:** locked restore passes, the build has 0 warnings, Architecture 91 of 91, Isolation 278 of 278 on `postgres:18.6`, and the diagram generator gives no diff. Run with SDK 10.0.403 and Node 26.13.0 on `PATH`; `BuildEnforcementTests` fail without them.

**Residual risks:** no production command calls the appender yet. `gk_migrator` can still drop triggers, which the catalogue reports but can't prevent. A rollback that can't be confirmed drops the `FailureContext` effect. `gk_retention` deleting detail isn't in AD-16 yet.
