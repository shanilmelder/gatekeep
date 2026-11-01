---
title: 'Story 1.4: Enforce Tenant isolation in the database'
type: 'feature'
created: '2026-11-02'
status: 'done'
baseline_commit: '5f194f3b1eff27397ac3ec3984ede4beb00028c2'
route: 'dispatch'
review_loop_iteration: 0
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-1-context.md'
  - '{project-root}/docs/threat-model.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Nothing in the database enforces the Tenant boundary yet, so one missed filter in a later story could expose another Tenant's data (FR-8, T-1).

**Approach:** Create the first schema (`tenant`, `tenant_host`, `tenant_settings`), the database roles, the AD-3 table registry, `TenantScope` and `CommandContext` in Kernel, and `gatekeep migrate`. Prove all of it against real PostgreSQL 18.6 in CI.

## Boundaries & Constraints

**Always:**
- Follow AD-3 exactly: `tenant` tables have `tenant_id uuid NOT NULL`, `ENABLE` and `FORCE` RLS, one permissive policy, one `RESTRICTIVE` policy using the failing cast.
- Grants are an allow-list: any privilege not in the registry fails the catalogue test, including grants to `PUBLIC`.
- `gatekeep migrate` refuses any connection whose `current_user` isn't `gk_migrator`.
- Migrations are forward-only: `Down` throws.
- Tests run on `postgres:18.6`, never a mock or another engine.

**Never:**
- No `BYPASSRLS`, superuser or table ownership for a runtime role.
- No session-level `SET`, `set_config(..., false)` or PgBouncer.
- No Tenant API, repository, module `DbContext`, `Actor`, audit or job code: Stories 1.5, 1.8 and 1.27 add those.
- No Compose, secrets delivery or role passwords: Story 1.10 adds those.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Scoped read | Rows in Tenants A and B, scope A, each runtime role granted the table | Only A's row | N/A |
| Scoped write to other Tenant | Scope A, `INSERT` or `UPDATE` with B's `tenant_id` | Refused | RLS violation (`42501`) |
| Unscoped, fresh connection | No `gatekeep.tenant_id` set, rows exist | Error, not an empty result | `42704` surfaces |
| Unscoped, reused connection | Setting was local to an earlier transaction, now empty | Error, not an empty result | `22P02` surfaces |
| Empty Tenant ID | `TenantScope` with `Guid.Empty` | Refused before opening a transaction | `ArgumentException` |
| Unregistered table | Table exists in the database, not in the registry | Catalogue test fails, naming it | CI fails |
| Wrong migrate role | Connection as any role except `gk_migrator` | Exits non-zero, nothing applied, names the role only | Non-zero exit |
| Missing connection file | Path absent or unreadable | Exits non-zero, no connection attempted | Non-zero exit |
| Data migration | Two Tenants, `ForEachTenant` statement | Each row changes under its own Tenant's setting | Failure rolls the migration back |

</frozen-after-approval>

## Code Map

- `src/Gatekeep.Kernel/KernelMarker.cs` -- placeholder; delete once real types exist.
- `src/Gatekeep.Cli/Program.cs` -- empty `return 0`; becomes the command entry.
- `src/Gatekeep.Cli/Gatekeep.Cli.csproj` -- gains the adapter reference.
- `tests/Architecture/module-edges.txt` -- add `dependency Cli -> Adapters.Postgres`; then run the generator for `docs/architecture/module-dependencies.md`.
- `Directory.Build.targets` -- strips `Gatekeep.`, so the short name is `Adapters.Postgres`; needs no change.
- `tests/Architecture/ModuleEdgeTests.cs:189` -- `ProjectFiles()` finds every csproj under `src` and `tests`; extend, don't duplicate. `Kernel_references_nothing_and_is_not_in_the_list` stays true.
- `.github/workflows/ci.yml` -- `Test` step runs only `tests/Architecture`.
- `Directory.Packages.props` -- central versions; every project has a `packages.lock.json`.
- `docs/threat-model.md` T-1, T-3 -- rows take test names.
- Local toolchain: `%LOCALAPPDATA%\Programs\dotnet-10.0.403\dotnet.exe`; not on PATH.

## Tasks & Acceptance

**Execution:**
- [x] `src/Gatekeep.Kernel/Persistence/TenantScope.cs`, `CommandContext.cs`, `StateChangingAttribute.cs` -- add the scope, context and marker over `System.Data.Common`, with no package -- Kernel stays free of infrastructure.
- [x] `src/Adapters/Postgres/Gatekeep.Adapters.Postgres.csproj`, `Gatekeep.slnx`, `Directory.Packages.props`, `module-edges.txt`, lockfiles -- add the project and pin EF Core 10.0.14 and Npgsql provider 10.0.3 -- Seed location.
- [x] `src/Adapters/Postgres/Schema/TableRegistry.cs` -- list every table with class, owner and per-role grants -- AD-3 and AD-27 source of truth.
- [x] `src/Adapters/Postgres/Migrations/` -- add `MigrationsContext`, the first migration and `ForEachTenant` -- creates the three tables, policies and grants.
- [x] `src/Adapters/Postgres/GatekeepMigrator.cs`, `src/Gatekeep.Cli/Program.cs` -- implement `gatekeep migrate --connection-file <path>` -- AD-3 role rule.
- [x] `deploy/postgres/roles.sql` -- create the eight roles with no password, and give `gk_migrator` the schema -- run once by a superuser.
- [x] `tests/Isolation/` -- add a Testcontainers project: catalogue, behaviour, scope and migrate tests covering the matrix -- AD-3's CI test.
- [x] `tests/Architecture/PersistenceRuleTests.cs` -- add source and reflection rules for contracts and session-level `SET` -- AD-4 and AD-28.
- [x] `.github/workflows/ci.yml` -- run `tests/Isolation` -- otherwise the proof never runs.
- [x] `docs/threat-model.md` -- add test names to T-1, update its "only Story 1.1 exists" status line, note the roles and grants now exist -- required by its update rule.

**Acceptance Criteria:**
- Given the migrated database, when the catalogue test runs, then it asserts registry entry, class, owner, exact grants, `ENABLE` and `FORCE` RLS, both policies with their exact expressions, composite foreign keys between `tenant` tables, and that no runtime role owns a table or holds `BYPASSRLS` or superuser.
- Given `TenantScope` and `CommandContext`, when reflection and source rules run, then `CommandContext` has no public constructor or commit or rollback member, a `[StateChanging]` contract method without a `CommandContext` parameter fails, and `Contracts` folders can't name `TenantScope`, `DbDataSource` or `.Commit`.
- Given source under `src`, when the rule runs, then session-level `SET` and `set_config` with `false` are absent, and every `set_config` call is `TenantScope`'s or `ForEachTenant`'s.
- Given a clean database, when `gatekeep migrate` runs twice, then the second run applies nothing and succeeds.

## Spec Change Log

## Review Triage Log

- high, patch: a role or database default for `gatekeep.tenant_id` made unscoped queries run silently as that Tenant, unaudited. Audit reads `pg_db_role_setting`.
- medium, patch: grant options were invisible to the catalogue (mutation passed 65 of 65). Audit reports `is_grantable`.
- medium, patch: `rolreplication` and members of gk roles were unaudited. Both reported.
- medium, patch: foreign key check lost column order, so a crossed composite key passed. Pairs compared by ordinality.
- medium, patch: `PUBLIC` kept `CONNECT` and `TEMPORARY` on the database. Revoked in `roles.sql`, `datacl` audited.
- medium, patch: `UpdateSet` masked a real `SET` after the word "update", other `SET` forms passed, and `deploy` wasn't scanned. Rule tightened.
- medium, patch: reused-connection test couldn't tell local from session-level, because the pool resets. `NoResetOnClose` added, and the mutation now fails.
- medium, patch: `ForEachTenant` final reset was untested. Test added.
- medium, patch: `$gatekeep_block$` could end the DO block early. Guard refuses `$gatekeep_`, with tests.
- medium, patch: a command made before commit could autocommit after it. `CommitAsync` releases the connection.
- medium, patch: `tenant_host` accepted mixed-case or empty hosts and any `kind`, against AD-6. `CHECK` constraints added.
- medium, patch: `gk_admin` `UPDATE` on `tenant` had no use and could rewrite a Tenant ID. Removed.
- medium, patch: unhandled exceptions bypassed the scrubbed Cli output. Final catch added; no test could force it simply.
- medium, patch: program built as `Gatekeep.Cli`, so `gatekeep migrate` didn't exist. Assembly renamed.
- low, patch: `.Transaction`, `.Connection` and raw `COMMIT` weren't banned in `Contracts`. Added. The ban is case-insensitive, so the word in a comment there also fails.
- low, patch: disposal could leak a connection if the transaction threw. try/finally added.
- low, patch: malformed-file test didn't assert the fixed message, and `RunAsync` assumed `dotnet` on PATH and left children on timeout. All fixed.
- low, patch: module inspection test couldn't fail. Compares csproj names now.
- low, patch: `roles.sql` wasn't atomic. Wrapped in a transaction.
- medium, defer: `BeginAsync` failure cleanup has no test. Hard to force before a real caller exists (filed disposition).
- medium, defer: column-level grants can't be expressed, though AD-2 needs them. The audit fails closed on any column grant, and no current table needs one.
- medium, defer: AD-3 wording contradicts the tested known limit.
- low, reject: `TenantScope` as sole path isn't enforced in `Core` and `Adapters`. Handlers there legitimately hold scopes; AC covers `Contracts`.
- low, reject: functions and default privileges aren't audited. None exist yet; first trigger story should add it.
- low, reject: nil UUID Tenant. Tenant creation is Story 1.27, and the guard adds complexity for an unlikely case.
- low, reject: concurrent migrate may misreport applied migrations. Wrong output only, in a rare case.
- low, reject: migrate failure doesn't name the migration. Scrubbed output is deliberate.
- low, reject: `last_updated` moved backwards. The old value was a future timestamp.
- low, reject: Design Notes known limit is stale. Fix edits this spec; Implementation Notes record the correction.
- false: sprint status differs from spec. Step 5 syncs it.

**Found in final verification:** the assembly rename broke `tests/Isolation/packages.lock.json` (NU1004), which would have failed CI. Lockfile regenerated.

## Design Notes

- **`CommandContext`:** only `TenantScope.CreateCommandContext()` makes one. It exposes `TenantId` and `CreateCommand()`, so callers get an enlisted command with no commit method. Only the scope holder commits. Module `DbContext` enlistment arrives with the first module that needs it. `DbCommand.Transaction` still leaks the transaction, so the source rule also bans `.Commit` and `.Rollback` in `Contracts`.
- **Scope shape:**
  ```csharp
  await using var scope = await TenantScope.BeginAsync(dataSource, tenantId, ct);
  await handler.Run(scope.CreateCommandContext(), ct); // contract methods see only this
  await scope.CommitAsync(ct);
  ```
- **Migrations:** hand-written SQL in `Migration` classes on a `MigrationsContext` with an empty model and no snapshot, per the Migrations convention.
- **History table:** `migration_history`, a `control` table owned by Operations with no runtime grants. AD-27 doesn't name it, but AD-3 says every table is listed. Spine catch-up is a deferred item.
- **Initial grants:** only what's named or plainly needed. `gk_hosted`: `SELECT` on all three, as AD-2 bars configuration writes. `gk_admin`: `SELECT, INSERT, UPDATE` on `tenant` and `tenant_settings`, `SELECT, INSERT` on `tenant_host`, as rows are never deleted (AD-6). `gk_worker`: `SELECT` on all three. `gk_cli`: `SELECT` on `tenant` (AD-4). `gk_dispatch`, `gk_sealer`, `gk_retention`: none. Later stories add theirs.
- **Columns:** minimum only. `tenant(id, created_at)`, `tenant_host(host, tenant_id, kind, created_at)`, `tenant_settings(tenant_id, created_at, updated_at)`. Story 1.27 adds the issuer, RP ID and label. `tenant_settings` references `tenant` with a single-column key, which AD-1 allows.
- **Known limit:** the failing cast fires per row, so an unscoped query on an empty table returns nothing rather than raising. Tests seed rows, and `TenantScope` being the only path is the control there. The threat model records this.
- **Tests:** Testcontainers, as it needs no extra CI service and works with local Docker. The tests run `roles.sql` as superuser, set test passwords, then call the real migrator as `gk_migrator`.

## Verification

**Commands:**
- `dotnet restore Gatekeep.slnx --locked-mode` -- expected: succeeds with updated lockfiles.
- `dotnet build Gatekeep.slnx --no-restore` -- expected: no warnings.
- `dotnet test tests/Architecture --no-build` -- expected: all pass.
- `dotnet test tests/Isolation --no-build` -- expected: all pass against `postgres:18.6`.
- `dotnet run --project tests/Architecture/Generator` -- expected: no diff after committing the diagram.

## Implementation Notes

- **Known limit differs from the Design Notes.** On `postgres:18.6`, an unscoped `SELECT` on an empty `tenant_settings` raised `42704` rather than returning nothing, because the planner evaluates the setting for selectivity. The real limit is narrower: a query that evaluates the policy for no row, such as `WHERE false`, returns nothing. Both are tested, and `docs/threat-model.md` T-1 records the tested behaviour. The plan-time error isn't a guarantee.
- **Edges beyond the Code Map:** `dependency Tests.Isolation -> Adapters.Postgres` and `dependency Tests.Isolation -> Cli`, because `Project_references_equal_the_edge_list_exactly` covers `tests`. The second builds the real command for the process-level migrate tests. Both now show in the generated diagram.
- **Added beyond the catalogue criteria:** the audit also refuses unregistered views, sequences not owned by `gk_migrator`, role membership, `CREATEROLE`, `CREATEDB`, schema grants beyond `USAGE`, and foreign keys that aren't `ON DELETE RESTRICT`.
- **Module assemblies:** `PersistenceRuleTests` loads module DLLs from their build output, so tests add no module edges. It needs the same configuration built first, as CI does.
- **History columns:** `migration_history` keeps EF's `MigrationId` and `ProductVersion` names, which aren't `snake_case`.
- **Grant change from the Design Notes:** `gk_admin` has `SELECT, INSERT` on `tenant`, not `UPDATE`. Its only columns are `id` and `created_at`, so `UPDATE` had no use and could rewrite a Tenant ID. Story 1.27 adds its own grant with the columns that need it.
- **Database grants:** `roles.sql` also limits `CONNECT` to the eight roles. PostgreSQL does not copy a template database ACL, so the test fixture reruns `roles.sql` without its `CREATE ROLE` lines on each clone.
