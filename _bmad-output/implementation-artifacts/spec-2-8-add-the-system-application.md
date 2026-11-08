---
title: 'Story 2.8: Add the system Application'
type: 'feature'
created: '2026-11-09'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-2-context.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** AD-12 and AR-43 give each Tenant one hidden system Application. Portal sign-in (Epic 4/16) binds its `signin_transaction` to it, because the Portal isn't an OIDC client. No such row exists: `application.kind` allows only `machine`, Tenant creation makes none, and nothing stops a code or token from naming one.

**Approach:** Add `kind = 'system'` to `application`, with database invariants: exactly one per Tenant, no grants, no audiences, no secret, no authorization or token, never edited, and deleted only by a Tenant purge. Tenant creation's completion handler writes it in the same transaction that activates the Tenant. A migration backfills every existing active Tenant. Directory's read paths filter it out, and Directory exposes its ID for the later Portal binding.

## Boundaries & Constraints

**Always:**
- **One forward-only migration** `Migration20261109000000AddSystemApplication.cs`:
  - `application_kind` CHECK becomes `kind IN ('machine', 'system')`.
  - A new CHECK: `kind <> 'system' OR (grant_types = '{}' AND audiences = '{}')`.
  - `CREATE UNIQUE INDEX application_one_system ON application (tenant_id) WHERE kind = 'system'`.
  - A `BEFORE INSERT` trigger on `client_secret`, `"authorization"` and `token` raises when `NEW.application_id` names a `system` row in that Tenant. It doesn't go on `signin_transaction`, which must bind to the system Application.
  - A `BEFORE UPDATE` trigger on `application` refuses any update of a `system` row, and a `BEFORE DELETE` trigger refuses deleting one unless its Tenant's status is `deleting` or `deleted`, so the purge still works. Both cover a future Epic 3 grant of UPDATE or DELETE.
  - `gk_worker` gets only the grants the completion handler's insert needs. Update `TableRegistry`'s `application` entry to match.
  - The backfill uses `migrationBuilder.ForEachTenant(...)` and inserts the system row only for that Tenant if it's `active` and has none. The ID is a UUIDv7 (`uuidv7()`, Postgres 18), the name is the fixed `Account Portal`, and `created_at` is `now()`.
  - Bump `tests/Isolation/MigrateCommandTests.cs` from 24 to 25 in all four places.
- **Creation:** `TenantCreation.ActivateAsync` calls `IDirectory.EnsureSystemApplicationAsync(context, ct)` in the completion's own Tenant context, only when `Tenants.ActivateAsync` returned true. So activation and the row commit together, and a Tenant being deleted gets no row.
  - Ensure is idempotent. It inserts only if the Tenant has none and returns the ID either way.
  - It writes no audit event of its own. `tenancy.tenant.activated` in the same transaction records the Tenant's creation, and a Log event naming the hidden Application would expose it.
  - The ID is UUIDv7 from the service's `TimeProvider`, and the name is the shared `Account Portal` constant.
- **Directory contract** (`IDirectory`):
  - `EnsureSystemApplicationAsync(CommandContext, CancellationToken) → Task<Guid>`, marked `[StateChanging]`.
  - `FindSystemApplicationAsync(CommandContext, CancellationToken) → Task<Guid?>`, which only reads. It's for the later Portal binding.
  - `ListApplicationsAsync(CommandContext, CancellationToken) → Task<IReadOnlyList<DirectoryApplication>>`, the repository list that Epic 3.1 and 8.6's export build on. It orders by `created_at, id` and never returns the system row.
  - Every method throws `InvalidOperationException` with no Tenant in the context.
- **Read filter:** every Directory query that returns Applications to callers, including `ApplicationRows.FindAsync` behind the OpenIddict store, excludes `kind = 'system'`, using one shared SQL predicate constant. So OpenIddict treats the system `client_id` as unknown: `invalid_client` at `/connect/token`, and later at authorize too. `FindSystemApplicationAsync` is the only query that selects it.
- `DirectoryApplication` stays as it is. The system row never reaches it.

**Never:**
- No Admin UI or API for Applications, no Portal, no `signin_transaction` writes, no authorize endpoint (Epic 3, 4, 16, Story 2.9).
- No change to earlier migrations, and no UPDATE grant on `application` to any role.
- No audit event for the system Application, and no secret for it.
- No new Operation stage, so the plan and stage list for `tenancy.tenant.create` stay unchanged.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Creation | `tenancy.tenant.create` runs to completion | Tenant `active`, exactly one `system` row, empty grants and audiences, no `client_secret` | No error expected |
| Completion repeated | Completion handler runs again for an active Tenant | Still exactly one system row | No error expected |
| Deleting during creation | Deletion started before completion | No system row | `ActivateAsync` false, nothing inserted |
| Backfill | Migrated DB with active Tenants A, B (no system row) and a `deleting` C, before the new migration | A and B get exactly one each, C none | No error expected |
| Ensure twice | `EnsureSystemApplicationAsync` called twice | Same ID returned, one row | No error expected |
| Second system row | Direct insert of a second `system` row | Refused | 23505 |
| System with grants | Insert `system` row with `grant_types` `{client_credentials}` | Refused | 23514 |
| Secret / token / authorization | Insert `client_secret`, `token` or `"authorization"` naming the system row | Refused | Trigger exception |
| Sign-in transaction | Insert `signin_transaction` naming the system row | Accepted | No error expected |
| Edit | Any UPDATE of the system row (as table owner, triggers on) | Refused | Trigger exception; `gk_admin`/`gk_hosted`/`gk_worker` lack UPDATE (42501) |
| Delete, active Tenant | `gk_worker` deletes the system row | Refused | Trigger exception |
| Purge | Tenant deletion runs to completion | System row gone with the rest | No error expected |
| List | Tenant with system + 2 machine apps | List returns the 2 machine apps only | No error expected |
| Token for it | `POST /connect/token` `client_credentials` with the system `client_id` and any secret | 401 `invalid_client`, no `token` row | Same response as an unknown client |
| Store lookup | OpenIddict store `FindByClientIdAsync`/`FindByIdAsync` with the system ID | `null` | No error expected |
| Tenant isolation | Tenant B's context | Can't see or find A's system row | RLS hides it |

</intent-contract>

## Code Map

- `src/Modules/Operations/Core/TenantCreation.cs:113-114` -- `ActivateAsync` completion. Add the ensure call, using a static `IDirectory` from `DirectoryContract.CreateDirectory(Appender, TimeProvider.System)`. The edge `Operations -> Directory` exists (`tests/Architecture/module-edges.txt`). Update the class summary.
- `src/Modules/Tenancy/Contracts/ITenants.cs:184-193` -- `ActivateAsync` returns whether this call activated the Tenant, and does nothing for a deleting Tenant.
- `src/Modules/Directory/Contracts/IDirectory.cs`, `Core/DirectoryService.cs:13-130` -- contract and service. The insert pattern is `InsertApplication` (`:21-25`), and `Add` is at `:124`. `ApplicationRows.FindAsync` (`:158-183`) gets the filter, and the new list and system queries go next to it.
- `src/Modules/Directory/Adapters/ApplicationStore.cs:23-31` -- `FindByIdAsync`/`FindByClientIdAsync` go through `ApplicationRows.FindAsync`. Once that's filtered, no change is needed, but update the summary.
- `src/Modules/Directory/Core/DirectoryPurge.cs:13-17` -- the purge order is unchanged. It runs while the Tenant is `deleting`, which the delete trigger must allow. Confirm that against `src/Modules/Operations/Core/TenantDeletion.cs`.
- `src/Adapters/Postgres/Migrations/Migration20261106000000CreateDirectoryTables.cs:31-40,135-148` -- the `application` table, its CHECK names and grants. `Migration20261105010000RotateSigningKeys.cs:39-46` and `ForEachTenant.cs` show the per-Tenant backfill (FORCE RLS holds the migrator too). `Migration20261105020000DeleteTenants.cs:134-144` shows the trigger-function style (`REVOKE EXECUTE ... FROM PUBLIC`, `GK0xx` error codes). Pick an unused `GK0xx` code.
- `src/Adapters/Postgres/Schema/TableRegistry.cs:562-567` -- `application` grants. `Worker` gains what the insert needs. The registry grant theory checks the actual privileges.
- `tests/Isolation/MigrateCommandTests.cs:20,28,43,78` -- 24 → 25.
- `tests/Isolation/Directory/DirectoryTests.cs` -- existing Directory DB tests (namespace `...Applications`, deliberately). Add the constraint, trigger, ensure, list and RLS cases here. `tests/Isolation/Tenancy/TenantSeeds.cs:20-28` seeds a `machine` Application.
- `tests/Isolation/Operations/TenantCreationOperationTests.cs`, `TenantDeletionOperationTests.cs` -- the creation, repeat, deleting-during-creation and purge rows.
- `tests/Isolation/Protocol/ClientCredentialsTests.cs`, `ProtocolHost.cs` -- the token-for-system-Application row. Follow the unknown-client test.
- The backfill test needs a database migrated up to the previous migration, then seeded, then migrated forward. Look at how `MigrateCommandTests` or existing migration tests drive the migrator. If no target-migration hook exists, run the backfill statement through the same `ForEachTenant` SQL against seeded Tenants.

## Tasks & Acceptance

**Execution:**
- [ ] `src/Adapters/Postgres/Migrations/Migration20261109000000AddSystemApplication.cs`, `TableRegistry.cs`, `MigrateCommandTests.cs` -- the CHECKs, unique index, triggers, `gk_worker` grant and backfill -- the database enforces the invariants.
- [ ] `src/Modules/Directory/**` -- the three contract methods, the shared visible-Application predicate and summaries -- Directory owns Applications.
- [ ] `src/Modules/Operations/Core/TenantCreation.cs` -- ensure on activation -- created with the Tenant.
- [ ] `tests/Isolation/Directory/DirectoryTests.cs`, `Operations/TenantCreationOperationTests.cs`, `Operations/TenantDeletionOperationTests.cs`, `Protocol/ClientCredentialsTests.cs` -- one test per I/O matrix row, against real Postgres.
- [ ] `docs/` -- regenerate anything the generator owns (`dotnet run --project tests/Architecture/Generator`) if registry output changes.

**Acceptance Criteria:**
- Given a Tenant created through `tenancy.tenant.create`, when the Operation completes, then exactly one `system` Application exists for it, and `POST /connect/token` with its `client_id` gets `invalid_client`.
- Given the Directory contract, when Applications are listed or looked up through the OpenIddict store, then the system Application is never returned, and any UPDATE or non-purge DELETE of it is refused by the database.
- Given CI's Architecture and Isolation suites, when they run, then all pass.

## Spec Change Log

## Review Triage Log

## Design Notes

**Why the completion handler.** Tenant creation's start command runs in a Deployment scope, and `application` is a forced-RLS `tenant` table, so the start command can't write the row. The completion handler already runs in the Tenant's own scope and activates the Tenant. Writing the row there means "active" implies "has its system Application" for every new Tenant, with no new stage or retry path.

**Why no audit event.** AD-12 hides the system Application from every list, and the Tenant Log is a list. Its existence is a fixed part of an active Tenant, recorded by `tenancy.tenant.activated`. The migration backfill is a Deployment upgrade, not a Tenant command.

**Database first.** No role can UPDATE `application` today, and only the purge can DELETE. The triggers keep the system row safe when Epic 3 grants edit and delete. The insert triggers make "no code or token is ever issued" hold even if a later store bypasses Directory's filter.

## Verification

**Commands:**
- CI on the PR (`build` job: Architecture and Isolation suites in Docker) -- expected: green. Don't run tests locally.
