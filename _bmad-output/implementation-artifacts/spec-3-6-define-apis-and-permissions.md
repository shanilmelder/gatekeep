---
title: 'Story 3.6: Define APIs and Permissions'
type: 'feature'
created: '2026-11-14'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-3-context.md'
warnings: ['multiple-goals', 'oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** A Tenant can't register the resource servers its tokens are for. There is no `api` or `permission` table, no built-in Management API record, and no API lifetimes for Story 3.7's grants and audiences to build on (FR-16, FR-15).

**Approach:**
- Directory gains `api` and `permission`.
- Editors and Owners create APIs, add and remove `resource:action` Permissions, and set offline access, RBAC and the four token lifetimes.
- Every Tenant gets a built-in Management API (`urn:gatekeep:management`), seeded with one Permission for each machine-allowed Tenant capability:
  - at Tenant activation;
  - by a migration backfill for existing Tenants;
  - by the hourly backfill job.
- Protocol's single lifetime lookup takes an optional API and applies the shorter value for each lifetime.

## Boundaries & Constraints

**Always:**
- **Who can do what:** reads need `tenant.configuration.read` (everyone). Writes need `tenant.apis.manage` (Editors and Owners, machine allowed, no fresh assertion). It already exists in `AdminCapabilities` with no route.
- **Routes,** under `/api/v1/tenants/{tenantId}`:
  - `GET /apis`: cursor pages of 50, the built-in first, then newest.
  - `POST /apis` with `{name, identifier}`: answers 201.
  - `GET /apis/{apiId}`: includes its Permissions.
  - `PUT /apis/{apiId}/settings` with `{offlineAccess, rbac, accessTokenLifetime, idTokenLifetime, refreshTokenAbsoluteLifetime, refreshTokenInactivityLifetime}`.
  - `POST /apis/{apiId}/permissions` with `{value, description}`: answers 201.
  - `DELETE /apis/{apiId}/permissions/{value}`: answers 204.
  - Public IDs are `api_…`. A Permission is addressed by its value.
- **Identifier rules:**
  - 1–255 characters, an absolute URI (it has a scheme), no fragment.
  - Exact, case-sensitive match, unique per Tenant (a unique index). A duplicate is a 409 `api_identifier_taken`, shown inline.
  - The `urn:gatekeep:` prefix is reserved and refused (400 `reserved`).
  - Never updatable: the API offers no route for it, and gk_admin has no UPDATE grant on the column.
- **Name:** 1–200 characters, trimmed. Duplicates are allowed.
- **Permission rules:**
  - The value matches `^[a-z0-9][a-z0-9_.-]{0,63}:[a-z0-9][a-z0-9_.-]{0,63}$` and is unique per API (409 `permission_taken`).
  - The description is 0–200 characters.
  - At most 200 Permissions per API.
- **Lifetimes:** API columns hold the same four values with the same defaults, CHECK limits and `above_maximum`/`maximum` errors as Story 3.4's Application lifetimes (§5.2). Reuse those rules and types.
- **Built-in Management API:**
  - Name "Gatekeep Management API", identifier `urn:gatekeep:management`, `built_in = true`, `offline_access = false`, `rbac = false`.
  - Its Permissions are the `resource:action` form of every Tenant capability with `MachineAllowed = true`, where `tenant.applications.manage` becomes `applications:manage`. That gives 18: configuration:read, users:read, logs:read, log_detail:read, applications:manage, apis:manage, roles:manage, users:manage, theme:manage, templates:manage, settings:manage, connections:toggle, configuration:export, password_policy:manage, connection_credentials:manage, signing_keys:rotate, user_data:export, user_data:erase.
  - The list is a Directory constant. An Architecture test pins it to the set derived from `AdminCapabilities`. The migration embeds it literally.
  - Its settings and lifetimes are editable like any API's (decision on 2026-11-14). Its identifier and Permissions are not: adding or removing one answers 409 `api_built_in`.
- **Seeding is idempotent** (`EnsureBuiltInApiAsync`), with the same three call sites as the system Application in Story 2.8:
  - `TenantCreation.ActivateAsync`;
  - a `ForEachTenant` backfill in the migration;
  - `TenantKeyBackfill`.
- **Audit:** every write is one command with one event: `directory.api.created`, `directory.api.updated` (settings or lifetimes; none when nothing changes), `directory.api.permission_added` and `directory.api.permission_removed`. The target is a new `AuditTargetKind.Api`. Seeding writes no event, like the system Application.
- **Shorter wins:**
  - Change `ApplicationTokenLifetimes.Of(application)` to `Of(application, api?)`. Each of the four lifetimes is the minimum of the two, and with no API it is the Application's value.
  - Every caller passes `null` until Story 3.7 resolves the audience.
- **Tables:** `api` and `permission` are Directory `tenant` class tables, with RLS, `tenant_row_guard`, composite foreign keys `ON DELETE RESTRICT`, registry entries and grants, all in one migration. Directory's Tenant purge deletes `permission`, then `api`.
- **Dashboard:**
  - **APIs page:** an APIs entry in the Applications nav group. The table has columns Name, Identifier, RBAC and Access token lifetime, with a "Built-in" badge.
  - **Create API modal:** name and identifier. Under the identifier, the advice reads: "Use a different identifier in each environment, such as Dev, Staging and Prod, so a token for one is never accepted by another. It can't be changed later."
  - **API detail, Settings:** the identifier shown read-only with "Can't be changed.", offline access ("Issue refresh tokens for this API"), "Enable RBAC", the four lifetimes as in Story 3.4, and a save toast.
  - **API detail, Permissions:** "No permissions yet" with Add, and a table of Permission and Description with Remove (none on the built-in API).
  - **Viewers** see everything read-only.
- **Validation runs on the server.** Browser checks are feedback only (UX-DR42). Errors are RFC 9457 with machine codes and per-field `errors`.
- **New routes join** the cross-Tenant suite, the canary, the capability tests, the OpenAPI document and the api-client.

**Never:**
- No `api_grant` table.
- No audiences or scopes in tokens, and no removal of the placeholder audience or the `invalid_target` refusal. Those are Story 3.7.
- No API deletion and no Permission editing; only add and remove.
- No HS256, algorithm, consent or "permissions claim" controls (UX-DR44).
- No Management API token endpoint (Epic 17).
- No change to the system Application.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| New Tenant | creation Operation completes | the list shows the built-in API with its 18 Permissions | No error expected |
| Existing Tenant | migration runs, rerun of backfill job | exactly one built-in API with 18 Permissions; reruns add nothing | No error expected |
| Create | Editor, `{name, identifier:"https://api.example.com"}` | 201, defaults (offline false, RBAC false, 900/900/2592000/604800). One `created` event. Listed after built-in. | No error expected |
| Duplicate identifier | same identifier in same Tenant; same in other Tenant | first 409; second 201 | 409 `api_identifier_taken` |
| Bad identifier | `""`, `api.example.com`, with `#frag`, 256 chars, `urn:gatekeep:x` | 400 with field error, nothing written | `invalid` / `reserved` |
| Add Permission | `invoices:read`, then again; `Invoices:read`, `invoices`, `:read` | 201, then 409; others 400 | `permission_taken` / `invalid` |
| Built-in Permissions | add or remove on the Management API | 409, nothing written | `api_built_in` |
| Settings | toggle RBAC; lifetime 3601 | 200 + one `updated` event; 3601 → 400 `above_maximum` with `maximum` 3600 | as Story 3.4 |
| Unchanged save | same values | 200, no event | No error expected |
| Viewer / other Tenant | Viewer writes; another Tenant's API id | 403; same 404 as an unknown id | `forbidden` / `not_found` |
| Shorter wins | App access 900, API 600; App 300, API 900; no API | 600; 300; 900 | No error expected |

</intent-contract>

## Code Map

- **Limits:** `src/Gatekeep.Kernel/Limits/SecurityLimits.cs:165-219` holds the lifetime defaults and hard limits. Add the API and Permission limits here.
- **Migrations:**
  - The RLS and table pattern is `src/Adapters/Postgres/Migrations/Migration20261106000000CreateDirectoryTables.cs:26,56,101-131`.
  - The backfill pattern is `Migration20261109000000AddSystemApplication.cs:36-41,124`, with `Migrations/ForEachTenant.cs`.
  - The CHECK pattern is `Migration20261116000000SetTokenLifetimes.cs`. `tests/Architecture/TokenLifetimeLimitTests.cs:16-42` pins that file, so extend the test to cover the new migration's API columns.
  - The latest migration is `Migration20261117000000DeleteApplications.cs`. Update the count in `tests/Isolation/MigrateCommandTests.cs:20,43,78` from 33 to 34.
- **Registry:** `src/Adapters/Postgres/Schema/TableRegistry.cs:612-652` has the `application` and `client_secret` entries to copy. `tests/Isolation/CatalogueTests.cs:23` checks them.
- **Directory:**
  - `Contracts/IDirectory.cs:81-291`, including `EnsureSystemApplicationAsync` at :276.
  - `Core/DirectoryService.cs`:
    - the lifetimes command at :334-375;
    - `EnsureSystemApplicationAsync` at :601-625;
    - `ApplicationRows` at :675-701 (keyset paging, `FOR NO KEY UPDATE`).
  - `Contracts/ApplicationLifetimes.cs:11-76` and `Core/ApplicationLifetimeRules.cs` are the rules to reuse.
  - `Contracts/DirectoryEvents.cs`, `Contracts/DirectoryContract.cs:107,124`, `Core/DirectoryPurge.cs:15-16`.
  - Regenerate the audit catalogue: `docs/audit-events.md` and `LogCatalogue.Generated.cs`, through `tests/Architecture/Generator/AuditCatalogue.cs`.
- **Kernel:**
  - `src/Gatekeep.Kernel/Audit/AuditEvent.cs:3` is the `AuditTargetKind` enum. Check whether a database CHECK or a generated list pins it.
  - `src/Gatekeep.Kernel/Identifiers/PublicId.cs:4,75-85` needs the `api_` prefix.
- **Capabilities:** `src/Modules/Admins/Contracts/AdminCapabilities.cs:132,148`. The Management Permissions come from the `MachineAllowed` Tenant capabilities at :132-176.
- **Management:** `src/Modules/Management/Contracts/IApplicationManagement.cs` and `Core/ApplicationManagement.cs:24,66,187-223,394,401` are the pattern. Add a new `IApiManagement`, registered next to `CreateApplications` (`ManagementContract.cs:31-61`).
- **Host.Admin:**
  - `src/Gatekeep.Host.Admin/AdminApi.cs:637-858` for the route metadata.
  - `ApplicationsApi.cs:10-145,389,575` for the DTOs, body caps and refusals; add a new `ApisApi.cs`.
  - `AdminResponses.cs:138-168` for the problem codes and `AdminOpenApi.cs:181-225,499` for the schemas.
  - Regenerate with `deploy/docker/api-contract.sh --write`.
- **Operations:**
  - `src/Modules/Operations/Core/TenantCreation.cs:127-133` (`ActivateAsync`).
  - `Core/TenantKeyBackfill.cs:61`.
  - Tests: `tests/Isolation/Operations/TenantCreationOperationTests.cs:54-73,594` and `tests/Isolation/Keys/TenantKeysTests.cs`.
- **Protocol:** `src/Modules/Protocol/Core/ApplicationLifetimes.cs:13-66`. The doc at :19-23 names this story. Callers: `RefreshTokens.cs:64,168,271-298`.
- **API client:** `packages/api-client/src/client.ts:46-62,331-345`.
- **Dashboard:**
  - Nav: `apps/admin-dashboard/src/shell/nav.ts:35-60`.
  - Routing: the if-chain in `Shell.tsx:514-545`.
  - Paths and lifetime helpers: `shell/applications.ts:29-44,160-227`.
  - Pages to copy: `ApplicationsPage.tsx`, `CreateApplicationModal.tsx`, `ApplicationDetailPage.tsx`, `ApplicationTokens.tsx`, `ApplicationSettings.tsx`.
  - Copy: `packages/ui/src/messages.tsx:456-604,892+`.
  - Design: `design/Gatekeep Admin.dc.html:1252,1265`.
- **Tests to copy:**
  - `tests/Isolation/Applications/{ApplicationsApiTests, ApplicationSettingsApiTests, ApplicationTokensApiTests}.cs`;
  - `CrossTenant/RouteRegistry.cs:98-107`, `Canary/CanaryFlows.cs:402-425`, `Admins/CapabilityMatrixTests.cs:42`;
  - `tests/Architecture/{CapabilityRuleTests, AdminApiRuleTests, AuditCatalogueTests, TenantKeyedTypes}.cs`;
  - `tests/browser/admin-applications.spec.ts`.

## Tasks & Acceptance

**Execution:**
- [ ] **Migration** `Migration20261118000000DefineApis.cs` with `TableRegistry.cs`:
  - `api` (id, name, identifier, built_in, offline_access, rbac, the four lifetimes with CHECKs, created_at, and a unique index on `(tenant_id, identifier)`);
  - `permission` (`api_id`, value, description, created_at, unique on `(tenant_id, api_id, value)`);
  - RLS, the guards and grants;
  - the `ForEachTenant` built-in backfill.
  - Update the counts and limit pins.
- [ ] **Kernel:** the `api_` public ID type, `AuditTargetKind.Api`, and the limits constants.
- [ ] **Directory:** the contracts, rules, service (create, list, find, update settings, add and remove Permission, `EnsureBuiltInApiAsync`), the four events, and purge. Expose the `ManagementPermissions` constant.
- [ ] **Operations:** call `EnsureBuiltInApiAsync` in `TenantCreation.ActivateAsync` and `TenantKeyBackfill`.
- [ ] **Management:** `IApiManagement` with capability re-checks, mapped results and field errors.
- [ ] **Host.Admin:** `ApisApi.cs` and the routes in `AdminApi.cs`, plus problem codes and OpenAPI enums. Regenerate the contract. Add the api-client methods (`listApis`, `getApi`, `createApi`, `updateApiSettings`, `addApiPermission`, `removeApiPermission`) and unit tests.
- [ ] **Protocol:** `ApplicationTokenLifetimes.Of(application, api?)`, with shorter wins per lifetime. Existing callers pass `null`.
- [ ] **Dashboard:** the APIs nav entry, list page, create modal with the environment advice, and detail page with its Settings and Permissions sections. Add the copy to `messages.tsx`, and put the path helpers in a new `apis.ts`.
- [ ] **Isolation tests:** `tests/Isolation/Apis/ApisApiTests.cs` covers the API rows. Built-in seeding at creation, migration backfill and job rerun go in the creation and backfill tests. Cover the shorter-wins row at the `Of` function.
- [ ] **Registries and pins:** `RouteRegistry`, `CanaryFlows`, `CapabilityRuleTests`, `CapabilityMatrixTests` and `AdminApiRuleTests`. Add a new Architecture test that the Management Permissions equal the machine-allowed Tenant capabilities. Grep both test projects for lists pinned on anything you changed (tables, grants, migration count, audit codes, public ID prefixes, target kinds, nav entries) and update them. Stories 3.4 and 3.5 each broke CI by missing one.
- [ ] **Browser tests:** a new `tests/browser/admin-apis.spec.ts`, with the project registered like `admin-applications`. Cover:
  - the list with the built-in badge;
  - create with the advice copy and an inline duplicate error;
  - settings save with a toast and `Maximum is {limit}.`;
  - Permissions empty state, add, a duplicate, and remove;
  - the built-in API having no Add or Remove;
  - the Viewer's read-only view;
  - axe in light and dark.

**Acceptance Criteria:**
- Given an API identifier, when it's created, then it's unique in the Tenant and can never be changed.
- Given a Permission, when it's saved, then it follows `resource:action` and is unique per API.
- Given any Tenant, when APIs loads, then the built-in Management API is listed.
- Given the create form, when it's shown, then it advises different identifiers for Dev, Staging and Prod.
- Given Tenant creation, or an existing Tenant after this ships, when you look at its APIs, then it has the built-in API and its Management Permissions.
- Given an API, when an Editor sets offline access, RBAC or a lifetime, then the value within §5.2 saves and the Log is written.
- Given Application and API lifetimes, when the lifetimes are resolved, then the shorter of each applies.

## Spec Change Log

## Review Triage Log

## Design Notes

- **Why "new tokens for that API use it" isn't visible yet:** no token can name an API until Story 3.7 resolves `resource`/`audience`. So this story makes the one lookup combine both lifetimes and tests it at that function. Story 3.7 passes the resolved API.
- **Why the built-in Management API is editable:** the user chose it on 2026-11-14. §5.2 fixes Management API tokens at 15 minutes, which Epic 17's own token endpoint enforces whatever these values say.
- **Why the API has no "Add permissions in the access token" toggle:** the design shows one, but EXPERIENCE.md's settings list doesn't include it. RBAC is the one switch.

## Verification

**Commands:**
- **.NET build:** with `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors.
- **Contract:** run `deploy/docker/api-contract.sh --write`. Then run `pnpm -r build`, `pnpm -r --if-present typecheck`, and the dashboard and api-client unit tests in the `gatekeep/tests:local` image. Expected: all clean.
- **Targeted suites:** run only the new or changed Isolation and Architecture test classes and the new browser project. Memory is tight, so don't run the full Isolation suite; CI runs it.
