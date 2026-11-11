---
title: 'Story 3.1: List and create Applications'
type: 'feature'
created: '2026-11-11'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-3-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-2-11-offer-userinfo-and-revocation.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** Applications exist in the database (Stories 2.5 and 2.8), but an Admin can't see or register one. Only tests and the system path create them, always with a secret and as `Actor.System`, and there are no single-page or native types (FR-11, FR-44, UX-DR44, AD-20).

**Approach:**
- Add Tenant-scoped Admin API routes to list, read and create Applications, reached through Management and then Directory.
- Support the four types: single-page `spa`, regular web `web`, native `native` and machine-to-machine `machine`.
- Create an Application with no secret, as the calling Admin. Secrets come in Story 3.3.
- Build the Applications list, the Create Application modal and a minimal Application detail page in the Admin Dashboard.
- Make signing in land on the current Tenant's Applications list.

## Boundaries & Constraints

**Always:**
- **Routes** go on Host.Admin in `AdminApi.MapAdminApi`, all as `TenantApiEndpoint` routes:
  - `GET /api/v1/tenants/{tenantId}/applications` (cursor, 50 per page, newest first)
  - `GET /api/v1/tenants/{tenantId}/applications/{applicationId}`
  - `POST /api/v1/tenants/{tenantId}/applications`
- **Capabilities:** reads require `AdminCapabilities.TenantConfigurationRead`; create requires `TenantApplicationsManage` (Editors and up, machine allowed, no fresh assertion). Management re-checks with `AdminCapabilities.Allows` and refuses with `Forbidden`, as `SigningKeyManagement` does.
- **Create body** is `{ "name": string, "type": "spa"|"web"|"native"|"machine" }`. The name is trimmed, 1 to 200 characters, and duplicates are allowed.
  - Validation failures are RFC 9457 400s with a stable `code`. Any new code is added to `AdminResponses` `ProblemCodes`.
  - The write requires the `X-Gatekeep-Tenant` header and documents 409 `tenant_mismatch`, like `TenantLabelApi`.
- **Application resource:** `{ id, clientId, name, type, credentialRequired, createdAt }`.
  - `id` and `clientId` are both the `app_…` public ID (`PublicId.Format(PublicIdType.Application, id)`).
  - `credentialRequired` is true exactly for `web` and `machine`.
  - Create answers 201 with this resource and a `Location` header.
- **Created defaults:**
  - Each type gets: `machine` → grants `{client_credentials}`; `web` → `{authorization_code}`; `spa` and `native` → `{}`.
  - Every type starts with no redirect URIs, no audiences and no `client_secret` row.
  - URLs and grants are Story 3.2.
- **Audit:** one `CommandContext` command inserts the row and writes `directory.application.created` with `Actor.Admin(principal.AdminId)` (or the machine principal's actor), in one transaction. Update the event's catalogue description and `docs/audit-events.md` so it no longer promises a secret.
- **System Application:** it stays hidden through `ApplicationRows.Visible` from the list and from GET-by-id. Another Tenant's ID, a malformed ID and the system Application's ID all get the same 404 `not_found`.
- **Migration** (`Migration20261113000000AddApplicationTypes`):
  - Widen the `kind` CHECK to `('machine','native','spa','system','web')`.
  - Redefine `application_redirect_uris` so `web` allows 0 to 10 redirect URIs with grants `{authorization_code[, refresh_token]}`, and every other kind has none.
  - Keep the system Application rules intact.
  - Bump `MigrateCommandTests` to 29.
- **Protocol paths:** Directory's protocol paths (`ApplicationStore`, `VerifyClientSecretAsync`, authorize) keep working for every kind.
  - An `spa` or `native` Application, or one with no secret, can't obtain any token. The existing grant and permission mapping already refuses it; prove it with a test.
- **Admin Dashboard:**
  - Sidebar entry "Applications" in the existing `applications` group.
  - The list is a `DataTable` with columns Name, Type, Client ID (mono, Copy) and Created, plus "Load more" when `nextCursor` is present.
  - Empty state: "No applications yet" with Create application.
  - The create button and empty-state action show only when the caller's capabilities include `tenant.applications.manage`.
  - The Create Application modal has a name field and a type `Choice`. Each type's description says whether it needs a credential. On success it navigates to the detail page.
  - The detail page shows a breadcrumb (Applications / name), the name and a type badge, the client ID with Copy, and a Credentials section:
    - `web`/`machine`: "Needs a client secret. A Tenant Owner creates it."
    - `spa`/`native`: "No secret needed."
  - Load failure shows a `Banner` with Retry and `ErrorReference`, and a 403 renders `ForbiddenPage`, as `SigningKeysPage` does.
- **Landing:** `LandingPage` and the `/tenants/{id}` redirect in `Shell.tsx` go to `/tenants/{id}/applications`.
- **API contract:** `docs/api/openapi-v1.json` and `packages/api-client` are regenerated, with typed client methods added.

**Never:**
- No secret creation or reveal, URL editing, grant editing, lifetimes, deletion, type filter chips, Logins 30d or Last used columns, `client_usage`, or Quickstart/Connections tabs. Those are later stories.
- No Design Delta removals reintroduced: Dynamic registration, SDK column, AI-agent and Third-party filters.
- Host.Admin never references Directory directly.
- Don't change `CreateMachineClientAsync` or `CreateWebClientAsync` behaviour that existing tests rely on.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Editor creates each type | `POST` name "Web", each of 4 types | 201, `app_` client ID, `credentialRequired` true only for web/machine, one `directory.application.created` event with the Admin actor, no `client_secret` row | — |
| Owner creates | Owner session | Same as Editor | — |
| Viewer creates | Viewer session | 403 `access_denied`, nothing written | denial audited as today |
| Machine principal without the capability | `TestOnlyMachinePrincipal` lacking `tenant.applications.manage` | Refused (Management `Forbidden`) | — |
| Bad name | `""`, whitespace, 201 chars | 400 with stable code, nothing written | RFC 9457 |
| Bad type | `"system"`, `"implicit"`, missing | 400 with stable code | RFC 9457 |
| Duplicate name | same name twice | two Applications, distinct client IDs | — |
| List | 0 apps / 51 apps | `[]` / 50 newest then `nextCursor` to the 51st; system Application never listed | bad cursor → 400 |
| Cross-Tenant | Tenant B's Admin reads or creates under Tenant A's path, or GETs A's app under B | refused (403 per the route checks; 404 for a foreign app ID under own Tenant) | registered in `RouteRegistry` |
| Header mismatch | `X-Gatekeep-Tenant` ≠ path | 409 `tenant_mismatch` | — |
| Inert new clients | token request from a new spa/native app, or a new web/machine app with no secret | `invalid_client` or refusal; no token issued | — |

</intent-contract>

## Code Map

- `src/Adapters/Postgres/Migrations/Migration20261106000000CreateDirectoryTables.cs:32-57` -- original `application` table, RLS and grants (`:101-138`)
- `src/Adapters/Postgres/Migrations/Migration20261110000000CreateCodeFlow.cs:27-37`, `Migration20261111000000AllowRefreshTokens.cs:35-44` -- current `kind` and `application_redirect_uris` CHECKs to redefine
- `src/Adapters/Postgres/Migrations/Migration20261109000000AddSystemApplication.cs:51-115` -- system kind, GK011–GK013 guards; keep intact
- `src/Adapters/Postgres/Schema/TableRegistry.cs:592-612` -- `application` entry; update only if grants change (they shouldn't: Admin already has SELECT and INSERT)
- `src/Modules/Directory/Contracts/IDirectory.cs:47,67,106` -- existing creates and the unpaginated `ListApplicationsAsync`; add a paginated list, a get-by-id and a no-secret create that takes the actor
- `src/Modules/Directory/Contracts/DirectoryApplication.cs`, `DirectoryContract.cs` -- Kind constants (`WebKind`); add `SpaKind`, `NativeKind`, `MachineKind` and a credential-required helper
- `src/Modules/Directory/Core/DirectoryService.cs:23-46,84-141,257,265` -- insert SQL, `CreateClientAsync` (UUIDv7, audit with `Actor.System`; comment at `:130` anticipates the Admin actor), `ApplicationRows.Visible`
- `src/Modules/Directory/Core/DirectoryEvents.cs`, `docs/audit-events.md:31` -- `directory.application.created` wording
- `src/Modules/Directory/Adapters/ApplicationStore.cs:85,102` -- permissions and PKCE requirement from `IsWeb`; new kinds fall through to no code permissions
- `src/Gatekeep.Kernel/Identifiers/PublicId.cs:28-31,75` -- `app_` public ID
- `src/Modules/Management/Core/SigningKeyManagement.cs:36`, `TenantManagement.cs:42,78` -- Management re-check and `Actor.Admin` pattern; add an `ApplicationManagement` (or similar)
- `src/Gatekeep.Host.Admin/AdminApi.cs:92,237,603-660,967` -- route mapping, capabilities endpoint, signing keys and label routes to copy
- `src/Gatekeep.Host.Admin/SigningKeysApi.cs:72-108`, `TenantLabelApi.cs:73-150` -- read handler and Tenant-path write handler (`TenantScope.BeginAsync`, `CommitAsync`, SqlState mapping)
- `src/Gatekeep.Host.Admin/TenantsApi.cs:174-180,246-275` -- cursor and `PageSize = 50`
- `src/Gatekeep.Host.Admin/AdminResponses.cs:126-148,180,242,253` -- problem codes and helpers
- `src/Gatekeep.Host.Admin/AdminApiServices.cs:76` -- service registration
- `src/Gatekeep.Host.Admin/AdminRequestChecks.cs:22-75` -- `TenantApiEndpoint`, `RequiresCapability`, `JsonRequestBody`
- `src/Modules/Admins/Contracts/AdminCapabilities.cs:132,144,242-263` -- capabilities used; no new capability needed
- `apps/admin-dashboard/src/shell/{nav.ts:33-53, Shell.tsx:165,167,491,507-530, LandingPage.tsx:13,40, SigningKeysPage.tsx, TenantsPage.tsx:62,330}` -- nav, routing, landing and page templates
- `packages/ui/src/components/{EmptyState.tsx, Modal, Choice, Banner, DataTable}`, `adminNav.tsx:44`, `messages.tsx:528` -- reusable UI
- `packages/api-client/src/client.ts:9-41,246-290`, `schema.generated.ts`, `docs/api/openapi-v1.json`, `deploy/docker/api-contract.sh` -- contract (regenerate with `docker compose -f deploy/compose.dev.yaml run --rm --build -v "<repo>:/out" tests sh deploy/docker/api-contract.sh --write /out`)
- `tests/Isolation/Keys/SigningKeysApiTests.cs`, `tests/Isolation/Tenancy/TenantRequests.cs:34,45,89,101`, `tests/Isolation/Admins/AdminHost.cs`, `TestOnlyMachinePrincipal.cs` -- test patterns and helpers
- `tests/Isolation/CrossTenant/RouteRegistry.cs:92-99`, `tests/Isolation/Canary/CanaryFlows.cs:187,293,374-380` -- route registration and canary surfaces
- `tests/Isolation/MigrateCommandTests.cs:20,43` (+ `Assert.Equal`) -- migration count 28 → 29
- `tests/browser/admin-signing-keys.spec.ts`, `admin-shell.spec.ts:568`, `admin-tenant-switcher.spec.ts:407,431,441,446,474,603`, `admin-tenants.spec.ts:56`, `admin-tenant-delete.spec.ts:496,539,558,583` -- browser test template and landing assertions to move to `/applications`
- `design/Gatekeep Admin.dc.html:265-444` -- Applications and Application detail screens

## Tasks & Acceptance

**Execution:**
- `src/Adapters/Postgres/Migrations/Migration20261113000000AddApplicationTypes.cs` -- widen kind CHECK; let `web` have 0–10 redirect URIs -- create with only name and type
- `src/Modules/Directory/{Contracts,Core}` -- kind constants and `CredentialRequired`; `CreateApplicationAsync(ctx, actor, name, kind)` with no secret; `ListApplicationsPageAsync(ctx, cursor, 50)`, keyset on `id` desc; `FindApplicationAsync(ctx, id)`, all honouring `Visible`; update event wording -- Directory owns the table
- `src/Modules/Management/Core/ApplicationManagement.cs` (+ contract) -- capability re-check and mapping to Directory -- Host.Admin → Management → Directory edge
- `src/Gatekeep.Host.Admin/{ApplicationsApi.cs, AdminApi.cs, AdminApiServices.cs, AdminResponses.cs}` -- three routes with metadata, validation, problem codes and the Location header -- API surface
- `docs/api/openapi-v1.json`, `packages/api-client/src/{schema.generated.ts, client.ts}` -- regenerate and add `listApplications`, `getApplication`, `createApplication` -- contract diff in CI
- `apps/admin-dashboard/src/shell/{ApplicationsPage.tsx, ApplicationDetailPage.tsx, CreateApplicationModal.tsx, nav.ts, Shell.tsx, LandingPage.tsx}` plus `packages/ui` messages -- screens and landing
- `tests/Isolation/Applications/ApplicationsApiTests.cs` -- every I/O matrix row, including the inert-client token refusals and audit actor
- `tests/Isolation/CrossTenant/RouteRegistry.cs`, `tests/Isolation/Canary/CanaryFlows.cs`, `tests/Isolation/MigrateCommandTests.cs`, `tests/Isolation/Directory/DirectoryTests.cs` -- register routes, canary surfaces (no credential returned), migration count, Directory-level create and list tests
- `tests/browser/admin-applications.spec.ts` + landing assertions in the four existing specs -- empty state with and without the button, list, Load more, create flow per type, detail Credentials copy, banners, axe light/dark at 1100 and 768 px

**Acceptance Criteria:**
- Given a Tenant with no Applications, when an Editor opens Applications, then "No applications yet" shows with Create application; a Viewer sees the same state with no button.
- Given an Admin with a Tenant, when they sign in, then that Tenant's Applications list opens.
- Given a created Application, when its detail opens, then the client ID shows with Copy, and Credentials says a secret is needed for regular web and machine-to-machine and "No secret needed." for single-page and native.
- Given the API changes, when CI runs the contract check, then `openapi-v1.json` and `schema.generated.ts` match the live routes, and the cross-Tenant, canary and capability suites pass with the new routes registered.

## Design Notes

- **Kind names stay as stored:** `web` and `machine` already exist, so the API exposes the stored kinds directly rather than mapping new names. UI labels: Single-page, Regular web, Native, Machine-to-machine.
- **No secret at create:** Story 3.3 adds Owner secret creation and the reveal (epic context: "Until then, creation follows the Editor path"). A web or machine Application without a secret fails client authentication, so it is inert until then. That is acceptable.
- **SPA and native get no grants yet:** public-client token exchange isn't built. Empty grants keep them inert, and 3.2 makes them configurable.

## Verification

**Commands:**
- `dotnet build Gatekeep.slnx` in the SDK container -- expected: 0 errors, 0 warnings
- `pnpm -r build` and `pnpm -r typecheck` (as the repo defines) -- expected: clean
- Don't run the test suites locally. CI on the PR is the test run.
