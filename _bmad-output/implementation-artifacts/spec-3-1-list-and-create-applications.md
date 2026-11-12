---
title: 'Story 3.1: List and create Applications'
type: 'feature'
created: '2026-11-11'
baseline_revision: '55dacdad8ec85446a78e621f88fb8357b9599082'
status: 'done'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-3-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-2-11-offer-userinfo-and-revocation.md'
warnings: ['oversized']
deferred:
  - summary: >-
      The generated OpenAPI document declares no path parameter for sub-resource IDs (applicationId, operationId, credentialId).
    evidence: |-
      docs/api/openapi-v1.json lists only tenantId for /api/v1/tenants/{tenantId}/applications/{applicationId}; /operations/{operationId} and /deployment/credentials/{credentialId} have the same gap, so the generator predates Story 3.1. Generated clients get no pattern for the ID.
    location: >-
      src/Gatekeep.Host.Admin/AdminOpenApi.cs
    severity: low
  - summary: >-
      ApplicationStore reports every Application to OpenIddict as Confidential and Web, now including the public spa and native kinds.
    evidence: |-
      src/Modules/Directory/Adapters/ApplicationStore.cs:47-57 returns ClientTypes.Confidential for all rows (pre-existing). New spa/native rows have no grants, so no flow reaches it yet; Story 3.2, which gives them grants, must map kind to client type.
    location: >-
      src/Modules/Directory/Adapters/ApplicationStore.cs:47
    severity: low
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

## Spec Change Log

## Review Triage Log

### 2026-11-12 — Review pass
- verdicts: 32 findings — high 0, medium 2, low 25, false 5, maybe-false 0
- findings:
  - `[low]` `[defer]` (Blind) OpenAPI GET detail route lacks the `applicationId` path parameter — real, but every sub-resource route (operations, credentials) has the same generator gap; deferred as pre-existing.
  - `[low]` `[patch]` (Blind) Name bound: the input's `maxLength=200` cuts a pasted padded name before trimming — dropped the input `maxLength`; `checkApplicationName` refuses over-long trimmed names. The OpenAPI `maxLength` describes the trimmed value and is left.
  - `[low]` `[defer]` (Blind) `ApplicationStore` treats spa/native as Confidential — pre-existing store behaviour; inert because spa/native have no grants; deferred to Story 3.2.
  - `[medium]` `[patch]` (Blind) No test that a web Application with zero redirect URIs is refused at `/authorize` — added an authorize case for new web, spa and native Applications in `InertApplicationTests`.
  - `[low]` `[reject]` (Blind) "Newest first" follows UUIDv7 order, not `created_at` — the keyset is a total order with no skips or repeats; only same-millisecond creates can swap places. Unlikely to be noticed, and the fix adds a composite cursor.
  - `[low]` `[patch]` (Blind) The Load more failure banner drops the code and trace ID — `loadMore` keeps the failure and the banner renders `ErrorReference`.
  - `[low]` `[patch]` (Blind) The detail page recomputes `credentialRequired` — it now reads the server's field.
  - `[low]` `[reject]` (Blind) Pages import helpers from each other — cosmetic; no named caller diverges, and the fix is a module move.
  - `[low]` `[patch]` (Blind) `nav.ts` hard-codes the Applications href — uses `applicationsPath`.
  - `[low]` `[patch]` (Blind) The dedupe in `loadMore` is dead code with a wrong comment — removed.
  - `[low]` `[patch]` (Blind) Create modal branches (409, 401, double submit) have no browser coverage — added 409 and 401 browser tests (grouped with the Verification Gap 409 finding).
  - `[low]` `[patch]` (Blind) The control character in the `DirectoryTests` data is invisible — written as an escaped literal.
  - `[low]` `[reject]` (Blind) No per-Tenant cap on Applications — only Editors of the Tenant can create, and the epic sets no quota. The fix adds a new limit and refusal.
  - `[false]` `[reject]` (Blind) The spec records nothing delivered — the finalize step writes the Auto Run Result after review; it hadn't run yet.
  - `[low]` `[patch]` (Verification Gap) The create route's 4096-byte cap and non-JSON refusal are untested — added oversized and `text/plain` cases to the bad-body theory.
  - `[low]` `[patch]` (Verification Gap) Load more's failure banner and Retry are untested — added a browser test with a failing cursor read and Retry.
  - `[low]` `[patch]` (Verification Gap) Create's 409 `tenant_mismatch`, 401 and network branches are untested — added 409 and 401 browser tests.
  - `[low]` `[patch]` (Verification Gap) Shell routing for reserved or undecodable Application IDs is not exercised — added browser navigations to `applications/logs`, `applications/settings` and an undecodable ID.
  - `[medium]` `[patch]` (Verification Gap) A web Application with zero redirect URIs reaches `/authorize` untested — same fix as the Blind Hunter's authorize finding.
  - `[low]` `[patch]` (Verification Gap) The "empty or too long name" browser test checks only the empty name — it now checks too-long and control-character names too.
  - `[low]` `[defer]` (Verification Gap) `ApplicationStore` reports spa/native as Confidential and Web — same deferred entry as the Blind Hunter's.
  - `[low]` `[reject]` (Edge Case) A late 201 after the modal unmounts navigates to the old Tenant — the modal overlays the shell, so the Tenant switcher can't be used during a create. Unlikely, and the fix adds a lifetime guard.
  - `[low]` `[patch]` (Edge Case) A 401 after renewal shows nothing in the modal — now shows `actionRetryAfterSignIn`, as `DeleteTenantModal` does.
  - `[false]` `[reject]` (Edge Case) A 201 without an `id` shows a failure and invites a duplicate — `ApplicationsApi.CreateAsync` always writes the JSON resource with its 201, so the case can't come from this server.
  - `[low]` `[patch]` (Edge Case) `maxLength` truncates a padded paste — same fix as the Blind Hunter's name-bound finding.
  - `[low]` `[reject]` (Edge Case) JS `trim()` and .NET `Trim()` strip different characters (U+FEFF, U+0085) — the server decides and the browser check is feedback only. A rare case, and the fix is a shared custom trim.
  - `[low]` `[reject]` (Edge Case) A double-clicked Load more Retry sends two reads — reads are idempotent and the keyset makes the outcome the same. The fix adds a guard.
  - `[false]` `[reject]` (Intent) UI criteria are tested only against a mocked API — that is the repo's browser-test convention; Isolation tests cover the server, and the contract diff binds the two.
  - `[low]` `[patch]` (Intent) The credential need is derived twice — same fix as the Blind Hunter's: the UI uses the server's field.
  - `[false]` `[reject]` (Intent) Machine-principal refusal is tested below HTTP — no machine HTTP scheme exists until Epic 17, and the matrix row names the Management refusal.
  - `[false]` `[reject]` (Intent) The redirect-URI CHECK relaxation widens beyond "list and create" — creating a regular web Application with only a name and type requires it, as the spec's Boundaries state.
  - `[low]` `[reject]` (Intent) The "no control character" name rule isn't in the spec — it matches the Tenant name rule and refuses only unprintable names; no harm named.

## Design Notes

- **Kind names stay as stored:** `web` and `machine` already exist, so the API exposes the stored kinds directly rather than mapping new names. UI labels: Single-page, Regular web, Native, Machine-to-machine.
- **No secret at create:** Story 3.3 adds Owner secret creation and the reveal (epic context: "Until then, creation follows the Editor path"). A web or machine Application without a secret fails client authentication, so it is inert until then. That is acceptable.
- **SPA and native get no grants yet:** public-client token exchange isn't built. Empty grants keep them inert, and 3.2 makes them configurable.

## Verification

**Commands:**
- `dotnet build Gatekeep.slnx` in the SDK container -- expected: 0 errors, 0 warnings
- `pnpm -r build` and `pnpm -r typecheck` (as the repo defines) -- expected: clean
- Don't run the test suites locally. CI on the PR is the test run.

## Auto Run Result

**Summary.** Admins can list, read and create a Tenant's Applications through the Admin API and the Admin Dashboard. Signing in now lands on the Tenant's Applications list (FR-11, FR-44, UX-DR44, AD-20).

**API** (Host.Admin, through Management and then Directory):
- `GET /api/v1/tenants/{tenantId}/applications` lists newest first, 50 per page, with an `app_` cursor.
- `GET .../applications/{applicationId}` reads one. An unknown, malformed, other-Tenant or system ID gets the same 404 `not_found`.
- `POST .../applications` takes `{name, type}`. It answers 201 with `Location`, or 400 `application_invalid`, 403 or 409 `tenant_mismatch`.
- Create runs as the calling Admin (or machine client) and writes no secret. One transaction writes the row and `directory.application.created`.
- `credentialRequired` is true for `web` and `machine`.
- New Applications are inert. `spa` and `native` get no grants, and no type can get a token without a secret. Tests prove this at the token endpoint and at `/authorize`.

**Database:** migration 29 (`AddApplicationTypes`) adds the `spa` and `native` kinds, and lets a `web` row start with no redirect URI.

**Dashboard:**
- The Applications list has Copy, Load more and the "No applications yet" empty state. Create appears only with `tenant.applications.manage`.
- The Create Application modal handles 400, 401, 403, 409 and 5xx answers.
- The detail page shows the breadcrumb, the type badge, the client ID with Copy, and the Credentials text. It also has Retry banners and the forbidden page.
- The sidebar entry and the landing change go with it.

**Files changed (main ones)**
- `src/Adapters/Postgres/Migrations/Migration20261113000000AddApplicationTypes.cs`: the kinds and the redirect-URI CHECK.
- `src/Modules/Directory/{Contracts,Core}`: kind constants, `CredentialRequired`, `CreateApplicationAsync`, `ListApplicationsPageAsync`, `FindApplicationAsync`, and the event wording.
- `src/Modules/Management/{Contracts/IApplicationManagement.cs, Core/ApplicationManagement.cs}`: the capability re-check, validation and actor.
- `src/Gatekeep.Host.Admin/{ApplicationsApi.cs, AdminApi.cs, AdminApiServices.cs, AdminResponses.cs, AdminOpenApi.cs}`: the routes and problem codes.
- `docs/api/openapi-v1.json`, `packages/api-client/*`: the regenerated contract and the typed methods.
- `apps/admin-dashboard/src/shell/{ApplicationsPage, CreateApplicationModal, ApplicationDetailPage, applications, nav, Shell, LandingPage, currentTenant}`, `packages/ui/src/messages.tsx`: the screens.
- Tests:
  - new `tests/Isolation/Applications/{ApplicationsApiTests, InertApplicationTests}.cs` and `tests/browser/admin-applications.spec.ts`;
  - updated `DirectoryTests`, `RouteRegistry`, `CanaryFlows`, `MigrateCommandTests` (29) and `ProtocolHost`, plus the landing assertions in four browser specs.

**Review findings.** 32 findings: 17 patched (13 root causes), 3 deferred (2 entries) and 12 rejected.
- Deferred: the OpenAPI generator declares no sub-resource path parameter (pre-existing), and `ApplicationStore` reports spa and native as Confidential (pre-existing, inert until Story 3.2).
- Rejected (reasons in the triage log):
  - 5 false: the spec's delivery record, a 201 with no body, mocked UI tests, machine refusal below HTTP, and the CHECK relaxation.
  - 7 low: UUIDv7 ordering, cross-page imports, no Application quota, a late 201 after unmount, trim character sets, a double Retry, and the control-character rule not being in the spec.

**Follow-up review: not recommended (`false`).** Patched counts by verdict: medium 1 (authorize coverage for inert Applications), low 12.

**Verification**
- `dotnet build Gatekeep.slnx` (SDK 10.0.403 container, `-p:NuGetAudit=false` because nuget.org was unreachable) passed with 0 warnings and 0 errors, before and after the patches.
- `pnpm -r build` and typecheck (Node 26 container) are clean. The implementer ran the dashboard unit tests (12/12).
- No suites were run locally. CI on PR #57 is the first run of the Isolation and browser tests.
- **Matrix audit:** every I/O row has a named test in `ApplicationsApiTests`, `InertApplicationTests` or the Management test. Whether they passed is judged from CI before merge.

**Residual risks**
- The browser specs are unrun: the new Applications spec, the 401 renewal test (mocked sign-in) and the moved landing assertions.
- The spa and native `/authorize` cases assume OpenIddict refuses an unregistered `redirect_uri` before it checks endpoint permissions.
