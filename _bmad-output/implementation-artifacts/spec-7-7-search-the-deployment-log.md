---
title: "Story 7.7: Search the Deployment Log"
type: 'feature'
created: '2026-11-14'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-7-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-7-4-search-a-tenant-s-logs.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-7-5-open-an-event-s-raw-detail.md'
warnings:
  - oversized
deferred: []
---

<intent-contract>

## Intent

**Problem:** The Deployment Log (`deployment_audit_event`) holds bootstrap, Admin sign-in, recovery and Tenant events, but nobody can read it. There's no route, no screen and no search index, and `deployment.log.read` (Deployment Owner only) gates nothing (FR-40).

**Approach:**
- **Search:** add a read-only, cursor-paged `GET /api/v1/deployment/logs` under `deployment.log.read`. It is Story 7.4's search over the Deployment Log, filtered by event type, Admin, Tenant, outcome and time range.
- **Open one event:** add `GET /api/v1/deployment/logs/{eventId}`, Story 7.5's open event. A Deployment Owner holds the capability that reads the Log, so `raw` is always sent.
- **Screen:** add a Deployment › Log screen, built from the Logs page and its event drawer.

## Boundaries & Constraints

**Always:**
- **Who may read:**
  - Both routes use `DeploymentApiEndpoint.Instance` and `RequiresCapability(DeploymentLogRead)`, so any other Admin gets 403 `access_denied`, audited as every capability refusal is.
  - A request without an Admin Session gets 401.
  - `AdminCapabilities.Allows(DeploymentLogRead, machine)` is false.
- **Reads:** each read runs in one Deployment transaction (`services.BeginAsync`, as `TenantsApi.ListAsync` does). The search reads `deployment_audit_event` only. The open read adds `deployment_audit_detail`.
- **Contract shapes:** the same response shapes as Stories 7.4 and 7.5:
  - The search answers `TenantLogsResponse` (events and `nextCursor`).
  - The open read answers `TenantLogEventDetailResponse`, with `raw` always set: envelope, seal in lowercase hex (null while unsealed), and detail (null with no row).
  - The same summary and outcome come from `LogCatalogue`.
  - A code no catalogue declares shows a `null` summary and outcome and is still listed.
- **Filters:** each takes one value, and all are ANDed.
  - `type`: a code.
  - `admin`: a UUID, matching events whose actor or target is `admin` with that ID.
  - `tenant`: a `ten_` public ID, matching events whose target is `tenant` with that ID.
  - `outcome`, `from`, `to` and `cursor`: as in Story 7.4.
  - A malformed value gets 400 `invalid_request` before anything is read. A database failure gets 503.
- **Order and paging:** newest first by `id`, 50 per page, and the cursor is an `evt_` ID.
- **Indexes:** filters hit indexed columns only. A new migration adds `deployment_audit_event (type_code, id DESC)`, `(actor_kind, actor_id, id DESC)`, `(target_kind, target_id, id DESC)` and `(occurred_at DESC)`.
- **Module edges:** the queries live in `src/Modules/Audit`, as a Contracts port named `IDeploymentLogReader` (not `*Events.cs`, which is reserved for catalogues) and a Core implementation.
- **Screen:**
  - **Where it lives:** Deployment › Log at `/deployment/logs`, shown only with `deployment.log.read`.
  - **Search and table:** the field select offers Event type, Admin, Tenant, Outcome and Time range. The page keeps `field` and `value` in the URL, and keeps Load more and the empty state. Its columns are Time (UTC), Type, Description, Admin and Tenant.
  - **Drawer:** a row opens the event drawer with raw JSON and Copy JSON. Its summary rows are Time (UTC), Actor, Target, IP address, User-Agent and Email; the last three only when detail holds them.
  - **Reuse:** the page reuses the Logs page component, parameterised by scope, rather than copying it.

**Never:**
- No route other than GET under `/api/v1/deployment/logs`. The Log stays immutable.
- No audit of Log reads.
- No change to the Tenant Logs routes, their responses or the hash envelope.
- No new `audit_event` code is written. Events not yet built (upgrade, restore and Deployment configuration) are proved by fixture rows only.
- No Live view, query bar or Log streams.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Classes searchable | Deployment Log holds bootstrap, Admin sign-in, recovery and Tenant events written by their real code paths, plus fixture rows for `deployment.upgrade.completed`, `deployment.restore.completed` and `deployment.configuration.changed` | Each found by `?type=` for its code; the unfiltered list has all, newest first | Uncatalogued fixture codes: `summary` and `outcome` null |
| Admin filter | `?admin=<uuid>` | Events whose actor or target is that Admin | Non-UUID gives 400 |
| Tenant filter | `?tenant=ten_…` | Events whose target is that Tenant | Not a `ten_` ID gives 400 |
| Outcome / range / paging | As Story 7.4 | As Story 7.4 (50, 50, 20; `nextCursor` null last) | As Story 7.4 |
| Other Admin | Admin with Owner role in a Tenant, not Deployment Owner | 403 `access_denied` on both routes | Refusal audited |
| No Session | No cookie | 401 on both routes | N/A |
| Machine | Test-only machine principal | `Allows(DeploymentLogRead, …)` false | N/A |
| Open event | Deployment Owner, sealed event with detail | 200 with summary and `raw` (envelope, hex seal, detail) | Unknown `evt_` gives 404 `not_found`; malformed gives 400 |
| Tenant Log event | `evt_` ID of an `audit_event` row | 404: it isn't in the Deployment Log | N/A |
| Screen | Deployment Owner opens Deployment › Log | Bootstrap events listed; a row opens the drawer with raw JSON | Nav item hidden without `deployment.log.read` |

</intent-contract>

## Code Map

- **Search to mirror:** `src/Gatekeep.Host.Admin/TenantLogsApi.cs`:
  - `Parse` L124 for query parsing, `Event` for the summary mapping, and `GetAsync`/`Raw` for the open read.
  - Generalise shared parsing helpers rather than copying them.
  - The new handler file is `DeploymentLogsApi.cs`.
- **Audit queries:** `src/Modules/Audit/Core/TenantLogSearch.cs` and `TenantLogEventReader.cs` are the query and mapping to mirror. Make the kind mappers reusable.
  - Register the new reader in `AuditContract.cs`, and expose it on `AdminApiServices.cs`.
  - `src/Modules/Audit/Contracts/ITenantLogSearch.cs` holds `TenantLogEntry` and `TenantLogPage`. Reuse them for Deployment rows.
- **Route:** `src/Gatekeep.Host.Admin/AdminApi.cs:403`, the `ListTenants` Deployment route, is the metadata pattern: `DeploymentApiEndpoint.Instance`, `RequiresCapability`, `QueryParameter` and `Produces`.
  - Map the two routes near the Tenant Logs ones (~L572), with `PathParameter` for `eventId` as Story 7.5 did.
- **Deployment transaction:** `src/Gatekeep.Host.Admin/TenantsApi.cs:259` (`services.BeginAsync`).
- **Capability:** `src/Modules/Admins/Contracts/AdminCapabilities.cs:189` (`DeploymentLogRead`).
- **DDL:** `src/Adapters/Postgres/Migrations/Migration20261102010000CreateAuditTables.cs`:
  - `deployment_audit_event`, and `deployment_audit_detail (event_id, ip_address, user_agent, email)`.
  - `gk_admin` has SELECT on both.
- **Migration:** add `Migration20261119000000DeploymentLogSearchIndexes.cs`, following `Migration20261106000000AuditSearchIndexes.cs`. Bump the count in `tests/Isolation/MigrateCommandTests.cs` (`Applied 34` becomes `35`, 3 places plus `Assert.Equal`).
- **Route inventories:**
  - `tests/Architecture/LogRouteRuleTests.cs`: add GET only for the two Deployment paths.
  - `tests/Isolation/Canary/CanaryFlows.cs`: list the routes in a flow, as Story 7.5 did for `admin.tenant-logs`.
  - `tests/Isolation/CrossTenant/RouteRegistry.cs`: add the routes if it lists Deployment routes.
- **Isolation fixtures:**
  - `tests/Isolation/Admins/AdminHost.cs`: `StartAsync`, `SendAsync`, `ScalarAsync`, and the Deployment Owner session helpers used by `TenantsApi` tests.
  - `tests/Isolation/Audit/TenantLogSearchTests.cs` and `TenantLogEventTests.cs` show the inserted-event pattern (triggers bypassed).
  - `tests/Isolation/Admins/TestOnlyMachinePrincipal.cs` is the machine principal.
- **API contract:**
  - `docs/api/openapi-v1.json` is regenerated (`sh deploy/docker/api-contract.sh --write /out`).
  - `packages/api-client/src/{client.ts,index.ts}` gets `searchDeploymentLogs` and `getDeploymentLogEvent`.
- **Front end:**
  - `apps/admin-dashboard/src/shell/LogsPage.tsx` and `logs.ts`: parameterise by scope.
    - Tenant: fields type, user, application, outcome, range.
    - Deployment: fields type, admin, tenant, outcome, range.
    - Each scope brings its own reads and columns.
  - `logEvent.ts` builds the summary rows.
  - `nav.ts` gets a Deployment item `/deployment/logs` requiring `deployment.log.read`. `Shell.tsx` routes it beside `/deployment/tenants` (L503).
  - `packages/ui/src/messages.tsx` gets `navDeploymentLog` and the field labels.
- **Front-end tests:**
  - `tests/browser/admin-logs.spec.ts`: add a Deployment Log describe or a sibling spec. If it's a new spec file, give it its own Playwright project and add it to the generic projects' `testIgnore` (see the project memory pitfall).
  - `apps/admin-dashboard/test/logs.test.mjs` holds the unit tests.

## Tasks & Acceptance

**Execution:**
- [ ] `src/Adapters/Postgres/Migrations/Migration20261119000000DeploymentLogSearchIndexes.cs`, `tests/Isolation/MigrateCommandTests.cs` -- add the four indexes and bump the migration count, so the searches stay indexed.
- [ ] `src/Modules/Audit/Contracts/IDeploymentLogReader.cs`, `src/Modules/Audit/Core/DeploymentLogReader.cs` (+ `AuditContract`) -- add a reader with `SearchAsync(context, DeploymentLogQuery, ct)` and `FindAsync(context, eventId, ct)` over `deployment_audit_event` and its detail. This keeps the reads in their module.
- [ ] `src/Gatekeep.Host.Admin/DeploymentLogsApi.cs`, `AdminApi.cs`, `AdminApiServices.cs` (+ shared helpers from `TenantLogsApi.cs`) -- add both handlers and routes, each under `RequiresCapability(DeploymentLogRead)`, with OpenAPI 200/400/401/403(/404)/503. These are the API surface.
- [ ] `tests/Architecture/LogRouteRuleTests.cs`, `tests/Isolation/Canary/CanaryFlows.cs`, and `RouteRegistry.cs` if applicable -- extend the GET-only rule and the route inventories, which keep the Log immutable and canary-scanned.
- [ ] `tests/Isolation/Audit/DeploymentLogTests.cs` -- cover every server matrix row against a real database through `AdminHost`.
  - Produce bootstrap, sign-in and recovery events through their real flows where `AdminHost` already drives them. Insert Tenant events through the API.
  - Insert the three not-yet-built classes as fixture rows. This proves AC 1.
  - Cover the other Admin's 403, the 401, and the machine `Allows` check. This proves AC 2.
- [ ] `docs/api/openapi-v1.json`, `packages/api-client/*` -- regenerate, and add the two client methods.
- [ ] `apps/admin-dashboard/src/shell/{LogsPage.tsx,logs.ts,logEvent.ts,nav.ts,Shell.tsx}`, `packages/ui/src/messages.tsx` -- build the Deployment Log screen from the parameterised Logs page.
- [ ] `apps/admin-dashboard/test/logs.test.mjs`, browser spec -- unit-test the Deployment fields' URL-to-query mapping. Browser-test that the page lists events, searches by Tenant, opens a row with raw JSON, and hides the nav item without the capability.

**Acceptance Criteria:**
- Given a Deployment Owner, when they open Deployment › Log, then the bootstrap events are listed newest first, and searching by event type finds each of the bootstrap, Admin sign-in, recovery, Tenant, upgrade, restore and configuration classes. The last three are fixture rows.
- Given an Admin who isn't the Deployment Owner, or a machine principal, when it calls either route, then it's refused: 403 for the Admin, and denied by `Allows` for the machine. No Deployment event is returned.
- Given CI, when the Architecture suite runs, then every Log route is GET only and `openapi-v1.json` matches its generator.

## Spec Change Log

## Review Triage Log

## Design Notes

- **Same shapes as the Tenant Log:** reusing the 7.4 and 7.5 response types lets one page component and one drawer serve both Logs. Raw is always sent, because `deployment.log.read` belongs to the Deployment Owner alone: there is no Viewer tier on the Deployment Log.
- **Fixtures for unbuilt classes:** the AC asks for upgrade, restore and configuration events to be "tested by fixture". Inserting rows with plausible codes proves that the search indexes and lists any Deployment code. When Epics 12 and 8 add the real codes, their stories catalogue them.

## Verification

**Commands:**
- `dotnet build Gatekeep.slnx` (in the tests Docker image under a worktree-only tag) -- expected: 0 warnings. `pnpm -r build` passes. Tests run in CI only, after a push.
