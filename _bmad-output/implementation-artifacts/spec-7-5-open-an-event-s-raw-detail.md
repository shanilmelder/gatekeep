---
title: "Story 7.5: Open an event's raw detail"
type: 'feature'
created: '2026-11-14'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-7-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-7-4-search-a-tenant-s-logs.md'
warnings:
  - oversized
deferred: []
---

<intent-contract>

## Intent

**Problem:** A Tenant's Logs list events, but nobody can open one. There's no detail endpoint and no event drawer, so an Editor can't see an event's IP address, User-Agent, email or seal while investigating. The `tenant.log_detail.read` capability (Editor and Owner, FR-39) exists but nothing enforces it (FR-40, UX-DR18).

**Approach:**
- **Endpoint:** add a read-only `GET /api/v1/tenants/{tenantId}/logs/{eventId}` under `tenant.logs.read`. It always returns the event's summary (the same fields as a search row). It adds a `raw` object only when the caller also holds `tenant.log_detail.read`.
- **Screen:** on the Logs screen, opening a row opens the existing `EventDrawer`, filled from that endpoint.

## Boundaries & Constraints

**Always:**
- **Scope:** the read runs in `TenantScope` on the path Tenant, so RLS holds it to that Tenant. An event of another Tenant answers exactly like an unknown one: 404 `not_found`.
- **Server decides:** the handler decides `raw` with `AdminCapabilities.Allows(TenantLogDetailRead, AdminRequestChecks.Principal(context), PathTenantGrant(context).Grant, tenantId)`, the `FreshAssertionApi` precedent.
- **Viewer response:** without detail, `raw` is `null`, and `audit_detail` isn't even queried. No IP address, User-Agent, email or seal appears anywhere in that response.
- **`raw` shape:**
  - The envelope: `id`, `occurredAt`, `type`, `actor` and `target`, as the search shows them.
  - `seal`: `{ seq, prevHash, hash }`, with the hashes as lowercase hex. It is `null` while the event is unsealed. `prevHash` is `null` for the first event in a chain.
  - `detail`: `{ ipAddress, userAgent, email }`, each nullable. `detail` itself is `null` when the event has no `audit_detail` row.
- **Event ID:** the `eventId` is an `evt_` public ID. A malformed one gets 400 `invalid_request`, and a database failure gets 503, through the same `AdminResponses` helpers as the search.
- **Module edges:** the query lives in `src/Modules/Audit`, as a Contracts port plus a Core implementation, not as SQL in Host.
- **Drawer contents:**
  - The header holds the code badge, toned by outcome, with the summary (or the type when the summary is missing) as its title.
  - The summary rows are Time (UTC), Actor, Target, User and Application, each taken from the envelope, plus IP address, User-Agent and Email when `raw.detail` has them.
  - With `raw`, the drawer passes `canSeeRaw` and shows the raw JSON with Copy JSON. Without it, the drawer shows the limited note and renders no raw section.
- **Drawer behaviour:**
  - The drawer opens on row click and on keyboard activation: the Description column is the `rowLink`, and `onRowActivate` opens the row.
  - The open row is drawn selected (`selectedKey`).
  - Esc and Close shut the drawer. Each open uses its own `AbortController`.
  - While loading, the drawer shows `SkeletonRows`. A failure shows a `Banner` with Retry, and a 404 shows no Retry.

**Never:**
- No route other than GET under `/logs`, so the Log stays immutable.
- No audit of Log reads, which keeps Story 7.4's rule.
- No change to the search response, the hash envelope or any published code.
- No drawer state in the URL.
- No User History (Story 7.6), no Deployment Log (Story 7.7), and no Connection or Location row: there's no data for them.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Editor / Owner | Sealed event with detail | 200: summary fields plus `raw` with envelope, `seal` (hex) and `detail` | N/A |
| Viewer | Same event | 200: summary fields, `raw: null`; body holds no IP, User-Agent, email or hash | N/A |
| No detail row | Editor, event without `audit_detail` | `raw.detail: null` | N/A |
| Unsealed | Editor, event before sealing | `raw.seal: null` | N/A |
| Other Tenant | Event of B, read through A | 404 `not_found` | Same as unknown |
| Unknown | Well-formed `evt_` with no event | 404 `not_found` | N/A |
| Malformed | `eventId=abc` or a `ten_` ID | 400 `invalid_request` | Nothing read |
| No role | Admin with no role in A | 403, audited like every Tenant refusal | N/A |
| Drawer, Viewer | Row opened, `raw: null` | Badge, summary rows and the limited note; no `[data-event-raw]` in the DOM | N/A |
| Drawer, failure | Detail read answers 503 | Banner with Retry; Retry reads again | 404: no Retry |

</intent-contract>

## Code Map

- **Search to mirror:** `src/Gatekeep.Host.Admin/TenantLogsApi.cs`:
  - `SearchAsync` L93 is the scope, 503 and JSON shape to follow.
  - `Event` L229 maps envelope to summary. Reuse it for the summary fields.
  - `RefuseAsync` L303 gives the 400.
  - The DTOs are at L13–56.
- **Route:** `src/Gatekeep.Host.Admin/AdminApi.cs:572` maps the search. Map the detail route beside it with `TenantApiEndpoint.Instance` and `RequiresCapability(TenantLogsRead)`, and give the parameter a description.
- **Capabilities:** `src/Modules/Admins/Contracts/AdminCapabilities.cs`:
  - `TenantLogsRead` L136 and `TenantLogDetailRead` L139.
  - `Allows` L242.
- **Capability-check precedent:** `src/Gatekeep.Host.Admin/FreshAssertionApi.cs:157`.
- **Request checks:** `src/Gatekeep.Host.Admin/AdminRequestChecks.cs:448-458` holds `PathTenant`, `PathTenantGrant` and `Principal`.
- **Audit search:** `src/Modules/Audit/Contracts/ITenantLogSearch.cs` and `Core/TenantLogSearch.cs` are the port and query to mirror. Register the new port where `TenantLogSearch` is registered, and add it to `AdminApiServices` beside `LogSearch`.
- **DDL:** `src/Adapters/Postgres/Migrations/Migration20261102010000CreateAuditTables.cs`:
  - `audit_event.seq`, `prev_hash` and `hash`.
  - `audit_detail (tenant_id, event_id, ip_address, user_agent, email)`.
  - `gk_admin` has SELECT on both tables. No migration is needed.
- **Public IDs:** `src/Gatekeep.Kernel/Identifiers/PublicId.cs` has `PublicIdType.AuditEvent` (`evt`). Parse it as the search parses its cursor.
- **Route inventory:** `tests/Architecture/LogRouteRuleTests.cs` has the GET-only Log routes. Extend it to the new path. If 404 isn't already declared, check `tests/Architecture/AdminApiRuleTests.cs` `Problem_responses_use_the_problem_schema`.
- **API contract:**
  - `docs/api/openapi-v1.json` is regenerated by the build.
  - Regenerate the client with `pnpm --filter @gatekeep/api-client generate`.
  - Add a `getTenantLogEvent` method and its type exports in `packages/api-client/src/{client.ts,index.ts}`, after `searchTenantLogs` L303.
- **UI:** `packages/ui/src/components/EventDrawer.tsx` has the props `code`, `outcome`, `title`, `summary` and `canSeeRaw`/`raw`, and Drawer's `open` and `onClose`. Add any new labels in `packages/ui/src/messages.tsx`.
- **Screen:**
  - `apps/admin-dashboard/src/shell/LogsPage.tsx` holds the `columns` and the `DataTable`. `DataTable` takes `onRowActivate`, a `rowLink` column and `selectedKey`.
  - `logs.ts` has `referenceOf` and `utcTime`.
- **Tests to extend:**
  - `tests/Isolation/Audit/TenantLogSearchTests.cs` has the fixtures: `AdminHost`, inserting events and detail, and granting roles.
  - `tests/browser/admin-logs.spec.ts` holds the mocked-API cases.
  - `apps/admin-dashboard/test/logs.test.mjs` holds the unit tests.

## Tasks & Acceptance

**Execution:**
- [ ] `src/Modules/Audit/Contracts/ITenantLogEvents.cs`, `src/Modules/Audit/Core/TenantLogEvents.cs` (+ registration) -- add a port and query. `FindAsync(context, eventId, includeDetail, ct)` returns the envelope and seal, plus detail only when `includeDetail`, or null when there's no such event. This keeps the read in its module.
- [ ] `src/Gatekeep.Host.Admin/TenantLogsApi.cs`, `AdminApi.cs`, `AdminApiServices.cs` -- add the `TenantLogEventDetailResponse` DTO: the summary fields plus a nullable `Raw`. Add a `GetAsync` handler that parses the `evt_` ID, checks `Allows` for detail, reads, and answers 404 when the event is missing. Map `GET /api/v1/tenants/{tenantId}/logs/{eventId}` with its OpenAPI `Produces` for 200, 400, 401, 403, 404 and 503. This is the detail endpoint, and the server decides `raw`.
- [ ] `tests/Architecture/LogRouteRuleTests.cs` -- add the new path to the GET-only rule. The Log stays immutable.
- [ ] `tests/Isolation/Audit/TenantLogEventTests.cs` -- cover every server matrix row through `AdminHost` against a real database. Include the Viewer body scan for the planted IP, User-Agent, email and hash hex, and the cross-Tenant 404. This proves AC 2.
- [ ] `docs/api/openapi-v1.json`, `packages/api-client/*` -- regenerate, and add `getTenantLogEvent`.
- [ ] `apps/admin-dashboard/src/shell/LogsPage.tsx` (+ a small `logEvent.ts` helper for summary rows), `packages/ui/src/messages.tsx` -- open the drawer on a row: loading, failure with Retry, the summary rows, and raw only when sent. This is the screen.
- [ ] `apps/admin-dashboard/test/logs.test.mjs`, `tests/browser/admin-logs.spec.ts` -- unit-test the summary-row builder (detail rows only with `raw`). Browser-test these cases:
  - An Editor row opens the badge, rows, raw JSON and a Copy JSON that copies it.
  - A Viewer sees the limited note and no raw section.
  - Esc closes the drawer.
  - A 503 shows Retry, which reads again.
  - Keyboard activation opens the drawer.

**Acceptance Criteria:**
- Given an Editor or Owner on Tenant A's Logs, when they open a row, then the drawer shows the event's code badge, the summary rows and the raw JSON with Copy JSON, and Copy JSON copies exactly that JSON.
- Given a Viewer of Tenant A, when they call `GET /api/v1/tenants/{A}/logs/{eventId}` directly, then the server answers 200 with summary fields only and `raw: null`, with no detail value in the body.
- Given CI, when the Architecture suite runs, then `docs/api/openapi-v1.json` matches its generator, and every Log route is GET only.

## Spec Change Log

## Review Triage Log

## Design Notes

- **One endpoint, two views:** the capability that gates the route stays `tenant.logs.read`, so a Viewer gets a 200 summary, as the AC says. A 403 would be wrong here. The detail capability only adds `raw`. Because `audit_detail` isn't queried without it, a bug in the response mapping can't leak detail to a Viewer.
- **Raw is a projection, not a row dump:** naming `seal` and `detail` keeps the JSON stable and readable, and lowercase hex is how a hash is usually compared by eye.

## Verification

**Commands:**
- `dotnet build Gatekeep.slnx` -- expected: 0 warnings. Tests run in CI only (see project memory), after a push.
