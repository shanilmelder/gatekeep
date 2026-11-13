---
title: "Story 7.5: Open an event's raw detail"
type: 'feature'
created: '2026-11-14'
status: 'done'
baseline_revision: '32ab16f3957465988058a012845b04ceb14a8f3b'
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
- [x] `src/Modules/Audit/Contracts/ITenantLogEvents.cs`, `src/Modules/Audit/Core/TenantLogEvents.cs` (+ registration) -- add a port and query. `FindAsync(context, eventId, includeDetail, ct)` returns the envelope and seal, plus detail only when `includeDetail`, or null when there's no such event. This keeps the read in its module.
- [x] `src/Gatekeep.Host.Admin/TenantLogsApi.cs`, `AdminApi.cs`, `AdminApiServices.cs` -- add the `TenantLogEventDetailResponse` DTO: the summary fields plus a nullable `Raw`. Add a `GetAsync` handler that parses the `evt_` ID, checks `Allows` for detail, reads, and answers 404 when the event is missing. Map `GET /api/v1/tenants/{tenantId}/logs/{eventId}` with its OpenAPI `Produces` for 200, 400, 401, 403, 404 and 503. This is the detail endpoint, and the server decides `raw`.
- [x] `tests/Architecture/LogRouteRuleTests.cs` -- add the new path to the GET-only rule. The Log stays immutable.
- [x] `tests/Isolation/Audit/TenantLogEventTests.cs` -- cover every server matrix row through `AdminHost` against a real database. Include the Viewer body scan for the planted IP, User-Agent, email and hash hex, and the cross-Tenant 404. This proves AC 2.
- [x] `docs/api/openapi-v1.json`, `packages/api-client/*` -- regenerate, and add `getTenantLogEvent`.
- [x] `apps/admin-dashboard/src/shell/LogsPage.tsx` (+ a small `logEvent.ts` helper for summary rows), `packages/ui/src/messages.tsx` -- open the drawer on a row: loading, failure with Retry, the summary rows, and raw only when sent. This is the screen.
- [x] `apps/admin-dashboard/test/logs.test.mjs`, `tests/browser/admin-logs.spec.ts` -- unit-test the summary-row builder (detail rows only with `raw`). Browser-test these cases:
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

### 2026-11-14 — Review pass
- verdicts: 27 findings — high 0, medium 0, low 20, false 7, maybe-false 0
- notes: the reviewed diff left out the generated `openapi-v1.json` and `schema.generated.ts`, which the API-contract drift check covers, and `_bmad-output`.
- findings:
  - Intent Alignment:
    - `false` `reject` A Viewer still gets Actor and Target IDs, which a narrow "summary only" might exclude. Disproved: those are envelope fields Story 7.4's search already shows every role, and FR-39 gates raw detail with personal data, which a Viewer never gets.
    - `low` `reject` AC 1 is browser-tested only against a mocked API, not a real Editor session. The role-to-`raw` decision is proved end to end in `TenantLogEventTests`, and mocked browser specs are the project's template (Story 7.4).
    - `low` `reject` The drawer rows and raw shape differ from the design (no Connection or Location, no design-style object). No such data exists in the audit model, and the spec's Never excludes those rows.
  - Verification Gap:
    - `low` `patch` A search change while the drawer is open leaves the old `eventRead`, so the next open flashes the previous event. Fixed: `eventRead` counts only when its ID is the open row's, and the search effect clears it.
  - Blind Hunter:
    - `low` `patch` Switching rows paints one frame of the previous event's title, rows and raw JSON. Same root cause and fix as the Verification Gap row.
    - `low` `patch` `readLogEvent` doesn't check that the answer is the asked-for event. Covered by the same ID guard.
    - `low` `reject` The raw JSON lacks `epoch` and the Tenant, so an Editor can't recompute the hash. Chain verification is the `gatekeep audit verify` CLI's job (Story 7.3); the drawer is an investigation view.
    - `false` `reject` A row with `seq` set and `hash` NULL throws a cast exception and answers 500. Disproved: `audit_event` has `CHECK ((seq IS NULL) = (hash IS NULL))`.
    - `low` `patch` The canary's comments say the failing run reads "another Tenant's event", but the request is a role-less Tenant path (403). Fixed: the comments say what it tests (a role-less Tenant path, 403), and a new read of a Tenant B event through the Admin's own Tenant A path expects 404.
    - `low` `patch` No test covers an Admin who is Editor in B and only Viewer in A reading A's event. Fixed: `TenantLogEventTests` adds that case, expecting `raw: null` and no planted value.
    - `low` `reject` `logEvent.ts` copies `utcTime` and mirrors `referenceOf`. It is kept standalone so Node runs it directly, and the two helpers are a few lines each.
    - `false` `reject` `named()` stops at a user-kind actor with no ID. Disproved: `CHECK ((actor_kind IN ('system','anonymous')) = (actor_id IS NULL))` makes a user actor always carry an ID.
    - `false` `reject` The generated contract files are missing from the diff. Disproved as a defect: they were left out of the review diff on purpose, and the API-contract drift check in CI holds them to the generator.
    - `low` `reject` The `eventId` path parameter has no pattern in OpenAPI. A malformed ID is a documented 400; the pattern would be cosmetic.
    - `low` `reject` The drawer's loading and failure states aren't announced. `Banner` with tone `bad` already uses `role="alert"`, and silent skeletons match every other page.
    - `low` `reject` The browser tests miss row switching, closing mid-read and a new search with the drawer open. The ID guard makes the stale case structural, and adding these cases means a lot of extra test code for low value.
    - `low` `reject` A 403 or 401 on the event read offers a Retry that can't succeed. A role removed mid-session is rare, and a separate state adds a branch.
    - `low` `reject` Opening personal data isn't audited. The spec's Never keeps Story 7.4's rule (no audit of Log reads), so the fix would edit the spec. It is recorded as a residual risk.
    - `low` `reject` `TenantLogEvent` means different things in C# and the TS client. They are in separate languages and namespaces, and renaming adds churn.
    - `low` `patch` `LogRouteRuleTests` L43 is implied by L44. Fixed: deleted.
  - Edge Case Hunter:
    - `low` `patch` The search effect doesn't clear `eventRead`. Same group as the stale-frame fix.
    - `low` `patch` The render before the event effect holds the old `eventRead`. Same group as the stale-frame fix.
    - `low` `reject` A 2xx without a string `occurredAt` renders an empty Time row. The server always sends it (a required field in the generated contract); guarding every field adds branches.
    - `low` `reject` A 2xx whose actor has no `kind` renders "undefined". Same reason as the row above.
    - `false` `reject` `status` passed as `0` or `''` hides the drawer body. Disproved: the only caller passes `undefined` or an element.
    - `false` `reject` A partly sealed row throws a non-`DbException`. Disproved by the same `CHECK` as the Blind Hunter row.
    - `false` `reject` An unknown stored kind throws from `ActorKindOf` and gives a 500. Disproved: `CHECK` constraints on `actor_kind` and `target_kind` allow only the kinds the mapper knows.

## Design Notes

- **One endpoint, two views:** the capability that gates the route stays `tenant.logs.read`, so a Viewer gets a 200 summary, as the AC says. A 403 would be wrong here. The detail capability only adds `raw`. Because `audit_detail` isn't queried without it, a bug in the response mapping can't leak detail to a Viewer.
- **Raw is a projection, not a row dump:** naming `seal` and `detail` keeps the JSON stable and readable, and lowercase hex is how a hash is usually compared by eye.

## Verification

**Commands:**
- `dotnet build Gatekeep.slnx` -- expected: 0 warnings. Tests run in CI only (see project memory), after a push.

## Auto Run Result

Status: done

**Summary:**
- `GET /api/v1/tenants/{tenantId}/logs/{eventId}` opens one event of a Tenant's Log under `tenant.logs.read`.
  - It runs in the path Tenant's scope, so another Tenant's event gets the same 404 as an unknown one.
  - The handler adds `raw` only when the caller holds `tenant.log_detail.read` in that Tenant (Editor and Owner). `raw` holds the envelope, the seal in lowercase hex, and the detail (IP address, User-Agent and email).
  - For a Viewer, `raw` is `null` and `audit_detail` isn't read.
- On the Logs screen, opening a row (by click, or with the keyboard from its Description link) opens the event drawer. It shows the code badge, the summary rows and, only when the server sent `raw`, the raw JSON with Copy JSON. It also has loading, failure-with-Retry and not-found states.

**Files changed:**
- `src/Modules/Audit/{Contracts/ITenantLogEventReader.cs,Core/TenantLogEventReader.cs,Contracts/AuditContract.cs}` -- the event port and query. Detail is read only on request. It is named `*Reader`, not `*Events`, because `AuditCatalogueTests` keeps `*Events.cs` in Contracts for catalogues; the first CI run failed on that, and the files were renamed.
- `src/Gatekeep.Host.Admin/{TenantLogsApi.cs,AdminApi.cs,AdminApiServices.cs,AdminOpenApi.cs}` -- the endpoint, its DTOs, the route and the OpenAPI path parameter and bounds.
- `docs/api/openapi-v1.json`, `packages/api-client/*` -- the regenerated contract and `getTenantLogEvent`.
- `apps/admin-dashboard/src/shell/{LogsPage.tsx,logEvent.ts}`, `packages/ui/src/{components/EventDrawer.tsx,messages.tsx}` -- the drawer on the Logs screen. `EventDrawer` gains an optional `status` slot.
- `tests/Isolation/Audit/TenantLogEventTests.cs`, `tests/Isolation/{Canary/CanaryFlows.cs,CrossTenant/RouteRegistry.cs}`, `tests/Architecture/LogRouteRuleTests.cs` -- the server matrix, the canary flow and the route inventories.
- `tests/browser/admin-logs.spec.ts`, `apps/admin-dashboard/test/logs.test.mjs`, `packages/api-client/test/client.test.mjs` -- the drawer, summary-row and client tests.

**Review findings:**
- 27 findings: 8 low ones patched as 4 fixes, 12 low ones rejected and 7 disproved (each with its reason in the Review Triage Log). Nothing was deferred.
- The 4 fixes:
  - the stale-drawer ID guard
  - a mixed-role test (Owner elsewhere, Viewer here, so no raw)
  - corrected canary comments and a new cross-Tenant 404 read
  - a redundant assertion removed
- Rejected low findings:
  - The browser AC 1 is tested against mocks only.
  - The drawer has no design-only rows.
  - The raw JSON lacks `epoch` and the Tenant, so the hash can't be recomputed from it.
  - `logEvent.ts` duplicates two helpers.
  - The `eventId` parameter has no OpenAPI pattern.
  - The loading state isn't announced to screen readers.
  - The extra browser state paths aren't tested.
  - A 403 or 401 on the event read offers Retry.
  - Reads of personal data aren't audited.
  - `TenantLogEvent` means different things in C# and TS.
  - Missing `occurredAt` isn't guarded.
  - Missing `kind` isn't guarded.

**Follow-up review recommended:** false. Only low entries were patched.

**Verification:**
- The implementer built and checked in Docker (`gatekeep/tests:story-7-5`):
  - `dotnet build Gatekeep.slnx` gave 0 warnings and 0 errors.
  - The API contract was regenerated, and `pnpm build` passed.
- After the patches:
  - Architecture `LogRouteRuleTests`: 22/22.
  - Isolation `TenantLogEventTests` plus the `admin.tenant-logs` canary: 17/17.
  - Browser `admin-logs.spec.ts`: 14/14.
  - Unit `logs.test.mjs`: 14/14.
- The full suites run in CI on PR #63, and the PR merges only on green.

**Residual risks:**
- Opening an event's personal data (IP, email, User-Agent) isn't audited, which keeps Story 7.4's no-audit-of-Log-reads rule. Revisit this if a compliance regime needs access to personal data to be traceable.
- A failed read of an earlier row can show its banner for one frame under a newly opened row. It carries no event data.
- CI on PR #63 failed twice in `ApplicationsApiTests`, which this story doesn't touch, both times on host startup.
  - **Cause of the HealthPort refusal:** `AdminHost` took its health and public ports from two back-to-back `HostProcess.FreePort()` calls, and each closes its probe before returning. The OS can hand back the same port twice, and `HostSettings` refuses a HealthPort that equals the PublicPort. The result is "Missing or unsafe settings: Gatekeep:HealthPort", the flake seen since Story 1.x.
  - **Fix:** a new `HostProcess.FreePorts()` holds both probes open until both are chosen. `AdminHost`, `TenantHostBeforeBootstrapTests` and `HostStartupTests` use it.
  - **Still possible:** the other failure, "address already in use", happens when another process takes a probed port before the host binds. That remains a rare race.
