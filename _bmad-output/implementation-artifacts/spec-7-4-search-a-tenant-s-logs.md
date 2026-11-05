---
title: "Story 7.4: Search a Tenant's Logs"
type: 'feature'
created: '2026-11-06'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-7-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-7-8-plant-canaries-and-publish-the-event-catalogue.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md'
warnings:
  - oversized
deferred: []
---

<intent-contract>

## Intent

**Problem:** Admins can't read a Tenant's Log at all: no endpoint, no screen, and no index beyond the key on `audit_event`. A refused cross-Tenant request is written only to the Deployment Log, so the attacked Tenant's Log never shows it. That breaks AD-9 and leaves the FR-40 class "rejected cross-Tenant attempts" pending on this story (FR-40, UX-DR12, UX-DR44).

**Approach:**
- **Endpoint:** add a read-only, cursor-paged `GET /api/v1/tenants/{tenantId}/logs` under `tenant.logs.read`. It filters indexed envelope columns by event type, User, Application, outcome and time range. A User given as an email resolves to internal User references first.
- **Refusals:** a refused request from an Admin who holds no role in an existing path Tenant also writes a catalogued cross-Tenant rejection event to that Tenant's Log.
- **Screen:** build the Admin Logs screen: one field select plus a value, kept in the URL, with a results table and Load more.

## Boundaries & Constraints

**Always:**
- **Reads:**
  - Every read runs in `TenantScope` on the path Tenant, so RLS limits rows to that Tenant.
  - The response holds envelope fields plus the catalogue summary only. It holds no `audit_detail` column (no IP, User-Agent or email).
- **Filters:**
  - Filters hit only `audit_event` columns that have an index. Add the indexes in a new migration.
  - The one exception is email resolution, which reads `audit_detail.email` to collect User references.
- **Outcome:**
  - Outcome is code-owned. Each `AuditEventDefinition` gains a required `AuditOutcome` (`Success` or `Failure`).
  - The outcome filter becomes `type_code = ANY(codes with that outcome)`.
- **Order and paging:** newest first by `id` (UUIDv7). The cursor is the last row's public event ID, and the page size is 50.
- **Errors:**
  - A malformed filter, cursor or range gets 400 `invalid_request`.
  - A database failure gets 503, using the same `AdminResponses` helpers as `TenantLabelApi`.
- **Cross-Tenant rejection:**
  - **When it's written:** only when the path Tenant exists, the Admin holds no `tenant_role` there, and the request was refused 403. It's written under the same 30 per 15 minutes cap as the Deployment write: a capped refusal writes neither.
  - **Envelope:** actor = Admin, target = Tenant.
  - **Deployment Log:** the `admin.access.denied` write there is kept unchanged.
- **Screen:**
  - The screen and nav item show only when the Admin has `tenant.logs.read` for the Tenant.
  - The URL query keeps `field` and `value`, so reload and Back restore the search.
  - Empty state text: "No events in this range".

**Never:**
- No PUT, PATCH or DELETE route, and no POST, under `/logs`. The Log stays immutable (DB triggers already enforce this).
- No Live view, Log streams, query bar, segmented quick filters, Location column or event drawer. The drawer is Story 7.5.
- No change to the hash envelope (columns or canonical form), and no change to any published code's spelling.
- No new `user` or `application` table, column or public ID type. Those come with Epics 2.5 and 3–5.
- No audit write for the 409 `tenant_mismatch` (it's deferred), and no audit of Log reads.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Type search | `?type=admin.access.denied` | Only events with that code in this Tenant | Bad code format gives 400 |
| User by ID | `?user=<uuid>` | Events whose actor or target is `user`/that ID | Non-UUID, non-email gives 400 |
| User by email | `?user=a@b.test` | Resolved to the User IDs on events whose detail holds that email, then filtered by actor or target | No match gives an empty list |
| Application | `?application=<uuid>` | Actor or target `client`/that ID | Non-UUID gives 400 |
| Outcome | `?outcome=failure` | Only codes whose catalogue outcome is Failure | Other value gives 400 |
| Range | `?from=…&to=…` (ISO 8601 instants) | `from <= occurred_at < to` | `from >= to` or unparsable gives 400 |
| Paging | 120 events, then `cursor` | 50, 50, 20; `nextCursor` null on the last page | Bad cursor gives 400 |
| Other Tenant | Events in Tenants A and B, read A | No B event | N/A |
| Cross-Tenant refusal | Admin with a role only in A calls a B route | 403; B's Log lists the rejection code; Deployment Log keeps `admin.access.denied` | Unknown or malformed B: Deployment Log only |
| Viewer | Viewer of A | 200, same envelope view | No `tenant.logs.read` gives 403 |
| Empty | No match | `events: []`; screen shows "No events in this range" | N/A |

</intent-contract>

## Code Map

- **Audit DDL and grants:**
  - `src/Adapters/Postgres/Migrations/Migration20261102010000CreateAuditTables.cs` -- `audit_event` and `audit_detail` DDL, RLS and grants. `gk_admin` already has SELECT on both.
  - The new migration follows the naming of `Migration20261102070000SealAuditChains.cs`, which also shows how the partial index was added.
- **Kernel audit types** (`src/Gatekeep.Kernel/Audit/`):
  - `AuditEventDefinition.cs` -- add `AuditOutcome`.
  - `AuditTypeCode.cs:28` -- the code regex, which allows `_`.
  - `IAuditAppender`, `AuditEvent`.
- **Catalogues:**
  - `src/Modules/{Admins,Audit,Authentication,Keys,Operations,Sessions,Tenancy}/Contracts/*Events.cs` -- every definition needs an outcome. `AdminsEvents.cs:127` is `AccessDenied`.
  - `tests/Architecture/Generator/AuditCatalogue.cs:47` -- the CrossTenantRejection class is pending on 7.4. Clear it, and add an outcome column to the render.
  - `docs/audit-events.md` -- regenerate with `dotnet run --project tests/Architecture/Generator`.
- **Event classes:** `tests/Isolation/Audit/EventClassTests.cs:30` -- `Proofs`. Add a CrossTenantRejection proof returning `(Database, TenantB)`.
- **Refusal path** (`src/Gatekeep.Host.Admin/AdminRequestChecks.cs`):
  - `PassesAsync` (L522–700): the path Tenant is parsed at L614, and the 403 is returned at L668.
  - `DenyAsync` (L726–745) applies the cap. The Deployment write happens there through `IAdminAuthorization.DenyAsync` (`src/Modules/Admins/Core/AdminAuthorization.cs:61`).
  - The Tenant write is a second `TenantScope.BeginAsync(services.Source, tenantId, ct)` (`src/Gatekeep.Kernel/Persistence/TenantScope.cs:26`), plus `AppendAsync` on its `CommandContext`. Write it only when the cap allowed the Deployment write, the Tenant row exists (FK), and the Admin has no role there.
- **Architecture rule:** `tests/Architecture/CapabilityRuleTests.cs:331` (helpers ~L604) allows a Tenant scope only on `AdminRequestChecks.PathTenant(context)`. Add one named, commented exemption for the refusal writer, and keep the rule otherwise strict.
- **Route mapping and tenant GET:**
  - `src/Gatekeep.Host.Admin/AdminApi.cs:536` -- the tenant-scoped GET pattern: `TenantApiEndpoint.Instance`, `RequiresCapability`, tags and `Produces`.
  - `TenantLabelApi.cs:44` -- the handler shape.
- **Paging:** `src/Gatekeep.Host.Admin/TenantsApi.cs:180,240` -- `PageSize`, cursor parsing and `NextCursor`. `TenantListResponse` at L83 is the DTO style.
- **Capability:** `src/Modules/Admins/Contracts/AdminCapabilities.cs:136` -- `TenantLogsRead` (Viewer, Editor, Owner).
- **Public IDs:** `src/Gatekeep.Kernel/Identifiers/PublicId.cs:41` -- add `PublicIdType.AuditEvent => "evt"` for event IDs and the cursor.
- **Module edges:** `tests/Architecture/module-edges.txt` -- `Host.Admin -> Audit` is allowed. Put the query in `src/Modules/Audit` (Core plus a contract port), not in Host SQL.
- **API contract:**
  - `docs/api/openapi-v1.json` -- regenerated by the build and drift-checked by `deploy/docker/api-contract.sh`.
  - Regenerate the client with `pnpm --filter @gatekeep/api-client generate`.
- **Route-inventory tests:** `tests/Architecture/AdminApiRuleTests.cs:315` (`Operations(document)`) and `CapabilityRuleTests.cs:106`. `RetentionRuleTests.cs:93` is the precedent for a "no such route" test.
- **Isolation fixtures:**
  - `tests/Isolation/Admins/AdminHost.cs`: `StartAsync`, `InsertTenantAsync` L508, `GrantTenantRoleAsync` L516, `SendAsync`, `ScalarAsync`.
  - `tests/Isolation/Admins/TenantCapabilitiesTests.cs:64` -- the cross-Tenant refusal tests to extend.
- **Front end** (`apps/admin-dashboard/src/shell/`):
  - `Shell.tsx:163,475` -- widen `TENANT_ROUTE` and add the page branch.
  - `nav.ts` -- add a Monitoring › Logs item, `requires: tenant.logs.read`.
  - `TenantsPage.tsx` and `tenants.ts` -- the fetch, abort and Load more pattern.
  - `capabilities.ts`.
- **UI package** (`packages/ui/src/`):
  - `messages.tsx` -- add `navLogs` and the empty-state text.
  - Components: `Select`, `Input`, `Field`, `DataTable`, `EmptyState`, `CodeBadge`, `Banner`.
  - `components/useUrlTab.ts` -- the URL-param hook to generalise, or a sibling for two params.
- **Design references:**
  - `design/Gatekeep Admin.dc.html:1103-1141` -- the Logs screen. Columns: Time (UTC), Type, Description, User, Application.
  - `_bmad-output/planning-artifacts/ux-designs/**/EXPERIENCE.md:106,288` and `DESIGN.md:538`.
- **Front-end tests:**
  - Browser: `tests/browser/admin-tenants.spec.ts`, the mocked-API Playwright template.
  - Unit: `apps/admin-dashboard/test/*.test.mjs`.
- **Docs to update:**
  - `docs/threat-model.md:237` -- T-53 says refusals go to the Deployment Log only, pending 7.4. Update it.
  - `_bmad-output/implementation-artifacts/deferred-work.md:185` -- close the matching item.

## Tasks & Acceptance

**Execution:**
- [ ] `src/Gatekeep.Kernel/Audit/AuditEventDefinition.cs` and every `src/Modules/*/Contracts/*Events.cs` -- add `AuditOutcome { Success, Failure }` as a required constructor argument and set it on every definition (refused, denied, failed or dead mean Failure). The outcome filter and the badge tone need it.
- [ ] `src/Modules/Admins/Contracts/AdminsEvents.cs` -- add `CrossTenantRejected` (`admin.cross_tenant.rejected`, Failure, `TenantLogClass.CrossTenantRejection`). This closes the FR-40 class.
- [ ] `src/Adapters/Postgres/Migrations/Migration20261106…AuditSearchIndexes.cs` -- add these indexes: `audit_event (tenant_id, type_code, id DESC)`, `(tenant_id, actor_kind, actor_id, id DESC)`, `(tenant_id, target_kind, target_id, id DESC)`, `(tenant_id, occurred_at DESC)` and `audit_detail (tenant_id, email)`. Searches stay indexed.
- [ ] `src/Gatekeep.Kernel/Identifiers/PublicId.cs` -- add the `evt` type. Event IDs and the cursor are public IDs, like `ten_`.
- [ ] `src/Modules/Audit/Contracts/*` and `src/Modules/Audit/Core/*` -- add a `TenantLogSearch` port and query: a filter record, email-to-User resolution, `type_code = ANY(…)` for outcome, a cursor, and 50 rows plus a look-ahead. The query belongs to its module.
- [ ] `src/Gatekeep.Host.Admin/TenantLogsApi.cs` and `AdminApi.cs` -- map `GET /api/v1/tenants/{tenantId}/logs` with `RequiresCapability(TenantLogsRead)`. Parse and validate the query parameters, and use a host-composed code-to-definition map (from every module's `*Events`) for the summary and outcome.
- [ ] `src/Gatekeep.Host.Admin/AdminRequestChecks.cs` (plus a Tenant-write helper) -- on a 403 that the cap allowed, where the path Tenant exists and the Admin has no role in it, append `CrossTenantRejected` to that Tenant's Log in a separate `TenantScope`. A Tenant-write failure is handled like a failure of the existing Deployment write. This satisfies AD-9.
- [ ] `tests/Architecture/CapabilityRuleTests.cs` -- add the named exemption for the refusal writer only.
- [ ] `tests/Architecture/LogRouteRuleTests.cs` -- the OpenAPI document and live endpoints have only GET under `/api/v1/tenants/{tenantId}/logs`, and no Log route anywhere has another method. This proves AC 3.
- [ ] `tests/Architecture/Generator/AuditCatalogue.cs`, `docs/audit-events.md` -- add an outcome column, clear the 7.4 pending story, and regenerate.
- [ ] `tests/Isolation/Audit/EventClassTests.cs` -- add the CrossTenantRejection proof over HTTP.
- [ ] `tests/Isolation/Audit/TenantLogSearchTests.cs` -- cover every I/O matrix row against a real database through `AdminHost`, including Tenant isolation and the cap.
- [ ] `docs/api/openapi-v1.json`, `packages/api-client` -- regenerate.
- [ ] `packages/ui/src/messages.tsx`, `apps/admin-dashboard/src/shell/{nav.ts,Shell.tsx,LogsPage.tsx,logs.ts}` -- build the screen:
  - The field select offers Event type, User, Application, Outcome and Time range. Outcome uses a select of Success and Failure. Time range uses a select of last 1 hour, 24 hours, 7 days, 30 days and 90 days, mapped to `from`.
  - A Search button runs the search.
  - The URL holds `field` and `value`.
  - The `DataTable` columns are Time (UTC), Type (a `CodeBadge` toned by outcome), Description, User and Application. The User and Application cells show the actor or target reference of that kind.
  - Load more uses `nextCursor`. The page has an empty state, a 400 or 503 banner, and an `AbortController` per attempt.
- [ ] `apps/admin-dashboard/test/logs.test.mjs`, `tests/browser/admin-logs.spec.ts` -- unit-test the URL-to-query mapping. In the browser test, cover search, URL restore on reload, Load more, the empty state, and the nav item hidden without the capability.
- [ ] `docs/threat-model.md`, `_bmad-output/implementation-artifacts/deferred-work.md` -- update T-53 and close the item.

**Acceptance Criteria:**
- Given an Admin with `tenant.logs.read` on Tenant A, when they open `/tenants/{A}/logs` and choose Event type `admin.cross_tenant.rejected` and Search, then the URL holds `field` and `value`, and the table lists only A's matching events newest first.
- Given an Admin with a role only in Tenant A who calls any Tenant B route, when B's Owner opens B's Logs, then the rejection event is listed with the Admin as actor, and A's Log doesn't hold it.
- Given CI, when the Architecture and Isolation suites run, then `EventClassTests` passes with CrossTenantRejection proved and no class pending on 7.4. `docs/audit-events.md` and `openapi-v1.json` also match their generators.

## Spec Change Log

## Review Triage Log

## Design Notes

- **Email resolution:** the `user` table has no email yet (Epics 3–5), and `gk_admin` can't read it. So an email resolves through the User references on events whose `audit_detail.email` matches. That keeps "resolve first, then filter the envelope". It also means an erased User can no longer be found by email, which is what erasure should do. When Identity stores email, the resolver switches to it.
- **Outcome on the catalogue, not a column:** a new envelope column would change the hash envelope, which Story 7.8 forbids. A code-owned outcome turns the filter into an indexed `type_code` match.
- **Second scope for the refusal:** the checks run in a Deployment transaction, so the Tenant-chain write uses its own `TenantScope`. This is the same two-scope pattern as `TenantLabelApi`. The 409 `tenant_mismatch` is deferred. It's a client header disagreeing with the path, and the request never reaches authorization on either Tenant.

## Verification

**Commands:**
- `docker build -t gatekeep/tests:story-7-4 -f deploy/docker/tests.Dockerfile .`, then from Git Bash `MSYS_NO_PATHCONV=1 docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal --add-host host.docker.internal:host-gateway gatekeep/tests:story-7-4` -- expected: 0 build warnings. Front-end unit, browser, Architecture and Isolation suites all pass.
