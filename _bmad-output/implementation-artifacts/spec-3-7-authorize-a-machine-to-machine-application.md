---
title: 'Story 3.7: Authorize a machine-to-machine Application'
type: 'feature'
created: '2026-11-14'
status: 'done'
baseline_revision: '26a1285a92d66c12e8b584fb184a41f2b498edc9'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-3-context.md'
warnings: ['oversized']
deferred:
  - summary: >-
      The grant audit events (directory.api.grant_updated, directory.api.grant_removed) name the API but not the Application.
    evidence: |-
      The spec asks their detail to name the Application's public ID, but AuditEvent holds one target by design (AD-16, architecture-tested) and AuditDetail holds only personal data (IP, user agent, email). Story 3.6's Permission events share the limit. Recording a second object needs an audit-envelope change (a secondary target column), beyond this story.
    location: >-
      src/Gatekeep.Kernel/Audit/AuditEvent.cs
    severity: medium
---

<intent-contract>

## Intent

**Problem:** A machine client can't get a token for one of the Tenant's APIs. Every token names the Story 2.5 placeholder audience, any `resource` or `audience` gets `invalid_target`, and no table records which Permissions a machine client holds (FR-16, UJ-5, AD-33).

**Approach:**
- Directory adds `api_grant`: the Permissions of one API granted to one machine-to-machine Application. Editors manage them from the API detail page.
- Hosted's token and authorize endpoints resolve the one API a request names, by `resource` or `audience`.
  - Client Credentials tokens carry that API as `aud`, plus exactly the requested Permissions that are currently granted.
  - The placeholder audience is removed.
  - The Management API audience is refused.
  - An API with offline access off gets no refresh token.
  - The token lifetime lookup gets the resolved API, so the shorter lifetime applies.

## Boundaries & Constraints

**Always:**
- **Grant model:** `api_grant` holds one row for each permitted value: `(tenant_id, api_id, application_id, value)`.
  - It is a Directory `tenant` class table, with RLS, `tenant_row_guard`, composite foreign keys `ON DELETE RESTRICT` to `permission (tenant_id, api_id, value)` and to `application`, its registry entry and its grants.
  - An Application is "authorized" on an API when it has at least one row.
  - Only `kind = 'machine'` Applications can be granted. Others get 409 `application_not_machine`.
  - The built-in Management API can't be granted here; that is Epic 17's Owner-only flow. Attempts get 409 `api_built_in`.
- **Routes,** under `/api/v1/tenants/{tenantId}/apis/{apiId}`, all with `tenant.apis.manage` and no fresh assertion:
  - `PUT grants/{applicationId}` with `{permissions: [values]}` replaces the set. It holds 1–200 distinct values, each an existing Permission of this API; a bad value is 400 with a field error per value.
  - `DELETE grants/{applicationId}` answers 204. Removing a grant that doesn't exist also answers 204, with nothing written.
  - `GET apis/{apiId}` gains `grants: [{applicationId, name, permissions[]}]`.
  - An unknown, deleted, system or other Tenant's Application is 404 `not_found`.
- **Audit:** one event per change. `directory.api.grant_updated` is written when the set changes (none when unchanged), and `directory.api.grant_removed` when a grant is removed. Both target the API (`AuditTargetKind.Api`), and their detail names the Application's public ID.
- **Cascades handled in code, never in the database:**
  - Removing a Permission deletes its grant rows in the same command.
  - Story 3.5's Application purge and the Tenant purge delete `api_grant` rows before `permission`, `api` and `application`.
- **Naming the API** (decided 2026-11-14):
  - A request names an API with RFC 8707 `resource` or with `audience`, holding exactly one value across both. Two values, or both parameters, is `invalid_target`.
  - The value must be an API identifier in this Tenant, compared exactly. Anything else, and `urn:gatekeep:management` (AD-33), is `invalid_target` with "The requested API isn't available."
- **Client Credentials:**
  - If no API is named, the request is refused with `invalid_target` and "Name an API with resource or audience."
  - Otherwise the token's `aud` is the API's identifier. Its Permissions are the currently granted ones, narrowed to the requested `scope` values if `scope` is sent. A requested value that isn't granted is dropped silently, never an error (FR-16, EXPERIENCE Flow 10).
  - An Application with no grant on the API gets a token with no Permissions.
- **How Permissions appear:** the access token carries them in a `permissions` JSON array claim and in the space-delimited `scope` claim, in the same order (ordinal). The token response's `scope` lists them too. With no Permissions, both claims are absent.
- **Authorization Code:**
  - `/authorize` may name one API in the same way. The authorization keeps it, and the token request may repeat that value or omit it; a different value is `invalid_target`.
  - Users get no API Permissions until Epic 5 (RBAC), so the token's `aud` is the named API, and the only scopes are `openid` and `offline_access`.
  - With no API named, the access token has no `aud` claim. Story 4.9 adds the default audience.
- **Offline access:** when the named API has `offline_access = false`, no refresh token is issued at the code exchange.
- **Refresh:** each refresh re-reads the API by its identifier from current state.
  - If the API is gone, the result is `invalid_grant`.
  - If its offline access is now off, an access token is issued without a new refresh token.
  - Permissions are recomputed from current state, which is none for users before Epic 5.
- **Lifetimes:** `ApplicationTokenLifetimes` gets the resolved API, so the shorter lifetime applies on every grant. `ForClientAsync`'s cache key accounts for the API.
- **Grants:** Hosted gets SELECT on `api`, `permission` and `api_grant`, limited to what resolution reads.
- **Dashboard:**
  - **Machine-to-machine applications:** a new section on the API detail page with a table of Application, Authorized (Yes/No) and Permissions, listing every machine Application of the Tenant.
    - **Edit:** opens a modal with a checkbox per Permission. Saving sends the PUT.
    - **Remove authorization:** sends the DELETE.
    - **Empty state:** "No machine-to-machine applications yet".
  - **On the built-in API:** the section shows "Management API access is granted by a Tenant Owner in a later release." and has no controls.
  - **Viewers:** see it read-only.
- **New routes join** the cross-Tenant suite, the canary, the capability tests, the OpenAPI document and the api-client.

**Never:**
- No Management API grants or Management token endpoint (Epic 17).
- No user Permissions or RBAC enforcement (Epic 5).
- No default audience setting (Story 4.6/4.9).
- No introspection endpoint.
- No `scp:` OpenIddict permissions or scope store. A Gatekeep handler validates them (AD-8).
- No more than one API per token.
- No `invalid_scope` for an ungranted scope.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Grant then token | grant `invoices:read`,`payments:write`; CC `resource=https://api.ex`, no scope | 200; `aud`=identifier; `permissions`=[invoices:read, payments:write]; same `scope` | No error expected |
| Narrowed | CC `scope=invoices:read admin:all` | only `invoices:read` | ungranted dropped silently |
| `audience` alias | CC `audience=https://api.ex` | same as `resource` | No error expected |
| Removed grant | PUT grant to `[invoices:read]`, next CC token | `payments:write` absent | No error expected |
| No API / unknown / two | CC without target; `resource=https://nope`; `resource`+`audience` | 400 | `invalid_target` |
| Management audience | `resource=urn:gatekeep:management` at Hosted | 400 | `invalid_target` |
| No grant | machine app never granted | 200, `aud` set, no permissions/scope claims | No error expected |
| Offline off | code flow with `offline_access` naming an API with offline off | tokens without `refresh_token` | No error expected |
| Offline turned off later | refresh after API offline set false | new access token, no new refresh token | No error expected |
| Code flow, no API | today's code flow | access token without `aud`; never the placeholder | No error expected |
| Shorter wins | app access 900, API 300 | CC token `exp−iat` = 300 | No error expected |
| Grant API errors | spa app; Management API; unknown permission; Viewer; other Tenant app | 409 `application_not_machine`; 409 `api_built_in`; 400 field error; 403; 404 | nothing written |
| Permission removed | remove a granted Permission | grant rows for it gone, next token lacks it | No error expected |

</intent-contract>

## Code Map

- **Protocol**, under `src/Modules/Protocol`:
  - **Placeholder:** `Contracts/ProtocolContract.cs:43-49` holds it. Delete it and its uses.
  - **`TokenEndpoint.cs`:**
    - `RefuseTokenTargets` at :218-260 (registered at `ProtocolServer.cs:145`) becomes target resolution.
    - `SignInClient` at :418-460 sets the audience and Permissions.
    - The refusal texts are at :81 and :117.
  - **`AuthorizeEndpoint.cs`:**
    - `GrantableScopes` is at :37-45 and the scope validation at :256-296.
    - The passthrough at :497-504 sets the audience.
    - `MayRefreshAsync` is at :298.
  - **`RefreshTokens.cs`:** issuance is at :13-31, and `SignInRefresh` at :160-190 clones the principal. Re-evaluate there.
  - **`ApplicationLifetimes.cs:19-90`:** `Of`, and `ForClientAsync` at :68-89, which passes `null` today.
  - **`ProtocolServer.cs`:** the handler list at :142-159. Discovery `scopes_supported` is unchanged; it is pinned at `tests/Isolation/Protocol/RefreshTokenTests.cs:699`.
- **Directory:**
  - `Contracts/DirectoryApi.cs:11-26`.
  - `Contracts/IDirectory.cs:302-362`, the API methods. Add find-by-identifier, the granted values for an Application, and grant set and remove.
  - `Contracts/DirectoryContract.cs:91-118`, holding `ManagementApiIdentifier` and the Permissions.
  - `Core/DirectoryService.Apis.cs:12-268`. `RemovePermissionAsync` at :151-180 must delete the grants.
  - `Contracts/DirectoryApplication.cs:74-75`: `Audiences` is superseded. Remove it, and keep the column untouched.
  - Purges: `Core/DirectoryPurge.cs` and the Story 3.5 per-ID purge.
  - `Contracts/DirectoryEvents.cs`.
- **Schema:**
  - `src/Adapters/Postgres/Migrations/Migration20261119000000DefineApis.cs` is the pattern.
  - In `Schema/TableRegistry.cs`, the `api` entry is at :658-681 and `permission` at :682-699. Add `api_grant`, plus the Hosted reads.
  - `tests/Isolation/MigrateCommandTests.cs:20,28,43,78` expects 35. Change it to 36.
- **Management and Host.Admin:**
  - `src/Modules/Management/Contracts/IApiManagement.cs:85-150` and `Core/ApiManagement.cs`.
  - `src/Gatekeep.Host.Admin/ApisApi.cs` (detail mapping around :396).
  - `AdminApi.cs:906-1047`, the API routes.
  - `AdminResponses.cs`, the problem codes, and `AdminOpenApi.cs`.
- **API client:** `packages/api-client/src/client.ts`, near the APIs methods. Add `setApiGrant` and `removeApiGrant`.
- **Dashboard:**
  - `apps/admin-dashboard/src/shell/ApiDetailPage.tsx:154-171,439-574`: the sections and the `AddPermissionModal` pattern.
  - `shell/apis.ts`.
  - The machine Application list is `listApplications` (`client.ts:372`), filtered on `kind === 'machine'` (`applications.ts:9,64`).
  - The table copy is at `design/Gatekeep Admin.dc.html:1265`.
  - `packages/ui/src/messages.tsx`.
- **Tests:**
  - `tests/Isolation/Protocol/ClientCredentialsTests.cs`: the placeholder at :62, `invalid_target` at :246-262, `invalid_scope` at :264-275, cross-Tenant at :314, and :646.
  - `AuthorizationCodeTests.cs:87,105-106,988`.
  - `RefreshTokenTests.cs:145-146,596-612`.
  - `tests/Isolation/Applications/{ApplicationLifetimeProtocolTests.cs:78, ApplicationDeletionProtocolTests.cs}`.
  - `tests/Isolation/Apis/ApisApiTests.cs`.
  - `CrossTenant/RouteRegistry.cs:110-115` and `Canary/CanaryFlows.cs:441-466`.
  - `tests/Architecture/{CapabilityRuleTests.cs:247-283, AdminApiRuleTests.cs, ProtocolRuleTests.cs, AuditCatalogueTests.cs}`.
  - `tests/browser/admin-apis.spec.ts`.

## Tasks & Acceptance

**Execution:**
- [ ] **Migration** `Migration20261122000000AuthorizeMachineApplications.cs` with `TableRegistry.cs`:
  - `api_grant` with RLS, foreign keys and grants (Admin writes; Hosted reads; Worker purges);
  - the Hosted reads on `api` and `permission`.
  - Update the migration count to 36 and every grant pin.
- [ ] **Directory:**
  - Resolve an API by identifier (the built-in API included, so Protocol can refuse it by name).
  - Read the granted values for one Application and API.
  - Set and remove a grant, with the machine-kind and built-in checks and the events.
  - Delete grants when a Permission is removed.
  - Purge grants, and drop `DirectoryApplication.Audiences`.
- [ ] **Management and Host.Admin:**
  - Add `IApiManagement` grant methods and the routes, with problem codes `application_not_machine` and `api_built_in` (reused).
  - Add `grants` to the API detail and update the OpenAPI enums.
  - Regenerate the contract, then add the api-client methods and unit tests.
- [ ] **Protocol:**
  - Resolve the target and refuse what the Boundaries say to refuse.
  - Set `aud`, `scope` and `permissions` for Client Credentials.
  - Keep the authorize-side target on the authorization, and drop the placeholder.
  - Apply the offline-access rule at the code exchange and at refresh, re-evaluating at refresh.
  - Pass the API to the lifetime lookup.
- [ ] **Dashboard:** in `ApiDetailPage.tsx`, add the machine-to-machine section and the grant modal, with copy in `messages.tsx`.
- [ ] **Isolation tests:** a new `tests/Isolation/Apis/ApiGrantsApiTests.cs` covers the grant API rows. A new `tests/Isolation/Protocol/ApiTargetTests.cs` covers the token rows. Update the existing Protocol tests pinned on the placeholder, `invalid_target` and `invalid_scope`, and add a shorter-wins case to `ApplicationLifetimeProtocolTests`.
- [ ] **Registries and pins:** `RouteRegistry`, `CanaryFlows`, `CapabilityRuleTests` and `AdminApiRuleTests`, plus the audit catalogue. Grep both test projects and the browser specs for lists pinned on anything you changed: tables, grants, the migration count, audit codes, problem codes, the placeholder string, `invalid_target`, and the CC `invalid_scope`. Stories 3.4–3.6 each broke CI by missing one.
- [ ] **Browser tests** in `tests/browser/admin-apis.spec.ts`:
  - the M2M table;
  - granting through the modal with its toast;
  - removing authorization;
  - the built-in API's copy, with no controls;
  - the Viewer's read-only view;
  - axe in light and dark.

**Acceptance Criteria:**
- Given a grant, when the client requests a token, then the token carries only granted Permissions, and an ungranted scope is omitted.
- Given a removed grant, when the next token is issued, then that Permission is gone.
- Given the Management API audience, when it's requested at `Host.Hosted`'s token endpoint, then it's refused.
- Given offline access off for an API, when a client requests a refresh token for it, then none is issued.
- Given this story, when any token is issued, then it never carries the Story 2.5 placeholder audience.

## Spec Change Log

## Review Triage Log

### 2026-11-14 — Review pass
- verdicts: 27 findings — high 0, medium 4, low 16, false 5, maybe-false 2
- findings:
  - `[false]` `[reject]` (intent) A machine client with no grant gets a 200 token with `aud` set and no Permissions, where "authorize" could mean refusal — the spec's "No grant" matrix row and the decision "no scope → all granted" (the empty set) settle it; the token carries no Permission, so it grants nothing.
  - `[low]` `[reject]` (intent) No single test drives Remove authorization over the Admin HTTP API and then requests a token — each segment is covered (`ApiGrantsApiTests` for the route, `ApiTargetTests` for the next token after a removal); joining them adds no behaviour under test.
  - `[false]` `[reject]` (intent) The offline-access acceptance check lands on the user code and refresh flows, not machine clients — Client Credentials never issues a refresh token, so the rule can only bite on the code flow; the spec's Offline access and Refresh rows place it there.
  - `[false]` `[reject]` (intent) A code flow that names no API now gets an access token with no `aud` — the spec decides this ("Story 4.9 adds the default audience"); the placeholder must go (AC5).
  - `[medium]` `[patch]` (verification) Nothing tests that a soft-deleted Application's grant is hidden from the API detail — added an `ApiGrantsApiTests` case that deletes a granted Application and asserts `grants` is empty.
  - `[medium]` `[patch]` (verification) API lifetimes on the code-exchange and refresh paths are untested — added a code-flow case to `ApplicationLifetimeProtocolTests` asserting the API's shorter access and refresh-absolute lifetimes on the exchange and a refresh.
  - `[medium]` `[patch]` (verification) No browser test checks that removing a Permission updates the machine-to-machine table — added an `admin-apis.spec.ts` case seeding a grant, removing its Permission, and asserting the row's Permissions and Authorized cells.
  - `[low]` `[patch]` (verification, other) `A_deleted_Applications_purge_and_a_Tenant_purge_delete_its_grants_first` runs only the deleted-Application purge — renamed it and its summary; the Tenant purge is covered by `TenantSeeds` and `TenantDeletionOperationTests`.
  - `[low]` `[reject]` (verification, other) The machine-to-machine table stops at 20 pages (1,000 Applications) without saying so — a Tenant with over 1,000 Applications is far from everyday use, and a truncation notice adds a new state and copy.
  - `[medium]` `[defer]` (blind) `directory.api.grant_updated`/`grant_removed` don't name the Application, which the spec asks for — the audit envelope (`AuditEvent`) holds one target by design (AD-16, architecture-tested) and `AuditDetail` holds only personal data; Story 3.6's Permission events share the limit. Recording a second object needs an audit-model change beyond this story.
  - `[low]` `[reject]` (blind) Removing a Permission silently de-authorizes an Application left with no values, with no grant event or dashboard warning — `directory.api.permission_removed` records the cause; a per-Application event loop and a warning add branches for a rare case.
  - `[low]` `[patch]` (blind) `IApiManagement.RemoveGrantAsync`'s doc says the result is `Done` when there's no grant; the code returns `Unchanged` — corrected the comment.
  - `[low]` `[reject]` (blind) A 200-value grant of long values, written in both `scope` and `permissions`, could make a ~52 KB token — the two claims are the user's decision, and 200 near-maximum values is not everyday use; a size cap is new design.
  - `[false]` `[reject]` (blind) An unauthorized machine client still gets a token with `aud` — same as the first intent row; spec-mandated and the token carries no Permission.
  - `[low]` `[reject]` (blind) The machine-to-machine table silently stops at 1,000 Applications — grouped with the verification note above; same reason.
  - `[low]` `[reject]` (blind) The `application.audiences` column is still written on insert but never read — it takes its empty default, which the system CHECK requires (Story 2.8); dropping it is a migration the spec excluded ("the column is untouched").
  - `[low]` `[reject]` (blind) Grant actions: Remove authorization has no confirmation, an unauthorized row's button reads "Edit", and Edit with no Permissions opens a modal with no Save — the modal explains there are no Permissions and the effect is reversible by re-granting; copy and flow changes are UX additions for little gain.
  - `[low]` `[reject]` (blind) The dashboard's grant failure states (modal failed/forbidden/401, load failed, remove failed) have no browser tests — they reuse the page's shared problem-rendering; the gap leaves no behaviour wrong.
  - `[low]` `[patch]` (blind) Protocol cases untested: repeating the authorization's own API at exchange and refresh, and a Client Credentials scope of only ungranted values — added both to `ApiTargetTests`. (Refresh naming an API when the family has none, and `resource`+`audience` with the same value, are refused by the same one-value rule already tested.)
  - `[low]` `[patch]` (blind) The `SetApiGrant` OpenAPI description says empty or oversized lists name the value's index; `CheckGrant` reports those with no index — reworded and regenerated the contract.
  - `[low]` `[patch]` (blind) `ApiRows.Grants` orders by `g.application_id` (a UUID) — now ordered by `a.name, g.application_id`. The 200 cap read through three names is rejected: all resolve to `SecurityLimits.MaxPermissionsPerApi`.
  - `[maybe-false]` `[reject]` (edge) A grant write racing a concurrent Application delete and its purge could leave a grant for a deleted Application — the RESTRICT FK makes either the insert or the purge's DELETE fail (`purge_conflict`, retried); settling it needs a concurrency test, and if true it is low: a narrow race whose fix adds row locking.
  - `[low]` `[reject]` (edge) Removing a Permission that was an Application's only value de-authorizes it with no grant event — grouped with the blind finding above; same reason.
  - `[false]` `[reject]` (edge) Pre-3.7 refresh families with no `gk_api` claim keep refreshing and now get no `aud` — those tokens carried only the placeholder, which granted nothing; a family with no API gets exactly what a new code flow naming no API gets.
  - `[low]` `[reject]` (edge) The machine-to-machine table silently stops at 1,000 Applications — grouped with the verification note above; same reason.
  - `[low]` `[reject]` (edge) Remove authorization answered 404 (Application deleted elsewhere) leaves the row with a generic failure — rare, a reload clears it, and the fix adds a branch.
  - `[maybe-false]` `[reject]` (edge) The grant modal shows only a generic failure on a 400 `unknown` or a 404/409 — settling it needs the rendered copy for each problem; if true it is low and rare, and specific copy adds branches.

## Design Notes

- **The user's decisions (2026-11-14):**
  - A request names one API, with `resource` or `audience`.
  - Client Credentials with no API named is refused.
  - Permissions appear as a `permissions` array, alongside `scope`.
  - An empty `scope` means every granted Permission.
- **Why grants are per value:** a foreign key to `permission` makes a grant on a removed Permission impossible, and "authorized" is simply "has rows".
- **Why Management API grants are refused:** FR-42 and Story 17.2 put them behind Owner-only access, a fresh assertion and a Security Alert, together with the Admin-host token endpoint. Refusing them here keeps the Hosted path free of Management Permissions.
- **Why a code flow with no API has no `aud`:** the placeholder must go, and the default audience is Story 4.6/4.9's. Userinfo doesn't check `aud`.

## Verification

**Commands:**
- **.NET build:** with `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors.
- **Contract:** regenerate with `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v "D:/Projects/Personal/gatekeep:/out" -w /src gatekeep/tests:local sh deploy/docker/api-contract.sh --write /out`. Then run `pnpm -r build`, typecheck, and the dashboard and api-client unit tests in `gatekeep/tests:local`. Expected: all clean.
- **Targeted Isolation tests:** run `docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal -v "D:/Projects/Personal/gatekeep:/src" -w /src gatekeep/tests:local sh -c '<pin the IPv4 as deploy/docker/run-tests.sh does>; dotnet test tests/Isolation --filter "<classes>"'` on the new and changed classes only (all of `Protocol/*`, `Apis/*`, and `Applications/ApplicationLifetimeProtocolTests`). Then run the Architecture suite and the `admin-apis` Playwright project. Memory is tight, so don't run the full Isolation suite; CI does.

## Auto Run Result

**Summary:** Directory gains `api_grant` (the Permissions of one API granted to one machine-to-machine Application), managed from the API detail page and two Admin routes. Hosted resolves the one API a request names by `resource` or `audience`: Client Credentials tokens carry it as `aud` with exactly the requested Permissions that are currently granted (in `permissions` and `scope`), the Story 2.5 placeholder audience is gone, the Management API audience is refused, an API with offline access off gets no refresh token, and token lifetimes take the shorter of the Application's and the API's.

**Files changed:**
- `src/Adapters/Postgres/Migrations/Migration20261122000000AuthorizeMachineApplications.cs` — `api_grant` with RLS, row guard, RESTRICT foreign keys and role grants (Hosted reads only what resolution needs).
- `src/Adapters/Postgres/Schema/TableRegistry.cs` — the new table and column grants.
- `src/Modules/Directory/**` — grant read/write methods, events `directory.api.grant_updated`/`grant_removed`, Permission removal deleting its grants, purges deleting grants first, `DirectoryApplication.Audiences` removed.
- `src/Modules/Management/**`, `src/Gatekeep.Host.Admin/**` — `PUT`/`DELETE /apis/{apiId}/grants/{applicationId}`, `grants` on the API detail, `application_not_machine`, OpenAPI text.
- `src/Modules/Protocol/Core/ApiTargets.cs` (new), `TokenEndpoint.cs`, `AuthorizeEndpoint.cs`, `RefreshTokens.cs`, `ApplicationLifetimes.cs`, `ProtocolServer.cs`, `ProtocolContract.cs` — target resolution, Permissions, the private `gk_api` claim, offline access, per-API lifetimes; placeholder removed.
- `apps/admin-dashboard/src/shell/ApiDetailPage.tsx`, `apis.ts`, `packages/ui/src/messages.tsx`, `packages/api-client/**` — the machine-to-machine section, grant modal and client methods.
- `docs/api/openapi-v1.json`, `docs/audit-events.md`, `LogCatalogue.Generated.cs`, `schema.generated.ts` — regenerated.
- Tests: new `tests/Isolation/Apis/ApiGrantsApiTests.cs` and `tests/Isolation/Protocol/ApiTargetTests.cs`; updated Protocol, lifetime, migration-count, cross-Tenant, canary, capability and Admin API rule tests; `tests/browser/admin-apis.spec.ts`.

**Review findings:** 27 findings (medium 4, low 16, false 5, maybe-false 2). Patched 8 (3 medium, 5 low): tests for a deleted Application's hidden grant, API lifetimes on the code flow, the dashboard grant table after a Permission removal, repeated API at exchange and refresh, and a Client Credentials scope of only ungranted values; the `RemoveGrantAsync` doc; the `SetApiGrant` OpenAPI text; grant ordering by name; a test rename. Deferred 1 (medium): grant events don't name the Application (audit envelope holds one target). Rejected 18, each with its reason in the Review Triage Log.

**Follow-up review:** not recommended. The three medium patches were test additions that ran green, and the low patches were a comment, a description, an ORDER BY and a rename; no unverified risk remains from them. Patched counts: high 0, medium 3, low 5.

**Verification:** .NET build 0 warnings / 0 errors; `api-contract.sh` reports the contract matches; Isolation `Protocol/*`, `Apis/*` and `ApplicationLifetimeProtocolTests`: 264 of 264 pass after the patches. The implementer also ran the api-client (33), dashboard (115) and ui unit tests, Architecture (785 pass; the one failure is the known local-only `.claude/worktrees` check), the cross-Tenant, migration, purge, Applications and canary classes, and Playwright `admin-apis` (19 of 19).

**Residual risks:**
- Grant audit events name the API only (deferred above).
- Machine-to-machine table lists at most 1,000 Applications without a notice.
- Refresh families issued before this release carry no `gk_api` and refresh as no-API tokens (no `aud`).
- `/authorize` doesn't keep the named API in the stored sign-in parameters; Story 4.2's resumed sign-in must add it.
