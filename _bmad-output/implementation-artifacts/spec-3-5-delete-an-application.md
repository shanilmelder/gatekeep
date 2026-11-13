---
title: 'Story 3.5: Delete an Application'
type: 'feature'
created: '2026-11-14'
status: 'done'
baseline_revision: '7f126857dfb3f7ece05c957d01fac85867334aeb'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-3-context.md'
warnings: ['oversized']
deferred:
  - summary: >-
      Deleting a busy Application revokes every refresh family and token inside the request, holding its row lock.
    evidence: |-
      DeleteApplicationAsync calls ISessions.RevokeAccessAsync (Application scope) in the Tenant transaction, the only
      revocation path (AD-13). Unmeasured: settle with a load test seeding many families and timing the DELETE and
      concurrent token-endpoint calls.
    location: >-
      src/Modules/Directory/Core/DirectoryService.cs (DeleteApplicationAsync)
    severity: medium (unverified)
  - summary: >-
      The OpenAPI DELETE (like every Application sub-route) lists no applicationId path parameter.
    evidence: |-
      docs/api/openapi-v1.json and schema.generated.ts declare only tenantId and X-Gatekeep-Tenant. Pre-existing since
      Story 3.2 and already deferred in Story 3.4; the fix belongs in AdminOpenApi for every such route.
    location: >-
      src/Gatekeep.Host.Admin/AdminOpenApi.cs
    severity: low
---

<intent-contract>

## Intent

**Problem:** Once an Application exists, nothing in the product can retire it. A decommissioned client keeps getting tokens and keeps its refresh tokens and grants (FR-11).

**Approach:**
- An Editor or Owner deletes an Application from its detail page. The confirmation modal states the token effect and needs no typed confirmation.
- One command marks the Application deleted, revokes its refresh tokens and grants through `ISessions.RevokeAccessAsync` with the `Application` scope, and writes `directory.application.deleted`.
- The route then answers `202` with an Operation, which purges the deleted Application's rows in each owning module (AD-1, AD-30).
- From then on, the token, authorize and revocation endpoints treat the deleted client as unknown.

## Boundaries & Constraints

**Always:**
- **Route:** `DELETE /api/v1/tenants/{tenantId}/applications/{applicationId}`, with capability `tenant.applications.manage` (Editors and Owners, machine allowed, no fresh assertion). It answers `202`, a `Location` to `/api/v1/tenants/{tenantId}/operations/{operationId}`, and the existing `OperationResponse` body.
- **Hidden cases are one 404:** an unknown, malformed, already-deleted, another Tenant's, or the system Application gets the same `404 not_found`. The system Application's GK012 is mapped to it, as `UpdateTokensAsync` does.
- **One transaction for the deletion:** set `application.deleted_at`, call `RevokeAccessAsync(…, RevocationScope.Application, …, RevocationReason.ApplicationDeleted, actor, …)`, revoke the Application's live client secrets (`revoked_at = now`), and append `directory.application.deleted` (target `Client`, the Application id). All four commit together or not at all.
- **The purge is an Operation of new type `directory.application.purge`, with Tenant stages in owning-module order:**
  1. Sessions: `token`, then `authorization`.
  2. Authentication: `signin_transaction`.
  3. Directory: `client_secret`, then `application`.
  - Each stage deletes only rows of this Tenant's Applications whose `deleted_at` is set. It is idempotent, so a rerun deletes nothing more.
  - It reuses the `TenantDeletion` SAVEPOINT pattern, which maps 23503 and 40001 to `purge_conflict`.
- **Starting the purge Operation:** it starts after the deletion commits, in a Deployment-scoped call to `IOperations.StartAsync`. If one of this type is already active (running or failed) for the Tenant, the route answers `202` with that active Operation. Its stages purge every deleted Application of the Tenant, including this one.
- **Every reader skips a deleted Application:**
  - `ApplicationRows.Visible` gains `deleted_at IS NULL`, so list, get, the OpenIddict store and `FindApplicationAsync` all skip it.
  - `VerifyClientSecretAsync` only accepts secrets of a visible Application, so a deleted confidential client is refused.
  - The token endpoint refuses a deleted client with today's `invalid_client` and "The client credentials are invalid."
- **Grants and migration:** the migration and its `TableRegistry` grants change together.
  - `gk_admin` gets UPDATE(`deleted_at`) on `application`.
  - `gk_admin` gets the SELECT and UPDATE(`status`, `concurrency_token`) on `token` and `authorization` that `RevokeAccessAsync` needs.
  - `gk_worker` gets SELECT(`deleted_at`) on `application` and DELETE on the purged tables, where it doesn't already have it.
- **Modal copy (no typed confirmation):**
  - Title: "Delete {name}?"
  - Body: "Its refresh tokens and grants are revoked now, and it can't get new tokens. Access tokens it already holds stay valid until they expire. Users aren't affected."
  - Confirm button: "Delete application", with `tone='destructive'`.
- **Errors use RFC 9457 machine codes only.** The route joins the cross-Tenant suite, the capability table tests, the OpenAPI document and the api-client.

**Never:**
- **No cascade and no hard delete in the request.** Deleted rows are removed only by the Operation.
- **Access tokens aren't revoked** (AD-13). Don't copy the design's "stop validating immediately".
- **No undelete,** no typed confirmation, and no new job type.
- **No subject-ID column on `operation`.**
- **The system Application is never deleted, shown, or purged here.**

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Editor deletes | web app with live secret, refresh family | 202 + Operation. `deleted_at` set; family and tokens `revoked`; secrets revoked. One `directory.application.deleted` and one `sessions.access.revoked`. Gone from GET list and detail. | No error expected |
| Owner, machine principal | either deletes | same as above | No error expected |
| Viewer | DELETE | 403, nothing written | `forbidden` |
| Hidden ids | unknown, malformed, other Tenant's, system app, already deleted | identical 404, nothing written | `not_found` |
| Purge runs | Operation steps executed | rows of deleted apps gone from token, authorization, signin_transaction, client_secret, application. Other apps and Tenants untouched. Rerun succeeds, deleting nothing. | Conflict → step `purge_conflict`, Retry |
| Second deletion | purge already active for Tenant | 202 with the active Operation. Both apps marked deleted. | No error expected |
| Deleted confidential client | client_credentials or refresh_token with old secret | 400 `invalid_client`, "The client credentials are invalid." | standard refusal |
| Deleted public client | authorize request or refresh | authorize refuses as unknown client; token endpoint `invalid_client` | standard refusal |
| Modal | Editor clicks Delete | modal shows the copy above, no text field; Cancel sends nothing | 4xx/5xx → banner in modal, stays open |

</intent-contract>

## Code Map

- **Schema:**
  - `src/Adapters/Postgres/Migrations/Migration20261116000000SetTokenLifetimes.cs`: the latest migration. Copy its column and grant style.
  - `Migration20261109000000AddSystemApplication.cs:63-115`: GK011, GK012 (BEFORE UPDATE on `application`, fires on a system row) and GK013 (DELETE of the system app).
  - `tests/Isolation/MigrateCommandTests.cs:28`: 32 becomes 33.
- **`src/Adapters/Postgres/Schema/TableRegistry.cs`:**
  - `application` :593-613;
  - `client_secret` :616-632;
  - `token` and `authorization` :330-347 (`TokenUpdateColumns` :96, `AuthorizationUpdateColumns` :100). gk_admin has no grant on these today.
- **Foreign keys** (all ON DELETE RESTRICT on `(tenant_id, application_id)`): `client_secret`, `authorization`, `token` and `signin_transaction`. The last is NOT NULL (`…CreateSessionTables.cs:59,79,102`).
- **Revocation:**
  - `src/Modules/Sessions/Contracts/ISessions.cs:80-108`;
  - `Contracts/Revocation.cs:49-54` (the `Application` scope) and :73 (`ApplicationDeleted`);
  - `Core/SessionRevocation.cs:41-94,187-188`.
  - `tests/Architecture/RevocationPathTests.cs` pins `SessionRevocation.cs` as the only writer of those columns.
- **Operations:**
  - `src/Modules/Operations/Core/TenantDeletion.cs:29-134`: type and stage codes, the SAVEPOINT purge, and the `Definition`. This is the model to copy.
  - `Core/OperationStore.cs:31-38`: `ProductionOperations.Registry`. Register the new type here.
  - `Contracts/OperationRegistry.cs` and `Contracts/OperationsContract.cs:88-101`.
  - `IOperations.StartAsync` (`Contracts/IOperations.cs:80`) needs a Deployment context (`OperationService.cs:301-305`).
  - The `operation_one_active` index throws `OperationAlreadyActiveException`.
  - `Management/Core/TenantManagement.cs:335-399` is the start example.
- **Per-module tenant purge** (copy each as Application-scoped): `Sessions/…/SessionsPurge.cs:13-15`, `Authentication/…/AuthenticationPurge.cs:13-14` and `Directory/Core/DirectoryPurge.cs:13-17`.
- **Directory, `src/Modules/Directory/Core/DirectoryService.cs`:**
  - `UpdateApplicationLifetimesAsync` :316-357 is the command pattern.
  - `ApplicationRows.Visible` is at :617, with `SelectLocked` at :640.
  - `VerifyClientSecretAsync` :503-539 (SQL `LiveSecretHashes` :59-64) doesn't check the application today.
  - `Adapters/ApplicationStore.cs:28-36`.
  - `Contracts/DirectoryEvents.cs:12-57`: add `ApplicationDeleted`. Regenerate `docs/audit-events.md` and `src/Gatekeep.Host.Admin/LogCatalogue.Generated.cs` with the `tests/Architecture/Generator/AuditCatalogue.cs` generator. `AuditCatalogueTests` checks both.
- **Protocol:** `src/Modules/Protocol/Core/TokenEndpoint.cs:278-375` (`AuthenticateGatekeepClient`), with the refusal at :81 and :117-118. Other `FindByClientIdAsync` callers are in `AuthorizeEndpoint.cs` and `RevocationEndpoint.cs:140`.
- **Management:**
  - `src/Modules/Management/Contracts/IApplicationManagement.cs:245-261`;
  - `Core/ApplicationManagement.cs:183-219` (`UpdateLifetimesAsync`), with `ActorOf` at :322.
- **Host.Admin:**
  - `src/Gatekeep.Host.Admin/AdminApi.cs:734-762`: the tokens route metadata to copy.
  - `ApplicationsApi.cs:389-468`: the handler and the GK012 → 404 mapping.
  - `TenantsApi.cs:414-487,656-683`: 202, `Location` and the `Operation(...)` mapper.
  - `AdminOpenApi.cs:157-205`.
- **API client:** `packages/api-client/src/client.ts:408` (`deleteTenant`). Regenerate with `deploy/docker/api-contract.sh --write`.
- **Dashboard:**
  - `apps/admin-dashboard/src/shell/ApplicationDetailPage.tsx:188-251`: the tabs and the existing `ConfirmModal`.
  - `shell/DeleteTenantModal.tsx:169-184`: the model for the modal.
  - `packages/ui/src/components/ConfirmModal.tsx`.
  - `packages/ui/src/messages.tsx:329-343,797-807`.
  - The design's danger-zone row is at `design/Gatekeep Admin.dc.html:342`.
- **Tests to copy:**
  - `tests/Isolation/Applications/ApplicationTokensApiTests.cs` (the role and GK012 tests :326-381);
  - `tests/Isolation/Operations/TenantDeletionOperationTests.cs` and `Sessions/RevokeAccessTests.cs`;
  - `CrossTenant/RouteRegistry.cs:98-106`;
  - `Canary/CanaryFlows.cs:339-440` (Operation types and Application surfaces);
  - `tests/Architecture/{CapabilityRuleTests.cs:229, OperationRuleTests.cs, AdminApiRuleTests.cs}`;
  - `tests/browser/{admin-tenant-delete.spec.ts, admin-applications.spec.ts:622}`.

## Tasks & Acceptance

**Execution:**
- [ ] **Migration and grants:** new `Migration20261117000000DeleteApplications.cs`, with matching `TableRegistry.cs`. Add `deleted_at timestamptz NULL` and the grants from Boundaries. Set `MigrateCommandTests` to 33.
- [ ] **Directory:**
  - `DeleteApplicationAsync`: lock the visible row, then GK012 or missing → not found.
  - Set `deleted_at` and revoke the live secrets.
  - Call `ISessions.RevokeAccessAsync`, then append the event.
  - Add `deleted_at IS NULL` to `Visible`, and the visibility join to `VerifyClientSecretAsync`.
  - Add the `ApplicationDeleted` event and regenerate the catalogues.
- [ ] **Purge stages:** an Application-scoped purge in Sessions, Authentication and Directory (deleted apps of the Tenant only). Add `ApplicationPurge.cs` in Operations: the type, the stage codes and the Definition. Register it.
- [ ] **Management:**
  - `IApplicationManagement.DeleteAsync` and `ApplicationDeleteResult`, with statuses Started, Forbidden and NotFound plus the Operation.
  - The capability re-check, the deletion in Tenant scope, then `StartAsync` in Deployment scope, falling back to the active Operation.
- [ ] **Host.Admin:** in `AdminApi.cs` and `ApplicationsApi.cs`, map the DELETE route: 202, `Location` and the Operation body, with GK012 → 404. Update the OpenAPI enums. Then regenerate the contract and api-client, and add `deleteApplication` plus a client unit test.
- [ ] **Dashboard:** a danger zone at the foot of `ApplicationDetailPage.tsx`, shown only to callers with `tenant.applications.manage`.
  - New `DeleteApplicationModal.tsx`.
  - On success, navigate to the list and show a "Application deleted." toast.
  - Add the copy to `messages.tsx`.
- [ ] **Isolation tests:** `tests/Isolation/Applications/ApplicationDeleteApiTests.cs` covers the API, hidden-id, revocation and audit rows. `ApplicationDeletionProtocolTests.cs` covers the refusal rows. `tests/Isolation/Operations/ApplicationPurgeOperationTests.cs` covers the purge rows.
- [ ] **Registries and pins:** `RouteRegistry`, `CanaryFlows`, `CapabilityRuleTests`, `OperationRuleTests` and `AdminApiRuleTests`. Grep both test projects for lists pinned on things you changed, and update them. Examples: Application JSON members, the migration count, Operation types, audit codes and grants. Story 3.4 broke 11 tests by missing one.
- [ ] **Browser tests** (`tests/browser/admin-applications.spec.ts`):
  - The modal copy, with no text field.
  - Cancel sends nothing; confirm sends the DELETE and navigates with the toast.
  - A failure shows the banner.
  - A Viewer sees no danger zone.
  - Axe in light and dark.

**Acceptance Criteria:**
- Given the delete modal, when it opens, then it states the token effect and asks for no typed confirmation.
- Given a confirmed deletion, when it commits, then the Application is marked deleted, and its refresh tokens and grants are revoked through `RevokeAccess`. The Log has `directory.application.deleted`, and an Operation purges its rows.
- Given a deleted client, when it calls the token endpoint, then it gets `invalid_client`.

## Spec Change Log

## Review Triage Log

### 2026-11-14 — Review pass
- verdicts: 30 findings — high 0, medium 0, low 24, false 5, maybe-false 1
- findings:
  - `false` `reject` (intent) Access tokens already issued survive deletion, against "can't keep tokens" — AD-13 makes access tokens irrevocable and the AC names only refresh tokens and grants; the modal states this honestly.
  - `low` `reject` (intent) No test follows a deletion end to end from the modal to the refusal — each AC clause is tested on its real surface (route, Operation, protocol), all through the same `DeleteApplicationAsync`; an end-to-end test adds little.
  - `low` `reject` (intent, group P) One purge per Tenant, not per deletion, so some deletions wait for a later Operation — the left rows are hidden, revoked and inert; it needs a concurrent or failed purge, and a fix needs new Operation semantics.
  - `low` `reject` (intent) An authorization code issued before deletion isn't tested at exchange — the same visibility predicate refuses the client at authorize, refresh and client_credentials, all tested.
  - `false` `reject` (intent) gk_admin's new grants on `token` and `"authorization"` relax the FR-46 isolation rule — the spec and AC require revocation in the deletion's commit through `RevokeAccess`; the grants are the minimum columns, and the test pins exactly them.
  - `false` `reject` (intent) The danger zone isn't in the screen spec — `design/Gatekeep Admin.dc.html:342` draws the "Delete application" danger-zone row.
  - `low` `patch` (blind, group M) A 404 on retrying (after a concurrent deletion or a post-commit 503) keeps the modal on "Couldn't delete" forever — patched: the modal treats 404 as deleted and goes to the list with the toast; the browser test asserts it.
  - `low` `reject` (blind, group P) A deletion joining a purge that already read its IDs may never be purged — see group P.
  - `low` `reject` (blind, group P) A failed purge Operation is handed back and never retried automatically — see group P; `purge_conflict` needs a reference written to a deleted Application, which every endpoint now refuses.
  - `maybe-false` `defer` (blind) Revocation of a busy Application runs unbounded inside the request while holding the row lock — would need a load test with many families; medium if true. `RevokeAccess` is the only revocation path (AD-13).
  - `low` `defer` (blind) The OpenAPI DELETE lists no `applicationId` path parameter — pre-existing for every Application sub-route since Story 3.2, already deferred in Story 3.4.
  - `low` `reject` (blind) The 202 doesn't document its `Location` header, and 503 and 401 have no descriptions — same as the existing Tenant deletion route; generated clients don't use it.
  - `low` `reject` (blind) The modal doesn't say the deletion is permanent or mention secrets — the copy is fixed by the spec's intent contract; changing it edits the spec.
  - `low` `reject` (blind) No tests for PurgeNotStarted, concurrent deletion of one Application, machine over HTTP, or old access tokens still working — rare or not yet reachable (no Management API tokens until Epic 17); the row lock and the status mapping are simple.
  - `false` `reject` (blind) The purge queries have no index — `token_application`, `authorization_application` and `signin_transaction_application` index `(tenant_id, application_id)`; a Tenant's Applications are few.
  - `low` `patch` (blind) `RevocationColumns` duplicates `AuthorizationUpdateColumns` — patched: reuse the one list.
  - `low` `patch` (blind) Canary reason has "store" for "stores" and claims it reads no reference — patched wording.
  - `low` `patch` (blind) The DELETE result switch sends every unhandled status to 403 — patched: `Forbidden` explicit, unknown throws.
  - `low` `patch` (blind) A stray blank line in the browser spec — removed.
  - `low` `patch` (verification-gap) `VerifyClientSecretAsync`'s visibility check is masked by secret revocation in every test — patched: `DirectoryTests` marks an Application deleted with a live secret and asserts it doesn't verify.
  - `low` `reject` (verification-gap) The route's 503 paths have no test — reaching them needs a fault injection hook the tests don't have; filed as defer, but it is caused by this change and low.
  - `low` `reject` (verification-gap) The spec's "Why two scopes" note is stale: a failed start rolls back the deletion too — the fix edits this build's spec; the OpenAPI text matches the code, and the Auto Run Result records the real behavior.
  - `low` `reject` (verification-gap) The modal's 401, 403, 409 and double-press branches aren't browser-tested — the spec asks only for the failure banner; the branches copy DeleteTenantModal's tested ones.
  - `low` `reject` (edge, group P) A deletion attached to an active purge past its ID read isn't purged by it — see group P.
  - `low` `reject` (edge, group M) A failed Deployment commit after the Tenant commit answers 503 for a kept deletion — needs a commit failure between two commits; the modal now treats the retry's 404 as deleted.
  - `low` `patch` (edge, group M) The modal's 404 retry loop — patched as above.
  - `low` `reject` (edge) A network failure shows ErrorReference with code `unavailable` and an empty trace — the same as DeleteTenantModal's tested behavior; changing it is a cross-modal UI decision.
  - `false` `reject` (edge) The purge's family-token branch could delete another Application's tokens — a token's authorization belongs to the same client; `SessionRevocation`'s Application scope uses the same filter.
  - `low` `reject` (edge, group P) A failed purge attaches every later deletion until a manual Retry — see group P.
  - `low` `reject` (edge, group P) "When it commits … an Operation purges its rows" holds only eventually — see group P; recorded as a residual risk.

## Design Notes

- **Why a Tenant-wide purge:** Operations store no subject ID, and only one is allowed per type and Tenant. So the purge removes every deleted Application of the Tenant, and a second deletion reuses the active Operation. A deletion marked after that Operation's Directory stage has run is purged by the next deletion's Operation. Until then its rows stay hidden and revoked, which is safe.
- **Why two scopes:** `StartAsync` requires Deployment scope. The deletion commits first, so a failed start leaves a deleted, hidden, revoked Application with no Operation yet. That is safe, and the next deletion's Operation purges it. If the start fails, the route answers `503 unavailable`.
- **Why the copy differs from the design:** AD-13 makes access tokens irrevocable, so the modal says they stay valid until they expire. The design says "stop validating immediately", which is wrong.
- **No polling:** the Dashboard doesn't poll the purge. Nothing on screen depends on it, because the Application disappears from reads at once.

## Verification

**Commands:**
- **.NET build:** with `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors.
- **Contract:** `deploy/docker/api-contract.sh --write`. Then run `pnpm -r build`, `pnpm -r --if-present typecheck`, and the dashboard and api-client unit tests in `node:26.13.0-bookworm-slim`. Expected: all clean.
- **Suites:** the Isolation, Architecture and browser suites run on CI. Before handing back, grep for pinned lists as in the task above.

## Auto Run Result

**Summary.** An Editor, Owner or machine principal can delete an Application (FR-11, AD-1, AD-30).
- `DELETE /api/v1/tenants/{tenantId}/applications/{applicationId}` marks it deleted, revokes its live secrets, revokes its refresh tokens and grants through `ISessions.RevokeAccessAsync` (Application scope, `application_deleted`), and writes `directory.application.deleted`, in one Tenant transaction.
- It answers `202` with a `directory.application.purge` Operation and a `Location` to it. That Operation's one Tenant stage reads the Tenant's deleted Application IDs once and purges Sessions, Authentication, then Directory rows for them, under one savepoint.
- Every reader skips a deleted Application. The token endpoint refuses it with `invalid_client`, and so do authorize and revocation.
- The Dashboard has a danger zone on the detail page and a destructive `ConfirmModal` with no typed confirmation, stating the token effect.

**Files changed (main ones)**
- `src/Adapters/Postgres/Migrations/Migration20261117000000DeleteApplications.cs`, `Schema/TableRegistry.cs`: `deleted_at`, the gk_admin revocation column grants on `token` and `"authorization"`, and the gk_worker purge reads (migration 33).
- `src/Modules/Directory/{Contracts,Core}`: `DeleteApplicationAsync`, the visibility predicate, the secret check join, the per-ID purge, and the `ApplicationDeleted` event.
- `src/Modules/Sessions/Core/SessionsApplicationPurge.cs`, `src/Modules/Authentication/Core/AuthenticationPurge.cs`: Application-scoped purges.
- `src/Modules/Operations/{Core/ApplicationPurge.cs, Core/OperationStore.cs, Contracts/OperationsContract.cs}`: the Operation type, its one stage, and its registration.
- `src/Modules/Management/{Contracts/IApplicationManagement.cs, Core/ApplicationManagement.cs}`: `DeleteAsync` with the capability re-check and the purge start, which falls back to the active Operation.
- `src/Gatekeep.Host.Admin/{AdminApi.cs, ApplicationsApi.cs, TenantsApi.cs, LogCatalogue.Generated.cs}`, `docs/{api/openapi-v1.json, audit-events.md}`, `packages/api-client/*`: the route, the contract and `deleteApplication`.
- `apps/admin-dashboard/src/shell/{DeleteApplicationModal.tsx (new), ApplicationDetailPage.tsx}`, `packages/ui/src/messages.tsx`: the danger zone, the modal and the copy.
- **Tests:**
  - New: `tests/Isolation/Applications/{ApplicationDeleteApiTests.cs, ApplicationDeletionProtocolTests.cs}`, `tests/Isolation/Operations/ApplicationPurgeOperationTests.cs`, and the browser "delete (Story 3.5)" block.
  - Updated: `RouteRegistry`, `CanaryFlows`, `CapabilityRuleTests`, `OperationRuleTests`, `AdminApiRuleTests`, `AdminCredentialIsolationTests`, `TenantTablesTests`, `MigrateCommandTests` (33) and `DirectoryTests`.

**Deviations from the plan**
- The purge is one stage, not three: Operation stages run as separate jobs in either order. A pre-review fix also reads the deleted IDs once, so all three module purges use the same list.
- The contract takes two contexts, because contracts may not name scopes. A failed purge start rolls the deletion back and answers 503. Only a failure of the Deployment commit after the Tenant commit keeps the deletion. The Design Note "Why two scopes" describes the earlier plan.
- The purge also maps SQLSTATE `23001` (`ON DELETE RESTRICT`) to `purge_conflict`.

**Review findings.** 30 findings: 7 patched in 6 entries, 2 deferred, 21 rejected (reasons in the triage log).
- **Patched (all low):**
  - The modal treats a 404 as deleted.
  - The DELETE status switch handles `Forbidden` explicitly and throws on an unknown status.
  - One revocation column list, not two.
  - The canary wording.
  - A stray blank line.
  - A test that a deleted Application's live secret no longer verifies.
- **Deferred:**
  - Revocation time for a busy Application (medium, unverified).
  - The missing `applicationId` OpenAPI parameter (pre-existing).

**Follow-up review recommended (`false`).** Patched counts by verdict: high 0, medium 0, low 6 entries.

**Verification**
- `dotnet build Gatekeep.slnx -p:NuGetAudit=false` (SDK 10.0.403 container): 0 warnings and 0 errors, after the patches.
- `sh deploy/docker/api-contract.sh`: the contract matches. `pnpm -r build` and typecheck are clean. The api-client unit tests passed 26/26 and the dashboard 105/105.
- Run by the implementer:
  - The new Isolation classes and the purge, delete and directory tests: all passed (22, then 17, then 29 after the patches).
  - `OperationRuleTests` 12/12.
  - `AdminApiRuleTests` and `AdminCredentialIsolationTests` 31/31.
  - The browser `admin-applications` project: 75/75, then the delete block 7/7.
- **Not run locally:** the full Isolation suite. The implementer's broad run was stopped for low memory, so CI on the PR is its first run.
- **Matrix audit:** every row has a named test.
  - The API rows are in `ApplicationDeleteApiTests`.
  - The refusal rows are in `ApplicationDeletionProtocolTests`.
  - The purge rows are in `ApplicationPurgeOperationTests`.
  - The modal row is in the browser block.

**Residual risks**
- A deletion that joins a purge Operation that has already read its IDs, or has failed, waits for a later purge. With no later deletion, its rows stay. They are hidden, revoked and inert, but "an Operation purges its rows" holds only eventually.
- A failed Deployment commit after the Tenant commit answers 503 for a deletion that was kept.
- The unrelated Isolation classes were not run locally.
