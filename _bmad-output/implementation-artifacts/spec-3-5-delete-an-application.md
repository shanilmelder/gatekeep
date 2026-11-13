---
title: 'Story 3.5: Delete an Application'
type: 'feature'
created: '2026-11-14'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-3-context.md'
warnings: ['oversized']
deferred: []
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
