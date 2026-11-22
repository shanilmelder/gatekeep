---
title: 'Story 4.12: Choose Connections per Application'
type: 'feature'
created: '2026-11-22'
status: 'done'
baseline_revision: 'e302861602f55ebb4a196975a6d5b422f96a2e3b'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-4-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-4-6-configure-the-database-connection.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-4-9-sign-in-with-a-password.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** Every Application offers the Tenant's database Connection, and there's no way to turn it off for one app. A reused Session skips Login even for an app whose Connection is off. Login also renders a form even when nothing can sign in. (FR-14, UX-DR32)

**Approach:**
- **Storage:** add `application_connection` (Directory), which records which Connections each Application allows.
- **Admin:** Admins toggle them on Application · Connections and see the users of a Connection on Database · Applications.
- **Hosted Login:** it offers, and the server accepts, only Connections enabled for the transaction's Application. A Session reused at authorize must come from one of them, or the User signs in again.
- **Exceptions and defaults:** the system Application follows every Tenant-enabled Connection, and a new Application starts with every enabled Connection on.

## Boundaries & Constraints

**Always:**
- **Schema:** one migration, `Migration20261201000000ApplicationConnections.cs`. Check `main`'s newest migration before pushing, and bump `MigrateCommandTests` 46 → 47 in all four places.
  - **`application_connection`:** `tenant_id`, `application_id`, `connection_id`, `enabled boolean NOT NULL`, `updated_at`.
    - **Keys:** PK `(tenant_id, application_id, connection_id)`, with composite FKs to `application` and `connection` (`ON DELETE RESTRICT`).
    - **Table setup:** a Directory, `tenant`, Runtime table with the RLS pair and `tenant_row_guard`, copying the loop in `Migration20261127000000ConfigureDatabaseConnection.cs:102-124`, plus a `TableRegistry` entry.
    - **Grants:** `gk_admin` SELECT, INSERT and `UPDATE (enabled, updated_at)`; `gk_hosted` SELECT; `gk_worker` `SELECT (tenant_id, application_id)` and DELETE (purge).
  - **Backfill:** for every existing non-system Application, one row per Tenant Connection, with `enabled = true`.
  - **System Application:** it gets no rows.
- **Effective rule** (one Directory method, used everywhere): a Connection is enabled for an Application when `connection.enabled` is true and either:
  - the Application is the system Application (`kind = 'system'`), or
  - it has an `application_connection` row with `enabled = true`.

  A missing row means off. Deleted Applications enable nothing.
- **Directory** (`IDirectory` plus `DirectoryService`):
  - **`FindDatabaseConnectionForApplicationAsync(context, Guid? applicationId, ct)`:** returns the database Connection with its `Enabled` already narrowed by the effective rule. A null `applicationId`, as on a link with none, means the system Application's view (Tenant-level).
  - **Every Hosted check site that reads `FindDatabaseConnectionAsync(...) is { Enabled: true }`** switches to it, passing the transaction's (or link's) `ApplicationId`:
    - `SignInService.cs:101`
    - `SignUpService.cs:99, 110, 174, 293, 329`
    - `PasswordResetService.cs:334-337`
    - `ReadPolicyAsync`, which gains an `applicationId`
  - **`CreateApplicationAsync`:** inserts an enabled row for every enabled Tenant Connection, in the same command (`DirectoryService.cs:231-243`).
  - **Purge:** both purges delete `application_connection` before `application` and `connection` (`DirectoryPurge.cs:13-26`), and the deleted-Application purge deletes that Application's rows (`:55-71`).
- **Management and Admin API** (`IConnectionManagement`, `AdminApi.cs`, handlers beside `ApplicationsApi.cs` and `DatabaseConnectionApi.cs`). Problems use the existing codes and statuses only.

  | Route | Capability | Result |
  |---|---|---|
  | `GET /api/v1/tenants/{tenantId}/applications/{applicationId}/connections` | `tenant.configuration.read` | `{connections: [{connectionId, name, kind: "database", enabled, tenantEnabled}]}` |
  | `PUT /api/v1/tenants/{tenantId}/applications/{applicationId}/connections/{connectionId}` `{enabled}` | `tenant.connections.toggle` | 200 with the row |
  | `GET /api/v1/tenants/{tenantId}/connections/database/applications` | `tenant.configuration.read` | `{applications: [{id, name, type}]}`: the non-system, non-deleted Applications with it enabled, ordered by name |

  - **The PUT:** writes one command plus the audit event `directory.application_connection.updated` (Actor the Admin, target the Application, no detail). An unchanged value writes no event.
  - **404 `not_found`** for an unknown, malformed, deleted, other-Tenant or system Application, and for an unknown Connection, as Epic 3's Application routes do.
  - **Regenerate:** `docs/api/openapi-v1.json`, `packages/api-client`, and `docs/audit-events.md` / `LogCatalogue.Generated.cs`.
  - **Registries:** add the routes to `RouteRegistry` and to `CapabilityRuleTests.ConnectionRoutes`.
- **Hosted Login:**
  - **No enabled Connection:** when the transaction's Application has none, the Login page, Continue, restart and Extend all answer Generic error `temporarily_unavailable`, the same for every identifier.
  - **Direct requests refused:** the password, sign-up (`open`, submit, Continue), resend, reset (`open`, request, page, complete, new-link) and verification-link routes, posted for an Application whose Connection is off, answer exactly as each already does for a disabled Connection. They write nothing and send nothing.
  - **Login's "Sign up" link** follows the narrowed policy.
- **Session reuse** (`HostedAuthorizationSignIn.SignInAsync`, `HostedSignIn.cs:278-286`):
  - `LiveSession` gains `ConnectionId` (`SelectLive`, `SessionService.cs:36-42`).
  - A live Session is reused only when its `ConnectionId` is enabled for the requesting Application, or is null (a Session not started through a Connection: test-only and pre-4.7 ones).
  - Otherwise authorize proceeds to Login as it does when `prompt=login` requires it. The Session isn't revoked, and the new sign-in rotates it through `StartOrRotateAsync`.
- **Admin dashboard** (copy in `messages.tsx`):
  - **Application · Connections tab:**
    - **Placement:** in `ApplicationDetailPage.tsx`'s tabs after Tokens, with `param="tab"` value `connections`.
    - **Card:** headed "Connections enabled for this app", with the subtext "Users can only sign in to {application} through enabled connections."
    - **Row:** one per Connection, showing the mono badge, the name ("Username-Password"), the kind ("Database"), "Enabled" or "Disabled", and a `Toggle`.
    - **Saving:** a toggle saves immediately (with an in-flight guard) and shows the `toast` "Changes saved". On failure it reverts and shows the error `Banner`.
    - **Viewers** get a read-only toggle with the view-only banner.
    - **No usable Connection:** when no row is both enabled and `tenantEnabled`, the `banner` reads "No Connections enabled. Users can't sign in."
  - **Database · Applications tab** (`DatabasePage.tsx`, after Password policy, `tab=applications`):
    - **Rows:** each shows the Application's name and type, and links to that Application's `?tab=connections`.
    - **Empty state:** "Not used by any application".
  - **Hidden:** no controls for other Connection kinds (Design Delta).
- **Tests:**
  - **New `tests/Isolation/Directory/ApplicationConnectionTests.cs`:**
    - grants and RLS;
    - the backfill;
    - the effective rule, including the system Application, a missing row and a Tenant-disabled Connection;
    - new-Application defaults.
  - **New `ApplicationConnectionsApiTests.cs`:**
    - every route, the capabilities (an Editor can toggle, a Viewer can't, a machine principal can);
    - the audit event, including none when unchanged;
    - the 404s.
  - **Hosted tests:**
    - the disabled-Application Login and its refused routes;
    - Session reuse forcing sign-in, then rotation;
    - the system Application still signing in.
  - **Updated registries:** `TenantSeeds`, `TenantPurgeRegistryTests`, `HostedGrantsTests`, `ApplicationPurgeOperationTests`, `TenantCreationOperationTests` (if Application creation runs there), and `AdminEndpointTests`' route list.
  - **Browser:** both tabs (toggle, toast, the no-Connections banner, the Viewer view, the empty state, the links) with axe in light and dark. Give a new spec its own Playwright project and `testIgnore` entry.

**Never:**
- No Tenant-level enable or disable control for the Connection itself, and no other Connection kinds (Epic 14).
- No change to the system Application's row; it gets no `application_connection` rows.
- No revocation when a Connection is turned off. Reuse is refused, and existing tokens run to expiry.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Off for this app | App A off, app B on | A's Login → Generic `temporarily_unavailable`; B's Login renders | generic |
| Direct request | password/sign-up/reset POST on A's transaction | refused as for a disabled Connection; nothing written | refused |
| Banner | A has no usable Connection | Application · Connections shows the banner | banner |
| Session from an off Connection | live Session via the database Connection; A turns it off; A authorizes | Login shown (not skipped); signing in rotates the Session | No error expected |
| Session still allowed | B on | reuse skips Login as before | No error expected |
| System Application | Portal authorize | follows the Tenant-level Connection; signs in | No error expected |
| New Application | created after the migration | row enabled for the database Connection | No error expected |
| Toggle | an Editor PUTs `enabled:false` | 200, row off, `directory.application_connection.updated` | No error expected |
| Unchanged | PUT the same value | 200, no new event | No error expected |
| Viewer | a Viewer PUTs | 403 | refused |
| System or foreign app | PUT on the system or another Tenant's Application | 404 `not_found` | refused |
| Database · Applications | A on, B off | lists A only; the system app is never listed | No error expected |

</intent-contract>

## Code Map

- **Schema:**
  - `src/Adapters/Postgres/Migrations/Migration20261127000000ConfigureDatabaseConnection.cs`: `connection` :54-73, the RLS loop :102-124, grants :128-137, the backfill `ForEachTenant` :38-46,148.
  - `Migration20261109000000AddSystemApplication.cs:50-58` (`kind = 'system'`, `application_one_system`).
  - `Schema/TableRegistry.cs:785-811` (the `connection` entry to copy).
  - The newest migration is `Migration20261130000000PasswordReset.cs`.
- **Directory:**
  - `Contracts/IDirectory.cs:133,276-290,420-446`, `Contracts/DatabaseConnection.cs:26,71-84`, `Contracts/DirectoryEvents.cs:111-128`.
  - `Core/DirectoryService.cs:203-260` (create), `DirectoryService.Connections.cs:11-62,101-209`, `Core/DirectoryPurge.cs:13-26,55-71`.
  - Tenant activation: `src/Modules/Operations/Core/TenantCreation.cs:132,138` and `TenantKeyBackfill.cs:63,71` (the system Application needs no rows).
- **Management and Admin:**
  - `src/Modules/Management/Core/ConnectionManagement.cs:22-106` and `Contracts/IConnectionManagement.cs`.
  - `src/Gatekeep.Host.Admin/AdminApi.cs:836-878` (Connection routes) and :951-1150 (Application routes); `ApplicationsApi.cs:130`; `DatabaseConnectionApi.cs`; `AdminResponses.cs`; `AdminOpenApi.cs`.
  - `src/Modules/Admins/Contracts/AdminCapabilities.cs:132,158`.
- **Hosted:**
  - The `ApplicationId` field is `IAuthentication.cs:61`.
  - Checks: `SignInService.cs:101`, `SignUpService.cs:95-110,174,293,329,357-363`, `PasswordResetService.cs:101,190,211,284,334-337`.
  - `HostedSignIn.cs`: `Current` :177-234, reset gates :425,470, `PageAsync` :714-728, `IdentifierAsync` :740-808, `ExtendAsync` :825, sign-up :836-963, `PasswordAsync` :1023-1059, `Login` helper :1493, authorize reuse :278-286.
  - Sessions: `ISessions.cs:12,29-34`, `SessionService.cs:36-42,130,169`.
- **Dashboard:** `apps/admin-dashboard/src/shell/ApplicationDetailPage.tsx:195-243`, `ApplicationTokens.tsx` (the tab pattern), `DatabasePage.tsx:135-200,267,274-400`, `database.ts`, `packages/ui/src/messages.tsx`, `packages/api-client/src/index.ts`.
- **Tests:**
  - `tests/Isolation/Directory/DatabaseConnectionTests.cs`, `DatabaseConnectionApiTests.cs:289`.
  - `Tenancy/TenantSeeds.cs:44-54`, `TenantPurgeRegistryTests.cs:107-126`, `CrossTenant/HostedGrantsTests.cs:90`, `RouteRegistry.cs:106-120`, `MigrateCommandTests.cs:20,28,43,78`.
  - `tests/Architecture/CapabilityRuleTests.cs:338-345`, `AdminApiRuleTests.cs`, `tests/Isolation/Admins/AdminEndpointTests.cs:95-111`.
  - `tests/browser/admin-applications.spec.ts`, `admin-database.spec.ts`, `playwright.config.ts:75,194-199`.

## Tasks & Acceptance

**Execution:**
- The migration plus `TableRegistry`, the seeds, the purge registry and the migration count.
- Directory: the effective-rule read, the default rows on create, the toggle command and event, the list of Applications using a Connection, the purges.
- Management, the Admin routes, OpenAPI, the api-client and the docs regeneration.
- Hosted: switch every check site to the per-Application read, the Login Generic error with no usable Connection, and Session reuse by Connection.
- Dashboard: the two tabs and their copy.
- The tests and browser specs listed above. `docs/threat-model.md`: one line under the Hosted or Admin rows describing per-Application Connections and the reuse rule.

**Acceptance Criteria:**
- Given a Connection disabled for an Application, when that Application starts sign-in, then Hosted Login doesn't offer it, and a direct request to any of its routes is refused.
- Given no enabled Connections, when the settings page shows, then a banner warns that Users can't sign in, and Login shows Generic error.
- Given a Session from a Connection disabled for this Application, when the Application requests sign-in, then the User signs in again.
- Given the system Application, when Connections change, then it follows every Connection enabled in the Tenant.
- Given a new Application, when it is created, then every enabled Connection is on.

## Spec Change Log

## Review Triage Log

### 2026-11-22 — Review pass
- verdicts: 35 findings — high 0, medium 4, low 22, false 3, maybe-false 6
- findings:
  - `low` `reject` (Intent) Login can't hide one Connection and keep another — v1 has one Connection kind (Design Delta); per-kind Login arrives with Epic 14.
  - `low` `reject` (Intent) The banner is on the Connections tab, not the Settings tab — the UX table places it on Application · Connections.
  - `low` `reject` (Intent) Sessions with no recorded Connection stay reusable — a deliberate Design Note: they are pre-4.7 or test-only, and refusing them would sign everyone out.
  - `maybe-false` `reject` (Intent) The system-Application test doesn't go through the Portal — the Portal is Epic 16; the rule is tested at the Directory and service layers. If it hid a defect it would be low.
  - `medium` `patch` (Intent) An Application created while the Connection is off stays off after it comes back — `InsertDefaults` now writes a row for every Connection.
  - `false` `reject` (Intent) Database · Applications can't toggle — the design draws a read-only list that links to the Application.
  - `maybe-false` `reject` (Intent) The Admin screens are tested only against a stubbed API — the routes are tested on the real host; that is the project's browser pattern.
  - `medium` `patch` (Blind) A Connection created after a Tenant's Applications leaves them all off — Ensure writes enabled rows for the existing Applications (a new `gk_worker` INSERT grant).
  - `medium` `patch` (Blind) The backfill and the defaults follow different rules — fixed with the Intent row.
  - `maybe-false` `reject` (Blind) A null `ApplicationId` on a link passes the per-Application check — every link is issued from a transaction carrying its Application; null means the Tenant view by design. If reachable it would be low.
  - `low` `reject` (Blind) No database guard stops rows for the system Application — the only write paths exclude it, and the effective rule ignores such rows.
  - `low` `reject` (Blind) The audit event records no value — `AuditDetail` admits no free-form field (the 4.8 deferral); the target names the Application.
  - `low` `reject` (Blind) The row says "Enabled" while the Tenant has the Connection off — no v1 control can turn it off at Tenant level; `tenantEnabled` drives the banner.
  - `low` `reject` (Blind) Database · Applications says "Not used" while the Tenant has it off — the same v1 unreachability.
  - `low` `patch` (Blind) Other switches drop presses during a save — every Toggle is disabled while saving.
  - `low` `reject` (Blind) An unchanged save still says "Changes saved" — it reaches the state the Admin asked for; exposing `changed` adds API surface for a cosmetic difference.
  - `low` `patch` (Blind) The badge always reads "Database" — taken from the kind (`kindBadge`).
  - `low` `patch` (Blind) A restart writes a transaction before the Generic error, against T-67's wording — T-67 reworded.
  - `low` `patch` (Blind) Missing test: a Connection created after the Applications — added with the Ensure fix.
  - `low` `reject` (Blind) Missing tests: a null link Application, the restart writes, the 409 and 403 banners — the first is unreachable as above, the second is now documented, and the banners reuse the Database page's tested refusal component.
  - `low` `patch` (Verification Gap) Sign-up submit and the verification new-link aren't tested with the Connection off for the Application — both added.
  - `low` `patch` (Verification Gap) The Applications list isn't tested with the Tenant's Connection off — added.
  - `low` `patch` (Verification Gap) `tenantEnabled` is only tested true — a false case added.
  - `low` `patch` (Verification Gap, other) The GK012 → 404 branch is dead — removed.
  - `medium` `patch` (Edge) New Applications get rows only for enabled Connections — fixed with the Intent row.
  - `medium` `patch` (Edge) Ensure leaves existing Applications without rows — fixed with the Blind row.
  - `medium` `patch` (Edge) A resume issues a code after the Connection was turned off mid-flow — `ResumeAsync` runs the reuse check; test added.
  - `maybe-false` `reject` (Edge) A null link `ApplicationId` falls back to the Tenant view — same as the Blind row.
  - `low` `patch` (Edge) Presses dropped during a save — fixed with the Blind row.
  - `false` `reject` (Edge) "Refused" implies no writes, but Continue records the identifier — refusal means no credential or account is written; T-67 now says so.
  - `medium` `patch` (Edge) A mid-flow toggle doesn't stop the in-flight code — fixed with the resume row.
  - `low` `reject` (Intent) The backfill, the audit event and the extra routes go beyond the story's text — the backfill keeps existing apps working, and the event follows the one-command-one-event convention.
  - `false` `reject` (Intent) The workflow steps aren't in the diff — process happens after review.
  - `maybe-false` `reject` (Intent) The system Application's Tenant-disabled case is tested only at the Directory layer — the service reads the same rule. If it hid a defect it would be low.
  - `maybe-false` `reject` (Blind) The admin bundle's 500 kB chunk warning — unrelated to this change's size (a new tab component); unverified whether it predates it.

## Design Notes

- **A missing row means off, and the system Application has no rows.** The system row can't be updated (GK012), and "follows every Tenant-enabled Connection" is exactly the Tenant-level flag, so the effective rule handles it with no stored state.
- **Toggles save immediately:** a single switch with a toast matches Database · Settings (4.6). A Save button would add an unsaved state to a one-field form.
- **A null Session Connection stays reusable:** Sessions started before Story 4.7, or by the test-only step, record no Connection. Refusing them would sign out every existing Session without reason.
- **Generic `temporarily_unavailable`** is the existing no-Connection answer (4.9), so no new error code is introduced.

## Verification

**Commands:**
- With `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors.
- `corepack pnpm -r build`, `corepack pnpm --filter @gatekeep/ui check`, and the admin-dashboard unit tests. Expected: green.
- The Isolation, Architecture and browser suites run on CI.

## Auto Run Result

Status: done

**Summary:**
- **Storage:** `application_connection` (Directory) holds each Application's on/off per Connection.
  - **The effective rule:** the Tenant enables the Connection AND (the Application is the system one OR its row is on).
  - **Rows:** the backfill, every new Application, and a Connection created later all write enabled rows.
- **Admin:** Admins toggle on Application · Connections, which saves immediately with a toast and shows a banner when nothing is usable. Database · Applications lists who uses the Connection. Three Admin routes back these.
- **Hosted Login:** Login, Continue, restart and Extend answer Generic `temporarily_unavailable` for an Application with no usable Connection. Every credential route refuses as for a disabled Connection.
- **Sessions:** authorize reuses, and resumes, only a Session from a Connection still enabled for the Application.

**Files changed (main ones):**
- `Migration20261201000000ApplicationConnections.cs` and `TableRegistry.cs`: the table, RLS, grants and backfill.
- `src/Modules/Directory/{Core/DirectoryService.ApplicationConnections.cs, Core/DirectoryService.Connections.cs, Core/DirectoryService.cs, Core/DirectoryPurge.cs, Contracts/*}`.
- `src/Modules/Management/*` and `src/Gatekeep.Host.Admin/{AdminApi.cs, ApplicationConnectionsApi.cs}`; OpenAPI and the api-client regenerated.
- Hosted: `SignInService`, `SignUpService`, `PasswordResetService`, `HostedSignIn.cs` (checks, Login, reuse, resume), and `ISessions`/`SessionService` (`ConnectionId`).
- `apps/admin-dashboard/src/shell/{ApplicationConnections.tsx, ApplicationDetailPage.tsx, DatabasePage.tsx, database.ts}` and `packages/ui/src/messages.tsx`.
- Tests: `ApplicationConnectionTests`, `ApplicationConnectionsApiTests`, `ApplicationConnectionSignInTests` and `admin-connections.spec.ts` (new); updated seeds, purge registry, grants, migration count (47), routes, capability rules and fixtures (`TestTenants.DatabaseConnectionSql`). Docs: threat model T-67, audit events.

**Review findings:** 35.
- **16 patched:** rows for every Connection, Ensure writing rows for existing Applications, the resume check, disabled toggles during a save, the badge, T-67's wording, the dead branch, and five tests.
- **None deferred.**
- **The rest rejected** with reasons in the triage log.

**Follow-up review recommended:** true. Three `medium` root causes were patched: the default rows, the rows written when a Connection is created (with a new `gk_worker` INSERT grant), and the resume check. The resume check and the new grant landed after review. Patched entries: high 0, medium 3, low 9.

**Verification:**
- .NET build in the SDK 10.0.403 Docker image: 0 warnings, 0 errors.
- `pnpm -r build`, the `@gatekeep/ui` check, and the admin-dashboard unit tests (152) pass.
- The Isolation, Architecture and browser suites run on CI.

**Residual risks:**
- The fixture changes and new tests are first run on CI.
- Sessions with no recorded Connection stay reusable.
- The admin bundle shows Vite's 500 kB chunk warning.
