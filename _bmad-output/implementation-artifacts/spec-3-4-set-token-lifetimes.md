---
title: 'Story 3.4: Set token lifetimes'
type: 'feature'
created: '2026-11-13'
baseline_revision: '68d12344cb7510941489cb3f211046c6a3be4091'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-3-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-3-3-create-rotate-and-revoke-client-secrets.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** Every Application gets the Deployment-wide lifetimes: access and ID tokens 15 min, refresh tokens 30 days absolute and 7 days inactivity. These come from global OpenIddict options and `SecurityLimits` constants. No Admin can tune them per client (FR-15, §5.2).

**Approach:**
- Store the four lifetimes on `application`.
- Add a Tenant-scoped `PUT …/applications/{applicationId}/tokens` route under `tenant.applications.manage`.
- Apply the saved values in one `ProcessSignInContext` handler that covers every grant.
- Add a Tokens tab to the Application page.

## Boundaries & Constraints

**Always:**
- **Columns.** Add four `integer NOT NULL` seconds columns to `application`, each with a DB default equal to today's default:
  - `access_token_lifetime` = 900
  - `id_token_lifetime` = 900
  - `refresh_token_absolute_lifetime` = 2592000
  - `refresh_token_inactivity_lifetime` = 604800

  Existing rows take the defaults.
  - CHECK each value between 1 and its hard limit (3600, 3600, 7776000, 2592000).
  - `GRANT UPDATE` on the four columns to `gk_admin`.
  - The system Application's GK012 guard stays. The route maps it to 404, as settings does.
  - Migration `Migration20261116000000SetTokenLifetimes`; the count goes from 31 to 32.
- **Limits.** The hard limits stay the `SecurityLimits` constants. Add no new limit, and keep `HardSignedTokenLifetime` (it drives `SigningKeyRetirementDelay`).
  - A unit or Architecture test pins the migration CHECK numbers to the constants.
  - Minimum: 1 second. Values are whole seconds.
- **Route `PUT /api/v1/tenants/{tenantId}/applications/{applicationId}/tokens`.**
  - Access: `RequiresCapability(TenantApplicationsManage)` (Editors and Owners; machine principals allowed; no fresh assertion) and `X-Gatekeep-Tenant`.
  - Body: `{ accessTokenLifetime, idTokenLifetime, refreshTokenAbsoluteLifetime, refreshTokenInactivityLifetime }`. All are required integers in seconds, and the save is a full replace.
  - A malformed body is 400 `application_invalid` with no errors.
  - A value over its limit is 400 `application_invalid` with `errors[]` `{ field, reason: "above_maximum", maximum }`, where `maximum` is the limit in seconds.
    - Add the optional `maximum` to `ApiProblemError` and its OpenAPI schema.
    - Below 1 is `reason: "below_minimum"`.
  - Success is 200 `ApplicationResponse`, which now carries the four lifetimes. The GET also returns them.
  - Audit: `directory.application.updated` in the same command. An unchanged save writes nothing.
  - The system Application, another Tenant's, an unknown or a malformed `applicationId` all get 404.
- **Issuance.** Add one `ProcessSignInContext` handler in Protocol, after OpenIddict's `Prepare*TokenPrincipal` handlers and before `ReportAccessTokenLifetime`. It looks up the client's `DirectoryApplication` and sets the expiry of each issued token:
  - **access:** now + the access lifetime;
  - **ID:** now + the ID lifetime;
  - **refresh:** min(now + inactivity, family absolute end).
  - This covers authorization_code, refresh_token and client_credentials.
  - `DirectoryApplication` gains the four values as `TimeSpan`.
  - `RefreshTokens.AbsoluteEnd`, the `SignInRefresh` absolute check and `CapRefreshTokenLifetime` use the Application's absolute lifetime in place of the constant. The family keeps its original `CreatedAt`.
  - `expires_in` follows automatically.
  - Global OpenIddict options stay at the defaults.
  - Make the lifetime lookup one function that 3.6 can extend with the API's value (shorter wins). Don't add API lookups now.
- **Dashboard, a Tokens tab** (new `ApplicationTokens.tsx`) on `ApplicationDetailPage`:
  - Shows "Access token", "ID token", and a "Refresh tokens" card with "Absolute lifetime" and "Inactivity lifetime", as seconds inputs with a human hint ("15 minutes", "30 days").
  - A machine-to-machine Application shows only Access token. The other values are sent back unchanged.
  - Each field shows its default ("Default: 15 minutes").
  - An over-limit value is refused in the browser with "Maximum is 1 hour." / "Maximum is 90 days." / "Maximum is 30 days." and nothing is sent. The server's `above_maximum` shows the same copy from `maximum`.
  - Save follows `ApplicationSettings.tsx`: dirty guard, `useUnsavedChanges`, `canLeave` extended to Tokens, the "Changes saved" toast, and a `Banner` with `ErrorReference` on failure.
  - Without `tenant.applications.manage` the fields are read-only and Save is hidden.

**Never:**
- No signing algorithm, rotation, reuse-detection or reuse-interval control, and no option to disable rotation or refresh tokens (Design Delta).
- No API (resource) lifetimes and no shorter-wins logic (3.6). No change to the authorization code lifetime or the User Session limits.
- Don't raise any hard limit. Don't change the global OpenIddict lifetime options or the refresh reuse leeway.
- Host.Admin never references Directory.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| New / existing app | no save | GET shows 900/900/2592000/604800; tokens as today | — |
| Editor saves | 300/600/864000/86400 | 200 with values; `updated` event; next tokens: at `exp−iat`=300, `expires_in`=300, id 600, refresh expiry ≈ now+1d | — |
| Over limit | access 3601 | 400 `above_maximum`, `maximum` 3600; nothing written | UI: "Maximum is 1 hour." before sending |
| Refresh over limits | absolute 7776001 / inactivity 2592001 | 400 per field, `maximum` 7776000 / 2592000 | UI copy per field |
| Zero / negative | 0 | 400 `below_minimum` | — |
| Unchanged save | same values | 200, no event | — |
| Viewer / unknown / system / foreign app | — | 403 `access_denied` / 404 `not_found` | — |
| Machine principal | Management token with the capability | 200 | — |
| Client credentials | machine app, access 120 | `expires_in` 120 | — |
| Absolute shortened | family 3 days old, absolute set to 2 days | next refresh `invalid_grant` | — |
| Inactivity shortened | inactivity 3600 | new refresh token expires ≈ now+1h; refresh after 1h+1s is `invalid_grant` | — |

</intent-contract>

## Code Map

- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs:165-216`: the defaults and hard limits. The docs at :203/:213 name Story 3.4.
- `src/Adapters/Postgres/Migrations/Migration20261114000000ConfigureApplicationSettings.cs:30-53`: the column, CHECK and grant model. The latest migration is `Migration20261115000000ManageClientSecrets.cs`.
- `src/Adapters/Postgres/Schema/TableRegistry.cs:593-607`: the `application` entry. Add the four columns to the Admin `Update` grant.
- `tests/Isolation/MigrateCommandTests.cs:20,28`: the count, 31 → 32.
- `src/Modules/Directory/Core/DirectoryService.cs`:
  - `Columns` at :575 (add the four);
  - the settings UPDATE at :600 and its params at :628 (copy for the tokens UPDATE);
  - `CheckSettings`/`DirectoryContract` for rules.
- `src/Modules/Directory/Contracts/{IDirectory.cs:157,180, DirectoryApplication.cs, ApplicationSettings.cs}`: add `UpdateApplicationLifetimesAsync` and the lifetime record and fields.
- `src/Modules/Directory/Adapters/ApplicationStore.cs:33`: OpenIddict's `FindByClientIdAsync` path, which must load the lifetimes.
- `src/Modules/Management/{Contracts/IApplicationManagement.cs:56,191, Core/ApplicationManagement.cs:100}`: copy `UpdateSettingsAsync` (capability re-check, actor) and the `ApplicationSettingsError` shape. `ManagementContract.ApplicationSettingsFields/Reasons` feed the OpenAPI enums.
- `src/Gatekeep.Host.Admin/`:
  - `AdminApi.cs:698-732`: the settings PUT to copy, with `TenantApplicationsManage` and no fresh assertion.
  - `ApplicationsApi.cs:20-56,257-363`: the response, request, handler, the GK012 map and the errors map.
  - `AdminResponses.cs:20-37`: `ApiProblemError`, which gains `Maximum`.
  - `AdminOpenApi.cs:202-205`: the error enums.
- `src/Modules/Protocol/Core/`:
  - `ProtocolServer.cs:101-117,144-152`: the global options (keep) and handler registration.
  - `RefreshTokens.cs:59,117-179,260-292`: `AbsoluteEnd`, `SignInRefresh` and `CapRefreshTokenLifetime`.
  - `TokenEndpoint.cs:425-464,562-585`: `SignInClient` and `ReportAccessTokenLifetime` (runs after the new handler).
- `deploy/docker/api-contract.sh`: regenerates `docs/api/openapi-v1.json` and `packages/api-client/src/schema.generated.ts`. Add `updateApplicationTokens` in `client.ts` near the settings method.
- Dashboard:
  - `apps/admin-dashboard/src/shell/ApplicationDetailPage.tsx:91-93,183-215`: tabs and `canLeave`.
  - `ApplicationSettings.tsx:154-245,410-421`: the form, save and read-only patterns.
  - `applications.ts`: add the lifetime limits and the human formatting.
  - `packages/ui/src/messages.tsx`: `applicationTab*` at :503 and the save copy.
- `design/Gatekeep Admin.dc.html:388-405`: the Tokens cards. Drop the algorithm and rotation controls and the 36000 default (EXPERIENCE.md:438).
- Tests to copy:
  - `tests/Isolation/Protocol/{ClientCredentialsTests.cs:42-64, AuthorizationCodeTests.cs:49-94, RefreshTokenTests.cs:242-295}`: `exp−iat`, `time.Advance` and family-absolute patterns.
  - `tests/Isolation/Applications/{ApplicationSettingsApiTests.cs, ApplicationSettingsProtocolTests.cs:24}`.
  - `tests/Isolation/CrossTenant/RouteRegistry.cs`, `tests/Architecture/{CapabilityRuleTests.cs, AdminApiRuleTests.cs}`.
  - `tests/browser/admin-applications.spec.ts`.

## Tasks & Acceptance

**Execution:**
- [ ] Migration + `TableRegistry.cs` + `MigrateCommandTests.cs`: the columns, defaults, CHECKs and grant. Count 32.
- [ ] `src/Modules/Directory/{Contracts,Core,Adapters}`: the lifetimes on `DirectoryApplication`, the SELECT columns, and `UpdateApplicationLifetimesAsync`, with the GK012 → not-found mapping, the limit checks and the `updated` event (none when unchanged).
- [ ] `src/Modules/Management/{Contracts,Core}/ApplicationManagement.cs`: `UpdateLifetimesAsync`, the capability re-check, errors with `Maximum`, and the new fields and reasons in `ManagementContract`.
- [ ] `src/Gatekeep.Host.Admin/{AdminApi.cs, ApplicationsApi.cs, AdminResponses.cs, AdminOpenApi.cs}`: the route, the response fields and `ApiProblemError.Maximum`.
- [ ] `src/Modules/Protocol/Core/{ProtocolServer.cs, RefreshTokens.cs, new ApplicationLifetimes.cs}`: the sign-in handler and per-Application absolute end.
- [ ] `docs/api/openapi-v1.json`, `packages/api-client/*` + a client unit test: regenerate, and add `updateApplicationTokens`.
- [ ] Dashboard: `ApplicationTokens.tsx` (+ `.module.css`), `ApplicationDetailPage.tsx`, `applications.ts` (+ unit test of the limits and formatting), `messages.tsx`.
- [ ] `tests/Isolation/Applications/ApplicationTokensApiTests.cs` (new): the API rows of the matrix, and a migration CHECK test refusing an over-limit UPDATE as superuser.
- [ ] `tests/Isolation/Applications/ApplicationLifetimeProtocolTests.cs` (new): the issuance rows across all three grants.
- [ ] `tests/Isolation/CrossTenant/RouteRegistry.cs`, `tests/Architecture/{CapabilityRuleTests.cs, AdminApiRuleTests.cs}` + a limits pin test: register and pin.
- [ ] `tests/browser/admin-applications.spec.ts`:
  - defaults shown, a save with its toast, and a refusal in the browser with no request;
  - the server's `above_maximum` copy;
  - Viewer read-only, machine shows Access only, the leave guard;
  - axe in light and dark at 1100 and 768 px.

**Acceptance Criteria:**
- Given lifetime fields, when a value exceeds a §5.2 hard limit, then the UI and the API both refuse it, and the UI shows "Maximum is {limit}."
- Given a saved lifetime, when a new token is issued, then it uses that lifetime.
- Given the Tokens tab, when it renders, then no option turns off rotation or chooses an algorithm.

## Spec Change Log

## Review Triage Log

## Design Notes

- **Seconds, NOT NULL, DB defaults.** These are the design's units. Existing Applications are unchanged in behavior. A CHECK in the database backs the Kernel limits ("enforced by the Deployment").
- **API carries the limit, not English.** The API never returns English text. `maximum` lets every client render "Maximum is {limit}." The dashboard formats it as 1 hour, 90 days or 30 days.
- **Absolute lifetime is read at refresh time**, as today with the constant. Shortening it ends older families at once, the safe direction. Lengthening it extends them, up to the 90-day hard limit. Fixing it at grant time would need a new per-family column and buys little.
- **Capability.** Lifetimes fall under `tenant.applications.manage` ("everything about Applications but their callback URLs"), so no fresh assertion is needed.

## Verification

**Commands:**
- With `$env:MSYS_NO_PATHCONV=1`: `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings, 0 errors.
- `pnpm -r build` and `pnpm -r --if-present typecheck` in `node:26.13.0-bookworm-slim`. Expected: clean.
- Don't run the suites locally. CI on the PR is the test run.
