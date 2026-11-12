---
title: 'Story 3.2: Configure Application URLs and grants'
type: 'feature'
created: '2026-11-12'
baseline_revision: 'e58fe4fb6d6beb92cc91cce031243e2ddddae22c'
status: 'done'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-3-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-3-1-list-and-create-applications.md'
warnings: ['oversized']
deferred:
  - summary: >-
      Allowed Web Origins are stored and validated but nothing consumes them; a single-page Application's browser token exchange needs CORS on Host.Hosted's token endpoint, which no story owns.
    evidence: |-
      No CORS handling exists in src/ or deploy/ (Story 3.2 recon). Story 3.2 makes spa a public client that redeems its code at /oauth/token, which a browser can only call cross-origin with CORS. The Design Delta removed the separate "Allowed Origins (CORS)" list, so web origins are the natural source. Origins are also stored as typed (no case or default-port canonicalization), which the CORS work must address when it compares them.
    location: >-
      src/Modules/Protocol/Core/ProtocolServer.cs (Host.Hosted endpoints)
    severity: medium
---

<intent-contract>

## Intent

**Problem:**
- An Application created in Story 3.1 has no callback, logout or web origin URLs and no editable grants, so it can never sign anyone in (FR-11, FR-13, FR-46, UX-DR42, AD-20).
- Single-page and native Applications can't hold redirect URIs at all.
- The token endpoint rejects any client without a secret, so the public types can't work even once configured.

**Approach:**
- Add one Tenant-scoped settings write for an Application: callback, logout and web origin URLs plus grant types. It goes Host.Admin → Management → Directory.
- Gate that write with `tenant.application_callbacks.manage`. Machine principals are always refused. A Prod Tenant whose callbacks change needs a fresh assertion.
- Make the protocol honour the settings:
  - exact match, with the RFC 8252 loopback port exception for native only;
  - spa and native become public clients;
  - a turned-off grant is refused.
- Give the Application page a Settings tab.

## Boundaries & Constraints

**Always:**

- **Route:** `PUT /api/v1/tenants/{tenantId}/applications/{applicationId}/settings`, a `TenantApiEndpoint`.
  - Access is `RequiresCapability(AdminCapabilities.TenantApplicationCallbacksManage)` + `EvaluatesFreshAssertion.Instance` + `FreshAssertionTarget("applicationId")`, following `TenantLabelApi`.
  - It needs `X-Gatekeep-Tenant`, so a mismatch gets 409 `tenant_mismatch`.
- **Request body:** `{ callbackUrls: string[], logoutUrls: string[], webOrigins: string[], grantTypes: string[], acknowledgeCustomScheme?: boolean }`.
  - The body is the full settings, and every array is required.
  - Body cap 16384 bytes.
  - The answer is 200 with the updated Application resource.
- **Application resource** (GET by id, list, create and this PUT) gains `callbackUrls`, `logoutUrls`, `webOrigins` and `grantTypes`.
- **Fresh assertion** is decided in Management on the locked row, the way `TenantManagement` evaluates the label predicate. It is required exactly when:
  - the Tenant's label is `prod`, and
  - the submitted `callbackUrls` set differs from the stored one.

  The handler then calls `FreshAssertionGate.RequireAsync`. A Prod save that leaves the callbacks unchanged needs no assertion.
- **Machine principals** are refused in every Tenant, because the capability is machine-denied. Management re-checks `AdminCapabilities.Allows` and returns `Forbidden`.
- **Rules by type.** Every rule is enforced on the server. A violation is 400 `application_invalid`.

  | Type | Grants allowed | Callback and logout URLs | Web origins |
  |---|---|---|---|
  | `web`, `spa` | `{}`, `{authorization_code}` or `{authorization_code, refresh_token}` | https, or http on `127.0.0.1` / `[::1]` | allowed |
  | `native` | same as web and spa | as web and spa, plus custom schemes | always empty |
  | `machine` | `{}` or `{client_credentials}` | always empty | always empty |

  - **Every list:** at most 10 entries (`DirectoryContract.MaxRedirectUris`), each at most 2000 characters, no duplicates.
  - **URLs:** absolute, no fragment, no userinfo, and no `*` anywhere. Extend `RedirectUris.Checked` rather than duplicating it.
  - **Custom schemes:** the scheme contains a `.` and is not `http`, `https`, `javascript`, `data`, `file`, `blob`, `about` or `vbscript`, as in `com.example.app:/callback`.
  - **Web origins:** `scheme://host[:port]` only, with no path other than empty, no query and no fragment. The scheme rules are the same as for URLs.
  - **Grants:** the list must be one of the sets for the type, and order doesn't matter. Store it sorted.
- **Per-line errors:** a 400 `application_invalid` carries `errors: [{ field, index, reason }]`.
  - `field` is `callbackUrls`, `logoutUrls`, `webOrigins` or `grantTypes`.
  - `index` is the 0-based array position, or null for a whole-field error.
  - `reason` is `not_absolute`, `wildcard`, `scheme_not_allowed`, `too_long`, `too_many`, `duplicate` or `not_allowed_for_type`.
  - Document the shape in OpenAPI.
- **Custom-scheme acknowledgement:**
  - Required when the Tenant is `prod` and the submitted callbacks or logout URLs contain a custom-scheme URL not already stored.
  - The request must carry `acknowledgeCustomScheme: true`, or it gets 400 `custom_scheme_acknowledgement_required`. Add that code to `AdminResponses` `ProblemCodes`.
  - The acknowledgement isn't stored.
- **Audit:** one `CommandContext` command updates the row and writes its events in one transaction.
  - When anything changes, it writes `directory.application.updated`.
  - When the Tenant is `prod` and a callback URL was added, it also writes `directory.application.prod_callback_added`. This is the event Story 11.1 turns into the "Prod callback added" Security Alert.
  - The actor is the Admin. Detail is null.
  - A save that changes nothing answers 200 and writes no event.
  - Regenerate `docs/audit-events.md` and `LogCatalogue.Generated.cs` with the generator.
- **System Application:**
  - The system Application and another Tenant's, unknown or malformed IDs all get the same 404 `not_found`.
  - The UPDATE also filters `kind <> 'system'`.
  - Map GK012 to 404 as a backstop.
- **Migration** `Migration20261114000000ConfigureApplicationSettings` (count 29 → 30):
  - Add `post_logout_redirect_uris text[] NOT NULL DEFAULT '{}'` and `web_origins text[] NOT NULL DEFAULT '{}'`.
  - Redefine `application_redirect_uris` (or replace it with `application_settings`) to encode the type table above. `system` keeps every list and its grants empty, and the existing system guards stay intact.
  - Every existing row must satisfy the new CHECK, including test-inserted `web` rows with `{authorization_code, refresh_token}` and machine rows with `{client_credentials}` or `{}`.
  - `GRANT UPDATE (redirect_uris, post_logout_redirect_uris, web_origins, grant_types) ON application TO gk_admin`, and update the `TableRegistry` entry to match.
- **Protocol (`ApplicationStore`, token client authentication, authorize):**
  - **Client and application type:** spa and native are `Public`; web, machine and system stay `Confidential`. Application type is `Native` for native, `Web` otherwise.
  - **Authorize:** the authorization endpoint and response type `code` are permitted only when the kind is web, spa or native and the Application holds `authorization_code`. PKCE is required for those kinds.
  - **Logout URLs:** post-logout redirect URIs come from the row, for Story 4.13.
  - **Public clients at the token endpoint:** a public client authenticates by `client_id` alone. Sending any `client_secret` is `invalid_client`. Confidential clients are unchanged.
  - **Loopback exception:** for native only, an authorize `redirect_uri` on `http://127.0.0.1:<port>` or `http://[::1]:<port>` matches a registered loopback URL that differs only in port. This applies everywhere OpenIddict validates the redirect URI. Every other comparison stays exact, string for string.
  - **A turned-off grant is refused:**
    - `/authorize` without `authorization_code` shows the static error page and never redirects;
    - a `refresh_token` grant without `refresh_token` is `unauthorized_client`;
    - a `client_credentials` grant without `client_credentials` is `unauthorized_client`.
- **Admin Dashboard Application page:**
  - **Tabs:** `Tabs` with Settings (the default) and Credentials (3.1's Credentials text), using `useUrlTab`.
  - **Application URLs card** (web, spa and native):
    - Textareas in mono, one URL per line: "Allowed Callback URLs", "Allowed Logout URLs", and "Allowed Web Origins" (web and spa only).
    - Helper: "Matched exactly. One per line. No wildcards." When there are no URLs, it explains exact matching.
    - Each server error shows on its field, naming the line, such as "Line 2: Must be an absolute URL."
  - **Machine:** no URL card. Instead, a note that machine-to-machine Applications have no URLs.
  - **Grant types card:** exactly three `Toggle`s: "Authorization Code with PKCE", "Refresh Token" and "Client Credentials". A grant the type can't have is disabled with "Not available for {type}." Refresh Token is disabled while Authorization Code is off.
  - **Native:** an info `Banner`: sign-in must open in the system browser, and embedded web views aren't supported. There is no embedded-view option anywhere.
  - **Prod custom schemes:** when the Tenant label is `prod` and a callback or logout line has a custom scheme, a `Checkbox` asks for acknowledgement before Save. The server still decides.
  - **Save changes:** one button sends the PUT through `fresh.withFreshAssertion({ action: 'tenant.application_callbacks.manage', target: applicationId, tenantId }, put)`, then shows the toast "Changes saved".
  - **Unsaved changes:** guarded with `useUnsavedChanges` and `canLeave`.
  - **Failures:**
    - 400 shows per-field errors;
    - 403 `access_denied` shows a forbidden `Banner`;
    - 401 keeps what was typed;
    - other failures show a Save failed `Banner` with `ErrorReference`.
  - **Callers without `tenant.application_callbacks.manage`** (Viewers) see read-only fields and no Save.

**Never:**

- No CORS / "Allowed Origins (CORS)", Domain, Logo URL, Description, name editing, Implicit / Password / Device / CIBA / Token Exchange grants, or wildcard copy. Those are Design Delta removals or later stories.
- No end-session endpoint (Story 4.13), no CORS handling of web origins on Host.Hosted, no secrets (3.3), no lifetimes (3.4) and no deletion (3.5).
- No revoking of existing refresh tokens when a grant is turned off: the next refresh is refused.
- No `localhost` hostname loopback, and no port exception for web or spa.
- Host.Admin never references Directory. Don't change `CreateMachineClientAsync` or `CreateWebClientAsync` behaviour that existing tests rely on.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Editor saves web URLs + grants (Dev) | callbacks `[https://app.example/cb]`, grants `[authorization_code, refresh_token]` | 200 resource; row updated; one `updated` event; no assertion | — |
| Owner, Prod, callbacks changed, no grant | Prod Tenant | 403 `fresh_assertion_required`, nothing written | UI runs the sheet, resends once |
| Prod, callbacks changed, fresh grant | grant bound to `applicationId` | 200; `updated` + `prod_callback_added` events | grant consumed once |
| Prod, only grants changed | callbacks identical | 200, no assertion asked, no `prod_callback_added` | — |
| Viewer / machine principal | — | 403 `access_denied` / Management `Forbidden`; nothing written | — |
| Wildcard, relative, http non-loopback, fragment | `https://*.a.example/cb`, `/cb`, `http://a.example/cb`, `https://a.example/cb#x` | 400 `application_invalid`, `errors` with field+index+reason | nothing written |
| 11 URLs, duplicate, 2001 chars | — | 400, reasons `too_many` / `duplicate` / `too_long` | — |
| Wrong grants for type | machine with `authorization_code`; web with `client_credentials`; spa with `[refresh_token]` | 400 `not_allowed_for_type` on `grantTypes` | — |
| Machine with URLs; native with web origin | — | 400 `not_allowed_for_type` | — |
| Native custom scheme, Dev | `com.example.app:/cb` | 200 | — |
| Native custom scheme, Prod | new custom-scheme URL without / with `acknowledgeCustomScheme: true` | 400 `custom_scheme_acknowledgement_required` / 200 | — |
| Custom scheme on web/spa | `com.example.app:/cb` | 400 `scheme_not_allowed` | — |
| Native loopback port | registered `http://127.0.0.1/cb`; authorize with `http://127.0.0.1:51004/cb` | accepted; same for `[::1]`; web Application with the same pair → static error page, no redirect | — |
| Grant off: authorize | spa/web without `authorization_code` | static page, never redirects | — |
| Grant off: refresh / client credentials | refresh with grant removed; machine with `{}` | `unauthorized_client` | — |
| Public client code exchange | spa with callbacks + `authorization_code`, PKCE | tokens issued with no secret; with a `client_secret` sent → `invalid_client`; without `code_verifier` → refused | — |
| System / foreign / malformed ID | — | 404 `not_found` | — |
| No-op save | same settings as stored | 200, no event | — |

</intent-contract>

## Code Map

- `src/Adapters/Postgres/Migrations/Migration20261106000000CreateDirectoryTables.cs:32-43` -- `application` columns; `grant_types` subset CHECK (never redefined)
- `src/Adapters/Postgres/Migrations/Migration20261113000000AddApplicationTypes.cs:27-39` -- current `application_kind` and `application_redirect_uris` CHECKs to replace; latest migration to copy
- `src/Adapters/Postgres/Migrations/Migration20261109000000AddSystemApplication.cs:54-115` -- `application_system_bare`, `application_one_system`, GK011–GK013 triggers; keep intact
- `src/Adapters/Postgres/Schema/TableRegistry.cs:586-606` -- `application` grants: Admin has Select and Insert only, and a comment says no role updates it; add the Admin column UPDATE
- `tests/Isolation/MigrateCommandTests.cs:28` (+ "Applied N" strings) -- 29 → 30
- `src/Modules/Directory/Contracts/{DirectoryApplication.cs, DirectoryContract.cs:37-43, IDirectory.cs}` -- row model; `CredentialRequired`, `MaxRedirectUris`, `MaxRedirectUriLength`; add settings fields and an update method
- `src/Modules/Directory/Core/DirectoryService.cs:150-205` -- `CreateApplicationAsync` (command + `_audit.AppendAsync` pattern to copy)
- `src/Modules/Directory/Core/DirectoryService.cs:335-444` -- `ApplicationRows` (`Columns` :340, `Read`, `Visible`)
- `src/Modules/Directory/Core/DirectoryService.cs:452-491` -- `RedirectUris.Checked`: https or http loopback, no fragment or userinfo; extend it for kinds, custom schemes and origins
- `src/Modules/Directory/Core/DirectoryEvents.cs:12-15` -- add `directory.application.updated` and `directory.application.prod_callback_added`
- `tests/Architecture/Generator` (`AuditCatalogue.cs:32-39`), `tests/Architecture/AuditCatalogueTests.cs` -- regenerate the catalogue and docs
- `src/Modules/Directory/Adapters/ApplicationStore.cs:47-57` -- client and application types (the deferred Confidential issue)
- `src/Modules/Directory/Adapters/ApplicationStore.cs:82-107` -- permissions, post-logout URIs, redirect URIs, PKCE
- `src/Modules/Protocol/.../TokenEndpoint.cs:158,301-313` -- `AuthenticateGatekeepClient` rejects an empty secret; add the public-client path (find with `graft grep "AuthenticateGatekeepClient"`)
- `src/Modules/Protocol/.../AuthorizeEndpoint.cs:208-244` -- `TrustRedirectTarget` → `ValidateRedirectUriAsync` (exact); add the native loopback exception
- `src/Modules/Protocol/.../AuthorizeEndpoint.cs:274-292` -- `offline_access` needs `gt:refresh_token`
- `src/Modules/Protocol/.../ProtocolServer.cs:80-215` -- OpenIddict options; no permission checks are ignored, and PKCE is required at :95
- `src/Modules/Admins/Contracts/AdminCapabilities.cs:24-30,144,147` -- `FreshAssertion` enum, `tenant.applications.manage`, and `tenant.application_callbacks.manage` (Editors, machine-denied, `WhenProdTenant`)
- `src/Gatekeep.Host.Admin/AdminRequestChecks.cs:123-209,395,635-640` -- `AccessDeclaration` rules and the `X-Gatekeep-Tenant` check
- `src/Gatekeep.Host.Admin/FreshAssertionGate.cs:19-51`, `FreshAssertionApi.cs:150,204-208` -- the gate, and target acceptance
- `src/Gatekeep.Host.Admin/TenantLabelApi.cs:73-153`, `AdminApi.cs:698-723` -- golden example: Management predicate, then gate, then commit, plus route metadata
- `src/Modules/Management/Core/TenantManagement.cs:260-325` -- predicate evaluated on the locked row
- `src/Modules/Tenancy/Core/Tenants.cs:65-67,255-259` (`ITenants.LockLabelAsync`/`GetLabelAsync`) -- the Prod label; inject `ITenants` into `ApplicationManagement`
- `src/Gatekeep.Host.Admin/ApplicationsApi.cs`, `src/Modules/Management/Core/ApplicationManagement.cs:16,87-92` -- 3.1 handlers, validation and actor mapping to extend
- `src/Gatekeep.Host.Admin/{AdminResponses.cs:112-131, AdminOpenApi.cs:445-477}` -- problem codes, SqlState map, OpenAPI fresh-assertion extension
- `deploy/docker/api-contract.sh` -- regenerate `docs/api/openapi-v1.json` and `packages/api-client/src/schema.generated.ts` (`docker compose -f deploy/compose.dev.yaml run --rm --build -v "<repo>:/out" tests sh deploy/docker/api-contract.sh --write /out`)
- `apps/admin-dashboard/src/shell/ApplicationDetailPage.tsx` -- read-only page; add tabs, Settings and the `fresh`/`tenant` props
- `apps/admin-dashboard/src/shell/Shell.tsx:503-543` -- how pages get `fresh` and `tenant`
- `apps/admin-dashboard/src/shell/TenantSettingsPage.tsx:46,83,102,148-223,322-346` -- golden example for fresh assertion, toast, unsaved changes and banners
- `apps/admin-dashboard/src/shell/CreateTenantPage.tsx:81-82,165-210` -- per-field server errors and focus
- `apps/admin-dashboard/src/shell/{freshAssertion.ts, capabilities.ts:173-198}` -- the withFreshAssertion and `has(cap)` helpers
- `packages/ui/src/components/{Input.tsx:47 Textarea, Field.tsx error, Toggle.tsx, Choice.tsx Checkbox, Tabs.tsx, Toast.tsx, Banner}`, `messages.tsx` -- UI kit and copy
- `design/Gatekeep Admin.dc.html:292-343,1325-1327` -- detail header, tabs, Settings cards, grant rows; Design Delta removals at `EXPERIENCE.md:435,437`
- `tests/Isolation/Tenancy/TenantLabelTests.cs:86-251`, `Admins/TenantFreshAssertionTests.cs` -- fresh-assertion test patterns
- `tests/Isolation/Protocol/{ProtocolHost.cs:69,147,206, ClientCredentialsTests.cs:215-227, AuthorizationCodeTests.cs:177, RefreshTokenTests.cs:84}`, `tests/Isolation/Applications/{ApplicationsApiTests.cs:351-367, InertApplicationTests.cs}` -- protocol and Application test helpers; InertApplicationTests expectations move with the new settings
- `tests/Isolation/CrossTenant/RouteRegistry.cs:91-102`, `tests/Isolation/Canary/CanaryFlows.cs:386-398`, `tests/Isolation/Admins/CapabilityMatrixTests.cs:42` -- register the new route
- `tests/Architecture/AdminApiRuleTests.cs:214` -- problem status allowlist (400/403/404/409/429); keep it in step
- `tests/browser/admin-applications.spec.ts`, `tests/browser/playwright.config.ts` (project `admin-applications`) -- browser spec to extend

## Tasks & Acceptance

**Execution:**
- `src/Adapters/Postgres/Migrations/Migration20261114000000ConfigureApplicationSettings.cs` + `TableRegistry.cs` + `MigrateCommandTests.cs` -- add the columns, the type CHECK and the Admin column UPDATE grant; count 30 -- storage for the settings
- `src/Modules/Directory/{Contracts,Core}` -- settings fields on `DirectoryApplication` and `ApplicationRows`; a kind-aware validator returning per-index errors; `UpdateApplicationSettingsAsync(ctx, actor, id, settings, prodCallbackAdded)` writing the row and events; the two events -- Directory owns the table
- `src/Modules/Directory/Adapters/ApplicationStore.cs` + Protocol token client authentication + authorize redirect validation -- public clients, kind permissions, post-logout URIs, native loopback exception -- the settings take effect
- `src/Modules/Management/{Contracts,Core}/ApplicationManagement.cs` -- `UpdateSettingsAsync`: capability re-check, label lock, fresh-assertion predicate callback, acknowledgement rule, no-op detection -- the Management edge
- `src/Gatekeep.Host.Admin/{ApplicationsApi.cs, AdminApi.cs, AdminResponses.cs, AdminOpenApi.cs}` -- the PUT route, metadata, problem codes, `errors` extension, GK012 mapping; resource fields on every Application response -- API surface
- `docs/api/openapi-v1.json`, `packages/api-client/src/{schema.generated.ts, client.ts, index.ts}` + client unit test -- regenerate and add `updateApplicationSettings` -- contract
- `docs/audit-events.md`, `src/Gatekeep.Host.Admin/LogCatalogue.Generated.cs` -- regenerate -- catalogue
- `apps/admin-dashboard/src/shell/{ApplicationDetailPage.tsx, ApplicationSettings.tsx (new), Shell.tsx, applications.ts}`, `packages/ui/src/messages.tsx` -- tabs, Settings form, per-line errors, native guidance, acknowledgement, fresh assertion, toast -- screen
- `tests/Isolation/Applications/ApplicationSettingsApiTests.cs` (new) -- every API row of the I/O matrix, including the fresh-assertion cases (no grant, grant consumed, Dev needs none) and audit events
- `tests/Isolation/Applications/ApplicationSettingsProtocolTests.cs` (new) + `InertApplicationTests.cs` -- loopback exception (native vs web), grant-off refusals at authorize and token, public spa/native code exchange with PKCE, secret sent by a public client
- `tests/Isolation/{CrossTenant/RouteRegistry.cs, Canary/CanaryFlows.cs, Admins/CapabilityMatrixTests.cs, Directory/DirectoryTests.cs}` -- register the route; Directory validator and CHECK tests
- `tests/browser/admin-applications.spec.ts` -- Settings tab per type, per-line errors, Prod custom-scheme checkbox, fresh-assertion resend, toast, Viewer read-only, unsaved guard, axe light/dark at 1100 and 768 px

**Acceptance Criteria:**
- Given an Application's Settings tab, when it renders, then the only grant controls are Authorization Code with PKCE, Refresh Token and Client Credentials.
- Given a native Application, when its Settings tab shows, then the system-browser guidance appears and no embedded-view option exists.
- Given a Prod Tenant, when an Editor changes callback URLs and Saves, then the sheet asks for a fresh assertion, the save is resent once, "Changes saved" shows, and `directory.application.prod_callback_added` is in the Tenant's Log.
- Given the API changes, when CI runs, then the contract check, cross-Tenant, canary, capability matrix and Architecture suites pass with the new route registered.

## Spec Change Log

## Review Triage Log

### 2026-11-12 — Review pass
- verdicts: 32 findings — high 0, medium 7, low 14, false 10, maybe-false 1
- findings:
  - **Intent Alignment**
    - `[medium]` `[defer]` Logout URLs and web origins are only validated and stored; nothing matches them at the protocol yet. Logout URLs feed `GetPostLogoutRedirectUrisAsync` for Story 4.13. Web origins have no consumer, and the browser token exchange of an spa needs CORS on Host.Hosted, which no story owns. Grouped with the Blind Hunter "web origins unused" row and deferred.
    - `[low]` `[reject]` The grant-off refusal is tested through SQL `UPDATE`, never chained after a settings PUT. Each half is tested (the PUT stores the grant set; the protocol refuses the stored set), and a chained test adds no new path.
    - `[false]` `[reject]` http loopback is allowed at save for every non-machine kind. The RFC 8252 exception is the port at match time, and that is native-only (`DirectoryContract.MatchesRedirectUri`). Allowing a loopback callback for web or spa is FR-11-compatible.
    - `[false]` `[reject]` Machine refusal is tested only at the Management layer. No machine principal can reach HTTP until Epic 17 (`TestOnlyMachinePrincipal`). The capability is machine-denied, and `CapabilityRuleTests` pins the route as handler-enforced.
    - `[false]` `[reject]` "Only three grants" is asserted in the UI. The server type table limits stored grants to those three as well, so there is no divergence.
    - `[low]` `[reject]` Native setup guidance is a Settings-tab banner, not a Quickstart flow. The Quickstart tab is a later Design surface, and the banner meets the AC's "requires the system browser and offers no embedded view".
    - `[false]` `[reject]` Acknowledgement only for a *new* custom scheme. That matches FR-11: acknowledgement is asked when a custom scheme is introduced, and re-saving an acknowledged URL needs none.
    - `[false]` `[reject]` Public-client authentication goes beyond the ACs. It is required for spa and native to sign in at all (FR-13 PKCE for public clients; Design Notes). Its tests exist.
  - **Verification Gap**
    - `[medium]` `[patch]` No test saves an authorised Prod callback removal, so a wrong `prod_callback_added` (a false Story 11.1 alert) would go unnoticed. Patched: a test saves the removal with a fresh assertion and asserts no new `prod_callback_added`.
    - `[low]` `[patch]` The no-op save is never given reordered grants. Patched: a test saves `[authorization_code, refresh_token]`, then resends the same grants reordered, and asserts no write and no event.
    - `[low]` `[patch]` Nothing pins the refusal of a public client presenting a secret that verifies. Patched: a test inserts a live `client_secret` for the spa and asserts `invalid_client`.
  - **Blind Hunter**
    - `[medium]` `[patch]` The 16384-byte settings body cap is below the largest legal save (3×10×2000 characters), so a legal save gets a bare 400. Patched: the cap is raised to 131072.
    - `[medium]` `[patch]` The dashboard dead-ends when it doesn't know the Tenant is Prod: there is no checkbox, and acknowledgement is never sent. Patched: the server's `custom_scheme_acknowledgement_required` brings up the checkbox and the resend carries it. A browser test covers this.
    - `[low]` `[patch]` Text typed during a save is overwritten, and line numbers drift. Patched: the textareas are read-only while saving.
    - `[medium]` `[defer]` Web origins have no consumer (CORS). Grouped with Intent Alignment's first row.
    - `[low]` `[reject]` Web origins aren't canonicalized (case, default port). There is no consumer yet to mismatch. Canonicalizing belongs with the CORS work that will compare them, and adding it now means new normalization branches.
    - `[low]` `[patch]` `127.1`, `2130706433` and `0177.0.0.1` pass because the check reads the normalized `uri.Host`. Such URLs are stored as typed, and the native port exception never applies to them. Patched: the literal text must start with `http://127.0.0.1` or `http://[::1]`. DirectoryTests cases cover it.
    - `[false]` `[reject]` Prod step-up covers only callbacks. FR-46 lists "changing a Prod Tenant's callback URLs", not logout URLs, origins or grants. The behaviour matches the requirement.
    - `[low]` `[reject]` Audit detail is null: changed fields and the acknowledgement aren't recorded. The event code plus `updated`/`prod_callback_added` separate the cases Story 11.1 needs. Field-level detail is a catalogue design change, not a defect anyone meets.
    - `[low]` `[reject]` `authorization_code` with zero callbacks is accepted. Story 3.1 creates web that way, and `/authorize` refuses such a client with the static page. It is inert, not unsafe. Requiring a callback would break the create-then-configure flow.
    - `[low]` `[patch]` The migration comment says the CHECK "encodes the type table", but per-URL rules live in C#. Patched: the comment now says the CHECK holds the kinds, counts and grant sets.
    - `[false]` `[reject]` Public-client refusals skip failure accounting. Before this change, a request with no secret was refused the same way, uncounted (`TokenEndpoint.cs:313` baseline), and the answer is the same `invalid_client` for unknown or confidential IDs. Client IDs aren't secrets.
    - `[low]` `[reject]` Duplicate lock, load and rule run, plus an extra `FindApplicationAsync` on the token path. These are one indexed row read each on a rare admin save and one on the token path. Not worth new plumbing.
    - `[false]` `[reject]` The GK012 catch is dead code. The spec requires it as a backstop behind the `kind <> 'system'` filter, and it maps a guard the database still owns.
  - **Edge Case Hunter**
    - `[medium]` `[patch]` The acknowledgement checkbox never renders on the server's 400. Same root cause and fix as the Blind Hunter dead-end row.
    - `[medium]` `[patch]` `prod` is derived from the switcher's possibly null or stale Tenant. Same root cause as above. The fix makes the server's answer authoritative.
    - `[low]` `[patch]` Text typed during a save is overwritten. Same as the Blind Hunter row: read-only while saving.
    - `[false]` `[reject]` `canLeave` can be re-entered while the unsaved modal is open. The modal is modal, so no tab can be activated beneath it to call `canLeave` again.
    - `[low]` `[patch]` An unknown `field` in a server error makes `lines[field]` throw (`isProblemError` accepts any string). Patched: the lookup is guarded, and an unknown field falls back to the bare reason.
    - `[low]` `[reject]` A save is possible while the Tenant is `creating`. Admin Tenant routes and the switcher don't offer a creating Tenant's Applications, and its only Application is the hidden system one. That is unreachable in everyday use.
    - `[maybe-false]` `[reject]` `InertApplicationTests` is unchanged although the spec lists it. Its spa and native rows now pass client authentication and rely on OpenIddict refusing the grant before reading the dummy token. CI on PR #58 settles it; if it were true, it would only be low, a test expectation.
    - `[false]` `[reject]` `CapabilityMatrixTests` is unmodified. It is driven by the capability table, which already holds `tenant.application_callbacks.manage`. The route is registered in `RouteRegistry` and `CapabilityRuleTests`.

## Design Notes

- **One route, the callbacks capability.** AD-20 hangs the Prod predicate on `tenant.application_callbacks.manage` and says it covers creating or changing an Application, and a route declares one capability. So the whole settings write uses it. Editors and Owners hold it. Machine principals lose grant edits too, which is stricter and safe. Management API grants are Epic 17.
- **Security Alert = audit event.** Story 11.1 derives alerts from sealed events ("Prod callback added"). Host.Admin has no alert channel, so this story writes only the dedicated event.
- **Logout URLs and web origins are stored and validated now.** Story 4.13 consumes logout URLs. Web origins have no consumer yet, and the Design Delta drops the separate CORS list.
- **Public clients belong here.** Single-page and native are the "No secret needed" types, and FR-13 requires PKCE for public clients. Enabling their grants means nothing until the token endpoint accepts them, and no later story owns it. This also closes 3.1's deferred `ApplicationStore` Confidential finding.
- **Turning refresh off** stops the next refresh through OpenIddict's permission check. Existing families aren't revoked: deletion (3.5) owns revocation.

## Verification

**Commands:**
- `MSYS_NO_PATHCONV=1 docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'` -- expected: 0 warnings, 0 errors
- `pnpm -r build` and `pnpm -r --if-present typecheck` in `node:26.13.0-bookworm-slim` (`npm i -g pnpm@12.16.1`) -- expected: clean
- Don't run the test suites locally. CI on the PR is the test run.

## Auto Run Result

**Summary.** An Admin can now save an Application's callback, logout and web origin URLs and its grant types, and the protocol honours them (FR-11, FR-13, FR-46, UX-DR42, AD-20).

**API:** `PUT /api/v1/tenants/{tenantId}/applications/{applicationId}/settings`, under `tenant.application_callbacks.manage`.
- **Access:** machine principals are always refused. A Prod Tenant needs a fresh assertion bound to the Application, but only when the callback set changes.
- **Validation:** rules per type, with per-line `errors` on 400 `application_invalid`.
- **Prod acknowledgement:** a new custom scheme in Prod needs `acknowledgeCustomScheme`. Without it the answer is 400 `custom_scheme_acknowledgement_required`.
- **Audit:** every change writes `directory.application.updated`. A Prod callback addition also writes `directory.application.prod_callback_added`, the event Story 11.1 turns into a Security Alert.
- **No-op:** a save that changes nothing writes nothing.

**Protocol:**
- spa and native are public clients: `client_id` only, PKCE, and any secret is refused. native is a native application type.
- `/authorize` requires the `authorization_code` grant and matches callbacks exactly. The only exception is the RFC 8252 loopback port, for native only. OpenIddict's own redirect check is removed in favour of Directory's.
- A refresh or client-credentials grant that is turned off gives `unauthorized_client`.
- Logout URLs are handed to OpenIddict for Story 4.13.

**Database:** migration 30 (`ConfigureApplicationSettings`) adds `post_logout_redirect_uris` and `web_origins`, replaces the redirect CHECK with the per-type `application_settings`, and gives `gk_admin` a column UPDATE on the four settings columns.

**Dashboard:**
- The Application page has Settings and Credentials tabs.
- Settings has the URL textareas with per-line errors, three grant toggles with disabled reasons, native system-browser guidance, the Prod custom-scheme checkbox (also brought up by the server's refusal), Save through the fresh-assertion flow with a "Changes saved" toast, an unsaved-changes guard, and read-only fields for Viewers.

**Files changed (main ones)**
- `src/Adapters/Postgres/Migrations/Migration20261114000000ConfigureApplicationSettings.cs`, `Schema/TableRegistry.cs`: columns, CHECK, grant.
- `src/Modules/Directory/{Contracts/ApplicationSettings.cs, Core/ApplicationSettingsRules.cs, Core/LoopbackRedirects.cs, Core/DirectoryService.cs, Contracts/*}`: rules, update command, events, loopback match.
- `src/Modules/Directory/Adapters/ApplicationStore.cs`: client and application type, permissions, logout URIs.
- `src/Modules/Protocol/Core/{TokenEndpoint.cs, AuthorizeEndpoint.cs, ProtocolServer.cs}`: public clients, grant-off at authorize, Directory's redirect match.
- `src/Modules/Management/{Contracts/IApplicationManagement.cs, Core/ApplicationManagement.cs}`: capability, label lock, acknowledgement, no-op, fresh assertion.
- `src/Gatekeep.Host.Admin/{ApplicationsApi.cs, AdminApi.cs, AdminResponses.cs, AdminOpenApi.cs}`: route, `errors` problem extension, new code.
- `docs/api/openapi-v1.json`, `packages/api-client/*`, `docs/audit-events.md`, `LogCatalogue.Generated.cs`: regenerated contract and catalogue.
- `apps/admin-dashboard/src/shell/{ApplicationDetailPage, ApplicationSettings(.module.css), applications, Shell, TenantSettingsPage}.tsx`, `packages/ui/src/messages.tsx`: tabs and Settings.
- Tests:
  - new `tests/Isolation/Applications/{ApplicationSettingsApiTests, ApplicationSettingsProtocolTests}.cs`;
  - updated `DirectoryTests`, `ApplicationsApiTests`, `RouteRegistry`, `CanaryFlows`, `MigrateCommandTests` (30), `CapabilityRuleTests` and `AdminApiRuleTests`;
  - the extended `tests/browser/admin-applications.spec.ts`.

**Review findings.** 32 findings: 12 patched (9 root causes), 2 deferred (1 entry: CORS for web origins) and 18 rejected.
- Patched: the body cap raised to 131072; the acknowledgement dead end, where the server's refusal now shows the checkbox; read-only textareas while saving; a guarded error-field lookup; literal loopback text; the corrected migration comment; three tests (authorised Prod removal, reordered no-op, public client with a real secret).
- Rejected, with reasons in the triage log:
  - 10 false: the http loopback for web and spa, machine refusal over HTTP, the three grants, new-only acknowledgement, public clients beyond the ACs, the logout and origin step-up, failure accounting, the GK012 backstop, `canLeave` re-entry, `CapabilityMatrixTests`.
  - 7 low: grant-off chained through the PUT, a Quickstart-style guidance flow, origin canonicalization, audit detail, auth code with zero callbacks, the duplicate row read, the Tenant `creating` state.
  - 1 maybe-false: `InertApplicationTests` expectations, which CI settles.

**Follow-up review recommended (`true`).** Patched counts by verdict: medium 3 (the body cap, the acknowledgement dead end, the Prod-removal test) and low 6. The unverified risk is the acknowledgement fallback: the server's `custom_scheme_acknowledgement_required` brings up the checkbox and the resend. That and the public-client token path have only been checked against mocked browser answers and unrun Isolation tests.

**Verification**
- `dotnet build Gatekeep.slnx -p:NuGetAudit=false` (SDK 10.0.403 container): 0 warnings and 0 errors, before and after the patches.
- `pnpm -r build` and typecheck (Node 26 container): clean, as the implementer reported.
- No suites were run locally. CI on PR #58 is the first run of the Isolation, Architecture and browser tests.
- **Matrix audit:** every I/O row has a named test in `ApplicationSettingsApiTests`, `ApplicationSettingsProtocolTests` or `DirectoryTests`. Whether they pass is judged from CI before merge.

**Residual risks**
- `InertApplicationTests`: its spa and native rows now pass client authentication, so they depend on OpenIddict refusing the grant before reading the dummy token.
- Removing OpenIddict's `ValidateClientRedirectUri` makes `TrustRedirectTarget` the only redirect check at authorize.
- Web origins have no consumer until CORS is built (deferred).
