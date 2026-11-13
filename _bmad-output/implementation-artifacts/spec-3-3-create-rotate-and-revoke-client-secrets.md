---
title: 'Story 3.3: Create, rotate and revoke client secrets'
type: 'feature'
created: '2026-11-13'
baseline_revision: 'f796ab0770c069799014ce4c847bd67174435fbd'
status: 'done'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-3-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-3-2-configure-application-urls-and-grants.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:**
- A regular web or machine-to-machine Application created in Story 3.1 has no client secret, and nothing lets an Admin give it one. It stays inert (FR-12, NFR-3, AD-24).
- Directory already stores secrets as SHA-256 and verifies every live one, honouring `expires_at` and `revoked_at`. But no route, Management edge, audit event or screen creates, rotates or revokes one.

**Approach:**
- Add three Tenant-scoped secret routes on an Application: list, create-or-rotate, and revoke. They go Host.Admin → Management → Directory.
- The writes sit under the existing `tenant.client_secrets.manage` capability: Owners only, machine-denied, `FreshAssertion.Always`.
- Rotation sets the old secret to expire after `SecurityLimits.ClientSecretOverlap` (24h). "End old secret now" revokes it.
- Give the Credentials tab the secret list, the one-time reveal, rotate, end-now and revoke.

## Boundaries & Constraints

**Always:**

- **Public ID:** add `PublicIdType.ClientSecret`, prefix `sec_`, for `client_secret.id`.
- **Routes:** all are `TenantApiEndpoint` with `applicationId` as `ApplicationsApi.ApplicationRouteValue`.
  - **`GET /api/v1/tenants/{tenantId}/applications/{applicationId}/secrets`**
    - Access: `TenantConfigurationRead`, so every Tenant Role can read.
    - Returns 200 `{ items: [{ id, createdAt, expiresAt }] }`, newest first.
    - Lists only live secrets: `revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`.
    - `expiresAt` is null for the current secret. A spa or native Application always gets `items: []`.
  - **`POST /api/v1/tenants/{tenantId}/applications/{applicationId}/secrets`**
    - Access: `RequiresCapability(TenantClientSecretsManage)` + `new FreshAssertionTarget(ApplicationRouteValue)`, and `X-Gatekeep-Tenant`.
    - Takes no body. Answers 201 `{ secret, items }`, where `secret` is the value as `RevealOnce<string>` and `items` is the list after the write.
  - **`POST /api/v1/tenants/{tenantId}/applications/{applicationId}/secrets/{secretId}/revoke`**
    - Access and headers are the same as create, and the fresh-assertion target is still the Application.
    - Takes no body. Answers 200 `{ items }`.
  - **Fresh assertions:** because the capability is `Always`, `AdminRequestChecks` consumes the grant for both writes. A missing grant is 403 `fresh_assertion_required`. Handlers don't call `FreshAssertionGate`.
  - **Refusals:** an Editor or Viewer gets 403 `access_denied`, and Management re-checks `AdminCapabilities.Allows` → `Forbidden` (machine principals included). The system Application, another Tenant's, an unknown or a malformed `applicationId` all get 404 `not_found`.
- **Create or rotate** runs in one `CommandContext` command with the Application row locked (`LockApplicationAsync`).
  - **Kind:** only `web` and `machine`. A spa or native Application gets 409 `client_secret_not_applicable`, and nothing is written.
  - **No live secret:** insert one, and write `directory.client_secret.created`.
  - **One live secret with `expires_at IS NULL`:** this is rotation.
    - Set that secret's `expires_at = now() + ClientSecretOverlap`, using the database clock.
    - Insert the new secret.
    - Write `directory.client_secret.rotated`.
  - **Live-secret cap:** an Application holds at most `SecurityLimits.MaxLiveClientSecrets = 2` live secrets (new constant). While an old secret still overlaps, create gets 409 `client_secret_limit_reached`, and nothing is written.
  - Generate and hash with `ClientSecrets.Create` / `ClientSecrets.Hash`. The format stays `{tenantPublicId}.{base64url(32 bytes)}`, 256-bit, SHA-256 of the whole string. Only the hash is stored.
  - `ClientSecretOverlap` must stay ≤ `HardClientSecretOverlap`, and an Architecture or unit test asserts it. There is no setting.
- **Revoke** sets `revoked_at = now()` on a live secret of that Application and writes `directory.client_secret.revoked`.
  - A `secretId` that is malformed, unknown, another Application's or already ended (revoked or expired) gets 404 `not_found`.
  - Revoking the current secret is allowed, even when it leaves no secret.
  - The token endpoint refuses a revoked secret at once. Verification already reads live hashes with the database clock.
- **Audit:** events are actor = Admin, target = the Application (`AuditTargetKind.Client`), detail null.
  - Add the three events to `DirectoryEvents`.
  - Regenerate `docs/audit-events.md` and `LogCatalogue.Generated.cs` with `dotnet run --project tests/Architecture/Generator`.
- **No secret value anywhere but the 201 body.** That means no logs, audit events, problem details or OpenAPI examples. Refusals log fixed codes only, as `ApplicationsApi.RefuseAsync` does.
- **OpenAPI:** the secret field needs its own client-secret schema and pattern, because `AdminOpenApi.cs:78-83` hard-codes the Recovery Code pattern for `RevealOnce<string>`. Add the new response type and builder to `RevealOnceRuleTests`.
- **Migration** `Migration20261115000000ManageClientSecrets` (count 30 → 31):
  - `GRANT UPDATE (expires_at, revoked_at) ON client_secret TO gk_admin`.
  - CHECK `client_secret_ended_after_created`: `revoked_at` and `expires_at` are null or ≥ `created_at`.
  - Update `TableRegistry` to match. The GK011 system guard stays.
- **Problem codes:** add `client_secret_not_applicable` and `client_secret_limit_reached` to `AdminResponses`. Both are 409, which is already in the status allowlist.
- **Dashboard, Credentials tab** (`ApplicationDetailPage.tsx`, a new `ApplicationCredentials.tsx`):
  - **spa and native:** unchanged, "No secret needed."
  - **web and machine:** list the live secrets.
    - The current secret shows as "Current secret · Created {date}".
    - An overlapping one shows as "Old secret · Valid until {datetime}", with **End old secret now**.
    - No value, hash or prefix is ever shown, and there is no Reveal.
  - **Owner** (has `tenant.client_secrets.manage`):
    - With no live secret, **Create secret**. With one, **Rotate secret**. Rotate is disabled while an old secret overlaps, with "End the old secret before rotating again."
    - **Revoke** on the current secret opens a confirm `Modal`: it stops working at once, and the Application can't get tokens until a new one is created.
    - Every write goes through `fresh.withFreshAssertion({ action: 'tenant.client_secrets.manage', target: application.id, tenantId }, send)`.
    - Create or rotate shows `OneTimeReveal` with the value (the first app use of it). Rotation then shows the toast "New secret created. Old secret valid for 24h."
    - End-now and revoke show a toast. A failure shows a `Banner` with `ErrorReference`, which is the UX rotate-failure banner.
  - **Without the capability:**
    - Write controls are disabled with "Tenant Owner only" (`tenantOwnerOnly`).
    - With no live secret, the text reads "No client secret yet. A Tenant Owner must create one."
- **Create Application as an Owner:** when the caller has `tenant.client_secrets.manage` and the new type needs a credential, the create flow:
  - navigates to the new Application's Credentials tab;
  - runs Create secret through the fresh-assertion sheet;
  - shows the reveal.

  A cancelled sheet leaves the Create secret button. An Editor's flow is unchanged.

**Never:**

- No Reveal of a stored secret, Private Key JWT, mTLS, public keys or an authentication-method picker (Design Delta).
- No configurable overlap, and no overlap beyond 7 days.
- No change to `VerifyClientSecretAsync` semantics, the secret format, `CreateMachineClientAsync`/`CreateWebClientAsync`, or the Application create API response.
- No secret history list. Ended secrets are visible only through the Log.
- No Management API token routes (Epic 17), no export feature (none exists), and no deletion (3.5).
- Host.Admin never references Directory.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Owner creates first secret | web app, no secret, fresh grant for app | 201 `secret` (`ten_….` 43-char tail) + 1 item `expiresAt` null; one `client_secret` row holding only its SHA-256; `created` event; token endpoint accepts the value | grant consumed once |
| Owner rotates | one current secret, fresh grant | 201 new value; 2 items, the old with `expiresAt` ≈ now+24h; `rotated` event; old and new both get tokens | — |
| Rotate again during overlap | 2 live | 409 `client_secret_limit_reached`, nothing written | UI disables Rotate |
| End old secret now | revoke the overlapping `sec_` | 200, 1 item; old value refused at token at once; `revoked` event | — |
| Revoke current | only secret | 200, `items: []`; value refused at once | — |
| Overlap elapsed | old `expires_at` set into the past (SQL) | old value refused; not listed | — |
| No fresh assertion | Owner, no grant | 403 `fresh_assertion_required`, nothing written | UI runs the sheet, resends once |
| Editor / Viewer write; machine principal | — | 403 `access_denied` / Management `Forbidden`; nothing written | — |
| Viewer lists | — | 200 items, no value/hash fields | — |
| spa / native create | — | 409 `client_secret_not_applicable` | — |
| Bad secret id | malformed, unknown, other app's, already revoked or expired | 404 `not_found` | — |
| System / foreign / malformed app | — | 404 `not_found` | — |
| Canary | flows create, rotate, use, revoke | planted value (full and random part) absent from every table, log and non-201 response | — |

</intent-contract>

## Code Map

- `src/Adapters/Postgres/Migrations/Migration20261106000000CreateDirectoryTables.cs:46-59,104-137`: the `client_secret` columns, hash CHECK, UNIQUE, FK, index, RLS and grants. No role has UPDATE.
- `src/Adapters/Postgres/Migrations/Migration20261109000000AddSystemApplication.cs:63-78`: the GK011 `system_application_guard`. Keep it.
- `src/Adapters/Postgres/Migrations/Migration20261114000000ConfigureApplicationSettings.cs`: the latest migration, to copy.
- `src/Adapters/Postgres/Schema/TableRegistry.cs:596-614`: copy the `application` `ColumnGrant(Update, …)` shape into the `client_secret` entry.
- `tests/Isolation/MigrateCommandTests.cs:20,28`: the count, 30 → 31.
- `src/Modules/Directory/Core/DirectoryService.cs`:
  - `ClientSecrets.Create`/`Hash` at :366-382;
  - `InsertSecret` SQL at :51-55;
  - `LiveSecretHashes` at :58-63;
  - `VerifyClientSecretAsync` at :280-316, which stays read-only;
  - `CreateApplicationAsync` at :150-207, the command and `_audit.AppendAsync` pattern to copy.
- `src/Modules/Directory/Contracts/{IDirectory.cs, DirectoryEvents.cs:12-27}`: add list, create-or-rotate and revoke, plus the three events. `LockApplicationAsync` exists.
- `src/Gatekeep.Kernel/Identifiers/PublicId.cs:4-80`: add `ClientSecret` → `sec`.
- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs:247-255`: `ClientSecretOverlap` and `HardClientSecretOverlap`, both unused so far. Add `MaxLiveClientSecrets`.
- `src/Gatekeep.Kernel/Secrets/{Secret.cs, RevealOnce.cs}`; `tests/Architecture/RevealOnceRuleTests.cs:24-37`: the allow-lists for response types, builders and schema names.
- `src/Modules/Admins/Contracts/AdminCapabilities.cs:162`: `TenantClientSecretsManage`, which is Owners, machine-denied and `Always`.
- `src/Gatekeep.Host.Admin/AdminRequestChecks.cs:642-655`: consumes the `Always` grant bound to the action, the Tenant and the target. The model is `AdminApi.cs:462-466`, DeleteTenant.
- `src/Gatekeep.Host.Admin/FreshAssertionApi.cs:134-175,204`: the Tenant begin. A target is accepted only if a route declares one.
- `src/Gatekeep.Host.Admin/AdminApi.cs:637-732`: the Application routes. Copy GET :658 and settings PUT :698.
- `src/Gatekeep.Host.Admin/ApplicationsApi.cs`:
  - `CreateAsync` :204-255, the pattern to copy;
  - the GK012 mapping at :303-309;
  - `RefuseAsync`/`LogRefusal` at :366-375;
  - `ApplicationResponse` at :20-50.
- `src/Gatekeep.Host.Admin/{AdminResponses.cs:42-169,309, AdminOpenApi.cs:78-83}`: problem codes and no-store; the `RevealOnce` schema pattern to special-case.
- `src/Modules/Management/{Contracts/IApplicationManagement.cs, Core/ApplicationManagement.cs:62-98}`: the capability re-check and actor mapping to copy.
- `deploy/docker/api-contract.sh`: regenerates `docs/api/openapi-v1.json` and `packages/api-client/src/schema.generated.ts`, as in Story 3.2. Client methods go near `client.ts:327-340`.
- `apps/admin-dashboard/src/shell/ApplicationDetailPage.tsx:36-45,199,205-213`: the props, `has`, and today's Credentials text.
- `apps/admin-dashboard/src/shell/ApplicationSettings.tsx:115,220`: toast and `withFreshAssertion` usage, to copy.
- `apps/admin-dashboard/src/shell/{freshAssertion.ts:119-136, capabilities.ts:174-186, CreateApplicationModal.tsx}`: the create flow to extend for Owners.
- `packages/ui/src/components/OneTimeReveal.tsx:12-75` (exported at `admin.ts:16`): props `open/onClose/title/value/what/fallbackFocus`, with Close gated on "I've copied this".
- `packages/ui/src/messages.tsx:371,495-499,759,844-846`: `tenantOwnerOnly` and the `applicationCredentials*` copy.
- `design/Gatekeep Admin.dc.html:345-362`: the Credentials card. Drop the method picker, Reveal and the public keys.
- `tests/Isolation/Canary/CanaryFlows.cs:61-75,187-286,386-405,1440-1500`:
  - the `Plant` API and the registry;
  - the credential-free exemptions, where the new routes must not go;
  - `ClientCredentialsAsync`, the planting model.
- `tests/Isolation/Tenancy/TenantRequests.cs:34,58,89,101,127,131`: Owner and Editor sessions, begin, events and grants.
- `tests/Isolation/Applications/ApplicationSettingsApiTests.cs:39,69,453,469`: the app create and `ConfirmAppAsync` fresh-assertion helpers.
- `tests/Isolation/Protocol/ClientCredentialsTests.cs:594` `TokenAsync`; `ProtocolHost.cs:177,191`; `ApplicationSettingsProtocolTests.cs:24`, which uses Admin and Protocol together.
- `tests/Isolation/CrossTenant/RouteRegistry.cs:98-102`; `tests/Architecture/CapabilityRuleTests.cs:183-221` (`DeletionRoutes` :216 is the model); `tests/Architecture/AdminApiRuleTests.cs:214`.
- `tests/browser/admin-applications.spec.ts:26,66-67,95`: caps, fixtures and the `answerApi` mock. Add an Owner caps constant.

## Tasks & Acceptance

**Execution:**
- `src/Gatekeep.Kernel/{Identifiers/PublicId.cs, Limits/SecurityLimits.cs}`: add the `sec_` type and `MaxLiveClientSecrets = 2`, with a test that the overlap is within the hard limit. These are the IDs and limits.
- `src/Adapters/Postgres/Migrations/Migration20261115000000ManageClientSecrets.cs` + `TableRegistry.cs` + `MigrateCommandTests.cs`: the UPDATE grant and CHECK, count 31. Admin can now end secrets.
- `src/Modules/Directory/{Contracts,Core}`: list live, create-or-rotate (lock, kind check, cap, overlap via `now()`) and revoke, plus the three events. Directory owns the table.
- `src/Modules/Management/{Contracts,Core}/ApplicationManagement.cs`: list, create and revoke, with the capability re-check and actor mapping. This is the Management edge.
- `src/Gatekeep.Host.Admin/{ApplicationsApi.cs or a new ApplicationSecretsApi.cs, AdminApi.cs, AdminResponses.cs, AdminOpenApi.cs}`: the three routes and their metadata, the problem codes, the client-secret schema, and no-store. This is the API surface.
- `tests/Architecture/{RevealOnceRuleTests.cs, CapabilityRuleTests.cs, AdminApiRuleTests.cs}`: allow-list and pin the new routes. These are the rules.
- `docs/api/openapi-v1.json`, `packages/api-client/src/{schema.generated.ts, client.ts, index.ts}` + a client unit test: regenerate, and add `listApplicationSecrets`, `createApplicationSecret` and `revokeApplicationSecret`. This is the contract.
- `docs/audit-events.md`, `src/Gatekeep.Host.Admin/LogCatalogue.Generated.cs`: regenerate the catalogue.
- `apps/admin-dashboard/src/shell/{ApplicationDetailPage.tsx, ApplicationCredentials.tsx (new, + .module.css), applications.ts, CreateApplicationModal.tsx}`, `packages/ui/src/messages.tsx`: the Credentials tab, the reveal, rotate, end-now, revoke, the Owner create flow and the copy. This is the screen.
- `tests/Isolation/Applications/ApplicationSecretsApiTests.cs` (new): every row of the I/O matrix, including token-endpoint use of the created, overlapping, ended, revoked and expired values, the audit events and the stored hash only.
- `tests/Isolation/{CrossTenant/RouteRegistry.cs, Canary/CanaryFlows.cs}`: register the routes, and add a secrets canary flow that plants the value.
- `tests/browser/admin-applications.spec.ts`: Credentials for Owner (create reveal gated on "I've copied this", rotate toast, Rotate disabled during overlap, end-now, revoke modal), Editor ("Tenant Owner only", the must-create text) and spa ("No secret needed."), the Owner create flow, and axe in light and dark at 1100 and 768 px.

**Acceptance Criteria:**
- Given an Owner on a web Application's Credentials tab, when they create a secret, then the value appears once in `OneTimeReveal`, Close stays disabled until "I've copied this" is ticked, and after closing no screen or API shows it again.
- Given an Editor on a web or machine Application with no secret, when Credentials opens, then it reads "No client secret yet. A Tenant Owner must create one." and the write controls read "Tenant Owner only".
- Given the new routes, when CI runs, then the cross-Tenant, canary, capability matrix, RevealOnce, contract and Architecture suites pass with the routes registered.

## Spec Change Log

## Review Triage Log

### 2026-11-13: Review pass

- **Verdicts:** 30 findings. High 0, medium 2, low 21, false 7, maybe-false 0.
- **Patched entries:** 7, from 10 findings. One entry is medium: the concurrent-rotation test.
- **Rejected:** 20 findings: 13 low and 7 false.

**Blind Hunter (13 findings)**

- `[false]` `[reject]` **Concurrent revoke and create can trip the CHECK.** The claim is that a revoke waiting on a concurrent create gets an earlier `now()` than the new secret's `created_at`. That can't happen: a revoke names a `sec_` ID taken from a list, and the new secret's ID exists only after the create commits. So any revoke of it starts later, with a later `now()`. A rotation's expiry is `now()` + 24h, far after any `created_at`.
- `[false]` `[reject]` **The revoke route declares a 409 it can never return.** The request checks answer 409 `tenant_mismatch` on it before the handler runs, and `AdminOpenApi` requires every state-changing Tenant route to declare that 409. A comment on the route now names the reason.
- `[low]` `[reject]` **The revoked event doesn't name the secret, or whether it was current or old.** The spec fixes `detail` as null, as every Directory event has it. Field-level detail is a catalogue design change. The event, the actor and the target still answer "who ended a secret on which Application, and when".
- `[low]` `[patch]` **`Rotated` is never sent, so the toast guesses from a stale list.** Grouped with Edge Case #7 and Verification Gap other #1. Patched: the toast now comes from the 201's `items` (a live old secret gives the overlap toast), and the dead `Rotated` properties are removed.
- `[low]` `[patch]` **The revoke modal says no tokens until a new secret, which is wrong while an old secret overlaps.** Patched: that wording is used only when no other live secret exists. Otherwise the modal says the old secret works until it ends.
- `[false]` `[reject]` **"End old secret now" has no confirmation.** Every write first gets 403 `fresh_assertion_required`, because the capability is `Always`. So `withFreshAssertion` always opens the passkey sheet first, and that is a deliberate confirmation step.
- `[low]` `[reject]` **The list doesn't refresh when an overlap lapses.** It is fixed by a reload or any later action, which gets 404/409 and re-reads the list. A tab left open for 24 hours is rare, and the fix needs a timer.
- `[low]` `[reject]` **The `TableRegistry` worker grant is inlined instead of referencing `PurgeColumns`.** The entry needed a merged column-grant dictionary. Sharing it would need a new merge helper. A drift would be caught by the schema-registry tests that compare grants with the database.
- `[false]` `[reject]` **The migration's CHECK has no plan for existing rows.** Before this migration no role held UPDATE on `client_secret`. `InsertSecret` sets neither `expires_at` nor `revoked_at`. So every deployed row has both null and passes. Only test fixtures that set them by superuser SQL needed changes.
- `[medium]` `[patch]` **No test races two creates.** Grouped with Verification Gap #1. Patched: a test races two rotations and asserts one Done, one LimitReached, at most two live rows and one rotated event.
- `[low]` `[reject]` **A create after revoking the current secret, while an old one overlaps, writes `created`.** That matches the rule: no current secret means a create. The event's wording is accurate, and the cap still holds.
- `[low]` `[reject]` **The OpenAPI secret schema is set in two places.** The regenerated `openapi-v1.json` shows the client-secret pattern on `secret` and the Recovery Code pattern unchanged. The contract diff in CI pins it.
- `[low]` `[reject]` **The GK011 catch logs twice.** It follows the existing GK012 settings catch (`ApplicationsApi.cs:303-309`): `AdminRequestChecks.Log` for the exception, then the fixed-code refusal. The backstop is unreachable in normal flow.

**Intent Alignment (5 findings)**

- `[low]` `[reject]` **End-now and revoke share one event code.** Same as the Blind Hunter detail row. The spec deliberately makes end-now a revoke.
- `[low]` `[reject]` **Token-endpoint checks use machine Applications only.** Web and machine authenticate through the same `VerifyClientSecretAsync` live-hash read. The kind isn't consulted there, so a web case exercises no new path.
- `[false]` `[reject]` **Dashboard criteria are tested only against mocked APIs.** That is the browser suite's design for every Admin screen. The server half of each criterion has its own Isolation test against real hosts.
- `[false]` `[reject]` **NFR-3 says Master-Key encryption, not a hash.** FR-12 allows "hashed or under the Master Key", and the AC says SHA-256. NFR-3 itself has one-time values stored hashed.
- `[false]` `[reject]` **"Exports" isn't scanned.** No export surface exists; `tenant.configuration.export` is only a capability. The canary covers every table, log and response that does exist (Design Notes).

**Edge Case Hunter (8 findings)**

- `[low]` `[patch]` **App-clock `created_at` from the System path can be ahead of the database clock.** A quick revoke or rotation then fails the CHECK. Patched: `revoked_at = greatest(now(), created_at)` and `expires_at = greatest(now(), created_at) + overlap`.
- `[low]` `[reject]` **"Newest first" with mixed clocks.** At most two live rows exist, and a mixed-clock order needs a System secret and an Admin secret created within the skew. Both rows still show correctly, by state.
- `[low]` `[reject]` **A commit that fails after the server commits gives 503 for a live rotation.** A lost connection mid-commit is rare. The Owner recovers by ending the old secret and rotating, and an ambiguous-commit protocol is new machinery.
- `[low]` `[reject]` **The panel unmounting while a create is in flight loses the reveal.** The passkey sheet is modal, so the window is only the resend's round trip after the assertion. Recovery is "End old secret now", then rotate. Keeping the panel mounted would change the shared `Tabs`.
- `[low]` `[patch]` **The auto-create ask stays in the module Set if the panel unmounts before the list loads.** Patched: the ask is taken once on mount, and acted on when the list is ready.
- `[low]` `[reject]` **The expired old secret stays listed and Rotate stays disabled.** Same as the Blind Hunter refresh row.
- `[low]` `[patch]` **A stale list gives the wrong toast.** Grouped with the Blind Hunter `Rotated` row.
- `[low]` `[patch]` **A 201 whose `items` fail the shape check drops the secret.** Patched: a 201 carrying a secret is revealed, independently of the items check.

**Verification Gap (4 findings)**

- `[medium]` `[patch]` **The row lock against concurrent rotations has no test.** Grouped with the Blind Hunter concurrent-create row.
- `[low]` `[patch]` **The re-read after a 404/409 write refusal is never exercised in the browser.** Patched: a browser test answers 409 with a changed server list, then asserts the banner, a second GET, the old-secret row and the rotate-blocked note.
- `[low]` `[patch]` **`Rotated` is dead as wired.** Grouped with the Blind Hunter `Rotated` row.
- `[low]` `[reject]` **The GK011 catch is unreachable and untested.** It is a backstop behind the visibility filter, like 3.2's GK012 catch. The database still owns the guard.

## Design Notes

- **Fresh assertion on every write.** The capability table encodes `tenant.client_secrets.manage` as `Always`, and a route declares one capability. So create, rotate, end-now and revoke all need a fresh assertion, not only rotation. That is stricter than the AC and consistent with the one capability table.
- **End old secret now = revoke.** Ending the overlap and revoking a secret have the same effect: it stops at once and the Log is written. One route keeps one code path. The UI labels it by the secret's state.
- **Cap of two live secrets.** Rotating again while an old secret overlaps would make overlaps pile up. Refusing it, until the old one is ended or expires, keeps "current + one old" as the only shape.
- **Exports.** No export feature exists yet; `tenant.configuration.export` is only a capability. The canary scan covers every database table (audit included), host logs and responses, which is every surface that exists. Each later export story joins the canary.

## Verification

**Commands:**
- With `$env:MSYS_NO_PATHCONV=1`: `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings, 0 errors.
- `pnpm -r build` and `pnpm -r --if-present typecheck` in `node:26.13.0-bookworm-slim` (`npm i -g pnpm@12.16.1`). Expected: clean.
- Don't run the test suites locally. CI on the PR is the test run.

## Auto Run Result

**Summary.** A Tenant Owner can now create, rotate and revoke the client secret of a regular web or machine-to-machine Application (FR-12, NFR-3, AD-24).

**API:** three routes under `/api/v1/tenants/{tenantId}/applications/{applicationId}/secrets`.
- **List** (`GET`, any Tenant Role): the live secrets, by `sec_` ID, creation time and end time. Never a value or hash.
- **Create or rotate** (`POST`):
  - Tenant Owners only, never a machine principal, with a fresh assertion bound to the Application.
  - With no current secret it creates one. With one it rotates: the old secret keeps working for 24 hours (`SecurityLimits.ClientSecretOverlap`, under the 7-day hard limit).
  - At most two live secrets: a second rotation during an overlap is 409 `client_secret_limit_reached`.
  - spa and native get 409 `client_secret_not_applicable`.
  - The value (`{tenantPublicId}.{43 base64url}`, 256 random bits) is shown only in the 201, through `RevealOnce`, and stored only as SHA-256.
- **Revoke** (`POST .../{secretId}/revoke`, same access): the secret is refused at the token endpoint at once. This is also the dashboard's "End old secret now".
- **Audit:** `directory.client_secret.created`, `.rotated` and `.revoked`, each naming the Application only.

**Database:** migration 31 (`ManageClientSecrets`) gives `gk_admin` UPDATE on `expires_at` and `revoked_at` only, and adds the CHECK `client_secret_ended_after_created`.

**Dashboard:** the Credentials tab for web and machine Applications:
- lists "Current secret" and "Old secret · Valid until …";
- has Create/Rotate, "End old secret now", and Revoke behind a confirm modal;
- runs every write through the passkey sheet, then shows the `OneTimeReveal`, gated on "I've copied this", and a toast;
- shows Viewers and Editors disabled controls marked "Tenant Owner only", and "No client secret yet. A Tenant Owner must create one."

An Owner who creates a web or machine Application is taken to Credentials, where the first secret is created and revealed.

**Files changed (main ones)**
- `src/Adapters/Postgres/Migrations/Migration20261115000000ManageClientSecrets.cs`, `Schema/TableRegistry.cs`: grant and CHECK.
- `src/Gatekeep.Kernel/{Identifiers/PublicId.cs, Limits/SecurityLimits.cs}`: `sec_` and `MaxLiveClientSecrets`.
- `src/Modules/Directory/{Contracts/IDirectory.cs, Contracts/DirectoryEvents.cs, Core/DirectoryService.cs}`: list, create-or-rotate and revoke under the row lock; events.
- `src/Modules/Management/{Contracts/IApplicationManagement.cs, Core/ApplicationManagement.cs}`: capability re-check and actor mapping.
- `src/Gatekeep.Host.Admin/{ApplicationSecretsApi.cs (new), AdminApi.cs, AdminResponses.cs, AdminOpenApi.cs, ApplicationsApi.cs}`: routes, problem codes, the client-secret schema.
- `docs/api/openapi-v1.json`, `packages/api-client/*`, `docs/audit-events.md`, `LogCatalogue.Generated.cs`: regenerated contract and catalogue.
- `apps/admin-dashboard/src/shell/{ApplicationCredentials.tsx (+ .module.css, new), ApplicationDetailPage.tsx, ApplicationsPage.tsx, CreateApplicationModal.tsx, applications.ts}`, `packages/ui/src/messages.tsx`: Credentials and the Owner create flow.
- **Tests:**
  - new `tests/Isolation/Applications/ApplicationSecretsApiTests.cs` (including a concurrent-rotation test) and `tests/Architecture/ClientSecretLimitTests.cs`;
  - a new canary flow, `admin.application-secrets`;
  - updated `RevealOnceRuleTests`, `CapabilityRuleTests`, `AdminApiRuleTests`, `RouteRegistry`, `DirectoryTests`, `MigrateCommandTests` (31), `ClientCredentialsTests` and `tests/browser/admin-applications.spec.ts`.

**Review findings.** 30 findings: 7 entries patched (10 findings), none deferred, 20 rejected.

Patched:
- `greatest(now(), created_at)` for revoke and rotation, against app/database clock skew;
- the create toast taken from the 201's items, and the dead `Rotated` flags removed;
- the revoke-modal wording while an old secret overlaps;
- the auto-create ask taken on mount;
- the secret revealed from any 201;
- a concurrent-rotation Isolation test;
- a stale-list browser test.

Rejected, with reasons in the triage log:
- **7 false:** the concurrent revoke CHECK; the revoke 409, which `tenant_mismatch` needs; end-now confirmation, which the passkey sheet gives; CHECK on existing rows; mocked dashboard tests; NFR-3 hashing; exports.
- **13 low:**
  - revoked-event detail, and the end-now and revoke code it shares;
  - the lapsed-overlap refresh, reported twice;
  - the `PurgeColumns` inline;
  - the create-after-revoke event;
  - the double OpenAPI schema;
  - the GK011 log, and that GK011 is untested;
  - machine-only token checks;
  - mixed-clock ordering;
  - a commit-phase failure;
  - the panel unmounting while a create is in flight.

**Follow-up review recommended (`false`).** Patched counts by verdict: medium 1 (the concurrent-rotation test) and low 6. No high was patched.

**Verification**
- `dotnet build Gatekeep.slnx -p:NuGetAudit=false` (SDK 10.0.403 container): 0 warnings and 0 errors, before and after the patches.
- `pnpm -r build` and typecheck (Node 26 container): clean, before and after the patches.
- No suites were run locally. CI on the PR is the first run of the Isolation, Architecture, canary and browser tests.
- **Matrix audit:** every I/O row has a named test in `ApplicationSecretsApiTests`, and the canary row has the `admin.application-secrets` flow. Whether they pass is judged from CI before merge.

**Residual risks**
- A secret is lost if the Credentials panel unmounts during the create's round trip after the passkey sheet (rejected low). Recovery: end the old secret, then rotate.
- An open tab doesn't drop a lapsed old secret until a reload or the next action.
- The browser tests use mocked API answers only.
