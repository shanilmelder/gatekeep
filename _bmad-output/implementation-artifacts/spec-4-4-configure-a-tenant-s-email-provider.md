---
title: "Story 4.4: Configure a Tenant's email provider"
type: 'feature'
created: '2026-11-16'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-4-context.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** A Tenant has nowhere to configure how its email is sent, so verification and reset messages (Stories 4.5, 4.7 and 4.11) can't reach Users. The capability `tenant.email_provider.manage` (Owner only, never machine, always a fresh assertion), the per-Tenant Transit `email-{tenant}` key and the OpenBao policy split (Admin encrypts and the Worker decrypts) already exist. Nothing stores or edits a provider (FR-36, FR-46, AD-10).

**Approach:**
- **Storage:** the Notifications module gains `email_provider`, one row per Tenant, holding the provider kind, its non-secret settings, the From address and the provider's one secret as Transit ciphertext.
- **Routes:** Host.Admin gets a read route for every Tenant role and Owner-only save and remove routes, which need a fresh assertion. The plaintext secret is encrypted in the request and never stored, logged or returned.
- **Dashboard:** an "Email provider" page.

**Decided 2026-11-16:**
- **Providers:** SMTP, plus named SendGrid, Postmark, Mailgun and Amazon SES, plus a Custom HTTP provider.
- **Security Alert:** FR-36's alert waits for Epic 11. This story writes only the Log.

## Boundaries & Constraints

**Always:**
- **Kinds and settings.** The non-secret settings are validated per kind and stored as a `settings` JSON object. Unknown members are refused.

  | Kind | Settings | Secret |
  |------|----------|--------|
  | `smtp` | `host` (DNS name or public IP, ≤253), `port` (1–65535), `tls` (`starttls` or `implicit`; no plaintext), `username` (optional, ≤256) | password, required when `username` is set |
  | `sendgrid` | `region` (`global` or `eu`) | API key |
  | `postmark` | `messageStream` (optional, ≤64, `[A-Za-z0-9_-]`) | server token |
  | `mailgun` | `domain` (DNS name, ≤253), `region` (`us` or `eu`) | API key |
  | `ses` | `region` (`^[a-z]{2}(-[a-z]+)+-[0-9]$`), `accessKeyId` (`^[A-Z0-9]{16,128}$`) | secret access key |
  | `custom_http` | `endpoint` (an absolute `https` URL ≤2048, with no userinfo or fragment, and not localhost, a loopback, private, link-local or unspecified IP literal), `authHeaderName` (an HTTP token ≤64, default `Authorization`) | auth header value |

  - The From address applies to every kind: `fromAddress` is a valid email address of at most 254 characters, and `fromName` is optional, at most 128 characters, with no control characters.
  - A secret is 1–4096 characters with no NUL.
  - How a Custom HTTP request is shaped, and the full outbound checks (resolved addresses and redirects), belong to Story 4.5. This story validates only the configuration.
- **Storage:**
  - **Columns:** `email_provider (tenant_id PK, kind, settings jsonb, from_address, from_name, secret_ciphertext, updated_at)`, a Notifications `tenant` table with RLS, `tenant_row_guard` and a registry entry, in migration `Migration20261125000000ConfigureEmailProviders` (sorting after the latest; the migration count goes from 40 to 41).
  - **Ciphertext check:** `secret_ciphertext` carries the `^vault:v[0-9]+:[A-Za-z0-9+/=]+$` CHECK with a length cap.
  - **Grants:**
    - `gk_admin`: insert, update and delete, plus column SELECT on everything except `secret_ciphertext`.
    - `gk_worker`: SELECT and DELETE, for sending (4.5) and the Tenant purge.
    - `gk_hosted`: nothing.
- **Encryption:** Host.Admin encrypts the secret with `IKeyCustody.EncryptAsync(KeyName.ForTenant(TenantKeyClass.Email, tenantId), tenantId, …)`. `associated_data` is the Tenant ID, as the adapter already makes it. Plaintext is held only as `Secret<T>` for that call.
- **Routes,** under `/api/v1/tenants/{tenantId}/email-provider`:
  - `GET` is open to every Tenant role. It answers `{configured:false}`, or `{configured:true, kind, settings, fromAddress, fromName, updatedAt, secretSet:true}`. It never returns the secret or the ciphertext.
  - `PUT {kind, settings, fromAddress, fromName?, secret?}` requires `tenant.email_provider.manage`, which is Owner only, refuses machine principals and always needs a fresh assertion (`fresh_assertion_required` comes from the existing checks).
    - `secret` is required when no provider exists or when `kind` changes. Omitted otherwise, it keeps the stored ciphertext.
    - It answers the GET shape.
    - Bad input is 400 with field errors (`invalid`, `required`, `too_long`).
  - `DELETE` has the same capability and answers 204. Removing nothing also answers 204, with nothing written.
  - Editors, Viewers and machine principals are refused with the existing 403s, and nothing is written.
- **Audit:** `notifications.email_provider.updated` is written when a save changes anything (no event when nothing changed). `notifications.email_provider.removed` is written on removal. Both target the Tenant and record no settings and no secret.
- **Purge:** a Notifications `ITenantPurge` deletes the Tenant's `email_provider` row and joins `TenantDeletion.StagePurges`.
- **Dashboard:**
  - **Navigation:** an "Email provider" page in the Branding group, gated on the route.
  - **No provider:** the empty state reads "No provider set", with Add for Owners.
  - **Kind cards:** SMTP, SendGrid, Postmark, Mailgun, Amazon SES and Custom HTTP, each showing its fields.
  - **The secret field** is write-only. When a secret is stored it shows "Saved – enter a new value to replace it".
  - **Save:** runs `withFreshAssertion`, then shows a toast.
  - **Remove:** a confirmation, then the fresh assertion, then a toast.
  - **Editors and Viewers** see it read-only with "Tenant Owner only".
  - **Copy:** all text comes from the catalogue.
- **Contract and registries:** the new routes join the OpenAPI document and generated client (with api-client wrappers), `RouteRegistry` (with bodies), the canary, `CapabilityRuleTests`, the audit catalogue and `TenantPurgeRegistryTests`.

**Never:**
- No sending, test send, connection check or adapter: Story 4.5, Story 15.5, and Host.Admin has no egress.
- No Security Alert (Epic 11).
- No decryption anywhere in Host.Admin, and no OpenBao policy change.
- No secret or ciphertext in a response, a log line or an audit event.
- No Deployment-wide provider.
- No SMS or phone provider.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| First save | Owner with a fresh assertion, PUT smtp with secret | 200 GET shape (`secretSet`); row with `vault:` ciphertext under `email-{tenant}`; event `updated` | No error expected |
| Admin can't read | as `gk_admin`, `SELECT secret_ciphertext` | permission denied; the Admin custody can't decrypt `email-*` | refused |
| Keep secret | PUT the same kind, no `secret`, a changed port | ciphertext unchanged; settings updated; event | No error expected |
| Kind change without secret | smtp → sendgrid without `secret` | 400 `required` on `secret`; nothing written | refused |
| Unchanged | PUT identical, no `secret` | 200, no event | No error expected |
| Each kind | a valid body per kind | stored; GET echoes the settings | No error expected |
| Bad fields | `custom_http` endpoint `http://` or `https://127.0.0.1`, smtp port 0, tls `none`, unknown member, `ses` bad region | 400 field errors | nothing written |
| Not fresh | Owner without a fresh assertion | 403 `fresh_assertion_required` | nothing written |
| Editor / Viewer / machine | PUT or DELETE | 403 | nothing written |
| Read | Viewer GET | 200 without the secret | No error expected |
| Remove | Owner with a fresh assertion, DELETE | 204; row gone; event `removed`; again → 204, no event | No error expected |
| Other Tenant | path Tenant ≠ grant | existing cross-Tenant refusal | refused |
| Tenant deleted | Tenant deletion runs | row purged | No error expected |

</intent-contract>

## Code Map

- `src/Modules/Admins/Contracts/AdminCapabilities.cs:166` -- `TenantEmailProviderManage` already exists (Owner only, not machine, `FreshAssertion.Always`). Find the read capability every Tenant role holds (as the Tenant settings GET uses).
- `src/Gatekeep.Host.Admin/AdminRequestChecks.cs:158-166, 225+` -- `Always` is enforced by the checks; a `{tenantId}`-only route needs no `FreshAssertionTarget`.
- **Route and handler template:** Signing Key revoke at `src/Gatekeep.Host.Admin/AdminApi.cs:735-767` and `SigningKeysApi.cs:183-258`:
  - `PathTenantGrant` and `Principal`;
  - `ReadJsonAsync` with a size cap;
  - `TenantScope`, the module call, commit;
  - `DbException` gives 503;
  - fixed-code logging;
  - `IKeyCustody` from the request services.
- **Management:** `src/Modules/Management/{Contracts/ManagementContract.cs:24,Core/SigningKeyManagement.cs:209,Contracts/ISigningKeyManagement.cs}` is the pattern, with a capability re-check and status enums. `Management.csproj` already references Notifications.
- `src/Modules/Notifications/{Contracts/NotificationsContract.cs,Core/NotificationsCore.cs,Adapters/NotificationsAdapters.cs}` -- placeholders to fill. Edges Management→Notifications and Notifications→Tenancy exist. `IKeyCustody` and `KeyName` are in Kernel (`src/Gatekeep.Kernel/Secrets/{IKeyCustody.cs:39-70,KeyName.cs:26,119-133}`).
- `src/Adapters/OpenBao/OpenBaoKeyCustody.cs:153,601-615` -- encrypt and `associated_data`. `deploy/openbao/policies/host-admin.hcl` allows encrypt only on `email-*`; no change.
- **Migration and registry patterns:**
  - Ciphertext column: `src/Adapters/Postgres/Migrations/Migration20261105000000CreateSigningKeyTables.cs:52-82`.
  - Length cap: `Migration20261102020000CreateJobTables.cs:46`.
  - `TableRegistry.cs` `job_payload` (L256-275, Admin insert only) and the column-SELECT patterns.
  - Latest migration: `Migration20261124000000PurgeExpiredSignInState.cs`.
- **Tenant purge:** `src/Modules/Operations/Core/TenantDeletion.cs:57-65` (`StagePurges`), `src/Modules/Keys/Core/KeysPurge.cs`, `tests/Isolation/Tenancy/TenantPurgeRegistryTests.cs`.
- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs` -- the limits for secret length and settings.
- **Dashboard:**
  - `apps/admin-dashboard/src/shell/TenantSettingsPage.tsx` (L49-57 confirmation failures, L96/L297 "Tenant Owner only", L160 `withFreshAssertion`, L184 toast), `SigningKeysPage.tsx:240,262`, `freshAssertion.ts`;
  - `EmptyState` (`packages/ui/src/admin.ts:10`, used at `ApplicationsPage.tsx:173`);
  - `nav.ts:39-70`, `Shell.tsx:175,557-565`;
  - `packages/ui/src/messages.tsx`;
  - `packages/api-client/src/client.ts:375` (`setTenantLabel` pattern).
- **Tests to extend:**
  - `tests/Architecture/CapabilityRuleTests.cs:276-287`;
  - `tests/Isolation/CrossTenant/RouteRegistry.cs:99-102`;
  - `tests/Isolation/Canary/CanaryFlows.cs:420-437`;
  - `tests/Isolation/Keys/SigningKeyRevokeApiTests.cs` (the API test template);
  - `tests/Isolation/Custody/PolicyMatrixTests.cs` (already proves the Admin/Worker split);
  - `tests/browser/admin-*.spec.ts` (the browser pattern);
  - `tests/Isolation/MigrateCommandTests.cs` (40).

## Tasks & Acceptance

**Execution:**
- Migration and `TableRegistry`: `email_provider`, RLS, guard, grants and the CHECKs. The migration count goes to 41.
- `src/Modules/Notifications/**`:
  - the provider model with per-kind validation;
  - read, save (encrypt then upsert, change detection) and remove in a `CommandContext`;
  - the events;
  - the Tenant purge.
- `src/Modules/Management/**`: `IEmailProviderManagement`, with a capability re-check and statuses.
- `src/Gatekeep.Host.Admin/**`: the three routes, OpenAPI descriptions, responses and problem codes. Regenerate `docs/api/openapi-v1.json`, the client schema, `docs/audit-events.md` and `LogCatalogue.Generated.cs`.
- `packages/api-client`: wrappers and a unit test. `packages/ui/src/messages.tsx`: copy.
- `apps/admin-dashboard`: the page, navigation, route and unit tests for its helpers.
- **Tests:**
  - `tests/Isolation/Notifications/EmailProviderApiTests.cs` (new): every matrix row, including a raw check that the stored value is `vault:` ciphertext and that the Admin custody can't decrypt it;
  - registries, canary, capability rules, purge registry and migration count;
  - `tests/browser/admin-email-provider.spec.ts`: empty state, the save flow per card with the fresh assertion and toast, the read-only Editor view, axe in light and dark.

**Acceptance Criteria:**
- Given provider credentials, when a Tenant Owner saves them with a fresh assertion, then they're stored as Transit ciphertext, `Host.Admin` can't decrypt them, and the Log is written.
- Given an Editor or machine principal, when it attempts to change the provider, then it's refused.

## Spec Change Log

## Review Triage Log

## Verification

**Commands:**
- **.NET build:** with `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors.
- **Contract:** regenerate with `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v "D:/Projects/Personal/gatekeep:/out" -w /src gatekeep/tests:local sh deploy/docker/api-contract.sh --write /out`. Then run `pnpm -r build`, the ui check and the api-client and admin-dashboard tests. Expected: all pass.
- **Browser:** run the Playwright `admin-email-provider` project. Expected: all pass.
- **Isolation:** with Testcontainers, pinning the IPv4 as `run-tests.sh` does, run `EmailProviderApiTests`, `CrossTenant*`, `Canary*`, `MigrateCommandTests`, `TenantPurge*`, `Custody*` and `AuditCatalogue*`, plus the Architecture suite. Don't run the full Isolation suite. The local-only `.claude/worktrees` failure is expected.
