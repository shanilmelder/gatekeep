---
title: "Story 4.4: Configure a Tenant's email provider"
type: 'feature'
created: '2026-11-16'
status: 'done'
baseline_revision: 'fb16bcccff4e959834f384c36b9105db97d05c8e'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-4-context.md'
warnings: ['oversized']
deferred:
  - summary: >-
      Changing the email provider doesn't raise a Security Alert yet.
    evidence: |-
      FR-36 asks for a Security Alert on a provider change. The product owner deferred it to Epic 11 (2026-11-16): Host.Admin can't raise alerts yet. This story writes only the Log events notifications.email_provider.updated and .removed.
    location: >-
      src/Modules/Notifications/Core/EmailProviderStore.cs
    severity: medium
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

### 2026-11-16 — Review pass
- verdicts: 31 findings — high 1, medium 13, low 12, false 5, maybe-false 0
- findings:
  - `[false]` `[reject]` (intent a) Nothing sends or test-sends mail, so "so that messages reach Users" isn't met — sending is Story 4.5 and test send Story 15.5 (spec Never list); this story's criteria are about storing the configuration.
  - `[low]` `[reject]` (intent b) "Host.Admin can't decrypt" is proven one layer below the endpoint (real OpenBao through the module) while the HTTP tests use a stand-in — the HTTP route calls the same module and custody; the database denial on `secret_ciphertext` is tested separately.
  - `[medium]` `[patch]` (intent c) A machine principal's change is refused only at the capability level, never at the endpoint — Host.Admin authenticates no machine client before Epic 17, so a test now drives a machine principal of the Tenant through the request checks' authorizer: refused `tenant.email_provider.manage` (still allowed `tenant.configuration.read`), nothing written.
  - `[false]` `[reject]` (intent e) "The Log" may mean the operational log — in Gatekeep "the Log" is the Tenant audit Log (FR-36); the event is tested.
  - `[low]` `[reject]` (intent f) SMTP with no username stores no ciphertext, narrowing "stored as Transit ciphertext" — an unauthenticated relay has no credential to store; every credential that exists is ciphertext.
  - `[false]` `[reject]` (intent g) Remove, no-op saves, purge and registries go beyond the intent — the screen's Remove and the Tenant purge are required by the design and the purge rule (AD-27).
  - `[medium]` `[patch]` (verification) A save that drops the SMTP username and clears the secret is untested — tested: 200, `secretSet:false`, ciphertext NULL, one more event.
  - `[medium]` `[patch]` (verification) Replacing the secret on a same-kind save is untested — tested: a second encryption replaces the stored ciphertext.
  - `[medium]` `[patch]` (verification) Adding an SMTP username with no secret stored isn't tested at the server — tested: 400 `secret: required`, row unchanged.
  - `[medium]` `[patch]` (verification, other) Removal skips the advisory lock, so a racing save can fail with an unhandled 500 — `RemoveAsync` now takes the same lock.
  - `[high]` `[patch]` (blind) A same-kind save without a secret keeps the stored secret while the destination or account changes (SMTP host, custom_http endpoint, Mailgun domain, SES key ID…), so an Owner who never knew it could redirect it to their own server — a stored secret is now kept only when `kind` and `settings` are unchanged apart from Postmark's `messageStream`; From fields may change freely. This narrows the spec's "omitted, it keeps the stored ciphertext" rule. Tests for SMTP `host` and custom_http `endpoint` changes without a secret (400 `required`) and a From-only change (kept); UI `secretRequired` mirrors it.
  - `[medium]` `[patch]` (blind) Removal doesn't take the lock and can race a save into a 500 — grouped with the verification row; fixed.
  - `[low]` `[reject]` (blind) A no-change save shows the same "saved" toast — the stored state is what the Owner asked for; nothing is misreported.
  - `[low]` `[patch]` (blind) Switching kind carries a typed secret to the new kind — the draft's secret is cleared on a kind change (unit test).
  - `[medium]` `[patch]` (blind) `IsPublic` lets through reserved IPv4 ranges and IPv6 forms (NAT64, 6to4, IPv4-compatible) that can embed private addresses — those ranges are refused and embedded addresses judged by their IPv4; tests added.
  - `[low]` `[patch]` (blind) `MaxBody` (32768) can't hold a full secret plus settings when non-ASCII is escaped — raised to 65536 with a corrected comment.
  - `[low]` `[reject]` (blind) The event records no detail (secret replaced, kind changed) — the audit envelope holds no free-form values (AD-16).
  - `[medium]` `[patch]` (blind) Important paths untested (clearsSecret, oversize body, save/remove race, destination change) — grouped with the verification rows and the high row; the oversize-body and cancellation cases are rejected as low (the cap is a fixed read limit; cancellation is the host's).
  - `[false]` `[reject]` (blind) The diff leaves out four generated files — they were left out of the review diff on purpose; the contract check and `AuditCatalogueTests` verify them.
  - `[low]` `[patch]` (blind) Length limits disagree between server, OpenAPI and UI (`tls`, `region`) — aligned. The merged OpenAPI settings schema (no per-kind `required`) is rejected: a `oneOf` per kind adds schema complexity for a client the dashboard already covers.
  - `[medium]` `[patch]` (edge) Remove vs save race (lock) — grouped; fixed.
  - `[medium]` `[patch]` (edge) An UPDATE that finds no row throws past the 503 handling — removed by serialising removal with saves under the same lock.
  - `[medium]` `[patch]` (edge) IPv6 literals embedding private IPv4 — grouped with the `IsPublic` row; fixed.
  - `[medium]` `[patch]` (edge) Reserved IPv4 ranges accepted — grouped; fixed.
  - `[low]` `[patch]` (edge) `MaxBody` too small for escaped input — grouped; fixed.
  - `[low]` `[patch]` (edge) Switching to SES carries `region` `global`/`us` into SES's free-text region — values invalid for the new kind are dropped on a kind change.
  - `[low]` `[reject]` (edge) A typed secret on a disabled field keeps the form dirty — the Owner is asked about unsaved changes they did type; harmless.
  - `[low]` `[reject]` (edge) A 400 naming only `kind` or `settings` moves focus nowhere — the dashboard never sends those shapes; only a hand-built client can.
  - `[low]` `[patch]` (edge) A whitespace-only SMTP `username` is stored and makes a secret required — treated as absent.
  - `[false]` `[reject]` (edge) The spec says GET answers `secretSet:true`, but SMTP with no username answers false — the spec's shape assumed a secret; reporting none when none exists is correct.
  - `[medium]` `[patch]` (edge) "Saves of one Tenant wait for each other" isn't true of removal — grouped with the lock row; fixed.

## Verification

**Commands:**
- **.NET build:** with `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors.
- **Contract:** regenerate with `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v "D:/Projects/Personal/gatekeep:/out" -w /src gatekeep/tests:local sh deploy/docker/api-contract.sh --write /out`. Then run `pnpm -r build`, the ui check and the api-client and admin-dashboard tests. Expected: all pass.
- **Browser:** run the Playwright `admin-email-provider` project. Expected: all pass.
- **Isolation:** with Testcontainers, pinning the IPv4 as `run-tests.sh` does, run `EmailProviderApiTests`, `CrossTenant*`, `Canary*`, `MigrateCommandTests`, `TenantPurge*`, `Custody*` and `AuditCatalogue*`, plus the Architecture suite. Don't run the full Isolation suite. The local-only `.claude/worktrees` failure is expected.

## Auto Run Result

**Summary:** Notifications gains `email_provider`, one row per Tenant: the provider kind (SMTP, SendGrid, Postmark, Mailgun, Amazon SES or Custom HTTP), its validated non-secret settings, the From address, and the provider's one secret as Transit ciphertext under `email-{tenant}` with the Tenant ID as associated data. Host.Admin can encrypt it but not decrypt it, and `gk_admin` can't read the ciphertext column. `GET`/`PUT`/`DELETE /api/v1/tenants/{tenantId}/email-provider` read for every Tenant role and save or remove for Owners with a fresh assertion; Editors, Viewers and machine principals are refused. Saves and removals write `notifications.email_provider.updated`/`.removed`. A stored secret is kept only when the destination settings are unchanged. The Admin Dashboard gains an Email provider page.

**Files changed:**
- `src/Adapters/Postgres/Migrations/Migration20261125000000ConfigureEmailProviders.cs`, `Schema/TableRegistry.cs` -- the table, RLS, guard, grants and CHECKs (migration 41).
- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs` -- secret, ciphertext, settings and From-name limits.
- `src/Modules/Notifications/**` -- kinds, per-kind rules (including public-address checks), the store (lock, change detection, encrypt, upsert, remove), events and the Tenant purge.
- `src/Modules/Management/**` -- `IEmailProviderManagement` with the capability re-check.
- `src/Gatekeep.Host.Admin/{AdminApi.cs,EmailProviderApi.cs,AdminResponses.cs,AdminOpenApi.cs}` -- the three routes and OpenAPI; regenerated contract, audit docs and Log catalogue.
- `src/Modules/Operations/Core/TenantDeletion.cs` -- the Notifications purge joins the stage.
- `packages/api-client/**`, `packages/ui/src/messages.tsx`, `apps/admin-dashboard/src/shell/{emailProvider.ts,EmailProviderPage.tsx,...}` -- client wrappers, copy and the page.
- Tests: new `EmailProviderApiTests` and `admin-email-provider.spec.ts`; updated capability rules, route registry, canary, seeds, purge registry, migration count, grants and sidebar order.

**Review findings:** 31 findings (high 1, medium 13, low 12, false 5). Patched 12 entries (high 1, medium 7, low 4, counted by group): a stored secret is no longer kept when the destination or account settings change (it could otherwise be redirected to an Owner's own server); removal takes the save lock; reserved and embedding IP ranges are refused; the dashboard clears a typed secret and invalid carried values on a kind switch; the body cap fits escaped input; limits agree across server, OpenAPI and UI; whitespace usernames count as absent; tests for clearing, replacing and requiring the secret, and for a machine principal at the authorizer (Host.Admin has no machine client before Epic 17). Deferred 1 (the Security Alert, Epic 11). Rejected 18 with reasons in the Review Triage Log.

**Follow-up review:** recommended. This pass patched a high finding. The specific unverified risk: the destination-bound secret rule now decides every save, and the Tenant deletion stage gained a purge whose tests are timing-sensitive under a loaded local run; the full Isolation suite runs only in CI. Patched counts: high 1, medium 7, low 4.

**Verification:**
- .NET build: 0 warnings / 0 errors; API contract matches.
- `pnpm -r build`; ui check; tests: ui 62, admin-dashboard 135, api-client 38.
- Architecture: 794 of 795; the one failure is the known local-only `.claude/worktrees` check.
- Isolation `EmailProviderApiTests`, `CrossTenant*`, `Canary*`, `MigrateCommandTests`, `TenantPurge*`, `AuditCatalogue*`, `TenantTablesTests`, `TenantDeletion*`, `PolicyMatrix*`, `CustodyTests`: 733 of 734 after the fixes. The one failure, `TenantDeletionTests.A_failed_deletion_is_read_and_retried_with_a_new_assertion_then_finishes`, and two other deletion tests that failed on the earlier run, all pass alone (the class 17 of 17, three times).
- `MasterKeyRotationTests.Full_rotation_keeps_every_value_and_leaves_the_old_generation_unable_to_unseal` fails locally even alone (an OpenBao root-token census in shell); this story touches no OpenBao script or policy. CI decides.
- Playwright `admin-email-provider` (implementer): 21 of 21; the sidebar-affected admin projects 254 of 254 before the fixes.

**Residual risks:**
- A machine principal's refusal is tested at the authorizer, not over HTTP, until Epic 17 adds machine clients.
- Custom HTTP endpoints are checked only as configured; resolved-address and redirect checks belong to Story 4.5.
- The Security Alert is deferred to Epic 11.
