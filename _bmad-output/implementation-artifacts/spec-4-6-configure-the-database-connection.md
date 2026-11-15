---
title: 'Story 4.6: Configure the database Connection'
type: 'feature'
created: '2026-11-16'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-4-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-4-4-configure-a-tenant-s-email-provider.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** Sign-up, sign-in and reset (4.7, 4.9, 4.11, 4.12) need a Tenant's database Connection: whether sign-up is open, and the password policy. They also need the Tenant settings a sign-up reads: the terms URL, Dev-only email verification off, and the default audience. None of these exists. There is no `connection` or `password_history` table, `tenant_settings` holds only timestamps, and the Admin Dashboard has no Database page (FR-17, FR-18, UX-DR21, UX-DR42, UX-DR44).

**Approach:**
- **New tables:**
  - Directory gets `connection`: one `database` Connection per Tenant, holding the sign-up flag and the password policy.
  - Identity gets `password_history`: created empty, for 4.7 and 4.11 to write.
- **Default Connection:** it is ensured when a Tenant's creation completes. Existing Tenants get it from a backfill.
- **Tenant settings:** `tenant_settings` gains the terms URL, verification off and the default audience.
- **Admin API routes** read and save each of these as one audited command per save, and a new Database page plus a card on Tenant settings show them.

## Boundaries & Constraints

**Always:**
- **`connection`** (Directory, a `tenant` table, Configuration use, RLS pair plus `tenant_row_guard`, registry entry, purge):
  - **Columns:** `tenant_id`, `id`, `kind` (CHECK `= 'database'`), `name` (`'Username-Password'`), `enabled` (default true), `signup_enabled` (default true), `password_min_length` (12–64, default 12), `password_strength` (`good` or `excellent`, default `good`), `password_history_count` (0–24, default 5, where 0 means off), `password_dictionary` (default true), `password_personal_data` (default true), `created_at`, `updated_at`.
  - **Uniqueness:** a unique index on `(tenant_id, kind)` gives one database Connection per Tenant in v1.
- **`connection` grants:**
  - `gk_admin`: SELECT, plus column UPDATE on `signup_enabled`, the five `password_*` columns and `updated_at` only.
  - `gk_hosted`: SELECT.
  - `gk_worker`: SELECT, INSERT and DELETE (ensure, backfill, purge).
- **`password_history`** (Identity, a `tenant` table, Runtime use, RLS pair plus `tenant_row_guard`, registry, purge):
  - **Columns:** `tenant_id`, `id`, `user_id` (FK to `user (tenant_id, id)`), `password_hash`, `created_at`.
  - **Grants:** `gk_hosted` SELECT, INSERT and DELETE; `gk_worker` SELECT and DELETE.
  - **No foreign key to `connection`:** Directory is purged before Identity.
- **Default Connection:**
  - `DirectoryContract` ensures it (insert-if-missing, idempotent), called from `TenantCreation.ActivateAsync`, as the system Application and the built-in API already are.
  - Existing Tenants get it from a `ForEachTenant` migration backfill and from the hourly `keys.tenant_keys.backfill` job.
  - The SQL defaults and the contract constants are held equal by a test.
- **Password policy:**
  - **Floor:** `SecurityLimits.PasswordMinimumLengthFloor = 12` and `PasswordMinimumLengthCeiling = 64`. A minimum below the floor is refused with exactly "Minimum is 12 characters.".
  - **Levels:**
    - `good`: the minimum length, plus 3 of 4 classes (lower, upper, number, special).
    - `excellent`: the same, plus no more than 2 identical characters in a row.
  - **Scope here:** 4.6 stores and validates the policy. Enforcing it on a password is 4.7's job.
- **`tenant_settings` gains:**
  - `terms_url`: NULL, or an absolute `https` URL with no userinfo, at most 2048 characters.
  - `email_verification_off`: default false.
  - `default_audience`: NULL, or an API identifier.
- **Saving those settings:**
  - `default_audience` must name an existing, non-built-in API of the same Tenant, checked at save. It is stored as text, not a foreign key, because Directory is purged before Tenancy. 4.9 falls back to its default if the API is gone.
  - `email_verification_off = true` saves only while the Tenant's label is Dev. Its read is effective only while the label is Dev.
- **Admin API**, all Tenant-scoped, with JSON bodies and RFC 9457 problems that carry fields and reasons:

  | Route | Capability |
  |------|------|
  | `GET /api/v1/tenants/{tenantId}/connections/database` | `tenant.configuration.read` |
  | `PUT …/connections/database/settings` `{signupEnabled}` | `tenant.connections.toggle` |
  | `PUT …/connections/database/password-policy` `{minLength, strength, historyCount, dictionary, personalData}` | `tenant.password_policy.manage` (Owner only) |
  | `GET /api/v1/tenants/{tenantId}/settings` → `{termsUrl, emailVerificationOff, emailVerificationOffAvailable, defaultAudience}` | `tenant.configuration.read` |
  | `PUT /api/v1/tenants/{tenantId}/settings` `{termsUrl, emailVerificationOff, defaultAudience}` | `tenant.settings.manage` |

  - Capabilities, machine-principal and fresh-assertion settings stay as `AdminCapabilities` has them today.
  - A Tenant that isn't active gets 409.
- **Each save** is one Management command in the path Tenant's scope. It writes its state and one Tenant-targeted audit event together, and only when a value changed. The events are `directory.connection.updated`, `directory.connection.password_policy_updated` and `tenancy.tenant.settings_updated`. The detail holds no values.
- **Read ports for later stories:** Directory reads the Tenant's database Connection and its policy; Tenancy reads the sign-up settings, with verification off already ANDed with the Dev label. Module edges are added deliberately.
- **Dashboard:**
  - **Navigation:** "Database" goes in the `authentication` nav group, at `/tenants/{id}/database`.
  - **Page header and tabs:** a "DB" badge, then "Username-Password". Two tabs, Settings (the default) and Password policy, each with its own Save and a "Changes saved" toast.
  - **Settings tab:**
    - One settings row with the sign-up toggle.
    - Its description reads "When off, the Sign up link is hidden and no one can create an account."
  - **Password policy tab:**
    - The minimum length.
    - A strength radio for Good and Excellent, each described.
    - A history toggle with a count input.
    - Dictionary and personal-data toggles.
    - A live "what users see" preview listing the rules as met or not met for a sample typed into a field that isn't sent.
  - **Read-only treatment:**
    - Editors see the policy read-only, labelled "Tenant Owner only".
    - Viewers see everything read-only, with the view-only banner.
  - **Tenant settings page:** gains a card with the terms URL, the default audience (a select of the Tenant's non-built-in APIs, plus "None") and the verification-off toggle, shown only for Dev Tenants.
  - **Errors:** shown inline, with the server's rule text. Copy lives in `messages.tsx`.

**Never:**
- No enforcement on a password, no hashing, no writes to `password_history`, and no sign-up UI (4.7, 4.9, 4.11).
- No `application_connection` or Applications tab (4.12).
- No custom dictionary list, no username, no identifier types, and no Custom database or Import tabs (Design Delta).
- No other Tenant settings fields (8.5). No terms version or acceptance record (4.8).
- No change to the token audience at issue time (4.9).
- No new audit target kind.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| New Tenant | creation completes | one `database` Connection with the defaults | No error expected |
| Existing Tenant | migrate | backfilled once; rerun adds nothing | No error expected |
| Floor | Owner PUT `minLength: 11` | 400, field `minLength`, detail "Minimum is 12 characters."; nothing saved | 400 |
| Ceiling / bad enum | `minLength: 65`, `strength: "fair"`, `historyCount: 25` | 400 naming each field | 400 |
| Editor and policy | Editor PUT password-policy | 403; GET still returns the policy | 403 |
| Editor and sign-up | Editor PUT `{signupEnabled:false}` | 200; one `directory.connection.updated` | No error expected |
| Viewer | any PUT | 403 | 403 |
| Unchanged save | PUT with the same values | 200; no event | No error expected |
| Other Tenant | PUT on Tenant A as an Admin with a role only in Tenant B | 403/404 as the other Tenant routes do; Tenant A unchanged | refused |
| Verification off on a non-Dev Tenant | PUT `emailVerificationOff:true`, label Staging | 400, field `emailVerificationOff` | 400 |
| Dev, then relabelled | saved true, then label set to Prod | the read port says not off; GET shows `emailVerificationOffAvailable:false` | No error expected |
| Default audience | built-in Management API, or an unknown identifier | 400, field `defaultAudience` | 400 |
| Terms URL | `http://…`, userinfo, more than 2048 characters | 400, field `termsUrl` | 400 |
| Clear | `termsUrl:null`, `defaultAudience:null` | saved as NULL | No error expected |
| Tenant purge | deleting Tenant | `connection` and `password_history` rows removed | No error expected |

</intent-contract>

## Code Map

- `src/Modules/Directory/{Contracts,Core}`: `DirectoryContract.cs:186` (factories), `DirectoryService.Apis.cs:302` (`EnsureBuiltInApiAsync`, the insert-if-missing model for `EnsureDatabaseConnectionAsync`), `IDirectory.cs:359` (`FindApiByIdentifierAsync`, used to check the default audience), `DirectoryEvents.cs` (add the events), `DirectoryPurge.cs:13` (add `connection`). Story 3.6's equal-literals test is at `DirectoryContract.cs:84-97`.
- `src/Modules/Identity/Core/IdentityPurge.cs:11`: add `password_history` before `user`.
- `src/Modules/Tenancy`: `Core/Tenants.cs:45` (the settings row insert), `Contracts/ITenants.cs:9,50,208-216` (`TenantLabel`, `GetLabelAsync`), `TenancyEvents.cs`.
- `src/Modules/Operations/Core/TenantCreation.cs:129` `ActivateAsync` (add the ensure next to the system Application and built-in API ones), `TenantKeyBackfill.cs:24-88` (add the ensure), `TenantDeletion.cs:57-66` (purge order: Directory, then Identity, then Tenancy).
- `src/Modules/Management`: the `EmailProviderManagement.cs` pattern (capability re-check via `AdminCapabilities.Allows`, status enums), created in `ManagementContract`.
- `src/Modules/Admins/Contracts/AdminCapabilities.cs:132,157,158,163`: the existing capabilities, unchanged.
- `src/Gatekeep.Host.Admin`: `AdminApi.cs:769-834` (route mapping pattern), `EmailProviderApi.cs:128-231` (handler pattern), `AdminResponses.cs:194` (problem codes), `AdminOpenApi.cs` (fields and reasons), `AdminApiServices.cs`, `LogCatalogue.Generated.cs` (regenerated).
- `src/Adapters/Postgres`: `Schema/TableRegistry.cs:152` (`tenant_settings`), `:312` (`user`), `:728` (`email_provider`, the template entry). The new migration `Migrations/Migration20261127000000ConfigureDatabaseConnection.cs` follows `Migration20261125000000ConfigureEmailProviders.cs` (table, RLS and grants) and `Migration20261119000000DefineApis.cs:33,179` (`ForEachTenant` backfill).
- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs`: the password floor and ceiling, history maximum and terms URL length.
- `apps/admin-dashboard/src/shell/`: `EmailProviderPage.tsx` (+ `.module.css`, `emailProvider.ts`) as the model, `TenantSettingsPage.tsx` (add the card), `nav.ts:40-79`, `Shell.tsx` (`TENANT_ROUTE` and branch). Copy in `packages/ui/src/messages.tsx`; client wrappers in `packages/api-client/src/client.ts` (regenerate with `pnpm --dir packages/api-client generate`).
- **Tests to touch:**
  - `tests/Isolation/MigrateCommandTests.cs` (42 → 43)
  - `Tenancy/TenantCreationTests.cs:58,339` (assert the Connection exists after creation)
  - `Tenancy/TenantSeeds.cs` (seed both tables)
  - `CrossTenant/HostedGrantsTests.cs:85-89` (add `connection`)
  - `CrossTenant/RouteRegistry.cs`, `Canary/CanaryFlows.cs`
  - `tests/Architecture/CapabilityRuleTests.cs:289-312`, `module-edges.txt` (+ regenerate `docs/architecture/module-dependencies.md`)
  - `AuditCatalogueTests`; regenerate `docs/audit-events.md` with `dotnet run --project tests/Architecture/Generator`
  - `tests/browser/playwright.config.ts:72` (testIgnore + own project), `admin-signing-keys.spec.ts` (nav-group order)

## Tasks & Acceptance

**Execution:**
- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs`: add the password and terms limits.
- `src/Adapters/Postgres/Migrations/Migration20261127000000ConfigureDatabaseConnection.cs` and `Schema/TableRegistry.cs`: both tables, `tenant_settings` columns with CHECKs, grants and backfill.
- `src/Modules/Directory/*`: the Connection model and rules (validation with field and reason codes), the store, the ensure, the read port, events and purge.
- `src/Modules/Identity/Core/IdentityPurge.cs`: purge `password_history`.
- `src/Modules/Tenancy/*`: the sign-up settings read, save rules (terms URL, Dev-only verification off) and event.
- `src/Modules/Operations/Core/TenantCreation.cs`, `TenantKeyBackfill.cs`: ensure the default Connection.
- `src/Modules/Management/*`: the database Connection and Tenant settings management commands. The default-audience check goes through Directory.
- `src/Gatekeep.Host.Admin/*`: the five routes, problems, OpenAPI fields and reasons, and services. Regenerate the OpenAPI doc, the API client, the log catalogue and audit docs.
- `apps/admin-dashboard/src/shell/DatabasePage.tsx` (+ css, `database.ts` helpers mirroring the limits), `TenantSettingsPage.tsx`, `nav.ts`, `Shell.tsx`, `packages/ui/src/messages.tsx`: the UI.
- `tests/Isolation/Directory/DatabaseConnectionApiTests.cs`, `tests/Isolation/Tenancy/TenantSettingsApiTests.cs`, a backfill/ensure test, plus the touched tests listed in the Code Map: cover every row of the I/O Matrix.
- `apps/admin-dashboard/test/database.test.mjs`, `tests/browser/admin-database.spec.ts` (Owner, Editor and Viewer views, the floor error, axe in light and dark), and a Tenant settings browser case.
- `docs/threat-model.md` (TB-6 grants for the new tables and columns).

**Acceptance Criteria:**
- Given password policy, when the minimum falls below 12, then the save is refused with "Minimum is 12 characters.".
- Given an Editor, when they toggle sign-up, then it saves, and the password policy stays read-only, labelled "Tenant Owner only".
- Given a saved change, when it commits, then it applies only to that Tenant and one audit event is written in the same transaction.
- Given Tenant settings, when an Editor saves a terms URL, a default audience, or (Dev Tenants only) verification off, then they persist and the read ports return them.
- Given Tenant creation or an existing Tenant after migrating, then exactly one database Connection with the defaults exists.

## Spec Change Log

## Review Triage Log

## Design Notes

- **The ensure lives in `ActivateAsync`, not in a new stage.** A Tenant already mid-creation when this ships would have no planned step for a new stage. `ActivateAsync` is where Stories 2.8 and 3.6 ensured the system Application and built-in API, and it still runs inside the creation Operation.
- **Audit events target the Tenant.** A `Connection` target kind would need a migration re-rendering both target-kind CHECKs, and the Tenant has exactly one Connection.
- **Strength levels:** the Design Delta drops None, Low and Fair, and redefines Good and Excellent on top of the minimum.

## Verification

**Commands:**
- **.NET build:** with `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors. If Docker isn't available, skip it; CI is the test source of truth.
- **Dashboard:** `pnpm -r build`, plus the dashboard unit tests. Expected: green.
- **Isolation, Architecture and browser suites:** CI on the PR. Don't run the full suites locally.
