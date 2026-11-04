---
title: 'Story 1.27: Create Tenants with permanent subdomains'
type: 'feature'
created: '2026-11-04'
status: 'done'
baseline_revision: 'e9546561cd9dc96f9ce82c20900631157b6e83bb'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-gatekeep-2026-11-01/prd.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/DESIGN.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-9-track-long-running-operations.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-25-open-the-admin-shell.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md'
  - '{project-root}/docs/spikes/2-1-openiddict-per-tenant.md'
  - '{project-root}/design/Gatekeep Admin.dc.html'
warnings: []
deferred:
  - summary: >-
      Host.Hosted Tenant lookup has no per-client limit.
    evidence: |-
      A short timeout and bounded pool protect it for now.
    location: >-
      src/Modules/Tenancy/Adapters/TenancyAdapters.cs
    severity: medium
  - summary: >-
      The Create poll stopping on unmount has no browser test.
    evidence: |-
      The cleanup is short and readable.
    location: >-
      apps/admin-dashboard/src/shell/CreateTenantPage.tsx
    severity: low
  - summary: >-
      Tenancy references ASP.NET Core and Npgsql, which reach every host and the CLI.
    evidence: |-
      Needed for the resolution middleware.
    location: >-
      src/Modules/Tenancy/Gatekeep.Modules.Tenancy.csproj
    severity: low
---

<intent-contract>

## Intent

**Problem:** FR-7 says "A Deployment Owner can create and delete Tenants … The Deployment Owner who creates a Tenant becomes its Tenant Owner", and its consequences: "Each Tenant is served from its own Tenant Subdomain, which gives it its own issuer, Hosted Login address, discovery document and JWKS", "A Tenant Subdomain can't change after creation, is never reused, and can't use a reserved infrastructure name", and "Requests for an unknown subdomain get a generic rejection and never reach a Tenant". FR-44: "With no Tenants, a Deployment Owner lands on a create-Tenant form." AD-6: "`Host.Hosted` resolves the whole host, lower-cased, by exact match on the `tenant_host` control table. No code parses a subdomain out of a host. An unknown host gets one fixed 404 before any Tenant code runs … The issuer, WebAuthn RP ID and email link base are read from the stored Tenant record, never from the request. `tenant_host` rows are never deleted … Reserved names live in a code-owned list." AD-30: "Work spanning modules or Tenants is an Operation … That covers Tenant creation", "Starting one returns `202`", "Each step is idempotent". AD-10: "Secret class keys have no row, and only Tenant creation and deletion create or destroy them."

Today nothing creates a Tenant:
- `tenant` has only `id` and `created_at`. `tenant_host` and `tenant_settings` exist (Story 1.4) with no writer. There is no issuer, RP ID, email link base, name, label or status column.
- The Tenancy, Keys and Management modules are placeholders. Host.Admin maps no Tenant or Operation route. `tenant_role` is read-only to `gk_admin` (Story 1.24).
- The Operations registry has one production type, `audit.chain.purge`, with no caller. A step's handler can't reach key custody, and an Operation has no completion step.
- Host.Hosted maps nothing. It answers every request with the ASP.NET Core default 404 (Story 1.21's `TenantHostBeforeBootstrapTests`), and never reads `tenant_host`.
- Host.Admin doesn't know the Tenant zone. Only Caddy reads `GATEKEEP_TENANT_ZONE`.
- The dashboard's sidebar registry is empty and `/` is a holding page ("No Tenants yet.").

Items in `deferred-work.md` this story takes in:
- "Grant `gk_admin` `INSERT` on `tenant_role` and make a Tenant's creator its Tenant Owner; add the first Owner-only Deployment route with its HTTP refusal test for a non-Owner" (Story 1.24), and its review twin "Over-HTTP refusal of a non-Owner on a real Owner-only Deployment route".
- "The create-Tenant landing and the first Deployment sidebar item, Tenants" (Story 1.25).
- "Prove Session renewal keeps the values of a real form on a real page" (Story 1.25), and its review twin "Prove a real form keeps its values across a Session renewal".
- "Mark open Operation steps failed when their run or step job goes dead, so the Operation can be retried … Needed before the first production Operation type" (Story 1.9). Tenant creation is the first production type with a caller.

Not taken in: "The Tenant-surface fresh-assertion begin" (Story 1.26). Tenant creation is `deployment.tenants.create`, whose `FreshAssertion` is `Never` (FR-46's list doesn't name creation), and no route here declares a fresh-assertion capability. The item moves to Story 1.28, whose Prod label removal (`tenant.label.manage`, `WhenProdTenant`) is the first Tenant route that needs it.

**Approach:**
- **Create is one command, then one Operation.**
  - `POST /api/v1/deployment/tenants` (Deployment Owner, `deployment.tenants.create`) runs one Deployment `CommandContext` in Management. It:
    1. validates the input;
    2. derives the host, issuer, RP ID and email link base once, in Tenancy;
    3. inserts `tenant` with status `creating`;
    4. inserts its `tenant_host` row, whose primary key makes a taken host fail;
    5. inserts the creator's `tenant_role` as `owner`;
    6. starts the Tenant-scoped Operation `tenancy.tenant.create`;
    7. appends `tenancy.tenant.created`.
  - It answers `202` with the Tenant and the Operation.
  - Every refusal of the subdomain (malformed, reserved or taken) is the same 400 `subdomain_refused`.
- **The Operation does the Worker-only work.**
  - Its one stage, `keys.secret_classes`, creates the six secret class Transit keys (`totp-`, `social-`, `email-`, `payload-`, `hmac-`, `tpk-{tenantId}`) through the Keys contract. Only `Host.Worker`'s policy may create them (AD-10). Creating an existing name returns it unchanged, so the step is idempotent.
  - A new **completion handler** runs once, in the transaction that marks the Operation `succeeded`, in the Tenant's own scope. It inserts the `tenant_settings` row, sets the Tenant `active` and appends `tenancy.tenant.activated`.
  - Later stories add their own creation stages (Signing Keys in Story 2.3, the built-in API in Story 3.x, the default Connection), and all of them run before activation without any ordering.
- **Host.Hosted resolves Tenants.**
  - A Tenancy middleware runs first on the public port. It looks up the request's lower-cased host, without its port, by exact match on `tenant_host` joined to an `active` `tenant`.
  - No match, a `creating` Tenant, or any other host gives one fixed 404. It is byte-identical to what Host.Hosted answers today, and is written before routing.
  - A match sets a `ResolvedTenant` feature carrying the stored issuer, RP ID and email link base. Forwarded host headers are never read.
- **Subdomains can't change.**
  - No grant allows `UPDATE` or `DELETE` on `tenant_host`, and a trigger refuses both for every role.
  - A trigger refuses any change to `tenant`'s `id`, `issuer`, `rp_id`, `email_link_base` and `created_at`.
  - Only the create request accepts a subdomain, which an architecture rule holds over the OpenAPI document.
- **Reading and retrying.**
  - `GET /api/v1/tenants/{tenantId}/operations/{operationId}` reads an Operation through `IOperations.GetForTenantAsync`. Another Tenant's, unknown and malformed IDs all get the unknown-path 404.
  - `POST /api/v1/deployment/operations/{operationId}/retry` retries a failed creation.
  - `GET /api/v1/deployment/tenants` lists Tenants for the Owner.
- **Dashboard.**
  - The first sidebar item is Deployment → Tenants.
  - `/` shows the Create Tenant form when the Owner has no Tenants, and opens Tenants otherwise.
  - The form follows `wiz.s0` without Region, polls the Operation, and on success shows a `toast` and opens Tenants.
  - A browser test proves the form keeps its values across a Session renewal.

## Boundaries & Constraints

**Always:**

- **Tenant address (Tenancy contract, `TenantAddress`, built in one place):**
  - Input is the subdomain, the zone and the Tenant HTTPS port:
    - `host` = `{subdomain}.{zone}`;
    - `issuer` = `https://{host}/`, with `:{port}` before the slash only when the port isn't 443;
    - `rpId` = `host`;
    - `emailLinkBase` = `issuer`.
  - The issuer is an origin with only the root path, the `Uri.AbsoluteUri` form the Story 2.1 spike compares against ("issuers are origin-only"). Story 2.3 reads it as stored.
  - It is computed once, at creation, and stored. Nothing ever recomputes it from a request or from configuration.
- **Tenant Subdomain rule (Tenancy contract, `TenantSubdomain.TryParse`):**
  - The value is taken exactly as sent: no trimming or case folding.
  - It must be 3–63 characters of `a–z`, `0–9` and `-` (EXPERIENCE: "Lowercase letters, numbers and hyphens (Admin L210). 3–63 characters `[ASSUMPTION]`").
  - It must not start or end with `-`, and must not have `--` at positions 3–4, so no `xn--` or other IDNA label is possible `[ASSUMPTION]`.
  - The whole host must be at most 253 characters.
  - It must not be in `ReservedSubdomains`.
- **`ReservedSubdomains` (Tenancy contract, code-owned, AD-6) `[ASSUMPTION]`:** `account`, `accounts`, `admin`, `api`, `app`, `apps`, `assets`, `auth`, `autoconfig`, `autodiscover`, `billing`, `cdn`, `connect`, `console`, `dashboard`, `dns`, `docs`, `email`, `ftp`, `gatekeep`, `health`, `help`, `id`, `identity`, `imap`, `internal`, `isatap`, `localhost`, `login`, `logout`, `mail`, `mta-sts`, `mx`, `ns`, `ns1`, `ns2`, `oauth`, `oidc`, `openpgpkey`, `pop`, `pop3`, `root`, `sftp`, `smtp`, `sso`, `static`, `status`, `support`, `system`, `vpn`, `webmail`, `wpad`, `www`. Any of these is refused exactly like a taken one. `id`, being two characters, is already refused by the length rule; it is listed so the list stands alone.
- **Tenant name and label (Tenancy contract):**
  - The name is trimmed, then must be 1–100 characters `[ASSUMPTION]`, with no control character (Unicode `Cc`). It is the Admin-facing name. FR-10's display name stays in `tenant_settings`, owned by its own story.
  - The label is one of `dev`, `staging`, `prod` in JSON and the database. `TenantLabel` is an enum.
- **Schema (new migration `Migration20261104020000CreateTenants`; registry entries in the same migration):**
  - `tenant` gains:

    | Column | Type and rule |
    | --- | --- |
    | `name` | `text NOT NULL`, `CHECK (char_length(name) BETWEEN 1 AND 100)` |
    | `label` | `text NOT NULL CHECK (label IN ('dev', 'staging', 'prod'))` |
    | `status` | `text NOT NULL CHECK (status IN ('creating', 'active'))`. Story 1.29 adds `deleted` |
    | `issuer` | `text NOT NULL UNIQUE` |
    | `rp_id` | `text NOT NULL UNIQUE` |
    | `email_link_base` | `text NOT NULL` |

    - The columns are added `NOT NULL` with no default. No production Deployment can hold a Tenant before this story, so a database that has one fails the migration loudly rather than storing a made-up issuer.
    - `created_at` becomes `DEFAULT clock_timestamp()`.
  - **Triggers:**
    - `tenant_guard_update` refuses a change to `id`, `issuer`, `rp_id`, `email_link_base` or `created_at`, and any `status` change other than `creating` → `active`.
    - `tenant_host_guard` refuses every `UPDATE` and `DELETE` on `tenant_host`, for every role, the migrator included. Both functions are `REVOKE EXECUTE … FROM PUBLIC`, as `operation_step_guard_insert` is.
  - **Grants:**

    | Table | Change |
    | --- | --- |
    | `tenant` | `gk_worker` gains `UPDATE (status)`. `gk_admin` keeps `SELECT, INSERT` and gets no `UPDATE` |
    | `tenant_host` | unchanged (`gk_hosted`, `gk_worker` `SELECT`; `gk_admin` `SELECT, INSERT`). Nobody gets `UPDATE` or `DELETE` |
    | `tenant_settings` | `gk_worker` gains `INSERT` |
    | `tenant_role` | `gk_admin` gains `INSERT`. Story 8.4 adds `UPDATE (role)` and `DELETE` |
  - `TableRegistry` records each grant and trigger: the `tenant` column grant, and `Triggers` for `tenant` and `tenant_host`.
- **Tenancy contract (`ITenants`, `TenancyContract.CreateTenants()`; adapter SQL in Tenancy only, AD-1 and AD-27):**
  - `InsertAsync(CommandContext, TenantDraft)` inserts `tenant` (`creating`) and `tenant_host` (`kind = 'subdomain'`), in a Deployment context, under a savepoint. A unique violation on `tenant_host_pkey` returns `SubdomainTaken`, leaving nothing of this Tenant. Any other unique violation, on `issuer` or `rp_id`, is the same outcome.
  - `ListAsync(CommandContext, after, limit)` returns Tenants with their `subdomain`-kind host, ordered by `id` (UUIDv7, so by creation).
  - `ActivateAsync(CommandContext, tenantId)`, in that Tenant's own context:
    - `INSERT INTO tenant_settings (tenant_id) … ON CONFLICT DO NOTHING`;
    - `UPDATE tenant SET status = 'active' WHERE id = @id AND status = 'creating'`;
    - appends `tenancy.tenant.activated` only when that update changed the row.
- **Tenant resolution (Tenancy adapter, `TenancyAdapters.UseTenantResolution`, Host.Hosted only):**
  - It is the first middleware on the public port, before routing. The private health port keeps its own branch.
  - The key is `context.Request.Host.Host`, lower-cased with the invariant culture: no port, no trailing-dot removal, no other normalization.
  - It runs `SELECT t.id, t.issuer, t.rp_id, t.email_link_base FROM tenant_host h JOIN tenant t ON t.id = h.tenant_id WHERE h.host = @host AND t.status = 'active'` as `gk_hosted`, with no transaction, scope or cache `[ASSUMPTION: no cache in v1]`.
  - No row is the fixed 404. A lookup failure is a fixed bodiless 503. Neither depends on the host or path.
  - A row sets `ResolvedTenant(TenantId, Issuer, RpId, EmailLinkBase)` as a request feature. It is the only Tenant source on Host.Hosted (AD-4).
  - `X-Forwarded-Host`, `Forwarded`, `X-Original-Host` and the absolute-form request target are never read. Host.Hosted keeps calling no `UseForwardedHeaders` for the host.
  - A resolved request with no endpoint gets the same fixed 404 from the fallback, so a known and an unknown host look alike.
  - The fixed 404 is the response Host.Hosted gives today: status 404, the same headers and an empty body. `TenantHostBeforeBootstrapTests` still passes unchanged.
- **Keys contract (`KeysContract.SecretClassKeys`):** `CreateSecretClassKeysAsync(IKeyCustody, Guid tenantId, CancellationToken)` creates `KeyName.ForTenant(c, tenantId)` for every `TenantKeyClass`, in enum order. No row is written (AD-10). The six names are the only keys it ever creates.
- **Operations:**
  - **Custody for stage handlers:** `OperationStepRun` gains `Custody` (`IKeyCustody?`), passed from `JobRunServices`, which gains it from the runner's custody. It is null when the Worker has no custody configured.
  - **Completion handler:** `OperationDefinition` gains an optional `OnSucceeded` (`OperationCompletionHandler(OperationCompletion, CancellationToken)`, with `OperationId`, `TenantId` and `Context`).
    - `OperationStore.TryFinishAsync`'s `UPDATE` returns the new status. When it is `succeeded` and the definition has a handler, the handler runs in that same transaction, so activation commits with success or neither does.
    - It runs only for a Tenant-scoped Operation, in a context scoped to that Tenant. Otherwise it throws `InvalidOperationException` and the finish rolls back.
    - For `tenancy.tenant.create` every stage is a Tenant stage, so the finisher is always the last step job, in that Tenant's own scope. The run job's own finish never wins, because its steps are already `running` once dispatched.
  - **`tenancy.tenant.create`** (production registry):
    - One Tenant stage `keys.secret_classes`. Null custody is `Failure(custody_unavailable)`, and a `KeyCustodyException` is the same code. Nothing from the exception is kept.
    - `OnSucceeded` calls `ITenants.ActivateAsync`.
    - The Operation is scoped to the new Tenant, so the one-active index allows one creation per Tenant.
  - **`IOperations.FindActiveAsync(context, type, tenantId)`**: the `running` or `failed` Operation of that type and scope, or null, for the Tenants list.
  - **Dead jobs** (taken in from Story 1.9). In `JobRunner.FinishAsync`, when a job goes `dead`, in the same transaction and before the payload is erased:
    - a dead `operations.operation.run` job marks every `pending` or `running` step of its Operation `failed` with `job_dead`;
    - a dead `operations.operation.step` job marks its own step (from its payload's `operation_id` and `step_id`, matched against its Tenant) the same way;
    - then `TryFinishAsync` runs, so the Operation becomes `failed` and Retry applies.

    No new grant is needed: it runs as `gk_worker`.
- **Admins contract:** `IAdminTenantRoles.GrantCreatorOwnerAsync(CommandContext, Guid adminId, Guid tenantId)` inserts `(tenant_id, admin_id, 'owner')` in a Deployment context. It is the only `tenant_role` writer in this story, and it isn't a capability of its own. FR-7 makes the creator Owner as part of `deployment.tenants.create`, so it isn't `deployment.admins.manage`, which needs a fresh assertion and grants roles to others.
- **Management contract (`ITenantManagement`, `ManagementContract.CreateTenants(appender, TenantAddressing)`)**, the one place that orchestrates Tenancy, Admins and Operations for Host.Admin (AD-1 edges):
  - `CreateAsync(CommandContext, AdminPrincipal, CreateTenantInput)`, in the Deployment context the handler opened:
    1. Re-checks `AdminCapabilities.Allows(DeploymentTenantsCreate, principal, null, null)`, because authorization runs in the handler too (AD-5).
    2. Validates name and label (`TenantInvalid`), then the subdomain (`SubdomainRefused`).
    3. Generates the Tenant's UUIDv7, then calls `ITenants.InsertAsync` (`SubdomainTaken` → `SubdomainRefused`), `GrantCreatorOwnerAsync` and `IOperations.StartAsync(tenancy.tenant.create, tenantId, [keys.secret_classes for tenantId])`.
    4. Appends `tenancy.tenant.created` on the Deployment chain: Actor the Admin, target the Tenant.
    5. Returns `Created(tenant, operation)`.
  - `ListAsync`, `GetOperationAsync(context, tenantId, operationId)` (`GetForTenantAsync` only) and `RetryCreationAsync(context, operationId)`, which retries only a `failed` `tenancy.tenant.create`. Another type, or no such Operation, is `NotFound`. One not `failed` is `NotFailed`. A retry appends `operations.operation.retried`.
- **Host.Admin settings:**
  - `Gatekeep:TenantZone` is required: lower-case LDH labels separated by dots, at least two labels, at most 200 characters `[ASSUMPTION]`.
  - `Gatekeep:TenantHttpsPort` is optional, 1–65535, default 443.
  - Both are refused at startup through `AdminApiServices.RefusedSettings`, by name only. A `PublicOrigin` host equal to the zone, or under it, is refused too (AD-6: "The Admin hostname sits outside the zone").
  - `deploy/compose.yaml`'s `admin` service sets `Gatekeep__TenantZone: ${GATEKEEP_TENANT_ZONE:-gatekeep.localhost}` and `Gatekeep__TenantHttpsPort: ${GATEKEEP_HTTPS_PORT:-443}`. The OpenAPI document build needs neither.
- **Routes after this story:**

  | Route | Access | Answers |
  | --- | --- | --- |
  | `GET /api/v1/deployment/tenants` | `deployment.tenants.read` | 200 `TenantListResponse` |
  | `POST /api/v1/deployment/tenants` | `deployment.tenants.create` | 202 `TenantCreatedResponse` with `Location`; 400 `tenant_invalid`; 400 `subdomain_refused` |
  | `POST /api/v1/deployment/operations/{operationId}/retry` | `deployment.tenants.create` | 202 `OperationResponse`; 409 `operation_not_failed`; unknown-path 404 |
  | `GET /api/v1/tenants/{tenantId}/operations/{operationId}` | `tenant.configuration.read` | 200 `OperationResponse`; unknown-path 404 |
  | Every existing route | unchanged | |

  - No route declares a fresh-assertion capability.
  - No Deployment route has `{tenantId}`: the Story 1.24 rule stands, so retry names the Operation, not the Tenant.
  - No `PUT`, `PATCH` or `DELETE` is mapped under `/api/v1/deployment/tenants`. Each is the unknown-path 404.
- **Shapes (camelCase, RFC 3339 times; `Cache-Control: no-store` on all four):**
  - **`CreateTenantRequest`:** `{ name: string, subdomain: string, label: "dev" | "staging" | "prod" }`.
    - The body is at most 4096 bytes, through `AdminApi.ReadJsonAsync`.
    - A body that isn't JSON, misses a field, or has the wrong type is 400 `tenant_invalid`.
    - An unknown extra property is ignored.
  - **`TenantResponse`:**
    - `id` is `ten_…`. `name`, `host` and `label` are the stored values. `status` is `creating` or `active`. `createdAt`.
    - `creation` is `{ operationId: "opr_…", status: "running" | "failed" }` while the Tenant is `creating`, else null.
    - There is no `subdomain` field: the host is shown as stored, and no code splits it (AD-6).
  - **`TenantListResponse`:** `{ tenantZone, tenants: TenantResponse[], nextCursor: string | null }`. Cursor pagination, 50 per page (Conventions). The cursor is the last row's `ten_` ID, and a malformed cursor is 400 `tenant_invalid`.
  - **`TenantCreatedResponse`:** `{ tenant: TenantResponse, operation: OperationResponse }`. `Location` is the Tenant-path Operation URL.
  - **`OperationResponse`:**
    - `{ id: "opr_…", type, tenantId: "ten_…" | null, status: "running" | "failed" | "succeeded", createdAt, updatedAt, finishedAt, steps: [{ stage, tenantId, status, resultCode, attempts, updatedAt }] }`.
    - It holds codes and IDs only (AD-30), and never a step's row ID.
  - **`PublicIdType.Operation`:** prefix `opr_` `[ASSUMPTION]`. A malformed `operationId` is the unknown-path 404, like an unknown one.
- **Refusals:**
  - `subdomain_refused` (400) for a malformed, reserved or taken subdomain, including a concurrent creation that loses the race. Its body never says which.
  - `tenant_invalid` (400) for the body, the name, the label and the cursor.
  - `operation_not_failed` (409).
  - A non-Owner is 403 `access_denied`, audited as in Story 1.24. A setup or recovery Session gets the bodiless 403 first.
  - Each is logged under `{Problem}` with fixed names. The subdomain and name are never logged.
- **Audit events (Deployment chain unless stated; none holds the Tenant's name):**
  - `tenancy.tenant.created` (new `TenancyEvents`): "A Deployment Owner created a Tenant and became its Tenant Owner, and its creation Operation started. Names the Tenant and its label." Actor the Admin; target the Tenant.
  - `tenancy.tenant.activated` (`TenancyEvents`, on the new Tenant's own chain, Actor `system`): "A Tenant's creation Operation succeeded: its settings exist and its Tenant Subdomain now resolves."
  - `operations.operation.retried` (`OperationsEvents`): "An Admin retried a failed Operation's failed steps. Names the Operation only." Actor the Admin.
  - `docs/audit-events.md` is regenerated with `dotnet run --project tests/Architecture/Generator`, in Docker. FR-40 class: none.
- **Module edges (`tests/Architecture/module-edges.txt`):**
  - Add `dependency Tests.Isolation -> Tenancy`, `-> Keys` and `-> Management`.
  - Tenancy gains the `Npgsql` package, for its adapter's SQL.
  - Regenerate `docs/architecture/module-dependencies.md` with the Generator.
- **Dashboard (no new runtime dependency; nothing inline; every string in `messages.tsx`):**
  - **API client (`packages/api-client/src/client.ts`):** `listTenants(cursor?)`, `createTenant(body)`, `getTenantOperation(tenantId, operationId)` and `retryOperation(operationId)`, each from the regenerated schema.
  - **Sidebar (`shell/nav.ts`):** one Deployment item, `{ group: 'deployment', label: 'navTenants' ("Tenants"), href: '/deployment/tenants', requires: 'deployment.tenants.read' }`. Update the registry comment. Only an Admin holding that capability, the Deployment Owner, sees the Deployment group.
  - **Routes in `Shell.tsx`:**

    | Path | Shows |
    | --- | --- |
    | `/deployment/tenants` | `TenantsPage` |
    | `/deployment/tenants/new` | `CreateTenantPage` |
    | `/` | `LandingPage`, as below |

    - A page whose capability isn't held shows `ForbiddenPage` without asking the server, because the shell's Deployment read already answered.
    - Nothing on these pages decides access: every write is decided by the server.
  - **Landing (`LandingPage.tsx`, interim until Stories 1.28 and 3.1):**
    - With `deployment.tenants.read`, it reads the first page of Tenants through `shellRequest('get', …)`, with `SkeletonRows` after 300ms.
    - No Tenants renders `CreateTenantPage` in place, as the landing (FR-44).
    - Any Tenant replaces the URL with `/deployment/tenants`.
    - A failed read shows the shell's load-failed banner with Retry.
    - Without the capability, the holding message is unchanged ("You don't have access to a Tenant yet. Ask a Deployment Owner.").
    - The `landingNoTenants` key is removed.
  - **Create Tenant (`shell/CreateTenantPage.tsx`, Spec only, composed from `wiz.s0` L208 without Region; UX-DR46: existing components only):**
    - **Heading:** `SectionPage` with title "Create your Tenant" and description "A Tenant is an isolated directory of Users, Applications and settings." These are `wtitles[0]` with PRD §3 terms `[ASSUMPTION]`.
    - **Name field:** `Field` "Name" `[ASSUMPTION]` with `Input` `autocomplete="off"` and `maxLength` 100, so the limit can't be passed by typing. Empty after trimming: "Enter a name." `[ASSUMPTION]`.
    - **Tenant Subdomain field:** `Field` "Tenant Subdomain" with `Input` in code type, `autocapitalize="none"`, `autocorrect="off"`, `spellcheck="false"` and `autocomplete="off"`, and a visible suffix `.{tenantZone}` from the list response.
      - Helper: "Lowercase letters, numbers and hyphens. Can't be changed later." This is the design's helper with "— use a custom domain for branding" removed, because custom domains are v2 (FR-44, AD-7).
      - Under the input, the full host is shown as typed, in code type.
      - Client-side rule failure: "Lowercase letters, numbers and hyphens." (EXPERIENCE), checked by `shell/tenantSubdomain.ts`, the same rule without the reserved list.
      - A server `subdomain_refused`: "This subdomain can't be used. Choose another." `[ASSUMPTION]`, inline under the field, with focus moved there. It never says taken or reserved.
    - **Environment field:** `RadioGroup` legend "Environment", in the design's order:

      | Option | Tag | Tone |
      | --- | --- | --- |
      | "Development" | `DEV` | `info` |
      | "Staging" | `STG` | `warn` |
      | "Production" | `PROD` | `bad` |

      Development is preselected, as drawn (`[ASSUMPTION]`, see Ask First). Tags are `Badge`s with the tones Story 1.28 names.
    - **Submit:** the primary button "Create Tenant" `[ASSUMPTION]`. There is no Cancel on the landing. On `/deployment/tenants/new` a secondary "Cancel" goes to Tenants.
    - **Pending (EXPERIENCE: Spinner):**
      - The button is pending and the form read-only.
      - A 202 keeps the form read-only and shows a `role="status"` line, "Creating {name}…" `[ASSUMPTION]`.
      - It polls `getTenantOperation` through `shellRequest('get', …)` every 1000ms `[ASSUMPTION]` until the status isn't `running`, and stops on unmount.
    - **Outcomes:**
      - `succeeded`: the `toast` "Tenant created." `[ASSUMPTION]`, then `/deployment/tenants`. Not the Applications list: see Ask First.
      - `failed`: a `bad` `Banner` "We couldn't finish creating this Tenant." `[ASSUMPTION]` with `ErrorReference` (the failed step's result code) and the action "Retry" (existing `retry`). Retry posts `retryOperation`, then polls again. A 409 re-reads the Operation.
      - 400 `tenant_invalid`, 5xx or a lost connection: the Save failed state, a `bad` `Banner` above the form with values kept, "Couldn't create the Tenant. Try again." `[ASSUMPTION]`, with `ErrorReference`.
      - 403 `access_denied` or the bodiless 403: the existing `actionForbidden` banner.
    - **Renewal (Story 1.25's rule):** a 401 on the POST leaves the page mounted with every value, focus and node. It is never resent, and the Admin presses Create Tenant again after renewing.
  - **Tenants (`shell/TenantsPage.tsx`, Spec only):**
    - `SectionPage` with eyebrow "Deployment", title "Tenants" and the primary action "Create Tenant" (only with `deployment.tenants.create`) to `/deployment/tenants/new`.
    - `DataTable` with columns "Name", "Tenant Subdomain" (the host, code type), "Environment" (the tag `Badge`) and "Created" (absolute, local) `[ASSUMPTION]`.
    - A `creating` row adds a `neutral` `Badge` "Creating" `[ASSUMPTION]`. A failed creation adds a `bad` `Badge` "Creation failed" `[ASSUMPTION]` and a secondary "Retry" button named "Retry creating {name}" for the accessible name.
    - Rows are not links: no Tenant page exists yet (FR-44: "Deferred features don't appear as … links"). EXPERIENCE's "Row opens the Tenant" arrives with Story 3.1 or 1.28.
    - "Load more" follows `nextCursor`.
    - Empty: `EmptyState` "No Tenants yet." `[ASSUMPTION]` with the one action "Create Tenant" (moving `landingNoTenants`'s text to `tenantsEmpty`).
- **CSP (AD-21):** nothing inline, no `data:` or `blob:` URI, and no CSP change. Every new browser test uses `watchCsp`.
- **Tests:**
  - **Isolation tests:** Testcontainers PostgreSQL. The real `Host.Admin` goes through `AdminHost`, with the new settings. The real `Host.Hosted` goes through `HostProcess`, plus an in-process `TestServer` running the real resolution middleware with a test-only probe endpoint. The Worker runner is driven in-process as Story 1.9's Operation tests do.
  - **Custody:** key creation runs against the real OpenBao Testcontainer under the `host-worker` policy, and proves `host-admin` is refused (Story 1.7's `PolicyMatrixTests` style).
  - **Fixtures:** a shared test helper `TestTenants.InsertAsync(connection, id, host?)` writes a valid `tenant` row (and optionally `tenant_host`). It replaces every bare `INSERT INTO tenant (id)` in the Isolation tests.
  - **Browser tests:** Playwright against the built Host.Admin (`admin-host.mjs`), with the API intercepted, a Chromium virtual authenticator for the renewal, axe and `watchCsp`.
- **Docs:**
  - **`docs/threat-model.md`:**
    - The header's "exists in code" list adds Story 1.27.
    - TB-1: "Built in Story 1.27: the exact `tenant_host` match and the fixed 404", with test names.
    - T-1: the Tenant-path Operation read and the creator-only role.
    - T-2: built, with test names.
    - T-46: the first production Operation type, and dead jobs now fail their steps.
    - A new T-55: "A Tenant Subdomain collides with infrastructure, is reused, or changes after creation". Its controls are the code-owned reserved list, the never-deleted `tenant_host` with its trigger, the immutable issuer, RP ID and link base columns, and the single create route. What remains: the reserved-versus-taken refusal differs in timing, visible only to the Deployment Owner, who can list every Tenant anyway, and the list can't anticipate every name a Deployment's own DNS might use.
  - `docs/audit-events.md` and `docs/architecture/module-dependencies.md`, regenerated.
  - `docs/install.md`: the `admin` service now reads the Tenant zone and HTTPS port. The "Not yet covered" list now says the dashboard creates and lists Tenants.
  - `deferred-work.md`, as described below.

**Ask First:**
- **After creation the dashboard opens Tenants, not the Applications list.** EXPERIENCE says Create Tenant's success is "Applications list, empty", and FR-44 that Admins with Tenants land there. That page is Story 3.1's. Until then `/` with any Tenant, and every successful creation, opens Tenants. Story 1.28 or 3.1 changes both. Confirm before changing.
- **The Tenant's name lives on `tenant` (`control`), not in `tenant_settings`.** The Tenants list and Story 1.28's switcher list names across Tenants, which a `tenant` table can't serve without one scope per Tenant (AD-4). FR-10's display name stays a separate `tenant_settings` value. Confirm before moving it.
- **Development is preselected**, as `wiz.s0` draws it. The alternative is no default, which forces a conscious choice before a Prod Tenant is created as Dev. Raising a label later is free, and only removing Prod is guarded (FR-7). Confirm before changing.
- **A `creating` Tenant doesn't resolve on Host.Hosted.** Its host gets the fixed 404 until the creation Operation succeeds, so no Hosted route ever sees a Tenant without its keys and settings. AD-6 names only unknown and deleted hosts. Confirm before relaxing.
- **A completion handler on Operations**, rather than ordered stages (still deferred to Story 1.29's purge-then-remove). Confirm before replacing it with stage ordering.
- **The values marked `[ASSUMPTION]`:** the reserved list, 3–63 characters with no IDNA labels, a name of 1–100, `opr_`, the 1-second poll, the issuer's `https://{host}/` form, and the copy.
- **Any change to the OpenBao policies.** None is needed: `host-worker` already creates `{class}-*` keys, and `host-admin` can't.

**Never:**
- No code parses a subdomain out of a host (AD-6). Host.Hosted matches the whole host, and responses carry the stored host.
- No issuer, RP ID or email link base taken from a request, a header or configuration after creation. They are stored once and only read.
- No Tenant from a forwarded header, cookie, session or claim on Host.Hosted. `ResolvedTenant` is the only source.
- No `UPDATE` or `DELETE` of a `tenant_host` row by any role or route, and no reuse of a host, ever.
- No route other than `POST /api/v1/deployment/tenants` accepts a subdomain.
- No refusal says whether a subdomain was taken or reserved, in the body, the code or the copy.
- No client-side authorization. The sidebar and the Create Tenant button follow the server's capability list, and the server decides every request.
- No Tenant name, subdomain or host in a log line. No placeholder named `{Code}`.
- No inline style or script, no CSP change, and no new runtime dependency in `apps/admin-dashboard` or `packages/ui`.
- No Region, custom domain or "promote" copy anywhere (FR-44, AD-7).
- **Out of scope**, recorded in `deferred-work.md`:
  - Signing and Management keys as a creation stage (Story 2.3, which also backfills).
  - The built-in API record and the default Connection as creation stages (their stories).
  - The Tenant switcher, the Tenant name and environment badge in the top bar, label changes, and the final landing rules (Story 1.28).
  - The Tenant-surface fresh-assertion begin, moved to Story 1.28.
  - Tenant deletion, its purge contracts, and a `deleted` status that resolves to the same 404 (Story 1.29). `tenant_host` and `tenant` rows are never deleted, so it must soft-delete.
  - A Tenant page that a Tenants row opens (Story 3.1 or 1.28).
  - Ordered Operation stages (carried on, Story 1.29).
  - Restricting Operation and step status transitions (T-46, carried on).
  - A per-Admin limit on Tenant creation `[ASSUMPTION]`: each creation makes six Transit keys.
  - A host-resolution cache (AD-14, if a measured need appears).
  - The Tenant name's bidi isolation (Story 18.3, carried on).
  - Catching `ARCHITECTURE-SPINE.md` up: AD-27's `tenant` columns, the completion handler in AD-30, the `opr_` prefix in Conventions, and the creating status in AD-6.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Create | Owner, full Session, CSRF; `{name:"Acme Dev", subdomain:"acme-dev", label:"dev"}`, zone `gatekeep.test`, port 443 | 202, `Location` to `/api/v1/tenants/ten_…/operations/opr_…`, `no-store`. Rows: `tenant` (`creating`, issuer `https://acme-dev.gatekeep.test/`, rp_id `acme-dev.gatekeep.test`, email_link_base = issuer), `tenant_host` (`subdomain`), `tenant_role` owner for the creator, `operation` running with one `keys.secret_classes` step, one run job. `tenancy.tenant.created` on the Deployment chain. | — |
| Port in issuer | Same with `TenantHttpsPort` 8443 | issuer `https://acme-dev.gatekeep.test:8443/`, rp_id without the port | — |
| Operation runs | The Worker runs the jobs | Six Transit keys `totp-`, `social-`, `email-`, `payload-`, `hmac-` and `tpk-{tenantId}` exist. Step `succeeded`. Operation `succeeded`. `tenant_settings` row exists. `tenant.status = active`. `tenancy.tenant.activated` on the Tenant's chain. | — |
| Step rerun | The step job runs twice (crash after key creation) | Same six keys, unchanged versions. One settings row, one activation event. | — |
| Completion once | The run job's finish and the last step's finish race | Exactly one `succeeded` transition, one activation, one event | — |
| Custody down | OpenBao unavailable, or Worker without custody | Step `failed` `custody_unavailable`. Operation `failed`. Tenant stays `creating`. No settings row. | — |
| Retry | Owner; `POST /deployment/operations/opr_…/retry` on that failed creation | 202 `OperationResponse` `running`. Only the failed step runs again. `operations.operation.retried`. Success then activates as above. | — |
| Retry not failed | Same on a running or succeeded creation | 409 `operation_not_failed` | — |
| Retry other type | `opr_` of an `audit.chain.purge` Operation, or unknown or malformed | Unknown-path 404 | — |
| Dead run job | `operations.operation.run` exhausts its attempts | Its open steps `failed` `job_dead`, Operation `failed`, `operations.job.dead`; Retry works | — |
| Dead step job | `operations.operation.step` exhausts its attempts | That step `failed` `job_dead`, Operation `failed` | — |
| Malformed subdomain | `"Acme"`, `"ab"`, `"-acme"`, `"acme-"`, `"xn--acme"`, `"ac--me"`, `"a_b"`, `" acme"`, 64 characters | 400 `subdomain_refused`, nothing written, nothing audited | — |
| Reserved subdomain | `"admin"`, `"www"`, `"mta-sts"` | 400 `subdomain_refused`, byte-identical body shape to taken | — |
| Taken subdomain | A second create with `acme-dev` | 400 `subdomain_refused`. No second `tenant` row, no role, no Operation. | — |
| Creation race | Two creates with the same new subdomain at once | One 202, one 400 `subdomain_refused`, one Tenant | — |
| Invalid name or label | `name:"   "`, a 101-character name, `name` with U+0007, `label:"production"`, a non-JSON body, a body over 4096 bytes | 400 `tenant_invalid`, nothing written | — |
| Non-Owner | Full Session of an Admin who isn't the Deployment Owner; `POST` or `GET /deployment/tenants` | 403 `access_denied`, `admin.access.denied` within the cap, nothing written | — |
| Restricted Session | Setup or recovery Session on any of the four routes | Bodiless 403 | — |
| No Session or bad CSRF | Missing cookie; wrong CSRF or Origin on the POSTs | 401; bodiless 403 | — |
| Subdomain never changes | `PUT`, `PATCH` or `DELETE /api/v1/deployment/tenants/ten_…`, `/api/v1/tenants/ten_…`, `…/host`, with a `subdomain` body | Unknown-path 404 for each | — |
| Subdomain in the database | `gk_admin`, `gk_worker` or `gk_hosted` `UPDATE` or `DELETE` on `tenant_host`; the migrator likewise | Permission denied for the roles; the trigger raises for the migrator | DB error |
| Issuer in the database | `gk_worker` `UPDATE tenant SET issuer = …`; the migrator changes `rp_id`, or sets `status` back to `creating` | Permission denied; the trigger raises | DB error |
| Owner role | After a create | `GET /api/v1/tenants/ten_…/capabilities` lists every Tenant capability for the creator. Another Admin gets 403 `access_denied`. | — |
| Operation via Tenant path | Creator; `GET /api/v1/tenants/ten_A/operations/opr_A` | 200, the Operation with only Tenant A's steps, no step row IDs | — |
| Operation from another Tenant | `GET /api/v1/tenants/ten_B/operations/opr_A`, where the Admin is Owner of both | Unknown-path 404, byte-identical to an unknown `opr_` and a malformed one | — |
| List | Owner with three Tenants; `limit` by cursor | 200 `{tenantZone, tenants, nextCursor}`, ordered by creation; `creation` set only on the creating one; hosts as stored | — |
| Unknown host | Host.Hosted, `Host: nobody.gatekeep.test`, any path or method | The fixed 404, byte-identical to Story 1.21's snapshot | — |
| Creating host | Host.Hosted, `Host: acme-dev.gatekeep.test` while `creating` | The same fixed 404 | — |
| Active host | Same after activation, on the probe server | The probe runs with `ResolvedTenant` = the stored ID, issuer, RP ID and link base. On the real process (no route), the same fixed 404. | — |
| Host case and port | `Host: ACME-DEV.gatekeep.test:8443` | Resolves as `acme-dev.gatekeep.test` | — |
| Forged host | `Host: evil.example` with `X-Forwarded-Host`, `Forwarded: host=` or `X-Original-Host` naming an active host; an absolute-form target naming it | Fixed 404, the probe never runs | — |
| Trailing dot | `Host: acme-dev.gatekeep.test.` | Fixed 404 | — |
| Lookup failure | Database unreachable | Fixed bodiless 503, the same for every host | 503 |
| Canary | A canary used as a Tenant name | Absent from operational logs | Test fails |
| Landing, no Tenants (browser) | Owner, list empty | The Create Tenant form at `/`: Name, Tenant Subdomain with `.gatekeep.test`, Environment with Development, Staging, Production; no Region field or text | — |
| Landing with Tenants (browser) | Owner, list of one | URL becomes `/deployment/tenants` | — |
| Landing, non-Owner (browser) | No Deployment capability | "You don't have access to a Tenant yet. Ask a Deployment Owner." No Deployment group in the sidebar | — |
| Sidebar (browser) | Owner | Deployment group with "Tenants", current on `/deployment/tenants` | — |
| Inline rule (browser) | `Acme`, then submit | "Lowercase letters, numbers and hyphens." under the field; no request sent; focus on the field | — |
| Server refusal (browser) | POST 400 `subdomain_refused` | "This subdomain can't be used. Choose another." under the field, values kept | — |
| Progress and success (browser) | 202, then the Operation `running`, then `succeeded` | "Creating Acme Dev…" in a status region, then the toast "Tenant created." and Tenants | — |
| Failure and Retry (browser) | Operation `failed` `custody_unavailable`; Retry 202; then `succeeded` | The banner with the code, Retry, then success | — |
| Save failed (browser) | POST 503; lost connection | The banner above the form, values kept, the form editable | — |
| Renewal keeps values (browser) | Fill all three fields, focus Name; POST answers 401; sign in again with the virtual authenticator | The Session banner, then live. The same input nodes, values and focused element. Exactly one POST so far. Pressing Create Tenant sends the second, which answers 202. | — |
| Tenants page (browser) | List with active, creating and failed rows | Tags `DEV`/`STG`/`PROD` in `info`/`warn`/`bad`; "Creating" and "Creation failed" badges; "Retry creating {name}" only on the failed row; rows aren't links; "Create Tenant" | — |
| CSP | Every new and changed test | No `securitypolicyviolation`, no console CSP message, no other-origin request | Test fails |
| axe | Create Tenant (initial, inline errors, pending, progress, failed), Tenants (list, empty); light and dark; 1100 and 768 | No violations | Test fails |

</intent-contract>

## Code Map

- `src/Gatekeep.Kernel/Identifiers/PublicId.cs`: `PublicIdType.Operation` (`opr_`).
- `src/Adapters/Postgres/`:
  - new `Migrations/Migration20261104020000CreateTenants.cs`: the `tenant` columns, `tenant_guard_update`, `tenant_host_guard` and the grants;
  - `Schema/TableRegistry.cs`: the `tenant`, `tenant_settings` and `tenant_role` grants, and the triggers.
- `src/Modules/Tenancy/`:
  - `Contracts/`: replace the placeholder with `TenancyContract.cs` (factories), `ITenants.cs`, `TenantAddress.cs`, `TenantSubdomain.cs` (with `ReservedSubdomains`), `TenantLabel` and the name rule, `ResolvedTenant.cs`, and `TenancyEvents.cs`;
  - `Core/`: `Tenants.cs`;
  - `Adapters/`: `TenancyAdapters.cs` (`UseTenantResolution`, the fixed 404 and 503);
  - the csproj gains `Npgsql`.
- `src/Modules/Keys/Contracts/KeysContract.cs`: `SecretClassKeys` and `CreateSecretClassKeysAsync`.
- `src/Modules/Admins/`:
  - new `Contracts/IAdminTenantRoles.cs`;
  - `Core/AdminTenantRoles.cs`;
  - `Contracts/AdminsContract.cs`: the factory.
- `src/Modules/Operations/`:
  - `Contracts/OperationRegistry.cs`: `OnSucceeded`, `OperationCompletion`, `OperationCompletionHandler` and `OperationStepRun.Custody`;
  - `Contracts/IOperations.cs`: `FindActiveAsync`;
  - `Contracts/OperationsEvents.cs`: `operations.operation.retried`;
  - `Core/OperationStore.cs`: the finish returns its status and runs the handler;
  - `Core/OperationJobs.cs`, `Core/JobRunner.cs` (dead jobs fail their steps, custody into `JobRunServices`);
  - `Core/OperationService.cs` (`FindActiveAsync`);
  - new `Core/TenantCreation.cs` (the type, its stage and its completion);
  - `ProductionOperations` in `Core/OperationStore.cs`: register it.
- `src/Modules/Management/`:
  - `Contracts/ManagementContract.cs` and new `Contracts/ITenantManagement.cs` (inputs, outcomes, `TenantAddressing`);
  - new `Core/TenantManagement.cs`.
- `src/Gatekeep.Host.Admin/`:
  - new `TenantsApi.cs` (create, list, retry, Tenant-path Operation read, the response types);
  - `AdminApi.cs`: the four routes and their OpenAPI text;
  - `AdminApiServices.cs`: `Tenants`, the zone and port settings and their refusals;
  - `AdminResponses.cs`: `tenant_invalid`, `subdomain_refused` and `operation_not_failed`.
- `src/Gatekeep.Host.Hosted/Program.cs`: `UseTenantResolution()` first, then the fixed-404 fallback.
- `deploy/compose.yaml`: the `admin` service's two settings.
- `docs/api/openapi-v1.json` and `packages/api-client/src/schema.generated.ts`: regenerated with `sh deploy/docker/api-contract.sh --write <abs dir>`. `packages/api-client/src/client.ts`: the four calls.
- `packages/ui/src/messages.tsx`: the new keys (`navTenants`, the Create Tenant and Tenants copy, `tenantsEmpty`). `landingNoTenants` is removed.
- `apps/admin-dashboard/`:
  - `src/shell/nav.ts`: the item;
  - `src/shell/Shell.tsx`: the routes;
  - `src/shell/LandingPage.tsx`;
  - new `src/shell/CreateTenantPage.tsx`, `src/shell/TenantsPage.tsx` and `src/shell/tenantSubdomain.ts`;
  - new `test/tenantSubdomain.test.mjs`.
- `tests/Architecture/`:
  - `AdminApiRuleTests.cs`: `tenant_role` now `gk_admin INSERT, SELECT`; new rows for `tenant`, `tenant_host` and `tenant_settings` with their exact grants, including that nobody holds `UPDATE` or `DELETE` on `tenant_host`.
  - new `TenantRuleTests.cs`:
    - only `CreateTenantRequest` has a `subdomain` property, and only `POST /api/v1/deployment/tenants` takes it;
    - no `PUT`, `PATCH` or `DELETE` exists under `/api/v1/deployment/tenants`;
    - `Host.Hosted`'s `Program.cs` calls `UseTenantResolution` before any other middleware or map;
    - no `src/` file outside Tenancy reads `tenant_host`, and nothing reads `X-Forwarded-Host` or `Forwarded`;
    - `TenantAddress` is the only builder of an issuer;
    - each rule has a self-check that catches a violation.
  - `OperationRuleTests.cs`: a production type with `OnSucceeded` has only Tenant stages.
  - `module-edges.txt` and the generated diagram.
  - `AuditCatalogueTests.cs`, through the regenerated catalogue.
- `tests/Isolation/`:
  - new `Tenancy/TenantCreationTests.cs` (HTTP create, list, refusals, race, Owner role, non-Owner, Operation reads and retry);
  - new `Tenancy/TenantResolutionTests.cs` (the probe server and the real Host.Hosted);
  - new `Tenancy/TenantTablesTests.cs` (columns, grants, triggers);
  - new `Operations/TenantCreationOperationTests.cs` (stage, completion, idempotence, race, custody down, dead jobs);
  - `Custody/` (secret class keys under the real `host-worker` policy, and the `host-admin` refusal);
  - `Hosting/HostStartupTests.cs` (the zone and port refusals);
  - `Admins/AdminHost.cs` (the settings);
  - new `TestTenants.cs`, and the nineteen files that insert bare Tenants.
- `tests/browser/`:
  - new `admin-tenants.spec.ts`;
  - updated `admin-shell.spec.ts` (the sidebar is no longer empty for the Owner, and the landing);
  - `playwright.config.ts`: the project, in the default projects' `testIgnore`.
- Docs: `docs/threat-model.md`, `docs/audit-events.md` (generated), `docs/architecture/module-dependencies.md` (generated), `docs/install.md`, `_bmad-output/implementation-artifacts/deferred-work.md`.

## Tasks & Acceptance

**Execution:**
- [x] Kernel and schema:
  - `PublicIdType.Operation`;
  - the migration and registry;
  - `TestTenants` and the fixture updates;
  - `TenantTablesTests` covers the columns, the `NOT NULL` failure on a pre-existing row, both triggers for every role and the migrator, the grants, and that `gk_hosted` still has only `SELECT`.
- [x] Tenancy, Keys and Admins:
  - `TenantAddress`, `TenantSubdomain` with the reserved list, name and label rules, `ITenants` and `TenancyEvents`;
  - `CreateSecretClassKeysAsync`;
  - `IAdminTenantRoles`.
  - The subdomain rule's test vectors (the matrix's malformed, reserved and valid values) are the same in the Tenancy tests and `tenantSubdomain.test.mjs`, so client and server can't drift.
- [x] Operations:
  - `OperationStepRun.Custody` and `JobRunServices`;
  - `OnSucceeded` in the finish;
  - `FindActiveAsync`;
  - `tenancy.tenant.create`;
  - dead jobs fail their steps;
  - `operations.operation.retried`.
- [x] Management: `ITenantManagement` (create, list, Operation read, retry), with the AD-5 re-check.
- [x] Host.Admin:
  - the settings and refusals;
  - the four routes, problem codes and OpenAPI text;
  - `compose.yaml`.
  - Then regenerate the contract with `sh deploy/docker/api-contract.sh --write <abs dir>`.
- [x] Host.Hosted: `UseTenantResolution` first, the fixed 404 fallback, the fixed 503.
- [x] Architecture tests:
  - `TenantRuleTests` with self-checks;
  - the Admins registry rows;
  - the `OnSucceeded` rule;
  - the edges and diagram;
  - the catalogue, with `docs/audit-events.md` regenerated.
- [x] Isolation tests: every server row of the I/O matrix, with Testcontainers PostgreSQL and the real OpenBao container for custody, and the canary row.
- [x] Dashboard:
  - the API calls;
  - `nav.ts`;
  - the routes;
  - `LandingPage`;
  - `CreateTenantPage`, `TenantsPage` and `tenantSubdomain.ts` with its Node test;
  - the catalogue keys.
- [x] Browser tests: `admin-tenants.spec.ts` (every browser row, `watchCsp`, axe in light and dark at 1100 and 768), `admin-shell.spec.ts`, and the config.
- [x] Docs:
  - threat model (header, TB-1, T-1, T-2, T-46, new T-55);
  - `install.md`;
  - `deferred-work.md`: remove the five taken-in items (Story 1.24's two, and Story 1.25's three, counting both renewal twins); remove Story 1.9's dead-job item; narrow Story 1.26's two Tenant-surface begin items to Story 1.28; add the out-of-scope ones.

**Acceptance Criteria:**
- Given a Deployment Owner with no Tenants, when they land, then the create-Tenant form appears, with name, Tenant Subdomain and label and no Region.
- Given valid input, when they create a Tenant, then an Operation returns `202`, and creates the `tenant`, `tenant_host`, secret class keys and Tenant Owner role, with each step idempotent. The control rows and the Owner role commit with the Operation's start. The keys are its step, and the settings row and activation are its completion: each repeats safely.
- Given a taken, reserved or malformed subdomain, when it's submitted, then creation is refused with the same 400 `subdomain_refused` without saying whether it was taken or reserved, and nothing is written.
- Given a host not in `tenant_host`, when a request arrives at `Host.Hosted`, then it gets one fixed 404 before any Tenant code runs, and a forged `Host` header, or a forwarded host header, selects nothing. A Tenant still being created gets the same 404.
- Given a non-Deployment Owner, when they call the create endpoint, then the server refuses it with 403 `access_denied`, over HTTP.
- Given a created Tenant, when its rows are written, then the issuer, WebAuthn RP ID and email link base are stored on the Tenant, and a `tenant_settings` row exists once its creation succeeds.
- Given an existing Tenant, when any route tries to change its subdomain, then it is refused: no route accepts one, and the database refuses every update or delete of `tenant_host` and every change to the stored issuer, RP ID and link base.
- Given an Operation from another Tenant, when it is read through a Tenant path, then it is refused with the unknown-path 404.
- Given the Create Tenant form, when the Session renews during a submit, then every value, focus and node is kept, and the submit isn't resent.
- Given every new and changed browser test, when it runs, then no CSP violation occurs and axe finds no violation in light and dark at 1100 and 768px.

## Spec Change Log

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 27 findings — high 0, medium 10, low 17, false 0, maybe-false 0
- findings:
  - `[medium]` `[patch]` Blind: a dead run job fails Tenant steps that live step jobs still own, stranding the Tenant — only pending and Deployment steps are failed.
  - `[medium]` `[patch]` Blind: Host.Hosted runs one lookup per request with default timeouts and pool — short timeout and bounded pool; per-client limiting deferred to Epic 10.
  - `[medium]` `[patch]` Blind: the database guards only UPDATE and DELETE, so a bug could add a second host, insert an active Tenant or grant Owner anywhere — INSERT guards added.
  - `[medium]` `[patch]` Blind: any Worker path can activate a Tenant without settings — activation requires `tenant_settings`.
  - `[medium]` `[patch]` Blind: the Create form polls forever on 403/404/5xx and Retry fails silently — bounded, with banners.
  - `[medium]` `[patch]` Blind: no test makes the completion handler throw — added, including going dead and Retry.
  - `[low]` `[patch]` Blind: a throw during dead marking keeps the job from ever reaching dead — the job commits dead first.
  - `[low]` `[patch]` Blind: Retry locks the Operation before its steps, against the Worker's order — matched.
  - `[low]` `[patch]` Blind: the trigger docs overstate the guarantee — reworded; a test checks the triggers are enabled.
  - `[low]` `[patch]` Blind: Tenant names allow bidi and zero-width characters — refused, server and dashboard.
  - `[low]` `[patch]` Blind: the list sorts by ID, not creation time, and queries per row — ordered by creation, one query per page.
  - `[low]` `[patch]` Blind: an Admin host sharing a registrable domain with the Tenant zone is same-site — documented.
  - `[low]` `[patch]` Blind: Retry reports a programming error as 409 — a dedicated status.
  - `[medium]` `[patch]` Edge: a dead step job with a missing payload leaves its Operation stuck — falls back to the claim's Operation.
  - `[medium]` `[patch]` Edge: a completion handler on a Deployment-scoped start throws on every success — refused at start.
  - `[low]` `[patch]` Edge: the lazy data source caches a first-call exception forever — not cached.
  - `[low]` `[patch]` Edge: list paging can skip a Tenant under clock skew — same fix as the Blind row.
  - `[low]` `[patch]` Edge: the Operation read doesn't re-check access in the module — it does now.
  - `[low]` `[patch]` Edge: the dashboard accepts names the server refuses — same rule.
  - `[medium]` `[patch]` Gap: the landing's history replacement is untested — Back is checked.
  - `[medium]` `[patch]` Gap: completion-handler rollback is untested — same as the Blind row.
  - `[low]` `[defer]` Gap: the Create poll stopping on unmount is untested — a later dashboard story.
  - `[low]` `[patch]` Intent: `tenancy.tenant.created` says the label is on the Tenant, untrue once 1.28 changes labels — reworded.
  - `[low]` `[reject]` Intent: `operations.operation.retried` targets the Tenant, not the Operation — the audit envelope has no Operation kind and one active creation per Tenant makes it unambiguous; deferred.
  - `[low]` `[patch]` Intent: the fixed 404 isn't compared with Story 1.21's bytes, and the absolute-form test accepts 400 or 404 — both pinned.
  - `[low]` `[patch]` Intent: resolution maps InvalidOperationException to 503, hiding bugs — narrowed.
  - `[low]` `[defer]` Intent: Tenancy now carries ASP.NET Core and Npgsql to every host and the CLI — noted for the architecture spine.

## Design Notes

- **What "the Operation creates" means here.** The `tenant` row has to exist before the Operation does, because `operation.tenant_id` and `operation_step.tenant_id` reference it. The taken-subdomain refusal has to be synchronous, or the Admin would learn of a clash from a failed Operation. And the creator must hold a role at once, so they can poll the Operation on the Tenant path. So the start command writes `tenant`, `tenant_host`, `tenant_role` and the Operation in one `CommandContext`, which commits all or nothing. That needs no idempotence: it's one transaction. The Operation then does what only `Host.Worker` may do: create the secret class keys (AD-10 gives that grant to the Worker alone), and write `tenant_settings`, a `tenant` table that Host.Admin may only open on the path Tenant (Story 1.24's rule). Each of those repeats safely: an existing key comes back unchanged, and the settings insert is `ON CONFLICT DO NOTHING`.
- **Why a completion handler.** Activation must come after every creation stage, including those later stories add (Signing Keys, the built-in API, the default Connection). Story 1.9 runs stages unordered and fans Tenant steps out in parallel. Ordering them would mean a run job that waits on its own steps, and the job guard forbids a Tenant-scoped step from re-enqueuing the Deployment-wide run job. A handler that runs in the transaction marking the Operation `succeeded` needs neither, and is "after every stage" by definition. The finisher of an all-Tenant-stage Operation is always its last step job, in that Tenant's scope, so the handler can write `tenant_settings` and the Tenant's own audit chain. The rule test pins that shape.
- **A `creating` Tenant is invisible to Hosted.** AD-6 treats a deleted Tenant's host like an unknown one. A Tenant without keys or settings is no more servable, so its host gets the same 404 until activation. This also gives Story 2.3 a clean invariant: a resolved Tenant has its keys.
- **The fixed 404 stays the one Host.Hosted already sends.** Story 1.21 snapshots it for every host and path before bootstrap. Keeping it byte-identical means unknown, creating and route-less known hosts can't be told apart. Proving that "no Tenant code runs" for an unknown host needs something observable, so the probe server mounts the real middleware and a test-only endpoint that counts its calls, as Story 1.26's `RequestChecksTests` does for Host.Admin.
- **Issuer form.** The spike compares `Issuer.AbsoluteUri`, which is `https://host/`. Storing that exact string means discovery, tokens and email links all print the same characters, and Story 2.3 needn't reformat it. The port is included only when it isn't 443, so local runs on another HTTPS port still produce working links. The RP ID never has a port (WebAuthn).
- **One refusal for every bad subdomain.** The story says creation is refused "without saying whether it was taken or reserved". The dashboard checks the format itself, so a malformed value rarely reaches the server, and the server still folds it into the same code. The reserved check runs in code and the taken check in the database, so their timing differs. Only the Deployment Owner can see that, and the Owner can list every Tenant anyway. The threat model records it.
- **Immutability below the API.** No route takes a subdomain after creation. That is checked over the OpenAPI document, so a future `PATCH` with `subdomain` fails the build. The database also refuses it for every role, the migrator included, through triggers. Never-reuse follows from never-delete: `tenant_host` is the primary-keyed history of every host ever issued, which Story 1.29 has to soft-delete around.
- **The Owner role isn't `deployment.admins.manage`.** FR-7 makes the creator Owner as part of creation, and Story 1.24's table names `deployment.tenants.create` with `FreshAssertion.Never`. Granting roles to *others* stays `deployment.admins.manage` (fresh, Epic 8). So `IAdminTenantRoles` exposes only "the creator becomes Owner", called only from creation.
- **No fresh assertion here.** Creation is `Never` in the table and absent from FR-46's list, and no route in this story declares a fresh capability. The Tenant-surface begin therefore waits for Story 1.28's Prod label removal, the first Tenant route whose capability (`WhenProdTenant`) needs it.
- **Renewal on a real form.** Create Tenant is the first shell form. The browser test drives Story 1.25's renewal through a real 401 on the POST and a virtual-authenticator sign-in, then asserts the same DOM nodes, values and focus. It also asserts that exactly one POST was sent before the Admin presses the button again, which proves the "never resent" rule on a real page and not only in `renewal.test.mjs`.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests`. Expected:
  - the build has no warnings;
  - the `@gatekeep/ui` checks pass (raw hex, dependencies, screens props-only);
  - the dashboard Node tests pass (`renewal.test.mjs`, `freshAssertion.test.mjs`, `tenantSubdomain.test.mjs`);
  - the api-client tests and the API contract drift check pass against the regenerated files;
  - the Architecture tests pass, including `TenantRuleTests`, the Admins registry rows, the module edges, the Operation rules and the audit catalogue;
  - the Isolation tests pass: `TenantCreationTests`, `TenantResolutionTests`, `TenantTablesTests`, `TenantCreationOperationTests`, the custody policy tests, `HostStartupTests`, the unchanged `TenantHostBeforeBootstrapTests`, every fixture moved to `TestTenants`, and the canary scan;
  - the browser tests pass, including `admin-tenants`, the updated `admin-shell`, and `admin-csp`.

  From a worktree, use a worktree-only image tag, not `gatekeep/tests:local`.
- After changing the endpoints, regenerate the contract in Docker with `sh deploy/docker/api-contract.sh --write <abs dir>` (as `docker compose -f deploy/compose.test.yaml run --rm --build -v "<repository>:/out" tests sh deploy/docker/api-contract.sh --write /out`). Regenerate the audit catalogue and the module diagram with the Generator. Commit all three.

Nothing runs on the host.

## Auto Run Result

Status: done

**Summary:** the Deployment Owner creates Tenants on their own permanent subdomains. One request writes the Tenant, its host, the creator's Tenant Owner role, an Operation and an audit event, and answers `202`. The Worker creates the six secret class keys, and a completion handler writes `tenant_settings` and activates the Tenant in the same transaction as the Operation's success. The issuer, RP ID and email link base are stored once and never change, and no route or role can change or delete a subdomain. Malformed, reserved and taken subdomains get one refusal. Host.Hosted resolves the exact host to an active Tenant, and every other host gets one fixed 404 before any Tenant code runs. The dashboard opens on Create Tenant and lists Tenants.

**Files:** `src/Modules/Tenancy/` (subdomain, address, Tenants, resolution); `src/Modules/Management/`; `src/Modules/Operations/` (completion handler, dead jobs, Tenant creation); `src/Modules/Admins/` (Tenant roles); the Tenants migration and `TableRegistry`; `src/Gatekeep.Host.Admin/` (Tenants API, OpenAPI); `src/Gatekeep.Host.Hosted/Program.cs`; `docs/api/openapi-v1.json`, `packages/api-client/`; `apps/admin-dashboard/src/shell/` (Create Tenant, Tenants); `tests/Isolation/Tenancy/`, `Operations/`, `Custody/`, `tests/Architecture/TenantRuleTests.cs`, `tests/browser/admin-tenants.spec.ts`; `docs/audit-events.md`, the threat model and `install.md`.

**Review:** 27 findings across four layers: 24 patched, 2 deferred, 1 rejected, each with its reason in the triage log.

**Follow-up review:** recommended. Dead-job handling and the database invariants changed in review, with new tests as the only proof.

**Verification:** see the PR screenshot; the full suite passes in the `tests` container.

**Residual risks:** Host.Hosted lookups have no per-client limit until Epic 10. The retry event targets the Tenant, not the Operation, until the audit envelope gains an Operation kind.
