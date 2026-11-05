---
title: 'Story 1.28: Switch Tenants and set the environment label'
type: 'feature'
created: '2026-11-04'
status: 'done'
baseline_revision: 'deb7f458d7cdb36200ae2bc29c83f314d4e01a0e'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-gatekeep-2026-11-01/prd.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/DESIGN.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-25-open-the-admin-shell.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-27-create-tenants-with-permanent-subdomains.md'
  - '{project-root}/design/Gatekeep Admin.dc.html'
warnings: []
deferred: []
---

<intent-contract>

## Intent

**Problem:** FR-9 says "An Admin can switch between Tenants they hold a Tenant Role in from the top bar", with three consequences: "The current Tenant name and environment badge are visible on every Admin Dashboard page, and Prod Tenants have a visibly distinct treatment", "Tenants the Admin has no Tenant Role in aren't listed", and "Every Admin action names its target Tenant, and a mismatch with the page's Tenant is rejected". FR-7: "A Tenant Owner can change a Tenant's Dev, Staging or Prod label", and "Removing the Prod label needs re-authentication (FR-46), writes to the Log and relaxes no existing setting". FR-46 lists "changing a Prod Tenant's callback URLs or label" among the fresh-assertion actions. FR-44: "With no Tenants, a Deployment Owner lands on a create-Tenant form. Otherwise, Admins land on the current Tenant's Applications list." EXPERIENCE adds: "A Deployment Owner holding no Tenant Role lands on Tenants. Any other Admin with no Tenant Role sees 'You don't have access to a Tenant yet. Ask a Deployment Owner.'" AD-19: "Every Tenant-scoped action names its Tenant in the path, and the Dashboard keeps it in its URL. No server-side 'current Tenant' exists." It also prevents "a stale tab acting on the wrong Tenant".

Today:
- The top bar has the brand, the theme toggle and the avatar menu only (Story 1.25). `TopBar`'s comment says "no … Tenant switcher until the stories that build them".
- No route lists the Tenants an Admin holds a role in. Story 1.24 added the `tenant_role_admin` index for this, with no reader.
- `tenant.label` is written once, at creation (Story 1.27). `gk_admin` has no `UPDATE` on `tenant`. `tenant_guard_update` doesn't mention `label`.
- `tenant.label.manage` (Owners, machine-denied, `FreshAssertion.WhenProdTenant`) is in the capability table, and no route declares it.
- The fresh-assertion begin exists only on the Deployment surface (`POST /api/v1/deployment/assertions`). It refuses a Tenant capability action with 400 `assertion_refused`. `FreshAssertionBinding` already takes the path Tenant, and `FreshAssertionGate` already reads it from `PathTenantFeature`.
- `HandlerEnforced` in `CapabilityRuleTests` lists registration begin only. Its violation self-checks already name `put /api/v1/tenants/{tenantId}/label`.
- The dashboard has no Tenant page. `/` sends a Deployment Owner with Tenants to Tenants, and Create Tenant's success opens Tenants.
- Nothing compares the page's Tenant with an action's Tenant.

Items in `deferred-work.md` this story takes in:
- Story 1.24: "Tenant switching from an Admin's roles, and the 'no Tenant Role' landing".
- Story 1.25: "The Tenant switcher, the current Tenant's name and environment badge in the top bar, Tenant mismatch, and the final landing rules". Final here means final until Story 3.1 builds the Applications list.
- Story 1.26: "The Tenant-surface fresh-assertion begin, `POST /api/v1/tenants/{tenantId}/assertions`", and its review twin "Tenant-scoped fresh-assertion begin route".
- Story 1.26: "The `WhenProdTenant` and `WhenLoweringPolicy` predicates". This story takes `WhenProdTenant` for `tenant.label.manage` only. Callback URLs (`tenant.application_callbacks.manage`) and `WhenLoweringPolicy` stay with their own stories.
- Story 1.27: "The Tenant switcher, the Tenant name and environment badge in the top bar, label changes, and the final landing rules".

Not taken in: "A Tenant page that a Tenants row opens (Story 3.1 or 1.28)". Tenants rows stay plain text. A Deployment Owner may hold no role in a listed Tenant, so a row link would often lead to the forbidden page. The item moves to Story 3.1.

**Approach:**
- **The switcher reads one self-service list.**
  - `GET /api/v1/deployment/my-tenants` returns the active Tenants the current Admin holds a Tenant Role in: ID, name, stored host and label. It never returns the role.
  - Management assembles it. Admins gives the role rows' Tenant IDs. Tenancy gives those Tenants' records.
  - The shell reads it on every navigation, together with the two capability lists. So a removed role, a new Tenant and a changed label all show on the next navigation.
- **The current Tenant is the path Tenant.**
  - On `/tenants/{tenantId}/…` the top bar shows that Tenant's name and environment badge.
  - Elsewhere it shows the Tenant this browser last visited, if it is still listed, else the first listed. This is a per-browser convenience in `localStorage`. It never reaches a request.
  - Choosing a Tenant loads the same page in the new Tenant as a full document load ("Switching reloads the page in the new Tenant"). Unsaved changes prompt first.
- **The server rejects a mismatch.**
  - Every Admin-Session state-changing request on `/api/v1/tenants/{tenantId}/…` carries `X-Gatekeep-Tenant`. The api-client sets it from the page the shell shows when it sends.
  - The request checks compare it, as a string, with the `{tenantId}` path segment, after the capability decision. A missing or different value is 409 `tenant_mismatch`, and nothing runs.
  - The header is never parsed, never authorizes and never selects a Tenant: the path stays the only source (AD-4, AD-19).
  - The dashboard shows the `banner` naming both Tenants, with Reload.
- **The label changes on one route.**
  - `PUT /api/v1/tenants/{tenantId}/label` (`tenant.label.manage`, Tenant Owner) runs in the path Tenant's `TenantScope`. It locks the `tenant` row and evaluates `WhenProdTenant` on the locked label: the Tenant is Prod and the new label isn't.
  - Only then does it call `FreshAssertionGate.RequireAsync`. It writes `label` and nothing else, and appends one event on the Tenant's own chain.
  - Raising a label, Dev and Staging changes, and an unchanged label need no fresh assertion.
- **A fresh assertion begins on the Tenant surface.**
  - `POST /api/v1/tenants/{tenantId}/assertions` begins a ceremony for a Tenant capability action, bound to the path Tenant.
  - The existing Deployment complete finishes it, because the challenge row already carries the binding.
- **The dashboard.**
  - The top bar gains the switcher.
  - The Settings group gains "Tenant", a Tenant page holding only the environment, which the label route needs. FR-10's other settings arrive with Story 8.5.
  - The landing follows the four rules above. With a Tenant Role, the "current Tenant's Applications list" is this Tenant page until Story 3.1.
  - Create Tenant's success opens the new Tenant.

## Boundaries & Constraints

**Always:**

- **Label rules (Tenancy contract, `TenantLabelChange`):**
  - `RemovesProd(current, requested)` is `current == Prod && requested != Prod`. It is the one encoding of `WhenProdTenant` for the label, and a pure function.
  - Raising to Prod, Dev to Staging, Staging to Dev and an unchanged label are never fresh (FR-46 names only "changing a Prod Tenant's … label"). Prod to Prod is unchanged.
  - A label changes only while the Tenant is `active`. A `creating` Tenant keeps the label it was created with.
- **Schema (new migration `Migration20261104030000ChangeTenantLabels`; registry entries in the same migration):**
  - `GRANT UPDATE (label) ON tenant TO gk_admin`. `gk_admin` gets no other `tenant` column. `gk_worker` keeps `UPDATE (status)`.
  - `CREATE OR REPLACE FUNCTION tenant_guard_update()` keeps every Story 1.27 rule and adds one: a `label` change while `OLD.status <> 'active'` raises `GK006`. The function stays `REVOKE EXECUTE … FROM PUBLIC`.
  - **SQLSTATE `GK006`** ("a tenant's label changes only while it is active") is a refusal: `AdminResponses.TenancyGuardStates` gains it, and Host.Admin maps it to 409 `tenant_not_active`, never a 500. The migration's summary comment lists it beside `GK002`–`GK005`.
  - `TableRegistry`: `tenant` gains `[Admin] = [new ColumnGrant(Update, ["label"])]`.
- **Tenancy contract (`ITenants`; SQL in Tenancy only, AD-1, AD-27):**
  - `ListActiveAsync(CommandContext, IReadOnlyCollection<Guid> ids)` returns the `active` Tenants among `ids` with their `subdomain` host, ordered by `created_at, id`. It is one query (`= ANY(@ids)`). An empty `ids` means no query.
  - `LockLabelAsync(CommandContext, Guid tenantId)` runs `SELECT label, status FROM tenant WHERE id = @id FOR UPDATE` and returns `(TenantLabel, TenantStatus)?`. It runs in the path Tenant's own context only, and otherwise throws `InvalidOperationException`.
  - `SetLabelAsync(CommandContext, Guid tenantId, TenantLabel label, Actor actor, bool removedProd)` runs `UPDATE tenant SET label = @label WHERE id = @id AND status = 'active'`, in that Tenant's context. It appends `TenancyEvents.ProdLabelRemoved` when `removedProd`, else `TenancyEvents.LabelChanged`, with the target being the Tenant. Zero rows changed throws, because the caller holds the lock.
  - `TenancyEvents` gains the two events below.
- **Admins contract:** `IAdminTenantRoles.ListTenantIdsAsync(CommandContext, Guid adminId)` returns the Tenant IDs of the Admin's `tenant_role` rows, in a Deployment context, through `tenant_role_admin`. It never returns the role, and it is the switcher's only role read.
- **Management contract (`ITenantManagement`):**
  - `ListForAdminAsync(CommandContext, AdminPrincipal)`, in a Deployment context, returns `ListTenantIdsAsync`, then `ListActiveAsync`, as `AdminTenant(Id, Name, Host, Label)`. There is no capability check: it is the caller's own roles (self-service, like `GET /deployment/capabilities`).
  - `GetLabelAsync(CommandContext, AdminPrincipal, TenantRoleGrant? grant, Guid tenantId)` re-checks `AdminCapabilities.Allows(TenantConfigurationRead, principal, grant, tenantId)` (AD-5) from the grant the request checks read, then reads the label.
  - `ChangeLabelAsync(CommandContext tenantContext, AdminPrincipal, TenantRoleGrant? grant, Guid tenantId, string? requested, Func<CancellationToken, Task<bool>> requireFreshAssertion)`, in the path Tenant's context:
    1. Re-checks `Allows(TenantLabelManage, principal, grant, tenantId)` with no second role read → `Forbidden`.
    2. Parses `requested` with `TenantValues.TryParseLabel` → `Invalid`.
    3. `LockLabelAsync`: no row → `Forbidden`, since the checks had allowed a role there; not `active` → `NotActive`.
    4. Equal to the current label → `Unchanged(label)`, with no write and no event.
    5. `RemovesProd` → `await requireFreshAssertion(…)`. False → `FreshAssertionRequired` (the gate has already written the 403).
    6. `SetLabelAsync` → `Changed(label)`.
  - The grant is used up before the write, in its own committed transaction (Story 1.26). A rollback after it still uses the grant, and a retry needs a new confirmation.
- **Request checks (`AdminRequestChecks`):**
  - `TenantHeader = "X-Gatekeep-Tenant"`.
  - For a Tenant endpoint with a state-changing method, after the capability decision allows and before a checks-enforced fresh assertion is consumed: the header must be sent exactly once and equal, ordinally, to the route value `{tenantId}` as routing decoded it. Otherwise the refusal is `TenantMismatch` → 409 `tenant_mismatch`.
  - It is logged under `{Problem}` with the trace ID, not audited, and no grant is consumed. Both values are the caller's own, so the refusal discloses nothing.
  - A capability refusal still comes first and is still audited, so a role-less path Tenant is 403 `access_denied` whatever the header says.
  - Reads (`GET`, `HEAD`) never need it.
  - Epic 17's Management API bearer scheme doesn't apply it. This story's rule applies to Admin Sessions, which are the only principals today.
  - The value is never parsed into a Guid, stored, logged or passed to a handler.
- **Tenant-surface fresh-assertion begin (`FreshAssertionApi.BeginForTenantAsync`):**
  - The route is `POST /api/v1/tenants/{tenantId}/assertions`, declared `TenantApiEndpoint`, `RequiresCapability(TenantConfigurationRead)` and `JsonRequestBody(FreshAssertionBeginRequest)`. Any Tenant Role reaches the handler, which then decides the action's own capability.
  - It is counted per Session under `AdminsContract.FreshAssertionPolicy` before anything else, as the Deployment begin is.
  - The body is the same `FreshAssertionBeginRequest`. The action must be a Tenant capability whose `FreshAssertion` isn't `Never` (`AdminFreshAssertions.CapabilityOf(action)?.Scope == Tenant`). A self-service action, a Deployment capability, a `Never` capability, an unknown action or a malformed body is 400 `assertion_refused`.
  - The action's capability is decided with `AdminCapabilities.Allows(capability, principal, PathTenantGrant(context).Grant, pathTenant)`, from the grant the checks read, with no second read. A refusal is 403 `access_denied`, counted and audited through `AdminRequestChecks.DenyAsync` with the path Tenant. Every fresh-assertion capability is machine-denied, so a future machine principal is refused here too.
  - A pass calls `IAdminFreshAssertions.BeginAsync` in a Deployment scope, with `FreshAssertionBinding(action, pathTenant, body.Target)`, and answers `AdminSignInOptionsResponse` as the Deployment begin does.
  - The Deployment begin keeps refusing Tenant actions with 400. The complete stays `POST /api/v1/deployment/assertions/complete`, unchanged: the challenge row carries the binding hash, which names the Tenant.
- **Label route (`TenantLabelApi.SetAsync`):**
  - Declared `TenantApiEndpoint`, `RequiresCapability(TenantLabelManage)`, `EvaluatesFreshAssertion.Instance` and `JsonRequestBody(SetTenantLabelRequest)`, with no `FreshAssertionTarget`: the route's only parameter is the path Tenant.
  - The body is at most 4096 bytes, through `AdminApi.ReadJsonAsync`. A body that isn't JSON, misses `label` or has the wrong type is 400 `tenant_invalid`.
  - It opens `TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), …)`. That is the only form `CapabilityRuleTests` allows, and `AdminApiServices` gains `Source` for it.
  - It calls `ChangeLabelAsync` with `requireFreshAssertion = ct => FreshAssertionGate.RequireAsync(context, services, ct)`, and commits only on `Changed`.
  - `GK006` (a race with nothing today, defence in depth) → 409 `tenant_not_active`. Any other `DbException` → the fixed 503.
- **Routes after this story:**

  | Route | Access | Answers |
  | --- | --- | --- |
  | `GET /api/v1/deployment/my-tenants` | self-service (reviewed list) | 200 `AdminTenantListResponse` |
  | `GET /api/v1/tenants/{tenantId}/label` | `tenant.configuration.read` | 200 `TenantLabelResponse`, whatever the Tenant's status |
  | `PUT /api/v1/tenants/{tenantId}/label` | `tenant.label.manage`, `WhenProdTenant`, handler-enforced | 200 `TenantLabelResponse`; 400 `tenant_invalid`; 403 `access_denied`; 403 `fresh_assertion_required`; 409 `tenant_mismatch`; 409 `tenant_not_active` |
  | `POST /api/v1/tenants/{tenantId}/assertions` | `tenant.configuration.read`, then the action's capability in the handler | 200 `AdminSignInOptionsResponse`; 400 `assertion_refused`; 403 `access_denied`; 409 `tenant_mismatch`; 429 `rate_limited` |
  | Every Tenant-path state-changing route | + 409 `tenant_mismatch` | |
  | Every other existing route | unchanged | |

  - `HandlerEnforced` becomes registration begin and `put /api/v1/tenants/{tenantId}/label`. `SelfService` adds `get /api/v1/deployment/my-tenants`.
  - No route but `PUT …/label` writes `tenant.label` after creation.
- **Shapes (camelCase; `Cache-Control: no-store` on all four):**
  - `AdminTenantListResponse`: `{ tenants: [{ id: "ten_…", name, host, label: "dev" | "staging" | "prod" }] }`, with only `active` Tenants, ordered by creation. There is no role, status or cursor, and no paging `[ASSUMPTION]`, see Ask First.
  - `TenantLabelResponse`: `{ label }`.
  - `SetTenantLabelRequest`: `{ label: "dev" | "staging" | "prod" }`. An unknown extra property is ignored.
  - OpenAPI: `AdminOpenApi` adds the required header parameter `X-Gatekeep-Tenant` ("The Tenant the page shows, its `ten_` ID: it must equal `{tenantId}`, or 409 `tenant_mismatch`. It never selects a Tenant.") and the 409 problem to every Tenant-path state-changing operation. `ApiProblem.code` gains `tenant_mismatch` and `tenant_not_active`.
- **Refusals:**
  - `tenant_mismatch` (409) and `tenant_not_active` (409) are new. `AdminResponses.ProblemCodes` lists both.
  - Each is logged under `{Problem}` with fixed names. No label, Tenant name, host or header value is logged, and no placeholder is named `{Code}`.
- **Audit events (each on the path Tenant's own chain, Actor the Admin, target the Tenant; none holds the Tenant's name or host):**
  - `tenancy.tenant.label_changed` (`TenancyEvents.LabelChanged`): "A Tenant Owner changed a Tenant's environment label, other than removing Prod. Names the Tenant only."
  - `tenancy.tenant.prod_label_removed` (`TenancyEvents.ProdLabelRemoved`): "A Tenant Owner removed a Tenant's Prod label after a fresh WebAuthn assertion. No setting changed with it."
  - Removing Prod also leaves Story 1.26's `admin.fresh_assertion.verified` on the Deployment chain, from the complete.
  - `docs/audit-events.md` is regenerated with `dotnet run --project tests/Architecture/Generator`, in Docker. FR-40 class: none.
- **Module edges:** none new. Management already depends on Tenancy and Admins, and Host.Admin on Management and Admins. `module-edges.txt` and `docs/architecture/module-dependencies.md` stay unchanged, which the edge test confirms.
- **api-client (`packages/api-client/src/client.ts`, from the regenerated schema):**
  - `ApiClientOptions.pageTenant?: () => string | null`. On a state-changing request whose path starts `/api/v1/tenants/`, a non-null value is sent as `X-Gatekeep-Tenant`. Reads, Deployment paths and a null value send none.
  - `listMyTenants()`, `getTenantLabel(tenantId)`, `setTenantLabel(tenantId, body)` and `beginTenantFreshAssertion(tenantId, binding)`. Each ID goes into the path encoded.
  - `client.test.mjs` covers the header rules.
- **Dashboard (no new runtime dependency; nothing inline; every string in `messages.tsx`):**
  - **Session (`session.ts`):** `pageTenant: () => pathTenant(window.location.pathname)` as a `ten_` string or null. It reads the page the shell shows at send time. The page builds the API path from the Tenant it was mounted with.
  - **Shell reads (`capabilities.ts`):**
    - `useCapabilityReads` also reads `listMyTenants` on every navigation and Retry, in parallel with the two capability lists, through the same renewal.
    - `Held` gains `tenants: readonly AdminTenant[]`.
    - A failed list read is a failed read, which shows the load-failed banner with Retry, as Story 1.25's lists do.
  - **Current Tenant (`shell/currentTenant.ts`, plain TypeScript, Node-tested):**
    - `current(path, tenants, remembered)` returns the listed path Tenant on a Tenant path, and null for an unlisted one. Elsewhere it returns the remembered one if listed, else the first, else null.
    - `switchHref(path, to)` replaces the Tenant segment on a Tenant path, and is `/tenants/{to}` elsewhere. Search and hash are dropped, and the result is always same-origin and path-absolute.
    - `remember(adminId, tenantId)` and `remembered(adminId)` use `localStorage` key `gatekeep.admin.lastTenant.{adminId}`. Every access is wrapped in try/catch, and a failure means none.
    - The shell remembers the path Tenant once its reads say it is listed.
  - **Switcher (`shell/TenantSwitcher.tsx`, in `TopBar`'s new `tenantSwitcher` slot after the brand and a `/` separator, as drawn at L35–L58):**
    - **Trigger:** the current Tenant's name in `<bdi>`, then `EnvironmentBadge` with the Story 1.27 tags: `DEV` `info`, `STG` `warn`, `PROD` `bad` (DESIGN.md "Prod treatment", UX-DR9). Its accessible name is "{name} {tag}, switch Tenant" `[ASSUMPTION]`. With no current Tenant but a list or `deployment.tenants.create`, it is "Choose a Tenant" `[ASSUMPTION]` with no badge. An Admin with neither sees no switcher.
    - **Items (`Menu`, UX-DR18: click or Enter opens, arrow keys move, Esc closes):** one per listed Tenant, with the name in `<bdi>`, the host in code type and the tag badge, flat, in the list's order. The current one is `current` (new `Menu` item flag: `aria-current="true"` and the sf2 background as drawn).
    - **Footer:** after a separator, "+ Create Tenant" (EXPERIENCE) to `/deployment/tenants/new`, only with `deployment.tenants.create`. There is no "Compare & promote environments" (FR-44, environments are v2), no group heading ("Tenants · Northwind" names an organization, which v1 lacks) and no initials tile `[ASSUMPTION]`.
    - **Width:** at 768–1099px the name truncates with an ellipsis, and the badge and the accessible name stay whole.
    - **Choosing a Tenant:** choosing the current one closes the menu. Another one runs `window.location.assign(switchHref(…))`.
    - **Unsaved changes:** a page that has registered unsaved changes (new `useUnsavedChanges` in the shell) first gets `ConfirmModal` with title "Discard unsaved changes?", body "Your changes on this page aren't saved.", confirm "Discard and switch" and cancel "Keep editing" `[ASSUMPTION]`.
  - **Every page:** the switcher is in the top bar on every shell page, Tenant and Deployment pages alike, so the name and badge show wherever a current Tenant exists.
  - **Tenant mismatch (shell):**
    - `shellRequest` sees a 409 `tenant_mismatch` answer and sets a shell `banner` (tone `warn`): "This action was for {actionTenant}, but this page shows {pageTenant}. Nothing was changed." `[ASSUMPTION]`, with the action "Reload" (`window.location.reload()`).
    - Names come from the switcher list, in `<bdi>`. A Tenant the list lacks shows its `ten_` ID in code type.
    - The answer still reaches the page, which keeps its values and stops pending.
  - **Sidebar (`shell/nav.ts`):** a Settings item `{ group: 'settings', label: 'navTenant' ("Tenant"), href: (t) => '/tenants/' + t + '/settings', requires: 'tenant.configuration.read' }` (EXPERIENCE IA: Settings → Tenant). Update the registry comment.
  - **Routes in `Shell.tsx`:**

    | Path | Shows |
    | --- | --- |
    | `/` | `LandingPage`, as below |
    | `/tenants/{tenantId}` | replaces the URL with `/tenants/{tenantId}/settings` (the interim Tenant landing until Story 3.1) |
    | `/tenants/{tenantId}/settings` | `TenantSettingsPage` with `key={tenantId}`, so another Tenant's page never reuses its form state |

    - A path Tenant the server refused stays the forbidden page (Story 1.25).
  - **Landing (`LandingPage.tsx`):**
    1. Any listed Tenant: the URL becomes `/tenants/{current}/settings` (remembered, else first) `[ASSUMPTION: the Applications list arrives with Story 3.1]`.
    2. Else, with `deployment.tenants.read`: the first Tenants page is read. None → Create Tenant in place (FR-44, unchanged). Any → `/deployment/tenants` ("A Deployment Owner holding no Tenant Role lands on Tenants").
    3. Else: "You don't have access to a Tenant yet. Ask a Deployment Owner." (`landingNoAccess`, unchanged).
  - **Create Tenant (`CreateTenantPage.tsx`):** success shows the `toast` "Tenant created." and then opens `/tenants/{newTenantId}`, not Tenants. EXPERIENCE: success is the new Tenant's landing.
  - **Tenant settings (`shell/TenantSettingsPage.tsx`, built from `GEN.tenant` L1294 as the Design Delta changes it; existing components only, UX-DR46):**
    - **Heading:** `SectionPage` with title "Tenant settings" (the design's `t`) and description the Tenant's host in code type, from the switcher list `[ASSUMPTION]`.
    - **Loading:** the page reads `getTenantLabel` through `shellRequest('get', …)`, with `SkeletonRows` after 300ms. A failed read shows the load-failed banner with Retry.
    - **Environment field:** `RadioGroup` with legend "Environment", the same three options and tags as Create Tenant, shared from one list: "Development" `DEV` `info`, "Staging" `STG` `warn`, "Production" `PROD` `bad`. The design draws a select ("Environment tag"). Radios keep each option's tone visible `[ASSUMPTION]`.
    - **Helper:** "Removing the Prod label needs you to confirm it's you." `[ASSUMPTION]`.
    - **Without `tenant.label.manage`:** the group is read-only with the helper "Tenant Owner only" (EXPERIENCE). When the Admin also lacks every `tenant.*.manage` capability, the page shows the `banner` "You have view-only access to this Tenant." (EXPERIENCE, Forbidden action). Both follow capabilities, never a role.
    - **Save:** the primary button "Save" `[ASSUMPTION]`. It sends only when the choice differs from the loaded label, and then registers no unsaved changes.
    - **Removing Prod (loaded `prod`, choice not `prod`):**
      - Save first opens `ConfirmModal` (Re-authentication gate: "modal first, then sheet, with failure shown inside the same modal"). Title "Remove the Prod label?", body "{name} will no longer be marked Prod. No other setting changes.", confirm "Remove Prod label" `[ASSUMPTION]`.
      - Confirm sends the `PUT` through `fresh.withFreshAssertion({ action: 'tenant.label.manage', target: null, tenantId }, …)`.
      - The sheet's status and failures show inside the modal, with the existing `freshAssertionPrompt`, `freshAssertionCancelled` and `freshAssertionUnavailable`, and a 429 as `CredentialsPage` shows it.
    - **Any other change:** a plain `PUT`.
    - **Outcomes:**
      - 200: the `toast` "Environment saved." `[ASSUMPTION]`. The page shows the returned label, and the shell's lists are read again so the badge changes at once.
      - 400, 5xx or a lost connection: the Save failed `banner` above the form, with values kept: "Couldn't save the environment. Try again." `[ASSUMPTION]`, with `ErrorReference`.
      - 409 `tenant_not_active`: the `banner` "This Tenant is still being created." `[ASSUMPTION]`.
      - 403 `access_denied` or the bodiless 403: the existing `actionForbidden` banner.
      - 409 `tenant_mismatch`: the shell's banner, with nothing else.
    - **Renewal:** a 401 on the `PUT` keeps the page mounted, as on Create Tenant, and it is never resent.
  - **Fresh assertions (`shell/freshAssertion.ts`):** `Binding` gains `tenantId?: string | null`. The shell's `begin` calls `beginTenantFreshAssertion(tenantId, …)` when it is set, else the Deployment begin. `freshAssertion.test.mjs` covers both.
  - **`TopBar`:** gains `tenantSwitcher?: ReactNode`. Its comment no longer says "no … Tenant switcher".
  - **`Menu`:** `MenuItem` gains `current?: boolean`. Its existing behaviour is unchanged.
- **CSP (AD-21):** nothing inline, no `data:` or `blob:` URI, no CSP change. Every new and changed browser test uses `watchCsp`.
- **Tests:**
  - **Isolation tests:** Testcontainers PostgreSQL. The real `Host.Admin` runs through `AdminHost`, with Story 1.26's `SoftwareAuthenticator` for assertions. Roles other than the creator's Owner role (Editor, Viewer, another Admin's) are inserted as the migrator through `TestTenants`, since no route grants them before Story 8.4.
  - **Browser tests:** Playwright against the built Host.Admin (`admin-host.mjs`), with the API intercepted. A Chromium virtual authenticator answers the Prod-removal sheet. Each runs with axe and `watchCsp`.
- **Docs:**
  - **`docs/threat-model.md`:**
    - The header's "exists in code" list adds Story 1.28.
    - **T-1:** the sentence "no Session column, cookie, header, query string or claim carries one" becomes: no Session column, cookie, query string or claim carries one, and `X-Gatekeep-Tenant` is only compared with the path, never read as a Tenant. Add test names.
    - **T-22:** removing Prod needs a fresh assertion bound to that Tenant.
    - **T-36:** labelling Prod while `GATEKEEP_CONFORMANCE_TENANT` is set is still Story 4.14's.
    - **T-53:** the label route, the Tenant begin and the self-service list, with test names.
    - **New T-56:** "An Admin changes the wrong Tenant or environment, or Prod is removed quietly or relaxes a setting". Its controls are the path-only Tenant, the mismatch header and its 409, the full-document switch, `key={tenantId}`, the Prod badge on every page, the fresh assertion bound to the Tenant, the label-only write and its Tenant-chain events. What remains: a dashboard that sends no header can't be checked, which only a non-dashboard Admin-Session client can do and then acts only on the Tenant it names; the remembered Tenant on Deployment pages is display only; later stories that read the label must keep "relaxes no existing setting".
  - **`docs/install.md`:** the "Not yet covered" Admin Dashboard item adds the switcher and the Tenant page's environment, and says Applications and the other settings arrive from Story 3.1 and Story 8.5.
  - **`docs/audit-events.md`:** regenerated.
  - **`deferred-work.md`:** as described in Tasks.

**Ask First:**
- **The Tenant landing is the Tenant settings page** (environment only) until Story 3.1's Applications list. FR-44 says Applications. Confirm before landing somewhere else.
- **Create Tenant's success opens the new Tenant**, not Tenants, which reverses Story 1.27's interim choice. Confirm before keeping Tenants.
- **On a Deployment page the switcher shows the remembered Tenant** (else the first listed), because the story says the name and badge show on "any page". The page itself acts on no Tenant. The alternative is "Choose a Tenant" on every Deployment page. Confirm before changing.
- **The mismatch header** (`X-Gatekeep-Tenant`, compared only). It makes FR-9's "a mismatch with the page's Tenant is rejected" a server rule rather than a dashboard-only one. Confirm before dropping it or making it a dashboard check.
- **Two event codes**, `label_changed` and `prod_label_removed`, because the audit envelope can't carry the new label (Story 1.27's deferred envelope item). Confirm before adding a label to the envelope instead, which is an AD-16 change.
- **The switcher lists only `active` Tenants**, in creation order, with no paging or search. A `creating` Tenant is reached from Tenants. Confirm before listing it, or paging.
- **A grant covers "change Tenant A's label" once, whatever the new label is.** The route's only parameter is the path Tenant, so the binding has no target. Confirm before binding the requested label too, which would need a body-bound binding.
- **The values marked `[ASSUMPTION]`:** the copy, the radio group in place of the drawn select, no initials tile, and the `localStorage` key.

**Never:**
- No server-side current Tenant (AD-19). The path names the Tenant, `X-Gatekeep-Tenant` is only compared, and the remembered Tenant never leaves the browser.
- No Tenant taken from `X-Gatekeep-Tenant`, a cookie, the Session, `localStorage` or a claim. The header is never parsed, stored, logged or passed on.
- No role in any response, and no client decision from a role. The switcher, the Settings item, read-only state and "+ Create Tenant" follow the server's capability lists, and the server decides every request.
- No Prod removal without a fresh assertion bound to that Session, action and Tenant. A grant for one Tenant never serves another.
- No write but `tenant.label` when the label changes. No setting, policy, retention or other row changes with it, and no relaxation is implied by it.
- No label change on a `creating` Tenant, by any role (`GK006`).
- No "Compare & promote environments", environments page, organization heading, Region or custom-domain copy (FR-44, AD-7).
- No Tenant name, host, label or header value in a log line. No placeholder named `{Code}`.
- No inline style or script, no CSP change, and no new runtime dependency in `apps/admin-dashboard` or `packages/ui`.
- **Out of scope**, recorded in `deferred-work.md`:
  - Refusing to label a Tenant Prod while `GATEKEEP_CONFORMANCE_TENANT` is set (Story 4.14, AD-21).
  - `WhenProdTenant` for callback URLs (Epic 3) and `WhenLoweringPolicy` (Epic 6). Both are carried on from Story 1.26's item.
  - The Applications list as the Tenant landing (Story 3.1).
  - FR-10's other Tenant settings on the same page (Story 8.5).
  - A Tenants row that opens the Tenant (Story 3.1).
  - Paging or search in the switcher.
  - The label in the audit envelope (carried on from Story 1.27).
  - The "role removed mid-session" and "Tenant deleted" banners (Story 8.4, Story 1.29, carried on).
  - The mismatch rule for the Management API's bearer scheme (Story 17.3).
  - Tenant page titles in `<title>` (carried on from Story 1.25).
  - Bidi isolation beyond the new switcher and banner (Story 18.3, carried on).

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| My Tenants | Admin with roles in A (active, created first), B (creating), C (active), none in D | 200 `{tenants:[A, C]}` with ID, name, stored host, label; no role, status or D; `no-store` | — |
| My Tenants, no role | The Deployment Owner holding no role; any other Admin | 200 `{tenants:[]}` | — |
| My Tenants, restricted | Setup or recovery Session; no Session | Bodiless 403; 401 | — |
| Read label | Any role in A; `GET /tenants/ten_A/label` | 200 `{label}` | — |
| Raise label | Owner; A `dev`; `PUT …/label {label:"prod"}`, header `ten_A` | 200 `{label:"prod"}`; only `tenant.label` changed; `tenancy.tenant.label_changed` on A's chain; no grant asked or consumed | — |
| Dev to Staging | Owner; A `dev` → `staging` | 200, `label_changed` | — |
| Unchanged | Owner; A `prod` → `prod`, no grant | 200 `{label:"prod"}`, no write, no event, no grant consumed | — |
| Remove Prod, no grant | Owner; A `prod` → `staging` | 403 `fresh_assertion_required`; label still `prod`; nothing written | — |
| Remove Prod, confirmed | Owner; begin `POST /tenants/ten_A/assertions {action:"tenant.label.manage", target:null}`; complete; `PUT …/label {label:"staging"}` | 200; `tenancy.tenant.prod_label_removed` on A's chain; `admin.fresh_assertion.verified` on the Deployment chain; grant gone | — |
| Grant used once | Same, then raise to `prod` and remove again without a new confirmation | Raise 200; second removal 403 `fresh_assertion_required` | — |
| Grant is per Tenant | Owner of A and B (both `prod`); confirm on A; `PUT /tenants/ten_B/label` | 403 `fresh_assertion_required`; A's grant still unused | — |
| Grant expired | Confirmation older than 5 minutes | 403 `fresh_assertion_required` | — |
| Relaxes nothing | Snapshot every row of A in `tenant`-class tables, `tenant_settings` and `tenant`, then remove Prod | Only `tenant.label` differs, plus the new audit rows | — |
| Removal race | Two confirmed removals of A at once with one grant | Exactly one `prod_label_removed`; the other is 403 `fresh_assertion_required` or 200 unchanged | — |
| Not Owner | Editor or Viewer of A; `PUT …/label` | 403 `access_denied`, `admin.access.denied` within the cap, nothing written | — |
| No role, or wrong Tenant | Owner of A; `PUT /tenants/ten_B/label` (no role), with header `ten_B` or `ten_A`; unknown and malformed `ten_` | 403 `access_denied`, audited against the path Tenant; the header changes nothing | — |
| Creating Tenant | Owner of creating E; `PUT /tenants/ten_E/label` | 409 `tenant_not_active`, nothing written | — |
| Bad body | `{label:"production"}`, `{}`, `{label:1}`, non-JSON, over 4096 bytes | 400 `tenant_invalid`, nothing written, no grant consumed | — |
| Mismatch | Owner of A and B; `PUT /tenants/ten_A/label` with header `ten_B`; with no header; with it sent twice | 409 `tenant_mismatch`; nothing written; not audited; a held grant stays unused | — |
| Mismatch order | Role-less path with a mismatched header; bad CSRF with a mismatched header | 403 `access_denied` (audited); bodiless 403 | — |
| Reads need no header | `GET …/label`, `GET …/capabilities`, `GET …/operations/opr_…` with no header | 200 | — |
| Header never selects | `PUT /tenants/ten_A/label`, header `ten_A`, where the Admin is Owner of B only | 403 `access_denied` | — |
| Tenant begin, refused | Owner of A; action `tenant.configuration.read`, `deployment.tenants.delete`, `self.credentials.add`, `nope`, non-JSON | 400 `assertion_refused`, no challenge stored | — |
| Tenant begin, not held | Editor of A; action `tenant.label.manage` | 403 `access_denied`, audited with Tenant A | — |
| Tenant begin, limited | 11th begin or complete in 15 minutes in one Session | 429 `rate_limited` | 429 |
| Deployment begin unchanged | `POST /deployment/assertions {action:"tenant.label.manage"}` | 400 `assertion_refused` | — |
| Database guard | `gk_admin` `UPDATE tenant SET name = …` or `status = …`; migrator sets the label of a `creating` Tenant | Permission denied; `GK006` | DB error |
| Canary | A canary as a Tenant name, then switching and relabelling | Absent from operational logs | Test fails |
| Switcher (browser) | Admin with roles in A (`prod`) and C (`dev`), Owner | Trigger "A" `PROD` in `bad`; menu lists A (current) and C with host and tag; "+ Create Tenant" | — |
| Switcher, not Owner (browser) | Same list, no Deployment capability | No "+ Create Tenant" | — |
| Keyboard (browser) | Enter opens; ArrowDown/ArrowUp move; Esc closes and returns focus | As UX-DR18 | — |
| Every page (browser) | `/tenants/ten_A/settings`, `/deployment/tenants`, `/account/credentials` | Name and badge in the top bar on each; on Deployment pages the remembered Tenant | — |
| Tones (browser) | Tenants labelled `dev`, `staging`, `prod` | `DEV` `info`, `STG` `warn`, `PROD` `bad` | — |
| Switch (browser) | On `/tenants/ten_A/settings` choose C | A new document loads at `/tenants/ten_C/settings` | — |
| Switch with changes (browser) | Change the environment, then choose C | "Discard unsaved changes?"; Keep editing stays; Discard and switch loads C | — |
| Landing (browser) | (1) a listed Tenant, (2) Owner with Tenants and no role, (3) Owner with none, (4) other Admin with none | (1) `/tenants/{remembered or first}/settings`; (2) `/deployment/tenants`; (3) Create Tenant in place; (4) "You don't have access to a Tenant yet. Ask a Deployment Owner." | — |
| Create opens Tenant (browser) | Creation succeeds | Toast "Tenant created.", then `/tenants/ten_new/settings` | — |
| Change label (browser) | Owner, `dev` → `staging`, Save | Toast "Environment saved."; badge becomes `STG` | — |
| Remove Prod (browser) | Owner, `prod` → `dev`, Save; PUT 403 `fresh_assertion_required`; Tenant begin; virtual authenticator; complete 204; PUT 200 | The modal, then the sheet status inside it, then the toast; badge `DEV`; the begin went to `/api/v1/tenants/ten_A/assertions` | — |
| Remove Prod cancelled (browser) | The sheet is cancelled | "Confirmation cancelled. Nothing was changed." inside the same modal; label still `PROD` | — |
| Read-only (browser) | Editor (holds a manage capability, not `tenant.label.manage`); Viewer (none) | Radios read-only with "Tenant Owner only"; the Viewer also sees "You have view-only access to this Tenant." | — |
| Mismatch (browser) | A's settings form mounted, URL moved to `/tenants/ten_C/settings` while its reads hang; Save answers 409 `tenant_mismatch` | Banner "This action was for A, but this page shows C. Nothing was changed." with Reload; the PUT carried `X-Gatekeep-Tenant: ten_C` on the `ten_A` path | — |
| CSP | Every new and changed test | No `securitypolicyviolation`, no console CSP message, no other-origin request | Test fails |
| axe | Switcher open; Tenant settings (read-only, editable, Prod modal, failure); mismatch banner; landing states; light and dark; 1100 and 768 | No violations | Test fails |

</intent-contract>

## Code Map

- `src/Adapters/Postgres/`:
  - new `Migrations/Migration20261104030000ChangeTenantLabels.cs`: the grant, the replaced `tenant_guard_update` with `GK006`;
  - `Schema/TableRegistry.cs`: `gk_admin`'s `UPDATE (label)` on `tenant`.
- `src/Modules/Tenancy/Contracts/`:
  - `ITenants.cs`: `ListActiveAsync`, `LockLabelAsync`, `SetLabelAsync`, `TenantLabelChange`;
  - `TenancyEvents.cs`: the two events.
- `src/Modules/Tenancy/Core/Tenants.cs`: their SQL.
- `src/Modules/Admins/Contracts/IAdminTenantRoles.cs` and `Core/AdminTenantRoles.cs`: `ListTenantIdsAsync`.
- `src/Modules/Management/Contracts/ITenantManagement.cs`: `AdminTenant`, `ListForAdminAsync`, `GetLabelAsync`, `ChangeLabelAsync` and `LabelChangeResult`.
- `src/Modules/Management/Core/TenantManagement.cs`: the three calls.
- `src/Gatekeep.Host.Admin/`:
  - `AdminApi.cs`: the four routes and their OpenAPI text;
  - new `TenantLabelApi.cs` (GET and PUT, `SetTenantLabelRequest`, `TenantLabelResponse`);
  - `TenantsApi.cs`: `ListMineAsync`, `AdminTenantListResponse`;
  - `FreshAssertionApi.cs`: `BeginForTenantAsync`;
  - `AdminRequestChecks.cs`: `TenantHeader` and the mismatch refusal;
  - `AdminResponses.cs`: `tenant_mismatch`, `tenant_not_active`, `GK006`;
  - `AdminOpenApi.cs`: the header parameter and the 409;
  - `AdminApiServices.cs`: `Source`.
- `docs/api/openapi-v1.json` and `packages/api-client/src/schema.generated.ts`: regenerated with `sh deploy/docker/api-contract.sh --write <abs dir>`.
- `packages/api-client/src/client.ts` and `test/client.test.mjs`: `pageTenant` and the four calls.
- `packages/ui/src/`:
  - `components/TopBar.tsx`: the slot;
  - `components/Menu.tsx` and `Menu.module.css`: `current`;
  - `messages.tsx`: the new keys (`navTenant`, switcher, mismatch, Tenant settings, Prod modal, unsaved changes).
- `apps/admin-dashboard/`:
  - `src/session.ts`: `pageTenant`;
  - `src/shell/capabilities.ts`: the list read;
  - new `src/shell/currentTenant.ts`, `src/shell/TenantSwitcher.tsx` and `src/shell/TenantSettingsPage.tsx`;
  - `src/shell/Shell.tsx`: the switcher, the routes, the mismatch banner, `useUnsavedChanges`;
  - `src/shell/nav.ts`: the item;
  - `src/shell/LandingPage.tsx`;
  - `src/shell/CreateTenantPage.tsx`: the success target and the shared environment options;
  - `src/shell/freshAssertion.ts`: `tenantId`;
  - new `test/currentTenant.test.mjs`, and `test/freshAssertion.test.mjs`.
- `tests/Architecture/`:
  - `CapabilityRuleTests.cs`: `HandlerEnforced` and `SelfService`; `Fresh_assertion_rule_holds_the_routes_this_story_declares` asserts the label route's handler enforcement and no target.
  - `TenantRuleTests.cs`:
    - only `AdminRequestChecks.cs` names `X-Gatekeep-Tenant` in `src/`, and never passes it to `PublicId.TryParse`;
    - every Tenant-path state-changing operation documents the header and a 409;
    - only `SetTenantLabelRequest` has a `label` property besides `CreateTenantRequest`, and only `PUT …/label` takes it;
    - each rule has a self-check that catches a violation.
  - `AdminApiRuleTests.cs`: the `tenant` row, `gk_admin SELECT, INSERT, UPDATE (label)`.
  - `AuditCatalogueTests.cs`, through the regenerated catalogue.
- `tests/Isolation/`:
  - new `Tenancy/TenantLabelTests.cs` (every label row of the matrix, the relax-nothing snapshot, the race);
  - new `Tenancy/MyTenantsTests.cs`;
  - new `Admins/TenantFreshAssertionTests.cs` (the Tenant begin, per-Tenant grants, Deployment begin unchanged);
  - new `Admins/TenantMismatchTests.cs`;
  - `Tenancy/TenantTablesTests.cs` (the grant, `GK006`);
  - `Admins/RequestChecksTests.cs` (the check order);
  - `TestTenants.cs` (a role helper);
  - the canary scan.
- `tests/browser/`:
  - new `admin-tenant-switcher.spec.ts`;
  - updated `admin-shell.spec.ts` (top bar, landing) and `admin-tenants.spec.ts` (success target);
  - `playwright.config.ts`: the project, and in the default projects' `testIgnore`.
- Docs: `docs/threat-model.md`, `docs/audit-events.md` (generated), `docs/install.md`, `_bmad-output/implementation-artifacts/deferred-work.md`.

## Tasks & Acceptance

**Execution:**
- [x] Schema:
  - the migration and registry entry;
  - `TenantTablesTests` covers the `gk_admin` column grant (label only), `GK006` for every role and the migrator, and that every Story 1.27 trigger rule still holds.
- [x] Tenancy, Admins, Management:
  - `TenantLabelChange`, the three `ITenants` calls and the events;
  - `ListTenantIdsAsync`;
  - `ListForAdminAsync`, `GetLabelAsync` and `ChangeLabelAsync`, with the AD-5 re-checks from the request's grant.
- [x] Host.Admin:
  - the request checks' mismatch rule and its position;
  - the Tenant begin;
  - the label routes and the self-service list;
  - the problem codes and the `GK006` mapping;
  - the OpenAPI header and 409.
  - Then regenerate the contract with `sh deploy/docker/api-contract.sh --write <abs dir>`.
- [x] Architecture tests:
  - `CapabilityRuleTests` lists;
  - `TenantRuleTests` rules with self-checks;
  - the Admins registry row;
  - the catalogue, with `docs/audit-events.md` regenerated;
  - the unchanged edge list.
- [x] Isolation tests: every server row of the I/O matrix, with Testcontainers PostgreSQL and the software authenticator, and the canary row.
- [x] api-client: `pageTenant`, the calls, and `client.test.mjs`.
- [x] Dashboard:
  - `Menu.current` and `TopBar`'s slot;
  - `currentTenant.ts` with its Node test;
  - the switcher;
  - the shell's reads, routes, mismatch banner and unsaved-changes prompt;
  - `TenantSettingsPage`;
  - `nav.ts`;
  - `LandingPage`;
  - Create Tenant's success;
  - `freshAssertion.ts` and its test;
  - the catalogue keys.
- [x] Browser tests: `admin-tenant-switcher.spec.ts` (every browser row, `watchCsp`, axe in light and dark at 1100 and 768), the updated `admin-shell.spec.ts` and `admin-tenants.spec.ts`, and the config.
- [x] Docs:
  - threat model (header, T-1, T-22, T-36, T-53, new T-56);
  - `install.md`;
  - `deferred-work.md`:
    - remove the taken-in items: Story 1.24's switching item, Story 1.25's switcher item, Story 1.26's two Tenant-surface begin items, and Story 1.27's switcher and label item;
    - narrow Story 1.26's predicates item to callback URLs and `WhenLoweringPolicy`;
    - move Story 1.27's "A Tenant page that a Tenants row opens" to Story 3.1;
    - add the out-of-scope ones.

**Acceptance Criteria:**
- Given an Admin with Tenant Roles, when they open the switcher, then only the active Tenants they hold a Tenant Role in are listed, and "+ Create Tenant" shows only to Deployment Owners.
- Given any shell page, when it renders with a current Tenant, then its name and environment badge show in the top bar, with Prod `bad`, Staging `warn` and Dev `info`.
- Given a request whose path Tenant the Admin holds no Tenant Role in, when it arrives, then the server refuses it with 403 `access_denied`, and neither the header, the Session nor the remembered Tenant changes that: the path is the only source of the Tenant.
- Given a page's Tenant that differs from an action's target Tenant, when the action is submitted, then the server rejects it with 409 `tenant_mismatch` before anything runs, and the dashboard shows a `banner` naming both Tenants with Reload.
- Given a Tenant Owner removing the Prod label, when they confirm, then a fresh WebAuthn assertion bound to that Tenant is required, `tenancy.tenant.prod_label_removed` is written to the Tenant's Log, and no row but `tenant.label` changes.
- Given a Tenant Owner raising a label, or moving between Dev and Staging, when they save, then no fresh assertion is asked for and `tenancy.tenant.label_changed` is written.
- Given a Tenant capability action, when its fresh assertion begins, then it begins on `POST /api/v1/tenants/{tenantId}/assertions` with the path Tenant in its binding, and a grant for one Tenant never serves another.
- Given a Deployment Owner holding no Tenant Role, when they land, then Tenants opens, or Create Tenant when there are none.
- Given any other Admin with no Tenant Role, when they land, then "You don't have access to a Tenant yet. Ask a Deployment Owner." shows.
- Given an Admin holding a Tenant Role, when they land, then their current Tenant's page opens.
- Given every new and changed browser test, when it runs, then no CSP violation occurs and axe finds no violation in light and dark at 1100 and 768px.

## Spec Change Log

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 23 findings — high 1, medium 9, low 13, false 0, maybe-false 0
- findings:
  - `[high]` `[patch]` Blind: the label lock is FOR UPDATE, which blocks every FK insert on the Tenant while a Prod removal runs, and GET takes it too — FOR NO KEY UPDATE for the change, a plain read for GET.
  - `[medium]` `[patch]` Blind: a label raised to Prod elsewhere sends a plain PUT and shows "forbidden" — the PUT always goes through the fresh-assertion helper.
  - `[medium]` `[patch]` Blind: unsaved changes are guarded only for picking another Tenant — every shell navigation, plus beforeunload.
  - `[medium]` `[patch]` Blind: a client abort after the gate rolls back the label with the grant used — the write finishes uncancellable.
  - `[medium]` `[patch]` Blind: a confirmed grant can outlive the change it was earned for — any label change clears it.
  - `[medium]` `[patch]` Blind: a failed switcher list makes every page unavailable — only the switcher and the landing degrade.
  - `[low]` `[patch]` Blind: the docs say localStorage never reaches a request, but it picks the landing Tenant — reworded.
  - `[low]` `[patch]` Blind: one global records the last Tenant write, so concurrent writes swap the banner's names — returned per request.
  - `[low]` `[patch]` Blind: a Tenant still being created shows an editable form — disabled, with the status from the label read.
  - `[low]` `[patch]` Blind: threat-model T-22 and T-53 cells put prose after their Tests lists — fixed.
  - `[medium]` `[patch]` Edge: stale loaded label — same fix as the Blind row.
  - `[medium]` `[patch]` Edge: GET takes a write lock — same fix as the Blind row.
  - `[low]` `[patch]` Edge: global last-write record — same fix as the Blind row.
  - `[low]` `[patch]` Edge: a path segment decoding to non-Latin-1 characters makes fetch throw on the header — only a well-formed ID is sent.
  - `[low]` `[patch]` Edge: a Tenant begin with a target for an action that has none makes an unusable grant — refused.
  - `[medium]` `[patch]` Gap: a failed switcher list is untested — tested, with the revised degrade behaviour.
  - `[low]` `[patch]` Gap: the Prod-removal modal's rate-limited and unavailable text is untested — added.
  - `[low]` `[patch]` Gap: a 401 on the label PUT is untested — renewal test added.
  - `[low]` `[patch]` Gap: the oldest-first order can't be told from insertion order — the test inserts out of order.
  - `[low]` `[reject]` Intent: the GK006 to 409 mapping is never reached over HTTP — the status check runs first; the trigger is tested directly.
  - `[low]` `[patch]` Intent: the switcher's ellipsis at 768 to 1099px is unproved — tested.
  - `[low]` `[patch]` Intent: a literal "-" in the mismatch banner is outside the message catalogue — moved.
  - `[medium]` `[patch]` Stack: before bootstrap the root sends the operator to sign-in, a dead end showing `signin_unavailable` — it now links to the bootstrap page.

## Design Notes

- **Why a header, when the path already names the Tenant.** AD-19 makes the path the only Tenant source, and Story 1.24 built that. A request built from the page's own mounted Tenant therefore always acts on the Tenant it names. The danger FR-9 and AD-19 name is a page that shows one Tenant while an action targets another. In this shell that can happen: Story 1.25 keeps the previous page mounted while the next route's reads are pending, so a form for A can still be on screen at `/tenants/ten_C/…`. The header carries what the shell shows at send time, and the server compares it with the path. A string compare can't select, widen or authorize anything: the capability decision has already run on the path alone. Placing it after that decision keeps every cross-Tenant attempt audited as `access_denied`. Placing it before the checks-enforced consume, and before the handler's gate, means a mismatched request never uses up a grant. `key={tenantId}` and the full-document switch close the same gap from the client side. The header proves it on the server.
- **Why switching is a document load.** EXPERIENCE says "Switching reloads the page in the new Tenant". A real load discards every component, timer and pending request from the old Tenant, including a renewal in flight. No React state from Tenant A can reach a Tenant B request. It costs one bundle load from cache.
- **The predicate is evaluated on a locked row.** `WhenProdTenant` must be true of the label the write replaces, not of a label read earlier. The handler takes `FOR UPDATE` on `tenant` in the path Tenant's transaction, decides `RemovesProd`, and only then consumes the grant, in its own committed transaction as Story 1.26 requires, before it writes. Two removals racing on one grant therefore produce one removal. The second either finds no grant or finds the label already changed. The callback keeps the gate in Host.Admin and the decision in Management, so no module reaches into the HTTP layer.
- **Why the Tenant's own chain.** FR-40 puts Admin changes in the Tenant's Logs, which a Tenant Owner reads. The Deployment Log belongs to Deployment Owners. `tenant` is a `control` table, so the write works in either scope. The `TenantScope` is there for the audit chain, opened on `AdminRequestChecks.PathTenant(context)` as Story 1.24's rule requires. The fresh assertion's own `admin.fresh_assertion.verified` stays on the Deployment chain, where Story 1.26 writes it.
- **"Relaxes no existing setting".** Today no setting reads the label, so the rule is that removing Prod writes nothing else, and the snapshot test proves it over every Tenant row. Later stories add label-dependent rules: the 90-day Prod retention floor, Prod callback confirmation, Dev-only email verification off, and the conformance Tenant. Each must read the label when its own setting is changed, and never rewrite an existing setting because the label changed. T-56 and the deferred items record that.
- **The Tenant begin reuses the complete.** The begin is where the Tenant enters the binding hash. The complete only verifies the assertion against the Session's pending challenge, whose row already carries that hash. A second, Tenant-path complete would add a route with nothing to decide. The begin is reachable with any Tenant Role (`tenant.configuration.read`) because a Tenant route must declare a Tenant capability. The action's own capability is then decided from the same grant row the checks read. So an Editor's begin for `tenant.label.manage` is refused and audited exactly as the action would be.
- **No role leaves the server.** The switcher list has no role, and the Tenant page's read-only states follow `has('tenant.label.manage')` and the `tenant.*.manage` capabilities. AD-20's comment in `capabilities.ts` ("the UI never names, compares or infers a role") still holds.
- **Active Tenants only in the switcher.** A `creating` Tenant has no settings, no keys and an unresolved host, and its label can't change (`GK006`). The Tenants page already shows its progress and Retry, so listing it in the switcher would add a destination with nothing to do there.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests`. Expected:
  - the build has no warnings;
  - the `@gatekeep/ui` checks pass (raw hex, dependencies, screens props-only);
  - the dashboard Node tests pass (`renewal.test.mjs`, `freshAssertion.test.mjs`, `tenantSubdomain.test.mjs`, `tenantName.test.mjs`, `currentTenant.test.mjs`);
  - the api-client tests and the API contract drift check pass against the regenerated files;
  - the Architecture tests pass, including `CapabilityRuleTests` with the new `HandlerEnforced` and `SelfService` entries, `TenantRuleTests`, the Admins registry rows, the unchanged module edges and the audit catalogue;
  - the Isolation tests pass: `TenantLabelTests`, `MyTenantsTests`, `TenantFreshAssertionTests`, `TenantMismatchTests`, `TenantTablesTests`, `RequestChecksTests`, every Story 1.24–1.27 test unchanged, and the canary scan;
  - the browser tests pass, including `admin-tenant-switcher`, the updated `admin-shell` and `admin-tenants`, and `admin-csp`.

  From a worktree, use a worktree-only image tag, not `gatekeep/tests:local`.
- After changing the endpoints, regenerate the contract in Docker with `sh deploy/docker/api-contract.sh --write <abs dir>` (as `docker compose -f deploy/compose.test.yaml run --rm --build -v "<repository>:/out" tests sh deploy/docker/api-contract.sh --write /out`). Regenerate the audit catalogue with the Generator. Commit both.

Nothing runs on the host.

## Auto Run Result

Status: done

**Summary:** an Admin switches Tenants from the top bar, which lists only the active Tenants they hold a role in, with each Tenant's environment badge. The path is the only source of the Tenant. Dashboard writes name the Tenant the page shows, and the server refuses a mismatch with `tenant_mismatch`, so an action never lands on a Tenant the Admin isn't looking at. Settings → Tenant changes the environment label. Removing Prod needs a fresh assertion bound to that Tenant, begun on a new Tenant-scoped route, and changes nothing but the label. Each change writes the Tenant's Log.

**Files:** the label migration and `TableRegistry`; `src/Modules/Tenancy/`, `Admins/`, `Management/`; `src/Gatekeep.Host.Admin/` (label API, my-tenants, Tenant fresh-assertion begin, request checks, OpenAPI); `docs/api/openapi-v1.json`, `packages/api-client/`; `packages/ui/` (Menu, TopBar); `apps/admin-dashboard/src/shell/` (switcher, Tenant settings, landing, current Tenant); `tests/Isolation/Tenancy/`, `Admins/`, `tests/Architecture/`, `tests/browser/admin-tenant-switcher.spec.ts`; `docs/audit-events.md`, the threat model and `install.md`.

**Review:** 23 findings across four layers: 22 patched, 0 deferred, 1 rejected, each with its reason in the triage log.

**Follow-up review:** recommended. Lock strength, grant clearing and the switcher's failure handling changed in review, with new tests as the only proof.

**Verification:** see the PR screenshot; the full suite passes in the `tests` container.

**Residual risks:** the switcher lists active Tenants only, without paging. The Tenant settings page stands in as the landing until Story 3.1.
