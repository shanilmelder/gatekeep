---
title: 'Story 1.24: Enforce capabilities and Tenant-scoped routes'
type: 'feature'
created: '2026-11-04'
status: 'done'
baseline_revision: '7e8b71ca98a296d1fdc6c387949b19a0872f1cc6'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-gatekeep-2026-11-01/prd.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-21-claim-bootstrap-and-create-the-first-admin.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-23-sign-in-as-an-admin-with-webauthn.md'
  - '{project-root}/docs/threat-model.md'
warnings: [oversized]
deferred:
  - summary: >-
      No real Owner-only Deployment route exists to refuse a non-Owner over HTTP.
    evidence: |-
      Proved by the generated matrix and route rules. Story 1.27 adds Tenant creation.
    location: >-
      src/Gatekeep.Host.Admin/AdminRequestChecks.cs
    severity: low
---

<intent-contract>

## Intent

**Problem:** Today the only authorization in `Host.Admin` is "has a live Admin Session, and isn't held to setup". NFR-5, AR-15 and AD-20 require one capability table in the Admins contract to be the only encoding of the FR-39 matrix. Each capability declares `MachineAllowed` and `FreshAssertion`, and every fresh-assertion capability is machine-denied. A generated test must deny every role and machine principal every capability outside the table. AR-14 and AD-19 require Tenant-scoped actions under `/api/v1/tenants/{tenantId}/*`, with the Tenant taken from the path only and no server-side "current Tenant". They also put `/api/v1/deployment/*` behind the Deployment Owner, with no machine access. No `tenant_role` table exists, so nothing yet says which Admin may act in which Tenant. `GET /api/v1/deployment/capabilities` returns `[]` (Story 1.21 left it for this story). Story 1.21 left the Deployment Owner check on the surface to this story. No item in `deferred-work.md` targets Story 1.24.

**Approach:**
- **Capability table:** add `AdminCapabilities` to the Admins contract: the FR-39 matrix, split where `FreshAssertion` or `MachineAllowed` differ. Each capability has a scope (Deployment or Tenant), the Tenant Roles that hold it, `MachineAllowed` and `FreshAssertion`. A pure decision function sits beside the table.
- **Authorizer:** add `IAdminAuthorization`, which turns a principal (an Admin, or a machine client) and a path Tenant into a decision. It reads the Admin's `tenant_role` row on every request and caches nothing.
- **`tenant_role` table:** a new `control` table owned by Admins, read-only to `gk_admin` for now.
- **Route declarations:** every `/api/` route in `Host.Admin` declares exactly one access kind: a capability, self-service, or sessionless. The request checks enforce the declaration and deny by default.
- **Tenant capabilities endpoint:** add `GET /api/v1/tenants/{tenantId}/capabilities`, the first Tenant-scoped route. Its path Tenant ID is the AD-9 public ID (`ten_` + base32).
- **Deployment capabilities endpoint:** `GET /api/v1/deployment/capabilities` now returns the Deployment capabilities the caller holds.
- **Exhaustive tests:**
  - Architecture tests over the build-generated OpenAPI document. The build generates it from the route table, and the drift check holds it to the code.
  - An Isolation test over the running host's live route table, compared with that document.

## Boundaries & Constraints

**Always:**
- **The capability table (AD-20, AR-15):** `src/Modules/Admins/Contracts/AdminCapabilities.cs`. It is the only place FR-39 is encoded. No handler, request check, OpenAPI transformer or UI may restate a role-to-action rule.
  - `Capability` record fields:
    - `Name`: matches `^(deployment|tenant)\.[a-z_]+\.[a-z_]+$` and is unique.
    - `Scope`: `Deployment` or `Tenant`.
    - `Roles`: a set of `TenantRole` (`Viewer`, `Editor`, `Owner`). It is empty for Deployment scope.
    - `MachineAllowed`.
    - `FreshAssertion`: `Never`, `Always`, `WhenProdTenant` or `WhenLoweringPolicy`. A `When…` value is a predicate on the target, which the handler evaluates (AD-20).
  - The constructor throws when:
    - `FreshAssertion != Never` and `MachineAllowed` (V-1);
    - `Scope == Deployment` and `MachineAllowed` (AD-19);
    - `Scope == Deployment` and `Roles` isn't empty;
    - `Scope == Tenant` and `Roles` is empty.
  - `AdminCapabilities.All` lists every capability in a fixed order, and each one is also a named static field.
  - The table, `[ASSUMPTION: granularity and names]`:

    | Capability | Scope | Roles | Machine | FreshAssertion | FR-39 row |
    | --- | --- | --- | --- | --- | --- |
    | `tenant.configuration.read` | Tenant | V, E, O | Yes | Never | Read configuration and Users |
    | `tenant.users.read` | Tenant | V, E, O | Yes | Never | Read configuration and Users |
    | `tenant.logs.read` (summaries) | Tenant | V, E, O | Yes | Never | Read configuration and Users |
    | `tenant.log_detail.read` | Tenant | E, O | Yes `[ASSUMPTION]` | Never | Raw Log detail |
    | `tenant.applications.manage` (all but callback URLs) | Tenant | E, O | Yes | Never | Manage Applications, … |
    | `tenant.application_callbacks.manage` (create with, or change, callback URLs) | Tenant | E, O | No | WhenProdTenant | Manage Applications, … |
    | `tenant.apis.manage` | Tenant | E, O | Yes | Never | Manage Applications, … |
    | `tenant.roles.manage` (User RBAC Roles, FR-32) | Tenant | E, O | Yes | Never | Manage Applications, … |
    | `tenant.users.manage` | Tenant | E, O | Yes | Never | Manage Applications, … |
    | `tenant.theme.manage` | Tenant | E, O | Yes | Never | Manage Applications, … |
    | `tenant.templates.manage` | Tenant | E, O | Yes | Never | Manage Applications, … |
    | `tenant.settings.manage` | Tenant | E, O | Yes | Never | Configure Tenant settings, … |
    | `tenant.connections.toggle` | Tenant | E, O | Yes | Never | Configure Tenant settings, … |
    | `tenant.configuration.export` | Tenant | E, O | Yes | Never | Configure Tenant settings, … |
    | `tenant.client_secrets.manage` | Tenant | O | No | Always | Owner settings |
    | `tenant.password_policy.manage` | Tenant | O | Yes | Never | Owner settings |
    | `tenant.mfa_policy.manage` | Tenant | O | No | WhenLoweringPolicy | Owner settings |
    | `tenant.connection_credentials.manage` | Tenant | O | Yes | Never | Owner settings |
    | `tenant.email_provider.manage` | Tenant | O | No | Always | Owner settings |
    | `tenant.label.manage` | Tenant | O | No | WhenProdTenant | Owner settings |
    | `tenant.signing_keys.rotate` | Tenant | O | Yes | Never | Signing Keys; Management API access |
    | `tenant.signing_keys.revoke` | Tenant | O | No | Always | Signing Keys; Management API access |
    | `tenant.management_access.grant` | Tenant | O | No | Always | Signing Keys; Management API access |
    | `tenant.user_data.export` | Tenant | O | Yes `[ASSUMPTION]` | Never | Export or erase; FR-50 |
    | `tenant.user_data.erase` | Tenant | O | Yes `[ASSUMPTION]` | Never | Export or erase; FR-50 |
    | `tenant.incident_response.run` | Tenant | O | No | Always | Export or erase; FR-50 |
    | `deployment.tenants.read` | Deployment | — | No | Never | Deployment Owner (FR-7) |
    | `deployment.tenants.create` | Deployment | — | No | Never | Deployment Owner (FR-7) |
    | `deployment.tenants.delete` | Deployment | — | No | Always | Deployment Owner (FR-7) |
    | `deployment.admins.read` | Deployment | — | No | Never | Deployment Owner (FR-39) |
    | `deployment.admins.manage` (invite, remove, grant Tenant Roles, reset credentials) | Deployment | — | No | Always | Deployment Owner (FR-39) |
    | `deployment.email_provider.manage` | Deployment | — | No | Always | Deployment Owner (Story 8.1) |
    | `deployment.incident_response.run` | Deployment | — | No | Always | Deployment Owner (FR-50) |
    | `deployment.log.read` | Deployment | — | No | Never | Deployment Owner (FR-40) |

- **The decision (`AdminCapabilities.Allows`):** pure, with no I/O. For a capability, a principal's grant and an optional path Tenant:
  - **Deployment capability:** allowed only for an Admin who is the Deployment Owner. Never for a machine, and never because of any Tenant Role.
  - **Tenant capability, Admin:** allowed only when there is a path Tenant and the Admin's role in that Tenant is in `Roles`. Being Deployment Owner adds nothing in a Tenant: EXPERIENCE says "With a Tenant Role".
  - **Tenant capability, machine:** allowed only when there is a path Tenant, the machine principal's Tenant equals it (AD-19), and `MachineAllowed` is true.
  - Everything else is denied.
  - `FreshAssertion` isn't evaluated here. It is returned with the decision for Story 1.26 to enforce. Until then, no route may declare a capability whose `FreshAssertion` isn't `Never` (an architecture rule; see below).
- **Principals (Admins contract):**
  - `AdminPrincipal(AdminId, DeploymentOwner)` is built by the request checks from the authenticated `AdminSession`.
  - `MachinePrincipal(ClientId, TenantId)` is a public record. No `src/` code constructs it until Epic 17's Management API token validation. An architecture test fails on any `new MachinePrincipal(` under `src/`.
  - Tests build one through `tests/Isolation/Admins/TestOnlyMachinePrincipal.cs`, following `TestOnlyAuthenticator`. That is AC 3's "test-only machine principal at handler level".
- **`IAdminAuthorization` (Admins contract, built by `AdminsContract.CreateAuthorization(IAuditAppender)`):**
  - `AuthorizeAsync(CommandContext, Principal, Capability, Guid? tenantId, CancellationToken)` returns `CapabilityDecision(Allowed, FreshAssertion)`.
  - `HeldAsync(CommandContext, Principal, CapabilityScope, Guid? tenantId, CancellationToken)` returns the capabilities held, in table order.
  - Both run as `gk_admin` in a Deployment scope. For an Admin with a path Tenant, they read `SELECT role FROM tenant_role WHERE tenant_id = @t AND admin_id = @a` in the caller's transaction. Nothing is cached, so a role removed mid-session counts on the next request (Story 8.4).
  - They don't read `tenant`, which Tenancy owns (AD-1). An unknown Tenant and a Tenant the Admin holds no role in are the same answer.
  - `DenyAsync(CommandContext, AdminPrincipal, Guid? tenantId, CancellationToken)` appends `admin.access.denied`.
- **`tenant_role` (AD-27: Admins, `control`), migration `Migration20261104000000CreateTenantRoleTable`:**
  - Columns:
    - `tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT`: a single-column key to `tenant`, which AD-1 allows;
    - `admin_id uuid NOT NULL REFERENCES admin (id) ON DELETE RESTRICT`;
    - `role text NOT NULL CONSTRAINT tenant_role_role CHECK (role IN ('viewer', 'editor', 'owner'))`;
    - `created_at timestamptz NOT NULL DEFAULT clock_timestamp()`.
  - `PRIMARY KEY (tenant_id, admin_id)`, so an Admin holds one role per Tenant, plus an index on `admin_id` for Story 1.28's switcher.
  - Grants: `gk_admin` gets `SELECT` only. Story 1.27 adds `INSERT` (the creator becomes Tenant Owner), and Story 8.4 adds `UPDATE (role)` and `DELETE`. No other role gets anything; in particular `gk_hosted` gets no `SELECT` (AD-2).
  - The registry entry, the catalogue test and the `AdminApiRuleTests` registry theory are updated in the same change.
- **Route declarations (Host.Admin):**
  - Every endpoint under `/api/` except the `/api/{**path}` fallback carries an API marker, either `DeploymentApiEndpoint` or the new `TenantApiEndpoint`, and exactly one access declaration:
    - `RequiresCapability(Capability)`;
    - `SelfService`: a live Session, any Admin, acting only on their own Session, credentials or capability list;
    - `BootstrapClaimEndpoint` or `SignInEndpoint`: sessionless, unchanged.
  - Rules:
    - `/api/v1/deployment/*` routes declare a Deployment-scope capability, unless they are on the reviewed self-service or sessionless list.
    - `/api/v1/tenants/{tenantId}/*` routes declare a Tenant-scope capability. None is self-service or sessionless.
    - No `SetupAllowed` route declares a capability, because a restricted Session holds none.
  - Every `Map*` call for an API route is in `AdminApi.cs`. `Program.cs` keeps only the fallbacks.
  - Current routes:

    | Route | Declaration |
    | --- | --- |
    | `POST /api/v1/deployment/bootstrap` | sessionless (claim) |
    | `POST /api/v1/deployment/signin` | sessionless (sign-in) |
    | `POST /api/v1/deployment/signin/complete` | sessionless (sign-in) |
    | `GET /api/v1/deployment/session` | `SelfService`, setup-allowed |
    | `DELETE /api/v1/deployment/session` | `SelfService` |
    | `POST /api/v1/deployment/credentials/registration` | `SelfService`, setup-allowed |
    | `POST /api/v1/deployment/credentials/registration/complete` | `SelfService`, setup-allowed |
    | `GET /api/v1/deployment/capabilities` | `SelfService` |
    | `GET /api/v1/tenants/{tenantId}/capabilities` | `RequiresCapability(tenant.configuration.read)` (new) |

- **Request checks (`AdminRequestChecks`), deny by default:**
  - The prefix denial widens from `/api/v1/deployment` to `/api/`. An endpoint there with no API marker, or with not exactly one access declaration, is the unknown-path 404. The fallback included, nothing under `/api/` is reached unchecked.
  - The existing order is unchanged: Origin on state change (403), then Session (401), then CSRF on state change (403), then the setup restriction (bodiless 403).
  - Then, for `RequiresCapability`:
    1. For a `TenantApiEndpoint`, parse the `tenantId` route value with `PublicId.TryParse(PublicIdType.Tenant, …)`. A malformed value gives no path Tenant, so every Tenant capability is denied.
    2. Build the `AdminPrincipal` and call `AuthorizeAsync` in the same Deployment scope that authenticated the Session.
    3. On denial, call `DenyAsync`, commit, log `"An Admin request was refused with {Problem} for {Capability}, trace {TraceId}."`, and answer 403 `access_denied`.
    4. On allow, set the `PathTenant` feature (the parsed Guid) for the handler.
  - `SelfService` and the sessionless routes skip the authorizer.
  - A malformed, unknown or role-less Tenant, an insufficient role, and a non-Owner on a Deployment capability all give the same 403 `access_denied` body, with no other difference.
- **Path Tenant only (AD-4, AD-19):**
  - The Tenant comes only from the `{tenantId}` path segment.
  - No Session column, cookie, header or claim carries a Tenant, and no "current Tenant" exists server-side.
  - A Host.Admin handler that reaches `tenant` tables opens `TenantScope.BeginAsync` with `AdminRequestChecks.PathTenant(context)` as the Tenant, and with nothing else. An architecture rule scans `src/Gatekeep.Host.Admin` and fails on any `TenantScope.BeginAsync` call whose Tenant argument isn't that. No handler opens one in this story.
- **Public IDs (spine Conventions, AD-9):**
  - Add `src/Gatekeep.Kernel/Identifiers/PublicId.cs`. `PublicIdType.Tenant` is `ten`.
  - `PublicId.Format(type, Guid)` gives `ten_` + the 16 UUID bytes in RFC 4648 base32, lowercase alphabet `a–z2–7`, with no padding (26 characters) `[ASSUMPTION: alphabet and case]`.
  - `TryParse` accepts only the canonical form: the exact prefix, exactly 26 characters from the alphabet, and the final character's two unused bits zero. Every Tenant therefore has exactly one path spelling, and uppercase, padding or a second spelling is malformed.
- **`GET /api/v1/tenants/{tenantId}/capabilities`:**
  - 200 `CapabilitiesResponse` with the Tenant-scope capabilities the caller holds in the path Tenant, in table order.
  - Other responses: 401 with no Session; bodiless 403 for a restricted Session; 403 `access_denied` for a malformed, unknown or role-less Tenant; 503 for a database fault.
  - The `tenantId` path parameter is documented with pattern `^ten_[a-z2-7]{26}$`.
- **`GET /api/v1/deployment/capabilities`:** returns the Deployment-scope capabilities the caller holds through `HeldAsync`. That is all eight for the Deployment Owner and `[]` for any other Admin. It stays self-service and not setup-allowed.
- **OpenAPI (`AdminOpenApi`), regenerated with `sh deploy/docker/api-contract.sh --write <abs dir>`:**
  - Every operation carries `x-gatekeep-access`. The value is one of:
    - `{ "kind": "capability", "capability": "<name>", "scope": "tenant"|"deployment", "machineAllowed": bool, "freshAssertion": "never"|"always"|"whenProdTenant"|"whenLoweringPolicy" }`;
    - `{ "kind": "self" }`;
    - `{ "kind": "sessionless" }`.
  - The operation transformer throws when an operation has no declaration, or more than one, so the build that generates the document fails.
  - `CapabilitiesResponse.capabilities.items` is an enum of every capability name.
  - `ApiProblem.code` gains `access_denied`.
  - Capability operations document 403 with the `ApiProblem` schema.
  - `packages/api-client`:
    - `schema.generated.ts` is regenerated.
    - `client.ts` gains `getTenantCapabilities(tenantId)`, which substitutes the `encodeURIComponent`'d ID into the templated path. Its fetch wrapper test covers this.
- **Audit:** `admin.access.denied` is catalogued in `AdminsEvents` and in `docs/audit-events.md`, which the Generator regenerates in Docker.
  - It goes on the Deployment chain. The Actor is the Admin.
  - The target is the path Tenant's ID (`AuditTargetKind.Tenant`) when the path named a well-formed Tenant ID, whether or not that Tenant exists. Otherwise there is no target.
  - It is written in the request checks' transaction for every authenticated capability refusal (AD-9: "Authenticated cross-Tenant attempts always write a Log event").
  - It holds no Session ID, CSRF token or capability name. The capability name and the trace ID go only in the log line, under `{Capability}` and `{TraceId}`, never `{Code}`.
  - Origin, CSRF, Session and setup refusals aren't audited, as today.
- **Tests:**
  - **Generated (Isolation, `CapabilityMatrixTests`):**
    - Principals: Admin, Owner or not, with each role or none in the path Tenant, or a role only in another Tenant; and machine for the path Tenant or another Tenant.
    - For every principal × every capability × path Tenant present or absent, assert `Allows` equals the rule above, so nothing outside the table is ever allowed.
    - An independent FR-39 golden: the PRD rows written literally in the test, each mapped to its capabilities. It asserts that every Tenant capability belongs to exactly one row and holds exactly that row's roles.
    - An FR-46 golden: the capabilities whose `FreshAssertion` isn't `Never` are exactly the FR-46 list.
    - Every fresh-assertion capability, and every Deployment capability, is `MachineAllowed = false`.
  - **Handler level (Isolation, Testcontainers):** a `TestOnlyMachinePrincipal` for Tenant A, through `AuthorizeAsync` on a migrated database:
    - is allowed exactly the `MachineAllowed` Tenant capabilities in A;
    - is denied every capability in Tenant B, and with no Tenant;
    - is denied every Deployment capability.
  - **Route table (Architecture, over the committed document, which the drift check holds equal to the build):**
    - Every operation has `x-gatekeep-access`.
    - Each named capability exists in the table, read by reflection from the Admins build output, with matching scope, `machineAllowed` and `freshAssertion`.
    - Deployment paths declare only Deployment capabilities, or are on the reviewed self-service or sessionless lists.
    - Tenant paths declare only Tenant capabilities.
    - Setup-allowed operations declare none.
    - No declared capability has `freshAssertion` other than `never` (lifted by Story 1.26).
    - No Host.Admin source calls `ExcludeFromDescription`, and every API `Map*` call is in `AdminApi.cs`.
  - **Route table (Isolation, `AdminEndpointTests`, the running host's `EndpointDataSource`):**
    - Every `/api/` route but the fallback has a marker and exactly one access declaration.
    - The live route and method set equals the committed document's operations, so no route escapes the document.
  - Isolation HTTP tests for every matrix row below, using Testcontainers through `AdminHost`.
- **Docs:**
  - `docs/threat-model.md`:
    - update T-19 (authorization behind every route, deny by default), T-22 (fresh-assertion capabilities machine-denied in the table, enforcement in Story 1.26) and T-23 (the table invariant, and the generated and handler-level tests);
    - update T-1 for the path Tenant;
    - add T-53, an Admin acting outside their Tenant Role, or a non-Owner reaching Deployment actions, naming the controls and tests.
  - `docs/audit-events.md`: `admin.access.denied`.
  - `deferred-work.md`: the out-of-scope items below.

**Ask First:**
- **Self-service routes under `/api/v1/deployment`:** AC 2 says a non-Deployment Owner is refused on `/api/v1/deployment/*`. Sign-in, the Session read, sign-out, credential registration and the Deployment capability list are there too, and every Admin needs them (Story 8.3's invited Admins included). The spec exempts exactly those reviewed self-service and sessionless routes, and puts every other `/api/v1/deployment` route behind a Deployment-scope capability, which only the Owner holds. The alternative is to move the self-service routes to another prefix, which breaks the just-shipped contract, the dashboard and the Story 1.21–1.23 tests. Confirm before implementing.
- **Owner-only routes:** no route that only the Deployment Owner may call exists yet, so AC 2 is proven at handler level (the generated test), by the route rule (any non-exempt Deployment route needs a capability only the Owner holds), and over HTTP by `GET /api/v1/deployment/capabilities` returning `[]` for a non-Owner. The first Owner-only route, Story 1.27's create, carries its own HTTP refusal test. Adding an Owner-only route now just to test it needs asking.
- **Public ID encoding:** the `PublicId` alphabet and case. `sub` and `{tenantId}` use the public ID, and `sub` can never change once issued, so this can't change after the first Tenant token.
- Any change to the capability table's names, roles or flags beyond the table above, or a Tenant-scoped route that isn't capability-declared.

**Never:**
- No role-to-action rule outside `AdminCapabilities`, and no authorization engine (AD-20).
- No Tenant taken from a Session, cookie, header, query string, body or token claim alone. No server-side current Tenant.
- No Deployment Owner bypass of Tenant Roles: an Owner with no role in a Tenant gets nothing there.
- No caching of roles or decisions across requests.
- No machine access to any Deployment capability, or to any fresh-assertion capability.
- No `gk_hosted` grant on `tenant_role` or any other Admins table. No `tenant_role` write grant in this story.
- No UI change, so no browser test change. The Admin shell, and its use of the capability lists, is Story 1.25.
- **Out of scope**, recorded in `deferred-work.md`:
  - enforcing `FreshAssertion`, and lifting the no-fresh-capability route rule (Story 1.26);
  - building `MachinePrincipal` from Management API tokens, the Management API bearer scheme on `/api/v1/tenants/*`, and mapping each capability to the Management API Permission that grants it, as ADV-22 asks (Epic 17, Story 17.3);
  - the `tenant_role` `INSERT` grant and creator-as-Owner, plus the first Owner-only route and its HTTP refusal test (Story 1.27);
  - Tenant switching from roles, and the "no Tenant Role" landing (Story 1.28);
  - a deleted Tenant's roles granting nothing (Story 1.29);
  - the `UPDATE`/`DELETE` grants on `tenant_role`, auditing role changes, the last-Owner guard, and the "role removed mid-session" banner (Story 8.4);
  - writing rejected cross-Tenant attempts to the Tenant's own Log, the FR-40 class (Story 7.4);
  - the cross-Tenant suite reading the Tenant routes from `x-gatekeep-access` (Story 1.31);
  - catching `ARCHITECTURE-SPINE.md` up: the AD-19 self-service exemption, the public ID alphabet in Conventions, and the capability names in AD-20.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Viewer reads capabilities | Admin with `viewer` in Tenant A; GET `/api/v1/tenants/{ten_A}/capabilities` | 200, exactly `tenant.configuration.read`, `tenant.users.read` and `tenant.logs.read`, in table order | — |
| Editor and Owner | `editor`, or `owner`, in A | 200, exactly that row set of the table | — |
| Role in another Tenant | `owner` in A only; GET for Tenant B | `admin.access.denied` targeting B; nothing else written | 403 `access_denied` |
| Unknown Tenant | Well-formed `ten_` ID with no `tenant` row | Same body as above; event targets that ID | 403 `access_denied` |
| Malformed Tenant ID | `ten_` with uppercase, padding, 25 or 27 characters, another prefix, non-zero trailing bits, or a raw UUID | Same body; event with no target | 403 `access_denied` |
| Deployment Owner without a role | Owner, no `tenant_role` row in A | Owner bypass refused | 403 `access_denied` |
| Deployment Owner with a role | Owner with `viewer` in A | Only the Viewer set; no Deployment capability in the list | — |
| Role removed mid-session | `tenant_role` row deleted (superuser) between two requests | First 200, second 403: nothing cached | 403 |
| Restricted Session | Setup Session, or an Admin with one credential, on the Tenant route | The setup gate refuses before the capability check; nothing audited | Bodiless 403 |
| No Session | No cookie, or an ended or expired one | Unchanged Story 1.21 behaviour | 401 |
| Deployment capabilities, Owner | Owner's full Session; GET `/api/v1/deployment/capabilities` | 200, all eight `deployment.*` capabilities in table order | — |
| Deployment capabilities, non-Owner | Non-Owner, two credentials | 200, `[]` | — |
| Self-service, non-Owner | Non-Owner calls GET and DELETE session, and registration begin | Same as the Owner: self-service isn't Owner-gated | — |
| Unknown API path | GET `/api/v1/tenants/{ten_A}/nope`, or `/api/v1/other` | The unknown-path 404, never the bundle | 404 |
| Machine at handler level | `TestOnlyMachinePrincipal` for A, every capability | Allowed exactly the `MachineAllowed` Tenant capabilities in A; denied in B, with no Tenant, and on every Deployment capability | Decision `Allowed = false` |
| Generated matrix | Every principal × capability × Tenant | Nothing outside the table is allowed; FR-39 and FR-46 goldens hold | Test fails otherwise |
| Undeclared route | An API route with no, or two, access declarations | Document generation throws (build fails); the live-route test fails; at runtime the unknown-path 404 | Build or test fails |
| Fresh-assertion route | A route declaring a capability whose `FreshAssertion` isn't `Never` | Architecture test fails until Story 1.26 | Test fails |
| `tenant_role` constraints | A second row for the same Admin and Tenant; role `admin`; a row for a missing Tenant or Admin; deleting a Tenant with roles | Unique violation; CHECK violation; FK violation; RESTRICT | Database error |
| `tenant_role` grants | `gk_hosted` or `gk_cli` SELECT; `gk_admin` INSERT, UPDATE or DELETE | Permission denied; the catalogue matches the registry | Database error |
| API contract | `api-contract.sh` | The document and client match the build, with `x-gatekeep-access` on every operation | Drift fails CI |

</intent-contract>

## Code Map

- `src/Gatekeep.Kernel/Identifiers/PublicId.cs`: a new file, with `PublicIdType` (`Tenant` = `ten`), `Format` and a strict canonical `TryParse`.
- `src/Modules/Admins/Contracts/`:
  - a new `AdminCapabilities.cs`: `Capability`, `CapabilityScope`, `TenantRole`, `FreshAssertion`, the table with its named fields and `All`, and the pure `Allows`;
  - a new `IAdminAuthorization.cs`: `Principal`, `AdminPrincipal`, `MachinePrincipal`, `CapabilityDecision` and the interface;
  - `AdminsContract.cs`: `CreateAuthorization(IAuditAppender)`;
  - `AdminsEvents.cs`: `AccessDenied` (`admin.access.denied`).
- `src/Modules/Admins/Core/AdminAuthorization.cs`: a new file. It reads `tenant_role` in the caller's transaction, makes the pure decision, and appends the denial event.
- `src/Adapters/Postgres/Migrations/Migration20261104000000CreateTenantRoleTable.cs`: a new migration. `Schema/TableRegistry.cs` gets the `tenant_role` entry (`control`, Admins, `gk_admin` `SELECT`).
- `src/Gatekeep.Host.Admin/`:
  - `AdminRequestChecks.cs`:
    - the `TenantApiEndpoint`, `RequiresCapability` and `SelfService` metadata;
    - the `/api/` prefix denial and the one-declaration check;
    - the authorize step, `PathTenant(context)` and the denial log line.
  - `AdminApi.cs`:
    - a declaration on every route;
    - `GET /api/v1/tenants/{tenantId}/capabilities`;
    - `GET /api/v1/deployment/capabilities` filled through `HeldAsync`.
  - `AdminResponses.cs`: `access_denied` added to `ProblemCodes`, and `AccessDeniedAsync`.
  - `AdminOpenApi.cs`:
    - `x-gatekeep-access`, which throws on a missing or double declaration;
    - the capability-name enum;
    - the `tenantId` pattern and the 403 problem response;
    - the document description naming the Tenant surface.
  - `AdminApiServices.cs`: `Authorization`.
- `docs/api/openapi-v1.json` and `packages/api-client/src/schema.generated.ts`: regenerate with `sh deploy/docker/api-contract.sh --write <abs dir>` in Docker.
- `packages/api-client/src/client.ts`: `getTenantCapabilities` and the `TenantCapabilities` type. `test/client.test.mjs` covers the path substitution and encoding.
- `tests/Isolation/Admins/`:
  - new `CapabilityMatrixTests.cs` (the generated and golden tests, plus the handler-level machine test on Testcontainers);
  - new `TestOnlyMachinePrincipal.cs`;
  - new `TenantCapabilitiesTests.cs` (HTTP, every matrix row);
  - `AdminEndpointTests.cs`: the live route table check against the committed document;
  - `AdminTablesTests.cs`: the `tenant_role` constraints and grants;
  - `AdminHost.cs`: `InsertTenantAsync`, `GrantTenantRoleAsync` and `RevokeTenantRoleAsync` as superuser, and a full Owner Session helper built on `AdminWithCredentialsAsync` plus `SignInAsync`.
- `tests/Isolation/Identifiers/PublicIdTests.cs`: a new file, covering the round trip and every non-canonical form.
- `tests/Architecture/`:
  - `AdminApiRuleTests.cs`:
    - the registry theory row for `tenant_role`;
    - `Every_deployment_endpoint_is_behind_the_request_checks` widened to both prefixes and the declarations;
    - `Problem_responses_use_the_problem_schema` accepting 403;
    - `Every_operation_states_its_auth…` covering the Tenant path.
  - New `CapabilityRuleTests.cs`:
    - the document's `x-gatekeep-access` rules, checked against the table by reflection;
    - no fresh-assertion route;
    - no `new MachinePrincipal(` under `src/`;
    - no `ExcludeFromDescription`, and every `Map*` call in `AdminApi.cs`;
    - the `TenantScope.BeginAsync` path-Tenant rule;
    - no Admins-owned table granting anything to `gk_hosted`.
  - `AuditCatalogueTests` covers the new code.
- `docs/threat-model.md`, `docs/audit-events.md` (regenerated by `tests/Architecture/Generator`, in Docker), `_bmad-output/implementation-artifacts/deferred-work.md`.

## Tasks & Acceptance

**Execution:**
- [x] Kernel `PublicId`, with Isolation tests.
- [x] Migration and registry: `tenant_role` (keys, CHECK, RESTRICT, `SELECT`-only grant), with the catalogue and `AdminApiRuleTests` updates.
- [x] Admins: `AdminCapabilities` (the table, constructor invariants and `Allows`), the principals, `IAdminAuthorization` and `AdminAuthorization`, and the `admin.access.denied` event.
- [x] Host.Admin: the markers and declarations on every route; the request checks' `/api/` deny-by-default, one-declaration check, authorize step and `PathTenant`; the Tenant capabilities endpoint and the filled Deployment one; `access_denied`; the OpenAPI extension and the throw; then regenerate the document and the client.
- [x] api-client: `getTenantCapabilities` and its test.
- [x] Tests: generated and golden matrix; handler-level machine test; Tenant capabilities HTTP tests for every matrix row; live route table against the document; `tenant_role` table tests; Architecture `CapabilityRuleTests` and the `AdminApiRuleTests` updates.
- [x] Docs: the threat model (T-1, T-19, T-22, T-23, new T-53), `audit-events.md` through the Generator, and `deferred-work.md` (out-of-scope items and the spine catch-up).

**Acceptance Criteria:**
- Given the capability table in the Admins contract, when the generated test runs, then every role and machine principal is denied every capability outside it, and every `FreshAssertion` capability is `MachineAllowed = false`.
- Given a non-Deployment Owner, when they call `/api/v1/deployment/*`, then the server refuses every route outside the reviewed self-service and sessionless list. No such route exists yet: this is proven by the generated test, by the route rule, and by a non-Owner holding no Deployment capability.
- Given a test-only machine principal at handler level, when it calls any capability, then it follows `MachineAllowed` (and its own Tenant), so later stories can test machine denial before the Management API exists.
- Given the capabilities endpoint, when the UI calls it, then it returns the caller's capabilities for the path Tenant, and refuses a Tenant where the caller holds no role.
- Given any route under `/api/`, when the route table is checked, then each declares exactly one access kind, and the live table equals the committed document.

## Spec Change Log

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 21 findings — high 0, medium 7, low 14, false 0, maybe-false 0
- findings:
  - `[medium]` `[patch]` Blind: any signed-in Admin can flood the Deployment chain with `admin.access.denied` against IDs they choose — denials are rate-limited per Admin; over the limit they are logged, not audited.
  - `[medium]` `[patch]` Blind: the check and the handler read the role in separate transactions, so a revoked role can answer 200 with an empty list — the handler uses the grant the checks read.
  - `[low]` `[patch]` Blind: the Tenant route's 403 is documented with a body, but a setup Session gets a bodiless one — both shapes documented and tested.
  - `[low]` `[patch]` Blind: "only the canonical spelling" is wrong for percent-encoded paths — the doc says after URL decoding.
  - `[low]` `[patch]` Blind: static files are served before the request checks — paths under `/api` are never served as files.
  - `[low]` `[patch]` Blind: a future Deployment route with `{tenantId}` would 500 — such a route is undeclared.
  - `[low]` `[patch]` Blind: `PublicId.TryParse` throws on an undefined type and other docs contradict the code — fixed.
  - `[low]` `[patch]` Blind: the capabilities list hangs on `configuration.read` — a test pins that every role holds it.
  - `[medium]` `[patch]` Blind: missing tests for path variants, bad declarations at runtime, a failed denial write, an exact Malformed count and an Owner-only route over HTTP — added.
  - `[medium]` `[patch]` Edge: role read twice — same fix as the Blind row.
  - `[medium]` `[patch]` Edge: unbounded denial events — same fix as the Blind row.
  - `[low]` `[patch]` Edge: the published `tenantId` pattern accepts IDs the server refuses — described as necessary, not sufficient.
  - `[low]` `[patch]` Edge: the RESTRICT test passes through another table's key — uses an Admin referenced only by `tenant_role`.
  - `[low]` `[patch]` Edge: the route-rule comment stripper and Map regex can be fooled — literal-aware stripping and every `Map*` caught, with self-checks.
  - `[medium]` `[patch]` Gap: a failed `admin.access.denied` write is untested — a trigger test proves 503, no row and the slide rolled back.
  - `[low]` `[patch]` Gap: the test-only machine-principal scan doesn't skip `bin` — skipped.
  - `[medium]` `[patch]` Intent: undeclared or doubly declared routes aren't proved at runtime or build time — unit theory over the declaration plus a runtime 404 test.
  - `[low]` `[defer]` Intent: no HTTP test refuses a non-Owner on a Deployment capability — Story 1.27 adds the first real Owner-only route.
  - `[low]` `[reject]` Intent: the machine half of the generated matrix reads the table it tests — the separate FR-42 literal rule pins the outcome.
  - `[low]` `[reject]` Intent: registration is only shown refused alike for Owner and non-Owner — the self-service route list and the Session tests prove the exemption.
  - `[low]` `[patch]` Intent: a stray rerun script was staged — removed.

## Design Notes

- **Granularity of the table:** FR-39's seven rows are split only where `FreshAssertion` or `MachineAllowed` differ, or where a handler would otherwise need a predicate the table can't name. Two examples:
  - Callback URLs are their own capability (ADV-22), because FR-46 makes changing a Prod Tenant's callbacks fresh, AD-20 extends that to creating an Application with them, and FR-42 machine-denies such actions in every Tenant.
  - Signing Key rotate and revoke differ in the same way.

  The FR-39 golden test ties every Tenant capability back to exactly one PRD row, so a split can never drift from the matrix. The machine flags marked `[ASSUMPTION]` follow FR-42 literally: only Admin management and FR-46 actions are excluded.
- **Why the decision is pure and the table is data:** the generated test has to enumerate everything, and Story 1.26 and Epic 17 add evaluation (fresh assertion, Permissions) around the decision without changing it. Keeping `Allows` free of I/O lets the matrix test run with no database. The handler-level machine test still goes through `AuthorizeAsync` on Testcontainers, so the I/O path is proven too.
- **Deployment Owner gets nothing in a Tenant:** EXPERIENCE's Role Capabilities table says "With a Tenant Role", and Story 1.28 lands a role-less Owner on Tenants. PRD FR-8 allows the Owner only the FR-7 and FR-50 Deployment actions, which are Deployment capabilities here. A bypass would make the role table decorative for the most powerful account.
- **One 403 for every Tenant refusal:** a malformed ID, an unknown Tenant, a Tenant with no role and an insufficient role all answer 403 `access_denied`, so the Tenant route can't be used to discover which Tenants exist. Unlike the bodiless Origin, CSRF and setup refusals, this 403 carries a problem body with the trace ID, which Story 1.25's "You don't have access to this page." shows. The authorizer doesn't read `tenant` (Tenancy's table, AD-1), so the event targets the path ID as given, whether or not the Tenant exists.
- **Auditing refusals:** AD-9 says authenticated cross-Tenant attempts always write an event. Only an authenticated, unrestricted Admin reaches the capability check, so writing `admin.access.denied` there can't be flooded anonymously. It goes on the Deployment chain now. The Tenant Log class waits for Story 7.4.
- **Exhaustiveness without referencing the host from Architecture:**
  - The Architecture project references only Kernel. It reads the committed OpenAPI document, which the build generates from the route table through ApiExplorer, and which `api-contract.sh` holds byte-equal to the build.
  - Two things close the gaps around that document. The operation transformer throws on an undeclared operation, and no source may call `ExcludeFromDescription`. `AdminEndpointTests` already reads the running host's `EndpointDataSource`, and now asserts the live route set equals the document's.
  - At runtime, the request checks deny an undeclared `/api/` endpoint with the unknown-path 404. So an undeclared route fails the build, the tests and the request, all three.
- **No caching:** roles are read on every request, in the transaction that slides the Session. That is one extra indexed primary-key lookup per Tenant request, and it means Story 8.4's "role removed mid-session" needs no invalidation.
- **`tenant_role` is `control`:** AD-27 puts it there, because Story 1.28's switcher lists one Admin's roles across Tenants, which a Tenant-scoped RLS table can't do in one scope. Its `tenant_id` is therefore not an RLS key, and the request checks filter by the path Tenant in code, like `operation_step` (T-1).
- **Capping the denial audit (review):** a refused capability names a Tenant ID the caller chose, which may not exist, so unlimited refusals could flood the Deployment chain. Every refusal is counted per Admin through the Admins `IRateLimiter` under `admins.access.denial_audit` (30 in 15 minutes, `SecurityLimits`), in the request checks' transaction. Within the cap it writes `admin.access.denied` as before; past it the answer is the same 403 `access_denied`, and the refusal is only logged (`audited False`). AD-9 caps rejected events per source in the same way.
- **One role read per request (review):** the check reads the Tenant Role, and the decision returns the grant it read. The request checks put it in `PathTenantFeature`, and the Tenant capabilities handler answers from it through the pure `AdminCapabilities.Held`, with no second read. Otherwise a role revoked between the two transactions would give a 200 with an empty list.
- **Fresh assertion is declared now, enforced in Story 1.26:** the architecture rule that no route may declare a fresh-assertion capability makes this fail closed. A sensitive route can't ship before its enforcement does.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests`. Expected:
  - the build has no warnings;
  - the api-client tests pass;
  - the API contract drift check and its self-check pass;
  - the Architecture tests pass (`CapabilityRuleTests`, `AdminApiRuleTests` and `AuditCatalogueTests` included);
  - the Isolation tests pass on Testcontainers (`CapabilityMatrixTests`, `TenantCapabilitiesTests`, `AdminEndpointTests`, `AdminTablesTests` and `PublicIdTests` included);
  - the existing browser tests are unchanged and pass.

  From a worktree, use a worktree-only image tag.
- `sh deploy/docker/api-contract.sh --write <abs dir>` (in the tests container, with the repository mounted) regenerates `docs/api/openapi-v1.json` and `packages/api-client/src/schema.generated.ts`.
- `dotnet run --project tests/Architecture/Generator` (in Docker, with the repository mounted) regenerates `docs/audit-events.md`.

Nothing runs on the host.

## Auto Run Result

Status: done

**Summary:** one server-side capability table in the Admins contract holds every Tenant and Deployment capability, with its roles, machine flag and fresh-assertion rule. Every `/api/` route declares exactly one capability, self-service or sessionless access, or answers the unknown-path 404. Each request reads the Admin's `tenant_role` row for the Tenant named in the path, the only source of the Tenant. The Deployment Owner gets nothing in a Tenant without a role. A refusal is one 403 `access_denied`, audited on the Deployment chain within a per-Admin limit. A new `GET /api/v1/tenants/{tenantId}/capabilities` lists what the caller holds, and Tenant public IDs take the `ten_` base32 form.

**Files:** `src/Gatekeep.Kernel/Identifiers/PublicId.cs`; `src/Modules/Admins/` (capability table, authorization); the `tenant_role` migration and `TableRegistry`; `src/Gatekeep.Host.Admin/` (request checks, API, OpenAPI); `docs/api/openapi-v1.json`, `packages/api-client/`; `tests/Architecture/CapabilityRuleTests.cs`, `AdminApiRuleTests.cs`; `tests/Isolation/Admins/` (capability matrix, Tenant capabilities), `tests/Isolation/Identifiers/`; `docs/audit-events.md` and the threat model.

**Review:** 21 findings across four layers: 18 patched, 1 deferred, 2 rejected, each with its reason in the triage log.

**Follow-up review:** recommended. The single role read and the denial rate limit changed in review, with new tests as the only proof.

**Verification:** see the PR screenshot; the full suite passes in the `tests` container.

**Residual risks:** fresh assertion isn't enforced yet, so routes needing it are refused by rule until Story 1.26. No real Owner-only route exists until Story 1.27. Machine principals are test-only until Epic 17.
