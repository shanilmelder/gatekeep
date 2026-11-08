---
title: 'Story 1.31: Run the cross-Tenant suite on every build'
type: 'feature'
created: '2026-11-08'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/_bmad-output/implementation-artifacts/epic-1-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** Tenant isolation (FR-8, AD-25, SM-2) is tested route by route, story by story. Nothing makes a new Admin, Management API, OAuth, OIDC or Hosted Login endpoint, a new artifact type, or a new job, cache or rate-limit type fail the build until it has a cross-Tenant case. `gk_hosted`'s AD-2 grant limits are also not asserted in one place.

**Approach:** Add code-owned registries in the test projects:
- **Routes.** Every live route of `Host.Admin` and `Host.Hosted` has a registry entry with an executable cross-Tenant case.
- **Artifacts.** The FR-8 artifact types are each covered or pending against a named backlog story.
- **Tenant-keyed types.** Job types, rate-limit policies and in-process caches are each declared Tenant-keyed or Deployment-wide.
- **Grants.** A grants test reads the live catalogue.

Any drift between code and a registry fails `build` in CI.

## Boundaries & Constraints

**Always:**
- The route set comes from the running hosts, never a hand-copied list:
  - `Host.Admin`: its `EndpointDataSource`, booted the way `AdminEndpointTests.RunningEndpointsAsync` does.
  - `Host.Hosted`: its `EndpointDataSource` plus the OpenIddict endpoint URIs it serves (`ProtocolContract`, `ProtocolServer.EndpointUris`).
  - A live route with no registry entry fails, and so does a registry entry that matches no live route.
- Every registry entry names exactly one case kind:
  - **`TenantPath`**: the route has `{tenantId}`. An Admin holding Owner in Tenant A calls it with Tenant B in the path (and in `X-Gatekeep-Tenant`). Expect 403 `access_denied` and exactly one `deployment_audit_event` row `admin.access.denied` whose target is Tenant B.
  - **`TargetTenant`**: a Deployment route naming `{targetTenantId}`. The same A-only Owner (not a Deployment Owner) targets Tenant B. Expect a refusal plus that audit row.
  - **`HostResolved`**: a Hosted route. Requested on Tenant B's host, the response carries only B's issuer and keys, never A's. For the token endpoint, the request is refused.
  - **`NotTenantBound`**: a pre-auth or self-service route with no Tenant in its path. It carries a one-line reason, and the test asserts the pattern has no `tenantId` or `targetTenantId` parameter.
- All `TenantPath` and `TargetTenant` entries run as one data-driven theory over the registry, so a new entry runs its case without new test code.
- **Artifact types.** The required set is fixed from FR-8: authorization code, refresh token, reset link, email code, verification link, invite, Passkey, Recovery Code.
  - Each is either `Covered` (by a named test) or `Pending("<story id>")`.
  - A missing type fails the build.
  - A `Pending` entry whose story is `done` in `_bmad-output/implementation-artifacts/sprint-status.yaml` fails, so the list can't shrink silently or go stale.
- **Tenant-keyed types.** Job types come from the production job registry. Rate-limit policies are every static `RateLimitPolicy` field found by reflection over the `src` assemblies. Caches are every field of type `ConcurrentDictionary<,>`, `IMemoryCache` or `MemoryCache` in the `src` assemblies.
  - Each must be in its registry as `Tenant` or `DeploymentWide(reason)`.
  - An unregistered type fails.
  - A `Tenant` cache must be keyed by a Tenant ID (`Guid`, or a key type with a `TenantId` member).
  - A `Tenant` job type must be `JobScope.Tenant` in the production registry.
- **Grants test.** It runs against a migrated database using `has_table_privilege` and `has_column_privilege` (or `information_schema`):
  - `gk_hosted` has no `SELECT` on any table named `admin*`, `tenant_role` or `deployment_*`.
  - `gk_hosted` has no `INSERT`, `UPDATE`, `DELETE` or `TRUNCATE`, at table or column level, on any table the registry marks as configuration.
- **Configuration marker.** `TableEntry` gains a required `TableUse Use` (`Configuration` | `Runtime`), so every new table must choose.
  - Configuration: `tenant`, `tenant_host`, `tenant_settings`, `tenant_role`, `admin`, `admin_credential`, `admin_recovery_code`, `bootstrap_state`, `signing_key`, `protection_key_wrap`, `migration_history`.
  - Runtime: every other table.
- Registry failure messages name the route, type or table and say what to add.

**Never:**
- No change to production behaviour, routes, capabilities or migrations. The only `src` changes are the `TableUse` marker and its values.
- Don't write cross-Tenant rejections to the Tenant's own Log; that's Story 7.4.
- Don't build pending artifact types or Tenant rate-limit counters.
- Don't hard-code the expected route list in the test that checks completeness.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Covered route | `GET /api/v1/tenants/{B}/label` with an A-only Owner | 403 `access_denied` and one `admin.access.denied` row targeting B | — |
| New unregistered route | the host maps a route the registry lacks | registry completeness test fails, naming the method and pattern | — |
| Stale entry | the registry lists a route the host no longer maps | test fails, naming the entry | — |
| Pending artifact, story done | `refresh token` is `Pending("2.10")` and 2.10 is `done` | artifact test fails | — |
| Unregistered cache | a new `ConcurrentDictionary` field in `src` | keyed-types test fails, naming the declaring type and field | — |
| Hosted grant regression | `GRANT SELECT ON admin_session TO gk_hosted` | grants test fails, naming the table | — |

</intent-contract>

## Code Map

- `src/Gatekeep.Host.Admin/AdminApi.cs:92` -- `MapAdminApi`, every Admin route. It has 5 `{tenantId}` routes (`capabilities`, `operations/{operationId}`, GET and PUT `label`, `assertions`), 3 `{targetTenantId}` deletion routes, plus deployment self-service and pre-auth routes.
- `src/Gatekeep.Host.Admin/Program.cs:44-51` -- `MapFallback("/api/{**path}")` and `MapFallbackToFile`. Register both as `NotTenantBound`, with the fixed 404 or static bundle as the reason.
- `src/Gatekeep.Host.Admin/AdminRequestChecks.cs:13-32,608-631,726` -- endpoint metadata (`TenantApiEndpoint`, `DeploymentApiEndpoint`, `RequiresCapability`). This is where the refusal is decided and audited (`AccessDeniedAuditPolicy`).
- `src/Gatekeep.Host.Hosted/Program.cs:23-30` -- tenant resolution, `UseGatekeepProtocol`, and `MapFallback(TenancyContract.NotFoundAsync)`.
- `src/Modules/Protocol/**/ProtocolContract.cs:17-21`, `ProtocolServer.cs:35-37,80` -- discovery `/.well-known/openid-configuration`, `/.well-known/jwks`, and `/connect/token`, which refuses everything until Story 2.5.
- `src/Adapters/Postgres/Schema/TableRegistry.cs` -- `TableEntry` record (add `TableUse`), 28 entries, role constants.
- `src/Modules/Operations/Core/ProductionJobs.cs`, `Contracts/JobRegistry.cs:6` -- `OperationsContract.ProductionRegistry`, `JobScope`.
- `src/Gatekeep.Kernel/RateLimiting/RateLimitPolicy.cs`, `src/Modules/Admins/Core/AdminAttemptLimiter.cs` -- policies are static fields in `AdminsContract`, all Deployment-scoped. The limiter throws on a Tenant context.
- `src/Modules/Protocol/Core/TenantRuntimes.cs:74` -- the only cache today, a `ConcurrentDictionary<Guid, Entry>` keyed by Tenant ID. Scan `src` for any other `ConcurrentDictionary` fields and classify each one.
- `tests/Isolation/Admins/AdminEndpointTests.cs:121-209` -- `RunningEndpointsAsync` plus `HostLoadContext`. Extract them into a shared helper and reuse them; don't duplicate.
- `tests/Isolation/Admins/AdminHost.cs` (`StartAsync`, `InsertTenantAsync` :508, `GrantTenantRoleAsync` :516, `OwnerWithCredentialsAsync`, `SendAsync`, `ScalarAsync`) and `tests/Isolation/Tenancy/TenantRequests.cs` (`OwnerOfAsync`, `RoleSessionAsync`, CSRF/fresh-assertion helpers, `Header`) -- real-process Admin calls.
- `tests/Isolation/Admins/TenantCapabilitiesTests.cs:64` -- the golden pattern for refused-and-audited.
- `tests/Isolation/Protocol/ProtocolHost.cs`, `DiscoveryAndJwksTests.cs:132` -- the Hosted TestServer with two Tenants (`ProtocolDatabase.AddTenantAsync`, `ProvisionAsync`).
- `tests/Isolation/CatalogueTests.cs`, `CatalogueAudit.cs` -- catalogue against the registry. The grants test sits beside them.
- `tests/Architecture/JobRegistryRuleTests.cs:181-199` -- reflection over the built `src` output; reuse its assembly loading for the keyed-types test.
- `deploy/docker/run-tests.sh:50,53` -- both test projects already run in CI `build`, so no CI change is needed.
- `_bmad-output/implementation-artifacts/deferred-work.md:188` -- the Story 1.31 item. The live route set already equals the OpenAPI paths, which `AdminEndpointTests:77` checks. Mark the item resolved.

## Tasks & Acceptance

**Execution:**
- `src/Adapters/Postgres/Schema/TableRegistry.cs` -- add `enum TableUse { Configuration, Runtime }` as a required `TableEntry` parameter, and classify all 28 entries as listed above. This is the AD-2 marker the grants test reads.
- `tests/Isolation/Hosting/RunningRoutes.cs` (new) -- shared live-route reader for `Host.Admin`, moved out of `AdminEndpointTests`, plus the `Host.Hosted` route set (`EndpointDataSource` and protocol endpoint URIs). Update `AdminEndpointTests` to use it.
- `tests/Isolation/CrossTenant/RouteRegistry.cs` (new) -- one entry per live route: method, pattern, case kind, reason for `NotTenantBound`, and the body or route values its case needs.
- `tests/Isolation/CrossTenant/RouteRegistryTests.cs` (new) -- checks registry completeness and staleness for both hosts, and that `NotTenantBound` patterns have no Tenant parameter. Also checks AR-13: `Host.Hosted` has no `/api/` route.
- `tests/Isolation/CrossTenant/CrossTenantRouteTests.cs` (new) -- a theory over the `TenantPath` and `TargetTenant` entries against one real Admin host with Tenants A and B, asserting refusal and the audit row. Facts for the `HostResolved` entries against `ProtocolHost`.
- `tests/Isolation/CrossTenant/ArtifactRegistry.cs` + `ArtifactRegistryTests.cs` (new) -- the 8 FR-8 types are all `Pending`: authorization code `2-9`, refresh token `2-10`, verification link `4-7`, reset link `4-11`, Passkey `6-3`, Recovery Code `6-8`, invite `8-3`, email code `14-6`. Match each to its `sprint-status.yaml` key by id prefix (for example `2-10-`). The tests check the required set and the sprint-status staleness rule.
- `tests/Architecture/TenantKeyedTypes.cs` + `TenantKeyedTypeTests.cs` (new) -- registries for jobs, rate-limit policies and caches, discovered by reflection, with the Tenant-key checks.
- `tests/Isolation/CrossTenant/HostedGrantsTests.cs` (new) -- AD-2 grants for `gk_hosted` on the migrated database. Also a registry-level check that `Configuration` tables grant `gk_hosted` no write.
- `_bmad-output/implementation-artifacts/deferred-work.md` -- mark the :188 item resolved by Story 1.31.
- `docs/threat-model.md` -- point T-1's cross-Tenant suite mention at `tests/Isolation/CrossTenant`.

**Acceptance Criteria:**
- Given the route and artifact registries, when an endpoint or artifact type has no cross-Tenant case, then the build fails.
- Given `gk_hosted`, when the grants test runs, then it has no `SELECT` on `admin*`, `tenant_role` or `deployment_*`, and no write on configuration tables.
- Given every registered Tenant-scoped Admin route, when it is presented at Tenant B with Tenant A's authority, then it is refused and a `deployment_audit_event` row is written.
- Given unbuilt artifact types, when the suite runs, then each is listed as pending against a story that isn't done.
- Given registered job, cache and rate-limit types, when the suite inspects them, then each is Tenant-keyed or a declared Deployment-wide type, and an unregistered one fails.

## Spec Change Log

## Review Triage Log

## Design Notes

- **Not-Tenant-bound routes.** Routes like `POST /deployment/signin` or `GET /deployment/session` can't be "presented at Tenant B", because no Tenant names them. The registry still holds them so a new route can't skip classification. A `NotTenantBound` entry can't hide a Tenant route, because the pattern check rejects any Tenant parameter.
- **Hosted's OIDC endpoints.** OpenIddict serves them as middleware, not endpoints, so they're added from the protocol endpoint URIs.
- **Authenticated attempts on Hosted.** Nothing on Hosted is authenticated until Epic 2, so no Hosted case asserts a Log row yet. Story 2.5 replaces the token case when the endpoint opens.
- Registry entry shape (illustrative):

```csharp
new("PUT", "/api/v1/tenants/{tenantId}/label", CaseKind.TenantPath, Body: """{"label":"dev"}"""),
new("POST", "/api/v1/deployment/signin", CaseKind.NotTenantBound, Reason: "pre-auth, no Tenant"),
```

## Verification

**Commands:**
- `docker compose -f deploy/compose.dev.yaml run --rm --build tests` -- expected: Architecture and Isolation pass, including the new `CrossTenant` and `TenantKeyedTypeTests`.
- Inside the tests container, temporarily add an unregistered `MapGet` (or remove one registry entry) -- expected: `RouteRegistryTests` fails, naming the route. Revert afterwards.
