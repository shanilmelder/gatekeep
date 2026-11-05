---
title: 'Story 9.1: View Signing Keys'
type: 'feature'
created: '2026-11-06'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-9-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-2-3-publish-discovery-and-jwks-per-tenant.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-2-4-rotate-signing-keys-automatically.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-28-switch-tenants-and-set-the-environment-label.md'
  - '{project-root}/design/Gatekeep Admin.dc.html'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** FR-37 and UX-DR44 need a Signing keys page. An Admin should see a Tenant's keys in every state (`next`, `current`, `previous`, `retired`, `revoked`), each key ID in mono with Copy, and the public JWKS sample below them. Today nothing in Host.Admin can read keys:
- `gk_admin` has no grant on `signing_key`.
- `host-admin.hcl` has no `read` on `transit/keys/sig-*`, so Host.Admin can't fetch public halves.
- `KeysContract` reads only the published rows (`ReadPublishedSigningKeysAsync`).
- The Dashboard has no Security nav item.

**Approach:**
- Two read-only Tenant routes on Host.Admin, both under `tenant.configuration.read`, which every Tenant Role holds:
  - `GET /api/v1/tenants/{tenantId}/signing-keys` returns the rows, read from Postgres only.
  - `GET /api/v1/tenants/{tenantId}/signing-keys/jwks` returns the public JWKS sample, built from custody's public halves.
- A new Keys read, a Management service that re-checks the capability (AD-5), one migration for the grant, and one policy line.
- The Dashboard gains the "Signing keys" page in the Security group. A JWKS failure never hides the table.

## Boundaries & Constraints

**Always:**
- **Scope of keys:** only `purpose = 'signing'` rows are listed and sampled. Management keys (AD-33) never appear in either response, in the page, or in a log.
- **List order and content:**
  - Order: `next`, then `current`, then `previous`, then `retired` and `revoked` rows together by `created_at DESC, id DESC`.
  - Retired rows are listed whether or not `destroyed_at` is set.
  - Each row carries `keyId` (`SigningKeys` format `{transit name}.v{version}`), `algorithm` (`"RS256"`, the algorithm Host.Hosted signs with), `state` and `createdAt` (ISO 8601 UTC).
  - It carries nothing else: no Transit ciphertext, no row UUID beyond what `keyId` already contains, no `published_at` or other lifecycle columns.
- **JWKS sample:**
  - Keys are the Tenant's published rows (`ReadPublishedSigningKeysAsync`: `current`, `next`, `previous`), in that order.
  - Each key has exactly the public members Host.Hosted's JWKS serves for it, expected to be `{ kty: "RSA", use: "sig", alg: "RS256", kid, n, e }` (confirm against `DiscoveryAndJwksTests`). `n` and `e` are base64url without padding, from `KeysContract.RsaPublicParameters` over the PEM custody returns for that row's `transit_version`.
  - It never holds a private member (`d`, `p`, `q`, `dp`, `dq`, `qi`).
  - The response also carries `jwksUri` = the Tenant's issuer + `/.well-known/jwks` (the path `ProtocolContract` serves).
  - A custody failure, or a published row whose version custody doesn't return, gives the existing fixed 503 for the whole sample. The list route doesn't depend on custody.
- **Schema:** new migration `Migration20261106090000ViewSigningKeys`, which runs `GRANT SELECT ON signing_key TO gk_admin`. In `TableRegistry`, `signing_key` gains `[Admin] = [Select]`. Row-level security applies unchanged, and no other privilege is granted.
- **Custody policy:** `deploy/openbao/policies/host-admin.hcl` gives `transit/keys/sig-*` the capabilities `["update", "read"]`, keeping its parameter rules. Update the header comment ("it has no read …") to say it reads Signing Keys' public halves for the Signing keys page (Story 9.1). `mgmt-*` stays `update` only.
- **Keys contract:** `KeysContract.ListSigningKeysAsync(CommandContext, CancellationToken)` returns `IReadOnlyList<ListedSigningKey(KeyName Key, int Version, SigningKeyState State, DateTimeOffset CreatedAt)>`.
  - New public enum `SigningKeyState` in `SigningKeys.cs` covers all five states.
  - The SQL lives in `Keys/Core` and names `WHERE tenant_id = @tenant_id AND purpose = 'signing'`.
  - It rebuilds and checks the name the way `TenantKeys.ReadPublishedAsync` does.
  - It needs a Tenant context, otherwise it throws `InvalidOperationException`. It only reads.
- **Management:** new `ISigningKeyManagement` in `Management/Contracts`, with its implementation in `Core` and registration beside `ITenantManagement`.
  - `ListAsync(context, principal, grant, tenantId)` and `GetJwksAsync(…)` each re-check `AdminCapabilities.Allows(TenantConfigurationRead, …)` as `TenantManagement` does, giving `Forbidden` otherwise.
  - `GetJwksAsync` reads the issuer through the Tenancy contract. Add an `ITenants` read in the Tenant's own context if none returns it.
  - Each key's public half comes from `IKeyCustody.GetPublicKeysAsync`. A `KeyCustodyException` becomes `Unavailable`.
  - It writes no audit event, because reads aren't state changes.
- **Routes (`AdminApi.cs`, handlers in new `SigningKeysApi.cs`, modelled on `GET …/label` and `TenantLabelApi.cs`):**
  - Both routes use `TenantApiEndpoint.Instance` and `RequiresCapability(TenantConfigurationRead)`, open `TenantScope.BeginAsync(services.Source, PathTenant)`, and send `Cache-Control: no-store`.
  - Answers: 200; 401; 403 `access_denied`; the fixed 503 (any `DbException`, or custody `Unavailable`).
  - Path IDs are handled as other Tenant routes handle them.
  - Shapes: `SigningKeysResponse { keys: SigningKeyResponse[] }` and `SigningKeysJwksResponse { jwksUri, keys: JwkResponse[] }`.
  - OpenAPI summaries and descriptions follow the existing ones.
- **Generated artifacts:**
  - `docs/api/openapi-v1.json` and `packages/api-client/src/schema.generated.ts` are regenerated in Docker (`sh deploy/docker/api-contract.sh --write <abs dir>`).
  - `client.ts` gains `listSigningKeys(tenantId)` and `getSigningKeysJwks(tenantId)`, each with the ID encoded in the path. `client.test.mjs` covers both.
- **Dashboard (`apps/admin-dashboard`, `packages/ui`; every string in `messages.tsx`; no inline style or script; no new runtime dependency):**
  - **Navigation:**
    - `nav.ts` gains `{ group: 'security', label: 'navSigningKeys', href: t => /tenants/{t}/signing-keys, requires: 'tenant.configuration.read' }`.
    - `Shell.tsx`'s `TENANT_ROUTE` and its page branch accept `/signing-keys`, keyed by `tenantId` like Settings.
  - **Page:** new `src/shell/SigningKeysPage.tsx`, using `SectionPage`.
    - Title "Signing keys". Description "Keys used to sign ID and access tokens. Rotate regularly; revoke if compromised." (design L1277).
    - A `DataTable` with the columns Key ID, Algorithm, Status and Created, and no Expires column.
    - The Key ID cell is `<code>` plus `CopyButton` (`what` "key ID"). Created is shown as a date.
  - **Badge:** new `KeyStateBadge` in `packages/ui` (exported from `admin.ts`). Next = info, Current = ok, Previous = muted, Retired = muted, Revoked = bad. The text carries the meaning. Colours come from existing tokens only (`check-no-raw-hex`).
  - **JWKS:**
    - Below the table, a `CodeBlock` titled "JWKS · {jwksUri}" holds the pretty-printed `{ "keys": [...] }`, with its own Copy.
    - `n` is shown in full, because Copy must give a usable JWKS.
  - **Loading and errors:**
    - Loading shows `SkeletonRows` (the existing 300 ms rule).
    - A failed list read shows the page's failed state with `ErrorReference`.
    - A failed JWKS read shows, in place of the block, "Couldn't load the public keys." with `ErrorReference`, and the table stays.
    - A 403 shows the existing forbidden page.
  - Story 9.1 adds no Rotate or Revoke control and no view-only banner.
- **Docs:**
  - `docs/threat-model.md`: the "exists in code" list adds Story 9.1. T-45 (or the Host.Admin custody control) notes the new public-half read, with the test names.
  - `docs/install.md`: the "Not yet covered" Admin item mentions Signing keys being viewable.

**Ask First:**
- **Management keys are not listed.** "Signing Key" and "Management key" are distinct terms (AD-33), and the page title is "Signing keys". Confirm before showing `mgmt-` rows in the table.
- **The JWKS sample is built by Host.Admin from custody**, which needs the new `read` on `sig-*`. Confirm before instead fetching Host.Hosted's public endpoint over the network.
- **Copy text `[ASSUMPTION]`:** "Couldn't load the public keys.", the badge labels "Next", "Current", "Previous", "Retired" and "Revoked", and the nav label "Signing keys".

**Never:**
- No private key material, Transit ciphertext, `transit_name` as a separate field, or Management key anywhere in either response, the page, or logs.
- No new capability, no write route, no audit event, no state change and no `UPDATE`/`INSERT` grant to `gk_admin`.
- No `read` on `mgmt-*` or on any secret class key for Host.Admin, and no `exportable` path.
- No query that spans Tenants (AD-4).
- Out of scope: Rotate (9.2), Revoke and its modal (9.3), the "Tenant Owner only" read-only controls (9.2 and 9.3).

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Fresh Tenant | Viewer of A; A has one `current` and one `next` per purpose | List: 2 rows (next, current), signing only. JWKS: 2 keys (current, next) with `kid` equal to the rows' `keyId` | — |
| Every state | A seeded with signing rows in all five states, plus a destroyed retired row and management rows | List order: next, current, previous, then retired and revoked newest first; 6 rows; no `mgmt-`. JWKS: current, next, previous only | — |
| No private material | Either response | No `d`/`p`/`q`/`dp`/`dq`/`qi`, no `vault:`, no `mgmt-`; each JWK has exactly the expected public members; `n` and `e` match custody's public key | Test fails |
| Other Tenant | Owner of B only, GET A's routes | 403 `access_denied` | — |
| Any role | Owner, Editor, Viewer of A | 200 on both | — |
| Unknown | Unknown or malformed `tenantId` | As other Tenant routes | — |
| Custody down | OpenBao refuses or is unreachable | JWKS: fixed 503; list still 200 | 503 |
| Policy | `host-admin` reads `sig-` public key; reads `mgmt-` public key | Allowed; refused | — |
| Browser: page | Mocked list and JWKS | Title, 4 columns, badges, a mono key ID with Copy (accessible name "Copy key ID"), CodeBlock titled with the URI | — |
| Browser: JWKS fails | JWKS 503 with trace ID | Table shown; "Couldn't load the public keys." with reference | — |
| Browser: nav | Tenant path, capability held | "Signing keys" under Security, active on the page | — |
| CSP and axe | Page states, light and dark, 1100 and 768 | No violations; `watchCsp` clean | Test fails |

</intent-contract>

## Code Map

- `src/Adapters/Postgres/Migrations/Migration20261105000000CreateSigningKeyTables.cs:28-50,86-87`: the table, the five-state CHECK, and the existing grants. A new migration sits beside it (copy the attribute pattern from `Migration20261105010000RotateSigningKeys.cs`).
- `src/Adapters/Postgres/Schema/TableRegistry.cs:472-492`: the `signing_key` entry. `tests/Isolation/Tenancy/TenantTablesTests.cs` checks the registry against the DB.
- `src/Modules/Keys/Contracts/SigningKeys.cs`: `SigningKeyPurpose`, `PublishedKeyState`, and `PublishedSigningKey.KeyId` (:35). Add `SigningKeyState` and `ListedSigningKey` here.
- `src/Modules/Keys/Core/TenantKeys.cs:42-47,169-201`: the published read and its name check, which the new list read copies. `KeysContract.cs:203,219`: `ReadPublishedSigningKeysAsync` and `RsaPublicParameters`.
- `src/Gatekeep.Kernel/Secrets/IKeyCustody.cs:104`: `GetPublicKeysAsync`. `src/Modules/Protocol/Core/TenantRuntimes.cs:191-208`: how Hosted picks the version and checks RSA-3072 (read-only reference; don't reference Protocol from Management).
- `src/Modules/Protocol/Contracts/ProtocolContract.cs:19`: the JWKS path. An architecture test asserts Management's suffix equals it.
- `deploy/openbao/policies/host-admin.hcl`: the `sig-*` block. `tests/Architecture/KeyCustodyRuleTests.cs:170-195`: policy rules (`read` on `sig-*` is already allowed).
- `src/Modules/Management/Core/TenantManagement.cs:237-258` and `Contracts/ITenantManagement.cs:273-282`: the re-check pattern.
- `src/Modules/Tenancy/Contracts/ITenants.cs`: the issuer (`ResolvedTenant.Issuer` :275). `Core/Tenants.cs` holds the SQL for any new read.
- `src/Gatekeep.Host.Admin/AdminApi.cs:536-547`, `TenantLabelApi.cs:7-71`, `AdminRequestChecks.cs:448-452` and `AdminResponses.cs:242-263`: the route, handler, path-Tenant and response patterns.
- `apps/admin-dashboard/src/shell/nav.ts:32-40`, `Shell.tsx:163,506-522`, `TenantSettingsPage.tsx:104-131` (load pattern) and `TenantsPage.tsx` (table, `<code>`).
- `packages/ui/src/components/{Badge.tsx,DataTable.tsx,CopyButton.tsx,CodeBlock.tsx}`, `admin.ts`, `messages.tsx:346,583` and `adminNav.tsx:56` (the `security` group).
- `packages/api-client/src/client.ts:237-242` and `test/client.test.mjs`.
- Tests to copy:
  - `tests/Isolation/Tenancy/TenantLabelTests.cs`, using `TenantRequests.cs` and `Admins/AdminHost.cs`;
  - `tests/Isolation/Protocol/DiscoveryAndJwksTests.cs:51-87` and `tests/Isolation/Keys/TenantKeysTests.cs` (key seeding, no `d`);
  - `tests/Isolation/Custody/*` with `OpenBaoFixture` (real policies);
  - `tests/browser/admin-tenant-switcher.spec.ts`, using `admin-host.mjs` and `playwright.config.ts`.

## Tasks & Acceptance

**Execution:**
- [ ] Schema:
  - write the migration and the `TableRegistry` entry;
  - extend `TenantTablesTests` so `gk_admin` has SELECT only on `signing_key` and RLS still holds.
- [ ] Keys:
  - add `SigningKeyState`, `ListedSigningKey`, `ListSigningKeysAsync` and its Core SQL;
  - add Isolation tests for order, signing-only, every state and the Tenant context guard.
- [ ] Custody policy:
  - update `host-admin.hcl` and its comment;
  - add an `OpenBaoFixture` test: `host-admin` reads a `sig-` key's public half and is refused on `mgmt-`.
- [ ] Tenancy: add the issuer read if needed, with a test.
- [ ] Management: add `ISigningKeyManagement` with its implementation and registration, plus a test for the forbidden re-check.
- [ ] Host.Admin:
  - add the routes in `AdminApi.cs`, `SigningKeysApi.cs` and the DTOs;
  - add new `tests/Isolation/Keys/SigningKeysApiTests.cs` covering every API row of the matrix, including custody down via the fake OpenBao socket.
- [ ] Architecture: a test that Management's JWKS suffix equals `ProtocolContract`'s path. The existing capability and OpenAPI rule tests must pass unchanged in intent.
- [ ] Regenerate the OpenAPI and api-client schema, then add the client methods and tests.
- [ ] UI package: add `KeyStateBadge`, its CSS module, the export and the messages.
- [ ] Dashboard:
  - add the nav entry, the Shell route and `SigningKeysPage.tsx`;
  - add new `tests/browser/admin-signing-keys.spec.ts` (axe, `watchCsp`, both themes, both widths), registered in `playwright.config.ts` as other admin specs are.
- [ ] Docs: update the threat model and install.md.

**Acceptance Criteria:**
- Given a Tenant, when an Admin with any Tenant Role opens Signing keys, then the page shows its signing keys in every state they exist in (next, current, previous, retired, revoked), each key ID in mono with a working Copy, and the public JWKS sample below.
- Given either Signing keys response, when it is inspected, then it has no private material and the JWKS sample has no `management` key.
- Given the full suite in Docker, when it runs, then every test passes, including the existing architecture, isolation and browser tests.

## Spec Change Log

## Review Triage Log

## Design Notes

There are two routes rather than one, so the table (Postgres only) still renders when custody is down. The sample is built in Host.Admin from custody, not from OpenIddict: only Protocol and Host.Hosted may reference OpenIddict (`ProtocolRuleTests.cs:70`). The members are expected to be the six RFC 7517 members Hosted publishes for RSA. If Hosted's serializer emits a different public set (for example it adds `x5t`), the sample follows Hosted, and the implementer records the difference in the Spec Change Log.

## Verification

**Commands:**
- `docker build -t gatekeep/tests:epic-9 -f deploy/docker/tests.Dockerfile .` then `MSYS_NO_PATHCONV=1 docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal --add-host host.docker.internal:host-gateway gatekeep/tests:epic-9`. Expected: all tests pass. Use this worktree-only tag, never `gatekeep/tests:local`.
