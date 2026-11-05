---
title: 'Story 2.5: Issue a token by Client Credentials'
type: 'feature'
created: '2026-11-06'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-2-context.md'
  - '{project-root}/docs/spikes/2-2-openiddict-stores.md'
  - '{project-root}/docs/spikes/2-1-openiddict-per-tenant.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** Every Tenant host publishes discovery and JWKS (2.3, 2.4), but `/connect/token` refuses every request. No `application` or `client_secret` table exists, and Tenant contexts have no `IRateLimiter`. So the token pipeline (Transit signing, per-Tenant options, stores) has never issued a real token (FR-13, FR-23, AR-21, AR-22, AD-8, AD-9).

**Approach:**
- Directory gets the tables `application` and `client_secret`, a contract to create a machine client that returns its secret once, and the OpenIddict application store (AD-8).
- Authentication gets the `UNLOGGED` `tenant_attempt` table and a Tenant `IRateLimiter` adapter (AD-14, AD-27).
- Sessions gets the minimal OpenIddict token store, so a Client Credentials access-token row is written.
- Protocol enables the Client Credentials grant on Tenant hosts:
  - a Gatekeep client-authentication handler that calls Directory
  - a request transaction opened by the token endpoint
  - per-Tenant and per-source rate limits
  - the cross-Tenant classification and its Log events
  - a placeholder audience

## Boundaries & Constraints

**Always:**
- **Tables** (one new forward-only migration, each with its `TableRegistry` entry, RLS (ENABLE + FORCE, `_permissive` + RESTRICTIVE `_tenant`), grants, `tenant_row_guard` trigger and purge seed):
  - `application` (Directory): `tenant_id`, `id` uuid v7, `PRIMARY KEY (tenant_id, id)`, `name`, `kind` (CHECK `machine` for now, extensible), `grant_types text[]` (CHECK subset of `client_credentials`, `authorization_code`, `refresh_token`), `audiences text[]`, `created_at`. There's no OpenIddict secret column. Directory writes rows itself, never through `OpenIddictApplicationManager`.
  - `client_secret` (Directory): `tenant_id`, `id`, `application_id` with composite FK to `application ON DELETE RESTRICT`, `secret_hash bytea` (32 bytes, SHA-256, AD-24) `UNIQUE (tenant_id, secret_hash)`, `created_at`, `expires_at NULL` (rotation overlap, used by Epic 3), `revoked_at NULL`.
  - `tenant_attempt` (Authentication, `UNLOGGED`): the `admin_attempt` shape (`policy`, `subject_hash bytea(32)`, `window_start`, `attempts`), plus `tenant_id` in the primary key, with column-level UPDATE grants only.
  - Add `(tenant_id, application_id) REFERENCES application (tenant_id, id) ON DELETE RESTRICT` on `signin_transaction`, `"authorization"` and `token` (from 2.6's deferral).
  - Tenant deletion purges Sessions and Authentication rows before Directory's.
- **Secret format:** `{tenantPublicId}.{base64url of 32 random bytes}` (AD-9). Only the SHA-256 of the whole string is stored. Creation returns it as `RevealOnce<string>`, and in code it's `Secret<string>`. `client_id` is the Application's `app_` public ID.
- **Client authentication:** a Gatekeep handler replaces OpenIddict's `ValidateClientSecret` (spike pattern) and calls `IDirectory` to verify `client_id` + `client_secret` with `CryptographicOperations.FixedTimeEquals`.
  - Accepted: `client_secret_basic` and `client_secret_post`. Discovery advertises exactly these.
  - A secret counts only while it's not revoked and `expires_at` is null or in the future.
  - Every failure returns the same `invalid_client` response.
- **Grant check:** a `client_credentials` request from an Application without that grant type gets `unauthorized_client`. Every other grant type still gets `unsupported_grant_type`.
- **Token:** JWS with `typ: at+jwt`, RS256 signed through Transit by the Tenant's `current` key, `iss` the stored issuer, `sub` = `client_id`, `aud` the placeholder audience, lifetime `SecurityLimits.DefaultAccessTokenLifetime` (15 min, at most `HardSignedTokenLifetime`). It verifies against that Tenant's JWKS and no other Tenant's.
- **Placeholder audience:** one constant, `ProtocolContract.PlaceholderAudience = "urn:gatekeep:placeholder"`, used when the Application's `audiences` is empty. Story 3.7 replaces it. Any `resource`/`audience` request parameter is refused with `invalid_target`, so the Management API audience can never be minted here.
- **Transaction:** only the token endpoint opens a `TenantScope`/`CommandContext`, after Tenant selection. It commits after a successful response and rolls back otherwise. Discovery and JWKS open none. `SelectTenantOptions` stays the only `int.MinValue` handler on `ProcessRequestContext`.
- **Rate limits** (constants in `SecurityLimits`; per Tenant 1200/min and per source 60/min per Tenant on the token endpoint):
  - Counted in their own short committed scope before client authentication (the Admin `SignInApi` pattern).
  - The source is the IPv4 address or the IPv6 /64, taken from `UseGatekeepForwardedClient()`, which Host.Hosted now calls.
  - An exceeded limit returns HTTP 429 with an OAuth error body and `Retry-After`.
- **Cross-Tenant:**
  - A secret whose prefix isn't the serving Tenant's public ID is refused with `invalid_client` before any lookup in the serving Tenant.
  - Then it's classified. If the prefix decodes to an existing Tenant A, and the `client_id`+secret verify under A's scope (read-only), the attempt is *authenticated*, which always writes `protocol.client.cross_tenant_rejected` (class `CrossTenantRejection`, `Actor.Anonymous`, no target) to the serving Tenant's Log. Otherwise it's *unauthenticated*: it increments the per-source mismatch counter (`tenant_attempt`) and writes the same event at most once per source per hour (`SecurityLimits.CrossTenantMismatchLogWindow`).
  - The response is the same in every case, and no identifier of Tenant A reaches B's Log.
  - The event commits through `FailureContext.CommitAfterRollbackAsync`.
- **No secrets in logs:** a canary flow plants a client secret and the issued token, and finds neither in logs or the database.
- **Load:** the token endpoint keeps issuing under concurrency (blocking Transit signing), and concurrent cold requests share one runtime build.

**Never:**
- No Admin UI or Management API for Applications, no secret rotation or "end now", no `client_usage` (Epic 3).
- No system Application (2.8), no authorize, userinfo or revocation endpoint, refresh token or authorization row (2.9–2.11).
- No authorization store beyond a registered stub that throws `NotSupportedException`. Token-store methods that Client Credentials doesn't call throw the same.
- No OpenIddict entity caching, pruning or scope store.
- No change to earlier migrations. No `DELETE`/`UPDATE` grants beyond what the new tables need.
- No raw secret or token in any column, log or exception message.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Happy path, basic | Seeded app with `client_credentials`; correct id+secret via HTTP Basic | 200, `token_type` Bearer, `expires_in` 900; JWT header `typ at+jwt`, `alg RS256`, `kid` = current key; claims `iss`, `sub`, `aud` placeholder; one `token` row with no raw value | No error expected |
| Happy path, post | Same via form fields | Same | No error expected |
| Verify only via own JWKS | Token from Tenant A | Validates with A's JWKS; fails with B's JWKS | No error expected |
| Wrong secret | Right prefix, wrong random part | 401 `invalid_client` | No Log event |
| Unknown client | Unknown `app_` id | 401 `invalid_client` | Same response as wrong secret |
| Revoked or expired secret | `revoked_at` set, or `expires_at` past | 401 `invalid_client` | — |
| Grant not enabled | App without `client_credentials` | 400 `unauthorized_client` | — |
| Other grant | `grant_type=password` or `authorization_code` | 400 `unsupported_grant_type` | — |
| Audience requested | `resource=` or `audience=` parameter | 400 `invalid_target` | — |
| Authenticated cross-Tenant | A's valid id+secret at B | 401 `invalid_client`; one `protocol.client.cross_tenant_rejected` in B's Log on every attempt; A's Log unchanged | Event committed despite the error |
| Unauthenticated cross-Tenant | Secret with A's prefix but wrong random, at B, sent 3 times from one source | 401 each time; one Log event within the hour; counter at 3; after backdating the window, a further attempt logs again | — |
| Garbage prefix | Secret without a dot, or with an undecodable prefix | 401 `invalid_client`; counted as unauthenticated | — |
| Rate limit per source | 61 requests in a minute from one source at one Tenant | 61st gets 429 + `Retry-After`; another source still works | Counter row committed |
| Rate limit per Tenant | Per-Tenant limit passed (limit overridden low in the test) | 429 at that Tenant only; other Tenant unaffected | — |
| RLS on counters | `gk_hosted` in Tenant B's scope | Can't read or update A's `tenant_attempt` rows | RLS hides them |
| No keys | Tenant with no `current` signing key | No token issued; existing 2.3 behaviour (no partial runtime) | `server_error` / 404, no secret logged |
| Concurrency | 50 parallel valid requests on a cold runtime | All 200; one runtime build | — |
| FK | Insert a `token` row with an unknown `application_id` | Rejected | 23503 |

</intent-contract>

## Code Map

- `src/Modules/Protocol/Core/ProtocolServer.cs:25-61` -- server registration (endpoints `:35-37`, `AllowClientCredentialsFlow` `:41`, `DisableAccessTokenEncryption` `:44`, inert credentials `:46-47`, `ResolveRequestUri` removal `:50`). `SelectTenantOptions` `:105-176` (swaps options at `:165`, opens no scope). Remove `RefuseTokenRequests` `:217-232` and `TrimDiscovery` `:238-257` (or narrow it to the methods actually supported). `CacheJsonWebKeySet` `:265-290` stays. Add `AddCore` with `SetDefault*Entity`, `Replace*Store` and `DisableEntityCaching()`.
- `tests/Isolation/Spikes/OpenIddict/Stores/StoreHandlers.cs:26-56,107-147,241-250` -- the patterns to copy: `ValidateGatekeepClientSecret` replacing `ValidateClientSecret` with the `RequireClientIdParameter`/`RequireClientSecretParameter` filters, and `SpikeRequestTransaction` / `EndRequestTransaction<ApplyTokenResponseContext>`. `SpikeServer.cs:110-117` covers Core registration and `SpikeApplicationStore` the read-only store. `SpikeDatabase.cs:60-77` has the spike schema.
- `src/Modules/Protocol/Core/TenantRuntimes.cs:61-281`, `TransitSigningKey.cs:53-111` -- runtime build and Transit signing (load-test note at `:53-54`). Nothing should need to change. If anything does, keep the `kid` check.
- `src/Modules/Protocol/Contracts/ProtocolContract.cs:21,37-52` -- `TokenPath` and `AddGatekeepProtocol`. Add `PlaceholderAudience` and register the stores and Directory/Sessions dependencies.
- `src/Gatekeep.Host.Hosted/Program.cs:17-26` -- add `app.UseGatekeepForwardedClient()` (`src/Adapters/Hosting/GatekeepHosting.cs:82`), in the same place Admin calls it (`src/Gatekeep.Host.Admin/Program.cs:28`).
- `tests/Architecture/ProtocolRuleTests.cs:26-29,70-79` -- `OpenIddictProjects`. AD-8 puts stores in their owners' adapters, so allow `Gatekeep.Modules.Directory` and `Gatekeep.Modules.Sessions` to reference **only** `OpenIddict.Abstractions` (`OpenIddict.Server*` stays Protocol + Host.Hosted) and assert exactly that. `Directory.Packages.props:20-21` -- update the "test only" note.
- `src/Modules/Directory/{Contracts/DirectoryContract.cs,Core/DirectoryCore.cs,Adapters/DirectoryAdapters.cs}` -- placeholders today. Add:
  - `IDirectory.CreateMachineClientAsync(context, name, ct)` → (`ApplicationId`, `ClientId`, `RevealOnce<string>` secret), plus `VerifyClientSecretAsync(context, clientId, Secret<string>, ct)`
  - `DirectoryEvents.cs` (pattern: `src/Modules/Sessions/Contracts/SessionsEvents.cs`) with `directory.application.created`
  - the application store adapter
  - the `ITenantPurge`
  Module edges Protocol→Directory, Directory→Sessions and Directory→Tenancy already exist (`tests/Architecture/module-edges.txt`). Add any new edge there deliberately.
- `src/Modules/Admins/Core/AdminAttemptLimiter.cs:18-42`, `Migration20261102100000CreateAdminAttemptTable.cs:20-32`, `src/Modules/Admins/Contracts/AdminsContract.cs:109-114`, `src/Gatekeep.Host.Admin/SignInApi.cs:244-262`, `AdminRequestChecks.cs:466-…` -- limiter upsert, table, policy declaration, caller pattern and source derivation to mirror in `src/Modules/Authentication`. Policy codes must be `public static RateLimitPolicy` fields on an exported contract type (`AuditCatalogueTests.cs:233-240`). Kernel port: `src/Gatekeep.Kernel/RateLimiting/IRateLimiter.cs:11-28`.
- `src/Adapters/Postgres/Migrations/Migration20261105020000DeleteTenants.cs` -- latest (20 migrations). `tenant_row_guard` at `:94-159`. New file `Migration20261106000000CreateDirectoryTables.cs`. `Migration20261102090000CreateSessionTables.cs:59,79,102,115-135` has the `application_id` columns and the RLS pattern. `tests/Isolation/MigrateCommandTests.cs:20,28` goes from 20 to 21.
- `src/Adapters/Postgres/Schema/TableRegistry.cs:21-47,277-315` -- entry shape, roles, Sessions `PurgeColumns`/`RowGuard`, `admin_attempt` `Unlogged`. `tests/Isolation/Tenancy/TenantPurgeRegistryTests.cs:22-62`, `TenantSeeds.cs:20`, `src/Modules/Operations/Core/TenantDeletion.cs:54-60` -- purge obligations and order.
- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs:120,144` -- add `DefaultAccessTokenLifetime`, the token rate-limit counts and windows, `CrossTenantMismatchLogWindow` (1 h) and `ClientSecretOverlap` (24 h, hard 7 d), with XML docs citing §5.2.
- `src/Gatekeep.Kernel/Audit/AuditEventDefinition.cs:16`, `tests/Architecture/Generator/AuditCatalogue.cs:47`, `tests/Isolation/Audit/EventClassTests.cs:152-160` -- `CrossTenantRejection` is pending on "7.4". Mapping the new event means clearing that pending entry. Regenerate `docs/audit-events.md` with `dotnet run --project tests/Architecture/Generator`.
- `src/Gatekeep.Kernel/Persistence/FailureContext.cs`, `tests/Isolation/FailureContextTests.cs:21` -- commit the cross-Tenant event despite the rollback.
- `src/Gatekeep.Kernel/Identifiers/PublicId.cs` -- `ten_`/`app_` encode and decode (prefix → Tenant ID for classification).
- `src/Gatekeep.Kernel/Secrets/` -- `Secret<T>`, `RevealOnce<T>`, `CredentialShapes` (already masks `client_secret=` and JWTs. Check that the new secret shape is masked too).
- `tests/Isolation/Protocol/ProtocolHost.cs:98-354,357,431`, `DiscoveryAndJwksTests.cs:32-48,242-275,497-505,536` -- test host, `ControlledCustody`, `ManualTimeProvider`, captured logs, `TwoTenantsAsync`. Rewrite the two "token refused / discovery trimmed" tests. Validate a JWT against a JWKS following `tests/Isolation/Spikes/OpenIddict/PerTenantOptionsSpikeTests.cs:455-460`.
- `tests/Isolation/Canary/CanaryFlows.cs:176-240,400-419,477-479`, `CanaryFlowTests.cs:16` -- add a `protocol.client_credentials` flow with `[]` surfaces (OpenIddict routes aren't `Map*` literals). It needs the OpenBao fixture.

## Tasks & Acceptance

**Execution:**
- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs` -- the new constants -- fixed limits live in one file.
- `src/Adapters/Postgres/Migrations/Migration20261106000000CreateDirectoryTables.cs`, `TableRegistry.cs`, `MigrateCommandTests.cs`, `TenantSeeds.cs` -- the three tables, RLS, grants, guards and the three FKs -- schema.
- `src/Modules/Directory/**` -- the contract, machine-client creation (one `CommandContext` command with an audit event), secret verification, the application store and the purge -- Directory owns Applications (AD-8, AD-27).
- `src/Modules/Authentication/**` -- the Tenant `IRateLimiter` adapter, the token policies and the purge -- Authentication owns attempt counters.
- `src/Modules/Sessions/**` -- the token store (create plus whatever Client Credentials calls), the throwing authorization store, purge order -- Sessions owns tokens.
- `src/Modules/Protocol/**`, `src/Gatekeep.Host.Hosted/Program.cs`, `Directory.Packages.props`, module csprojs -- Core registration, the client-auth handler, the grant/audience checks, the token-endpoint transaction, rate limits, cross-Tenant classification and events, forwarded client.
- `src/Modules/Operations/Core/TenantDeletion.cs` -- purge order.
- `tests/Architecture/ProtocolRuleTests.cs`, `AuditCatalogue.cs`, `module-edges.txt` -- the rule updates.
- `tests/Isolation/Protocol/ClientCredentialsTests.cs` (new), `DiscoveryAndJwksTests.cs`, `tests/Isolation/Directory/*`, `tests/Isolation/Authentication/*`, `CanaryFlows.cs` -- one test per I/O matrix row against real Postgres and OpenBao, plus the grant and RLS theories for the new tables.
- `docs/audit-events.md`, the module diagram, `docs/spikes/2-2-openiddict-stores.md` -- regenerate, and record where the stores live.
- `_bmad-output/implementation-artifacts/deferred-work.md` -- mark the FK and load-test items done.

**Acceptance Criteria:**
- Given a running Hosted host and a seeded machine client, when it calls `POST /connect/token` with `grant_type=client_credentials`, then it gets an RS256 `at+jwt` that validates only against that Tenant's `/.well-known/jwks`, and no `application` column holds a secret.
- Given Tenant A's discovery document, when it's read, then it advertises `token_endpoint`, `grant_types_supported` with `client_credentials` only, and `token_endpoint_auth_methods_supported` with `client_secret_basic` and `client_secret_post` only.
- Given the Architecture and Isolation suites, when they run in Docker with locked restore, then all pass, including the 2.3/2.4 Protocol tests.

## Spec Change Log

## Review Triage Log

## Design Notes

**Where the stores live.** AD-8 says each store lives in its owner's adapters. Directory and Sessions reference only `OpenIddict.Abstractions` (the store interfaces). The engine (`OpenIddict.Server*`, `OpenIddict.Core`) stays in Protocol and Host.Hosted. Protocol wires the stores in.

**Which Log gets the cross-Tenant event.** The serving Tenant's, because SM-2 counts rejected attempts in the Log of the Tenant that was probed. The event names no Tenant A identifier, so B's Owner learns nothing about A. "Authenticated" means the credential really verifies at its own Tenant. That case is always logged. Garbage only counts, and logs once per source per hour.

**The secret is an opaque artifact.** The `{tenantPublicId}.` prefix lets the wrong-Tenant case be refused before any lookup, and classified without scanning other Tenants.

## Verification

**Commands:**
- `docker build -t gatekeep/tests:epic2-rest -f deploy/docker/tests.Dockerfile .` -- expected: the image builds with locked restore.
- `MSYS_NO_PATHCONV=1 docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal --add-host host.docker.internal:host-gateway gatekeep/tests:epic2-rest` -- expected: all architecture and isolation tests pass.
