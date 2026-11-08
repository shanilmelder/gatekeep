---
title: 'Story 2.9: Run the authorization code flow with PKCE'
type: 'feature'
created: '2026-11-09'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-2-context.md'
  - '{project-root}/docs/spikes/2-2-openiddict-stores.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** Tenant hosts issue tokens only by Client Credentials (2.5). There is no authorize endpoint, no code grant, no Application with redirect URIs, and no working authorization or token store. Story 1.31's cross-Tenant suite still lists "authorization code" as pending on 2.9. So no OIDC library can sign a user in (FR-13, FR-23, FR-47, AD-8, AD-9).

**Approach:** Protocol opens `/connect/authorize` with the authorization code grant, PKCE `S256` only, and `iss` in every authorization response.
- Sign-in runs through `IAuthentication.BeginAsync`, then a Protocol-owned completion port. The test host plugs `TestOnlyAuthenticator` into that port, and the release composition plugs in a default that completes nothing.
- Codes are `{tenantPublicId}.{random}` reference tokens.
- Sessions builds the authorization store and the rest of the token store, and wires code replay into `ISessions.RevokeAccessAsync` through `FailureContext`.
- Directory gains confidential `web` Applications with registered redirect URIs.
- An unregistered `redirect_uri` gets a static, fixed-text error page under the AD-21 CSP.

## Boundaries & Constraints

**Always:**
- **Kernel:**
  - `SecurityLimits.AuthorizationCodeLifetime = 60 s`, with XML docs citing §5.2.
  - `PublicIdType.User` with the prefix `usr_`. It's the ID token's and the access token's `sub`.
- **One forward-only migration**, `Migration20261110000000CreateCodeFlow.cs`:
  - `application.kind` allows `web`. Add `redirect_uris text[] NOT NULL DEFAULT '{}'`.
  - A CHECK requires a `web` row to have at least one redirect URI and the grant set `{authorization_code}`. `machine` and `system` rows have none.
  - Narrow `gk_hosted`'s table-wide UPDATE on `token` and `"authorization"` to exactly the columns the stores update, in both the migration and `TableRegistry`. This closes the 2.6/2.7 deferral.
  - Add any lookup indexes the new store queries need.
  - Bump `MigrateCommandTests` from 25 to 26, in all four places.
- **Directory:**
  - `IDirectory.CreateWebClientAsync(context, name, redirectUris, ct)` → (`ApplicationId`, `ClientId`, `RevealOnce<string>` secret). It mirrors `CreateMachineClientAsync`, with the same secret shape and the same `directory.application.created` event.
  - Each redirect URI is an absolute `https` URI, or `http` on loopback only. It has no fragment and is at most 2000 characters, with 1 to 10 URIs.
  - The application store returns:
    - the redirect URIs;
    - `ept:authorization`, `ept:token`, `rst:code` and the `gt:` grant permissions;
    - the PKCE requirement `ft:pkce` for `web` rows.
  - `FindByRedirectUriAsync` works with the system-row filter. Every Application stays confidential: no public clients in this story.
- **Protocol server:**
  - `SetAuthorizationEndpointUris(ProtocolContract.AuthorizePath = "/connect/authorize")`, `AllowAuthorizationCodeFlow()`, `RequireProofKeyForCodeExchange()`, and `plain` removed from `CodeChallengeMethods`.
  - Responses only `code`, response modes `query` and `form_post`, and authorization passthrough.
  - `iss` is in every authorization response, success or error, and discovery says `authorization_response_iss_parameter_supported: true`.
  - Discovery advertises `grant_types_supported` `[authorization_code, client_credentials]`, `response_types_supported` `[code]` and `code_challenge_methods_supported` `[S256]`. Implicit, hybrid and ROPC are never enabled.
  - `SelectTenantOptions` stays the only `int.MinValue` handler.
- **Authorize flow** (passthrough handler in Protocol):
  1. OpenIddict validates the client, the exact registered `redirect_uri`, `response_type=code`, and PKCE (missing or `plain` → error redirect `invalid_request`).
  2. The handler opens the request transaction (as the token endpoint does) and calls `IAuthentication.BeginAsync(SignInRequest(applicationId, parameters))`.
  3. It then calls the new port `IAuthorizationSignIn.CompleteAsync(context, StartedSignIn, HttpContext, ct) → AuthenticationResult?`, defined in Protocol's contract.
     - On a result, Protocol signs in with:
       - claims `sub` (`usr_`), `sid` (`user_session_id`), `auth_time` and `amr`;
       - destinations: the ID token gets `sub`, `auth_time`, `amr`, `sid` and `nonce`, and the access token gets `sub` and the placeholder `aud`.
     - It creates one ad-hoc authorization anchored to `AuthenticationResult.SessionId`, then issues the code.
     - `null` → error redirect `temporarily_unavailable` (with `iss`). This is the release default, `UnavailableSignIn`, until Stories 4.1 and 4.2.
  4. It commits on success and rolls back otherwise.
  - Scope: `openid` is required and is the only scope accepted at authorize. Any other scope gets `invalid_scope`. `prompt=none` gets `login_required`. `prompt=login` and `max_age` pass through in `Parameters`; honouring them is Story 4.2's. No refresh token is issued (Story 2.10).
- **Unregistered or malformed `redirect_uri`, or an unknown client:** HTTP 400 with a static, fixed-text HTML page ("Something went wrong" / "This sign-in link isn't valid. Go back to the app and try again."). The page never redirects, never echoes request values, and sends `Cache-Control: no-store` and the AD-21 Hosted CSP from `SecurityHeaders`. Story 4.1 replaces it.
- **Token endpoint, `authorization_code` grant:**
  - Client authentication is unchanged: the secret is required, and every failure answers the same `invalid_client`.
  - `RefuseTokenTargets` allows the code grant's `scope`. `resource`/`audience` stay refused.
  - The code verifies only for the same client, `redirect_uri` and Tenant, with a matching `code_verifier` and within 60 s. Any failure is `invalid_grant`.
  - It issues an RS256 `at+jwt` access token (15 min) and an ID token, both signed through Transit by the Tenant's current key.
- **Reference IDs:**
  - A handler (spike `AttachTenantReferenceId`) gives codes the reference ID `{tenantPublicId}.{base64url of 32 random bytes}`. The store keeps only a hash (OpenIddict's, which matches the `reference_id` CHECK). The payload is encrypted with the Tenant's protection key.
  - `RejectForeignReferenceIds` (spike) rejects any presented code whose prefix isn't the serving Tenant's public ID with `invalid_grant`, before any store lookup.
- **Replay:**
  - A redeemed code presented again is `invalid_grant`. OpenIddict's `RevokeByAuthorizationIdAsync` routes to `RevokeAccessAsync(Authorization scope, RevocationReason.CodeReplay, Actor.Anonymous)`.
  - The call is recorded on the request transaction and replayed through `FailureContext.CommitAfterRollbackAsync` at endpoint end, so the access and ID token rows issued from the code end up `revoked`, with one `sessions.access.revoked` event.
  - `TokenRequestTransaction.DisposeAsync` must replay recorded effects when the endpoint never reached its normal end (unhandled exception).
- **Store rules (Sessions):**
  - The authorization store and the token store implement exactly what the code grant calls; everything else throws `NotSupportedException`.
  - `UpdateAsync` refuses (throws) any change that sets status `revoked`, and `RevokeBySubjectAsync` refuses. `RevocationPathTests` keeps passing.
  - A SQL failure inside a store marks the request transaction failed, so the endpoint answers `server_error` and never reports success on an aborted transaction.
- **Release build:** an Architecture test asserts that no type in any `src/` assembly implements `IAuthorizationSignIn` except `UnavailableSignIn`, and that `TestOnlyAuthenticator` lives only in the tests assembly. Host.Hosted registers `UnavailableSignIn`.
- **Cross-Tenant:** `ArtifactRegistry` `"authorization code"` goes from Pending to Covered by a test that redeems Tenant A's code at Tenant B and gets `invalid_grant`. `RouteRegistry` gets `/connect/authorize` (HostResolved), and `CrossTenantRouteTests` gets its case.
- **No secrets in logs:** a `protocol.authorization_code` canary flow plants the code, the verifier and the issued tokens, and finds none of them in logs or the database.

**Never:**
- No login screens, cookies set by Protocol, session resumption, consent, `prompt`/`max_age` enforcement (Stories 4.1 and 4.2), refresh tokens or `offline_access` (2.10), userinfo, revocation or end-session endpoints (2.11).
- No public (secretless) clients and no Admin API for Applications (Epic 3).
- No implicit, hybrid or ROPC flow, and no `plain` PKCE.
- No change to earlier migrations, and no raw code, verifier or token in any column, log or exception message.
- No authorize-endpoint rate limit beyond what exists.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Happy path | Seeded `web` client, test authenticator for a seeded User, `S256` challenge, `openid` | 302 to the redirect URI with `code`, `state` and `iss` (the stored issuer). The code starts `ten_…`. One authorization row anchored to the Session. Exchange (Basic auth plus verifier) → 200 with `access_token` (`at+jwt`, RS256, current `kid`, `sub` `usr_…`) and `id_token` (`sub`, `nonce`, `auth_time`, `amr`, `sid`). Both verify only with that Tenant's JWKS | No error expected |
| form_post | `response_mode=form_post` | 200 auto-post form carrying `code`, `state` and `iss` | No error expected |
| No PKCE | No `code_challenge` | Error redirect `invalid_request` with `iss`; no transaction | — |
| plain PKCE | `code_challenge_method=plain` | Error redirect `invalid_request` with `iss` | — |
| Bad verifier | Valid code, wrong `code_verifier` | 400 `invalid_grant` | No tokens |
| Unregistered redirect | `redirect_uri` not registered (or a different port/path) | 400 static page, CSP header, no `Location`, no echo | Never redirects |
| Unknown client | Unknown or system `client_id` | 400 static page | Never redirects |
| Other scope | `scope=openid email` | Error redirect `invalid_scope` | — |
| No openid | `scope` missing `openid` | Error redirect `invalid_scope` | — |
| prompt=none | `prompt=none` | Error redirect `login_required` | — |
| Implicit/hybrid | `response_type=token` or `code id_token` | Error redirect `unsupported_response_type` | — |
| ROPC | `grant_type=password` | 400 `unsupported_grant_type` | — |
| No authenticator | Release default `UnavailableSignIn` | Error redirect `temporarily_unavailable` with `iss`; the transaction rolled back | — |
| Replay | Same code redeemed twice | Second → 400 `invalid_grant`; the first exchange's token rows `revoked`; one `sessions.access.revoked` (`code_replay`) committed | Revocation committed despite the error |
| Other client | Code redeemed by another client of the same Tenant | 400 `invalid_grant` | — |
| Other redirect | Exchange with a different `redirect_uri` | 400 `invalid_grant` | — |
| Other Tenant | A's code at Tenant B (with B's client) | 400 `invalid_grant`, rejected before lookup | — |
| Garbage prefix | Code with no dot or another `ten_` prefix | 400 `invalid_grant`, no store query | — |
| Expired | Redeemed after 60 s (time advanced) | 400 `invalid_grant` | — |
| Revoked status via update | Store `UpdateAsync` with status `revoked` | Throws; nothing written | — |
| Unhandled exception | A store throws after a revocation was recorded | The recorded revocation is still committed | — |
| Discovery | GET discovery | `authorization_endpoint`, grants `[authorization_code, client_credentials]`, `response_types_supported` `[code]`, `code_challenge_methods_supported` `[S256]`, `authorization_response_iss_parameter_supported` true | — |
| Web client CHECK | Insert `web` row with no redirect URI, or with `client_credentials` | Refused | 23514 |
| Redirect validation | `CreateWebClientAsync` with `http://example.com`, a fragment, or 11 URIs | `ArgumentException`, nothing written | — |

</intent-contract>

## Code Map

- `src/Modules/Protocol/Core/ProtocolServer.cs:70-121` -- registration: endpoints `:72-74`, flows `:77`, client-auth trim `:88-93`, handler lists `:99-116`, `UseAspNetCore` `:120`. `SelectTenantOptions` `:167-239`. `EndpointUris` (`:130-154`) already includes authorization.
- `src/Modules/Protocol/Core/TokenEndpoint.cs`:
  - `LimitTokenRequests` `:115`, `BeginTokenTransaction` `:159`.
  - `RefuseTokenTargets` `:186-210` (allow `scope` for the code grant).
  - `AuthenticateGatekeepClient` `:223-330` (prefix parse `:249-263`).
  - `SignInClient` `:339-353`, `EndTokenTransaction` `:386-413`.
  - `ReportAccessTokenLifetime` `:445` (extend to ID tokens as needed).
- `src/Modules/Protocol/Core/TokenRequestTransaction.cs:40,56-88` -- `KeepOnFailure`, `FailAsync` and `DisposeAsync`, which today only rolls back (fix it). Reuse it for authorize.
- `src/Modules/Protocol/Contracts/ProtocolContract.cs:17-21,37-52` -- paths and `AddGatekeepProtocol`. Add `AuthorizePath`, the `IAuthorizationSignIn` port and `UnavailableSignIn`.
- `src/Modules/Protocol/Core/TenantRuntimes.cs:216-252` -- the protection key is already unwrapped into `EncryptionCredentials`/`TokenDecryptionKeys`. It's cached for 5 s.
- `tests/Isolation/Spikes/OpenIddict/SpikeServer.cs:127-136,159-178,327-350` -- code-flow options, passthrough mapping and client permissions. `Stores/StoreHandlers.cs:17-56,154-234,241` -- the reference-ID handlers and the generic end-transaction. `Stores/SpikeTokenStore.cs`, `SpikeAuthorizationStore.cs`, `SpikeRequestTransaction.cs:40` -- full store patterns. Don't copy `RevokeFamilyAsync`'s direct UPDATE: the revocation goes through `RevokeAccessAsync`. `CustomStoresSpikeTests.cs:212,314` -- the replay and prefix tests to mirror. `docs/spikes/2-2-openiddict-stores.md:89-158` -- the replay path, hashing, PKCE behaviour and the risks.
- `src/Modules/Sessions/Adapters/TokenStore.cs:18-182` -- the token store (Create works; Find/Update/Revoke throw). `:190-275` -- `AuthorizationStore` (all throw). `SessionsContract.cs:30` -- `CreateAuthorizationStore()` needs a context func, as the token store has. `SessionsEntities.cs:11-49` -- the entities. `Core/SessionRevocation.cs:41`, `Contracts/ISessions.cs:38,62-68`, `Contracts/Revocation.cs:7-72` (`CodeReplay` exists).
- `tests/Architecture/RevocationPathTests.cs:6-54` -- the text scan that the stores must keep passing.
- `src/Adapters/Postgres/Migrations/Migration20261102090000CreateSessionTables.cs:56-94,141-145` -- the `authorization`/`token` columns and the table-wide UPDATE grants to narrow. `Migration20261109000000AddSystemApplication.cs` -- the latest migration (25), with the system-row guards.
- `src/Adapters/Postgres/Schema/TableRegistry.cs` -- the `application`, `token` and `authorization` entries.
- `src/Modules/Directory/{Contracts/IDirectory.cs:33, Core/DirectoryService.cs, Adapters/ApplicationStore.cs:45-94}` -- client creation, the `Visible` filter, client type and permissions, redirect URIs, `FindByRedirectUriAsync`.
- `src/Modules/Authentication/Contracts/IAuthentication.cs:7-29`, `AuthenticationResult.cs:8` -- `BeginAsync` and the result. `tests/Isolation/Sessions/TestOnlyAuthenticator.cs` -- adapt it, or wrap it in a test `IAuthorizationSignIn` that takes the User ID from a test header and calls `AuthenticateAsync`. `SessionTablesTests.cs:657-675` -- the existing location guard.
- `src/Gatekeep.Host.Hosted/Program.cs:14-40` -- register `UnavailableSignIn` and Authentication/Sessions as Protocol needs. `src/Adapters/Hosting/SecurityHeaders.cs:14-55` -- the AD-21 CSP, for the static page.
- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs`, `src/Gatekeep.Kernel/Identifiers/PublicId.cs:4-47` -- the new constant and `usr_`.
- `src/Gatekeep.Kernel/Persistence/FailureContext.cs:17-31` -- `CommitAfterRollbackAsync`.
- Tests:
  - `tests/Isolation/Protocol/ProtocolHost.cs:65-260` -- the host (add the sign-in port and Sessions/Authentication), `CreateClientAsync`, two Tenants, `ControlledCustody`.
  - `ClientCredentialsTests.cs:93-106`, `DiscoveryAndJwksTests.cs:32-49,209` -- discovery assertions and the authorize 404 to rewrite.
  - `tests/Isolation/CrossTenant/ArtifactRegistry.cs:40`, `RouteRegistry.cs:107-114`, `CrossTenantRouteTests.cs:149-209` -- the cross-Tenant updates.
  - `tests/Isolation/Canary/CanaryFlows.cs:283,1423+` -- the canary pattern.
  - `tests/Isolation/MigrateCommandTests.cs:20,28,43,78` -- 25 → 26.

## Tasks & Acceptance

**Execution:**
- [ ] `src/Gatekeep.Kernel/**` -- `AuthorizationCodeLifetime` and `PublicIdType.User`.
- [ ] `src/Adapters/Postgres/Migrations/Migration20261110000000CreateCodeFlow.cs`, `TableRegistry.cs`, `MigrateCommandTests.cs` -- `web` kind, redirect URIs, CHECKs, narrowed grants, indexes.
- [ ] `src/Modules/Directory/**` -- `CreateWebClientAsync` and the store's redirect URIs, permissions and requirements.
- [ ] `src/Modules/Sessions/**` -- the authorization store and the rest of the token store, the replay routing, the refusal of a revoked status through update, and the SQL-failure flag.
- [ ] `src/Modules/Protocol/**` -- the server options, the authorize passthrough and its transaction, `IAuthorizationSignIn` and `UnavailableSignIn`, the reference-ID handlers, the claims and destinations, the token-endpoint scope change, the static error page, and `TokenRequestTransaction.DisposeAsync`.
- [ ] `src/Gatekeep.Host.Hosted/Program.cs` -- composition.
- [ ] `tests/Architecture/**` -- the release-build port test, and any rule updates (module edges stay as they are unless a new edge is unavoidable; record it deliberately).
- [ ] `tests/Isolation/Protocol/AuthorizationCodeTests.cs` (new), `ProtocolHost.cs`, `DiscoveryAndJwksTests.cs`, `ClientCredentialsTests.cs`, `tests/Isolation/Directory/*`, `tests/Isolation/Sessions/*`, `CrossTenant/*`, `Canary/*` -- one test per I/O matrix row, against real Postgres and OpenBao.
- [ ] `docs/spikes/2-2-openiddict-stores.md`, `_bmad-output/implementation-artifacts/deferred-work.md` -- record the wiring; mark the grant-narrowing and `reference_id` items done.

**Acceptance Criteria:**
- Given a running Hosted test host with the test authenticator, when a seeded `web` client runs authorize then token with S256 PKCE, then it gets a code (with `iss`) and exchanges it for an access token and an ID token that verify only with that Tenant's JWKS.
- Given the release composition, when `/connect/authorize` runs, then no code is issued (`temporarily_unavailable`), and no `src/` type completes a sign-in.
- Given CI's Architecture and Isolation suites, when they run, then all pass, including the 2.3–2.8 Protocol tests and the cross-Tenant suite with "authorization code" covered.

## Spec Change Log

## Review Triage Log

## Design Notes

**The sign-in seam.** AD-8 says Protocol calls `IAuthentication.Begin` and receives an `AuthenticationResult`. No screens exist until Story 4.1, and Story 4.2 binds real transactions and cookies. So Protocol owns a narrow port, `IAuthorizationSignIn`. The test host plugs `TestOnlyAuthenticator` in, and the release build plugs in `UnavailableSignIn`, which completes nothing. The authorize request therefore runs end to end in one call in tests, and safely refuses in production. Story 4.2 replaces the default with transaction-cookie resumption, not the port.

**Confidential clients only.** Every Application is already confidential with a secret (2.5). A `web` kind with secret plus PKCE covers server-side OIDC libraries. Public SPA and native clients need their own decisions (Epic 3, Story 17.9).

**Replay revocation.** OpenIddict revokes on replay inside a log-only catch (spike notes). Routing the store's `RevokeByAuthorizationIdAsync` into a recorded effect, replayed through `FailureContext`, makes the revocation commit even though the response is an error and the request scope rolled back.

## Verification

**Commands:**
- CI on the PR (Architecture and Isolation suites in Docker) -- expected: green. Don't run the full suite locally; targeted classes in the tests container are fine.
