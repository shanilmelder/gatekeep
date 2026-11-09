---
title: 'Story 2.9: Run the authorization code flow with PKCE'
type: 'feature'
created: '2026-11-09'
status: 'done'
baseline_revision: '7bf1b457d749891a91149aef458f4a065ee0ad3b'
review_loop_iteration: 0
followup_review_recommended: true
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

### 2026-11-09 — Review pass
- Layers: Blind Hunter, Edge Case Hunter, Verification Gap and Intent Alignment.
- Intent Alignment was descriptive and filed no findings. It found Story 2.9 implemented, with every acceptance criterion mapped to code and a test. The evidence sits at the test-host surface: `ProtocolHost`, a header-driven test sign-in, and a check of the `src` assemblies.
- Verdicts: 27 findings in total (high 0, medium 6, low 18, false 3, maybe-false 0).

| # | Verdict | Route | Finding | Evidence / action |
|---|---------|-------|---------|-------------------|
| 1 | medium | patch | VG: the store-marked-failed → `server_error` end is never driven through an endpoint | Only `SessionStoresTests` sets the flag. Added an endpoint test that forces a failed store statement. |
| 2 | medium | patch | VG: no test races two exchanges of one code | Added a `Task.WhenAll` test: exactly one 200. Same root cause as rows 18 and 26. |
| 3 | low | patch | VG: the 15-minute ID token lifetime is never asserted | The happy path now asserts `exp - iat`. |
| 4 | low | patch | VG: a code exchange with `scope` is untested | Same root cause as rows 23 and 27. |
| 5 | low | patch | VG: authorize's no-signing-key and oversized-parameter refusals never run | Two tests added (unprovisioned Tenant; 17000-character `state`). |
| 6 | low | patch | VG: Host.Hosted's own `IAuthorizationSignIn` registration is never exercised | `AddGatekeepProtocol` now `TryAdd`s `UnavailableSignIn`, so no host can miss it. Same root cause as row 15. |
| 7 | low | patch | BH: `sid` is the raw Session GUID | Added `PublicIdType.Session` (`ses_`); `sid` uses it before any relying party depends on the format. |
| 8 | medium | patch | BH: `http://localhost` is accepted as a loopback redirect | `Uri.IsLoopback` is true for the name. Plain `http` is now allowed only for the IP literals `127.0.0.1` and `[::1]` (RFC 8252 §8.3), and exact port matching is documented. |
| 9 | low | patch | BH: the redirect-URI error message is incomplete, hard-codes limits, and has the wrong `ParamName` | Direct correction. |
| 10 | low | reject | BH: the database doesn't check each URI's form | Directory is the only writer and validates every URI. A per-element CHECK needs a SQL function for no named harm. |
| 11 | low | patch | BH: `FindByRedirectUriAsync` and its GIN index are dead | OpenIddict validates the redirect URI on the client found by `client_id`. The method now throws `Unsupported()`, and the unreleased index is dropped. |
| 12 | medium | patch | BH: a foreign-prefix code is refused with no Log event | Classified as an unauthenticated cross-Tenant mismatch through Story 2.5's counter and hourly-logged event. |
| 13 | low | patch | BH: a cancelled statement doesn't mark the request failed | Same root cause as row 22. |
| 14 | low | reject | BH: replay depends on OpenIddict swallowing store exceptions | The replay test pins the response and the committed revocation, so an upgrade that rethrows fails it. |
| 15 | low | patch | BH: a missing sign-in registration fails at request time | Same root cause as row 6. |
| 16 | low | reject | BH: `authorization`/`token` restate the purge grant | `CatalogueAudit` compares each registry entry with the live grants (same call as 2.8's follow-up). |
| 17 | low | reject | BH: `TokenEndpointServices`/`TokenRequestTransaction` names now span both endpoints | A rename is churn. The doc comments state the wider role. |
| 18 | medium | patch | BH: several new paths are untested | Same root cause as rows 1, 2 and 5. The Session-ended-within-60-s case is false: a Session's revocation revokes its family, code row included. |
| 19 | false | reject | ECH: a revoked token can be un-revoked through `UpdateAsync` | `SessionRevocation` sets `concurrency_token = gen_random_uuid()` on revoke, so a stale update matches no row. OpenIddict never moves a revoked entity to valid. |
| 20 | low | reject | ECH: a DB failure inside the passthrough answers a bare 500 | Only during a database outage. Same call as Story 2.5's row 14. |
| 21 | false | reject | ECH: the passthrough throws when the validated client has no Application | OpenIddict's own client validation found it moments before in the same transaction, so this is unreachable. |
| 22 | low | patch | ECH: `StoreSql` catches only `DbException` | It now also marks the request failed on `OperationCanceledException`. |
| 23 | low | patch | ECH: extra scope on a code exchange relies on an unverified OpenIddict check | The code grant now refuses any scope but `openid`. Same root cause as rows 4 and 27. |
| 24 | false | reject | ECH: the authorization anchor could name an ended or foreign Session | The anchor is the Session `CompleteAsync` started in the same transaction, so this is unreachable. |
| 25 | low | reject | ECH (claim): `iss` isn't on a bare 500 | A 500 from a database outage isn't an authorization response. Same root cause as row 20. |
| 26 | medium | patch | ECH: a raced redemption is refused but the family isn't revoked | A 0-row redeem of a code now records the `CodeReplay` revocation through `KeepOnFailure`. Tested with the race. |
| 27 | low | patch | ECH (claim): the `RefuseTokenTargets` comment claims a check nothing enforces | The comment matches the new explicit check. |

## Design Notes

**The sign-in seam.** AD-8 says Protocol calls `IAuthentication.Begin` and receives an `AuthenticationResult`. No screens exist until Story 4.1, and Story 4.2 binds real transactions and cookies. So Protocol owns a narrow port, `IAuthorizationSignIn`. The test host plugs `TestOnlyAuthenticator` in, and the release build plugs in `UnavailableSignIn`, which completes nothing. The authorize request therefore runs end to end in one call in tests, and safely refuses in production. Story 4.2 replaces the default with transaction-cookie resumption, not the port.

**Confidential clients only.** Every Application is already confidential with a secret (2.5). A `web` kind with secret plus PKCE covers server-side OIDC libraries. Public SPA and native clients need their own decisions (Epic 3, Story 17.9).

**Replay revocation.** OpenIddict revokes on replay inside a log-only catch (spike notes). Routing the store's `RevokeByAuthorizationIdAsync` into a recorded effect, replayed through `FailureContext`, makes the revocation commit even though the response is an error and the request scope rolled back.

## Verification

**Commands:**
- CI on the PR (Architecture and Isolation suites in Docker) -- expected: green. Don't run the full suite locally; targeted classes in the tests container are fine.

## Auto Run Result

**Summary.** Tenant hosts now run the authorization code flow with S256 PKCE (FR-13, FR-23, FR-47, AD-8, AD-9).
- **Authorize:** `/connect/authorize` validates the client and its exact redirect URI, then calls `IAuthentication.BeginAsync` and the new `IAuthorizationSignIn` port.
  - On a result it creates one ad-hoc authorization anchored to the Session, then issues a `{tenantPublicId}.{random}` code that lives 60 seconds. `iss` is in every response.
  - The release default, `UnavailableSignIn`, answers `temporarily_unavailable`. The test host plugs in `TestOnlyAuthenticator`.
  - An unknown client or unregistered `redirect_uri` gets a static fixed-text page with the AD-21 CSP, never a redirect.
- **Token exchange:** the code grant issues an `at+jwt` access token and an ID token.
- **Replay:** a replayed or raced code revokes its family through `RevokeAccessAsync(CodeReplay)`, committed by `FailureContext`.
- **Foreign codes:** a code carrying another Tenant's prefix is refused before lookup and logged as an unauthenticated cross-Tenant mismatch.
- **Stores and grants:** Sessions' authorization and token stores are built, with a revoked status refused through update. `gk_hosted`'s UPDATE on `token`/`authorization` is narrowed to columns.
- **Directory:** gains confidential `web` clients with validated redirect URIs.

**Files changed (main ones)**
- `src/Adapters/Postgres/Migrations/Migration20261110000000CreateCodeFlow.cs`, `TableRegistry.cs`: `web` kind, `redirect_uris`, CHECKs, narrowed grants.
- `src/Gatekeep.Kernel/{Limits/SecurityLimits.cs, Identifiers/PublicId.cs}`: the code and ID token lifetimes, `usr_` and `ses_`.
- `src/Modules/Directory/**`: `CreateWebClientAsync`, redirect-URI rules, store permissions and PKCE requirement.
- `src/Modules/Sessions/Adapters/TokenStore.cs`, `Contracts/*`: the token and authorization stores, replay and race routing, failure marking.
- `src/Modules/Protocol/Core/{AuthorizeEndpoint.cs, ReferenceIds.cs, TokenEndpoint.cs, TokenRequestTransaction.cs, ProtocolServer.cs}`, `Contracts/ProtocolContract.cs`: the endpoint, the port and its default, reference IDs, scope rules, and replay on dispose.
- `src/Gatekeep.Host.Hosted/Program.cs`, `src/Adapters/Hosting/SecurityHeaders.cs`: composition and page headers.
- Tests:
  - new: `AuthorizationCodeTests`, `TestAuthorizationSignIn`, `SessionStoresTests`, `SignInPortRuleTests`;
  - updated: discovery, cross-Tenant registries, canary, `MigrateCommandTests` (26).

**Deviations from the spec**
- The authorize transaction opens at `ExtractAuthorizationRequestContext`, because OpenIddict's client checks read through it.
- A validation error after the client and redirect URI are trusted goes back to the client with `iss`. OpenIddict normally answers those locally.
- A code exchange may send only `scope=openid`, which is dropped before OpenIddict sees it, because OpenIddict 7.7.2 refuses any scope there. Any other scope gets `invalid_scope`.
- `AddGatekeepProtocol` takes a page-headers delegate, and `TryAdd`s the release sign-in.
- Only `token` and `authorization` grants are narrowed. `user_session` and `signin_transaction` keep table-wide UPDATE.

**Review findings.** 27 findings: 17 patched (9 root causes), 0 deferred, and 10 rejected (3 false, 7 low). Reasons are in the triage log.

**Follow-up review: recommended (`true`).** Six medium entries were patched (patched counts by verdict: medium 6, low 11). The unverified risks a second pass should check:
- The foreign-prefix logging now runs inside a token-request handler. A second pass should confirm it never logs a value or holds two pooled connections.
- The `scope=openid` drop relies on OpenIddict's handler order.
- The swallowed-failure test reaches `TokenRequestTransaction.Store` by reflection, and assumes the ID token row is OpenIddict's last write.

**Verification**
- Implementer runs in the tests container, before the patches:
  - Architecture: 758 of 758.
  - `AuthorizationCodeTests`, `SessionStoresTests`, `DirectoryTests` and `SessionTablesTests`: 180 of 180.
- After the patches, in the same container: `AuthorizationCodeTests` 36 of 36, `DirectoryTests` 69 of 69 and `SessionStoresTests` 4 of 4.
- The full local run was stopped for low memory, so the full Architecture and Isolation suites run in CI on PR #54.
- **Matrix audit:** every I/O row has a test in `AuthorizationCodeTests`, `DirectoryTests` or `SessionStoresTests`, and those classes passed in the runs above.

**Residual risks**
- `form_post` auto-submit hasn't been tried in a real browser under Hosted's headers.
- Discovery still lists the `consent` and `select_account` prompt values.
- The real Host.Hosted is never driven through authorize; the release default is tested through Protocol's own `TryAdd`.
