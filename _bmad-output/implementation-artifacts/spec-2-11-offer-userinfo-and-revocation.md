---
title: 'Story 2.11: Offer userinfo and revocation'
type: 'feature'
created: '2026-11-09'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-2-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-2-10-rotate-refresh-tokens-and-detect-reuse.md'
  - '{project-root}/docs/spikes/2-2-openiddict-stores.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** Tenant hosts issue access, ID and refresh tokens (2.5, 2.9, 2.10). But a relying party can't read the User's claims, and can't end a refresh token when it's done with it. `prompt=login` and `max_age` are kept on the sign-in transaction but nothing enforces them. So "the protocol honours `auth_time`/`amr`" is unproven (FR-23, RFC 7009, AD-9).

**Approach:** Open `/connect/userinfo` and `/connect/revoke` on Tenant hosts.
- **Userinfo** accepts only this Tenant's `at+jwt` access tokens that carry a User and the `openid` scope. It returns only the claims those scopes allow, which today is just `sub`.
- **Revocation** authenticates the client through Gatekeep's own handler, then ends a refresh token's whole Token Family through `ISessions.RevokeAccessAsync` with a new `client_revoke` reason.
- **Authorize** enforces `prompt=login` and `max_age` against `AuthenticationResult.AuthTime`. It refuses rather than issue a code on an authentication too old for the request.

## Boundaries & Constraints

**Always:**
- **Revocation reason:** add `RevocationReason.ClientRevoke` (`client_revoke`) to the closed set and `All`.
  - One forward-only migration, `Migration20261112000000AddClientRevokeReason.cs`, widens the `end_reason` CHECK. Follow how the CHECK was written in the Sessions migrations.
  - Bump `MigrateCommandTests` from 27 to 28, in all four places. Keep `RevocationPathTests` passing.
- **Server options:** userinfo endpoint `ProtocolContract.UserinfoPath = "/connect/userinfo"` and revocation endpoint `ProtocolContract.RevocationPath = "/connect/revoke"`.
  - Discovery advertises `userinfo_endpoint`, `revocation_endpoint`, and `revocation_endpoint_auth_methods_supported` `[client_secret_basic, client_secret_post]`.
  - Both new paths go in `RouteRegistry` (HostResolved) with their `CrossTenantRouteTests` cases.
- **Userinfo** (GET and POST, bearer token in the header only):
  - Valid only for an access token that verifies against **this** Tenant's JWKS and has `typ` `at+jwt`, a `usr_` `sub`, and the `openid` scope.
  - Refused with 401 `invalid_token` and a `WWW-Authenticate: Bearer` header:
    - an ID token, or anything not typed `at+jwt`;
    - `alg: none` or an unsigned token;
    - an HS* token, or one signed by another Tenant's key;
    - an expired token, or a Client Credentials token (no User);
    - a missing or garbage token.
  - A token without `openid` gets 403 `insufficient_scope`.
  - The response is exactly `{"sub": "usr_…"}`. No other claim exists for any scope yet. Profile and email claims come with Epic 5/6 data.
  - It reads no Session state and writes nothing; it opens no transaction. Access tokens stay non-revocable (AD-13), so a valid unexpired token works after logout until it expires.
- **Revocation** (POST, RFC 7009):
  - **Client authentication:** Gatekeep's `AuthenticateGatekeepClient` covers this endpoint before anything else, exactly as at the token endpoint. Same `invalid_client`, same per-Tenant and per-source rate limits, and the same cross-Tenant client classification and events.
  - **The endpoint's transaction:** it opens the request transaction like the token endpoint. Commit on success, rollback otherwise, with recorded effects replayed through `FailureContext`.
  - **Refresh token of this client:** `RevokeAccessAsync(Authorization(familyId), RevocationReason.ClientRevoke, actor: the client)` revokes the authorization and every token in it, and writes one `sessions.access.revoked`. Pick the closest existing `Actor` for a client, or add `Actor.Client(applicationId)` if the audit model needs it, and record the choice. Then 200 with an empty body.
  - **Answers that revoke nothing:**
    - A refresh token of **another** client of the same Tenant: 200, nothing revoked (RFC 7009 §2.2).
    - Unknown, garbage, already revoked, redeemed or expired: 200, nothing revoked.
    - A foreign `ten_` prefix or a malformed prefix: 200. It's rejected before any lookup and counted as Story 2.5's unauthenticated cross-Tenant mismatch.
    - An access token or an ID token: 400 `unsupported_token_type`. Access tokens aren't revocable (AD-13).
    - `token_type_hint` is a hint only. A wrong hint never changes the outcome.
  - Revoking twice is still 200 and writes nothing the second time.
- **`prompt=login` / `max_age` on authorize:**
  - Protocol derives "the sign-in must be at or after T":
    - `prompt=login` → T = the time the authorize request started;
    - `max_age=N` → T = now − N seconds;
    - both → the later of the two;
    - `max_age=0` → the same as `prompt=login`.
  - It passes T to `IAuthorizationSignIn.CompleteAsync`, by adding a field to the call or to `SignInRequest`'s parameters. It refuses with an error redirect `login_required` (with `iss`) if `AuthenticationResult.AuthTime` is before T.
  - A malformed `max_age` (non-integer or negative) is `invalid_request`.
  - The ID token always carries `auth_time` and `amr` from the `AuthenticationResult`, and `auth_time` is exactly the result's (in seconds).
  - The test sign-in can return a chosen `AuthTime` (a test header), so tests can show both an old authentication refused and a fresh one accepted.
- **No secrets in logs:** the canary flows plant the revoked refresh token and the bearer token sent to userinfo, and find neither in logs.

**Never:**
- No profile, email or custom claims at userinfo, and no consent or scope beyond `openid` and `offline_access`.
- No access-token revocation or introspection endpoint, and no end-session/logout endpoint (Story 4.13).
- No real re-authentication UI (Stories 4.1 and 4.2): a stale authentication is refused, not re-prompted.
- No change to earlier migrations, and no raw token in any column, log or exception.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Userinfo happy | Access token from the code flow | 200 `{"sub":"usr_…"}` exactly | No error expected |
| Userinfo POST | Same token, POST with the header | 200 same body | No error expected |
| ID token | ID token as bearer | 401 `invalid_token`, `WWW-Authenticate` | — |
| alg none | Hand-made JWT with `alg: none`, valid-looking claims | 401 `invalid_token` | — |
| Other Tenant | Tenant A's access token at B's userinfo | 401 `invalid_token` | — |
| Client Credentials token | Machine client's token | 401 `invalid_token` | — |
| Expired | Access token after 15 min (time advanced) | 401 `invalid_token` | — |
| No token / garbage | No header, or `Bearer abc` | 401 `invalid_token` (or `invalid_request` with no header, per RFC 6750) | — |
| Revoke refresh | Owning client revokes R1 (basic auth) | 200; R1 refused at refresh; family revoked; one `sessions.access.revoked` | No error expected |
| Revoke rotated family member | Revoke R2 after R1→R2 | 200; R2 and the family revoked | No error expected |
| Revoke twice | Same R1 again | 200; no second event | — |
| Other client | Another client of the Tenant revokes R1 | 200; R1 still refreshes | Nothing revoked |
| Bad client auth | Wrong secret | 401 `invalid_client` | Same as the token endpoint |
| Foreign prefix | A's R1 at B's revoke (with B's client) | 200; A's R1 still refreshes at A; one mismatch event in B's Log | Rejected before lookup |
| Garbage | `token=abc` | 200; nothing revoked | — |
| Access token | Revoke an access token | 400 `unsupported_token_type` | — |
| Wrong hint | Refresh token with `token_type_hint=access_token` | 200; revoked | — |
| Rate limit | 61 revocations from one source in a minute | 61st 429 with `Retry-After` | — |
| prompt=login fresh | `prompt=login`; the test sign-in returns `auth_time` = now | Code issued; ID token `auth_time` = that time | No error expected |
| prompt=login stale | `prompt=login`; sign-in returns `auth_time` 5 min before the request | Error redirect `login_required` with `iss`; no code; nothing committed | — |
| max_age ok | `max_age=600`; `auth_time` 5 min ago | Code issued | No error expected |
| max_age stale | `max_age=60`; `auth_time` 5 min ago | `login_required` | — |
| max_age=0 | `max_age=0`; `auth_time` 1 s before the request | `login_required` | — |
| bad max_age | `max_age=-1` or `abc` | Error redirect `invalid_request` | — |
| amr | Any issued ID token | `amr` equals the result's `Amr` | — |
| Discovery | GET | `userinfo_endpoint`, `revocation_endpoint`, revocation auth methods basic and post | — |

</intent-contract>

## Code Map

- `src/Modules/Protocol/Core/ProtocolServer.cs` -- options: add the userinfo and revocation endpoint URIs, and passthrough or handlers as the code-flow work did. `EndpointUris` lists them for the Tenant handler.
- `src/Modules/Protocol/Core/TokenEndpoint.cs` -- `LimitTokenRequests`, `BeginTokenTransaction`, `AuthenticateGatekeepClient` (filters bound to the token endpoint today; extend each to the revocation endpoint), `KeepUnauthenticatedMismatch`, `EndTokenTransaction` / `RequestEnd.EndAsync`.
- `src/Modules/Protocol/Core/ReferenceIds.cs` -- `RejectForeignReferenceIds` (extend to the revocation endpoint's token: a foreign prefix answers 200, logged).
- `src/Modules/Protocol/Core/AuthorizeEndpoint.cs` -- `AuthorizePassthrough` and `KeptParameters` (`prompt`, `max_age` are kept), `SetUserClaims`. Add the freshness requirement and its check.
- `src/Modules/Protocol/Contracts/ProtocolContract.cs` -- paths, plus the `IAuthorizationSignIn` signature if it gains the requirement.
- `src/Modules/Sessions/Contracts/Revocation.cs:60-90` -- `RevocationReason`. `Core/SessionRevocation.cs` -- `RevokeAccessAsync`. `Adapters/TokenStore.cs` -- `FindByReferenceIdAsync`, family lookup, `RequireWritable` (a revocation never goes through `UpdateAsync`), and the store's `RevokeAsync` paths. Route OpenIddict's revocation-endpoint revoke into `RevokeAccessAsync`, or handle revocation in a Gatekeep handler before OpenIddict's own revoke. Note which.
- `src/Adapters/Postgres/Migrations/Migration20261102090000CreateSessionTables.cs` and later Sessions migrations -- where the `end_reason` CHECK lives (it may have been redefined by `ConstrainSessionEndReason`). Latest migration: `Migration20261111000000AllowRefreshTokens.cs` (27).
- `src/Gatekeep.Kernel/Audit/*` -- `Actor`, if a client actor is needed.
- Tests:
  - `tests/Isolation/Protocol/{AuthorizationCodeTests.cs, RefreshTokenTests.cs, TestAuthorizationSignIn.cs, ProtocolHost.cs}` -- the `CodeFlow` helpers, refresh helpers, `ShiftedTimeProvider`, test headers.
  - `ClientCredentialsTests.cs` -- the machine-token and rate-limit patterns.
  - `DiscoveryAndJwksTests.cs` -- discovery.
  - `tests/Isolation/CrossTenant/{RouteRegistry.cs, CrossTenantRouteTests.cs}`, `tests/Isolation/Canary/CanaryFlows.cs`, `tests/Architecture/RevocationPathTests.cs`, `tests/Isolation/MigrateCommandTests.cs`.

## Tasks & Acceptance

**Execution:**
- [ ] `src/Modules/Sessions/**`, the migration, `MigrateCommandTests.cs` -- `ClientRevoke` and the CHECK.
- [ ] `src/Modules/Protocol/**` -- the userinfo and revocation endpoints, client auth, limits, transaction and prefix rejection on revocation, and `prompt=login`/`max_age` enforcement.
- [ ] `tests/Isolation/Protocol/TestAuthorizationSignIn.cs` -- a chosen `AuthTime`.
- [ ] `tests/Isolation/Protocol/UserinfoAndRevocationTests.cs` (new), `AuthorizationCodeTests.cs` (the freshness rows), discovery tests, `CrossTenant/*`, `Canary/*` -- one test per I/O matrix row.
- [ ] `docs/spikes/2-2-openiddict-stores.md`, `deferred-work.md` -- record the wiring.

**Acceptance Criteria:**
- Given a code-flow access token, when userinfo is called, then only `sub` is returned. An ID token, `alg: none` or another Tenant's token is refused.
- Given a refresh token, when its client revokes it under RFC 7009, then it and its family stop working.
- Given `prompt=login` or `max_age`, when the test sign-in returns an older `auth_time`, then no code is issued. When it returns a fresh one, the ID token carries that `auth_time` and the result's `amr`.
- Given CI's Architecture and Isolation suites, when they run, then all pass.

## Spec Change Log

## Review Triage Log

## Design Notes

**Why refuse instead of re-prompt.** No sign-in screen exists until Story 4.1. A request that demands a fresher authentication than the sign-in delivered must not get a code. Refusing with `login_required` is safe, and Story 4.2 replaces it with a re-prompt.

**Why access tokens get `unsupported_token_type`.** AD-13 makes access tokens non-revocable, and their 15-minute life is the bound. RFC 7009 §2.2.1 gives `unsupported_token_type` for exactly this, which tells the client honestly that the token stays valid.

## Verification

**Commands:**
- CI on the PR (Architecture and Isolation suites in Docker) -- expected: green. Don't run the full suite locally (low memory); targeted classes one at a time in the tests container at most.
