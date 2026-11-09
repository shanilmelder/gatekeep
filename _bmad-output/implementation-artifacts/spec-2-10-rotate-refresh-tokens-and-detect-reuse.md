---
title: 'Story 2.10: Rotate refresh tokens and detect reuse'
type: 'feature'
created: '2026-11-09'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-2-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-2-9-run-the-authorization-code-flow-with-pkce.md'
  - '{project-root}/docs/spikes/2-2-openiddict-stores.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** The code flow (2.9) issues only access and ID tokens. A relying party must send the User through sign-in again every 15 minutes. There is no refresh token, so there is no rotation and no reuse detection, and Story 1.31's cross-Tenant suite still lists "refresh token" as pending on 2-10 (FR-15, FR-13, NFR-3, AD-13, AD-5).

**Approach:** Enable the refresh token grant on Tenant hosts.
- A code exchange whose authorization asked for `offline_access` also returns a refresh token. It is a `{tenantPublicId}.{random}` reference token, stored only as a hash.
- Each use rotates it, with no leeway.
- Presenting a rotated token again revokes the whole Token Family through `ISessions.RevokeAccessAsync(TokenReuse)`, committed through `FailureContext`.
- An absolute limit and an inactivity limit (§5.2) both apply.
- The existing per-Tenant and per-source token-request limits cover the refresh grant.

## Boundaries & Constraints

**Always:**
- **Kernel limits (`SecurityLimits`):**
  - `RefreshTokenAbsoluteLifetime` is 30 days, with a hard maximum `HardRefreshTokenAbsoluteLifetime` of 90 days.
  - `RefreshTokenInactivityLifetime` is 7 days, with a hard maximum `HardRefreshTokenInactivityLifetime` of 30 days.
  - XML docs cite §5.2. The defaults are what this story uses; Story 3.4 makes them configurable within the hard limits.
- **One forward-only migration, `Migration20261111000000AllowRefreshTokens.cs`:**
  - A `web` Application's grant set is `{authorization_code}` or `{authorization_code, refresh_token}`. Change the 2.9 CHECK.
  - `CreateWebClientAsync` writes both grants.
  - Widen `gk_hosted`'s column UPDATE grants only if the stores now write more columns, in both the migration and `TableRegistry`.
  - Bump `MigrateCommandTests` from 26 to 27, in all four places.
- **Authorize:**
  - Scope may be `openid` or `openid offline_access`. Anything else is still `invalid_scope`.
  - `offline_access` is accepted only for an Application allowed `refresh_token`; otherwise it's `invalid_scope`.
  - The authorization's scopes record what was granted.
- **Code exchange:** it returns a `refresh_token` only when `offline_access` was granted. Otherwise the response is exactly as in 2.9.
- **Refresh grant (`grant_type=refresh_token`):**
  - Same client authentication as before: the secret is required, and every failure is `invalid_client`.
  - The token must belong to the same client and Tenant.
  - It returns a new access token, a new ID token (`sub`, `sid`, `auth_time` and `amr` from the authorization's anchored Session), and a **new** refresh token.
  - The presented token becomes `redeemed`. `SetRefreshTokenReuseLeeway(TimeSpan.Zero)`; rolling tokens stay on.
  - A `scope` other than one already granted is `invalid_scope`.
- **Limits:**
  - **Inactivity:** each refresh token expires `RefreshTokenInactivityLifetime` after it was issued.
  - **Absolute:** no refresh token in a family outlives the authorization's `creation_date + RefreshTokenAbsoluteLifetime`.
    - A new token's expiry is the earlier of the inactivity and absolute ends.
    - A refresh presented after the absolute end is `invalid_grant`, even if its own expiry was set wrongly.
  - An expired token is `invalid_grant` and revokes nothing.
- **Reuse:**
  - A rotated (`redeemed`) refresh token presented again is `invalid_grant`.
  - The store's `RevokeByAuthorizationIdAsync` routes to `RevokeAccessAsync(Authorization scope, RevocationReason.TokenReuse, Actor.Anonymous)`. That revokes the authorization and every token in it, the newest refresh and access tokens included. It writes one `sessions.access.revoked`, recorded on the request and committed through `FailureContext`.
  - Two concurrent refreshes of one token: exactly one succeeds, and the loser revokes the family (`TokenReuse`), as the 2.9 code race does.
- **Late refusals:**
  - Write down, in Design Notes and in the code, which refusals after a successful redemption still burn the presented token.
  - Today the only such refusal is a family revoked mid-request. There is no User status yet; Epic 5 adds "blocked".
  - Any late refusal commits the burn through `FailureContext`.
- **Revoked family:** a refresh token whose authorization is `revoked` (logout, Session end, any FR-48 trigger through `RevokeAccessAsync`) is `invalid_grant`. Natural Session expiry doesn't end the family (AD-13).
- **Reference IDs:**
  - The 2.9 handlers give refresh tokens `{tenantPublicId}.{base64url of 32 random bytes}` and reject a foreign or garbage prefix with `invalid_grant` before lookup.
  - That rejection is logged as the same unauthenticated cross-Tenant mismatch as for codes.
  - The `token` table holds only the hash. A test scans every column of every `token` row for the raw refresh token and finds nothing.
- **Rate limits:** a refresh request counts against the existing `TokenRequestTenantAttempts` and `TokenRequestSourceAttempts` limits. Past either it gets 429, `Retry-After`, and an OAuth error body.
- **Discovery:** `grant_types_supported` is `[authorization_code, client_credentials, refresh_token]` and `scopes_supported` includes `offline_access`.
- **Cross-Tenant:** `ArtifactRegistry` `"refresh token"` goes from Pending("2-10") to Covered, by a test that presents Tenant A's refresh token at Tenant B.
- **Canary:** a `protocol.refresh_token` flow plants the refresh token and finds it nowhere in logs or the database.

**Never:**
- No revocation endpoint, userinfo endpoint or `prompt`/`max_age` work (Story 2.11).
- No Admin-configurable lifetimes (Story 3.4), no User block or disable (Epic 5), and no token pruning job.
- No reuse leeway, no non-rolling refresh tokens, and no refresh tokens for Client Credentials.
- No change to earlier migrations, and no raw refresh token in any column, log or exception.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Issued with offline_access | Code flow with `scope=openid offline_access` | Exchange returns `refresh_token` starting with the Tenant's `ten_` prefix; one refresh row (hash only) in the family | No error expected |
| Not issued without it | `scope=openid` | No `refresh_token` in the exchange | No error expected |
| offline_access not allowed | Application allowed only `authorization_code` asks for `offline_access` | Error redirect `invalid_scope` | — |
| Rotate | Refresh with R1 | 200 with new access token, ID token and R2 ≠ R1; R1 row `redeemed` | No error expected |
| Old one stops | R1 again after rotation | 400 `invalid_grant`; the family is revoked (R2 now refused); one `sessions.access.revoked` committed | Revocation committed despite the error |
| Chain | R1→R2→R3 | Each works once; R3 valid | No error expected |
| Race | Two concurrent refreshes with R1 | Exactly one 200; family revoked afterwards | — |
| Inactivity | R1 used after 7 days + 1 s (time advanced) | 400 `invalid_grant`; nothing revoked | — |
| Absolute | Chain refreshed every 6 days until past 30 days from the code exchange | Refused once past the absolute end; expiry of the last issued token ≤ absolute end | — |
| Revoked family | Family revoked through `RevokeAccessAsync(Session)` | Refresh gets 400 `invalid_grant` | — |
| Other client | R1 presented with another client of the same Tenant | 400 `invalid_grant` | — |
| Other Tenant | A's R1 at Tenant B | 400 `invalid_grant`, before lookup; one mismatch event in B's Log, none in A's | — |
| Garbage prefix | Token with no dot or a foreign `ten_` | 400 `invalid_grant` | — |
| Extra scope | Refresh with `scope=openid email` | 400 `invalid_scope` | — |
| Rate limit | 61 refreshes from one source in a minute | 61st gets 429 with `Retry-After`; another source still works | — |
| No raw value | After issue and rotation | No column of any `token` row contains R1 or R2 | — |
| Discovery | GET discovery | Grants include `refresh_token`; `offline_access` in `scopes_supported` | — |
| Web CHECK | Insert `web` row with `{refresh_token}` alone | Refused | 23514 |

</intent-contract>

## Code Map

- `src/Modules/Protocol/Core/ProtocolServer.cs` -- server options from 2.9. Add `AllowRefreshTokenFlow()`, `SetRefreshTokenLifetime(...)`, `SetRefreshTokenReuseLeeway(TimeSpan.Zero)` and the reference refresh tokens. Rolling tokens are already the default; keep it.
- `src/Modules/Protocol/Core/AuthorizeEndpoint.cs` -- the 2.9 openid-only scope rule and the claims and destinations. Allow `offline_access` when the Application has `refresh_token`, record it on the authorization, and set the destinations. `AuthorizePassthrough` is around `:315-401`.
- `src/Modules/Protocol/Core/TokenEndpoint.cs` -- `LimitTokenRequests` (it already counts every grant; prove it for refresh), `RefuseTokenTargets` (the code-grant scope rule from 2.9; add the refresh-grant rule), `AuthenticateGatekeepClient`, `KeepUnauthenticatedMismatch` and `SignInClient` (Client Credentials only). The refresh grant needs a principal rebuilt from the authorization's anchored Session (`sid`, `auth_time`, `amr`) and the absolute-limit check.
- `src/Modules/Protocol/Core/ReferenceIds.cs:~99` -- refresh tokens are already in `ValidTokenTypes` for the prefix check. Confirm `AttachTenantReferenceId` covers refresh tokens.
- `src/Modules/Sessions/Adapters/TokenStore.cs:~150-180` -- `RevokeFamilyAsync` already picks `TokenReuse` for a presented refresh token and `CodeReplay` for a code. Add any lookups and updates refresh needs, keep the race path for refresh tokens, and keep `RequireWritable`.
- `src/Modules/Sessions/Contracts/*`, `Core/SessionRevocation.cs` -- `RevokeAccessAsync` and the Session reads the principal needs. Add a read-only contract method if Protocol needs the anchored Session's `amr` and `auth_time`.
- `src/Modules/Directory/Core/DirectoryService.cs` (`CreateWebClientAsync`), `Adapters/ApplicationStore.cs` (permissions: `gt:refresh_token`, `scp:offline_access` if needed).
- `src/Adapters/Postgres/Migrations/Migration20261110000000CreateCodeFlow.cs` -- the `web` CHECK to supersede. `TableRegistry.cs` holds the token and authorization column grants.
- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs` -- the new constants.
- Tests:
  - `tests/Isolation/Protocol/AuthorizationCodeTests.cs` -- the `CodeFlow` helpers, `ShiftedTimeProvider`, the race test pattern, and the discovery test to update.
  - `ClientCredentialsTests.cs` -- the rate-limit tests pattern and discovery.
  - `tests/Isolation/CrossTenant/ArtifactRegistry.cs:41` -- refresh token goes from Pending to Covered.
  - `tests/Isolation/Canary/CanaryFlows.cs` -- the 2.9 `protocol.authorization_code` flow pattern.
  - `tests/Isolation/MigrateCommandTests.cs` -- 26 → 27.

## Tasks & Acceptance

**Execution:**
- [ ] `src/Gatekeep.Kernel/Limits/SecurityLimits.cs` -- the four refresh constants.
- [ ] `src/Adapters/Postgres/Migrations/Migration20261111000000AllowRefreshTokens.cs`, `TableRegistry.cs`, `MigrateCommandTests.cs` -- the `web` grant CHECK and any grant changes.
- [ ] `src/Modules/Directory/**` -- web clients get `refresh_token`, plus the store permissions.
- [ ] `src/Modules/Sessions/**` -- refresh lookups and updates, reuse and race revocation, and any read the principal needs.
- [ ] `src/Modules/Protocol/**` -- the refresh grant, `offline_access`, the lifetimes, the absolute limit, the principal rebuild, the scope rule, and the late-refusal burn.
- [ ] `tests/Isolation/Protocol/RefreshTokenTests.cs` (new), the discovery tests, `CrossTenant/ArtifactRegistry.cs`, `Canary/*`, `Directory/*` -- one test per I/O matrix row against real Postgres and OpenBao.
- [ ] `docs/spikes/2-2-openiddict-stores.md`, `deferred-work.md` -- record the refresh wiring.

**Acceptance Criteria:**
- Given a seeded `web` client that completed the code flow with `offline_access`, when it refreshes, then it gets a new refresh token, and the old one, presented again, is refused and revokes the family in a committed revocation.
- Given CI's Architecture and Isolation suites, when they run, then all pass, including the 2.3–2.9 Protocol tests and the cross-Tenant suite with "refresh token" covered.

## Spec Change Log

## Review Triage Log

## Design Notes

**Absolute limit.** OpenIddict's refresh lifetime is per token, so rotating forever would never hit a family-wide end. The authorization (the Token Family, AD-13) has a creation date. Capping each new token's expiry at that date plus the absolute lifetime, and refusing any refresh past it, gives both limits without a new column.

**Late refusals that burn.** OpenIddict marks the presented refresh token `redeemed` before the new tokens are generated. A refusal after that point (today only a family revoked concurrently; later a blocked User in Epic 5) must not leave the token usable, so its burn is committed through `FailureContext`, like a revocation.

## Verification

**Commands:**
- CI on the PR (Architecture and Isolation suites in Docker) -- expected: green. Don't run the full suite locally (low memory); run targeted test classes one at a time in the tests container.
