# Epic 2 Context: OIDC core

<!-- Generated from planning artifacts. Regenerate with compile-epic-context if planning docs change. -->

## Goal

Make every Tenant its own OpenID Provider. Each Tenant gets an issuer read from its stored record, its own discovery document and JWKS, Signing Keys held in OpenBao Transit that rotate on their own, and a working token pipeline: Client Credentials, Authorization Code with PKCE, rotating refresh tokens with reuse detection, userinfo and revocation. The spikes (2.1, 2.2) passed, so wrapping OpenIddict per Tenant stands as designed. The shared session tables (2.6) and the single revocation path (2.7) are built. No real sign-in screens are built in this epic. Flows run through a test-only authenticator in `tests/`, which must never ship in a release build. Later epics (sign-in, Applications, key operations, Management API) build on this protocol behaviour.

## Stories

- Story 2.1: Prove per-Tenant options and Transit signing (done)
- Story 2.2: Prove custom stores and revocation commit (done)
- Story 2.3: Publish discovery and JWKS per Tenant
- Story 2.4: Rotate Signing Keys automatically
- Story 2.5: Issue a token by Client Credentials
- Story 2.6: Add Session and transaction tables (done)
- Story 2.7: Build the one revocation path (done)
- Story 2.8: Add the system Application
- Story 2.9: Run the authorization code flow with PKCE
- Story 2.10: Rotate refresh tokens and detect reuse
- Story 2.11: Offer userinfo and revocation

## Requirements & Constraints

- **Protocol:**
  - Follow RFC 9700. Access tokens are `at+jwt`, and authorization responses carry `iss`.
  - S256 PKCE is mandatory. `plain` or a missing challenge is refused, and `plain` must be removed from OpenIddict's default methods.
  - Implicit and ROPC grants don't exist.
  - Codes are single-use and bound to client, redirect URI and Tenant. A replayed code revokes the tokens issued from it.
  - An unregistered `redirect_uri` never redirects.
  - `prompt=login`, `max_age`, `auth_time` and `amr` are honoured through `AuthenticationResult`.
- **Refresh tokens:** they rotate on every use with no leeway. Reuse revokes the whole Token Family, and that revocation commits even though the response is an error. Absolute and inactivity limits both apply. No raw token value is stored.
- **Tenant isolation:**
  - The issuer never comes from the `Host` header.
  - JWKS holds only that Tenant's keys, and no two Tenants share a key.
  - A credential, code or token from Tenant A is refused at Tenant B. An opaque artifact with the wrong `tenantPublicId` is rejected before any lookup.
  - An authenticated cross-Tenant attempt always writes a Log event. An unauthenticated mismatch increments a counter and logs at most once per source per hour. The spike didn't build that limit.
  - Each new artifact type (code, refresh token) adds its cross-Tenant case and leaves the Story 1.31 pending list.
- **Rate limits:** token and refresh requests are limited per Tenant and per source through `IRateLimiter`, with counters in `UNLOGGED` `tenant` rows under RLS.
- **No secrets in logs:** the canary scan finds no secret or token. Credential values use `Secret<T>`.
- **Fixed limits:** these live as constants in the one Kernel limits file. Never hard-code them.
  - Authorization code: 60 seconds.
  - Access and ID tokens: 15 minutes by default, 1 hour hard.
  - Refresh token: 30 days absolute (90 hard) and 7 days inactivity (30 hard).
  - Signing Key maximum age: 180 days, not configurable in v1.

## Technical Decisions

- **OpenIddict 7.7.2, wrapped.** It owns the authorize, token, userinfo, revocation, end-session, discovery and JWKS endpoints on Tenant hosts.
  - **The first handler:** one Gatekeep handler on `ProcessRequestContext` at order `int.MinValue`. It resolves the Tenant by exact `tenant_host` match, swaps in a per-Tenant options copy, sets `BaseUri`/`Issuer` from the stored issuer and opens the `TenantScope`.
    - Keep the test asserting that this handler runs first and that `ResolveRequestUri` stays removed.
    - Open the scope lazily, or only on endpoints that write. Discovery and JWKS don't need a transaction.
    - Issuers are origins only. Forbid a path or handle it.
  - **Options copies:** build each one from the same pipeline, so the handler list, degraded mode and other Deployment-wide settings stay identical. Set `IssuerSigningKeys` and `TokenDecryptionKeys` explicitly on each copy.
  - **Global credentials:** they are inert and throw if used. A test asserts they never reach a JWKS or a token.
  - **Stores:** the application store lives in Directory, and the authorization and token stores live in Sessions. The scope store is unused, and a Gatekeep handler validates scopes against APIs. Entity caching is off. Pruning is a job, not OpenIddict's.
  - **Client authentication:** a Gatekeep handler calls Directory's contract against `client_secret`, and OpenIddict's secret column stays empty. Any newly enabled endpoint that authenticates clients, such as revocation (2.11), must be covered by that handler first.
  - **Application rows:** Directory writes them itself, never through `OpenIddictApplicationManager`, whose validation rejects a confidential client with no secret.
- **Token formats.**
  - RS256 with RSA-3072 is a Deployment-wide constant.
  - Access tokens are unencrypted JWS.
  - Codes and refresh tokens are reference tokens of the form `{tenantPublicId}.{random}`, with at least 256 random bits, stored only as a hash. They are protected with the Tenant's token protection key: a random 256-bit key, wrapped by Transit and cached unwrapped for at most 5 minutes.
  - A stored, unique, dot-free Tenant public ID must exist before 2.9 issues codes. Story 2.3 is the natural place to add it.
- **Signing in Transit** (through `IKeyCustody`):
  - No host process holds private key material.
  - The `kid` is `{transit key name}.v{version}`. Transit names are `sig-{tenantId}-{rowId}` and `mgmt-{tenantId}-{rowId}`. Create the Transit key first, then commit the row.
  - The PEM-import APIs are banned in `src/`. Build the RSA public key from SubjectPublicKeyInfo (`System.Formats.Asn1`) or from modulus and exponent.
  - Signing blocks a thread-pool thread, so load-test the token endpoint before 2.5 ships.
  - Bound every custody call with a timeout, and evict a failed Tenant build instead of caching it.
  - If a key rotates after a Tenant's runtime is built, signing fails until that runtime is rebuilt. Story 2.4 must handle this.
- **Signing Key lifecycle.**
  - States: `next → current → previous → retired`, and any non-retired state can become `revoked`. The `signing_key` row is authoritative, with `purpose` set to `signing` or `management`.
  - At commit, each Tenant has exactly one `current` and one `next` per purpose. Any command that consumes `next` creates its replacement.
  - JWKS serves `next`, `current` and `previous` signing keys with `Cache-Control: max-age=900`. `Host.Hosted` may cache it for 5 seconds, cleared by `NOTIFY`. `management` keys are never published.
  - **Rotation:**
    - Routine promotion needs `next` published at least 15 minutes earlier. A new Tenant may promote at once.
    - A daily job rotates keys within 30 days of the maximum age.
    - `previous` retires after the hard token lifetime plus 15 minutes.
  - **Destruction:** a job destroys Transit keys after commit. A failure retries and writes an audit event.
  - **Orphan sweep:** it removes only `sig-`/`mgmt-` keys that have had no row for 24 hours, never secret-class keys.
- **Token Family and revocation.**
  - Each completed code flow creates one ad-hoc authorization anchored to one `user_session`. The column is `authorization.user_session_id NOT NULL`, and Client Credentials creates no authorization.
  - `ISessions.RevokeAccessAsync(context, scope, exceptSessionId, reason, actor, ct)` is the only revocation path.
    - Scopes: `Authorization`, `Session`, `User` (the only one with `exceptSessionId`), `Application`, `Tenant`.
    - It sets the authorization row and tokens to `revoked` and writes one `sessions.access.revoked` event.
    - `RevocationReason` is a closed set that includes `token_reuse` and `code_replay`.
    - `RevocationPathTests` text-scans `src/` for other revocation writes.
  - **Story 2.9 must wire the store revocations:**
    - Route the token store's `RevokeByAuthorizationIdAsync` and the authorization store's `RevokeAsync`/`RevokeByApplicationIdAsync` into it, with `Actor.Anonymous` for reuse and replay.
    - `RevokeBySubjectAsync` refuses.
    - No generic `UpdateAsync` may set a revoked status.
    - Record each call on the request, then replay it through `FailureContext.CommitAfterRollbackAsync` at endpoint end, including the unhandled-exception path.
  - **Store failures:** track SQL failures that OpenIddict swallows. Never report success on an aborted transaction.
  - **Story 2.10 must also:**
    - List which late refusals (such as a disabled user) still burn the presented token, and commit that burn through `FailureContext`.
    - Test concurrent refreshes of the same token.
  - Natural Session expiry doesn't end a family. Access tokens aren't revocable.
- **Built tables (2.6):**
  - `user`, `user_session`, `signin_transaction`, `authorization` and `token`. Access and ID token rows are kept because `DisableTokenStorage` is all or nothing.
  - `application_id` columns have no foreign key yet. Story 2.5's migration adds `(tenant_id, application_id) REFERENCES application ON DELETE RESTRICT`.
  - `gk_hosted` has table-wide `UPDATE`, to be narrowed once the stores are built.
  - Confirm the `token.reference_id` CHECK against real OpenIddict output in 2.9.
- **Sessions and transactions.** Cookies are `__Host-gk_session` and `__Host-gk_txn`, set `Secure; HttpOnly; SameSite=Lax; Path=/` with no `Domain`. Protocol calls `IAuthentication.Begin` and receives an `AuthenticationResult`. Only Protocol issues codes.
- **System Application:** each Tenant has exactly one, created with the Tenant and backfilled. Directory hides it from list, edit, delete and export. No code or token is ever issued for it.
- **Ownership:** Keys owns `signing_key` and the protection key wraps. Directory owns `application`, `client_secret` and `client_usage`. Authentication owns `signin_transaction` and the attempt counters. Sessions owns `user_session`, `authorization` and `token`. Identity owns `user`. Each new table's registry entry, RLS policies and grants go in the same migration.
- **Conventions:**
  - Every mutation is one `CommandContext` command writing the state, the audit event and any jobs together. OpenIddict store writes enlist in the context opened by the first handler.
  - Audit codes follow `{domain}.{object}.{action}`.
  - OIDC endpoints return protocol errors, and everything else uses RFC 9457.
  - IDs are UUIDv7 with prefixed public IDs. Times are UTC `timestamptz`.

## UX & Interaction Patterns

The only screen is the Generic error page (L409 in `Gatekeep Hosted Login.dc.html`). It is a static, fixed-text page with the Hosted CSP, shown for an unregistered `redirect_uri`. Story 4.1 replaces it.

## Cross-Story Dependencies

- **Within the epic:**
  - 2.3 adds `signing_key`, the token protection key wraps, the Tenant public ID and the stored-issuer resolution that 2.4, 2.5 and 2.9 need.
  - 2.3's key creation becomes a stage in the Tenant creation Operation (from Story 1.27, which has only the secret-class key stage), with a backfill. Until then, an active Tenant resolves with no Signing Key.
  - 2.5 creates `application`, which 2.8 and 2.9 need.
  - 2.9 and 2.10 build on the 2.6 tables and the 2.7 revocation path.
  - 2.11 needs the tokens from 2.5, 2.9 and 2.10.
- **From Epic 1:** Tenant resolution, `TenantScope`/RLS, the Tenant creation Operation, `IKeyCustody` and OpenBao policies, `IRateLimiter`, `IAuditAppender`, `FailureContext`, the canary scan, and the Story 1.31 cross-Tenant suite.
- **For later epics:**
  - Story 3.7 replaces 2.5's placeholder audience.
  - Story 4.1 replaces the static error page.
  - Story 4.2 binds real transactions and Sessions.
  - Epic 4 adds the FR-48 triggers that call `RevokeAccessAsync`.
  - Epic 9 adds on-demand rotation and revocation.
  - Epic 11 alerts on failed key destruction.
  - The Admin-host Management token endpoint reuses Directory's client authentication and the `management` keys. The Tenant-host token endpoint must refuse the Management API audience.
