# Epic 2 Context: OIDC core

<!-- Generated from planning artifacts. Regenerate with compile-epic-context if planning docs change. -->

## Goal

Make every Tenant its own OpenID Provider. Each has an issuer taken from its stored record, its own discovery document and JWKS, Signing Keys held in OpenBao Transit that rotate automatically, and a working token pipeline: Client Credentials, Authorization Code with PKCE, rotating refresh tokens with reuse detection, userinfo and revocation. The epic starts with spikes, now done and passed, which proved that OpenIddict can be wrapped per Tenant. That lets later epics on sign-in, Applications, key operations and the Management API build on tested protocol behaviour. This epic builds no real sign-in screens: flows run through a test-only authenticator, which must never ship in a release build.

## Stories

- Story 2.1: Prove per-Tenant options and Transit signing (done)
- Story 2.2: Prove custom stores and revocation commit (done)
- Story 2.3: Publish discovery and JWKS per Tenant
- Story 2.4: Rotate Signing Keys automatically
- Story 2.5: Issue a token by Client Credentials
- Story 2.6: Add Session and transaction tables
- Story 2.7: Build the one revocation path
- Story 2.8: Add the system Application
- Story 2.9: Run the authorization code flow with PKCE
- Story 2.10: Rotate refresh tokens and detect reuse
- Story 2.11: Offer userinfo and revocation

## Requirements & Constraints

- **Protocol:** follow RFC 9700. Use one fixed asymmetric algorithm, `at+jwt` access tokens and `iss` in authorization responses. Honour `prompt=login`, `max_age`, `auth_time` and `amr` through the `AuthenticationResult`. S256 PKCE is mandatory and `plain` or a missing challenge is refused. Implicit and ROPC grants don't exist. Codes are single-use and bound to client, redirect URI and Tenant, and a replayed code revokes the tokens issued from it. An unregistered `redirect_uri` never redirects.
- **Refresh tokens:** they rotate on every use with no leeway. Reuse revokes the whole Token Family and is logged. Absolute and inactivity lifetimes both apply. The token table stores no raw token value.
- **Tenant isolation:** an issuer can never come from the `Host` header. JWKS holds only that Tenant's keys, and no two Tenants share a key. A credential, code or token from Tenant A is refused at Tenant B, and an opaque artifact whose `tenantPublicId` doesn't match is rejected before any lookup. Authenticated cross-Tenant attempts always write a Log event. Unauthenticated mismatches increment a counter and log at most once per source per hour. When a new artifact type ships (code, refresh token), its cross-Tenant case must run and it leaves the Story 1.31 pending list.
- **Rate limits:** token and refresh requests are limited per Tenant and per source through `IRateLimiter`, with counters in `UNLOGGED` `tenant` rows under RLS.
- **No secrets in logs:** the canary scan must find no secret or token in operational logs or the database. Credential values use `Secret<T>`.
- **Limits:** lifetimes (code, refresh, key maximum age, hard token lifetime) come from the §5.2 constants in the one Kernel file. Never hard-code them.

## Technical Decisions

- **OpenIddict 7.7.2, wrapped:** OpenIddict owns the authorization, token, userinfo, revocation, end-session, discovery and JWKS endpoints on Tenant hosts.
  - The first Gatekeep handler (`ProcessRequestContext`, order `int.MinValue`) resolves the Tenant by exact `tenant_host` match. It swaps in a per-Tenant options copy, sets `BaseUri`/`Issuer` from the stored issuer and opens the `TenantScope`. Keep a test that asserts it runs first and that `ResolveRequestUri` stays removed.
  - Build every options copy from the same pipeline, so Deployment-wide settings stay identical. Set `IssuerSigningKeys` and `TokenDecryptionKeys` explicitly per copy.
  - Global credentials are inert: they throw if used, and a test asserts they never reach a JWKS or a token.
  - Custom stores: the application store lives in Directory, and the authorization and token stores live in Sessions. The scope store is unused, and a Gatekeep handler validates scopes against APIs.
  - Keep entity caching disabled. Pruning is a job, not OpenIddict's.
  - Client authentication is a Gatekeep handler calling Directory's contract against `client_secret`, and OpenIddict's secret column stays empty. Any new endpoint that authenticates clients, such as revocation, must be covered by that handler before it's enabled.
  - Directory writes `application` rows itself, never through `OpenIddictApplicationManager`.
- **Token formats:** RS256 with RSA-3072 is a Deployment-wide constant. Access tokens are unencrypted JWS with `typ: at+jwt`. Codes and refresh tokens are reference tokens of the form `{tenantPublicId}.{random}`, with at least 256 random bits, stored only as a SHA-256 hash. Their internal protection uses the Tenant's token protection key, a random 256-bit key wrapped by Transit and cached unwrapped for at most 5 minutes. This needs a stored, unique, dot-free Tenant public ID before codes are issued.
- **Signing in Transit:** signing happens in OpenBao through `IKeyCustody`, and no host process holds private key material. The `kid` is `{transit key name}.v{version}`. Transit key names are `sig-{tenantId}-{rowId}` and `mgmt-{tenantId}-{rowId}`: create the key first, then commit the row. The PEM-parsing calls are banned in `src/`, so build the RSA public key from SubjectPublicKeyInfo or from modulus and exponent. Signing blocks synchronously, so load-test the token endpoint before it ships. Bound every custody call with a timeout, and evict failed Tenant builds rather than caching them.
- **Signing Key lifecycle:** states are `next → current → previous → retired`, and any state can become `revoked`. The `signing_key` row is authoritative, with `purpose` set to `signing` or `management`. At commit, each Tenant has exactly one `current` and one `next` per purpose. JWKS serves `next`, `current` and `previous` signing keys with `Cache-Control: max-age=900`. `Host.Hosted` may cache it for 5 seconds, cleared by `NOTIFY`. `management` keys are never published. Routine promotion needs `next` to have been published at least 15 minutes earlier. A daily job rotates keys within 30 days of the maximum age. A `previous` key retires once the hard token lifetime plus 15 minutes has passed. Transit keys are destroyed by a job after commit, which retries on failure and writes an audit event. An orphan sweep removes only `sig-`/`mgmt-` keys that have had no row for 24 hours.
- **Sessions and transactions:**
  - `user_session` stores only a SHA-256 of a 256-bit ID, plus `amr`, `auth_time`, the Connection, and idle and absolute expiry.
  - `signin_transaction` belongs to Authentication. It is bound to the browser cookie, Tenant and Application, holds the authorization parameters and completed steps, and has a 30-minute sliding lifetime. Expired rows are kept for 1 hour.
  - The cookies are `__Host-gk_session` and `__Host-gk_txn`, set `Secure; HttpOnly; SameSite=Lax; Path=/` with no `Domain`.
  - Protocol calls `IAuthentication.Begin` and receives an `AuthenticationResult`. Only Protocol issues codes.
- **Token Family:** each completed code flow creates one ad-hoc OpenIddict authorization, anchored to one `user_session`, and that authorization is the Token Family. `ISessions.RevokeAccess(context, scope, exceptSessionId)` is the only revocation path, and a generated test walks the FR-48 triggers. OpenIddict's `RevokeByAuthorizationIdAsync` and the authorization-store revocations must route into it or be captured.
  - Revocations on refused requests (reuse, code replay, late refusals that must burn a token) are recorded on the request and replayed through `FailureContext` after the rollback. That includes the unhandled-exception path.
  - Track SQL failures that OpenIddict swallows, and never report success on an aborted transaction.
  - Natural Session expiry doesn't end a family. Access tokens aren't revocable.
- **Schema hints from the spike:** `authorization` and `token` use text `status` and `type`, `text[]` scopes, `jsonb` properties and a concurrency token. Tokens have a nullable hashed `reference_id`, unique per Tenant, and a `payload`. Use composite `(tenant_id, …)` foreign keys. `gk_hosted` gets only `SELECT`, `INSERT` and `UPDATE`.
- **Ownership:** Keys owns `signing_key` and the protection key wraps. Directory owns `application`, `client_secret` and `client_usage`. Authentication owns `signin_transaction` and the attempt counters. Sessions owns `user_session`, `authorization` and `token`. Identity owns `user`. Each new table's registry entry, RLS policies and grants go in the same migration.
- **Mutations:** every state change is a command in one `CommandContext` that writes the state, the audit event and any jobs together. OpenIddict store writes enlist in the context that the first Gatekeep handler opens. Audit codes follow `{domain}.{object}.{action}`.
- **System Application:** each Tenant has exactly one, created with the Tenant and backfilled for existing Tenants. Directory hides it from list, edit, delete and export. It exists only to bind Portal `signin_transaction` rows, and no code or token is ever issued for it.
- **Conventions:** OIDC endpoints return protocol errors, and everything else uses RFC 9457. UUIDv7 internally, with prefixed public IDs. Times are UTC `timestamptz`.

## UX & Interaction Patterns

The only screen in this epic is the Generic error page (L409 in `Gatekeep Hosted Login.dc.html`). It is a static, fixed-text page with the AD-21 CSP, shown for an unregistered `redirect_uri`, and Story 4.1 replaces it later.

## Cross-Story Dependencies

- **Order within the epic:**
  - 2.3 builds `signing_key`, the token protection key wraps, the Tenant public ID and `tenant_host`-based issuer resolution that 2.4, 2.5 and 2.9 rely on.
  - 2.6 provides the tables used by 2.7, 2.9 and 2.10.
  - 2.7 must exist before 2.10's reuse revocation.
  - 2.8 depends on the Directory `application` table from 2.5.
  - 2.11 depends on the access and refresh tokens from 2.5, 2.9 and 2.10.
- **From Epic 1:** relies on Tenant resolution, `TenantScope`/RLS, the Tenant creation Operation (key creation and the system Application are steps in it, each with a backfill), `IKeyCustody`/OpenBao policies, `IRateLimiter`, `IAuditAppender`, `FailureContext`, the canary scan and the Story 1.31 cross-Tenant suite.
- **For later epics:**
  - Story 3.7 replaces the 2.5 placeholder audience.
  - Story 4.1 replaces the static error page.
  - Story 4.2 binds real sign-in transactions and Sessions.
  - Epic 4 adds the FR-48 triggers that call `RevokeAccess`.
  - Epic 9 adds on-demand rotation and revocation on top of the 2.4 lifecycle.
  - Epic 11 alerts on failed key destruction.
  - The Management token endpoint (AD-33) reuses Directory's client authentication and the `management` keys.
