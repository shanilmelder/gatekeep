# Epic 2 Context: OIDC core

<!-- Generated from planning artifacts. Regenerate with compile-epic-context if planning docs change. -->

## Goal

Make every Tenant a standalone OpenID Provider: its own issuer, discovery document and JWKS, automatically rotated Signing Keys held in OpenBao Transit, and a working token pipeline (Client Credentials, Authorization Code with PKCE, rotating refresh tokens, userinfo and revocation). It starts with a spike that proves OpenIddict can be wrapped per Tenant, so later sign-in, Application and key-operation epics build on tested protocol behaviour instead of assumptions. Real sign-in screens are not part of this epic; flows run through a test-only authenticator.

## Stories

- Story 2.1: Prove per-Tenant options and Transit signing
- Story 2.2: Prove custom stores and revocation commit
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

- Each Tenant publishes valid discovery and JWKS and offers token, userinfo and RFC 7009 revocation endpoints. Follow RFC 9700 and record any deviation. Honour `prompt=login`, `max_age`, `auth_time` and `amr`.
- One fixed asymmetric algorithm; anything else, including `alg: none`, is rejected. Access tokens are `typ: at+jwt`. ID tokens are never accepted as access tokens.
- PKCE S256 is mandatory on every code flow, including confidential clients; `plain` and missing PKCE are refused. Codes are single-use and bound to client, redirect URI and Tenant; replay revokes tokens issued from the code. Authorization responses include `iss`. Implicit and ROPC grants must not exist. An unregistered `redirect_uri` never redirects.
- Refresh tokens rotate on every use with no reuse leeway; reuse revokes the whole Token Family and is logged. Absolute and inactivity lifetimes both apply.
- Signing Keys: a `next` key is always published for at least the JWKS cache limit before signing; `previous` verifies until tokens expire, then is retired and destroyed. Rotating one Tenant never touches another.
- Tenant isolation: tokens carry only that Tenant's issuer and verify only against that Tenant's JWKS; Tenants share no key; credentials from Tenant A are refused at Tenant B.
- Token and refresh endpoints are rate limited per Tenant and per source. No secret or token value may appear in logs (canary scan) or be stored raw.
- Lifetimes, code lifetime, key maximum age and JWKS cache limit come from the security-limits constants in the Kernel file; cite them, never hard-code or make them settings (key maximum age has no v1 setting).

## Technical Decisions

- **OpenIddict 7.7.2, wrapped.** OpenIddict owns authorization, token, userinfo, revocation, end-session, discovery and JWKS endpoints on Tenant hosts. The first Gatekeep handler per request replaces `context.Transaction.Options` with a per-Tenant copy and sets `BaseUri` from the stored issuer; nothing later reads global options. Global signing/encryption credentials are inert keys that throw, and a test proves they never reach a token or JWKS. Entity caching off; OpenIddict pruning unused (pruning is a job).
- **Spike fallback.** If the spike fails, switch to per-Tenant options through a keyed provider and amend the OpenIddict architecture decision before discovery/JWKS work starts.
- **Custom stores.** Application store lives in Directory adapters; authorization and token stores in Sessions adapters. Scope store unused; a Gatekeep handler validates scopes. Client authentication is a Gatekeep handler calling Directory's contract against `client_secret`; OpenIddict's secret column stays empty.
- **Sign-in handoff.** Protocol calls `IAuthentication.Begin` (creates `signin_transaction`) and later receives an `AuthenticationResult` (Session, `amr`, `auth_time`). Only Protocol issues codes.
- **Token formats.** RS256 with RSA-3072, a Deployment-wide constant. Access tokens JWS, unencrypted. Codes and refresh tokens are reference tokens protected by the Tenant's token protection key (random 256-bit, wrapped by Transit; `Host.Hosted` may cache it unwrapped up to 5 minutes). Opaque artifacts are `{tenantPublicId}.{random}` with at least 256 random bits; a Tenant mismatch is rejected before lookup. Unauthenticated mismatches log at most once per source per hour; authenticated cross-Tenant attempts always log.
- **Key custody.** All access via Kernel `IKeyCustody`. Each Signing Key is its own non-exportable Transit key named `sig-{tenantId}-{rowId}` or `mgmt-{tenantId}-{rowId}`; create the Transit key first from a pre-generated row ID, then commit the row. Orphan sweep removes only `sig-`/`mgmt-` keys with no row after 24 hours; secret-class keys are never touched. Signing happens in OpenBao.
- **Key lifecycle.** `signing_key` row is authoritative, `purpose` is `signing` or `management`. States next → current → previous → retired (or revoked). Each state change is one command leaving exactly one `current` and one `next` per purpose. Routine promotion requires `next` published at least 15 minutes earlier (new Tenants may promote at once). `previous` retires after hard token lifetime + 15 minutes. Transit destruction is a post-commit job; failures retry and write an audit event. Daily job rotates keys within 30 days of maximum age. JWKS = `signing` keys in next/current/previous, `Cache-Control: max-age=900`, cached per Tenant in `Host.Hosted` up to 5 seconds, cleared by `NOTIFY`. `management` keys never appear in JWKS; `Host.Hosted`'s token endpoint refuses the Management API audience.
- **Issuer and host.** Issuer comes from the stored Tenant record, resolved by exact match on `tenant_host`; a forged `Host` header can't change it.
- **Sessions and transactions.** `user_session` stores only SHA-256 of a 256-bit ID plus `amr`, `auth_time`, Connection, idle and absolute expiry. `signin_transaction` (Authentication) is bound to browser cookie, Tenant and Application, 30-minute sliding lifetime. Cookies `__Host-gk_session` / `__Host-gk_txn`: Secure, HttpOnly, SameSite=Lax, Path=/, no Domain.
- **Token Family and revocation.** Each completed code flow creates one ad-hoc authorization anchored to one `user_session`; that authorization is the Token Family. `ISessions.RevokeAccess(context, scope, exceptSessionId)` is the only revocation path. Natural Session expiry doesn't end a family. Access tokens are not revocable.
- **Mutation path.** Every state change is a command in one `CommandContext` writing state, audit event and jobs together; OpenIddict store writes run in a `CommandContext` opened by the first Gatekeep handler and committed at endpoint end. Refresh reuse and code replay revocations commit in a separate `FailureContext` even though the response is an error. No MediatR.
- **System Application.** One hidden per Tenant, created with the Tenant (plus backfill); filtered from list/edit/delete/export, never issued a code or token.
- **Rate limiting.** `IRateLimiter` counters live in `UNLOGGED` `tenant` tables under row-level security.
- **Table ownership.** Keys: `signing_key`, protection key wraps. Directory: `application`, `client_secret`. Sessions: `user_session`, `authorization`, `token`. Authentication: `signin_transaction`, attempt counters. Identity: `user`. Every new table ships with its registry entry, RLS policies and grants in the same migration; cross-module FKs are composite or to `tenant`, `ON DELETE RESTRICT`.
- **Errors.** OIDC endpoints return protocol errors; the static error page for a bad `redirect_uri` uses the fixed Hosted CSP (`default-src 'none'; script-src 'self'; ... frame-ancestors 'none'`) and shows fixed text only.

## UX & Interaction Patterns

- Only one screen: the Generic error page from `Gatekeep Hosted Login.dc.html`, served as a static fixed-text page with no redirect. Hosted Login (Story 4.1) replaces it later.

## Cross-Story Dependencies

- Stories 2.1 and 2.2 (spike) block 2.3 onward; a failed proof forces the keyed-provider fallback first.
- 2.3 adds key creation as a step in Epic 1's Tenant creation Operation and backfills existing Tenants; 2.8 does the same for the system Application.
- 2.4 builds on 2.3's key table; its destruction-failure audit event feeds Epic 11 alerts. Manual rotate/revoke is Epic 9.
- 2.5 uses a placeholder audience until Story 3.7 grants real API audiences; Epic 3 adds Application management UI.
- 2.6 and 2.7 precede 2.9 and 2.10; the test-only authenticator in `tests/` must not ship in release builds and is replaced by real sign-in in Epic 4.
- 2.9 and 2.10 remove the code and refresh-token artifacts from the Story 1.31 cross-Tenant pending list.
- Relies on Epic 1: `TenantScope`, `CommandContext`, `IAuditAppender`, `IKeyCustody` (OpenBao Transit), jobs, Operations, `tenant_host` resolution, the cross-Tenant suite and the canary scan.
- OpenID conformance on real sign-in comes in Story 4.14; final conformance in Epic 18.
