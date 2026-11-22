---
title: 'Story 4.13: Log out'
type: 'feature'
created: '2026-11-22'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-4-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-4-9-sign-in-with-a-password.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** A User can't end their Session, and an Application can't trigger logout.
- **No endpoint:** there's no OIDC end-session endpoint, and discovery advertises none.
- **No screen:** Hosted Login has no logout confirmation or logged-out screen.
- **Unused URLs:** Story 3.2's registered logout URLs are never used.

(FR-24)

**Approach:**
- **Endpoint:** add OIDC RP-Initiated Logout at `/connect/endsession`.
- **Confirmation:** the browser sees "Log out of {Tenant}?". Confirming ends this browser's Session and its bound Token Families through `RevokeAccess`, and clears the cookie.
- **Redirect:** the browser is sent back to the Application's `post_logout_redirect_uri` by a top-level GET, but only when the request carries a valid `id_token_hint` for that Application and the URL is registered.
- **Otherwise:** the User is logged out and sees "You're logged out." with no redirect.

## Boundaries & Constraints

**Always:**
- **Endpoint:**
  - `ProtocolContract.EndSessionPath = "/connect/endsession"` (GET and POST, as the spec requires). It is configured in `ProtocolServer` with `SetEndSessionEndpointUris` and passthrough, and discovery advertises `end_session_endpoint`.
  - **Errors:** our handler decides every outcome. OpenIddict must never answer an end-session request with an error page. A bad hint or URI is a "no redirect" logout, never an error. Remove or override OpenIddict's hint and URI rejection handlers as needed, and assert that in the discovery/handler tests as `DiscoveryAndJwksTests.cs:444-462` does.
- **Redirect decision:** one pure function, re-run on the confirm POST, so no server state is needed. A redirect target is allowed only when all of these hold:
  1. `id_token_hint` is an ID token this Tenant issued: its signature checks against the Tenant's keys, its issuer is the Tenant's, and it may be expired.
  2. Its `aud` names one of the Tenant's live, non-deleted Applications.
  3. `client_id`, if present, equals that Application.
  4. `post_logout_redirect_uri` exactly equals one of that Application's registered logout URLs. Native Applications also get the RFC 8252 loopback-port exception, as authorize's `TrustRedirectTarget` gives (`ProtocolServer.cs:244-246`).
  - **The target:** the URI with `state` appended when one was given.
  - **Otherwise there is no target.** No outcome reveals which check failed.
- **GET or POST `/connect/endsession`:**
  - **Live Session** (the browser's `__Host-gk_session` cookie names a live Session in this Tenant): render the page with the `logout` step `{tenant}` and a Session-bound CSRF, `base64url(SHA256("gatekeep-logout-csrf\0" ‖ the Session cookie's SHA-256))`. The page also carries the original request parameters (`id_token_hint`, `post_logout_redirect_uri`, `state`, `client_id`) as step data the client posts back.
  - **No live Session:** nothing to end. Clear the cookie and answer as a completed logout: `logged_out` with the decision's target or none.
- **`POST /login/api/logout`** `{idTokenHint?, postLogoutRedirectUri?, state?, clientId?}` with the logout CSRF in `X-Gatekeep-CSRF`:
  - **Checks:** the exact-host Origin check, then CSRF against the presented Session cookie. A failure is 403, as the other Login routes give.
  - **Live Session:** run `ISessions.RevokeAccessAsync(context, new RevocationScope.Session(sessionId), null, RevocationReason.Logout, Actor.User(userId), ct)` in one command, then clear the cookie.
  - **No live Session:** clear the cookie.
  - **Answer:** `logged_out` `{redirectTo: target | null}`, using the decision recomputed from the posted parameters.
  - **Scope:** only the browser's own Session ends. The hint selects only the redirect, never which Session ends.
- **The client:**
  - **`logout`:** "Log out" posts the confirm. "Stay signed in" sends no request and goes `history.back()`.
  - **`logged_out` with `redirectTo`:** navigates there at once with a top-level `window.location.assign`. This is the one external navigation the client makes, and only for that step's server-validated value. It isn't a form post. `navigate.ts` gains a separate, documented function for it.
  - **`logged_out` without one:** shows "You're logged out." with no action.
- **UI** (copy in `messages.tsx`, every new export added to the `HOSTED` list in `tests/browser/fixture/src/main.tsx`):
  - **`LogoutScreen`:** heading "Log out of {Tenant}?", body "You'll be signed out of all {Tenant} apps on this browser.", the secondary button "Stay signed in" and the primary "Log out".
  - **`LoggedOutScreen`:** a ✓ icon and "You're logged out."
  - **Focus and title** follow the existing step rules.
- **Registries:**
  - Add `logout` and `logged_out` to `StepNames`, with factories and client readers.
  - Add both routes to `RouteRegistry` and `CrossTenantRouteTests`: a Tenant A Session cookie or hint at Tenant B ends nothing and gets no redirect.
  - Add a canary flow `protocol.logout` that plants the hint, the Session cookie and the CSRF, none of which may reach a log, Audit event or table.
- **Audit:** nothing new. `RevokeAccess` writes `sessions.access.revoked`.

**Never:**
- No Back-Channel or Front-Channel Logout (v2).
- Never revoke by the hint's `sid`.
- No OpenIddict error page for end-session.
- No `logout_hint` or `ui_locales` handling.
- Never redirect without both checks passing.
- Never put the hint or the Session cookie in a log, Audit event or `Referer`.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Confirm and redirect | live Session, valid hint, registered URL, `state=xyz` | `logout` page; confirm → Session ended, its families and refresh tokens revoked, cookie cleared, `logged_out {redirectTo: url?state=xyz}` | No error expected |
| Refresh after logout | the family's refresh token | `invalid_grant` | refused |
| Invalid hint | tampered or foreign-Tenant hint | logged out; `logged_out {redirectTo:null}` | no redirect |
| Unregistered URL | valid hint, unknown URL | logged out; no redirect | no redirect |
| `client_id` mismatch | hint for A, `client_id` B | no redirect | no redirect |
| Expired hint | valid but expired hint, registered URL | redirect allowed | No error expected |
| No Session | no or ended cookie, valid hint | `logged_out` with target, nothing revoked | No error expected |
| No hint | GET with no parameters, live Session | confirm → logged out, no redirect | No error expected |
| POST end-session | form POST with the same parameters | same as GET | No error expected |
| CSRF/Origin | confirm without CSRF or with a wrong Origin | 403, Session still live | refused |
| Native loopback | native app with `http://127.0.0.1/cb` registered, hint valid, URL on another port | redirect allowed | No error expected |
| Other Tenant | Tenant A's cookie at Tenant B | nothing ended in A | refused |

</intent-contract>

## Code Map

- **Endpoint:**
  - `src/Modules/Protocol/Core/ProtocolServer.cs`: endpoint URIs :118-123, passthrough :263, `IsEndpointPath` :289, the authorize redirect trust :244-246.
  - Paths and cookies: `src/Modules/Protocol/Contracts/ProtocolContract.cs:22-113`.
- **Logout URLs:** `application.post_logout_redirect_uris` (`Migration20261114000000ConfigureApplicationSettings.cs:30`), `DirectoryApplication.PostLogoutRedirectUris` (`src/Modules/Directory/Contracts/DirectoryApplication.cs:79`), `ApplicationStore.cs:89,113`, `ApplicationSettingsRules.cs:81`.
- **ID tokens:** `AuthorizeEndpoint.cs:32,50-61` (`sid`, the ID-token claims). The Tenant's signing keys and issuer come from the existing token validation used by userinfo.
- **Revocation:** `ISessions.cs` (~:118 `FindLiveAsync`, ~:131-158 `RevokeAccessAsync`), `Revocation.cs:66` (`Logout`), `Actor.cs:31`, the model at `RevocationEndpoint.cs:153`.
- **Hosted:** `src/Modules/Protocol/Core/HostedSignIn.cs`:
  - `SignInCookies.Read`/`Clear` :35/:49, `LinkCsrf` :101-125 (the pattern for the new CSRF);
  - `VerifyEmailPageAsync` :1264-1308 (the page-without-a-transaction model), `LoginEndpoints.Map` :389+, the resume flow :314-347.
- **Steps and client:** `StepResponse.cs:130-185`, `apps/hosted-login/src/{step.ts:22-320, StepScreen.tsx:36,246, navigate.ts, App.tsx, api.ts}`, `packages/hosted-screens/src/index.ts`, `packages/ui/src/messages.tsx`.
- **Tests:**
  - `tests/Isolation/Protocol/DiscoveryAndJwksTests.cs:40-60,444-462`; `AuthorizationCodeTests.cs`, `ProtocolHost.cs`, `HostedBrowser.cs`, `RefreshTokenTests.cs`.
  - `tests/Isolation/CrossTenant/RouteRegistry.cs:140-183`, `CrossTenantRouteTests.cs` (~:241,318), `tests/Isolation/Canary/CanaryFlows.cs` (flows ~:302, reasons :319+).
  - `tests/browser/hosted-step-server.mjs` (~:258-293,345-374,413), `tests/browser/fixture/src/main.tsx:57`, plus a new `hosted-logout.spec.ts` with its own Playwright project and `testIgnore` entry.

## Tasks & Acceptance

**Execution:**
- `src/Modules/Protocol/*`: the end-session endpoint (configuration, passthrough, handler override), the redirect decision, the page, the confirm route, the logout CSRF, the steps and the wiring.
- Client and UI: the two screens, the readers, the external-navigation helper for `logged_out`, and the copy. Update the `HOSTED` list.
- `tests/Isolation/Protocol/LogoutTests.cs` (new): every I/O Matrix row, asserting the DB state (Session `ended_at` and `end_reason='logout'`, families revoked) and the cleared cookie. Plus the discovery assertion, the routes, the cross-Tenant cases and the canary flow.
- `tests/browser/hosted-logout.spec.ts`: the confirmation copy, Stay (no request), Log out with and without `redirectTo` (the stub answers both), and axe in light and dark.
- `docs/threat-model.md`: T-38 (logout redirect needs a valid hint and an exact URL; the hint never selects the Session).

**Acceptance Criteria:**
- Given a logout, when it completes, then the Session and the refresh tokens bound to it end.
- Given a valid `id_token_hint` and a registered URL, when logout finishes, then it redirects there through a top-level GET (with `state`).
- Given an invalid hint or unregistered URL, when logout runs, then the User is logged out and sees the logged-out state with no redirect.

## Spec Change Log

## Review Triage Log

## Design Notes

- **A stateless confirm:** the confirm POST carries the original parameters back and re-runs the same decision. No logout request has to be stored, and a tampered POST can only lose its redirect, never gain one.
- **The cookie selects the Session:** an ID token is a bearer artefact that any Relying Party holds. Ending whichever Session it names would let one App log the User out of another browser. The browser's own cookie is what logout means here.
- **External navigation only for `logged_out`:** EXPERIENCE requires a top-level GET back to the Application, and the value is validated server-side on the same request.

## Verification

**Commands:**
- With `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors.
- `corepack pnpm -r build`, `corepack pnpm --filter @gatekeep/ui check`, `corepack pnpm --filter @gatekeep/hosted-login budget`. Expected: green.
- The Isolation, Architecture and browser suites run on CI.
