---
title: 'Story 4.13: Log out'
type: 'feature'
created: '2026-11-22'
status: 'done'
baseline_revision: '34cc4f0560a56a0c37d8af3e1c046dbad5ee750f'
review_loop_iteration: 0
followup_review_recommended: true
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

### 2026-11-22 — Review pass
- verdicts: 36 findings — high 1, medium 3, low 24, false 3, maybe-false 5
- findings:
  - `low` `patch` (Verification Gap) The `state` encoding and query-bearing logout URLs are untested — tested with `?from=app` and `state=a&b=c d`; the target is now built with `QueryHelpers.AddQueryString`.
  - `low` `patch` (Verification Gap) `isExternalTarget` is tested only against `javascript:` — hostile fixtures for `data:`, userinfo and an embedded tab; the guard is now an allowlist.
  - `maybe-false` `reject` (Intent) No test drives the real server and client together — the project's pattern (server over HTTP, client against the stub); if it hid a defect it would be low.
  - `false` `reject` (Intent) The server never sends a 302 — EXPERIENCE requires a top-level GET, which the client performs from the validated `redirectTo`.
  - `low` `reject` (Intent) The confirmation shows even with an invalid hint — the design draws one confirmation; logging out without asking would let any link end a Session.
  - `low` `patch` (Intent) The buttons are stacked, unlike the design's side-by-side pair, and the shared `.action` gap changed every screen — reverted; an opt-in `actionLayout="pair"` on `HostedCard` gives Logout its two columns.
  - `false` `reject` (Intent) The `HOSTED` list wasn't updated — it lists `@gatekeep/ui/hosted` exports only, and the new screens live in `@gatekeep/hosted-screens`.
  - `low` `reject` (Intent) No Gatekeep-side logout entry point — the Account Portal (Epic 16) adds one; v1 logout is Application-initiated.
  - `false` `reject` (Intent) The conformance plan isn't run — Story 4.14.
  - `high` `patch` (Blind) A cross-site form POST to end-session carries no `SameSite=Lax` cookie, so it says "logged out" while the Session stays live — a cookie-less POST now gets a 303 to the GET form; test added.
  - `low` `reject` (Blind) The `HOSTED` fixture list wasn't updated — same as the Intent row.
  - `medium` `patch` (Blind) The confirm body cap is below what the parameters allow — `MaxLogoutBodyBytes` sized for four maximal escaped parameters; boundary test.
  - `medium` `patch` (Blind) A failure in the redirect decision rolls back the logout — the revocation commits first; the decision runs after and treats any failure as no target.
  - `low` `patch` (Blind) A cookie gone before the click gives a 403 — with no cookie there's nothing to end, so it answers `logged_out`; a wrong CSRF with a cookie stays 403.
  - `low` `reject` (Blind) A logout CSRF refusal writes the sign-in refusal event — the shared refusal path every Login route uses; a new event code adds catalogue surface for a refusal.
  - `low` `patch` (Blind) Stay signed in does nothing with no history — shows "You're still signed in. You can close this page."
  - `maybe-false` `reject` (Blind) Going back lands on an auto-posting page and loops — the auto-post now 303s to a GET, so the history entry is that GET; if a loop remained it would be low.
  - `low` `patch` (Blind) `isExternalTarget` is a denylist — now an allowlist.
  - `low` `reject` (Blind) A registered URL that already carries `state` gets a duplicate — Admins register their own logout URLs; a registered `state` is an Application choice.
  - `low` `patch` (Blind) The encoding branches are untested — fixed with the Verification Gap row.
  - `low` `patch` (Blind) There are no negative tests for an `at+jwt` hint, several audiences, the system Application or a retired key — the first three added with forged hints; a retired key follows the published-keys rule already tested by userinfo.
  - `low` `patch` (Blind) The logout CSRF has no server secret — recorded in T-38's What remains (forced logout only).
  - `low` `patch` (Blind) Unauthenticated end-session costs a signature check with no rate limit — recorded in T-38's What remains.
  - `low` `patch` (Blind) The browser spec copies harness constants — moved to `hosted-logout-fixture.mjs` and imported by both.
  - `low` `reject` (Blind) The Tenant name is passed twice — harmless duplication in one call site.
  - `medium` `patch` (Edge) The confirm body cap — fixed with the Blind row.
  - `medium` `patch` (Edge) A decision failure rolls back the logout — fixed with the Blind row.
  - `low` `patch` (Edge) Only `ArgumentException` is caught — any non-cancellation exception is now no target.
  - `low` `patch` (Edge) Any non-`at+jwt` type passes as a hint — only an absent `typ` or `JWT` is accepted; `oi_reft+jwt` and `oi_auc+jwt` are refused in tests.
  - `low` `patch` (Edge) A started response returns without `HandleRequest` — now calls it.
  - `low` `patch` (Edge) Stay with no history is stuck — fixed with the Blind row.
  - `maybe-false` `reject` (Edge) Going back loops through an auto-posting page — same as the Blind row.
  - `low` `patch` (Edge) The concatenated target breaks on `?`, `&` or a fragment — fixed with `QueryHelpers`.
  - `maybe-false` `reject` (Edge) The `HOSTED`-list claim misleads — the spec line didn't apply; recorded here.
  - `maybe-false` `reject` (Edge) Logout's guarantee fails on the over-limit body or a decision error — both fixed above, so the claim no longer holds.
  - `false` `reject` (Intent) The process steps aren't in the diff — they happen after review.

## Design Notes

- **A stateless confirm:** the confirm POST carries the original parameters back and re-runs the same decision. No logout request has to be stored, and a tampered POST can only lose its redirect, never gain one.
- **The cookie selects the Session:** an ID token is a bearer artefact that any Relying Party holds. Ending whichever Session it names would let one App log the User out of another browser. The browser's own cookie is what logout means here.
- **External navigation only for `logged_out`:** EXPERIENCE requires a top-level GET back to the Application, and the value is validated server-side on the same request.

## Verification

**Commands:**
- With `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors.
- `corepack pnpm -r build`, `corepack pnpm --filter @gatekeep/ui check`, `corepack pnpm --filter @gatekeep/hosted-login budget`. Expected: green.
- The Isolation, Architecture and browser suites run on CI.

## Auto Run Result

Status: done

**Summary:**
- **Endpoint:** `/connect/endsession` (GET and POST, advertised in discovery) always answers Hosted Login, never an OpenIddict error.
  - **With a live Session cookie:** it shows "Log out of {Tenant}?" (Stay signed in / Log out, side by side).
  - **Cookie-less cross-site POST:** 303s to its GET, so the Lax cookie arrives.
  - **Otherwise:** nothing to end, so the answer is `logged_out`.
- **Confirming** ends this browser's Session and its Token Families through `RevokeAccess` (committed first), clears the cookie, and answers `logged_out`.
- **The redirect** is a top-level GET back to the Application with `state`, allowed only when all of these hold:
  - the hint is an ID token (`typ` absent or `JWT`) signed by the Tenant's published key with its issuer, even if expired;
  - its single `aud` is a live, visible Application;
  - any `client_id` matches;
  - the URL matches a registered one exactly (native apps get the loopback-port exception).
- **Otherwise** the User is logged out with no redirect. The hint never chooses the Session.

**Files changed (main ones):**
- `src/Modules/Protocol/Core/HostedLogout.cs` (new): the decision, the page, the confirm route, the CSRF and the OpenIddict handler.
- `ProtocolServer.cs`, `ProtocolContract.cs`, `StepResponse.cs`, `DirectoryContract.MatchesPostLogoutRedirectUri`.
- `packages/hosted-screens/src/{LogoutScreen, LoggedOutScreen, StillSignedInScreen}.tsx`; `packages/ui` (`HostedCard` `actionLayout="pair"`, copy); `apps/hosted-login/src/{step.ts, navigate.ts, App.tsx, StepScreen.tsx, api.ts}`.
- Tests: `LogoutTests` (new), discovery and handler removal, routes, cross-Tenant, the canary `protocol.logout`, and `hosted-logout.spec.ts` with `hosted-logout-fixture.mjs`. Docs: T-38.

**Review findings:** 36.
- **24 patched:** the SameSite 303, the body limit, revoke before deciding, the catch-all decision, the hint type allowlist, the no-cookie confirm, `QueryHelpers`, `HandleRequest`, the client allowlist, the Stay fallback, the side-by-side layout (shared CSS reverted), the shared fixture constants, two threat-model residuals, and the tests.
- **None deferred.**
- **The rest rejected** with reasons in the triage log.

**Follow-up review recommended:** true. A `high` was patched (the SameSite 303), plus three `medium` entries (the body limit and the revoke-first ordering, which share a root cause). The 303 and the reordering changed control flow after review.

**Verification:**
- .NET build in the SDK 10.0.403 Docker image: 0 warnings, 0 errors.
- `pnpm -r build`, the `@gatekeep/ui` check and the budget (98.9 of 150 kB) pass. Playwright lists all 24 logout tests.
- The Isolation, Architecture and browser suites run on CI.

**Residual risks:**
- The forged-hint tests rely on Transit signatures being usable directly in a JWT.
- The no-history test relies on Chromium reporting `history.length` as 1.
- T-38: a forced logout is possible for anyone who can read the stored Session hash, and end-session has no rate limit yet.
