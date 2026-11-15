---
title: 'Story 4.2: Bind sign-in transactions and issue Sessions'
type: 'feature'
created: '2026-11-15'
status: 'done'
baseline_revision: '0149fa60cc7cbfd317447641c309ba0504dad97a'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-4-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-4-1-serve-hosted-login-step-screens.md'
warnings: ['oversized']
deferred:
  - summary: >-
      Anonymous Hosted Login requests write audit events (refusals, and an extended event on every reload) with no rate limit.
    evidence: |-
      GET /login without a cookie, bad-Origin or bad-CSRF posts and unknown transactions each commit authentication.signin_transaction.refused, and each GET /login on a live transaction writes extended (the product owner chose to audit every extension). Nothing limits them per source or per Tenant; Epic 10 owns rate limits (IRateLimiter).
    location: >-
      src/Modules/Protocol/Core/HostedSignIn.cs (LoginEndpoints)
    severity: medium
  - summary: >-
      signin_transaction.identifier keeps the email entered at Login until a purge removes the row.
    evidence: |-
      In release every sign-in stops after the email is recorded (no credential step before Story 4.9), and nothing removes expired transactions yet. Story 4.3's purge must remove expired rows, identifier included, after the one-hour restart retention.
    location: >-
      src/Adapters/Postgres/Migrations/Migration20261123000000BindSignInTransactions.cs
    severity: medium
---

<intent-contract>

## Intent

**Problem:** `/connect/authorize` can't start a real sign-in. It creates a `signin_transaction` and then asks the placeholder `UnavailableSignIn`, which completes nothing. No cookie binds the transaction to a browser. No Session cookie exists, and Sessions are never reused or rotated. Nothing checks CSRF or Origin on Hosted, and the client has no Login step and no expiry warning (FR-47, FR-8, NFR-3, NFR-4, AD-12, UX-DR32, UX-DR33).

**Approach:**
- **At `/authorize`:** a reusable, fresh-enough Session completes the request at once. Otherwise Authentication starts a transaction bound to this browser, Tenant and Application, sets `__Host-gk_txn`, and redirects to `/login`.
- **At `/login`:** Hosted Login serves the identifier step. A CSRF- and Origin-checked API records the email and moves the transaction on.
- **Completing authentication:** each authentication issues a new 256-bit Session identifier, sets `__Host-gk_session`, and resumes `/authorize` with a top-level GET.
- **Before Story 4.9:** no credential step exists in release, so after Continue the next step is Generic error with code `temporarily_unavailable` (decided 2026-11-15). Tests complete authentication through a test-only credential step.

## Boundaries & Constraints

**Always:**
- **Cookies:**
  - **Names:** `__Host-gk_txn` holds the transaction binding value, and `__Host-gk_session` holds the Session identifier.
  - **Attributes:** both are `Secure; HttpOnly; SameSite=Lax; Path=/`, with no `Domain`.
  - **Values:** each is 32 random bytes as base64url. The server stores only SHA-256 (the existing `binding_hash` and `id_hash`).
  - **Lifetime:** the Session cookie's `Max-Age` runs to the Session's absolute expiry. The transaction cookie has no `Max-Age`.
  - **Clearing:** a refused or ended cookie is cleared with `Max-Age=0`.
- **Transaction state:** a migration adds `step_version int NOT NULL DEFAULT 1`, `identifier text NULL` (the email as entered, trimmed, at most 254 characters), `authenticated_session_id uuid NULL` and `completed_at timestamptz NULL` to `signin_transaction`.
  - Grants and registry entries stay as they are, apart from the columns `gk_hosted` needs.
  - The transaction is the only record of which steps have passed. `completed_steps` holds `identifier`, then `authenticated`.
- **Binding:** a transaction is found only by the SHA-256 of the `__Host-gk_txn` cookie value, under the request's Tenant (RLS).
  - At resume it must also match the request's `client_id`, which is its Application.
  - It is refused (Generic error `invalid_transaction`, 400, cookie cleared, nothing written but the failure event) when:
    - no cookie or no row matches;
    - it has completed;
    - the step it needs hasn't passed;
    - it is presented with another Application.
  - It is presented from another browser when the cookie is absent. It is presented from another Tenant when the RLS lookup finds nothing.
- **Sliding life:**
  - Every accepted `/login` request and `POST /login/api/transaction/extend` sets `expires_at = now + SecurityLimits.SignInTransactionLifetime` (30 min).
  - Each slide writes `authentication.signin_transaction.extended` (decided 2026-11-15: every extension is audited).
  - The response's `expiresInSeconds` is the remaining life.
- **Expiry restart:** `GET /login` with an expired transaction that hasn't completed starts a new transaction with the same Application, the same parameters and the same `identifier`. It sets a new cookie and renders Login with the email filled in. Refusing or deleting the old row is 4.3's purge.
- **CSRF and Origin** on every Hosted state-changing request (`POST /login/api/*`), checked before anything is read or written:
  - **Origin:** must exactly equal the resolved Tenant's issuer origin (scheme, host and port). A missing or different Origin is 403 `origin_mismatch`.
  - **CSRF:** header `X-Gatekeep-CSRF` must equal `base64url(SHA-256("gatekeep-signin-csrf\0" || txn cookie value))`. It is derived and never stored, and it is compared in constant time. Otherwise 403 `csrf_mismatch`.
  - **Delivery:** the token is the `csrfToken` of each `StepResponse`.
  - **Failure events:** both refusals write `authentication.signin_transaction.refused` through a `FailureContext`.
- **API:**
  - `POST /login/api/identifier` with `{stepVersion, email}`.
  - `POST /login/api/transaction/extend` with `{}`.
  - Both answer JSON `StepResponse`s, `no-store`, with the AD-21 headers.
  - A `stepVersion` other than the current one returns the current step unchanged (200) and writes nothing.
  - An email that isn't a valid address returns Login with field error "Enter a valid email address." (`email_invalid`) and no state change.
- **Identifier step:**
  - Records the trimmed email in `identifier`, appends `identifier`, increments `step_version`, slides, and writes `authentication.signin_transaction.identified`.
  - The next step comes from Authentication's credential-step port. Its release default returns none, so the step is `generic_error` with code `temporarily_unavailable`.
  - The step after Continue never depends on whether an account exists.
- **Authentication completion** (credential-step port, tests only in 4.2):
  1. Starts a Session through Sessions with a new identifier. If the browser presented a live `__Host-gk_session` for the same User, that row's `id_hash` is replaced in the same command (rotation, `sessions.session.rotated`), so the old value stops working. Otherwise a new Session starts (`sessions.session.started`).
  2. Records `authenticated` and `authenticated_session_id`.
  3. Answers a `StepResponse` with step `redirect` and `data.location` = `/connect/authorize?{kept parameters}&gk_resume=1`, which the client follows with a top-level GET.
- **Resume at `/connect/authorize` with `gk_resume=1`:**
  - Requires the cookie's transaction to have passed `authenticated`, to belong to this `client_id`, and not to be completed.
  - It sets `completed_at` (`authentication.signin_transaction.completed`) and completes with that Session, counted as fresh for `prompt=login` and `max_age`.
  - It clears `__Host-gk_txn`.
  - `gk_resume` never reaches the client. Without a matching transaction the request gets Generic error `invalid_transaction`.
- **Session reuse:**
  - With no `gk_resume`, a `__Host-gk_session` whose row isn't ended and is within its idle and absolute expiry completes the request when `prompt=login` isn't set and `max_age` is satisfied.
  - Reuse touches the idle expiry, unaudited (AD-5 exemption).
  - Otherwise a transaction starts. `prompt=none` keeps today's `login_required`.
- **Commit:** the redirect to `/login` commits the new transaction even though no code is issued.
- **Ownership and edges:** Authentication owns transaction state and the credential-step port. Sessions owns Session lookup, start and rotation. Protocol owns the `/login` HTTP surface and the real `IAuthorizationSignIn`, which replaces `UnavailableSignIn` in `src`. Module edges stay within `module-edges.txt`.
- **Limits and helpers:** new limits go in `SecurityLimits`: `SignInExpiryWarning` = 2 min, `SignInRestartRetention` = 1 h and the id byte size. One shared helper makes and hashes the opaque values.
- **Login screen** (`packages/hosted-screens`, props only):
  - Monogram, "Welcome back", "Log in to {tenant} to continue".
  - "Email address" field (`type=email`, `autocomplete="username webauthn"`, `data-gk-initial-focus`, prefilled when kept), "Continue", and the field error.
  - No social, passkey, SSO, sign-up or recovery-code control yet (FR-33: no deferred controls).
- **Expiry warning (client):**
  - At `expiresInSeconds − 120` a `role="alertdialog"` shows "Your session is about to expire." with "Keep going". It is focus-trapped and returns focus when closed.
  - Keep going posts extend and resets the timer without a reload.
  - At expiry the client navigates to `/login`.
- **Text and registries:** all new text goes in the catalogue. New routes join `RouteRegistry` and the cross-Tenant suite. Audit codes join the catalogue and `docs/audit-events.md`. `SignInPortRuleTests` names the real implementation and keeps the `TestOnly` rule, and a matching rule allows only the empty credential-step default in `src`.

**Never:**
- No password, Argon2id, Connection or rate limit (Stories 4.6 and 4.9; Epic 10).
- No logout or ending Sessions outside `RevokeAccess` (4.13).
- No purge of expired transactions (4.3).
- No ASP.NET antiforgery, and no `SameSite` relied on as a CSRF defence.
- No Tenant named by a cookie, header or claim.
- No test-only type in `src`.
- No flow logic in the client beyond following `StepResponse`s.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Login starts | valid `/authorize`, no Session cookie | 302 `/login`; `__Host-gk_txn` set (attributes above); row committed, bound to Tenant and Application, `expires_at` = now+30m | No error expected |
| Login page | `GET /login` with that cookie | 200 step `login`, `stepVersion` 1, `expiresInSeconds` ≈1800, `csrfToken`; event `extended` | No error expected |
| Continue (release) | `POST identifier` with a valid CSRF, Origin and email | `generic_error` `temporarily_unavailable`; `identifier` recorded; `step_version` 2 | No error expected |
| Bad email | `email=nope` | Login with `email_invalid`; nothing written | No error expected |
| Stale step | `stepVersion` 1 after it became 2 | current step, nothing written | No error expected |
| CSRF / Origin | wrong or missing `X-Gatekeep-CSRF`; Origin of another host or missing | 403 `csrf_mismatch` / `origin_mismatch`; nothing written; failure event | refused |
| Test sign-in | test credential step after identifier | Session row (SHA-256 only); `__Host-gk_session` set; `redirect` to authorize with `gk_resume=1` → code issued; txn `completed_at` set | No error expected |
| Rotation | prior live Session cookie, same User signs in again | same row, new `id_hash`; old cookie value no longer reuses | No error expected |
| Reuse | live Session, `/authorize` without `prompt=login` | code issued with no Login; with `prompt=login` → `/login` | No error expected |
| Skip a step | `gk_resume=1` before `authenticated`, or with no cookie | Generic error `invalid_transaction` | refused |
| Replay / other app | `gk_resume` after completion, or for another `client_id` | Generic error `invalid_transaction` | refused |
| Other Tenant | Tenant A's txn or Session cookie sent to Tenant B's host, and B's to A's | not found → refused, and no Session is reused, in both directions; no `Domain` on any `Set-Cookie` | refused |
| Expired | `GET /login` after `expires_at` | new txn and cookie; Login with the email filled in | No error expected |
| Keep going | `POST extend` | `expiresInSeconds` ≈1800; event `extended` | CSRF/Origin as above |

</intent-contract>

## Code Map

- `src/Modules/Protocol/Core/AuthorizeEndpoint.cs`:
  - `AuthorizePassthrough.InvokeAsync` (L443-541) today calls `BeginAsync` then `IAuthorizationSignIn.CompleteAsync`. A null result gives `temporarily_unavailable`, and a stale result `login_required`; L495 says "Story 4.2 replaces the refusal".
  - `SetUserClaims` (L50), the ad-hoc authorization with `SessionsContract.SessionAnchorProperty` (L524-537), `KeptParameters` (L130-145) and the freshness helpers (L69-121).
  - Commit is through `EndAuthorizeTransaction` (L319) → `RequestEnd.EndAsync` (`TokenEndpoint.cs` L474-503), which commits only when there's no error. The `/login` redirect needs an explicit commit.
- `src/Modules/Protocol/Contracts/ProtocolContract.cs`: `IAuthorizationSignIn` (L107-125) and `UnavailableSignIn` (L132-141, `TryAddSingleton` at L81) are what gets replaced. `StepResponse.cs` holds `StepResponse`, `StepNames` and `IStepPages` from 4.1.
- `src/Modules/Authentication/Contracts/IAuthentication.cs` and `Core/AuthenticationService.cs`: `BeginAsync` (L30-70) inserts the transaction with `NewOpaqueValue` (L104-117) and the event `authentication.signin_transaction.started`. `AuthenticationEvents.cs` holds the event codes.
- `src/Modules/Sessions/Contracts/ISessions.cs` and `Core/SessionService.cs`: `StartAsync` (L53+) has a duplicated `NewOpaqueValue` (L177). There's no find, rotate or touch yet. `RevokeAccessAsync` is the only way to end a Session; `tests/Architecture/RevocationPathTests.cs` L43/L98 allows hash and idle updates.
- `src/Adapters/Postgres/Migrations/Migration20261102090000CreateSessionTables.cs` L32-51 and L98-145: the table shapes and grants. `TableRegistry.cs` L325 (`user_session`) and L370 (`signin_transaction`). `tests/Architecture/AdminApiRuleTests.cs:162` pins the `signin_transaction` grants.
- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs` L11-17: transaction and Session lifetimes.
- `src/Gatekeep.Host.Admin/AdminRequestChecks.cs` L355-600 and `AdminResponses.cs` L274-300: the Admin pattern for Origin then CSRF checks and hand-written `Set-Cookie`. `src/Modules/Admins/Core/SessionSecrets.cs` L9-11/L82 is the derived-CSRF pattern. Admins is walled off, so copy the pattern rather than reference it.
- `src/Modules/Tenancy/Contracts/ITenants.cs:283`: `ResolvedTenant.Issuer` gives the exact origin.
- `src/Gatekeep.Host.Hosted/Program.cs`, `HostedStepPages.cs`, and `src/Adapters/Hosting/StepPageTemplate.cs`: the 4.1 page writer, which now writes the Login step.
- `apps/hosted-login/src/{step.ts,StepScreen.tsx,main.tsx}`: the 4.1 client. Add the `login` and `redirect` steps, API posts with the CSRF header, and the expiry warning. `packages/hosted-screens/src/` holds the new `LoginScreen`. `packages/ui/src/messages.tsx` is the catalogue.
- `tests/Isolation/Protocol/{ProtocolHost.cs,TestAuthorizationSignIn.cs,AuthorizationCodeTests.cs}` and `tests/Isolation/Sessions/TestOnlyAuthenticator.cs`: today's test sign-in, to replace with a test-only credential step registered by `ProtocolHost`. `AuthorizationCodeTests` L420-428 expects `temporarily_unavailable` from the release sign-in.
- `tests/Architecture/SignInPortRuleTests.cs`, `module-edges.txt`, `AdminCredentialIsolationTests.cs`, `PersistenceRuleTests.cs` L108-131 (`[StateChanging]` takes `CommandContext`), and the audit catalogue tests.
- `tests/Isolation/CrossTenant/{RouteRegistry.cs,CrossTenantRouteTests.cs}` and `tests/Isolation/Hosting/HostedStepTests.cs`. `tests/browser/{hosted-step-server.mjs,hosted-step.spec.ts}` is the browser harness, which serves fixture steps.

## Tasks & Acceptance

**Execution:**
- `src/Adapters/Postgres/Migrations/Migration20261123000000BindSignInTransactions.cs` (it must sort after the latest migration; rename it if `main` gains a later one) and `TableRegistry.cs`: the four columns and any column grants, plus the migration count in `MigrateCommandTests` (38 → 39).
- `src/Gatekeep.Kernel/**`: the limits and the shared opaque-value helper. The two copies of `NewOpaqueValue` use it.
- `src/Modules/Sessions/**`:
  - find a live Session by cookie value;
  - touch its idle expiry;
  - start or rotate a Session in a `CommandContext`, with the event `sessions.session.rotated`.
- `src/Modules/Authentication/**`:
  - find a transaction by binding (live, expired or completed);
  - restart it;
  - record the identifier;
  - slide it;
  - mark it authenticated or completed;
  - write the refusal failure event;
  - the credential-step port with an empty default;
  - the new events.
- `src/Modules/Protocol/**`:
  - the real `IAuthorizationSignIn` (reuse, resume, start and redirect, with commit);
  - the `/login` page and the `/login/api/{identifier,transaction/extend}` endpoints with the Origin and CSRF checks and cookie writing;
  - the `login` and `redirect` step names and data;
  - `UnavailableSignIn` removed.
- `src/Gatekeep.Host.Hosted/Program.cs`: map the endpoints. `ProtocolHost` mirrors it.
- `packages/hosted-screens`, `packages/ui/src/messages.tsx`, `apps/hosted-login/**`: the `LoginScreen`, the expiry warning, API posts and redirect following. Extend `screens-props-only` if needed; the client's only network calls are the two API posts.
- **Tests:**
  - `tests/Isolation/**`: a test-only credential step, plus a new `SignInTransactionTests` covering every matrix row at HTTP level, including both cross-Tenant directions and cookie attributes.
  - Update `AuthorizationCodeTests`, `RouteRegistry`, `SignInPortRuleTests`, `AdminApiRuleTests`, the migration count and the audit catalogue.
  - `tests/browser/**`: the Login step and the expiry warning (Playwright clock) in light and dark with axe, plus Keep going and the expiry navigation against the harness's stubbed API.

**Acceptance Criteria:**
- Given an authorization request, when Login starts, then the existing `signin_transaction` is bound to the browser, Tenant and Application with a `__Host-gk_txn` cookie and a 30-minute sliding life.
- Given a post-step URL requested directly, when no server record shows earlier steps passed, then it's refused.
- Given a Session issued, when authentication completes, then the identifier is new, only its SHA-256 is stored, and the old one stops working.
- Given a cookie for Tenant A, when it's sent to or set by Tenant B or the parent domain, then a test shows both directions fail.
- Given a state-changing request, when the CSRF token or exact-host Origin is wrong, then it's refused.
- Given 2 minutes left on a transaction, when the warning shows, then "Keep going" extends it, and expiry restarts at Login with the email kept.
- Given a stale `stepVersion`, when it's submitted, then the current valid step returns.
- Given a transaction, when it is presented from another browser, Tenant or Application, after expiry or after completion, then it is refused (expiry restarts at Login rather than continuing).

## Spec Change Log

## Review Triage Log

### 2026-11-15 — Review pass
- verdicts: 35 findings — high 2, medium 11, low 17, false 4, maybe-false 1
- findings:
  - `[high]` `[patch]` (blind) The resume trusts the URL's parameters: only the Application is compared, so a cross-site top-level GET carrying the Lax cookie could swap `redirect_uri` or the PKCE challenge on an authenticated transaction and get a code — the resume now requires the kept parameters to equal the stored ones exactly; tests for a tampered `redirect_uri`, `code_challenge` and `state`.
  - `[medium]` `[patch]` (blind) `isSameOriginPath` passes `"/\t/evil.example"`, which the browser normalises to `//evil.example` — control characters are rejected and the location is resolved against the page origin; browser test with hostile locations.
  - `[medium]` `[patch]` (blind) An expired transaction can be restarted repeatedly from one cookie within the hour — the restart retires the old row in the same command; a second restart with the old cookie is refused (test).
  - `[medium]` `[defer]` (blind) Anonymous requests write unbounded audit events (refusals, `extended` on each reload) with no rate limit — rate limiting is Epic 10's (`IRateLimiter`), and every extension being audited was the product owner's decision; recorded for Epic 10.
  - `[low]` `[patch]` (blind) The parsed `JsonDocument` is never disposed; `Content-Type` isn't checked — the document is disposed on every path. The media-type check is rejected: CSRF doesn't rely on it.
  - `[low]` `[reject]` (blind) `GET /login` slides a transaction without CSRF — a slide only extends the life of the victim's own transaction; with the resume now tied to its exact parameters, a longer life grants nothing.
  - `[low]` `[reject]` (blind) The countdown uses relative timers that throttle in background tabs — the server is authoritative: a late Keep going on an expired transaction gets the redirect to `/login`, which restarts it.
  - `[low]` `[patch]` (blind) Unknown error codes are shown as the email error — lookup uses `Object.hasOwn`, and an unknown code makes the step unreadable (Generic error `invalid_step`).
  - `[low]` `[reject]` (blind) The warning says "session" for the transaction — the copy is the spec's; to Users the sign-in is their session.
  - `[medium]` `[patch]` (blind) In-place rotation overwrites `auth_time`/`amr` that earlier Token Families read on refresh (OIDC Core 12.2 wants the original) — `auth_time` and `amr` are anchored on the family at creation and read from there; a test refreshes the first family after a rotation.
  - `[low]` `[reject]` (blind) No concurrency test for the step-version lock — `FindAsync` takes `FOR UPDATE`; a race test adds timing-dependent flakiness for a Postgres guarantee.
  - `[low]` `[patch]` (blind) `IdentifyAsync` accepts emails the endpoint would refuse — the service now validates with `TryNormalizeEmail`.
  - `[medium]` `[defer]` (blind) `signin_transaction.identifier` keeps emails with no removal until Story 4.3's purge — Story 4.3 purges expired transactions; recorded so its purge covers `identifier`.
  - `[low]` `[patch]` (blind) Small inconsistencies: the `extended` description says every accepted request writes it; `SetSession` reads the clock twice — the description is corrected; the clock read is rejected (sub-second difference, no effect).
  - `[low]` `[reject]` (blind) Unnamed CHECK constraints and no index on `authenticated_session_id` — no later migration targets them yet; the index belongs with a query that needs it (4.3).
  - `[high]` `[patch]` (edge) Resume with different redirect_uri/state/nonce/code_challenge/scope — grouped with the blind high row; fixed.
  - `[medium]` `[patch]` (edge) The same expired cookie spawns another live transaction each time — grouped with the restart row; fixed.
  - `[low]` `[patch]` (edge) `JsonDocument` never disposed — grouped with the blind row; fixed.
  - `[medium]` `[patch]` (edge) Tab or newline after the first slash passes the guard — grouped with the same-origin row; fixed.
  - `[low]` `[patch]` (edge) An error code equal to a prototype key resolves to undefined — `Object.hasOwn`; fixed with the unknown-code row.
  - `[low]` `[patch]` (edge) Keep going's stale closure can overwrite a newer step — a functional update only refreshes the expiry and CSRF token when the `stepVersion` still matches.
  - `[low]` `[reject]` (edge) The claim "expiry restarts with the email kept" fails for an email typed on Login but not yet submitted — the server keeps the recorded email; keeping an unsubmitted one would need client state the props-only client doesn't hold. Losing a typed email after 28 idle minutes on Login is minor.
  - `[false]` `[reject]` (edge) A previous User's Session stays valid after another User signs in on the browser — the spec's rule: rotation only for the same User; the other Session is that User's own and isn't fixation (no attacker-chosen value reaches a `__Host-`, HttpOnly cookie). Ending it would need a revocation reason outside 4.2.
  - `[low]` `[patch]` (edge) `extended`'s description doesn't match what writes it — grouped with the description row; fixed.
  - `[low]` `[reject]` (intent) Cookie isolation is shown by server lookups and attribute checks, not a browser — `__Host-` with no `Domain` is enforced by browsers; the tests pin the attributes and both Tenant directions.
  - `[low]` `[reject]` (intent) A typed but unsubmitted email is lost at expiry — grouped with the edge row; same reason.
  - `[false]` `[reject]` (intent) "The old one stops working" read as any prior Session — the spec settles same-User rotation (R3b); see the edge row.
  - `[low]` `[reject]` (intent) The Application binding is checked only at resume; a cookie is a bearer value — `/login` carries no Application context, and the Application matters where the code is issued; device binding beyond the cookie is not in the requirements.
  - `[false]` `[reject]` (intent) "Post-step URL" realised as a refused resume and a current-step answer — no step routes exist; the server picks the step from its record, which is the requirement's purpose.
  - `[false]` `[reject]` (intent) Expiry within an hour restarts instead of refusing — AC6 requires restart at Login with the email kept; the expired transaction itself never continues.
  - `[medium]` `[patch]` (verification) A resume of an expired authenticated transaction, or one whose Session ended, is untested — both cases added, asserting no code and no `completed` event.
  - `[medium]` `[patch]` (verification) Rotation never presents an ended or expired same-User Session — case added: a new Session starts, no `rotated`, old row unchanged.
  - `[medium]` `[patch]` (verification) The client's redirect guard is never exercised with a hostile location — browser case added with four hostile locations.
  - `[medium]` `[patch]` (verification, other) Tab or newline bypass of `isSameOriginPath` — grouped with the same-origin row; fixed.
  - `[maybe-false]` `[reject]` (verification, other) `GoToLoginAsync`'s failed-commit branch may be untested — settling it needs a coverage trace; if true it is low: an infrastructure-failure path that answers `server_error`.

## Design Notes

**Why resume through `/connect/authorize`.** OpenIddict issues the code only inside its authorization endpoint, so completion returns there with a top-level GET. `gk_resume=1` ties that request to a completed, bound, single-use transaction. Its Session then counts as fresh, which avoids a `prompt=login` loop. Every other request takes the reuse-or-start path.

**"Parent domain" in the cookie AC.** `__Host-` cookies can't carry `Domain`, so a browser never sends them to a sibling or parent host. The test asserts the `Set-Cookie` attributes, and that each Tenant's cookie finds nothing on the other Tenant's host.

## Verification

**Commands:**
- **.NET build:** with `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors.
- **JS:** in `gatekeep/tests:local`, run `pnpm -r build`, `pnpm --filter @gatekeep/ui check` and `test`, and the hosted-login tests. Expected: all pass.
- **Browser:** run the Playwright `hosted-step` and `hosted-login` projects. Expected: all pass.
- **Isolation:** with Testcontainers, pinning the IPv4 as `deploy/docker/run-tests.sh` does, run `SignInTransactionTests`, `Protocol/*`, `CrossTenant*`, `HostedStepTests`, `MigrateCommandTests` and `Sessions/*`, plus the Architecture suite. Don't run the full Isolation suite. The local-only `.claude/worktrees` Architecture failure is expected.

## Auto Run Result

**Summary:** `/connect/authorize` now reuses a live, fresh-enough Session or starts a sign-in transaction bound to the browser (`__Host-gk_txn`), Tenant and Application, and redirects to `/login`. Hosted Login serves the identifier step; `POST /login/api/identifier` and `/login/api/transaction/extend` check exact-host Origin, then a derived CSRF token, before reading anything. The transaction slides for 30 minutes (each slide audited), restarts at Login with the email kept after expiry, and returns the current step for a stale `stepVersion`. Authentication (through a test-only credential step until Story 4.9; release shows Generic error `temporarily_unavailable`) issues a new 256-bit Session identifier, stored as SHA-256, rotating a live same-User Session in place, and resumes `/connect/authorize` with `gk_resume=1`, which must match the transaction's stored parameters exactly and completes it once.

**Files changed:**
- `src/Gatekeep.Kernel/{Limits/SecurityLimits.cs,Secrets/OpaqueValues.cs}` -- new limits and the one opaque-value helper.
- `src/Adapters/Postgres/Migrations/Migration20261123000000BindSignInTransactions.cs` -- `step_version`, `identifier`, `authenticated_session_id`, `completed_at`.
- `src/Modules/Sessions/**` -- find live, touch, start-or-rotate (`sessions.session.rotated`); families read their own `auth_time`/`amr`.
- `src/Modules/Authentication/**` -- find, restart (retiring the old row), extend, identify, complete, refuse; the credential-step port with an empty default; four new events.
- `src/Modules/Protocol/**` -- `HostedSignIn.cs` (the real `IAuthorizationSignIn` and the `/login` endpoints), authorize changes, `login` and `redirect` steps; `UnavailableSignIn` removed.
- `src/Gatekeep.Host.Hosted/Program.cs` -- maps the Login endpoints.
- `packages/hosted-screens/src/LoginScreen.tsx`, `packages/ui/src/messages.tsx`, `apps/hosted-login/src/**` -- Login, the expiry warning, the API client and the guarded navigation.
- Tests: new `SignInTransactionTests`, `HostedBrowser`, `TestOnlyCredentialStep`; updated code-flow helpers, `AuthorizationCodeTests`, `RefreshTokenTests`, `RouteRegistry`, `CrossTenantRouteTests`, `HostedStepTests`, `SignInPortRuleTests`, the migration count and audit catalogue; browser harness and `hosted-step.spec.ts`.

**Review findings:** 35 findings (high 2, medium 11, low 17, false 4, maybe-false 1). Patched 10 entries (high 1, medium 6, low 3, counted by group): the resume now requires the stored parameters exactly; a restart retires the old row; families keep their own `auth_time`/`amr`; the client's redirect guard rejects control characters and other origins (browser-tested); unknown error codes and prototype keys no longer show the email error; Keep going can't overwrite a newer step; `IdentifyAsync` validates; the body is disposed; the `extended` description is corrected; tests for expired or ended-Session resumes and for an expired Session not being rotated. Deferred 2 (rate limits for anonymous audit writes, Epic 10; email retention until 4.3's purge). Rejected 16 with reasons in the Review Triage Log.

**Follow-up review:** recommended. This pass patched a high finding. The specific unverified risk: the exact-parameter resume rule and the family-anchored `auth_time`/`amr` now sit on every code flow's path; the targeted suites pass, but the full Isolation and Playwright suites run only in CI. Patched counts: high 1, medium 6, low 3.

**Verification:**
- .NET build: 0 warnings / 0 errors; API contract matches.
- `pnpm -r build`; `@gatekeep/ui` check passes; ui 62 and hosted-login 4 tests pass (admin-dashboard 122 and api-client 36 before the fixes, which didn't touch them).
- Isolation `Protocol/*`, `CrossTenant*`, `HostedStepTests`, `MigrateCommandTests`, `Sessions/*`, `Applications/*`, `EventClassTests`, `Canary*` and `AuditCatalogue*`: 874 of 874 after the fixes.
- Architecture: 794 of 795; the one failure is the known local-only `.claude/worktrees` check.
- Playwright `hosted-step` and `hosted-login` (implementer): 35 of 35 after the fixes.

**Residual risks:**
- An email typed on Login but not submitted is lost when the transaction expires; only a recorded email survives the restart.
- A different User's live Session stays valid when another User signs in on the same browser (only same-User Sessions rotate).
- Cookie isolation is proven by server-side lookups and `Set-Cookie` attributes, not in a browser.
- Anonymous audit writes are unlimited until Epic 10, and recorded emails stay until 4.3's purge (both deferred).
