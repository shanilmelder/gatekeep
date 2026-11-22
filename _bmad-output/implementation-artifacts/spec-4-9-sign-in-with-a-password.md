---
title: 'Story 4.9: Sign in with a password'
type: 'feature'
created: '2026-11-22'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-4-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-4-8-keep-sign-up-neutral-and-limited.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-4-7-sign-up-and-verify-an-email-address.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:**
- A returning User can't sign in. In a release build, Login's Continue answers Generic error `temporarily_unavailable` (the Story 4.2 placeholder), because no credential step exists.
- A code-flow User token with no requested API carries no `aud` at all.
- The FR-40 "Sign-ins and failures" log class is still pending on this story.

(FR-17, FR-23, NFR-2, NFR-6, NFR-20, AR-25, AD-24, UX-DR27, UX-DR32)

**Approach:**
- **Password step:** when the Tenant's database Connection is enabled, Login's Continue leads every identifier to the same Password step, which shows the email chip.
- **Submitting a password** goes through the hash gate:
  - An unknown account, an account with no active password, or a wrong password runs one Argon2id verify (a dummy hash for the first two) and gets the identical "Incorrect email or password."
  - The correct password, for a verified User, upgrades an old-parameter hash and starts a Session (`amr ["pwd"]`, `auth_time`, the Connection), and the Application gets its code.
- **Rate limits and audit:** sign-in is limited per Tenant and per source, and every sign-in and failure is audited under the SignIn class.
- **User token audience:** the requested API, else the Tenant's default audience, else the Tenant's userinfo endpoint.

## Boundaries & Constraints

**Always:**
- **Continue** (`IdentifierAsync`, `SignInStepResponses.Current`):
  - When `ICredentialStep.AfterIdentifierAsync` yields nothing (the release `NoCredentialStep`) and the Tenant's database Connection exists and is enabled, the transaction records `identifier` and answers the new **`password`** step.
  - It never looks up the account, and it is byte-identical for every identifier, apart from the step version, CSRF token and expiry.
  - With no enabled database Connection, Continue keeps today's Generic error `temporarily_unavailable` for every identifier. Story 4.12 refines Connections per Application.
  - The test-only credential step keeps working as before.
- **The `password` step:**
  - **Data:** `{email, error}`, where `email` is `transaction.Identifier` and `error` is null or `incorrect`.
  - **Routes** (constants in `ProtocolContract`, mapped in `LoginEndpoints.Map`, listed in `RouteRegistry`): every POST goes through `Login.CheckAsync`, the exact-host Origin check plus the transaction-bound CSRF.

    | Route | Needs | Result |
    |---|---|---|
    | `POST /login/api/password` `{stepVersion, password}` | `identifier` passed, not yet authenticated | see "Submitting" |
    | `POST /login/api/password/back` `{stepVersion}` | `password` | Login, with the email kept; the transaction may record `identifier` again |

  - **Extend** works on `password` as on the other steps.
- **Submitting a password:**
  - **Order:** first the rate limits (below). Then the Unicode NFKC normalisation from 4.7. Then the hash gate. A null slot answers Generic error `temporarily_unavailable` with 200, writes nothing, and is the same for every account.
  - **Lookup:** a new non-locking Identity read by `lower(email)` returns the User ID, the active credential's ID and `password_hash`, its `connection_id`, and `email_verified_at`.
  - **Verify:**
    - Exactly one `PasswordHasher.VerifyAsync` runs inside the slot. It runs against the active credential's hash, or, with no User or no active credential, against a process-wide **dummy hash** made once (lazily) by `HashAsync` of random bytes with the current `SecurityLimits` parameters.
    - Pending credentials never sign in.
  - **Failure:**
    - Covers an unknown account, no active credential, a wrong password, or a dummy-hash match, which is impossible.
    - The answer is `password` with `error: "incorrect"`, HTTP 200, and nothing written apart from the counters and the failure audit event below.
    - The response and status are identical in all these cases.
    - **Stated timing tolerance:** the median wall time of the password POST for a known account with a wrong password and for an unknown account differs by at most **100 ms**, over 8 alternating requests each. Neither path sleeps. Record the tolerance in `docs/threat-model.md` T-6.
  - **Success, verified User** (`email_verified_at` not null, or the Tenant's `EmailVerificationOff` is true):
    - **Hash upgrade:** if the stored hash's parameters (`PasswordHasher.ParametersOf`) differ from the current `SecurityLimits` Argon2 parameters, one `HashAsync` (still inside the same slot) replaces `password_hash` and `updated_at` on that credential in the same command. Do not add the upgraded hash to `password_history`.
    - **Session:** `ISessions.StartOrRotateAsync` with `NewSession(userId, ["pwd"], now, connectionId)`, rotating the presented Session for the same User.
    - **Completion:** a guarded `RecordAuthenticated`, then `Redirect` to `ResumeLocation`, as 4.7's Continue does. The Application then receives its code through the existing resume path.
  - **Success, unverified User** (an active credential, `email_verified_at` null, and verification on, which can only happen after a Dev Tenant turns verification back on): no Session. The transaction records `registered`, with `signup_user_id` and the credential, so 4.7's Continue and Resend work. A new verification link and email are issued as in a sign-up, and the answer is `verify_email`. This state is revealed only after the correct password (EXPERIENCE: states appear only after correct credentials).
- **Rate limits:**
  - **Configuration:** a new `SignInLimits` record beside `SignUpLimits`, shaped the same way. Its policies are public static `RateLimitPolicy` fields with a `Default`, registered with `TryAddSingleton`, and their defaults live in `SecurityLimits`:
    - `signin.attempt.tenant`: 1,200 per 15 min.
    - `signin.attempt.source`: 30 per 15 min.
  - **How counting works:** each password POST is counted through `Login.LimitAsync` (source first, then the Tenant, never by email), after the Origin, CSRF and step checks and before any lookup or hash.
  - **When limited:** `AnswerLimitedAsync` answers 429 with `Retry-After` and Generic error `temporarily_unavailable`.
  - **Not counted:** Continue and Back are not counted.
  - **Registration:** register the new members in `tests/Architecture/TenantKeyedTypes.cs`.
  - **Forwarded addresses:** they come only through the existing `UseGatekeepForwardedClient`, which trusts Caddy's network alone.
- **Audit** (Authentication's `AuthenticationEvents.cs`):
  - **The events:**
    - `authentication.signin.succeeded` (Success): Actor is the User and the target is the User.
    - `authentication.signin.failed` (Failure): Anonymous, the target is the User when the account exists and none otherwise, and no detail.
  - Both are mapped to `TenantLogClass.SignIn`. Neither holds an email or password.
  - **Where they're written:** the failure event is written in its own short committed scope, the FailureContext pattern, so it survives the request's rollback. The success event is written in the success command.
  - **Catalogue:** remove the `"4.9"` pending tag from `tests/Architecture/Generator/AuditCatalogue.cs` and add the SignIn proof to `EventClassTests.Proofs`.
  - **Regenerate** `docs/audit-events.md` (`dotnet run --project tests/Architecture/Generator`).
- **User token audience** (code flow, at authorize, so it survives exchange and refresh):
  - **API requested:** unchanged (`resource` or `audience`, through `ApiTargets`).
  - **Default audience:** otherwise, when `TenantSignupSettings.DefaultAudience` names an existing API, use that API exactly as if it were requested (its identifier as `aud`, plus `gk_api`).
  - **Userinfo:** otherwise `aud` = the Tenant's userinfo URL, `{issuer}connect/userinfo` from the stored issuer and `ProtocolContract.UserinfoPath`, with no `gk_api`, so refresh keeps it.
  - **Placeholder:** never `urn:gatekeep:placeholder`.
  - Client Credentials is unchanged.
- **Release-guard tests:**
  - `SignInPortRuleTests` keeps its rules (no `TestOnly*` type in `src`, and `NoCredentialStep` is the only `src` `ICredentialStep`).
  - The tests that expected `temporarily_unavailable` after Continue in a release build now expect `password`: `AuthorizationCodeTests` around :412 and `SignInTransactionTests` :91 and :113.
  - Update the stale "until Story 4.9" comments.
- **UI:**
  - **`PasswordScreen`** in `packages/hosted-screens`, with copy in `messages.tsx`:
    - **Heading:** "Enter your password".
    - **Identifier chip:** a new `IdentifierChip` in `packages/ui`. It shows the email, wraps and never truncates, and has an "Edit" button that posts `password/back`.
    - **Form:** a read-only `username` field holding the email (visually hidden but present for password managers), a `PasswordField` labelled "Password" with `autoComplete="current-password"`, masked by default with its Show toggle, and the primary "Log in" button.
    - **Error:** `incorrect` shows "Incorrect email or password." under the password field. Focus goes there and the title gets the "Error:" prefix.
    - **Focus on load:** the card heading.
    - **Hidden:** no "Forgot password?" (Story 4.11), no "Use a recovery code" (Story 6.8's criterion turns it on), and no passkey hint (Design Delta).
  - **Client** (`apps/hosted-login`): the reader, the error allowlist, the API paths, the `StepScreen` case and heading, and the `App.tsx` handlers. The password is cleared from state after every answer.
  - **Exports:** add any new `packages/ui` export to the `HOSTED` list in `tests/browser/fixture/src/main.tsx`.

**Never:**
- No per-account backoff, lockout, breach check, failed-spike Security Alert, or MFA or Factor step (Epic 10, Epic 6).
- No reset or "Forgot password?" (4.11), no logout (4.13), no recovery-code link (6.8).
- No new `ICredentialStep` implementation in `src`, and no `TestOnly`-named type in `src`.
- No account lookup before the password is submitted. No sleep or padding. No email in a rate-limit subject, log line or Audit detail.
- Never put the password, the hash, a Session ID or a token in a log, an Audit event, step data or `Referer`.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Continue, known vs unknown | Login Continue for an existing and an unknown email | both `password` steps, bodies equal apart from version, CSRF and expiry | No error expected |
| Continue, Connection disabled | database Connection disabled | Generic error `temporarily_unavailable` for every email | generic |
| Correct password | verified User | Session row with `amr ["pwd"]`, `auth_time`, `connection_id`; `Redirect`; Application gets a code; `authentication.signin.succeeded` | No error expected |
| Wrong password | verified User, bad password | `password` `incorrect`, no Session; `authentication.signin.failed` targeting the User | inline error |
| Unknown account | no such email | identical `incorrect` answer; one dummy verify ran; failed event with no target | inline error |
| Pending only | User with only a pending credential | identical `incorrect` | inline error |
| Timing | 8 alternating wrong-password / unknown | medians within 100 ms | test fails |
| Old parameters | stored hash with m=8192,t=1, correct password | after sign-in, the stored hash has the current parameters and still verifies | No error expected |
| Unverified, verification on | active credential, `email_verified_at` NULL | `verify_email`, new link and email queued, no Session | No error expected |
| Edit | `password/back` | Login with the email kept; Continue works again | No error expected |
| Source limit | 31st password POST from one source | 429 `Retry-After`, Generic `temporarily_unavailable`; no lookup | rate limited |
| Gate full | no hashing slot | Generic `temporarily_unavailable` 200; nothing written | generic |
| Audience: API | `resource=` a Tenant API | `aud` = that API | No error expected |
| Audience: default | none requested, default audience set | `aud` = the default API, and refresh keeps it | No error expected |
| Audience: none | neither set | `aud` = `{issuer}connect/userinfo`; userinfo accepts the token | No error expected |
| CSRF/Origin | password POST without CSRF or with a wrong Origin | 403 as the other Login routes | refused |

</intent-contract>

## Code Map

- **Continue:**
  - `src/Modules/Protocol/Core/HostedSignIn.cs`: `IdentifierAsync` :385-441 (the placeholder answer at :437), `SignInStepResponses.Current` :152-196 (the placeholder branch at :189-192, which becomes the `password` step), `TemporarilyUnavailable` :137, routes ~:331-337, `ContinueAsync` :691-738 (the commit, `SetSession`, `Redirect` model), `LimitAsync` :1010-1036 and `AnswerLimitedAsync` :1042-1047.
  - `src/Modules/Authentication/Core/AuthenticationService.cs`: `IdentifyAsync` :183-249, `RecordIdentifier` :55-62 (guarded by `cardinality(completed_steps)=0`, so Back needs a guarded reset), `RecordAuthenticated` :64-72.
  - Steps: `IAuthentication.cs:21-34` (`SignInSteps`; add `password` if the guards need it) and the `ICredentialStep` port :160-167. `NoCredentialStep` is at `AuthenticationService.cs:367`.
- **Sign-in service:** model it on 4.7's `SignUpService`:
  - `src/Modules/Authentication/Core/SignUpService.cs`: `AuthenticateAsync` :359-391 (Session plus `RecordAuthenticated`), `PasswordAmr` :34, the gate use :199-206, issuing the link and enqueuing the email :366-375, recording `registered` :208-222.
  - Expose it as a new `ISignIn` in `Contracts/` (or extend `ISignUp`), built in `ProtocolServer.cs:56-67`. It must share the one `PasswordHashGate` instance with sign-up.
- **Hashing:** `src/Modules/Authentication/Core/PasswordHasher.cs`: `HashAsync` :27-43, `VerifyAsync` :50-68, `ParametersOf` :71, `Parameters` :172. Defaults are in `SecurityLimits.cs:398-410`. The gate is `PasswordHashGate.cs:23`.
- **Identity:** `src/Modules/Identity/Contracts/IIdentity.cs` (add the sign-in read and the hash update) and `Core/IdentityService.cs` (`SelectUserByEmail` :24-31 is the shape to copy without `FOR UPDATE`). `gk_hosted` already holds `UPDATE (status, password_hash, updated_at)` (`TableRegistry.cs:349`).
- **Sessions:** `src/Modules/Sessions/Contracts/ISessions.cs:12,104`.
- **Audience:**
  - `src/Modules/Protocol/Core/AuthorizeEndpoint.cs:254-277` (API resolution) and :519-533 (`SetAudiences` plus `gk_api`).
  - `ApiTargets.cs:68,94,111`, and `RefreshTokens.cs:171` (re-reads `gk_api`).
  - `ITenants.GetSignupSettingsAsync` (`src/Modules/Tenancy/Contracts/ITenants.cs:310`) → `DefaultAudience`. The authorize services need `ITenants`.
  - Userinfo: `ProtocolContract.UserinfoPath` :35, the issuer from `ProtocolIssuer.Parse` (`TenantRuntimes.cs:288`), and the userinfo audience handling at `ProtocolServer.cs:209`.
- **Limits:** `src/Modules/Protocol/Contracts/ProtocolContract.cs:243-266` (`SignUpLimits`, the model), `ProtocolServer.cs:47,67`, `TokenEndpoint.cs:44-47`, `SecurityLimits.cs:355-380`.
- **Audit:** `src/Modules/Authentication/Contracts/AuthenticationEvents.cs` (the codes, with `TenantLogClass` as in `SessionsEvents.cs:41`), `tests/Architecture/Generator/AuditCatalogue.cs:51`, `tests/Isolation/Audit/EventClassTests.cs` (`Proofs`; the rule is at :127-135).
- **Client:**
  - `apps/hosted-login/src/step.ts` (the `Step` union :95-105, `readers` :170), `StepScreen.tsx` (:34-47, :88-163), `App.tsx` (password state :37, `onContinue` :108-111, the password-keeping rule :78), `api.ts` (:9-30, :70-113).
  - `packages/hosted-screens/src/{LoginScreen.tsx,index.ts}`.
  - `packages/ui/src/{components/PasswordField.tsx,messages.tsx,index.ts}`.
  - `tests/browser/fixture/src/main.tsx` (`HOSTED`).
- **Tests:**
  - `tests/Isolation/Protocol/AuthorizationCodeTests.cs:412-433,733-739`, `SignInTransactionTests.cs:91,113,230`, `HostedBrowser.cs:81-102`, `ProtocolHost.cs:78-135` (add a `signInLimits` parameter).
  - `tests/Isolation/Identity/SignUpFlow.cs` (helpers to create a verified User with a password).
  - `tests/Isolation/Canary/CanaryFlows.cs`: register `protocol.sign_in` near :308, modelled on `SignUpAsync` :1994.
  - `tests/browser/hosted-step.spec.ts:242` (expects `temporarily_unavailable`) plus `hosted-step-server.mjs` (routes :239-266, allow-list :271-278), or a new `hosted-signin.spec.ts` with its own Playwright project and `testIgnore` entry.
  - No new migration is expected. If one is added, `MigrateCommandTests` goes 45 → 46.

## Tasks & Acceptance

**Execution:**
- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs`: add the sign-in limits and window.
- `src/Modules/Identity/*`: the non-locking sign-in read and `UpdatePasswordHashAsync`.
- `src/Modules/Authentication/*`:
  - an `ISignIn` service with the dummy hash, verify, upgrade check, Session start, `RecordAuthenticated`, the unverified `registered` branch and the Back reset, plus the `NeedsRehash` helper;
  - the two events;
  - shared gate wiring.
- `src/Modules/Protocol/*`:
  - the `password` step (name, data, factory, error code `incorrect`), the two routes and `Current()`;
  - `SignInLimits`;
  - the authorize audience fallback (default audience, then userinfo);
  - the wiring.
- `src/Gatekeep.Host.Hosted/Program.cs` and the Contracts comments: drop the "until Story 4.9" wording.
- `packages/ui` (`IdentifierChip` and copy) plus `packages/hosted-screens/src/PasswordScreen.tsx`, the client in `apps/hosted-login/src/*`, and the `HOSTED` list.
- `tests/Isolation/Identity/SignInTests.cs` (new): every I/O Matrix row, including the timing test, the hash upgrade (seed an old-parameter hash), the audience rows (exchange, refresh, userinfo) and the audit rows.
  - Also update the release-build tests, the canary `protocol.sign_in` flow (password, Session cookie and token planted; none may reach a log), `EventClassTests` and `AuditCatalogue`, and `TenantKeyedTypes`.
- `tests/browser`: the Password step (chip wraps at 320 px, Edit keeps the email, `current-password`, no Forgot or recovery link, the `incorrect` error focused with "Error:" in the title, 429 Generic error), with axe in light and dark.
- `docs/threat-model.md`: T-6 (sign-in timing tolerance and the dummy hash), the sign-in limits, and the audience rule. Regenerate `docs/audit-events.md`.

**Acceptance Criteria:**
- Given any identifier, when Continue is pressed, then the next step is the same `password` step whether or not the account exists.
- Given an unknown account, when a password is submitted, then a dummy Argon2id verify runs, and the message, status and timing (within 100 ms) match a wrong password.
- Given a stored hash with old parameters, when sign-in succeeds, then the stored hash carries the current parameters.
- Given correct credentials, when sign-in completes, then the Session records `amr ["pwd"]`, `auth_time` and the Connection, and the Application receives a code whose tokens carry them.
- Given repeated attempts past the limit, then password submits are limited per Tenant and per source.
- Given the sign-in path, when the canary scan runs, then no password, token or Session identifier reaches a log.
- Given a User token, when it is issued, then its `aud` is the requested API, else the default audience, else only the userinfo URL, and never the placeholder.

## Spec Change Log

## Review Triage Log

## Design Notes

- **Dummy hash:** one hash made per process with the current parameters, so a verify against it costs exactly what a real credential with current parameters costs. Old-parameter real hashes cost less until they are upgraded, which is acceptable: they upgrade at the first sign-in.
- **Limit numbers:** no source gives them. Sign-ins are more frequent than sign-ups, so these are 3× the sign-up per-source limit (30 per 15 min) and twice its per-Tenant limit (1,200, which equals the token endpoint's). Per-account backoff is FR-28 / Epic 10.
- **Unverified with the correct password:** EXPERIENCE's flow sends "Email verified? no" to Email verification required. Recording `registered` reuses 4.7's Continue, Resend and link machinery instead of adding a new step.
- **Hidden links:** "Use a recovery code" appears in Story 6.8 (its acceptance criterion), and "Forgot password?" in 4.11. UX-DR45 bans controls for deferred features.
- **Userinfo audience:** `{issuer}connect/userinfo` is the URL the token is good for, so a resource server can't mistake it for an API audience.

## Verification

**Commands:**
- With `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors.
- `corepack pnpm -r build`, `corepack pnpm --filter @gatekeep/ui check`, `corepack pnpm --filter @gatekeep/hosted-login budget`, and the package unit tests. Expected: green.
- The Isolation, Architecture and browser suites run on CI on the PR. Don't run them locally.
