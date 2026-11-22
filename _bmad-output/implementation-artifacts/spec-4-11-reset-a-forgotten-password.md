---
title: 'Story 4.11: Reset a forgotten password'
type: 'feature'
created: '2026-11-22'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-4-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-4-9-sign-in-with-a-password.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-4-7-sign-up-and-verify-an-email-address.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** A User who forgot their password has no way back. There is no "Forgot password?" link, no reset link, and nothing replaces a password, ends the User's access and tells them.
- The `password_reset` email template from Story 4.5 has nothing that sends it.
- FR-48's "password reset" trigger and the cross-Tenant "reset link" artifact are both still pending on this story.

(FR-19, FR-48, NFR-6, NFR-20)

**Approach:**
- **Request:** the Password step gets "Forgot password?", which leads to Forgot password. A request answers the identical neutral confirmation for every address. For a User holding an active password, it issues a 30-minute, single-use, hashed reset link (superseding older ones) and enqueues the `password_reset` email.
- **Link:** it opens Reset password (new and confirm fields, strength meter, server-side policy with history). Completing it, in one command:
  - replaces the password and verifies the email;
  - runs `RevokeAccess` for the User with no acting Session, so no Session starts;
  - sends the security notice;
  - shows Password changed.

## Boundaries & Constraints

**Always:**
- **Schema:** one migration, `Migration20261130000000PasswordReset.cs`. Check `main`'s newest migration before pushing, and bump `MigrateCommandTests` 45 → 46.
  - **`one_time_token.purpose`:** the CHECK becomes `('email_verification', 'password_reset')`.
  - **No other change.** The grants already cover what's needed: `password_credential` `UPDATE (status, password_hash, updated_at)`, `user` `UPDATE (email_verified_at)`, `password_history` INSERT, and `one_time_token` INSERT, DELETE and `UPDATE (used_at)`.
- **Reset link:**
  - **Shape and storage:** the same `{tenantPublicId}.{random}` shape as `VerificationLinks`. Only SHA-256 is stored, and the Tenant prefix is checked before any lookup.
  - **Row:** purpose `password_reset`, `credential_id` = the User's active credential, `application_id` = the transaction's, and `expires_at` = now + `SecurityLimits.PasswordResetLinkLifetime` (30 min, §5.2).
  - **Newest wins:** issuing one deletes the User's other unused `password_reset` links first.
  - **Usable** only when its purpose is `password_reset`, `used_at` is NULL, it hasn't expired, and its credential is still the User's active one.
  - **Email:** the raw value travels only as the `password_reset` job's `Secret<byte[]>` credential. The template already builds `login/reset-password?token=`.
- **Request flow** (routes in `ProtocolContract`, mapped in `LoginEndpoints.Map`, listed in `RouteRegistry`). Every route uses `Login.CheckAsync` (exact-host Origin plus transaction CSRF):

  | Route | Needs | Result |
  |---|---|---|
  | `POST /login/api/reset/open` `{stepVersion}` | the Password step (`[identifier]`) | records `reset` and answers `forgot_password` `{email}` (the identifier) |
  | `POST /login/api/reset` `{stepVersion, email}` | `forgot_password` | see Requesting |
  | `POST /login/api/reset/back` `{stepVersion}` | `forgot_password` or the in-transaction `link_sent` | Login with the email kept; the transaction may record `identifier` again, as `password/back` does |

  - **Steps:** add `reset` and `reset_sent` to `SignInSteps`, and the matching branches to `SignInStepResponses.Current`: `[identifier, reset]` → `forgot_password`, and `[identifier, reset, reset_sent]` → `link_sent` with `back: true`.
- **Requesting a reset:**
  1. **Limits** first. Past the Tenant or source limit: 429 Generic error. Past the recipient limit: the neutral answer below, with nothing issued or sent.
  2. **Email check:** a malformed email gets `forgot_password` with `email_invalid`.
  3. **Lookup:** the User by `lower(email)` with an active credential, read without a lock.
  4. **Known** (a User with an active password): supersede and issue the link, then enqueue the `password_reset` job with the link credential, in the same command.
  5. **Otherwise** (no User, or only pending credentials): mint a link value the same way and run the same Transit payload encryption the enqueuer does, then discard it, so the work matches. If the enqueuer exposes no way to do that, add one internal hook.
  6. **Answer:** in every case, record `reset_sent` and answer `link_sent` `{back: true}`, HTTP 200. The bodies are identical apart from the step version, CSRF token and expiry.
  - **Timing tolerance:** the request's median time for a known and an unknown address differs by at most 100 ms over 8 alternating requests each. Neither path sleeps. Record this in threat model T-6.
- **Rate limits:** a new `PasswordResetLimits` record, shaped like `SignInLimits` (public static `RateLimitPolicy` fields plus `Default`, `TryAddSingleton`, defaults in `SecurityLimits`, and members registered in `TenantKeyedTypes`). It counts after the Origin, CSRF and step checks and before any lookup:
  - `reset.request.tenant`: 600 per 15 min, subject `tenant`.
  - `reset.request.source`: 10 per 15 min, subject the source.
  - `reset.request.recipient`: 3 per 15 min, subject `recipient:` plus the lower-cased, normalised email.
  - **Why keying by email is safe here:** the recipient key is counted for every address alike, known or unknown, so a limit can't reveal an account. Update the "never by an email address" doc comments (`LimitAsync`, `SignUpLimits`, `SignInLimits`) to name this one exception and why it holds.
  - **Order:** check the source first, then the Tenant, then the recipient. The send-time per-recipient email limit (Story 4.5) still applies.
- **The link page:** `GET /login/reset-password?token=`, modelled on `VerifyEmailPageAsync`. It needs no transaction, and the client strips the token from the URL as it already does.
  - **Usable link:** `reset_password` `{policy: {minLength, strength}, error: null, rules: []}`, plus a reset-link CSRF, `base64url(SHA256("gatekeep-reset-csrf\0" ‖ tokenHash))`.
  - **Anything else** (malformed, foreign, unknown, expired, used, superseded, or the credential no longer active): `link_expired` `{token (if link-shaped), purpose: "reset"}` with the same reset-link CSRF.
- **`POST /login/api/reset/complete` `{token, password, confirm}`:** checks the Origin and the reset-link CSRF, then does the following in this order:
  1. **Stale link:** an unusable link answers `link_expired` `{purpose: "reset"}`.
  2. **Mismatch:** if `confirm` ≠ `password`, answer `reset_password` with `password_mismatch`, writing nothing.
  3. **Policy:** run the Connection's password rules with the User's email (`personal_data`) and their newest `HistoryCount` history hashes (`history`), through `AuthenticationContract.CheckPasswordAsync`. Failures answer `reset_password` with `password_rule` and `rules`, writing nothing.
  4. **Hash:** hash through the shared gate. No slot answers Generic error `temporarily_unavailable`, writing nothing.
  5. **Complete,** in one command:
     - `UPDATE` the active credential's `password_hash` (guarded by its ID and `status='active'`) and insert the new hash into `password_history`;
     - delete the User's pending credentials and their links;
     - mark the link used and delete the User's other `password_reset` links;
     - set `email_verified_at` if it's NULL;
     - run `ISessions.RevokeAccessAsync(context, new RevocationScope.User(userId), exceptSessionId: null, RevocationReason.CredentialChange, Actor.User(userId), ct)`;
     - enqueue the `security_notification` job;
     - write `identity.password.reset` (Success, `TenantLogClass.PasswordReset`, Actor the User, target the User, no detail).
  6. **No Session** is started.
  7. **Answer:** `password_changed` `{continueTo}`.
     - **`"login"`** when the request's `__Host-gk_txn` names a live transaction in this Tenant at `[identifier, reset, reset_sent]`. In the same command, that transaction moves back to Login with the email kept, and "Log in" is a top-level GET to `/login/`.
     - **`"close"`** otherwise ("You can close this page.").
- **`POST /login/api/reset/new-link` `{token}`:** from a reset `link_expired`, with the reset-link CSRF and the limits counted as a request. It always answers `link_sent` `{back: false}`. When the token's row exists and its User still holds an active credential, it issues a new link and email.
- **Supersession by a password change:** expose `IIdentity.SupersedeResetLinksAsync(context, userId, ct)` and call it in the reset completion. Story 16.4 (password change) calls it later. A sign-in rehash must **not** supersede.
- **Audit and coverage:**
  - Add `identity.password.reset` to `IdentityEvents.cs`, clear the PasswordReset pending story in `tests/Architecture/Generator/AuditCatalogue.cs:54`, add its proof to `EventClassTests.Proofs`, and regenerate `docs/audit-events.md`.
  - FR-48: `Fr48TriggerRegistry["password reset"]` becomes `Covered("<test>")`. That test carries `[Trait("FR-48", "password reset")]` and asserts that a completed reset ends every Session and Token Family of the User.
  - Cross-Tenant: `ArtifactRegistry["reset link"]` becomes `Covered("<test>")`, modelled on the verification-link case (`EmailVerificationTests.cs:191`).
  - Canary: a `protocol.password_reset` flow that plants the link, its random part and the new password, none of which may reach a log, Audit event, table or `Referer`.
- **UI:**
  - **Copy** in `messages.tsx`, with every new `packages/ui` export added to the `HOSTED` list in `tests/browser/fixture/src/main.tsx`.
  - **Password step:** a "Forgot password?" link button on the right of the Password label row, which posts `reset/open`. Update `PasswordScreen`'s doc.
  - **`ForgotPasswordScreen`:**
    - Heading "Forgot your password?", body "Enter your email and we'll send a reset link."
    - An "Email address" field (`autocomplete="email"`, pre-filled).
    - The "Send reset link" button, and a "Back to login" link button (posts `reset/back`).
    - Error: `email_invalid` shows the existing copy.
  - **`link_sent`** gains an optional "Back to login" action when `back` is true.
  - **`ResetPasswordScreen`:**
    - Heading "Choose a new password".
    - A "New password" `PasswordField` (`new-password`) with the `StrengthMeter` driven by the step's policy.
    - A "Confirm password" `PasswordField` (`new-password`).
    - The "Reset password" button.
    - Errors: a client-side mismatch shows "Passwords don't match." under Confirm (and the server repeats it), and the named rule errors show under New password.
  - **`PasswordChangedScreen`:** a ✓ icon, "Password changed", and "You've been signed out everywhere for your security." Then "Log in" (`continueTo: "login"`) or "You can close this page."
  - **`link_expired` with `purpose: "reset"`:** "Send a new link" posts `reset/new-link`.
  - **Focus and titles** follow the existing step rules.

**Never:**
- No breach check (Epic 10), no MFA step (Epic 6), and no Account Portal password change (16.4).
- No Session from a reset, and no sleep or padding.
- No account-dependent difference in a request's content, status or next step.
- Never put the reset link or the new password in a log, Audit event, step data (beyond `link_expired`'s own `token`), table or `Referer`.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Request, known | User with active password | `link_sent {back:true}`; 1 reset link row; 1 `password_reset` job | No error expected |
| Request, unknown or pending-only | no User / only pending | identical `link_sent`; no row, no job | No error expected |
| Timing | 8 alternating known/unknown | medians within 100 ms | test fails |
| Newest wins | two requests, then link 1 opened | link 1 → `link_expired`; link 2 works | link_expired |
| Expired / used | 31 min later, or used once | `link_expired {purpose:"reset"}` | link_expired |
| Mismatch | confirm ≠ password | `reset_password` `password_mismatch`; nothing written | inline |
| Policy / history | the current password again, HistoryCount 5 | `password_rule` with `history`; nothing written | named rule |
| Complete | valid link, good password | hash replaced, history row, link used, email verified, every Session and family ended, security notice queued, `identity.password.reset`; no `user_session` created | No error expected |
| Same browser | the txn cookie at `reset_sent` | `password_changed {continueTo:"login"}`; the transaction back at Login with the email | No error expected |
| Other browser | no live transaction | `continueTo:"close"` | No error expected |
| Recipient limit | 4th request for one address in 15 min | neutral `link_sent`, no new link or job | neutral |
| Source limit | 11th request from one source | 429 Generic `temporarily_unavailable` | rate limited |
| Foreign link | Tenant A link at B | `link_expired`, no lookup; A's link still works at A | refused |
| New link | expired reset link → Send a new link | `link_sent`; new link and job only for a User with an active password | neutral |
| Old password after reset | password sign-in with the old password | `incorrect` | inline |
| CSRF/Origin | any POST without a valid CSRF, or a wrong Origin | 403 | refused |

</intent-contract>

## Code Map

- **Links:**
  - `src/Adapters/Postgres/Migrations/Migration20261128000000SignUp.cs`: `one_time_token` :59-78 (purpose CHECK at :64; credential FK RESTRICT at :72) and grants :127-137.
  - `src/Modules/Identity/Core/IdentityService.cs`: purpose constant :17, `DeleteUnusedLinks` :116, `InsertLink` :122, `SelectLink` :129, `UseLink` :138, `DeleteOtherLinks` :62, `IssueVerificationLinkAsync` :262, `FindVerificationLinkAsync` :316, `VerifyEmailAsync` :349, `UpdateHash` :102, `UpdatePasswordHashAsync` :425, `SelectSignInAccount` :94, `MarkVerified` :144, `InsertHistory` :76 and `InsertHistoryAsync` :481, `ReadPasswordHistoryAsync` :446, the pending-credential cleanup :55 and :65.
  - `Identity/Core/VerificationLinks.cs:15-69` (shape and hash); `Identity/Contracts/IIdentity.cs:46-56,163`; `IdentityContract.cs:35,38`.
  - `SecurityLimits.cs:403` (add `PasswordResetLinkLifetime`).
  - `IdentityExpiredStatePurge.cs:15-24` (purges any purpose; no change expected).
- **Pages and routes:** `src/Modules/Protocol/Core/HostedSignIn.cs`:
  - routes :331-349, `LinkCsrf` :101-125, `VerifyEmailPageAsync` :895-939, `NewLinkAsync` :946-982, `QueryToken` :988;
  - `PasswordAsync` :677-760 (the in-transaction model), `CheckAsync` :1085, `UsableAsync` :1118, `LimitAsync` :1161-1197, `AnswerLimitedAsync` :1199.
  - Paths: `ProtocolContract.cs:71,74`. Limits records: `ProtocolContract.cs:250-293`, registered at `ProtocolServer.cs:47-48,72,79`, read at `TokenEndpoint.cs:50,56`.
- **Steps:** `StepResponse.cs`: `StepNames` :113-137, `LinkExpired` :92, `LinkSent` :96, data :209-212. `SignInSteps` is in `IAuthentication.cs:21-34`.
- **Service:** model it on `SignInService.cs` (gate :113-126, rehash use :166-169) and on `SignUpService.cs` (`EnqueueVerificationAsync` :400-409, security notice :224-229). Revocation: `ISessions.cs:150-156`, `Revocation.cs:39-44,67`, the example at `DirectoryService.cs:401`.
- **Email:** `NotificationsContract.cs:83,92,98`, `EmailTemplateDefaults.cs:41,60-69,87-95`, `EmailSendJobs.cs:85`. The Transit encryption inside the enqueuer comes from `OperationsContract.CreateEnqueuer`.
- **Rules:** `AuthenticationContract.CheckPasswordAsync` :117-131, `PasswordRules.cs:31`, `DatabaseConnection.cs:20`.
- **Client:**
  - `packages/hosted-screens/src/{PasswordScreen.tsx:26-33,79-88, LinkExpiredScreen.tsx:21, LinkSentScreen.tsx:16, index.ts}`.
  - `apps/hosted-login/src/{step.ts:102-112,157-169,188-245, App.tsx:69-71,170-175, StepScreen.tsx:48-50,173-182, api.ts:36, navigate.ts:32}`.
  - `tests/browser/fixture/src/main.tsx` (`HOSTED`).
- **Tests:**
  - `tests/Isolation/CrossTenant/ArtifactRegistry.cs:43`, `EmailVerificationTests.cs:191` (model), `tests/Isolation/Revocation/Fr48TriggerRegistry.cs:68`, `RouteRegistry.cs:163-168`.
  - `CanaryFlows.cs:307-310,1988-2060`, `MigrateCommandTests.cs:28`, `AuditCatalogue.cs:54`, `EventClassTests.cs:34-41`, `TenantKeyedTypes.cs`.
  - Helpers: `tests/Isolation/Identity/SignUpFlow.cs`.
  - Browser: `tests/browser/hosted-step-server.mjs` (:23-46, :284-317, CSRF allow-list :345) plus a new `hosted-reset.spec.ts` with its own Playwright project and `testIgnore` entry.

## Tasks & Acceptance

**Execution:**
- `Migration20261130000000PasswordReset.cs` and `MigrateCommandTests`.
- `SecurityLimits.cs`: the link lifetime and the reset limits.
- `src/Modules/Identity/*`:
  - issue, find and supersede reset links;
  - complete the reset (update the hash, write history, clean up pending credentials, use the link, verify the email);
  - the event.
- `src/Modules/Authentication/*`: an `IPasswordReset` service (request with the equal-work unknown path, open, back, the complete orchestration with rules, gate, revoke and notice, and new-link), plus its steps.
- `src/Modules/Protocol/*`: the steps, factories and errors (`password_mismatch`), the routes, the page, the reset-link CSRF, `Current()`, `PasswordResetLimits` and the wiring.
- UI: `packages/ui` (copy and any new components), `packages/hosted-screens` (the screens and the Forgot link), `apps/hosted-login/src/*`, and the `HOSTED` list.
- `tests/Isolation/Identity/PasswordResetTests.cs` (new): every I/O Matrix row, including timing and the FR-48 `[Trait]` test. Plus the cross-Tenant case, the registry flips, the canary flow, `EventClassTests`, `AuditCatalogue`, `RouteRegistry` and `TenantKeyedTypes`.
- `tests/browser`: the Forgot link, Forgot password, the neutral confirmation with Back, Reset password (meter, mismatch, rule error), Password changed (both variants), and the reset Link expired, with axe in light and dark.
- `docs/threat-model.md`: T-6 (reset timing), the reset limits, T-62 (the reset is the recovery), T-12 (a trigger is now covered). Regenerate `docs/audit-events.md`.

**Acceptance Criteria:**
- Given any address, when a reset is requested, then the confirmation is identical in content, status and timing (within 100 ms).
- Given a reset link, when it's used, expired or superseded, then only the newest unused link within 30 minutes works, and the others show Link expired.
- Given a completed reset, when it commits, then no Session is created, `RevokeAccess` ends every Session and Token Family of the User, and a security notice is queued.
- Given the reset URL, when the canary scan runs, then the link appears in no log, Audit event or `Referer`.
- Given repeated requests, when the limit is passed, then they're limited per Tenant, per source and per recipient.
- Given a new password failing policy at reset, when it is submitted, then the server refuses it and names the rule.
- Given the reset link artifact, when this story ships, then its cross-Tenant case runs, and it leaves the Story 1.31 pending list.

## Spec Change Log

## Review Triage Log

## Design Notes

- **Reset verifies the email.** Using the link proves control of the mailbox, and it is T-62's stated recovery for a pre-account takeover. So the reset also deletes pending credentials and verifies the email.
- **Only active-password Users get a link.** A sign-up that was never verified holds only pending credentials. For it, a new sign-up is the path, and its request looks the same as any other.
- **The per-recipient key is safe** because it is counted before and regardless of any lookup. The 3-per-15-min default sits below the 4.5 send limit, so the request limit is the one that bites.
- **Update in place, not delete and insert.** The FK from links to their credential is RESTRICT, and `updated_at` already moves on a rehash. So supersession is an explicit deletion of reset links, not a timestamp comparison.

## Verification

**Commands:**
- With `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors.
- `corepack pnpm -r build`, `corepack pnpm --filter @gatekeep/ui check`, `corepack pnpm --filter @gatekeep/hosted-login budget`, and the package unit tests. Expected: green.
- The Isolation, Architecture and browser suites run on CI. Don't run them locally.
