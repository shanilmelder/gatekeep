---
title: 'Story 4.7: Sign up and verify an email address'
type: 'feature'
created: '2026-11-19'
status: 'done'
baseline_revision: 'e23172d70fbf2530b449111efd290f9157f246a2'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-4-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-4-6-configure-the-database-connection.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-4-2-bind-sign-in-transactions-and-issue-sessions.md'
warnings: ['oversized']
deferred:
  - summary: >-
      Email verified in another browser shows "You can close this page." instead of "Log in" starting a new request for the Application.
    evidence: |-
      EXPERIENCE.md Email verified row; Applications have no login-initiation URI to start a fresh authorization request from.
    location: >-
      src/Modules/Protocol/Contracts/StepResponse.cs
    severity: low
---

<intent-contract>

## Intent

**Problem:** A new User can't create an account. Hosted Login has only the Login and error steps. Nothing hashes or stores a password, and nothing issues or redeems a verification link. The verification email template from 4.5 has nothing that sends it, and the "verification link" artifact is still pending in the Story 1.31 cross-Tenant list (FR-17, FR-18, NFR-2, UX-DR28, UX-DR31, UX-DR42, UX-DR43).

**Approach:**
- **Sign-up flow:** Login gets a "Sign up" link (only while the database Connection is enabled and sign-up is on). It leads to a Signup step with email, password and a live strength meter.
  - On submit, the server checks the Connection's password policy and names any failing rule.
  - If the policy passes, it creates an unverified User with a pending Argon2id `password_credential`, issues a single-use hashed `one_time_token`, and enqueues the 4.5 verification email.
  - The User then sees Email verification required.
- **Using the link** verifies the email, activates that credential, and deletes every other pending credential. A Session is issued only then.
- **Dev Tenants with verification off** skip the email and get a Session straight away.

## Boundaries & Constraints

**Always:**
- **Schema** (one migration, `Migration20261128000000SignUp.cs`; before pushing, check that `main`'s newest migration timestamp doesn't clash). All tables are Identity, `tenant`, Runtime use, with the RLS pair, `tenant_row_guard`, a registry entry, composite `(tenant_id, …)` FKs and purge:
  - **`"user"`** gains `email_verified_at timestamptz NULL`.
    - `gk_hosted` gets `INSERT (tenant_id, id, email, created_at)` and `UPDATE (email_verified_at)`.
  - **`password_credential`:**
    - **Columns:** `tenant_id`, `id`, `user_id` (FK to `user`), `connection_id uuid` (no FK; Directory is purged first), `password_hash text` (PHC string, 1–512), `status` (CHECK `pending` | `active`), `created_at`, `updated_at`.
    - **Index:** a partial unique index gives one `active` credential per User.
    - **Grants:** `gk_hosted` SELECT, INSERT, DELETE and `UPDATE (status, password_hash, updated_at)`; `gk_worker` `SELECT (tenant_id)` and DELETE.
  - **`one_time_token`:**
    - **Columns:** `tenant_id`, `id`, `user_id` (FK to `user`), `credential_id` (FK to `password_credential`, `ON DELETE CASCADE`), `purpose` (CHECK `email_verification`; 4.11 adds reset), `token_hash bytea` (unique per Tenant), `application_id uuid NULL`, `expires_at`, `used_at NULL`, `created_at`.
    - **Grants:** `gk_hosted` SELECT, INSERT, DELETE and `UPDATE (used_at)`; `gk_worker` `SELECT (tenant_id, expires_at)` and DELETE.
  - **`signin_transaction`** gains `signup_user_id uuid NULL` (FK to `user`), with a matching `gk_hosted` column UPDATE grant.
- **Link token:**
  - **Shape:** `{tenantPublicId}.{base64url 32 random bytes}`. The prefix is checked first, so a link from another Tenant is refused before any lookup. The same masking shape applies in `CredentialShapes`.
  - **Storage:** SHA-256 of the whole value only. The raw value travels only as the 4.5 job's `Secret<byte[]>` credential, which is Transit ciphertext that is erased on completion.
  - **Lifetime:** `SecurityLimits.EmailVerificationLinkLifetime = 24h`, matching the PRD's enrolment link.
  - **Use:** a link works once (`used_at` set in the same command that verifies the User).
- **Verifying:**
  - **One command does everything:** it sets `email_verified_at` (if still NULL), activates the token's credential, deletes the User's other `pending` credentials (their tokens cascade), and inserts the new hash into `password_history`.
  - **Audit:** it writes `identity.user.email_verified`, targeting the User.
  - **An already-verified User** keeps their active credential, so the link only marks itself used.
- **No Session or token** exists for a User whose `email_verified_at` is NULL, unless `ITenants.GetSignupSettingsAsync(...).EmailVerificationOff` is true at sign-up time. That flag is already ANDed with the Dev label.
- **Sessions:** a Session is started only through `ISessions.StartOrRotateAsync`, with `amr: ["pwd"]` and `ConnectionId` set to the database Connection. The transaction records `authenticated`, then redirects to the existing resume location.
- **Password hashing** (NFR-2):
  - **Algorithm:** Argon2id via the `Konscious.Security.Cryptography.Argon2` package (central version), producing a PHC string `$argon2id$v=19$m=…,t=…,p=…$salt$hash`.
  - **Parameters:** read from the stored string, so they can be raised later. The defaults live in `SecurityLimits`: m = 19456 KiB, t = 2, p = 1, a 16-byte salt and a 32-byte hash.
  - **Concurrency:** all hashing passes one Deployment-wide gate that bounds concurrent hashes, gives each Tenant a share, and waits only until a deadline. On overflow the request gets the generic `temporarily_unavailable` step.
  - **Existing verified address:** sign-up with that address still runs one hash, and changes nothing.
- **Password rules** (server-side, in Authentication Core, from the Connection's `PasswordPolicy` plus `SecurityLimits.PasswordMaximumLength = 256`). Each failure is a stable rule code:

  | Rule | When it applies | Fails when |
  |------|----------------|------------|
  | `length` | always | fewer code points than the minimum |
  | `too_long` | always | more than 256 code points |
  | `classes` | always | fewer than 3 of lower, upper, number, special, using 4.6's definitions |
  | `repeats` | `excellent` only | more than 2 identical characters in a row |
  | `dictionary` | if on | the lower-cased password is in the embedded common-password list |
  | `personal_data` | if on | the password contains the email's local part, or its first domain label of 4 or more characters, case-insensitively |
  | `history` | when `HistoryCount > 0` | the password matches one of the User's newest `HistoryCount` `password_history` hashes |

  - **The common-password list:** the top 10,000 entries from SecLists `Passwords/Common-Credentials/10k-most-common.txt` (MIT, attributed in `THIRD-PARTY-NOTICES` or its equivalent). It ships only on the server.
  - **The history rule** is exercised by unit tests here; sign-up has no prior history to compare against.
- **Steps** (each is a new `StepNames` entry, data record and factory, a client reader, a `StepScreen` case and a heading):
  - **`signup`:** data `{email, policy: {minLength, strength}}`. Errors are `email_invalid`, or `password_rule` with `rules: [code…]`.
  - **`verify_email`:** data `{email, resent}`. Error: `not_verified_yet`.
  - **`email_verified`:** data `{continueTo: "app" | "close"}`.
  - **`link_expired`**, and the neutral **`link_sent`**.
  - **Login data** gains `signupEnabled`.
- **Routes** (constants in `ProtocolContract`, mapped in `LoginEndpoints.Map`, added to `RouteRegistry`). Every POST goes through `Login.CheckAsync`, the exact-host Origin check plus the transaction-bound CSRF; the link POST uses a link-bound CSRF instead:

  | Route | Needs | Result |
  |------|------|------|
  | `POST /login/api/signup/open` `{stepVersion, email}` | Login step, sign-up enabled | `signup` (records `signup`). Sign-up off: the current Login step, unchanged. |
  | `POST /login/api/signup/back` `{stepVersion}` | `signup` | Login, email kept |
  | `POST /login/api/signup` `{stepVersion, email, password}` | `signup`, sign-up enabled | `verify_email` (records `registered`, sets `signup_user_id`). Verification off: `redirect`. |
  | `POST /login/api/verification/resend` `{stepVersion}` | `registered` | `verify_email {resent: true}`. A new token replaces the credential's unused one, and the email is enqueued again. |
  | `POST /login/api/verification/continue` `{stepVersion}` | `registered` | `redirect` if the User is verified; otherwise `verify_email` with `not_verified_yet` |
  | `GET /login/verify-email?token=` | — | Page with `email_verified`, or `link_expired` for a malformed, foreign, unknown, expired or used token |
  | `POST /login/api/verification/new-link` `{token}` | link CSRF = `base64url(SHA256("gatekeep-link-csrf\0" ‖ tokenHash))` | Always `link_sent`. If the token row exists and its User is still unverified, a new token and email go out. |

- **`email_verified`:**
  - **Same browser** (the transaction cookie names a live transaction whose `signup_user_id` is the token's User): start the Session, record `authenticated`, and set `continueTo: "app"`. Continue is a top-level GET to the resume location.
  - **Otherwise:** `continueTo: "close"`, with "You can close this page."
- **Audit:**
  - `IdentityEvents.cs` gets `identity.user.signed_up` and `identity.user.email_verified`. The detail holds no email or password.
  - The verification email job is enqueued in the same command as the sign-up or resend.
  - Hosted gets an `IJobEnqueuer` from `OperationsContract.CreateEnqueuer`, using Hosted's custody. Add the module edge deliberately and regenerate `module-dependencies.md`.
- **UI** (`packages/hosted-screens` plus `apps/hosted-login`, copy only in `messages.tsx`):
  - **Signup:**
    - The heading is "Create your account". The "Email address" field has `autocomplete="username"`, and the "Password" field is a `PasswordField` with `autoComplete="new-password"`, masked.
    - Below them: the strength meter, the "Create account" button, and "Already have an account? Log in".
  - **Strength meter:** a new `StrengthMeter` in `packages/ui`.
    - **Segments:** four, with the filled share equal to rules met ÷ rules shown.
    - **Label:** "Good" or "Excellent" once every client-checkable rule is met; otherwise "Not strong enough".
    - **Rules:** a checklist of length, classes and `repeats` (Excellent only), each with a distinct met/not-met glyph and text ("Met"/"Not met").
    - **Announcements:** the label goes through a `role="status"` region debounced by 500 ms.
    - **Evaluation:** the rules are evaluated in the browser from step data, and nothing is sent before submit. Move 4.6's `previewRules`/`characterClasses`/`hasLongRun` into `packages/ui` so the Admin preview and the meter share them.
  - **Server rule errors:** shown under the password with named-rule copy.
  - **Verification required:** an `@` warning icon and the heading "Verify your email to continue". The body is "We sent a link to {email}. Click it, then come back here."
    - The primary action is "I've verified — continue". The error text is "We haven't seen that yet. Check your inbox."
    - A "Resend email" link stays `aria-disabled` for 30 s with a visible countdown outside live regions. "Email sent" is announced once via `role="status"`.
  - **Email verified:** a ✓ icon and "Email verified". "Continue" when `continueTo` is `app`; otherwise "You can close this page." with no action.
  - **Link expired:** "This link has expired or was already used.", with a "Send a new link" button.
  - **Link sent:** "If an account exists for that email, we've sent a link."
  - **Constraints:** keep the bundle under budget, and no Terms row (4.8).

**Never:**
- No existing-address notice email, no timing padding beyond the one hash, no sign-up or resend rate limits, and no terms acceptance (4.8).
- No password sign-in for returning Users, no dummy hash on Login, and no hash upgrade (4.9).
- No reset, Passkey prompt or breach dataset (4.11, Epic 6, Epic 10).
- No new `ICredentialStep` implementation, and no `TestOnly`-named type in `src`.
- Never put the raw token or the password in a log, Audit event, step data (beyond the `link_expired` page's own `token` field for "Send a new link"), the DB or `Referer`.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| New sign-up | valid email + policy-passing password | User (unverified), 1 pending credential, 1 token, 1 queued email, `verify_email`; no `user_session` row | No error expected |
| Verification off (Dev) | same | User, active credential, Session, `redirect`; no token, no email | No error expected |
| Off flag on non-Dev | stored true, label Prod | behaves as New sign-up | No error expected |
| Failing rule | `"aaaaaaaaaaaa"` | 200 with step `signup` and `password_rule` naming `classes` (and `dictionary` if listed); nothing written | named rule |
| Personal data | `felix@brandt.dev`, password contains `felix` | `personal_data` named | named rule |
| Sign-up disabled | POST `/signup` | Login step, nothing created | No error expected |
| Re-sign-up, unverified | second sign-up, new password | 2nd pending credential + token; using link 2 activates it and deletes credential 1 and link 1 | No error expected |
| Existing verified | sign-up with that email | identical `verify_email`; nothing written, no email | No error expected |
| Link reused | same link twice | 2nd shows `link_expired`; state unchanged | link_expired |
| Link expired | `expires_at` passed | `link_expired` | link_expired |
| Foreign link | Tenant A link at Tenant B host | `link_expired`, no lookup; A's link still works at A | refused |
| Same browser | link opened with the txn cookie | Session started, `email_verified {continueTo:"app"}` | No error expected |
| Other browser | no/other txn cookie | verified, no Session, `continueTo:"close"`; then "I've verified" in browser 1 → `redirect` | No error expected |
| Too early | "I've verified" before link | `verify_email` with `not_verified_yet` | inline error |
| New link | `link_expired` → Send a new link | `link_sent`; new email only if still unverified | neutral |
| CSRF/Origin | any POST without CSRF or wrong Origin | 403 as the Login routes do | refused |
| Hash gate full | gate overflow | `generic_error temporarily_unavailable`; nothing written | generic |

</intent-contract>

## Code Map

- **Protocol (server steps):**
  - `src/Modules/Protocol/Contracts/StepResponse.cs`: `StepNames` :51, factories :28-43, `LoginErrors` :63, data records :70-76.
  - `src/Modules/Protocol/Core/HostedSignIn.cs`:
    - `LoginEndpoints.Map` :246; follow `IdentifierAsync` :293-357 as the POST handler model.
    - Checks: `CheckAsync` :444, `UsableAsync` :466, `ReadBodyAsync` :384.
    - Next-step choice: `SignInStepResponses.Current` :115-130.
    - CSRF: `SignInCsrf` :59-92. Cookies: `SignInCookies` :28.
    - Resume: `HostedAuthorizationSignIn.ResumeAsync` :195.
  - `ProtocolContract.cs:43-62,127`: paths and `MapGatekeepLogin`.
  - `ProtocolServer.cs:44-57`: service wiring. Add the enqueuer, Identity, Tenancy and Directory here.
- **Authentication:**
  - `src/Modules/Authentication/Contracts/IAuthentication.cs`: `SignInSteps` :17-24 (add `signup` and `registered`), methods :59-138.
  - `Core/AuthenticationService.cs`: `RecordIdentifier` :55 and `RecordAuthenticated` :64 (SQL-guarded appends), `IdentifyAsync` :181-248 (session start at :230).
  - `AuthenticationContract.cs:57,107`.
  - New: `Core/PasswordRules.cs` and the hashing gate.
- **Sessions:** `src/Modules/Sessions/Contracts/ISessions.cs`: `NewSession` :12 (with a `ConnectionId` slot), `StartOrRotateAsync` :104.
- **Identity** (nearly empty):
  - Existing: `IdentityContract.cs`, `Core/UserEmails.cs`, `Core/IdentityPurge.cs:11-16` (add the two tables before `"user"`).
  - New: the User and credential store, the token store, and `Contracts/IdentityEvents.cs` (picked up by `tests/Architecture/Generator/AuditCatalogue.cs:73`).
- **Ports from 4.6:**
  - `IDirectory.FindDatabaseConnectionAsync` (`src/Modules/Directory/Contracts/IDirectory.cs:427`). Its model, `DatabaseConnection.cs:4-26`, holds the strength definitions.
  - `ITenants.GetSignupSettingsAsync` (`src/Modules/Tenancy/Contracts/ITenants.cs:310`). Module edges: `tests/Architecture/module-edges.txt`.
- **Email (4.5):**
  - `NotificationsContract.cs`: `SendEmailJob` :71, `VerificationTemplate` :80, `EmailPayload(userId, templateId, Secret<byte[]>?)` :98.
  - `EmailTemplateDefaults.cs:38` (`login/verify-email?token=`).
  - `IJobEnqueuer` (`src/Gatekeep.Kernel/Jobs/IJobEnqueuer.cs:22`), from `OperationsContract.CreateEnqueuer` :144. The Hosted job policy is `ProductionJobs.cs:200-209`, and its custody is `GatekeepHosting.cs:107`. `deploy/openbao/policies/host-hosted.hcl:18` already allows `payload-*`.
- **Kernel:** `src/Gatekeep.Kernel/Secrets/{OpaqueValues.cs:20-46, Secret.cs:13, CredentialShapes.cs:42}` and `Limits/SecurityLimits.cs:337-343` (add the lifetime, maximum length and Argon2 parameters). Tenant-prefixed shapes: `src/Modules/Protocol/Core/ReferenceIds.cs:15`.
- **Expired cleanup:** `src/Modules/Authentication/Core/AuthenticationExpiredStatePurge.cs` and `src/Modules/Operations/Core/ExpiredStatePurgeJobs.cs`. Delete `one_time_token` rows expired over an hour ago. That needs a home in Identity: add `IdentityExpiredStatePurge` and register it beside Authentication's.
- **Schema:**
  - `src/Adapters/Postgres/Migrations/Migration20261127000000ConfigureDatabaseConnection.cs` (model: tables loop, RLS, `password_history` :79-89).
  - `Schema/TableRegistry.cs:312-330` (`user`, `password_history`), and :815 (the `tenant_attempt` grant shape).
- **Client:**
  - `apps/hosted-login/src/`:
    - `step.ts`: `Step` :49, readers :91, `LOGIN_ERRORS` :88.
    - `StepScreen.tsx`: `heading` :13, `screen` :31, `FIELD_ERRORS` :10.
    - `App.tsx`: `show` :40, `onContinue` :48.
    - `api.ts`: `ApiPath` :20, `post` :22.
  - `packages/hosted-screens/src/LoginScreen.tsx`, `index.ts`.
  - `packages/ui/src/components/{PasswordField.tsx:21, Button.tsx:15, HostedCard.tsx:20, StatusIcon.tsx:4}` and `messages.tsx` (4.6's rule copy :913-917, defaults :1552-1556). Tokens: `--gk-strength-meter-*` in `packages/design-tokens/css/tokens.css:395`.
  - `apps/admin-dashboard/src/shell/database.ts:146-189` (rules to move), `DatabasePage.tsx:84,547`.
  - Lint and checks: `packages/ui/scripts/check-no-hardcoded-strings.mjs`, `screens-props-only.test.mjs`, `check-dependencies.mjs:39`, `apps/hosted-login/scripts/check-bundle-budget.mjs`.
- **Tests to touch:**
  - `tests/Isolation/MigrateCommandTests.cs`: 43 → 44, in 4 places.
  - `Tenancy/TenantSeeds.cs:20-73`: seed both new tables.
  - `Tenancy/TenantPurgeRegistryTests.cs:102`: the expected-survivors list. Verify it against the new seeds.
  - `CrossTenant/ArtifactRegistry.cs:42`: change "verification link" from `Pending("4-7")` to `Covered("…")`. Model the new test on `Protocol/AuthorizationCodeTests.cs:602-645`.
  - `CrossTenant/RouteRegistry.cs:148`.
  - `Canary/CanaryFlows.cs`: add a flow modelled on `AuthorizationCodeAsync` :1922 and `EmailSendAsync` :2361, planting the password and the token.
  - Grant-style checks: `Directory/DatabaseConnectionTests.cs:123-191`.
  - Architecture: `AdminApiRuleTests` (`signin_transaction` grants), `AuditCatalogueTests`, `SignInPortRuleTests`.
- **Test helpers:**
  - `tests/Isolation/Protocol/HostedBrowser.cs`: `PostAsync` :43, `LoginStepAsync` :96.
  - `ProtocolHost.cs:71` and `ProtocolDatabase` (`AddTenantAsync`, `CreateWebClientAsync`, `Runner`); the release sign-in check is `AuthorizationCodeTests.cs:738`.
  - Browser: `tests/browser/hosted-step-server.mjs` (fixtures and stubs) and `hosted-step.spec.ts`.

## Tasks & Acceptance

**Execution:**
- **Kernel:**
  - `Directory.Packages.props` and the hashing project's csproj: add `Konscious.Security.Cryptography.Argon2`.
  - `src/Gatekeep.Kernel/Limits/SecurityLimits.cs`: add the link lifetime, maximum password length, Argon2 defaults and hash-gate sizes.
  - Hashing: an Argon2id PHC hasher and verifier plus the Deployment-wide gate, with unit tests.
- **Schema:** `src/Adapters/Postgres/Migrations/Migration20261128000000SignUp.cs` and `Schema/TableRegistry.cs`: the tables, columns, grants, RLS and guards above.
- **Identity:** `src/Modules/Identity/*`: create the User and pending credential, issue, find and consume tokens, verify, write history, read verified state, the events, purge, and the expired-token purge.
- **Authentication:**
  - `src/Modules/Authentication/*`: `PasswordRules` plus the embedded common-password list (`Core/Resources/common-passwords.txt`), the new `SignInSteps`, and guarded records for `signup` and `registered` plus `signup_user_id`.
  - The sign-up, resend and continue operations each run as one command per request, with the Session issued via Sessions.
- **Protocol:** `src/Modules/Protocol/*`: the step names, data and factories, the routes, the link-page GET, the link CSRF, `Current()` branches for `signup` and `registered`, and the wiring.
- **Host:** `src/Gatekeep.Host.Hosted/Program.cs`: register the enqueuer. Update `module-edges.txt` and regenerate `docs/architecture/module-dependencies.md` and `docs/audit-events.md` (`dotnet run --project tests/Architecture/Generator`).
- **Shared UI:**
  - `packages/ui`: `StrengthMeter`, the shared password-rule evaluator moved from `database.ts` (repoint `DatabasePage`), the resend countdown, and the copy.
  - `packages/hosted-screens`: `SignupScreen`, `VerifyEmailScreen`, `EmailVerifiedScreen`, `LinkExpiredScreen` and `LinkSentScreen`; add a "Sign up" link to `LoginScreen`.
- **Client:** `apps/hosted-login/src/*`: the readers, error allowlists, API paths, `StepScreen` cases, headings and `App.tsx` handlers.
- **Tests:**
  - `tests/Isolation/Identity/SignUpTests.cs` and `EmailVerificationTests.cs`: every I/O Matrix row, the DB state assertions, and the cross-Tenant link case (`Covered` in `ArtifactRegistry`).
  - `tests/Isolation/Identity/PasswordCredentialTableTests.cs`: grants for each role, plus RLS.
  - Unit tests for `PasswordRules` (every rule, including `history`) and the hasher (parameters round-trip).
  - The touched tests from the Code Map, and the canary flow.
- **Browser and unit:**
  - `tests/browser/hosted-step-server.mjs` plus `hosted-step.spec.ts` (or `hosted-signup.spec.ts`, with its own project and `testIgnore` per the pitfall): the meter updating with no request while typing, the rule error, verify-required with the resend countdown, verified, and link expired. Run axe in light and dark.
  - The `packages/ui` unit tests for the rule evaluator.
- **Docs:** `docs/threat-model.md:127`: the new credential tables, the link token and the grants.

**Acceptance Criteria:**
- Given a new address, when sign-up succeeds, then no `user_session` or `token` row exists for that User until the link is used, unless the Tenant is Dev with verification off.
- Given a verification link, when it is used, then it works once, only its SHA-256 is stored, and the User's earlier pending credentials and links are gone.
- Given the password field, when the User types, then the meter and checklist follow the step's policy and no network request is made until Create account.
- Given a password failing a length, classes, repeats, dictionary, personal-data or history rule, when it is submitted, then the server refuses it, names each failing rule, and writes nothing.
- Given the verification link artifact, when this story ships, then its cross-Tenant test passes, `ArtifactRegistry` lists it as covered, and the canary scan finds no password or link value in logs, Audit events or tables.

## Spec Change Log

## Review Triage Log

### 2026-11-19 — Review pass
- verdicts: 40 findings — high 0, medium 4, low 30, false 5, maybe-false 1
- findings:
  - `low` `reject` (Intent) Server tests run through the test `ProtocolHost`, not `Host.Hosted/Program.cs` — `Program.cs` registers the same `OperationsContract.CreateEnqueuer` with its custody that the test host wraps; a real-host sign-up test is more than a direct correction.
  - `low` `patch` (Intent) The server is exercised only with the default policy — a non-default policy case (minimum 14, Excellent, `repeats` named) was added to `SignUpTests`.
  - `low` `reject` (Intent) Most rules are refused only in unit tests, not over HTTP — the HTTP path calls the same `PasswordRules.Check`, and the unit tests cover every rule.
  - `low` `reject` (Intent) "Refused before any lookup" is shown only indirectly — the test proves nothing in B is read or written; observing the absence of a query adds instrumentation for no user-visible gain.
  - `false` `reject` (Intent) After a second sign-up's link wins, the first browser's Continue says `not_verified_yet` — that credential was deleted, so refusing it is the account-takeover guard; signing that browser in would be the defect.
  - `low` `reject` (Blind) The GET link page uses the link, so mail scanners can spend it — common practice (verification on GET) and only a "Send a new link" away from recovery; a confirm page plus a POST route is new surface. Worth noting for production.
  - `false` `reject` (Blind) The server doesn't limit resends or sign-ups — the intent puts those limits in Story 4.8 ("repeated sign-ups or resends … rate limited"), and the 4.5 per-recipient email limit (5 per 15 min) already caps the inbox.
  - `low` `reject` (Blind) An existing verified address answers faster (no link, no enqueue) — equal timing within tolerance is Story 4.8's acceptance criterion by the intent.
  - `low` `reject` (Blind) The owner of a verified address gets no email — the existing-address notice is Story 4.8's by the intent.
  - `medium` `patch` (Blind) Pre-account takeover: an attacker signs up with a victim's address and their own password, and the victim's click activates it — the threat model now records it, its mitigations (only this transaction's credential signs it in; one active credential) and the residual risk, with 4.11 reset as recovery.
  - `low` `reject` (Blind) The 30-minute transaction vs the 24-hour link leaves a late verifier with "You can close this page." and no way to sign in — Story 4.9 adds password sign-in, which closes it; carrying sign-up state through restarts is more than a direct correction.
  - `low` `patch` (Blind) personal_data matches a 1–2 character local part — the local part is checked only at 3+ code points.
  - `medium` `patch` (Blind) No Unicode normalization before rules and hashing — NFKC applied once before both; NFC/NFD test added.
  - `low` `reject` (Blind) The hash gate is bypassed by public contract methods; 1 GiB parameter cap; per-Tenant semaphores never shrink — the public methods have test callers only (4.9 must gate its verify), stored hashes are written only by this code, and the semaphore map is bounded by the Tenant count. The `DateTime.UtcNow` part is fixed with the gate test below.
  - `medium` `patch` (Blind) Abandoned unverified Users and pending credentials are kept forever — the expired-state purge now deletes pending credentials with no remaining link, then unverified Users with no credential and no transaction.
  - `low` `patch` (Blind) The meter doesn't know the 256-code-point maximum — a client `too_long` rule mirrors the limit, shown only when exceeded.
  - `low` `patch` (Blind) The 4 KiB body limit can turn a long escaped password into a Generic error — the sign-up route's limit is sized for the worst-case escaped body.
  - `low` `reject` (Blind) Refused sign-ups and a full gate write no audit or log — anonymous refusal events would multiply audit volume before 4.8's limits; Epic 10 adds monitoring.
  - `low` `reject` (Blind) No concurrency tests for the same address or two links at once — the `ON CONFLICT` and `FOR UPDATE` guards are straightforward, and the gate tests below cover the budget.
  - `low` `reject` (Edge) The link opened after the transaction expired leaves no sign-in path — same as the Blind row above; 4.9 closes it.
  - `low` `reject` (Edge) Mail scanners spend the GET link — same as the Blind row above.
  - `false` `reject` (Edge) Unlimited resends — Story 4.8 by the intent; the per-recipient email limit applies.
  - `false` `reject` (Edge) Unlimited "Send a new link" — same as above.
  - `low` `reject` (Edge) Repeated unverified sign-ups pile up pending credentials — bounded by 4.8's limits, and the purge above removes them once their links are gone.
  - `medium` `patch` (Edge) Orphaned pending credentials and unverified Users are kept forever — same root cause as the Blind row, fixed by it.
  - `low` `patch` (Edge) A short local part refuses nearly every password — fixed with the Blind row.
  - `low` `patch` (Edge) The body limit replaces the `too_long` rule — fixed with the Blind row.
  - `low` `patch` (Edge) The meter has no maximum — fixed with the Blind row.
  - `low` `patch` (Edge) Resend and Continue can race, so a late answer overwrites a newer step — each is refused while the other is in flight, and superseded answers are dropped.
  - `low` `patch` (Edge) A Session starts under a Connection disabled after sign-up — Continue and the link page now need an enabled Connection to start one; the link still verifies.
  - `low` `patch` (Edge) Authentication near expiry doesn't slide the transaction, so Continue can hit an expired resume — `RecordAuthenticated` slides `expires_at`.
  - `false` `reject` (Edge) The history rule is skipped at sign-up — no history can exist at sign-up: an unverified User has none, and a verified address changes nothing. The rule is covered by unit tests for 4.11.
  - `maybe-false` `reject` (Edge) The gate is per process, so several hosts exceed the budget — the architecture describes a Deployment-wide gate, and v1 runs one Hosted instance; if true it would be low.
  - `low` `patch` (Verification Gap) The purge job's Identity step is never run — `ExpiredStatePurgeTests` now seeds links and asserts them through the job.
  - `low` `patch` (Verification Gap) The one-hour retention boundary is untested — a link 30 minutes past expiry is asserted to survive.
  - `low` `patch` (Verification Gap) The gate's share, limit and release are untested — gate tests added, with an injected `TimeProvider`.
  - `low` `patch` (Verification Gap) Nothing ties the template's link path to the route — an equality test was added.
  - `low` `patch` (Verification Gap) Extend on Signup and Email verification required is untested, and the stub answers Login — server and browser tests were added, and the stub answers the posted step.
  - `low` `patch` (Verification Gap) Removing the token from the address bar is untested — assertions added on both link fixtures.
  - `low` `patch` (Verification Gap) A restarted Login's `signupEnabled` is untested — restart case added.

## Design Notes

- **The verification-link lifetime of 24 h** follows the PRD's credential enrolment link (§5.2, A-18). No lifetime is set for verification itself.
- **A token-bound CSRF for "Send a new link":** the link page has no transaction. Its CSRF derives from the token hash, so only someone holding the link can post it. The token itself is dead at that point.
- **"Other browser" shows "You can close this page."** The UX row's "Log in starts a new request for the Application" needs a login-initiation URI that Applications don't have yet. Leave it to a later story, logged as deferred.
- **Pending credentials, not overwrite:** each unverified sign-up keeps its own credential until one link wins. That gives "invalidates any pending credential from an earlier unverified sign-up" without letting a second sign-up silently change the first one's password.
- **Meter fill:** `filled = ceil(4 × met ÷ shown)`, so a policy-passing password fills all four segments.

## Verification

**Commands:**
- **.NET build:** with `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors. If Docker isn't available, use a local SDK.
- **Front end:** `pnpm -r build`, `pnpm --filter @gatekeep/ui check`, `pnpm --filter @gatekeep/hosted-login budget`, and the package unit tests. Expected: green.
- **Isolation, Architecture and browser suites:** CI on the PR. Don't run the full suites locally.

## Auto Run Result

Status: done

**Summary:**
- Hosted Login gains Sign up, Email verification required, Email verified, Link expired and Link sent.
- **Sign-up:**
  - The server checks the database Connection's password policy and names each failing rule: length, too_long, classes, repeats, dictionary (SecLists top 10,000) and personal_data. History is unit-tested for 4.11.
  - Passwords are NFKC-normalized and hashed with Argon2id as PHC strings, through a Deployment-wide gate with per-Tenant shares.
  - Sign-up creates an unverified User with a pending credential, plus a single-use, SHA-256-stored, Tenant-prefixed link, and enqueues the 4.5 verification email.
- **Verifying:** using the link verifies the email, activates that credential, and deletes the User's other pending credentials and links.
- **Sessions:** a Session starts only after verification, or straight away on a Dev Tenant with verification off. It goes through `StartOrRotateAsync` with `amr ["pwd"]` and the Connection.
- **Strength meter:** it evaluates the policy in the browser from step data and sends nothing before submit.
- **Cross-Tenant:** the "verification link" case runs and is `Covered` in `ArtifactRegistry`.

**Files changed (main ones):**
- `Migration20261128000000SignUp.cs` and `TableRegistry.cs`: `password_credential`, `one_time_token`, `user.email_verified_at`, and `signin_transaction.signup_user_id` / `signup_credential_id`, with grants, RLS and guards.
- `src/Modules/Identity/{Contracts/IIdentity.cs, Contracts/IdentityEvents.cs, Core/IdentityService.cs, Core/VerificationLinks.cs, Core/IdentityExpiredStatePurge.cs}`: Users, credentials, links, verification, events and purges.
- `src/Modules/Authentication/{Contracts/ISignUp.cs, Core/SignUpService.cs, Core/PasswordRules.cs, Core/PasswordHasher.cs, Core/PasswordHashGate.cs, Core/Resources/common-passwords.txt}`: sign-up, rules, hashing and the gate.
- `src/Modules/Protocol/{Contracts/StepResponse.cs, Contracts/ProtocolContract.cs, Core/HostedSignIn.cs}`: steps, the seven routes and the link page.
- `src/Gatekeep.Host.Hosted/Program.cs`: the job enqueuer, plus a new Host.Hosted → Operations module edge.
- `packages/ui/src/{passwordRules.ts, components/StrengthMeter.tsx, components/ResendAction.tsx, components/LinkButton.tsx, messages.tsx}`: shared rules, meter, resend countdown and copy. The dashboard now uses the shared rules.
- `packages/hosted-screens/src/*Screen.tsx` and `apps/hosted-login/src/{App.tsx, StepScreen.tsx, step.ts, api.ts, navigate.ts}`: screens and client.
- `deploy/docker/run-tests.sh`: an Isolation shard now fails when its tests fail (this was broken since `b14f960`). Committed separately.
- Tests: `SignUpTests`, `EmailVerificationTests`, `PasswordCredentialTableTests`, `PasswordRuleTests`, `PasswordHashGateTests`, `hosted-signup.spec.ts`, the canary flow, the purge job, routes and touched suites. Docs: the threat model (T-62 among others), `THIRD-PARTY-NOTICES.md`, and regenerated audit and module docs.

**Review findings:** 40 in total.
- **18 patched:**
  - personal data now needs a local part of at least 3 characters;
  - NFKC normalization;
  - purging abandoned sign-ups;
  - a client `too_long` rule;
  - a 16 KiB body limit on sign-up;
  - client request races;
  - no Session under a disabled Connection;
  - sliding expiry on authentication;
  - the pre-account-takeover threat row;
  - and nine test gaps (purge job, retention boundary, gate, template path, extend on the new steps, the token removed from the URL, restart, non-default policy).
- **1 deferred** at planning: the other-browser "Log in".
- **The rest rejected**, each with a reason in the triage log. Mainly:
  - rate limits, timing and the existing-account notice belong to Story 4.8;
  - GET consuming the link (mail scanners);
  - the late verifier with no sign-in until 4.9;
  - the ungated public hash methods, which have test callers only.

**Follow-up review recommended:** true. Three `medium` entries were patched (NFKC, the abandoned-sign-up purge, the threat row). The purge deletes unverified Users and widened `gk_worker`'s column reads, and NFKC changes what gets hashed; both landed after review and deserve a second look. Patched counts: high 0, medium 3, low 15.

**Verification:**
- **.NET:** builds with 0 warnings and 0 errors (local SDK 10.0.204, `global.json` changed for the build only and restored).
- **Front end:** `pnpm -r build`, the `@gatekeep/ui` check, and the ui, admin-dashboard and hosted-login unit tests (68, 150 and 4) are green. The bundle is 94.5 kB of the 150 kB budget.
- **Not run locally:** Docker isn't running here, so the Isolation, Architecture and browser suites run on CI (PR #75), which is the source of truth.

**Residual risks:**
- **CI:** with the `run-tests.sh` fix, CI may go red on `EmailSendTests.Transient_failure_retries…`, which already fails on `main`.
- **Mail scanners** can spend a link on GET; the user recovers with "Send a new link".
- **Late verifiers:** a User who verifies after their 30-minute transaction can't sign in until Story 4.9.
