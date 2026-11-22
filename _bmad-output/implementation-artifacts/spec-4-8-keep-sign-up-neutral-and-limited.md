---
title: 'Story 4.8: Keep sign-up neutral and limited'
type: 'feature'
created: '2026-11-22'
status: 'done'
baseline_revision: '4158625732b93f371205b115ee5c8dc81e0e72d5'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-4-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-4-7-sign-up-and-verify-an-email-address.md'
warnings: ['oversized']
deferred:
  - summary: >-
      `identity.user.signed_up` doesn't carry `termsAccepted: true` as the spec asked.
    evidence: |-
      AuditEvent admits no free-form detail fields (an architecture test enforces it) and AuditDetail holds only IP, user agent and email; adding one means changing the audit tables and their hash chain. Acceptance itself is recorded on the User (terms_accepted_url, terms_accepted_at).
    location: >-
      src/Modules/Identity/Core/IdentityService.cs (RegisterAsync audit append)
    severity: low
---

<intent-contract>

## Intent

**Problem:** Story 4.7's sign-up leaks account state. For an address that is already verified it skips the link and the email, so it answers measurably faster and the owner is never told. Sign-up, resend and "Send a new link" have no rate limit. A Tenant's terms URL is never shown or accepted. (FR-17, FR-8, NFR-6, NFR-20)

**Approach:**
- **Existing verified address:** the sign-up changes nothing on the account. The owner gets the `security_notification` email, and the answer matches a new sign-up in content, status, next step and timing within a stated tolerance.
- **Terms:** when the Tenant sets a terms URL, Signup shows a required terms checkbox, and the accepted URL and time are recorded on the User.
- **Rate limits:** sign-up, resend and new-link are limited per Tenant and per source, through the existing `IRateLimiter`, with an answer that is the same for every address.
- **Tests:** prove that two Tenants with the same email get unrelated Users, and that a disabled sign-up reveals nothing.

## Boundaries & Constraints

**Always:**
- **Existing verified address** (`IdentityService.RegisterAsync` returns null):
  - **What happens:**
    - The one hash still runs, as in 4.7, and no account row changes (`user`, `password_credential` and `one_time_token` are untouched).
    - In the same command, one `SendEmailJob` is enqueued with `EmailPayload(existingUserId, NotificationsContract.SecurityNotificationTemplate)` and no credential. The 4.5 per-recipient email limit (5 per 15 min) still caps the inbox.
    - The response is the same `verify_email` step, with the same `email`, `resent: false` and HTTP 200, and the transaction records `registered` the same way.
  - **What follows the response:**
    - Resend answers `verify_email {resent: true}` and sends nothing.
    - Continue answers `not_verified_yet`.
    - Both match a new address's answers while that User is unverified.
  - **Unverified existing address:** unchanged from 4.7. It gets a new pending credential and link, and no notice (threat model T-62).
- **Timing:** stated tolerance (NFR-20), recorded in `docs/threat-model.md`:
  - **Rule:** the median wall time of the sign-up POST for an existing verified address and for a new address differs by at most **100 ms**, over 8 alternating requests each.
  - **What makes it hold:** both paths do the same work (one gated hash, one enqueue, one transaction write), and neither path sleeps.
- **Terms:**
  - **Step data:** `SignupData` gains `termsUrl: string | null`, taken from `TenantSignupSettings.TermsUrl` when the Signup step is built.
  - **Request:** `POST /login/api/signup` gains `acceptTerms: bool`.
  - **Missing acceptance:** when a terms URL is set and `acceptTerms` isn't true, the answer is `signup` with the error `terms_required`. It comes before the rules and the hash, and nothing is written.
  - **The terms "version" is the terms URL itself**, as accepted. One migration, `Migration20261129000000SignUpTerms.cs`, adds `terms_accepted_url text NULL` (CHECK length 1–2048) and `terms_accepted_at timestamptz NULL` to `"user"`. Before pushing, check `main`'s newest migration timestamp. `gk_hosted` gets INSERT on both columns and `UPDATE (terms_accepted_url, terms_accepted_at)`.
  - **What gets recorded:**
    - A new User's INSERT records both columns.
    - An unverified re-sign-up updates them in the same command as its new pending credential.
    - An existing verified address records nothing.
    - With no terms URL, both columns stay NULL.
  - **Audit:** `identity.user.signed_up` adds `termsAccepted: true` when terms were accepted. It never carries the URL.
- **Rate limits:**
  - **Configuration:** a new `SignUpLimits` record in `ProtocolContract` holds four `RateLimitPolicy` values, with defaults from `SecurityLimits`. It is registered with `TryAddSingleton`, like `TokenRequestLimits`, so tests can override it.
  - **Policies** (fixed window):

    | Policy code | Routes | Subject | Default |
    |---|---|---|---|
    | `signup.attempt.tenant` | `POST /login/api/signup` | `AuthenticationContract.TenantSubject` | 600 per 15 min |
    | `signup.attempt.source` | `POST /login/api/signup` | `TokenEndpoint.Source(http)` | 10 per 15 min |
    | `verification.send.tenant` | resend and new-link | Tenant | 600 per 15 min |
    | `verification.send.source` | resend and new-link | source | 10 per 15 min |

  - **How counting works:**
    - A request is counted only after the Origin and CSRF checks pass and the step is valid. It is counted in its own short committed `TenantScope` before any hash or lookup, like `TokenEndpoint.LimitTokenRequests`.
    - Both the Tenant and the source counters are bumped.
    - The key never involves the email address, so the limit can't reveal an account.
  - **When limited:**
    - Sign-up and resend answer HTTP 429 with `Retry-After` (seconds, the larger of the two) and the body `StepResponse.GenericError(tenant, SignInStepResponses.TemporarilyUnavailable, traceId)`. Nothing is written beyond the counters, and nothing is enqueued.
    - New-link still answers `link_sent` with 200 (it's always neutral) and sends nothing.
- **Sign-up disabled:** POST `/signup` and `/signup/open` keep 4.7's answer, the current Login step unchanged, and create nothing. The answer is byte-identical for an existing and a new address (tested, not newly built).
- **Two Tenants:** the same email signs up in Tenant A and Tenant B and yields two `user` rows with different IDs. A's sign-up has no effect on B's: B's sign-up for that email is a new sign-up, not an existing-address notice (tested).
- **UI:**
  - **The terms row** (`SignupScreen`, copy in `messages.tsx`):
    - **Placement:** it sits between the strength meter and "Create account", and only when `termsUrl` is non-null.
    - **Checkbox:** a checkbox labelled "I agree to the" followed by the link "Terms of Service". The link sits outside the `<label>`, has `href = termsUrl`, `target="_blank"` and `rel="noopener noreferrer"`, and is underlined, not colour-only.
    - **Hit area:** at least 24 px, with a 3:1 box edge from tokens.
  - **Error:** `terms_required` shows "Accept the terms to continue." under the checkbox and moves focus to it.
  - **Client checks:** the client blocks submit with the same error when the box isn't ticked, and the server check still applies.
  - **429:** a 429 step renders as the existing Generic error screen. The client already parses the body whatever the status.

**Never:**
- No sixth email template and no change to the `security_notification` default text. The five template IDs are fixed.
- No notice to an unverified address, no padding sleep or artificial delay, and no per-email rate-limit key.
- No password sign-in, dummy hash on Login, lockout, breach check or Security Alert (4.9 and Epic 10).
- No Admin change to the terms URL or the sign-up toggle (Story 4.6 already has both).
- Never put the email address or the terms URL in a rate-limit subject, a log line or an Audit detail.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Existing verified | sign-up with a verified User's email | `verify_email` 200, as for a new address; account rows unchanged; 1 `security_notification` job for that User | No error expected |
| Existing, then resend | resend after the above | `verify_email {resent:true}`, no job | No error expected |
| Timing | 8 alternating new/existing sign-ups | medians within 100 ms | test fails |
| Terms set, accepted | `acceptTerms:true` | User has `terms_accepted_url` = Tenant URL and `terms_accepted_at` = now | No error expected |
| Terms set, not accepted | `acceptTerms` false or missing | `signup` with `terms_required`; nothing written, no hash | inline error |
| No terms URL | any `acceptTerms` | sign-up proceeds; both columns NULL | No error expected |
| Sign-up source limit | 11th sign-up from one source in 15 min | 429 + `Retry-After`, `generic_error temporarily_unavailable`; no User or job | rate limited |
| Tenant limit | Tenant counter at limit, new source | 429 as above | rate limited |
| Resend limit | 11th resend or new-link from one source | resend: 429 generic; new-link: `link_sent` with no job | rate limited / neutral |
| Limit is per Tenant | source limited in A | the same source signs up fine in B | No error expected |
| Same email, two Tenants | `x@example.com` in A and B | two Users, different IDs; B gets a link, not a notice | No error expected |
| Sign-up disabled | POST `/signup` for an existing and a new email | identical Login step bodies; nothing created, no job | No error expected |

</intent-contract>

## Code Map

- **Sign-up service:** `src/Modules/Authentication/Core/SignUpService.cs`:
  - the constructor :23-31 (add the notice enqueue; limits stay in Protocol);
  - `SignUpAsync` :149: disabled :171-176, rules :179-183, the gated hash :185-195, settings and `RegisterAsync` :197-199, the null-`registered` branch :201-226 (the notice goes here), verification-off :229-231;
  - `ResendAsync` :234-250, `SendNewLinkAsync` :311-323, `EnqueueVerificationAsync` :366-375.
- **Identity:** `src/Modules/Identity/Core/IdentityService.cs`. In `RegisterAsync` :145, the user INSERT is at :174-182 (add the terms columns), the existing branch returns null at :188-192, and the unverified re-sign-up is at :194-207 (update the terms columns). Return the existing User's ID to the caller so the notice can be addressed, for example as a result type with `ExistingUserId`. Keep the signature change inside Identity Contracts.
- **HTTP:** `src/Modules/Protocol/Core/HostedSignIn.cs`:
  - routes :331-337;
  - `SignupAsync` :549-629 (body parse :558, scope :565, service :584, `Unavailable` :595-598, `Disabled` :600-607, `VerifyEmail` :621-627);
  - `ResendAsync` :632-664 and `NewLinkAsync` :772-800;
  - `SignInStepResponses.TemporarilyUnavailable` :136, and the Signup step in `Current` :176-185 (pass `TermsUrl`).
- **Limit model:** `src/Modules/Protocol/Core/TokenEndpoint.cs`: `LimitTokenRequests` :166-194, `AnswerRateLimited` :511 (`Retry-After` :529), `Source(HttpContext)` :100-121. The limits record goes beside `TokenRequestLimits` (`src/Modules/Protocol/Contracts/ProtocolContract.cs:235`), and its registration beside :44 in `ProtocolServer.cs`. The limiter comes from `AuthenticationContract.CreateAttemptLimiter()` :171, and the policy shapes from :22-52. `tenant_attempt` needs no grant change.
- **Limits:** `src/Gatekeep.Kernel/Limits/SecurityLimits.cs`. The token-limit pattern is at :247-256; add `SignUpTenantAttempts`, `SignUpSourceAttempts`, `VerificationSendTenantAttempts`, `VerificationSendSourceAttempts` and `SignUpWindow`.
- **Steps:** `src/Modules/Protocol/Contracts/StepResponse.cs`: `Signup` :45-54, `SignupData` :171, `SignupErrors` :138-141 (add `TermsRequired = "terms_required"`).
- **Settings:** `src/Modules/Tenancy/Contracts/TenantSettings.cs:19`, which already holds `TermsUrl`.
- **Schema:**
  - `src/Adapters/Postgres/Migrations/Migration20261128000000SignUp.cs`: the `"user"` alteration model at :38, the `NO FORCE`/`FORCE` RLS pattern at :83 and :92, and the grants at :126-127.
  - `Schema/TableRegistry.cs:314-327`.
- **Email:** `src/Modules/Notifications/Contracts/NotificationsContract.cs:92,98`.
- **Client:**
  - `apps/hosted-login/src/step.ts`: `SignupData` :43-49, parser :179-190, `SIGNUP_ERRORS` :138.
  - `api.ts:90` `postSignup`.
  - `StepScreen.tsx:100-109`.
  - `packages/hosted-screens/src/SignupScreen.tsx:16-41`.
  - `packages/ui/src/messages.tsx`, plus a `Checkbox` from `packages/ui` if one exists (otherwise add one there, with tokens only).
- **Tests:**
  - `tests/Isolation/Identity/SignUpTests.cs`: the existing-address test :219-255 asserts no job at :248, so invert it; the hash-budget test :296-310; `AssertNothingWrittenAsync` :441.
  - `SignUpFlow.cs`: `StartHostAsync` :58 (add a `signUpLimits` parameter passed to `ProtocolHost.StartAsync`, `ProtocolHost.cs:80-84`) and `SignUpBrowser` :134-188 (add `acceptTerms`). `X-Test-Source` (`ProtocolHost.cs:64`) sets the source.
  - `tests/Isolation/MigrateCommandTests.cs:28`: 44 → 45, in every place the count appears.
  - `tests/browser/hosted-step-server.mjs` and `hosted-signup.spec.ts`.
- **Docs:** `docs/threat-model.md`, T-62 (around :212) and the enumeration row.

## Tasks & Acceptance

**Execution:**
- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs`: add the sign-up and verification-send limits and window, which are the NFR-6 defaults.
- `src/Adapters/Postgres/Migrations/Migration20261129000000SignUpTerms.cs` plus `TableRegistry.cs`: the two `"user"` terms columns, the CHECK and the gk_hosted column grants.
- `src/Modules/Identity/*`:
  - `RegisterAsync` records the terms on INSERT and on unverified re-sign-up, and reports the existing User's ID.
  - `signed_up` adds `termsAccepted` to its detail.
- `src/Modules/Authentication/Core/SignUpService.cs` plus `Contracts/ISignUp.cs`:
  - Sign-up takes `acceptTerms` and returns `TermsRequired` before the rules when a terms URL is set and terms aren't accepted.
  - It enqueues the `security_notification` job for an existing verified address in the same command.
- `src/Modules/Protocol/*`:
  - The `SignUpLimits` record, its registration, and a shared limit helper used by `SignupAsync`, `ResendAsync` and `NewLinkAsync`, answering 429 with `Retry-After` and a Generic error, or `link_sent`.
  - `acceptTerms` parsing, `termsUrl` in Signup step data, and `SignupErrors.TermsRequired`.
- `packages/ui` plus `packages/hosted-screens/src/SignupScreen.tsx`: the terms row, the copy, the error and its focus.
- `apps/hosted-login/src/{step.ts, api.ts, StepScreen.tsx, App.tsx}`: read `termsUrl`, allow `terms_required`, send `acceptTerms`, and block submit when the box isn't ticked.
- `tests/Isolation/Identity/SignUpTests.cs` (plus `SignUpNeutralityTests.cs` if it is clearer): every I/O Matrix row, including the timing test (medians within 100 ms) and the DB state assertions.
  - Also touch `SignUpFlow.cs`, `MigrateCommandTests.cs` and the canary flow, so the terms URL isn't logged.
- `tests/browser/hosted-step-server.mjs` plus `hosted-signup.spec.ts`:
  - the terms row is shown only with a URL;
  - submitting unticked shows "Accept the terms to continue." with focus on the checkbox;
  - the link opens in a new tab with `rel="noopener noreferrer"`;
  - run axe in light and dark.
- `docs/threat-model.md`: the stated timing tolerance and how it holds, the existing-address notice, and the sign-up and resend limits. Keep T-62's unverified-address residual.

**Acceptance Criteria:**
- Given an existing verified address, when sign-up is submitted, then:
  - no account row changes;
  - exactly one `security_notification` job targets that User;
  - the response's status and body equal a new sign-up's, apart from the step version, CSRF token and expiry;
  - the timing medians are within 100 ms.
- Given a terms URL, when a User signs up, then acceptance is required (server and client), and the accepted URL and time are stored on the User.
- Given repeated sign-ups or resends past the limit, when the next one arrives, then it is limited per Tenant and per source with an answer that doesn't depend on the address.
- Given the same email in two Tenants, when both sign up, then two unrelated Users exist.
- Given sign-up disabled, when sign-up is submitted, then no account is created and the response is identical for existing and new addresses.

## Spec Change Log

## Review Triage Log

### 2026-11-22 — Review pass
- verdicts: 30 findings — high 0, medium 2, low 22, false 2, maybe-false 4
- findings:
  - `medium` `patch` (Blind) One source past its limit still bumps the Tenant counter, so it alone can fill the Tenant's 600 — `LimitAsync` now counts the source first and bumps the Tenant only when the source is allowed; T-63 updated; test `A_source_kept_going_past_its_limit_doesnt_use_up_the_Tenants_limit`.
  - `low` `reject` (Blind) The terms URL recorded is the Tenant's at submit, not the one shown — only when an Owner changes the URL mid-sign-up; the fix adds a request field and a branch. The misleading comment is patched (Edge row below).
  - `low` `patch` (Blind) The terms tick isn't reset when Signup is opened again — `App.tsx` resets it on a step change or a new terms URL.
  - `low` `patch` (Blind) The terms error stays after ticking — ticking clears `terms_required` and the failed state.
  - `low` `patch` (Blind) The checkbox's accessible name is "I agree to the" — `aria-labelledby` covers the label and the link: "I agree to the Terms of Service".
  - `low` `reject` (Blind) A limited Resend replaces Email verification required with Generic error — the spec's chosen answer; reached only after 10 resends from one source; the link already sent still works.
  - `maybe-false` `reject` (Blind) Unforwarded requests share one `unknown` source counter — Kestrel always sets RemoteIpAddress behind Caddy; if true it would be low (a proxy misconfiguration).
  - `low` `patch` (Blind) The two terms columns can disagree — CHECK `user_terms_accepted_together` added.
  - `low` `reject` (Blind) The 100 ms tolerance is weak against many-sample averaging — the tolerance is the stated one (NFR-20 "within a stated tolerance"); matching every insert is new design.
  - `low` `reject` (Blind) The notice is generic and notice jobs pile up — the template text is fixed (five IDs); jobs are bounded by the sign-up limits and delivery by the per-recipient limit.
  - `low` `reject` (Blind) Create account and Resend hold a second connection while counting — bounded by the pool and only for two upserts; moving the count changes the spec's "after the step is valid" order.
  - `low` `reject` (Blind) No test proves a terms refusal costs a limit slot — it follows from the handler order; test-only with no user-visible gain.
  - `low` `reject` (Edge) Second connection during counting — same as the Blind row.
  - `medium` `patch` (Edge) One source fills the Tenant counter — same root cause as the Blind row, fixed by it.
  - `low` `reject` (Edge) Terms changed between render and submit — same as the Blind row.
  - `low` `patch` (Edge) Tick carried to a fresh Signup — fixed with the Blind row.
  - `low` `reject` (Edge) With an invalid email and unticked terms the client shows only the terms error — a second submit shows the email error; reordering client checks for a corner case.
  - `low` `reject` (Edge) An unverified re-sign-up after the terms URL is removed keeps the earlier acceptance — that acceptance did happen; clearing it adds a branch for a rare case.
  - `low` `reject` (Edge) `signed_up` lacks `termsAccepted` — the audit model has no field for it; deferred (frontmatter) since the fix changes the audit schema; AC2's recording is met on the User.
  - `low` `patch` (Edge) The comment claims the URL is "recorded as it was shown" — reworded to the URL at submit.
  - `low` `patch` (Edge) T-63 understates single-source exhaustion — fixed with the limiter patch.
  - `low` `patch` (Verification Gap) A server-sent `terms_required` never passes the client reader in a test — fixture `signup_terms_late` and a browser test added.
  - `low` `patch` (Verification Gap) The https-only `termsUrl` guard is untested — fixture `signup_terms_hostile` (`javascript:`) and a Generic error test added.
  - `low` `patch` (Verification Gap) The Tenant-wide send limit is never exercised — test `With_the_Tenants_send_counter_at_its_limit_a_new_sources_Resend_is_429_and_its_new_link_sends_nothing` added.
  - `low` `reject` (Intent) `/signup/open` isn't limited — it hashes nothing, writes only the step, and sends nothing; the cost-bearing endpoints are limited.
  - `false` `reject` (Intent) The design's "Privacy Policy" link is missing — EXPERIENCE.md's Design Delta: "Terms row uses the Tenant's single terms URL."
  - `false` `reject` (Intent) An unverified existing address is changed and gets no notice — FR-17's "existing account" is a held one; T-62 records the unverified case, and a notice to it would itself differ from a new sign-up.
  - `maybe-false` `reject` (Intent) Only verified-vs-new is timed — the unverified path does the new path's work; if true it would be low.
  - `maybe-false` `reject` (Intent) No test compares a limited answer for an existing and a new address — the limit runs before any lookup and keys on no address; if true it would be low.
  - `maybe-false` `reject` (Intent) The disabled path's timing isn't compared — the disabled path does no lookup for any address; if true it would be low.

## Design Notes

- **Notice template:** `security_notification` is the template that already exists for this story ("Stories 4.8 and 4.11: takes no credential"). Its generic text names no account detail. A sixth template would break the "five IDs, fixed for good" contract.
- **Terms version = URL:** nothing in the PRD or UX defines a separate version, and the Admin terms field accepts versioned URLs (`…/terms@v2` is a tested valid value). Recording the exact URL accepted is unambiguous and survives later URL changes.
- **Limit numbers:** no source gives values (the architecture review flags it as a PRD gap). These defaults follow precedent:
  - per source: 10 per 15 min, like the Admin sign-in order of magnitude and the 5-per-15-min email recipient limit;
  - per Tenant: 600 per 15 min (40/min), high enough for a launch spike and below the token endpoint's 1,200.
  - They are overridable through `SignUpLimits` for tests, with no runtime setting yet.
- **Timing tolerance of 100 ms** sits well under Argon2id's cost (around 50–150 ms at m=19 MiB). Because both paths do identical work, the remaining difference is one link-token insert. Measuring medians over alternating requests keeps CI noise out.
- **429 for limits** follows the token endpoint. The status is the same for every address, so it reveals nothing, and the Hosted client already renders a step from any status.

## Verification

**Commands:**
- With `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors. If Docker isn't running, use the local SDK.
- `pnpm -r build`, `pnpm --filter @gatekeep/ui check`, `pnpm --filter @gatekeep/hosted-login budget`, and the package unit tests. Expected: green.
- The Isolation, Architecture and browser suites run on CI on the PR. Don't run them locally.

## Auto Run Result

Status: done

**Summary:**
- **Existing verified address:** sign-up changes no account row and enqueues one `security_notification` email to its owner. It answers the same `verify_email` 200 as a new address, with medians within the stated 100 ms tolerance.
- **Terms:** with a Tenant terms URL, Signup shows a required terms checkbox (server and client enforced, refused before the rules and the hash). The accepted URL and time are stored on the User.
- **Rate limits:** Create account, Resend and Send a new link are limited per Tenant and per source (never by address). Refused-by-source requests don't count against the Tenant. Past a limit: 429 `Retry-After` Generic error, or the neutral `link_sent`.
- **Tests:** two Tenants with one email give unrelated Users, and disabled sign-up answers identically.

**Files changed (main ones):**
- `Migration20261129000000SignUpTerms.cs`, `TableRegistry.cs`: `user.terms_accepted_url/at`, checks and grants.
- `SecurityLimits.cs`, `ProtocolContract.cs` (`SignUpLimits`), `ProtocolServer.cs`, `TokenEndpoint.cs`: the four policies.
- `IdentityService.cs`, `IIdentity.cs` (`Registration`), `SignUpService.cs`, `ISignUp.cs`: terms, notice, `TermsRequired`.
- `HostedSignIn.cs`, `StepResponse.cs`: limits, `acceptTerms`, `termsUrl`, `terms_required`.
- `packages/ui` (`TermsAgreement`, copy), `SignupScreen.tsx`, `apps/hosted-login/src/{App,StepScreen,step,api}`: terms row and client checks.
- Tests: `SignUpNeutralityTests` (new), `SignUpTests`, `SignUpFlow`, `MigrateCommandTests` (45), the canary flow, Architecture key scopes, browser `hosted-signup.spec.ts` and stub. Docs: threat model T-6 and T-63.

**Review findings:** 30.
- **13 patched:** the single-source Tenant exhaustion (one root cause, two rows), the terms tick reset and error clearing, the accessible name, the paired-columns CHECK, the comment, the T-63 wording, and three test gaps.
- **1 deferred:** the `termsAccepted` audit detail.
- **The rest rejected** with reasons in the triage log.

**Follow-up review recommended:** false. One `medium` entry (the limiter order, two rows) was patched and is covered by a new test. Patched entries: high 0, medium 1, low 10.

**Verification:**
- .NET build in the SDK 10.0.403 Docker image: 0 warnings, 0 errors.
- `pnpm -r build`, the `@gatekeep/ui` check and the ui unit tests are green. The bundle is 96.0 kB of 150 kB.
- The Isolation, Architecture and browser suites run on CI (the source of truth).

**Residual risks:**
- The timing test compares medians on CI runners; a noisy runner could flake it.
- A terms URL changed mid-sign-up records the new URL.
- A limited Resend shows Generic error in place of Email verification required.
