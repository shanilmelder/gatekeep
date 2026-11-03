---
title: 'Story 1.23: Sign in as an Admin with WebAuthn'
type: 'feature'
created: '2026-11-03'
status: 'done'
baseline_revision: 'e0b41c48e902e05310dd7abc643e7b5e2711f4a9'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-21-claim-bootstrap-and-create-the-first-admin.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-22-register-admin-webauthn-credentials.md'
  - '{project-root}/docs/threat-model.md'
warnings: [oversized]
deferred:
  - summary: >-
      An Owner whose setup Session expires before registering any credential is locked out.
    evidence: |-
      Bootstrap is closed and sign-in needs a credential. Story 1.32 recovers Admin access from the host.
    location: >-
      apps/admin-dashboard/src/CredentialSetupPage.tsx
    severity: high
  - summary: >-
      No test for sign-in or bootstrap claims with no client address.
    evidence: |-
      The real-Kestrel test host cannot produce a null remote address.
    location: >-
      src/Gatekeep.Host.Admin/SignInApi.cs
    severity: low
---

<intent-contract>

## Intent

**Problem:** An Admin can get a Session only by claiming bootstrap (Story 1.21). Once that setup Session ends, nobody can reach the Admin Dashboard again. FR-46 and AD-31 require Admins to sign in with WebAuthn only: no email, no password and no Tenant Connection. Verification goes through the Kernel `IWebAuthnVerifier`, with the RP ID as the Admin hostname. AD-12, AR-24 and NFR-4 require a full `admin_session` row that stores only a hash, a `SameSite=Strict` `__Host-` cookie with the §5.2 Admin lifetimes (30 minutes idle, 8 hours absolute), and a CSRF token plus an exact-Origin check on every state-changing request. Threat-model gap G-8 is still open for assertions. Two items deferred from earlier stories belong here: auditing sign-in and sign-out (from 1.21), and detecting a `sign_count` regression, the sign of a cloned authenticator (from 1.22).

**Approach:**
- **Port and adapter:** extend `IWebAuthnVerifier` and the `Fido2` adapter with an assertion ceremony, `BeginAssertion` and `FinishAssertionAsync`. Each call carries the RP ID and origin, and the adapter stays stateless.
- **Pending challenge:** sign-in has no Session yet, so the pending challenge lives in a new short-lived `UNLOGGED` `control` table, `admin_signin_challenge`. Each row is bound to a `__Host-gk-admin-signin` cookie and is taken (deleted) before verification.
- **Endpoints:** add two sessionless, Origin-checked, rate-limited endpoints that begin and complete sign-in. A verified assertion starts a `full` Admin Session in the same transaction that advances the credential's counter and writes `admin.signin.succeeded`.
- **Sign-out:** writes `admin.session.signed_out`.
- **Dashboard:** gets an Admin sign-in page at `/signin` and a Sign out action.

## Boundaries & Constraints

**Always:**
- **Port and adapter (AD-31, AR-7):**
  - `IWebAuthnVerifier` gains `BeginAssertion(WebAuthnAssertionBegin)` and `FinishAssertionAsync(WebAuthnAssertionFinish, CancellationToken)`.
  - A begin carries the `WebAuthnRelyingParty` and the 32-byte challenge, and returns `WebAuthnRequestOptions`: the challenge, `rpId`, timeout, `userVerification: required` and an empty `allowCredentials`.
  - A finish carries the Relying Party, the stored challenge's SHA-256, the assertion (`WebAuthnAssertion`: credential ID, `clientDataJSON`, `authenticatorData`, signature and `userHandle`), and the stored credential (`WebAuthnStoredCredential`: credential ID, COSE public key, sign count and the owning user handle).
  - A finish returns a `WebAuthnAssertionResult`. When verified, it holds the new sign count and the UV flag. When refused, it holds a fixed `WebAuthnRefusal`. A refusal is never an exception.
  - The adapter still references no module, User or Admin type, and keeps no state. `WebAuthnAdapterRuleTests` keeps passing unchanged.
- **What an assertion requires:**
  - Client data type `webauthn.get`.
  - An origin that is byte-for-byte the Admin origin, with no `crossOrigin` and no `topOrigin`.
  - A challenge whose SHA-256 matches the stored one, compared in constant time.
  - An `rpIdHash` equal to SHA-256 of the Admin hostname.
  - The UP and UV flags both set, and a valid signature over the stored COSE key.
  - A `userHandle` that is present and equal to the stored credential's owner handle (closes G-8's `userHandle` half for Admins).
  - **Sign count:** if the stored and new counts are both 0, the assertion passes (the authenticator keeps no counter). Otherwise the new count must be strictly greater than the stored one, or the assertion is refused with `SignCountRegressed`. The adapter checks this itself and doesn't rely on library behaviour.
  - New `WebAuthnRefusal` members: `SignCountRegressed` and `UserHandleMismatch`. A bad signature is `Invalid`.
- **Discoverable credentials:**
  - Sign-in identifies the Admin from the credential alone, with no username, so `allowCredentials` is always empty and no credential ID is ever sent to an unauthenticated client.
  - Registration (Story 1.22) changes `residentKey` from `preferred` to `required`, so every Admin credential can sign in. The 1.22 Isolation and browser tests that assert `preferred` are updated to match. See Ask First.
- **`admin_signin_challenge` table:**
  - An `UNLOGGED` `control` table owned by Admins. Columns:
    - `id` (uuid PK)
    - `binding_hash` (bytea, 32 bytes, unique): the SHA-256 of the 256-bit cookie value
    - `challenge_sha256` (bytea, 32 bytes)
    - `created_at`
    - `expires_at`, with `CHECK (expires_at > created_at AND expires_at - created_at <= interval '5 minutes')`
  - `gk_admin` gets exactly `SELECT`, `INSERT` and `DELETE`, with no `UPDATE`. This is the first Admins table with `DELETE`, and the registry comment says why: a take is a delete, so the challenge can't be used twice.
  - The registry, the migration, the catalogue test and `AdminApiRuleTests`' registry theory are updated.
  - Lifetime is `SecurityLimits.WebAuthnChallengeLifetime` (5 minutes). Times come from the database clock.
- **Ceremony state:**
  - **Begin:** inserts a row with a fresh 32-byte CSPRNG challenge and a fresh 256-bit binding value. In the same transaction it deletes every expired row (a bounded sweep, so no purge job is needed) and the row for any binding cookie the request already carried.
  - **Begin's cookie:** sets `__Host-gk-admin-signin=<binding>; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=300`.
  - **Complete:** once the attempt is counted, and before the body is read, takes the row with `DELETE … WHERE binding_hash = @h RETURNING challenge_sha256, expires_at > clock_timestamp()`: an expired row is deleted too, and only a live one's hash is used. The take is a transaction of its own, committed with `CancellationToken.None` before anything is verified, so a client abort can't roll it back. A challenge therefore answers at most once, whatever happens next. Only a 429, or a 503 for a missing client address, returns before the take and leaves the challenge live.
  - **Complete's cookie:** always clears the binding cookie (`Max-Age=0`).
  - A complete with no cookie, an unknown or expired binding, or a used one is refused.
- **Endpoints** (sessionless, marked with a new `SignInEndpoint` metadata class, like `BootstrapClaimEndpoint`):
  - **Request checks for `SignInEndpoint`:**
    - Origin exactly the Admin origin, else 403.
    - No Session or CSRF check.
    - Until bootstrap completes, both endpoints are the unknown-path 404, as `/bootstrap` is after it completes.
    - Not `SetupAllowed`, so the setup-allowed list in `AdminApiRuleTests` stays as it is.
  - `POST /api/v1/deployment/signin`:
    - 200 `AdminSignInOptionsResponse` (WebAuthn JSON: base64url `challenge`, `rpId`, `timeout`, `userVerification`, `allowCredentials: []`), with the binding cookie set.
    - Refusals: 403 for a wrong Origin, 404 before bootstrap, 429 `rate_limited` with `Retry-After`, 503 for no client address or a database fault.
  - `POST /api/v1/deployment/signin/complete`:
    - Body: `AdminSignInRequest` (`id`, `rawId`, `type: public-key`, `response { clientDataJSON, authenticatorData, signature, userHandle }`), read under a 10-second deadline and a 64 KiB cap, with the same reader rules as registration.
    - 200 `AdminSignInResponse` (`adminId`, `csrfToken`, `setupComplete`) with `__Host-gk-admin=<id>; Path=/; Secure; HttpOnly; SameSite=Strict` and the binding cookie cleared.
    - Every refusal is the same 400 `signin_refused` (a new `AdminResponses` problem code), with no Session and nothing that says why. This covers an unknown credential, no challenge, a ceremony refusal, a sign-count regression and an unparseable body.
    - Other statuses: 403 for a wrong Origin, 404 before bootstrap, 429, 503.
  - Both endpoints, and their sessionless security, are in the OpenAPI document. The generated client is regenerated with `deploy/docker/api-contract.sh --write <abs dir>`.
  - `DELETE /api/v1/deployment/session` (sign-out, from Story 1.21) keeps its contract (204, cookie cleared, not setup-allowed) and now audits.
- **Session created at sign-in:** one transaction does all of the following:
  - locks the credential row and its Admin row;
  - updates `sign_count` and `last_used_at` with `WHERE sign_count = @stored` (zero rows affected is a refusal);
  - starts a `kind = 'full'` Session through `AdminSessions.StartAsync`, so only the SHA-256 of a 256-bit ID is stored and the §5.2 lifetimes come from `SecurityLimits`;
  - appends `admin.signin.succeeded`;
  - ends with `superseded` any live Session the request's `__Host-gk-admin` cookie named.

  An Admin with fewer than two credentials gets a `full` Session that the existing gate still restricts to setup-allowed endpoints (`AdminSession.Restricted`).
- **Rate limits (`IRateLimiter` over `admin_attempt`, per client from `AdminRequestChecks.Client`):**
  - `admins.signin.begin`: 20 per 15 minutes.
  - `admins.signin.complete`: 10 per 15 minutes.
  - Each attempt is counted in its own committed transaction before it runs. Every complete is counted, so every failed attempt is counted and can't be undone; a success spends one too.
  - The new constants go in `SecurityLimits` (`[ASSUMPTION: values]`) and the policies in `AdminsContract`.
- **Audit (Deployment chain, catalogued in `AdminsEvents` and `docs/audit-events.md`):**
  - `admin.signin.succeeded`: Actor and target are the Admin. Written in the Session's transaction.
  - `admin.signin.failed`: Actor `Anonymous`, target the Admin who owns the credential. Written only for a failure attributable to a registered credential: a ceremony refusal, or a counter race.
  - `admin.credential.sign_count_regressed`: Actor `Anonymous`, target the Admin. Written instead of `admin.signin.failed` when the counter goes backwards.
  - `admin.session.signed_out`: Actor and target are the Admin. Written by `IAdminSessions.EndAsync` in its transaction, only when that call actually ended the Session.
  - The failure events commit even though sign-in is refused.
  - None of these events holds a credential ID, challenge, user handle, Session ID or CSRF token.
  - Unattributable refusals (unknown credential, no challenge, malformed body, rate-limited) are logged with their fixed refusal name and trace ID only, and not audited. This keeps anonymous traffic from flooding the chain.
- **Tenant User credentials can't authenticate:**
  - The Admins sign-in reads only `admin_credential` and has no edge to Identity, Authentication or Sessions.
  - An architecture test proves it. It asserts that `gk_admin` holds no grant on any registry table owned by Identity, Authentication or Sessions (today `user`, `user_session`, `authorization`, `token` and `signin_transaction`). It also asserts that the `module-edges.txt` edges keep `Admins` and `Adapters.Fido2` away from those modules.
  - An Isolation test proves it from the outside: a credential made for a Tenant RP ID and never stored in `admin_credential` is refused with 400 `signin_refused`, and no Session is created.
- **Dashboard:**
  - **`SignInPage` at `/signin`:**
    - A `hosted-card` in the default theme, with title "Sign in" `[ASSUMPTION]` and subtitle "Sign in with your security key or passkey.", and one primary action, "Sign in".
    - It has no email, password or username field.
    - The flow is begin, then `navigator.credentials.get({ publicKey })`, then complete.
    - On success it stores the CSRF token in memory and goes to `/`, which sends a restricted Admin on to `/setup/credentials`.
    - A cancel (`NotAllowedError`, `AbortError`) leaves the page as it is, with no error.
    - A 400, or any other WebAuthn error, keeps the screen and shows an error `Banner` reading "That credential wasn't recognised.", with Sign in available again.
    - A 429 or 503 shows Generic error, as Bootstrap does.
    - Strings come from the `@gatekeep/ui` message catalogue.
  - **Sign out:** a Sign out button on the root placeholder page, until Story 1.25's avatar menu. It calls `DELETE /api/v1/deployment/session` with the CSRF token, then goes to `/signin`.
  - **Expired Session:** a 401 from the root page or from credential setup now goes to `/signin`, not `/bootstrap`.
  - `webauthn.ts` gains `requestOptions()` and `assertionRequest()`, using only the platform API.
- **CSRF and Origin (NFR-4):**
  - Isolation tests show that sign-out, and both registration calls, are refused with 403 for a missing or wrong `X-Gatekeep-CSRF` and for a wrong, missing or duplicated `Origin`, and that the Session isn't ended.
  - They also show both sign-in endpoints refusing a wrong, missing or duplicated `Origin` with 403, with no row and no Session created.
- **Docs:**
  - `docs/threat-model.md`:
    - close G-8 for Admins: assertions get per-call RP ID, origin and `crossOrigin`, plus `userHandle` (the Tenant half stays open for the Passkeys story);
    - update T-11, T-50 and the Admin session, credential and challenge rows;
    - add a row for the sign-in challenge and binding cookie;
    - add the clone-detection control and name its tests.
  - `docs/audit-events.md` gains the four codes.
  - `deferred-work.md` gains the out-of-scope items below, and adds `admin_signin_challenge` to AD-27's Admins table list.

**Ask First:**
- Changing registration's `residentKey` to `required` excludes non-discoverable security keys from Admin use. The alternative is to send every Admin credential ID in `allowCredentials` to unauthenticated callers, which exposes how many Admin credentials there are and probes them. The spec chooses `required`. Confirm before implementing.
- Any change to the sign-out contract (status, setup-allowed), or adding a sessionless endpoint beyond the two named here.

**Never:**
- No email, password, username, email code, TOTP, social or Tenant Connection path to an Admin Session. No Admin Recovery Code sign-in: the "Use a recovery code" link from EXPERIENCE is omitted until Admin Recovery Codes exist.
- No reuse of Identity, Authentication or Sessions tables, code or flows. No shared `signin_transaction`.
- No challenge held in a signed cookie, in memory or in the adapter. No credential ID in `allowCredentials`.
- **Out of scope**, recorded in `deferred-work.md`:
  - auditing refused and rate-limited bootstrap claims (Epic 7);
  - auditing Admin Session expiry, and the expiry banner (Epic 7, and Story 1.25's shell);
  - storing and using the BE/BS backup flags (credential management);
  - disabling a credential, or raising a Security Alert, on a sign-count regression (Security Alerts story);
  - fresh assertions for sensitive actions (FR-46 re-authentication);
  - Admin Recovery Codes;
  - a real-browser-to-real-server WebAuthn end-to-end test (deferred from 1.22, still open);
  - purging `admin_attempt` rows.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Screen loads | GET `/signin` | Card with subtitle "Sign in with your security key or passkey." and no input field; begin's options carry `rpId` = Admin hostname, empty `allowCredentials`, UV required | — |
| Valid sign-in | Begin, then complete with an assertion from a registered credential | 200; one `full` `admin_session` row storing only `id_hash`; `__Host-gk-admin` cookie `Secure; HttpOnly; SameSite=Strict; Path=/`, no Domain; idle 30 min, absolute 8 h; `sign_count` and `last_used_at` updated; `admin.signin.succeeded` | — |
| Admin with one credential | Valid assertion, Admin has one credential | 200, `setupComplete: false`; non-setup endpoints return 403; dashboard goes to credential setup | — |
| Cancelled | `navigator.credentials.get` rejects with NotAllowedError | Screen stays; no banner; Sign in works again; nothing written beyond the begin's row and count | — |
| Bad signature | Assertion signed by another key for a stored credential ID | No Session; `admin.signin.failed` (target the Admin); screen shows "That credential wasn't recognised." | 400 `signin_refused` |
| Unknown credential | Credential ID not in `admin_credential` (for example a Tenant User's passkey) | No Session; nothing audited; logged | 400 `signin_refused` |
| Tenant RP | Assertion whose `rpIdHash` is a Tenant hostname's | Refused `RpIdMismatch` | 400 |
| Origin, crossOrigin, UV | `clientDataJSON.origin` not exact; `crossOrigin` true; `topOrigin` present; UV flag clear; type `webauthn.create` | Refused, no Session | 400 |
| Wrong user handle | `userHandle` absent or another Admin's | Refused `UserHandleMismatch` | 400 |
| Cloned authenticator | Stored `sign_count` 7, assertion's 7 or lower (non-zero) | No Session; `admin.credential.sign_count_regressed`; counter unchanged | 400 |
| Counter-less authenticator | Stored 0, assertion 0 | Signed in | — |
| No or expired challenge | Complete with no binding cookie, an unknown one, or after 5 minutes | Refused; binding cookie cleared | 400 |
| Replay | The same assertion and cookie submitted twice | Second refused: the row was deleted by the first take | 400 |
| New begin | Begin twice with the same binding cookie | First row deleted; only the second challenge answers | — |
| Rate limited | 11th complete or 21st begin from one client in 15 minutes | Counted, refused before anything else | 429 + `Retry-After` |
| No client address | Remote address missing | Refused, nothing counted | 503 |
| Before bootstrap | Either sign-in endpoint while bootstrap is open | Unknown-path 404 | 404 |
| Wrong Origin | Sign-in begin or complete with a wrong, missing or duplicated Origin | Refused by the request checks: no row, nothing counted, no Session | 403 |
| CSRF on state change | Sign-out with no or a wrong `X-Gatekeep-CSRF`, or a wrong Origin | Session still live | 403 |
| Sign out | DELETE session with a valid cookie and CSRF | Row `ended_at` set, `end_reason = 'signed_out'`; `admin.session.signed_out`; cookie cleared; dashboard at `/signin`; old cookie then gets 401 | 204 |
| Signing in again | Complete while the browser holds a live Admin Session cookie | Old Session ended `superseded`; new Session issued | — |
| Isolation of User credentials | Architecture test | `gk_admin` has no grant on Identity, Authentication or Sessions tables; no module edge from Admins or Fido2 to them | Test fails otherwise |

</intent-contract>

## Code Map

- `src/Gatekeep.Kernel/WebAuthn/IWebAuthnVerifier.cs`: add the assertion records and methods, and the two refusals.
- `src/Adapters/Fido2/Fido2WebAuthnVerifier.cs`: add `BeginAssertion` and `FinishAssertionAsync` over `Fido2.MakeAssertionAsync`, with a fresh `Fido2Configuration` per call. The client-data pre-checks (type `webauthn.get`, exact origin, `crossOrigin`, `topOrigin`, challenge hash) run first; then come the `userHandle` comparison and the sign-count rule. Registration's `residentKey` becomes `required`.
- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs`: add the sign-in attempt limits and window.
- `src/Modules/Admins/Contracts/`:
  - a new `IAdminSignIn.cs` with `BeginAsync`, `TakeChallengeAsync` and `FinishAsync` (the two-transaction pattern of `IAdminCredentialRegistration`) and its outcome records;
  - `AdminsContract.cs` gains the two policies and `CreateSignIn(IAuditAppender, IWebAuthnVerifier)`, and `CreateSessions` takes the appender;
  - `AdminsEvents.cs` gains the four events;
  - `IAdminSessions.EndAsync` returns whether it ended the Session.
- `src/Modules/Admins/Core/`:
  - a new `AdminSignIn.cs`;
  - `AdminSessions.cs`: the sign-out audit, plus a `SupersedeAsync` helper;
  - `SessionSecrets.cs` is reused for the binding value.
- `src/Adapters/Postgres/Migrations/`: a new `Migration20261103030000CreateAdminSignInChallengeTable.cs`. `Schema/TableRegistry.cs` gets the new entry.
- `src/Gatekeep.Host.Admin/`:
  - a new `SignInApi.cs`, modelled on `CredentialRegistrationApi.cs`;
  - `AdminApi.cs`: the two maps, and the audited sign-out;
  - `AdminRequestChecks.cs`: the `SignInEndpoint` marker, with the bootstrap-open and Origin checks;
  - `AdminResponses.cs`: `signin_refused`, and the binding-cookie helpers;
  - `AdminOpenApi.cs`: no security on the two sign-in operations;
  - `AdminApiServices.cs`: wire `IAdminSignIn`.
- `docs/api/openapi-v1.json` and `packages/api-client`: regenerate in Docker with `deploy/docker/api-contract.sh --write <abs dir>`.
- `apps/admin-dashboard/src/`:
  - a new `SignInPage.tsx`;
  - `main.tsx`: the `/signin` route, and Sign out on the root page;
  - `webauthn.ts`: assertion conversion;
  - `CredentialSetupPage.tsx`: 401 goes to `/signin`.
- `packages/ui/src/messages.tsx`: sign-in and sign-out strings.
- `tests/Isolation/Admins/`:
  - `SoftwareAuthenticator.cs` gains `Assert(options, origin, AssertionTweaks?)`, which produces a `webauthn.get` response with a configurable sign count, user handle, RP ID, origin, `crossOrigin`, `topOrigin` and UV, and can sign with a different key;
  - a new `AdminSignInTests.cs`;
  - extend `AdminEndpointTests.cs` with the CSRF and Origin refusals;
  - extend `Fido2AdapterTests.cs` with the assertion cases.
- `tests/browser/`: a new `signin.spec.ts`, following `credential-setup.spec.ts`: route interception for the API, and a Chromium virtual authenticator (`hasResidentKey: true`) with a credential added through `WebAuthn.addCredential` for the assertion. `credential-setup.spec.ts` is updated for `residentKey: required` and the 401 redirect.
- `tests/Architecture/`:
  - `AdminApiRuleTests.cs`: the registry theory row for `admin_signin_challenge`; the claim and the two sign-in operations are the only operations with no security scheme; the sessionless marker set is exactly those three routes; the setup-allowed list is unchanged.
  - `AuditCatalogueTests` covers the new codes.
  - A new `AdminCredentialIsolationTests` (or a fact in `AdminApiRuleTests`) holds the no-shared-table and no-edge proof.
- `docs/threat-model.md`, `docs/audit-events.md`, `_bmad-output/implementation-artifacts/deferred-work.md`.

## Tasks & Acceptance

**Execution:**
- [x] Kernel: the assertion records, methods and refusals. Fido2 adapter: the assertion ceremony, the pre-checks, the user-handle and sign-count rules, and registration `residentKey: required`. Adapter tests.
- [x] Migration and registry: `admin_signin_challenge` (`UNLOGGED`, CHECKs, exact grants including `DELETE`), with catalogue and `AdminApiRuleTests` updates.
- [x] Admins: `IAdminSignIn` (begin with sweep, take, finish with the counter compare-and-set, Session start, supersede and audit); the sign-out audit in `EndAsync`; the policies, limits and events.
- [x] Host.Admin: `SignInEndpoint` checks, the two endpoints with their cookies, rate limits and the `signin_refused` problem, the audited sign-out, then OpenAPI and client regeneration.
- [x] Dashboard: `SignInPage`, the `webauthn.ts` assertion helpers, Sign out on the root, the 401 redirects to `/signin`, and the catalogue strings.
- [x] Tests: Isolation for every matrix row with `SoftwareAuthenticator`, plus CSRF and Origin refusals; browser `signin.spec.ts` (no fields, cancel, failure banner, success to `/`, sign-out to `/signin`, axe, CSP); the architecture isolation proof; the updated 1.22 tests.
- [x] Docs: the threat model (G-8, T-11, T-50, rows), `audit-events.md`, and `deferred-work.md` (out-of-scope items and the AD-27 table note).

**Acceptance Criteria:**
- Given the Admin sign-in screen, when it loads, then it shows no email or password field, and the RP ID is the Admin hostname.
- Given a valid assertion, when it verifies through `IWebAuthnVerifier`, then a full `admin_session` row is created with only its hash stored, using a `SameSite=Strict` `__Host-` cookie and the §5.2 Admin lifetimes.
- Given a cancelled or failed assertion, when it returns, then the screen stays, showing "That credential wasn't recognised." on failure, and failed attempts count in `admin_attempt`.
- Given a state-changing request, when the CSRF token or exact-host Origin is wrong, then it's refused.
- Given Sign out, when it completes, then the Session row is ended and the Admin returns to Admin sign-in.
- Given a Tenant User credential, when it's presented to Admin sign-in, then it can't authenticate, because no shared table or flow exists.
- Given an assertion whose sign count doesn't advance past a non-zero stored count, when it's verified, then sign-in is refused and `admin.credential.sign_count_regressed` is written.

## Spec Change Log

- 2026-11-04, Story 1.23 review: the complete takes the challenge before reading the body and commits the take with `CancellationToken.None`; the take deletes any row the binding names, then flags whether it was live. Only signature-verified refusals are audited (`admin.signin.failed` is kept, documented for the defence-in-depth compare-and-set). New event `admin.session.superseded`. The counter-race note is corrected: under the row lock a racing lower counter is reported as a regression.

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 21 findings — high 2, medium 8, low 11, false 0, maybe-false 0
- findings:
  - `[high]` `[patch]` Blind: the "race, not a clone" branch is unreachable under `FOR UPDATE`, so a racing lower counter is reported as a clone — docs describe the real behaviour and a test pins it; the compare-and-set stays as defence in depth.
  - `[high]` `[defer]` Blind: an Owner whose setup Session expires before registering any credential can never sign in — recovery is Story 1.32; recorded in the threat model.
  - `[medium]` `[reject]` Blind: credentials registered under 1.22 with `residentKey: preferred` may not be discoverable — no Deployment holds 1.22 credentials.
  - `[medium]` `[reject]` Blind: `NotAllowedError` is silent on timeout or no passkey — the spec keeps the screen unchanged on cancel, and browsers blur the cases on purpose.
  - `[medium]` `[patch]` Blind: the root page shows a bare placeholder when the Session read fails — Generic error with a way back.
  - `[medium]` `[patch]` Blind: anyone with a credential ID can write `admin.signin.failed` against a chosen Admin — only signature-verified failures are audited; the rest are logged.
  - `[low]` `[patch]` Blind: "the challenge is used up whatever the outcome" is false for 429s and aborted body reads — the challenge is taken before the body, and the description is accurate.
  - `[low]` `[patch]` Blind: superseding another Session writes no event — `admin.session.superseded` added.
  - `[low]` `[patch]` Blind: missing tests for double sign-out, a NULL user handle, supersede over an ended Session and an empty begin answer — added.
  - `[low]` `[reject]` Blind: before bootstrap every sign-in POST opens a transaction to answer 404 — the window is short and the endpoint answers nothing useful.
  - `[medium]` `[patch]` Edge: a client abort during the body read or before the take commits leaves the challenge live — taken first and committed with `CancellationToken.None`.
  - `[low]` `[patch]` Edge: a Session without a CSRF token shows a Sign out that can never work — guarded.
  - `[low]` `[reject]` Edge: non-discoverable 1.22 credentials — same as the Blind row.
  - `[medium]` `[patch]` Gap: the log line for unattributable refusals is never asserted — tests check the refusal name and trace ID in the host output.
  - `[low]` `[patch]` Gap: `EndAsync` on an already-ended Session is never run — covered.
  - `[medium]` `[patch]` Gap: a 401 from the credential-setup begin going to `/signin` is unpinned — browser test added.
  - `[low]` `[defer]` Gap: no test for a missing client address on sign-in — the test host can't produce one; close with the bootstrap claim's same gap.
  - `[low]` `[patch]` Intent: the take SQL deletes expired rows too, unlike the contract text — the stricter behaviour is kept and the spec updated.
  - `[low]` `[patch]` Intent: the restricted Admin's redirect to setup after sign-in is untested in the browser — added.
  - `[low]` `[patch]` Intent: an unused `SignInAllowedCredential` type and an unreachable `InvalidSignCount` mapping — cleaned up.
  - `[medium]` `[patch]` Verification: every Admin refusal log line since 1.21 named its problem in a `{Code}` placeholder, which the log scrubber masks as a sensitive name — renamed `{Problem}`; the sign-in and bootstrap tests now assert the code in the log.

## Design Notes

- **Where the pending challenge lives:** a row in `admin_signin_challenge`, bound to a `__Host-gk-admin-signin` cookie. Three alternatives were rejected:
  - A signed challenge cookie. It needs a signing key in `Host.Admin`, still needs server state to stop replays, and AD-12 rules out session-like state in signed cookies.
  - A pre-auth `admin_session` row. It would weaken that table's invariants (`admin_id NOT NULL`, its kinds, the 8-hour CHECK) and its "only a hash of a live Session" meaning.
  - In-memory storage. It doesn't survive across instances or restarts, and the adapter must stay stateless.

  `UNLOGGED` fits because losing pending ceremonies in a crash only makes an Admin press Sign in again. Taking a challenge is a `DELETE … RETURNING`, so single use doesn't depend on an update grant. The begin's sweep of expired rows bounds the table to five minutes of begins, which the per-client begin limit bounds in turn.
- **Login CSRF without a Session:** NFR-4's CSRF token is bound to a Session, and none exists before sign-in. The sign-in endpoints rely instead on three things. The exact-Origin check refuses cross-site posts. The `SameSite=Strict` binding cookie ties the challenge to the browser that began. And the ceremony needs the Admin's own authenticator gesture. Every endpoint that needs a Session keeps the CSRF header check unchanged.
- **Discoverable-only:** with no username, the server learns which Admin is signing in from the credential ID and checks it against `userHandle`. Listing credential IDs in `allowCredentials` would hand them to anyone on the public Admin hostname (T-47). Registration therefore requires a resident key. Credentials already registered in test databases are rebuilt by the tests, and no production Deployment exists yet.
- **One refusal for every failure:** the API answers every failure with the same 400 `signin_refused`, and the UI shows one message. A probe can't tell an unknown credential from a bad signature or a missing challenge. The fixed `WebAuthnRefusal` name reaches only the log.
- **Counting:** each begin and each complete is counted per client in its own committed transaction before it runs, as bootstrap claims are. A refused attempt's count is therefore never rolled back, and parallel attempts can't exceed the limit. `admin_attempt` has no `DELETE` grant, so success doesn't reset the window. 10 completes per 15 minutes leaves room for normal use. Counting per Admin as well was rejected: no credential ID is public, so it would add a lockout route and no protection.
- **Taking the challenge:** a complete takes it straight after it is counted, before reading the body, so a slow, oversized or malformed body uses it up too, and every response after the take clears the binding cookie (a 503 included). The take deletes any row the binding names and only then flags whether it was live, which is stricter than deleting live rows only: asking with an expired binding uses that row up as well.
- **Counter race:** the finish locks the credential's row and its Admin's `FOR UPDATE`, so sign-ins with one credential run one at a time. Under that serialisation an assertion with a lower counter after one with a higher counter is indistinguishable from a clone, and is reported as `admin.credential.sign_count_regressed`. The counter update stays a compare-and-set on the verified value as defence in depth; under the lock it can't lose, and if it ever did it would be refused with `admin.signin.failed`.
- **What is audited (review):** only refusals after the signature verified over a registered credential: a counter regression, or the compare-and-set losing. Anything refused before the signature (a bad signature, another user handle or RP ID, a missing flag, an Admin with no handle, an unknown credential) is logged only, because anyone with a credential ID could otherwise write `admin.signin.failed` against a chosen Admin. Every attempt is still counted. A sign-in that supersedes a live Session writes `admin.session.superseded` in its transaction.
- **Signing in while signed in:** the new Session supersedes the one the browser presented (`end_reason = 'superseded'` already exists in the CHECK). One browser therefore holds at most one live Admin Session.
- **Restricted Admins:** the Session is always `full`. What it may reach is still decided by the credential count (Story 1.22's gate), so a one-credential Admin who signs in can only finish setup. `admin.signin.succeeded` is still written.
- **Bootstrap gating:** before bootstrap completes there's no Admin to sign in, so both endpoints are the unknown-path 404. This mirrors `/bootstrap` disappearing afterwards and keeps the pre-bootstrap surface to the claim alone.
- **Sign-out stays not setup-allowed** (Story 1.21's decision): a restricted Admin who signs out would need recovery. The dashboard shows Sign out only on the root page, which a restricted Admin never stays on.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests`. Expected:
  - the build has no warnings;
  - the API contract drift check passes;
  - the browser, Architecture and Isolation tests pass, including the 1.22 tests updated for `residentKey: required`.

  Nothing runs on the host.

## Auto Run Result

Status: done

**Summary:** an Admin signs in with a discoverable WebAuthn credential and nothing else. A single-use challenge lives in a short-lived table bound to a strict cookie and is used up before the response body is read. The stateless Fido2 adapter verifies the assertion against the Admin hostname and exact origin. A counter that doesn't advance is refused and audited as a possible clone. Success starts a full Admin Session in the same transaction as the counter update and its audit event. Sign-out ends the row and returns to sign-in. Tenant User credentials can't authenticate, because no table or flow is shared.

**Files:** `src/Gatekeep.Kernel/WebAuthn/`; `src/Adapters/Fido2/`; the sign-in challenge migration and `TableRegistry`; `src/Modules/Admins/` (sign-in, sessions, events); `src/Gatekeep.Host.Admin/` (sign-in API, request checks, OpenAPI); `docs/api/openapi-v1.json`, `packages/api-client/`; `apps/admin-dashboard/src/` (sign-in page, root, credential setup); `tests/Isolation/Admins/`, the canary flows, `tests/Architecture/AdminCredentialIsolationTests.cs`, `tests/browser/signin.spec.ts`; `docs/audit-events.md` and the threat model.

**Review:** 21 findings across four layers: 15 patched, 2 deferred, 4 rejected, each with its reason in the triage log.

**Follow-up review:** recommended. The challenge ordering and the audit rules changed in review, with new tests as the only proof.

**Verification:** see the PR screenshot; the full suite passes in the `tests` container.

**Residual risks:** an Owner who loses the setup Session before registering a credential needs Story 1.32's recovery. Two sign-ins racing with one authenticator are reported as a possible clone. Admin credentials must be discoverable, so security keys that can't store resident credentials can't be used.
