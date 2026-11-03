---
title: 'Story 1.22: Register Admin WebAuthn credentials'
type: 'feature'
created: '2026-11-03'
status: 'done'
baseline_revision: '9d1a9c65f68cee7520262e45eaae88f982dc584b'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-21-claim-bootstrap-and-create-the-first-admin.md'
  - '{project-root}/docs/threat-model.md'
warnings: [oversized]
deferred:
  - summary: >-
      Backup-eligible and backed-up flags are not stored on admin_credential.
    evidence: |-
      Synced passkeys holding both credentials cannot be detected. Belongs with credential management.
    location: >-
      src/Adapters/Fido2/Fido2WebAuthnVerifier.cs
    severity: medium
  - summary: >-
      No real-browser WebAuthn ceremony reaches the real server verifier in tests.
    evidence: |-
      Server tests use a software authenticator; browser tests mock the API.
    location: >-
      tests/browser/credential-setup.spec.ts
    severity: medium
  - summary: >-
      The two-credential cap and the concurrent duplicate-credential path have no database guard or test.
    evidence: |-
      Enforced in application code; race path untested.
    location: >-
      src/Modules/Admins/Core/AdminCredentialRegistration.cs
    severity: low
---

<intent-contract>

## Intent

**Problem:** After claiming bootstrap, the Owner holds only a setup Session and no credential. FR-2 and FR-46 require the first Admin to register two WebAuthn credentials before anything else, so that losing one device can't lock them out. AD-31 requires verification through the Kernel `IWebAuthnVerifier` port. Its stateless `src/Adapters/Fido2` adapter takes the RP ID and origin on every call and knows no User or Admin types. Threat-model gap G-8 asks to confirm per-call RP ID and origin, and that `crossOrigin` is rejected.

**Approach:** Add the `IWebAuthnVerifier` port to the Kernel and a `Fido2` adapter over a pinned `Fido2` NuGet package. Add an `admin_credential` table in the Admins module. Add setup-allowed endpoints to begin and finish a registration. While an Admin has fewer than two credentials, the request checks allow only setup-allowed endpoints, whatever kind of Session it is. The second credential ends setup: it upgrades the Session to `full` and writes the audit events. The dashboard's credential setup page drives the browser's WebAuthn ceremony.

## Boundaries & Constraints

**Always:**
- **Port and adapter:**
  - `IWebAuthnVerifier` (in the Kernel) exposes `BeginRegistration` and `FinishRegistration`. Every call carries the RP ID, the RP name, the expected origin, the user handle and display name, the existing credential IDs to exclude, and the stored challenge. It returns plain data: the credential ID, the COSE public key, the sign count, the AAGUID, the transports, and the user-verified flag.
  - `src/Adapters/Fido2` implements the port statelessly. It builds a fresh `Fido2` instance per call from those parameters and references no Admins, Identity or User types.
  - An architecture test enforces both properties: no reference from the adapter to any module, and no stored configuration.
- **What a registration requires:**
  - Attestation `none`; user verification `required`; resident key `preferred`.
  - Algorithms ES256 and RS256.
  - The ceremony is refused when `clientDataJSON.crossOrigin` is true, when the origin isn't exactly the Admin origin, when the RP ID isn't exactly the Admin hostname, and when user verification is absent.
- **`admin_credential` table:**
  - Columns: `id`, `admin_id` (FK to `admin`, `ON DELETE RESTRICT`), `credential_id` (bytea, unique Deployment-wide), `public_key` (bytea), `sign_count` (bigint), `aaguid` (uuid), `transports` (text[]), `created_at`, `last_used_at`.
  - It is a `control` table owned by Admins, with exact grants for `gk_admin` (insert, select, and update on `sign_count` and `last_used_at` only). The registry, migration and catalogue tests are updated.
- **User handle:** each Admin gets a random 64-byte WebAuthn user handle, stored once on `admin` (new column `webauthn_handle`, unique). It is not the Admin's ID.
- **Ceremony state:**
  - The pending challenge (32 CSPRNG bytes) is stored as its SHA-256, with a 5-minute expiry, on the Admin Session row (new nullable columns). Each new begin replaces it, and a finish clears it.
  - A finish without a matching, unexpired challenge is refused. So is a replay of a used challenge.
- **Endpoints**, all setup-allowed and requiring the Session cookie, the exact Origin and the CSRF token:
  - `POST /api/v1/deployment/credentials/registration` returns the creation options.
  - `POST /api/v1/deployment/credentials/registration/complete` accepts the attestation response, verifies it and stores the credential.
  - Both are refused once the Admin has two credentials.
  - They are documented in the OpenAPI document; the generated client is regenerated.
- **Two-credential rule:**
  - While an Admin has fewer than two credentials, the request checks give every endpoint that isn't setup-allowed a 403, whether the Session is `setup` or `full`.
  - Storing the second credential, in the same transaction, sets the Session `kind` to `full`. It writes the Deployment audit events `admin.credential.registered` (once per credential) and `admin.setup.completed`, both with the Admin as the Actor, and catalogues them.
- **Rate limit:** registration attempts are rate-limited per Session through `IRateLimiter`, at 10 per 15 minutes.
- **Dashboard `CredentialSetupPage`:**
  - It shows step 1 of 2, then 2 of 2, using `navigator.credentials.create` with the options.
  - A cancelled ceremony (`NotAllowedError` or `AbortError`) leaves the page as it is, with no error banner and with Register available again.
  - A server refusal shows Generic error.
  - Setup can't be left: no navigation appears until it's complete, and `/` sends an Admin with fewer than two credentials back to setup.
  - After the second credential, the page goes to the landing page (`/`).
  - Strings come from the message catalogue.
- **Threat model:** update G-8 (closed for registration, with tests for per-call RP ID and origin and the `crossOrigin` refusal), T-11 and the Admin credential rows.

**Never:**
- No Recovery Code alternative in this story. FR-46's "one credential plus a Recovery Code" option for other Admins comes with Admin invites and recovery.
- No sign-in ceremony (Story 1.23), no credential removal, and no attestation trust store.
- No WebAuthn library in the browser beyond the platform API.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| First credential | Setup Session, begin then finish with a valid attestation | Credential stored; Session still `setup`; one `admin.credential.registered` | — |
| Second credential | Same, second time, a different authenticator | Stored; Session becomes `full`; `admin.setup.completed` written in the same transaction | — |
| Third attempt | Admin with two credentials begins again | Refused | 403 |
| Same authenticator twice | Second registration excludes the first credential ID; the authenticator returns it anyway | Refused, nothing stored | 400 |
| Gate | Admin with fewer than two credentials calls a non-setup-allowed endpoint (setup or full Session) | Refused | 403 |
| Per-call RP and origin | Attestation for a different RP ID, or `clientDataJSON.origin` not the Admin origin | Refused | 400, nothing stored |
| Cross origin | `clientDataJSON.crossOrigin` true | Refused | 400 |
| No user verification | UV flag absent | Refused | 400 |
| Expired or missing challenge | Finish after 5 minutes, or with no begin | Refused | 400 |
| Replayed finish | Same attestation submitted twice | Second refused | 400 |
| Cancelled ceremony | Browser rejects with NotAllowedError | Page stays on the same step; no error; Register again works | — |
| Server refusal in UI | Finish returns 400 | Generic error on the page; can retry | — |
| Can't leave | Navigate to `/` with one credential | Sent back to credential setup | — |
| Adapter isolation | Architecture test | `Adapters.Fido2` references no module and keeps no RP state | Test fails otherwise |

</intent-contract>

## Code Map

- `src/Gatekeep.Host.Admin/AdminApi.cs`, `AdminRequestChecks.cs`, `AdminOpenApi.cs`, `AdminResponses.cs`, `AdminApiServices.cs`:
  - Story 1.21's endpoints use `DeploymentApiEndpoint` and `SetupAllowed` metadata.
  - The request checks run in order: Origin, then Session, then CSRF, then setup restriction.
  - The OpenAPI transformer emits `x-gatekeep-setup-allowed`.
- `src/Modules/Admins/` -- `AdminSessions.cs` (cookie, derived CSRF token, `kind`), `BootstrapClaimer.cs` (one-transaction pattern with the audit append), `SessionSecrets.cs`, `AdminAttemptLimiter.cs`, plus the contracts and `AdminsEvents.cs` (audit codes and catalogue).
- `src/Adapters/Postgres/Migrations/Migration20261103010000CreateAdminTables.cs`, `Schema/TableRegistry.cs` -- `admin` and `admin_session`, their grants and CHECKs. A new migration adds `admin_credential`, `admin.webauthn_handle` and the session challenge columns.
- `src/Gatekeep.Kernel/RateLimiting/IRateLimiter.cs` -- the rate-limit port.
- `tests/Architecture/module-edges.txt`, `ModuleEdgeTests` -- add `Adapters.Fido2` and the edges for Host.Admin composing it. Regenerate the diagram.
- `docs/api/openapi-v1.json`, `packages/api-client`, `deploy/docker/api-contract.sh --write <abs dir>` -- regenerate the document and client in Docker.
- `apps/admin-dashboard/src/CredentialSetupPage.tsx`, `main.tsx`, `session.ts` -- the placeholder page and root routing from Story 1.21.
- `tests/Isolation/Admins/` (`AdminHost.cs` and its helpers), `tests/browser/bootstrap.spec.ts` -- patterns. For browser tests, use a Chromium virtual authenticator over CDP (`WebAuthn.addVirtualAuthenticator`). For Isolation tests, build attestations with a software authenticator in test code.
- `Directory.Packages.props` -- pin `Fido2` (fido2-net-lib) to one exact version and regenerate the lockfiles.
- `docs/threat-model.md` -- G-8, T-11 and the credential rows.
- Verification runs only in Docker: `docker compose -f deploy/compose.test.yaml run --rm --build tests`.

## Tasks & Acceptance

**Execution:**
- [x] Kernel `IWebAuthnVerifier` and its plain data types; `src/Adapters/Fido2` with an architecture test for statelessness and isolation.
- [x] Migration and registry: `admin_credential`, `admin.webauthn_handle`, session challenge columns, grants, and catalogue updates.
- [x] Admins: the registration service (begin and finish), the two-credential completion in one transaction, the audit codes and the catalogue.
- [x] Host.Admin: the two endpoints, the two-credential gate in the request checks, the rate limit, and the OpenAPI document and client regeneration.
- [x] Dashboard: `CredentialSetupPage` with the ceremony, cancellation, Generic error and the leave-guard.
- [x] Tests: Isolation for every matrix row with a software authenticator; browser tests with a virtual authenticator; the architecture test; the threat model.

**Acceptance Criteria:**
- Given an Admin with fewer than two WebAuthn credentials, when they attempt any other action, then the server refuses it.
- Given `IWebAuthnVerifier` and `src/Adapters/Fido2`, when a registration runs, then the RP ID and origin are passed per call, and the adapter knows no User or Admin types.
- Given a cancelled ceremony, when it returns, then the screen stays, and setup can't be left until complete.

## Spec Change Log

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 24 findings — high 2, medium 10, low 12, false 0, maybe-false 0
- findings:
  - `[high]` `[patch]` Blind: a unique-violation finish rolls back the challenge clear, so a used challenge stays answerable — the clear now survives every failure path.
  - `[medium]` `[patch]` Blind: `ReadAttestationAsync` throws on client resets and slow bodies despite "Never throws" — caught and refused.
  - `[medium]` `[patch]` Blind: a 401 from complete shows a dead-end Generic error — sent to `/bootstrap` like begin.
  - `[medium]` `[patch]` Blind: reusing the step-1 authenticator shows Generic error with no guidance — `InvalidStateError` gets its own message and a browser test.
  - `[low]` `[reject]` Blind: every `NotAllowedError` is treated as a cancel — browsers deliberately use it for cancel, timeout and failed user verification; the page can't tell them apart.
  - `[low]` `[patch]` Blind: stored transports aren't sent back in `excludeCredentials` — passed through.
  - `[low]` `[patch]` Blind: `UserVerified` hard-coded to true — read from the authenticator data.
  - `[medium]` `[defer]` Blind: backup-eligible and backed-up flags aren't stored, so synced passkeys holding both credentials can't be detected — needs a schema change; belongs with the credential-management work.
  - `[low]` `[patch]` Blind: two sources of truth for setup complete — the count is documented as authoritative, `setup_completed_at` as a set-once audit stamp.
  - `[low]` `[defer]` Blind: the two-credential cap is enforced only in application code — a database guard can follow with credential management.
  - `[low]` `[patch]` Blind: no grants test for `admin_credential` — other roles hold nothing and `gk_admin` can't delete.
  - `[medium]` `[patch]` Blind: untested content-type, oversized-body, 401 and 429 paths — tests added.
  - `[low]` `[patch]` Blind: threat-model drafting errors and a registration-specific `Retry-After` description — fixed.
  - `[high]` `[patch]` Edge: CHECK violations and library throws also roll back the challenge clear — same fix as the Blind row; credential lengths pre-validated.
  - `[medium]` `[patch]` Edge: the Fido2 adapter lets unlisted exception types from attacker bytes escape as 500 — every parse failure maps to a refusal.
  - `[low]` `[patch]` Edge: a Session ended between the checks and the begin answers 500 — answers 401.
  - `[low]` `[patch]` Edge: a 403 from begin after setup finished elsewhere shows Generic error — goes to `/`.
  - `[low]` `[patch]` Edge: another live setup Session stays restricted after setup completes — every live setup Session of the Admin is upgraded.
  - `[low]` `[defer]` Gap: the concurrent unique-violation catch is never run — needs a race harness; the pre-check covers the non-concurrent case.
  - `[medium]` `[patch]` Gap: no test raises a non-cancel ceremony error — added.
  - `[medium]` `[patch]` Gap: no browser test for a `full` Session with fewer than two credentials — added.
  - `[medium]` `[patch]` Gap: a non-JSON Content-Type on complete is never sent — added.
  - `[medium]` `[defer]` Intent: the server is only verified against a software authenticator and the dashboard only against a mocked API — no real-browser ceremony reaches the real verifier; an end-to-end flow is follow-up work.
  - `[low]` `[reject]` Intent: begin and finish each count toward the 10-attempt limit — counting every call bounds verifier work; documented.

## Design Notes

- **Port shape:** `IWebAuthnVerifier.BeginRegistration` is synchronous and `FinishRegistrationAsync` carries the .NET `Async` suffix; both take only Kernel records (`WebAuthnRelyingParty`, `WebAuthnUser`, the exclude list and the challenge). A refusal is a `WebAuthnRegistrationResult` with a fixed `WebAuthnRefusal`, never an exception, so nothing from the response reaches a log.
- **The stored challenge:** the begin is handed the 32 CSPRNG bytes Admins generated; the finish is handed the challenge as it is stored, its SHA-256. The adapter decodes the client data's challenge, compares its SHA-256 in constant time, and only then gives the library that challenge as the original.
- **Exact origin and `crossOrigin` in the adapter:** fido2-net-lib 4.3.2 compares origins case-insensitively after dropping a default port, so the adapter first checks the client data itself: type `webauthn.create`, origin byte for byte the Admin origin, no `crossOrigin` (anything but `false` refuses) and no `topOrigin`. The library then checks the RP ID hash, UP and UV, algorithms and the excluded credential through its uniqueness callback.
- **Statelessness:** a `Fido2Configuration` and `Fido2` instance per call. The architecture test refuses any instance field, writable static field or property in the adapter, any module or configuration assembly reference, and the `Fido2` package or `Fido2NetLib` namespace anywhere else in `src/`.
- **Every live setup Session is upgraded** with the second credential, so a second tab's Session never says `setupComplete` while staying restricted. A Session that ended after the request checks authenticated it is a 401.
- **Excluded credentials carry their transports**, from `admin_credential` through the Kernel `WebAuthnCredentialDescriptor` to the options and the browser. `UserVerified` is the authenticator data's UV flag, read from the parsed attestation, not assumed.
- **The adapter refuses rather than throws** on any exception from attacker bytes except cancellation; the body reader turns a cut-off or malformed request (`IOException`, which `BadHttpRequestException` is) into a refused finish.
- **Dashboard edge cases:** a 401 from either call goes to `/bootstrap`; a 403 from begin (setup finished elsewhere) goes to `/`; `InvalidStateError` (the authenticator already holds an excluded credential) shows guidance to use a different security key or device, while `NotAllowedError` stays a silent cancel.
- **The gate counts credentials:** the Session read counts the Admin's `admin_credential` rows; `AdminSession.Restricted` is a setup Session or fewer than two credentials. `setupComplete` in the Session response now means two credentials, and a new `credentials` count lets the page resume at step 2 after a reload. `admin.setup_completed_at` is still set, once, with the second credential, as an audit stamp only: the credential count is authoritative.
- **The user handle** is made at the first begin, under the Admin row lock, and a new `admin_guard_update` trigger makes it, and `setup_completed_at`, write-once. The authenticator's account name is the Admin's role ("Deployment Owner" or "Gatekeep Admin") until Admins have names.
- **Kind:** `gk_admin` may now update `admin_session.kind`; the extended `admin_session_guard_update` refuses any change from `full`, and the CHECK leaves `full` as the only change from `setup`.
- **A finish always uses the challenge up:** it is two transactions. `TakeChallengeAsync` clears the pending challenge under the Admin row lock and is committed before anything is verified; `FinishAsync` then verifies and stores. A refusal, a unique or CHECK violation (400 `credential_refused`) or any other fault (the request checks' 503) can't bring the challenge back. Begin and the take are ceremony state on the Session row and write no audit event; only stored credentials and setup completion do. Verified lengths are checked against the table's CHECKs first and refused as malformed, and unknown transports are dropped.
- **Rate limit:** each begin and each complete counts under `admins.credential.register` (10 per Session in 15 minutes), in its own transaction before the call runs, so two credentials take at least four of the ten.
- **Duplicates:** the exclude list refuses one of the Admin's own credentials in the adapter; a credential ID another Admin holds is refused by a lookup before the insert, and a unique violation on a race is a 400 with nothing stored.
- **Browser tests:** `credential-setup.spec.ts` loads from `http://localhost:4313` because WebAuthn takes no IP address as an RP ID. Cancellation is simulated with the virtual authenticator's user verification turned off, which Chromium ends with `NotAllowedError`, as a cancel does.
- **Dependencies:** `Fido2` 4.3.2 brings `Fido2.Models`, `NSec.Cryptography` (with libsodium), `System.Formats.Cbor`, `Microsoft.IdentityModel.JsonWebTokens` and `Microsoft.Extensions.Http` into Host.Admin only.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: build with no warnings; API contract drift check passes; browser, Architecture and Isolation tests pass.

## Auto Run Result

Status: done

**Summary:** an Admin registers two WebAuthn credentials before leaving setup. A stateless Fido2 adapter behind a Kernel port verifies each registration with the exact origin, refuses cross-origin and wrong-ceremony data, and checks the single-use challenge stored as a hash on the Session. Registering the second credential upgrades the Session to full and writes both audit events in one transaction. An Admin with fewer than two credentials gets 403 on everything except setup. The dashboard runs the two-step ceremony.

**Files:** `src/Adapters/Fido2/`; `src/Gatekeep.Kernel/WebAuthn/`; `src/Modules/Admins/`; the admin credential migration and `TableRegistry`; `src/Gatekeep.Host.Admin/` (registration API, request checks, OpenAPI); `docs/api/openapi-v1.json`, `packages/api-client/`; `apps/admin-dashboard/src/`; `tests/Isolation/Admins/`, `tests/Architecture/`, `tests/browser/credential-setup.spec.ts`; `docs/audit-events.md`, the threat model and module diagram.

**Review:** 24 findings across four layers: 18 patched, 4 deferred, 2 rejected, each with its reason in the triage log.

**Follow-up review:** recommended. The high findings (the challenge clear rolled back on failures) were patched, with new tests as the only proof.

**Verification:** see the PR screenshot; the full suite passes in the `tests` container.

**Residual risks:** refused registrations are logged but not audited. No real-browser ceremony is verified end to end. Backup flags aren't stored, so a synced passkey provider may hold both credentials.
