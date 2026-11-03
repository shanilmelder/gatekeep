---
title: 'Story 1.22: Register Admin WebAuthn credentials'
type: 'feature'
created: '2026-11-03'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-21-claim-bootstrap-and-create-the-first-admin.md'
  - '{project-root}/docs/threat-model.md'
warnings: [oversized]
deferred: []
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
- [ ] Kernel `IWebAuthnVerifier` and its plain data types; `src/Adapters/Fido2` with an architecture test for statelessness and isolation.
- [ ] Migration and registry: `admin_credential`, `admin.webauthn_handle`, session challenge columns, grants, and catalogue updates.
- [ ] Admins: the registration service (begin and finish), the two-credential completion in one transaction, the audit codes and the catalogue.
- [ ] Host.Admin: the two endpoints, the two-credential gate in the request checks, the rate limit, and the OpenAPI document and client regeneration.
- [ ] Dashboard: `CredentialSetupPage` with the ceremony, cancellation, Generic error and the leave-guard.
- [ ] Tests: Isolation for every matrix row with a software authenticator; browser tests with a virtual authenticator; the architecture test; the threat model.

**Acceptance Criteria:**
- Given an Admin with fewer than two WebAuthn credentials, when they attempt any other action, then the server refuses it.
- Given `IWebAuthnVerifier` and `src/Adapters/Fido2`, when a registration runs, then the RP ID and origin are passed per call, and the adapter knows no User or Admin types.
- Given a cancelled ceremony, when it returns, then the screen stays, and setup can't be left until complete.

## Spec Change Log

## Review Triage Log

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: build with no warnings; API contract drift check passes; browser, Architecture and Isolation tests pass.
