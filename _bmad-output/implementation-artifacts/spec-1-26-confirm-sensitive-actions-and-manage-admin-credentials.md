---
title: 'Story 1.26: Confirm sensitive actions and manage Admin credentials'
type: 'feature'
created: '2026-11-04'
status: 'done'
baseline_revision: '76c21445a08d779e8fd4dd5bcd73bd4ac37e0faa'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-gatekeep-2026-11-01/prd.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/DESIGN.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-22-register-admin-webauthn-credentials.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-23-sign-in-as-an-admin-with-webauthn.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-25-open-the-admin-shell.md'
  - '{project-root}/design/Gatekeep Admin.dc.html'
warnings: []
deferred:
  - summary: >-
      Rotating the Deployment hmac key voids every Admin Recovery Code.
    evidence: |-
      The lookup uses the latest key version only.
    location: >-
      src/Modules/Admins/Core/AdminRecoveryCodes.cs
    severity: medium
  - summary: >-
      No Tenant-scoped fresh-assertion begin route.
    evidence: |-
      Tenant Always and When capabilities can't be confirmed until it exists.
    location: >-
      src/Gatekeep.Host.Admin/FreshAssertionApi.cs
    severity: medium
  - summary: >-
      The credential floor trigger blocks deleting an Admin's credentials.
    evidence: |-
      Epic 8's Admin removal must handle it.
    location: >-
      src/Adapters/Postgres/Migrations/Migration20261104010000ConfirmSensitiveActions.cs
    severity: medium
  - summary: >-
      Recovery can't retire the lost credential, and an Admin at the maximum can't register in recovery.
    evidence: |-
      Recovery-code Admins first exist with Story 8.3.
    location: >-
      src/Modules/Admins/Core/AdminRecoveryCodes.cs
    severity: low
---

<intent-contract>

## Intent

**Problem:** FR-46 says "These actions need a fresh WebAuthn assertion within §5.2: Admin grant or removal, Signing Key revocation, lowering MFA policy, changing a Prod Tenant's callback URLs or label, rotating a client secret, changing the email provider, granting Management API access, Tenant deletion, and FR-50 actions." §5.2 sets "Recent authentication: 5 minutes". UX-DR17 adds the gate: "If the last assertion is over 5 minutes old, the WebAuthn sheet appears on confirm, with failure shown inside the same modal and no second modal."

Story 1.24 built the declaration but nothing enforces it:
- `AdminCapabilities` gives each capability a `FreshAssertion` of `Never`, `Always`, `WhenProdTenant` or `WhenLoweringPolicy`, and every one that isn't `Never` is machine-denied.
- `CapabilityDecision` returns the flag, and `AdminCapabilities.Allows` says it "isn't evaluated here".
- `CapabilityRuleTests` refuses any route that declares a fresh-assertion capability "until Story 1.26 enforces it".
- Threat model G-5: "A fresh assertion isn't bound to its action and target Tenant".

FR-46 also says "Every Admin registers two WebAuthn credentials, or one and a Recovery Code held offline. A Recovery Code sets up a new credential and can't reach any other action." Today:
- An Admin can't list, add or remove a credential. Registration is refused with 403 once there are two, and `admin_credential` has no `DELETE` grant.
- EXPERIENCE's "Your credentials" screen ("List of the Admin's credentials, with Add and Remove", "Removing the last credential is refused", `toast`) and the avatar menu item ("The avatar menu holds Your credentials and Sign out") don't exist.
- The `admin_recovery_code` table (AD-27), `RevealOnce<T>` (AD-24) and the "Use a recovery code" link on Admin sign-in (EXPERIENCE) don't exist either.

Items in `deferred-work.md` this story takes in:
- "Fresh assertions for sensitive Admin actions (FR-46 re-authentication)" (Story 1.23).
- "Enforce `FreshAssertion` on capability routes, and lift the architecture rule…" (Story 1.24).
- "Admin Recovery Codes, and the 'Use a recovery code' link on Admin sign-in" (Story 1.23).
- "Your credentials in the avatar menu (Story 1.26)" (Story 1.25).
- "Store and use the WebAuthn BE/BS backup flags for Admin credentials (credential management)" (Stories 1.22 and 1.23).
- "Database guard for the two-credential cap and a race test for duplicate credential IDs" (Story 1.22). The cap becomes a floor of two and a maximum of ten, both guarded in the database.

**Approach:**
- **A fresh assertion is a server-side grant.** It is a row in a new `UNLOGGED` `control` table, `admin_fresh_assertion`, owned by Admins. Each row is bound to:
  - one Admin Session;
  - one action: a capability name, or a self-service action name;
  - the path Tenant, when there is one;
  - one target, such as the credential being removed.

  It is made by a WebAuthn assertion with user verification, from one of the Session's Admin's own credentials. It lives 5 minutes (§5.2) and is used up by the first request it matches (`DELETE … RETURNING`). It never travels as a token: the Session cookie carries it.
- **Ceremony:**
  1. `POST /api/v1/deployment/assertions` with `{ action, target }` returns WebAuthn request options and stores one pending challenge for the Session.
  2. `POST /api/v1/deployment/assertions/complete` takes that challenge in its own transaction, verifies the assertion as sign-in does, and stores the verified grant.
- **Enforcement:**
  - The request checks require the grant for every route that declares an `Always` capability or a self-service fresh-assertion action. They use it up in their own transaction, after the capability decision and before the handler.
  - A capability whose `FreshAssertion` is a predicate (`When…`), and the one self-service route whose need depends on the Session (registration begin), call the same consume from their handler, after evaluating the predicate (AD-20: "Handlers evaluate it").
  - Without a matching grant the answer is 403 `fresh_assertion_required`.
  - The Story 1.24 architecture rule becomes a consistency rule over the OpenAPI document.
- **Your credentials:** a new shell page at `/account/credentials`, reached from the avatar menu.
  - It lists the Admin's credentials.
  - Add is a fresh assertion with an existing credential, then the existing registration ceremony, allowed up to 10 credentials.
  - Remove is a destructive `ConfirmModal`, then the sheet, and is refused when fewer than two credentials would remain.
  - Removing a credential ends every other live Session of that Admin as `revoked`.
  - Every add and remove writes to the Deployment Log.
- **Admin Recovery Code:**
  - At credential setup, an Admin who isn't the Deployment Owner and has one credential may take one offline Recovery Code instead of a second credential.
  - It is issued once through the new `RevealOnce<T>` and stored only as an HMAC under the Deployment `hmac` key in `admin_recovery_code`.
  - Redeeming it from "Use a recovery code" on Admin sign-in starts a `recovery` Session, which reaches only credential registration. It works once and is limited per client through `admin_attempt`.

## Boundaries & Constraints

**Always:**

- **Fresh-assertion actions (Admins contract, `AdminFreshAssertions`):**
  - An action is a capability name whose `FreshAssertion` isn't `Never`, or one of the self-service actions `self.credentials.add` and `self.credentials.remove`. Nothing else is an action.
  - The binding is `SHA-256(UTF-8(action + "\n" + tenantPublicId + "\n" + target))`. `tenantPublicId` and `target` are empty strings when absent. `target` is the route value exactly as the request names it, such as `acr_…`, and isn't parsed. `FreshAssertionBinding(Action, TenantId?, Target?)` builds it in one place.
  - The ceremony stays bound to the Admin hostname's RP ID and exact origin, as sign-in is (AD-24, AD-31).
- **`admin_fresh_assertion` (new migration; `UNLOGGED` `control`, owned by Admins, registry entry, policies and grants in the same migration):**

  | Column | Type and rule |
  | --- | --- |
  | `id` | `uuid` primary key |
  | `session_id` | `uuid NOT NULL REFERENCES admin_session (id) ON DELETE RESTRICT` |
  | `stage` | `text NOT NULL CHECK (stage IN ('challenge', 'verified'))` |
  | `binding_hash` | `bytea NOT NULL`, 32 bytes |
  | `challenge_sha256` | `bytea NULL`, 32 bytes. Set if and only if `stage = 'challenge'` |
  | `credential_id` | `uuid NULL REFERENCES admin_credential (id) ON DELETE RESTRICT`. Set if and only if `stage = 'verified'` |
  | `created_at`, `expires_at` | `timestamptz NOT NULL`, with `CHECK (expires_at > created_at AND expires_at - created_at <= interval '5 minutes')` |

  - Unique: one `challenge` row per Session, and one `verified` row per `(session_id, binding_hash)`. Indexed on `expires_at`.
  - `gk_admin` has `SELECT`, `INSERT` and `DELETE`, and never `UPDATE`. No other role has anything.
  - A crash empties the table, which only means the Admin confirms again.
  - Times come from the database clock. Lifetimes are `SecurityLimits.WebAuthnChallengeLifetime` for a challenge, and the new `SecurityLimits.RecentAuthentication` (5 minutes, §5.2) for a verified grant.
- **Begin (`POST /api/v1/deployment/assertions`, self-service, full Sessions only):**
  - Body `{ "action": string, "target": string | null }`. A body that isn't JSON, an unknown action, or a Tenant capability action is 400 `assertion_refused`. Tenant actions begin on the Tenant surface, which arrives with the first Tenant fresh-assertion route.
  - A Deployment capability action needs the authorizer to allow it. A refusal is the Story 1.24 403 `access_denied`, counted and audited exactly as the request checks do. A self-service action needs only the Session.
  - It is counted per Session under the new `AdminsContract.FreshAssertionPolicy` (`admins.fresh_assertion`, 10 in 15 minutes `[ASSUMPTION]`), in its own committed transaction, before it runs. Over the limit is 429 `rate_limited` with `Retry-After`.
  - In one transaction it:
    - deletes every expired row;
    - deletes the Session's pending challenge and any verified row with the same binding, so only the newest confirmation counts;
    - inserts a 32-byte challenge as its SHA-256, with the binding.
  - It returns the request options from `IWebAuthnVerifier.BeginAssertion`, unchanged: user verification `required` and `allowCredentials` empty. The same `AdminSignInOptionsResponse` shape is used.
- **Complete (`POST /api/v1/deployment/assertions/complete`, self-service, full Sessions only):**
  - It is counted under the same policy. Then the Session's pending challenge is taken (deleted and returned when live) in a transaction of its own, before the body is verified, so it is used up whatever follows.
  - The body is the sign-in assertion JSON (`AdminSignInRequest`).
  - Verification reuses sign-in's path, moved into one internal `AdminAssertions` helper that `AdminSignIn` also uses:
    - lock the credential's row and its Admin's;
    - the credential must belong to the **Session's** Admin;
    - the user handle must be that Admin's;
    - UV is required;
    - the counter must advance by compare-and-set;
    - the new `backed_up` flag is stored.
  - A pass inserts the `verified` row (binding from the challenge, `credential_id`, 5 minutes) and appends `admin.fresh_assertion.verified`. It answers 204 with `Cache-Control: no-store`.
  - Every refusal is the same 400 `assertion_refused` with nothing stored. That covers no live challenge, a malformed body, another RP or origin, no UV, a bad signature, an unknown credential and another Admin's credential:
    - A counter regression appends `admin.credential.sign_count_regressed`, with the Session's Admin as Actor.
    - The defence-in-depth compare-and-set miss appends `admin.fresh_assertion.failed`.
    - Every other refusal is only logged, with its fixed `WebAuthnRefusal` name.
- **Consume (`IAdminFreshAssertions.ConsumeAsync(context, session, binding)`):**
  - It runs `DELETE FROM admin_fresh_assertion WHERE session_id = @s AND stage = 'verified' AND binding_hash = @b AND expires_at > clock_timestamp() RETURNING id` and returns whether a row came back.
  - The caller's transaction commits it **before** the action runs. So a grant is used up even when the action then fails (400, 404, 409 or 5xx), and a retried action needs a new confirmation (AD-30).
- **Request checks (`AdminRequestChecks`, `AccessDeclaration`):**
  - The declaration gains a `FreshAssertionRequirement? (Action, TargetRouteValue?, EnforcedBy: Checks | Handler)`, derived in one place:

    | Declared | Requirement |
    | --- | --- |
    | Capability with `Never` | none, and no fresh-assertion metadata allowed |
    | Capability with `Always` | `Checks`, action = the capability name |
    | Capability with `WhenProdTenant` or `WhenLoweringPolicy` | `Handler`. The route must also carry `EvaluatesFreshAssertion` metadata, or the declaration is invalid |
    | Self-service with `new RequiresFreshAssertion(action, targetRouteValue, inHandler)` | `Checks`, or `Handler` when `inHandler` |
    | Sessionless | none allowed |

  - The optional `FreshAssertionTarget(routeValue)` metadata names a capability route's target.
  - A `Checks` requirement on a setup-allowed route is invalid, because a restricted Session can never confirm.
  - An invalid declaration is the unknown-path 404 at runtime and fails the OpenAPI build, as in Story 1.24.
  - Check order: the existing Origin, Session, CSRF, restricted-Session and capability checks, then, for `Checks`, `ConsumeAsync` with the path Tenant and the target route value, in the checks' transaction, which commits with the Session slide.
  - No grant is 403 `fresh_assertion_required` (problem body, `traceId`). It is logged under `{Problem}` with the action name and isn't audited: the Admin is allowed, only unconfirmed.
  - A `Handler` route calls `FreshAssertionGate.RequireAsync(context, services, cancellationToken)` when its predicate holds. It consumes in its own committed transaction and writes the same 403 when there is no grant.
- **OpenAPI (`AdminOpenApi`):** every operation with a requirement gets `x-gatekeep-fresh-assertion: { "action", "target" (route value name or null), "enforcedBy": "checks" | "handler" }`, and lists 403 `fresh_assertion_required`. `x-gatekeep-access.freshAssertion` stays the table's flag.
- **Routes after this story:**

  | Route | Access | Fresh assertion |
  | --- | --- | --- |
  | `POST /api/v1/deployment/assertions` | self | none: it is the ceremony |
  | `POST /api/v1/deployment/assertions/complete` | self | none |
  | `GET /api/v1/deployment/credentials` | self | none |
  | `DELETE /api/v1/deployment/credentials/{credentialId}` | self | `self.credentials.remove`, target `credentialId`, checks |
  | `POST /api/v1/deployment/credentials/registration` | self, setup-allowed, recovery-allowed | `self.credentials.add`, handler: only when the Session isn't restricted |
  | `POST /api/v1/deployment/credentials/registration/complete` | self, setup-allowed, recovery-allowed | none: only a begin that passed leaves a challenge |
  | `POST /api/v1/deployment/credentials/recovery-code` | self, setup-allowed | none |
  | `POST /api/v1/deployment/credentials/recovery-code/confirm` | self, setup-allowed | none |
  | `POST /api/v1/deployment/signin/recovery-code` | sessionless | none |
  | `GET` and `DELETE /api/v1/deployment/session`, both `capabilities` reads, bootstrap and sign-in | unchanged | none |

  No current route declares a fresh-assertion capability. The FR-46 list's routes arrive with their stories, and each one is enforced by declaring its capability.
- **Credential listing (`GET /api/v1/deployment/credentials`):**
  - Returns `{ credentials: [{ id, kind, backedUp, createdAt, lastUsedAt, removable }], recoveryCode: boolean }` for the Session's own Admin, oldest first.
  - `id` is the row's public ID with the new `PublicIdType.AdminCredential` prefix `acr_` `[ASSUMPTION]`.
  - `kind` is `passkey` when the credential is backup-eligible or reported `internal` or `hybrid`, and `securityKey` otherwise `[ASSUMPTION]`.
  - `removable` is the server's floor rule.
  - `recoveryCode` says whether the Admin holds a confirmed, unused code.
  - It never returns a credential ID, public key, AAGUID, counter or user handle.
- **Credential floor and maximum (`AdminsContract`):**
  - `RequiredCredentials = 2` stays.
  - New `MaxCredentials = 10` `[ASSUMPTION]`.
  - A removal must leave at least `RequiredCredentials` credentials. That covers an Admin holding a Recovery Code too, whose only credential is always their last.
  - Both rules are enforced in code under the Admin row lock and **in the database**:
    - a `BEFORE INSERT` trigger on `admin_credential` locks the `admin` row and refuses an 11th;
    - a `BEFORE DELETE` trigger locks it and refuses a delete that leaves fewer than two.
- **Remove (`DELETE /api/v1/deployment/credentials/{credentialId}`):**
  - After the checks have used up the grant, one transaction:
    1. Locks the Admin row.
    2. Finds the credential among the **Session's** Admin's own. A malformed, unknown or other Admin's ID is the same 404.
    3. Refuses with 409 `credentials_minimum` when fewer than two would remain.
    4. Deletes every `verified` grant made with it, then the credential.
    5. Ends every other live Session of that Admin as `revoked`, appending `admin.session.revoked` for each.
    6. Appends `admin.credential.removed`.
  - Answers 204. The current Session stays.
  - `gk_admin` gains `DELETE` on `admin_credential`.
- **Add (`POST /api/v1/deployment/credentials/registration` in a full Session):**
  - The handler calls `FreshAssertionGate.RequireAsync` for `self.credentials.add` with no target, then runs the existing begin.
  - At `MaxCredentials` it is 409 `credentials_maximum`. That check runs **before** the gate, so a full list costs no confirmation.
  - In a restricted Session (setup or recovery) there is no gate, as today, and the 403-at-two rule becomes "allowed while the Admin is below the floor, or once in a recovery Session".
  - Complete and its `admin.credential.registered` event are unchanged, except that the cap is now `MaxCredentials`.
  - A same-credential-ID race between two completes stores one credential; the other is 400 `credential_refused` (unique violation, already caught).
- **BE/BS flags (Kernel port and Fido2 adapter):**
  - `WebAuthnRegisteredCredential` gains `BackupEligible` and `BackedUp`, and `WebAuthnAssertionResult.Asserted` gains `BackedUp`, read from the authenticator data flags.
  - `admin_credential` gains `backup_eligible boolean NULL` and `backed_up boolean NULL`, both NULL for a credential registered before this migration and both set for every new one, with BS only with BE. `gk_admin` gains `UPDATE (backup_eligible, backed_up)`, and a trigger keeps BE once known (review amendment).
  - Sign-in and fresh assertions store the latest `backed_up`. An assertion whose BE flag differs from a known stored one is refused as `Invalid` (WebAuthn §6.3.3: BE never changes); an unknown one is recorded on the first verified assertion (review amendment).
- **Admin Session kinds:**
  - `admin_session.kind` adds `recovery`. The guard trigger allows only `setup` to `full` and `recovery` to `full`.
  - `AdminSession` reads the Admin's credential count and whether they hold a confirmed, unused Recovery Code.
  - `SetupComplete` = two or more credentials, or exactly one with such a code.
  - `Restricted` = kind `setup` or `recovery`, or `!SetupComplete`.
  - A recovery Session reaches only routes marked `RecoveryAllowed`: `GET /session` and registration begin and complete. Every other route answers it with the bodiless 403.
  - After a registration or a code confirmation that leaves the Admin meeting the floor, every live `setup` and `recovery` Session of theirs becomes `full`. `setup_completed_at` is set if null. `admin.setup.completed` is appended when this took the Admin from not meeting the floor to meeting it.
  - `AdminSessionResponse` gains `kind: "recovery"` and `recoveryCodeAllowed`, which is true only for a `setup` Session of a non-Owner Admin with exactly one credential and no confirmed code.
- **`admin_recovery_code` (new; logged `control`, owned by Admins):**

  | Column | Type and rule |
  | --- | --- |
  | `id` | `uuid` primary key |
  | `admin_id` | `uuid NOT NULL REFERENCES admin (id) ON DELETE RESTRICT` |
  | `code_hmac` | `bytea NOT NULL UNIQUE`, 32 bytes |
  | `hmac_key_version` | `int NOT NULL` |
  | `created_at` | `timestamptz NOT NULL` |
  | `confirmed_at` | `timestamptz NULL` |
  | `used_at` | `timestamptz NULL`, with `CHECK (used_at IS NULL OR confirmed_at IS NOT NULL)` |

  - A partial unique index allows one unused code per Admin.
  - A trigger makes `confirmed_at` and `used_at` set-once and refuses deleting a confirmed row.
  - `gk_admin` has `SELECT`, `INSERT`, `UPDATE (confirmed_at, used_at)` and `DELETE`. `gk_cli` has `SELECT`, for `recover-admin` later.
  - The table holds no code, ciphertext or hint.
- **Recovery Code value:**
  - 16 characters from Crockford base32 (`0–9`, `A–Z` without `I L O U`), 80 bits, shown as `XXXX-XXXX-XXXX-XXXX`, made with `RandomNumberGenerator` (review amendment).
  - Input is normalized before any check: uppercase, hyphens and spaces removed, and `O` read as `0`, `I` and `L` as `1`. Anything that isn't then 16 alphabet characters is refused, and still counted.
  - The stored value is `IKeyCustody.HmacAsync(KeyName.ForDeployment(DeploymentKeyClass.Hmac), "gatekeep-admin-recovery-code\0" + normalized)`. Host.Admin's policy already grants `transit/hmac/dep-hmac`, and the policy is unchanged.
  - A custody failure is 503 with nothing stored or used.
- **Issue (`POST …/credentials/recovery-code`):**
  - Only in a `setup` Session, only for an Admin who isn't the Deployment Owner (FR-2: "The first Admin is a Deployment Owner and must register two WebAuthn credentials"), with exactly one credential and no confirmed code. Otherwise the bodiless 403.
  - In one transaction it deletes the Admin's unconfirmed code, if any, and inserts the new HMAC unconfirmed.
  - It answers 200 `AdminRecoveryCodeResponse { code: RevealOnce<string> }` with `Cache-Control: no-store`.
  - An unconfirmed code can't be redeemed. A reload before confirming shows nothing: the Admin issues a new one, which voids the old (AD-24: "A lost reveal means rotating again").
- **Confirm (`POST …/recovery-code/confirm`):** sets `confirmed_at` on the unconfirmed code and appends `admin.recovery_code.issued`. The Admin now meets the floor, so it applies the Session rule above. Without an unconfirmed code it is the bodiless 403.
- **Redeem (`POST /api/v1/deployment/signin/recovery-code`):**
  - Sessionless, exact Origin, the unknown-path 404 before bootstrap, like sign-in.
  - It is counted per client under the new `AdminsContract.RecoveryCodePolicy` (`admins.recovery_code.redeem`, 5 in 15 minutes, §5.2's "5 in 15 minutes" `[ASSUMPTION]`), in its own committed transaction, before the code is read. Over the limit is 429 with `Retry-After`. No client address is 503.
  - Body `{ "code": string }`. Then the HMAC, then one transaction:
    1. `UPDATE admin_recovery_code SET used_at = clock_timestamp() WHERE code_hmac = @h AND confirmed_at IS NOT NULL AND used_at IS NULL RETURNING admin_id`.
    2. End every live Session of that Admin as `revoked` (`admin.session.revoked` each), and supersede the presented Session as sign-in does.
    3. Start a `recovery` Session.
    4. Append `admin.recovery_code.used`.
  - It answers like sign-in complete, with `setupComplete: false`, and sets the Session cookie.
  - Every refusal (wrong, unconfirmed, used or malformed) is the same 400 `recovery_code_refused`. It is only logged, because no Admin is known.
- **`RevealOnce<T>` (Kernel, `Secrets`):** the one credential-equivalent type with a JSON form. It writes its value and prints `[secret]`. An architecture rule allows it only as a property of a code-listed response type, which is only `AdminRecoveryCodeResponse` in this story. Every response holding one sets `Cache-Control: no-store`.
- **Audit events (`AdminsEvents`, Deployment chain; each holds no credential ID, challenge, binding, code, HMAC or Session ID):**
  - `admin.fresh_assertion.verified`: Actor and target are the Admin.
  - `admin.fresh_assertion.failed`: Actor and target are the Admin.
  - `admin.credential.removed`: Actor and target are the Admin.
  - `admin.session.revoked`: Actor is the Admin who acted; target is the Admin whose Session ended.
  - `admin.recovery_code.issued`: at confirmation.
  - `admin.recovery_code.used`.
  - `admin.setup.completed`'s summary changes to cover "two WebAuthn credentials, or one and an offline Recovery Code". The code is unchanged.
  - `docs/audit-events.md` is regenerated: `dotnet run --project tests/Architecture/Generator`, in Docker.
- **Problem codes (`AdminResponses.ProblemCodes`):** `fresh_assertion_required` (403), `assertion_refused` (400), `credentials_minimum` (409), `credentials_maximum` (409), `recovery_code_refused` (400).
- **Logging:** fixed names only. A problem code goes under `{Problem}` and never under a placeholder named `{Code}`. No recovery code, HMAC, binding, challenge or Session value is ever logged, and the scrubber and canary scan must still pass.
- **Dashboard, the fresh-assertion helper (`apps/admin-dashboard/src/shell/freshAssertion.ts`, plain TypeScript with injected calls, tested by `test/freshAssertion.test.mjs` like `renewal.test.mjs`):**
  - `confirmItsYou({ action, target }, signal)`: begin, then `navigator.credentials.get` with the `webauthn.ts` helpers, then complete. Its outcomes are `confirmed`, `cancelled` (`NotAllowedError` or `AbortError`), `refused` (400), `rateLimited` (429 with `Retry-After`) and `unavailable`.
  - `withFreshAssertion(binding, send)`: sends, and on 403 `fresh_assertion_required` runs `confirmItsYou`, then sends **once** more. A second `fresh_assertion_required` is `refused`. Every call goes through `shellRequest`, so a 401 still renews (Story 1.25) and a state-changing request is never resent by renewal.
  - The UI never decides that an action needs a confirmation from roles or flags. The server's 403 does, except Add, which always confirms first (below).
- **Dashboard, the re-authentication gate (UX-DR17; `ConfirmModal`'s existing `reauthentication` slot):**
  - Confirm runs the helper while the modal stays open, `pending`, with Cancel and Esc disabled.
  - While the sheet is open, the slot shows "Confirm it's you with your security key or passkey." `[ASSUMPTION]`.
  - A failure shows in the slot as a `bad` `Banner` and the action isn't performed:
    - refused: "That credential wasn't recognised." (the existing `signInRefused`);
    - cancelled: "Confirmation cancelled. Nothing was changed." `[ASSUMPTION]`;
    - rate-limited: "Too many attempts. Try again in {seconds} seconds." `[ASSUMPTION]`;
    - unavailable: "We couldn't confirm it's you. Try again." `[ASSUMPTION]`.
  - Confirm then retries the whole flow. No second modal ever opens.
- **Your credentials (`/account/credentials`, new `shell/CredentialsPage.tsx`):**
  - **Reaching it:** the avatar menu gets "Your credentials" above Sign out. The route is a shell page needing only the Deployment capabilities read the shell already makes (self-service). It is not a sidebar item.
  - **Layout:** `SectionPage` with eyebrow "Account" `[ASSUMPTION]`, title "Your credentials", and description "The passkeys and security keys you sign in with. Keep at least two, so losing one device can't lock you out." `[ASSUMPTION]`. The one primary action is "Add credential" `[ASSUMPTION]`.
  - **Loading:** the list read goes through `shellRequest`, with `SkeletonRows` after the 300ms delay.
  - **Table columns** "Credential", "Added", "Last used" `[ASSUMPTION]`:
    - the name is "Passkey" or "Security key" from `kind`, with a "Synced" `Badge` when `backedUp` `[ASSUMPTION]`;
    - dates are absolute and local;
    - last used shows "Never" when null `[ASSUMPTION]`;
    - each row with `removable` true has a `button-destructive` "Remove".
  - **No removable row:** when no row is removable, the rows show no Remove button and a note says "You need at least two credentials. Add another before removing one." `[ASSUMPTION]`.
  - **Recovery Code:** when `recoveryCode` is true, a line says "You also hold an offline recovery code." `[ASSUMPTION]`.
  - **Remove:**
    1. A destructive `ConfirmModal` with title "Remove this credential?", body "You won't be able to sign in with it again. Your other Admin sessions will end." and confirm label "Remove credential" (all `[ASSUMPTION]`).
    2. `withFreshAssertion({ action: 'self.credentials.remove', target: id }, DELETE)`.
    3. A 204 closes the modal, shows the `toast` "Credential removed." `[ASSUMPTION]`, re-reads the list and moves focus to the next row, or to the heading.
    4. A 409 `credentials_minimum` shows "You can't remove this credential: you need at least two." `[ASSUMPTION]` in the slot. A 404 re-reads the list.
  - **Add:**
    1. A default `ConfirmModal` with title "Add a credential", body "Confirm it's you with a credential you already have, then register the new passkey or security key." and confirm label "Continue" (all `[ASSUMPTION]`).
    2. Continue runs `confirmItsYou({ action: 'self.credentials.add' })`.
    3. On `confirmed`, the slot shows "Now register the new passkey or security key." `[ASSUMPTION]` with the existing `credentialSetupRegister` button. That is a fresh user activation for the second sheet.
    4. The button runs registration begin, `navigator.credentials.create` and complete.
    5. Success closes the modal, shows the `toast` "Credential added." `[ASSUMPTION]` and re-reads the list.
    6. Failure handling:
       - 409 `credentials_maximum` shows "You already have 10 credentials. Remove one before adding another." `[ASSUMPTION]`;
       - 403 `fresh_assertion_required` (the grant expired or was used) returns to step 1's state with the cancelled text;
       - a cancelled create keeps step 3;
       - `InvalidStateError` shows the existing `credentialSetupAlreadyRegistered`.
- **Admin sign-in and recovery (pre-Session `hosted-card` pages):**
  - **Sign-in link:** `SignInPage` gets the link "Use a recovery code" (EXPERIENCE) to `/signin/recovery`.
  - **The entry page:** the new `RecoveryCodePage` (added to `PRE_SESSION`) has:
    - the title "Use a recovery code" and subtitle "Enter the offline recovery code you saved when you set up your credentials. It lets you register a new passkey." (both `[ASSUMPTION]`);
    - the field follows EXPERIENCE's `code-input-recovery`: label "Recovery code", helper "Format: XXXX-XXXX", `inputmode="text"`, `autocapitalize="characters"`, `autocomplete="off"` and `spellcheck="false"`;
    - the primary "Continue" `[ASSUMPTION]`, and a link "Sign in with a passkey instead" `[ASSUMPTION]` to `/signin`.
  - **Its outcomes:**
    - 400 is "That code isn't valid." (EXPERIENCE);
    - 429 is "Too many attempts. Try again in {seconds} seconds.";
    - a 5xx or network failure is the Hosted Generic error;
    - success keeps the CSRF token and goes to `/setup/credentials`.
- **Credential setup (`CredentialSetupPage`):**
  - **Recovery Session:** the title is "Set up a new passkey" (EXPERIENCE, Credential enrolment) and the subtitle "Your recovery code has been used. Register a new passkey or security key to continue." `[ASSUMPTION]`, with the Register action only.
  - **The recovery-code choice:** with `recoveryCodeAllowed`, step 2 adds a secondary button, "Use an offline recovery code instead" `[ASSUMPTION]`. It issues the code and shows the display inside the card:
    - a `warn` `Banner` with "If you lose your device, this code works once. We won't show it again." (the Design Delta's copy, made singular `[ASSUMPTION]`);
    - the code in code type with `CopyButton`;
    - an unticked checkbox "I've saved this code" `[ASSUMPTION]`;
    - Continue. Pressed unticked, the checkbox shows "Confirm you've saved your code." (EXPERIENCE, made singular). Ticked, it confirms and goes to `/`.
  - **What stays out:** there is no Download (below). The code lives only in component state, is cleared on `pagehide`, and is never stored.
- **CSP (AD-21):** nothing inline, no `data:` or `blob:` URI, styles from CSS Modules and tokens. Every new browser test uses `watchCsp` from `tests/browser/csp-watch.ts`.
- **Copy:** every string above goes in the `@gatekeep/ui` catalogue (`messages.tsx`, NFR-19). Existing keys are reused where they exist (`signInRefused`, `signInRateLimited`, `credentialSetupRegister`, `credentialSetupAlreadyRegistered`, `signOut`, `retry`).
- **Tests:**
  - **Isolation tests:** Testcontainers PostgreSQL and the real `Host.Admin` process through `AdminHost`, with every WebAuthn response from `SoftwareAuthenticator`. `FakeOpenBaoSocket` gains a `Respond` handler for AppRole login and `transit/hmac/dep-hmac` that returns a deterministic HMAC, so tests can compute the stored value.
  - **Browser tests:** Playwright against the built Host.Admin (`admin-host.mjs`), with the API intercepted, a Chromium virtual authenticator, axe and `watchCsp`.
- **Docs:**
  - `docs/threat-model.md`:
    - T-22: built. Bound, single-use, 5 minutes, consumed before the action.
    - G-5: the Admin half is closed; the sign-in transaction half stays with Story 4.2.
    - T-51: the floor, the maximum, removal ending Sessions, and Recovery Codes.
    - T-52: BE/BS.
    - T-11: fresh assertions use the same RP and origin checks.
    - The asset rows "Admin WebAuthn private key" (lifetime "Until removed in Your credentials") and "Admin Recovery Code".
    - A new T-54 for Recovery Code guessing and a stolen Recovery Code.
  - `docs/audit-events.md`, regenerated.
  - `docs/install.md` "Not yet covered": the Dashboard now also has Your credentials.
  - `deferred-work.md`, as described below.

**Ask First:**
- **Every sensitive action shows the sheet.** A grant is bound to one action and target and used once, so a sign-in a minute ago doesn't skip it. That is stricter than UX-DR17's "over 5 minutes old" wording, which this design meets trivially. The alternative, reusing any assertion under 5 minutes old, isn't action-bound and reopens G-5. Confirm before changing.
- **Adding a credential needs a fresh assertion**, though FR-46's list doesn't name it: an unattended Session could otherwise register an attacker's authenticator as a lasting way in. Confirm before changing.
- **The removal floor is two credentials** for every Admin, even one holding a Recovery Code, rather than FR-46's "two, or one and a Recovery Code". A Recovery Code is single-use and reaches only setup, so it is a way back, not a second credential. Confirm before relaxing.
- **The Recovery Code choice is offered only to non-Owner Admins** (FR-2). No such Admin can exist until Story 8.3's invites, so in production the choice first appears there. The flow is proven with a seeded non-Owner Admin.
- **No Download for the Recovery Code.** EXPERIENCE's Recovery Code display has Copy and Download, but a client-made file needs a `blob:` or `data:` URI, which AD-21's CSP and Story 1.25's rules forbid. A server-sent download would mean a second reveal. Copy only.
- The values marked `[ASSUMPTION]`: 10 fresh-assertion attempts per Session in 15 minutes, 5 Recovery Code attempts per client, a maximum of 10 credentials, `acr_`, the code alphabet, the route `/account/credentials`, and the copy.
- Any change to the OpenBao policies, the `IWebAuthnVerifier` begin options (such as listing `allowCredentials`), or the Admin CSP.

**Never:**
- No client-side authorization or fresh-assertion rule. The dashboard never decides from a role, a capability flag or a timer that an action is allowed or confirmed: the server's 403s decide.
- No fresh-assertion token in JavaScript, web storage, a cookie set by script, a header or the URL. The grant is server-side and bound to the Session.
- No grant reused, refreshed or extended, and none made from a sign-in. Nothing slides a grant.
- No fresh-assertion route reachable by a machine principal. This is unchanged: every fresh capability is machine-denied, and self-service routes need an Admin Session.
- No raw Recovery Code stored, logged, audited, cached or put in a URL. No ciphertext of it either: Host.Admin decrypts nothing (AD-10).
- No Recovery Code reaching anything but credential registration. No email, TOTP or Tenant Connection path for Admins.
- No removal of an Admin's last two credentials, by any path, the database included.
- No inline style or script, and no CSP change.
- No new runtime dependency in `apps/admin-dashboard` or `packages/ui`.
- **Out of scope**, recorded in `deferred-work.md`:
  - the Tenant-surface begin (`POST /api/v1/tenants/{tenantId}/assertions`), owned by the first story that maps a Tenant fresh-assertion route;
  - the first HTTP test of an `Always` capability route (Tenant deletion, Story 1.29; Admin invites and removal, Epic 8);
  - the `WhenProdTenant` and `WhenLoweringPolicy` predicates themselves, owned by their routes' stories;
  - renaming a credential;
  - reissuing an Admin Recovery Code from Your credentials, and a Recovery Code for the Deployment Owner;
  - Download of the Recovery Code;
  - a Security Alert on Recovery Code use or credential removal (Story 1.30);
  - email notice of credential changes, since Admins have no email until Story 8.2;
  - HMAC key rotation for `admin_recovery_code` (`hmac_key_version` is kept for it);
  - `allowCredentials` in fresh-assertion options;
  - purging `admin_attempt` rows, carried on;
  - disabling a credential on a counter regression (Security Alerts, carried on);
  - the real-browser, real-server WebAuthn end-to-end test, carried on;
  - adding `admin_fresh_assertion` (and `admin_signin_challenge`) to AD-27 in the spine.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Remove without confirmation | Full Session, 3 credentials; `DELETE /credentials/acr_b` with CSRF, no grant | 403 `fresh_assertion_required` with `traceId`. Nothing deleted, nothing audited, a log line. | — |
| Confirm, then remove | Begin `{action:"self.credentials.remove", target:"acr_b"}`, the authenticator asserts, complete 204, then DELETE | 204. Credential gone, its grants gone, other live Sessions `revoked`, one `admin.session.revoked` each, `admin.fresh_assertion.verified` and `admin.credential.removed`. Current Session works. | — |
| Grant used once | The same DELETE again, or another target | 403 `fresh_assertion_required` | — |
| Grant bound to target | Grant for `acr_b`; DELETE `acr_c` | 403 `fresh_assertion_required`. The `acr_b` grant stays until it expires. | — |
| Grant bound to Session | Grant made in Session A; DELETE sent with Session B of the same Admin | 403 `fresh_assertion_required` | — |
| Grant expired | Verified row moved 6 minutes into the past by the superuser | 403 `fresh_assertion_required` | — |
| Removal floor | 2 credentials, a grant for `acr_a` | 409 `credentials_minimum`. Nothing deleted. The grant is used up. List shows `removable: false` on both. | — |
| Floor in the database | A direct `gk_admin` `DELETE` that would leave 1 | Trigger raises. Nothing deleted. | DB error |
| Other Admin's credential | Grant for `acr_x` owned by another Admin; DELETE | 404, as an unknown ID. Nothing deleted. | — |
| Malformed credential ID | Grant for `nope`; `DELETE /credentials/nope` | 404 | — |
| Ceremony with another Admin's key | Complete with Admin B's credential in Admin A's Session | 400 `assertion_refused`. No grant, only logged. | — |
| No UV | Assertion with UV unset | 400 `assertion_refused`. No grant. | — |
| Counter regression | Assertion counter ≤ stored non-zero | 400 `assertion_refused`, `admin.credential.sign_count_regressed` (Actor the Admin), counter unchanged | — |
| Challenge single-use | Complete twice for one begin | Second is 400 `assertion_refused` | — |
| Newer begin replaces | Begin twice, complete with the first challenge | 400 `assertion_refused` | — |
| Unknown action | Begin `{action:"tenant.users.read"}` or `{action:"x"}` | 400 `assertion_refused` | — |
| Deployment action, non-Owner | Begin `{action:"deployment.tenants.delete"}` by a non-Owner | 403 `access_denied`, audited within the cap as in Story 1.24 | — |
| Deployment action, Owner | Same by the Owner | 200 options. Complete makes a grant bound to that action. | — |
| Ceremony rate limit | 11th begin or complete in 15 minutes in one Session | 429 `rate_limited`, `Retry-After` | — |
| Restricted Session | Setup or recovery Session calls begin, complete, list or DELETE | Bodiless 403 | — |
| Add without confirmation | Full Session, 2 credentials; registration begin | 403 `fresh_assertion_required`. No challenge stored. | — |
| Add with confirmation | Grant for `self.credentials.add`; begin, create, complete | 200 options, then credential stored, `admin.credential.registered`; list shows 3 | — |
| Add at maximum | 10 credentials, no grant | 409 `credentials_maximum`, before any confirmation | — |
| Maximum in the database | `gk_admin` `INSERT` of an 11th | Trigger raises | DB error |
| Duplicate credential race | Two completes storing the same credential ID at once | One stored, the other 400 `credential_refused` | — |
| Setup unchanged | Setup Session, 0 then 1 credential | Registration needs no confirmation. The second makes the Session full, as in Story 1.22. | — |
| List | Full Session | Own credentials only, oldest first, `acr_` IDs, `kind`, `backedUp`, dates, `removable`, `recoveryCode`. No credential ID, key, AAGUID, counter or handle in the body. | — |
| BE/BS stored | Registration with BE=1, BS=1, then an assertion with BS=0 | Row `backup_eligible` true, `backed_up` false after the assertion; list `backedUp: false` | — |
| BE changed | Assertion with BE=0 for a BE=1 credential | Refused (`assertion_refused` or `signin_refused`) | — |
| Recovery choice offered | Seeded non-Owner Admin, setup Session, 1 credential | Session `recoveryCodeAllowed: true` | — |
| Recovery choice refused | Deployment Owner, 1 credential; issue | Bodiless 403. Owner's Session `recoveryCodeAllowed: false`. | — |
| Issue | Non-Owner, 1 credential; issue | 200 `{code:"XXXX-XXXX"}`, `Cache-Control: no-store`. DB holds only the HMAC and key version, unconfirmed. | — |
| Reissue before confirm | Issue twice | Second code differs, first's row gone | — |
| Confirm | Confirm after issue | Session `full`, `setupComplete: true`, `admin.recovery_code.issued` then `admin.setup.completed` | — |
| Unconfirmed can't redeem | Redeem an issued, unconfirmed code | 400 `recovery_code_refused` | — |
| Redeem | Confirmed code, entered lowercase without hyphen and with an `O` for `0` | 200, cookie set, `kind: recovery`, `setupComplete: false`; the Admin's other Sessions `revoked`; `admin.recovery_code.used` | — |
| Redeem is single-use | Same code again | 400 `recovery_code_refused` | — |
| Recovery reaches only setup | Recovery Session calls capabilities, list, issue or sign-out | Bodiless 403. `GET /session` and registration begin and complete work. | — |
| Recovery completes | Register one credential in the recovery Session | Session `full`, `admin.credential.registered`, `admin.setup.completed` | — |
| Wrong codes limited | 6th redeem from one client in 15 minutes | 429 with `Retry-After`, counted in `admin_attempt` before the code is read | — |
| Redeem before bootstrap | No bootstrap yet | Unknown-path 404 | — |
| Custody down | HMAC call fails | 503. Nothing stored or used. | 503 |
| Canary | A planted Recovery Code through issue and redeem | Absent from operational logs, audit rows and every table | Test fails |
| Gate in the modal (browser) | Remove → Confirm; DELETE 403 `fresh_assertion_required`; ceremony; DELETE 204 | Sheet status in the modal's slot, one modal only, `toast` "Credential removed.", focus to the next row | — |
| Gate failure (browser) | Complete 400; sheet cancelled; 429; 503 | The matching text in the slot, modal stays, nothing removed, Confirm retries | — |
| Floor (browser) | List with both `removable: false` | No Remove button, the floor note shown | — |
| Add flow (browser) | Add → Continue → assertion → "Now register…" → Register → create → complete | `toast` "Credential added.", list re-read. Two sheets, the second from its own button. | — |
| Avatar menu (browser) | Open Account | "Your credentials", then "Sign out" | — |
| Recovery link (browser) | `/signin` | "Use a recovery code" link to `/signin/recovery` | — |
| Recovery entry (browser) | 400; 429 `Retry-After: 30`; 200 | "That code isn't valid."; "Too many attempts. Try again in 30 seconds."; goes to `/setup/credentials` | — |
| Recovery display (browser) | `recoveryCodeAllowed`, choose the code, Continue unticked, then ticked | "Confirm you've saved your code." on the checkbox; then confirm and `/` | — |
| Reveal once (browser) | Reload the display before confirming | No code shown; the choice is offered again | — |
| CSP | Every new and changed test | No `securitypolicyviolation`, no console CSP message, no other-origin request | Test fails |
| axe | Your credentials (list, floor, both modals in every slot state), recovery entry and display; light and dark; 1100 and 768 | No violations | Test fails |

</intent-contract>

## Code Map

- `src/Gatekeep.Kernel/`:
  - `Limits/SecurityLimits.cs`: `RecentAuthentication` (5 minutes), `FreshAssertionAttempts` and window, `AdminRecoveryCodeAttempts` and window, `MaxAdminCredentials`.
  - `Secrets/RevealOnce.cs` (new).
  - `Identifiers/PublicId.cs`: `PublicIdType.AdminCredential` (`acr_`).
  - `WebAuthn/IWebAuthnVerifier.cs`: the BE/BS fields on the registered credential and the assertion result, and the BE check input on `WebAuthnStoredCredential`.
- `src/Adapters/Fido2/Fido2WebAuthnVerifier.cs`: read the BE/BS flags; refuse a changed BE.
- `src/Adapters/Postgres/`:
  - new `Migrations/Migration20261104010000ConfirmSensitiveActions.cs`, holding:
    - `admin_fresh_assertion` and `admin_recovery_code`;
    - the `admin_credential` BE/BS columns, the `DELETE` and `UPDATE (backed_up)` grants, and the insert-maximum and delete-floor triggers;
    - the `admin_session.kind` `recovery` value and its trigger;
  - `Schema/TableRegistry.cs`: both tables, the grants and the triggers.
- `src/Modules/Admins/`:
  - `Contracts/`:
    - new `IAdminFreshAssertions.cs` (`FreshAssertionBinding`, `AdminFreshAssertions` actions, begin, take, finish, consume);
    - new `IAdminCredentials.cs` (list, remove);
    - new `IAdminRecoveryCodes.cs` (issue, confirm, redeem);
    - `IAdminSessions.cs` (`AdminSessionKind.Recovery`, `SetupComplete` and `Restricted`, the recovery-code flag);
    - `IAdminCredentialRegistration.cs` (the floor and maximum statuses);
    - `AdminsEvents.cs`, and `AdminsContract.cs` (the policies, `MaxCredentials` and the factories).
  - `Core/`:
    - new `AdminAssertions.cs`, the shared verification moved out of `AdminSignIn`;
    - new `AdminFreshAssertions.cs`, `AdminCredentials.cs` and `AdminRecoveryCodes.cs`;
    - `AdminSignIn.cs` (uses `AdminAssertions`, stores BS), `AdminCredentialRegistration.cs` (the setup rule, the maximum, BE/BS, the Session rule), `AdminSessions.cs` (the count with the code, start `recovery`, revoke others).
- `src/Gatekeep.Host.Admin/`:
  - `AdminRequestChecks.cs`: `RequiresFreshAssertion`, `EvaluatesFreshAssertion`, `FreshAssertionTarget`, `RecoveryAllowed`, the requirement on `AccessDeclaration`, and the consume step.
  - new `FreshAssertionGate.cs`.
  - new `FreshAssertionApi.cs`, `CredentialsApi.cs` and `RecoveryCodeApi.cs`.
  - `AdminApi.cs`: the routes.
  - `CredentialRegistrationApi.cs`: the gate and the maximum.
  - `SignInApi.cs`: the shared assertion parsing.
  - `AdminResponses.cs`: the problem codes and `no-store`.
  - `AdminOpenApi.cs`: `x-gatekeep-fresh-assertion`.
  - `AdminApiServices.cs`: the new services and `IKeyCustody`.
- `docs/api/openapi-v1.json` and `packages/api-client/src/schema.generated.ts`: regenerated with `sh deploy/docker/api-contract.sh --write <abs dir>`.
- `packages/ui/src/messages.tsx`: the new keys.
- `apps/admin-dashboard/`:
  - `src/main.tsx` (`/signin/recovery` in `PRE_SESSION`);
  - `src/SignInPage.tsx` (the link);
  - new `src/RecoveryCodePage.tsx`;
  - `src/CredentialSetupPage.tsx` (the recovery kind, the code choice and display);
  - `src/shell/Shell.tsx` (the avatar menu item, the `/account/credentials` page, the `ToastProvider`);
  - new `src/shell/CredentialsPage.tsx` and `src/shell/freshAssertion.ts`;
  - new `test/freshAssertion.test.mjs`.
- `tests/Architecture/`:
  - `CapabilityRuleTests.cs`: replace the "no route before Story 1.26" rule with the fresh-assertion consistency rules and their self-checks; add the new self-service and sessionless routes to the reviewed lists.
  - `AdminApiRuleTests.cs`: the self-service, setup-allowed and recovery-allowed lists.
  - new `RevealOnceRuleTests.cs`.
  - `AuditCatalogueTests.cs`, through the regenerated catalogue.
- `tests/Isolation/`:
  - `Admins/`: new `FreshAssertionTests.cs`, `CredentialManagementTests.cs` and `AdminRecoveryCodeTests.cs`; updated `CredentialRegistrationTests.cs`, `AdminSignInTests.cs`, `RequestChecksTests.cs`, `AdminTablesTests.cs`, `Fido2AdapterTests.cs` and `AdminHost.cs` (the HMAC responder);
  - `Hosting/FakeOpenBaoSocket.cs`, if a helper is needed;
  - `Canary/CanaryFlows.cs` (the Recovery Code flow).
- `tests/browser/`:
  - new `admin-credentials.spec.ts` and `admin-recovery.spec.ts`;
  - updated `signin.spec.ts` (the link), `credential-setup.spec.ts` (the code choice and the recovery kind) and `admin-shell.spec.ts` (the avatar menu items);
  - `playwright.config.ts`: the two projects, in the default projects' `testIgnore`.
- Docs: `docs/threat-model.md`, `docs/audit-events.md` (generated), `docs/install.md`, `_bmad-output/implementation-artifacts/deferred-work.md`.

## Tasks & Acceptance

**Execution:**
- [x] Kernel and adapter: `SecurityLimits`, `RevealOnce<T>`, `PublicIdType.AdminCredential`, and BE/BS in the port and the Fido2 adapter. `Fido2AdapterTests` covers the flags and a changed BE.
- [x] Migration and registry: `admin_fresh_assertion`, `admin_recovery_code`, the `admin_credential` columns, grants and triggers, and the `recovery` kind. `AdminTablesTests` covers the constraints, the grants, both triggers and that `gk_hosted` has nothing.
- [x] Admins: `AdminAssertions` (shared with sign-in), `AdminFreshAssertions`, `AdminCredentials`, `AdminRecoveryCodes`, the Session kinds and floor, the registration rule changes, and the events.
- [x] Host.Admin:
  - the declaration requirement, the consume step in the checks and `FreshAssertionGate`;
  - the new routes, the registration gate and the maximum;
  - the problem codes and the OpenAPI extension.
  - Then regenerate the contract with `sh deploy/docker/api-contract.sh --write <abs dir>`.
- [x] Architecture tests:
  - the replaced fresh-assertion rule (`Always` → checks, `When…` → handler with the marker, a reviewed list of handler-enforced routes, the 403 `fresh_assertion_required` listed, self actions known);
  - the reviewed route lists;
  - the `RevealOnce` rule;
  - the catalogue, with `docs/audit-events.md` regenerated.
- [x] Isolation tests: every server row of the I/O matrix, with Testcontainers and `SoftwareAuthenticator`, and the canary flow.
- [x] Dashboard:
  - `freshAssertion.ts` and its Node test;
  - Your credentials with both modals, the avatar menu and the toasts;
  - the recovery link and entry page;
  - credential setup's recovery kind and the code choice and display;
  - the catalogue keys.
- [x] Browser tests: `admin-credentials.spec.ts` and `admin-recovery.spec.ts` (every browser row, `watchCsp`, axe in light and dark at 1100 and 768), the updated specs, and the config.
- [x] Docs: threat model (T-11, T-22, G-5, T-51, T-52, the two asset rows, new T-54), `install.md`, and `deferred-work.md`. In `deferred-work.md`, remove or narrow the six taken-in items and add the out-of-scope ones.

**Acceptance Criteria:**
- Given a `FreshAssertion` capability and a last assertion over the §5.2 limit old, when the Admin confirms, then the WebAuthn sheet appears, failure shows in the same modal, and the action isn't performed. Every sensitive confirmation needs its own assertion, bound to its action and target and usable once within 5 minutes.
- Given a request that skips the UI, when it has no fresh assertion bound to its Session, action and target, then the server refuses it with 403 `fresh_assertion_required` before any handler acts. The `Always` capabilities are refused by the request checks, and the `When…` ones by their handler's gate. A route declaring a `When…` capability without its gate fails the build.
- Given Your credentials, when the Admin removes their last credential, then it's refused: no removal ever leaves fewer than two, in code or in the database. Adding a credential needs a fresh assertion and is capped at 10. Adding or removing a credential writes to the Deployment Log, and a removal ends the Admin's other Sessions.
- Given an offline Admin Recovery Code, when it's used, then it leads only to credential setup, is stored as HMAC under the Deployment key and works once.
- Given Admin credential setup, when an Admin chooses an offline Recovery Code, then it is issued once through `RevealOnce` and stored as HMAC under the Deployment key in `admin_recovery_code`.
- Given repeated wrong Admin Recovery Codes, when the limit is passed, then attempts are limited through `admin_attempt`.
- Given every new and changed browser test, when it runs, then no CSP violation occurs and axe finds no violation in light and dark at 1100 and 768px.

## Spec Change Log

- 2026-11-04, Story 1.26 review patches, applied before review closed:
  - BE and BS are NULL for credentials registered before the migration; the first verified assertion records BE, and only a known BE is compared.
  - The Recovery Code issue returns an `issueId`; the confirm sends it and matches only the current unconfirmed code, or answers 409 `recovery_code_superseded` with nothing changed. The page explains a 403 or 409 and starts again.
  - A registration in a recovery Session that brings the Admin back to the floor revokes every other Session of theirs. Retiring the lost credential stays with Story 8.3.
  - Recovery Codes are 16 characters, `XXXX-XXXX-XXXX-XXXX`, 80 bits. Redemptions are also limited Deployment-wide under `admins.recovery_code.deployment`, 50 in 15 minutes, counted before the per-client count and before the code is read; it counts every redemption, not only failed ones.
  - `DELETE /api/v1/deployment/session` is setup-allowed and recovery-allowed, and the setup and recovery cards have Sign out.
  - Assertions lock the Admin row before the credential row, as removal does. Two begins in one Session take turns on its row. 23503 and the P0001 floor and maximum triggers map to the uniform refusals.
  - A fresh-assertion target must be one of the route's own parameters by exact name, and an `Always` or `When…` route with a parameter other than the path Tenant must name its target.
  - `ConsumeAsync` returns the grant's credential row. Removing the credential that confirmed the removal also ends the current Session: 200 `{ sessionEnded: true }` with the cookie cleared, and the page goes to `/signin`.
  - The redeem response's `setupComplete` uses the floor rule the Session read uses.
  - Your credentials: a cancelled second sheet in Add returns to the confirm step; Add is disabled at 10; a removal's 401 after renewal and any other 403 each say so in the modal.

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 25 findings — high 5, medium 11, low 9, false 0, maybe-false 0
- findings:
  - `[high]` `[patch]` Blind: `backup_eligible DEFAULT false` refuses every synced passkey registered before the migration, locking the Owner out — unknown for old rows, learned from the first verified assertion.
  - `[high]` `[patch]` Blind: confirming a Recovery Code confirms whichever code is current, not the one shown — the confirm names the issued code; a stale one is 409.
  - `[high]` `[patch]` Blind: after recovery a thief signing in with the lost device becomes unrestricted when the Admin registers — reaching the floor from recovery revokes every other Session; retiring the lost credential is deferred to 8.3.
  - `[high]` `[patch]` Blind: a 40-bit Recovery Code behind a per-client limit is guessable across many /64s — 80-bit code and a Deployment-wide failed-redeem limit.
  - `[medium]` `[defer]` Blind: rotating the Deployment hmac key voids every Recovery Code — recorded for Epic 9's key rotation.
  - `[medium]` `[patch]` Blind: sign-in and removal lock the Admin and credential rows in opposite orders — one lock order.
  - `[low]` `[patch]` Blind: two concurrent fresh-assertion begins can 500 — the Session row is locked first.
  - `[medium]` `[patch]` Blind: a recovery Session can't sign out — sign-out is setup- and recovery-allowed.
  - `[medium]` `[patch]` Blind: an Always route with an object ID needn't bind its grant to the target — such a declaration is refused.
  - `[medium]` `[defer]` Blind: Tenant-scoped fresh-assertion capabilities have no begin route — Story 1.27 or the first such route.
  - `[low]` `[patch]` Blind: Your credentials gaps (cancelled create, Add at the maximum, 401 and other 403s) — handled.
  - `[high]` `[patch]` Edge: pre-migration synced passkeys locked out — same fix as the Blind row.
  - `[medium]` `[patch]` Edge: removing the credential that confirmed the removal leaves the Session it proved live — the current Session ends too.
  - `[low]` `[defer]` Edge: a recovery Admin at the maximum of 10 can redeem but never register — Story 8.3, where such Admins first exist.
  - `[low]` `[patch]` Edge: recovery Session can't sign out — same fix as the Blind row.
  - `[medium]` `[patch]` Edge: the target check matches route parameters by prefix — matched exactly.
  - `[low]` `[patch]` Edge: the redeem response's `setupComplete` disagrees with the Session read — same floor rule.
  - `[low]` `[patch]` Edge: an FK violation on complete is a 500 — mapped to the refusal.
  - `[medium]` `[patch]` Gap: confirming one action twice in a Session is untested — added.
  - `[medium]` `[patch]` Gap: voiding pending registrations at the floor is untested — added.
  - `[medium]` `[patch]` Gap: removing a credential that made a live grant is untested — added.
  - `[low]` `[patch]` Gap: Your credentials 404, cancelled create and already-registered states are untested — added.
  - `[medium]` `[defer]` Intent: the floor trigger blocks deleting an Admin's credentials on every path — Epic 8's Admin removal must account for it.
  - `[low]` `[patch]` Intent: "grant used once" isn't shown by repeating the same DELETE — added.
  - `[low]` `[reject]` Intent: a cancelled create in Add keeps step 3 only visually — the grant is used by begin, as specified; the page now returns to confirm.

## Design Notes

- **Where the state lives, and why there.** The grant is a row tied to the Session, so nothing new reaches the browser: the `SameSite=Strict` Session cookie and the CSRF token already prove the request, and the row proves the confirmation. It is `UNLOGGED` like `admin_signin_challenge` and `admin_attempt`, because losing it in a crash only costs a touch. Splitting the stages (challenge, then verified) without `UPDATE` keeps every step a single `INSERT` or `DELETE … RETURNING`, so "single use" is a database fact, not a code path. The binding is a hash of the action, Tenant and target, so one table serves Deployment, Tenant and self-service actions, and the target route value is compared as sent, never parsed into a possibly different value.
- **Why a grant is used up before the action.** The checks and the gate commit the delete before the handler runs. A failure afterwards therefore can't leave a grant behind for a second, different attempt within 5 minutes, and AD-30's "a retry of a fresh-assertion Operation needs a new assertion" holds by construction. The cost is a second touch after a 409 or 5xx. The floor and maximum are therefore exposed in the list (`removable`) and checked before the add gate, so the ordinary refusals cost no touch.
- **Checks or handler.** `Always` is pure metadata, so the checks enforce it and no handler can forget. `When…` depends on the target (a Prod Tenant, a lower policy), which only the handler knows (AD-20). The route must carry `EvaluatesFreshAssertion`, its handler calls the one gate, and the OpenAPI document marks it `enforcedBy: handler` on a reviewed list. Registration begin is the first handler-enforced route, because its need depends on the Session being full, so the gate is exercised by a real route in this story. Removal is checks-enforced, which exercises that path. No `Always` capability route exists yet. The capability branch derives the same requirement through the same code and is held to it by the document rule. Its first HTTP test belongs to the first such route's story.
- **Try first, then confirm.** The dashboard sends the action and confirms only on the server's 403. That keeps the server the only decider, exactly as Story 1.25 left capabilities to the server, and it covers the `When…` predicates, which the client can't evaluate. Add is the exception, because its first request would start a registration ceremony, so it confirms first. Its second sheet (the new authenticator) comes from its own button, because some browsers want a fresh user activation for `create` after `get`.
- **The floor is two.** EXPERIENCE says "Removing the last credential is refused", and the story says "never lock myself out". Two covers both, and it is what FR-2 asks of the first Admin. The database triggers make it hold for any future path, including Story 8.4 and Story 1.32, which add enrolments and never delete credentials (FR-5: recovery "doesn't disable WebAuthn"). The maximum of 10 bounds the exclude list and the list page.
- **Ending Sessions on removal.** A removed credential is usually a lost or suspect device. A Session doesn't record which credential started it, so every other Session of the Admin ends, as FR-48 does for Users. The acting Session just proved itself with a remaining credential, so it stays.
- **Recovery Code without decryption.** AD-24 holds a pending User code as ciphertext so a reload can show it again, but Host.Admin's policy encrypts and never decrypts (AD-10). So the Admin code is HMAC-only from the start, unconfirmed until "I've saved this code". A lost reveal is a reissue that voids the old code, which AD-24 already accepts ("A lost reveal means rotating again"). The HMAC is keyed by the Deployment `hmac` key, with domain separation, so the code alone finds its row with one keyed lookup. 40 bits behind 5 attempts per client per 15 minutes is the threat model's T-54 note.
- **A recovery Session is its own kind.** "Leads only to credential setup" has to hold even for an Admin who already meets the floor, for example one who had added a second credential. Kind `recovery` is restricted whatever the counts, reaches only the `RecoveryAllowed` routes, and becomes `full` only through a registration, under the same rule that ends setup.
- **BE/BS.** Storing the flags gives the list its "Synced" badge, so the Admin can see when both credentials are copies in one passkey provider (T-51's residual risk). Refusing a changed BE follows WebAuthn, which defines BE as fixed for a credential.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests`. Expected:
  - the build has no warnings;
  - the `@gatekeep/ui` checks pass (raw hex, dependencies, screens props-only);
  - the dashboard Node tests pass (`renewal.test.mjs`, `freshAssertion.test.mjs`);
  - the api-client tests and the API contract drift check pass against the regenerated files;
  - the Architecture tests pass, including the replaced fresh-assertion rule, `RevealOnceRuleTests` and the audit catalogue;
  - the Isolation tests pass: `FreshAssertionTests`, `CredentialManagementTests`, `AdminRecoveryCodeTests`, the updated Admin tests and the canary scan;
  - the browser tests pass, including `admin-credentials`, `admin-recovery`, the updated `signin`, `credential-setup` and `admin-shell`, and `admin-csp`.

  From a worktree, use a worktree-only image tag, not `gatekeep/tests:local`.
- After changing the endpoints, regenerate the contract in Docker with `sh deploy/docker/api-contract.sh --write <abs dir>` (as `docker compose -f deploy/compose.test.yaml run --rm --build -v "<repository>:/out" tests sh deploy/docker/api-contract.sh --write /out`), and the audit catalogue with the Generator. Commit both.

Nothing runs on the host.

## Auto Run Result

Status: done

**Summary:** sensitive Admin actions need a fresh WebAuthn assertion: a server-side grant bound to one Session and one action, used once within 5 minutes, enforced by the request checks or a handler gate, so a request that skips the UI is refused. Your credentials lists an Admin's own credentials with their synced flag, and adds or removes them behind a fresh assertion. The floor of two and the maximum of ten hold in code and in the database, and a removal ends the Admin's other Sessions and writes to the Deployment Log. An Admin who isn't the Owner may take one offline Recovery Code at setup, issued once through `RevealOnce`, stored as an HMAC under the Deployment key, rate-limited per client and Deployment-wide, and leading only to credential setup.

**Files:** `src/Gatekeep.Kernel/Secrets/RevealOnce.cs`; the Story 1.26 migration and `TableRegistry`; `src/Modules/Admins/` (fresh assertions, credentials, Recovery Codes, sessions, sign-in); `src/Adapters/Fido2/`; `src/Gatekeep.Host.Admin/` (fresh assertion API and gate, credentials and Recovery Code APIs, request checks, OpenAPI); `docs/api/openapi-v1.json`, `packages/api-client/`; `apps/admin-dashboard/src/` (Your credentials, Recovery Code pages, setup, sign-in); `tests/Isolation/Admins/`, `tests/Architecture/`, `tests/browser/admin-credentials.spec.ts`, `admin-recovery.spec.ts`; `docs/audit-events.md`, the threat model and `install.md`.

**Review:** 25 findings across four layers: 20 patched, 4 deferred, 1 rejected, each with its reason in the triage log.

**Follow-up review:** recommended. The Recovery Code strength and binding, recovery eviction and the pre-migration backup flags changed in review, with new tests as the only proof.

**Verification:** see the PR screenshot; the full suite passes in the `tests` container.

**Residual risks:** rotating the hmac key voids Recovery Codes until Epic 9 handles it. Tenant fresh assertions have no begin route yet. Recovery can't retire a lost credential until Story 8.3, so the Admin adds a third and removes it.
