---
title: 'Story 9.2: Rotate a Signing Key on demand'
type: 'feature'
created: '2026-11-14'
status: 'done'
baseline_revision: 'b805adb24e715c98f099ab569a56109604910e1a'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-9-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-9-1-view-signing-keys.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-2-4-rotate-signing-keys-automatically.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** FR-37 needs a Tenant Owner to be able to rotate the Tenant's Signing Key now, not just wait for the daily age-gated rotation (Story 2.4). Today:
- the Signing keys page (Story 9.1) is read-only;
- `gk_admin` may only SELECT `signing_key`;
- `KeysContract.RotateTenantKeysAsync` only rotates keys that are due by age, covers both purposes and retirement, and writes `Actor.System`.

**Approach:**
- One Owner-only route, `POST /api/v1/tenants/{tenantId}/signing-keys/rotate`, on Host.Admin.
- In one Tenant command, it promotes the signing `next` (once published for at least 15 minutes) to `current`, moves `current` to `previous`, and creates a replacement `next`. Transit comes first, then the rows, then three Log events with the Admin as actor, then the NOTIFY.
- A younger `next` gives 409 with the seconds remaining.
- The page gains a Rotate action, read-only for Editors as "Tenant Owner only".

## Boundaries & Constraints

**Always:**
- **Keys contract:** new `[StateChanging] KeysContract.RotateSigningKeyNowAsync(CommandContext, IKeyCustody, IAuditAppender, Actor actor, Guid tenantId, CancellationToken)`, implemented in `SigningKeyLifecycle`. It returns a public `SigningKeyRotation(SigningKeyRotationStatus Status, TimeSpan? RetryAfter)`, where Status is `Rotated` or `NotReady`. Its steps:
  - **Checks:** it requires the Tenant context (`TenantKeys.RequireTenant`) and takes `TenantKeys.Lock` first, so it is serialized with the daily rotation and the backfill.
  - **Scope:** `purpose = 'signing'` only. Management keys are untouched: they are never published and are not on this page.
  - **Readiness:** reads the signing `current` and `next`, plus `next`'s readiness from database time: `published_at <= now() - SigningKeyPublicationBeforePromotion`.
    - If not ready, it returns `NotReady` with `RetryAfter` = `published_at + 15 min - now()` from the database, never below 1 s, and writes nothing.
    - A missing `current` or `next` breaks the AD-11 invariant and throws `InvalidOperationException`.
  - **When ready:**
    - `custody.CreateKeyAsync(KeyName.Signing(tenantId, newId))` first, then the existing `Rotate`, `Promote` and `InsertKey` SQL in that order;
    - then `KeysEvents.SigningKeyRotated`, `SigningKeyPromoted` and `SigningKeyCreated`, appended with the given `actor`;
    - then `pg_notify` on `SigningKeyLifecycle.Channel`.
  - Reuse the existing SQL constants and helpers; don't copy them. Thread an `Actor` through the private `AppendAsync`. The daily path keeps passing `Actor.System` and doesn't change its behaviour.
  - It never age-gates `current` (that is the daily rule) and does no retirement or destruction work.
- **Events:**
  - `KeysEvents.SigningKeyRotated`'s summary no longer says "reached its rotation age". It covers both triggers, e.g. "A Signing Key was rotated: current became previous."
  - `rotated`, `promoted` and `created` get `TenantLogClass.KeyOperation`.
  - `tests/Architecture/Generator/AuditCatalogue.cs:58` drops the pending "9.2" and adds a `Proofs` entry naming the new tests.
  - Regenerate `docs/audit-events.md` and `LogCatalogue.Generated.cs` with `dotnet run --project tests/Architecture/Generator`, in Docker.
  - Update comments that say these events always have a system Actor.
- **Schema:**
  - New migration `Migration20261117000000RotateSigningKeysOnDemand` (`20261117000000_RotateSigningKeysOnDemand`) runs:
    - `GRANT INSERT ON signing_key TO gk_admin`
    - `GRANT UPDATE (state, promoted_at, rotated_at) ON signing_key TO gk_admin`
  - `TableRegistry`'s `signing_key` entry gains `[Admin] = [Select, Insert]` and a `ColumnGrant(Update, [state, promoted_at, rotated_at])` for Admin, with its comment revised to name Story 9.2.
  - `MigrateCommandTests` expects 33.
  - Admin gets no DELETE, and no UPDATE of `retired_at`, `destroyed_at` or any identity column. The existing `signing_key_guard_update` trigger keeps the allowed transitions.
- **Capability:** `AdminCapabilities.TenantSigningKeysRotate` becomes `machineAllowed: false`, still Owners and `FreshAssertion.Never`. Update `CapabilityMatrixTests`, the OpenAPI `x-gatekeep-access`, and any test that pins it, to match.
- **Management:** `ISigningKeyManagement.RotateAsync(CommandContext, IKeyCustody?, AdminPrincipal, TenantRoleGrant?, Guid tenantId, CancellationToken)` returns `SigningKeyRotateResult(Status, RetryAfter)`. Status is one of `Rotated`, `Forbidden`, `NotReady` or `Unavailable`.
  - The AD-5 re-check uses `AdminCapabilities.Allows(TenantSigningKeysRotate, …)`.
  - Null custody, or a `KeyCustodyException`, gives `Unavailable`.
  - The actor is `Actor.Admin(principal.AdminId)`.
- **Route (`AdminApi.cs`, with a handler in `SigningKeysApi.cs`):** `MapPost` with `TenantApiEndpoint.Instance` and `RequiresCapability(TenantSigningKeysRotate)`, and no body. It follows `TenantLabelApi.SetAsync`: TenantScope, commit with `CancellationToken.None` only when `Rotated`, `DbException` → the fixed 503, and `Cache-Control: no-store`. Answers:
  - 200 with the refreshed `SigningKeysResponse`, read in the same scope after the change;
  - 401;
  - 403 `access_denied`;
  - 409 `tenant_mismatch` (existing);
  - 409 `signing_key_not_ready`, with a new nullable `ApiProblem.RetryAfterSeconds`, a whole number rounded up and serialized only when set, plus a `Retry-After` header with the same value;
  - 503 for custody or the database.
  - `signing_key_not_ready` is added to `AdminResponses.ProblemCodes`.
  - Extend the 409 comment in `AdminApiRuleTests`.
  - Register the route in `tests/Isolation/CrossTenant/RouteRegistry.cs` (`TenantPath`) and in `tests/Isolation/Canary/CanaryFlows.cs` beside the other Signing keys routes.
- **Generated artifacts:**
  - Regenerate `docs/api/openapi-v1.json` and `schema.generated.ts` in Docker with `deploy/docker/api-contract.sh --write`.
  - `client.ts` gains `rotateSigningKeys(tenantId)`, a POST with the ID encoded and the CSRF and Tenant headers.
  - `client.test.mjs` covers it.
- **Dashboard (`SigningKeysPage.tsx`; every string in `packages/ui/src/messages.tsx`; no inline style or script; no new dependency):**
  - **Rotate button:** a "Rotate now" action in the `SectionPage` actions.
    - With `has('tenant.signing_keys.rotate')` it is enabled.
    - Otherwise follow the existing role pattern in `ApplicationCredentials.tsx:234-272` (Editor: `aria-disabled` plus `aria-describedby` to a "Tenant Owner only" note) and in `TenantSettingsPage.tsx` (how a Viewer is told apart and given the view-only `banner` with no action button). Reuse whichever mechanism those pages use; add no new capability.
  - **While running:** it is busy and guarded by an `inFlight` ref.
  - **Success:**
    - the table is replaced with the response's list and the JWKS sample is read again;
    - a `toast` says "Signing key rotated.".
  - **`signing_key_not_ready`:** a `Banner` (tone `warn`) reads "The next key was published less than 15 minutes ago. Try again in {n} min." Here n = ceil(retryAfterSeconds / 60), and it carries `ErrorReference`.
  - **Other failures:** a `Banner` (tone `bad`) with `ErrorReference` (trace ID). 401, 409 `tenant_mismatch` and 403 are handled as `ApplicationCredentials.tsx` handles them.
  - Remove the "arrives with 9.2" comment at `SigningKeysPage.tsx:58`.
- **Docs:**
  - `docs/threat-model.md`: the status paragraph adds Story 9.2, gk_admin's INSERT and column UPDATE on `signing_key`, and the test names. TB-6 / T-45 note that Host.Admin now creates Signing Keys on demand (its policy already allowed it).
  - `docs/install.md:372`: rotating is available; revoking arrives with 9.3.

**Ask First:**
- **Machine principals:** flipping `TenantSigningKeysRotate` to not machine-allowed follows this story's AC ("Given an Editor or machine principal … refused") over spec-1-24's table. Confirm before keeping it machine-allowed.
- **Copy `[ASSUMPTION]`:** "Rotate now", "Signing key rotated.", and the not-ready text.

**Never:**
- No change to `host-admin.hcl`: it already permits creating `sig-*`.
- No rotation of Management keys.
- No retirement, destruction or job enqueue on this path.
- No fresh-assertion requirement.
- No confirmation modal; that comes with Revoke (9.3).
- No query spanning Tenants.
- No key material or ciphertext in any response or log.
- Revoke and its modal stay out of scope (9.3).

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Owner, aged next | A: current C, next N with `published_at` 20 min ago | 200: N current, C previous, new next N2 with a Transit key created; 3 events with the Admin actor and KeyOperation class; NOTIFY on commit; list in response | — |
| Owner, young next | N published 5 min ago | 409 `signing_key_not_ready`, `retryAfterSeconds` about 600 (580 to 600), `Retry-After` the same; rows, Transit and Log unchanged | — |
| Already previous | A also has an older `previous` P | Succeeds; P stays `previous` (two previous rows) | — |
| Editor / Viewer | Editor or Viewer of A | 403 `access_denied`; nothing changed | — |
| Other Tenant | Owner of B posts to A | 403; A and B unchanged | — |
| B untouched | Owner rotates A | B's `signing_key` rows byte-identical | — |
| Custody fails | Fake OpenBao refuses the create | 503; A's rows and Log unchanged | — |
| Concurrent | Two rotate requests in parallel on an aged A | One 200; the other 200 or 409 not-ready (its `next` is brand new); never two `current` | — |
| Browser: Owner | Mocked 200 | Rotate visible; click → toast, table shows new states, JWKS re-requested | — |
| Browser: not ready | Mocked 409 with 600 s | Warn banner "Try again in 10 min." with reference | — |
| Browser: Editor / Viewer | Capabilities without rotate | Editor: aria-disabled plus "Tenant Owner only"; Viewer: no button, view-only banner | — |
| Browser: failure | Mocked 503 with trace ID | Bad banner with reference; table unchanged | — |
| CSP and axe | States above, both themes, 1100 and 768 | No violations; `watchCsp` clean | Test fails |

</intent-contract>

## Code Map

- `src/Modules/Keys/Core/SigningKeyLifecycle.cs`:
  - `:38-52`: `SelectOpen`, `Rotate` and `Promote` SQL;
  - `:84-239`: `RotateAsync`, the pattern to follow (lock, Transit first, ordered updates, insert, events, notify);
  - `:394`: the private `AppendAsync` that hardcodes `Actor.System`.
- `src/Modules/Keys/Core/TenantKeys.cs`: `Lock` (:19), `InsertKey` (:31), `LockNamespace` (:62), `Add`/`RequireTenant` (:262-291).
- `src/Modules/Keys/Contracts/KeysContract.cs:130-138`: `RotateTenantKeysAsync`; the new method goes beside it. `SigningKeys.cs` holds the public Keys types (add `SigningKeyRotation` and its status here). `KeysEvents.cs` holds the event definitions.
- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs:159`: `SigningKeyPublicationBeforePromotion`. `src/Gatekeep.Kernel/Audit/Actor.cs:29`: `Actor.Admin`.
- Migrations:
  - `src/Adapters/Postgres/Migrations/Migration20261105010000RotateSigningKeys.cs:60-98`: the update guard trigger and gk_worker's column grant.
  - `Migration20261108090000ViewSigningKeys.cs`: the pattern for a grant-only migration.
  - The newest migration is `Migration20261116000000SetTokenLifetimes`.
- `src/Adapters/Postgres/Schema/TableRegistry.cs:555-575` (`signing_key`, with `ColumnGrant` at :26). It is checked by `tests/Isolation/CatalogueTests.cs` and `CatalogueAudit.cs:155-162`.
- `src/Modules/Admins/Contracts/AdminCapabilities.cs:170`: `TenantSigningKeysRotate`. `tests/Isolation/Admins/CapabilityMatrixTests.cs` and `tests/Architecture/CapabilityRuleTests.cs:120` pin it.
- `src/Modules/Management/Core/SigningKeyManagement.cs` and `Contracts/ISigningKeyManagement`: add `RotateAsync`. Re-check pattern: `TenantManagement.ChangeLabelAsync` (`TenantManagement.cs:260-325`).
- `src/Gatekeep.Host.Admin/`:
  - `AdminApi.cs:783-857`: the secret-rotate and label-set routes;
  - `SigningKeysApi.cs:114`: how custody is fetched;
  - `TenantLabelApi.cs`: the handler shape;
  - `AdminResponses.cs:7-21,199-227,324-328`: `ApiProblem`, `ProblemCodes` and the `Retry-After` precedent;
  - `RecoveryCodeApi.cs:50-53,229`: custody null or failure handling and logging.
- Tests:
  - `tests/Architecture/AdminApiRuleTests.cs:211-216` (409 comment), `tests/Architecture/Generator/AuditCatalogue.cs:58-76`, `tests/Isolation/Audit/EventClassTests.cs`, `tests/Isolation/MigrateCommandTests.cs:20,28`;
  - `tests/Isolation/CrossTenant/RouteRegistry.cs:90-106`, `tests/Isolation/Canary/CanaryFlows.cs:382-388`;
  - to model on: `tests/Isolation/Keys/SigningKeysApiTests.cs` (`AdminHost`, `RoleSessionAsync`, `host.OpenBao.RespondToBody`, `PublicHalves` :278), `SigningKeyListTests.cs:16-94` (`SigningKeySeeds`), and `SigningKeyRotationTests.cs` (`BackdateAsync`, the rollback test :381, the interleaving test :422).
- Dashboard:
  - `apps/admin-dashboard/src/shell/SigningKeysPage.tsx` and `capabilities.ts` (`useCapabilities().has`);
  - `ApplicationCredentials.tsx:107-157,234-293` (action, owner-only and banner patterns) and `TenantSettingsPage.tsx:150-215,297`;
  - `packages/ui/src/messages.tsx:371,821` (`tenantOwnerOnly`).
- `packages/api-client/src/client.ts:177-200,319-325,380-384` and `test/client.test.mjs:242,453-475`.
- `tests/browser/admin-signing-keys.spec.ts`: `answerApi` (:54-80), `TENANT_VIEWER` (:22), and the no-Rotate assertion at :155 that must change. Its project is at `playwright.config.ts:153-157`.

## Tasks & Acceptance

**Execution:**
- [x] `src/Modules/Keys/{Contracts,Core}`: add `SigningKeyRotation`, `RotateSigningKeyNowAsync` and the `Actor` threading. Revise the `KeysEvents` summary and classes. Add new `tests/Isolation/Keys/SigningKeyRotateNowTests.cs`: aged, young (`RetryAfter` range), existing previous, Transit failure rolls back, management untouched, other Tenant untouched, concurrent calls, Admin actor on events.
- [x] Add the migration and the `TableRegistry` change. Bump `MigrateCommandTests` to 33. Add a grants assertion (`gk_admin` can't DELETE `signing_key` or update `retired_at`/`destroyed_at`) beside `TenantKeysTests`' grant checks.
- [x] `AdminCapabilities`: rotate not machine-allowed, with the pinning tests updated.
- [x] Management: add `RotateAsync`, plus a Forbidden re-check test.
- [x] Host.Admin:
  - add the route, the handler, `ApiProblem.RetryAfterSeconds`, the problem code, and the `Retry-After` header;
  - add new `tests/Isolation/Keys/SigningKeyRotateApiTests.cs` covering every API row of the matrix;
  - add the RouteRegistry, CanaryFlows and AdminApiRuleTests entries.
- [x] Audit catalogue: update the generator entry, then regenerate the docs and code in Docker.
- [x] Regenerate OpenAPI and the schema. Add the client method and its test.
- [x] Dashboard: add the Rotate action, the messages, and the owner-only and view-only states. Extend `admin-signing-keys.spec.ts` with every browser row.
- [x] Docs: update the threat model and install.md.

**Acceptance Criteria:**
- Given a `next` key aged at least 15 minutes, when the Owner rotates, then it's promoted and a replacement `next` is created in one command, and a Log event is written.
- Given a younger `next` key, when rotation is requested, then it's refused with the time remaining.
- Given an Editor or machine principal, when it attempts rotation, then it's refused.
- Given the full suite in CI, when it runs, then every test passes, including the existing Architecture, Isolation and browser tests.

## Spec Change Log

- 2026-11-14, implementation:
  - **`rotated` summary.** The event still covers the daily rotation's Management keys, so it reads "A Tenant's Signing or Management key was rotated, by the daily rotation or a Tenant Owner: current became previous. Names no key." rather than the example's "A Signing Key was rotated…".
  - **Readiness time.** `SelectOpen` gives the gate, as the spec says. The seconds left come from one more read of `next`'s `published_at + 15 min - now()`, by database time, made only when it isn't ready.
  - **Shared custody stand-in.** `SigningKeysApiTests`' private `PublicHalves` moved to `tests/Isolation/Keys/PublicHalves.cs`. It also answers creates now, recording them or refusing them with 503, so `SigningKeyRotateApiTests` and the `EventClassTests` proof can share it.
  - **KeyOperation proof.** `EventClassTests.Proofs` proves the class over HTTP on the real Host.Admin: an Owner's rotation writes the three codes to the Tenant's Log.
  - **Existing tests changed by the new grants.** `TenantTablesTests.Admin_only_reads_signing_keys_and_only_its_scopes_Tenants` is now `Admin_reads_inserts_and_rotates_signing_keys_only_in_its_scopes_Tenant`. `CapabilityMatrixTests`' FR-42 rule lists rotate as its one reviewed exception. `CapabilityRuleTests` pins the route's `x-gatekeep-access`.
  - **The 9.1 browser test.** The Viewer row now expects the view-only banner.

## Review Triage Log

### 2026-11-14: Review pass

- verdicts: 27 findings. High 0, medium 0, low 19, false 8, maybe-false 0.
- findings:
  - `[low]` `[reject]` Blind: `gk_admin` INSERT on the whole table with no insert guard.
    - Refuted in part: the `signing_key_transit_name` CHECK ties `transit_name` to the row's own Tenant and ID, so no other Tenant's key or `mgmt-` name can be inserted as `signing`.
    - What's left (any state, backdated `published_at`) needs SQL as `gk_admin`, which `gk_worker` already has in the same way.
    - A column list wouldn't help, because `InsertKey` itself writes `created_at`, `published_at` and `promoted_at`. The fix would be a new trigger.
  - `[low]` `[patch]` Blind: Rotated, then a list read other than `Read`, falls to `default` and answers 403. It's unreachable for an Owner, but it is the wrong answer. Fixed: that case is now 503.
  - `[false]` `[reject]` Blind: a NULL `published_at` gives a never-true "retry in 1 s". The `signing_key_signing_published` CHECK makes `published_at` NOT NULL for every signing row.
  - `[low]` `[reject]` Blind: on-demand rotations can pile up `previous` keys, about 96 a day. Owner-only, and each one is held 15 minutes by the gate. Every `previous` key retires after 1 h 15 min once the daily job runs. A cap would add a new refusal and new surface for a case nobody meets in normal use.
  - `[false]` `[reject]` Blind: the daily clock doesn't reset after an on-demand rotation. That's intended: due-ness counts from the key's own `created_at`, and `SigningKeyMaxAge` limits every key's lifetime. An early daily rotation can only follow a `next` that was already old.
  - `[low]` `[reject]` Blind: no fresh assertion and no confirmation. Story 1.24's capability table sets rotate to `FreshAssertion.Never`, and the epic's UX puts the confirmation modal on Revoke (9.3) only. Rotation retires nothing and invalidates no token.
  - `[low]` `[reject]` Blind: switching Tenant while a rotate is in flight. The page is keyed by `tenantId`, so a remount clears `refusal`; the only leak is a toast that is still true. Switching in the second the POST takes is rare, and the fix adds a guard.
  - `[false]` `[reject]` Blind: an Owner with rotate but no `*.manage` would see no action. Owners always hold `tenant.label.manage` (`AdminCapabilities.cs:167`), so `canRotate` implies `!viewOnly`.
  - `[low]` `[reject]` Blind: HTTP gaps (machine principal, a Deployment Owner without a Role, CSRF, the broken invariant).
    - No request path can bring a machine principal into Host.Admin before Epic 17, and the flag is pinned by `CapabilityRuleTests` and `CapabilityMatrixTests`.
    - A Deployment Owner without a Role is covered at the module level.
    - CSRF and Origin are the shared request checks, which their own tests cover for every state-changing route.
  - `[low]` `[patch]` Blind: the TB-6 cell runs the 9.2 sentence into the backtick list. Fixed with punctuation.
  - `[low]` `[patch]` Blind: the `SigningKeyManagementTests` comment gives the assertions in the wrong order. Fixed: the comment is reordered.
  - `[low]` `[reject]` Blind: no countdown or disabled state after not-ready. The banner already gives the minutes; a timer adds state for little gain.
  - `[low]` `[reject]` Blind: the loading `aria-disabled` has no description. The state lasts a moment, and axe passes on every state.
  - `[false]` `[reject]` Blind: not-ready isn't audited. Audit records state changes and capability denials. A not-ready refusal is neither, and writes nothing, like `client_secret_limit_reached`.
  - `[low]` `[patch]` Verification gap: no browser test for the refusals the shell handles (409 `tenant_mismatch`, 401). Fixed: a test modelled on `admin-applications.spec.ts:583` asserts that none of the page's banners or toast appear. The 401 variant was left out: it needs the WebAuthn renewal harness, which this spec's mocks don't have, and the renewal is the shell's and tested in its own specs.
  - `[low]` `[patch]` Verification gap (other): Rotated plus a list read other than `Read` gives 403. Grouped with Blind #2.
  - `[low]` `[patch]` Verification gap (other): the comment order. Grouped with Blind #11.
  - `[low]` `[reject]` Edge: no cap on `previous` rows. Grouped with Blind #4.
  - `[false]` `[reject]` Edge: no `current` or `next` gives an unhandled 500. AD-11 guarantees both at every commit, so this is a broken invariant, and failing loudly is correct; the spec asks for the throw.
  - `[false]` `[reject]` Edge: an empty version list from custody gives a 500 and an orphan. This is the existing guard moved unchanged from `RotateAsync`. Transit always returns the created version, and the orphan sweep removes an unowned key.
  - `[low]` `[reject]` Edge: a client abort after the Transit create rolls the rotation back. The outcome is safe: no rows change, and the orphan sweep takes the Transit key. The comment refers to the list read and commit, which do use `CancellationToken.None`.
  - `[low]` `[patch]` Edge: Rotated plus a list read other than `Read` gives 403. Grouped with Blind #2.
  - `[low]` `[reject]` Edge: the page unmounts mid-rotation and the toast appears elsewhere. Grouped with Blind #7.
  - `[low]` `[reject]` Intent: machine principal refusal is shown by declaration only. No machine principal can reach Host.Admin before Epic 17; the capability, OpenAPI and matrix tests pin the refusal.
  - `[false]` `[reject]` Intent: three events, where the intent says "a Log event". "A Log event is written" holds, and the three codes match the daily rotation's record of the same change.
  - `[low]` `[reject]` Intent: the time remaining in the UI is checked only against mocked APIs. That is the repository's convention: browser specs intercept the API, and Isolation proves the 580 to 600 s against real Postgres.
  - `[false]` `[reject]` Intent: reclassifying KeyOperation also changes the daily rotation's events. Intended: both paths write the same key operation, and the Tenant Log should show both.

## Design Notes

**Why a new contract method:** `RotateTenantKeysAsync` is the daily sweep. It is gated on `current`'s age, handles both purposes, retires, and re-queues destruction, which needs SELECT on `job`, a grant `gk_admin` doesn't have. The on-demand method shares the SQL and the Transit-first order, but its only gate is `next`'s publication age, which keeps the 15-minute JWKS cache promise.

**Why the readiness time comes from the database:** `SelectOpen` already reads it from the database, so the API's "seconds remaining" and the actual gate can't disagree with the host clock.

## Verification

**Commands:**
- Don't run the suite locally (CI is the source of truth). Generated files only: the audit catalogue generator, and `sh deploy/docker/api-contract.sh --write` in Docker.
- Push and open a draft PR; CI's build, Isolation, Architecture and browser jobs must be green.

## Auto Run Result

Status: done

- **Implemented:** a Tenant Owner can rotate the Signing Key on demand.
  - **Server:** `KeysContract.RotateSigningKeyNowAsync` covers the signing purpose only. It takes the per-Tenant lock and gates on `next`'s publication age by database time. It creates the Transit key first, then makes the Rotate and Promote changes and inserts the new `next`. It writes three events with the Admin as Actor, classed KeyOperation, and sends the NOTIFY at commit.
  - **Route:** `POST /api/v1/tenants/{tenantId}/signing-keys/rotate` answers 200 with the refreshed list, 409 `signing_key_not_ready` with `retryAfterSeconds` and `Retry-After`, 403, or 503.
  - **Grants and permission:** a migration gives `gk_admin` INSERT plus UPDATE on (state, promoted_at, rotated_at). The rotate permission is no longer machine-allowed.
  - **Page:** a "Rotate now" action with owner-only, view-only, not-ready and failure states.
- **Files changed:**
  - Keys contract and lifecycle;
  - the migration and the `TableRegistry` entry;
  - `AdminCapabilities`;
  - Management `ISigningKeyManagement` and `SigningKeyManagement`;
  - Host.Admin: `AdminApi`, `SigningKeysApi` and `AdminResponses`;
  - api-client, the `SigningKeysPage` and its messages;
  - the regenerated OpenAPI, schema and audit catalogue;
  - the threat model and install.md;
  - new Isolation tests (`SigningKeyRotateNowTests`, `SigningKeyRotateApiTests`, `PublicHalves`), and updates to the matrix, rule, catalogue, grants, route registry, canary and browser tests.
- **Review:**
  - 27 findings: 7 patch rows (low) grouped into 4 fixes, 0 deferred.
  - The rest were rejected; the reasons are in the triage log.
  - Patched by verdict: high 0, medium 0, low 4 entries.
  - Follow-up review recommended: false.
- **Verification:** CI on PR #61 is the test run.
  - **First run:** 633 of 634 browser tests passed. The Editor test clicked an `aria-disabled` button without `force` and timed out. Fixed as the other specs do.
  - **Second run:** Architecture passed 763/763 and Isolation 3425/3426. `CapabilityMatrixTests.Machine_principal_at_handler_level_…` still pinned 18 machine-allowed Tenant capabilities; it is now 17 and asserts that rotate is refused to a machine principal at the authorizer. That test is the live machine-principal check for AC3.
- **Matrix audit:**
  - Every API and domain row is covered in `SigningKeyRotateApiTests` and `SigningKeyRotateNowTests`.
  - Every browser row is covered in `admin-signing-keys.spec.ts`: Owner, not ready, Editor and Viewer, failure, and axe in both themes at both widths.
  - The final green CI run is the one that runs them.
- **Residual risks:**
  - On-demand rotations aren't capped beyond the 15-minute gate. Up to about 96 `previous` keys a day could stay published until the daily retirement.
  - `gk_admin`'s INSERT isn't guarded by a trigger. The transit-name CHECK still keeps it to the Tenant's own keys.
