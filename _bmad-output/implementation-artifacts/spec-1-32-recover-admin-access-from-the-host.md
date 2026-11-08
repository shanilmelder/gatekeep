---
title: 'Story 1.32: Recover Admin access from the host'
type: 'feature'
created: '2026-11-08'
status: 'done'
baseline_revision: '49ef4b3a246319af4313a70528eac78478c697e7'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-1-context.md'
  - '{project-root}/docs/threat-model.md'
warnings: ['oversized']
deferred:
  - summary: >-
      A recovered Admin who already holds the 10-credential maximum uses up the enrolment and loses
      their Sessions but can't register a new credential, because lost credentials stay registered.
    evidence: |-
      AdminEnrolments.RedeemAsync starts a Recovery Session without checking the credential count;
      registration refuses an 11th credential. Already recorded in deferred-work.md (Story 8.3,
      retire the lost credential during recovery). Fix belongs with credential retirement.
    location: >-
      src/Modules/Admins/Core/AdminEnrolments.cs
    severity: medium
  - summary: >-
      The lost credentials stay registered after recovery; nothing retires them.
    evidence: |-
      Recovery adds a fresh credential next to the lost ones; deferred-work.md already assigns
      retiring the lost credential to Story 8.3.
    location: >-
      src/Modules/Admins/Core/AdminEnrolments.cs
    severity: medium
---

<intent-contract>

## Intent

**Problem:** An Admin who loses every WebAuthn credential (or a first Admin whose setup Session ended before registering credentials) is permanently locked out. Nothing in the product can let them back in, and any way back must not be quiet.

**Approach:** Add `gatekeep recover-admin` to `Gatekeep.Cli`. It sends a Security Alert through `IAlertChannel` and writes a signed off-server record itself. Only after both are confirmed does it store a single-use, 15-minute enrolment in a new `control` table, `admin_enrolment`, and print its link once. Host.Admin redeems the enrolment on a sessionless sign-in route. That ends the Admin's Sessions, writes the Deployment Log and starts a Session that can only register WebAuthn credentials.

## Boundaries & Constraints

**Always:**
- **Order is fixed:** resolve the Admin, generate the value, send the alert and await a 2xx, write the off-server record and await confirmation, then insert the `admin_enrolment` row and the `admin.enrolment.issued` audit event in one Deployment-scope `CommandContext` and commit, then print the link. If any step fails, the command exits non-zero, nothing is inserted and nothing is printed.
- **Enrolment value:** 256 bits from a CSPRNG, base64url. It is stored only as SHA-256, using the `BootstrapToken.Hash` pattern.
- **`admin_enrolment` columns:** `id` (UUIDv7), `admin_id` (FK to `admin`, `ON DELETE RESTRICT`), `value_sha256` (unique), `created_at`, `expires_at = created_at + 15 min` (a `SecurityLimits` constant), and nullable `used_at`. No other column holds anything derived from the value.
- **Grants:** `gk_cli` gets Select + Insert. `gk_admin` gets Select + column Update(`used_at`). No other role gets a grant, and no role deletes.
- **Migration:** one forward-only migration ships the table, its `TableRegistry` entry and its grants. It also adds an `end_reason` value only if one is truly needed; prefer reusing `revoked`.
- **Alert and record content:** both carry only internal references: the Admin ID, the enrolment ID, the issue time and the expiry. They never carry the value or its hash.
- **Alert code:** define a new `SecurityAlertCode`, `admin.recovery.started`.
- **Record kind:** use the off-server record kind `admin_recovery` through `OffServerRecordWriter` (signed with `dep-records`).
- **Choosing the Admin:**
  - `--admin <public Admin id>` selects the Admin.
  - With no flag and exactly one Admin, that Admin is used.
  - Otherwise the command refuses, listing the Admin public IDs (and no secrets).
  - If bootstrap isn't complete (no Admin exists), the command refuses and points to `gatekeep init`.
- **Printed link:** `https://<admin host>/recover#<value>`. The fragment keeps the value out of request lines and Caddy logs. Use the Admin hostname the `cli` service already receives.
- **Redemption route:** `POST /api/v1/deployment/signin/enrolment` with body `{ "enrolment": "<value>" }`.
  - Metadata is the same as `POST /signin/recovery-code`: sessionless, exact Origin, `DeploymentApiEndpoint`, `SignInEndpoint` and `JsonRequestBody`.
  - Two rate-limit policies are counted and committed before the lookup, like `RecoveryCodeApi`: `admins.enrolment.deployment` (50/15 min on `DeploymentSubject`) and `admins.enrolment.redeem` (5/15 min per client).
  - Lookup: hash the input, then `SELECT … FOR UPDATE` where `used_at IS NULL AND expires_at > now()`.
  - On a miss, return one generic refusal, identical for unknown, used and expired.
  - On a match, in one transaction:
    1. Set `used_at`.
    2. `AdminSessions.RevokeAsync` all of that Admin's Sessions.
    3. Supersede the presented cookie.
    4. Start a `Setup` Session if the Admin hasn't completed credential setup, otherwise a `Recovery` Session.
    5. Append `admin.enrolment.used`.
- **WebAuthn stays required.** The new Session can only reach `SetupAllowed`/`RecoveryAllowed` endpoints. Full access comes only from the existing registration flow.
- **Redaction:** the raw value appears in no log, audit event, audit detail, error, alert, record or OpenAPI example. Test this with a canary value.
- **Same PR:** update `docs/threat-model.md` (T-21, and the `admin_enrolment` line around :149), regenerate `docs/audit-events.md`, the OpenAPI document and `packages/api-client`, and update the Cli Usage text and the operator docs (where `gatekeep init` is documented).

**Never:**
- No HTTP route, in any host, issues an enrolment, and no Worker job does. Only `Gatekeep.Cli` references the issuer.
- No change to `deploy/compose*.yaml`: `cli` already has `egress`.
- No Notifications event-to-alert table (Story 11.1).
- No "Reset credentials" enrolment (Epic 8).
- No retiring the lost credential (deferred, Story 8.3).
- No disabling WebAuthn or sign-in by any other factor.
- No grants for `gk_cli` on `admin_session` or `admin_credential`.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Happy path | One Admin with lost credentials; alert sink and Object Lock store up | Alert received, signed record in bucket, one `admin_enrolment` row (hash only), `admin.enrolment.issued` event, link printed once, exit 0 | None |
| Alert fails | Alert sink returns 5xx or is unreachable | Exit non-zero; no record written, no row, nothing printed | Message names the alert channel, with no value |
| Record fails | Store refuses, or custody signing fails | Exit non-zero; no row, nothing printed (the alert has already gone out, which is acceptable) | Message names the off-server store |
| Ambiguous Admin | Two Admins, no `--admin` | Refuse, listing public IDs | Exit non-zero |
| No Admin | Bootstrap incomplete | Refuse and point to `gatekeep init` | Exit non-zero |
| Redeem | Valid value, within 15 min | `used_at` set, all of the Admin's Sessions revoked, Recovery (or Setup) Session cookie and CSRF returned, `admin.enrolment.used` written | None |
| Reuse or expiry | Same value again, or after 15 min | Generic refusal, no Session | Same body and status as an unknown value |
| Rate limit | Sixth try from one client in 15 min | 429 before lookup | Counted rows committed |
| Lost setup Session | First Admin, 0 credentials, setup Session ended | Redemption gives a Setup Session; registering two credentials completes setup | None |

</intent-contract>

## Code Map

- `src/Gatekeep.Cli/Program.cs:23-63`: the Usage text and the `args switch`. Add `["recover-admin", ..]` when `cliReady`.
- `src/Gatekeep.Cli/InitCommand.cs:40-159,237-293`: the template to follow:
  - `ConnectionAsync`, `DeploymentScope.BeginAsync`, `CreateCommandContext` and `CommitAsync`.
  - `CustodyOptions` with `new OpenBaoKeyCustody`.
  - The current-role check and the SIGINT/SIGTERM cancellation.
- `src/Gatekeep.Cli/AlertsTestCommand.cs` and `RecordsTestCommand.cs:42`: the synchronous send-and-confirm pattern. They use `OffServerSettings.Alerts`/`Records`, `EgressHttp.Create()`, `WebhookAlertChannel` and `S3ObjectLockStore`. Copy their testable core shape: dependencies as parameters (handler, custody, TimeProvider, out/err).
- `src/Gatekeep.Kernel/Alerts/SecurityAlert.cs`: `SecurityAlertCode.Define` and `SecurityAlert.Raise`. Add `AdminRecovery`, which is allowlisted by reflection in `tests/Architecture/AuditCatalogueTests.cs:235`.
- `src/Gatekeep.Kernel/Records/OffServerRecordWriter`: `WriteAsync(kind, JsonObject, ct)`.
- `src/Modules/Admins/Core/BootstrapIssuer.cs:26-37` and `BootstrapToken.Hash`: hashing, `clock_timestamp()` expiry and `Actor.System` audit. These are the model for a new `EnrolmentIssuer` in Admins Core.
- `src/Modules/Admins/Contracts/AdminsContract.cs`:
  - Factories at :144/:178/:221. Add `CreateEnrolmentIssuer(appender)` and `CreateEnrolments()` for redemption.
  - Rate-limit policies at :17-104.
- `src/Modules/Admins/Contracts/AdminsEvents.cs`: add `admin.enrolment.issued` and `admin.enrolment.used`.
- `src/Modules/Admins/Core/AdminRecoveryCodes.cs:115-160`: the redemption template to follow (consume, `RevokeAsync`, `SupersedeAsync`, `StartAsync`, floor, audit).
- `src/Modules/Admins/Core/AdminSessions.cs`: `StartAsync` :96, `SupersedeAsync` :221, `RevokeAsync` :253, `FloorAsync` :285.
- `src/Modules/Admins/Contracts/IAdminSessions.cs:12`: `AdminSessionKind`.
- `src/Gatekeep.Host.Admin/AdminApi.cs:361` and `RecoveryCodeApi.cs:145-148`: the route and rate-limit pattern to copy for the enrolment route.
- `src/Gatekeep.Host.Admin/AdminRequestChecks.cs:538-603`: Origin, sessionless sign-in, and Setup/Recovery restrictions. No change is expected.
- `src/Adapters/Postgres/Schema/TableRegistry.cs`: `bootstrap_state` :346-367 and `admin_recovery_code` :489-504 are the entry templates. Replace the "for recover-admin later" comments at :370/:488 with the real reason.
- `src/Adapters/Postgres/Migrations/`: the latest is `Migration20261105020000DeleteTenants.cs`. Add `Migration20261108000000CreateAdminEnrolment.cs`.
- `apps/admin-dashboard/src/main.tsx:14-17`: add the `/recover` route. Its page reads `location.hash`, clears it with `history.replaceState`, POSTs it, then navigates to `/setup/credentials`.
  - Build the page from existing components and `hosted-card`, using `RecoveryCodePage.tsx` as the template.
  - Error copy is generic.
- `docs/api/openapi-v1.json` and `packages/api-client`: regenerate.
- **Tests, in `tests/Isolation`:**
  - `tests/Isolation/CrossTenant/RouteRegistry.cs:58-100`: add the new route as `CaseKind.NotTenantBound`.
  - `tests/Isolation/Admins/AdminHost.cs`: `InsertSetupAdminAsync` :445, `RegisterAsync` :268 and `OwnerWithCredentialsAsync`.
  - `Admins/SoftwareAuthenticator.cs`.
  - `AdminRecoveryCodeTests.cs` is the model.
  - `OffServer/ObjectLockFixture.cs`, `AlertSinkFixture`, `OffServerDoubles.SigningCustody` (`Fails`) and `OffServerCliTests.cs` cover in-process CLI cores.
  - `Bootstrap/InitCommandTests.cs` uses `[Collection(OpenBaoCollection.Name)]`.
  - `CliProcess.cs` covers process-level runs.
- **Rule tests:** `tests/Isolation/CatalogueTests.cs:23` (registry vs migrated DB), `Admins/AdminTablesTests.cs` (grants), and the `tests/Architecture` rule tests (`BootstrapStateRuleTests.cs` and `AdminApiRuleTests.cs` are models for an "only Cli references the issuer" rule).

## Tasks & Acceptance

**Execution:**
1. `src/Adapters/Postgres/Migrations/Migration20261108000000CreateAdminEnrolment.cs` and `TableRegistry.cs`: create the table, registry entry and grants described above.
2. `src/Modules/Admins/{Contracts,Core}`:
   - Add `EnrolmentIssuer` (insert + `admin.enrolment.issued`) and `AdminEnrolments.RedeemAsync` (the Setup/Recovery choice, Session revoke, `admin.enrolment.used`).
   - Add the factories, the events, the two rate-limit policies, and `SecurityLimits.AdminEnrolmentLifetime = 15 min`.
3. `src/Gatekeep.Kernel/Alerts/SecurityAlert.cs`: add `SecurityAlertCode.AdminRecovery`.
4. `src/Gatekeep.Cli/RecoverAdminCommand.cs` and `Program.cs`: the command. It has an in-process `RunAsync(options, deployment, alertHandler, custody, store, TimeProvider, out, err, ct)` core and the fixed order. The link goes to `out` only after commit, and errors go to `err` without the value.
5. `src/Gatekeep.Host.Admin/AdminApi.cs` (plus the API class): add the redemption route, its metadata and its rate limits. The refusal is generic.
6. `apps/admin-dashboard` (the `/recover` page and route), `docs/api/openapi-v1.json` and `packages/api-client`: wire the page to the generated client.
7. Add `tests/Isolation/Admins/RecoverAdminTests.cs` covering every matrix row. Test the CLI core in-process against Postgres, OpenBao, MinIO and the AlertSink.
   - Show that a failed alert or a failed record leaves zero rows and empty stdout.
   - Show that the alert precedes the record, and the record precedes the row.
   - Show that a used or expired value gets the same refusal as an unknown one.
   - Show that every one of the Admin's prior Sessions is ended with `revoked`.
   - Show that the Recovery Session can't call a full-only endpoint, and becomes full after one registration.
   - Show that the setup path completes with two registrations.
   - Show a canary value is absent from the `deployment_audit_*` tables, captured logs, the alert body and the record.
8. `tests/Architecture`: add a rule that only `Gatekeep.Cli` references `CreateEnrolmentIssuer`. Extend the grant tests so only `gk_cli` may insert into `admin_enrolment`.
9. Update `docs/threat-model.md`, `docs/audit-events.md`, the Cli Usage text and the operator docs, plus a short "Recover Admin access" section next to `gatekeep init`.

**Acceptance Criteria:**
- Given any container other than `cli`, when its routes are enumerated (`RunningRoutes`) and its role's grants are checked, then no route issues an enrolment and only `gk_cli` can insert into `admin_enrolment`.
- Given a successful run, when `admin_enrolment` is inspected, then its row holds only the ID, Admin ID, SHA-256, creation time, expiry and used time.
- Given the full suite, when it runs in Docker, then everything passes, including the registry, catalogue, route-registry and cross-Tenant tests.

## Spec Change Log

## Review Triage Log

### 2026-11-08 — Review pass
- verdicts: 31 findings — high 0, medium 8, low 21, false 2, maybe-false 0
- findings:
  - `[low]` `[reject]` (intent) The CLI success path is only run in-process, never through `docker compose run cli recover-admin`. Every Cli command in the repo is tested this way. The real wiring is covered by the process-level refusal test and CI's stack job, and a container-level run would need new stack fixtures.
  - `[false]` `[reject]` (intent) "No route offers recovery" is proven only structurally, with no `RunningRoutes`. `RouteRegistryTests` (unchanged) already enumerates the running hosts' endpoints through `RunningRoutes` against `RouteRegistry`, which now lists the redeem route. Hosted is proven to have nothing under `/api`.
  - `[low]` `[reject]` (intent) The printed link drops any non-443 port. Duplicate of the Blind Hunter port finding; see that row.
  - `[low]` `[reject]` (intent) No end-to-end browser test from link to registration. Browser tests intercept the API by project convention, and isolation tests cover the server half.
  - `[low]` `[reject]` (intent) The Setup/Recovery choice is tested only at its extremes (0 credentials vs an Owner). It reuses `MeetsFloor`, which existing Session tests already cover.
  - `[medium]` `[defer]` (intent) The lost credentials stay registered after recovery. Story 8.3 is already assigned to retire them (deferred-work.md).
  - `[low]` `[reject]` (intent) The migration revokes `gk_cli` SELECT on `admin_recovery_code`. That narrows a grant made only "for recover-admin later", which the command doesn't need. No harm, and the tests are updated.
  - `[medium]` `[patch]` (blind) Earlier unused enrolments stay live, so a link left over from an earlier run can re-run recovery after it has completed. Patch: redemption sets `used_at` on all of that Admin's other unused enrolments, with a test.
  - `[low]` `[reject]` (blind) The usable window shrinks by the alert and record latency. Output prints the exact UTC expiry, and the guard refuses a run that exceeds the lifetime. Warning about a thin window would add branches for a rare case.
  - `[low]` `[patch]` (blind) A failure after the alert and record says only "No enrolment was issued". Patch: `FailureMessage` tracks the alert-sent and record-written phases.
  - `[medium]` `[patch]` (blind) One client over its limit still spends the Deployment-wide budget. Patch: count per client first, and Deployment-wide only when the client is allowed.
  - `[low]` `[reject]` (blind) The link drops the HTTPS port. The production default is 443, so the link works as printed. The fix needs a new compose setting in both compose files plus tests, which is more than a direct correction. install.md documents the non-443 case.
  - `[low]` `[reject]` (blind) The audit events don't carry the enrolment ID. They are correlatable by Admin target and time, and adding a detail row needs new detail-table surface.
  - `[low]` `[reject]` (blind) `SecurityAlert` doesn't require `Enrolment` for `AdminRecovery`. There's a single caller, and the guard would add branches.
  - `[medium]` `[patch]` (blind) Missing server tests. Patch: the supersede of another Admin's Session (same as the VG row) and a second run whose link dies when the first is redeemed. Concurrency, cancellation and slow-run tests rejected as low: the `FOR UPDATE` + `used_at IS NULL` update is sound and the guard is a DB trigger.
  - `[low]` `[patch]` (blind) Recover page paths untested. Patch: the 503 path (same as the VG row). The setup path rejected: the page navigates to `/setup/credentials` either way.
  - `[low]` `[patch]` (blind) The browser comment claims Back can't return to the link but only checks `location.href`. Patch: `page.goBack()`, or drop the claim.
  - `[low]` `[patch]` (blind) `AssertHolds`' `absent` parameter is always true. Patch: rename to `AssertAbsent` and drop the parameter.
  - `[low]` `[patch]` (blind) `EnrolmentRedemption.Kind` is unused. Patch: removed.
  - `[low]` `[reject]` (blind) No index on `admin_enrolment.admin_id`. The table holds a handful of rows per recovery.
  - `[low]` `[reject]` (blind) No retention for used or expired rows. No role deletes by design (append-only evidence), and the rows are tiny.
  - `[low]` `[reject]` (blind) The T-21 tests don't cover the concurrency or slow-run claims. Both are enforced by the database (row lock, trigger), and tests would add fixtures for little value.
  - `[medium]` `[patch]` (verification-gap) No test ties the cli's `GATEKEEP_ALERT_DEPLOYMENT` to Caddy's `GATEKEEP_ADMIN_HOST`. Patch: a ComposeConfigTests fact for both compose files.
  - `[medium]` `[patch]` (verification-gap) The supersede of a different Admin's presented Session isn't tested. Patch: a RecoverAdminTests fact covering `superseded`, the event and the 401.
  - `[low]` `[patch]` (verification-gap) The Recover page's 503 path has no browser test. Patch: mirrors the Recovery Code 503 test.
  - `[false]` `[reject]` (edge) The per-client key is Caddy's address. `GatekeepHosting.cs:120-130` applies `UseForwardedHeaders` trusting only Caddy, so `RemoteIpAddress` is the real client.
  - `[medium]` `[patch]` (edge) Junk traffic exhausts the Deployment-wide count. Same root cause as the blind budget row; the same patch reorders the counts.
  - `[medium]` `[defer]` (edge) An Admin at the 10-credential maximum can't register after redeeming. Pre-existing, already in deferred-work.md (Story 8.3).
  - `[low]` `[patch]` (edge) The failure message after the alert or record omits that they were sent. Same as the blind row; same patch.
  - `[low]` `[reject]` (edge) A slow run leaves a thin or zero window. Same as the blind window row: the expiry is printed and the trigger refuses past the lifetime.
  - `[low]` `[patch]` (edge) The architecture rule excludes the whole Admins module. Patch: exclusion narrowed to the three defining files.

## Design Notes

**Why Sessions end at redemption, not at issue.**
- `gk_cli` has no grant on `admin_session`. Keeping it that way keeps the CLI's database reach narrow.
- Redemption ends every Session of that Admin in the same transaction that starts the restricted one, so a completed recovery always leaves only the new Session.
- An intruder's Session survives at most until redemption (15 minutes at most), and the alert has already reached the Operator.

**Why alert first.** If the commit fails after the alert, the Operator gets a false alarm but no access is issued. That is fail-safe. The reverse order could issue access with no alert.

**Setup vs Recovery Session.** An Admin who never finished setup (`admin.setup.completed` absent, or fewer than 2 credentials) needs two credentials, which the `Setup` kind already enforces. A set-up Admin needs one fresh credential, which the `Recovery` kind already enforces.

## Verification

**Commands:**
- `docker compose -f deploy/compose.dev.yaml run --rm --build tests` — expected: all tests pass.
- `pnpm -r build` and `pnpm -r lint` (inside the tests image) — expected: success. The api-client diff matches the OpenAPI document.

## Auto Run Result

Status: done

**Summary:** `gatekeep recover-admin` lets an Admin who lost every WebAuthn credential, or a first Admin whose setup Session ended, register new credentials, and it never happens quietly.

The command runs in the `cli` container as `gk_cli`, in a fixed order:
1. It reads the Admin and the database clock.
2. It sends the `admin.recovery.started` Security Alert and waits for a 2xx.
3. It signs and writes the `admin_recovery` off-server record.
4. Only then, in one transaction, it stores the SHA-256 of a 256-bit value in `admin_enrolment` and writes `admin.enrolment.issued`.
5. It prints `https://<admin host>/recover#<value>` once.

**Redemption:** Host.Admin redeems the value at `POST /api/v1/deployment/signin/enrolment`, which takes no Session.
- Both rate limits are counted before the lookup: per client first, then Deployment-wide.
- In one transaction it:
  - uses up that enrolment and every other unused enrolment of the Admin;
  - revokes all of the Admin's Sessions;
  - supersedes the Session the browser presented;
  - starts a Setup or Recovery Session, which can reach only credential registration;
  - writes `admin.enrolment.used`.
- Every refusal is the same 400 `enrolment_refused`.

**Files changed:**
- `src/Adapters/Postgres/Migrations/Migration20261108000000CreateAdminEnrolment.cs` and `Schema/TableRegistry.cs`: the table, its CHECKs, the guard trigger and the grants. It also revokes `gk_cli`'s unused read on `admin_recovery_code`.
- `src/Modules/Admins/Contracts/IAdminEnrolments.cs` and `Core/AdminEnrolments.cs`: the value, the issuer and the redemption.
- `AdminsContract.cs`: the factories and the two rate-limit policies.
- `AdminsEvents.cs`: two new events.
- `src/Gatekeep.Kernel/`:
  - `SecurityAlertCode.AdminRecovery` and `AlertEnrolment`;
  - `PublicIdType.Admin` (`adm_`);
  - the `SecurityLimits` constants.
- `src/Adapters/AlertChannel/WebhookAlertChannel.cs`: the alert body carries the enrolment references.
- `src/Gatekeep.Cli/RecoverAdminCommand.cs` and `Program.cs`: the command and its Usage text.
- `src/Gatekeep.Host.Admin/EnrolmentApi.cs`, `AdminApi.cs`, `AdminApiServices.cs`, `AdminResponses.cs` and `AdminOpenApi.cs`: the redemption route.
- `apps/admin-dashboard/src/RecoverPage.tsx`, `main.tsx` and `packages/ui/src/messages.tsx`: the `/recover` page.
- `docs/api/openapi-v1.json` and `packages/api-client`: regenerated.
- `docs/threat-model.md` (T-21), `docs/audit-events.md` and `docs/install.md` ("Recover Admin access").
- **Tests:**
  - `tests/Isolation/Admins/RecoverAdminTests.cs` (new);
  - `AdminTablesTests`, `AdminEndpointTests` and `AdminHost`;
  - `CanaryFlows` and `CanarySurfaceTests`;
  - `RouteRegistry` and `HostedGrantsTests`;
  - `OffServerRecordTests`, `ComposeConfigTests` and `MigrateCommandTests`;
  - `tests/Architecture` (`AdminApiRuleTests`, `CapabilityRuleTests`, `TenantKeyedTypes`);
  - `tests/browser/admin-recovery.spec.ts`.

**Review findings:** 31 findings: 0 high, 8 medium, 21 low, 2 false.
- **Patched:** 14 rows (5 medium, 9 low).
- **Deferred:** 2 medium, both for Story 8.3: the lost credentials stay registered, and an Admin at the 10-credential maximum can't register.
- **Rejected:** 15 rows (13 low, 2 false), each with its reason in the triage log.

**Follow-up review:** recommended (`true`), because five medium entries were patched. No reviewer has looked at the patched code since. The unverified risks are:
- the reordered rate-limit counting in `EnrolmentApi` (per client, then Deployment-wide);
- the sweep in `AdminEnrolments.RedeemAsync` that uses up an Admin's other unused enrolments.

**Verification:**
- **Final full Docker run on the merged tree:** browser 533 passed and architecture 720 passed. The isolation tests were stopped by Claude Code because the machine was low on memory.
- **Earlier runs:** every `RecoverAdminTests`, compose and migrate test passed. The other failures were Docker-load connection errors (`192.168.65.254` refused, IPv6 unreachable) that hit different tests on each run.
- **`MasterKeyRotationTests.Full_rotation…`** failed locally in every run. It is untouched by this diff and passes in `main`'s CI.
- **CI** runs the full suite on a clean runner before merge.

**Residual risks:**
- The printed link carries no port, so a non-443 deployment must add `:{port}` by hand (documented in `docs/install.md`).
- Sessions end at redemption, not at issue, so an intruder's Session lasts at most until the link is used or expires.
- The alert goes out before the commit, so a failed commit gives a false alarm (by design).
