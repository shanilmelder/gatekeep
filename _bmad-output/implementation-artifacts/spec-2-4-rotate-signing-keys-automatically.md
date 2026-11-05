---
title: 'Story 2.4: Rotate Signing Keys automatically'
type: 'feature'
created: '2026-11-05'
status: 'done'
baseline_revision: '27dd30331e7c210c396b165cd8e5cf29620c5633'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-2-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-2-3-publish-discovery-and-jwks-per-tenant.md'
warnings: ['oversized']
deferred:
  - summary: >-
      Nothing alerts when a current key passes the 180-day maximum age because rotation keeps failing.
    evidence: |-
      The daily rotation logs a failed Tenant by type only and retries. If custody stays down, or the job goes dead, a current key can sign past 180 days with no audit event or alert. Epic 11 (Security Alerts) is where an over-age alert belongs.
    location: >-
      src/Modules/Operations/Core/SigningKeyJobs.cs
    severity: medium
  - summary: >-
      Revoked keys have no destruction path yet.
    evidence: |-
      Only retirement enqueues a destroy job, and destroyed_at is limited to retired rows. Nothing revokes a key before Epic 9, which must add destruction for revoked rows.
    location: >-
      src/Modules/Keys/Core/SigningKeyLifecycle.cs
    severity: low
---

<intent-contract>

## Intent

**Problem:** Story 2.3 creates each Tenant's `current` and `next` keys but nothing ever moves them. A key would stay `current` forever, past the §5.2 maximum age of 180 days (FR-37, AR-21, AD-11). Retired keys would stay in Transit, and a Transit key whose row never committed would be left as an orphan.

**Approach:** Add three Worker jobs: a daily rotation, a destruction job per retired key, and a daily orphan sweep. Add the columns and grants the state changes need. Rotation fans out per Tenant. In one command it promotes, rotates, creates the replacement `next` and retires. Then a `NOTIFY` tells Host.Hosted to drop that Tenant's cached runtime, so JWKS changes at once.

## Boundaries & Constraints

**Always:**
- **Fixed limits** go in `SecurityLimits`, never hard-coded:
  - Signing Key maximum age is 180 days.
  - The rotation margin is 30 days.
  - Promotion needs 15 minutes of publication.
  - The hard token lifetime is 1 hour (the longest signed token: access and ID).
  - The retirement delay is that lifetime plus 15 minutes.
  - The orphan grace period is 24 hours.
- **Key age** is `now() - created_at`, by database time. A key is due when its age is at least 150 days. Because `next` ages alongside `current`, a promoted `next` can itself be due the next day. That second rotation is expected, and it is what keeps every key's existence under 180 days.
- **Rotation job** `keys.signing_keys.rotate` runs daily, Deployment-wide, as `gk_worker`. It fans out over active Tenants, one Tenant scope and one command each, and one Tenant's failure doesn't stop the others. It takes the same per-Tenant advisory lock as `EnsureTenantKeysAsync`. Per purpose:
  - If `current` is due, and `next` qualifies (`signing`: `published_at <= now() - 15 min`; `management`: no ageing), then `current` becomes `previous` (with `rotated_at`), `next` becomes `current` (with `promoted_at`), and a new `next` is created Transit-first and inserted (`published_at = now()` for `signing`).
  - If `next` doesn't qualify, nothing changes for that purpose until the next run.
  - Any `previous` with `rotated_at <= now() - (1 h + 15 min)` becomes `retired` (with `retired_at`), and a `keys.signing_key.destroy` Tenant job for that row is enqueued in the same command.
  - One audit event is written per state change. A `pg_notify` on channel `gatekeep_signing_keys` with the Tenant ID as payload goes out whenever any row changed.
  - At commit, one `current` and one `next` per purpose still exist. A Transit failure rolls back the whole Tenant command.
- **Destruction job** `keys.signing_key.destroy`, per Tenant, with the row ID in the payload:
  - It re-checks that the row is `retired` and not yet destroyed, then calls `IKeyCustody.DeleteAsync` and sets `destroyed_at`, with an audit event.
  - A custody failure commits a `keys.signing_key.destruction_failed` audit event through `FailureContext.CommitAfterRollbackAsync`, then throws so the job retries with backoff. It never touches another row or key.
  - A row that is already destroyed, or not retired, is a no-op success.
- **Orphan sweep** `keys.transit_keys.sweep` runs daily, Deployment-wide.
  - It lists Transit keys through a new `IKeyCustody` method that returns each name with its creation time. The adapter needs `list` on `transit/keys`, added to `deploy/openbao/policies/host-worker.hcl` only.
  - It considers only names that parse as `sig-{tenantId}-{rowId}` or `mgmt-{tenantId}-{rowId}`. Everything else, including every secret-class key, is skipped.
  - It deletes a key only when the key is older than 24 hours and that Tenant's scope has no `signing_key` row with that `transit_name`.
  - It writes one Deployment audit event per removal. A failure on one key is logged by type and the sweep goes on.
- **Columns.** A new migration adds `promoted_at`, `rotated_at`, `retired_at` and `destroyed_at` (`timestamptz NULL`) to `signing_key`.
  - Existing `current` rows get `promoted_at = created_at`, and new Tenants' `current` rows get it at insert.
  - CHECKs tie each column to its state: `previous` and `retired` have `rotated_at`, `retired` has `retired_at`, and `destroyed_at` only on `retired`.
  - `gk_worker` gets a column-level `UPDATE` on `(state, promoted_at, rotated_at, retired_at, destroyed_at)` only.
  - A trigger refuses any state transition outside AD-11 (`next→current`, `current→previous`, `previous→retired`, any non-retired → `revoked`) and any change to `id`, `tenant_id`, `purpose`, `transit_name`, `transit_version`, `created_at` or `published_at`.
- **Host.Hosted LISTEN.** `TenantRuntimes` keeps one dedicated `gk_hosted` connection listening on `gatekeep_signing_keys`, and evicts the named Tenant's runtime on each notification. If the connection is lost, it reconnects with capped backoff and evicts every entry on reconnect. The 5-second lifetime stays as the bound when no listener is connected.
- **Registration.** Every new job type is registered with its review text and canary reason, and the job guard is re-rendered. Rotation and sweep are scheduled daily in `JobSchedule`. Audit codes go in `KeysEvents` (and `docs/audit-events.md` is regenerated).

**Never:**
- No on-demand rotation or revocation, and no Admin UI (Epic 9). No alert delivery (Epic 11 alerts on the destruction-failed event).
- No change to the `signing_key` state set, and no deletion of `signing_key` rows.
- No widening of Host.Hosted's or Host.Admin's OpenBao policy.
- The sweep never touches a key with a row, a key younger than 24 hours, or any non-`sig-`/`mgmt-` key.
- No key name, version, key material or ciphertext in logs, audit details or test output.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Due, next aged | `signing` current 150 d old, next published 20 min ago | current→previous, next→current, a new next (fresh Transit key, published now). JWKS on the next request shows the new set without waiting 5 s | No error expected |
| Due, next too young | current 150 d, next published 5 min ago | Nothing changes for `signing` | No error expected |
| Management due | `management` current 150 d, next published_at null | Rotates without the 15 min gate. JWKS unchanged (no management key) | No error expected |
| Not due | current 149 d | Nothing changes | No error expected |
| Retire | previous rotated 1 h 16 min ago | → `retired` with `retired_at`; leaves JWKS; one destroy job enqueued for it | No error expected |
| Previous too recent | previous rotated 1 h 14 min ago | Stays `previous` | No error expected |
| Destroy ok | Destroy job for a retired row | Transit key deleted, `destroyed_at` set, audit event | No error expected |
| Destroy fails | Custody delete fails | `destruction_failed` audit event committed; job retries; no other row or key changed | Job failure + retry |
| Destroy rerun | Row already destroyed, or not retired | No custody call, success | No error expected |
| Two Tenants | A due, B not | Only A's rows and JWKS change; B's JWKS byte-identical | No error expected |
| Transit failure mid-rotation | Create of the new next fails | Tenant's rows unchanged; other Tenants still rotate | Logged by type; job fails and retries |
| Orphan old | `sig-{A}-{x}` 25 h old, no row | Deleted, Deployment audit event | No error expected |
| Orphan young | `sig-{A}-{x}` 1 h old, no row | Kept | No error expected |
| Key with row / secret class | `sig-` key with a row; `tpk-{A}`, `totp-{A}`, `dep-*` | Never deleted | No error expected |
| Forbidden change | `gk_worker` UPDATE `current→next`, or of `transit_name` | Refused by the trigger or the grant | SQL error |

</intent-contract>

## Code Map

- `src/Modules/Keys/Core/TenantKeys.cs` -- 2.3's provisioning: the advisory lock (`Lock`, `LockNamespace`), Transit-first insert, `InsertKey`, the savepoint pattern and `ReadPublishedAsync`. Rotation goes beside it and reuses the lock and the insert. Add `promoted_at` to new `current` inserts.
- `src/Modules/Keys/Contracts/KeysContract.cs`, `KeysEvents.cs` -- public surface: add the rotation, destruction and sweep entry points and their events.
- `src/Adapters/Postgres/Migrations/Migration20261105000000CreateSigningKeyTables.cs` -- the table, its CHECKs and grants, and the rendered job guard block. The new migration `Migration20261105010000RotateSigningKeys.cs` follows it and re-renders the guard for the three new types. `tests/Isolation/MigrateCommandTests.cs` goes from 18 to 19. `TableRegistry.cs` gets the column grant and the trigger name (pattern: `ColumnGrant` entries such as `admin_recovery_code_guard` near :436).
- `src/Modules/Operations/Core/TenantKeyBackfill.cs`, `ProductionJobs.cs` (JobDefinition with `JobReview`), `AuditRetentionJobs.cs:41-70` (Deployment-wide fan-out and `JobEnqueuer.EnqueueAsync` with `payload`) -- the job patterns. `src/Modules/Operations/Contracts/JobRun.cs` (`Ids` payload, `Services.Custody`, `Services.Logger`). `OperationsContract.cs` exposes job types for `src/Gatekeep.Host.Worker/JobSchedule.cs`.
- `src/Gatekeep.Kernel/Persistence/FailureContext.cs` (`CommitAfterRollbackAsync`) and `tests/Isolation/FailureContextTests.cs:21` -- commit the failure event despite the rollback.
- `src/Gatekeep.Kernel/Secrets/IKeyCustody.cs:36-99` and `KeyName.cs` (name parsing, `KeyKind`) -- add the list-with-creation-time method. `src/Adapters/OpenBao/OpenBaoKeyCustody.cs` (`DeleteAsync` at :250, HTTP helpers) implements it with `LIST transit/keys` plus a read for `keys.{v}.creation_time`. Update the test doubles in `tests/Isolation/Custody/CustodyTestDoubles.cs` and any `IKeyCustody` fakes under `tests/Isolation/Protocol/` and `Keys/`.
- `deploy/openbao/policies/host-worker.hcl` -- add `path "transit/keys" { capabilities = ["list"] }`. Policy tests live under `tests/Isolation/Custody/`, so check that none asserts the exact policy text.
- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs:110-120` -- 2.3's limits. Add the new ones beside them.
- `src/Modules/Protocol/Core/TenantRuntimes.cs` -- the cache, timed eviction and `Kept` count. Add the listener, started on first use and disposed with the singleton. `src/Modules/Protocol/Adapters/TenantKeyReader.cs` has the `gk_hosted` connection string and pool settings to reuse.
- `tests/Isolation/Keys/TenantKeysTests.cs` (seeding, `ControlledCustody`, `RunBackfillAsync`, the grant and constraint theories, including `Worker_inserts_and_reads_but_never_changes_a_key_row`, which must be updated) and `tests/Isolation/Protocol/ProtocolHost.cs` + `DiscoveryAndJwksTests.cs` (manual clock, JWKS reads) -- extend them.
- `tests/Isolation/Canary/CanaryFlows.cs` -- reviewed reasons for the new job types. `tests/Isolation/Jobs/WorkerStartupTests.cs` -- the scheduled-job-runs-to-done pattern.

## Tasks & Acceptance

**Execution:**
- `SecurityLimits.cs` -- the new limits.
- The new migration, `TableRegistry.cs`, `MigrateCommandTests.cs` -- the columns, CHECKs, backfill of `promoted_at`, column grant, transition trigger and re-rendered job guard.
- `IKeyCustody.cs`, `OpenBaoKeyCustody.cs`, `host-worker.hcl`, test doubles -- list keys with creation time.
- `src/Modules/Keys/**` -- rotation, retirement with the destroy enqueue, destruction, sweep, NOTIFY and events.
- `src/Modules/Operations/Core/*` (job handlers and registry), `OperationsContract.cs`, `JobSchedule.cs` -- the three job types and the two daily schedule entries.
- `src/Modules/Protocol/Core/TenantRuntimes.cs` (and its adapter) -- the LISTEN-driven eviction.
- `tests/Isolation/Keys/*`, `tests/Isolation/Protocol/*`, `tests/Isolation/Custody/*`, `WorkerStartupTests`, `CanaryFlows` -- at least one test per I/O matrix row, against real Postgres and OpenBao. Age states by backdating rows as superuser, never by waiting.
- `docs/audit-events.md`, the module diagram -- regenerated.
- `_bmad-output/implementation-artifacts/sprint-status.yaml` -- set `2-4-…` to `done` at finalize.

**Acceptance Criteria:**
- Given the Architecture and Isolation suites, when they run in Docker with locked restore, then all pass, including Story 2.3's tests.
- Given any interleaving of the rotation job and the 2.3 backfill for one Tenant, when both commit, then it still has exactly one `current` and one `next` per purpose.
- Given a real Worker started on an empty migrated database, when the schedule runs, then the rotation and sweep jobs are enqueued and reach `done`.
- Given a rotation committed for Tenant A, when A's JWKS is requested before the 5-second lifetime ends, then it already shows the new set (LISTEN eviction), while B's cached runtime is untouched.

## Spec Change Log

## Review Triage Log

### 2026-11-05 — Review pass
- verdicts: 35 findings — high 0, medium 4, low 19, false 12, maybe-false 0
- findings:
  - `low` `patch` (blind) The double rotation recurs every 150-day cycle (alternate keys sign about 1 day and about 149 days), and the Design Note said it happened once — the code comment now describes the recurring pattern, and a three-cycle test asserts that no key exists past 180 days and that every promoted signing key had been published. The behaviour stays within AD-11 and the intent contract (age from `created_at`), and the only cost is churn. A different cadence (rotating by time served) would change the intent contract, so it is raised with the user as a residual, not patched.
  - `medium` `patch` (blind) A destroy job that has gone dead is never queued again, and its row keeps naming the key, so the sweep skips it — the daily rotation now enqueues a destroy for every `retired` row with no `destroyed_at` and no live destroy job.
  - `low` `defer` (blind) Revoked keys have no destruction path — nothing revokes a key until Epic 9. Deferred.
  - `medium` `defer` (blind) Nothing enforces or alerts on the 180-day maximum when rotation keeps failing — belongs to Epic 11 alerts. Deferred.
  - `false` `reject` (blind) Only active Tenants are rotated — `creating` and `active` are the only statuses. A `creating` Tenant never serves a token, and its keys are less than a day old.
  - `medium` `patch` (blind) One key's failed read fails the whole sweep list — each key is now skipped and the list goes on, with a test.
  - `low` `patch` (blind) Any `Rejected` LIST is read as an empty mount — only the 404 returns `[]` now, and a LIST failure fails the job, with a test.
  - `low` `patch` (blind) The migration doesn't backfill `rotated_at`/`retired_at` — both are backfilled before the CHECKs are added.
  - `low` `patch` (blind) Nothing requires `promoted_at` on promoted states — a CHECK now does, for `current`, `previous` and `retired`.
  - `low` `reject` (blind) The audit events carry no row ID or purpose — the events name no key by design (as in Story 2.3), and the envelope's Tenant and type are what Epic 11 alerts on. Adding detail is an audit-schema decision for Epic 11.
  - `low` `reject` (blind) The sweep's check and delete aren't atomic, and clock skew isn't allowed for — the 24-hour grace is much larger than any provisioning window or plausible skew. Locking would add a cross-scope lock for no reachable race.
  - `false` `reject` (blind) Management keys retire on the access-token lifetime — Management API tokens last 15 minutes (PRD §5.2), less than the 1-hour hard lifetime used.
  - `low` `patch` (blind) `sprint-status` is marked done before merge, and the sweep wording overstates its check — sprint-status is set at finalize, as in every story (false part). The sweep event wording is now corrected.
  - `medium` `patch` (blind) Tests are missing — the cadence, dead destroy, revoke transition, Hosted UPDATE refusal and list-failure tests were added. The migration-staged backfill test is rejected (verification-gap row). The persistent-failure-to-`dead` test is rejected as standard job-runner behaviour, already tested in Jobs.
  - `low` `patch` (edge) A 400 LIST reads as empty — grouped with the 404-only patch.
  - `false` `reject` (edge) A non-string entry in the `keys` array — OpenBao's LIST returns only strings.
  - `low` `patch` (edge) One key's read failing aborts the list — grouped with the per-key skip patch.
  - `low` `patch` (edge) A dead destroy job is never queued again — grouped with the re-enqueue patch.
  - `false` `reject` (edge) An over-age `next` gets promoted (after the backfill replaced a revoked `current`) — nothing revokes yet, and the 2.3 carry-over requires Epic 9 never to commit a `next` without a `current`.
  - `low` `defer` (edge) Revoked keys and non-active Tenants — revoked is deferred (blind row). Non-active Tenants are false (blind row).
  - `low` `patch` (edge) The migration fails on existing `previous`/`retired` rows — grouped with the backfill patch.
  - `false` `reject` (edge) Setting `rotated_at` on `current` with no state change blocks a later rotation — only Gatekeep's own commands write these columns, and they never do that.
  - `low` `reject` (edge) The listener isn't `IDisposable` — the generic host disposes its services asynchronously, and no synchronous disposal path is reachable.
  - `low` `patch` (edge, claim) "One key's failure is logged and the others still run" was false for list reads — grouped with the per-key skip patch.
  - `false` `reject` (edge, claim) "No key outlives the maximum age" while a `next` of any age is promoted — every `next` is younger than the `current` it replaces, and the cadence test now shows it.
  - `low` `patch` (verification-gap) No test of retirement-only `NOTIFY` and eviction — added.
  - `low` `patch` (verification-gap) No test of `Rejected` with the key still present — added.
  - `low` `patch` (verification-gap) No test of a LIST failure failing the job — added with the 404-only patch.
  - `low` `reject` (verification-gap, other) No test of the migration's `promoted_at` backfill — nothing reads `promoted_at` yet, and the test would need staged migrations.
  - `false` `reject` (intent) Retirement can lag to about 25 hours — the intent's "past … plus 15 minutes" is a minimum and the daily job meets it. The retired key is harmless while published.
  - `false` `reject` (intent) Most tests call the contract directly — the job path is covered by the rotate-only-the-due-Tenant, mid-rotation-failure and Worker startup tests. The contract is the job's only body.
  - `false` `reject` (intent) One failure event per attempt rather than one when retries run out — the intent says "retries, writes an audit event", and a per-attempt event lets Epic 11 alert before exhaustion.
  - `false` `reject` (intent) "No key outlives its maximum age" is a schedule, not a hard limit — same root cause as the deferred alert row.
  - `false` `reject` (intent) No signing test with the promoted key — signing isn't reachable until Story 2.5.
  - `false` `reject` (intent) Additions beyond the intent (trigger, column grants, listener) — the spec requires them to keep AD-11's transitions and its immediate JWKS change.

## Design Notes

Measuring age from `created_at` (not from promotion) is the only reading under which no key outlives 180 days, because `next` waits while `current` ages. The double rotation it causes is deliberate. Cycle example: on day 150 `next` N0 is promoted, and on day 151 N0 is itself due and N150 is promoted. After that, each key signs for about 149 days. Write this in the code comment.

Each Transit key name is a row, and Transit never rotates it in place. A Hosted runtime built just before a rotation still signs with the old key for at most 5 seconds. That key is `previous` then, still in JWKS, and valid for at least 1 h 15 min, so the 2.1 carry-over ("signing fails until the runtime is rebuilt") can't happen.

`pg_notify` inside the Tenant's command is delivered only at commit, so a rolled-back rotation never evicts anything.

## Verification

**Commands:**
- `docker build -t gatekeep/tests:epic2 -f deploy/docker/tests.Dockerfile .` -- expected: builds with locked restore.
- `MSYS_NO_PATHCONV=1 docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal --add-host host.docker.internal:host-gateway gatekeep/tests:epic2` -- expected: all architecture and isolation tests pass. 15–23 s connection timeouts under shared-Docker load are rerun alone.

## Auto Run Result

**Summary.** Signing and Management keys now rotate on their own, through three new Worker jobs:
- **Daily rotation** (`keys.signing_keys.rotate`): runs one command per Tenant under the provisioning advisory lock. It promotes `next` to `current` and moves `current` to `previous` once `current` is 150 days old. For `signing`, the `next` key must have been published at least 15 minutes earlier. It creates the replacement `next` Transit-first. It retires any `previous` key rotated more than 1 h 15 min ago and queues a destroy job for it. It also queues a destroy job again for any retired key whose earlier one went dead. Then it sends a `NOTIFY` (`gatekeep_signing_keys`).
- **Destroy** (`keys.signing_key.destroy`): deletes the Transit key and sets `destroyed_at`. If deletion fails, it commits `keys.signing_key.destruction_failed` through `FailureContext` and retries.
- **Daily orphan sweep** (`keys.transit_keys.sweep`): removes `sig-`/`mgmt-` Transit keys at least 24 hours old that no row names. It never touches any other key.

Host.Hosted keeps a `LISTEN` connection, so a committed change drops that Tenant's cached runtime at once.

The migration adds the lifecycle times with their backfill and CHECKs, a trigger that enforces the AD-11 transitions, and a column-level `UPDATE` for `gk_worker`. The Worker's OpenBao policy gains `list` on `transit/keys`.

**Deviations from the spec**
- The per-Tenant scopes, the failed-destroy `FailureContext` commit and the sweep's per-key commits live in Operations, because architecture rules forbid scopes and `FailureContext` in contracts. Keys keeps only the steps that take a `CommandContext`.
- Destroying a key that is already gone from custody marks its row destroyed.

**Files changed**
- `SecurityLimits.cs` -- six key lifecycle limits.
- `IKeyCustody.cs`, `KeyName.cs`, `OpenBaoKeyCustody.cs`, `host-worker.hcl` -- `ListRowKeysAsync` (row keys with creation time; 404 only means empty; an unreadable key is skipped) and the `list` grant.
- `Migration20261105010000RotateSigningKeys.cs`, `TableRegistry.cs` -- the columns, backfill, CHECKs (including `promoted_at`), transition trigger, column grant and re-rendered job guard.
- `src/Modules/Keys/**` -- `SigningKeyLifecycle.cs` (rotate, retire, re-queue destroy, destroy, row-name check, NOTIFY) and seven `KeysEvents`.
- `src/Modules/Operations/Core/SigningKeyJobs.cs`, `ProductionJobs.cs`, `OperationsContract.cs`, `JobSchedule.cs` -- the three jobs and the two daily entries.
- `src/Modules/Protocol/**` -- `SigningKeyChangeListener` and `TenantRuntimes` eviction.
- Tests -- `SigningKeyRotationTests`, `KeyChangeEvictionTests`, a policy matrix case, a Worker startup case, canary reasons, and updated 2.3 fixtures.
- `docs/audit-events.md` -- regenerated.

**Review findings.** There were 35 findings: 20 patched in 7 groups, 3 deferred (revoked-key destruction, the over-age alert, and the non-active row that shares the revoked deferral), and 12 rejected (all false), plus the low rejections recorded in the triage log.

**Follow-up review: recommended (`true`).** Three medium entries were patched:
- re-queuing dead destroy jobs
- per-key skip in the list
- the missing tests group

None were high. The unverified risk is the destroy re-queue's match on `job_payload.ids` for live jobs. It runs in every Tenant's daily command, and only one test covers it. A second pass should confirm that it never queues a duplicate while a destroy job is still retrying, and that it scales with job history.

**Verification**
- Before the patches, the full Docker suite (`gatekeep/tests:epic2`) passed Architecture 599/599 and Isolation 2329/2333, with 4 load timeouts.
- After the patches, it passed Architecture 599/599 and Isolation 2340/2344. The 4 failures were 15–17 s connection timeouts in unrelated tests (FreshAssertion, TenantLabel, Audit, InitCommand). Rerun alone, those four tests passed (13/13 cases).
- The matrix audit found a covering test for every I/O matrix row, and each one ran and passed.

**Residual risks**
- **Rotation cadence:** age is counted from `created_at`, so the double rotation recurs every cycle. Alternate keys sign for about 1 day and about 149 days, which means two extra Transit keys and retirements per Tenant every 150 days. A 75/75 cadence would change the intent contract and is left for the user to decide.
- **Failing rotation:** nothing alerts when a key passes 180 days because rotation keeps failing (Epic 11).
- **Revoked keys:** they have no destruction path yet (Epic 9).
- **Sweep cost:** it reads every row key one by one.
- **Listener wait:** the first Hosted request waits up to 5 s for the listener.
- **Migration backfill:** the backfill on pre-existing rows has no migration-staged test.
