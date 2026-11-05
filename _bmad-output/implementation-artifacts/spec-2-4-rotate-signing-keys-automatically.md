---
title: 'Story 2.4: Rotate Signing Keys automatically'
type: 'feature'
created: '2026-11-05'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-2-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-2-3-publish-discovery-and-jwks-per-tenant.md'
warnings: ['oversized']
deferred: []
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

## Design Notes

Measuring age from `created_at` (not from promotion) is the only reading under which no key outlives 180 days, because `next` waits while `current` ages. The double rotation it causes is deliberate. Cycle example: on day 150 `next` N0 is promoted, and on day 151 N0 is itself due and N150 is promoted. After that, each key signs for about 149 days. Write this in the code comment.

Each Transit key name is a row, and Transit never rotates it in place. A Hosted runtime built just before a rotation still signs with the old key for at most 5 seconds. That key is `previous` then, still in JWKS, and valid for at least 1 h 15 min, so the 2.1 carry-over ("signing fails until the runtime is rebuilt") can't happen.

`pg_notify` inside the Tenant's command is delivered only at commit, so a rolled-back rotation never evicts anything.

## Verification

**Commands:**
- `docker build -t gatekeep/tests:epic2 -f deploy/docker/tests.Dockerfile .` -- expected: builds with locked restore.
- `MSYS_NO_PATHCONV=1 docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal --add-host host.docker.internal:host-gateway gatekeep/tests:epic2` -- expected: all architecture and isolation tests pass. 15–23 s connection timeouts under shared-Docker load are rerun alone.
