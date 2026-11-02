---
title: 'Story 7.3: Verify chains and apply retention'
type: 'feature'
created: '2026-11-02'
status: 'done'
baseline_commit: 'e9bd3747f70b42e8db34ab7470d6f34502309b28'
baseline_revision: 'e9bd3747f70b42e8db34ab7470d6f34502309b28'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-7-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-7-1-seal-audit-events-into-hash-chains.md'
  - '{project-root}/docs/threat-model.md'
warnings:
  - oversized
  - multiple-goals
deferred: []
---

<intent-contract>

## Intent

**Problem:** Story 7.1 seals chains, but nothing checks them, nothing deletes expired events, and the retention period exists nowhere in code (FR-40, NFR-15, AD-16, §5.2).

**Approach:** Add `gatekeep audit verify`, which walks every chain as `gk_cli` and reports the position of any altered or missing row. Add retention jobs under `gk_retention` that delete whole expired sealed ranges and write a sealed checkpoint carrying the last deleted hash. Fix the 90-day period as a Kernel constant that a test holds to the floor. Add an Operation that purges a deleted Tenant's chain once its retention ends.

## Boundaries & Constraints

**Always:**
- The retention period is one Kernel constant of 90 days, and nothing configures it: no setting, route or Cli argument.
- Retention deletes only a contiguous sealed prefix of a chain whose rows are all older than the period, never the chain head. It deletes detail rows first, then events, then writes one checkpoint event in the same transaction, under the chain's advisory lock (the sealer's lock).
- A checkpoint carries the last deleted row's `epoch`, `seq` and `hash` in envelope columns, inside its own hash. Ordinary rows' canonical envelopes stay byte-for-byte as in Story 7.1.
- Verify reads only. It reports each problem with the chain (Tenant ID or `deployment`), `epoch` and `seq`, and exits 1 on any problem, 0 when every chain verifies.
- Erasing a User deletes `audit_detail` only, so the chain still verifies.

**Never:**
- No off-server heads, signed records or checking a checkpoint against them (Story 7.2). No restore records or new epochs (Epic 12).
- No Tenant deletion flow or deletion marker. The purge Operation is started by its future caller, or by a test.
- No change to how writers append or how the sealer orders rows.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Intact | Sealed Tenant and Deployment chains | Exit 0, a count of chains and rows | N/A |
| Altered | Superuser changes a sealed row's `type_code` (triggers off) | Exit 1, names that chain, epoch and seq as altered | N/A |
| Missing middle | Superuser deletes seq 3 of 5 | Exit 1, names seq 3 as missing | N/A |
| Missing start | Rows 1–2 deleted with no checkpoint | Exit 1, names seq 1–2 as missing | N/A |
| Retention cut | Rows 1–3 older than 90 days, 4–5 newer | 1–3 and their detail deleted, checkpoint (seq 3, hash of 3) written and sealed, verify exits 0 | N/A |
| Late old row | Row 2 is new, rows 1 and 3 old | Only row 1 deleted | N/A |
| Whole chain old | Every row older than 90 days | All but the head deleted | N/A |
| Erased User | Detail rows deleted as `gk_worker` | Verify exits 0 | N/A |
| Purge, retention not ended | Tenant chain with an event under 90 days old | Nothing deleted, step fails with a fixed code | Retry later |
| Purge, retention ended | Every event older than 90 days, all sealed | Whole chain and detail deleted | N/A |
| Fake checkpoint | Non-`gk_retention` role inserts a checkpoint type | Refused | Trigger error |

</intent-contract>

## Code Map

- `src/Modules/Audit/Core/AuditSealer.cs` -- chain lock (`pg_advisory_xact_lock(0x41554454, hashtext(chain))`), head and seal SQL. It must read the new checkpoint columns into the envelope.
- `src/Modules/Audit/Core/ChainHash.cs`, `Contracts/ChainEnvelope.cs` -- the 10-member envelope. Add three optional checkpoint members, written only when set.
- `src/Modules/Audit/Contracts/AuditContract.cs` -- factory pattern. Add the verifier and retention factories here.
- `src/Adapters/Postgres/Migrations/Migration20261102070000SealAuditChains.cs` -- pattern for the guard functions (`CREATE OR REPLACE`) and CHECKs.
- `src/Adapters/Postgres/Migrations/Migration20261102030000CreateOperationTables.cs` -- holds the latest rendered job guard. `tests/Isolation/Jobs/JobGuardTests.cs:48` requires the latest guard-carrying migration to equal `OperationsContract.RenderGuard(ProductionRegistry)`.
- `src/Modules/Operations/Core/ProductionJobs.cs` -- registry; Deployment-wide types need a `JobReview`. `Core/OperationJobs.cs` shows fan-out into per-Tenant jobs in each Tenant's own scope.
- `src/Modules/Operations/Core/OperationService.cs`, `Contracts/OperationRegistry.cs` -- the `ProductionOperations` registry (empty today) and the stage handler shape. Stage bodies run as `gk_worker`.
- `src/Gatekeep.Host.Worker/JobSchedule.cs` -- add the daily retention entries.
- `src/Gatekeep.Cli/Program.cs` -- `args switch` and the connection and password file handling to reuse. `Gatekeep.Cli.csproj` -- add the Audit reference; `tests/Architecture/module-edges.txt` needs `dependency Cli -> Audit`, then run the generator.
- `deploy/postgres/generate-passwords.sh`, `role-passwords.sh` -- `gk_cli` has no password ("nothing logs in as it yet"). `deploy/compose.yaml:281` -- `cli` service gets only the migrator secret.
- `tests/Isolation/Stack/ComposeConfigTests.cs` -- `Each_service_gets_exactly_its_own_secrets`. `deploy/ci/stack-check.sh` -- runs the real stack.
- `tests/Isolation/MigrateCommandTests.cs` -- how tests run the Cli process. `tests/Isolation/Audit/SealerTests.cs` -- backdating rows as superuser with `session_replication_role = replica`, and `ChainCheck`.
- `tests/Architecture/PersistenceRuleTests.cs` -- pattern for source-scanning rules.
- `docs/threat-model.md` -- T-31, TB-6; `docs/install.md` -- operator commands.

## Tasks & Acceptance

**Execution:**
- [ ] `src/Gatekeep.Kernel/Retention/RetentionPeriods.cs` -- `public const int LogDays = 90` and `public const int LogFloorDays = 90`, with the §5.2 quote -- one Kernel file for §5.2 values.
- [ ] `src/Adapters/Postgres/Migrations/Migration20261102080000AuditRetention.cs` -- on both event tables add `checkpoint_epoch bigint`, `checkpoint_seq bigint`, `checkpoint_hash bytea`, with a `CHECK` that all three are set exactly when `type_code = 'audit.retention.checkpoint'`. Update the insert guard to refuse that type from any role but `gk_retention`, and the update guard's envelope comparison to stay correct. Re-render the job guard for the new job types. -- AD-16 checkpoint.
- [ ] `src/Modules/Audit/Core/ChainHash.cs`, `AuditSealer.cs`, `Contracts/ChainEnvelope.cs` -- optional checkpoint members (hash as lower-case hex), read and hashed by the sealer.
- [ ] `src/Modules/Audit/Core/AuditRetention.cs`, `Contracts/IAuditRetention.cs` -- `ApplyAsync(CommandContext, DateTimeOffset now)` cuts one chain as the Boundaries say. `PurgeAsync(CommandContext, DateTimeOffset now)` deletes the whole chain only if every event is sealed and older than the period, and returns whether it did.
- [ ] `src/Modules/Audit/Core/AuditVerifier.cs`, `Contracts/IAuditVerifier.cs` -- `VerifyAsync(CommandContext)` walks the context's chain in `seq` order. It checks for a gap, for `prev_hash` linking, for a recomputed hash and for a constant epoch. A first row above `seq = 1` must be preceded by a checkpoint in the chain naming `seq - 1` and that row's `prev_hash`. It returns a report of problems and counts.
- [ ] `src/Modules/Operations/Core/ProductionJobs.cs`, `ProductionOperations` -- job types `audit.retention.sweep` (Deployment-wide, `gk_worker`; fans out one `audit.retention.apply` per Tenant), `audit.retention.apply` (Tenant, run as `gk_retention`), `audit.retention.deployment` (Deployment-wide, run as `gk_retention`) and `audit.chain.purge` (Tenant, run as `gk_retention`; throws while retention hasn't ended, so it retries). Add an Operation type `audit.chain.purge` whose Tenant stage enqueues that job. Reviews recorded.
- [ ] `src/Gatekeep.Host.Worker/JobSchedule.cs` -- daily sweep and Deployment retention entries.
- [ ] `src/Gatekeep.Cli/Program.cs`, `Gatekeep.Cli.csproj` -- `gatekeep audit verify --connection-file <path> [--password-file <path>]`, plus the env-var form like `migrate`. It lists Tenants, verifies the Deployment chain and each Tenant chain in its own scope, and prints one line per problem with no row content.
- [ ] `deploy/postgres/*.sh`, `deploy/compose.yaml`, `deploy/postgres/cli.connection` -- give `gk_cli` a generated password secret. The `cli` service gets it and its connection file through `GATEKEEP_CLI_CONNECTION_FILE` and `GATEKEEP_CLI_PASSWORD_FILE`. `deploy/ci/stack-check.sh` runs `cli audit verify` and expects exit 0.
- [ ] `tests/Isolation/Audit/VerifyTests.cs`, `RetentionTests.cs`, `PurgeTests.cs`, `tests/Isolation/AuditVerifyCommandTests.cs` -- cover the matrix. The command tests run the real Cli process.
- [ ] `tests/Architecture/RetentionRuleTests.cs` -- the constant is a `const` of at least the floor. No source outside Kernel declares a retention period. No host setting key, route pattern or Cli argument contains "retention" (case-insensitive), job and event type codes excepted.
- [ ] `tests/Isolation/Stack/ComposeConfigTests.cs`, job guard and registry tests, `MigrateCommandTests` count -- updated for the new secret, types and migration.
- [ ] `docs/threat-model.md`, `docs/install.md` -- T-31 and TB-6 built parts and gaps; the `audit verify` command.

**Acceptance Criteria:**
- Given the Compose stack, when `cli audit verify` runs, then it exits 0 (stack check).
- Given a running `Host.Worker` whose schedule enqueues the sweep, when the sweep job runs, then each Tenant gets one `audit.retention.apply` job run as `gk_retention`.
- Given the retention constant, when the architecture test reads it, then it is a `const` of at least 90 days, and nothing configures it.
- Given a started `audit.chain.purge` Operation for a Tenant whose events are all past retention and sealed, when its jobs finish, then the Tenant has no `audit_event` or `audit_detail` rows.

## Spec Change Log

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 35 findings — high 1, medium 10, low 16, false 4, maybe-false 4
- findings:
  - `[false]` `[reject]` Intent AC1: missing end isn't detected — the epic places off-server heads in Story 7.2, and T-31 states the gap.
  - `[low]` `[reject]` Intent AC2: cuts by row age, not by seal unit, and keeps the head — "whole sealed ranges" holds for a contiguous sealed prefix. Keeping the head is the 7.1 deferred item's fix.
  - `[maybe-false]` `[reject]` Intent AC3: the rule is a source scan and doesn't model Prod Tenants — no Tenant environment exists yet, and one value at the floor meets §5.2 for every Tenant. It would be low if true.
  - `[low]` `[reject]` Intent AC4: erasure tested by raw detail delete through the library — no erasure flow exists (Story 5.9), and the hash excludes detail by construction.
  - `[maybe-false]` `[reject]` Intent AC5: no deletion marker, and retention runs from the newest event — Tenant deletion is a later story. The newest event is the latest evidence a deleted Tenant can have. It would be low if true.
  - `[medium]` `[patch]` Gap: a checkpoint that names the wrong range would still be accepted — tests added for a mismatched or tampered checkpoint and for rows missing after a cut.
  - `[medium]` `[patch]` Gap: nothing pins the checkpoint members in the hash — exact canonical envelope test added, plus a changed-checkpoint-column verify test.
  - `[medium]` `[patch]` Gap: the scheduled Deployment retention job never runs end to end — Worker test added.
  - `[low]` `[reject]` Gap other: the purge Operation reports success once the job is queued — its result code is `purge_queued`, a dead job writes `operations.job.dead` (G-17), and nothing starts this Operation yet.
  - `[medium]` `[patch]` Gap other: verify fails falsely right after a cut — an unsealed matching checkpoint now accounts for the cut range; Cli test added.
  - `[medium]` `[patch]` Blind: false verify failure after a cut — same fix as the Gap row.
  - `[medium]` `[patch]` Blind: the epoch check compares to the first row, flagging every later row — now compares to the previous row and reports once.
  - `[low]` `[patch]` Blind: a genesis row with a non-null `prev_hash` passes verify — now reported altered.
  - `[medium]` `[patch]` Blind: a mismatched checkpoint gets a misleading reason and is untested — own reason and tests, same fix as the Gap row.
  - `[low]` `[reject]` Blind: the purge Operation succeeds before purging — same reason as the Gap row.
  - `[low]` `[reject]` Blind: retention and purge write no audit event or alert, and a gap refusal is only a job failure — alerts derive from `operations.job.dead` in the alerts story (AD-17, G-17).
  - `[medium]` `[patch]` Blind: the cutoff uses the Worker clock while `occurred_at` uses the database clock — cutoff now from the database's `now()`.
  - `[low]` `[reject]` Blind: the active-job check races its enqueue — the chain lock makes a duplicate cut a no-op, and the guard fix adds surface.
  - `[low]` `[reject]` Blind: missing tests for skip-if-queued paths — duplicates are harmless under the chain lock; the Deployment job test is added through the Gap row.
  - `[low]` `[patch]` Blind: "1 problems" — pluralised. No Ctrl+C handling and no `--tenant` option are rejected: a verify walk is read-only, and neither is in the story.
  - `[low]` `[reject]` Blind: the handler discards the deleted count and logs nothing — the checkpoint row records each cut.
  - `[false]` `[reject]` Blind: `ChainLock.Add` is a general parameter helper — a naming preference with no named harm.
  - `[low]` `[reject]` Blind: the retention rule test catches only obvious cases — no source declares another period, and the cutoff comes only from `RetentionPeriods.LogDays`.
  - `[low]` `[patch]` Blind: garbled threat-model sentence — punctuation fixed.
  - `[high]` `[patch]` Edge: daily checkpoints keep a cut chain recent, so the purge never succeeds — checkpoints are left out of the purge recency test and `NewestEvent`, and an expired prefix made only of checkpoints isn't cut; test added.
  - `[medium]` `[patch]` Edge: the purge job falls due as a newer checkpoint lands and goes dead — same fix as the row above.
  - `[low]` `[patch]` Edge: `PurgeAsync` returns true with a row committed after its check — it now returns whether the chain is empty.
  - `[low]` `[patch]` Edge: any `ArgumentException` is reported as a bad connection file — catch narrowed to creating the data source.
  - `[low]` `[reject]` Edge: one chain's database error stops the summary — the command exits 1 with a failure line, which an operator reruns; per-chain recovery adds surface.
  - `[medium]` `[patch]` Edge: an altered first-row epoch flags every later row — same fix as the Blind epoch row.
  - `[low]` `[patch]` Edge: `ChainCheck` ignores the checkpoint columns — now reads and hashes them.
  - `[false]` `[reject]` Edge (claim): retention never ends for a deleted Tenant — a true outcome, fixed through the high row above, so this claim row adds nothing new.
  - `[maybe-false]` `[reject]` Intent: `gk_cli` credentials and Compose changes are beyond the intent — needed to run the named command on the Docker-only stack. It would be low if true.
  - `[maybe-false]` `[reject]` Blind: unbounded problems list — the epoch fix removes the cascade, and other problems are one per broken row. It would be low if true.
  - `[false]` `[reject]` Gap other: scheduled verify automation hits the window — duplicate of the window row, fixed there.

## Design Notes

- **Contiguous cut:** S = (lowest `seq` of a sealed row at or after the cutoff) − 1. If there is none, S = head − 1. Delete rows with `seq <= S` only when S is at least the first remaining `seq`. A late writer's old row past a newer one stays.
- **Keeping the head** answers Story 7.1's deferred item: the chain never restarts at `seq = 1`.
- **Checkpoint row:** `type_code = 'audit.retention.checkpoint'`, `system` actor, no target. It's unsealed when written, and the next seal pass links it to the head.
- **Verify output** (one line per problem; exit 1):
  ```
  chain 0f3c…: epoch 1 seq 3: altered (hash doesn't match)
  chain deployment: seq 1-2: missing (no checkpoint names seq 2)
  verified 4 chains, 1,203 sealed rows, 2 problems
  ```
- **Tail deletion** (head removed) is undetectable until Story 7.2's off-server heads. The threat model says so.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: locked restore, build with 0 warnings, Architecture and Isolation tests all pass.
- `docker compose -f deploy/compose.test.yaml run --rm --build stack` -- expected: the stack check passes, including `cli audit verify`.
- `dotnet run --project tests/Architecture/Generator` (inside the test image) -- expected: no diff beyond line endings.

## Auto Run Result

Status: done

**Summary:** `gatekeep audit verify` walks every chain as `gk_cli` and reports each altered or missing row by chain, epoch and seq. Daily retention under `gk_retention` cuts whole expired sealed prefixes, keeping the last real event, and writes a checkpoint carrying the last deleted hash inside its own envelope. The 90-day period is a Kernel constant held to the §5.2 floor by an architecture test. An `audit.chain.purge` Operation deletes a Tenant's whole chain once every event is sealed and past retention.

**Files:**
- `src/Gatekeep.Kernel/Retention/RetentionPeriods.cs` -- the §5.2 constants.
- `src/Adapters/Postgres/Migrations/Migration20261102080000AuditRetention.cs` -- checkpoint columns and CHECK, checkpoint-only-by-`gk_retention` insert guard, re-rendered job guard.
- `src/Modules/Audit/Core/AuditRetention.cs`, `AuditVerifier.cs`, `ChainLock.cs`, `ChainHash.cs`, `AuditSealer.cs`, and the matching contracts -- cut, purge, verify, checkpoint envelope members.
- `src/Modules/Operations/Core/AuditRetentionJobs.cs`, `ProductionJobs.cs`, `ProductionOperations` -- four job types and the purge Operation.
- `src/Gatekeep.Host.Worker/JobSchedule.cs` -- daily sweep and Deployment retention.
- `src/Gatekeep.Cli/Program.cs` -- `audit verify`, shared connection-file handling.
- `deploy/` -- `gk_cli` password secret, `cli.connection`, stack check runs `cli audit verify`.
- `tests/Isolation/Audit/*`, `AuditVerifyCommandTests.cs`, `Jobs/WorkerStartupTests.cs`, `tests/Architecture/RetentionRuleTests.cs`, and updated existing tests.
- `docs/threat-model.md`, `docs/install.md`.

**Review:** 35 findings across four layers: 18 rows patched (12 fixes, one of them the high: daily checkpoints kept a cut chain recent, so the purge could never run), 0 deferred, 17 rejected with reasons in the triage log.

**Follow-up review:** not recommended. The one high was patched, and its fix is held by `Dormant_chain_cut_on_two_days_gets_one_checkpoint_and_stays_purgeable`, which runs the failing scenario. Every other patch is a test or a small correction that ran and passed, so no unverified risk can be named.

**Verification:** in the `gatekeep/tests:epic7` image: build with 0 warnings, Architecture 343 of 343, and Isolation 1124 of 1125. The one failure was the recurring local IPv6 "Network is unreachable" on a test's PostgreSQL connection, before its code ran. The rerun of the Audit and Worker tests passed 316 of 316, that test included. The stack check, which runs `cli audit verify` on the real Compose stack, runs in CI on the PR. It wasn't run locally because it rebuilds shared `gatekeep/*:local` images.

**Residual risks:** a deleted tail, head included, and a superuser deleting a prefix with a matching forged checkpoint, both stay undetectable until Story 7.2's off-server heads. Nothing marks a Tenant deleted, so the purge Operation could be started for a live Tenant whose events are all past retention. A purge or a gap-refused cut is visible only as a job outcome until the alerts story. Existing installs must rerun the `passwords` step for `gk_cli`.
