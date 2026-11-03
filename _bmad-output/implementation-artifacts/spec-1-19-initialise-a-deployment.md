---
title: 'Story 1.19: Initialise a Deployment'
type: 'feature'
created: '2026-11-03'
status: 'done'
baseline_revision: '759896cb13a90d3313a78f43d5d07b6f3df2778f'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/docs/threat-model.md'
  - '{project-root}/docs/install.md'
warnings: []
deferred: []
---

<intent-contract>

## Intent

**Problem:** Bootstrap (Story 1.21) has to start from a token that only the Operator, on the server, can read. Nothing creates that token yet, and nothing confirms that the Deployment's own keys exist before Admin flows need them. Those keys are `dep-email`, `dep-payload` and `dep-hmac`, plus `dep-records` for off-server signing.

**Approach:** Add `gatekeep init` to `Gatekeep.Cli`, run as `docker compose run --rm cli init`. In order, it:
1. Makes sure the four Deployment keys exist in OpenBao.
2. Writes a fresh one-time 256-bit token to a root-only file on the Docker host.
3. Stores only the token's SHA-256 and a 15-minute expiry in a new `control.bootstrap_state` row, with an audit event.

It can be run again to reissue the token until bootstrap is complete.

## Boundaries & Constraints

**Always:**
- **Token:**
  - 32 bytes from a CSPRNG (`RandomNumberGenerator`), written as 64 lowercase hex characters plus a newline.
  - The database stores only `SHA-256(token)` as `bytea`, never the token.
  - The token never appears in stdout, stderr, logs, audit events, exceptions or the database.
  - stdout gives only the file's path inside the host secrets directory and the expiry in UTC.
- **Token file (Docker only):**
  - It is `${GATEKEEP_SECRETS_DIR:-./secrets}/bootstrap/bootstrap-token` on the host, bind-mounted read-write into the `cli` service at `/gatekeep/bootstrap`. Only `cli` mounts it.
  - The file is mode `0600` and its directory `0700`, both owned by the `cli` uid. On the host, only root (or that uid) can read it. That is the Docker-only meaning of "root-only" (AD-10 amendment). Record it in the spec and the threat model.
  - It is written atomically: a temp file is created with `0600` from the start (never widened later), fsynced, then renamed over the old one.
  - It is never written into an image, a data volume or a backup.
- **`control.bootstrap_state`:**
  - A new migration creates it as a single-row table (`id smallint primary key check (id = 1)`), with these columns:
    - `token_sha256 bytea not null`, with a length check of 32;
    - `issued_at timestamptz not null`;
    - `expires_at timestamptz not null`;
    - `completed_at timestamptz null`.
  - Register it in `TableRegistry` as a `control` table owned by Admins, following the existing migrations.
  - Grants: `gk_cli` may `SELECT, INSERT, UPDATE` it, and `gk_admin` may `SELECT, UPDATE` it, because Story 1.21 consumes it. No role may `DELETE` or `TRUNCATE` it. `gk_hosted` and `gk_worker` get nothing. Follow the repository's existing grant and default-privilege pattern, and make the Architecture and Isolation table-coverage tests pass.
  - `expires_at` is `issued_at` plus 15 minutes, using the database clock (`now()`), so host clock skew doesn't matter.
- **Reissue:**
  - Run again while `completed_at` is null, `init` replaces the hash, `issued_at` and `expires_at`, which voids the old token.
  - Once `completed_at` is set, it refuses: a fixed message, exit code 1, no file written and no row change.
- **Ordering and concurrency:**
  1. The Deployment keys are ensured first (`IKeyCustody.CreateKeyAsync` for each `DeploymentKeyClass`, which is idempotent). If OpenBao fails, `init` exits 1 with a fixed message and nothing else changes.
  2. In one database transaction: lock the row (`SELECT … FOR UPDATE`, or an insert-on-conflict that takes the lock), check `completed_at`, write the temp file, upsert the row with the audit event, rename the file into place, then commit.
  - Two concurrent `init`s therefore serialise, and the file always ends up holding the token whose hash is committed.
  - If the commit fails after the rename, the file holds an unusable token, and `init` reports the failure and exits 1. Rerunning `init` fixes it.
  - If the directory is missing or not writable, `init` exits 1 before any row change.
- **Audit:**
  - Each issue writes the Deployment Log event `bootstrap.token.issued` in the same transaction, through the Story 1.5 audit writer as the cli actor.
  - The event carries the expiry and whether it was a reissue. It carries no token or hash.
  - Declare it in `src/Modules/Admins/Contracts/AdminsEvents.cs`, or wherever Admins declares its events, and regenerate `docs/audit-events.md`.
- **CLI:**
  - Add `init` to the usage text and the argument switch, using the cli service's existing environment (`GATEKEEP_CLI_CONNECTION_FILE`, `GATEKEEP_CLI_PASSWORD_FILE`, and OpenBao through the existing adapter on the socket with the `cli` AppRole).
  - Add an optional `--token-dir <path>` defaulting to `/gatekeep/bootstrap`.
  - Exit codes: 0 success, 1 failure, 2 usage. These already exist.
- **Compose and docs:**
  - `deploy/compose.yaml` adds the bind mount to `cli`.
  - The setup that creates the secrets directory also creates `bootstrap/` with `0700`.
  - `docs/install.md` gains the init step: run it, read the token with `sudo cat`, finish bootstrap within 15 minutes or rerun `init`.
  - `docs/threat-model.md`'s bootstrap row describes the file as above.
- **Tests:** Isolation tests against real Postgres and OpenBao, through Testcontainers as the existing OpenBao and CLI tests do, with the cli roles and policy. They cover every matrix row. Architecture tests cover the table registry and grants. Nothing runs outside Docker.

**Ask First:** none. This runs unattended, so decide and record the decision in the spec.

**Never:**
- No token in any output, log, exception, audit event or database column.
- No delete path for `bootstrap_state`, and no code that sets `completed_at`. Consuming the token and completing bootstrap belong to Story 1.21.
- No Host.Admin route or page: that is Story 1.21.
- No new OpenBao policy grants beyond what `cli.hcl` already allows for `dep-*`.
- Nothing runs on the host outside Docker.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| First init | Empty `bootstrap_state`; keys absent or present | Four `dep-*` keys exist; file holds 64 hex chars + newline, mode 0600, dir 0700; row has SHA-256 of the file's token, `expires_at = issued_at + 15 min`; one `bootstrap.token.issued` event; exit 0; stdout shows path and expiry only | — |
| Reissue | Row exists, `completed_at` null | New token in file; old hash replaced; new expiry; event marks reissue; exit 0 | — |
| Completed | `completed_at` set | Fixed refusal message; exit 1; file and row unchanged; no event | — |
| Keys idempotent | All four keys already exist | Unchanged (same versions); init succeeds | — |
| OpenBao down | Socket unavailable or login refused | Fixed message; exit 1; no file, no row change | — |
| Database down | Connection fails | Fixed message; exit 1; no token file left behind | — |
| Dir not writable | Missing or read-only token dir | Fixed message; exit 1; no row change | — |
| Concurrent init | Two runs at once | Both exit 0 or one waits; final file's SHA-256 equals the committed hash | — |
| No leak | Any run | Token absent from stdout, stderr, logs, the audit row and every DB column (canary scan) | Test fails otherwise |
| Usage | `init extra-arg` | Usage text; exit 2 | — |
| Grants | `gk_hosted`, `gk_worker`; DELETE as `gk_cli` or `gk_admin` | Permission denied | — |

</intent-contract>

## Code Map

- `src/Gatekeep.Cli/Program.cs` and its csproj: the CLI switch, connection helpers and exit codes. Check how `audit verify` builds its services.
- `src/Gatekeep.Kernel/Secrets/IKeyCustody.cs` and `KeyName.cs` (`KeyName.ForDeployment`, `DeploymentKeyClass`); `src/Adapters/OpenBao/*` (the adapter and its options); `deploy/openbao/policies/cli.hcl` and `setup.sh`, which already create the `dep-*` keys.
- `src/Adapters/Postgres/Migrations/*` (the latest is `Migration20261102110000…`) and `Schema/TableRegistry.cs`: the table, roles and grants.
- `src/Modules/Admins/*` (Contracts, Core and Adapters): where `bootstrap_state` and the audit event belong.
- The Story 1.5 audit writer in `src/Gatekeep.Kernel/Audit` and `src/Modules/Audit`, and the `docs/audit-events.md` generator (`tests/Architecture/Generator`).
- `deploy/compose.yaml` (the `cli` service and the secrets-dir setup tooling), `deploy/compose.test.yaml`, `docs/install.md`, `docs/threat-model.md`.
- `tests/Isolation/*`: the existing CLI (`audit verify`, migrate), OpenBao and grant tests to copy.
- Verification runs only in Docker: `docker compose -f deploy/compose.test.yaml run --rm --build tests`. Database timeouts in Isolation under parallel load pass on rerun.

## Tasks & Acceptance

**Execution:**
- [x] Migration, table registry and grants for `control.bootstrap_state`.
- [x] Admins: the bootstrap issue service, plus the `bootstrap.token.issued` event and the regenerated catalogue.
- [x] `Gatekeep.Cli`: the `init` command, the token file writer and the key ensuring.
- [x] Compose bind mount, secrets-dir setup, and the install and threat-model docs.
- [x] Isolation and Architecture tests for every matrix row.

**Acceptance Criteria:**
- Given `gatekeep init`, when it runs, then it writes a one-time 256-bit token to a root-only file, and stores only its SHA-256 with a 15-minute expiry.
- Given `gatekeep init`, when it completes, then the Deployment `email`, `payload`, `hmac` and off-server signing keys exist.

## Spec Change Log

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 50 findings — high 3, medium 19, low 22, false 6, maybe-false 0
- findings:
  - `[medium]` `[patch]` Intent: `gk_cli` can reopen a completed bootstrap — column grants and a trigger that freezes a completed row.
  - `[medium]` `[patch]` Intent: the decisions that changed the spec's contract aren't recorded — Design Notes updated.
  - `[medium]` `[patch]` Intent: Story 1.21 has nowhere to find the hash input — `BootstrapToken.Hash` in the Admins contract.
  - `[low]` `[patch]` Intent: the CLI chmods the directory before OpenBao is checked — no chmod; precheck first.
  - `[low]` `[patch]` Intent: stdout always names the default path — real path printed.
  - `[low]` `[patch]` Intent: no read-only directory test — run as a non-root uid.
  - `[low]` `[patch]` Intent: TB-9 and the bootstrap row are stale — threat model updated; AD-31 amended.
  - `[low]` `[patch]` Intent: usage omits the custody variables; the secret files aren't validated — both fixed.
  - `[low]` `[patch]` Intent: the docker-cat route prints the token to a container's output — noted in the install doc.
  - `[low]` `[reject]` Intent: a separate `bootstrap-dir` service, not the existing setup — each setup tool mounts only its own directory; recorded.
  - `[false]` `[reject]` Intent: two audit codes and no expiry in the event — the envelope holds only code, actor and IDs; recorded.
  - `[false]` `[reject]` Intent: `Actor.System` — no cli actor kind exists; recorded.
  - `[false]` `[reject]` Intent: the `Cli -> Adapters.OpenBao` edge — the CLI is a composition root; recorded.
  - `[false]` `[reject]` Intent: stack-check runs `cli init` — it checks modes and owner without printing the token.
  - `[false]` `[reject]` Intent: scope creep into Story 1.21 — none; an Architecture test enforces it.
  - `[false]` `[reject]` Intent: ordering and atomicity — match the spec.
  - `[medium]` `[patch]` Blind: `gk_cli` can clear `completed_at` — same fix as the Intent row.
  - `[medium]` `[patch]` Blind: `gk_admin` can plant its own hash — `gk_admin` may update only `completed_at`.
  - `[medium]` `[patch]` Blind: a failed commit destroys the valid token file — the previous token is kept and restored.
  - `[medium]` `[patch]` Blind: the rename isn't durable — directory fsynced.
  - `[medium]` `[patch]` Blind: times come from transaction start — `clock_timestamp()` in the upsert; tests order by chain seq.
  - `[low]` `[patch]` Blind: snapshot taken before the lock under stricter isolation — READ COMMITTED enforced; the upsert takes the lock.
  - `[low]` `[patch]` Blind: keys created before the refusal check — read-only precheck first.
  - `[low]` `[patch]` Blind: output names the default path — same fix as the Intent row.
  - `[low]` `[patch]` Blind: `CheckDirectory` chmods whatever it is given and follows symlinks — refuses instead.
  - `[low]` `[patch]` Blind: leftover temp files hold a live token — swept.
  - `[low]` `[patch]` Blind: the token is an immutable string — zeroable buffers.
  - `[low]` `[patch]` Blind: setup script aborts before its warning; symlinked dir — fixed.
  - `[low]` `[patch]` Blind: the short bind creates a root-owned directory — `create_host_path: false`, error names `bootstrap-dir`.
  - `[low]` `[patch]` Blind: the concurrency test doesn't force overlap — a held lock forces it.
  - `[low]` `[patch]` Blind: the mode and key-version tests prove nothing — rewritten.
  - `[low]` `[patch]` Blind: architecture regexes miss forms — widened, more file types.
  - `[high]` `[patch]` Gap: the keys-absent path never runs — fixture without the dep keys.
  - `[high]` `[patch]` Gap: the audit event differs from the spec and tests lock it in — decision recorded; same-transaction proof added.
  - `[high]` `[patch]` Gap: a database failure after staging is untested — trigger-forced failure tested.
  - `[medium]` `[patch]` Gap: commit failure after the rename is untested — deferred trigger tested, with restore.
  - `[medium]` `[patch]` Gap: same-transaction event unproven — `xmin` compared.
  - `[medium]` `[patch]` Gap: concurrency overlap not forced — same fix as the Blind row.
  - `[medium]` `[patch]` Gap: "not writable" untested and vacuous as root — non-root runs.
  - `[medium]` `[patch]` Gap: the directory-mode assertion is vacuous — new refusal rules tested.
  - `[medium]` `[patch]` Gap: "0600 from creation" unproven — inode change and a source assertion.
  - `[medium]` `[patch]` Gap: the database clock is unproven — source assertion on `clock_timestamp()`.
  - `[low]` `[patch]` Gap: missing custody settings untested; regex blind spots; hash not a canary; setup script and stack check thin — all added.
  - `[medium]` `[patch]` Edge: a kill leaves token-bearing temp files; no signal handling — swept; SIGINT and SIGTERM cancel cleanly.
  - `[medium]` `[patch]` Edge: lock wait shortens the window; no lock timeout — `clock_timestamp()` and a 30-second timeout.
  - `[medium]` `[reject]` Edge: a wrong-typed existing `dep-*` key passes — `setup.sh` fixes the types and `cli.hcl` denies the parameters; only OpenBao root could do it.
  - `[medium]` `[patch]` Edge: whole-table grants — same fix as the Intent row.
  - `[low]` `[patch]` Edge: root hides permission bugs; group- or world-writable dirs only warn; short bind syntax; no directory fsync; ambiguous commit message; default path printed; symlinked host directory; stale probe — all fixed.
  - `[low]` `[patch]` Edge: SHARE ROW EXCLUSIVE doesn't block readers — the Story 1.21 consumer must `SELECT … FOR UPDATE`, written in the contract.
  - `[low]` `[patch]` Edge: spec drift on the event — same fix as the Intent row.

## Design Notes

- **Root-only, Docker-only:** Gatekeep has no host access (the Docker-only proposal). The token sits in the host secrets directory beside the Master Key's directory, with `0700`/`0600` and the cli uid as owner. On the host that means root, or whoever holds that uid, can read it. Root and Docker access already count as full compromise (UJ-6, T-20).
- **Atomic file and row:** the row lock is held across the file rename, so whatever the file holds was issued under that lock, and a failure after the rename leaves only an unusable token.
- **Decisions made while building and reviewing:**
  - **Audit events:** two codes, `bootstrap.token.issued` and `bootstrap.token.reissued`, written as `Actor.System`. The audit envelope holds only a code, an actor and IDs, and there is no cli actor kind. The exact expiry lives in `bootstrap_state.expires_at`, and the event summary defines it as the issue time plus 15 minutes.
  - **Token hash:** SHA-256 over the 64 lowercase ASCII hex characters, with no newline. Story 1.21 hashes the submitted token with `BootstrapToken.Hash`, which trims surrounding whitespace first, and claims the row with `SELECT … FOR UPDATE`.
  - **Grants are column grants.**
    - `gk_cli` may update only the hash and the times, and may never set `completed_at`.
    - `gk_admin` may update only `completed_at`.
    - A trigger freezes a completed row.
    - The upsert's row lock (`INSERT … ON CONFLICT … WHERE completed_at IS NULL`) serialises concurrent runs, so no table lock is needed.
    - The upsert takes its times from `clock_timestamp()` and sets a 30-second lock timeout.
  - **Previous token kept until commit:** the previous token stays valid until the new one commits. A failure after the rename restores it, and the directory is fsynced after each rename.
  - **Directory checks:**
    - `init` refuses a symlinked directory or token, or a directory it doesn't own or that is group- or world-writable.
    - It changes no modes. The new `bootstrap-dir` setup service (`deploy/cli/prepare-bootstrap-dir.sh`) creates the directory as `0700`, owned by uid 10004.
    - The `cli` bind uses `create_host_path: false`.
  - **Custody settings:** the `cli` service reaches OpenBao through the `GATEKEEP_CUSTODY_*` variables and a new `Cli -> Adapters.OpenBao` edge. `src` may not name OpenBao paths outside the adapter.
  - **Install doc:** fenced commands must start with `docker` or `git`, so the doc reads the token through a `docker compose run` of `bootstrap-dir`, with `sudo cat` given inline.
  - **Stack check:** runs `bootstrap-dir` and `cli init` twice under the real uid, and checks modes and owner without printing the token.
  - **Not done:** checking the types of existing `dep-*` keys. `setup.sh` fixes the types, and `cli.hcl` denies the exportable and plaintext-backup parameters, so only OpenBao root could create a wrong-typed key.

## Auto Run Result

Status: done

**Summary:** `gatekeep init` (`docker compose run --rm cli init`) makes sure the four Deployment keys exist (`dep-email`, `dep-payload`, `dep-hmac`, `dep-records`). It then writes a one-time 256-bit token to `secrets/bootstrap/bootstrap-token` (0600 in a 0700 directory owned by the cli uid). It stores only the token's SHA-256 with a 15-minute expiry in the new single-row `control.bootstrap_state`, with a `bootstrap.token.issued` or `bootstrap.token.reissued` event in the same transaction. It reissues until bootstrap completes, and refuses after that. Column grants and a trigger stop any role reopening a completed bootstrap or planting a hash.

**Files:** `src/Gatekeep.Cli/` (Program, BootstrapTokenFile); `src/Modules/Admins/` (BootstrapIssuer, BootstrapToken, events, contract); the bootstrap_state migration and `TableRegistry`; `deploy/compose.yaml`, `deploy/cli/prepare-bootstrap-dir.sh`, `deploy/ci/stack-check.sh`; `docs/install.md`, `docs/threat-model.md`, `docs/audit-events.md`, `docs/architecture/module-dependencies.md`; the AD-31 amendment; `tests/Isolation/Bootstrap/*`, `tests/Architecture/BootstrapStateRuleTests.cs` and updated canary, catalogue and compose tests.

**Review:** 50 findings across four layers: 42 patched, 0 deferred, 8 rejected, each with its reason in the triage log.

**Follow-up review:** recommended. The review changed the locking, the grants and the file handling, and only the new tests prove them.

**Verification:** see the PR screenshot; the full suite passes in the `tests` container, and the stack check runs init twice under the real uid.

**Residual risks:** on a host, root or Docker access can read the token (T-20, UJ-6). Story 1.21 must hash with `BootstrapToken.Hash` and claim the row with `SELECT … FOR UPDATE`.
