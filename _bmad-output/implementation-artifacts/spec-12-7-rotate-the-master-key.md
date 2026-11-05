---
title: 'Story 12.7: Rotate the Master Key'
type: 'feature'
created: '2026-11-05'
status: 'done'
baseline_revision: 'c68541de79aa21f1d1a0f4f3f2195b5db804246b'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-12-context.md'
  - '{project-root}/docs/key-custody.md'
  - '{project-root}/docs/threat-model.md'
warnings: [oversized]
deferred:
  - summary: >-
      No test shows that sys/rotate/root actually changes the root key, so an old generation plus a pre-rotation snapshot still failing to open later data is unproven.
    evidence: |-
      The keyring term is checked and must rise, but removing the sys/rotate/root call would pass every test. Proving it needs a snapshot-and-restore harness, which arrives with backups (Stories 12.1 and 12.2).
    location: >-
      deploy/openbao/rotate-root-key.sh
    severity: medium (unverified)
  - summary: >-
      "Transit rewrap" is a version rotation: existing ciphertext isn't moved to the new versions, and old versions stay decryptable.
    evidence: |-
      OpenBao 2.7.2 rewrap ignores associated_data, so no Gatekeep ciphertext can be rewrapped without decrypting it (G-16). Before this story, docs/threat-model.md already assigned that to Stories 12.2 and 13.4.
    location: >-
      src/Gatekeep.Cli/RotateTransitKeysCommand.cs
    severity: medium
  - summary: >-
      "Sign-in keeps working" is shown on the custody operations sign-in relies on, not by an actual sign-in across a rotation.
    evidence: |-
      End-user sign-in doesn't exist yet (Hosted answers 404; Epic 2). To settle it, sign in before and after a rotation once a sign-in flow runs in the stack check.
    location: >-
      deploy/ci/stack-check.sh
    severity: medium (unverified)
  - summary: >-
      Escrow retention ("until the last backup needing it has expired") and "neither appears in a backup" are stated rules and volume searches, not checks against a real backup set.
    evidence: |-
      No backup set or manifest exists yet. Story 12.1's manifest records the Master Key generation, and the backup story must exclude master/ and the escrow drives and check it.
    location: >-
      docs/runbooks/master-key-rotation.md
    severity: medium
---

<intent-contract>

## Intent

**Problem:** The Master Key (OpenBao's static seal key, `secrets/master/master-key`) can't be rotated. The Compose secret is one fixed file, the key ID `gatekeep-master-1` is baked into the image, and no step or runbook exists. A suspected exposure therefore has no response short of re-installing, which would force every User to re-enrol (NFR-3, AD-10, G-3).

**Approach:** Ship a rehearsed, Docker-only rotation. A `prepare` step makes generation N+1 and moves generation N aside. OpenBao restarts in rotation mode (current = N+1, previous = N), which re-wraps its root key under the new seal key. A root-key step, run with a quorum of escrowed recovery keys, rotates OpenBao's root key and barrier keyring, so an old generation plus an old snapshot can't open new snapshots. OpenBao then restarts on N+1 alone, `finish` destroys the online copy of N, and `gatekeep rotate-transit-keys` gives every secret-class Transit key a new version. Users do nothing, and every value made before rotation still works.

## Boundaries & Constraints

**Always:**
- **Generations.** Key ID is `gatekeep-master-<N>` (N ≥ 1, no leading zero). It lives in a non-secret file `master/master-key-id` next to `master/master-key`. `keygen` writes `gatekeep-master-1` with a new key. OpenBao refuses to start if the ID file is missing or malformed. Generation 1 keeps the ID `gatekeep-master-1`, so today's seal data still unseals.
- **Rendered config.** The OpenBao image's entrypoint (`deploy/openbao/start-openbao.sh`) renders the server config onto a tmpfs from `/etc/openbao/openbao.hcl`, then `exec`s `bao server`. The config holds only `file://` references and key IDs, never key bytes. Only when both `/run/secrets/master_key_previous` and `/run/secrets/master_key_previous_id` exist (rotation mode) does it add `previous_key_id`/`previous_key` and set `disable_unauthed_generate_root_endpoints = false` on the socket listener. Base mode never enables unauthenticated generate-root.
- **Base Compose.** `openbao` gets exactly the secrets `master_key` and `master_key_id`. The rotation-only pieces live in the overlay `deploy/compose.rotate.yaml`:
  - `openbao` gains `master_key_previous` and `master_key_previous_id` (from `master/previous/`).
  - `master-key-rotate` uses the openbao image, `profiles: [rotate]`, no network, the hardened anchors, and binds only `master/` plus the `openbao-socket` volume.
  - `master-key-rotate-root` is the same, but has the socket only and no `master/`. It takes recovery shares on stdin (`run --rm -T`).
- **`master-key-rotate prepare`** refuses if `master/previous/` already holds a key. It moves the current key and ID to `master/previous/` (mode 0400, owner 100:1000), then writes N+1 with the same atomic, no-overwrite rules as `generate-master-key.sh`. It prints only paths, the two generation numbers and the escrow label `master-key-gen<N+1>-<UTC date>`.
- **`master-key-rotate-root`** reads the threshold of recovery shares from stdin. It gets a short-lived root token through the legacy `sys/generate-root/attempt` and `/update` endpoints, using an OTP generated and decoded in the container. It calls `sys/rotate/root` (root key) and `sys/rotate/keyring` (barrier term), then revokes the token on success, failure or interrupt (`trap`). It prints the new key term only. It refuses unless OpenBao is in rotation mode, which the unauthenticated endpoint answering shows.
- **`master-key-rotate finish`** refuses unless `bao status` over the socket reports unsealed, and refuses if `master/previous/` is empty. It then shreds `master/previous/*` and prints the retirement rule: keep generation N escrowed until the last backup taken before this rotation has expired.
- **`gatekeep rotate-transit-keys`** (Gatekeep.Cli, cli AppRole) rotates `dep-email` and `dep-payload`, plus for every `tenant` row its `totp`, `social`, `email`, `payload` and `tpk` keys, through `IKeyCustody.RotateAsync`. It prints counts only. A key that doesn't exist (`Rejected`) is counted as skipped, not as a failure. Any other failure exits non-zero, naming the key and the `KeyCustodyFailure` and nothing else. A rerun is harmless.
- Never touched: `hmac-*` and `dep-hmac` (T-54: HMAC outputs would change), `sig-*` and `mgmt-*` (Signing Key lifecycle, Epic 9), and `dep-records`. `min_decryption_version` stays where it is, so every older ciphertext still decrypts (G-16 stays open).
- No key byte, recovery share, OTP or token is ever written to stdout or stderr, a volume, an env var, an image or the repo. The key search in `stack-check.sh` covers both generations during the rotation window.
- Every runbook shell line starts with `docker` (DockerOnlyRuleTests).

**Never:**
- No `transit/rewrap` (G-16). No re-encryption of stored ciphertext, no raising `min_decryption_version`, no `sys/*` grant in any AppRole policy, no persistent root token, no `bao` in the CLI image.
- No backup or manifest code (Stories 12.1 and 12.2), and no `gatekeep rekey` (Story 13.4).

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Full rotation | gen 1 Deployment, values made before rotation | each step exits 0; OpenBao unseals on gen 2 alone; sign, verify, decrypt, HMAC and unwrap of the earlier values all still work through the hosts' AppRoles | — |
| Old key after rotation | gen 1 key only, data rotated to gen 2 | OpenBao stays sealed | healthcheck unhealthy |
| Second prepare | `master/previous/` holds a key | refused, nothing moved | exit non-zero, names the dir |
| Root step in base mode | OpenBao without the overlay | refused before reading any share | exit non-zero |
| Wrong or too few shares | bad recovery share | no token, nothing rotated, attempt cancelled | exit non-zero |
| Finish while sealed | OpenBao sealed or unreachable | previous key kept | exit non-zero |
| Missing or bad key ID | `master-key-id` absent, or `gk-1` | OpenBao doesn't start | names the file, no key bytes |
| Transit rerun | `rotate-transit-keys` twice | second run rotates again and exits 0 | — |

</intent-contract>

## Code Map

- `deploy/openbao/openbao.hcl:36-43` -- the `seal "static"` stanza, fixed `current_key_id = "gatekeep-master-1"`; becomes the template the entrypoint renders.
- `deploy/docker/openbao.Dockerfile:135-150` -- pinned `openbao/openbao:2.7.2@sha256:5046…`; COPYs hcl and scripts; `ENTRYPOINT bao server -config=…` → the new start script.
- `deploy/openbao/generate-master-key.sh` -- 32 bytes, mode 0400, `100:1000`, no overwrite (94-97), atomic `ln` (114). Reuse it for `prepare`, and add the ID file.
- `deploy/openbao/setup.sh` -- pattern for socket use, the root-token `trap` revoke (153-155) and print-paths-only. Recovery shares are 5 with threshold 3 (77-81).
- `deploy/compose.yaml:141-163` (openbao, add tmpfs `/tmp`), `:343-350` (keygen), `:374-390` (openbao-setup), `:392-394` (secrets).
- `deploy/openbao/policies/cli.hcl` -- `transit/keys/{totp,social,email,payload,tpk}-*` and `dep-*` already allow update, so `/rotate` is covered; no change expected.
- `src/Gatekeep.Kernel/Secrets/IKeyCustody.cs:36-99`, `KeyName.cs:49-95` (`ForTenant`, `ForDeployment`), `KeyCustodyException.cs:19-32`.
- `src/Adapters/OpenBao/OpenBaoKeyCustody.cs:223-228` -- `RotateAsync` posts `keys/{key}/rotate`.
- `src/Modules/Keys/Contracts/KeysContract.cs` -- `SecretClassKeys(tenantId)`; filter out `Hmac` for rotation.
- `src/Gatekeep.Cli/Program.cs:24-54` (usage and `args` switch), `InitCommand.cs:209-259` (custody options from `GATEKEEP_CUSTODY_*`, `KeyCustodyException` handling, the pattern to copy). `tenant` has `Select` for `gk_cli` (`TableRegistry.cs:75-85`).
- `tests/Isolation/Custody/OpenBaoFixture.cs` (~180-215 `Build(generateKey, setup)`, `start-openbao.sh` stand-in copying `/secrets/master-key`), `SealTests.cs`, `CustodyTests.cs:111`, `tests/Isolation/CliProcess.cs`.
- `tests/Isolation/Stack/ComposeConfigTests.cs:205, 223, 392, 454-485` and `tests/Architecture/KeyCustodyRuleTests.cs:123, 170` -- pin today's secret shape; update them for `master_key_id` and the overlay.
- `deploy/ci/stack-check.sh:108-161, 469-493` -- install, key search (`find-key.mjs`), OpenBao stop and key-missing checks; add the rehearsal here.
- `tests/Architecture/DockerOnlyRuleTests.cs:16-52, 117-149` -- scans `docs/runbooks/*.md` automatically.
- Throwaway test on 2.7.2 (2026-11-05): current = gen 2 plus previous = gen 1 unseals and Transit decrypts; afterwards gen 1 alone fails (`unknown key id`). The legacy `sys/generate-root/attempt` answers without a token only with `disable_unauthed_generate_root_endpoints = false` on the listener. The CLI's new `generate-root-token` path always answers 403, so call the endpoints over HTTP on the socket, not with `bao operator generate-root`. Root and keyring rotation after generate-root were not proven: the first isolation test must prove them, and record the exact endpoint in Design Notes.

## Tasks & Acceptance

**Execution:**
- `deploy/openbao/start-openbao.sh` + `openbao.hcl` + `openbao.Dockerfile` -- render config to `/tmp`, validate the ID files, rotation mode as in the Boundaries, `exec bao server`.
- `deploy/openbao/generate-master-key.sh` -- also write `master-key-id` (`gatekeep-master-1`) with a new key.
- `deploy/openbao/rotate-master-key.sh` -- `prepare` and `finish` subcommands.
- `deploy/openbao/rotate-root-key.sh` -- the root and keyring rotation over the socket.
- `deploy/compose.yaml`, `deploy/compose.rotate.yaml` -- `master_key_id` secret, openbao tmpfs, the overlay services and secrets.
- `src/Gatekeep.Cli/RotateTransitKeysCommand.cs` + `Program.cs` -- `rotate-transit-keys` as in the Boundaries; add a usage line.
- `tests/Isolation/Custody/MasterKeyRotationTests.cs` (+ fixture support for the ID and previous files) -- run the real scripts against OpenBao 2.7.2 for every I/O row except the Transit rerun. Create a signing key, a `totp` ciphertext with associated data, an HMAC and a wrapped data key before rotation, then check them after with host AppRole tokens issued before rotation. Assert no output contains a key byte, share or token.
- `tests/Isolation/RotateTransitKeysCommandTests.cs` -- two Tenants: every non-HMAC secret-class key gains a version, and `hmac-`, `sig-` and `dep-records` don't. A missing key is skipped. The rerun row, and old ciphertext still decrypts.
- `tests/Isolation/Stack/ComposeConfigTests.cs`, `tests/Architecture/KeyCustodyRuleTests.cs` -- the new secret shape; overlay services hardened, no network, the right binds; only `keygen` and `master-key-rotate` bind `master/`; base `openbao.hcl` and its rendering have no unauthenticated generate-root.
- `deploy/ci/stack-check.sh` -- rehearsal on the installed stack. Run `prepare`, rotation-mode up, the root step with shares from the stack's own `recovery/openbao-init.json` (kept until then), key search for both generations, base up, `finish`, `cli rotate-transit-keys`. Every service healthy and `/healthz` 200 after; gen 1 alone stays sealed.
- `docs/runbooks/master-key-rotation.md` -- when to rotate, prerequisites (recovery shares and escrow drives), every step's `docker compose` command, escrow labelling and the retirement rule, recovery if a step fails partway, and a "Rehearsal record" table filled from this story's stack-check run (date, environment = Docker Desktop Linux VM, commit, result).
- `docs/key-custody.md`, `docs/install.md`, `docs/threat-model.md` -- the ID file; the rotation pointer; G-3 (12.7 part closed), G-16 (rotation doesn't rewrap), a T-row for rotation-mode unauthenticated generate-root.

**Acceptance Criteria:**
- Given a running Deployment with existing Signing Keys, secrets and host tokens, when the full rotation runs, then no User or Tenant data changes, every pre-rotation value still verifies, decrypts or matches through the hosts, and every service is healthy afterwards.
- Given a new generation, when `prepare` and `finish` run, then both generations' bytes are absent from every volume, image and container env during the window, the old online copy is gone after `finish`, and the runbook keeps every escrowed generation until the last backup needing it has expired.
- Given the stack-check rehearsal on the Docker Desktop VM, when it passes, then `docs/runbooks/master-key-rotation.md` records its date, commit and result.

## Spec Change Log

## Review Triage Log

### 2026-11-05 — Review pass
- verdicts: 39 findings — high 0, medium 15, low 21, false 0, maybe-false 3
- findings:
  - `[low]` `[defer]` intent-alignment: Admin WebAuthn sign-in exists, but no sign-in runs across a rotation. Grouped with the sign-in deferral: End-user sign-in isn't built yet. Admin sign-in doesn't touch the rotated Transit keys, so all a rotation could do to it is the OpenBao restart the stack check already covers.
  - `[medium]` `[defer]` intent-alignment: "Transit rewrap" became a version rotation. This is pre-existing G-16, assigned to Stories 12.2 and 13.4 before this story.
  - `[low]` `[reject]` intent-alignment: the stack check rotates only Deployment keys (0 Tenants). The Tenant path runs against real OpenBao and policies in `RotateTransitKeysCommandTests`. A Tenant in the stack check needs the Admin creation flow, which is a large addition for little gain.
  - `[medium]` `[defer]` intent-alignment: escrow retention and backup exclusion aren't checked against a backup. No backup set exists yet (Story 12.1).
  - `[low]` `[reject]` intent-alignment: the rehearsal passes the shares on stdin and the prompt is untested. The prompt is a `stty -echo` read loop around the same parsing. Testing it needs a pseudo-terminal harness, which costs more than the defect is likely to.
  - `[maybe-false]` `[defer]` intent-alignment: no pre-rotation snapshot is opened. Grouped with the root-key proof deferral.
  - `[medium]` `[patch]` verification-gap: nothing checks that the root step leaves no root token. Fixed: the test plants an extra root token, asserts the "revoked 1 other root token" warning and its 403, then counts exactly one root token remaining, the counter's own.
  - `[maybe-false]` `[defer]` verification-gap: the `sys/rotate/root` effect is unproven. Settled only by a snapshot harness, so deferred (medium, unverified).
  - `[medium]` `[patch]` verification-gap: the two rotation-mode refusals in start-openbao are untested. Fixed: a new Theory covers a half-present pair and an out-of-sequence generation.
  - `[low]` `[patch]` verification-gap: the gk_cli role check is untested. Fixed: a `gk_admin` case asserts exit 1 and the message, and that no key gained a version.
  - `[low]` `[reject]` verification-gap: the prepare rollback is untested. It needs a test seam that makes `generate-master-key.sh` fail after prepare's own checks have passed. It's unlikely in practice, and the runbook now covers recovery.
  - `[low]` `[patch]` verification-gap: the canary doc comment was misplaced. Fixed: `InitAsync`'s summary is back above it.
  - `[medium]` `[patch]` verification-gap: Rejected (400 or 404) was counted as skipped. Fixed: a rejected `dep-*` key fails the run, naming it. Tenant keys keep the skip, because `keys/{name}/rotate` takes no body, so a 400 there means the key is missing.
  - `[low]` `[patch]` blind-hunter: the canary doc comment. Grouped with the doc-comment row and fixed there.
  - `[medium]` `[patch]` blind-hunter: Rejected hides failures. Grouped with the Rejected row and fixed there.
  - `[medium]` `[patch]` blind-hunter: the root step reports success with no term check. Fixed: it reads the term before and after, and fails unless it rose.
  - `[medium]` `[patch]` blind-hunter: the step order isn't enforced, so `finish` can run without the root step. Fixed: the root step writes a non-secret marker on the socket volume, `prepare` clears it, and `finish` refuses without it.
  - `[maybe-false]` `[defer]` blind-hunter: the main security claim (no old snapshot opens later data) is untested. Grouped with the root-key proof deferral.
  - `[medium]` `[patch]` blind-hunter: the start-openbao refusals are untested. Grouped with the start-openbao row and fixed there.
  - `[low]` `[patch]` blind-hunter: install.md's ID-file fix fails on Compose's empty directory. Fixed: the command removes an empty directory first.
  - `[low]` `[reject]` blind-hunter: the rotation services fall back silently to the local OpenBao image. With `pull_policy: never`, a missing image fails loudly, and the runbook tells a release install to add the release files. A `:?` guard needs release-overlay entries for services that exist only in the rotate overlay.
  - `[low]` `[reject]` blind-hunter: the stack check has no Tenants. Grouped with the intent-alignment Tenant row.
  - `[low]` `[patch]` blind-hunter: a cancelled attempt is reported as a refused share. Fixed: the message now names both causes.
  - `[low]` `[reject]` blind-hunter: the rotation writes no Gatekeep audit event. OpenBao's audit device already records generate-root, `sys/rotate/*` and every Transit rotate. A Gatekeep event type would need an AD-15 alert-table entry, which is wider than this story.
  - `[low]` `[patch]` blind-hunter: the rehearsal record names uncommitted work. Fixed at finalization, when the row was refilled with the committed revision.
  - `[low]` `[patch]` blind-hunter: prepare can be killed after removing generation N. Fixed: "If a step fails" covers it, with a `docker` command that moves `previous/` back.
  - `[medium]` `[patch]` edge-case: `finish` runs after `prepare` while the old OpenBao process never restarted. Grouped with the step-order row: the marker exists only after a root step, which needs rotation mode.
  - `[medium]` `[patch]` edge-case: steps 3 and 4 skipped, then `finish`. Grouped with the step-order row.
  - `[low]` `[patch]` edge-case: a transient error in the rotation-mode check counts as base mode. Fixed: only the 405 "unsupported operation" refusal counts as base mode, and anything else fails.
  - `[low]` `[patch]` edge-case: prepare interrupted mid-move. Grouped with the blind-hunter prepare-window row.
  - `[medium]` `[patch]` edge-case: a failing accessors list is ignored. Fixed: the step fails before rotating.
  - `[medium]` `[patch]` edge-case: a failed `sys/key-status` read still exits 0. Grouped with the term-check row.
  - `[low]` `[reject]` edge-case: a race could cancel another user's attempt. It needs a socket user to start an attempt in the gap between two calls during an Operator-run window. That's the T-57 residual, and guarding it adds nonce-matching branches.
  - `[medium]` `[patch]` edge-case: a 400 is counted as skipped. Grouped with the Rejected row.
  - `[medium]` `[patch]` edge-case: missing Deployment keys pass silently. Grouped with the Rejected row.
  - `[low]` `[reject]` edge-case: generate-master-key.sh doesn't cap the generation at 9 digits. Reaching it would take 10^9 rotations.
  - `[low]` `[patch]` edge-case: install.md and the directory. Grouped with the blind-hunter install.md row.
  - `[low]` `[patch]` edge-case: grep's `[ \t]` doesn't match a tab. Fixed: `[[:space:]]`.
  - `[low]` `[patch]` edge-case: the canary doc comment. Grouped with the doc-comment row.

## Design Notes

Why root key rotation: a seal rotation only re-wraps OpenBao's root key. An attacker holding generation N and any snapshot taken under N recovers that root key, which still decrypts the keyring in every later snapshot. Rotating the root key, plus a new keyring term, after the seal change closes that, so generation N opens only snapshots taken before the rotation. This is exactly the escrow-retention rule.

Endpoints proven on 2.7.2 (2026-11-05, `MasterKeyRotationTests`, all over the socket with the `bao` CLI's generic `read`/`write`/`delete`, since the image has no curl): `GET sys/generate-root/attempt` answers without a token only in rotation mode (base mode: 405 `unsupported operation`) and gives `required`; `PUT sys/generate-root/attempt` with no body starts an attempt and returns the OTP itself (26 characters; an `otp` parameter is ignored, and `bao operator generate-root -generate-otp`/`-decode` call the new `sys/generate-root-token` path, which answers 403); `PUT sys/generate-root/update` with `key` (read from stdin, `key=-`) and `nonce`, once per share, until `complete`; the `encoded_token` is unpadded base64, and the root token is it XOR the OTP byte by byte (done with `od` and busybox awk's `xor`); then, with that token, `PUT sys/rotate/root` (root key) and `PUT sys/rotate/keyring` (new term, read back from `GET sys/key-status`), and `auth/token/revoke-self`. Before rotating, the step also revokes every other token whose policies are exactly `["root"]`, found through `auth/token/accessors`, so a run that couldn't revoke its own leaves nothing behind for long. `DELETE sys/generate-root/attempt` cancels.

Why Transit rotation without rewrap: G-16 blocks moving ciphertext without decrypting it. New Transit versions exist only in post-rotation storage, so values written afterwards are out of reach of an old snapshot. Retiring old versions belongs to Stories 12.2 and 13.4.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: all architecture and isolation tests pass.
- `GATEKEEP_HOST_REPO=… GATEKEEP_HTTP_PORT=18080 GATEKEEP_HTTPS_PORT=18443 docker compose -f deploy/compose.test.yaml run --rm --build stack` (from PowerShell) -- expected: the stack check passes, including the rotation rehearsal.

## Auto Run Result

Status: done

An earlier session had locked this worktree and then stopped after regenerating the epic context. This run reverted that file and started from current `main`.

**Summary:** the Master Key (OpenBao's static seal key) can now be rotated, rehearsed, with no User action. The rotation runs in this order:
1. `master-key-rotate prepare` writes generation N+1 and moves N to `master/previous/`.
2. OpenBao restarts in rotation mode through `deploy/compose.rotate.yaml`, with both generations, and re-wraps its root key under N+1. The rendered config is the only place the socket's unauthenticated generate-root endpoints are opened.
3. `master-key-rotate-root` uses 3 of the 5 escrowed recovery shares to make a short-lived root token through the legacy `sys/generate-root` endpoints. With it, it sweeps any other root tokens, rotates the root key and the barrier keyring (the term must rise), writes a non-secret marker, and revokes its token.
4. OpenBao restarts in base mode on N+1 alone.
5. `finish` refuses unless OpenBao is unsealed, out of rotation mode and has the marker. It then shreds the online copy of generation N.
6. `gatekeep rotate-transit-keys` gives every non-HMAC secret-class Transit key a new version.

The Master Key's ID now lives in `master/master-key-id` (`gatekeep-master-<N>`). `start-openbao.sh` renders the server config from it.

**Files:**
- `deploy/openbao/start-openbao.sh`, `openbao.hcl`, `deploy/docker/openbao.Dockerfile`: the entrypoint that renders the config from the key ID; rotation mode.
- `deploy/openbao/generate-master-key.sh`: writes the key ID file too.
- `deploy/openbao/rotate-master-key.sh`: `prepare` and `finish`.
- `deploy/openbao/rotate-root-key.sh`: root key and keyring rotation with recovery shares.
- `deploy/compose.yaml`, `deploy/compose.rotate.yaml`: the `master_key_id` secret; the rotation-only overlay and its two services.
- `src/Gatekeep.Cli/RotateTransitKeysCommand.cs`, `Program.cs`, `InitCommand.cs`, `Gatekeep.Cli.csproj`: `gatekeep rotate-transit-keys`.
- `deploy/ci/stack-check.sh`: the full rotation rehearsal on the installed stack.
- `tests/Isolation/Custody/MasterKeyRotationTests.cs`, `OpenBaoFixture.cs`, `start-openbao.sh`, `SealTests.cs`: every I/O row against real OpenBao 2.7.2.
- `tests/Isolation/RotateTransitKeysCommandTests.cs`, `tests/Isolation/Canary/*`: the CLI command and its canary flow.
- `tests/Isolation/Stack/ComposeConfigTests.cs`, `tests/Architecture/KeyCustodyRuleTests.cs`, `module-edges.txt`: the secret shape, overlay hardening, and base mode never opening generate-root.
- `docs/runbooks/master-key-rotation.md`: the new runbook and rehearsal record.
- `docs/key-custody.md`, `docs/install.md`, `docs/threat-model.md`: the ID file, the upgrade note, G-3 (the 12.7 part closed), G-16, and T-57.

**Review:**
- Patched: 25 rows in 16 entries (11 medium and 5 low entries).
- Deferred: 4 entries, covering 7 rows: root-key proof, rewrap (G-16), real sign-in, backup-set checks.
- Rejected: 8 low rows, each with its reason in the triage log: Tenant keys in the stack check (2), the prompt path, prepare rollback seam, image fallback, Gatekeep audit event, attempt race, 9-digit cap.

**Follow-up review recommended: true.** Patched entries by verdict: high 0, medium 11, low 5. The unverified risk is the new step-order marker on the `openbao-socket` volume. Nothing covers a marker left behind by a rotation abandoned after the root step and then restarted with a fresh `prepare`. `prepare` clears it, but the case where `finish` meets a marker from an older rotation is reasoned, not tested.

**Verification:**
- `docker build` / `docker run` of `deploy/docker/tests.Dockerfile` (the worktree-only tag `gatekeep/tests:story-12-7`):
  - Architecture: 596/596 passed.
  - Isolation: 2,204 of 2,206 passed. The other 2 (`TenantCreationTests`, `BootstrapClaimTests`) were Admin host 503s under Docker load. They passed on rerun (56/56).
  - An earlier run lost 4 to the known `192.168.65.254` connect timeout.
- `docker compose -f deploy/compose.test.yaml run --rm --build stack` (project `gk1207`, ports 18180/18543): passed, ending `rotation rehearsal passed` and `passed`.

**Residual risks:**
- The interactive share prompt is untested; only the piped path was exercised.
- During the rotation window, any user of the socket can start or cancel a root-generation attempt (T-57).
- An install from before this story needs `master/master-key-id` written before OpenBao starts (`docs/install.md`).
- The stack check builds the shared `gatekeep/*:local` tags, so a parallel stack check could swap images mid-run.
