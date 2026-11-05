---
title: 'Story 12.7: Rotate the Master Key'
type: 'feature'
created: '2026-11-05'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-12-context.md'
  - '{project-root}/docs/key-custody.md'
  - '{project-root}/docs/threat-model.md'
warnings: [oversized]
deferred: []
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

## Design Notes

Why root key rotation: a seal rotation only re-wraps OpenBao's root key. An attacker holding generation N and any snapshot taken under N recovers that root key, which still decrypts the keyring in every later snapshot. Rotating the root key, plus a new keyring term, after the seal change closes that, so generation N opens only snapshots taken before the rotation. This is exactly the escrow-retention rule.

Why Transit rotation without rewrap: G-16 blocks moving ciphertext without decrypting it. New Transit versions exist only in post-rotation storage, so values written afterwards are out of reach of an old snapshot. Retiring old versions belongs to Stories 12.2 and 13.4.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: all architecture and isolation tests pass.
- `GATEKEEP_HOST_REPO=… GATEKEEP_HTTP_PORT=18080 GATEKEEP_HTTPS_PORT=18443 docker compose -f deploy/compose.test.yaml run --rm --build stack` (from PowerShell) -- expected: the stack check passes, including the rotation rehearsal.
