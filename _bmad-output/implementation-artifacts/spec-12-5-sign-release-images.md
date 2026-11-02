---
title: 'Story 12.5: Sign release images'
type: 'feature'
created: '2026-11-02'
status: 'done'
baseline_revision: 'b6d501e4f54f58b3ee564b74318318fad63464f9'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-12-context.md'
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/docs/install.md'
warnings: [oversized]
deferred:
  - summary: >-
      release.env and the checked-out Compose files are unsigned, and install.md asks for no git verify-tag, so whoever controls the channel can name a lying verifier.
    evidence: |-
      Recorded as the T-48 residual. Story 12.6 checks image signatures inside gatekeep upgrade, independent of release.env's verifier choice.
    location: >-
      deploy/compose.release.yaml, docs/install.md
    severity: medium
  - summary: >-
      Nothing forces release-verify to run (or to re-run after release.env changes) before up.
    evidence: |-
      T-48 residual: "nothing stops up without it". Story 12.6 makes gatekeep upgrade refuse an image whose signature fails.
    location: >-
      deploy/compose.release.yaml
    severity: medium
  - summary: >-
      release-verify being a manual Operator step is the reason the intent's "so that an upgrade can't install a tampered release" is only met once Story 12.6 lands.
    evidence: |-
      Intent-alignment audit: the AC surface is met; the so-that surface is gatekeep upgrade (Story 12.6).
    location: >-
      docs/install.md
    severity: medium
  - summary: >-
      The verifier can be rolled back: an older, complete, signed release still passes release-verify.
    evidence: |-
      verify.sh checks that every image shares one release annotation, not which release is current. Story 12.6 limits upgrades to the previous minor release or its latest patch.
    location: >-
      deploy/release/verify.sh
    severity: medium
  - summary: >-
      release.yml's build step (non-root with the socket group, writing dist/, all six images through buildx OCI and syft) first runs on a real v* tag.
    evidence: |-
      The CI rehearsal builds openbao and release-tools only, as root, through compose.test.yaml. A failure would fail closed (nothing signed). Settle by running the workflow's exact docker run line in CI or on a schedule.
    location: >-
      .github/workflows/release.yml
    severity: medium (unverified)
  - summary: >-
      The release workflow as a whole (jobs, environment, runner label, repository settings) is only ever exercised by a real tag push.
    evidence: |-
      ReleaseConfigTests checks the YAML text only. Settle with a first rehearsal tag on a fork or a v0.0.x pre-release.
    location: >-
      .github/workflows/release.yml
    severity: medium (unverified)
---

<intent-contract>

## Intent

**Problem:** Gatekeep images are only ever built locally (`gatekeep/<svc>:local`). Nothing signs them, nothing records an SBOM, and nothing lets the Deployment run an exact released image. So an upgrade (Story 12.6) has nothing to verify and could install a tampered release (NFR-7, AR-33, AD-25).

**Approach:** Add a tag-triggered release workflow with two jobs. A secret-free `build` job runs the existing gates, then builds each release image to an OCI archive with an SPDX SBOM and its digest. A separate `sign` job runs on Esm's self-hosted signing runner behind a manual-approval environment. It pushes those exact digests to GHCR, signs each digest and attests its SBOM with cosign using a hardware-held key, and publishes a `release.env` naming every image by digest. A Compose overlay deploys from `release.env`. A `release-verify` tool checks every digest against a public key pinned in a host directory outside every image. A CI rehearsal runs the same scripts end to end with a throwaway software key against a local registry.

## Boundaries & Constraints

**Always:**
- Release images = every service in `deploy/compose.yaml` with a `build:` (today `hosted`, `admin`, `worker`, `cli`, `openbao`), named `ghcr.io/<owner>/gatekeep-<svc>`. A test derives the list from `docker compose config`, so a newly built service (Caddy from Story 1.11) fails until it's in the release.
- `build` job: `permissions: contents: read` only. No `secrets.*`, no `environment:`, no registry login, no `id-token`. It runs third-party code (dotnet/pnpm restore, syft) and outputs only workflow artifacts.
- `sign` job: `needs: build`, `runs-on: [self-hosted, gatekeep-signing]`, `environment: release-signing`. Permissions are `contents: write` and `packages: write` only. It never runs repository build steps. It only pushes the archives, signs and publishes.
- `publish.sh` refuses a signing key reference that isn't hardware (`pkcs11:` URI or cosign `--sk`) unless `GATEKEEP_RELEASE_REHEARSAL=1`. It refuses if a pushed digest differs from the digest the build job recorded.
- Signatures and attestations are made with `--tlog-upload=false`. The pinned key is the only root of trust, so verification needs no Sigstore egress.
- `release.env` holds only `GATEKEEP_<SVC>_IMAGE=<repo>@sha256:<64 hex>` lines. `compose.release.yaml` sets every built service's `image:` from it, uses `${VAR:?}` (fail if unset), and drops `build:` (`!reset`).
- The pinned key lives at `${GATEKEEP_TRUST_DIR:-./trust}/release-signing.pub`, a host directory resolved against `deploy/`. It's gitignored, never a Docker volume, never COPYed into an image, and mounted read-only into `release-verify` only.
- `release-verify` is hardened like the other tools (non-root, read-only, `cap_drop: [ALL]`, no-new-privileges, pids and log limits, no Compose secrets). It is the only service on a non-internal network, `registry`, which exists only in the overlay.
- Every new image (`release-tools`, buildkit, registry, syft and cosign sources) and every new action is pinned by digest or commit SHA.

**Never:**
- No change to `gatekeep upgrade` and no enforcement inside the CLI (Story 12.6). No private key, PIN or key file in the repo, a CI secret, an image or an env var. No keyless (OIDC/Fulcio) signing. No Caddy service edits (Story 1.11 is on another branch).

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Signed release | `release.env` digests signed by the pinned key, SBOM attested | `release-verify` exits 0, naming each image verified | — |
| Unsigned digest | an image pushed but never signed | refused, names the image | exit non-zero |
| Wrong key | signed with key A, trust dir holds key B | refused | exit non-zero |
| Tag ref | `GATEKEEP_X_IMAGE=...:v1.2.3` | refused before any network call | exit non-zero, "not pinned by digest" |
| No pinned key | trust file missing | refused | exit non-zero, names the expected path |
| Software key, real run | `GATEKEEP_SIGNING_KEY=cosign.key`, rehearsal unset | `publish.sh` refuses before pushing | exit non-zero |
| Digest drift | pushed digest differs from the build's recorded digest | `publish.sh` stops, nothing signed | exit non-zero |

</intent-contract>

## Code Map

- `.github/workflows/ci.yml` -- existing `build` and `stack` jobs; checkout pinned `actions/checkout@3d3c42e5…` (v7.0.1); reuse that style for the new rehearsal job.
- `deploy/compose.yaml` -- built services use `build: {context: .., dockerfile: deploy/docker/<svc>.Dockerfile}` + `image: gatekeep/<svc>:local`; `keygen`/`openbao-setup` reuse `gatekeep/openbao:local` and must also be overridden; all networks `internal: true`; `x-hardened`/`x-limits` anchors to copy.
- `deploy/compose.test.yaml` -- test-only services with Docker socket (`tests`, `stack`); add `release` here.
- `deploy/ci/stack-check.sh` -- pattern for a socket-driven check script: `until_true` polling, `trap cleanup`, `fail()` dumping logs, `GATEKEEP_HOST_REPO`.
- `tests/Isolation/Stack/ComposeConfigTests.cs` -- `Config(file, args…)` runs `docker compose config --format json`; `Only_the_test_services_get_the_Docker_socket` hard-codes `["stack","tests"]` (update); `AssertFromLinesPinned`, `Volumes`, `Strings` helpers to reuse; `Repository.Root`.
- `deploy/docker/*.Dockerfile` -- header comment "Signing is Story 12.5" in each app Dockerfile (update wording); `tests.Dockerfile` already has docker CLI + compose plugin.
- `.gitignore` -- add `/deploy/trust/` and `/deploy/release.env`; `.dockerignore` must exclude `deploy/trust/`.
- `docs/install.md` -- Docker-only install steps; add "Install a signed release" section.
- `docs/threat-model.md` -- add release-integrity rows (tampered image, compromised build dependency reaching signing key).

## Tasks & Acceptance

**Execution:**
- `deploy/docker/release-tools.Dockerfile` -- pinned busybox (or alpine) base + `cosign`, `crane`, `syft` binaries COPYed from their pinned official images; non-root `USER`; scripts under `/opt/gatekeep/release` -- one image for build-side SBOM/digest work, rehearsal and `release-verify`.
- `deploy/release/build.sh` -- for each release service: `docker buildx build` with a `docker-container` builder (pinned `moby/buildkit` image), `--provenance=false --sbom=false --output type=oci,dest=dist/<svc>.tar`; then syft writes `dist/<svc>.spdx.json`; read the manifest digest from the archive's `index.json` into `dist/digests.txt` (`<svc> sha256:…`). Service list from `GATEKEEP_RELEASE_SERVICES` (default: all five) -- secret-free build output.
- `deploy/release/publish.sh` -- inputs `dist/`, `GATEKEEP_REGISTRY`, `GATEKEEP_RELEASE_TAG`, `GATEKEEP_SIGNING_KEY`, `COSIGN`/`CRANE` overrides. Enforce the hardware-key rule; `crane push` each archive; compare the pushed digest to `digests.txt`; `cosign sign` and `cosign attest --type spdxjson` on `<repo>@<digest>` with `--tlog-upload=false`; write `dist/release.env` -- the only step that touches the key.
- `deploy/release/verify.sh` -- read `GATEKEEP_*_IMAGE` from env; refuse non-digest refs and a missing key file; `cosign verify` and `cosign verify-attestation --type spdxjson` with `--key /trust/release-signing.pub --insecure-ignore-tlog=true` per image; print one line per image -- the pre-deploy check, used by the overlay and the rehearsal.
- `.github/workflows/release.yml` -- `on: push: tags: ['v*']`; top-level `permissions: {}`; `build` job (run `docker compose -f deploy/compose.test.yaml run --rm --build tests`, then `build.sh` in `release-tools`, then upload `dist/` with pinned `actions/upload-artifact`); `sign` job as in the Boundaries (download artifact; `docker login ghcr.io` with `GITHUB_TOKEN`; `publish.sh` with host cosign (pivkey build) and `GATEKEEP_SIGNING_KEY` from a repo **variable**, not a secret; `gh release create` attaching `release.env`, SBOMs and `digests.txt`).
- `deploy/compose.release.yaml` -- overlay: each built service plus `keygen`/`openbao-setup` gets `image: ${GATEKEEP_<SVC>_IMAGE:?…}`, `build: !reset null`, `pull_policy: missing`; adds the `release-verify` service (profile `release`, `release-tools` image by digest var `GATEKEEP_RELEASE_TOOLS_IMAGE`, the env vars, ro bind of the trust file, `registry` network). Header comment gives usage with `--env-file deploy/release.env`.
- `deploy/ci/release-check.sh` + `release` service in `deploy/compose.test.yaml` -- rehearsal: start a pinned `registry` container, generate a throwaway cosign key pair, run `build.sh` for `openbao` only, then `publish.sh` with `GATEKEEP_RELEASE_REHEARSAL=1`, then `verify.sh`. Assert it passes. Then assert refusal for an unsigned pushed digest, a different key, a tag ref, a missing key file, and a software key without rehearsal. Clean up always.
- `.github/workflows/ci.yml` -- add `release` job running the rehearsal (`docker compose -f deploy/compose.test.yaml run --rm --build release`).
- `tests/Isolation/Stack/ReleaseConfigTests.cs` -- parse `release.yml` (YamlDotNet if already a test dependency, else line-scoped regex) and resolved overlay config: build job has no `secrets.`, `environment`, registry login or write permission; sign job `needs: build`, self-hosted `gatekeep-signing`, `environment: release-signing`, no `secrets.` other than `GITHUB_TOKEN`; overlay with a sample env resolves every base `build:` service (plus `keygen`/`openbao-setup`) to an `@sha256:` image with no `build`; missing var fails `config`; `release-verify` hardened, trust bind read-only and under the trust dir, sole member of `registry`; no Dockerfile COPYs `trust`; new Dockerfile `FROM`s pinned.
- `tests/Isolation/Stack/ComposeConfigTests.cs` -- socket test expects `["release","stack","tests"]` (with `--profile release` if profiled).
- `.gitignore`, `.dockerignore`, `deploy/docker/tests.Dockerfile.dockerignore` -- ignore `deploy/trust/`, `deploy/release.env`, `dist/`.
- `docs/release-signing.md` -- runbook: YubiKey PIV key generation (`cosign piv-tool generate-key`), runner setup (label, repo-scoped, tag-only workflow), `release-signing` environment with Esm as required reviewer, cutting a release, exporting the public key (`cosign public-key --sk`) onto the server.
- `docs/install.md` -- "Install a signed release": put the key at `deploy/trust/release-signing.pub`, download `release.env`, run `release-verify`, then the existing steps with `-f deploy/compose.release.yaml --env-file deploy/release.env`.
- `docs/threat-model.md`, app Dockerfile headers -- record the release controls; replace "Signing is Story 12.5" with a pointer to `docs/release-signing.md`.

**Acceptance Criteria:**
- Given a pushed `v*` tag, when `release.yml` runs, then `build` (no secrets, read-only token) and `sign` (self-hosted, approval-gated, hardware key) are separate jobs, and the release carries `release.env`, one SBOM per image and signatures plus SBOM attestations in GHCR.
- Given `release.env` and the pinned key in `deploy/trust/`, when the Operator runs `release-verify` and then `up` with the overlay, then every Gatekeep container runs an image referenced by `@sha256:` digest, and no image contains the key.
- Given the CI rehearsal, when it runs, then the signed path passes and every refusal row of the I/O matrix fails closed.

## Spec Change Log

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 33 findings — high 0, medium 15, low 12, false 4, maybe-false 2
- findings:
  - `[low]` `[reject]` intent-alignment: hardware-key check is only on the key reference's form; a `pkcs11:` URI to a software token passes — no script can attest hardware; the runbook makes the YubiKey the procedure, and the fix would need hardware attestation plumbing.
  - `[medium]` `[patch]` intent-alignment: SBOMs proven for openbao only; the no-SBOM refusal is untested — grouped with verification-gap SBOM row; fixed there.
  - `[medium]` `[defer]` intent-alignment: `release-verify` is a manual step nothing enforces — grouped with blind-hunter "nothing forces release-verify"; deferred to Story 12.6.
  - `[maybe-false]` `[defer]` intent-alignment: release.yml itself never runs before a real tag — grouped with verification-gap build-step row; deferred.
  - `[low]` `[reject]` intent-alignment: DockerOnlyRuleTests gains a per-file exception for the signing runbook — needed for the signing machine, which runs no part of a Deployment; scoped to one file and pinned by `Only_the_signing_runbook_may_give_signing_machine_commands`.
  - `[false]` `[reject]` intent-alignment: `ComposeConfigTests.Config` now clears every `GATEKEEP_*` variable — the tests pass their own environment; clearing is stricter isolation, no caller relies on an inherited value (942 isolation tests pass).
  - `[false]` `[reject]` intent-alignment: worktree named `epic-12`, not per story — the intent asked for a new worktree and a new branch; both are new.
  - `[medium]` `[patch]` verification-gap: publish.sh's hyphen-to-underscore variable naming is never exercised — rehearsal now builds `openbao release-tools` and asserts exactly `GATEKEEP_OPENBAO_IMAGE` and `GATEKEEP_RELEASE_TOOLS_IMAGE` by digest.
  - `[medium]` `[patch]` verification-gap: verify.sh's "no SBOM attestation" refusal is never exercised — rehearsal adds a signed-but-not-attested digest, refused.
  - `[medium]` `[patch]` verification-gap: release-verify as deployed is never run — rehearsal runs the release-tools image as uid 10010, read-only, tmpfs `/tmp`, own entrypoint, key mounted read-only at `/trust`; ReleaseConfigTests asserts the entrypoint and verify.sh's default key path.
  - `[maybe-false]` `[defer]` verification-gap: release.yml's build step (non-root + socket group, writing `dist/`, all six images) first runs on a real tag — fails closed (nothing signed); deferred.
  - `[low]` `[reject]` verification-gap: "pushed nothing" check passes if `crane ls` fails for any reason — the refusal's own message is asserted first and the key check precedes any push; hardening the probe adds branches for an unlikely case.
  - `[medium]` `[patch]` blind-hunter: the pushed-vs-recorded digest check is presented as a tamper control, though both come from the build artifact — reworded as transfer integrity in release-signing.md, TB-14 and T-49.
  - `[medium]` `[patch]` blind-hunter: signatures not bound to a service or release, so slot swaps and mixed releases pass — `cosign sign -a org.gatekeep.service -a org.gatekeep.release`; verify.sh checks the repository name, the service annotation and one release across images; rehearsal refuses both; T-48 records rollback to an older complete release as residual until Story 12.6. Attestations carry no annotations (cosign 2.6.5 `attest` has no `-a`).
  - `[medium]` `[defer]` blind-hunter: release.env and the checked-out Compose files are unsigned; no `git verify-tag` — already recorded as T-48 residual; Story 12.6 checks signatures in `gatekeep upgrade`.
  - `[medium]` `[defer]` blind-hunter: nothing forces release-verify before `up` — T-48 residual; Story 12.6 enforces it in `gatekeep upgrade`.
  - `[medium]` `[patch]` blind-hunter: no recovery for a sign job failing partway — runbook section "A sign job that fails partway" (re-run only the sign job within the 7-day artifact window); publish step create-or-upload.
  - `[medium]` `[patch]` blind-hunter: GHCR packages are private by default — runbook makes each package public and linked; install.md requires pullable images.
  - `[medium]` `[patch]` blind-hunter: CI never builds the real release set — grouped with verification-gap naming row (release-tools now built and verified, including as deployed); the .NET images remain covered only by the tests/stack builds.
  - `[low]` `[patch]` blind-hunter: signing machine tools unchecked and untrusted archives parsed — publish.sh requires cosign v2.6.5 and crane v0.22.1 outside the rehearsal (crane accepts the v0.22.1 tag commit, which the pinned image prints); T-49 residual names tar/crane parsing.
  - `[low]` `[patch]` blind-hunter: test gaps (release-verify uid uniqueness, artifact names, stack gate) — ReleaseConfigTests asserts all three.
  - `[low]` `[patch]` blind-hunter: workflow details (7-day retention, bare `${VAR:?}`, step 6 checks one image) — runbook notes the approval window; overlay messages unified; step 7 runs release-verify against the exported key. Main-ancestry check rejected: the tag ruleset limits who can tag.
  - `[medium]` `[patch]` edge-case: slot swap or older release passes verify — grouped with blind-hunter binding row.
  - `[low]` `[patch]` edge-case: digests.txt naming only some services publishes an incomplete release.env — publish.sh requires exactly `RELEASE_SERVICES` outside the rehearsal; ReleaseConfigTests holds it equal to build.sh's list.
  - `[false]` `[reject]` edge-case: last digests.txt line without a newline is skipped — build.sh writes every line with `echo`, always newline-terminated (`deploy/release/build.sh:66`).
  - `[low]` `[patch]` edge-case: tag regex accepts `+build`, an invalid OCI tag — regex allows only a `-` pre-release.
  - `[low]` `[patch]` edge-case: `sk:` with an empty slot — refused.
  - `[low]` `[patch]` edge-case: earlier services stay tagged when a later digest drifts — grouped with blind-hunter recovery row; the drift is refused before any signing and the runbook covers cleanup by re-running the sign job.
  - `[low]` `[patch]` edge-case: sign-job re-run fails on an existing GitHub release — grouped with blind-hunter recovery row; create-or-upload.
  - `[medium]` `[patch]` edge-case: GHCR private packages — grouped with blind-hunter GHCR row.
  - `[medium]` `[defer]` edge-case: release.env changing between verify and up deploys unverified images — grouped with blind-hunter enforcement row.
  - `[low]` `[reject]` edge-case: any `pkcs11:` URI passes the hardware rule — same as the intent-alignment hardware row.
  - `[false]` `[reject]` edge-case: spec says five images, build.sh lists six — release-tools is required by the spec's own `GATEKEEP_RELEASE_TOOLS_IMAGE`; the fix would edit the spec.

## Design Notes

Why a self-hosted runner: "hardware-held by Esm" plus "separate CI jobs" means the sign job must reach a physical YubiKey. A GitHub environment with Esm as required reviewer is the gate. The runner accepts only this repo's tag workflow. Why no Rekor: the server verifies offline against its pinned key, which is the trust root AD-25 names. Why OCI archives: the digest is fixed in the secret-free job and only re-checked, never recomputed, after signing.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: all architecture and isolation tests pass, including `ReleaseConfigTests`.
- `docker compose -f deploy/compose.test.yaml run --rm --build release` -- expected: rehearsal prints PASS for the signed path and each refusal.
- `GATEKEEP_HOST_REPO=… docker compose -f deploy/compose.test.yaml run --rm --build stack` -- expected: unchanged stack check still passes.

## Auto Run Result

Status: done

An earlier run was blocked because the Docker Desktop engine returned 500 on every call. After Docker came back, the run resumed from verification.

**Summary:** a tag-triggered release workflow with a secret-free `build` job (gates, OCI archives, SPDX SBOMs, digests) and a separate `sign` job. The `sign` job runs on a self-hosted, approval-gated runner. It pushes the archives to GHCR, refuses digest drift, signs each digest with service and release annotations using a YubiKey key, attests its SBOM, and publishes `release.env`. A Compose overlay deploys every image by digest, and `release-verify` checks every image against a key pinned in `deploy/trust/`. A CI rehearsal runs the real scripts with a throwaway key.

**Files:**
- `.github/workflows/release.yml`: build and sign jobs.
- `.github/workflows/ci.yml`: new `release` rehearsal job.
- `deploy/release/build.sh`, `publish.sh`, `verify.sh`: build, sign, verify.
- `deploy/ci/release-check.sh`, plus a `release` service in `deploy/compose.test.yaml`: the rehearsal.
- `deploy/compose.release.yaml`: deploy-by-digest overlay and `release-verify`.
- `deploy/docker/release-tools.Dockerfile`: cosign, crane, syft and buildx image.
- `deploy/docker/{hosted,admin,worker,cli}.Dockerfile`: header comments.
- `.gitignore`, `.dockerignore`, `tests.Dockerfile.dockerignore`: trust dir, `release.env`, `dist/`.
- `tests/Isolation/Stack/ReleaseConfigTests.cs`: workflow, overlay and verifier tests.
- `ComposeConfigTests.cs`: socket test and shared helpers.
- `tests/Architecture/DockerOnlyRuleTests.cs`: signing-runbook exception.
- `docs/release-signing.md`: runbook.
- `docs/install.md`: "Install a signed release".
- `docs/threat-model.md`: TB-14, TB-16, T-24, T-48 and T-49, plus key rows.

**Review:**
- 33 findings, logged above.
- Patches applied: 19 rows, grouped into 12 fixes. By verdict: 11 medium and 8 low.
- Deferred: 6 rows (4 medium, 2 maybe-false), recorded in frontmatter `deferred`.
- Rejected: 8 (4 false, 4 low), each with its reason in the triage log.
- Also fixed during verification: a static-initialization compile error in `ReleaseConfigTests`, and the crane version check, which wrongly refused the pinned v0.22.1 build.

**Follow-up review recommended:** `true`. Two or more medium entries were patched on a first pass. The unverified risk is that verify.sh's new release and slot binding parses cosign's JSON output with grep in busybox. Only the rehearsal's openbao and release-tools cases cover it, and no human has read that parsing.

**Verification:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` passed: architecture 290/290, isolation 942/942. A first run had one `PolicyMatrixTests` timeout (`Unavailable` after 10 s). Rerun alone, 286/286 passed, and the final full run was clean.
- `docker compose -f deploy/compose.test.yaml run --rm --build release` passed: every PASS line, the signed path direct and as deployed, plus 11 refusals.
- Stack check (`GATEKEEP_HOST_REPO=/run/desktop/mnt/host/d/...`, with `MSYS_NO_PATHCONV=1` under Git Bash) passed.

**Rebase onto main (Stories 1.11, 1.12, 2.1 and 7.1):**
- Caddy is now a built service, so it joined the release lists and the overlay.
- The overlay network test now checks that the overlay adds no egress to base networks, since Caddy's `edge` network has egress.
- This story's threats were renumbered to T-48 and T-49.
- install.md now names `--env-file deploy/.env` alongside `release.env` for production.
- Re-verified after the rebase:
  - tests: architecture 333/333, isolation 1046/1046;
  - rehearsal: every case PASS;
  - stack check: passed with `GATEKEEP_HTTP_PORT=8880 GATEKEEP_HTTPS_PORT=8443`. Port 80 on this Windows machine is held by http.sys (PID 4).

**Residual risks:**
- `release.env` is unsigned, and `release-verify` isn't enforced before `up`. Both are for Story 12.6.
- Rollback to an older complete signed release still passes.
- The hardware path (`--sk`, `pkcs11:`) and `release.yml` itself first run on a real tag.
- A new built service must join the release lists. `ReleaseConfigTests.Release_images_are_every_built_service_and_the_verifier` fails until it does.
