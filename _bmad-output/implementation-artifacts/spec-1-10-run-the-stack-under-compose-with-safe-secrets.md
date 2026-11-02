---
title: 'Story 1.10: Run the stack under Compose with safe secrets'
type: 'feature'
created: '2026-11-02'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/docs/threat-model.md'
  - '{project-root}/docs/key-custody.md'
warnings: [oversized, multiple-goals]
deferred: []
---

<intent-contract>

## Intent

**Problem:** Nothing runs Gatekeep as a stack. AD-26 needs every host but OpenBao under Compose from locally built images, with `/healthz` on a private port, startup that refuses missing or default secrets, no cloud egress, and OpenBao, PostgreSQL and key data on LUKS.

**Approach:** Esm's decisions, 2026-11-02: (1) there is still no Linux host, so build and test everything against Docker on this machine as a stand-in, check LUKS with a command tested against sample device output, and leave the real-host runs open under G-10; (2) the LUKS passphrase is entered at boot over SSH from the initramfs (dropbear), a new trust boundary. Add Dockerfiles, `deploy/compose.yaml`, shared host startup code, a `gatekeep check-volumes` command, initramfs SSH config, install docs and a CI job that brings the stack up.

## Boundaries & Constraints

**Always:**
- One `deploy/compose.yaml` runs PostgreSQL 18.6, `Host.Hosted`, `Host.Admin` and `Host.Worker` from images built locally from `deploy/docker/*.Dockerfile`. Each app container runs as a non-root user with a read-only root filesystem, `cap_drop: [ALL]`, `no-new-privileges`, and no Docker socket (closes G-4 for these services). App networks are `internal: true`: the stack needs no egress.
- Each host serves `/healthz` on a private port, separate from any public endpoint and not published to the host. It answers 200 only when the host's database role connects and, when key custody is configured, OpenBao answers on its socket; otherwise 503 with a fixed body naming the failed check, never a value.
- Every host refuses to start when a required setting is missing, empty, or a known default (a fixed list including `changeme`, `password`, `postgres`, `gatekeep` and the isolation test password, plus anything under 16 characters for a password). It logs the setting's name only and exits non-zero.
- Secrets reach containers only as Compose secrets mounted under `/run/secrets`, read through a file-based configuration source. No secret in an environment variable, image, `compose.yaml` value or log.
- Hosts wire `IKeyCustody` (the Story 1.7 OpenBao adapter) from the socket path and their AppRole role ID and secret ID files. OpenBao stays native: containers reach its socket through a bind mount of `/run/openbao`, with the `gatekeep-custody` group. `Host.Worker` passes custody to its job runner.
- `gatekeep check-volumes` (Cli) reads `lsblk --json` output and fails, naming the mount, unless each required mount point (OpenBao data, PostgreSQL data, key volume) sits on a `crypt` device. It's tested against recorded sample output, including an unencrypted mount.
- `deploy/luks/` holds the dropbear-initramfs setup: a dedicated host key and authorized key separate from normal SSH, the key restricted to `cryptroot-unlock` with no forwarding or PTY, a non-default port. `docs/install.md` covers the whole install, the boot passphrase step and its alert, and says what has not run on a real host.
- Update `docs/threat-model.md`: a new trust boundary and key rows for initramfs SSH, G-4, G-9, G-14 (entry method decided; separate disk and measured boot stay open), G-10, and the tests.

**Never:**
- No Caddy, public routes or firewall rules (Story 1.11). No signed images (Story 12.5).
- No OpenBao container in `deploy/compose.yaml`; a CI-only override may run one as the stand-in for the native service.
- No claim that a real host, LUKS, initramfs SSH or systemd ran.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Stack up | `docker compose up --wait` with all secrets set, CI override running OpenBao | Every service healthy; each `/healthz` 200 | No error expected |
| No egress | Same, app networks internal | Every `/healthz` 200; an outbound request from a host container fails | No error expected |
| Missing secret | Host started without one required setting | Exits non-zero; log names the setting | No value in the log |
| Default secret | A password set to `changeme` or under 16 characters | Same as missing | No value in the log |
| Database down | PostgreSQL stopped | `/healthz` 503 naming `database` | Fixed body |
| Custody down | OpenBao socket gone | `/healthz` 503 naming `custody` | Fixed body |
| Private port | Compose config | `/healthz` port not published to the host | Architecture or config test fails if published |
| Hardening | Compose config | Each app service non-root, read-only, all caps dropped, no Docker socket | Config test fails otherwise |
| Encrypted mounts | Sample `lsblk` with all three on `crypt` | `check-volumes` exits 0 | No error expected |
| Unencrypted mount | Sample with PostgreSQL data on a plain partition | Exits non-zero naming that mount | — |
| Missing mount | Sample without the key volume | Exits non-zero naming it | — |

</intent-contract>

## Code Map

- `src/Gatekeep.Host.Hosted/Program.cs`, `Gatekeep.Host.Admin/Program.cs` -- three lines each; `Host.Worker/Program.cs` and `WorkerJobs.cs` already refuse missing connection settings (Story 1.8) — move that onto the shared check, keep its tests passing.
- `src/Adapters/OpenBao/OpenBaoServiceCollectionExtensions.cs`, `OpenBaoOptions.cs` -- `AddOpenBaoKeyCustody(services, options)`; socket path and role/secret ID file paths.
- `src/Modules/Operations/Contracts/OperationsContract.cs` -- `CreateRunner(..., custody, ...)`.
- `src/Gatekeep.Cli/` -- existing `gatekeep migrate` command pattern for adding `check-volumes`.
- `deploy/postgres/roles.sql` -- roles have no passwords; the install sets them from the secret files.
- `docs/key-custody.md` -- OpenBao install steps the install doc links to; `/etc/gatekeep/openbao/{role}/` holds role and secret IDs.
- `tests/Architecture/module-edges.txt` -- a new shared project (for example `Adapters.Hosting`) needs edges from each host, and to `Adapters.OpenBao` if it checks custody; regenerate the diagram.
- `tests/Isolation/Jobs/WorkerStartupTests.cs` -- pattern for running a host process and reading its output.
- `.github/workflows/ci.yml` -- add a job that builds the images and runs the stack test; pin actions by SHA as the file does.
- `global.json` -- SDK 10.0.403 at `%LOCALAPPDATA%\Programs\dotnet-10.0.403` and Node 26.13.0 at `%LOCALAPPDATA%\Programs\node-v26.13.0-win-x64` first on `PATH` (pnpm shim in `C:\Users\esm\AppData\Local\Temp\claude\D--Projects-Personal-gatekeep\94ff8bc2-4a0e-49fa-a28e-6d3d0ecd048d\scratchpad\shims`), or `BuildEnforcementTests` fail. Docker Desktop runs Linux containers here.

## Tasks & Acceptance

**Execution:**
- [ ] Shared host startup project -- file-based secret configuration from `/run/secrets`, required-setting and default-value check, `/healthz` on a private port with database and custody checks, custody wiring.
- [ ] The three host `Program.cs` files -- use it; `Host.Worker` hands custody to its runner.
- [ ] `src/Gatekeep.Cli/` -- `check-volumes` with an `lsblk --json` parser.
- [ ] `deploy/docker/` -- one Dockerfile per host, multi-stage, non-root, pinned base images by digest.
- [ ] `deploy/compose.yaml`, `deploy/compose.ci.yaml` -- the stack and the CI stand-in override (OpenBao container sharing a socket volume, generated test secrets).
- [ ] `deploy/luks/` -- dropbear-initramfs config, authorized key options, crypttab notes.
- [ ] `docs/install.md` -- the install, the boot passphrase step and its alert.
- [ ] Tests: startup refusal per host for missing and default values; `/healthz` 200 and 503 cases; `check-volumes` against sample output; a config test over `compose.yaml` for hardening, internal networks, unpublished health ports and no secret values; a stack test the CI job runs.
- [ ] `.github/workflows/ci.yml` -- the stack job.
- [ ] `docs/threat-model.md`, edges, diagram.

**Acceptance Criteria:**
- Given the stack in CI, when `docker compose up --wait` runs with the CI override, then every service reports healthy and the job passes.
- Given any app container, when inspected, then it runs as non-root with a read-only root filesystem and no capabilities.

## Spec Change Log

## Review Triage Log

## Design Notes

- **Defaults list:** keep it in one place, used by every host and testable; compare case-insensitively.
- **Health port:** for example 8081 inside the container, reachable on the internal network only, so Compose healthchecks and later monitoring (AD-32) can use it.
- **Socket permissions:** containers run with the host's `gatekeep-custody` group ID as a supplementary group, set by the install; the CI override uses the stand-in container's group.

## Verification

**Commands:**
- `dotnet restore Gatekeep.slnx --locked-mode` -- expected: succeeds.
- `dotnet build Gatekeep.slnx --no-restore` -- expected: no warnings.
- `dotnet test tests/Architecture --no-build` -- expected: all pass.
- `dotnet test tests/Isolation --no-build` -- expected: all pass.
- `docker compose -f deploy/compose.yaml -f deploy/compose.ci.yaml up --build --wait` then `down -v` -- expected: every service healthy.
- `dotnet run --project tests/Architecture/Generator` -- expected: no diff after committing the diagram.
