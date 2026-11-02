---
title: 'Story 1.7: Hold keys in OpenBao behind IKeyCustody'
type: 'feature'
created: '2026-11-02'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/docs/threat-model.md'
warnings: [oversized]
deferred: []
---

<intent-contract>

## Intent

**Problem:** Keys have no home. AD-10 needs every key in OpenBao Transit behind the Kernel `IKeyCustody` port, with one policy per host, and the key-file handoff and host login method were undecided (G-1, G-2).

**Approach:** Esm's decisions, 2026-11-02: (1) no Linux host yet, so build and test everything against an OpenBao 2.7.2 container and leave the systemd start criterion open (G-10); (2) the Master Key is 32 CSPRNG bytes in a root-owned `0400` file on the key volume, handed to the non-root service by plain systemd `LoadCredential=`, with `RequiresMountsFor=` so a missing volume stops the start; (3) each host and the Cli log in with its own AppRole and short-lived tokens. Add the port, an OpenBao adapter, `deploy/openbao/` (config, unit, policies, setup script), setup docs and tests.

## Boundaries & Constraints

**Always:**
- Transit only. Tenant secrets use AEAD keys with the Tenant ID as `associated_data`, never `context`.
- Key names follow AD-10: `sig-{tenantId}-{rowId}`, `mgmt-{tenantId}-{rowId}`, `{class}-{tenantId}`, `dep-{class}`. Classes: `totp`, `social`, `email`, `payload`, `hmac`, `tpk` (token protection wrap key). The off-server record key is `dep-records`.
- Policies match AD-10 exactly. No policy grants `transit/export/*` or `transit/backup/*`, and every path that creates or configures a key denies `exportable` and `allow_plaintext_backup`.
- The production config listens only on a unix socket, uses Raft storage and the static seal read from `$CREDENTIALS_DIRECTORY`. No TCP listener in `deploy/`.
- The Master Key, recovery keys, root token and secret IDs never reach a container image, environment file, `docs/`, a log or the repo. The setup revokes the root token when done.
- No new NuGet package beyond `Testcontainers` core (same version as `Testcontainers.PostgreSql`). The adapter uses BCL HTTP and JSON.
- Update `docs/threat-model.md` (G-1, G-2, TB-7, credential rows) and `docs/spikes/1-2-key-custody.md` (container results, AppRole decision, quota finding) in this change.

**Never:**
- No TPM, `systemd-creds` or `LoadCredentialEncrypted`. No environment-file delivery of any secret.
- No host wiring of the adapter (`Program.cs`) and no Compose: Story 1.10 delivers secret IDs and wires hosts.
- No claim that the systemd criterion passed, and no "hardware-bound" wording.
- No key material, plaintext or ciphertext in logs or exception messages; errors name the key and operation only.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Seal and storage | Container runs `deploy/openbao/openbao.hcl` with a 32-byte key file mounted at the credential path | Starts unsealed after init, Raft storage, socket listener answers inside the container | No error expected |
| Missing key | Same, key file absent | Server fails to start; no unsealed state | Start failure observed |
| Tenant binding | Encrypt under `social-{A}` with A's ID, decrypt with B's ID | Decrypt fails | `KeyCustodyException` naming key and operation only |
| Policy allowed | Each AppRole calls each operation AD-10 grants it | Succeeds | No error expected |
| Policy forbidden | Each AppRole calls each operation AD-10 withholds, plus export, backup, `exportable=true` create and config | Refused with 403 | Adapter maps to `KeyCustodyException` (refused) |
| Deployment record signing | `Host.Worker` and Cli sign with `dep-records`; `Host.Hosted` and `Host.Admin` try | Worker and Cli succeed and verify; Hosted and Admin refused | Refused |
| Token expiry | AppRole token passes its TTL between calls | Adapter logs in again and the call succeeds | One retry only, then the error |
| Setup leaks | Run `deploy/openbao/setup.sh` against a fresh server | Root token revoked; init output written only to the root-only escrow path; stdout and container logs hold no recovery key, root token or Master Key | Canary scan finding fails the test |

</intent-contract>

## Code Map

- `src/Gatekeep.Kernel/Secrets/Secret.cs` -- `Secret<T>` for plaintext crossing the port; Kernel references nothing in Gatekeep.
- `src/Modules/Keys/*` -- placeholders only; the port lives in Kernel per the spine rule (line 465), not in Keys.
- `src/Adapters/Logging/Gatekeep.Adapters.Logging.csproj` -- pattern for an adapter project with no package pin.
- `tests/Architecture/module-edges.txt`, `Gatekeep.slnx` -- add `Adapters.OpenBao` and `dependency Tests.Isolation -> Adapters.OpenBao`, then run `dotnet run --project tests/Architecture/Generator`.
- `Directory.Packages.props` -- add `Testcontainers` 4.16.0; regenerate lockfiles.
- `tests/Isolation/PostgresFixture.cs` -- assembly fixture pattern; an OpenBao fixture should be a separate class fixture or collection so Postgres tests don't wait on it.
- `tests/Isolation/Canary/` -- reuse the scanner for the setup-leak row.
- `tests/Architecture/PersistenceRuleTests.cs`, `LoggingRuleTests.cs` -- pattern for source rules.
- `docs/threat-model.md:101,153-171,284-285,293` -- TB-7, custody rows, G-1, G-2, G-10.
- `global.json` -- needs SDK 10.0.403 at `%LOCALAPPDATA%\Programs\dotnet-10.0.403` and Node 26.13.0 at `%LOCALAPPDATA%\Programs\node-v26.13.0-win-x64` first on `PATH` (pnpm shim in `C:\Users\esm\AppData\Local\Temp\claude\D--Projects-Personal-gatekeep\94ff8bc2-4a0e-49fa-a28e-6d3d0ecd048d\scratchpad\shims`), or `BuildEnforcementTests` fail.
- Image `openbao/openbao:2.7.2` is pulled locally (`bao version` 2.7.2). Docker Desktop is Linux containers; the host is Windows, so tests reach the server over a test-only TCP listener mounted alongside the production file.

## Tasks & Acceptance

**Execution:**
- [ ] `src/Gatekeep.Kernel/Secrets/IKeyCustody.cs`, `KeyName.cs`, `KeyCustodyException.cs` -- port: create key, sign, verify, encrypt and decrypt with `associated_data`, HMAC, wrapped datakey, rotate, rewrap, delete, public key read. `KeyName` builds only AD-10 names.
- [ ] `src/Adapters/OpenBao/` -- `Gatekeep.Adapters.OpenBao.csproj`, `OpenBaoKeyCustody.cs`, `OpenBaoOptions.cs` (socket path or address, role ID and secret ID file paths), AppRole login with token reuse and one re-login, unix socket via `SocketsHttpHandler.ConnectCallback`, `AddOpenBaoKeyCustody(IServiceCollection, OpenBaoOptions)`.
- [ ] `deploy/openbao/openbao.hcl`, `openbao.service`, `generate-master-key.sh`, `setup.sh`, `policies/{host-hosted,host-admin,host-worker,cli}.hcl` -- unit runs as `openbao`, `LoadCredential=master-key:<key volume path>`, `RequiresMountsFor=` key and data volumes, hardening options. Setup: init with recovery shares to a root-only escrow file, enable Transit and a file audit device, write policies, create four AppRoles (token TTL 15 min, max 1 h, `token_no_default_policy` off only if renew needs it), create `dep-*` keys, revoke the root token.
- [ ] `docs/key-custody.md` -- first setup steps: key generation, volume, offline escrow of the Master Key and recovery keys apart from backups, keeping every generation, destroying the temporary escrow file. No sample key values.
- [ ] `tests/Isolation/Custody/` -- OpenBao fixture running the `deploy/` config and `setup.sh`, then tests for every matrix row.
- [ ] `tests/Architecture/KeyCustodyRuleTests.cs` -- outside `src/Adapters/OpenBao`, no source uses `transit/`, `X-Vault-Token` or the OpenBao address, and no source in `src/` creates asymmetric or AEAD keys (`RSA.Create`, `ECDsa.Create`, `AesGcm`, `IDataProtectionProvider`, and similar); policy files have no export or backup path and deny `exportable`; `deploy/openbao/openbao.hcl` has no `tcp` listener.
- [ ] `docs/threat-model.md`, `docs/spikes/1-2-key-custody.md`, module diagram -- record decisions and results; G-10 stays open.

**Acceptance Criteria:**
- Given the Story 1.2 result, when OpenBao starts from `deploy/` in a container, then it serves Transit on the unix socket only, with Raft and the static seal from the credential file; the systemd start itself is recorded as open until a Linux host exists (G-10).
- Given any code needing a key, when the architecture tests run, then access goes only through `IKeyCustody`.
- Given the Master Key and recovery keys, when the first setup follows `docs/key-custody.md`, then the escrow steps keep them apart from backups and none appears in `docs/`, a log or the repo.

## Spec Change Log

## Review Triage Log

## Design Notes

- **Seal config:** `seal "static" { current_key_id = "...", current_key = "file://..." }`. Confirm the parameter names against 2.7.2 by running the container, and record what you used.
- **Wrap:** Worker uses `transit/datakey/wrapped/tpk-*`, so it never sees the plaintext; Hosted decrypts it.
- **Quotas:** OpenBao rate-limit quotas apply per path, not per AppRole. Probe and record the finding; apply none if per-host support is absent.
- **Backups:** no backup set exists yet. Docs name the key volume as excluded; the backup story checks it.

## Verification

**Commands:**
- `dotnet restore Gatekeep.slnx --locked-mode` -- expected: succeeds.
- `dotnet build Gatekeep.slnx --no-restore` -- expected: no warnings.
- `dotnet test tests/Architecture --no-build` -- expected: all pass.
- `dotnet test tests/Isolation --no-build` -- expected: all pass, including `Custody`.
- `dotnet run --project tests/Architecture/Generator` -- expected: no diff after committing the diagram.
