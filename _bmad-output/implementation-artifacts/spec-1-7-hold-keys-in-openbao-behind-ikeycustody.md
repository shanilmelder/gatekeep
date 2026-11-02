---
title: 'Story 1.7: Hold keys in OpenBao behind IKeyCustody'
type: 'feature'
created: '2026-11-02'
status: 'done'
baseline_revision: '567c4b71d518c09812cbe0dae19ff094df5fd629'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/docs/threat-model.md'
warnings: [oversized]
deferred:
  - summary: >-
      Host.Admin can rotate its own Signing and Management keys with a crafted request (T-45).
    evidence: |-
      A policy glob on transit/keys/sig-* reaches /rotate, and OpenBao ignores the pinned type there. A known-limit test pins it.
    location: >-
      deploy/openbao/policies/host-admin.hcl
    severity: medium
  - summary: >-
      OpenBao 2.7.2 rewrap takes no associated_data, so no Gatekeep ciphertext can be rewrapped (G-16).
    evidence: |-
      The matrix test expects Rejected for Cli rewrap. Stories 12.2 and 13.4 need another way to move ciphertexts to a new key version.
    location: >-
      src/Adapters/OpenBao/OpenBaoKeyCustody.cs
    severity: medium
  - summary: >-
      No test shows the adapter logs in again at three quarters of the lease.
    evidence: |-
      Both expiry tests freeze the clock, so the 403 fallback path is the only one exercised. Add a moving-clock test when hosts are wired.
    location: >-
      src/Adapters/OpenBao/OpenBaoKeyCustody.cs
    severity: medium
  - summary: >-
      mlock behaviour under the hardened unit is undecided.
    evidence: |-
      The unit drops every capability, including CAP_IPC_LOCK, and openbao.hcl does not set disable_mlock. A Linux host under systemd settles it.
    location: >-
      deploy/openbao/openbao.service
    severity: medium (unverified)
  - summary: >-
      The OpenBao file audit log has no rotation, and a full disk blocks every request.
    evidence: |-
      OpenBao refuses requests when its only audit device cannot write.
    location: >-
      deploy/openbao/openbao.hcl
    severity: medium
  - summary: >-
      AppRole secret IDs never expire and have no replacement procedure.
    evidence: |-
      setup.sh sets secret_id_ttl=0 and keeps no accessor. Story 1.10 delivers secret IDs.
    location: >-
      deploy/openbao/setup.sh
    severity: medium
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
- [x] `src/Gatekeep.Kernel/Secrets/IKeyCustody.cs`, `KeyName.cs`, `KeyCustodyException.cs` -- port: create key, sign, verify, encrypt and decrypt with `associated_data`, HMAC, wrapped datakey, rotate, rewrap, delete, public key read. `KeyName` builds only AD-10 names.
- [x] `src/Adapters/OpenBao/` -- `Gatekeep.Adapters.OpenBao.csproj`, `OpenBaoKeyCustody.cs`, `OpenBaoOptions.cs` (socket path or address, role ID and secret ID file paths), AppRole login with token reuse and one re-login, unix socket via `SocketsHttpHandler.ConnectCallback`, `AddOpenBaoKeyCustody(IServiceCollection, OpenBaoOptions)`.
- [x] `deploy/openbao/openbao.hcl`, `openbao.service`, `generate-master-key.sh`, `setup.sh`, `policies/{host-hosted,host-admin,host-worker,cli}.hcl` -- unit runs as `openbao`, `LoadCredential=master-key:<key volume path>`, `RequiresMountsFor=` key and data volumes, hardening options. Setup: init with recovery shares to a root-only escrow file, enable Transit and a file audit device, write policies, create four AppRoles (token TTL 15 min, max 1 h, `token_no_default_policy` off only if renew needs it), create `dep-*` keys, revoke the root token.
- [x] `docs/key-custody.md` -- first setup steps: key generation, volume, offline escrow of the Master Key and recovery keys apart from backups, keeping every generation, destroying the temporary escrow file. No sample key values.
- [x] `tests/Isolation/Custody/` -- OpenBao fixture running the `deploy/` config and `setup.sh`, then tests for every matrix row.
- [x] `tests/Architecture/KeyCustodyRuleTests.cs` -- outside `src/Adapters/OpenBao`, no source uses `transit/`, `X-Vault-Token` or the OpenBao address, and no source in `src/` creates asymmetric or AEAD keys (`RSA.Create`, `ECDsa.Create`, `AesGcm`, `IDataProtectionProvider`, and similar); policy files have no export or backup path and deny `exportable`; `deploy/openbao/openbao.hcl` has no `tcp` listener.
- [x] `docs/threat-model.md`, `docs/spikes/1-2-key-custody.md`, module diagram -- record decisions and results; G-10 stays open.

**Acceptance Criteria:**
- Given the Story 1.2 result, when OpenBao starts from `deploy/` in a container, then it serves Transit on the unix socket only, with Raft and the static seal from the credential file; the systemd start itself is recorded as open until a Linux host exists (G-10).
- Given any code needing a key, when the architecture tests run, then access goes only through `IKeyCustody`.
- Given the Master Key and recovery keys, when the first setup follows `docs/key-custody.md`, then the escrow steps keep them apart from backups and none appears in `docs/`, a log or the repo.

## Spec Change Log

- **2026-11-02, implementation, needs Esm's approval: loopback tcp listener in `deploy/openbao/openbao.hcl`.** The "No TCP listener in `deploy/`" rule can't hold with Raft on OpenBao 2.7.2: with only a unix listener, init fails with `unseal with stored key failed: cluster addresses not found`, and `disable_clustering = true` is refused with Raft. Only a tcp listener supplies the cluster address. The config therefore has one tcp listener on `127.0.0.1:8200` (cluster `127.0.0.1:8201`), and `openbao.service` sets `PrivateNetwork=yes` so that loopback belongs to OpenBao's own network namespace. Hosts still reach OpenBao only on the socket. `KeyCustodyRuleTests` enforces "the only tcp listener is loopback, and the unit sets `PrivateNetwork=yes`" instead of "no tcp listener". Alternatives if Esm refuses: file storage instead of Raft, or a different OpenBao version.
- **2026-11-02, implementation: rewrap can't carry associated data.** OpenBao 2.7.2 `transit/rewrap` has no `associated_data` parameter, so `IKeyCustody.RewrapAsync` is `Rejected` for every Gatekeep ciphertext. The port method and the `cli` grant stay; the matrix test expects `Rejected` for the granted rows. Recorded as G-16.
- **2026-11-02, implementation: `Host.Admin` has no read grant.** `required_parameters = ["type"]` on its create grant also blocks reads of that path, so `CreateKeyAsync` returns the public halves instead. A crafted rotate by `Host.Admin` still passes (T-45), pinned by a known-limit test.

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 52 findings — high 0, medium 23, low 22, false 6, maybe-false 1
- findings:
  - `[medium]` `[reject]` Intent: `openbao.hcl` has a tcp listener against "No TCP listener in `deploy/`" — Raft on 2.7.2 refuses to unseal without one, and AD-10 requires Raft; the loopback sits in `PrivateNetwork=yes`, so hosts still reach only the socket. The only fix is to edit the spec, so it is rejected and raised with Esm; the Spec Change Log records it.
  - `[low]` `[reject]` Intent: the seal path is hardcoded to `/run/credentials/openbao.service`, not read from `$CREDENTIALS_DIRECTORY` — that is the fixed systemd path for this unit, and checking it needs systemd (G-10).
  - `[false]` `[reject]` Intent: systemd behaviour is checked only as text — what the intent asks: decision (1) leaves the systemd start open.
  - `[false]` `[reject]` Intent: the adapter never uses OpenBao's real socket in tests — the matrix row asks only that the socket answer inside the container, which `bao status` over it shows; Docker Desktop on Windows can't share a unix socket with the host.
  - `[false]` `[reject]` Intent: "match AD-10 exactly" checked against the author's table — I compared the four policies and the `Granted` table with AD-10 line 200 and they agree, apart from the recorded T-45 and G-16 limits.
  - `[medium]` `[defer]` Intent: `Host.Admin` can rotate its keys with a crafted request — a limit of the OpenBao policy model (a glob reaches subpaths, and a `+` deny loses priority); T-45 records it with a known-limit test.
  - `[medium]` `[defer]` Intent: Cli's granted rewrap fails — OpenBao 2.7.2 rewrap takes no `associated_data`; G-16 records it for Stories 12.2 and 13.4.
  - `[low]` `[reject]` Intent: any 403 with a reused token triggers one re-login and retry, not only an expired one — OpenBao answers both with the same 403; a refusal is a bug or an attack, and the cost is one login.
  - `[low]` `[patch]` Intent: role IDs aren't canaries in the setup leak scan — added.
  - `[false]` `[reject]` Intent: `setup.sh` keeps the root token in `BAO_TOKEN` — that is the bao CLI's process environment, not an environment file, and the token is revoked before exit.
  - `[false]` `[reject]` Intent: docs say "Not hardware-bound" — the rule bans claiming hardware binding, and this denies it.
  - `[low]` `[patch]` Intent: G-10 moved off Story 1.7, and G-1 and G-2 deleted rather than closed — G-10 lists 1.7 and 1.10 again; G-1 and G-2 stay as rows closed by Story 1.7.
  - `[false]` `[reject]` Intent: `FrameworkReference Microsoft.AspNetCore.App` goes beyond BCL — it is the shared framework, not a NuGet package, as in `Adapters.Logging`.
  - `[medium]` `[patch]` Gap: no test for a Tenant key used without its Tenant ID, or a Deployment key given one — test added, with the cross-Tenant case below.
  - `[low]` `[patch]` Gap: no test that a refused call with a fresh token skips the retry — test asserts 1 login and 1 request.
  - `[medium]` `[defer]` Gap: no test that the adapter logs in again at three quarters of the lease — no host runs the adapter before Story 1.10, and the 403 fallback keeps calls working.
  - `[medium]` `[patch]` Gap: rotation never checks versions — test signs and encrypts, rotates, verifies and decrypts the old values, and checks public versions [1, 2].
  - `[medium]` `[patch]` Gap: root token revocation on a failed setup is untested — test injects a failure after init and checks the escrowed root token is refused.
  - `[medium]` `[patch]` Gap: the no-overwrite guard in `generate-master-key.sh` is untested — test reruns it and checks the key is unchanged.
  - `[medium]` `[patch]` Edge: `AssociatedData` compares only HasValue, so a Tenant A key with Tenant B's ID binds to B — throws unless the IDs match, tested.
  - `[medium]` `[patch]` Edge: `DeleteAsync` leaves `deletion_allowed` set when the delete is refused, as for Cli on `dep-*` — the Cli `dep-*` grant now denies `deletion_allowed`, so the first step is refused; tested.
  - `[medium]` `[patch]` Edge: Cli `update` on `dep-*` reaches `/trim` and `/config` — version and deletion parameters denied, tested.
  - `[low]` `[patch]` Edge: a sealed or down OpenBao at login reads as a bad credential — LoginFailed only for 400 and 403, Unavailable otherwise.
  - `[low]` `[reject]` Edge: an oversized `lease_duration` escapes as a raw exception — OpenBao returns integer seconds, and a guard adds branches for an input it never sends.
  - `[low]` `[patch]` Edge: no public key in the response gives an empty list — Unavailable.
  - `[low]` `[patch]` Edge: an unknown `KeyKind` becomes an HMAC key — explicit arm, throwing default.
  - `[low]` `[patch]` Edge: `v-1` parses as a version — `NumberStyles.None`, and the version must be positive.
  - `[low]` `[reject]` Edge: a null `KeySignature.Value` throws `ArgumentNullException` — nullable reference types already warn on it, and the exception is clear.
  - `[low]` `[reject]` Edge: `OpenBaoOptions` accepts an empty socket path, a relative address or a zero timeout — each fails loudly at construction or first connect, and only Story 1.10 config builds these.
  - `[medium]` `[patch]` Edge: `generate-master-key.sh` writes to an unmounted key directory on the root disk — requires `mountpoint -q`.
  - `[low]` `[patch]` Edge: a file can appear between the `-e` check and `mv` — published with `ln`, which refuses an existing file.
  - `[low]` `[reject]` Edge: a failed init leaves an empty escrow file that blocks a rerun — it needs threshold above shares or a dead server, and the error names the file.
  - `[medium]` `[patch]` Edge: sh skips the EXIT trap on a signal, so an interrupted setup leaves the root token live — INT, TERM and HUP trapped.
  - `[medium]` `[patch]` Edge: a failure after init leaves a half-set-up server with no way out — `docs/key-custody.md` gives the recovery.
  - `[low]` `[reject]` Edge: a long temp path could pass the unix socket length limit in a test — CI and local runs use short temp paths, and it would fail loudly.
  - `[low]` `[reject]` Edge: a cancelled forwarder can leak one accepted socket in a test — test-only, disposed with the process.
  - `[low]` `[patch]` Edge: `SealTests` doesn't check the `rm` exit code — asserted.
  - `[medium]` `[reject]` Edge (claim): the config has a tcp listener against the spec — same as the first Intent row.
  - `[low]` `[patch]` Edge (claim): setup doesn't check that the audit device exists — setup fails unless `bao audit list` shows one.
  - `[medium]` `[patch]` Edge (claim): the `cli.hcl` header says Deployment keys can't be deleted, but `/trim` was allowed — same fix as the `dep-*` row.
  - `[medium]` `[patch]` Blind: Worker and Cli key globs reach `/import`, `/import_version`, `/trim` and `/config` — `ciphertext`, `public_key`, `min_decryption_version` and `min_available_version` denied on every keys grant, tested.
  - `[medium]` `[patch]` Blind: `DeleteAsync` is two steps and a refused delete leaves a side effect — same fix as the Edge delete row, plus a test that a refused delete leaves the key.
  - `[low]` `[patch]` Blind: `CreateKeyAsync` on an existing name is undefined — the contract now says the existing key comes back unchanged, so names come from fresh row IDs.
  - `[medium]` `[patch]` Blind: no mount check in `generate-master-key.sh` — same fix as the Edge row.
  - `[medium]` `[patch]` Blind: no documented way out of a setup that fails after init — same fix as the Edge row.
  - `[maybe-false]` `[defer]` Blind: mlock is undecided, and the unit drops `CAP_IPC_LOCK` — whether 2.7.2 needs it, and whether swap is encrypted, needs a Linux host under systemd (G-10).
  - `[medium]` `[defer]` Blind: the file audit log has no rotation, and a full disk blocks every request — belongs to the story that ships the audit log off the server.
  - `[medium]` `[defer]` Blind: re-login never revokes the old token, and secret IDs never expire with no replacement procedure — the per-refusal login is rejected as in the Intent row; secret ID lifetime and replacement go to Story 1.10, which delivers them.
  - `[low]` `[reject]` Blind: `KeyHmac` and `KeySignature` compare arrays by reference and give no constant-time comparison — nothing compares them yet; AD-24's story adds the comparison.
  - `[medium]` `[patch]` Blind: no unit tests for status mapping, parsing or `KeyName` — stub-handler tests added.
  - `[low]` `[patch]` Blind: the threat model cites a stand-in test as evidence for `LoadCredential=` — the row now says it checks the stand-in.
  - `[low]` `[patch]` Blind: setup tests are weaker than their names — role IDs added as canaries; the `initialized` and not-answering branches stay untested as low value.

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

## Auto Run Result

Status: done

**Summary:** added the Kernel `IKeyCustody` port and an OpenBao Transit adapter, logging in with one AppRole per host over the unix socket, plus `deploy/openbao` (config, systemd unit with plain `LoadCredential=`, key generation, setup that revokes the root token, four policies), setup docs and container tests.

**Files:** `src/Gatekeep.Kernel/Secrets/` (port, key names, exception); `src/Adapters/OpenBao/`; `deploy/openbao/`; `docs/key-custody.md`, `docs/threat-model.md`, `docs/spikes/1-2-key-custody.md`, the module diagram; `tests/Isolation/Custody/`; `tests/Architecture/KeyCustodyRuleTests.cs`; `Directory.Packages.props` (`Testcontainers` 4.16.0); `.gitattributes`.

**Review:** 52 findings across four layers: 29 patched, 6 deferred, 17 rejected, each with its reason in the triage log.

**Follow-up review:** recommended. Several medium policy patches add `denied_parameters` whose effect on OpenBao 2.7.2 subpaths is proved only by the new forbidden tests; a second pass should check those grants against AD-10 again.

**Verification:** see the PR screenshot; restore, build, Architecture, Isolation and the diagram generator all pass on SDK 10.0.403 and Node 26.13.0, with OpenBao 2.7.2 in a container.

**Residual risks:** nothing has run under systemd (G-10), including `LoadCredential=`, the mount guards and `PrivateNetwork=yes`, which is what keeps the loopback listener private. `Host.Admin` can rotate its keys with a crafted request (T-45). Rewrap can't carry the Tenant binding (G-16). No per-host quotas exist. The audit log isn't shipped off the server, and no host uses the adapter until Story 1.10.
