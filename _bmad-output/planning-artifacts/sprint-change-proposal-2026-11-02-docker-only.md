# Sprint Change Proposal: Docker only

Date: 2026-11-02. Raised by Esm during Story 1.10. Mode: batch.

## 1. Issue summary

**Trigger:** Story 1.10 (run the stack under Compose). Its plan, like AD-10 and AD-26, assumed a Linux host that Gatekeep's install manages: OpenBao as a native systemd service, the Master Key in a root-only file loaded by systemd, LUKS volumes and a boot passphrase typed over initramfs SSH.

**Decision (Esm, 2026-11-02):** Gatekeep runs only inside Docker. Nothing related to it runs outside Docker:

1. OpenBao is a Compose service. Its Master Key (the static seal key) reaches it as a Compose secret.
2. The Gatekeep CLI (`migrate`, `recover-admin`, `restore`, `upgrade`, `rekey`, `check-*`), the OpenBao setup script and Master Key generation all run as Compose services (`docker compose run --rm ...`).
3. Disk encryption and the boot passphrase are the Docker host owner's job. Gatekeep documents the requirement and can't check it.
4. Builds and the test suite run in a container too, locally and in CI. A developer's machine needs only Docker and Git.

**Kind:** a deployment decision by the owner, not a technical failure.

## 2. Impact analysis

### Checklist

| Item | Status | Finding |
|---|---|---|
| 1.1 Trigger story | [x] | Story 1.10 |
| 1.2 Problem | [x] | Strategic change of deployment target |
| 1.3 Evidence | [x] | Esm's answers, 2026-11-02 |
| 2.1 Current epic | [!] | Epic 1 can finish; Stories 1.10, 1.11, 1.12 and 1.32 change, and Story 1.7's `deploy/openbao` is reworked |
| 2.2 Epic changes | [x] | No epic added or removed |
| 2.3 Later epics | [!] | Epic 12 (backup, restore, upgrade, Master Key rotation) and Story 13.4 run their commands in the CLI container |
| 2.4 Obsolete or new epics | [x] | None. The TPM design target (AR-1) is retired |
| 2.5 Order | [x] | Unchanged |
| 3.1 PRD | [!] | FR-1 wording only; MVP unchanged |
| 3.2 Architecture | [!] | AD-10, AD-26, line 107, 494, 526, project tree, Open Items |
| 3.3 UX | [N/A] | No screen depends on the host |
| 3.4 Other artifacts | [!] | `deploy/openbao`, `docs/key-custody.md`, `docs/spikes/1-2-key-custody.md`, `docs/threat-model.md`, CI, custody tests |
| 4.1 Direct adjustment | Viable | Low–medium effort, low risk |
| 4.2 Rollback | Not viable | Story 1.7's adapter, policies and setup stay; only the host packaging changes |
| 4.3 MVP review | Not needed | |

### Security consequences (recorded in the threat model)

- **Master Key:** it now lives as a file on the Docker host's disk, mounted read-only into the OpenBao container as a Compose secret. Anyone with root or Docker access on the host can read it. The threat model already treats live root or Docker access as full compromise (T-29), so this widens nothing for a running attacker. A stolen powered-off disk is protected only if the host owner encrypts it. Gatekeep can't check that, and T-30 says so.
- **Kept:** the Master Key is never in an image, an environment variable, a data volume, a log, the repository or a backup. Every generation is escrowed offline.
- **OpenBao isolation:** the container joins no network (`network_mode: none`). Hosts reach it only through its unix socket on a shared volume. Raft's loopback listener sits in the container's own network namespace, which replaces `PrivateNetwork=yes`.
- **Test-only Docker socket:** the test container gets the Docker socket so tests can start PostgreSQL and OpenBao. No runtime service ever gets it (G-4 stays).

## 3. Recommended approach

**Direct adjustment.** Amend the documents below, then rewrite and finish Story 1.10 so it also:

- moves OpenBao into Compose;
- reworks `deploy/openbao` for containers;
- adds the CLI and test containers;
- drops the systemd unit, LUKS and initramfs SSH.

Effort: medium, all inside Story 1.10. Risk: low. Timeline: Story 1.10 grows, and later stories shrink because no host work remains.

## 4. Detailed change proposals

### Architecture spine (`ARCHITECTURE-SPINE.md`)

**AD-10, line 195**

OLD: "OpenBao Transit runs on the same host as a native systemd service with Raft storage, reachable only over a private socket."

NEW: "OpenBao Transit runs as a Compose service with Raft storage on its own volume, attached to no network and reachable only over a unix socket on a shared volume."

**AD-10, line 202**

OLD: "...the static seal key... is held in a root-only key file on a separate volume, recorded as a weaker control... The target design remains `systemd-creds` sealed to the host TPM2 and PCR 7... It's never in a container, environment file or backup."

NEW: "**Amended 2026-11-02 (Docker only):** the static seal key is a 32-byte file on the Docker host, outside every data volume and backup, delivered to the OpenBao container as a read-only Compose secret. It is never in an image, environment variable, data volume, log, repository or backup. Root or Docker access on the host reads it. This is a weaker control, and it replaces the TPM target, which needs host access Gatekeep no longer has. Offline escrow and generation rules are unchanged."

**AD-10, line 203**

OLD: "...the OpenBao, PostgreSQL and key volumes use LUKS unlocked by a passphrase at boot... A person must enter that passphrase after every reboot..."

NEW: "This protects backups. Protection of a stolen disk or powered-off server depends on the Docker host's disk encryption, which the host owner provides and Gatekeep can't verify. Whether restarts are unattended is the host owner's choice."

**AD-26, lines 430–432**

OLD: "One Linux host. OpenBao and PostgreSQL's disks sit on LUKS volumes. OpenBao runs as a native systemd service. Everything else runs in Docker Compose... Environments are local, CI, rehearsal VM and production."

NEW: "One Docker host running Docker Compose. Every Gatekeep process runs in a container: the hosts, PostgreSQL, OpenBao, Caddy, the CLI, setup and key generation, and the test suite. Nothing is installed on the host but Docker. Disk encryption, the host firewall and host access control are host requirements in the install docs, not something Gatekeep sets up. Environments are local, CI and production, sharing one Compose definition with different values."

**AD-26, line 435:** "The host firewall allows public traffic only to Caddy" becomes "Only Caddy publishes ports; the install docs require a host firewall allowing just those."

**Line 107:** "`Gatekeep.Cli` runs only on the host, with its own role" becomes "`Gatekeep.Cli` runs only as the `cli` Compose service, with its own role and no published port."

**Line 494 (AD-31):** "`gatekeep recover-admin` runs on the host as `gk_cli`" becomes "runs in the `cli` container as `gk_cli`".

**Line 526:** "Injected at runtime through systemd credentials or Compose secrets" becomes "Injected at runtime only as Compose secrets."

**Line 628:** the `deploy/` comment "Compose, Caddyfile, systemd units, OpenBao policies" becomes "Compose, Dockerfiles, Caddyfile, OpenBao config and policies".

**Lines 673 and 675 (Open Items):** close the Linux custody spike and the TPM2/Linux assumption as "Retired 2026-11-02: Docker only."

### Epics (`epics.md`)

- **AR-1:** retire it. Keep the line, marked "Retired 2026-11-02: Docker only; no TPM design."
- **AR-20:** "runs as a native systemd service" becomes "runs as a Compose service". The Master Key sentence follows AD-10 line 202. "Disks use LUKS" becomes "Disk encryption is a host requirement."
- **AR-34:** becomes "Deployment per AD-26: one Docker host, every process in Docker Compose including OpenBao, Caddy with public and Admin sites, a validation-only DNS credential, Compose networks that deny by default, one `EgressHttp` handler that blocks private addresses, and code-owned social endpoints. Disk encryption and the host firewall are documented host requirements."
- **AR-42:** retire it ("Docker only: no Linux or TPM2 dependency").

**Story 1.10:** "Run the stack under Compose with safe secrets"

OLD acceptance criteria:
1. Clean Linux host, stack under Compose with OpenBao native, `/healthz`.
2. Missing or default secret refused.
3. No cloud egress.
4. OpenBao and PostgreSQL data on LUKS, and a test fails on an unencrypted mount.

NEW acceptance criteria:
- **Given** the install docs and a host with only Docker, **when** the Operator runs `docker compose up`, **then** the whole stack, OpenBao included, runs as containers, and each host exposes `/healthz` on an unpublished port.
- **Given** a required secret that's missing or left at a default, **when** a host starts, **then** it refuses to start and logs the secret's name, never a value.
- **Given** the stack with no egress, **when** it starts, **then** every `/healthz` passes.
- **Given** the Master Key, **when** the stack is inspected, **then** it reaches OpenBao only as a read-only Compose secret, and it's in no image, environment variable, data volume or backup.
- **Given** the CLI, OpenBao setup and Master Key generation, **when** the Operator runs them, **then** they run as Compose services, and the docs give no command to run outside Docker.
- **Given** the test suite, **when** a developer or CI runs it, **then** it runs in the `tests` container, needing only Docker on the machine.

Rationale: Esm's decision. LUKS moves to Story 1.12 as a documented requirement.

**Story 1.11:** "Given the host firewall and Compose networks" becomes "Given the Compose networks". Rationale: the host firewall is now a documented host requirement.

**Story 1.12:** add an acceptance criterion: "**Given** the install docs, **when** they're reviewed, **then** they state the Docker host requirements: encrypted disks for volumes and the secrets directory, a firewall allowing only Caddy's ports, and that Docker access equals full control of Gatekeep."

**Story 1.32:** "Recover Admin access from the host"
- "`gatekeep recover-admin` on the host" becomes "`gatekeep recover-admin` in the `cli` container".
- "a process other than `Gatekeep.Cli` on the host" becomes "any container other than `cli`".

**Epic 12 and Story 13.4:** no text change. Their commands run in the `cli` container under AD-26.

### PRD (`prd.md`, FR-1)

"A clean install on an on-premises server" becomes "A clean install on an on-premises Docker host". The MVP is unchanged.

### Other artifacts (done in Story 1.10)

- **`deploy/openbao/`:**
  - Remove `openbao.service`.
  - Point `openbao.hcl` at the Compose secret path and the socket volume.
  - Run `generate-master-key.sh` and `setup.sh` as one-shot Compose services.
  - Adapt `KeyCustodyRuleTests` and the custody tests.
- **`docs/key-custody.md`:** rewrite for Compose.
- **`docs/spikes/1-2-key-custody.md`:** add a "Superseded by Docker only" note.
- **`docs/threat-model.md`:**
  - Update T-29, T-30, TB-7 and the custody rows.
  - Reopen G-2 for the Compose secret handoff.
  - Close G-9, G-10 and G-14 as host requirements.
  - Add a row for the Master Key file on the Docker host and for the test-only Docker socket.
- **CI:** run the build and tests in the `tests` container.

## 5. Implementation handoff

**Scope: moderate.** The architecture and stories change, but no epic does.

- **Developer (this run):** apply the document edits above, then rewrite and implement Story 1.10 to the new acceptance criteria. Stories 1.11, 1.12 and 1.32 pick up their amended criteria when they come up.
- **Success criteria:**
  - `docker compose up` brings up the whole stack, OpenBao included, on a machine with only Docker.
  - The test suite passes in the `tests` container, locally and in CI.
  - No doc, script or test runs anything outside Docker.
  - The threat model states the weaker Master Key control and the host requirements.
