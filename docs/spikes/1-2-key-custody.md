# Key custody spike (Story 1.2)

**Outcome: not run. The fallback applies, and it's a weaker control.**

Date: 2026-11-02. No Linux host with a TPM2 was available, so Esm chose to record the fallback rather than run the spike. Nothing here was tested on Linux, and no commands were run.

## Proof results

| Proof | Result | What remains |
| --- | --- | --- |
| `LoadCredentialEncrypted` | `not-run` | Needs a TPM2 host |
| PCR 7 | `not-run` | Needs a TPM2 host |
| Static seal | `not-run` | Needs Linux with systemd |
| Raft storage | `not-run` | Needs Linux with systemd |
| Socket access from containers | `not-run` | Needs Linux with Docker |
| OpenBao host login | `not-run` | Needs Linux; the login method is still undecided |
| Per-host quotas | `not-run` | Needs Linux; AD-10 applies them only if support is confirmed |

`not-run` isn't a pass or a fail: it means there's no evidence either way. An earlier architecture review ran the static seal and Raft on OpenBao 2.7.2, but not on Linux with systemd, so that doesn't count as a proof here.

## The fallback

The OpenBao static seal key, which AD-10 calls the Master Key, is a root-only key file on a separate volume. It's never in a container, environment file or backup, and the offline escrow rule in AD-10 still applies.

OpenBao's documentation recommends the static seal only where a source of trust already exists. With no TPM, that trust is file permissions alone, and Esm accepted that risk.

The OpenBao, PostgreSQL and key volumes use LUKS, unlocked by a passphrase at boot, with no unlock key on the host. Esm chose this over unattended restart: after any reboot, the service stays down until someone enters the passphrase. That wait counts against the 99.5% availability target (NFR-10), which allows about 3.6 hours of downtime a month, so an unplanned reboot overnight could use all of it.

## Why it's weaker

| Threat | TPM design | Fallback |
| --- | --- | --- |
| Backup stolen | Protected | Protected, because the key file isn't backed up |
| Database disk stolen | Protected | Protected, if the key volume isn't taken too |
| Whole server stolen | Partly: an unattended boot still unseals, and PCR 7 reflects only Secure Boot state | Protected if powered off, because LUKS needs a passphrase at boot. **Not protected** if taken while running |
| Key moved to other hardware | Blocked by the chip | **Not blocked:** the file can be copied |
| Live root | Not protected | Not protected |

## What this doesn't settle

- Story 1.7 and Story 1.10 still need a Linux host. Five of the seven proofs need only Linux, not a TPM2, so they can run there, but those stories don't yet require it.
- The handoff from the root-only file to the non-root OpenBao service is untested and undecided.
- Key rotation, restore and `gatekeep rekey` assumed the TPM design and haven't been rechecked. A copied key file has no hardware binding, so old copies stay valid until the key rotates.
- Moving to the TPM design later means running this spike on a real host, then amending AD-10 again.

## Story 1.7 container results

Date: 2026-11-02. Esm chose to build and test against an OpenBao 2.7.2 container (`openbao/openbao:2.7.2`) because there's still no Linux host. **These are container results, not proofs on a host:** the table above stays as it is, and nothing here ran under systemd (G-10). The tests are in `tests/Isolation/Custody`.

| Question | Container result | What remains |
| --- | --- | --- |
| Static seal | Passes. `seal "static"` with `current_key_id` and `current_key = "file:///run/credentials/openbao.service/master-key"` takes a 32-byte raw key. After `operator init` it unseals itself, and again after a restart with nobody entering anything. With the file absent the server exits at start: `Error configuring seal "static": error reading file`. Tests: `SealTests.Server_without_a_key_file_fails_to_start`, `SealTests.Restart_unseals_from_the_key_file_and_stops_when_the_file_is_gone` | `LoadCredential=` itself, `RequiresMountsFor=` and `AssertPathIsMountPoint=` are untested: the container stands in for systemd with a start script |
| Raft storage | Passes, with one finding: **Raft refuses to unseal with only a unix listener** (`cluster addresses not found`), and `disable_clustering` can't be set with Raft. Only a tcp listener supplies a cluster address. `deploy/openbao/openbao.hcl` therefore has a tcp listener on `127.0.0.1`, and the unit sets `PrivateNetwork=yes` so that loopback belongs to OpenBao alone | That `PrivateNetwork=yes` keeps the loopback unreachable needs a host |
| Socket listener | Passes inside the container. OpenBao 2.7.2 **ignores `socket_mode` and `socket_group` unless `socket_user` is also set**; with all three the socket is `0660 openbao:gatekeep-custody` | Socket access from other containers, which is Story 1.10 |
| Host login | **Decided: AppRole**, one role per host and one for the Cli, `token_ttl` 15 minutes, `token_max_ttl` 1 hour, `token_no_default_policy=true` because hosts log in again rather than renew. The adapter reuses a token until three quarters of its lease and, on a 403 with a reused token, logs in once and retries once | Delivering secret IDs to hosts is Story 1.10. Secret IDs don't expire yet (`secret_id_ttl=0`) |
| Per-host quotas | **Not supported.** Rate-limit quotas apply to a path or mount per client address. The `role` setting works only on an auth method's login path, and `transit/` is refused as a role-quota path. Every host comes through the same socket, so per-host quotas are impossible here. **None is applied** | Decrypt-rate alerts from the audit log remain the AD-10 control |
| Audit device | OpenBao 2.7.2 refuses to enable audit devices through the API, so a declarative `audit "file"` block sits in `openbao.hcl` | Off-server shipping and alerts are later stories |
| Rewrap | **OpenBao 2.7.2 `transit/rewrap` takes no `associated_data`**, so every Gatekeep ciphertext, which is bound to its Tenant that way, fails authentication on rewrap. `cli` holds the grant, but it can't be used yet (G-16) | Decide how ciphertexts move to a new key version |
| Policy globs | `transit/keys/sig-*` also matches `transit/keys/sig-*/rotate`, `/config`, `/trim` and `/import`. A `*` in the middle of a path is literal, `+` only matches a whole segment, and a more specific `deny` loses to the earlier glob. `Host.Admin`'s create grant pins and requires `type`, which refuses everything but a crafted rotate (T-45) | None, short of a different policy model |
