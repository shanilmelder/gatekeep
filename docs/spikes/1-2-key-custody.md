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
