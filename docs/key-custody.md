# Key custody: first setup

How the Operator sets up OpenBao for one Deployment (AD-10). Written for Story 1.7, from runs against an OpenBao 2.7.2 container. **No step here has been run on a Linux host under systemd yet (G-10).** Do the first real run on the rehearsal VM, and record what differs.

This document never holds a key, token, recovery share, role ID or secret ID, and nor may any note, ticket or chat about it. If one ends up somewhere it shouldn't, treat it as stolen and follow the rotation in AD-10.

## What you end up with

| Thing | Where | Who can read it |
| --- | --- | --- |
| Master Key (static seal key), 32 random bytes | `/srv/gatekeep/keys/master-key` on the key volume | root only, `0400`. systemd gives OpenBao its own copy at each start |
| Master Key escrow copies, every generation | Offline, in two places, apart from backups | Esm |
| Recovery keys and the first root token | `/root/openbao-init.json` for minutes, then offline with the Master Key | root, then Esm |
| OpenBao data (Raft) | `/var/lib/openbao` on the OpenBao volume | `openbao` |
| Audit log | `/var/log/openbao/audit.log` | `openbao` |
| AppRole role ID and secret ID per host | `/etc/gatekeep/openbao/{role}/` | root only. Story 1.10 hands each to its host |

The root token is revoked at the end of setup, so none exists afterwards.

## Before you start

- Linux with systemd, and the `bao` 2.7.2 binary at `/usr/bin/bao`.
- Three LUKS volumes, each unlocked by passphrase at boot: the key volume mounted at `/srv/gatekeep/keys`, the OpenBao volume at `/var/lib/openbao`, and the PostgreSQL volume. The key volume holds nothing but Master Key files.
- A user and a group: `useradd --system --home-dir /var/lib/openbao --shell /usr/sbin/nologin openbao`, and `groupadd --system gatekeep-custody`. Members of `gatekeep-custody` can reach the socket. Story 1.10 decides which host processes join it.
- `/srv/gatekeep/keys` owned by root, mode `0700`. `/var/lib/openbao` owned by `openbao`, mode `0700`.
- Two pieces of offline storage for escrow, such as two encrypted USB drives kept in different places. Neither is ever plugged into the server while it's on the network, and neither is part of any backup.

## Steps

1. **Install the files.** Copy `deploy/openbao/openbao.hcl` to `/etc/openbao/openbao.hcl` and `deploy/openbao/openbao.service` to `/etc/systemd/system/openbao.service`. Keep `deploy/openbao/` (the scripts and `policies/`) somewhere root-only, such as `/opt/gatekeep/openbao`.

2. **Make the Master Key.** As root, run `generate-master-key.sh`. It writes `/srv/gatekeep/keys/master-key` as `root:root 0400` and prints only the path. It refuses to run unless `/srv/gatekeep/keys` is a mounted volume, and refuses to overwrite a file that exists.

3. **Escrow the Master Key.** Copy the file to both offline drives, named with its generation and date, for example `master-key-gen1-2026-11-02`. Check each copy's SHA-256 against the original, by eye, without writing the hash anywhere online. Don't email, sync, photograph or paste it.

4. **Start OpenBao.** `systemctl daemon-reload`, then `systemctl enable --now openbao`. If the key volume isn't mounted, or the key file is missing, the unit refuses to start, and that's intended. `systemctl status openbao` should show it running and sealed, waiting for init.

5. **Run setup.** As root, `sh /opt/gatekeep/openbao/setup.sh`. It talks to the socket, initializes OpenBao with 5 recovery shares (threshold 3) written only to `/root/openbao-init.json`, enables Transit, writes the four policies, creates the four AppRoles with 15-minute tokens (1 hour maximum), writes each role's ID and secret ID under `/etc/gatekeep/openbao`, creates the `dep-email`, `dep-payload`, `dep-hmac` and `dep-records` keys, and revokes the root token. It prints progress only. Don't run it with `sh -x`, which would print the root token.

6. **Escrow the recovery keys.** Copy `/root/openbao-init.json` to the same two offline drives, next to the Master Key generation it belongs to. The root token inside it is already revoked.

7. **Destroy the temporary escrow file.** `shred -u /root/openbao-init.json`. On a journaling or copy-on-write file system `shred` can't promise the old blocks are gone, which is one more reason the server disk is LUKS.

8. **Check.** `bao status -address=unix:///run/openbao/openbao.sock` shows `Sealed false`, `Seal Type static` and `Storage Type raft`. `ls -l /srv/gatekeep/keys` shows only `root` with `-r--------`.

## If setup fails after init

Setup revokes the root token on any failure or interrupt, so a half-done server can't be finished by hand, and nothing is stored in it yet. Start again from a clean OpenBao:

1. `systemctl stop openbao`.
2. `shred -u /root/openbao-init.json`. Those recovery keys belong to the failed init and open nothing you'll keep.
3. Wipe the Raft data: `rm -rf /var/lib/openbao/data/*`. Only this init's state is there.
4. `systemctl start openbao`, fix the cause, then run `setup.sh` again from step 5.

The Master Key can stay: it hasn't sealed anything you'll keep, and it's already escrowed.

## Rules that outlast setup

- **Keep every generation.** A new Master Key (seal rotation) never replaces the old escrow copy. Each generation stays escrowed until the last backup that needs it has expired, because an OpenBao snapshot can only be opened with the generation it was taken under.
- **Apart from backups.** The key volume, the escrow drives and `/etc/gatekeep/openbao` are never in a backup set. No backup set exists yet: the backup story must exclude them and check it.
- **Nothing else.** No Master Key, recovery key, root token, role ID or secret ID in a container image, an environment file, `docs/`, a log or the repository.
- **Not hardware-bound.** The Master Key is a file. Anyone who copies it and an OpenBao snapshot has every key, and old copies stay valid until the key rotates. See `docs/spikes/1-2-key-custody.md`.

## Still open

- Running this on Linux under systemd (G-10), including whether `Type=notify` and the hardening options start cleanly.
- Seal rotation, restore and `gatekeep rekey` against the key file (G-3).
- Rewrapping ciphertexts after a Transit key rotation (G-16).
