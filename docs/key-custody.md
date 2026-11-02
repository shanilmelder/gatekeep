# Key custody: first setup

How the Operator sets up OpenBao for one Deployment (AD-10), as the Compose services in `deploy/compose.yaml`. Rewritten for Story 1.10 when Gatekeep moved to Docker only (`_bmad-output/planning-artifacts/sprint-change-proposal-2026-11-02-docker-only.md`). Every command is a `docker` command, run from the repository root. `docs/install.md` has the whole install; these are its custody steps in detail.

This document never holds a key, token, recovery share, role ID or secret ID, and nor may any note, ticket or chat about it. If one ends up somewhere it shouldn't, treat it as stolen and follow the rotation in AD-10.

## What you end up with

| Thing | Where | Who can read it |
| --- | --- | --- |
| Master Key (static seal key), 32 random bytes | `master/master-key` in the secrets directory (`GATEKEEP_SECRETS_DIR`, default `deploy/secrets`), on the Docker host. Never a Docker volume | On the host, root and anyone with Docker access. In containers, OpenBao as the read-only Compose secret `/run/secrets/master_key`, and `keygen`, which writes it. No other service mounts `master/` |
| Master Key escrow copies, every generation | Offline, in two places, apart from backups | Esm |
| Recovery keys and the first root token | `recovery/openbao-init.json` in the secrets directory for minutes, then offline with the Master Key | root, then Esm |
| OpenBao data (Raft) | The `openbao-data` volume | OpenBao's user |
| Audit log | The `openbao-audit` volume | OpenBao's user |
| OpenBao's socket | The `openbao-socket` volume, mode `0660`, group `gatekeep-custody` (gid 4500) | The hosts and `cli`, which run with that group |
| AppRole role ID and secret ID per host and the Cli | `approle/{role}/` in the secrets directory, `0400`, owned by that role's container user | That one container, as its Compose secrets `openbao_role_id` and `openbao_secret_id` |

The root token is revoked at the end of setup, so none exists afterwards.

## Before you start

- The Docker host requirements in `docs/install.md`: encrypted disks for the volumes and the secrets directory, and Docker access given only to the Operator.
- The images built: `docker compose -f deploy/compose.yaml --profile tools --profile setup build`.
- Two pieces of offline storage for escrow, such as two encrypted USB drives kept in different places. Neither is ever attached to the Docker host while it's on the network, and neither is part of any backup.

## Steps

1. **Make the Master Key.** `keygen` runs `deploy/openbao/generate-master-key.sh` with no network, mounting only `master/`. It writes `master-key` mode `0400` for OpenBao's user and prints only the path. It refuses to run unless the directory is mounted, and refuses to overwrite a key that exists. The owner and mode hold only on a Linux host file system: on a Docker Desktop bind mount from Windows or macOS they're ignored, and it prints a warning saying so.

   ```sh
   docker compose -f deploy/compose.yaml run --rm keygen
   ```

2. **Check the handoff.** The key reaches OpenBao only as a read-only secret file. This shows the mount, and no key value:

   ```sh
   docker compose -f deploy/compose.yaml config openbao
   ```

3. **Escrow the Master Key.** Copy `master/master-key` from the secrets directory to both offline drives, named with its generation and date, for example `master-key-gen1-2026-11-02`. Check each copy's SHA-256 against the original by eye, without writing the hash anywhere online. Don't email, sync, photograph or paste it.

4. **Start OpenBao.** It has no network and runs as its own non-root user with a read-only root filesystem. Without the key file it refuses to start, and that's intended. Until setup runs it reports unhealthy, because it isn't initialized.

   ```sh
   docker compose -f deploy/compose.yaml up -d openbao
   ```

5. **Run setup.** `openbao-setup` runs `deploy/openbao/setup.sh` against the socket, with no network, mounting only `recovery/` and `approle/`: it can't read the Master Key or the database passwords. It waits up to 30 seconds for OpenBao to answer, then initializes it with 5 recovery shares (threshold 3) written only to `recovery/openbao-init.json`, enables Transit, writes the four policies, creates the four AppRoles with 15-minute tokens (1 hour maximum), writes each role's ID and secret ID under `approle/`, mode `0400` and owned by that role's container user (with the same Linux-only caveat and warning as step 1), creates the `dep-email`, `dep-payload`, `dep-hmac` and `dep-records` keys, and revokes the root token. It prints progress only.

   ```sh
   docker compose -f deploy/compose.yaml run --rm openbao-setup
   ```

6. **Escrow the recovery keys.** Copy `recovery/openbao-init.json` to the same two offline drives, next to the Master Key generation it belongs to. The root token inside it is already revoked.

7. **Destroy the escrow file.** On an encrypted disk this removes the only online copy; `shred` can't promise more on a journaling or copy-on-write file system.

   ```sh
   docker compose -f deploy/compose.yaml run --rm --entrypoint shred openbao-setup -u /secrets/recovery/openbao-init.json
   ```

8. **Check.** OpenBao reports healthy once unsealed:

   ```sh
   docker compose -f deploy/compose.yaml exec openbao bao status -address=unix:///run/openbao/openbao.sock
   ```

   It shows `Sealed false`, `Seal Type static` and `Storage Type raft`.

## If setup fails after init

Setup revokes the root token on any failure or interrupt, so a half-done server can't be finished by hand, and nothing is stored in it yet. Start again from a clean OpenBao:

```sh
docker compose -f deploy/compose.yaml rm -fs openbao
docker volume rm gatekeep_openbao-data gatekeep_openbao-audit
docker compose -f deploy/compose.yaml run --rm --entrypoint shred openbao-setup -u /secrets/recovery/openbao-init.json
docker compose -f deploy/compose.yaml up -d openbao
docker compose -f deploy/compose.yaml run --rm openbao-setup
```

The recovery keys of the failed init open nothing you'll keep. The Master Key can stay: it hasn't sealed anything you'll keep, and it's already escrowed.

## Rules that outlast setup

- **Keep every generation.** A new Master Key (seal rotation) never replaces the old escrow copy. Each generation stays escrowed until the last backup that needs it has expired, because an OpenBao snapshot can only be opened with the generation it was taken under.
- **Apart from backups.** The secrets directory and the escrow drives are never in a backup set. No backup set exists yet: the backup story must exclude them and check it.
- **Nothing else.** No Master Key, recovery key, root token, role ID or secret ID in a container image, an environment variable, a Docker volume, `docs/`, a log or the repository.
- **Not hardware-bound.** The Master Key is a file on the Docker host. Anyone with root or Docker access there, or who copies it and an OpenBao snapshot, has every key, and old copies stay valid until the key rotates. The TPM design is retired: see `docs/spikes/1-2-key-custody.md`.

## Still open

- Seal rotation, restore and `gatekeep rekey` against the key file (G-3).
- Rewrapping ciphertexts after a Transit key rotation (G-16).
