# Installing Gatekeep

How the Operator installs one Deployment (AD-26). Gatekeep runs only inside Docker: every process, OpenBao, the CLI, setup and key generation included, is a Compose service. The machine needs Docker with Compose and Git, and nothing else. Every command below is a `docker` or `git` command, run from the repository root.

Written for Story 1.10 and run on Docker Desktop (Linux containers) and in CI. No public route exists yet: Caddy, TLS and published ports arrive in Story 1.11.

## What the Docker host must provide

Gatekeep can't check any of these. They're the host owner's job, and the security of the Deployment depends on them.

| Requirement | Why |
| --- | --- |
| **Encrypted disks** for Docker's data (the named volumes) and for the secrets directory | The Master Key is a file in the secrets directory, and PostgreSQL and OpenBao data sit in volumes. A stolen disk or powered-off server is protected only by this encryption (T-30). Whether the host unlocks at boot unattended is the host owner's choice. |
| **The secrets directory on its own physical disk**, apart from Docker's data, if the threat of one stolen disk matters | Then a single stolen data disk holds no key. Gatekeep doesn't require it and can't check it (G-14). |
| **A trusted boot chain**: measured or secure boot, or physical control of the machine | With an unprotected boot chain, someone who tampers with a powered-off server can capture the disk passphrase or the key at the next boot. Gatekeep can't check it (G-14). |
| **A Linux host file system** for the secrets directory | The setup tools set owners and modes (`0400`, one owner per container). A Docker Desktop bind mount from Windows or macOS ignores them, and the tools print a warning when that happens. There, every container that mounts a secret file can read it whatever its user. |
| **A host firewall** that allows only the ports Compose publishes | No service publishes a port today. From Story 1.11, only Caddy will. |
| **Docker access is full control** | Anyone in the `docker` group, or with root, can read the Master Key, every secret and every volume, and start a container with any mount. Treat Docker access as root on Gatekeep (T-29). Give it to the Operator only. |
| **The secrets directory stays out of backups** and is never committed | It holds the Master Key, recovery keys, AppRole IDs and database passwords. Escrow the Master Key and recovery keys offline instead (`docs/key-custody.md`). |
| **Linux containers** | Every image is Linux. |

The secrets directory is `deploy/secrets` unless `GATEKEEP_SECRETS_DIR` says otherwise; a relative value is resolved against `deploy/`. Set it the same way for every command. It has four subdirectories: `master/` (the Master Key), `postgres/` (database passwords), `recovery/` (OpenBao recovery keys, until escrowed) and `approle/` (each role's AppRole IDs). Each setup tool mounts only the subdirectories it writes.

## Steps

1. **Get the source.**

   ```sh
   git clone <repository URL> gatekeep
   ```

2. **Build every image** from this repository. Base images are pinned by digest. Nothing is pulled at runtime.

   ```sh
   docker compose -f deploy/compose.yaml --profile tools --profile setup build
   ```

3. **Make the Master Key.** The `keygen` service writes 32 random bytes to `master/master-key`, owned by OpenBao's user with mode `0400`, and refuses to replace a key that exists.

   ```sh
   docker compose -f deploy/compose.yaml run --rm keygen
   ```

4. **Escrow the Master Key offline** now, before anything is sealed with it: `docs/key-custody.md`, step 3.

5. **Make the database passwords.** The `passwords` service writes a random password for the PostgreSQL superuser and each login role into `postgres/`, and keeps any that exists and isn't empty.

   ```sh
   docker compose -f deploy/compose.yaml run --rm passwords
   ```

6. **Start OpenBao and set it up.** OpenBao has no network. `openbao-setup` waits for its socket, initializes it, writes the policies, AppRoles and Deployment keys, writes the recovery keys into `recovery/` and each AppRole's IDs into `approle/`, and revokes the root token.

   ```sh
   docker compose -f deploy/compose.yaml up -d openbao
   docker compose -f deploy/compose.yaml run --rm openbao-setup
   ```

7. **Escrow the recovery keys and destroy the escrow file**: `docs/key-custody.md`, steps 6 and 7.

8. **Migrate.** This starts PostgreSQL, whose first start creates the roles from `deploy/postgres/roles.sql`, and `postgres-passwords`, which sets every role's password from its file. `gatekeep migrate` then runs in the `cli` container as `gk_migrator`, which supplies its connection and password files itself.

   ```sh
   docker compose -f deploy/compose.yaml run --rm cli migrate
   ```

9. **Start the stack.** `--wait` returns once every service reports healthy.

   ```sh
   docker compose -f deploy/compose.yaml up -d --wait
   ```

10. **Check.** Every service should show `healthy`, and `postgres-passwords` should have exited `0`.

    ```sh
    docker compose -f deploy/compose.yaml ps -a
    ```

## Changing a database password

Change the password file in `postgres/`, then recreate the stack. `postgres-passwords` runs on every `up` and sets every role's password from its file before any host starts, so a changed or restored file can't drift from the database, and the recreated hosts read the new file.

```sh
docker compose -f deploy/compose.yaml up -d --wait --force-recreate
```

## What the stack enforces

- **Secrets only as files.** Each secret reaches only the containers that need it, as a Compose secret under `/run/secrets`. No secret is in an image, an environment variable or `compose.yaml`. Only `keygen` can see `master/`; `passwords` sees only `postgres/`, and `openbao-setup` only `recovery/` and `approle/`. All three have no network.
- **Refusal of missing or default secrets.** Each host refuses to start if a required setting is missing, empty, a known default such as `changeme` or `postgres`, or a password under 16 characters. That includes its key custody settings: every host uses OpenBao. It logs the setting's name, never its value, and exits non-zero, so Compose shows it restarting. `gatekeep migrate` refuses an unsafe password the same way.
- **Hardened containers.** `Host.Hosted`, `Host.Admin`, `Host.Worker` and `cli` run as their own non-root user, with a read-only root filesystem, every capability dropped and `no-new-privileges`, as do PostgreSQL and OpenBao. Every service has a process limit and rotated logs. No runtime service has the Docker socket.
- **No egress, and separate networks.** Every network is internal. Each host has its own network and shares only PostgreSQL, so `Host.Hosted` has no route to `Host.Admin`. OpenBao is on no network at all.
- **Health.** Each host answers `/healthz` on port 8081 inside its network only, never published: `200 healthy`, or `503` with `unhealthy: database` or `unhealthy: custody`, within 3 seconds even when a dependency hangs. Compose uses it as the healthcheck.

## When it doesn't start

- **A host keeps restarting.** Its log names the setting it refused:

  ```sh
  docker compose -f deploy/compose.yaml logs hosted
  ```

- **OpenBao won't start** and its log mentions `seal "static"`: the Master Key file is missing from `master/`. Don't run `keygen` again unless this is a new install: a new key can't open data sealed by the old one. Restore the file from escrow.
- **OpenBao stays unhealthy** after starting: it hasn't been set up. Run step 6's `openbao-setup`.
- **A setup tool prints a WARNING about ownership or modes**: the secrets directory is on a file system that ignores them, such as a Docker Desktop bind mount from Windows or macOS. Fine for trying Gatekeep out; not for a Deployment.

## Not yet covered

- Caddy, TLS, the Admin site and published ports (Story 1.11).
- Signed images and `gatekeep upgrade` (Story 12.5 and Epic 12).
- Backups, which must leave the secrets directory out (Epic 12).
