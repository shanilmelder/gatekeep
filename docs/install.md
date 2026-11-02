# Installing Gatekeep

How the Operator installs one Deployment (AD-26). Gatekeep runs only inside Docker: every process, OpenBao, the CLI, setup and key generation included, is a Compose service. The machine needs Docker with Compose and Git, and nothing else. Every command below is a `docker` or `git` command, run from the repository root.

Written for Story 1.10, with Caddy, TLS and published ports added by Story 1.11. Story 1.12 added the dedicated-zone rule and the "Not yet covered" list. Run on Docker Desktop (Linux containers) and in CI. Production TLS (`cloudflare` mode) has been validated offline only: it hasn't yet obtained a real certificate.

## What the Docker host must provide

Gatekeep can't check any of these. They're the host owner's job, and the security of the Deployment depends on them.

| Requirement | Why |
| --- | --- |
| **Encrypted disks** for Docker's data (the named volumes) and for the secrets directory | The Master Key is a file in the secrets directory, and PostgreSQL and OpenBao data sit in volumes. A stolen disk or powered-off server is protected only by this encryption (T-30). Whether the host unlocks at boot unattended is the host owner's choice. |
| **The secrets directory on its own physical disk**, apart from Docker's data, if the threat of one stolen disk matters | Then a single stolen data disk holds no key. Gatekeep doesn't require it and can't check it (G-14). |
| **A trusted boot chain**: measured or secure boot, or physical control of the machine | With an unprotected boot chain, someone who tampers with a powered-off server can capture the disk passphrase or the key at the next boot. Gatekeep can't check it (G-14). |
| **A Linux host file system** for the secrets directory | The setup tools set owners and modes (`0400`, one owner per container). A Docker Desktop bind mount from Windows or macOS ignores them, and the tools print a warning when that happens. There, every container that mounts a secret file can read it whatever its user. |
| **A host firewall** that allows only the ports Compose publishes | Only Caddy publishes, on TCP 80 and 443. Allow those two inbound and nothing else. |
| **Docker access is full control** | Anyone in the `docker` group, or with root, can read the Master Key, every secret and every volume, and start a container with any mount. Treat Docker access as root on Gatekeep (T-29). Give it to the Operator only. |
| **The secrets directory stays out of backups** and is never committed | It holds the Master Key, recovery keys, AppRole IDs and database passwords. Escrow the Master Key and recovery keys offline instead (`docs/key-custody.md`). |
| **Linux containers** | Every image is Linux. |

The secrets directory is `deploy/secrets` unless `GATEKEEP_SECRETS_DIR` says otherwise; a relative value is resolved against `deploy/`. Set it the same way for every command. It has four subdirectories: `master/` (the Master Key), `postgres/` (database passwords), `recovery/` (OpenBao recovery keys, until escrowed) and `approle/` (each role's AppRole IDs), and in production a fifth, `cloudflare/`, holding the Cloudflare DNS token (see "Hostnames and TLS"). Each setup tool mounts only the subdirectories it writes.

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

9. **Start the stack.** `--wait` returns once every service reports healthy. On a production host, first set the hostnames and add the Cloudflare override to this and every later command, as "Hostnames and TLS" below says. Without them Caddy serves the local defaults with its internal CA.

   ```sh
   docker compose -f deploy/compose.yaml up -d --wait
   ```

10. **Check.** Every service should show `healthy`, and `postgres-passwords` should have exited `0`.

    ```sh
    docker compose -f deploy/compose.yaml ps -a
    ```

## Verifying the audit chains

`gatekeep audit verify` walks every audit chain, the Deployment's and each Tenant's, as `gk_cli`, which can only read them. It checks that no row is missing, that each row links to the one before and that each hash recomputes. It prints one line per problem, naming the chain (a Tenant ID or `deployment`), the epoch and the `seq`, never a row's content, then a count, and exits `1` on any problem and `0` when every chain verifies:

```sh
docker compose -f deploy/compose.yaml run --rm cli audit verify
```

```text
chain deployment: seq 1-2: missing (no checkpoint names seq 2)
verified 4 chains, 1,203 sealed rows, 1 problem
```

The `cli` service supplies its own connection and password files. A row sealed in the last second or so isn't walked yet. The range the daily retention job removed is accounted for by the checkpoint it writes, sealed or not yet.

Audit events are kept for 90 days. Retention runs daily in `Host.Worker` and deletes only older, sealed events. The period is fixed in the release, and no setting, route or command changes it.

## Hostnames and TLS

Caddy is the only way in (AD-2, AD-26). It serves two sites and refuses everything else:

| Site | Setting | Local default | Proxied to |
| --- | --- | --- | --- |
| Every Tenant host, `*.{zone}` | `GATEKEEP_TENANT_ZONE` | `gatekeep.localhost` | `Host.Hosted`, port 8080 |
| The Admin hostname | `GATEKEEP_ADMIN_HOST` | `admin.gatekeep-admin.localhost` | `Host.Admin`, port 8080 |

- **The Tenant zone is used only by Gatekeep** (NFR-21). Here "zone" means a DNS name and everything under it, such as `id.example.com`, not necessarily a zone of its own in Cloudflare. No application, mail server or other host may have a name under it, the zone itself included, because the `*.{zone}` wildcard certificate covers every name there: whoever holds its key can impersonate any of them, and a foreign site there would be a sibling origin of every Tenant (`docs/threat-model.md`, T-17 and T-35). Pick a name of its own rather than a domain that already serves something. Hosts on the parent domain (`example.com` in the examples, which also serves `admin.example.com`) can still set `Domain=example.com` cookies that every Tenant name receives (T-17). Gatekeep's own `__Host-` cookies can't be overwritten that way, but only put hosts you trust on the parent domain.
- **The Admin hostname must be outside the Tenant zone**: not the zone itself and not any name under it. Caddy refuses to start otherwise, and its log names `GATEKEEP_ADMIN_HOST`. For example, with the zone `id.example.com`, use `admin.example.com`, never `admin.id.example.com`.
- Only one label under the zone is served: `acme.id.example.com`, not `id.example.com` or `a.b.id.example.com`. Any name Caddy doesn't serve fails the TLS handshake. A request whose `Host` header isn't the name its TLS connection was for gets an empty `421`, so one site's connection never reaches the other.
- Plain HTTP on port 80 only redirects the two sites to HTTPS, with no body and no cookie, and closes the connection for any other name.
- Caddy publishes host ports 80 and 443. `GATEKEEP_HTTP_PORT` and `GATEKEEP_HTTPS_PORT` change them on a machine where those are taken, such as a Windows desktop that holds 80; a production host keeps 80 and 443.
- The Admin site is public, with no VPN and no IP allowlist (`sprint-change-proposal-2026-11-02-public-admin.md`). Its protection is WebAuthn-only sign-in and the controls in `docs/threat-model.md`, T-47.

### TLS modes

Caddy gets certificates for both sites in one of two modes. **Only `deploy/compose.cloudflare.yaml` switches the mode**: `compose.yaml` sets `GATEKEEP_TLS_MODE` to `internal` itself, so setting it in `deploy/.env` or the environment has no effect.

- **`internal`** (without the override, for local runs and CI): Caddy's own local CA. No browser trusts it, and it needs no token and makes no outside call. The root certificate stays in Caddy's `caddy-data` volume and is never installed anywhere.
- **`cloudflare`** (production): publicly trusted certificates from ACME (Let's Encrypt, falling back to ZeroSSL) for the `*.{zone}` wildcard and the Admin hostname, both validated by DNS-01 through Cloudflare DNS. Adding `-f deploy/compose.cloudflare.yaml` turns it on.

Certificates and their private keys live only in the `caddy-data` volume, which no other service mounts, readable only by Caddy's user.

### Cloudflare DNS for production

Challenge records never go into the zone that serves Gatekeep's names (NFR-21). They go into a separate **validation-only zone** that holds nothing else, so the API token Caddy holds can't touch the real records. With the Tenant zone `id.example.com`, the Admin hostname `admin.example.com` and a validation zone `example-acme.com`, all in Cloudflare:

1. **The sites' records.** Choose a Tenant zone nothing else uses (see "Hostnames and TLS" above). In the zone that holds them, add `*.id.example.com` and `admin.example.com` as `A` records to the Docker host's public IPv4 address. Don't add `AAAA` records: the Compose networks are IPv4 only, and IPv6 traffic would reach Caddy through Docker's proxy, from an address inside the `edge` network rather than the client's. Set both to **DNS only** (grey cloud), never proxied, so Cloudflare never terminates or sees Gatekeep traffic.
2. **The validation-only zone.** Add `example-acme.com` to Cloudflare as its own zone, used for nothing else.
3. **The challenge CNAMEs.** In the sites' zone, add two `CNAME` records, both **DNS only**:
   - `_acme-challenge.id.example.com` to `id.example-acme.com`
   - `_acme-challenge.admin.example.com` to `admin.example-acme.com`
4. **CAA records.** In the sites' zone, allow only the CAs Caddy uses: `CAA 0 issue "letsencrypt.org"` and `CAA 0 issue "sectigo.com"` (ZeroSSL) on `id.example.com` and on `admin.example.com`, plus `CAA 0 issuewild "letsencrypt.org"` and `CAA 0 issuewild "sectigo.com"` on `id.example.com`. Add an `iodef` address to hear about refusals. Watch Certificate Transparency for both names.
5. **The API token.** In the Cloudflare dashboard, under API Tokens, create a custom token with the permissions `Zone : DNS : Edit` and `Zone : Zone : Read` (the provider module needs it to find the zone), and under Zone Resources include **only** the validation zone `example-acme.com`. Restrict it to the Docker host's address if you can, and give it an expiry you'll renew.
6. **Hand the token to Caddy.** Save it as `cloudflare/dns-token` in the secrets directory, on one line. Give the file mode `0400`, owned by uid `10005`, Caddy's user, on a Linux host file system. It's a secret like the Master Key: never committed, never in an environment variable, never backed up with the data.
7. **Set the names and start with the override.** Put the settings in `deploy/.env`, which Compose reads and which never leaves the host:

   ```text
   GATEKEEP_TENANT_ZONE=id.example.com
   GATEKEEP_ADMIN_HOST=admin.example.com
   GATEKEEP_ACME_EMAIL=ops@example.com
   GATEKEEP_ACME_CHALLENGE_DOMAIN=id.example-acme.com
   GATEKEEP_ADMIN_ACME_CHALLENGE_DOMAIN=admin.example-acme.com
   ```

   Then add `-f deploy/compose.cloudflare.yaml` to every command, starting with step 9:

   ```sh
   docker compose -f deploy/compose.yaml -f deploy/compose.cloudflare.yaml up -d --wait
   ```

   Caddy refuses to start in `cloudflare` mode if a setting is missing or the token file is empty, and its log names which. A certificate it can't obtain shows up in its log:

   ```sh
   docker compose -f deploy/compose.yaml -f deploy/compose.cloudflare.yaml logs caddy
   ```

### What Caddy doesn't do yet

- **Its healthcheck proves only that it listens** on 8443, not that it holds valid certificates. A certificate Caddy couldn't obtain or renew shows up only in its log and in clients' errors.
- **`edge` gives Caddy unrestricted egress.** It needs it for ACME and the Cloudflare API in `cloudflare` mode, but nothing limits it to them, so code execution in Caddy can reach the internet (`docs/threat-model.md`, Z-9).
- **The hosts see Caddy's address, not the client's,** and no forwarded header is trusted yet. Which forwarded headers to trust, and so real client addresses for rate limits, is Story 1.20's decision.
- **No access log at the edge.** One is deferred, because a request line can carry sensitive query values such as codes and tokens (`docs/threat-model.md`, T-42).

A stolen token can issue certificates for both sites, the wildcard included, while it lives (`docs/threat-model.md`, Cloudflare DNS API token). Revoke and replace it if the host is compromised.

## Install a signed release

The steps above build every image from source. To run a published release instead, every Gatekeep image comes from GHCR by digest, and is checked against the release key pinned on this host before anything runs (Story 12.5). `docs/release-signing.md` says how releases are signed.

1. **Pin the release key**, once per host: put Esm's public key at `deploy/trust/release-signing.pub`, copied by hand, never downloaded from the release, and compare its SHA-256 with Esm's (`docs/release-signing.md`, "Pin the key on a Docker host"). `GATEKEEP_TRUST_DIR` moves the directory; a relative value is resolved against `deploy/`. It's a host directory like the secrets directory: never a volume, never committed, never in an image.

2. **Get the release.** Check out the release tag, then download that release's `release.env` from its GitHub release page into `deploy/release.env`. It holds one `GATEKEEP_<SVC>_IMAGE=<repository>@sha256:<digest>` line per image, and nothing else. The images and their signatures must be pullable from this host: the release packages are public, and if one isn't, run `docker login ghcr.io` here first.

   ```sh
   git fetch --tags
   git checkout v1.2.3
   ```

3. **Check every image.** `release-verify` checks each digest's signature and signed SBOM against the pinned key, and refuses a tag reference, an unsigned image, another key's signature, an image in another service's slot, images from two releases or a missing key file. Don't go on unless it ends with `every image is signed by the pinned key`.

   ```sh
   docker compose -f deploy/compose.yaml -f deploy/compose.release.yaml --env-file deploy/release.env --profile release run --rm release-verify
   ```

4. **Install** with steps 3 to 10 above, adding the overlay and the env file to every command. Skip step 2: nothing is built, and Compose refuses to start if any image variable is missing rather than build one. For example:

   ```sh
   docker compose -f deploy/compose.yaml -f deploy/compose.release.yaml --env-file deploy/release.env run --rm keygen
   docker compose -f deploy/compose.yaml -f deploy/compose.release.yaml --env-file deploy/release.env up -d --wait
   ```

   On a production host, also add the Cloudflare override, and name `deploy/.env` as well: once any `--env-file` is given, Compose reads only the files named, so the hostnames in `deploy/.env` would otherwise be lost. Use this form for step 3 above too:

   ```sh
   docker compose -f deploy/compose.yaml -f deploy/compose.cloudflare.yaml -f deploy/compose.release.yaml --env-file deploy/.env --env-file deploy/release.env up -d --wait
   ```

Caddy keeps its `edge` network, and `release-verify` alone gets egress besides, on a `registry` network that exists only in the overlay. The pinned key is mounted into `release-verify` alone, read-only. Moving an existing Deployment to a new release is `gatekeep upgrade` (Story 12.6), which isn't built yet.

## Changing a database password

An install made before `gatekeep audit verify` existed has no `gk_cli` password: run step 5's `passwords` again, which writes only the missing one, then recreate the stack.

Change the password file in `postgres/`, then recreate the stack. `postgres-passwords` runs on every `up` and sets every role's password from its file before any host starts, so a changed or restored file can't drift from the database, and the recreated hosts read the new file.

```sh
docker compose -f deploy/compose.yaml up -d --wait --force-recreate
```

## What the stack enforces

- **Secrets only as files.** Each secret reaches only the containers that need it, as a Compose secret under `/run/secrets`. No secret is in an image, an environment variable or `compose.yaml`. Only `keygen` can see `master/`; `passwords` sees only `postgres/`, and `openbao-setup` only `recovery/` and `approle/`. All three have no network.
- **Refusal of missing or default secrets.** Each host refuses to start if a required setting is missing, empty, a known default such as `changeme` or `postgres`, or a password under 16 characters. That includes its key custody settings: every host uses OpenBao. It logs the setting's name, never its value, and exits non-zero, so Compose shows it restarting. `gatekeep migrate` refuses an unsafe password the same way.
- **Hardened containers.** `Host.Hosted`, `Host.Admin`, `Host.Worker` and `cli` run as their own non-root user, with a read-only root filesystem, every capability dropped and `no-new-privileges`, as do PostgreSQL and OpenBao. Every service has a process limit and rotated logs. No runtime service has the Docker socket.
- **One way in.** Only Caddy publishes ports, 80 and 443. It runs as its own non-root user, read-only, with every capability dropped and no admin API.
- **No egress, and separate networks.** Only Caddy's `edge` network reaches outside; every other network is internal. Each host has its own network and shares only PostgreSQL. Caddy reaches `Host.Hosted` over `hosted-edge` and `Host.Admin` over `admin-edge`, each holding just that host and Caddy, on fixed subnets (`10.201.1.0/24` and `10.201.2.0/24`). Each site closes the connection on a request from the other host's edge subnet, so `Host.Hosted` has no route to `Host.Admin`, directly or through Caddy, and Caddy has none to the worker, PostgreSQL or OpenBao. Those subnets must not clash with other networks on the Docker host. OpenBao is on no network at all.
- **Health.** Each host answers `/healthz` on port 8081 on its own loopback only, never published and unreachable from any other container, Caddy included: `200 healthy`, or `503` with `unhealthy: database` or `unhealthy: custody`, within 3 seconds even when a dependency hangs. Compose uses it as the healthcheck.

## When it doesn't start

- **A host keeps restarting.** Its log names the setting it refused:

  ```sh
  docker compose -f deploy/compose.yaml logs hosted
  ```

- **Caddy keeps restarting.** Its log starts with `caddy: refusing to start:` and names the setting, for example an Admin hostname under the Tenant zone:

  ```sh
  docker compose -f deploy/compose.yaml logs caddy
  ```

- **Port 80 or 443 is taken** and Caddy won't start: free it, or on a machine that isn't a Deployment set `GATEKEEP_HTTP_PORT` and `GATEKEEP_HTTPS_PORT` to others.
- **OpenBao won't start** and its log mentions `seal "static"`: the Master Key file is missing from `master/`. Don't run `keygen` again unless this is a new install: a new key can't open data sealed by the old one. Restore the file from escrow.
- **OpenBao stays unhealthy** after starting: it hasn't been set up. Run step 6's `openbao-setup`.
- **A setup tool prints a WARNING about ownership or modes**: the secrets directory is on a file system that ignores them, such as a Docker Desktop bind mount from Windows or macOS. Fine for trying Gatekeep out; not for a Deployment.

## Not yet covered

These steps install the stack, not a usable product. What they can't deliver yet, and the work that owns each:

- **A working Admin Dashboard.** After install every host reports healthy, but there's no Admin sign-in, bootstrap or Dashboard to use yet (Stories 1.21 to 1.25).
- **Certificate Transparency alerts.** Gatekeep raises none yet (Epic 11). Until then watch CT logs yourself for the wildcard `*.id.example.com` and the Admin hostname `admin.example.com`: search crt.sh regularly, or subscribe both names to a CT monitoring service that emails you on each new certificate. Any certificate Caddy didn't obtain is misissued.
- **Emergency certificate replacement.** No procedure or rehearsal exists yet for a stolen key or misissued certificate (Story 13.6). As a stopgap: revoke the certificate with the CA that issued it (Let's Encrypt or ZeroSSL, through ACME revocation or the CA's own process); roll the Cloudflare token in the dashboard and write the new one to `cloudflare/dns-token`; then remove the certificates from `caddy-data` and restart Caddy, which obtains new ones and a new key:

  ```sh
  docker compose -f deploy/compose.yaml -f deploy/compose.cloudflare.yaml stop caddy
  docker compose -f deploy/compose.yaml -f deploy/compose.cloudflare.yaml run --rm --no-deps --entrypoint sh caddy -c 'rm -rf /data/caddy/certificates/*/wildcard_.id.example.com /data/caddy/certificates/*/admin.example.com'
  docker compose -f deploy/compose.yaml -f deploy/compose.cloudflare.yaml up -d --wait caddy
  ```

- **Real client addresses.** No forwarded header is trusted yet, so the hosts see Caddy's address, not the client's (Story 1.20).
- **IPv6.** The Compose networks are IPv4 only. Add no `AAAA` records.
- **A real production certificate.** `cloudflare` mode has been validated offline only and has never obtained a real certificate. On the first production start, watch Caddy's log until both certificates are obtained.
- **Backups and upgrades.** No backup, restore or `gatekeep upgrade` yet. Backups must leave the secrets directory out (Epic 12). Signed releases can be installed ("Install a signed release" above), but `gatekeep upgrade`, which will check signatures itself, is Story 12.6.
