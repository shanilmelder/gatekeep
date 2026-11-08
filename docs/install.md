# Installing Gatekeep

How the Operator installs one Deployment (AD-26). Gatekeep runs only inside Docker: every process, OpenBao, the CLI, setup and key generation included, is a Compose service. The machine needs Docker with Compose and Git, and nothing else. Every command below is a `docker` or `git` command, run from the repository root.

Written for Story 1.10, with Caddy, TLS and published ports added by Story 1.11. Story 1.12 added the dedicated-zone rule and the "Not yet covered" list, and Story 1.30 the alert channel and off-server bucket. Run on Docker Desktop (Linux containers) and in CI. Production TLS (`cloudflare` mode) has been validated offline only: it hasn't yet obtained a real certificate.

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

The secrets directory is `deploy/secrets` unless `GATEKEEP_SECRETS_DIR` says otherwise; a relative value is resolved against `deploy/`. Set it the same way for every command. It has seven subdirectories: `master/` (the Master Key), `postgres/` (database passwords), `recovery/` (OpenBao recovery keys, until escrowed), `approle/` (each role's AppRole IDs), `bootstrap/` (the one-time bootstrap token, see step 12), `alerts/` (the alert channel's token) and `records/` (the off-server bucket's write-only credential), both written by the Operator (see step 9), and in production an eighth, `cloudflare/`, holding the Cloudflare DNS token (see "Hostnames and TLS"). Each setup tool mounts only the subdirectories it writes.

## Steps

1. **Get the source.**

   ```sh
   git clone <repository URL> gatekeep
   ```

2. **Build every image** from this repository. Base images are pinned by digest. Nothing is pulled at runtime.

   ```sh
   docker compose -f deploy/compose.yaml --profile tools --profile setup build
   ```

3. **Make the Master Key.** The `keygen` service writes 32 random bytes to `master/master-key`, owned by OpenBao's user with mode `0400`, and its ID, `gatekeep-master-1`, to `master/master-key-id`, and refuses to replace either. Replacing the key later is a rotation: `docs/runbooks/master-key-rotation.md`.

   ```sh
   docker compose -f deploy/compose.yaml run --rm keygen
   ```

4. **Escrow the Master Key offline** now, before anything is sealed with it: `docs/key-custody.md`, step 3.

5. **Make the database passwords and the bootstrap directory.** The `passwords` service writes a random password for the PostgreSQL superuser and each login role into `postgres/`, and keeps any that exists and isn't empty. The `bootstrap-dir` service makes `bootstrap/`, where step 12 writes the bootstrap token, with mode `0700` and the `cli` service's uid, `10004`, as owner. `bootstrap/` must be a real directory, not a symbolic link; running `bootstrap-dir` again changes nothing. Compose never creates it, so `cli init` fails until this step has run.

   ```sh
   docker compose -f deploy/compose.yaml run --rm passwords
   docker compose -f deploy/compose.yaml run --rm bootstrap-dir
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

9. **Connect the alert channel and the off-server bucket.** Security Alerts and the off-server record leave the Deployment for services on another provider, which an intruder on this host can't reach into (AD-17). `Host.Worker` refuses to start until both are set, as below, and names each setting it refuses. "Alert channel and off-server bucket" below says what each provider must offer, every setting and secret file, and how to prove both work. Do that now, before the stack starts.

10. **Start the stack.** `--wait` returns once every service reports healthy. On a production host, first set the hostnames and add the Cloudflare override to this and every later command, as "Hostnames and TLS" below says. Without them Caddy serves the local defaults with its internal CA.

    ```sh
    docker compose -f deploy/compose.yaml up -d --wait
    ```

11. **Check.** Every service should show `healthy`, and `postgres-passwords` should have exited `0`. `openbao-audit-shipper` should be `running`: it has no healthcheck.

    ```sh
    docker compose -f deploy/compose.yaml ps -a
    ```

12. **Initialise the Deployment.** `gatekeep init` runs in the `cli` container. It first makes sure the Deployment's own keys exist in OpenBao (`dep-email`, `dep-payload`, `dep-hmac` and `dep-records`, which sign off-server records), leaving any that exist unchanged. Then, as `gk_cli`, it writes a fresh one-time bootstrap token, 64 hex characters, to `bootstrap/bootstrap-token` in the secrets directory, mode `0600` in the `0700` directory, and stores only the token's SHA-256 in the database with an expiry 15 minutes later. It prints the file's place and the expiry in UTC, never the token. It refuses, changing nothing, if bootstrap is already complete, or if the token directory is a symbolic link, isn't owned by uid `10004` or is writable by anyone else: run `bootstrap-dir` again to fix it. Until the new token is committed, the previous token file stays in place.

    ```sh
    docker compose -f deploy/compose.yaml run --rm cli init
    ```

    Read the token on the Docker host as root: `sudo cat deploy/secrets/bootstrap/bootstrap-token`, with the default secrets directory. Only root, or whoever holds uid `10004`, can read it there, and that's all "root-only" means on a Docker host: root and Docker access are full control anyway (T-29). Docker access reads it too, through the setup service that made its directory. That prints the token in that container's output, so run it only at a terminal nobody records:

    ```sh
    docker compose -f deploy/compose.yaml run --rm --entrypoint cat bootstrap-dir /secrets/bootstrap/bootstrap-token
    ```

    Finish bootstrap within 15 minutes. If the token expires first, run `init` again: each run replaces the token and voids the one before, until bootstrap is complete, after which `init` refuses and exits `1`. The token file is never copied into an image, a volume or a backup; keep the secrets directory out of backups as for every other secret. Bootstrap itself, which consumes the token, is Story 1.21 and isn't built yet.

## Recover Admin access

`gatekeep recover-admin` (Story 1.32) is the way back in for an Admin who lost every WebAuthn credential, or for the first Admin whose setup Session ended before they registered two. It runs only in the `cli` container, on the Docker host: no route in any host, and no job, issues what it issues. It needs the settings `init`, `alerts test` and `records test` use (see "Alert channel and off-server bucket"), and it is never quiet. In this order, it:

1. finds the Admin. With one Admin, that one; with more, name one with `--admin` and its `adm_` public ID. Without `--admin` it refuses and lists every Admin's public ID. Before bootstrap there is no Admin, and it refuses and points to `gatekeep init`;
2. sends an `admin.recovery.started` Security Alert through the alert channel and waits for a 2xx;
3. signs an `admin_recovery` record with `dep-records` and writes it to the off-server bucket, at `records/admin_recovery/{yyyy}/{MM}/{dd}/{recordId}.json`, and waits for the bucket;
4. only then stores a single-use enrolment, held only as its SHA-256 in `admin_enrolment`, with the `admin.enrolment.issued` audit event, and commits;
5. prints a link, once: `https://{Admin hostname}/recover#{enrolment}`.

```sh
docker compose -f deploy/compose.yaml run --rm cli recover-admin
docker compose -f deploy/compose.yaml run --rm cli recover-admin --admin adm_...
```

The alert and the record name the Admin, the enrolment and its issue and expiry times, never the enrolment itself. If the alert is refused or unreachable, it exits `1` having written nothing; if the record is refused, or can't be signed, it exits `1` with nothing stored, and the alert that already went out is a false alarm. Either way nothing is printed but the reason. Run it again once the channel or bucket is fixed.

The link works once, for 15 minutes. It names the Admin hostname from `GATEKEEP_ADMIN_HOST`; on a machine where Caddy publishes HTTPS on another port (`GATEKEEP_HTTPS_PORT`), add `:{port}` after the hostname before opening it. The enrolment is in the link's fragment, which the browser never sends, so it reaches no request line or Caddy log; the Recover page reads it, clears it from the address bar and sends it when you press Continue. Using it uses up any other unused link for that Admin, ends every Session that Admin holds, as revoked, and starts one that reaches only credential registration: an Admin who never finished setup registers two credentials, and any other registers one, which makes the Session full and ends the others. WebAuthn stays the only way in. A used, expired or unknown link is refused the same way; run `recover-admin` again for a new one. The lost credentials stay registered: retiring them is Story 8.3.

Anyone with Docker access to the host can run it, which is why it alerts before it issues anything: treat an alert nobody here expected as a compromised host (T-21).

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

## Alert channel and off-server bucket

Step 9 (Story 1.30). Gatekeep sends Security Alerts to a service outside the Deployment and keeps its evidence in a bucket the server can write to but never erase (AD-17). Both are chosen at install, on a provider other than the one that runs the Docker host, so an intruder here can't silence or rewrite them. Each is reached over HTTPS through Gatekeep's one outbound path, `EgressHttp`, which refuses any name that resolves only to a private, loopback, link-local or otherwise reserved address (`docs/threat-model.md`, TB-12 lists the ranges), and tries a name's IPv4 addresses before its IPv6 ones.

### What each provider must offer

- **The alert channel: an HTTPS webhook** at a service that pages or emails a person, such as an incident service, directly or through its webhook bridge. It must accept a `POST` of JSON with an `Authorization: Bearer` token, and answer `2xx`. Anything else, a redirect included, counts as a failure, and nothing is retried. Each alert holds only `code` (such as `operations.alert.test`), `alertId`, `raisedAt` in UTC, `deployment` (the Admin hostname), a fixed `summary` for the code, and `tenantId` and `eventId` when it has them: no personal data, credential, token, address query or free text. The webhook's URL must carry no credential: it sits in `deploy/.env` and in each container's environment, where `docker inspect` shows it. A service whose webhook URL is itself the secret, with a key in its path or query, needs a bridge that takes a bearer token instead. The token goes in `alerts/token` (below), which only reaches the containers as a Compose secret.
- **The off-server bucket: an S3-API bucket on a separate provider**, created with **versioning and Object Lock** on, and a default retention in **compliance** mode of **at least 90 days**. Every object Gatekeep writes carries compliance mode, a retain-until date at least 90 days on, and `Content-MD5`, at path-style URLs (`https://<endpoint>/<bucket>/<key>`), so the bucket needs no DNS name of its own.
- **A write-only credential for the server.** It may write objects and nothing else: no read, list, delete, version delete or governance bypass. S3 requires `s3:PutObjectRetention` beside `s3:PutObject` for a write that carries Object Lock headers, and in compliance mode that lets it lengthen a retention but never shorten or remove one. A policy in the AWS form, which most S3 providers take:

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": ["s3:PutObject", "s3:PutObjectRetention"],
        "Resource": ["arn:aws:s3:::gatekeep-records-example/*"]
      }
    ]
  }
  ```

- **Console logins kept off this host.** Whoever holds the provider's console can lift these protections from outside Gatekeep (`docs/threat-model.md`, provider console logins).

### Settings and secret files

Put the settings in `deploy/.env`, which Compose reads and which never leaves the host:

```text
GATEKEEP_ALERT_URL=https://alerts.example.net/hooks/gatekeep
GATEKEEP_RECORDS_ENDPOINT=https://s3.eu-central-1.example.net
GATEKEEP_RECORDS_REGION=eu-central-1
GATEKEEP_RECORDS_BUCKET=gatekeep-records-example
```

| Setting | Must be |
| --- | --- |
| `GATEKEEP_ALERT_URL` | The webhook: an absolute `https` URL with no user info. A path and query are allowed, but no credential in either: the token belongs in `alerts/token` |
| `GATEKEEP_RECORDS_ENDPOINT` | The S3 API endpoint: an absolute `https` URL with nothing after the host and port |
| `GATEKEEP_RECORDS_REGION` | The bucket's region, such as `eu-central-1`: lower-case letters, digits and hyphens |
| `GATEKEEP_RECORDS_BUCKET` | The bucket's name, following the S3 naming rules |
| `GATEKEEP_ADMIN_HOST` | Already set for Caddy ("Hostnames and TLS"): it names the Deployment in every alert |

The secrets are files in the secrets directory, each value on one line, never in `deploy/.env` or an environment variable. Each value is printable ASCII with no space inside it, as an HTTP header needs. Like the database passwords, give each file mode `0444` in a `0700` directory on a Linux host file system: `Host.Worker` and the `cli` read all three, and the audit shipper the bucket's two.

| File | Holds |
| --- | --- |
| `alerts/token` | The webhook's bearer token |
| `records/access-key-id` | The write-only credential's access key ID |
| `records/secret-access-key` | The write-only credential's secret key |

`Host.Worker` refuses to start, naming every setting it refuses and never a value, when one is missing, a URL isn't absolute `https` or has user info, the bucket or region breaks the S3 rules, or a file is missing, empty, a known default such as `changeme`, or holds a space, tab, control or non-ASCII character inside its value. The `cli` commands refuse by the same rules, and the adapters check each file again at every send, by the same rule, so a file that passes at startup isn't refused later unless it changes. It only checks them: it sends nothing at startup. Inside the containers the settings are `Alerts:Url`, `Alerts:TokenFile`, `Alerts:Deployment`, `Records:Endpoint`, `Records:Region`, `Records:Bucket`, `Records:AccessKeyIdFile` and `Records:SecretAccessKeyFile` for `Host.Worker`, and the `GATEKEEP_ALERT_*` and `GATEKEEP_RECORDS_*` variables for the `cli` and the shipper, which `deploy/compose.yaml` sets.

### Prove both work

Send a test alert, then write a signed test record. Each refuses the same way before doing anything when a setting is wrong, and prints only fixed lines: never the address, the token, the credential or the provider's answer.

```sh
docker compose -f deploy/compose.yaml run --rm cli alerts test
docker compose -f deploy/compose.yaml run --rm cli records test
```

- `alerts test` sends one `operations.alert.test` alert and prints `Test alert delivered.` with the alert's ID. Check that it reached a person. On failure it prints `Alert channel rejected the alert.`, `Alert channel unavailable.` `Alert channel refused: private address.` (the URL's name resolves only to private addresses) or `Alert channel refused: token file unusable.` (the token file changed since the check and can't be read, or holds an unusable value), and exits `1`.
- `records test` signs a test record with `dep-records`, as the `cli` AppRole, and writes it to `records/test/{yyyy}/{MM}/{dd}/{recordId}.json`, printing that key. In the provider's console, check that the object is in compliance mode until at least 90 days from now. On failure it prints `Off-server store rejected the record.`, `Off-server store unavailable.` `Off-server store refused: private address.` or `Off-server store refused: credential file unusable.`, and exits `1`.

### The audit shipper

The `openbao-audit-shipper` service starts with the stack. It runs `gatekeep audit-ship` from the `cli` image, as uid `10006`, and copies what OpenBao appends to its audit file into the bucket within 30 seconds, in whole lines, as `openbao-audit/{yyyy}/{MM}/{dd}/{fileId}-{startOffset}.jsonl`, at most 1 MiB each, so each goes up well inside the 10-second timeout. It reads the `openbao-audit` volume read-only, through the `openbao-audit` group (gid `4501`) that only it and OpenBao have (the directory is setgid, so a file OpenBao makes again keeps that group), keeps its read offset on its own `shipper-state` volume, and resumes there after a restart. It refuses to start, naming `GATEKEEP_AUDIT_SHIP_STATE_DIR`, unless it can write there. The saved state also holds a hash of the file's first 4 KiB: a file that is shorter than the offset, or starts differently, was replaced, so the shipper says so and ships it again from the start under a new file ID. A saved state it can't read is said in one line too, and shipping starts over the same way, which repeats chunks rather than leaving a gap. OpenBao's audit device HMACs every request and response value, so no key material, plaintext or token is shipped. The chunks aren't signed: the shipper holds no OpenBao login, and Object Lock keeps them from erasure. Its log shows each chunk's key, and one line when the bucket fails, which it retries every 5 seconds:

```sh
docker compose -f deploy/compose.yaml logs openbao-audit-shipper
```

## Hostnames and TLS

Caddy is the only way in (AD-2, AD-26). It serves two sites and refuses everything else:

| Site | Setting | Local default | Proxied to |
| --- | --- | --- | --- |
| Every Tenant host, `*.{zone}` | `GATEKEEP_TENANT_ZONE` | `gatekeep.localhost` | `Host.Hosted`, port 8080 |
| The Admin hostname | `GATEKEEP_ADMIN_HOST` | `admin.gatekeep-admin.localhost` | `Host.Admin`, port 8080 |

- **The Tenant zone is used only by Gatekeep** (NFR-21). Here "zone" means a DNS name and everything under it, such as `id.example.com`, not necessarily a zone of its own in Cloudflare. No application, mail server or other host may have a name under it, the zone itself included, because the `*.{zone}` wildcard certificate covers every name there: whoever holds its key can impersonate any of them, and a foreign site there would be a sibling origin of every Tenant (`docs/threat-model.md`, T-17 and T-35). Pick a name of its own rather than a domain that already serves something. Hosts on the parent domain (`example.com` in the examples, which also serves `admin.example.com`) can still set `Domain=example.com` cookies that every Tenant name receives (T-17). Gatekeep's own `__Host-` cookies, the Admin Session's included, can't be overwritten that way, but only put hosts you trust on the parent domain. **Same-site:** when the Admin hostname and the Tenant zone share a registrable domain, as `admin.example.com` and `id.example.com` do, every Tenant page is same-site with the Admin Dashboard, so the `SameSite=Strict` cookie attribute doesn't keep requests a Tenant page starts away from it; Host.Admin's exact-Origin and CSRF checks still refuse them (`docs/threat-model.md`, T-17). To remove the risk, put the Tenant zone under a registrable domain of its own.
- **The Admin hostname must be outside the Tenant zone**: not the zone itself and not any name under it. Caddy refuses to start otherwise, and its log names `GATEKEEP_ADMIN_HOST`. For example, with the zone `id.example.com`, use `admin.example.com`, never `admin.id.example.com`.
- Only one label under the zone is served: `acme.id.example.com`, not `id.example.com` or `a.b.id.example.com`. Any name Caddy doesn't serve fails the TLS handshake. A request whose `Host` header isn't the name its TLS connection was for gets an empty `421`, so one site's connection never reaches the other.
- Plain HTTP on port 80 only redirects the two sites to HTTPS, with no body and no cookie, and closes the connection for any other name.
- Caddy publishes host ports 80 and 443. `GATEKEEP_HTTP_PORT` and `GATEKEEP_HTTPS_PORT` change them on a machine where those are taken, such as a Windows desktop that holds 80; a production host keeps 80 and 443.
- **`Host.Admin` reads the Tenant zone and the HTTPS port too** (Story 1.27). The `admin` service gets `GATEKEEP_TENANT_ZONE` and `GATEKEEP_HTTPS_PORT` as `Gatekeep:TenantZone` and `Gatekeep:TenantHttpsPort`. When a Tenant is created, its issuer, WebAuthn RP ID and email link base are derived from its Tenant Subdomain, the zone and the port once and stored: `https://acme.id.example.com/`, with `:{port}` before the slash when the port isn't 443. Changing either setting later doesn't change an existing Tenant, so pick them before creating any. `Host.Admin` refuses to start, naming the setting, when the zone is malformed or the Admin hostname is the zone or under it.
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

   Then add `-f deploy/compose.cloudflare.yaml` to every command, starting with step 10:

   ```sh
   docker compose -f deploy/compose.yaml -f deploy/compose.cloudflare.yaml up -d --wait
   ```

   Caddy refuses to start in `cloudflare` mode if a setting is missing or the token file is empty, and its log names which. A certificate it can't obtain shows up in its log:

   ```sh
   docker compose -f deploy/compose.yaml -f deploy/compose.cloudflare.yaml logs caddy
   ```

### What Caddy doesn't do yet

- **Its healthcheck proves only that it listens** on 8443, not that it holds valid certificates. A certificate Caddy couldn't obtain or renew shows up only in its log and in clients' errors.
- **`edge` gives Caddy unrestricted egress.** It needs it for ACME and the Cloudflare API in `cloudflare` mode, but nothing limits it to them, so code execution in Caddy can reach the internet (`docs/threat-model.md`, Z-9). The `egress` network that `Host.Worker`, the `cli` and the audit shipper join (Story 1.30) is the same: Gatekeep's code sends only through `EgressHttp`, which refuses private addresses, but the network itself limits no destination, so code execution in those containers can reach any public address.
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

4. **Install** with steps 3 to 12 above, adding the overlay and the env file to every command. Skip step 2: nothing is built, and Compose refuses to start if any image variable is missing rather than build one. For example:

   ```sh
   docker compose -f deploy/compose.yaml -f deploy/compose.release.yaml --env-file deploy/release.env run --rm keygen
   docker compose -f deploy/compose.yaml -f deploy/compose.release.yaml --env-file deploy/release.env up -d --wait
   ```

   On a production host, also add the Cloudflare override, and name `deploy/.env` as well: once any `--env-file` is given, Compose reads only the files named, so the hostnames, the alert channel and the bucket in `deploy/.env` would otherwise be lost. Use this form for step 3 above too:

   ```sh
   docker compose -f deploy/compose.yaml -f deploy/compose.cloudflare.yaml -f deploy/compose.release.yaml --env-file deploy/.env --env-file deploy/release.env up -d --wait
   ```

Caddy keeps its `edge` network and `Host.Worker`, the `cli` and the audit shipper their `egress` network, and `release-verify` alone gets egress besides, on a `registry` network that exists only in the overlay. The pinned key is mounted into `release-verify` alone, read-only. Moving an existing Deployment to a new release is `gatekeep upgrade` (Story 12.6), which isn't built yet.

## Changing a database password

An install made before `gatekeep audit verify` existed has no `gk_cli` password: run step 5's `passwords` again, which writes only the missing one, then recreate the stack.

Change the password file in `postgres/`, then recreate the stack. `postgres-passwords` runs on every `up` and sets every role's password from its file before any host starts, so a changed or restored file can't drift from the database, and the recreated hosts read the new file.

```sh
docker compose -f deploy/compose.yaml up -d --wait --force-recreate
```

## What the stack enforces

- **Secrets only as files.** Each secret reaches only the containers that need it, as a Compose secret under `/run/secrets`. No secret is in an image, an environment variable or `compose.yaml`. Only `keygen` can see `master/`, and during a Master Key rotation `master-key-rotate`; `passwords` sees only `postgres/`, `bootstrap-dir` only `bootstrap/`, and `openbao-setup` only `recovery/` and `approle/`. All of them have no network. The `cli` service mounts `bootstrap/` alone of them, to write the bootstrap token.
- **Refusal of missing or default secrets.** Each host refuses to start if a required setting is missing, empty, a known default such as `changeme` or `postgres`, or a password under 16 characters. That includes its key custody settings: every host uses OpenBao. It logs the setting's name, never its value, and exits non-zero, so Compose shows it restarting. `gatekeep migrate` refuses an unsafe password the same way.
- **Hardened containers.** `Host.Hosted`, `Host.Admin`, `Host.Worker` and `cli` run as their own non-root user, with a read-only root filesystem, every capability dropped and `no-new-privileges`, as do PostgreSQL and OpenBao. Every service has a process limit and rotated logs. No runtime service has the Docker socket.
- **One way in.** Only Caddy publishes ports, 80 and 443. It runs as its own non-root user, read-only, with every capability dropped and no admin API.
- **Egress only where it's needed, and separate networks.** Only two networks reach outside: Caddy's `edge`, and `egress` (Story 1.30), which only `Host.Worker`, the `cli` and the audit shipper join, to reach the alert channel and the bucket. Every request they make goes through `EgressHttp`, which refuses private, loopback and link-local addresses, follows no redirect and uses no proxy. `Host.Hosted` and `Host.Admin` have no egress. Every other network is internal. Each host has its own network and shares only PostgreSQL. Caddy reaches `Host.Hosted` over `hosted-edge` and `Host.Admin` over `admin-edge`, each holding just that host and Caddy, on fixed subnets (`10.201.1.0/24` and `10.201.2.0/24`). Each site closes the connection on a request from the other host's edge subnet, so `Host.Hosted` has no route to `Host.Admin`, directly or through Caddy, and Caddy has none to the worker, PostgreSQL or OpenBao. Those subnets must not clash with other networks on the Docker host. OpenBao is on no network at all.
- **Health.** Each host answers `/healthz` on port 8081 on its own loopback only, never published and unreachable from any other container, Caddy included: `200 healthy`, or `503` with `unhealthy: database` or `unhealthy: custody`, within 3 seconds even when a dependency hangs. Compose uses it as the healthcheck.

## When it doesn't start

- **A host keeps restarting.** Its log names the setting it refused:

  ```sh
  docker compose -f deploy/compose.yaml logs hosted
  ```

- **`Host.Worker` keeps restarting, naming `Alerts:` or `Records:` settings.** The alert channel or the bucket isn't set, or a setting or secret file is unsafe: see "Alert channel and off-server bucket" above.
- **`openbao-audit-shipper` keeps restarting, naming `GATEKEEP_RECORDS_` settings.** The same, for the bucket. If it runs but logs `Off-server store unavailable` or `rejected`, the bucket or its credential is wrong: run `cli records test` to see which.
- **Caddy keeps restarting.** Its log starts with `caddy: refusing to start:` and names the setting, for example an Admin hostname under the Tenant zone:

  ```sh
  docker compose -f deploy/compose.yaml logs caddy
  ```

- **Port 80 or 443 is taken** and Caddy won't start: free it, or on a machine that isn't a Deployment set `GATEKEEP_HTTP_PORT` and `GATEKEEP_HTTPS_PORT` to others.
- **OpenBao won't start** and its log mentions `seal "static"`: the Master Key file is missing from `master/`. Don't run `keygen` again unless this is a new install: a new key can't open data sealed by the old one. Restore the file from escrow.
- **OpenBao won't start** and its log starts `start-openbao: refusing to start:` naming `master_key_id`: `master/master-key-id` is missing, or doesn't hold `gatekeep-master-<N>`. An install from before Story 12.7 has no ID file: its key is generation 1, so write `gatekeep-master-1` there, as below. Compose leaves an empty directory where a missing secret file should be, and the command removes it first. After a rotation, write the generation the key's escrow label names.

  ```sh
  docker compose -f deploy/compose.yaml run --rm --entrypoint sh keygen -c 'if [ -d /secrets/master-key-id ]; then rmdir /secrets/master-key-id; fi && echo gatekeep-master-1 > /secrets/master-key-id && chown 100:1000 /secrets/master-key-id && chmod 0444 /secrets/master-key-id'
  ```

- **OpenBao stays sealed** after a Master Key rotation: follow "If a step fails" in `docs/runbooks/master-key-rotation.md`.
- **OpenBao stays unhealthy** after starting: it hasn't been set up. Run step 6's `openbao-setup`.
- **A setup tool prints a WARNING about ownership or modes**: the secrets directory is on a file system that ignores them, such as a Docker Desktop bind mount from Windows or macOS. Fine for trying Gatekeep out; not for a Deployment.

## Using the Admin Dashboard

The Admin Dashboard is desktop-first (NFR-17):

- **1100px and wider:** the full sidebar.
- **768 to 1099px:** the sidebar becomes an icon rail. Each icon is named by its group, and the rest of the page is unchanged.
- **Below 768px: unsupported.** The layout isn't designed or tested there, and the page shows no notice. Use a wider window.

The light and dark toggle in the top bar is kept per browser, in that browser's own storage. Until it's used, the Dashboard follows the device's colour scheme. The sign-in and setup pages always follow the device.

## Not yet covered

These steps install the stack, not a usable product. What they can't deliver yet, and the work that owns each:

- **A working Admin Dashboard.** Bootstrap, Admin sign-in and the Dashboard's shell work, and so does Your credentials in the avatar menu, where an Admin adds and removes their passkeys and security keys, each change confirmed with a fresh WebAuthn assertion. The Dashboard creates and lists Tenants (Deployment, then Tenants), and deletes them: deleting one needs its Tenant Subdomain typed and a fresh WebAuthn assertion, ends every role in it at once and never frees its subdomain, and its Logs are kept for 90 days. With no Tenants the Deployment Owner lands on the Create Tenant form. The top bar's Tenant switcher lists the Tenants an Admin holds a role in, with each one's environment badge, and a Tenant's page (Settings, then Tenant) holds only its environment, which its Tenant Owner changes; removing Prod needs a fresh WebAuthn assertion. A Tenant's Applications and Users arrive from Story 3.1 on, and its other settings with Story 8.5.
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
- **Alerts from events, and evidence in the bucket.** Only `alerts test` and `recover-admin` send alerts yet: deriving Security Alerts from audit events is Story 11.1, decrypt-rate alerts Story 11.2 and the heartbeat Story 11.3. Only `records test`, `recover-admin` and the audit shipper write to the bucket: sealed events, revocations and chain heads follow in Story 7.2.
- **Audit log rotation.** OpenBao's one audit file grows without bound, and OpenBao refuses every request when it can't write it. Watch the `openbao-audit` volume's size; rotation and a second audit device are deferred.
- **Backups and upgrades.** No backup, restore or `gatekeep upgrade` yet. Backups must leave the secrets directory out (Epic 12). Signed releases can be installed ("Install a signed release" above), but `gatekeep upgrade`, which will check signatures itself, is Story 12.6.
