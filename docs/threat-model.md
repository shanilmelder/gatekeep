# Gatekeep threat model

Status: written 2026-11-02 for Story 1.3, before authentication work starts (NFR-1, AR-3). It's built from AD-2's trust zones and describes the design in `ARCHITECTURE-SPINE.md`, including the Story 1.2 amendment to AD-10.

**Nothing here is proof.** Only the Story 1.1 module boundaries, the Story 1.4 database isolation, the Story 1.5 audit write path and the Story 1.6 log scrubbing and first canary scan exist in code: the eight database roles, the AD-3 grants for `tenant`, `tenant_host`, `tenant_settings`, `migration_history` and the four audit tables, `TenantScope`, `DeploymentScope`, `FailureContext`, `IAuditAppender`, `Secret<T>`, `ScrubbingLoggerProvider`, `CanaryScanner` and `gatekeep migrate`. Every other control below is designed, not built, and none has been tested against an attacker. A control is evidence only once its story's test passes. The security gate (Story 18.9) checks this document against the built product.

Terms follow PRD §3. `AD-n`, `FR-n` and `NFR-n` refer to the architecture spine and the PRD.

## Update rule

**Any work that changes a trust boundary changes this document in the same work.** A story that does this isn't finished, and its review doesn't pass, until the change here is part of the same pull request.

A trust boundary changes when work does any of these:

- adds, moves or removes a zone, a host, or a route surface on a host
- adds a network path, an egress target or an external service
- changes a database role, or a grant in the AD-3 registry
- changes an OpenBao policy, or where any key is held
- adds a credential-equivalent value, or changes how one is stored, delivered or logged
- adds a kind of principal, or changes what machine clients may do
- changes where Tenant identity comes from (AD-4)
- changes token signing, audiences or cookie scope, or weakens CSP
- changes how releases are built or signed, or adds a runtime dependency to a Hosted surface
- closes a gap, or accepts a risk, listed in this document

The reviewer of every story asks whether any of these apply. If one does, the change must:

1. Update the affected tables below, and remove any gap the work closes.
2. Name new threats with the next free `T-n`. Numbers are never reused, so stories can cite them.
3. Flag the affected ASVS chapters for reassessment, which NFR-8 requires when a trust boundary changes.

The rule is enforced by review, not by a tool. `.github/pull_request_template.md` puts the question in every pull request.

## Who we're defending against

| Attacker | Starting position | Treated as realistic? |
| --- | --- | --- |
| Internet attacker | Any request to a Tenant host | Yes. This is the main threat |
| Malicious or compromised User | A valid account in one Tenant | Yes |
| Remote code execution in `Host.Hosted` | Runs code in a host that parses unauthenticated input | Yes. Isolation below the application must hold against it |
| Code execution in `Host.Admin` or `Host.Worker` | Runs code behind the private network, for example through a poisoned stored value | Yes. Less exposed than `Host.Hosted`, and more privileged in places |
| Compromised dependency or build | Code inside a release | Yes |
| Stolen Admin session, Management client or Admin device | Acts as that Admin or client | Yes |
| Email or social provider compromise | Controls a delivery or identity path | Yes |
| Compromise of Caddy or the VPN endpoint | Sits in front of both public and Admin traffic | Yes. Caddy parses internet input and sees plaintext |
| Person with the server, a disk or a backup | Physical or storage access, including tampering with a powered-off server | Yes |
| Root on the host | Full control of the running server | Yes, and it can't be contained. UJ-6 applies |
| Malicious Admin | Valid high-privilege credentials | Lowered by A-1, because Esm operates every Tenant. Not designed against, beyond audit |

## Trust zones

AD-2 defines three zones, one per host. The others below aren't separate AD-2 zones, but the boundaries can't be stated without them.

| ID | Zone | Holds or runs | Exposure |
| --- | --- | --- | --- |
| Z-1 | Public: `Host.Hosted` | OIDC endpoints, Hosted Login, Account Portal. Database role `gk_hosted` | Internet, through Caddy's public site |
| Z-2 | Admin: `Host.Admin` | Admin Dashboard, Management API. Database role `gk_admin` | Private network only, through Caddy's Admin site on the VPN interface |
| Z-3 | Worker: `Host.Worker` | Jobs, sealing, retention, off-server shipping. Roles `gk_dispatch`, `gk_worker`, `gk_sealer`, `gk_retention` | No inbound port except private health |
| Z-4 | Data and custody | PostgreSQL, OpenBao Transit, breach dataset | No public exposure. Reached by the hosts over private paths |
| Z-5 | Host | Linux, Docker, Caddy's keys, `Gatekeep.Cli` as `gk_cli`, `gk_migrator` during upgrades, the root-only key file | Host login only |
| Z-6 | Off-server | Object Lock bucket, immutable backups, alert channel, dead-man's check | Separate provider. The server can write, but not delete or shorten retention |
| Z-7 | Offline | Escrowed Master Key generations, recovery keys, backup repository key, image signing key | Never connected to the server |
| Z-8 | External parties | Browsers, Applications, email and social providers, DNS and certificate authorities | Untrusted input |
| Z-9 | Edge | Caddy's public and Admin sites, the VPN endpoint | Internet and VPN |

### What each zone can do if taken

| Zone taken | Attacker can | Attacker can't, by design |
| --- | --- | --- |
| Z-1 | Forge User tokens for every Tenant while present. Read and write `tenant` data in any Tenant, including adding a Passkey to a User with no audit event. Decrypt `totp` and `social` secrets. Hold token protection keys | Reach `Host.Admin`. Sign with Management keys. Read Admin tables. Change Signing Key or configuration tables. Decrypt `email` secrets or `payload` values. Enqueue anything but notification jobs. Request new signatures after eviction |
| Z-2 | Use `gk_admin` grants across Tenants with no session. Create keys. Sign with Management keys, forging Management API tokens for every Tenant while present. Abuse live Admin sessions | Decrypt anything. Reach the internet directly, since `Host.Admin` has no egress. Fresh-assertion rules are handler code, so they don't bind code execution here |
| Z-3 | Use `gk_worker` data access across Tenants. Decrypt `social`, `email` and `payload` secrets, including queued reset links, which is account takeover. Destroy keys. Delete audit rows through `gk_retention`. Sign off-server records, so forged records can be appended. Reach the alert channel and bucket with write-only rights | Delete or rewrite anything already off the server. Remove Object Lock retention |
| Z-4 database, read | Read ciphertext, hashes and personal data. Crack weak passwords offline from Argon2id hashes (T-44) | Decrypt, because keys are in OpenBao. Use hashed tokens |
| Z-4 database, superuser or `gk_migrator` | Turn off RLS. Add Admin rows and credentials. Alter unsealed audit rows | Rewrite what's already off the server |
| Z-4 OpenBao | Same as Z-5: every key is usable | Rewrite Z-6 |
| Z-5 | Everything. Treat every key and secret as stolen | Rewrite Z-6. Reach Z-7 |
| Z-6 | Read evidence and encrypted backups. Console access to the provider may lift the protections this zone gives | Decrypt backups, or unseal OpenBao, without Z-7 |
| Z-7 | Master Key, recovery keys and backup repository key sit together, so Z-7 plus Z-6 read access yields every key and all data | Nothing further. This is the single place where everything can be lost |
| Z-8 | A compromised email provider can read links and codes in transit. A compromised social provider can assert identities for its Connection | Bypass Factors through email |
| Z-9 | Read passwords, codes and tokens in transit. Rewrite responses, including serving script. Reach `Host.Admin` through the Admin site, because one Caddy serves both | Sign tokens. Reach OpenBao or the database directly |

### What survives eviction

Removing an intruder doesn't end the compromise. These last until replaced:

- Tokens forged while present can carry any expiry, and stay valid until the Signing Key or Management key is revoked.
- Passkeys added with no audit event, until the User's credentials are reset. UJ-3 can't remove them. Only UJ-6 can.
- Decrypted TOTP seeds and social credentials, until re-enrolled or replaced.
- Token protection keys, until replaced: see G-12.

## Trust boundaries

| ID | Boundary | What crosses | Enforced by | Must hold against |
| --- | --- | --- | --- | --- |
| TB-1 | Internet to Z-1 | Unauthenticated HTTP | Caddy forwards zone hostnames only. Exact `tenant_host` match. One fixed 404. Rate limits. CSP and CSRF checks | Forged `Host` header, floods, injection |
| TB-2 | VPN to Z-2 | Admin and Management requests | VPN interface binding. Caddy Admin site. WebAuthn. Capability table | Anyone outside the VPN, stolen sessions |
| TB-3 | Z-1 to Z-2 | No network path. Stored data does cross, through the shared database | Default-deny container networks. Release test from inside the `Host.Hosted` container. CSP and output encoding on the Dashboard | Z-1 code execution, stored injection (T-37) |
| TB-4 | Tenant to Tenant | Nothing, except by a bug | `FORCE` RLS, composite foreign keys, opaque artifact prefix, exact-host cookies, separate keys per Tenant, cross-Tenant suite | Application bugs. **Not** code execution: see T-3 |
| TB-5 | User to Admin | No identity crosses, but User-supplied values are displayed to Admins. Separate identity, tables, cookies and hostname | AD-2, AD-12, AD-31 | A User or User session reaching Admin functions |
| TB-6 | Hosts to database | SQL as a per-host role | Allow-list grants per table and column. Catalogue test. No role owns a table or holds `BYPASSRLS`. Built in Story 1.4 for the tables that exist so far. Database `CONNECT` is limited to the eight roles, and `PUBLIC` holds nothing. Story 1.5 adds the audit tables, with column grants in the registry: `gk_sealer` updates only the seal columns, and `gk_hosted` can append to Tenant audit tables, read neither, and has no access to `deployment_*` tables. The catalogue test also refuses any function `PUBLIC` can execute, that is `SECURITY DEFINER` or that `gk_migrator` doesn't own, and any `pg_default_acl` row. ASVS 5.0 chapters on authorization and configuration need reassessing for these changes under NFR-8 | Z-1 or Z-2 code execution exceeding its grants |
| TB-7 | Hosts to OpenBao | Sign, encrypt, decrypt and wrap requests | One policy per host, per key purpose and class. Private socket. Audit device shipped off the server. Quotas only if confirmed | Bulk decrypt, key export, use of another host's keys |
| TB-8 | Z-1 to Z-3 | Job rows | Job type registry enforced by trigger. Handlers re-check authoritative state and never trust the payload | Z-1 or Z-2 directing the Worker |
| TB-9 | Hosts to Z-5 | Docker and host access | Containers, default-deny networks. **Container hardening is unspecified: see G-4** | Container escape |
| TB-10 | Z-3 and Z-5 to Z-6 | Signed records, encrypted backups, alerts | Write-only credential. Object Lock. Signature check on restore | An intruder erasing evidence. **Not** forged additions from Z-3 or Z-5, which can sign |
| TB-11 | Z-7 to Z-5 | Escrowed keys, restore only | Kept offline by a person | Backup theft reaching keys |
| TB-12 | Gatekeep to Z-8 outbound | Email, social and external calls | One `EgressHttp` handler that blocks private addresses. Code-owned social endpoints. Named infrastructure endpoints | SSRF, exfiltration, downgrade |
| TB-13 | Application to token | Access and ID tokens | Audience checks. Short lifetimes. Management tokens signed only by a separate key | A token valid in one place being accepted in another |
| TB-14 | Build to production | Signed images | CI jobs that run third-party code hold no secrets. Lockfiles. Signature verified by `gatekeep upgrade` | A malicious package |
| TB-15 | Tenant to Tenant in the browser | Cookies under the shared zone | `__Host-` cookies. Tenants can't supply code: themes and templates can't run it | A sibling Tenant origin setting cookies |

## Credential-equivalent values

This covers every NFR-3 class, and the other secrets we could identify that the design relies on. If a value isn't here, adding it is a trust boundary change.

### User and client values

| Value | Stored as | Lifetime | If stolen |
| --- | --- | --- | --- |
| Password | Argon2id, parameters per hash | Until changed | Account takeover, unless a Factor is required |
| Access and ID tokens | Not stored. RS256 JWS, held by Applications | 15 minutes default, 1 hour limit. Can't be revoked | Use until expiry, within audience |
| Authorization code | Reference token, hashed per NFR-3. Mechanism proven by the Story 2.2 spike | 60 seconds, single use | Blocked by PKCE. Replay revokes the family |
| Refresh token | Reference token, lookup stored as SHA-256 | 30 days absolute, 7 days idle by default | Rotation on use. Reuse revokes the Token Family |
| Session identifier | SHA-256 in `user_session` | 3 days idle, 7 days absolute by default | Acts as the User in Hosted Login and the Account Portal |
| Email recovery cancel and enrolment links (Story 6.9) | Storage not stated: see G-7 | Not stated | Takes over a Passkey-only account, or cancels its recovery |
| Sign-in transaction cookie value | Storage form not stated: see G-7 | 30 minutes sliding | Continues a sign-in in progress |
| Reset, verification and email change links | SHA-256 in `one_time_token`. Transit `payload` ciphertext while queued | Reset 30 minutes, others per §5.2 | Password reset or email takeover |
| Credential enrolment links | SHA-256, and revealed once | Per §5.2 | Enrols a credential on the account |
| Email code | HMAC under Tenant `hmac` key | 10 minutes, 5 attempts | One sign-in |
| Recovery Code | HMAC under Tenant `hmac` key. Pending codes are `totp` ciphertext | Single use | Regains access, and may replace the whole sign-in for a Passkey-only User |
| TOTP seed | Transit `totp` ciphertext | Until re-enrolled | Generates second factors. `Host.Hosted` can decrypt it |
| Client secret | SHA-256 of a 256-bit value, revealed once | Until rotated | Acts as the Application |
| Tokens returned by social providers | Handling not stated: see G-7 | Per provider | Acts as the User at that provider |
| CSRF token | Bound to the Session or transaction | That of its binding | Needs the cookie as well |
| WebAuthn private key | Never reaches Gatekeep. Only public keys are stored | Until removed | Needs the authenticator |
| URL query containing any of these | Scrubbed from logs | n/a | As the value it contains |

### Admin values

| Value | Stored as | Lifetime | If stolen |
| --- | --- | --- | --- |
| Admin session identifier | Separate `control` table, `SameSite=Strict` cookie | 30 minutes idle, 8 hours absolute | Acts as the Admin, short of fresh-assertion actions |
| Admin Recovery Code | HMAC under Deployment `hmac` key | Single use, offline | Reaches credential setup only |
| Bootstrap token | Root-only file, SHA-256 in `bootstrap_state` | 15 minutes, single use | Becomes first Admin, if bootstrap isn't complete |
| `recover-admin` and Reset credentials enrolments | SHA-256 in `admin_enrolment` | Recovery 15 minutes, single use. Reset per §5.2 | Enrols an Admin credential. Recovery raises a Security Alert first |
| Admin invite link | `dep-payload` ciphertext in `admin_invite`, erased once sent | 72 hours | Joins as an invited Admin |
| Management API token | Not stored. Signed by the Tenant's Management key | 15 minutes | Management API in that Tenant, never fresh-assertion actions |
| VPN client credential | Admin devices | Until revoked | Network position only, with no Admin rights |

### Keys and infrastructure secrets

| Value | Held | Used by | If stolen |
| --- | --- | --- | --- |
| Master Key (OpenBao static seal key) | Root-only file on a separate LUKS volume, with offline escrow. Never in a container, environment file or backup | OpenBao at startup | Opens every key, given an OpenBao snapshot or storage. No hardware binding, so old copies stay valid until rotation |
| OpenBao recovery keys | Offline, with the escrow | Operator | Administrative recovery of OpenBao |
| OpenBao host login credentials | Undecided: see G-1 | Each host | That host's OpenBao policy |
| Signing Key private half | OpenBao, non-exportable | `Host.Hosted` signs | Forges User tokens for that Tenant |
| Management key private half | OpenBao, non-exportable | `Host.Admin` signs | Forges Management API tokens for that Tenant |
| Token protection key | Wrapped by Transit. In `Host.Hosted` memory for up to 5 minutes | `Host.Hosted` | Reads or creates protected reference token contents for that Tenant |
| Tenant secret class keys, `dep-*` keys | OpenBao, non-exportable | Per AD-10 policies | Decrypts that class |
| Social and email provider credentials | Transit `social` and `email` ciphertext | Hosted, Worker | Acts as the Tenant at that provider |
| Database role passwords | Compose secrets at runtime | Each host | That role's grants |
| `gk_migrator` and PostgreSQL superuser credentials | Not in any running host | Cli, upgrades only | Owns every table, so RLS and grants stop applying |
| OpenBao root token | Storage not stated: see G-1 | Setup only | Every key and policy |
| LUKS passphrase | A person. No unlock key on the host | Boot | Opens the volumes, given the disks |
| TLS private keys | Readable only by Caddy | Caddy | Impersonates every Tenant, since the wildcard is shared |
| Caddy internal CA key | Readable only by Caddy. Trusted on Admin devices | Admin certificate | Impersonates the Admin hostname to those devices |
| DNS credential | Validation records only | Caddy | Certificate issuance under the zone |
| Bucket and backup credentials | Host | Worker, Cli, pgBackRest | Write access only. No delete or retention change |
| VPN server key | Storage not stated: see G-13 | VPN endpoint | Impersonates the private network |
| Backup repository key | Offline escrow | Restore | Reads backups |
| Off-server record signing key | OpenBao, Deployment key | Worker, Cli | Forges off-server records until the key changes |
| Alert channel and dead-man's check URLs | Host | Worker, Cli | False alerts, or a false all-clear from elsewhere |
| Image signing key | Hardware, held by Esm | Release | Signs a malicious release |
| Pinned image verification key | Host | `gatekeep upgrade` | Public, but replacing it lets a malicious release pass |
| CI and image registry credentials | CI | Release | Publishes images. The signature check still refuses them |
| Provider console logins: DNS, bucket, alert, email | Esm | Operator | Can undo DNS, Object Lock or alert guarantees from outside Gatekeep |

## Named threats

Stories cite these by number. Every entry is `designed`: when a story's test proves a control, that story adds the test's name to the row. Story 18.9 checks these rows against the product. "None identified" means none in design review, not that the control has been shown to work.

### Tenant and data

| ID | Threat | Controls | What remains |
| --- | --- | --- | --- |
| T-1 | A missed filter exposes another Tenant's data | AD-3, AD-4, AD-27 and the cross-Tenant suite. An unscoped query raises an error. Tests: `CatalogueTests.Migrated_database_matches_the_registry`, `TenantBehaviourTests.Scoped_role_sees_its_own_row_and_no_other_Tenants`, `TenantBehaviourTests.Scoped_write_to_another_Tenant_is_refused`, `TenantBehaviourTests.Unscoped_query_on_a_fresh_connection_raises_an_error`, `TenantBehaviourTests.Unscoped_query_on_a_reused_connection_raises_an_error` | One bug in a shared policy still reaches every Tenant. The failing cast fires only when the policy expression is evaluated, so an unscoped query that evaluates it for no row returns nothing rather than raising (`TenantBehaviourTests.Known_limit_an_unscoped_query_the_planner_proves_empty_returns_nothing`). PostgreSQL 18.6 also raises while planning a plain query on an empty table, but that's engine behaviour, not a guarantee. `TenantScope` being the only path is the control there. The cross-Tenant suite (Story 1.31) isn't built |
| T-2 | A forged `Host` header picks a Tenant or poisons an email link | AD-6. Issuer, RP ID and link base come from the stored Tenant | None identified |
| T-3 | Code execution sets `gatekeep.tenant_id` to any Tenant | Grants limit which tables it reaches. Tests: `TenantBehaviourTests.Grants_limit_a_role_that_sets_any_Tenant`, `CatalogueTests.Catalogue_names_each_drift_made_by_the_migrator` | **RLS stops bugs, not code execution.** Each runtime role sets the Tenant itself |
| T-4 | An artifact from one Tenant is accepted in another | AD-9 prefix check, negative token pack | Rejected events can be flooded, so AD-9 caps them per source |

### Authentication and tokens

| ID | Threat | Controls | What remains |
| --- | --- | --- | --- |
| T-5 | A user skips a sign-in step | AD-12. The server-side transaction is the only source of what comes next. FR-25 matrix | See G-5 |
| T-6 | Identifier enumeration | AD-24 dummy hash, NFR-20 | Queue load could affect timing, so it needs measuring |
| T-7 | Credential stuffing | FR-28, FR-29, NFR-6 | Accepted until v2: see Risks |
| T-8 | Argon2 work exhausts memory and takes down every Tenant | AD-14 semaphore, per-Tenant floors, HMAC for Recovery Codes | A flood inside one Tenant's share still slows that Tenant |
| T-9 | Refresh token theft or code replay | AD-13 rotation with no leeway. Reuse revokes the family | Concurrent redemption: see G-6 |
| T-10 | A User token is accepted by the Management API | AD-33 separate keys, issuer and endpoint. Hosted's policy can't use the key | None identified |
| T-11 | Phished or relayed WebAuthn assertion, or one accepted across siblings | AD-24 exact RP ID and origin per request, user verification | Per-request support in `Fido2.AspNet` is unconfirmed: see G-8 |
| T-12 | Revoked access outlives revocation | AD-13's one revocation path, FR-48 walk | Access tokens can't be revoked: see Risks |
| T-13 | Phishing of passwords and email codes | Passkeys are offered. Dedicated zone | Passwords and codes are not phishing-resistant |
| T-14 | Email takeover diverts reset | Email can't bypass Factors. Security Alert on provider change | A User with no Factor relies on the mailbox |

### Web surface

| ID | Threat | Controls | What remains |
| --- | --- | --- | --- |
| T-15 | Script injection on a Hosted Login origin captures passwords | AD-21 CSP, no third-party origins, typed themes, logos rasterized | Hosted surfaces still ship React and one reviewed QR encoder, so a compromise there serves script from `self`: see T-24 |
| T-16 | CSRF on a state change | AD-12, NFR-4. Token plus exact Origin | None identified |
| T-17 | A sibling Tenant origin sets parent-domain cookies | `__Host-` prefix stops fixation. Tenants can't supply code | Oversized cookies could block a browser. The Public Suffix List isn't used in v1 |
| T-18 | A template or preview runs code | Fixed variable substitution, no template engine, text-only previews | None identified |

### Admin and host

| ID | Threat | Controls | What remains |
| --- | --- | --- | --- |
| T-19 | A public flaw reaches Admin functions | AD-2, AD-33, no route from Hosted to Admin, grants | Depends on TB-3 and TB-9 holding, and on T-37 |
| T-20 | First-comer claims bootstrap | AD-31. Server-only token, single use, 15 minutes | Root on the host can read the token |
| T-21 | Recovery is abused silently | AD-31. Alert and off-server record are confirmed before the enrolment is issued | Root can run recovery, but can't hide it |
| T-22 | A stolen Admin session takes destructive action | 5-minute fresh assertion, machine-denied | Assertion isn't yet bound to the action: see G-5 |
| T-23 | Machine client escalates | AD-20. Every fresh-assertion capability is machine-denied | A stolen client acts within its grants until rotated |
| T-24 | A malicious package ships in a release | AD-25. Lockfiles, install scripts off, separate build and sign jobs, hardware key, signature check | A malicious package inside the lockfile and passing review still ships. Nothing here detects it at runtime |
| T-25 | SSRF through a Tenant-supplied provider address | AD-26 `EgressHttp`, code-owned social endpoints | Test results must not reveal network detail |
| T-26 | `Host.Hosted` directs `Host.Worker` | AD-15 registry, trigger, re-checks | Limited to notification jobs, which can still send mail |

### Server, keys and evidence

| ID | Threat | Controls | What remains |
| --- | --- | --- | --- |
| T-27 | Code execution in `Host.Hosted` forges tokens | Signing stays in OpenBao, so new signatures stop at eviction. The audit device records sign requests off the server | **Forgery for every Tenant while present, and forged tokens work after eviction until the key is revoked.** Forged tokens leave no row, and nothing alerts on signing: see G-11. Inherent to any process that can request signatures. UJ-6 applies |
| T-28 | Bulk decrypt of TOTP seeds and social credentials | Per-class keys, audit device off the server, decrypt-rate alerts. Quotas only if confirmed | Possible while present. Detection is after the fact |
| T-29 | Live root or Docker access | None. UJ-6 treats this as full compromise | Every private key is reachable through OpenBao's memory or the key file, and old copies stay valid until rotation |
| T-30 | Stolen disk, server or backup | AD-10, AD-18. Key file apart from backups, LUKS on OpenBao, PostgreSQL and key volumes | **Weaker control.** LUKS protects a powered-off server. Not protected: a server taken running, or a copied key file. Not hardware-bound. With no measured boot, tampering with the unencrypted boot chain could capture the passphrase: see G-14 |
| T-31 | Intruder rewrites or erases evidence | AD-16 chains, AD-17 Object Lock, `audit verify` walks every head. Built in Story 1.5: triggers and grants stop update, delete and truncate, including by `gk_migrator`, and the event commits or rolls back with its state change. Sealing, chains, shipping and `audit verify` aren't built (Epic 7). Tests: `AuditTests.Update_of_audit_event_is_refused`, `AuditTests.Delete_of_audit_event_is_refused`, `AuditTests.Owner_cant_truncate`, `AuditTests.Sealer_cant_change_the_envelope`, `AuditTests.Sealer_seals_once_and_cant_reseal`, `AuditTests.Tenant_command_rollback_leaves_nothing`, `FailureContextTests.Refused_request_loses_its_state_and_keeps_the_effect_and_its_event` | Events after the last shipped head can be lost. Unsealed rows have no chain protection, and until Epic 7 no row is sealed. `gk_migrator` or a superuser can drop or disable the triggers, which the catalogue test reports but doesn't prevent. Every role with `INSERT` can insert a false event for any Tenant it sets. Nothing yet fails a state change that skips the appender, and the first real commands arrive from Story 1.21. A rollback that can't be confirmed, such as on a lost connection, drops the `FailureContext` effect. Z-3 or Z-5 can append signed false records |
| T-32 | Intruder silences alerts | Heartbeat carries sealed and shipped positions to an external check | Stopped evidence is detected, not prevented |
| T-33 | Restore undoes revocations | AD-17 replay, AD-18 ends all access and rotates Signing Keys | Changes after the last shipped record are unknown, so restore assumes the worst. A signed false record from the compromise period passes the check, so the Operator must bound that period |
| T-34 | Intruder destroys backups | AD-18. Server can't delete inside retention | Method is chosen in the backup story. Backups may hold intruder changes if detection is slow |
| T-35 | Certificate or wildcard key theft | Key readable only by Caddy, validation-only DNS credential, CAA, CT monitoring | One wildcard key serves every Tenant |
| T-36 | Conformance mode weakens production | AD-25. One named Dev Tenant, evaluated per request, refuses Prod | None identified |

### Protocol, leakage and abuse

| ID | Threat | Controls | What remains |
| --- | --- | --- | --- |
| T-37 | Public input stored by Z-1, such as a name or user agent, runs in the Admin Dashboard | AD-21 CSP, and React encodes output | Depends on no raw HTML rendering, which needs a test |
| T-38 | Redirect abuse through `redirect_uri` or logout redirects | FR-11 exact matching | Relabelling a Tenant changes what's allowed, so it needs a fresh assertion |
| T-39 | Authorization code injection or mix-up | PKCE, Tenant-prefixed artifacts, per-Tenant issuer | Applications must validate `iss` and `state` themselves |
| T-40 | JWT algorithm or key confusion | AD-9 fixed RS256, `at+jwt`, negative token pack, AD-33 key separation | Applications validate tokens with their own libraries |
| T-41 | Social sign-in abuse: forged `state` or `nonce`, a hostile provider, or takeover through an email conflict | Code-owned endpoints, `external_identity` keyed on issuer and subject, FR-20 conflict rule | Per-provider rules arrive with Epic 14. A compromised provider can assert its own Users |
| T-42 | Credential-equivalent values leak through logs, errors, exports or `Referer` | AD-24 scrubbing sink, `Secret<T>`, canary scan. Built in Story 1.5: `Secret<T>`, and an envelope that can't hold one, whose only string is a type code checked for shape and length. No event catalogue exists yet, so nothing checks that a code is a known one. Built in Story 1.6: `AddGatekeepLogging` clears every default provider, so the scrubbing provider is the only one in all three hosts, wrapping JSON console, the only sink. The message, exception text and values of sensitive names are scrubbed before the sink sees them, scopes aren't forwarded, and a record that can't be scrubbed becomes one fixed line. W3C trace and span IDs pass as named state. The CI canary scan reads what the console provider hands its formatter from test-sent records, not a host's stdout, and all four audit tables, and names the source without printing the value. A canary per flow and the release gate aren't built (Story 7.8). ASVS 5.0 chapters on logging and error handling need reassessing for this change under NFR-8. Tests: `SecretTests.ToString_shows_no_value`, `SecretTests.Serializing_a_secret_is_refused`, `SecretTests.Secret_has_no_public_property_or_field`, `PersistenceRuleTests.Audit_envelope_holds_only_a_code_and_internal_references`, `ScrubbingTests.Secret_argument_prints_only_the_mask`, `ScrubbingTests.Sensitive_name_loses_its_value_and_the_message_stays`, `ScrubbingTests.Shape_in_a_message_is_scrubbed`, `ScrubbingTests.Exception_keeps_its_type_and_loses_the_value`, `ScrubbingTests.Scope_never_reaches_the_sink`, `ScrubbingTests.Argument_that_throws_writes_the_fixed_line`, `HostLoggingTests.Scrubbing_provider_is_the_only_one`, `CanaryScanTests.Canaries_sent_as_designed_are_found_nowhere`, `CanaryScanTests.Canary_written_straight_to_the_output_fails_and_names_the_source`, `CanaryScanTests.Canary_planted_in_detail_fails_and_names_the_table_and_column_kind`, `LoggingRuleTests.Host_adds_scrubbing_before_it_builds`, `LoggingRuleTests.Only_the_adapter_adds_a_logging_provider` | **The scrubber catches shapes and named values only.** A value held as a plain string, with an innocent name and no known shape, passes. So does a sensitive value printed with a format string that changes its text, a number or boolean under a sensitive name, and a `Bearer` or `Basic` credential under 16 characters outside a named header. Encoded values other than the listed forms pass. `Cli` writes to the console directly and has no scrubbing. An unhandled host exception reaches stderr through the runtime, unscrubbed. `audit_detail.user_agent` and `email`, and their Deployment twins, store request text with no scrubbing. Errors, exports and `Referer` aren't covered. A path the canary doesn't reach isn't caught, and the scan finds only the raw text of a value, not an encoded form. `Secret<T>` is only a type: a value that code holds as a plain string has no protection, and a value passed to `Use` can be copied out |
| T-43 | Abuse of unauthenticated writes: email bombing through reset or code flows, or storage growth in `signin_transaction` and audit rows | NFR-6 rate limits, AD-9 capped events, purge jobs | Distributed sources get past per-source limits until v2 bot defences |
| T-44 | Offline cracking of Argon2id hashes from a stolen database | NFR-2 memory-hard hashing, breach list refusal | Weak passwords can still fall. No pepper is designed |

## PRD §9 risks

| Risk | Threats | Position |
| --- | --- | --- |
| Tenant isolation flaw | T-1, T-3, T-4 | Mitigated against bugs. Not against code execution |
| Server compromise | T-27, T-28, T-29, T-30 | Mitigated before root. Weaker since Story 1.2. Root means UJ-6 |
| On-premises server failure | None: this is failure, not an attacker. T-33 and T-34 cover restore | **Accepted:** no redundancy, and outages can last hours. Off-server backups and SM-5 rehearsals limit data loss. Story 1.2 made this worse: every reboot now waits for a person to enter the LUKS passphrase, counting against NFR-10 |
| No independent security review | All | **Accepted** by Esm, against advice. This document was also written without independent review |
| Scope grows towards the full design | None | Not a security threat. §6 and §7 hold the line, and a v2 feature that changes a boundary triggers the update rule |
| Generated code the Operator doesn't understand | All | Esm reviews every authentication story (SM-7). No control here replaces that |
| Email provider failure or compromise | T-14 | Passkeys are an independent path, and FR-6 shows provider status. Security Alert on provider change. During an outage, verification, reset and code sign-in stop |
| Credential stuffing without bot defences | T-7 | **Accepted until v2.** Revisit if a failed sign-in spike recurs |
| Application keeps a session after revocation | T-12 | **Accepted until v2** Back-Channel Logout. Short token lifetimes limit it |

## Accepted weaker controls

- **Key custody.** Esm accepted file permissions as the static seal's only root of trust. The custody spike didn't run, and all seven proofs are `not-run`, which is no evidence either way (`docs/spikes/1-2-key-custody.md`). Don't describe custody as hardware-bound or TPM-sealed.
- **One server.** OpenBao shares a host with everything it protects. Compromise of the host has no further line of defence.
- **Self-assessment.** NFR-8 is run by the person who built the product.

The residual risks in T-3, T-13, T-24 and T-27 are stated here but **not yet accepted by Esm**: see G-15.

## Gaps to close

Each gap is real in the current design and has no criterion that closes it. Authentication stories must not assume an answer. The first story that touches a gap decides it, and removes it here.

| ID | Gap | First needed by |
| --- | --- | --- |
| G-1 | The OpenBao host login method, and how the root token is handled, are undecided | Story 1.7 |
| G-2 | How the root-only key file reaches the non-root OpenBao service is undecided: owner, mode, key generation, mount order and behaviour when the volume is missing at boot | Story 1.7 |
| G-3 | Seal rotation, restore and `gatekeep rekey` haven't been rechecked against the key file, including destroying old copies. Five custody proofs still need a Linux host, and the TPM spike has no story | Stories 1.7, 1.10, 12.2, 12.7, 13.4 |
| G-4 | Nothing requires keeping the Docker socket out of containers, or running them non-root with a read-only filesystem and dropped capabilities. A socket in a container is equal to root, so T-19 and TB-9 depend on this | Story 1.10 |
| G-5 | A fresh assertion isn't bound to its action and target Tenant, and a sign-in transaction slides with no absolute limit, so a passed password step need never go stale | Stories 1.26, 4.2 |
| G-6 | Single-use redemption isn't required to be atomic. Two concurrent redemptions could both pass a read-then-write check and skip reuse detection | Stories 2.9, 2.10 |
| G-7 | Storage isn't stated for the `__Host-gk_txn` value, email recovery links or tokens returned by social providers | Stories 4.2, 6.9, 14.2 |
| G-8 | Per-request RP ID and origin in `Fido2.AspNet`, the rule tying `userHandle` to the Tenant, and rejection of `crossOrigin` aren't confirmed | Story 1.22 |
| G-9 | AD-26 and Story 1.10 name LUKS on the OpenBao and PostgreSQL volumes only, while AD-10 also needs it on the key volume. The boot passphrase step isn't in the install docs or alerts | Stories 1.10, 1.12 |
| G-10 | Linux on the production host is unconfirmed, and has no fallback | Stories 1.7, 1.10 |
| G-11 | Nothing alerts on Transit sign counts. AD-10's alerts cover decrypts, so T-27 forgery is recorded but not detected | Story 1.7 |
| G-12 | AD-18's `gatekeep rekey` list doesn't name token protection keys | Story 13.4 |
| G-13 | The VPN endpoint isn't designed: where it runs, its key, and how it relates to Caddy's Admin site | Story 1.11 |
| G-14 | Physical gaps in custody: nothing requires the key volume to be a separate physical disk, the boot chain is unmeasured, and how the passphrase is entered on the server (console, remote KVM or initramfs SSH) is undecided. Remote entry would be a new boundary | Stories 1.10, 1.12 |
| G-15 | The residual risks in T-3, T-13, T-24 and T-27 need Esm's explicit acceptance | Story 18.9 |
