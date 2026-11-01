---
title: Gatekeep Architecture Spine Security Review
reviewed: _bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md
prior_review: _bmad-output/planning-artifacts/prds/prd-gatekeep-2026-11-01/review-security.md
reviewer_role: Identity-platform security engineer
created: 2026-11-02
---

# Gatekeep Architecture Spine Security Review

## Verdict

**Not ready for epics and stories. Changes required to the spine first.**

The structure is sound: three hosts, row-level security, Transit custody, and a server-held sign-in state machine are the right shape, and most PRD review remedies survived. The weakness is that the spine treats some boundaries as stronger than they are after code execution in `Host.Hosted`:

- AD-2 says an internet-facing flaw can't reach Admin functions, but `Host.Hosted` holds a signing oracle for the keys that the Management API trusts (ASEC-01).
- AD-2 lists a few tables `Host.Hosted` can't write. It doesn't list the Admin tables, and it lets `Host.Hosted` queue work for a more privileged host (ASEC-02, ASEC-03).
- Three recovery controls fail in the incident they exist for: restore replay, audit verification, and backups (ASEC-05, ASEC-06, ASEC-09).
- FR-2 and FR-5 have no design, although they are the root of Admin trust (ASEC-07).

| Severity | Count |
| --- | --- |
| Critical | 1 |
| High | 10 |
| Medium | 11 |
| Low | 5 |
| **Total** | **27** |

**Severity scale**

- **Critical:** a direct route to takeover, or a compromise that can't be contained.
- **High:** a realistic incident across many Users, an Admin or a Tenant boundary.
- **Medium:** needs a precondition or has limited reach, or weakens a control.
- **Low:** low direct incident risk, or a story-level rule that should be stated.

**Calibration.** A-1 (Esm operates every Tenant) lowers malicious-Tenant-Admin risk. That is why theme, template and SSRF findings needing an Owner or Editor are Medium. A-1 doesn't lower the risk from an RCE, a compromised dependency or a stolen Admin session. RCE in `Host.Hosted` is treated as realistic, because it parses unauthenticated input and has a third-party dependency tree.

**Inherent residual.** While an attacker has code execution in `Host.Hosted`, they can forge User tokens for every Tenant. Any process that can request signatures has this problem, and Transit's benefit is that signing stops after eviction. The findings below don't ask to remove that residual. They ask to stop it reaching Admin functions, to detect it, and to state it plainly in the threat model.

## Fix before stories

| Order | Finding | Spine change |
| --- | --- | --- |
| 1 | ASEC-01 | Management API tokens use a separate key that `Host.Hosted` can't sign with, and are issued from `Host.Admin` |
| 2 | ASEC-02 | Replace AD-2's denylist with an exact per-role grant matrix, tested in CI |
| 3 | ASEC-03 | Limit job types by inserting role, re-check state in destructive handlers, add sealer and retention roles |
| 4 | ASEC-05, ASEC-06, ASEC-09 | Define incident restore, full-history verification and immutable backups |
| 5 | ASEC-07 | Add an AD for bootstrap and recovery |

## Summary of findings

| ID | Severity | Area | Finding |
| --- | --- | --- | --- |
| ASEC-01 | Critical | AD-2, AD-10, AD-19 | `Host.Hosted` can sign Management API tokens for every Tenant |
| ASEC-02 | High | AD-2, AD-3, AD-4 | `gk_hosted` grants are a short denylist that omits Admin credentials |
| ASEC-03 | High | AD-3, AD-4, AD-15, AD-16 | Job rows let `Host.Hosted` direct `Host.Worker`, and sealer and retention roles don't exist |
| ASEC-04 | High | AD-10 | One Transit key per Tenant and no quota or audit device make bulk decryption silent |
| ASEC-05 | High | AD-17, AD-18 | Restore can't tell that the off-server record is behind, and "revocations" is undefined |
| ASEC-06 | High | AD-16, AD-17 | Tail truncation, forged checkpoints and head-only verification defeat tamper evidence |
| ASEC-07 | High | AD-26, Structural Seed | FR-2 and FR-5 have no design |
| ASEC-08 | High | AD-10 | The TPM seal doesn't protect against root or, by default, a stolen server |
| ASEC-09 | High | AD-18 | Backups have no immutability, so an intruder can destroy the UJ-6 path |
| ASEC-10 | High | AD-23, AD-25, AD-26 | Build and release controls wouldn't stop a malicious package reaching Hosted Login |
| ASEC-11 | High | AD-14, AD-24 | The Argon2 budget covers passwords only, and Recovery Codes multiply the cost |
| ASEC-12 | Medium | AD-11, AD-14 | JWKS costs an unauthenticated database transaction, and AD-11 conflicts with AD-14 |
| ASEC-13 | Medium | AD-8, AD-9, AD-10 | Transit is an unbudgeted chokepoint, and OpenIddict's internal credentials are undesigned |
| ASEC-14 | Medium | AD-17 | The dead-man's check proves a process is alive, not that evidence is flowing |
| ASEC-15 | Medium | AD-9, SM-2 | Anyone can write rejected cross-Tenant events, which corrupts the SM-2 signal |
| ASEC-16 | Medium | AD-6, AD-7 | WebAuthn verification rules are unstated, including the Admin RP ID |
| ASEC-17 | Medium | Conventions, AD-26 | No egress control, SSRF rule or owner for social provider endpoints |
| ASEC-18 | Medium | AD-25 | Conformance mode is checked once at startup and doesn't name its Tenant |
| ASEC-19 | Medium | AD-21 | CSP omits non-fallback directives, and logos have no design |
| ASEC-20 | Medium | AD-19 | `[FreshAssertion]` doesn't cover new Applications, and Roles can carry Management Permissions |
| ASEC-21 | Medium | Notifications | The email template engine is unchosen, and previews can run in the Admin origin |
| ASEC-22 | Medium | AD-13 | Deployment-wide compromise response has no resume or completion record |
| ASEC-23 | Low | AD-13, AD-24 | Single-use redemption isn't required to be atomic |
| ASEC-24 | Low | AD-12 | Sign-in transactions slide with no absolute limit |
| ASEC-25 | Low | AD-26 | Admin TLS, HSTS, CAA and Certificate Transparency have no owner |
| ASEC-26 | Low | AD-12, Conventions | UUIDv7 reveals creation time, and cookie flooding works across siblings |
| ASEC-27 | Low | AD-15 | Dead jobs keep ciphertext and can flood Security Alerts |

## Critical

### ASEC-01: `Host.Hosted` can sign Management API tokens for every Tenant

- **Citation:** AD-2, AD-10, AD-19 last bullet, AD-26; FR-42, A-13
- **Attack:**
  1. An attacker gets code execution in `Host.Hosted`.
  2. AD-19 says Management API tokens come from each Tenant's own token endpoint, so they use that Tenant's Signing Key. AD-10 lets `Host.Hosted` sign with it.
  3. The attacker calls Transit directly and creates an `at+jwt` for the built-in Management API, with every Permission, for any Tenant.
  4. They send it to `Host.Admin`, which accepts it as a valid signature from that Tenant's JWKS.

  AD-26 only limits *public* traffic and binds `Host.Admin` to the VPN interface. Nothing stops one container reaching another on the same host, so network position doesn't reliably stop step 4.

  With no key theft and no database access, the attacker gets the non-`[FreshAssertion]` Management surface in every Tenant. That includes creating Applications (ASEC-20), resetting a User's Factors, and editing templates. It directly contradicts AD-2's "Prevents" line: an internet-facing flaw reaching Admin functions.

  The same bullet also puts a Management credential exchange on the public internet, which weakens A-13. A stolen client secret works from anywhere, and only API calls need the VPN.
- **Proposed change:**
  - Each Tenant gets a separate Management Transit key, which isn't in `Host.Hosted`'s OpenBao policy and isn't in the public JWKS.
  - `Host.Admin` issues Management API tokens from a private token endpoint and validates against that key alone. Change AD-19's last bullet and AD-2 to match.
  - `Host.Admin` rejects any Management API token signed by a Signing Key.
  - Add a default-deny network rule to AD-26. `Host.Hosted` has no route to `Host.Admin`, `Host.Worker`, or their health ports. Each service gets its own Compose network, and host firewall rules cover container-to-host traffic.
  - Add a release test: from inside the `Host.Hosted` container, a forged Management token and a connection to `Host.Admin` both fail.

## High

### ASEC-02: `gk_hosted` grants are a short denylist that omits Admin credentials

- **Citation:** AD-2, AD-3, AD-4, AD-12; Conventions (Migrations)
- **Attack:** AD-2 denies `Host.Hosted` writes on five table groups only. AD-4 places Admins, their credentials, sessions and Tenant Roles in `control` tables, which have no row policy, so grants are their only protection. The spine sets no grants for them.

  If `gk_hosted` gets a broad default grant, an SQL injection or RCE can add a WebAuthn credential to a Deployment Owner, insert an Admin session, or edit `tenant_host` or bootstrap state. That is Admin takeover from the public host. This is rated High rather than Critical because the grant is undecided, not given.

  Row-level security doesn't help here. Each runtime role sets `gatekeep.tenant_id` itself, so RLS stops bugs, not code execution. The threat model should say so.

  Even with correct grants, `gk_hosted` must write User credentials. An attacker can add a Passkey to any User without an audit event. That is expected, but it means UJ-3 can't evict a host-level intruder, only UJ-6 can.
- **Proposed change:**
  - Replace the AD-2 sentence with an exact matrix of role, table and privilege, default deny.
  - `gk_hosted` has no privilege on Admin, Admin credential, Admin session or Tenant Role tables, and read-only access to `tenant_host`.
  - The AD-3 catalogue test asserts the whole matrix, so a new grant fails CI unless the matrix changes.

### ASEC-03: Job rows let `Host.Hosted` direct `Host.Worker`, and sealer and retention roles don't exist

- **Citation:** AD-3, AD-4, AD-5, AD-11, AD-15, AD-16
- **Attack:** Sign-up and reset commands run in `Host.Hosted`, and AD-15 inserts their jobs in the same transaction, so `gk_hosted` needs `INSERT` on `job`. Nothing restricts which job types it can insert. AD-4 also makes the job row an accepted source of the Tenant.

  An SQL injection, not just RCE, can insert a row that `Host.Worker` runs with stronger rights:
  - A Transit destruction job (AD-11) for live Signing Keys or a Tenant's secrets key. Destroying the secrets key loses that Tenant's TOTP seeds and Connection credentials unless a snapshot is restored.
  - A retention or Tenant purge job, deleting audit ranges and Tenant data.
  - An email job with attacker-chosen content.

  The check constraint requires a `tenant_id` or the `deployment_wide` flag, but it doesn't tie the flag to the type registry.

  Three related gaps:
  - **Missing roles.** AD-16 relies on a sealer role and on deletion by the retention job only, but AD-3 lists just four runtime roles. As written, these rights land on `gk_worker`, so every job body can alter seal columns and delete audit rows.
  - **Cross-Tenant payloads.** `job` is a `control` table with no RLS. `gk_worker` must read payloads, so a body in Tenant A's scope can read Tenant B's payloads, which breaks AD-4.
  - **Weak `gk_dispatch` separation.** `gk_dispatch` and `gk_worker` credentials sit in one process, so the split guards against bugs but not against compromise of `Host.Worker`.
- **Proposed change:**
  - Add a `job_type` table recording allowed inserting roles, scope and whether the type is destructive, and enforce it with a trigger or per-role `WITH CHECK` policy. `gk_hosted` may insert only named notification types, and never `deployment_wide`.
  - Destructive handlers re-read authoritative state and refuse otherwise: a key must be `retired` or `revoked`, a Tenant must be deleted, and a range must be past retention.
  - Move payloads to a `job_payload` `tenant` table under RLS, keyed by `(tenant_id, job_id)`. `job` keeps dispatch columns only.
  - Add `gk_sealer` and `gk_retention` to AD-3, used only by those job types.
  - Add a test: `gk_hosted` can't insert each destructive or Deployment-wide type.

### ASEC-04: One Transit key per Tenant and no quota or audit device make bulk decryption silent

- **Citation:** AD-10, AD-15, AD-24; NFR-9, UJ-6
- **Attack:** AD-10 uses one Transit key per Tenant for all secrets, with the Tenant ID as the only context. OpenBao policy works by key path, so it can't let `Host.Hosted` decrypt TOTP seeds without also allowing email provider credentials and job payloads containing email links. `Host.Hosted` sends no email, so it has no need for those.

  After RCE, the attacker reads ciphertext for every Tenant by setting `gatekeep.tenant_id`, then decrypts it in bulk. "Decrypted only at the moment of use" is a coding rule, and an attacker doesn't follow it.

  The spine has no OpenBao audit device, request quota or anomaly check. Forged JWTs leave no row in the token table, and direct Transit calls write no `audit_event`. So the highest-value abuse leaves no evidence that the off-server record can see.
- **Proposed change:**
  - Use separate per-Tenant Transit keys by purpose: Hosted (TOTP seeds, social credentials), and Worker (email credentials, job payloads). Bind the purpose in the context too.
  - Give `Host.Hosted` access to the Hosted key only, on specific operations.
  - Enable an OpenBao audit device, and ship its output off the server with the AD-17 record.
  - Set rate limits per host identity, sized near expected peak. Confirm that OpenBao 2.6.4 provides quotas. If it doesn't, enforce the limit by proxy.
  - Add a Security Alert when Transit sign or decrypt counts exceed what the application recorded.
  - Specify OpenBao authentication: one short-lived identity per host, delivered through a Compose secret mounted only into that service.

### ASEC-05: Restore can't tell that the off-server record is behind, and "revocations" is undefined

- **Citation:** AD-17, AD-18; FR-4, UJ-3, UJ-6; SEC-06
- **Attack:** Esm revokes a Signing Key and removes an Admin during an incident. The events are committed but not yet shipped, because shipping is asynchronous and depends on `Host.Worker`. The intruder stops `Host.Worker`, or the server dies. Restore then replays an incomplete record and has no way of knowing it. The revoked key comes back as `current`, and the Operator sees a clean result.

  AD-18 reports the lost-change window relative to the backup, not the window between the last shipped event and the failure. AD-17's "within 60 seconds of sealing" has no bound on how long sealing takes (ASEC-06).

  Other gaps:
  - **Scope.** FR-4 covers a key, Admin or credential. AD-17 doesn't define what counts as a revocation. Unless named, these return after restore: a blocked User, a removed Admin, an old password an attacker knows, an attacker-enrolled Factor, spent Recovery Codes, a rotated client secret, and a revoked Management client.
  - **Admin sessions.** They are in a separate `control` table, and AD-18 names only Sessions and refresh tokens.
  - **Retention.** The off-server record is kept for §5.2's 90 days. A UJ-6 restore from an older backup has a silent replay gap. Backup retention isn't stated at all.
  - **Trust.** The server's credential can write to the bucket, so an intruder can add false records. Restore treats them as authentic, and Object Lock stops their removal.
  - **`--planned-rollback`.** AD-18 doesn't say that it leaves replay on.
  - **Exposure during restore.** Nothing keeps Tenant traffic closed until replay finishes.
  - **Chain continuity.** After restore, the local chain is behind its off-server head, and that looks exactly like truncation (ASEC-06).
- **Proposed change:**
  - Make replay assume the record may be behind. Unless `--planned-rollback` is given, restore revokes **every** Signing Key across all Tenants and promotes new keys, and it ends all Admin sessions as well as Sessions and refresh tokens.
  - List re-applied event types in one code-owned table, covering every case above. For a password change, re-application marks the password as needing reset.
  - Report the last shipped `seq` per chain, and require the Operator to acknowledge that later events can't be known.
  - Show pending-shipment state for key revocation, Admin removal and FR-50 actions until the bucket write is confirmed. Alert if a revocation stays unshipped for 5 minutes.
  - Sign off-server records with a key `Host.Worker` holds for that purpose alone, verify on restore, and quarantine bad records. This limits forgery to the period of compromise, which the Operator bounds at restore.
  - `--planned-rollback` skips only the invalidation step, never replay.
  - Keep a `restore_in_progress` state in `control` that blocks Tenant traffic, as bootstrap does.
  - Refuse, or require explicit acknowledgement, if a backup is older than the off-server retention.
  - Write a restore epoch event linking the restored head to the last off-server head.
  - Extend the SM-5 rehearsal to kill `Host.Worker` immediately after a revocation.

### ASEC-06: Tail truncation, forged checkpoints and head-only verification defeat tamper evidence

- **Citation:** AD-16, AD-17; FR-40, V-7; SEC-20
- **Attack:** These assume an intruder has host-level or migrator access, so triggers no longer bind them.
  - **Unsealed window.** Rows have no chain protection until sealed. Time to seal has no limit, and a flood of events (ASEC-15) or a stopped `Host.Worker` extends it. The intruder deletes unsealed rows and sealed rows after the last shipped head. An off-server head that's behind the local head looks like normal lag, so `audit verify` passes.
  - **Unkeyed chain.** SHA-256 has no secret, so anyone with database access can recompute everything after the last shipped head.
  - **Forged checkpoint.** AD-16 makes verification report a checkpoint "rather than a gap". An intruder deletes a recent range and writes a checkpoint event, or injects a retention job (ASEC-03). Verification then reports the deletion as expected.
  - **Head-only comparison.** The server's bucket credential can write. An intruder rewrites the tail, ships the new head, and local head matches latest off-server head. Object Lock preserves the older head, but AD-16's check doesn't look at it.

  Shipped security events remain safe. The harm is a false green from the tool Esm would run in UJ-6, plus loss of the events covering the intrusion itself.
- **Proposed change:**
  - State a sealing target of 10 seconds, and alert on the age of the oldest unsealed row.
  - Store heads off-server under a key of chain and `seq`, with conditional create, so a `seq` can't be overwritten.
  - `audit verify` walks **every** off-server head for the chain. It fails on a fork, a `seq` regression, or a head newer than any local row.
  - A checkpoint counts only if its range is past retention and its hash matches an off-server head.
  - Report seal and ship lag in `audit verify` output, so lag is visible rather than implied.
  - Add tests for each attack above.

### ASEC-07: FR-2 and FR-5 have no design

- **Citation:** AD-26 bullet 4, Structural Seed (`recover-admin`); FR-2, FR-5, FR-46; SEC-01
- **Attack:** The spine's only mention of bootstrap is one sentence that blocks Tenant traffic. Recovery appears only as a CLI name. That leaves these unanswered:
  - **Reopened bootstrap.** If bootstrap state is a `control` row, restoring an old backup or writing that row reopens FR-2. FR-2 says it can't be used again.
  - **Unknown privilege.** AD-3 says `gk_migrator` connects only during `gatekeep migrate`, and `recover-admin` needs a role. If it uses `gk_admin`, any Admin SQL injection can create a recovery enrolment.
  - **Suppressed alert.** FR-5 requires an alert, but alerts need `Host.Worker`. An intruder with infrastructure access stops `Host.Worker`, runs recovery, and enrols a credential before anyone hears about it.
  - **Token handling.** Bootstrap and recovery tokens have no stated storage, lifetime, binding or single-use mechanism. A value printed by a CLI lands in terminal scrollback.
  - **Partial enrolment.** A first Admin holds an unfinished state until two credentials exist, and this has no enforced definition.
  - **Admin Recovery Code.** FR-46's limited Recovery Code isn't placed in any AD.

  Recovery does need infrastructure access, which is the right anchor, and this is the Deployment's root of trust.
- **Proposed change:** Add an AD covering:
  - A 256-bit token, stored as SHA-256 only, expiring in 15 minutes, accepted only on `Host.Admin`, and consumed atomically with the write of the first Admin.
  - `control` rows that record bootstrap as complete. On restore, a pre-bootstrap backup needs an explicit flag and a Security Alert.
  - A dedicated `gk_recovery` role, with credentials not available to any running host, that can only insert a recovery enrolment. It needs a CHECK that it can't alter existing Admins.
  - Recovery that fails closed: the CLI sends the alert and writes the off-server record itself, and issues the enrolment only after both are confirmed.
  - Enrolment needs a fresh WebAuthn credential with user verification, and the session gets no other capability until the Admin's credential set is complete.
  - A rehearsal in SM-5, with `Host.Worker` stopped.

### ASEC-08: The TPM seal doesn't protect against root or, by default, a stolen server

- **Citation:** AD-10, AD-26, Open Items row 4; memlog (static seal); FR-4, UJ-6, §9; SEC-04
- **Attack:** OpenBao, its storage, the sealed credential and the TPM are in one machine, and the seal must open without a person present.
  - **Root.** Anything that can run as root on the host can unseal the credential, or read the key from OpenBao's memory, the same way boot does. Docker socket access is equivalent to root. "Non-exportable" is an API rule, not a cryptographic one. Root therefore gets every private key, and they stay usable after eviction.
  - **Stolen server.** The `systemd-creds` documentation says `--tpm2-pcrs=` binds to no PCRs by default. The default key mode, `auto`, uses the TPM plus a host key stored on disk. An unencrypted disk plus the same TPM can decrypt under any OS. AD-10 doesn't specify PCRs, disk encryption or a key mode.
  - **Container handoff.** `auto` doesn't use the TPM in a container, and the static seal takes its key by `file://` or `env://`. So the decrypted key must cross from host to container. AD-10 bars environment files and doesn't describe the path, so an implementer may write it to disk.
  - **Weak fallback.** The no-TPM default in Open Items is a root-only file, with the same issue.

  The OpenBao static seal page recommends the seal only where a root of trust already exists. A TPM with no PCR policy gives little more than hardware binding.

  Also, a static seal key isn't literally the barrier key. It protects OpenBao's key hierarchy, and each snapshot needs the seal key in use when it was taken. NFR-3's Master Key rotation has no design, though the static seal's `current_key` and `previous_key` give a mechanism. After rotation, older backups still need the older escrowed key.
- **Proposed change:**
  - **Best fix:** run OpenBao in a separate VM or small machine, reachable only by a narrow network path, so container escape or root on the application host doesn't reach it. Signing remains an oracle, but the key isn't readable.
  - **Minimum if kept on one host:**
    - Use `--with-key=host+tpm2`, with PCR binding to the boot chain plus Secure Boot.
    - Use full-disk encryption with TPM unlock under the same policy.
    - Pass the key by tmpfs to OpenBao only.
    - Keep the Docker socket out of every container, run them as non-root with a read-only filesystem and dropped capabilities, and limit OpenBao process access with ptrace restrictions.
  - Change AD-10's "Prevents" line to say this protects against process compromise and disk loss, not root. UJ-6 must treat every Transit key as stolen, including re-encrypting secrets under new keys.
  - Add an AD-10 rule on Master Key rotation and on keeping each escrowed key version as long as backups that need it.
  - Update the fallback row: no TPM means a separate unlock step or a recorded risk acceptance.

### ASEC-09: Backups have no immutability, so an intruder can destroy the UJ-6 path

- **Citation:** AD-17, AD-18; FR-4, NFR-13, UJ-6
- **Attack:** AD-17 gives audit data Object Lock, but AD-18 only says backups are "off the server". pgBackRest needs a repository credential on the server, and its normal expiry needs delete rights. An intruder deletes or overwrites all backups and OpenBao snapshots, then destroys the server or holds it for ransom. UJ-6's "rebuild from a backup that predates the compromise" is then impossible.

  Slow detection makes this worse, as no retention is stated. If backups are kept for less than the time to detect, every copy may include the intruder's changes.
- **Proposed change:**
  - Store backups in an immutable tier on a separate provider, using Object Lock or a pull from an off-site system that the server has no credential for. Test compatibility with pgBackRest expiry.
  - The server's credential can't delete, overwrite or shorten retention.
  - Keep immutable copies for at least 90 days, with periodic restore checks. Align this with ASEC-05's replay retention.
  - Alert when a backup is missing, and add this to the dead-man's content (ASEC-14).

### ASEC-10: Build and release controls wouldn't stop a malicious package reaching Hosted Login

- **Citation:** AD-21, AD-22, AD-23, AD-25, AD-26; NFR-7
- **Attack:** AD-21 and AD-22 keep Hosted Login's runtime free of third-party packages, which is a strong start. But the build still runs pnpm, Vite and their dependency tree. A hijacked build package can insert script into the bundle. That script is served from `self`, so CSP allows it, and CSP doesn't stop top-level navigation, so it can send typed passwords out. One release would capture credentials in all Tenants.

  AD-25's dependency scan only finds known vulnerabilities, so it misses a newly published malicious version. The same applies to the Admin bundle, which may use third-party primitives and runs in Owner sessions.

  AD-26 says "pinned, signed images" but not who signs, where the key lives, or what verifies a signature. `gatekeep upgrade` doesn't verify one. A build job with install scripts and signing credentials in one environment would hand both to a malicious package.

  `@gatekeep/*` package names could also suffer dependency confusion if the scope isn't owned on npm.
- **Proposed change:**
  - Frozen lockfiles for pnpm and NuGet, including transitive packages, with package source mapping for NuGet.
  - Lifecycle scripts disabled by default, with an explicit allowlist, and a minimum release age for new versions.
  - Own the `@gatekeep` npm scope, and use `workspace:` references only.
  - Separate jobs: install and build with no secrets, then sign digests in a job that runs no third-party code.
  - Pin base images and CI actions by digest or commit.
  - Generate an SBOM and provenance. `gatekeep upgrade` verifies image signatures against a key pinned on the server, and refuses otherwise.
  - Review the diff of bundle contents between releases, and rebuild independently before tagging if practical.
  - Keep the signing key in hardware, held by Esm.

### ASEC-11: The Argon2 budget covers passwords only, and Recovery Codes multiply the cost

- **Citation:** AD-14, AD-24; FR-27, NFR-6, NFR-20; SEC-32
- **Attack:** AD-14's budget names "password hashing". AD-24 also stores Recovery Codes in Argon2id. Salted hashes can't be looked up, so checking a code means testing each stored code in turn. For a Passkey-only User, FR-27 lets a Recovery Code replace the whole sign-in, so this step has no first factor. NFR-20 means unknown identifiers need equivalent dummy work.

  With 10 codes, one unauthenticated request costs up to 10 Argon2 runs. If this bypasses the semaphore, a low-rate flood exhausts memory in `Host.Hosted` and takes down every Tenant, breaking the Tenant failure-domain promise of NFR-6.

  Other gaps:
  - **Queue behaviour.** The semaphore has no bounded wait or queue size. An unbounded queue exhausts threads and memory instead.
  - **Shares.** A flood at one Tenant, inside its share, stops password sign-in for that Tenant from a distributed source. Per-source limits don't help, and bot defences are deferred. AD-14 doesn't say if shares are reserved or if Prod has priority.
  - **Memory.** A concurrency limit needs to be derived from the memory cost per hash, or the host can run out of memory.
  - **Client secrets.** A slow client secret hash on the public token endpoint is another unbudgeted path. Check OpenIddict's default.
  - **Spike tightening.** NFR-6 requires this and no AD owns it.
  - **Counter growth.** Counting unknown identifiers gives attackers unbounded row growth in `UNLOGGED` tables.
  - **IPv6.** Per-source keys should use a /64, or one host has endless sources.
- **Proposed change:**
  - The budget covers every memory-hard operation behind one port.
  - Generate Recovery Codes with at least 128 random bits, and store them under AD-24's SHA-256 rule. If shorter codes are preferred, use an HMAC lookup, so one attempt costs one operation. Generated client secrets get the same treatment.
  - Set a bounded queue with a short deadline. On overflow, return the generic failure without leaking account state.
  - Reserve a floor for each Tenant, and let Prod Tenants borrow idle capacity first.
  - Derive the concurrency limit from memory cost and container memory limit.
  - Assign spike tightening to `IRateLimiter`, cap counter rows, and key by hashed identifier.
  - Load test: a flood at one Tenant, including the recovery path, leaves the other Tenants within NFR-11.

## Medium

### ASEC-12: JWKS costs an unauthenticated database transaction, and AD-11 conflicts with AD-14

- **Citation:** AD-4, AD-11, AD-14; FR-38, NFR-10
- **Attack:** Each JWKS request opens a `TenantScope` transaction, and host resolution adds another query. PgBouncer is forbidden, so the connection pool is small and shared with sign-in. A distributed flood at a public, uncredentialed endpoint can fill the pool and stop sign-in for every Tenant. Per-source limiting helps less here, because tightening it risks blocking real resource servers. Discovery has the same cost if it's read per request.

  AD-11 says no server-side cache holds JWKS, while AD-14 allows caches of public data for up to 60 seconds. Adding a cache naively would also extend revocation: 900 seconds of client cache plus 60 of server cache exceeds FR-38's 15-minute limit.

  Attackers can also send tokens with random `kid` values to Applications, whose libraries may refetch JWKS each time.
- **Proposed change:** Let JWKS and discovery use a per-Tenant, single-flight cache with a 60-second maximum. Invalidate it through `LISTEN/NOTIFY` on key state change, and set `max-age=840` so the total stays within 15 minutes. Serve from a separate small connection pool, with ETag support. Quickstarts keep their library's unknown-`kid` refetch cooldown.

### ASEC-13: Transit is an unbudgeted chokepoint, and OpenIddict's internal credentials are undesigned

- **Citation:** AD-8, AD-9, AD-10, AD-24; Open Items rows 1 and 3
- **Attack:** RSA-3072 private operations run on every token issue, and signing needs a valid grant. An attacker can sign up for a free User account or use a low-value client, then loop through refresh rotation. All Tenants share Transit with TOTP decryption and code HMAC. No per-Tenant budget exists, unlike Argon2.

  OpenIddict's own code increases this. Its `AttachSecurityCredentials` handler gives authorization codes and refresh tokens both `SigningCredentials[0]` and `EncryptionCredentials[0]`, and stores the result as the reference token payload. So:
  - If all signing goes through Transit, one sign-in needs more RSA signatures than the two that token format suggests.
  - AD-8 and AD-10 cover signing only. An encryption credential exists too, and the spine doesn't say where it lives. AD-10's custody claim and AD-8's inert-credential design are incomplete without this.
  - At the handler layer, reference IDs are looked up as supplied. The hashing open item remains unresolved, and so does AD-9's custom `{tenantPublicId}.{random}` format through this path.

  Also check whether Microsoft.IdentityModel's signing path can call Transit asynchronously. A blocking call per signature under load risks thread-pool starvation. I couldn't confirm the API from the sources reached, so the spike should test it.

  RSA-3072 is flagged in AD-9 as an assumption. Key size isn't the problem by itself, and at 20 sign-ins per second the expected load should be manageable. Measure this rather than assume it.
- **Proposed change:** Extend the AD-8 spike to cover: all credential types by token type, where the encryption key lives, async signing, and sign counts per flow. Add a per-Tenant Transit concurrency limit behind `IKeyCustody`, with signing given priority over bulk work. Keep Transit's request deadline short, and rate limit `/token` per client and per User. Load test signing at NFR-11 peak with a flood running.

### ASEC-14: The dead-man's check proves a process is alive, not that evidence is flowing

- **Citation:** AD-17; FR-45, UJ-6, SM-5
- **Attack:** AD-17 doesn't say what sends the heartbeat, how often, or what it covers. If it's a simple ping, an intruder can stop sealing and shipping while it continues, or take the heartbeat URL from the server and send it from elsewhere after shutting everything down. Alerts derive from sealed events, so stopping the sealer also silences alerts, and the dead-man's check is the only remaining signal.

  Also, `gatekeep upgrade` stops the hosts, which trains a sole Operator to dismiss these alerts.
- **Proposed change:** Check off-server, independently of the server's claim. A small external scheduled check reads the Object Lock bucket and alerts when heads or backup markers go stale. The heartbeat object carries last sealed `seq`, last shipped `seq` and oldest unsealed age. Set an interval of 5 minutes or less. Announce planned maintenance through an off-server record with a time limit. Include this in AD-25 or SM-5, with tests that stop only the sealer and only the shipper.

### ASEC-15: Anyone can write rejected cross-Tenant events, which corrupts the SM-2 signal

- **Citation:** AD-9, AD-14, AD-16, AD-17; SM-2, NFR-3
- **Attack:** The enumeration risk from the format itself is low. The check compares against the serving Tenant only, so it doesn't reveal which other Tenants exist, and Tenant Subdomains are public anyway. Random parts of 256 bits can't be guessed. Keep error responses identical for mismatch, malformed and unknown artifacts, so that remains true.

  The real issue is that the check runs before any proof, and each mismatch writes a Log event. An unauthenticated sender using `x.y` at any endpoint causes:
  - Durable writes, with sealing work and potentially Object Lock storage that can't be deleted for 90 days.
  - A longer sealing lag, which widens ASEC-06's window.
  - An SM-2 signal that an attacker can fill with noise, hiding a real cross-Tenant event.

  If the event records the presented value, a real token sent to the wrong Tenant would be stored in a Log, breaking NFR-3.
- **Proposed change:** Aggregate per Tenant, source and minute, with a cap. Never record the value. Rate limit before writing. To make the signal trustworthy, add a short authenticator to artifacts that a valid Gatekeep artifact from another Tenant passes and random strings fail. Only then write an individual SM-2 event. Keep these out of off-server copying unless they pass that check.

### ASEC-16: WebAuthn verification rules are unstated, including the Admin RP ID

- **Citation:** AD-6, AD-7, AD-12, AD-19; FR-21, FR-46
- **Attack:** The spine says where the RP ID comes from, and browsers block a sibling Tenant from using another's exact RP ID. That is the main protection, and it holds. What's missing is the server side:
  - `AddFido2` is normally configured once with a domain and origin set, as a process-wide setting. A rushed per-Tenant build might use one global `Origins` list, or build it from the request `Host`. Either weakens the Tenant boundary. Confirm how `Fido2.AspNet` 4.3.2 supports per-request configuration in the AD-8 spike.
  - The Admin RP ID isn't defined. If set to a parent domain, any host under that domain can request Admin assertions.
  - No rule requires user verification for Admin, although FR-21 does for Users.
  - Nothing states that a fresh assertion is bound to the action. An attacker with a hijacked Admin session can use another action's 5-minute window.
  - Credential lookup and `userHandle` matching for discoverable sign-in aren't specified. The credential must belong to the User in the same Tenant.
  - AD-7 allows many hosts per Tenant, but one RP ID. The allowed origin source must be defined now.
- **Proposed change:** Add one rule to AD-6 or a new AD:
  - Build verification per request from stored Tenant values. `rpIdHash` must match the Tenant's RP ID, and `origin` must exactly match a `tenant_host` row of allowed kind. Reject `crossOrigin`, and never read the request `Host`.
  - Challenges are single-use and bound to the `signin_transaction` or Admin action.
  - Admin RP ID equals the exact Admin hostname, and UV is required.
  - Bind a fresh assertion's challenge to a hash of the action and target Tenant.
  - Make credential lookups Tenant-scoped, and check `userHandle`, which must be opaque.
  - Add negative tests for wrong origin, wrong RP hash, a sibling credential and a mismatched `userHandle`.

### ASEC-17: No egress control, SSRF rule or owner for social provider endpoints

- **Citation:** Conventions (Email), Structural Seed, AD-26; FR-20, FR-36
- **Attack:** Tenants set their own SMTP or HTTP email provider, and FR-36 adds a test send. So a stored value decides where `Host.Worker` connects, and test results may show connection errors. That gives port scanning of the private network and requests to internal services. Redirects and DNS rebinding bypass a simple check. Provider change needs an Owner and a fresh assertion, and A-1 applies, so this is Medium.

  Other gaps:
  - AD-26 covers inbound traffic only, so an RCE can send data anywhere.
  - The SMTP adapter has no TLS requirement. A downgrade exposes reset links and the provider credential.
  - `HH --> SO` is the entire social design. The Adapters list has no social or HTTP email adapter. If `Host.Hosted` fetches discovery from a configurable URL, that is SSRF from the host with decrypt rights.
  - GitHub isn't an OIDC provider, so "keyed on issuer and subject" needs a defined rule. Microsoft's multi-tenant issuer needs one too, or SEC-16's nOAuth concern comes back.
- **Proposed change:**
  - Add default-deny egress per container to AD-26. `Host.Hosted` reaches named social endpoints only, and email goes through one egress path.
  - Keep social endpoints in code, per provider, and never in Tenant config.
  - Add one outbound client for Tenant-supplied targets. It allows HTTPS or SMTP with mandatory validated TLS, on fixed ports, and no redirects. It checks the resolved address at connect time and blocks private, loopback and link-local ranges.
  - Test results return fixed categories, not raw errors.
  - Add a social adapter with per-provider subject rules, including Microsoft `tid` and `oid` handling.

### ASEC-18: Conformance mode is checked once at startup and doesn't name its Tenant

- **Citation:** AD-25; FR-7, FR-13, FR-23, FR-24, SM-4
- **Attack:**
  - The check runs at startup. A Tenant labelled Prod afterwards, or a running host that doesn't see the change, leaves relaxed code live.
  - A Tenant Owner can remove a Prod label, and then a restart with the flag passes.
  - "One Dev Tenant" has no selector. An environment flag is Deployment-wide. A Staging Tenant holding real data isn't protected by the check.
  - Each host checks independently, and the flag being on isn't reported.
  - Production images contain the relaxed code path. This is a precondition rather than a flaw, but only a Boolean guards it.
  - SM-4 evidence comes from a configuration different from production unless each deviation is listed.
- **Proposed change:** Make the flag name one Tenant ID. Relaxed paths check at request time that this Tenant matches, it's labelled Dev, and no Prod or Staging Tenant exists in the Deployment. If that fails, relaxation is off and an alert fires. Also refuse any change that would add such a Tenant while the flag is active. Write the mode to the Deployment Log and raise a Security Alert at startup. Ship conformance runs only on CI or a rehearsal VM. Add a test that the production Compose values can't set it.

### ASEC-19: CSP omits non-fallback directives, and logos have no design

- **Citation:** AD-21, AD-22; FR-33, FR-34; EXPERIENCE (Logo validation); SEC-31
- **Attack:**
  - `default-src 'none'` doesn't cover `base-uri` or `form-action`. HTML injection without script can then send a sign-in form to another site, or change the base URL. AD-21 mentions only `frame-ancestors` by name.
  - The first response embeds a JSON block containing Tenant and error strings. It needs escaping of `<`, or a value can break out of the block. CSP stops script, not injected markup.
  - EXPERIENCE allows sanitized SVG logos up to 1 MB. The spine has no logo decision on storage, serving or sanitizing. An SVG opened directly on a Tenant origin is a document, and script in it would run unless that response has its own restrictive CSP. XSS on a Hosted Login origin reaches passwords. Needs an Editor or a sanitizer bypass, and A-1 applies, so this is Medium.
  - AD-21 covers Hosted Login only. FR-33 requires the same for the Admin Dashboard, whose third-party primitives may inject style tags.
  - The Admin preview runs theme code in the Admin origin, which needs care, as does any stored logo.
- **Proposed change:** Name the full CSP: add `base-uri 'none'`, `form-action 'self'`, `object-src 'none'` and `require-trusted-types-for 'script'`, and test its behaviour with redirects. Use a single serializer for the data block that escapes `<`, `>`, `&`, U+2028 and U+2029. Convert uploaded SVG to PNG on `Host.Admin`, and serve only the raster from `Host.Hosted`, with `nosniff`. If SVG must stay, serve it with `Content-Security-Policy: default-src 'none'; sandbox` and only reference it through `<img>`. Give the Admin Dashboard a stated CSP. Set `no-store` on HTML responses that carry the step block.

### ASEC-20: `[FreshAssertion]` doesn't cover new Applications, and Roles can carry Management Permissions

- **Citation:** AD-19; FR-16, FR-32, FR-39, FR-42, FR-46; §7.2 (consent deferred); SEC-09
- **Attack:**
  - AD-19 calls `[FreshAssertion]` "the only rule needed". FR-46 lists *changing* Prod callback URLs. It doesn't clearly list *creating* a Prod Application with a callback. Third-party consent is deferred, so a new first-party-looking Application with an attacker's callback receives codes through silent sign-in for any User who follows a link. A stolen Management client, or ASEC-01, can do this.
  - Each Tenant's Management API is a normal API record. FR-32 lets an Editor put Permissions in Roles. If the built-in API's Permissions are selectable, a User token could carry them. FR-42's Owner-only rule is written about machine grants.
- **Proposed change:** Treat adding a callback to any Prod Application as a `[FreshAssertion]` action, including at creation. Add machine-exclusion review for Connection credentials and template destinations. Make the built-in API's Permissions unavailable to Roles and to any non-client-credentials grant. `Host.Admin` accepts only client-credentials tokens. Add tests for both paths.

### ASEC-21: The email template engine is unchosen, and previews can run in the Admin origin

- **Citation:** Conventions (Email), Notifications module; FR-36; SEC-29
- **Attack:** Editors and Management clients can edit templates, and `Host.Worker` renders them with decrypt rights. An engine that can reach code or objects makes template editing a route to code execution in `Host.Worker`. HTML preview in the Dashboard would be stored XSS from Editor to Owner in the Admin origin. A-1 applies, but a stolen Editor session or Management client doesn't need malice from Esm.
- **Proposed change:** Require a logic-less engine with a fixed set of variables. System link and code values are inserted by the server after rendering. Sanitize output and strip remote references. Show preview in a sandboxed frame without `allow-same-origin`, or as generated text.

### ASEC-22: Deployment-wide compromise response has no resume or completion record

- **Citation:** AD-13, AD-11; FR-50, UJ-6
- **Attack:** AD-13 uses one transaction per Tenant, which is correct, but nothing tracks progress. A crash during Deployment-wide FR-50, or an attacker stopping a host, leaves some Tenants still exposed, and Esm may believe the action finished. FR-50 also revokes all keys including `next`, while AD-11 assumes a ready `next` to promote.
- **Proposed change:** Model FR-50 as a parent operation with per-Tenant steps, which resumes on restart and shows per-Tenant status. Define key creation for the all-keys case, and create replacements before the commit that revokes. Treat completion as a Deployment Log event.

## Low

### ASEC-23: Single-use redemption isn't required to be atomic

- **Citation:** AD-13, AD-24; FR-13, FR-15, FR-19, FR-26, FR-27
- **Problem:** Two concurrent redemptions of a code, refresh token, Recovery Code or TOTP step could both pass a read-then-write check, and would then skip reuse detection.
- **Proposed change:** State one rule: redemption is a conditional update inside the handler, and the loser is treated as reuse. Add concurrent tests per artifact type.

### ASEC-24: Sign-in transactions slide with no absolute limit

- **Citation:** AD-12; FR-47
- **Problem:** A 30-minute sliding lifetime can be kept alive indefinitely, so a passed password step never goes stale. FR-47 calls the transaction short-lived.
- **Proposed change:** Add an absolute limit, suggested 60 minutes, and a shorter limit on a completed first factor awaiting the second.

### ASEC-25: Admin TLS, HSTS, CAA and Certificate Transparency have no owner

- **Citation:** AD-6, AD-26; NFR-4, NFR-21; SEC-11
- **Problem:** Caddy forwards only zone hostnames and the Admin hostname is outside the zone, so nothing states who terminates Admin TLS, which WebAuthn and `Secure` cookies need. NFR-21's CAA and Certificate Transparency items, and HSTS, have no place in the spine.
- **Proposed change:** Add these to AD-26. Use a separate certificate for Admin, not the wildcard. Add HSTS with `includeSubDomains` for the zone, and CAA and CT monitoring to the install runbook.

### ASEC-26: UUIDv7 reveals creation time, and cookie flooding works across siblings

- **Citation:** Conventions (Identifiers), AD-9, AD-12; Deferred (Public Suffix List)
- **Problem:** A public ID that encodes UUIDv7 exposes creation time through `sub`, and implies volumes. It remains unguessable. Separately, `__Host-` stops fixation, but script on a sibling Tenant can set many large parent-domain cookies, and those block requests to every Tenant from that browser until cleared.
- **Proposed change:** Use a random public ID separate from the internal UUIDv7, at least for `usr_`. Configure Caddy to return a clear error for oversized cookie headers, and document how to clear them. Revisit the Public Suffix List decision if this happens.

### ASEC-27: Dead jobs keep ciphertext and can flood Security Alerts

- **Citation:** AD-15; FR-45
- **Problem:** Payloads are erased when a job "finishes", and `dead` isn't clearly finished. An email provider outage raises one alert per dead job, which buries real alerts for a sole Operator.
- **Proposed change:** Erase credential-equivalent payloads on `dead` and past expiry. Aggregate dead-job alerts by type and Tenant.

## PRD review remedies

Status covers the architecture-level part of each remedy. Items marked "PRD" were resolved in the PRD and need no AD of their own.

| ID | Status | Evidence or gap |
| --- | --- | --- |
| SEC-01 | **Partial** | Admin separation in AD-2, AD-12 and AD-26 holds. Bootstrap and recovery have no design (ASEC-07) |
| SEC-02 | Survived | AD-12 server-held steps, AD-25 FR-25 matrix |
| SEC-03 | Survived | AD-13 |
| SEC-04 | **Partial** | AD-10 and AD-18 separate the key and backup. Master Key rotation and TPM strength are open (ASEC-08) |
| SEC-05 | Survived | AD-11 |
| SEC-06 | **Partial** | The mechanism exists, but scope and completeness don't (ASEC-05) |
| SEC-07 | PRD | AD-12 can carry it |
| SEC-08 | Survived | AD-19, AD-20 |
| SEC-09 | **Partial** | `[FreshAssertion]` rule holds. Token issue and trust undermine it (ASEC-01, ASEC-20) |
| SEC-10 | Survived | AD-19. Assertion isn't action-bound (ASEC-16) |
| SEC-11 | **Partial** | AD-6 and AD-26 hold for zone, key and DNS. CAA and CT have no owner (ASEC-25) |
| SEC-12 | Survived | AD-12. Public Suffix List decision recorded |
| SEC-13 | Survived | AD-12, with a lifetime caveat (ASEC-24) |
| SEC-14 | Survived | AD-8, AD-9, AD-25. Atomic redemption needs stating (ASEC-23) |
| SEC-15 | Survived | AD-9, AD-25 negative pack |
| SEC-16 | **Partial** | FR-20 rule has no adapter or per-provider design (ASEC-17) |
| SEC-17 | PRD | Notifications module carries it |
| SEC-18 | PRD | ASEC-11 changes Recovery Code storage cost only |
| SEC-19 | Survived | AD-3, AD-4, AD-15, AD-25. Job Tenant trust is new (ASEC-03) |
| SEC-20 | **Partial** | Structure holds. Verification doesn't deliver what it claims (ASEC-06) |
| SEC-21 | **Partial** | Alert table exists, but depends on `Host.Worker` (ASEC-14) |
| SEC-22 | **Partial** | Runbook is implied. Key replacement after root and FR-50 completion are open (ASEC-08, ASEC-22) |
| SEC-23 | Survived | No AD relaxes exact matching. FR-11 stands |
| SEC-24 | Survived | AD-21, AD-24. Keep timing equal under queue load (ASEC-11) |
| SEC-25 | Survived | AD-14. A database crash resets attempt counters, recorded as accepted |
| SEC-26 | Survived | AD-8, AD-12 |
| SEC-27 | Survived | AD-6, AD-7 |
| SEC-28 | Survived | AD-6 |
| SEC-29 | **Partial** | Provider change holds through AD-19. Template engine is open (ASEC-21) |
| SEC-30 | Survived | AD-13. Back-Channel Logout deferral recorded |
| SEC-31 | **Partial** | Theme generation holds. Logo design is **lost**, and CSP is incomplete (ASEC-19) |
| SEC-32 | **Partial** | Budget exists. Scope, queueing and spike response are open (ASEC-11) |
| SEC-33 | Survived | Kernel limits convention |
| SEC-34 | Survived | AD-25. Evidence caveat (ASEC-18) |
| SEC-35 | PRD | Not architecture-level |
| SEC-36 | Survived | AD-19 |
| SEC-37 | Survived | AD-24 |

**Result:** 21 survived, 12 partial, 4 PRD-level, none lost entirely. SEC-31's logo remedy is the one sub-item with nothing in the spine.

## What holds up

These parts are sound and shouldn't be weakened when the changes above are applied.

- **Tenant isolation against bugs:** `FORCE` RLS, restrictive policies, composite foreign keys, the failing cast, and the catalogue test (AD-3).
- **Transaction-scoped Tenant setting:** PgBouncer's exclusion avoids a classic leak (AD-4).
- **Host resolution:** exact match, no subdomain parsing, stored issuer and RP ID (AD-6).
- **Private keys outside application memory:** Transit stops post-eviction signing after application-level RCE (AD-10).
- **Inert global credential** in OpenIddict (AD-8), once extended to encryption (ASEC-13).
- **Key lifecycle:** one authoritative row, aged promotion, unaged emergency promotion (AD-11).
- **No cache tier:** revocation state can't be lost in Redis (AD-14).
- **Personal data outside the hash:** erasure and tamper evidence coexist (AD-16).
- **Object Lock with a separate provider** (AD-17). ASEC-06 fixes how it's checked, not the choice.
- **Dedicated zone and validation-only DNS delegation** (AD-6, AD-26).
- **No third-party runtime code in Hosted Login** (AD-22).
- **Single rule for machine exclusions** (AD-19), once its action list is complete.

## Checked against sources

| Claim | Result |
| --- | --- |
| `systemd-creds` default PCRs and key mode | Confirmed: no PCRs by default, `auto` mode, and no TPM use in a container |
| OpenBao static seal | Confirmed: `file://` and `env://` key sources, `current_key` and `previous_key`, and root of trust caution |
| OpenIddict signs and encrypts codes and refresh tokens | Confirmed in `OpenIddictServerHandlers.Protection.cs`. Hashing in the store layer not confirmed |
| Fido2.AspNet per-request configuration | **Not confirmed.** Docs show `AddFido2` setup. Spike must verify |
| Microsoft.IdentityModel async signing | **Not confirmed.** Spike must verify |
| OpenBao 2.6.4 rate limit quotas | **Not confirmed.** The docs page returned no content |
| OpenIddict default client secret hash cost | **Not checked** |
| Root can unseal the credential | Inference from unattended unsealing. The man page doesn't state it. No authorization other than PCR state gates the seal in this configuration |

**Limits of this review.** It is a design review of the spine, using the PRD, memlog and EXPERIENCE. No code exists, and nothing was tested. Timing and capacity statements are reasoning to be measured, not results.

Sources: [systemd-creds](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html), [OpenBao static seal](https://openbao.org/docs/configuration/seal/static/), [OpenIddict server protection handlers](https://raw.githubusercontent.com/openiddict/openiddict-core/dev/src/OpenIddict.Server/OpenIddictServerHandlers.Protection.cs), [fido2-net-lib docs](https://docsearch.algolia.com/mcp/docs/repo/passwordless-lib/fido2-net-lib).
