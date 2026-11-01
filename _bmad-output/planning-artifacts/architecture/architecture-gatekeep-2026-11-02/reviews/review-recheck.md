---
name: 'Gatekeep architecture spine: post-revision recheck'
type: architecture-review
reviews: ../ARCHITECTURE-SPINE.md
lens: recheck
created: '2026-11-02'
status: open
---

# Recheck: Gatekeep Architecture Spine After Revision

## Verdict

**Not ready for epics. No Critical is fully open, but 16 High text defects remain, plus one PRD decision.** The revision closed the structural problems: table ownership, command context, the dependency diagram, the Admins module, Operations and token isolation. Of the 51 earlier Critical and High findings, 29 are closed and 22 are partly or wholly open.

The remaining work is one editing pass of about 30 lines, with no change of paradigm or stack. One diagram edge is added. The biggest cluster is around Transit: AD-10's grants don't match what AD-15, AD-24, AD-11 and AD-33 need.

Severity follows the earlier reviews. **High** means an FR can't be built as written, a stated guarantee fails, or conforming units need cross-epic rework. **Medium** means the rework is local or the failure shows up early.

This was a document review. Nothing was run, and no Docker, container or local service was used. OpenBao policy path matching in H-2 comes from product knowledge, so the custody spike should confirm it. Medium and Low findings from the earlier reviews weren't re-audited, except where they're residuals of a High. Line numbers refer to the spine as read on 2026-11-02.

## 1. Status of earlier Critical and High findings

| Review | Closed | Partly or wholly open |
| --- | --- | --- |
| Adversary | ADV-01, 02, 03, 04, 05, 06, 07, 08, 14 | ADV-09 (H-9, H-10), ADV-10 (M-15), ADV-11 (H-7), ADV-12 (H-11), ADV-13 (H-8), ADV-15 (H-1), ADV-16 (H-1), ADV-17 (H-6), ADV-18 (M-12) |
| Security | ASEC-02, 03, 06, 09 | ASEC-01 (H-2, H-3), ASEC-04 (H-1), ASEC-05 (H-13), ASEC-07 (H-12), ASEC-08 (H-14), ASEC-10 (H-15), ASEC-11 (H-16) |
| Reconcile PRD | R-1, R-4 | R-2 (H-14), R-3 (H-17), R-5 (M-8) |
| Reconcile UX | R-1, R-2, R-4, R-5 | R-3 (M-7), R-6 (M-16), R-7 (M-14) |
| Rubric | F-1, F-2, F-3, F-4, F-5 | None |
| Verification | F-1, F-2, F-3, F-4, F-5 | None |

Three residuals dropped to Medium because what's left is local: ADV-10, UX R-3 and UX R-7, along with the smaller remainders of ADV-18, R-5 and UX R-6.

## 2. High findings

The Origin column says whether the defect is a residual of an earlier finding or was introduced by the revision.

| ID | Origin | Defect |
| --- | --- | --- |
| H-1 | ADV-15, ADV-16, ASEC-04, new | AD-10 grants don't cover HMAC, encrypt, unwrap, job payloads, Admin key creation or the Cli, and `provider` mixes two trust levels |
| H-2 | New, ASEC-01 | Transit names can't separate Management keys in a policy, and the orphan sweep would destroy secret class keys |
| H-3 | ASEC-01 | Nothing makes `Host.Admin` reject a Management token signed by a Signing Key |
| H-4 | New | AD-33 breaks AD-11's "exactly one `current` and one `next`" and its JWKS and ageing rules |
| H-5 | New | FR-35 account deletion can't start: it's an Operation, and `gk_hosted` can enqueue only notifications |
| H-6 | ADV-17, new | AD-5's exception list is wrong, and a refused refresh rolls back its own reuse revocation |
| H-7 | ADV-11, new | Alerts have no path from the sealer, and dead jobs and sealer lag can't alert |
| H-8 | ADV-13, new | Operations has no edge to Authentication, whose tables it must purge and read |
| H-9 | ADV-09 | Deployment events have nowhere to put personal data |
| H-10 | ADV-09, new | Admin invites have no provider table and no place for the link |
| H-11 | ADV-12 | Admin attempt counters have no store |
| H-12 | ASEC-07, new | Bootstrap and recovery can be suppressed or reopened, and `Host.Hosted` can't read `bootstrap_state` |
| H-13 | ASEC-05 | Restore reuses `seq` values, skips signature checks and omits credential replay |
| H-14 | ASEC-08, R-2 | Old backups can't be matched to the Master Key generation that opens them |
| H-15 | ASEC-10 | Nothing verifies image signatures, and build and signing aren't separated |
| H-16 | ASEC-11 | The Argon2 queue is unbounded |
| H-17 | R-3 | V-2 still needs a PRD decision |

### H-1. AD-10 grants don't match their callers

- AD-24 needs `Host.Hosted` to HMAC email codes and Recovery Codes. AD-10 gives it only sign and decrypt.
- AD-24 and AD-15 need it to encrypt pending values and email links, and AD-10 lets it unwrap nothing, although it must hold the token protection key.
- AD-15's payload ciphertext has no key class, and `Host.Worker` can decrypt only `provider`.
- `provider` holds social and email credentials together, so `Host.Hosted` can decrypt email provider credentials. ASEC-04 asked for exactly this split.
- FR-37 and FR-38 create a new `next` from a Dashboard action, and AD-11 requires it at commit. Only `Host.Worker` may create keys.
- AD-18 and `gatekeep rekey` create and replace keys from the Cli, which has no policy.
- FR-46's Admin Recovery Codes have no Tenant `hmac` key.
- "Not decrypt `totp`" implies that `Host.Admin` may decrypt everything else.

**Fix, AD-10 line 195, replace with:**

> - Each Signing Key is its own Transit key. Each Tenant has separate Transit keys per secret class: `totp` (TOTP seeds and pending Recovery Codes), `social` (social provider credentials), `email` (email provider credentials), `payload` (credential-equivalent job payloads), `hmac`, and a wrap key for the token protection key. The Deployment has its own `email`, `payload` and `hmac` keys for Admin flows.

**Fix, AD-10 line 199, replace with:**

> - `Host.Hosted` may sign with Signing Keys, encrypt `totp` and `payload`, decrypt `totp` and `social`, compute `hmac`, and unwrap the token protection key. `Host.Admin` may create Signing and Management keys, sign with the Management key (AD-33), encrypt `social`, `email` and `payload`, and compute the Deployment `hmac`. It decrypts nothing. `Host.Worker` may create, rotate and delete keys, wrap the token protection key, and decrypt `social`, `email` and `payload`. `Gatekeep.Cli` has its own policy: create, rotate, rewrap and delete keys, encrypt `social` and `email`, and sign and verify off-server records. Nobody may export.

**Fix, AD-24 line 406, append:**

> Admin Recovery Codes use the Deployment `hmac` key.

### H-2. Transit naming can't support AD-33, and the sweep is unsafe

AD-10 line 204 names every key from "the row's UUID". OpenBao policies work by path, so `Host.Hosted` can't be allowed Signing Keys and denied Management keys unless the name shows the purpose. AD-33's central guarantee depends on this. Secret class keys also have no row, so "removes unreferenced keys" would destroy them.

**Fix, AD-10 line 204, replace with:**

> - A key's Transit name starts with its purpose, so a policy can separate keys by path: `sig-{tenantId}-{rowId}`, `mgmt-{tenantId}-{rowId}`, `{class}-{tenantId}`, and `dep-{class}` for Deployment keys. A Signing or Management key is created first, named from a pre-generated row ID, and then its row commits. An orphan sweep removes only `sig-` and `mgmt-` keys with no row after 24 hours. Secret class keys have no row, and only Tenant creation and deletion create or destroy them.

### H-3. `Host.Admin` isn't required to reject Signing Key tokens

AD-33 says how tokens are issued, but not what `Host.Admin` accepts. ASEC-01 required that rejection, because that's where a forged token from `Host.Hosted` is stopped.

**Fix, AD-33 line 503, insert after "never appears in the public JWKS.":**

> `Host.Admin` validates Management API tokens only against that Tenant's `management` keys and rejects any token signed by a `purpose = signing` key. The token's `iss` is the Admin endpoint, so it can never equal a Tenant issuer.

### H-4. AD-33 contradicts AD-11

A `management` row that "follows AD-11" gives a Tenant two `current` and two `next` rows, against line 226. Line 227 would publish it in JWKS, against AD-33. Line 228 would age a key that's never published. Lines 226 to 229 also don't say who replaces a consumed or revoked `next`, and "Revocation promotes `next`" reads as applying when `previous` is revoked too.

**Fix, AD-11 line 226, replace with:**

> - The `signing_key` row is authoritative, and its `purpose` is `signing` or `management` (AD-33). A state change is one command, so at commit a Tenant has exactly one `current` and one `next` per purpose. Any command that consumes or revokes `next` creates its replacement.

**Fix, AD-11 line 227, replace its first clause with:**

> - JWKS contains the `next`, `current` and `previous` keys with `purpose = signing`, served with `Cache-Control: max-age=900`.

**Fix, AD-11 line 228, append:**

> `management` keys are never published, so they need no ageing.

**Fix, AD-11 line 229, replace with:**

> - Revoking `current` promotes `next` even if it's younger than 15 minutes. The Log records that it was unaged. Revoking every key (FR-50) creates and promotes new keys of both purposes in the same Operation.

### H-5. FR-35 account deletion has no route

FR-35 lets a User delete their account in the Account Portal, on `Host.Hosted`. AD-1 makes cross-module deletion an Operation. `Host.Hosted` has no edge to Operations, and AD-15 limits `gk_hosted` to notification jobs. That limit is right and should stay.

**Fix, AD-30, add a bullet after line 477:**

> - Account deletion (FR-35) is a command in `Host.Hosted` that sets `user.deletion_requested_at` and revokes the User's access through `RevokeAccess`, in one `CommandContext`. Authentication refuses a marked User. `Host.Hosted` can't start an Operation, so a recurring Worker job turns each marked User into a deletion Operation, whose handler re-checks the marker (AD-15).

### H-6. AD-5 lists the wrong exceptions and loses revocations

Line 140 calls three exceptions "the only" ones, yet job state, seal columns, `rate_usage`, sign counts and TOTP last-used steps are also writes to logged tables. Read literally, sealing an event writes an audit event, which needs sealing. Line 142 keeps only events after a rollback, but refresh reuse must commit its revocation while the response is an error (AD-13, ADV-17). Verification F-9 flagged the same risk.

**Fix, AD-5 line 140, replace with:**

> - A state change is any write to a logged table, except these operational writes, which are exempt from audit but not from AD-3: Session idle touches, WebAuthn sign counts, TOTP last-used steps, `client_usage`, `rate_usage`, `service_status`, job and `operation_step` state, seal columns and UNLOGGED counters. Adding one needs an AD change.

**Fix, AD-5 line 142, replace with:**

> - A refused request that must leave a durable effect commits it in a separate short `FailureContext` after the rollback. That covers failed sign-in events, lockout state and attempt counts, and the revocations caused by refresh token reuse and code replay, which commit even though the response is an error. A `FailureContext` is a `CommandContext` in every other respect.

**Fix, Open Items line 663, add to the spike list:**

> a refused refresh committing its revocation

### H-7. Security Alerts have no working path

AD-17 makes the sealer the trigger, but Audit has no edge to Notifications, and no role is allowed to enqueue the alert. AD-15 says a job body runs under `gk_worker`, while AD-16 runs sealing under `gk_sealer` and retention under `gk_retention`. AD-11 and AD-15 raise alerts from dead jobs, which have no event, and a dead alert job would alert about itself. AD-16 raises a lag alert from the component that's stalled.

**Fix, AD-15 line 280, replace with:**

> - A code-owned registry lists each job type and the roles allowed to enqueue it, enforced by the same trigger. `gk_hosted` can enqueue only notification types, and `gk_sealer` only alert types.

**Fix, AD-15 line 282, replace with:**

> - `gk_dispatch` sees only dispatch columns. A job body runs in its own `TenantScope` under `gk_worker`, except sealing under `gk_sealer` and retention under `gk_retention`, as the registry states.

**Fix, AD-15 line 283, replace the end with:**

> exhausted jobs stop in a `dead` state and raise a Security Alert (AD-17). Alert jobs never go `dead`. They retry with capped backoff.

**Fix, AD-16 line 295, replace the last sentence with:**

> The target is 5 seconds. Lag above 60 seconds is reported through the AD-17 heartbeat, which raises the Security Alert.

**Fix, AD-17 line 311, replace with:**

> - Security Alerts derive from audit event types through one code-owned table in Notifications, and go through the `IAlertChannel` port to a service outside the Deployment. The Operations sealing job calls Audit to seal a batch, checks the sealed events against that table, and enqueues one alert job per match, keyed on event ID, in the same transaction under `gk_sealer`. An alert therefore can't precede its committed event. A condition with no event writes one first: an exhausted job writes `operations.job.dead` through a `system` Actor.

**Fix, AD-17 line 312, replace with:**

> - A heartbeat to an external dead-man's check carries the latest sealed and shipped chain positions, the oldest unsealed age and the oldest undelivered alert age, so stalled evidence raises an alert as well as a dead Deployment. `[ASSUMPTION]`

### H-8. Operations can't reach Authentication

Authentication owns `signin_transaction` and attempt counters (AD-27). Operations must purge them on Tenant deletion and expiry (AD-1, AD-15, AD-30), roll counters into `rate_usage` (AD-14), and erase email held in transactions (FR-49). AD-1 forbids it from querying those tables, and it has no edge. Adding one creates no cycle. AD-30 claims to prevent "no module able to reach everything".

**Fix, diagram, add after line 74:**

> `OPS --> AUTHN`

**Fix, AD-30, add a bullet after line 474:**

> - Each module with `tenant` tables exposes a Tenant purge in its contract, and Tenant deletion calls each one. An architecture test fails if AD-27 gives a module `tenant` tables and Operations has no edge to it.

### H-9. Deployment events have no home for personal data

AD-16 puts IP address, user agent and email in `audit_detail`, a `tenant` table. Deployment events have no Tenant, so Admin sign-in details would land in the tamper-evident envelope, which AD-16 exists to prevent. Line 296 also gives "runtime roles" `SELECT`, which contradicts AD-2 for `gk_hosted`.

**Fix, AD-16 line 293, append:**

> Personal data for Deployment events goes in `deployment_audit_detail`, with the same rules as `audit_detail`.

**Fix, AD-16 line 296, replace "Runtime roles have `INSERT` and `SELECT`" with:**

> Roles granted access in the registry have only `INSERT` and `SELECT`

**Fix, AD-27 line 452, replace with:**

> | Audit | `deployment_audit_event`, `deployment_audit_detail` | control |

### H-10. Admin invites can't be sent

AD-31 uses a Deployment-level email provider, but AD-27's `email_provider` is `tenant` class and no Deployment table exists. `Host.Admin` has no egress (AD-26), so the Worker must send, as a Deployment-wide job. The link is credential-equivalent, and `job_payload` is a `tenant` table, so that job can't hold it.

**Fix, AD-27, add after line 453:**

> | Notifications | `deployment_email_provider` | control |

**Fix, AD-31 line 487, replace with:**

> - Admin invites use the provider in `deployment_email_provider`. `Host.Admin` has no egress, so sending is a Deployment-wide job. `job_payload` is a `tenant` table, so the invite link waits in `admin_invite` as Transit ciphertext under the Deployment `payload` key, and is erased once sent.

### H-11. Admin attempt counters have no store

AD-14 puts counters in `tenant` tables, and Admins have no Tenant. FR-46 sign-in and Admin Recovery Codes therefore have no limit store.

**Fix, AD-14 line 265, append:**

> `IRateLimiter` is a Kernel port. Admin attempt counters live in the `UNLOGGED` `control` table `admin_attempt`, owned by Admins, behind the same port.

**Fix, AD-27 line 445, add `admin_attempt` to the Admins row. AD-28 line 461, add `IRateLimiter` to the Kernel list.**

### H-12. Bootstrap and recovery remain weak

- Line 486 sends the FR-5 alert through the normal path. An intruder who stops `Host.Worker` suppresses it before enrolling, which is ASEC-07's main attack.
- Line 485 gives the token no lifetime and doesn't state that it works only on `Host.Admin`.
- Erasing the state leaves nothing to show that bootstrap happened, and FR-2's two-credential rule isn't placed.
- `Host.Hosted` has no edge to Admins, so it can't read `bootstrap_state`. It doesn't need to: no Tenant can exist yet, so AD-6's 404 already does the job.
- FR-5 requires a short-lived enrolment, and no lifetime is stated.

**Fix, AD-31 line 485, replace with:**

> - `gatekeep init` writes a one-time 256-bit bootstrap token to a root-only file and stores its SHA-256 and a 15-minute expiry in `bootstrap_state`. It can reissue the token until bootstrap completes. `[ASSUMPTION: lifetime]` Only `Host.Admin` accepts it. Consuming it and creating the first Admin is one command that records completion, and the row is never deleted. The route then returns the same 404 as any unknown path. The first Admin can do nothing else until two WebAuthn credentials are registered. No Tenant can exist before bootstrap, so `Host.Hosted` needs no check: AD-6's fixed 404 refuses all traffic. `gatekeep restore` refuses a backup with incomplete bootstrap unless given an explicit flag, which raises a Security Alert.

**Fix, AD-31 line 486, replace with:**

> - `gatekeep recover-admin` runs on the host as `gk_cli`. It sends the Security Alert through `IAlertChannel` and writes the off-server record itself, and issues the enrolment only after both are confirmed, so stopping `Host.Worker` can't suppress them. The enrolment for FR-5 is single-use and expires in 15 minutes. `[ASSUMPTION: lifetime]` It then ends that Admin's sessions and writes to the Deployment Log.

**Fix, AD-17 line 309, replace with:**

> - Records are signed by a Deployment Transit key that only `Host.Worker` and `Gatekeep.Cli` can use.

### H-13. Restore breaks the chain and leaves gaps

AD-17 ships one immutable head per `seq`. After a restore, sealing reuses those `seq` values with new hashes, so shipping conflicts and `audit verify` reports a fork after every restore. Records are signed, but nothing checks them on replay, so a forged record would be applied. FR-4 says a revoked credential can't return, while AD-17's list omits passwords, Factors, Passkeys and spent Recovery Codes.

**Fix, AD-17 line 308, replace "one chain head per `seq`" with:**

> one chain head per `(epoch, seq)`

**Fix, AD-17 line 310, replace the last sentence with:**

> It covers keys, Token Families, Sessions, Users, Admins, client secrets, password changes, Factor and Passkey removals, and Recovery Code use. A replayed password change sets `credential_reset_required`, because the old hash has returned.

**Fix, AD-18 line 324, replace with:**

> 2. Verifies the signature on each off-server record, reports and skips any that fail, and replays the rest of the AD-17 revocations.

**Fix, AD-18, add after line 325:**

> 4. Writes a signed restore record off the server, naming the restored head of each chain, and starts a new `epoch` for each chain. `--planned-rollback` skips only step 3.

**Fix, AD-16 line 298, append:**

> A break between epochs is accepted only where a signed restore record names it.

### H-14. Older backups may become unopenable

After Master Key rotation, an older backup still needs the older seal key, and nothing records which one. UJ-6 restores from an older backup, so this is the moment it would fail.

**Fix, AD-10 line 203, append:**

> Every escrowed generation is kept until the last backup that needs it has expired.

**Fix, AD-18 line 319, replace "with the release version and timestamp" with:**

> with the release version, timestamp and Master Key generation

### H-15. Signed images aren't verified

AD-25 signs images but nothing verifies them, and a malicious build package could reach signing credentials in the same job.

**Fix, AD-25 line 420, append:**

> Building and signing are separate CI jobs: the job that runs third-party code holds no secrets, and the signing key is held in hardware by Esm. `gatekeep upgrade` verifies each image signature against a key pinned on the server, and refuses otherwise.

### H-16. The Argon2 queue is unbounded

An unbounded queue moves the exhaustion from CPU and memory to threads and requests, which breaks NFR-6's Tenant failure domain.

**Fix, AD-14 line 268, replace the first sentence with:**

> All Argon2id work passes through a Deployment-wide semaphore with a bounded queue, a short deadline, per-Tenant shares and a reserved floor per Tenant (NFR-6). Concurrency is derived from the memory cost per hash and the container memory limit. On overflow the request gets the generic failure, which reveals no account state.

### H-17. V-2 needs a PRD decision

The Open Items row is accurate, so the spine text needs no edit today. FR-27 and FR-31 stories stay blocked until Esm chooses between the proposed single-use enrolment link and accepting that the account can't be recovered. If the link is chosen, it needs a §5.2 lifetime and entries in AD-9 and AD-24.

## 3. Medium findings

| ID | Origin | Defect | Exact fix |
| --- | --- | --- | --- |
| M-1 | New | The Kernel's Fido2 wrapper pulls an external library into every contract, against "Infrastructure sits behind ports". | AD-31 line 484, replace the sentence with: "It uses the Kernel `IWebAuthnVerifier` port, whose stateless adapter in `src/Adapters/Fido2` takes the RP ID and origin per call and knows no User or Admin types, but no tables or flows from Identity or Authentication." Add the port to AD-28 and `Fido2` to the Adapters line in the Seed. |
| M-2 | New | Hosts must wire adapters for modules they have no edge to, so AD-1's generated test fails on the first build. | AD-1 line 97, append: "A host's composition root may also reference any module's adapter registration. It's used only to wire ports." |
| M-3 | New | Payloads carry IDs only, but Notifications can't resolve an address: it has no edge to Identity or Admins, and adding one makes a cycle. | AD-15 line 284, append: "Recipients are IDs too. The Operations send handler resolves the address through Identity or Admins at send time and passes it to Notifications." |
| M-4 | New | `service_status` has no owner or writer. The read route through Management and Operations is fine. | AD-32 line 497, replace the last sentence with: "`Host.Worker` polls each `/healthz` and writes the `service_status` `control` table owned by Operations, with a timestamp so that a stale row shows as unknown. The Dashboard reads it through Management and Operations." Add the table to AD-27. |
| M-5 | New | "Notification outbox state" has no table name and implies a second queue beside AD-15. | AD-27 line 453, replace with: "\| Notifications \| `email_template`, `email_provider` \| tenant \|". Queueing and retry state live in `job`, and per-recipient limits use `IRateLimiter`. |
| M-6 | New | `operation_step` is `tenant` class with `tenant_id NOT NULL`, but AD-30 also has Deployment stages. Deployment-wide jobs have no payload table. | AD-27: move `operation_step` to the Operations `control` row. AD-30 line 475, append: "`operation_step` holds a nullable Tenant ID, a stage, a status and a result code, and no personal data. Every read filters on the path's Tenant, and the cross-Tenant suite covers it." AD-15 line 279, append: "Its only parameter is an `operation_id` dispatch column." |
| M-7 | UX R-3 | AD-21 says "no fetch", while AD-24 keeps one-time values out of the first response. | AD-21 line 366, insert after "with no fetch.": "The exception is a step carrying a `RevealOnce` value, which the client fetches from `/login/api/*`." |
| M-8 | R-5 | AD-6 still says Caddy forwards only zone hostnames, which contradicts AD-26's Admin site. | AD-6 line 152, replace the first sentence with: "Caddy terminates TLS. Its public site forwards only hostnames under the zone, and its Admin site (AD-26) serves only the Admin hostname." |
| M-9 | New | AD-26 limits egress to two hosts, but Caddy, pgBackRest, OpenBao's shipping and H-12's Cli alert all need it. | AD-26 line 432, replace the second sentence with: "Application egress is limited to `Host.Hosted`, `Host.Worker` and `Gatekeep.Cli`, through one `EgressHttp` handler that blocks private addresses. Infrastructure egress is limited to named endpoints: Caddy to its ACME and DNS providers, and pgBackRest and OpenBao's snapshot and audit shipping to their off-server targets." |
| M-10 | New | AD-8 has Protocol code reading Directory's and Sessions' tables, against AD-1. | AD-8 line 173, replace the second sentence with: "Each store lives in its owner's adapters: the application store in Directory, and the authorization and token stores in Sessions (AD-13)." Line 174, replace "reading Directory's `client_secret` table" with "calling Directory's contract, which reads `client_secret`". |
| M-11 | New | AD-33's endpoint has no module, can't reach Protocol's client authentication, and doesn't fit AD-19's Auth column. | AD-33 line 503, insert after the endpoint path: "This endpoint isn't OpenIddict. It lives in Management and authenticates clients through the same Directory contract method as AD-8." AD-19 line 340, Auth column: "Admin session or Management API token, or client authentication on `/oauth/token`". |
| M-12 | ADV-18, F-15 | The Account Portal has no backend owner, and the Map row omits Identity and Sessions. | AD-12, add a bullet: "The Account Portal's commands belong to Authentication, Identity and Sessions. It authenticates by Session cookie and isn't an OIDC client, which overrides EXPERIENCE line 38. Password policy checks run in Authentication, which has the edge to Directory." Map line 634, add Authentication, Identity and Sessions. |
| M-13 | New | AD-15 purges expired Sessions, while AD-13 keeps anchor rows until families expire. | AD-15 line 285, replace "purging expired Sessions, transactions and tokens" with "purging expired transactions and tokens, and Sessions with no live Token Family". |
| M-14 | UX R-7 | `rate_usage` can't see the in-memory limiter, so usage reads low during a flood. | AD-14 line 266, append: "`Host.Hosted` flushes its in-memory rejections into those counters each minute, keyed by resolved Tenant." |
| M-15 | ADV-10 | Email uniqueness and the number of Connections are undecided. This needs Esm's confirmation. | AD-29 line 467, append: "A Tenant has one database Connection in v1, and `user.email` is unique per Tenant. `[ASSUMPTION]`" |
| M-16 | UX R-6 | AD-22's override list omits the logo and dark primary. | AD-22 line 390, replace with: "Tenant themes override only the DESIGN.md theme contract: `ac`, its dark variant, their derived tokens, font, radius and logo." |

## 4. Low findings

| ID | Defect | Exact fix |
| --- | --- | --- |
| L-1 | AD-1 allows only composite cross-module foreign keys, but every `tenant_id` points to `tenant(id)`, a single column. | AD-1 line 97, replace "only as composite keys" with "only as composite keys, or as a single-column key to `tenant`,". |
| L-2 | AD-4's Tenant sources omit the Cli, which works one Tenant at a time in restore. | AD-4 line 132, insert after "the job row (AD-15)": "or a Cli command's iteration of `tenant`". |
| L-3 | AD-3 says `gk_migrator` connects only during `gatekeep migrate`, and AD-18 uses it in `gatekeep upgrade`. | AD-3 line 122, replace "`gatekeep migrate`" with "`gatekeep migrate` or `gatekeep upgrade`". |

## 5. Checked, no defect

- **Admins and Tenancy:** Admins has no edge to Tenancy and needs none. The capability table moved to the Admins contract, and Management and Operations already reach Tenancy for the Prod predicates.
- **Operations reading `service_status`:** the route from `Host.Admin` through Management to Operations exists. Only the table owner and writer are missing (M-4).
- **Notifications and AD-17:** the alert "table" is code-owned, so AD-27 doesn't need to list it.
- **Enqueue allow-list:** the `gk_hosted` limit holds for every Hosted flow except FR-35 (H-5).
- **FR-48 walk:** every caller of `RevokeAccess` (Identity, Directory, Authentication, Protocol, Management, Operations) has an edge to Sessions.
- **AD-8 handoff:** the `PROTO --> AUTHN` contract works, and Authentication needs no edge back.
- **Diagram:** it has 12 modules, matching the Seed, and stays free of cycles after H-8.
- **Stack table:** it carries the corrected OpenBao and React versions.
