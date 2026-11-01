---
title: Architecture spine rubric review
target: ../ARCHITECTURE-SPINE.md
spec: ../../../prds/prd-gatekeep-2026-11-01/prd.md
reviewed: 2026-11-02
verdict: revise before epics
---

# Rubric Review: Gatekeep Architecture Spine

## Verdict

**Revise before epics.** The spine is strong and most ADs hold up, but it doesn't yet pass the checklist. There are 5 high, 12 medium and 8 low findings. None needs the design to be rethought. Most can be fixed by amending an AD or the diagram.

Terseness was not treated as a defect. `.memlog.md` was read for rationale, and a gap was raised only when neither file settles it.

| Checklist item | Result | Findings |
| --- | --- | --- |
| Fixes the real divergence points, misses none | **Fail** | F-1, F-3, F-4, F-7, F-8, F-9, F-12 |
| Every Rule is enforceable and prevents its stated divergence | **Fail** | F-2, F-6, F-10, F-11 |
| Nothing under Deferred lets two units diverge | **Partial** | F-14 |
| Named tech is verified-current | **Fail** | F-13 |
| Covers the spec's capabilities | **Partial** | F-15, F-16 |
| Every owned dimension is decided, deferred or open | **Fail** | F-5 |
| Mermaid is valid | **Pass** | All four parse by reading |
| Dependency diagram agrees with the module list | **Fail** | F-1 |

Severity meanings:

- **High:** units will diverge, a stated guarantee fails, or Foundation work is blocked.
- **Medium:** a real gap that a story can trip over, with a contained blast radius.
- **Low:** an inconsistency or tidy-up.

## High Findings

### F-1. The dependency diagram omits a module and forbids calls that other ADs require

**Where:** Invariants diagram, AD-1, Structural Seed, AD-5, AD-13.

AD-1 makes the diagram binding and has CI fail on a violation, so every missing edge is a build failure or a pressure to weaken the test.

| Problem | Evidence |
| --- | --- |
| **Notifications is missing entirely.** | Structural Seed lists 11 modules and the diagram shows 10. The Capability Map assigns FR-33 to FR-36 to Notifications. |
| **Tenancy can't write audit events.** | AD-5 requires an audit event for every state change, and Tenancy owns Tenant, label and theme commands. The diagram has `AUD --> TEN`, so `TEN --> AUD` would run upward. |
| **Identity can't revoke Sessions.** | FR-48 fires on password, Factor and email changes in Identity. There's no `IDENT --> SESS` edge. |
| **Token Families have no home that Sessions can reach.** | AD-13 makes FR-48 one command across Sessions and Token Families. A Token Family is an OpenIddict row, and `PROTO --> SESS` means Sessions can't call Protocol. AD-1 says only the owner may query its tables. No AD names who owns the OpenIddict tables. |
| **Authentication and Directory aren't linked.** | FR-14 and AD-8 need Application and Connection checks during sign-in. There's no `AUTHN --> DIR`. |
| **Protocol and Identity aren't linked.** | Userinfo and token claims need User data. There's no `PROTO --> IDENT`. |
| **Management can't reach Sessions or Audit.** | FR-31 revokes Sessions, and FR-40 searches Logs. There's no `MGMT --> SESS` or `MGMT --> AUD`. |
| **Most writers can't reach Audit directly.** | Authentication, Protocol and Management all emit events, but only Directory, Identity, Keys, Sessions and Operations have the edge. AD-1 doesn't say whether transitive edges count. |
| **Key custody is out of reach.** | AD-10 has Identity, Authentication and Notifications decrypting secrets through `IKeyCustody`, but only Protocol, Management and Operations reach Keys, and the port's location isn't stated. |
| **Hosts have too few edges.** | `Host.Worker` runs Notifications jobs but reaches only Operations. `Host.Hosted` serves the Account Portal, with no route to Identity. |
| **Admin authentication has no module.** | See F-4. |
| **`Gatekeep.Cli` has no place.** | It isn't in the diagram or the layer table, yet it runs restore, recover-admin and audit verify. |

**Fix:**

1. Generate the diagram from an explicit edge list and make that list the input to the architecture tests.
2. Add Notifications and Cli.
3. Make audit writing a Kernel-level port, or a contract with no Tenancy dependency, so every module can write without a cycle.
4. State that Sessions owns the Token Family revocation contract, with OpenIddict rows behind it, or move the FR-48 command to a named orchestrating module.
5. Say whether transitive dependencies are allowed. They shouldn't be.

### F-2. `Host.Hosted` can forge Management API tokens, so AD-2 doesn't prevent what it claims

**Where:** AD-2, AD-9, AD-10, AD-19, AD-26.

AD-2 says it prevents an internet-facing flaw from reaching Admin functions or changing Tenant security configuration. The chain below defeats that:

1. AD-19 says Management API tokens come from the Tenant's own token endpoint, which is on `Host.Hosted`.
2. AD-9 makes them JWS tokens signed by the Tenant's Signing Key.
3. AD-10 gives `Host.Hosted` sign permission on those keys, for every Tenant.
4. `Host.Admin` must therefore accept a signature that a compromised `Host.Hosted` can produce on demand, with any audience and scope.

A forged token is held back only by `[FreshAssertion]`. Everything else in the Tenant's Management API stays open, including Connections, non-Prod callback URLs, Users and Roles. The remaining barrier is network reachability from the Hosted container to `Host.Admin`, and no Rule states it. AD-26 binds Admin to the VPN interface but says nothing about Compose networks or container-to-host routes.

**Fix:** Separate the trust path. Pick one:

- Sign Management API tokens with a dedicated per-Tenant Transit key that `Host.Hosted`'s policy can't use. It would be published to `Host.Admin` only, with issuance on a private endpoint.
- Make Management API tokens reference tokens looked up in a table that `gk_hosted` can't write.

Either way, add a Rule that `Host.Hosted` has no network route to `Host.Admin`, with a deployment test. FR-8's "tokens from any other Tenant" rule still holds if the Tenant stays in the token. FR-42 and A-13 are unaffected.

### F-3. AD-8's scope omits the two OpenIddict couplings most likely to break other ADs

**Where:** AD-5, AD-8, AD-9, AD-10, AD-24, Open Items.

**Encryption credentials are undecided.** OpenIddict's server option validation fails when `EncryptionCredentials` is empty, and `AttachSecurityCredentials` selects `context.Options.EncryptionCredentials[0]` for everything except identity tokens and access tokens with encryption disabled. Authorization codes and refresh tokens therefore need one. AD-8 designs an inert global *signing* key and doesn't cover this. A real global key would be one cross-Tenant secret in an internet-facing process, outside AD-10's custody, and it protects the `Payload` column. OpenIddict's docs strongly recommend Data Protection format or column encryption when reference refresh tokens are on, as AD-9 requires.

**OpenIddict writes outside AD-5.** Its stores save tokens from inside its own pipeline, not from a Gatekeep command. So AD-5's "no direct write outside a handler" and "state, audit and jobs in one transaction" don't hold on the token path. That path also needs a `TenantScope` open before any OpenIddict store query, or AD-3's failing cast fires. No rule says where the scope starts for an OpenIddict request.

**AD-9's artifact format needs a handler replaced.** `AttachTokenPayload` generates the reference ID itself, so `{tenantPublicId}.{random}` isn't a configuration choice.

**Fix:**

1. Decide where encryption keys live. A per-Tenant key held by `IKeyCustody` is the option that fits AD-10.
2. Amend AD-5 with a named exception or wrapper for the protocol path, stating how audit events and `TenantScope` attach to it.
3. Extend the spike's exit criteria to cover encryption credentials, RLS through the stores, reference ID format, and audit atomicity on refresh rotation.
4. Close the reference-hashing Open Item. `OpenIddictTokenManager.ObfuscateReferenceIdAsync` applies SHA-256 on create, update and lookup, with no option disabling it. This was read on the `dev` branch, so confirm it at the 7.7.2 tag. The canary scan stays worthwhile, but the Open Item's fallback is unnecessary.

### F-4. Admin TLS and Admin authentication have no owner

**Where:** AD-2, AD-6, AD-26, AD-12, Structural Seed.

**TLS.** AD-6 says Caddy forwards only hostnames under the zone. AD-6 also puts the Admin hostname outside the zone. The Seed routes Admins straight to `Host.Admin` over the VPN, and AD-26 binds `Host.Admin` to the VPN interface. Nothing terminates TLS for the Admin hostname, or issues its certificate. AD-26's "certificate private key is held only by Caddy" would then be broken if Kestrel took a key. NFR-4 requires TLS, and WebAuthn and `Secure` cookies need a secure context on a non-localhost name, so the first Foundation story (Admin sign-in, §7.4) can't be built without this decision.

**Authentication.** FR-46 needs WebAuthn ceremonies, Admin credentials, Recovery Codes, fresh assertions and Admin sessions. `Host.Admin` reaches only Management, and Authentication sits under `Host.Hosted` only. The Capability Map lists Management, Tenancy and Audit, none of which claims this. Unit authors could build a second WebAuthn stack, or put Admin credentials in a module that also sees User credentials, which FR-46 forbids.

**Fix:**

- Add a second Caddy site or instance bound to the VPN interface for the Admin hostname, and name how it gets a certificate. DNS-01 or an internal CA would both work. Keep the key out of `Host.Admin`.
- Name an `AdminAuth` module, or a named area of Tenancy, that owns the `control` Admin tables.
- State that it shares the Fido2 wrapper with Authentication but no credential tables.

### F-5. Infrastructure strategy and operations are only partly decided

**Where:** AD-17, AD-18, AD-26, Deferred. AD-26 decides deployment and environments well. Infrastructure strategy and operations are the silent dimensions.

| Dimension | Status | Gap |
| --- | --- | --- |
| Backup immutability | **Unsafe** | UJ-6 depends on a backup that predates the compromise. AD-17 locks audit data against the server's credential, but AD-18 says only that backups are "off the server". pgBackRest normally holds repository write and delete rights, so an intruder could destroy backups. |
| Backup schedule | Silent | Nothing states frequency, what runs it, or a failure alert. NFR-13 needs 24 hours at most, and `gatekeep upgrade` relies on a recent manifest. |
| Backup consistency | Gap | AD-18 reconciles `signing_key` rows only. A per-Tenant *secrets* Transit key created between the OpenBao snapshot and the database backup can't be reconciled, and snapshot order isn't stated. |
| OpenBao storage | Silent | Storage backend and snapshot mechanism aren't named. How hosts authenticate to OpenBao isn't either, though AD-2 and AD-10 depend on per-host identity. |
| Host provisioning | Silent | No statement of how the host is built or hardened, nor whether it's reproducible for clean-hardware restore (UJ-6). `deploy/` has Compose and scripts only. |
| Network segments | Silent | No Compose network layout, and no VPN choice even under Deferred. See F-2. |
| Build and release | Silent | No CI system, image registry or signing tool, though AD-26 requires signed images and AD-25 defines the gates. No promotion path from CI through rehearsal VM to production. |
| Monitoring | Partial | `/healthz` is on a private port, but FR-6 needs a signal external monitoring can read. No metrics decision, no alerts for disk, sealed OpenBao, stale backups, dead-letter depth or certificate expiry. The dead-man heartbeat covers only total failure. |
| Operational logs | Partial | Stdout JSON, but no shipping, rotation or retention. They carry IP addresses, which FR-49 and NFR-14 touch. |
| Patching | Silent | AD-18 covers Gatekeep releases only. OS, PostgreSQL major, OpenBao and Caddy upgrades have no rule, even though F-13 shows these need regular action. |
| NFR-21 controls | Missing | CAA records, Certificate Transparency monitoring and rehearsed emergency certificate replacement aren't mentioned, though the Capability Map assigns NFR-21 to AD-26. |
| NFR-3 Master Key rotation | Missing | AD-10 binds NFR-3 but has no rotation rule. OpenBao's static seal supports it through `current_key` and `previous_key`. Rotation must also re-escrow, and the UJ-6 runbook depends on it. |
| Recurring jobs | Silent | AD-11, AD-16 and AD-17 need recurring jobs. AD-15 defines a queue but no scheduler, so nothing prevents double firing or missed runs. |
| Data lifecycle | Silent | No purge rule for expired tokens, authorizations, Sessions, `signin_transaction` rows or finished jobs. OpenIddict tables will grow without one. |

**Fix:** Add one AD for infrastructure and one for operations. At minimum:

- Require Object Lock, or pull-based backup, on the backup repository, with a retention period longer than the time an intrusion could go unnoticed.
- Set a daily backup schedule that takes the OpenBao snapshot after the database backup, with a failed-backup Security Alert.
- Decide the rest, or list each under Deferred or Open Items with a default, so nothing stays silent.

## Medium Findings

### F-6. AD-3's policy as written returns no rows

PostgreSQL's `CREATE POLICY` docs say: "If only restrictive policies exist, then no records will be accessible." AD-3 specifies only a `RESTRICTIVE` policy, so every implementer has to invent a permissive one, and the catalogue test doesn't constrain it.

**Fix:** Name one standard permissive policy per runtime role, keep the restrictive one, and have the catalogue test assert both. The failing-cast design itself is sound: an unset or empty setting raises an error.

### F-7. Refresh tokens and Sessions have no defined relationship at expiry

§5.2 gives Sessions 7 days absolute and refresh tokens 30. AD-13 links each refresh token to its Session, and the ER diagram makes the Session mandatory for an authorization. No Rule says whether a refresh token survives natural Session expiry. A purge of expired Sessions would either cascade or orphan the tokens. FR-24 settles logout only.

**Fix:** State it. For example, Session expiry leaves refresh tokens valid, only explicit end-of-Session revokes them, and the reference is retained or nullable.

### F-8. Transactions have no rule about slow work

AD-4 and AD-5 put a command in one transaction, but nothing keeps Argon2id, Transit calls or SMTP outside it. A handler that hashes inside the transaction holds a pooled connection for the full hashing time, which threatens NFR-11. Transit calls during a key command are also a dual write.

**Fix:** Add to AD-5: no hashing or network I/O inside a transaction, with Transit keys created before commit, and orphans tolerated and swept.

### F-9. Modules have no shared-transaction mechanism

AD-5 needs state, audit and jobs in one transaction across module boundaries, and AD-1 gives each module its own tables. No Rule says how a transaction crosses contracts, or how many `DbContext`s are involved. Each module author could choose differently, and atomicity would quietly fail.

**Fix:** Define the unit of work in the Kernel, with one connection and transaction per `TenantScope`, and module contexts enlisted in it.

### F-10. AD-5's audit guarantee isn't enforced

The Rule says every state change writes an audit event, and AD-25 has no gate that checks it. An architecture test can catch a stray `DbContext` write but not a handler that forgets the event.

**Fix:** Have the command pipeline refuse to commit without an event or an explicit `[NoAudit]` declaration, and add that to AD-25.

### F-11. `GATEKEEP_CONFORMANCE_MODE` is checked only at startup

The Deployment refuses to start with the flag if a Prod Tenant exists, but a Tenant can be created or relabelled Prod while it's running. The Rule also doesn't say how the "one Dev Tenant" is chosen.

**Fix:** Name the Tenant in the flag's value, and refuse any Prod label while the flag is set. A conformance-only build would be stronger still.

### F-12. Database roles don't match the ADs that use them

- AD-3 lists four runtime roles, while AD-16 relies on a "sealer role" and a retention-only delete right that aren't listed.
- AD-3 says `gk_migrator` connects "only during `gatekeep migrate`", while AD-18 uses it in `gatekeep upgrade`.
- `restore`, `recover-admin` and `audit verify` have no role, though restore writes across Tenants and FR-5 writes Admin state.
- AD-3 says every table is `tenant` or `control`. AD-16 puts "one chain per Tenant and one Deployment chain" in `audit_event`, whose Deployment rows can't satisfy `tenant_id NOT NULL`, and AD-4 puts the Deployment Log in `control`.

**Fix:** Publish one role table with each role's grants and each CLI command's role, and name a separate `deployment_audit_event` table.

### F-13. Stack table isn't current for OpenBao or React

The spine says "Verified against vendor pages on 2026-11-02". Rechecked the same day:

| Name | Spine | Found | Status |
| --- | --- | --- | --- |
| .NET SDK / runtime | 10.0.403 / 10.0.14 | 10.0.403 / 10.0.14 | Current |
| OpenIddict | 7.7.2 | 7.7.2, with 8.0 in preview | Current |
| Npgsql EF provider | 10.0.3 | 10.0.3 stable | Current |
| Fido2.AspNet | 4.3.2 | 4.3.2 stable | Current |
| PostgreSQL | 18.6 | 18.6 | Current |
| Caddy | 2.11.7 | 2.11.7 | Current |
| pgBackRest | 2.60.0 | 2.60.0 | Current |
| Node.js | 26.13.0 | 26.13.0 LTS | Current |
| pnpm | 12.16.1 | 12.16.1 | Current |
| Vite | 8.3.5 | 8.3.5 | Current |
| **OpenBao** | 2.6.4 | **2.7.2 (2026-10-26). 2.6.5 also exists.** | **Stale** |
| **React** | 19.3.0 | **19.3.1** | **Stale** |

The OpenBao gap matters most. `.memlog.md` records "2.7 beta", but 2.7.0 shipped on 2026-09-23 without a beta label, followed by 2.7.1 and 2.7.2. Their notes list security fixes, including a Transit path traversal in imported key backups (GHSA-5pmx-2p74-x478). The spine's pin isn't even the latest 2.6 patch. Whether 2.6.5 carries those fixes wasn't confirmed. OpenBao is the custody layer for every key, so this should move.

React 19.3.1 is reported as a Server Components transport fix. That's from a secondary source, and Gatekeep doesn't use Server Components, so the impact is low.

**Fix:** Move OpenBao to 2.7.2 after checking 2.7's breaking changes, which affect moved plugins and the HSM distribution but don't appear to affect Transit or static seal. Move React to 19.3.1.

### F-14. Two Deferred items can cause divergence

- **DNS provider "chosen at install, behind ports".** It isn't behind a Gatekeep port. Wildcard certificates need the DNS challenge, and Caddy's DNS provider modules don't ship with Caddy: they're added with `xcaddy` or the download page. This conflicts with AD-26's "pinned, signed images per release". Either the provider is fixed at build time, or the image has to be built at install.
- **Email provider.** It's listed as chosen at install, but Conventions says Tenants configure their own provider through SMTP and HTTP adapters. Which HTTP providers are supported is a product and adapter contract decision, and the Seed lists only `Smtp`. Decide SMTP-only for v1, or name the HTTP shape.

The remaining Deferred items are safe: each stays within one unit, or the PRD places it later.

### F-15. Capability Map gaps

- **NFR-14 and NFR-15** are in `binds` but in no Map row. AD-16 does govern NFR-15.
- **FR-35 Account Portal** has no backend owner. The row names `apps/hosted-login`, Tenancy and Notifications, and none of them handles profile, credential or Session changes.
- **FR-2 and FR-5** have no governing AD beyond one line in AD-26, though both are security-critical one-time paths. Token creation and single use need a Rule.
- **Portal sign-in model:** EXPERIENCE assumes the Portal is a first-party Application in each Tenant. AD-19 and AD-21 describe Session-cookie APIs. The spine should confirm or overrule, as it did for JavaScript.

### F-16. Client secrets and machine permissions leave a fork open

- AD-10 says "client secrets not stored as hashes", and AD-24 has no hash rule, so both forms are possible. FR-12's overlap also needs two valid secrets per client, which isn't addressed.
- AD-20 makes one capability table the only role encoding, but Management API clients use Permissions on the built-in API. Nothing maps those to capabilities, so the machine path could express a second matrix.

**Fix:** Pick one stored form, name a two-secret model, and derive Management API Permissions from the capability table.

### F-17. FR-50 all-key revocation has no replacement rule

AD-11 says revocation promotes `next`. FR-50 revokes all Signing Keys, including `next`, so nothing clean remains to promote. The same applies to UJ-6.

**Fix:** State that revoking all keys creates a fresh key, promoted unaged, in the same command, and logged as AD-11 already does for unaged promotion. Also state that deployment-wide runs are resumable per Tenant, since AD-13's per-Tenant transactions can partly complete.

## Low Findings

- **L-1.** AD-14's in-memory limiter is per-source across Tenants, while FR-8 says counters are keyed by Tenant. It's defensible as pre-Tenant flood control, so record it as a deliberate exception.
- **L-2.** AD-15 doesn't state whether a claim is a lease or a held lock. Crash recovery needs a lease or a visible timeout.
- **L-3.** AD-16 bounds off-server copy at 60 seconds after sealing, but sealing delay itself has no bound, so FR-40's "near real time" isn't guaranteed.
- **L-4.** Restore replays revocations but not erasures. An FR-49 erasure after the backup comes back on restore. Put erasures in the off-server record too.
- **L-5.** AD-17 should state that `audit_detail` is never copied off-server.
- **L-6.** Restore needs the breach dataset, which AD-18 excludes from backups. NFR-13's 1 hour needs a source and a fallback. The refresh mechanism is also unstated.
- **L-7.** AD-26 says all environments use the same Compose definition, but local and CI have no TPM or `systemd-creds`. State the local seal arrangement.
- **L-8.** AD-2's grants cover only writes. Add read limits for `gk_hosted` on Admin `control` tables, asserted by the catalogue test.

## AD Rule Check

| AD | Enforceable | Prevents the stated divergence | Note |
| --- | --- | --- | --- |
| AD-1 | Yes | No, until the diagram is right | F-1 |
| AD-2 | Partly | **No** | F-2 |
| AD-3 | Yes | Yes, once fixed | F-6, F-12 |
| AD-4 | Yes | Yes | |
| AD-5 | Partly | Partly | F-3, F-8, F-9, F-10 |
| AD-6 | Yes | Yes | Admin hostname: F-4 |
| AD-7 | Yes | Yes | |
| AD-8 | Partly | Partly | F-3 |
| AD-9 | Yes | Yes | Needs handler work: F-3 |
| AD-10 | Yes | Partly | Rotation: F-5. OpenIddict key: F-3 |
| AD-11 | Yes | Yes | Edge case: F-17 |
| AD-12 | Yes | Yes | |
| AD-13 | Yes | Partly | F-1, F-7 |
| AD-14 | Yes | Yes | L-1 |
| AD-15 | Yes | Yes | Scheduler: F-5 |
| AD-16 | Yes | Yes | F-12 |
| AD-17 | Yes | Yes | L-3, L-5 |
| AD-18 | Yes | Partly | F-5 |
| AD-19 | Yes | Yes | V-1 resolved well |
| AD-20 | Yes | Partly | F-16 |
| AD-21 | Yes | Yes | Overrule of EXPERIENCE is explicit |
| AD-22 | Yes | Yes | |
| AD-23 | Yes | Yes | |
| AD-24 | Yes | Partly | F-16 |
| AD-25 | Yes | Partly | F-10, F-11 |
| AD-26 | Partly | Partly | F-4, F-5, F-14 |

## Mermaid Check

Diagrams were checked by reading, not by rendering.

| Diagram | Syntax | Agreement with the text |
| --- | --- | --- |
| Dependency flowchart | Valid | **Disagrees** with the module list and ADs: F-1 |
| AD-11 `stateDiagram-v2` | Valid | Agrees with the Rule and FR-37/38. Promotion on revocation is in text only, which is acceptable. The fence at column 0 ends the Rule's list, and the indented bullets after it still render. |
| Seed flowchart | Valid. `HH` and `HA` are first referenced outside the subgraph and then used inside it, which renders them inside as intended. | Omits Cli, VPN termination, Caddy's ACME and DNS traffic, the dead-man service, and the restore read from the Object Lock bucket. F-4 |
| `erDiagram` | Valid | `TENANT ||--o{ AUDIT_EVENT` conflicts with a Deployment chain (F-12). The mandatory `USER_SESSION` link sits on F-7. |

## What Works Well

- AD-3, AD-4 and AD-9 give isolation real depth, with a production signal for SM-2.
- AD-16's split of chained envelope and erasable detail resolves V-7 cleanly.
- AD-11 resolves V-9, and AD-19's `[FreshAssertion]` rule resolves V-1 with a single mechanism.
- AD-25's registry-driven cross-Tenant suite makes new endpoints fail until covered.
- The challenges to OpenFGA, Redis, the broker and the sandbox all follow the PRD.

## Sources

- [OpenIddict server configuration](https://raw.githubusercontent.com/openiddict/openiddict-core/dev/src/OpenIddict.Server/OpenIddictServerConfiguration.cs) and [protection handlers](https://raw.githubusercontent.com/openiddict/openiddict-core/dev/src/OpenIddict.Server/OpenIddictServerHandlers.Protection.cs)
- [OpenIddict token manager](https://raw.githubusercontent.com/openiddict/openiddict-core/dev/src/OpenIddict.Core/Managers/OpenIddictTokenManager.cs)
- [OpenIddict token storage docs](https://documentation.openiddict.com/configuration/token-storage)
- [PostgreSQL CREATE POLICY](https://www.postgresql.org/docs/current/sql-createpolicy.html)
- [OpenBao 2.7 release notes](https://openbao.org/community/release-notes/2-7-0/), [tags](https://api.github.com/repos/openbao/openbao/tags?per_page=20) and [static seal](https://openbao.org/docs/configuration/seal/static/)
- [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https) and [DNS provider module example](https://caddyserver.com/docs/modules/dns.providers.cloudflare)
- [.NET 10 release metadata](https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json), [PostgreSQL versions](https://www.postgresql.org/versions.json), [Node.js releases](https://nodejs.org/dist/index.json)
- NuGet flat-container indexes for OpenIddict, Fido2.AspNet and Npgsql EF
- npm dist-tags for pnpm, React and Vite
- GitHub releases for Caddy and pgBackRest
- [React 19.3.1 secondary report](https://www.issoh.co.jp/md/tech/4509)
