---
name: 'Gatekeep architecture spine: adversarial composition review'
type: architecture-review
reviews: ../ARCHITECTURE-SPINE.md
lens: adversary
created: '2026-11-02'
status: open
---

# Adversarial Review: Gatekeep Architecture Spine

## Verdict

**Not ready to break into epics.** I found 24 holes: 4 critical, 14 high and 6 medium. Two teams could follow every AD exactly and still build parts that can't be merged.

The decisions on security mechanics are strong. The spine is weak on composition, in three ways:

1. **Table ownership is never stated.** AD-1 says a module owns its tables, but the spine has no list of who owns what. The ER diagram names entities without owners, and the capability map names several modules per row.
2. **The dependency diagram can't carry the required calls.** AD-1 makes the diagram binding, and FR-14, FR-48, FR-50, FR-31 and FR-36 can't be implemented on it. Notifications is missing from it entirely.
3. **AD-5 assumes one transaction across modules, and nothing provides it.** AD-1 walls off each module's tables, and AD-4 makes `TenantScope` open a transaction. Nothing says how two modules share that transaction.

Fixes 1 to 4 below close most of the rest. Apply them before any epic is cut, because each one changes module boundaries.

**How to read this.** Each finding names two units, both of which obey the ADs, and the point where they collide. "Unit" means a plausible epic or story. Severity is:

- **Critical:** at least one FR can't be built on the spine as written, or two conforming units can't both exist.
- **High:** conforming units need cross-epic rework, or a boundary invariant silently weakens.
- **Medium:** rework is local, or the failure is caught early.

This was a document review: no code exists and nothing was run. Statements about OpenIddict and PostgreSQL behaviour come from my knowledge of those products, not from a test. The ones that need confirming are in the AD-8 spike list at the end.

## Summary

| ID | Severity | Hole | Fix |
| --- | --- | --- | --- |
| ADV-01 | Critical | User and Connection have no viable owner: Authentication and Protocol reach disjoint modules | New AD-27, amend AD-1 and diagram |
| ADV-02 | Critical | Module contract calls can open separate transactions and still obey every AD | New AD-28 |
| ADV-03 | Critical | Tenancy can't write audit; no low-level module can insert a job | AD-28, AD-1 |
| ADV-04 | Critical | Token Family has two owners, and no module can run FR-48 | Tighten AD-13, AD-27 |
| ADV-05 | High | Tenant configuration has no owner or table class | Tighten AD-4, AD-27 |
| ADV-06 | High | Application and client secret can live in three stores; FR-12 overlap doesn't fit OpenIddict's column | Tighten AD-8, AD-10, AD-24 |
| ADV-07 | High | AD-2 is a deny-list, so the most sensitive writes and reads stay open to `gk_hosted` | Tighten AD-2, new grant matrix |
| ADV-08 | High | The `job` row is trusted for the Tenant but has no Tenant boundary | Tighten AD-3, AD-15 |
| ADV-09 | High | AD-4's closed `control` list contradicts other ADs; Deployment Log can't fit `audit_event` | Tighten AD-3, AD-4, AD-16 |
| ADV-10 | High | One `CREDENTIAL` entity or many tables; social identity has no home | New AD-29 |
| ADV-11 | High | Notifications is absent; Security Alerts have no owner or trigger point | Amend diagram, tighten AD-17 |
| ADV-12 | High | Admin identity has no module; Admin sign-in has no route through the diagram | Add Admins module, amend AD-1, AD-14 |
| ADV-13 | High | Tenant create, delete and FR-50 have no module able to reach everything | New AD-30 |
| ADV-14 | High | A `RESTRICTIVE`-only policy denies everything and loses the failing cast | Tighten AD-3 |
| ADV-15 | High | Transit key creation can't join the transaction; AD-10 omits `encrypt`; `IKeyCustody` has no home | Tighten AD-10, AD-11 |
| ADV-16 | High | Cli is an unroled fourth host; data migrations can't pass RLS | Tighten AD-2, AD-3, AD-18 |
| ADV-17 | High | Failure events and counters roll back with the command; "every state change" is undefined | Tighten AD-5, AD-14 |
| ADV-18 | High | Authentication and Protocol have no agreed handoff; `signin_transaction` has no owner | Tighten AD-8, AD-12 |
| ADV-19 | Medium | The sealer role doesn't exist; erasure conflicts with "only retention may delete" | Tighten AD-3, AD-16 |
| ADV-20 | Medium | Cross-module foreign keys and cascades are undecided | Tighten AD-1 |
| ADV-21 | Medium | Deployment-wide jobs have two conforming shapes | Tighten AD-15 |
| ADV-22 | Medium | `[FreshAssertion]` can't express data-dependent rules; machine principals have no capability mapping | Tighten AD-19, AD-20 |
| ADV-23 | Medium | Public ID shape is undecided for `sub`, `{tenantId}` and `{tenantPublicId}` | Tighten Consistency Conventions |
| ADV-24 | Medium | OpenIddict's own caching and pruning may bypass AD-14 and AD-15 | Tighten AD-8, spike item |

## Critical

### ADV-01: User and Connection have no viable owner

**Unit A, Identity epic:** Identity owns `user`. Authentication reaches it through the existing `AUTHN --> IDENT` edge. Obeys AD-1.

**Unit B, Directory epic:** Directory owns `user`, as its name suggests, next to Applications and Roles. Protocol reaches it through `PROTO --> DIR`. The capability map row for FR-30 to FR-32 lists both modules. Obeys AD-1.

**Collision.** Authentication reaches Identity and Sessions. Protocol reaches Directory, Keys and Sessions. No module they both reach can hold a User, and the same is true of Connection:

| Entity | Needed by Authentication for | Needed by Protocol for | If in Identity | If in Directory |
| --- | --- | --- | --- | --- |
| User | Sign-in, sign-up, block check | `sub`, userinfo, `email_verified`, block check at refresh (AD-13) | Protocol can't read it | Authentication can't read it |
| Connection and per-Application enablement | FR-14 "shows only Connections enabled", FR-18 policy | FR-14 session reuse check (AD-8) | Protocol can't read it | Authentication can't read it |

Each module will reach for a local copy or an unofficial route. This is the two-owners failure the brief asked about, and the diagram forces it.

AD-1 also doesn't say whether transitive dependencies count. `PROTO --> DIR --> AUD` either permits Protocol to write audit or doesn't. The story writing the architecture test has to invent the answer, and half the codebase may have assumed the other one.

**Other required calls with no edge:**

| Missing edge | Required by |
| --- | --- |
| Management to Sessions | FR-30 view Sessions, FR-31 revoke, FR-39 |
| Management to Audit (direct) | FR-40 search, FR-49 erasure |
| Management to Notifications | FR-36 templates, provider, test email |
| Operations to Identity | FR-50 forced password reset and TOTP re-enrolment |
| Operations to Tenancy (direct) | Enumerating Tenants for rotation and retention jobs |
| Host.Worker, Authentication, Management and Operations to Notifications | ADV-11 |

**Fix. Add AD-27, and amend AD-1 and the diagram:**

> **AD-27: Table ownership.** Every table has exactly one owning module, named in the AD-3 registry. A registry entry with no owner fails CI.
> - **Tenancy:** `tenant`, `tenant_host`, `tenant_settings`, `tenant_theme`.
> - **Admins:** `admin`, `admin_credential`, `admin_session`, `admin_invite`, `tenant_role`.
> - **Identity:** `user`, every User credential table (AD-29), `external_identity`.
> - **Directory:** `application`, `client_secret`, `application_connection`, `connection`, `api`, `permission`, `role`, `role_permission`, `user_role`, `api_grant`, and the OpenIddict application and scope entities.
> - **Sessions:** `user_session`, `signin_transaction`, and the OpenIddict authorization and token entities.
> - **Keys:** `signing_key`.
> - **Audit:** `audit_event`, `audit_detail`, `deployment_audit_event`, `deployment_audit_detail`.
> - **Notifications:** `email_provider`, `email_template`.
> - **Operations:** `job`, `bootstrap_state`, `deployment_config`, attempt counters.
> - **Protocol, Authentication and Management** own no tables.

> **AD-1 amendment.** The diagram lists every allowed direct dependency. Transitive reach grants nothing: to call a contract, a module needs its own edge. The kernel ports in AD-28 are available to every module. Add these edges: Authentication to Directory, Protocol to Identity, Management to Sessions, Management to Audit, Management to Notifications, Management to Admins, Operations to Identity, Operations to Tenancy, Operations to Notifications, Authentication to Notifications, Notifications to Identity, Notifications to Tenancy, Admins to Tenancy, Protocol to Tenancy, Authentication to Tenancy. Modules write audit through the Kernel port (AD-28), so write-only callers need no Audit edge.

Protocol and Authentication still have no edge to each other (ADV-18).

### ADV-02: Module calls can split one command across transactions

**Unit A, password change (Identity):** The handler opens a `TenantScope`, which AD-4 says opens a transaction. It updates the hash and calls `ISessions.RevokeAll` through the contract. Obeys AD-1 and AD-5.

**Unit B, Sessions:** `RevokeAll` is a state change, so it's a command with its own handler, and it opens its own `TenantScope` because AD-4 makes that the only way in. It writes its audit event and commits. Obeys AD-4 and AD-5.

**Collision.** Two connections and two transactions now exist. If Unit A then rolls back, Sessions are ended and the audit trail records a change that didn't happen, which is exactly what AD-5 exists to prevent. The reverse order leaves a changed password with live Sessions, which breaks FR-48. If one module instead keeps its scope open while waiting on the other, that holds a pooled connection for the duration.

No AD says whether contracts accept a caller's scope, whether modules share a `DbContext`, or whether one handler may invoke another. Each module would answer differently.

**Fix. Add AD-28:**

> **AD-28: Command context.** A command runs in exactly one `CommandContext`, created only by the outermost handler. It holds the `TenantScope`, its single connection and transaction, the Actor, the trace ID, and the `IAuditAppender` and `IJobEnqueuer` ports. Every state-changing contract method takes the `CommandContext` as a required parameter and can't open a scope or commit. Only the outermost handler commits. Each module has its own `DbContext`, and all of them enlist on the context's connection and transaction. `TenantScope`, `CommandContext`, Actor and both ports live in the Kernel. An architecture test fails if a contract method on a state-changing path lacks `CommandContext`, or if `TenantScope` is opened anywhere but a host-level entry point or job runner.

> **Actor** is one Kernel type: `user`, `admin`, `machine` or `system`, with an internal ID. It's the only actor shape in handlers and audit events.

### ADV-03: Audit and job writers run against the dependency direction

**Unit A, Tenancy epic:** FR-10 settings, FR-7 label changes and FR-34 theme changes must write the Log. AD-5 requires this in the same transaction. Tenancy has no edge to Audit, and `AUD --> TEN` makes one a cycle. A conforming Tenancy can't write audit.

**Unit B, Audit epic:** Audit depends on Tenancy, as drawn, to validate a Tenant or read retention settings. Also conforming.

**Same shape for jobs.** AD-5 has every handler insert into `job`, and AD-1 says only the owner's adapters touch it. Operations is the natural owner and sits at the top of the diagram, so Identity, Keys and Directory can't depend on it. If each module inserts rows itself, AD-1 is broken. If each publishes its own job type, the table has many writers and no owner. Tenant-level FR-7 deletion, Admin changes and every email hit this.

**Collision.** Unit A has to move audit into Kernel, duplicate a writer, or skip the event. Each of those is a different table access path.

**Fix.** AD-28 above, plus this addition to AD-16 and AD-15:

> **AD-16 addition.** Audit is written only through the Kernel `IAuditAppender` port, implemented by an Audit adapter on the `CommandContext` connection. No module depends on Audit to write. Audit's contract covers reads, verification, retention and erasure. Each module defines its event type codes in its own contract, and a generated registry collects them.

> **AD-15 addition.** Jobs are enqueued only through the Kernel `IJobEnqueuer` port. Operations owns `job`. Each job type is registered by the module that handles it, and `Host.Worker` runs handlers through the Operations dispatcher.

Audit can then keep `AUD --> TEN` for its reads, because Tenancy's writes go through the Kernel port.

### ADV-04: Token Family has two owners, and FR-48 has no home

**Unit A, Protocol epic:** AD-13 says a Token Family is an OpenIddict authorization row, and AD-8 makes OpenIddict Protocol's concern. Protocol owns authorization and token tables and calls Sessions for the anchor. Obeys AD-1.

**Unit B, Sessions epic:** The ER shows `USER_SESSION ||--o{ AUTHORIZATION : anchors`, and AD-13 places revocation on Sessions and Token Families in "one command". The capability map lists Sessions, not Protocol, on the FR-48 row. Sessions owns the authorization table. Obeys AD-1.

**Collision.** If Protocol owns the rows, Sessions has no edge to revoke them, because `PROTO --> SESS` is one-way. FR-48 triggers begin in Identity, which has no edge to Sessions or Protocol at all. Authentication has no edge to Protocol and Management has neither. No module can run AD-13's "one command" as drawn.

**Second collision: what "ends" means.**

- AD-13 says reuse revokes the tokens and "the authorization stays, so a fresh sign-in still works". FR-48 says Token Families "end". One story revokes tokens, another sets the authorization's status to revoked, and these behave differently.
- If an authorization is one family and is anchored to one Session, a fresh sign-in creates a new Session. So it either needs a new authorization, which makes "stays" meaningless, or re-anchors the old row, which merges an attacker's family with the victim's.
- `user_session` absolute lifetime is 7 days and refresh tokens run 30 days by default. FR-24 ties refresh tokens to the Session on logout, but nothing says what happens at Session expiry. One story cuts the refresh token off at 7 days and another keeps it alive to 30. A cleanup job that deletes expired Sessions can also break the reference.
- Client Credentials have no Session, and AD-13 says "every refresh token references ... the Session". That's fine for now, but an authorization's session reference must be nullable or absent for machine clients.

**Fix. Tighten AD-13:**

> **Ownership.** Sessions owns the OpenIddict authorization and token entities and their store adapters (AD-27). Protocol drives OpenIddict through those stores and owns no tables.

> **Family.** Each completed authorization code flow creates one new ad-hoc authorization row, anchored to one `user_session` for its whole life. A row is never re-anchored or reused by a later sign-in. Machine clients have no authorization row.

> **Revocation.** `ISessions.RevokeAccess(context, scope, exceptSessionId)` is the only revocation path, with scope of Authorization, Session, User, Application or Tenant. It sets each affected authorization's status to revoked and revokes its tokens, and ends each affected Session, all in the caller's `CommandContext`. Refresh token reuse uses Authorization scope, which ends no Session. "A fresh sign-in still works" because it creates a new family.

> **Lifetime.** A refresh token can be used only while its Session is live. [DECISION NEEDED: this caps refresh at the Session's absolute lifetime, 7 days by default. The alternative is that a Session's natural expiry leaves its families alive until their own limits, and only explicit end revokes them. PRD §5.2 suggests the second reading, because a 30-day refresh default is otherwise unreachable.] Ended Sessions are retained until their last token expires.

> **Callers.** Identity never calls `RevokeAccess`. The handlers in Authentication, Management and Operations that change credentials do so, and a generated test walks the FR-48 trigger list and asserts each handler calls it.

## High

### ADV-05: Tenant configuration has no owner or table class

**Unit A, Tenancy epic:** AD-7 says "issuer and RP ID are Tenant columns" and AD-4 places the "Tenant registry" in `control`. FR-10 settings, MFA policy and thresholds are simply more Tenant columns on `tenant`. Read by `gk_hosted` without a scope.

**Unit B, Authentication epic:** MFA policy, attack thresholds and the terms URL are Tenant data, so they go in a `tenant_policy` `tenant` table under RLS, read within `TenantScope`.

**Collision.** Host.Hosted reads Tenant configuration from two places under two access rules. With Unit A, one bad lookup returns another Tenant's MFA policy with no RLS to stop it, which is the "one missed filter" AD-3 exists to prevent. The AD-2 ban on writing "policy" tables also doesn't cover Unit A, because `tenant` isn't a policy table by name. AD-14's 60-second cache rule then leaves it open whether MFA policy counts as "public, non-credential data": one story caches it and another doesn't, so FR-10's "takes effect" differs by path. Separately, the capability map splits FR-25 to FR-29 across Authentication and Identity with no owner.

**Fix. Tighten AD-4 and AD-14:**

> `tenant` in `control` holds only what's needed before a scope exists: ID, public ID, status, label, issuer, RP ID and email link base. All other Tenant configuration is in `tenant_settings`, a `tenant` table owned by Tenancy, covering session lifetimes, default audience, error page, MFA policy, allowed Factors, attack thresholds, terms URL and Passkey prompt. Password policy is on the database Connection (Directory). Security configuration is never held in an in-memory cache.

### ADV-06: Application and client secret can live in three stores

**Unit A, Directory epic:** Directory owns `application`, with callback URLs and lifetimes. It stores the secret as Transit ciphertext, which AD-10 allows for "client secrets not stored as hashes", and writes through its own table.

**Unit B, Protocol epic:** AD-8 says OpenIddict tables use custom entities, so `OpenIddictApplications` is the Application. It carries `ClientSecret`, and OpenIddict validates against that hash.

**Unit C, AD-8:** "Client credentials ... are enforced in Gatekeep handlers", so a third reading is that a Gatekeep table is authoritative and OpenIddict validation is bypassed.

**Collision.** The ER has one `APPLICATION`, and the spine has at least two candidates. Rotation updates one store while the token endpoint validates another. FR-12 needs two live secrets during overlap, and OpenIddict's application entity has one `ClientSecret` column, so Unit B can't meet it. AD-10 also leaves hash versus ciphertext open, and AD-24's hash list omits client secrets.

**Fix. Tighten AD-8, AD-10 and AD-24:**

> The OpenIddict application entity is the `application` table, extended with `tenant_id` and owned by Directory. There's no second Application table. Its `ClientSecret` column is always null. Secrets are rows in `client_secret`, owned by Directory, with `application_id`, `not_after`, `revoked_at` and the secret's SHA-256 hash. Secrets are generated by Gatekeep with at least 256 random bits, so they're never stored as ciphertext. A Gatekeep handler in Protocol validates a presented secret against all live rows in constant time. Remove client secrets from the AD-10 ciphertext list and add them to AD-24.

### ADV-07: AD-2 denies by list, so sensitive access stays open to `gk_hosted`

**Unit A, Identity epic:** `gk_hosted` needs sign-up and password writes, so it gets `INSERT, UPDATE` on `user`. AD-2 doesn't forbid it. Admin-only `blocked` is a column on `user`, so a Hosted flaw can unblock an account.

**Unit B, Directory epic:** Roles, `user_role`, `api_grant`, email provider, templates, theme and `tenant_settings` aren't named in AD-2. A migration grants `gk_hosted` broad write access for convenience, or the story for FR-42 "last use" adds a write.

**Collision.** AD-2's purpose is that an internet-facing flaw can't change Tenant security configuration, but its list misses Roles, grants, and the email provider, which can divert every reset email. It also says nothing about control reads, so `gk_hosted` may be able to `SELECT` `admin_session`, `admin_credential` and `tenant_role`.

FR-42 needs last-use data on each client. The natural column is on `application`, written at the token endpoint by `Host.Hosted`, which AD-2 forbids. One story adds the column and fails on grants, and another adds a hole.

Admin writes also collide with Hosted writes: a block by Admin and a concurrent sign-in have no ordering rule.

**Fix. Replace AD-2's write sentence:**

> Grants are an allow-list held per table and per column in the AD-3 registry, and a grant not listed fails the catalogue test. `gk_hosted` may write only `user` self-service columns, User credential tables, `external_identity`, `user_session`, `signin_transaction`, OpenIddict authorization and token entities, attempt counters, `client_usage`, `audit_event` and `audit_detail`, and may only insert into `job`. It has no `SELECT` on `admin*`, `tenant_role` or `deployment_*` tables. `user.blocked_at` and `user.mfa_reset_at` are writable only by `gk_admin` and `gk_worker`, by column grant. `client_usage` is a separate table, so last-use writes never touch `application`. Every sign-in and refresh reads block state from the database inside its command.

### ADV-08: The `job` row carries a Tenant with no boundary

**Unit A, a Hosted handler:** Inserts `job` rows with `tenant_id`. AD-15 says `job` is `control`, so there's no RLS and any `tenant_id` value is accepted, even inside a scope for a different Tenant.

**Unit B, Worker:** AD-4 lists "the job row (AD-15)" as a trusted source of Tenant, so it opens `TenantScope` on whatever the row says.

**Collision.** One Tenant's request can schedule work in another Tenant's scope with a one-line bug, and RLS never sees it because the second scope is legitimate. This is the "one missed filter" problem moved to a table with no filter. Also:

- `gk_hosted` reading `job` sees every Tenant's IDs and ciphertext.
- `gk_worker` needs payload access that `gk_dispatch` doesn't have, and nothing says how.
- PostgreSQL requires `UPDATE` on at least one column for `SELECT ... FOR UPDATE`, so a "see only dispatch columns" grant needs that column stated.

A story could also add a check "any table with `tenant_id` must be class `tenant`" to the catalogue test, because AD-3 gives no criterion, and that would fail `job`, `tenant_host` and `tenant_role`.

**Fix. Tighten AD-3 and AD-15:**

> AD-3 has a third class, `dispatch`, holding only `job`. It has RLS enabled and forced. `gk_hosted` and `gk_admin` may only `INSERT`, under a policy `WITH CHECK (tenant_id = current_setting('gatekeep.tenant_id', true)::uuid)`, and have no `SELECT`. `gk_admin` alone has a second policy allowing `deployment_wide` rows, and `gk_worker` has it for declared follow-on jobs. `gk_dispatch` has `SELECT` on dispatch columns and `UPDATE` on `state`, `claimed_at`, `attempts` and `next_run_at`. `gk_worker` reads `payload` only within a `TenantScope` matching the row.

> A `control` table with a `tenant_id` column is listed by name in the registry with a stated reason. The catalogue test fails any other.

### ADV-09: AD-4's closed list contradicts other ADs

**Unit A, install epic:** AD-26 keeps "bootstrap state in `control`". The Conventions keep a Deployment-level email provider "in Deployment config". Both need tables.

**Unit B, catalogue test story:** AD-4 says `control` tables hold "only" the listed items, and neither item is listed. Admin invites, Admin Recovery Codes and Admin attempt counters aren't listed either. Conforming to AD-4 means rejecting Unit A.

**Same shape for the Deployment Log.** AD-16 says rows go in `audit_event` with one Deployment chain. AD-4 puts the Deployment Log in `control`. AD-3 requires `tenant_id NOT NULL` on `tenant` tables, and the ER shows Tenants recording `AUDIT_EVENT`. One story uses a sentinel Tenant ID, which pollutes RLS. Another adds a nullable `tenant_id`, which breaks AD-3. A third makes a second table, which departs from AD-16's wording. FR-50 also requires writing "to the Log and Deployment Log" and has no rule for two chains in one command.

"Admins and their credentials, sessions and Tenant Roles" also reads as if User sessions might be `control`, against AD-12.

**Fix. Replace AD-4's list:**

> `control` holds exactly the tables listed in the registry with that class. As of v1: `tenant`, `tenant_host`, `admin`, `admin_credential`, `admin_session`, `admin_invite`, `tenant_role`, `deployment_audit_event`, `deployment_audit_detail`, `bootstrap_state`, `deployment_config`. Adding one requires an AD change. The test for inclusion is: the row has no Tenant, or must be read before a Tenant is resolved.

> **AD-16 change.** `audit_event` and `audit_detail` are `tenant` tables. The Deployment chain is in `deployment_audit_event` and `deployment_audit_detail`, with identical structure and triggers. `gk_hosted` has no access to them. A command that writes to both chains does so in one `CommandContext`, through `IAuditAppender`.

### ADV-10: One `CREDENTIAL` entity or many tables

**Unit A, password and recovery (Identity):** Takes the ER at its word: one `credential` table with `kind` and a JSON `data` column for password, Passkey, TOTP, security key and Recovery Code.

**Unit B, Passkey epic:** Fido2 needs a credential ID, public key, sign count, transports and AAGUID, so it creates `user_passkey`. Factors go in `user_factor`. Both follow AD-1 and AD-24.

**Collision.** FR-26 "last Factor or Passkey" has to count across both shapes. FR-25 "different category" needs a method category on each. FR-21 and FR-26 use the same WebAuthn technology for two glossary terms. AD-24 and AD-10 apply different protections per kind, so one generic column makes the canary scan harder. Writes on use also differ: sign count, TOTP last-used step, consumed Recovery Code. Password history (FR-18) has no home.

Social identities have no home. FR-20 requires keying on issuer and subject and FR-30 lists identities, but the ER has neither, and `credential.kind = social` is a conforming reading.

Email uniqueness is unstated too. FR-18 says "per database Connection", which implies several may exist. One story makes `(tenant_id, email)` unique, another `(tenant_id, connection_id, email)`, and FR-20's email conflict rule assumes the first.

**Fix. Add AD-29:**

> **AD-29: User credential model.** Identity owns these separate tables, each `tenant`: `user_password` (one per User, plus `password_history`), `user_webauthn` (one table with `purpose` of `passkey` or `factor`, unique on Tenant and credential ID), `user_totp`, `recovery_code`, and `external_identity`, unique on Tenant, provider issuer and subject, which isn't a credential. Each method exposes a `category` through the Identity contract, and FR-25 and FR-26 rules read only that. A Tenant has exactly one database Connection in v1. `user.email` is unique per Tenant, regardless of Connection.

### ADV-11: Notifications is absent, and Security Alerts have no owner

**Unit A, email epic:** Notifications exists in the Structural Seed but not the diagram, so under AD-1 nothing may call it and it may call nothing. Identity, wanting FR-36 notices, inserts `job` rows and renders templates itself.

**Unit B, Notifications epic:** Owns templates and sending. Host.Worker needs to run its handlers, but `HW --> OPS` only. Host.Admin needs template editing, and `HA --> MGMT` only. Template ownership is shared: the capability map row lists "`apps/hosted-login`, Tenancy, Notifications".

**Alerts.** AD-17 says alerts "derive from audit event types through one code-owned table", without saying when or where. One story adds an alert job in the command's transaction, as AD-5 suggests. Another raises it from sealed events, as AD-17's neighbouring sentence suggests. That gives two alerts or none. AD-11 and AD-15 "raise a Security Alert" from a failed or dead job, with no audit event to derive it from and no role able to write one. An alert job that dies raises an alert for itself.

Email recipients also have a gap: AD-15 says payloads carry "IDs only", but FR-17's notice to an unverified address and an Admin invite may have no ID to resolve.

**Fix. Tighten AD-15 and AD-17, and amend the diagram:**

> Notifications owns `email_provider`, `email_template`, rendering and sending, and is added to the diagram per AD-27. It provides one contract: `INotifications.Queue(context, templateKey, recipient)`. A recipient is a `userId`, `adminInviteId` or `pendingSignupId`, and the address is resolved at send time.

> Operations owns Security Alerts. A sealer step reads newly sealed events against the alert table and enqueues one alert job per event, keyed on event ID, so delivery is idempotent. No command enqueues an alert directly. A job failure writes an `ops.job.dead` event through a `system` Actor, which alerts through the same path. If the job that dies is an alert job, it's retried indefinitely with backoff, and the dead-man's check covers the gap.

### ADV-12: Admin identity has no module

**Unit A, Management epic:** Puts Admin sign-in, `admin`, and sessions in Management, adding its own WebAuthn ceremony because `HA --> MGMT` is the only route. Obeys AD-1.

**Unit B, Tenancy epic:** Owns Admins and Tenant Roles, because AD-20 puts the capability table there and the capability map lists it. Unit C, Sessions, could own `admin_session`, as AD-12 discusses both session kinds, and Identity could own Admin credentials through `MGMT --> IDENT`.

**Collision.** Four modules have a conforming claim. Reusing Authentication's WebAuthn in Host.Admin breaks AD-1, because `HA` has no edge to `AUTHN`. It also risks AD-12's "no code path treats one as the other". Copying it duplicates a sensitive ceremony. AD-14 puts attempt counters in `tenant` tables, and Admins have no Tenant, so Admin sign-in has no rate limit store. FR-5 recovery and FR-2 bootstrap are Cli paths with no module.

**Fix.**

> Add an **Admins** module owning the tables in AD-27. It holds Admin sign-in, re-authentication, invites, FR-2 bootstrap and FR-5 recovery. It depends on Tenancy for the capability table and is called by Management and Cli. WebAuthn verification is a stateless helper in an adapter, shared with Identity by library and carrying no User or Admin types. AD-14 addition: Admin attempt counters live in an `UNLOGGED` `control` table.

### ADV-13: Tenant lifecycle and FR-50 have no reachable orchestrator

**Unit A, Management epic:** Creates a Tenant: a `tenant` row, `tenant_host`, `tenant_role`, Signing Keys, built-in Management API. Reaches Tenancy, Directory and Keys.

**Unit B, Tenant delete (Operations):** Deletion needs Sessions and Keys, which Operations reaches, but not Directory or Identity. Management reaches those but, as drawn, not Sessions or Audit. Tenancy can reach nobody, because everything points at it.

**Collision.** Each epic builds its own partial delete, and no module holds the full list of what a Tenant has. Each new module with Tenant data can be forgotten silently. FR-7's isolation test passes on the tables someone remembered.

FR-50 repeats the problem. Deployment-wide response needs Identity, Sessions and Keys. Management lacks Sessions and Operations lacks Identity, both as drawn. AD-13's "one transaction per Tenant" also means a crash leaves some Tenants revoked and others not, with no resume rule, and nothing says whether it runs in the Admin request or in jobs.

**Fix. Add AD-30:**

> **AD-30: Lifecycle participants.** The Tenancy contract defines `ITenantLifecycleParticipant`, with `OnCreate` and `OnDelete`, and each module holding `tenant` tables implements it. The composition root in each host registers all of them, and an architecture test fails if a module owning a `tenant` table has no implementation. Tenant creation runs all participants in one `CommandContext`. Tenant deletion sets status to deleted and enqueues a Tenant-scoped purge job, which is idempotent and runs participants in turn. Audit data stays until its retention ends.

> FR-50 at Deployment level is a `deployment_wide` job that fans out to one job per Tenant (AD-15), with progress visible in the Admin Dashboard and a re-run that resumes. Each Tenant's job runs in Operations. The Deployment Owner's fresh assertion is checked when the job is created.

### ADV-14: A `RESTRICTIVE`-only policy denies every row

**Unit A, migration story:** Follows AD-3 exactly: one `RESTRICTIVE` policy on each `tenant` table, and no other. In PostgreSQL, a restrictive policy only narrows what permissive policies grant. With no permissive policy, every row is denied and the expression is never reached, so the failing cast never fires.

**Unit B, catalogue test:** Asserts what AD-3 lists, so it passes against Unit A. A fix in Unit C adds `USING (true)` permissive policies, which also passes.

**Collision.** AD-3's "an unscoped query raises an error rather than returning nothing" is silently false under the literal reading. The fix is simple, but it has to be written down so that all tables share one shape and the test can check it.

**Fix. Tighten AD-3:**

> Each `tenant` table has exactly two policies: a `PERMISSIVE` policy `USING (true) WITH CHECK (true)` and the `RESTRICTIVE` policy above. The catalogue test asserts both, and an integration test asserts that an unscoped `SELECT` on each `tenant` table raises an error rather than returning zero rows.

### ADV-15: Transit operations don't fit the transaction

**Unit A, Keys epic, transactional:** AD-11 says a Tenant has "exactly one `current` and one `next` at commit", so the handler creates the Transit key inside the command. If the transaction rolls back, a key is orphaned. Destroying it is a separate action.

**Unit B, Keys epic, job-based:** AD-5 says side effects are jobs, and AD-11 uses a job for destruction, so creation is too. Then a row commits with no Transit key, JWKS has no public key, and FR-38 "promotes the next key at once" can't complete.

**Collision.** Both are readings of AD-5 and AD-11, and they differ on what a `next` row guarantees.

**Related gaps:**

- AD-10 says `Host.Hosted` "can sign and decrypt". TOTP enrolment and queued email links need `encrypt`, and AD-24 needs `hmac`. A policy written from AD-10 fails at enrolment.
- A single per-Tenant Transit key means Hosted's decrypt right covers email provider and other credentials it never uses. AD-10 relies on Hosted not being able to read that ciphertext, which ADV-07 now enforces.
- `IKeyCustody` has no stated home. If it's in Keys' contract, Identity and Directory can't reach it, since neither has an edge to Keys.
- Which host creates keys for the daily rotation is implied only.

**Fix. Tighten AD-10 and AD-11:**

> Transit key creation happens before the transaction, with the key named from a pre-generated `signing_key` ID. The transaction then inserts the row with the public key. A key with no matching row after 24 hours is destroyed by a sweeper job. Destruction stays a post-commit job. A `signing_key` row therefore always has a Transit key, except as reconciled by AD-18.

> `IKeyCustody` and `ISecretVault` are Kernel ports. Policy table: `Host.Hosted` has sign, encrypt, decrypt and hmac on existing keys. `Host.Admin` adds create. `Host.Worker` adds create and delete. No host has export.

### ADV-16: Cli is an unroled fourth host

**Unit A, restore epic:** `gatekeep restore` updates `signing_key`, replays revocations and invalidates Sessions across Tenants. AD-3 says `gk_migrator` "connects only during `gatekeep migrate`", so it must use a runtime role. No runtime role is assigned to Cli, and `audit verify` and `recover-admin` also need a role. AD-2's "each host has its own database role and OpenBao policy" doesn't name it.

**Unit B, upgrade epic:** A migration backfills a `tenant` column as `gk_migrator`. The owner is subject to `FORCE ROW LEVEL SECURITY` and has no `BYPASSRLS`, so the data step fails or requires a scope. One scope holds one Tenant (AD-4), but AD-18 says migrations run in one transaction.

**Collision.** Restore may reuse `gk_worker`, and recovery may reuse `gk_admin`, each with its own OpenBao policy assumption. Cli isn't in the diagram either, so AD-1 gives it no allowed dependencies.

**Fix. Tighten AD-2, AD-3 and AD-18:**

> Cli is a host in the diagram, with `gk_cli` as its role and its own OpenBao policy. `gk_cli` connects only while a named Cli command runs, and each command's grants are listed. Work on `tenant` tables uses `TenantScope`, per Tenant.

> Migrations run schema changes as `gk_migrator`. A data change to `tenant` tables loops over Tenants, calling `set_config` within the same transaction once per Tenant. The migration template provides this. The role never gets `BYPASSRLS`.

### ADV-17: Failure events roll back with the command

**Unit A, password step (Authentication):** A wrong password is a failed command, so the handler throws and the transaction rolls back, taking its audit row and attempt counter with it. AD-5's "an event for a change that rolled back" is honoured.

**Unit B, FR-40 and FR-28:** Logs must cover "failures", and each lockout writes to the Log. Counters must survive a new challenge. FR-13's code replay and AD-9's cross-Tenant rejection must record an event for something that was refused, and AD-13's reuse revocation must commit while the request fails.

**Collision.** Results depend on whether each handler models refusal as an exception or a committed outcome. SM-2's "production signal" is lost whenever a handler throws.

"Every state change" is also undefined. `user_session` idle touches, attempt counters, sign counts, seal columns and job state are all state changes. One story audits each one and another none, and FR-47 identifier rotation falls between.

**Fix. Tighten AD-5 and AD-14:**

> A refused request is a successful command with a refused outcome. It commits its audit event and any counter change, and the handler returns a result that the route maps to an error. Exceptions are for faults, and a fault rolls back. An architecture test forbids throwing authentication refusal types.

> The following are operational writes, exempt from audit but not from `TenantScope`: session idle touch, attempt counters, WebAuthn sign count, TOTP last-used step, `client_usage`, job state and seal columns. Anything else is a command. New exemptions need an AD change.

### ADV-18: Authentication and Protocol have no agreed handoff

**Unit A, Protocol epic:** AD-8 says "passthrough into the Authentication module", so the authorize endpoint calls Authentication and receives a principal to sign in. That needs an edge `PROTO --> AUTHN`, which doesn't exist.

**Unit B, Authentication epic:** Finishes MFA and directly issues the code, or calls into Protocol. That needs `AUTHN --> PROTO`, which doesn't exist.

**Collision.** Host.Hosted can stitch them together only if the shape is agreed, and AD-12 doesn't say who owns `signin_transaction` or who creates it. The Application binding exists at authorize time in Protocol, and the steps are recorded in Authentication. The FR-14 reuse check must run on return, and `prompt=login` and `max_age` must be honoured on re-entry. The Account Portal is in Hosted but no module is named for it, including how it authenticates.

**Fix. Tighten AD-8 and AD-12:**

> Sessions owns `user_session` and `signin_transaction`. Protocol and Authentication never call each other. The authorize endpoint validates the request, then either accepts a live Session that passes FR-14, `prompt` and `max_age`, or creates a `signin_transaction` holding the request's parameters and redirects to Hosted Login. Authentication advances the transaction. On completion it creates the Session, marks the transaction complete and redirects back to the authorize endpoint, which is re-run from the stored parameters and issues the code. Authorization logic runs only in Protocol, and step logic runs only in Authentication.

> The Account Portal is part of Authentication's surface. It uses the Session cookie directly, not an OIDC client registration.

## Medium

### ADV-19: The sealer role doesn't exist, and erasure conflicts with retention

**Unit A, audit sealer:** AD-16 refers to "the sealer role", which isn't in AD-3's list. The story adds `gk_sealer`, or grants `gk_worker` the seal columns, which then applies to every job body.

**Unit B, FR-49 erasure:** AD-16 says erasure acts on `audit_detail`, yet "runtime roles have `INSERT` and `SELECT`" and "only the retention job may delete". Erasure then either deletes (against the rule) or lacks grants.

**Also:** two sealer jobs on one chain under SKIP LOCKED can fork it. A sealer that selects by ID order rather than by unsealed state skips a late-committing transaction, leaving a permanent unsealed row.

**Fix. Tighten AD-3 and AD-16:**

> Add `gk_sealer` to the runtime roles, used only by sealing and retention job types. It has `UPDATE` on seal columns once, and `DELETE` on sealed ranges. `gk_admin` has `DELETE` on `audit_detail` only, through the FR-49 handler. The sealer takes `pg_advisory_xact_lock` on the chain ID and selects rows where `seq IS NULL`, ordered by ID.

### ADV-20: Cross-module foreign keys are undecided

**Unit A, Sessions:** AD-3 asks for composite foreign keys, so `user_session.user_id` references `user`, with `ON DELETE CASCADE`.

**Unit B, Identity:** AD-1 keeps modules apart, so it holds only a bare `user_id`. User delete runs through handlers.

**Collision.** A cascade is a state change with no handler or audit event, which conflicts with AD-5. Without foreign keys, nothing stops dangling references. `user_session` also records "the Connection used", and deleting that Connection is undecided.

**Fix. Tighten AD-1:**

> A cross-module reference within `tenant` tables is a composite foreign key with `ON DELETE RESTRICT`, so the owning handler must clear dependants first. No `CASCADE` crosses a module. Deleted Connections stay as tombstones while any Session names them. A User deletion runs an `IUserLifecycleParticipant` set in the same way as AD-30.

### ADV-21: Deployment-wide jobs have two conforming shapes

**Unit A, daily key rotation:** One `deployment_wide` job loops over Tenants in-process, one `TenantScope` each. Obeys AD-4 and AD-15.

**Unit B, retention:** One `deployment_wide` job enqueues one Tenant job each.

**Collision.** Unit A's retry reruns all Tenants, and a failing Tenant holds up the others, which also weakens FR-37's "doesn't affect other Tenants". The two also behave differently under the dead state, and it's undefined whether a job for a deleted Tenant may run.

**Fix. Tighten AD-15:**

> A `deployment_wide` job body never opens a `TenantScope`. It may read `control` tables and enqueue one Tenant job per Tenant. Tenant jobs for a deleted Tenant run only if their job type is declared `purge`. Otherwise they end as cancelled.

### ADV-22: `[FreshAssertion]` and machine authorization

**Unit A, route story:** Puts `[FreshAssertion]` on `PATCH /applications/{id}` because Prod callback URLs are in the list, which blocks every machine call, including in Dev Tenants and for unrelated fields.

**Unit B, handler story:** AD-5 says authorization runs in the handler, so the check is conditional on Prod and on field changed, in code. A route-registry test can't then see it.

Machine principals also hold Management API Permissions, while AD-20 handlers declare capabilities and the table encodes only Tenant Roles, so scope-to-capability mapping can be repeated in each handler.

**Fix. Tighten AD-19 and AD-20:**

> `[FreshAssertion]` is a handler declaration, with an optional predicate on the command and Tenant. Callback URL changes are a separate command from other Application edits. The route registry derives its report from handler declarations. The AD-20 table has a fourth column mapping each capability to the Management API Permission that grants it, or to none.

### ADV-23: Public ID shape is undecided

**Unit A, Protocol:** AD-9 says `sub` is the "opaque User ID", so it uses the UUID.

**Unit B, Directory and Management:** The Conventions say public IDs are prefixed, so `sub` is `usr_...`.

**Collision.** `sub` can never change once issued. The same applies to `{tenantId}` in AD-19 and `{tenantPublicId}` in AD-9: does the artifact prefix include `ten_`? Is a `client_id` the `app_` ID?

**Fix. Tighten the Identifiers convention:**

> Public IDs are `{prefix}_{base32 of UUIDv7}`. `sub` is the `usr_` form, `client_id` the `app_` form, and `{tenantId}` and `{tenantPublicId}` the `ten_` form. Internal UUIDs appear only in the database and in audit references. Note that a UUIDv7 exposes its creation time. If that matters, use a separate random public ID column.

### ADV-24: OpenIddict's built-in caching and pruning

**Unit A, Protocol:** Uses OpenIddict's defaults, including its entity cache, and enables its Quartz pruning.

**Unit B, Operations:** AD-14 requires in-memory caches to be Tenant-keyed, public and under 60 seconds. AD-15 says all background work uses explicit Tenants.

**Collision.** OpenIddict's stores can cache entities in memory by client ID and token ID, without knowing about Tenants. Its pruning job runs with no Tenant and would fail under RLS. Both are off the spike's stated scope, so the defaults may ship. Its default indexes on `ClientId` and reference ID are also global, while Tenants need composite uniqueness.

**Fix. Tighten AD-8:**

> OpenIddict entity caching and its Quartz integration are disabled. Token pruning is a Tenant job. Its unique indexes are replaced with composite indexes including `tenant_id`. The AD-8 spike proves each of these.

## Attacked and held

These resisted construction, so no change is needed:

- **Tenant-local GUC:** a pooled connection reverts `gatekeep.tenant_id` to empty at transaction end, and the empty cast still raises, so the failing-cast design holds once ADV-14 is fixed.
- **Signing Key state:** one authoritative row and no cache leaves no room for two conforming versions, apart from creation timing (ADV-15).
- **Cookie separation:** `__Host-` names, no `Domain`, and separate Admin cookies leave nothing to disagree about.
- **Custom-domain seam (AD-7):** `kind` plus Tenant columns for issuer and RP ID composes cleanly.
- **Token format:** RS256, `at+jwt` and reference tokens are fully decided, apart from the ID shape in ADV-23.
- **Design tokens (AD-22):** one source, generated outputs and a CI diff leave nothing to fork.
- **Frontend and API client:** AD-19, AD-21 and AD-23 force one contract and one generated client.

## AD-8 spike additions

Confirm these against OpenIddict 7.7.2 and PostgreSQL 18.6, since this review didn't run them:

1. `ClientSecret` can stay null for confidential clients while a custom handler validates `client_secret` rows (ADV-06).
2. Revoked authorization status rejects its tokens at refresh, with no extra handler (ADV-04).
3. Entity caching can be fully disabled, and no other in-process cache holds Tenant data (ADV-24).
4. All OpenIddict entities and stores can run on the `CommandContext` connection and transaction (ADV-02). If they can't, AD-28 needs an explicit exception and AD-13's one-transaction rule must change.
5. Reference token IDs can take the `{tenantPublicId}.{random}` form (AD-9).
6. An unscoped `SELECT` raises on a table with the two policies in ADV-14.

## Decisions needed from Esm

1. **Refresh token and Session lifetime (ADV-04):** does a Session's natural expiry end its Token Families, or do they run to their own limits? PRD §5.2's 30-day refresh default suggests the latter.
2. **One database Connection per Tenant (ADV-10):** FR-18's wording allows several. I've proposed one for v1.
3. **New module (ADV-12):** an Admins module is the cleanest fix, but it adds a twelfth module.
