---
status: final
stepsCompleted:
  - step-01-validate-prerequisites
  - step-02-design-epics
  - step-03-create-stories
  - step-04-final-validation
inputDocuments:
  - _bmad-output/planning-artifacts/prds/prd-gatekeep-2026-11-01/prd.md
  - _bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md
  - _bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/DESIGN.md
  - _bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md
  - _bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/design-consistency.md
  - design/SCREENS.md
epicOrderSource: reconstructed
---

# gatekeep - Epic Breakdown

## Overview

This document provides the complete epic and story breakdown for gatekeep, decomposing the requirements from the PRD, UX Design if it exists, and Architecture requirements into implementable stories.

**Epic order.** `docs/epic-plan.md` does not exist in this repo. Esm chose to reconstruct the 18-epic order. The first seven epics are fixed by Esm's brief, in this order: foundation, OIDC core, applications, database login, users/RBAC, MFA, logs. The other eleven are derived from PRD §7.4 and the architecture.

**Story rules from Esm's brief.** Every story references its FR ids, names the screen(s) it implements from `design/SCREENS.md` and the `.dc.html` file they're in, fits one build session, and includes security acceptance criteria where relevant (tenant isolation, rate limits, no secrets in logs).

**Reading the requirements.** This inventory is a working index. The testable consequences under each FR in the PRD remain the authority, and stories must cite them. Terms follow PRD §3 exactly.

## Requirements Inventory

### Functional Requirements

FR-1: The Operator can install a Deployment from a released version using documented steps. It needs no cloud-managed service, the docs cover wildcard DNS and TLS, and it refuses to start with missing or default secrets.
FR-2: The Operator can create the first Admin through a one-time, server-only token. No Tenant traffic is served until bootstrap completes, the first Admin is a Deployment Owner who must register two WebAuthn credentials before making changes, and the path can't be reused.
FR-3: The Operator can upgrade from the previous minor release or its latest patch. Upgrade refuses without a backup under 24 hours old, a failure stays recoverable through FR-4, and valid Sessions and tokens survive unless a release names a security reason.
FR-4: The Operator can back up and restore a Deployment, including onto clean hardware. A backup without the Master Key reveals no secret, restore reports the lost-change window, invalidates earlier Sessions and refresh tokens by default, and re-applies later revocations from the off-server record.
FR-5: The Operator can regain Admin access after losing all credentials, using infrastructure-level access. It issues a single-use, short-lived enrolment, doesn't disable WebAuthn, ends that Admin's sessions, writes to the Deployment Log and raises a Security Alert.
FR-6: The Operator can see service status, email provider status and rate-limit usage, through a health signal for external monitoring and a per-Tenant view in the Admin Dashboard.
FR-7: A Deployment Owner can create and delete Tenants, and a Tenant Owner can change the Dev, Staging or Prod label. Tenant Subdomains are permanent, never reused and never reserved names; unknown subdomains get a generic rejection; deletion needs typed confirmation and re-authentication, destroys Signing Keys, withdraws the JWKS and keeps security Logs for 90 days.
FR-8: The system keeps each Tenant's data, keys and Sessions isolated, enforced below application logic. A cross-Tenant suite covers every endpoint and artifact type on every release. Jobs, caches and counters are Tenant-keyed, cookies can't cross subdomains, and email links come from the stored issuer.
FR-9: An Admin can switch between Tenants they hold a Tenant Role in. The current Tenant and environment badge show on every page, Prod is visibly distinct, and an action whose target mismatches the page's Tenant is rejected.
FR-10: A Tenant Owner or Editor can configure display name, support contact, session lifetimes, default audience and error page, within §5.2 and written to the Log. A custom error page receives only an error code and trace ID.
FR-11: A Tenant Owner or Editor can create, edit and delete single-page, regular web, native and machine-to-machine Applications. URLs match exactly, with the RFC 8252 loopback exception; a custom URI scheme in Prod needs acknowledgement; deletion revokes refresh tokens and grants.
FR-12: A Tenant Owner can create, rotate and revoke a client secret. It's shown once, stored only hashed or under the Master Key, and the old secret overlaps within §5.2 with an "end now" option.
FR-13: A Tenant Owner or Editor can enable Authorization Code with PKCE, Refresh Token and Client Credentials per Application. S256 PKCE is mandatory, codes are single-use and bound, replay revokes issued tokens, responses include `iss`, an unregistered `redirect_uri` never redirects, and Implicit and ROPC don't exist.
FR-14: A Tenant Owner or Editor can enable or disable each Connection per Application. Hosted Login shows only enabled Connections, and a Session is reused only if established through a Connection enabled for that Application.
FR-15: A Tenant Owner or Editor can set ID, access and refresh token lifetimes within §5.2. Refresh tokens always rotate, reuse revokes the whole Token Family and writes to the Log, and absolute and inactivity lifetimes both apply.
FR-16: A Tenant Owner or Editor can create APIs, define Permissions, set offline access and RBAC per API, and authorize machine-to-machine Applications. Permissions are re-evaluated at every refresh, API identifiers are immutable and unique, and each Tenant lists the built-in Management API.
FR-17: A User can sign up, verify their email and sign in with email and password. Login is identifier-first and doesn't vary by account; no Session exists for an unverified email unless a Dev Tenant turns this off; sign-up with an existing address changes nothing, sends a notice and looks identical; sign-up can be disabled; terms acceptance is recorded.
FR-18: A Tenant Owner can set password strength, history, dictionary and personal-data rules per database Connection, never below the §5.2 floor.
FR-19: A User can reset a forgotten password by email. The confirmation is identical for known and unknown addresses, links are single-use and invalidated by newer resets, and a reset never creates a Session.
FR-20: A User can sign in with Google, GitHub or Microsoft. Credentials are per Tenant, identity keys on provider issuer and subject, nothing links automatically, a verified email is required, and a conflict creates no account and shows a neutral error.
FR-21: A User can create and use a Passkey. User verification is required, no attestation is requested, discovery needs no account lookup, and a Passkey is bound to the exact Tenant Subdomain.
FR-22: A User can sign in with an email one-time code. Codes are single-use, a new code doesn't reset attempts, and a Tenant chooses whether the Connection creates accounts.
FR-23: Applications authenticate Users through OIDC and OAuth 2.0. Each Tenant publishes discovery and JWKS and offers token, userinfo and revocation endpoints; Gatekeep follows RFC 9700; passes Basic OP, Config OP and RP-Initiated Logout OP on every release; uses `at+jwt` and one fixed asymmetric algorithm; and honours `prompt=login`, `max_age`, `auth_time` and `amr`.
FR-24: A User can end their Session and Applications can trigger logout. Logout ends the Session and its bound refresh tokens, and redirects only to registered URLs with `id_token_hint` or equivalent.
FR-25: A Tenant Owner can set MFA to Never or Always and choose allowed Factors. Under Always nothing completes without a second factor from a different category; a user-verified Passkey satisfies it alone; email codes never count; email flows can't bypass a Factor; lowering needs re-authentication; a test matrix covers every Connection and recovery path.
FR-26: A User can enrol and use TOTP and WebAuthn security key Factors. TOTP codes can't be reused in their window, and under Always removing the last method is refused.
FR-27: A User receives Recovery Codes at first enrolment. They're shown once, single-use and non-reversible; regeneration invalidates the old set; a code replaces only the Factor step, or the sign-in for a Passkey-only User, followed by mandatory re-enrolment; email recovery under Never waits 24 hours.
FR-28: The system limits repeated failed sign-ins per account and per source, separately per step, surviving a new challenge. Thresholds are configurable within §5.2 and can't be turned off; the system backs off rather than locks; a failed-attempt limit doesn't block a valid Passkey; blocked and locked states appear only after valid credentials.
FR-29: The system checks passwords against a local breach dataset at sign-up, reset, change and sign-in. A password never leaves in recoverable form; a breached password is rejected, and at sign-in needs a verified Factor or out-of-band reset before any Session. Detections write to the Log.
FR-30: An Admin can search Users by field and view profile, identities, last login, Sessions, Factors and history. No credential-equivalent value appears.
FR-31: A Tenant Owner or Editor can create, block, unblock, delete, send verification to, reset the Factors and Passkeys of, and revoke the Sessions and refresh tokens of a User. Deletion needs typed confirmation and every action is logged with the acting Admin.
FR-32: A Tenant Owner or Editor can create Roles, assign Permissions and assign Roles to Users. Effective Permissions appear in access tokens with RBAC on, and removals apply to any later token.
FR-33: Users can complete every v1 flow through the §7.2 Hosted Login screens. Every error state has a screen with only a code and trace ID, a strict CSP applies across surfaces, framing is denied, `Referrer-Policy: no-referrer` is set, and deferred controls don't appear.
FR-34: A Tenant Owner or Editor can set logo, colours, font and corner radius, previewing login, signup, MFA, reset and error before publishing. Values use typed allowlists, nothing injects script, logos are sanitized, contrast failures are refused, and Prod changes are logged.
FR-35: A User can edit their profile, manage password, Passkeys and Factors, review and end Sessions, and delete their account, across Profile, Security and Sessions tabs. Sensitive changes need re-proof by the strongest enrolled method. An email change needs verification, and the old address can reverse it for 72 hours.
FR-36: A Tenant Owner can configure an email provider, and an Owner or Editor can edit five templates. Provider changes need re-authentication and raise an alert; test sends report SPF, DKIM and DMARC; templates can't change link destinations, load remote content or read other Tenants; email is rate limited per recipient; security notifications can't be disabled.
FR-37: The system rotates Signing Keys automatically, and a Tenant Owner can rotate at any time. A next key is always published for at least the JWKS cache limit, previous keys verify until tokens expire, then private material is destroyed, and no other Tenant is affected.
FR-38: A Tenant Owner can revoke a Signing Key after re-authentication. It leaves the JWKS at once, its private material is destroyed, next is promoted automatically, Session revocation is offered, and a test proves a forged token is rejected within the limit.
FR-39: A Deployment Owner can invite and remove Admins and give them Tenant Roles, following the capability matrix enforced server-side. Invites are single-use and email-bound, removal ends sessions and lists Management API clients, and the last Deployment Owner can't be lost.
FR-40: An Admin can filter Logs and open raw detail subject to FR-39, and a Deployment Owner can do the same for the Deployment Log. Event type codes are a public contract, logs hold no credential-equivalent value (canary test), can't be changed through any surface, are hash-chained with a verification command, and are copied off-server in near real time.
FR-41: A Tenant Owner or Editor can export a Tenant's configuration as a readable file containing no secrets or private keys.
FR-42: An authorized machine-to-machine Application can perform Tenant-scoped actions through a versioned Management API, excluding Admin management and every fresh-assertion action. Only a re-authenticated Tenant Owner grants access; each grant raises an alert; clients can't escalate; tokens are bound to one Tenant; clients are listed with last use.
FR-43: Developers can follow quickstarts for React, Next.js, Node, .NET and Python and read a reference for every public API. Quickstarts complete UJ-1 within 30 minutes, never pre-fill a secret, validate signature, `iss`, `aud`, `exp` and a fixed algorithm, and a negative test pack runs on every release.
FR-44: An Admin can reach every v1 feature from the sidebar, light or dark, on desktop and tablet. Deferred features don't appear in any form, and landing depends on whether Tenants exist.
FR-45: The Deployment sends Security Alerts through an independent channel for the twelve listed events, with delivery tested as part of SM-5.
FR-46: Admins sign in with WebAuthn only, stored apart from every Tenant's Users, with two credentials or one plus an offline Recovery Code. The Admin Dashboard has its own hostname on a VPN or private network, and the listed actions need a fresh WebAuthn assertion within §5.2.
FR-47: The system protects every sign-in against fixation, step skipping and cross-site attacks. Session identifiers change at each privilege step, transactions are bound and short-lived, steps need a server-side record, and login CSRF plus `state`, `nonce` and PKCE apply.
FR-48: The system ends existing access when a credential changes. All Sessions and Token Families end on the listed triggers, the acting Session continues for self-service changes, and quickstarts state the residual access token window.
FR-49: A Tenant Owner can export or erase a User's personal data. Logs identify people by internal reference, so erasure keeps the event record and hash chain intact.
FR-50: A Tenant Owner can revoke every Session and refresh token, force password resets and TOTP re-enrolment, and send a security notice. A Deployment Owner can do this across Tenants and revoke all Signing Keys. Both need re-authentication and write to the Log and Deployment Log.

### NonFunctional Requirements

NFR-1: A written threat model covers the product before authentication work begins, and is updated when a feature changes a trust boundary.
NFR-2: Passwords use a modern memory-hard hash whose parameters can be raised without resetting Users.
NFR-3: Secrets and private keys are encrypted under the Master Key with Tenant-specific keys. The Master Key rotates without resetting Users, an offline escrow copy is stored apart from backups and rehearsed, refresh tokens, Session identifiers and one-time values are stored hashed, and credential-equivalent values never reach Logs, errors, debug output or exports.
NFR-4: All external traffic uses TLS. Cookies use the `__Host-` prefix. Every state-changing request needs a Session-bound CSRF token and an exact-host Origin check. `SameSite` alone isn't accepted.
NFR-5: Authorization happens server-side on every request. Hiding something in the Admin Dashboard isn't a control.
NFR-6: Sign-in, sign-up, reset, email code, verification resend, token, Factor and recovery endpoints are rate limited per Tenant and per source. Forwarded addresses are trusted only from a configured proxy. Hashing has a Deployment-wide budget with per-Tenant shares. A failed sign-in spike tightens limits and raises an alert.
NFR-7: Dependencies are pinned and scanned on every release, and a known critical vulnerability blocks release.
NFR-8: Esm completes an OWASP ASVS 5.0 Level 2 self-assessment before real Users sign in, with a stored result per requirement. All critical and high findings are fixed.
NFR-9: A tested runbook covers vulnerability intake, a 7-day critical fix target, User notification within 72 hours of a confirmed breach, Tenant key compromise (UJ-3) and full server compromise (UJ-6).
NFR-10: Prod Tenants target 99.5% monthly availability, including planned upgrades.
NFR-11: Sign-in API requests complete under 500ms at p95 at 20 sign-ins per second, excluding deliberate hashing cost and third-party providers.
NFR-12: Expected load is under 10,000 Users across the Deployment at launch.
NFR-13: Restore takes under 1 hour with no more than 24 hours of data lost, and backups are stored off the server.
NFR-14: Each Tenant meets User export and erasure requests through FR-49.
NFR-15: Logs have the §5.2 retention, fixed in v1, and the floor can't be lowered.
NFR-16: Hosted Login meets WCAG 2.2 AA.
NFR-17: Hosted Login works on current desktop and mobile browsers. The Admin Dashboard is desktop-first and responsive to tablet.
NFR-18: Interfaces follow the Design System: tokens not raw values, one jade signal colour, status colours for state only, mono type with copy controls for identifiers. Fonts and assets are bundled, with no third-party runtime requests.
NFR-19: v1 ships in English, with text separable for later translation.
NFR-20: Across sign-in, sign-up, reset, email code and verification, response content, status, next step and timing don't differ for known and unknown identifiers within a stated tolerance. The only exception is the FR-20 social conflict.
NFR-21: Tenant Subdomains sit under a dedicated zone. The application process can't read the certificate's private key, DNS credentials are limited to validation records, CAA is set, Certificate Transparency monitoring raises alerts, and emergency certificate replacement is rehearsed.

**§5.2 Security Limits** bind every story that touches a lifetime, threshold or code. They live as constants in one Kernel file, and stories cite the PRD table rather than restating values.

### Additional Requirements

**Greenfield setup (Epic 1, Story 1).** The architecture names no starter template. The first story scaffolds the AD-23 monorepo from nothing, using the Structural Seed layout: `Gatekeep.slnx`, Central Package Management, pnpm workspaces and no Turborepo or Nx.

**Spikes that block other work**

- AR-1: Linux custody spike (AD-10, Open Items) proves `LoadCredentialEncrypted`, PCR 7, static seal, Raft, socket access from containers, OpenBao host login and quotas. It blocks Foundation. The fallback is a root-only key file on a separate volume, recorded as a weaker control.
- AR-2: OpenIddict per-Tenant spike (AD-8, Open Items) proves options replacement, `BaseUri`, signing through Transit including the synchronous provider, token protection keys, custom stores, one ad-hoc authorization per flow, and a refused refresh committing its revocation. It blocks Core sign-in. The fallback is per-Tenant options through a keyed provider, which amends AD-8.
- AR-3: The threat model (NFR-1) is a Foundation story built from AD-2's trust zones, finished before authentication work starts.

**Structure and dependency rules**

- AR-4: Modular monolith with twelve modules: Tenancy, Admins, Identity, Authentication, Sessions, Directory, Protocol, Keys, Audit, Notifications, Management, Operations. Three hosts (`Host.Hosted`, `Host.Admin`, `Host.Worker`) plus `Gatekeep.Cli`.
- AR-5: AD-1 edge list in `tests/Architecture` generates both the diagram and the architecture tests. An unlisted dependency fails the build. Cross-module foreign keys are composite or to `tenant`, with `ON DELETE RESTRICT`, and cross-module deletion is an Operation.
- AR-6: AD-27 table ownership is one owner per table. Each module with `tenant` tables exposes a Tenant purge in its contract (AD-30).
- AR-7: Kernel holds `TenantScope`, `CommandContext`, `Actor`, `IAuditAppender`, `IJobEnqueuer`, `IKeyCustody`, `IRateLimiter` and `IWebAuthnVerifier` (AD-28). `Secret<T>` and `RevealOnce<T>` also live in Kernel (AD-24).

**Tenant isolation**

- AR-8: AD-3 table registry, `ENABLE` and `FORCE` row-level security, permissive plus `RESTRICTIVE` policies, composite foreign keys, and a catalogue test over `pg_class`, `pg_policies`, `pg_roles` and `information_schema`.
- AR-9: Runtime roles `gk_hosted`, `gk_admin`, `gk_worker`, `gk_dispatch`, `gk_sealer`, `gk_retention`, `gk_cli`, plus `gk_migrator` for migrations only. None owns a table except `gk_migrator`, and none has `BYPASSRLS` or superuser. Grants are an allow-list per table and column.
- AR-10: `TenantScope` uses `set_config(..., true)` in a transaction. Session-level `SET` and PgBouncer are forbidden (AD-4).
- AR-11: Tenant resolution is an exact match on the `tenant_host` control table. Issuer, RP ID and email base come from the stored record. Unknown or deleted hosts get one fixed 404 (AD-6). `tenant_host` carries the `kind` seam for v2 custom domains (AD-7).
- AR-12: The cross-Tenant suite is driven by route and artifact registries, so a new endpoint or artifact type fails until covered (AD-25).

**Trust zones and surfaces**

- AR-13: `Host.Admin` listens only on the private network. Admin routes aren't registered in `Host.Hosted`, and Hosted Login routes aren't registered in `Host.Admin`. A release test proves from inside its container that `Host.Hosted` has no route to `Host.Admin` (AD-2).
- AR-14: API surfaces per AD-19: `/login/api/*` and `/account/api/*` are private; `/api/v1/tenants/{tenantId}/*` is one route set with two auth schemes; `/api/v1/deployment/*` has no machine access. The OpenAPI document is committed and diffed in CI. `packages/api-client` is generated (AD-23).
- AR-15: One capability table in the Admins contract encodes FR-39, with `MachineAllowed` and `FreshAssertion` on each capability. Every fresh-assertion capability is machine-denied. A generated test denies every role and machine principal everything outside the table (AD-20).
- AR-16: Management API tokens are issued only by `/api/v1/tenants/{tenantId}/oauth/token` on `Host.Admin`, signed by a per-Tenant `management` key that's never published (AD-33).

**Mutation, jobs and operations**

- AR-17: Every state change is a command in one `CommandContext` writing state, audit event and jobs together. Refused requests with durable effects use `FailureContext`. MediatR isn't used. Listed operational writes are exempt from audit only (AD-5).
- AR-18: Postgres-backed jobs: `job` is `control`, `job_payload` is `tenant`, claimed with `SKIP LOCKED`, woken by `LISTEN/NOTIFY`. A registry lists types and allowed enqueuers. Handlers are idempotent, and credential payloads are Transit ciphertext erased on completion (AD-15). No Redis, broker or second data store (AD-14).
- AR-19: Long-running Operations with `202`, `operation` and `operation_step`, one active per scope and type, and Retry for failed steps. Covers Tenant creation and deletion, FR-50 actions, security notices, test sends and connection tests (AD-30).

**Keys, tokens and credentials**

- AR-20: OpenBao Transit runs as a native systemd service with non-exportable keys, per-purpose names and per-host policies. Signing happens in OpenBao. The Master Key is the barrier key, held through `systemd-creds` sealed to TPM2, with offline escrow. Disks use LUKS (AD-10).
- AR-21: Signing Key states and the JWKS follow AD-11. RS256 with RSA-3072 is a Deployment-wide constant. Access tokens are `at+jwt`, codes and refresh tokens are references, and opaque artifacts are `{tenantPublicId}.{random}` (AD-9).
- AR-22: OpenIddict is wrapped per AD-8: per-Tenant options, inert global credentials, custom stores owned by Directory and Sessions, Gatekeep client authentication, entity caching off and pruning off.
- AR-23: `ISessions.RevokeAccess(context, scope, exceptSessionId)` is the only revocation path. A generated test walks the FR-48 trigger list (AD-13).
- AR-24: Sessions and sign-in transactions per AD-12: `user_session` and `signin_transaction` rows, `__Host-gk_session` and `__Host-gk_txn` cookies, 30-minute sliding transactions, and a separate Admin session table and `SameSite=Strict` cookie.
- AR-25: Credential handling per AD-24 and AD-29: Argon2id with dummy hash for unknown identifiers, SHA-256 for high-entropy values, HMAC under Transit for low-entropy values, typed credential tables and no generic table, and a scrubbing log sink.
- AR-26: Argon2id passes through a Deployment-wide bounded semaphore with per-Tenant shares and a reserved floor. Counters live in `UNLOGGED` tables behind `IRateLimiter`, with a coarse in-memory per-source limit in `Host.Hosted` (AD-14).

**Audit, alerts and recovery**

- AR-27: Audit writes only through `IAuditAppender`. One chain per Tenant plus a Deployment chain, with personal data in `audit_detail` outside the hash, a sealer under `gk_sealer`, RFC 8785 canonical form, `{domain}.{object}.{action}` event codes and `gatekeep audit verify` (AD-16).
- AR-28: Off-server record: sealed events, revocations and chain heads copied within 60 seconds to an Object Lock bucket, signed by a Deployment key. Alerts derive from event types through one table in Notifications. An external dead-man's check carries chain positions and oldest ages (AD-17).
- AR-29: Backup with pgBackRest plus OpenBao snapshot and a manifest. `gatekeep restore` follows the four AD-18 steps. `gatekeep rekey` serves UJ-6, `gatekeep upgrade` refuses without a recent manifest, and migrations are forward-only.
- AR-30: Bootstrap and recovery per AD-31: `gatekeep init` writes a 15-minute token, `gatekeep recover-admin` confirms the alert and off-server record before issuing enrolment. Admin invites use `deployment_email_provider` through a Deployment-wide job.

**Delivery and release**

- AR-31: Hosted Login and the Account Portal are one React bundle with a 150 kB compressed budget. The first response embeds the step as JSON. Every response is a `StepResponse`. All responses are `no-store`, and CSP follows the exact AD-21 string on all three surfaces.
- AR-32: Themes are versioned rows, draft or published, with server-generated same-origin CSS. Logos live in `tenant_asset` up to 1 MB. SVG uploads are rasterized by a job and never served as SVG (AD-21).
- AR-33: Release gates per AD-25: architecture tests, catalogue test, cross-Tenant suite, FR-25 matrix, FR-48 walk, canary scan, negative token pack, OpenAPI diff, dependency scan and OpenID conformance plans. Images are signed, shipped with an SBOM and deployed by digest. `GATEKEEP_CONFORMANCE_TENANT` is refused alongside any Prod Tenant.
- AR-34: Deployment per AD-26: one Linux host, LUKS volumes, Docker Compose for everything but OpenBao, Caddy with public and Admin sites, a validation-only DNS credential, a default-deny firewall, one `EgressHttp` handler that blocks private addresses, and code-owned social endpoints.
- AR-35: Operations envelope per AD-32: runbooks in `docs/runbooks`, SM-5 rehearsals recorded there, external monitoring, and `service_status` written by `Host.Worker`.
- AR-36: Conventions apply to every story: UUIDv7 internally with prefixed public IDs, RFC 9457 errors with a stable `code` and `traceId`, cursor pagination at 50, UTC `timestamptz`, message catalogues, §5.2 constants in one Kernel file, and each new table's registry entry, policies and grants in the same migration.

**Architecture overrides of EXPERIENCE.md**

- AR-37: The Account Portal authenticates by Session cookie and isn't an OIDC client (AD-12 overrides EXPERIENCE line 38).
- AR-38: JavaScript is required on Hosted Login, with fixed `<noscript>` text (AD-21 overrides the EXPERIENCE JavaScript-off assumption).
- AR-39: Audit event codes are `{domain}.{object}.{action}`, replacing the short sample codes in the exports (AD-16).

**Open items that touch stories**

- AR-40: V-2 is resolved. Esm chose the single-use enrolment link. An Admin reset of a Passkey-only User under Always issues a link shown once through `RevealOnce` and passed on outside the product (PRD FR-27, FR-31, §5.2).
- AR-43: Each Tenant has a hidden system Application, used only to bind Portal sign-in transactions (AD-12).
- AR-44: `deployment_email_provider` is configured on a Deployment email provider screen (EXPERIENCE), which Admin invites depend on.
- AR-41: Conformance behaviour for PKCE and logout is unconfirmed. Default is the AD-25 conformance Tenant, with any deviation recorded per FR-23.
- AR-42: TPM2 and Linux on the host are unconfirmed. Default follows AR-1.

### UX Design Requirements

**Design system foundation**

UX-DR1: `packages/design-tokens` generates `tokens.css`, a TypeScript map and a C# constants file from the `DESIGN.md` frontmatter: all 24 colour tokens in light and dark, plus the `knob` and `code-*` extensions. Tokens are emitted against a scope selector, and CI fails if output differs from `DESIGN.md`.
UX-DR2: Bundle Geist and Geist Mono in `packages/ui`, serve them from the Deployment, and implement the seven-step type scale plus the field-label, helper, table-head, badge, button and Hosted extensions. No runtime font request. Minimum 11px text, glyphs excepted.
UX-DR3: Implement the 4px spacing scale, layout metrics (30, 26 and 36px controls; 38px rows; 32px table heads; 44px two-line rows; 48px top bar; 440px drawer; 460px modal; 384px Hosted card), the radius scale, one shadow, the scrim and the single `gkIn` motion. Off-scale export values snap to scale (AD-4 to AD-7, HL-6, HL-9, HL-10).
UX-DR4: Raw hex fails lint in `packages/ui`, with the QR code as the only documented exception. `packages/ui` has `@gatekeep/ui/hosted` and `@gatekeep/ui/admin` entry points, and a surface attribute selects sizing rather than a second component.

**Shared components**

UX-DR5: Buttons: primary, secondary, ghost, outlined destructive, disabled and small. One primary per page. Pending keeps width and name with `aria-busy` and `aria-disabled` and ignores clicks. Destructive always leads to a modal. The filled warn button doesn't exist.
UX-DR6: Input, select and textarea with field label, helper, focus and error states. Validate on blur, then on change once in error. Link errors with `aria-describedby` and set `aria-invalid`. Identifier fields use the code type. Treat control heights as `min-height`.
UX-DR7: Selection controls: toggle (changes form state only), 15px checkbox and radio with 24px hit areas, and segmented with arrow-key movement.
UX-DR8: `focus-ring` on every interactive element through `:focus-visible`, outside the control, kept in error and forced-colours modes, never clipped. No export has focus styles, so this is built new (design-consistency AD-1, HL-3).
UX-DR9: Badges: status with 6px dot (Active, Pending, Blocked), protocol, outlined Draft, and mono for environment and Log codes. Prod uses `bad`, Staging `warn`, Dev `info`.
UX-DR10: Tabs with a 2px `tx` underline, URL addressable, using the ARIA tab pattern, prompting on unsaved changes.
UX-DR11: Data table with real table semantics, right-aligned mono numerics, row click to detail, copy controls that don't open the row, and 50-row paging.
UX-DR12: Field search on Users (email, user ID, Connection, status) and Logs (event type, User, Application, outcome, time range): a field select plus a value, kept in the URL.
UX-DR13: Code block with filename and Copy, line-numbered JSON viewer, and Copy control showing "Copied" for 2 seconds through `role="status"`.
UX-DR14: Empty state with one line and one action, hidden for roles that can't act. Skeleton rows appear after 300ms and hold height. Spinner sits left of the button label.
UX-DR15: Toast (Admin 2.4 seconds; Portal `role="status"` until next action; never an error or copyable value) and persistent status banner.
UX-DR16: Modal one level deep, with Esc and Cancel, focus trap, and focus returning to the trigger or next row. Typed confirmation disables Confirm until an exact match. One-time reveal disables Close until "I've copied this" is ticked.
UX-DR17: Re-authentication gate on every FR-46 fresh-assertion action. If the last assertion is over 5 minutes old, the WebAuthn sheet appears on confirm, with failure shown inside the same modal and no second modal.
UX-DR18: Drawer for Log events, with code badge, summary rows and raw JSON, and Viewers seeing no raw detail. Menu for the Tenant switcher, avatar and User actions, with arrow keys and Esc.

**Admin Dashboard shell**

UX-DR19: Shell: 48px top bar with brand, flat Tenant switcher, help opening API reference, theme toggle and avatar menu (Your credentials, Sign out). No global search or alerts bell. The window never scrolls.
UX-DR20: Sidebar with exactly the nine v1 groups in EXPERIENCE, shrinking to an icon rail below 1100px. The Deployment group shows only to Deployment Owners. Implements the five label changes and landing rules.
UX-DR21: Reusable Section blocks: stat tile, settings row, usage bar, and the RBAC matrix as a table with `ok` ticks.
UX-DR22: Admin global states: page loading, action pending, save succeeded and failed, field invalid, no results, forbidden action ("You have view-only access to this Tenant.", "Tenant Owner only"), forbidden page, not found, Tenant deleted mid-session, Tenant mismatch, session expired with values kept, rate limited and service failure.
UX-DR23: Role Capabilities table is driven by the capabilities endpoint (AD-20), with every role able to read all Tenant pages except the Deployment group, and hiding never acting as the control.

**Hosted Login components**

UX-DR24: `hosted-card` composition in order: 42px logo tile, heading in theme font, optional subtitle, content, one primary action, quiet text link. 384px wide, full width less 16px on phones, on `bg`, scrolling rather than clipping.
UX-DR25: Hosted button, secondary, social button (up to three, "Continue with {provider}") and input at 44px, with `tx3` control edges. Password field toggle named "Show password" or "Hide password", re-masking on submit, with paste and managers never blocked.
UX-DR26: One `code-input` for email and TOTP codes, with `inputmode="numeric"`, `autocomplete="one-time-code"`, paste accepted, spaces stripped and never auto-submitting. One `code-input-recovery` with `XXXX-XXXX`, normalized hyphens and spaces, and `autocomplete="off"`.
UX-DR27: Identifier chip that wraps and never truncates, with Edit keeping the email. Method row as a whole-row button showing only enrolled or allowed methods.
UX-DR28: Strength meter with four segments, rules from the Connection's policy delivered as step data, a distinct "not met" glyph and text, a debounced `role="status"` label, and the breach check on the server at submit only.
UX-DR29: Recovery code block as a real list in two columns, with Copy, Download as `{tenant}-recovery-codes.txt`, confirmation checkbox, and Back never showing the codes again. Status icon decorative with the heading carrying meaning.
UX-DR30: QR code as dark modules on `#fff` in every theme, `role="img"` with the specified label, and a labelled setup key with Copy returning it unspaced. One reviewed encoder rendering SVG.
UX-DR31: Resend link uses `aria-disabled` for 30 seconds so focus stays, with a countdown outside live regions, and doesn't reset the attempt count. The Passkey prompt is the browser's own sheet, and cancelling returns to the card with no error.
UX-DR32: Login content varies by enabled Connection per the EXPERIENCE Login table, never by identifier. "Use a recovery code" always shows. A reusable Session skips Login unless `prompt=login` or `max_age` requires it.
UX-DR33: Transaction timing: 30-minute sliding lifetime, a `role="alertdialog"` warning 2 minutes before expiry with "Keep going", and restart at Login with the email kept. Account locked shows an absolute retry time.
UX-DR34: Hosted Login follows `prefers-color-scheme` with no toggle. The export draws no dark theme, so dark is the same components on `-dark` tokens. All Hosted text uses `tx2`, with `tx3` only for disabled controls and control edges.

**Tenant theming**

UX-DR35: Tenant theme contract limited to logo, primary colour, optional dark primary, one bundled-allowlist font and corner radius. Implements the DESIGN.md `on-ac`, `ac-sf` and `ac-tx` derivation and publish validation, naming the failing pair and scheme, in both schemes.

**Account Portal**

UX-DR36: Two-column card with a 220px rail, 1100px maximum, with the rail becoming tabs below 768px. Tabs are Profile, Security and Sessions, using Skeleton loading and Admin-sized toast, banner and modal in the Hosted theme.

**Accessibility**

UX-DR37: Hosted focus precedence: first invalid field, Login's email field on first load, otherwise the card heading. `<title>` is "{step heading} – {Tenant}" with "Error:" after a failed submit. `html` has `lang="en"`, with one `main` landmark. `role="alert"` only for errors injected after load.
UX-DR38: Hosted WCAG 2.2 specifics: email carries across steps (3.3.7), paste and managers work on every credential field (3.3.8), controls at least 44px with 24px inline hit areas, unique names on repeated actions, 200% zoom and 320px reflow without horizontal scroll, and reduced motion removes `gkIn`.
UX-DR39: Admin accessibility floor: every control operable by keyboard with `focus-ring`, native elements replacing clickable `div`s, real table semantics, ARIA tabs and focus-trapped modals (design-consistency AD-2).

**Responsive**

UX-DR40: Admin: full sidebar at 1100px and up; icon rail with tables scrolling inside their card and drawer at most 50% from 768 to 1099px; below 768px unsupported. Hosted: centred card, with the card filling the width below 768px.

**Content, validation and scope**

UX-DR41: Voice and copy rules: neutral failures, Tenant name rather than "Gatekeep" on Hosted Login, what happened then what to do, real units in Admin copy, destructive confirmations stating token impact, and all strings in message catalogues.
UX-DR42: Implement the EXPERIENCE Validation Rules for Hosted Login and Admin Dashboard, including `autocomplete` values, with every rule on the server and browser checks as feedback only.
UX-DR43: Apply the Hosted Login Design Delta row by row, including removing company SSO and Apple buttons and replacing the k-anonymity sentence.
UX-DR44: Apply the Admin Dashboard Design Delta row by row, including removing secret Reveal, HS256, Region, Impersonate and rotation toggles, and replacing sample domains with Tenant Subdomains.
UX-DR45: Banned everywhere in v1: drag and drop, infinite scroll, modals over modals, and any control for a deferred feature.
UX-DR46: Spec-only screens have no export and compose from existing components only, with no new visual language. They are named in the EXPERIENCE state tables and Screen-to-PRD Map.

### FR Coverage Map

FR-1: Epic 1 - Secure Deployment and Admin access
FR-2: Epic 1 - Secure Deployment and Admin access
FR-3: Epic 12 - Backup, restore and upgrade
FR-4: Epic 12 - Backup, restore and upgrade
FR-5: Epic 1 - Secure Deployment and Admin access
FR-6: Epic 11 - Security Alerts and health
FR-7: Epic 1 - Secure Deployment and Admin access
FR-8: Epic 1 - Secure Deployment and Admin access
FR-9: Epic 1 - Secure Deployment and Admin access
FR-10: Epic 8 - Admin team and Tenant settings
FR-11: Epic 3 - Applications and APIs
FR-12: Epic 3 - Applications and APIs
FR-13: Epic 3 - Applications and APIs (enforcement in Epic 2)
FR-14: Epic 4 - Database login
FR-15: Epic 3 - Applications and APIs
FR-16: Epic 3 - Applications and APIs
FR-17: Epic 4 - Database login
FR-18: Epic 4 - Database login
FR-19: Epic 4 - Database login
FR-20: Epic 14 - Social and email code sign-in
FR-21: Epic 6 - Passkeys, MFA and recovery
FR-22: Epic 14 - Social and email code sign-in
FR-23: Epic 2 - OIDC core (conformance from Epic 4, final pass in Epic 18)
FR-24: Epic 4 - Database login
FR-25: Epic 6 - Passkeys, MFA and recovery
FR-26: Epic 6 - Passkeys, MFA and recovery
FR-27: Epic 6 - Passkeys, MFA and recovery
FR-28: Epic 10 - Attack protection
FR-29: Epic 10 - Attack protection
FR-30: Epic 5 - Users and RBAC
FR-31: Epic 5 - Users and RBAC (Factor reset in Epic 6)
FR-32: Epic 5 - Users and RBAC
FR-33: Epic 4 - Database login (screens added by later epics)
FR-34: Epic 15 - Branding and email
FR-35: Epic 16 - Account Portal
FR-36: Epic 15 - Branding and email (sending, provider and default templates in Epic 4)
FR-37: Epic 9 - Signing Key operations (automatic lifecycle in Epic 2)
FR-38: Epic 9 - Signing Key operations
FR-39: Epic 8 - Admin team and Tenant settings
FR-40: Epic 7 - Logs and audit evidence
FR-41: Epic 8 - Admin team and Tenant settings
FR-42: Epic 17 - Management API and developer docs
FR-43: Epic 17 - Management API and developer docs
FR-44: Epic 1 - Secure Deployment and Admin access (pages added by later epics)
FR-45: Epic 11 - Security Alerts and health
FR-46: Epic 1 - Secure Deployment and Admin access
FR-47: Epic 4 - Database login
FR-48: Epic 4 - Database login (triggers added by later epics, walk confirmed in Epic 18)
FR-49: Epic 5 - Users and RBAC
FR-50: Epic 13 - Compromise response (sign-in step in Epic 10)

## Epic List

### Epic 1: Secure Deployment and Admin access

Esm installs Gatekeep, bootstraps with WebAuthn, creates isolated Tenants and uses the Admin shell.
**FRs covered:** FR-1, FR-2, FR-5, FR-7, FR-8, FR-9, FR-44, FR-46

### Epic 2: OIDC core

Each Tenant publishes its own issuer, discovery document and JWKS, and issues signed tokens.
**FRs covered:** FR-23

### Epic 3: Applications and APIs

Esm registers clients and APIs, and a machine client gets a scoped token (UJ-5).
**FRs covered:** FR-11, FR-12, FR-13, FR-15, FR-16

### Epic 4: Database login

A User signs up, verifies, signs in, resets a password and logs out through Hosted Login (core of UJ-1).
**FRs covered:** FR-14, FR-17, FR-18, FR-19, FR-24, FR-33, FR-47, FR-48

### Epic 5: Users and RBAC

Admins find and administer Users, assign Roles and export or erase data.
**FRs covered:** FR-30, FR-31, FR-32, FR-49

### Epic 6: Passkeys, MFA and recovery

Users enrol Passkeys and Factors and recover with codes (UJ-2).
**FRs covered:** FR-21, FR-25, FR-26, FR-27

### Epic 7: Logs and audit evidence

Admins search tamper-evident Logs, and evidence is copied off the server.
**FRs covered:** FR-40

### Epic 8: Admin team and Tenant settings

Esm invites Admins with Tenant Roles, configures Tenants and exports configuration.
**FRs covered:** FR-10, FR-39, FR-41

### Epic 9: Signing Key operations

A Tenant Owner rotates or revokes keys with no manual follow-up (UJ-3).
**FRs covered:** FR-37, FR-38

### Epic 10: Attack protection

Sign-in resists guessing, floods and breached passwords.
**FRs covered:** FR-28, FR-29

### Epic 11: Security Alerts and health

Esm hears about trouble outside the Deployment and can see its status.
**FRs covered:** FR-6, FR-45

### Epic 12: Backup, restore and upgrade

Esm upgrades safely and recovers onto clean hardware (UJ-4).
**FRs covered:** FR-3, FR-4

### Epic 13: Compromise response

Esm ends all access in one Tenant or every Tenant, following tested runbooks (UJ-6).
**FRs covered:** FR-50

### Epic 14: Social and email code sign-in

Users sign in with Google, GitHub, Microsoft or an emailed code.
**FRs covered:** FR-20, FR-22

### Epic 15: Branding and email

Hosted Login and email carry each Tenant's identity.
**FRs covered:** FR-34, FR-36

### Epic 16: Account Portal

Users manage their own profile, credentials and Sessions.
**FRs covered:** FR-35

### Epic 17: Management API and developer docs

Esm automates Tenant tasks and adds sign-in from a quickstart in 30 minutes.
**FRs covered:** FR-42, FR-43

### Epic 18: Production readiness and cutover

v1 passes its gates and the first production app moves over.
**FRs covered:** None led here. Closes SM-1, SM-3, SM-4, SM-5 and NFR-8

**Sequence notes**

- Epic 2 tests the authorization code flow with a test-only sign-in stand-in in `tests/` that never ships.
- The audit write path starts in Epic 1. Epic 7 adds search, verification and off-server copying.
- Earlier epics write audit events, and Epic 11 connects them to the alert table.
- Passkeys sit inside Epic 6 because MFA rules, Recovery Codes and Factor choice depend on them.
- Shared foundations are built where first needed: Hosted components, the alert and off-server adapters, and `IRateLimiter` in Epic 1; Sessions, transactions and `RevokeAccess` in Epic 2; the email code primitive in Epic 6. Release image signing moves to Epic 12, before upgrade.
- Departures from PRD §7.4, approved by Esm: Logs search follows MFA; RBAC comes before MFA; Signing Key operations follow Logs; the Admin team moves up to Epic 8; conformance runs from Epic 4 and closes in Epic 18. Nothing reaches real Users before Epic 18.

**Story fields.** Each story adds **Requirements** and **Screens** lines to the template, as Esm's brief requires, and **Creates tables** where it's the first to need a table. Where a story covers only what exists so far, unbuilt cases sit on a code-owned pending list that a later named story closes. Screens are named as in `design/SCREENS.md`, with the export and its locator. "Spec only" means the screen is in EXPERIENCE.md and in no export, so it's composed from existing components (UX-DR46). "None" means no UI.

## Epic 1: Secure Deployment and Admin access

Esm installs Gatekeep, bootstraps with WebAuthn, creates isolated Tenants and uses the Admin shell.

### Story 1.1: Scaffold the monorepo and enforce module boundaries

As the Operator,
I want the repository, build and CI set up with the module dependency rules enforced,
So that every later story lands in the right place and an illegal dependency can't merge.

**Requirements:** AR-4, AR-5, AR-36; AD-1, AD-23; NFR-7
**Screens:** None

**Acceptance Criteria:**

**Given** a clean clone
**When** the build runs
**Then** `Gatekeep.slnx`, the three hosts, `Gatekeep.Cli`, `Gatekeep.Kernel`, twelve module projects and the pnpm workspaces from the Structural Seed all compile at the Stack versions, using Central Package Management

**Given** the AD-1 edge list in `tests/Architecture`
**When** a project references a module with no listed edge
**Then** the build fails
**And** the documented diagram is generated from the same edge list

**Given** a pull request
**When** CI runs
**Then** dependencies install from lockfiles with install scripts disabled
**And** a known critical vulnerability fails the build

### Story 1.2: Prove key custody on the target host

As the Operator,
I want the Linux custody design proven on real hardware,
So that the Master Key design is settled before anything depends on it.

**Requirements:** AR-1, AR-42; AD-10; NFR-3
**Screens:** None

**Acceptance Criteria:**

**Given** the rehearsal host
**When** the spike runs
**Then** it records a pass or fail for `LoadCredentialEncrypted`, PCR 7, static seal, Raft storage, socket access from containers, OpenBao host login and per-host quotas

**Given** a host with no TPM2 or a failed proof
**When** the spike ends
**Then** the recorded fallback is a root-only key file on a separate volume, marked as a weaker control, and AD-10 is amended

**Given** the spike's commands and output
**When** they're committed to `docs/`
**Then** they contain no key material, token or unseal value

### Story 1.3: Write the threat model

As the Operator,
I want a written threat model before authentication work starts,
So that each authentication story is built against named threats.

**Requirements:** NFR-1, AR-3; AD-2
**Screens:** None

**Acceptance Criteria:**

**Given** AD-2's trust zones
**When** the threat model is written in `docs/`
**Then** it covers each zone, trust boundary and credential-equivalent value, and the PRD §9 risks

**Given** a later feature that changes a trust boundary
**When** its story is reviewed
**Then** the document's update rule requires the threat model to change in the same work

### Story 1.4: Enforce Tenant isolation in the database

As the Operator,
I want the Tenant boundary enforced below application logic,
So that one missed filter can't expose another Tenant's data.

**Requirements:** FR-8, AR-8, AR-9, AR-10; AD-3, AD-4, AD-28; SM-2, AD-18
**Screens:** None
**Creates tables:** `tenant`, `tenant_host`, `tenant_settings`

**Acceptance Criteria:**

**Given** migrations creating `tenant` and `tenant_host` as `control` tables and `tenant_settings` as a `tenant` table
**When** the AD-3 catalogue test runs
**Then** it asserts registry entry, class, owner, grants, `ENABLE` and `FORCE` row-level security, both policies, and that no runtime role owns a table or holds `BYPASSRLS` or superuser

**Given** a new table missing from the registry
**When** CI runs
**Then** the build fails

**Given** a query on a `tenant` table with no `TenantScope`
**When** it runs
**Then** it raises an error rather than returning nothing

**Given** rows in two Tenants
**When** a scoped role queries inside one `TenantScope`
**Then** it sees its own row and no row from the other Tenant

**Given** `TenantScope` and `CommandContext` in Kernel
**When** a contract method changes state
**Then** it requires a `CommandContext` and can't open a scope or commit
**And** `set_config` is transaction-local and session-level `SET` is absent from the code

**Given** new schema changes
**When** `gatekeep migrate` runs
**Then** it connects as `gk_migrator` only, applies forward-only migrations, and scopes any data migration one Tenant at a time

### Story 1.5: Write an audit event with every state change

As an Admin,
I want every state change to record its audit event atomically,
So that no change is unrecorded and no event describes a change that rolled back.

**Requirements:** FR-40, AR-7, AR-17, AR-27; AD-5, AD-16, AD-28
**Screens:** None
**Creates tables:** `audit_event`, `audit_detail`, `deployment_audit_event`, `deployment_audit_detail`

**Acceptance Criteria:**

**Given** a command in a `CommandContext`
**When** it commits
**Then** its state and `audit_event` row commit together
**And** when it rolls back, neither exists

**Given** a Deployment-level command
**When** it commits
**Then** the event lands in `deployment_audit_event`, with personal data only in `deployment_audit_detail`

**Given** a refused request that must leave a durable effect
**When** it fails
**Then** a `FailureContext` commits that effect after the rollback

**Given** a role other than `gk_sealer` or `gk_retention`
**When** it tries to update or delete an `audit_event` row
**Then** the database refuses it

**Given** an event envelope
**When** it's written
**Then** it carries a `{domain}.{object}.{action}` code and internal references only
**And** a `Secret<T>` value has no serializable form, so it can't enter the envelope or an operational log

### Story 1.6: Scrub logs and scan for canaries

As the Operator,
I want secrets scrubbed from logs and a scan that proves it,
So that no credential-equivalent value reaches a log from the first story on.

**Requirements:** NFR-3, AR-25; AD-24
**Screens:** None

**Acceptance Criteria:**

**Given** `Secret<T>` values and operational logging
**When** a value reaches the logging pipeline
**Then** the AD-24 scrubbing sink removes it

**Given** a first canary scanner
**When** it runs in CI over logs and Audit events
**Then** a planted raw value fails the build
**And** Story 7.8 extends it to every flow

### Story 1.7: Hold keys in OpenBao behind `IKeyCustody`

As the Operator,
I want secrets and keys held in OpenBao with separate powers per host,
So that a stolen disk, a backup or a compromised public host can't yield private keys.

**Requirements:** AR-20; AD-10; NFR-3; FR-4 (backup secrecy)
**Screens:** None

**Acceptance Criteria:**

**Given** the Story 1.2 result
**When** OpenBao starts as a systemd service
**Then** Transit is reachable only over the private socket and its barrier key isn't in a container, environment file or backup

**Given** the per-host policies in `deploy/`
**When** a policy test runs for each host and the Cli
**Then** each allowed operation succeeds, each forbidden one is refused, and no policy can export a key

**Given** a Tenant-scoped encryption
**When** ciphertext from Tenant A is decrypted with Tenant B's `associated_data`
**Then** it fails

**Given** any code needing a key
**When** the architecture tests run
**Then** access goes only through `IKeyCustody`

**Given** `Host.Worker`
**When** it signs an off-server record with the Deployment key
**Then** the signature succeeds, and `Host.Hosted` and `Host.Admin` are refused

**Given** the Master Key and recovery keys
**When** the first setup follows `docs/`
**Then** an offline escrow copy is stored apart from backups, and none of it appears in `docs/`, a log or a backup

### Story 1.8: Run Tenant-scoped jobs

As the Operator,
I want background work to run with an explicit Tenant,
So that no job runs unscoped or loses its payload.

**Requirements:** FR-8, AR-18; AD-15
**Screens:** None
**Creates tables:** `job`, `job_payload`

**Acceptance Criteria:**

**Given** the `job` table
**When** a row has neither or both of `tenant_id` and `deployment_wide`
**Then** the check constraint refuses it
**And** a trigger refuses a `tenant_id` that differs from the transaction's scope

**Given** a role not listed for a job type in the registry
**When** it enqueues that type
**Then** the trigger refuses it

**Given** a job that fails repeatedly
**When** its retries are exhausted
**Then** it stops as `dead` and writes `operations.job.dead` through a `system` Actor

**Given** a payload holding a credential-equivalent value
**When** the job finishes
**Then** the Transit ciphertext has been erased
**And** other payloads carry IDs only

**Given** the code-owned schedule in `Host.Worker`
**When** a recurring job is due
**Then** it runs through the same job path

**Given** a `deployment_wide` job type with no recorded review in the registry
**When** CI runs
**Then** the build fails

### Story 1.9: Track long-running Operations

As the Operator,
I want work spanning modules or Tenants tracked step by step,
So that a partial failure is visible and can be retried.

**Requirements:** AR-19; AD-30
**Screens:** None
**Creates tables:** `operation`, `operation_step`

**Acceptance Criteria:**

**Given** an active Operation for a scope and type
**When** a second one starts
**Then** it's refused, and Retry repeats only failed steps

**Given** a started Operation
**When** the Operations contract responds
**Then** it returns an `operation` resource with one `operation_step` per Tenant or stage
**And** no personal data is stored in a step

### Story 1.10: Run the stack under Compose with safe secrets

As the Operator,
I want Gatekeep running from locally built images until Story 12.5 signs releases,
So that it needs no cloud service and refuses unsafe settings.

**Requirements:** FR-1, AR-20, AR-34; AD-10, AD-26
**Screens:** None

**Acceptance Criteria:**

**Given** a clean Linux host and the install docs
**When** the Operator follows them
**Then** the stack runs under Compose with OpenBao native, and each host exposes `/healthz` on a private port

**Given** a required secret that's missing or left at a default
**When** a host starts
**Then** it refuses to start and logs the secret's name, never a value

**Given** the stack on a host with no cloud egress
**When** it starts
**Then** every `/healthz` passes

**Given** the OpenBao and PostgreSQL data
**When** the install is checked
**Then** both sit on LUKS volumes, and a test fails on an unencrypted mount

### Story 1.11: Route traffic through Caddy and default-deny networks

As the Operator,
I want only intended traffic to reach each host,
So that the Admin surface is never exposed publicly.

**Requirements:** FR-1, NFR-4, NFR-21, AR-34; AD-2, AD-26
**Screens:** None

**Acceptance Criteria:**

**Given** the Caddy configuration
**When** a request names a host outside the zone or the Admin hostname
**Then** it's refused, and Admin traffic is served only on the VPN interface

**Given** the host firewall and Compose networks
**When** a test runs from inside `Host.Hosted`
**Then** `Host.Admin` is unreachable

**Given** any public host
**When** plain HTTP is attempted
**Then** no content or cookie is served

**Given** certificate private keys
**When** file permissions are tested
**Then** only Caddy can read them

### Story 1.12: Document installation

As the Operator,
I want complete install documentation,
So that I can install using the documentation alone.

**Requirements:** FR-1, NFR-21; AD-26
**Screens:** None

**Acceptance Criteria:**

**Given** the install docs
**When** they're reviewed
**Then** they cover wildcard DNS and TLS, the dedicated zone, CAA records and a validation-only DNS credential

### Story 1.13: Generate design tokens and bundle fonts

As a developer,
I want one token source generating every surface's values,
So that the interface can't drift from DESIGN.md.

**Requirements:** NFR-18, UX-DR1, UX-DR2, UX-DR3, UX-DR4, UX-DR8; AD-22
**Screens:** Surface, Border, Text, Accent, Status, Code and Elevation tokens; Type scale; Spacing scale; Radius scale; Layout metrics in `design/Gatekeep Design System.dc.html` (`:root` L14–15, "Type scale" L58, "Space, radius, elevation" L70). DESIGN.md wins over the export.

**Acceptance Criteria:**

**Given** the DESIGN.md frontmatter
**When** the generator runs
**Then** it emits `tokens.css`, a TypeScript map and C# constants for all 24 colour tokens in both schemes, plus extensions, against a scope selector

**Given** generated output that differs from DESIGN.md
**When** CI runs
**Then** the build fails

**Given** a raw hex value in `packages/ui` other than the QR exception
**When** lint runs
**Then** it fails

**Given** a built surface
**When** it loads in a browser test
**Then** Geist and Geist Mono load from the Deployment and no third-party request occurs

**Given** any interactive element
**When** it receives keyboard focus
**Then** `focus-ring` shows outside the control

### Story 1.14: Build shared form and action components

As a developer,
I want accessible form controls in `packages/ui`, sized by a surface attribute,
So that Admin and Hosted screens share one component.

**Requirements:** NFR-18, UX-DR5, UX-DR6, UX-DR7, UX-DR39, UX-DR41
**Screens:** Buttons (L97), Form fields (L109), Selection controls (L116) in `design/Gatekeep Design System.dc.html`

**Acceptance Criteria:**

**Given** the button variants
**When** rendered
**Then** primary, secondary, ghost, outlined destructive, disabled and small exist, and no filled warn button exists

**Given** a pending button
**When** it's clicked again
**Then** it ignores the click and keeps its width and accessible name, with `aria-busy` and `aria-disabled` set

**Given** an invalid input
**When** it blurs
**Then** the helper shows the error, linked by `aria-describedby`, with `aria-invalid` set, and it revalidates on change

**Given** toggle, checkbox, radio and segmented controls
**When** driven by keyboard only
**Then** each works as EXPERIENCE specifies, and segmented responds to arrow keys

**Given** the shared controls
**When** dependencies are reviewed
**Then** Hosted-reachable controls use no third-party headless primitive, and one component serves both surfaces

### Story 1.15: Build data display components

As a developer,
I want tables, tabs, code blocks and empty states,
So that every Admin page shows data the same way.

**Requirements:** NFR-18, UX-DR9, UX-DR10, UX-DR11, UX-DR13, UX-DR14, UX-DR21, UX-DR39
**Screens:** Status badges (L123), Tabs (L136), Data table (L139), Code blocks (L146), Empty state (L158) in `Gatekeep Design System.dc.html`; Section blocks (`b.isStats` L1159) in `Gatekeep Admin.dc.html`

**Acceptance Criteria:**

**Given** a table
**When** rendered
**Then** it uses real table semantics, 38px rows, 32px heads and 50-row paging, and a Copy control in a row doesn't open the row

**Given** tabs
**When** one is selected
**Then** the URL changes, the ARIA tab pattern applies, and unsaved changes prompt first

**Given** an empty list or slow page
**When** it renders
**Then** `empty-state` has one action, and skeleton rows appear after 300ms and hold height

### Story 1.16: Build overlay and feedback components

As a developer,
I want modal, toast and banner components,
So that every Admin page confirms actions the same way.

**Requirements:** NFR-18, UX-DR15, UX-DR16, UX-DR39, UX-DR45
**Screens:** Toast and inline banner (L162), Modal (L169) in `Gatekeep Design System.dc.html`; Confirmation modal (L1233), Toast (L1243) in `Gatekeep Admin.dc.html`

**Acceptance Criteria:**

**Given** a modal
**When** it opens
**Then** focus is trapped, Esc and Cancel close it, focus returns to the trigger or next row, and no second modal can open over it

**Given** typed confirmation
**When** the value doesn't match exactly
**Then** Confirm stays disabled

**Given** a one-time reveal
**When** "I've copied this" isn't ticked
**Then** Close stays disabled, and the value is never rendered again after closing

**Given** a toast
**When** it's used
**Then** it never carries an error or a value to copy

### Story 1.17: Build the drawer and menu

As a developer,
I want drawer and menu components,
So that detail panels and menus behave the same everywhere.

**Requirements:** NFR-18, UX-DR18, UX-DR39
**Screens:** Logs · Event drawer (`logOpen` L1131) in `Gatekeep Admin.dc.html`, as a component only

**Acceptance Criteria:**

**Given** a drawer
**When** Esc is pressed
**Then** it closes and focus returns

**Given** a menu
**When** it is driven by keyboard
**Then** Enter opens it, arrow keys move, and Esc closes it

### Story 1.18: Build the Hosted component entry and screen package

As a developer,
I want `@gatekeep/ui/hosted` and `packages/hosted-screens`,
So that pre-session Admin screens and Hosted Login share one set of cards.

**Requirements:** NFR-16, NFR-18, UX-DR24, UX-DR25; AD-22
**Screens:** Generic error (L409), Theme variants (L34) in `Gatekeep Hosted Login.dc.html`

**Acceptance Criteria:**

**Given** the Hosted entry
**When** it builds
**Then** its only third-party runtime dependency is the reviewed QR encoder

**Given** `hosted-card`, Hosted button, input and error components
**When** they render
**Then** they follow DESIGN.md order and sizing, and control heights are `min-height`

**Given** `packages/hosted-screens`
**When** a screen is added
**Then** it is a props-only component usable by the Hosted app, the Admin pre-session pages and the theme preview

**Given** Hosted text
**When** contrast is tested in both schemes
**Then** all text uses `tx2`, and `tx3` appears only on disabled controls and control edges

**Given** a Hosted `role="alertdialog"`
**When** it opens
**Then** focus moves into it and it uses no third-party dependency

### Story 1.19: Initialise a Deployment

As the Operator,
I want `gatekeep init` to prepare a new Deployment,
So that bootstrap starts from a server-only token.

**Requirements:** FR-2, AR-30; AD-10, AD-31
**Screens:** None
**Creates tables:** `bootstrap_state`

**Acceptance Criteria:**

**Given** `gatekeep init`
**When** it runs
**Then** it writes a one-time 256-bit token to a root-only file and stores only its SHA-256 with a 15-minute expiry

**Given** `gatekeep init`
**When** it completes
**Then** the Deployment `email`, `payload`, `hmac` and off-server signing keys exist

### Story 1.20: Add the rate limiter and Admin CSP

As a developer,
I want the rate limiter and Admin bundle headers,
So that the first Admin routes start safe.

**Requirements:** NFR-6, AR-14, AR-31; AD-14, AD-19, AD-21
**Screens:** None
**Creates tables:** `admin_attempt`

**Acceptance Criteria:**

**Given** `IRateLimiter` in Kernel
**When** a test caller exceeds a limit
**Then** attempts are counted in `admin_attempt` through the port

**Given** the Admin bundle
**When** it is served
**Then** it sends the AD-21 CSP, `Referrer-Policy: no-referrer` and denies framing, with no third-party request

### Story 1.21: Claim bootstrap and create the first Admin

As the Operator,
I want to claim a new Deployment with a server-only token and two WebAuthn credentials,
So that nobody who arrives first can take it.

**Requirements:** FR-2, NFR-5; AD-31
**Screens:** Bootstrap (Spec only; `hosted-card` in the default theme)
**Creates tables:** `admin`, `admin_session`

**Acceptance Criteria:**

**Given** a valid token at Bootstrap
**When** it's consumed
**Then** the first Admin is created as Deployment Owner in one command, and `bootstrap.admin.created` is written to the Deployment Log

**Given** a wrong or expired token
**When** it's submitted
**Then** Generic error shows, and attempts are rate limited through `admin_attempt`

**Given** a completed bootstrap
**When** the route is requested
**Then** it returns the same 404 as an unknown path

**Given** bootstrap logs and events
**When** the canary scan runs
**Then** the token appears in none of them

**Given** the first Admin
**When** they are created
**Then** a setup-restricted `admin_session` starts with a CSRF token, and it allows only credential registration

**Given** incomplete bootstrap
**When** any Tenant host is requested
**Then** the fixed 404 is returned, because no Tenant exists

**Given** a consumed token and incomplete credential setup
**When** it is submitted again
**Then** the route returns the same 404, and no second Admin is created

**Given** the first API routes
**When** CI runs
**Then** the OpenAPI document is committed and diffed, and `packages/api-client` is generated from it

### Story 1.22: Register Admin WebAuthn credentials

As a first Admin,
I want to register two WebAuthn credentials,
So that losing one device can't lock me out.

**Requirements:** FR-2, FR-46, AR-7; AD-31
**Screens:** Admin credential setup (Spec only; `hosted-card` in the default theme)
**Creates tables:** `admin_credential`

**Acceptance Criteria:**

**Given** an Admin with fewer than two WebAuthn credentials
**When** they attempt any other action
**Then** the server refuses it

**Given** `IWebAuthnVerifier` and `src/Adapters/Fido2`
**When** a registration runs
**Then** the RP ID and origin are passed per call, and the adapter knows no User or Admin types

**Given** a cancelled ceremony
**When** it returns
**Then** the screen stays, and setup can't be left until complete

### Story 1.23: Sign in as an Admin with WebAuthn

As an Admin,
I want to sign in with WebAuthn only,
So that no email, password or Tenant Connection can reach the Admin Dashboard.

**Requirements:** FR-46, AR-7, AR-24; AD-12, AD-31; NFR-4
**Screens:** Admin sign-in, Admin sign-out (both Spec only)

**Acceptance Criteria:**

**Given** the Admin sign-in screen
**When** it loads
**Then** it shows no email or password field, and the RP ID is the Admin hostname

**Given** a valid assertion
**When** it verifies through `IWebAuthnVerifier`
**Then** a full `admin_session` row is created with only its hash stored, using a `SameSite=Strict` `__Host-` cookie and §5.2 Admin lifetimes

**Given** a cancelled or failed assertion
**When** it returns
**Then** the screen stays, showing "That credential wasn't recognised." on failure, and failed attempts count in `admin_attempt`

**Given** a state-changing request
**When** the CSRF token or exact-host Origin is wrong
**Then** it's refused

**Given** Sign out
**When** it completes
**Then** the session row is ended and the Admin returns to Admin sign-in

**Given** a Tenant User credential
**When** it's presented to Admin sign-in
**Then** it can't authenticate, because no shared table or flow exists

### Story 1.24: Enforce capabilities and Tenant-scoped routes

As the Operator,
I want one server-side capability table,
So that no role or machine client exceeds the FR-39 matrix.

**Requirements:** NFR-5, AR-14, AR-15; AD-19, AD-20
**Screens:** None
**Creates tables:** `tenant_role`

**Acceptance Criteria:**

**Given** the capability table in the Admins contract
**When** the generated test runs
**Then** every role and machine principal is denied every capability outside it, and every `FreshAssertion` capability is `MachineAllowed = false`

**Given** a non-Deployment Owner
**When** they call `/api/v1/deployment/*`
**Then** the server refuses it

**Given** a test-only machine principal at handler level
**When** it calls any capability
**Then** it follows `MachineAllowed`, so later stories can test machine denial before the Management API exists

**Given** the capabilities endpoint
**When** the UI calls it
**Then** it returns the caller's capabilities for the path Tenant

### Story 1.25: Open the Admin shell

As an Admin,
I want a shell that shows what I can reach,
So that I can navigate, while the server stays the only access control.

**Requirements:** FR-44, NFR-17, UX-DR19, UX-DR20, UX-DR22, UX-DR23, UX-DR40; AD-21
**Screens:** Top bar (`data-screen-label="Top bar"` L28), Sidebar (`data-screen-label="Sidebar"` L83), Section page template (L1143) in `design/Gatekeep Admin.dc.html`, as changed by the Design Delta

**Acceptance Criteria:**

**Given** a signed-in Admin
**When** the shell loads
**Then** the top bar has brand, theme toggle and avatar menu, and no global search or alerts bell

**Given** a window narrower than 1100px
**When** the shell renders
**Then** the sidebar is an icon rail

**Given** the sidebar
**When** it renders
**Then** it lists only pages built so far, within the nine v1 groups, and later stories add their own items

**Given** a page at width below 768px
**When** it loads
**Then** the layout is documented as unsupported

**Given** a direct URL to a page the Admin can't reach
**When** it loads
**Then** "You don't have access to this page." shows with the trace ID

**Given** an expired Admin session with unsaved values
**When** the Admin next acts
**Then** the WebAuthn sheet appears with a `banner` explaining why, and the values remain

### Story 1.26: Confirm sensitive actions and manage Admin credentials

As an Admin,
I want sensitive actions to need a fresh WebAuthn assertion, and to manage my own credentials,
So that an unattended session can't cause harm and I never lock myself out.

**Requirements:** FR-46, UX-DR17; AD-20
**Screens:** Admin re-authentication, Your credentials (both Spec only); Confirmation modal (L1233) in `design/Gatekeep Admin.dc.html`
**Creates tables:** `admin_recovery_code`

**Acceptance Criteria:**

**Given** a `FreshAssertion` capability and a last assertion over the §5.2 limit old
**When** the Admin confirms
**Then** the WebAuthn sheet appears, failure shows in the same modal, and the action isn't performed

**Given** a request that skips the UI
**When** it has no fresh assertion
**Then** the server refuses it

**Given** Your credentials
**When** the Admin removes their last credential
**Then** it's refused
**And** adding or removing a credential writes to the Deployment Log

**Given** an offline Admin Recovery Code
**When** it's used
**Then** it leads only to credential setup, is stored as HMAC under the Deployment key and works once

**Given** Admin credential setup
**When** an Admin chooses an offline Recovery Code
**Then** it is issued once through `RevealOnce` and stored as HMAC under the Deployment key in `admin_recovery_code`

**Given** repeated wrong Admin Recovery Codes
**When** the limit is passed
**Then** attempts are limited through `admin_attempt`

### Story 1.27: Create Tenants with permanent subdomains

As a Deployment Owner,
I want to create a Tenant on its own subdomain,
So that each project or environment is a separate identity system.

**Requirements:** FR-7, FR-8, FR-44, AR-6, AR-11, AR-19, UX-DR46; AD-6, AD-7, AD-30
**Screens:** Create Tenant, Tenants (both Spec only; Create Tenant replaces Get started · Tenant step, `wiz.s0` L208, in `design/Gatekeep Admin.dc.html`, without Region)

**Acceptance Criteria:**

**Given** a Deployment Owner with no Tenants
**When** they land
**Then** the create-Tenant form appears, with name, Tenant Subdomain and label and no Region

**Given** valid input
**When** they create a Tenant
**Then** an Operation returns `202`, and creates the `tenant`, `tenant_host`, secret class keys and Tenant Owner role, with each step idempotent

**Given** a taken, reserved or malformed subdomain
**When** it's submitted
**Then** creation is refused without saying whether it was taken or reserved

**Given** a host not in `tenant_host`
**When** a request arrives at `Host.Hosted`
**Then** it gets one fixed 404 before any Tenant code runs, and a forged `Host` header selects nothing

**Given** a non-Deployment Owner
**When** they call the create endpoint
**Then** the server refuses it

**Given** a created Tenant
**When** its rows are written
**Then** the issuer, WebAuthn RP ID and email link base are stored on the Tenant, and a `tenant_settings` row exists

**Given** an existing Tenant
**When** any route tries to change its subdomain
**Then** it is refused

**Given** an Operation from another Tenant
**When** it is read through a Tenant path
**Then** it is refused

### Story 1.28: Switch Tenants and set the environment label

As an Admin,
I want to see and switch my current Tenant,
So that I never change the wrong environment by mistake.

**Requirements:** FR-7, FR-9, FR-44, UX-DR9, UX-DR18, UX-DR22; AD-19
**Screens:** Tenant switcher menu (`tenantMenu` L41) in `design/Gatekeep Admin.dc.html`, as a flat list

**Acceptance Criteria:**

**Given** an Admin with Tenant Roles
**When** they open the switcher
**Then** only Tenants they hold a Tenant Role in are listed, and "+ Create Tenant" shows only to Deployment Owners

**Given** any page
**When** it renders
**Then** the Tenant name and environment badge show, with Prod `bad`, Staging `warn` and Dev `info`

**Given** a request whose path Tenant the Admin has no Tenant Role in
**When** it arrives
**Then** the server refuses it, and the path is the only source of the Tenant

**Given** a mismatch between a page's Tenant and an action's target
**When** it's submitted
**Then** it's rejected, and a `banner` names both Tenants with Reload

**Given** a Tenant Owner removing the Prod label
**When** they confirm
**Then** re-authentication is required, the Log is written and no setting relaxes

**Given** a Deployment Owner holding no Tenant Role
**When** they land
**Then** Tenants opens

**Given** any other Admin with no Tenant Role
**When** they land
**Then** "You don't have access to a Tenant yet. Ask a Deployment Owner." shows

### Story 1.29: Delete a Tenant without touching others

As a Deployment Owner,
I want to delete a Tenant safely,
So that retired projects are removed and every other Tenant stays exactly as it was.

**Requirements:** FR-7, FR-8, FR-46, AR-6, UX-DR22; AD-30
**Screens:** Delete Tenant (Spec only)

**Acceptance Criteria:**

**Given** a Tenant
**When** a Deployment Owner deletes it
**Then** typed confirmation of the Tenant Subdomain and a fresh assertion are required

**Given** a confirmed deletion
**When** the Operation runs
**Then** it calls each module's Tenant purge, destroys its keys, and keeps security Logs for at least 90 days, whatever the Tenant's label

**Given** two Tenants
**When** one is deleted
**Then** a test proves the other's data, keys and Logs are unchanged

**Given** a deleted Tenant's subdomain
**When** it's requested or reused
**Then** it gets the fixed 404, and creation with that name is refused

**Given** the AD-3 table registry
**When** the purge test runs
**Then** it seeds every `tenant` table except Audit's, deletes the Tenant and asserts no row remains, so a table added by a later story fails until its purge exists

**Given** an Admin working in a Tenant that's been deleted
**When** their next request arrives
**Then** they return to the landing page with a `banner`

### Story 1.30: Connect the alert channel and off-server store

As the Operator,
I want a working channel and store outside the Deployment,
So that recovery and evidence don't depend on the server.

**Requirements:** FR-45, AR-28, AR-34; AD-10, AD-14, AD-17, AD-26
**Screens:** None

**Acceptance Criteria:**

**Given** `IAlertChannel` and its adapter
**When** a test alert is sent
**Then** it reaches a service outside the Deployment

**Given** the Object Lock adapter and bucket
**When** a signed record is written
**Then** the server's credential can write but not delete it or shorten its retention

**Given** install configuration
**When** a channel or bucket setting is missing
**Then** startup refuses

**Given** alert and record contents
**When** the canary scan runs
**Then** no credential-equivalent value appears

**Given** outbound HTTP from any host
**When** it runs
**Then** it goes through one `EgressHttp` handler, which blocks private addresses

**Given** the OpenBao audit device
**When** a Transit operation runs
**Then** its record reaches off-server storage, and holds no key material or plaintext

### Story 1.31: Run the cross-Tenant suite on every build

As the Operator,
I want isolation tested from registries of every route and artifact,
So that a new endpoint can't ship without an isolation test.

**Requirements:** FR-8, AR-12, AR-13, AR-33; AD-2, AD-25; SM-2
**Screens:** None

**Acceptance Criteria:**

**Given** route and artifact registries
**When** an endpoint or artifact type has no cross-Tenant case
**Then** the build fails

**Given** `gk_hosted`
**When** the grants test runs
**Then** it has no `SELECT` on `admin*`, `tenant_role` or `deployment_*`, and no write on configuration tables

**Given** every registered Admin, Management API, OAuth, OIDC and Hosted Login route, and the code, refresh token, reset link, email code, verification link, invite, Passkey and Recovery Code artifact types
**When** each is presented at Tenant B with Tenant A's authority or artifact
**Then** it is refused, and an authenticated attempt writes a Log event
**And** the registries may start with few entries, and an unbuilt artifact type is listed as pending, so the list can't shrink silently

**Given** registered job, cache and rate-limit types
**When** the suite inspects them
**Then** each is keyed by Tenant, and new types are added to the registry by the story that introduces them

### Story 1.32: Recover Admin access from the host

As the Operator,
I want to regain access after losing every Admin credential,
So that I can't be permanently locked out, and recovery can't happen quietly.

**Requirements:** FR-5, FR-45 (FR-5 alert), AR-30; AD-17, AD-31
**Screens:** Admin credential setup (Spec only)
**Creates tables:** `admin_enrolment`

**Acceptance Criteria:**

**Given** `gatekeep recover-admin` on the host
**When** it runs
**Then** it sends the alert through `IAlertChannel` and writes the off-server record itself, and issues the enrolment only after both are confirmed

**Given** either confirmation fails
**When** the command continues
**Then** no enrolment is issued

**Given** an issued enrolment
**When** it's used or 15 minutes pass
**Then** it stops working, and WebAuthn stays required

**Given** a completed recovery
**When** it finishes
**Then** that Admin's sessions are ended and the Deployment Log is written

**Given** a process other than `Gatekeep.Cli` on the host
**When** it tries the recovery path
**Then** no network route offers it

**Given** a first Admin who lost their setup session before registering credentials
**When** `gatekeep recover-admin` runs
**Then** the same single-use enrolment finishes credential setup

**Given** an issued enrolment
**When** it's stored
**Then** only its SHA-256, expiry and used time are in `admin_enrolment`, and the raw value appears in no log or Audit event

## Epic 2: OIDC core

Each Tenant publishes its own issuer, discovery document and JWKS, and issues signed tokens.

### Story 2.1: Prove per-Tenant options and Transit signing

As the Operator,
I want per-Tenant options and Transit signing proven,
So that token signing rests on tested behaviour.

**Requirements:** AR-2, AR-22; AD-8
**Screens:** None

**Acceptance Criteria:**

**Given** two Tenants in a spike build
**When** requests reach each Tenant host
**Then** the spike records a pass or fail for options replacement, `BaseUri`, signing through Transit including the synchronous provider, and token protection keys

**Given** the inert global credentials
**When** tokens and JWKS are produced
**Then** a test shows those credentials never appear

### Story 2.2: Prove custom stores and revocation commit

As the Operator,
I want custom stores and revocation commit proven,
So that Token Families rest on tested behaviour.

**Requirements:** AR-2, AR-22; AD-8, AD-13
**Screens:** None

**Acceptance Criteria:**

**Given** a failed proof
**When** the spike ends
**Then** AD-8 is amended to per-Tenant options through a keyed provider before Story 2.3 starts

**Given** custom stores in a spike build
**When** a flow runs
**Then** the spike records a pass or fail for one ad-hoc authorization per flow and for a refused refresh committing its revocation

### Story 2.3: Publish discovery and JWKS per Tenant

As an Application developer,
I want each Tenant to publish its own discovery document and keys,
So that my library can configure itself and trust only that Tenant.

**Requirements:** FR-23, FR-8, FR-37, AR-21; AD-9, AD-11
**Screens:** None
**Creates tables:** `signing_key`, protection key wraps

**Acceptance Criteria:**

**Given** a new Tenant
**When** creation completes
**Then** exactly one `current` and one `next` key exist per purpose (`signing` and `management`), each a separate Transit key using RS256 and RSA-3072

**Given** a Tenant host
**When** discovery and JWKS are requested
**Then** the issuer comes from the stored Tenant record, and JWKS contains only that Tenant's `next`, `current` and `previous` keys with `max-age=900`

**Given** a forged `Host` header
**When** discovery is requested
**Then** it can't change the issuer

**Given** two Tenants
**When** their JWKS are compared
**Then** they share no key

**Given** Tenant creation
**When** this story ships
**Then** key creation is a step in the creation Operation, a backfill covers existing Tenants, and the Tenant's token protection key is wrapped by Transit

**Given** `management` keys
**When** JWKS is built
**Then** they never appear

### Story 2.4: Rotate Signing Keys automatically

As a Tenant Owner,
I want keys to rotate without my involvement,
So that no key outlives its maximum age and rotation causes no downtime.

**Requirements:** FR-37, AR-21; AD-11
**Screens:** None

**Acceptance Criteria:**

**Given** a key within 30 days of the §5.2 maximum age
**When** the daily job runs
**Then** `next` becomes `current` only if published at least 15 minutes earlier, and a new `next` is created in the same command

**Given** a `previous` key past the hard token lifetime plus 15 minutes
**When** the job runs
**Then** it becomes `retired`, leaves the JWKS, and a job destroys its Transit key

**Given** a failed destruction
**When** it retries
**Then** it retries, writes an audit event for Epic 11 to alert on, and the Tenant's other keys are untouched

**Given** two Tenants
**When** one rotates
**Then** the other's keys and JWKS are unchanged

**Given** a `sig-` or `mgmt-` Transit key with no row after 24 hours
**When** the orphan sweep runs
**Then** it is removed, and secret class keys are never touched

### Story 2.5: Issue a token by Client Credentials

As a backend job owner,
I want a seeded machine client to obtain a signed access token,
So that the token pipeline works before any sign-in exists.

**Requirements:** FR-13, FR-23, AR-21, AR-22; AD-8, AD-9
**Screens:** None
**Creates tables:** `application`, `client_secret`, attempt counters

**Acceptance Criteria:**

**Given** a seeded `application` and `client_secret` in Directory
**When** the client requests a token
**Then** a Gatekeep handler authenticates it through Directory's contract, and OpenIddict's secret column stays empty

**Given** a token
**When** it's inspected
**Then** it's `typ: at+jwt`, unencrypted, RS256, and verifiable only through that Tenant's JWKS

**Given** a credential for Tenant A
**When** it's presented at Tenant B
**Then** it's refused and an authenticated attempt writes a Log event

**Given** repeated token requests
**When** the limit is passed
**Then** they're rate limited per Tenant and per source

**Given** token issuance
**When** the canary scan runs
**Then** no secret or token appears in logs

**Given** no API exists yet
**When** a token is issued
**Then** it uses a placeholder audience for the seeded client, replaced when Story 3.7 grants real audiences

**Given** the `IRateLimiter` adapter
**When** token requests are counted
**Then** counters live in `UNLOGGED` `tenant` rows under row-level security

### Story 2.6: Add Session and transaction tables

As a developer,
I want the tables every sign-in shares,
So that the code flow runs on real structures, not fixtures.

**Requirements:** FR-47, AR-24; AD-8, AD-12
**Screens:** None
**Creates tables:** `user`, `user_session`, `signin_transaction`, `authorization`, `token`

**Acceptance Criteria:**

**Given** `IAuthentication.Begin`
**When** it runs
**Then** a `signin_transaction` row is created, bound to the browser, Tenant and Application

**Given** `user`
**When** a minimal row is seeded in tests
**Then** the test-only authenticator can return an `AuthenticationResult` for it

### Story 2.7: Build the one revocation path

As a developer,
I want `ISessions.RevokeAccess`,
So that every later revocation uses one path.

**Requirements:** FR-48, AR-23; AD-13
**Screens:** None

**Acceptance Criteria:**

**Given** `ISessions.RevokeAccess`
**When** it runs
**Then** Sessions and Token Families in scope end, and it is the only revocation path

### Story 2.8: Add the system Application

As a developer,
I want a hidden system Application in each Tenant,
So that Portal sign-in can bind to an Application.

**Requirements:** AR-43; AD-12
**Screens:** None

**Acceptance Criteria:**

**Given** a Tenant
**When** creation completes
**Then** one hidden system Application exists, a backfill covers existing Tenants, and no code or token can be issued for it

**Given** the Directory repository
**When** Applications are listed, edited, deleted or exported
**Then** the system Application is filtered out, and direct edit or delete is refused

### Story 2.9: Run the authorization code flow with PKCE

As an Application developer,
I want a standard code flow,
So that my app can obtain tokens the way OIDC libraries expect.

**Requirements:** FR-13, FR-23, FR-47; AD-8, AD-9
**Screens:** Generic error (L409) in `Gatekeep Hosted Login.dc.html`, as a static page

**Acceptance Criteria:**

**Given** a test-only authenticator in `tests/`
**When** a seeded client completes the flow through `IAuthentication.Begin`
**Then** it receives a code and exchanges it for tokens
**And** a release build contains no such authenticator

**Given** a request with no PKCE or with `plain`
**When** it arrives
**Then** it's refused

**Given** an unregistered `redirect_uri`
**When** it arrives
**Then** Gatekeep shows a static fixed-text error page with the AD-21 CSP and never redirects, and Story 4.1 replaces the page

**Given** a used code
**When** it's replayed
**Then** it's refused, and tokens issued from it are revoked through a `FailureContext`

**Given** a code
**When** it's redeemed by another client, redirect URI or Tenant
**Then** it's refused, and any opaque artifact with the wrong `tenantPublicId` is rejected before lookup

**Given** an authorization response
**When** it returns
**Then** it includes `iss`, and Implicit and Resource Owner Password grants don't exist

**Given** a valid code
**When** it is redeemed with a non-matching `code_verifier`
**Then** it is refused

**Given** a code older than the §5.2 lifetime
**When** it is redeemed
**Then** it is refused

**Given** the code artifact
**When** this story ships
**Then** its cross-Tenant case runs, and it leaves the Story 1.31 pending list

### Story 2.10: Rotate refresh tokens and detect reuse

As an Application developer,
I want refresh tokens that rotate on every use,
So that a stolen token ends its whole family.

**Requirements:** FR-15, FR-13, NFR-3; AD-13, AD-5
**Screens:** None

**Acceptance Criteria:**

**Given** a refresh token
**When** it's used
**Then** a new one is issued, the old one stops working, and no reuse leeway applies

**Given** a rotated token
**When** it's reused
**Then** the whole Token Family is revoked and logged, and that revocation commits although the response is an error

**Given** absolute and inactivity limits
**When** either passes
**Then** the token is refused

**Given** the token table
**When** a test scans it
**Then** no raw token value is stored

**Given** a token request at the refresh endpoint
**When** the limit is passed
**Then** it's rate limited per Tenant and per source

**Given** the refresh token artifact
**When** this story ships
**Then** its cross-Tenant case runs, and it leaves the Story 1.31 pending list

### Story 2.11: Offer userinfo and revocation

As an Application developer,
I want userinfo and revocation endpoints,
So that I can read claims and end a token when my app is done with it.

**Requirements:** FR-23; RFC 7009; AD-9
**Screens:** None

**Acceptance Criteria:**

**Given** a valid access token
**When** userinfo is called
**Then** only the claims its scopes allow are returned

**Given** a refresh token
**When** it's revoked under RFC 7009
**Then** it stops working

**Given** a token from another Tenant, an ID token, or `alg: none`
**When** it's presented to userinfo
**Then** it's refused

**Given** `prompt=login`, `max_age`, `auth_time` and `amr`
**When** the protocol tests run
**Then** each is honoured through the `AuthenticationResult`

## Epic 3: Applications and APIs

Esm registers clients and APIs, and a machine client gets a scoped token (UJ-5).

### Story 3.1: List and create Applications

As a Tenant Editor,
I want to register an Application,
So that a project has a client ID to integrate with.

**Requirements:** FR-11, FR-44, UX-DR44; AD-20
**Screens:** Applications (L266), Application detail (L293) in `Gatekeep Admin.dc.html`; Create Application (Spec only)

**Acceptance Criteria:**

**Given** a Tenant with no Applications
**When** an Editor opens Applications
**Then** "No applications yet" shows with Create application, and a Viewer sees no button

**Given** a name and type
**When** it's created
**Then** a client ID exists, and an Audit event is written

**Given** a Viewer or a machine principal without the capability
**When** it calls create
**Then** the server refuses it

**Given** an Application in Tenant A
**When** Tenant B's Admin requests it
**Then** it's refused, and the cross-Tenant suite covers the route

**Given** each Application type
**When** it is created
**Then** regular web and machine-to-machine types are marked as needing a credential, and single-page and native types need none

**Given** an Admin with a Tenant
**When** they sign in
**Then** that Tenant's Applications list opens

### Story 3.2: Configure Application URLs and grants

As a Tenant Editor,
I want to set exact URLs and grant types,
So that tokens reach only where I intended.

**Requirements:** FR-11, FR-13, FR-46, UX-DR42; AD-20
**Screens:** Application · Settings (`at.settings` L309) in `Gatekeep Admin.dc.html`, as changed by the Design Delta

**Acceptance Criteria:**

**Given** callback, logout and origin URLs
**When** they're saved
**Then** each is absolute and matched exactly, with no wildcards, per line

**Given** a native Application
**When** a loopback URL is used
**Then** only the RFC 8252 port exception applies

**Given** a custom URI scheme in a Prod Tenant
**When** it's saved
**Then** an explicit acknowledgement is required

**Given** a Prod Tenant's callback URLs
**When** they change
**Then** a fresh assertion is required, and machine principals are refused

**Given** grant options
**When** the page renders
**Then** only Authorization Code with PKCE, Refresh Token and Client Credentials appear

**Given** a native Application
**When** setup guidance shows
**Then** it requires the system browser and offers no embedded view

**Given** a grant type turned off for an Application
**When** that client attempts it
**Then** the authorization or token endpoint refuses it

### Story 3.3: Create, rotate and revoke client secrets

As a Tenant Owner,
I want to manage client secrets safely,
So that a secret can be replaced with no downtime and is never visible twice.

**Requirements:** FR-12, FR-46, NFR-3; AD-24
**Screens:** Application · Credentials (`at.credentials` L345) in `Gatekeep Admin.dc.html`, without Reveal, Private Key JWT, mTLS or public keys

**Acceptance Criteria:**

**Given** a new secret
**When** it's created
**Then** it's 256-bit, shown once through `RevealOnce`, and stored only as SHA-256

**Given** a rotation
**When** the Owner confirms with a fresh assertion
**Then** the old secret stays valid for the §5.2 default overlap, and "End old secret now" stops it

**Given** an Editor
**When** they try to manage a secret
**Then** the server refuses it, and the control reads "Tenant Owner only"

**Given** logs, Audit events and exports
**When** the canary scan runs
**Then** no secret value appears

**Given** a secret
**When** a Tenant Owner revokes it
**Then** it stops working at once and the Log is written

**Given** a regular web or machine-to-machine Application with no secret
**When** an Editor opens Credentials
**Then** it says a Tenant Owner must create one

### Story 3.4: Set token lifetimes

As a Tenant Editor,
I want to set token lifetimes per Application,
So that each client gets a suitable balance of safety and convenience.

**Requirements:** FR-15; §5.2
**Screens:** Application · Tokens (`at.tokens` L388) in `Gatekeep Admin.dc.html`, without signing algorithm or rotation toggles

**Acceptance Criteria:**

**Given** lifetime fields
**When** a value exceeds a §5.2 hard limit
**Then** it's refused with "Maximum is {limit}." on both the UI and the API

**Given** a saved lifetime
**When** a new token is issued
**Then** it uses that lifetime

**Given** the page
**When** it renders
**Then** no option turns off rotation or chooses an algorithm

### Story 3.5: Delete an Application

As a Tenant Editor,
I want to delete an Application,
So that a retired client can't obtain or keep tokens.

**Requirements:** FR-11, AD-1, AD-30
**Screens:** Delete Application, using Confirmation modal (L1233) in `Gatekeep Admin.dc.html`

**Acceptance Criteria:**

**Given** the delete modal
**When** it opens
**Then** it states the token effect

**Given** a confirmed deletion
**When** it commits
**Then** the Application is marked deleted, its refresh tokens and grants are revoked through `RevokeAccess`, the Log is written, and an Operation purges its rows

**Given** a deleted client
**When** it calls the token endpoint
**Then** it's refused

### Story 3.6: Define APIs and Permissions

As a Tenant Editor,
I want to register an API with its Permissions,
So that tokens can name an audience and scopes.

**Requirements:** FR-16, UX-DR42, UX-DR44
**Screens:** APIs (`GEN.apis` L1265) in `Gatekeep Admin.dc.html`, without HS256 or consent controls
**Creates tables:** `api`, `permission`

**Acceptance Criteria:**

**Given** an API identifier
**When** it's created
**Then** it's unique in the Tenant and locked afterwards

**Given** a Permission
**When** it's saved
**Then** it follows `resource:action` and is unique per API

**Given** any Tenant
**When** APIs loads
**Then** the built-in Management API is listed, so the list is never empty

**Given** the create form
**When** it's shown
**Then** it advises different identifiers for Dev, Staging and Prod

**Given** Tenant creation
**When** this story ships
**Then** the built-in API record and its Management Permissions are a creation step, with a backfill for existing Tenants

**Given** an API
**When** an Editor sets offline access or RBAC
**Then** the setting saves and the Log is written

**Given** an API
**When** an Editor sets its ID, access or refresh token lifetime
**Then** it stays within §5.2, and new tokens for that API use it

**Given** different lifetimes on an Application and an API
**When** a token is issued
**Then** the shorter value applies

### Story 3.7: Authorize a machine-to-machine Application

As a Tenant Editor,
I want to grant a machine client selected Permissions,
So that a job gets only the access it needs (UJ-5).

**Requirements:** FR-16, FR-13; AD-33; UJ-5
**Screens:** APIs · machine-to-machine access (`GEN.apis` L1265) in `Gatekeep Admin.dc.html`
**Creates tables:** `api_grant`

**Acceptance Criteria:**

**Given** a grant
**When** the client requests a token
**Then** the token carries only granted Permissions, and an ungranted scope is omitted

**Given** a removed grant
**When** the next token is issued
**Then** that Permission is gone

**Given** the Management API audience
**When** it's requested at `Host.Hosted`'s token endpoint
**Then** it's refused

**Given** offline access off for an API
**When** a client requests a refresh token for it
**Then** none is issued

**Given** real API grants
**When** this story ships
**Then** the Story 2.5 placeholder audience is removed

## Epic 4: Database login

A User signs up, verifies, signs in, resets a password and logs out through Hosted Login (core of UJ-1).

### Story 4.1: Serve Hosted Login step screens

As a User,
I want sign-in pages that arrive complete and safe,
So that I never see a flash of loading or a page that leaks detail.

**Requirements:** FR-33, NFR-16, NFR-17, NFR-19, AR-31, AR-38, UX-DR34, UX-DR37, UX-DR38, UX-DR41, UX-DR45; AD-21
**Screens:** Generic error (L409), Theme variants (L34) in `Gatekeep Hosted Login.dc.html`

**Acceptance Criteria:**

**Given** a sign-in step
**When** the first response arrives
**Then** the step is embedded as JSON, the theme stylesheet is in `<head>`, and the client renders with no fetch

**Given** any step response
**When** it's sent
**Then** it's `no-store`, carries the AD-21 CSP, denies framing and sets `Referrer-Policy: no-referrer`

**Given** the bundle
**When** CI runs
**Then** it stays within 150 kB compressed and has no third-party runtime request

**Given** an error
**When** Generic error shows
**Then** only fixed text, a code and a trace ID appear, and `<noscript>` shows fixed text

**Given** the screen in both colour schemes
**When** an accessibility test runs
**Then** focus precedence, `<title>`, `lang`, one `main` landmark and 320px reflow pass

**Given** a surface
**When** lint runs
**Then** a hard-coded user-facing string fails the build

### Story 4.2: Bind sign-in transactions and issue Sessions

As a User,
I want my sign-in protected against fixation and step skipping,
So that nobody can hijack or shortcut it.

**Requirements:** FR-47, FR-8, NFR-3, NFR-4, AR-24, UX-DR32, UX-DR33; AD-12
**Screens:** Login · identifier first (L39) in `Gatekeep Hosted Login.dc.html`

**Acceptance Criteria:**

**Given** an authorization request
**When** Login starts
**Then** the existing `signin_transaction` is bound to the browser, Tenant and Application, with a `__Host-gk_txn` cookie and a 30-minute sliding life

**Given** a post-step URL requested directly
**When** no server record shows earlier steps passed
**Then** it's refused

**Given** a Session issued
**When** authentication completes
**Then** the identifier is new, only its SHA-256 is stored, and the old one stops working

**Given** a cookie for Tenant A
**When** it's sent to or set by Tenant B or the parent domain
**Then** a test shows both directions fail

**Given** a state-changing request
**When** the CSRF token or exact-host Origin is wrong
**Then** it's refused

**Given** 2 minutes left on a transaction
**When** the warning shows
**Then** "Keep going" extends it, and expiry restarts at Login with the email kept

**Given** a stale `stepVersion`
**When** it's submitted
**Then** the current valid step returns

**Given** a transaction
**When** it is presented from another browser, Tenant or Application, after expiry, or after completion
**Then** it is refused

### Story 4.3: Purge expired sign-in state

As the Operator,
I want expired state removed on schedule,
So that old transactions and tokens don't linger.

**Requirements:** FR-8, NFR-3; AD-15
**Screens:** None

**Acceptance Criteria:**

**Given** expired transactions and tokens, and Sessions with no live Token Family
**When** the recurring job runs
**Then** they are purged one Tenant scope at a time
**And** transactions stay one hour past expiry, so a restart keeps the email

### Story 4.4: Configure a Tenant's email provider

As a Tenant Owner,
I want to configure an email provider,
So that verification and reset messages reach Users.

**Requirements:** FR-36, FR-46; AD-10
**Screens:** Email & SMS providers (`GEN.providers` L1290) in `Gatekeep Admin.dc.html`, as Email provider
**Creates tables:** `email_provider`

**Acceptance Criteria:**

**Given** provider credentials
**When** a Tenant Owner saves them with a fresh assertion
**Then** they're stored as Transit ciphertext, `Host.Admin` can't decrypt them, and the Log is written

**Given** an Editor or machine principal
**When** it attempts to change the provider
**Then** it's refused

### Story 4.5: Send email through the job pipeline

As a User,
I want transactional email to arrive safely,
So that links never leak or point elsewhere.

**Requirements:** FR-36, AR-18; AD-15
**Screens:** None
**Creates tables:** `email_template`

**Acceptance Criteria:**

**Given** a queued email
**When** the worker sends it
**Then** the recipient is resolved from an ID at send time, the link payload is ciphertext, and it's erased afterwards

**Given** an email link
**When** it's built
**Then** its host comes from the stored issuer, never request headers

**Given** the five default templates
**When** a message is sent
**Then** subject and body use fixed variable substitution only

**Given** one recipient
**When** the per-recipient limit is passed
**Then** further email is held back

### Story 4.6: Configure the database Connection

As a Tenant Owner,
I want to set sign-up and password rules,
So that a Tenant's password login suits its risk.

**Requirements:** FR-17, FR-18, UX-DR21, UX-DR42, UX-DR44
**Screens:** Database (L446), Database · Settings (`dt.settings` L458), Database · Password policy (`dt.policy` L465) in `Gatekeep Admin.dc.html`
**Creates tables:** `connection`, `password_history`

**Acceptance Criteria:**

**Given** password policy
**When** the minimum falls below the §5.2 floor
**Then** it's refused with "Minimum is 12 characters."

**Given** an Editor
**When** they toggle sign-up
**Then** it saves, and password policy stays read-only labelled "Tenant Owner only"

**Given** a saved change
**When** it commits
**Then** it applies only to that Tenant and the Log is written

**Given** the Tenant settings a sign-up reads
**When** this story ships
**Then** a terms URL and, in Dev Tenants only, email verification off can be set here, and Story 8.5 keeps both

**Given** Tenant creation
**When** this story ships
**Then** the default database `connection` is a creation step, with a backfill for existing Tenants

**Given** the default audience
**When** an Editor sets it in Tenant settings
**Then** it saves within this Tenant, and Story 8.5 keeps the field

### Story 4.7: Sign up and verify an email address

As a new User,
I want to create an account and verify my email,
So that I can use the app.

**Requirements:** FR-17, FR-18, NFR-2, UX-DR28, UX-DR31, UX-DR42, UX-DR43
**Screens:** Signup · password strength (L80), Email verification required (L261), Email verified (L271) in `Gatekeep Hosted Login.dc.html`; Link expired (Spec only)
**Creates tables:** `password_credential`, `one_time_token`

**Acceptance Criteria:**

**Given** a new address
**When** sign-up succeeds
**Then** no Session or token exists until verification, unless a Dev Tenant turned this off

**Given** a verification link
**When** it's used
**Then** it works once, is stored hashed, and invalidates any pending credential from an earlier unverified sign-up

**Given** the password field
**When** the User types
**Then** the meter uses the Connection's rules, and nothing leaves the browser until submit

**Given** a password failing a strength, history, dictionary or personal-data rule
**When** it is submitted
**Then** the server refuses it and names the rule

**Given** the verification link artifact
**When** this story ships
**Then** its cross-Tenant case runs, and it leaves the Story 1.31 pending list

### Story 4.8: Keep sign-up neutral and limited

As an User,
I want sign-up to reveal nothing about existing accounts,
So that nobody can use it to find me.

**Requirements:** FR-17, NFR-6, NFR-20, FR-8
**Screens:** Signup · password strength (L80) in `Gatekeep Hosted Login.dc.html`

**Acceptance Criteria:**

**Given** an existing address
**When** sign-up is submitted
**Then** nothing changes, a notice goes to that address, and the response matches a new sign-up in content, status, next step and timing within tolerance

**Given** a terms URL
**When** the User signs up
**Then** acceptance is required and its version and time are recorded

**Given** repeated sign-ups or resends
**When** the limit is passed
**Then** they're rate limited per Tenant and per source, without revealing an account

**Given** the same email in two Tenants
**When** both sign up
**Then** two unrelated Users exist

**Given** sign-up disabled
**When** sign-up is submitted
**Then** no account is created, and no account state is revealed

### Story 4.9: Sign in with a password

As a returning User,
I want to sign in with my email and password,
So that I reach my app without revealing anything to an attacker.

**Requirements:** FR-17, FR-23, NFR-2, NFR-6, NFR-11, NFR-20, AR-25, UX-DR27, UX-DR32; AD-24
**Screens:** Login · identifier first (L39), Login · password step (L53) in `Gatekeep Hosted Login.dc.html`

**Acceptance Criteria:**

**Given** any identifier
**When** Continue is pressed
**Then** the next step doesn't depend on whether the account exists or how it signs in

**Given** an unknown account
**When** a password is submitted
**Then** an equivalent dummy Argon2id hash runs, and the message and timing match a wrong password

**Given** a stored hash with old parameters
**When** sign-in succeeds
**Then** it's upgraded

**Given** correct credentials
**When** sign-in completes
**Then** the Session records `amr`, `auth_time` and the Connection, and the Application receives a code

**Given** repeated failures
**When** the limit is passed
**Then** requests are limited per Tenant and per source, and forwarded addresses are honoured only from the Caddy network address

**Given** the sign-in path
**When** the canary scan runs
**Then** no password, token or Session identifier reaches a log

**Given** a User token
**When** it is issued
**Then** its audience is the requested API, or the Tenant's default audience, or, with neither set, the Tenant's userinfo endpoint only, and never the Story 2.5 placeholder

### Story 4.10: Revoke access through one path

As a User,
I want every credential change to end existing access,
So that recovering my account evicts an attacker.

**Requirements:** FR-48, AR-23; AD-13
**Screens:** None

**Acceptance Criteria:**

**Given** `ISessions.RevokeAccess`
**When** it runs
**Then** all Sessions and Token Families in scope end at once, except the named acting Session

**Given** the FR-48 trigger list
**When** the generated test runs
**Then** each trigger built so far calls `RevokeAccess`, and each unbuilt trigger is listed as pending, so the list can't shrink silently

**Given** two Tenants
**When** one User's access is revoked
**Then** no other Tenant's data changes

### Story 4.11: Reset a forgotten password

As a User who forgot my password,
I want to set a new one by email,
So that I regain access safely.

**Requirements:** FR-19, FR-48, NFR-6, NFR-20
**Screens:** Forgot password (L232), Reset password (L242), Password changed (L252) in `Gatekeep Hosted Login.dc.html`; Neutral confirmation, Link expired (Spec only)

**Acceptance Criteria:**

**Given** any address
**When** a reset is requested
**Then** the confirmation is identical in content, status and timing

**Given** a reset link
**When** it's used, expired, or superseded by a newer reset
**Then** only the newest unused link within §5.2 works, and others show Link expired

**Given** a completed reset
**When** it commits
**Then** no Session is created, `RevokeAccess` runs, and a notification is sent

**Given** the reset URL
**When** the canary scan runs
**Then** the link appears in no log, Audit event or `Referer`

**Given** repeated requests
**When** the limit is passed
**Then** they're rate limited per Tenant, per source and per recipient

**Given** a new password failing policy at reset
**When** it is submitted
**Then** the server refuses it and names the rule

**Given** the reset link artifact
**When** this story ships
**Then** its cross-Tenant case runs, and it leaves the Story 1.31 pending list

### Story 4.12: Choose Connections per Application

As a Tenant Editor,
I want to turn Connections on or off per Application,
So that each app offers only the sign-in methods I intended.

**Requirements:** FR-14, UX-DR32
**Screens:** Application · Connections (`at.connections` L365), Database · Applications (`dt.applications` L504) in `Gatekeep Admin.dc.html`
**Creates tables:** `application_connection`

**Acceptance Criteria:**

**Given** a disabled Connection
**When** that Application starts sign-in
**Then** Hosted Login doesn't offer it, and a direct request is refused

**Given** no enabled Connections
**When** the settings page shows
**Then** a banner warns that Users can't sign in, and Login shows Generic error

**Given** a Session from a Connection disabled for this Application
**When** the Application requests sign-in
**Then** the User signs in again

**Given** the system Application
**When** Connections change
**Then** it follows every Connection enabled in the Tenant, so Portal sign-in keeps working

**Given** a new Application
**When** it is created
**Then** every enabled Connection is on by default

### Story 4.13: Log out

As a User,
I want to end my Session,
So that nobody else can continue it.

**Requirements:** FR-24
**Screens:** Logout confirmation (L401) in `Gatekeep Hosted Login.dc.html`

**Acceptance Criteria:**

**Given** a logout
**When** it completes
**Then** the Session and its bound refresh tokens end

**Given** a valid `id_token_hint` and a registered URL
**When** logout finishes
**Then** it redirects there through a top-level GET

**Given** an invalid hint or unregistered URL
**When** logout runs
**Then** the User is logged out and sees the logged out state with no redirect

### Story 4.14: Run OpenID conformance on real sign-in

As the Operator,
I want conformance tests running against real login,
So that protocol faults show up early.

**Requirements:** FR-23, AR-33, AR-41; AD-25; SM-4
**Screens:** None

**Acceptance Criteria:**

**Given** a Dev Tenant
**When** CI runs Basic OP, Config OP and RP-Initiated Logout OP
**Then** results are stored per plan

**Given** `GATEKEEP_CONFORMANCE_TENANT` set
**When** a Prod Tenant exists or a Tenant is labelled Prod
**Then** startup or labelling is refused

**Given** a relaxed rule
**When** it's used
**Then** it applies to one named Dev Tenant per request, and the deviation is recorded

## Epic 5: Users and RBAC

Admins find and administer Users, assign Roles and export or erase data.

### Story 5.1: Search Users by field

As an Admin,
I want to find a User by field,
So that I can reach an account quickly.

**Requirements:** FR-30, UX-DR12, UX-DR44
**Screens:** Users (L584) in `Gatekeep Admin.dc.html`, without bulk bar, Import, Export or query bar

**Acceptance Criteria:**

**Given** a field and value
**When** the search runs
**Then** results are cursor-paged at 50 and values stay in the URL

**Given** no matches
**When** results load
**Then** "No results" shows with Clear filters

**Given** the same email in two Tenants
**When** one Tenant is searched
**Then** only its own User appears

**Given** any response
**When** it's inspected
**Then** it holds no credential-equivalent value

### Story 5.2: View a User's profile and Sessions

As an Admin,
I want to see a User's account,
So that I can understand and help with a problem.

**Requirements:** FR-30
**Screens:** User detail (L625), User · Details (`ut.details` L658), User · Sessions & devices (`ut.sessions` L684) in `Gatekeep Admin.dc.html`

**Acceptance Criteria:**

**Given** a User
**When** detail opens
**Then** profile, last login and Sessions are shown read-only to a Viewer

**Given** another Tenant's User ID
**When** it's requested
**Then** "This no longer exists." shows and nothing leaks

**Given** User detail through the Dashboard
**When** each response is scanned
**Then** no Session identifier, token or hash appears, and Story 6.10 and Story 17.3 extend this to Factors and the Management API

### Story 5.3: Create a User and send verification

As a Tenant Editor,
I want to create a User and send verification,
So that I can set up an account for someone.

**Requirements:** FR-31
**Screens:** Create User (Spec only)

**Acceptance Criteria:**

**Given** an email
**When** the Editor creates a User
**Then** the User exists unverified, the Log names the acting Admin, and verification can be sent

**Given** an email already in this Tenant
**When** it's submitted
**Then** an inline error shows, on this Admin-only path

**Given** a Viewer
**When** they call the endpoint
**Then** it's refused

### Story 5.4: Block, unblock and revoke a User

As a Tenant Editor,
I want to stop a User's access at once,
So that I can respond to abuse or a suspected takeover.

**Requirements:** FR-31, FR-48, FR-30, FR-33; AD-2
**Screens:** User · Actions menu (`userMenu` L639), User · Sessions & devices (L684) in `Gatekeep Admin.dc.html`; Blocked account (L357) in `Gatekeep Hosted Login.dc.html`

**Acceptance Criteria:**

**Given** Block
**When** it's confirmed in a modal
**Then** `user.blocked_at` is set, `RevokeAccess` runs and the Log names the Admin

**Given** `gk_hosted`
**When** it tries to write `blocked_at`
**Then** the database refuses it

**Given** a blocked User with valid credentials
**When** they sign in
**Then** Blocked account shows only after valid credentials

**Given** Revoke on a Session
**When** it completes
**Then** the row disappears and a toast confirms

**Given** unblock, send verification, or Session or refresh token revocation
**When** it commits
**Then** the Log names the acting Admin

**Given** an unblocked User
**When** they sign in with valid credentials
**Then** sign-in succeeds

### Story 5.5: Delete a User

As a Tenant Editor,
I want to delete a User,
So that a removed account can't sign in.

**Requirements:** FR-31, FR-48; AD-30
**Screens:** User · Actions menu (L639), Confirmation modal (L1233) in `Gatekeep Admin.dc.html`

**Acceptance Criteria:**

**Given** Delete
**When** the modal opens
**Then** typed confirmation of the User's email is required

**Given** a confirmed deletion
**When** the Operation runs
**Then** `RevokeAccess` runs, the User's data is removed, and the Log keeps its record by internal reference

**Given** a retried Operation
**When** it runs again
**Then** it re-checks authoritative state and repeats only failed steps

**Given** per-User data in tables added later
**When** the registry test runs
**Then** every `tenant` table holding a User reference has a delete path, so a later table fails until it has one

**Given** a confirmed deletion
**When** it commits
**Then** the Log names the acting Admin

### Story 5.6: Manage Roles

As a Tenant Editor,
I want to group Permissions into Roles,
So that I can assign access by job rather than one Permission at a time.

**Requirements:** FR-32
**Screens:** Roles (`GEN.roles` L1271) in `Gatekeep Admin.dc.html`, without organization samples
**Creates tables:** `role`, `role_permission`

**Acceptance Criteria:**

**Given** a Role name
**When** it duplicates another
**Then** an inline error shows

**Given** a Role
**When** Permissions are added
**Then** only Permissions from this Tenant's APIs can be chosen, and the server refuses others

**Given** a Management API Permission
**When** it's added to a Role
**Then** it's refused

### Story 5.7: Assign Roles and put Permissions in tokens

As a Tenant Editor,
I want a User's Roles reflected in access tokens,
So that my APIs can authorize requests.

**Requirements:** FR-32, FR-16; AD-13
**Screens:** RBAC (`GEN.rbac` L1273), User · Roles & permissions (`ut.roles` L694) in `Gatekeep Admin.dc.html`
**Creates tables:** `user_role`

**Acceptance Criteria:**

**Given** RBAC on for an API
**When** a User's token is issued
**Then** their effective Permissions are in it

**Given** a removed Role or Permission
**When** the next token or refresh is issued
**Then** it's absent

**Given** an API with no Permissions
**When** RBAC opens
**Then** the empty state links to APIs

### Story 5.8: Export a User's data

As a Tenant Owner,
I want to export a person's data,
So that the Tenant can answer an access request.

**Requirements:** FR-49, NFR-14
**Screens:** User · Actions menu (L639) in `Gatekeep Admin.dc.html`; Export or erase User (Spec only)

**Acceptance Criteria:**

**Given** an export
**When** it completes
**Then** the file holds the User's personal data, no credential-equivalent value, and the Log is written

**Given** an Editor
**When** they attempt an export
**Then** it's refused

**Given** an export
**When** it's requested
**Then** `Host.Admin` builds it during the request and streams it with `no-store`, and no copy is kept on the server

**Given** personal data in tables added later
**When** the registry test runs
**Then** every `tenant` table with personal data is in the export, so a later table fails until it is

### Story 5.9: Erase a User's data

As a Tenant Owner,
I want to erase a person's data without breaking the Logs,
So that the Tenant can answer an erasure request.

**Requirements:** FR-49, NFR-14; AD-16, AD-30
**Screens:** User · Actions menu (L639) in `Gatekeep Admin.dc.html`; Export or erase User (Spec only)

**Acceptance Criteria:**

**Given** an erasure
**When** it completes
**Then** `audit_detail` and personal data are removed, the `audit_event` envelope is unchanged, and an internal-reference event is written

**Given** an Editor
**When** they attempt erasure
**Then** it is refused

**Given** an erasure
**When** it starts
**Then** it runs as an Operation

**Given** personal data in tables added later
**When** the registry test runs
**Then** every `tenant` table with personal data has an erase path, so a later table fails until it has one

## Epic 6: Passkeys, MFA and recovery

Users enrol Passkeys and Factors and recover with codes (UJ-2).

### Story 6.1: Create a Passkey

As a verified User,
I want to create a Passkey,
So that my next sign-in takes one prompt.

**Requirements:** FR-21, AR-25, UX-DR31; AD-24
**Screens:** Passkey create (L107) in `Gatekeep Hosted Login.dc.html`; Passkeys (`GEN.passkeys` L1268) in `Gatekeep Admin.dc.html`, without stats or attestation selects
**Creates tables:** `webauthn_credential`

**Acceptance Criteria:**

**Given** a verified email
**When** the prompt is on
**Then** Passkey creation is offered, and a Tenant can turn the prompt off

**Given** a registration
**When** it runs
**Then** the exact RP ID and origin come from the stored Tenant record, user verification is required, and no attestation is requested

**Given** a cancelled sheet
**When** the User returns
**Then** the card shows no error

**Given** a Passkey added
**When** it commits
**Then** a notification is sent, and `RevokeAccess` ends other Sessions while the acting one continues

### Story 6.2: Show Recovery Codes at first enrolment

As a User,
I want recovery codes when I first enrol,
So that losing a device doesn't lock me out.

**Requirements:** FR-27, FR-36, NFR-3, UX-DR29; AD-24
**Screens:** Recovery codes (L205) in `Gatekeep Hosted Login.dc.html`, with corrected copy
**Creates tables:** `recovery_code`

**Acceptance Criteria:**

**Given** a first enrolment
**When** it completes
**Then** 8 codes show once, fetched from `/login/api/*` as `RevealOnce` and never embedded in first-response JSON

**Given** stored codes
**When** they're inspected
**Then** each is an HMAC under the Tenant's Transit key

**Given** Continue with the box unticked
**When** it's pressed
**Then** "Confirm you've saved your codes." shows

**Given** Back after Continue
**When** it's pressed
**Then** the codes don't reappear

### Story 6.3: Sign in with a Passkey

As a User with a Passkey,
I want one prompt to sign in,
So that I needn't type anything.

**Requirements:** FR-21, FR-25
**Screens:** Passkey sign-in prompt (L64) in `Gatekeep Hosted Login.dc.html`

**Acceptance Criteria:**

**Given** the Login card
**When** autofill or the button is used
**Then** discovery is browser-mediated and needs no account lookup

**Given** a verified assertion with user verification
**When** it completes
**Then** the Session records `amr`, and no further step follows

**Given** failure
**When** it returns
**Then** "That passkey didn't work. Try again or use another method." shows, and attempts are limited

**Given** a Passkey from Tenant A
**When** it is tried at Tenant B
**Then** it fails

**Given** the Passkey artifact
**When** this story ships
**Then** its cross-Tenant case runs, and it leaves the Story 1.31 pending list

### Story 6.4: Set MFA policy

As a Tenant Owner,
I want to require a second factor,
So that a stolen password alone can't reach an account.

**Requirements:** FR-25, FR-46, UX-DR44
**Screens:** Multi-factor auth (L818) in `Gatekeep Admin.dc.html`, Never and Always only, without the Adaptive panel

**Acceptance Criteria:**

**Given** a policy change
**When** it's saved
**Then** it's written to the Log and takes effect in that Tenant only

**Given** Always lowered to Never
**When** it's confirmed
**Then** a fresh assertion is required, and machine principals are refused

**Given** an Editor
**When** they attempt a change
**Then** it's refused

### Story 6.5: Enrol an authenticator app

As a User,
I want to set up TOTP,
So that I have a second factor.

**Requirements:** FR-25, FR-26, NFR-3, UX-DR26, UX-DR27, UX-DR30; AD-10
**Screens:** Enroll · choose a factor (L148), TOTP · scan QR (L159) in `Gatekeep Hosted Login.dc.html`; Enrolment email check (Spec only)
**Creates tables:** `totp_factor`, `email_code`

**Acceptance Criteria:**

**Given** a first Factor at sign-in
**When** enrolment starts
**Then** an email code check comes first, so a stolen password alone stops here, and it's skipped straight after signup verification

**Given** the TOTP seed
**When** it's stored
**Then** it's Transit ciphertext under `totp`, and shown only through `RevealOnce`

**Given** a wrong code
**When** it's entered
**Then** "That code is incorrect." shows and the seed stays until the screen closes

**Given** enrolment completes
**When** it commits
**Then** a notification is sent and `RevokeAccess` ends other Sessions while the acting one continues

**Given** the email code primitive
**When** a code is issued
**Then** it is single-use, stored as HMAC under the Tenant's Transit key, and uses §5.2 expiry and attempts, and Story 14.6 reuses it

### Story 6.6: Enrol a security key

As a User,
I want to register a security key,
So that I have a phishing-resistant Factor.

**Requirements:** FR-26, FR-25
**Screens:** WebAuthn security key (L194) in `Gatekeep Hosted Login.dc.html`, setup

**Acceptance Criteria:**

**Given** the setup screen
**When** a key is touched
**Then** it's stored in `webauthn_credential` with `kind` security key

**Given** an already registered key
**When** it's used
**Then** "This key is already set up." shows

**Given** a disallowed Factor
**When** Factor choice renders
**Then** it isn't offered, and Users relying on it enrol a replacement at next sign-in

**Given** a security key added
**When** it commits
**Then** a notification is sent, and `RevokeAccess` ends other Sessions while the acting one continues

### Story 6.7: Pass an MFA challenge

As a User under Always,
I want to prove my second factor,
So that I can finish signing in, by whichever method I have.

**Requirements:** FR-25, FR-26, FR-47, NFR-6, UX-DR26, UX-DR27
**Screens:** MFA method picker, TOTP challenge (both Spec only); WebAuthn security key (L194) in `Gatekeep Hosted Login.dc.html`, challenge

**Acceptance Criteria:**

**Given** the first factor passes
**When** policy is Always
**Then** no Session or token exists until a second factor from a different category is verified

**Given** a used TOTP code
**When** it's reused in its window
**Then** it gets the same "That code is incorrect." message

**Given** the picker
**When** it renders
**Then** only enrolled methods show

**Given** a post-MFA URL
**When** it's requested directly
**Then** it's refused

**Given** repeated failures
**When** the limit is passed
**Then** attempts are limited per method and per source, per Tenant

**Given** Factor completion
**When** it commits
**Then** the Session identifier is new, and the earlier one is refused

### Story 6.8: Recover with a Recovery Code

As a User who lost a device,
I want to use a recovery code,
So that I can regain access and evict anyone else.

**Requirements:** FR-27, FR-48, FR-36, NFR-6, NFR-20
**Screens:** Recovery Code entry (Spec only)

**Acceptance Criteria:**

**Given** a code at the MFA step
**When** it's valid
**Then** it replaces only the Factor step, works once, and a notification is sent

**Given** a code from Login for a Passkey-only account
**When** it's valid
**Then** it replaces sign-in, mandatory Passkey enrolment follows, and `RevokeAccess` ends other Sessions

**Given** a code from Login for any other account
**When** it's submitted
**Then** "That code isn't valid." shows, identical to an unknown account, and no code is consumed

**Given** repeated attempts
**When** the limit is passed
**Then** they back off per Tenant and per source

**Given** Login and the picker
**When** this story ships
**Then** "Use a recovery code" appears, as UX-DR32 requires

**Given** a code used at the MFA step
**When** it commits
**Then** `RevokeAccess` ends every other Session

**Given** the Recovery Code artifact
**When** this story ships
**Then** its cross-Tenant case runs, and it leaves the Story 1.31 pending list

### Story 6.9: Recover a Passkey-only account by email

As a Passkey-only User under Never,
I want a delayed email recovery where my Tenant allows it,
So that I can return, with time to stop an attacker.

**Requirements:** FR-27, NFR-20
**Screens:** Email recovery waiting (Spec only); Forgot password (L232), Neutral confirmation in `Gatekeep Hosted Login.dc.html`; Multi-factor auth (L818) in `Gatekeep Admin.dc.html`
**Creates tables:** `email_recovery`

**Acceptance Criteria:**

**Given** Tenant policy allows it
**When** recovery starts
**Then** the neutral confirmation is unchanged, and a 24-hour delay starts with a notification carrying a cancel link

**Given** the 24 hours pass
**When** the second email arrives
**Then** it links to enrol a new Passkey, single-use

**Given** policy Always
**When** a Passkey-only User asks
**Then** no email recovery is offered

**Given** a Passkey added through email recovery
**When** enrolment completes
**Then** a notification is sent, and `RevokeAccess` ends every other Session

### Story 6.10: Reset a User's Factors and Passkeys

As a Tenant Editor,
I want to reset a locked-out User's methods,
So that they can enrol again after I've checked who they are.

**Requirements:** FR-30, FR-31, FR-48
**Screens:** User · MFA (`ut.mfa` L711) in `Gatekeep Admin.dc.html`

**Acceptance Criteria:**

**Given** a reset
**When** it's confirmed in a modal
**Then** `RevokeAccess` runs, a notification is sent, and the Log names the Admin

**Given** a User with a remaining first factor
**When** they next sign in
**Then** they enrol again under FR-25

**Given** User · MFA
**When** it opens
**Then** enrolled Factors and Passkeys are listed, with no seed or credential secret in the response

### Story 6.11: Recover a Passkey-only User with an enrolment link

As a Tenant Editor,
I want to issue a single-use enrolment link after checking identity outside the product,
So that a Passkey-only User who lost everything can return.

**Requirements:** FR-27, FR-31, AR-40; §5.2
**Screens:** User · MFA (`ut.mfa` L711) in `Gatekeep Admin.dc.html`; Credential enrolment (Spec only)

**Acceptance Criteria:**

**Given** a Passkey-only User under Always or Never
**When** an Editor confirms the reset
**Then** a single-use link is shown once through `RevealOnce`, stored only hashed, and the Log names the Admin

**Given** the link
**When** it is used
**Then** Passkey creation runs, then Recovery Code display, and no Session or token exists before enrolment completes

**Given** a used link or one past its §5.2 lifetime
**When** it is opened
**Then** Link expired shows, with no "Send a new link"

**Given** a link from Tenant A
**When** it is opened at Tenant B
**Then** it is refused, and the cross-Tenant suite covers it

**Given** the link
**When** the canary scan runs
**Then** it appears in no log, Audit event or job payload

**Given** repeated invalid link attempts
**When** the limit is passed
**Then** they are limited per Tenant and per source

**Given** a Passkey added through the link
**When** enrolment completes
**Then** a notification is sent, and `RevokeAccess` ends every other Session

### Story 6.12: Prove the FR-25 matrix

As the Operator,
I want every sign-in and recovery path tested under Always,
So that no path bypasses the second factor.

**Requirements:** FR-25, AR-33; AD-25
**Screens:** None

**Acceptance Criteria:**

**Given** the matrix
**When** a new Connection or recovery path is registered
**Then** the build fails until it's covered

**Given** every path built so far under Always
**When** the test runs
**Then** each ends with a verified second factor or an FR-27 Recovery Code

**Given** a change from Never to Always
**When** a User with no method signs in
**Then** they enrol under the same rule before any token

**Given** a User with Factors
**When** password reset completes
**Then** every Factor and Passkey is unchanged, and email code and email change sit on a pending list that Story 14.6 and Story 16.8 close

## Epic 7: Logs and audit evidence

Admins search tamper-evident Logs, and evidence is copied off the server.

### Story 7.1: Seal audit events into hash chains

As the Operator,
I want events chained,
So that any change or gap is detectable.

**Requirements:** FR-40, AR-27; AD-16
**Screens:** None

**Acceptance Criteria:**

**Given** unsealed events
**When** the sealer runs under `gk_sealer`
**Then** it assigns `epoch`, `seq`, `prev_hash` and `hash` over the RFC 8785 envelope, one chain per Tenant plus one Deployment chain, with a 5-second target

**Given** a sealed envelope
**When** any role tries to change it
**Then** the database refuses it

**Given** a sign-in flood
**When** events arrive
**Then** writers don't serialize on a chain head

### Story 7.2: Copy evidence off the server

As the Operator,
I want security events held where the server can't rewrite them,
So that an intruder can't erase the evidence.

**Requirements:** FR-40, AR-28; AD-17
**Screens:** None

**Acceptance Criteria:**

**Given** sealed security events, revocations and chain heads
**When** the worker ships them
**Then** they arrive within 60 seconds, signed, in an Object Lock bucket in compliance mode

**Given** the server's credential
**When** it tries to delete or shorten retention
**Then** it's refused

**Given** the replayable event table
**When** an event is shipped
**Then** it carries internal IDs only and no personal data

### Story 7.3: Verify chains and apply retention

As the Operator,
I want a verification command and safe retention,
So that I can prove the Logs are intact.

**Requirements:** FR-40, NFR-15; AD-16; §5.2
**Screens:** None

**Acceptance Criteria:**

**Given** `gatekeep audit verify`
**When** a row is altered or missing
**Then** it reports the position

**Given** retention under `gk_retention`
**When** whole sealed ranges expire
**Then** they're deleted and a checkpoint carrying the last hash is written

**Given** the retention constant
**When** a test reads it
**Then** it meets the §5.2 floor, and no route, setting or Cli command changes it

**Given** an erased User
**When** `gatekeep audit verify` runs
**Then** the chain still verifies

**Given** a deleted Tenant
**When** its retention ends
**Then** an Operation purges its chain

### Story 7.4: Search a Tenant's Logs

As an Admin,
I want to filter events,
So that I can find what happened.

**Requirements:** FR-40, UX-DR12, UX-DR44
**Screens:** Logs (L1104) in `Gatekeep Admin.dc.html`, without Live, Log streams or query bar

**Acceptance Criteria:**

**Given** a field and value
**When** the search runs
**Then** it filters indexed envelope columns, and a User or email search resolves to the internal reference first

**Given** a Tenant
**When** Logs loads
**Then** no event from another Tenant is returned, and rejected cross-Tenant attempts appear

**Given** any route
**When** a role tries to change or delete a Log
**Then** no such route exists

### Story 7.5: Open an event's raw detail

As a Tenant Editor,
I want the raw event,
So that I can investigate.

**Requirements:** FR-40, FR-39, UX-DR18
**Screens:** Logs · Event drawer (`logOpen` L1131) in `Gatekeep Admin.dc.html`

**Acceptance Criteria:**

**Given** an Editor or Owner
**When** a row opens
**Then** the drawer shows code badge, summary rows and raw JSON with Copy

**Given** a Viewer
**When** they call the detail endpoint
**Then** the server returns summary only

### Story 7.6: View a User's history

As an Admin,
I want to see a User's recent events,
So that I can understand what happened to an account.

**Requirements:** FR-30, FR-40
**Screens:** User · History (`ut.history` L718) in `Gatekeep Admin.dc.html`

**Acceptance Criteria:**

**Given** History
**When** a Viewer opens it
**Then** they see summaries and no raw personal detail

**Given** an Editor
**When** a row opens
**Then** the drawer shows raw detail

### Story 7.7: Search the Deployment Log

As a Deployment Owner,
I want Deployment-level events,
So that I can see what happened above any Tenant.

**Requirements:** FR-40
**Screens:** Deployment Log (Spec only), composed from Logs (L1104) in `Gatekeep Admin.dc.html`

**Acceptance Criteria:**

**Given** a Deployment Owner
**When** the page opens
**Then** bootstrap, Admin sign-in, recovery, Tenant, upgrade, restore and configuration events are searchable, tested by fixture for events not yet built

**Given** any other Admin or a machine principal
**When** it calls the route
**Then** it's refused

### Story 7.8: Plant canaries and publish the event catalogue

As the Operator,
I want proof that no secret reaches a log,
So that the rule stays true as features are added.

**Requirements:** FR-40, NFR-3, AR-33, AR-39; AD-16, AD-24
**Screens:** None

**Acceptance Criteria:**

**Given** canary values planted through each flow
**When** the scan runs across Logs, operational logs and the database
**Then** any raw hit fails the build

**Given** a new flow
**When** it's registered with no canary
**Then** the build fails

**Given** the event catalogue
**When** the build runs
**Then** it's generated into `docs/`, and a changed code fails as a contract break

**Given** each FR-40 event class
**When** its flow runs
**Then** a test shows an event with a catalogued code in that Tenant's Log, and email change and Management API grant classes sit on a pending list that Story 16.8 and Story 17.2 close

**Given** planted canaries
**When** each flow is forced to fail with debug logging on
**Then** no error response or debug output holds a raw value

## Epic 8: Admin team and Tenant settings

Esm invites Admins with Tenant Roles, configures Tenants and exports configuration.

### Story 8.1: Configure the Deployment email provider

As a Deployment Owner,
I want one email provider for Deployment messages,
So that Admin invites can be sent.

**Requirements:** FR-39, FR-46, AR-44; AD-10, AD-31
**Screens:** Deployment email provider (Spec only), composed from Email & SMS providers (`GEN.providers` L1290) in `Gatekeep Admin.dc.html`
**Creates tables:** `deployment_email_provider`

**Acceptance Criteria:**

**Given** provider credentials
**When** a Deployment Owner saves them with a fresh assertion
**Then** they are Transit ciphertext under `dep-email`, and `Host.Admin` can't decrypt them

**Given** any other Admin or a machine principal
**When** it calls the route
**Then** it is refused

**Given** a change
**When** it commits
**Then** the Deployment Log is written

**Given** a test send
**When** it runs as an Operation
**Then** the result shows inline, and no credential appears in any log

### Story 8.2: Invite an Admin

As a Deployment Owner,
I want to invite another Admin,
So that I don't work alone in the Dashboard.

**Requirements:** FR-39, FR-46, AR-30; AD-31
**Screens:** Team & audit (`GEN.team` L1296) in `Gatekeep Admin.dc.html`, as Admins, without the Audit log tab
**Creates tables:** `admin_invite`

**Acceptance Criteria:**

**Given** the Deployment email provider
**When** an invite is sent
**Then** a Deployment-wide job sends it, and the link waits in `admin_invite` as Transit ciphertext and is erased once sent

**Given** an invite grant
**When** it's confirmed
**Then** a fresh assertion is required, and machine principals are refused

**Given** any other Admin
**When** they call the route
**Then** it's refused

### Story 8.3: Accept an invite and set up credentials

As an invited Admin,
I want to accept and register WebAuthn,
So that I can reach the Tenants I was given.

**Requirements:** FR-39, FR-46
**Screens:** Admin invite acceptance, Admin credential setup (both Spec only)

**Acceptance Criteria:**

**Given** an invite
**When** it's used, expired past §5.2, or for a different email
**Then** Generic error shows

**Given** a valid invite
**When** it's accepted
**Then** the Admin can't leave setup until they've two credentials, or one and an offline Recovery Code

**Given** repeated attempts
**When** the limit is passed
**Then** they're limited through `admin_attempt`

**Given** the invite artifact
**When** this story ships
**Then** its cross-Tenant case runs, and it leaves the Story 1.31 pending list

### Story 8.4: Manage Tenant Roles and remove Admins

As a Deployment Owner,
I want to change and remove Admin access,
So that access follows who actually needs it.

**Requirements:** FR-39, FR-46, AR-15, UX-DR22; AD-20
**Screens:** Team & audit (`GEN.team` L1296) in `Gatekeep Admin.dc.html`, as Admins

**Acceptance Criteria:**

**Given** a role change
**When** the matrix test runs
**Then** each role is denied each action outside the FR-39 matrix, server-side

**Given** the last Deployment Owner
**When** removal is attempted
**Then** it's refused

**Given** "Reset credentials"
**When** it's used
**Then** a single-use enrolment is shown once through `RevealOnce`, stored only hashed in `admin_enrolment` with the §5.2 lifetime, and the Deployment Log is written

**Given** a removal
**When** it is confirmed
**Then** that Admin's sessions end at once, and Story 17.4 adds the list of their Management API clients

**Given** a role grant or Admin removal with no assertion inside §5.2
**When** it is submitted
**Then** the server refuses it

**Given** the last Deployment Owner
**When** their role is lowered
**Then** it is refused

**Given** an Admin whose Tenant Role was removed mid-session
**When** their next request arrives
**Then** they return to the landing page with a `banner`

### Story 8.5: Configure Tenant settings

As a Tenant Editor,
I want to set a Tenant's details and session rules,
So that it behaves as its project needs.

**Requirements:** FR-10, FR-17, UX-DR44; §5.2
**Screens:** Tenant (`GEN.tenant` L1294) in `Gatekeep Admin.dc.html`, with session lifetimes from Tenant security (`GEN.tenantsec` L1276)

**Acceptance Criteria:**

**Given** display name, support contact, session lifetimes, default audience, error page and terms URL
**When** saved
**Then** each change applies to that Tenant only and writes to the Log

**Given** a value over a §5.2 limit
**When** saved
**Then** it's refused by the server

**Given** a custom error page
**When** it's shown
**Then** it receives only an error code and trace ID

**Given** the email verification off option
**When** a Tenant isn't Dev
**Then** it isn't available

### Story 8.6: Export Tenant configuration

As a Tenant Editor,
I want a readable configuration file,
So that I can review or keep a record of a Tenant's setup.

**Requirements:** FR-41
**Screens:** Tenant (`GEN.tenant` L1294) in `Gatekeep Admin.dc.html`

**Acceptance Criteria:**

**Given** Export
**When** it's used
**Then** a readable file downloads

**Given** the file
**When** the canary scan runs
**Then** it holds no secret, private key or credential-equivalent value

**Given** a Viewer
**When** they call the route
**Then** it's refused

## Epic 9: Signing Key operations

A Tenant Owner rotates or revokes keys with no manual follow-up (UJ-3).

### Story 9.1: View Signing Keys

As an Admin,
I want to see a Tenant's keys and JWKS,
So that I know their state.

**Requirements:** FR-37, UX-DR44
**Screens:** Signing keys (`GEN.keys` L1277) in `Gatekeep Admin.dc.html`, without Expires, with Retired added

**Acceptance Criteria:**

**Given** a Tenant
**When** the page opens
**Then** states show next, current, previous, retired and revoked, with key IDs in mono with Copy

**Given** any response
**When** it's inspected
**Then** it has no private material and no `management` key in the public JWKS sample

### Story 9.2: Rotate a Signing Key on demand

As a Tenant Owner,
I want to rotate now,
So that I can replace a key without waiting.

**Requirements:** FR-37; AD-11
**Screens:** Signing keys (`GEN.keys` L1277) in `Gatekeep Admin.dc.html`

**Acceptance Criteria:**

**Given** a `next` key aged at least 15 minutes
**When** the Owner rotates
**Then** it's promoted and a replacement `next` is created in one command, and a Log event is written

**Given** a younger `next` key
**When** rotation is requested
**Then** it's refused with the time remaining

**Given** an Editor or machine principal
**When** it attempts rotation
**Then** it's refused

### Story 9.3: Revoke a Signing Key

As a Tenant Owner,
I want to revoke a compromised key,
So that tokens it signed stop being trusted (UJ-3).

**Requirements:** FR-38, FR-46, AR-23; AD-11; UJ-3
**Screens:** Signing keys (`GEN.keys` L1277), Confirmation modal (L1233) in `Gatekeep Admin.dc.html`

**Acceptance Criteria:**

**Given** a revoke
**When** it's confirmed with a fresh assertion
**Then** the key leaves the JWKS at once, a job destroys its private material, and failure retries

**Given** the `current` key is revoked
**When** it commits
**Then** `next` is promoted even if unaged, the Log records that, and a new `next` is created

**Given** the modal
**When** it opens
**Then** it states token impact and offers Session and refresh token revocation through `RevokeAccess`

**Given** a token forged with the revoked key
**When** a fixture resource server in `tests/Protocol` validates it after the JWKS cache limit
**Then** it's rejected

**Given** a failure
**When** the command rolls back
**Then** a `banner` shows the trace ID, the key is unchanged, and other Tenants are untouched

## Epic 10: Attack protection

Sign-in resists guessing, floods and breached passwords.

### Story 10.1: Back off repeated failures per step

As a User,
I want guessing against my account slowed,
So that an attacker can't work through passwords or codes.

**Requirements:** FR-28, NFR-6, AR-26; AD-14
**Screens:** None

**Acceptance Criteria:**

**Given** password, TOTP, Recovery Code, email code and Passkey steps
**When** failures occur
**Then** limits apply separately per step, per account and per source, and survive a new challenge, with the email code step listed as pending until Story 14.6

**Given** a failed-attempt limit
**When** a valid Passkey is used
**Then** it isn't blocked

**Given** two Tenants
**When** one is attacked
**Then** counters are `UNLOGGED` `tenant` rows, and the other Tenant's limits are unaffected

**Given** a flood
**When** it hits `Host.Hosted`
**Then** the in-memory per-source limit rejects it before PostgreSQL

### Story 10.2: Configure attack protection

As a Tenant Owner,
I want to set thresholds,
So that protection suits each project.

**Requirements:** FR-28, FR-29, UX-DR44; §5.2
**Screens:** Attack protection (L862) in `Gatekeep Admin.dc.html`, brute-force and breached detection only

**Acceptance Criteria:**

**Given** a threshold over the hard limit or set to off
**When** saved
**Then** it's refused by the server

**Given** the page
**When** it renders
**Then** breached detection shows as always on, with no Notify only option

**Given** a threshold within limits
**When** it is saved
**Then** that Tenant's backoff uses it, and other Tenants are unchanged

### Story 10.3: Show lockout states honestly

As a User,
I want a clear message only when it's safe,
So that I know what to do and attackers learn nothing.

**Requirements:** FR-28, NFR-20, FR-36
**Screens:** Brute-force lockout (L366) in `Gatekeep Hosted Login.dc.html`, as Account locked, without the unlock link

**Acceptance Criteria:**

**Given** invalid credentials
**When** the account is locked
**Then** the User sees the same generic failure

**Given** valid credentials on a backed-off account
**When** they're submitted
**Then** Account locked shows an absolute retry time

**Given** lockout emails
**When** they're sent
**Then** they're rate limited per recipient and can't undo an Admin block

**Given** a lockout
**When** it occurs
**Then** the Log is written through a `FailureContext`

### Story 10.4: Protect the hashing budget

As the Operator,
I want password hashing bounded,
So that one Tenant under attack can't stop sign-in for the others.

**Requirements:** NFR-6, NFR-2, AR-26; AD-14
**Screens:** None

**Acceptance Criteria:**

**Given** Argon2id work
**When** it runs
**Then** it passes through a Deployment-wide semaphore with per-Tenant shares and a reserved floor

**Given** a queue overflow
**When** a request is refused
**Then** it gets the generic failure, revealing no account state

**Given** one Tenant at saturation
**When** another Tenant signs in
**Then** a test shows its floor is honoured

**Given** a failed sign-in spike
**When** it's detected
**Then** limits tighten and an event is written

### Story 10.5: Refuse breached passwords

As a User,
I want known-breached passwords refused,
So that my account doesn't start exposed.

**Requirements:** FR-29, AD-24; AR-25
**Screens:** Signup · password strength (L80), Reset password (L242) in `Gatekeep Hosted Login.dc.html`

**Acceptance Criteria:**

**Given** a breached password at sign-up or reset, with change listed as pending until Epic 16
**When** it's submitted
**Then** "This password appeared in a data breach." shows and the Log is written

**Given** the check
**When** it runs
**Then** it reads a read-only local file in `Host.Hosted`, and a network test shows no password leaves the process

### Story 10.6: Stop sign-in with a breached password

As a User whose password appeared in a breach,
I want to prove myself and replace it,
So that the leaked password can't be used against me.

**Requirements:** FR-29, FR-25, UX-DR43
**Screens:** Breached password warning (L376) in `Gatekeep Hosted Login.dc.html`, with the local-dataset copy

**Acceptance Criteria:**

**Given** a correct but breached password
**When** it's submitted
**Then** no Session or token exists, and the User verifies a Factor or gets a reset link

**Given** a verified Factor
**When** a new password is set
**Then** sign-in continues, and with a reset link it ends at Password changed

**Given** the screen
**When** it renders
**Then** the k-anonymity sentence is absent

**Given** a correct but breached password at sign-in
**When** it is detected
**Then** the Log is written

### Story 10.7: Prove identifiers can't be enumerated

As the Operator,
I want timing and content tested,
So that the no-enumeration claim holds as code changes.

**Requirements:** NFR-20, NFR-11; AD-24
**Screens:** None

**Acceptance Criteria:**

**Given** sign-in, sign-up, reset and verification, with email code listed as pending until Story 14.6
**When** known and unknown identifiers are compared
**Then** content, status and next step match, and timing is within the stated tolerance recorded in the test

**Given** a new credential endpoint
**When** it's registered
**Then** the build fails until it's in the test

### Story 10.8: Replace a flagged credential at sign-in

As a User whose credential must be replaced,
I want to prove myself and set a new one before I'm signed in,
So that anything taken in an incident stops working, and an attacker can't do this for me.

**Requirements:** FR-50, FR-4, FR-25, FR-26, FR-48, NFR-20; AD-17, AD-30
**Screens:** Password reset required, Authenticator reset required (both Spec only); TOTP · scan QR (L159), Reset password (L242), Password changed (L252) in `Gatekeep Hosted Login.dc.html`

**Acceptance Criteria:**

**Given** `user.password_reset_required` and `user.totp_reset_required`
**When** this story ships
**Then** both columns exist, and either one stops a Session being issued until it's cleared

**Given** a User with `password_reset_required` and a correct password
**When** they submit it
**Then** Password reset required shows, offering each enrolled proof plus "Email me a reset link", and no Session or token exists

**Given** an incorrect password or an unknown account
**When** it's submitted
**Then** the response is the usual generic failure, so the screen shows only after valid credentials

**Given** a verified proof
**When** the User sets a new password that passes policy and breach checks
**Then** the requirement clears, `RevokeAccess` runs, a notification is sent, and sign-in continues

**Given** the reset link
**When** it's used, or any other reset completes, including Forgot password
**Then** the requirement clears, and the flow ends at Password changed with no Session

**Given** a User with `totp_reset_required` past the first factor
**When** Authenticator reset required shows
**Then** the old TOTP code, a Recovery Code or another enrolled Factor is accepted once, only to reach TOTP setup, and email is never offered

**Given** a new TOTP seed
**When** it's confirmed
**Then** the old seed stops working, the requirement clears, and Recovery Codes aren't reissued

**Given** proof already given in this sign-in, or a Passkey sign-in
**When** the next required step starts
**Then** no further proof is asked for

**Given** a User holding neither credential
**When** a flag would be set
**Then** it isn't, and that User sees no step

**Given** social and email code sign-in
**When** this story ships
**Then** they're on a code-owned pending list that Story 14.2, Story 14.3 and Story 14.6 close

**Given** the FR-25 matrix
**When** it runs
**Then** both steps are registered, and each ends with a verified second factor or an FR-27 Recovery Code

**Given** repeated failed proof
**When** the limit is passed
**Then** the existing per-step backoff applies, and the Log is written

## Epic 11: Security Alerts and health

Esm hears about trouble outside the Deployment and can see its status.

### Story 11.1: Derive Security Alerts from audit events

As the Operator,
I want listed events to alert me outside the Deployment,
So that I learn of danger even if the server is compromised.

**Requirements:** FR-45, AR-28; AD-17
**Screens:** None

**Acceptance Criteria:**

**Given** the alert table in Notifications
**When** a batch is sealed
**Then** one alert job per match is enqueued under `gk_sealer`, keyed on event ID, so an alert can't precede its event

**Given** Admin added or raised, FR-5 recovery, key rotation or revocation, a failed key destruction, a `dead` job, MFA lowered, email provider changed and Prod callback added, with Management API grant and restore on a code-owned pending list
**When** each event occurs
**Then** a test shows its alert fires through `IAlertChannel`

**Given** a failing channel
**When** delivery fails
**Then** alert jobs retry with capped backoff and never go `dead`

**Given** an alert payload
**When** it's sent
**Then** it holds no credential-equivalent value

**Given** a Deployment email provider change
**When** its event is sealed
**Then** a test shows the Security Alert fires

### Story 11.2: Raise threshold and device alerts

As the Operator,
I want alerts on patterns,
So that I hear about attacks, not only single events.

**Requirements:** FR-45, NFR-6, NFR-21; AD-10, AD-26
**Screens:** None

**Acceptance Criteria:**

**Given** refresh token reuse above a threshold or a failed sign-in spike
**When** it's detected
**Then** an event is written and its alert fires

**Given** an Admin sign-in from a new device
**When** it completes
**Then** an alert fires

**Given** a Log verification failure
**When** `gatekeep audit verify` reports it
**Then** an alert fires

**Given** an unexpected certificate
**When** Certificate Transparency monitoring sees it
**Then** an alert fires

**Given** a decrypt rate above threshold for one host
**When** it's detected from the OpenBao audit output
**Then** an alert fires

### Story 11.3: Detect a silent Deployment

As the Operator,
I want a dead-man's check,
So that a stopped or stalled server still raises an alarm.

**Requirements:** AR-28, AR-35, NFR-10; AD-17, AD-32
**Screens:** None

**Acceptance Criteria:**

**Given** the heartbeat
**When** it's sent
**Then** it carries the latest sealed and shipped positions, oldest unsealed age and oldest undelivered alert age

**Given** stopped heartbeats or sealing lag above 60 seconds
**When** the external check runs
**Then** it raises an alert

**Given** external probes per Prod Tenant and certificate expiry checks
**When** they're configured from the docs
**Then** a failed probe alerts without the Deployment's help

### Story 11.4: Collect health and rate-limit usage

As the Operator,
I want status recorded,
So that the Dashboard shows the truth.

**Requirements:** FR-6, AR-35; AD-14, AD-32
**Screens:** None
**Creates tables:** `service_status`, `rate_usage`

**Acceptance Criteria:**

**Given** `Host.Worker`
**When** it polls `/healthz`
**Then** it writes `service_status` with a timestamp, and a stale row reads as unknown

**Given** rate counters and in-memory rejections
**When** the minute job runs
**Then** they roll up into `rate_usage`, keyed by Tenant

**Given** external monitoring
**When** it reads the health signal
**Then** the response holds no sensitive detail

**Given** the email provider
**When** the worker checks it
**Then** its status is recorded for the Dashboard

### Story 11.5: Show Health & rate limits

As an Admin,
I want status on one page,
So that I can see whether Gatekeep is healthy.

**Requirements:** FR-6, UX-DR21, UX-DR44
**Screens:** Health & rate limits (`GEN.health` L1293) in `Gatekeep Admin.dc.html`, without Region, Log streams, Custom domains or uptime rows

**Acceptance Criteria:**

**Given** the page
**When** it opens
**Then** it shows service status, email provider status and per-Tenant rate-limit usage, with zero shown as 0

**Given** a status fetch failure
**When** it occurs
**Then** a `banner` shows, with the trace ID and Retry

**Given** another Tenant's usage
**When** it's requested
**Then** it's refused

## Epic 12: Backup, restore and upgrade

Esm upgrades safely and recovers onto clean hardware (UJ-4).

### Story 12.1: Back up the Deployment

As the Operator,
I want nightly off-server backups,
So that I can recover from any failure.

**Requirements:** FR-4, NFR-3, NFR-13, AR-29; AD-18
**Screens:** None

**Acceptance Criteria:**

**Given** the nightly job
**When** it runs
**Then** a pgBackRest encrypted set, WAL archive and OpenBao snapshot reach off-server storage, recorded in one manifest with version, timestamp and Master Key generation

**Given** a backup without the Master Key
**When** it's examined
**Then** no secret or private key can be read

**Given** the server's credential
**When** it tries to delete or overwrite a backup inside retention
**Then** it's refused

### Story 12.2: Restore a Deployment onto clean hardware

As the Operator,
I want to restore from backup alone,
So that a dead server isn't the end (UJ-4).

**Requirements:** FR-4, NFR-13, AR-29; AD-18, AD-31
**Screens:** None

**Acceptance Criteria:**

**Given** the off-server backup, escrowed Master Key and docs
**When** `gatekeep restore` runs on clean hardware
**Then** it succeeds within 1 hour, and credentials from backup time work

**Given** a restore
**When** it starts
**Then** it reports the backup timestamp, lost-change window and last shipped `seq`, and Tenant traffic is refused until it ends

**Given** a backup with incomplete bootstrap
**When** restored
**Then** it's refused unless given the explicit flag

### Story 12.3: Reconcile keys and end stale access after restore

As the Operator,
I want restored state made safe,
So that nothing the backup brought back can be trusted by accident.

**Requirements:** FR-4, AR-29; AD-18
**Screens:** None

**Acceptance Criteria:**

**Given** a `signing_key` row with no Transit key
**When** reconciliation runs
**Then** it moves to `revoked` and a replacement is created

**Given** no `--planned-rollback`
**When** restore runs
**Then** all Sessions, refresh tokens and Admin sessions end, and every Signing Key rotates

**Given** `--planned-rollback`
**When** restore finishes
**Then** Sessions and refresh tokens from backup time remain valid

### Story 12.4: Replay revocations after restore

As the Operator,
I want later revocations re-applied,
So that a restored backup can't bring back a dead credential.

**Requirements:** FR-4, AR-29; AD-17, AD-18
**Screens:** None

**Acceptance Criteria:**

**Given** off-server records
**When** restore reaches step 2
**Then** each signature is verified, failures are reported and skipped, and the rest are replayed

**Given** a replayed password change
**When** it applies
**Then** it sets `password_reset_required`

**Given** the end of a restore
**When** it finishes
**Then** a signed restore record names each chain's head, a new `epoch` starts, `gatekeep audit verify` accepts that break only, and a Security Alert fires

**Given** a Signing Key revoked and an Admin removed after the backup
**When** restore finishes
**Then** the key is out of the JWKS and unusable, and the Admin can't sign in

**Given** `password_reset_required` on a User whose newer password no longer works
**When** they use Forgot password
**Then** the reset clears the requirement, as Story 10.8 specifies

**Given** the restore event
**When** it is sealed
**Then** a test shows the Security Alert fires, and restore leaves the Story 11.1 pending list

**Given** a real restore
**When** it finishes
**Then** its event is in the Deployment Log, replacing the fixture in Story 7.7

### Story 12.5: Sign release images

As the Operator,
I want signed images deployed by digest,
So that an upgrade can't install a tampered release.

**Requirements:** NFR-7, AR-33; AD-25
**Screens:** None

**Acceptance Criteria:**

**Given** build and signing
**When** they run
**Then** they're separate CI jobs, the build job holds no secrets, the signing key is hardware-held, and images ship with an SBOM and are deployed by digest

**Given** the pinned public key
**When** it is installed
**Then** it lives on the server, outside the image

### Story 12.6: Upgrade between releases

As the Operator,
I want a safe upgrade command,
So that a new release can't strand me.

**Requirements:** FR-3, AR-29, AR-33; AD-18, AD-25
**Screens:** None

**Acceptance Criteria:**

**Given** no manifest under 24 hours old
**When** `gatekeep upgrade` starts
**Then** it refuses

**Given** an image whose signature fails against the pinned key
**When** upgrade runs
**Then** it refuses

**Given** a successful upgrade from the previous minor
**When** it finishes
**Then** valid Sessions and tokens survive, unless the release names a security reason

**Given** a failed upgrade
**When** the Operator follows the docs
**Then** restoring the backup on the previous version with `--planned-rollback` recovers the Deployment

**Given** a real upgrade
**When** it finishes
**Then** its event is in the Deployment Log, replacing the fixture in Story 7.7

### Story 12.7: Rotate the Master Key

As the Operator,
I want to rotate the Master Key,
So that a suspected exposure doesn't need Users to re-enrol.

**Requirements:** NFR-3; AD-10
**Screens:** None

**Acceptance Criteria:**

**Given** a seal rotation and Transit rewrap
**When** they run
**Then** Users take no action and sign-in keeps working

**Given** the escrow procedure
**When** a new generation is made
**Then** each generation stays until the last backup needing it has expired, and neither appears in a backup

**Given** the rehearsal
**When** it runs on the VM
**Then** its result is recorded in `docs/runbooks`

## Epic 13: Compromise response

Esm ends all access in one Tenant or every Tenant, following tested runbooks (UJ-6).

### Story 13.1: Revoke all access in a Tenant

As a Tenant Owner,
I want to end every Session and refresh token, and force re-enrolment,
So that a suspected leak can be cut off at once.

**Requirements:** FR-50, FR-46, AR-19, AR-23; AD-30
**Screens:** Incident response (Spec only)

**Acceptance Criteria:**

**Given** either action
**When** it's confirmed
**Then** a fresh assertion is needed, the modal states the effect, and an Operation returns `202`

**Given** forced resets
**When** the Operation runs
**Then** `password_reset_required` and `totp_reset_required` are set on each User holding that credential, and Story 10.8 enforces them

**Given** a partial failure
**When** progress shows
**Then** what didn't finish is listed, and Retry needs a new assertion

**Given** the action
**When** it finishes
**Then** the Log and Deployment Log are written, other Tenants are untouched, and machine principals are refused

### Story 13.2: Send a security notice

As a Tenant Owner,
I want to notify all Users,
So that they know what happened and what to do.

**Requirements:** FR-50, NFR-9, FR-36
**Screens:** Incident response (Spec only)

**Acceptance Criteria:**

**Given** a notice
**When** it's sent
**Then** an Operation sends to each User in that Tenant only, with recipients resolved at send time

**Given** a repeat while one is active
**When** it starts
**Then** it's refused

### Story 13.3: Respond across every Tenant

As a Deployment Owner,
I want the same actions across all Tenants, plus revoking all Signing Keys,
So that a Deployment compromise has one response.

**Requirements:** FR-50, FR-38, FR-46; AD-11, AD-30
**Screens:** Deployment incident response (Spec only)

**Acceptance Criteria:**

**Given** the action
**When** it runs
**Then** it's one Operation with one `operation_step` per Tenant, each in its own `TenantScope`

**Given** revoke all Signing Keys
**When** it completes
**Then** new keys of both purposes exist per Tenant in the same Operation

**Given** any other Admin or machine principal
**When** it calls the route
**Then** it's refused

**Given** the Deployment-wide action
**When** it is confirmed
**Then** a fresh assertion is needed, and the Log and Deployment Log are written

### Story 13.4: Replace every key and secret with `gatekeep rekey`

As the Operator,
I want a tested rebuild procedure,
So that every credential an intruder could read is dead (UJ-6).

**Requirements:** AR-29; AD-18; UJ-6
**Screens:** None

**Acceptance Criteria:**

**Given** a restored Deployment
**When** `gatekeep rekey` runs
**Then** Signing Keys, provider and email credentials and the Master Key are replaced, and it lists what the Operator must replace by hand

### Story 13.5: Write and test the security runbooks

As the Operator,
I want tested runbooks,
So that an incident is never the first time I think about it.

**Requirements:** NFR-9, AR-35; AD-32
**Screens:** None

**Acceptance Criteria:**

**Given** `docs/runbooks`
**When** they're reviewed
**Then** they cover notification updates when the scope widens, forced re-enrolment, vulnerability intake, the 7-day critical fix, 72-hour notification, UJ-3, UJ-6, TLS and Master Key replacement, and reaching Users if Gatekeep is down

**Given** both server and escrowed Master Key are lost
**When** the runbook is followed
**Then** Users re-enrol and all keys are replaced

**Given** a release
**When** it is published
**Then** the security contact and intake route are visible in its docs

### Story 13.6: Rehearse emergency certificate replacement

As the Operator,
I want certificate replacement rehearsed,
So that a leaked certificate key has a known fix.

**Requirements:** NFR-21; AD-26
**Screens:** None

**Acceptance Criteria:**

**Given** emergency certificate replacement
**When** it's rehearsed
**Then** the result is recorded

## Epic 14: Social and email code sign-in

Users sign in with Google, GitHub, Microsoft or an emailed code.

### Story 14.1: Configure social providers

As a Tenant Owner,
I want to add each provider's credentials,
So that a Tenant can offer social sign-in with its own keys.

**Requirements:** FR-20, FR-14, UX-DR44; AD-10, AD-26, AD-30
**Screens:** Social (L517) in `Gatekeep Admin.dc.html`, Google, GitHub and Microsoft only, without dev keys

**Acceptance Criteria:**

**Given** provider credentials
**When** an Owner saves them
**Then** they're Transit ciphertext under `social`, and `Host.Admin` can't decrypt them

**Given** an Editor
**When** they toggle a Connection
**Then** it saves, and credentials stay "Tenant Owner only"

**Given** Test connection
**When** it runs as an Operation
**Then** the provider's error code shows, and egress goes only to code-owned endpoints

**Given** social provider credentials
**When** `gatekeep rekey` runs
**Then** they are on its list to replace

### Story 14.2: Sign in with Google or Microsoft

As a User,
I want to continue with my provider,
So that I needn't create a password.

**Requirements:** FR-20, FR-30, FR-47; AD-21, AD-29
**Screens:** Login · identifier first (L39) in `Gatekeep Hosted Login.dc.html`; Social return (Spec only)
**Creates tables:** `external_identity`

**Acceptance Criteria:**

**Given** a provider button
**When** it's pressed
**Then** the browser leaves by top-level GET, with `state`, `nonce` and PKCE

**Given** a return
**When** `state` or the transaction doesn't match
**Then** it's refused

**Given** a returning identity
**When** it's matched
**Then** it matches `external_identity` on provider issuer and subject, never on email

**Given** a provider cancel or failure
**When** it returns
**Then** cancel goes to Login with no error, and failure shows Generic error

**Given** policy Always
**When** social sign-in succeeds
**Then** the second factor step still applies

**Given** User · Details
**When** a User has a social identity
**Then** it is listed, with no provider token

**Given** a User with a reset requirement
**When** this sign-in succeeds
**Then** the Story 10.8 proof step applies before any Session, and this path leaves its pending list

### Story 14.3: Sign in with GitHub

As a User,
I want to continue with GitHub,
So that I can use the account I already have.

**Requirements:** FR-20, FR-47; AD-29
**Screens:** Login · identifier first (L39) in `Gatekeep Hosted Login.dc.html`; Social return (Spec only)

**Acceptance Criteria:**

**Given** GitHub, which has no ID token
**When** a sign-in runs
**Then** it uses single-use `state` and PKCE, with no `nonce`, under the FR-47 exception for providers without OIDC

**Given** a GitHub identity
**When** it is stored
**Then** `external_identity` uses a code-owned constant issuer and the numeric subject, never the email

**Given** a GitHub return
**When** `state` or the transaction does not match
**Then** it is refused

**Given** a User with a reset requirement
**When** this sign-in succeeds
**Then** the Story 10.8 proof step applies before any Session, and this path leaves its pending list

### Story 14.4: Handle social email conflicts

As a User,
I want a safe outcome when my email already has an account,
So that no attacker can link to it.

**Requirements:** FR-20, NFR-20
**Screens:** Social email conflict, Social return (both Spec only)

**Acceptance Criteria:**

**Given** a provider with no verified email
**When** it returns
**Then** sign-in is refused with "We couldn't confirm your email with {provider}."

**Given** a verified email matching an existing User
**When** it returns
**Then** no account is created or linked, and the neutral conflict shows a path to the existing method

**Given** `email_verified`
**When** tokens are issued
**Then** it's true only when the provider asserted it

### Story 14.5: Configure the email code Connection

As a Tenant Editor,
I want to enable email code,
So that Users can sign in without a password.

**Requirements:** FR-22, FR-14, UX-DR44
**Screens:** Passwordless (`GEN.passwordless` L1267) in `Gatekeep Admin.dc.html`, as Email code, without SMS or magic link

**Acceptance Criteria:**

**Given** the page
**When** it renders
**Then** Enabled and "creates accounts" are the only settings, and §5.2 values are fixed

**Given** no provider
**When** it's enabled
**Then** a `banner` links to Email provider

### Story 14.6: Sign in with an email code

As a User,
I want a code by email,
So that I can sign in on a borrowed machine.

**Requirements:** FR-22, FR-25, NFR-6, NFR-20, UX-DR26; AD-24, FR-28
**Screens:** Email / SMS code entry (L123) in `Gatekeep Hosted Login.dc.html`, email only

**Acceptance Criteria:**

**Given** any address
**When** a code is requested
**Then** the screen and attempt countdown are identical whether or not one was sent

**Given** a code
**When** it's stored
**Then** it's an HMAC under the Tenant's Transit key, single-use, with §5.2 expiry and attempts

**Given** a resend
**When** it's used
**Then** the attempt count isn't reset

**Given** policy Always
**When** a code succeeds
**Then** the MFA challenge follows, because an email code is never a second factor

**Given** "creates accounts" off
**When** an unknown address is used
**Then** nothing is sent and the screen is the same

**Given** repeated code requests across addresses
**When** the limit is passed
**Then** they are limited per Tenant and per source, with an identical screen

**Given** the email code step
**When** this story ships
**Then** it leaves the pending lists in Story 10.1 and Story 10.7, and its cross-Tenant artifact case runs

**Given** a User with Factors
**When** an email code sign-in completes
**Then** every Factor and Passkey is unchanged, and this path leaves the Story 6.12 pending list

**Given** a User with a reset requirement
**When** this sign-in succeeds
**Then** the Story 10.8 proof step applies before any Session, and this path leaves its pending list

## Epic 15: Branding and email

Hosted Login and email carry each Tenant's identity.

### Story 15.1: Validate and publish a Tenant theme

As a Tenant Editor,
I want to set a primary colour, font and radius,
So that sign-in looks like my project and stays readable.

**Requirements:** FR-34, NFR-16, UX-DR35, AR-32; AD-21, AD-22
**Screens:** Universal Login (L999) in `Gatekeep Admin.dc.html`, as Hosted Login, without widget position, background, Advanced or custom domain
**Creates tables:** `tenant_theme`

**Acceptance Criteria:**

**Given** a theme
**When** it's published
**Then** every DESIGN.md contrast check passes in both schemes, or publishing is refused naming the pair and scheme

**Given** an arbitrary string as a colour, font or radius
**When** it's submitted
**Then** typed allowlists refuse it, so theming can't inject CSS or script

**Given** a draft
**When** it's saved
**Then** published Users see no change until Publish, and CSS is served same-origin with a content hash

**Given** a Prod Tenant's theme change
**When** it commits
**Then** the Log is written

### Story 15.2: Preview a theme on real screens

As a Tenant Editor,
I want to preview before publishing,
So that I can catch problems safely.

**Requirements:** FR-34; AD-21
**Screens:** Universal Login · Preview screens (`us.login` L1028 to `us.error` L1089) in `Gatekeep Admin.dc.html`: login, signup, MFA, reset and error only

**Acceptance Criteria:**

**Given** a draft
**When** preview opens
**Then** `packages/hosted-screens` components render with draft CSS under a scope selector, in both schemes

**Given** preview
**When** it renders
**Then** consent and org picker aren't shown, and no third-party request occurs

### Story 15.3: Upload a logo safely

As a Tenant Editor,
I want to add a logo,
So that Users recognise the sign-in page.

**Requirements:** FR-34, AR-32; AD-21
**Screens:** Universal Login (L999) in `Gatekeep Admin.dc.html`
**Creates tables:** `tenant_asset`

**Acceptance Criteria:**

**Given** a PNG or SVG up to 1 MB and at least 64×64
**When** it's uploaded
**Then** it's stored in `tenant_asset`, and SVG is rasterized by a job and never served as SVG

**Given** a served logo
**When** it's requested
**Then** it's same-origin with a hashed URL, `nosniff` and the sanitized type

**Given** an SVG with script
**When** it's uploaded
**Then** no script survives

### Story 15.4: Edit email templates

As a Tenant Editor,
I want to edit the five templates,
So that emails sound like my project without weakening them.

**Requirements:** FR-36, UX-DR44
**Screens:** Email templates (`GEN.emails` L1289) in `Gatekeep Admin.dc.html`, five templates, no Liquid

**Acceptance Criteria:**

**Given** a reset, verification or code template
**When** the system link or code is missing or its destination changes
**Then** Save is blocked, naming the variable

**Given** an unknown variable or remote content
**When** it's saved
**Then** it's refused, and no template can read another Tenant's data

**Given** a preview
**When** it renders
**Then** it's text only

### Story 15.5: Test delivery and guarantee security notifications

As a Tenant Admin,
I want to test email and rely on notifications,
So that I know Users hear about changes to their accounts.

**Requirements:** FR-36; AD-30
**Screens:** Email & SMS providers (`GEN.providers` L1290), Email templates (`GEN.emails` L1289) in `Gatekeep Admin.dc.html`

**Acceptance Criteria:**

**Given** a test send
**When** it runs as an Operation
**Then** it reports SPF, DKIM and DMARC state

**Given** a test send
**When** the limit is passed
**Then** it's rate limited per recipient

**Given** the notifications built so far
**When** each flow runs
**Then** a test shows a notification is sent, and no setting disables it

## Epic 16: Account Portal

Users manage their own profile, credentials and Sessions.

### Story 16.1: Build Hosted overlays and Portal feedback

As a developer,
I want toast, banner and modal in the Hosted theme,
So that the Portal uses the same feedback as the Dashboard.

**Requirements:** NFR-16, UX-DR15, UX-DR16, UX-DR36; AD-22
**Screens:** Self-service account portal (L421) in `Gatekeep Hosted Login.dc.html`

**Acceptance Criteria:**

**Given** Hosted toast
**When** it shows
**Then** it is a `role="status"` region that stays until the next action, and never covers the focused control

**Given** Hosted modal and banner
**When** they render
**Then** they use Admin sizes in the Hosted theme and add no third-party dependency

### Story 16.2: Open the Account Portal and edit a profile

As a User,
I want my own account area,
So that I can keep my details current.

**Requirements:** FR-35, AR-37, UX-DR36, UX-DR43; AD-12
**Screens:** Self-service account portal (L421) in `Gatekeep Hosted Login.dc.html`, Profile tab, without Connected apps or Privacy

**Acceptance Criteria:**

**Given** a Session cookie
**When** the Portal opens
**Then** `/account/api/*` authenticates by Session, with no OIDC client involved, and shows three tabs

**Given** no Session
**When** the Portal is requested
**Then** the normal sign-in flow runs

**Given** a Profile save
**When** the CSRF token or Origin is wrong
**Then** it's refused

**Given** a width below 768px
**When** it renders
**Then** the rail becomes tabs

**Given** any Portal response
**When** it is sent
**Then** it carries the AD-21 CSP, denies framing and sets `Referrer-Policy: no-referrer`

**Given** a Portal sign-in
**When** it runs
**Then** its transaction binds to the Tenant's system Application, and no code or token is issued

### Story 16.3: Re-prove identity for sensitive changes

As a User,
I want sensitive changes to need my strongest method,
So that a borrowed session can't take over my account.

**Requirements:** FR-35, FR-47; §5.2
**Screens:** Re-authentication (Spec only)

**Acceptance Criteria:**

**Given** email, password, Factor, Passkey, Recovery Code regeneration or deletion
**When** the last proof is older than §5.2
**Then** the strongest enrolled method is required

**Given** a stronger method enrolled
**When** a Recovery Code or email code is offered
**Then** the server refuses it

**Given** re-authentication succeeds
**When** the Session continues
**Then** its identifier rotates

**Given** repeated failed re-proof attempts
**When** the limit is passed
**Then** they back off per Tenant and per source

### Story 16.4: Change a password

As a User,
I want to change my password,
So that I can replace one I no longer trust.

**Requirements:** FR-35, FR-29, FR-47, FR-48, FR-19
**Screens:** Self-service account portal (L421) in `Gatekeep Hosted Login.dc.html`, Security tab

**Acceptance Criteria:**

**Given** a password change
**When** it commits
**Then** policy and breach checks pass, other Sessions end and the acting Session continues

**Given** a password change
**When** it commits
**Then** the Session identifier is new, the earlier one is refused, and any pending reset link shows Link expired

**Given** a breached password
**When** it is submitted
**Then** it is refused, and the pending item in Story 10.5 closes

### Story 16.5: Add and remove Passkeys and Factors

As a User,
I want to add and remove Passkeys and Factors,
So that my sign-in methods stay current.

**Requirements:** FR-35, FR-26, FR-48, UX-DR38
**Screens:** Self-service account portal (L421) in `Gatekeep Hosted Login.dc.html`, Security tab

**Acceptance Criteria:**

**Given** the last method under Always
**When** removal is attempted
**Then** it's refused with the reason

**Given** repeated actions
**When** names are read by a screen reader
**Then** each is unique, such as "Remove passkey MacBook Pro"

**Given** an added or removed method
**When** it commits
**Then** a notification is sent, and `RevokeAccess` ends other Sessions while the acting one continues

### Story 16.6: Regenerate Recovery Codes

As a User,
I want to regenerate my Recovery Codes,
So that lost codes can't be used against me.

**Requirements:** FR-35, FR-27, FR-48
**Screens:** Self-service account portal (L421) in `Gatekeep Hosted Login.dc.html`, Security tab

**Acceptance Criteria:**

**Given** regenerated Recovery Codes
**When** they're issued
**Then** the old set stops working, and codes show once

**Given** regeneration
**When** it commits
**Then** a notification is sent, and `RevokeAccess` ends other Sessions while the acting one continues

### Story 16.7: Review and end Sessions

As a User,
I want to see where I'm signed in,
So that I can end anything I don't recognise.

**Requirements:** FR-35, FR-48
**Screens:** Self-service account portal (L421) in `Gatekeep Hosted Login.dc.html`, Sessions tab

**Acceptance Criteria:**

**Given** a Session
**When** it's ended
**Then** the row disappears, and only that User's Sessions in this Tenant can be targeted

**Given** "Sign out all"
**When** it's used
**Then** every other Session ends and the current one continues

### Story 16.8: Change an email address safely

As a User,
I want to change my email with a way back,
So that an attacker can't quietly take my account.

**Requirements:** FR-35, FR-48, FR-36
**Screens:** Email change landing, Email change reversal (both Spec only)
**Creates tables:** `pending_email_change`

**Acceptance Criteria:**

**Given** a new address
**When** it's requested
**Then** it takes effect only after verification, and the old address is told

**Given** the old address's link within 72 hours
**When** it's used
**Then** the change reverses, Sessions end and sign-in is required

**Given** an expired or used link
**When** it's opened
**Then** Link expired shows

**Given** a verified email change
**When** it commits
**Then** `RevokeAccess` ends other Sessions while the acting one continues

**Given** an email change
**When** it commits
**Then** every Factor and Passkey is unchanged, the Log is written, and this path leaves the Story 6.12 pending list

**Given** the email change event class
**When** this story ships
**Then** it leaves the Story 7.8 pending list

### Story 16.9: Delete my account

As a User,
I want to delete my account,
So that I can leave.

**Requirements:** FR-35, FR-48; AD-30
**Screens:** Self-service account portal (L421) in `Gatekeep Hosted Login.dc.html`, the red panel, without the data-copy promise

**Acceptance Criteria:**

**Given** a confirmed deletion
**When** it commits
**Then** `user.deletion_requested_at` is set and `RevokeAccess` runs in one `CommandContext`

**Given** a marked User
**When** they try to sign in
**Then** Authentication refuses them

**Given** the recurring job
**When** it finds a marked User
**Then** it starts a deletion Operation whose handler re-checks the marker

### Story 16.10: Prove mandatory notifications

As an User,
I want to hear about every change to my account,
So that I notice an attacker.

**Requirements:** FR-36, FR-48
**Screens:** None

**Acceptance Criteria:**

**Given** password changed, email change requested, Factor or Passkey added or removed, Recovery Code used and Recovery Codes regenerated
**When** each occurs
**Then** a test shows a notification is sent, and no setting disables it

**Given** the FR-48 walk
**When** this epic closes
**Then** no trigger is pending

## Epic 17: Management API and developer docs

Esm automates Tenant tasks and adds sign-in from a quickstart in 30 minutes.

### Story 17.1: Issue isolated Management API tokens

As a backend job owner,
I want a Management API token that can't be forged from the public host,
So that an internet-facing flaw can't reach Admin functions.

**Requirements:** FR-42, AR-16, FR-8; AD-33; §5.2
**Screens:** None

**Acceptance Criteria:**

**Given** a client at `/api/v1/tenants/{tenantId}/oauth/token`
**When** it authenticates
**Then** the token is `at+jwt`, 15 minutes, signed by that Tenant's `management` key, with `iss` that never equals a Tenant issuer

**Given** a token signed by a `signing` key
**When** it reaches `Host.Admin`
**Then** it's rejected

**Given** a token whose Tenant differs from the path
**When** it's used
**Then** it's refused and logged

**Given** `Host.Hosted`'s OpenBao policy
**When** it tries to use the `management` key
**Then** it's refused

**Given** repeated requests to `/oauth/token`
**When** the limit is passed
**Then** they are limited per Tenant and per source

### Story 17.2: Grant and review Management API access

As a Tenant Owner,
I want to grant machine access deliberately,
So that I always know which clients can act.

**Requirements:** FR-42, FR-16, FR-46
**Screens:** API keys (`GEN.apikeys` L1297) in `Gatekeep Admin.dc.html`, as Management API, without token explorer
**Creates tables:** `client_usage`

**Acceptance Criteria:**

**Given** a grant
**When** a Tenant Owner confirms with a fresh assertion
**Then** it's logged, and `client_usage` records last use

**Given** a grant
**When** its event is sealed
**Then** a test shows the Security Alert fires, and the grant leaves the Story 7.8 and Story 11.1 pending lists

**Given** clients with access
**When** the page opens
**Then** each shows its grants and last use, and each API use is logged

### Story 17.3: Prove machine clients cannot escalate

As the Operator,
I want machine limits tested,
So that a client can't reach more than it was granted.

**Requirements:** FR-42, FR-30, AR-15; AD-20
**Screens:** None

**Acceptance Criteria:**

**Given** a client with Management access
**When** it grants a Permission or changes any client's access
**Then** it's refused

**Given** Admin management and each fresh-assertion action
**When** a machine principal calls them
**Then** a generated test shows each is refused

**Given** a Permission
**When** it's targeted at a Role
**Then** it's refused

**Given** User detail through the Management API
**When** the response is scanned
**Then** no credential-equivalent value appears

### Story 17.4: List an Admin's clients on removal

As a Deployment Owner,
I want to see a removed Admin's Management API clients,
So that no access outlives the person who set it up.

**Requirements:** FR-39, FR-42
**Screens:** Team & audit (`GEN.team` L1296) in `Gatekeep Admin.dc.html`, as Admins

**Acceptance Criteria:**

**Given** Admin removal
**When** it is confirmed
**Then** their Management API clients are listed with an offer to revoke

### Story 17.5: Publish the API reference and version contract

As a developer,
I want an accurate reference,
So that I can build against a stable contract.

**Requirements:** FR-42, FR-43, AR-14; AD-19
**Screens:** API reference (Spec only)

**Acceptance Criteria:**

**Given** a release
**When** it's built
**Then** the reference for every public API ships with it, and help opens it

**Given** an unmarked breaking change
**When** CI diffs OpenAPI
**Then** the build fails

**Given** a new major
**When** it ships
**Then** the old major stays for at least one minor release

**Given** the API reference
**When** this story ships
**Then** the top bar help control opens it

### Story 17.6: Publish the Node quickstart

As a developer,
I want a Node quickstart,
So that I can add sign-in and protect an API quickly.

**Requirements:** FR-43, FR-48, UX-DR44; UJ-1, UJ-5; SM-6
**Screens:** Application · Quickstart (`at.quickstart` L408), Quickstarts (`GEN.quickstarts` L1266) in `Gatekeep Admin.dc.html`, standard OIDC libraries only

**Acceptance Criteria:**

**Given** each quickstart
**When** it's followed
**Then** it validates signature, `iss`, `aud`, `exp` and a fixed algorithm, uses `sub`, and rejects ID tokens as access tokens

**Given** the Quickstart tab
**When** it renders
**Then** the client ID is pre-filled and no secret appears

**Given** the docs
**When** they're read
**Then** they state the residual access token window, the JWKS cache limit and the lack of Back-Channel Logout

**Given** a timed Node run
**When** it is followed
**Then** UJ-1 completes within 30 minutes, and the machine token flow of UJ-5 works

### Story 17.7: Publish the .NET quickstart

As a developer,
I want a .NET quickstart,
So that I can add sign-in and protect an API quickly.

**Requirements:** FR-43, FR-48, UX-DR44; UJ-1, UJ-5; SM-6
**Screens:** Application · Quickstart (`at.quickstart` L408), Quickstarts (`GEN.quickstarts` L1266) in `Gatekeep Admin.dc.html`, standard OIDC libraries only

**Acceptance Criteria:**

**Given** each quickstart
**When** it's followed
**Then** it validates signature, `iss`, `aud`, `exp` and a fixed algorithm, uses `sub`, and rejects ID tokens as access tokens

**Given** a timed .NET run
**When** it is followed
**Then** UJ-1 completes within 30 minutes, and the machine token flow of UJ-5 works

**Given** the quickstart docs
**When** they are read
**Then** they state the residual access token window, the JWKS cache limit and the lack of Back-Channel Logout

### Story 17.8: Publish the Python quickstart

As a developer,
I want a Python quickstart,
So that I can add sign-in and protect an API quickly.

**Requirements:** FR-43, FR-48, UX-DR44; UJ-1, UJ-5; SM-6
**Screens:** Application · Quickstart (`at.quickstart` L408), Quickstarts (`GEN.quickstarts` L1266) in `Gatekeep Admin.dc.html`, standard OIDC libraries only

**Acceptance Criteria:**

**Given** each quickstart
**When** it's followed
**Then** it validates signature, `iss`, `aud`, `exp` and a fixed algorithm, uses `sub`, and rejects ID tokens as access tokens

**Given** a timed Python run
**When** it is followed
**Then** UJ-1 completes within 30 minutes, and the machine token flow of UJ-5 works

**Given** the quickstart docs
**When** they are read
**Then** they state the residual access token window, the JWKS cache limit and the lack of Back-Channel Logout

### Story 17.9: Publish browser quickstarts

As a developer,
I want React and Next.js quickstarts,
So that a web app reaches working sign-in within 30 minutes.

**Requirements:** FR-43; SM-6
**Screens:** Application · Quickstart (`at.quickstart` L408), Quickstarts (`GEN.quickstarts` L1266) in `Gatekeep Admin.dc.html`

**Acceptance Criteria:**

**Given** a timed run
**When** a developer follows either quickstart
**Then** UJ-1 completes within 30 minutes

**Given** the code
**When** it's reviewed
**Then** it uses standard OIDC libraries and no `@gatekeep/*` package

**Given** React and Next.js
**When** the sign-in response is handled
**Then** signature, `iss`, `aud`, `exp` and a fixed algorithm are validated, and `sub` is the User key

**Given** the quickstart docs
**When** they are read
**Then** they state the residual access token window, the JWKS cache limit and the lack of Back-Channel Logout

### Story 17.10: Run the negative token pack

As the Operator,
I want bad tokens tested on every release,
So that quickstart APIs reject what they should.

**Requirements:** FR-43, FR-38, AR-33; AD-25
**Screens:** None

**Acceptance Criteria:**

**Given** the quickstart APIs
**When** the pack runs wrong Tenant, wrong audience, expired, ID token, `alg: none` and revoked key
**Then** every case is rejected

**Given** a revoked key and a token forged with it
**When** a quickstart API validates it once the §5.2 JWKS cache limit has passed since revocation
**Then** it is rejected

## Epic 18: Production readiness and cutover

v1 passes its gates and the first production app moves over.

### Story 18.1: Enforce release gates

As the Operator,
I want a release to fail unless every safety check passes,
So that nothing ships with a property untested.

**Requirements:** NFR-7, AR-33; AD-25, AD-32
**Screens:** None

**Acceptance Criteria:**

**Given** a release
**When** it builds
**Then** architecture tests, catalogue test, cross-Tenant suite, FR-25 matrix, FR-48 walk with nothing pending, canary scan, negative token pack, OpenAPI diff, dependency scan and conformance plans must all pass

**Given** the cross-Tenant artifact list, the FR-40 event class list and every other pending list
**When** a release builds
**Then** each must be empty, or the build fails

### Story 18.2: Pass OpenID conformance

As the Operator,
I want conformance recorded on the release candidate,
So that I can trust the standards claim.

**Requirements:** FR-23, AR-41; SM-4
**Screens:** None

**Acceptance Criteria:**

**Given** the release candidate
**When** Basic OP, Config OP and RP-Initiated Logout OP run
**Then** all pass, and any deviation is recorded, with no rule relaxed in a Prod Tenant

**Given** the release candidate
**When** RFC 9700 is checked
**Then** a stored result exists per requirement, with deviations recorded

### Story 18.3: Audit Hosted Login accessibility and browsers

As the Operator,
I want Hosted Login audited for accessibility and browser support,
So that real Users can complete every flow.

**Requirements:** NFR-16, NFR-17
**Screens:** Every Hosted Login and Account Portal screen in the EXPERIENCE Screen-to-PRD Map

**Acceptance Criteria:**

**Given** every Hosted Login and Portal screen
**When** the WCAG 2.2 AA audit runs in both colour schemes
**Then** no AA failure remains open at cutover

**Given** a named browser matrix
**When** every Hosted Login flow runs
**Then** each passes on desktop and mobile

### Story 18.4: Check every Design Delta row

As the Operator,
I want every Design Delta row checked,
So that nothing deferred or drifted reaches release.

**Requirements:** NFR-18, FR-33, FR-44, UX-DR43, UX-DR44, UX-DR45, UX-DR46
**Screens:** Every v1 screen in the EXPERIENCE Screen-to-PRD Map

**Acceptance Criteria:**

**Given** every Design Delta row
**When** it's checked
**Then** the removal or change is present, and no deferred control appears

### Story 18.5: Load test sign-in

As the Operator,
I want sign-in load tested,
So that it holds up at expected peak.

**Requirements:** NFR-10, NFR-11, NFR-12
**Screens:** None

**Acceptance Criteria:**

**Given** 20 sign-ins per second
**When** the load test runs at 10,000 Users
**Then** sign-in APIs are under 500ms at p95, with hashing cost excluded

### Story 18.6: Assess input, web, API and file chapters

As the Operator,
I want the input, web, API and file handling ASVS chapters assessed,
So that each has stored evidence before real Users arrive.

**Requirements:** NFR-8
**Screens:** None

**Acceptance Criteria:**

**Given** the ASVS 5.0 chapters Encoding and Sanitization, Validation and Business Logic, Web Frontend Security, API and Web Service, File Handling and WebRTC, checked against the published standard
**When** the assessment is done
**Then** each requirement in them has a stored result and evidence in `docs/`, and a requirement that does not apply is marked so with a reason

### Story 18.7: Assess authentication, session and token chapters

As the Operator,
I want the authentication, session, authorization, token and OAuth ASVS chapters assessed,
So that each has stored evidence before real Users arrive.

**Requirements:** NFR-8
**Screens:** None

**Acceptance Criteria:**

**Given** the ASVS 5.0 chapters Authentication, Session Management, Authorization, Self-contained Tokens, and OAuth and OIDC, checked against the published standard
**When** the assessment is done
**Then** each requirement in them has a stored result and evidence in `docs/`, and a requirement that does not apply is marked so with a reason

### Story 18.8: Assess crypto, data, code and logging chapters

As the Operator,
I want the cryptography, communication, configuration, data protection, secure coding and logging ASVS chapters assessed,
So that each has stored evidence before real Users arrive.

**Requirements:** NFR-8
**Screens:** None

**Acceptance Criteria:**

**Given** the ASVS 5.0 chapters Cryptography, Secure Communication, Configuration, Data Protection, Secure Coding and Architecture, and Security Logging and Error Handling, checked against the published standard
**When** the assessment is done
**Then** each requirement in them has a stored result and evidence in `docs/`, and a requirement that does not apply is marked so with a reason

### Story 18.9: Pass the security gate

As the Operator,
I want one final gate before real Users,
So that cutover can't happen with a known critical or high finding.

**Requirements:** NFR-1, NFR-8; SM-3
**Screens:** None

**Acceptance Criteria:**

**Given** a critical or high finding
**When** the gate is checked
**Then** cutover is blocked until it's fixed

**Given** the threat model
**When** the gate is checked
**Then** it matches the built product

**Given** a major release or trust boundary change
**When** the gate runs
**Then** a current assessment must exist

**Given** the full ASVS 5.0 Level 2 requirement list
**When** the gate is checked
**Then** every requirement has a stored result, or cutover is blocked

### Story 18.10: Rehearse keys and alerts

As the Operator,
I want key and alert procedures rehearsed,
So that I know they work when needed.

**Requirements:** NFR-9, AR-35; SM-5
**Screens:** None

**Acceptance Criteria:**

**Given** spare hardware
**When** the rehearsal runs
**Then** key rotation, key revocation and Security Alert delivery are each recorded in `docs/runbooks`

### Story 18.11: Rehearse install, upgrade and restore

As the Operator,
I want install, upgrade and restore rehearsed,
So that I know recovery works on clean hardware.

**Requirements:** FR-1, FR-3, FR-4, NFR-9; SM-5
**Screens:** None

**Acceptance Criteria:**

**Given** clean hardware and only the docs
**When** install and bootstrap are followed
**Then** the Admin Dashboard loads and is usable

**Given** spare hardware
**When** the rehearsal runs
**Then** a failed upgrade, a clean-hardware restore with the escrowed Master Key and revocation replay are recorded

**Given** the installed stack with no cloud egress
**When** every core flow runs
**Then** each one works

### Story 18.12: Run the UJ-6 tabletop and set the schedule

As the Operator,
I want the UJ-6 tabletop run and rehearsals scheduled,
So that compromise response stays practised.

**Requirements:** NFR-9; SM-5, UJ-6
**Screens:** None

**Acceptance Criteria:**

**Given** a failed step
**When** it's recorded
**Then** cutover waits until it passes, and the quarterly schedule is set

**Given** the UJ-6 runbook
**When** the tabletop runs
**Then** the result is recorded in `docs/runbooks`

### Story 18.13: Move the first production app

As Esm,
I want my first app on Gatekeep for real Users,
So that v1 is proven in production.

**Requirements:** SM-1, NFR-10; UJ-1
**Screens:** None

**Acceptance Criteria:**

**Given** SM-3 passed
**When** cutover runs
**Then** the app signs real Users in through a Prod Tenant, with no fallback login in use

### Story 18.14: Write the protocol walkthroughs

As the Operator,
I want a walkthrough of each protocol flow,
So that I can explain what I run.

**Requirements:** SM-7
**Screens:** None

**Acceptance Criteria:**

**Given** each v1 protocol flow
**When** Esm writes a walkthrough
**Then** it's written without reference to generated code

### Story 18.15: Review the first 90 days

As the Operator,
I want a review of the first 90 days,
So that I can judge the v2 entry condition.

**Requirements:** SM-1, SM-2, NFR-10
**Screens:** None

**Acceptance Criteria:**

**Given** 90 days on Gatekeep
**When** they're reviewed
**Then** NFR-10 was met each month, with no critical incident and zero cross-Tenant access in Logs, and v2 entry can be judged
