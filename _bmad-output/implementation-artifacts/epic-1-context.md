# Epic 1 Context: Secure Deployment and Admin access

<!-- Generated from planning artifacts. Regenerate with compile-epic-context if planning docs change. -->

## Goal

Stand up Gatekeep's secure foundation on one Docker host: the Operator installs with nothing but Docker, claims the Deployment with a server-only token and two WebAuthn credentials, creates isolated Tenants on permanent subdomains and works in the Admin shell on its own public hostname. Every later epic builds on what starts here: database-enforced Tenant isolation, audited mutations, key custody in OpenBao, Tenant-scoped jobs and Operations, the shared UI kit, the rate limiter, the alert channel and off-server store, and the cross-Tenant suite.

## Stories

- Story 1.1: Scaffold the monorepo and enforce module boundaries
- Story 1.2: Prove key custody on the target host
- Story 1.3: Write the threat model
- Story 1.4: Enforce Tenant isolation in the database
- Story 1.5: Write an audit event with every state change
- Story 1.6: Scrub logs and scan for canaries
- Story 1.7: Hold keys in OpenBao behind `IKeyCustody`
- Story 1.8: Run Tenant-scoped jobs
- Story 1.9: Track long-running Operations
- Story 1.10: Run the stack under Compose with safe secrets
- Story 1.11: Route traffic through Caddy and default-deny networks
- Story 1.12: Document installation
- Story 1.13: Generate design tokens and bundle fonts
- Story 1.14: Build shared form and action components
- Story 1.15: Build data display components
- Story 1.16: Build overlay and feedback components
- Story 1.17: Build the drawer and menu
- Story 1.18: Build the Hosted component entry and screen package
- Story 1.19: Initialise a Deployment
- Story 1.20: Add the rate limiter and Admin CSP
- Story 1.21: Claim bootstrap and create the first Admin
- Story 1.22: Register Admin WebAuthn credentials
- Story 1.23: Sign in as an Admin with WebAuthn
- Story 1.24: Enforce capabilities and Tenant-scoped routes
- Story 1.25: Open the Admin shell
- Story 1.26: Confirm sensitive actions and manage Admin credentials
- Story 1.27: Create Tenants with permanent subdomains
- Story 1.28: Switch Tenants and set the environment label
- Story 1.29: Delete a Tenant without touching others
- Story 1.30: Connect the alert channel and off-server store
- Story 1.31: Run the cross-Tenant suite on every build
- Story 1.32: Recover Admin access from the host

## Requirements & Constraints

- **Docker only:** every process runs in a container, including OpenBao, the CLI (`cli` service), setup, key generation, builds and the test suite (`tests` container). Nothing is documented or verified outside Docker. Startup refuses missing or default secrets and logs the secret's name, never its value. Disk encryption, a host firewall allowing only Caddy's ports, and host access control are documented host requirements Gatekeep can't verify; Docker access equals full control. The Linux/TPM custody spike is retired.
- Tenant data, keys and Sessions are isolated below application logic; jobs, caches and rate-limit counters are Tenant-keyed; a cross-Tenant suite covers every route and artifact type on every build.
- Admin auth is WebAuthn only, stored apart from Users: two credentials, or one plus an offline Recovery Code. Admin sessions: 30 minutes idle, 8 hours absolute. The Admin site is public with no IP allowlist, so WebAuthn, fresh assertions, rate limits, CSP and CSRF/Origin checks are its only controls.
- A fresh assertion (within 5 minutes) is required for Admin grant/removal, Signing Key revocation, lowering MFA, Prod callback or label changes, client secret rotation, email provider change, Management API grants, Tenant deletion and incident actions. Hiding in the UI is never the control.
- Bootstrap token and `recover-admin` enrolment are single-use, 15 minutes, stored only as SHA-256. Recovery sends its Security Alert and writes its off-server record itself, and issues the enrolment only after both are confirmed.
- Tenant Subdomains are permanent, never reused and never a reserved name; refusal doesn't reveal taken versus reserved. Unknown or deleted hosts get one fixed 404.
- Tenant deletion needs typed confirmation plus a fresh assertion, destroys Signing Keys, withdraws the JWKS and keeps security Logs at least 90 days; other Tenants are provably unchanged.
- Every state change needs a session-bound CSRF token and exact-host Origin check. Authorization is server-side on every request. No third-party runtime requests; no credential-equivalent value in logs, events, errors, alerts or off-server records (canary-scanned).
- Sign-in, recovery and token endpoints are rate limited per Tenant and per source; forwarded addresses are trusted only from Caddy's network address.

## Technical Decisions

- **Stack:** .NET 10 modular monolith (12 modules, hexagonal inside), PostgreSQL 18 only (no Redis, broker or second store), OpenBao 2.7 Transit, Caddy 2.11, Docker Compose, React 19 + Vite, pnpm workspaces, one solution with Central Package Management. Exact versions are in the architecture Stack table.
- **Hosts:** `Host.Hosted` serves Tenant Subdomains only; `Host.Admin` serves the Admin Dashboard (static bundle) and Management API, reachable only through Caddy's Admin site; `Host.Worker` exposes only health; `Gatekeep.Cli` runs only as the `cli` service with no published port. Admin and Hosted routes never overlap, and a release test proves from inside its container that `Host.Hosted` has no route to `Host.Admin`.
- **Edge and TLS:** Caddy has two public sites: the Tenant zone wildcard and the Admin hostname (outside the zone). Both certificates come by ACME DNS-01 through Cloudflare DNS, with a token limited to a validation-only zone that `_acme-challenge` is delegated to. Cloudflare provides DNS only and never sees traffic. Certificate keys are readable only by Caddy; CAA is set; CT monitoring raises alerts. Only Caddy publishes ports; Compose networks deny by default.
- **Egress:** application egress only from `Host.Hosted`, `Host.Worker` and `Gatekeep.Cli`, through one `EgressHttp` handler that blocks private addresses. `Host.Admin` has no egress, so its sending is a Deployment-wide job.
- **Boundaries:** one edge list in `tests/Architecture` generates tests and diagram; an unlisted dependency fails the build. Modules query only their own tables; cross-module FKs are composite or to `tenant` with `ON DELETE RESTRICT`; cross-module deletion is an Operation, and each module with `tenant` tables exposes a Tenant purge.
- **Isolation:** every table is in a registry with class (`tenant`/`control`), single owner and per-column grants. `tenant` tables use `ENABLE`+`FORCE` RLS with a permissive plus `RESTRICTIVE` policy on `current_setting('gatekeep.tenant_id')::uuid`, so unscoped queries error. Only `gk_migrator` owns tables; no runtime role has `BYPASSRLS`. New tables ship registry entry, policies and grants in the same migration.
- **Tenant source:** resolved host (exact match on `tenant_host`, never parsed), URL path, job row or CLI iteration, never a session or token claim alone. `TenantScope` uses transaction-local `set_config`; session `SET` and PgBouncer are forbidden. Issuer, RP ID and email base come from the stored Tenant.
- **Mutations:** one `CommandContext` writes state, audit event and jobs together; authorization runs in the handler; no MediatR. `FailureContext` commits durable effects of refused requests. Audit only via `IAuditAppender`, `{domain}.{object}.{action}` codes, internal references only, personal data in detail tables.
- **Keys:** all access through `IKeyCustody`; non-exportable Transit keys with purpose-prefixed names (`sig-`, `mgmt-`, `{class}-{tenantId}`, `dep-{class}`) and per-host policies; Tenant ID as `associated_data`. OpenBao joins no network; hosts reach it over a unix socket on a shared volume. The Master Key is a 32-byte file on the Docker host delivered as a read-only Compose secret, never in an image, env var, data volume, log, repo or backup, with offline escrow (a weaker control).
- **Bootstrap file:** `gatekeep init` writes the token to `secrets/bootstrap/bootstrap-token` (0600 in a 0700 directory owned by the `cli` uid, bind-mounted only into `cli`); `bootstrap_state` holds its SHA-256 and expiry and is never deleted. After bootstrap the route returns the generic 404.
- **Alerts and off-server record:** alerts derive from audit event types through one table in Notifications and go through `IAlertChannel` to a service outside the Deployment. Worker jobs copy sealed security events, revocations and chain heads within 60 seconds to an S3-API Object Lock bucket (compliance mode) on a separate provider, signed by a Deployment Transit key usable only by `Host.Worker` and `Gatekeep.Cli`; the server's credential can write but not delete or shorten retention. The OpenBao audit device ships off-server. Vendors are chosen at install, behind ports.
- **Rate limiting:** `IRateLimiter` Kernel port over `UNLOGGED` tables (crash reset acceptable); Admin counters in the `UNLOGGED` `control` table `admin_attempt`. `Host.Hosted` adds a coarse in-memory per-source limit. Argon2id runs through a Deployment-wide bounded semaphore with per-Tenant shares.
- **CSP:** Hosted Login, Account Portal and Admin Dashboard all send exactly `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`, plus `Referrer-Policy: no-referrer`; a browser test covers it.
- **Secrets in code:** `Secret<T>` has no serializable form; `RevealOnce<T>` only from a code-listed set of responses. High-entropy values stored as SHA-256; Admin Recovery Codes as HMAC under the Deployment `hmac` key. Admin sessions live in a `control` table, hash-only, `__Host-` cookie with `SameSite=Strict` on the Admin hostname.
- **Work:** jobs need exactly one of `tenant_id` or `deployment_wide`, claimed with `SKIP LOCKED`, enqueue allow-listed per role; credential payloads are Transit ciphertext erased on completion. Operations return `202`, idempotent steps, one active per scope and type, Retry for failed steps.
- **Authorization:** one capability table in the Admins contract declares `MachineAllowed` and `FreshAssertion`; every fresh-assertion capability is machine-denied. No server-side current Tenant: the path names it (`/api/v1/tenants/{tenantId}/*`; `/api/v1/deployment/*` is Deployment Owner only, no machine access).
- **Conventions:** UUIDv7 with prefixed public IDs, RFC 9457 errors with `code` and `traceId`, cursor paging at 50, UTC `timestamptz`, message catalogues, §5.2 limits as constants in one Kernel file, forward-only migrations. `packages/api-client` is generated from the committed, CI-diffed OpenAPI document.
- **UI:** DESIGN.md frontmatter generates tokens (CSS, TS, C#) and wins over `design/` exports, which are never imported; raw hex fails lint except the QR code; `@gatekeep/ui/hosted` allows only the QR encoder as a third-party runtime dependency; fonts are bundled.

## UX & Interaction Patterns

- Pre-session Admin screens (Bootstrap, Admin sign-in, credential setup) use `hosted-card` in the default theme; spec-only screens compose existing components only. Admin sign-in has no email or password field; cancelled ceremonies stay on screen.
- Shell: 48px top bar, no global search or alerts bell; sidebar is an icon rail below 1100px, unsupported below 768px; Deployment group for Deployment Owners only; sidebar lists only pages built so far.
- Tenant name and environment badge on every page: Prod `bad`, Staging `warn`, Dev `info`. Tenant mismatch shows a `banner` naming both Tenants with Reload; a Tenant deleted mid-session has its own state.
- Destructive actions go to a modal (typed confirmation where required), then the WebAuthn sheet, with failure in the same modal; never stack modals. Toasts carry no errors or copyable values.
- Expired session: WebAuthn sheet on next action with a `banner`, values kept.

## Cross-Story Dependencies

- The threat model (`docs/threat-model.md`) precedes authentication work; any change to a trust boundary updates it in the same pull request.
- Stories 1.13–1.18 precede screens. Stories 1.19 and 1.20 precede 1.21–1.23 (bootstrap and Admin sign-in rely on `admin_attempt` and the Admin CSP). Story 1.30 precedes 1.32, which needs `IAlertChannel` and the off-server store.
- Registries (routes, artifacts, jobs, rate-limit types) may start small with code-owned pending lists; later stories add their own entries.
- Epic 2 adds Sessions and `RevokeAccess` (its OpenIddict spikes are done); Epic 7 extends Audit search, verification and the canary scan; Epic 8 adds Admin invites via `deployment_email_provider`; Epic 10 builds sign-in backoff on `IRateLimiter`; Epic 11 connects all alert events and decrypt-rate alerts; Epic 12 adds backup, restore and release image signing.
