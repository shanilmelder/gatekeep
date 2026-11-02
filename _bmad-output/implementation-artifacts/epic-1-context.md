# Epic 1 Context: Secure Deployment and Admin access

<!-- Generated from planning artifacts. Regenerate with compile-epic-context if planning docs change. -->

## Goal

Stand up Gatekeep's secure foundation on one Docker host: the Operator installs with no cloud runtime service, claims the Deployment with a server-only token and two WebAuthn credentials, creates isolated Tenants on permanent subdomains and works in the Admin shell. Every later epic builds on what starts here: database-enforced Tenant isolation, audited mutations, key custody in OpenBao, Tenant-scoped jobs and Operations, the shared UI kit, the rate limiter, and the cross-Tenant suite.

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

- Install needs only Docker on the host; startup refuses missing or default secrets and logs the secret's name, never its value. Disk encryption, host firewall (only Caddy's ports) and host access control are documented host requirements Gatekeep can't verify; Docker access equals full control.
- Tenant data, keys and Sessions are isolated below application logic; jobs, caches and rate-limit counters are Tenant-keyed; a cross-Tenant suite covers every route and artifact type on every build.
- Admin auth is WebAuthn only, stored apart from Users: two credentials, or one plus an offline Recovery Code that reaches only credential setup. Admin sessions: 30 minutes idle, 8 hours absolute.
- A fresh assertion (within 5 minutes) is required for Admin grant/removal, Signing Key revocation, lowering MFA, Prod callback or label changes, client secret rotation, email provider change, Management API grants, Tenant deletion and incident actions. Hiding in the UI is never the control.
- Bootstrap token and `recover-admin` enrolment are single-use, 15 minutes, stored only as SHA-256. Recovery confirms its alert and off-server record before issuing.
- Tenant Subdomains: 3–63 lowercase letters, digits and hyphens, no reserved name, permanent, never reused. Refusal doesn't reveal taken versus reserved. Unknown or deleted hosts get one fixed 404.
- Tenant deletion needs typed confirmation plus a fresh assertion, destroys keys and keeps security Logs at least 90 days; other Tenants are provably unchanged.
- Every state change needs a session-bound CSRF token and exact-host Origin check. Authorization is server-side on every request. No third-party runtime requests; no credential-equivalent value in logs, events, errors or alerts (canary-scanned).
- Sign-in, recovery and token endpoints are rate limited per Tenant and per source; forwarded addresses are trusted only from Caddy.

## Technical Decisions

- **Stack:** .NET 10 modular monolith (12 modules, hexagonal inside), PostgreSQL only (no Redis or second store), OpenBao Transit, Caddy, Docker Compose, React + Vite, pnpm workspaces. Versions are pinned in the architecture Stack table.
- **Docker only:** every process runs in a container, including OpenBao, the CLI (`cli` service), setup, key generation and the test suite (`tests` container). Nothing is documented to run outside Docker.
- **Hosts:** `Host.Hosted` serves Tenant hosts only; `Host.Admin` serves the Admin Dashboard and Management API on its own public hostname via Caddy's Admin site (outside the Tenant zone); `Host.Worker` exposes only health; `Gatekeep.Cli` has no published port. Admin and Hosted routes never overlap. `Host.Hosted` has no network route to `Host.Admin`. Because Admin is internet-facing, WebAuthn, fresh assertions, rate limits, CSP and CSRF are its controls.
- **Boundaries:** one edge list in `tests/Architecture` generates tests and diagram; an unlisted dependency fails the build. Modules query only their own tables; cross-module FKs are composite or to `tenant` with `ON DELETE RESTRICT`; cross-module deletion is an Operation.
- **Isolation:** every table is in a registry with class (`tenant`/`control`), owner and per-column grants. `tenant` tables use `ENABLE`+`FORCE` RLS with a permissive plus `RESTRICTIVE` policy on `current_setting('gatekeep.tenant_id')::uuid`, so unscoped queries error. Only `gk_migrator` owns tables; no runtime role has `BYPASSRLS`. New tables ship registry entry, policies and grants in the same migration.
- **Tenant source:** resolved host, URL path, job row or CLI iteration only, never session or token claim alone. `TenantScope` uses transaction-local `set_config`; session `SET` and PgBouncer are forbidden. Issuer, RP ID and email base come from the stored Tenant.
- **Mutations:** one `CommandContext` writes state, audit event and jobs together; authorization runs in the handler; no MediatR. `FailureContext` commits durable effects of refused requests. Audit via `IAuditAppender` only, `{domain}.{object}.{action}` codes, internal references only, personal data in detail tables.
- **Rate limiting:** `IRateLimiter` is a Kernel port. Counters live in `UNLOGGED` tables (crash reset is acceptable); Admin counters in the `UNLOGGED` `control` table `admin_attempt`, owned by Admins. `Host.Hosted` also has a coarse in-memory per-source limit. Argon2id goes through a Deployment-wide bounded semaphore with per-Tenant shares.
- **CSP:** Hosted Login, Account Portal and Admin Dashboard all send exactly `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`, plus `Referrer-Policy: no-referrer` and framing denied; a browser test covers it. The Admin Dashboard is a static bundle served by `Host.Admin`.
- **Keys:** all access through `IKeyCustody`; non-exportable Transit keys with purpose-prefixed names and per-host policies; Tenant ID as `associated_data`. Master Key is a 32-byte file on the Docker host delivered as a read-only Compose secret, never in an image, env var, data volume, log, repo or backup, with offline escrow (a weaker control). OpenBao joins no network; hosts reach it over a unix socket. No TPM design.
- **Secrets in code:** `Secret<T>` has no serializable form; `RevealOnce<T>` only from a code-listed set of responses. High-entropy values stored as SHA-256; low-entropy (Recovery Codes) as HMAC under Transit (Admin uses the Deployment `hmac` key).
- **Sessions:** Admin sessions in a `control` table, hash-only, `__Host-` cookie with `SameSite=Strict`, on the Admin hostname.
- **Work:** jobs need exactly one of `tenant_id` or `deployment_wide`, claimed with `SKIP LOCKED`; Operations return `202`, idempotent steps, one active per scope and type.
- **Authorization:** one capability table in the Admins contract declares `MachineAllowed` and `FreshAssertion`; every fresh-assertion capability is machine-denied. No server-side current Tenant: the path names it (`/api/v1/tenants/{tenantId}/*`; `/api/v1/deployment/*` is Deployment Owner only, no machine access).
- **Conventions:** UUIDv7 with prefixed public IDs, RFC 9457 errors with `code` and `traceId`, cursor paging at 50, UTC `timestamptz`, message catalogues, §5.2 limits as constants in one Kernel file. `packages/api-client` is generated from the committed, CI-diffed OpenAPI document.
- **UI:** DESIGN.md frontmatter generates tokens and wins over `design/` exports; raw hex fails lint except the QR code; `@gatekeep/ui/hosted` allows only the QR encoder as a third-party runtime dependency.

## UX & Interaction Patterns

- Pre-session Admin screens (Bootstrap, Admin sign-in, credential setup) use `hosted-card` in the default theme; spec-only screens compose existing components. Admin sign-in has no email or password field; cancelled ceremonies stay on screen.
- Shell: 48px top bar, no global search or alerts bell; sidebar is an icon rail below 1100px, unsupported below 768px; Deployment group for Deployment Owners only; sidebar lists only pages built so far.
- Tenant name and environment badge on every page: Prod `bad`, Staging `warn`, Dev `info`. Tenant mismatch shows a `banner` naming both Tenants with Reload.
- Destructive actions go to a modal, then the WebAuthn sheet, with failure in the same modal; never stack modals. Toasts carry no errors or copyable values.
- Expired session: WebAuthn sheet on next action with a `banner`, values kept.

## Cross-Story Dependencies

- Story 1.3's threat model (`docs/threat-model.md`, threats `T-n`, gaps `G-n`) precedes authentication work; any change to a trust boundary updates it in the same pull request.
- Stories 1.13–1.18 precede screens. Stories 1.19 and 1.20 precede 1.21–1.23 (bootstrap and Admin sign-in rely on `admin_attempt` and the Admin CSP). Story 1.30 precedes 1.32.
- Registries (routes, artifacts, jobs, rate-limit types) may start small with code-owned pending lists; later stories add their own entries.
- Epic 2 adds Sessions and `RevokeAccess`; Epic 7 extends Audit and the canary scan; Epic 8 adds Admin invites; Epic 10 builds sign-in backoff on `IRateLimiter`; Epic 11 connects alerts; Story 12.5 signs release images.
