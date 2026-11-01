# Epic 1 Context: Secure Deployment and Admin access

<!-- Compiled from planning artifacts. Edit freely. Regenerate with compile-epic-context if planning docs change. -->

## Goal

Stand up Gatekeep's secure foundation on one on-premises Linux server: the Operator installs with no cloud service, claims the Deployment with a server-only token and WebAuthn, creates isolated Tenants and uses the Admin shell. Every later epic builds on what starts here: database-enforced isolation, audited mutations, key custody, jobs, the UI kit and the isolation suite.

## Stories

- Story 1.1: Scaffold monorepo and module boundaries
- Story 1.2: Prove key custody on target host
- Story 1.3: Threat model
- Story 1.4: Database Tenant isolation
- Story 1.5: Audit event with every state change
- Story 1.6: Log scrubbing and canary scan
- Story 1.7: OpenBao behind `IKeyCustody`
- Story 1.8: Tenant-scoped jobs
- Story 1.9: Long-running Operations
- Story 1.10: Compose stack with safe secrets
- Story 1.11: Caddy and default-deny networks
- Story 1.12: Install documentation
- Story 1.13: Design tokens and fonts
- Story 1.14: Form and action components
- Story 1.15: Data display components
- Story 1.16: Overlay and feedback components
- Story 1.17: Drawer and menu
- Story 1.18: Hosted entry and screen package
- Story 1.19: Initialise a Deployment
- Story 1.20: Rate limiter and Admin CSP
- Story 1.21: Claim bootstrap, first Admin
- Story 1.22: Register Admin WebAuthn credentials
- Story 1.23: Admin WebAuthn sign-in
- Story 1.24: Capabilities and Tenant-scoped routes
- Story 1.25: Admin shell
- Story 1.26: Fresh assertions and Admin credentials
- Story 1.27: Create Tenants
- Story 1.28: Switch Tenants, environment label
- Story 1.29: Delete a Tenant
- Story 1.30: Alert channel and off-server store
- Story 1.31: Cross-Tenant suite
- Story 1.32: Recover Admin access from host

## Requirements & Constraints

- Startup refuses missing or default secrets, logging names only.
- OpenBao, PostgreSQL and key volumes use LUKS, unlocked by a passphrase at boot, with no unlock key on the host. Restarts aren't unattended: the service stays down after any reboot until a person enters it, and that wait counts against the 99.5% monthly availability target.
- Admin auth is WebAuthn only, stored apart from Users: two credentials, or one plus an offline Recovery Code that reaches only credential setup. Sessions: 30 minutes idle, 8 hours absolute.
- Fresh assertion (5 minutes) covers Admin grant or removal, key revocation, lowering MFA, Prod callback or label changes, secret rotation, email provider change, Management API grants, Tenant deletion and incident actions.
- Bootstrap and `recover-admin` tokens are single-use, last 15 minutes and are stored hashed. Recovery confirms its alert and off-server record before issuing.
- Tenant Subdomains are permanent, never reused, 3–63 lowercase letters, digits and hyphens. Refusals don't reveal taken versus reserved.
- Every state change needs a CSRF token and exact-host Origin check; authorization is server-side; no third-party runtime requests.

## Technical Decisions

- **Stack:** .NET 10 modular monolith, PostgreSQL only (no Redis), OpenBao Transit, Caddy, Compose, React and Vite, pnpm workspaces. Exact versions are in the architecture Stack table.
- **Hosts:** `Host.Hosted` serves Tenant hosts only; `Host.Admin` is private-network only; `Host.Worker` has only health; `Gatekeep.Cli` runs on the host. OpenBao runs as a native systemd service, everything else under Compose. Routes never overlap.
- **Boundaries:** one edge list in `tests/Architecture` drives tests and diagram. Modules query only their own tables. Cross-module deletion is an Operation.
- **Isolation:** every table is registered with class (`tenant` or `control`), owner and grants. `tenant` tables use `FORCE` RLS on `gatekeep.tenant_id`, so unscoped queries raise an error. Their foreign keys are composite. Only `gk_migrator` owns tables.
- **Tenant source:** resolved host, path, job row or Cli iteration only. Hosts match `tenant_host` exactly; unknown hosts get one fixed 404. Issuer and RP ID come from the stored Tenant.
- **Mutations:** one `CommandContext` writes state, audit and jobs together; only the outermost handler creates it, and authorization runs in the handler. `FailureContext` commits durable effects of refused requests. `TenantScope` uses transaction-local `set_config`.
- **Secrets:** keys go through `IKeyCustody`, never exportable; Transit uses Tenant ID as `associated_data`. `Secret<T>` can't serialize; `RevealOnce<T>` is code-listed. OpenBao's audit output goes off the server.
- **Key custody (weaker control):** the custody spike didn't run because no TPM2 host was available; all seven proofs are `not-run`, which is no evidence either way. The Master Key, meaning the OpenBao static seal key, is a root-only key file on a separate volume. It's never in a container, environment file or backup. An offline escrow copy, with the recovery keys, is kept apart from backups, and every generation stays until the last backup needing it expires. Esm accepted that file permissions are the seal's only root of trust.
- **What custody protects:** backups; a stolen database disk if the key volume isn't taken too; a server stolen while powered off. **Not protected:** a server taken while running, a copied key file (no hardware binding, so old copies stay valid until rotation) or live root. Don't describe it as hardware-bound or TPM-sealed.
- **TPM design:** deferred. `systemd-creds` sealed to TPM2 and PCR 7 stays the target, adopted only after the spike passes on a real host. Build nothing on it, including `LoadCredentialEncrypted`.
- **Undecided custody work:** how the root-only file reaches the non-root OpenBao service (owner, mode, key generation, mount order, behaviour when the volume is missing at boot), and the OpenBao host login method. Rotation, restore and `gatekeep rekey` haven't been rechecked against the key file. Decide these explicitly; don't assume them.
- **Audit:** `IAuditAppender`, `{domain}.{object}.{action}` codes, internal references only; personal data goes in detail tables.
- **Work:** `IJobEnqueuer` jobs need exactly one of `tenant_id` or `deployment_wide`. Operations return `202`, with idempotent steps, one active per scope and type.
- **Authorization:** one capability table declares `MachineAllowed` and `FreshAssertion`. No server-side current Tenant: the path names it.
- **Contract:** `packages/api-client` is generated from the committed OpenAPI document. Errors are RFC 9457 with `code` and `traceId`.
- **UI:** DESIGN.md frontmatter generates tokens and wins over `design/` exports. Raw hex fails lint, except the QR code. `@gatekeep/ui/hosted` allows only the QR encoder.

## UX & Interaction Patterns

- Pre-session Admin screens use `hosted-card`. Spec-only screens compose existing components.
- Sidebar: icon rail below 1100px, unsupported below 768px; Deployment group for Deployment Owners only.
- Tenant name and environment badge show on every page: Prod `bad`, Staging `warn`, Dev `info`.
- Destructive actions go modal, then WebAuthn sheet, with failure in the same modal. Never stack modals. Toasts carry no errors or copyable values.
- Expired session: WebAuthn sheet on next action, `banner` shown, values kept.

## Cross-Story Dependencies

- Story 1.2 is settled by its fallback, so the TPM spike now blocks only the TPM design. Stories 1.7 and 1.10 build on the key file design and still need a Linux host, which is unconfirmed and has no fallback. Five of the seven proofs need only Linux and can run there.
- Story 1.3 precedes authentication work. `docs/threat-model.md` names threats (`T-n`) and open gaps (`G-n`) for stories to cite. Any work that changes a trust boundary updates it in the same pull request.
- Stories 1.13–1.18 precede screens. Stories 1.19 and 1.20 precede 1.21–1.23. Story 1.30 precedes 1.32.
- Registries may start small with code-owned pending lists; later stories add their own entries.
- Epic 7 extends Audit, Epic 8 adds invites, Epic 11 connects alerts, Story 12.5 signs images.
