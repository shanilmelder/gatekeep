- source_spec: `_bmad-output/implementation-artifacts/spec-1-1-scaffold-the-monorepo-and-enforce-module-boundaries.md`
  summary: Prove `.github/workflows/ci.yml` fails a real pull request on lockfile drift and on a critical advisory.
  evidence: The architecture tests run equivalent commands but never run the workflow, so removing `--locked-mode` or the `pnpm audit` step fails nothing. It needs a GitHub remote, which doesn't exist yet; run one deliberately failing PR when the repo is created.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-2-prove-key-custody-on-the-target-host.md`
  summary: Add acceptance criteria to Stories 1.7 and 1.10 that record results for static seal, Raft, socket access from containers, OpenBao host login and per-host quotas, and decide the host login method.
  evidence: Story 1.2 recorded these five proofs as `not-run`, they need only Linux, and no story currently requires them.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-2-prove-key-custody-on-the-target-host.md`
  summary: Decide how the root-only key file reaches the non-root OpenBao service, with owner, mode, key generation, mount order and the behaviour when the volume is missing at boot.
  evidence: AD-10 bans environment files and `LoadCredentialEncrypted` needs a TPM; Story 1.7 inherits this undecided.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-2-prove-key-custody-on-the-target-host.md`
  summary: Recheck seal rotation, restore and `gatekeep rekey` (AD-10, AD-18, Stories 12.2, 12.7, 13.4) against the key file design, including destroying old copies.
  evidence: These paths assumed a TPM-sealed key. A copied file has no hardware binding, so old copies stay valid until rotation.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-2-prove-key-custody-on-the-target-host.md`
  summary: Run the custody spike on a real TPM2 host before adopting the TPM design, and amend AD-10 again.
  evidence: AD-10 and AR-20 name the TPM design as the target, but no story schedules the spike.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-2-prove-key-custody-on-the-target-host.md`
  summary: Extend Story 1.10's LUKS criterion to the key volume, and cover the boot passphrase step in the install docs and alerts.
  evidence: Story 1.10 tests only the OpenBao and PostgreSQL volumes, while AD-10 now needs the key volume on LUKS, and a reboot waits for a person against NFR-10.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-3-write-the-threat-model.md`
  summary: Add acceptance criteria to the stories named in `docs/threat-model.md` Gaps to close (G-1 to G-14), and record Esm's decision on G-15.
  evidence: The gaps have no criterion in any story, so closing them depends on a reviewer reading the threat model. Editing epics was outside Story 1.3.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-3-write-the-threat-model.md`
  summary: Point the `ARCHITECTURE-SPINE.md` Deferred entry for the threat model at `docs/threat-model.md`, and amend AD-10, AD-18 and AD-26 for the gaps it raises.
  evidence: The spine still lists the threat model as pending, and G-9, G-11 and G-12 are spine-level changes.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-4-enforce-tenant-isolation-in-the-database.md`
  summary: Catch `ARCHITECTURE-SPINE.md` up with Story 1.4: name `migration_history` in AD-27, add `Cli -> Adapters.Postgres` to the AD-1 diagram, and correct AD-3 if the known limit wording changes.
  evidence: AD-27 does not list `migration_history`, and the spine diagram has no adapter edge, though the edge list and generated diagram do.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-4-enforce-tenant-isolation-in-the-database.md`
  summary: Add a test that a failed `TenantScope.BeginAsync` returns its connection to the pool.
  evidence: Removing the cleanup passed every test, and the failure is hard to force before Story 1.5 gives it a real caller.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-4-enforce-tenant-isolation-in-the-database.md`
  summary: Add column-level grants to `TableEntry` and the catalogue audit.
  evidence: AD-2 and TB-6 require per-column allow-lists, but the registry is table-level. The audit reports any column grant as unlisted, so the first story needing one must add this.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-4-enforce-tenant-isolation-in-the-database.md`
  summary: Correct AD-3 so it no longer says an unscoped query always raises an error.
  evidence: `Known_limit_an_unscoped_query_the_planner_proves_empty_returns_nothing` shows a query that evaluates the policy for no row returns nothing.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-4-enforce-tenant-isolation-in-the-database.md`
  summary: Audit function ACLs, `SECURITY DEFINER` and `pg_default_acl` in the catalogue test.
  evidence: None exist yet, but triggers in Stories 1.8 and 7.1 add functions, and `PUBLIC` can execute new functions by default.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-5-write-an-audit-event-with-every-state-change.md`
  summary: Add a rule that fails a state-changing handler which does not call `IAuditAppender`.
  evidence: No production command exists until Story 1.21, so the AD-5 rule for every state change is neither enforced nor tested.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-5-write-an-audit-event-with-every-state-change.md`
  summary: Add `DeploymentScope`, `FailureContext` and `gk_retention` `DELETE` on detail tables to the spine (AD-4, AD-16, AD-28).
  evidence: The spine names none of them, and AD-16 gives detail deletion only to `gk_worker`, though `ON DELETE RESTRICT` needs it for range deletion.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-6-scrub-logs-and-scan-for-canaries.md`
  summary: Decide whether `AuditDetail` text is scrubbed before storage, and extend the canary scan to shaped request values.
  evidence: The clean scan wraps canaries in `Secret<T>`, so a raw value never reaches the appender. Story 7.8 extends the scan.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-6-scrub-logs-and-scan-for-canaries.md`
  summary: Scan a real host process stdout in the canary scan.
  evidence: The scan reads what the console provider hands its formatter from test-sent records, because no flow exists yet.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-7-hold-keys-in-openbao-behind-ikeycustody.md`
  summary: Add a moving-clock test for the adapter logging in at three quarters of the lease.
  evidence: Both Story 1.7 expiry tests freeze the clock. Do it when Story 1.10 wires hosts.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-7-hold-keys-in-openbao-behind-ikeycustody.md`
  summary: Decide mlock for OpenBao under the hardened unit, and whether swap is encrypted.
  evidence: The unit drops CAP_IPC_LOCK and the config does not set disable_mlock; needs a Linux host (G-10).
- source_spec: `_bmad-output/implementation-artifacts/spec-1-7-hold-keys-in-openbao-behind-ikeycustody.md`
  summary: Rotate the OpenBao audit log and decide on a second audit device.
  evidence: A full disk under the only audit device blocks every request. Belongs with shipping the audit log off the server.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-7-hold-keys-in-openbao-behind-ikeycustody.md`
  summary: Set a secret ID lifetime and write the replacement procedure for one leaked secret ID.
  evidence: Story 1.7 setup uses secret_id_ttl=0. Story 1.10 delivers secret IDs.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-8-run-tenant-scoped-jobs.md`
  summary: Decide job retention for dead jobs and for Tenant deletion, since job and job_payload keys are ON DELETE RESTRICT.
  evidence: Story 1.8 purges only done jobs.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-8-run-tenant-scoped-jobs.md`
  summary: Guard who may attach a job_payload row, so only the enqueuing transaction can.
  evidence: Story 1.8 review: the enqueuing roles cannot read job and SECURITY DEFINER is banned.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-8-run-tenant-scoped-jobs.md`
  summary: Bound a credential job's attempts and backoff by the credential's lifetime.
  evidence: Needed by the first credential job type (reset links).
- source_spec: `_bmad-output/implementation-artifacts/spec-1-8-run-tenant-scoped-jobs.md`
  summary: Give operations.job.dead a job reference, and raise the Security Alert.
  evidence: G-17.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-9-track-long-running-operations.md`
  summary: Mark open Operation steps failed when their run or step job goes dead, so the Operation can be retried.
  evidence: Story 1.9 review: a dead job leaves the Operation stuck active. Needed before the first production Operation type.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-9-track-long-running-operations.md`
  summary: Order Operation stages, so Tenant deletion can purge before it removes the Tenant.
  evidence: Story 1.9 runs stages unordered.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-9-track-long-running-operations.md`
  summary: Restrict Operation and step status transitions and step inserts to the transitions start, retry and the Worker make.
  evidence: Column grants let gk_admin, gk_cli and gk_worker set any status and add steps. T-46.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-10-run-the-stack-under-compose-with-safe-secrets.md`
  summary: Check each host's AppRole login at startup, so a wrong or revoked secret ID stops the host instead of reporting healthy.
  evidence: Story 1.10 health checks only sys/health, which needs no token.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-11-route-traffic-through-caddy-and-default-deny-networks.md`
  summary: Decide forwarded-header trust behind Caddy so rate limits see real client addresses.
  evidence: Story 1.11 review; Story 1.20 owns the rate limiter.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-11-route-traffic-through-caddy-and-default-deny-networks.md`
  summary: Decide whether Caddy keeps an access log, with query values scrubbed.
  evidence: Story 1.11 review: T-42.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-11-route-traffic-through-caddy-and-default-deny-networks.md`
  summary: Prove Caddy's cloudflare mode issues real certificates on the first real install.
  evidence: Story 1.11 validated it offline only.
- source_spec: `_bmad-output/implementation-artifacts/spec-2-6-add-session-and-transaction-tables.md`
  summary: Add `(tenant_id, application_id) REFERENCES application (tenant_id, id) ON DELETE RESTRICT` on `signin_transaction`, `authorization` and `token` in Story 2.5's migration.
  evidence: Story 2.6 created those columns with no foreign key, because the `application` table is Story 2.5's (user decision, 2026-11-02).
- source_spec: `_bmad-output/implementation-artifacts/spec-2-6-add-session-and-transaction-tables.md`
  summary: Narrow `gk_hosted` UPDATE on `user_session`, `signin_transaction`, `authorization` and `token` to the columns that change, once Story 2.9's stores and Story 2.7's revocation define them.
  evidence: Story 2.6 grants table-wide UPDATE, so the Hosted path could rewrite `id_hash`, `binding_hash` or `user_id`.
- source_spec: `_bmad-output/implementation-artifacts/spec-2-6-add-session-and-transaction-tables.md`
  summary: Confirm the `token.reference_id` CHECK (`^[A-Za-z0-9+/_-]{43}=?$`) against real OpenIddict output in Story 2.9, and recheck it on every OpenIddict upgrade.
  evidence: It assumes OpenIddict 7.7.2's obfuscated form (base64 SHA-256), and only a hand-built value has tested it.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-13-generate-design-tokens-and-bundle-fonts.md`
  summary: Prove fonts and same-origin requests through Caddy once the stack serves the apps.
  evidence: Story 1.13 proved them on vite preview.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-13-generate-design-tokens-and-bundle-fonts.md`
  summary: Make the Hosted Login app's own `index.html` follow prefers-color-scheme (DESIGN.md line 579), with `data-gk-surface="hosted"` and `data-gk-scheme="auto"` on `<html>` (Story 4.1).
  evidence: Story 1.13 review. Story 1.18 gave HostedPage its `auto` scope, and Story 1.25 settled the Admin side: the pre-Session cards follow the device and only the shell takes the manual toggle. Only the Hosted Login app's own page is left.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-13-generate-design-tokens-and-bundle-fonts.md`
  summary: Add a prefers-reduced-motion override for motion tokens.
  evidence: Story 1.13 review; Story 1.16.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-14-build-shared-form-and-action-components.md`
  summary: Test controlled values and change callbacks of Toggle, Segmented and RadioGroup.
  evidence: Story 1.14 review.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-14-build-shared-form-and-action-components.md`
  summary: Give Checkbox and RadioGroup helper, error, required and group-disabled support.
  evidence: Story 1.14 review.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-14-build-shared-form-and-action-components.md`
  summary: Validate every field on submit and focus the first invalid one.
  evidence: Story 1.14 review; EXPERIENCE "Focus moves only on submit".
- source_spec: `_bmad-output/implementation-artifacts/spec-1-15-build-data-display-components.md`
  summary: Colour the usage bar as it nears and passes its limit.
  evidence: Story 1.15 review; Story 11.4.
- source_spec: `_bmad-output/implementation-artifacts/spec-2-7-build-the-one-revocation-path.md`
  summary: In Story 2.9, record every revocation OpenIddict asks the stores for (token store `RevokeByAuthorizationIdAsync`, authorization-store revokes, and any `UpdateAsync` that sets a revoked status) on the request, route it through `ISessions.RevokeAccessAsync`, and replay it through `FailureContext` at endpoint end, including the unhandled-exception path.
  evidence: The spike 2.2 carry-over gave this capture to Story 2.7, but 2.7 has no stores to capture from. It proved only that `RevokeAccessAsync` commits inside `CommitAfterRollbackAsync`.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-20-add-the-rate-limiter-and-admin-csp.md`
  summary: Purge expired `admin_attempt` rows with a job.
  evidence: Story 1.20 never deletes a row: an elapsed window is reset in place by the next attempt, so a subject that never returns keeps its row until a crash empties the `UNLOGGED` table. `gk_admin` has no `DELETE` on it, so the purge needs its own grant and job type.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-20-add-the-rate-limiter-and-admin-csp.md`
  summary: Add the `rate_usage` roll-up job (AD-14).
  evidence: Story 1.20 builds the counters only; nothing rolls them up yet.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-20-add-the-rate-limiter-and-admin-csp.md`
  summary: Decide which forwarded headers `Host.Admin` trusts, so the limiter's subject is the real client address and not Caddy's.
  evidence: `docs/threat-model.md` T-47 named this as Story 1.20's decision, but the limiter has no caller until Story 1.21, which first needs a source address.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-18-build-the-hosted-component-entry-and-screen-package.md`
  summary: Session-expiry alert precedence over an open dialog (the session-expiry story)
  evidence: Story 1.18 review: AlertDialog is refused while a Modal or Drawer holds the registry.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-18-build-the-hosted-component-entry-and-screen-package.md`
  summary: Tenant font family token (Story 15.1)
  evidence: Story 1.18 review: composite --gk-font-* tokens bake in Geist.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-18-build-the-hosted-component-entry-and-screen-package.md`
  summary: Bidi isolation for Tenant names (NFR-19, Story 18.3)
  evidence: Story 1.18 review: RTL Tenant names in LTR templates.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-21-claim-bootstrap-and-create-the-first-admin.md`
  summary: Audit refused and rate-limited bootstrap claims, Admin sign-outs and Session expiries.
  evidence: Story 1.21 review; Stories 1.23 and Epic 7.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-22-register-admin-webauthn-credentials.md`
  summary: End-to-end WebAuthn registration test: real browser, real dashboard, real server.
  evidence: Story 1.22 review.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-23-sign-in-as-an-admin-with-webauthn.md`
  summary: Audit refused and rate-limited bootstrap claims (Epic 7).
  evidence: Story 1.23 audits Admin sign-in and sign-out only; the rest of the Story 1.21 item stays open.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-23-sign-in-as-an-admin-with-webauthn.md`
  summary: Audit Admin Session expiry (Epic 7).
  evidence: Story 1.23 out of scope. An expired Session is ended as `expired` with no event. Story 1.25's shell now shows the expiry banner and renews in place; the audit is what's left.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-23-sign-in-as-an-admin-with-webauthn.md`
  summary: Disable the credential, or raise a Security Alert, on a sign-count regression (Security Alerts story).
  evidence: Story 1.23 refuses the one sign-in and writes `admin.credential.sign_count_regressed`; the credential stays usable (threat model T-52).
- source_spec: `_bmad-output/implementation-artifacts/spec-1-23-sign-in-as-an-admin-with-webauthn.md`
  summary: End-to-end WebAuthn test, registration and sign-in: real browser, real dashboard, real server.
  evidence: Deferred from Story 1.22 and still open: `signin.spec.ts` intercepts the API, and the Isolation tests use a software authenticator.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-23-sign-in-as-an-admin-with-webauthn.md`
  summary: Purge `admin_attempt` rows.
  evidence: Story 1.23 adds two more policies counted there, per client; carries on the Story 1.20 item.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-23-sign-in-as-an-admin-with-webauthn.md`
  summary: Catch `ARCHITECTURE-SPINE.md` up with Story 1.23: add `admin_signin_challenge` to AD-27's Admins table list.
  evidence: Story 1.23 adds the `UNLOGGED` `control` table `admin_signin_challenge`, owned by Admins, which AD-27 doesn't name yet.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-23-sign-in-as-an-admin-with-webauthn.md`
  summary: Recover a Deployment Owner whose setup Session ended before they registered any credential (Story 1.32, `gatekeep recover-admin`).
  evidence: Story 1.23 review. WebAuthn sign-in needs a registered credential, so an Owner with none can never sign in once the setup Session expires; threat model T-51.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-23-sign-in-as-an-admin-with-webauthn.md`
  summary: Recover an Owner locked out before registering any credential.
  evidence: Story 1.23 review; Story 1.32.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-23-sign-in-as-an-admin-with-webauthn.md`
  summary: Test the no-client-address 503 on sign-in and the bootstrap claim.
  evidence: Story 1.23 review.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md`
  summary: Build `MachinePrincipal` from validated Management API tokens, add the Management API bearer scheme on `/api/v1/tenants/*`, and map each capability to the Management API Permission that grants it, as ADV-22 asks (Epic 17, Story 17.3).
  evidence: Story 1.24 has no `src/` construction of `MachinePrincipal` (an architecture rule holds it to that); machine denial is proven only at handler level with `TestOnlyMachinePrincipal`.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md`
  summary: Grant `gk_admin` `INSERT` on `tenant_role` and make a Tenant's creator its Tenant Owner; add the first Owner-only Deployment route with its HTTP refusal test for a non-Owner (Story 1.27).
  evidence: Story 1.24 makes `tenant_role` read-only and has no Owner-only route, so AC 2 is proven by the generated matrix, the route rule and a non-Owner's empty Deployment capability list.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md`
  summary: Tenant switching from an Admin's roles, and the "no Tenant Role" landing (Story 1.28).
  evidence: Story 1.24 adds the `tenant_role_admin` index for the switcher but no route lists an Admin's Tenants.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md`
  summary: Make a deleted Tenant's roles grant nothing (Story 1.29).
  evidence: Story 1.24's authorizer doesn't read `tenant` (AD-1), and `tenant_role` keeps `RESTRICT` keys, so deletion isn't designed yet.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md`
  summary: Grant `UPDATE (role)` and `DELETE` on `tenant_role`, audit role changes, guard the last Tenant Owner, and show the "role removed mid-session" banner (Story 8.4).
  evidence: Story 1.24 reads roles on every request, so a removal counts at once, but nothing writes or audits role changes.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md`
  summary: Write rejected cross-Tenant attempts to the Tenant's own Log, the FR-40 `CrossTenantRejection` class (Story 7.4).
  evidence: Story 1.24 writes `admin.access.denied` on the Deployment chain only, with no FR-40 class.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md`
  summary: Have the cross-Tenant suite read the Tenant routes from `x-gatekeep-access` in the committed OpenAPI document (Story 1.31).
  evidence: Story 1.24 adds `x-gatekeep-access` to every operation; the suite isn't built.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md`
  summary: Catch `ARCHITECTURE-SPINE.md` up with Story 1.24: the AD-19 self-service exemption under `/api/v1/deployment`, the public ID alphabet (lowercase RFC 4648 base32, no padding, canonical only, never the empty UUID) in Conventions, the capability names in AD-20, and `tenant_role` in AD-27's Admins tables.
  evidence: Story 1.24 exempts the reviewed self-service and sessionless routes from the Deployment Owner gate and fixes the public ID encoding, which the spine doesn't yet state.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md`
  summary: Over-HTTP refusal of a non-Owner on a real Owner-only Deployment route.
  evidence: Story 1.24 review; Story 1.27.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-25-open-the-admin-shell.md`
  summary: The Tenant switcher, the current Tenant's name and environment badge in the top bar, Tenant mismatch, and the final landing rules (Story 1.28).
  evidence: Story 1.25 out of scope. The top bar has the brand, the theme toggle and the avatar menu only, and the landing page is a holding page.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-25-open-the-admin-shell.md`
  summary: Help in the top bar, opening the API reference (Story 17.5).
  evidence: Story 1.25 out of scope. FR-44: a deferred feature doesn't appear in any form, so the top bar has no Help until the reference exists.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-25-open-the-admin-shell.md`
  summary: The create-Tenant landing and the first Deployment sidebar item, Tenants (Story 1.27).
  evidence: Story 1.25 ships the sidebar with an empty item registry (`apps/admin-dashboard/src/shell/nav.ts`) and a holding landing page.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-25-open-the-admin-shell.md`
  summary: The "role removed mid-session" and "Tenant deleted" banners (Story 8.4, Story 1.29).
  evidence: Story 1.25 out of scope. The shell reads capabilities on every navigation, so a removal counts at once, but no banner says so.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-25-open-the-admin-shell.md`
  summary: Prove Session renewal keeps the values of a real form on a real page (Story 1.27's Create Tenant is the first).
  evidence: Story 1.25 proves the banner slot keeps an input's value, focus and node on the fixture, and no reload or remount on a real 401 in the dashboard; no shell page has a form yet. Renewal's rule for a state-changing request (never resent) is proven by `apps/admin-dashboard/test/renewal.test.mjs` only.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-25-open-the-admin-shell.md`
  summary: Tenant page titles in `<title>`.
  evidence: Story 1.25 out of scope. Every shell page keeps the document title "Gatekeep Admin Dashboard".
- source_spec: `_bmad-output/implementation-artifacts/spec-1-25-open-the-admin-shell.md`
  summary: Prove a real form keeps its values across a Session renewal.
  evidence: Story 1.25 review; Story 1.27.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: The Tenant-surface fresh-assertion begin, `POST /api/v1/tenants/{tenantId}/assertions`, for Tenant capability actions (Story 1.27, or the first story that maps a Tenant route with a fresh-assertion capability).
  evidence: Story 1.26 refuses a Tenant capability action on the Deployment begin with 400 `assertion_refused`; the binding already takes the path Tenant.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: The first HTTP test of an `Always` capability route on a production route (Tenant deletion, Story 1.29; Admin invites and removal, Epic 8).
  evidence: Story 1.26 proves the checks' consume on a test-only route in `RequestChecksTests`; no production route declares an `Always` capability yet.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: The `WhenProdTenant` and `WhenLoweringPolicy` predicates, each evaluated in its route's handler before `FreshAssertionGate.RequireAsync` (their routes' stories).
  evidence: Story 1.26 builds the gate, the `EvaluatesFreshAssertion` marker and the reviewed handler-enforced list; registration begin is its only caller.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: Rename an Admin credential in Your credentials.
  evidence: Story 1.26 out of scope: credentials are named by their kind only.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: Reissue an Admin Recovery Code from Your credentials, and a Recovery Code for the Deployment Owner.
  evidence: Story 1.26 issues one only at setup, to an Admin who isn't the Owner (FR-2); the Owner's way back is Story 1.32's host recovery.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: Download for the Admin Recovery Code.
  evidence: Story 1.26 offers Copy only: a client-made file needs a `blob:` or `data:` URI, which AD-21's CSP forbids, and a server-sent one would be a second reveal.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: A Security Alert on Admin Recovery Code use and on credential removal (Story 1.30).
  evidence: Story 1.26 audits both on the Deployment chain and ends the Admin's other Sessions, but alerts nobody.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: Email notice of Admin credential changes (Story 8.2).
  evidence: Admins have no email address until Story 8.2.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: HMAC key rotation for `admin_recovery_code`, using its `hmac_key_version`.
  evidence: Story 1.26 stores the key version with each HMAC but never rewraps or rehashes.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: List the Admin's credentials in `allowCredentials` for fresh assertions.
  evidence: Story 1.26 keeps the begin options unchanged (empty `allowCredentials`), so the browser may offer another account's passkey, which the server then refuses.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: Purge `admin_attempt` rows.
  evidence: Story 1.26 adds two more policies counted there, per Session and per client; carries on the Story 1.20 item.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: Disable the credential, or raise a Security Alert, on a sign-count regression (Security Alerts story).
  evidence: Story 1.26 writes `admin.credential.sign_count_regressed` for fresh assertions too, with the Admin as Actor; the credential stays usable. Carries on the Story 1.23 item.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: End-to-end WebAuthn test, real browser, real dashboard and real server, for registration, sign-in and fresh assertions.
  evidence: Story 1.26's browser tests intercept the API, and its Isolation tests use a software authenticator. Carries on the Story 1.23 item.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: Catch `ARCHITECTURE-SPINE.md` up with Story 1.26: add `admin_fresh_assertion` and `admin_signin_challenge` to AD-27's Admins tables.
  evidence: Story 1.26 adds the `UNLOGGED` `control` table `admin_fresh_assertion`, which AD-27 doesn't name, nor Story 1.23's `admin_signin_challenge`.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: Retire the lost credential during recovery (Story 8.3).
  evidence: Story 1.26 review. A recovery registration evicts every other Session, but the lost credential stays registered, so whoever holds the lost device can sign in again until the Admin adds a third credential and removes it in Your credentials; threat model T-54.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: A recovery Admin who already holds the maximum of 10 credentials can't register one (Story 8.3).
  evidence: Story 1.26 review. A recovery Session's registration is refused with 409 `credentials_maximum` at 10, so such an Admin can only sign out.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: Re-key `admin_recovery_code` on Deployment `hmac` key rotation, or keep the old key version for recovery lookups (Epic 9).
  evidence: Story 1.26 review. The redeem looks a code up by its HMAC under the latest key version and ignores `hmac_key_version`, so rotating the key would invalidate every Recovery Code. No rotation path exists in the code yet; threat model T-54.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: Decide how removing an Admin works with the credential floor trigger (Epic 8, Admin removal).
  evidence: Story 1.26 review. `admin_credential_guard_delete` refuses any delete that leaves an Admin fewer than two credentials, for every role, so an Admin's credentials can't be deleted with them; threat model T-51.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: Limit only failed Recovery Code redemptions Deployment-wide.
  evidence: Story 1.26 review. `admins.recovery_code.deployment` counts every redemption before the code is read, since `IRateLimiter` has no way to check a limit without counting; a flood of wrong codes therefore also holds back the genuine Admin for the window.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: Key rotation must re-key or keep the old hmac version for Admin Recovery Code lookups.
  evidence: Story 1.26 review; Epic 9.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: Tenant-scoped fresh-assertion begin route.
  evidence: Story 1.26 review; Story 1.27 or the first Tenant fresh-assertion route.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: Admin removal must account for the credential floor trigger.
  evidence: Story 1.26 review; Epic 8.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: Retire the lost credential during recovery, and handle a recovery Admin at the maximum.
  evidence: Story 1.26 review; Story 8.3.
