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
  evidence: A full disk under the only audit device blocks every request. Story 1.30 ships the log off the server, so only rotation (with the shipper starting over when the file is replaced) and a second device remain.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-7-hold-keys-in-openbao-behind-ikeycustody.md`
  summary: Set a secret ID lifetime and write the replacement procedure for one leaked secret ID.
  evidence: Story 1.7 setup uses secret_id_ttl=0. Story 1.10 delivers secret IDs.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-8-run-tenant-scoped-jobs.md`
  summary: Decide job retention for dead jobs.
  evidence: Story 1.8 purges only done jobs. Story 1.29 takes the Tenant deletion half: the `tenant` row is a tombstone and is never deleted, so no `RESTRICT` key to it fires, and the completion purges the Tenant's `job_payload` rows.
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
  summary: Order Operation stages, if a later Operation needs one stage to finish before another starts.
  evidence: Story 1.9 runs stages unordered. Story 1.29 no longer needs it: a deleted Tenant is a tombstone marked deleted by the completion handler, which runs after every stage, and its purge and key destruction are independent stages.
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
  status: done in Story 2.5. `Migration20261106000000CreateDirectoryTables` adds all three, validating any existing rows; `ClientCredentialsTests` covers the 23503.
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
  summary: Grant `UPDATE (role)` and `DELETE` on `tenant_role`, audit role changes, guard the last Tenant Owner, and show the "role removed mid-session" banner (Story 8.4).
  evidence: Story 1.24 reads roles on every request, so a removal counts at once, but nothing writes or audits role changes.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md`
  summary: Write rejected cross-Tenant attempts to the Tenant's own Log, the FR-40 `CrossTenantRejection` class (Story 7.4).
  evidence: Story 1.24 writes `admin.access.denied` on the Deployment chain only, with no FR-40 class.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md`
  summary: Have the cross-Tenant suite read the Tenant routes from `x-gatekeep-access` in the committed OpenAPI document (Story 1.31).
  evidence: Story 1.24 adds `x-gatekeep-access` to every operation; the suite isn't built.
  resolution: Resolved by Story 1.31. The suite reads the live route set from the running hosts (`tests/Isolation/Hosting/RunningRoutes.cs`), which `AdminEndpointTests` already holds equal to the committed document's operations, so `x-gatekeep-access` adds nothing the registry check doesn't. Every live route has an entry in `tests/Isolation/CrossTenant/RouteRegistry.cs`, and each `{tenantId}` and `{targetTenantId}` entry runs its refusal case.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md`
  summary: Catch `ARCHITECTURE-SPINE.md` up with Story 1.24: the AD-19 self-service exemption under `/api/v1/deployment`, the public ID alphabet (lowercase RFC 4648 base32, no padding, canonical only, never the empty UUID) in Conventions, the capability names in AD-20, and `tenant_role` in AD-27's Admins tables.
  evidence: Story 1.24 exempts the reviewed self-service and sessionless routes from the Deployment Owner gate and fixes the public ID encoding, which the spine doesn't yet state.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-25-open-the-admin-shell.md`
  summary: Help in the top bar, opening the API reference (Story 17.5).
  evidence: Story 1.25 out of scope. FR-44: a deferred feature doesn't appear in any form, so the top bar has no Help until the reference exists.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-25-open-the-admin-shell.md`
  summary: Prove the lost-Tenant banner for a removed role (Story 8.4).
  evidence: Story 1.25 out of scope. Story 1.29 shows one banner, "It was deleted, or your role in it was removed", when a Tenant the shell listed drops out; only deletion can make that happen until Story 8.4 removes single roles.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-25-open-the-admin-shell.md`
  summary: Tenant page titles in `<title>`.
  evidence: Story 1.25 out of scope. Every shell page keeps the document title "Gatekeep Admin Dashboard".
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: The first HTTP test of an `Always` capability route for Admin invites and removal (Epic 8).
  evidence: Story 1.26 proves the checks' consume on a test-only route in `RequestChecksTests`. Story 1.29's Tenant deletion start and retry are the first production `Always` routes, tested in `TenantDeletionTests`.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: The `WhenProdTenant` predicate for callback URLs (`tenant.application_callbacks.manage`, Epic 3) and the `WhenLoweringPolicy` predicate (Epic 6), each evaluated in its route's handler before `FreshAssertionGate.RequireAsync`.
  evidence: Story 1.26 builds the gate, the `EvaluatesFreshAssertion` marker and the reviewed handler-enforced list; registration begin is its only caller. Story 1.28 evaluates `WhenProdTenant` for `tenant.label.manage` only, on the locked label.
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
  summary: Admin removal must account for the credential floor trigger.
  evidence: Story 1.26 review; Epic 8.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md`
  summary: Retire the lost credential during recovery, and handle a recovery Admin at the maximum.
  evidence: Story 1.26 review; Story 8.3.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-27-create-tenants-with-permanent-subdomains.md`
  summary: Signing and Management keys as a Tenant creation stage, and their backfill for Tenants created before it (Story 2.3).
  evidence: Story 1.27's `tenancy.tenant.create` has one stage, the six secret class keys. A Tenant resolves on Host.Hosted once active, with no Signing Key yet.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-27-create-tenants-with-permanent-subdomains.md`
  summary: The built-in API record and the default Connection as Tenant creation stages (their stories).
  evidence: Story 1.27 out of scope: every stage a later story adds runs before the completion handler activates the Tenant.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-27-create-tenants-with-permanent-subdomains.md`
  summary: A Tenant page that a Tenants row opens (Story 3.1).
  evidence: Story 1.27: Tenants rows aren't links, as no Tenant page exists (FR-44). Story 1.28 keeps rows plain text: a Deployment Owner may hold no role in a listed Tenant, so a row link would often lead to the forbidden page.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-27-create-tenants-with-permanent-subdomains.md`
  summary: Restrict Operation and step status transitions (T-46, carried on).
  evidence: Story 1.27 doesn't change the Operation grants: `gk_admin`, `gk_cli` and `gk_worker` can still set any status.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-27-create-tenants-with-permanent-subdomains.md`
  summary: A per-Admin limit on Tenant creation.
  evidence: Story 1.27 `[ASSUMPTION]`: only the Deployment Owner creates Tenants, unlimited, and each creation makes six Transit keys; its audit event is written per creation, unthrottled.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-27-create-tenants-with-permanent-subdomains.md`
  summary: A Tenant host resolution cache on Host.Hosted (AD-14), if a measured need appears.
  evidence: Story 1.27 reads `tenant_host` joined to `tenant` as `gk_hosted` on every request, with no cache, so activation is seen at once.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-27-create-tenants-with-permanent-subdomains.md`
  summary: The Tenant name's bidi isolation in the dashboard (Story 18.3, carried on).
  evidence: Story 1.27 shows the Admin-supplied name as text in the Tenants list and the create progress line.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-27-create-tenants-with-permanent-subdomains.md`
  summary: Catch `ARCHITECTURE-SPINE.md` up with Story 1.27: AD-27's `tenant` columns (name, label, status, issuer, rp_id, email_link_base), the Operation completion handler in AD-30, the `opr_` prefix in Conventions, and the `creating` status that resolves to the fixed 404 in AD-6.
  evidence: Story 1.27 builds them; the spine doesn't state them yet.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-27-create-tenants-with-permanent-subdomains.md`
  summary: Give the Operation audit envelope an Operation target kind, so `operations.operation.retried` can name the Operation itself.
  evidence: Story 1.27: `AuditTargetKind` has no Operation, so the retry event targets the Operation's Tenant; `tenancy.tenant.created` likewise can't carry the label, which stays on the Tenant.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-27-create-tenants-with-permanent-subdomains.md`
  summary: Catch `ARCHITECTURE-SPINE.md` up with the Tenancy module's new reach: it carries an ASP.NET Core `FrameworkReference` and the Npgsql package (for `Host.Hosted`'s resolution middleware and its own SQL), which every module depending on Tenancy, so every host and the Cli, now gets.
  evidence: Story 1.27 review: AD-1 doesn't yet say a module may carry a framework reference.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-27-create-tenants-with-permanent-subdomains.md`
  summary: A per-client limit on `Host.Hosted`'s Tenant host lookup (Epic 10).
  evidence: Story 1.27 review: the lookup has a 3-second command timeout, a 5-second connect timeout and a pool of 20 connections, so a flood answers 503, but nothing counts per client.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-27-create-tenants-with-permanent-subdomains.md`
  summary: A browser test that polling stops when Create Tenant or Tenants unmounts.
  evidence: Story 1.27 review: the pages stop their timers on unmount, but no browser test watches for a read after navigating away.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-27-create-tenants-with-permanent-subdomains.md`
  summary: Widen `tenant_role_guard_insert` when Story 8.4 grants roles to other Admins.
  evidence: Story 1.27 review: the trigger holds `gk_admin` to inserting the creator's `owner` role on a `creating` Tenant.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-27-create-tenants-with-permanent-subdomains.md`
  summary: Per-client limit on Host.Hosted Tenant lookups.
  evidence: Story 1.27 review; Epic 10.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-27-create-tenants-with-permanent-subdomains.md`
  summary: Browser test that the Create Tenant poll stops on unmount.
  evidence: Story 1.27 review.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-27-create-tenants-with-permanent-subdomains.md`
  summary: Record Tenancy's ASP.NET Core and Npgsql dependency in the architecture spine.
  evidence: Story 1.27 review.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-28-switch-tenants-and-set-the-environment-label.md`
  summary: Refuse to label a Tenant Prod while `GATEKEEP_CONFORMANCE_TENANT` is set (Story 4.14, AD-21).
  evidence: Story 1.28 out of scope: any Tenant Owner can label any active Tenant Prod; threat model T-36.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-28-switch-tenants-and-set-the-environment-label.md`
  summary: The Applications list as the Tenant landing (Story 3.1).
  evidence: Story 1.28 `[ASSUMPTION]`: `/tenants/{tenantId}` and the landing with a Tenant Role open the Tenant settings page, which holds only the environment.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-28-switch-tenants-and-set-the-environment-label.md`
  summary: FR-10's other Tenant settings on the Tenant settings page (Story 8.5).
  evidence: Story 1.28 builds the page with the environment only, which the label route needs.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-28-switch-tenants-and-set-the-environment-label.md`
  summary: Paging or search in the Tenant switcher.
  evidence: Story 1.28 `[ASSUMPTION]`: `GET /api/v1/deployment/my-tenants` lists every active Tenant the Admin holds a role in, with no paging, and the switcher shows them flat.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-28-switch-tenants-and-set-the-environment-label.md`
  summary: The label in the audit envelope, so `tenancy.tenant.label_changed` can say which label (carried on from Story 1.27).
  evidence: Story 1.28 writes two codes, `label_changed` and `prod_label_removed`, because the envelope can't carry the new label (AD-16).
- source_spec: `_bmad-output/implementation-artifacts/spec-1-28-switch-tenants-and-set-the-environment-label.md`
  summary: The `X-Gatekeep-Tenant` mismatch rule for the Management API's bearer scheme (Story 17.3).
  evidence: Story 1.28 applies it to Admin Sessions, the only principals today.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-28-switch-tenants-and-set-the-environment-label.md`
  summary: Prove the lost-Tenant banner for a removed role (Story 8.4, carried on).
  evidence: Story 1.28 reads the switcher's list on every navigation. Story 1.29's banner covers both causes, and is proven for deletion only.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-28-switch-tenants-and-set-the-environment-label.md`
  summary: Tenant page titles in `<title>` (carried on from Story 1.25).
  evidence: Story 1.28's Tenant settings page keeps the document title "Gatekeep Admin Dashboard".
- source_spec: `_bmad-output/implementation-artifacts/spec-1-28-switch-tenants-and-set-the-environment-label.md`
  summary: Bidi isolation beyond the Tenant switcher and the mismatch banner (Story 18.3, carried on).
  evidence: Story 1.28 isolates the Tenant name in `<bdi>` in the switcher, the mismatch banner and the Prod modal only.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-28-switch-tenants-and-set-the-environment-label.md`
  summary: Every later rule that reads the label (the 90-day Prod retention floor, Prod callback confirmation, Dev-only email verification off, the conformance Tenant) reads it when its own setting changes, and never rewrites a setting because the label changed.
  evidence: Story 1.28: no setting reads the label yet, so removing Prod writes only `tenant.label`; threat model T-56.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-29-delete-a-tenant-without-touching-others.md`
  summary: A caller for the `audit.chain.purge` Operation, to schedule a Tenant's chain purge again after its job went dead.
  evidence: Story 1.29's completion enqueues the purge job itself, from the Tenant's scope; the Operation stays registered with no production caller.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-29-delete-a-tenant-without-touching-others.md`
  summary: Cancel or fail a deleted Tenant's pending jobs.
  evidence: Story 1.29 leaves them: each later job type must re-check the Tenant's status (AD-15). The completion purges their payloads.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-29-delete-a-tenant-without-touching-others.md`
  summary: Have the retention sweep skip a deleted Tenant whose chain is purged.
  evidence: Story 1.29: the sweep lists every `tenant` row, tombstones included, so it keeps enqueuing apply jobs that find nothing to cut.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-29-delete-a-tenant-without-touching-others.md`
  summary: Show tombstones, and read a deleted Tenant's Logs, from the Dashboard (Epic 7).
  evidence: Story 1.29 `[ASSUMPTION]`: a deleted Tenant leaves the Tenants list; its chain is kept but no page reads it.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-29-delete-a-tenant-without-touching-others.md`
  summary: A Tenants list refresh that covers rows loaded with Load more.
  evidence: Story 1.29: the bounded refresh re-reads the first page only, so a deleting row on a later page keeps "Deleting" until the page reloads.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-29-delete-a-tenant-without-touching-others.md`
  summary: An HTTP test for the start route mapping `GK007` and `GK009` to 409 `tenant_deleted`.
  evidence: Story 1.29 review: the start holds the Tenant's row lock before it writes, so a concurrent start waits and finds the Tenant deleting; reaching either guard needs a fault seam.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-29-delete-a-tenant-without-touching-others.md`
  summary: A test for the purge stage's `GK008` savepoint rollback (`purge_refused`).
  evidence: Story 1.29 review: the stage re-checks the Tenant is deleting under its own `FOR UPDATE` lock before it deletes settings, so the guard is unreachable without a fault seam.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-29-delete-a-tenant-without-touching-others.md`
  summary: Map `GK010` (a Tenant row written for a Tenant being deleted, or deleted) on Host.Hosted's first write route to its fixed 404 or 503, never a 500 (Epic 2).
  evidence: Story 1.29 review: `tenant_row_guard` raises it on every purged table, but Host.Hosted has no write route yet, so there is nothing to map.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-29-delete-a-tenant-without-touching-others.md`
  summary: Close the residual race on purged-table writes: a statement that passed `tenant_row_guard` before the deletion started but runs its foreign-key check only after the purge stage's lock commits keeps its row.
  evidence: Story 1.29 review: no runtime role but gk_admin and gk_worker may lock `tenant` rows, so the guard's read takes no lock; the purge stage's `FOR UPDATE` waits out every writer whose foreign-key check already holds the row, which leaves only a statement stalled between its row trigger and its check across the whole start-to-purge interval.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-29-delete-a-tenant-without-touching-others.md`
  summary: Fault seam to test the deletion guard mappings that the locks make unreachable.
  evidence: Story 1.29 review.
- source_spec: `_bmad-output/implementation-artifacts/spec-2-3-publish-discovery-and-jwks-per-tenant.md`
  summary: Bound or fan out the hourly key backfill, so a first run over many pre-2.3 Tenants can't outlive its job lease.
  evidence: Story 2.3 review: `TenantKeyBackfill.RunAsync` provisions every active Tenant in one job run (up to four RSA-3072 Transit keys plus a wrap each).
- source_spec: `_bmad-output/implementation-artifacts/spec-2-3-publish-discovery-and-jwks-per-tenant.md`
  summary: A test that concurrent cold requests share one Tenant runtime build, alongside Story 2.5's token-endpoint load test.
  evidence: Story 2.3 review: every Protocol test sends requests one at a time.
  status: done in Story 2.5. `ClientCredentialsTests.Fifty_concurrent_requests_on_a_cold_runtime_all_get_tokens_from_one_build`: 50 parallel token requests, each blocking on a Transit signature, all succeed from one runtime build (one public-key read per key, one unwrap).
- source_spec: `_bmad-output/implementation-artifacts/spec-2-3-publish-discovery-and-jwks-per-tenant.md`
  summary: Rotation and revocation (Stories 2.4, 9.x) must never commit a Tenant with a `next` and no `current`, or `EnsureTenantKeysAsync` would create a `current` that was never published ahead.
  evidence: Story 2.3 review: the backfill creates whatever (purpose, state) is missing.
- source_spec: `_bmad-output/implementation-artifacts/spec-2-3-publish-discovery-and-jwks-per-tenant.md`
  summary: A stored, unique, dot-free `tenant.public_id` before Story 2.9 issues codes.
  evidence: Story 2.3 left it out by spec; only `PublicId.Format` exists.
- source_spec: `_bmad-output/implementation-artifacts/spec-2-3-publish-discovery-and-jwks-per-tenant.md`
  summary: Story 2.4 adds the `NOTIFY` that clears Host.Hosted's 5-second Tenant runtime cache on a key state change.
  evidence: Story 2.3 caches each runtime for at most 5 seconds, with no NOTIFY yet.
- source_spec: `_bmad-output/implementation-artifacts/spec-2-4-rotate-signing-keys-automatically.md`
  summary: An alert when a `current` Signing Key passes 180 days because rotation keeps failing (Epic 11).
  evidence: Story 2.4 review: the daily rotation only logs a failed Tenant by type and retries.
- source_spec: `_bmad-output/implementation-artifacts/spec-2-4-rotate-signing-keys-automatically.md`
  summary: Destruction for `revoked` Signing Keys (Epic 9).
  evidence: Story 2.4 destroys only `retired` keys; `destroyed_at` is CHECKed to `retired` rows.
- source_spec: `_bmad-output/implementation-artifacts/spec-2-4-rotate-signing-keys-automatically.md`
  summary: Decide whether to rotate on a 75/75-day cadence (time served) instead of counting age from creation, which double-rotates every cycle.
  evidence: Story 2.4 review: alternate keys sign about 1 day and about 149 days; still within 180 days.
- source_spec: `_bmad-output/implementation-artifacts/spec-12-7-rotate-the-master-key.md`
  summary: Prove that `sys/rotate/root` changes the root key, so that an old generation plus a snapshot taken before the rotation can't open data written afterwards.
  evidence: Story 12.7 checks that the keyring term rises. Removing the root-key call still passes every test. It needs a snapshot-and-restore harness, which comes with Stories 12.1 and 12.2.
- source_spec: `_bmad-output/implementation-artifacts/spec-12-7-rotate-the-master-key.md`
  summary: Rewrap or re-encrypt existing ciphertext to the new Transit versions, and then retire the old versions (G-16).
  evidence: Story 12.7 only rotates the versions. OpenBao 2.7.2 rewrap ignores `associated_data`. The threat model assigns this to Stories 12.2 and 13.4.
- source_spec: `_bmad-output/implementation-artifacts/spec-12-7-rotate-the-master-key.md`
  summary: Sign in before and after a Master Key rotation in the stack check, once a sign-in flow exists (Epic 2).
  evidence: Story 12.7 shows "sign-in keeps working" only on the custody operations sign-in uses, because Hosted still answers 404.
- source_spec: `_bmad-output/implementation-artifacts/spec-12-7-rotate-the-master-key.md`
  summary: Check the escrow retention rule and "never in a backup" against the real backup set and manifest (Story 12.1).
  evidence: Story 12.7 states the rule in the runbook, and `finish` prints it. Its stack check searches volumes, images and environments for both generations, but no backup exists yet.
- source_spec: `_bmad-output/implementation-artifacts/spec-12-7-rotate-the-master-key.md`
  summary: Make the root-token census in `MasterKeyRotationTests.Full_rotation_keeps_every_value_and_leaves_the_old_generation_unable_to_unseal` stable under load.
  evidence: While merging `main` into Story 1.29 on 2026-11-05, the census step (line 155) printed nothing in 2 of 5 local Docker runs alongside other classes, and passed alone and on rerun. Story 1.29 doesn't touch root tokens.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-30-connect-the-alert-channel-and-off-server-store.md`
  summary: Stop the audit shipper re-shipping a chunk after a crash between the `PUT` and the save of its offset.
  evidence: Story 1.30 saves the offset only after a successful `PUT`. A crash in between ships the same `{fileId}-{startOffset}` key again as a second locked version, or under the next day's path after midnight. A clean restart is tested. Fixing it needs a read-back or a conditional `PUT`, and the credential can't read.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-30-connect-the-alert-channel-and-off-server-store.md`
  summary: Read the alert webhook URL from a secret file, so a provider whose URL path is the credential can be used safely.
  evidence: Story 1.30 passes `GATEKEEP_ALERT_URL` as a plain environment variable, so it shows in `.env` and `docker inspect`. `install.md` requires a URL that carries no credential, with the token in `alerts/token`.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-30-connect-the-alert-channel-and-off-server-store.md`
  summary: Bind a signed off-server record to its object key, or check its `id` and `writtenAt` against the key when verifying.
  evidence: Story 1.30's `OffServerRecordWriter.VerifyAsync` checks only the signature. Someone holding the write-only credential could copy an old signed record to a new key. Belongs with Story 7.2's verifier.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-30-connect-the-alert-channel-and-off-server-store.md`
  summary: Design a filtering egress proxy for the `egress` network, so the worker, cli and shipper can reach only the alert and bucket hosts.
  evidence: Story 1.30's `egress` network is unrestricted, and threat-model T-59 accepts that until such a proxy is designed.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-30-connect-the-alert-channel-and-off-server-store.md`
  summary: Tidy up the EgressHttp edge cases.
  evidence: Story 1.30 has these open:
    - an empty DNS answer is reported as "no public address";
    - a bracketed literal with a named zone ends as Unavailable;
    - secret file reads have no size cap;
    - the handler that `EgressHttp.Create()` returns can still be changed afterwards;
    - no test makes a connect hang.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-30-connect-the-alert-channel-and-off-server-store.md`
  summary: Make the `openbao.audit.ship` canary flow ship real OpenBao audit lines and search both days' prefixes.
  evidence: Story 1.30's `CanaryFlows.AuditShipAsync` ships synthetic HMAC lines and builds its prefix from `DateTime.UtcNow`, so it can flake at midnight UTC. `AuditShipTests` cover real Transit output. After an OpenBao crash, a partial last line is glued to the next line and shipped as is.

- source_spec: `_bmad-output/implementation-artifacts/spec-2-5-issue-a-token-by-client-credentials.md`
  summary: Keep unauthenticated token traffic from locking real machine clients out of a Tenant through the per-Tenant token limit.
  evidence: Story 2.5 review. `LimitTokenRequests` counts the 1200/min per-Tenant limit before client authentication (as §5.2 asks), so about 20 sources at 60/min each make every token request at that Tenant answer 429, valid clients included. Needs a product decision, such as counting the Tenant limit after authentication or reserving capacity for authenticated clients.
- source_spec: `_bmad-output/implementation-artifacts/spec-2-5-issue-a-token-by-client-credentials.md`
  summary: Prune expired access-token rows from `token`.
  evidence: Story 2.5 review. Every Client Credentials token writes a `token` row and Story 2.5 excludes pruning; at the per-Tenant limit that is up to about 1.7 M rows per Tenant per day, with nothing removing expired ones.
- source_spec: `_bmad-output/implementation-artifacts/spec-2-5-issue-a-token-by-client-credentials.md`
  summary: Sweep stale `tenant_attempt` (and `admin_attempt`) counter rows.
  evidence: Story 2.5 review. Each distinct IPv4 address or IPv6 /64 leaves a lasting row per policy per Tenant; rows go only on a crash (UNLOGGED) or Tenant deletion. `admin_attempt` has the same gap.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-32-recover-admin-access-from-the-host.md`
  summary: Let `gatekeep recover-admin` recover an Admin who already holds the 10-credential maximum, and retire the lost credentials during recovery.
  evidence: Story 1.32 review. Lost credentials stay registered, so an Admin at the maximum uses up the enrolment and loses their Sessions but can't register a new one. This belongs with Story 8.3's credential retirement.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-32-recover-admin-access-from-the-host.md`
  summary: Print the `recover-admin` link with the Admin site's HTTPS port when it isn't 443.
  evidence: Story 1.32 review. The `cli` service doesn't get `GATEKEEP_HTTPS_PORT` or the Admin origin, so a non-443 setup (such as dev on 18443) must add `:{port}` by hand, as `docs/install.md` says.
