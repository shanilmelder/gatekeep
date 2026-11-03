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
  summary: Make Hosted Login follow prefers-color-scheme (DESIGN.md line 579).
  evidence: Story 1.13 review; surface stories 1.18 and 1.25.
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
  summary: Store WebAuthn backup-eligible and backed-up flags for Admin credentials.
  evidence: Story 1.22 review; credential management.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-22-register-admin-webauthn-credentials.md`
  summary: End-to-end WebAuthn registration test: real browser, real dashboard, real server.
  evidence: Story 1.22 review.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-22-register-admin-webauthn-credentials.md`
  summary: Database guard for the two-credential cap and a race test for duplicate credential IDs.
  evidence: Story 1.22 review.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-23-sign-in-as-an-admin-with-webauthn.md`
  summary: Audit refused and rate-limited bootstrap claims (Epic 7).
  evidence: Story 1.23 audits Admin sign-in and sign-out only; the rest of the Story 1.21 item stays open.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-23-sign-in-as-an-admin-with-webauthn.md`
  summary: Audit Admin Session expiry, and show the expiry banner (Epic 7, and Story 1.25's shell).
  evidence: Story 1.23 out of scope. An expired Session is ended as `expired` with no event, and the dashboard only goes to `/signin` on the 401.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-23-sign-in-as-an-admin-with-webauthn.md`
  summary: Store and use the WebAuthn BE/BS backup flags for Admin credentials (credential management).
  evidence: Story 1.23 out of scope; carries on the Story 1.22 item. A synced passkey that reports a 0 counter gives no clone signal.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-23-sign-in-as-an-admin-with-webauthn.md`
  summary: Disable the credential, or raise a Security Alert, on a sign-count regression (Security Alerts story).
  evidence: Story 1.23 refuses the one sign-in and writes `admin.credential.sign_count_regressed`; the credential stays usable (threat model T-52).
- source_spec: `_bmad-output/implementation-artifacts/spec-1-23-sign-in-as-an-admin-with-webauthn.md`
  summary: Fresh assertions for sensitive Admin actions (FR-46 re-authentication).
  evidence: Story 1.23 out of scope; threat model T-22 and G-5.
- source_spec: `_bmad-output/implementation-artifacts/spec-1-23-sign-in-as-an-admin-with-webauthn.md`
  summary: Admin Recovery Codes, and the "Use a recovery code" link on Admin sign-in.
  evidence: Story 1.23 omits the EXPERIENCE link until Admin Recovery Codes exist.
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
