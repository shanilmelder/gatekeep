---
title: Architecture spine reconciliation against the PRD
created: 2026-11-02
spine: ../ARCHITECTURE-SPINE.md
prd: ../../../prds/prd-gatekeep-2026-11-01/prd.md
verification: ../../../prds/prd-gatekeep-2026-11-01/verification.md
---

# Reconcile: Architecture Spine vs PRD

## Verdict

**Needs revision before epics.** The spine is strong on isolation, custody, audit and token format, and its PRD references are almost entirely accurate. Five High findings remain:

- The module dependency diagram can't legally host several FRs.
- The compromise paths (V-3) stop short of UJ-6.
- V-2 is still open.
- V-1 is only partly closed.
- The Admin host has no TLS terminator.

Each needs an AD amendment, and R-2 and R-3 also need a PRD decision. None needs a change of paradigm or stack.

Severity:

- **High:** a requirement is contradicted, or left open on a security or foundation path where two builders would diverge.
- **Medium:** a real divergence with a contained blast radius.
- **Low:** a quiet requirement or precision gap that a one-line fix closes.

Tags on findings:

- **Contradicted:** the spine conflicts with the PRD, or with itself on a PRD consequence.
- **Unaddressed:** no rule exists, and two builders could diverge.
- **Dropped:** a quiet PRD requirement fell out of the AD structure.

The FR-to-AD reading is my own trace through the spine. No code exists yet, so nothing was tested. OpenIddict behaviour noted below comes from my knowledge of the library plus the spine's memlog, and the spike should confirm it.

## V-1 to V-9 status

The PRD changed after `verification.md`, so each item was judged against the current `prd.md`.

| Item | PRD now | Spine | Status |
| --- | --- | --- | --- |
| V-1 FR-42 vs FR-46 | FR-42 excludes all FR-46 actions | AD-19 `[FreshAssertion]` | **Partly landed**, R-4 |
| V-2 Passkey-only lockout | FR-27 and FR-31 now cover Passkeys. The first sign-in afterwards is still undefined | Nothing | **Open**, R-3 |
| V-3 FR-50 vs UJ-6, NFR-9 | FR-50 now revokes all Signing Keys | AD-11 and AD-13 cover part of it | **Partly landed**, R-2 |
| V-4 first Tenant Role | FR-7 makes the creator Tenant Owner | No conflict | Closed |
| V-5 display name | FR-7 no longer mentions it | No conflict | Closed |
| V-6 dangling §5.2 | Rows now exist. Per-source thresholds still have no row | AD-14 and the Limits convention | Closed for architecture. The per-source value is a PRD gap (NFR-6, FR-28) |
| V-7 erasure vs chain | Unchanged | AD-16 separates `audit_detail` and adds checkpoints | Closed, with R-17 |
| V-8 social conflict | Exception in NFR-20 | Nothing needed | Closed |
| V-9 FR-37 vs FR-38 | Unchanged | AD-11 | Closed for single-key revoke. Not for revoke-all (R-2), and two literal FR-37 deviations aren't recorded (R-14) |

Medium items in `verification.md` section 5 that touch architecture:

| Item | Status |
| --- | --- |
| H-8 Admin invite email | Closed by the Email convention |
| L5.2 restore scope | Closed by AD-18 |
| B-14 Deployment Log | Route exists, but Host.Admin has no path to Audit (R-1) |
| B-7 FR-49 | No flow owner (R-1, R-11) |
| A-7 Passkey autofill | Not placed. AD-21 should say the challenge is in the first response (R-19) |
| D-4 Tenant name uniqueness | Still undecided. Not architecture-blocking, and subdomain uniqueness carries the identity |
| FR-36 test email, Viewer (QUESTION) | AD-20's generated test will deny it, because the matrix has no row (R-19) |

## High findings

### R-1. The dependency diagram can't host FR-48, FR-50, FR-40, FR-30, FR-31, FR-36 or FR-6 (Contradicted)

AD-1 says dependencies follow the diagram and that architecture tests fail the build on a violation. Host.Admin reaches only Management, and Management reaches only Directory, Identity, Keys and Tenancy. Tracing the FRs through those edges:

- **FR-48:** triggers fire in Identity and Directory, and in Management for Admin actions. Identity, Directory and Management have no edge to Sessions. Only Authentication and Protocol reach it, and Operations does so from the Worker.
- **AD-13's single revocation command has no owner.** It must end Sessions (Sessions) and Token Families, which are OpenIddict tables. Protocol depends on Sessions, so if Protocol owns those tables, Sessions can't reach them. If Sessions owns them, Protocol can't query them under AD-1. No AD assigns them.
- **FR-30, FR-31, FR-50:** viewing or revoking Sessions from Host.Admin has no edge.
- **FR-40, B-14, FR-49:** Management has no edge to Audit, unless transitive use is allowed, and the spine doesn't say.
- **FR-50, FR-6:** the map places these in Operations, but only Host.Worker reaches Operations, and Management has no edge to it.
- **FR-36, FR-48, FR-5, FR-45:** Notifications appears in the Structural Seed and the map but not in the diagram, so no module may call it.
- **FR-23:** Protocol reaches Directory, Keys and Sessions, not Identity. If profile or email claims sit in Identity, userinfo has no path. The spine doesn't say which of Identity and Directory owns the User row.
- **AD-21:** theme generation is Tenancy-only, and Host.Hosted reaches Tenancy only transitively.
- **Cli:** it isn't in the diagram, yet it runs restore and recovery.

**Proposed fix:**

1. Add the missing edges. Management needs Sessions, Audit, Notifications and Operations or its contract. Add Identity and Directory to Sessions, or route FR-48 through a named orchestrator.
2. Add Notifications and Cli to the diagram.
3. Name the owner of the OpenIddict tables. I'd use Sessions, renamed Sessions and Tokens if preferred, with Protocol calling its contract.
4. Name the owner of the User row.
5. State whether transitive dependency is allowed.

### R-2. FR-50 and UJ-6 stop short: revoke-all has no key path, and forced re-enrolment and secret replacement have no owner (Contradicted, Unaddressed)

This is what remains of V-3.

- **Revoke-all contradicts AD-11.** FR-50 revokes all Signing Keys and says FR-38 replaces them automatically. AD-11's only replacement is promoting `next`. If `next` is revoked too, which UJ-6 requires, nothing can be promoted, yet AD-11 requires exactly one `current` and one `next` at commit. The state diagram has no route from a freshly created key to `current`, apart from the new-Tenant exception.
- **Forced password reset and TOTP re-enrolment have no design.** AD-13 covers the Session and token half of FR-50 only. No AD says where the "must reset" or "must re-enrol" state lives, or how a sign-in transaction enforces it. FR-25 and FR-29 interact here, and a forced reset under Always must not become an email bypass.
- **Deployment-wide execution isn't defined.** AD-13 says one transaction per Tenant. AD-4 agrees, but nothing says whether this is a synchronous loop in Host.Admin or one job per Tenant, how partial failure is shown, or how an action that must write to the Log and Deployment Log is resumed. An operator mid-compromise needs that answer.
- **UJ-6 and NFR-9 have no mechanism.** "Every key and secret" includes client secrets, Connection credentials, email credentials, TLS and DNS, per SEC-22. `gatekeep restore` has only a default mode and `--planned-rollback`. A clean-hardware restore after compromise needs a mode that replaces rather than reconciles. The spine's Cli list has no such command, and AD-18 leaves everything to an unnamed runbook.
- **NFR-3 Master Key rotation is dropped.** NFR-3 requires rotation without resetting Users, and NFR-9 requires replacement in UJ-6. AD-10 defines custody but no rotation. Rotation also has to state which escrow copy opens which older backup.

**Proposed fix:**

1. Amend AD-11 with a `revoke-all` transition that creates a replacement, promotes it unaged in the same command, creates a new `next`, and logs both as unaged.
2. Add a `credential_reset_required` state on the User, enforced by `signin_transaction`, with a rule for each of FR-25, FR-27 and FR-29.
3. State that the Deployment-wide action is one idempotent job per Tenant, with progress visible and retried failures raising a Security Alert.
4. Add `gatekeep restore --compromised`, or a `gatekeep rekey` command, that lists and forces replacement of every secret class.
5. Add Master Key rotation to AD-10, and record the key generation in each backup manifest.

### R-3. No first sign-in exists after an Admin resets a Passkey-only User (Unaddressed)

V-2's first half landed in the PRD, because FR-31 now resets Passkeys. Its second half didn't. Under Always, FR-27 says "The User then enrols again under FR-25", and a Passkey-only User now holds nothing that can start a sign-in. FR-25 bars email from bypassing a Factor, and no Admin-issued artifact exists in the spine. AD-12's `signin_transaction` has no entry state for this, and AD-9 and AD-24 list no such artifact, so the FR-8 artifact registry won't cover it either. The verification pass tied this to a critical rubric finding.

Builders could reasonably pick an emailed link, which breaks FR-25, an Admin-handed code, or a dead end.

**Proposed fix:** take a PRD decision first. The likely shape is a single-use, short-lived, Admin-issued enrolment artifact delivered out of band, with no email-only path, modelled on FR-5. It needs a §5.2 lifetime, an AD-9 and AD-24 entry, a Log event and a Security Alert or User notification. The alternative is for the PRD to state that the account can't be recovered.

### R-4. `[FreshAssertion]` isn't "the only rule needed" for FR-42 (Contradicted)

This is what remains of V-1. AD-19 says the marker alone applies the FR-42 exclusions. It doesn't:

- **FR-42 excludes "Admin management", which is wider than FR-46's "Admin grant or removal".** Tenant Role reads and invites aren't in the FR-46 list. `/api/v1/deployment/*` has no machine access, but the spine doesn't say Tenant Role routes live there.
- **FR-42 bars a client from creating or changing any client's Management API access.** FR-46 lists only granting. Revoking or narrowing another client's grant, or a client editing itself, isn't marked.
- **The Prod callback bypass survives through creation.** A machine client can create a new Application with a Prod callback URL, which isn't "changing" one, and the original V-1 risk returns. FR-45 also alerts on "a callback URL added in a Prod Tenant". Creating a secret on a new Application has the same shape.
- **Several markers are conditional.** "Lowering MFA policy" and "Prod Tenant's callback URLs" depend on data, not on the route. An action-level attribute can't express this, so builders would either over-block or check it in the handler differently each time.

**Proposed fix:** replace the sentence with an explicit, reviewed `MachineDenied` list in the Tenancy capability table covering Admin management, all Management API access changes, and Application creation or callback edits in a Prod Tenant. Let `[FreshAssertion]` take a predicate evaluated in the handler (AD-5). Add a generated test that every machine-allowed route is outside the list.

### R-5. Host.Admin has no TLS terminator, certificate or RP ID (Contradicted)

NFR-4 requires TLS on all external traffic, and FR-46 requires WebAuthn on the Admin hostname. WebAuthn and `Secure` cookies need HTTPS. In the spine:

- AD-6 has Caddy forward only hostnames under the zone, and the Admin hostname sits outside it.
- AD-26 binds Host.Admin directly to the VPN interface and gives the TLS key only to Caddy's container.
- The Structural Seed draws Admin traffic going directly to HA, bypassing Caddy.
- AD-6 defines RP ID only for Tenants, so the Admin RP ID has no rule, and AD-7's seam doesn't touch it.

Admin sign-in is in the first §7.4 phase, so the first builder hits this. They could add a second Caddy listener on the VPN, have Kestrel terminate with a private CA, or use a public certificate that puts the hostname in CT logs.

**Proposed fix:** add to AD-26 a second Caddy site bound to the VPN interface for the Admin hostname, with its own certificate from a private CA or DNS-validated. Update AD-6's "forwards only" rule and the diagram. Add a fixed Deployment-level Admin RP ID that never comes from the request. Note that changing it invalidates every Admin credential.

## Medium findings

### R-6. "Token Family is one authorization row" conflicts with its own consequence and FR-15 (Contradicted)

AD-13 says the authorization row anchors to one Session (also in the ER diagram) and that it stays after reuse "so a fresh sign-in still works". If each sign-in makes a new row, that sentence is meaningless. If a sign-in reuses the row, which OpenIddict supports for permanent authorizations, a family spans several Sessions and reuse would kill an unrelated login. That's the "two definitions of family" AD-13 exists to prevent. Separately, FR-15's absolute lifetime has no anchor. Rotating on each use means a per-token expiry slides forever unless the deadline sits on the family.

**Fix:** state that each code exchange creates a new ad-hoc authorization, never reused. Store family `absolute_expires_at` on it and copy it to every rotated token. Delete the "fresh sign-in" clause or reword it as "the Session is untouched".

### R-7. FR-4 clean-hardware restore needs things that aren't in the backup (Contradicted)

FR-4 says restore uses only the off-server backup, the escrowed Master Key and the documentation. AD-18 excludes the breach dataset, and nothing covers runtime secrets injected through systemd or Compose: database role passwords, OpenBao tokens, Object Lock and alert credentials, the Deployment email provider, DNS credential and Compose values. The TPM reseal on new hardware isn't in AD-18's ordered list either. NFR-13's one hour has to include all of this. Behaviour with a missing breach dataset also isn't stated, though FR-29 implies fail-closed or an explicit degraded state.

**Fix:** put Deployment secrets in OpenBao KV, or add an escrowed bundle listed in the manifest. Add the TPM reseal step to AD-18. State the dataset's source, update path and missing-file behaviour in AD-24.

### R-8. Restore replay covers revocations, not deletions (Unaddressed)

AD-17 and AD-18 replay revocations. Within the lost-change window, a restore also brings back a deleted Tenant with its Transit keys (FR-7), erased personal data (FR-49, NFR-14), deleted Users, and forgets a Tenant Subdomain issued after the backup, breaking "never reused". A Transit key destroyed after the backup also returns in the snapshot, so replay must destroy it again, not just flip the row.

**Fix:** widen the replayed event set to Tenant deletion, User deletion, erasure and Tenant host creation, by internal ID. State that key replay re-runs destruction.

### R-9. Several FR-45 triggers aren't audit event types (Unaddressed)

AD-17 derives alerts from event types through one table. These triggers need more than that:

- "Refresh token reuse above a threshold" and "a failed sign-in spike" are aggregates, and NFR-6 also tightens limits on the spike. No AD says who computes the window, whether it's per Tenant or Deployment-wide, or where the tightened state lives.
- "Admin sign-in from a new device" needs a definition.
- "A Log verification failure": `gatekeep audit verify` is a manual Cli command, so nothing runs it on a schedule, and a failure from a Cli has no stated alert path.

**Fix:** add a threshold rule type to the AD-17 table, evaluated by a Worker job. Add a scheduled verify job. Define new device as a credential not previously seen, or as a stored marker.

### R-10. Cli and sealer roles don't exist in AD-3 (Contradicted)

AD-3 lists four runtime roles and says `gk_migrator` connects "only during `gatekeep migrate`". AD-18 uses it under `gatekeep upgrade`. Restore, `recover-admin` and `audit verify` must write or read under AD-5 and AD-4, with no role named. AD-16's "sealer role" and retention-delete privilege also aren't in AD-3, and `gk_worker` is a runtime role, so "runtime roles have INSERT and SELECT" and "the sealer may update" conflict unless a separate role exists. The AD-3 catalogue test can't assert what isn't listed. FR-2's one-time token has no Cli command, though EXPERIENCE says it's read on the server.

**Fix:** add `gk_sealer`, `gk_retention` and `gk_ops` to AD-3. Add `bootstrap-token` to the Cli list. Correct the `gk_migrator` sentence.

### R-11. Tenant deletion and FR-49 have no flow (Unaddressed)

FR-7 keeps only security Logs, so every other Tenant row must go. The spine covers the 404, the host row and the audit purge. It doesn't state the ordering of soft-delete, key destruction, destroying the per-Tenant Transit key that makes secrets unreadable, or the purge job and its timing. It also doesn't say what happens to `audit_detail` personal data for the 90-day period. "Its retention" in AD-16 could be under 90 days in a Dev Tenant, while FR-7 says 90 flatly. FR-49 has no owner across Identity, Directory, Sessions and Audit, and no statement of how an export file is held and delivered (B-7).

**Fix:** add a short Tenant deletion sequence, and an FR-49 orchestrator command, to AD-16 or a new AD. Set retention for a deleted Tenant to 90 days regardless of label.

### R-12. AD-9's "every opaque artifact" can't apply to FR-8's typed artifacts (Contradicted)

FR-8 names email codes and Recovery Codes as artifact types. AD-9 says every opaque artifact is `{tenantPublicId}.{random}` with 256 bits. §5.2 fixes email codes at 6 digits, and AD-24 acknowledges that. So the rule's rejected-cross-Tenant signal, which AD-9 calls the production signal for SM-2, can't fire for those types, and the cross-Tenant suite driven from the AD-25 artifact registry has no defined expectation. Token-path mismatch (AD-19) and a role-less Admin request also must write a rejected event under FR-40, and only AD-9 says so. An unauthenticated mismatch writing an audit row also needs a rate limit.

**Fix:** scope AD-9 to machine-handled artifacts. State that typed codes are looked up only inside `TenantScope`. Make one rule list every rejected-cross-Tenant source, with a rate-limited event.

### R-13. UNLOGGED counters and the shared limiter don't meet FR-22, FR-28 and FR-8 (Contradicted)

AD-14 accepts a crash reset for all attempt counters. FR-22 and §5.2 fix email code attempts at 5 and FR-28 says limits survive a new challenge, so a crash, which an attacker might induce, resets a hard limit on a 6-digit code. The attempt count belongs on the durable code row. The in-memory per-source limiter also isn't keyed by Tenant, and it runs before Tenant resolution, while FR-8 says rate-limit counters are keyed by Tenant.

**Fix:** keep per-artifact attempts durable and leave only backoff windows in UNLOGGED. Key the coarse limiter by host plus source, or record it as an intended Deployment-level exception.

### R-14. Unrecorded FR-37 deviations and rotation timing (Contradicted)

FR-37 says a next key is published for the cache limit "before it signs anything". AD-11 waives that in two cases: for a new Tenant and for an unaged revoke. Both are sensible, and the memlog records them, but no PRD deviation or note does. FR-37 also lets a Tenant Owner rotate "at any time", while AD-11 requires 15 minutes of ageing, and it doesn't say whether a second manual rotation is refused or queued. Creating a Transit key also can't join AD-5's transaction, so "one `next` at commit" needs an order: create the Transit key first, and treat an orphan as harmless.

**Fix:** record the two exceptions in AD-11 and amend FR-37 via `bmad-correct-course`. Say that manual rotation is refused with the time remaining. State the Transit-then-commit order.

### R-15. Conformance mode is checked only at startup (Unaddressed)

FR-23 and Open Question 1 forbid relaxing a rule in a Prod Tenant. AD-25 refuses startup if any Prod Tenant exists, but a Prod Tenant can be created or a label changed later (FR-7) while the flag is on.

**Fix:** with the flag set, refuse creating or labelling a Prod Tenant, and restrict the mode to CI and rehearsal environments.

## Low findings

- **R-16 (Dropped), FR-33:** AD-21 gives CSP and framing for Hosted surfaces only. `Referrer-Policy: no-referrer` isn't stated, and the Admin Dashboard's CSP, framing and referrer policy aren't either. Add a host-wide header rule. The FR-10 custom error page also has no rule for its form or delivery.
- **R-17 (Unaddressed), FR-40:** `audit_detail` sits outside the hash, so changing an IP address in a stored Log is undetectable, though the glossary calls a Log tamper-evident. A salted detail hash in the envelope would keep erasure working. Also, AD-17's 60 seconds runs from sealing, and the sealer has no latency bound, so "near real time" is unbounded. Add one.
- **R-18 (Dropped), NFR-21:** CAA records, CT monitoring alerts and rehearsed emergency certificate replacement appear in no AD. AD-26 binds NFR-21 but covers only the key and DNS credential.
- **R-19 (Unaddressed), small items:**
  - AD-4's "only" list omits bootstrap state (AD-26) and Deployment config.
  - AD-3's `tenant_id NOT NULL` doesn't fit AD-16's one `audit_event` table with a Deployment chain. Say there are two tables.
  - AD-5's "an event for a change that rolled back" needs a carve-out for rejected-action events (FR-40).
  - FR-42's "last use" must not write to the Application row (AD-2). Derive it from the Log.
  - Host.Admin has no breach dataset (AD-24), which matters if FR-31 create sets a password.
  - The two-secret overlap in FR-12 doesn't fit a single OpenIddict secret column, so it needs its own table.
  - FR-5 enrolment has no §5.2 lifetime.
  - AD-18's restore should also end Admin sessions.
  - `gatekeep upgrade` should refuse a source version outside FR-3.
  - FR-15 needs precedence between Application and API lifetimes.
  - The Permissions claim name is a public contract and isn't fixed.
  - Logos have no storage or sanitising rule (FR-34).
  - FR-44's "current Tenant" has no starting value without a server-side one.
  - Passkey autofill needs a challenge in AD-21's first response.
  - The matrix has no row for sending a test email.
- **R-20 (Contradicted), Account Portal:** EXPERIENCE line 38 makes the Portal a first-party Application in each Tenant, whereas AD-19 gives it a Session cookie API. Pick one. If it's cookie-only, correct EXPERIENCE. FR-14's Connection check and the Applications list both depend on the answer.
- **R-21 (Contradicted), Master Key placement:** the glossary says "held apart from the data it protects". A TPM on the same server is defensible for a stolen disk but not for a stolen server, and the Open Items fallback is a key file on the same host. Record this as an accepted residual in §9 terms, not just "a weaker control".

## PRD reference accuracy

All cited FR, NFR, UJ, SM, A-, V- and §-references resolve, and their content matches. That includes §7.1 row 7 (FGA, Later), §7.1 row 11 (custom domains, v2), §9 server compromise, the FR-21 note, SEC-06, SEC-27, SEC-28, the §5.2 values used in AD-11 and AD-18 (15 minutes, 24 hours) and the EXPERIENCE references (line 144, line 160, 30-minute sliding at line 375, 50 rows at line 110). Deferred items match §6, §7.1 and §9.

Inaccuracies, all minor:

- **Frontmatter and Map:** `binds` claims NFR-1..NFR-21, but the Capability Map has no row for NFR-14 or NFR-15. AD-16 binds NFR-15, and nothing binds NFR-14.
- **Map, FR-1 to FR-6:** points at AD-17, AD-18 and AD-26, but FR-2 and FR-5 have no governing rule beyond one line in AD-26 and a Cli name. FR-6 is bound by AD-14 and missing from that row's list.
- **Map, FR-40:** AD-17 binds it but is missing from the row. The same applies to FR-12 and AD-24.
- **AD-13 "family":** the spine says "Terms follow PRD §3 exactly", but the glossary defines Token Family by rotation lineage and AD-13 by storage row. They agree only if R-6 is fixed.
- **AD-3:** "`gk_migrator` connects only during `gatekeep migrate`" conflicts with AD-18 (R-10).
- **`[ASSUMPTION]` on A-16:** AD-9's RS256 reasoning is an inference from OIDC Core, per the memlog. It's sound, and it wasn't re-verified here.

## Checked and landed

These got particular attention because they carry the most risk, and no gap was found:

- Tenant isolation rules (AD-3, AD-4), host resolution, poisoned links and subdomain lifecycle (AD-6)
- Per-Tenant issuer and JWKS, and the inert global credential (AD-8)
- `__Host-` cookies, CSRF and step records (AD-12, FR-47)
- Refresh rotation with no leeway, and code replay through the authorization row
- Session reuse Connection check (FR-14)
- JWKS cache limit, and retirement after hard lifetime (AD-11)
- Off-server copy of revocations, and writes that can't be rewritten (AD-17)
- FR-3 survival of Sessions and the 24-hour gate (AD-18)
- Capability matrix enforcement (AD-20)
- Dummy hash for NFR-20 (AD-24), and hashing shares for NFR-6 (AD-14)
- Theme validation, and no third-party runtime dependency (AD-21, AD-22)
