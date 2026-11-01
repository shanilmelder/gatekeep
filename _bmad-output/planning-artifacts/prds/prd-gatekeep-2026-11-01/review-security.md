---
title: Gatekeep PRD Security Review
reviewed: _bmad-output/planning-artifacts/prds/prd-gatekeep-2026-11-01/prd.md
reviewer_role: Identity-platform security engineer
created: 2026-11-01
---

# Gatekeep PRD Security Review

## Verdict

**Not ready to finalize. Changes required before `bmad-architecture`.**

The PRD gets many of the headline decisions right (see "What holds up"). Its weakness is the paths around the main flow: recovery, revocation, restore, Admin identity and key custody. Four findings are critical because each one either leaves an attacker a route around MFA or a route to staying in after remediation, or makes a stated recovery outcome impossible to meet. Several of them are architecture-shaping, so they should be settled before architecture starts rather than in stories.

| Severity | Count |
| --- | --- |
| Critical | 4 |
| High | 18 |
| Medium | 11 |
| Low | 4 |
| **Total** | **37** |

**Severity scale**

- **Critical:** a direct route to takeover or loss of the whole Deployment, or a compromise that can't be contained, as the PRD is written.
- **High:** a realistic incident affecting many Users, an Admin account or a Tenant boundary, or a contradiction that would be built wrongly.
- **Medium:** needs a precondition or has limited reach, or weakens a control.
- **Low:** untestable or ambiguous wording, with low direct incident risk.

**Calibration.** A-1 (Esm operates every Tenant) lowers malicious-Tenant-Admin risk, and that is reflected in the ratings. It doesn't lower the risk of a stolen Admin session, a compromised dependency, or a bug in one Tenant reaching another. The self-assessment gate in NFR-8 is accepted and isn't argued here; SEC-35 only asks that it be measurable.

Suggested numbers (lifetimes, counts) are starting points for Esm to confirm. What matters is that a number exists and can be tested.

## Decisions to make before architecture

These open items change the findings below, so treat them as blockers rather than notes.

| Item | Why it blocks | Findings |
| --- | --- | --- |
| Open Question 3: Admins across Tenants, or a separate Prod Admin login | Sets the Admin identity model and blast radius | SEC-01, SEC-08 |
| Open Question 4: is the server reachable from the public internet | Decides whether the Admin Dashboard can sit behind a network boundary, and how client IPs and TLS work | SEC-01, SEC-11, SEC-28 |
| Not in the PRD: where the master key lives and how it is escrowed | Determines whether FR-4 and NFR-13 can be met at all | SEC-04 |
| Not in the PRD: does the Tenant domain share a registrable domain with Esm's apps | Decides cookie, CSRF and wildcard certificate exposure | SEC-11, SEC-12 |

## Summary of findings

| ID | Severity | Type | Finding |
| --- | --- | --- | --- |
| SEC-01 | Critical | Missing | Admin identity, login and recovery are undefined |
| SEC-02 | Critical | Missing, untestable | MFA "Always" has no defined meaning, and recovery or alternate sign-in routes around it |
| SEC-03 | Critical | Unsafe | Reset, block and factor changes don't evict an attacker holding tokens |
| SEC-04 | Critical | Contradictory | Encrypted backups, restore on new hardware and key custody can't all hold as written |
| SEC-05 | High | Contradictory | UJ-3 treats rotation as revocation |
| SEC-06 | High | Unsafe | Restore silently undoes revocations, including a revoked key |
| SEC-07 | High | Unsafe | Forced change of a breached password hands the account to the attacker |
| SEC-08 | High | Contradictory | "An Admin" includes Viewer, and no Deployment-level role exists |
| SEC-09 | High | Unsafe | Management API credentials bypass Admin MFA and allow escalation |
| SEC-10 | High | Missing | No re-authentication for high-impact Admin actions |
| SEC-11 | High | Missing | Wildcard TLS key and DNS credential exposure isn't treated as a security concern |
| SEC-12 | High | Unsafe | Sibling Tenant subdomains are same-site, so the cookie and CSRF requirements are insufficient |
| SEC-13 | High | Missing | No session fixation or sign-in transaction binding requirement |
| SEC-14 | High | Missing | No OAuth security baseline for codes, PKCE, mix-up or redirects |
| SEC-15 | High | Untestable | Cross-Tenant token rejection is outside Gatekeep's control |
| SEC-16 | High | Missing | Account pre-hijacking and same-email social accounts |
| SEC-17 | High | Missing | Email change is unprotected and Users get no security notifications |
| SEC-18 | High | Contradictory | UJ-2 recovery doesn't work for a passkey-only User, and Owner assurance can be downgraded |
| SEC-19 | High | Missing | Isolation testing omits jobs, protocol endpoints and shared infrastructure |
| SEC-20 | High | Contradictory | Logs are mutable in practice, Tenant-scoped, on-box and deletable |
| SEC-21 | High | Missing | UJ-3 starts with an alert that no requirement produces |
| SEC-22 | High | Missing | No response defined for compromise of the whole server |
| SEC-23 | Medium | Unsafe | Wildcard redirects outside Prod, controlled by a mutable label |
| SEC-24 | Medium | Contradictory | Enumeration rule conflicts with identifier-first, lockout and blocked screens |
| SEC-25 | Medium | Missing | Second-factor guessing isn't limited, and lockout is a denial-of-service tool |
| SEC-26 | Medium | Unsafe | Single sign-on bypasses per-Application Connection choices |
| SEC-27 | Medium | Missing | Subdomain lifecycle: rename, reuse and reserved names |
| SEC-28 | Medium | Missing | Tenant resolution from Host, poisoned links and spoofed client IP |
| SEC-29 | Medium | Missing | Email channel integrity and provider changes |
| SEC-30 | Medium | Missing | Logout and authorization changes don't reach Applications |
| SEC-31 | Medium | Missing | Hosted Login clickjacking, theme assets and token leakage |
| SEC-32 | Medium | Missing | Unauthenticated hashing cost and distributed stuffing take down every Tenant |
| SEC-33 | Medium | Untestable | Security bounds and floors are undefined |
| SEC-34 | Low | Untestable | Conformance passes vacuously with no named profiles |
| SEC-35 | Low | Untestable | ASVS version, level and evidence aren't stated |
| SEC-36 | Low | Unsafe | Tenant switching can apply an action to the wrong Tenant |
| SEC-37 | Low | Untestable | "Tokens" in the Log exclusion is ambiguous |

## Critical

### SEC-01: Admin identity, login and recovery are undefined

- **Type:** Missing
- **Citation:** §3 Admin; FR-2; FR-5; FR-39; §7.2; Open Questions 3 and 4
- **Problem:** The PRD never says what an Admin authenticates against. Admin isn't a User (Users belong to one Tenant), and no requirement covers Admin login, Admin password reset, a lost Admin Factor, Admin session lifetime, invite handling or the Dashboard's network exposure. §7.2 lists only Hosted Login screens. An implementer's natural default is to reuse the User flows, including email reset. That would mean one compromised mailbox takes over a Deployment holding every project's identities. FR-2 also doesn't say how the installer proves they are the Operator, so a freshly installed, internet-reachable server can be claimed by whoever reaches it first. FR-2 doesn't say the first Admin is an Owner, either.
- **Proposed change:** Add a new FR, "Admin authentication":
  - Admin credentials are stored apart from every Tenant's Users, and no Tenant's data or Connection can sign in an Admin.
  - Admins sign in with WebAuthn only. No email-based reset, email code, social login or recovery code can sign an Admin in or remove an Admin Factor.
  - A lost Admin Factor is recovered by another Owner or by FR-5.
  - Every Owner registers at least two WebAuthn credentials.
  - Admin sessions have their own short absolute and idle lifetimes (suggested 8 hours and 30 minutes), set at Deployment level.
  - Admin invites are single-use, expire within 72 hours and are bound to the invited email.
  - The Admin Dashboard is on its own hostname, separate from all Tenant origins, and can be limited to a network allowlist or VPN.

  Change FR-2 to: "Bootstrap requires a secret available only from the server. Until it completes, the Deployment serves no Tenant traffic. The first Admin is an Owner."

  Change FR-5 to add: "Recovery issues a single-use, short-lived enrolment. It revokes all existing sessions for that Admin, doesn't disable MFA, and raises a SEC-21 alert."

### SEC-02: MFA "Always" has no defined meaning, and recovery or alternate sign-in routes around it

- **Type:** Missing, untestable
- **Citation:** FR-25 (no Consequences at all); FR-19; FR-20; FR-21; FR-22; FR-28; FR-31; §3 Connection, Factor
- **Problem:** FR-25 is the central MFA control and the only such FR with no testable consequence. The PRD doesn't answer:
  - Does Always apply after social, email code and passkey sign-in?
  - Does a completed reset sign the User in, or skip the Factor step?
  - Does a lockout recovery by email (FR-28) clear MFA?
  - Does a passkey count as two factors, and only with user verification?
  - What happens at next sign-in for a User with no Factor, including one whose Factors an Admin just reset (FR-31)?

  The last case is the classic gap: an attacker with a stolen password reaches the enrolment prompt first and enrols their own Factor. Email code as a first factor followed by email reset also makes the mailbox the sole secret. NIST SP 800-63B doesn't accept email as an out-of-band authenticator.
- **Proposed change:** Add to FR-25:
  - "With MFA Always, no Connection, reset, lockout recovery or email-verification flow completes a sign-in or issues a token until a second factor from a different category has been verified."
  - "An email code never counts as a second factor after an email-based step, or the reverse."
  - "A passkey satisfies MFA only when user verification was performed. Tokens report this in `amr`."
  - "A completed password reset never creates a Session. The User signs in afterwards, including the Factor step."
  - "Email-based flows can't remove, replace or bypass a Factor."
  - "A User with no Factor under MFA Always can enrol only after proof beyond the first factor (a verified email challenge at minimum), and the enrolment triggers the SEC-17 notification."
  - "After an Admin resets a User's Factors (FR-31), the same enrolment rule applies, and Sessions and refresh tokens are revoked."
  - "A change of the MFA policy is written to the Log, and lowering it on a Prod Tenant follows SEC-10."

  Add a test matrix to the Consequences: every Connection crossed with each recovery path, under MFA Always, ends with a verified second factor.

### SEC-03: Reset, block and factor changes don't evict an attacker holding tokens

- **Type:** Unsafe
- **Citation:** §3 Session ("independent of tokens"); FR-19; FR-24; FR-31; FR-35; FR-15; §7.1 row 8
- **Problem:** FR-19 ends "other Sessions" only, and the glossary says Sessions are independent of tokens. Read literally, a victim who resets their password leaves the attacker's refresh token working. With no ceiling in FR-15, it could work indefinitely. Only blocking (FR-31) covers refresh tokens. Removing a Factor, changing a password in the Account Portal, deleting an account and the Admin's "revoke Sessions" action say nothing about them. Password reset is the action Users take to recover from a compromise, so it must actually remove the attacker. Access tokens have no maximum lifetime either, and because sender-constrained tokens are deferred, a stolen access token stays usable for as long as an Admin configured.
- **Proposed change:** Add a new FR, "Credential change revokes access", with a single table of triggers and effects:
  - **Triggers:** password reset or change, Factor added or removed, recovery codes regenerated, email change, User blocked, User deleted, Admin Factor reset, Admin "revoke Sessions".
  - **Effects:** all Sessions (except the acting Session for User-initiated changes, where stated) and all refresh token families end at once.
  - "Access tokens remain valid only until expiry, and that expiry is bounded by a Deployment-enforced ceiling (suggested 1 hour, with a 15-minute default)."
  - "The product states this residual window, and the UJ-3 and quickstart docs repeat it."
  - Add refresh token ceilings to FR-15 (suggested absolute 90 days), which no Admin setting can exceed.

### SEC-04: Encrypted backups, restore on new hardware and key custody can't all hold as written

- **Type:** Contradictory
- **Citation:** NFR-3; FR-1; FR-4; NFR-13; UJ-4; SM-5; §9 On-premises server failure
- **Problem:** NFR-3 says secrets are encrypted at rest but not where the decrypting key lives. FR-4 requires that backups don't expose secrets, and also that a restored Deployment accepts existing credentials. NFR-13 and §9 assume the server itself can be lost. These combine in only two ways, both bad:
  - The master key is in the backup or stored off-box next to it, so anyone with the backup reads every Signing Key and TOTP seed, which breaks FR-4.
  - The master key exists only on the server, so losing the disk loses all Signing Keys, TOTP seeds and client secrets, and UJ-4's "no credentials lost" can't be met.

  Equally, if the key sits on the same disk as the database, encryption at rest gives almost no protection against a server compromise or a stolen drive, yet still passes NFR-3 literally.
- **Proposed change:** Replace NFR-3's first clause with a key custody requirement:
  - "Secrets and private keys are encrypted under a master key that is held apart from the encrypted data and is never included in a backup."
  - "An offline escrow copy of the master key exists, stored in a separate location from the backups, and its handling is documented."
  - "Each Tenant's secrets are encrypted under a Tenant-specific key derived from or wrapped by the master key."
  - "The master key can be rotated without resetting Users."

  Change FR-4's second consequence to: "A backup alone, without the escrowed master key, reveals no secret or private key." Add: "Restore onto clean hardware succeeds using only the off-server backup, the escrowed key and the documentation." Add that clean-hardware case to SM-5, since the current rehearsal could pass on the same server with the same key in place.

## High

### SEC-05: UJ-3 treats rotation as revocation

- **Type:** Contradictory
- **Citation:** UJ-3; FR-37; FR-38; §4.8 description
- **Problem:** UJ-3 has Esm "rotate" a suspected key, then says tokens signed by the old key are rejected. FR-37 says the opposite: previous-key tokens verify until they expire. Following UJ-3 in an incident leaves the stolen key trusted by the JWKS, so forged tokens are still accepted. §4.8 promises revocation "without downtime", which conflicts with FR-38, because revocation invalidates every token the key signed. FR-37 also sets no minimum time between publishing a next key and using it, and FR-38 doesn't say how quickly resource servers stop trusting a revoked key, since they cache JWKS. If no next key is ready, revocation also leaves nothing to sign with.
- **Proposed change:** Rewrite UJ-3 to: "Esm revokes the affected key, Gatekeep promotes a new key, and affected sessions are revoked. Tokens signed by the revoked key are rejected within the documented JWKS cache window, and Applications recover by re-authenticating or refreshing."
  - Change the §4.8 description to: "rotated without downtime; revoked with a stated token impact."
  - Add to FR-37: "A next key is published for at least the JWKS cache lifetime before it signs."
  - Add to FR-38: "Revocation always leaves a usable signing key, and Tenant signing continues without manual steps."
  - Add to FR-38: "The maximum time for a resource server to stop trusting a revoked key is stated, and quickstarts honour it."
  - Add a test: a token forged with a revoked key is rejected by a quickstart API inside that window.
  - State in FR-38 whether refresh tokens survive key revocation. The safe default for a compromise is to offer revoking them in the same action, matching UJ-3.

### SEC-06: Restore silently undoes revocations, including a revoked key

- **Type:** Unsafe
- **Citation:** FR-4; NFR-13; UJ-4; FR-38; FR-15; FR-27
- **Problem:** NFR-13 accepts up to 24 hours of data loss. After a restore, everything done in that window is reversed without notice:
  - a revoked Signing Key can become current again
  - revoked refresh token families and ended Sessions come back
  - a removed Admin or blocked User comes back
  - an old password replaces a reset one, and spent recovery codes work again
  - a rotated client secret works again

  A restore during an incident is the most likely time for this to happen, and it can bring back the attacker's access. FR-4 presents "accepts existing credentials" as success, with no exception for these.
- **Proposed change:** Add to FR-4:
  - "A restore reports the backup's timestamp and the window of lost changes."
  - "After a restore, the Operator completes a documented post-restore step that replays or re-applies revocations recorded after the backup, from a record kept off the server."
  - "By default, a restore invalidates all refresh tokens and Sessions issued before the restore, unless the Operator opts out for a planned rollback such as UJ-4."
  - "A key that was revoked after the backup can't return to active use."

  Add a test: revoke a key and a token family, restore an earlier backup, and show both stay revoked after the post-restore step. A short off-server revocation journal, or the off-box log in SEC-20, can be the source of the record.

### SEC-07: Forced change of a breached password hands the account to the attacker

- **Type:** Unsafe
- **Citation:** FR-29; §7.2 "breached password warning"
- **Problem:** "A detected password forces a change before access continues." If the password is breached, the person at the keyboard may well be the attacker. A forced in-session change lets them set a new password, which locks out the owner and turns a detection control into an account takeover. §7.2 also calls this a "warning", which contradicts "forces". FR-29's list of checks omits a password changed in the Account Portal (FR-35).
- **Proposed change:** Replace the consequence with: "When a password is detected as breached at sign-in, it isn't accepted as proof of identity on its own. The User must complete a verified Factor, or an out-of-band reset through email, before setting a new password, and no Session or token is issued first. The event is written to the Log."
  - Add password change to the list of checks.
  - Rename the §7.2 screen to match.

### SEC-08: "An Admin" includes Viewer, and no Deployment-level role exists

- **Type:** Contradictory
- **Citation:** §3 Admin; FR-7; FR-10; FR-31; FR-25; FR-36; FR-37; FR-38; FR-39; FR-40; Open Question 3
- **Problem:** The glossary defines Admin as anyone with a role, and FR-39 also uses "Admin" as a role name alongside Owner and Viewer. So "An Admin can revoke a Signing Key" (FR-38), read with the glossary, includes a Viewer. Nowhere does the PRD say what each role can do. FR-7 gives Tenant creation to an Owner, but FR-39 makes Owner a per-Tenant role. Creating a Tenant, and bootstrap, have no scope to belong to, so an Owner of a Dev Tenant might have Deployment-wide powers. A stolen low-value Dev credential should never reach Prod.
- **Proposed change:** Add a permission matrix to FR-39 covering every Admin action by role. As a minimum:
  - Owner only: key rotate and revoke, MFA policy, Connection credentials, email provider, Application secrets, Management API grants, Tenant delete.
  - Viewer: read-only, with no access to raw Log detail containing personal data unless stated.

  Rename the role or the glossary term so "Admin" has one meaning (for example, "Editor" for the role). Add a separate Deployment Owner role that is the only one able to create or delete Tenants, and state that a Tenant role grants nothing in another Tenant. Add a test: each role is denied each action outside the matrix, server-side.

### SEC-09: Management API credentials bypass Admin MFA and allow escalation

- **Type:** Unsafe
- **Citation:** FR-42; FR-39; FR-11; FR-12; FR-16; FR-38; §7.1 row 13
- **Problem:** FR-39 requires MFA for Admins, but FR-42 gives a client secret every Tenant-scoped action except Admin management. That covers disabling MFA, adding redirect URLs, resetting Factors, swapping the email provider, and revoking keys. The secret has no MFA, and it survives the removal of the Admin who created it. Anyone with a stolen Admin session can mint a Management API Application and keep access after the Admin is removed. A Management API token that can create or edit Applications can also grant itself Permissions it doesn't hold. FR-42 doesn't exclude those self-granting paths.
- **Proposed change:** Add to FR-42:
  - "Only an Owner, after re-authentication (SEC-10), can grant Management API Permissions."
  - "A Management API client can't grant any Permission it doesn't hold, and can't create or change a client's Management API access."
  - "Tenant delete, Signing Key revocation, MFA policy downgrade and email provider changes are excluded from the Management API in v1, or require a separately granted Permission."
  - "Management API tokens are short-lived (suggested 15 minutes or less) and are issued only to a client bound to one Tenant."
  - "Every client with Management API access is listed with its grants and last use, and a new grant raises a SEC-21 alert."
  - "A Management API credential is reviewed when its creating Admin is removed: the removal screen lists these clients and offers to revoke them."

### SEC-10: No re-authentication for high-impact Admin actions

- **Type:** Missing
- **Citation:** FR-7; FR-11; FR-12; FR-25; FR-31; FR-36; FR-38; FR-39; §4.5 Out of Scope; FR-35
- **Problem:** FR-35 requires recent authentication for User changes, but no Admin action has an equivalent. FR-38 needs only a confirmation and FR-7 only a typed name. A hijacked Dashboard session can therefore lower MFA, add a redirect URL or delete a Tenant. Step-up is listed as v2, but that entry is about User policy and shouldn't be read as covering Admins.
- **Proposed change:** Add to FR-39: "These actions require a fresh WebAuthn assertion within the last 5 minutes: Owner grant, Admin removal, Signing Key revocation, MFA policy lowering, Application redirect changes in Prod Tenants, secret rotation, email provider change, Management API grant, Tenant deletion." State in §4.5 that Admin re-authentication is v1. Add to FR-39: "When an Admin is removed, their sessions end at once."

### SEC-11: Wildcard TLS key and DNS credential exposure isn't treated as a security concern

- **Type:** Missing
- **Citation:** FR-1 (documentation only); FR-7; FR-8; NFR-3; NFR-4; NFR-9; Open Question 4
- **Problem:** FR-1 treats the wildcard certificate as install documentation. It's a shared secret that spans every Tenant, so a stolen key lets an attacker with a network position impersonate every Hosted Login at once, which undermines FR-8's isolation claim. Automated wildcard issuance also needs DNS-01, which usually leaves a zone-editing API credential on the server. That credential is worse than the certificate key, because it can repoint hosts or change MX records and capture every reset email. If the wildcard or DNS credential covers the domain Esm's apps also use, the exposure extends to those apps. Nothing requires rotation, revocation or monitoring.
- **Proposed change:** Add a new NFR, "TLS and DNS custody":
  - "Tenant subdomains sit under a dedicated zone used only by Gatekeep, so the wildcard covers no Application or mail host."
  - "The certificate private key isn't readable by the application process, and no Admin or Tenant-scoped function can reach it."
  - "If certificates are issued automatically, the DNS credential is limited to the validation records of that zone, and it is kept off the server if feasible."
  - "Certificate rotation and emergency replacement are documented and rehearsed in SM-5."
  - "CAA records are set, and Certificate Transparency monitoring alerts on unexpected issuance."
  - "Requests for an unknown subdomain get a generic rejection and don't fall through to a Tenant."

### SEC-12: Sibling Tenant subdomains are same-site, so the cookie and CSRF requirements are insufficient

- **Type:** Unsafe
- **Citation:** FR-8 (last consequence); NFR-4; FR-35; §3 Tenant
- **Problem:** All Tenants share one registrable domain, so to a browser they are the same site. `SameSite` therefore gives no protection between Tenants, or between Tenants and any Esm app on that domain, and NFR-4's "protected against cross-site requests" can pass while cross-Tenant requests stay open. FR-8 tests only that cookies aren't sent to another Tenant. It doesn't cover the reverse direction: script running on any sibling host, such as an XSS in a Dev Tenant or an app on the same parent, can set a parent-domain cookie that the Prod Tenant receives. That enables session fixation (SEC-13) and CSRF token bypass. The boundary between Dev and Prod Tenants ends up depending on an XSS-free Dev Tenant.
- **Proposed change:** Change NFR-4 to:
  - "Session and sign-in transaction cookies use the `__Host-` prefix, so no sibling host can set or overwrite them."
  - "Every state-changing request in Hosted Login, the Account Portal and the Admin Dashboard requires a CSRF token bound to the Session and verifies Origin against the exact Tenant host. `SameSite` alone isn't accepted."

  Add to FR-8: "A cookie set from another Tenant's subdomain or from the parent domain isn't accepted as a Session." Add an automated test for both directions. Separately, decide whether the parent zone should be submitted to the Public Suffix List, which would make Tenants cross-site. Registration is outside Esm's control, so it can only be defence in depth.

### SEC-13: No session fixation or sign-in transaction binding requirement

- **Type:** Missing
- **Citation:** §3 Session; FR-17 (identifier-first); FR-20; FR-25; NFR-4; FR-35
- **Problem:** The PRD's multi-step sign-in spans identifier, password, Factor and enrolment steps, but nothing requires:
  - a new Session identifier on authentication
  - the steps being bound to one browser transaction
  - each step's prerequisites being enforced on the server

  Without this, an attacker plants a known identifier (easier with SEC-12) and inherits the victim's sign-in, or skips straight from the password step to a post-MFA step. Login CSRF is also uncovered: a User can be silently signed in to an attacker's account, then enter their own data there. The inbound social flow in FR-20 has the same need.
- **Proposed change:** Add a new FR, "Session and sign-in integrity":
  - "The Session identifier changes at authentication, at Factor completion, at re-authentication and at password change, and any identifier issued before sign-in stops working."
  - "Each sign-in transaction is bound to the initiating browser, the Tenant and the Application, is short-lived, and can't be replayed."
  - "A step can't be reached without a server-side record that the earlier steps passed."
  - "Sign-in forms are protected against login CSRF, and Gatekeep's own requests to social providers use `state`, `nonce` and PKCE."

  Add tests: a pre-set identifier is unusable after sign-in, a post-MFA URL requested directly is refused, and a transaction started in one browser can't be finished in another without a fresh challenge.

### SEC-14: No OAuth security baseline for codes, PKCE, mix-up or redirects

- **Type:** Missing
- **Citation:** FR-11; FR-13; FR-15; FR-23 ("OAuth 2.x"); UJ-1
- **Problem:** FR-13 covers PKCE for public clients and the removal of implicit and password grants, which is good, but "OAuth 2.x" sets no normative baseline. Missing items:
  - PKCE for confidential clients and a ban on the `plain` method. RFC 9700 expects PKCE for confidential clients as well, and a regular web app is the likeliest v1 Application.
  - Authorization codes that are single-use, short-lived, and bound to client and redirect URI.
  - Revoking tokens from a replayed code.
  - The `iss` authorization response parameter (RFC 9207). Gatekeep has many issuers by design, and an app configured for two Tenants is exposed to mix-up.
  - A rule that no redirect is sent when `redirect_uri` is invalid. UJ-1 implies this but no FR tests it.
  - Requiring `id_token_hint` or equivalent for logout redirects.
  - Fixed signing algorithms, so `none` and algorithm confusion are rejected.
  - Native Applications using the system browser with claimed HTTPS or loopback redirects (RFC 8252).

  OpenID conformance tests (FR-23) don't cover all of this.
- **Proposed change:** Add to FR-23: "Gatekeep follows RFC 9700 (OAuth 2.0 Security Best Current Practice). Any deviation is recorded." Add to FR-13:
  - "PKCE with S256 is required for every authorization code flow, including confidential clients. `plain` is rejected."
  - "Codes are single-use, expire within 60 seconds, and are bound to the client, redirect URI and PKCE challenge."
  - "Replaying a code is refused and revokes tokens issued from it."
  - "Authorization responses include `iss`."
  - "An unregistered `redirect_uri` shows an error page at Gatekeep and never redirects."
  - "Native Applications can't register a custom URI scheme in Prod Tenants without an explicit acknowledgement."
  - "Tokens use a fixed Tenant algorithm, and metadata and verification reject others."

### SEC-15: Cross-Tenant token rejection is outside Gatekeep's control

- **Type:** Untestable
- **Citation:** FR-8 (first consequence); FR-16; FR-43; UJ-5; §3 API; SM-2
- **Problem:** "Rejected by every other Tenant's APIs" can't be tested as a Gatekeep property, because the APIs are Esm's own services and validate tokens themselves. A service that checks only signature and audience is the failure case, especially if the Dev and Prod APIs share an audience and the service reads a shared JWKS URL. Then a Dev token works in Prod. The PRD doesn't say that the access token and ID token must be distinguishable, or that quickstarts validate properly. Because the quickstarts are what people copy, a flaw there becomes a flaw in every project.
- **Proposed change:** Replace the FR-8 consequence with two:
  - "Each Tenant's tokens carry that Tenant's unique issuer and are signed by keys found only in that Tenant's JWKS."
  - "The Management API rejects tokens from any other Tenant."

  Add to FR-16: "An API identifier is unique within a Tenant, and setup guidance states that Dev, Staging and Prod use different identifiers." Add to FR-43:
  - "Every quickstart validates signature, `iss`, `aud`, `exp` and a fixed algorithm allowlist, and it uses `sub` rather than email as the User key."
  - "Quickstart APIs reject an ID token used as an access token." Access tokens use `typ: at+jwt` (RFC 9068).
  - "A negative test pack is published and run on every release: wrong Tenant, wrong audience, expired, ID token, `alg: none`, revoked key."

### SEC-16: Account pre-hijacking and same-email social accounts

- **Type:** Missing
- **Citation:** FR-17; FR-20; §7.1 row 6 (account linking is v2); §7.2 (linking deferred); FR-36
- **Problem:** Pre-hijacking is a known attack that FR-17 doesn't exclude. An attacker signs up with the victim's address and a password they know, and leaves it unverified. If the victim later claims the address (by social sign-in, code or reset) and the attacker's password survives, the attacker shares the account. FR-17 doesn't say that unverified accounts can't receive tokens.

  FR-20 correctly bans automatic linking, but because linking is deferred, it doesn't say what happens when a social sign-in arrives with an email that already exists in the Tenant. The options are two Users with one email, or a dead end. If the app keys on email, two Users merge in the app, which is an account takeover Gatekeep can't see. Social `email` claims aren't always verified or stable, as with the Microsoft "nOAuth" issue.
- **Proposed change:** Add to FR-17:
  - "No Session or token is issued for an unverified email, unless the Tenant turns this off for a Dev Tenant."
  - "Sign-up with an existing address changes nothing on the account and sends a notice to that address. The response is the same as a new sign-up."
  - "Verifying an address invalidates any pending password or credential set by an earlier unverified sign-up."

  Add to FR-20:
  - "A social identity is keyed on the provider's issuer and subject, never on email."
  - "A social sign-in whose email matches an existing User creates no account and shows a neutral error with a path to the existing sign-in method."
  - "`email_verified` is passed to Applications only when the provider asserts it."

### SEC-17: Email change is unprotected and Users get no security notifications

- **Type:** Missing
- **Citation:** FR-35; FR-36 (template list); FR-40; UJ-2
- **Problem:** "Edit their profile" includes the email address, the key to all email recovery. A short hijack of a Session can change the email, then use reset for permanent takeover. "Sensitive changes require recent authentication" doesn't name which changes, and doesn't say what counts for a User with a passkey or social login only. FR-36's template list has no security notifications, so a User never learns a Factor was added or a password changed. The notification is the only detection a User has.
- **Proposed change:** Add to FR-35:
  - "The sensitive changes are: email, password, adding or removing a Factor or passkey, regenerating recovery codes, deleting the account."
  - "Recent authentication means re-proof within 5 minutes using the strongest method enrolled. A recovery code or email code doesn't satisfy it when a stronger one is enrolled."
  - "An email change takes effect only after the new address is verified. The old address is told, and can reverse the change for at least 72 hours."
  - "Removing the last Factor is refused under MFA Always."

  Add to FR-36 mandatory, non-disableable notifications for: password changed, email change requested, Factor or passkey added or removed, recovery code used, recovery codes regenerated. Add these events to FR-40's coverage list (see SEC-20).

### SEC-18: UJ-2 recovery doesn't work for a passkey-only User, and Owner assurance can be downgraded

- **Type:** Contradictory
- **Citation:** UJ-2; §3 Connection, Factor; FR-21; FR-27; FR-25; FR-26; FR-39
- **Problem:** The glossary puts passkey under Connection and WebAuthn under Factor. FR-27 issues recovery codes on enrolling a Factor. So Maya, who has only a passkey, may have no recovery codes, though UJ-2 says a recovery code gets her back in. Her fallback is then email reset, and her phishing-resistant account is only as strong as her mailbox. The PRD also doesn't say whether a recovery code replaces only the second factor or the whole sign-in. Used alone, it's a single static secret. Recovery code is listed as a Factor, so FR-25 lets it be chosen as allowed, while FR-26 omits it. FR-39's "phishing-resistant Factor for Owners" is meaningless if the same Owner can use a recovery code or TOTP as a fallback.
- **Proposed change:**
  - Define in §3: "a passkey is a credential that can serve as a first factor, and as a Factor when verified with user verification."
  - Change FR-27 to: "Recovery codes are issued at the first enrolment of a passkey or Factor, and shown once with a confirmation that they were saved."
  - Add: "A recovery code replaces only the Factor step, unless the User has no other first factor, in which case the state is documented." Pick one rule for passkey-only Users and state it. Recommended: a recovery code alone gets in, followed by mandatory re-enrolment, a notification and revocation of other Sessions.
  - Add: "Email recovery for a passkey-only User can be turned off per Tenant, and if it's on, it requires a delay and a notification."
  - Reclassify recovery code as a recovery method rather than a selectable Factor in FR-25.
  - Add to FR-39: "Owners can't complete any sign-in with a phishable method."

### SEC-19: Isolation testing omits jobs, protocol endpoints and shared infrastructure

- **Type:** Missing
- **Citation:** FR-8; FR-7; SM-2; §9 Tenant isolation flaw; FR-36
- **Problem:** The automated suite covers "every Management API endpoint". Isolation failures are as likely in places it doesn't touch: the OAuth and Hosted Login endpoints (a code, refresh token, reset link or email code from Tenant A redeemed at Tenant B), Dashboard backends, background jobs (email sending, retention purge, Tenant deletion, token cleanup, key rotation), and caches, rate-limit counters, and search indexes. A purge job with a missing Tenant filter is a data loss event across all Tenants. FR-7's Tenant deletion is the riskiest job in the product. SM-2's "zero in production" also can't be measured, as nothing detects a cross-Tenant access in production.
- **Proposed change:** Change the FR-8 test consequence to: "The cross-Tenant suite covers every Management API, Admin Dashboard, OAuth, OIDC and Hosted Login endpoint, and every artifact type (code, refresh token, reset link, email code, verification link, invite, passkey, recovery code)." Add:
  - "Every background job runs with one explicit Tenant, or is declared Deployment-wide and reviewed. A job with no Tenant context fails rather than running unscoped."
  - "Cached values, rate-limit counters and queued jobs are keyed by Tenant."
  - "A test proves deleting one Tenant leaves every other Tenant's data, keys and Logs unchanged."
  - "Data access enforces the Tenant boundary below application logic, so one missed filter doesn't expose data." The architecture chooses how.

  Change SM-2 to measure what can be seen, with a defined production signal such as Log entries for rejected cross-Tenant attempts.

### SEC-20: Logs are mutable in practice, Tenant-scoped, on-box and deletable

- **Type:** Contradictory
- **Citation:** §3 Log ("immutable", "in a Tenant"); FR-5; FR-7; FR-40; NFR-14; NFR-15; §7.1 row 12 (Log streams are v2)
- **Problem:** Several conflicts:
  - The glossary says immutable, but FR-40 only bars change through the Dashboard and API. Anyone with database access, including an intruder, can rewrite them.
  - NFR-15 lets each Tenant configure retention with no floor, so an Admin can shorten it to wipe history, which FR-40 forbids.
  - FR-7 deletes the Tenant's data, so a hijacked Owner destroys the evidence of what they did.
  - NFR-14's erasure conflicts with immutability, and the PRD doesn't resolve which wins.
  - Logs are "in a Tenant", so FR-5 recovery, bootstrap, Tenant create and delete, Admin sign-in, upgrades and restores have nowhere defined to go.
  - Log streams are v2, so all evidence sits on the one server the attacker would own.
  - 30 days is shorter than the typical time to detect a compromise, especially with one Operator.
  - FR-40's coverage list omits password resets, recovery code use, Factor changes, email changes and Session revocation.
- **Proposed change:** Update the glossary to define integrity as tamper-evident, not impossible to change. Add to FR-40:
  - "Logs are hash-chained or equivalent, and a verification command reports any change or gap."
  - "Security events are copied off the server, near real time, to a store the server can't rewrite or delete." This is a minimal v1 forwarder, separate from v2 Log streams.
  - "A Deployment Log exists for events above Tenant level: bootstrap, Admin sign-in, recovery, Tenant create and delete, upgrade, restore, config changes."
  - "Coverage includes all of the following: password reset, email change, Factor and recovery code events, Session and token revocation, Management API grants."

  Change NFR-15 to: "Retention can't be set below a Deployment floor (suggested 90 days for Prod Tenants), and any change is logged." Add to FR-7: "Security Logs of a deleted Tenant are kept until the floor expires." Add to NFR-14: "Erasure pseudonymizes personal data in Logs while keeping the event record."

### SEC-21: UJ-3 starts with an alert that no requirement produces

- **Type:** Missing
- **Citation:** UJ-3 ("An alert or log entry"); FR-6; §9; §2.1 "Trust it"; §7.1 row 12
- **Problem:** FR-6 covers availability and rate limits only. There's no security alerting. With one Operator and Logs that wait to be searched, a key misuse or Admin takeover goes unseen until someone looks. No signal is defined for a new Admin, a new Management API grant, refresh-token reuse spikes, a lowered MFA policy, or a credential-stuffing run. SM-2's production claim relies on this as well.
- **Proposed change:** Add a new FR, "Security alerting":
  - "The Deployment sends alerts through a channel independent of the Deployment itself."
  - Mandatory v1 events: Admin added or role raised, Admin sign-in from a new location or device, FR-5 recovery, Management API grant, Signing Key rotation or revocation, MFA policy lowered, email provider changed, redirect URL added in a Prod Tenant, refresh token reuse above a threshold, failed sign-in spike, Log verification failure, restore.
  - "An alert delivery test is part of SM-5."

### SEC-22: No response defined for compromise of the whole server

- **Type:** Missing
- **Citation:** UJ-3; NFR-9; SM-5; §9; FR-8
- **Problem:** Every Tenant, key, secret, TOTP seed and the TLS key sit on one server. UJ-3 models one Tenant's key and stresses that no other Tenant is touched. A server compromise is more likely in this design, and it touches everything, but the PRD has no outcome for it. NFR-9 only says a process exists. In that incident a key rotation isn't enough: TOTP seeds, client secrets, social provider secrets, the email credential, the DNS credential, the TLS key and the master key all need replacing, and restoring onto the same host may reinstall the intruder. §9 lists this nowhere as a risk.
- **Proposed change:** Add to §9 a "Server compromise" risk and a new journey, UJ-6. Change NFR-9 to require a tested runbook that covers:
  - rebuilding on clean hardware from a backup known to predate the compromise
  - rotating every Signing Key, client secret, provider secret, email credential, DNS credential, TLS key and the master key
  - forcing password reset and TOTP re-enrolment for affected Users
  - ending all Sessions and refresh tokens
  - notifying Users, including how the owner reaches them if Gatekeep is down
  - a Deployment-wide command that rotates all Tenants' keys together

  Add a tabletop run of this runbook to SM-5.

## Medium

### SEC-23: Wildcard redirects outside Prod, controlled by a mutable label

- **Citation:** FR-11; FR-7; FR-9
- **Type:** Unsafe
- **Problem:** "Without wildcards in Prod Tenants" allows wildcards elsewhere, and makes safety depend on a label that FR-7 lets an Owner change. A Staging Tenant with real data and a wildcard redirect leaks codes to any matching host, such as a takeover of a preview subdomain. Changing a label from Prod to Dev also unlocks weaker rules.
- **Proposed change:** "Redirect, logout and origin URLs are matched exactly in every Tenant, with the RFC 8252 loopback port exception for native Applications." If preview URLs need a Dev exception: "Allowed only on Dev Tenants, on a named domain, and only after explicit opt-in." Add to FR-7: "Lowering a Tenant from Prod follows SEC-10, is logged, and doesn't relax existing settings on its own."

### SEC-24: Enumeration rule conflicts with identifier-first, lockout and blocked screens

- **Citation:** FR-17; FR-19; FR-21; FR-22; FR-28; §7.2 blocked account, brute-force lockout
- **Type:** Contradictory
- **Problem:** "Responses don't reveal whether an email is registered" is stated only under FR-17, and sits next to "identifier-first", which by nature tends to reveal the next step for a known account. Offering a passkey or a social-only path after the identifier reveals both existence and method. The blocked account and lockout screens confirm existence unless they appear only after a correct credential. FR-19, FR-22 and sign-up have no rule, and timing isn't covered.
- **Proposed change:** Move this to a cross-cutting NFR: "Across sign-in, sign-up, reset, email code and verification, response content, status, next step and timing don't differ for known and unknown identifiers, within a stated tolerance." Add to FR-17: "The step shown after the identifier doesn't depend on the account's state." Passkey discovery uses a browser-mediated flow, without account lookup. Add to FR-28: "Blocked and locked states appear only after valid credentials, or as the same generic failure otherwise."

### SEC-25: Second-factor guessing isn't limited, and lockout is a denial-of-service tool

- **Citation:** FR-26; FR-27; FR-28; FR-22; NFR-6
- **Type:** Missing
- **Problem:** FR-28 covers "failed sign-ins" in general. A six-digit TOTP code, or a recovery code, has no attempt limit of its own, and a password-verified attacker can keep guessing. A per-account lockout also lets anyone lock out a known address, and the email path in FR-28 could turn into a mail flood. Requesting a new email code could reset FR-22's attempt counter. NFR-6's "sensitive endpoints" isn't defined.
- **Proposed change:** Add to FR-28: "Limits apply separately to password, TOTP, recovery code, email code and passkey steps, and they survive a new challenge." Prefer backing off rather than hard lockout: "A failed-attempt lock doesn't block a valid passkey or a sign-in from an established device." Add per-recipient limits for all outbound email. Define NFR-6's endpoint list: sign-in, sign-up, reset, email code, verification resend, token, Factor verification and recovery.

### SEC-26: Single sign-on bypasses per-Application Connection choices

- **Citation:** §3 Session; FR-14; FR-25; FR-23; FR-10
- **Type:** Unsafe
- **Problem:** A Session is held at Tenant level, so it seems a sign-in through a weak Connection in App A reuses silently into App B, which disabled that Connection. FR-14 tests only which Connections are displayed. The PRD doesn't say whether an existing Session is checked against the requesting Application, or whether Applications can see how a User authenticated.
- **Proposed change:** Add to FR-14: "An existing Session is reused for an Application only if it was established through a Connection enabled for that Application. Otherwise, the User signs in again." Add to FR-23: "`prompt=login`, `max_age` and `auth_time` are honoured, and `amr` reports the methods used."

### SEC-27: Subdomain lifecycle: rename, reuse and reserved names

- **Citation:** FR-7; FR-21; §3 Tenant; §7.1 row 11 (custom domains in v2)
- **Type:** Missing
- **Problem:** Each Tenant's issuer and passkey RP ID derive from its subdomain. FR-7 allows rename without saying whether the subdomain changes. If it does, the issuer changes, every passkey stops working, and every Application breaks. A deleted Tenant's subdomain can be reused, so a new Tenant inherits an old issuer that APIs may still trust. A Tenant named `admin`, `api`, `www` or `mail` can collide with Gatekeep or other hosts. v2 custom domains would strand passkeys bound to the v1 subdomain.
- **Proposed change:** Add to FR-7: "A Tenant's subdomain can't change after creation. Rename affects only the display name." "A subdomain is never reused after deletion." "A reserved list blocks infrastructure names." Add to FR-21 an explicit note: "Custom domains (v2) need a passkey migration plan." Decide on Tenant delete: "Signing Keys are destroyed, and JWKS is withdrawn."

### SEC-28: Tenant resolution from Host, poisoned links and spoofed client IP

- **Citation:** FR-7; FR-8; FR-19; FR-36; NFR-6; FR-28; Open Question 4
- **Type:** Missing
- **Problem:** The Tenant is selected by hostname, so hostname handling becomes a security control. A forged Host header can resolve the wrong Tenant, or put an attacker's domain into a reset link, which then sends the reset token to the attacker when the victim clicks. Per-source rate limits (FR-28, NFR-6) and Log IPs rely on the true client address. A self-hosted proxy with loose forwarded-header trust lets attackers rotate their apparent IP, bypassing limits and poisoning the Log.
- **Proposed change:** Add to FR-8: "Requests for hostnames not matching a known Tenant are rejected, and every link in email is built from the Tenant's stored issuer, never from request headers." Add to NFR-6: "Forwarded client addresses are trusted only from a configured proxy. A spoofed forwarding header has no effect on rate limits or Logs."

### SEC-29: Email channel integrity and provider changes

- **Citation:** FR-36; FR-19; FR-22; §9; §10
- **Type:** Missing
- **Problem:** Email carries reset links and sign-in codes, so whoever controls delivery controls those accounts. FR-36 lets "an Admin" change the provider, and edit reset templates, including the link itself. A stolen Admin session can route every reset through an attacker's provider, or add an external link or image that leaks the reset URL. Sender authentication isn't required, which makes phishing the Tenant's Users easy. Provider API credentials are a high-value secret.
- **Proposed change:** Add to FR-36: "Changing the provider is Owner only, follows SEC-10, is logged and raises an alert." "A reset, verification or code template must contain the system-generated link or code, and can't change its destination." "Templates can't load remote content." "The documented setup requires SPF, DKIM and DMARC, and test sends report their state." Add to §9 a risk for email provider compromise, covering that SEC-02 limits its reach.

### SEC-30: Logout and authorization changes don't reach Applications

- **Citation:** FR-24; FR-11; FR-16; FR-32; §3 Session; §7.1
- **Type:** Missing
- **Problem:** FR-24 says only where logout redirects, not what ends. It doesn't say whether Application sessions or refresh tokens stop, and there's no back-channel logout or token revocation endpoint. So a blocked User stays signed in to apps holding their own session. Deleting an Application, removing a Permission or changing a Role doesn't state any effect on existing refresh tokens, so a removed Role can keep renewing. "A token never contains a Permission… wasn't granted" (FR-16) is ambiguous about permissions granted once and later removed.
- **Proposed change:** Add to FR-24: "Logout ends the Session and refresh tokens bound to it, per a stated rule for offline access." Add token revocation (RFC 7009), and OIDC Back-Channel Logout for regular web Applications, to v1 or record the deferral and its residual risk. Add to FR-11: "Deleting an Application revokes its refresh tokens and grants." Add to FR-16 and FR-32: "Permissions are re-evaluated at every refresh, and a removed Permission doesn't appear in a token issued after removal."

### SEC-31: Hosted Login clickjacking, theme assets and token leakage

- **Citation:** FR-33; FR-34; FR-19; FR-35; NFR-4
- **Type:** Missing
- **Problem:** FR-34 limits script injection, but logos and fonts open further paths. An SVG logo served from a Tenant origin can run script there, a hosted font URL can see sign-in traffic, and CSS can be used for phishing. Nothing requires framing protection on Hosted Login or the Account Portal, so MFA enrolment could be clickjacked. Reset tokens in URLs can leak by `Referer`.
- **Proposed change:** Add to FR-33: "Hosted Login, the Account Portal and the Admin Dashboard send a strict Content Security Policy, deny framing, and set `Referrer-Policy: no-referrer`." Add to FR-34: "Theme values are validated against typed allowlists, and logos are served as sanitized images or from a separate origin." "No theme asset loads from a third party at sign-in." "Theme changes on Prod Tenants are logged."

### SEC-32: Unauthenticated hashing cost and distributed stuffing take down every Tenant

- **Citation:** NFR-2; NFR-6; NFR-10; FR-28; §7.1 row 8; §7.2 (CAPTCHA deferred); §9
- **Type:** Missing
- **Problem:** Memory-hard hashing is deliberately costly, and is triggered by unauthenticated requests on one server. A flood at a Dev Tenant can exhaust memory for Prod, so Tenants share a failure domain despite §2.1 "a problem in one can't reach another". Limits per account and per source don't stop a distributed credential-stuffing run, and bot detection and CAPTCHA are deferred. An expensive request also shouldn't run for an account that doesn't exist without equalized cost, which also relates to SEC-24.
- **Proposed change:** Add to NFR-6: "Hashing work has a Deployment-wide concurrency budget, with per-Tenant shares, so one Tenant can't exhaust it." "A global failed-sign-in rate per Tenant is measured, and it triggers a tighter limit and an alert (SEC-21)." Record the deferred bot defences as an accepted risk in §9, with a stated trigger for revisiting them.

### SEC-33: Security bounds and floors are undefined

- **Citation:** FR-10; FR-12; FR-15; FR-18; FR-19; FR-22; FR-28; FR-35
- **Type:** Untestable
- **Problem:** "Expire", "limited", "configurable" and "recent" can't be failed by a test, and several values have no bound. Admins can set a long session lifetime, unbounded client secret overlap (FR-12), no password minimum (FR-18), or thresholds that turn off protection (FR-28). During a client secret compromise, the overlap keeps the stolen secret alive unless it can be skipped.
- **Proposed change:** Add a table of defaults and hard limits, enforced in the Deployment:
  - reset link: 30 minutes or less, invalidated by any newer reset or a password change
  - email code: 10 minutes or less, at least 6 digits, at most 5 attempts per code
  - session absolute and idle maximums
  - secret overlap: 7 days or less, with an "end now" option in FR-12
  - password: 12 characters minimum for Prod (FR-18 can only raise this)
  - lockout thresholds that can't be turned off

  Also state that a client secret, and every other credential, is stored only as a hash or under NFR-3 encryption.

## Low

### SEC-34: Conformance passes vacuously with no named profiles

- **Citation:** FR-23; SM-4; §10
- **Type:** Untestable
- **Problem:** "Passes the tests for the profiles it claims" is satisfied by claiming none.
- **Proposed change:** Name the v1 profiles in FR-23, such as Basic OP, Config OP and RP-Initiated Logout, plus the Back-Channel OP profile if adopted. Add the suite to release gating.

### SEC-35: ASVS version, level and evidence aren't stated

- **Citation:** NFR-8; SM-3
- **Type:** Untestable
- **Problem:** The method is accepted. Without a named version and level, though, "complete" can't be checked, and the gate could pass once and then go stale. The PRD also doesn't define what counts as critical or high.
- **Proposed change:** Add to NFR-8: "Assessed against a named ASVS version at Level 2 or above, with a stored result per requirement, and a severity definition. Re-run in full before each major release, and for the affected chapters whenever a trust boundary changes (NFR-1)."

### SEC-36: Tenant switching can apply an action to the wrong Tenant

- **Citation:** FR-9; FR-8
- **Type:** Unsafe
- **Problem:** If the active Tenant is held in session state, a stale tab showing Dev can apply a destructive action to Prod after a switch in another tab. FR-9 requires the badge to be visible, but doesn't bind the action.
- **Proposed change:** Add to FR-9: "Every Admin action names its target Tenant explicitly, and a mismatch with the page's Tenant is rejected." Add: "Prod Tenants use a visibly distinct treatment."

### SEC-37: "Tokens" in the Log exclusion is ambiguous

- **Citation:** FR-30; FR-40; NFR-3
- **Type:** Untestable
- **Problem:** "Passwords, secrets or full tokens" doesn't clearly include reset links, email codes, authorization codes, recovery codes or TOTP seeds. "Full" implies that partial tokens are allowed, without limit. Raw detail view (FR-40) could display them, along with query strings.
- **Proposed change:** Add to FR-40 and FR-30: "Neither Logs nor raw detail ever contain any credential-equivalent value: reset link, verification link, email code, authorization code, recovery code, TOTP seed, Session identifier, or any URL query containing these." Add a test that plants canary values through each flow and scans the Logs for them.

## What holds up

These parts are sound and shouldn't be weakened when the changes above are applied.

- **Authorization grants:** Implicit and Resource Owner Password grants are removed, and PKCE is required for public clients (FR-13).
- **Refresh tokens:** rotation with whole-family reuse revocation (FR-15).
- **Social linking:** no automatic linking (FR-20). It only needs the same-email case defined (SEC-16).
- **Passkey scope:** each passkey is bound to the exact Tenant subdomain rather than the parent (FR-21).
- **Narrow surface:** impersonation, customer code, SMS, push, and magic link are all out of v1 (§6, §7). Each exclusion removes a known source of account takeover.
- **Bearer tokens:** deferring sender-constrained tokens is acceptable at this scale, provided the access token ceiling in SEC-03 exists.
- **Infrastructure-gated Admin recovery:** FR-5's requirement for infrastructure-level access is the right anchor. SEC-01 only tightens what it does.
- **Threat model before authentication work** (NFR-1), and **critical vulnerabilities block release** (NFR-7).
- **Quality posture:** SM-C1 to SM-C3 explicitly protect security from schedule pressure.
