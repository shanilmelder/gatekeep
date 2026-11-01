# Decision Reconciliation: Gatekeep PRD

Checked on 2026-11-01. The PRD was not edited.

**Inputs:** `prd.md`; the PRD run `.memlog.md`; the brief run `.memlog.md` and `research-landscape.md`. `design/design-prompt.md` and `brief-gatekeep.md` were read only to check references.

**Limits:** incident lessons are judged against the digest's one-line summaries. The linked sources were not opened. The digest's findings are marked in it as partly vendor-sourced or unconfirmed.

**Severity:** High means fix before the PRD is finalized. Medium means fix before architecture or epics depend on it. Low means tidy-up.

## Summary

- **The six named user decisions are all reflected.** None is contradicted outright, and no feature gap is claimed.
- **Several decisions have consequences the PRD hasn't followed through.** The main ones are subdomain immutability, the availability arithmetic on one on-premises server, and who holds Deployment-level authority.
- **One logged decision is misrecorded.** The §12 index says A-6 is achievable, while the memlog and NFR-10 say it's conditional.
- **Of the five incident lessons, tenant isolation is the best covered, and disclosure is the weakest.** Signing key handling covers the mechanics but not the "stale key" failure the research names. Phishing resistance covers Owners only.

### Priority findings

| # | Finding | Severity | Where |
| --- | --- | --- | --- |
| 1 | Signing keys have no maximum age, retirement or private-key destruction rule, and UJ-3 contradicts FR-37 | High | L5.1, C1 |
| 2 | Deployment-level authority and Admin identity are undefined, though multi-tenancy depends on them | High | C2 |
| 3 | Phishing-resistant access covers Owners only, while Admins and machine clients can rotate and revoke keys | High | L5.4 |
| 4 | Disclosure is one sentence, and the tools to act on it are missing | High | L5.5 |
| 5 | A-6 is misindexed, and 99.9% can't absorb one restore within NFR-13 | High | C3 |
| 6 | Nothing says a Tenant's subdomain is immutable, yet FR-7 allows rename | High | C4 |

## 1. Logged decisions

### PRD memlog

| Line | Decision | Status | Evidence and notes |
| --- | --- | --- | --- |
| 8 | No Keycloak or Clerk failure drives this; no feature gap claimed | Reflected | §1 L20 says so directly. A full read found no gap claim. Competitors appear nowhere else in the PRD. |
| 9 | Fast path with ASSUMPTION tags | Partly | Tags are used, but several inferred values are untagged (see C6). |
| 10 | Multiple isolated Tenants in v1 | Reflected, with a gap | §3, §4.2, FR-7 to FR-10, SM-2 and §9 cover it. Deployment-level authority is missing (C2). |
| 10 | Remaining fast-path defaults stand as assumptions | Partly | Same as line 9. |
| 12 | Subdomain tenancy; cookies and passkeys bound to the exact subdomain | Reflected, with a gap | FR-7, FR-8 L152, FR-21 L270 and FR-1 L86. Consequences are incomplete (C4). |
| 13 | On-premises; no cloud-managed services; A-6 depends on redundancy | Partly | FR-1 L85, NFR-10 L515 and OQ4 are right. The §12 index is wrong (C3). "No cloud-managed service" also has a wording problem (C5). |
| 14 | ASVS self-assessment, not a paid penetration test | Reflected | NFR-8, SM-3 and the §9 row. Notes in C7. |
| 15 | Quickstarts for React, Next.js, Node, .NET, Python | Reflected | FR-43 L481 and §7.1 row 14. Notes in C8. |

### PRD memlog: assumptions and events

| Line | Item | Status | Evidence and notes |
| --- | --- | --- | --- |
| 6 | Started before the brief finished | Reflected | §0 L14. |
| 7 | Self-hosted, own production projects, learning exercise | Reflected | §1 and A-12. |
| 7 | Expected 80+ stories | Not traceable | Not in the PRD or the brief memlog, although the log says it was carried from the brief run. Harmless, but `bmad-create-epics-and-stories` shouldn't treat it as a given. |
| 7 | Heavy security requirements | Reflected | §5.1. |
| 11 | 44 FRs, 19 NFRs, 12 assumptions, 6 open questions | Counts drifted | FRs and NFRs match. The PRD now has 11 assumptions (A-4 and A-5 are absent) and 4 open questions. No memlog entry records what happened to them. They may have been resolved by lines 12 to 15, but that's an inference. |
| 11 | Status stays draft until review and Finalize | Reflected | Front matter says `draft`. |
| 16 | Answers taken as approval to finalize, with a rubric and security reviewer selected | Open | No rubric or review output exists in the PRD folder, and status is still `draft`. Either finalization hasn't run or its output wasn't saved. |

### Brief memlog

| Line | Item | Status | Evidence and notes |
| --- | --- | --- | --- |
| 6 | Brief named `brief-gatekeep.md` | Reflected | The file exists. The PRD doesn't reference it by name. |
| 7, 10 | `design-prompt.md` missing, then found | Reflected | PRD uses it. The file exists. |
| 8, 11 | 14 sections map onto 12 sidebar groups | Reflected | §7.1 has all 14 rows in the source order. |
| 9 | Research has vendor-sourced or unconfirmed figures | Reflected | The PRD cites no market figures. |
| 12 | Re-invocation treated as resume | Not applicable | Process only. |
| 13 | Reason for building: Keycloak and Clerk lack features | Correctly superseded | PRD memlog line 8 replaces it, and the PRD follows the later decision. The brief memlog still carries the old reason, so anyone reading it alone would be misled. |
| 14 | Learning exercise, also production; real credentials in scope | Reflected | §1 L22. |
| 15 | "No" read as no other sources, with the user as first real user; confirmation requested | Unconfirmed | No log entry shows confirmation. A-1 and A-12 depend on the same reading, and A-10 says "real strangers may use these apps". |
| 16 | Coaching path for users, MVP cut, non-goals and metrics | Superseded | Replaced by the fast path. |
| 17 | MVP cut, non-goals and metrics left for the PRD | Settled by default | §6, §7 and §8 settle them. The logs show no direct user discussion of them, only "no other objection". §7's v1 cut is the largest decision in the PRD and has only the A-12 tag. |

## 2. Conflicts and consequences

### C1. UJ-3 contradicts FR-37 (High)

UJ-3 L46 has Esm rotate the key, and its climax is "tokens signed by the old key are rejected". FR-37 L421 says tokens signed by the previous key verify until they expire. Only FR-38 (revoke) rejects them, and UJ-3 never mentions revoke. As written, the compromise journey leaves the compromised key trusted.

**Fix:** have UJ-3 rotate and then revoke, and name the app impact of FR-38's warning.

### C2. Multi-tenancy has no Deployment-level authority (High)

- **Who creates a Tenant:** FR-7 gives this to "an Admin with the Owner role", but FR-39 and §3 make roles per Tenant. An Owner of one Tenant can't sensibly be the authority for creating another, and there is no Deployment role.
- **First Admin:** FR-2 creates an Admin before any Tenant exists, so that Admin has no role to hold under §3.
- **Admin identity:** §3 defines Session and Hosted Login in terms of Users, and a User belongs to one Tenant. Nothing says where Admins sign in, where their credentials are held, or which host serves the Admin Dashboard. FR-8's cookie rule covers Tenant subdomains only.
- **OQ3 is open but already assumed:** "Can Admins hold roles across Tenants?" is unanswered, while FR-9, FR-39 and §3 all assume yes.
- **Admin Factor reset:** FR-31 covers Users. Nothing says who resets an Admin's Factors short of FR-5.

**Fix:** define a Deployment-level role and the Admin identity model, and answer OQ3 before architecture. All three are trust boundaries for the threat model (NFR-1).

### C3. A-6 is misindexed, and the availability numbers conflict (High)

- **Index error:** §12 L625 says 99.9% "is achievable on the on-premises server". NFR-10 L515 says it needs revisiting, and memlog line 13 says it depends on redundancy. OQ4 is still open. The index states as fact something the decision leaves open.
- **Arithmetic:** NFR-10 allows about 43 minutes a month, and NFR-13 allows up to 1 hour for a restore. One compliant restore breaks the monthly target. This is the UJ-4 scenario, and on one server every upgrade (FR-3) and reboot also spends the budget. FR-3 doesn't say whether planned downtime counts.
- **Rehearsals:** SM-5 needs a full restore every quarter. Nothing says on what. Rehearsing on the only server would be an outage, and spare hardware isn't in §10.

**Fix:** correct the index, say whether planned maintenance counts, and align NFR-10 and NFR-13 once OQ4 is answered.

### C4. Subdomain tenancy is not followed through (High for the first item)

- **Immutability:** FR-7 lets an Owner rename a Tenant, and FR-7 ties the subdomain to issuer, Hosted Login, discovery and JWKS. FR-21 binds passkeys to it. If the subdomain changes, every token and passkey in the Tenant breaks. The PRD must say that the subdomain is fixed and separate from the display name. Compare FR-16 L224, which does this for API identifiers.
- **Reuse after deletion:** nothing stops a deleted Tenant's subdomain being reissued, which would reuse an issuer identity. FR-7's retention rule doesn't address this.
- **Reserved names:** no rule covers names such as `admin`, `api` or `www`.
- **Sibling subdomains:** FR-8 scopes cookies to the exact host, which stops cookies being sent elsewhere. It doesn't stop one sibling setting a parent-domain cookie. The risk is limited here because theming and templates can't run code (FR-34, FR-36), but it belongs in the threat model.
- **Wildcard certificate:** one wildcard private key serves every Tenant. It's a shared key that FR-1 treats only as documentation. Nothing covers where it lives or how it's renewed.
- **Dependencies:** §10 omits DNS control and the wildcard certificate.
- **Prod label as a control:** FR-11 relaxes wildcard callbacks outside Prod Tenants, and FR-7 lets the label be changed. Relabelling a Tenant could switch the protection off. Changing a label should be restricted and logged.

### C5. "No cloud-managed service" is at odds with §10 (Low)

FR-1 L85 says the Deployment needs no cloud-managed service to run. §10 lists an email provider, and FR-17, FR-19 and FR-22 can't work without one. OQ1 also leaves external breach data open. Either name a self-hostable option or narrow FR-1 to "for the core runtime".

**Also unsettled:** OQ4 asks whether the server is reachable from the public internet, while UJ-2, A-10 and FR-20 all assume it is.

### C6. Untagged inferred values (Medium)

§0 promises that inferred decisions are tagged, and memlog line 10 says defaults stand as assumptions. These read as inferred but have no tag, and the logs don't record the user choosing them:

- NFR-15's 30-day Log retention
- SM-5's quarterly rehearsal
- the 30-minute target in FR-43 and SM-6
- the Never and Always MFA options in FR-25
- the §7.1 v1 and v2 cut
- OQ2's "Assumed: apps use another login until SM-3 passes"

A-4 and A-5 are also missing from the numbering (see the memlog line 11 entry).

### C7. ASVS self-assessment (Medium)

The decision itself is reflected and isn't reopened here. Research also found no buyer-side penetration test requirement, though that's weak support because Gatekeep has no buyers. Four things limit what the gate proves:

- **No target:** NFR-8 names no ASVS version or level, so it can't be failed or passed consistently.
- **Circular mitigation:** the §9 row says the self-assessment can miss what its author missed, then lists the NFR-8 checklist first as mitigation. The same goes for "review of every authentication story", which has no named reviewer for a sole builder.
- **Decision not recorded:** the memlog says the user accepted this after being advised an external test was preferable. The PRD doesn't record that as an accepted risk.
- **SM-3 overclaims:** it says it validates NFR-1 to NFR-9 but only measures NFR-8.

### C8. Quickstarts (Low)

The five are correct everywhere they appear. Two points remain:

- **SDKs:** the PRD doesn't say whether quickstarts rely on Gatekeep SDKs or standard libraries. See L5.2 for why this matters.
- **Coverage:** FR-43's only test is UJ-1. No quickstart is tied to UJ-5, although Node, .NET and Python are the likely API languages.

### C9. Risk mitigations and journeys with no requirement behind them (Medium)

- §9 cites "provider status in health view", but FR-6 only requires service status and rate-limit usage.
- UJ-3 starts with "an alert". No FR defines alerts. Home's security alerts, Security Center and Log streams are all deferred to v2 by §7.1. In v1, Esm only finds out by reading Logs.
- SM-2 requires zero cross-Tenant access in production, but no requirement detects it.

## 3. Incident lessons

| Lesson | Research source | Coverage |
| --- | --- | --- |
| Signing key handling | Storm-0558 | Partial: mechanics yes, lifecycle no |
| Tenant isolation | Entra CVE-2025-55241 | Good, with gaps |
| Support tooling | Okta 2023 | Mostly good by exclusion |
| Admin phishing resistance | 2026 Okta SSO vishing | Partial |
| Disclosure | Researcher's read; Okta scope widening | Thin |

### L5.1 Signing key handling (High)

**Covered:** per-Tenant keys, staged rotation (FR-37), revocation (FR-38), encryption at rest (NFR-3), backups (FR-4), rehearsal (SM-5).

**Not covered:**

- **Maximum key age:** rotation is manual only. Storm-0558's stale key is the failure this leaves open. SM-5 rehearses "a key rotation", which needn't touch every Tenant.
- **Retirement:** §3's states are next, current, previous and revoked. Nothing moves a previous key out once its tokens expire, removes it from the JWKS or destroys its private material.
- **Restore brings revoked keys back:** restoring a backup taken before a revocation returns the revoked key to use. The same applies to revoked Sessions, token families and blocked Users. Neither FR-4 nor UJ-3 and UJ-4 address this.
- **Root of trust:** NFR-3 requires encryption but doesn't say where the encrypting key lives. With no cloud KMS, this matters more. A shared key would also link all Tenants, undercutting FR-8.
- **Backup key custody:** NFR-13 sends backups off the server and FR-4 needs them restorable. Nothing covers who holds the decryption key if the server is lost.
- **Revocation latency:** FR-38 says tokens are invalidated, but resource servers verify offline against cached JWKS. No maximum cache time is stated, so the promise isn't testable.
- **Log coverage:** FR-40 lists key operations, which is good, but no requirement detects a key being used outside its state.

### L5.2 Tenant isolation (Medium)

**Covered:** FR-8 is strong, SM-2 is a primary metric, and subdomain binding gives separate issuers, cookies and passkey scopes.

**Not covered:**

- **Test scope:** FR-8 L149 covers Hosted Login, Management API and Admin Dashboard requests, but the automated suite (L150) covers Management API endpoints only. Hosted Login, OIDC endpoints and the Dashboard backend have no test obligation.
- **Enforcement outside Gatekeep:** FR-8 L148 says other Tenants' APIs reject a token. Those APIs are Esm's code, so this is true only if each one validates issuer and audience. Quickstarts are the place to require it. The Clerk SDK bypass in the research shows the same class of risk in client libraries, and no PRD requirement covers SDK or sample security.
- **Non-request paths:** background jobs, caches, email rendering, rate-limit counters and exports aren't named. FR-8's wording centres on requests.
- **Shared fate:** restore is Deployment-wide, so recovering one Tenant rolls back all of them. That sits badly with the §2.1 goal that a problem in one can't reach another.
- **Noisy neighbour:** one Tenant can exhaust shared capacity. NFR-6 rate limits are per Tenant, but that isn't stated as a protection for the others.

### L5.3 Support tooling (Medium)

**Covered:** impersonation is excluded (§6), the Support role is deferred (A-3), and FR-30 and FR-40 keep secrets and full tokens out of views. FR-33 limits errors to a code and trace ID. There's no support console, which removes much of the Okta exposure.

**Not covered:**

- **Term coverage:** "secrets and full tokens" doesn't clearly include Session identifiers, authorization codes, reset links or one-time codes. The Okta incident was about session tokens specifically. FR-30 also shows Sessions to Admins, so what it displays needs defining. FR-40's raw detail needs the same.
- **Storage:** NFR-3 covers secrets and private keys. It doesn't say Session identifiers or refresh tokens are stored hashed, so a database read or backup could yield live ones.
- **Debugging output:** the realistic "support channel" for a sole Operator is debug logs, diagnostic captures and database access while fixing a fault. No rule covers these, and NFR-3 names only Logs, error messages and exports.
- **Design leftover:** `design-prompt.md` §13 lists a support centre and status page link. §7.1 doesn't place it. It should be ruled out so it doesn't return as a channel.
- **Related, Salesloft Drift (stolen OAuth tokens):** FR-15 handles refresh reuse. Management API credentials are the stronger exposure, covered in L5.4.

### L5.4 Admin phishing resistance (High)

**Covered:** the first Admin (FR-2) and Owners (FR-39) must use a phishing-resistant Factor. All Admins must use MFA.

**Not covered:**

- **Admin role:** FR-39 L443 lets Admins use TOTP, yet FR-37, FR-38, FR-11 and FR-31 let "an Admin" rotate or revoke keys, change callback URLs and reset User Factors. These are the actions an attacker wants. Either give them to Owners or require a phishing-resistant Factor for all Prod Tenant Admins. A sole Operator loses little by doing so.
- **Machine clients:** FR-42 gives a machine-to-machine Application every Tenant-scoped action except Admin management. That includes key revocation and callback changes, protected only by a client secret, with sender-constrained tokens deferred to v2. It sidesteps the Admin Factor requirement. High-impact Permissions should be excluded or separately granted.
- **Undefined term:** "phishing-resistant Factor" isn't in §3. §3's Factors include TOTP and recovery codes, so state that only WebAuthn counts.
- **Downgrades:** nothing stops an Owner's recovery codes acting as a phishable fallback, or says how FR-5 recovery re-establishes a phishing-resistant Factor. FR-5 requires logging but not re-enrolment.
- **Social engineering:** the vishing case had no product flaw. FR-31 lets an Admin reset a User's Factors with no identity-check step and no notice to the User.
- **Privileged action check:** FR-38 requires confirmation, but no key or Admin action requires fresh authentication, although FR-35 requires it for Users.

### L5.5 Disclosure (High)

**Covered:** NFR-9 says a security fix process exists, "including how to rotate keys and notify affected Users". NFR-7 blocks releases with known critical vulnerabilities.

**Not covered:**

- **Intake:** no way for anyone to report a vulnerability, such as a published security contact.
- **Timing:** the research says "fast disclosure". NFR-9 has no time target or test, so it passes on a document existing.
- **Legal notice:** A-10 accepts GDPR-style rights, but NFR-14 covers only export and erasure. Breach notification, including any regulator deadline, isn't addressed.
- **Widening scope:** Okta's scope grew after first disclosure. Nothing says how to update affected people.
- **Notification tool:** FR-36's templates are verification, reset, one-time code and blocked account. There's no security notice or way to message a Tenant's Users.
- **Tenant-wide response:** UJ-3 "revokes affected sessions", but FR-31 revokes per User. No FR covers revoking all Sessions and refresh tokens in a Tenant, or forcing a Tenant-wide password reset. The UJ-3 climax can't be delivered at any scale.
- **Evidence window:** NFR-15's 30-day default may end before a compromise is noticed, and Logs live on the server under investigation. An Admin who can configure retention may also be able to shorten it, undermining FR-40. Nothing says who can change it.
- **Rehearsal:** SM-5 tests key rotation and restore, but not notification.

## 4. Recommended order

1. Decide before architecture: Deployment-level role, Admin identity and OQ3 (C2); OQ4 (C3); subdomain immutability (C4).
2. Add to the PRD: key lifecycle rules (L5.1), Prod Admin and machine-client limits (L5.4), Tenant-wide revocation and a fuller NFR-9 (L5.5).
3. Correct: the UJ-3 wording (C1), the A-6 index (C3), and the FR-8 suite scope (L5.2).
4. Tidy: tags (C6), NFR-8 version and level (C7), §9 and §10 (C4, C9).
5. Then run `bmad-prd` update and finalization, since memlog line 16 left no review output.

**Needs the user:** C2, OQ4, the Prod Admin rule in L5.4 and the ASVS level are product decisions. Everything else follows from decisions already made.
