---
title: Gatekeep PRD reconciliation against design inputs
created: 2026-11-01
prd: prd.md
inputs: design/design-prompt.md, design/SCREENS.md
---

# Reconciliation: PRD vs design inputs

**Scope.** `prd.md` was compared with `design/design-prompt.md` and `design/SCREENS.md`. The three exports were read only in targeted passages, to settle specific doubts; they were not reviewed end to end. Export references give the file (`Admin`, `Hosted Login`, `Design System`) and line. Neither the PRD nor the design files were changed.

**Severity.** High: blocks a v1 journey, or makes a security-relevant requirement unbuildable or ambiguous. Medium: a builder would have to guess. Low: tidy-up.

**Rule applied.** An item that §6 or §7 places is not a gap, even if it is missing from v1.

## Most important findings

1. **Sign-in MFA challenges and recovery-code sign-in have no screen (H-1).** The design has only enrolment and display screens, so UJ-2's edge case cannot be built as designed.
2. **UJ-2 contradicts FR-27 and the glossary (H-2).** Maya only has a passkey, which is not a Factor, so she never receives the recovery codes the journey relies on.
3. **v1 screens contain deferred controls, and nothing says to remove them (B-1).** FR-33 and FR-44 point at the design, but FR-44 only excludes whole screens.
4. **Non-enumeration (FR-17) conflicts with the identifier-first, lockout and blocked screens (D-1).**
5. **Tenant rename (FR-7) conflicts with the design's immutable tenant name, which is also the issuer subdomain (D-2).**
6. **Owner is a per-Tenant role, but Tenant creation and Admin sign-in need a Deployment-level answer (B-2, B-3).**

---

## (a) Designed items placed nowhere

Not in §4, §5, §6 or §7.

| ID | Designed item | Source | Sev | Why it matters |
| --- | --- | --- | --- | --- |
| A-1 | First-party SDKs (`@gatekeep/react`, `@gatekeep/nextjs`) | Admin L241, L420, L1266; prompt §2 "SDK code samples" | High | Every quickstart installs one. FR-43 promises five quickstarts but never says whether SDKs exist. If they do, that is five more packages to build and secure. If not, the quickstarts rely on generic OIDC libraries and the design's samples are wrong. |
| A-2 | Admin "+ Create user" | Admin L584–600 | High | No FR creates a User. FR-17 lets Admins disable sign-up, and import is v2, so a sign-up-disabled Connection has no way to gain Users. |
| A-3 | Suspicious IP throttling (per-IP login and signup limits, CIDR allowlist) | prompt §8; Admin L862–903 | Medium | Not in 7.1's v1 or v2 lists. NFR-6 and FR-28 cover part of it, but they do not say whether this screen block ships. |
| A-4 | PAR and JAR | prompt §8; `GEN.tenantsec` | Medium | §6 places FAPI and 7.1 places sender-constrained tokens, but PAR and JAR are placed nowhere. The design shows PAR on by default. This also affects which profiles FR-23 can claim. |
| A-5 | Signing algorithm choice (RS256 or HS256) per API and per ID token | prompt §3; `GEN.apis`; Admin L388 | Medium | See D-7. HS256 does not fit the Tenant Signing Key model. |
| A-6 | Allow offline access per API | `GEN.apis` | Medium | Determines when refresh tokens are issued. FR-13 and FR-15 are silent. |
| A-7 | Passkey policy: prompt enrolment, autofill, user verification, attestation, device-bound fallback | `GEN.passkeys` | Medium | FR-21 gives Admins no controls, though 7.1 puts "passkeys" in v1. User verification decides whether a passkey can count as multi-factor (H-2). |
| A-8 | Email code settings: code length, expiry, attempts, disable sign-ups | `GEN.passwordless` | Medium | FR-22 requires expiry and attempt limits but not who configures them. FR-17's sign-up toggle covers "a Connection", yet whether email code can create accounts is unstated. |
| A-9 | Terms acceptance at sign-up and consent records | Hosted Login L80–94; `GEN.compliance` | Medium | The signup screen has a required terms checkbox. No FR covers it, no setting holds the terms URL, and no consent record exists. Real strangers may use these apps (A-10). |
| A-10 | Data residency and Region (tenant creation, Tenant settings, health, domain pattern) | prompt §13; Admin L208–214; `GEN.tenant` | Medium | Meaningless on one on-premises server, but never ruled out. Needs a §6 line, and the `.us.` domain segment needs removing (D-3). |
| A-11 | Custom metadata: `user_metadata` and `app_metadata` editors | prompt §6; Admin L658–683 | Medium | Not in FR-30 or FR-31. Tokens carry it only through Actions (v2), but Applications may need stored profile data in v1. |
| A-12 | Back-channel logout | `GEN.tenant` | Medium | Affects whether FR-31 revocation and FR-24 logout reach Applications. Placed nowhere. |
| A-13 | Remember browser for 30 days | Admin L818–860 | Medium | Directly changes what "Always" means in FR-25. |
| A-14 | Email as an MFA Factor | prompt §8 | Low | FR-26 omits it, and §6 excludes only SMS, voice and push. |
| A-15 | Device Authorization grant and device flow settings | prompt §2, §13; Admin L1327; `GEN.tenant` | Low | 7.2 defers the screen, but 7.1 has no entry for the grant. FR-13's list excludes it only by implication. CIBA and Token Exchange are placed through section 10 and "custom token exchange". |
| A-16 | Other social providers (Apple, Facebook, LinkedIn, X) and per-provider scopes and sync profile | prompt §4 | Low | A-2 implies the providers are out, but no later release is named. The provider settings have no owner. |
| A-17 | Password policy details: personal data check, require username, identifier types | prompt §4; Admin `dt.policy`, `dt.settings` | Low | FR-18 lists only strength, history and dictionary. FR-17 implies email only without excluding usernames. |
| A-18 | Brute-force allowlist and user notification; breached-password admin digest | prompt §8; Admin L862–903 | Low | FR-28 and FR-29 cover neither. |
| A-19 | Theme widget position and background | prompt §11; Admin L1003–1026 | Low | Dropped from FR-34 without a statement. |
| A-20 | Users: bulk actions, Lucene query, filters | prompt §6; Admin `hasSel`, L584–600 | Low | FR-30 says only "search". 7.1 defers import and export jobs, not bulk actions or the query language. |
| A-21 | Admin actions "Change password" and "Revoke refresh tokens" | prompt §6; Admin L1339 | Low | FR-31 lists neither. Only blocking ends refresh tokens. |
| A-22 | User detail: devices, authorized apps | prompt §6 | Low | Not in FR-30. |
| A-23 | Global search, help, alerts in the top bar; Support page and status link | prompt preamble, §13; SCREENS "Top bar"; `GEN.support` | Low | No release placement. The Support page's tickets imply a vendor, so it probably needs a §6 line. |
| A-24 | Tenant security extras: allowed domains, persistent sessions; Admin extras: allowed IP ranges | `GEN.tenantsec`; `GEN.team` | Low | Allowed IP ranges could be useful for a self-hosted Admin Dashboard, so it should be an explicit decision. |
| A-25 | Application extras: logo, CORS origins distinct from web origins | prompt §2; Admin L309–344 | Low | FR-11 mentions web origins only. |
| A-26 | Email templates: welcome, MFA enrolment; verification link lifetime and redirect | prompt §11; `GEN.emails` | Low | FR-36 lists four templates. See also H-8 for Admin invitations. |
| A-27 | Tenant settings: default directory, Application default Connections | `GEN.tenant` | Low | Absent from FR-10. |

---

## (b) v1 items with missing or conflicting screens or FRs

### Hosted Login (§7.2 vs FRs vs design)

| ID | Issue | Refs | Sev | Suggested resolution |
| --- | --- | --- | --- | --- |
| H-1 | **No sign-in challenge screens.** FR-26 needs entering a TOTP code at sign-in and UJ-2 needs entering a recovery code. The design has only TOTP enrolment (QR) and recovery code display. "Try another method" (Hosted Login L178, L201) leads to no designed screen. The only code-challenge screen is SMS (deferred). 7.2's bare "TOTP" and "recovery codes" hide this. | FR-26, FR-27, UJ-2, 7.2 | High | Split 7.2 into enrol and challenge for each Factor. Add TOTP challenge, recovery code entry and method-picker screens. |
| H-2 | **Maya never gets recovery codes.** UJ-2: Maya creates a passkey and recovers with a recovery code. FR-27 issues codes "when first enrolling a Factor". The glossary makes passkey a Connection, not a Factor. Relatedly, FR-25 "Always" does not say whether a passkey satisfies MFA, while UJ-2's climax is "one passkey prompt". The design's factor chooser offers "Passkey or security key" (L148), blurring the two. | UJ-2, FR-21, FR-25, FR-27, §3 | High | Issue codes at first passkey creation too, and state whether a user-verified passkey satisfies MFA "Always". |
| H-3 | **FR-35 needs re-authentication, but its only designed screen is deferred.** "Sensitive changes require recent authentication", and the Step-up challenge is deferred. That screen is also payment-specific. | FR-35, 7.2 | High | Add a re-authentication screen to 7.2, separate from step-up. |
| H-4 | **Social email collision has no outcome.** FR-20 forbids automatic linking and 7.2 defers the linking prompt, so a social sign-in matching an existing email has no defined behaviour or screen, despite FR-33's "every error state has a screen". | FR-20, FR-33, 7.2 | High | Define the outcome and add its screen, while respecting FR-17. |
| H-5 | **Forgot password has no "check your email" state.** The design ends at the form (L232). FR-17's non-enumeration needs a neutral confirmation. | FR-17, FR-19, 7.2 | Medium | Add it to 7.2 and design it. |
| H-6 | **The email code screen exists only as SMS.** The design shows "Check your phone" with "Use email instead" (L123). 7.2 says "email code entry" but no email version exists. | FR-22, 7.2 | Medium | Redraw for email. |
| H-7 | **Account Portal is in 7.2 unqualified, but FR-35 narrows it.** The design has Connected apps & agents and Privacy & data tabs, neither in FR-35 nor in the deferred list. Delete promises "a copy of your data by email first" (L421+), which FR-35 does not require. Should a first-party "connected apps" list ship? Its agent and token vault rows are clearly Later, and the "Verify app" row is §6. | FR-35, 7.2, NFR-14 | Medium | List portal tabs explicitly in 7.2. Decide on connected apps and the data copy. |
| H-8 | **Admin invitation has no screen.** FR-39 invites Admins, the only designed acceptance screen is the organization invitation (deferred, and through SSO), and FR-36 has no Admin invitation template. The design's Invitation template is for organizations only. | FR-39, FR-36, 7.2 | Medium | Add Admin invite acceptance and its template. See B-3. |
| H-9 | **"Blocked" means two things.** FR-36's "blocked-account" template and FR-28's lockout email overlap. In the design the Blocked account *screen* is an Admin suspension with no self-service path, while the Blocked account *template* has a 24h unblock link and belongs to brute-force lockout (`GEN.emails`). Sending that link after an Admin block would undo FR-31. | FR-28, FR-31, FR-36 | Medium | Separate "blocked" (Admin) from "locked" (automatic) and rename the template. |
| H-10 | **Custom error page vs FR-33.** FR-10 and `GEN.tenant` allow a custom URL; FR-33 requires a Hosted Login screen with a limited payload. Neither says what a redirect carries. | FR-10, FR-33 | Low | State the precedence and the parameters passed. |

No reverse gap was found: each 7.2 v1 screen traces to at least one FR. No deferred screen contradicts an FR apart from step-up (H-3), account linking (H-4) and invitation (H-8).

### Admin Dashboard and cross-cutting

| ID | Issue | Refs | Sev | Suggested resolution |
| --- | --- | --- | --- | --- |
| B-1 | **Deferred controls sit inside v1 screens.** FR-33 says "following" the Hosted Login export, and FR-44 removes only deferred *screens*. Elements inside v1 screens stay undecided: "Continue with company SSO" on login; "Gatekeep Verify app" and SMS in the factor chooser; magic link fallback in the email code template; Custom domain in Application settings, the JWKS URL, quickstart and theme panel; Implicit, Password, Device, CIBA and Token Exchange grants; Private Key JWT and mTLS on Credentials; Organizations tab; Adaptive and step-up on MFA; bot detection and "Open Security Center" on Attack protection; "Compare & promote" in the tenant switcher; Impersonate, Organizations and linked accounts on Users; provider "Send via an Action"; "Stream to your SIEM" on Logs. | FR-33, FR-44, §6, §7 | High | Extend FR-44's consequence to controls, links and copy, and apply the same rule to Hosted Login. |
| B-2 | **Owner cannot do Deployment-level work.** FR-39 makes Owner per Tenant, yet FR-7 has an Owner create Tenants. The first Admin (FR-2) has no Tenant, so holds no Owner role. Open Question 3 touches this but does not resolve it. | FR-2, FR-7, FR-39 | High | Define a Deployment-level role, or rule that the creator owns the new Tenant and state who may create. |
| B-3 | **Admin authentication has no design or home.** No Admin login, MFA enrolment, bootstrap or recovery screen exists in any export. The glossary defines Factor for Users only, and Admins are not Users of a Tenant, while FR-2, FR-5 and FR-39 all depend on Admin Factors. Which domain serves the Admin Dashboard is also unstated. | FR-2, FR-5, FR-39, §3, §7.2 | High | Add a v1 surface list for Admin authentication and decide whether it reuses Hosted Login. |
| B-4 | **Role permissions are undefined.** "An Admin can…" is used for nearly every FR, while Admin is also a role name beside Owner and Viewer. Nothing says what Viewer may do, or which FRs are Owner-only beyond FR-7 and FR-39. The design has no matrix either. | §3, FR-39, FR-40, NFR-5 | High | Add a role capability table. Consider renaming the role or the term. |
| B-5 | **No v1 landing page.** 7.1 defers Home and the wizard, but FR-44 does not name where an Admin lands, and a first run has zero Tenants. The Overview sidebar group would be empty. | 7.1, FR-44, UJ-1 | Medium | Name a landing page and the zero-Tenant state. |
| B-6 | **Tenant creation has no screen of its own.** The name, region and environment form exists only inside the wizard (L208–214), which is v2. The tenant switcher's "+ Create tenant" leads nowhere else. | FR-7, 7.1 row 1 | Medium | Extract a v1 create form without Region. |
| B-7 | **NFR-14 has no FR or screen.** User data export and erasure are required, but the design's Data subject requests live on the Compliance & privacy page, which 7.1 does not place. 7.1 row 6 defers "export jobs" and FR-30 has no export. Erasure could use FR-31 delete, though Logs are immutable (FR-40), and no rule covers personal data held in them. | NFR-14, NFR-15, FR-31, FR-40, 7.1 row 13 | Medium | Add an FR and place the Compliance page's parts: v1 requests, §6 certifications. |
| B-8 | **RBAC toggles have no FR.** FR-32 depends on "when RBAC is enabled for the API", but no FR enables it. The design has two toggles (Enable RBAC; Add permissions in the access token), and FR-32 collapses them. The RBAC matrix page is in 7.1 row 7 with no FR. | FR-16, FR-32, `GEN.apis`, `GEN.rbac` | Medium | Add to FR-16 and FR-32. |
| B-9 | **API keys page overlaps M2M.** 7.1 row 13 places "Management API tokens" in v1. FR-42 only covers M2M Applications. The design's page includes "+ Create token", test tokens and a token explorer, while 7.1 row 14 defers "token tools". The built-in Management API entry (`GEN.apis`) has no FR, though M2M authorization needs something to authorize against. | FR-42, 7.1 rows 13–14 | Medium | State whether v1 has this page or only M2M Applications, and add the built-in API. |
| B-10 | **Configuration export has no v1 screen or format.** FR-41's only designed surface is Config as code, whose Terraform and Deploy CLI formats are v2. | FR-41, `GEN.iac` | Medium | Name the format and location. |
| B-11 | **Quickstart tab has no FR.** 7.1 puts it in v1, while FR-43 covers quickstarts generally. FR-44 implies sidebar access, so the gallery page is presumably v1 too, cut to five frameworks. The tab shows Next.js, Express, ASP.NET, Django and Spring: Spring and the gallery's other frameworks need cutting, and React needs adding. "Pre-filled with credentials" cannot include the secret after FR-12's one-time display. | FR-12, FR-43, 7.1 row 2, Admin L408–433 | Medium | Add a consequence to FR-43. |
| B-12 | **API reference has no surface.** FR-43 requires a reference, while the only designed surface is the API explorer, whose console is v2. Whether docs ship inside the product or separately is unstated. | FR-43, 7.1 row 14 | Medium | Decide; it also affects install on-premises (FR-1). |
| B-13 | **Email provider status has no home.** §9 mitigates provider failure with "provider status in health view". FR-6 omits it, and the design's Components table (`GEN.health`) does not show it, listing v2 items instead. | §9, FR-6 | Medium | Add to FR-6 and redraw the table. |
| B-14 | **Deployment-level events have no Log.** Log is defined per Tenant, yet FR-5's recovery must be logged, and Tenant deletion (FR-7) removes the Logs that would record it. FR-40 and the design's Team & audit tab also differ: is audit a filter on Logs, or a separate tab? | §3, FR-5, FR-7, FR-40, 7.1 row 13 | Medium | Define a Deployment audit trail and state the audit tab's fate. |
| B-15 | **Theme preview scope is unclear.** FR-34 says "a preview", while the design previews 8 of 33 screens, including deferred consent and organization picker, and lacks most v1 screens. | FR-34, SCREENS differences | Low | List the v1 preview set. |

---

## (c) Qualitative intent the FR structure dropped

| ID | Intent | Source | PRD state | Sev | Suggested carry-over |
| --- | --- | --- | --- | --- | --- |
| C-1 | **"Quiet, dense, exact. An interface for people who read JWTs for fun."** | Design System L30 | Absent. NFR-18 only says interfaces follow the file. A testable FR list invites a form-per-FR product, and the design system is at risk of being treated as just tokens. | Medium | Add a short design-principles passage to §4.11 or §5.4, and pass it to `bmad-ux`. |
| C-2 | **Mono for identifiers, codes and anything a developer might copy.** Includes client IDs, key IDs, scopes, event codes and query bars. | Design System L31 | Absent. | Medium | Add as an NFR-18 consequence, with copy affordances on those values. |
| C-3 | **Developer-first** as the product's stance. | prompt line 1 | The phrase is gone. Developer Experience (§4.10) is reduced to Management API and docs. The feel in the design comes from raw JSON, event type codes, query syntax, ⌘K search, copy buttons and real seconds values, and most of these are A-20, A-23 or unstated. | Medium | State the stance, then decide which of those affordances are v1. |
| C-4 | **Logs as a live developer tool:** real-time stream, event type codes, query syntax. | prompt §12; Admin L1104–1130 | FR-40 has "filter" and "raw detail" only. | Medium | Add event codes and state whether live tail is v1. Stable codes are also a Management API contract. |
| C-5 | **Disciplined colour:** one jade signal colour for primary actions, "allowed" states and focus; status colours only describe state; reference tokens, never hex. | Design System L31, L39 | Absent. | Low | Include in C-1's passage. |
| C-6 | **Flat, tabular density:** 38px rows, 30px controls, elevation only for menus and modals. | Design System L85, L83 | Absent, though "dense but readable data tables" is explicit in the prompt. | Low | Include in C-1's passage. |
| C-7 | **Calm, honest Hosted Login copy,** such as "We never saw your password — checked with k-anonymity." | Hosted Login L376 | Absent. That sentence also depends on Open Question 1: it is wrong if a local dataset is used. | Low | Treat as voice guidance, and tie the copy to the decision. |
| C-8 | **Branding by tokens only:** the same screens re-themed, and only tokens changing. | SCREENS "Theme variants" | FR-34 covers injection but not that themes must remain accessible. Admin-chosen colours can break NFR-16's WCAG 2.2 AA. | Medium | Add a contrast check or guard to FR-34. |
| C-9 | **Populated, realistic product.** The design is nearly always shown full, with one empty state ("No log streams yet"). | Design System L158 | A new Tenant in v1 is nearly all empty states, and neither side covers them. | Low | Have `bmad-ux` cover first-use states. |

Related build note: all three exports load Geist from Google Fonts (Admin L11–12). On-premises self-hosting and FR-1's no-cloud-service intent suggest bundling the fonts, as a requirement for `bmad-architecture`.

---

## (d) Design details contradicting the PRD

| ID | Conflict | Design | PRD | Sev | Suggested resolution |
| --- | --- | --- | --- | --- | --- |
| D-1 | **Account enumeration** | SCREENS: password step is "for a known email". Lockout says the account is locked, shows a masked email (L366). Blocked says the account is blocked (L357). All reachable by whoever typed the email. | FR-17: responses don't reveal whether an email is registered. | High | Decide the post-password or uniform-flow behaviour for each screen, and include sign-up with an existing email. |
| D-2 | **Tenant rename** | "Can't be changed later — use a custom domain for branding" (Admin L208–214). | FR-7 allows rename, and the subdomain is the issuer, so changing it breaks tokens, passkeys (FR-21) and Applications. | High | Separate an immutable slug from a renameable display name. |
| D-3 | **Domain model** | `northwind.us.gatekeep.dev`: a vendor domain with a region segment. | FR-7: subdomain of the Deployment's domain, no region. | Medium | Treat design domains as placeholders and say so. |
| D-4 | **Environment and tenant grouping** | The menu reads "Tenants · Northwind" with environment rows under one project name, and SCREENS says "switch tenants or environments". Three Tenants share one name. The design has an Environments page. | §3: environments are separate Tenants, with no project or group level. FR-7 has no name rule. | Medium | Confirm no grouping level exists, or add one. Decide whether names must be unique. |
| D-5 | **Wildcards in Prod** | Northwind Web, in a PROD Tenant, uses `https://*.preview.northwind.app/...`. Allowed domains uses `*.northwind.app`. Helper text allows subdomain wildcards in general. | FR-11: exact match, no wildcards in Prod. The rule hangs on a label an Owner can edit (FR-7, Environment tag dropdown), so relabelling evades it. FR-11 also doesn't say what non-Prod allows. | Medium | Update samples, restrict relabelling, define the non-Prod wildcard shape. |
| D-6 | **Client secret display** | Reveal, Hide and Copy at any time (Admin L355; prompt "reveal/rotate"). Design grace window is a fixed 24h. | FR-12: shown only when created; overlap configurable. | Medium | PRD should win. Remove Reveal from the design. |
| D-7 | **HS256 on APIs** | `Billing Internal` uses HS256, and the algorithm is selectable. | FR-37 and §3 assume Tenant asymmetric keys published in a JWKS. HS256 needs a shared secret with the resource server, outside the rotation and revocation model. | Medium | Restrict v1 to one asymmetric algorithm. See A-5. |
| D-8 | **Refresh rotation optional** | Rotation and Reuse detection are toggles, with a tenant default and a reuse interval (`GEN.tenantsec`, Admin L388). | FR-15: rotates on every use; reuse revokes the family. No toggle, no interval. | Medium | Remove the toggles, or justify an interval for retry safety. |
| D-9 | **Admin MFA optional** | "Require MFA for all admins" is a toggle, and Ivo Petrov is shown "Not enrolled" (`GEN.team`). | FR-39: every Admin must use MFA. | Medium | Remove the toggle. |
| D-10 | **Admin roles scope** | One role per member, on a page about "this dashboard" (`GEN.team`), with no Tenant selection in the invite. | FR-39: role per Tenant. | Medium | Redesign the member table. The five roles vs three are already covered by A-3. |
| D-11 | **Breached password "Notify only"** | Block & force reset or Notify only. Check at signup and change is an option. | FR-29: a detected password forces a change; checks at sign-up and reset are unconditional. | Medium | PRD should win. Remove Notify only, or relax FR-29. |
| D-12 | **Social dev keys** | "Dev keys work out of the box in DEV tenants" (Admin L519). | FR-20: each Tenant supplies its own credentials. A self-hosted Deployment has no shared keys. | Medium | Remove the copy. |
| D-13 | **Signing key expiry** | Keys have Expires dates; a banner warns "Signing key expires…" (Design System L163). JWKS sample lists Current and Next but omits Previous. | FR-37 has manual rotation and no expiry, and needs Previous to stay published so tokens verify. | Medium | Decide whether keys expire or rotate automatically. Fix the sample. |
| D-14 | **Passkey moment** | Passkey create sits in the Sign up group, and also as a passkey suggestion on the password step. | FR-21: offered after sign-in. UJ-2: at sign-up. Admin-controlled in the design (A-7). | Low | State the offer points. |
| D-15 | **MFA override copy** | "Override per-login with a post-login Action" on the Require MFA panel. | FR-25: per Tenant only. Actions are v2. | Low | Remove the copy. |
| D-16 | **Terminology** | Universal Login (an Auth0 term, despite the brief's call for original branding), Team, Database, Passwordless, dashboard admin. | §3 says terms are exact: Hosted Login, Admin. | Low | Align labels with §3. |
| D-17 | **Logout scope** | "You'll be signed out of all apps on this browser." | FR-24: ends the Session. Consistent with §3, but the effect on Application sessions and tokens is unstated (see A-12). | Low | State explicitly. |

---

## Checked, no gap

- **Placed by §6:** billing, certifications, marketplace, push, SMS and voice, FAPI, Rules and Hooks, impersonation, translations editor.
- **Placed by 7.1:** wizard, Home, Organizations, FGA, Actions, Forms, AI agents, custom domains, custom templates, log streams, analytics, promotion, Dashboard SSO, enterprise Connections, SCIM, self-service SSO, magic link, custom database, adaptive MFA, step-up, bot detection, Security Center, sender-constrained tokens, Private Key JWT, mTLS, add-ons, third-party apps, dynamic client registration, LDAP, Duo.
- **Placed by 7.2:** all deferred Hosted Login screens, including CAPTCHA, device activation and agent approval.
- **Consistent:** Editor and Support roles (A-3 in the PRD), Never and Always policy (FR-25), Log retention of 30 days (NFR-15), block and delete modal behaviour (FR-31), immutable API identifier (FR-16), Next, Current, Previous and Revoked key states (§3), light and dark, desktop and tablet (FR-44, NFR-17), password changed signing out other devices (FR-19), error code and trace ID (FR-33).
