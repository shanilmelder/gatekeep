---
title: Gatekeep PRD verification and editorial pass
created: 2026-11-01
prd: prd.md
inputs: review-rubric.md, review-security.md, reconcile-design.md, reconcile-decisions.md
---

# Gatekeep PRD: Verification and Editorial Pass

## Verdict

**No critical or high finding is fully open, but five findings, in four groups, are only partly resolved, and each traces to a contradiction that needs a decision (V-1 to V-4).** One of the four touches a critical finding. `prd.md` stays `status: draft`. No requirement number, target or limit value was changed.

This document exists to help Esm decide whether the revised PRD can go to finalization, and to give `bmad-ux` and `bmad-architecture` a list of what is still undecided.

| Source | Critical | High | Resolved | Partly resolved |
| --- | --- | --- | --- | --- |
| review-rubric.md | 3 | 11 | 13 | 1 |
| review-security.md | 4 | 18 | 19 | 3 |
| reconcile-design.md | 0 | 12 | 11 | 1 |
| reconcile-decisions.md | 0 | 7 | 7 | 0 |
| **Total** | **7** | **48** | **50** | **5** |

Findings were judged against the PRD after this pass's edits. Finding IDs come from the review files. The A-numbers in `reconcile-design.md` are design-gap IDs, not the PRD's assumption numbers.

## 1. Partly resolved critical and high findings

| Finding | What is resolved | What remains |
| --- | --- | --- |
| Rubric critical, "Passkey, MFA and recovery rules don't compose"; SEC-18 is the same issue | Glossary, Passkey under Always, Recovery Codes at first Passkey, and Recovery Code as a non-Factor are all settled | The recovery path for "every account type" fails in one case: V-2 |
| SEC-09, Management API bypasses Admin MFA | Every change proposed in SEC-09 is adopted | Some FR-46 actions stay open to a client: V-1 |
| SEC-22, whole-server compromise | UJ-6, NFR-9, the §9 risk, FR-50 and SM-5 all exist | The product action doesn't deliver the UJ-6 climax: V-3 |
| B-2, Owner can't do Deployment-level work (reconcile-design) | Deployment Owner role defined | A new Tenant has no route to a first Tenant Role: V-4 |

## 2. Contradictions left

These have more than one reasonable fix, or need a value that can't be inferred, so they were left in place.

### Need a decision

- **V-1. FR-42 vs FR-46.** FR-46 requires a fresh WebAuthn assertion for changing a Prod Tenant's callback URLs or label and for rotating a client secret. FR-42 doesn't exclude those actions, and a machine client can't give an assertion. The Management API can therefore add a Prod callback URL protected only by a client credential. *Options:* add them to the FR-42 exclusions, or state that FR-46 covers Admin Dashboard use only and accept the risk.
- **V-2. FR-27 vs FR-31, glossary and FR-25.** Under Always, a Passkey-only User who has lost both the Passkey and the Recovery Codes falls back to a Factor reset. That User has no Factor to reset, because a Passkey isn't a Factor, and FR-31 doesn't cover Passkeys. After the reset they may have no first-factor route back, since email flows are barred and they may have no password. *Options:* extend FR-31 to Passkeys and define the first sign-in afterwards, or state that the account can't be recovered.
- **V-3. FR-50 vs UJ-6 and NFR-9.** UJ-6's climax is that every credential the intruder could read is dead, but FR-50 only rotates keys. Under FR-37 the previous key stays trusted until its tokens expire. NFR-9 also needs forced re-enrolment, while FR-50 offers only forced password resets, and FR-31 acts on one User at a time. *Options:* make the Deployment-wide action revoke, with Tenant-wide Factor re-enrolment, or accept the residual window and soften UJ-6.
- **V-4. FR-7 vs FR-8, FR-9 and UJ-1.** A Deployment Owner creates a Tenant but holds no Tenant Role in it, so UJ-1's next step of registering an Application isn't allowed until they grant themselves a role. FR-44's landing page has the same gap. *Options:* the creator becomes Tenant Owner automatically, or role assignment becomes an explicit step in UJ-1.
- **V-5. FR-7 vs FR-10.** FR-7 lets a Tenant Owner change the display name, while FR-10 lets a Tenant Owner or Editor do so. The new matrix row follows FR-10. *Options:* drop display name from one of them. The risk is low either way.
- **V-6. Dangling §5.2 references.** FR-28 sets thresholds "within §5.2", but §5.2 has no threshold row. FR-15 enforces an inactivity lifetime for refresh tokens, but §5.2 has only an absolute one. Both need values, and none was invented here. This is also the remainder of SEC-33.
- **V-7. FR-49 vs FR-40.** Erasure pseudonymizes personal data in Logs, but a hash chain reports any change, and the off-server store can't be rewritten. Retention expiry raises the same issue for "reports any gap". *Options:* carve these out of verification, or have architecture separate personal data from the chained record.
- **V-8. FR-20 vs FR-17 and NFR-20.** The social email conflict error reveals that an account exists and points to its sign-in method. NFR-20 and FR-17 forbid both, and neither has an exception. The attacker must control a provider identity with that email, so the exposure is limited. *Options:* record an exception, or remove the path to the existing method.
- **V-9. FR-37 vs FR-38.** FR-37 publishes a next key for at least 15 minutes before it signs. FR-38 promises a usable key with no manual steps at any moment. Both hold only if an aged next key always exists, which is never stated. Revoking within 15 minutes of a rotation breaks one of them. Architecture may be able to settle this, but it should be stated.

### Lower impact

- **FR-48 acting Session.** The exception covers only the Account Portal. Read literally, adding a Passkey during sign-up or forced enrolment in Hosted Login ends the Session in progress.
- **FR-26.** Removing the last Factor is guarded under Always, but removing the last Passkey from an account with no Factor is not.
- **FR-27 vs §7.2.** The 24-hour email recovery delay has no waiting screen.
- **§5.2 and FR-7.** The retention floor is defined only for Prod Tenants, so "until the retention floor expires" has no meaning for a deleted Dev Tenant.
- **FR-23 vs FR-13, FR-24.** Not verified here: confirm that mandatory PKCE and `id_token_hint` for logout redirects can pass the named conformance plans, and that the fixed algorithm is one Basic OP accepts.

### Checked and not a contradiction

- **FR-2 and FR-46:** the first Admin needs two credentials and later Admins may use one plus a Recovery Code. FR-2 is deliberately stricter.
- **§5.2 values vs FRs:** all stated values agree. 99.5% is about 3.6 hours a month, which absorbs a one-hour restore.
- **FR-25 and FR-46 lists:** every action marked "needs re-authentication (FR-46)" appears in FR-46's list.
- **§7.1 and §7.2 vs §4:** no v1 FR depends on a deferred item, and no deferred item appears in a v1 FR.
- **FR-39 matrix vs actor statements:** these agree after the edits below, apart from V-5.

## 3. Resolved critical and high findings

| Source | Findings | Resolved by |
| --- | --- | --- |
| Rubric, critical | UJ-3 contradiction; Admin identity | UJ-3, FR-38, FR-45, FR-50; §3, FR-2, FR-39, FR-46 |
| Rubric, high | Hosting; availability arithmetic; independent review | A-4, §11; NFR-10 at 99.5% including upgrades; §9 accepted risk |
| Rubric, high | v1 scope and sequencing | Scope kept by user decision, smallest-safe promise restated in §1, order in §7.4 |
| Rubric, high | FR-25 consequences; restore; gate; Log conflicts; conformance | FR-25; UJ-4, FR-4; NFR-8, SM-3; §3, FR-7, FR-40, FR-49, NFR-15; FR-23 |
| Rubric, high | Custom domains; "Admin" as person and role | FR-7, FR-21 notes; §3 and the FR-39 matrix |
| Security, critical | SEC-01 to SEC-04 | FR-46, FR-2, FR-5; FR-25, with this pass's Recovery Code wording; FR-48, §5.2; NFR-3, FR-4, SM-5 |
| Security, high | SEC-05 to SEC-08 | UJ-3, §4.8, FR-37, FR-38; FR-4; FR-29, §7.2; FR-39 matrix, §3 |
| Security, high | SEC-10 to SEC-17 | FR-46, FR-25 note; NFR-21; NFR-4, FR-8, §11; FR-47; FR-11, FR-13, FR-23, FR-24; FR-8, FR-16, FR-43; FR-17, FR-20; FR-35, FR-36, FR-40 |
| Security, high | SEC-19 to SEC-21 | FR-8, FR-7, SM-2; §3, FR-7, FR-40, FR-49, NFR-15; FR-45 |
| Design, high | A-1, A-2 | FR-43 and §7.1 (standard libraries, SDKs v2); FR-31 |
| Design, high | H-1 to H-4 | §7.2 and §7.3; FR-25, FR-27; FR-35 and §7.2; FR-20 and §7.2 |
| Design, high | B-1, B-3, B-4 | FR-33, FR-44, §7.3; FR-46, §7.3; FR-39 matrix |
| Design, high | D-1, D-2 | FR-17, FR-28, NFR-20; §3, FR-7, FR-10 |
| Decisions, high | C1, C2, C3, C4, L5.1, L5.4, L5.5 | As for UJ-3; FR-39, FR-46; A-4, §10; FR-7, NFR-21, §10; FR-37, §3, NFR-3; FR-46, FR-42; NFR-9, FR-36, FR-50 |

## 4. Edits made to prd.md

26 exact-match replacements. No requirement was removed.

### Contradiction fixes

These change requirement wording, so they are worth a direct look.

| Location | Change | Why |
| --- | --- | --- |
| FR-25, first and last bullets | Recovery Code stands in for the second-factor step only as FR-27 allows, and the test matrix says so | FR-25 said a second factor was always required, while FR-27 and UJ-2 let a Recovery Code replace it. Under §3 a Recovery Code isn't a Factor |
| FR-27 | "A Factor reset by a Tenant Owner or Editor" | FR-31 and the matrix both give this to Editors |
| FR-16 | Management API grants follow FR-42 | FR-16 otherwise let an Editor grant what FR-42 and the matrix keep Owner-only |
| FR-8 | Adds "apart from the Deployment Owner actions in FR-7 and FR-50" | FR-8 otherwise forbade Tenant deletion and FR-50 for a Deployment Owner without a Tenant Role |
| FR-39 matrix | New row for Tenant settings, Connection toggles and configuration export; Tenant label added to the Owner-only row | FR-10, FR-14, FR-17, FR-41 and FR-7 grant these, yet the matrix must deny anything it omits |
| FR-40 | Logs cover rejected cross-Tenant attempts | SM-2 states that Logs record them, and the list omitted them |
| §7.1, A-10 inline | Adds "Applications use another login until SM-3 passes." | The §12 index already carried it, so tag and index differed |

### Glossary consistency

- **"passkey" to "Passkey":** UJ-1, UJ-2 (three places) and the Connection definition.
- **"users" to "Users":** §2.1.
- **"recovery code" to "Recovery Code":** FR-46 (two places).
- **"signing key" to "Signing Key":** FR-38.
- **"tenant switcher" to "Tenant switcher":** §7.3.
- **"Portal" to "Account Portal":** FR-35.
- **"Alerts" to "Security Alerts":** FR-45.
- **Tenant Role entry:** now defines "Tenant Owner, Editor or Viewer", used throughout but not defined before.

### Prose

| Location | Revised text |
| --- | --- |
| FR-22 | "Codes are single-use, and their expiry and attempt limit stay within §5.2." |
| FR-30 | "appears in the Admin Dashboard or in Management API responses" |
| §6 | "impersonation bypasses authentication", replacing an unclear "this" |
| §7.1 | "This table places the 14 sections…", replacing a sentence fragment |
| §7.4 | "in each month of those 90 days", replacing an unclear "those months" |

### Duplicates cut

- **§3 Tenant Subdomain:** the immutability sentence now points to FR-7, which states it in full.
- **FR-21 note:** dropped the reason, which repeats the consequence above it.

### Structure

Model used: Strategic/Context (Pyramid). No section was cut or moved. Length went from 9,191 to 9,257 words, because the contradiction fixes add more than the cuts remove.

| Tag | Passage | Reason |
| --- | --- | --- |
| PRESERVE | Lower-case "session" for Admins and Applications | The glossary defines Session for Users only, so capitalizing would be wrong |
| PRESERVE | Lower-case "first factor" and "second factor" | Generic authentication terms. A capitalized Factor has a narrower meaning |
| PRESERVE | Per-FR "Realizes" links that repeat a section's line | They give FR-level traceability to epics |
| PRESERVE | Per-FR Out of Scope notes that repeat §7 | They sit where a reader would otherwise assume the feature |
| PRESERVE | FR-35's tab list, which repeats §7.2 | It is a testable consequence |
| QUESTION | FR-36 "Admins can send a test email" | Includes Viewers as written, though FR-39 denies them. Left for the author |
| QUESTION | §7.4 "Remaining v1" omits FR-41, FR-42 and FR-49 | Sequence looks like an oversight rather than a decision |

## 5. Medium and low findings knowingly deferred

Count: **11 medium and 13 low**. Other medium and low findings were resolved by the revision, or are covered by the §0 rule that a designed item isn't a v1 commitment unless §7 says so.

**Medium**

| Finding | What remains |
| --- | --- |
| Rubric, Open Questions | No owners, and no `[NOTE FOR PM]` callouts |
| Rubric, §9 mitigations | "Esm reviews every authentication story" isn't a requirement |
| A-7 (design) | Passkey autofill and device-bound fallback unplaced |
| H-8 | Admin invite has a screen, but no email template or Deployment-level email provider |
| B-7 | FR-49 has no screen in §7.3, and the Compliance page is unplaced |
| B-14 | Deployment Log view and the design's audit tab not in §7.3 |
| D-4 | Tenant name uniqueness undecided |
| D-13 | Design's JWKS sample and expiry banner not in §7.3 |
| C6 (decisions) | Quarterly rehearsal, 30-minute target and Never/Always options remain untagged |
| L5.2 (decisions) | Restore is Deployment-wide, so recovering one Tenant rolls back all |
| SEC-33 | Remainder is V-6 |

**Low:** design items A-16, A-17, A-18, A-19, A-21, A-22, A-24, A-25, A-26, A-27, C-6 and C-9 (partial or unplaced details, for `bmad-ux`), and one rubric item: "Developers" and "RBAC" are used without glossary entries.
