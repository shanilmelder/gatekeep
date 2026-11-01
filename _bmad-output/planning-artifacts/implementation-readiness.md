---
title: Gatekeep Implementation Readiness
status: resolved
verdict: CONCERNS
date: 2026-11-02
assessed:
  - _bmad-output/planning-artifacts/epics.md
  - _bmad-output/planning-artifacts/prds/prd-gatekeep-2026-11-01/prd.md
  - _bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md
  - _bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md
---

# Gatekeep Implementation Readiness

**Verdict: CONCERNS.** The plan is sound overall, but seven gaps would force a developer to invent decisions. Esm chose to fix them before generating `sprint-status.yaml`.

**Resolved on 2026-11-02.** All seven gaps were closed by `sprint-change-proposal-2026-11-02.md`. Rerun `bmad-sprint-planning` to repeat the gate.

## What passed

- All 173 stories in 18 epics have Requirements, Screens and acceptance criteria.
- Every FR, NFR, UX-DR and AR is cited by a story, and all 50 FRs are mapped to an epic.
- All AD-27 tables have a creator story, in dependency order.
- Forward references are explicit, using pending lists that Story 18.1 requires to be empty.
- No unresolved placeholders remain in `epics.md`.
- The generator's dry run parsed 18 epics and 173 stories. Its two warnings are harmless: they're the document title and the `## Epic List` heading.

## Gaps to fix

Ordered by severity.

### 1. The forced-reset sign-in step isn't designed

- **Where:** Stories 12.4 and 13.1 (both "Screens: None"), AD-17, AD-30, EXPERIENCE
- **Gap:** `credential_reset_required` must become a required step before any Session, but no screen or state exists for it. Story 13.1 says Authentication "already enforces" it, and only Story 12.4 mentions that enforcement, in one line.
- **Undecided:**
  - How a User proves identity when their password may be the compromised credential. A replayed password change sets this flag because the old hash has returned.
  - How forced TOTP re-enrolment proceeds, and how it relates to the Enrolment email check.
- **Fix:** `bmad-ux`, then add or extend a story with a named screen.
- **Status:** UX designed on 2026-11-02: Password reset required, Authenticator reset required and Flow 15 in EXPERIENCE. Still open for `bmad-correct-course`:
  - Add or extend a story, and name both screens in it.
  - Split `credential_reset_required` into password and TOTP parts (AD-17, AD-30).
  - Add both screens to PRD §7.2.

### 2. Admin enrolment has nowhere to be stored

- **Where:** Stories 1.32 and 8.4, AD-27, AD-31
- **Gap:** `gatekeep recover-admin` and "Reset credentials" both issue a single-use enrolment. AD-27 lists no store for it, and `admin_invite` doesn't exist until Story 8.2, after Story 1.32 needs it. `one_time_token` belongs to Identity and is a `tenant` table, so it can't serve Admins.
- **Fix:** Amend AD-27 and AD-31, then name the table in Story 1.32.

### 3. Three key-custody and disk controls have no acceptance criteria

- **Where:** AD-10, AD-26; should sit in Stories 1.7 and 1.10
- **Gap:**
  - The OpenBao audit device, its off-server output and per-host decrypt-rate alerts appear in no story.
  - LUKS volumes are mentioned only in the requirements inventory (AR-20, AR-34), with no acceptance criterion.
  - The first offline escrow of the Master Key and recovery keys has no acceptance criterion. Later stories assume it exists (12.2, 12.7, 18.11).
- **Fix:** `bmad-correct-course`, adding criteria to Stories 1.7 and 1.10.

### 4. User data export has no home for its output

- **Where:** Story 5.8, AD-27, AD-30
- **Gap:** The export runs as an Operation and EXPERIENCE says it downloads, but `operation_step` can't hold personal data and no file store, download route or expiry is recorded.
- **Fix:** Amend the architecture, then update Story 5.8.

### 5. Three values have no setting

- **Where:** Stories 2.4, 3.3 and 7.3, PRD §5.2, NFR-15
- **Gap:** "The Tenant's maximum age", the "configured overlap" and Log retention changes have no field, screen or capability.
- **Fix:** Decide whether each is a Tenant setting or a Deployment constant. A setting needs a screen, a capability and a Log event.

### 6. Some UX states are cited but not tested

- **Where:** Stories 1.25 and 1.28, UX-DR22, EXPERIENCE line 56
- **Gap:** Tenant deleted mid-session and session expired with values kept have no acceptance criteria. No story covers landing for a Deployment Owner or other Admin with no Tenant Role.
- **Fix:** Add acceptance criteria to Stories 1.25 and 1.28.

### 7. Grant toggles aren't enforced by any test

- **Where:** Story 3.2, FR-13
- **Gap:** Story 3.2 only checks which grant options render. No criterion says the token endpoint refuses a grant that's switched off for an Application.
- **Fix:** Add an acceptance criterion to Story 3.2.

## Outside prerequisites

These don't affect the verdict, but Epic 1 can't finish without them.

- A Linux host, still unconfirmed (AR-42), for Stories 1.7 and 1.10. A TPM2 is needed only to adopt the TPM design, because Story 1.2 applied the fallback.
- A dedicated DNS zone and a VPN.
- An Object Lock bucket and an independent alert channel for Story 1.30.

## Next step

After the gaps are fixed, rerun `bmad-sprint-planning` to repeat the gate and generate `sprint-status.yaml`.
