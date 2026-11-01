---
title: Gatekeep Sprint Change Proposal
status: approved
date: 2026-11-02
scope: Moderate
trigger: _bmad-output/planning-artifacts/implementation-readiness.md
---

# Sprint Change Proposal: Readiness Gaps

## 1. Issue Summary

The readiness gate returned CONCERNS on 2026-11-02. Seven gaps in the plan would force a developer to invent decisions. No code exists yet, so no story has been affected. The evidence for each gap is in `implementation-readiness.md`.

The forced-reset UX was designed separately through `bmad-ux`. This proposal carries that design into the stories, and closes the other six gaps.

## 2. Impact Analysis

- **Epics:** All 18 stay, in the same order. Epics 1, 2, 3, 5, 7, 8, 10, 11, 12, 13 and 14 change.
- **Stories:** One story is added (10.8), making 174. Nineteen stories change.
- **PRD:** Three small edits. MVP scope is unchanged.
- **Architecture:** AD-2, AD-11, AD-17, AD-27, AD-30 and AD-31 change. One table is added.
- **UX:** One Validation Rules row changes.
- **Technical:** None yet, because nothing is built.

Story 10.8 sits in Epic 10 so that it ships before Story 12.4 and Story 13.1 rely on it. That avoids a new forward dependency. Its social and email code cases use a pending list, which Stories 14.2, 14.3 and 14.6 close.

## 3. Recommended Approach

**Direct adjustment.** Rollback doesn't apply, and no MVP review is needed.

- **Effort:** Low. These are document edits only. They add one story and a few acceptance criteria to the build.
- **Risk:** Low.
- **Timeline:** No meaningful change.

### Decisions by Esm

- Admin enrolments live in a new `admin_enrolment` table.
- User data export is a direct download that stores nothing.
- Signing Key maximum age, client secret overlap and Log retention are constants at their §5.2 defaults.

### Calls made while drafting

Please check these in review:

1. **Admin "Reset credentials" lifetime:** uses the §5.2 credential enrolment link lifetime of 24 hours, because it's passed on by hand. `gatekeep recover-admin` keeps its 15 minutes from AD-31.
2. **Decrypt-rate alerts:** go in Story 11.2. The audit device's off-server output goes in Story 1.30, because the off-server store doesn't exist until then.
3. **Mid-session states:** Tenant deleted goes in Story 1.29, and role removed goes in Story 8.4, because those stories build the actions that cause them.

## 4. Detailed Change Proposals

### Gap 1: Forced reset

#### New story, after Story 10.7

```markdown
### Story 10.8: Replace a flagged credential at sign-in

As a User whose credential must be replaced,
I want to prove myself and set a new one before I'm signed in,
So that anything taken in an incident stops working, and an attacker can't do this for me.

**Requirements:** FR-50, FR-4, FR-25, FR-26, FR-48, NFR-20; AD-17, AD-30
**Screens:** Password reset required, Authenticator reset required (both Spec only); TOTP · scan QR (L159), Reset password (L242), Password changed (L252) in `Gatekeep Hosted Login.dc.html`

**Acceptance Criteria:**

**Given** `user.password_reset_required` and `user.totp_reset_required`
**When** this story ships
**Then** both columns exist, and either one stops a Session being issued until it's cleared

**Given** a User with `password_reset_required` and a correct password
**When** they submit it
**Then** Password reset required shows, offering each enrolled proof plus "Email me a reset link", and no Session or token exists

**Given** an incorrect password or an unknown account
**When** it's submitted
**Then** the response is the usual generic failure, so the screen shows only after valid credentials

**Given** a verified proof
**When** the User sets a new password that passes policy and breach checks
**Then** the requirement clears, `RevokeAccess` runs, a notification is sent, and sign-in continues

**Given** the reset link
**When** it's used, or any other reset completes, including Forgot password
**Then** the requirement clears, and the flow ends at Password changed with no Session

**Given** a User with `totp_reset_required` past the first factor
**When** Authenticator reset required shows
**Then** the old TOTP code, a Recovery Code or another enrolled Factor is accepted once, only to reach TOTP setup, and email is never offered

**Given** a new TOTP seed
**When** it's confirmed
**Then** the old seed stops working, the requirement clears, and Recovery Codes aren't reissued

**Given** proof already given in this sign-in, or a Passkey sign-in
**When** the next required step starts
**Then** no further proof is asked for

**Given** a User holding neither credential
**When** a flag would be set
**Then** it isn't, and that User sees no step

**Given** social and email code sign-in
**When** this story ships
**Then** they're on a code-owned pending list that Story 14.2, Story 14.3 and Story 14.6 close

**Given** the FR-25 matrix
**When** it runs
**Then** both steps are registered, and each ends with a verified second factor or an FR-27 Recovery Code

**Given** repeated failed proof
**When** the limit is passed
**Then** the existing per-step backoff applies, and the Log is written
```

#### Story 12.4

OLD:

```markdown
**Given** a replayed password change
**When** it applies
**Then** it sets `credential_reset_required`
```

NEW:

```markdown
**Given** a replayed password change
**When** it applies
**Then** it sets `password_reset_required`
```

OLD:

```markdown
**Given** `credential_reset_required` on a User
**When** they sign in
**Then** Authentication requires the step before any Session
```

NEW:

```markdown
**Given** `password_reset_required` on a User whose newer password no longer works
**When** they use Forgot password
**Then** the reset clears the requirement, as Story 10.8 specifies
```

#### Story 13.1

OLD:

```markdown
**Then** `credential_reset_required` is set on each User, which Authentication already enforces
```

NEW:

```markdown
**Then** `password_reset_required` and `totp_reset_required` are set on each User holding that credential, and Story 10.8 enforces them
```

#### Stories 14.2, 14.3 and 14.6

Add to each:

```markdown
**Given** a User with a reset requirement
**When** this sign-in succeeds
**Then** the Story 10.8 proof step applies before any Session, and this path leaves its pending list
```

#### PRD §7.2

OLD:

```markdown
- **Protection:** blocked account, account locked, breached password check.
```

NEW:

```markdown
- **Protection:** blocked account, account locked, breached password check, password reset required, authenticator reset required.
```

#### Architecture AD-17

OLD: `A replayed password change sets `credential_reset_required`, because the old hash has returned.`

NEW: `A replayed password change sets `password_reset_required`, because the old hash has returned.`

#### Architecture AD-30

OLD: `Forced password reset and TOTP re-enrolment set `credential_reset_required` on the User, which Authentication turns into a required step before any Session is issued.`

NEW: `Forced password reset and TOTP re-enrolment set `password_reset_required` and `totp_reset_required` on each User holding that credential, which Authentication turns into required steps before any Session is issued. They're separate because a reset link clears only the first. EXPERIENCE specifies the proof each step accepts.`

### Gap 2: Admin enrolment storage

#### Architecture AD-27, Admins row

OLD: `` `admin_invite`, `admin_attempt` ``

NEW: `` `admin_invite`, `admin_enrolment`, `admin_attempt` ``

#### Architecture AD-31

Add at the end:

```markdown
  - Single-use Admin enrolments from `gatekeep recover-admin` and "Reset credentials" live in the `admin_enrolment` `control` table, which holds the Admin ID, a SHA-256 of the value, an expiry and a used time. A "Reset credentials" enrolment lasts for the §5.2 credential enrolment link lifetime and is returned through `RevealOnce`.
```

Add the new response to the code-listed set in AD-24, which already covers "the credential enrolment link".

#### Story 1.32

Add `**Creates tables:** `admin_enrolment``, and add:

```markdown
**Given** an issued enrolment
**When** it's stored
**Then** only its SHA-256, expiry and used time are in `admin_enrolment`, and the raw value appears in no log or Audit event
```

#### Story 8.4

OLD: `**Then** a single-use enrolment is issued, and the Deployment Log is written`

NEW: `**Then** a single-use enrolment is shown once through `RevealOnce`, stored only hashed in `admin_enrolment` with the §5.2 lifetime, and the Deployment Log is written`

### Gap 3: Key-custody and disk controls

#### Story 1.7

Add:

```markdown
**Given** the Master Key and recovery keys
**When** the first setup follows `docs/`
**Then** an offline escrow copy is stored apart from backups, and none of it appears in `docs/`, a log or a backup
```

#### Story 1.10

Add `AR-20, AD-10` to Requirements, and add:

```markdown
**Given** the OpenBao and PostgreSQL data
**When** the install is checked
**Then** both sit on LUKS volumes, and a test fails on an unencrypted mount
```

#### Story 1.30

Add `AD-10` to Requirements, and add:

```markdown
**Given** the OpenBao audit device
**When** a Transit operation runs
**Then** its record reaches off-server storage, and holds no key material or plaintext
```

#### Story 11.2

Add `AD-10` to Requirements, and add:

```markdown
**Given** a decrypt rate above threshold for one host
**When** it's detected from the OpenBao audit output
**Then** an alert fires
```

### Gap 4: User data export

#### Story 5.8

Change Requirements to `FR-49, NFR-14`.

OLD:

```markdown
**Given** an export
**When** it starts
**Then** it runs as an Operation
```

NEW:

```markdown
**Given** an export
**When** it's requested
**Then** `Host.Admin` builds it during the request and streams it with `no-store`, and no copy is kept on the server
```

#### Architecture AD-30

Add:

```markdown
  - A User data export (FR-49) isn't an Operation. `Host.Admin` builds it during the request, through Management's existing edges, and streams it. No copy is stored.
```

### Gap 5: Constants

#### PRD §5.2

Add after the table:

```markdown
v1 has no setting for Signing Key maximum age, client secret overlap or Log retention. Each is fixed at its default, and only a release can change it, within the hard limit.
```

#### PRD NFR-15 and the epics inventory

OLD (PRD): `Logs have the retention in §5.2. Any change is logged, and the floor can't be lowered.`

NEW (PRD): `Logs have the retention in §5.2, fixed in v1. The floor can't be lowered.`

OLD (epics): `NFR-15: Logs have the §5.2 retention, any change is logged, and the floor can't be lowered.`

NEW (epics): `NFR-15: Logs have the §5.2 retention, fixed in v1, and the floor can't be lowered.`

#### Architecture AD-11

OLD: `A daily job rotates any key within 30 days of the Tenant's maximum age.`

NEW: `A daily job rotates any key within 30 days of the §5.2 maximum age.`

#### Story 2.4

OLD: `**Given** a key within 30 days of the Tenant's maximum age`

NEW: `**Given** a key within 30 days of the §5.2 maximum age`

#### Story 3.3

OLD: `the old secret stays valid for the configured overlap within §5.2`

NEW: `the old secret stays valid for the §5.2 default overlap`

#### Story 7.3

OLD:

```markdown
**Given** a Prod Tenant
**When** retention would go below 90 days
**Then** it's refused, and any change is logged
```

NEW:

```markdown
**Given** the retention constant
**When** a test reads it
**Then** it meets the §5.2 floor, and no route, setting or Cli command changes it
```

#### EXPERIENCE Validation Rules

OLD: `| Any lifetime, threshold, overlap or retention | Bounded by the §5.2 hard limit. Thresholds can't be off. Password minimum can only be raised. Log retention floor can't be lowered. |`

NEW: `| Any lifetime or threshold | Bounded by the §5.2 hard limit. Thresholds can't be off. Password minimum can only be raised. |`

### Gap 6: Untested UX states

#### Story 1.25

Add:

```markdown
**Given** an expired Admin session with unsaved values
**When** the Admin next acts
**Then** the WebAuthn sheet appears with a `banner` explaining why, and the values remain
```

#### Story 1.28

Add `FR-44` to Requirements, and add:

```markdown
**Given** a Deployment Owner holding no Tenant Role
**When** they land
**Then** Tenants opens

**Given** any other Admin with no Tenant Role
**When** they land
**Then** "You don't have access to a Tenant yet. Ask a Deployment Owner." shows
```

#### Story 1.29

Add `UX-DR22` to Requirements, and add:

```markdown
**Given** an Admin working in a Tenant that's been deleted
**When** their next request arrives
**Then** they return to the landing page with a `banner`
```

#### Story 8.4

Add `UX-DR22` to Requirements, and add:

```markdown
**Given** an Admin whose Tenant Role was removed mid-session
**When** their next request arrives
**Then** they return to the landing page with a `banner`
```

### Gap 7: Grant enforcement

#### Story 3.2

Add:

```markdown
**Given** a grant type turned off for an Application
**When** that client attempts it
**Then** the authorization or token endpoint refuses it
```

### Architecture AD-2

Add after the `user.blocked_at` rule:

```markdown
`user.password_reset_required` and `user.totp_reset_required` are set only by `gk_worker` and `gk_cli`. `gk_hosted` may only clear them.
```

## 5. Implementation Handoff

**Scope: Moderate.** The backlog changes, but the plan doesn't need a replan.

- **Developer agent:** Apply the approved edits to `prd.md`, `ARCHITECTURE-SPINE.md`, `EXPERIENCE.md` and `epics.md`, then mark the gaps closed in `implementation-readiness.md`.
- **Esm:** Rerun `bmad-sprint-planning` to repeat the gate and generate `sprint-status.yaml`. There's no status file to update before then.

**Success criteria:**

- `credential_reset_required` no longer appears in any planning document, and `implementation-readiness.md` still records it as history.
- The gate returns PASS, and the generator reports 18 epics and 174 stories.
