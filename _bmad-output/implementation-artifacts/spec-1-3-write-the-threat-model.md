---
title: 'Story 1.3: Write the threat model'
type: 'chore'
created: '2026-11-02'
status: 'done'
route: 'oneshot'
review_loop_iteration: 0
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-1-context.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** NFR-1 and AR-3 require a written threat model before authentication work starts, and none exists, so authentication stories have no named threats to build against.

**Approach:** Write `docs/threat-model.md` from AD-2's trust zones. It covers each zone, trust boundary and credential-equivalent value, and every PRD §9 risk, and its update rule requires any later work that changes a trust boundary to change the document in the same work. It states the design as amended by Story 1.2, describes planned controls as planned, and claims nothing as built or tested that isn't.

</frozen-after-approval>

## Implementation Notes

- **Files:** `docs/threat-model.md`, `.github/pull_request_template.md`, `epic-1-context.md`, `deferred-work.md`, `sprint-status.yaml`.
- **Epic context:** recompiled because the Story 1.2 amendments had made it stale. Those edits are catch-up, not Story 1.3 scope.
- **Zones:** AD-2 defines three. Z-4 to Z-9 were added because boundaries to data, the host, off-server stores and the edge can't be stated without them.
- **Gaps:** what the spine and epics leave open is recorded as `G-n` in the document, not resolved there. Nothing in the document claims a built or tested control beyond Story 1.1.

## Review Triage Log

- high, patch: T-27 and the Z-1 row implied compromise ends at eviction. Added What survives eviction, and corrected T-27.
- medium, patch: T-27 cited decrypt alerts for forgery, which uses sign calls. Corrected, and added G-11.
- medium, patch: TB-3 said no path, but stored data crosses the shared database. Corrected, and added T-37.
- medium, patch: Caddy and the VPN endpoint had no place. Added Z-9, an attacker row and G-13.
- medium, patch: zone-taken table omitted OpenBao, Z-7, Z-8 and database write access, and understated Z-2 and Z-3. Table rewritten, with T-44 for offline cracking.
- medium, patch: TB-10 overclaimed against Z-3 and Z-5, which can sign. Stated in TB-10, T-31 and T-33.
- medium, patch: "no third-party code" was false, given React and the QR encoder. Reworded in TB-15, T-15 and T-17.
- medium, patch: physical analysis was unclear. T-30 reworded, and G-14 added.
- medium, patch: core protocol and leakage threats had no number. Added T-38 to T-43.
- medium, patch: credential inventory claimed completeness and had omissions. Rows added and the claim softened.
- medium, patch: status had no home, and "None known" read as cleared. Rows now take a test name, and the wording is "None identified".
- medium, patch: update rule missed TB-13 to TB-15, and nothing surfaced it. Triggers added, plus a pull request template.
- medium, patch: residuals had no owner. G-15 added; acceptance is Esm's decision.
- medium, defer: gaps have no story criteria, because that needs epic edits.
- low, patch: PRD §9 mapping was loose. Three rows corrected.
- low, patch: spec notes and triage log were empty, and the epic context didn't carry the update rule. Both added.
- low, defer: the spine's Deferred entry still lists the threat model as pending.
- low, reject: spec `context` omits the spine and PRD. The spec is finished and nothing resumes from it.
