---
title: 'Story 1.2: Prove key custody on the target host'
type: 'chore'
created: '2026-11-02'
status: 'done'
route: 'oneshot'
review_loop_iteration: 0
baseline_commit: 'e4221a282317b04ea1bda88f2822a0484392f4c3'
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-1-context.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** AD-10's custody chain has never been tested on Linux with systemd and a TPM, and Stories 1.7 and 1.10 depend on it. The design must be settled before anything builds on it.

**Approach:** Esm decided that no rehearsal host is available, so this story records the fallback rather than running the spike. Record all seven proofs as `not-run` with the reason in `docs/spikes/1-2-key-custody.md`, set the root-only key file on a separate volume as the design, marked as a weaker control, and amend AD-10. No proof may be reported as passed, and the docs contain no key material, token or unseal value.

</frozen-after-approval>

## Implementation Notes

- **Files:** `docs/spikes/1-2-key-custody.md`, AD-10 and two Open Items rows in `ARCHITECTURE-SPINE.md`, AR-1, AR-20, AR-42 and Story 1.2 in `epics.md`, `implementation-readiness.md`, `deferred-work.md` and `sprint-status.yaml`.
- **LUKS decision.** Esm chose a passphrase at boot, giving up unattended restart. The volumes and the NFR-10 cost are recorded in AD-10 and the spike doc.
- **`not-run` rather than `fail`.** The story says pass or fail, but nothing ran, so `not-run` is the honest record. The fallback branch of the story covers the outcome.
- **Scope of the fallback.** It settles where the key lives, but not the Linux work: Stories 1.7 and 1.10 still need a Linux host.

## Review Triage Log

- medium, patch: LUKS unlock undecided. Esm chose a passphrase at boot; AD-10 and the threat table updated.
- medium, patch: stolen disk claim dropped its condition in AD-10. Condition restored.
- medium, patch: loss of the static seal's root of trust wasn't stated. Stated in AD-10 and the spike doc.
- medium, patch: seal key and barrier key were named inconsistently. The file is now defined as the static seal key, which AD-10 calls the Master Key.
- medium, defer: key file handoff to the non-root service is undecided. Needs a design choice in Story 1.7.
- medium, defer: rotation, restore and `gatekeep rekey` assumed the TPM design.
- medium, patch: AR-1, AR-42 and the readiness note contradicted the amendment. All three amended.
- medium, patch: Story 1.2's criteria didn't cover a spike that never ran. A `not-run` criterion was added.
- medium, defer: five proofs need only Linux, so a plain Linux VM could run them. Moved to Stories 1.7 and 1.10.
- medium, defer: deferred proofs and the TPM design had no owner. Four deferred entries added.
- low, patch: the TPM column overstated whole-server protection. Corrected.
- low, reject: the spec lacks Tasks and Verification sections, which the one-shot route omits by design. The secret scan of the spike doc found nothing.
