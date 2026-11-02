---
title: 'Story 1.12: Document installation'
type: 'chore'
created: '2026-11-02'
status: 'done'
baseline_revision: '297d0407634765a44debd23b0b3e0dff5301374e'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/docs/install.md'
  - '{project-root}/docs/threat-model.md'
warnings: []
deferred: []
---

<intent-contract>

## Intent

**Problem:** Story 1.12 needs install docs that let the Operator install using the documentation alone. They must cover wildcard DNS and TLS, the dedicated zone, CAA records and a validation-only DNS credential, and state the Docker host requirements: encrypted disks for volumes and the secrets directory, a firewall allowing only Caddy's ports, and that Docker access equals full control. `docs/install.md` (Stories 1.10 and 1.11) covers most of this, but never says the Tenant zone must be dedicated to Gatekeep (NFR-21), and nothing stops any of it from being dropped later.

**Approach:** Fill the gaps in `docs/install.md` and add an architecture test that fails when a required topic disappears from it.

## Boundaries & Constraints

**Always:**
- `docs/install.md` states that the Tenant zone is used only by Gatekeep. No application, mail or other host may live under it, because the wildcard certificate covers every name there. The validation-only zone also holds nothing else.
- It keeps covering:
  - wildcard DNS (`*.{zone}` record);
  - TLS (both modes);
  - CAA records, including `issuewild`;
  - the validation-only DNS credential (zone-scoped token, delivery as a secret);
  - every Docker host requirement in the table (encrypted disks for volumes and the secrets directory, a firewall allowing only Caddy's ports, Docker access equals full control).
- It names what the docs can't yet deliver and which story owns each item:
  - a working Admin Dashboard after install (Stories 1.21–1.25);
  - Certificate Transparency alerts (Epic 11);
  - emergency certificate replacement (Story 13.6);
  - backups and upgrades (Epic 12).
- `tests/Architecture/InstallDocTests.cs` asserts each required topic is present, by heading or key phrase, so removing one fails the build. It has a detection test on altered text.
- The existing `DockerOnlyRuleTests` keep passing: only `docker` and `git` commands.

**Never:**
- No new runtime behaviour, Compose change or script.
- No claim that an install reaches a working Admin Dashboard today.

</intent-contract>

## Code Map

- `docs/install.md` -- sections: "What the Docker host must provide", "Steps", "Hostnames and TLS" (with "TLS modes", "Cloudflare DNS for production" and "What Caddy doesn't do yet"), "Changing a database password", "What the stack enforces", "When it doesn't start" and "Not yet covered".
- `tests/Architecture/DockerOnlyRuleTests.cs` -- pattern for reading `docs/` from Architecture tests.
- `docs/threat-model.md` -- NFR-21 and T-35 (wildcard key), the DNS token row.
- Verification runs only in Docker.

## Tasks & Acceptance

**Execution:**
- [x] `docs/install.md` -- add the dedicated-zone rule, and the "can't yet" list with owning stories.
- [x] `tests/Architecture/InstallDocTests.cs` -- the topic checks and a detection test.

**Acceptance Criteria:**
- Given the install docs, when they're reviewed, then they cover wildcard DNS and TLS, the dedicated zone, CAA records and a validation-only DNS credential.
- Given the install docs, when they're reviewed, then they state the Docker host requirements: encrypted disks for volumes and the secrets directory, a firewall allowing only Caddy's ports, and that Docker access equals full control of Gatekeep.
- Given a required topic removed from the install docs, when the architecture tests run, then they fail naming the topic.

## Spec Change Log

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 21 findings — high 0, medium 8, low 11, false 2, maybe-false 0
- findings:
  - `[false]` `[reject]` Intent: the test checks text, not whether the guide is adequate — the intent's approach is a presence guard; adequacy is the review's job.
  - `[low]` `[patch]` Intent: the wildcard topic pins an example literal, not the instruction — anchored to the A-record sentence.
  - `[low]` `[patch]` Intent: host-requirement rows are pinned by separate topics, and a reworded row may pass — altered-text cases added for each row's topic.
  - `[low]` `[patch]` Intent: the removal test proves only its own patterns — replaced with altered-text cases.
  - `[low]` `[reject]` Intent: nothing tests that no working-Dashboard claim is added — the disclaimer is pinned; a claim added later would be caught in review, and a negative text test is brittle.
  - `[false]` `[reject]` Intent: the Docker-only rule isn't exercised by the new test — `DockerOnlyRuleTests` already runs over `docs/` and passes.
  - `[low]` `[reject]` Intent: the `JobRunnerTests` fix is outside the story — it's a separate commit fixing a flaky test found while verifying.
  - `[medium]` `[patch]` Edge: the flaky-test fix hides the real error if the runner ends before the body starts — awaits whichever finishes first.
  - `[medium]` `[patch]` Edge: the ZeroSSL CAA lines aren't pinned, so deleting them would block the fallback CA silently — pinned.
  - `[low]` `[patch]` Edge: the wildcard topic matches any mention of the example name — anchored to the A-record instruction.
  - `[low]` `[patch]` Edge: "the zone itself included" isn't pinned — pinned.
  - `[low]` `[patch]` Blind: the intro sentence is garbled — split.
  - `[medium]` `[patch]` Blind: the dedicated-zone rule doesn't define "zone" or address the parent domain's cookies — both stated, with the `__Host-` note.
  - `[low]` `[patch]` Blind: the rule sits away from the DNS steps — reminder added at step 1.
  - `[medium]` `[patch]` Blind: CAA topic misses ZeroSSL and `iodef` — same fix as the Edge row, plus `iodef`.
  - `[medium]` `[patch]` Blind: the DNS-credential topic misses `Zone : Zone : Read`, the token file's owner and mode, "DNS only" and no `AAAA` — pinned.
  - `[low]` `[patch]` Blind: example literals pinned instead of instructions, and the Admin-outside-zone rule unguarded — anchored, and a topic added.
  - `[low]` `[patch]` Blind: the removal test is true by construction — same fix as the Intent row.
  - `[medium]` `[patch]` Blind: "Not yet covered" omits client addresses, IPv6 and unproven `cloudflare` mode — added.
  - `[medium]` `[patch]` Blind: no interim guidance for CT watching or emergency certificate replacement — how and which names, and a stopgap, added.
  - `[medium]` `[patch]` Blind: the `JobRunnerTests` fix can hide real failures — same fix as the Edge row; it stays its own commit.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: build with no warnings; Architecture and Isolation all pass.

## Auto Run Result

Status: done

**Summary:** `docs/install.md` now states that the Tenant zone is used only by Gatekeep and what "zone" means for the parent domain's cookies. It lists what an install can't deliver yet and who owns each item, with interim guidance for CT watching and emergency certificate replacement. A new architecture test fails when any required topic leaves the guide. A separate commit fixes a flaky Story 1.8 job-runner test.

**Files:** `docs/install.md`; `tests/Architecture/InstallDocTests.cs`; `tests/Isolation/Jobs/JobRunnerTests.cs` (separate commit).

**Review:** 21 findings across four layers: 17 patched, 0 deferred, 4 rejected, each with its reason in the triage log.

**Follow-up review:** not recommended. The patches are doc text and test patterns, each checked by the new altered-text cases.

**Verification:** see the PR screenshot; the full suite passes in the `tests` container.

**Residual risks:** the guide is checked for topics, not completeness. An install still can't reach a working Admin Dashboard (Stories 1.21 to 1.25).
