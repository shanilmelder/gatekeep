---
title: 'Story 1.12: Document installation'
type: 'chore'
created: '2026-11-02'
status: 'ready-for-dev'
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
- [ ] `docs/install.md` -- add the dedicated-zone rule, and the "can't yet" list with owning stories.
- [ ] `tests/Architecture/InstallDocTests.cs` -- the topic checks and a detection test.

**Acceptance Criteria:**
- Given the install docs, when they're reviewed, then they cover wildcard DNS and TLS, the dedicated zone, CAA records and a validation-only DNS credential.
- Given the install docs, when they're reviewed, then they state the Docker host requirements: encrypted disks for volumes and the secrets directory, a firewall allowing only Caddy's ports, and that Docker access equals full control of Gatekeep.
- Given a required topic removed from the install docs, when the architecture tests run, then they fail naming the topic.

## Spec Change Log

## Review Triage Log

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: build with no warnings; Architecture and Isolation all pass.
