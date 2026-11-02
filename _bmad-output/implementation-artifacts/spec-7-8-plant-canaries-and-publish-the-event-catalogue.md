---
title: 'Story 7.8: Plant canaries and publish the event catalogue'
type: 'feature'
created: '2026-11-02'
status: 'done'
baseline_commit: '97ea8dc846c09884b634a6dcb4b670ae13a0daa0'
baseline_revision: '97ea8dc846c09884b634a6dcb4b670ae13a0daa0'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-7-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-6-scrub-logs-and-scan-for-canaries.md'
  - '{project-root}/docs/threat-model.md'
warnings:
  - oversized
  - multiple-goals
deferred:
  - summary: >-
      The canary scan doesn't read the PostgreSQL server log.
    evidence: |-
      Refused logins and failed statements in the forced-failure runs can be logged by the server, which the scan never captures. Unverified whether any planted value reaches it: settle by capturing the test PostgreSQL container's log after each flow and scanning it as another source.
    location: >-
      tests/Isolation/Canary/CanaryScanner.cs
    severity: medium (unverified)
---

<intent-contract>

## Intent

**Problem:** The Story 1.6 canary scan covers five fixed values sent through the sink and the appender, not each flow. Nothing fails the build when a new flow skips a canary. Audit type codes are scattered string literals with no published catalogue. Nothing ties FR-40 event classes to the events that prove them (NFR-3, AR-33, AR-39, AD-16, AD-24, T-42).

**Approach:** Add a code-owned canary flow registry in the Isolation tests. Every production surface (job type, Operation type, Cli command, host startup) must have a canary flow, or a reviewed reason it handles no credential-equivalent value. Each flow plants canaries and runs both normally and forced to fail with debug logging on. The scan then covers the four audit tables, every database table and the captured operational logs, error output and responses. Move audit codes into per-module catalogues, and generate `docs/audit-events.md` from them. Map every FR-40 event class to a catalogued code proved by a test, or to a pending story.

## Boundaries & Constraints

**Always:**
- A finding names the canary kind and the source, never the value.
- Each module declares its audit codes in its own contract. No `new AuditTypeCode("…")` literal appears outside a catalogue.
- A published code that is removed or renamed fails as a contract break. A new code fails until `docs/audit-events.md` is regenerated.
- A pending FR-40 class names a story ID that exists in `sprint-status.yaml` and isn't `done`. A pending class whose story is `done` fails the build.
- The canary scan and the catalogue tests run in the Architecture and Isolation suites, which CI and the release workflow already run, so they are release gates.

**Never:**
- No new production flow, endpoint or event class only to give a canary somewhere to go.
- No third-party package. No claim that the scrubber catches an arbitrary plain string.
- No change to the hash envelope or to any already-published code's spelling.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Clean flows | Every registered flow run, normally and failing at Debug | Scan finds nothing in audit tables, any table, logs, stderr or responses | N/A |
| Raw hit | A test flow writes a canary straight to a table or log | Scan names the source and kind; test fails | Build fails |
| Unregistered surface | A job type, Operation type or Cli command with no flow and no reviewed reason | Rule test names it | Build fails |
| Bearer in User-Agent | Appender gets `Bearer <canary>` as User-Agent | `audit_detail.user_agent` holds the mask, not the value | N/A |
| Code removed | A catalogued code no longer declared | Catalogue test names it as a contract break | Build fails |
| Code added | Declared code missing from `docs/audit-events.md` | Test says to regenerate | Build fails |
| Stray literal | `new AuditTypeCode("x.y.z")` outside a catalogue | Rule test names the file | Build fails |
| Class pending, story done | A pending class whose story is `done` | Test names the class and story | Build fails |
| Class proved | A class mapped to a code | A test runs its flow and finds that code in the Tenant's Log | N/A |

</intent-contract>

## Code Map

- `tests/Isolation/Canary/CanaryScanner.cs` -- canaries, `Scan`, `AuditTables`, `ThrowIfFound`. Extend with a whole-database source: every table's rows as JSON, read as superuser.
- `tests/Isolation/Canary/CanaryScanTests.cs` -- the Story 1.6 scan to build on.
- `src/Adapters/Logging/Scrubber.cs:10` -- shape matching (`Scrub`, `IsSensitiveName`, `Mask`). Move the pure shape matching into `src/Gatekeep.Kernel/Secrets/CredentialShapes.cs` (no package), and have the Scrubber use it.
- `src/Modules/Audit/Adapters/AuditAppender.cs` -- stores `user_agent` raw. This is the Story 1.6 deferred item. Mask credential shapes with `CredentialShapes` before storing.
- `src/Modules/Operations/Core/JobRunner.cs:74` -- `operations.job.dead` literal. `src/Modules/Audit/Core/AuditRetention.cs:20` -- `audit.retention.checkpoint`. These are the only production codes today.
- `src/Gatekeep.Kernel/Audit/AuditTypeCode.cs` -- the code type. Add a Kernel `AuditEventAttribute` or catalogue record (code, summary, FR-40 class or none) that modules use in their contracts.
- `src/Modules/Operations/Contracts/OperationsContract.cs` (`ProductionRegistry`, `ProductionOperationRegistry`), `src/Gatekeep.Cli/Program.cs` (the `args switch`) -- the surfaces the rule enumerates.
- `tests/Isolation/CliProcess.cs`, `tests/Isolation/Hosting/HostProcess.cs`, `tests/Isolation/Scrubbing/MemorySink.cs`, `tests/Isolation/Jobs/JobTestSupport.cs` -- run Cli and host processes, capture logs and run jobs.
- `tests/Architecture/Generator/Program.cs`, `EdgeList.cs` -- the generator writes the module diagram. Add the catalogue render here, so one command regenerates both.
- `tests/Architecture/PersistenceRuleTests.cs`, `RetentionRuleTests.cs` -- source-scan rule patterns.
- `_bmad-output/implementation-artifacts/sprint-status.yaml` -- story statuses the pending test reads, keys like `16-8-…`.
- `.github/workflows/ci.yml`, `release.yml` -- both run `compose.test.yaml run tests`, so the gate needs no workflow change.
- `docs/threat-model.md` -- T-42 and the 1.6 deferred item.

## Tasks & Acceptance

**Execution:**
- [ ] `src/Gatekeep.Kernel/Secrets/CredentialShapes.cs`, `src/Adapters/Logging/Scrubber.cs` -- move the shape matching to Kernel, unchanged in behaviour. The Story 1.6 scrubbing tests must still pass.
- [ ] `src/Modules/Audit/Adapters/AuditAppender.cs` -- mask credential shapes in `user_agent` before insert.
- [ ] `src/Gatekeep.Kernel/Audit/AuditEventDefinition.cs` -- a record of code, one-line summary and optional FR-40 class.
- [ ] `src/Modules/Operations/Contracts/OperationsEvents.cs`, `src/Modules/Audit/Contracts/AuditEvents.cs` -- catalogues for `operations.job.dead` and `audit.retention.checkpoint`. Callers use them.
- [ ] `tests/Architecture/Generator/*`, `docs/audit-events.md` -- render a table of code, module, summary and FR-40 class, sorted by code, with a pending-classes section.
- [ ] `tests/Architecture/AuditCatalogueTests.cs` -- the committed doc equals the render, and every code in the doc is still declared (contract break). No `AuditTypeCode` literal appears outside catalogues. Every code matches `{domain}.{object}.{action}` and is unique.
- [ ] `tests/Isolation/Canary/CanaryFlows.cs`, `CanaryFlowTests.cs` -- a flow registry. Each flow has a name, the surfaces it covers, and normal and forced-failure runs at Debug or Trace, capturing logs, stderr, stdout and responses. Cover:
  - **Cli:** `migrate` and `audit verify`, with the canary as the password file and failing by an unreachable or refused database.
  - **Host startup:** each of the three hosts, with a canary password in a connection string, failing by an unreachable database, plus `/healthz`.
  - **Jobs:** a credential-carrying job payload through enqueue, run and dead.
  - **Key custody:** a canary through the `FakeOpenBaoSocket` failure path.
  - **Audit:** the appender with a canary-shaped User-Agent.
  
  After each run, scan all sources.
- [ ] `tests/Isolation/Canary/CanarySurfaceTests.cs` -- every job type, Operation type and Cli command must be covered by a flow, or listed in `NoCredentialSurfaces` with a reason and a reviewer and date. A surface in neither fails. So does a listed reason for a surface that no longer exists.
- [ ] `tests/Isolation/Audit/EventClassTests.cs` -- the 11 FR-40 Tenant classes, each mapped to a catalogued code proved by a test, or pending on a story: sign-ins and failures 4.9, password resets 4.11, email changes 16.8, Factor events 6.1, Recovery Code events 6.8, Session and token revocation 2.7, Admin changes 8.2, key operations 9.2, Management API grants 17.2, Token Family revocations 2.10, rejected cross-Tenant attempts 7.4. The test fails on a pending class whose story is `done` or missing.
- [ ] `docs/threat-model.md` -- T-42 and TB-6 built parts. Close the Story 1.6 deferred item.

**Acceptance Criteria:**
- Given CI, when the Architecture and Isolation suites run, then the canary flow, surface, catalogue and class tests all run and pass.
- Given a test that adds a fake job type to a copy of the production registry with no flow, when the surface check runs over it, then it reports that type.
- Given `docs/audit-events.md`, when the generator runs, then the file is unchanged.

## Spec Change Log

## Review Triage Log

### 2026-11-03 — Review pass
- verdicts: 41 findings — high 0, medium 9, low 23, false 5, maybe-false 4
- findings:
  - `[medium]` `[patch]` Intent: new HTTP endpoints aren't surfaces, so an endpoint on an existing host trips nothing — a Route surface kind scans `Map*` route literals; a fake route is reported.
  - `[low]` `[reject]` Intent: the custody and appender debug lines are written by the test — no production code logs on those paths yet, and the lines prove the scrubber the production sink uses.
  - `[maybe-false]` `[reject]` Intent: no FR-40 class is proved, including ones planned before Epic 7 — none of their flows exist. The done-story check forces each closure, and the Design Notes record it. It would be low if true.
  - `[false]` `[reject]` Intent: the catalogue is regenerated by hand, not by the build — the AC's "generated into `docs/`" holds with a drift check that fails the build.
  - `[false]` `[reject]` Intent: the CI and release gate isn't shown in the diff — `ci.yml` and `release.yml` already run both suites through `compose.test.yaml`.
  - `[false]` `[reject]` Intent: User-Agent masking is outside the ACs — it's the Story 1.6 deferred item and an NFR-3 leak the new scan would report.
  - `[low]` `[reject]` Blind: a hand edit to the doc can hide a removal — it needs two deliberate deletions, and the PR diff shows the removed row. Comparing against the base branch needs git in the test image.
  - `[medium]` `[patch]` Blind: the construction regex misses target-typed `new(…)` and assignments — replaced by a scan of code-shaped string literals.
  - `[low]` `[patch]` Blind: comment stripping eats `//` inside strings — dropped with the literal scan.
  - `[low]` `[patch]` Blind: catalogue members that aren't public static fields drop from the doc — reported as problems.
  - `[medium]` `[patch]` Blind: the SQL checkpoint literal and a second code source aren't tied to the catalogue — both point at `AuditEvents.RetentionCheckpoint`, and a test pins the migration literal.
  - `[low]` `[reject]` Blind: `email` is stored raw and has no canary — email is personal data held in detail by design (AD-16), not a credential.
  - `[medium]` `[patch]` Blind: no-credential reasons ignore `mayCarryCredential` — such a reason is now a problem.
  - `[low]` `[reject]` Blind: host flows never fail on custody — the custody flow covers the adapter's failure paths, and hosts start custody through the same adapter.
  - `[medium]` `[patch]` Blind: the plaintext canary never reaches the Transit error path — the failing run now fails the encrypt after a good login.
  - `[low]` `[reject]` Blind: hosts are killed, so shutdown logging isn't scanned — no host logs configuration on shutdown, and a graceful stop adds flake.
  - `[low]` `[patch]` Blind: the docs disagree on Debug versus Trace — comments say Trace.
  - `[low]` `[reject]` Blind: the empty proof runner is untested — it has no entry. The first proved class's own test exercises it.
  - `[low]` `[reject]` Blind: the catalogue has no chain or role column — not in the AC, and the codes are the contract.
  - `[maybe-false]` `[defer]` Blind: the scan skips the PostgreSQL server log — recorded in `deferred` as medium (unverified).
  - `[low]` `[reject]` Blind: summaries can hold Markdown — summaries are code-owned and reviewed. `|` and newlines, which break the table, are refused.
  - `[false]` `[reject]` Blind: the diff leaves out the spec and `sprint-status.yaml` — the review diff was cut to code and docs on purpose; both are committed at finalize.
  - `[medium]` `[patch]` Gap: the generator's refusal to drop a code is untested — moved into `AuditCatalogue.Regenerate`, with tests.
  - `[low]` `[patch]` Gap: the appender's failing run never sends the User-Agent — the failure is forced at the detail insert.
  - `[low]` `[patch]` Gap: Debug in two comments — same fix as the Blind row.
  - `[medium]` `[patch]` Edge: a property initializer escapes the scan — same fix as the literal-scan row.
  - `[medium]` `[patch]` Edge: a target-typed argument escapes the scan — same fix.
  - `[low]` `[patch]` Edge: `//` in a string hides code — same fix.
  - `[low]` `[patch]` Edge: property definitions drop from the doc — same fix as the Blind catalogue-member row.
  - `[low]` `[reject]` Edge: other `Assembly.Load` exceptions crash unhelpfully — the failure is still loud, in a developer tool.
  - `[medium]` `[patch]` Edge: a missing doc lets the generator publish with codes removed — `Regenerate` refuses a missing document.
  - `[low]` `[patch]` Edge: Cli commands with digits or underscores aren't surfaces — regex widened, and an unparsed arm fails.
  - `[low]` `[reject]` Edge: three-word commands fold into one — none exists; the widened parse fails loudly on arms it can't read.
  - `[low]` `[reject]` Edge: an arm containing `};` ends the scan early — no arm does today, and the unparsed-arm check reports lines it can't read.
  - `[low]` `[patch]` Edge: duplicate reasons go unreported — now a problem.
  - `[low]` `[patch]` Edge: `Kill` can race the host's exit — exception caught.
  - `[low]` `[reject]` Edge: the closed port could be reused — the window is milliseconds, and a reuse fails the flow loudly rather than passing it.
  - `[low]` `[reject]` Edge: tables outside `public` aren't scanned — every Gatekeep table is in `public`, which the catalogue test pins.
  - `[maybe-false]` `[reject]` Edge (claim): no literal outside catalogues — fixed by the literal scan. It would be low if still true.
  - `[maybe-false]` `[reject]` Edge (claim): every Cli command is a surface — fixed by the widened parse. It would be low if still true.
  - `[false]` `[reject]` Edge (claim): the generator refuses to drop a code — true after the `Regenerate` fix, duplicate of the missing-doc row.

## Design Notes

- **Why everything is pending:** the epic order put Epics 2–6 first, so the story names only two pending classes. Today only two production codes exist and neither is an FR-40 Tenant class, so all 11 classes are pending. The two the story names (16.8 and 17.2) are among them. The done-story check closes each class as its story lands.
- **Surface rule:** credential flows mostly arrive later. A surface with no credential needs a reviewed reason, not a fake flow. For example, `audit.retention.apply` carries IDs only.
- **Forced failure** means the flow's own failure path (refused connection, custody error, exhausted job), not an injected exception, so real error messages are what gets scanned.

## Verification

**Commands:**
- `docker build -f deploy/docker/tests.Dockerfile -t gatekeep/tests:epic7 .` then, from Git Bash, `MSYS_NO_PATHCONV=1 docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal --add-host host.docker.internal:host-gateway gatekeep/tests:epic7` -- expected: build with 0 warnings, Architecture and Isolation all pass.
- `dotnet run --project tests/Architecture/Generator` inside the image -- expected: no diff in `docs/audit-events.md` or the module diagram beyond line endings.

## Auto Run Result

Status: done

**Summary:** canaries are planted through each flow that exists, and scanned across the audit tables, every database table, logs, stderr, stdout, exception text and responses. Each flow runs both normally and forced to fail at Trace. Every production surface (job type, Operation type, Cli command, host, HTTP route) needs a flow or a reviewed no-credential reason, or the build fails. Audit codes live in per-module catalogues rendered to `docs/audit-events.md`. A removed or renamed code is a contract break. All 11 FR-40 Tenant classes are pending on the stories that will emit them. The appender now masks credential shapes in `user_agent`.

**Files:**
- `src/Gatekeep.Kernel/Secrets/CredentialShapes.cs`, `src/Adapters/Logging/Scrubber.cs` -- shape matching moved to Kernel.
- `src/Modules/Audit/Adapters/AuditAppender.cs` -- `user_agent` masked (the Story 1.6 deferred item).
- `src/Gatekeep.Kernel/Audit/AuditEventDefinition.cs`, `src/Modules/{Audit,Operations}/Contracts/*Events.cs` -- the catalogues. Callers use them.
- `tests/Architecture/Generator/*`, `docs/audit-events.md`, `tests/Architecture/AuditCatalogueTests.cs` -- render, regenerate refusal, literal scan, contract break.
- `tests/Isolation/Canary/*` -- flows, surfaces, scanner, captured logging.
- `tests/Isolation/Audit/EventClassTests.cs` -- FR-40 class map.
- `tests/Isolation/Hosting/*`, `CliProcess.cs` -- capture and stop helpers.
- `docs/threat-model.md` -- T-42 and TB-6.

**Review:** 41 findings across four layers: 20 rows patched (11 fixes), 1 deferred (PostgreSQL server log not scanned), 20 rejected with reasons in the triage log.

**Follow-up review:** not recommended. No high was found. The patched mediums (route surfaces, the literal scan, the regenerate refusal, the checkpoint source, the credential-reason check, the custody error path) each come with a test that ran and passed, so no unverified risk can be named.

**Verification:**
- **Image:** `gatekeep/tests:epic7`. Build with 0 warnings. Architecture 386 of 386.
- **First full run:** Isolation 1206 of 1210, all 62 canary and class tests included. The 4 failures were one simultaneous connection timeout to the test PostgreSQL container (the recurring local flake).
- **Rerun:** the three affected classes passed 302 of 302.
- **Earlier pre-review run:** found and fixed one real test bug. A successful credential job logs nothing, so the flow now writes a Debug line to prove the capture is live.

**Residual risks:**
- **No proved class:** no FR-40 class is proved yet; each closes as its story lands.
- **Manual regeneration:** the catalogue is regenerated by hand. A deliberate edit to both a catalogue and the doc is caught only in review.
- **Raw text only:** the scan matches raw text, so encoded or encrypted values prove nothing.
- **Server log:** the PostgreSQL server log isn't scanned (deferred).
- **Stand-ins:** the job and custody flows use a test job type and the fake OpenBao socket, because no production path carries those credentials yet.
