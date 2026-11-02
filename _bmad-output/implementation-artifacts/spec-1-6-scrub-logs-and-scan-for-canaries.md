---
title: 'Story 1.6: Scrub logs and scan for canaries'
type: 'feature'
created: '2026-11-02'
status: 'done'
baseline_commit: 'c35aeb37a72b83a1c2cd942ca6a52a2f7e0049c0'
baseline_revision: 'c35aeb37a72b83a1c2cd942ca6a52a2f7e0049c0'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-1-context.md'
  - '{project-root}/docs/threat-model.md'
warnings:
  - multiple-goals
deferred:
  - summary: >-
      Audit detail stores request text with no scrubbing.
    evidence: |-
      user_agent and email come from requests, so a Bearer token in a User-Agent would be stored raw. T-42 records it, and Story 7.8 extends the canary scan.
    location: >-
      src/Modules/Audit/Adapters/AuditAppender.cs
    severity: medium
---

<intent-contract>

## Intent

**Problem:** Hosts log through the default providers with nothing removing credential-equivalent values, and nothing proves a value stays out of logs or Audit events (NFR-3, AD-24, T-42).

**Approach:** Add a scrubbing logger provider that wraps the only real sink and is the only provider in all three hosts, then a first canary scanner that runs in CI over logs and Audit tables and fails on any planted raw value.

## Boundaries & Constraints

**Always:**
- A record's message, exception text and named values all pass through the scrubber before the inner sink sees them.
- `Secret<T>` values logged as arguments print only the mask.
- If scrubbing throws, the record is replaced by a fixed line naming no value.
- Hosts clear every default provider, then add only the scrubbing one.
- The scanner reads real rows from all four audit tables and real sink output.

**Never:**
- No third-party logging package, and no package in Kernel.
- No log shipping, files, retention or log levels policy.
- No canary for every flow, and no release gate wiring: Story 7.8 adds those.
- No claim that the scrubber catches an arbitrary plain string. It catches shapes and named values only.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Secret argument | `Log("{S}", new Secret<string>(v))` | Mask only | N/A |
| Sensitive name | `Log("{Password}", v)` | `v` absent, message otherwise kept | N/A |
| Shape in message | Connection string `Password=x`, `Bearer x`, a JWT, `?code=x`, a PEM private key | Value absent | N/A |
| Exception | Exception message holds `Password=x` | Exception type kept, value absent | N/A |
| Scope | `BeginScope` with a value | Value never reaches the sink | Scopes aren't forwarded |
| Scrubber throws | Argument whose `ToString` throws | Fixed line written, host keeps running | No exception escapes |
| Ordinary log | `Started {Host}` | Unchanged | N/A |
| Clean scan | Canaries sent through sink and appender as designed | Scan finds nothing | N/A |
| Planted in log | Raw canary written straight to the captured output | Scan names the source, test fails | Build fails |
| Planted in Audit | Raw canary in `audit_detail` or `deployment_audit_detail` | Scan names table and column kind, never the value | Build fails |

</intent-contract>

## Code Map

- `src/Gatekeep.Host.Hosted/Program.cs`, `src/Gatekeep.Host.Admin/Program.cs`, `src/Gatekeep.Host.Worker/Program.cs` -- two or three lines each; add the logging call after the builder.
- `src/Gatekeep.Kernel/Secrets/Secret.cs:15` -- `Mask` is private; `ToString` prints `[secret]`.
- `src/Adapters/Postgres/Gatekeep.Adapters.Postgres.csproj` -- pattern for an adapter project.
- `Gatekeep.slnx`, `tests/Architecture/module-edges.txt` -- add the project and `dependency` edges; `Directory.Build.targets` strips `Gatekeep.`, so the name is `Adapters.Logging`. Then run the generator.
- `tests/Isolation/AuditTests.cs` -- how to reach audit rows and `AuditContract.CreateAppender()`.
- `tests/Isolation/Gatekeep.Tests.Isolation.csproj` -- already references Audit; add the adapter.
- `tests/Architecture/PersistenceRuleTests.cs` -- pattern for source rules.
- `docs/threat-model.md:252` -- T-42.
- `global.json` -- needs SDK 10.0.403 on `PATH`, and Node 26.13.0 for `BuildEnforcementTests`.

## Tasks & Acceptance

**Execution:**
- [x] `src/Adapters/Logging/Gatekeep.Adapters.Logging.csproj` -- add a project using `FrameworkReference` `Microsoft.AspNetCore.App`, so no package or version pin is added.
- [x] `src/Adapters/Logging/Scrubber.cs` -- add the shape and name rules, with mask `[scrubbed]`.
- [x] `src/Adapters/Logging/ScrubbingLoggerProvider.cs`, `LoggingExtensions.cs` -- wrap an inner `ILoggerProvider`; `AddGatekeepLogging(ILoggingBuilder)` clears providers and adds console through the wrapper.
- [x] The three host `Program.cs` files, `.csproj` files, `module-edges.txt`, `Gatekeep.slnx`, lockfiles, diagram -- wire it in.
- [x] `tests/Isolation/Scrubbing/` -- cover the first seven matrix rows with an in-memory inner sink.
- [x] `tests/Isolation/Canary/CanaryScanner.cs`, `CanaryScanTests.cs` -- add the scanner and the last three rows.
- [x] `tests/Architecture/LoggingRuleTests.cs` -- each host calls `AddGatekeepLogging`, and no source outside the adapter adds a logging provider.
- [x] `docs/threat-model.md` -- update T-42, the status line and the test names.

**Acceptance Criteria:**
- Given any host's service provider, when its `ILoggerProvider` set is read, then the scrubbing provider is the only one.
- Given a scan finding, when it is reported, then the output names the source and never prints the canary.
- Given a scanner with a canary list, when a later story adds a value or a source, then it needs only a new entry.

## Spec Change Log

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 40 findings — high 4, medium 21, low 10, false 5, maybe-false 0
- findings:
  - `[high]` `[patch]` Blind: colon, JSON, cookie and URL credentials passed the scrubber — separator widened; cookie and userinfo rules added, tested.
  - `[medium]` `[patch]` Blind: credential names missing, and `{Code}` not sensitive — names added, tested.
  - `[medium]` `[patch]` Blind: `&` ended a connection-string value — stops at `&` only in query context.
  - `[medium]` `[patch]` Blind: scopes dropped and the sink got a flat string, against the spine JSON and trace ID rule — JSON console formatter plus `TraceId` and `SpanId` state.
  - `[medium]` `[patch]` Blind: exact-text replacement of short values garbled lines — numbers and booleans skipped; a numeric secret is a recorded limit in T-42.
  - `[medium]` `[patch]` Blind: `SchemeCredential` rewrote prose — needs a 16-character credential.
  - `[medium]` `[defer]` Blind: appender stores request-derived `user_agent` unscrubbed — scrubbing there needs a module edge the story did not plan; T-42 records it for Story 7.8.
  - `[medium]` `[patch]` Blind: T-42 overstated what the log scan reads — wording corrected.
  - `[low]` `[patch]` Blind: an unhandled host exception bypasses the scrubber — recorded in T-42; the hosts have no startup code yet.
  - `[medium]` `[patch]` Blind: `LoggingRuleTests` left bypasses open — provider names added, hosts discovered, console rule exempts only Cli.
  - `[medium]` `[patch]` Blind: `Logging:Console:LogLevel` silently ignored — `[ProviderAlias("Console")]` added, tested.
  - `[low]` `[reject]` Blind: `HostLoggingTests` can read stale binaries — CI builds first, and a project reference would break the edge list rule.
  - `[high]` `[patch]` Edge: colon-separated values pass — same fix as the Blind row.
  - `[medium]` `[patch]` Edge: `&` in a connection-string value — same fix as the Blind row.
  - `[medium]` `[patch]` Edge: unterminated quote leaked the tail — masked to the end of the line.
  - `[medium]` `[patch]` Edge: text after a closing quote survived — masked to the next separator.
  - `[medium]` `[patch]` Edge: `code` in a form body, fragment or encoded form — matched at line start, after `#`, and as `%3Fcode%3D`; a mid-line `Body: code=abc` still passes, as a wider match masks `exit code=5`.
  - `[medium]` `[patch]` Edge: names outside the list — same fix as the Blind row.
  - `[medium]` `[patch]` Edge: URL userinfo and cookies — same fix as the Blind row.
  - `[medium]` `[patch]` Edge: short values garble text — same fix as the Blind row.
  - `[high]` `[patch]` Edge: a self-containing collection overflowed the stack and killed the host — read one level deep, tested.
  - `[low]` `[reject]` Edge: a one-shot enumerable under a sensitive name stays unmasked — unlikely argument, and materializing needs a formatter rewrite.
  - `[medium]` `[patch]` Edge: console filter rules ignored — same fix as the Blind row.
  - `[low]` `[reject]` Edge: `//` in a string hides a provider call from the rule — needs a real parser for an unlikely line.
  - `[low]` `[reject]` Edge: `BuildOutput` needs a prior build — same reason as the Blind row.
  - `[low]` `[reject]` Edge: a `dotnet test -o` layout breaks path derivation — fails loudly, and neither CI nor local runs use it.
  - `[low]` `[patch]` Edge: `audit_detail` substring matches the Deployment table — exact source asserted.
  - `[medium]` `[patch]` Edge: provider rule misses package extensions — same fix as the Blind row.
  - `[medium]` `[patch]` Gap: the scan scope path could not fail — `CapturedConsole` walks scopes; it guards a future change, as the wrapper sets no scope provider.
  - `[low]` `[patch]` Gap: longest-first replacement unpinned — overlap test added.
  - `[low]` `[patch]` Gap: disposal forwarding unobserved — flag and test added.
  - `[medium]` `[patch]` Gap (other): `SchemeCredential` prose — same fix as the Blind row.
  - `[medium]` `[patch]` Gap (other): sensitive substring names garble lines — same fix as the Blind row.
  - `[high]` `[patch]` Gap (other): colon forms pass — same fix as the Blind row.
  - `[false]` `[reject]` Intent: the diff touches no Operator surface — descriptive; the story has `Screens: None`.
  - `[false]` `[reject]` Intent: planted tests prove detection, not a red build — the clean scan is an ordinary test, so any finding fails CI.
  - `[false]` `[reject]` Intent: `ci.yml` is not in the diff — `tests/Isolation` already runs there.
  - `[false]` `[reject]` Intent: the `Secret<T>` test asserts the Kernel mask — the matrix row says "mask only", and that is what prints.
  - `[false]` `[reject]` Intent: `Gatekeep.Cli` writes to the console directly — it is not a host, its messages are fixed text, and T-42 discloses it.
  - `[low]` `[reject]` Intent: category and event name are outside the scan — these are code constants, not values.

## Design Notes

- **Rules:** name rule: `password`, `passwd`, `pwd`, `secret`, `token`, `api_key`, `apikey`, `authorization`, `cookie`, in any case, as a substring of the value's name. Shape rules: `name=value` for the same names, `Bearer` and `Basic` credentials, `[?&]code=`, three-part `eyJ` tokens, PEM private key blocks.
- **Inner call:** pass a plain scrubbed string as state, the formatter returning it, and a null exception, with the scrubbed exception text appended. Console would otherwise print the raw exception.
- **Named values:** read the state as key and value pairs, and replace the text of each sensitive value in the formatted message.
- **Scanner:** `Scan(canaries, sources)` where a source is a name plus text. Audit sources read each table with `row_to_json` as superuser.
- **Limit:** a value held as a plain string with an innocent name and no known shape passes. T-42 must say so.

## Verification

**Commands:**
- `dotnet restore Gatekeep.slnx --locked-mode` -- expected: succeeds.
- `dotnet build Gatekeep.slnx --no-restore` -- expected: no warnings.
- `dotnet test tests/Architecture --no-build` -- expected: all pass.
- `dotnet test tests/Isolation --no-build` -- expected: all pass.
- `dotnet run --project tests/Architecture/Generator` -- expected: no diff after committing the diagram.

## Auto Run Result

Status: done

**Summary:** added a scrubbing logger provider, the only provider in all three hosts, writing JSON with trace IDs, and a first canary scanner over logs and all four audit tables.

**Files:** `src/Adapters/Logging/`; the three host entry points and project files; `tests/Isolation/Scrubbing/`, `tests/Isolation/Canary/` and `HostLoggingTests`; `tests/Architecture/LoggingRuleTests.cs`; `docs/threat-model.md`; the module diagram.

**Review:** 40 findings across four layers: 28 patched, 1 deferred, 11 rejected, each with its reason in the triage log.

**Follow-up review:** not recommended. Every patched high has a test that exercises the fixed form, so no unverified risk can be named.

**Verification:** see the PR screenshot; restore, build, Architecture, Isolation and the diagram generator all pass on SDK 10.0.403 and Node 26.13.0.

**Residual risks:** the scrubber catches shapes and names only, as T-42 records with its limits. `Bearer` and `Basic` need 16 characters outside an `Authorization:` header, and a numeric value under a sensitive name passes. An unhandled host exception reaches stderr unscrubbed. Sensitive JSON keys can over-mask the rest of a line.
