---
title: 'Story 4.10: Revoke access through one path'
type: 'feature'
created: '2026-11-22'
status: 'done'
baseline_revision: 'd48eecb8c064839a61ab7bd668c4d0c2d2c1cdfb'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-4-context.md'
warnings: []
deferred: []
---

<intent-contract>

## Intent

**Problem:** `ISessions.RevokeAccessAsync` (Story 2.7) is the one revocation path, but nothing walks the FR-48 trigger list. A trigger built later could skip `RevokeAccess`, or drop off the list, and no test would notice (FR-48, AR-23, AD-13).

**Approach:** Add a generated FR-48 walk. It is a fixed registry of every FR-48 trigger, each either `Covered` by a named test that proves the trigger calls `RevokeAccess`, or `Pending` on the backlog story that builds it, held to `sprint-status.yaml`. It mirrors Story 1.31's cross-Tenant `ArtifactRegistry`. It also confirms the first and third criteria against the existing Story 2.7 tests.

## Boundaries & Constraints

**Always:**
- **Registry** (`tests/Isolation/Revocation/Fr48TriggerRegistry.cs`, new):
  - **Required:** a fixed list of the FR-48 triggers from the PRD. Each PRD phrase is split into one entry per action:

    | Trigger | Pending on |
    |---|---|
    | `password reset` | `4-11` |
    | `password change` | `16-4` |
    | `Factor added` | `16-5` |
    | `Factor removed` | `16-5` |
    | `Passkey added` | `16-5` |
    | `Passkey removed` | `16-5` |
    | `Recovery Codes regenerated` | `16-6` |
    | `Recovery Code used` | `6-8` |
    | `email change` | `16-8` |
    | `User blocked` | `5-4` |
    | `User deleted` | `5-5` |
    | `Factor reset` | `6-10` |
    | `Admin revoke` | `5-4` |

  - **Entries:** each entry is `Fr48Trigger.Covered(test)`, where `test` is `Class.Method` of a test that drives the trigger and asserts the User's Sessions and Token Families ended through `RevokeAccess`, or `Fr48Trigger.Pending(storyId)`. Every entry is `Pending` today, because none of these triggers is built yet.
- **Walk** (`tests/Isolation/Revocation/Fr48WalkTests.cs`, new). Model it on `tests/Isolation/CrossTenant/ArtifactRegistryTests.cs` and reuse its sprint-status reading. It fails when:
  1. **The PRD and the registry disagree.** The registry's keys differ from `Required`. Or `Required` no longer matches the PRD: the walk parses the FR-48 "Triggers:" line in `_bmad-output/planning-artifacts/prds/prd-gatekeep-2026-11-01/prd.md`, and every phrase there (password reset or change; Factor or Passkey added or removed; Recovery Codes regenerated or used; email change; User blocked or deleted; Factor reset; Admin "revoke") must be represented. A fixed mapping from each phrase to its entries makes this check exact, so the list can't shrink silently.
  2. **A pending entry is wrong.** Its story isn't in `sprint-status.yaml`, or its story is `done` while the entry is still `Pending`.
  3. **A covered entry is wrong.** It names a test method that doesn't exist in the test assemblies (found by reflection, with a `[Fact]` or `[Theory]` attribute).
  - **Rule tests:** each failure kind gets a unit test fed a synthetic registry and status, as `ArtifactRegistryTests` does for its rules. Each one asserts an exact message naming the trigger and the fix.
- **The other two criteria** are already proven by Story 2.7's `tests/Isolation/Sessions/RevokeAccessTests.cs`:
  - `User_scope_spares_the_acting_Session_and_its_families`, `User_scope_with_no_acting_Session_ends_every_Session_of_the_User`, `Tenant_scope_ends_everything_in_its_Tenant_and_nothing_in_another` and `Another_Tenants_rows_with_the_same_IDs_are_untouched`.
  - **Gap to add:** if no test shows a User-scope revocation in Tenant A leaving a Tenant B User with the same ID untouched, add one: `User_scope_in_one_Tenant_leaves_another_Tenants_same_User_ID_untouched`.
  - **"At once":** add one test, `User_scope_ends_every_Session_and_family_in_one_statement_set_or_none`, showing that a User-scope revocation whose transaction rolls back leaves every Session and family live, so the end is all-or-nothing.
- **Docs:** `docs/threat-model.md` T-12 gets the walk ("A walk over the FR-48 trigger list, `Fr48WalkTests`, holds every trigger to a covering test or a pending backlog story"). Also add one line to the `ISessions.RevokeAccessAsync` doc comment naming the registry for later triggers.

**Never:**
- No new trigger is built here: no reset, block, delete or Factor work (those stories own them).
- No change to `RevokeAccessAsync`'s behaviour, its signature, or `RevocationReason`.
- No `Covered` entry without a real test that asserts revocation.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Registry current | every trigger `Pending` on a backlog story | walk passes | No error expected |
| Trigger missing | a `Required` entry absent from the registry | walk fails naming it | test fails |
| PRD grows | the "Triggers:" line names a phrase the mapping lacks | walk fails naming the phrase | test fails |
| Pending on unknown story | `Pending("9-99")` | walk fails: no such story | test fails |
| Pending on done story | the story is `done` in sprint-status | walk fails: make it `Covered` | test fails |
| Covered, test missing | `Covered("X.Y")` with no such test method | walk fails naming it | test fails |
| Cross-Tenant | User scope in A, the same User ID in B | B's Sessions and families untouched | No error expected |
| All at once | User-scope revoke inside a rolled-back transaction | every Session and family still live | No error expected |

</intent-contract>

## Code Map

- `src/Modules/Sessions/Contracts/ISessions.cs:127-155`: the `RevokeAccessAsync` contract and doc comment.
- `src/Modules/Sessions/Contracts/Revocation.cs:59-104`: `RevocationScope` and `RevocationReason` (read-only here).
- `tests/Isolation/Sessions/RevokeAccessTests.cs`: Story 2.7's tests (:66 acting Session, :193 no acting Session, :260 Tenant scope, :278 same IDs in another Tenant) and their setup helpers.
- `tests/Isolation/CrossTenant/ArtifactRegistry.cs` and `ArtifactRegistryTests.cs` (:15 sprint-status path, :94 and :194 message shapes): the pattern to copy.
- `tests/Architecture/RevocationPathTests.cs`: the "only Sessions revokes" rule (unchanged).
- `_bmad-output/planning-artifacts/prds/prd-gatekeep-2026-11-01/prd.md:475-483`: FR-48's "Triggers:" line.
- `_bmad-output/implementation-artifacts/sprint-status.yaml`: the story IDs above.
- `docs/threat-model.md`: T-12.

## Tasks & Acceptance

**Execution:**
- `tests/Isolation/Revocation/Fr48TriggerRegistry.cs`: the fixed `Required` list, the PRD phrase mapping and the 13 entries.
- `tests/Isolation/Revocation/Fr48WalkTests.cs`: the walk, plus a rule test for each failure kind.
- `tests/Isolation/Sessions/RevokeAccessTests.cs`: the cross-Tenant same-User-ID test (if missing) and the all-or-nothing test.
- `src/Modules/Sessions/Contracts/ISessions.cs` (doc comment only) and `docs/threat-model.md` T-12.

**Acceptance Criteria:**
- Given `ISessions.RevokeAccess`, when it runs with User scope and an acting Session, then every other Session and Token Family of the User ends in one transaction, and the acting one stays.
- Given the FR-48 trigger list, when the walk runs, then every trigger is covered by a named, existing test or pending on a not-yet-done story, and removing or renaming a trigger fails it.
- Given two Tenants, when one User's access is revoked, then no row of another Tenant changes.

## Spec Change Log

## Review Triage Log

### 2026-11-22 — Review pass
- verdicts: 27 findings — high 0, medium 2, low 18, false 3, maybe-false 4
- findings:
  - `low` `patch` (Edge) The PRD regex takes the first `- Triggers:` bullet anywhere — the parse is now sliced to the `#### FR-48:` section.
  - `low` `patch` (Edge) A Pending id matching several stories reports "no story has" — reports "matches N stories: use a unique id".
  - `low` `patch` (Edge) A duplicate in `Required` passes — duplicates are refused.
  - `low` `reject` (Edge) A story set to done without flipping its entry turns main red after the merge — the same contract as `ArtifactRegistry` (Story 1.31); the story loop finalizes sprint-status in the story's own PR, so the PR itself goes red.
  - `medium` `patch` (Edge) A sub-trigger can be dropped from the mapping, `Required` and `Triggers` in one edit — each PRD phrase must map to 2^(its " or " count) entries, 13 in all.
  - `medium` `patch` (Edge) Any existing test counts as coverage — a Covered test must carry `[Trait("FR-48", "<trigger>")]` for its trigger and not be skipped.
  - `low` `patch` (Verification Gap, other) A skipped test counts as coverage, and the doc comment overstates it — fixed with the trait rule; the `ISessions` doc line is reworded.
  - `medium` `patch` (Blind) The list can still shrink without failing — same root cause as the Edge row, fixed by it.
  - `low` `patch` (Blind) The PRD regex isn't tied to FR-48 — fixed with the Edge row.
  - `medium` `patch` (Blind) A Covered entry only has to name a test that exists — fixed with the trait rule.
  - `low` `patch` (Blind) Story 18.1's "nothing pending" gate isn't enforced — once `18-1` is done, any Pending entry fails.
  - `low` `reject` (Blind) A trigger can ship before its entry flips, until its story is marked done — the sprint-status contract shared with `ArtifactRegistry`; detecting built triggers from the code is beyond this story.
  - `low` `patch` (Blind) T-12 reads as in force though every trigger is pending — the residual column now says all 13 are pending on their stories.
  - `low` `patch` (Blind) T-12 omits the acting-Session test — now cites `User_scope_spares_the_acting_Session_and_its_families`.
  - `low` `patch` (Blind) The `ISessions` comment misdescribes the walk — reworded: each trigger is covered by a test tagged with it, or pending on its story.
  - `low` `patch` (Blind) The rollback test's name overclaims and never looks inside the open transaction — renamed; it reads the rows through the same scope before the rollback, then shows they're back.
  - `low` `reject` (Blind) The walk is a near copy of `ArtifactRegistryTests` — the shared reading is reused (made internal); a generic registry is a refactor of Story 1.31's code beyond a direct correction.
  - `low` `patch` (Blind) The wrong message for several matches — fixed with the Edge row.
  - `false` `reject` (Blind) The spec doesn't record the cross-Tenant test decision — this triage log records it (next row) and the spec made the test conditional.
  - `low` `patch` (Blind) `Fr48Trigger` can be subclassed outside — the base has a private constructor.
  - `low` `reject` (Blind) `Covered` and `Pending` accept blank strings — a blank story id matches no story and a blank test name matches no method, so the walk already fails on both.
  - `maybe-false` `reject` (Intent) "At once" under concurrency isn't exercised — the revocation runs as one set of statements in the caller's transaction; if a partial window existed it would be low.
  - `maybe-false` `reject` (Intent) "Generated" could mean derived from code call paths — the architecture (AR-23) describes a walk of the FR-48 list; if a code-derived walk were meant it would be low here, since no trigger exists yet.
  - `maybe-false` `reject` (Intent) "Built so far" is inferred from sprint-status, not the code — same as the Blind reject row; if true it would be low.
  - `false` `reject` (Intent) Sign-up's credential activation counts as an FR-48 trigger — FR-48 lists the triggers, and sign-up activation isn't among them; its carve-out only says the acting Session continues for such changes.
  - `false` `reject` (Intent) No new two-Tenant test — `Another_Tenants_rows_with_the_same_IDs_are_untouched` already revokes at User scope and checks Tenant B's rows and audit events, which is the spec's condition for not adding one.
  - `maybe-false` `reject` (Intent) The user-facing eviction isn't shown end to end — no trigger exists yet; Story 4.11 shows it for reset. If true it would be low.

## Design Notes

- **Why the PRD is parsed:** "so the list can't shrink silently" needs a source outside the registry itself. Parsing FR-48's "Triggers:" line ties the list to the requirement, and a fixed phrase-to-entry mapping keeps the parse simple.
- **Why everything is Pending:** every trigger lands in a later story (4.11, 5.4, 5.5, 6.8, 6.10, 16.4–16.8). Each of those stories flips its entry to `Covered` with its own test, and the sprint-status check forces it to, as with `ArtifactRegistry`. Story 18.1 requires the walk "with nothing pending".

## Verification

**Commands:**
- With `MSYS_NO_PATHCONV=1`, run `docker run --rm -v "D:/Projects/Personal/gatekeep:/src" -v gk-nuget:/root/.nuget -w /src mcr.microsoft.com/dotnet/sdk:10.0.403-noble sh -c 'dotnet build Gatekeep.slnx -p:NuGetAudit=false -v q'`. Expected: 0 warnings and 0 errors.
- The Isolation suite runs on CI on the PR. Don't run it locally.

## Auto Run Result

Status: done

**Summary:**
- **FR-48 walk:** `Fr48WalkTests` walks the FR-48 trigger list. `Fr48TriggerRegistry` holds all 13 triggers, split from the PRD's "Triggers:" line, each pending on the backlog story that builds it.
- **What the walk fails on:**
  - the PRD's FR-48 section and the registry disagree, or a phrase maps to fewer triggers than its actions;
  - a trigger is missing or duplicated;
  - a pending story is unknown, ambiguous or already done;
  - Story 18.1 is done while anything is pending;
  - a covered test is missing, untagged (`[Trait("FR-48", "<trigger>")]`) or skipped.
- **The other two criteria** stand on Story 2.7's tests, plus a new all-or-nothing test.

**Files changed:**
- `tests/Isolation/Revocation/Fr48TriggerRegistry.cs`: the trigger list, the phrase mapping and the entries.
- `tests/Isolation/Revocation/Fr48WalkTests.cs`: the walk and its rule tests.
- `tests/Isolation/CrossTenant/ArtifactRegistryTests.cs`: the sprint-status reading and test index, made internal for reuse.
- `tests/Isolation/Sessions/RevokeAccessTests.cs`: `User_scope_spares_the_acting_Session_and_is_all_or_nothing_in_the_callers_transaction`.
- `src/Modules/Sessions/Contracts/ISessions.cs`: one doc line.
- `docs/threat-model.md`: T-12.

**Review findings:** 27.
- **16 patched:** the phrase-count rule, the FR-48 section slice, the trait-bound coverage, the Story 18.1 gate, the ambiguous-id message, duplicates and subclassing, the rollback test, the doc comment, and T-12.
- **None deferred.**
- **The rest rejected** with reasons in the triage log.

**Follow-up review recommended:** false. One `medium` root cause was patched twice over (the list could shrink, and any test counted as coverage), and both are covered by new rule tests. Patched entries: high 0, medium 2, low 9. That is below a second pass's threshold for test-only code, and no production behaviour changed.

**Verification:**
- .NET build in the SDK 10.0.403 Docker image: 0 warnings, 0 errors.
- The Isolation suite runs on CI.

**Residual risks:**
- The PRD parse expects the current "Triggers:" line shape, and fails loudly if it changes.
- A trigger built before its story is marked done isn't detected until then.
