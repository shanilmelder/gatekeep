---
title: 'Story 2.7: Build the one revocation path'
type: 'feature'
created: '2026-11-03'
status: 'done'
baseline_revision: '83b6da6b28d5ef3495e688076545a8fe0abd77bd'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-2-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-2-6-add-session-and-transaction-tables.md'
  - '{project-root}/docs/spikes/2-2-openiddict-stores.md'
warnings: ['oversized']
deferred:
  - summary: >-
      The revocation audit event can't say which scope or reason it covers.
    evidence: |-
      AD-16's envelope has no free-form field, AuditDetail holds only IP, User-Agent and email,
      and AuditTargetKind has no Session or Application kind. So a refresh-reuse revocation and an
      Application deletion write the same event with no target. This limit predates this story;
      settle it with the audit type catalogue or a per-reason type code.
    location: >-
      src/Modules/Sessions/Core/SessionRevocation.cs
    severity: medium
  - summary: >-
      Overlapping revocations (for example Tenant and User at once) may deadlock, and under
      FailureContext the losing revocation would be lost.
    evidence: |-
      The three UPDATEs lock rows in each statement's scan order, not a fixed order. Unverified:
      settle it with two concurrent scopes over the same rows, then decide on ordered locking or
      a retry on 40P01.
    location: >-
      src/Modules/Sessions/Core/SessionRevocation.cs
    severity: medium (unverified)
---

<intent-contract>

## Intent

**Problem:** AD-13 and AR-23 require that every revocation goes through `ISessions.RevokeAccess(context, scope, exceptSessionId)`. That covers logout, every FR-48 trigger, refresh reuse, code replay, Application deletion and Tenant deletion. Story 2.6 created `user_session`, `"authorization"` and `token`, but nothing ends a Session or a Token Family yet.

**Approach:** Add `RevokeAccessAsync` to the Sessions contract. In the caller's `CommandContext`, it does three things:
- ends every live Session in scope
- sets every Token Family (authorization) in scope to `revoked`
- revokes those families' tokens

It writes one audit event and returns counts. A source-scan test proves no other `src/` code ends a Session or revokes a family or token. The scope shapes are Authorization, Session, User, Application and Tenant, as reviewed for AD-13 (`reviews/review-adversary.md:164`). The FR-48 trigger walk is Story 4.10's.

## Boundaries & Constraints

**Always:**
- **Contract.** `RevokeAccessAsync(CommandContext context, RevocationScope scope, Guid? exceptSessionId, RevocationReason reason, Actor actor, CancellationToken)` is `[StateChanging]`. It requires `context.TenantId`, and nothing is written without one. It returns `RevocationOutcome(SessionsEnded, FamiliesRevoked, TokensRevoked)`.
- **`RevocationScope`** is a closed set of records: `Authorization(id)`, `Session(id)`, `User(id)`, `Application(id)`, `Tenant` (the context's Tenant). Every ID must be non-empty.
- **Effects by scope.** Everything stays inside the context's Tenant under RLS, in one context:
  - `Authorization`: that family becomes `revoked`, with its tokens. No Session ends. This is the scope for refresh reuse and code replay.
  - `Session`: the Session ends, and every family anchored to it is revoked, with its tokens.
  - `User`: every live Session of the User ends, and every family anchored to those Sessions is revoked, with their tokens.
  - `Application`: every family with that `application_id` is revoked, plus every token with that `application_id`. No Session ends.
  - `Tenant`: every live Session ends, and every family and token is revoked.
- **Acting Session.** `exceptSessionId` is allowed only with `User` scope. That Session, and the families anchored to it, are left untouched (FR-48: "the acting Session continues"). With any other scope, it throws `ArgumentException`.
- **Writes.** Ending a Session sets `ended_at` to the `TimeProvider`'s now, truncated to microseconds, and `end_reason` to the reason's code. Only Sessions with `ended_at IS NULL` change. A revoked authorization gets `status = 'revoked'` and a new `concurrency_token`, so an OpenIddict store holding it sees a conflict. Tokens of those families, and those matched by Application or Tenant scope, get `status = 'revoked'` and a new `concurrency_token`, unless they are already `revoked`. The operation is idempotent: a second identical call changes nothing and returns zeros, but still writes its audit event.
- **`RevocationReason`** is a closed set with fixed snake_case codes: `logout`, `credential_change`, `admin_revoke`, `user_blocked`, `user_deleted`, `token_reuse`, `code_replay`, `application_deleted`, `tenant_deleted`. A new forward-only migration adds `CHECK (end_reason IN (...))` on `user_session` with exactly these codes.
- **Audit.** Each call writes one `sessions.access.revoked` audit event with the caller's `Actor`. For `User` scope its target is `User`. Other scopes have no target, because the envelope has no Session or Application kind.
- **Commit on a refused request.** `RevokeAccessAsync` works as the effect of `FailureContext.CommitAfterRollbackAsync`, so a refused request still commits its revocation (AD-13, spike 2.2).
- **One path.** An architecture test scans every `.cs` file under `src/` and fails if any file other than the Sessions revocation implementation contains SQL that sets `ended_at` or `end_reason`, or the literal `'revoked'`.

**Never:**
- No OpenIddict stores, endpoints, cookies or logout UI. Those are Stories 2.9, 2.10 and 4.x.
- No FR-48 trigger handlers and no trigger walk test. Those are Story 4.10.
- No change to the audit envelope's target kinds.
- No `DELETE` of any row, and no new grants beyond what the migration's CHECK needs (none).
- No revocation of access tokens beyond their `token` row status (AD-13: access tokens aren't revocable).
- No change to Story 2.6's migration. Add a new one.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| User, with an acting Session | User U has Sessions S1, S2 and S3, each with one family and tokens; except S1 | S2 and S3 ended with the reason; their families and tokens revoked; S1, its family and its tokens unchanged; counts 2/2/n; one audit event | No error expected |
| User, no acting Session | Same, `exceptSessionId` null | All three Sessions ended and all families revoked | No error expected |
| Authorization | Family F under live Session S | F and its tokens revoked; S still live | No error expected |
| Session | S with two families | S ended; both families and their tokens revoked | No error expected |
| Application | Families and tokens for apps A1 and A2 | Only A1's families and tokens revoked; no Session ended | No error expected |
| Tenant | Rows in Tenants A and B; Tenant scope in A | Everything in A ended or revoked; nothing in B changed | No error expected |
| Other Tenant untouched | User scope in A for U; B has rows (including the same IDs inserted under B) | B's rows unchanged | No error expected |
| Idempotent | The same call twice | Second call returns 0/0/0; rows unchanged | No error expected |
| Except with the wrong scope | `exceptSessionId` with Session scope | Nothing written | `ArgumentException` |
| No Tenant | Context with a null `TenantId` | Nothing written | `InvalidOperationException` |
| Refused request | Revocation run through `FailureContext.CommitAfterRollbackAsync` after the request scope wrote other rows | The revocation and its audit event are committed; the request's other writes are rolled back | No error expected |
| Bad end reason | A direct UPDATE with `end_reason = 'whatever'` | Rejected | Check violation 23514 |

</intent-contract>

## Code Map

- `src/Modules/Sessions/Contracts/ISessions.cs` -- add `RevokeAccessAsync` and the records `RevocationScope`, `RevocationReason` and `RevocationOutcome` (new files in `Contracts/` are fine).
- `src/Modules/Sessions/Core/SessionService.cs` -- has the `StartAsync` pattern to follow: Tenant guard, microsecond truncation, `context.CreateCommand()`, the `Add` helper and the audit append. Put revocation in a new `Core/SessionRevocation.cs` (the one file the scan test allows), called from `SessionService`.
- `src/Adapters/Postgres/Migrations/Migration20261102090000CreateSessionTables.cs` -- the `user_session`, `"authorization"` and `token` columns. `"authorization"` is quoted, and `token.authorization_id` has a composite FK. Read-only.
- `src/Adapters/Postgres/Migrations/` -- the new migration `Migration20261102110000ConstrainSessionEndReason.cs` follows the same attributes and has a forward-only `Down`.
- `tests/Isolation/MigrateCommandTests.cs:20,28,43,78` -- the migration count becomes 8.
- `src/Gatekeep.Kernel/Persistence/FailureContext.cs:17` -- `CommitAfterRollbackAsync(CommandScope failedScope, Func<CommandContext, CancellationToken, Task> effect)`. The pattern test is `tests/Isolation/FailureContextTests.cs:21`.
- `src/Gatekeep.Kernel/Audit/AuditEvent.cs:3-18` and `Actor` -- the audit envelope.
- `tests/Isolation/Sessions/SessionTablesTests.cs` -- reuse its seeding helpers for Tenants, Users, Sessions and superuser inserts of `"authorization"` and `token` rows (the `reference_id` must satisfy the 2.6 CHECK or be null).
- `tests/Isolation/Sessions/TestOnlyAuthenticator.cs` -- can start real Sessions for the tests.
- `tests/Architecture/` -- the existing source-scan style. Add the one-path test there and walk `src/` the way the other architecture tests find sources.
- `docs/spikes/2-2-openiddict-stores.md:122-127` -- the carry-over this story settles:
  - `RevokeAccess` does set the authorization to `revoked`.
  - The Story 2.9 token store's `RevokeByAuthorizationIdAsync` and the authorization-store revokes must call `RevokeAccess` with Authorization or Application scope, and record it for `FailureContext` replay.

## Tasks & Acceptance

**Execution:**
- `src/Modules/Sessions/Contracts/` -- add `RevocationScope`, `RevocationReason` (with its `Code`), `RevocationOutcome`, and `RevokeAccessAsync` on `ISessions` with XML docs stating the scope effects -- the contract.
- `src/Modules/Sessions/Core/SessionRevocation.cs` and `SessionService.cs` -- the scoped UPDATE statements in the caller's context, the counts and the audit event -- the one path.
- `src/Adapters/Postgres/Migrations/Migration20261102110000ConstrainSessionEndReason.cs` -- add the `end_reason` CHECK -- reasons are a closed set.
- `tests/Isolation/MigrateCommandTests.cs` -- set the migration count to 8.
- `tests/Isolation/Sessions/RevokeAccessTests.cs` -- one test per I/O matrix row.
- `tests/Architecture/RevocationPathTests.cs` -- the source scan, plus a positive control showing the scan finds the patterns in `SessionRevocation.cs`.
- `docs/spikes/2-2-openiddict-stores.md` -- under the Story 2.7 carry-over, record what was decided and what Story 2.9 must wire.
- `_bmad-output/implementation-artifacts/sprint-status.yaml` -- set `2-7-…` to `done` at the end.

**Acceptance Criteria:**
- Given `ISessions.RevokeAccess`, when it runs with any scope, then every Session and Token Family in that scope ends in the caller's context, except the named acting Session, and other Tenants' rows don't change.
- Given the `src/` tree, when the architecture tests run, then no file other than `SessionRevocation.cs` ends a Session or revokes a family or token.
- Given the full suite, when it runs in Docker with locked restore, then the architecture and isolation tests pass.

## Spec Change Log

## Review Triage Log

### 2026-11-03 — Review pass
- verdicts: 27 findings — high 0, medium 4, low 11, false 9, maybe-false 3
- findings:
  - `medium` `patch` (intent) The one-path guard checks text only — grouped with the scan rework below.
  - `false` `reject` (intent) There is no production caller of `RevokeAccessAsync` — callers arrive with Stories 2.9, 2.10 and 4.10, as the intent says.
  - `false` `reject` (intent) The signature has six parameters, not three, and is `Async` — AR-23's three are the minimum. The audit event needs an `Actor`, the CHECK needs a reason, and `Async` plus `CancellationToken` is the repository convention.
  - `false` `reject` (intent) Access-token rows are marked `revoked` although AD-13 says access tokens aren't revocable — only the row status changes. An issued JWT stays valid until expiry, which is what AD-13 means.
  - `medium` `defer` (blind) The audit event records no scope or reason — the envelope (AD-16) has no field to hold them, and that limit predates this story. Added to `deferred`.
  - `medium` `patch` (blind) The scan misses parameter-bound, quoted and row-constructor writes — the scan now flags `Statuses.Revoked`, and flags files that `UPDATE` the three tables while writing `revoked` or setting `ended_at`/`end_reason` in any form. Cases added.
  - `low` `patch` (blind) The scan flags reads such as `WHERE end_reason = @r` — only `SET` clauses count now. Grouped with the scan rework.
  - `low` `patch` (blind) Recording revocations for `FailureContext` replay moved to Story 2.9 without a record — added to `deferred-work.md` for Story 2.9.
  - `low` `patch` (blind) There's no `application_id` index for Application scope — the new migration adds `(tenant_id, application_id)` indexes on `"authorization"` and `token`.
  - `medium` `patch` (blind) `exceptSessionId` isn't checked against the User — it must now name one of that User's Sessions, or the call throws and writes nothing. Tests added.
  - `false` `reject` (blind) `redeemed` tokens are overwritten as `revoked` — OpenIddict's `RevokeByAuthorizationIdAsync` revokes every token of a family whatever its status, `redemption_date` is kept, and a revoked token is refused at use either way.
  - `low` `patch` (blind) The CHECK and `RevocationReason` are checked in one direction only — a test now compares the `pg_get_constraintdef` set with `RevocationReason.All`.
  - `low` `reject` (blind) In `ExecuteAsync`, the `CancellationToken` comes before optional parameters, and `endedAt`/`reason` are only loosely paired — the build has warnings as errors and passes, there is one private caller, and the change would be cosmetic.
  - `false` `reject` (blind) The bookkeeping contradicts itself — status moves to `done` at finalization, and `sprint-status` is committed with the PR.
  - `low` `patch` (blind) Edge tests are missing for an already-ended Session, the Application family branch, null arguments, and other Users left untouched — tests added.
  - `medium` `patch` (verification-gap) A parameter-bound revocation passes the scan — grouped with the scan rework.
  - `low` `patch` (verification-gap) The CHECK isn't compared with `RevocationReason` both ways — grouped with the both-way test.
  - `low` `patch` (verification-gap) The spike doc overstates what the scan guarantees — reworded, and the `UpdateAsync` obligation for Story 2.9 added.
  - `maybe-false` `reject` (edge) A token inserted concurrently into a family being revoked survives — OpenIddict's `ValidateAuthorizationEntry` refuses any token whose authorization is `revoked`, so the token can't be used. If it were real it would be low. To settle it, show a use path that skips the authorization check.
  - `maybe-false` `reject` (edge) A Session started concurrently escapes User revocation — Authentication refuses a blocked or deleted User before starting one (AD-30), and a fresh sign-in creating a new Session is allowed by design. Low if real; to settle it, show a sign-in path that reaches `StartAsync` for a blocked User.
  - `maybe-false` `defer` (edge) Overlapping revocations can deadlock — medium if real (the revocation is lost under `FailureContext`). Deferred, unverified.
  - `false` `reject` (edge) Tokens with no family but the User's subject survive — every token that carries a User comes from a code-flow family (AD-13). Client Credentials tokens have no User subject.
  - `medium` `patch` (edge) `exceptSessionId` names a Session that isn't the User's — grouped with the check above.
  - `medium` `patch` (edge) A double-quoted `"revoked"` passes the scan — grouped with the scan rework.
  - `low` `patch` (edge) A row-constructor `SET` passes the scan — grouped with the scan rework.
  - `low` `patch` (edge) `.sql` files aren't scanned — they are now. Grouped with the scan rework.
  - `low` `patch` (edge) The claim "a test holds the two together" — grouped with the both-way test.

## Design Notes

**Why an Authorization scope exists.** Refresh reuse and code replay must kill one family without logging the User out (`review-adversary.md:164`). Story 2.9's store calls `RevokeAccess(Authorization(id), null, TokenReuse or CodeReplay, Actor.Anonymous)` from OpenIddict's `RevokeByAuthorizationIdAsync`.

**Why the source scan matches literals.** Production SQL is hand-written strings (no ORM), so `ended_at`, `end_reason` and `'revoked'` are reliable markers. The positive control keeps the scan from passing vacuously.

## Verification

**Commands:**
- `docker build -t gatekeep/tests:epic2 -f deploy/docker/tests.Dockerfile .` -- expected: the image builds with locked restore.
- `MSYS_NO_PATHCONV=1 docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal --add-host host.docker.internal:host-gateway gatekeep/tests:epic2` -- expected: all architecture and isolation tests pass.

## Auto Run Result

**Summary.** `ISessions.RevokeAccessAsync(context, scope, exceptSessionId, reason, actor, ct)` is the one revocation path. Its scopes are Authorization, Session, User, Application and Tenant. In the caller's `CommandContext` it ends the live Sessions in scope with a fixed reason code. It sets their Token Families (authorizations) to `revoked` and revokes those families' tokens, rotating each `concurrency_token`. It writes one `sessions.access.revoked` audit event and returns the counts. An acting Session is spared only in User scope, and it must belong to that User. The call is idempotent and works as a `FailureContext` effect. A new migration limits `end_reason` to the nine codes and indexes `application_id`. An architecture scan fails if any other `src/` file revokes.

**Files changed**
- `src/Modules/Sessions/Contracts/Revocation.cs` and `ISessions.cs`: `RevocationScope`, `RevocationReason`, `RevocationOutcome` and `RevokeAccessAsync`.
- `src/Modules/Sessions/Core/SessionRevocation.cs` and `SessionService.cs`: the scoped UPDATEs, the acting-Session check and the audit event.
- `src/Adapters/Postgres/Migrations/Migration20261102110000ConstrainSessionEndReason.cs`: the `end_reason` CHECK and the `(tenant_id, application_id)` indexes.
- `tests/Architecture/RevocationPathTests.cs`: the one-path scan, its positive control and the detection cases.
- `tests/Isolation/Sessions/RevokeAccessTests.cs`: every I/O matrix row, plus the review's edge cases.
- `tests/Isolation/MigrateCommandTests.cs`: the migration count is now 8.
- `docs/spikes/2-2-openiddict-stores.md`: the decisions, and what the Story 2.9 stores must wire.
- `deferred-work.md` and `sprint-status.yaml`: the Story 2.9 capture follow-up, and tracking.

**Review findings.** There were 27 findings: 18 patched in 8 groups (by group verdict, 2 medium and 6 low), 2 deferred, 7 rejected (6 false and 1 low, reasons in the triage log), plus 2 maybe-false findings that were rejected. The two deferred items are:
- the audit event can't carry the scope or reason, because of an envelope limit that predates this story
- overlapping revocations might deadlock (unverified)

**Follow-up review: recommended (`true`).** Two medium groups were patched: the scan rework and the acting-Session check. The unverified risk is that the scan is still a text check. A Story 2.9 store that receives `revoked` as a variable, or through OpenIddict's generic `UpdateAsync`, passes it. Story 2.9 must add a runtime guard or route `UpdateAsync` through `RevokeAccessAsync`.

**Verification**
- The image builds with locked restore.
- Before the patches, the full suite was green: 371/371 architecture and 1275/1275 isolation tests.
- After the patches, three full runs: 381/381 architecture each time, and 1282/1283 isolation each time.
  - Each run failed a different Audit test that this story doesn't touch: `SealerTests` and `AuditTests` twice. Every failure was `Failed to connect to 192.168.65.254 … Timeout during connection attempt`, which is the Docker Desktop host gateway after a restart, not this code.
  - All new and changed tests passed in every run.
  - CI on the PR is the deciding run.

**Residual risks**
- The scan is text-only (see above).
- There is no runtime guard on revocation outside `SessionRevocation`.
- The audit event has no scope or reason.
- A deadlock is possible under overlapping revocations.
- No production caller yet (Stories 2.9, 2.10 and 4.10).
