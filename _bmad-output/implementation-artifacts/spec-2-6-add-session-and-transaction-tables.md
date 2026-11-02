---
title: 'Story 2.6: Add Session and transaction tables'
type: 'feature'
created: '2026-11-02'
status: 'done'
baseline_revision: '6bde9ba5c2f2a0897ce30c56460d99444638bc2c'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-2-context.md'
  - '{project-root}/docs/spikes/2-2-openiddict-stores.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** The code flow (2.9), the one revocation path (2.7) and refresh rotation (2.10) need real tables and contracts: `user`, `user_session`, `signin_transaction`, `authorization` and `token`, plus `IAuthentication.Begin` and `AuthenticationResult`. Today only spike tables exist, and the Authentication, Sessions and Identity modules are empty placeholders.

**Approach:** Add one forward-only migration that creates the five Tenant-class tables, each with the RLS pair, grants and a `TableRegistry` entry. Add the first contracts:
- Authentication: `IAuthentication.BeginAsync`, which creates a `signin_transaction` bound to a browser binding, the Tenant and an Application ID.
- Authentication: the `AuthenticationResult` record.
- Sessions: `ISessions.StartAsync`, which creates a `user_session`.

Prove both acceptance criteria with isolation tests, using a test-only authenticator that lives in `tests/`. **User decision (2026-11-02):** the `application` table is Story 2.5's, so `application_id` columns carry no foreign key yet. Story 2.5 adds those foreign keys in its own migration.

## Boundaries & Constraints

**Always:**
- **Table rules.** Every table follows the existing conventions:
  - Tenant-class, with `tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT`, `PRIMARY KEY (tenant_id, id)` and UUIDv7 IDs.
  - Composite `(tenant_id, …)` foreign keys with `ON DELETE RESTRICT`, and times as `timestamptz`.
  - The exact `ENABLE`/`FORCE` RLS and `_permissive`/`_tenant` policy pair.
  - Grants that equal the registry entry exactly.
- **Ownership:** `user` belongs to Identity. `user_session`, `authorization` and `token` belong to Sessions. `signin_transaction` belongs to Authentication. `user` is quoted in SQL as `"user"`.
- **Minimal `user`:** `tenant_id`, `id` and `created_at` only. Later stories add profile columns.
- **`user_session`:**
  - `user_id` with a composite FK to `"user"`.
  - `id_hash bytea NOT NULL`: the SHA-256 of a 256-bit random identifier, `UNIQUE (tenant_id, id_hash)`, and a check that its length is 32.
  - `amr text[] NOT NULL`, `auth_time`, a nullable `connection_id uuid` (no FK; Connections arrive later), `idle_expires_at`, `absolute_expires_at`, `created_at`, a nullable `ended_at` and a nullable `end_reason text`.
- **`signin_transaction`:**
  - `application_id uuid NOT NULL` (no FK yet).
  - `binding_hash bytea NOT NULL`: the SHA-256 of a 256-bit random `__Host-gk_txn` value, unique per Tenant, length 32.
  - `parameters jsonb NOT NULL`, `completed_steps text[] NOT NULL DEFAULT '{}'`, `created_at` and `expires_at`, which is `created_at` plus the 30-minute sliding lifetime.
- **`authorization` and `token`:** follow the spike schema (`SpikeDatabase.cs:79-115`) with these changes:
  - `application_id` has no FK.
  - `authorization` gains `user_session_id uuid NOT NULL` with a composite FK to `user_session`. That is the AD-13 Token Family anchor.
  - `token.authorization_id` keeps its composite FK to `authorization`.
  - `token` stores only OpenIddict's obfuscated (hashed) `reference_id`, unique per Tenant, never a raw value.
- **Grants:** `gk_hosted` gets `SELECT, INSERT, UPDATE` on `user_session`, `signin_transaction`, `authorization` and `token`, and `SELECT` on `"user"`. Other roles get only what an existing or in-story caller needs, and the reason for each extra grant goes in a registry comment.
- **Command rules:**
  - Each new contract method is `[StateChanging]`, takes a `CommandContext` and requires `context.TenantId` to be non-null.
  - It writes its row and one audit event in that same context. The codes are `authentication.signin_transaction.started` (actor `Anonymous`) and `sessions.session.started` (actor `User(userId)`, target `User`).
  - Each returns its cookie value as `Secret<string>`: base64url of 32 random bytes from a CSPRNG.
- **Lifetimes:** they come from one new Kernel limits file holding only what this story uses: the sign-in transaction lifetime of 30 minutes, the expired-row retention of 1 hour, and the Session idle and absolute defaults of 3 days and 7 days. Callers pass a `TimeProvider`.
- **`AuthenticationResult`:** the Session ID, the user ID, `amr` and `auth_time`.

**Never:**
- No Directory `application` table, OpenIddict stores, endpoints or cookies written to HTTP responses. Those belong to Stories 2.5, 2.7, 2.9 and 4.2.
- No revocation API. `RevokeAccess` is Story 2.7.
- No test authenticator, or any code that returns an `AuthenticationResult` without a real factor, under `src/`.
- No raw session or transaction identifier is stored or logged.
- The spike tests stay unchanged.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Begin | Tenant scope A, Application ID, parameters | One `signin_transaction` row in A with `application_id`, `binding_hash` = SHA-256 of the returned value, `expires_at` = now + 30 minutes, and one audit event | No error expected |
| Begin without Tenant | `CommandContext` with a null `TenantId` | Nothing is written | `InvalidOperationException` |
| Cross-Tenant read | A row in A, read under Tenant scope B as `gk_hosted` | No rows | No error expected |
| Test authenticator | Minimal `user` seeded in A, transaction begun | `AuthenticationResult` whose Session row exists, with `id_hash` = SHA-256 of the returned Session value, `amr` and `auth_time` as given, and expiry from the limits | No error expected |
| Unknown user | User ID not in A (or only in B) | No Session row | FK violation surfaces as an exception; the scope rolls back |
| Bad hash length | Direct insert of a 31-byte hash | Rejected | Check violation |

</intent-contract>

## Code Map

- `src/Adapters/Postgres/Migrations/Migration20261102000000CreateTenantTables.cs:6-57` -- the pattern for a migration: attributes, one `Sql`, the RLS pair at :32-43, grants, and a `Down` that throws. The next timestamp is `20261102080000`.
- `src/Adapters/Postgres/Migrations/Migration20261102030000CreateOperationTables.cs:79-84` -- the column-grant pattern.
- `src/Adapters/Postgres/Schema/TableRegistry.cs:19-25,33-44,61-217` -- `TableEntry` and the role constants. Add five entries.
- `tests/Isolation/CatalogueAudit.cs:14,344-422` and `tests/Isolation/CatalogueTests.cs:23,32` -- checks for the RLS expression, `tenant_id` and FKs, and that registry owners are real modules.
- `tests/Isolation/Spikes/OpenIddict/SpikeDatabase.cs:79-115` -- the working schema for `authorization` and `token`.
- `src/Gatekeep.Kernel/Persistence/` -- the persistence API: `TenantScope.BeginAsync` (:26), `CommandScope.CreateCommandContext`/`CommitAsync`, `CommandContext.CreateCommand` and `TenantId`, and `StateChangingAttribute`.
- `src/Gatekeep.Kernel/Audit/IAuditAppender.cs:9-17`, `AuditEvent.cs:3-18` and `AuditTypeCode.cs` -- the audit API.
- `src/Modules/Audit/Contracts/AuditContract.cs:8-13` -- how to obtain the appender.
- `src/Gatekeep.Kernel/Secrets/Secret.cs:13,27` -- the type that wraps the returned cookie values.
- `src/Modules/{Authentication,Sessions,Identity}/{Contracts,Core,Adapters}/*.cs` -- each module holds only placeholder static classes today. Follow the Operations module's pattern:
  - a public interface and records in `Contracts/`
  - a static `XContract.CreateX()` factory (`Operations/Contracts/OperationsContract.cs:30`)
  - an internal implementation in `Core/` or `Adapters/`
- `tests/Architecture/module-edges.txt`, `ModuleEdgeTests.cs:36,94,119,146` -- the boundary rules:
  - Authentication → Sessions is allowed. Sessions → Identity is not.
  - Add `dependency Tests.Isolation -> Authentication`, `-> Sessions` and `-> Identity`, plus the matching project references, then regenerate the diagram with `dotnet run --project tests/Architecture/Generator`.
- `tests/Architecture/PersistenceRuleTests.cs:108,131` -- each `[StateChanging]` method takes a `CommandContext`, and contracts may not name scopes.
- `tests/Isolation/PostgresFixture.cs:66,70,77` -- a migrated clone per test, plus superuser and role connections.
- `tests/Isolation/TenantBehaviourTests.cs:26,48,83,181` -- the behaviour-test patterns for RLS and grants.
- `tests/Isolation/AuditTests.cs:65-71` -- the pattern for writing state and audit together in one context.
- `tests/Isolation/Custody/CustodyTestDoubles.cs:7` -- the `FrozenTime` fake clock.

## Tasks & Acceptance

**Execution:**
- `src/Gatekeep.Kernel/Limits/Limits.cs` -- add the four lifetime constants with spine and PRD references -- the one-file rule for limits.
- `src/Adapters/Postgres/Migrations/Migration20261102090000CreateSessionTables.cs` -- create the five tables, RLS and grants in dependency order: `"user"`, `user_session`, `authorization`, `token`, `signin_transaction` -- the tables.
- `src/Adapters/Postgres/Schema/TableRegistry.cs` -- add the five entries with their owners and grants -- keeps the catalogue green.
- `src/Modules/Sessions/Contracts/` (`ISessions.cs`, `SessionsContract.cs`) and `Core/` -- add `ISessions.StartAsync(CommandContext, NewSession(UserId, Amr, AuthTime, ConnectionId?), TimeProvider-based expiry, CancellationToken)`, which returns `StartedSession(SessionId, Secret<string> Token, …)` and writes the row plus audit -- Sessions owns `user_session`.
- `src/Modules/Authentication/Contracts/` (`IAuthentication.cs`, `AuthenticationResult.cs`, `AuthenticationContract.cs`) and `Core/` -- add `IAuthentication.BeginAsync(CommandContext, SignInRequest(ApplicationId, Parameters), CancellationToken)`, which returns `StartedSignIn(TransactionId, Secret<string> Binding)` and writes the row plus audit -- AD-8 `Begin`.
- `tests/Architecture/module-edges.txt`, `tests/Isolation/Gatekeep.Tests.Isolation.csproj`, the generated diagram and the lock file if it changes -- let the tests reach the new contracts.
- `tests/Isolation/Sessions/TestOnlyAuthenticator.cs` -- given a transaction and a seeded user ID, call `ISessions.StartAsync` and return an `AuthenticationResult`. Under `tests/` only.
- `tests/Isolation/Sessions/SessionTablesTests.cs` -- one test per I/O matrix row, plus the cross-Tenant RLS read and write refusal for each of the five tables and a grant check per role -- the proof.
- `_bmad-output/implementation-artifacts/sprint-status.yaml` -- set `2-6-…` to `done` at the end -- tracking.

**Acceptance Criteria:**
- Given `IAuthentication.Begin`, when it runs in Tenant A's scope, then one `signin_transaction` row exists in A, bound to the hash of the returned browser value, Tenant A and the given Application ID, and the transaction commits with its audit event.
- Given a minimal `user` row seeded in a test, when the test-only authenticator runs, then it returns an `AuthenticationResult` whose Session is a committed `user_session` for that user.
- Given the migrated database, when the catalogue test runs, then all five tables match the registry (RLS, grants and FKs), and `TestOnlyAuthenticator` exists only under `tests/` (the release-build check is Story 2.9's).
- Given the full suite, when it runs in Docker with locked restore, then the architecture and isolation tests pass, including the spike tests.

## Spec Change Log

## Review Triage Log

### 2026-11-03 — Review pass
- verdicts: 32 findings — high 0, medium 2, low 18, false 12, maybe-false 0
- findings:
  - `low` `reject` (blind) `gk_hosted` has table-wide UPDATE — the spec sets table grants. Narrowing them to columns needs the columns OpenIddict's stores update, which Story 2.9 defines. Recorded in `deferred-work.md` for Story 2.9.
  - `false` `reject` (blind) `idle_expires_at <= absolute_expires_at` breaks sliding renewal — no code slides yet. A later unclamped slide fails loudly with 23514, which is the intended invariant.
  - `medium` `patch` (blind) Anonymous `Parameters` are unbounded — `BeginAsync` now refuses a null value, a NUL character, or more than 16 KiB of JSON before writing, with tests.
  - `low` `reject` (blind) `NewOpaqueValue` is duplicated in two modules — each module issues and looks up only its own cookie, so the copies can't drift between issue and lookup. A shared Kernel helper would add public surface for 10 lines.
  - `low` `patch` (blind) `ExpiredSignInTransactionRetention` is unused — deleted.
  - `low` `reject` (blind) The start audit events carry no transaction, Session or Application ID — `AuditDetail` only holds IP, User-Agent and email, and `AuditTargetKind` has no Session or Application kind. Adding one is new envelope surface, and Story 2.7 decides the Session audit shape.
  - `low` `patch` (blind) Stored and returned times differ below a microsecond — `now` and `AuthTime` are now truncated to microseconds before they are stored and returned, with a test.
  - `low` `reject` (blind) Indexes for OpenIddict lookups and expiry scans are missing — those queries arrive with the Story 2.9 stores and the pruning job. Adding the indexes now is speculative.
  - `medium` `patch` (blind) Tests for the UPDATE `WITH CHECK` cross-Tenant case and for the argument guards are missing — grouped with the verification-gap guard tests. Tests added.
  - `false` `reject` (blind) `AuthenticationResult` isn't tied to its transaction — AD-8 defines the result as the Session, `amr` and `auth_time`. Binding it to the transaction is Protocol's job in Story 2.9.
  - `low` `reject` (blind) The `reference_id` check is tied to OpenIddict's obfuscated form — 7.7.2 outputs base64 SHA-256 (44 characters), which the check accepts. An upgrade that changes the form fails loudly on insert. Recorded in `deferred-work.md` for Story 2.9 and upgrades.
  - `low` `patch` (blind) The `Tests.Isolation -> Identity` edge is unused — removed, and the diagram regenerated.
  - `false` `reject` (blind) Tracking says `in-progress`, not `done` — it is set to `done` at finalization.
  - `low` `patch` (blind) The file `Limits.cs` holds the type `SecurityLimits` — renamed to `SecurityLimits.cs`. The missing `end_reason` CHECK is left to Story 2.7, which defines the reasons.
  - `low` `patch` (verification-gap) No test covers the reserved-name fix in `CatalogueAudit` — a drift test with a single-column FK into `"user"` was added.
  - `low` `patch` (verification-gap) The argument guards are untested — tests added for an empty Application ID, an empty User ID and an `amr` entry that is only whitespace.
  - `low` `patch` (verification-gap) `ToUniversalTime` is tested only with UTC input — a +02:00 test was added.
  - `low` `patch` (verification-gap) Four CHECK constraints are never exercised — a 23514 test was added for each.
  - `low` `patch` (edge) A NUL character in a parameter aborts the scope — grouped with the `Parameters` guard.
  - `low` `patch` (edge) A null value or an unbounded number of parameters — grouped with the `Parameters` guard.
  - `low` `reject` (edge) A default or future `AuthTime` — the only callers pass a real authentication time. A guard adds a branch for a case no caller reaches yet, and Story 4.2 owns real sign-in times.
  - `low` `patch` (edge) Ticks below a microsecond — grouped with the truncation fix.
  - `low` `reject` (edge) `ConnectionId` can be `Guid.Empty` — no caller passes a Connection yet, because Connections arrive in Epic 4.
  - `low` `reject` (edge) `amr` with duplicate or unbounded entries — the values come from Gatekeep's own authenticators, never from the caller.
  - `low` `patch` (edge) `TestOnlyAuthenticator` accepts an expired transaction — it now requires `expires_at` later than now, with a test.
  - `low` `reject` (edge) CHECKs for `created_at < idle_expires_at` and `auth_time <= created_at` are missing — only `SessionService` writes these columns, and it computes them from one clock. The extra constraints would guard no observed state.
  - `false` `reject` (edge) A `relname` collision across schemas — every Gatekeep table is in `public`, and the catalogue reads only that schema.
  - `false` `reject` (edge) Tracking says `in-progress` — same as the blind-hunter row above.
  - `false` `reject` (edge) Other roles are checked only for SELECT — `Migrated_database_matches_the_registry` compares every grant with the registry in both directions, so an extra INSERT or UPDATE grant fails that test.
  - `false` `reject` (intent) The unused retention constant — the same as the blind-hunter row, and patched there.
  - `false` `reject` (intent) Tracking status — the same as the rows above.
  - `false` `reject` (intent) No cookie, HTTP or Protocol caller, and no transaction link in the result — the spec's Never list and AD-8 put cookies in Story 4.2 and Protocol in Story 2.9. The intent's acceptance criteria are met at the contract surface.

## Design Notes

**Why `authorization.user_session_id` is `NOT NULL`.** AD-13 makes every Token Family an ad-hoc authorization anchored to exactly one Session. Client Credentials (2.5) creates no authorization, so nothing legitimate needs a null anchor. Story 2.9's store sets the anchor from the `AuthenticationResult`.

**Why access and ID token rows are kept.** OpenIddict's `DisableTokenStorage` is all-or-nothing, and its revocation and reuse logic reads rows by authorization. Story 2.9 can revisit this once real traffic exists.

**The `application_id` foreign keys come later.** Story 2.5 adds `(tenant_id, application_id) REFERENCES application (tenant_id, id) ON DELETE RESTRICT` on `signin_transaction`, `authorization` and `token` in its own migration. Record this in `deferred-work.md` so Story 2.5 picks it up.

## Verification

**Commands:**
- `docker build -t gatekeep/tests:epic2 -f deploy/docker/tests.Dockerfile .` -- expected: the image builds with locked restore.
- `MSYS_NO_PATHCONV=1 docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal --add-host host.docker.internal:host-gateway gatekeep/tests:epic2` -- expected: all architecture and isolation tests pass.

## Auto Run Result

**Summary.** Story 2.6 adds the tables and the first contracts that sign-in shares:
- **The migration.** `Migration20261102090000CreateSessionTables` creates `"user"` (Identity), `user_session`, `"authorization"` and `token` (Sessions), and `signin_transaction` (Authentication). Each is Tenant-class, with forced row-level security, the permissive and Tenant policy pair, `gk_hosted` grants and a `TableRegistry` entry. As the user decided, the `application_id` columns have no foreign key; Story 2.5 adds it, and `deferred-work.md` records that.
- **`IAuthentication.BeginAsync`.** It writes a `signin_transaction` bound to the SHA-256 of a returned 256-bit browser value, the Tenant and an Application ID, plus one audit event.
- **`ISessions.StartAsync`.** It writes a `user_session`, stores only the hash of its identifier, and writes one audit event.
- **`AuthenticationResult`.** It carries the Session ID, User ID, `amr` and `auth_time`.
- **`TestOnlyAuthenticator`.** It lives only under `tests/` and returns a result for a seeded User.

**Files changed**
- `src/Adapters/Postgres/Migrations/Migration20261102090000CreateSessionTables.cs`: the five tables, their checks, indexes, RLS and grants.
- `src/Adapters/Postgres/Schema/TableRegistry.cs`: five entries.
- `src/Gatekeep.Kernel/Limits/SecurityLimits.cs`: the sign-in transaction lifetime and the Session idle and absolute defaults.
- `src/Modules/Authentication/{Contracts,Core}`: `IAuthentication`, `SignInRequest`, `StartedSignIn`, `AuthenticationResult`, `AuthenticationContract` and `AuthenticationService`.
- `src/Modules/Sessions/{Contracts,Core}`: `ISessions`, `NewSession`, `StartedSession`, `SessionsContract` and `SessionService`.
- `tests/Architecture/module-edges.txt`, the Isolation csproj and `docs/architecture/module-dependencies.md`: the `Tests.Isolation -> Authentication` and `-> Sessions` edges.
- `tests/Isolation/Sessions/`: `TestOnlyAuthenticator` and `SessionTablesTests`.
- `tests/Isolation/CatalogueAudit.cs` and `CatalogueTests.cs`: foreign keys on reserved-name tables are now checked, with a drift test.
- `tests/Isolation/Jobs/JobGuardTests.cs` and `MigrateCommandTests.cs`: quoting for the reserved names, and the new migration count.
- `deferred-work.md` and `sprint-status.yaml`: the follow-ups and tracking.

**Review findings.** The four review layers reported 32 findings. 14 were patched, in 11 groups (2 medium and 9 low by group verdict), and none was deferred to the spec's `deferred` list. 12 were false. 6 low findings were rejected, with the reasons in the triage log. Two of the rejected lows are recorded as follow-ups in `deferred-work.md`:
- narrow the UPDATE grants to the columns that change
- confirm the `reference_id` check against real OpenIddict output

**Follow-up review: recommended (`true`).** Two medium groups were patched: the guard on anonymous `Parameters`, and the missing tests for the argument guards and the cross-Tenant UPDATE check. The unverified risk is that the `Parameters` guard (16 KiB, no NUL characters, no null values) has only been tried against hand-built dictionaries. It has never met a real authorize request from Story 2.9, and the cap could refuse a legitimate long `request_uri` or `claims` parameter.

**Verification**
- The `gatekeep/tests:epic2` image builds with locked restore.
- Before the patches, the full suite passed: 333/333 architecture and 1131/1131 isolation tests. An earlier run had failed one test with the known local IPv6 flake, and the rerun was green.
- After the patches, the full suite passed: 333/333 architecture and 1150/1150 isolation tests.
- Every row of the I/O matrix has a covering test that passed.

**Residual risks**
- Table-wide UPDATE grants for `gk_hosted`, until Stories 2.7 and 2.9 narrow them.
- The `reference_id` format check assumes OpenIddict 7.7.2's obfuscated form.
- Nothing ties `AuthenticationResult` to its transaction yet (Story 2.9).
- No cookie or HTTP wiring yet (Story 4.2).
- The `application_id` foreign keys wait for Story 2.5.
