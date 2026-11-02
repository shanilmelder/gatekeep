---
title: 'Story 2.2: Prove custom stores and revocation commit'
type: 'chore'
created: '2026-11-02'
status: 'done'
baseline_revision: 'dde33b1565d37fe6721b98a8c743b08a9f8b8584'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-2-context.md'
  - '{project-root}/docs/spikes/2-1-openiddict-per-tenant.md'
warnings: ['multiple-goals', 'oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** AD-8 and AD-13 assume several things about OpenIddict 7.7.2:
- Custom stores can hold Applications, authorizations and tokens on Gatekeep's own transaction.
- Each completed code flow creates exactly one ad-hoc authorization, the Token Family.
- A refused refresh still commits its revocation.

None of this has run. Story 2.1 proved options and signing in degraded mode with no stores. Story 2.3 onward depends on these points (AR-2, AR-22).

**Approach:** Extend the Story 2.1 spike. Turn degraded mode off and back OpenIddict's Application, authorization and token stores with spike tables in a cloned, migrated PostgreSQL database under row-level security. Run every store write in the request's `CommandContext`. Record `pass` or `fail` for each proof in `docs/spikes/2-2-openiddict-stores.md`, naming the test that proves each row. If a proof fails, amend AD-8 (and AD-13 where the transaction proofs fail) before closing.

## Boundaries & Constraints

**Always:**
- **Location.** Everything is test-only, under `tests/Isolation/Spikes/OpenIddict/`. Story 2.1's spike tests must keep passing, unchanged or only adapted to the shared server.
- **Spike tables.** `spike_application`, `spike_authorization` and `spike_token` are created by the spike in a database from `PostgresFixture.NewMigratedDatabaseAsync()`. Each has `tenant_id` and the same `ENABLE`/`FORCE` RLS policy pair as the migrated tenant tables. Each grants only what `gk_hosted` needs, and the request path connects as `gk_hosted`.
- **Tenants.** Each Tenant has a `tenant` row and a public ID (in memory in the spike, because `tenant` has no `public_id` column yet).
- **Store transaction.** The first Gatekeep handler opens a `TenantScope` for the resolved Tenant, and every store call runs through that request's `CommandContext`. A successful request commits at endpoint end. A rejected request rolls back.
- **Refused refresh.** Refresh reuse has no leeway (`RefreshTokenReuseLeeway` off). A reused refresh token revokes every token in its Token Family, and that revocation plus one audit event commit through `FailureContext.CommitAfterRollbackAsync`, even though the response is `invalid_grant`.
- **Kept settings.** OpenIddict entity caching is disabled. The scope store is unused. Client authentication is a Gatekeep handler that replaces `ValidateClientSecret` and checks a spike secret, and the Application's `ClientSecret` column stays null. Rolling refresh tokens and authorization storage stay on.
- **Reference IDs.** Authorization codes and refresh tokens are reference tokens whose returned value is `{tenantPublicId}.{random}`, with at least 256 random bits. A value with another Tenant's prefix is rejected before any store lookup.
- **Recording.** Each result is `pass` or `fail`. A failed proof keeps a test that asserts the observed failure, so CI stays green, and the doc records why. Packages follow central versions and the lock file, including `OpenIddict.Core` 7.7.2 for the managers.

**Never:**
- Nothing goes into `src/`.
- No production migrations, no `TableRegistry` entries, and no changes to OpenBao policies.
- No re-test of Story 2.1 proofs beyond keeping its tests green.
- No key material, token or secret value in the docs or test output.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| One authorization per flow | Code flow with `offline_access` on host A, then two refreshes | Exactly one `spike_authorization` row for that flow. Every token row references it. A second completed flow creates a second row | No error expected |
| Rotation | Refresh with a valid refresh token | A new refresh token is issued and the old one is marked redeemed | No error expected |
| Reuse commits revocation | The rotated (old) refresh token is presented again | `invalid_grant`. Afterwards, every token in that family is revoked in the database and one audit event is committed. The newest refresh token is then refused | Protocol error; the revocation survives the rollback |
| Revoked authorization | Authorization revoked in the database, then refresh | `invalid_grant`, no tokens | Protocol error |
| No entity cache | A row is changed directly in the database between two requests | The second request sees the change | No error expected |
| Confidential client, null secret column | Client Credentials with the right secret and with a wrong one | Right secret: token. Wrong secret: `invalid_client`. The stored `ClientSecret` stays null | Protocol error for the wrong secret |
| Reference ID form | Code and refresh token from host A | Both match `{publicIdA}.{random}` | No error expected |
| Cross-Tenant reference | A's refresh token presented on host B | `invalid_grant`, with no store lookup for that value under B | Protocol error |
| Failed request leaves no state | Token request rejected for another reason, such as a bad PKCE verifier | Nothing that request wrote remains (it rolled back) | Protocol error |

</intent-contract>

## Code Map

- `tests/Isolation/Spikes/OpenIddict/SpikeServer.cs` -- `StartAsync` sits at :61. The `AddServer` block (:77) is where `EnableDegradedMode` (:79) comes out and `AddCore` with the custom stores and `DisableEntityCaching()` goes in. `SelectTenantOptions` (:218, order `int.MinValue`) is the first handler: it opens the `TenantScope` and keeps it on `context.Transaction`. `ValidateSpikeTokenRequest` (:291) and `ValidateSpikeAuthorizationRequest` are the degraded-mode client checks, which the stores and the Gatekeep secret handler replace. `TenantRuntimes` is at :159.
- `tests/Isolation/Spikes/OpenIddict/SpikeTenants.cs` -- add a public ID per Tenant and insert the `tenant` row.
- `src/Gatekeep.Kernel/Persistence/TenantScope.cs:190` (`BeginAsync`), `CommandScope.cs:79,85,101` (`CreateCommandContext`, `CommitAsync`, rollback on dispose), `CommandContext.cs:20` (`CreateCommand`) and `FailureContext.cs:38` (`CommitAfterRollbackAsync`, 5 s limit) -- the request transaction and the commit-despite-error path. Read-only.
- `src/Gatekeep.Kernel/Audit/IAuditAppender.cs:12` and `AuditContract.CreateAppender()` -- the audit event for the reuse revocation. Usage example: `tests/Isolation/AuditTests.cs:35,59`, with helpers `Source(role, db)` at :816 and `TenantDatabaseAsync` at :819.
- `tests/Isolation/FailureContextTests.cs:21` -- reference pattern for a refused request that keeps its effect.
- `src/Adapters/Postgres/Migrations/Migration20261102000000CreateTenantTables.cs:32-52` -- the RLS policy pair and grant pattern for the spike tables to copy.
- `tests/Isolation/PostgresFixture.cs:66,70,77` -- a migrated clone per test, plus superuser and role connections. `CatalogueTests` checks only its own clone, so spike tables don't affect it.
- OpenIddict 7.7.2 source (local copy at `C:\Users\esm\AppData\Local\Temp\claude\D--Projects-Personal-gatekeep\2354d5d6-f399-4c84-bcb9-711f4f6b09bf\scratchpad\oi\x\openiddict-core-7.7.2\src`):
  - Store interfaces are in `OpenIddict.Abstractions/Stores/`.
  - `Protection.AttachTokenPayload` (`OpenIddictServerHandlers.Protection.cs:1782`, reference ID at :1845) is what to replace or follow for the `{publicId}.{random}` form. Watch the manager's `ObfuscateReferenceIdAsync` (`OpenIddictTokenManager.cs:1154`), which hashes the ID before the store sees it.
  - `ValidateTokenEntry` (:1207, reuse calls `RevokeByAuthorizationIdAsync` at :1255 inside a catch that only logs).
  - `ValidateAuthorizationEntry` (:1384).
  - `AttachAuthorization` (`OpenIddictServerHandlers.cs:3502`).
  - `RedeemTokenEntry` (:2992).
  - `ValidateClientSecret` (:1176), which fails on an empty stored secret.
  - `RefreshTokenReuseLeeway` defaults to 30 s (`OpenIddictServerOptions.cs:302`).
- `Directory.Packages.props`, `tests/Isolation/Gatekeep.Tests.Isolation.csproj`, `tests/Isolation/packages.lock.json` -- add `OpenIddict.Core` 7.7.2.
- `_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md:165-178` (AD-8), AD-13 and the Open Items row at :672 -- amend if a proof fails. Mark the Open Items row resolved either way, pointing at both spike docs.

## Tasks & Acceptance

**Execution:**
- `Directory.Packages.props`, the Isolation csproj and lock file -- add `OpenIddict.Core` 7.7.2 and restore with the lock file -- the custom stores need the managers.
- `tests/Isolation/Spikes/OpenIddict/SpikeDatabase.cs` -- create the three spike tables with RLS and grants in a migrated clone, insert both `tenant` rows, and expose `gk_hosted` and superuser sources -- this is the store backing.
- `tests/Isolation/Spikes/OpenIddict/Stores/` -- add Application, authorization and token stores over the request's `CommandContext`, with no scope store -- this is the custom-store proof.
- `tests/Isolation/Spikes/OpenIddict/SpikeServer.cs`, `SpikeTenants.cs` -- add a stores mode with degraded mode off. It covers the `TenantScope` opened in the first handler, commit at endpoint end and rollback on rejection, the reuse revocation and audit event through `FailureContext`, the Gatekeep client-secret handler, `{publicId}.{random}` reference IDs with the prefix check before lookup, no reuse leeway, PKCE `plain` removed, and entity caching disabled. Keep Story 2.1's tests green -- this is the spike build.
- `tests/Isolation/Spikes/OpenIddict/CustomStoresSpikeTests.cs` -- at least one test per I/O matrix row, in the `OpenBao` collection and using `PostgresFixture` -- these produce the records.
- `docs/spikes/2-2-openiddict-stores.md` -- outcome, a results table with the test for each row, what each proof showed, and carry-over for Stories 2.3, 2.6, 2.7 and 2.10 -- this is the spike record.
- `ARCHITECTURE-SPINE.md` -- if a proof failed, amend AD-8 and AD-13 as the evidence requires; in every case, mark the Open Items spike row resolved with links to both spike docs -- this meets the failure criterion.
- `_bmad-output/implementation-artifacts/sprint-status.yaml` -- set `2-2-…` to `done` -- tracking.

**Acceptance Criteria:**
- Given custom stores in the spike build, when a flow runs, then the spike doc records `pass` or `fail` for one ad-hoc authorization per flow and for a refused refresh committing its revocation, each naming a test that ran.
- Given a failed proof, when the spike ends, then AD-8 (and AD-13 where the failure concerns the transaction) is amended in `ARCHITECTURE-SPINE.md` before Story 2.3 starts, and the spike doc links the amendment.
- Given the full suite, when it runs in Docker, then the architecture and isolation tests pass with locked restore, including Story 2.1's spike tests.

## Spec Change Log

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 35 findings — high 0, medium 6, low 22, false 6, maybe-false 1
- findings:
  - `false` `reject` (intent) The stores aren't in Directory or Sessions adapters on production tables — the criterion says "in a spike build", and production ownership belongs to Stories 2.3, 2.6 and 2.7.
  - `false` `reject` (intent) There is no `user_session` anchor — that's Story 2.6, and the doc defers it.
  - `false` `reject` (intent) Authorization count is asserted for code flows only — "one ad-hoc authorization per flow" concerns code flows, because Client Credentials creates no authorization (AD-13).
  - `false` `reject` (intent) Late refusals roll back their redemption — this is recorded as a finding and carried over to Story 2.10, not claimed as a pass.
  - `false` `reject` (intent) Revocation doesn't go through `ISessions.RevokeAccess` — Story 2.7 builds that path; the spike proves the commit mechanism.
  - `low` `patch` (intent) The Open Items row overwrote its Blocks and Default columns — the original text is restored and the resolution appended.
  - `false` `reject` (intent) The entity-cache proof is recorded as a pass though weak — the doc already labels it "pass, but weak" and says why.
  - `medium` `patch` (blind) Reuse and replay revoke the tokens but leave the authorization row valid, while the doc says the family is revoked — this is OpenIddict's deliberate choice (Protection.cs, `ValidateTokenEntry`). The tests now assert the observed status, and the doc states it with a carry-over for Stories 2.7 and 2.10.
  - `low` `patch` (blind) Revocations through the authorization store aren't captured for replay — not reachable in today's flows; added to the doc's carry-over for Story 2.7.
  - `medium` `patch` (blind) An unhandled exception after a family was recorded loses the revocation — added to the doc as untested and carried over.
  - `low` `patch` (blind) `CommitAsync` leaks the scope when the commit throws — the scope is now disposed in a `finally`.
  - `low` `patch` (blind) Client-secret checking fails open on endpoints other than token — not reachable today (no such endpoint is enabled); added to the carry-over list.
  - `medium` `patch` (blind) The late-rejection test can pass with no writes — positive evidence of the writes added.
  - `low` `patch` (blind) The cross-Tenant test has no positive control on the probe — an assertion on B's own lookups added.
  - `low` `patch` (blind) The PKCE refusal test parses the body as a query string and never asserts the error — the `invalid_request` assertion added.
  - `medium` `patch` (blind) `ValidateGatekeepScopes` is untested — an unknown-scope test added, plus the handler assertion.
  - `low` `patch` (blind) The RLS check is incomplete — the restrictive-policy check and cross-Tenant visibility for all three tables added.
  - `low` `patch` (blind) The order of `RejectForeignReferenceIds` isn't asserted — assertion added.
  - `low` `patch` (blind) Every request opens a transaction, discovery and JWKS included — added to the carry-over for Story 2.3.
  - `low` `patch` (blind) The `SetProperty` call is dead — removed from the code and the doc.
  - `low` `patch` (blind) The code-path late refusal is untested — the doc now says so.
  - `medium` `patch` (verification-gap) The scope gate has no test — grouped with the unknown-scope test.
  - `low` `patch` (verification-gap, other) `Outcomes.Last()` passes spuriously on the second iteration — now compares counts.
  - `low` `reject` (edge) A non-GUID client in `RevokeAsync` drops the filter — OpenIddict passes only IDs this store issued, which are always GUIDs; the guard would add a branch for an unreachable case.
  - `low` `reject` (edge) A non-GUID client in `FindAsync` widens the filter — same reason.
  - `maybe-false` `reject` (edge) A request with no error but a recorded family would commit with no audit event — no successful path revokes a family in OpenIddict 7.7.2 (every revoke is followed by a rejection). To settle it, find a success path that calls `RevokeByAuthorizationIdAsync`. Low even if true.
  - `medium` `patch` (edge) A swallowed SQL error aborts the transaction, and COMMIT may roll back silently — added to the doc as untested, with the production requirement.
  - `low` `patch` (edge) Client secret on other endpoints — grouped with the carry-over bullet.
  - `low` `reject` (edge) `ValidTokenTypes` with mixed or empty types — no endpoint validating access tokens is enabled in the spike; unreachable.
  - `low` `patch` (edge) `Outcomes.Last()` — grouped with the count fix.
  - `low` `patch` (edge) The PKCE error isn't asserted without a redirect — grouped with the PKCE fix.
  - `low` `reject` (edge) A non-JSON body hides the status — affects diagnostics only, and the test still fails.
  - `low` `reject` (edge) `StartWithStoresAsync` leaks the data source when it fails — test harness only; the process ends.
  - `low` `reject` (edge) `SpikeDatabase` leaks on a seeding failure — same reason.
  - `low` `reject` (edge) Settings JSON holding non-string values — the spike writes only strings; unreachable.

## Design Notes

Reuse revocation runs inside OpenIddict's authentication phase. The request then rejects, so a rollback at endpoint end would lose it. `FailureContext` is the designed answer (AD-5, AD-13): roll back the request scope, then re-run "revoke the Token Family and append its audit event" in a fresh `TenantScope` and commit. The family to revoke must be captured before the rollback.

OpenIddict's own revoke call sits in a catch that only logs. If it fails on the request transaction, the transaction is left aborted (Postgres error 25P02). The spike should show which path actually commits.

Run every test with a fake or fixed clock where lifetimes matter. Never rely on wall-clock waits.

## Verification

**Commands:**
- `docker build -t gatekeep/tests:epic2 -f deploy/docker/tests.Dockerfile .` -- expected: the image builds with locked restore and the audit. Don't use the shared `gatekeep/tests:local` tag, because other checkouts overwrite it.
- `MSYS_NO_PATHCONV=1 docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal --add-host host.docker.internal:host-gateway gatekeep/tests:epic2` -- expected: all architecture and isolation tests pass, including `CustomStoresSpikeTests` and `PerTenantOptionsSpikeTests`.

**Manual checks (if no CLI):**
- `docs/spikes/2-2-openiddict-stores.md` has a result for every matrix row and no token or secret value.

## Auto Run Result

**Summary.** The Story 2.2 spike is test-only. It extends the Story 2.1 server with a stores mode: degraded mode off, and custom Application, authorization and token stores on `spike_*` tables in a migrated PostgreSQL clone under forced row-level security, used as `gk_hosted`. Every store call runs in the request's `CommandContext`. The request commits at endpoint end and rolls back when rejected, and a recorded Token Family revocation plus its audit event are committed again through `FailureContext`.

Every proof passed: one ad-hoc authorization per code flow, rotation, reuse committing its revocation, revoked-authorization refusal, entity caching off (weak proof), null `ClientSecret` with Gatekeep client authentication, `{publicId}.{random}` reference IDs, cross-Tenant refusal before lookup, and rollback of failed requests. AD-8 and AD-13 stand. The Open Items row is resolved.

**Files changed**
- `Directory.Packages.props`, the Isolation csproj and lock file -- add `OpenIddict.Core` 7.7.2.
- `tests/Isolation/Spikes/OpenIddict/SpikeDatabase.cs` -- the spike tables, RLS, grants, Tenant rows and seeded clients.
- `tests/Isolation/Spikes/OpenIddict/Stores/` -- the three stores, the request transaction and probe, the SQL helpers, and the Gatekeep handlers (scopes, client secret, reference IDs, prefix check, endpoint-end commit with `FailureContext`).
- `tests/Isolation/Spikes/OpenIddict/SpikeServer.cs`, `SpikeTenants.cs` -- `StartWithStoresAsync` and Tenant public IDs.
- `tests/Isolation/Spikes/OpenIddict/CustomStoresSpikeTests.cs` -- 15 tests.
- `docs/spikes/2-2-openiddict-stores.md` -- the spike record and carry-over.
- `ARCHITECTURE-SPINE.md` -- Open Items spike row resolved, with the original columns kept.
- `sprint-status.yaml` -- Story 2.2 set to done.

**Review findings.** There were 35 findings: 23 patched in 13 groups, none deferred, 6 false, and 6 low or maybe-false rejected (reasons in the triage log).

**Follow-up review: recommended (`true`).** Four medium groups were patched:
- the authorization row status
- the unhandled-exception and aborted-transaction notes
- the late-rejection evidence
- the scope gate

The unverified risk is that two failure paths are recorded as untested, not proven: an unhandled exception after a recorded revocation, and a swallowed SQL error before COMMIT. A second pass should confirm the doc's description of both, against Npgsql's behaviour on COMMIT of an aborted transaction.

**Verification**
- Before the patches, the full suite passed in Docker (image `gatekeep/tests:epic2`, locked restore): 287/287 architecture and 955/955 isolation tests.
- After the patches, the 26 spike tests passed.
- After the patches, the full suite passed: 287/287 architecture and 956/956 isolation tests.

**Residual risks**
- Concurrent refreshes with the same token are untested.
- `tenant.public_id` doesn't exist yet.
- Late refusals undo redemption (Story 2.10).
- The authorization row stays valid after reuse (Stories 2.7 and 2.10).
- Production needs failed-command tracking before reporting a commit.
- Everything ran on TestServer.
