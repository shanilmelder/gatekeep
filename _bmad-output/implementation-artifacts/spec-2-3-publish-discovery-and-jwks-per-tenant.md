---
title: 'Story 2.3: Publish discovery and JWKS per Tenant'
type: 'feature'
created: '2026-11-05'
status: 'done'
baseline_revision: 'c27d05c692a2c3e2be749f927091ce56121081ed'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-2-context.md'
  - '{project-root}/docs/spikes/2-1-openiddict-per-tenant.md'
  - '{project-root}/docs/spikes/2-2-openiddict-stores.md'
warnings: ['oversized']
deferred:
  - summary: >-
      The key backfill provisions every active Tenant in one job run, with no batch bound or lease renewal.
    evidence: |-
      TenantKeyBackfill.RunAsync loops over every active Tenant inside one job lease, and each Tenant needs up to four RSA-3072 Transit generations plus a wrap. A deployment with many pre-2.3 Tenants could outlive the lease on the first run and have the job reclaimed and repeated. Later runs only read. Settle it by measuring the first run against the job lease at a realistic Tenant count, or by fanning out one job per Tenant.
    location: >-
      src/Modules/Operations/Core/TenantKeyBackfill.cs
    severity: medium
  - summary: >-
      No test shows that concurrent cold requests share one Tenant runtime build.
    evidence: |-
      TenantRuntimes shares a build through GetOrAdd plus an ExecutionAndPublication Lazy, but every Protocol test sends requests one at a time. A regression to per-request builds would multiply Transit calls without failing a test. Story 2.5 must load-test this path before the token endpoint ships, so it belongs there.
    location: >-
      src/Modules/Protocol/Core/TenantRuntimes.cs
    severity: low
---

<intent-contract>

## Intent

**Problem:** Tenant hosts serve only a fixed 404. No production OpenIddict server, no `signing_key` table and no Signing Keys exist, so no library can discover a Tenant or trust its keys (FR-23, FR-8, FR-37, AR-21; AD-9, AD-10, AD-11). Stories 2.4, 2.5 and 2.9 build on this.

**Approach:** Add the `signing_key` and `protection_key_wrap` tables, owned by Keys. Add a Tenant creation stage that creates, per Tenant, a `current` and a `next` Transit key for each purpose (`signing`, `management`) plus the Transit-wrapped token protection key. Add a Worker backfill job that runs the same code for Tenants that lack them. Then host OpenIddict 7.7.2 on `Host.Hosted`, wrapped per Tenant as the Story 2.1 spike proved, serving only discovery and JWKS.

## Boundaries & Constraints

**Always:**
- **Ownership.** Keys owns both tables (AD-27). The registry entry, the RLS `ENABLE`/`FORCE` pair, the grants and `tenant_id` foreign keys go in the same migration. `gk_hosted` gets `SELECT` only. The Worker role gets only what provisioning needs.
- **`signing_key`.** A UUIDv7 `id`, then `tenant_id`, `purpose` (`signing`|`management`), `state` (`next`|`current`|`previous`|`retired`|`revoked`), Transit key name and version, `created_at`, and `published_at` (when the row first became visible in JWKS; null for `management`). CHECK constraints cover purpose and state. Partial unique indexes allow at most one `current` and one `next` per `(tenant_id, purpose)`.
- **`protection_key_wrap`.** One row per Tenant, holding the ciphertext from `IKeyCustody.CreateWrappedDataKeyAsync` on the existing `tpk-{tenantId}` key, plus `created_at`. Never plaintext.
- **Transit first, row second (AD-10).** Pre-generate the row ID, create `sig-{tenantId}-{rowId}` or `mgmt-{tenantId}-{rowId}` (RS256, RSA-3072), then insert the row in the step's `CommandContext`. Provisioning is idempotent. It creates only the missing keys, writes one audit event when it creates anything, and a rerun after any crash converges on exactly one `current` and one `next` per purpose. A new Tenant's keys start as `current` and `next` at once (AD-11), and the `signing` pair's `published_at` is set at insert.
- **One code path.** A Keys contract method (e.g. `KeysContract.EnsureTenantKeysAsync(context, custody, tenantId, ct)`) serves both the new `keys.signing` Tenant stage in `TenantCreation` (planned in `TenantManagement`, exposed via `OperationsContract`) and the backfill.
- **Backfill.** A scheduled Worker job, `keys.backfill_tenant_keys`, every hour. It finds active Tenants that lack keys or a wrap and provisions each in its own Tenant scope. A failure for one Tenant doesn't stop the others.
- **Hosted OpenIddict.**
  - `OpenIddict.AspNetCore`/`Server` move from test-only to production central versions, referenced by Protocol and Host.Hosted only.
  - Endpoints: `/.well-known/openid-configuration` and `/.well-known/jwks`. A token endpoint `/connect/token` with the client credentials grant is registered only because OpenIddict refuses to start without a flow (ID0076/ID0079). A Gatekeep handler refuses every token request with `unsupported_grant_type` until Story 2.5. Discovery must not advertise `token_endpoint` or any grant type until then.
  - The Tenant handler on `ProcessRequestContext` sits at order `int.MinValue`. It takes the `ResolvedTenant` from Tenancy's existing middleware, swaps in that Tenant's options copy, and sets `Issuer` from the stored issuer. `ResolveRequestUri` stays removed. Discovery and JWKS open no write transaction.
  - Per-Tenant options copies are built from `IOptionsFactory`, with `SigningCredentials` from Transit through `IKeyCustody`, `kid = {transitName}.v{version}`, and the unwrapped token protection key as the encryption credential. `IssuerSigningKeys`/`TokenDecryptionKeys` are set explicitly. A Tenant runtime is cached for at most 5 seconds (AD-11's JWKS exception) and is never cached when its build failed. Every custody call has a timeout.
  - Global credentials are inert and throw if used.
  - The RSA public key is built without PEM import (banned in `src/`): use SubjectPublicKeyInfo via `System.Formats.Asn1`, or modulus and exponent.
- **JWKS** holds only the resolving Tenant's `signing` rows in `next`, `current` or `previous`, with `Cache-Control: public, max-age=900`. A Tenant with no keys yet gets `{"keys":[]}`, and discovery still works.
- **Issuer.** It always comes from the stored `tenant.issuer`. `Host`, `X-Forwarded-*` and the request scheme or port never change it. An issuer with a path is rejected when the runtime is built.
- **Audit codes** go in a new `src/Modules/Keys/Contracts/KeysEvents.cs`, following `{domain}.{object}.{action}`. Regenerate `docs/audit-events.md` and the module diagram with `dotnet run --project tests/Architecture/Generator`.

**Never:**
- No other OIDC endpoint, no token issuance, no stores, and no Application rows (Stories 2.5 and 2.9).
- No rotation, retirement, destruction, orphan sweep or `NOTIFY` (Story 2.4).
- No `tenant.public_id` column. It is deferred to Story 2.9, which first needs it.
- No `management` key in JWKS, discovery or a Hosted options copy. Hosted's OpenBao policy can't read `mgmt-*` and must not be widened.
- No private key material, unwrapped protection key or ciphertext in logs, docs or test output.
- No changes to Story 2.1/2.2 spike tests other than keeping them green.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| New Tenant | Tenant creation Operation runs to success | 4 `signing_key` rows (current+next × signing+management), 4 distinct Transit keys of type `rsa-3072`, 1 `protection_key_wrap` row; Tenant active | No error expected |
| Stage rerun | `keys.signing` step runs twice, or crashes after creating 2 Transit keys | Still exactly one current and one next per purpose; the extra Transit keys are left as orphans for Story 2.4's sweep | No error expected |
| No custody | Worker without custody | Step fails with `custody_unavailable`; Tenant stays `creating` | Operation failure code |
| Backfill | Active Tenant with no keys (pre-2.3 data) | After one job run it has the full key set and a wrap. Tenants that already have them are untouched | Per-Tenant failure is logged, others continue |
| Discovery | `GET /.well-known/openid-configuration` on Tenant A's host | 200; `issuer` = A's stored issuer; `jwks_uri` under that issuer; no `token_endpoint` and no grant types | No error expected |
| JWKS | `GET /.well-known/jwks` on A | 200, `Cache-Control: public, max-age=900`; exactly A's `next`+`current` signing keys (and `previous` if a row is in that state), each `kty RSA`, `alg RS256`, `use sig`, `kid` = `{transitName}.v{n}`; no management key | No error expected |
| Forged host | A's host with `X-Forwarded-Host`/`X-Forwarded-Proto` set to something else, different port, or upper-case host | Issuer and `jwks_uri` unchanged, or 404 when Tenancy doesn't resolve | Unknown host → existing 404 |
| Two Tenants | JWKS of A and B | No shared `kid` or modulus | No error expected |
| Token endpoint | `POST /connect/token` any body | `unsupported_grant_type` protocol error, no store touched | Protocol error |
| Custody down | Hosted can't reach OpenBao building A's runtime | JWKS/discovery return 503; next request rebuilds (failed build not cached) | 503, no secret in log |

</intent-contract>

## Code Map

- `src/Gatekeep.Host.Hosted/Program.cs:19,23` -- `UseTenantResolution`, then routing, then the 404 `MapFallback`. Add OpenIddict after Tenant resolution. The fallback stays for every other path.
- `src/Modules/Tenancy/Adapters/TenancyAdapters.cs:22-28,79,85-97` and `Contracts/ITenants.cs:212` -- exact `tenant_host` match, the `ResolvedTenant(TenantId, Issuer, …)` request feature, 404 or 503. Read-only.
- `src/Modules/Tenancy/Core/TenantAddress.cs:46-48` -- the issuer is `https://{host}[:port]/`, an origin with a trailing slash.
- `src/Modules/Protocol/` -- placeholders only (`ProtocolContract.cs`, `ProtocolCore.cs`). The OpenIddict wiring goes here, following Contracts/Core/Adapters.
- `src/Modules/Keys/Contracts/KeysContract.cs:13-30` -- `CreateSecretClassKeysAsync`, the `tpk` class. `Adapters/KeysAdapters.cs` is a placeholder, and there is no Core yet.
- `src/Gatekeep.Kernel/Secrets/IKeyCustody.cs:36-99` -- `CreateKeyAsync` (idempotent, returns `KeyPublicVersion(int, PEM)`), `SignAsync`, `GetPublicKeysAsync`, `CreateWrappedDataKeyAsync`, `DecryptAsync`. `KeyName.cs:71-76` -- `Signing(t,row)`/`Management(t,row)`.
- `src/Adapters/OpenBao/OpenBaoKeyCustody.cs:98` -- `rsa-3072`.
- `deploy/openbao/policies/host-hosted.hcl`, `host-worker.hcl` -- already cover what's needed. Change nothing.
- `tests/Architecture/KeyCustodyRuleTests.cs:22` -- the PEM-import ban. Because custody returns PEM, decode the base64 SPKI body yourself or extend the adapter to give modulus and exponent.
- `src/Modules/Operations/Core/TenantCreation.cs:21-54` -- stage pattern. `src/Modules/Management/Core/TenantManagement.cs:67-72` -- step plan. `OperationsContract.cs:49-58` -- stage codes. `OperationRegistry.cs:111-155` (`OperationStepRun.Context`/`Custody`), `:243-247` (a type with a completion handler takes Tenant stages only). Steps fan out as separate jobs (`OperationJobs.cs:7-13`).
- `src/Gatekeep.Host.Worker/JobSchedule.cs:12-17` and `WorkerJobs.cs` -- the schedule entries and runner with custody. Look at how `OperationsContract.PurgeJobs` is defined and registered for the job pattern.
- `src/Adapters/Postgres/Migrations/Migration20261104030000ChangeTenantLabels.cs` -- latest. The new one is `Migration20261105000000CreateSigningKeyTables.cs`. Pattern: `Migration20261102000000CreateTenantTables.cs:32-52` (RLS pair and grants). `ForEachTenant.cs` is SQL-only with no custody, so it isn't usable for the backfill.
- `src/Adapters/Postgres/Schema/TableRegistry.cs` -- add two entries owned by Keys.
- `tests/Isolation/MigrateCommandTests.cs:20,28` -- 17 → 18.
- `tests/Isolation/Spikes/OpenIddict/SpikeServer.cs:39-42,77-218` and `SpikeSigning*`/credential files there -- the proven per-Tenant options, Transit signing credential and first handler to port into `src/`.
- `tests/Architecture/module-edges.txt` -- Host.Hosted → Protocol, Protocol → Keys/Tenancy and Operations → Keys are allowed. Add only the edges you need, and regenerate.
- `Directory.Packages.props:20-22` -- OpenIddict marked "Test only". `packages.lock.json` of every touched project gets a locked restore.
- `tests/Isolation/Custody/OpenBaoFixture.cs:13-60` (collection `"OpenBao"`, roles `host-hosted`/`host-worker`), `tests/Isolation/Operations/TenantCreationOperationTests.cs`, `tests/Isolation/Tenancy/TenantResolutionTests.cs`, `tests/Isolation/PostgresFixture.cs:66,70,77` -- test patterns to reuse.

## Tasks & Acceptance

**Execution:**
- `src/Adapters/Postgres/Migrations/Migration20261105000000CreateSigningKeyTables.cs`, `TableRegistry.cs`, `MigrateCommandTests.cs` -- the two tables, constraints, RLS, grants and registry entries, with the count bumped to 18.
- `src/Modules/Keys/{Contracts,Core,Adapters}` -- `EnsureTenantKeysAsync`, a read API for published signing keys and the wrap (used by Protocol as `gk_hosted`), the SPKI-to-RSA decoding, and `KeysEvents.cs`.
- `src/Modules/Operations/Core/TenantCreation.cs`, `Management/Core/TenantManagement.cs`, `OperationsContract.cs` -- the `keys.signing` stage, before activation.
- Operations job definition + `src/Gatekeep.Host.Worker/JobSchedule.cs` -- the hourly backfill job.
- `src/Modules/Protocol/**`, `src/Gatekeep.Host.Hosted/Program.cs` + csproj, `Directory.Packages.props`, lock files -- the OpenIddict server, the Tenant handler, per-Tenant runtime cache, inert global credentials, the token-endpoint refusal, the discovery trim and the JWKS `Cache-Control`.
- `tests/Architecture/*` -- a test that the Tenant handler is first at `int.MinValue` and `ResolveRequestUri` is removed, plus edges and diagram regenerated.
- `tests/Isolation/Keys/*`, `tests/Isolation/Protocol/*` -- at least one test per I/O matrix row, against real Postgres and OpenBao (`"OpenBao"` collection). Hosted endpoints run through `TestServer` or the existing host harness, and the global-credential test asserts that inert keys never reach a JWKS.
- `docs/audit-events.md` -- regenerated.
- `_bmad-output/implementation-artifacts/sprint-status.yaml` -- `2-3-…` set to `done` at finalize.

**Acceptance Criteria:**
- Given the Architecture and Isolation suites, when they run in Docker with locked restore, then all pass, including Story 2.1/2.2 spike tests.
- Given a Hosted options copy for any Tenant, when its credentials are inspected, then none is the global inert credential, and no `mgmt-` key name appears.
- Given the RLS catalogue checks, when they run, then `signing_key` and `protection_key_wrap` pass the same checks as other `tenant`-class tables, and `gk_hosted` can't write either.

## Spec Change Log

## Review Triage Log

### 2026-11-05 — Review pass
- verdicts: 39 findings — high 0, medium 6, low 23, false 10, maybe-false 0
- findings:
  - `false` `reject` (blind) The diff leaves out `docs/audit-events.md` and three lock files — the review diff excluded them on purpose. The files are changed in the working tree and committed with the story.
  - `medium` `patch` (blind) An expired Tenant runtime keeps the unwrapped token protection key in memory until that Tenant is asked for again — each entry is now evicted when its lifetime ends, with a test.
  - `low` `reject` (blind) `EnsureTenantKeysAsync` could create a `current` that was never published as `next` when only `current` is missing — no committed state lacks a `current`, because AD-11 holds at commit and nothing rotates yet. Carried to Story 2.4 as a residual risk: rotation and revocation must keep the invariant, or the backfill must create only `next`.
  - `medium` `patch` (blind) The backfill reports `done` when Tenants failed — it now throws after the loop, so the job records a failure and retries.
  - `medium` `defer` (blind) The backfill runs every Tenant in one job lease with no bound — deferred, with what would settle it.
  - `low` `patch` (blind) `published_at` can be NULL on a published signing row — a CHECK now requires it for `signing` rows.
  - `low` `reject` (blind) `gk_hosted` can read `management` rows — it sees only row names and versions, never key material. OpenBao's Hosted policy refuses every `mgmt-*` use, and the architecture rule bans naming a Management key on the Hosted path. A per-role RLS policy would add a catalogue exception for no reachable harm.
  - `low` `patch` (blind) Public-key parsing accepts any modulus size — the runtime build now refuses anything but a 3072-bit modulus.
  - `low` `patch` (blind) The reader's `PublicationOnly` Lazy can leak data sources — changed to `ExecutionAndPublication`.
  - `low` `reject` (blind) Discovery returns 503 when custody is down — JWKS is down then too, so no client could use the discovery document alone. Serving discovery from the global options would need a second runtime path past the inert-credential backstop.
  - `low` `reject` (blind) The runtime build is sequential, at worst about 25 s — every call is already bounded, and parallel fetches plus an overall deadline add complexity on a path with no traffic before Story 2.5's load test.
  - `medium` `patch` (blind) Tests are missing for the advisory lock, the shared build, the order of the two stages and rollback masking — the lock test was added (with the verification-gap row). The shared-build test is deferred to Story 2.5. Either stage order is already covered by the creation tests. Rollback masking is rejected below (edge).
  - `low` `reject` (blind) The provisioned audit event has no detail — the event is a fact with a `system` Actor. Its detail would be optional counts, and the "names no key" rule is met either way.
  - `medium` `patch` (blind) Uncaught build exceptions become 500s — the Tenant handler now turns every non-cancellation failure into the fixed 503, logging only the type.
  - `low` `patch` (blind) An empty JWKS is cacheable for 15 minutes — it is now `no-store`.
  - `low` `patch` (edge) Expired entries stay in memory — grouped with the eviction patch.
  - `low` `reject` (edge) An expired entry with a build still in flight starts a second build every 5 s during a stall — each custody call is bounded at 5 s, so at most about one extra build overlaps per window. Guarding it adds a branch for a stall case only.
  - `low` `patch` (edge) A wrong-length protection key throws `ArgumentException`, giving a 500 — grouped with the catch-all 503 patch.
  - `low` `patch` (edge) `ArgumentException` isn't in the caught set — grouped with the catch-all 503 patch.
  - `low` `reject` (edge) A malformed stored issuer answers 503 on non-endpoint paths — unreachable: issuers are written only by `TenantAddress.For` as origins, and triggers make them immutable.
  - `low` `patch` (edge) An empty JWKS is cached — grouped with the `no-store` patch.
  - `low` `patch` (edge) `SignBlocking` relies on custody honouring cancellation — `.WaitAsync(limit.Token)` added.
  - `low` `reject` (edge) A Transit signature longer than the destination throws in `CopyTo` — an RS256 signature is always the modulus length, and Wilson sizes the buffer from it. Unreachable, and guarding it adds a branch.
  - `low` `patch` (edge) The reader's Lazy race — grouped with the `ExecutionAndPublication` patch.
  - `low` `reject` (edge) A failed `ROLLBACK TO SAVEPOINT` masks the custody error — only a connection-level failure gets there, and the step then fails as `handler_failed` and retries, so nothing is lost. Masking the error would need another try/catch.
  - `medium` `patch` (verification-gap) The hourly schedule entry is checked only as source text — `WorkerStartupTests` now runs the real Worker and sees the backfill job reach `done`.
  - `low` `patch` (verification-gap) No test shows a failed key read giving the fixed 503 — `Key_read_failure_is_a_503` added.
  - `low` `defer` (verification-gap) No test that concurrent requests share one build — deferred to Story 2.5's load test, as the layer proposed.
  - `low` `patch` (verification-gap) The advisory lock is untested — `Concurrent_provisioning_of_one_Tenant_creates_one_set` added.
  - `low` `patch` (verification-gap, other) The lease-expiry test may hang the wrong step — it now hangs the `keys.signing` step deterministically.
  - `false` `reject` (intent) Only the test pipeline exercises the host — `TenantResolutionTests` starts the real Host.Hosted process and asserts discovery (stored issuer, `jwks_uri`) and an empty JWKS. Compose gives Hosted custody.
  - `false` `reject` (intent) The diff reads "forged Host" as "can't produce a non-stored issuer" — with host-based tenancy that is the only coherent reading. The tests cover forwarded headers, scheme, port and case.
  - `false` `reject` (intent) No test stores an issuer that differs from the host — the scheme and port variants already tell stored from derived (an `http://`/`:8443` request still gets `https://host/`).
  - `false` `reject` (intent) No single test goes from creation to JWKS — both halves go through the one `EnsureTenantKeysAsync` contract, and the creation tests assert the rows JWKS serves.
  - `false` `reject` (intent) `previous` is tested only with hand-inserted rows — nothing produces `previous` before Story 2.4's rotation, which the spec excludes.
  - `false` `reject` (intent) The hourly backfill leaves a window — a schedule entry is due as soon as no job of its type exists, so the first Worker tick after deploy runs it.
  - `false` `reject` (intent) RS256 is untested for Management keys — they are `rsa-3072` Transit keys, and nothing signs with them until the Management API story.
  - `false` `reject` (intent) Discovery leaves out `authorization_endpoint`/`token_endpoint` — no flow is served yet. Advertising them would point libraries at endpoints that refuse, and Stories 2.5 and 2.9 add them.
  - `false` `reject` (intent) Scope goes beyond the intent — the refusing token endpoint, inert credentials, runtime cache and timeouts are what OpenIddict and AD-8/AD-10 require to serve discovery and JWKS at all.

## Design Notes

OpenIddict needs one enabled flow, and that flow needs the token endpoint. A refusing handler placed before OpenIddict's own token validation keeps that endpoint inert until Story 2.5 replaces it. OpenIddict's token handlers would otherwise need the managers, which have no stores yet. A discovery handler that removes the token endpoint and grant types stops clients from trying it.

Discovery and JWKS only read. Build the runtime from a short read-only Tenant scope as `gk_hosted`, then cache it per Tenant for at most 5 seconds. Don't keep a connection open through OpenIddict's pipeline, unlike the spike (2-2 carry-over).

Use a fake or fixed clock where `created_at`/`published_at` matter. Never rely on wall-clock waits.

## Verification

**Commands:**
- `docker build -t gatekeep/tests:epic2 -f deploy/docker/tests.Dockerfile .` -- expected: builds with locked restore. Don't use the shared `gatekeep/tests:local` tag.
- `MSYS_NO_PATHCONV=1 docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal --add-host host.docker.internal:host-gateway gatekeep/tests:epic2` -- expected: all architecture and isolation tests pass.

## Auto Run Result

**Summary.** Each Tenant now has its own OpenID Provider on Host.Hosted. OpenIddict 7.7.2 is wrapped per Tenant and serves only discovery and JWKS. The issuer comes from the stored Tenant record. JWKS holds only that Tenant's `next`, `current` and `previous` signing keys, with `Cache-Control: public, max-age=900`, or `no-store` while the key set is empty. A new `keys.signing` Tenant creation stage, and the hourly `keys.tenant_keys.backfill` job for existing Tenants, both call `KeysContract.EnsureTenantKeysAsync`. That method creates a `current` and a `next` RSA-3072 Transit key for each of `signing` and `management`, plus the Transit-wrapped token protection key. Each Transit key is created first and its row committed after, under a per-Tenant advisory lock. The token endpoint is registered only because OpenIddict requires a flow. It refuses every request with `unsupported_grant_type` until Story 2.5, and discovery doesn't advertise it. The global credentials are inert and throw if used.

**Deviations from the spec**
- The backfill job is named `keys.tenant_keys.backfill`, because job types must follow `{domain}.{object}.{action}`.
- `EnsureTenantKeysAsync` also takes the `IAuditAppender`, so Keys gains no edge to Audit.
- The `keys.signing` stage creates `tpk-` itself as well, because the two creation steps run as separate jobs in either order.

**Files changed**
- `Migration20261105000000CreateSigningKeyTables.cs`, `TableRegistry.cs` -- `signing_key` and `protection_key_wrap` with RLS, grants (`gk_hosted` SELECT; `gk_worker` SELECT and INSERT), CHECKs, one-current and one-next indexes, and the re-rendered job guard.
- `src/Modules/Keys/**` -- provisioning, read APIs, SPKI/PKCS#1 decoding with `System.Formats.Asn1`, and `KeysEvents` (`keys.tenant_keys.provisioned`).
- `src/Modules/Operations/Core/{TenantCreation,TenantKeyBackfill,ProductionJobs,JobRunner,OperationStore}.cs`, `OperationsContract.cs`, `TenantManagement.cs`, `Host.Worker/JobSchedule.cs` -- the stage, the step plan and the hourly job.
- `src/Modules/Protocol/**`, `Host.Hosted/Program.cs` and csproj, `Directory.Packages.props`, lock files -- the OpenIddict server, Tenant handler, runtime cache with timed eviction, Transit signing key, inert credentials, token refusal, trimmed discovery and JWKS caching.
- `SecurityLimits.cs` -- runtime lifetime, JWKS max-age and custody call timeout.
- Tests -- `tests/Isolation/Keys/TenantKeysTests.cs`, `tests/Isolation/Protocol/*`, `tests/Architecture/ProtocolRuleTests.cs`, `WorkerStartupTests`, canary reasons, and updated creation, resolution, migrate and operation tests.
- `docs/audit-events.md`, `docs/architecture/module-dependencies.md`, `module-edges.txt` -- regenerated.

**Review findings.** There were 39 findings: 21 patched in 13 groups, 2 deferred (backfill bound, shared-build test), and 16 rejected (10 false, 6 low not worth fixing). The reasons for each are in the triage log.

**Follow-up review: recommended (`true`).** Five medium entries were patched:
- runtime eviction
- backfill failure reporting
- the missing tests group
- the catch-all 503
- the schedule test

None were high. The unverified risk is the new timer-based runtime eviction. It uses `TimeProvider` timers and races with in-flight builds and request-driven removal. Only one manual-clock test covers it, so a second pass should confirm that no entry, and so no unwrapped protection key, outlives its lifetime when builds and evictions interleave.

**Verification**
- Before the patches, the full Docker suite (`gatekeep/tests:epic2`, locked restore) passed Architecture 595/595. Isolation had 16 failures: 10 canary surface failures from the new job type, the creation test that expected one step, and 5 load timeouts. All were then fixed.
- After the patches, the full suite passed Architecture 595/595 and Isolation 2253/2256. The 3 failures were 15–23 s connection timeouts under shared-Docker load (AuditTests, FreshAssertionTests, JobGuardTests). Rerun alone, those three tests passed (30/30 cases).
- The matrix audit found a covering test for every I/O matrix row, and each one ran and passed.

**Residual risks**
- Signing through Transit isn't reachable yet. It needs Story 2.5's load test.
- The first backfill run is unbounded (deferred).
- `gk_hosted` can read the names of `management` rows, but OpenBao refuses their use.
- Discovery returns 503 while custody is down.
- There is no `tenant.public_id` yet (Story 2.9).
- There is no `NOTIFY` cache clear yet (Story 2.4).
- OpenIddict's ASP.NET Core integration brings in DataProtection, which may log a warning about its key store in the read-only Hosted container. That hasn't been checked in the real stack.
