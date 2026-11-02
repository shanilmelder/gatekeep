---
title: 'Story 1.20: Add the rate limiter and Admin CSP'
type: 'feature'
created: '2026-11-02'
status: 'done'
baseline_revision: 'ccae18cfd67eac2ef80908ccb341c87f55215f57'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-1-context.md'
  - '{project-root}/docs/threat-model.md'
warnings: ['oversized']
deferred:
  - summary: >-
      The Admin bundle is served with no caching policy, so a browser or proxy can keep a stale index.html after an upgrade.
    evidence: |-
      UseStaticFiles and MapFallbackToFile in src/Gatekeep.Host.Admin/Program.cs send only ETag and Last-Modified. There is no Cache-Control: no-cache on index.html and no immutable caching on the hashed /assets files. The spec doesn't ask for caching headers, and the stale-index risk grows only once the Dashboard has screens (Story 1.25).
    location: >-
      src/Gatekeep.Host.Admin/Program.cs
    severity: medium
  - summary: >-
      Rate-limit subjects aren't normalised or grouped: the same address written differently, or each address in one IPv6 /64, counts separately.
    evidence: |-
      AdminAttemptLimiter hashes the raw subject string. No caller exists yet. Story 1.21 decides which forwarded address to trust (T-47), and the canonical subject form belongs with that decision.
    location: >-
      src/Modules/Admins/Core/AdminAttemptLimiter.cs
    severity: medium
  - summary: >-
      Counters are keyed by policy code only, so two call sites that build one code with different limits or windows silently share a counter.
    evidence: |-
      RateLimitPolicy carries Limit and Window, but admin_attempt's key is (policy, subject_hash). Nothing like the job type registry pins one definition per code. This matters once Stories 1.21 to 1.23 add policies.
    location: >-
      src/Gatekeep.Kernel/RateLimiting/RateLimitPolicy.cs
    severity: low
---

<intent-contract>

## Intent

**Problem:** Stories 1.21–1.23 put the first Admin routes on a public hostname, and nothing exists yet to protect them. There is no `IRateLimiter` port and no `admin_attempt` table (AD-14). `Host.Admin` doesn't serve the Admin bundle and sends no CSP, `Referrer-Policy` or anti-framing header (AD-21).

**Approach:** Add the `IRateLimiter` port to Kernel. Implement it in the Admins module over a new `UNLOGGED` `control` table, `admin_attempt`, using a fixed window and an atomic upsert. Make `Host.Admin` serve the built `apps/admin-dashboard` bundle as static files. Every response on its public port gets the exact AD-21 CSP, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff`. Prove this at three levels: the host over HTTP, a real browser, and the Compose stack through Caddy.

## Boundaries & Constraints

**Always:**
- `IRateLimiter` lives in Kernel (`Gatekeep.Kernel.RateLimiting`) and takes a `CommandContext`, so a count commits in the caller's transaction. It is `[StateChanging]`. It is exempt from audit, because AD-5 exempts UNLOGGED counters.
- A policy is a checked code in the `{domain}.{object}.{action}` form, plus a limit (> 0) and a window (> 0). A decision reports whether the attempt is allowed and, when it isn't, how long until it can be retried.
- Every attempt is counted, including refused ones. The stored count saturates at `limit + 1`. Once the window has elapsed, the next attempt starts a new window at 1.
- The subject key, such as a source address or a credential handle, is stored only as its SHA-256 (32 bytes). The raw key never reaches the table or a log.
- The Admins limiter works only in a `DeploymentScope`. A Tenant context gets `InvalidOperationException`, and nothing is written. Tenant counters belong to a later story (Story 2.5's adapter row).
- `admin_attempt` is `UNLOGGED`, class `control`, owned by Admins. Only `gk_admin` may read or write it: `SELECT`, `INSERT`, and `UPDATE` on the counter columns only. The registry and the catalogue test both record that it is unlogged, so a logged `admin_attempt` fails the build.
- The CSP is exactly `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`. It is defined once, in Adapters.Hosting, so Host.Hosted can reuse it later.
- Every public-port response from `Host.Admin` carries the four headers, including 404s and API paths. An unknown non-`/api/` path serves `index.html`, which supports deep links. An unknown `/api/` path is a 404 and never `index.html`.
- The Admin image builds the bundle in a Node stage pinned by digest, with pnpm at the version `package.json` pins and scripts disabled, then copies `dist` into the host's web root.
- If the bundle violates the CSP, fix the build: for example, set `build.assetsInlineLimit: 0` so no `data:` URI is produced. Never loosen the CSP.

**Never:**
- No Redis or in-memory counter store for Admin attempts, and no use of ASP.NET's `RateLimiter` middleware as the store.
- No sign-in, bootstrap or Admin route yet. No caller of the limiter beyond the tests (Stories 1.21–1.23 wire it in).
- No `rate_usage` roll-up job and no purge of expired rows. Both are recorded as deferred.
- No `unsafe-inline`, nonce, hash or third-party origin in the CSP.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Under limit | policy limit 3, attempts 1–3 for key K | allowed; row count 1..3 | — |
| Over limit | 4th and 5th attempt for K in window | refused, RetryAfter > 0 and ≤ window; stored count stays 4 | — |
| Other subject | key L after K is refused | allowed, own row | — |
| Window elapsed | K's window_start older than window | allowed, count reset to 1 | — |
| Refused request | count, then `FailureContext.CommitAfterRollbackAsync` | the count made in the effect survives the rollback | — |
| Tenant scope | `TenantScope` context | nothing written | `InvalidOperationException` |
| Bad policy | empty or malformed code, limit ≤ 0, window ≤ 0 | — | `ArgumentException` at policy creation |
| Bundle root | `GET /` | 200 `index.html` + four headers | — |
| Deep link | `GET /tenants/x` | 200 `index.html` + headers | — |
| Unknown API | `GET /api/v1/nope` | 404 + headers | — |

</intent-contract>

## Code Map

- `src/Gatekeep.Kernel/Jobs/IJobEnqueuer.cs`, `JobType.cs`: the port shape and checked-code value type to mirror. `Persistence/CommandContext.cs` has `TenantId` and `CreateCommand()`. `Persistence/FailureContext.cs` commits refused-request effects.
- `src/Modules/Operations/Core/JobEnqueuer.cs`, `Core/Sql.cs`: how a module writes through `CommandContext` with parameters. `Contracts/OperationsContract.cs` shows the factory-on-contract pattern (`CreateEnqueuer`).
- `src/Modules/Admins/{Contracts/AdminsContract.cs,Core/AdminsCore.cs,Adapters/AdminsAdapters.cs}`: placeholders. Replace them with `AdminsContract.CreateAttemptLimiter()` and an internal `AdminAttemptLimiter`.
- `src/Adapters/Postgres/Migrations/Migration20261102070000SealAuditChains.cs`: the latest migration on main. Name the new one `Migration20261102100000CreateAdminAttemptTable`, because `080000` (Story 7.3) and `090000` (Story 2.6) are taken. Migrations are forward-only, with raw SQL and grants in the same migration.
- `src/Adapters/Postgres/Schema/TableRegistry.cs`: `TableEntry` and `Tables`. Add `admin_attempt` and an `Unlogged` flag. `tests/Isolation/CatalogueAudit.cs` and `CatalogueTests.cs` compare the catalogue to the registry; add a `relpersistence` check and a drift case for it.
- `src/Gatekeep.Host.Admin/Program.cs`: add the headers middleware, static files, and the fallback that skips `/api/`. `src/Adapters/Hosting/GatekeepHosting.cs` holds the shared host startup; put `SecurityHeaders` beside it.
- `apps/admin-dashboard/{vite.config.ts,index.html,src/main.tsx}`: the bundle. It imports `@gatekeep/ui/styles.css`, which brings the fonts from Story 1.13.
- `deploy/docker/admin.Dockerfile`: add the Node bundle stage, with the same node image digest as `tests.Dockerfile`. `tests/Isolation/Stack/ReleaseConfigTests.cs` and `ComposeConfigTests.cs` must keep passing.
- `tests/Isolation/Hosting/{HostProcess.cs,HostStartupTests.cs,FakeOpenBaoSocket.cs}`: start a real `Host.Admin` with migrated database roles and fake custody (see `Host_reads_passwords_from_secret_files_and_reports_healthy`), and fetch with `GetAsync`.
- `tests/browser/{playwright.config.ts,surfaces.spec.ts}`: the Playwright suite from Story 1.13. It runs after `dotnet build` and `pnpm -r build` in `deploy/docker/run-tests.sh`, with no egress.
- `deploy/ci/stack-check.sh`: has a `curl` helper against `ADMIN_HOST=admin.gatekeep-admin.localhost` through Caddy with the internal CA.
- `docs/threat-model.md`: update the Admin-surface rows (rate limit, CSP and framing) if they name these as gaps.

## Tasks & Acceptance

**Execution:**
- [ ] `src/Gatekeep.Kernel/RateLimiting/{IRateLimiter.cs,RateLimitPolicy.cs,RateLimitDecision.cs}`: add the port, the validated policy and the decision.
- [ ] `src/Adapters/Postgres/Migrations/Migration20261102100000CreateAdminAttemptTable.cs`: create `UNLOGGED` `admin_attempt` (`policy` checked code, `subject_hash bytea` of 32 bytes, `window_start timestamptz`, `attempts integer ≥ 1`, primary key `(policy, subject_hash)`) with its grants.
- [ ] `src/Adapters/Postgres/Schema/TableRegistry.cs`, `tests/Isolation/CatalogueAudit.cs`, `tests/Isolation/CatalogueTests.cs`: register the table, add the `Unlogged` flag and a drift check.
- [ ] `src/Modules/Admins/Core/AdminAttemptLimiter.cs`, `Contracts/AdminsContract.cs`: a single-statement upsert that resets an elapsed window, saturates the count and returns the count and the time remaining.
- [ ] `tests/Isolation/RateLimiting/AdminAttemptLimiterTests.cs`: every limiter row in the matrix as `gk_admin`, plus a check that the raw key appears in no stored column and that `gk_hosted` is denied.
- [ ] `src/Adapters/Hosting/SecurityHeaders.cs`, `src/Gatekeep.Host.Admin/Program.cs`: the headers on every response, and serving the bundle.
- [ ] `apps/admin-dashboard/vite.config.ts`: no inlined assets.
- [ ] `deploy/docker/admin.Dockerfile`: build the bundle into the web root.
- [ ] `tests/Isolation/Hosting/AdminBundleTests.cs`: the bundle rows in the matrix against a real `Host.Admin` serving `apps/admin-dashboard/dist`, plus the same headers on each asset `index.html` references.
- [ ] `tests/browser/admin-host.mjs`, `playwright.config.ts`, `admin-csp.spec.ts`: a `webServer` that starts the built `Host.Admin` (with throwaway secret files, an unreachable database and custody) serving the built bundle. Test that the page renders with zero `securitypolicyviolation` events, that every request is same-origin, that the response headers are exact, and that a page on another origin can't frame it.
- [ ] `deploy/ci/stack-check.sh`: `GET https://$ADMIN_HOST/` through Caddy answers 200 with the exact CSP and `Referrer-Policy: no-referrer`.
- [ ] `_bmad-output/implementation-artifacts/deferred-work.md`: add the purge of expired `admin_attempt` rows and the `rate_usage` roll-up.

**Acceptance Criteria:**
- Given `IRateLimiter` in Kernel, when a test caller exceeds a limit, then the extra attempts are refused and counted in `admin_attempt` through the port.
- Given the Admin bundle served by `Host.Admin`, when a browser loads it, then the response sends the AD-21 CSP, `Referrer-Policy: no-referrer` and denies framing, the page renders with no CSP violation, and no request leaves the origin.
- Given the Compose stack, when the Admin hostname is requested through Caddy, then the same headers arrive.
- Given `admin_attempt` recreated as a logged table, when the catalogue test runs, then it fails naming the table.

## Spec Change Log

## Review Triage Log

### 2026-11-03 — Review pass
- verdicts: 25 findings — high 0, medium 7, low 14, false 3, maybe-false 1
- findings:
  - `[low]` `[reject]` Intent: the forwarded-address decision that T-47 gave to Story 1.20 moves to Story 1.21. The story's ACs don't include it, nothing calls the limiter yet, and `deferred-work.md` records it. The user has been asked to confirm.
  - `[low]` `[reject]` Blind: the fallbacks answer every HTTP method, so `POST /` gets `index.html`. The bundle is static and holds no state, and filtering methods adds endpoint metadata for no real harm.
  - `[medium]` `[patch]` Blind: "every public-port response" carries the headers is untested for Kestrel's own errors and unhandled 500s. Grouped with the two Edge rows on 500s. The wording in `SecurityHeaders` and TB-2 is narrowed and names both exceptions.
  - `[medium]` `[defer]` Blind: no caching headers on the bundle, so a stale `index.html` survives an upgrade. Not caused by a defect in the spec'd behaviour; deferred.
  - `[false]` `[reject]` Blind: the CSP has no `report-to` or Trusted Types. AD-21 mandates the exact policy string, so adding directives would break it.
  - `[medium]` `[patch]` Blind: the counter row lock is held for the caller's whole transaction, which can queue requests behind slow work. `IRateLimiter`'s doc now says to count in a short transaction, never around slow work.
  - `[medium]` `[defer]` Blind: subjects aren't normalised (IPv4-mapped forms, IPv6 case, /64 grouping). This belongs with Story 1.21's forwarded-address decision; deferred.
  - `[low]` `[reject]` Blind: plain SHA-256 of a low-entropy subject is reversible. T-50 records and accepts it for an `UNLOGGED`, `gk_admin`-only table, and the spec chose SHA-256.
  - `[medium]` `[patch]` Blind: a window with no upper bound overflows `window_start + @window`. Grouped with the Edge sub-microsecond row. `RateLimitPolicy` refuses windows under 1 second or over 365 days. The policy-registry part is deferred (low).
  - `[low]` `[patch]` Blind: the `admin.Dockerfile` bundle stage lost its `\` continuations. Restored as multi-line continuations. The hand-listed manifests and cache order are rejected: a missing manifest fails the image build loudly in CI.
  - `[low]` `[reject]` Blind: `admin.Dockerfile.dockerignore` can drift from `.dockerignore`. The root file is equally hand-kept, and the config tests already pin the secret and trust exclusions in it.
  - `[low]` `[patch]` Blind: per-project `testMatch` silently skips a new spec file. The surfaces projects now run every spec except `admin-csp.spec.ts`.
  - `[low]` `[patch]` Blind: the asset test hard-codes exactly 2 fonts. It now asserts at least one.
  - `[low]` `[reject]` Blind: public `/healthz` serves the bundle with a 200. Health lives only on the loopback port, and Caddy and the container healthcheck never ask the public one.
  - `[low]` `[reject]` Blind: the stack check covers only `/` through Caddy. Caddy only adds HSTS, and `AdminBundleTests` covers the deep link, the 404 and the assets on the host.
  - `[false]` `[reject]` Blind: the bundle check misses `eval` in the JavaScript. React's production build has no eval, the browser test would see any CSP violation on load, and nothing in the bundle loads lazily.
  - `[low]` `[reject]` Edge: a deep link whose last segment has a dot gets a 404. Dashboard paths use prefixed IDs with no dot (AD-19), and the `nonfile` fallback is what keeps `/assets/missing.js` a 404.
  - `[medium]` `[patch]` Edge: an unhandled exception's 500 can lose the headers. Grouped with the Blind wording row and patched the same way.
  - `[low]` `[patch]` Edge: a sub-microsecond window truncates to a zero interval and never refuses. Grouped with the Blind window row.
  - `[low]` `[patch]` Edge: a whitespace-only subject is accepted. Now `ThrowIfNullOrWhiteSpace`, with a test case.
  - `[low]` `[reject]` Edge: lone UTF-16 surrogates collide on U+FFFD. Subjects are addresses and handles, never arbitrary text.
  - `[maybe-false]` `[reject]` Edge: a stale `now()` can push `RetryAfter` past the window. It would take a transaction that started before a concurrent reset; the overshoot is at most that transaction's age, so at most low.
  - `[low]` `[patch]` Edge: `admin-host.mjs` crashes on a spawn error and leaves its secrets directory. The child's `error` event is now handled: it logs, cleans up and exits 1.
  - `[false]` `[reject]` Edge: config-level web servers fail surfaces-only runs when `Host.Admin` isn't built. `run-tests.sh` always builds .NET before the browser tests, and that's the only documented way to run them.
  - `[medium]` `[patch]` Edge (claim): TB-2 and T-47 overstate the coverage of "every public-port response". Grouped with the 500 rows; the wording is narrowed.
- verification-gap: no gaps found.

## Design Notes

The upsert is one statement, so concurrent attempts can't lose counts:

```sql
INSERT INTO admin_attempt (policy, subject_hash, window_start, attempts)
VALUES (@policy, @hash, now(), 1)
ON CONFLICT (policy, subject_hash) DO UPDATE SET
  window_start = CASE WHEN admin_attempt.window_start + @window <= now() THEN now() ELSE admin_attempt.window_start END,
  attempts     = CASE WHEN admin_attempt.window_start + @window <= now() THEN 1 ELSE least(admin_attempt.attempts, @limit) + 1 END
RETURNING attempts, window_start + @window - now();
```

`now()` is the transaction's time, so every attempt in one command uses the same clock. The browser test runs `Host.Admin` itself rather than `vite preview`, because the headers being tested are the host's own.

## Verification

**Commands:**
- `docker build -t gatekeep/tests:story-1-20 -f deploy/docker/tests.Dockerfile .` and then `MSYS_NO_PATHCONV=1 docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal --add-host host.docker.internal:host-gateway gatekeep/tests:story-1-20`. Expected: no build warnings, and the browser, Architecture and Isolation suites all pass.
- `docker build -f deploy/docker/admin.Dockerfile .`. Expected: the image builds with `wwwroot/index.html` inside.
- CI `stack` job. Expected: the new Admin header check passes.

## Auto Run Result

Status: done

**Summary:** Kernel has the `IRateLimiter` port. The Admins module implements it over the new `UNLOGGED` `control` table `admin_attempt`, with one upsert that counts, resets an elapsed window and saturates the count. Only a SHA-256 of the subject is stored, and only `gk_admin` holds grants. `Host.Admin` serves the built Admin Dashboard bundle, which the Admin image now builds. Every response from the pipeline carries the exact AD-21 CSP, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff`. Coverage is at three levels: the host over HTTP, a real browser, and the Compose stack through Caddy.

**Files:**
- `src/Gatekeep.Kernel/RateLimiting/*`: the port, the validated policy and the decision.
- `src/Modules/Admins/Core/AdminAttemptLimiter.cs`, `Contracts/AdminsContract.cs`: the Admin limiter and its factory. The placeholder `AdminsCore.cs` is removed.
- `src/Adapters/Postgres/Migrations/Migration20261102100000CreateAdminAttemptTable.cs`: the table and its grants.
- `src/Adapters/Postgres/Schema/TableRegistry.cs`, `tests/Isolation/CatalogueAudit.cs`, `CatalogueTests.cs`: the registry entry, the `Unlogged` flag and the persistence drift check.
- `src/Adapters/Hosting/SecurityHeaders.cs`, `src/Gatekeep.Host.Admin/Program.cs`: the headers, static files and the fallbacks.
- `apps/admin-dashboard/vite.config.ts`: no inlined assets.
- `deploy/docker/admin.Dockerfile`, `.dockerignore`: the bundle stage, and `apps/` and `packages/` let into the shared build context. A per-Dockerfile ignore file first failed the CI stack job, because the classic builder there ignores it.
- `deploy/ci/stack-check.sh`: the header check through Caddy. The Admin host now answers 200.
- `tests/Isolation/RateLimiting/AdminAttemptLimiterTests.cs`, `tests/Isolation/Hosting/AdminBundleTests.cs`: limiter and host tests.
- `tests/browser/admin-host.mjs`, `admin-csp.spec.ts`, `playwright.config.ts`: the browser tests against the built host.
- `tests/Isolation/MigrateCommandTests.cs`: 6 migrations. `tests/Isolation/Stack/*ConfigTests.cs`: the admin ignore file.
- `tests/Isolation/Gatekeep.Tests.Isolation.csproj`, `tests/Architecture/module-edges.txt`, `docs/architecture/module-dependencies.md`: the test reference to Admins.
- `docs/threat-model.md`: TB-2, TB-6, T-37, T-47 and the new T-50.
- `_bmad-output/implementation-artifacts/deferred-work.md`: the expired-row purge, the `rate_usage` roll-up and the forwarded-address decision.

**Review:** 25 findings across four layers.
- **Patched:** 8 entries, 3 of them medium (the header-coverage wording, the lock-holding guidance and the window bounds) and 5 low.
- **Deferred:** 3 (bundle caching, subject normalisation, a policy registry).
- **Rejected:** the rest, each with its reason in the triage log.

**Follow-up review:** not recommended. The medium patches are doc wording, guidance and constructor validation, each covered by a test that ran. No unverified risk remains from them.

**Verification:** the full suite in `gatekeep/tests:story-1-20` after the patches.
- Build: 0 warnings.
- Browser 12/12 and Architecture 337/337.
- Isolation 1121/1122. The one failure was a PostgreSQL connection timeout in the untouched `AuditTests`; rerun alone, it passed 176/176. The run before the patches was fully green at 1116/1116.
- `docker build -f deploy/docker/admin.Dockerfile .` builds with `wwwroot/index.html`. The CI `stack` job, which runs the Caddy header check, runs on the PR.

**Residual risks:**
- Nothing calls the limiter until Stories 1.21 to 1.23. Which forwarded address to trust moved to Story 1.21; the user has been asked to confirm this.
- Rebased onto Story 7.3 (merged first): `MigrateCommandTests` now expects 7 migrations, and the threat model keeps both stories' text. On the rebased branch: browser 12/12, Architecture 362/362, Isolation 1217/1220, the three failures being PostgreSQL connection timeouts in untouched audit tests that passed on a rerun (99/99 with `MigrateCommandTests`).
- Kernel-level 400, 413 and 431 responses, and unhandled 500s, may not carry the headers.
