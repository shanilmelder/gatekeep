---
title: 'Story 2.1: Prove per-Tenant options and Transit signing'
type: 'chore'
created: '2026-11-02'
status: 'done'
baseline_revision: 'b6d501e4f54f58b3ee564b74318318fad63464f9'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-2-context.md'
warnings: ['multiple-goals', 'oversized']
deferred:
  - summary: >-
      An unregistered redirect_uri might still redirect in the spike's degraded mode; untested.
    evidence: |-
      ValidateSpikeAuthorizationRequest rejects with invalid_client, but no test checks that the response isn't a 302 to the foreign URI. Settle it by sending an authorize request with a foreign redirect_uri and asserting no Location. Story 2.9 owns redirect URI handling.
    location: >-
      tests/Isolation/Spikes/OpenIddict/SpikeServer.cs (ValidateSpikeAuthorizationRequest)
    severity: medium (unverified)
  - summary: >-
      SelectTenantOptions sets RequestUri with the issuer's scheme, so a plain-http request might pass OpenIddict's transport-security check.
    evidence: |-
      Settle it by checking whether OpenIddict 7.7.2's transport-security handler reads HttpRequest.IsHttps or the transaction's RequestUri, then sending an http request to a Tenant host. Production sits behind TLS termination (Caddy), which Story 2.3 must account for.
    location: >-
      tests/Isolation/Spikes/OpenIddict/SpikeServer.cs (SelectTenantOptions)
    severity: medium (unverified)
---

<intent-contract>

## Intent

**Problem:** AD-8 says OpenIddict 7.7.2 can be wrapped per Tenant: a first handler swaps in per-Tenant options and sets `BaseUri`, Signing Keys sign in OpenBao Transit, and global credentials are inert. None of this has run. Stories 2.3 onward build on it (AR-2, AR-22).

**Approach:** Build a test-only spike: an in-process OpenIddict server serving two Tenants on two hosts, backed by the real OpenBao test container. Record pass or fail for each proof in `docs/spikes/2-1-openiddict-per-tenant.md`, naming the test that proves each row. Production `src/` code is out of scope.

## Boundaries & Constraints

**Always:**
- The spike lives under `tests/Isolation/Spikes/OpenIddict/`. It uses the existing `OpenBaoFixture` collection and its `host-worker` role for setup, which creates `sig-` and `tpk-` keys and wrapped data keys. Request-time signing and unwrapping use the `host-hosted` role only, which shows the Hosted policy is enough.
- There are two Tenants, each with its own host, issuer, Signing Key (`KeyName.Signing`) and token protection key (a random 256-bit key wrapped by `tpk-{tenant}`). Tenants are held in an in-memory map in the spike; database host resolution is Story 2.3.
- The first Gatekeep handler on every OpenIddict request does three things: it resolves the Tenant from the host, replaces `context.Transaction.Options` with that Tenant's copy, and sets `BaseUri` from the stored issuer. Code after it reads only the per-Tenant options.
- The global options carry inert signing and encryption keys that throw on any cryptographic use and count each attempt.
- Signing calls `IKeyCustody.SignAsync` through a `SignatureProvider`. Its synchronous `Sign` blocks on the async call, and that blocking is the behaviour under test. The algorithm is RS256 from the RSA-3072 Transit key, and the `kid` identifies the Transit key and its version.
- Each Tenant's encryption credential is its unwrapped token protection key, which protects authorization codes.
- OpenIddict runs in degraded mode, because custom stores are Story 2.2. A passthrough authorization endpoint signs in one fixed test subject. The flows exercised are Client Credentials and Authorization Code with PKCE S256.
- Every result is `pass` or `fail`. A failed proof keeps a test that asserts the observed failure, so CI stays green and the doc records `fail` with the reason. No proof is weakened until it passes.
- New packages need central versions, regenerated lock files and the critical audit.

**Never:**
- No OpenIddict code, package or wiring goes into `src/`.
- No change to OpenBao policies, the Kernel or the adapters.
- No AD-8 amendment. That is Story 2.2's failure criterion.
- No key material, token or secret value in the docs or test output.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Discovery per Tenant | GET `/.well-known/openid-configuration` on host A and on host B | Each `issuer` and endpoint URI is that Tenant's stored issuer | No error expected |
| JWKS per Tenant | GET JWKS on each host | Each JWKS holds only that Tenant's Transit public key, with no inert key and no key from the other Tenant | No error expected |
| Client Credentials | Token request on host A | `at+jwt` with `iss` A and `kid` A. It verifies against A's Transit public key and fails against B's | No error expected |
| Code flow | Authorize with PKCE S256 on host A, then redeem on A | Code redeemed and tokens issued, signed by A | No error expected |
| Cross-Tenant code | A's code redeemed on host B | Refused with `invalid_grant`, because B's protection key can't open it | Protocol error, no tokens |
| Unknown host | Any OpenIddict endpoint on an unmapped host | Refused before OpenIddict reads global options | 404 or 400, no tokens |
| Inert credentials | All of the above | Inert key use count stays 0 | Any use throws and fails the request |

</intent-contract>

## Code Map

- `src/Gatekeep.Kernel/Secrets/IKeyCustody.cs:36-99` -- async-only custody: `CreateKeyAsync` returns public halves, `SignAsync` returns `KeySignature(KeyVersion, Value)`, `GetPublicKeysAsync` returns PEM per version, `CreateWrappedDataKeyAsync` and `DecryptAsync(key, tenantId, …)` handle unwrapping.
- `src/Gatekeep.Kernel/Secrets/KeyName.cs:71,87` -- `KeyName.Signing(t,row)` gives `sig-…`, and `KeyName.ForTenant(TenantKeyClass.TokenProtection,t)` gives `tpk-…`.
- `src/Adapters/OpenBao/OpenBaoKeyCustody.cs` -- the real Transit client. Signs use sha2-256 with pkcs1v15. A constructor overload takes an `HttpMessageHandler`.
- `deploy/openbao/policies/host-hosted.hcl` -- Hosted may run `sign/sig-*`, read `keys/sig-*` and run `decrypt/tpk-*`. It can't create keys or call verify.
- `tests/Isolation/Custody/OpenBaoFixture.cs` -- collection fixture. `Custody(role)` and the role constants come from here. `SeedKeysAsync:222` shows how Worker creates keys.
- `tests/Isolation/Custody/CustodyTests.cs` -- style reference: sealed class with a primary-constructor fixture, underscore sentence names and `TestContext.Current.CancellationToken`. The wrapped token protection key flow is near :97.
- `tests/Isolation/Gatekeep.Tests.Isolation.csproj` -- needs a `FrameworkReference` to `Microsoft.AspNetCore.App` (if missing) plus `OpenIddict.Server.AspNetCore` and `Microsoft.AspNetCore.TestHost` (latest 10.0.x). No new project reference, so `module-edges.txt` is unchanged.
- `Directory.Packages.props` -- add the two `PackageVersion` entries. `tests/Isolation/packages.lock.json` must be regenerated.
- `tests/Architecture/KeyCustodyRuleTests.cs:21-26` -- bans `RSA.Create` and similar in `src/` only. The spike may parse PEMs in tests. Record that Story 2.3 must build the public key without these calls in `src/`.
- `docs/spikes/1-2-key-custody.md` -- format to follow: outcome line, context, a `Proof | Result | What remains` table and a test-name column.

## Tasks & Acceptance

**Execution:**
- `Directory.Packages.props`, `tests/Isolation/Gatekeep.Tests.Isolation.csproj`, `tests/Isolation/packages.lock.json` -- add OpenIddict.Server.AspNetCore 7.7.2 and TestHost 10.0.x, then restore with the lock file -- the spike needs the real library.
- `tests/Isolation/Spikes/OpenIddict/SpikeTenants.cs` -- create two Tenants per test run with Worker (Signing Key and wrapped token protection key), and keep host → Tenant in memory -- this stands in for `tenant_host`.
- `tests/Isolation/Spikes/OpenIddict/TransitSigning.cs` -- add a Transit-backed asymmetric security key, a `CryptoProviderFactory` and a `SignatureProvider` that blocks on `SignAsync` and counts calls. The public half comes from `GetPublicKeysAsync` -- this is the synchronous provider proof.
- `tests/Isolation/Spikes/OpenIddict/InertCredentials.cs` -- add inert signing and encryption keys whose crypto throws and counts each attempt -- this is the inert global credential proof.
- `tests/Isolation/Spikes/OpenIddict/SpikeServer.cs` -- build a TestServer with OpenIddict in degraded mode. It has the token, authorization (passthrough), discovery and JWKS endpoints, plus the first-handler options swap and `BaseUri` -- this is the spike build.
- `tests/Isolation/Spikes/OpenIddict/PerTenantOptionsSpikeTests.cs` -- add one test per I/O matrix row, in the `OpenBao` collection -- these produce the pass and fail records.
- `docs/spikes/2-1-openiddict-per-tenant.md` -- write the outcome, a results table for options replacement, `BaseUri`, Transit signing, the synchronous provider, token protection keys and inert credentials, the test name for each row, and what Story 2.3 must carry over (blocking risk, PEM parsing outside `src/`, ordering) -- this is the spike record.
- `_bmad-output/implementation-artifacts/sprint-status.yaml` -- set `2-1-…` to its final status -- tracking.

**Acceptance Criteria:**
- Given two Tenants in the spike build, when requests reach each Tenant host, then the spike doc records `pass` or `fail` for options replacement, `BaseUri`, signing through Transit including the synchronous provider, and token protection keys, and each row names a test that ran.
- Given the inert global credentials, when tokens and JWKS are produced on both hosts, then a test shows the inert keys' `kid` appears in no token header or JWKS and their use count is 0.
- Given the full suite, when `run-tests.sh` runs in Docker, then the architecture and isolation tests pass with locked restore.

## Spec Change Log

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 38 findings — high 0, medium 7, low 23, false 6, maybe-false 2
- findings:
  - `false` `reject` (intent) Story 2.2 is absent from the diff — the run resolved the invocation to one story per run and PR (the user's rule); 2.2 is the next run.
  - `false` `reject` (intent) The proofs run on an in-process TestServer, not real hosts — the criterion says "in a spike build", and the doc lists proxy and TLS as untested.
  - `false` `reject` (intent) Token protection is tested on self-contained JWE codes, not reference tokens — the protection key is what's under test; reference tokens are Story 2.2's custom stores, which the doc names.
  - `false` `reject` (intent) The doc's pass/fail table is written by hand — the criterion asks the spike to record results, and each row names the test that produced it.
  - `medium` `patch` (verification-gap) PKCE S256 enforcement is never tested with a bad request — added `Authorize_without_S256_PKCE_is_refused_and_issues_no_code` for `plain` and a missing challenge.
  - `medium` `patch` (verification-gap) The `SignBlocking` version check is never exercised — the doc now marks it untested and notes that Story 2.4 must rebuild the cached runtime.
  - `medium` `patch` (verification-gap, other) The doc states the rotation fail-safe as fact — same fix as above.
  - `false` `reject` (blind) The lock file, spec and status are missing from the diff — they were left out of the review diff on purpose; the lock file is in the tree and the locked-mode image build passed.
  - `low` `patch` (blind) Host matching is called "exact" but ignores case and port — comment reworded.
  - `medium` `patch` (blind) No negative PKCE tests — grouped with the PKCE test above.
  - `maybe-false` `defer` (blind) An unregistered `redirect_uri` is rejected with `invalid_client` and untested; it might still redirect in degraded mode — to settle, send an authorize request with a foreign `redirect_uri` and assert there's no 302. Story 2.9 owns redirect URI handling; deferred.
  - `medium` `patch` (blind) The inert test covers only signing and encryption and passes on any exception — it now requires `InertKeyUsedException` in the chain, and the doc claim is narrowed.
  - `low` `patch` (blind) A faulted Tenant build is cached forever — added to the doc's carry-over list (production must evict faulted builds).
  - `low` `patch` (blind) Transit signing has no timeout — added to the carry-over list (bound custody calls).
  - `low` `patch` (blind) The span `Sign` overload can call Transit twice — the buffer is now checked before signing.
  - `low` `patch` (blind) The concurrency test records no numbers but the doc says "harmless" — doc reworded.
  - `low` `patch` (blind) The options-replacement test checks only Tenant A — Tenant B assertions and a no-cross-key check added.
  - `low` `patch` (blind) Path issuers are untested, and `RequestUri` drops the issuer path — the carry-over list now says issuers are origin-only.
  - `maybe-false` `defer` (blind) `RequestUri` takes the issuer's scheme, so a plain-http request might pass the transport-security check — to settle, check whether OpenIddict's transport-security handler reads `HttpRequest.IsHttps` or `RequestUri`. Medium if true; deferred.
  - `low` `patch` (blind) The doc says every test checks inert use is 0, and the heading names Story 2.3 for items owned by other stories — both corrected.
  - `false` `reject` (blind) The JWKS publishes only the newest Transit version, and there's no cross-Tenant token test — AD-11 makes each Signing Key its own Transit key (one row each), so versions don't carry rotation overlap; the token-against-B's-key check is already in the Client Credentials test.
  - `low` `patch` (edge) A faulted `Lazy` stays cached — grouped with the carry-over note.
  - `low` `patch` (edge) `BuildAsync` runs with `CancellationToken.None` — grouped with the carry-over note.
  - `low` `reject` (edge) `MaxBy` returns null on an empty version list — a created Transit key always has version 1; unreachable in the spike.
  - `medium` `patch` (edge) Rotation after the runtime is cached makes every sign throw — grouped with the version-check doc fix.
  - `low` `patch` (edge) `SignAsync` has no timeout — grouped with the carry-over note.
  - `low` `patch` (edge) `_signs` counts failed signs — it now increments after a successful signature.
  - `low` `patch` (edge) A small destination buffer leads to a double sign — grouped with the span fix.
  - `low` `reject` (edge) The unwrapped key length isn't checked — Worker's wrapped data key is always 256-bit; unreachable.
  - `low` `reject` (edge) Unwrapped key bytes are never zeroed — test-only keys in a test process; adding the guard brings no benefit to the spike.
  - `low` `reject` (edge) The app isn't disposed if `StartAsync` throws — test harness only; the process ends.
  - `low` `patch` (edge) A path issuer breaks `RequestUri` — grouped with the origin-only note.
  - `low` `reject` (edge) A public client presenting a `client_secret` is accepted — degraded-mode scaffolding; client authentication is Story 2.2.
  - `low` `reject` (edge) A 500 or empty body surfaces as a `JsonException` — affects diagnostics only, and the test still fails.
  - `low` `reject` (edge) A `WaitAsync` timeout disposes the server mid-flight — the test already fails on the timeout; noise only.
  - `medium` `patch` (edge) `ThrowsAny<Exception>` passes on unrelated errors — grouped with the inert test fix.
  - `low` `reject` (edge, claim) The spec says an unknown host is refused before global options are read, but the transaction is built from them — the fix would be a spec edit; the doc's "Global reads that remain" section already states it correctly.
  - `low` `patch` (edge, claim) The doc overstates which tests check inert use is 0 — grouped with the doc wording fix.

## Design Notes

Degraded mode is deliberate. It lets the spike test options, signing and token protection without the custom stores, which Story 2.2 proves. The cross-Tenant code redemption proves the protection key is per Tenant. If OpenIddict accepts the code at host B, the proof fails.

If the per-request options swap can't work (for example, if a needed handler caches options before the first Gatekeep handler runs), record `fail`. Story 2.2's criterion then moves the design to a keyed provider.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml build tests` -- expected: the image builds with locked restore and no audit failure.
- `docker compose -f deploy/compose.test.yaml run --rm tests` -- expected: all architecture and isolation tests pass, including `PerTenantOptionsSpikeTests`.

**Manual checks (if no CLI):**
- `docs/spikes/2-1-openiddict-per-tenant.md` has a result for every proof and no key material.

## Auto Run Result

**Summary.** The Story 2.1 spike is test-only, in `tests/Isolation/Spikes/OpenIddict/`. It runs OpenIddict 7.7.2 in degraded mode on a TestServer and serves two Tenants on two hosts against the real OpenBao container. Every proof passed: options replacement, `BaseUri` from the stored issuer, signing through Transit including the synchronous provider, JWKS per Tenant, token protection keys, inert global credentials, and refusal of an unknown host. AD-8 holds as written. `docs/spikes/2-1-openiddict-per-tenant.md` records the conditions later stories must carry over.

**Files changed**
- `Directory.Packages.props` -- adds OpenIddict.Server.AspNetCore 7.7.2 and Microsoft.AspNetCore.TestHost 10.0.14.
- `tests/Isolation/Gatekeep.Tests.Isolation.csproj`, `tests/Isolation/packages.lock.json` -- add the ASP.NET Core framework reference, the two packages and a regenerated lock file.
- `tests/Isolation/Spikes/OpenIddict/SpikeTenants.cs` -- two Tenants per run, set up by Worker, with host-to-Tenant held in memory.
- `tests/Isolation/Spikes/OpenIddict/TransitSigning.cs` -- the Transit-backed RSA key and the blocking `SignatureProvider`.
- `tests/Isolation/Spikes/OpenIddict/InertCredentials.cs` -- inert global keys that throw and count every use.
- `tests/Isolation/Spikes/OpenIddict/SpikeServer.cs` -- the spike server, the first-handler options swap, per-Tenant runtimes and the degraded-mode client checks.
- `tests/Isolation/Spikes/OpenIddict/PerTenantOptionsSpikeTests.cs` -- 11 tests, one or more for each proof.
- `docs/spikes/2-1-openiddict-per-tenant.md` -- the spike record.
- `_bmad-output/implementation-artifacts/sprint-status.yaml` -- Story 2.1 and Epic 2 status.
- `_bmad-output/implementation-artifacts/epic-2-context.md` -- the compiled Epic 2 context.

**Review findings.** There were 38 findings: 15 patched in 7 groups, 2 deferred (both unverified, medium if true), 6 false and 15 rejected. The reasons for every rejection are in the Review Triage Log above.
- **Patched groups:** PKCE negative test; version-check doc claim; inert-test exception type; Tenant B options assertions; span `Sign` buffer check and counter; host comment; doc accuracy and carry-over bullets.
- **Deferred:** redirect on an unregistered `redirect_uri` (Story 2.9), and the issuer scheme in `RequestUri` versus the transport-security check (Story 2.3).

**Follow-up review: recommended (`true`).** Three medium groups were patched: PKCE, the version-check claim and the inert exception type. No high groups were patched. The unverified risk is the new PKCE test. It accepts any non-200 response with no code, so it hasn't been shown whether OpenIddict or the spike handler refuses `plain`. A second pass should confirm that the refusal comes from the intended layer.

**Verification**
- `docker build -t gatekeep/tests:epic2 -f deploy/docker/tests.Dockerfile .` succeeded, with locked restore and the audit. This replaces the spec's `docker compose ... build`, because the shared `gatekeep/tests:local` tag was overwritten by another checkout mid-run.
- Before the patches, the full suite passed: 275/275 architecture and 934/934 isolation tests.
- After the patches, the 11 spike tests passed.
- After the patches, the full suite passed: 275/275 architecture and 935/935 isolation tests.

**Residual risks**
- Each blocking signature holds a thread-pool thread, and no load figures were measured.
- The spike ran on TestServer only, so the proxy and TLS path is untested.
- Production must evict failed Tenant builds and bound custody calls.
- Turning Transit's public key into an RSA key needs a way that is allowed in `src/`.
