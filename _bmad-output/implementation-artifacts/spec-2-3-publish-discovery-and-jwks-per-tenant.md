---
title: 'Story 2.3: Publish discovery and JWKS per Tenant'
type: 'feature'
created: '2026-11-05'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-2-context.md'
  - '{project-root}/docs/spikes/2-1-openiddict-per-tenant.md'
  - '{project-root}/docs/spikes/2-2-openiddict-stores.md'
warnings: ['oversized']
deferred: []
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

## Design Notes

OpenIddict needs one enabled flow, and that flow needs the token endpoint. A refusing handler placed before OpenIddict's own token validation keeps that endpoint inert until Story 2.5 replaces it. OpenIddict's token handlers would otherwise need the managers, which have no stores yet. A discovery handler that removes the token endpoint and grant types stops clients from trying it.

Discovery and JWKS only read. Build the runtime from a short read-only Tenant scope as `gk_hosted`, then cache it per Tenant for at most 5 seconds. Don't keep a connection open through OpenIddict's pipeline, unlike the spike (2-2 carry-over).

Use a fake or fixed clock where `created_at`/`published_at` matter. Never rely on wall-clock waits.

## Verification

**Commands:**
- `docker build -t gatekeep/tests:epic2 -f deploy/docker/tests.Dockerfile .` -- expected: builds with locked restore. Don't use the shared `gatekeep/tests:local` tag.
- `MSYS_NO_PATHCONV=1 docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal --add-host host.docker.internal:host-gateway gatekeep/tests:epic2` -- expected: all architecture and isolation tests pass.
