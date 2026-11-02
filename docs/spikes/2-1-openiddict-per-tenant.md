# OpenIddict per-Tenant spike (Story 2.1)

**Outcome: pass. AD-8 holds as written, with two conditions Story 2.3 must carry over (below).**

Date: 2026-11-02. The spike ran OpenIddict 7.7.2 (`OpenIddict.Server.AspNetCore`) in degraded mode on an ASP.NET Core TestServer, serving two Tenants on two hosts (`a.spike.test`, `b.spike.test`). It was backed by the real OpenBao 2.7.2 test container (`OpenBaoFixture`), not a fake. Each run creates both Tenants fresh with the `host-worker` login: a Signing Key `sig-{tenant}-{row}` (RSA-3072 in Transit) and a random 256-bit token protection key wrapped by `tpk-{tenant}`. Everything at request time, meaning reading the public half, unwrapping the token protection key and signing, uses the `host-hosted` login only, so the Hosted policy is enough.

The code is test-only, in `tests/Isolation/Spikes/OpenIddict/`. Nothing is in `src/`. The tests are `PerTenantOptionsSpikeTests` in the `OpenBao` collection, and all of them ran and passed in the tests container.

## Proof results

| Proof | Result | Test | What remains |
| --- | --- | --- | --- |
| Options replacement | `pass` | `Gatekeep_handler_runs_first_and_swaps_in_a_separate_Tenant_options_object` | Keep the Deployment-wide settings identical in every copy (see "Global reads that remain") |
| `BaseUri` from the stored issuer | `pass`, only once the built-in `ResolveRequestUri` handler is removed | `Discovery_on_each_host_names_that_Tenants_stored_issuer_and_endpoints` | Story 2.3 resolves the issuer from `tenant_host` instead of the in-memory map |
| Signing through Transit | `pass` | `Client_credentials_token_is_signed_in_Transit_and_verifies_only_against_its_Tenant`, `Authorization_code_with_PKCE_S256_is_redeemed_on_its_own_host_and_signed_by_it` | Rotation (Story 2.4) has to update the `kid` version. The provider is written to refuse a signature from any other version, but that check is **untested** |
| Synchronous provider | `pass`, with a load risk | `Concurrent_token_requests_complete_while_each_Sign_blocks_on_Transit` | Measure thread-pool behaviour under real load before Story 2.5 ships (see "Blocking") |
| JWKS per Tenant | `pass` | `Jwks_on_each_host_holds_only_that_Tenants_Transit_public_key` | `Cache-Control` and the 5-second cache are Story 2.3 |
| Token protection keys | `pass` | `Code_from_one_Tenant_is_refused_on_another_because_its_protection_key_cant_open_it` | Codes become reference tokens with custom stores in Story 2.2 |
| Inert global credentials | `pass` | `Inert_global_credentials_reach_no_token_or_JWKS_and_are_never_used`, `Inert_credentials_throw_and_count_on_any_cryptographic_use` | None |
| Unknown host refused | `pass` | `Unknown_host_is_refused_with_404_before_any_other_OpenIddict_handler` | None |

Every test that starts the spike server also checks that the inert use count is 0 at the end. `Authorize_without_S256_PKCE_is_refused_and_issues_no_code` covers the PKCE negative cases: `code_challenge_method=plain` and a missing `code_challenge` are both refused, and no code is issued.

## What each proof showed

**Options replacement.** The Gatekeep handler `SelectTenantOptions` runs on `ProcessRequestContext` at order `int.MinValue`, and the test checks it's first in the sorted handler list. It resolves the Tenant by exact host match, replaces `context.Transaction.Options` with that Tenant's copy, and sets `BaseUri` and `RequestUri`. Each copy comes from `IOptionsFactory<OpenIddictServerOptions>.Create(Options.DefaultName)`, which runs every `Configure` and `PostConfigure` step, including OpenIddict's own validation, on a fresh object. The handler then:

- sets `Issuer` to the stored issuer
- replaces the signing credentials with the Tenant's Transit key
- replaces the encryption credentials with the Tenant's unwrapped token protection key
- sets `TokenValidationParameters.IssuerSigningKeys` and `TokenDecryptionKeys` explicitly

That last step is required. OpenIddict's `PostConfigure` wires those two properties lazily to the credential lists, so a copy made any other way would still validate with the inert keys. The test checks that the copy is a separate object for each Tenant, that it holds only that Tenant's keys, and that the global options still hold only the inert ones.

**`BaseUri`.** OpenIddict's own `ResolveRequestUri` handler runs at `int.MinValue + 50_000` and sets `BaseUri` and `RequestUri` from the `Host` header. Left in place, it overwrites whatever Gatekeep sets, so the spike removes it with `RemoveEventHandler` and builds both URIs from the stored issuer. Endpoint matching (`InferEndpointType`) and every discovery endpoint then use the stored issuer. The test proves it with a request to `https://a.spike.test:8443/...`: the discovery document still names `https://a.spike.test/` and endpoints with no port. Built from the `Host` header, they would include the port.

**Signing through Transit.** `TransitSigning` gives OpenIddict an `RsaSecurityKey` that holds only the public half, taken from `IKeyCustody.GetPublicKeysAsync`. Its custom `CryptoProviderFactory` returns a `SignatureProvider` that calls `IKeyCustody.SignAsync`. Tokens carry `alg: RS256`, a 3072-bit modulus and `kid: {transit key name}.v{version}`. Each verifies against its own Tenant's PEM public key and fails against the other Tenant's. The Transit sign counter shows exactly one call per signed artifact: 1 for a Client Credentials token, and 3 for the code flow (code, access token, ID token). Verification never calls Transit, because `host-hosted` can't call verify. The factory gives Wilson's default verifier the public key instead.

**Synchronous provider.** Wilson's `SignatureProvider.Sign` is synchronous, so the provider blocks on `SignAsync(...).GetAwaiter().GetResult()`. ASP.NET Core has no synchronization context, so this doesn't deadlock: 32 concurrent token requests across both hosts all completed within the test's 60-second timeout, each signed by its own Tenant. No latency or thread-pool figures were measured. It's still a blocking call; see "Blocking".

**Token protection keys.** In degraded mode, authorization codes are self-contained JWE: `A256KW` with `A256CBC-HS512` under the Tenant's unwrapped token protection key, and the JWE `kid` is `tpk-{tenant}`. A's code redeemed at host B fails with `invalid_grant` and no tokens. The test confirms the reason directly: B's key can't decrypt the code, and A's key can.

**Inert global credentials.** The global options hold one signing and one encryption credential. They pass OpenIddict's startup checks, but their crypto provider factory throws and counts on every sign, verify, wrap, unwrap, encrypt, decrypt or hash it is asked for. Across discovery, JWKS, Client Credentials and the code flow on both hosts, no token header, code header or JWKS entry carries an inert `kid`, and the count stays 0. A separate test checks signing and encryption with the inert keys: each throws an `InertKeyUsedException` and is counted. The other operations refuse by construction and aren't tested.

**Unknown host.** On an unmapped host, discovery, JWKS, authorize and token all get 404 with an empty body and no redirect. No Tenant options are built and no key is touched, because the Gatekeep handler calls `HandleRequest()` before any other OpenIddict handler runs.

## Global reads that remain

OpenIddict still reads the global options in three places that a per-request swap can't reach. None of them reads Tenant data:

1. `OpenIddictServerFactory` creates each transaction with the global options, before the Gatekeep handler replaces them.
2. `OpenIddictServerDispatcher` reads the handler list from the global options on every dispatch, so a per-Tenant copy can't change which handlers run.
3. Several built-in handler factories read the global `EnableDegradedMode` to choose a constructor.

The rule "nothing later reads global options" therefore holds for Tenant data: issuer, credentials and validation keys. The handler list, degraded mode and every other Deployment-wide setting must stay identical in every copy. Building each copy from the same options pipeline guarantees that.

## Carry over to later stories

- **Blocking.** Every signature holds a thread-pool thread for one Transit round trip. 32 concurrent requests completed within the 60-second timeout, but no latency or thread-pool figures were measured. Under sustained load it can starve the pool. Before token issuance ships (Story 2.5), load-test the token endpoint, and if needed raise the minimum thread count or move signing off the request thread.
- **PEM parsing outside `src/`.** The spike turns Transit's PEM into `RSAParameters` with `RSA.Create().ImportFromPem`, which `KeyCustodyRuleTests` bans in `src/`. Story 2.3 must build the public key without those calls. Options: decode the SubjectPublicKeyInfo with `System.Formats.Asn1`, or have the OpenBao adapter return modulus and exponent. Wilson's default verifier builds its own RSA object from `RSAParameters`, and that code isn't in `src/`.
- **Ordering.** The Gatekeep handler must stay at `int.MinValue` on `ProcessRequestContext`, and `ResolveRequestUri` must stay removed. An OpenIddict upgrade that adds a handler before it, or renames that handler, breaks the design. Keep a test that asserts the first handler and the removal.
- **Validation keys.** Every per-Tenant copy must set `TokenValidationParameters.IssuerSigningKeys` and `TokenDecryptionKeys` explicitly.
- **PKCE `plain`.** OpenIddict's default `CodeChallengeMethods` includes `plain`. The spike removes it, and production must too. Degraded mode also skips OpenIddict's own PKCE requirement, so the spike's Gatekeep handler enforces S256. Once stores exist (Story 2.2), OpenIddict's requirement applies again. The negative cases are tested in `Authorize_without_S256_PKCE_is_refused_and_issues_no_code`.
- **Unwrapped key lifetime.** The spike unwraps each token protection key once, on the Tenant's first request, and keeps it for the server's lifetime. AD-8 allows at most 5 minutes.
- **Failed builds and custody timeouts.** A Tenant build that fails is cached for the server's lifetime, so that Tenant fails every request until restart. Custody calls, both the build and every sign, have no timeout. Production must evict faulted builds and bound every custody call.
- **Path issuers.** The spike assumes an issuer is an origin only: the request URI is rebuilt from the issuer's scheme and authority, so any issuer path is dropped. Story 2.3 must either forbid issuers with a path or handle them.

## What this doesn't settle

- Custom stores, reference codes and refresh tokens, and the revocation commit are Story 2.2. If that spike fails, its criterion moves the design to a keyed provider and amends AD-8. This spike doesn't.
- The spike ran on TestServer, not Kestrel behind the real proxy, so forwarded headers and TLS termination are untested.
- Key rotation while requests are in flight is Story 2.4. The provider is written to check that Transit signed with the version in `kid`, so a rotation between building a Tenant's options and signing should fail the request instead of issuing a token with the wrong `kid`. That check is **untested**. If it works as written, the cached Tenant runtime keeps the old version, so every sign for that Tenant fails until the runtime is rebuilt. Story 2.4 must handle that.
