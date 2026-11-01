---
review: verification
target: ARCHITECTURE-SPINE.md
target_log: .memlog.md
date: 2026-11-02
verdict: NOT VERIFIED - revise before the first implementation story
---

# Verification Review: Gatekeep Architecture Spine

## Verdict

**Not verified. Revise the spine before the first implementation story.**

The technology choices hold up. Every named product exists, fits the job, and is maintained. The problem is what the spine claims about how they behave:

- AD-3 as written denies all access to every `tenant` table (tested).
- AD-8's handler plan misses where OpenIddict actually gets its issuer and encryption credentials (source read at tag 7.7.2).
- AD-10's seal chain has not been shown to work in Compose, and it claims more than the TPM provides.
- The Stack heading says "Verified against vendor pages on 2026-11-02", but two rows were out of date on that date. The OpenBao row and the memlog note "(2.7 beta)" were wrong by weeks.

The memlog shows web checks only for the Stack versions and OIDC §15.1. Other behavioural claims have no recorded evidence, and that is where these findings sit.

All High findings have a concrete fix. None forces a change of technology.

## How each claim was checked

| Label | Meaning |
| --- | --- |
| **Tested** | Run by this review against the real software |
| **Source** | Read in the upstream source at the stated tag |
| **Doc** | Stated by a vendor or standards page fetched today |
| **Secondary** | Third-party page or test file only |
| **Inferred** | Reasoned from the above and not run. Treat as a spike item |
| **Unconfirmed** | Could not be established |

Environments used:

- PostgreSQL 18.6 in Docker (`postgres:18.6`).
- OpenBao 2.6.4 dev mode in Docker.
- OpenBao 2.7.2 native Windows binary, with raft storage and a static seal.
- OpenIddict at tag 7.7.2 (commit 950cb13, because `dev` already differs).
- EF Core `release/10.0`.
- Fido2 at tag 4.3.2.
- Microsoft.IdentityModel at default-branch head. This is not the version OpenIddict 7.7.2 resolves.

### Limits of this review

- **Docker Desktop stopped partway through testing.** The first static-seal test had also failed on a bad config mount, so it proved nothing.
- **Nothing was tested on Linux with systemd, TPM2 or Compose.** That means no `systemd-creds`, no Compose secrets, no OpenBao Unix listener and no file-permission test. OpenBao's container user (uid 100) was observed, but its effect on key access is inferred.
- **The OpenIddict findings come from reading source.** No per-Tenant OpenIddict code was run, so the proposed fixes still need the AD-8 spike.
- **Throughput figures are from a 16-core Windows desktop over plain loopback TCP.** They are order-of-magnitude only.

## Findings

### F-1. High. AD-3: a `RESTRICTIVE` policy alone denies everything

**Claim:** `tenant` tables have ENABLE, FORCE and "a `RESTRICTIVE` policy".

**Evidence (Tested, PostgreSQL 18.6):** With only that policy and a correctly set Tenant, a matching row returned 0 rows and the insert failed with `new row violates row-level security policy`. Adding a permissive `USING (true) WITH CHECK (true)` policy gave the intended behaviour (1 row visible when scoped). Doc: PostgreSQL combines restrictive policies with AND and uses default-deny when no policy applies; the page does not spell out the restrictive-only case, so the test is the stronger evidence.

**Impact:** This fails closed, so it leaks nothing, but every `tenant` query breaks. The spine's CI catalogue test could pass while this is present, because it asserts the policy exists rather than that it works.

**Fix:** Amend AD-3 to require one permissive policy plus the restrictive one on every `tenant` table. Have the catalogue test assert both from `pg_policies.permissive`. Add a behavioural test that a scoped role sees its own row and only its own row.

### F-2. High. AD-8: "handlers after the built-in ones" misses the issuer and several credential reads

**Claim:** Per-Tenant issuer, credentials and JWKS are supplied by custom handlers ordered after the built-in ones. AD-6 adds that the issuer is never read from the request.

**Evidence (Source, OpenIddict 7.7.2):**

- `Options.Issuer ?? BaseUri` appears at 14 sites, not one. They are in `OpenIddictServerHandlers.cs` (636, and 8 claim-setting sites from 3711 to 4821), `Handlers.Authentication.cs:2246`, `Handlers.Discovery.cs:370`, `Handlers.Introspection.cs:710`, `Handlers.Userinfo.cs:475` and `Handlers.Protection.cs:191`.
- `BaseUri` is built from the request Host (`OpenIddictServerAspNetCoreHandlers.cs:102`). With no global `Issuer`, which a multi-Tenant deployment cannot set, **the default issuer is request-derived. AD-6 forbids exactly that.**
- `Options.SigningCredentials` is also read outside the two handlers the memlog names: `at_hash`/`c_hash` calculation (`Handlers.cs:5391`) and the algorithm list in discovery (`Handlers.Discovery.cs:760`).
- `id_token_signing_alg_values_supported` therefore depends on the inert key, which must be declared RS256. A custom `SecurityKey` that OpenIddict cannot serialise is dropped from JWKS with a warning, but an `RsaSecurityKey` would be published. The inert key's type decides whether the AD-8 test is meaningful.
- `Handlers.Protection.cs:189` clones `Options.TokenValidationParameters`, so issuer signing keys and decryption keys also come from global options unless replaced.

**A better mechanism exists (Source):** `OpenIddictServerTransaction.Options` has a public setter (line 58), and `context.Options` is simply `Transaction.Options` (`OpenIddictServerEvents.cs:83`). `BaseUri` also has a public setter.

**Fix:**

1. Make this the spike's primary design: one early `ProcessRequestContext` handler replaces `context.Transaction.Options` with a per-Tenant copy (Issuer, credentials, validation parameters) built from the stored Tenant record. Every built-in handler then reads Tenant values without being individually overridden.
2. Set `BaseUri` from the stored record in the same handler, ordered after the ASP.NET Core handler that sets it.
3. Add negative tests: a mismatched `Host` must not change `iss`, `at_hash` must use the Tenant's algorithm, and the inert key must never appear in JWKS or discovery.

Whether a replaced options object is honoured through every flow is **Inferred**. `IOptionsMonitor.CurrentValue` is still read in places, though the sites inspected only check startup-style flags such as degraded mode. The spike must prove it.

### F-3. High. AD-8 and AD-10: encryption credentials are missing from the design, and codes and refresh tokens are signed too

**Claim:** AD-8 covers "credentials" and an inert global key. AD-10 says no host process holds private signing material and secrets live in Transit.

**Evidence (Source, OpenIddict 7.7.2):**

- `OpenIddictServerConfiguration.Validate` raises ID0085 unconditionally when `EncryptionCredentials` is empty. `DisableAccessTokenEncryption` does not remove the requirement.
- `AttachSecurityCredentials` (`Handlers.Protection.cs:1470-1485`) encrypts every token type except identity tokens and unencrypted access tokens, including authorization codes and refresh tokens. A throwing inert encryption key would break both.
- The same handler signs every token type, using the first signing credential. Reference tokens still have a JWS/JWE payload, stored in the token table's `Payload` column.

**Impact:**

- `Host.Hosted` needs a live decryption key in process, and the spine never says where it lives. That key protects stored refresh-token and code payloads for all Tenants if it is Deployment-wide, which is the "Deployment-level credentials" risk AD-8 exists to prevent.
- Signing all of them in Transit means about 4 Transit calls per sign-in (code, access, ID, refresh) and each read of a code or refresh token also needs signature validation. Capacity is not the problem: 2.7.2 managed about 440 signs/s on one connection and about 3,800 at concurrency 16 (Tested, rough). The design question is whether internal artifacts should use Transit at all.

**Fix:** Decide this explicitly in AD-8 and AD-10. Two options to take into the spike:

- **Option A:** Use OpenIddict's Data Protection token format for internal tokens. The OpenIddict docs mention it for reference-token payloads, and the `OpenIddict.Server.DataProtection` package exists at 7.7.2. Data Protection keys then need their own custody rule.
- **Option B:** A per-Tenant symmetric key, wrapped by Transit and held in memory briefly. This needs an explicit exception to AD-14's in-memory rule.

Keep RSA Transit signing for access and ID tokens only. Which option is better is **Inferred** and was not tested.

### F-4. High. AD-10 and AD-26: the seal chain is unproven in Compose and claims more than the TPM gives

**Claim:** The barrier key is the Master Key, held by `systemd-creds` sealed to TPM2, with OpenBao in the Docker Compose deployment. The memlog says the TPM is the root of trust the static seal docs ask for.

**What holds:**

- `seal "static"` exists in 2.7.x and auto-unseals. Tested on 2.7.2 with raft: restart unsealed and signed on the first try. With the wrong key it stayed sealed with an authentication failure.
- It is not among the seals removed in 2.7.0 (Doc).
- Keys load through `file://` or `env://` and must be 32 bytes (Doc).
- `n-1` to `n` rotation is supported (Doc).
- `systemd-creds --with-key=tpm2` ties a credential to the original chip (Doc).

**What does not hold or is unconfirmed:**

1. **The docs do not say what the memlog says.** The page does not use "root of trust". It recommends the static seal only "when an existing source of trust, such as another third-party secrets manager" exists. A local TPM is a reasoned substitute, not vendor-endorsed. Record it as an accepted risk.
2. **There is no defined way to get the key into the container.**
   - Compose file secrets are bind mounts, and `uid`, `gid` and `mode` are "silently ignored" (Doc).
   - The OpenBao image runs as uid 100 (Tested), so a root-only `0400` file is likely unreadable (**Inferred**; the test did not complete).
   - Whether `dockerd` can see `$CREDENTIALS_DIRECTORY` from a unit's namespace is **Unconfirmed**. One secondary source says the directory exists only in the service's namespace.
3. **The protection is narrower than AD-10's "prevents" line.** Without PCR binding, which is off by default (Doc), root on the running host can decrypt the credential. Once decrypted, the key sits in tmpfs and in OpenBao's memory. This protects stolen disks and backups, not a live root compromise. PRD §9 server compromise is not covered by this control.
4. **"The barrier key is the Master Key" is imprecise.** The status output and config describe a seal key used for auto-unseal, not the barrier key itself. `operator init` also emits Shamir **recovery keys** (Tested), and the spine gives them no custody rule.
5. **The storage backend and the hosts' OpenBao login method are unstated.** Raft is effectively required: `operator raft snapshot save` worked (Tested) and 2.7.0 removed `file` from the server (Doc). AD-2 and AD-10 rely on per-host policies but do not say how a host authenticates.
6. **Chip loss needs a runbook.** A TPM-sealed credential cannot move to replacement hardware, so the escrow copy is the only path. Credentials made on systemd v262+ are also incompatible with earlier versions (Doc).

**Fix:**

- Run a Linux spike before relying on AD-10.
- Prefer running OpenBao as a native systemd service using `LoadCredentialEncrypted=`, with the Unix socket shared to containers. This avoids the Compose secret problem entirely. It does change AD-26's "all Compose", so it needs a decision. The alternative is an `ExecStartPre` decrypt to tmpfs with a matching uid.
- Reword AD-10's scope to at-rest protection.
- Decide on PCR binding (`--tpm2-pcrs=7` or a signed PCR 11 policy), weighing update lockouts.
- Add recovery key custody, the login method and raft to AD-10.
- Add static seal rotation to the runbook.

### F-5. High. Stack table: "Verified" is untrue for OpenBao and React

| Item | Spine | Actual on 2026-11-02 |
| --- | --- | --- |
| OpenBao | 2.6.4, memlog "(2.7 beta)" | 2.7.0 GA on 2026-09-23; **2.7.2 and 2.6.5 on 2026-10-26** |
| React | 19.3.0 | 19.3.1 is `latest`, published 2026-10-14 per one secondary source |

OpenBao 2.6.5 and 2.7.2 fix published advisories that 2.6.4 lacks, including GHSA-5pmx-2p74-x478 (Transit imported-key backup path traversal) and GHSA-736f-82w7-hj22 (includes AppRole path canonicalization). The AppRole fix matters if AppRole becomes the host login method. Key custody should not start on a superseded patch.

**Fix:** Pin OpenBao 2.7.2, which this review tested for signing, static seal, raft and restart. The rsa-3072 create, sign and non-export tests were on 2.6.4, and create and sign were repeated on 2.7.2. Pin React 19.3.1. The RSC-focused notes are unlikely to matter here because Gatekeep uses no Server Components, but the claim is secondary-sourced. Change the Stack heading to record the check date per row.

### F-6. Medium. AD-10: "Tenant ID as bound context" silently does nothing if built on Transit `context`

**Evidence (Tested, 2.7.2):** On a normal `aes256-gcm96` key, encrypting with `context=tenantA` and decrypting with `context=tenantB` **succeeded and returned the plaintext**, with no warning. Both alternatives enforce binding: `associated_data` failed with `message authentication failed` on mismatch, as did a `derived=true` key with `context`.

**Impact:** Per-Tenant keys still separate Tenants, so this is defence in depth. But the obvious implementation gives no binding and no error.

**Fix:** State the mechanism in AD-10: `associated_data` on a non-derived key, recommended because it also suits binding purpose and record ID. Add a negative test that wrong context fails.

### F-7. Medium. AD-18: "migrations in one transaction" is valid PostgreSQL but not what EF Core does by default

**PostgreSQL (Tested):** Normal DDL, `SET UNLOGGED` and `CREATE POLICY` ran in a transaction. These failed:

- `CREATE INDEX CONCURRENTLY` and `ALTER SYSTEM` cannot run in a transaction block.
- `ALTER TYPE ... ADD VALUE` on an existing enum works, but using the new value in the same transaction fails with `unsafe use of new value`.

**EF Core (Source and Doc):** `Migrator.MigrateImplementation` executes each migration's command list with `commitTransaction: useTransaction` (`Migrator.cs:184-185`). The default therefore commits per migration, so a failure can leave earlier migrations applied (**Inferred** from source; confirm with a two-migration failure test). Wrapping it in your own transaction:

- raises `MigrationsUserTransactionWarning`, an exception by default since EF Core 9 (Doc);
- skips EF's database lock, because the lock is taken only when `useTransaction` is true (Source);
- throws if any migration suppresses its transaction, or if the context uses a retrying execution strategy (`MigrationCommandExecutor.cs:50`).

**Fix:** Generate the SQL script at release time and have `gatekeep upgrade` run it in one transaction with its own advisory lock. Alternatively, wrap `Migrate` in a suppressed user transaction with a non-retrying strategy and your own lock. Add a CI rule banning `suppressTransaction`, `CONCURRENTLY` and same-release enum add-and-use. State how large-table online indexing will be handled, since it can never join this transaction.

### F-8. Medium. AD-26: a stock Caddy image cannot do wildcard DNS-01, and the provider is chosen at install

**Holds (Doc):** Wildcards need DNS-01. `_acme-challenge` CNAME delegation is supported through `dns_challenge_override_domain`, which needs the full target name because `_acme-challenge` is not prepended. `resolvers` and `propagation_delay` are available.

**Conflict:** DNS providers are `caddy-dns` plugins, so a Caddy build with the plugin is required. AD-26 demands pinned, signed images per release, while the Deferred section picks the DNS provider at install. The spine does not say which build is signed.

**Also:** `.localhost` names cannot use a public CA, so local Caddy uses its internal CA and a different TLS block (Doc). "Same Compose definition with different values" needs that TLS config to be a value too.

**Fix:** Either choose the delegation-zone DNS provider at build time and ship one custom image, which delegation makes easy because the provider only hosts the validation zone, or publish a small set of images. Record the `_acme-challenge` setup in the runbook.

### F-9. Medium. AD-8, AD-3 and AD-4: OpenIddict EF custom entities need more than `tenant_id`

**Holds (Doc and Source):** `ReplaceDefaultEntities` plus `UseOpenIddict` with custom types is the documented route. `Guid` keys are fine.

**Needs handling (Source, 7.7.2):**

- `ClientId`, Scope `Name` and Token `ReferenceId` are unique on their own column. Two Tenants cannot reuse a `client_id` or scope name until these become `(tenant_id, ...)`.
- Application, Authorization and Token foreign keys are single-column, which contradicts AD-3's composite foreign key rule. They need a remap in `OnModelCreating`, or a recorded exception. Whether the model remap works cleanly is **Inferred**.
- Stores call `SaveChangesAsync` directly. All must run inside the `TenantScope` transaction. The store transaction helper returns null if a transaction already exists, because it catches the failure (`OpenIddictEntityFrameworkCoreHelpers.cs:266-273`), so nesting appears safe.
- These writes bypass AD-5's "every state change is a command" rule. Record OpenIddict as a named exception, and say how audit events join the same transaction.
- **Refresh reuse:** a request that detects reuse returns an error but must still commit its revocation (`Handlers.Protection.cs:1255`). A scope that rolls back on error responses would undo it (**Inferred**). Test this in the spike.
- The prune routines query across Tenants, so they must run per Tenant under AD-4.

**8.0 note:** `dev` already adds Session and Resource entities (Source). Do not adopt the 8.0 preview, and expect migration work later.

### F-10. Medium. AD-9: Transit signing with `SignatureProvider`

**Answer (Source and Tested):** Transit works, but only as a blocking call through this API.

- `SignatureProvider` has no async member. `JsonWebTokenHandler` calls the span `Sign` overload, whose base implementation throws `NotImplementedException` (`SignatureProvider.cs:126`, `JwtTokenUtilities.cs:201`). A custom provider must override it as well as `Sign(byte[])`. Confirm this against the IdentityModel version OpenIddict 7.7.2 resolves.
- `GenerateIdentityModelToken` calls `CreateToken` synchronously, and handlers are async. It returns early if a token is already attached (`Handlers.Protection.cs`, the "already attached" check).
- Transit details: `rsa-3072`, `signature_algorithm=pkcs1v15`, `marshaling_algorithm=jws` works on RSA and returns base64url, with a `vault:v1:` prefix to strip. Verified. Export is refused and deletion is off until `deletion_allowed` is set (Tested), so AD-11's destruction job must set it first.

**Fix:** Add a handler ordered before `GenerateIdentityModelToken` that builds the header and payload, awaits `IKeyCustody.SignAsync`, and sets `context.Token`. This avoids sync-over-async. A blocking `HttpClient.Send` is a fallback, not tested here. Throughput is not the risk.

### F-11. Low. AD-9: `{tenantPublicId}.{random}` needs two custom handlers

No length check blocks a custom format (Source; this review had expected one and did not find it at 7.7.2). The ID is generated in `AttachTokenPayload` and replaces `context.Token`. Outbound, add a handler after it. Inbound, validate and strip the prefix before `ValidateReferenceTokenIdentifier`, or `FindByReferenceIdAsync` will miss. Include the prefix in the AD-9 spike. `ReferenceId` has a max length of 100, but the stored form is a hash.

### F-12. Low. Local development on `*.gatekeep.localhost`

- **Secure context:** `.localhost` hosts qualify when the browser guarantees loopback resolution (Doc, optional for browsers).
- **WebAuthn:** Chromium allows `.localhost`, including over HTTP, and treats `localhost` as a TLD (Doc). Firefox's own tests list `subdomain.localhost` as a valid RP ID (Secondary, test source).
- **`__Host-` cookies:** Chrome and Firefox relax `Secure` on localhost. Safari drops them over plain HTTP (Secondary).
- **Safari with `*.localhost`:** **Unconfirmed**, for both name resolution and WebAuthn.

**Fix:** Run local through Caddy over HTTPS with its internal CA, and treat Chromium and Firefox as the supported local browsers. Test Safari on the rehearsal VM with a real domain.

### F-13. Low. AD-16: RFC 8785 is real but carries caveats

RFC 8785 exists, dated 2020, Informational, published outside the IETF standards track (Doc). Nothing fetched shows it updated or obsoleted, and errata status is **Unconfirmed**. .NET has no built-in canonicaliser that this review confirmed, and the spine names no library. Pick one in the Audit story and commit test vectors, because the canonical bytes become a permanent contract. Keeping the envelope to strings and integers avoids number-format risk.

### F-14. Low. Licence and deployment notes

- **Geist:** SIL OFL 1.1, Copyright 2023 Vercel with basement.studio, with no Reserved Font Name (Doc). Self-hosting and subsetting are fine. Ship the licence text with `packages/ui`.
- **pgBackRest 2.60.0:** A notice dated October 2026 covers weak encryption subkeys and salts, and 2.59.3 carries the fix. New repositories on 2.60.0 are after the fix; read the notice before any repository created earlier is reused.
- **`FORCE ROW LEVEL SECURITY`** applies to `gk_migrator` as table owner (Doc). Data backfills in migrations will hit RLS, so decide how they run.

## Resolved, including one Open Item

| Item | Result | Evidence |
| --- | --- | --- |
| **Open Item: reference token hashing** | **Close it.** IDs are stored as SHA-256 in `CreateAsync`, and lookups hash too. `ObfuscateReferenceIdAsync` is `protected virtual`. The canary scan remains a good check | Source, 7.7.2 and `dev` |
| Codes are reference tokens | Default. Refresh tokens need `UseReferenceRefreshTokens()` | Doc |
| No reuse leeway | Default is 30 seconds, so AD-13 needs explicit config. Use `SetRefreshTokenReuseLeeway(null)`: `IsReusableAsync` then returns false immediately, while `TimeSpan.Zero` still treats a token with no redemption date as reusable | Source |
| `current_setting` failing cast | Holds in both states. Never set: `unrecognized configuration parameter`. After a local `set_config` commits: value is `''` and the cast fails on `""`. Both raised on non-empty and empty tables | Tested |
| `UNLOGGED` + RLS | Works, policies enforced, including `WITH CHECK` | Tested |
| pgBackRest skips UNLOGGED | Yes: temporary and unlogged relation files are excluded | Doc (release notes) |
| PostgreSQL 18 in pgBackRest | Supported | Doc (release notes) |
| EF Core + Npgsql on PostgreSQL 18 | Fits. Npgsql 10.0.3 needs EF Core 10.0.4 to <11, so 10.0.14 is in range. Release notes cover PG18 features. A formal version range was not found. Use `SetPostgresVersion(18, 0)` to get `uuidv7()` translation; `uuidv7()` ran on 18.6 | Doc, Tested |
| Fido2 per-request RP ID | Supported by constructing `new Fido2(config, mds)` per Tenant. `ServerDomain` and `Origins` are on the config. `AddFido2` registers one config, so skip that and build per request. Assertion uses `options.RpId` from stored options | Source, 4.3.2 |
| RS256 mandatory | Quote is accurate, including the `none` exception | Doc (OIDC Core §15.1) |
| Unix socket listener | Exists with mode, user and group options. Not run | Doc |
| MassTransit v9 commercial | Confirmed | Doc |

## Decision-by-decision status

| AD | External claim | Status |
| --- | --- | --- |
| AD-1, 2, 5, 7, 19, 20, 22, 23 | Internal design. AD-2 depends on OpenBao login method | No external fact to check, see F-4 |
| AD-3 | RLS policy shape, failing cast | **Wrong on shape** (F-1). Cast holds |
| AD-4 | `set_config` local, no PgBouncer | Holds (Tested) |
| AD-6 | Issuer never from request | **Not met by default** (F-2) |
| AD-8 | Handlers, inert key, custom entities | **Incomplete** (F-2, F-3, F-9) |
| AD-9 | RS256, `at+jwt`, reference tokens, prefixed IDs | Holds with work (F-10, F-11) |
| AD-10 | Transit, static seal, TPM | Transit holds. **Seal chain unproven** (F-4, F-6) |
| AD-11 | Key states, JWKS | Internal. Needs `deletion_allowed` (F-10) |
| AD-12 | `__Host-` cookies | Holds on HTTPS (F-12) |
| AD-13 | Token Family, reuse | `RevokeByAuthorizationIdAsync` exists. See F-9 |
| AD-14 | UNLOGGED under RLS | Holds (Tested) |
| AD-15 | `SKIP LOCKED`, `LISTEN/NOTIFY` | Standard PostgreSQL. Not separately tested |
| AD-16 | RFC 8785 | Holds with caveat (F-13) |
| AD-17 | S3 Object Lock compliance mode | Vendor deferred. **Not checked** |
| AD-18 | pgBackRest, snapshot, one transaction | Partly (F-7). Snapshot saved; **restore not tested** |
| AD-21 | JSON data block under strict CSP | **Not checked by this review** |
| AD-24 | Argon2id, SHA-256, Transit HMAC | `transit/hmac` works on an AES key (Tested) |
| AD-25 | OpenID conformance | Still open in the spine. **Not checked** |
| AD-26 | Compose, Caddy, `.localhost` | Partly (F-4, F-8, F-12) |

## Stack table

| Name | Spine | Current stable found | Result | Note |
| --- | --- | --- | --- | --- |
| .NET SDK / runtime | 10.0.403 / 10.0.14 | Same | OK | Released 2026-10-25 |
| ASP.NET Core, EF Core | 10.0.14 | Same | OK | EF 11 RC 3 exists. .NET 11 GA date **Unconfirmed**. Stay on 10, believed LTS (support page not read) |
| OpenIddict | 7.7.2 | 7.7.2 | OK | 2026-10-10. 8.0 is preview |
| Npgsql EF | 10.0.3 | 10.0.3 | OK | 2026-07-10 |
| Fido2.AspNet | 4.3.2 | 4.3.2 | OK | 2026-10-29. Three security or validation releases since 2026-10-02, so watch advisories |
| PostgreSQL | 18.6 | 18.6 | OK | 19 is RC 1 as of the page read; do not move yet. A November minor is likely but **Unconfirmed** |
| OpenBao | 2.6.4 | **2.7.2 / 2.6.5** | **STALE** | F-5 |
| Caddy | 2.11.7 | 2.11.7 | OK | 2026-10-03. Needs plugin build (F-8) |
| pgBackRest | 2.60.0 | 2.60.0 | OK | 2026-10-18 |
| Node.js | 26.13.0 | 26.13.0 | OK | Listed as latest LTS |
| pnpm | 12.16.1 | 12.16.1 | OK | |
| React | 19.3.0 | **19.3.1** | **STALE** | F-5 |
| Vite | 8.3.5 | 8.3.5 | OK | |

## Memlog claims not checked

Valkey 9, Hangfire and Wolverine lacking an explicit-Tenant rule, the Storm-0558 precedent, and conformance suite PKCE behaviour.

## Sources

OpenIddict: [OpenIddict.AspNetCore on NuGet](https://www.nuget.org/packages/OpenIddict.AspNetCore), [openiddict-core at 7.7.2](https://github.com/openiddict/openiddict-core/tree/7.7.2), [EF Core integration](https://documentation.openiddict.com/integrations/entity-framework-core), [token storage](https://documentation.openiddict.com/configuration/token-storage).

OpenBao: [static seal](https://openbao.org/docs/configuration/seal/static/), [Unix listener](https://openbao.org/docs/configuration/listener/unix/), [2.7 release notes](https://openbao.org/community/release-notes/2-7-0/), [releases](https://github.com/openbao/openbao/releases).

systemd and Docker: [systemd-creds](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html), [systemd credentials](https://systemd.io/CREDENTIALS/), [Compose services reference](https://docs.docker.com/reference/compose-file/services/).

PostgreSQL and backup: [row security](https://www.postgresql.org/docs/18/ddl-rowsecurity.html), [admin functions](https://www.postgresql.org/docs/current/functions-admin.html), [versioning](https://www.postgresql.org/support/versioning/), [pgBackRest releases](https://pgbackrest.org/release.html), [pgBackRest repository](https://github.com/pgbackrest/pgbackrest).

.NET: [.NET 10 downloads](https://dotnet.microsoft.com/en-us/download/dotnet/10.0), [Microsoft.EntityFrameworkCore](https://www.nuget.org/packages/Microsoft.EntityFrameworkCore), [Npgsql EF package](https://www.nuget.org/packages/Npgsql.EntityFrameworkCore.PostgreSQL), [EF Core 9 breaking changes](https://learn.microsoft.com/en-us/ef/core/what-is-new/ef-core-9.0/breaking-changes), [Npgsql EF 10 notes](https://www.npgsql.org/efcore/release-notes/10.0.html), [EF Core source](https://github.com/dotnet/efcore/tree/release/10.0), [IdentityModel source](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet), [Fido2.AspNet](https://www.nuget.org/packages/Fido2.AspNet), [fido2-net-lib](https://github.com/passwordless-lib/fido2-net-lib).

Caddy and standards: [Caddy tls directive](https://caddyserver.com/docs/caddyfile/directives/tls), [Automatic HTTPS](https://caddyserver.com/docs/automatic-https), [RFC 8785](https://www.rfc-editor.org/info/rfc8785), [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html), [Secure Contexts](https://w3c.github.io/webappsec-secure-contexts/), [Chromium WebAuthn origins](https://chromium.googlesource.com/chromium/src/+/main/content/browser/webauth/origins.md), [Firefox RP ID tests](https://searchfox.org/firefox-main/source/dom/webauthn/tests/gtest/TestWebAuthnRpIdCommon.h), [httpwg issue 2605](https://github.com/httpwg/http-extensions/issues/2605).

Other: [Geist licence](https://raw.githubusercontent.com/vercel/geist-font/main/LICENSE.txt), [MassTransit v9](https://masstransit.io/introduction/v9-announcement), [Node.js releases](https://nodejs.org/en/about/previous-releases), [react on npm](https://www.npmjs.com/package/react), [vite on npm](https://www.npmjs.com/package/vite), [pnpm on npm](https://www.npmjs.com/package/pnpm).
