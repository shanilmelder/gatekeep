# OpenIddict custom stores spike (Story 2.2)

**Outcome: pass. AD-8 and AD-13 hold as written. Every proof passed, so neither needed amending. Stories 2.6, 2.7 and 2.10 must carry over the findings below.**

Date: 2026-11-02. The spike extends the [Story 2.1 spike](2-1-openiddict-per-tenant.md). It has the same two Tenants on the same two hosts, the same Transit signing and the same per-Tenant options. In stores mode, degraded mode is off and OpenIddict 7.7.2 (`OpenIddict.Core` managers, `OpenIddict.Server.AspNetCore`) runs on three custom stores. Each store is backed by a spike table in a migrated PostgreSQL 18.6 clone (`PostgresFixture.NewMigratedDatabaseAsync()`):

- `spike_application`
- `spike_authorization`
- `spike_token`

Each table has `tenant_id`, the same `ENABLE`/`FORCE` row-level security policy pair as the migrated tenant tables, and only the grants `gk_hosted` needs:

| Table | `gk_hosted` grants |
| --- | --- |
| `spike_application` | `SELECT` |
| `spike_authorization` | `SELECT`, `INSERT`, `UPDATE` |
| `spike_token` | `SELECT`, `INSERT`, `UPDATE` |

The request path connects as `gk_hosted`. Each Tenant has a `tenant` row. Its public ID is held in memory, because `tenant` has no `public_id` column yet.

The code is test-only, in `tests/Isolation/Spikes/OpenIddict/`, with the stores in `Stores/`. Nothing is in `src/`, and there is no production migration, `TableRegistry` entry or OpenBao policy change. `SpikeServer.StartAsync` still builds Story 2.1's degraded-mode server, and `SpikeServer.StartWithStoresAsync` builds this one. The tests are `CustomStoresSpikeTests`, in the `OpenBao` collection and using `PostgresFixture`. All 15 of them passed, and so did the 11 `PerTenantOptionsSpikeTests`, which are unchanged.

## Proof results

| Proof (I/O matrix row) | Result | Test |
| --- | --- | --- |
| One authorization per flow | `pass` | `Each_completed_code_flow_creates_one_authorization_that_every_token_references` |
| Rotation | `pass` | `Refresh_issues_a_new_refresh_token_and_marks_the_old_one_redeemed` |
| Reuse commits revocation | `pass` | `Reused_refresh_token_revokes_its_family_and_the_revocation_and_event_survive_the_rollback` |
| Revoked authorization | `pass` | `Refresh_under_an_authorization_revoked_in_the_database_is_refused_and_issues_nothing` |
| No entity cache | `pass`, but weak (see below) | `A_row_changed_in_the_database_between_requests_is_seen_because_entity_caching_is_off` |
| Confidential client, null secret column | `pass` | `Confidential_client_is_checked_by_the_Gatekeep_handler_and_its_secret_column_stays_null` |
| Reference ID form | `pass` | `Code_and_refresh_token_are_reference_ids_prefixed_with_the_Tenants_public_id` |
| Cross-Tenant reference | `pass` | `Code_or_refresh_token_from_one_Tenant_is_refused_on_another_before_any_store_lookup` |
| Failed request leaves no state | `pass` | `Code_redeemed_with_a_bad_PKCE_verifier_is_refused_and_leaves_the_store_as_it_was`, `Sign_in_rejected_after_its_writes_rolls_every_write_back` |

Supporting tests:

| What | Test |
| --- | --- |
| Degraded mode off, and the kept settings and handler replacements in place, including `ValidateGatekeepScopes`. `RejectForeignReferenceIds` is ordered after `RemoveDisallowedCharacters` and before `ValidateReferenceTokenIdentifier`. Spike tables under forced RLS with the restrictive `{table}_tenant` policy, no write grant on Applications and no `DELETE` anywhere | `Stores_mode_runs_with_degraded_mode_off_and_the_settings_AD8_keeps` |
| `ValidateGatekeepScopes`, the only scope gate, refuses an unknown scope on authorize and on Client Credentials with `invalid_scope`, issues nothing and writes nothing | `Unknown_scope_is_refused_by_the_Gatekeep_scope_handler_and_writes_nothing` |
| OpenIddict's own revoke, on the request transaction alone, is lost when the request rolls back. This is the evidence for the `FailureContext` path | `Reuse_revocation_on_the_request_transaction_alone_is_lost_with_the_rollback` |
| A replayed code revokes its family, and the revocation commits on the same path as refresh reuse (AD-13) | `Replayed_code_revokes_its_family_and_the_revocation_commits` |
| With stores, OpenIddict's own PKCE check refuses `plain` and a missing challenge. Degraded mode needed a Gatekeep handler for this | `Authorize_without_S256_PKCE_is_refused_by_OpenIddict_itself_and_writes_nothing` |

Every test also checks that the inert global credentials are used 0 times. No test compares a token, code or secret value in an assertion that could print it. A token is found by the SHA-256 hash the store holds, and two values are compared with `Assert.True(a != b, …)`. The server clears its logging providers, so no value reaches test output. No test depends on a token lifetime, so none needs a fake clock, and none waits on the wall clock.

## The spike build

**Request transaction.** `SelectTenantOptions` is still the first handler (`ProcessRequestContext`, order `int.MinValue`). After it swaps in the Tenant's options, it opens a `TenantScope` on the `gk_hosted` data source for the resolved Tenant. The scope is held by `SpikeRequestTransaction`, a service scoped to the HTTP request. All three stores take that service and run every command through its `CommandContext`. A store call with no open scope throws, so none can fall back to autocommit.

**Endpoint end.** `EndRequestTransaction<TContext>` runs first (order `int.MinValue`) on `ApplyAuthorizationResponseContext` and `ApplyTokenResponseContext`, before the response is written:

- A response with no error commits.
- An error response with no revocation recorded rolls back.
- An error response with a Token Family revoked on the way goes through `FailureContext.CommitAfterRollbackAsync`. That rolls the request back, then revokes the family's tokens again and appends one audit event in a fresh `TenantScope`, and commits.

Any other endpoint, such as discovery or JWKS, never commits. Its scope is disposed with the request's service scope, which rolls it back.

**Stores.** `SpikeApplicationStore` only reads, and refuses `Create`, `Update` and `Delete`, because Application writes are Directory's. `SpikeAuthorizationStore` and `SpikeTokenStore` write with an optimistic concurrency token and raise OpenIddict's `ConcurrencyException` when it doesn't match. LINQ query overloads and `Prune` throw `NotSupportedException`. No flow called any of them. No scope store is registered: resolving `IOpenIddictScopeManager` throws, OpenIddict's scope validation is off, and `ValidateGatekeepScopes` refuses any scope other than `openid` and `offline_access`.

**Kept settings:**

- Entity caching is disabled (`DisableEntityCaching()`).
- Rolling refresh tokens and authorization storage stay on.
- `RefreshTokenReuseLeeway` is `null`.
- Refresh tokens are reference tokens (`UseReferenceRefreshTokens()`). Codes already are, whenever token storage is on.
- `CodeChallengeMethods` is `S256` only.
- `ValidateClientSecret` is removed. In its place, `ValidateGatekeepClientSecret`, at the same order, checks the spike secret, and every `client_secret` column stays null.
- `AttachTokenPayload` is replaced by `AttachTenantReferenceId`, and `RejectForeignReferenceIds` is added.

## What each proof showed

**One authorization per flow.** A code flow with `offline_access` creates exactly one `ad-hoc` authorization row, in OpenIddict's `AttachAuthorization`. Every token from that flow carries its ID: the code, then the access, refresh and ID tokens from the code and from each of two refreshes, 10 rows in all. A refresh doesn't create a new authorization, because the refresh token's principal already carries one. A second completed flow creates a second authorization, with 4 tokens of its own. So the authorization is a Token Family, as AD-13 defines it.

**Rotation.** Each refresh returns a new refresh token. The old token's row moves to `redeemed` with a `redemption_date` (OpenIddict's `RedeemTokenEntry` and `TryRedeemAsync`), and the new one is `valid`.

**Reuse commits revocation.** The refresh token that was rotated out is presented again. OpenIddict's `ValidateTokenEntry` finds it `redeemed` and, with no leeway, calls `RevokeByAuthorizationIdAsync`, which reaches `SpikeTokenStore`. The store records the family ID on the request before it runs its `UPDATE`, so the family is captured before any rollback. OpenIddict then rejects with `invalid_token`, which the token endpoint returns as `invalid_grant`. At endpoint end, `FailureContext` rolls the request back and commits the revocation and one `sessions.token_family.revoked` audit event in a fresh scope. The event's target is the family's Application. The test checks:

- the response is `invalid_grant` and carries no token
- all 7 tokens of the family are `revoked` in the database
- the family's authorization row is still `valid`
- exactly one audit event exists
- the newest refresh token is then refused with `invalid_grant`, and that refusal adds no second event

The tokens are revoked, but the authorization row is not. That is OpenIddict's choice, stated in `ValidateTokenEntry`'s comment: the authorization is left alone "to allow the legitimate client to start a new flow". Under AD-13 that row is the Token Family, so after a reuse the family's tokens are dead while the family itself still reads `valid`. No new token can come from it, because every token in it is revoked and a new flow creates a new authorization. Stories 2.7 and 2.10 must still decide whether `RevokeAccess` also revokes the authorization (see carry-over).

**Which path actually commits.** The design note asked this. OpenIddict's own revoke call did not fail on the request transaction, so there was no aborted transaction (25P02) to observe. It did run, and the rollback at endpoint end discarded it: with the `FailureContext` step switched off, the reused token is still refused, but the newest refresh token stays `valid`, still redeems, and no audit event exists. So the request transaction alone never commits a reuse revocation. The fresh scope under `FailureContext` is the path that commits. A replayed authorization code takes the same path: OpenIddict revokes the family's tokens in `ValidateTokenEntry`, the store captures it, and it commits after the rollback. Here too the authorization row stays `valid`.

**Revoked authorization.** With the authorization row set to `revoked` directly in the database, a refresh fails in `ValidateAuthorizationEntry` with `invalid_grant`. The response carries no tokens, and the request rolls back with no new row.

**No entity cache.** A Client Credentials request succeeds. Then `gt:client_credentials` is removed from that Application's row by SQL, and the next request gets `unauthorized_client`. Tenant B's untouched row still issues. With caching disabled, every manager call goes straight to the store, and `Stores_mode_runs_with_degraded_mode_off_and_the_settings_AD8_keeps` checks that `DisableEntityCaching` is set.

This proof is weaker than it looks. In 7.7.2, OpenIddict registers its entity caches as scoped services, each holding its own `MemoryCache`, so a cache lives for one request only. The test would also pass with caching on. What disabling the cache actually prevents is a stale entity within one request, such as a token read before and after another transaction changes it. The spike doesn't test that case. Keep `DisableEntityCaching()` anyway (AD-8): it costs nothing with per-request caches, and it means no OpenIddict upgrade that widens the cache's lifetime can change behaviour.

**Confidential client, null secret column.** The right secret gets a token with Tenant A's issuer, and a wrong secret gets `invalid_client` from `ValidateGatekeepClientSecret`, because nothing else checks the secret once `ValidateClientSecret` is removed. A request with no secret at all gets `invalid_request` from OpenIddict's own parameter check, before any client lookup. Every `client_secret` column is still null afterwards. Since the Application rows are seeded by SQL, OpenIddict's manager validation, which wants a secret on a confidential client, never runs.

**Reference ID form.** On both hosts, the code and the refresh token each match `{publicId}.{random}` for their own Tenant, and `{random}` decodes to 32 bytes (256 bits). `AttachTenantReferenceId` makes the value. OpenIddict's token manager hashes the whole value (SHA-256, base64) in `ObfuscateReferenceIdAsync` before the store sees it, so the store holds only the hash: no `reference_id` column starts with a public ID. The access token stays a JWS.

**Cross-Tenant reference.** Tenant A's refresh token and A's code, each presented on host B, are refused with `invalid_grant`. `RejectForeignReferenceIds` runs on `ValidateTokenContext` between `RemoveDisallowedCharacters` and `ValidateReferenceTokenIdentifier`, and rejects any code or refresh token whose prefix isn't the current Tenant's. B's token store never received either value's hash. As a positive control, B's own refresh token, refreshed on B, is recorded as a lookup under B's Tenant ID, so a probe that recorded nothing would fail the test. Under B's `TenantScope`, `gk_hosted` sees none of A's rows in `spike_token`, `spike_authorization` or `spike_application`, while the superuser sees A has rows in each. A's code still redeems at A.

**Failed request leaves no state.** There are two tests.

1. **Bad PKCE verifier.** The token endpoint refuses it with `invalid_grant` and rolls back. OpenIddict writes nothing before its PKCE check, so the store is unchanged: every token and authorization row has the same status, redemption flag and concurrency token as before. The code still redeems with the right verifier.
2. **Sign-in rejected after its writes.** A spike switch rejects the sign-in at order 400,000, after OpenIddict has marked the refresh token `redeemed` and stored three new tokens, but before the response handler at 500,000. That is exactly what OpenIddict's `RedeemTokenEntry` comment says it guards against: it marks the token early "even if the sign-in demand is rejected later in the pipeline". A probe counting store writes confirms at least four writes (the redemption, then each new token's insert and payload update) ran inside that request before the rejection. The rollback takes back the redemption and all three new rows, so the presented token is `valid` again and redeems once the switch is off.

**PKCE with stores.** Story 2.1's degraded mode needed a Gatekeep handler to enforce S256. With stores, that handler is gone. OpenIddict's own `RequireProofKeyForCodeExchange` refuses a missing challenge, and the S256-only `CodeChallengeMethods` refuses `plain`. Each is refused with `invalid_request`, answered directly rather than by redirect, and rolls back exactly one request transaction. Neither request issues a code or writes a row.

## Carry over to later stories

- **Story 2.3 (and wherever `tenant` gains `public_id`).** The first handler now does two jobs: it swaps options and opens the request's `TenantScope`. Keep both in one handler at `int.MinValue`, and keep the test that asserts it is first. The spike opens a `TenantScope`, and so a connection and transaction, on every OpenIddict request, including discovery and JWKS, which never write. Story 2.3 should open the scope lazily, on the first store call, or only for the endpoints that write. Reference IDs need a stored, unique, dot-free Tenant public ID before Story 2.9 issues a code, and Story 2.3's `tenant_host` resolution is the natural place for that column.
- **Story 2.6 (tables).** The spike tables are a working schema for `authorization` and `token`:
  - text `status` and `type`
  - a `text[]` of scopes
  - `jsonb` properties
  - a concurrency token
  - on tokens, a nullable hashed `reference_id` that is unique per Tenant, and a `payload` holding the encrypted JWE
  - composite foreign keys `(tenant_id, …)` to the parent rows

  `gk_hosted` needs only `SELECT`, `INSERT` and `UPDATE`, because OpenIddict's pruning and delete are unused. AD-13's anchor to `user_session` is not in the spike, and Story 2.6 adds it. A token row is written for every issued artifact, including access and ID tokens, which AD-13 says can't be revoked. Story 2.6 should decide whether to keep those rows (`DisableTokenStorage` is all or nothing) or drop them in the store.
- **Story 2.7 (one revocation path).** OpenIddict revokes a family through `IOpenIddictTokenStore.RevokeByAuthorizationIdAsync`, on reuse and on code replay, from inside a catch that only logs. In production the Sessions token store must route that call into `ISessions.RevokeAccess`, or the generated FR-48 test must treat it as that path. Either way:
  - The store must record the family on the request before it runs anything.
  - Endpoint end must re-run the revocation and its audit event through `FailureContext`.
  - The audit type code `sessions.token_family.revoked`, with an anonymous actor and the Application as target, is a spike placeholder. Story 2.7 fixes the real code and actor.
  - Only revocations through the token store are captured for the `FailureContext` replay. A revocation through the authorization store (`RevokeAsync`, `RevokeByApplicationIdAsync`, `RevokeBySubjectAsync`) is not, so a refused request would lose it. Story 2.7 must capture both.
  - Stories 2.7 and 2.10 must decide whether `RevokeAccess` also sets the authorization row to `revoked`. OpenIddict leaves it `valid` on reuse and replay, so a family revoked that way still reads `valid` (see "Reuse commits revocation").

  **Settled by Story 2.7.** `ISessions.RevokeAccessAsync(context, scope, exceptSessionId, reason, actor, ct)` is built, in `src/Modules/Sessions/Core/SessionRevocation.cs`:
  - **The authorization is revoked.** Every scope that reaches a family sets the `authorization` row to `revoked` with a new `concurrency_token`, then revokes the family's tokens the same way. A store holding the old row sees a conflict. So after reuse or replay the family reads `revoked`, not `valid`.
  - **Scopes.** `Authorization(id)` (one family, no Session ends), `Session(id)`, `User(id)` (the only scope that takes `exceptSessionId`), `Application(id)` (its families plus every token with that `application_id`), and `Tenant`.
  - **The audit event.** The spike's `sessions.token_family.revoked` placeholder is replaced by one `sessions.access.revoked` event per call, by the caller's `Actor`. Its target is the User for User scope, and absent otherwise, because the envelope has no Session or Application kind. Refresh reuse and code replay pass `Actor.Anonymous`.
  - **Reasons.** `RevocationReason` is a closed set (`token_reuse` and `code_replay` among them), and a migration holds `user_session.end_reason` to exactly those codes.
  - **One path.** `RevocationPathTests` scans every `.cs` and `.sql` file under `src/` other than `SessionRevocation.cs`. A file fails if it names `Statuses.Revoked`, or if it has an `UPDATE` of `user_session`, `"authorization"` or `token` and also holds a `'revoked'` literal, a `"revoked"` string or an `@revoked` parameter, or names `ended_at` or `end_reason` in a `SET` clause. That catches the forms the spike stores used. It is a text scan, so a status built some other way (from a variable or a generic status parameter) gets past it.

  **What Story 2.9 must wire.**
  - The token store's `RevokeByAuthorizationIdAsync` calls `RevokeAccessAsync(Authorization(id), null, TokenReuse or CodeReplay, Actor.Anonymous)` and records that call on the request before it runs.
  - The authorization store's `RevokeAsync` uses `Authorization(id)`, and `RevokeByApplicationIdAsync` uses `Application(id)`. They are recorded the same way, so a refused request loses neither. `RevokeBySubjectAsync` has no Session-free scope that fits, so it should refuse rather than revoke on its own.
  - The generic `UpdateAsync` of either store must not set a revoked status. A revoked status reaching it must route through `RevokeAccessAsync` instead, because the scan can't see a status passed through as a generic value.
  - The token store's own `RevokeAsync` on one token and `RevokeByApplicationIdAsync` route to the family or Application scope the same way, or throw. None may write `status` itself.
  - Endpoint end, including the unhandled-exception path, replays every recorded call through `FailureContext.CommitAfterRollbackAsync`. `RevokeAccessAsync` is idempotent, so replaying a revocation that partly ran is safe.
  **Wired by Story 2.9.**
  - **Stores.** `src/Modules/Sessions/Adapters/TokenStore.cs` holds both, on a `StoreRequest` (the request's context, `KeepOnFailure` and `MarkFailed`). Each implements exactly what Client Credentials and the code grant call; every other call throws. The token store's `UpdateAsync` writes only `status` (valid or redeemed, never revoked), `payload`, `reference_id`, `redemption_date` and `concurrency_token`, and refuses a change to any other column. The authorization store creates the one ad-hoc authorization of a completed flow, anchored to its Session through `SessionsContract.SessionAnchorProperty`, and finds one; its `UpdateAsync` and every revoke refuse.
  - **Replay.** `RevokeByAuthorizationIdAsync` records `ISessions.RevokeAccessAsync(Authorization(id), CodeReplay, Actor.Anonymous)` on the request, then runs it. `TokenRequestTransaction` commits every recorded effect after the rollback, at endpoint end and also on disposal, when an unhandled exception skipped the end. So a replayed code leaves the first exchange's access and ID token rows, the code row and the authorization `revoked`, with one `sessions.access.revoked` event.
  - **Swallowed SQL failures.** A store statement that fails calls `MarkFailed`. A marked transaction never commits: endpoint end turns a would-be success into `server_error` and rolls back.
  - **Reference IDs.** `AttachTenantReferenceId` (in place of `AttachTokenPayload`) and `RejectForeignReferenceIds` are in `src/Modules/Protocol/Core/ReferenceIds.cs`. The prefix is `PublicId.Format(PublicIdType.Tenant, tenantId)`.
  - **PKCE errors redirect.** OpenIddict sends no validation error to a redirect URI. Gatekeep's `TrustRedirectTarget` checks the client and the exact registered `redirect_uri` right after OpenIddict's form check of the parameter. Once it has, `RedirectTrustedErrors` sends every later error, a missing or `plain` challenge included, back there with `iss`. An untrusted target gets the static page (`AnswerInvalidRequestPage`).
  - **Grants.** `gk_hosted`'s UPDATE on `token` and `"authorization"` is narrowed to those columns (`Migration20261110000000CreateCodeFlow`).
- **Story 2.10 (rotation and reuse).** No leeway, rotation and reuse revocation all work as AD-13 says. Story 2.10 must also handle the following:
  - **Late rejections.** A sign-in refused after `RedeemTokenEntry` rolls back the redemption, so the presented refresh token stays usable. OpenIddict intends the opposite. Story 2.10 must list which late refusals should still burn the token, such as a refresh refused because the user is now disabled, and commit that redemption through `FailureContext` as well. Only the refresh path is tested. The same is expected for a code, but that path is untested.
  - **Concurrent refreshes.** Two refreshes racing with the same token are untested. The stores enforce the concurrency token, but `RedeemTokenEntry` ignores a failed redemption for refresh tokens, so the outcome depends on row locking in the request transactions.
  - **Mismatch logging.** AD-9's rule (unauthenticated Tenant mismatches logged at most once per source per hour) isn't implemented. The spike only refuses.

  **Wired by Story 2.10.** The handlers are in `src/Modules/Protocol/Core/RefreshTokens.cs`, the options in `ProtocolServer.cs`.
  - **Options.** `AllowRefreshTokenFlow()`, `UseReferenceRefreshTokens()`, `SetRefreshTokenLifetime(SecurityLimits.RefreshTokenInactivityLifetime)` (7 days) and `SetRefreshTokenReuseLeeway(TimeSpan.Zero)`. Rolling refresh tokens stay on (OpenIddict's default). OpenIddict's own default leeway is 30 seconds, so the explicit zero matters.
  - **Issue.** Authorize accepts `openid offline_access` only for an Application with `gt:refresh_token` (Directory now writes `web` clients with both grants, and the migration backfills the refresh grant onto existing ones; the `application_redirect_uris` CHECK allows `{authorization_code}` or `{authorization_code, refresh_token}`). Anything else is `invalid_scope`. The authorization records the granted scopes, so only an `offline_access` code exchange returns a refresh token. `AttachTenantReferenceId` already covers refresh tokens, and `RejectForeignReferenceIds` refuses a foreign or garbage prefix before lookup, logged as an unauthenticated mismatch.
  - **Refresh.** `RefuseUngrantedRefreshScopes` answers `invalid_scope` for a scope the family wasn't granted, right after `ValidateAuthentication`. `SignInRefresh` (on `HandleTokenRequestContext`, before the redemption) does four things:
    - It reads the family through `ISessions.FindFamilyAsync`, which takes `FOR SHARE` on the authorization row until the request ends.
    - It refuses a revoked family, or one past `creation_date + RefreshTokenAbsoluteLifetime`, with `invalid_grant`.
    - It rebuilds `sub`, `sid`, `auth_time` and `amr` from the anchored Session.
    - It narrows the scopes to a requested `scope`. A refresh without `offline_access` gets no new refresh token, and its presented one is still redeemed: that is the client's choice to end offline access.

    `CapRefreshTokenLifetime` (after `PrepareRefreshTokenPrincipal`) cuts every new refresh token's expiry to the family's absolute end. That gives both limits with no new column. Access and ID tokens keep their 15 minutes, even near the end. It also drops the code's `nonce` from refresh tokens, so a refreshed ID token has none (OIDC Core §12.2).
  - **Reuse and races.** A rotated token presented again reaches `RevokeByAuthorizationIdAsync`, which uses `TokenReuse`. A redemption that updates 0 rows re-reads the row:
    - If it reads `redeemed`, the request lost a race, and the store records the `TokenReuse` revocation (for codes, `CodeReplay`, as in 2.9).
    - If it reads `revoked`, a logout or other revocation got there first, and nothing more is revoked.

    `RedeemTokenEntry` ignores a failed refresh redemption. Under READ COMMITTED the row reads `redeemed` for the loser too, so the token store reports each request's own successful redemption on its `StoreRequest` (`MarkRedeemed`). `RefuseLateRefreshes` (right after `RedeemTokenEntry`) refuses with `invalid_grant` when this request's redemption didn't succeed. So exactly one of two racing refreshes succeeds, and the family is revoked.
  - **Revocation during a refresh.** Because `SignInRefresh` share-locks the authorization row, a concurrent `RevokeAccessAsync` either finishes first, and the refresh reads `revoked`, or waits until the refresh commits. Its token update is a later statement, so it then revokes the new tokens too. No `valid` token is left in a revoked family.
  - **Late refusals that burn.** There is exactly one: the family reads revoked after the redemption. `RefuseLateRefreshes` then records `ISessions.BurnRefreshTokenAsync` (a `valid` refresh row becomes `redeemed`) on the request and refuses, so the burn commits through `FailureContext` after the rollback. With the share lock, `RevokeAccessAsync` can't cause it, so this is a defensive refusal and is untested. Epic 5's blocked User belongs here too. A lost race needs no burn, because its revocation is already kept. Transit or database failures after the redemption aren't refusals of the token: they roll back, and the token stays usable. The code path's late refusal is still untested.
  - **Session expiry.** `FindFamilyAsync` doesn't filter on the Session's idle or absolute expiry, so a natural expiry doesn't end the family (AD-13). An ended Session has already revoked it.
  - **Grants.** No change. A rotation, a reuse revocation and a burn update only the token columns 2.9 granted.
- **Story 2.11 (userinfo and revocation).** The handlers are in `src/Modules/Protocol/Core/UserinfoEndpoint.cs` and `RevocationEndpoint.cs`, the options in `ProtocolServer.cs` (`/connect/userinfo`, `/connect/revoke`). Discovery advertises both, with `revocation_endpoint_auth_methods_supported` `[client_secret_basic, client_secret_post]`.
  - **Revocation is Gatekeep's, not OpenIddict's.** OpenIddict's generic token validation would look a presented reference token up and, on a `redeemed` refresh token or code, run `ValidateTokenEntry`'s reuse revocation, so revoking a rotated token would revoke its family as reuse. So `LeaveRevokedTokenToGatekeep` turns OpenIddict's generic token validation off on the revocation endpoint, `ValidateTokenType`, `ValidateAuthorizedParty` and `RevokeToken` are removed, and `RevokeRefreshTokenFamily` (on `HandleRevocationRequestContext`, where `RevokeToken` ran) reads the token itself:
    - this Tenant's prefix, a `valid` unexpired refresh token of the authenticated client: `ISessions.RevokeAccessAsync(Authorization(family), RevocationReason.ClientRevoke, Actor.Client(applicationId))`, one `sessions.access.revoked`, committed with the request, and an empty 200;
    - this Tenant's prefix, anything else (unknown, revoked, redeemed, expired, a code, another client's): `invalid_token`, which OpenIddict's `NormalizeErrorResponse` answers as an empty 200, and the request rolls back;
    - another or a malformed prefix that isn't a JWT: refused before any lookup, counted as Story 2.5's unauthenticated cross-Tenant mismatch, and answered 200;
    - a JWT (an access or ID token): `unsupported_token_type`, since neither is revocable (AD-13).
    `token_type_hint` is never read. The token store's `RevokeAsync` paths stay refusing: nothing calls them.
  - **Actor.** `Actor.Client(applicationId)`: the Kernel already had the `client` kind, and `audit_event.actor_kind` allows it.
  - **Reason.** `client_revoke`, added to `RevocationReason` and to the `user_session_end_reason` CHECK by `Migration20261112000000AddClientRevokeReason`. No Session ends on it.
  - **Client authentication.** `AuthenticateGatekeepRevocationClient` runs `AuthenticateGatekeepClient.AuthenticateAsync`, the token endpoint's own, before OpenIddict's `ValidateTokenParameter`: the same `invalid_client` and cross-Tenant classification and events. Every Application now has `ept:revocation`. The limits (`LimitTokenRequests`), the transaction (`BeginTokenTransaction`, `EndTokenTransaction`) and the 429 (`AnswerRateLimited`) are now generic over the context, and registered for both endpoints.
  - **Userinfo reads the token alone.** No transaction is opened. `RefuseUserinfoReferenceTokens` refuses a value that isn't a JWT before OpenIddict would look it up as a reference token, and `ReadUserinfoTokensStatelessly` drops the verified token's token and authorization IDs, so OpenIddict reads no token row and no family. A valid unexpired access token so answers after its family is revoked (AD-13). OpenIddict still verifies the signature against the Tenant's keys, the issuer, `typ` `at+jwt` and the expiry. `RequireUserinfoUserAndOpenId` refuses a non-`usr_` subject (a Client Credentials token) with `invalid_token` and a token without `openid` with `insufficient_scope`. `AttachUserinfoSubject` replaces OpenIddict's `AttachAudiences` and `AttachClaims`, so the answer is `{"sub": …}` only. `TakeUserinfoBearerFromHeaderOnly` drops an `access_token` in the query or form.
  - **`prompt=login` and `max_age`.** `AuthorizeEndpoint.AuthenticatedSince` derives the time the sign-in must be at or after, and `IAuthorizationSignIn.CompleteAsync` gets it. A result older than it, in whole seconds, is refused with `login_required` and rolls back. A malformed `max_age` is `invalid_request`.
- **Application writes (Story 2.5, 2.8 and Epic 3).** Directory must write `application` rows itself, not through `OpenIddictApplicationManager.CreateAsync` or `UpdateAsync`. Their validation refuses a confidential client that has neither a secret nor a signing JWKS (`ID2113`), and Gatekeep keeps that column empty on purpose.

  **Settled by Story 2.5: where the stores live.** Each store lives in its owner's adapters (AD-8), and its owner references only `OpenIddict.Abstractions`, the store interfaces; the engine (`OpenIddict.Server*`, `OpenIddict.Core`) stays in Protocol and Host.Hosted, which wire the stores in. `ProtocolRuleTests` holds both.
  - **Application store:** `src/Modules/Directory/Adapters/ApplicationStore.cs`, through `DirectoryContract.CreateApplicationStore`. It only reads; every write throws. `IDirectory.CreateMachineClientAsync` writes `application` and `client_secret` itself, and Gatekeep's `AuthenticateGatekeepClient` (in `src/Modules/Protocol/Core/TokenEndpoint.cs`, on token request validation right after `ValidateGrantType`, so before OpenIddict's parameter checks and `ValidateClientId`) calls `IDirectory.VerifyClientSecretAsync` in place of `ValidateClientSecret`.
  - **Token store:** `src/Modules/Sessions/Adapters/TokenStore.cs`, through `SessionsContract.CreateTokenStore`. Minimal for Client Credentials: instantiate, the getters and setters, and create. Every other call throws `NotSupportedException` until Story 2.9.
  - **Authorization store:** a registered stub in the same file, through `SessionsContract.CreateAuthorizationStore`, which throws on every call.
  - **No scope store,** no entity cache (`DisableEntityCaching()`) and no pruning.
  - **Request transaction:** `TokenRequestTransaction`, opened only by the token endpoint once the request is counted (`BeginTokenTransaction`), and ended before the response by `EndTokenTransaction`: commit on success, roll back otherwise, with any effect a refused request keeps (the cross-Tenant event) committed through `FailureContext`. Discovery and JWKS open none.
  - **Mismatch logging:** built. An unauthenticated cross-Tenant mismatch is counted per source in `tenant_attempt` and logged at most once per source per hour; an authenticated one is always logged.
- **Client authentication on other endpoints.** `ValidateClientSecret` is removed globally, but `ValidateGatekeepClientSecret` only checks the token endpoint. Any later endpoint that authenticates clients, such as introspection, revocation (Story 2.11) or pushed authorization requests, must be covered by the Gatekeep handler before it is enabled, or a confidential client's secret goes unchecked there. **Revocation is covered by Story 2.11** (`AuthenticateGatekeepRevocationClient`).
- **All stories.** `SpikeRequestTransaction` commits before the response is written, so a commit that throws becomes a 500. Two failure paths are untested:
  - **Unhandled exception after a family was recorded.** If a handler throws after a store recorded a revoked family, `EndRequestTransaction` never runs. The request's service scope disposes the transaction, which rolls back, and the recorded revocation is lost. Production must replay recorded revocations on that path too.
  - **Swallowed SQL error.** A store call that OpenIddict wraps in a log-only catch, such as `TryRedeemAsync` or the revoke in `ValidateTokenEntry`, can fail with a SQL error without failing the request. PostgreSQL then leaves the transaction aborted. Later store calls fail, and a `COMMIT` on an aborted transaction is turned into a rollback without an error, so tokens could be returned that were never stored. Production must track any failed command on the request transaction and refuse to report success.

## What this doesn't settle

- The `public_id` column, its format and uniqueness, and the hourly-limited mismatch log are not built.
- The `user_session` anchor, Session expiry and FR-48 triggers are not built.
- Concurrent refresh-token races are not tested.
- A revocation lost to an unhandled exception, a swallowed SQL error leaving the transaction aborted, and a late refusal on the code path are not tested (see carry-over).
- Whether a revoked family's authorization row should also be revoked is not settled.
- The spike ran on TestServer, the same limit as Story 2.1.
