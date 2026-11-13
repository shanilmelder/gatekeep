---
title: 'Story 9.3: Revoke a Signing Key'
type: 'feature'
created: '2026-11-14'
status: 'ready-for-dev'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/implementation-artifacts/epic-9-context.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-9-2-rotate-a-signing-key-on-demand.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-3-5-delete-an-application.md'
warnings: ['oversized']
deferred: []
---

<intent-contract>

## Intent

**Problem:** FR-38 and UJ-3 need a Tenant Owner who suspects a key compromise to revoke that Signing Key. Tokens it signed must stop being trusted, and nothing manual should follow. Today:
- there is no revoke path;
- the destroy job and the `signing_key_destroyed_at` CHECK accept only `retired` rows;
- only `gk_worker` may enqueue `keys.signing_key.destroy`;
- `gk_admin` can't end Sessions.

**Approach:**
- An Owner-only, fresh-assertion route revokes one published signing key, in one Tenant command:
  - the replacement Transit key is created first when one is needed;
  - the row becomes `revoked`;
  - if it was `current`, `next` is promoted at once, even if it hasn't aged;
  - a new `next` is created whenever `next` was consumed or revoked;
  - the destruction job is enqueued;
  - the events are written and the JWKS NOTIFY is sent;
  - optionally, the Tenant's Sessions and refresh tokens are revoked through `RevokeAccess`.
- The page gains a per-row Revoke action with a Confirmation modal.

## Boundaries & Constraints

**Always:**
- **Keys contract:** new `[StateChanging] KeysContract.RevokeSigningKeyAsync(CommandContext, IKeyCustody, IAuditAppender, IJobEnqueuer, JobType destroyJob, Actor actor, Guid tenantId, string keyId, CancellationToken)`, implemented in `SigningKeyLifecycle`. It returns public `SigningKeyRevocation(SigningKeyRevocationStatus Status)`, where Status is `Revoked` or `NotFound`.
  - **Checks:** it requires the Tenant context and takes `TenantKeys.Lock`.
  - **Parsing `keyId`:** `keyId` has the form `{transit_name}.v{version}`. The name must parse as a `sig-` row key of this Tenant (`KeyName.TryParseRowKey`). The row must exist with `purpose = 'signing'`, a matching `transit_version`, and state `next`, `current` or `previous`. Anything else, including an unparseable ID, a `mgmt-` key, a `retired` or `revoked` row, or another Tenant's key, is `NotFound`, and nothing is written.
  - **Ordering:** every replacement Transit key is created (`custody.CreateKeyAsync`) before any row changes. A custody failure throws, and the caller rolls back.
  - **Row moves, in an order the one-current and one-next indexes allow:**
    - `previous`: becomes `revoked`. No other row changes.
    - `next`: becomes `revoked`, then the new `next` is inserted.
    - `current`: becomes `revoked`. Then `next` becomes `current` (`promoted_at = now()`), whatever its age. Then the new `next` is inserted.
  - **Destruction:** in the same command, it enqueues `destroyJob` with `{signing_key_id: revokedRowId}`.
  - **Events:** all are written with `actor` and classed `TenantLogClass.KeyOperation`. These are new codes unless marked:
    - `keys.signing_key.revoked` ("A Tenant Owner revoked a Signing Key: it left the JWKS and its private material is queued for destruction. Names no key.");
    - for `current`, either the existing `keys.signing_key.promoted` (when `next` was published for at least 15 minutes, by database time as in 9.2) or the new `keys.signing_key.promoted_unaged` (when it wasn't);
    - `keys.signing_key.created` (existing) whenever a new `next` is created.
  - Then `pg_notify` (`NotifyAsync`) is sent.
  - Reuse the 9.2 helpers (`LockAsync`, `ReadOpenAsync`, `NotifyAsync`, `AppendAsync` with an actor, `InsertKey`); don't copy them.
- **Destruction of revoked keys:** every path that may destroy a key, or re-queue its destruction, accepts `revoked` as well as `retired`:
  - `SelectForDestroy` (the `DestroyAsync` state check);
  - `MarkDestroyed`;
  - `SelectUndestroyed`, so the daily rotation re-queues a revoked key's dead destroy job;
  - the `ProductionJobs` destroy review text;
  - the `KeysEvents` destroyed and destruction_failed summaries, which now say "retired or revoked".
  - Retry and failure recording are unchanged: backoff, 20 attempts, `destruction_failed`.
- **Migration `Migration20261119000000RevokeSigningKeys` (`20261119000000_RevokeSigningKeys`):**
  - drop and re-add `signing_key_destroyed_at` as `CHECK (destroyed_at IS NULL OR state IN ('retired','revoked'))`;
  - include the full re-rendered `job_guard_insert` block (`OperationsContract.RenderGuard` of the production registry, where `keys.signing_key.destroy` now has `enqueuingRoles` `[Worker, Admin]`);
  - grant `gk_admin` exactly the `user_session` column privileges that `SessionRevocation`'s Tenant-scope statements need, as column grants and nothing more (expected: `SELECT (tenant_id, ended_at)` and `UPDATE (ended_at, end_reason)`; confirm against the SQL).
  - `TableRegistry` follows: the `user_session` Admin column grants. The `signing_key` grants don't change: 9.2's `UPDATE(state, …)` already lets Admin set `revoked`.
  - `MigrateCommandTests` expects 35.
- **Management:** `ISigningKeyManagement.RevokeAsync(CommandContext, IKeyCustody?, AdminPrincipal, TenantRoleGrant?, Guid tenantId, string keyId, bool revokeAccess, CancellationToken)` returns `SigningKeyRevokeResult(Status)`. Status is one of `Revoked`, `Forbidden`, `NotFound` or `Unavailable`.
  - The AD-5 re-check uses `TenantSigningKeysRevoke`.
  - The enqueuer is `OperationsContract.CreateEnqueuer(OperationsContract.ProductionRegistry, custody: null)`.
  - When `revokeAccess` is set, after the key revocation in the same command it calls `ISessions.RevokeAccessAsync(context, RevocationScope.Tenant(…), exceptSessionId: null, RevocationReason.AdminRevoke, Actor.Admin(principal.AdminId), ct)`. That is the single revocation path and writes `sessions.access.revoked`.
  - Null custody or a `KeyCustodyException` gives `Unavailable`.
- **Route:** `POST /api/v1/tenants/{tenantId}/signing-keys/{keyId}/revoke`.
  - Registration: `TenantApiEndpoint.Instance`, `RequiresCapability(TenantSigningKeysRevoke)` (fresh assertion Always), `FreshAssertionTarget` on the `keyId` route value, and `JsonRequestBody(typeof(RevokeSigningKeyRequest))` with `{ revokeAccess: boolean }`, required.
  - Handler: in `SigningKeysApi`, following 9.2's `RotateAsync`. It commits with `CancellationToken.None` only on `Revoked`, then answers 200 with the refreshed list read in the same transaction.
  - Answers:
    - 200;
    - 400 for a malformed body;
    - 401;
    - 403 `access_denied` or `fresh_assertion_required`;
    - 404 with the same not-found code the client-secret revoke uses for an unknown secret;
    - 409 `tenant_mismatch`;
    - 503 for custody or the database.
  - Register the route in `RouteRegistry` (`TenantPath`), `CanaryFlows`, and `CapabilityRuleTests` (capability `tenant.signing_keys.revoke`, `freshAssertion` "always", `machineAllowed` false). Add a 404 to `AdminApiRuleTests`' comment if needed.
- **Generated artifacts:** regenerate the OpenAPI document, the api-client schema, `docs/audit-events.md` and `LogCatalogue.Generated.cs` in Docker. `client.ts` gains `revokeSigningKey(tenantId, keyId, { revokeAccess })`, with both IDs encoded, plus a test.
- **Dashboard (`SigningKeysPage.tsx`, given `fresh` from `Shell.tsx`; strings in `messages.tsx`):**
  - **Revoke column:**
    - Owners with `has('tenant.signing_keys.revoke')` get a per-row `Revoke` button (`variant="destructive" size="sm"`) on `next`, `current` and `previous` rows only.
    - Editors get the same buttons `aria-disabled` and described by the "Tenant Owner only" note.
    - Viewers get no column (view-only banner as today).
  - **Modal:** a `ConfirmModal` with tone `destructive`, title "Revoke signing key?" and confirm "Revoke key". Its body states:
    - the key ID (in `<code>`);
    - "Tokens signed with this key stop being trusted. Relying parties that cached the JWKS can accept them for up to 15 minutes.";
    - for `current`: "The next key becomes current now, even if relying parties haven't fetched it yet.";
    - a `Checkbox`, unchecked by default: "Also end every Session and refresh token in this Tenant". This sets `revokeAccess`.
  - **Flow:**
    - Confirming runs `fresh.withFreshAssertion({ action: 'tenant.signing_keys.revoke', target: keyId, tenantId }, …)` with the `reauthentication` slot as in `DeleteApplicationModal.tsx`. An assertion failure shows inside the same modal, and no second modal opens.
    - Success closes the modal, replaces the table with the response, reads the JWKS sample again and toasts "Signing key revoked.".
    - Any other failure shows a bad `Banner` with `ErrorReference` (trace ID) inside the modal, and the table is unchanged.
  - Remove the "arrives with 9.3" comment.
- **Docs:**
  - `docs/install.md:372`: revoking is available.
  - `docs/threat-model.md`: add Story 9.3, the new grants (`user_session` columns, the destroy job's Admin enqueue) and the tests, plus UJ-3 coverage in T-45 or the compromise row.

**Ask First:**
- **The forged-token test location.** The repository has no `tests/Protocol` project; protocol tests live in `tests/Isolation/Protocol/`. The fixture resource server test goes there.
- **Copy `[ASSUMPTION]`:** the modal title and texts, the checkbox label, "Revoke key", and "Signing key revoked.".

**Never:**
- No revocation of `retired`, already `revoked` or `management` keys.
- No destruction inside the request: destruction is the Worker job's, after commit.
- No session or token revocation write outside `RevokeAccessAsync`.
- No new `signing_key` grant, and no `destroyed_at`, `retired_at` or DELETE for `gk_admin`.
- No query spanning Tenants.
- No key material in any response or log.
- No change to rotation behaviour (9.2) beyond the shared helpers.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Revoke previous | Owner, fresh assertion, P is `previous` | 200: P `revoked`; current and next unchanged; destroy job queued for P; `revoked` event with the Admin actor; NOTIFY; JWKS (Hosted) no longer has P's kid | — |
| Revoke current, aged next | C current, N published 20 min ago | C revoked, N current, new next N2 in Transit and rows; events revoked, promoted, created; destroy job for C | — |
| Revoke current, young next | N published 2 min ago | Same, with `promoted_unaged` instead of `promoted` | — |
| Revoke next | N is next | N revoked, new next N2; events revoked, created; current unchanged | — |
| With revokeAccess | Live Sessions, families and tokens in A and in B | A's all revoked, one `sessions.access.revoked` in the same transaction; B untouched | — |
| Not found | Unknown, malformed, `mgmt-`, retired, already revoked, or B's keyId | 404; nothing written | — |
| Stale assertion | Last assertion older than 5 min | 403 `fresh_assertion_required`; nothing written | — |
| Editor / Viewer / other Tenant | — | 403 `access_denied`; nothing written | — |
| Custody fails | The replacement create refused | 503; A unchanged (key still current); no job; B untouched | — |
| Destroy job | Run for a revoked row; then custody fails once | Transit key deleted, `destroyed_at` set, `destroyed` event; a failure writes `destruction_failed` and retries | — |
| Dead job re-queued | Revoked, undestroyed row, its job dead | The daily rotation enqueues a fresh destroy job | — |
| Forged token | Token signed with K while it was current, then K revoked | A fixture resource server fetching the Tenant JWKS after the cache limit (a fresh fetch) rejects it (kid unknown); Hosted userinfo rejects it | — |
| DB rules | `destroyed_at` on revoked allowed; on next, current or previous refused; gk_admin may enqueue destroy and update `user_session` (ended_at, end_reason) only | Per CatalogueTests and JobGuardTests | — |
| Browser: Owner | Mocked APIs and a virtual authenticator | Revoke on a row opens the modal with impact text (and the current-key line on current); confirm sends `{revokeAccess}`, toast, table refreshed, JWKS re-read | — |
| Browser: assertion | First answer 403 `fresh_assertion_required` | WebAuthn sheet; retry succeeds inside the same modal | — |
| Browser: failure | 503 with trace ID | Bad banner with reference in the modal; table unchanged | — |
| Browser: Editor / Viewer | Capabilities | Editor: aria-disabled Revoke plus "Tenant Owner only", pressing sends nothing; Viewer: no Revoke | — |
| CSP and axe | The modal open (both variants) and failure, both themes, both widths | No violations | Test fails |

</intent-contract>

## Code Map

- `src/Modules/Keys/Core/SigningKeyLifecycle.cs`:
  - `SelectUndestroyed` (:57-66), `SelectForDestroy`/`DestroyAsync` (:268), `MarkDestroyed` (:85-86);
  - the 9.2 helpers: `RotateNowAsync`, `LockAsync`, `ReadOpenAsync`, `ReplaceAsync` (:418-457, Rotate-then-Promote order, so not reusable for revoke), `NotifyAsync`, `AppendAsync`;
  - `SelectPublicationRemaining`/`SelectOpen` `aged`.
- `src/Modules/Keys/Core/TenantKeys.cs`: `Lock`, `InsertKey`, `SelectPublished` (:42-47). `KeyName.TryParseRowKey`. `src/Modules/Keys/Contracts/{KeysContract,SigningKeys,KeysEvents}.cs`.
- `src/Adapters/Postgres/Migrations/Migration20261105010000RotateSigningKeys.cs`: :58 the CHECK, :60-95 the update trigger (already allows next, current and previous to become revoked, and `destroyed_at` set once), :146-152 the newest destroy guard case.
- `src/Modules/Operations/Core/ProductionJobs.cs:130-145` (destroy entry, review text :142), `JobGuardRenderer.cs`, `OperationsContract.cs:131` (`CreateEnqueuer`, `RenderGuard`), `SigningKeyJobs.cs:88-123`.
- `src/Modules/Sessions/Contracts/ISessions.cs:102` (`RevokeAccessAsync`), `Revocation.cs` (scopes, `RevocationReason.AdminRevoke`), `Core/SessionRevocation.cs:17-36,189` (the SQL whose columns the grant must cover).
- `src/Adapters/Postgres/Schema/TableRegistry.cs`: the `user_session` entry (:323-327) and `signing_key` (:594).
- Host.Admin:
  - `AdminApi.cs:858-881`: client-secret revoke (FreshAssertionTarget). `:462-467`: `JsonRequestBody` with `DeleteTenantRequest`. The 404 code is the one that route uses.
  - `AdminRequestChecks.cs:160-167,640-652` and `FreshAssertionGate.cs:80-88`.
  - `SigningKeysApi.cs`: `RotateAsync`, the model to follow.
- `src/Modules/Management/Core/SigningKeyManagement.cs` (`RotateAsync`), `Contracts/ISigningKeyManagement.cs`, `DirectoryService.cs:402` (an existing indirect RevokeAccess call).
- Dashboard:
  - `apps/admin-dashboard/src/shell/SigningKeysPage.tsx` (columns :187-201, banners :244-259, Rotate :275-292, comment :74);
  - `Shell.tsx:540` (pass `fresh`), `freshAssertion.ts`;
  - `DeleteApplicationModal.tsx:112` and `DeleteTenantModal.tsx:179` (in-modal reauthentication), `CredentialsPage.tsx:309-327,370-386` (per-row destructive button plus `SlotView`).
- `packages/ui/src/components/ConfirmModal.tsx:11-49`, `components/Choice` (`Checkbox`), `messages.tsx:436-456,884-896`. `packages/api-client/src/client.ts` and `test/client.test.mjs`.
- Tests:
  - `tests/Isolation/Keys/SigningKeyRotateNowTests.cs`, `SigningKeyRotateApiTests.cs`, `PublicHalves.cs` (models);
  - `SigningKeyRotationTests.cs:676` (the lifecycle CHECK theory) and `:701-703` (job roles Worker-only, must change);
  - `TenantKeysTests.cs:333-347`, `TenantTablesTests.cs:707-745`, `SessionTablesTests`, `JobGuardTests.cs:248-266`;
  - `tests/Architecture/RevocationPathTests.cs:100`, `CapabilityRuleTests.cs:247-254`, `AdminApiRuleTests.cs:250-255`;
  - `tests/Isolation/CrossTenant/RouteRegistry.cs:96-98`, `CanaryFlows.cs:356,389-410`, `MigrateCommandTests.cs:20,28,43,78`.
- Protocol:
  - `tests/Isolation/Protocol/ProtocolHost.cs`, `KeyChangeEvictionTests.cs`;
  - `ClientCredentialsTests.VerifiesAsync` (:640): the relying-party `JsonWebTokenHandler` against fetched JWKS, the model for the fixture resource server;
  - `tests/Isolation/Spikes/OpenIddict/TransitSigning.cs`: signing with a named Transit key.
- Browser: `tests/browser/admin-signing-keys.spec.ts` (:184-186 asserts no revoke button for a Viewer), `admin-tenant-delete.spec.ts:188-189,329-413` (in-modal assertion), `admin-applications.spec.ts:320-339` (virtual authenticator).

## Tasks & Acceptance

**Execution:**
- [ ] Keys: add `RevokeSigningKeyAsync`, the revoked-destroy changes, the new event codes and the revised summaries. Add new `tests/Isolation/Keys/SigningKeyRevokeTests.cs` covering every domain row: three states, aged and unaged, not-found cases, custody failure rollback, the destroy job on a revoked row with retry, dead-job re-queue, and other Tenant untouched.
- [ ] Add the migration and the `ProductionJobs` roles, and update `TableRegistry` (`user_session`). Update `SigningKeyRotationTests` (CHECK theory, job roles), `JobGuardTests` (latest block), `TenantKeysTests`/`TenantTablesTests`/`SessionTablesTests` and `MigrateCommandTests` (35).
- [ ] Management: add `RevokeAsync`, plus tests for the re-check and for `revokeAccess` through `RevokeAccessAsync` (A revoked, B untouched, one event).
- [ ] Host.Admin:
  - add the route, the request type and the handler;
  - add new `tests/Isolation/Keys/SigningKeyRevokeApiTests.cs` covering every API row, including the stale assertion and JWKS leaving Hosted;
  - add the `RouteRegistry`, `CanaryFlows`, `CapabilityRuleTests` and `AdminApiRuleTests` entries.
- [ ] Protocol: add new `tests/Isolation/Protocol/RevokedSigningKeyTests.cs`, the forged-token fixture resource server row.
- [ ] Regenerate the OpenAPI, schema and audit catalogue in Docker. Add the client method and its test.
- [ ] Dashboard: add the Revoke column, the modal, the messages and the `fresh` wiring. Extend `admin-signing-keys.spec.ts` with every browser row.
- [ ] Docs: update install.md and the threat model.

**Acceptance Criteria:**
- Given a revoke, when it's confirmed with a fresh assertion, then the key leaves the JWKS at once, a job destroys its private material, and failure retries.
- Given the `current` key is revoked, when it commits, then `next` is promoted even if unaged, the Log records that, and a new `next` is created.
- Given the modal, when it opens, then it states token impact and offers Session and refresh token revocation through `RevokeAccess`.
- Given a token forged with the revoked key, when a fixture resource server validates it after the JWKS cache limit, then it's rejected.
- Given a failure, when the command rolls back, then a banner shows the trace ID, the key is unchanged, and other Tenants are untouched.
- Given the full suite in CI, when it runs, then every test passes.

## Spec Change Log

## Review Triage Log

## Design Notes

**Why `promoted_unaged` is its own code:** `AuditDetail` carries only an IP address, a user agent and an email, so an event can't carry a flag. `tenancy.tenant.prod_label_removed` sets the precedent of a separate code for a variant.

**Why Admin enqueues the destroy job directly:** the revoked row and its destruction must commit together, as retirement does in `RotateAsync`. Host.Admin needs only INSERT on `job` and `job_payload`, which it has, plus the guard's role.

**Revoking `previous` or `next`:** both are published, so revoking them also takes them out of the JWKS. Only `current` and `next` need a replacement, which keeps AD-11's one `current` and one `next` at every commit.

## Verification

**Commands:**
- Don't run the suite locally (CI is the source of truth). Generated files only, in Docker under the worktree tag `gatekeep/tests:epic-9`: `sh deploy/docker/api-contract.sh --write /out`, and `dotnet build Gatekeep.slnx` then `dotnet run --project tests/Architecture/Generator` (copy the two catalogue files out). The re-rendered guard SQL comes from `OperationsContract.RenderGuard`.
- Push and open a draft PR; CI's build, stack and release jobs must be green.
