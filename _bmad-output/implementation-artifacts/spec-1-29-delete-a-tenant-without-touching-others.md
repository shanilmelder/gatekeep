---
title: 'Story 1.29: Delete a Tenant without touching others'
type: 'feature'
created: '2026-11-05'
status: 'ready-for-dev'
baseline_revision: '34d8b8d282ab4e4c6bd06c904ec5abec5e87cad0'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/planning-artifacts/architecture/architecture-gatekeep-2026-11-02/ARCHITECTURE-SPINE.md'
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-gatekeep-2026-11-01/prd.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/EXPERIENCE.md'
  - '{project-root}/_bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/DESIGN.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-7-hold-keys-in-openbao-behind-ikeycustody.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-9-track-long-running-operations.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-7-3-verify-chains-and-apply-retention.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-24-enforce-capabilities-and-tenant-scoped-routes.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-26-confirm-sensitive-actions-and-manage-admin-credentials.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-27-create-tenants-with-permanent-subdomains.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-1-28-switch-tenants-and-set-the-environment-label.md'
  - '{project-root}/design/Gatekeep Admin.dc.html'
warnings: []
deferred: []
---

<intent-contract>

## Intent

**Problem:** FR-7 says "A Deployment Owner can create and delete Tenants". Its consequences: "A Tenant Subdomain can't change after creation, is never reused", "Deleting a Tenant needs typed confirmation and re-authentication. Its Signing Keys are destroyed, its JWKS is withdrawn, and its security Logs are kept for 90 days", and "A test proves that deleting one Tenant leaves every other Tenant's data, keys and Logs unchanged". FR-46 lists "Tenant deletion" among the fresh-assertion actions. FR-8: "The system keeps each Tenant's data, keys and Sessions isolated from every other Tenant". AD-6: "A resolved host for a deleted Tenant gets the same 404", and "`tenant_host` rows are never deleted, so a Tenant Subdomain can't be reused". AD-30: "Work spanning modules or Tenants is an Operation … That covers Tenant creation and deletion", "a retry of a fresh-assertion Operation needs a new assertion", and "Each module with `tenant` tables exposes a Tenant purge in its contract, and Tenant deletion calls each one". AD-10: "Secret class keys have no row, and only Tenant creation and deletion create or destroy them." AD-16: "A deleted Tenant's chain stays until its retention ends, then an Operation purges it." AD-1: "Cross-module deletion is an Operation (AD-30), never a cascade." PRD §5.2: "Log retention | 90 days | 90-day floor in Prod Tenants". EXPERIENCE: "Delete Tenant | Spec only | Deployment Owner only, on Tenants. Typed confirmation and re-authentication. | Global | Back to Tenants list". It also says "Typed confirmation | Confirm stays disabled until the value matches exactly. Used for User and Tenant deletion. The helper names what to type", and "Tenant deleted or role removed mid-session | The next request returns to the landing page with a `banner` `[ASSUMPTION]`". UX-DR22 lists "Tenant deleted mid-session".

Today:
- `tenant.status` allows only `creating` and `active` (Story 1.27). `tenant_guard_update` lets the status go only from `creating` to `active`, raising no SQLSTATE for any other change.
- `tenant_host_guard` refuses every `UPDATE`, `DELETE` and `TRUNCATE` of `tenant_host`, for every role. A host is the table's primary key, so `ITenants.InsertAsync` already refuses a host issued before, as `SubdomainTaken`.
- `TenancyAdapters` resolves a host only to an `active` Tenant (`WHERE h.host = @host AND t.status = 'active'`). Any other status already gets the fixed 404.
- `deployment.tenants.delete` (Deployment, `FreshAssertion.Always`) is in the capability table, and no route declares it. No production route declares any `Always` capability yet.
- `IKeyCustody.DeleteAsync` exists ("Destroys the key and every version of it"). `OpenBaoKeyCustody` sets `deletion_allowed` and then deletes. A key that doesn't exist is `KeyCustodyFailure.Rejected`, so a repeat isn't harmless. `host-worker.hcl` and `cli.hcl` allow `delete` on all six secret class prefixes. `host-admin.hcl` and `host-hosted.hcl` don't. `KeysContract` creates the six keys and destroys none.
- `IAuditRetention.PurgeAsync` and the `audit.chain.purge` job and Operation exist (Story 7.3). `ProductionOperations` says "Tenant deletion, its future caller, starts it". The job is due once the newest non-checkpoint event is past `RetentionPeriods.LogDays` (90), a constant that doesn't read the label. The retention sweep lists every `tenant` row, whatever its status.
- `tenant`-class tables in `TableRegistry`, with their owners:
  - Tenancy: `tenant_settings`.
  - Audit: `audit_event`, `audit_detail`.
  - Operations: `job_payload`.
  - Identity: `user`.
  - Sessions: `user_session`, `authorization`, `token`.
  - Authentication: `signin_transaction`.
- No module exposes a Tenant purge. `gk_worker` can delete only `job_payload` and `audit_detail` rows among these. The cross-module key `user_session → user` is `ON DELETE RESTRICT`.
- Operations already has edges to Authentication, Identity, Sessions, Keys, Audit, Admins and Tenancy. `OperationRuleTests.Operations_has_an_edge_to_every_module_owning_tenant_tables` checks the edges only.
- An Operation runs its Tenant steps unordered. A completion handler (Story 1.27) runs once every step has succeeded, in the last step job's transaction and its Tenant's scope.
- `tenant_role` keeps `ON DELETE RESTRICT` keys. No role deletes a row. The authorizer reads roles on every request and never reads `tenant` (AD-1).
- The Tenants page shows each row's stored host under the column "Subdomain" (`tenantsColumnSubdomain`). No code splits a subdomain out of a host (AD-6).
- `ConfirmModal` already has typed confirmation (`confirmText`, helper `typeToConfirm` "Type {value} to confirm.", label `typeToConfirmLabel` "Type to confirm") and the re-authentication slot.

Items in `deferred-work.md` this story takes in:
- Story 1.24: "Make a deleted Tenant's roles grant nothing (Story 1.29)".
- Story 1.27: "Tenant deletion, its purge contracts, and a `deleted` status that resolves to the same fixed 404 (Story 1.29)".
- Story 1.27: "Ordered Operation stages (carried on to Story 1.29)". It is resolved without ordering, see Design Notes.
- Story 1.26: "The first HTTP test of an `Always` capability route on a production route (Tenant deletion, Story 1.29 …)". This story takes the Tenant deletion half.
- Story 1.25 and Story 1.28: "The 'role removed mid-session' and 'Tenant deleted' banners". This story takes the "Tenant deleted" banner. The detection rule also covers a removed role, which Story 8.4 must prove.
- Story 1.8: "Decide job retention for dead jobs and for Tenant deletion". This story takes the Tenant deletion half: the `tenant` row is never deleted, so no `RESTRICT` key to it ever fires.
- Threat model G-18: the purge contracts, and what happens to `operation` and `operation_step`.

Not taken in: "Admin removal must account for the credential floor trigger" (Story 1.26, Epic 8). Deleting a Tenant deletes its `tenant_role` rows and never an `admin` or `admin_credential` row, so `admin_credential_guard_delete` isn't touched.

**Approach:**
- **A deleted Tenant is a tombstone, never a deleted row.**
  - `tenant.status` gains `deleting` and `deleted`.
  - The `tenant` row and its `tenant_host` row stay for good. The host keeps its primary key, so no creation can take it again. The Tenant's `issuer` and `rp_id` stay `UNIQUE`.
  - Host.Hosted already resolves only `active` Tenants, so `deleting` and `deleted` both get the fixed 404, unchanged.
  - Because the row stays, no `ON DELETE RESTRICT` key to `tenant` ever fires. `operation`, `operation_step` and `job` rows keep their history, and the existing job purge still removes done jobs.
- **Starting is one Host.Admin command, and access ends in it.**
  - `POST /api/v1/deployment/tenants/{tenantId}/deletion` is declared with `deployment.tenants.delete`. Its `Always` fresh assertion is used up by the request checks and bound to the target `tenantId`.
  - The body carries the typed confirmation, which must equal the Tenant's stored host.
  - In one Deployment transaction it:
    1. locks the Tenant;
    2. sets it `deleting`, so its host stops resolving at once;
    3. deletes every `tenant_role` row in it, so every Tenant route refuses its former members at once;
    4. starts `tenancy.tenant.delete`;
    5. writes `tenancy.tenant.deletion_started` on the Deployment chain.
  - It answers 202 with the Operation.
- **The Operation purges and destroys. Its completion marks the Tenant deleted.**
  - The stage `tenancy.tenant.purge` calls each module's Tenant purge in a code-owned order, in one transaction in the Tenant's scope: Sessions, Authentication, Identity, then Tenancy.
  - The stage `keys.secret_classes.destroy` destroys the six secret class keys. A key already gone counts as destroyed.
  - The completion handler runs once both stages have succeeded. It purges Operations' own `job_payload` rows, sets the Tenant `deleted`, writes `tenancy.tenant.deleted` on the Tenant's own chain, and schedules the `audit.chain.purge` job for 90 days after that event.
  - Every step and the completion are idempotent. Retry repeats only failed steps, and needs a new fresh assertion.
- **Audit is kept, whatever the label.**
  - No purge touches `audit_event` or `audit_detail`. Retention goes on cutting the chain daily, with the constant 90 days, and never cuts its head.
  - The chain is purged only by the existing purge job, once every event, `tenancy.tenant.deleted` included, is sealed and past retention.
- **The registry decides what must be purged.**
  - A Kernel `ITenantPurge` port.
  - Each module that owns `tenant` tables, other than Audit, exposes one in its contract.
  - An architecture test ties the owners in `TableRegistry` to the deletion's purge list.
  - An Isolation test seeds every `tenant` table except Audit's for two Tenants, deletes one, and asserts none of its rows remain while the other's are unchanged.
- **The dashboard.**
  - Tenants gains Delete, a destructive `ConfirmModal` with typed confirmation of the host and the re-authentication sheet in the same modal.
  - A row shows "Deleting" while its Operation runs, and "Deletion failed" with Retry if it fails.
  - A deleted Tenant leaves the list.
  - An Admin whose current Tenant is gone returns to the landing page with a `banner`.

## Boundaries & Constraints

**Always:**

- **Tenant lifecycle (Tenancy contract):**
  - `TenantStatus` gains `Deleting` (`deleting`) and `Deleted` (`deleted`). `TenantValues.Stored` and `ParseStatus` cover them.
  - The only transitions are:
    - `creating → active` (creation's completion, `gk_worker`, settings must exist, `GK005` as today);
    - `creating → deleting` and `active → deleting` (deletion start, `gk_admin`);
    - `deleting → deleted` (deletion's completion, `gk_worker`, with no `tenant_settings` row left).
  - Nothing leaves `deleting` except to `deleted`, and nothing leaves `deleted`.
  - A `creating` Tenant can be deleted only while its creation Operation isn't `running`. A failed creation can be deleted.
- **Schema (new migration `Migration20261105000000DeleteTenants`; registry entries in the same migration):**
  - `tenant_status` is replaced by `CHECK (status IN ('creating', 'active', 'deleting', 'deleted'))`.
  - `CREATE OR REPLACE FUNCTION tenant_guard_update()` keeps every Story 1.27 and 1.28 rule (the immutable columns, `GK005`, `GK006`). Its status rule becomes:
    - any transition not listed above raises **`GK007`** ("a tenant's status goes only creating to active, creating or active to deleting, and deleting to deleted"), replacing the old message that raised no SQLSTATE;
    - `gk_admin` may set only `deleting`, and `gk_worker` only `active` or `deleted` (`GK007` otherwise);
    - `deleting → deleted` while a `tenant_settings` row exists raises `GK007`.
  - New `tenant_settings_guard_delete` (`BEFORE DELETE … FOR EACH ROW`): deleting a row whose Tenant isn't `deleting` raises **`GK008`**, for every role.
  - New `tenant_role_guard_delete` (`BEFORE DELETE … FOR EACH ROW`): when `current_user = 'gk_admin'`, deleting a row whose Tenant isn't `deleting` raises **`GK009`**. Story 8.4 replaces it when it removes single roles.
  - Each new function is `REVOKE EXECUTE … FROM PUBLIC`. The migration's summary comment lists `GK002`–`GK009`.
  - Grants:
    - `GRANT UPDATE (status) ON tenant TO gk_admin`;
    - `GRANT DELETE ON tenant_role TO gk_admin`;
    - `GRANT DELETE ON tenant_settings TO gk_worker`;
    - `GRANT SELECT (tenant_id), DELETE` on `"user"`, `user_session`, `"authorization"`, `token` and `signin_transaction` to `gk_worker`. Only the column the purge's `WHERE` reads, never the content.
  - `TableRegistry`:
    - `tenant`: `[Admin]` column grants become `Update (label, status)`.
    - `tenant_settings`: `[Worker] = [Select, Insert, Delete]`, `Triggers: ["tenant_settings_guard_delete"]`.
    - `tenant_role`: `[Admin] = [Select, Insert, Delete]`, triggers `["tenant_role_guard_insert", "tenant_role_guard_delete"]`.
    - The five Identity, Sessions and Authentication tables: `[Worker] = [Delete]` with the column grant `Select (tenant_id)`. Update the comment that says "No role deletes".
  - Comments name Story 1.29.
- **SQLSTATE mapping:**
  - `AdminResponses.TenancyGuardStates` gains `GK007` and `GK009`. Host.Admin maps each to 409 `tenant_deleted`, never a 500:
    - `GK007` is a concurrent start that lost the race;
    - `GK009` is defence in depth with no normal-use path.
  - `GK008` reaches only the Worker. The purge stage maps it to the step result code `purge_refused`.
- **Tenancy contract (`ITenants`, SQL in Tenancy only):**
  - `LockForDeletionAsync(CommandContext, Guid tenantId)`:
    - runs in a Deployment context only, else `InvalidOperationException`;
    - runs `SELECT t.status, h.host FROM tenant t JOIN tenant_host h ON h.tenant_id = t.id AND h.kind = 'subdomain' WHERE t.id = @id FOR NO KEY UPDATE OF t`;
    - returns `TenantDeletionState(TenantStatus Status, string Host)?`.
  - `BeginDeletionAsync(CommandContext, Guid tenantId)`: in a Deployment context, `UPDATE tenant SET status = 'deleting' WHERE id = @id AND status IN ('creating', 'active')`. Zero rows throws, because the caller holds the lock.
  - `LockStatusAsync(CommandContext, Guid tenantId)`: in the Tenant's own context, `SELECT status FROM tenant WHERE id = @id FOR SHARE`. Returns `TenantStatus?`. It conflicts with the start's lock, so a stage's decision holds for its transaction.
  - `MarkDeletedAsync(CommandContext, Guid tenantId)`:
    - in the Tenant's own context, locks the row;
    - `deleting` → `UPDATE … SET status = 'deleted'`, appends `TenancyEvents.TenantDeleted` (Actor `system`, target the Tenant) on its chain, and returns true;
    - `deleted` → returns false and writes nothing;
    - any other status throws.
  - `ActivateAsync` locks the row first (`FOR NO KEY UPDATE`) and does nothing, settings insert included, unless the Tenant is `creating`. A creation's completion can never give a deleted Tenant settings.
  - `ListAsync` leaves out `deleted` Tenants. The cursor still works when it names one. `ListActiveAsync` is unchanged.
  - `TenancyContract.TenantPurge` (`ITenantPurge`) deletes the context Tenant's `tenant_settings` row.
  - `TenancyEvents` gains the two events below.
- **Purge port (Kernel, `Gatekeep.Kernel.Persistence.ITenantPurge`):**
  - It has one member, `[StateChanging] Task PurgeAsync(CommandContext context, CancellationToken cancellationToken)`.
  - It deletes every row of the module's `tenant` tables for `context.TenantId`, children before parents. It throws `InvalidOperationException` in a Deployment context.
  - Each statement names `WHERE tenant_id = @tenant_id` as well as relying on row-level security.
  - It is idempotent: a second call deletes nothing and succeeds.
  - It writes no audit event, because the Operation's completion records the deletion.
  - Each module exposes it as `{Module}Contract.TenantPurge`:
    - `SessionsContract.TenantPurge`: `token`, then `"authorization"`, then `user_session`.
    - `AuthenticationContract.TenantPurge`: `signin_transaction`.
    - `IdentityContract.TenantPurge`: `"user"`.
    - `TenancyContract.TenantPurge`: `tenant_settings`.
    - Operations' own purge is internal (`job_payload`) and runs in the completion, because the stage jobs' own payloads live there.
- **Admins contract:** `IAdminTenantRoles.RemoveAllForTenantAsync(CommandContext, Guid tenantId)`, in a Deployment context, runs `DELETE FROM tenant_role WHERE tenant_id = @tenant_id` and returns the count. Only deletion calls it, after `BeginDeletionAsync`.
- **Keys contract:**
  - `KeysContract.DestroySecretClassKeysAsync(IKeyCustody, Guid tenantId, CancellationToken)` deletes `SecretClassKeys(tenantId)` in order. Only `Host.Worker`'s and the Cli's policies may.
  - `IKeyCustody.DeleteAsync` gains "A key that doesn't exist counts as destroyed, so a repeat is harmless". `OpenBaoKeyCustody.DeleteAsync` first reads `transit/keys/{key}`:
    - 404 returns at once;
    - 403 is `Refused` with `KeyOperation.Delete`, as today;
    - otherwise it sets `deletion_allowed` and deletes.
  - No policy file changes.
- **Operations (`TenantDeletion` in `Operations/Core`, registered in `ProductionOperations`):**
  - Type `tenancy.tenant.delete`. It has two Tenant stages and a completion handler:
    - **`tenancy.tenant.purge`:** `LockStatusAsync`. If the Tenant isn't `deleting`, the result is `Failure(tenant_not_deleting)` and nothing is deleted. Otherwise it calls `TenantDeletion.StagePurges` in order: Sessions, Authentication, Identity, Tenancy. `GK008` becomes `Failure(purge_refused)`.
    - **`keys.secret_classes.destroy`:** the same status re-check (`tenant_not_deleting`). No custody, or a `KeyCustodyException`, becomes `Failure(custody_unavailable)` (the existing code). Otherwise it calls `DestroySecretClassKeysAsync`.
    - **Completion:** Operations' `job_payload` purge (`DELETE FROM job_payload WHERE tenant_id = @tenant_id`), then `MarkDeletedAsync`. When that returns true, `AuditRetentionJobs.SchedulePurgeAsync(context, tenantId)` runs. It is the body of `PurgeStageAsync`, factored out: it enqueues `audit.chain.purge` unless one is pending or running, due at the newest non-checkpoint event plus `RetentionPeriods.LogDays`.
  - `OperationsContract` gains:
    - `TenantDeletionOperation`;
    - `TenantPurgeStage` and `SecretClassKeysDestroyStage`;
    - `TenantPurgeModules`, the ordered owners `["Sessions", "Authentication", "Identity", "Tenancy", "Operations"]`, for the architecture test.
  - `ProductionOperations`' comment drops "Tenant deletion, its future caller, starts it". The `audit.chain.purge` Operation stays registered, with no production caller (deferred).
  - **The creation stage re-checks too:** `keys.secret_classes` runs `LockStatusAsync`, and a Tenant that isn't `creating` is `Failure(tenant_not_creating)`, with no key created.
  - No new job type, so the rendered job guard is unchanged.
- **Management contract (`ITenantManagement`):**
  - `DeleteAsync(CommandContext, AdminPrincipal, Guid tenantId, string? confirmation, CancellationToken)`, in a Deployment context:
    1. Re-checks `Allows(DeploymentTenantsDelete, principal, null, null)` (AD-5) → `Forbidden`.
    2. `LockForDeletionAsync`: none → `NotFound`.
    3. `deleting` or `deleted` → `AlreadyDeleted`.
    4. `confirmation` not ordinally equal to the stored host → `ConfirmationMismatch`. There is no trimming or case folding, as the modal enforces.
    5. `creating` with a `running` `tenancy.tenant.create` (`FindActiveAsync`) → `Busy`.
    6. `BeginDeletionAsync`, then `RemoveAllForTenantAsync`, then `IOperations.StartAsync(…, TenantDeletion type, tenantId, [purge step, destroy step])`, then appends `TenancyEvents.DeletionStarted` → `Started(operation)`.
    - A refusal writes nothing. `OperationAlreadyActiveException` can't follow step 3, and it throws if it does.
  - `GetDeletionAsync(CommandContext, AdminPrincipal, Guid tenantId)`:
    - re-checks `DeploymentTenantsRead`;
    - returns the newest `tenancy.tenant.delete` Operation of the Tenant, any status, with every step, through new `IOperations.FindLatestAsync(context, type, tenantId)` (`ORDER BY created_at DESC, id DESC LIMIT 1`).
  - `RetryDeletionAsync(CommandContext, AdminPrincipal, Guid tenantId)`:
    - re-checks `DeploymentTenantsDelete`;
    - locks the Tenant: none → `NotFound`; not `deleting` → `NotFailed`;
    - its active deletion isn't `failed` → `NotFailed`;
    - otherwise `RetryAsync`, then appends `operations.operation.retried` with the Tenant as target.
  - `RetryCreationAsync` locks the Tenant first. A Tenant that isn't `creating` → new `OperationRetryStatus.TenantDeleted` → 409 `tenant_deleted`, and nothing runs.
  - `ListAsync`:
    - `ManagedTenant` gains `Deletion` (`ManagedTenantDeletion(Guid OperationId, ManagedOperationStatus Status)`) for a `deleting` row, read with `FindActiveForTenantsAsync` for the deletion type in the same one query pattern as creation;
    - a `deleting` Tenant whose deletion succeeded can't be listed, because the completion made it `deleted` in the same transaction.
- **Routes (`TenantsApi`, declared in `AdminApi`):**
  - `POST /api/v1/deployment/tenants/{tenantId}/deletion`:
    - declared with `DeploymentApiEndpoint`, `RequiresCapability(DeploymentTenantsDelete)`, `FreshAssertionTarget("tenantId")` and `JsonRequestBody(DeleteTenantRequest)`;
    - the body is at most 4096 bytes through `AdminApi.ReadJsonAsync`;
    - the path ID is parsed with `PublicId.TryParse(PublicIdType.Tenant, …)`, and a malformed one is the unknown-path 404;
    - it runs `DeleteAsync` in a Deployment scope and commits only on `Started`;
    - `Location: /api/v1/deployment/tenants/{tenantId}/deletion`.
  - `GET /api/v1/deployment/tenants/{tenantId}/deletion` (`DeploymentTenantsRead`): 200 `OperationResponse` (the existing shape, every step), or 404.
  - `POST /api/v1/deployment/tenants/{tenantId}/deletion/retry`:
    - `RequiresCapability(DeploymentTenantsDelete)` and `FreshAssertionTarget("tenantId")`, with no body;
    - 202 `OperationResponse`.
  - The checks use up the grant before the handler (Story 1.26), so any refusal after it still uses the grant, and a retry needs a new confirmation.
  - `GK007` and `GK009` → 409 `tenant_deleted`. Any other `DbException` → the fixed 503.
  - The routes are on the Deployment surface, so `X-Gatekeep-Tenant` doesn't apply (Story 1.28 applies it to `/api/v1/tenants/…` only).
  - **Routes after this story:**

    | Route | Access | Answers |
    | --- | --- | --- |
    | `POST /api/v1/deployment/tenants/{tenantId}/deletion` | `deployment.tenants.delete`, `Always`, checks-enforced, target `tenantId` | 202 `OperationResponse`; 400 `tenant_invalid`; 400 `confirmation_mismatch`; 403 `access_denied`; 403 `fresh_assertion_required`; 404; 409 `tenant_deleted`; 409 `tenant_busy` |
    | `GET /api/v1/deployment/tenants/{tenantId}/deletion` | `deployment.tenants.read` | 200 `OperationResponse`; 404 |
    | `POST /api/v1/deployment/tenants/{tenantId}/deletion/retry` | `deployment.tenants.delete`, `Always`, checks-enforced, target `tenantId` | 202 `OperationResponse`; 403 `access_denied`; 403 `fresh_assertion_required`; 404; 409 `operation_not_failed` |
    | `POST /api/v1/deployment/operations/{operationId}/retry` | unchanged | + 409 `tenant_deleted` for a creation whose Tenant is being deleted; a deletion Operation stays the unknown-path 404 |
    | `GET /api/v1/deployment/tenants` | unchanged | no `deleted` rows; `deleting` rows carry `deletion` |
    | Every `/api/v1/tenants/{tenantId}/…` route of a `deleting` or `deleted` Tenant | unchanged | 403 `access_denied`, as no role remains |
    | Host.Hosted, a `deleting` or `deleted` Tenant's host | unchanged | the fixed 404 |

  - `TenantRuleTests.No_Tenant_is_changed_or_deleted_under_the_Deployment_Tenants_path` becomes a reviewed list. Only `post /api/v1/deployment/tenants`, `post …/{tenantId}/deletion` and `post …/{tenantId}/deletion/retry` write there, and a `delete` or `patch` is still reported.
- **Shapes (camelCase; `Cache-Control: no-store`):**
  - `DeleteTenantRequest`: `{ confirmation: string }`. An unknown extra property is ignored. A missing or non-string `confirmation`, or a body that isn't JSON, is 400 `tenant_invalid`.
  - `TenantResponse.status` gains `"deleting"`. `TenantResponse` gains `deletion: { operationId: "opr_…", status: "running" | "failed" } | null`.
  - `ApiProblem.code` gains `tenant_deleted`, `tenant_busy` and `confirmation_mismatch`.
- **Refusals:**
  - New codes, all listed in `AdminResponses.ProblemCodes`:
    - `tenant_deleted` (409): the Tenant is already being deleted, or deleted;
    - `tenant_busy` (409): its creation is still running;
    - `confirmation_mismatch` (400): the typed value isn't its Tenant Subdomain.
  - Each is logged under `{Problem}` with fixed names. No host, name, typed value or Tenant ID is logged, and no placeholder is named `{Code}`.
- **Audit events (none holds the Tenant's name or host):**
  - `tenancy.tenant.deletion_started` (`TenancyEvents.DeletionStarted`):
    - on the Deployment chain, with the Actor the Admin and the target the Tenant;
    - summary: "A Deployment Owner deleted a Tenant after typing its Tenant Subdomain and a fresh WebAuthn assertion: its host stopped resolving, every Tenant Role in it ended, and its deletion Operation started. Names the Tenant only."
  - `tenancy.tenant.deleted` (`TenancyEvents.TenantDeleted`):
    - on the Tenant's own chain, with a `system` Actor and the target the Tenant;
    - summary: "A Tenant's deletion Operation succeeded: every module's Tenant data is purged and its keys are destroyed. Its Logs are kept until their retention ends."
  - Also written: Story 1.26's `admin.fresh_assertion.verified` on the Deployment chain, and `operations.operation.retried` on a retry.
  - `docs/audit-events.md` is regenerated with `dotnet run --project tests/Architecture/Generator`, in Docker. FR-40 class: none.
- **Module edges:** none new. Management already reaches Tenancy, Admins and Operations, and Operations reaches every owner. The Kernel gains `ITenantPurge` only. `module-edges.txt` and `docs/architecture/module-dependencies.md` stay unchanged, which the edge test confirms.
- **api-client (from the regenerated schema):** `deleteTenant(tenantId, body)`, `getTenantDeletion(tenantId)` and `retryTenantDeletion(tenantId)`. Each ID goes into the path encoded. `client.test.mjs` covers the three paths.
- **Dashboard (no new runtime dependency; nothing inline; every string in `messages.tsx`):**
  - **Tenants (`TenantsPage.tsx`):**
    - With `deployment.tenants.delete`, a trailing column holds a destructive "Delete" button. Its accessible name is "Delete {name}" `[ASSUMPTION]`. It shows on `active` rows and on `creating` rows whose creation `failed`.
    - A `deleting` row shows the badge "Deleting" while its deletion runs, and "Deletion failed" with "Retry" (accessible name "Retry deleting {name}") when it failed `[ASSUMPTION]`.
    - The page reads again every `REFRESH_MS` while any row is `creating` or `deleting`, within `REFRESH_LIMIT`, as Story 1.27 does for creation.
  - **Delete modal (`shell/DeleteTenantModal.tsx`, `ConfirmModal`, `tone="destructive"`, existing components only):**
    - Title "Delete {name}?" `[ASSUMPTION]`, with the name in `<bdi>`.
    - Body `[ASSUMPTION]`, worded from the export's delete-user copy (`modalInfo` L1340): "This permanently removes its Users, Sessions and settings, and destroys its keys. {host} stops answering and can never be used again. Its Logs are kept for 90 days. This can't be undone." The host is in code type.
    - The typed field: `confirmText={row.host}`, `confirmTextLabel` "Tenant subdomain" (the label `ConfirmModal`'s own docs name), and the existing helper "Type {value} to confirm."
    - Confirm "Delete Tenant" `[ASSUMPTION]`.
    - Confirm sends the `POST` through `fresh.withFreshAssertion({ action: 'deployment.tenants.delete', target: tenantId }, …)`, with no `tenantId` in the binding, so the Deployment begin is used.
    - The sheet's status and failures show inside the modal (Re-authentication gate: "modal first, then sheet, with failure shown inside the same modal"), with the existing `freshAssertionPrompt`, `freshAssertionCancelled` and `freshAssertionUnavailable`, and a 429 as `CredentialsPage` shows it.
  - **Outcomes:**
    - 202: the modal closes. The `toast` "Tenant deletion started." `[ASSUMPTION]`. The list is read again and the row shows "Deleting". The shell's lists are read again, so the switcher drops the Tenant at once. EXPERIENCE: "Back to Tenants list".
    - 409 `tenant_busy`: inside the modal, "This Tenant is still being created. Try again once it finishes." `[ASSUMPTION]`.
    - 409 `tenant_deleted`: the modal closes and the list is read again.
    - 400, 5xx or a lost connection: inside the modal, "Couldn't delete the Tenant. Try again." `[ASSUMPTION]`, with `ErrorReference`.
    - 403 `access_denied` or the bodiless 403: the existing `actionForbidden`.
    - 401: renewal keeps the modal mounted, and the request is never resent (as on Create Tenant).
  - **Retry:** "Retry" opens `ConfirmModal` (default tone, no typed field) titled "Retry deleting {name}?" with the body "Only the steps that didn't finish run again." and confirm "Retry deletion" `[ASSUMPTION]`. Confirming sends `retryTenantDeletion` through the same fresh assertion. 409 `operation_not_failed` reads the list again.
  - **Lost Tenant (`shell/lostTenant.ts`, plain TypeScript, Node-tested; used in `Shell.tsx`):**
    - `isLost(pathTenant, listedBefore, remembered, listedNow)` is true when the path Tenant isn't in `listedNow` and either was in `listedBefore` (the switcher list this document last held) or is the `remembered` one.
    - The shell checks it:
      - when a Tenant path's reads come back forbidden;
      - after any answer 403 `access_denied` to a request on `/api/v1/tenants/{pageTenant}/…`, once the shell's lists have been read again.
    - When it holds:
      - the shell forgets the remembered Tenant and replaces the URL with `/`;
      - the landing rules of Story 1.28 then apply;
      - a shell `banner` (tone `warn`) reads "You no longer have access to {tenant}. It was deleted, or your role in it was removed." `[ASSUMPTION]`, with the name from the earlier list in `<bdi>`, else its `ten_` ID in code type.
    - The banner survives the landing's own redirect and clears on the Admin's next navigation.
    - It replaces the forbidden page in that case, which is otherwise unchanged for a Tenant never listed.
    - Unsaved changes on that page aren't prompted for, because they can't be saved.
  - **Messages:** new keys for the column, the badges, both modals, the toast, the failures and the lost-Tenant banner.
- **CSP (AD-21):** nothing inline, no `data:` or `blob:` URI, no CSP change. Every new and changed browser test uses `watchCsp`.
- **Tests:**
  - **Isolation tests:** Testcontainers PostgreSQL.
    - The real `Host.Admin` runs through `AdminHost`, with Story 1.26's `SoftwareAuthenticator`.
    - The real Operation runs as `TenantCreationOperationTests` runs creation.
    - Key tests use `OpenBaoFixture` with the real `host-worker` policy.
    - Seed rows are inserted as the migrator, one Tenant scope at a time (AD-3).
  - **Browser tests:** Playwright against the built Host.Admin (`admin-host.mjs`), with the API intercepted. A Chromium virtual authenticator answers the sheet. Each runs with axe and `watchCsp`.
- **Docs:**
  - **`docs/threat-model.md`:**
    - The header's "exists in code" list adds Story 1.29.
    - **T-1:** a deleted Tenant's rows are purged per owning module in its own scope, never by a wider query.
    - **T-22:** deletion is `Always`, checks-enforced and bound to the target Tenant, and needs the typed host. Add test names.
    - **T-31:** a deleted Tenant's chain is never purged with its data. It ends with `tenancy.tenant.deleted` and is purged only past retention, whatever its label.
    - **T-46:** the deletion Operation, its re-checks, and retry needing a new assertion.
    - **T-53:** a deleted Tenant's roles are removed in the start's transaction.
    - **T-55:** a deleted Tenant's host and `tenant` row are kept, so the subdomain is refused for good.
    - **New T-57:** "Deleting one Tenant changes another, leaves its data or keys behind, loses its evidence, or is done by mistake". Its controls:
      - the tombstone, and the fixed 404;
      - removing roles at the start;
      - per-module purges in the Tenant's own scope;
      - the registry-driven purge test, and the two-Tenant proof;
      - idempotent key destruction under the Worker policy;
      - the creation re-check and retry refusal;
      - audit excluded from the purge;
      - typed confirmation, and the fresh assertion.
    - What T-57 leaves:
      - Applications holding tokens can verify them against a cached JWKS until they expire;
      - the tombstone keeps the Tenant's name, which is Admin-entered and not personal data;
      - later `tenant` tables fail the purge test until their purge exists;
      - Signing Keys arrive with Story 2.3, whose purge must destroy them.
    - **G-18:** closed by Story 1.29, with test names. `operation` and `operation_step` rows stay as history, because the `tenant` row is never deleted.
  - **`docs/install.md`:** the "Not yet covered" Admin Dashboard item says the Dashboard also deletes Tenants.
  - **`docs/audit-events.md`:** regenerated.
  - **`deferred-work.md`:** as described in Tasks.

**Ask First:**
- **Soft delete.** The `tenant` and `tenant_host` rows stay for good, with the Tenant's name, label, issuer and RP ID, as a tombstone. That is how "never reused" and "the same 404" both hold. Confirm before deleting the row or blanking its name.
- **Deleted Tenants leave the Tenants list.** A `deleting` one stays until it is `deleted`. Confirm before showing tombstones.
- **The typed value is the stored host**, the value the Tenants list shows under "Subdomain", such as `acme.id.example.com`. It isn't the label before the zone, because no code splits a host (AD-6). Confirm before asking for the label alone, which needs a subdomain split or a stored subdomain.
- **The server also checks the typed value** (400 `confirmation_mismatch`). The checks have already used the grant by then, so a mismatch needs a new confirmation. Confirm before leaving it to the dashboard only.
- **Access ends at the start, not at completion:** the Tenant is `deleting` and its roles are gone in the start's transaction. Confirm before keeping roles until the Operation succeeds.
- **The 90 days run from `tenancy.tenant.deleted`**, the completion's event on the Tenant's own chain. The completion schedules the existing purge job, rather than starting the `audit.chain.purge` Operation, which can't be started from a Tenant scope. Confirm before measuring from the start or the last event before it.
- **A failed creation can be deleted, a running one can't** (409 `tenant_busy`). Confirm before refusing every `creating` Tenant.
- **Retry needs a new fresh assertion but no typed confirmation.** Confirm before requiring both.
- **One banner for both causes:** "It was deleted, or your role in it was removed." The dashboard can't tell the two apart without the server disclosing a deletion to someone who no longer holds a role. Confirm before adding a server signal for deletion.
- **The values marked `[ASSUMPTION]`:** EXPERIENCE gives no copy for the Delete modal, its outcomes, the badges or the landing banner, only the typed-confirmation helper, which already exists. Every string here is proposed.

**Never:**
- No `DELETE` of a `tenant` or `tenant_host` row, by any role, and no change to `tenant_host`. The guards stay.
- No cascade across modules (AD-1). Each module's purge deletes only its own tables, in the Tenant's own scope. One scope holds one Tenant, and no query spans Tenants (AD-4).
- No purge of `audit_event` or `audit_detail` by the deletion. Only `audit.chain.purge`, as `gk_retention`, past retention.
- No retention period that reads the label. `RetentionPeriods.LogDays` stays the constant 90.
- No key destroyed but the deleted Tenant's six secret class keys, and none by `Host.Admin` or `Host.Hosted` (AD-10).
- No deletion without a fresh assertion bound to that Session, `deployment.tenants.delete` and that Tenant ID. A grant for one Tenant never serves another.
- No way back from `deleting` or `deleted`, and no creation stage, settings insert or creation retry for a Tenant that isn't `creating`.
- No row of another Tenant read, written or deleted. The two-Tenant test proves it.
- No Tenant name, host, typed value or Tenant ID in a log line. No placeholder named `{Code}`.
- No inline style or script, no CSP change, and no new runtime dependency in `apps/admin-dashboard` or `packages/ui`.
- **Out of scope**, recorded in `deferred-work.md`:
  - Destroying `sig-` and `mgmt-` keys and purging `signing_key` rows in Keys' purge (Story 2.3).
  - A caller for the `audit.chain.purge` Operation, to schedule a purge again after its job went dead.
  - Cancelling or failing a deleted Tenant's pending jobs. Each later job type re-checks the Tenant's status (AD-15).
  - The retention sweep skipping a deleted Tenant whose chain is purged.
  - Showing tombstones, or reading a deleted Tenant's Logs from the Dashboard (Epic 7).
  - Proving the lost-Tenant banner for a removed role (Story 8.4).
  - Retention of dead jobs (carried on from Story 1.8, narrowed).
  - An `Always` capability route test for Admin invites and removal (Epic 8, narrowed from Story 1.26).

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| No grant | Deployment Owner; active A; `POST …/ten_A/deletion {confirmation:"a.zone"}` | 403 `fresh_assertion_required`; nothing written | — |
| Confirmed | Deployment begin `{action:"deployment.tenants.delete", target:"ten_A"}`; complete; same POST | 202 `OperationResponse` with steps `tenancy.tenant.purge` and `keys.secret_classes.destroy` for A; Location; A `deleting`; A's `tenant_role` rows gone; `tenancy.tenant.deletion_started` and `admin.fresh_assertion.verified` on the Deployment chain; grant used | — |
| Grant per Tenant | Grant for `ten_A`; POST for `ten_B` | 403 `fresh_assertion_required`; A's grant still unused | — |
| Grant used once | Confirmed delete of A refused 409 `tenant_busy`; resend | 403 `fresh_assertion_required` | — |
| Wrong typed value | Grant held; `{confirmation:"A.zone"}`, `" a.zone"`, `"a"` | 400 `confirmation_mismatch`; nothing written; grant used | — |
| Bad body | `{}`, `{confirmation:1}`, non-JSON, over 4096 bytes | 400 `tenant_invalid`; nothing written | — |
| Unknown or malformed | `ten_` of no Tenant; `nope` | 404 | — |
| Not Deployment Owner | Owner of A without Deployment Owner | 403 `access_denied`, audited | — |
| Already deleting | A `deleting` or `deleted` | 409 `tenant_deleted` | — |
| Creating, running | A `creating`, creation `running` | 409 `tenant_busy`; nothing written | — |
| Creating, failed | A `creating`, creation `failed` | 202; A `deleting`; its creation can't be retried (409 `tenant_deleted`) | — |
| Race | Two confirmed starts for A at once | One 202; the other 409 `tenant_deleted` | GK007 → 409 |
| Access ends | Editor of A on `GET /tenants/ten_A/label` and `PUT …/label` after the start | 403 `access_denied`; `my-tenants` lacks A | — |
| Fixed 404 | Host.Hosted request for A's host while `deleting` and once `deleted` | Same status, headers and empty body as an unknown host | — |
| Reuse refused | `POST /deployment/tenants` with A's subdomain after deletion | 400 `subdomain_refused`, nothing written | — |
| Operation succeeds | Worker runs A's deletion | Seeded rows of A gone from every non-Audit `tenant` table; A's six keys absent in OpenBao; A `deleted`; `tenancy.tenant.deleted` on A's chain; one `audit.chain.purge` job for A with `run_after` ≥ that event + 90 days; A's `audit_event` rows kept | — |
| Any label | Same, for a `dev` and a `prod` Tenant | Same `run_after` rule; nothing reads the label | — |
| Rerun | Each stage and the completion run twice | No error; nothing more deleted, destroyed or written; one purge job | — |
| Keys gone | A's keys already destroyed | Destroy stage succeeds | — |
| Custody down | Worker without custody, or OpenBao refusing | Step `custody_unavailable`; Operation `failed`; row "Deletion failed" | Retry |
| Retry | Failed deletion; deletion begin and complete; `POST …/ten_A/deletion/retry` | 202; only the failed step runs; then success; `operations.operation.retried` | — |
| Retry refused | Deletion running; succeeded; A active; no grant | 409 `operation_not_failed` ×3; 403 `fresh_assertion_required` | — |
| Generic retry | `POST /deployment/operations/{deletion}/retry` | 404 | — |
| Stage re-check | A test-built `tenancy.tenant.delete` Operation for an `active` Tenant | Both steps `tenant_not_deleting`; nothing deleted or destroyed; Tenant stays `active` | — |
| Creation re-check | Creation stage for a `deleting` Tenant | `tenant_not_creating`; no key created | — |
| Two Tenants | Seed A and B in every table; give both keys and events; delete A | Every B row in every registry table, B's six keys and versions, and B's chain rows identical before and after; B still resolves | Test fails |
| Registry purge | Every `tenant` table except Audit's has a seed; a registry table lacking one | Pass; then the test fails, naming the table | Test fails |
| Missing purge | Seed exists, no purge deletes it | Test fails naming the table with rows left | Test fails |
| Database guards | `gk_admin` sets `active`; `gk_worker` sets `deleting`; `deleted → active`; `deleting → deleted` with settings; `gk_worker` deletes an active Tenant's settings; `gk_admin` deletes an active Tenant's role; `DELETE` on `tenant` or `tenant_host` | GK007 ×4; GK008; GK009; refused | DB error |
| Destroy policy | `host-admin` and `host-hosted` call `DestroySecretClassKeysAsync` | `Refused`, Operation `Delete`; keys intact | — |
| Canary | A canary as Tenant name and subdomain, then delete | Absent from operational logs | Test fails |
| Delete (browser) | Deployment Owner; active row; Delete | Modal titled "Delete {name}?"; Confirm `aria-disabled` until the field equals the host exactly; helper "Type {host} to confirm." | — |
| Confirm (browser) | Typed host; POST 403 `fresh_assertion_required`; Deployment begin with target; virtual authenticator; complete 204; POST 202 | Sheet status inside the modal; toast "Tenant deletion started."; row "Deleting"; begin went to `/api/v1/deployment/assertions` with `target:"ten_A"` | — |
| Cancelled (browser) | The sheet is cancelled | "Confirmation cancelled. Nothing was changed." in the same modal; row unchanged | — |
| Busy (browser) | POST 409 `tenant_busy` | Busy text inside the modal | — |
| Failed and retry (browser) | Row `deleting`, deletion `failed`; Retry; confirm; sheet; 202 | "Deletion failed" then "Deleting" | — |
| No capability (browser) | No `deployment.tenants.delete` | No Delete column | — |
| Lost Tenant (browser) | On `/tenants/ten_A/settings` with A listed; next navigation's reads 403 and `my-tenants` lacks A | URL `/`; the landing's rules; banner "You no longer have access to A. It was deleted, or your role in it was removed." | — |
| Lost on an action (browser) | Save on A answers 403 `access_denied`; lists no longer have A | Same banner and landing | — |
| Never listed (browser) | Direct URL to a Tenant never listed or remembered | Forbidden page, unchanged | — |
| CSP | Every new and changed test | No `securitypolicyviolation`, no console CSP message, no other-origin request | Test fails |
| axe | Tenants with Delete column, badges; Delete modal (empty, matching, failure, sheet); Retry modal; lost banner; light and dark; 1100 and 768 | No violations | Test fails |

</intent-contract>

## Code Map

- `src/Gatekeep.Kernel/Persistence/ITenantPurge.cs`: the port.
- `src/Adapters/Postgres/`:
  - new `Migrations/Migration20261105000000DeleteTenants.cs`: the status check, the replaced `tenant_guard_update` with `GK007`, `tenant_settings_guard_delete` (`GK008`), `tenant_role_guard_delete` (`GK009`), the grants;
  - `Schema/TableRegistry.cs`: the grant and trigger entries.
- `src/Adapters/OpenBao/OpenBaoKeyCustody.cs`: idempotent `DeleteAsync`. `src/Gatekeep.Kernel/Secrets/IKeyCustody.cs`: its doc.
- `src/Modules/Tenancy/`:
  - `Contracts/ITenants.cs`: the statuses, `TenantDeletionState`, the four new calls;
  - `Contracts/TenancyEvents.cs`: the two events;
  - `Contracts/TenancyContract.cs`: `TenantPurge`;
  - `Core/Tenants.cs`: their SQL, `ActivateAsync`'s lock, `ListAsync`'s filter;
  - new `Core/TenancyPurge.cs`.
- `src/Modules/Identity/Contracts/IdentityContract.cs`, `src/Modules/Sessions/Contracts/SessionsContract.cs`, `src/Modules/Authentication/Contracts/AuthenticationContract.cs`: `TenantPurge`, each with its SQL in its own `Core`.
- `src/Modules/Admins/Contracts/IAdminTenantRoles.cs` and `Core/AdminTenantRoles.cs`: `RemoveAllForTenantAsync`.
- `src/Modules/Keys/Contracts/KeysContract.cs`: `DestroySecretClassKeysAsync`.
- `src/Modules/Operations/`:
  - new `Core/TenantDeletion.cs`;
  - `Core/TenantCreation.cs`: the re-check;
  - `Core/AuditRetentionJobs.cs`: `SchedulePurgeAsync`;
  - `Core/OperationStore.cs`: `ProductionOperations`;
  - `Core/OperationService.cs` and `Contracts/IOperations.cs`: `FindLatestAsync`;
  - `Contracts/OperationsContract.cs`.
- `src/Modules/Management/Contracts/ITenantManagement.cs` and `Core/TenantManagement.cs`: `DeleteAsync`, `GetDeletionAsync`, `RetryDeletionAsync`, their results, `ManagedTenantDeletion`, and the retry and list changes.
- `src/Gatekeep.Host.Admin/`:
  - `AdminApi.cs`: the three routes and their OpenAPI text;
  - `TenantsApi.cs`: the handlers, `DeleteTenantRequest`, `TenantResponse.deletion`;
  - `AdminResponses.cs`: the codes, `GK007`, `GK009`.
- `docs/api/openapi-v1.json` and `packages/api-client/src/schema.generated.ts`: regenerated with `sh deploy/docker/api-contract.sh --write <abs dir>`.
- `packages/api-client/src/client.ts` and `test/client.test.mjs`.
- `packages/ui/src/messages.tsx`: the new keys.
- `apps/admin-dashboard/`:
  - `src/shell/TenantsPage.tsx`;
  - new `src/shell/DeleteTenantModal.tsx`;
  - new `src/shell/lostTenant.ts`;
  - `src/shell/Shell.tsx`: the lost-Tenant banner and redirect;
  - `src/shell/tenants.ts`: the status;
  - new `test/lostTenant.test.mjs`.
- `tests/Architecture/`:
  - `OperationRuleTests.cs`:
    - every `TableRegistry` owner of a `tenant` table except Audit is in `OperationsContract.TenantPurgeModules`, and the list holds nothing else;
    - each owner except Operations exposes `{Module}Contract.TenantPurge` as `ITenantPurge`;
    - two production types have a completion handler;
    - a self-check catches a missing owner.
  - `CapabilityRuleTests.cs`: the two deletion `POST`s are checks-enforced, with action `deployment.tenants.delete` and target `tenantId`.
  - `TenantRuleTests.cs`: the reviewed Deployment Tenants writes; only `DeleteTenantRequest` has `confirmation`. Self-checks.
  - `KeyCustodyRuleTests.cs`: only `KeysContract` and the adapter call `DeleteAsync` under `src/`. Self-check.
  - `AdminApiRuleTests.cs`: the `tenant_role` row.
  - `AuditCatalogueTests.cs`, through the regenerated catalogue.
- `tests/Isolation/`:
  - new `Tenancy/TenantDeletionTests.cs`: the HTTP rows;
  - new `Tenancy/TenantPurgeRegistryTests.cs` with its seed table;
  - new `Tenancy/TenantDeletionIsolationTests.cs`: two Tenants, with Postgres and OpenBao;
  - new `Operations/TenantDeletionOperationTests.cs`;
  - `Tenancy/TenantTablesTests.cs`: the guards and grants;
  - `Tenancy/TenantResolutionTests.cs`: `deleting` and `deleted`;
  - `Tenancy/TenantCreationTests.cs`: reuse;
  - `Custody/SecretClassKeyTests.cs`: destroy;
  - `Operations/TenantCreationOperationTests.cs`: the re-check;
  - `TestTenants.cs`: status and seed helpers;
  - the canary scan.
- `tests/browser/`:
  - new `admin-tenant-delete.spec.ts`;
  - `admin-tenants.spec.ts`: the column and badges;
  - `playwright.config.ts`: the project, and in the default projects' `testIgnore`.
- Docs: `docs/threat-model.md`, `docs/audit-events.md` (generated), `docs/install.md`, `_bmad-output/implementation-artifacts/deferred-work.md`.

## Tasks & Acceptance

**Execution:**
- [ ] Schema:
  - the migration and registry entries;
  - `TenantTablesTests` covers each guard row of the matrix, the grants (column `tenant_id` only for the five tables), and that every Story 1.27 and 1.28 trigger rule still holds.
- [ ] Kernel and Keys:
  - `ITenantPurge`;
  - idempotent `DeleteAsync`;
  - `DestroySecretClassKeysAsync`;
  - `SecretClassKeyTests` for destroy, repeat, the refused policies, and another Tenant's keys untouched.
- [ ] Module purges: Sessions, Authentication, Identity and Tenancy, each with its SQL in its own module.
- [ ] Tenancy, Admins, Operations, Management:
  - the lifecycle calls and events;
  - `RemoveAllForTenantAsync`;
  - `TenantDeletion` with its stages, completion and `SchedulePurgeAsync`;
  - the creation re-check;
  - `FindLatestAsync`;
  - `DeleteAsync`, `GetDeletionAsync` and `RetryDeletionAsync`;
  - the creation retry refusal and the list changes, with AD-5 re-checks.
- [ ] Host.Admin:
  - the three routes;
  - the problem codes, and the `GK007` and `GK009` mapping;
  - the OpenAPI text.
  - Then regenerate the contract with `sh deploy/docker/api-contract.sh --write <abs dir>`.
- [ ] Architecture tests:
  - the purge-owner rule with its self-check;
  - the fresh-assertion route assertions;
  - the Tenant path and body rules;
  - the `DeleteAsync` caller rule;
  - the registry row;
  - the catalogue, with `docs/audit-events.md` regenerated;
  - the unchanged edge list.
- [ ] Isolation tests:
  - every server row of the I/O matrix;
  - the registry-driven purge test, which fails for a `tenant` table with no seed and for one whose rows a purge leaves;
  - the two-Tenant proof over every registry table, the keys in the real OpenBao and the audit chain;
  - the canary row.
- [ ] api-client: the three calls and `client.test.mjs`.
- [ ] Dashboard:
  - `DeleteTenantModal`;
  - the Tenants column, badges, refresh and Retry;
  - `lostTenant.ts` with its Node test;
  - the shell's banner and redirect;
  - the catalogue keys.
- [ ] Browser tests: `admin-tenant-delete.spec.ts` (every browser row, `watchCsp`, axe in light and dark at 1100 and 768), the updated `admin-tenants.spec.ts`, and the config.
- [ ] Docs:
  - threat model (header, T-1, T-22, T-31, T-46, T-53, T-55, new T-57, G-18 closed);
  - `install.md`;
  - `deferred-work.md`:
    - remove the taken-in items: Story 1.24's deleted-Tenant roles, Story 1.27's deletion item and its carried ordered-stages item;
    - leave Story 1.9's ordered-stages item, with evidence that Story 1.29 no longer needs it;
    - narrow Story 1.26's `Always` route item to Epic 8, Story 1.8's job retention item to dead jobs, and Story 1.25's and Story 1.28's banner items to proving the removed-role case in Story 8.4;
    - add the out-of-scope items.

**Acceptance Criteria:**
- Given a Tenant, when a Deployment Owner deletes it, then typed confirmation of its Tenant Subdomain and a fresh WebAuthn assertion bound to that Tenant are required, and the server refuses a request missing either.
- Given a confirmed deletion, when the Operation runs, then it calls each module's Tenant purge, destroys the Tenant's six secret class keys, marks it `deleted`, and keeps its audit chain until the purge job runs at least 90 days after `tenancy.tenant.deleted`, for a `dev`, `staging` or `prod` Tenant alike.
- Given two Tenants, when one is deleted, then a test proves the other's rows in every registry table, its keys and its Logs are unchanged.
- Given a deleted or deleting Tenant's subdomain, when it is requested, then Host.Hosted answers the fixed 404, and when a Tenant is created with it, then creation is refused with `subdomain_refused`.
- Given the AD-3 table registry, when the purge test runs, then it seeds every `tenant` table except Audit's, deletes the Tenant, and asserts no row of it remains, so a table added by a later story fails until its seed and purge exist.
- Given the AD-27 owners of `tenant` tables, when the architecture tests run, then each owner but Audit exposes a Tenant purge that Tenant deletion calls.
- Given an Admin working in a Tenant that has been deleted, when their next request arrives, then they return to the landing page with a `banner`.
- Given a deletion whose Operation failed, when the Deployment Owner retries it, then a new fresh assertion is required and only the failed steps run again.
- Given every new and changed browser test, when it runs, then no CSP violation occurs and axe finds no violation in light and dark at 1100 and 768px.

## Spec Change Log

## Review Triage Log

## Design Notes

- **Why a tombstone.** FR-7 needs a deleted subdomain never reused, and AD-6 needs its host to keep getting the same 404. Story 1.27 already made `tenant_host` undeletable and its host the primary key, so creation already refuses a host issued once. A tombstone in `tenant` keeps that and also keeps every `ON DELETE RESTRICT` key to `tenant` valid. `operation`, `operation_step`, `job`, and the audit chain until its purge, need no special handling. The cost is a row holding the Admin-entered name, label, issuer and RP ID, which aren't personal data. A separate retired-subdomain table was rejected because it would duplicate what `tenant_host` already guarantees.
- **Why access ends at the start.** The danger is a deleting Tenant still being served or still acted on. The start's one transaction sets `deleting`, which Host.Hosted's `status = 'active'` lookup already refuses, and deletes the `tenant_role` rows. The authorizer reads roles on every request and caches nothing. It still never reads `tenant` (AD-1), so the role rows are what must go. `GK009` holds `gk_admin`'s new `DELETE` to a `deleting` Tenant until Story 8.4 designs single-role removal.
- **Why no ordered stages.** Story 1.27 carried "ordered stages" here so that deletion could purge before removing the Tenant. With a tombstone, removal means marking the Tenant `deleted`, and the completion handler already runs after every stage. The two stages are independent: the data purge and the key destruction can run in either order on a Tenant nobody can reach. `job_payload` is purged in the completion, not in a stage, because the stage jobs' own payloads live there. Purging them from a parallel stage could break the other stage's job. The completion runs in the last step job's transaction, whose own payload the runner deletes as done anyway.
- **Why one purge stage calling module purges in order.** AD-30 asks for a purge per module and a call to each. Cross-module keys are `RESTRICT` (`user_session → user` today), so separate parallel stages would fail on order. One stage calling `Sessions, Authentication, Identity, Tenancy` in one transaction is atomic: a failure leaves nothing half purged, and Retry repeats it whole. Each purge still lives in its owning module, so no module touches another's table. Later stories add a table, a seed and the owner's purge. The registry test fails until they do, and the architecture test fails if a new owner isn't in the list.
- **Why the 90 days start at `tenancy.tenant.deleted`.** FR-7 keeps "its security Logs … for 90 days" and the story says "at least 90 days, whatever the Tenant's label". Retention already keeps each event 90 days from when it occurred, for every label, through one constant. Writing `tenancy.tenant.deleted` as the chain's last event, and scheduling the purge from it, makes the whole chain outlive the deletion by at least 90 days. Story 7.3's purge job already refuses while any non-checkpoint event is inside retention or unsealed. Its daily cuts never remove the head, so the deleted event survives until the purge. The completion can't start the `audit.chain.purge` Operation: an Operation's run job is Deployment-wide and the completion runs in the Tenant's scope. So it enqueues the same purge job, through the stage's own code.
- **Why destroying a missing key succeeds.** Every step must be idempotent (AD-30). A rerun after the stage destroyed three of six keys and then lost custody must finish the other three, not fail on the first. Reading the key first keeps the policy story unchanged: the Worker and Cli policies already have `read` on these paths, and Admin and Hosted have none, so they are still refused.
- **Racing creation.** A deletion start refuses while creation runs (`tenant_busy`). After a start, creation can't be retried (`TenantDeleted`), its stage refuses a Tenant that isn't `creating` under `FOR SHARE`, and its completion's `ActivateAsync` does nothing to a Tenant that isn't `creating`. So no key is created after the destroy stage looked, and no settings row appears after the purge.
- **Why the typed value is the host.** "Tenant Subdomain" is "a Tenant's permanent address under the Deployment's dedicated zone" (PRD §3). The Tenants list shows that address, as stored, under "Subdomain". Asking for exactly what is on screen keeps AD-6's "no code splits a host". The server compares it ordinally with the stored host, so a client other than the dashboard can't skip it.
- **Lost Tenant detection stays client-side.** The server answers every request in a deleted Tenant with the same 403 `access_denied` it gives any role-less Tenant, so a former member learns nothing they couldn't already infer. The shell knows what it listed a moment ago, and what this browser last used. A Tenant that drops out of the list is gone for this Admin, whether it was deleted or the role was removed. EXPERIENCE gives both the same state.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests`. Expected:
  - the build has no warnings;
  - the `@gatekeep/ui` checks pass (raw hex, dependencies, screens props-only);
  - the dashboard Node tests pass, including the new `lostTenant.test.mjs`;
  - the api-client tests and the API contract drift check pass against the regenerated files;
  - the Architecture tests pass, including:
    - `OperationRuleTests` with the purge-owner rule;
    - `CapabilityRuleTests` with the deletion routes;
    - `TenantRuleTests`;
    - `KeyCustodyRuleTests`;
    - the Admins registry rows;
    - the unchanged module edges;
    - the audit catalogue.
  - the Isolation tests pass, including:
    - `TenantDeletionTests`, `TenantPurgeRegistryTests`, `TenantDeletionIsolationTests` and `TenantDeletionOperationTests`;
    - `TenantTablesTests`, `TenantResolutionTests`, `TenantCreationTests` and `SecretClassKeyTests`;
    - every Story 1.7, 1.9, 7.3 and 1.24–1.28 test unchanged;
    - the canary scan.
  - the browser tests pass, including `admin-tenant-delete`, the updated `admin-tenants`, `admin-shell`, `admin-tenant-switcher` and `admin-csp`.

  From a worktree, use a worktree-only image tag, not `gatekeep/tests:local`.
- After changing the endpoints, regenerate the contract in Docker with `sh deploy/docker/api-contract.sh --write <abs dir>` (as `docker compose -f deploy/compose.test.yaml run --rm --build -v "<repository>:/out" tests sh deploy/docker/api-contract.sh --write /out`). Regenerate the audit catalogue with the Generator. Commit both.

Nothing runs on the host.
