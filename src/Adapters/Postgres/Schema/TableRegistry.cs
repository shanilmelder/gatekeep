namespace Gatekeep.Adapters.Postgres.Schema;

public enum TableClass
{
    /// <summary>Has meaning inside one Tenant: row-level security applies.</summary>
    Tenant,

    /// <summary>Has no meaning inside one Tenant, as named in AD-27.</summary>
    Control,
}

/// <summary>
/// What a table holds, for AD-2's grant limits (Story 1.31): <c>gk_hosted</c> may never write a
/// <see cref="Configuration"/> table, at table or column level. Every table must choose.
/// </summary>
public enum TableUse
{
    /// <summary>Deployment or Tenant configuration, identity of Admins, or key material: the public path never writes it.</summary>
    Configuration,

    /// <summary>State the running hosts write as they work: events, jobs, Sessions, counters.</summary>
    Runtime,
}

/// <summary>One privilege on named columns only.</summary>
public sealed record ColumnGrant(string Privilege, IReadOnlyList<string> Columns);

/// <summary>
/// One table: its class, its one owning module, its use (AD-2), every privilege per role, on the table
/// and per column, the triggers it must have, and whether it is <c>UNLOGGED</c>. Only
/// counters a crash may reset (AD-14), pending sign-in challenges a crash may drop
/// (Story 1.23), and fresh-assertion challenges and grants (Story 1.26) are unlogged; every other table must be logged.
/// </summary>
public sealed record TableEntry(
    string Name,
    TableClass Class,
    string Owner,
    TableUse Use,
    IReadOnlyDictionary<string, IReadOnlyList<string>> Grants,
    IReadOnlyDictionary<string, IReadOnlyList<ColumnGrant>>? ColumnGrants = null,
    IReadOnlyList<string>? Triggers = null,
    bool Unlogged = false);

/// <summary>
/// The AD-3 and AD-27 source of truth. A table not listed here, or a privilege
/// not listed here, fails the catalogue test.
/// </summary>
public static class TableRegistry
{
    public const string Migrator = "gk_migrator";

    public const string Hosted = "gk_hosted";
    public const string Admin = "gk_admin";
    public const string Worker = "gk_worker";
    public const string Dispatch = "gk_dispatch";
    public const string Sealer = "gk_sealer";
    public const string Retention = "gk_retention";
    public const string Cli = "gk_cli";

    public static readonly IReadOnlyList<string> RuntimeRoles =
        [Hosted, Admin, Worker, Dispatch, Sealer, Retention, Cli];

    private const string Select = "SELECT";
    private const string Insert = "INSERT";
    private const string Update = "UPDATE";
    private const string Delete = "DELETE";

    private static readonly IReadOnlyDictionary<string, IReadOnlyList<ColumnGrant>> SealColumns =
        new Dictionary<string, IReadOnlyList<ColumnGrant>>
        {
            [Sealer] = [new ColumnGrant(Update, ["epoch", "seq", "prev_hash", "hash"])],
        };

    private static readonly IReadOnlyList<string> OperationStatusColumns = ["status", "updated_at", "finished_at"];

    private static readonly IReadOnlyList<string> StepRetryColumns = ["status", "result_code", "updated_at"];

    private static readonly IReadOnlyList<string> BootstrapTokenColumns = ["token_sha256", "issued_at", "expires_at"];

    /// <summary>
    /// Story 1.29: every purged tenant table's <c>BEFORE INSERT</c> guard, so no row reaches a Tenant
    /// whose status doesn't allow it, and a deleted Tenant's purge leaves nothing behind.
    /// </summary>
    public static readonly IReadOnlyList<string> RowGuard = ["tenant_row_guard"];

    /// <summary>
    /// Story 2.8: the row guard, and the guard that refuses a row naming its Tenant's <c>system</c>
    /// Application, on each table that may never hold one: <c>client_secret</c>, <c>authorization</c>, <c>token</c>.
    /// </summary>
    private static readonly IReadOnlyList<string> SystemApplicationGuard = ["system_application_guard", "tenant_row_guard"];

    /// <summary>
    /// Story 2.9: what a token row's update may change, through the token store (a redemption, the
    /// reference ID and payload a code gets once generated) or the one revocation path (its status).
    /// </summary>
    private static readonly IReadOnlyList<string> TokenUpdateColumns =
        ["status", "payload", "reference_id", "redemption_date", "concurrency_token"];

    /// <summary>Story 2.9: an authorization row changes only by the one revocation path: its status.</summary>
    private static readonly IReadOnlyList<string> AuthorizationUpdateColumns = ["status", "concurrency_token"];

    /// <summary>A Tenant purge's read (Story 1.29): the one column its <c>WHERE</c> names, never the content.</summary>
    private static readonly IReadOnlyDictionary<string, IReadOnlyList<ColumnGrant>> PurgeColumns =
        new Dictionary<string, IReadOnlyList<ColumnGrant>>
        {
            [Worker] = [new ColumnGrant(Select, ["tenant_id"])],
        };

    public static readonly IReadOnlyList<TableEntry> Tables =
    [
        // Story 1.27: Host.Admin creates a Tenant, always creating, which its creation Operation's
        // completion, as gk_worker, makes active once its settings exist. Nobody else changes one, and
        // the triggers keep its ID, issuer, RP ID, link base and creation time, and let its status go
        // only from creating to active. From Story 1.28 a Tenant Owner, through Host.Admin, changes its
        // label, only while it is active. From Story 1.29 a Deployment Owner, through Host.Admin, sets a
        // Tenant deleting, and its deletion Operation's completion, as gk_worker, sets it deleted: the
        // row is a tombstone, never deleted, so its host is never reused. They hold every DML by any
        // role; an owner or superuser can still disable triggers.
        new(
            "tenant",
            TableClass.Control,
            "Tenancy",
            TableUse.Configuration,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Hosted] = [Select],
                [Admin] = [Select, Insert],
                [Worker] = [Select],
                [Cli] = [Select],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                // The seal loop lists the Tenant chains, so it reads the IDs only.
                [Sealer] = [new ColumnGrant(Select, ["id"])],
                // Activation, once the creation Operation succeeds, and deleted, once the deletion
                // Operation does (Story 1.29).
                [Worker] = [new ColumnGrant(Update, ["status"])],
                // A Tenant Owner's label change (Story 1.28), and a deletion's start (Story 1.29).
                [Admin] = [new ColumnGrant(Update, ["label", "status"])],
            },
            ["tenant_guard_insert", "tenant_guard_update"]),

        // Every host ever issued, kept for good (AD-6): one per Tenant and kind, added only to a
        // creating Tenant. No role updates or deletes one, and the triggers refuse every DML and
        // TRUNCATE by any role, so a host is never changed or reused; an owner or superuser can still
        // disable triggers.
        new(
            "tenant_host",
            TableClass.Control,
            "Tenancy",
            TableUse.Configuration,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Hosted] = [Select],
                [Admin] = [Select, Insert],
                [Worker] = [Select],
            },
            Triggers: ["tenant_host_guard", "tenant_host_guard_insert", "tenant_host_refuse_truncate"]),
        new(
            "tenant_settings",
            TableClass.Tenant,
            "Tenancy",
            TableUse.Configuration,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Hosted] = [Select],
                [Admin] = [Select, Insert, Update],
                // Story 1.27: the creation Operation's completion writes the new Tenant's row. Story
                // 1.29: the deletion Operation's purge deletes it, which the trigger allows only while
                // the Tenant is deleting, for every role.
                [Worker] = [Select, Insert, Delete],
            },
            Triggers: ["tenant_row_guard", "tenant_settings_guard_delete", "tenant_settings_guard_update"]),
        new("migration_history", TableClass.Control, "Operations", TableUse.Configuration, new Dictionary<string, IReadOnlyList<string>>()),
        new(
            "audit_event",
            TableClass.Tenant,
            "Audit",
            TableUse.Runtime,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Hosted] = [Insert],
                [Admin] = [Select, Insert],
                [Worker] = [Select, Insert],
                [Sealer] = [Select],
                [Retention] = [Select, Insert, Delete],
                [Cli] = [Select, Insert],
            },
            SealColumns,
            EventTriggers("audit_event")),
        new(
            "audit_detail",
            TableClass.Tenant,
            "Audit",
            TableUse.Runtime,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Hosted] = [Insert],
                [Admin] = [Select, Insert],
                [Worker] = [Select, Insert, Delete],
                [Retention] = [Select, Delete],
                [Cli] = [Select, Insert],
            },
            Triggers: DetailTriggers("audit_detail")),
        new(
            "deployment_audit_event",
            TableClass.Control,
            "Audit",
            TableUse.Runtime,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select, Insert],
                [Worker] = [Select, Insert],
                [Sealer] = [Select],
                [Retention] = [Select, Insert, Delete],
                [Cli] = [Select, Insert],
            },
            SealColumns,
            EventTriggers("deployment_audit_event")),
        new(
            "deployment_audit_detail",
            TableClass.Control,
            "Audit",
            TableUse.Runtime,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select, Insert],
                [Worker] = [Select, Insert, Delete],
                [Retention] = [Select, Delete],
                [Cli] = [Select, Insert],
            },
            Triggers: DetailTriggers("deployment_audit_detail")),
        new(
            "job",
            TableClass.Control,
            "Operations",
            TableUse.Runtime,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Hosted] = [Insert],
                [Admin] = [Insert],
                [Worker] = [Select, Insert, Delete],
                [Dispatch] = [Select],
                [Sealer] = [Insert],
                [Cli] = [Insert],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                // Finishing a job: done or dead, with its timing and a dead job's reason code.
                // Never its type, Tenant or attempts.
                [Worker] = [new ColumnGrant(Update, ["status", "locked_until", "finished_at", "failure_code"])],
                // Claiming and retrying: dispatch columns only.
                [Dispatch] = [new ColumnGrant(Update, ["status", "attempts", "run_after", "locked_until", "failure_code"])],
            },
            ["job_guard_insert", "job_notify_insert"]),
        new(
            "job_payload",
            TableClass.Tenant,
            "Operations",
            TableUse.Runtime,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Hosted] = [Insert],
                [Admin] = [Insert],
                [Worker] = [Select, Insert, Delete],
                [Sealer] = [Select, Insert],
                [Retention] = [Select],
                [Cli] = [Insert],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                // Erasing a dead job's credential.
                [Worker] = [new ColumnGrant(Update, ["ciphertext"])],
            },
            RowGuard),
        new(
            "operation",
            TableClass.Control,
            "Operations",
            TableUse.Runtime,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select, Insert],
                [Worker] = [Select, Insert],
                [Cli] = [Select, Insert],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                // Retrying reopens a failed Operation; the Worker sets its final status.
                [Admin] = [new ColumnGrant(Update, OperationStatusColumns)],
                [Worker] = [new ColumnGrant(Update, OperationStatusColumns)],
                [Cli] = [new ColumnGrant(Update, OperationStatusColumns)],
            }),
        new(
            "operation_step",
            TableClass.Control,
            "Operations",
            TableUse.Runtime,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select, Insert],
                [Worker] = [Select, Insert],
                [Cli] = [Select, Insert],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                // Retrying sets failed steps back to pending. Running a step also counts its attempts.
                [Admin] = [new ColumnGrant(Update, StepRetryColumns)],
                [Worker] = [new ColumnGrant(Update, [.. StepRetryColumns, "attempts"])],
                [Cli] = [new ColumnGrant(Update, StepRetryColumns)],
            },
            ["operation_step_guard_insert"]),

        // AD-12 and AD-13. Only the Hosted request path reaches these yet: sign-in reads Users,
        // and writes Sessions, transactions and OpenIddict's entities. Only a Tenant's deletion
        // deletes (Story 1.29): its Operation's purges, as gk_worker in the Tenant's own scope, which
        // read nothing but the tenant_id their WHERE names.
        new("user", TableClass.Tenant, "Identity", TableUse.Runtime, new Dictionary<string, IReadOnlyList<string>>
        {
            [Hosted] = [Select],
            [Worker] = [Delete],
        }, PurgeColumns, RowGuard),
        // Story 9.3: a Signing Key revocation, as gk_admin, may also end every Session of its Tenant by the
        // one revocation path, reading only the columns its WHERE names and setting only the end.
        new("user_session", TableClass.Tenant, "Sessions", TableUse.Runtime, new Dictionary<string, IReadOnlyList<string>>
        {
            [Hosted] = [Select, Insert, Update],
            [Worker] = [Delete],
        }, new Dictionary<string, IReadOnlyList<ColumnGrant>>(PurgeColumns)
        {
            [Admin] =
            [
                new ColumnGrant(Select, ["tenant_id", "ended_at"]),
                new ColumnGrant(Update, ["ended_at", "end_reason"]),
            ],
        }, RowGuard),
        // Story 2.8: neither ever names a Tenant's system Application. Story 2.9: gk_hosted updates
        // only the columns the Sessions stores and the one revocation path write. Story 3.5: an
        // Application's deletion, as gk_admin, revokes its families and tokens by that one path, reading
        // only the columns its WHERE names; its purge, as gk_worker, deletes them by their Application.
        new("authorization", TableClass.Tenant, "Sessions", TableUse.Runtime, new Dictionary<string, IReadOnlyList<string>>
        {
            [Hosted] = [Select, Insert],
            [Worker] = [Delete],
        }, new Dictionary<string, IReadOnlyList<ColumnGrant>>
        {
            [Hosted] = [new ColumnGrant(Update, AuthorizationUpdateColumns)],
            [Admin] =
            [
                new ColumnGrant(Select, ["tenant_id", "id", "application_id", "status"]),
                new ColumnGrant(Update, AuthorizationUpdateColumns),
            ],
            [Worker] = [new ColumnGrant(Select, ["tenant_id", "id", "application_id"])],
        }, SystemApplicationGuard),
        new("token", TableClass.Tenant, "Sessions", TableUse.Runtime, new Dictionary<string, IReadOnlyList<string>>
        {
            [Hosted] = [Select, Insert],
            [Worker] = [Delete],
        }, new Dictionary<string, IReadOnlyList<ColumnGrant>>
        {
            [Hosted] = [new ColumnGrant(Update, TokenUpdateColumns)],
            [Admin] =
            [
                new ColumnGrant(Select, ["tenant_id", "application_id", "authorization_id", "status"]),
                // Story 3.5: only what the one revocation path changes, as on an authorization row.
                new ColumnGrant(Update, AuthorizationUpdateColumns),
            ],
            [Worker] = [new ColumnGrant(Select, ["tenant_id", "application_id", "authorization_id"])],
        }, SystemApplicationGuard),
        new("signin_transaction", TableClass.Tenant, "Authentication", TableUse.Runtime, new Dictionary<string, IReadOnlyList<string>>
        {
            [Hosted] = [Select, Insert, Update],
            [Worker] = [Delete],
        }, new Dictionary<string, IReadOnlyList<ColumnGrant>>
        {
            // Story 3.5: a deleted Application's purge deletes its transactions by their Application.
            [Worker] = [new ColumnGrant(Select, ["tenant_id", "application_id"])],
        }, RowGuard),
        new(
            "admin_attempt",
            TableClass.Control,
            "Admins",
            TableUse.Runtime,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select, Insert],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                // Counting: the window and the count. Never the policy or the subject.
                [Admin] = [new ColumnGrant(Update, ["window_start", "attempts"])],
            },
            Unlogged: true),

        // Story 1.19: one row, holding only the bootstrap token's SHA-256. The Cli issues and
        // reissues it; Host.Admin reads it and completes bootstrap (Story 1.21). No role deletes,
        // and a completed row is final.
        new(
            "bootstrap_state",
            TableClass.Control,
            "Admins",
            TableUse.Configuration,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select],
                [Cli] = [Select],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                // Issuing and reissuing: the token's hash and times. Never completion.
                [Cli] =
                [
                    new ColumnGrant(Insert, ["id", "token_sha256", "issued_at", "expires_at"]),
                    new ColumnGrant(Update, BootstrapTokenColumns),
                ],
                // Completing bootstrap. Never the token.
                [Admin] = [new ColumnGrant(Update, ["completed_at"])],
            },
            ["bootstrap_state_guard_update"]),

        // Story 1.21: the Admins and their Sessions. Host.Admin creates the first Admin at
        // bootstrap and every Admin Session; the Cli reads Admins so recover-admin (Story 1.32)
        // can find the one it recovers and list them by public ID, and reads no Session. No
        // role deletes either. A Session stores only its ID's hash; its CSRF token is derived
        // from the ID, so nothing about the token is stored.
        new(
            "admin",
            TableClass.Control,
            "Admins",
            TableUse.Configuration,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select, Insert],
                [Cli] = [Select],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                // Completing credential setup, and the WebAuthn user handle (Story 1.22), each
                // written once by the trigger. Never the ID or ownership. setup_completed_at is a
                // set-once stamp only: the count of admin_credential rows decides access.
                [Admin] = [new ColumnGrant(Update, ["setup_completed_at", "webauthn_handle"])],
            },
            ["admin_guard_update"]),
        new(
            "admin_session",
            TableClass.Control,
            "Admins",
            TableUse.Runtime,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select, Insert],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                // Sliding the idle expiry and ending; the pending registration challenge's hash and
                // expiry, and setup to full once the second credential is stored (Story 1.22).
                // Never the ID, its Admin or its absolute expiry. The trigger makes an ending
                // final and lets the kind go only from setup to full.
                [Admin] =
                [
                    new ColumnGrant(
                        Update,
                        ["idle_expires_at", "ended_at", "end_reason", "kind", "registration_challenge_sha256", "registration_challenge_expires_at"]),
                ],
            },
            ["admin_session_guard_update"]),

        // Story 1.22: Admin WebAuthn credentials, public material only. Host.Admin registers them
        // and, from Story 1.23, updates the counter and last use at sign-in. From Story 1.26 it
        // also stores the BS flag on each assertion and removes credentials in Your credentials;
        // its triggers lock the Admin's row and refuse an 11th credential and a delete that would
        // leave fewer than two, for every role.
        new(
            "admin_credential",
            TableClass.Control,
            "Admins",
            TableUse.Configuration,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select, Insert, Delete],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                // The signature counter, last use and backup flags: BE is recorded once, for a credential
                // registered before Story 1.26, and the trigger keeps it. Never the credential, its key or its Admin.
                [Admin] = [new ColumnGrant(Update, ["sign_count", "last_used_at", "backup_eligible", "backed_up"])],
            },
            ["admin_credential_guard_insert", "admin_credential_guard_delete", "admin_credential_guard_update"]),

        // Story 1.23: each pending Admin sign-in's challenge, as its SHA-256, bound to the browser
        // that began it by the SHA-256 of its cookie. Taking a challenge deletes its row, so it can never answer twice, and a begin
        // sweeps the expired rows. No role updates one. Losing them in a crash only makes an
        // Admin press Sign in again, so it is UNLOGGED.
        new(
            "admin_signin_challenge",
            TableClass.Control,
            "Admins",
            TableUse.Runtime,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select, Insert, Delete],
            },
            Unlogged: true),

        // Story 1.24: the one Tenant Role each Admin holds in a Tenant (AD-27). control, not tenant:
        // one Admin's roles are listed across Tenants, so the request checks filter by the path
        // Tenant in code. Host.Admin reads it on every Tenant request, caching nothing, and from
        // Story 1.27 inserts the creator's Owner role. From Story 1.29 it deletes every role of a
        // Tenant whose deletion starts, which the trigger holds it to; Story 8.4 adds UPDATE (role)
        // and single-role removal. gk_hosted never reads it (AD-2).
        new(
            "tenant_role",
            TableClass.Control,
            "Admins",
            TableUse.Configuration,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select, Insert, Delete],
            },
            Triggers: ["tenant_role_guard_insert", "tenant_role_guard_delete"]),

        // Story 1.26: each Admin Session's pending fresh-assertion challenge and its verified grants,
        // bound to the Session and to the SHA-256 of their action, Tenant and target, for 5 minutes
        // at most. Every step is an INSERT or a DELETE … RETURNING, never an UPDATE, so a challenge
        // answers once and a grant is used up once. Losing them in a crash only makes an Admin
        // confirm again, so it is UNLOGGED.
        new(
            "admin_fresh_assertion",
            TableClass.Control,
            "Admins",
            TableUse.Runtime,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select, Insert, Delete],
            },
            Unlogged: true),

        // Story 1.26: an Admin's offline Recovery Code, as an HMAC under the Deployment hmac key and
        // its key version only. Host.Admin issues, confirms and redeems it, and deletes an unconfirmed
        // one it replaces; the trigger writes confirmation and use once and keeps a confirmed one.
        // Story 1.32 took back the Cli's read, granted for recover-admin, which reads no code.
        new(
            "admin_recovery_code",
            TableClass.Control,
            "Admins",
            TableUse.Configuration,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select, Insert, Delete],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                // Confirming and redeeming. Never the HMAC, its key version or its Admin.
                [Admin] = [new ColumnGrant(Update, ["confirmed_at", "used_at"])],
            },
            ["admin_recovery_code_guard"]),

        // Story 1.32 (AD-31): gatekeep recover-admin's single-use enrolments, as the SHA-256 of the
        // value only, with their Admin, issue time, 15-minute expiry and use. Only the Cli inserts
        // one, after its Security Alert and off-server record are confirmed; Host.Admin reads it and
        // marks it used at redemption. No role deletes; the trigger writes the use once and
        // refuses an issue time other than now.
        new(
            "admin_enrolment",
            TableClass.Control,
            "Admins",
            TableUse.Configuration,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select],
                [Cli] = [Select, Insert],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                // Redeeming. Never the hash, its Admin or its times.
                [Admin] = [new ColumnGrant(Update, ["used_at"])],
            },
            ["admin_enrolment_guard"]),

        // Story 2.3 (AD-10, AD-11): each Tenant's Signing and Management key rows, and its token
        // protection key, only as the Transit wrap. Host.Worker creates them at Tenant creation and in
        // the hourly backfill; Host.Hosted only reads them, for discovery and JWKS. Story 2.4: Host.Worker
        // rotates, retires and destroys keys through their state and lifecycle times only, the trigger
        // holds every change to AD-11's transitions. Only a Tenant's deletion deletes a row (Story 1.29), which
        // the triggers allow only while the Tenant is deleting, and no row reaches a Tenant past creating or active.
        // Story 9.1: Host.Admin reads the path Tenant's rows for the Signing keys page. Story 9.2: a Tenant
        // Owner's rotation on demand inserts the new next row and moves state, promoted_at and rotated_at,
        // and nothing else: Host.Admin never retires, destroys or deletes a key row.
        new(
            "signing_key",
            TableClass.Tenant,
            "Keys",
            TableUse.Configuration,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select, Insert],
                [Hosted] = [Select],
                // Story 1.29: the deletion Operation's Keys purge deletes a deleting Tenant's rows.
                [Worker] = [Select, Insert, Delete],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                [Admin] = [new ColumnGrant(Update, ["state", "promoted_at", "rotated_at"])],
                [Worker] = [new ColumnGrant(Update, ["state", "promoted_at", "rotated_at", "retired_at", "destroyed_at"])],
            },
            ["signing_key_guard_delete", "signing_key_guard_update", "tenant_row_guard"]),
        new("protection_key_wrap", TableClass.Tenant, "Keys", TableUse.Configuration, new Dictionary<string, IReadOnlyList<string>>
        {
            [Hosted] = [Select],
            [Worker] = [Select, Insert, Delete],
        }, Triggers: ["protection_key_wrap_guard_delete", "tenant_row_guard"]),

        // Story 2.5 (AD-8, AD-9, AD-24): each Tenant's Applications and their client secrets, a secret
        // only as its SHA-256. Host.Admin creates them (Epic 3 adds the API, rotation and revocation);
        // Host.Hosted only reads them, to authenticate a client. Only a Tenant's deletion deletes (Story
        // 1.29): its Operation's purges, reading only tenant_id.
        // Story 2.8 (AD-12): each Tenant's one hidden system Application. Host.Worker writes it in Tenant
        // creation's completion, finding it by its kind first; the triggers refuse any edit of it, its
        // delete but with its Tenant's, and a secret naming it.
        // Story 3.2: Host.Admin's settings save updates an Application's URLs and grants, and nothing else.
        // Story 3.4: its tokens save updates the four token lifetimes too.
        // Story 3.5: its deletion sets deleted_at, and the directory.application.purge Operation, as
        // gk_worker, deletes the rows that have it set.
        new(
            "application",
            TableClass.Tenant,
            "Directory",
            TableUse.Configuration,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Hosted] = [Select],
                [Admin] = [Select, Insert],
                [Worker] = [Insert, Delete],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                [Worker] = [new ColumnGrant(Select, ["tenant_id", "id", "kind", "deleted_at"])],
                [Admin] = [new ColumnGrant(Update, [
                    "redirect_uris", "post_logout_redirect_uris", "web_origins", "grant_types",
                    "access_token_lifetime", "id_token_lifetime",
                    "refresh_token_absolute_lifetime", "refresh_token_inactivity_lifetime",
                    "deleted_at",
                ])],
            },
            ["application_guard_delete", "application_guard_update", "tenant_row_guard"]),
        // Story 3.3: Host.Admin's rotation sets a secret's expiry and its revocation its revoked_at, and
        // nothing else: never its hash, Application or creation time.
        new(
            "client_secret",
            TableClass.Tenant,
            "Directory",
            TableUse.Configuration,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Hosted] = [Select],
                [Admin] = [Select, Insert],
                [Worker] = [Delete],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                // Story 3.5: a deleted Application's purge deletes its secrets by their Application.
                [Worker] = [new ColumnGrant(Select, ["tenant_id", "application_id"])],
                [Admin] = [new ColumnGrant(Update, ["expires_at", "revoked_at"])],
            },
            SystemApplicationGuard),

        // Story 3.6 (FR-16): each Tenant's APIs, the resource servers its tokens are for. Host.Admin creates them and
        // changes only their offline access, RBAC and lifetimes: never the identifier, which is fixed at creation, or
        // the name. Host.Worker writes the built-in Management API at Tenant activation and in the hourly backfill,
        // finding it by built_in, and a Tenant's deletion purges, reading only tenant_id.
        new(
            "api",
            TableClass.Tenant,
            "Directory",
            TableUse.Configuration,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select, Insert],
                [Worker] = [Insert, Delete],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                [Worker] = [new ColumnGrant(Select, ["tenant_id", "id", "built_in"])],
                [Admin] = [new ColumnGrant(Update, [
                    "offline_access", "rbac",
                    "access_token_lifetime", "id_token_lifetime",
                    "refresh_token_absolute_lifetime", "refresh_token_inactivity_lifetime",
                ])],
            },
            RowGuard),
        // Story 3.6: an API's resource:action Permissions. Host.Admin adds and removes them, never edits one; Host.Worker
        // writes the built-in Management API's, reading which values it has so it inserts only the missing ones, and a
        // Tenant's deletion purges.
        new(
            "permission",
            TableClass.Tenant,
            "Directory",
            TableUse.Configuration,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select, Insert, Delete],
                [Worker] = [Insert, Delete],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                [Worker] = [new ColumnGrant(Select, ["tenant_id", "api_id", "value"])],
            },
            RowGuard),

        // Story 2.5 (AD-14): Tenant attempt counters, such as token requests per Tenant and per source,
        // and cross-Tenant mismatches per source. Host.Hosted counts; only a Tenant's deletion deletes.
        new(
            "tenant_attempt",
            TableClass.Tenant,
            "Authentication",
            TableUse.Runtime,
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Hosted] = [Select, Insert],
                [Worker] = [Delete],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                // Counting: the window and the count. Never the Tenant, policy or subject.
                [Hosted] = [new ColumnGrant(Update, ["window_start", "attempts"])],
                [Worker] = [new ColumnGrant(Select, ["tenant_id"])],
            },
            RowGuard,
            Unlogged: true),
    ];

    private static IReadOnlyList<string> EventTriggers(string table) =>
        [$"{table}_guard_insert", .. DetailTriggers(table)];

    private static IReadOnlyList<string> DetailTriggers(string table) =>
        [$"{table}_guard_update", $"{table}_guard_delete", $"{table}_refuse_truncate"];
}
