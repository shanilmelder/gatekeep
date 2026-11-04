namespace Gatekeep.Adapters.Postgres.Schema;

public enum TableClass
{
    /// <summary>Has meaning inside one Tenant: row-level security applies.</summary>
    Tenant,

    /// <summary>Has no meaning inside one Tenant, as named in AD-27.</summary>
    Control,
}

/// <summary>One privilege on named columns only.</summary>
public sealed record ColumnGrant(string Privilege, IReadOnlyList<string> Columns);

/// <summary>
/// One table: its class, its one owning module, every privilege per role, on the table
/// and per column, the triggers it must have, and whether it is <c>UNLOGGED</c>. Only
/// counters a crash may reset (AD-14), pending sign-in challenges a crash may drop
/// (Story 1.23), and fresh-assertion challenges and grants (Story 1.26) are unlogged; every other table must be logged.
/// </summary>
public sealed record TableEntry(
    string Name,
    TableClass Class,
    string Owner,
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

    public static readonly IReadOnlyList<TableEntry> Tables =
    [
        new("tenant", TableClass.Control, "Tenancy", new Dictionary<string, IReadOnlyList<string>>
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
        }),
        new("tenant_host", TableClass.Control, "Tenancy", new Dictionary<string, IReadOnlyList<string>>
        {
            [Hosted] = [Select],
            [Admin] = [Select, Insert],
            [Worker] = [Select],
        }),
        new("tenant_settings", TableClass.Tenant, "Tenancy", new Dictionary<string, IReadOnlyList<string>>
        {
            [Hosted] = [Select],
            [Admin] = [Select, Insert, Update],
            [Worker] = [Select],
        }),
        new("migration_history", TableClass.Control, "Operations", new Dictionary<string, IReadOnlyList<string>>()),
        new(
            "audit_event",
            TableClass.Tenant,
            "Audit",
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
            }),
        new(
            "operation",
            TableClass.Control,
            "Operations",
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
        // and writes Sessions, transactions and OpenIddict's entities. No role deletes.
        new("user", TableClass.Tenant, "Identity", new Dictionary<string, IReadOnlyList<string>>
        {
            [Hosted] = [Select],
        }),
        new("user_session", TableClass.Tenant, "Sessions", new Dictionary<string, IReadOnlyList<string>>
        {
            [Hosted] = [Select, Insert, Update],
        }),
        new("authorization", TableClass.Tenant, "Sessions", new Dictionary<string, IReadOnlyList<string>>
        {
            [Hosted] = [Select, Insert, Update],
        }),
        new("token", TableClass.Tenant, "Sessions", new Dictionary<string, IReadOnlyList<string>>
        {
            [Hosted] = [Select, Insert, Update],
        }),
        new("signin_transaction", TableClass.Tenant, "Authentication", new Dictionary<string, IReadOnlyList<string>>
        {
            [Hosted] = [Select, Insert, Update],
        }),
        new(
            "admin_attempt",
            TableClass.Control,
            "Admins",
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
        // bootstrap and every Admin Session; the Cli reads Admins for recover-admin later. No
        // role deletes either. A Session stores only its ID's hash; its CSRF token is derived
        // from the ID, so nothing about the token is stored.
        new(
            "admin",
            TableClass.Control,
            "Admins",
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
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select, Insert, Delete],
            },
            Unlogged: true),

        // Story 1.24: the one Tenant Role each Admin holds in a Tenant (AD-27). control, not tenant:
        // one Admin's roles are listed across Tenants, so the request checks filter by the path
        // Tenant in code. Host.Admin only reads it on every Tenant request, caching nothing. Story
        // 1.27 adds INSERT, Story 8.4 UPDATE (role) and DELETE. gk_hosted never reads it (AD-2).
        new(
            "tenant_role",
            TableClass.Control,
            "Admins",
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select],
            }),

        // Story 1.26: each Admin Session's pending fresh-assertion challenge and its verified grants,
        // bound to the Session and to the SHA-256 of their action, Tenant and target, for 5 minutes
        // at most. Every step is an INSERT or a DELETE … RETURNING, never an UPDATE, so a challenge
        // answers once and a grant is used up once. Losing them in a crash only makes an Admin
        // confirm again, so it is UNLOGGED.
        new(
            "admin_fresh_assertion",
            TableClass.Control,
            "Admins",
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select, Insert, Delete],
            },
            Unlogged: true),

        // Story 1.26: an Admin's offline Recovery Code, as an HMAC under the Deployment hmac key and
        // its key version only. Host.Admin issues, confirms and redeems it, and deletes an unconfirmed
        // one it replaces; the trigger writes confirmation and use once and keeps a confirmed one.
        // The Cli reads it, for recover-admin later.
        new(
            "admin_recovery_code",
            TableClass.Control,
            "Admins",
            new Dictionary<string, IReadOnlyList<string>>
            {
                [Admin] = [Select, Insert, Delete],
                [Cli] = [Select],
            },
            new Dictionary<string, IReadOnlyList<ColumnGrant>>
            {
                // Confirming and redeeming. Never the HMAC, its key version or its Admin.
                [Admin] = [new ColumnGrant(Update, ["confirmed_at", "used_at"])],
            },
            ["admin_recovery_code_guard"]),
    ];

    private static IReadOnlyList<string> EventTriggers(string table) =>
        [$"{table}_guard_insert", .. DetailTriggers(table)];

    private static IReadOnlyList<string> DetailTriggers(string table) =>
        [$"{table}_guard_update", $"{table}_guard_delete", $"{table}_refuse_truncate"];
}
