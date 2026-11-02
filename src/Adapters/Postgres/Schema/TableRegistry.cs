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
/// and per column, and the triggers it must have.
/// </summary>
public sealed record TableEntry(
    string Name,
    TableClass Class,
    string Owner,
    IReadOnlyDictionary<string, IReadOnlyList<string>> Grants,
    IReadOnlyDictionary<string, IReadOnlyList<ColumnGrant>>? ColumnGrants = null,
    IReadOnlyList<string>? Triggers = null);

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
            [Sealer] = [new ColumnGrant(Update, ["seq", "prev_hash", "hash"])],
        };

    public static readonly IReadOnlyList<TableEntry> Tables =
    [
        new("tenant", TableClass.Control, "Tenancy", new Dictionary<string, IReadOnlyList<string>>
        {
            [Hosted] = [Select],
            [Admin] = [Select, Insert],
            [Worker] = [Select],
            [Cli] = [Select],
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
    ];

    private static IReadOnlyList<string> EventTriggers(string table) =>
        [$"{table}_guard_insert", .. DetailTriggers(table)];

    private static IReadOnlyList<string> DetailTriggers(string table) =>
        [$"{table}_guard_update", $"{table}_guard_delete", $"{table}_refuse_truncate"];
}
