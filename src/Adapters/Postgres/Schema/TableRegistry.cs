namespace Gatekeep.Adapters.Postgres.Schema;

public enum TableClass
{
    /// <summary>Has meaning inside one Tenant: row-level security applies.</summary>
    Tenant,

    /// <summary>Has no meaning inside one Tenant, as named in AD-27.</summary>
    Control,
}

/// <summary>One table: its class, its one owning module and every privilege per role.</summary>
public sealed record TableEntry(
    string Name,
    TableClass Class,
    string Owner,
    IReadOnlyDictionary<string, IReadOnlyList<string>> Grants);

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
    ];
}
