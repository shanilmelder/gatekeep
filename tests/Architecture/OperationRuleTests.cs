using System.Collections;
using System.Reflection;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// AD-30: Tenant deletion reaches every module holding <c>tenant</c> tables, so Operations
/// needs an edge to each, and, from Story 1.29, its purge list names every such owner but Audit,
/// each of which exposes its own Tenant purge. Tests reference no adapter, so the AD-3 table
/// registry is read by reflection from the Postgres adapter's own output folder, and the modules'
/// contracts from theirs.
/// </summary>
public class OperationRuleTests
{
    private const string Operations = "Operations";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    [Fact]
    public void Table_registry_is_found_and_lists_tenant_tables()
    {
        Assert.Contains(TenantTableOwners(), t => t.Owner != Operations);
    }

    [Fact]
    public void Operations_has_an_edge_to_every_module_owning_tenant_tables()
    {
        Assert.Empty(MissingEdges(TenantTableOwners(), EdgeList.Load(Root)));
    }

    [Fact]
    public void Module_owning_tenant_tables_without_an_Operations_edge_is_reported()
    {
        (string, string)[] tables = [("widget", "Widgets"), ("tenant_settings", "Tenancy"), ("job_payload", Operations)];
        var edges = EdgeList.Parse(["dependency Operations -> Tenancy", "dependency Widgets -> Operations"]);

        Assert.Equal(["Widgets: owns tenant table widget, but Operations has no edge to it (AD-30)."], MissingEdges(tables, edges));
    }

    [Fact]
    public void Composition_edge_doesnt_count()
    {
        (string, string)[] tables = [("widget", "Widgets")];
        var edges = EdgeList.Parse(["composition Operations -> Widgets"]);

        Assert.Single(MissingEdges(tables, edges));
    }

    [Fact]
    public void Production_Operation_types_are_found_and_two_have_a_completion_handler()
    {
        var types = ProductionOperationTypes();

        Assert.Contains(types, t => t.Type == "tenancy.tenant.create" && t.HasCompletion);
        Assert.Contains(types, t => t.Type == "tenancy.tenant.delete" && t.HasCompletion);
        Assert.Contains(types, t => t.Type == "audit.chain.purge" && !t.HasCompletion);
        Assert.Equal(2, types.Count(t => t.HasCompletion));

        // Story 3.5: a deleted Application's purge, one Tenant stage calling every owning module in one transaction, and no completion.
        Assert.Contains(types, t => t.Type == "directory.application.purge" && !t.HasCompletion && t.StageKinds.SequenceEqual(["Tenant"]));
        Assert.Equal(
            ["audit.chain.purge", "directory.application.purge", "tenancy.tenant.create", "tenancy.tenant.delete"],
            types.Select(t => t.Type).Order(StringComparer.Ordinal));
    }

    /// <summary>
    /// Story 3.5: the Application purge is one stage, so its modules can't run out of order as separate step jobs can,
    /// and it purges them in owning-module order, Sessions, Authentication, then Directory, as Tenant deletion's purge
    /// list orders the same modules: each one's rows reference the next one's.
    /// </summary>
    [Fact]
    public void Application_purge_is_one_stage_purging_in_the_Tenant_purge_order()
    {
        var assembly = Assembly.LoadFrom(Path.Combine(Root, "src/Modules/Operations", Output(), "Gatekeep.Modules.Operations.dll"));
        var contract = assembly.GetType("Gatekeep.Modules.Operations.Contracts.OperationsContract", throwOnError: true)!;
        var stages = ((IEnumerable)contract.GetProperty("ApplicationPurgeStages")!.GetValue(null)!).Cast<object>().Select(s => s.ToString()!).ToList();
        var owners = ((IEnumerable)contract.GetProperty("ApplicationPurgeModules")!.GetValue(null)!).Cast<string>().ToList();

        Assert.Equal(["directory.application.purge"], stages);
        Assert.Equal(["Sessions", "Authentication", "Directory"], owners);

        var modules = PurgeModules();
        Assert.All(owners, o => Assert.Contains(o, modules));
        Assert.Equal(owners, owners.OrderBy(o => modules.IndexOf(o)));
    }

    /// <summary>
    /// Story 1.29: the owners of the registry's <c>tenant</c> tables, but Audit, are exactly the
    /// deletion's purge list, each once. A table a later story adds under a new owner fails here
    /// until its owner's purge is on the list.
    /// </summary>
    [Fact]
    public void Tenant_deletion_purges_every_owner_of_a_tenant_table_but_Audit()
    {
        var modules = PurgeModules();

        Assert.Contains(Operations, modules);
        Assert.Empty(PurgeListViolations(TenantTableOwners(), modules));
    }

    [Fact]
    public void Purge_list_missing_an_owner_or_naming_another_is_reported()
    {
        (string, string)[] tables = [("widget", "Widgets"), ("tenant_settings", "Tenancy"), ("audit_event", Audit), ("job_payload", Operations)];

        Assert.Equal(
            [
                "Directory: is on the purge list, but owns no tenant table.",
                "Tenancy: is on the purge list twice.",
                "Widgets: owns tenant table widget, but Tenant deletion doesn't purge it (Story 1.29).",
            ],
            PurgeListViolations(tables, ["Tenancy", "Tenancy", "Directory", Operations]));

        // Audit's chain is never purged with its Tenant's data, so listing it is a violation too.
        Assert.Equal(
            ["Audit: is on the purge list, but its chain is kept until its retention ends (Story 1.29)."],
            PurgeListViolations(tables.Where(t => t.Item2 != "Widgets"), ["Tenancy", Audit, Operations]));
    }

    /// <summary>Story 1.29: each owner on the purge list but Operations, whose purge is internal, exposes <c>{Module}Contract.TenantPurge</c>.</summary>
    [Fact]
    public void Every_purged_module_but_Operations_exposes_its_Tenant_purge()
    {
        var missing = PurgeModules().Where(m => m != Operations).Where(m => !ExposesPurge(m)).ToList();

        Assert.Empty(missing);
    }

    [Fact]
    public void Module_without_a_Tenant_purge_is_reported()
    {
        // Notifications owns no tenant table today, and exposes no purge.
        Assert.False(ExposesPurge("Notifications"));
    }

    /// <summary>
    /// Story 1.27: a completion handler runs in the transaction of whichever job finishes the
    /// Operation, which must be a step job in the Operation's own Tenant scope. A Deployment stage
    /// would let the Deployment-wide run job finish it, where the handler can't run.
    /// </summary>
    [Fact]
    public void Production_type_with_a_completion_handler_has_only_Tenant_stages()
    {
        Assert.Empty(CompletionViolations(ProductionOperationTypes()));
    }

    [Fact]
    public void Completion_handler_beside_a_Deployment_stage_is_reported()
    {
        OperationTypeShape[] types =
        [
            new("widgets.widget.create", true, ["Tenant", "Deployment"]),
            new("widgets.widget.purge", false, ["Deployment"]),
            new("widgets.widget.make", true, ["Tenant"]),
        ];

        Assert.Equal(
            ["widgets.widget.create: has a completion handler, so its stages are all Tenant stages (Story 1.27)."],
            CompletionViolations(types));
    }

    private const string Audit = "Audit";

    private static List<string> PurgeListViolations(IEnumerable<(string Table, string Owner)> tenantTables, IReadOnlyList<string> modules)
    {
        var owners = tenantTables.Select(t => t.Owner).Where(o => o != Audit).ToHashSet(StringComparer.Ordinal);
        var problems = new List<string>();

        foreach (var (table, owner) in tenantTables.Where(t => t.Owner != Audit && !modules.Contains(t.Owner)).DistinctBy(t => t.Owner))
        {
            problems.Add($"{owner}: owns tenant table {table}, but Tenant deletion doesn't purge it (Story 1.29).");
        }

        foreach (var module in modules.Distinct(StringComparer.Ordinal))
        {
            if (module == Audit)
            {
                problems.Add($"{Audit}: is on the purge list, but its chain is kept until its retention ends (Story 1.29).");
            }
            else if (!owners.Contains(module))
            {
                problems.Add($"{module}: is on the purge list, but owns no tenant table.");
            }

            if (modules.Count(m => m == module) > 1)
            {
                problems.Add($"{module}: is on the purge list twice.");
            }
        }

        return [.. problems.Order(StringComparer.Ordinal)];
    }

    private static string Output() =>
        Path.GetRelativePath(
            Path.Combine(Root, "tests/Architecture"),
            AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

    private static List<string> PurgeModules()
    {
        var assembly = Assembly.LoadFrom(Path.Combine(Root, "src/Modules/Operations", Output(), "Gatekeep.Modules.Operations.dll"));
        var contract = assembly.GetType("Gatekeep.Modules.Operations.Contracts.OperationsContract", throwOnError: true)!;
        return [.. ((IEnumerable)contract.GetProperty("TenantPurgeModules")!.GetValue(null)!).Cast<string>()];
    }

    /// <summary>Whether the module's contract has a static <c>TenantPurge</c> of the Kernel's <c>ITenantPurge</c>, set.</summary>
    private static bool ExposesPurge(string module)
    {
        var path = Path.Combine(Root, "src/Modules", module, Output(), $"Gatekeep.Modules.{module}.dll");
        if (!File.Exists(path))
        {
            return false;
        }

        var contract = Assembly.LoadFrom(path).GetType($"Gatekeep.Modules.{module}.Contracts.{module}Contract");
        var property = contract?.GetProperty("TenantPurge", BindingFlags.Public | BindingFlags.Static);
        return property?.PropertyType.FullName == "Gatekeep.Kernel.Persistence.ITenantPurge" && property.GetValue(null) is not null;
    }

    private sealed record OperationTypeShape(string Type, bool HasCompletion, IReadOnlyList<string> StageKinds);

    private static List<string> CompletionViolations(IEnumerable<OperationTypeShape> types) =>
        [.. types
            .Where(t => t.HasCompletion && t.StageKinds.Any(k => k != "Tenant"))
            .Select(t => $"{t.Type}: has a completion handler, so its stages are all Tenant stages (Story 1.27).")];

    private static List<OperationTypeShape> ProductionOperationTypes()
    {
        var output = Path.GetRelativePath(
            Path.Combine(Root, "tests/Architecture"),
            AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        var assembly = Assembly.LoadFrom(Path.Combine(Root, "src/Modules/Operations", output, "Gatekeep.Modules.Operations.dll"));

        var contract = assembly.GetType("Gatekeep.Modules.Operations.Contracts.OperationsContract", throwOnError: true)!;
        var registry = contract.GetProperty("ProductionOperationRegistry")!.GetValue(null)!;
        var definitions = (IEnumerable)registry.GetType().GetProperty("Definitions")!.GetValue(registry)!;

        object? Get(object target, string name) => target.GetType().GetProperty(name)!.GetValue(target);

        return [.. definitions.Cast<object>().Select(d => new OperationTypeShape(
            Get(d, "Type")!.ToString()!,
            Get(d, "OnSucceeded") is not null,
            [.. ((IEnumerable)Get(d, "Stages")!).Cast<object>().Select(s => Get(s, "Kind")!.ToString()!)]))];
    }

    private static List<string> MissingEdges(IEnumerable<(string Table, string Owner)> tenantTables, IReadOnlyList<Edge> edges) =>
        [.. tenantTables
            .Where(t => t.Owner != Operations)
            .Where(t => !edges.Any(e => e.Kind == EdgeList.Dependency && e.From == Operations && e.To == t.Owner))
            .Select(t => $"{t.Owner}: owns tenant table {t.Table}, but {Operations} has no edge to it (AD-30).")];

    private static List<(string Table, string Owner)> TenantTableOwners()
    {
        // Output folders mirror this test's, so the solution build provides the assembly.
        var output = Path.GetRelativePath(
            Path.Combine(Root, "tests/Architecture"),
            AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        var assembly = Assembly.LoadFrom(Path.Combine(Root, "src/Adapters/Postgres", output, "Gatekeep.Adapters.Postgres.dll"));

        var registry = assembly.GetType("Gatekeep.Adapters.Postgres.Schema.TableRegistry", throwOnError: true)!;
        var tables = (IEnumerable)registry.GetField("Tables")!.GetValue(null)!;

        object? Get(object target, string name) => target.GetType().GetProperty(name)!.GetValue(target);

        return [.. tables.Cast<object>()
            .Where(t => Get(t, "Class")!.ToString() == "Tenant")
            .Select(t => ((string)Get(t, "Name")!, (string)Get(t, "Owner")!))];
    }
}
