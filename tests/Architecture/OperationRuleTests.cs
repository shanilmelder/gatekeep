using System.Collections;
using System.Reflection;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// AD-30: Tenant deletion reaches every module holding <c>tenant</c> tables, so Operations
/// needs an edge to each. Tests reference no adapter, so the AD-3 table registry is read by
/// reflection from the Postgres adapter's own output folder.
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
    public void Production_Operation_types_are_found_and_one_has_a_completion_handler()
    {
        var types = ProductionOperationTypes();

        Assert.Contains(types, t => t.Type == "tenancy.tenant.create" && t.HasCompletion);
        Assert.Contains(types, t => t.Type == "audit.chain.purge" && !t.HasCompletion);
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
