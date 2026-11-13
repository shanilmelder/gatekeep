using System.Collections;
using System.Reflection;
using System.Text.RegularExpressions;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// Story 3.6 (FR-16, FR-42): the built-in Management API's Permissions are exactly the <c>resource:action</c> form of every
/// Tenant capability a machine client may be allowed, in the capability table's order: <c>tenant.applications.manage</c>
/// becomes <c>applications:manage</c>. Directory's constant and the migration's literal backfill both hold that list, so a
/// capability added, removed or made machine-allowed in one place but not the others fails here.
/// </summary>
public class ManagementPermissionTests
{
    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    [Fact]
    public void Directorys_Management_Permissions_are_the_machine_allowed_Tenant_capabilities()
    {
        Assert.Equal(Derived(), DirectoryPermissions());
    }

    [Fact]
    public void The_migrations_backfill_writes_exactly_Directorys_Management_Permissions_and_the_API_they_belong_to()
    {
        // Read as source: the migration's base type is EF Core's, which this project doesn't load.
        var source = File.ReadAllText(Path.Combine(Root, "src/Adapters/Postgres/Migrations/Migration20261118000000DefineApis.cs"));
        var permissions = Constant(source, "BackfillPermissions");
        var api = Constant(source, "BackfillApi");

        // Each ('value', 'description') pair of the VALUES list, in order: Directory's values with their descriptions.
        var pairs = Regex.Matches(permissions, @"\('(?<value>[^']*)', '(?<description>[^']*)'\)")
            .Select(m => $"{m.Groups["value"].Value} = {m.Groups["description"].Value}")
            .ToList();
        var contract = DirectoryContract();
        var descriptions = (IReadOnlyDictionary<string, string>)contract.GetField("ManagementPermissionDescriptions")!.GetValue(null)!;
        Assert.Equal(DirectoryPermissions().Select(value => $"{value} = {descriptions[value]}"), pairs);

        Assert.Contains($"'{contract.GetField("ManagementApiName")!.GetValue(null)}'", api, StringComparison.Ordinal);
        Assert.Contains($"'{contract.GetField("ManagementApiIdentifier")!.GetValue(null)}'", api, StringComparison.Ordinal);
    }

    [Fact]
    public void There_are_18_and_each_is_a_valid_Permission_value()
    {
        var permissions = Derived();

        Assert.Equal(18, permissions.Count);
        Assert.Equal(permissions.Count, permissions.Distinct(StringComparer.Ordinal).Count());

        // Each has a short description, which the Permissions table shows and the column's CHECK allows.
        var descriptions = (IReadOnlyDictionary<string, string>)DirectoryContract().GetField("ManagementPermissionDescriptions")!.GetValue(null)!;
        Assert.Equal(permissions.Order(StringComparer.Ordinal), descriptions.Keys.Order(StringComparer.Ordinal));
        Assert.All(descriptions.Values, d => Assert.InRange(d.Length, 1, 200));
        Assert.All(permissions, p => Assert.Matches(@"\A[a-z0-9][a-z0-9_.-]{0,63}:[a-z0-9][a-z0-9_.-]{0,63}\z", p));
    }

    /// <summary>The raw string literal of the constant <paramref name="name"/> in <paramref name="source"/>.</summary>
    private static string Constant(string source, string name)
    {
        var match = Regex.Match(source, $"public const string {name} =\\s*\"\"\"(?<body>.*?)\"\"\";", RegexOptions.Singleline);
        Assert.True(match.Success, $"The migration has no {name} constant.");
        return match.Groups["body"].Value;
    }

    /// <summary>The <c>resource:action</c> of each machine-allowed Tenant capability, read by reflection from the Admins build output.</summary>
    private static List<string> Derived()
    {
        var table = Load("src/Modules/Admins", "Gatekeep.Modules.Admins.dll")
            .GetType("Gatekeep.Modules.Admins.Contracts.AdminCapabilities", throwOnError: true)!;
        var all = ((IEnumerable)table.GetField("All")!.GetValue(null)!).Cast<object>().ToList();
        Assert.NotEmpty(all);

        return
        [
            .. all
                .Where(c => Get(c, "Scope")!.ToString() == "Tenant" && (bool)Get(c, "MachineAllowed")!)
                .Select(c => (string)Get(c, "Name")!)
                .Select(name => name.Split('.'))
                .Select(parts => $"{parts[1]}:{parts[2]}"),
        ];
    }

    private static List<string> DirectoryPermissions() =>
        [.. ((IEnumerable<string>)DirectoryContract().GetField("ManagementPermissions")!.GetValue(null)!)];

    private static Type DirectoryContract() =>
        Load("src/Modules/Directory", "Gatekeep.Modules.Directory.dll")
            .GetType("Gatekeep.Modules.Directory.Contracts.DirectoryContract", throwOnError: true)!;

    private static Assembly Load(string project, string file) => Assembly.LoadFrom(Path.Combine(Root, project, Output(), file));

    /// <summary>The build output folder, relative to a project: the same as this test's.</summary>
    private static string Output() =>
        Path.GetRelativePath(
            Path.Combine(Root, "tests/Architecture"),
            AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

    private static object? Get(object target, string name) => target.GetType().GetProperty(name)!.GetValue(target);
}
