using System.Collections;
using System.Reflection;
using System.Text.RegularExpressions;
using Gatekeep.Kernel.Audit;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// AD-16 and AR-39: audit codes are a public contract, declared only in each module's
/// <c>{Module}Events</c> catalogue and published in <c>docs/audit-events.md</c>. The committed
/// document is the render, a published code is never dropped, and no code is written anywhere else.
/// </summary>
public class AuditCatalogueTests
{
    private const string Project = "tests/Architecture";

    private const string Migrations = "src/Adapters/Postgres/Migrations";

    private const string RetentionMigration = $"{Migrations}/Migration20261102080000AuditRetention.cs";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] SkippedDirectories = ["bin", "obj", "node_modules"];

    private static readonly Regex CodePattern = new(@"\A[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\z", RegexOptions.Compiled);

    // A regular or verbatim C# string literal. Raw strings hold SQL, never a whole code.
    private static readonly Regex StringLiteral = new(@"@?""(?:[^""\\\r\n]|\\.)*""", RegexOptions.Compiled);

    private static IReadOnlyList<CatalogueEvent> Catalogue => AuditCatalogue.Load(Root, Project);

    [Fact]
    public void Catalogue_is_found_and_holds_the_production_codes()
    {
        var codes = Catalogue.Select(e => e.Code).ToList();

        Assert.Contains("operations.job.dead", codes);
        Assert.Contains("audit.retention.checkpoint", codes);
    }

    [Fact]
    public void Committed_document_is_the_render()
    {
        var problem = DocumentProblem(Catalogue);

        Assert.True(problem is null, problem);
    }

    [Fact]
    public void Added_code_reports_the_document_stale_with_the_regenerate_command()
    {
        CatalogueEvent[] added = [.. Catalogue, new("tests.catalogue.added", "Tests", "A code no document has yet.", null)];

        var problem = DocumentProblem(added);

        Assert.NotNull(problem);
        Assert.Contains("tests.catalogue.added", problem);
        Assert.Contains(AuditCatalogue.RegenerateCommand, problem);
    }

    [Fact]
    public void Every_published_code_is_still_declared()
    {
        var document = File.ReadAllText(Path.Combine(Root, AuditCatalogue.DocPath));

        Assert.NotEmpty(AuditCatalogue.PublishedCodes(document));
        Assert.Empty(AuditCatalogue.ContractBreaks(document, Catalogue));
    }

    [Fact]
    public void Removed_or_renamed_code_is_a_contract_break()
    {
        var document = File.ReadAllText(Path.Combine(Root, AuditCatalogue.DocPath));
        var renamed = Catalogue.Select(e => e.Code == "operations.job.dead" ? e with { Code = "operations.job.died" } : e);

        var problem = Assert.Single(AuditCatalogue.ContractBreaks(document, renamed));

        Assert.StartsWith("Contract break: operations.job.dead", problem);
    }

    [Fact]
    public void Regenerating_over_a_document_that_publishes_a_dropped_code_writes_nothing()
    {
        var document = File.ReadAllText(Path.Combine(Root, AuditCatalogue.DocPath));
        var dropped = Catalogue.Where(e => e.Code != "operations.job.dead").ToList();

        var (text, problems) = AuditCatalogue.Regenerate(document, dropped);

        Assert.Null(text);
        Assert.StartsWith("Contract break: operations.job.dead", Assert.Single(problems));
    }

    [Fact]
    public void Regenerating_with_no_document_is_refused()
    {
        var (text, problems) = AuditCatalogue.Regenerate(null, Catalogue);

        Assert.Null(text);
        Assert.Contains("Restore it from git first", Assert.Single(problems), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Regenerating_the_committed_document_writes_the_render()
    {
        var document = File.ReadAllText(Path.Combine(Root, AuditCatalogue.DocPath));

        var (text, problems) = AuditCatalogue.Regenerate(document, Catalogue);

        Assert.Empty(problems);
        Assert.Equal(AuditCatalogue.Render(Catalogue), text);
    }

    [Fact]
    public void Catalogue_member_that_isnt_a_public_static_field_is_reported()
    {
        var problems = AuditCatalogue.MemberProblems(typeof(MisshapenEvents));

        Assert.Equal(4, problems.Count);
        Assert.Contains(problems, p => p.Contains(".AsProperty ", StringComparison.Ordinal));
        Assert.Contains(problems, p => p.Contains(".Hidden ", StringComparison.Ordinal));
        Assert.Contains(problems, p => p.Contains(".BareCode ", StringComparison.Ordinal));
        Assert.Contains(problems, p => p.Contains(".Made ", StringComparison.Ordinal));
        Assert.Empty(AuditCatalogue.MemberProblems(typeof(WellShapedEvents)));
    }

    [Fact]
    public void Every_code_is_three_lower_case_parts_and_unique()
    {
        var codes = Catalogue.Select(e => e.Code).ToList();

        Assert.All(codes, code => Assert.Matches(CodePattern, code));
        Assert.Empty(codes.GroupBy(c => c, StringComparer.Ordinal).Where(g => g.Count() > 1).Select(g => g.Key));
    }

    [Fact]
    public void Every_FR40_class_is_listed_once_in_the_Kernel_order()
    {
        Assert.Equal(Enum.GetNames<TenantLogClass>(), AuditCatalogue.TenantLogClasses.Select(c => c.Name));
        Assert.Equal(11, AuditCatalogue.TenantLogClasses.Count);
    }

    [Fact]
    public void Every_code_shaped_literal_outside_the_migrations_is_a_catalogued_code_or_a_registered_type()
    {
        var allowed = Allowed();

        var offenders = SourceFiles(Path.Combine(Root, "src"))
            .Select(Relative)
            .Where(f => !f.StartsWith(Migrations + "/", StringComparison.Ordinal))
            .SelectMany(f => StrayCodes(File.ReadAllText(Path.Combine(Root, f)), allowed).Select(code => $"{f}: {code}"));

        Assert.Empty(offenders);
    }

    [Fact]
    public void Retention_migration_names_the_catalogued_checkpoint_code()
    {
        var code = Catalogue.Single(e => e.Module == "Audit" && e.Code.EndsWith(".checkpoint", StringComparison.Ordinal)).Code;

        Assert.Contains($"'{code}'", File.ReadAllText(Path.Combine(Root, RetentionMigration)));
    }

    [Fact]
    public void Catalogue_files_are_the_only_events_files_in_contracts()
    {
        var eventsFiles = Directory.EnumerateDirectories(Path.Combine(Root, "src", "Modules"))
            .Select(m => Path.Combine(m, "Contracts"))
            .Where(Directory.Exists)
            .SelectMany(d => Directory.EnumerateFiles(d, "*Events.cs"))
            .Select(Relative)
            .Order(StringComparer.Ordinal);

        Assert.Equal(
            AuditCatalogue.CatalogueModules(Root).Select(AuditCatalogue.CatalogueFile).Order(StringComparer.Ordinal),
            eventsFiles);
    }

    [Theory]
    [InlineData("var code = new AuditTypeCode(\"x.y.z\");")]
    [InlineData("appender.AppendAsync(context, new AuditEvent(new(\"x.y.z\"), Actor.System), null, token);")]
    [InlineData("public AuditTypeCode Code { get; } = new(\"x.y.z\");")]
    [InlineData("var url = \"http://example.test\"; var code = new AuditTypeCode(\"x.y.z\");")]
    [InlineData("const string Code = @\"x.y.z\";")]
    [InlineData("command.CommandText = \"x.y.z\";")]
    public void Stray_code_literal_is_found_in_any_form(string source)
    {
        Assert.Equal(new[] { "x.y.z" }, StrayCodes(source, new HashSet<string>(StringComparer.Ordinal)));
    }

    [Theory]
    [InlineData("private static readonly AuditTypeCode JobDead = OperationsEvents.JobDead.Code;")]
    [InlineData("throw new ArgumentException(\"An audit type code is {domain}.{object}.{action}.\");")]
    [InlineData("var name = \"Gatekeep.Host.Hosted\";")]
    [InlineData("public static readonly JobType Purge = new(\"operations.job.purge\");")]
    public void Allowed_or_non_code_literal_is_not_found(string source)
    {
        Assert.Empty(StrayCodes(source, new HashSet<string>(["operations.job.purge"], StringComparer.Ordinal)));
    }

    /// <summary>The catalogued codes, and the production job and Operation types, which share the code shape.</summary>
    private static HashSet<string> Allowed()
    {
        var contract = AuditCatalogue.ModuleAssembly(Root, "Operations", Project)
            .GetType("Gatekeep.Modules.Operations.Contracts.OperationsContract", throwOnError: true)!;

        IEnumerable<string> Types(string registry)
        {
            var value = contract.GetProperty(registry)!.GetValue(null)!;
            var definitions = (IEnumerable)value.GetType().GetProperty("Definitions")!.GetValue(value)!;
            return definitions.Cast<object>().Select(d =>
            {
                var type = d.GetType().GetProperty("Type")!.GetValue(d)!;
                return (string)type.GetType().GetProperty("Value")!.GetValue(type)!;
            });
        }

        var allowed = new HashSet<string>(Catalogue.Select(e => e.Code), StringComparer.Ordinal);
        allowed.UnionWith(Types("ProductionRegistry"));
        allowed.UnionWith(Types("ProductionOperationRegistry"));

        // Stage codes share the shape too (Story 1.29: tenancy.tenant.purge, keys.secret_classes.destroy):
        // each stage a production Operation type declares is allowed.
        var operations = contract.GetProperty("ProductionOperationRegistry")!.GetValue(null)!;
        foreach (var definition in ((IEnumerable)operations.GetType().GetProperty("Definitions")!.GetValue(operations)!).Cast<object>())
        {
            foreach (var stage in ((IEnumerable)definition.GetType().GetProperty("Stages")!.GetValue(definition)!).Cast<object>())
            {
                var code = stage.GetType().GetProperty("Code")!.GetValue(stage)!;
                allowed.Add((string)code.GetType().GetProperty("Value")!.GetValue(code)!);
            }
        }

        // Rate limit policy codes share the shape (AD-14): each one a contract publishes is allowed.
        foreach (var module in Directory.EnumerateDirectories(Path.Combine(Root, "src", "Modules")).Select(Path.GetFileName))
        {
            allowed.UnionWith(AuditCatalogue.ModuleAssembly(Root, module!, Project).GetExportedTypes()
                .SelectMany(t => t.GetFields(BindingFlags.Public | BindingFlags.Static))
                .Where(f => f.FieldType.FullName == "Gatekeep.Kernel.RateLimiting.RateLimitPolicy")
                .Select(f => f.GetValue(null)!.ToString()!));
        }

        // Capability names share the shape too (Story 1.24, AD-20): each one the Admins table holds is allowed.
        allowed.UnionWith(AuditCatalogue.ModuleAssembly(Root, "Admins", Project)
            .GetType("Gatekeep.Modules.Admins.Contracts.AdminCapabilities", throwOnError: true)!
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.FieldType.FullName == "Gatekeep.Modules.Admins.Contracts.Capability")
            .Select(f => f.GetValue(null)!.ToString()!));

        // So do the self-service fresh-assertion actions (Story 1.26): each one AdminFreshAssertions lists.
        allowed.UnionWith(((IEnumerable)AuditCatalogue.ModuleAssembly(Root, "Admins", Project)
            .GetType("Gatekeep.Modules.Admins.Contracts.AdminFreshAssertions", throwOnError: true)!
            .GetField("SelfActions")!
            .GetValue(null)!).Cast<string>());

        return allowed;
    }

    /// <summary>Each string literal in <paramref name="source"/> shaped like a code that <paramref name="allowed"/> doesn't hold.</summary>
    private static List<string> StrayCodes(string source, IReadOnlySet<string> allowed) =>
        [.. StringLiteral.Matches(source)
            .Select(m => m.Value.TrimStart('@')[1..^1])
            .Where(text => CodePattern.IsMatch(text) && !allowed.Contains(text))];

    /// <summary>Compares the committed document with the render of <paramref name="events"/>. Null when it's current.</summary>
    private static string? DocumentProblem(IReadOnlyList<CatalogueEvent> events)
    {
        var path = Path.Combine(Root, AuditCatalogue.DocPath);
        var expected = AuditCatalogue.Render(events);
        var actual = File.Exists(path) ? File.ReadAllText(path).ReplaceLineEndings("\n") : string.Empty;

        if (actual == expected)
        {
            return null;
        }

        var missing = events.Select(e => e.Code).Except(AuditCatalogue.PublishedCodes(actual), StringComparer.Ordinal).ToList();
        var detail = missing.Count == 0 ? string.Empty : $" Not yet published: {string.Join(", ", missing)}.";

        return $"{AuditCatalogue.DocPath} is stale.{detail} Regenerate it: {AuditCatalogue.RegenerateCommand}";
    }

    private static string Relative(string path) => Path.GetRelativePath(Root, path).Replace('\\', '/');

    private static IEnumerable<string> SourceFiles(string directory)
    {
        var nested = Directory.EnumerateDirectories(directory)
            .Where(d => !SkippedDirectories.Contains(Path.GetFileName(d)))
            .SelectMany(SourceFiles);

        return Directory.EnumerateFiles(directory, "*.cs").Concat(nested);
    }

    /// <summary>A catalogue the loader can read in full.</summary>
    private static class WellShapedEvents
    {
        public static readonly AuditEventDefinition Read = new(new AuditTypeCode("tests.catalogue.read"), "Read.");
    }

    /// <summary>Every shape the loader would miss.</summary>
    private static class MisshapenEvents
    {
        public static readonly AuditEventDefinition Read = new(new AuditTypeCode("tests.catalogue.read"), "Read.");

        public static AuditEventDefinition AsProperty { get; } = new(new AuditTypeCode("tests.catalogue.property"), "Property.");

        public static readonly AuditTypeCode BareCode = new("tests.catalogue.bare");

        internal static readonly AuditEventDefinition Hidden = new(new AuditTypeCode("tests.catalogue.hidden"), "Hidden.");

        public static AuditEventDefinition Made() => Read;
    }
}
