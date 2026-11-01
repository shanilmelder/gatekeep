using System.Text.RegularExpressions;
using System.Xml.Linq;
using Xunit;

namespace Gatekeep.Tests.Architecture;

public class ModuleEdgeTests
{
    private const string Kernel = "Kernel";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] ForbiddenInProjectFiles =
    [
        "DisableTransitiveProjectReferences",
        "ManagePackageVersionsCentrally",
        "NuGetAudit",
        "NuGetAuditLevel",
        "NuGetAuditMode",
        "Reference",
        "TargetFramework",
        "TargetFrameworks",
        "TreatWarningsAsErrors",
        "Version",
    ];

    private static readonly string[] SkippedDirectories = ["bin", "obj", "node_modules", ".git"];

    private static readonly Regex PublicType = new(
        @"^[ \t]*public\s+(?:[a-z]+\s+)*(?:class|struct|record|interface|enum|delegate)\b",
        RegexOptions.Multiline);

    private static readonly Regex FileScopedNamespace = new(@"^\s*namespace\s+[\w.]+\s*;", RegexOptions.Multiline);

    [Fact]
    public void Project_references_equal_the_edge_list_exactly()
    {
        var listed = EdgeList.Load(Root).Select(e => $"{e.From} -> {e.To}").Order().ToList();

        var referenced = ProjectFiles()
            .SelectMany(project => References(project).Select(to => (From: ShortName(project), To: to)))
            .Where(r => r.To != Kernel)
            .Select(r => $"{r.From} -> {r.To}")
            .Order()
            .ToList();

        Assert.Equal(listed, referenced);
    }

    [Fact]
    public void Kernel_references_nothing_and_is_not_in_the_list()
    {
        var kernel = ProjectFiles().Single(p => ShortName(p) == Kernel);

        Assert.Empty(References(kernel));
        Assert.DoesNotContain(EdgeList.Load(Root), e => e.From == Kernel || e.To == Kernel);
    }

    [Fact]
    public void No_project_overrides_the_shared_build_rules()
    {
        foreach (var project in ProjectFiles())
        {
            var elements = XDocument.Load(project).Descendants().Select(e => e.Name.LocalName);

            Assert.Empty(elements.Intersect(ForbiddenInProjectFiles));
        }
    }

    [Fact]
    public void Build_configuration_files_exist_only_at_the_repository_root()
    {
        var nested = SourceFiles(Root, "Directory.*")
            .Where(f => Path.GetFileName(f).StartsWith("Directory.Build.", StringComparison.OrdinalIgnoreCase)
                || Path.GetFileName(f).Equals("Directory.Packages.props", StringComparison.OrdinalIgnoreCase))
            .Where(f => Path.GetDirectoryName(f) != Root);

        Assert.Empty(nested);
    }

    [Fact]
    public void Every_project_is_in_the_solution()
    {
        var inSolution = XDocument.Load(Path.Combine(Root, "Gatekeep.slnx"))
            .Descendants("Project")
            .Select(p => p.Attribute("Path")!.Value);

        var projects = ProjectFiles().Select(p => Path.GetRelativePath(Root, p).Replace('\\', '/'));

        Assert.Empty(projects.Except(inSolution));
    }

    [Fact]
    public void Module_core_and_adapters_declare_no_public_top_level_types()
    {
        var files = Directory.EnumerateDirectories(Path.Combine(Root, "src", "Modules"))
            .SelectMany(module => new[] { "Core", "Adapters" }.Select(layer => Path.Combine(module, layer)))
            .Where(Directory.Exists)
            .SelectMany(layer => SourceFiles(layer, "*.cs"))
            .ToList();

        Assert.NotEmpty(files);
        Assert.DoesNotContain(files, f => DeclaresPublicTopLevelType(File.ReadAllText(f)));
    }

    [Theory]
    [InlineData("namespace N;\npublic sealed class C;\n", true)]
    [InlineData("namespace N;\n\npublic readonly record struct C;\n", true)]
    [InlineData("namespace N\n{\n    public enum E { A }\n}\n", true)]
    [InlineData("namespace N;\ninternal class C\n{\n    public class Nested;\n}\n", false)]
    [InlineData("namespace N\n{\n    internal class C\n    {\n        public class Nested;\n    }\n}\n", false)]
    [InlineData("namespace N;\ninternal class C\n{\n    public static string classify() => \"\";\n}\n", false)]
    public void Public_top_level_type_detection(string source, bool expected)
    {
        Assert.Equal(expected, DeclaresPublicTopLevelType(source));
    }

    [Fact]
    public void Nothing_in_src_uses_InternalsVisibleTo()
    {
        var offenders = SourceFiles(Path.Combine(Root, "src"), "*")
            .Where(f => File.ReadAllText(f).Contains("InternalsVisibleTo"));

        Assert.Empty(offenders);
    }

    [Theory]
    [InlineData("dependency  Keys -> Tenancy")]
    [InlineData("dependency Keys  -> Tenancy")]
    [InlineData("dependency Keys ->  Tenancy")]
    [InlineData("Keys -> Tenancy")]
    public void Edge_list_rejects_lines_the_build_check_would_not_match(string line)
    {
        Assert.Throws<FormatException>(() => EdgeList.Parse([line]));
    }

    [Fact]
    public void Composition_edge_renders_dashed()
    {
        var diagram = EdgeList.RenderDiagram([new Edge(EdgeList.Composition, "Host.Admin", "Keys")]);

        Assert.Contains("  HostAdmin -.-> Keys\n", diagram);
    }

    [Fact]
    public void Diagram_is_current()
    {
        var problem = DiagramProblem(EdgeList.Load(Root));

        Assert.True(problem is null, problem);
    }

    [Fact]
    public void Changed_edge_list_reports_the_diagram_stale_with_the_regenerate_command()
    {
        var changed = EdgeList.Load(Root).SkipLast(1).ToList();

        var problem = DiagramProblem(changed);

        Assert.NotNull(problem);
        Assert.Contains("is stale", problem);
        Assert.Contains(EdgeList.RegenerateCommand, problem);
    }

    /// <summary>Compares the committed diagram with the given edges. Null when it is current.</summary>
    private static string? DiagramProblem(IReadOnlyList<Edge> edges)
    {
        var path = Path.Combine(Root, EdgeList.DiagramPath);
        var expected = EdgeList.RenderDiagram(edges);
        var actual = File.Exists(path) ? File.ReadAllText(path).ReplaceLineEndings("\n") : string.Empty;

        return actual == expected
            ? null
            : $"{EdgeList.DiagramPath} is stale. Regenerate it: {EdgeList.RegenerateCommand}";
    }

    private static bool DeclaresPublicTopLevelType(string source)
    {
        // Brace counting, not a parser: a brace in a comment or string can skew it.
        var topLevelDepth = FileScopedNamespace.IsMatch(source) ? 0 : 1;

        return PublicType.Matches(source).Any(match =>
        {
            var before = source[..match.Index];
            return before.Count(c => c == '{') - before.Count(c => c == '}') <= topLevelDepth;
        });
    }

    private static IEnumerable<string> ProjectFiles() =>
        new[] { "src", "tests" }.SelectMany(d => SourceFiles(Path.Combine(Root, d), "*.csproj"));

    private static IEnumerable<string> SourceFiles(string directory, string pattern)
    {
        var nested = Directory.EnumerateDirectories(directory)
            .Where(d => !SkippedDirectories.Contains(Path.GetFileName(d)))
            .SelectMany(d => SourceFiles(d, pattern));

        return Directory.EnumerateFiles(directory, pattern).Concat(nested);
    }

    private static IEnumerable<string> References(string project) =>
        XDocument.Load(project)
            .Descendants("ProjectReference")
            .Select(r => ShortName(r.Attribute("Include")!.Value.Replace('\\', '/')));

    private static string ShortName(string project) =>
        Path.GetFileNameWithoutExtension(project)
            .Replace("Gatekeep.Modules.", string.Empty)
            .Replace("Gatekeep.", string.Empty);
}
