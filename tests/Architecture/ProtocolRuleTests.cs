using System.Text.RegularExpressions;
using System.Xml.Linq;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// Story 2.3 (AD-8, AD-33): the OpenIddict wrapping holds only while the Gatekeep Tenant handler is
/// the first <c>ProcessRequestContext</c> handler, at <see cref="int.MinValue"/>, and OpenIddict's
/// own <c>ResolveRequestUri</c> stays removed; an OpenIddict upgrade that adds an earlier handler,
/// or renames that one, breaks the design (Story 2.1 carry-over). Only the Protocol module and
/// Host.Hosted reference OpenIddict's engine (the store owners, Directory and Sessions, only its
/// abstractions, Story 2.5), and neither names a Management key, which Host.Hosted's custody
/// policy can't use. Tests reference no module, so sources are read as text; the Isolation suite
/// checks the built handler list itself. Each rule has a self-check that a violation is caught.
/// </summary>
public class ProtocolRuleTests
{
    private const string ServerFile = "src/Modules/Protocol/Core/ProtocolServer.cs";

    private const string RemoveResolveRequestUri = "options.RemoveEventHandler(OpenIddictServerAspNetCoreHandlers.ResolveRequestUri.Descriptor);";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] SkippedDirectories = ["bin", "obj"];

    private const string DirectoryProject = "src/Modules/Directory/Gatekeep.Modules.Directory.csproj";

    private const string SessionsProject = "src/Modules/Sessions/Gatekeep.Modules.Sessions.csproj";

    private static readonly string[] OpenIddictProjects =
    [
        "src/Gatekeep.Host.Hosted/Gatekeep.Host.Hosted.csproj",
        "src/Modules/Protocol/Gatekeep.Modules.Protocol.csproj",
    ];

    private static readonly Regex Comment = new(@"//[^\r\n]*|/\*.*?\*/", RegexOptions.Singleline | RegexOptions.Compiled);

    /// <summary>A handler descriptor on <c>ProcessRequestContext</c>, up to its <c>Build()</c>.</summary>
    private static readonly Regex ProcessRequestDescriptor = new(
        @"CreateBuilder\s*<\s*ProcessRequestContext\s*>\s*\(\s*\)(?<body>.*?)\.Build\s*\(\s*\)",
        RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex AtMinValue = new(@"\.SetOrder\s*\(\s*int\.MinValue\s*\)", RegexOptions.Compiled);

    private static readonly Regex HandlerType = new(@"\.Use(?:Singleton|Scoped)Handler\s*<\s*(?<type>\w+)\s*>", RegexOptions.Compiled);

    private static readonly Regex ManagementKey = new(@"KeyName\s*\.\s*Management\b|""mgmt-|SigningKeyPurpose\s*\.\s*Management\b", RegexOptions.Compiled);

    [Fact]
    public void The_Tenant_handler_is_the_only_one_first_on_ProcessRequestContext()
    {
        Assert.Equal(["SelectTenantOptions"], FirstHandlers(SourceFiles("src")));
    }

    [Fact]
    public void A_second_handler_at_MinValue_or_none_is_reported()
    {
        const string selected = "OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>().UseSingletonHandler<SelectTenantOptions>().SetOrder(int.MinValue).Build();";
        const string other = "OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()\n  .UseScopedHandler<Early>()\n  .SetOrder(int.MinValue)\n  .Build();";
        const string later = "OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>().UseSingletonHandler<SelectTenantOptions>().SetOrder(int.MinValue + 1).Build();";

        Assert.Equal(["Early", "SelectTenantOptions"], FirstHandlers([("a.cs", selected), ("b.cs", other)]));
        Assert.Empty(FirstHandlers([("a.cs", later)]));
        Assert.Empty(FirstHandlers([("a.cs", "// " + selected)]));
    }

    [Fact]
    public void ResolveRequestUri_stays_removed()
    {
        Assert.Contains(RemoveResolveRequestUri, Code(File.ReadAllText(Path.Combine(Root, ServerFile))));
    }

    [Fact]
    public void Only_Protocol_and_Host_Hosted_reference_OpenIddict()
    {
        var engine = OpenIddictReferences(SourceFiles("src", "*.csproj")).Where(r => r.Value.Any(p => p != "OpenIddict.Abstractions")).Select(r => r.Key);

        Assert.Equal(OpenIddictProjects, engine);
    }

    /// <summary>
    /// Story 2.5 (AD-8): each store lives in its owner's adapters, so Directory and Sessions reference
    /// OpenIddict too, but only <c>OpenIddict.Abstractions</c>, the store interfaces. The engine, the
    /// server and the managers, stays in Protocol and Host.Hosted.
    /// </summary>
    [Fact]
    public void Store_owners_reference_only_the_OpenIddict_abstractions()
    {
        var references = OpenIddictReferences(SourceFiles("src", "*.csproj"));

        Assert.Equal(["OpenIddict.Abstractions"], references[DirectoryProject]);
        Assert.Equal(["OpenIddict.Abstractions"], references[SessionsProject]);
        Assert.Equal([DirectoryProject, SessionsProject], references.Keys.Except(OpenIddictProjects).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void A_store_owner_referencing_the_engine_is_reported()
    {
        const string engine = "<Project><ItemGroup><PackageReference Include=\"OpenIddict.Abstractions\" /><PackageReference Include=\"OpenIddict.Core\" /></ItemGroup></Project>";

        var references = OpenIddictReferences([(DirectoryProject, engine)]);

        Assert.NotEqual(["OpenIddict.Abstractions"], references[DirectoryProject]);
    }

    /// <summary>Each project referencing an OpenIddict package, by path, with the packages it references.</summary>
    private static SortedDictionary<string, string[]> OpenIddictReferences(IEnumerable<(string Path, string Source)> projects)
    {
        var references = new SortedDictionary<string, string[]>(StringComparer.Ordinal);
        foreach (var (path, source) in projects)
        {
            string[] packages = [.. XDocument.Parse(source).Descendants("PackageReference")
                .Select(r => r.Attribute("Include")?.Value ?? string.Empty)
                .Where(p => p.StartsWith("OpenIddict", StringComparison.Ordinal))
                .Order(StringComparer.Ordinal)];
            if (packages.Length > 0)
            {
                references[path] = packages;
            }
        }

        return references;
    }

    [Fact]
    public void Nothing_on_the_Hosted_path_names_a_Management_key()
    {
        var files = SourceFiles("src/Modules/Protocol").Concat(SourceFiles("src/Gatekeep.Host.Hosted"));

        Assert.NotEmpty(files);
        Assert.Empty(files.Where(f => ManagementKey.IsMatch(Code(f.Source))).Select(f => f.Path));
    }

    [Theory]
    [InlineData("var key = KeyName.Management(tenant, row);", true)]
    [InlineData("if (name.StartsWith(\"mgmt-\")) { }", true)]
    [InlineData("var purpose = SigningKeyPurpose.Management;", true)]
    [InlineData("// Never a mgmt- key.", false)]
    [InlineData("var key = KeyName.Signing(tenant, row);", false)]
    public void Management_key_detection(string source, bool expected)
    {
        Assert.Equal(expected, ManagementKey.IsMatch(Code(source)));
    }

    private static List<string> FirstHandlers(IEnumerable<(string Path, string Source)> files) =>
        [.. files
            .SelectMany(f => ProcessRequestDescriptor.Matches(Code(f.Source)))
            .Where(m => AtMinValue.IsMatch(m.Groups["body"].Value))
            .Select(m => HandlerType.Match(m.Groups["body"].Value) is { Success: true } type ? type.Groups["type"].Value : "?")
            .Order(StringComparer.Ordinal)];

    private static string Code(string source) => Comment.Replace(source, string.Empty);

    private static List<(string Path, string Source)> SourceFiles(string directory, string pattern = "*.cs") =>
        [.. Files(Path.Combine(Root, directory), pattern)
            .Select(f => (Path.GetRelativePath(Root, f).Replace('\\', '/'), File.ReadAllText(f)))];

    private static IEnumerable<string> Files(string directory, string pattern)
    {
        var nested = Directory.EnumerateDirectories(directory)
            .Where(d => !SkippedDirectories.Contains(Path.GetFileName(d)))
            .SelectMany(d => Files(d, pattern));

        return Directory.EnumerateFiles(directory, pattern).Concat(nested);
    }
}
