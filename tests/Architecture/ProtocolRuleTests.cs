using System.Text.RegularExpressions;
using System.Xml.Linq;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// Story 2.3 (AD-8, AD-33): the OpenIddict wrapping holds only while the Gatekeep Tenant handler is
/// the first <c>ProcessRequestContext</c> handler, at <see cref="int.MinValue"/>, and OpenIddict's
/// own <c>ResolveRequestUri</c> stays removed; an OpenIddict upgrade that adds an earlier handler,
/// or renames that one, breaks the design (Story 2.1 carry-over). Only the Protocol module and
/// Host.Hosted reference OpenIddict, and neither names a Management key, which Host.Hosted's custody
/// policy can't use. Tests reference no module, so sources are read as text; the Isolation suite
/// checks the built handler list itself. Each rule has a self-check that a violation is caught.
/// </summary>
public class ProtocolRuleTests
{
    private const string ServerFile = "src/Modules/Protocol/Core/ProtocolServer.cs";

    private const string RemoveResolveRequestUri = "options.RemoveEventHandler(OpenIddictServerAspNetCoreHandlers.ResolveRequestUri.Descriptor);";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] SkippedDirectories = ["bin", "obj"];

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
        var referencing = SourceFiles("src", "*.csproj")
            .Where(f => XDocument.Parse(f.Source).Descendants("PackageReference")
                .Any(r => r.Attribute("Include")?.Value.StartsWith("OpenIddict", StringComparison.Ordinal) == true))
            .Select(f => f.Path)
            .Order(StringComparer.Ordinal);

        Assert.Equal(OpenIddictProjects, referencing);
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

    /// <summary>
    /// Story 9.1: the Signing keys page names the Tenant's JWKS URI with Management's own copy of the
    /// path, since Management can't reference Protocol. It must be the path Host.Hosted serves.
    /// </summary>
    [Fact]
    public void Managements_JWKS_path_is_the_one_Protocol_serves()
    {
        var protocol = ConstantIn(File.ReadAllText(Path.Combine(Root, "src/Modules/Protocol/Contracts/ProtocolContract.cs")), "JsonWebKeySetPath");
        var management = ConstantIn(File.ReadAllText(Path.Combine(Root, "src/Modules/Management/Contracts/ISigningKeyManagement.cs")), "JwksPath");

        Assert.NotNull(protocol);
        Assert.Equal(protocol, management);
    }

    [Theory]
    [InlineData("public const string JwksPath = \"/.well-known/jwks\";", "/.well-known/jwks")]
    [InlineData("// public const string JwksPath = \"/old\";\npublic const string JwksPath = \"/.well-known/jwks.json\";", "/.well-known/jwks.json")]
    [InlineData("public const string OtherPath = \"/.well-known/jwks\";", null)]
    public void Jwks_path_constant_detection(string source, string? expected)
    {
        Assert.Equal(expected, ConstantIn(source, "JwksPath"));
    }

    private static string? ConstantIn(string source, string name) =>
        Regex.Match(Code(source), $@"\bconst\s+string\s+{name}\s*=\s*""(?<value>[^""]*)""") is { Success: true } m ? m.Groups["value"].Value : null;

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
