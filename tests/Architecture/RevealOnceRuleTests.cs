using System.Text.Json;
using System.Text.RegularExpressions;
using Gatekeep.Kernel.Secrets;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// Story 1.26, AD-24: <c>RevealOnce&lt;T&gt;</c> is the one credential-equivalent type with a JSON
/// form, so where it may appear is a reviewed list. Under <c>src/</c> it is only a property of a
/// listed response type, built only in that response's handler, and named in the OpenAPI
/// transformer for its schema. It writes its value as JSON, prints a mask and is never read in.
/// Sources are read as text, comments removed.
/// </summary>
public class RevealOnceRuleTests
{
    private const string Declaration = "src/Gatekeep.Kernel/Secrets/RevealOnce.cs";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] SkippedDirectories = ["bin", "obj"];

    /// <summary>The reviewed response types that may hold one, each in the file that declares it.</summary>
    private static readonly (string File, string Type)[] Responses =
    [
        ("src/Gatekeep.Host.Admin/RecoveryCodeApi.cs", "AdminRecoveryCodeResponse"),
        // Story 2.5: a machine client's secret, shown once to the caller that created it (AD-24).
        ("src/Modules/Directory/Contracts/IDirectory.cs", "CreatedMachineClient"),
        // Story 2.9: a web client's secret, the same way.
        ("src/Modules/Directory/Contracts/IDirectory.cs", "CreatedWebClient"),
        // Story 3.3: an Application's created or rotated-in secret, from Directory through Management to the
        // one 201 that shows it (AD-24).
        ("src/Modules/Directory/Contracts/IDirectory.cs", "ClientSecretWrite"),
        ("src/Modules/Management/Contracts/IApplicationManagement.cs", "ApplicationSecretsResult"),
        ("src/Gatekeep.Host.Admin/ApplicationSecretsApi.cs", "ApplicationSecretCreatedResponse"),
    ];

    /// <summary>Where one may be built: the handler that sends the reviewed response.</summary>
    private static readonly string[] Builders = ["src/Gatekeep.Host.Admin/RecoveryCodeApi.cs", "src/Modules/Directory/Core/DirectoryService.cs"];

    /// <summary>Where it may be named for its schema only.</summary>
    private static readonly string[] SchemaNames = ["src/Gatekeep.Host.Admin/AdminOpenApi.cs"];

    private static readonly Regex Comment = new(@"//[^\r\n]*|/\*.*?\*/", RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex Use = new(@"\bRevealOnce\s*<", RegexOptions.Compiled);

    private static readonly Regex Property = new(@"\bpublic\s+(?:required\s+)?RevealOnce\s*<[^>]+>\??\s+\w+\s*\{\s*get;\s*init;\s*\}", RegexOptions.Compiled);

    private static readonly Regex Construction = new(@"\bnew\s+RevealOnce\s*<", RegexOptions.Compiled);

    private static readonly Regex SchemaName = new(@"\btypeof\s*\(\s*(?:[\w.]+\.)?RevealOnce\s*<", RegexOptions.Compiled);

    private static readonly Regex TypeDeclaration = new(@"\b(?:class|record|struct|interface)\s+(?<name>\w+)", RegexOptions.Compiled);

    [Fact]
    public void Reveal_once_appears_only_where_reviewed()
    {
        var sources = SourceFiles(Path.Combine(Root, "src"))
            .Select(f => (Name: Path.GetRelativePath(Root, f).Replace('\\', '/'), Text: File.ReadAllText(f)))
            .ToList();

        Assert.Empty(sources.SelectMany(s => Problems(s.Name, s.Text)));

        // The reviewed response holds one, so the rule isn't vacuous.
        Assert.Contains(sources, s => s.Name == Responses[0].File && Property.IsMatch(s.Text));
    }

    [Theory]
    [InlineData("src/Modules/Admins/Core/Codes.cs", "public sealed record Issue(RevealOnce<string> Code);")]
    [InlineData("src/Gatekeep.Host.Admin/RecoveryCodeApi.cs", "public sealed class Other\n{\n    public required RevealOnce<string> Code { get; init; }\n}")]
    [InlineData("src/Gatekeep.Host.Admin/SignInApi.cs", "var code = new RevealOnce<string>(value);")]
    [InlineData("src/Gatekeep.Host.Admin/RecoveryCodeApi.cs", "private static RevealOnce<string> Keep;")]
    [InlineData("src/Gatekeep.Host.Admin/AdminApi.cs", "var t = typeof(RevealOnce<string>);")]
    public void Rule_catches_a_use_outside_the_reviewed_places(string file, string source)
    {
        Assert.NotEmpty(Problems(file, source));
    }

    [Fact]
    public void Rule_accepts_the_reviewed_shapes()
    {
        Assert.Empty(Problems(
            "src/Gatekeep.Host.Admin/RecoveryCodeApi.cs",
            "public sealed class AdminRecoveryCodeResponse\n{\n    public required RevealOnce<string> Code { get; init; }\n}\nvar r = new RevealOnce<string>(c);"));
        Assert.Empty(Problems("src/Gatekeep.Host.Admin/AdminOpenApi.cs", "if (type == typeof(Gatekeep.Kernel.Secrets.RevealOnce<string>))"));
        Assert.Empty(Problems("src/Modules/Admins/Core/Codes.cs", "// A RevealOnce<string> would be wrong here."));
    }

    [Fact]
    public void Reveal_once_writes_its_value_as_JSON_masks_it_elsewhere_and_is_never_read_in()
    {
        var value = new RevealOnce<string>("7K3M-QX2P");

        Assert.Equal("\"7K3M-QX2P\"", JsonSerializer.Serialize(value));
        Assert.Equal("[secret]", value.ToString());
        Assert.DoesNotContain("7K3M", $"{value}", StringComparison.Ordinal);
        Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<RevealOnce<string>>("\"7K3M-QX2P\""));
    }

    /// <summary>Each use of the type in <paramref name="source"/> that isn't a reviewed one.</summary>
    private static List<string> Problems(string file, string source)
    {
        if (file == Declaration)
        {
            return [];
        }

        var code = Comment.Replace(source, string.Empty);
        var allowed = new List<(int Start, int End)>();
        foreach (Match property in Property.Matches(code))
        {
            var owner = TypeDeclaration.Matches(code[..property.Index]).LastOrDefault()?.Groups["name"].Value;
            if (Responses.Contains((file, owner ?? string.Empty)))
            {
                allowed.Add((property.Index, property.Index + property.Length));
            }
        }

        if (Builders.Contains(file))
        {
            allowed.AddRange(Construction.Matches(code).Select(m => (m.Index, m.Index + m.Length)));
        }

        if (SchemaNames.Contains(file))
        {
            allowed.AddRange(SchemaName.Matches(code).Select(m => (m.Index, m.Index + m.Length)));
        }

        return [.. Use.Matches(code)
            .Where(m => !allowed.Any(a => m.Index >= a.Start && m.Index < a.End))
            .Select(m => $"{file}: RevealOnce is used outside the reviewed response, its handler and its schema, at {m.Index}.")];
    }

    private static IEnumerable<string> SourceFiles(string directory)
    {
        var nested = Directory.EnumerateDirectories(directory)
            .Where(d => !SkippedDirectories.Contains(Path.GetFileName(d)))
            .SelectMany(SourceFiles);

        return Directory.EnumerateFiles(directory, "*.cs").Concat(nested);
    }
}
