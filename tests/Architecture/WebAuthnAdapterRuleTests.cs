using System.Reflection;
using System.Runtime.CompilerServices;
using System.Xml.Linq;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// Story 1.22, AD-31: the Kernel <c>IWebAuthnVerifier</c> port's adapter in <c>src/Adapters/Fido2</c>
/// references no module, so it knows no User or Admin type, and keeps no configuration: no instance
/// field anywhere, and only read-only constants as static fields, so the RP ID and origin can only
/// come in with each call. It is the one place the Fido2 package is used. The adapter is read by
/// reflection from Host.Admin's output, which holds the package's assemblies beside it.
/// </summary>
public class WebAuthnAdapterRuleTests
{
    private const string Project = "src/Adapters/Fido2/Gatekeep.Adapters.Fido2.csproj";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] SkippedDirectories = ["bin", "obj", "node_modules", ".git"];

    [Fact]
    public void Adapter_references_the_Kernel_alone_and_no_module()
    {
        var references = XDocument.Load(Path.Combine(Root, Project))
            .Descendants("ProjectReference")
            .Select(r => r.Attribute("Include")!.Value.Replace('\\', '/'));

        Assert.Equal(["../../Gatekeep.Kernel/Gatekeep.Kernel.csproj"], references);
        Assert.DoesNotContain(EdgeList.Load(Root), e => e.From == "Adapters.Fido2");

        var assemblies = Adapter().GetReferencedAssemblies().Select(a => a.Name!).ToList();
        Assert.DoesNotContain(assemblies, a => a.StartsWith("Gatekeep.", StringComparison.Ordinal) && a != "Gatekeep.Kernel");
        Assert.DoesNotContain(assemblies, a => a.StartsWith("Microsoft.Extensions.Configuration", StringComparison.Ordinal));
        Assert.DoesNotContain(assemblies, a => a.StartsWith("Microsoft.Extensions.Options", StringComparison.Ordinal));
    }

    [Fact]
    public void Adapter_keeps_no_state_between_calls()
    {
        const BindingFlags Declared = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;

        var types = Adapter().GetTypes().Where(t => t.GetCustomAttribute<CompilerGeneratedAttribute>() is null).ToList();
        Assert.Contains(types, t => t.Name == "Fido2WebAuthnVerifier");

        var instanceFields = types.SelectMany(t => t.GetFields(Declared | BindingFlags.Instance).Select(f => $"{t.Name}.{f.Name}"));
        Assert.Empty(instanceFields);

        var writableStatics = types.SelectMany(t => t.GetFields(Declared | BindingFlags.Static)
            .Where(f => !f.IsInitOnly && !f.IsLiteral)
            .Select(f => $"{t.Name}.{f.Name}"));
        Assert.Empty(writableStatics);

        // Nothing it hands out can carry an RP ID, origin or challenge from one call to the next.
        var properties = types.SelectMany(t => t.GetProperties(Declared | BindingFlags.Instance | BindingFlags.Static).Select(p => $"{t.Name}.{p.Name}"));
        Assert.Empty(properties);
    }

    [Fact]
    public void Only_the_adapter_uses_the_Fido2_package()
    {
        var projects = SourceFiles(Path.Combine(Root, "src"), "*.csproj")
            .Where(p => XDocument.Load(p).Descendants("PackageReference").Any(r => r.Attribute("Include")?.Value.StartsWith("Fido2", StringComparison.Ordinal) == true))
            .Select(p => Path.GetRelativePath(Root, p).Replace('\\', '/'));
        Assert.Equal([Project], projects);

        var sources = SourceFiles(Path.Combine(Root, "src"), "*.cs")
            .Where(f => File.ReadAllText(f).Contains("Fido2NetLib", StringComparison.Ordinal))
            .Select(f => Path.GetRelativePath(Root, f).Replace('\\', '/'));
        Assert.All(sources, s => Assert.StartsWith("src/Adapters/Fido2/", s));
    }

    private static Assembly Adapter()
    {
        var output = Path.GetRelativePath(
            Path.Combine(Root, "tests/Architecture"),
            AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        return Assembly.LoadFrom(Path.Combine(Root, "src/Gatekeep.Host.Admin", output, "Gatekeep.Adapters.Fido2.dll"));
    }

    private static IEnumerable<string> SourceFiles(string directory, string pattern)
    {
        var nested = Directory.EnumerateDirectories(directory)
            .Where(d => !SkippedDirectories.Contains(Path.GetFileName(d)))
            .SelectMany(d => SourceFiles(d, pattern));

        return Directory.EnumerateFiles(directory, pattern).Concat(nested);
    }
}
