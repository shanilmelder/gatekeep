using System.Diagnostics;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>Runs real builds on a throwaway copy of the source tree, one per I/O matrix case.</summary>
public sealed class BuildEnforcementTests : IDisposable
{
    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] RootFiles =
    [
        "Gatekeep.slnx",
        "global.json",
        "nuget.config",
        "Directory.Build.props",
        "Directory.Build.targets",
        "Directory.Packages.props",
    ];

    private static readonly string[] WorkspaceFiles =
    [
        ".npmrc",
        "package.json",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
    ];

    private static readonly string[] BuildOutput = ["bin", "obj", "node_modules", "dist"];

    private static readonly TimeSpan CommandTimeout = TimeSpan.FromMinutes(5);

    private const string KernelProject = "src/Gatekeep.Kernel/Gatekeep.Kernel.csproj";

    private readonly string _copy = Path.Combine(Path.GetTempPath(), "gatekeep-" + Guid.NewGuid().ToString("N"));

    public BuildEnforcementTests()
    {
        foreach (var file in RootFiles)
        {
            CopyFile(file);
        }

        CopyFile(EdgeList.ListPath);
        CopyTree("src");
    }

    [Fact]
    public void Listed_edge_builds()
    {
        var (exitCode, output) = Build(Module("Protocol"));

        Assert.True(exitCode == 0, output);
    }

    [Theory]
    [InlineData("src/Modules/Keys/Gatekeep.Modules.Keys.csproj", "Identity", "Keys -> Identity")]
    [InlineData("src/Gatekeep.Host.Admin/Gatekeep.Host.Admin.csproj", "Keys", "Host.Admin -> Keys")]
    [InlineData("src/Gatekeep.Kernel/Gatekeep.Kernel.csproj", "Tenancy", "Kernel -> Tenancy")]
    public void Unlisted_edge_fails_naming_both_projects_and_the_list(string project, string target, string edge)
    {
        AddReference(project, target);

        var (exitCode, output) = Build(project);

        Assert.True(exitCode != 0, output);
        Assert.Contains($"GK0001: Unlisted project reference {edge}.", output);
        Assert.Contains(EdgeList.ListPath, output);
    }

    [Fact]
    public void Transitive_use_fails_with_a_compiler_error()
    {
        // Operations is a direct edge and Tenancy is reachable only through it, so the
        // first line must compile and the second must not.
        const string project = "src/Gatekeep.Host.Worker/Gatekeep.Host.Worker.csproj";
        File.AppendAllText(
            Path.Combine(_copy, "src/Gatekeep.Host.Worker/Program.cs"),
            """

            _ = typeof(Gatekeep.Modules.Operations.Contracts.OperationsContract);
            _ = typeof(Gatekeep.Modules.Tenancy.Contracts.TenancyContract);
            """);

        var (exitCode, output) = Build(project);

        Assert.True(exitCode != 0, output);
        var errors = output.Split('\n').Where(l => l.Contains("error CS")).ToList();
        Assert.NotEmpty(errors);
        Assert.All(errors, l => Assert.Contains("Tenancy", l));
        Assert.DoesNotContain("GK0001", output);
    }

    [Fact]
    public void Composition_edge_builds()
    {
        const string project = "src/Gatekeep.Host.Admin/Gatekeep.Host.Admin.csproj";
        File.AppendAllText(Path.Combine(_copy, EdgeList.ListPath), "composition Host.Admin -> Keys\n");
        AddReference(project, "Keys");

        var (exitCode, output) = Build(project);

        Assert.True(exitCode == 0, output);
    }

    [Fact]
    public void Pnpm_install_scripts_do_not_run()
    {
        CopyWorkspace();
        File.WriteAllText(Path.Combine(_copy, "mark.js"), "require('fs').writeFileSync('marker', 'ran');\n");
        var manifest = Path.Combine(_copy, "package.json");
        File.WriteAllText(
            manifest,
            File.ReadAllText(manifest).Replace("\"scripts\": {", "\"scripts\": {\n    \"preinstall\": \"node mark.js\","));

        var (exitCode, output) = Pnpm("install");

        Assert.True(exitCode == 0, output);
        Assert.False(File.Exists(Path.Combine(_copy, "marker")), "The root preinstall script ran.");
    }

    [Fact]
    public void NuGet_lockfile_drift_fails_locked_restore()
    {
        // Already a central package version, so only the project's lockfile is out of date.
        AddPackage(KernelProject, "Microsoft.NET.Test.Sdk");

        var (exitCode, output) = Dotnet("restore", KernelProject, "--locked-mode");

        Assert.True(exitCode != 0, output);
        Assert.Contains("NU1004", output);
    }

    [Fact]
    public void Pnpm_lockfile_drift_fails_frozen_install()
    {
        CopyWorkspace();
        AddNpmDependency("minimist", "1.2.5");

        var (exitCode, output) = Pnpm("install", "--frozen-lockfile", "--ignore-scripts");

        Assert.True(exitCode != 0, output);
        Assert.Contains("ERR_PNPM_OUTDATED_LOCKFILE", output);
    }

    // Depends on the live NuGet advisory feed: needs network access, and the result
    // follows the advisory data for GHSA-ghhp-997w-qr28.
    [Fact]
    public void NuGet_critical_advisory_fails_locked_restore_naming_the_package()
    {
        const string package = "System.Text.Encodings.Web";
        var packages = Path.Combine(_copy, "Directory.Packages.props");
        File.WriteAllText(
            packages,
            File.ReadAllText(packages).Replace(
                "</Project>",
                $"  <ItemGroup><PackageVersion Include=\"{package}\" Version=\"4.7.1\" /></ItemGroup>\n</Project>"));
        AddPackage(KernelProject, package);

        // Update the lockfile first, so the locked restore can fail only on the audit.
        var (lockExitCode, lockOutput) = Dotnet(
            "restore", KernelProject, "--force-evaluate", "-p:TreatWarningsAsErrors=false");
        Assert.True(lockExitCode == 0, lockOutput);
        Directory.Delete(Path.Combine(_copy, "src/Gatekeep.Kernel/obj"), recursive: true);

        var (exitCode, output) = Dotnet("restore", KernelProject, "--locked-mode");

        Assert.True(exitCode != 0, output);
        Assert.Contains(output.Split('\n'), l => l.Contains("NU1904") && l.Contains(package));
    }

    // Depends on the live npm advisory feed: needs network access, and the result
    // follows the advisory data for GHSA-xvch-5gv4-984h.
    [Fact]
    public void Pnpm_critical_advisory_fails_audit_naming_the_package()
    {
        CopyWorkspace();
        AddNpmDependency("minimist", "1.2.5");
        var (lockExitCode, lockOutput) = Pnpm("install", "--lockfile-only", "--ignore-scripts");
        Assert.True(lockExitCode == 0, lockOutput);

        var (exitCode, output) = Pnpm("audit", "--audit-level", "critical");

        Assert.True(exitCode != 0, output);
        Assert.Contains("minimist", output);
        Assert.Matches(@"Severity:.*\bcritical\b", output);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_copy, recursive: true);
        }
        catch (IOException)
        {
            // Leaves a temp folder at worst. Cleanup never fails a test.
        }
        catch (UnauthorizedAccessException)
        {
            // As above: a build process may still be releasing a file on Windows.
        }
    }

    private static string Module(string name) => $"src/Modules/{name}/Gatekeep.Modules.{name}.csproj";

    private void CopyTree(string directory)
    {
        foreach (var file in Directory.EnumerateFiles(Path.Combine(Root, directory), "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(Root, file);
            if (!relative.Split(Path.DirectorySeparatorChar).Intersect(BuildOutput).Any())
            {
                CopyFile(relative);
            }
        }
    }

    private void CopyFile(string relative)
    {
        var destination = Path.Combine(_copy, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        File.Copy(Path.Combine(Root, relative), destination);
    }

    private void AddReference(string project, string target)
    {
        var path = Path.Combine(_copy, project);
        var targetPath = Path.GetRelativePath(Path.GetDirectoryName(path)!, Path.Combine(_copy, Module(target)));
        var item = $"  <ItemGroup><ProjectReference Include=\"{targetPath}\" /></ItemGroup>\n</Project>";

        File.WriteAllText(path, File.ReadAllText(path).Replace("</Project>", item));
    }

    private void AddPackage(string project, string package)
    {
        var path = Path.Combine(_copy, project);
        var item = $"  <ItemGroup><PackageReference Include=\"{package}\" /></ItemGroup>\n</Project>";

        File.WriteAllText(path, File.ReadAllText(path).Replace("</Project>", item));
    }

    private void CopyWorkspace()
    {
        foreach (var file in WorkspaceFiles)
        {
            CopyFile(file);
        }

        CopyTree("apps");
        CopyTree("packages");
        CopyTree("tests/browser");
    }

    private void AddNpmDependency(string name, string version)
    {
        var path = Path.Combine(_copy, "packages/api-client/package.json");
        var dependency = $"\"type\": \"module\",\n  \"dependencies\": {{ \"{name}\": \"{version}\" }}";

        File.WriteAllText(path, File.ReadAllText(path).Replace("\"type\": \"module\"", dependency));
    }

    private (int ExitCode, string Output) Build(string project) =>
        Dotnet("build", project, "--nologo", "--disable-build-servers");

    private (int ExitCode, string Output) Dotnet(params string[] arguments) => Run("dotnet", arguments);

    // pnpm is a .cmd shim on Windows, which Process.Start can't launch directly.
    private (int ExitCode, string Output) Pnpm(params string[] arguments) =>
        OperatingSystem.IsWindows()
            ? Run("cmd.exe", ["/c", "pnpm", .. arguments])
            : Run("pnpm", arguments);

    private (int ExitCode, string Output) Run(string fileName, string[] arguments)
    {
        var start = new ProcessStartInfo(fileName)
        {
            WorkingDirectory = _copy,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        // The test host inherits MSBuild settings from `dotnet test`. The child picks its own.
        var inherited = start.Environment.Keys.Where(k => k.StartsWith("MSBUILD", StringComparison.OrdinalIgnoreCase));
        foreach (var key in inherited.ToList())
        {
            start.Environment.Remove(key);
        }

        using var process = Process.Start(start)!;
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();

        if (!process.WaitForExit(CommandTimeout) || !Task.WaitAll([standardOutput, standardError], CommandTimeout))
        {
            process.Kill(entireProcessTree: true);
            Assert.Fail($"{fileName} {string.Join(' ', arguments)} did not finish within {CommandTimeout}.");
        }

        return (process.ExitCode, standardOutput.Result + standardError.Result);
    }
}
