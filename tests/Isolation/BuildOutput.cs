namespace Gatekeep.Tests.Isolation;

/// <summary>
/// Finds a program in its own output folder, which mirrors this test's, so the solution
/// build provides it. This test's folder is no substitute: the ASP.NET shared framework
/// replaces its <c>Microsoft.Extensions</c> assemblies, which the Cli needs beside it.
/// </summary>
internal static class BuildOutput
{
    public static string AssemblyPath(string project, string assembly)
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (!File.Exists(Path.Combine(root.FullName, "Gatekeep.slnx")))
        {
            root = root.Parent ?? throw new InvalidOperationException("No Gatekeep.slnx above the test output.");
        }

        var output = Path.GetRelativePath(
            Path.Combine(root.FullName, "tests/Isolation"),
            AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

        return Path.Combine(root.FullName, "src", project, output, $"{assembly}.dll");
    }
}
