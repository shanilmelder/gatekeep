using System.Text.RegularExpressions;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// AD-26 (Docker only, 2026-11-02): nothing related to Gatekeep runs outside Docker. No
/// file in <c>deploy/</c> or <c>docs/</c> is a systemd unit or names a host path the old
/// native install used, and every command a doc gives is a <c>docker</c> or <c>git</c> command.
/// </summary>
public class DockerOnlyRuleTests
{
    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    /// <summary>Records of what was decided before, kept as they were.</summary>
    private static readonly string[] HistoricalDirectories = ["docs/spikes/", "docs/pr-assets/"];

    private static readonly string[] SkippedDirectories = ["bin", "obj", "node_modules", "secrets"];

    private static readonly Regex HostOnly = new(
        @"/srv/gatekeep|/etc/gatekeep|/etc/systemd|\bsystemctl\b|\bLoadCredential|\bcryptsetup\b|\bdropbear\b|\binitramfs\b|/root/",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // A fence of three or more backticks or tildes, indented or not (as inside a list item),
    // closed by the same fence. The language is the info string's first word.
    private static readonly Regex FencedBlock = new(
        @"^[ \t]*(?<fence>`{3,}|~{3,})[ \t]*(?<info>[^\n]*)\n(?<body>.*?)^[ \t]*\k<fence>[ \t]*$",
        RegexOptions.Multiline | RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly string[] ShellLanguages = ["", "sh", "bash", "shell", "console"];

    private static readonly string[] AllowedCommands = ["docker", "git"];

    /// <summary>
    /// The one exception, per file. The release signing runbook (Story 12.5) is for Esm's
    /// signing machine, which holds the hardware key and runs no part of a Deployment: cosign
    /// must reach the YubiKey, and the Actions runner, crane and gh run beside it. Nothing it
    /// lists runs on a Docker host.
    /// </summary>
    private static readonly Dictionary<string, string[]> SigningMachineCommands = new()
    {
        ["docs/release-signing.md"] = ["cosign", "crane", "gh", "./config.sh", "./run.sh"],
    };

    public static TheoryData<string> CheckedFiles =>
    [
        .. new[] { "deploy", "docs" }
            .SelectMany(d => Files(Path.Combine(Root, d)))
            .Select(f => Path.GetRelativePath(Root, f).Replace('\\', '/'))
            .Where(f => !HistoricalDirectories.Any(h => f.StartsWith(h, StringComparison.Ordinal)))
            .Where(f => !f.EndsWith(".png", StringComparison.OrdinalIgnoreCase)),
    ];

    [Fact]
    public void Install_and_custody_docs_are_checked()
    {
        Assert.Contains("docs/install.md", CheckedFiles.Select(f => (string)f));
        Assert.Contains("docs/key-custody.md", CheckedFiles.Select(f => (string)f));
        Assert.Contains("deploy/compose.yaml", CheckedFiles.Select(f => (string)f));

        // The install's commands sit in fences indented inside list items: they must be seen.
        var install = File.ReadAllText(Path.Combine(Root, "docs", "install.md")).ReplaceLineEndings("\n");
        Assert.True(FencedBlock.Matches(install).Count >= 8, "install.md's command fences aren't all matched.");
    }

    [Theory]
    [MemberData(nameof(CheckedFiles))]
    public void File_is_no_systemd_unit_and_names_no_host_path(string file)
    {
        Assert.False(file.EndsWith(".service", StringComparison.Ordinal), $"{file} is a systemd unit.");

        var match = HostOnly.Match(File.ReadAllText(Path.Combine(Root, file)));
        Assert.False(match.Success, $"{file} names '{match.Value}', which only a host install would use.");
    }

    [Theory]
    [MemberData(nameof(CheckedFiles))]
    public void Every_command_a_doc_gives_runs_through_docker_or_git(string file)
    {
        if (!file.EndsWith(".md", StringComparison.Ordinal))
        {
            return;
        }

        Assert.Empty(NonDockerCommands(File.ReadAllText(Path.Combine(Root, file)), SigningMachineCommands.GetValueOrDefault(file, [])));
    }

    [Fact]
    public void Only_the_signing_runbook_may_give_signing_machine_commands()
    {
        Assert.Equal(["docs/release-signing.md"], SigningMachineCommands.Keys);
        Assert.Contains("docs/release-signing.md", CheckedFiles.Select(f => (string)f));
        Assert.Single(NonDockerCommands("```sh\ncosign piv-tool generate-key\n```\n"));
    }

    [Theory]
    [InlineData("```sh\ndocker compose up -d\n```\n", 0)]
    [InlineData("```\n# a comment\ngit clone https://example.invalid/gatekeep.git\n\n```\n", 0)]
    [InlineData("```bash\n$ docker compose run --rm cli migrate\n```\n", 0)]
    [InlineData("```sh\nsudo systemctl start openbao\n```\n", 1)]
    [InlineData("```console\nbao status\ndotnet test\n```\n", 2)]
    [InlineData("```hcl\nlistener \"unix\" {}\n```\n", 0)]
    [InlineData("Run `sh setup.sh` by hand.", 0)]
    [InlineData("1. Step:\n\n   ```sh\n   sh setup.sh\n   ```\n", 1)]
    [InlineData("- Step:\n\n    ```sh\n    docker compose ps\n    ```\n", 0)]
    [InlineData("~~~sh\nbao status\n~~~\n", 1)]
    [InlineData("~~~~\ndocker compose ps\n~~~~\n", 0)]
    [InlineData("```sh title=install.sh\nsystemctl start x\n```\n", 1)]
    [InlineData("```bash {linenos}\ncurl https://example.invalid\n```\n", 1)]
    [InlineData("```yaml title=compose.yaml\nservices: {}\n```\n", 0)]
    [InlineData("```sh\ndocker compose up\n~~~\nsh oops\n```\n", 2)]
    public void Non_docker_command_detection(string markdown, int expected)
    {
        Assert.Equal(expected, NonDockerCommands(markdown).Count);
    }

    private static List<string> NonDockerCommands(string markdown, string[]? alsoAllowed = null)
    {
        var offenders = new List<string>();
        foreach (Match block in FencedBlock.Matches(markdown.ReplaceLineEndings("\n")))
        {
            var language = block.Groups["info"].Value.Trim().Split([' ', '\t', '{'], 2)[0].ToLowerInvariant();
            if (!ShellLanguages.Contains(language))
            {
                continue;
            }

            var continued = false;
            foreach (var raw in block.Groups["body"].Value.Split('\n'))
            {
                var line = raw.Trim();
                var isContinuation = continued;
                continued = line.EndsWith('\\');
                if (line.Length == 0 || line.StartsWith('#') || isContinuation)
                {
                    continue;
                }

                line = line.StartsWith("$ ", StringComparison.Ordinal) ? line[2..] : line;
                var command = line.Split(' ', 2)[0];
                if (!AllowedCommands.Contains(command) && !(alsoAllowed ?? []).Contains(command))
                {
                    offenders.Add(line);
                }
            }
        }

        return offenders;
    }

    private static IEnumerable<string> Files(string directory)
    {
        var nested = Directory.EnumerateDirectories(directory)
            .Where(d => !SkippedDirectories.Contains(Path.GetFileName(d))
                && !Path.GetFileName(d).StartsWith("secrets-", StringComparison.Ordinal))
            .SelectMany(Files);

        return Directory.EnumerateFiles(directory).Concat(nested);
    }
}
