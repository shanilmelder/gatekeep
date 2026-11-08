using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;

namespace Gatekeep.Tests.Isolation.Stack;

/// <summary>
/// Story 12.5: the signed release path. The release workflow keeps building and signing in
/// separate jobs, the release overlay runs every Gatekeep image by digest, and the pinned
/// key stays on the Docker host, outside every image and volume. The CI rehearsal
/// (<c>deploy/ci/release-check.sh</c>) runs the scripts themselves.
/// </summary>
public sealed class ReleaseConfigTests
{
    private const string Verifier = "release-tools";
    private const string TrustFile = "/trust/release-signing.pub";

    private static readonly Regex DigestReference = new(@"^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$");

    private static readonly Lazy<JsonElement> Base = new(() =>
        ComposeConfigTests.Config("deploy/compose.yaml", "--profile", "tools", "--profile", "setup"));

    // Declared before Overlay, which reads them: static fields initialize in textual order.
    private static readonly string[] OverlayFiles = ["deploy/compose.yaml", "deploy/compose.release.yaml"];
    private static readonly string[] OverlayProfiles = ["--profile", "tools", "--profile", "setup", "--profile", "release"];

    private static readonly Lazy<JsonElement> Overlay = new(() =>
        ComposeConfigTests.Config(OverlayFiles, OverlayProfiles, SampleEnvironment()));

    private static readonly Lazy<string[]> Workflow = new(() =>
        File.ReadAllLines(Path.Combine(Repository.Root, ".github", "workflows", "release.yml")));

    /// <summary>
    /// Every image <c>deploy/compose.yaml</c> builds, named by its Dockerfile, as its service is: the
    /// audit shipper builds the cli image too (Story 1.30), so it adds no image of its own.
    /// </summary>
    private static List<string> BuiltServices => Base.Value.GetProperty("services").EnumerateObject()
        .Where(s => s.Value.TryGetProperty("build", out _))
        .Select(s => Path.GetFileName(s.Value.GetProperty("build").GetProperty("dockerfile").GetString()!)
            .Replace(".Dockerfile", string.Empty, StringComparison.Ordinal))
        .Distinct(StringComparer.Ordinal)
        .Order()
        .ToList();

    /// <summary>The release images <c>deploy/release/build.sh</c> builds by default.</summary>
    private static List<string> ReleaseServices
    {
        get
        {
            var script = File.ReadAllText(Path.Combine(Repository.Root, "deploy", "release", "build.sh"));
            var match = Regex.Match(script, "(?m)^DEFAULT_SERVICES=\"(?<list>[^\"]+)\"");
            Assert.True(match.Success, "build.sh has no DEFAULT_SERVICES line.");
            return match.Groups["list"].Value.Split(' ', StringSplitOptions.RemoveEmptyEntries).Order().ToList();
        }
    }

    [Fact]
    public void Release_images_are_every_built_service_and_the_verifier()
    {
        // A newly built service fails here until it's part of the release.
        Assert.Equal(BuiltServices.Append(Verifier).Order(), ReleaseServices);

        // publish.sh requires exactly this list outside the rehearsal.
        var publish = File.ReadAllText(Path.Combine(Repository.Root, "deploy", "release", "publish.sh"));
        var published = Regex.Match(publish, "(?m)^RELEASE_SERVICES=\"(?<list>[^\"]+)\"");
        Assert.True(published.Success, "publish.sh has no RELEASE_SERVICES line.");
        Assert.Equal(ReleaseServices, published.Groups["list"].Value.Split(' ', StringSplitOptions.RemoveEmptyEntries).Order());
        foreach (var service in ReleaseServices)
        {
            Assert.True(File.Exists(Path.Combine(Repository.Root, "deploy", "docker", $"{service}.Dockerfile")), $"No Dockerfile for {service}.");
        }
    }

    [Fact]
    public void Overlay_runs_every_built_service_and_setup_tool_by_digest_with_no_build()
    {
        var services = Overlay.Value.GetProperty("services");
        var environment = SampleEnvironment();

        foreach (var name in BuiltServices.Concat(["keygen", "openbao-setup", "openbao-audit-shipper"]))
        {
            var service = services.GetProperty(name);
            Assert.False(service.TryGetProperty("build", out _), $"{name} still builds from source.");

            var image = service.GetProperty("image").GetString()!;
            Assert.Matches(DigestReference, image);
            var source = name switch
            {
                "keygen" or "openbao-setup" => "openbao",
                // Story 1.30: the shipper runs the cli image.
                "openbao-audit-shipper" => "cli",
                _ => name,
            };
            Assert.Equal(environment[Variable(source)], image);
        }

        // Nothing in the release stack runs by tag or builds.
        foreach (var service in services.EnumerateObject())
        {
            Assert.False(service.Value.TryGetProperty("build", out _), $"{service.Name} builds.");
            Assert.Contains("@sha256:", service.Value.GetProperty("image").GetString()!, StringComparison.Ordinal);
        }
    }

    public static TheoryData<string> ReleaseVariables => [.. ReleaseServices.Select(Variable)];

    [Theory]
    [MemberData(nameof(ReleaseVariables))]
    public void Overlay_refuses_a_missing_image_variable(string variable)
    {
        var environment = SampleEnvironment();
        environment.Remove(variable);

        var (exitCode, _, error) = ComposeConfigTests.TryConfig(OverlayFiles, OverlayProfiles, environment);

        Assert.NotEqual(0, exitCode);
        Assert.Contains(variable, error, StringComparison.Ordinal);
    }

    [Fact]
    public void Release_verify_is_hardened_and_mounts_only_the_pinned_key_read_only()
    {
        var verify = Overlay.Value.GetProperty("services").GetProperty("release-verify");

        Assert.Equal(["release"], ComposeConfigTests.Strings(verify, "profiles"));
        Assert.Matches(DigestReference, verify.GetProperty("image").GetString()!);
        Assert.Equal(SampleEnvironment()[Variable(Verifier)], verify.GetProperty("image").GetString());

        var uid = verify.GetProperty("user").GetString()!.Split(':')[0];
        Assert.True(int.TryParse(uid, out var id) && id > 0, $"release-verify runs as '{uid}'.");

        // The image's own user, and no other service's.
        var toolsUser = Assert.Single(
            File.ReadAllLines(Path.Combine(Repository.Root, "deploy", "docker", "release-tools.Dockerfile")),
            l => l.StartsWith("USER ", StringComparison.Ordinal))[5..].Trim();
        Assert.Equal(toolsUser, verify.GetProperty("user").GetString());
        foreach (var service in Overlay.Value.GetProperty("services").EnumerateObject().Where(s => s.Name != "release-verify"))
        {
            if (service.Value.TryGetProperty("user", out var other))
            {
                Assert.NotEqual(uid, other.GetString()!.Split(':')[0]);
            }
        }

        foreach (var dockerfile in Directory.EnumerateFiles(Path.Combine(Repository.Root, "deploy", "docker"), "*.Dockerfile")
            .Where(f => !f.EndsWith("release-tools.Dockerfile", StringComparison.Ordinal)))
        {
            foreach (var line in File.ReadAllLines(dockerfile).Where(l => l.StartsWith("USER ", StringComparison.Ordinal)))
            {
                Assert.NotEqual(uid, line[5..].Trim().Split(':')[0]);
            }
        }

        // It runs verify.sh, whose default key is the mounted one: no GATEKEEP_TRUST_KEY is set.
        Assert.Equal(["sh", "/opt/gatekeep/release/verify.sh"], ComposeConfigTests.Strings(verify, "entrypoint"));
        var script = File.ReadAllText(Path.Combine(Repository.Root, "deploy", "release", "verify.sh"));
        var key = Regex.Match(script, @"(?m)^KEY=""\$\{GATEKEEP_TRUST_KEY:-(?<key>[^}]+)\}""$");
        Assert.True(key.Success, "verify.sh has no default KEY line.");
        Assert.Equal(TrustFile, key.Groups["key"].Value);
        Assert.True(verify.GetProperty("read_only").GetBoolean());
        Assert.Equal(["ALL"], ComposeConfigTests.Strings(verify, "cap_drop"));
        Assert.Empty(ComposeConfigTests.Strings(verify, "cap_add"));
        Assert.Contains("no-new-privileges:true", ComposeConfigTests.Strings(verify, "security_opt"));
        Assert.False(verify.TryGetProperty("privileged", out var privileged) && privileged.GetBoolean());
        Assert.True(verify.GetProperty("pids_limit").GetInt64() > 0);
        Assert.Equal("json-file", verify.GetProperty("logging").GetProperty("driver").GetString());
        Assert.True(verify.GetProperty("logging").GetProperty("options").TryGetProperty("max-size", out _));
        Assert.False(verify.TryGetProperty("secrets", out _), "release-verify gets a Compose secret.");
        Assert.False(verify.TryGetProperty("ports", out _), "release-verify publishes a port.");

        // Its only mount is the pinned key, read-only, from the trust directory on the host.
        var mount = Assert.Single(verify.GetProperty("volumes").EnumerateArray());
        Assert.Equal("bind", mount.GetProperty("type").GetString());
        Assert.Equal(TrustFile, mount.GetProperty("target").GetString());
        Assert.True(mount.GetProperty("read_only").GetBoolean(), "The pinned key is writable.");
        var source = Normalized(mount.GetProperty("source").GetString()!);
        Assert.EndsWith("/deploy/trust/release-signing.pub", source, StringComparison.Ordinal);

        // Its environment is the image references and nothing else.
        foreach (var variable in verify.GetProperty("environment").EnumerateObject())
        {
            Assert.Matches("^GATEKEEP_[A-Z0-9_]+_IMAGE$", variable.Name);
            Assert.Matches(DigestReference, variable.Value.GetString()!);
        }

        Assert.Equal(
            ReleaseServices.Select(Variable).Order(),
            verify.GetProperty("environment").EnumerateObject().Select(v => v.Name).Order());
    }

    [Fact]
    public void Only_release_verify_has_egress_on_the_registry_network()
    {
        var networks = Overlay.Value.GetProperty("networks");
        var services = Overlay.Value.GetProperty("services");

        // The overlay adds egress to no network of the base stack (Caddy's edge keeps its own),
        // and adds no network but registry.
        static bool IsInternal(JsonElement network) =>
            network.TryGetProperty("internal", out var isInternal) && isInternal.GetBoolean();

        var baseNetworks = Base.Value.GetProperty("networks");
        foreach (var network in networks.EnumerateObject().Where(n => n.Name != "registry"))
        {
            Assert.True(baseNetworks.TryGetProperty(network.Name, out var original), $"The overlay adds network {network.Name}.");
            Assert.Equal(IsInternal(original), IsInternal(network.Value));
        }

        Assert.False(networks.GetProperty("registry").TryGetProperty("internal", out var registryInternal) && registryInternal.GetBoolean());
        var members = services.EnumerateObject()
            .Where(s => s.Value.TryGetProperty("networks", out var n) && n.TryGetProperty("registry", out _))
            .Select(s => s.Name)
            .ToList();
        Assert.Equal(["release-verify"], members);
        Assert.Equal(["registry"], services.GetProperty("release-verify").GetProperty("networks").EnumerateObject().Select(n => n.Name));

        // The base stack has no registry network: it exists only in the overlay.
        Assert.False(Base.Value.GetProperty("networks").TryGetProperty("registry", out _));
    }

    [Fact]
    public void Pinned_key_is_in_no_image_volume_or_repository()
    {
        foreach (var dockerfile in Directory.EnumerateFiles(Path.Combine(Repository.Root, "deploy", "docker"), "*.Dockerfile"))
        {
            Assert.DoesNotMatch(@"(?im)^\s*(COPY|ADD)\b.*\btrust\b", File.ReadAllText(dockerfile));
        }

        Assert.Contains("deploy/trust/", File.ReadAllText(Path.Combine(Repository.Root, ".dockerignore")));
        Assert.Contains("deploy/trust/", File.ReadAllText(Path.Combine(Repository.Root, "deploy", "docker", "tests.Dockerfile.dockerignore")));
        var gitignore = File.ReadAllText(Path.Combine(Repository.Root, ".gitignore"));
        Assert.Contains("/deploy/trust/", gitignore);
        Assert.Contains("/deploy/release.env", gitignore);

        // No named volume is the trust directory, and only release-verify binds it.
        foreach (var volume in Overlay.Value.GetProperty("volumes").EnumerateObject())
        {
            Assert.DoesNotContain("trust", volume.Name, StringComparison.OrdinalIgnoreCase);
        }

        foreach (var service in Overlay.Value.GetProperty("services").EnumerateObject().Where(s => s.Name != "release-verify"))
        {
            Assert.DoesNotContain(
                ComposeConfigTests.Volumes(service.Value),
                v => Normalized(v.Source).Contains("/deploy/trust", StringComparison.Ordinal) || v.Target.StartsWith("/trust", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void Release_tools_image_is_pinned_and_runs_non_root()
    {
        const string dockerfile = "deploy/docker/release-tools.Dockerfile";
        ComposeConfigTests.AssertFromLinesPinned(dockerfile);

        var lines = File.ReadAllLines(Path.Combine(Repository.Root, dockerfile));
        var stages = lines
            .Select(l => Regex.Match(l, @"^FROM\s+\S+\s+AS\s+(?<name>\S+)", RegexOptions.IgnoreCase))
            .Where(m => m.Success)
            .Select(m => m.Groups["name"].Value)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Every tool comes from a pinned stage, never straight from a tag.
        foreach (var line in lines.Where(l => l.StartsWith("COPY --from=", StringComparison.Ordinal)))
        {
            var from = Regex.Match(line, @"--from=(?<from>\S+)").Groups["from"].Value;
            Assert.True(stages.Contains(from) || from.Contains("@sha256:", StringComparison.Ordinal), $"'{line}' copies from an unpinned image.");
        }

        var user = Assert.Single(lines, l => l.StartsWith("USER ", StringComparison.Ordinal));
        Assert.NotEqual("0", user[5..].Split(':')[0].Trim());

        // The rehearsal's own pinned images.
        Assert.Matches(@"(?m)^BUILDKIT=moby/buildkit:[^@\s]+@sha256:[0-9a-f]{64}$", File.ReadAllText(Path.Combine(Repository.Root, "deploy", "release", "build.sh")));
        Assert.Matches(@"(?m)^REGISTRY_IMAGE=registry:[^@\s]+@sha256:[0-9a-f]{64}$", File.ReadAllText(Path.Combine(Repository.Root, "deploy", "ci", "release-check.sh")));
    }

    [Fact]
    public void Release_runs_only_from_a_version_tag_with_no_default_permissions()
    {
        var text = string.Join('\n', Code(Workflow.Value));

        Assert.Matches(@"(?m)^on:\n  push:\n    tags: \[""v\*""\]$", text);
        Assert.DoesNotContain("pull_request", text, StringComparison.Ordinal);
        Assert.DoesNotContain("branches:", text, StringComparison.Ordinal);
        Assert.DoesNotContain("workflow_dispatch", text, StringComparison.Ordinal);
        Assert.Matches(@"(?m)^permissions: \{\}$", text);
        Assert.Equal(["build", "sign"], Jobs().Keys.Order());
    }

    [Fact]
    public void Build_job_holds_no_secret_and_has_a_read_only_token()
    {
        var build = Jobs()["build"];
        var text = string.Join('\n', build);

        Assert.Equal(["contents: read"], Permissions(build));
        Assert.DoesNotContain("secrets.", text, StringComparison.Ordinal);
        Assert.DoesNotContain("vars.", text, StringComparison.Ordinal);
        Assert.DoesNotContain("github.token", text, StringComparison.Ordinal);
        Assert.DoesNotContain("environment:", text, StringComparison.Ordinal);
        Assert.DoesNotContain("id-token", text, StringComparison.Ordinal);
        Assert.DoesNotMatch(@"\blogin\b", text);
        Assert.DoesNotContain("publish.sh", text, StringComparison.Ordinal);
        Assert.DoesNotContain("cosign", text, StringComparison.Ordinal);
        Assert.Matches(@"(?m)^    runs-on: ubuntu-latest$", text);

        // It runs the gates, then build.sh, and hands over only an artifact.
        Assert.Contains("docker compose -f deploy/compose.dev.yaml run --rm --build tests", text, StringComparison.Ordinal);
        Assert.Contains("docker compose -f deploy/compose.dev.yaml run --rm --build stack", text, StringComparison.Ordinal);
        Assert.Contains("/opt/gatekeep/release/build.sh", text, StringComparison.Ordinal);
        Assert.Contains("actions/upload-artifact@", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Sign_job_downloads_the_artifact_the_build_job_uploads()
    {
        var uploaded = ArtifactName(Jobs()["build"], "actions/upload-artifact@");
        Assert.False(string.IsNullOrEmpty(uploaded), "The build job uploads an unnamed artifact.");
        Assert.Equal(uploaded, ArtifactName(Jobs()["sign"], "actions/download-artifact@"));
    }

    [Fact]
    public void Sign_job_is_on_its_own_hosted_runner_tag_gated_and_builds_nothing()
    {
        var sign = Jobs()["sign"];
        var text = string.Join('\n', sign);

        Assert.Contains("    needs: build", sign);
        Assert.Contains("    runs-on: ubuntu-latest", sign);
        Assert.Contains("    environment: release-signing", sign);
        Assert.Equal(["contents: write", "packages: write"], Permissions(sign).Order());

        // The secrets are the job's own token and the encrypted key with its password. The key
        // is named by reference, and reaches only the step that runs publish.sh.
        Assert.All(
            Regex.Matches(text, @"secrets\.(?<name>[A-Za-z0-9_]+)"),
            m => Assert.Contains(m.Groups["name"].Value, new[] { "GITHUB_TOKEN", "COSIGN_PRIVATE_KEY", "COSIGN_PASSWORD" }));
        Assert.Contains("      GATEKEEP_SIGNING_KEY: env://COSIGN_PRIVATE_KEY", sign);
        var signing = Step(sign, "Push, sign and attest each image");
        Assert.Contains("          COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}", signing);
        Assert.Contains("          COSIGN_PASSWORD: ${{ secrets.COSIGN_PASSWORD }}", signing);
        Assert.Contains("sh deploy/release/publish.sh", string.Join('\n', signing), StringComparison.Ordinal);
        var outside = string.Join('\n', sign.Except(signing));
        Assert.DoesNotContain("secrets.COSIGN_", outside, StringComparison.Ordinal);

        Assert.Contains("sh deploy/release/publish.sh", text, StringComparison.Ordinal);
        Assert.Contains("actions/download-artifact@", text, StringComparison.Ordinal);
        foreach (var build in new[] { "docker build", "docker compose", "buildx", "build.sh", "dotnet", "pnpm", "npm ", "syft" })
        {
            Assert.DoesNotContain(build, text, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Sign_job_installs_the_cosign_and_crane_the_release_tools_image_pins()
    {
        // The hosted runner has neither tool: the sign job copies them out of the very images,
        // by the very digests, that release-tools.Dockerfile builds from, so the job and the
        // rehearsal sign with the same binaries, and bumping one without the other fails here.
        var dockerfile = File.ReadAllLines(Path.Combine(Repository.Root, "deploy", "docker", "release-tools.Dockerfile"));
        var install = string.Join('\n', Step(Jobs()["sign"], "Install the pinned cosign and crane"));

        foreach (var tool in new[] { "cosign", "crane" })
        {
            var from = Assert.Single(dockerfile, l => Regex.IsMatch(l, $@"^FROM\s+\S+\s+AS\s+{tool}$"));
            var image = from.Split(' ', StringSplitOptions.RemoveEmptyEntries)[1];
            Assert.Matches(@"^[a-z0-9./-]+:v[0-9.]+@sha256:[0-9a-f]{64}$", image);
            Assert.Contains($"\"{tool} {image}\"", install, StringComparison.Ordinal);
        }

        Assert.Contains("docker cp", install, StringComparison.Ordinal);
        Assert.Contains(">> \"$GITHUB_PATH\"", install, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_action_is_pinned_by_commit()
    {
        foreach (var workflow in Directory.EnumerateFiles(Path.Combine(Repository.Root, ".github", "workflows"), "*.yml"))
        {
            foreach (var line in Code(File.ReadAllLines(workflow)).Where(l => Regex.IsMatch(l, @"^\s*-?\s*uses:")))
            {
                Assert.Matches(@"uses:\s+[\w.-]+/[\w./-]+@[0-9a-f]{40}(\s|$)", line);
            }
        }
    }

    [Fact]
    public void Signing_and_verifying_use_the_pinned_key_alone()
    {
        var publish = File.ReadAllText(Path.Combine(Repository.Root, "deploy", "release", "publish.sh"));
        var verify = File.ReadAllText(Path.Combine(Repository.Root, "deploy", "release", "verify.sh"));

        Assert.Matches(@"\$COSIGN sign [^\n]*--tlog-upload=false", publish);
        Assert.Matches(@"\$COSIGN attest [^\n]*--tlog-upload=false", publish);
        Assert.Contains("--type spdxjson", publish, StringComparison.Ordinal);
        Assert.Matches(@"\$COSIGN verify --key [^\n]*--insecure-ignore-tlog=true", verify);
        Assert.Matches(@"\$COSIGN verify-attestation --key [^\n]*--insecure-ignore-tlog=true --type spdxjson", verify);
        Assert.DoesNotContain("--identity-token", publish, StringComparison.Ordinal);
        Assert.DoesNotContain("--certificate-identity", verify, StringComparison.Ordinal);
    }

    private static string Variable(string service) => $"GATEKEEP_{service.ToUpperInvariant().Replace('-', '_')}_IMAGE";

    private static Dictionary<string, string> SampleEnvironment() =>
        ReleaseServices.ToDictionary(
            Variable,
            s => $"ghcr.io/example/gatekeep-{s}@sha256:{Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(s)))}");

    private static string Normalized(string path) => path.Replace('\\', '/');

    /// <summary>Lines with comments and blank lines removed.</summary>
    private static IEnumerable<string> Code(IEnumerable<string> lines) =>
        lines.Where(l => l.Trim().Length > 0 && !l.TrimStart().StartsWith('#'));

    /// <summary>The release workflow's jobs, each as its code lines.</summary>
    private static Dictionary<string, List<string>> Jobs()
    {
        var jobs = new Dictionary<string, List<string>>();
        List<string>? current = null;
        var inJobs = false;
        foreach (var line in Code(Workflow.Value))
        {
            if (!line.StartsWith(' '))
            {
                inJobs = line.TrimEnd() == "jobs:";
                current = null;
                continue;
            }

            if (!inJobs)
            {
                continue;
            }

            var header = Regex.Match(line, @"^  (?<name>[A-Za-z0-9_-]+):\s*$");
            if (header.Success)
            {
                current = [];
                jobs[header.Groups["name"].Value] = current;
            }
            else
            {
                current?.Add(line);
            }
        }

        return jobs;
    }

    /// <summary>The <c>name:</c> given to the step that uses <paramref name="action"/>.</summary>
    private static string? ArtifactName(List<string> job, string action)
    {
        var start = job.FindIndex(l => l.Contains(action, StringComparison.Ordinal));
        Assert.True(start >= 0, $"The job doesn't use {action}.");
        return job.Skip(start + 1)
            .TakeWhile(l => !Regex.IsMatch(l, @"^\s*- "))
            .Select(l => Regex.Match(l, @"^\s+name:\s*(?<name>\S+)\s*$"))
            .FirstOrDefault(m => m.Success)?.Groups["name"].Value;
    }

    /// <summary>The lines of the step named <paramref name="name"/>, from its <c>- name:</c> to the next step.</summary>
    private static List<string> Step(List<string> job, string name)
    {
        var start = job.IndexOf($"      - name: {name}");
        Assert.True(start >= 0, $"The job has no step named {name}.");
        return [job[start], .. job.Skip(start + 1).TakeWhile(l => !l.StartsWith("      - ", StringComparison.Ordinal))];
    }

    /// <summary>The <c>permissions:</c> entries of a job, as "scope: level".</summary>
    private static List<string> Permissions(List<string> job)
    {
        var start = job.IndexOf("    permissions:");
        Assert.True(start >= 0, "The job sets no permissions of its own.");
        return job.Skip(start + 1).TakeWhile(l => l.StartsWith("      ", StringComparison.Ordinal)).Select(l => l.Trim()).ToList();
    }
}
