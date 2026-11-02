using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;

namespace Gatekeep.Tests.Isolation.Stack;

/// <summary>
/// Story 1.10: the Compose definition as Compose itself resolves it (<c>docker compose config</c>),
/// so anchors, merges and defaults are applied before anything is checked.
/// </summary>
public sealed class ComposeConfigTests
{
    private static readonly string[] HardenedServices = ["hosted", "admin", "worker", "cli", "postgres", "postgres-passwords", "openbao"];
    private static readonly string[] Hosts = ["hosted", "admin", "worker"];

    private static readonly Lazy<JsonElement> Stack = new(() => Config("deploy/compose.yaml", "--profile", "tools", "--profile", "setup"));

    private static JsonElement Services => Stack.Value.GetProperty("services");

    public static TheoryData<string> HardenedServiceNames => [.. HardenedServices];

    [Theory]
    [MemberData(nameof(HardenedServiceNames))]
    public void Service_is_non_root_read_only_with_no_capabilities(string name)
    {
        var service = Services.GetProperty(name);

        var uid = service.GetProperty("user").GetString()!.Split(':')[0];
        Assert.True(int.TryParse(uid, out var id) && id > 0, $"{name} runs as '{uid}'.");
        Assert.True(service.GetProperty("read_only").GetBoolean(), $"{name} has a writable root filesystem.");
        Assert.Equal(["ALL"], Strings(service, "cap_drop"));
        Assert.Empty(Strings(service, "cap_add"));
        Assert.Contains("no-new-privileges:true", Strings(service, "security_opt"));
        Assert.False(service.TryGetProperty("privileged", out var privileged) && privileged.GetBoolean());
        Assert.False(service.TryGetProperty("network_mode", out var mode) && mode.GetString() == "host");
        Assert.False(service.TryGetProperty("pid", out _));
    }

    [Fact]
    public void No_service_mounts_the_Docker_socket()
    {
        foreach (var service in Services.EnumerateObject())
        {
            foreach (var volume in Volumes(service.Value))
            {
                Assert.DoesNotContain("docker.sock", volume.Source, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("docker.sock", volume.Target, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    [Fact]
    public void No_service_publishes_a_port_and_health_ports_stay_private()
    {
        foreach (var service in Services.EnumerateObject())
        {
            Assert.False(
                service.Value.TryGetProperty("ports", out var ports) && ports.GetArrayLength() > 0,
                $"{service.Name} publishes a port.");
        }

        // Each host's healthcheck asks its own private port, the default health port.
        foreach (var host in Hosts)
        {
            var service = Services.GetProperty(host);
            Assert.Contains("--health-probe", Strings(service.GetProperty("healthcheck"), "test"));
            Assert.False(service.TryGetProperty("environment", out var environment)
                && environment.TryGetProperty("Gatekeep__HealthPort", out _), $"{host} moves its health port.");
        }
    }

    [Fact]
    public void Every_network_is_internal_and_each_host_has_its_own()
    {
        foreach (var network in Stack.Value.GetProperty("networks").EnumerateObject())
        {
            Assert.True(
                network.Value.TryGetProperty("internal", out var isInternal) && isInternal.GetBoolean(),
                $"Network {network.Name} has egress.");
        }

        var networks = Hosts.Select(h => Services.GetProperty(h).GetProperty("networks").EnumerateObject().Select(n => n.Name).Single()).ToList();
        Assert.Equal(Hosts.Length, networks.Distinct().Count());
    }

    [Fact]
    public void OpenBao_has_no_network_and_gets_the_Master_Key_only_as_a_read_only_secret()
    {
        var openbao = Services.GetProperty("openbao");

        Assert.Equal("none", openbao.GetProperty("network_mode").GetString());
        Assert.True(openbao.GetProperty("read_only").GetBoolean());
        Assert.Equal(["ALL"], Strings(openbao, "cap_drop"));
        Assert.NotEqual("0", openbao.GetProperty("user").GetString()!.Split(':')[0]);
        Assert.False(openbao.TryGetProperty("environment", out _));
        Assert.Contains(
            openbao.GetProperty("secrets").EnumerateArray(),
            s => s.GetProperty("source").GetString() == "master_key" && s.GetProperty("target").GetString() == "/run/secrets/master_key");

        // Only named volumes: no bind mount, so the secrets directory can't be reached as a volume.
        Assert.All(Volumes(openbao), v => Assert.Equal("volume", v.Type));
    }

    [Fact]
    public void Master_Key_is_a_file_secret_only_OpenBao_receives_and_is_on_no_volume()
    {
        var file = Normalized(Stack.Value.GetProperty("secrets").GetProperty("master_key").GetProperty("file").GetString()!);
        Assert.EndsWith("/secrets/master/master-key", file, StringComparison.Ordinal);
        var secretsDirectory = file[..^"/master/master-key".Length];

        // Each one-shot tool binds only the secrets subdirectories it writes.
        var expected = new Dictionary<string, string[]>
        {
            ["keygen"] = ["/master"],
            ["passwords"] = ["/postgres"],
            ["openbao-setup"] = ["/approle", "/recovery"],
        };

        foreach (var service in Services.EnumerateObject())
        {
            var receives = service.Value.TryGetProperty("secrets", out var secrets)
                && secrets.EnumerateArray().Any(s => s.GetProperty("source").GetString() == "master_key");
            Assert.Equal(service.Name == "openbao", receives);

            var bound = Volumes(service.Value)
                .Where(v => v.Type == "bind" && Normalized(v.Source).StartsWith(secretsDirectory, StringComparison.Ordinal))
                .Select(v => Normalized(v.Source)[secretsDirectory.Length..])
                .Order()
                .ToList();
            Assert.Equal(expected.GetValueOrDefault(service.Name, []), bound);
            if (bound.Count > 0)
            {
                Assert.Equal(["setup"], Strings(service.Value, "profiles"));
                Assert.Equal("none", service.Value.GetProperty("network_mode").GetString());
            }
        }

        // No named volume is the secrets directory.
        foreach (var volume in Stack.Value.GetProperty("volumes").EnumerateObject())
        {
            Assert.DoesNotContain("secret", volume.Name, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void Every_secret_is_a_file_and_no_environment_value_holds_one()
    {
        foreach (var secret in Stack.Value.GetProperty("secrets").EnumerateObject())
        {
            Assert.True(secret.Value.TryGetProperty("file", out _), $"Secret {secret.Name} isn't a file.");
            Assert.False(secret.Value.TryGetProperty("environment", out _), $"Secret {secret.Name} comes from the environment.");
            Assert.False(secret.Value.TryGetProperty("content", out _), $"Secret {secret.Name} is written in the Compose file.");
        }

        var credential = new Regex(@"(?i)password\s*=|pwd\s*=|secret_id\s*=|token\s*=");
        foreach (var service in Services.EnumerateObject())
        {
            if (!service.Value.TryGetProperty("environment", out var environment))
            {
                continue;
            }

            foreach (var variable in environment.EnumerateObject())
            {
                var value = variable.Value.GetString() ?? string.Empty;
                Assert.False(credential.IsMatch(value), $"{service.Name} {variable.Name} holds a credential.");
                if (Regex.IsMatch(variable.Name, "(?i)password|secret|token|key") && !variable.Name.EndsWith("_FILE", StringComparison.Ordinal))
                {
                    Assert.StartsWith("/run/secrets/", value);
                }
            }
        }
    }

    [Fact]
    public void Every_image_is_pinned_by_digest_or_built_here_from_pinned_bases()
    {
        var built = Services.EnumerateObject()
            .Where(s => s.Value.TryGetProperty("build", out _))
            .Select(s => s.Value.GetProperty("image").GetString())
            .ToHashSet();

        foreach (var service in Services.EnumerateObject())
        {
            if (service.Value.TryGetProperty("build", out var build))
            {
                var dockerfile = build.GetProperty("dockerfile").GetString()!;
                Assert.StartsWith("deploy/docker/", dockerfile);
                AssertFromLinesPinned(dockerfile);
            }
            else
            {
                // Either pinned, or an image another service here builds, such as the setup tools'.
                var image = service.Value.GetProperty("image").GetString()!;
                Assert.True(image.Contains("@sha256:", StringComparison.Ordinal) || built.Contains(image), $"{service.Name} uses {image}.");
            }
        }
    }

    [Fact]
    public void No_image_build_copies_a_secret()
    {
        foreach (var dockerfile in Directory.EnumerateFiles(Path.Combine(Repository.Root, "deploy", "docker"), "*.Dockerfile"))
        {
            var text = File.ReadAllText(dockerfile);
            Assert.DoesNotMatch(@"(?im)^\s*(COPY|ADD)\b.*\bsecrets\b", text);
        }

        Assert.Contains("deploy/secrets*/", File.ReadAllText(Path.Combine(Repository.Root, ".dockerignore")));
        Assert.Contains("deploy/secrets/", File.ReadAllText(Path.Combine(Repository.Root, "deploy", "docker", "tests.Dockerfile.dockerignore")));
    }

    [Fact]
    public void Only_the_test_services_get_the_Docker_socket()
    {
        var tests = Config("deploy/compose.test.yaml", "--profile", "stack").GetProperty("services");

        Assert.Equal(["stack", "tests"], tests.EnumerateObject().Select(s => s.Name).Order());
        foreach (var service in tests.EnumerateObject())
        {
            Assert.Contains(Volumes(service.Value), v => v.Target == "/var/run/docker.sock");
        }
    }

    [Fact]
    public void Every_service_has_a_process_limit_and_rotated_logs()
    {
        foreach (var service in Services.EnumerateObject())
        {
            Assert.True(service.Value.TryGetProperty("pids_limit", out var pids) && pids.GetInt64() > 0, $"{service.Name} has no pids_limit.");
            var logging = service.Value.GetProperty("logging");
            Assert.Equal("json-file", logging.GetProperty("driver").GetString());
            Assert.True(logging.GetProperty("options").TryGetProperty("max-size", out _), $"{service.Name} logs grow without bound.");
            Assert.True(logging.GetProperty("options").TryGetProperty("max-file", out _), $"{service.Name} logs grow without bound.");
        }
    }

    [Fact]
    public void Each_service_gets_exactly_its_own_secrets()
    {
        string[] passwords = ["postgres_password", "gk_migrator_password", "gk_hosted_password", "gk_admin_password",
            "gk_worker_password", "gk_dispatch_password", "gk_sealer_password", "gk_retention_password"];
        var expected = new Dictionary<string, string[]>
        {
            ["postgres"] = passwords,
            ["postgres-passwords"] = passwords,
            ["openbao"] = ["master_key"],
            ["hosted"] = ["gk_hosted_password", "openbao_hosted_role_id", "openbao_hosted_secret_id"],
            ["admin"] = ["gk_admin_password", "openbao_admin_role_id", "openbao_admin_secret_id"],
            ["worker"] = ["gk_dispatch_password", "gk_worker_password", "gk_sealer_password", "gk_retention_password",
                "openbao_worker_role_id", "openbao_worker_secret_id"],
            ["cli"] = ["gk_migrator_password", "openbao_cli_role_id", "openbao_cli_secret_id"],
        };

        foreach (var service in Services.EnumerateObject())
        {
            var actual = service.Value.TryGetProperty("secrets", out var secrets)
                ? secrets.EnumerateArray().Select(s => s.GetProperty("source").GetString()!).Order().ToList()
                : [];
            Assert.Equal(expected.GetValueOrDefault(service.Name, []).Order(), actual);
        }
    }

    [Fact]
    public void Networks_are_joined_only_by_the_services_meant_to_share_them()
    {
        var expected = new Dictionary<string, string[]>
        {
            ["hosted"] = ["hosted", "postgres"],
            ["admin"] = ["admin", "postgres"],
            ["worker"] = ["postgres", "worker"],
            ["tools"] = ["cli", "postgres", "postgres-passwords"],
        };

        var members = Services.EnumerateObject()
            .Where(s => s.Value.TryGetProperty("networks", out _))
            .SelectMany(s => s.Value.GetProperty("networks").EnumerateObject().Select(n => (Network: n.Name, Service: s.Name)))
            .GroupBy(m => m.Network)
            .ToDictionary(g => g.Key, g => g.Select(m => m.Service).Order().ToList());

        Assert.Equal(expected.Keys.Order(), members.Keys.Order());
        foreach (var (network, services) in expected)
        {
            Assert.Equal(services.Order(), members[network]);
        }

        // Everything else joins no network at all.
        foreach (var service in Services.EnumerateObject().Where(s => !s.Value.TryGetProperty("networks", out _)))
        {
            Assert.Equal("none", service.Value.GetProperty("network_mode").GetString());
        }
    }

    [Fact]
    public void Each_uid_is_unique_and_the_same_in_every_file_that_names_it()
    {
        var setup = File.ReadAllText(Path.Combine(Repository.Root, "deploy", "openbao", "setup.sh"));
        var keygen = File.ReadAllText(Path.Combine(Repository.Root, "deploy", "openbao", "generate-master-key.sh"));
        var roles = new (string Service, string Dockerfile, string AppRole)[]
        {
            ("hosted", "hosted.Dockerfile", "host-hosted"),
            ("admin", "admin.Dockerfile", "host-admin"),
            ("worker", "worker.Dockerfile", "host-worker"),
            ("cli", "cli.Dockerfile", "cli"),
        };

        var users = new List<string>();
        foreach (var (service, dockerfile, appRole) in roles)
        {
            var user = Services.GetProperty(service).GetProperty("user").GetString()!;
            var uid = user.Split(':')[0];
            users.Add(uid);

            var image = File.ReadAllText(Path.Combine(Repository.Root, "deploy", "docker", dockerfile));
            Assert.Matches($@"(?m)^USER {Regex.Escape(user)}\s*$", image);
            Assert.Matches($@"(?m)^\s*{Regex.Escape(appRole)}\) echo {uid} ;;", setup);
        }

        Assert.Equal(users.Count, users.Distinct().Count());
        Assert.DoesNotContain(Services.GetProperty("openbao").GetProperty("user").GetString()!.Split(':')[0], users);

        // The Master Key's owner is the user OpenBao runs as.
        var openBaoUser = Services.GetProperty("openbao").GetProperty("user").GetString()!;
        Assert.Contains($"GATEKEEP_KEY_OWNER:-{openBaoUser}", keygen);
    }

    private static string Normalized(string path) => path.Replace('\\', '/');

    private static void AssertFromLinesPinned(string dockerfile)
    {
        var lines = File.ReadAllLines(Path.Combine(Repository.Root, dockerfile))
            .Where(l => l.TrimStart().StartsWith("FROM ", StringComparison.OrdinalIgnoreCase));

        foreach (var line in lines)
        {
            Assert.Contains("@sha256:", line);
        }
    }

    private static IEnumerable<string> Strings(JsonElement element, string property) =>
        element.TryGetProperty(property, out var array) && array.ValueKind == JsonValueKind.Array
            ? array.EnumerateArray().Select(e => e.GetString()!).ToList()
            : [];

    private static IEnumerable<(string Type, string Source, string Target)> Volumes(JsonElement service) =>
        service.TryGetProperty("volumes", out var volumes)
            ? volumes.EnumerateArray().Select(v => (
                v.GetProperty("type").GetString()!,
                v.TryGetProperty("source", out var source) ? source.GetString()! : string.Empty,
                v.GetProperty("target").GetString()!)).ToList()
            : [];

    private static JsonElement Config(string file, params string[] arguments)
    {
        var start = new ProcessStartInfo("docker")
        {
            WorkingDirectory = Repository.Root,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in new[] { "compose", "-f", file }.Concat(arguments).Concat(["config", "--format", "json"]))
        {
            start.ArgumentList.Add(argument);
        }

        start.Environment.Remove("GATEKEEP_SECRETS_DIR");
        start.Environment.Remove("COMPOSE_PROJECT_NAME");

        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(TimeSpan.FromMinutes(1)))
        {
            process.Kill();
            throw new TimeoutException("docker compose config didn't finish.");
        }

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"docker compose config failed: {error.Result}");
        }

        using var document = JsonDocument.Parse(output.Result);
        return document.RootElement.Clone();
    }
}

internal static class Repository
{
    public static readonly string Root = Find();

    private static string Find()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Gatekeep.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException("No Gatekeep.slnx above the test output.");
    }
}
