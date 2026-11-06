using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;

namespace Gatekeep.Tests.Isolation.Stack;

/// <summary>
/// Stories 1.10 and 1.11: the Compose definition as Compose itself resolves it (<c>docker compose config</c>),
/// so anchors, merges and defaults are applied before anything is checked.
/// </summary>
public sealed class ComposeConfigTests
{
    private static readonly string[] HardenedServices =
        ["hosted", "admin", "worker", "cli", "postgres", "postgres-passwords", "openbao", "caddy", "openbao-audit-shipper"];
    private static readonly string[] Hosts = ["hosted", "admin", "worker"];

    private static readonly Lazy<JsonElement> Stack = new(() => Config("deploy/compose.yaml", "--profile", "tools", "--profile", "setup"));

    /// <summary>Production TLS for both sites: the Cloudflare DNS-01 override on top.</summary>
    private static readonly Lazy<JsonElement> CloudflareStack = new(() => Config(
        ["deploy/compose.yaml", "deploy/compose.cloudflare.yaml"],
        new Dictionary<string, string>
        {
            ["GATEKEEP_ACME_EMAIL"] = "ops@gatekeep.invalid",
            ["GATEKEEP_ACME_CHALLENGE_DOMAIN"] = "zone.validation.invalid",
            ["GATEKEEP_ADMIN_ACME_CHALLENGE_DOMAIN"] = "admin.validation.invalid",
        },
        "--profile", "tools", "--profile", "setup"));

    /// <summary>Story 12.7: a Master Key rotation, the rotation overlay on top.</summary>
    private static readonly Lazy<JsonElement> RotateStack = new(() => Config(
        ["deploy/compose.yaml", "deploy/compose.rotate.yaml"],
        new Dictionary<string, string>(),
        "--profile", "tools", "--profile", "setup", "--profile", "rotate"));

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
    public void Only_Caddy_publishes_ports_only_80_and_443_and_health_ports_stay_private()
    {
        // Caddy listens unprivileged inside, published as the host's 80 and 443.
        var published = Services.GetProperty("caddy").GetProperty("ports").EnumerateArray()
            .Select(p => $"{p.GetProperty("published").GetString()}->{p.GetProperty("target").GetInt32()}/{p.GetProperty("protocol").GetString()}")
            .Order();
        Assert.Equal(["443->8443/tcp", "80->8080/tcp"], published);

        foreach (var service in Services.EnumerateObject().Where(s => s.Name != "caddy"))
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

    /// <summary>
    /// Story 1.30 adds <c>egress</c>, the second network with a way out, for application egress: only
    /// Host.Worker, the cli and the audit shipper join it. Host.Hosted and Host.Admin get none.
    /// </summary>
    [Fact]
    public void Only_the_edge_and_egress_networks_have_egress_and_each_host_has_its_own()
    {
        foreach (var network in Stack.Value.GetProperty("networks").EnumerateObject())
        {
            var isInternal = network.Value.TryGetProperty("internal", out var value) && value.GetBoolean();
            Assert.True(isInternal == (network.Name is not ("edge" or "egress")), $"Network {network.Name} is internal: {isInternal}.");
        }

        var egress = Services.EnumerateObject()
            .Where(s => s.Value.TryGetProperty("networks", out var networks) && networks.TryGetProperty("egress", out _))
            .Select(s => s.Name)
            .Order();
        Assert.Equal(["cli", "openbao-audit-shipper", "worker"], egress);
        Assert.Equal(["egress"], NetworksOf(Services.GetProperty("openbao-audit-shipper")));

        // Each host's own network is the one named after it, and it joins no other host's.
        foreach (var host in Hosts)
        {
            var networks = NetworksOf(Services.GetProperty(host));
            Assert.Contains(host, networks);
            Assert.DoesNotContain(networks, n => Hosts.Contains(n) && n != host);
            Assert.DoesNotContain("edge", networks);
        }
    }

    [Fact]
    public void Caddy_reaches_Hosted_and_Admin_each_over_a_network_of_its_own_and_nothing_else()
    {
        Assert.Equal(["admin-edge", "edge", "hosted-edge"], NetworksOf(Services.GetProperty("caddy")));
        Assert.Equal(["hosted", "hosted-edge"], NetworksOf(Services.GetProperty("hosted")));
        Assert.Equal(["admin", "admin-edge"], NetworksOf(Services.GetProperty("admin")));
        Assert.Equal(["egress", "worker"], NetworksOf(Services.GetProperty("worker")));

        // The Caddyfile proxies to the two public ports only, and its admin API is off.
        var caddy = Path.Combine(Repository.Root, "deploy", "caddy");
        var configs = Directory.EnumerateFiles(caddy, "*.caddy").Append(Path.Combine(caddy, "Caddyfile")).Select(File.ReadAllText).ToList();
        var upstreams = configs.SelectMany(t => Regex.Matches(t, @"(?m)^\s*reverse_proxy\s+(\S+)").Select(m => m.Groups[1].Value)).Order();
        Assert.Equal(["admin:8080", "hosted:8080"], upstreams);
        Assert.Matches(@"(?m)^\s*admin off\s*$", configs[^1]);

        // Each site refuses the other host's edge subnet, which Compose fixes.
        string Subnet(string network) => Stack.Value.GetProperty("networks").GetProperty(network)
            .GetProperty("ipam").GetProperty("config").EnumerateArray().Single().GetProperty("subnet").GetString()!;
        Assert.Contains($"@from_admin_edge remote_ip {Subnet("admin-edge")}", configs[^1]);
        Assert.Contains($"@from_hosted_edge remote_ip {Subnet("hosted-edge")}", configs[^1]);
        Assert.Matches(@"(?s)https://\*\.\{\$GATEKEEP_TENANT_ZONE\} \{[^}]*abort @from_admin_edge", configs[^1]);
        Assert.Matches(@"(?s)https://\{\$GATEKEEP_ADMIN_HOST\} \{[^}]*abort @from_hosted_edge", configs[^1]);
        Assert.Equal(2, Regex.Matches(configs[^1], @"header Strict-Transport-Security ""max-age=31536000""").Count);
        Assert.All(configs, t => Assert.DoesNotMatch(@"(?m)^\s*(metrics|admin\s+(?!off\s*$)\S)", t));
    }

    [Fact]
    public void Caddy_refuses_an_Admin_hostname_under_the_Tenant_zone()
    {
        var start = File.ReadAllText(Path.Combine(Repository.Root, "deploy", "caddy", "start.sh"));
        Assert.Contains("at_or_under \"$admin\" \"$zone\" && refuse \"GATEKEEP_ADMIN_HOST is under", start);
        Assert.Contains("at_or_under \"$zone\" \"$admin\" && refuse \"GATEKEEP_TENANT_ZONE is under", start);
        Assert.Contains("case \"$1\" in \"$2\" | *\".$2\") return 0 ;; esac", start);
        Assert.Contains("ENTRYPOINT [\"sh\", \"/etc/caddy/start.sh\"]", File.ReadAllText(Path.Combine(Repository.Root, "deploy", "docker", "caddy.Dockerfile")));

        // The defaults are two separate names.
        var environment = Services.GetProperty("caddy").GetProperty("environment");
        var zone = environment.GetProperty("GATEKEEP_TENANT_ZONE").GetString()!;
        var admin = environment.GetProperty("GATEKEEP_ADMIN_HOST").GetString()!;
        Assert.False(admin == zone || admin.EndsWith("." + zone, StringComparison.Ordinal), $"{admin} is under {zone}.");
    }

    [Fact]
    public void Caddy_volumes_are_mounted_by_Caddy_alone()
    {
        foreach (var service in Services.EnumerateObject())
        {
            var mounts = Volumes(service.Value)
                .Where(v => v.Source.StartsWith("caddy-", StringComparison.Ordinal))
                .Select(v => $"{v.Source}:{v.Target}")
                .Order()
                .ToList();
            Assert.Equal(service.Name == "caddy" ? new[] { "caddy-config:/config", "caddy-data:/data" } : [], mounts);
        }
    }

    [Fact]
    public void Caddy_uses_its_internal_CA_with_no_token_unless_the_Cloudflare_override_is_added()
    {
        var caddy = Services.GetProperty("caddy");
        Assert.Equal("internal", caddy.GetProperty("environment").GetProperty("GATEKEEP_TLS_MODE").GetString());
        Assert.False(caddy.TryGetProperty("secrets", out _), "Caddy gets a secret in internal mode.");
        Assert.False(Stack.Value.GetProperty("secrets").TryGetProperty("cloudflare_dns_token", out _));

        var production = CloudflareStack.Value.GetProperty("services");
        var cloudflare = production.GetProperty("caddy");
        Assert.Equal("cloudflare", cloudflare.GetProperty("environment").GetProperty("GATEKEEP_TLS_MODE").GetString());
        var secret = Assert.Single(cloudflare.GetProperty("secrets").EnumerateArray());
        Assert.Equal("cloudflare_dns_token", secret.GetProperty("source").GetString());
        Assert.Equal("/run/secrets/cloudflare_dns_token", secret.GetProperty("target").GetString());
        Assert.EndsWith(
            "/secrets/cloudflare/dns-token",
            Normalized(CloudflareStack.Value.GetProperty("secrets").GetProperty("cloudflare_dns_token").GetProperty("file").GetString()!),
            StringComparison.Ordinal);

        // The DNS token reaches Caddy alone.
        foreach (var service in production.EnumerateObject().Where(s => s.Name != "caddy"))
        {
            Assert.False(
                service.Value.TryGetProperty("secrets", out var secrets)
                    && secrets.EnumerateArray().Any(s => s.GetProperty("source").GetString() == "cloudflare_dns_token"),
                $"{service.Name} gets the DNS token.");
        }

        // Caddy reads it from that file, never from its environment, and writes challenge
        // records only under the validation-only names.
        var tls = File.ReadAllText(Path.Combine(Repository.Root, "deploy", "caddy", "tls-cloudflare.caddy"));
        Assert.Contains("dns cloudflare {file./run/secrets/cloudflare_dns_token}", tls);
        Assert.Contains("dns_challenge_override_domain {args[0]}", tls);
        Assert.Contains("import cloudflare-dns-01 {$GATEKEEP_ACME_CHALLENGE_DOMAIN}", tls);
        Assert.Contains("import cloudflare-dns-01 {$GATEKEEP_ADMIN_ACME_CHALLENGE_DOMAIN}", tls);
        Assert.DoesNotContain("{env.", tls);
        Assert.All(cloudflare.GetProperty("environment").EnumerateObject(), v => Assert.DoesNotContain("TOKEN", v.Name, StringComparison.OrdinalIgnoreCase));
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
        // Exactly the key and its ID: the previous generation only ever comes from the rotation overlay.
        Assert.Equal(
            ["master_key:/run/secrets/master_key", "master_key_id:/run/secrets/master_key_id"],
            openbao.GetProperty("secrets").EnumerateArray()
                .Select(s => $"{s.GetProperty("source").GetString()}:{s.GetProperty("target").GetString()}")
                .Order(StringComparer.Ordinal));
        Assert.EndsWith(
            "/secrets/master/master-key-id",
            Normalized(Stack.Value.GetProperty("secrets").GetProperty("master_key_id").GetProperty("file").GetString()!),
            StringComparison.Ordinal);

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
            ["bootstrap-dir"] = ["/bootstrap"],
            // The one runtime exception: init writes the bootstrap token there (Story 1.19).
            ["cli"] = ["/bootstrap"],
        };

        foreach (var service in Services.EnumerateObject())
        {
            var receives = service.Value.TryGetProperty("secrets", out var secrets)
                && secrets.EnumerateArray().Any(s => s.GetProperty("source").GetString() is "master_key" or "master_key_id");
            Assert.Equal(service.Name == "openbao", receives);

            var bound = Volumes(service.Value)
                .Where(v => v.Type == "bind" && Normalized(v.Source).StartsWith(secretsDirectory, StringComparison.Ordinal))
                .Select(v => Normalized(v.Source)[secretsDirectory.Length..])
                .Order()
                .ToList();
            Assert.Equal(expected.GetValueOrDefault(service.Name, []), bound);
            if (bound.Count > 0 && service.Name != "cli")
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

    /// <summary>
    /// Story 12.7: the rotation overlay gives <c>openbao</c> the previous generation and adds its two
    /// one-shot services, hardened, with no network. Only <c>keygen</c> and <c>master-key-rotate</c>
    /// bind <c>master/</c>, and <c>master-key-rotate-root</c> has the socket alone.
    /// </summary>
    [Fact]
    public void Rotation_overlay_adds_the_previous_generation_and_two_hardened_tools_with_no_network()
    {
        var services = RotateStack.Value.GetProperty("services");
        var secrets = RotateStack.Value.GetProperty("secrets");
        var file = Normalized(secrets.GetProperty("master_key").GetProperty("file").GetString()!);
        var secretsDirectory = file[..^"/master/master-key".Length];

        Assert.Equal(
            ["master_key", "master_key_id", "master_key_previous", "master_key_previous_id"],
            services.GetProperty("openbao").GetProperty("secrets").EnumerateArray().Select(s => s.GetProperty("source").GetString()).Order(StringComparer.Ordinal));
        Assert.Equal(secretsDirectory + "/master/previous/master-key", Normalized(secrets.GetProperty("master_key_previous").GetProperty("file").GetString()!));
        Assert.Equal(secretsDirectory + "/master/previous/master-key-id", Normalized(secrets.GetProperty("master_key_previous_id").GetProperty("file").GetString()!));
        Assert.All(Volumes(services.GetProperty("openbao")), v => Assert.Equal("volume", v.Type));

        foreach (var service in services.EnumerateObject())
        {
            var bound = Volumes(service.Value)
                .Where(v => v.Type == "bind" && Normalized(v.Source).StartsWith(secretsDirectory + "/master", StringComparison.Ordinal))
                .Select(v => $"{Normalized(v.Source)[secretsDirectory.Length..]}:{v.Target}")
                .ToList();
            string[] expected = service.Name is "keygen" or "master-key-rotate" ? ["/master:/secrets"] : [];
            Assert.Equal(expected, bound);

            var previous = service.Value.TryGetProperty("secrets", out var received)
                && received.EnumerateArray().Any(s => s.GetProperty("source").GetString()!.StartsWith("master_key", StringComparison.Ordinal));
            Assert.Equal(service.Name == "openbao", previous);
        }

        foreach (var name in new[] { "master-key-rotate", "master-key-rotate-root" })
        {
            var service = services.GetProperty(name);
            Assert.Equal(["rotate"], Strings(service, "profiles"));
            Assert.Equal("none", service.GetProperty("network_mode").GetString());
            Assert.False(service.TryGetProperty("networks", out _), $"{name} joins a network.");
            Assert.True(service.GetProperty("read_only").GetBoolean(), $"{name} has a writable root filesystem.");
            Assert.Equal(["ALL"], Strings(service, "cap_drop"));
            Assert.Contains("no-new-privileges:true", Strings(service, "security_opt"));
            Assert.False(service.TryGetProperty("privileged", out var privileged) && privileged.GetBoolean());
            Assert.Equal("no", service.GetProperty("restart").GetString());
            Assert.Equal(["4500"], Strings(service, "group_add"));
            Assert.Equal("gatekeep/openbao:local", service.GetProperty("image").GetString());
            Assert.Equal("never", service.GetProperty("pull_policy").GetString());
            Assert.True(service.GetProperty("pids_limit").GetInt64() > 0);
            Assert.False(service.TryGetProperty("secrets", out _), $"{name} gets a Compose secret.");
            Assert.False(service.TryGetProperty("ports", out var ports) && ports.GetArrayLength() > 0);
        }

        // prepare and finish chown into master/ as keygen does; the root step runs as OpenBao's user,
        // with no capability and nothing but the socket.
        var rotate = services.GetProperty("master-key-rotate");
        Assert.Equal(Strings(services.GetProperty("keygen"), "cap_add").Order(), Strings(rotate, "cap_add").Order());
        Assert.Equal(["/opt/gatekeep/openbao/rotate-master-key.sh"], Strings(rotate, "entrypoint").Skip(1));
        Assert.Equal(
            ["bind:/secrets", "volume:/run/openbao"],
            Volumes(rotate).Select(v => $"{v.Type}:{v.Target}").Order());

        var root = services.GetProperty("master-key-rotate-root");
        Assert.Equal("100:1000", root.GetProperty("user").GetString());
        Assert.Empty(Strings(root, "cap_add"));
        Assert.Equal(["/opt/gatekeep/openbao/rotate-root-key.sh"], Strings(root, "entrypoint").Skip(1));
        Assert.Equal(("volume", "openbao-socket", "/run/openbao"), Assert.Single(Volumes(root)));
    }

    /// <summary>Story 12.7: the base config and its renderer never allow unauthenticated generate-root outside rotation mode.</summary>
    [Fact]
    public void Base_OpenBao_config_disables_unauthenticated_generate_root_and_only_rotation_mode_reopens_it()
    {
        var config = File.ReadAllText(Path.Combine(Repository.Root, "deploy", "openbao", "openbao.hcl"));
        var listeners = Regex.Matches(config, @"(?s)listener ""(?<type>\w+)"" \{(?<body>[^}]*)\}");
        Assert.Equal(2, listeners.Count);
        Assert.All(listeners, l => Assert.Matches(@"(?m)^\s*disable_unauthed_generate_root_endpoints = true\s*$", l.Groups["body"].Value));
        Assert.DoesNotMatch(@"(?m)^[^#]*disable_unauthed_generate_root_endpoints\s*=\s*false", config);
        Assert.Contains("current_key_id = \"@MASTER_KEY_ID@\"", config);

        var start = File.ReadAllText(Path.Combine(Repository.Root, "deploy", "openbao", "start-openbao.sh"));
        Assert.Contains("if [ -e \"$PREVIOUS_KEY_FILE\" ] || [ -e \"$PREVIOUS_ID_FILE\" ]; then", start);
        Assert.Contains("previous != \"\" && unix && /^[ \\t]*disable_unauthed_generate_root_endpoints", start);
        Assert.Contains("[ \"$opened\" -eq 0 ] || refuse", start);
        Assert.Contains("ENTRYPOINT [\"sh\", \"/opt/gatekeep/openbao/start-openbao.sh\"]", File.ReadAllText(Path.Combine(Repository.Root, "deploy", "docker", "openbao.Dockerfile")));
    }

    /// <summary>
    /// Story 1.19: only <c>cli</c> mounts <c>bootstrap/</c>, read-write at <c>init</c>'s default token
    /// directory, and <c>bootstrap-dir</c> hands that directory to the uid <c>cli</c> runs as.
    /// </summary>
    [Fact]
    public void Only_cli_mounts_the_bootstrap_directory_and_its_setup_gives_it_the_cli_uid()
    {
        var file = Normalized(Stack.Value.GetProperty("secrets").GetProperty("master_key").GetProperty("file").GetString()!);
        var bootstrap = file[..^"/master/master-key".Length] + "/bootstrap";

        var mounting = Services.EnumerateObject()
            .Where(s => Volumes(s.Value).Any(v => Normalized(v.Source) == bootstrap))
            .Select(s => s.Name)
            .Order()
            .ToList();
        Assert.Equal(["bootstrap-dir", "cli"], mounting);

        var cli = Services.GetProperty("cli");
        var mount = Assert.Single(cli.GetProperty("volumes").EnumerateArray(), v => Normalized(v.GetProperty("source").GetString()!) == bootstrap);
        Assert.Equal("bind", mount.GetProperty("type").GetString());
        Assert.Equal("/gatekeep/bootstrap", mount.GetProperty("target").GetString());
        Assert.False(mount.TryGetProperty("read_only", out var readOnly) && readOnly.GetBoolean());
        // Docker would make a missing source root-owned, which init refuses: bootstrap-dir makes it.
        Assert.False(mount.GetProperty("bind").GetProperty("create_host_path").GetBoolean());
        Assert.Contains("const string DefaultTokenDirectory = \"/gatekeep/bootstrap\";", File.ReadAllText(Path.Combine(Repository.Root, "src", "Gatekeep.Cli", "Program.cs")));

        var cliUid = cli.GetProperty("user").GetString()!.Split(':')[0];
        var script = File.ReadAllText(Path.Combine(Repository.Root, "deploy", "cli", "prepare-bootstrap-dir.sh"));
        Assert.Matches($@"(?m)^CLI_UID={cliUid}\s*$", script);
        Assert.Contains("chmod 0700", script);
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
        var tests = Config("deploy/compose.test.yaml", "--profile", "stack", "--profile", "release").GetProperty("services");

        Assert.Equal(["release", "stack", "tests"], tests.EnumerateObject().Select(s => s.Name).Order());
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
            "gk_worker_password", "gk_dispatch_password", "gk_sealer_password", "gk_retention_password", "gk_cli_password"];
        var expected = new Dictionary<string, string[]>
        {
            ["postgres"] = passwords,
            ["postgres-passwords"] = passwords,
            ["openbao"] = ["master_key", "master_key_id"],
            ["hosted"] = ["gk_hosted_password", "openbao_hosted_role_id", "openbao_hosted_secret_id"],
            ["admin"] = ["gk_admin_password", "openbao_admin_role_id", "openbao_admin_secret_id"],
            ["worker"] = ["gk_dispatch_password", "gk_worker_password", "gk_sealer_password", "gk_retention_password",
                "openbao_worker_role_id", "openbao_worker_secret_id", .. OffServerSecrets],
            ["cli"] = ["gk_migrator_password", "gk_cli_password", "openbao_cli_role_id", "openbao_cli_secret_id", .. OffServerSecrets],
            // Story 1.30: the bucket's credential only, and no OpenBao login.
            ["openbao-audit-shipper"] = ["records_access_key_id", "records_secret_access_key"],
        };

        foreach (var service in Services.EnumerateObject())
        {
            var actual = service.Value.TryGetProperty("secrets", out var secrets)
                ? secrets.EnumerateArray().Select(s => s.GetProperty("source").GetString()!).Order().ToList()
                : [];
            Assert.Equal(expected.GetValueOrDefault(service.Name, []).Order(), actual);
        }
    }

    /// <summary>Story 1.30: the alert channel's token and the bucket's write-only credential.</summary>
    private static readonly string[] OffServerSecrets = ["alert_token", "records_access_key_id", "records_secret_access_key"];

    /// <summary>
    /// Story 1.30: the alert and bucket secrets are files under alerts/ and records/ in the secrets
    /// directory, read by Host.Worker and the cli under their own names, and the bucket's alone by the shipper.
    /// </summary>
    [Fact]
    public void Alert_and_bucket_secrets_are_files_in_the_secrets_directory_named_in_each_service()
    {
        var secrets = Stack.Value.GetProperty("secrets");
        var directory = Normalized(secrets.GetProperty("master_key").GetProperty("file").GetString()!)[..^"/master/master-key".Length];
        Assert.Equal(directory + "/alerts/token", Normalized(secrets.GetProperty("alert_token").GetProperty("file").GetString()!));
        Assert.Equal(directory + "/records/access-key-id", Normalized(secrets.GetProperty("records_access_key_id").GetProperty("file").GetString()!));
        Assert.Equal(directory + "/records/secret-access-key", Normalized(secrets.GetProperty("records_secret_access_key").GetProperty("file").GetString()!));

        var worker = Services.GetProperty("worker").GetProperty("environment");
        Assert.Equal("/run/secrets/alert_token", worker.GetProperty("Alerts__TokenFile").GetString());
        Assert.Equal("/run/secrets/records_access_key_id", worker.GetProperty("Records__AccessKeyIdFile").GetString());
        Assert.Equal("/run/secrets/records_secret_access_key", worker.GetProperty("Records__SecretAccessKeyFile").GetString());
        foreach (var name in new[] { "Alerts__Url", "Alerts__Deployment", "Records__Endpoint", "Records__Region", "Records__Bucket" })
        {
            Assert.True(worker.TryGetProperty(name, out _), $"worker has no {name}.");
        }

        foreach (var service in new[] { "cli", "openbao-audit-shipper" })
        {
            var environment = Services.GetProperty(service).GetProperty("environment");
            Assert.Equal("/run/secrets/records_access_key_id", environment.GetProperty("GATEKEEP_RECORDS_ACCESS_KEY_ID_FILE").GetString());
            Assert.Equal("/run/secrets/records_secret_access_key", environment.GetProperty("GATEKEEP_RECORDS_SECRET_ACCESS_KEY_FILE").GetString());
        }

        Assert.Equal("/run/secrets/alert_token", Services.GetProperty("cli").GetProperty("environment").GetProperty("GATEKEEP_ALERT_TOKEN_FILE").GetString());
    }

    /// <summary>
    /// Story 1.30: the audit shipper runs the cli image's <c>audit-ship</c> as a uid of its own. Only it
    /// and OpenBao mount the audit volume, the shipper read-only, and only they hold the openbao-audit
    /// group (gid 4501) that may read the file. Its state volume is its own, and it has no OpenBao socket.
    /// </summary>
    [Fact]
    public void Audit_shipper_alone_reads_the_audit_volume_read_only_through_its_group()
    {
        var shipper = Services.GetProperty("openbao-audit-shipper");
        Assert.Equal("gatekeep/cli:local", shipper.GetProperty("image").GetString());
        // Built as the cli service builds it, so `docker compose up --build` has it without the tools profile.
        var cliBuild = Services.GetProperty("cli").GetProperty("build");
        var shipperBuild = shipper.GetProperty("build");
        Assert.Equal(cliBuild.GetProperty("dockerfile").GetString(), shipperBuild.GetProperty("dockerfile").GetString());
        Assert.Equal(cliBuild.GetProperty("context").GetString(), shipperBuild.GetProperty("context").GetString());
        Assert.False(shipper.TryGetProperty("profiles", out _));
        Assert.Equal(["audit-ship"], Strings(shipper, "command"));
        Assert.Equal("10006:10006", shipper.GetProperty("user").GetString());
        Assert.Equal(["4501"], Strings(shipper, "group_add"));
        Assert.Equal("unless-stopped", shipper.GetProperty("restart").GetString());

        foreach (var service in Services.EnumerateObject())
        {
            var mounts = Volumes(service.Value).Where(v => v.Source is "openbao-audit" or "shipper-state").Select(v => $"{v.Source}:{v.Target}").Order().ToList();
            string[] expected = service.Name switch
            {
                "openbao" => ["openbao-audit:/var/log/openbao"],
                "openbao-audit-shipper" => ["openbao-audit:/var/log/openbao", "shipper-state:/var/lib/gatekeep/audit-ship"],
                _ => [],
            };
            Assert.Equal(expected, mounts);

            var audit = Strings(service.Value, "group_add").Contains("4501");
            Assert.Equal(service.Name is "openbao" or "openbao-audit-shipper", audit);
        }

        var auditMount = shipper.GetProperty("volumes").EnumerateArray().Single(v => v.GetProperty("source").GetString() == "openbao-audit");
        Assert.True(auditMount.GetProperty("read_only").GetBoolean());
        Assert.DoesNotContain(Volumes(shipper), v => v.Source == "openbao-socket");
        Assert.Equal(["4500", "4501"], Strings(Services.GetProperty("openbao"), "group_add").Order());

        var environment = shipper.GetProperty("environment");
        Assert.Equal("/var/log/openbao/audit.log", environment.GetProperty("GATEKEEP_AUDIT_LOG_FILE").GetString());
        Assert.Equal("/var/lib/gatekeep/audit-ship", environment.GetProperty("GATEKEEP_AUDIT_SHIP_STATE_DIR").GetString());

        // The image gives the state directory to the shipper's uid alone, and OpenBao's the audit log's group.
        var cli = File.ReadAllText(Path.Combine(Repository.Root, "deploy", "docker", "cli.Dockerfile"));
        Assert.Contains("mkdir -p /audit-ship && chmod 0700 /audit-ship", cli);
        Assert.Contains("COPY --from=build --chown=10006:10006 /audit-ship /var/lib/gatekeep/audit-ship", cli);
        // The stack check builds without BuildKit, which COPY --chmod needs.
        Assert.DoesNotContain("--chmod", cli);
        var openbao = File.ReadAllText(Path.Combine(Repository.Root, "deploy", "docker", "openbao.Dockerfile"));
        Assert.Contains("addgroup -S -g 4501 openbao-audit", openbao);
        Assert.Contains("chown openbao:openbao-audit /var/log/openbao", openbao);
        Assert.Contains("chmod 2750 /var/log/openbao", openbao);
        var start = File.ReadAllText(Path.Combine(Repository.Root, "deploy", "openbao", "start-openbao.sh"));
        Assert.Contains("AUDIT_GROUP=openbao-audit", start);
        Assert.Contains("chmod 0640 \"$AUDIT_DIR/audit.log\"", start);
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
            ["edge"] = ["caddy"],
            ["egress"] = ["cli", "openbao-audit-shipper", "worker"],
            ["hosted-edge"] = ["caddy", "hosted"],
            ["admin-edge"] = ["admin", "caddy"],
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

        // Story 1.30: the audit shipper runs the cli image as a uid of its own.
        users.Add(Services.GetProperty("openbao-audit-shipper").GetProperty("user").GetString()!.Split(':')[0]);

        // Caddy's uid is its own too, and the one its image runs as.
        var caddyUser = Services.GetProperty("caddy").GetProperty("user").GetString()!;
        Assert.Matches($@"(?m)^USER {Regex.Escape(caddyUser)}\s*$", File.ReadAllText(Path.Combine(Repository.Root, "deploy", "docker", "caddy.Dockerfile")));
        users.Add(caddyUser.Split(':')[0]);

        Assert.Equal(users.Count, users.Distinct().Count());
        Assert.DoesNotContain(Services.GetProperty("openbao").GetProperty("user").GetString()!.Split(':')[0], users);

        // The Master Key's owner is the user OpenBao runs as.
        var openBaoUser = Services.GetProperty("openbao").GetProperty("user").GetString()!;
        Assert.Contains($"GATEKEEP_KEY_OWNER:-{openBaoUser}", keygen);
    }

    private static List<string> NetworksOf(JsonElement service) =>
        [.. service.GetProperty("networks").EnumerateObject().Select(n => n.Name).Order()];

    private static string Normalized(string path) => path.Replace('\\', '/');

    internal static void AssertFromLinesPinned(string dockerfile)
    {
        var lines = File.ReadAllLines(Path.Combine(Repository.Root, dockerfile))
            .Where(l => l.TrimStart().StartsWith("FROM ", StringComparison.OrdinalIgnoreCase));

        foreach (var line in lines)
        {
            Assert.Contains("@sha256:", line);
        }
    }

    internal static IEnumerable<string> Strings(JsonElement element, string property) =>
        element.TryGetProperty(property, out var array) && array.ValueKind == JsonValueKind.Array
            ? array.EnumerateArray().Select(e => e.GetString()!).ToList()
            : [];

    internal static IEnumerable<(string Type, string Source, string Target)> Volumes(JsonElement service) =>
        service.TryGetProperty("volumes", out var volumes)
            ? volumes.EnumerateArray().Select(v => (
                v.GetProperty("type").GetString()!,
                v.TryGetProperty("source", out var source) ? source.GetString()! : string.Empty,
                v.GetProperty("target").GetString()!)).ToList()
            : [];

    /// <summary>Story 1.11's form: files and extra variables, then arguments.</summary>
    private static JsonElement Config(string[] files, Dictionary<string, string> environment, params string[] arguments) =>
        Config(files, arguments, environment);

    internal static JsonElement Config(string file, params string[] arguments) =>
        Config([file], arguments, new Dictionary<string, string>());

    /// <summary>
    /// <c>docker compose config</c> over <paramref name="files"/>, with <paramref name="environment"/>
    /// as the only extra variables. Throws when Compose refuses.
    /// </summary>
    internal static JsonElement Config(string[] files, string[] arguments, IReadOnlyDictionary<string, string> environment)
    {
        var (exitCode, output, error) = TryConfig(files, arguments, environment);
        if (exitCode != 0)
        {
            throw new InvalidOperationException($"docker compose config failed: {error}");
        }

        using var document = JsonDocument.Parse(output);
        return document.RootElement.Clone();
    }

    internal static (int ExitCode, string Output, string Error) TryConfig(
        string[] files, string[] arguments, IReadOnlyDictionary<string, string> environment)
    {
        var start = new ProcessStartInfo("docker")
        {
            WorkingDirectory = Repository.Root,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("compose");
        foreach (var file in files)
        {
            start.ArgumentList.Add("-f");
            start.ArgumentList.Add(file);
        }

        foreach (var argument in arguments.Concat(["config", "--format", "json"]))
        {
            start.ArgumentList.Add(argument);
        }

        // Only what the caller passes: nothing from the machine running the tests.
        foreach (var name in start.Environment.Keys.Where(k => k.StartsWith("GATEKEEP_", StringComparison.Ordinal)).ToList())
        {
            start.Environment.Remove(name);
        }

        start.Environment.Remove("COMPOSE_PROJECT_NAME");
        foreach (var (name, value) in environment)
        {
            start.Environment[name] = value;
        }

        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(TimeSpan.FromMinutes(1)))
        {
            process.Kill();
            throw new TimeoutException("docker compose config didn't finish.");
        }

        return (process.ExitCode, output.Result, error.Result);
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
