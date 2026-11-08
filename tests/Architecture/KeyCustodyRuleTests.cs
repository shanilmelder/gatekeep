using System.Text.RegularExpressions;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>AD-10 rules: every key is reached through <c>IKeyCustody</c>, and the policies can't export.</summary>
public class KeyCustodyRuleTests
{
    private const string AdapterDirectory = "src/Adapters/OpenBao/";
    private const string DeployDirectory = "deploy/openbao";
    private const string ComposeFile = "deploy/compose.yaml";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] SkippedDirectories = ["bin", "obj"];

    private static readonly Regex ReachesOpenBao = new(
        @"transit/|X-Vault-Token|\bBAO_(?:ADDR|TOKEN)\b|openbao\.sock|auth/approle|:8200\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex MakesKeyMaterial = new(
        @"\b(?:RSA|DSA|ECDsa|ECDiffieHellman|MLDsa|MLKem|SlhDsa|CompositeMLDsa)\s*\.\s*(?:Create|GenerateKey|ImportFromPem|ImportFromEncryptedPem)\b"
        + @"|\bnew\s+(?:RSACryptoServiceProvider|RSACng|RSAOpenSsl|DSACryptoServiceProvider|DSACng|DSAOpenSsl|ECDsaCng|ECDsaOpenSsl|ECDiffieHellmanCng|ECDiffieHellmanOpenSsl)\b"
        + @"|\b(?:AesGcm|AesCcm|ChaCha20Poly1305|AesCng|AesCryptoServiceProvider|TripleDES|IDataProtectionProvider|IDataProtector|DataProtectionProvider)\b"
        + @"|\bAes\s*\.\s*Create\b|\bAddDataProtection\b|\bProtectKeysWith\w*\b",
        RegexOptions.Compiled);

    private static readonly Regex Comment = new(@"//[^\r\n]*|/\*.*?\*/", RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex HclComment = new(@"#[^\r\n]*", RegexOptions.Compiled);

    private static readonly Regex PolicyPath = new(
        @"path\s+""(?<path>[^""]+)""\s*\{(?<body>(?:[^{}]|\{[^{}]*\})*)\}",
        RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex Capabilities = new(@"capabilities\s*=\s*\[(?<caps>[^\]]*)\]", RegexOptions.Compiled);

    private static readonly Regex DeniedParameters = new(
        @"denied_parameters\s*=\s*\{(?<body>[^}]*)\}",
        RegexOptions.Singleline | RegexOptions.Compiled);

    /// <summary>Transit endpoints a policy may name. Everything else, including export and backup, stays default-deny.</summary>
    private static readonly Regex AllowedPolicyPath = new(
        @"^transit/(?:keys|sign|verify|encrypt|decrypt|hmac|rewrap|datakey/wrapped)/(?:sig|mgmt|totp|social|email|payload|hmac|tpk)-\*$"
        + @"|^transit/(?:keys|sign|verify|encrypt|decrypt|hmac|rewrap)/dep-(?:email|payload|hmac|records|\*)$",
        RegexOptions.Compiled);

    /// <summary>The one Transit path that names no key: the key list.</summary>
    private const string ListPath = "transit/keys";

    private static readonly Regex Listener = new(@"listener\s+""(?<type>\w+)""\s*\{(?<body>[^}]*)\}", RegexOptions.Singleline | RegexOptions.Compiled);

    public static TheoryData<string> PolicyFiles =>
    [
        .. Directory.EnumerateFiles(Path.Combine(Root, DeployDirectory, "policies"), "*.hcl")
            .Select(f => Path.GetRelativePath(Root, f).Replace('\\', '/')),
    ];

    [Fact]
    public void Only_the_OpenBao_adapter_reaches_OpenBao()
    {
        var sources = SourceFiles(Path.Combine(Root, "src")).Select(Relative).ToList();

        Assert.Contains(sources, f => f.StartsWith(AdapterDirectory, StringComparison.Ordinal)
            && ReachesOpenBao.IsMatch(File.ReadAllText(Path.Combine(Root, f))));
        var offenders = sources
            .Where(f => !f.StartsWith(AdapterDirectory, StringComparison.Ordinal))
            .Where(f => ReachesOpenBao.IsMatch(File.ReadAllText(Path.Combine(Root, f))))
            .ToList();

        Assert.Empty(offenders);
    }

    [Theory]
    [InlineData("await http.PostAsync(\"v1/transit/sign/sig-1\", body);", true)]
    [InlineData("request.Headers.Add(\"X-Vault-Token\", token);", true)]
    [InlineData("var address = Environment.GetEnvironmentVariable(\"BAO_ADDR\");", true)]
    [InlineData("var socket = \"/run/openbao/openbao.sock\";", true)]
    [InlineData("var login = \"v1/auth/approle/login\";", true)]
    [InlineData("var uri = new Uri(\"http://127.0.0.1:8200\");", true)]
    [InlineData("// A Transit key holds the Signing Key.", false)]
    [InlineData("await custody.SignAsync(key, data, ct);", false)]
    public void OpenBao_reach_detection(string source, bool expected)
    {
        Assert.Equal(expected, ReachesOpenBao.IsMatch(source));
    }

    /// <summary>
    /// Story 1.29 (AD-10): a key is destroyed only inside the Keys module, through <c>KeysContract</c>,
    /// which destroys a deleted Tenant's six secret class keys and, from Story 2.3, its Signing and
    /// Management keys (and Story 2.4's retired and orphaned ones), and nowhere else under <c>src/</c>
    /// but the adapter itself.
    /// </summary>
    [Fact]
    public void Only_KeysContract_destroys_a_key()
    {
        var sources = SourceFiles(Path.Combine(Root, "src")).Select(f => (Relative(f), File.ReadAllText(f))).ToList();

        Assert.Contains(sources, s => s.Item1 == KeysContractFile && DestroysKey.IsMatch(Comment.Replace(s.Item2, string.Empty)));
        Assert.Empty(DestroyViolations(sources));
    }

    [Theory]
    [InlineData("src/Modules/Operations/Core/TenantDeletion.cs", "await custody.DeleteAsync(key, ct);", 1)]
    [InlineData("src/Gatekeep.Host.Admin/TenantsApi.cs", "await services.Custody\n  .DeleteAsync(KeyName.ForTenant(c, id), ct);", 1)]
    [InlineData("src/Modules/Operations/Core/TenantDeletion.cs", "// custody.DeleteAsync(key, ct) is KeysContract's alone.", 0)]
    [InlineData("src/Modules/Operations/Core/TenantDeletion.cs", "await KeysContract.DestroySecretClassKeysAsync(custody, id, ct);", 0)]
    [InlineData(KeysContractFile, "await custody.DeleteAsync(key, cancellationToken);", 0)]
    [InlineData("src/Modules/Keys/Core/KeysPurge.cs", "await custody.DeleteAsync(key, cancellationToken);", 0)]
    [InlineData("src/Modules/Operations/Core/SigningKeyJobs.cs", "await custody.DeleteAsync(key, ct);", 1)]
    [InlineData("src/Adapters/OpenBao/OpenBaoKeyCustody.cs", "await other.DeleteAsync(key, ct);", 0)]
    [InlineData("src/Gatekeep.Host.Admin/TenantsApi.cs", "await services.Tenants.DeleteAsync(context, principal, id, typed, ct);", 0)]
    public void Key_destroy_detection(string path, string source, int expected)
    {
        Assert.Equal(expected, DestroyViolations([(path, source)]).Count);
    }

    private const string KeysContractFile = "src/Modules/Keys/Contracts/KeysContract.cs";

    private const string KeysModule = "src/Modules/Keys/";

    /// <summary>A <c>DeleteAsync</c> call on a receiver named for custody: a Tenant's or anything else's <c>DeleteAsync</c> isn't a key.</summary>
    private static readonly Regex DestroysKey = new(@"\b\w*[Cc]ustody\w*\s*\.\s*DeleteAsync\s*\(", RegexOptions.Compiled);

    private static List<string> DestroyViolations(IEnumerable<(string Path, string Source)> sources) =>
        [.. sources
            .Where(s => !s.Path.StartsWith(KeysModule, StringComparison.Ordinal) && !s.Path.StartsWith(AdapterDirectory, StringComparison.Ordinal))
            .Where(s => DestroysKey.IsMatch(Comment.Replace(s.Source, string.Empty)))
            .Select(s => $"{s.Path} destroys a key: only the Keys module, through {KeysContractFile}, may (AD-10).")];

    [Fact]
    public void No_source_makes_asymmetric_or_AEAD_keys()
    {
        var offenders = SourceFiles(Path.Combine(Root, "src"))
            .Where(f => MakesKeyMaterial.IsMatch(Comment.Replace(File.ReadAllText(f), string.Empty)))
            .Select(Relative);

        Assert.Empty(offenders);
    }

    [Theory]
    [InlineData("using var rsa = RSA.Create(3072);", true)]
    [InlineData("var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);", true)]
    [InlineData("var dh = ECDiffieHellman.Create();", true)]
    [InlineData("var rsa = new RSACryptoServiceProvider(2048);", true)]
    [InlineData("using var gcm = new AesGcm(key, 16);", true)]
    [InlineData("using var aes = Aes.Create();", true)]
    [InlineData("var c = new ChaCha20Poly1305(key);", true)]
    [InlineData("public Thing(IDataProtectionProvider provider) { }", true)]
    [InlineData("services.AddDataProtection();", true)]
    [InlineData("// RSA.Create() is forbidden here.", false)]
    [InlineData("var hash = SHA256.HashData(bytes);", false)]
    [InlineData("await custody.CreateKeyAsync(key, ct);", false)]
    public void Key_material_detection(string source, bool expected)
    {
        Assert.Equal(expected, MakesKeyMaterial.IsMatch(Comment.Replace(source, string.Empty)));
    }

    [Fact]
    public void Four_policies_exist_one_per_host_and_the_Cli()
    {
        Assert.Equal(
            ["cli.hcl", "host-admin.hcl", "host-hosted.hcl", "host-worker.hcl"],
            PolicyFiles.Select(f => Path.GetFileName((string)f)).Order());
    }

    [Theory]
    [MemberData(nameof(PolicyFiles))]
    public void Policy_has_no_export_or_backup_path_and_every_key_write_denies_exportable(string file)
    {
        Assert.Empty(PolicyViolations(File.ReadAllText(Path.Combine(Root, file))));
    }

    [Theory]
    [InlineData("path \"transit/sign/sig-*\" {\n  capabilities = [\"update\"]\n}", 0)]
    [InlineData("path \"transit/export/encryption-key/social-*\" {\n  capabilities = [\"read\"]\n}", 1)]
    [InlineData("path \"transit/backup/*\" {\n  capabilities = [\"read\"]\n}", 1)]
    [InlineData("path \"transit/restore/*\" {\n  capabilities = [\"update\"]\n}", 1)]
    [InlineData("path \"transit/*\" {\n  capabilities = [\"update\"]\n}", 1)]
    [InlineData("path \"sys/policies/acl/*\" {\n  capabilities = [\"update\"]\n}", 1)]
    [InlineData("path \"transit/datakey/plaintext/tpk-*\" {\n  capabilities = [\"update\"]\n}", 1)]
    [InlineData("path \"transit/keys/sig-*\" {\n  capabilities = [\"update\"]\n}", 1)]
    [InlineData("path \"transit/keys/sig-*\" {\n  capabilities = [\"update\"]\n  denied_parameters = {\n    \"exportable\" = []\n  }\n}", 1)]
    [InlineData("path \"transit/keys/sig-*\" {\n  capabilities = [\"update\"]\n  denied_parameters = {\n    \"exportable\" = []\n    \"allow_plaintext_backup\" = []\n  }\n}", 0)]
    [InlineData("path \"transit/keys/sig-*\" {\n  capabilities = [\"read\"]\n}", 0)]
    [InlineData("# path \"transit/backup/*\" {}\npath \"transit/hmac/dep-hmac\" {\n  capabilities = [\"update\"]\n}", 0)]
    [InlineData("", 1)]
    [InlineData("path \"transit/keys\" {\n  capabilities = [\"list\"]\n}", 0)]
    [InlineData("path \"transit/keys\" {\n  capabilities = [\"list\", \"update\"]\n}", 1)]
    [InlineData("path \"transit/keys\" {\n  capabilities = [\"read\"]\n}", 1)]
    [InlineData("path \"transit/keys/*\" {\n  capabilities = [\"list\"]\n}", 1)]
    public void Policy_violation_detection(string policy, int violations)
    {
        Assert.Equal(violations, PolicyViolations(policy).Count);
    }

    [Fact]
    public void Production_config_has_no_listener_beyond_the_socket_and_its_private_loopback()
    {
        var violations = ListenerViolations(
            File.ReadAllText(Path.Combine(Root, DeployDirectory, "openbao.hcl")),
            OpenBaoService(File.ReadAllText(Path.Combine(Root, ComposeFile))));

        Assert.Empty(violations);
    }

    [Theory]
    [InlineData("listener \"unix\" { address = \"/run/openbao/openbao.sock\" }", "    network_mode: none\n", 0)]
    [InlineData("listener \"unix\" { address = \"/run/openbao/openbao.sock\" }\nlistener \"tcp\" {\n address = \"127.0.0.1:8200\"\n}", "    network_mode: none\n", 0)]
    [InlineData("listener \"unix\" { address = \"/run/openbao/openbao.sock\" }\nlistener \"tcp\" {\n address = \"0.0.0.0:8200\"\n}", "    network_mode: none\n", 1)]
    [InlineData("listener \"unix\" { address = \"/run/openbao/openbao.sock\" }\nlistener \"tcp\" {\n address = \"127.0.0.1:8200\"\n}", "    networks: [tools]\n", 1)]
    [InlineData("listener \"unix\" { address = \"/run/openbao/openbao.sock\" }\nlistener \"tcp\" {\n address = \"127.0.0.1:8200\"\n}", "    # network_mode: none\n", 1)]
    [InlineData("listener \"tcp\" {\n address = \"127.0.0.1:8200\"\n}", "    network_mode: none\n", 1)]
    public void Listener_violation_detection(string config, string service, int violations)
    {
        Assert.Equal(violations, ListenerViolations(config, service).Count);
    }

    [Fact]
    public void OpenBao_service_gets_the_Master_Key_only_as_a_secret_file()
    {
        var service = OpenBaoService(File.ReadAllText(Path.Combine(Root, ComposeFile)));
        var config = HclComment.Replace(File.ReadAllText(Path.Combine(Root, DeployDirectory, "openbao.hcl")), string.Empty);

        Assert.NotEmpty(service);
        Assert.Contains("current_key    = \"file:///run/secrets/master_key\"", config);
        Assert.Matches(@"(?m)^      - master_key$", service);
        Assert.Matches(@"(?m)^      - master_key_id$", service);
        Assert.DoesNotContain("master_key_previous", service);
        Assert.DoesNotContain("environment:", service);
        Assert.DoesNotContain("env_file", service);
        Assert.DoesNotContain("SECRETS_DIR", service);
    }

    /// <summary>
    /// Story 12.7: the previous generation reaches OpenBao only from the rotation overlay, as two
    /// more secret files, and the rendered key IDs never come from anything but the ID file.
    /// </summary>
    [Fact]
    public void Previous_generation_reaches_OpenBao_only_through_the_rotation_overlay()
    {
        var overlay = File.ReadAllText(Path.Combine(Root, "deploy", "compose.rotate.yaml")).ReplaceLineEndings("\n");
        var service = Regex.Match(overlay, @"(?m)^  openbao:\n(?<body>(?:(?:    .*)?\n)*)").Groups["body"].Value;

        Assert.Equal(["master_key_previous", "master_key_previous_id"], Regex.Matches(service, @"(?m)^      - (\S+)$").Select(m => m.Groups[1].Value));
        Assert.DoesNotContain("environment:", service);
        Assert.DoesNotContain("volumes:", service);

        var config = HclComment.Replace(File.ReadAllText(Path.Combine(Root, DeployDirectory, "openbao.hcl")), string.Empty);
        Assert.Contains("current_key_id = \"@MASTER_KEY_ID@\"", config);
        Assert.DoesNotContain("previous_key", config);

        var start = File.ReadAllText(Path.Combine(Root, DeployDirectory, "start-openbao.sh"));
        Assert.Contains("KEY_ID_FILE=/run/secrets/master_key_id", start);
        Assert.Contains("PREVIOUS_KEY_FILE=/run/secrets/master_key_previous", start);
        Assert.Contains("PREVIOUS_ID_FILE=/run/secrets/master_key_previous_id", start);
    }

    /// <summary>
    /// Story 1.30: the audit file leaves the server, so the device keeps OpenBao's default HMAC of
    /// every request and response value. No <c>log_raw</c>, and neither <c>hmac_accessor</c> nor
    /// <c>elide_list_responses</c> set to false; and the file is readable by its group alone, the
    /// one the shipper reads it through.
    /// </summary>
    [Fact]
    public void Audit_device_keeps_its_default_HMAC_and_is_readable_by_its_group_alone()
    {
        var config = HclComment.Replace(File.ReadAllText(Path.Combine(Root, DeployDirectory, "openbao.hcl")), string.Empty);

        Assert.Empty(AuditViolations(config));
        var options = Regex.Match(config, @"(?s)audit\s+""file""\s+""file""\s*\{.*?options\s*\{(?<options>[^}]*)\}");
        Assert.True(options.Success, "openbao.hcl declares no file audit device.");
        Assert.Matches(@"(?m)^\s*file_path\s*=\s*""/var/log/openbao/audit\.log""\s*$", options.Groups["options"].Value);
        Assert.Matches(@"(?m)^\s*mode\s*=\s*""0640""\s*$", options.Groups["options"].Value);
        Assert.Single(Regex.Matches(config, @"(?m)^\s*audit\s+"""));
    }

    [Theory]
    [InlineData("audit \"file\" \"file\" {\n  options {\n    file_path = \"/x\"\n  }\n}", 0)]
    [InlineData("audit \"file\" \"file\" {\n  options {\n    log_raw = true\n  }\n}", 1)]
    [InlineData("audit \"file\" \"file\" {\n  options {\n    log_raw = \"true\"\n  }\n}", 1)]
    [InlineData("audit \"file\" \"file\" {\n  options {\n    hmac_accessor = false\n  }\n}", 1)]
    [InlineData("audit \"file\" \"file\" {\n  options {\n    hmac_accessor = \"false\"\n  }\n}", 1)]
    [InlineData("audit \"file\" \"file\" {\n  options {\n    elide_list_responses = false\n  }\n}", 1)]
    [InlineData("audit \"file\" \"file\" {\n  options {\n    hmac_accessor = true\n  }\n}", 0)]
    public void Audit_violation_detection(string config, int violations)
    {
        Assert.Equal(violations, AuditViolations(config).Count);
    }

    private static List<string> AuditViolations(string config) =>
    [
        .. Regex.Matches(config, @"\blog_raw\b").Select(_ => "log_raw"),
        .. Regex.Matches(config, @"\bhmac_accessor\s*=\s*""?false""?").Select(_ => "hmac_accessor = false"),
        .. Regex.Matches(config, @"\belide_list_responses\s*=\s*""?false""?").Select(_ => "elide_list_responses = false"),
    ];

    [Fact]
    public void No_deploy_file_is_a_systemd_unit()
    {
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(Root, "deploy"), "*.service", SearchOption.AllDirectories));
    }

    /// <summary>The openbao service's lines in compose.yaml, up to the next service.</summary>
    private static string OpenBaoService(string compose)
    {
        var match = Regex.Match(compose.ReplaceLineEndings("\n"), @"(?m)^  openbao:\n(?<body>(?:(?:    .*)?\n)*)");
        return match.Success ? match.Groups["body"].Value : string.Empty;
    }

    private static List<string> PolicyViolations(string policy)
    {
        var code = HclComment.Replace(policy, string.Empty);
        var violations = new List<string>();
        var paths = PolicyPath.Matches(code);

        if (paths.Count == 0)
        {
            violations.Add("no path");
        }

        foreach (Match match in paths)
        {
            var path = match.Groups["path"].Value;
            var body = match.Groups["body"].Value;

            // The key list (Story 2.4's orphan sweep) shows names only, so it may list and do nothing else.
            if (path == ListPath)
            {
                if (Capabilities.Match(body).Groups["caps"].Value.Trim() != "\"list\"")
                {
                    violations.Add($"{path}: may only list");
                }

                continue;
            }

            if (!AllowedPolicyPath.IsMatch(path))
            {
                violations.Add($"{path}: not an allowed Transit path");
                continue;
            }

            var caps = Capabilities.Match(body).Groups["caps"].Value;
            var writesKey = path.StartsWith("transit/keys/", StringComparison.Ordinal)
                && (caps.Contains("\"update\"", StringComparison.Ordinal) || caps.Contains("\"create\"", StringComparison.Ordinal));
            var denied = DeniedParameters.Match(body).Groups["body"].Value;

            if (writesKey && !(denied.Contains("\"exportable\"", StringComparison.Ordinal)
                && denied.Contains("\"allow_plaintext_backup\"", StringComparison.Ordinal)))
            {
                violations.Add($"{path}: creates or configures keys without denying exportable and allow_plaintext_backup");
            }
        }

        return violations;
    }

    private static List<string> ListenerViolations(string config, string service)
    {
        var listeners = Listener.Matches(HclComment.Replace(config, string.Empty));
        var violations = new List<string>();

        if (!listeners.Any(l => l.Groups["type"].Value == "unix"))
        {
            violations.Add("no unix socket listener");
        }

        foreach (Match listener in listeners.Where(l => l.Groups["type"].Value != "unix"))
        {
            var loopback = Regex.IsMatch(listener.Groups["body"].Value, @"\baddress\s*=\s*""127\.0\.0\.1:\d+""");
            // With no network, the loopback is the container's own.
            var isolated = Regex.IsMatch(service, @"(?m)^[ \t]*network_mode:[ \t]*none[ \t]*$");

            if (listener.Groups["type"].Value != "tcp" || !loopback || !isolated)
            {
                violations.Add($"{listener.Groups["type"].Value} listener reachable outside OpenBao's own network namespace");
            }
        }

        return violations;
    }

    private static string Relative(string file) => Path.GetRelativePath(Root, file).Replace('\\', '/');

    private static IEnumerable<string> SourceFiles(string directory)
    {
        var nested = Directory.EnumerateDirectories(directory)
            .Where(d => !SkippedDirectories.Contains(Path.GetFileName(d)))
            .SelectMany(SourceFiles);

        return Directory.EnumerateFiles(directory, "*.cs").Concat(nested);
    }
}
