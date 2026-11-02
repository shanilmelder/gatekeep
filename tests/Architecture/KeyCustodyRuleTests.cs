using System.Text.RegularExpressions;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>AD-10 rules: every key is reached through <c>IKeyCustody</c>, and the policies can't export.</summary>
public class KeyCustodyRuleTests
{
    private const string AdapterDirectory = "src/Adapters/OpenBao/";
    private const string DeployDirectory = "deploy/openbao";

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
    public void Policy_violation_detection(string policy, int violations)
    {
        Assert.Equal(violations, PolicyViolations(policy).Count);
    }

    [Fact]
    public void Production_config_has_no_listener_beyond_the_socket_and_its_private_loopback()
    {
        var violations = ListenerViolations(
            File.ReadAllText(Path.Combine(Root, DeployDirectory, "openbao.hcl")),
            File.ReadAllText(Path.Combine(Root, DeployDirectory, "openbao.service")));

        Assert.Empty(violations);
    }

    [Theory]
    [InlineData("listener \"unix\" { address = \"/run/openbao/openbao.sock\" }", "PrivateNetwork=yes", 0)]
    [InlineData("listener \"unix\" { address = \"/run/openbao/openbao.sock\" }\nlistener \"tcp\" {\n address = \"127.0.0.1:8200\"\n}", "PrivateNetwork=yes", 0)]
    [InlineData("listener \"unix\" { address = \"/run/openbao/openbao.sock\" }\nlistener \"tcp\" {\n address = \"0.0.0.0:8200\"\n}", "PrivateNetwork=yes", 1)]
    [InlineData("listener \"unix\" { address = \"/run/openbao/openbao.sock\" }\nlistener \"tcp\" {\n address = \"127.0.0.1:8200\"\n}", "", 1)]
    [InlineData("listener \"tcp\" {\n address = \"127.0.0.1:8200\"\n}", "PrivateNetwork=yes", 1)]
    public void Listener_violation_detection(string config, string unit, int violations)
    {
        Assert.Equal(violations, ListenerViolations(config, unit).Count);
    }

    [Fact]
    public void Unit_hands_the_key_over_by_plain_LoadCredential_only()
    {
        var unit = File.ReadAllText(Path.Combine(Root, DeployDirectory, "openbao.service"));
        var directives = HclComment.Replace(unit, string.Empty);

        Assert.Contains("LoadCredential=master-key:/srv/gatekeep/keys/master-key", directives);
        Assert.Contains("RequiresMountsFor=/srv/gatekeep/keys /var/lib/openbao", directives);
        Assert.Contains("User=openbao", directives);
        Assert.DoesNotContain("LoadCredentialEncrypted", directives);
        Assert.DoesNotContain("systemd-creds", directives);
        Assert.DoesNotContain("EnvironmentFile", directives);
        Assert.DoesNotContain("Environment=", directives);
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

    private static List<string> ListenerViolations(string config, string unit)
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
            var isolated = HclComment.Replace(unit, string.Empty).Contains("PrivateNetwork=yes", StringComparison.Ordinal);

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
