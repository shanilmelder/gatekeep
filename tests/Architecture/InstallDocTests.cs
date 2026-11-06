using System.Text.RegularExpressions;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// Story 1.12: the Operator installs from <c>docs/install.md</c> alone, so every topic the
/// install depends on must stay in it. Each topic is a heading or key phrase; removing one
/// fails the build and names the topic.
/// </summary>
public class InstallDocTests
{
    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly Dictionary<string, string[]> Topics = new()
    {
        ["wildcard DNS"] =
        [
            @"add `\*\.id\.example\.com` and `admin\.example\.com` as `A` records to the Docker host's public IPv4 address",
            @"Don't add `AAAA` records",
            @"Set both to \*\*DNS only\*\* \(grey cloud\), never proxied",
        ],
        ["TLS modes"] =
        [
            @"^### TLS modes$",
            @"^- \*\*`internal`\*\*",
            @"^- \*\*`cloudflare`\*\*",
        ],
        ["dedicated Tenant zone"] =
        [
            @"\*\*The Tenant zone is used only by Gatekeep\*\* \(NFR-21\)",
            @"No application, mail server or other host may have a name under it, the zone itself included",
            @"separate \*\*validation-only zone\*\* that holds nothing else",
        ],
        ["CAA records"] =
        [
            @"\*\*CAA records\.\*\*",
            @"CAA 0 issue ""letsencrypt\.org""",
            @"CAA 0 issue ""sectigo\.com""",
            @"CAA 0 issuewild ""letsencrypt\.org""",
            @"CAA 0 issuewild ""sectigo\.com""",
            @"Add an `iodef` address",
        ],
        ["validation-only DNS credential"] =
        [
            @"separate \*\*validation-only zone\*\*",
            @"`Zone : DNS : Edit`",
            @"`Zone : Zone : Read`",
            @"include \*\*only\*\* the validation zone",
            @"`cloudflare/dns-token`",
            @"Give the file mode `0400`, owned by uid `10005`",
            @"never in an environment variable",
        ],
        ["Admin hostname outside the Tenant zone"] =
        [
            @"\*\*The Admin hostname must be outside the Tenant zone\*\*",
            @"never `admin\.id\.example\.com`",
        ],
        ["Docker host requirements"] =
        [
            @"^## What the Docker host must provide$",
        ],
        ["encrypted disks for volumes and the secrets directory"] =
        [
            @"\*\*Encrypted disks\*\* for Docker's data \(the named volumes\) and for the secrets directory",
        ],
        ["firewall allowing only Caddy's ports"] =
        [
            @"\*\*A host firewall\*\* that allows only the ports Compose publishes",
            @"Only Caddy publishes, on TCP 80 and 443\. Allow those two inbound and nothing else",
        ],
        ["Docker access equals full control"] =
        [
            @"\*\*Docker access is full control\*\*",
            @"Treat Docker access as root on Gatekeep",
        ],
        ["what isn't covered yet"] =
        [
            @"^## Not yet covered$",
        ],
        ["Admin Dashboard below 768px is unsupported (NFR-17)"] =
        [
            @"^## Using the Admin Dashboard$",
            @"\*\*Below 768px: unsupported\.\*\*",
        ],
        ["the Tenant switcher and environment, with Applications from Story 3.1 and other settings from Story 8.5"] =
        [
            @"\*\*A working Admin Dashboard\.\*\*[^\n]*creates and lists Tenants[^\n]*Tenant switcher[^\n]*environment[^\n]*from Story 3\.1 on[^\n]*Story 8\.5",
        ],
        ["no Certificate Transparency alerts yet (Epic 11)"] =
        [
            @"\*\*Certificate Transparency alerts\.\*\*[^\n]*\(Epic 11\)",
            @"search crt\.sh",
        ],
        ["no emergency certificate replacement yet (Story 13.6)"] =
        [
            @"\*\*Emergency certificate replacement\.\*\*[^\n]*\(Story 13\.6\)",
        ],
        ["no backups or upgrades yet (Epic 12)"] =
        [
            @"\*\*Backups and upgrades\.\*\*[^\n]*\(Epic 12",
        ],
        ["alert channel and off-server bucket (Story 1.30)"] =
        [
            @"^9\. \*\*Connect the alert channel and the off-server bucket\.\*\*",
            @"^## Alert channel and off-server bucket$",
            @"\*\*The alert channel: an HTTPS webhook\*\*",
            @"The webhook's URL must carry no credential",
            @"\*\*The off-server bucket: an S3-API bucket on a separate provider\*\*",
            @"\*\*versioning and Object Lock\*\* on, and a default retention in \*\*compliance\*\* mode of \*\*at least 90 days\*\*",
            @"\*\*A write-only credential for the server\.\*\*[^\n]*no read, list, delete, version delete or governance bypass",
            @"""Action"": \[""s3:PutObject"", ""s3:PutObjectRetention""\]",
            @"^\| `GATEKEEP_ALERT_URL` \|",
            @"^\| `GATEKEEP_RECORDS_ENDPOINT` \|",
            @"^\| `GATEKEEP_RECORDS_REGION` \|",
            @"^\| `GATEKEEP_RECORDS_BUCKET` \|",
            @"^\| `alerts/token` \|",
            @"^\| `records/access-key-id` \|",
            @"^\| `records/secret-access-key` \|",
            @"docker compose -f deploy/compose\.yaml run --rm cli alerts test",
            @"docker compose -f deploy/compose\.yaml run --rm cli records test",
            @"^### The audit shipper$",
        ],
        ["the egress network (Story 1.30)"] =
        [
            @"`egress` \(Story 1\.30\), which only `Host\.Worker`, the `cli` and the audit shipper join",
            @"`Host\.Hosted` and `Host\.Admin` have no egress",
            @"The `egress` network that `Host\.Worker`, the `cli` and the audit shipper join \(Story 1\.30\) is the same",
        ],
    };

    public static TheoryData<string> TopicNames => [.. Topics.Keys];

    private static string InstallDoc() =>
        File.ReadAllText(Path.Combine(Root, "docs", "install.md")).ReplaceLineEndings("\n");

    [Theory]
    [MemberData(nameof(TopicNames))]
    public void Install_doc_covers_topic(string topic)
    {
        var missing = MissingPhrases(InstallDoc(), topic);
        Assert.True(
            missing.Count == 0,
            $"docs/install.md no longer covers {topic}: {string.Join("; ", missing.Select(p => $"'{p}' not found"))}.");
    }

    [Theory]
    [InlineData("CAA 0 issuewild \"letsencrypt.org\"", "CAA 0 issue \"letsencrypt.org\"", "CAA records")]
    [InlineData("## Not yet covered", "## Later", "what isn't covered yet")]
    [InlineData("(Story 13.6)", "(later)", "no emergency certificate replacement yet (Story 13.6)")]
    [InlineData("**The Tenant zone is used only by Gatekeep**", "**The Tenant zone**", "dedicated Tenant zone")]
    [InlineData("TCP 80 and 443", "any port", "firewall allowing only Caddy's ports")]
    [InlineData("`Zone : Zone : Read`", "`Zone : Read`", "validation-only DNS credential")]
    [InlineData("include **only** the validation zone", "include the zones", "validation-only DNS credential")]
    [InlineData("owned by uid `10005`", "owned by root", "validation-only DNS credential")]
    [InlineData("for Docker's data (the named volumes) and for the secrets directory", "for Docker's data", "encrypted disks for volumes and the secrets directory")]
    [InlineData("**Docker access is full control**", "**Docker access**", "Docker access equals full control")]
    [InlineData("search crt.sh", "check", "no Certificate Transparency alerts yet (Epic 11)")]
    [InlineData("(Epic 11)", "(later)", "no Certificate Transparency alerts yet (Epic 11)")]
    [InlineData("**Backups and upgrades.**", "**Upgrades.**", "no backups or upgrades yet (Epic 12)")]
    [InlineData("`admin.example.com` as `A` records", "`admin.example.com` as `CNAME` records", "wildcard DNS")]
    [InlineData(", the zone itself included", "", "dedicated Tenant zone")]
    [InlineData("**The Admin hostname must be outside the Tenant zone**", "**The Admin hostname**", "Admin hostname outside the Tenant zone")]
    [InlineData("mode of **at least 90 days**", "mode of **at least 30 days**", "alert channel and off-server bucket (Story 1.30)")]
    [InlineData("\"Action\": [\"s3:PutObject\", \"s3:PutObjectRetention\"]", "\"Action\": [\"s3:*\"]", "alert channel and off-server bucket (Story 1.30)")]
    [InlineData("`Host.Hosted` and `Host.Admin` have no egress", "`Host.Hosted` has no egress", "the egress network (Story 1.30)")]
    public void Altered_text_is_detected(string original, string replacement, string topic)
    {
        var doc = InstallDoc();
        Assert.Contains(original, doc, StringComparison.Ordinal);

        Assert.Contains(topic, MissingTopics(doc.Replace(original, replacement, StringComparison.Ordinal)));
    }

    private static List<string> MissingTopics(string markdown) =>
        [.. Topics.Keys.Where(topic => MissingPhrases(markdown, topic).Count > 0)];

    private static List<string> MissingPhrases(string markdown, string topic) =>
        [.. Topics[topic].Where(pattern => !Pattern(pattern).IsMatch(markdown))];

    private static Regex Pattern(string pattern) => new(pattern, RegexOptions.Multiline);
}
