using System.Text.Json;
using Gatekeep.Modules.Tenancy.Contracts;
using Gatekeep.Tests.Isolation.Stack;
using Xunit;

namespace Gatekeep.Tests.Isolation.Tenancy;

/// <summary>
/// Story 1.27 (FR-7, AD-6): the Tenant Subdomain, name, label, zone and address rules, with no
/// database. The subdomain vectors are the dashboard's own file, so the browser and server rules
/// can't drift.
/// </summary>
public sealed class TenantValueTests
{
    private const string Zone = "gatekeep.test";

    private static readonly JsonElement Vectors = JsonDocument.Parse(
        File.ReadAllText(Path.Combine(Repository.Root, "apps", "admin-dashboard", "test", "tenant-subdomain-vectors.json"))).RootElement;

    public static TheoryData<string> Malformed() => [.. Vector("malformed")];

    public static TheoryData<string> Reserved() => [.. Vector("reserved")];

    public static TheoryData<string> Valid() => [.. Vector("valid")];

    [Theory]
    [MemberData(nameof(Malformed))]
    public void Malformed_subdomain_is_refused(string value)
    {
        Assert.False(TenantSubdomain.IsWellFormed(value));
        Assert.False(TenantSubdomain.TryParse(value, Zone, out _));
    }

    [Theory]
    [MemberData(nameof(Reserved))]
    public void Reserved_subdomain_is_well_formed_and_refused(string value)
    {
        Assert.True(TenantSubdomain.IsWellFormed(value));
        Assert.True(ReservedSubdomains.Contains(value));
        Assert.False(TenantSubdomain.TryParse(value, Zone, out _));
    }

    [Theory]
    [MemberData(nameof(Valid))]
    public void Valid_subdomain_is_taken_exactly_as_sent(string value)
    {
        Assert.True(TenantSubdomain.TryParse(value, Zone, out var subdomain));
        Assert.Equal(value, subdomain.Value);
    }

    [Fact]
    public void Matrix_values_are_in_the_shared_vectors()
    {
        var malformed = Vector("malformed").ToList();
        Assert.All(new[] { "Acme", "ab", "-acme", "acme-", "xn--acme", "ac--me", "a_b", " acme", new string('a', 64) }, v => Assert.Contains(v, malformed));
        var reserved = Vector("reserved").ToList();
        Assert.All(new[] { "admin", "www", "mta-sts" }, v => Assert.Contains(v, reserved));
    }

    [Fact]
    public void Every_reserved_name_of_three_or_more_is_well_formed()
    {
        Assert.Equal(53, ReservedSubdomains.All.Count);

        // id, mx and ns are below the length rule anyway; the list names them so it stands alone.
        Assert.All(ReservedSubdomains.All.Where(n => n.Length >= TenantSubdomain.MinLength), n => Assert.True(TenantSubdomain.IsWellFormed(n), n));
        Assert.Equal(["id", "mx", "ns"], ReservedSubdomains.All.Where(n => n.Length < TenantSubdomain.MinLength).Order(StringComparer.Ordinal));
        Assert.True(ReservedSubdomains.Contains("mta-sts"));
        Assert.True(ReservedSubdomains.Contains("gatekeep"));
    }

    [Fact]
    public void Whole_host_is_at_most_253_characters()
    {
        var zone = string.Join('.', Enumerable.Repeat(new string('z', 62), 3)) + ".test";
        Assert.True(TenantZone.IsValid(zone));

        var longest = new string('a', 253 - 1 - zone.Length);
        Assert.True(TenantSubdomain.TryParse(longest, zone, out _));
        Assert.False(TenantSubdomain.TryParse(longest + "a", zone, out _));
    }

    [Theory]
    [InlineData(443, "https://acme-dev.gatekeep.test/")]
    [InlineData(8443, "https://acme-dev.gatekeep.test:8443/")]
    public void Address_is_derived_once_with_the_port_only_when_it_isnt_443(int port, string issuer)
    {
        Assert.True(TenantSubdomain.TryParse("acme-dev", Zone, out var subdomain));

        var address = TenantAddress.For(subdomain, Zone, port);

        Assert.Equal("acme-dev.gatekeep.test", address.Host);
        Assert.Equal(issuer, address.Issuer);
        Assert.Equal("acme-dev.gatekeep.test", address.RpId);
        Assert.Equal(issuer, address.EmailLinkBase);

        // The origin-only form the Story 2.1 spike compares against.
        Assert.Equal(issuer, new Uri(issuer).AbsoluteUri);
    }

    [Theory]
    [InlineData("gatekeep.test", true)]
    [InlineData("tenants.example.com", true)]
    [InlineData("a-b.c1", true)]
    [InlineData("localhost", false)]
    [InlineData("", false)]
    [InlineData("Gatekeep.test", false)]
    [InlineData("-a.test", false)]
    [InlineData("a-.test", false)]
    [InlineData("a..test", false)]
    [InlineData(".gatekeep.test", false)]
    [InlineData("gatekeep.test.", false)]
    [InlineData("gate_keep.test", false)]
    public void Zone_is_lower_case_LDH_labels_at_least_two(string zone, bool valid)
    {
        Assert.Equal(valid, TenantZone.IsValid(zone));
    }

    [Fact]
    public void Zone_is_at_most_200_characters()
    {
        var zone = new string('a', 60) + "." + new string('b', 60) + "." + new string('c', 60) + "." + new string('d', 17);
        Assert.Equal(200, zone.Length);
        Assert.True(TenantZone.IsValid(zone));
        Assert.False(TenantZone.IsValid(zone + "d"));
    }

    [Theory]
    [InlineData("gatekeep.test", "gatekeep.test", true)]
    [InlineData("gatekeep.test", "admin.gatekeep.test", true)]
    [InlineData("gatekeep.test", "ADMIN.Gatekeep.Test", true)]
    [InlineData("gatekeep.test", "admin.gatekeep-admin.test", false)]
    [InlineData("gatekeep.test", "notgatekeep.test", false)]
    public void Zone_covers_itself_and_names_under_it(string zone, string host, bool covered)
    {
        Assert.Equal(covered, TenantZone.Covers(zone, host));
    }

    [Theory]
    [InlineData("Acme Dev", "Acme Dev")]
    [InlineData("  Acme  ", "Acme")]
    [InlineData("Ünïcødé 🙂", "Ünïcødé 🙂")]
    public void Name_is_trimmed(string text, string expected)
    {
        Assert.True(TenantName.TryNormalize(text, out var name));
        Assert.Equal(expected, name);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("a\u0007b")]
    [InlineData("a\u0000b")]
    [InlineData("a\nb")]
    [InlineData("a\u009Fb")]
    public void Empty_or_control_name_is_refused(string text)
    {
        Assert.False(TenantName.TryNormalize(text, out _));
    }

    [Theory]
    [InlineData("a\u200Bb")]
    [InlineData("a\u200Eb")]
    [InlineData("a\u202Eb")]
    [InlineData("a\u2066b")]
    [InlineData("a\uFEFFb")]
    public void Name_with_a_format_character_is_refused(string text)
    {
        Assert.False(TenantName.TryNormalize(text, out _));
    }

    /// <summary>The dashboard's own name vectors, so the browser and server rules can't drift.</summary>
    [Fact]
    public void Name_rule_agrees_with_the_dashboard_vectors()
    {
        var vectors = JsonDocument.Parse(
            File.ReadAllText(Path.Combine(Repository.Root, "apps", "admin-dashboard", "test", "tenant-name-vectors.json"))).RootElement;

        // Decoded from the raw JSON: System.Text.Json refuses a lone surrogate, which the vectors hold on purpose.
        static string Text(JsonElement value) => System.Text.RegularExpressions.Regex.Unescape(value.GetRawText()[1..^1]);

        Assert.All(vectors.GetProperty("valid").EnumerateArray(), v => Assert.True(TenantName.TryNormalize(Text(v), out _), v.GetRawText()));
        Assert.All(vectors.GetProperty("invalid").EnumerateArray(), v => Assert.False(TenantName.TryNormalize(Text(v), out _), v.GetRawText()));
    }

    [Fact]
    public void Name_with_a_lone_surrogate_is_refused()
    {
        // Built here, not as theory data, whose serialization replaces a lone surrogate first.
        foreach (var text in new[] { "a" + (char)0xD800 + "b", "a" + (char)0xDC00, (char)0xDBFF + "x", "x" + (char)0xD800 })
        {
            Assert.False(TenantName.TryNormalize(text, out _));
        }
    }

    [Fact]
    public void Name_is_at_most_100_characters_after_trimming()
    {
        Assert.True(TenantName.TryNormalize(" " + new string('n', 100) + " ", out _));
        Assert.False(TenantName.TryNormalize(new string('n', 101), out _));
        Assert.False(TenantName.TryNormalize(null, out _));
    }

    [Theory]
    [InlineData("dev", TenantLabel.Dev)]
    [InlineData("staging", TenantLabel.Staging)]
    [InlineData("prod", TenantLabel.Prod)]
    public void Label_is_one_of_three_stored_spellings(string text, TenantLabel label)
    {
        Assert.True(TenantValues.TryParseLabel(text, out var parsed));
        Assert.Equal(label, parsed);
        Assert.Equal(text, TenantValues.Stored(label));
    }

    [Theory]
    [InlineData("production")]
    [InlineData("Dev")]
    [InlineData(" dev")]
    [InlineData("")]
    [InlineData(null)]
    public void Other_label_is_refused(string? text)
    {
        Assert.False(TenantValues.TryParseLabel(text, out _));
    }

    private static IEnumerable<string> Vector(string name) =>
        Vectors.GetProperty(name).EnumerateArray().Select(v => v.GetString()!);
}
