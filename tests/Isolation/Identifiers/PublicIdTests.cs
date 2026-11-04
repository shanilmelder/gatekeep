using System.Text;
using Gatekeep.Kernel.Identifiers;
using Xunit;

namespace Gatekeep.Tests.Isolation.Identifiers;

/// <summary>
/// Story 1.24, spine Conventions: a Tenant's public ID is <c>ten_</c> and the UUID's 16 bytes in
/// lowercase RFC 4648 base32 with no padding. It round-trips, matches an independent encoding,
/// and only the one canonical spelling parses: uppercase, padding, the wrong length, another
/// prefix, non-zero trailing bits, a raw UUID and the empty UUID are all malformed.
/// </summary>
public sealed class PublicIdTests
{
    private const string Alphabet = "abcdefghijklmnopqrstuvwxyz234567";

    private static readonly Guid Sample = Guid.Parse("01900000-0000-7000-8000-0000000007a8");

    [Fact]
    public void Every_bit_set_is_twenty_five_sevens_and_a_four()
    {
        var id = Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff");

        Assert.Equal("ten_" + new string('7', 25) + "4", PublicId.Format(PublicIdType.Tenant, id));
    }

    [Fact]
    public void Random_IDs_match_an_independent_encoding_and_round_trip()
    {
        for (var i = 0; i < 1000; i++)
        {
            var id = Guid.NewGuid();
            var formatted = PublicId.Format(PublicIdType.Tenant, id);

            Assert.Equal(Independent(id), formatted);
            Assert.Matches(@"\Aten_[a-z2-7]{26}\z", formatted);
            Assert.True(PublicId.TryParse(PublicIdType.Tenant, formatted, out var parsed), formatted);
            Assert.Equal(id, parsed);
        }
    }

    [Fact]
    public void Big_endian_UUID_bytes_are_encoded_in_RFC_order()
    {
        // 0x01 0x90 then zeros: 00000 00110 01000 0… → a, g, i, a…
        Assert.StartsWith("ten_agia", PublicId.Format(PublicIdType.Tenant, Sample));
    }

    public static TheoryData<string> Malformed()
    {
        var canonical = PublicId.Format(PublicIdType.Tenant, Sample);
        var body = canonical["ten_".Length..];
        var last = body[^1];
        var nonZeroTrailing = Alphabet[Alphabet.IndexOf(last, StringComparison.Ordinal) | 1];

        return new TheoryData<string>
        {
            string.Empty,
            canonical.ToUpperInvariant(),
            "TEN_" + body,
            "ten_" + body.ToUpperInvariant(),
            canonical + "======",
            canonical + "=",
            canonical[..^1],
            canonical + "a",
            "usr_" + body,
            "ten-" + body,
            "ten" + body,
            "_" + body,
            body,
            canonical[..^1] + nonZeroTrailing,
            canonical[..^1] + "7",
            " " + canonical,
            canonical + " ",
            "ten_" + body[..^2] + "01",
            "ten_" + body[..^1] + "8",
            Sample.ToString(),
            Sample.ToString("N"),
            "ten_" + new string('a', 26),
        };
    }

    [Theory]
    [MemberData(nameof(Malformed))]
    public void Only_the_canonical_spelling_parses(string? text)
    {
        Assert.False(PublicId.TryParse(PublicIdType.Tenant, text, out var id));
        Assert.Equal(Guid.Empty, id);
    }

    [Fact]
    public void Null_doesnt_parse()
    {
        Assert.False(PublicId.TryParse(PublicIdType.Tenant, null, out var id));
        Assert.Equal(Guid.Empty, id);
    }

    [Fact]
    public void Undefined_type_doesnt_parse_and_doesnt_throw()
    {
        var canonical = PublicId.Format(PublicIdType.Tenant, Sample);

        Assert.False(PublicId.TryParse((PublicIdType)99, canonical, out var id));
        Assert.Equal(Guid.Empty, id);
    }

    [Fact]
    public void Empty_UUID_has_no_public_ID()
    {
        Assert.Throws<ArgumentException>(() => PublicId.Format(PublicIdType.Tenant, Guid.Empty));
    }

    /// <summary>The 128 bits as text, two zero bits added, read five at a time.</summary>
    private static string Independent(Guid id)
    {
        var bits = new StringBuilder();
        foreach (var b in id.ToByteArray(bigEndian: true))
        {
            bits.Append(Convert.ToString(b, 2).PadLeft(8, '0'));
        }

        bits.Append("00");
        var text = new StringBuilder("ten_");
        for (var i = 0; i < bits.Length; i += 5)
        {
            text.Append(Alphabet[Convert.ToInt32(bits.ToString(i, 5), 2)]);
        }

        return text.ToString();
    }
}
