using System.Security.Cryptography;
using System.Text;
using Gatekeep.Modules.Audit.Contracts;
using Xunit;

namespace Gatekeep.Tests.Isolation.Audit;

/// <summary>RFC 8785 output and the AD-16 envelope and hash, with no database.</summary>
public sealed class CanonicalJsonTests
{
    private static readonly ChainEnvelope Envelope = new(
        TenantId: Guid.Parse("0190ABCD-0000-7000-8000-00000000000A"),
        Id: Guid.Parse("0190ABCD-0000-7000-8000-0000000000E1"),
        OccurredAt: new DateTimeOffset(2026, 11, 2, 9, 30, 15, TimeSpan.FromHours(2)).AddTicks(1234560),
        TypeCode: "tenancy.settings.updated",
        ActorKind: "admin",
        ActorId: Guid.Parse("0190ABCD-0000-7000-8000-0000000000A1"),
        TargetKind: "tenant",
        TargetId: Guid.Parse("0190ABCD-0000-7000-8000-00000000000A"),
        Epoch: 1,
        Seq: 7);

    private const string ExpectedEnvelope =
        """{"actor_id":"0190abcd-0000-7000-8000-0000000000a1","actor_kind":"admin","epoch":1,"id":"0190abcd-0000-7000-8000-0000000000e1","occurred_at":"2026-11-02T07:30:15.123456Z","seq":7,"target_id":"0190abcd-0000-7000-8000-00000000000a","target_kind":"tenant","tenant_id":"0190abcd-0000-7000-8000-00000000000a","type_code":"tenancy.settings.updated"}""";

    [Fact]
    public void Keys_are_sorted_with_no_whitespace()
    {
        var json = AuditContract.CanonicalJson([new("b", 2), new("a", "x"), new("c", null)]);

        Assert.Equal("""{"a":"x","b":2,"c":null}""", json);
    }

    [Fact]
    public void Empty_object_is_two_braces()
    {
        Assert.Equal("{}", AuditContract.CanonicalJson([]));
    }

    [Fact]
    public void Keys_sort_by_UTF16_code_units_as_RFC_8785_shows()
    {
        // RFC 8785 section 3.2.3: the surrogate pair sorts before U+FB33, by code unit.
        string[] keys = ["\u20ac", "\r", "\ufb33", "1", "\ud83d\ude00", "\u0080", "\u00f6"];

        var json = AuditContract.CanonicalJson(keys.Select(k => new KeyValuePair<string, object?>(k, null)));

        Assert.Equal("{\"\\r\":null,\"1\":null,\"\u0080\":null,\"\u00f6\":null,\"\u20ac\":null,\"\ud83d\ude00\":null,\"\ufb33\":null}", json);
    }

    [Fact]
    public void Control_characters_use_the_short_escapes_and_lower_case_hex()
    {
        var json = AuditContract.CanonicalJson([new("v", "\u0000\u0001\b\t\n\u000b\f\r\u001f\"\\/")]);

        Assert.Equal("""{"v":"\u0000\u0001\b\t\n\u000b\f\r\u001f\"\\/"}""", json);
    }

    [Fact]
    public void Non_ASCII_text_is_written_as_itself_in_UTF8()
    {
        const string text = "\u00f6\u20ac\u2028\u007f\ud83d\ude00";

        var json = AuditContract.CanonicalJson([new("v", text)]);

        Assert.Equal("{\"v\":\"" + text + "\"}", json);
        Assert.Equal(
            "7B2276223A22C3B6E282ACE280A87FF09F988022" + "7D",
            Convert.ToHexString(Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void Integers_are_plain_decimals_up_to_the_I_JSON_limit()
    {
        var json = AuditContract.CanonicalJson(
            [new("max", 9_007_199_254_740_991L), new("min", -9_007_199_254_740_991L), new("zero", 0), new("int", -5)]);

        Assert.Equal("""{"int":-5,"max":9007199254740991,"min":-9007199254740991,"zero":0}""", json);
    }

    [Theory]
    [InlineData(9_007_199_254_740_992L)]
    [InlineData(-9_007_199_254_740_992L)]
    [InlineData(long.MaxValue)]
    public void Integer_beyond_the_I_JSON_limit_is_refused(long value)
    {
        Assert.Throws<ArgumentException>(() => AuditContract.CanonicalJson([new("v", value)]));
    }

    [Theory]
    // Built here, not in attributes: metadata stores attribute strings as UTF-8, which can't hold a lone surrogate.
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void Lone_surrogate_is_refused(int which)
    {
        var text = which switch
        {
            0 => "\ud83d",
            1 => "\ude00",
            _ => "a\ude00\ud83d",
        };


        Assert.Throws<ArgumentException>(() => AuditContract.CanonicalJson([new("v", text)]));
        Assert.Throws<ArgumentException>(() => AuditContract.CanonicalJson([new(text, null)]));
    }

    [Fact]
    public void Repeated_key_is_refused()
    {
        Assert.Throws<ArgumentException>(() => AuditContract.CanonicalJson([new("a", 1), new("a", 2)]));
    }

    [Fact]
    public void Value_of_another_type_is_refused()
    {
        Assert.Throws<ArgumentException>(() => AuditContract.CanonicalJson([new("v", 1.5)]));
        Assert.Throws<ArgumentException>(() => AuditContract.CanonicalJson([new("v", true)]));
    }

    [Fact]
    public void Envelope_has_every_member_sorted_with_lower_case_IDs_and_UTC_microseconds()
    {
        Assert.Equal(ExpectedEnvelope, AuditContract.CanonicalEnvelope(Envelope));
    }

    [Fact]
    public void Deployment_envelope_has_a_null_Tenant_and_absent_values_are_null()
    {
        var deployment = Envelope with { TenantId = null, ActorKind = "system", ActorId = null, TargetKind = null, TargetId = null };

        Assert.Equal(
            """{"actor_id":null,"actor_kind":"system","epoch":1,"id":"0190abcd-0000-7000-8000-0000000000e1","occurred_at":"2026-11-02T07:30:15.123456Z","seq":7,"target_id":null,"target_kind":null,"tenant_id":null,"type_code":"tenancy.settings.updated"}""",
            AuditContract.CanonicalEnvelope(deployment));
    }

    [Fact]
    public void Checkpoint_envelope_adds_its_three_members_with_lower_case_hex()
    {
        var checkpoint = Envelope with
        {
            TypeCode = "audit.retention.checkpoint",
            ActorKind = "system",
            ActorId = null,
            TargetKind = null,
            TargetId = null,
            CheckpointEpoch = 1,
            CheckpointSeq = 6,
            CheckpointHash = [0x0A, 0xBC, 0xFF],
        };

        Assert.Equal(
            """{"actor_id":null,"actor_kind":"system","checkpoint_epoch":1,"checkpoint_hash":"0abcff","checkpoint_seq":6,"epoch":1,"id":"0190abcd-0000-7000-8000-0000000000e1","occurred_at":"2026-11-02T07:30:15.123456Z","seq":7,"target_id":null,"target_kind":null,"tenant_id":"0190abcd-0000-7000-8000-00000000000a","type_code":"audit.retention.checkpoint"}""",
            AuditContract.CanonicalEnvelope(checkpoint));
    }

    [Fact]
    public void Genesis_hash_is_over_the_envelope_alone()
    {
        var expected = SHA256.HashData(Encoding.UTF8.GetBytes(ExpectedEnvelope));

        Assert.Equal(expected, AuditContract.ChainHashOf(null, Envelope));
    }

    [Fact]
    public void Linked_hash_is_over_the_previous_hash_then_the_envelope()
    {
        var previous = SHA256.HashData("previous"u8);
        var expected = SHA256.HashData([.. previous, .. Encoding.UTF8.GetBytes(ExpectedEnvelope)]);

        Assert.Equal(expected, AuditContract.ChainHashOf(previous, Envelope));
    }

    [Theory]
    [InlineData("actor_id")]
    [InlineData("actor_kind")]
    [InlineData("epoch")]
    [InlineData("id")]
    [InlineData("occurred_at")]
    [InlineData("seq")]
    [InlineData("target_id")]
    [InlineData("target_kind")]
    [InlineData("tenant_id")]
    [InlineData("type_code")]
    public void Changing_any_envelope_member_changes_the_hash(string member)
    {
        var other = Guid.Parse("0190ABCD-0000-7000-8000-0000000000FF");
        var changed = member switch
        {
            "actor_id" => Envelope with { ActorId = other },
            "actor_kind" => Envelope with { ActorKind = "user" },
            "epoch" => Envelope with { Epoch = 2 },
            "id" => Envelope with { Id = other },
            "occurred_at" => Envelope with { OccurredAt = Envelope.OccurredAt.AddTicks(10) },
            "seq" => Envelope with { Seq = 8 },
            "target_id" => Envelope with { TargetId = other },
            "target_kind" => Envelope with { TargetKind = "user" },
            "tenant_id" => Envelope with { TenantId = other },
            "type_code" => Envelope with { TypeCode = "tenancy.settings.deleted" },
            _ => throw new ArgumentOutOfRangeException(nameof(member)),
        };

        Assert.NotEqual(AuditContract.CanonicalEnvelope(Envelope), AuditContract.CanonicalEnvelope(changed));

        Assert.NotEqual(AuditContract.ChainHashOf(null, Envelope), AuditContract.ChainHashOf(null, changed));
    }
}
