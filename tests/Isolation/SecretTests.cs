using System.Reflection;
using System.Text.Json;
using Gatekeep.Kernel.Secrets;
using Xunit;

namespace Gatekeep.Tests.Isolation;

public sealed class SecretTests
{
    private const string Value = "canary-value-1234";

    private sealed record Holder(string Name, Secret<string> Password);

    [Fact]
    public void ToString_shows_no_value()
    {
        var secret = new Secret<string>(Value);

        Assert.DoesNotContain(Value, secret.ToString());
        Assert.DoesNotContain(Value, $"{secret}");
    }

    [Fact]
    public void Serializing_a_secret_is_refused()
    {
        var exception = Assert.Throws<NotSupportedException>(() => JsonSerializer.Serialize(new Secret<string>(Value)));

        Assert.DoesNotContain(Value, exception.ToString());
    }

    [Fact]
    public void Serializing_a_secret_inside_another_object_is_refused()
    {
        var exception = Assert.Throws<NotSupportedException>(
            () => JsonSerializer.Serialize(new Holder("name", new Secret<string>(Value))));

        Assert.DoesNotContain(Value, exception.ToString());
    }

    [Fact]
    public void Serializing_a_secret_as_object_is_refused()
    {
        object secret = new Secret<string>(Value);

        Assert.Throws<NotSupportedException>(() => JsonSerializer.Serialize(secret));
    }

    [Fact]
    public void Serializing_a_secret_of_another_type_is_refused()
    {
        Assert.Throws<NotSupportedException>(() => JsonSerializer.Serialize(new Secret<byte[]>([1, 2, 3])));
    }

    [Fact]
    public void Deserializing_a_secret_is_refused()
    {
        Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<Secret<string>>("\"x\""));
    }

    [Theory]
    [InlineData(typeof(Secret<string>))]
    [InlineData(typeof(Secret<byte[]>))]
    public void Secret_has_no_public_property_or_field(Type type)
    {
        const BindingFlags AllPublic = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static;

        Assert.Empty(type.GetProperties(AllPublic));
        Assert.Empty(type.GetFields(AllPublic));
    }

    [Fact]
    public void Use_reaches_the_value()
    {
        Assert.Equal(Value.Length, new Secret<string>(Value).Use(v => v.Length));
    }

    [Fact]
    public void Null_is_refused()
    {
        Assert.Throws<ArgumentNullException>(() => new Secret<string>(null!));
    }
}
