using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Gatekeep.Kernel.Secrets;

/// <summary>
/// A credential-equivalent value with no serializable form (AD-24). It has no public
/// property or field, prints a fixed mask, and JSON refuses it in both directions.
/// </summary>
[JsonConverter(typeof(SecretJsonConverterFactory))]
[DebuggerDisplay(Mask)]
public sealed class Secret<T>
{
    private const string Mask = "[secret]";

    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private readonly T _value;

    public Secret(T value)
    {
        ArgumentNullException.ThrowIfNull(value);
        _value = value;
    }

    /// <summary>Hands the value to <paramref name="use"/>, which is the only way to reach it.</summary>
    public TResult Use<TResult>(Func<T, TResult> use)
    {
        ArgumentNullException.ThrowIfNull(use);
        return use(_value);
    }

    public override string ToString() => Mask;
}

internal sealed class SecretJsonConverterFactory : JsonConverterFactory
{
    public override bool CanConvert(Type typeToConvert) =>
        typeToConvert.IsGenericType && typeToConvert.GetGenericTypeDefinition() == typeof(Secret<>);

    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options) =>
        (JsonConverter)Activator.CreateInstance(
            typeof(SecretJsonConverter<>).MakeGenericType(typeToConvert.GetGenericArguments()))!;
}

internal sealed class SecretJsonConverter<T> : JsonConverter<Secret<T>>
{
    private const string Refusal = "A Secret has no serialized form.";

    public override Secret<T> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        throw new NotSupportedException(Refusal);

    public override void Write(Utf8JsonWriter writer, Secret<T> value, JsonSerializerOptions options) =>
        throw new NotSupportedException(Refusal);
}
