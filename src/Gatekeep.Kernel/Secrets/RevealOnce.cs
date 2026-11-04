using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Gatekeep.Kernel.Secrets;

/// <summary>
/// A credential-equivalent value shown to its owner once, in the one response that issues it
/// (AD-24), such as an Admin Recovery Code (Story 1.26). It is the only such type with a JSON
/// form: serialized, it writes its value; anywhere else it prints a fixed mask, and JSON never
/// reads one in. An architecture rule allows it only as a property of a reviewed response type,
/// and every response holding one is sent with <c>Cache-Control: no-store</c>.
/// </summary>
[JsonConverter(typeof(RevealOnceJsonConverterFactory))]
[DebuggerDisplay(Mask)]
public sealed class RevealOnce<T>
{
    private const string Mask = "[secret]";

    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private readonly T _value;

    public RevealOnce(T value)
    {
        ArgumentNullException.ThrowIfNull(value);
        _value = value;
    }

    /// <summary>Hands the value to <paramref name="use"/>, the serializer's way to write it.</summary>
    public TResult Use<TResult>(Func<T, TResult> use)
    {
        ArgumentNullException.ThrowIfNull(use);
        return use(_value);
    }

    public override string ToString() => Mask;
}

internal sealed class RevealOnceJsonConverterFactory : JsonConverterFactory
{
    public override bool CanConvert(Type typeToConvert) =>
        typeToConvert.IsGenericType && typeToConvert.GetGenericTypeDefinition() == typeof(RevealOnce<>);

    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options) =>
        (JsonConverter)Activator.CreateInstance(
            typeof(RevealOnceJsonConverter<>).MakeGenericType(typeToConvert.GetGenericArguments()))!;
}

/// <summary>Writes the value as its own JSON. Reading one in is refused: a revealed value never comes back.</summary>
internal sealed class RevealOnceJsonConverter<T> : JsonConverter<RevealOnce<T>>
{
    public override RevealOnce<T> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        throw new NotSupportedException("A revealed value is never read back.");

    public override void Write(Utf8JsonWriter writer, RevealOnce<T> value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        value.Use(v =>
        {
            JsonSerializer.Serialize(writer, v, options);
            return 0;
        });
    }
}
