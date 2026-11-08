using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Gatekeep.Kernel.Records;

/// <summary>
/// RFC 8785 (JCS) output for the JSON an off-server record holds: objects, arrays, strings,
/// integers, booleans and null. Members are sorted by their names' UTF-16 code units, nothing is
/// added between tokens, and strings use the minimal ECMAScript escaping. Fractions aren't
/// written, so no number formatting rule is needed: a record carries IDs, codes and counts.
/// </summary>
public static class CanonicalJson
{
    /// <summary>The largest integer an IEEE 754 double holds exactly, as RFC 8785 requires (I-JSON).</summary>
    private const long MaxSafeInteger = 9_007_199_254_740_991;

    /// <exception cref="ArgumentException">A value is a fraction or outside the I-JSON integer range, or a string holds a lone surrogate.</exception>
    public static string Write(JsonNode? node)
    {
        var builder = new StringBuilder();
        WriteNode(builder, node);
        return builder.ToString();
    }

    /// <summary><see cref="Write"/> as UTF-8, the bytes a record's signature covers.</summary>
    public static byte[] Utf8(JsonNode? node) => Encoding.UTF8.GetBytes(Write(node));

    private static void WriteNode(StringBuilder builder, JsonNode? node)
    {
        switch (node)
        {
            case null:
                builder.Append("null");
                break;
            case JsonObject value:
                WriteObject(builder, value);
                break;
            case JsonArray array:
                builder.Append('[');
                for (var i = 0; i < array.Count; i++)
                {
                    if (i > 0)
                    {
                        builder.Append(',');
                    }

                    WriteNode(builder, array[i]);
                }

                builder.Append(']');
                break;
            case JsonValue value:
                WriteValue(builder, value);
                break;
            default:
                throw new ArgumentException("Canonical JSON holds objects, arrays and values only.", nameof(node));
        }
    }

    private static void WriteObject(StringBuilder builder, JsonObject value)
    {
        var members = value.ToList();
        members.Sort((a, b) => string.CompareOrdinal(a.Key, b.Key));

        builder.Append('{');
        for (var i = 0; i < members.Count; i++)
        {
            if (i > 0)
            {
                builder.Append(',');
            }

            WriteString(builder, members[i].Key);
            builder.Append(':');
            WriteNode(builder, members[i].Value);
        }

        builder.Append('}');
    }

    private static void WriteValue(StringBuilder builder, JsonValue value)
    {
        switch (value.GetValueKind())
        {
            case JsonValueKind.String:
                WriteString(builder, value.GetValue<string>());
                break;
            case JsonValueKind.True:
                builder.Append("true");
                break;
            case JsonValueKind.False:
                builder.Append("false");
                break;
            case JsonValueKind.Null:
                builder.Append("null");
                break;
            case JsonValueKind.Number when value.TryGetValue<long>(out var number) && number is >= -MaxSafeInteger and <= MaxSafeInteger:
                builder.Append(number.ToString(CultureInfo.InvariantCulture));
                break;
            case JsonValueKind.Number when value.TryGetValue<int>(out var small):
                builder.Append(small.ToString(CultureInfo.InvariantCulture));
                break;
            default:
                throw new ArgumentException("Canonical JSON here holds integers in the I-JSON range only, never a fraction.", nameof(value));
        }
    }

    private static void WriteString(StringBuilder builder, string text)
    {
        builder.Append('"');

        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
            {
                builder.Append(c).Append(text[++i]);
                continue;
            }

            if (char.IsSurrogate(c))
            {
                throw new ArgumentException("A string holds a lone surrogate.", nameof(text));
            }

            switch (c)
            {
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '\b':
                    builder.Append("\\b");
                    break;
                case '\f':
                    builder.Append("\\f");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                case < ' ':
                    builder.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    break;
                default:
                    builder.Append(c);
                    break;
            }
        }

        builder.Append('"');
    }
}
