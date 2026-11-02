using System.Globalization;
using System.Text;

namespace Gatekeep.Modules.Audit.Core;

/// <summary>
/// RFC 8785 (JCS) output for one flat object whose values are strings, integers or null,
/// which is all an audit envelope holds. Members are sorted by their names' UTF-16 code
/// units, nothing is added between tokens, and strings use the minimal ECMAScript escaping.
/// </summary>
internal static class CanonicalJson
{
    /// <summary>The largest integer an IEEE 754 double holds exactly, as RFC 8785 requires (I-JSON).</summary>
    private const long MaxSafeInteger = 9_007_199_254_740_991;

    /// <exception cref="ArgumentException">A name repeats, a value has an unsupported type, an
    /// integer is outside the I-JSON range, or a string holds a lone surrogate.</exception>
    public static string Write(IEnumerable<KeyValuePair<string, object?>> members)
    {
        ArgumentNullException.ThrowIfNull(members);

        var sorted = members.ToList();
        sorted.Sort((a, b) => string.CompareOrdinal(a.Key, b.Key));

        var builder = new StringBuilder();
        builder.Append('{');

        for (var i = 0; i < sorted.Count; i++)
        {
            var (name, value) = sorted[i];
            ArgumentNullException.ThrowIfNull(name, nameof(members));

            if (i > 0)
            {
                if (string.Equals(sorted[i - 1].Key, name, StringComparison.Ordinal))
                {
                    throw new ArgumentException($"Member {name} appears twice.", nameof(members));
                }

                builder.Append(',');
            }

            WriteString(builder, name);
            builder.Append(':');
            WriteValue(builder, name, value);
        }

        builder.Append('}');
        return builder.ToString();
    }

    private static void WriteValue(StringBuilder builder, string name, object? value)
    {
        switch (value)
        {
            case null:
                builder.Append("null");
                break;
            case string text:
                WriteString(builder, text);
                break;
            case int number:
                builder.Append(number.ToString(CultureInfo.InvariantCulture));
                break;
            case long number when number is >= -MaxSafeInteger and <= MaxSafeInteger:
                builder.Append(number.ToString(CultureInfo.InvariantCulture));
                break;
            case long:
                throw new ArgumentException($"Member {name} is outside the I-JSON integer range.", nameof(value));
            default:
                throw new ArgumentException($"Member {name} has a type canonical JSON here doesn't hold.", nameof(value));
        }
    }

    private static void WriteString(StringBuilder builder, string text)
    {
        builder.Append('"');

        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];

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
                case var high when char.IsHighSurrogate(high):
                    if (i + 1 >= text.Length || !char.IsLowSurrogate(text[i + 1]))
                    {
                        throw new ArgumentException("A string holds a lone surrogate.", nameof(text));
                    }

                    builder.Append(high).Append(text[++i]);
                    break;
                case var low when char.IsLowSurrogate(low):
                    throw new ArgumentException("A string holds a lone surrogate.", nameof(text));
                default:
                    builder.Append(c);
                    break;
            }
        }

        builder.Append('"');
    }
}
