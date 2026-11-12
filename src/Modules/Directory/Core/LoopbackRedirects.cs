using System.Globalization;

namespace Gatekeep.Modules.Directory.Core;

/// <summary>
/// RFC 8252 §7.3's one exception to exact matching (Story 3.2), for <c>native</c> Applications only: a
/// loopback redirect URI may carry any port, since the app picks one when it starts listening. Only the
/// IP literals <c>127.0.0.1</c> and <c>[::1]</c> over <c>http</c> qualify, never the name <c>localhost</c>,
/// and the two URIs must match string for string once the port is set aside.
/// </summary>
internal static class LoopbackRedirects
{
    private static readonly string[] Prefixes = ["http://127.0.0.1", "http://[::1]"];

    private const int MaxPort = 65535;

    public static bool SameButPort(string registered, string requested)
    {
        foreach (var prefix in Prefixes)
        {
            if (registered.StartsWith(prefix, StringComparison.Ordinal) && requested.StartsWith(prefix, StringComparison.Ordinal))
            {
                return Tail(registered[prefix.Length..]) is { } left
                    && Tail(requested[prefix.Length..]) is { } right
                    && string.Equals(left, right, StringComparison.Ordinal);
            }
        }

        return false;
    }

    /// <summary>
    /// What follows the host once an optional <c>:port</c> is set aside: empty, or a path or query. Null when
    /// anything else follows the host, such as user info or a second host, or the port isn't 1 to 65535 digits' worth.
    /// </summary>
    private static string? Tail(string rest)
    {
        var start = 0;
        if (rest.StartsWith(':'))
        {
            var end = 1;
            while (end < rest.Length && char.IsAsciiDigit(rest[end]))
            {
                end++;
            }

            if (end == 1 || end > 6
                || !int.TryParse(rest.AsSpan(1, end - 1), NumberStyles.None, CultureInfo.InvariantCulture, out var port)
                || port is 0 or > MaxPort)
            {
                return null;
            }

            start = end;
        }

        var tail = rest[start..];
        return tail.Length == 0 || tail[0] is '/' or '?' ? tail : null;
    }
}
