using System.Text.RegularExpressions;

namespace Gatekeep.Adapters.Logging;

/// <summary>
/// Removes credential-equivalent values from log text (AD-24). It catches known shapes and
/// the values of sensitive names only. A value held as a plain string, with an innocent
/// name and no known shape, passes: see T-42.
/// </summary>
public static class Scrubber
{
    public const string Mask = "[scrubbed]";

    private const string Names =
        "password|passwd|pwd|passphrase|secret|token|api[_-]?key|authorization|cookie|credential|assertion"
        + "|private[_-]?key|code[_-]?verifier|device[_-]?code|user[_-]?code";

    /// <summary>Sensitive as a whole name only, as many ordinary names contain it.</summary>
    private const string WholeName = "code";

    // A name, the closing quote it has in JSON, then `=` or `:`.
    private const string Key = $@"[A-Za-z0-9_.-]*(?:{Names})[A-Za-z0-9_.-]*[""']?[ \t]*[=:][ \t]*";

    // Logged text can come from a request, so these run in linear time.
    private const RegexOptions Options =
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking;

    private static readonly Regex SensitiveName = new(Names, Options);

    // An unterminated block is still key material, so the end marker is optional.
    private static readonly Regex PemPrivateKey = new(
        @"-----BEGIN[A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END[A-Z0-9 ]*PRIVATE KEY-----|\z)",
        Options | RegexOptions.Singleline);

    private static readonly Regex Jwt = new(
        @"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]*)*",
        Options);

    private static readonly Regex UrlUserInfo = new(@"\b([a-z][a-z0-9+.-]*://)[^/?#\s]+@", Options);

    private static readonly Regex CookieHeader = new(@"(\b(?:Set-)?Cookie[ \t]*:[ \t]*)[^\r\n]+", Options);

    // At least 16 characters, so prose such as "Basic auth failed" keeps its words.
    private static readonly Regex SchemeCredential = new(@"\b(Bearer|Basic)[ \t]+[A-Za-z0-9._~+/=-]{16,}", Options);

    // Only a query value ends at `&`: a connection string's password may hold one. Elsewhere
    // an unquoted value runs to `;`, as it may hold spaces. An unterminated quote runs to the
    // end of the line, and text after a closing quote is masked with it. All of this can
    // lose ordinary text after the value on that line, which is safe.
    private static readonly Regex NamedAssignment = new(
        $@"([?&]{Key})[^&\r\n]+|({Key})(?:""(?:[^""\\\r\n]|\\.|"""")*""[^;\r\n]*|""[^\r\n]*|'(?:[^'\\\r\n]|\\.|'')*'[^;\r\n]*|'[^\r\n]*|[^;\r\n]+)",
        Options);

    // The percent-encoded form is a URL nested in another URL. Its value ends at `%26`.
    private static readonly Regex QueryCode = new(
        @"((?:^|[?&#])code=|(?:%3F|%26|%23)code%3D)(?:[^&#\s%]|%[013-9a-f][0-9a-f]|%2[0-57-9a-f])+",
        Options | RegexOptions.Multiline);

    public static bool IsSensitiveName(string name) =>
        name.Equals(WholeName, StringComparison.OrdinalIgnoreCase) || SensitiveName.IsMatch(name);

    /// <summary>Replaces the text of each <paramref name="values"/> item, then every known shape.</summary>
    public static string Scrub(string text, IEnumerable<string> values)
    {
        // Longest first, so a value that contains another isn't left in part.
        foreach (var value in values.Where(v => v.Length > 0).OrderByDescending(v => v.Length))
        {
            text = text.Replace(value, Mask, StringComparison.Ordinal);
        }

        text = PemPrivateKey.Replace(text, Mask);
        text = Jwt.Replace(text, Mask);
        text = UrlUserInfo.Replace(text, $"$1{Mask}@");
        text = CookieHeader.Replace(text, $"$1{Mask}");
        text = SchemeCredential.Replace(text, $"$1 {Mask}");
        text = NamedAssignment.Replace(text, $"$1$2{Mask}");
        return QueryCode.Replace(text, $"$1{Mask}");
    }
}
