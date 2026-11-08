using System.Text.RegularExpressions;

namespace Gatekeep.Kernel.Secrets;

/// <summary>
/// The known shapes of a credential-equivalent value in text (AD-24), and the names that mark
/// one. It catches shapes and sensitive names only: a value held as a plain string, with an
/// innocent name and no known shape, passes (T-42). The log scrubber and the audit appender
/// both use it, so a shape is masked the same way wherever text is kept.
/// </summary>
public static class CredentialShapes
{
    public const string Mask = "[scrubbed]";

    private const string Names =
        "password|passwd|pwd|passphrase|secret|token|api[_-]?key|authorization|cookie|credential|assertion"
        + "|private[_-]?key|code[_-]?verifier|device[_-]?code|user[_-]?code";

    /// <summary>Sensitive as a whole name only, as many ordinary names contain it.</summary>
    private const string WholeName = "code";

    // A name, the closing quote it has in JSON, then `=` or `:`.
    private const string Key = $@"[A-Za-z0-9_.-]*(?:{Names})[A-Za-z0-9_.-]*[""']?[ \t]*[=:][ \t]*";

    // Text can come from a request, so these run in linear time.
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

    // An opaque Tenant artifact (AD-9): a client secret now, codes and refresh tokens later, as
    // `{tenantPublicId}.{base64url random}`. The whole value goes, Tenant prefix included.
    private static readonly Regex TenantArtifact = new(@"\bten_[a-z2-7]{26}\.[A-Za-z0-9_-]{16,}", Options);

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

    /// <summary>Whether a value's name marks it as credential-equivalent, such as <c>Password</c> or <c>code</c>.</summary>
    public static bool IsSensitiveName(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        return name.Equals(WholeName, StringComparison.OrdinalIgnoreCase) || SensitiveName.IsMatch(name);
    }

    /// <summary>
    /// Replaces every known shape in <paramref name="text"/> with <see cref="Mask"/>: PEM private
    /// keys, three-part <c>eyJ</c> tokens, <c>{tenantPublicId}.{random}</c> artifacts, URL userinfo, cookie headers, <c>Bearer</c> and
    /// <c>Basic</c> credentials, <c>name=value</c> for sensitive names, and <c>code=</c> in a query.
    /// </summary>
    public static string MaskShapes(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        text = PemPrivateKey.Replace(text, Mask);
        text = Jwt.Replace(text, Mask);
        text = TenantArtifact.Replace(text, Mask);
        text = UrlUserInfo.Replace(text, $"$1{Mask}@");
        text = CookieHeader.Replace(text, $"$1{Mask}");
        text = SchemeCredential.Replace(text, $"$1 {Mask}");
        text = NamedAssignment.Replace(text, $"$1$2{Mask}");
        return QueryCode.Replace(text, $"$1{Mask}");
    }
}
