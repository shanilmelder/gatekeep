using System.Globalization;
using Gatekeep.Modules.Directory.Contracts;

namespace Gatekeep.Modules.Directory.Core;

/// <summary>
/// A web client's redirect URIs as Stories 2.9 and 2.10 create them (RFC 9700 §2.1, RFC 8252 §8.3): 1 to
/// <see cref="DirectoryContract.MaxRedirectUris"/> distinct callback URLs, each passing
/// <see cref="ApplicationSettingsRules.Problem"/> for a <c>web</c> Application. Each is kept exactly as given:
/// OpenIddict matches a request's <c>redirect_uri</c> to it character for character, the port included.
/// </summary>
internal static class RedirectUris
{
    private static readonly string Rules = string.Create(
        CultureInfo.InvariantCulture,
        $"A web client registers 1 to {DirectoryContract.MaxRedirectUris} distinct redirect URIs, each an absolute https URI, or http on 127.0.0.1 or [::1] only, with no fragment, userinfo, wildcard, white space or control character, at most {DirectoryContract.MaxRedirectUriLength} characters.");

    public static string[] Checked(IReadOnlyList<string>? redirectUris)
    {
        if (redirectUris is null
            || redirectUris.Count is 0 or > DirectoryContract.MaxRedirectUris
            || redirectUris.Distinct(StringComparer.Ordinal).Count() != redirectUris.Count
            || redirectUris.Any(uri => ApplicationSettingsRules.Problem(uri, customSchemeAllowed: false, origin: false) is not null))
        {
            throw new ArgumentException(Rules, nameof(redirectUris));
        }

        return [.. redirectUris];
    }
}

/// <summary>
/// The type table for an Application's settings (Story 3.2, FR-11, FR-13), decided on the server.
/// <list type="bullet">
/// <item>Every URL is absolute, with no fragment, user info, <c>*</c>, white space or control character, at
/// most <see cref="DirectoryContract.MaxRedirectUriLength"/> characters; <c>https</c>, or <c>http</c> only on the
/// loopback IP literals <c>127.0.0.1</c> and <c>[::1]</c>, never the name <c>localhost</c>.</item>
/// <item>A <c>native</c> Application's callback and logout URLs may also use a custom scheme, one with a dot
/// that isn't a browser's own (<c>com.example.app:/callback</c>), and it has no web origin.</item>
/// <item>A web origin is <c>scheme://host[:port]</c> alone, with no path, query or fragment.</item>
/// <item>Each list holds at most <see cref="DirectoryContract.MaxRedirectUris"/> distinct entries; a
/// <c>machine</c> Application holds none.</item>
/// <item>Grants are <c>{}</c> or <c>{client_credentials}</c> for <c>machine</c>, and <c>{}</c>,
/// <c>{authorization_code}</c> or <c>{authorization_code, refresh_token}</c> otherwise, in any order.</item>
/// </list>
/// </summary>
internal static class ApplicationSettingsRules
{
    /// <summary>Schemes that are never a custom scheme: the web's own, and those a browser runs or reads.</summary>
    private static readonly HashSet<string> ReservedSchemes = new(StringComparer.Ordinal)
    {
        "http", "https", "javascript", "data", "file", "blob", "about", "vbscript",
    };

    private static readonly string[][] SignInGrants =
    [
        [],
        [DirectoryContract.AuthorizationCodeGrant],
        [DirectoryContract.AuthorizationCodeGrant, DirectoryContract.RefreshTokenGrant],
    ];

    private static readonly string[][] MachineGrants = [[], [DirectoryContract.ClientCredentialsGrant]];

    public static IReadOnlyList<ApplicationSettingsProblem> Check(string kind, ApplicationSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(settings.CallbackUrls);
        ArgumentNullException.ThrowIfNull(settings.LogoutUrls);
        ArgumentNullException.ThrowIfNull(settings.WebOrigins);
        ArgumentNullException.ThrowIfNull(settings.GrantTypes);
        if (kind is null || !DirectoryContract.CreatableKinds.Contains(kind, StringComparer.Ordinal))
        {
            throw new ArgumentException("Only an spa, web, native or machine Application has settings.", nameof(kind));
        }

        var machine = kind == DirectoryContract.MachineKind;
        var native = kind == DirectoryContract.NativeKind;
        var problems = new List<ApplicationSettingsProblem>();

        CheckUrls(problems, ApplicationSettingsFields.CallbackUrls, settings.CallbackUrls, allowed: !machine, customSchemeAllowed: native, origin: false);
        CheckUrls(problems, ApplicationSettingsFields.LogoutUrls, settings.LogoutUrls, allowed: !machine, customSchemeAllowed: native, origin: false);
        CheckUrls(problems, ApplicationSettingsFields.WebOrigins, settings.WebOrigins, allowed: !machine && !native, customSchemeAllowed: false, origin: true);

        var sorted = Sorted(settings.GrantTypes);
        var sets = machine ? MachineGrants : SignInGrants;
        if (!sets.Any(set => set.SequenceEqual(sorted, StringComparer.Ordinal)))
        {
            problems.Add(new ApplicationSettingsProblem(ApplicationSettingsFields.GrantTypes, null, ApplicationSettingsReasons.NotAllowedForType));
        }

        return problems;
    }

    /// <summary>The grants in their stored order: sorted, ordinal.</summary>
    public static string[] Sorted(IEnumerable<string> grants) => [.. grants.Order(StringComparer.Ordinal)];

    /// <summary>Whether <paramref name="url"/>'s scheme is neither <c>http</c> nor <c>https</c>.</summary>
    public static bool IsCustomScheme(string? url) =>
        SchemeOf(url) is { } scheme && scheme is not ("http" or "https");

    /// <summary>
    /// Why <paramref name="text"/> can't be one line of a URL list, as one of <see cref="ApplicationSettingsReasons"/>,
    /// or null when it can. A custom scheme is refused unless <paramref name="customSchemeAllowed"/>, and a web
    /// <paramref name="origin"/> may have no path or query.
    /// </summary>
    public static string? Problem(string? text, bool customSchemeAllowed, bool origin)
    {
        if (string.IsNullOrEmpty(text))
        {
            return ApplicationSettingsReasons.NotAbsolute;
        }

        if (text.Length > DirectoryContract.MaxRedirectUriLength)
        {
            return ApplicationSettingsReasons.TooLong;
        }

        if (text.Contains('*', StringComparison.Ordinal))
        {
            return ApplicationSettingsReasons.Wildcard;
        }

        // A scheme first, by its RFC 3986 syntax: "/cb" parses as an absolute file URI on Unix, so the parse alone won't do.
        if (text.Contains('#', StringComparison.Ordinal)
            || text.Any(c => char.IsWhiteSpace(c) || char.IsControl(c))
            || SchemeOf(text) is not { } scheme)
        {
            return ApplicationSettingsReasons.NotAbsolute;
        }

        var web = scheme is "https" or "http";
        if (!web && !(customSchemeAllowed && scheme.Contains('.', StringComparison.Ordinal) && !ReservedSchemes.Contains(scheme)))
        {
            return ApplicationSettingsReasons.SchemeNotAllowed;
        }

        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) || uri.UserInfo.Length > 0)
        {
            return ApplicationSettingsReasons.NotAbsolute;
        }

        if (web)
        {
            if (!text.AsSpan(scheme.Length).StartsWith("://", StringComparison.Ordinal) || string.IsNullOrEmpty(uri.Host))
            {
                return ApplicationSettingsReasons.NotAbsolute;
            }

            // The literal text, not the parsed host: 127.1 or 2130706433 normalize to 127.0.0.1 but are stored as typed.
            if (scheme == "http" && !IsLiteralLoopback(text))
            {
                return ApplicationSettingsReasons.SchemeNotAllowed;
            }

            // An origin is scheme://host[:port] and nothing after it.
            if (origin && text[(scheme.Length + 3)..].IndexOfAny(['/', '?']) >= 0)
            {
                return ApplicationSettingsReasons.NotAbsolute;
            }

            return null;
        }

        // An allowed custom scheme, such as com.example.app:/callback.
        return null;
    }

    private static void CheckUrls(
        List<ApplicationSettingsProblem> problems,
        string field,
        IReadOnlyList<string> urls,
        bool allowed,
        bool customSchemeAllowed,
        bool origin)
    {
        if (urls.Count == 0)
        {
            return;
        }

        if (!allowed)
        {
            problems.Add(new ApplicationSettingsProblem(field, null, ApplicationSettingsReasons.NotAllowedForType));
            return;
        }

        if (urls.Count > DirectoryContract.MaxRedirectUris)
        {
            problems.Add(new ApplicationSettingsProblem(field, null, ApplicationSettingsReasons.TooMany));
            return;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < urls.Count; i++)
        {
            var reason = Problem(urls[i], customSchemeAllowed, origin);
            if (reason is null && !seen.Add(urls[i]))
            {
                reason = ApplicationSettingsReasons.Duplicate;
            }

            if (reason is not null)
            {
                problems.Add(new ApplicationSettingsProblem(field, i, reason));
            }
        }
    }

    /// <summary>Whether <paramref name="text"/> is <c>http://127.0.0.1</c> or <c>http://[::1]</c>, spelled exactly so, then a port, path, query or the end.</summary>
    private static bool IsLiteralLoopback(string text)
    {
        foreach (var prefix in (string[])["http://127.0.0.1", "http://[::1]"])
        {
            if (text.StartsWith(prefix, StringComparison.Ordinal)
                && (text.Length == prefix.Length || text[prefix.Length] is ':' or '/' or '?'))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>The scheme of <paramref name="text"/>, lowercased, when it starts with one by RFC 3986 §3.1's syntax.</summary>
    private static string? SchemeOf(string? text)
    {
        var colon = text?.IndexOf(':', StringComparison.Ordinal) ?? -1;
        if (colon <= 0 || !char.IsAsciiLetter(text![0]))
        {
            return null;
        }

        for (var i = 1; i < colon; i++)
        {
            var c = text[i];
            if (!(char.IsAsciiLetterOrDigit(c) || c is '+' or '-' or '.'))
            {
                return null;
            }
        }

        return text[..colon].ToLowerInvariant();
    }
}
