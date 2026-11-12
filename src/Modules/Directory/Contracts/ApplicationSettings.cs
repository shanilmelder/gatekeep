namespace Gatekeep.Modules.Directory.Contracts;

/// <summary>
/// An Application's full settings as an Admin saves them (Story 3.2): its Allowed Callback URLs (the OAuth
/// redirect URIs), Allowed Logout URLs (post-logout redirect URIs), Allowed Web Origins and grant types.
/// Each URL is kept exactly as given and matched exactly; grants are stored sorted.
/// </summary>
public sealed record ApplicationSettings(
    IReadOnlyList<string> CallbackUrls,
    IReadOnlyList<string> LogoutUrls,
    IReadOnlyList<string> WebOrigins,
    IReadOnlyList<string> GrantTypes);

/// <summary>
/// One problem with a settings save (Story 3.2): the <paramref name="Field"/> it is in (one of
/// <see cref="ApplicationSettingsFields"/>), the 0-based <paramref name="Index"/> of the line, or null for
/// the whole field, and the <paramref name="Reason"/>, one of <see cref="ApplicationSettingsReasons"/>.
/// It never carries the value.
/// </summary>
public sealed record ApplicationSettingsProblem(string Field, int? Index, string Reason);

/// <summary>The fields a settings problem names, as the Admin API spells them.</summary>
public static class ApplicationSettingsFields
{
    public const string CallbackUrls = "callbackUrls";

    public const string LogoutUrls = "logoutUrls";

    public const string WebOrigins = "webOrigins";

    public const string GrantTypes = "grantTypes";

    public static readonly IReadOnlyList<string> All = [CallbackUrls, LogoutUrls, WebOrigins, GrantTypes];
}

/// <summary>Why a settings line or field is refused (Story 3.2), as the Admin API spells it.</summary>
public static class ApplicationSettingsReasons
{
    /// <summary>Not an absolute URL, or one with a fragment, user info, white space or a control character; a web origin with a path or query.</summary>
    public const string NotAbsolute = "not_absolute";

    /// <summary>A <c>*</c> anywhere: nothing is matched by pattern.</summary>
    public const string Wildcard = "wildcard";

    /// <summary>A scheme the type can't have: http off the loopback IP literals, or a custom scheme outside a <c>native</c> Application.</summary>
    public const string SchemeNotAllowed = "scheme_not_allowed";

    /// <summary>Longer than <see cref="DirectoryContract.MaxRedirectUriLength"/> characters.</summary>
    public const string TooLong = "too_long";

    /// <summary>More than <see cref="DirectoryContract.MaxRedirectUris"/> lines.</summary>
    public const string TooMany = "too_many";

    /// <summary>The same line twice, exactly.</summary>
    public const string Duplicate = "duplicate";

    /// <summary>A field or grant set the Application's type can't have.</summary>
    public const string NotAllowedForType = "not_allowed_for_type";

    public static readonly IReadOnlyList<string> All = [NotAbsolute, Wildcard, SchemeNotAllowed, TooLong, TooMany, Duplicate, NotAllowedForType];
}
