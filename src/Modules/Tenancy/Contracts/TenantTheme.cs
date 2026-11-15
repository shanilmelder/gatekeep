namespace Gatekeep.Modules.Tenancy.Contracts;

/// <summary>
/// A Tenant's Hosted Login theme stylesheet (AD-21, Story 4.1): its CSS and the hex SHA-256 prefix of
/// that CSS, which names it. Host.Hosted links it in every step page's <c>head</c> at <see cref="Href"/>
/// and serves it there; any other hash is a 404, so a changed theme gets a new URL.
/// </summary>
public sealed record TenantTheme(string Css, string Hash)
{
    /// <summary>The path a theme stylesheet is served under, before its hash.</summary>
    public const string PathPrefix = "/login/theme/";

    /// <summary>Where this theme is served: <c>/login/theme/{hash}.css</c>, on the Tenant's own host.</summary>
    public string Href => $"{PathPrefix}{Hash}.css";
}
