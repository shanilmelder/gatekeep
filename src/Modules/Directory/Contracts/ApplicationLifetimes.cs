using Gatekeep.Kernel.Limits;

namespace Gatekeep.Modules.Directory.Contracts;

/// <summary>
/// An Application's four token lifetimes as an Admin saves them (Story 3.4, FR-15), each in whole seconds:
/// its access tokens', its ID tokens', and its refresh tokens' absolute (from the family's authorization) and
/// inactivity (from each refresh token's issue) lifetimes. Each is 1 second to its <see cref="SecurityLimits"/>
/// hard limit; the table checks the same numbers.
/// </summary>
public sealed record ApplicationLifetimes(
    int AccessTokenLifetime,
    int IdTokenLifetime,
    int RefreshTokenAbsoluteLifetime,
    int RefreshTokenInactivityLifetime)
{
    /// <summary>The Deployment defaults every Application starts with, and every one created before Story 3.4 keeps.</summary>
    public static ApplicationLifetimes Defaults { get; } = new(
        Seconds(SecurityLimits.DefaultAccessTokenLifetime),
        Seconds(SecurityLimits.DefaultIdentityTokenLifetime),
        Seconds(SecurityLimits.RefreshTokenAbsoluteLifetime),
        Seconds(SecurityLimits.RefreshTokenInactivityLifetime));

    /// <summary>The hard maximum of each, in seconds: the <see cref="SecurityLimits"/> constants (PRD §5.2).</summary>
    public static ApplicationLifetimes Maximums { get; } = new(
        Seconds(SecurityLimits.HardSignedTokenLifetime),
        Seconds(SecurityLimits.HardSignedTokenLifetime),
        Seconds(SecurityLimits.HardRefreshTokenAbsoluteLifetime),
        Seconds(SecurityLimits.HardRefreshTokenInactivityLifetime));

    /// <summary>The shortest of each: 1 second.</summary>
    public const int Minimum = 1;

    private static int Seconds(TimeSpan lifetime) => checked((int)lifetime.TotalSeconds);
}

/// <summary>
/// One problem with a lifetimes save (Story 3.4): the <paramref name="Field"/> it is in (one of
/// <see cref="ApplicationLifetimeFields"/>), the <paramref name="Reason"/> (one of
/// <see cref="ApplicationLifetimeReasons"/>), and for <see cref="ApplicationLifetimeReasons.AboveMaximum"/>
/// the field's hard limit in seconds, so a client can say "Maximum is {limit}."
/// </summary>
public sealed record ApplicationLifetimeProblem(string Field, string Reason, int? Maximum);

/// <summary>The fields a lifetimes problem names, as the Admin API spells them.</summary>
public static class ApplicationLifetimeFields
{
    public const string AccessTokenLifetime = "accessTokenLifetime";

    public const string IdTokenLifetime = "idTokenLifetime";

    public const string RefreshTokenAbsoluteLifetime = "refreshTokenAbsoluteLifetime";

    public const string RefreshTokenInactivityLifetime = "refreshTokenInactivityLifetime";

    public static readonly IReadOnlyList<string> All =
        [AccessTokenLifetime, IdTokenLifetime, RefreshTokenAbsoluteLifetime, RefreshTokenInactivityLifetime];
}

/// <summary>Why a lifetime is refused (Story 3.4), as the Admin API spells it.</summary>
public static class ApplicationLifetimeReasons
{
    /// <summary>Under <see cref="ApplicationLifetimes.Minimum"/>: zero or negative.</summary>
    public const string BelowMinimum = "below_minimum";

    /// <summary>Over the field's hard limit, which the problem carries as its maximum.</summary>
    public const string AboveMaximum = "above_maximum";

    public static readonly IReadOnlyList<string> All = [BelowMinimum, AboveMaximum];
}

/// <summary>
/// A lifetimes save's result (Story 3.4): the Application as it now stands, and whether anything changed. An
/// unchanged save writes nothing and no event.
/// </summary>
public sealed record ApplicationLifetimesWrite(DirectoryApplication Application, bool Changed);
