namespace Gatekeep.Modules.Tenancy.Contracts;

/// <summary>
/// The Tenant settings a sign-up reads (Story 4.6), as stored: the terms URL, or null; whether email verification is off,
/// which only a Dev Tenant may save and which counts only while the Tenant is Dev; and the default audience, an API
/// identifier, or null. Story 8.5 keeps them.
/// </summary>
public sealed record TenantSettings(string? TermsUrl, bool EmailVerificationOff, string? DefaultAudience)
{
    /// <summary>A Tenant's settings before any are saved: no terms URL, verification on, no default audience.</summary>
    public static TenantSettings Defaults { get; } = new(null, false, null);
}

/// <summary>
/// The Tenant settings as sign-up, sign-in and token issue read them (Stories 4.7 and 4.9): the terms URL, whether email
/// verification is off, already false unless the Tenant is Dev now, and the default audience. A default audience may
/// name an API since removed: the reader falls back as it would with none.
/// </summary>
public sealed record TenantSignupSettings(string? TermsUrl, bool EmailVerificationOff, string? DefaultAudience);

/// <summary>A Tenant settings save's input as the request gave it (Story 4.6): each part may be missing, and the save decides.</summary>
public sealed record TenantSettingsInput(string? TermsUrl, bool? EmailVerificationOff, string? DefaultAudience);

/// <summary>A Tenant's settings, its label and its status, as read with its row lock or without.</summary>
public sealed record TenantSettingsState(TenantSettings Settings, TenantLabel Label, TenantStatus Status);

/// <summary>The fields a Tenant settings save's errors name (Story 4.6): the request's own member names.</summary>
public static class TenantSettingsFields
{
    public const string TermsUrl = "termsUrl";
    public const string EmailVerificationOff = "emailVerificationOff";
    public const string DefaultAudience = "defaultAudience";

    public static IReadOnlyList<string> All { get; } = [TermsUrl, EmailVerificationOff, DefaultAudience];
}

/// <summary>The reasons a Tenant settings save's errors give (Story 4.6).</summary>
public static class TenantSettingsReasons
{
    /// <summary>Absent, or null, where it is needed.</summary>
    public const string Required = "required";

    /// <summary>Of the wrong form: a terms URL that isn't an absolute https URL with no userinfo, or a malformed identifier.</summary>
    public const string Invalid = "invalid";

    /// <summary>Longer than its limit.</summary>
    public const string TooLong = "too_long";

    /// <summary>Email verification turned off in a Tenant that isn't Dev.</summary>
    public const string DevOnly = "dev_only";

    /// <summary>A default audience that names none of the Tenant's APIs.</summary>
    public const string NotFound = "not_found";

    /// <summary>A default audience that names the built-in Management API.</summary>
    public const string BuiltIn = "built_in";

    public static IReadOnlyList<string> All { get; } = [Required, Invalid, TooLong, DevOnly, NotFound, BuiltIn];
}

/// <summary>One refused field of a Tenant settings save (Story 4.6): its name, why, and the rule's text. Never its value.</summary>
public sealed record TenantSettingsProblem(string Field, string Reason, string Detail);
