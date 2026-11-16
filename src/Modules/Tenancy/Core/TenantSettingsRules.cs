using Gatekeep.Kernel.Limits;
using Gatekeep.Modules.Tenancy.Contracts;

namespace Gatekeep.Modules.Tenancy.Core;

/// <summary>
/// A Tenant settings save's own rules (Story 4.6): the terms URL null or an absolute https URL with a host and no
/// userinfo, white space or control character, of at most <see cref="SecurityLimits.MaxTermsUrlLength"/> characters;
/// email verification off only in a Dev Tenant; the default audience null or an identifier of at most
/// <see cref="SecurityLimits.MaxApiIdentifierLength"/> characters with no white space or control character. Whether the
/// audience names one of the Tenant's APIs is Directory's to say, so the caller checks it.
/// </summary>
internal static class TenantSettingsRules
{
    private const string TermsUrlText = "Enter an https URL.";

    private static readonly string TermsUrlLengthText = $"Use at most {SecurityLimits.MaxTermsUrlLength} characters.";

    private const string DevOnlyText = "Only a Dev Tenant can turn off email verification.";

    private const string RequiredText = "Required.";

    private const string AudienceText = "Choose one of the Tenant's APIs.";

    public static IReadOnlyList<TenantSettingsProblem> Check(TenantSettingsInput input, TenantLabel label, out TenantSettings? settings)
    {
        ArgumentNullException.ThrowIfNull(input);
        var problems = new List<TenantSettingsProblem>();

        if (input.TermsUrl is { } terms)
        {
            if (terms.Length > SecurityLimits.MaxTermsUrlLength)
            {
                problems.Add(new(TenantSettingsFields.TermsUrl, TenantSettingsReasons.TooLong, TermsUrlLengthText));
            }
            else if (!IsTermsUrl(terms))
            {
                problems.Add(new(TenantSettingsFields.TermsUrl, TenantSettingsReasons.Invalid, TermsUrlText));
            }
        }

        if (input.EmailVerificationOff is not { } off)
        {
            problems.Add(new(TenantSettingsFields.EmailVerificationOff, TenantSettingsReasons.Required, RequiredText));
        }
        else if (off && label != TenantLabel.Dev)
        {
            problems.Add(new(TenantSettingsFields.EmailVerificationOff, TenantSettingsReasons.DevOnly, DevOnlyText));
        }

        if (input.DefaultAudience is { } audience)
        {
            if (audience.Length > SecurityLimits.MaxApiIdentifierLength)
            {
                problems.Add(new(TenantSettingsFields.DefaultAudience, TenantSettingsReasons.TooLong, AudienceText));
            }
            else if (audience.Length == 0 || audience.Any(static c => char.IsWhiteSpace(c) || char.IsControl(c)))
            {
                problems.Add(new(TenantSettingsFields.DefaultAudience, TenantSettingsReasons.Invalid, AudienceText));
            }
        }

        settings = problems.Count == 0 ? new TenantSettings(input.TermsUrl, input.EmailVerificationOff!.Value, input.DefaultAudience) : null;
        return problems;
    }

    /// <summary>An absolute https URL with a host, and no userinfo, white space or control character anywhere.</summary>
    public static bool IsTermsUrl(string text) =>
        text.Length is > 0 and <= SecurityLimits.MaxTermsUrlLength
        && !text.Any(static c => char.IsWhiteSpace(c) || char.IsControl(c))
        && text.StartsWith("https://", StringComparison.Ordinal)
        && Uri.TryCreate(text, UriKind.Absolute, out var uri)
        && uri.Scheme == Uri.UriSchemeHttps
        && uri.UserInfo.Length == 0
        && !Authority(text).Contains('@', StringComparison.Ordinal)
        && uri.Host.Length > 0;

    /// <summary>The text between <c>https://</c> and the path, query or fragment: where userinfo would be, however it is spelt.</summary>
    private static string Authority(string text)
    {
        var rest = text["https://".Length..];
        var end = rest.IndexOfAny(['/', '?', '#', '\\']);
        return end < 0 ? rest : rest[..end];
    }
}
