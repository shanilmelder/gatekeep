using System.Text.RegularExpressions;
using Gatekeep.Modules.Notifications.Contracts;

namespace Gatekeep.Modules.Notifications.Core;

/// <summary>
/// Fixed substitution (Story 4.5): each <c>{{name}}</c> the template allows is replaced by literal text, in one pass, so a
/// substituted value is never expanded again. Anything else in braces stays as written. There is no escaping language,
/// loop, condition or other syntax. The subject loses every CR and LF after substitution, so no value can add a header.
/// </summary>
internal static partial class EmailTemplateRenderer
{
    public static EmailRender Render(
        Guid templateId,
        EmailTemplateText text,
        string tenantName,
        string emailLinkBase,
        string? credential)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(tenantName);
        ArgumentNullException.ThrowIfNull(emailLinkBase);

        if (EmailTemplateDefaults.Find(templateId) is not { } template)
        {
            return new EmailRender(EmailRenderStatus.UnknownTemplate, null, null);
        }

        if (template.Credential == EmailCredentialUse.None && credential is not null)
        {
            return new EmailRender(EmailRenderStatus.CredentialRefused, null, null);
        }

        if (template.Credential != EmailCredentialUse.None && credential is null)
        {
            return new EmailRender(EmailRenderStatus.CredentialMissing, null, null);
        }

        // A link or code template that wouldn't carry its link or code is refused rather than sent without it.
        var required = template.Credential switch
        {
            EmailCredentialUse.Link => "{{" + EmailTemplateDefaults.LinkVariable + "}}",
            EmailCredentialUse.Code => "{{" + EmailTemplateDefaults.CodeVariable + "}}",
            _ => null,
        };
        if (required is not null
            && !text.Subject.Contains(required, StringComparison.Ordinal)
            && !text.Body.Contains(required, StringComparison.Ordinal))
        {
            return new EmailRender(EmailRenderStatus.TemplateInvalid, null, null);
        }

        var values = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [EmailTemplateDefaults.TenantNameVariable] = tenantName,
        };

        switch (template.Credential)
        {
            case EmailCredentialUse.Link:
                values[EmailTemplateDefaults.LinkVariable] = Link(emailLinkBase, template.LinkPath!, credential!);
                break;
            case EmailCredentialUse.Code:
                values[EmailTemplateDefaults.CodeVariable] = credential!;
                break;
        }

        var subject = Substitute(text.Subject, values).Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\n", string.Empty, StringComparison.Ordinal);
        return new EmailRender(EmailRenderStatus.Rendered, subject, Substitute(text.Body, values));
    }

    /// <summary>The stored email link base, never a request's host, then the template's fixed path and the URL-encoded token.</summary>
    public static string Link(string emailLinkBase, string path, string token)
    {
        var root = emailLinkBase.EndsWith('/') ? emailLinkBase : emailLinkBase + "/";
        return $"{root}{path}?token={Uri.EscapeDataString(token)}";
    }

    private static string Substitute(string text, Dictionary<string, string> values) =>
        Variable().Replace(text, m => values.TryGetValue(m.Groups["name"].Value, out var value) ? value : m.Value);

    [GeneratedRegex(@"\{\{(?<name>[^{}]*)\}\}", RegexOptions.CultureInvariant)]
    private static partial Regex Variable();
}
