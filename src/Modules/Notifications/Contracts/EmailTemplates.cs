namespace Gatekeep.Modules.Notifications.Contracts;

/// <summary>
/// One email template's text (Story 4.5): a subject and a plain-text body, with <c>{{name}}</c> variables replaced by
/// fixed substitution only. A Tenant's override (Story 15.4) or the built-in default.
/// </summary>
public sealed record EmailTemplateText(string Subject, string Body);

/// <summary>How a render ended.</summary>
public enum EmailRenderStatus
{
    /// <summary>Subject and body are set.</summary>
    Rendered,

    /// <summary>The template ID is none of the five.</summary>
    UnknownTemplate,

    /// <summary>The template sends a link or a code, and the job carries no credential.</summary>
    CredentialMissing,

    /// <summary>The template sends neither a link nor a code, and the job carries a credential.</summary>
    CredentialRefused,

    /// <summary>The template sends a link or a code, but its text (a Tenant's override) has no <c>{{link}}</c> or <c>{{code}}</c>.</summary>
    TemplateInvalid,
}

/// <summary>A render's outcome: the subject and body only when <see cref="EmailRenderStatus.Rendered"/>. Prints neither.</summary>
public sealed record EmailRender(EmailRenderStatus Status, string? Subject, string? Body)
{
    public override string ToString() => $"{nameof(EmailRender)} {Status}";
}

/// <summary>
/// The Tenant's email provider as Host.Worker reads it to send (Story 4.5): its configuration and its secret as the
/// Transit ciphertext stored under the Tenant's <c>email-</c> key, null only for SMTP with no username. Prints neither.
/// </summary>
public sealed record EmailDelivery(EmailProviderConfiguration Provider, string? SecretCiphertext)
{
    public override string ToString() => $"{nameof(EmailDelivery)} {Provider.Kind}";
}
