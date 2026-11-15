using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Email;
using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.RateLimiting;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Notifications.Core;

namespace Gatekeep.Modules.Notifications.Contracts;

/// <summary>What other modules use to reach a Tenant's notification settings (Story 4.4).</summary>
public static class NotificationsContract
{
    /// <summary>
    /// The context Tenant's email provider, without its secret, or null when it has none. It writes nothing.
    /// Host.Admin reads every column but <c>secret_ciphertext</c>, which only Host.Worker may.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't a Tenant's.</exception>
    public static Task<EmailProviderConfiguration?> ReadEmailProviderAsync(CommandContext context, CancellationToken cancellationToken) =>
        EmailProviderStore.ReadAsync(context, cancellationToken);

    /// <summary>
    /// Saves the context Tenant's email provider (Story 4.4, FR-36, AD-10): the kind's settings, validated per
    /// kind with unknown members refused, the From address and name, and the provider's one secret, encrypted
    /// through <paramref name="custody"/> under the Tenant's <c>email-</c> key with its ID as associated data,
    /// before anything is written. A secret is needed when no provider is stored, when the kind changes, or for
    /// an SMTP username with none stored, or any change of settings but Postmark's message stream; omitted otherwise,
    /// the stored ciphertext stays. Saves and removals of one Tenant wait for each other. A save that changes nothing writes nothing; any other writes the row and
    /// <c>notifications.email_provider.updated</c>, with <paramref name="actor"/> and the Tenant as target, in
    /// the caller's transaction, which commits only on <see cref="EmailProviderSaveStatus.Saved"/> or
    /// <see cref="EmailProviderSaveStatus.Unchanged"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't a Tenant's.</exception>
    [StateChanging]
    public static Task<EmailProviderSave> SaveEmailProviderAsync(
        CommandContext context,
        IKeyCustody? custody,
        IAuditAppender appender,
        Actor actor,
        EmailProviderInput input,
        CancellationToken cancellationToken) =>
        EmailProviderStore.SaveAsync(context, custody, appender, actor, input, cancellationToken);

    /// <summary>
    /// Removes the context Tenant's email provider and its stored secret (Story 4.4), with
    /// <c>notifications.email_provider.removed</c>, <paramref name="actor"/> and the Tenant as target. True when
    /// one was removed; removing none writes nothing and is false.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't a Tenant's.</exception>
    [StateChanging]
    public static Task<bool> RemoveEmailProviderAsync(
        CommandContext context,
        IAuditAppender appender,
        Actor actor,
        CancellationToken cancellationToken) =>
        EmailProviderStore.RemoveAsync(context, appender, actor, cancellationToken);

    /// <summary>
    /// Notifications' Tenant purge (Story 4.4, AD-30): deletes the context Tenant's <c>email_template</c> overrides
    /// (Story 4.5) and its <c>email_provider</c> row.
    /// </summary>
    public static ITenantPurge TenantPurge { get; } = new NotificationsPurge();

    /// <summary>
    /// The one email job (Story 4.5, AD-15): a Tenant job whose payload is <see cref="EmailUserIdName"/> and
    /// <see cref="EmailTemplateIdName"/>, plus the link token or one-time code for a template that sends one, as Transit
    /// ciphertext the runner erases when the job finishes. Host.Worker resolves the address from the User at send time.
    /// Build its payload with <see cref="EmailPayload"/>.
    /// </summary>
    public static JobType SendEmailJob { get; } = new("notifications.email.send");

    /// <summary>The payload ID naming the recipient User.</summary>
    public const string EmailUserIdName = "user_id";

    /// <summary>The payload ID naming the template: one of <see cref="EmailTemplateIds"/>.</summary>
    public const string EmailTemplateIdName = "template_id";

    /// <summary>The verification email (Story 4.7): sends <c>{{link}}</c> to <c>login/verify-email</c>, so it needs a credential.</summary>
    public static Guid VerificationTemplate => EmailTemplateDefaults.Verification;

    /// <summary>The password reset email (Story 4.11): sends <c>{{link}}</c> to <c>login/reset-password</c>, so it needs a credential.</summary>
    public static Guid PasswordResetTemplate => EmailTemplateDefaults.PasswordReset;

    /// <summary>The one-time code email: sends <c>{{code}}</c>, so it needs a credential.</summary>
    public static Guid OneTimeCodeTemplate => EmailTemplateDefaults.OneTimeCode;

    /// <summary>The account locked notice: takes no credential.</summary>
    public static Guid AccountLockedTemplate => EmailTemplateDefaults.AccountLocked;

    /// <summary>The security notice (Stories 4.8 and 4.11): takes no credential.</summary>
    public static Guid SecurityNotificationTemplate => EmailTemplateDefaults.SecurityNotification;

    /// <summary>The five template IDs, fixed for good: <c>verification</c>, <c>password_reset</c>, <c>one_time_code</c>, <c>account_locked</c> and <c>security_notification</c>.</summary>
    public static IReadOnlyList<Guid> EmailTemplateIds { get; } = [.. EmailTemplateDefaults.All.Select(t => t.Id)];

    /// <summary>The send job's payload: the User and template IDs, and the template's link token or code, if it sends one.</summary>
    public static JobPayload EmailPayload(Guid userId, Guid templateId, Secret<byte[]>? credential = null) =>
        new(new Dictionary<string, Guid> { [EmailUserIdName] = userId, [EmailTemplateIdName] = templateId }, credential);

    /// <summary>
    /// Emails per recipient (Story 4.5, AD-14): <see cref="SecurityLimits.EmailPerRecipientLimit"/> per User in a fixed
    /// <see cref="SecurityLimits.EmailPerRecipientWindow"/>, counted when each is sent. One past it is held back: dropped
    /// and logged, never delayed.
    /// </summary>
    public static readonly RateLimitPolicy EmailRecipientPolicy = new(
        "notifications.email.recipient",
        SecurityLimits.EmailPerRecipientLimit,
        SecurityLimits.EmailPerRecipientWindow);

    /// <summary>
    /// Whether <paramref name="address"/>, a User's stored email, is exactly one mailbox (Story 4.5): a valid address with
    /// no display name, list, group, comment or line break, so one User's email can never fan out to several recipients.
    /// </summary>
    public static bool IsSingleMailbox(string? address) =>
        !string.IsNullOrWhiteSpace(address)
        && address.Length <= SecurityLimits.MaxEmailLength
        && !address.Any(static c => char.IsWhiteSpace(c) || char.IsControl(c) || c == '"' || ",;<>()[]:".Contains(c))
        && address.Count(static c => c == '@') == 1
        && System.Net.Mail.MailAddress.TryCreate(address, out var parsed)
        && string.Equals(parsed.Address, address, StringComparison.Ordinal)
        && parsed.DisplayName.Length == 0;

    /// <summary>The template's built-in subject and body, or null when the ID is none of the five.</summary>
    public static EmailTemplateText? DefaultEmailTemplate(Guid templateId) => EmailTemplateDefaults.Find(templateId)?.Default;

    /// <summary>
    /// The context Tenant's text for the template (Story 4.5): its override (Story 15.4), else the built-in default; null
    /// when the ID is none of the five. It writes nothing.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't a Tenant's.</exception>
    public static Task<EmailTemplateText?> ReadEmailTemplateAsync(CommandContext context, Guid templateId, CancellationToken cancellationToken) =>
        EmailTemplateStore.ReadAsync(context, templateId, cancellationToken);

    /// <summary>
    /// Renders <paramref name="text"/> as the template <paramref name="templateId"/> (Story 4.5), by fixed substitution only:
    /// <c>{{tenant_name}}</c> always, <c>{{link}}</c> for verification and reset, <c>{{code}}</c> for the one-time code, each
    /// replaced by literal text in one pass. Any other <c>{{...}}</c> stays as written, and no substituted value is expanded
    /// again. <c>{{link}}</c> is <paramref name="emailLinkBase"/>, the Tenant's stored issuer and never a request's host, the
    /// template's path, and <c>?token=</c> with <paramref name="credential"/> URL-encoded. The subject loses every CR and LF.
    /// A template that sends a link or code refuses no credential, and any other refuses one.
    /// </summary>
    public static EmailRender RenderEmail(
        Guid templateId,
        EmailTemplateText text,
        string tenantName,
        string emailLinkBase,
        string? credential) =>
        EmailTemplateRenderer.Render(templateId, text, tenantName, emailLinkBase, credential);

    /// <summary>
    /// The context Tenant's email provider with its secret's Transit ciphertext, as Host.Worker reads it to send (Story
    /// 4.5), or null when it has none. It writes nothing. Only <c>gk_worker</c> may read the ciphertext.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't a Tenant's.</exception>
    public static Task<EmailDelivery?> ReadEmailDeliveryAsync(CommandContext context, CancellationToken cancellationToken) =>
        EmailProviderStore.ReadForSendAsync(context, cancellationToken);

    /// <summary>
    /// The transport the email port sends through (Story 4.5): <paramref name="delivery"/>'s settings, and its secret
    /// decrypted now through <paramref name="custody"/> under <paramref name="tenantId"/>'s <c>email-</c> key, with the
    /// Tenant ID as associated data. Only Host.Worker's custody may decrypt there.
    /// </summary>
    /// <exception cref="KeyCustodyException">Custody refused, rejected or failed the decrypt.</exception>
    public static Task<EmailTransport> CreateEmailTransportAsync(
        EmailDelivery delivery,
        Guid tenantId,
        IKeyCustody custody,
        CancellationToken cancellationToken) =>
        EmailTransports.CreateAsync(delivery, tenantId, custody, cancellationToken);
}
