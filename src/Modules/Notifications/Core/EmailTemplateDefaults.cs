using Gatekeep.Modules.Notifications.Contracts;

namespace Gatekeep.Modules.Notifications.Core;

/// <summary>What a template may substitute, and what its credential becomes.</summary>
internal enum EmailCredentialUse
{
    /// <summary>The template takes no credential, and a job carrying one is refused.</summary>
    None,

    /// <summary>The credential is a link token: <c>{{link}}</c> is the email link base, the template's path and <c>?token=</c>.</summary>
    Link,

    /// <summary>The credential is a one-time code: <c>{{code}}</c> is the code itself.</summary>
    Code,
}

/// <summary>One of the five templates: its fixed ID, its name, what its credential becomes, its link path and its default text.</summary>
internal sealed record EmailTemplateDefinition(
    Guid Id,
    string Name,
    EmailCredentialUse Credential,
    string? LinkPath,
    EmailTemplateText Default);

/// <summary>
/// The five built-in templates and their default text (Story 4.5), every string in this one file. The copy is short and
/// plain, names the Tenant and never Gatekeep. A Tenant's override (Story 15.4) replaces a template's subject and body,
/// never what it may substitute.
/// </summary>
internal static class EmailTemplateDefaults
{
    public const string TenantNameVariable = "tenant_name";
    public const string LinkVariable = "link";
    public const string CodeVariable = "code";

    /// <summary>Where Hosted Login serves the verification page (Story 4.7), under the email link base.</summary>
    public const string VerifyEmailPath = "login/verify-email";

    /// <summary>Where Hosted Login serves the reset page (Story 4.11), under the email link base.</summary>
    public const string ResetPasswordPath = "login/reset-password";

    public static readonly Guid Verification = Guid.Parse("01930000-0000-7000-8000-0000000045e1");
    public static readonly Guid PasswordReset = Guid.Parse("01930000-0000-7000-8000-0000000045e2");
    public static readonly Guid OneTimeCode = Guid.Parse("01930000-0000-7000-8000-0000000045e3");
    public static readonly Guid AccountLocked = Guid.Parse("01930000-0000-7000-8000-0000000045e4");
    public static readonly Guid SecurityNotification = Guid.Parse("01930000-0000-7000-8000-0000000045e5");

    public static readonly IReadOnlyList<EmailTemplateDefinition> All =
    [
        new(
            Verification,
            "verification",
            EmailCredentialUse.Link,
            VerifyEmailPath,
            new(
                "Verify your email for {{tenant_name}}",
                "Confirm this address to finish setting up your {{tenant_name}} account:\n\n{{link}}\n\n"
                + "If you didn't ask for this, ignore this email.")),
        new(
            PasswordReset,
            "password_reset",
            EmailCredentialUse.Link,
            ResetPasswordPath,
            new(
                "Reset your {{tenant_name}} password",
                "Use this link to choose a new password for your {{tenant_name}} account:\n\n{{link}}\n\n"
                + "The link works once and expires in 30 minutes. If you didn't ask for this, ignore this email. "
                + "Your password won't change.")),
        new(
            OneTimeCode,
            "one_time_code",
            EmailCredentialUse.Code,
            null,
            new(
                "Your {{tenant_name}} code",
                "Your code is {{code}}. It expires soon. Don't share it.")),
        new(
            AccountLocked,
            "account_locked",
            EmailCredentialUse.None,
            null,
            new(
                "Your {{tenant_name}} account is locked",
                "Sign-in to your {{tenant_name}} account is paused after too many failed attempts.\n\n"
                + "If this wasn't you, change your password as soon as you can sign in again.")),
        new(
            SecurityNotification,
            "security_notification",
            EmailCredentialUse.None,
            null,
            new(
                "Security notice for your {{tenant_name}} account",
                "There was a security change on your {{tenant_name}} account.\n\n"
                + "If you made it, there's nothing to do. If you didn't, contact {{tenant_name}} for help.")),
    ];

    public static EmailTemplateDefinition? Find(Guid id) => All.FirstOrDefault(t => t.Id == id);
}
