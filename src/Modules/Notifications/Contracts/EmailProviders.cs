using System.Text.Json;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Modules.Notifications.Contracts;

/// <summary>The kinds of email provider a Tenant can configure (Story 4.4), in a fixed order.</summary>
public static class EmailProviderKinds
{
    public const string Smtp = "smtp";
    public const string SendGrid = "sendgrid";
    public const string Postmark = "postmark";
    public const string Mailgun = "mailgun";
    public const string Ses = "ses";
    public const string CustomHttp = "custom_http";

    public static IReadOnlyList<string> All { get; } = [Smtp, SendGrid, Postmark, Mailgun, Ses, CustomHttp];
}

/// <summary>The fields an email provider save's errors name (Story 4.4). A settings member is <c>settings.{name}</c>.</summary>
public static class EmailProviderFields
{
    public const string Kind = "kind";

    /// <summary>The settings object as a whole: not an object, or holding a member its kind doesn't have.</summary>
    public const string Settings = "settings";

    public const string Host = "settings.host";
    public const string Port = "settings.port";
    public const string Tls = "settings.tls";
    public const string Username = "settings.username";
    public const string Region = "settings.region";
    public const string MessageStream = "settings.messageStream";
    public const string Domain = "settings.domain";
    public const string AccessKeyId = "settings.accessKeyId";
    public const string Endpoint = "settings.endpoint";
    public const string AuthHeaderName = "settings.authHeaderName";
    public const string FromAddress = "fromAddress";
    public const string FromName = "fromName";
    public const string Secret = "secret";

    public static IReadOnlyList<string> All { get; } =
    [
        Kind, Settings, Host, Port, Tls, Username, Region, MessageStream, Domain, AccessKeyId, Endpoint, AuthHeaderName,
        FromAddress, FromName, Secret,
    ];
}

/// <summary>The reasons an email provider save's errors give (Story 4.4).</summary>
public static class EmailProviderReasons
{
    /// <summary>Absent, or null, where it is needed.</summary>
    public const string Required = "required";

    /// <summary>Of the wrong type or form, or not one of its allowed values.</summary>
    public const string Invalid = "invalid";

    /// <summary>Longer than its limit.</summary>
    public const string TooLong = "too_long";

    public static IReadOnlyList<string> All { get; } = [Required, Invalid, TooLong];
}

/// <summary>One refused field of an email provider save: its name and why, never its value.</summary>
public sealed record EmailProviderFieldError(string Field, string Reason);

/// <summary>
/// A save's input as the request gave it (Story 4.4): each part may be missing, and the save decides. The
/// secret is held only as <see cref="Secret{T}"/> and only until it is encrypted.
/// </summary>
public sealed record EmailProviderInput(
    string? Kind,
    JsonElement? Settings,
    string? FromAddress,
    string? FromName,
    Secret<string>? Secret);

/// <summary>
/// A provider's non-secret settings as stored: only the members of its kind are set (Story 4.4). The
/// secret is never part of them.
/// </summary>
public sealed record EmailProviderSettings
{
    /// <summary><c>smtp</c>: a DNS name or public IP.</summary>
    public string? Host { get; init; }

    /// <summary><c>smtp</c>: 1 to 65535.</summary>
    public int? Port { get; init; }

    /// <summary><c>smtp</c>: <c>starttls</c> or <c>implicit</c>.</summary>
    public string? Tls { get; init; }

    /// <summary><c>smtp</c>, optional.</summary>
    public string? Username { get; init; }

    /// <summary><c>sendgrid</c> (<c>global</c> or <c>eu</c>), <c>mailgun</c> (<c>us</c> or <c>eu</c>) or <c>ses</c>.</summary>
    public string? Region { get; init; }

    /// <summary><c>postmark</c>, optional.</summary>
    public string? MessageStream { get; init; }

    /// <summary><c>mailgun</c>: a DNS name.</summary>
    public string? Domain { get; init; }

    /// <summary><c>ses</c>.</summary>
    public string? AccessKeyId { get; init; }

    /// <summary><c>custom_http</c>: an absolute <c>https</c> URL.</summary>
    public string? Endpoint { get; init; }

    /// <summary><c>custom_http</c>: the header the secret is sent in.</summary>
    public string? AuthHeaderName { get; init; }
}

/// <summary>
/// The Tenant's email provider as stored (Story 4.4), without its secret: whether one is stored is all that
/// is said of it.
/// </summary>
public sealed record EmailProviderConfiguration(
    string Kind,
    EmailProviderSettings Settings,
    string FromAddress,
    string? FromName,
    DateTimeOffset UpdatedAt,
    bool SecretSet);

/// <summary>How a save ended.</summary>
public enum EmailProviderSaveStatus
{
    /// <summary>Written, with <c>notifications.email_provider.updated</c>.</summary>
    Saved,

    /// <summary>Exactly what is stored, with no new secret: nothing written.</summary>
    Unchanged,

    /// <summary>A field is refused; the result names each. Nothing written.</summary>
    Invalid,

    /// <summary>Key custody is missing or failed to encrypt the secret. Nothing written; the caller rolls back.</summary>
    Unavailable,
}

/// <summary>A save's outcome: the provider as it now stands on <see cref="EmailProviderSaveStatus.Saved"/> and <see cref="EmailProviderSaveStatus.Unchanged"/>.</summary>
public sealed record EmailProviderSave(
    EmailProviderSaveStatus Status,
    EmailProviderConfiguration? Provider,
    IReadOnlyList<EmailProviderFieldError> Errors);
