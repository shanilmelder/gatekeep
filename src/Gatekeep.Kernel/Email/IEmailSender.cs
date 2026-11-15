using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Kernel.Email;

/// <summary>
/// Sends one plain-text email through a Tenant's provider (Story 4.5, AD-15, AD-26). An adapter per provider kind sits
/// behind it, and every one reaches the provider only through the vetted egress path. It never throws for a delivery
/// failure: it says whether the message was sent, was refused for good, or may succeed if tried again. Only the
/// caller's cancellation throws.
/// </summary>
public interface IEmailSender
{
    Task<EmailSendResult> SendAsync(EmailTransport transport, EmailMessage message, CancellationToken cancellationToken);
}

/// <summary>
/// How to reach a Tenant's provider (Story 4.5): its kind, the kind's non-secret settings and its one secret, decrypted at
/// the moment of use and held only as <see cref="Secret{T}"/>. Only the members of its kind are set.
/// </summary>
public sealed record EmailTransport
{
    public required string Kind { get; init; }

    /// <summary><c>smtp</c>: a DNS name or public IP.</summary>
    public string? Host { get; init; }

    /// <summary><c>smtp</c>: 1 to 65535.</summary>
    public int? Port { get; init; }

    /// <summary><c>smtp</c>: <c>starttls</c> or <c>implicit</c>. Never plaintext.</summary>
    public string? Tls { get; init; }

    /// <summary><c>smtp</c>, optional: AUTH is used only when it is set.</summary>
    public string? Username { get; init; }

    /// <summary><c>sendgrid</c> (<c>global</c> or <c>eu</c>), <c>mailgun</c> (<c>us</c> or <c>eu</c>) or <c>ses</c>.</summary>
    public string? Region { get; init; }

    /// <summary><c>postmark</c>, optional: <c>outbound</c> when unset.</summary>
    public string? MessageStream { get; init; }

    /// <summary><c>mailgun</c>: the sending domain.</summary>
    public string? Domain { get; init; }

    /// <summary><c>ses</c>.</summary>
    public string? AccessKeyId { get; init; }

    /// <summary><c>custom_http</c>: an absolute <c>https</c> URL.</summary>
    public string? Endpoint { get; init; }

    /// <summary><c>custom_http</c>: the header the secret is sent in.</summary>
    public string? AuthHeaderName { get; init; }

    /// <summary>The provider's password, API key or token. Null only for SMTP with no username.</summary>
    public Secret<string>? Secret { get; init; }

    /// <summary>The kind only: no setting, destination or secret.</summary>
    public override string ToString() => $"{nameof(EmailTransport)} {Kind}";
}

/// <summary>
/// One plain-text message (Story 4.5): no HTML part, remote content or attachment. The recipient is resolved at send
/// time and never logged, so this prints no address, subject or body.
/// </summary>
public sealed record EmailMessage(string FromAddress, string? FromName, string To, string Subject, string Body)
{
    public override string ToString() => nameof(EmailMessage);
}

/// <summary>How one send ended.</summary>
public enum EmailSendOutcome
{
    /// <summary>The provider accepted the message.</summary>
    Sent,

    /// <summary>Refused for good: a refused recipient, bad credentials, a refused destination, any other client error.</summary>
    Permanent,

    /// <summary>May succeed later: a failed connect, a timeout, a rate limit or a server error.</summary>
    Transient,
}

/// <summary>A send's outcome and a fixed reason code, such as <c>http_503</c> or <c>smtp_550</c>. The code never holds a value.</summary>
public sealed record EmailSendResult(EmailSendOutcome Outcome, string Reason)
{
    public static EmailSendResult Sent { get; } = new(EmailSendOutcome.Sent, "sent");

    public static EmailSendResult Permanent(string reason) => new(EmailSendOutcome.Permanent, reason);

    public static EmailSendResult Transient(string reason) => new(EmailSendOutcome.Transient, reason);
}

/// <summary>
/// HTTP header names a provider's auth header may never take (Story 4.5): the ones that frame or route the request, so a
/// stored setting can't rewrite where or how the request is sent. Checked when a provider is saved and again at send.
/// </summary>
public static class EmailHeaderNames
{
    private static readonly string[] Reserved = ["Host", "Transfer-Encoding", "Connection", "Cookie", "Upgrade", "TE", "Trailer", "Expect", "Keep-Alive"];

    private static readonly string[] ReservedPrefixes = ["Content-", "Proxy-"];

    public static bool IsReserved(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return Reserved.Any(r => string.Equals(r, name, StringComparison.OrdinalIgnoreCase))
            || ReservedPrefixes.Any(p => name.StartsWith(p, StringComparison.OrdinalIgnoreCase));
    }
}
