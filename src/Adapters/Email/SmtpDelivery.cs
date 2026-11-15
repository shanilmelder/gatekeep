using System.Globalization;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Net.Sockets;
using Gatekeep.Adapters.Egress;
using Gatekeep.Kernel.Email;
using Gatekeep.Kernel.Limits;
using MailKit;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using MimeKit.Text;
using MimeKit.Utils;

namespace Gatekeep.Adapters.Email;

/// <summary>
/// SMTP (Story 4.5): <see cref="EgressSmtp"/> resolves the host, refuses a non-public address and connects; MailKit then
/// takes that stream, never a socket of its own, and runs STARTTLS (<c>starttls</c>) or TLS from the first byte
/// (<c>implicit</c>), with the certificate chain and host name validated but nothing fetched: revocation isn't checked and
/// no certificate is downloaded, since the host is a Tenant's choice. A server that offers no STARTTLS is refused:
/// there is no plaintext SMTP. AUTH runs only when a username is set. The message is one <c>text/plain</c> part.
/// </summary>
internal static class SmtpDelivery
{
    private static readonly TimeSpan QuitTimeout = TimeSpan.FromSeconds(5);

    public static async Task<EmailSendResult> SendAsync(
        EgressSmtp egress,
        EmailTransport transport,
        EmailMessage message,
        CancellationToken cancellationToken)
    {
        if (transport.Host is not { Length: > 0 } host
            || transport.Port is not { } port
            || transport.Tls is not ("starttls" or "implicit"))
        {
            return EmailSendResult.Permanent("invalid_settings");
        }

        if (transport.Username is not null && transport.Secret is null)
        {
            return EmailSendResult.Permanent("invalid_settings");
        }

        MimeMessage mime;
        try
        {
            mime = Message(message);
        }
        catch (Exception e) when (e is ParseException or ArgumentException)
        {
            return EmailSendResult.Permanent("invalid_message");
        }

        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(SecurityLimits.EmailSendTimeout);

        using var client = new VettedSmtpClient(egress.CreateChainPolicy())
        {
            Timeout = (int)SecurityLimits.EmailSendTimeout.TotalMilliseconds,
            // The chain policy decides revocation: never checked, so nothing the certificate names is fetched.
            CheckCertificateRevocation = false,
            // The chain was built against the vetted policy; any error, a name mismatch included, refuses it.
            ServerCertificateValidationCallback = static (_, certificate, _, errors) => certificate is not null && errors == SslPolicyErrors.None,
        };

        try
        {
            var stream = await egress.OpenAsync(host, port, limit.Token);
            try
            {
                // MailKit takes the stream Egress checked and connected: it opens no connection of its own.
                await client.ConnectAsync(
                    stream,
                    host,
                    port,
                    transport.Tls == "implicit" ? SecureSocketOptions.SslOnConnect : SecureSocketOptions.StartTls,
                    limit.Token);
            }
            catch
            {
                await stream.DisposeAsync();
                throw;
            }

            if (transport.Username is { } username)
            {
                await transport.Secret!.Use(password => client.AuthenticateAsync(username, password, limit.Token));
            }

            await client.SendAsync(mime, limit.Token);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception e)
        {
            return Classify(e);
        }

        // The server already accepted the message: QUIT gets a short bound of its own and no caller cancellation, and
        // whatever happens to it, the email was sent and is never retried.
        try
        {
            client.Timeout = (int)QuitTimeout.TotalMilliseconds;
            using var quit = new CancellationTokenSource(QuitTimeout);
            await client.DisconnectAsync(quit: true, quit.Token);
        }
        catch (Exception)
        {
            // Nothing to do: the message is delivered.
        }

        return EmailSendResult.Sent;
    }

    /// <summary>A refused destination, bad credentials, a missing extension or a 5xx answer never succeed; anything else may.</summary>
    internal static EmailSendResult Classify(Exception exception) => exception switch
    {
        EgressRefusedException => EmailSendResult.Permanent("egress_refused"),
        ArgumentException => EmailSendResult.Permanent("invalid_settings"),
        MailKit.Security.AuthenticationException => EmailSendResult.Permanent("smtp_auth"),
        SmtpCommandException command => (int)command.StatusCode >= 500
            ? EmailSendResult.Permanent(string.Create(CultureInfo.InvariantCulture, $"smtp_{(int)command.StatusCode}"))
            : EmailSendResult.Transient(string.Create(CultureInfo.InvariantCulture, $"smtp_{(int)command.StatusCode}")),
        NotSupportedException => EmailSendResult.Permanent("smtp_unsupported"),
        SslHandshakeException => EmailSendResult.Transient("tls_failed"),
        SmtpProtocolException => EmailSendResult.Transient("smtp_protocol"),
        OperationCanceledException or TimeoutException => EmailSendResult.Transient("timeout"),
        SocketException or IOException or ServiceNotConnectedException => EmailSendResult.Transient("connect_failed"),
        _ => EmailSendResult.Transient("smtp_failed"),
    };

    /// <summary>MailKit's client, whose TLS builds the certificate chain with Egress's policy: no revocation fetch, no download.</summary>
    private sealed class VettedSmtpClient(X509ChainPolicy policy) : SmtpClient
    {
        protected override SslClientAuthenticationOptions GetSslClientAuthenticationOptions(string host, RemoteCertificateValidationCallback remoteCertificateValidationCallback)
        {
            var options = base.GetSslClientAuthenticationOptions(host, remoteCertificateValidationCallback);
            options.CertificateChainPolicy = policy;
            options.CertificateRevocationCheckMode = X509RevocationMode.NoCheck;
            return options;
        }
    }

    private static MimeMessage Message(EmailMessage message)
    {
        var from = new MailboxAddress(message.FromName ?? string.Empty, message.FromAddress);
        var mime = new MimeMessage();
        mime.From.Add(from);
        mime.To.Add(new MailboxAddress(string.Empty, message.To));
        mime.Subject = message.Subject;
        mime.MessageId = MimeUtils.GenerateMessageId(from.Domain);
        mime.Body = new TextPart(TextFormat.Plain) { Text = message.Body };
        return mime;
    }
}
