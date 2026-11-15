using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Gatekeep.Adapters.Egress;
using Gatekeep.Kernel.Email;
using Gatekeep.Kernel.Limits;

namespace Gatekeep.Adapters.Email;

/// <summary>
/// <see cref="IEmailSender"/> with one adapter per provider kind (Story 4.5). The HTTP kinds each make one HTTPS
/// <c>POST</c> through a handler from <see cref="EgressHttp"/>, which checks every resolved address, follows no redirect
/// and refuses plain HTTP, so a Custom HTTP endpoint gets the same checks as a named provider. SMTP runs MailKit over a
/// stream <see cref="EgressSmtp"/> opened and checked. A response body is never read, and no result carries an address,
/// a setting or a secret: only a fixed reason code.
/// </summary>
public sealed partial class EmailSender : IEmailSender, IDisposable
{
    private const string JsonMediaType = "application/json";

    private readonly HttpClient _http;
    private readonly EgressSmtp _smtp;
    private readonly TimeProvider _time;

    /// <summary>
    /// Takes a handler from <see cref="EgressHttp.Create()"/>, which it disposes, and an <see cref="EgressSmtp"/>.
    /// <paramref name="time"/> dates SES signatures.
    /// </summary>
    public EmailSender(HttpMessageHandler handler, EgressSmtp smtp, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentNullException.ThrowIfNull(smtp);
        ArgumentNullException.ThrowIfNull(time);

        _http = new HttpClient(handler, disposeHandler: true) { Timeout = SecurityLimits.EmailSendTimeout };
        _smtp = smtp;
        _time = time;
    }

    /// <summary>Every refusal in force: <see cref="EgressHttp.Create()"/> and <see cref="EgressSmtp.Create()"/>.</summary>
    public static EmailSender Create(TimeProvider? time = null) =>
        new(EgressHttp.Create(), EgressSmtp.Create(), time ?? TimeProvider.System);

    public async Task<EmailSendResult> SendAsync(EmailTransport transport, EmailMessage message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(message);

        if (transport.Kind == "smtp")
        {
            return await SmtpDelivery.SendAsync(_smtp, transport, message, cancellationToken);
        }

        HttpRequestMessage? request;
        try
        {
            request = Request(transport, message);
        }
        catch (Exception e) when (e is ArgumentException or FormatException or UriFormatException or InvalidOperationException)
        {
            return EmailSendResult.Permanent("invalid_request");
        }

        if (request is null)
        {
            return EmailSendResult.Permanent("invalid_settings");
        }

        using (request)
        {
            return await PostAsync(request, cancellationToken);
        }
    }

    public void Dispose() => _http.Dispose();

    /// <summary>A 2xx sends. A timeout, 429 or 5xx may succeed later. Anything else, a redirect included, never will.</summary>
    internal static EmailSendResult Classify(HttpStatusCode status)
    {
        var code = (int)status;
        var reason = string.Create(CultureInfo.InvariantCulture, $"http_{code}");
        return code switch
        {
            >= 200 and < 300 => EmailSendResult.Sent,
            408 or 429 or >= 500 => EmailSendResult.Transient(reason),
            _ => EmailSendResult.Permanent(reason),
        };
    }

    private async Task<EmailSendResult> PostAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            return Classify(response.StatusCode);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception e) when (EgressRefusedException.Find(e) is not null)
        {
            return EmailSendResult.Permanent("egress_refused");
        }
        catch (OperationCanceledException)
        {
            return EmailSendResult.Transient("timeout");
        }
        catch (HttpRequestException)
        {
            return EmailSendResult.Transient("connect_failed");
        }
    }

    /// <summary>The kind's one request, or null when its settings or secret are missing.</summary>
    private HttpRequestMessage? Request(EmailTransport transport, EmailMessage message)
    {
        var secret = transport.Secret?.Use(static s => s);
        if (string.IsNullOrEmpty(secret) || secret.Contains('\r', StringComparison.Ordinal) || secret.Contains('\n', StringComparison.Ordinal))
        {
            return null;
        }

        return transport.Kind switch
        {
            "sendgrid" => SendGrid(transport, message, secret),
            "postmark" => Postmark(transport, message, secret),
            "mailgun" => Mailgun(transport, message, secret),
            "ses" => Ses(transport, message, secret),
            "custom_http" => CustomHttp(transport, message, secret),
            _ => null,
        };
    }

    private static HttpRequestMessage SendGrid(EmailTransport transport, EmailMessage message, string apiKey)
    {
        var from = new JsonObject { ["email"] = message.FromAddress };
        if (message.FromName is { } name)
        {
            from["name"] = name;
        }

        var body = new JsonObject
        {
            ["personalizations"] = new JsonArray(new JsonObject { ["to"] = new JsonArray(new JsonObject { ["email"] = message.To }) }),
            ["from"] = from,
            ["subject"] = message.Subject,
            ["content"] = new JsonArray(new JsonObject { ["type"] = "text/plain", ["value"] = message.Body }),
        };

        var request = Json(Https(transport.Region == "eu" ? "api.eu.sendgrid.com/v3/mail/send" : "api.sendgrid.com/v3/mail/send"), body);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
        return request;
    }

    private static HttpRequestMessage Postmark(EmailTransport transport, EmailMessage message, string serverToken)
    {
        var body = new JsonObject
        {
            ["From"] = Mailbox(message),
            ["To"] = message.To,
            ["Subject"] = message.Subject,
            ["TextBody"] = message.Body,
            ["MessageStream"] = string.IsNullOrEmpty(transport.MessageStream) ? "outbound" : transport.MessageStream,
        };

        var request = Json(Https("api.postmarkapp.com/email"), body);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(JsonMediaType));
        request.Headers.TryAddWithoutValidation("X-Postmark-Server-Token", serverToken);
        return request;
    }

    private static HttpRequestMessage? Mailgun(EmailTransport transport, EmailMessage message, string apiKey)
    {
        if (string.IsNullOrEmpty(transport.Domain))
        {
            return null;
        }

        var root = transport.Region == "eu" ? "api.eu.mailgun.net/v3/" : "api.mailgun.net/v3/";
        var request = new HttpRequestMessage(HttpMethod.Post, Https($"{root}{Uri.EscapeDataString(transport.Domain)}/messages"))
        {
            Content = new FormUrlEncodedContent(
            [
                new("from", Mailbox(message)),
                new("to", message.To),
                new("subject", message.Subject),
                new("text", message.Body),
            ]),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"api:{apiKey}")));
        return request;
    }

    private HttpRequestMessage? Ses(EmailTransport transport, EmailMessage message, string secretAccessKey)
    {
        // Checked again here: the region becomes part of the host.
        if (transport.Region is null || !SesRegion().IsMatch(transport.Region) || string.IsNullOrEmpty(transport.AccessKeyId))
        {
            return null;
        }

        var body = new JsonObject
        {
            ["FromEmailAddress"] = Mailbox(message),
            ["Destination"] = new JsonObject { ["ToAddresses"] = new JsonArray(message.To) },
            ["Content"] = new JsonObject
            {
                ["Simple"] = new JsonObject
                {
                    ["Subject"] = new JsonObject { ["Data"] = message.Subject, ["Charset"] = "UTF-8" },
                    ["Body"] = new JsonObject
                    {
                        ["Text"] = new JsonObject { ["Data"] = message.Body, ["Charset"] = "UTF-8" },
                    },
                },
            },
        };

        var bytes = Encoding.UTF8.GetBytes(body.ToJsonString());
        var request = new HttpRequestMessage(HttpMethod.Post, Https($"email.{transport.Region}.amazonaws.com/v2/email/outbound-emails"))
        {
            Content = new ByteArrayContent(bytes),
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue(JsonMediaType);
        SigV4.Sign(request, bytes, transport.AccessKeyId, secretAccessKey, transport.Region, _time.GetUtcNow(), SigV4.Ses);
        return request;
    }

    private static HttpRequestMessage? CustomHttp(EmailTransport transport, EmailMessage message, string headerValue)
    {
        if (string.IsNullOrEmpty(transport.Endpoint) || !Uri.TryCreate(transport.Endpoint, UriKind.Absolute, out var endpoint))
        {
            return null;
        }

        var body = new JsonObject
        {
            ["from"] = new JsonObject { ["address"] = message.FromAddress, ["name"] = message.FromName },
            ["to"] = message.To,
            ["subject"] = message.Subject,
            ["text"] = message.Body,
        };

        var request = Json(endpoint, body);
        var name = string.IsNullOrEmpty(transport.AuthHeaderName) ? "Authorization" : transport.AuthHeaderName;
        if (EmailHeaderNames.IsReserved(name) || !request.Headers.TryAddWithoutValidation(name, headerValue))
        {
            request.Dispose();
            return null;
        }

        return request;
    }

    /// <summary>A provider's fixed endpoint, always HTTPS: <paramref name="hostAndPath"/> carries no scheme of its own.</summary>
    private static Uri Https(string hostAndPath) => new($"{Uri.UriSchemeHttps}{Uri.SchemeDelimiter}{hostAndPath}");

    private static HttpRequestMessage Json(Uri uri, JsonObject body) =>
        new(HttpMethod.Post, uri) { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, JsonMediaType) };

    /// <summary>
    /// The From mailbox for a header-style field: <c>Name &lt;address&gt;</c> when it has a name, the name quoted or RFC 2047
    /// encoded as MIME needs, so a non-ASCII name reaches the provider as a valid header.
    /// </summary>
    private static string Mailbox(EmailMessage message) =>
        message.FromName is { Length: > 0 } name ? new MimeKit.MailboxAddress(name, message.FromAddress).ToString(true) : message.FromAddress;

    [GeneratedRegex(@"\A[a-z]{2}(-[a-z]+)+-[0-9]\z", RegexOptions.CultureInvariant)]
    private static partial Regex SesRegion();
}
