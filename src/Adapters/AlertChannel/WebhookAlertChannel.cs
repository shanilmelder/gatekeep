using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using Gatekeep.Adapters.Egress;
using Gatekeep.Kernel.Alerts;
using Gatekeep.Kernel.Records;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Adapters.AlertChannel;

/// <summary>Where the webhook is and the file its bearer token is read from, at each send.</summary>
public sealed record WebhookAlertOptions
{
    /// <summary>An absolute <c>https</c> URL with no user info or fragment (<see cref="TryParseUrl"/>).</summary>
    public required Uri Url { get; init; }

    public required string TokenFile { get; init; }

    /// <summary>How long one send may take, connecting included.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// The webhook URL, when <paramref name="text"/> is an absolute <c>https</c> URL with a host, no
    /// user info and no fragment. A path and query are allowed, as many services put the hook's
    /// name there. Null otherwise.
    /// </summary>
    public static Uri? TryParseUrl(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)
            || !Uri.TryCreate(text.Trim(), UriKind.Absolute, out var url)
            || url.Scheme != Uri.UriSchemeHttps
            || url.UserInfo.Length > 0
            || url.Fragment.Length > 0
            || url.Host.Length == 0
            || text.Contains('@', StringComparison.Ordinal))
        {
            return null;
        }

        return url;
    }
}

/// <summary>
/// <see cref="IAlertChannel"/> as one HTTPS <c>POST</c> of the alert's JSON with a bearer token, which
/// most alert services take directly or through a webhook bridge (Story 1.30). Only a 2xx answer
/// delivers; anything else, a redirect included, is <see cref="AlertChannelFailure.Rejected"/>. The
/// response body is never read and no failure carries the address, the token or the answer.
/// </summary>
public sealed class WebhookAlertChannel : IAlertChannel, IDisposable
{
    private readonly HttpClient _http;
    private readonly WebhookAlertOptions _options;

    /// <summary>Takes the handler from <see cref="EgressHttp.Create()"/>, and disposes it.</summary>
    public WebhookAlertChannel(HttpMessageHandler handler, WebhookAlertOptions options)
    {
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.Url);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.TokenFile);

        _options = options;
        _http = new HttpClient(handler, disposeHandler: true) { Timeout = options.Timeout };
    }

    /// <summary>
    /// The JSON body: exactly <c>alertId</c>, <c>code</c>, <c>deployment</c>, <c>raisedAt</c> and
    /// <c>summary</c>, plus <c>tenantId</c> and <c>eventId</c> when the alert has them, and
    /// <c>adminId</c>, <c>enrolmentId</c>, <c>issuedAt</c> and <c>expiresAt</c> when it names an
    /// enrolment (Story 1.32), in canonical form.
    /// </summary>
    public static byte[] Body(SecurityAlert alert)
    {
        ArgumentNullException.ThrowIfNull(alert);

        var body = new JsonObject
        {
            ["alertId"] = alert.AlertId.ToString("D"),
            ["code"] = alert.Code.Code.Value,
            ["deployment"] = alert.Deployment.Name,
            ["raisedAt"] = Timestamp(alert.RaisedAt),
            ["summary"] = alert.Summary,
        };

        if (alert.TenantId is { } tenantId)
        {
            body["tenantId"] = tenantId.ToString("D");
        }

        if (alert.EventId is { } eventId)
        {
            body["eventId"] = eventId.ToString("D");
        }

        if (alert.Enrolment is { } enrolment)
        {
            body["adminId"] = enrolment.AdminId.ToString("D");
            body["enrolmentId"] = enrolment.EnrolmentId.ToString("D");
            body["issuedAt"] = Timestamp(enrolment.IssuedAt);
            body["expiresAt"] = Timestamp(enrolment.ExpiresAt);
        }

        return CanonicalJson.Utf8(body);
    }

    /// <summary>RFC 3339 in UTC to the microsecond, as audit events and records are.</summary>
    private static string Timestamp(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", System.Globalization.CultureInfo.InvariantCulture);

    public async Task SendAsync(SecurityAlert alert, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(alert);

        var token = ReadToken();

        using var request = new HttpRequestMessage(HttpMethod.Post, _options.Url)
        {
            Content = new ByteArrayContent(Body(alert)),
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }
        catch (Exception e) when (EgressRefusedException.Find(e) is not null)
        {
            throw new AlertChannelException(AlertOperation.Send, AlertChannelFailure.Refused, AlertRefusal.Address);
        }
        catch (HttpRequestException)
        {
            throw new AlertChannelException(AlertOperation.Send, AlertChannelFailure.Unavailable);
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // HttpClient's own timeout, not the caller's cancellation.
            throw new AlertChannelException(AlertOperation.Send, AlertChannelFailure.Unavailable);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                throw new AlertChannelException(AlertOperation.Send, AlertChannelFailure.Rejected);
            }
        }
    }

    public void Dispose() => _http.Dispose();

    /// <summary>The token, read at each send so a replaced file takes effect. Its value is never kept or shown.</summary>
    private string ReadToken()
    {
        string token;
        try
        {
            token = File.ReadAllText(_options.TokenFile).Trim();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new AlertChannelException(AlertOperation.Send, AlertChannelFailure.Refused, AlertRefusal.TokenFile);
        }

        if (SecretDefaults.IsUnsafeCredential(token))
        {
            throw new AlertChannelException(AlertOperation.Send, AlertChannelFailure.Refused, AlertRefusal.TokenFile);
        }

        return token;
    }
}
