using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Gatekeep.Modules.Protocol.Contracts;
using Xunit;

namespace Gatekeep.Tests.Isolation.Protocol;

/// <summary>
/// One browser on one Tenant host, as Hosted Login sees it (Story 4.2): a cookie jar the host's <c>Set-Cookie</c>
/// headers fill and clear, requests that send its cookies back, and the API requests Hosted Login's client makes,
/// with the page's CSRF token and the Tenant's exact <c>Origin</c>. Every <c>Set-Cookie</c> it saw is kept, so a test
/// can check the attributes. Redirects are never followed: a test reads each one.
/// </summary>
internal sealed class HostedBrowser(ProtocolHost host, string tenantHost, string? origin = null)
{
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    /// <summary>The cookies the browser holds, by name.</summary>
    public Dictionary<string, string> Cookies { get; } = new(StringComparer.Ordinal);

    /// <summary>Every <c>Set-Cookie</c> header the browser was sent, in order.</summary>
    public List<string> SetCookies { get; } = [];

    public string TenantHost => tenantHost;

    /// <summary>The Tenant's issuer origin, which a same-origin request sends as its <c>Origin</c>.</summary>
    public string Origin => origin ?? new UriBuilder(Uri.UriSchemeHttps, tenantHost).Uri.GetLeftPart(UriPartial.Authority);

    /// <summary>GETs <paramref name="pathAndQuery"/> with the browser's cookies, keeping what the response sets.</summary>
    public async Task<HttpResponseMessage> GetAsync(string pathAndQuery)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://{tenantHost}{pathAndQuery}"));
        return await SendAsync(request);
    }

    /// <summary>
    /// POSTs <paramref name="body"/> as JSON to a Hosted Login API path with the browser's cookies, <paramref name="csrf"/>
    /// in <c>X-Gatekeep-CSRF</c> unless null, and <paramref name="requestOrigin"/> (by default <see cref="Origin"/>) unless
    /// <see cref="NoOrigin"/>.
    /// </summary>
    public async Task<HttpResponseMessage> PostAsync(string path, object body, string? csrf, string? requestOrigin = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"http://{tenantHost}{path}"))
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
        };

        if (csrf is not null)
        {
            request.Headers.TryAddWithoutValidation(ProtocolContract.CsrfHeader, csrf);
        }

        var sentOrigin = requestOrigin ?? Origin;
        if (sentOrigin != NoOrigin)
        {
            request.Headers.TryAddWithoutValidation("Origin", sentOrigin);
        }

        return await SendAsync(request);
    }

    /// <summary>The value <see cref="PostAsync"/> takes to send no <c>Origin</c> at all.</summary>
    public const string NoOrigin = "";

    /// <summary>
    /// Signs <paramref name="user"/> in through Hosted Login for the authorization request <paramref name="authorizeUrl"/>,
    /// as a browser does: the request goes to <c>/login</c>, the page's step is Login, Continue posts the test-only
    /// credential step's email for the User (authenticated at <paramref name="authTime"/>, or now), and the redirect step
    /// is followed back to the authorization endpoint. Returns that last response, the code's redirect when all went well.
    /// A first response that isn't the redirect to <c>/login</c>, such as a reused Session's code or an error, is returned
    /// as it is.
    /// </summary>
    public async Task<HttpResponseMessage> SignInAsync(string authorizeUrl, Guid user, DateTimeOffset? authTime = null)
    {
        var first = await GetAsync(authorizeUrl);
        if (!IsLoginRedirect(first))
        {
            return first;
        }

        first.Dispose();
        var login = await LoginStepAsync();
        using var continued = await PostAsync(
            ProtocolContract.LoginIdentifierPath,
            new { stepVersion = login.StepVersion, email = TestOnlyCredentialStep.Email(user, authTime) },
            login.Csrf);
        Assert.Equal(HttpStatusCode.OK, continued.StatusCode);
        using var next = await StepAsync(continued);
        Assert.Equal(StepNames.Redirect, next.RootElement.GetProperty("step").GetString());
        return await GetAsync(next.RootElement.GetProperty("data").GetProperty("location").GetString()!);
    }

    /// <summary>GETs <c>/login</c> and reads its Login step: the step version and CSRF token Continue needs.</summary>
    public async Task<(int StepVersion, string Csrf, JsonElement Step)> LoginStepAsync()
    {
        using var page = await GetAsync(ProtocolContract.LoginPath);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        using var step = StepPage.Read(await page.Content.ReadAsStringAsync(Cancellation));
        var root = step.RootElement;
        Assert.Equal(StepNames.Login, root.GetProperty("step").GetString());
        return (root.GetProperty("stepVersion").GetInt32(), root.GetProperty("csrfToken").GetString()!, root.Clone());
    }

    /// <summary>The JSON step an API response holds.</summary>
    public static async Task<JsonDocument> StepAsync(HttpResponseMessage response)
    {
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
    }

    /// <summary>Whether <paramref name="response"/> is the authorization endpoint's redirect to Login.</summary>
    public static bool IsLoginRedirect(HttpResponseMessage response) =>
        response.StatusCode == HttpStatusCode.Found && response.Headers.Location?.OriginalString == ProtocolContract.LoginPath;

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request)
    {
        if (Cookies.Count > 0)
        {
            request.Headers.TryAddWithoutValidation("Cookie", string.Join("; ", Cookies.Select(c => $"{c.Key}={c.Value}")));
        }

        var response = await host.Http.SendAsync(request, Cancellation);
        if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
        {
            foreach (var cookie in cookies)
            {
                SetCookies.Add(cookie);
                Absorb(cookie);
            }
        }

        return response;
    }

    private void Absorb(string setCookie)
    {
        var parts = setCookie.Split(';', StringSplitOptions.TrimEntries);
        var pair = parts[0].Split('=', 2);
        if (parts.Any(p => p.Equals("Max-Age=0", StringComparison.OrdinalIgnoreCase)) || pair[1].Length == 0)
        {
            Cookies.Remove(pair[0]);
        }
        else
        {
            Cookies[pair[0]] = pair[1];
        }
    }
}

/// <summary>A <c>Set-Cookie</c> header's parts, for checking a cookie's attributes.</summary>
internal static class SetCookie
{
    /// <summary>The attributes of <paramref name="setCookie"/> after its name and value, as written.</summary>
    public static IReadOnlyList<string> Attributes(string setCookie) =>
        [.. setCookie.Split(';', StringSplitOptions.TrimEntries).Skip(1)];

    public static string Name(string setCookie) => setCookie.Split('=', 2)[0];

    public static string Value(string setCookie) => setCookie.Split(';', 2)[0].Split('=', 2)[1];

    /// <summary>The headers <paramref name="response"/> sets cookies with.</summary>
    public static IReadOnlyList<string> Of(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Set-Cookie", out var values) ? [.. values] : [];

    /// <summary>A header value list's single value, or null.</summary>
    public static string? Single(HttpHeaders headers, string name) =>
        headers.TryGetValues(name, out var values) ? values.SingleOrDefault() : null;
}
