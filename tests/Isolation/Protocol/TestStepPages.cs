using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Gatekeep.Adapters.Hosting;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;
using Gatekeep.Tests.Isolation.Stack;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Gatekeep.Tests.Isolation.Protocol;

/// <summary>
/// Host.Hosted's step pages (Story 4.1), as its <c>HostedStepPages</c> composes them, which a test
/// host can't reference: the shared <see cref="StepPageTemplate"/> over the built Hosted Login bundle
/// (<c>apps/hosted-login/dist</c>, from <c>pnpm -r build</c>), the request's Tenant's theme from
/// Tenancy and the shared <see cref="RequestTrace"/>. <c>HostedStepTests</c> proves the real host's.
/// </summary>
internal sealed class TestStepPages(StepPageTemplate template) : IStepPages
{
    /// <summary>The built Hosted Login bundle.</summary>
    public static string Bundle { get; } = Path.Combine(Repository.Root, "apps", "hosted-login", "dist");

    /// <summary>Step pages over the built bundle.</summary>
    public static IStepPages Create(IServiceProvider _) =>
        new TestStepPages(StepPageTemplate.TryLoad(Bundle) ?? throw new InvalidOperationException($"{Bundle} holds no valid Hosted Login bundle: build the apps first (pnpm -r build)."));

    public string TraceId(HttpContext http) => RequestTrace.Id(http);

    public Task WriteAsync(HttpContext http, int statusCode, StepResponse step, CancellationToken cancellationToken) =>
        template.WriteAsync(
            http,
            statusCode,
            TenancyContract.Theme(http.Features.Get<ResolvedTenant>() ?? throw new InvalidOperationException("No resolved Tenant.")).Href,
            step.ToJson(),
            cancellationToken);

    public Task WriteJsonAsync(HttpContext http, int statusCode, StepResponse step, CancellationToken cancellationToken) =>
        StepPageTemplate.WriteJsonAsync(http, statusCode, step.ToJson(), cancellationToken);
}

/// <summary>Reads and checks a Hosted Login step page (Story 4.1).</summary>
internal static partial class StepPage
{
    /// <summary>
    /// <paramref name="response"/> is Generic error's step page: 400, never a redirect, <c>no-store</c>,
    /// the AD-21 headers and HTML, its step JSON <c>generic_error</c> with only the Tenant's name, a code
    /// and a trace ID. Returns the step's <c>data</c>.
    /// </summary>
    public static async Task<JsonElement> AssertGenericErrorAsync(HttpResponseMessage response, string? tenant = null, string? code = null)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.True(response.Headers.CacheControl?.NoStore, "The page isn't no-store.");
        Assert.Contains("no-cache", response.Headers.Pragma.Select(p => p.Name));
        Assert.Equal([SecurityHeaders.ContentSecurityPolicy], response.Headers.GetValues("Content-Security-Policy"));
        Assert.Equal(["DENY"], response.Headers.GetValues("X-Frame-Options"));
        Assert.Equal(["no-referrer"], response.Headers.GetValues("Referrer-Policy"));
        Assert.Equal(["nosniff"], response.Headers.GetValues("X-Content-Type-Options"));
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("utf-8", response.Content.Headers.ContentType?.CharSet);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        using var step = Read(body);
        var root = step.RootElement;
        Assert.Equal(["step", "stepVersion", "expiresInSeconds", "data", "csrfToken"], root.EnumerateObject().Select(p => p.Name));
        Assert.Equal("generic_error", root.GetProperty("step").GetString());
        Assert.Equal(1, root.GetProperty("stepVersion").GetInt32());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("expiresInSeconds").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("csrfToken").ValueKind);

        var data = root.GetProperty("data");
        Assert.Equal(["tenant", "code", "traceId"], data.EnumerateObject().Select(p => p.Name));
        Assert.Matches("^[a-z_]+$", data.GetProperty("code").GetString());
        Assert.Matches("^[0-9a-f]{32}$", data.GetProperty("traceId").GetString());
        if (tenant is not null)
        {
            Assert.Equal(tenant, data.GetProperty("tenant").GetString());
        }

        if (code is not null)
        {
            Assert.Equal(code, data.GetProperty("code").GetString());
        }

        Assert.Matches(ThemeLink(), Head(body));
        return data.Clone();
    }

    /// <summary>The step JSON a page embeds, from its one <c>#gk-step</c> data block.</summary>
    public static JsonDocument Read(string body)
    {
        var blocks = StepBlock().Matches(body);
        Assert.Single(blocks);
        return JsonDocument.Parse(blocks[0].Groups["json"].Value);
    }

    /// <summary>The page's <c>head</c>.</summary>
    public static string Head(string body)
    {
        var end = body.IndexOf("</head>", StringComparison.OrdinalIgnoreCase);
        Assert.True(end > 0, "The page has no head.");
        return body[..end];
    }

    [GeneratedRegex("""<script type="application/json" id="gk-step">(?<json>[^<]*)</script>""")]
    private static partial Regex StepBlock();

    [GeneratedRegex("""<link rel="stylesheet" href="/login/theme/[0-9a-f]{16}\.css">""")]
    public static partial Regex ThemeLink();
}
