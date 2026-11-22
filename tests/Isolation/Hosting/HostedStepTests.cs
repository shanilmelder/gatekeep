using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Gatekeep.Adapters.Hosting;
using Gatekeep.Modules.Tenancy.Contracts;
using Gatekeep.Tests.Isolation.Bootstrap;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Gatekeep.Tests.Isolation.Stack;
using Xunit;

namespace Gatekeep.Tests.Isolation.Hosting;

/// <summary>
/// Story 4.1: a real <c>Host.Hosted</c> serving the built Hosted Login bundle (<c>apps/hosted-login/dist</c>,
/// from <c>pnpm -r build</c>) through <c>--webroot</c>, over a migrated database as <c>gk_hosted</c> and the
/// real OpenBao. An authorization request it can't send back is Generic error's step page: the bundle's
/// <c>index.html</c> with the step as HTML-safe JSON and the Tenant's theme linked in <c>head</c>, 400,
/// <c>no-store</c> and the exact AD-21 headers. The bundle's assets and the theme are served with the
/// headers too. The browser harness (<c>tests/browser/hosted-step-server.mjs</c>) injects the same markers.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed partial class HostedStepTests(PostgresFixture postgres, OpenBaoFixture bao) : IDisposable
{
    private const string Host = "steps.hosted.test";
    private const string Callback = "https://client.steps.test/callback";
    private const string HostileName = "</script><b>x";

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    private static readonly string Bundle = Path.Combine(Repository.Root, "apps", "hosted-login", "dist");

    private readonly List<OpenBaoSocketProxy> _sockets = [];
    private readonly List<HostProcess> _processes = [];

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public void Built_index_holds_both_markers_and_nothing_the_policy_would_block()
    {
        var index = File.ReadAllText(IndexPath());

        Assert.Single(Regex.Matches(index, Regex.Escape(StepPageTemplate.HeadMarker)));
        Assert.Single(Regex.Matches(index, Regex.Escape(StepPageTemplate.StepMarker)));
        Assert.True(index.IndexOf(StepPageTemplate.HeadMarker, StringComparison.Ordinal) < index.IndexOf("</head>", StringComparison.Ordinal));
        AssertNothingBlocked(index);
        Assert.Contains("<noscript>", index, StringComparison.Ordinal);
        Assert.DoesNotContain("%gk:", index, StringComparison.Ordinal);
        Assert.DoesNotContain("Gatekeep", index, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unknown_client_gets_Generic_error_with_its_code_and_the_requests_trace()
    {
        var (port, _) = await StartAsync();
        var trace = Convert.ToHexStringLower(Guid.NewGuid().ToByteArray());

        using var response = await SendAsync(port, AuthorizeUrl("nope", Callback), trace);

        var data = await StepPage.AssertGenericErrorAsync(response, ProtocolDatabase.TestTenantName);
        Assert.Equal(trace, data.GetProperty("traceId").GetString());
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        AssertPage(body);
        Assert.DoesNotContain("echo-me-not", body, StringComparison.Ordinal);
        Assert.DoesNotContain("client.steps.test", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unregistered_redirect_uri_gets_the_same_page_with_its_code()
    {
        var (port, clientId) = await StartAsync();

        using var response = await SendAsync(port, AuthorizeUrl(clientId, "https://elsewhere.steps.test/cb"));

        var data = await StepPage.AssertGenericErrorAsync(response, ProtocolDatabase.TestTenantName);
        Assert.Matches("^invalid_[a-z_]+$", data.GetProperty("code").GetString());
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        AssertPage(body);
        Assert.DoesNotContain("elsewhere.steps.test", body, StringComparison.Ordinal);
        Assert.DoesNotContain(clientId, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Hostile_Tenant_name_is_escaped_in_the_JSON_and_read_back_literally()
    {
        var (port, _) = await StartAsync(HostileName);

        using var response = await SendAsync(port, AuthorizeUrl("nope", Callback));

        var data = await StepPage.AssertGenericErrorAsync(response, HostileName);
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        Assert.Contains("""\u003c/script\u003e\u003cb\u003ex""", body, StringComparison.Ordinal);
        Assert.DoesNotContain(HostileName, body, StringComparison.Ordinal);
        Assert.DoesNotContain("<b>", body, StringComparison.Ordinal);
        Assert.Equal(HostileName, data.GetProperty("tenant").GetString());
        AssertPage(body);
    }

    [Fact]
    public async Task Theme_is_served_at_its_hash_with_the_headers_and_any_other_hash_is_a_404()
    {
        var (port, _) = await StartAsync();
        using var page = await SendAsync(port, AuthorizeUrl("nope", Callback));
        var href = ThemeHref().Match(StepPage.Head(await page.Content.ReadAsStringAsync(Cancellation))).Groups["href"].Value;
        Assert.NotEmpty(href);

        using var theme = await SendAsync(port, href);
        Assert.Equal(HttpStatusCode.OK, theme.StatusCode);
        Assert.Equal("text/css", theme.Content.Headers.ContentType?.MediaType);
        AssertHeaders(theme);
        var css = await theme.Content.ReadAsStringAsync(Cancellation);
        AssertThemeRules(css);
        Assert.DoesNotContain("data:", css, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("url(", css, StringComparison.OrdinalIgnoreCase);

        foreach (var wrong in new[] { "/login/theme/0123456789abcdef.css", href.Replace(".css", "0.css", StringComparison.Ordinal), TenantTheme.PathPrefix + href[TenantTheme.PathPrefix.Length..].ToUpperInvariant(), href.ToUpperInvariant() })
        {
            using var missing = await SendAsync(port, wrong);
            Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
            AssertHeaders(missing);
        }
    }

    [Fact]
    public async Task Every_asset_the_page_loads_is_served_with_the_headers_and_an_unknown_one_is_a_404()
    {
        var (port, _) = await StartAsync();
        using var page = await SendAsync(port, AuthorizeUrl("nope", Callback));
        var body = await page.Content.ReadAsStringAsync(Cancellation);
        var assets = Reference().Matches(body).Select(m => m.Groups["path"].Value).Where(p => p.StartsWith("/login/assets/", StringComparison.Ordinal)).Distinct().ToList();

        Assert.Contains(assets, a => a.EndsWith(".js", StringComparison.Ordinal));
        Assert.Contains(assets, a => a.EndsWith(".css", StringComparison.Ordinal));
        var fonts = new List<string>();
        foreach (var asset in assets)
        {
            using var response = await SendAsync(port, asset);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            AssertHeaders(response);
            if (asset.EndsWith(".css", StringComparison.Ordinal))
            {
                var css = await response.Content.ReadAsStringAsync(Cancellation);
                Assert.DoesNotContain("data:", css, StringComparison.OrdinalIgnoreCase);
                fonts.AddRange(CssUrl().Matches(css).Select(m => m.Groups["path"].Value));
            }
        }

        Assert.NotEmpty(fonts);
        foreach (var font in fonts.Distinct())
        {
            Assert.StartsWith("/login/assets/", font);
            using var response = await SendAsync(port, font);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("font/woff2", response.Content.Headers.ContentType?.MediaType);
            AssertHeaders(response);
        }

        foreach (var path in new[] { "/login/assets/missing.js", "/login/index.html", "/index.html" })
        {
            using var missing = await SendAsync(port, path);
            Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
            Assert.DoesNotContain("gk-step", await missing.Content.ReadAsStringAsync(Cancellation), StringComparison.Ordinal);
            if (path.StartsWith("/login/", StringComparison.Ordinal))
            {
                AssertHeaders(missing);
            }
        }
    }

    /// <summary>
    /// Story 4.2 on the real host: a valid authorization request goes to Login with a host-only transaction cookie,
    /// committed, and <c>/login</c> with that cookie is the Login step's page, with the AD-21 headers; without it,
    /// the page is Generic error <c>invalid_transaction</c>. Program.cs maps the sign-in surface, as ProtocolHost does.
    /// </summary>
    [Fact]
    public async Task A_valid_request_goes_to_Login_whose_page_is_the_Login_step()
    {
        var (port, clientId) = await StartAsync();

        using var authorize = await SendAsync(port, AuthorizeUrl(clientId, Callback));
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        Assert.Equal("/login", authorize.Headers.Location?.OriginalString);
        var cookie = Assert.Single(authorize.Headers.GetValues("Set-Cookie"));
        Assert.Matches("^__Host-gk_txn=[A-Za-z0-9_-]{43}; Path=/; Secure; HttpOnly; SameSite=Lax$", cookie);

        using var page = await SendAsync(port, "/login", cookie: cookie.Split(';')[0]);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.True(page.Headers.CacheControl?.NoStore, "The Login page isn't no-store.");
        AssertHeaders(page);
        var body = await page.Content.ReadAsStringAsync(Cancellation);
        AssertPage(body);
        using (var step = StepPage.Read(body))
        {
            Assert.Equal("login", step.RootElement.GetProperty("step").GetString());
            Assert.Equal(ProtocolDatabase.TestTenantName, step.RootElement.GetProperty("data").GetProperty("tenant").GetString());
            Assert.Matches("^[A-Za-z0-9_-]{43}$", step.RootElement.GetProperty("csrfToken").GetString());
        }

        using var refused = await SendAsync(port, "/login/");
        await StepPage.AssertGenericErrorAsync(refused, ProtocolDatabase.TestTenantName, "invalid_transaction");
    }

    public void Dispose()
    {
        foreach (var process in _processes)
        {
            process.Dispose();
        }

        foreach (var socket in _sockets)
        {
            socket.Dispose();
        }
    }

    /// <summary>The step page's shape (AD-21): its html tag, one data block, the theme link in head, nothing the policy blocks.</summary>
    private static void AssertPage(string body)
    {
        Assert.Contains(StepPageTemplate.HtmlTag, body, StringComparison.Ordinal);
        Assert.DoesNotContain(StepPageTemplate.HeadMarker, body, StringComparison.Ordinal);
        Assert.DoesNotContain(StepPageTemplate.StepMarker, body, StringComparison.Ordinal);
        Assert.Matches(StepPage.ThemeLink(), StepPage.Head(body));
        AssertNothingBlocked(body);
    }

    /// <summary>No script but the JSON data block and module scripts by src, no style, no data: URL, nothing from another origin.</summary>
    private static void AssertNothingBlocked(string html)
    {
        foreach (Match script in ScriptTag().Matches(html))
        {
            var tag = script.Value;
            Assert.True(
                tag.Contains(" src=", StringComparison.Ordinal) || tag.Contains("type=\"application/json\"", StringComparison.Ordinal),
                $"Inline script: {tag}");
        }

        Assert.DoesNotContain("<style", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotMatch(@"(?i)\sstyle\s*=", html);
        Assert.DoesNotContain("data:", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotMatch(@"(?i)\s(?:src|href)\s*=\s*[""']?(?:[a-z][a-z0-9+.-]*:|//)", html);
    }

    /// <summary>
    /// The theme's three rules carry the generated tokens (Tenancy's <c>DesignTokens</c>, read by reflection,
    /// as it is internal): the light rule every <c>Light</c> value, and both the forced-dark rule and the
    /// <c>auto</c> rule under <c>prefers-color-scheme: dark</c> every <c>Dark</c> value, each on its own property.
    /// </summary>
    private static void AssertThemeRules(string css)
    {
        const string media = "@media (prefers-color-scheme: dark) {";
        var at = css.IndexOf(media, StringComparison.Ordinal);
        Assert.True(at > 0, "No prefers-color-scheme: dark block.");
        var outside = Rules(css[..at]);
        var inside = Rules(css[(at + media.Length)..]);

        var light = Assert.Single(outside, r => r.Selectors.Contains("[data-gk-theme][data-gk-theme]")).Body;
        var forced = Assert.Single(outside, r => r.Selectors.Contains("[data-gk-theme][data-gk-scheme=\"dark\"]")).Body;
        var auto = Assert.Single(inside, r => r.Selectors.Contains("[data-gk-theme][data-gk-scheme=\"auto\"]")).Body;
        Assert.Contains("[data-gk-theme] [data-gk-scheme=\"dark\"]", outside.Single(r => r.Body == forced).Selectors);
        Assert.Contains("[data-gk-theme] [data-gk-scheme=\"auto\"]", inside.Single(r => r.Body == auto).Selectors);

        AssertScheme(light, "Light", "light");
        AssertScheme(forced, "Dark", "dark");
        AssertScheme(auto, "Dark", "dark");
    }

    private static void AssertScheme(string body, string scheme, string colorScheme)
    {
        var tokens = typeof(Gatekeep.Modules.Tenancy.Contracts.TenancyContract).Assembly
            .GetType($"Gatekeep.Modules.Tenancy.Core.Theme.DesignTokens+{scheme}", throwOnError: true)!
            .GetFields(System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Where(f => f.IsLiteral && f.FieldType == typeof(string))
            .ToList();

        Assert.NotEmpty(tokens);
        Assert.Contains($"color-scheme: {colorScheme};", body, StringComparison.Ordinal);
        foreach (var token in tokens)
        {
            var property = token.Name == "Sh" ? "elevation-sh" : "color-" + KebabCase().Replace(token.Name, "-$1").ToLowerInvariant();
            Assert.Contains($"--gk-{property}: {token.GetRawConstantValue()};", body, StringComparison.Ordinal);
        }
    }

    private static List<(string Selectors, string Body)> Rules(string css) =>
        [.. CssRule().Matches(css).Select(m => (m.Groups["selectors"].Value, m.Groups["body"].Value))];

    private static void AssertHeaders(HttpResponseMessage response)
    {
        Assert.Equal([SecurityHeaders.ContentSecurityPolicy], response.Headers.GetValues("Content-Security-Policy"));
        Assert.Equal(["no-referrer"], response.Headers.GetValues("Referrer-Policy"));
        Assert.Equal(["DENY"], response.Headers.GetValues("X-Frame-Options"));
        Assert.Equal(["nosniff"], response.Headers.GetValues("X-Content-Type-Options"));
    }

    private static string AuthorizeUrl(string clientId, string redirectUri) =>
        "/connect/authorize?response_type=code&scope=openid&state=echo-me-not"
        + $"&client_id={Uri.EscapeDataString(clientId)}&redirect_uri={Uri.EscapeDataString(redirectUri)}"
        + $"&code_challenge={Pkce.New().Challenge}&code_challenge_method=S256";

    private static async Task<HttpResponseMessage> SendAsync(int port, string path, string? trace = null, string? cookie = null)
    {
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false });
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{port}{path}"));
        request.Headers.Host = Host;
        if (cookie is not null)
        {
            request.Headers.Add("Cookie", cookie);
        }

        if (trace is not null)
        {
            request.Headers.Add("traceparent", $"00-{trace}-{trace[..16]}-01");
        }

        var response = await http.SendAsync(request, Cancellation);
        await response.Content.LoadIntoBufferAsync(Cancellation);
        return response;
    }

    private static string IndexPath()
    {
        var index = Path.Combine(Bundle, StepPageTemplate.IndexFile);
        Assert.True(File.Exists(index), $"{index} is missing: build the apps first (pnpm -r build).");
        return index;
    }

    /// <summary>
    /// Starts Host.Hosted on the built bundle, with one Tenant on <see cref="Host"/>, named
    /// <paramref name="name"/>, its keys provisioned, a web client registered for <see cref="Callback"/> and its database
    /// Connection enabled for it, and waits until it's healthy. Returns its public port and the client's ID.
    /// </summary>
    private async Task<(int Port, string ClientId)> StartAsync(string name = ProtocolDatabase.TestTenantName)
    {
        IndexPath();
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var tenant = await database.AddTenantAsync(Host);
        if (name != ProtocolDatabase.TestTenantName)
        {
            await database.ExecuteAsync(
                $"SET session_replication_role = replica; UPDATE tenant SET name = '{name.Replace("'", "''", StringComparison.Ordinal)}' WHERE id = '{tenant.TenantId}'; SET session_replication_role = DEFAULT");
        }

        Assert.True(await database.ProvisionAsync(bao, tenant.TenantId));
        var client = await database.CreateWebClientAsync(tenant.TenantId, [Callback]);

        // Story 4.12: on the release build, Login is shown only while a Connection is enabled for the Application.
        await database.ExecuteAsync(TestTenants.DatabaseConnectionSql(tenant.TenantId));

        var socket = new OpenBaoSocketProxy(bao.Address);
        _sockets.Add(socket);
        var custody = bao.Options(OpenBaoFixture.Hosted);
        var health = HostProcess.FreePort();
        var port = HostProcess.FreePort();
        var process = HostProcess.Start(
            "Hosted",
            $"--ConnectionStrings:Hosted={database.Hosted}",
            $"--Custody:SocketPath={socket.Path}",
            $"--Custody:RoleIdFile={custody.RoleIdFile}",
            $"--Custody:SecretIdFile={custody.SecretIdFile}",
            $"--Gatekeep:HealthPort={health}",
            $"--Gatekeep:PublicPort={port}",
            $"--webroot={Bundle}");
        _processes.Add(process);

        var (status, body) = await process.GetAsync(health, "/healthz", Timeout, Cancellation);
        Assert.True(status == HttpStatusCode.OK, $"Host.Hosted isn't healthy: {body}\n{process.Output}");
        return (port, client.ClientId);
    }

    [GeneratedRegex("(?<!^)([A-Z])")]
    private static partial Regex KebabCase();

    [GeneratedRegex(@"(?<selectors>[^{}]+)\{(?<body>[^{}]*)\}")]
    private static partial Regex CssRule();

    [GeneratedRegex("""<script\b[^>]*>""", RegexOptions.IgnoreCase)]
    private static partial Regex ScriptTag();

    [GeneratedRegex(@"(?:src|href)=""(?<path>/[^""]+)""")]
    private static partial Regex Reference();

    [GeneratedRegex("""url\((?<q>['"]?)(?<path>[^)'"]+)\k<q>\)""")]
    private static partial Regex CssUrl();

    [GeneratedRegex("""<link rel="stylesheet" href="(?<href>/login/theme/[0-9a-f]{16}\.css)">""")]
    private static partial Regex ThemeHref();
}
