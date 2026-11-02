using System.Net;
using System.Text.RegularExpressions;
using Gatekeep.Adapters.Hosting;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Tests.Isolation.Stack;
using Xunit;

namespace Gatekeep.Tests.Isolation.Hosting;

/// <summary>
/// Story 1.20: a real <c>Host.Admin</c> serving the built Admin Dashboard bundle
/// (<c>apps/admin-dashboard/dist</c>, from <c>pnpm -r build</c>) sends the AD-21 headers on
/// every public-port response, serves <c>index.html</c> for deep links and never for an API path.
/// </summary>
public sealed partial class AdminBundleTests(PostgresFixture postgres) : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    private static readonly string Bundle = Path.Combine(Repository.Root, "apps", "admin-dashboard", "dist");

    private readonly string _directory = Directory.CreateTempSubdirectory("gatekeep-admin-bundle-").FullName;
    private readonly List<FakeOpenBaoSocket> _sockets = [];
    private readonly List<HostProcess> _processes = [];

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public void Defined_policy_is_exactly_AD_21()
    {
        Assert.Equal(
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
            SecurityHeaders.ContentSecurityPolicy);
        Assert.Equal("no-referrer", SecurityHeaders.ReferrerPolicy);
    }

    [Fact]
    public void Built_index_has_nothing_the_policy_would_block()
    {
        var index = File.ReadAllText(IndexPath());

        Assert.DoesNotMatch(InlineScript(), index);
        Assert.DoesNotContain("<style", index, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotMatch(@"(?i)\sstyle\s*=", index);
        Assert.DoesNotContain("data:", index, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotMatch(@"(?i)\s(?:src|href)\s*=\s*[""']?(?:https?:)?//", index);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/tenants/x")]
    [InlineData("/deployment/admins/a/b")]
    public async Task Bundle_root_and_deep_links_serve_index_with_the_headers(string path)
    {
        var port = await StartAsync();
        using var http = new HttpClient();

        using var response = await http.GetAsync(Url(port, path), Cancellation);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(await File.ReadAllTextAsync(IndexPath(), Cancellation), await response.Content.ReadAsStringAsync(Cancellation));
        AssertHeaders(response);
    }

    [Theory]
    [InlineData("/api/v1/nope")]
    [InlineData("/api/v1/tenants/x")]
    [InlineData("/api")]
    [InlineData("/api/")]
    [InlineData("/api/v1/nope.js")]
    [InlineData("/assets/missing.js")]
    [InlineData("/missing.css")]
    public async Task Unknown_API_path_or_file_is_a_404_with_the_headers_and_never_the_bundle(string path)
    {
        var port = await StartAsync();
        using var http = new HttpClient();

        using var response = await http.GetAsync(Url(port, path), Cancellation);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain("<div id=\"root\">", await response.Content.ReadAsStringAsync(Cancellation));
        AssertHeaders(response);
    }

    [Fact]
    public async Task Every_asset_index_references_is_served_with_the_headers()
    {
        var port = await StartAsync();
        using var http = new HttpClient();
        var index = await File.ReadAllTextAsync(IndexPath(), Cancellation);
        var assets = Reference().Matches(index).Select(m => m.Groups["path"].Value).Distinct().ToList();

        // At least the script and the stylesheet, which in turn reaches the fonts.
        Assert.Contains(assets, a => a.EndsWith(".js", StringComparison.Ordinal));
        Assert.Contains(assets, a => a.EndsWith(".css", StringComparison.Ordinal));

        var fonts = new List<string>();
        foreach (var asset in assets)
        {
            using var response = await http.GetAsync(Url(port, asset), Cancellation);

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
            Assert.StartsWith("/", font);
            using var response = await http.GetAsync(Url(port, font), Cancellation);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("font/woff2", response.Content.Headers.ContentType?.MediaType);
            AssertHeaders(response);
        }
    }

    [Fact]
    public async Task Health_port_still_answers_only_health()
    {
        var health = HostProcess.FreePort();
        var port = await StartAsync(health);
        using var http = new HttpClient();

        using var bundle = await http.GetAsync(Url(health, "/"), Cancellation);
        using var publicHealth = await http.GetAsync(Url(port, "/healthz"), Cancellation);

        Assert.Equal(HttpStatusCode.NotFound, bundle.StatusCode);
        // On the public port, /healthz is just a deep link into the bundle.
        Assert.Equal(HttpStatusCode.OK, publicHealth.StatusCode);
        Assert.Contains("<div id=\"root\">", await publicHealth.Content.ReadAsStringAsync(Cancellation));
        AssertHeaders(publicHealth);
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

        Directory.Delete(_directory, recursive: true);
    }

    private static void AssertHeaders(HttpResponseMessage response)
    {
        Assert.Equal([SecurityHeaders.ContentSecurityPolicy], response.Headers.GetValues("Content-Security-Policy"));
        Assert.Equal(["no-referrer"], response.Headers.GetValues("Referrer-Policy"));
        Assert.Equal(["DENY"], response.Headers.GetValues("X-Frame-Options"));
        Assert.Equal(["nosniff"], response.Headers.GetValues("X-Content-Type-Options"));
    }

    private static string IndexPath()
    {
        var index = Path.Combine(Bundle, "index.html");
        Assert.True(File.Exists(index), $"{index} is missing: build the apps first (pnpm -r build).");
        return index;
    }

    private static Uri Url(int port, string path) => new($"http://127.0.0.1:{port}{path}");

    /// <summary>Starts Host.Admin on the built bundle and waits until it's healthy. Returns its public port.</summary>
    private async Task<int> StartAsync(int? healthPort = null)
    {
        IndexPath();
        var database = await postgres.NewMigratedDatabaseAsync();
        var health = healthPort ?? HostProcess.FreePort();
        var port = HostProcess.FreePort();
        var socket = new FakeOpenBaoSocket();
        _sockets.Add(socket);

        var process = HostProcess.Start(
            "Admin",
            $"--ConnectionStrings:Admin={postgres.RoleConnection(TableRegistry.Admin, database)}",
            $"--Custody:SocketPath={socket.Path}",
            $"--Custody:RoleIdFile={SecretFile("role-id")}",
            $"--Custody:SecretIdFile={SecretFile("secret-id")}",
            $"--Gatekeep:HealthPort={health}",
            $"--Gatekeep:PublicPort={port}",
            $"--webroot={Bundle}");
        _processes.Add(process);

        var (status, body) = await process.GetAsync(health, "/healthz", Timeout, Cancellation);
        Assert.True(status == HttpStatusCode.OK, $"Host.Admin isn't healthy: {body}");
        return port;
    }

    private string SecretFile(string name)
    {
        var path = Path.Combine(_directory, $"{name}-{Guid.NewGuid():N}");
        File.WriteAllText(path, Guid.NewGuid().ToString());
        return path;
    }

    /// <summary>A script element with no src attribute: inline script.</summary>
    [GeneratedRegex(@"(?i)<script(?![^>]*\ssrc\s*=)[^>]*>")]
    private static partial Regex InlineScript();

    [GeneratedRegex(@"(?:src|href)=""(?<path>/[^""]+)""")]
    private static partial Regex Reference();

    [GeneratedRegex(@"url\((?<q>['""]?)(?<path>[^)'""]+)\k<q>\)")]
    private static partial Regex CssUrl();
}
