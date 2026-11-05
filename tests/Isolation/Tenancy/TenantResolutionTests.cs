using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Modules.Tenancy.Contracts;
using Gatekeep.Tests.Isolation.Admins;
using Gatekeep.Tests.Isolation.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Gatekeep.Tests.Isolation.Tenancy;

/// <summary>
/// Story 1.27 (AD-4, AD-6): Host.Hosted resolves its Tenant from the whole request host, lower-cased
/// and without its port, by exact match on an active Tenant's stored host, before anything else
/// runs. An unknown host, a Tenant still being created and a trailing dot get the one fixed 404, no
/// forwarded header or absolute-form target selects a Tenant, and a lookup failure is one fixed
/// 503. The real Host.Hosted proves the 404 is the same for every host; a probe server mounting the
/// real middleware and a test-only endpoint proves when Tenant code runs, and what it is given.
/// </summary>
public sealed class TenantResolutionTests(PostgresFixture postgres) : IDisposable
{
    private const string Active = "acme-dev.gatekeep.test";
    private const string Creating = "beta.gatekeep.test";

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Story 1.21's fixed 404, as <see cref="AdminHost.SnapshotAsync"/> prints it: the status, the one
    /// header Kestrel sends for it, and no body. Every unknown, creating or route-less host gets exactly this.
    /// </summary>
    private const string FixedNotFound = "404\ncontent-length: 0\n";

    private static readonly Guid ActiveTenant = Guid.Parse("01900000-0000-7000-8000-0000000127a1");
    private static readonly Guid CreatingTenant = Guid.Parse("01900000-0000-7000-8000-0000000127b2");

    private readonly string _directory = Directory.CreateTempSubdirectory("gatekeep-tenant-resolution-").FullName;

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Real_Host_Hosted_answers_unknown_creating_and_routeless_active_hosts_alike()
    {
        var database = await SeededAsync();

        using var socket = new FakeOpenBaoSocket();
        var health = HostProcess.FreePort();
        var port = HostProcess.FreePort();
        using var process = HostProcess.Start(
            "Hosted",
            $"--ConnectionStrings:Hosted={postgres.RoleConnection(TableRegistry.Hosted, database)}",
            $"--Custody:SocketPath={socket.Path}",
            $"--Custody:RoleIdFile={SecretFile("role-id")}",
            $"--Custody:SecretIdFile={SecretFile("secret-id")}",
            $"--Gatekeep:HealthPort={health}",
            $"--Gatekeep:PublicPort={port}");
        Assert.Equal(HttpStatusCode.OK, (await process.GetAsync(health, "/healthz", Timeout, Cancellation)).Status);

        using var http = Client();
        var snapshots = new List<string>();
        foreach (var (host, method, path) in new[]
        {
            ("nobody.gatekeep.test", HttpMethod.Get, "/"),
            ("nobody.gatekeep.test", HttpMethod.Post, "/connect/token"),
            (Creating, HttpMethod.Get, "/.well-known/openid-configuration"),
            (Creating, HttpMethod.Delete, "/x"),
            (Active, HttpMethod.Get, "/"),
            (Active, HttpMethod.Put, "/random/path?with=query"),
            ("ACME-DEV.gatekeep.test:8443", HttpMethod.Get, "/"),
            (Active + ".", HttpMethod.Get, "/"),
        })
        {
            using var response = await SendAsync(http, port, host, method, path);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            snapshots.Add(await AdminHost.SnapshotAsync(response));
        }

        Assert.Equal(FixedNotFound, Assert.Single(snapshots.Distinct()));

        // Story 2.3: the active Tenant's own discovery and JWKS, its issuer the stored one. This
        // Tenant has no keys yet, so its JWKS is empty and no custody call is made.
        using (var discovery = await SendAsync(http, port, Active, HttpMethod.Get, "/.well-known/openid-configuration"))
        {
            Assert.Equal(HttpStatusCode.OK, discovery.StatusCode);
            using var document = JsonDocument.Parse(await discovery.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal($"https://{Active}/", document.RootElement.GetProperty("issuer").GetString());
            Assert.Equal($"https://{Active}/.well-known/jwks", document.RootElement.GetProperty("jwks_uri").GetString());
        }

        using (var jwks = await SendAsync(http, port, Active, HttpMethod.Get, "/.well-known/jwks"))
        {
            Assert.Equal(HttpStatusCode.OK, jwks.StatusCode);
            using var document = JsonDocument.Parse(await jwks.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal(0, document.RootElement.GetProperty("keys").GetArrayLength());
        }
    }

    [Fact]
    public async Task Active_host_runs_the_probe_with_the_stored_Tenant()
    {
        await using var probe = await ProbeServer.StartAsync(postgres.RoleConnection(TableRegistry.Hosted, await SeededAsync()));

        using var response = await SendAsync(probe.Http, probe.Port, Active, HttpMethod.Get, "/probe");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(ActiveTenant, body.RootElement.GetProperty("tenantId").GetGuid());
        Assert.Equal($"https://{Active}/", body.RootElement.GetProperty("issuer").GetString());
        Assert.Equal(Active, body.RootElement.GetProperty("rpId").GetString());
        Assert.Equal($"https://{Active}/", body.RootElement.GetProperty("emailLinkBase").GetString());
        Assert.Equal(1, probe.Calls);
    }

    [Theory]
    [InlineData("ACME-DEV.gatekeep.test")]
    [InlineData("ACME-DEV.gatekeep.test:8443")]
    [InlineData("acme-dev.gatekeep.test:1")]
    public async Task Host_is_matched_lower_cased_and_without_its_port(string host)
    {
        await using var probe = await ProbeServer.StartAsync(postgres.RoleConnection(TableRegistry.Hosted, await SeededAsync()));

        using var response = await SendAsync(probe.Http, probe.Port, host, HttpMethod.Get, "/probe");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, probe.Calls);
    }

    [Fact]
    public async Task Unknown_creating_and_near_miss_hosts_get_the_fixed_404_before_any_Tenant_code()
    {
        await using var probe = await ProbeServer.StartAsync(postgres.RoleConnection(TableRegistry.Hosted, await SeededAsync()));

        var snapshots = new List<string>();
        foreach (var (host, method) in new[]
        {
            ("nobody.gatekeep.test", HttpMethod.Get),
            ("nobody.gatekeep.test", HttpMethod.Post),
            (Creating, HttpMethod.Get),
            (Active + ".", HttpMethod.Get),
            ("dev.gatekeep.test", HttpMethod.Get),
            ("x." + Active, HttpMethod.Get),
            ("gatekeep.test", HttpMethod.Get),
            ("127.0.0.1", HttpMethod.Get),
        })
        {
            using var response = await SendAsync(probe.Http, probe.Port, host, method, "/probe");
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            snapshots.Add(await AdminHost.SnapshotAsync(response));
        }

        // A resolved host with no endpoint answers exactly the same.
        using (var routeless = await SendAsync(probe.Http, probe.Port, Active, HttpMethod.Get, "/nothing/here"))
        {
            Assert.Equal(HttpStatusCode.NotFound, routeless.StatusCode);
            snapshots.Add(await AdminHost.SnapshotAsync(routeless));
        }

        Assert.Equal(FixedNotFound, Assert.Single(snapshots.Distinct()));
        Assert.Equal(0, probe.Calls);
    }

    [Theory]
    [InlineData("X-Forwarded-Host", Active)]
    [InlineData("Forwarded", "host=" + Active)]
    [InlineData("Forwarded", "for=192.0.2.1;host=" + Active + ";proto=https")]
    [InlineData("X-Original-Host", Active)]
    public async Task Forwarded_host_headers_select_nothing(string header, string value)
    {
        await using var probe = await ProbeServer.StartAsync(postgres.RoleConnection(TableRegistry.Hosted, await SeededAsync()));

        using var response = await SendAsync(probe.Http, probe.Port, "evil.example", HttpMethod.Get, "/probe", (header, value));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(0, probe.Calls);
    }

    [Fact]
    public async Task Absolute_form_target_selects_nothing()
    {
        await using var probe = await ProbeServer.StartAsync(postgres.RoleConnection(TableRegistry.Hosted, await SeededAsync()));

        var status = await RawStatusAsync(probe.Port, $"GET http://{Active}/probe HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n");

        // Kestrel refuses an absolute-form target that disagrees with Host before any middleware, so
        // no Tenant is resolved from it.
        Assert.Equal(400, status);
        Assert.Equal(0, probe.Calls);
    }

    [Fact]
    public async Task Lookup_failure_is_one_fixed_bodiless_503_for_every_host()
    {
        // Port 9 (discard) on loopback: nothing answers.
        await using var probe = await ProbeServer.StartAsync(
            "Host=127.0.0.1;Port=9;Database=gatekeep;Username=gk_hosted;Password=unreachable-isolation-only;Timeout=2;Pooling=false");

        var snapshots = new List<string>();
        foreach (var host in new[] { Active, "nobody.gatekeep.test", "127.0.0.1" })
        {
            using var response = await SendAsync(probe.Http, probe.Port, host, HttpMethod.Get, "/probe");
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
            snapshots.Add(await AdminHost.SnapshotAsync(response));
        }

        Assert.Single(snapshots.Distinct());
        Assert.Equal(0, probe.Calls);
    }

    [Fact]
    public async Task Tenant_resolves_once_its_creation_activates_it()
    {
        var database = await SeededAsync();
        await using var probe = await ProbeServer.StartAsync(postgres.RoleConnection(TableRegistry.Hosted, database));

        using (var before = await SendAsync(probe.Http, probe.Port, Creating, HttpMethod.Get, "/probe"))
        {
            Assert.Equal(HttpStatusCode.NotFound, before.StatusCode);
        }

        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"INSERT INTO tenant_settings (tenant_id) VALUES ('{CreatingTenant}'); UPDATE tenant SET status = 'active' WHERE id = '{CreatingTenant}'");

        // No cache: the next request sees it.
        using var after = await SendAsync(probe.Http, probe.Port, Creating, HttpMethod.Get, "/probe");
        Assert.Equal(HttpStatusCode.OK, after.StatusCode);
        Assert.Equal(1, probe.Calls);
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private async Task<string> SeededAsync()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var superuser = postgres.SuperuserConnection(database);
        await PostgresFixture.ExecuteAsync(
            superuser,
            $"""
            SET session_replication_role = replica;
            INSERT INTO tenant (id, name, label, status, issuer, rp_id, email_link_base) VALUES
              ('{ActiveTenant}', 'Acme Dev', 'dev', 'active', 'https://{Active}/', '{Active}', 'https://{Active}/'),
              ('{CreatingTenant}', 'Beta', 'prod', 'creating', 'https://{Creating}/', '{Creating}', 'https://{Creating}/');
            INSERT INTO tenant_host (host, tenant_id, kind) VALUES ('{Active}', '{ActiveTenant}', 'subdomain'), ('{Creating}', '{CreatingTenant}', 'subdomain');
            SET session_replication_role = DEFAULT;
            """);
        return database;
    }

    private static HttpClient Client() => new(new SocketsHttpHandler { UseCookies = false, AllowAutoRedirect = false, UseProxy = false });

    private static async Task<HttpResponseMessage> SendAsync(
        HttpClient http,
        int port,
        string host,
        HttpMethod method,
        string path,
        params (string Name, string Value)[] headers)
    {
        using var request = new HttpRequestMessage(method, new Uri($"http://127.0.0.1:{port}{path}"));
        request.Headers.TryAddWithoutValidation("Host", host);
        foreach (var (name, value) in headers)
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }

        if (method == HttpMethod.Post || method == HttpMethod.Put)
        {
            request.Content = new StringContent("{}");
        }

        var response = await http.SendAsync(request, Cancellation);
        await response.Content.LoadIntoBufferAsync(Cancellation);
        return response;
    }

    /// <summary>The status line's code for a request written byte for byte.</summary>
    private static async Task<int> RawStatusAsync(int port, string request)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, Cancellation);
        await using var stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request), Cancellation);

        var buffer = new byte[256];
        var read = await stream.ReadAsync(buffer, Cancellation);
        var line = Encoding.ASCII.GetString(buffer, 0, read).Split("\r\n")[0];
        return int.Parse(line.Split(' ')[1], System.Globalization.CultureInfo.InvariantCulture);
    }

    private string SecretFile(string name)
    {
        var path = Path.Combine(_directory, $"{name}-{Guid.NewGuid():N}");
        File.WriteAllText(path, Guid.NewGuid().ToString());
        return path;
    }

    /// <summary>
    /// The real resolution middleware, first, then routing, a test-only probe endpoint that counts
    /// its calls and echoes the <see cref="ResolvedTenant"/> it was given, and Host.Hosted's fallback.
    /// </summary>
    private sealed class ProbeServer : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private int _calls;

        private ProbeServer(WebApplication app) => _app = app;

        public int Calls => Volatile.Read(ref _calls);

        public int Port { get; private set; }

        public HttpClient Http { get; } = Client();

        public static async Task<ProbeServer> StartAsync(string connectionString)
        {
            var builder = WebApplication.CreateSlimBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(kestrel =>
            {
                kestrel.AddServerHeader = false;
                kestrel.Listen(IPAddress.Loopback, 0);
            });

            var app = builder.Build();
            var probe = new ProbeServer(app);

            app.UseTenantResolution(() => connectionString);
            app.UseRouting();
            app.MapGet("/probe", (HttpContext context) =>
            {
                Interlocked.Increment(ref probe._calls);
                return Results.Json(context.Features.Get<ResolvedTenant>());
            });
            app.MapFallback(TenancyContract.NotFoundAsync);

            await app.StartAsync(Cancellation);
            var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
            probe.Port = new Uri(address).Port;
            return probe;
        }

        public async ValueTask DisposeAsync()
        {
            Http.Dispose();
            await _app.StopAsync(CancellationToken.None);
            await _app.DisposeAsync();
        }
    }
}
