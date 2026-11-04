using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Gatekeep.Adapters.Hosting;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Modules.Admins.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Story 1.24: <c>Host.Admin</c>'s own request checks and <c>AccessDeclaration.Of</c>, read from
/// its build output, on test-only endpoints in an in-process host over a migrated database. Every
/// shape of bad declaration is undeclared, and at runtime the unknown-path 404 with nothing
/// audited, a Deployment route that takes <c>{tenantId}</c> included. A test-only Deployment
/// capability route, the first Owner-only route over HTTP, refuses a non-Owner with 403
/// <c>access_denied</c> and an event with no target, and lets the Deployment Owner through.
/// No test-only route is ever mapped in the production host.
/// </summary>
public sealed class RequestChecksTests(PostgresFixture postgres)
{
    private const string Namespace = "Gatekeep.Host.Admin.";

    private static readonly Assembly Host = Assembly.LoadFrom(BuildOutput.AssemblyPath("Gatekeep.Host.Admin", "Gatekeep.Host.Admin"));

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public static TheoryData<string, bool> Declarations => new()
    {
        { "deployment self", true },
        { "deployment sessionless", true },
        { "deployment capability", true },
        { "tenant capability", true },
        { "no marker", false },
        { "two markers", false },
        { "no declaration", false },
        { "two declarations", false },
        { "capability and setup-allowed", false },
        { "tenant marker and self-service", false },
        { "deployment capability on a tenant route", false },
        { "tenant capability on a deployment route", false },
        { "tenantId on a deployment self-service route", false },
        { "tenantId on a deployment capability route", false },
        { "tenant marker without tenantId", false },
    };

    [Theory]
    [MemberData(nameof(Declarations))]
    public void Access_declaration_accepts_only_one_marker_and_one_valid_declaration(string shape, bool valid)
    {
        var (metadata, pattern) = Shape(shape);
        var of = Host.GetType(Namespace + "AccessDeclaration", throwOnError: true)!
            .GetMethod("Of", BindingFlags.Public | BindingFlags.Static)!;

        Assert.Equal(valid, of.Invoke(null, [metadata, pattern]) is not null);
    }

    [Fact]
    public async Task Undeclared_endpoints_are_the_unknown_path_404_and_nothing_is_audited()
    {
        await using var app = await StartAsync(await postgres.NewMigratedDatabaseAsync());
        var owner = await app.SessionAsync(owner: true);

        foreach (var path in new[]
        {
            "/api/v1/deployment/test/undeclared",
            "/api/v1/deployment/test/two-declarations",
            "/api/v1/deployment/test/capability-and-setup",
            $"/api/v1/deployment/{PublicIdFor()}/test",
            "/api/v1/tenants/x/test/self",
        })
        {
            using var response = await app.GetAsync(path, owner);
            Assert.True(response.StatusCode == HttpStatusCode.NotFound, $"{path} answered {(int)response.StatusCode}.");
            Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
        }

        Assert.Equal(0L, await app.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event"));
    }

    [Fact]
    public async Task Deployment_capability_route_refuses_a_non_Owner_and_lets_the_Owner_through()
    {
        await using var app = await StartAsync(await postgres.NewMigratedDatabaseAsync());
        var admin = await app.SessionAsync(owner: false);
        var owner = await app.SessionAsync(owner: true);

        using (var refused = await app.GetAsync("/api/v1/deployment/test/owner-only", admin))
        {
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
            Assert.Equal("application/problem+json", refused.Content.Headers.ContentType?.MediaType);
            using var json = JsonDocument.Parse(await refused.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal("access_denied", json.RootElement.GetProperty("code").GetString());
        }

        Assert.Equal(
            $"1 admin {app.AdminOf(admin)} t",
            await app.ScalarAsync<string>(
                """
                SELECT count(*) || ' ' || min(actor_kind) || ' ' || min(actor_id::text) || ' '
                       || bool_and(target_kind IS NULL AND target_id IS NULL)::text::char
                FROM deployment_audit_event WHERE type_code = 'admin.access.denied'
                """));

        using var allowed = await app.GetAsync("/api/v1/deployment/test/owner-only", owner);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        Assert.Equal("owner-only", await allowed.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(1L, await app.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.access.denied'"));
    }

    private static string PublicIdFor() =>
        Gatekeep.Kernel.Identifiers.PublicId.Format(Gatekeep.Kernel.Identifiers.PublicIdType.Tenant, Guid.CreateVersion7());

    private static object Instance(string type) =>
        Host.GetType(Namespace + type, throwOnError: true)!.GetField("Instance")!.GetValue(null)!;

    private static object Requires(Capability capability) =>
        Activator.CreateInstance(Host.GetType(Namespace + "RequiresCapability", throwOnError: true)!, capability)!;

    /// <summary>The metadata and route pattern of each named declaration shape.</summary>
    private static (object[] Metadata, string Pattern) Shape(string shape)
    {
        const string Deployment = "/api/v1/deployment/x";
        const string Tenant = "/api/v1/tenants/{tenantId}/x";
        var deploymentMarker = Instance("DeploymentApiEndpoint");
        var tenantMarker = Instance("TenantApiEndpoint");
        var self = Instance("SelfService");
        var tenantCapability = Requires(AdminCapabilities.TenantConfigurationRead);
        var deploymentCapability = Requires(AdminCapabilities.DeploymentTenantsRead);

        return shape switch
        {
            "deployment self" => (new object[] { deploymentMarker, self }, Deployment),
            "deployment sessionless" => (new object[] { deploymentMarker, Instance("SignInEndpoint") }, Deployment),
            "deployment capability" => (new object[] { deploymentMarker, deploymentCapability }, Deployment),
            "tenant capability" => (new object[] { tenantMarker, tenantCapability }, Tenant),
            "no marker" => (new object[] { self }, Deployment),
            "two markers" => (new object[] { deploymentMarker, tenantMarker, tenantCapability }, Tenant),
            "no declaration" => (new object[] { deploymentMarker }, Deployment),
            "two declarations" => (new object[] { deploymentMarker, self, deploymentCapability }, Deployment),
            "capability and setup-allowed" => (new object[] { deploymentMarker, deploymentCapability, Instance("SetupAllowed") }, Deployment),
            "tenant marker and self-service" => (new object[] { tenantMarker, self }, Tenant),
            "deployment capability on a tenant route" => (new object[] { tenantMarker, deploymentCapability }, Tenant),
            "tenant capability on a deployment route" => (new object[] { deploymentMarker, tenantCapability }, Deployment),
            "tenantId on a deployment self-service route" => (new object[] { deploymentMarker, self }, "/api/v1/deployment/{tenantId}/x"),
            "tenantId on a deployment capability route" => (new object[] { deploymentMarker, deploymentCapability }, "/api/v1/deployment/{TenantId:guid}/x"),
            "tenant marker without tenantId" => (new object[] { tenantMarker, tenantCapability }, "/api/v1/tenants/x"),
            _ => throw new ArgumentOutOfRangeException(nameof(shape)),
        };
    }

    /// <summary>The real request checks and services, test-only endpoints and the fallback, on a test server.</summary>
    private async Task<CheckedApp> StartAsync(string database)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var connection = postgres.RoleConnection(TableRegistry.Admin, database);
        var databases = new HostDatabases(new Dictionary<string, string> { ["Admin"] = connection });
        var origin = (HostOrigin)Activator.CreateInstance(typeof(HostOrigin), BindingFlags.NonPublic | BindingFlags.Instance, null, [Gatekeep.Tests.Isolation.Hosting.HostProcess.AdminOrigin], null)!;
        var servicesType = Host.GetType(Namespace + "AdminApiServices", throwOnError: true)!;
        builder.Services.AddSingleton(origin);
        builder.Services.AddSingleton(servicesType, Activator.CreateInstance(servicesType, databases, new ConfigurationBuilder().Build())!);

        var app = builder.Build();
        app.UseRouting();
        Host.GetType(Namespace + "AdminRequestChecks", throwOnError: true)!
            .GetMethod("UseAdminRequestChecks", BindingFlags.Public | BindingFlags.Static)!
            .Invoke(null, [app]);

        var deployment = Instance("DeploymentApiEndpoint");
        var tenant = Instance("TenantApiEndpoint");
        var self = Instance("SelfService");
        Map(app, "/api/v1/deployment/test/owner-only", deployment, Requires(AdminCapabilities.DeploymentTenantsRead));
        Map(app, "/api/v1/deployment/test/undeclared", deployment);
        Map(app, "/api/v1/deployment/test/two-declarations", deployment, self, Requires(AdminCapabilities.DeploymentTenantsRead));
        Map(app, "/api/v1/deployment/test/capability-and-setup", deployment, Requires(AdminCapabilities.DeploymentTenantsRead), Instance("SetupAllowed"));
        Map(app, "/api/v1/deployment/{tenantId}/test", deployment, self);
        Map(app, "/api/v1/tenants/{tenantId}/test/self", tenant, self);
        app.MapFallback("/api/{**path}", static context =>
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return Task.CompletedTask;
        });

        await app.StartAsync(Cancellation);
        return new CheckedApp(app, postgres.SuperuserConnection(database));
    }

    private static void Map(WebApplication app, string pattern, params object[] metadata) =>
        app.MapGet(pattern, (HttpContext context) =>
        {
            // Reached only past the checks: calling PathTenant here would be the 500 a bad declaration must never reach.
            _ = context;
            return Results.Text(pattern.Split('/')[^1]);
        }).WithMetadata(metadata);

    private sealed class CheckedApp(WebApplication app, string superuser) : IAsyncDisposable
    {
        private readonly Dictionary<string, Guid> _admins = [];

        private readonly HttpClient _client = app.GetTestClient();

        public Guid AdminOf(string cookie) => _admins[cookie];

        /// <summary>A full Session with two credentials, inserted as the superuser. Returns its cookie.</summary>
        public async Task<string> SessionAsync(bool owner)
        {
            var raw = RandomNumberGenerator.GetBytes(32);
            var admin = Guid.CreateVersion7();
            var session = Guid.CreateVersion7();
            await using var connection = new NpgsqlConnection(superuser);
            await connection.OpenAsync(Cancellation);
            await using var command = new NpgsqlCommand(
                """
                INSERT INTO admin (id, deployment_owner) VALUES (@admin, @owner);
                INSERT INTO admin_session (id, id_hash, admin_id, kind, created_at, idle_expires_at, absolute_expires_at)
                VALUES (@id, @hash, @admin, 'full', now(), now() + interval '30 minutes', now() + interval '8 hours');
                INSERT INTO admin_credential (id, admin_id, credential_id, public_key, sign_count, aaguid)
                SELECT gen_random_uuid(), @admin, decode(md5(random()::text || n), 'hex'), '\x01', 0, gen_random_uuid()
                FROM generate_series(1, 2) AS n;
                """,
                connection);
            command.Parameters.AddWithValue("admin", admin);
            command.Parameters.AddWithValue("owner", owner);
            command.Parameters.AddWithValue("id", session);
            command.Parameters.AddWithValue("hash", SHA256.HashData(raw));
            await command.ExecuteNonQueryAsync(Cancellation);

            var cookie = System.Buffers.Text.Base64Url.EncodeToString(raw);
            _admins[cookie] = admin;
            return cookie;
        }

        public async Task<HttpResponseMessage> GetAsync(string path, string cookie)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, path);
            request.Headers.TryAddWithoutValidation("Cookie", $"{AdminHost.Cookie}={cookie}");
            var response = await _client.SendAsync(request, Cancellation);
            await response.Content.LoadIntoBufferAsync(Cancellation);
            return response;
        }

        public Task<T> ScalarAsync<T>(string sql) => PostgresFixture.ScalarAsync<T>(superuser, sql);

        public async ValueTask DisposeAsync()
        {
            _client.Dispose();
            await app.StopAsync(CancellationToken.None);
            await app.DisposeAsync();
        }
    }
}
