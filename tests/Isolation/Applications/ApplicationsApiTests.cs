using System.Net;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Management.Contracts;
using Gatekeep.Tests.Isolation.Admins;
using Npgsql;
using Xunit;
using static Gatekeep.Tests.Isolation.Tenancy.TenantRequests;

namespace Gatekeep.Tests.Isolation.Applications;

/// <summary>
/// Story 3.1 (FR-11, FR-44, UX-DR44, AD-5, AD-19, AD-20) on the real Host.Admin and PostgreSQL:
/// <c>GET</c> and <c>POST /api/v1/tenants/{tenantId}/applications</c> and
/// <c>GET …/applications/{applicationId}</c>. Editors and Owners create each of the four types with no
/// secret, by their own Admin actor; every Tenant Role lists and reads; a Viewer, another Tenant and a
/// machine of another Tenant are refused; the hidden system Application is never listed or read.
/// One test or more per row of the story's I/O matrix; the inert-client rows are
/// <see cref="InertApplicationTests"/>.
/// </summary>
public sealed class ApplicationsApiTests(PostgresFixture postgres)
{
    private const string Created = "directory.application.created";

    private const string Denied = "type_code = 'admin.access.denied'";

    private static readonly string[] Members = ["clientId", "createdAt", "credentialRequired", "id", "name", "type"];

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public static TheoryData<string> Types => ["spa", "web", "native", "machine"];

    public static TheoryData<string> Creators => ["editor", "owner"];

    public static TheoryData<string> Roles => ["owner", "editor", "viewer"];

    [Theory]
    [MemberData(nameof(Types))]
    public async Task An_Editor_creates_each_type_with_no_secret_and_one_event_by_them(string type)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, csrf, admin) = await RoleSessionAsync(host, tenant, "editor");

        using var response = await CreateAsync(host, cookie, csrf, tenant, Body("Web", type));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        var application = await ApplicationAsync(response, HttpStatusCode.Created);

        var id = application.GetProperty("id").GetString()!;
        Assert.Matches("^app_[a-z2-7]{25}[aeimquy4]$", id);
        Assert.Equal(id, application.GetProperty("clientId").GetString());
        Assert.Equal("Web", application.GetProperty("name").GetString());
        Assert.Equal(type, application.GetProperty("type").GetString());
        Assert.Equal(type is "web" or "machine", application.GetProperty("credentialRequired").GetBoolean());
        Assert.Matches(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", application.GetProperty("createdAt").GetString()!);
        Assert.Equal($"{ApplicationsPath(tenant)}/{id}", response.Headers.Location?.ToString());

        Assert.True(PublicId.TryParse(PublicIdType.Application, id, out var applicationId));
        var grants = type switch
        {
            "machine" => "ARRAY['client_credentials']",
            "web" => "ARRAY['authorization_code']",
            _ => "'{}'",
        };
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM application WHERE tenant_id = '{tenant}' AND id = '{applicationId}' AND name = 'Web' AND kind = '{type}' AND grant_types = {grants} AND audiences = '{{}}' AND redirect_uris = '{{}}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM client_secret WHERE tenant_id = '{tenant}'"));
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Created}' AND actor_kind = 'admin' AND actor_id = '{admin}' AND target_kind = 'client' AND target_id = '{applicationId}'"));
        Assert.Equal(1L, await TenantEventsAsync(host, tenant, Created));
    }

    [Theory]
    [MemberData(nameof(Creators))]
    public async Task Editors_and_Owners_create_and_read_it_back(string role)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, role);

        using var created = await CreateAsync(host, cookie, csrf, tenant, Body("  Billing worker  ", "machine"));
        var application = await ApplicationAsync(created, HttpStatusCode.Created);
        Assert.Equal("Billing worker", application.GetProperty("name").GetString());

        using var read = await host.SendAsync(HttpMethod.Get, created.Headers.Location!.ToString(), cookie);
        var again = await ApplicationAsync(read, HttpStatusCode.OK);
        Assert.Equal(application.GetRawText(), again.GetRawText());
    }

    [Fact]
    public async Task A_Viewer_is_403_audited_and_nothing_is_written()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "viewer");

        using var response = await CreateAsync(host, cookie, csrf, tenant, Body("Web", "web"));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("access_denied", await CodeAsync(response));

        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM application"));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Created));
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied} AND target_id = '{tenant}'"));
    }

    [Theory]
    [InlineData("""{"name":"","type":"spa"}""")]
    [InlineData("""{"name":"   ","type":"spa"}""")]
    [InlineData("""{"name":"a\u0007b","type":"spa"}""")]
    [InlineData("""{"name":"Web","type":"system"}""")]
    [InlineData("""{"name":"Web","type":"implicit"}""")]
    [InlineData("""{"name":"Web","type":"SPA"}""")]
    [InlineData("""{"name":"Web"}""")]
    [InlineData("""{"type":"spa"}""")]
    [InlineData("""{"name":1,"type":"spa"}""")]
    [InlineData("""{"name":"Web","type":null}""")]
    [InlineData("not json")]
    public async Task A_bad_name_or_type_is_400_application_invalid_and_nothing_is_written(string body)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");

        using var response = await CreateAsync(host, cookie, csrf, tenant, body);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application_invalid", await CodeAsync(response));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM application"));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Created));
    }

    [Fact]
    public async Task A_name_of_201_characters_is_400_and_one_of_200_is_created()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");

        using (var tooLong = await CreateAsync(host, cookie, csrf, tenant, Body(new string('x', 201), "spa")))
        {
            Assert.Equal(HttpStatusCode.BadRequest, tooLong.StatusCode);
            Assert.Equal("application_invalid", await CodeAsync(tooLong));
        }

        using var longest = await CreateAsync(host, cookie, csrf, tenant, Body(new string('x', 200), "spa"));
        Assert.Equal(new string('x', 200), (await ApplicationAsync(longest, HttpStatusCode.Created)).GetProperty("name").GetString());
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM application"));
    }

    [Fact]
    public async Task A_duplicate_name_makes_two_Applications_with_distinct_client_IDs()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");

        using var first = await CreateAsync(host, cookie, csrf, tenant, Body("Web", "web"));
        using var second = await CreateAsync(host, cookie, csrf, tenant, Body("Web", "web"));
        var a = (await ApplicationAsync(first, HttpStatusCode.Created)).GetProperty("clientId").GetString();
        var b = (await ApplicationAsync(second, HttpStatusCode.Created)).GetProperty("clientId").GetString();

        Assert.NotEqual(a, b);
        Assert.Equal(2L, await host.ScalarAsync<long>($"SELECT count(*) FROM application WHERE tenant_id = '{tenant}' AND name = 'Web'"));
        Assert.Equal(2L, await TenantEventsAsync(host, tenant, Created));
    }

    [Theory]
    [MemberData(nameof(Roles))]
    public async Task Any_Tenant_Role_lists_an_empty_Tenant_as_an_empty_list(string role)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        await InsertSystemApplicationAsync(host, tenant);
        var (cookie, _, _) = await RoleSessionAsync(host, tenant, role);

        using var response = await host.SendAsync(HttpMethod.Get, ApplicationsPath(tenant), cookie);
        var (applications, next) = await ListAsync(response);

        Assert.Empty(applications);
        Assert.Null(next);
    }

    [Fact]
    public async Task Fifty_one_Applications_list_as_the_fifty_newest_then_the_oldest_and_never_the_system_one()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var system = await InsertSystemApplicationAsync(host, tenant);

        // Oldest first, each a millisecond after the last, so the order by UUIDv7 is the order made.
        var start = DateTimeOffset.UtcNow.AddMinutes(-10);
        var ids = Enumerable.Range(0, 51).Select(i => Guid.CreateVersion7(start.AddMilliseconds(i))).ToList();
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            "INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES "
            + string.Join(", ", ids.Select((id, i) => $"('{tenant}', '{id}', 'App {i}', 'spa', now())")));
        var (cookie, _, _) = await RoleSessionAsync(host, tenant, "viewer");

        using var first = await host.SendAsync(HttpMethod.Get, ApplicationsPath(tenant), cookie);
        var (page, next) = await ListAsync(first);
        Assert.Equal(50, page.Count);
        Assert.Equal(ids.Skip(1).Reverse().Select(Public), page.Select(a => a.GetProperty("id").GetString()));
        Assert.Equal(Public(ids[1]), next);
        Assert.All(page, a => Assert.Equal(Members, a.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal)));

        using var second = await host.SendAsync(HttpMethod.Get, $"{ApplicationsPath(tenant)}?cursor={next}", cookie);
        var (last, end) = await ListAsync(second);
        Assert.Equal([Public(ids[0])], last.Select(a => a.GetProperty("id").GetString()));
        Assert.Null(end);

        foreach (var body in new[] { await first.Content.ReadAsStringAsync(Cancellation), await second.Content.ReadAsStringAsync(Cancellation) })
        {
            Assert.DoesNotContain(Public(system), body, StringComparison.Ordinal);
            Assert.DoesNotContain("Account Portal", body, StringComparison.Ordinal);
        }

        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}'"));
    }

    [Theory]
    [InlineData("cursor=")]
    [InlineData("cursor=nope")]
    [InlineData("cursor=ten_aaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("cursor=app_aaaaaaaaaaaaaaaaaaaaaaaaaa&cursor=app_aaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public async Task A_bad_cursor_is_400_invalid_request(string query)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, _, _) = await RoleSessionAsync(host, tenant, "viewer");

        using var response = await host.SendAsync(HttpMethod.Get, $"{ApplicationsPath(tenant)}?{query}", cookie);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", await CodeAsync(response));
    }

    [Fact]
    public async Task Another_Tenants_malformed_unknown_and_the_system_Application_are_the_same_404()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await InsertAsync(host);
        var b = await InsertAsync(host);
        var system = await InsertSystemApplicationAsync(host, b);
        var (ownerA, csrfA, _) = await RoleSessionAsync(host, a, "owner");
        using var createdInA = await CreateAsync(host, ownerA, csrfA, a, Body("A's app", "web"));
        var appOfA = (await ApplicationAsync(createdInA, HttpStatusCode.Created)).GetProperty("id").GetString()!;
        var (viewerB, _, _) = await RoleSessionAsync(host, b, "viewer");

        foreach (var id in new[] { appOfA, Public(system), Public(Guid.CreateVersion7()), "app_x", "nope", "app_" + new string('a', 26).ToUpperInvariant() })
        {
            using var response = await host.SendAsync(HttpMethod.Get, $"{ApplicationsPath(b)}/{id}", viewerB);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Equal("not_found", await CodeAsync(response));
            Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        }
    }

    [Fact]
    public async Task Another_Tenants_Admin_is_403_on_every_route_with_the_other_path_and_nothing_is_written()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await InsertAsync(host);
        var b = await InsertAsync(host);
        var (ownerA, csrfA, _) = await RoleSessionAsync(host, a, "owner");
        using var createdInA = await CreateAsync(host, ownerA, csrfA, a, Body("A's app", "spa"));
        var appOfA = (await ApplicationAsync(createdInA, HttpStatusCode.Created)).GetProperty("id").GetString()!;
        var (ownerB, csrfB, _) = await RoleSessionAsync(host, b, "owner");

        using (var list = await host.SendAsync(HttpMethod.Get, ApplicationsPath(a), ownerB))
        {
            Assert.Equal(HttpStatusCode.Forbidden, list.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(list));
        }

        using (var read = await host.SendAsync(HttpMethod.Get, $"{ApplicationsPath(a)}/{appOfA}", ownerB))
        {
            Assert.Equal(HttpStatusCode.Forbidden, read.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(read));
        }

        using (var create = await CreateAsync(host, ownerB, csrfB, a, Body("B's app", "spa")))
        {
            Assert.Equal(HttpStatusCode.Forbidden, create.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(create));
        }

        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM application"));
        Assert.Equal(0L, await TenantEventsAsync(host, b, Created));
    }

    [Theory]
    [InlineData("other")]
    [InlineData(NoHeader)]
    public async Task A_page_Tenant_that_isnt_the_path_is_409_tenant_mismatch_and_nothing_is_written(string header)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var other = await InsertAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");

        using var response = await CreateAsync(host, cookie, csrf, tenant, Body("Web", "spa"), header == "other" ? Id(other) : header);
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal("tenant_mismatch", await CodeAsync(response));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM application"));
    }

    [Fact]
    public async Task No_Session_is_401_on_every_route()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);

        using var list = await host.SendAsync(HttpMethod.Get, ApplicationsPath(tenant));
        using var read = await host.SendAsync(HttpMethod.Get, $"{ApplicationsPath(tenant)}/{Public(Guid.CreateVersion7())}");
        Assert.Equal(HttpStatusCode.Unauthorized, list.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, read.StatusCode);
    }

    /// <summary>Management decides again (AD-5): a machine of another Tenant is refused, and one of the path Tenant creates as itself.</summary>
    [Fact]
    public async Task Management_refuses_a_machine_principal_without_the_capability_and_records_an_allowed_ones_actor()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var a = Guid.CreateVersion7();
        var b = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), TestTenants.InsertSql(a, b));
        var applications = ManagementContract.CreateApplications(AuditContract.CreateAppender());
        var foreign = TestOnlyMachinePrincipal.For(b);
        var own = TestOnlyMachinePrincipal.For(a);

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using (var scope = await TenantScope.BeginAsync(source, a, Cancellation))
        {
            var context = scope.CreateCommandContext();
            Assert.Equal(ApplicationStatus.Forbidden, (await applications.CreateAsync(context, foreign, null, a, "Job", "machine", Cancellation)).Status);
            Assert.Equal(ApplicationStatus.Forbidden, (await applications.ListAsync(context, foreign, null, a, null, 50, Cancellation)).Status);
            Assert.Equal(ApplicationStatus.Forbidden, (await applications.GetAsync(context, foreign, null, a, Guid.CreateVersion7(), Cancellation)).Status);

            // An Admin with no grant in the path Tenant is refused too, whatever the route checks decided.
            var admin = new Gatekeep.Modules.Admins.Contracts.AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: true);
            Assert.Equal(ApplicationStatus.Forbidden, (await applications.CreateAsync(context, admin, null, a, "Job", "machine", Cancellation)).Status);

            var created = await applications.CreateAsync(context, own, null, a, "Job", "machine", Cancellation);
            Assert.Equal(ApplicationStatus.Done, created.Status);
            await scope.CommitAsync(Cancellation);

            Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database),
                $"SELECT count(*) FROM audit_event WHERE tenant_id = '{a}' AND type_code = '{Created}' AND actor_kind = 'client' AND actor_id = '{own.ClientId}' AND target_id = '{created.Application!.Id}'"));
        }

        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM application"));
    }

    private static string ApplicationsPath(Guid tenant) => $"/api/v1/tenants/{Id(tenant)}/applications";

    private static string Public(Guid id) => PublicId.Format(PublicIdType.Application, id);

    private static string Body(string name, string type) => JsonSerializer.Serialize(new { name, type });

    private static Task<HttpResponseMessage> CreateAsync(AdminHost host, string cookie, string csrf, Guid tenant, string body, string? header = null)
    {
        var headers = (header ?? Id(tenant)) is var value && value == NoHeader ? [] : new[] { (Header, value) };
        return host.SendAsync(HttpMethod.Post, ApplicationsPath(tenant), cookie, csrf, AdminHost.Origin, body, headers);
    }

    /// <summary>The Tenant's hidden system Application, as Tenant creation writes it, as the superuser.</summary>
    private static async Task<Guid> InsertSystemApplicationAsync(AdminHost host, Guid tenant)
    {
        var id = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(
            host.Superuser, $"INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{tenant}', '{id}', 'Account Portal', 'system', now())");
        return id;
    }

    private static async Task<JsonElement> ApplicationAsync(HttpResponseMessage response, HttpStatusCode status)
    {
        Assert.Equal(status, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(Members, json.RootElement.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));
        return json.RootElement.Clone();
    }

    private static async Task<(List<JsonElement> Applications, string? Next)> ListAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(["applications", "nextCursor"], json.RootElement.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));
        return (
            [.. json.RootElement.GetProperty("applications").EnumerateArray().Select(a => a.Clone())],
            json.RootElement.GetProperty("nextCursor").GetString());
    }
}
