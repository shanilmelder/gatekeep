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
/// Story 3.5 (FR-11, AD-13, AD-30) on the real Host.Admin and PostgreSQL:
/// <c>DELETE /api/v1/tenants/{tenantId}/applications/{applicationId}</c>. Editors and Owners, and machine principals
/// with <c>tenant.applications.manage</c>, delete an Application with no fresh assertion: in one transaction it is
/// marked deleted, its live secrets are revoked, its Token Families and tokens are revoked through the one
/// revocation path (<c>sessions.access.revoked</c>), and <c>directory.application.deleted</c> is written; then the
/// Tenant's <c>directory.application.purge</c> Operation answers 202, the one already active when there is one.
/// Every hidden Application is the same 404. One test or more per API, hidden-id, revocation and audit row of the
/// story's I/O matrix; the purge rows are <see cref="Operations.ApplicationPurgeOperationTests"/>, the protocol
/// rows <see cref="ApplicationDeletionProtocolTests"/>.
/// </summary>
public sealed class ApplicationDeleteApiTests(PostgresFixture postgres)
{
    private const string Deleted = "directory.application.deleted";

    private const string Revoked = "sessions.access.revoked";

    private const string Purge = "directory.application.purge";

    private static readonly string[] Stages = ["directory.application.purge"];

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task An_Editor_deletes_it_revokes_its_secrets_families_and_tokens_and_starts_the_purge()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, editor) = await RoleSessionAsync(host, tenant, "editor");
        var app = await CreateAppAsync(host, cookie, csrf, tenant, "web");
        var other = await CreateAppAsync(host, cookie, csrf, tenant, "web");
        await SeedFamilyAsync(host, tenant, IdOf(app));
        await SeedFamilyAsync(host, tenant, IdOf(other));
        var untouched = await RowsOfAsync(host, IdOf(other));

        using var response = await DeleteAsync(host, cookie, csrf, tenant, app);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        var operation = json.RootElement;
        Assert.Equal(Purge, operation.GetProperty("type").GetString());
        Assert.Equal(Id(tenant), operation.GetProperty("tenantId").GetString());
        Assert.Equal("running", operation.GetProperty("status").GetString());
        Assert.Equal(Stages, operation.GetProperty("steps").EnumerateArray().Select(s => s.GetProperty("stage").GetString()));
        Assert.All(operation.GetProperty("steps").EnumerateArray(), s => Assert.Equal(Id(tenant), s.GetProperty("tenantId").GetString()));
        var operationId = operation.GetProperty("id").GetString()!;
        Assert.Equal($"/api/v1/tenants/{Id(tenant)}/operations/{operationId}", response.Headers.Location?.OriginalString);

        var id = IdOf(app);
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM application WHERE id = '{id}' AND deleted_at IS NOT NULL"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM client_secret WHERE application_id = '{id}' AND revoked_at IS NULL"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM \"authorization\" WHERE application_id = '{id}' AND status <> 'revoked'"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM token WHERE application_id = '{id}' AND status <> 'revoked'"));
        Assert.Equal(2L, await host.ScalarAsync<long>($"SELECT count(*) FROM token WHERE application_id = '{id}'"));

        // Nothing is deleted in the request, no Session ends, and the other Application is untouched.
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM client_secret WHERE application_id = '{id}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM user_session WHERE tenant_id = '{tenant}' AND ended_at IS NOT NULL"));
        Assert.Equal(untouched, await RowsOfAsync(host, IdOf(other)));

        // One deleted and one revoked event, both by the Editor; the deletion names the Application.
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Deleted}' AND actor_kind = 'admin' AND actor_id = '{editor}' AND target_kind = 'client' AND target_id = '{id}'"));
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Revoked}' AND actor_kind = 'admin' AND actor_id = '{editor}'"));
        Assert.Equal(1L, await TenantEventsAsync(host, tenant, Deleted));
        Assert.Equal(1L, await TenantEventsAsync(host, tenant, Revoked));
        Assert.Equal(0L, await GrantsAsync(host));

        // One running Operation for the Tenant, with its one step pending.
        Assert.Equal("running", await host.ScalarAsync<string>($"SELECT status FROM operation WHERE type = '{Purge}' AND tenant_id = '{tenant}'"));
        Assert.Equal("pending", await host.ScalarAsync<string>(
            $"SELECT string_agg(s.status, '/' ORDER BY s.position) FROM operation_step s JOIN operation o ON o.id = s.operation_id WHERE o.type = '{Purge}'"));

        // Gone from the list and the detail at once.
        using (var read = await host.SendAsync(HttpMethod.Get, AppPath(tenant, app), cookie))
        {
            Assert.Equal(HttpStatusCode.NotFound, read.StatusCode);
            Assert.Equal("not_found", await CodeAsync(read));
        }

        using (var list = await host.SendAsync(HttpMethod.Get, $"/api/v1/tenants/{Id(tenant)}/applications", cookie))
        {
            Assert.Equal(HttpStatusCode.OK, list.StatusCode);
            using var page = JsonDocument.Parse(await list.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal([other], page.RootElement.GetProperty("applications").EnumerateArray().Select(a => a.GetProperty("id").GetString()));
        }

        // The Location reads the Operation, in the path Tenant's view.
        using var location = await host.SendAsync(HttpMethod.Get, response.Headers.Location!.OriginalString, cookie);
        Assert.Equal(HttpStatusCode.OK, location.StatusCode);
        using var read2 = JsonDocument.Parse(await location.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(operationId, read2.RootElement.GetProperty("id").GetString());
        Assert.Equal(1, read2.RootElement.GetProperty("steps").GetArrayLength());
    }

    [Theory]
    [InlineData("spa")]
    [InlineData("native")]
    [InlineData("machine")]
    public async Task An_Owner_deletes_any_type(string type)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");
        var (cookie, csrf, owner) = await RoleSessionAsync(host, tenant, "owner");
        var app = await CreateAppAsync(host, cookie, csrf, tenant, type);

        using var response = await DeleteAsync(host, cookie, csrf, tenant, app);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM application WHERE id = '{IdOf(app)}' AND deleted_at IS NOT NULL"));
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE type_code = '{Deleted}' AND actor_id = '{owner}' AND target_id = '{IdOf(app)}'"));
        Assert.Equal(1L, await TenantEventsAsync(host, tenant, Revoked));
    }

    [Fact]
    public async Task A_second_deletion_while_the_purge_is_active_answers_that_Operation()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var first = await CreateAppAsync(host, cookie, csrf, tenant, "web");
        var second = await CreateAppAsync(host, cookie, csrf, tenant, "spa");

        string firstOperation;
        using (var response = await DeleteAsync(host, cookie, csrf, tenant, first))
        {
            Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
            firstOperation = await OperationIdAsync(response);
        }

        // A failed one is active too, and is answered the same way.
        await PostgresFixture.ExecuteAsync(host.Superuser, $"UPDATE operation SET status = 'failed' WHERE type = '{Purge}'");

        using (var response = await DeleteAsync(host, cookie, csrf, tenant, second))
        {
            Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
            Assert.Equal(firstOperation, await OperationIdAsync(response));
            Assert.Equal($"/api/v1/tenants/{Id(tenant)}/operations/{firstOperation}", response.Headers.Location?.OriginalString);
        }

        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM operation WHERE type = '{Purge}'"));
        Assert.Equal(2L, await host.ScalarAsync<long>($"SELECT count(*) FROM application WHERE tenant_id = '{tenant}' AND deleted_at IS NOT NULL"));
        Assert.Equal(2L, await TenantEventsAsync(host, tenant, Deleted));

        // Once it has finished, the next deletion starts another.
        await PostgresFixture.ExecuteAsync(host.Superuser, $"UPDATE operation SET status = 'succeeded', finished_at = now() WHERE type = '{Purge}'");
        var third = await CreateAppAsync(host, cookie, csrf, tenant, "machine");
        using (var response = await DeleteAsync(host, cookie, csrf, tenant, third))
        {
            Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
            Assert.NotEqual(firstOperation, await OperationIdAsync(response));
        }

        Assert.Equal(2L, await host.ScalarAsync<long>($"SELECT count(*) FROM operation WHERE type = '{Purge}'"));
    }

    [Fact]
    public async Task A_Viewer_is_403_audited_and_nothing_is_written()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");
        var (editor, editorCsrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var app = await CreateAppAsync(host, editor, editorCsrf, tenant, "web");
        await SeedFamilyAsync(host, tenant, IdOf(app));
        var before = await RowsOfAsync(host, IdOf(app));
        var (cookie, csrf, viewer) = await RoleSessionAsync(host, tenant, "viewer");

        using var response = await DeleteAsync(host, cookie, csrf, tenant, app);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("access_denied", await CodeAsync(response));
        await AssertNothingWrittenAsync(host, tenant);
        Assert.Equal(before, await RowsOfAsync(host, IdOf(app)));
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.access.denied' AND actor_id = '{viewer}' AND target_id = '{tenant}'"));
    }

    [Fact]
    public async Task The_system_another_Tenants_unknown_malformed_and_a_deleted_Application_are_the_same_404()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await InsertAsync(host, "dev");
        var b = await InsertAsync(host, "dev");
        var system = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(
            host.Superuser, $"INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{b}', '{system}', 'Account Portal', 'system', now())");
        var (ownerA, csrfA, _) = await RoleSessionAsync(host, a, "owner");
        var appOfA = await CreateAppAsync(host, ownerA, csrfA, a, "web");
        var (editorB, csrfB, _) = await RoleSessionAsync(host, b, "editor");
        var gone = await CreateAppAsync(host, editorB, csrfB, b, "spa");
        await PostgresFixture.ExecuteAsync(host.Superuser, $"UPDATE application SET deleted_at = now() WHERE id = '{IdOf(gone)}'");
        var before = await host.ScalarAsync<string>("SELECT string_agg(to_jsonb(a)::text, ',' ORDER BY id) FROM application a");

        var bodies = new List<string>();
        foreach (var id in new[] { appOfA, PublicId.Format(PublicIdType.Application, system), PublicId.Format(PublicIdType.Application, Guid.CreateVersion7()), gone, "app_x", "nope" })
        {
            using var response = await DeleteAsync(host, editorB, csrfB, b, id);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Equal("not_found", await CodeAsync(response));
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
            bodies.Add(string.Join(",", json.RootElement.EnumerateObject().Select(p => p.Name)));
        }

        Assert.Single(bodies.Distinct());
        Assert.Equal(before, await host.ScalarAsync<string>("SELECT string_agg(to_jsonb(a)::text, ',' ORDER BY id) FROM application a"));
        await AssertNothingWrittenAsync(host, a);
        await AssertNothingWrittenAsync(host, b);
    }

    [Fact]
    public async Task Another_Tenants_Admin_is_403_and_a_page_Tenant_that_isnt_the_path_is_409()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await InsertAsync(host, "dev");
        var b = await InsertAsync(host, "dev");
        var (ownerA, csrfA, _) = await RoleSessionAsync(host, a, "owner");
        var app = await CreateAppAsync(host, ownerA, csrfA, a, "web");
        var (ownerB, csrfB, _) = await RoleSessionAsync(host, b, "owner");

        using (var foreign = await DeleteAsync(host, ownerB, csrfB, a, app))
        {
            Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(foreign));
        }

        foreach (var header in new[] { Id(b), NoHeader })
        {
            using var mismatch = await DeleteAsync(host, ownerA, csrfA, a, app, header);
            Assert.Equal(HttpStatusCode.Conflict, mismatch.StatusCode);
            Assert.Equal("tenant_mismatch", await CodeAsync(mismatch));
        }

        await AssertNothingWrittenAsync(host, a);
    }

    [Fact]
    public async Task No_Session_is_401()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");

        using var response = await host.SendAsync(
            HttpMethod.Delete,
            AppPath(tenant, PublicId.Format(PublicIdType.Application, Guid.CreateVersion7())),
            origin: AdminHost.Origin);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// Management decides again (AD-5): a machine principal of the path Tenant holds tenant.applications.manage and
    /// deletes as itself, the purge started in a Deployment scope; one of another Tenant, and an Admin with no grant
    /// there, are refused with nothing written.
    /// </summary>
    [Fact]
    public async Task Management_lets_the_path_Tenants_machine_principal_delete_and_refuses_the_others()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var a = Guid.CreateVersion7();
        var b = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), TestTenants.InsertSql(a, b));
        var applications = ManagementContract.CreateApplications(AuditContract.CreateAppender());
        var own = TestOnlyMachinePrincipal.For(a);
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));

        Guid id;
        await using (var scope = await TenantScope.BeginAsync(source, a, Cancellation))
        {
            id = (await applications.CreateAsync(scope.CreateCommandContext(), own, null, a, "Worker", "machine", Cancellation)).Application!.Id;
            await scope.CommitAsync(Cancellation);
        }

        foreach (var principal in new Gatekeep.Modules.Admins.Contracts.Principal[]
        {
            TestOnlyMachinePrincipal.For(b),
            new Gatekeep.Modules.Admins.Contracts.AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: true),
        })
        {
            await using var scope = await TenantScope.BeginAsync(source, a, Cancellation);
            await using var deployment = await DeploymentScope.BeginAsync(source, Cancellation);
            Assert.Equal(
                ApplicationDeleteStatus.Forbidden,
                (await applications.DeleteAsync(scope.CreateCommandContext(), deployment.CreateCommandContext(), principal, null, a, id, Cancellation)).Status);
        }

        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM application WHERE deleted_at IS NOT NULL"));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM operation"));

        await using (var scope = await TenantScope.BeginAsync(source, a, Cancellation))
        await using (var deployment = await DeploymentScope.BeginAsync(source, Cancellation))
        {
            var deleted = await applications.DeleteAsync(scope.CreateCommandContext(), deployment.CreateCommandContext(), own, null, a, id, Cancellation);
            Assert.Equal(ApplicationDeleteStatus.Started, deleted.Status);
            Assert.Equal(Purge, deleted.Operation!.Type);
            Assert.Equal(a, deleted.Operation.TenantId);
            Assert.Equal(Stages, deleted.Operation.Steps.Select(s => s.Stage));
            await scope.CommitAsync(Cancellation);
            await deployment.CommitAsync(Cancellation);
        }

        var superuser = postgres.SuperuserConnection(database);
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser,
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{a}' AND type_code = '{Deleted}' AND actor_kind = 'client' AND actor_id = '{own.ClientId}' AND target_id = '{id}'"));
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser,
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{a}' AND type_code = '{Revoked}' AND actor_kind = 'client' AND actor_id = '{own.ClientId}'"));
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM operation WHERE type = '{Purge}' AND tenant_id = '{a}' AND status = 'running'"));

        // A second deletion of the same Application finds it hidden: nothing more is written.
        await using (var scope = await TenantScope.BeginAsync(source, a, Cancellation))
        await using (var deployment = await DeploymentScope.BeginAsync(source, Cancellation))
        {
            Assert.Equal(
                ApplicationDeleteStatus.NotFound,
                (await applications.DeleteAsync(scope.CreateCommandContext(), deployment.CreateCommandContext(), own, null, a, id, Cancellation)).Status);
        }

        // A Deployment context that names a Tenant is refused before anything is written.
        await using (var scope = await TenantScope.BeginAsync(source, a, Cancellation))
        await using (var other = await TenantScope.BeginAsync(source, a, Cancellation))
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                applications.DeleteAsync(scope.CreateCommandContext(), other.CreateCommandContext(), own, null, a, id, Cancellation));
        }

        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM audit_event WHERE type_code = '{Deleted}'"));
    }

    /// <summary>
    /// gk_admin may set <c>deleted_at</c> in its Tenant's scope (Story 3.5), and GK012 still refuses it on the system
    /// Application; it can't delete an Application row or read a token's payload.
    /// </summary>
    [Fact]
    public async Task The_admin_role_marks_an_Application_deleted_but_never_the_system_one_or_deletes_a_row()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var a = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), TestTenants.InsertSql(a));
        var app = Guid.CreateVersion7();
        var system = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), $"""
            INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{a}', '{app}', 'Web', 'web', now());
            INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{a}', '{system}', 'Account Portal', 'system', now());
            """);

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        foreach (var (sql, state) in new[]
        {
            ($"UPDATE application SET deleted_at = now() WHERE tenant_id = '{a}' AND id = '{system}'", "GK012"),
            ($"DELETE FROM application WHERE tenant_id = '{a}' AND id = '{app}'", PostgresErrorCodes.InsufficientPrivilege),
            ($"SELECT payload FROM token WHERE tenant_id = '{a}'", PostgresErrorCodes.InsufficientPrivilege),
            ($"SELECT subject FROM \"authorization\" WHERE tenant_id = '{a}'", PostgresErrorCodes.InsufficientPrivilege),
        })
        {
            await using var scope = await TenantScope.BeginAsync(source, a, Cancellation);
            await using var command = scope.CreateCommandContext().CreateCommand();
            command.CommandText = sql;
            var refused = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));
            Assert.Equal(state, refused.SqlState);
        }

        await using (var scope = await TenantScope.BeginAsync(source, a, Cancellation))
        {
            await using var command = scope.CreateCommandContext().CreateCommand();
            command.CommandText = $"UPDATE application SET deleted_at = now() WHERE tenant_id = '{a}' AND id = '{app}'";
            Assert.Equal(1, await command.ExecuteNonQueryAsync(Cancellation));
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM application WHERE deleted_at IS NOT NULL"));
    }

    private static string AppPath(Guid tenant, string app) => $"/api/v1/tenants/{Id(tenant)}/applications/{app}";

    private static Guid IdOf(string app) =>
        PublicId.TryParse(PublicIdType.Application, app, out var id) ? id : throw new ArgumentException("Not an app_ ID.", nameof(app));

    private static Task<HttpResponseMessage> DeleteAsync(AdminHost host, string cookie, string csrf, Guid tenant, string app, string? header = null)
    {
        var page = header ?? Id(tenant);
        return host.SendAsync(
            HttpMethod.Delete,
            AppPath(tenant, app),
            cookie,
            csrf,
            AdminHost.Origin,
            headers: page == NoHeader ? [] : [(Header, page)]);
    }

    private static async Task<string> OperationIdAsync(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(Purge, json.RootElement.GetProperty("type").GetString());
        return json.RootElement.GetProperty("id").GetString()!;
    }

    private static async Task<string> CreateAppAsync(AdminHost host, string cookie, string csrf, Guid tenant, string type)
    {
        using var response = await host.SendAsync(
            HttpMethod.Post,
            $"/api/v1/tenants/{Id(tenant)}/applications",
            cookie,
            csrf,
            AdminHost.Origin,
            JsonSerializer.Serialize(new { name = "App", type }),
            [(Header, Id(tenant))]);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return json.RootElement.GetProperty("id").GetString()!;
    }

    /// <summary>A live secret, and a User's Session with a Token Family of the Application holding a refresh and an access token.</summary>
    private static Task SeedFamilyAsync(AdminHost host, Guid tenant, Guid application)
    {
        var user = Guid.CreateVersion7();
        var session = Guid.CreateVersion7();
        var family = Guid.CreateVersion7();
        return PostgresFixture.ExecuteAsync(host.Superuser, $"""
            INSERT INTO client_secret (tenant_id, id, application_id, secret_hash, created_at)
            VALUES ('{tenant}', gen_random_uuid(), '{application}', sha256(convert_to(gen_random_uuid()::text, 'UTF8')), now());
            INSERT INTO "user" (tenant_id, id) VALUES ('{tenant}', '{user}');
            INSERT INTO user_session (tenant_id, id, user_id, id_hash, amr, auth_time, idle_expires_at, absolute_expires_at, created_at)
            VALUES ('{tenant}', '{session}', '{user}', sha256(convert_to('{session}', 'UTF8')), ARRAY['pwd'], now(), now() + interval '3 days', now() + interval '7 days', now());
            INSERT INTO "authorization" (tenant_id, id, application_id, user_session_id, status, type, concurrency_token)
            VALUES ('{tenant}', '{family}', '{application}', '{session}', 'valid', 'ad-hoc', gen_random_uuid());
            INSERT INTO token (tenant_id, id, application_id, authorization_id, type, status, concurrency_token)
            VALUES ('{tenant}', gen_random_uuid(), '{application}', '{family}', 'refresh_token', 'valid', gen_random_uuid()),
                   ('{tenant}', gen_random_uuid(), '{application}', '{family}', 'access_token', 'valid', gen_random_uuid());
            """);
    }

    /// <summary>The Application, its secrets, families and tokens, as text, to compare before and after.</summary>
    private static Task<string> RowsOfAsync(AdminHost host, Guid application) =>
        host.ScalarAsync<string>($"""
            SELECT concat_ws('|',
              (SELECT to_jsonb(a)::text FROM application a WHERE id = '{application}'),
              (SELECT string_agg(to_jsonb(s)::text, ',' ORDER BY id) FROM client_secret s WHERE application_id = '{application}'),
              (SELECT string_agg(to_jsonb(f)::text, ',' ORDER BY id) FROM "authorization" f WHERE application_id = '{application}'),
              (SELECT string_agg(to_jsonb(t)::text, ',' ORDER BY id) FROM token t WHERE application_id = '{application}'))
            """);

    private static async Task AssertNothingWrittenAsync(AdminHost host, Guid tenant)
    {
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Deleted));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Revoked));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM operation WHERE tenant_id = '{tenant}' AND type = '{Purge}'"));
    }
}
