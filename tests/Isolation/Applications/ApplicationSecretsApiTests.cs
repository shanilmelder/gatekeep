using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Management.Contracts;
using Gatekeep.Tests.Isolation.Admins;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Npgsql;
using Xunit;
using static Gatekeep.Tests.Isolation.Tenancy.TenantRequests;

namespace Gatekeep.Tests.Isolation.Applications;

/// <summary>
/// Story 3.3 (FR-12, NFR-3, AD-24) on the real Host.Admin and PostgreSQL, with the real Protocol pipeline
/// as <c>gk_hosted</c> for the token endpoint: an Application's client secrets are listed with any Tenant
/// Role, and created, rotated and revoked by Tenant Owners only, each write after a fresh assertion bound to
/// the Application. A secret is shown once, in the create's 201, stored only as its SHA-256, refused at the
/// token endpoint the moment it is revoked or its overlap ends, and an Application holds at most two live
/// secrets. One test or more per row of the story's I/O matrix; the canary row is the
/// <c>admin.application-secrets</c> canary flow.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class ApplicationSecretsApiTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string TenantHost = "acme.secrets.test";

    private const string Action = "tenant.client_secrets.manage";

    private const string Created = "directory.client_secret.created";

    private const string Rotated = "directory.client_secret.rotated";

    private const string Revoked = "directory.client_secret.revoked";

    private static readonly Regex SecretIdShape = new(@"\Asec_[a-z2-7]{25}[aeimquy4]\z", RegexOptions.Compiled);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("web")]
    [InlineData("machine")]
    public async Task An_Owner_creates_the_first_secret_shown_once_stored_as_its_hash_with_one_event(string type)
    {
        await using var setup = await SetupAsync();
        var app = await CreateAppAsync(setup, type);

        await setup.ConfirmAsync(app);
        using var response = await CreateSecretAsync(setup, app);

        var (secret, items) = await CreatedAsync(response);
        Assert.Matches($@"\A{Regex.Escape(Id(setup.Tenant))}\.[A-Za-z0-9_-]{{43}}\z", secret);
        var item = Assert.Single(items);
        Assert.Matches(SecretIdShape, item.GetProperty("id").GetString()!);
        Assert.Equal(JsonValueKind.Null, item.GetProperty("expiresAt").ValueKind);
        Assert.Equal(["createdAt", "expiresAt", "id"], item.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));

        // One row, holding only the whole value's SHA-256: neither the value nor its random part anywhere in it.
        var id = IdOf(app);
        Assert.Equal(1L, await setup.Admin.ScalarAsync<long>(
            $"SELECT count(*) FROM client_secret WHERE application_id = '{id}' AND secret_hash = sha256(convert_to('{secret}', 'UTF8')) AND expires_at IS NULL AND revoked_at IS NULL"));
        Assert.Equal(1L, await setup.Admin.ScalarAsync<long>($"SELECT count(*) FROM client_secret WHERE application_id = '{id}'"));
        Assert.Equal(0L, await setup.Admin.ScalarAsync<long>(
            $"SELECT count(*) FROM client_secret c WHERE position('{RandomPart(secret)}' IN to_jsonb(c)::text) > 0"));
        Assert.Equal(1L, await setup.Admin.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{setup.Tenant}' AND type_code = '{Created}' AND actor_kind = 'admin' AND actor_id = '{setup.Owner}' AND target_kind = 'client' AND target_id = '{id}'"));
        Assert.Equal(0L, await GrantsAsync(setup.Admin));

        // Never shown again: the list holds the same item and no value.
        using var listed = await ListAsync(setup, setup.Cookie, app);
        var body = await listed.Content.ReadAsStringAsync(Cancellation);
        Assert.Equal(HttpStatusCode.OK, listed.StatusCode);
        Assert.DoesNotContain(RandomPart(secret), body, StringComparison.Ordinal);
        Assert.Equal(item.GetRawText(), Assert.Single(Items(body)).GetRawText());

        if (type == "machine")
        {
            await using var protocol = await setup.ProtocolAsync();
            using var token = await TokenAsync(protocol, app, secret);
            Assert.Equal(HttpStatusCode.OK, token.Status);
        }
    }

    [Fact]
    public async Task An_Owner_rotates_and_both_secrets_get_tokens_through_the_24_hour_overlap()
    {
        await using var setup = await SetupAsync();
        var app = await CreateAppAsync(setup, "machine");
        var first = await CreateConfirmedAsync(setup, app);

        await setup.ConfirmAsync(app);
        using var response = await CreateSecretAsync(setup, app);

        var (second, items) = await CreatedAsync(response);
        Assert.NotEqual(first.Secret, second);
        Assert.Equal(2, items.Count);
        Assert.Equal(JsonValueKind.Null, items[0].GetProperty("expiresAt").ValueKind);
        Assert.NotEqual(first.Id, items[0].GetProperty("id").GetString());
        Assert.Equal(first.Id, items[1].GetProperty("id").GetString());
        Assert.Equal(JsonValueKind.String, items[1].GetProperty("expiresAt").ValueKind);

        // The overlap is the fixed 24 hours, by the database's clock.
        Assert.Equal(1L, await setup.Admin.ScalarAsync<long>(
            $"SELECT count(*) FROM client_secret WHERE application_id = '{IdOf(app)}' AND expires_at BETWEEN now() + interval '23 hours 55 minutes' AND now() + interval '24 hours'"));
        Assert.Equal(1L, await TenantEventsAsync(setup.Admin, setup.Tenant, Rotated));
        Assert.Equal(1L, await TenantEventsAsync(setup.Admin, setup.Tenant, Created));

        await using var protocol = await setup.ProtocolAsync();
        foreach (var secret in new[] { first.Secret, second })
        {
            using var token = await TokenAsync(protocol, app, secret);
            Assert.Equal(HttpStatusCode.OK, token.Status);
        }
    }

    [Fact]
    public async Task Rotating_again_during_the_overlap_is_409_and_writes_nothing()
    {
        await using var setup = await SetupAsync();
        var app = await CreateAppAsync(setup, "web");
        await CreateConfirmedAsync(setup, app);
        await CreateConfirmedAsync(setup, app);
        var rows = await RowsAsync(setup, app);

        await setup.ConfirmAsync(app);
        using var response = await CreateSecretAsync(setup, app);

        await FreshAssertionTests.AssertProblemAsync(response, HttpStatusCode.Conflict, "client_secret_limit_reached");
        Assert.Equal(rows, await RowsAsync(setup, app));
        Assert.Equal(1L, await TenantEventsAsync(setup.Admin, setup.Tenant, Rotated));
        Assert.Equal(0L, await GrantsAsync(setup.Admin));
    }

    [Fact]
    public async Task Ending_the_old_secret_now_refuses_it_at_once_and_keeps_the_new_one()
    {
        await using var setup = await SetupAsync();
        var app = await CreateAppAsync(setup, "machine");
        var old = await CreateConfirmedAsync(setup, app);
        var current = await CreateConfirmedAsync(setup, app);

        await setup.ConfirmAsync(app);
        using var response = await RevokeAsync(setup, app, old.Id);

        var item = Assert.Single(await ListedAsync(response));
        Assert.Equal(current.Id, item.GetProperty("id").GetString());
        Assert.Equal(1L, await setup.Admin.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{setup.Tenant}' AND type_code = '{Revoked}' AND actor_id = '{setup.Owner}' AND target_id = '{IdOf(app)}'"));
        Assert.Equal(1L, await setup.Admin.ScalarAsync<long>(
            $"SELECT count(*) FROM client_secret WHERE application_id = '{IdOf(app)}' AND revoked_at IS NOT NULL"));

        await using var protocol = await setup.ProtocolAsync();
        using (var refused = await TokenAsync(protocol, app, old.Secret))
        {
            Assert.Equal("invalid_client", refused.Error);
        }

        using var issued = await TokenAsync(protocol, app, current.Secret);
        Assert.Equal(HttpStatusCode.OK, issued.Status);
    }

    [Fact]
    public async Task Revoking_the_only_secret_leaves_none_and_refuses_it_at_once()
    {
        await using var setup = await SetupAsync();
        var app = await CreateAppAsync(setup, "machine");
        var only = await CreateConfirmedAsync(setup, app);
        await using var protocol = await setup.ProtocolAsync();
        using (var before = await TokenAsync(protocol, app, only.Secret))
        {
            Assert.Equal(HttpStatusCode.OK, before.Status);
        }

        await setup.ConfirmAsync(app);
        using var response = await RevokeAsync(setup, app, only.Id);

        Assert.Empty(await ListedAsync(response));
        using var refused = await TokenAsync(protocol, app, only.Secret);
        Assert.Equal("invalid_client", refused.Error);
        Assert.Equal(1L, await TenantEventsAsync(setup.Admin, setup.Tenant, Revoked));

        // A new secret can be created after: it is a create, not a rotation.
        var next = await CreateConfirmedAsync(setup, app);
        using var issued = await TokenAsync(protocol, app, next.Secret);
        Assert.Equal(HttpStatusCode.OK, issued.Status);
        Assert.Equal(2L, await TenantEventsAsync(setup.Admin, setup.Tenant, Created));
        Assert.Equal(0L, await TenantEventsAsync(setup.Admin, setup.Tenant, Rotated));
    }

    [Fact]
    public async Task An_elapsed_overlap_refuses_the_old_secret_and_lists_only_the_new_one()
    {
        await using var setup = await SetupAsync();
        var app = await CreateAppAsync(setup, "machine");
        var old = await CreateConfirmedAsync(setup, app);
        var current = await CreateConfirmedAsync(setup, app);

        await setup.Database.ExecuteAsync(
            $"UPDATE client_secret SET created_at = created_at - interval '2 days', expires_at = now() - interval '1 second' WHERE id = '{SecretIdOf(old.Id)}'");

        using var listed = await ListAsync(setup, setup.Cookie, app);
        var item = Assert.Single(Items(await listed.Content.ReadAsStringAsync(Cancellation)));
        Assert.Equal(current.Id, item.GetProperty("id").GetString());

        await using var protocol = await setup.ProtocolAsync();
        using (var refused = await TokenAsync(protocol, app, old.Secret))
        {
            Assert.Equal("invalid_client", refused.Error);
        }

        using var issued = await TokenAsync(protocol, app, current.Secret);
        Assert.Equal(HttpStatusCode.OK, issued.Status);

        // With the old one gone, rotation is open again.
        await setup.ConfirmAsync(app);
        using var rotated = await CreateSecretAsync(setup, app);
        Assert.Equal(2, (await CreatedAsync(rotated)).Items.Count);
    }

    [Fact]
    public async Task With_no_fresh_assertion_a_create_or_revoke_is_403_and_writes_nothing()
    {
        await using var setup = await SetupAsync();
        var app = await CreateAppAsync(setup, "web");

        using (var create = await CreateSecretAsync(setup, app))
        {
            await FreshAssertionTests.AssertProblemAsync(create, HttpStatusCode.Forbidden, "fresh_assertion_required");
        }

        Assert.Equal(0L, await setup.Admin.ScalarAsync<long>("SELECT count(*) FROM client_secret"));

        var secret = await CreateConfirmedAsync(setup, app);
        using (var revoke = await RevokeAsync(setup, app, secret.Id))
        {
            await FreshAssertionTests.AssertProblemAsync(revoke, HttpStatusCode.Forbidden, "fresh_assertion_required");
        }

        Assert.Equal(0L, await setup.Admin.ScalarAsync<long>("SELECT count(*) FROM client_secret WHERE revoked_at IS NOT NULL"));

        // A grant bound to another Application never serves this one.
        var other = await CreateAppAsync(setup, "web");
        await setup.ConfirmAsync(other);
        using (var wrongTarget = await CreateSecretAsync(setup, app))
        {
            await FreshAssertionTests.AssertProblemAsync(wrongTarget, HttpStatusCode.Forbidden, "fresh_assertion_required");
        }

        Assert.Equal(1L, await setup.Admin.ScalarAsync<long>("SELECT count(*) FROM client_secret"));
        Assert.Equal(1L, await TenantEventsAsync(setup.Admin, setup.Tenant, Created));
        Assert.Equal(0L, await TenantEventsAsync(setup.Admin, setup.Tenant, Revoked));
    }

    [Theory]
    [InlineData("editor")]
    [InlineData("viewer")]
    public async Task An_Editor_or_Viewer_is_refused_every_write_and_nothing_is_written(string role)
    {
        await using var setup = await SetupAsync();
        var app = await CreateAppAsync(setup, "web");
        var secret = await CreateConfirmedAsync(setup, app);
        var (cookie, csrf, _) = await RoleSessionAsync(setup.Admin, setup.Tenant, role);
        var rows = await RowsAsync(setup, app);

        using (var create = await setup.Admin.SendAsync(HttpMethod.Post, SecretsPath(setup.Tenant, app), cookie, csrf, AdminHost.Origin, headers: [(Header, Id(setup.Tenant))]))
        {
            await FreshAssertionTests.AssertProblemAsync(create, HttpStatusCode.Forbidden, "access_denied");
        }

        using (var revoke = await setup.Admin.SendAsync(
            HttpMethod.Post, $"{SecretsPath(setup.Tenant, app)}/{secret.Id}/revoke", cookie, csrf, AdminHost.Origin, headers: [(Header, Id(setup.Tenant))]))
        {
            await FreshAssertionTests.AssertProblemAsync(revoke, HttpStatusCode.Forbidden, "access_denied");
        }

        // Nor may they begin the assertion the writes need.
        var (begin, _) = await BeginAsync(setup.Admin, cookie, csrf, setup.Tenant, JsonSerializer.Serialize(new { action = Action, target = app }));
        using (begin)
        {
            Assert.Equal(HttpStatusCode.Forbidden, begin.StatusCode);
        }

        Assert.Equal(rows, await RowsAsync(setup, app));
        Assert.Equal(1L, await TenantEventsAsync(setup.Admin, setup.Tenant, Created));
        Assert.Equal(0L, await TenantEventsAsync(setup.Admin, setup.Tenant, Revoked));
    }

    [Fact]
    public async Task A_Viewer_lists_the_live_secrets_with_no_value_or_hash()
    {
        await using var setup = await SetupAsync();
        var app = await CreateAppAsync(setup, "machine");
        var first = await CreateConfirmedAsync(setup, app);
        var second = await CreateConfirmedAsync(setup, app);
        var (cookie, _, _) = await RoleSessionAsync(setup.Admin, setup.Tenant, "viewer");

        using var response = await ListAsync(setup, cookie, app);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        var items = Items(body);
        Assert.Equal([second.Id, first.Id], items.Select(i => i.GetProperty("id").GetString()));
        Assert.All(items, i => Assert.Equal(["createdAt", "expiresAt", "id"], i.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal)));
        foreach (var secret in new[] { first.Secret, second.Secret })
        {
            Assert.DoesNotContain(RandomPart(secret), body, StringComparison.Ordinal);
        }

        var hash = await setup.Admin.ScalarAsync<string>($"SELECT encode(secret_hash, 'hex') FROM client_secret WHERE id = '{SecretIdOf(first.Id)}'");
        Assert.DoesNotContain(hash, body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Convert.ToBase64String(Convert.FromHexString(hash)), body, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("spa")]
    [InlineData("native")]
    public async Task A_spa_or_native_Application_needs_no_secret_lists_none_and_a_create_is_409(string type)
    {
        await using var setup = await SetupAsync();
        var app = await CreateAppAsync(setup, type);

        await setup.ConfirmAsync(app);
        using var response = await CreateSecretAsync(setup, app);

        await FreshAssertionTests.AssertProblemAsync(response, HttpStatusCode.Conflict, "client_secret_not_applicable");
        Assert.Equal(0L, await setup.Admin.ScalarAsync<long>("SELECT count(*) FROM client_secret"));
        Assert.Equal(0L, await TenantEventsAsync(setup.Admin, setup.Tenant, Created));

        using var listed = await ListAsync(setup, setup.Cookie, app);
        Assert.Equal(HttpStatusCode.OK, listed.StatusCode);
        Assert.Empty(Items(await listed.Content.ReadAsStringAsync(Cancellation)));
    }

    [Fact]
    public async Task A_malformed_unknown_other_Applications_revoked_or_expired_secret_is_the_same_404()
    {
        await using var setup = await SetupAsync();
        var app = await CreateAppAsync(setup, "web");
        var other = await CreateAppAsync(setup, "web");
        var live = await CreateConfirmedAsync(setup, app);
        var othersSecret = await CreateConfirmedAsync(setup, other);
        var revoked = await CreateConfirmedAsync(setup, app);
        await setup.ConfirmAsync(app);
        using (var revoke = await RevokeAsync(setup, app, revoked.Id))
        {
            Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        }

        // The live one rotated out and its overlap elapsed: expired, never revoked.
        var expired = live;
        await setup.Database.ExecuteAsync(
            $"UPDATE client_secret SET created_at = created_at - interval '2 days', expires_at = now() - interval '1 second' WHERE id = '{SecretIdOf(expired.Id)}'");

        foreach (var secretId in new[]
        {
            "sec_x",
            "nope",
            "sec_" + new string('a', 26).ToUpperInvariant(),
            PublicId.Format(PublicIdType.Application, Guid.CreateVersion7()),
            PublicId.Format(PublicIdType.ClientSecret, Guid.CreateVersion7()),
            othersSecret.Id,
            revoked.Id,
            expired.Id,
        })
        {
            await setup.ConfirmAsync(app);
            using var response = await RevokeAsync(setup, app, secretId);
            await FreshAssertionTests.AssertProblemAsync(response, HttpStatusCode.NotFound, "not_found");
        }

        Assert.Equal(1L, await TenantEventsAsync(setup.Admin, setup.Tenant, Revoked));
        Assert.Equal(0L, await setup.Admin.ScalarAsync<long>(
            $"SELECT count(*) FROM client_secret WHERE id = '{SecretIdOf(othersSecret.Id)}' AND revoked_at IS NOT NULL"));
    }

    [Fact]
    public async Task The_system_another_Tenants_unknown_and_a_malformed_Application_are_the_same_404()
    {
        await using var setup = await SetupAsync();
        var otherTenant = await InsertAsync(setup.Admin);
        await setup.Admin.GrantTenantRoleAsync(otherTenant, setup.Owner, "owner");
        var foreign = await CreateAppAsync(setup, "web", otherTenant);
        var system = Guid.CreateVersion7();
        await setup.Database.ExecuteAsync(
            $"INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{setup.Tenant}', '{system}', 'Account Portal', 'system', now())");

        foreach (var app in new[]
        {
            PublicId.Format(PublicIdType.Application, system),
            foreign,
            PublicId.Format(PublicIdType.Application, Guid.CreateVersion7()),
            "app_x",
            "app_" + new string('a', 26).ToUpperInvariant(),
        })
        {
            using (var listed = await ListAsync(setup, setup.Cookie, app))
            {
                await FreshAssertionTests.AssertProblemAsync(listed, HttpStatusCode.NotFound, "not_found");
            }

            await setup.ConfirmAsync(app);
            using (var created = await CreateSecretAsync(setup, app))
            {
                await FreshAssertionTests.AssertProblemAsync(created, HttpStatusCode.NotFound, "not_found");
            }

            await setup.ConfirmAsync(app);
            using var revoked = await RevokeAsync(setup, app, PublicId.Format(PublicIdType.ClientSecret, Guid.CreateVersion7()));
            await FreshAssertionTests.AssertProblemAsync(revoked, HttpStatusCode.NotFound, "not_found");
        }

        Assert.Equal(0L, await setup.Admin.ScalarAsync<long>("SELECT count(*) FROM client_secret"));
        Assert.Equal(0L, await setup.Admin.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE type_code LIKE 'directory.client_secret.%'"));
    }

    /// <summary>Management decides again (AD-5): the capability is Owner-only and machine-denied, in any Tenant.</summary>
    [Fact]
    public async Task Management_refuses_every_machine_principal_and_an_Admin_with_no_grant()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var a = Guid.CreateVersion7();
        var b = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), TestTenants.InsertSql(a, b));
        var applications = ManagementContract.CreateApplications(AuditContract.CreateAppender());

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using var scope = await TenantScope.BeginAsync(source, a, Cancellation);
        var context = scope.CreateCommandContext();
        var created = await applications.CreateAsync(context, TestOnlyMachinePrincipal.For(a), null, a, "Worker", "machine", Cancellation);
        var id = created.Application!.Id;

        foreach (var principal in new Gatekeep.Modules.Admins.Contracts.Principal[]
        {
            TestOnlyMachinePrincipal.For(a),
            TestOnlyMachinePrincipal.For(b),
            new Gatekeep.Modules.Admins.Contracts.AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: true),
        })
        {
            Assert.Equal(ApplicationSecretStatus.Forbidden, (await applications.CreateSecretAsync(context, principal, null, a, id, Cancellation)).Status);
            Assert.Equal(ApplicationSecretStatus.Forbidden, (await applications.RevokeSecretAsync(context, principal, null, a, id, Guid.CreateVersion7(), Cancellation)).Status);
        }

        await scope.CommitAsync(Cancellation);
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM client_secret"));
    }

    /// <summary>
    /// The Application's row lock keeps concurrent rotations within the cap: two creates race on an Application
    /// with one current secret, and the second waits for the first, then finds two live secrets.
    /// </summary>
    [Fact]
    public async Task Two_concurrent_rotations_rotate_once_and_stay_within_two_live_secrets()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var tenant = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), TestTenants.InsertSql(tenant));
        var applications = ManagementContract.CreateApplications(AuditContract.CreateAppender());
        var owner = new Gatekeep.Modules.Admins.Contracts.AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: false);
        var grant = new Gatekeep.Modules.Admins.Contracts.TenantRoleGrant(tenant, Gatekeep.Modules.Admins.Contracts.TenantRole.Owner);
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));

        Guid id;
        await using (var setup = await TenantScope.BeginAsync(source, tenant, Cancellation))
        {
            var created = await applications.CreateAsync(setup.CreateCommandContext(), owner, grant, tenant, "Worker", "machine", Cancellation);
            id = created.Application!.Id;
            var first = await applications.CreateSecretAsync(setup.CreateCommandContext(), owner, grant, tenant, id, Cancellation);
            Assert.Equal(ApplicationSecretStatus.Done, first.Status);
            await setup.CommitAsync(Cancellation);
        }

        // The first rotation holds the Application's lock, uncommitted, while the second starts.
        await using var one = await TenantScope.BeginAsync(source, tenant, Cancellation);
        var winner = await applications.CreateSecretAsync(one.CreateCommandContext(), owner, grant, tenant, id, Cancellation);
        var racing = Task.Run(async () =>
        {
            await using var two = await TenantScope.BeginAsync(source, tenant, Cancellation);
            var result = await applications.CreateSecretAsync(two.CreateCommandContext(), owner, grant, tenant, id, Cancellation);
            await two.CommitAsync(Cancellation);
            return result;
        }, Cancellation);

        await Task.Delay(TimeSpan.FromMilliseconds(500), Cancellation);
        Assert.False(racing.IsCompleted);
        await one.CommitAsync(Cancellation);
        var loser = await racing;

        Assert.Equal(ApplicationSecretStatus.Done, winner.Status);
        Assert.Equal(ApplicationSecretStatus.LimitReached, loser.Status);
        Assert.Null(loser.Secret);
        var superuser = postgres.SuperuserConnection(database);
        Assert.Equal(2L, await PostgresFixture.ScalarAsync<long>(superuser,
            $"SELECT count(*) FROM client_secret WHERE application_id = '{id}' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())"));
        Assert.Equal(2L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM client_secret WHERE application_id = '{id}'"));
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser,
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Rotated}' AND target_id = '{id}'"));
    }

    [Fact]
    public async Task No_Session_is_401()
    {
        await using var setup = await SetupAsync();
        var app = PublicId.Format(PublicIdType.Application, Guid.CreateVersion7());

        using var list = await setup.Admin.SendAsync(HttpMethod.Get, SecretsPath(setup.Tenant, app));
        Assert.Equal(HttpStatusCode.Unauthorized, list.StatusCode);
        using var create = await setup.Admin.SendAsync(HttpMethod.Post, SecretsPath(setup.Tenant, app), origin: AdminHost.Origin);
        Assert.Equal(HttpStatusCode.Unauthorized, create.StatusCode);
    }

    private async Task<Setup> SetupAsync()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var tenant = await database.AddTenantAsync(TenantHost);
        var admin = await AdminHost.StartAsync(postgres, database.Name);
        var (cookie, csrf, owner, authenticators) = await OwnerOfAsync(admin, tenant.TenantId);
        return new Setup(database, admin, tenant.TenantId, cookie, csrf, owner, authenticators, bao);
    }

    private static string AppsPath(Guid tenant) => $"/api/v1/tenants/{Id(tenant)}/applications";

    private static string SecretsPath(Guid tenant, string app) => $"{AppsPath(tenant)}/{app}/secrets";

    private static Guid IdOf(string app) =>
        PublicId.TryParse(PublicIdType.Application, app, out var id) ? id : throw new ArgumentException("Not an app_ ID.", nameof(app));

    private static Guid SecretIdOf(string secret) =>
        PublicId.TryParse(PublicIdType.ClientSecret, secret, out var id) ? id : throw new ArgumentException("Not a sec_ ID.", nameof(secret));

    private static string RandomPart(string secret) => secret[(secret.IndexOf('.', StringComparison.Ordinal) + 1)..];

    private static async Task<string> CreateAppAsync(Setup setup, string type, Guid? tenant = null)
    {
        var path = tenant ?? setup.Tenant;
        using var response = await setup.Admin.SendAsync(
            HttpMethod.Post, AppsPath(path), setup.Cookie, setup.Csrf, AdminHost.Origin, JsonSerializer.Serialize(new { name = "App", type }), [(Header, Id(path))]);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return json.RootElement.GetProperty("id").GetString()!;
    }

    private static Task<HttpResponseMessage> ListAsync(Setup setup, string cookie, string app) =>
        setup.Admin.SendAsync(HttpMethod.Get, SecretsPath(setup.Tenant, app), cookie);

    private static Task<HttpResponseMessage> CreateSecretAsync(Setup setup, string app) =>
        setup.Admin.SendAsync(HttpMethod.Post, SecretsPath(setup.Tenant, app), setup.Cookie, setup.Csrf, AdminHost.Origin, headers: [(Header, Id(setup.Tenant))]);

    private static Task<HttpResponseMessage> RevokeAsync(Setup setup, string app, string secretId) =>
        setup.Admin.SendAsync(
            HttpMethod.Post, $"{SecretsPath(setup.Tenant, app)}/{secretId}/revoke", setup.Cookie, setup.Csrf, AdminHost.Origin, headers: [(Header, Id(setup.Tenant))]);

    /// <summary>Confirms, creates, and returns the new secret and its ID, the newest item.</summary>
    private static async Task<(string Secret, string Id)> CreateConfirmedAsync(Setup setup, string app)
    {
        await setup.ConfirmAsync(app);
        using var response = await CreateSecretAsync(setup, app);
        var (secret, items) = await CreatedAsync(response);
        return (secret, items[0].GetProperty("id").GetString()!);
    }

    private static async Task<(string Secret, IReadOnlyList<JsonElement> Items)> CreatedAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return (json.RootElement.GetProperty("secret").GetString()!, [.. json.RootElement.GetProperty("items").EnumerateArray().Select(e => e.Clone())]);
    }

    private static async Task<IReadOnlyList<JsonElement>> ListedAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        Assert.DoesNotContain("secret\"", body, StringComparison.Ordinal);
        return Items(body);
    }

    private static List<JsonElement> Items(string body)
    {
        using var json = JsonDocument.Parse(body);
        return [.. json.RootElement.GetProperty("items").EnumerateArray().Select(e => e.Clone())];
    }

    private static Task<string> RowsAsync(Setup setup, string app) =>
        setup.Admin.ScalarAsync<string>(
            $"SELECT coalesce(string_agg(id || ' ' || coalesce(expires_at::text, '-') || ' ' || coalesce(revoked_at::text, '-'), ',' ORDER BY id), '') FROM client_secret WHERE application_id = '{IdOf(app)}'");

    private static Task<TokenResponse> TokenAsync(ProtocolHost protocol, string app, string secret) =>
        ClientCredentialsTests.TokenAsync(protocol, TenantHost, app, secret);

    /// <summary>
    /// One test's database, Admin host, Tenant and its Owner, whose writes confirm against <see cref="Authenticators"/>.
    /// A Session may make only <see cref="Gatekeep.Kernel.Limits.SecurityLimits.FreshAssertionAttempts"/> fresh-assertion
    /// calls (a begin and a complete each), so a test confirming more often than that signs the Owner in again first.
    /// </summary>
    private sealed class Setup(
        ProtocolDatabase database,
        AdminHost admin,
        Guid tenant,
        string cookie,
        string csrf,
        Guid owner,
        SoftwareAuthenticator[] authenticators,
        OpenBaoFixture bao) : IAsyncDisposable
    {
        private int _calls;

        public ProtocolDatabase Database => database;

        public AdminHost Admin => admin;

        public Guid Tenant => tenant;

        /// <summary>The Owner's current Session: every write sends this one, the Session its grant is bound to.</summary>
        public string Cookie { get; private set; } = cookie;

        public string Csrf { get; private set; } = csrf;

        public Guid Owner => owner;

        public SoftwareAuthenticator[] Authenticators => authenticators;

        public OpenBaoFixture Bao => bao;

        /// <summary>Confirms tenant.client_secrets.manage in the Tenant, bound to <paramref name="app"/>: the Tenant begin, the sheet and the complete.</summary>
        public async Task ConfirmAsync(string app)
        {
            if (_calls + 2 > Gatekeep.Kernel.Limits.SecurityLimits.FreshAssertionAttempts)
            {
                (Cookie, Csrf) = await Admin.SignInAsync(Authenticators[0]);
                _calls = 0;
            }

            _calls += 2;
            var (begin, options) = await BeginAsync(Admin, Cookie, Csrf, Tenant, JsonSerializer.Serialize(new { action = Action, target = app }));
            using (begin)
            {
                Assert.Equal(HttpStatusCode.OK, begin.StatusCode);
            }

            using var complete = await Admin.CompleteAssertionAsync(Cookie, Csrf, Authenticators[0].Assert(options, AdminHost.Origin));
            Assert.Equal(HttpStatusCode.NoContent, complete.StatusCode);
        }

        /// <summary>The Protocol pipeline on the same database, with the Tenant's keys provisioned once.</summary>
        public async Task<ProtocolHost> ProtocolAsync()
        {
            if (await Database.ScalarAsync<long>($"SELECT count(*) FROM signing_key WHERE tenant_id = '{Tenant}'") == 0)
            {
                Assert.True(await Database.ProvisionAsync(Bao, Tenant));
            }

            return await ProtocolHost.StartAsync(Database.Hosted, Bao);
        }

        public async ValueTask DisposeAsync()
        {
            foreach (var authenticator in Authenticators)
            {
                authenticator.Dispose();
            }

            await Admin.DisposeAsync();
        }
    }
}
