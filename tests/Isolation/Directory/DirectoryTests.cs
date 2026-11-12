using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Gatekeep.Adapters.Postgres.Migrations;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Applications;

/// <summary>
/// Story 2.5 (AD-8, AD-9, AD-24, AD-27): Directory's Applications and client secrets. A machine client
/// is created in one command with its event, its secret is <c>{tenantPublicId}.{random}</c> shown once
/// and stored only as its SHA-256, and only a live secret of that Application, in that Tenant, verifies.
/// The tables hold every role to its grants and every Tenant to its own rows. Story 2.8 (AD-12, AR-43):
/// each Tenant's one hidden <c>system</c> Application, which no read but its own lookup returns, nothing
/// may name but a sign-in transaction, and nothing but its Tenant's deletion may change or delete.
/// </summary>
public sealed class DirectoryTests(PostgresFixture postgres)
{
    private const string PermissionDenied = "42501";

    /// <summary>Story 2.8's guards: a row naming the system Application, its edit, and its delete outside a Tenant deletion.</summary>
    private const string SystemApplicationNamed = "GK011";
    private const string SystemApplicationEdited = "GK012";
    private const string SystemApplicationDeleted = "GK013";

    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-0000000025d1");
    private static readonly Guid TenantB = Guid.Parse("01900000-0000-7000-8000-0000000025d2");
    private static readonly Guid TenantC = Guid.Parse("01900000-0000-7000-8000-0000000025d3");
    private static readonly Guid TenantD = Guid.Parse("01900000-0000-7000-8000-0000000025d4");

    private static readonly Regex SecretShape = new(@"\Aten_[a-z2-7]{26}\.[A-Za-z0-9_-]{43}\z", RegexOptions.Compiled);

    private readonly IDirectory _directory = DirectoryContract.CreateDirectory(AuditContract.CreateAppender(), TimeProvider.System);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    /// <summary>What no role may do to Applications and secrets, by role: Host.Hosted only reads, Host.Admin only creates.</summary>
    public static TheoryData<string, string> Refusals => new()
    {
        { TableRegistry.Hosted, $"INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{TenantA}', gen_random_uuid(), 'x', 'machine', now())" },
        { TableRegistry.Hosted, "UPDATE application SET grant_types = '{}'" },
        { TableRegistry.Hosted, "UPDATE client_secret SET revoked_at = NULL" },
        { TableRegistry.Hosted, "DELETE FROM client_secret" },
        { TableRegistry.Admin, "UPDATE application SET audiences = '{}'" },
        { TableRegistry.Admin, "UPDATE application SET name = 'x'" },
        { TableRegistry.Admin, "UPDATE application SET kind = 'spa'" },
        { TableRegistry.Admin, "UPDATE client_secret SET expires_at = NULL" },
        { TableRegistry.Admin, "DELETE FROM application" },
        { TableRegistry.Worker, "SELECT name FROM application" },
        { TableRegistry.Worker, "SELECT grant_types FROM application" },
        { TableRegistry.Worker, "UPDATE application SET name = 'x'" },
        { TableRegistry.Worker, "SELECT secret_hash FROM client_secret" },
        { TableRegistry.Dispatch, "SELECT count(*) FROM application" },
        { TableRegistry.Sealer, "SELECT count(*) FROM client_secret" },
        { TableRegistry.Retention, "SELECT count(*) FROM application" },
        { TableRegistry.Cli, "SELECT count(*) FROM client_secret" },
    };

    [Fact]
    public async Task Creating_a_machine_client_writes_its_Application_one_secret_hash_and_one_event()
    {
        var database = await DatabaseAsync();

        var created = await CreateAsync(database, TenantA, "Billing worker");
        var secret = created.Secret.Use(static s => s);

        Assert.Equal(PublicId.Format(PublicIdType.Application, created.ApplicationId), created.ClientId);
        Assert.True(SecretShape.IsMatch(secret), "The secret isn't {tenantPublicId}.{base64url of 32 bytes}.");
        Assert.True(secret.StartsWith(PublicId.Format(PublicIdType.Tenant, TenantA) + ".", StringComparison.Ordinal), "The secret's prefix isn't its Tenant's public ID.");
        Assert.Equal("[secret]", created.Secret.ToString());

        var superuser = postgres.SuperuserConnection(database);
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser,
            $"SELECT count(*) FROM application WHERE tenant_id = '{TenantA}' AND id = '{created.ApplicationId}' AND name = 'Billing worker' AND kind = 'machine' AND grant_types = ARRAY['client_credentials'] AND audiences = '{{}}'"));
        Assert.Equal(1L, await CountAsync(superuser, "SELECT count(*) FROM client_secret WHERE application_id = @id AND secret_hash = @hash AND expires_at IS NULL AND revoked_at IS NULL",
            ("id", created.ApplicationId), ("hash", SHA256.HashData(Encoding.UTF8.GetBytes(secret)))));
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser,
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{TenantA}' AND type_code = 'directory.application.created' AND actor_kind = 'system' AND target_kind = 'client' AND target_id = '{created.ApplicationId}'"));

        // The secret is in no column, in either spelling, and its random part nowhere either.
        foreach (var table in new[] { "application", "client_secret", "audit_event", "audit_detail" })
        {
            Assert.Equal(0L, await CountAsync(superuser, $"SELECT count(*) FROM \"{table}\" r WHERE strpos(to_jsonb(r)::text, @value) > 0", ("value", secret.Split('.')[1])));
        }
    }

    [Fact]
    public async Task Creating_a_web_client_writes_its_redirect_uris_the_code_grant_one_secret_hash_and_one_event()
    {
        var database = await DatabaseAsync();
        string[] uris = ["https://app.example/callback", "http://127.0.0.1:8080/cb", "http://[::1]/cb?x=1"];

        await using (var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database)))
        await using (var scope = await TenantScope.BeginAsync(source, TenantA, Cancellation))
        {
            var created = await _directory.CreateWebClientAsync(scope.CreateCommandContext(), "Web app", uris, Cancellation);
            await scope.CommitAsync(Cancellation);

            var secret = created.Secret.Use(static s => s);
            Assert.Equal(PublicId.Format(PublicIdType.Application, created.ApplicationId), created.ClientId);
            Assert.True(SecretShape.IsMatch(secret), "The secret isn't {tenantPublicId}.{base64url of 32 bytes}.");

            var superuser = postgres.SuperuserConnection(database);
            Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser,
                $"SELECT count(*) FROM application WHERE id = '{created.ApplicationId}' AND kind = 'web' AND grant_types = ARRAY['authorization_code', 'refresh_token'] AND audiences = '{{}}' AND redirect_uris = ARRAY['https://app.example/callback', 'http://127.0.0.1:8080/cb', 'http://[::1]/cb?x=1']"));
            Assert.Equal(1L, await CountAsync(superuser, "SELECT count(*) FROM client_secret WHERE application_id = @id AND secret_hash = @hash",
                ("id", created.ApplicationId), ("hash", SHA256.HashData(Encoding.UTF8.GetBytes(secret)))));
            Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser,
                $"SELECT count(*) FROM audit_event WHERE type_code = 'directory.application.created' AND actor_kind = 'system' AND target_id = '{created.ApplicationId}'"));
        }

        // OpenIddict's store hands out the redirect URIs, the code flow's permissions and PKCE.
        await using var hosted = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Hosted, database));
        await using var read = await TenantScope.BeginAsync(hosted, TenantA, Cancellation);
        var context = read.CreateCommandContext();
        var store = DirectoryContract.CreateApplicationStore(() => context);
        var found = (await store.FindByClientIdAsync(PublicId.Format(PublicIdType.Application, await PostgresFixture.ScalarAsync<Guid>(
            postgres.SuperuserConnection(database), "SELECT id FROM application WHERE kind = 'web'")), Cancellation))!;
        Assert.Equal(uris, await store.GetRedirectUrisAsync(found, Cancellation));
        Assert.Equal(
            ["ept:authorization", "ept:revocation", "ept:token", "gt:authorization_code", "gt:refresh_token", "rst:code"],
            (await store.GetPermissionsAsync(found, Cancellation)).Order(StringComparer.Ordinal));
        Assert.Equal(["ft:pkce"], await store.GetRequirementsAsync(found, Cancellation));
        Assert.Equal("confidential", await store.GetClientTypeAsync(found, Cancellation));
    }

    [Fact]
    public async Task The_system_Application_and_machine_clients_have_no_redirect_uri_or_code_flow_permission()
    {
        var database = await DatabaseAsync();
        var machine = await CreateAsync(database, TenantA);
        await EnsureAsync(database, TenantA);

        await using var hosted = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Hosted, database));
        await using var read = await TenantScope.BeginAsync(hosted, TenantA, Cancellation);
        var context = read.CreateCommandContext();
        var store = DirectoryContract.CreateApplicationStore(() => context);
        var found = (await store.FindByClientIdAsync(machine.ClientId, Cancellation))!;

        Assert.Empty(await store.GetRedirectUrisAsync(found, Cancellation));
        Assert.Empty(await store.GetRequirementsAsync(found, Cancellation));
        Assert.Equal(["ept:token", "gt:client_credentials"], (await store.GetPermissionsAsync(found, Cancellation)).Order(StringComparer.Ordinal));
    }

    public static TheoryData<string[]> BadRedirectUris => new()
    {
        new[] { "http://example.com/cb" },
        new[] { "http://localhost/cb" },
        new[] { "http://localhost:8080/cb" },
        new[] { "https://example.com/cb#fragment" },
        new[] { "https://example.com/cb#" },
        new[] { "/relative/cb" },
        new[] { "https://user:pass@example.com/cb" },
        new[] { "https://example.com/c b" },
        new[] { "https://example.com/" + new string('a', 2000) },
        new[] { "https://example.com/cb", "https://example.com/cb" },
        Enumerable.Range(0, 11).Select(i => $"https://example.com/cb{i}").ToArray(),
        Array.Empty<string>(),
    };

    [Theory]
    [MemberData(nameof(BadRedirectUris))]
    public async Task A_bad_redirect_uri_set_is_refused_and_writes_nothing(string[] uris)
    {
        var database = await DatabaseAsync();
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using var scope = await TenantScope.BeginAsync(source, TenantA, Cancellation);

        await Assert.ThrowsAsync<ArgumentException>(() => _directory.CreateWebClientAsync(scope.CreateCommandContext(), "Web app", uris, Cancellation));
        await scope.CommitAsync(Cancellation);

        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM application"));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(
            postgres.SuperuserConnection(database), "SELECT count(*) FROM audit_event WHERE type_code = 'directory.application.created'"));
    }

    [Fact]
    public async Task Two_clients_get_different_secrets()
    {
        var database = await DatabaseAsync();

        var first = (await CreateAsync(database, TenantA)).Secret.Use(static s => s);
        var second = (await CreateAsync(database, TenantA)).Secret.Use(static s => s);

        Assert.True(first != second, "Two clients got the same secret.");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("bad\0name")]
    public async Task A_bad_name_is_refused_and_writes_nothing(string name)
    {
        var database = await DatabaseAsync();
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using var scope = await TenantScope.BeginAsync(source, TenantA, Cancellation);

        await Assert.ThrowsAsync<ArgumentException>(() => _directory.CreateMachineClientAsync(scope.CreateCommandContext(), name, Cancellation));
        await Assert.ThrowsAsync<ArgumentException>(() => _directory.CreateMachineClientAsync(scope.CreateCommandContext(), new string('x', 201), Cancellation));
        await scope.CommitAsync(Cancellation);

        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM application"));
    }

    [Fact]
    public async Task Only_a_live_secret_of_that_Application_in_that_Tenant_verifies()
    {
        var database = await DatabaseAsync();
        var a = await CreateAsync(database, TenantA);
        var other = await CreateAsync(database, TenantA);
        var secret = new Secret<string>(a.Secret.Use(static s => s));

        Assert.True(await VerifyAsync(database, TenantA, a.ClientId, secret));
        Assert.False(await VerifyAsync(database, TenantA, other.ClientId, secret));
        Assert.False(await VerifyAsync(database, TenantB, a.ClientId, secret));
        Assert.False(await VerifyAsync(database, TenantA, a.ClientId, new Secret<string>(secret.Use(static s => s + "x"))));
        Assert.False(await VerifyAsync(database, TenantA, "app_notaclient", secret));
        Assert.False(await VerifyAsync(database, TenantA, PublicId.Format(PublicIdType.Tenant, a.ApplicationId), secret));

        var superuser = postgres.SuperuserConnection(database);
        await PostgresFixture.ExecuteAsync(superuser, $"UPDATE client_secret SET expires_at = now() + interval '1 day' WHERE application_id = '{a.ApplicationId}'");
        Assert.True(await VerifyAsync(database, TenantA, a.ClientId, secret));

        await PostgresFixture.ExecuteAsync(superuser, $"UPDATE client_secret SET expires_at = now() - interval '1 second' WHERE application_id = '{a.ApplicationId}'");
        Assert.False(await VerifyAsync(database, TenantA, a.ClientId, secret));

        await PostgresFixture.ExecuteAsync(superuser, $"UPDATE client_secret SET expires_at = NULL, revoked_at = now() WHERE application_id = '{a.ApplicationId}'");
        Assert.False(await VerifyAsync(database, TenantA, a.ClientId, secret));
    }

    [Theory]
    [MemberData(nameof(Refusals))]
    public async Task Each_role_is_held_to_its_grants(string role, string statement)
    {
        var database = await DatabaseAsync();
        await CreateAsync(database, TenantA);
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(role, database));
        await using var scope = await TenantScope.BeginAsync(source, TenantA, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = statement;

        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));
        Assert.Equal(PermissionDenied, error.SqlState);
    }

    [Fact]
    public async Task Another_Tenants_scope_sees_none_of_the_Applications_or_secrets()
    {
        var database = await DatabaseAsync();
        await CreateAsync(database, TenantA);

        foreach (var role in new[] { TableRegistry.Hosted, TableRegistry.Admin })
        {
            await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(role, database));
            await using var scope = await TenantScope.BeginAsync(source, TenantB, Cancellation);
            foreach (var table in new[] { "application", "client_secret" })
            {
                await using var command = scope.CreateCommandContext().CreateCommand();
                command.CommandText = $"SELECT count(*) FROM {table}";
                Assert.Equal(0L, (long)(await command.ExecuteScalarAsync(Cancellation))!);
            }
        }
    }

    [Theory]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'interactive', now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, grant_types, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'machine', ARRAY['password'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{0}', gen_random_uuid(), '', 'machine', now())")]
    [InlineData("INSERT INTO client_secret (tenant_id, id, application_id, secret_hash, created_at) VALUES ('{0}', gen_random_uuid(), '{1}', decode(repeat('00', 31), 'hex'), now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, grant_types, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'system', ARRAY['client_credentials'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, audiences, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'system', ARRAY['https://api.test'], now())")]
    // Story 2.9: a web client has up to 10 redirect URIs (from Story 3.1, possibly none) and the code grant,
    // from Story 2.10 with or without refresh tokens, and nothing else; no other kind has one.
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, grant_types, redirect_uris, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'web', ARRAY['refresh_token'], ARRAY['https://app.test/cb'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, grant_types, redirect_uris, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'web', ARRAY['refresh_token', 'authorization_code'], ARRAY['https://app.test/cb'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, grant_types, redirect_uris, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'web', ARRAY['authorization_code', 'refresh_token', 'client_credentials'], ARRAY['https://app.test/cb'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, grant_types, redirect_uris, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'web', ARRAY['client_credentials'], ARRAY['https://app.test/cb'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, grant_types, redirect_uris, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'web', ARRAY['authorization_code', 'client_credentials'], ARRAY['https://app.test/cb'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, grant_types, redirect_uris, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'web', ARRAY['authorization_code'], array_fill('https://app.test/cb'::text, ARRAY[11]), now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, grant_types, redirect_uris, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'machine', ARRAY['client_credentials'], ARRAY['https://app.test/cb'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, redirect_uris, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'system', ARRAY['https://app.test/cb'], now())")]
    // Story 3.2: the type table. A machine row has no URL and only {} or {client_credentials}; a native row
    // no web origin; the system row nothing; every list at most 10; every other kind only the code flow's sets.
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, grant_types, post_logout_redirect_uris, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'machine', ARRAY['client_credentials'], ARRAY['https://app.test/'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, web_origins, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'machine', ARRAY['https://app.test'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, grant_types, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'machine', ARRAY['authorization_code'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, web_origins, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'native', ARRAY['https://app.test'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, post_logout_redirect_uris, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'system', ARRAY['https://app.test/'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, web_origins, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'system', ARRAY['https://app.test'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, grant_types, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'spa', ARRAY['refresh_token'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, grant_types, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'spa', ARRAY['client_credentials'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, grant_types, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'native', ARRAY['authorization_code', 'authorization_code'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, post_logout_redirect_uris, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'web', array_fill('https://app.test/'::text, ARRAY[11]), now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, web_origins, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'spa', array_fill('https://app.test'::text, ARRAY[11]), now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'implicit', now())")]
    public async Task Each_check_refuses_a_row_that_breaks_it(string statement)
    {
        var database = await DatabaseAsync();
        var created = await CreateAsync(database, TenantA);

        var error = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database), string.Format(System.Globalization.CultureInfo.InvariantCulture, statement, TenantA, created.ApplicationId)));
        Assert.Equal(PostgresErrorCodes.CheckViolation, error.SqlState);
    }

    [Fact]
    public async Task An_Application_with_a_secret_cant_be_deleted_from_under_it()
    {
        var database = await DatabaseAsync();
        var created = await CreateAsync(database, TenantA);

        var error = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database), $"DELETE FROM application WHERE id = '{created.ApplicationId}'"));
        Assert.Equal(PostgresErrorCodes.RestrictViolation, error.SqlState);
    }

    // Story 2.8 (AD-12, AR-43): each Tenant's one hidden system Application.

    [Fact]
    public async Task Ensuring_writes_one_bare_system_Application_and_returns_it_again()
    {
        var database = await DatabaseAsync();

        var id = await EnsureAsync(database, TenantA);
        var again = await EnsureAsync(database, TenantA);

        Assert.Equal(id, again);
        Assert.Equal(7, id.Version);
        var superuser = postgres.SuperuserConnection(database);
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM application WHERE tenant_id = '{TenantA}'"));
        Assert.Equal(1L, await CountAsync(
            superuser,
            "SELECT count(*) FROM application WHERE id = @id AND kind = 'system' AND name = @name AND grant_types = '{}' AND audiences = '{}'",
            ("id", id),
            ("name", DirectoryContract.SystemApplicationName)));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, "SELECT count(*) FROM client_secret"));

        // No audit event: the Tenant's activation records it, and a Log event would expose it.
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, "SELECT count(*) FROM audit_event"));
        Assert.Equal(id, await InTenantAsync(database, TableRegistry.Hosted, TenantA, c => _directory.FindSystemApplicationAsync(c, Cancellation)));
    }

    [Fact]
    public async Task Every_system_Application_method_needs_a_Tenant()
    {
        var database = await DatabaseAsync();
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Worker, database));
        await using var scope = await DeploymentScope.BeginAsync(source, Cancellation);
        var context = scope.CreateCommandContext();

        await Assert.ThrowsAsync<InvalidOperationException>(() => _directory.EnsureSystemApplicationAsync(context, Cancellation));
        await Assert.ThrowsAsync<InvalidOperationException>(() => _directory.FindSystemApplicationAsync(context, Cancellation));
        await Assert.ThrowsAsync<InvalidOperationException>(() => _directory.ListApplicationsAsync(context, Cancellation));
        await scope.CommitAsync(Cancellation);

        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM application"));
    }

    [Fact]
    public async Task Listing_returns_only_the_machine_Applications_in_creation_order()
    {
        var database = await DatabaseAsync();
        var first = await CreateAsync(database, TenantA, "First");
        await EnsureAsync(database, TenantA);
        var second = await CreateAsync(database, TenantA, "Second");
        await CreateAsync(database, TenantB, "Other Tenant's");

        var listed = await InTenantAsync(database, TableRegistry.Hosted, TenantA, c => _directory.ListApplicationsAsync(c, Cancellation));

        Assert.Equal([first.ApplicationId, second.ApplicationId], listed.Select(a => a.Id));
        Assert.Equal(["First", "Second"], listed.Select(a => a.Name));
        Assert.Equal([first.ClientId, second.ClientId], listed.Select(a => a.ClientId));
    }

    // Story 3.1 (FR-11, FR-44): an Admin's Application, of four types, with no secret.

    [Theory]
    [InlineData("spa", "'{}'")]
    [InlineData("native", "'{}'")]
    [InlineData("web", "ARRAY['authorization_code']")]
    [InlineData("machine", "ARRAY['client_credentials']")]
    public async Task An_Admins_Application_has_its_kinds_grants_no_secret_and_one_event_by_its_actor(string kind, string grants)
    {
        var database = await DatabaseAsync();
        var admin = Guid.CreateVersion7();

        var created = await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.CreateApplicationAsync(c, Gatekeep.Kernel.Audit.Actor.Admin(admin), "My app", kind, Cancellation));

        Assert.Equal(PublicId.Format(PublicIdType.Application, created.Id), created.ClientId);
        Assert.Equal(7, created.Id.Version);
        Assert.Equal(kind, created.Kind);
        Assert.Equal(kind is "web" or "machine", created.CredentialRequired);
        var superuser = postgres.SuperuserConnection(database);
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser,
            $"SELECT count(*) FROM application WHERE tenant_id = '{TenantA}' AND id = '{created.Id}' AND name = 'My app' AND kind = '{kind}' AND grant_types = {grants} AND audiences = '{{}}' AND redirect_uris = '{{}}'"));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, "SELECT count(*) FROM client_secret"));
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser,
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{TenantA}' AND type_code = 'directory.application.created' AND actor_kind = 'admin' AND actor_id = '{admin}' AND target_kind = 'client' AND target_id = '{created.Id}'"));

        var found = await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.FindApplicationAsync(c, created.Id, Cancellation));
        Assert.Equal(created.Id, found?.Id);
        Assert.Equal(created.CreatedAt.ToUnixTimeMilliseconds(), found!.CreatedAt.ToUnixTimeMilliseconds());

        // No secret: it verifies nothing, whatever is presented.
        Assert.False(await VerifyAsync(database, TenantA, created.ClientId, new Secret<string>($"{PublicId.Format(PublicIdType.Tenant, TenantA)}.x")));
    }

    [Theory]
    [InlineData("", "spa")]
    [InlineData("   ", "spa")]
    [InlineData("a\u0001b", "spa")]
    [InlineData("x", "system")]
    [InlineData("x", "implicit")]
    [InlineData("x", "")]
    public async Task An_Admins_Application_with_a_bad_name_or_kind_writes_nothing(string name, string kind)
    {
        var database = await DatabaseAsync();

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using var scope = await TenantScope.BeginAsync(source, TenantA, Cancellation);
        await Assert.ThrowsAsync<ArgumentException>(() => _directory.CreateApplicationAsync(scope.CreateCommandContext(), Gatekeep.Kernel.Audit.Actor.System, name, kind, Cancellation));
        await Assert.ThrowsAsync<ArgumentException>(() => _directory.CreateApplicationAsync(scope.CreateCommandContext(), Gatekeep.Kernel.Audit.Actor.System, new string('x', 201), "spa", Cancellation));
        await scope.CommitAsync(Cancellation);

        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM application"));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM audit_event"));
    }

    [Fact]
    public async Task A_page_lists_newest_first_after_its_cursor_and_never_the_system_or_another_Tenants_Application()
    {
        var database = await DatabaseAsync();
        var first = await CreateAsync(database, TenantA, "First");
        await EnsureAsync(database, TenantA);
        var second = await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.CreateApplicationAsync(c, Gatekeep.Kernel.Audit.Actor.System, "Second", "spa", Cancellation));
        var third = await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.CreateApplicationAsync(c, Gatekeep.Kernel.Audit.Actor.System, "Third", "native", Cancellation));
        await CreateAsync(database, TenantB, "Other Tenant's");

        var page = await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.ListApplicationsPageAsync(c, null, 2, Cancellation));
        Assert.Equal([third.Id, second.Id], page.Applications.Select(a => a.Id));
        Assert.Equal(second.Id, page.NextAfter);

        var rest = await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.ListApplicationsPageAsync(c, page.NextAfter, 2, Cancellation));
        Assert.Equal([first.ApplicationId], rest.Applications.Select(a => a.Id));
        Assert.Null(rest.NextAfter);

        var all = await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.ListApplicationsPageAsync(c, null, 50, Cancellation));
        Assert.Equal(3, all.Applications.Count);
        Assert.Null(all.NextAfter);
    }

    [Fact]
    public async Task Finding_an_Application_hides_the_system_one_and_another_Tenants()
    {
        var database = await DatabaseAsync();
        var system = await EnsureAsync(database, TenantA);
        var other = await CreateAsync(database, TenantB);

        Assert.Null(await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.FindApplicationAsync(c, system, Cancellation)));
        Assert.Null(await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.FindApplicationAsync(c, other.ApplicationId, Cancellation)));
        Assert.Null(await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.FindApplicationAsync(c, Guid.CreateVersion7(), Cancellation)));
    }

    [Fact]
    public async Task OpenIddicts_store_finds_no_system_Application()
    {
        var database = await DatabaseAsync();
        var machine = await CreateAsync(database, TenantA);
        var id = await EnsureAsync(database, TenantA);

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Hosted, database));
        await using var scope = await TenantScope.BeginAsync(source, TenantA, Cancellation);
        var context = scope.CreateCommandContext();
        var store = DirectoryContract.CreateApplicationStore(() => context);

        Assert.Null(await store.FindByIdAsync(id.ToString(), Cancellation));
        Assert.Null(await store.FindByClientIdAsync(PublicId.Format(PublicIdType.Application, id), Cancellation));
        Assert.Equal(machine.ApplicationId, (await store.FindByClientIdAsync(machine.ClientId, Cancellation))!.Id);
        Assert.Equal(machine.ApplicationId, (await store.FindByIdAsync(machine.ApplicationId.ToString(), Cancellation))!.Id);
    }

    [Fact]
    public async Task A_second_system_Application_is_refused()
    {
        var database = await DatabaseAsync();
        await EnsureAsync(database, TenantA);

        var error = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{TenantA}', gen_random_uuid(), 'Second', 'system', now())"));
        Assert.Equal(PostgresErrorCodes.UniqueViolation, error.SqlState);
        Assert.Equal("application_one_system", error.ConstraintName);
    }

    /// <summary>The User and Session an <c>"authorization"</c> row in Tenant <c>{0}</c> anchors to, so only its Application can fail.</summary>
    private const string SessionIn =
        """
        INSERT INTO "user" (tenant_id, id) VALUES ('{0}', '01900000-0000-7000-8000-0000000028a1');
        INSERT INTO user_session (tenant_id, id, user_id, id_hash, amr, auth_time, idle_expires_at, absolute_expires_at, created_at)
          VALUES ('{0}', '01900000-0000-7000-8000-0000000028a2', '01900000-0000-7000-8000-0000000028a1', sha256('s'::bytea), '{{pwd}}', now(), now() + interval '1 hour', now() + interval '1 hour', now());
        """;

    [Theory]
    [InlineData("client_secret", "", "INSERT INTO client_secret (tenant_id, id, application_id, secret_hash, created_at) VALUES ('{0}', gen_random_uuid(), '{1}', sha256('x'::bytea), now())")]
    [InlineData("authorization", SessionIn, "INSERT INTO \"authorization\" (tenant_id, id, application_id, user_session_id, status, type, concurrency_token) VALUES ('{0}', gen_random_uuid(), '{1}', '01900000-0000-7000-8000-0000000028a2', 'valid', 'ad-hoc', gen_random_uuid())")]
    [InlineData("token", "", "INSERT INTO token (tenant_id, id, application_id, type, status, concurrency_token) VALUES ('{0}', gen_random_uuid(), '{1}', 'access_token', 'valid', gen_random_uuid())")]
    public async Task No_secret_authorization_or_token_may_name_the_system_Application(string table, string setup, string insert)
    {
        var database = await DatabaseAsync();
        var id = await EnsureAsync(database, TenantA);
        var superuser = postgres.SuperuserConnection(database);
        if (setup.Length > 0)
        {
            await PostgresFixture.ExecuteAsync(superuser, string.Format(System.Globalization.CultureInfo.InvariantCulture, setup, TenantA));
        }

        var error = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            superuser, string.Format(System.Globalization.CultureInfo.InvariantCulture, insert, TenantA, id)));

        Assert.True(error.SqlState == SystemApplicationNamed, $"{table}: {error.SqlState}");
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM \"{table}\""));
    }

    /// <summary>
    /// No update may point an <c>"authorization"</c> or <c>token</c> row at the system Application. From
    /// Story 2.9 Host.Hosted can't update either's <c>application_id</c> at all; the guard still refuses
    /// any role that can.
    /// </summary>
    [Theory]
    [InlineData("authorization", SessionIn, "INSERT INTO \"authorization\" (tenant_id, id, application_id, user_session_id, status, type, concurrency_token) VALUES ('{0}', '01900000-0000-7000-8000-0000000028b1', '{1}', '01900000-0000-7000-8000-0000000028a2', 'valid', 'ad-hoc', gen_random_uuid())")]
    [InlineData("token", "", "INSERT INTO token (tenant_id, id, application_id, type, status, concurrency_token) VALUES ('{0}', '01900000-0000-7000-8000-0000000028b1', '{1}', 'access_token', 'valid', gen_random_uuid())")]
    public async Task No_update_may_point_an_authorization_or_token_at_the_system_Application(string table, string setup, string insert)
    {
        var database = await DatabaseAsync();
        var machine = await CreateAsync(database, TenantA);
        var id = await EnsureAsync(database, TenantA);
        var superuser = postgres.SuperuserConnection(database);
        if (setup.Length > 0)
        {
            await PostgresFixture.ExecuteAsync(superuser, string.Format(System.Globalization.CultureInfo.InvariantCulture, setup, TenantA));
        }

        await PostgresFixture.ExecuteAsync(superuser, string.Format(System.Globalization.CultureInfo.InvariantCulture, insert, TenantA, machine.ApplicationId));

        var update = $"UPDATE \"{table}\" SET application_id = '{id}' WHERE id = '01900000-0000-7000-8000-0000000028b1'";
        var refused = await Assert.ThrowsAsync<PostgresException>(() => InTenantAsync(database, TableRegistry.Hosted, TenantA, async c =>
        {
            await using var command = c.CreateCommand();
            command.CommandText = update;
            return await command.ExecuteNonQueryAsync(Cancellation);
        }));
        Assert.True(refused.SqlState == PermissionDenied, $"{table}: {refused.SqlState}");

        var error = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(superuser, update));

        Assert.True(error.SqlState == SystemApplicationNamed, $"{table}: {error.SqlState}");
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(
            superuser, $"SELECT count(*) FROM \"{table}\" WHERE application_id = '{machine.ApplicationId}'"));
    }

    [Fact]
    public async Task A_signin_transaction_binds_to_the_system_Application()
    {
        var database = await DatabaseAsync();
        var id = await EnsureAsync(database, TenantA);

        var inserted = await InTenantAsync(database, TableRegistry.Hosted, TenantA, async c =>
        {
            await using var command = c.CreateCommand();
            command.CommandText =
                "INSERT INTO signin_transaction (tenant_id, id, application_id, binding_hash, parameters, created_at, expires_at) " +
                $"VALUES ('{TenantA}', gen_random_uuid(), '{id}', sha256(gen_random_uuid()::text::bytea), '{{}}', now(), now() + interval '1 minute')";
            return await command.ExecuteNonQueryAsync(Cancellation);
        });

        Assert.Equal(1, inserted);
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(
            postgres.SuperuserConnection(database), $"SELECT count(*) FROM signin_transaction WHERE application_id = '{id}'"));
    }

    [Theory]
    [InlineData("UPDATE application SET name = 'Renamed' WHERE kind = 'system'")]
    [InlineData("UPDATE application SET created_at = now() WHERE kind = 'system'")]
    [InlineData("UPDATE application SET kind = 'system' WHERE kind = 'machine'")]
    public async Task The_system_Application_is_never_edited_even_by_the_superuser(string statement)
    {
        var database = await DatabaseAsync();
        await CreateAsync(database, TenantB);
        await EnsureAsync(database, TenantA);
        var superuser = postgres.SuperuserConnection(database);
        const string Rows = "SELECT string_agg(to_jsonb(r)::text, ',' ORDER BY id) FROM application r";
        var before = await PostgresFixture.ScalarAsync<string>(superuser, Rows);

        var error = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(superuser, statement));

        Assert.Equal(SystemApplicationEdited, error.SqlState);
        Assert.Equal(before, await PostgresFixture.ScalarAsync<string>(superuser, Rows));
    }

    [Theory]
    [InlineData(TableRegistry.Hosted)]
    [InlineData(TableRegistry.Admin)]
    [InlineData(TableRegistry.Worker)]
    public async Task No_role_may_update_the_system_Application(string role)
    {
        var database = await DatabaseAsync();
        await EnsureAsync(database, TenantA);
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(role, database));
        await using var scope = await TenantScope.BeginAsync(source, TenantA, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = "UPDATE application SET name = 'Renamed'";

        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));
        Assert.Equal(PermissionDenied, error.SqlState);
    }

    [Fact]
    public async Task Only_its_Tenants_deletion_deletes_the_system_Application()
    {
        var database = await DatabaseAsync();
        await EnsureAsync(database, TenantA);
        var superuser = postgres.SuperuserConnection(database);

        var error = await Assert.ThrowsAsync<PostgresException>(() => InTenantAsync(database, TableRegistry.Worker, TenantA, async c =>
        {
            await using var command = c.CreateCommand();
            command.CommandText = $"DELETE FROM application WHERE tenant_id = '{TenantA}'";
            return await command.ExecuteNonQueryAsync(Cancellation);
        }));
        Assert.Equal(SystemApplicationDeleted, error.SqlState);
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM application WHERE tenant_id = '{TenantA}'"));

        // Once its deletion has started, Directory's purge deletes it.
        await PostgresFixture.ExecuteAsync(
            superuser,
            $"SET session_replication_role = replica; UPDATE tenant SET status = 'deleting' WHERE id = '{TenantA}'; SET session_replication_role = DEFAULT");
        await InTenantAsync(database, TableRegistry.Worker, TenantA, async c =>
        {
            await DirectoryContract.TenantPurge.PurgeAsync(c, Cancellation);
            return 0;
        });
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM application WHERE tenant_id = '{TenantA}'"));
    }

    [Fact]
    public async Task Another_Tenant_can_neither_see_nor_find_the_system_Application()
    {
        var database = await DatabaseAsync();
        var id = await EnsureAsync(database, TenantA);

        Assert.Null(await InTenantAsync(database, TableRegistry.Hosted, TenantB, c => _directory.FindSystemApplicationAsync(c, Cancellation)));
        Assert.Empty(await InTenantAsync(database, TableRegistry.Hosted, TenantB, c => _directory.ListApplicationsAsync(c, Cancellation)));
        Assert.Equal(0L, await InTenantAsync(database, TableRegistry.Worker, TenantB, async c =>
        {
            await using var command = c.CreateCommand();
            command.CommandText = $"SELECT count(*) FROM application WHERE id = '{id}' OR kind = 'system'";
            return (long)(await command.ExecuteScalarAsync(Cancellation))!;
        }));

        // Tenant B's own is another row, and A's is unchanged.
        var other = await EnsureAsync(database, TenantB);
        Assert.NotEqual(id, other);
        Assert.Equal(id, await EnsureAsync(database, TenantA));
    }

    /// <summary>
    /// The migration's backfill, rendered through the same <c>ForEachTenant</c> the migration calls and run as
    /// the migrator over Tenants seeded after migrating: no hook migrates only up to the migration before it.
    /// </summary>
    [Fact]
    public async Task Backfill_gives_each_creating_or_active_Tenant_without_one_exactly_one_system_Application()
    {
        var database = await DatabaseAsync();
        var superuser = postgres.SuperuserConnection(database);
        await TestTenants.InsertAsync(superuser, TenantC, status: "deleting");
        await TestTenants.InsertAsync(superuser, TenantD, status: "creating");
        var existing = await EnsureAsync(database, TenantA);

        var builder = new MigrationBuilder("Npgsql.EntityFrameworkCore.PostgreSQL");
        builder.ForEachTenant(Migration20261109000000AddSystemApplication.Backfill);
        var sql = Assert.IsType<SqlOperation>(Assert.Single(builder.Operations)).Sql;

        // The migration's Up() runs exactly that statement, last.
        var migration = new Migration20261109000000AddSystemApplication { ActiveProvider = "Npgsql.EntityFrameworkCore.PostgreSQL" };
        Assert.Equal(sql, Assert.IsType<SqlOperation>(migration.UpOperations[^1]).Sql);

        await PostgresFixture.ExecuteAsync(postgres.RoleConnection(TableRegistry.Migrator, database), sql);
        await PostgresFixture.ExecuteAsync(postgres.RoleConnection(TableRegistry.Migrator, database), sql);

        Assert.Equal(existing, await PostgresFixture.ScalarAsync<Guid>(superuser, $"SELECT id FROM application WHERE tenant_id = '{TenantA}' AND kind = 'system'"));
        Assert.Equal(1L, await CountAsync(
            superuser,
            $"SELECT count(*) FROM application WHERE tenant_id = '{TenantB}' AND kind = 'system' AND name = @name AND grant_types = '{{}}' AND audiences = '{{}}'",
            ("name", DirectoryContract.SystemApplicationName)));
        Assert.Equal(7, (await PostgresFixture.ScalarAsync<Guid>(superuser, $"SELECT id FROM application WHERE tenant_id = '{TenantB}' AND kind = 'system'")).Version);
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM application WHERE tenant_id = '{TenantC}'"));
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM application WHERE tenant_id = '{TenantD}' AND kind = 'system'"));
        Assert.Equal(3L, await PostgresFixture.ScalarAsync<long>(superuser, "SELECT count(*) FROM application"));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, "SELECT count(*) FROM audit_event"));
    }

    /// <summary>
    /// Story 2.10's backfill, rendered the same way and run as the migrator: a Story 2.9 web client allowed
    /// only the code grant gains the refresh grant, and nothing else changes.
    /// </summary>
    [Fact]
    public async Task Refresh_backfill_gives_each_code_only_web_client_the_refresh_grant_and_nothing_else()
    {
        var database = await DatabaseAsync();
        var superuser = postgres.SuperuserConnection(database);
        var machine = await CreateAsync(database, TenantA);
        var webA = await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.CreateWebClientAsync(c, "Web A", ["https://a.example/cb"], Cancellation));
        var webB = await InTenantAsync(database, TableRegistry.Admin, TenantB, c => _directory.CreateWebClientAsync(c, "Web B", ["https://b.example/cb"], Cancellation));
        var refreshing = await InTenantAsync(database, TableRegistry.Admin, TenantB, c => _directory.CreateWebClientAsync(c, "Web B2", ["https://b.example/cb2"], Cancellation));
        await PostgresFixture.ExecuteAsync(superuser,
            $"UPDATE application SET grant_types = ARRAY['authorization_code'] WHERE id IN ('{webA.ApplicationId}', '{webB.ApplicationId}')");

        var builder = new MigrationBuilder("Npgsql.EntityFrameworkCore.PostgreSQL");
        builder.ForEachTenant(Migration20261111000000AllowRefreshTokens.Backfill);
        var sql = Assert.IsType<SqlOperation>(Assert.Single(builder.Operations)).Sql;

        // The migration's Up() runs exactly that statement, last.
        var migration = new Migration20261111000000AllowRefreshTokens { ActiveProvider = "Npgsql.EntityFrameworkCore.PostgreSQL" };
        Assert.Equal(sql, Assert.IsType<SqlOperation>(migration.UpOperations[^1]).Sql);

        await PostgresFixture.ExecuteAsync(postgres.RoleConnection(TableRegistry.Migrator, database), sql);
        await PostgresFixture.ExecuteAsync(postgres.RoleConnection(TableRegistry.Migrator, database), sql);

        Assert.Equal(3L, await PostgresFixture.ScalarAsync<long>(superuser,
            $"SELECT count(*) FROM application WHERE id IN ('{webA.ApplicationId}', '{webB.ApplicationId}', '{refreshing.ApplicationId}') AND grant_types = ARRAY['authorization_code', 'refresh_token']"));
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser,
            $"SELECT count(*) FROM application WHERE id = '{machine.ApplicationId}' AND grant_types = ARRAY['client_credentials']"));
    }

    // Story 3.2 (FR-11, FR-13): an Application's settings, by the type table.

    [Theory]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, grant_types, redirect_uris, post_logout_redirect_uris, web_origins, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'spa', ARRAY['authorization_code', 'refresh_token'], ARRAY['https://app.test/cb'], ARRAY['https://app.test/'], ARRAY['https://app.test'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, grant_types, redirect_uris, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'native', ARRAY['authorization_code'], ARRAY['com.example.app:/cb', 'http://127.0.0.1/cb'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, redirect_uris, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'web', ARRAY['https://app.test/cb'], now())")]
    [InlineData("INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{0}', gen_random_uuid(), 'x', 'machine', now())")]
    public async Task The_type_table_allows_each_types_own_settings(string statement)
    {
        var database = await DatabaseAsync();

        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database), string.Format(System.Globalization.CultureInfo.InvariantCulture, statement, TenantA));

        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM application"));
    }

    public static TheoryData<string, string[], string[], string[], string[], string> SettingsProblems => new()
    {
        // kind, callbacks, logouts, origins, grants, then the problems as "field index reason", joined by "; ".
        { "web", ["https://app.example/cb", "http://127.0.0.1:8080/cb", "http://[::1]/cb?x=1"], ["https://app.example/"], ["https://app.example", "http://127.0.0.1:3000"], ["refresh_token", "authorization_code"], "" },
        { "spa", [], [], [], [], "" },
        { "native", ["com.example.app:/callback", "http://127.0.0.1/cb"], ["com.example.app:/logout"], [], ["authorization_code"], "" },
        { "machine", [], [], [], ["client_credentials"], "" },
        { "machine", [], [], [], [], "" },
        { "web", ["https://*.a.example/cb", "/cb", "http://a.example/cb", "https://a.example/cb#x"], [], [], [], "callbackUrls 0 wildcard; callbackUrls 1 not_absolute; callbackUrls 2 scheme_not_allowed; callbackUrls 3 not_absolute" },
        { "web", ["https://user@a.example/cb", "http://localhost/cb", "https://a.example/a b", "", "https://a.example/cb", "https://a.example/cb"], [], [], [], "callbackUrls 0 not_absolute; callbackUrls 1 scheme_not_allowed; callbackUrls 2 not_absolute; callbackUrls 3 not_absolute; callbackUrls 5 duplicate" },
        // Loopback by its literal spelling only: these parse to 127.0.0.1 but aren't what is stored and matched.
        { "native", ["http://127.1/cb", "http://2130706433/cb", "http://0177.0.0.1/cb", "http://127.0.0.10/cb", "http://127.0.0.1:51004/cb"], [], [], [], "callbackUrls 0 scheme_not_allowed; callbackUrls 1 scheme_not_allowed; callbackUrls 2 scheme_not_allowed; callbackUrls 3 scheme_not_allowed" },
        { "spa", [.. Enumerable.Range(0, 11).Select(i => $"https://a.example/{i}")], [], [], [], "callbackUrls - too_many" },
        { "spa", ["https://a.example/" + new string('x', 1983)], [], [], [], "callbackUrls 0 too_long" },
        { "spa", ["https://a.example/" + new string('x', 1982)], [], [], [], "" },
        { "spa", ["com.example.app:/cb"], ["javascript:alert(1)"], [], [], "callbackUrls 0 scheme_not_allowed; logoutUrls 0 scheme_not_allowed" },
        { "native", ["javascript:alert(1)", "data.x:/y", "file:///etc", "myapp:/cb"], [], [], [], "callbackUrls 0 scheme_not_allowed; callbackUrls 2 scheme_not_allowed; callbackUrls 3 scheme_not_allowed" },
        { "spa", [], [], ["https://a.example/", "https://a.example?x", "https://a.example:8443", "com.example.app://x"], [], "webOrigins 0 not_absolute; webOrigins 1 not_absolute; webOrigins 3 scheme_not_allowed" },
        { "native", [], [], ["https://a.example"], [], "webOrigins - not_allowed_for_type" },
        { "machine", ["https://a.example/cb"], ["https://a.example/"], ["https://a.example"], [], "callbackUrls - not_allowed_for_type; logoutUrls - not_allowed_for_type; webOrigins - not_allowed_for_type" },
        { "machine", [], [], [], ["authorization_code"], "grantTypes - not_allowed_for_type" },
        { "web", [], [], [], ["client_credentials"], "grantTypes - not_allowed_for_type" },
        { "spa", [], [], [], ["refresh_token"], "grantTypes - not_allowed_for_type" },
        { "spa", [], [], [], ["authorization_code", "authorization_code"], "grantTypes - not_allowed_for_type" },
        { "spa", [], [], [], ["password"], "grantTypes - not_allowed_for_type" },
    };

    [Theory]
    [MemberData(nameof(SettingsProblems))]
    public void The_settings_rules_name_each_refused_line(string kind, string[] callbacks, string[] logouts, string[] origins, string[] grants, string expected)
    {
        var problems = DirectoryContract.CheckSettings(kind, new ApplicationSettings(callbacks, logouts, origins, grants));

        Assert.Equal(
            expected,
            string.Join("; ", problems.Select(p => $"{p.Field} {p.Index?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "-"} {p.Reason}")));
    }

    [Fact]
    public async Task Saving_settings_writes_the_lists_as_given_the_grants_sorted_and_its_events()
    {
        var database = await DatabaseAsync();
        var actor = Gatekeep.Kernel.Audit.Actor.Admin(Guid.CreateVersion7());
        var settings = new ApplicationSettings(
            ["https://app.example/cb", "http://127.0.0.1:8080/cb"], ["https://app.example/"], ["https://app.example"], ["refresh_token", "authorization_code"]);

        var created = await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.CreateApplicationAsync(c, actor, "Web", "web", Cancellation));
        var updated = await InTenantAsync(database, TableRegistry.Admin, TenantA, c =>
            _directory.UpdateApplicationSettingsAsync(c, actor, created.Id, settings, prodCallbackAdded: true, Cancellation));

        Assert.NotNull(updated);
        Assert.Equal(["https://app.example/cb", "http://127.0.0.1:8080/cb"], updated.RedirectUris);
        Assert.Equal(["https://app.example/"], updated.PostLogoutRedirectUris);
        Assert.Equal(["https://app.example"], updated.WebOrigins);
        Assert.Equal(["authorization_code", "refresh_token"], updated.GrantTypes);
        var superuser = postgres.SuperuserConnection(database);
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser,
            $"SELECT count(*) FROM application WHERE id = '{created.Id}' AND grant_types = ARRAY['authorization_code', 'refresh_token'] AND redirect_uris = ARRAY['https://app.example/cb', 'http://127.0.0.1:8080/cb'] AND post_logout_redirect_uris = ARRAY['https://app.example/'] AND web_origins = ARRAY['https://app.example']"));
        foreach (var code in new[] { "directory.application.updated", "directory.application.prod_callback_added" })
        {
            Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser,
                $"SELECT count(*) FROM audit_event WHERE type_code = '{code}' AND actor_kind = 'admin' AND target_kind = 'client' AND target_id = '{created.Id}'"));
        }

        // Nothing of a URL reaches the Log.
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, "SELECT count(*) FROM audit_event r WHERE strpos(to_jsonb(r)::text, 'app.example') > 0"));
    }

    [Fact]
    public async Task Settings_that_break_the_type_table_or_name_the_system_Application_write_nothing()
    {
        var database = await DatabaseAsync();
        var actor = Gatekeep.Kernel.Audit.Actor.Admin(Guid.CreateVersion7());
        var system = await EnsureAsync(database, TenantA);
        var machine = await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.CreateApplicationAsync(c, actor, "Job", "machine", Cancellation));
        var urls = new ApplicationSettings(["https://app.example/cb"], [], [], []);

        await Assert.ThrowsAsync<ArgumentException>(() => InTenantAsync(database, TableRegistry.Admin, TenantA, c =>
            _directory.UpdateApplicationSettingsAsync(c, actor, machine.Id, urls, prodCallbackAdded: false, Cancellation)));
        Assert.Null(await InTenantAsync(database, TableRegistry.Admin, TenantA, c =>
            _directory.UpdateApplicationSettingsAsync(c, actor, system, urls, prodCallbackAdded: false, Cancellation)));

        // Another Tenant's Application is no Application here.
        Assert.Null(await InTenantAsync(database, TableRegistry.Admin, TenantB, c =>
            _directory.UpdateApplicationSettingsAsync(c, actor, machine.Id, new ApplicationSettings([], [], [], []), prodCallbackAdded: false, Cancellation)));

        var superuser = postgres.SuperuserConnection(database);
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, "SELECT count(*) FROM application WHERE redirect_uris <> '{}'"));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, "SELECT count(*) FROM audit_event WHERE type_code = 'directory.application.updated'"));
    }

    [Theory]
    [InlineData("spa", "public", "web")]
    [InlineData("native", "public", "native")]
    [InlineData("web", "confidential", "web")]
    public async Task The_store_hands_OpenIddict_each_types_client_type_permissions_and_URLs(string kind, string clientType, string applicationType)
    {
        var database = await DatabaseAsync();
        var actor = Gatekeep.Kernel.Audit.Actor.Admin(Guid.CreateVersion7());
        var created = await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.CreateApplicationAsync(c, actor, "App", kind, Cancellation));

        async Task<DirectoryApplication> ReadAsync()
        {
            await using var hosted = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Hosted, database));
            await using var read = await TenantScope.BeginAsync(hosted, TenantA, Cancellation);
            var context = read.CreateCommandContext();
            return (await DirectoryContract.CreateApplicationStore(() => context).FindByClientIdAsync(created.ClientId, Cancellation))!;
        }

        var store = DirectoryContract.CreateApplicationStore(() => throw new InvalidOperationException("Only the getters run."));

        // With no grant, a code-flow kind may not use the authorization endpoint.
        var bare = await ReadAsync();
        Assert.Equal(clientType, await store.GetClientTypeAsync(bare, Cancellation));
        Assert.Equal(applicationType, await store.GetApplicationTypeAsync(bare, Cancellation));
        Assert.DoesNotContain("ept:authorization", await store.GetPermissionsAsync(bare, Cancellation));
        Assert.Equal(["ft:pkce"], await store.GetRequirementsAsync(bare, Cancellation));

        await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.UpdateApplicationSettingsAsync(
            c, actor, created.Id, new ApplicationSettings(["https://app.example/cb"], ["https://app.example/"], [], ["authorization_code", "refresh_token"]), false, Cancellation));
        var configured = await ReadAsync();
        Assert.Equal(
            ["ept:authorization", "ept:revocation", "ept:token", "gt:authorization_code", "gt:refresh_token", "rst:code"],
            (await store.GetPermissionsAsync(configured, Cancellation)).Order(StringComparer.Ordinal));
        Assert.Equal(["https://app.example/cb"], await store.GetRedirectUrisAsync(configured, Cancellation));
        Assert.Equal(["https://app.example/"], await store.GetPostLogoutRedirectUrisAsync(configured, Cancellation));
    }

    [Fact]
    public async Task Only_a_native_Applications_loopback_redirect_may_differ_in_port()
    {
        var database = await DatabaseAsync();
        var actor = Gatekeep.Kernel.Audit.Actor.Admin(Guid.CreateVersion7());
        var settings = new ApplicationSettings(
            ["http://127.0.0.1/cb", "http://[::1]:8080/cb?x=1", "https://app.example/cb"], [], [], ["authorization_code"]);

        async Task<DirectoryApplication> WithSettingsAsync(string kind)
        {
            var created = await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.CreateApplicationAsync(c, actor, kind, kind, Cancellation));
            return (await InTenantAsync(database, TableRegistry.Admin, TenantA, c =>
                _directory.UpdateApplicationSettingsAsync(c, actor, created.Id, settings, prodCallbackAdded: false, Cancellation)))!;
        }

        var native = await WithSettingsAsync("native");
        var web = await WithSettingsAsync("web");
        var spa = await WithSettingsAsync("spa");

        foreach (var exact in settings.CallbackUrls)
        {
            Assert.True(DirectoryContract.MatchesRedirectUri(native, exact));
            Assert.True(DirectoryContract.MatchesRedirectUri(web, exact));
        }

        foreach (var port in new[] { "http://127.0.0.1:51004/cb", "http://[::1]/cb?x=1", "http://[::1]:1/cb?x=1", "http://127.0.0.1:65535/cb" })
        {
            Assert.True(DirectoryContract.MatchesRedirectUri(native, port), port);
            Assert.False(DirectoryContract.MatchesRedirectUri(web, port), port);
            Assert.False(DirectoryContract.MatchesRedirectUri(spa, port), port);
        }

        foreach (var other in new[]
        {
            "http://localhost:51004/cb", "http://127.0.0.1:51004/cb/", "http://127.0.0.1:51004/CB", "http://127.0.0.1:0/cb",
            "http://127.0.0.1:65536/cb", "http://127.0.0.1:/cb", "http://127.0.0.1:80@evil.example/cb", "http://127.0.0.1.evil.example/cb",
            "https://127.0.0.1:51004/cb", "https://app.example:443/cb", "http://[::1]:8080/cb", "http://127.0.0.1:51004/cb#x",
        })
        {
            Assert.False(DirectoryContract.MatchesRedirectUri(native, other), other);
        }
    }

    private async Task<Guid> EnsureAsync(string database, Guid tenantId) =>
        await InTenantAsync(database, TableRegistry.Worker, tenantId, c => _directory.EnsureSystemApplicationAsync(c, Cancellation));

    private async Task<T> InTenantAsync<T>(string database, string role, Guid tenantId, Func<CommandContext, Task<T>> body)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(role, database));
        await using var scope = await TenantScope.BeginAsync(source, tenantId, Cancellation);
        var result = await body(scope.CreateCommandContext());
        await scope.CommitAsync(Cancellation);
        return result;
    }

    private async Task<string> DatabaseAsync()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), TestTenants.InsertSql(TenantA, TenantB));
        return database;
    }

    private async Task<CreatedMachineClient> CreateAsync(string database, Guid tenantId, string name = "Machine client")
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using var scope = await TenantScope.BeginAsync(source, tenantId, Cancellation);
        var created = await _directory.CreateMachineClientAsync(scope.CreateCommandContext(), name, Cancellation);
        await scope.CommitAsync(Cancellation);
        return created;
    }

    private async Task<bool> VerifyAsync(string database, Guid tenantId, string clientId, Secret<string> secret)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Hosted, database));
        await using var scope = await TenantScope.BeginAsync(source, tenantId, Cancellation);
        return await _directory.VerifyClientSecretAsync(scope.CreateCommandContext(), clientId, secret, Cancellation);
    }

    private static async Task<long> CountAsync(string connection, string sql, params (string Name, object Value)[] parameters)
    {
        await using var npgsql = new NpgsqlConnection(connection);
        await npgsql.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand(sql, npgsql);
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value);
        }

        return (long)(await command.ExecuteScalarAsync(Cancellation))!;
    }
}
