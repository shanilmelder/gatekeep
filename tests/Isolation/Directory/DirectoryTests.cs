using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Applications;

/// <summary>
/// Story 2.5 (AD-8, AD-9, AD-24, AD-27): Directory's Applications and client secrets. A machine client
/// is created in one command with its event, its secret is <c>{tenantPublicId}.{random}</c> shown once
/// and stored only as its SHA-256, and only a live secret of that Application, in that Tenant, verifies.
/// The tables hold every role to its grants and every Tenant to its own rows.
/// </summary>
public sealed class DirectoryTests(PostgresFixture postgres)
{
    private const string PermissionDenied = "42501";

    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-0000000025d1");
    private static readonly Guid TenantB = Guid.Parse("01900000-0000-7000-8000-0000000025d2");

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
        { TableRegistry.Admin, "UPDATE client_secret SET expires_at = NULL" },
        { TableRegistry.Admin, "DELETE FROM application" },
        { TableRegistry.Worker, "SELECT name FROM application" },
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
