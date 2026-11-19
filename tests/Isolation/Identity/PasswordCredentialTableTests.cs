using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Identity;

/// <summary>
/// Story 4.7: the tables sign-up writes hold every role to its grants. Host.Hosted inserts a User with only its ID, email
/// and creation time and sets only when it was verified; it keeps credentials and links, changing only a credential's
/// status, hash and update time and a link's use. Host.Worker reads only what its purges name, never a hash. Host.Admin
/// reaches none of them. Row-level security keeps each Tenant to its own rows, and one User holds one active password.
/// </summary>
public sealed class PasswordCredentialTableTests(PostgresFixture postgres)
{
    private const string PermissionDenied = "42501";

    private const string UniqueViolation = "23505";

    private const string ForeignKeyViolation = "23503";

    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-0000000047a1");
    private static readonly Guid TenantB = Guid.Parse("01900000-0000-7000-8000-0000000047a2");
    private static readonly Guid UserA = Guid.Parse("01900000-0000-7000-8000-0000000047b1");
    private static readonly Guid CredentialA = Guid.Parse("01900000-0000-7000-8000-0000000047c1");

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    /// <summary>What no role may do to a User, a credential or a link, by role.</summary>
    public static TheoryData<string, string> Refusals => new()
    {
        { TableRegistry.Hosted, "UPDATE \"user\" SET email = 'x@example.com'" },
        { TableRegistry.Hosted, "DELETE FROM \"user\"" },
        { TableRegistry.Hosted, $"INSERT INTO \"user\" (tenant_id, id, email, email_verified_at) VALUES ('{TenantA}', gen_random_uuid(), 'v@example.com', now())" },
        { TableRegistry.Hosted, "UPDATE password_credential SET user_id = gen_random_uuid()" },
        { TableRegistry.Hosted, "UPDATE password_credential SET connection_id = gen_random_uuid()" },
        { TableRegistry.Hosted, "UPDATE one_time_token SET token_hash = sha256('x')" },
        { TableRegistry.Hosted, "UPDATE one_time_token SET expires_at = now()" },
        { TableRegistry.Hosted, "UPDATE one_time_token SET credential_id = gen_random_uuid()" },
        { TableRegistry.Admin, "SELECT count(*) FROM password_credential" },
        { TableRegistry.Admin, "SELECT count(*) FROM one_time_token" },
        { TableRegistry.Admin, "UPDATE \"user\" SET email_verified_at = now()" },
        { TableRegistry.Worker, "SELECT password_hash FROM password_credential" },
        { TableRegistry.Worker, "SELECT token_hash FROM one_time_token" },
        { TableRegistry.Worker, "SELECT user_id FROM one_time_token" },
        { TableRegistry.Worker, "UPDATE password_credential SET status = 'active'" },
        { TableRegistry.Worker, "UPDATE one_time_token SET used_at = now()" },
        { TableRegistry.Worker, "UPDATE \"user\" SET email_verified_at = now()" },
    };

    [Theory]
    [MemberData(nameof(Refusals))]
    public async Task Each_role_is_held_to_its_grants(string role, string sql)
    {
        var database = await DatabaseAsync();

        await using var connection = new NpgsqlConnection(postgres.RoleConnection(role, database));
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand($"SELECT set_config('gatekeep.tenant_id', '{TenantA}', false); {sql}", connection);
        var refused = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));
        Assert.Equal(PermissionDenied, refused.SqlState);
    }

    [Fact]
    public async Task Host_Hosted_writes_what_sign_up_needs_in_its_own_Tenant_only()
    {
        var database = await DatabaseAsync();
        var superuser = postgres.SuperuserConnection(database);

        await InTenantAsync(database, TableRegistry.Hosted, TenantA, async c =>
        {
            var user = Guid.CreateVersion7();
            var credential = Guid.CreateVersion7();
            await ExecuteAsync(c, $"INSERT INTO \"user\" (tenant_id, id, email, created_at) VALUES ('{TenantA}', '{user}', 'new@example.com', now())");
            await ExecuteAsync(c, $"UPDATE \"user\" SET email_verified_at = now() WHERE id = '{user}'");
            await ExecuteAsync(
                c,
                $"INSERT INTO password_credential (tenant_id, id, user_id, connection_id, password_hash, status) VALUES ('{TenantA}', '{credential}', '{user}', gen_random_uuid(), '$argon2id$x', 'pending')");
            await ExecuteAsync(
                c,
                $"INSERT INTO one_time_token (tenant_id, id, user_id, credential_id, purpose, token_hash, expires_at) VALUES ('{TenantA}', gen_random_uuid(), '{user}', '{credential}', 'email_verification', sha256('b'), now() + interval '1 day')");
            await ExecuteAsync(c, $"UPDATE one_time_token SET used_at = now() WHERE credential_id = '{credential}'");
            await ExecuteAsync(c, $"UPDATE password_credential SET status = 'active', updated_at = now() WHERE id = '{credential}'");
            return 0;
        });

        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM password_credential WHERE tenant_id = '{TenantA}' AND status = 'active'"));
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM one_time_token WHERE tenant_id = '{TenantA}' AND used_at IS NOT NULL"));

        // Row-level security: Tenant B's scope sees none of A's rows, and can't write one naming A.
        Assert.Equal(0L, await InTenantAsync(database, TableRegistry.Hosted, TenantB, c => CountAsync(c, "SELECT count(*) FROM password_credential")));
        Assert.Equal(0L, await InTenantAsync(database, TableRegistry.Hosted, TenantB, c => CountAsync(c, "SELECT count(*) FROM one_time_token")));
        await Assert.ThrowsAsync<PostgresException>(() => InTenantAsync(database, TableRegistry.Hosted, TenantB, c => ExecuteAsync(
            c,
            $"INSERT INTO password_credential (tenant_id, id, user_id, connection_id, password_hash, status) VALUES ('{TenantA}', gen_random_uuid(), '{UserA}', gen_random_uuid(), '$argon2id$x', 'pending')")));
    }

    [Fact]
    public async Task A_User_holds_one_active_password_and_a_credential_goes_only_after_its_links()
    {
        var database = await DatabaseAsync();
        var superuser = postgres.SuperuserConnection(database);
        await PostgresFixture.ExecuteAsync(
            superuser,
            $"INSERT INTO password_credential (tenant_id, id, user_id, connection_id, password_hash, status) VALUES ('{TenantA}', gen_random_uuid(), '{UserA}', gen_random_uuid(), '$argon2id$x', 'active')");

        var second = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            superuser,
            $"INSERT INTO password_credential (tenant_id, id, user_id, connection_id, password_hash, status) VALUES ('{TenantA}', gen_random_uuid(), '{UserA}', gen_random_uuid(), '$argon2id$y', 'active')"));
        Assert.Equal(UniqueViolation, second.SqlState);

        // A credential with a link can't be deleted before it (ON DELETE RESTRICT); with its links gone first, it can.
        var restricted = await Assert.ThrowsAsync<PostgresException>(() => InTenantAsync(
            database, TableRegistry.Hosted, TenantA, c => ExecuteAsync(c, $"DELETE FROM password_credential WHERE id = '{CredentialA}'")));
        Assert.Equal(ForeignKeyViolation, restricted.SqlState);
        await InTenantAsync(database, TableRegistry.Hosted, TenantA, async c =>
            await ExecuteAsync(c, $"DELETE FROM one_time_token WHERE credential_id = '{CredentialA}'")
            + await ExecuteAsync(c, $"DELETE FROM password_credential WHERE id = '{CredentialA}'"));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM password_credential WHERE id = '{CredentialA}'"));
    }

    [Fact]
    public async Task Host_Worker_purges_by_tenant_and_by_expiry_reading_neither_hash()
    {
        var database = await DatabaseAsync();
        var superuser = postgres.SuperuserConnection(database);
        await PostgresFixture.ExecuteAsync(
            superuser,
            $"INSERT INTO one_time_token (tenant_id, id, user_id, credential_id, purpose, token_hash, expires_at) VALUES ('{TenantA}', gen_random_uuid(), '{UserA}', '{CredentialA}', 'email_verification', sha256('old'), now() - interval '2 hours'), "
            + $"('{TenantA}', gen_random_uuid(), '{UserA}', '{CredentialA}', 'email_verification', sha256('recent'), now() - interval '30 minutes')");

        var deleted = await InTenantAsync(
            database, TableRegistry.Worker, TenantA, c => PurgeExpiredAsync(c));

        Assert.Equal(1, deleted);
        // The unexpired link stays, and so does one only 30 minutes past its expiry: the retention is an hour.
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM one_time_token WHERE tenant_id = '{TenantA}' AND token_hash = sha256('a')"));
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM one_time_token WHERE tenant_id = '{TenantA}' AND token_hash = sha256('recent')"));
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM password_credential WHERE id = '{CredentialA}'"));
        Assert.Equal(0, await InTenantAsync(
            database, TableRegistry.Worker, TenantA, c => PurgeExpiredAsync(c)));
    }

    [Fact]
    public async Task The_purge_removes_an_abandoned_sign_up_once_its_links_are_gone()
    {
        var database = await DatabaseAsync();
        var superuser = postgres.SuperuserConnection(database);
        var kept = Guid.CreateVersion7();
        var named = Guid.CreateVersion7();
        var noEmail = Guid.CreateVersion7();
        var application = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(
            superuser,
            // A's only link is long expired, so its pending credential and then its User go.
            $"UPDATE one_time_token SET expires_at = now() - interval '2 hours' WHERE tenant_id = '{TenantA}'; "
            // A verified User with no credential, an unverified one a transaction names, and one with no email all stay.
            + $"INSERT INTO \"user\" (tenant_id, id, email, email_verified_at) VALUES ('{TenantA}', '{kept}', 'kept@example.com', now()); "
            + $"INSERT INTO \"user\" (tenant_id, id, email) VALUES ('{TenantA}', '{named}', 'named@example.com'); "
            + $"INSERT INTO \"user\" (tenant_id, id) VALUES ('{TenantA}', '{noEmail}'); "
            + "SET session_replication_role = replica; "
            + TestTenants.ApplicationSql(TenantA, application) + "; "
            + "INSERT INTO signin_transaction (tenant_id, id, application_id, binding_hash, parameters, created_at, expires_at, signup_user_id) "
            + $"VALUES ('{TenantA}', gen_random_uuid(), '{application}', sha256('txn'), '{{}}', now(), now() + interval '10 minutes', '{named}'); "
            + "SET session_replication_role = DEFAULT");

        var deleted = await InTenantAsync(database, TableRegistry.Worker, TenantA, c => PurgeExpiredAsync(c));

        Assert.Equal(3, deleted);
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM password_credential WHERE id = '{CredentialA}'"));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM \"user\" WHERE id = '{UserA}'"));
        Assert.Equal(3L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM \"user\" WHERE tenant_id = '{TenantA}'"));
        Assert.Equal(0, await InTenantAsync(database, TableRegistry.Worker, TenantA, c => PurgeExpiredAsync(c)));
    }

    /// <summary>Identity's expired-state purge (Story 4.7), by reflection: this project reaches Identity only through other modules.</summary>
    private static Task<int> PurgeExpiredAsync(CommandContext context) =>
        (Task<int>)Type.GetType("Gatekeep.Modules.Identity.Contracts.IdentityContract, Gatekeep.Modules.Identity", throwOnError: true)!
            .GetMethod("PurgeExpiredStateAsync")!
            .Invoke(null, [context, DateTimeOffset.UtcNow, Cancellation])!;

    private static async Task<int> ExecuteAsync(CommandContext context, string sql)
    {
        await using var command = context.CreateCommand();
        command.CommandText = sql;
        return await command.ExecuteNonQueryAsync(Cancellation);
    }

    private static async Task<long> CountAsync(CommandContext context, string sql)
    {
        await using var command = context.CreateCommand();
        command.CommandText = sql;
        return (long)(await command.ExecuteScalarAsync(Cancellation))!;
    }

    private async Task<T> InTenantAsync<T>(string database, string role, Guid tenantId, Func<CommandContext, Task<T>> body)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(role, database));
        await using var scope = await TenantScope.BeginAsync(source, tenantId, Cancellation);
        var result = await body(scope.CreateCommandContext());
        await scope.CommitAsync(Cancellation);
        return result;
    }

    /// <summary>Two active Tenants, and in A a User with a pending credential and an unexpired link.</summary>
    private async Task<string> DatabaseAsync()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var superuser = postgres.SuperuserConnection(database);
        await PostgresFixture.ExecuteAsync(superuser, TestTenants.InsertSql(TenantA, TenantB));
        await PostgresFixture.ExecuteAsync(
            superuser,
            $"INSERT INTO \"user\" (tenant_id, id, email) VALUES ('{TenantA}', '{UserA}', 'a@example.com'); "
            + $"INSERT INTO password_credential (tenant_id, id, user_id, connection_id, password_hash, status) VALUES ('{TenantA}', '{CredentialA}', '{UserA}', gen_random_uuid(), '$argon2id$x', 'pending'); "
            + $"INSERT INTO one_time_token (tenant_id, id, user_id, credential_id, purpose, token_hash, expires_at) VALUES ('{TenantA}', gen_random_uuid(), '{UserA}', '{CredentialA}', 'email_verification', sha256('a'), now() + interval '1 day')");
        return database;
    }
}
