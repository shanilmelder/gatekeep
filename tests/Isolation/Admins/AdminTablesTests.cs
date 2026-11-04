using Gatekeep.Adapters.Postgres.Schema;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Stories 1.21 and 1.22: <c>admin</c>, <c>admin_session</c> and <c>admin_credential</c> refuse
/// what no code path should write, for the owner too: one Deployment Owner, Session lifetimes within PRD §5.2's 8 hours, a 32-byte ID
/// hash, a known kind and end reason, an ending with its reason and not before the Session began,
/// and an ending written once; a challenge hash of 32 bytes with its expiry, a kind that only goes
/// from setup to full, a 64-byte user handle and setup completion each set once, and credentials
/// with an ID unique Deployment-wide, a 32-bit counter and known transports.
/// </summary>
public sealed class AdminTablesTests(PostgresFixture postgres)
{
    private const string CheckViolation = "23514";
    private const string UniqueViolation = "23505";
    private const string Raised = "P0001";
    private const string PermissionDenied = "42501";

    private static readonly Guid Owner = Guid.Parse("01900000-0000-7000-8000-000000000a01");

    private static readonly Guid Session = Guid.Parse("01900000-0000-7000-8000-000000000a02");

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public static TheoryData<string> CheckViolations =>
    [
        "UPDATE admin_session SET idle_expires_at = absolute_expires_at + interval '1 second'",
        "UPDATE admin_session SET idle_expires_at = created_at - interval '1 second'",
        "UPDATE admin_session SET absolute_expires_at = created_at + interval '8 hours 1 second'",
        "UPDATE admin_session SET ended_at = clock_timestamp()",
        "UPDATE admin_session SET end_reason = 'expired'",
        "UPDATE admin_session SET ended_at = clock_timestamp(), end_reason = 'logout'",
        "UPDATE admin_session SET ended_at = created_at - interval '1 second', end_reason = 'expired'",
        "UPDATE admin_session SET id_hash = '\\x00'",
        "UPDATE admin_session SET kind = 'owner'",
        "UPDATE admin_session SET registration_challenge_sha256 = sha256('c')",
        "UPDATE admin_session SET registration_challenge_expires_at = clock_timestamp()",
        "UPDATE admin_session SET registration_challenge_sha256 = '\\x00', registration_challenge_expires_at = clock_timestamp()",
        "UPDATE admin SET webauthn_handle = '\\x00'",
        "UPDATE admin_credential SET sign_count = -1",
        "UPDATE admin_credential SET sign_count = 4294967296",
        "UPDATE admin_credential SET transports = '{usb,carrier-pigeon}'",
        "UPDATE admin_credential SET credential_id = ''",
        "UPDATE admin_credential SET public_key = ''",
        "UPDATE admin_credential SET last_used_at = created_at - interval '1 second'",
    ];

    [Theory]
    [MemberData(nameof(CheckViolations))]
    public async Task Session_constraints_refuse_a_violation(string sql)
    {
        var database = await SeededAsync();

        Assert.Equal(CheckViolation, await SqlStateAsync(database, sql));
    }

    [Fact]
    public async Task A_second_Deployment_Owner_is_refused()
    {
        var database = await SeededAsync();

        Assert.Equal(
            UniqueViolation,
            await SqlStateAsync(database, $"INSERT INTO admin (id, deployment_owner) VALUES ('{Guid.CreateVersion7()}', true)"));

        // Admins who aren't the Owner aren't limited.
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"INSERT INTO admin (id, deployment_owner) VALUES ('{Guid.CreateVersion7()}', false), ('{Guid.CreateVersion7()}', false)");
    }

    [Theory]
    [InlineData("UPDATE admin_session SET ended_at = NULL, end_reason = NULL")]
    [InlineData("UPDATE admin_session SET end_reason = 'revoked'")]
    [InlineData("UPDATE admin_session SET ended_at = ended_at + interval '1 second'")]
    public async Task An_ending_is_written_once(string sql)
    {
        var database = await SeededAsync();
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            "UPDATE admin_session SET ended_at = clock_timestamp(), end_reason = 'signed_out'");

        Assert.Equal(Raised, await SqlStateAsync(database, sql));

        // Its other columns may still change, as a slide's race may touch them.
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), "UPDATE admin_session SET idle_expires_at = idle_expires_at");
    }

    [Theory]
    [InlineData("UPDATE admin_session SET kind = 'full'; UPDATE admin_session SET kind = 'setup'")]
    [InlineData("UPDATE admin SET webauthn_handle = sha512('a'); UPDATE admin SET webauthn_handle = sha512('b')")]
    [InlineData("UPDATE admin SET webauthn_handle = sha512('a'); UPDATE admin SET webauthn_handle = NULL")]
    [InlineData("UPDATE admin SET setup_completed_at = clock_timestamp(); UPDATE admin SET setup_completed_at = NULL")]
    public async Task Kind_handle_and_setup_completion_only_move_forward(string sql)
    {
        var database = await SeededAsync();

        Assert.Equal(Raised, await SqlStateAsync(database, sql));
    }

    [Fact]
    public async Task A_credential_ID_is_unique_Deployment_wide()
    {
        var database = await SeededAsync();
        var other = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), $"INSERT INTO admin (id, deployment_owner) VALUES ('{other}', false)");

        Assert.Equal(
            UniqueViolation,
            await SqlStateAsync(
                database,
                $"INSERT INTO admin_credential (id, admin_id, credential_id, public_key, sign_count, aaguid) VALUES (gen_random_uuid(), '{other}', '\\x0102', '\\x01', 0, gen_random_uuid())"));
    }

    public static TheoryData<string> RolesWithoutCredentialGrants =>
        [.. TableRegistry.RuntimeRoles.Where(r => r != TableRegistry.Admin)];

    [Theory]
    [MemberData(nameof(RolesWithoutCredentialGrants))]
    public async Task Other_roles_hold_nothing_on_admin_credential(string role)
    {
        var database = await SeededAsync();

        foreach (var sql in new[]
        {
            "SELECT count(*) FROM admin_credential",
            $"INSERT INTO admin_credential (id, admin_id, credential_id, public_key, sign_count, aaguid) VALUES (gen_random_uuid(), '{Owner}', '\\x0a', '\\x01', 0, gen_random_uuid())",
            "UPDATE admin_credential SET sign_count = 1",
            "DELETE FROM admin_credential",
        })
        {
            var denied = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(postgres.RoleConnection(role, database), sql));
            Assert.Equal(PermissionDenied, denied.SqlState);
        }
    }

    [Theory]
    [InlineData("DELETE FROM admin_credential")]
    [InlineData("TRUNCATE admin_credential")]
    [InlineData("UPDATE admin_credential SET public_key = '\\x02'")]
    [InlineData("UPDATE admin_credential SET credential_id = '\\x03'")]
    [InlineData("UPDATE admin_credential SET admin_id = admin_id")]
    public async Task Admin_cant_delete_a_credential_or_change_its_key(string sql)
    {
        var database = await SeededAsync();

        var denied = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(postgres.RoleConnection(TableRegistry.Admin, database), sql));

        Assert.Equal(PermissionDenied, denied.SqlState);

        // The counter and last use are what it may write.
        await PostgresFixture.ExecuteAsync(
            postgres.RoleConnection(TableRegistry.Admin, database),
            "UPDATE admin_credential SET sign_count = 7, last_used_at = clock_timestamp()");
    }

    private const string ForeignKeyViolation = "23503";

    // ON DELETE RESTRICT refuses at once, with its own state.
    private const string RestrictViolation = "23001";

    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-000000000a0a");

    /// <summary>An Admin referenced by nothing but a tenant_role row, so only its RESTRICT can block deleting them.</summary>
    private static readonly Guid Invitee = Guid.Parse("01900000-0000-7000-8000-000000000a0b");

    [Fact]
    public async Task Only_tenant_role_blocks_deleting_its_Tenant_or_Admin()
    {
        var database = await WithRoleAsync();
        var superuser = postgres.SuperuserConnection(database);

        // Each refusal above is tenant_role's own: with its rows gone, both deletes go through.
        await PostgresFixture.ExecuteAsync(superuser, "DELETE FROM tenant_role");
        await PostgresFixture.ExecuteAsync(superuser, $"DELETE FROM admin WHERE id = '{Invitee}'");
        await PostgresFixture.ExecuteAsync(superuser, $"DELETE FROM tenant WHERE id = '{TenantA}'");
    }

    [Theory]
    // Story 1.24: one role per Admin per Tenant, a known role, and keys to a real Tenant and Admin.
    [InlineData("INSERT INTO tenant_role (tenant_id, admin_id, role) VALUES ('01900000-0000-7000-8000-000000000a0a', '01900000-0000-7000-8000-000000000a01', 'editor')", UniqueViolation)]
    [InlineData("UPDATE tenant_role SET role = 'admin'", CheckViolation)]
    [InlineData("UPDATE tenant_role SET role = 'Owner'", CheckViolation)]
    [InlineData("INSERT INTO tenant_role (tenant_id, admin_id, role) VALUES (gen_random_uuid(), '01900000-0000-7000-8000-000000000a01', 'viewer')", ForeignKeyViolation)]
    [InlineData("INSERT INTO tenant_role (tenant_id, admin_id, role) VALUES ('01900000-0000-7000-8000-000000000a0a', gen_random_uuid(), 'viewer')", ForeignKeyViolation)]
    [InlineData("DELETE FROM tenant WHERE id = '01900000-0000-7000-8000-000000000a0a'", RestrictViolation)]
    [InlineData("DELETE FROM admin WHERE id = '01900000-0000-7000-8000-000000000a0b'", RestrictViolation)]
    public async Task Tenant_role_constraints_refuse_a_violation(string sql, string state)
    {
        var database = await WithRoleAsync();

        Assert.Equal(state, await SqlStateAsync(database, sql));
    }

    public static TheoryData<string> RolesWithoutTenantRoleGrants =>
        [.. TableRegistry.RuntimeRoles.Where(r => r != TableRegistry.Admin)];

    [Theory]
    [MemberData(nameof(RolesWithoutTenantRoleGrants))]
    public async Task Other_roles_hold_nothing_on_tenant_role(string role)
    {
        var database = await WithRoleAsync();

        foreach (var sql in TenantRoleWrites.Prepend("SELECT count(*) FROM tenant_role"))
        {
            var denied = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(postgres.RoleConnection(role, database), sql));
            Assert.Equal(PermissionDenied, denied.SqlState);
        }
    }

    [Fact]
    public async Task Admin_only_reads_tenant_role()
    {
        var database = await WithRoleAsync();
        var admin = postgres.RoleConnection(TableRegistry.Admin, database);

        Assert.Equal("owner", await PostgresFixture.ScalarAsync<string>(admin, $"SELECT role FROM tenant_role WHERE admin_id = '{Owner}'"));
        foreach (var sql in TenantRoleWrites.Append("TRUNCATE tenant_role"))
        {
            var denied = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(admin, sql));
            Assert.Equal(PermissionDenied, denied.SqlState);
        }
    }

    private static readonly string[] TenantRoleWrites =
    [
        $"INSERT INTO tenant_role (tenant_id, admin_id, role) VALUES ('{TenantA}', '{Owner}', 'viewer')",
        "UPDATE tenant_role SET role = 'viewer'",
        "DELETE FROM tenant_role",
    ];

    /// <summary>A seeded database with Tenant A, in which the Owner holds the <c>owner</c> Tenant Role.</summary>
    private async Task<string> WithRoleAsync()
    {
        var database = await SeededAsync();
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"""
            INSERT INTO tenant (id) VALUES ('{TenantA}');
            INSERT INTO admin (id, deployment_owner) VALUES ('{Invitee}', false);
            INSERT INTO tenant_role (tenant_id, admin_id, role) VALUES ('{TenantA}', '{Owner}', 'owner'), ('{TenantA}', '{Invitee}', 'viewer');
            """);
        return database;
    }

    /// <summary>A database with one Owner and one live setup Session.</summary>
    private async Task<string> SeededAsync()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"""
            INSERT INTO admin (id, deployment_owner) VALUES ('{Owner}', true);
            INSERT INTO admin_session (id, id_hash, admin_id, kind, created_at, idle_expires_at, absolute_expires_at)
            VALUES ('{Session}', sha256('x'), '{Owner}', 'setup', now(),
                    now() + interval '30 minutes', now() + interval '8 hours');
            INSERT INTO admin_credential (id, admin_id, credential_id, public_key, sign_count, aaguid, transports)
            VALUES (gen_random_uuid(), '{Owner}', '\x0102', '\x01', 0, gen_random_uuid(), ARRAY['usb']);
            """);
        return database;
    }

    /// <summary>The SQL state <paramref name="sql"/> fails with, as the superuser, whom grants don't stop.</summary>
    private async Task<string?> SqlStateAsync(string database, string sql)
    {
        var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), sql));
        _ = Cancellation;
        return failure.SqlState;
    }
}
