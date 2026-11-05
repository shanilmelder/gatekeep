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
        // Story 1.26: BS only with BE, and the kinds.
        "UPDATE admin_credential SET backed_up = true",
        "UPDATE admin_credential SET backup_eligible = true",
        "UPDATE admin_session SET kind = 'restricted'",
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
    [InlineData("UPDATE admin_session SET kind = 'full'; UPDATE admin_session SET kind = 'recovery'")]
    [InlineData("UPDATE admin_session SET kind = 'recovery'")]
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
    [InlineData("TRUNCATE admin_credential")]
    [InlineData("UPDATE admin_credential SET public_key = '\\x02'")]
    [InlineData("UPDATE admin_credential SET credential_id = '\\x03'")]
    [InlineData("UPDATE admin_credential SET admin_id = admin_id")]
    public async Task Admin_cant_truncate_credentials_or_change_a_key_or_its_BE_flag(string sql)
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

    /// <summary>Story 1.27: gk_admin inserts the creator's Owner role, and still never changes or removes one.</summary>
    [Fact]
    public async Task Admin_reads_and_inserts_tenant_role_but_never_changes_or_removes_one()
    {
        var database = await WithRoleAsync();
        var admin = postgres.RoleConnection(TableRegistry.Admin, database);

        Assert.Equal("owner", await PostgresFixture.ScalarAsync<string>(admin, $"SELECT role FROM tenant_role WHERE admin_id = '{Owner}'"));

        // The creator's Owner role, on the Tenant it is creating; any other insert is GK004.
        var creator = Guid.CreateVersion7();
        var creating = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), $"INSERT INTO admin (id, deployment_owner) VALUES ('{creator}', false)");
        await TestTenants.InsertAsync(postgres.SuperuserConnection(database), creating, status: "creating");
        await PostgresFixture.ExecuteAsync(admin, $"INSERT INTO tenant_role (tenant_id, admin_id, role) VALUES ('{creating}', '{creator}', 'owner')");
        Assert.Equal("owner", await PostgresFixture.ScalarAsync<string>(admin, $"SELECT role FROM tenant_role WHERE admin_id = '{creator}'"));

        foreach (var sql in new[]
        {
            $"INSERT INTO tenant_role (tenant_id, admin_id, role) VALUES ('{creating}', '{Invitee}', 'viewer')",
            $"INSERT INTO tenant_role (tenant_id, admin_id, role) VALUES ('{TenantA}', '{creator}', 'owner')",
        })
        {
            var refused = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(admin, sql));
            Assert.Equal("GK004", refused.SqlState);
        }

        foreach (var sql in TenantRoleWrites.Skip(1).Where(s => !s.StartsWith("DELETE", StringComparison.Ordinal)).Append("TRUNCATE tenant_role"))
        {
            var denied = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(admin, sql));
            Assert.Equal(PermissionDenied, denied.SqlState);
        }

        // Story 1.29: gk_admin may delete roles, but only a deleting Tenant's, which none is.
        var roles = await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM tenant_role");
        var removed = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(admin, "DELETE FROM tenant_role"));
        Assert.Equal("GK009", removed.SqlState);
        Assert.Equal(roles, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM tenant_role"));
    }

    // The floor and maximum triggers' own SQLSTATE, so the host maps exactly them to a refusal.
    private const string FloorOrMaximum = "GK001";

    private const string AddCredentials =
        """
        INSERT INTO admin_credential (id, admin_id, credential_id, public_key, sign_count, aaguid)
        SELECT gen_random_uuid(), '01900000-0000-7000-8000-000000000a01', decode(md5(random()::text || n), 'hex'), '\x01', 0, gen_random_uuid()
        FROM generate_series(1, {0}) AS n
        """;

    [Fact]
    public async Task The_floor_of_two_and_the_maximum_of_ten_hold_in_the_database()
    {
        var database = await SeededAsync();
        var superuser = postgres.SuperuserConnection(database);
        var admin = postgres.RoleConnection(TableRegistry.Admin, database);

        // One credential: none may go, by gk_admin or the owner.
        Assert.Equal(FloorOrMaximum, await StateAsync(admin, "DELETE FROM admin_credential"));
        Assert.Equal(FloorOrMaximum, await SqlStateAsync(database, "DELETE FROM admin_credential"));

        // Three: one may go, and then neither of the last two, even in one statement.
        await PostgresFixture.ExecuteAsync(superuser, string.Format(null, AddCredentials, 2));
        await PostgresFixture.ExecuteAsync(admin, "DELETE FROM admin_credential WHERE id = (SELECT min(id::text)::uuid FROM admin_credential)");
        Assert.Equal(FloorOrMaximum, await StateAsync(admin, "DELETE FROM admin_credential"));
        Assert.Equal(2L, await PostgresFixture.ScalarAsync<long>(superuser, "SELECT count(*) FROM admin_credential"));

        // Ten, and no eleventh by any role.
        await PostgresFixture.ExecuteAsync(superuser, string.Format(null, AddCredentials, 8));
        Assert.Equal(FloorOrMaximum, await StateAsync(admin, string.Format(null, AddCredentials, 1)));
        Assert.Equal(FloorOrMaximum, await SqlStateAsync(database, string.Format(null, AddCredentials, 1)));
        Assert.Equal(10L, await PostgresFixture.ScalarAsync<long>(superuser, "SELECT count(*) FROM admin_credential"));
    }

    [Fact]
    public async Task Backup_flags_start_unknown_and_BE_once_recorded_never_changes()
    {
        var database = await SeededAsync();
        var admin = postgres.RoleConnection(TableRegistry.Admin, database);

        // A credential stored without flags, as before Story 1.26, has neither.
        Assert.True(await PostgresFixture.ScalarAsync<bool>(admin, "SELECT backup_eligible IS NULL AND backed_up IS NULL FROM admin_credential"));

        // Recorded once, by gk_admin; then BS may change and BE may not, nor go back to unknown.
        await PostgresFixture.ExecuteAsync(admin, "UPDATE admin_credential SET backup_eligible = true, backed_up = true");
        await PostgresFixture.ExecuteAsync(admin, "UPDATE admin_credential SET backed_up = false");
        Assert.Equal(Raised, await StateAsync(admin, "UPDATE admin_credential SET backup_eligible = false"));
        Assert.Equal(Raised, await SqlStateAsync(database, "UPDATE admin_credential SET backup_eligible = NULL, backed_up = NULL"));
    }

    private const string Challenge =
        """
        INSERT INTO admin_fresh_assertion (id, session_id, stage, binding_hash, challenge_sha256, credential_id, created_at, expires_at)
        VALUES (gen_random_uuid(), '01900000-0000-7000-8000-000000000a02', {0}, sha256('b'), {1}, {2}, now(), now() + interval {3})
        """;

    [Theory]
    [InlineData("'pending'", "sha256('c')", "NULL", "'5 minutes'", CheckViolation)]
    [InlineData("'challenge'", "NULL", "NULL", "'5 minutes'", CheckViolation)]
    [InlineData("'challenge'", "sha256('c')", "(SELECT id FROM admin_credential)", "'5 minutes'", CheckViolation)]
    [InlineData("'verified'", "NULL", "NULL", "'5 minutes'", CheckViolation)]
    [InlineData("'verified'", "sha256('c')", "(SELECT id FROM admin_credential)", "'5 minutes'", CheckViolation)]
    [InlineData("'verified'", "NULL", "(SELECT id FROM admin_credential)", "'5 minutes 1 second'", CheckViolation)]
    [InlineData("'challenge'", "'\\x00'", "NULL", "'5 minutes'", CheckViolation)]
    [InlineData("'verified'", "NULL", "gen_random_uuid()", "'5 minutes'", ForeignKeyViolation)]
    public async Task Fresh_assertion_constraints_refuse_a_violation(string stage, string challenge, string credential, string lifetime, string state)
    {
        var database = await SeededAsync();

        Assert.Equal(state, await SqlStateAsync(database, string.Format(null, Challenge, stage, challenge, credential, lifetime)));
    }

    [Fact]
    public async Task One_challenge_per_Session_and_one_grant_per_binding_and_gk_admin_never_updates()
    {
        var database = await SeededAsync();
        var superuser = postgres.SuperuserConnection(database);
        var admin = postgres.RoleConnection(TableRegistry.Admin, database);
        var challenge = string.Format(null, Challenge, "'challenge'", "sha256('c')", "NULL", "'5 minutes'");
        var grant = string.Format(null, Challenge, "'verified'", "NULL", "(SELECT id FROM admin_credential)", "'5 minutes'");

        await PostgresFixture.ExecuteAsync(admin, challenge);
        await PostgresFixture.ExecuteAsync(admin, grant);
        Assert.Equal(UniqueViolation, await StateAsync(admin, challenge));
        Assert.Equal(UniqueViolation, await StateAsync(admin, grant));
        Assert.Equal(PermissionDenied, await StateAsync(admin, "UPDATE admin_fresh_assertion SET expires_at = expires_at"));

        // The grant's credential can't go while the grant does.
        await PostgresFixture.ExecuteAsync(superuser, string.Format(null, AddCredentials, 2));
        Assert.Equal(RestrictViolation, await SqlStateAsync(database, "DELETE FROM admin_credential WHERE id IN (SELECT credential_id FROM admin_fresh_assertion)"));

        await PostgresFixture.ExecuteAsync(admin, "DELETE FROM admin_fresh_assertion");
    }

    private const string Code =
        "INSERT INTO admin_recovery_code (id, admin_id, code_hmac, hmac_key_version, created_at, confirmed_at, used_at) VALUES (gen_random_uuid(), '01900000-0000-7000-8000-000000000a01', {0}, {1}, now(), {2}, {3})";

    [Theory]
    [InlineData("'\\x00'", "1", "NULL", "NULL", CheckViolation)]
    [InlineData("sha256('a')", "0", "NULL", "NULL", CheckViolation)]
    [InlineData("sha256('a')", "1", "NULL", "now()", CheckViolation)]
    [InlineData("sha256('a')", "1", "now() - interval '1 hour'", "NULL", CheckViolation)]
    [InlineData("sha256('a')", "1", "now()", "now() - interval '1 hour'", CheckViolation)]
    public async Task Recovery_code_constraints_refuse_a_violation(string hmac, string version, string confirmed, string used, string state)
    {
        var database = await SeededAsync();

        Assert.Equal(state, await SqlStateAsync(database, string.Format(null, Code, hmac, version, confirmed, used)));
    }

    [Fact]
    public async Task A_recovery_code_is_confirmed_and_used_once_one_unused_each_and_a_confirmed_one_kept()
    {
        var database = await SeededAsync();
        var admin = postgres.RoleConnection(TableRegistry.Admin, database);

        await PostgresFixture.ExecuteAsync(admin, string.Format(null, Code, "sha256('a')", "1", "NULL", "NULL"));
        Assert.Equal(UniqueViolation, await StateAsync(admin, string.Format(null, Code, "sha256('b')", "1", "NULL", "NULL")));
        Assert.Equal(PermissionDenied, await StateAsync(admin, "UPDATE admin_recovery_code SET code_hmac = sha256('c')"));

        // Unconfirmed, it may be replaced; confirmed, never deleted, and each stamp is set once.
        await PostgresFixture.ExecuteAsync(admin, "DELETE FROM admin_recovery_code");
        await PostgresFixture.ExecuteAsync(admin, string.Format(null, Code, "sha256('a')", "1", "NULL", "NULL"));
        await PostgresFixture.ExecuteAsync(admin, "UPDATE admin_recovery_code SET confirmed_at = clock_timestamp()");
        Assert.Equal(Raised, await StateAsync(admin, "UPDATE admin_recovery_code SET confirmed_at = clock_timestamp()"));
        Assert.Equal(Raised, await StateAsync(admin, "DELETE FROM admin_recovery_code"));
        Assert.Equal(Raised, await SqlStateAsync(database, "DELETE FROM admin_recovery_code"));
        await PostgresFixture.ExecuteAsync(admin, "UPDATE admin_recovery_code SET used_at = clock_timestamp()");
        Assert.Equal(Raised, await StateAsync(admin, "UPDATE admin_recovery_code SET used_at = NULL"));

        // Used, it no longer holds the Admin's one unused place.
        await PostgresFixture.ExecuteAsync(admin, string.Format(null, Code, "sha256('b')", "1", "NULL", "NULL"));
    }

    public static TheoryData<string> RolesWithoutNewAdminsGrants =>
        [.. TableRegistry.RuntimeRoles.Where(r => r != TableRegistry.Admin)];

    [Theory]
    [MemberData(nameof(RolesWithoutNewAdminsGrants))]
    public async Task Other_roles_hold_nothing_on_the_Story_1_26_tables_but_the_Cli_reading_codes(string role)
    {
        var database = await SeededAsync();
        var connection = postgres.RoleConnection(role, database);

        foreach (var sql in new[]
        {
            "SELECT count(*) FROM admin_fresh_assertion",
            "DELETE FROM admin_fresh_assertion",
            role == TableRegistry.Cli ? null : "SELECT count(*) FROM admin_recovery_code",
            "DELETE FROM admin_recovery_code",
            "UPDATE admin_recovery_code SET used_at = now()",
        }.OfType<string>())
        {
            Assert.Equal(PermissionDenied, await StateAsync(connection, sql));
        }

        if (role == TableRegistry.Cli)
        {
            Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(connection, "SELECT count(*) FROM admin_recovery_code"));
        }
    }

    /// <summary>The SQL state <paramref name="sql"/> fails with on <paramref name="connection"/>.</summary>
    private static async Task<string?> StateAsync(string connection, string sql)
    {
        var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(connection, sql));
        return failure.SqlState;
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
            {TestTenants.InsertSql(TenantA)};
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
