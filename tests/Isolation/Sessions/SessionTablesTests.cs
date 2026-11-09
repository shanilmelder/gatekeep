using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Sessions.Contracts;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Sessions;

/// <summary>
/// Story 2.6: the Session and transaction tables under row-level security and their grants,
/// <see cref="IAuthentication.BeginAsync"/>, and <see cref="ISessions.StartAsync"/> through the
/// test-only authenticator. No test compares or prints a cookie value: each is checked by the
/// hash the table holds.
/// </summary>
public sealed class SessionTablesTests(PostgresFixture postgres)
{
    private const string RowSecurityOrPermission = "42501";
    private const string ForeignKeyViolation = "23503";
    private const string CheckViolation = "23514";

    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-00000000000a");
    private static readonly Guid TenantB = Guid.Parse("01900000-0000-7000-8000-00000000000b");
    private static readonly Guid UserA = Guid.Parse("01900000-0000-7000-8000-0000000001a1");
    private static readonly Guid UserB = Guid.Parse("01900000-0000-7000-8000-0000000001b1");
    private static readonly Guid SessionA = Guid.Parse("01900000-0000-7000-8000-0000000002a1");
    private static readonly Guid AuthorizationA = Guid.Parse("01900000-0000-7000-8000-0000000003a1");
    private static readonly Guid TokenA = Guid.Parse("01900000-0000-7000-8000-0000000004a1");
    private static readonly Guid TransactionA = Guid.Parse("01900000-0000-7000-8000-0000000005a1");
    private static readonly Guid Application = Guid.Parse("01900000-0000-7000-8000-0000000006a1");

    /// <summary>Whole seconds, so a stored microsecond time compares exactly.</summary>
    private static readonly DateTimeOffset Now = new(2026, 11, 2, 12, 0, 0, TimeSpan.Zero);

    private static readonly DateTimeOffset AuthTime = Now.AddSeconds(-5);

    private static readonly Dictionary<string, string> Parameters = new()
    {
        ["client_id"] = "app-a",
        ["redirect_uri"] = "https://app-a.example/callback",
        ["scope"] = "openid",
    };

    private static readonly string[] Tables = ["user", "user_session", "authorization", "token", "signin_transaction"];

    private readonly IAuthentication _authentication =
        AuthenticationContract.CreateAuthentication(AuditContract.CreateAppender(), new FixedTime(Now));

    private readonly ISessions _sessions = SessionsContract.CreateSessions(AuditContract.CreateAppender(), new FixedTime(Now));

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public static TheoryData<string> AllTables => [.. Tables];

    /// <summary>The write each table's writer could make for Tenant A, run in Tenant B's scope.</summary>
    public static TheoryData<string, string> CrossTenantInserts => new()
    {
        // No runtime role may write Users yet, so the owner shows the policy, which FORCE applies to it.
        { TableRegistry.Migrator, $"""INSERT INTO "user" (tenant_id, id) VALUES ('{TenantA}', gen_random_uuid())""" },
        {
            TableRegistry.Hosted,
            $"""
            INSERT INTO user_session (tenant_id, id, user_id, id_hash, amr, auth_time, idle_expires_at, absolute_expires_at, created_at)
            VALUES ('{TenantA}', gen_random_uuid(), '{UserA}', sha256(gen_random_uuid()::text::bytea), ARRAY['pwd'],
                    now(), now() + interval '1 day', now() + interval '2 days', now())
            """
        },
        {
            TableRegistry.Hosted,
            $"""
            INSERT INTO "authorization" (tenant_id, id, user_session_id, status, type, concurrency_token)
            VALUES ('{TenantA}', gen_random_uuid(), '{SessionA}', 'valid', 'ad-hoc', gen_random_uuid())
            """
        },
        {
            TableRegistry.Hosted,
            $"""
            INSERT INTO token (tenant_id, id, authorization_id, type, status, concurrency_token)
            VALUES ('{TenantA}', gen_random_uuid(), '{AuthorizationA}', 'refresh_token', 'valid', gen_random_uuid())
            """
        },
        {
            TableRegistry.Hosted,
            $"""
            INSERT INTO signin_transaction (tenant_id, id, application_id, binding_hash, parameters, created_at, expires_at)
            VALUES ('{TenantA}', gen_random_uuid(), '{Application}', sha256(gen_random_uuid()::text::bytea), jsonb_build_object(),
                    now(), now() + interval '30 minutes')
            """
        },
    };

    public static TheoryData<string> HostedWritableTables => [.. Tables.Where(t => t != "user")];

    /// <summary>
    /// Every runtime role but <c>gk_hosted</c> and <c>gk_worker</c>, on every table: none has any grant.
    /// From Story 1.29 <c>gk_worker</c> deletes them for a Tenant's purge, reading only <c>tenant_id</c>,
    /// which <c>TenantTablesTests.Worker_reads_no_purged_tables_content</c> holds.
    /// </summary>
    public static TheoryData<string, string> UngrantedRoles
    {
        get
        {
            var data = new TheoryData<string, string>();
            foreach (var role in TableRegistry.RuntimeRoles.Where(r => r != TableRegistry.Hosted && r != TableRegistry.Worker))
            {
                foreach (var table in Tables)
                {
                    data.Add(role, table);
                }
            }

            return data;
        }
    }

    /// <summary>What <c>gk_hosted</c> may not do: delete anything, or write Users.</summary>
    public static TheoryData<string> HostedRefusals =>
    [
        .. Tables.Select(t => $"DELETE FROM \"{t}\""),
        $"""INSERT INTO "user" (tenant_id, id) VALUES ('{TenantA}', gen_random_uuid())""",
        """UPDATE "user" SET created_at = now()""",
    ];

    public static TheoryData<string> ShortHashInserts =>
    [
        $"""
        INSERT INTO user_session (tenant_id, id, user_id, id_hash, amr, auth_time, idle_expires_at, absolute_expires_at, created_at)
        VALUES ('{TenantA}', gen_random_uuid(), '{UserA}', decode(repeat('00', 31), 'hex'), ARRAY['pwd'],
                now(), now() + interval '1 day', now() + interval '2 days', now())
        """,
        $"""
        INSERT INTO signin_transaction (tenant_id, id, application_id, binding_hash, parameters, created_at, expires_at)
        VALUES ('{TenantA}', gen_random_uuid(), '{Application}', decode(repeat('00', 31), 'hex'), jsonb_build_object(),
                now(), now() + interval '30 minutes')
        """,
    ];

    /// <summary>One statement per consistency CHECK, each breaking only that check.</summary>
    public static TheoryData<string> BrokenChecks =>
    [
        $"""
        INSERT INTO user_session (tenant_id, id, user_id, id_hash, amr, auth_time, idle_expires_at, absolute_expires_at, created_at)
        VALUES ('{TenantA}', gen_random_uuid(), '{UserA}', sha256(gen_random_uuid()::text::bytea), ARRAY['pwd'],
                now(), now() + interval '8 days', now() + interval '7 days', now())
        """,
        $"UPDATE user_session SET ended_at = now() WHERE id = '{SessionA}'",
        $"""
        INSERT INTO user_session (tenant_id, id, user_id, id_hash, amr, auth_time, idle_expires_at, absolute_expires_at, created_at)
        VALUES ('{TenantA}', gen_random_uuid(), '{UserA}', sha256(gen_random_uuid()::text::bytea), ARRAY[]::text[],
                now(), now() + interval '1 day', now() + interval '2 days', now())
        """,
        $"UPDATE signin_transaction SET expires_at = created_at WHERE id = '{TransactionA}'",
    ];

    [Fact]
    public async Task Begin_writes_one_transaction_bound_to_the_returned_value_the_Tenant_and_the_Application()
    {
        var database = await SeededDatabaseAsync();
        await using var hosted = Source(TableRegistry.Hosted, database);

        StartedSignIn started;
        await using (var scope = await TenantScope.BeginAsync(hosted, TenantA, Cancellation))
        {
            started = await _authentication.BeginAsync(
                scope.CreateCommandContext(), new SignInRequest(Application, Parameters), Cancellation);
            await scope.CommitAsync(Cancellation);
        }

        await using var connection = await OpenAsync(postgres.SuperuserConnection(database));
        await using (var command = new NpgsqlCommand(
            """
            SELECT tenant_id, id, application_id, binding_hash, parameters::text, completed_steps, created_at, expires_at
            FROM signin_transaction
            """,
            connection))
        await using (var reader = await command.ExecuteReaderAsync(Cancellation))
        {
            Assert.True(await reader.ReadAsync(Cancellation));
            Assert.Equal(TenantA, reader.GetGuid(0));
            Assert.Equal(started.TransactionId, reader.GetGuid(1));
            Assert.Equal(Application, reader.GetGuid(2));
            Assert.Equal(HashOf(started.Binding), reader.GetFieldValue<byte[]>(3));
            Assert.Equal(Parameters, ParametersOf(reader.GetString(4)));
            Assert.Empty(reader.GetFieldValue<string[]>(5));
            Assert.Equal(Now, reader.GetFieldValue<DateTimeOffset>(6));
            Assert.Equal(Now + SecurityLimits.SignInTransactionLifetime, reader.GetFieldValue<DateTimeOffset>(7));
            Assert.Equal(Now.AddMinutes(30), reader.GetFieldValue<DateTimeOffset>(7));
            Assert.False(await reader.ReadAsync(Cancellation));
        }

        Assert.Equal(32, started.Binding.Use(v => Base64Url.DecodeFromChars(v).Length));
        Assert.Equal(
            [$"{TenantA}|authentication.signin_transaction.started|anonymous|||"],
            await AuditEventsAsync(connection));
    }

    [Fact]
    public async Task Two_begins_never_share_a_binding()
    {
        var database = await SeededDatabaseAsync();
        await using var hosted = Source(TableRegistry.Hosted, database);

        await using var scope = await TenantScope.BeginAsync(hosted, TenantA, Cancellation);
        var context = scope.CreateCommandContext();
        var first = await _authentication.BeginAsync(context, new SignInRequest(Application, Parameters), Cancellation);
        var second = await _authentication.BeginAsync(context, new SignInRequest(Application, Parameters), Cancellation);

        Assert.True(!HashOf(first.Binding).SequenceEqual(HashOf(second.Binding)), "Two bindings matched.");
        Assert.NotEqual(first.TransactionId, second.TransactionId);
    }

    [Fact]
    public async Task Begin_without_a_Tenant_throws_and_writes_nothing()
    {
        var database = await SeededDatabaseAsync();
        await using var hosted = Source(TableRegistry.Hosted, database);

        await using (var scope = await DeploymentScope.BeginAsync(hosted, Cancellation))
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => _authentication.BeginAsync(
                scope.CreateCommandContext(), new SignInRequest(Application, Parameters), Cancellation));
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal(0, await CountAsync(database, "signin_transaction"));
        Assert.Equal(0, await CountAsync(database, "audit_event"));
        Assert.Equal(0, await CountAsync(database, "deployment_audit_event"));
    }

    [Fact]
    public async Task Start_without_a_Tenant_throws_and_writes_nothing()
    {
        var database = await SeededDatabaseAsync();
        await using var hosted = Source(TableRegistry.Hosted, database);

        await using (var scope = await DeploymentScope.BeginAsync(hosted, Cancellation))
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => _sessions.StartAsync(
                scope.CreateCommandContext(), new NewSession(UserA, ["pwd"], AuthTime), Cancellation));
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal(0, await CountAsync(database, "user_session"));
        Assert.Equal(0, await CountAsync(database, "deployment_audit_event"));
    }

    [Fact]
    public async Task Start_without_an_authentication_method_throws_and_writes_nothing()
    {
        var database = await SeededDatabaseAsync();
        await using var hosted = Source(TableRegistry.Hosted, database);

        await using (var scope = await TenantScope.BeginAsync(hosted, TenantA, Cancellation))
        {
            await Assert.ThrowsAsync<ArgumentException>(() => _sessions.StartAsync(
                scope.CreateCommandContext(), new NewSession(UserA, [], AuthTime), Cancellation));
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal(0, await CountAsync(database, "user_session"));
        Assert.Equal(0, await CountAsync(database, "audit_event"));
    }

    [Fact]
    public async Task Test_authenticator_returns_a_result_whose_Session_is_committed_for_that_User()
    {
        var database = await SeededDatabaseAsync();
        await using var hosted = Source(TableRegistry.Hosted, database);
        var authenticator = new TestOnlyAuthenticator(_sessions, new FixedTime(Now));

        AuthenticationResult result;
        StartedSession session;
        await using (var scope = await TenantScope.BeginAsync(hosted, TenantA, Cancellation))
        {
            var context = scope.CreateCommandContext();
            var started = await _authentication.BeginAsync(context, new SignInRequest(Application, Parameters), Cancellation);
            (result, session) = await authenticator.AuthenticateAsync(
                context, started.TransactionId, UserA, AuthTime, Cancellation);
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal(session.SessionId, result.SessionId);
        Assert.Equal(UserA, result.UserId);
        Assert.Equal([TestOnlyAuthenticator.Method], result.Amr);
        Assert.Equal(AuthTime, result.AuthTime);
        Assert.Equal(Now + SecurityLimits.UserSessionIdleDefault, session.IdleExpiresAt);
        Assert.Equal(Now + SecurityLimits.UserSessionAbsoluteDefault, session.AbsoluteExpiresAt);

        await using var connection = await OpenAsync(postgres.SuperuserConnection(database));
        await using (var command = new NpgsqlCommand(
            """
            SELECT tenant_id, id, user_id, id_hash, amr, auth_time, connection_id, idle_expires_at, absolute_expires_at,
                   created_at, ended_at, end_reason
            FROM user_session
            """,
            connection))
        await using (var reader = await command.ExecuteReaderAsync(Cancellation))
        {
            Assert.True(await reader.ReadAsync(Cancellation));
            Assert.Equal(TenantA, reader.GetGuid(0));
            Assert.Equal(result.SessionId, reader.GetGuid(1));
            Assert.Equal(UserA, reader.GetGuid(2));
            Assert.Equal(HashOf(session.Token), reader.GetFieldValue<byte[]>(3));
            Assert.Equal([TestOnlyAuthenticator.Method], reader.GetFieldValue<string[]>(4));
            Assert.Equal(AuthTime, reader.GetFieldValue<DateTimeOffset>(5));
            Assert.True(reader.IsDBNull(6));
            Assert.Equal(Now.AddDays(3), reader.GetFieldValue<DateTimeOffset>(7));
            Assert.Equal(Now.AddDays(7), reader.GetFieldValue<DateTimeOffset>(8));
            Assert.Equal(Now, reader.GetFieldValue<DateTimeOffset>(9));
            Assert.True(reader.IsDBNull(10));
            Assert.True(reader.IsDBNull(11));
            Assert.False(await reader.ReadAsync(Cancellation));
        }

        Assert.Equal(32, session.Token.Use(v => Base64Url.DecodeFromChars(v).Length));
        Assert.Equal(
            [
                $"{TenantA}|authentication.signin_transaction.started|anonymous|||",
                $"{TenantA}|sessions.session.started|user|{UserA}|user|{UserA}",
            ],
            await AuditEventsAsync(connection));
    }

    [Fact]
    public async Task Test_authenticator_refuses_a_transaction_of_another_Tenant()
    {
        var database = await SeededDatabaseAsync();
        await SeedChainAsync(database);
        await using var hosted = Source(TableRegistry.Hosted, database);
        var authenticator = new TestOnlyAuthenticator(_sessions, new FixedTime(Now));

        await using (var scope = await TenantScope.BeginAsync(hosted, TenantB, Cancellation))
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => authenticator.AuthenticateAsync(
                scope.CreateCommandContext(), TransactionA, UserB, AuthTime, Cancellation));
        }

        Assert.Equal(1, await CountAsync(database, "user_session"));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Unknown_user_fails_on_the_foreign_key_and_the_scope_rolls_back(bool userOfTenantB)
    {
        var database = await SeededDatabaseAsync();
        await using var hosted = Source(TableRegistry.Hosted, database);
        var authenticator = new TestOnlyAuthenticator(_sessions, new FixedTime(Now));
        var userId = userOfTenantB ? UserB : Guid.CreateVersion7();

        await using (var scope = await TenantScope.BeginAsync(hosted, TenantA, Cancellation))
        {
            var context = scope.CreateCommandContext();
            var started = await _authentication.BeginAsync(context, new SignInRequest(Application, Parameters), Cancellation);

            var error = await Assert.ThrowsAsync<PostgresException>(() => authenticator.AuthenticateAsync(
                context, started.TransactionId, userId, AuthTime, Cancellation));

            Assert.Equal(ForeignKeyViolation, error.SqlState);
        }

        Assert.Equal(0, await CountAsync(database, "user_session"));
        Assert.Equal(0, await CountAsync(database, "signin_transaction"));
        Assert.Equal(0, await CountAsync(database, "audit_event"));
    }

    [Theory]
    [MemberData(nameof(ShortHashInserts))]
    public async Task A_hash_that_isnt_32_bytes_is_refused(string insert)
    {
        var database = await SeededDatabaseAsync();

        var error = await Assert.ThrowsAsync<PostgresException>(
            () => PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), insert));

        Assert.Equal(CheckViolation, error.SqlState);
    }

    [Theory]
    [InlineData("pub_a1b2c3.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("short")]
    public async Task Token_reference_id_holds_only_an_obfuscated_hash(string raw)
    {
        var database = await SeededDatabaseAsync();
        await SeedChainAsync(database);

        var error = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"""
            INSERT INTO token (tenant_id, id, authorization_id, type, status, reference_id, concurrency_token)
            VALUES ('{TenantA}', gen_random_uuid(), '{AuthorizationA}', 'refresh_token', 'valid', '{raw}', gen_random_uuid())
            """));

        Assert.Equal(CheckViolation, error.SqlState);
    }

    [Theory]
    [MemberData(nameof(AllTables))]
    public async Task Hosted_sees_its_own_Tenants_row_and_none_of_another_Tenants(string table)
    {
        var database = await SeededDatabaseAsync();
        await SeedChainAsync(database);
        await using var hosted = Source(TableRegistry.Hosted, database);

        // Users exist in both Tenants, so count only Tenant A's.
        var sql = $"SELECT count(*) FROM \"{table}\" WHERE tenant_id = '{TenantA}'";

        Assert.Equal(1, await ScopedCountAsync(hosted, TenantA, sql));
        Assert.Equal(0, await ScopedCountAsync(hosted, TenantB, sql));
        Assert.Equal(0, await ScopedCountAsync(hosted, TenantB, $"SELECT count(*) FROM \"{table}\" WHERE tenant_id <> '{TenantB}'"));
    }

    [Theory]
    [MemberData(nameof(CrossTenantInserts))]
    public async Task Write_for_another_Tenant_is_refused_by_row_level_security(string role, string insert)
    {
        var database = await SeededDatabaseAsync();
        await SeedChainAsync(database);
        await using var source = Source(role, database);

        await using var scope = await TenantScope.BeginAsync(source, TenantB, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = insert;

        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));

        Assert.Equal(RowSecurityOrPermission, error.SqlState);
        Assert.Contains("row-level security", error.MessageText);
    }

    [Theory]
    [MemberData(nameof(HostedWritableTables))]
    public async Task Hosted_update_cant_reach_another_Tenants_row(string table)
    {
        var database = await SeededDatabaseAsync();
        await SeedChainAsync(database);
        await using var hosted = Source(TableRegistry.Hosted, database);

        await using var scope = await TenantScope.BeginAsync(hosted, TenantB, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = $"UPDATE \"{table}\" SET {UpdatableColumn(table)} = {UpdatableColumn(table)} WHERE tenant_id = '{TenantA}'";

        Assert.Equal(0, await command.ExecuteNonQueryAsync(Cancellation));
    }

    /// <summary>
    /// A column <c>gk_hosted</c> may update. From Story 2.9 it updates only some of <c>authorization</c>'s
    /// and <c>token</c>'s, never <c>tenant_id</c>.
    /// </summary>
    private static string UpdatableColumn(string table) => table is "authorization" or "token" ? "concurrency_token" : "tenant_id";

    [Theory]
    [MemberData(nameof(UngrantedRoles))]
    public async Task Roles_with_no_grant_cant_read(string role, string table)
    {
        var database = await SeededDatabaseAsync();
        await using var source = Source(role, database);

        await using var scope = await TenantScope.BeginAsync(source, TenantA, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = $"SELECT 1 FROM \"{table}\" LIMIT 1";

        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));

        Assert.Equal(RowSecurityOrPermission, error.SqlState);
        Assert.Contains("permission denied", error.MessageText);
    }

    [Theory]
    [MemberData(nameof(HostedRefusals))]
    public async Task Hosted_cant_delete_or_write_Users(string statement)
    {
        var database = await SeededDatabaseAsync();
        await using var hosted = Source(TableRegistry.Hosted, database);

        await using var scope = await TenantScope.BeginAsync(hosted, TenantA, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = statement;

        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));

        Assert.Equal(RowSecurityOrPermission, error.SqlState);
        Assert.Contains("permission denied", error.MessageText);
    }

    [Theory]
    [InlineData("null value")]
    [InlineData("NUL in key")]
    [InlineData("NUL in value")]
    [InlineData("over 16 KiB")]
    [InlineData("empty Application")]
    public async Task Begin_refuses_bad_arguments_and_writes_nothing(string bad)
    {
        var parameters = new Dictionary<string, string>(Parameters);
        var application = Application;
        switch (bad)
        {
            case "null value":
                parameters["state"] = null!;
                break;
            case "NUL in key":
                parameters["st\0ate"] = "x";
                break;
            case "NUL in value":
                parameters["state"] = "x\0y";
                break;
            case "over 16 KiB":
                parameters["state"] = new string('a', 16 * 1024);
                break;
            case "empty Application":
                application = Guid.Empty;
                break;
        }

        var database = await SeededDatabaseAsync();
        await using var hosted = Source(TableRegistry.Hosted, database);

        await using (var scope = await TenantScope.BeginAsync(hosted, TenantA, Cancellation))
        {
            await Assert.ThrowsAsync<ArgumentException>(() => _authentication.BeginAsync(
                scope.CreateCommandContext(), new SignInRequest(application, parameters), Cancellation));
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal(0, await CountAsync(database, "signin_transaction"));
        Assert.Equal(0, await CountAsync(database, "audit_event"));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Start_refuses_an_empty_User_or_a_blank_method_and_writes_nothing(bool emptyUser)
    {
        var database = await SeededDatabaseAsync();
        await using var hosted = Source(TableRegistry.Hosted, database);
        var session = emptyUser ? new NewSession(Guid.Empty, ["pwd"], AuthTime) : new NewSession(UserA, [" "], AuthTime);

        await using (var scope = await TenantScope.BeginAsync(hosted, TenantA, Cancellation))
        {
            await Assert.ThrowsAsync<ArgumentException>(
                () => _sessions.StartAsync(scope.CreateCommandContext(), session, Cancellation));
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal(0, await CountAsync(database, "user_session"));
        Assert.Equal(0, await CountAsync(database, "audit_event"));
    }

    [Fact]
    public async Task Returned_times_equal_the_stored_ones_on_a_sub_microsecond_clock()
    {
        // 7 ticks past a microsecond, so an untruncated value can't match the row.
        var clock = new FixedTime(Now.AddTicks(12_345_677));
        var sessions = SessionsContract.CreateSessions(AuditContract.CreateAppender(), clock);
        var authentication = AuthenticationContract.CreateAuthentication(AuditContract.CreateAppender(), clock);
        var authenticator = new TestOnlyAuthenticator(sessions, clock);

        var database = await SeededDatabaseAsync();
        await using var hosted = Source(TableRegistry.Hosted, database);

        AuthenticationResult result;
        StartedSession session;
        await using (var scope = await TenantScope.BeginAsync(hosted, TenantA, Cancellation))
        {
            var context = scope.CreateCommandContext();
            var started = await authentication.BeginAsync(context, new SignInRequest(Application, Parameters), Cancellation);
            (result, session) = await authenticator.AuthenticateAsync(
                context, started.TransactionId, UserA, AuthTime.AddTicks(3), Cancellation);
            await scope.CommitAsync(Cancellation);
        }

        var stored = await SessionTimesAsync(database);

        Assert.Equal(stored.AuthTime, session.AuthTime);
        Assert.Equal(stored.AuthTime, result.AuthTime);
        Assert.Equal(stored.IdleExpiresAt, session.IdleExpiresAt);
        Assert.Equal(stored.AbsoluteExpiresAt, session.AbsoluteExpiresAt);
        Assert.Equal(AuthTime, stored.AuthTime);
    }

    [Fact]
    public async Task Auth_time_at_another_offset_is_stored_as_the_same_instant()
    {
        var database = await SeededDatabaseAsync();
        await using var hosted = Source(TableRegistry.Hosted, database);
        var elsewhere = AuthTime.ToOffset(TimeSpan.FromHours(2));

        StartedSession session;
        await using (var scope = await TenantScope.BeginAsync(hosted, TenantA, Cancellation))
        {
            session = await _sessions.StartAsync(
                scope.CreateCommandContext(), new NewSession(UserA, ["pwd"], elsewhere), Cancellation);
            await scope.CommitAsync(Cancellation);
        }

        var stored = await SessionTimesAsync(database);

        Assert.Equal(TimeSpan.FromHours(2), elsewhere.Offset);
        Assert.Equal(AuthTime.UtcTicks, stored.AuthTime.UtcTicks);
        Assert.Equal(AuthTime.UtcTicks, session.AuthTime.UtcTicks);
    }

    [Fact]
    public async Task Test_authenticator_refuses_an_expired_transaction()
    {
        var database = await SeededDatabaseAsync();
        await using var hosted = Source(TableRegistry.Hosted, database);
        var later = new FixedTime(Now + SecurityLimits.SignInTransactionLifetime);
        var authenticator = new TestOnlyAuthenticator(_sessions, later);

        await using (var scope = await TenantScope.BeginAsync(hosted, TenantA, Cancellation))
        {
            var context = scope.CreateCommandContext();
            var started = await _authentication.BeginAsync(context, new SignInRequest(Application, Parameters), Cancellation);

            await Assert.ThrowsAsync<InvalidOperationException>(() => authenticator.AuthenticateAsync(
                context, started.TransactionId, UserA, AuthTime, Cancellation));
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal(1, await CountAsync(database, "signin_transaction"));
        Assert.Equal(0, await CountAsync(database, "user_session"));
    }

    [Theory]
    [MemberData(nameof(BrokenChecks))]
    public async Task Each_consistency_check_refuses_a_row_that_breaks_it(string statement)
    {
        var database = await SeededDatabaseAsync();
        await SeedChainAsync(database);

        var error = await Assert.ThrowsAsync<PostgresException>(
            () => PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), statement));

        Assert.Equal(CheckViolation, error.SqlState);
    }

    [Theory]
    [MemberData(nameof(HostedWritableTables))]
    public async Task Hosted_update_cant_move_a_row_to_another_Tenant(string table)
    {
        var database = await SeededDatabaseAsync();
        await SeedChainAsync(database);
        await using var hosted = Source(TableRegistry.Hosted, database);

        await using var scope = await TenantScope.BeginAsync(hosted, TenantA, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = $"UPDATE \"{table}\" SET tenant_id = '{TenantB}' WHERE tenant_id = '{TenantA}'";

        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));

        // Story 2.9: gk_hosted can't update an authorization's or token's tenant_id at all.
        Assert.Equal(RowSecurityOrPermission, error.SqlState);
        Assert.Contains(table is "authorization" or "token" ? "permission denied" : "row-level security", error.MessageText);
    }

    [Fact]
    public void Test_only_authenticator_lives_only_under_tests()
    {
        Assert.Equal(typeof(SessionTablesTests).Assembly, typeof(TestOnlyAuthenticator).Assembly);

        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (!File.Exists(Path.Combine(root.FullName, "Gatekeep.slnx")))
        {
            root = root.Parent ?? throw new InvalidOperationException("No Gatekeep.slnx above the test output.");
        }

        var offenders = Directory
            .EnumerateFiles(Path.Combine(root.FullName, "src"), "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(f => File.ReadAllText(f).Contains(nameof(TestOnlyAuthenticator), StringComparison.Ordinal));

        Assert.Empty(offenders);
    }

    private static byte[] HashOf(Secret<string> value) =>
        value.Use(v => SHA256.HashData(Encoding.ASCII.GetBytes(v)));

    private static Dictionary<string, string> ParametersOf(string json) =>
        System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json)!;

    private NpgsqlDataSource Source(string role, string database) =>
        NpgsqlDataSource.Create(postgres.RoleConnection(role, database));

    private async Task<string> SeededDatabaseAsync()
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"""
            {TestTenants.InsertSql(TenantA, TenantB)};
            INSERT INTO "user" (tenant_id, id) VALUES ('{TenantA}', '{UserA}'), ('{TenantB}', '{UserB}');
            {TestTenants.ApplicationSql(TenantA, Application)};
            {TestTenants.ApplicationSql(TenantB, Application)};
            """);

        return database;
    }

    /// <summary>One row in each Tenant A table, linked as the code flow will link them.</summary>
    private async Task SeedChainAsync(string database) =>
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"""
            INSERT INTO user_session (tenant_id, id, user_id, id_hash, amr, auth_time, idle_expires_at, absolute_expires_at, created_at)
            VALUES ('{TenantA}', '{SessionA}', '{UserA}', sha256('session-a'::bytea), ARRAY['pwd'],
                    now(), now() + interval '3 days', now() + interval '7 days', now());

            INSERT INTO "authorization" (tenant_id, id, application_id, user_session_id, subject, status, type, concurrency_token)
            VALUES ('{TenantA}', '{AuthorizationA}', '{Application}', '{SessionA}', '{UserA}', 'valid', 'ad-hoc', gen_random_uuid());

            INSERT INTO token (tenant_id, id, application_id, authorization_id, subject, type, status, reference_id, concurrency_token)
            VALUES ('{TenantA}', '{TokenA}', '{Application}', '{AuthorizationA}', '{UserA}', 'refresh_token', 'valid',
                    encode(sha256('token-a'::bytea), 'base64'), gen_random_uuid());

            INSERT INTO signin_transaction (tenant_id, id, application_id, binding_hash, parameters, created_at, expires_at)
            VALUES ('{TenantA}', '{TransactionA}', '{Application}', sha256('txn-a'::bytea), jsonb_build_object(),
                    now(), now() + interval '30 minutes');
            """);

    private static async Task<long> ScopedCountAsync(NpgsqlDataSource source, Guid tenantId, string sql)
    {
        await using var scope = await TenantScope.BeginAsync(source, tenantId, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = sql;

        return (long)(await command.ExecuteScalarAsync(Cancellation))!;
    }

    private async Task<long> CountAsync(string database, string table) =>
        await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), $"SELECT count(*) FROM \"{table}\"");

    private async Task<(DateTimeOffset AuthTime, DateTimeOffset IdleExpiresAt, DateTimeOffset AbsoluteExpiresAt)> SessionTimesAsync(
        string database)
    {
        await using var connection = await OpenAsync(postgres.SuperuserConnection(database));
        await using var command = new NpgsqlCommand(
            "SELECT auth_time, idle_expires_at, absolute_expires_at FROM user_session", connection);
        await using var reader = await command.ExecuteReaderAsync(Cancellation);

        Assert.True(await reader.ReadAsync(Cancellation));
        var times = (
            reader.GetFieldValue<DateTimeOffset>(0),
            reader.GetFieldValue<DateTimeOffset>(1),
            reader.GetFieldValue<DateTimeOffset>(2));
        Assert.False(await reader.ReadAsync(Cancellation));

        return times;
    }

    private static async Task<List<string>> AuditEventsAsync(NpgsqlConnection connection)
    {
        await using var command = new NpgsqlCommand(
            """
            SELECT concat_ws('|', tenant_id, type_code, actor_kind, coalesce(actor_id::text, ''),
                             coalesce(target_kind, ''), coalesce(target_id::text, ''))
            FROM audit_event
            ORDER BY type_code
            """,
            connection);

        var events = new List<string>();
        await using var reader = await command.ExecuteReaderAsync(Cancellation);
        while (await reader.ReadAsync(Cancellation))
        {
            events.Add(reader.GetString(0));
        }

        return events;
    }

    private static async Task<NpgsqlConnection> OpenAsync(string connectionString)
    {
        var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(Cancellation);
        return connection;
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
