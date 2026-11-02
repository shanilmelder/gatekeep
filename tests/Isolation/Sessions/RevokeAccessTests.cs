using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Sessions.Contracts;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Sessions;

/// <summary>
/// Story 2.7: <see cref="ISessions.RevokeAccessAsync"/>, the one revocation path (AD-13). Each
/// test seeds the same rows, with the same IDs, in Tenants A and B, runs one revocation as
/// <c>gk_hosted</c> in Tenant A's scope, and compares every Session, family and token row
/// before and after.
/// </summary>
/// <remarks>
/// The seed in each Tenant: User U has Sessions S1, S2 and S3, and User V has S4. Families
/// (authorizations) are F1 on S1, F2 and F2b on S2, F3 on S3 and F4 on S4. F1, F2 and F4 belong to
/// Application A1, and F2b and F3 to A2. Each family has a refresh token (r) and an access token
/// (a). T1 and T2 are tokens of A1 and A2 with no family, as Client Credentials issues them.
/// </remarks>
public sealed class RevokeAccessTests(PostgresFixture postgres)
{
    private const string CheckViolation = "23514";

    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-00000000000a");
    private static readonly Guid TenantB = Guid.Parse("01900000-0000-7000-8000-00000000000b");

    private static readonly Guid UserU = Id(0x1001);
    private static readonly Guid UserV = Id(0x1002);
    private static readonly Guid S1 = Id(0x2001);
    private static readonly Guid S2 = Id(0x2002);
    private static readonly Guid S3 = Id(0x2003);
    private static readonly Guid S4 = Id(0x2004);
    private static readonly Guid F1 = Id(0x3001);
    private static readonly Guid F2 = Id(0x3002);
    private static readonly Guid F2b = Id(0x3012);
    private static readonly Guid F3 = Id(0x3003);
    private static readonly Guid F4 = Id(0x3004);
    private static readonly Guid A1 = Id(0x6001);
    private static readonly Guid A2 = Id(0x6002);

    /// <summary>Whole seconds, so a stored microsecond time compares exactly.</summary>
    private static readonly DateTimeOffset Now = new(2026, 11, 3, 12, 0, 0, TimeSpan.Zero);

    private static readonly (string Name, Guid Id, Guid Session, Guid Application)[] Families =
    [
        ("F1", F1, S1, A1),
        ("F2", F2, S2, A1),
        ("F2b", F2b, S2, A2),
        ("F3", F3, S3, A2),
        ("F4", F4, S4, A1),
    ];

    private static readonly Dictionary<Guid, string> Names = BuildNames();

    private readonly ISessions _sessions = SessionsContract.CreateSessions(AuditContract.CreateAppender(), new FixedTime(Now));

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public static TheoryData<string> ScopesOtherThanUser => ["Authorization", "Session", "Application", "Tenant"];

    public static TheoryData<string> ReasonCodes => [.. RevocationReason.All.Select(r => r.Code)];

    [Fact]
    public async Task User_scope_spares_the_acting_Session_and_its_families()
    {
        var database = await SeededDatabaseAsync();
        var before = await RowsAsync(database);

        var outcome = await RevokeAsync(database, new RevocationScope.User(UserU), S1, RevocationReason.CredentialChange);

        var after = await RowsAsync(database);

        Assert.Equal(new RevocationOutcome(2, 3, 6), outcome);
        AssertChanged(
            before,
            after,
            RevocationReason.CredentialChange,
            ["A:S2", "A:S3", "A:F2", "A:F2b", "A:F3", "A:F2r", "A:F2a", "A:F2br", "A:F2ba", "A:F3r", "A:F3a"]);
        Assert.Equal([$"{TenantA}|sessions.access.revoked|user|{UserU}|user|{UserU}"], await AuditEventsAsync(database));

        // The acting Session, and User V's Session and family, are untouched.
        Assert.All(
            new[] { "A:S1", "A:F1", "A:F1r", "A:F1a", "A:S4", "A:F4", "A:F4r", "A:F4a" },
            k => Assert.Equal(before[k], after[k]));
        Assert.Null(after["A:S4"].EndedAt);
        Assert.Equal("valid", after["A:F4"].Status);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Acting_Session_that_isnt_the_Users_throws_and_writes_nothing(bool anotherUsersSession)
    {
        var database = await SeededDatabaseAsync();
        var before = await RowsAsync(database);
        var except = anotherUsersSession ? S4 : Id(0x2999);

        await Assert.ThrowsAsync<ArgumentException>(
            () => RevokeAsync(database, new RevocationScope.User(UserU), except, RevocationReason.CredentialChange));

        Assert.Equal(before, await RowsAsync(database));
        Assert.Empty(await AuditEventsAsync(database));
    }

    [Fact]
    public async Task Session_scope_on_an_ended_Session_still_revokes_its_families()
    {
        var database = await SeededDatabaseAsync();
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"UPDATE user_session SET ended_at = now(), end_reason = 'logout' WHERE tenant_id = '{TenantA}' AND id = '{S2}'");
        var before = await RowsAsync(database);

        var outcome = await RevokeAsync(database, new RevocationScope.Session(S2), null, RevocationReason.AdminRevoke);

        Assert.Equal(new RevocationOutcome(0, 2, 4), outcome);
        AssertChanged(
            before,
            await RowsAsync(database),
            RevocationReason.AdminRevoke,
            ["A:F2", "A:F2b", "A:F2r", "A:F2a", "A:F2br", "A:F2ba"]);
    }

    [Fact]
    public async Task Application_scope_revokes_a_family_token_whose_own_Application_differs()
    {
        var database = await SeededDatabaseAsync();
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"""
            UPDATE token SET application_id = NULL WHERE tenant_id = '{TenantA}' AND id = '{TokenId("F1", "r")}';
            UPDATE token SET application_id = '{A2}' WHERE tenant_id = '{TenantA}' AND id = '{TokenId("F1", "a")}';
            """);
        var before = await RowsAsync(database);

        var outcome = await RevokeAsync(
            database, new RevocationScope.Application(A1), null, RevocationReason.ApplicationDeleted, Actor.System);

        Assert.Equal(new RevocationOutcome(0, 3, 7), outcome);
        AssertChanged(
            before,
            await RowsAsync(database),
            RevocationReason.ApplicationDeleted,
            ["A:F1", "A:F2", "A:F4", "A:F1r", "A:F1a", "A:F2r", "A:F2a", "A:F4r", "A:F4a", "A:T1"]);
    }

    [Theory]
    [InlineData("scope")]
    [InlineData("reason")]
    [InlineData("actor")]
    public async Task Null_argument_throws_and_writes_nothing(string missing)
    {
        var database = await SeededDatabaseAsync();
        var before = await RowsAsync(database);
        await using var hosted = Source(database);

        await using (var scope = await TenantScope.BeginAsync(hosted, TenantA, Cancellation))
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => _sessions.RevokeAccessAsync(
                scope.CreateCommandContext(),
                missing == "scope" ? null! : new RevocationScope.Tenant(),
                null,
                missing == "reason" ? null! : RevocationReason.AdminRevoke,
                missing == "actor" ? null! : Actor.System,
                Cancellation));
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal(before, await RowsAsync(database));
        Assert.Empty(await AuditEventsAsync(database));
    }

    [Fact]
    public async Task End_reason_check_holds_exactly_the_reason_codes()
    {
        var database = await SeededDatabaseAsync();

        await using var connection = new NpgsqlConnection(postgres.SuperuserConnection(database));
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'user_session_end_reason'", connection);
        var definition = (string)(await command.ExecuteScalarAsync(Cancellation))!;

        var codes = System.Text.RegularExpressions.Regex.Matches(definition, "'([^']*)'").Select(m => m.Groups[1].Value);

        Assert.Equal(RevocationReason.All.Select(r => r.Code).Order(), codes.Order());
    }

    [Fact]
    public async Task User_scope_with_no_acting_Session_ends_every_Session_of_the_User()
    {
        var database = await SeededDatabaseAsync();
        var before = await RowsAsync(database);

        var outcome = await RevokeAsync(database, new RevocationScope.User(UserU), null, RevocationReason.UserBlocked);

        Assert.Equal(new RevocationOutcome(3, 4, 8), outcome);
        AssertChanged(
            before,
            await RowsAsync(database),
            RevocationReason.UserBlocked,
            [
                "A:S1", "A:S2", "A:S3", "A:F1", "A:F2", "A:F2b", "A:F3",
                "A:F1r", "A:F1a", "A:F2r", "A:F2a", "A:F2br", "A:F2ba", "A:F3r", "A:F3a",
            ]);
    }

    [Fact]
    public async Task Authorization_scope_revokes_one_family_and_leaves_its_Session_live()
    {
        var database = await SeededDatabaseAsync();
        var before = await RowsAsync(database);

        var outcome = await RevokeAsync(
            database, new RevocationScope.Authorization(F1), null, RevocationReason.TokenReuse, Actor.Anonymous);

        Assert.Equal(new RevocationOutcome(0, 1, 2), outcome);
        AssertChanged(before, await RowsAsync(database), RevocationReason.TokenReuse, ["A:F1", "A:F1r", "A:F1a"]);
        Assert.Equal([$"{TenantA}|sessions.access.revoked|anonymous|||"], await AuditEventsAsync(database));
    }

    [Fact]
    public async Task Session_scope_ends_the_Session_and_both_its_families()
    {
        var database = await SeededDatabaseAsync();
        var before = await RowsAsync(database);

        var outcome = await RevokeAsync(database, new RevocationScope.Session(S2), null, RevocationReason.Logout);

        Assert.Equal(new RevocationOutcome(1, 2, 4), outcome);
        AssertChanged(
            before,
            await RowsAsync(database),
            RevocationReason.Logout,
            ["A:S2", "A:F2", "A:F2b", "A:F2r", "A:F2a", "A:F2br", "A:F2ba"]);
        Assert.Equal([$"{TenantA}|sessions.access.revoked|user|{UserU}||"], await AuditEventsAsync(database));
    }

    [Fact]
    public async Task Application_scope_revokes_only_that_Applications_families_and_tokens()
    {
        var database = await SeededDatabaseAsync();
        var before = await RowsAsync(database);

        var outcome = await RevokeAsync(
            database, new RevocationScope.Application(A1), null, RevocationReason.ApplicationDeleted, Actor.System);

        Assert.Equal(new RevocationOutcome(0, 3, 7), outcome);
        AssertChanged(
            before,
            await RowsAsync(database),
            RevocationReason.ApplicationDeleted,
            ["A:F1", "A:F2", "A:F4", "A:F1r", "A:F1a", "A:F2r", "A:F2a", "A:F4r", "A:F4a", "A:T1"]);
    }

    [Fact]
    public async Task Tenant_scope_ends_everything_in_its_Tenant_and_nothing_in_another()
    {
        var database = await SeededDatabaseAsync();
        var before = await RowsAsync(database);

        var outcome = await RevokeAsync(
            database, new RevocationScope.Tenant(), null, RevocationReason.TenantDeleted, Actor.System);

        Assert.Equal(new RevocationOutcome(4, 5, 12), outcome);
        AssertChanged(
            before,
            await RowsAsync(database),
            RevocationReason.TenantDeleted,
            [.. before.Keys.Where(k => k.StartsWith("A:", StringComparison.Ordinal))]);
        Assert.Contains(before.Keys, k => k.StartsWith("B:", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Another_Tenants_rows_with_the_same_IDs_are_untouched()
    {
        var database = await SeededDatabaseAsync();
        var before = await RowsAsync(database);

        await RevokeAsync(database, new RevocationScope.User(UserU), null, RevocationReason.AdminRevoke);

        var after = await RowsAsync(database);
        var tenantB = before.Keys.Where(k => k.StartsWith("B:", StringComparison.Ordinal)).ToList();

        Assert.Equal(21, tenantB.Count);
        Assert.All(tenantB, k => Assert.Equal(before[k], after[k]));
        Assert.Contains("B:S1", tenantB);
        Assert.Equal(0, await CountAsync(database, $"SELECT count(*) FROM audit_event WHERE tenant_id = '{TenantB}'"));
    }

    [Fact]
    public async Task Second_identical_call_changes_nothing_returns_zeros_and_still_audits()
    {
        var database = await SeededDatabaseAsync();
        await RevokeAsync(database, new RevocationScope.User(UserU), S1, RevocationReason.CredentialChange);
        var before = await RowsAsync(database);

        var outcome = await RevokeAsync(database, new RevocationScope.User(UserU), S1, RevocationReason.CredentialChange);

        Assert.Equal(new RevocationOutcome(0, 0, 0), outcome);
        Assert.Equal(before, await RowsAsync(database));
        Assert.Equal(2, (await AuditEventsAsync(database)).Count);
    }

    [Theory]
    [MemberData(nameof(ScopesOtherThanUser))]
    public async Task Acting_Session_with_a_scope_other_than_User_throws_and_writes_nothing(string kind)
    {
        RevocationScope scope = kind switch
        {
            "Authorization" => new RevocationScope.Authorization(F1),
            "Session" => new RevocationScope.Session(S2),
            "Application" => new RevocationScope.Application(A1),
            _ => new RevocationScope.Tenant(),
        };

        var database = await SeededDatabaseAsync();
        var before = await RowsAsync(database);

        await Assert.ThrowsAsync<ArgumentException>(
            () => RevokeAsync(database, scope, S1, RevocationReason.AdminRevoke));

        Assert.Equal(before, await RowsAsync(database));
        Assert.Empty(await AuditEventsAsync(database));
    }

    [Fact]
    public async Task Empty_acting_Session_throws_and_writes_nothing()
    {
        var database = await SeededDatabaseAsync();
        var before = await RowsAsync(database);

        await Assert.ThrowsAsync<ArgumentException>(
            () => RevokeAsync(database, new RevocationScope.User(UserU), Guid.Empty, RevocationReason.AdminRevoke));

        Assert.Equal(before, await RowsAsync(database));
        Assert.Empty(await AuditEventsAsync(database));
    }

    [Fact]
    public void Scopes_refuse_an_empty_ID()
    {
        Assert.Throws<ArgumentException>(() => new RevocationScope.Authorization(Guid.Empty));
        Assert.Throws<ArgumentException>(() => new RevocationScope.Session(Guid.Empty));
        Assert.Throws<ArgumentException>(() => new RevocationScope.User(Guid.Empty));
        Assert.Throws<ArgumentException>(() => new RevocationScope.Application(Guid.Empty));
    }

    [Fact]
    public async Task No_Tenant_throws_and_writes_nothing()
    {
        var database = await SeededDatabaseAsync();
        var before = await RowsAsync(database);
        await using var hosted = Source(database);

        await using (var scope = await DeploymentScope.BeginAsync(hosted, Cancellation))
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => _sessions.RevokeAccessAsync(
                scope.CreateCommandContext(),
                new RevocationScope.Tenant(),
                null,
                RevocationReason.TenantDeleted,
                Actor.System,
                Cancellation));
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal(before, await RowsAsync(database));
        Assert.Empty(await AuditEventsAsync(database));
        Assert.Equal(0, await CountAsync(database, "SELECT count(*) FROM deployment_audit_event"));
    }

    [Fact]
    public async Task Refused_request_still_commits_its_revocation_and_event_and_loses_its_other_writes()
    {
        var database = await SeededDatabaseAsync();
        var before = await RowsAsync(database);
        await using var hosted = Source(database);

        RevocationOutcome? outcome = null;
        await using (var scope = await TenantScope.BeginAsync(hosted, TenantA, Cancellation))
        {
            // The request's own write, which the refusal must roll back.
            await _sessions.StartAsync(scope.CreateCommandContext(), new NewSession(UserV, ["pwd"], Now), Cancellation);

            await FailureContext.CommitAfterRollbackAsync(scope, async (context, ct) =>
                outcome = await _sessions.RevokeAccessAsync(
                    context, new RevocationScope.Authorization(F3), null, RevocationReason.CodeReplay, Actor.Anonymous, ct));
        }

        Assert.Equal(new RevocationOutcome(0, 1, 2), outcome);
        AssertChanged(before, await RowsAsync(database), RevocationReason.CodeReplay, ["A:F3", "A:F3r", "A:F3a"]);
        Assert.Equal([$"{TenantA}|sessions.access.revoked|anonymous|||"], await AuditEventsAsync(database));
    }

    [Fact]
    public async Task An_end_reason_outside_the_closed_set_is_refused()
    {
        var database = await SeededDatabaseAsync();

        var error = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"UPDATE user_session SET ended_at = now(), end_reason = 'whatever' WHERE id = '{S1}'"));

        Assert.Equal(CheckViolation, error.SqlState);
        Assert.Equal("user_session_end_reason", error.ConstraintName);
    }

    [Theory]
    [MemberData(nameof(ReasonCodes))]
    public async Task Every_reason_code_is_accepted_as_an_end_reason(string code)
    {
        var database = await SeededDatabaseAsync();

        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"UPDATE user_session SET ended_at = now(), end_reason = '{code}' WHERE tenant_id = '{TenantA}' AND id = '{S1}'");

        Assert.Equal(
            1, await CountAsync(database, $"SELECT count(*) FROM user_session WHERE end_reason = '{code}'"));
    }

    [Fact]
    public void Reason_codes_are_the_fixed_snake_case_set()
    {
        Assert.Equal(
            [
                "logout", "credential_change", "admin_revoke", "user_blocked", "user_deleted",
                "token_reuse", "code_replay", "application_deleted", "tenant_deleted",
            ],
            RevocationReason.All.Select(r => r.Code));
    }

    private async Task<RevocationOutcome> RevokeAsync(
        string database,
        RevocationScope scope,
        Guid? except,
        RevocationReason reason,
        Actor? actor = null)
    {
        await using var hosted = Source(database);
        await using var tenantScope = await TenantScope.BeginAsync(hosted, TenantA, Cancellation);

        var outcome = await _sessions.RevokeAccessAsync(
            tenantScope.CreateCommandContext(), scope, except, reason, actor ?? Actor.User(UserU), Cancellation);
        await tenantScope.CommitAsync(Cancellation);

        return outcome;
    }

    /// <summary>
    /// Exactly <paramref name="expected"/> changed, each the way revocation changes it: a Session
    /// ended now with the reason, a family or token revoked with a new concurrency token.
    /// </summary>
    private static void AssertChanged(
        Dictionary<string, Row> before,
        Dictionary<string, Row> after,
        RevocationReason reason,
        string[] expected)
    {
        Assert.Equal(before.Keys.Order(), after.Keys.Order());

        var changed = before.Keys.Where(k => before[k] != after[k]).Order().ToList();
        Assert.Equal(expected.Order(), changed);

        foreach (var key in changed)
        {
            var row = after[key];
            if (row.Status is null)
            {
                Assert.Equal(Now, row.EndedAt);
                Assert.Equal(reason.Code, row.EndReason);
            }
            else
            {
                Assert.Equal("revoked", row.Status);
                Assert.NotEqual(before[key].Concurrency, row.Concurrency);
            }
        }
    }

    private NpgsqlDataSource Source(string database) =>
        NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Hosted, database));

    private async Task<string> SeededDatabaseAsync()
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        foreach (var tenant in new[] { TenantA, TenantB })
        {
            await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), SeedSql(tenant));
        }

        return database;
    }

    private static string SeedSql(Guid tenant)
    {
        var sql =
            $"""
            INSERT INTO tenant (id) VALUES ('{tenant}');
            INSERT INTO "user" (tenant_id, id) VALUES ('{tenant}', '{UserU}'), ('{tenant}', '{UserV}');

            """;

        foreach (var (session, user) in new[] { (S1, UserU), (S2, UserU), (S3, UserU), (S4, UserV) })
        {
            sql +=
                $"""
                INSERT INTO user_session (tenant_id, id, user_id, id_hash, amr, auth_time, idle_expires_at, absolute_expires_at, created_at)
                VALUES ('{tenant}', '{session}', '{user}', sha256('{session}'::bytea), ARRAY['pwd'],
                        now(), now() + interval '3 days', now() + interval '7 days', now());

                """;
        }

        foreach (var (name, id, session, application) in Families)
        {
            sql +=
                $"""
                INSERT INTO "authorization" (tenant_id, id, application_id, user_session_id, status, type, concurrency_token)
                VALUES ('{tenant}', '{id}', '{application}', '{session}', 'valid', 'ad-hoc', gen_random_uuid());

                INSERT INTO token (tenant_id, id, application_id, authorization_id, type, status, concurrency_token)
                VALUES ('{tenant}', '{TokenId(name, "r")}', '{application}', '{id}', 'refresh_token', 'valid', gen_random_uuid()),
                       ('{tenant}', '{TokenId(name, "a")}', '{application}', '{id}', 'access_token', 'valid', gen_random_uuid());

                """;
        }

        sql +=
            $"""
            INSERT INTO token (tenant_id, id, application_id, type, status, concurrency_token)
            VALUES ('{tenant}', '{Id(0x5001)}', '{A1}', 'access_token', 'valid', gen_random_uuid()),
                   ('{tenant}', '{Id(0x5002)}', '{A2}', 'access_token', 'valid', gen_random_uuid());
            """;

        return sql;
    }

    /// <summary>Every Session, family and token in both Tenants, keyed <c>{Tenant}:{name}</c>.</summary>
    private async Task<Dictionary<string, Row>> RowsAsync(string database)
    {
        await using var connection = new NpgsqlConnection(postgres.SuperuserConnection(database));
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand(
            """
            SELECT tenant_id, id, ended_at, end_reason, NULL::text, NULL::uuid FROM user_session
            UNION ALL
            SELECT tenant_id, id, NULL::timestamptz, NULL::text, status, concurrency_token FROM "authorization"
            UNION ALL
            SELECT tenant_id, id, NULL::timestamptz, NULL::text, status, concurrency_token FROM token
            """,
            connection);

        var rows = new Dictionary<string, Row>();
        await using var reader = await command.ExecuteReaderAsync(Cancellation);
        while (await reader.ReadAsync(Cancellation))
        {
            var tenant = reader.GetGuid(0) == TenantA ? "A" : "B";
            rows.Add(
                $"{tenant}:{Names[reader.GetGuid(1)]}",
                new Row(
                    reader.IsDBNull(2) ? null : reader.GetFieldValue<DateTimeOffset>(2),
                    reader.IsDBNull(3) ? null : reader.GetString(3),
                    reader.IsDBNull(4) ? null : reader.GetString(4),
                    reader.IsDBNull(5) ? null : reader.GetGuid(5)));
        }

        return rows;
    }

    private async Task<List<string>> AuditEventsAsync(string database)
    {
        await using var connection = new NpgsqlConnection(postgres.SuperuserConnection(database));
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand(
            """
            SELECT concat_ws('|', tenant_id, type_code, actor_kind, coalesce(actor_id::text, ''),
                             coalesce(target_kind, ''), coalesce(target_id::text, ''))
            FROM audit_event
            ORDER BY occurred_at, id
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

    private Task<long> CountAsync(string database, string sql) =>
        PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), sql);

    private static Guid Id(int n) => Guid.Parse($"01900000-0000-7000-8000-{n:x12}");

    private static Guid TokenId(string family, string kind) =>
        Id(0x4000 + (Array.FindIndex(Families, f => f.Name == family) * 2) + (kind == "r" ? 0 : 1));

    private static Dictionary<Guid, string> BuildNames()
    {
        var names = new Dictionary<Guid, string>
        {
            [S1] = "S1",
            [S2] = "S2",
            [S3] = "S3",
            [S4] = "S4",
            [Id(0x5001)] = "T1",
            [Id(0x5002)] = "T2",
        };

        foreach (var family in Families)
        {
            names[family.Id] = family.Name;
            names[TokenId(family.Name, "r")] = family.Name + "r";
            names[TokenId(family.Name, "a")] = family.Name + "a";
        }

        return names;
    }

    private sealed record Row(DateTimeOffset? EndedAt, string? EndReason, string? Status, Guid? Concurrency);

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
