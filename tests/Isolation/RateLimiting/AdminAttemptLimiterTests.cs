using System.Security.Cryptography;
using System.Text;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.RateLimiting;
using Gatekeep.Modules.Admins.Contracts;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.RateLimiting;

/// <summary>
/// Story 1.20: the Kernel <see cref="IRateLimiter"/> over <c>admin_attempt</c>, as <c>gk_admin</c>.
/// Every attempt is counted, refused ones too, in the caller's transaction.
/// </summary>
public sealed class AdminAttemptLimiterTests(PostgresFixture postgres)
{
    private const string PermissionDenied = "42501";

    private const string SubjectK = "203.0.113.7";
    private const string SubjectL = "198.51.100.23";

    private static readonly TimeSpan Window = TimeSpan.FromHours(1);

    private static readonly RateLimitPolicy ThreePerHour = new("admins.bootstrap.claim", 3, Window);

    private readonly IRateLimiter _limiter = AdminsContract.CreateAttemptLimiter();

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public static TheoryData<string> OtherRoles =>
    [
        TableRegistry.Hosted,
        TableRegistry.Worker,
        TableRegistry.Dispatch,
        TableRegistry.Sealer,
        TableRegistry.Retention,
        TableRegistry.Cli,
    ];

    [Fact]
    public async Task Attempts_up_to_the_limit_are_allowed_and_counted()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using var dataSource = Source(TableRegistry.Admin, database);

        for (var attempt = 1; attempt <= 3; attempt++)
        {
            var decision = await AttemptAsync(dataSource, ThreePerHour, SubjectK);

            Assert.True(decision.Allowed);
            Assert.Equal(TimeSpan.Zero, decision.RetryAfter);
            Assert.Equal(attempt, await StoredAttemptsAsync(database, ThreePerHour, SubjectK));
        }
    }

    [Fact]
    public async Task Attempts_over_the_limit_are_refused_counted_and_saturate()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using var dataSource = Source(TableRegistry.Admin, database);
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            await AttemptAsync(dataSource, ThreePerHour, SubjectK);
        }

        foreach (var _ in new[] { 4, 5 })
        {
            var decision = await AttemptAsync(dataSource, ThreePerHour, SubjectK);

            Assert.False(decision.Allowed);
            Assert.InRange(decision.RetryAfter, TimeSpan.FromTicks(1), Window);
            // Counted, and saturated at limit + 1.
            Assert.Equal(4, await StoredAttemptsAsync(database, ThreePerHour, SubjectK));
        }
    }

    [Fact]
    public async Task Another_subject_is_counted_apart()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using var dataSource = Source(TableRegistry.Admin, database);
        for (var attempt = 1; attempt <= 4; attempt++)
        {
            await AttemptAsync(dataSource, ThreePerHour, SubjectK);
        }

        var decision = await AttemptAsync(dataSource, ThreePerHour, SubjectL);

        Assert.True(decision.Allowed);
        Assert.Equal(1, await StoredAttemptsAsync(database, ThreePerHour, SubjectL));
        Assert.Equal(4, await StoredAttemptsAsync(database, ThreePerHour, SubjectK));
        Assert.Equal(2L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM admin_attempt"));
    }

    [Fact]
    public async Task Another_policy_is_counted_apart()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using var dataSource = Source(TableRegistry.Admin, database);
        var other = new RateLimitPolicy("admins.signin.attempt", 3, Window);
        for (var attempt = 1; attempt <= 4; attempt++)
        {
            await AttemptAsync(dataSource, ThreePerHour, SubjectK);
        }

        Assert.True((await AttemptAsync(dataSource, other, SubjectK)).Allowed);
        Assert.Equal(1, await StoredAttemptsAsync(database, other, SubjectK));
    }

    [Fact]
    public async Task Elapsed_window_starts_again_at_one()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using var dataSource = Source(TableRegistry.Admin, database);
        for (var attempt = 1; attempt <= 4; attempt++)
        {
            await AttemptAsync(dataSource, ThreePerHour, SubjectK);
        }

        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            "UPDATE admin_attempt SET window_start = now() - interval '61 minutes'");

        var decision = await AttemptAsync(dataSource, ThreePerHour, SubjectK);

        Assert.True(decision.Allowed);
        Assert.Equal(1, await StoredAttemptsAsync(database, ThreePerHour, SubjectK));
        var age = await PostgresFixture.ScalarAsync<TimeSpan>(
            postgres.SuperuserConnection(database), "SELECT now() - window_start FROM admin_attempt");
        Assert.InRange(age, TimeSpan.Zero, TimeSpan.FromMinutes(1));
    }

    [Fact]
    public async Task Window_not_yet_elapsed_keeps_refusing_with_the_time_left()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using var dataSource = Source(TableRegistry.Admin, database);
        for (var attempt = 1; attempt <= 4; attempt++)
        {
            await AttemptAsync(dataSource, ThreePerHour, SubjectK);
        }

        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            "UPDATE admin_attempt SET window_start = now() - interval '50 minutes'");

        var decision = await AttemptAsync(dataSource, ThreePerHour, SubjectK);

        Assert.False(decision.Allowed);
        Assert.InRange(decision.RetryAfter, TimeSpan.FromMinutes(9), TimeSpan.FromMinutes(10));
    }

    [Fact]
    public async Task Count_made_in_a_refused_requests_effect_survives_its_rollback()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using var dataSource = Source(TableRegistry.Admin, database);

        await using (var scope = await DeploymentScope.BeginAsync(dataSource, Cancellation))
        {
            // Counted in the failed transaction: rolled back with it.
            await _limiter.AttemptAsync(scope.CreateCommandContext(), ThreePerHour, SubjectK, Cancellation);

            await FailureContext.CommitAfterRollbackAsync(
                scope,
                (context, ct) => _limiter.AttemptAsync(context, ThreePerHour, SubjectK, ct));
        }

        Assert.Equal(1, await StoredAttemptsAsync(database, ThreePerHour, SubjectK));
    }

    [Fact]
    public async Task Tenant_scope_is_refused_and_nothing_is_written()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using var dataSource = Source(TableRegistry.Admin, database);

        await using (var scope = await TenantScope.BeginAsync(dataSource, Guid.CreateVersion7(), Cancellation))
        {
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => _limiter.AttemptAsync(scope.CreateCommandContext(), ThreePerHour, SubjectK, Cancellation));

            // Nothing failed in the database, so the scope still commits: nothing was written.
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM admin_attempt"));
    }

    [Theory]
    [InlineData("", 3, 60)]
    [InlineData("bootstrap", 3, 60)]
    [InlineData("admins.bootstrap", 3, 60)]
    [InlineData("Admins.bootstrap.claim", 3, 60)]
    [InlineData("admins.bootstrap.claim.extra", 3, 60)]
    [InlineData("admins..claim", 3, 60)]
    [InlineData("admins.bootstrap.claim ", 3, 60)]
    [InlineData("admins.bootstrap.claim", 0, 60)]
    [InlineData("admins.bootstrap.claim", -1, 60)]
    [InlineData("admins.bootstrap.claim", int.MaxValue, 60)]
    [InlineData("admins.bootstrap.claim", 3, 0)]
    [InlineData("admins.bootstrap.claim", 3, -60)]
    // Under a second, or over 365 days.
    [InlineData("admins.bootstrap.claim", 3, 0.0000001)]
    [InlineData("admins.bootstrap.claim", 3, 0.999)]
    [InlineData("admins.bootstrap.claim", 3, 31_536_001)]
    [InlineData("admins.bootstrap.claim", 3, 1e11)]
    public void Bad_policy_is_refused_when_made(string code, int limit, double windowSeconds)
    {
        Assert.Throws<ArgumentException>(() => new RateLimitPolicy(code, limit, TimeSpan.FromSeconds(windowSeconds)));
    }

    [Fact]
    public void Overlong_policy_code_is_refused()
    {
        Assert.Throws<ArgumentException>(() => new RateLimitPolicy($"admins.{new string('a', 120)}.claim", 3, Window));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\t\r\n")]
    public async Task Empty_subject_is_refused_and_nothing_is_written(string subject)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using var dataSource = Source(TableRegistry.Admin, database);

        await Assert.ThrowsAsync<ArgumentException>(() => AttemptAsync(dataSource, ThreePerHour, subject));

        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM admin_attempt"));
    }

    [Fact]
    public async Task Subject_is_stored_only_as_its_SHA_256()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using var dataSource = Source(TableRegistry.Admin, database);
        const string credentialHandle = "canary-admin-attempt-subject-7c41";

        await AttemptAsync(dataSource, ThreePerHour, credentialHandle);

        await using var connection = new NpgsqlConnection(postgres.SuperuserConnection(database));
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand(
            "SELECT row_to_json(a)::text, subject_hash FROM admin_attempt a",
            connection);
        await using var reader = await command.ExecuteReaderAsync(Cancellation);
        Assert.True(await reader.ReadAsync(Cancellation));

        var row = reader.GetString(0);
        var hash = reader.GetFieldValue<byte[]>(1);
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(credentialHandle)), hash);
        Assert.Equal(32, hash.Length);
        Assert.DoesNotContain(credentialHandle, row);
        Assert.DoesNotContain(Convert.ToHexStringLower(Encoding.UTF8.GetBytes(credentialHandle)), row);
        Assert.False(await reader.ReadAsync(Cancellation));
    }

    [Fact]
    public async Task Concurrent_attempts_lose_no_count()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using var dataSource = Source(TableRegistry.Admin, database);
        var fivePerHour = new RateLimitPolicy("admins.signin.attempt", 5, Window);

        var decisions = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => AttemptAsync(dataSource, fivePerHour, SubjectK)));

        Assert.Equal(5, decisions.Count(d => d.Allowed));
        Assert.Equal(6, await StoredAttemptsAsync(database, fivePerHour, SubjectK));
    }

    [Theory]
    [MemberData(nameof(OtherRoles))]
    public async Task Only_gk_admin_can_count(string role)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using var dataSource = Source(role, database);

        var denied = await Assert.ThrowsAsync<PostgresException>(() => AttemptAsync(dataSource, ThreePerHour, SubjectK));

        Assert.Equal(PermissionDenied, denied.SqlState);
    }

    [Theory]
    [InlineData("UPDATE admin_attempt SET policy = 'admins.other.claim'")]
    [InlineData("UPDATE admin_attempt SET subject_hash = sha256('x'::bytea)")]
    [InlineData("DELETE FROM admin_attempt")]
    [InlineData("TRUNCATE admin_attempt")]
    public async Task Admin_cant_change_a_counters_key_or_remove_it(string sql)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using (var dataSource = Source(TableRegistry.Admin, database))
        {
            await AttemptAsync(dataSource, ThreePerHour, SubjectK);
        }

        var denied = await Assert.ThrowsAsync<PostgresException>(
            () => PostgresFixture.ExecuteAsync(postgres.RoleConnection(TableRegistry.Admin, database), sql));

        Assert.Equal(PermissionDenied, denied.SqlState);
    }

    [Theory]
    [InlineData("INSERT INTO admin_attempt VALUES ('admins.bootstrap.claim', sha256('x'::bytea), now(), 0)")]
    [InlineData("INSERT INTO admin_attempt VALUES ('admins.bootstrap.claim', 'short'::bytea, now(), 1)")]
    [InlineData("INSERT INTO admin_attempt VALUES ('203.0.113.7', sha256('x'::bytea), now(), 1)")]
    public async Task Schema_refuses_a_row_off_its_shape(string sql)
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        var refused = await Assert.ThrowsAsync<PostgresException>(
            () => PostgresFixture.ExecuteAsync(postgres.RoleConnection(TableRegistry.Admin, database), sql));

        Assert.Equal("23514", refused.SqlState);
    }

    private NpgsqlDataSource Source(string role, string database) =>
        NpgsqlDataSource.Create(postgres.RoleConnection(role, database));

    /// <summary>One attempt in its own Deployment scope, committed.</summary>
    private async Task<RateLimitDecision> AttemptAsync(NpgsqlDataSource dataSource, RateLimitPolicy policy, string subject)
    {
        await using var scope = await DeploymentScope.BeginAsync(dataSource, Cancellation);
        var decision = await _limiter.AttemptAsync(scope.CreateCommandContext(), policy, subject, Cancellation);
        await scope.CommitAsync(Cancellation);
        return decision;
    }

    private async Task<int> StoredAttemptsAsync(string database, RateLimitPolicy policy, string subject)
    {
        await using var connection = new NpgsqlConnection(postgres.SuperuserConnection(database));
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand(
            "SELECT attempts FROM admin_attempt WHERE policy = @policy AND subject_hash = @hash",
            connection);
        command.Parameters.AddWithValue("policy", policy.Code);
        command.Parameters.AddWithValue("hash", SHA256.HashData(Encoding.UTF8.GetBytes(subject)));
        return (int)(await command.ExecuteScalarAsync(Cancellation))!;
    }
}
