using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Story 1.21: <c>admin</c> and <c>admin_session</c> refuse what no code path should write, for
/// the owner too: one Deployment Owner, Session lifetimes within PRD §5.2's 8 hours, a 32-byte ID
/// hash, a known kind and end reason, an ending with its reason and not before the Session began,
/// and an ending written once.
/// </summary>
public sealed class AdminTablesTests(PostgresFixture postgres)
{
    private const string CheckViolation = "23514";
    private const string UniqueViolation = "23505";
    private const string Raised = "P0001";

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
