using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.RateLimiting;
using Gatekeep.Modules.Authentication.Contracts;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.RateLimiting;

/// <summary>
/// Story 2.5 (AD-14): the Kernel <see cref="IRateLimiter"/> over the <c>UNLOGGED</c> <c>tenant_attempt</c>,
/// as <c>gk_hosted</c>, keyed by the context's Tenant under row-level security. Every attempt is
/// counted, refused ones too, in the caller's transaction.
/// </summary>
public sealed class TenantAttemptLimiterTests(PostgresFixture postgres)
{
    private const string PermissionDenied = "42501";

    private const string Subject = "203.0.113.7";

    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-0000000025a1");
    private static readonly Guid TenantB = Guid.Parse("01900000-0000-7000-8000-0000000025b1");

    private static readonly RateLimitPolicy TwoPerHour = new(AuthenticationContract.TokenRequestSourcePolicy.Code, 2, TimeSpan.FromHours(1));

    private readonly IRateLimiter _limiter = AuthenticationContract.CreateAttemptLimiter();

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public static TheoryData<string> OtherRoles =>
    [
        TableRegistry.Admin,
        TableRegistry.Worker,
        TableRegistry.Dispatch,
        TableRegistry.Sealer,
        TableRegistry.Retention,
        TableRegistry.Cli,
    ];

    [Fact]
    public async Task Each_Tenant_counts_the_same_subject_apart_and_refuses_past_the_limit()
    {
        var database = await DatabaseAsync();
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Hosted, database));

        Assert.True((await AttemptAsync(source, TenantA)).Allowed);
        Assert.True((await AttemptAsync(source, TenantA)).Allowed);
        var refused = await AttemptAsync(source, TenantA);
        Assert.False(refused.Allowed);
        Assert.InRange(refused.RetryAfter, TimeSpan.FromTicks(1), TimeSpan.FromHours(1));

        // Tenant B's count of the same subject is its own.
        Assert.True((await AttemptAsync(source, TenantB)).Allowed);

        Assert.Equal(3, await StoredAsync(database, TenantA));
        Assert.Equal(1, await StoredAsync(database, TenantB));
    }

    [Fact]
    public async Task The_table_is_unlogged_and_holds_only_the_subjects_hash()
    {
        var database = await DatabaseAsync();
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Hosted, database));
        await AttemptAsync(source, TenantA);

        Assert.Equal("u", await PostgresFixture.ScalarAsync<string>(
            postgres.SuperuserConnection(database), "SELECT relpersistence::text FROM pg_class WHERE relname = 'tenant_attempt'"));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(
            postgres.SuperuserConnection(database), $"SELECT count(*) FROM tenant_attempt r WHERE strpos(to_jsonb(r)::text, '{Subject}') > 0"));
    }

    [Fact]
    public async Task A_Deployment_scope_is_refused_and_writes_nothing()
    {
        var database = await DatabaseAsync();
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using var scope = await DeploymentScope.BeginAsync(source, Cancellation);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _limiter.AttemptAsync(scope.CreateCommandContext(), TwoPerHour, Subject, Cancellation));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM tenant_attempt"));
    }

    [Theory]
    [MemberData(nameof(OtherRoles))]
    public async Task No_other_runtime_role_may_count(string role)
    {
        var database = await DatabaseAsync();
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(role, database));
        await using var scope = await TenantScope.BeginAsync(source, TenantA, Cancellation);

        var error = await Assert.ThrowsAsync<PostgresException>(() =>
            _limiter.AttemptAsync(scope.CreateCommandContext(), TwoPerHour, Subject, Cancellation));
        Assert.Equal(PermissionDenied, error.SqlState);
    }

    [Theory]
    [InlineData("DELETE FROM tenant_attempt")]
    [InlineData("UPDATE tenant_attempt SET policy = 'authentication.token_request.tenant'")]
    [InlineData("UPDATE tenant_attempt SET subject_hash = sha256('x'::bytea)")]
    public async Task Hosted_may_not_delete_or_change_what_a_counter_counts(string statement)
    {
        var database = await DatabaseAsync();
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Hosted, database));
        await AttemptAsync(source, TenantA);
        await using var scope = await TenantScope.BeginAsync(source, TenantA, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = statement;

        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));
        Assert.Equal(PermissionDenied, error.SqlState);
    }

    private async Task<string> DatabaseAsync()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), TestTenants.InsertSql(TenantA, TenantB));
        return database;
    }

    private async Task<RateLimitDecision> AttemptAsync(NpgsqlDataSource source, Guid tenantId)
    {
        await using var scope = await TenantScope.BeginAsync(source, tenantId, Cancellation);
        var decision = await _limiter.AttemptAsync(scope.CreateCommandContext(), TwoPerHour, Subject, Cancellation);
        await scope.CommitAsync(Cancellation);
        return decision;
    }

    private async Task<int> StoredAsync(string database, Guid tenantId) =>
        await PostgresFixture.ScalarAsync<int>(
            postgres.SuperuserConnection(database),
            $"SELECT attempts FROM tenant_attempt WHERE tenant_id = '{tenantId}' AND policy = '{TwoPerHour.Code}' AND subject_hash = sha256(convert_to('{Subject}', 'UTF8'))");
}
