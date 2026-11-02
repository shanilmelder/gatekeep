using System.Net;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Audit;

/// <summary>
/// One migrated database for chain tests: appends through the real writer path as
/// <c>gk_admin</c>, seals as <c>gk_sealer</c>, cuts and purges as <c>gk_retention</c>,
/// verifies as <c>gk_cli</c>, and tampers as the superuser with the triggers off.
/// </summary>
internal sealed class AuditChains
{
    public static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-00000000003a");
    public static readonly Guid TenantB = Guid.Parse("01900000-0000-7000-8000-00000000003b");

    private static readonly Guid AdminId = Guid.Parse("01900000-0000-7000-8000-0000000003a1");

    private readonly PostgresFixture _postgres;

    private AuditChains(PostgresFixture postgres, string name)
    {
        _postgres = postgres;
        Name = name;
    }

    public string Name { get; }

    public static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public string Superuser => _postgres.SuperuserConnection(Name);

    public static async Task<AuditChains> CreateAsync(PostgresFixture postgres, params Guid[] tenants)
    {
        var chains = new AuditChains(postgres, await postgres.NewMigratedDatabaseAsync());

        foreach (var tenant in tenants)
        {
            await chains.SuperuserAsync($"INSERT INTO tenant (id) VALUES ('{tenant}')");
        }

        return chains;
    }

    public string Connection(string role) => _postgres.RoleConnection(role, Name);

    public Task SuperuserAsync(string sql) => PostgresFixture.ExecuteAsync(Superuser, sql);

    public Task<T> ScalarAsync<T>(string sql) => PostgresFixture.ScalarAsync<T>(Superuser, sql);

    /// <summary>Runs <paramref name="work"/> as <paramref name="role"/> in the chain's own scope, then commits.</summary>
    public async Task<T> InScopeAsync<T>(string role, Guid? tenantId, Func<CommandContext, Task<T>> work)
    {
        await using var source = NpgsqlDataSource.Create(Connection(role));
        await using CommandScope scope = tenantId is { } id
            ? await TenantScope.BeginAsync(source, id, Cancellation)
            : await DeploymentScope.BeginAsync(source, Cancellation);

        var result = await work(scope.CreateCommandContext());
        await scope.CommitAsync(Cancellation);
        return result;
    }

    /// <summary>Appends <paramref name="count"/> events, each with detail, one transaction each.</summary>
    public async Task AppendAsync(Guid? tenantId, int count)
    {
        var appender = AuditContract.CreateAppender();

        for (var i = 0; i < count; i++)
        {
            await InScopeAsync(TableRegistry.Admin, tenantId, async context =>
            {
                await appender.AppendAsync(
                    context,
                    new AuditEvent(new AuditTypeCode("tenancy.settings.updated"), Actor.Admin(AdminId), AuditTargetKind.Tenant, tenantId ?? TenantA),
                    new AuditDetail(IPAddress.Parse("192.0.2.1"), "test-agent", "someone@example.test"),
                    Cancellation);
                return 0;
            });
        }
    }

    public Task<int> SealAsync(Guid? tenantId) =>
        InScopeAsync(TableRegistry.Sealer, tenantId, context => AuditContract.CreateSealer().SealAsync(context, 500, Cancellation));

    public Task<int> ApplyRetentionAsync(Guid? tenantId) =>
        InScopeAsync(TableRegistry.Retention, tenantId, context =>
            AuditContract.CreateRetention().ApplyAsync(context, Cancellation));

    public Task<bool> PurgeAsync(Guid tenantId) =>
        InScopeAsync(TableRegistry.Retention, tenantId, context =>
            AuditContract.CreateRetention().PurgeAsync(context, Cancellation));

    public Task<ChainReport> VerifyAsync(Guid? tenantId) =>
        InScopeAsync(TableRegistry.Cli, tenantId, context => AuditContract.CreateVerifier().VerifyAsync(context, Cancellation));

    /// <summary>
    /// Appends <paramref name="count"/> events, moves the ones at <paramref name="oldPositions"/>
    /// (1 up, in ID order) back 100 days, then seals, so <c>seq</c> follows the positions and every
    /// hash is over the time as stored. Only a superuser with the triggers off can backdate.
    /// </summary>
    public async Task SealedChainAsync(Guid? tenantId, int count, params int[] oldPositions)
    {
        await AppendAsync(tenantId, count);

        foreach (var position in oldPositions)
        {
            await SuperuserAsync(
                $"""
                SET session_replication_role = replica;
                UPDATE {EventTable(tenantId)} SET occurred_at = occurred_at - interval '100 days'
                WHERE id = (SELECT id FROM {EventTable(tenantId)} WHERE {TenantFilter(tenantId)} seq IS NULL ORDER BY id OFFSET {position - 1} LIMIT 1);
                """);
        }

        Assert.Equal(count, await SealAsync(tenantId));
    }

    public Task<long> CountAsync(string table, Guid? tenantId) =>
        ScalarAsync<long>($"SELECT count(*) FROM {table}{(tenantId is null ? string.Empty : $" WHERE tenant_id = '{tenantId}'")}");

    /// <summary>The <c>seq</c> of each sealed row, in order.</summary>
    public async Task<List<long>> SeqsAsync(Guid? tenantId) =>
        [.. (await ChainCheck.ReadAsync(Superuser, tenantId)).Select(r => r.Envelope.Seq)];

    public static string EventTable(Guid? tenantId) => tenantId is null ? "deployment_audit_event" : "audit_event";

    public static string DetailTable(Guid? tenantId) => tenantId is null ? "deployment_audit_detail" : "audit_detail";

    /// <summary>A <c>WHERE</c> prefix ending in <c>AND</c>, or nothing on the Deployment chain.</summary>
    public static string TenantFilter(Guid? tenantId) => tenantId is null ? string.Empty : $"tenant_id = '{tenantId}' AND";
}
