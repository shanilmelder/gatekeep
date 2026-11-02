using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation;

public sealed class FailureContextTests(PostgresFixture postgres)
{
    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-00000000000a");

    private static readonly AuditEvent Refused = new(new AuditTypeCode("auth.signin.refused"), Actor.Anonymous);

    private readonly IAuditAppender _appender = AuditContract.CreateAppender();

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Refused_request_loses_its_state_and_keeps_the_effect_and_its_event()
    {
        var database = await TenantDatabaseAsync();
        await using var dataSource = AdminSource(database);

        await using (var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation))
        {
            await InsertSettingsAsync(scope.CreateCommandContext());

            await FailureContext.CommitAfterRollbackAsync(
                scope,
                (context, ct) => _appender.AppendAsync(context, Refused, null, ct));
        }

        Assert.Equal(0, await CountAsync(database, "tenant_settings"));
        Assert.Equal(1, await CountAsync(database, "audit_event"));
    }

    [Fact]
    public async Task Effect_sees_no_state_from_the_failed_transaction()
    {
        var database = await TenantDatabaseAsync();
        await using var dataSource = AdminSource(database);
        await using var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);
        await InsertSettingsAsync(scope.CreateCommandContext());

        await FailureContext.CommitAfterRollbackAsync(scope, async (context, ct) =>
        {
            // The key would collide if the failed insert were still in place.
            await InsertSettingsAsync(context);
        });

        Assert.Equal(1, await CountAsync(database, "tenant_settings"));
    }

    [Fact]
    public async Task Effect_runs_after_the_failed_transaction_hit_a_database_error()
    {
        var database = await TenantDatabaseAsync();
        await using var dataSource = AdminSource(database);
        await using var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);

        await using (var bad = scope.CreateCommandContext().CreateCommand())
        {
            bad.CommandText = "SELECT 1 / 0";
            await Assert.ThrowsAsync<PostgresException>(() => bad.ExecuteNonQueryAsync(Cancellation));
        }

        await FailureContext.CommitAfterRollbackAsync(
            scope,
            (context, ct) => _appender.AppendAsync(context, Refused, null, ct));

        Assert.Equal(1, await CountAsync(database, "audit_event"));
    }

    [Fact]
    public async Task Deployment_scope_gets_a_fresh_Deployment_scope()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using var dataSource = AdminSource(database);
        await using var scope = await DeploymentScope.BeginAsync(dataSource, Cancellation);
        Guid? seenTenant = Guid.NewGuid();

        await FailureContext.CommitAfterRollbackAsync(scope, async (context, ct) =>
        {
            seenTenant = context.TenantId;
            await _appender.AppendAsync(context, Refused, null, ct);
        });

        Assert.Null(seenTenant);
        Assert.Equal(1, await CountAsync(database, "deployment_audit_event"));
    }

    [Fact]
    public async Task Effect_keeps_the_Tenant_of_the_failed_scope()
    {
        var database = await TenantDatabaseAsync();
        await using var dataSource = AdminSource(database);
        await using var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);
        Guid? seenTenant = null;

        await FailureContext.CommitAfterRollbackAsync(scope, (context, _) =>
        {
            seenTenant = context.TenantId;
            return Task.CompletedTask;
        });

        Assert.Equal(TenantA, seenTenant);
    }

    [Fact]
    public async Task Cancelled_caller_cant_stop_the_effect()
    {
        var database = await TenantDatabaseAsync();
        await using var dataSource = AdminSource(database);
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(Cancellation);
        await using var scope = await TenantScope.BeginAsync(dataSource, TenantA, caller.Token);

        await caller.CancelAsync();

        await FailureContext.CommitAfterRollbackAsync(
            scope,
            (context, ct) => _appender.AppendAsync(context, Refused, null, ct));

        Assert.Equal(1, await CountAsync(database, "audit_event"));
    }

    [Fact]
    public async Task Effect_failure_surfaces_and_commits_nothing()
    {
        var database = await TenantDatabaseAsync();
        await using var dataSource = AdminSource(database);
        await using var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);

        await Assert.ThrowsAsync<TimeZoneNotFoundException>(() => FailureContext.CommitAfterRollbackAsync(
            scope,
            async (context, ct) =>
            {
                await _appender.AppendAsync(context, Refused, null, ct);
                throw new TimeZoneNotFoundException();
            }));

        Assert.Equal(0, await CountAsync(database, "audit_event"));
    }

    [Fact]
    public async Task Effect_that_hangs_is_stopped_by_the_limit()
    {
        var database = await TenantDatabaseAsync();
        await using var dataSource = AdminSource(database);
        await using var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => FailureContext.CommitAfterRollbackAsync(
            scope,
            async (context, ct) =>
            {
                await _appender.AppendAsync(context, Refused, null, ct);
                await Task.Delay(Timeout.Infinite, ct);
            }));

        Assert.Equal(0, await CountAsync(database, "audit_event"));
    }

    [Fact]
    public async Task Committed_scope_is_refused_and_the_effect_doesnt_run()
    {
        var database = await TenantDatabaseAsync();
        await using var dataSource = AdminSource(database);
        await using var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);
        await InsertSettingsAsync(scope.CreateCommandContext());
        await scope.CommitAsync(Cancellation);
        var ran = false;

        await Assert.ThrowsAsync<InvalidOperationException>(() => FailureContext.CommitAfterRollbackAsync(
            scope,
            (_, _) =>
            {
                ran = true;
                return Task.CompletedTask;
            }));

        Assert.False(ran);
        Assert.Equal(1, await CountAsync(database, "tenant_settings"));
    }

    [Fact]
    public async Task Disposed_scope_is_refused_and_the_effect_doesnt_run()
    {
        var database = await TenantDatabaseAsync();
        await using var dataSource = AdminSource(database);
        var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);
        await scope.DisposeAsync();
        var ran = false;

        await Assert.ThrowsAsync<InvalidOperationException>(() => FailureContext.CommitAfterRollbackAsync(
            scope,
            (_, _) =>
            {
                ran = true;
                return Task.CompletedTask;
            }));

        Assert.False(ran);
    }

    [Fact]
    public async Task Failed_scope_cant_be_used_after_the_rollback()
    {
        var database = await TenantDatabaseAsync();
        await using var dataSource = AdminSource(database);
        await using var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);
        var failedContext = scope.CreateCommandContext();

        await FailureContext.CommitAfterRollbackAsync(scope, (_, _) => Task.CompletedTask);

        Assert.Throws<InvalidOperationException>(() => failedContext.CreateCommand());
        await Assert.ThrowsAsync<InvalidOperationException>(() => scope.CommitAsync(Cancellation));
    }

    [Fact]
    public async Task Lost_connection_stops_the_effect_because_the_rollback_cant_be_confirmed()
    {
        var database = await TenantDatabaseAsync();
        await using var dataSource = AdminSource(database);
        await using var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);

        await using (var pid = scope.CreateCommandContext().CreateCommand())
        {
            pid.CommandText = "SELECT pg_backend_pid()";
            var backend = (int)(await pid.ExecuteScalarAsync(Cancellation))!;
            await PostgresFixture.ExecuteAsync(
                postgres.SuperuserConnection(database), $"SELECT pg_terminate_backend({backend})");
        }

        var ran = false;

        await Assert.ThrowsAnyAsync<Exception>(() => FailureContext.CommitAfterRollbackAsync(
            scope,
            (_, _) =>
            {
                ran = true;
                return Task.CompletedTask;
            }));

        Assert.False(ran);
    }

    private NpgsqlDataSource AdminSource(string database) =>
        NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));

    private async Task<string> TenantDatabaseAsync()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database), $"INSERT INTO tenant (id) VALUES ('{TenantA}')");
        return database;
    }

    private static async Task InsertSettingsAsync(CommandContext context)
    {
        await using var command = context.CreateCommand();
        command.CommandText = $"INSERT INTO tenant_settings (tenant_id) VALUES ('{TenantA}')";
        await command.ExecuteNonQueryAsync(Cancellation);
    }

    /// <summary>Counts as the superuser, which row-level security doesn't limit.</summary>
    private Task<long> CountAsync(string database, string table) =>
        PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), $"SELECT count(*) FROM {table}");
}
