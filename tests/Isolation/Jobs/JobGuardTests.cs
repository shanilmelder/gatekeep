using Gatekeep.Adapters.Postgres.Migrations;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Jobs;
using Gatekeep.Modules.Operations.Contracts;
using System.Reflection;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using Npgsql;
using Xunit;
using static Gatekeep.Tests.Isolation.Jobs.JobDatabase;

namespace Gatekeep.Tests.Isolation.Jobs;

/// <summary>The <c>job</c> CHECK constraint and the generated insert guard (AD-15, TB-8).</summary>
public sealed class JobGuardTests(PostgresFixture postgres)
{
    private const string CheckViolation = "23514";
    private const string RaisedByTrigger = "P0001";
    private const string PermissionDenied = "42501";

    private const string BeginGuard = "-- BEGIN rendered guard";
    private const string EndGuard = "-- END rendered guard";

    private static readonly JobType Notification = new("notifications.email.send");
    private static readonly JobType Alert = new("alerts.security.send");
    private static readonly JobType DeploymentTask = new("tests.deployment.run");

    /// <summary>A registry shaped like the ones the alert and notification stories will add.</summary>
    private static readonly JobRegistry TestRegistry = new(
    [
        new JobDefinition(Notification, JobScope.Tenant, [JobRole.Hosted, JobRole.Worker], JobRole.Worker, 3, NoOp),
        new JobDefinition(Alert, JobScope.Tenant, [JobRole.Sealer], JobRole.Worker, 3, NoOp, neverDead: true),
        new JobDefinition(DeploymentTask, JobScope.DeploymentWide, [JobRole.Admin, JobRole.Cli], JobRole.Worker, 3, NoOp),
    ]);

    /// <summary>Roles the registry grants no <c>INSERT</c> on <c>job</c>, so they're refused before the guard runs.</summary>
    private static readonly string[] NoInsertGrant = [TableRegistry.Dispatch, TableRegistry.Retention];

    public static TheoryData<string, string> ProductionRolesByType => RolesByType(OperationsContract.ProductionRegistry);

    public static TheoryData<string, string> TestRolesByType => RolesByType(TestRegistry);

    public static TheoryData<string> TenantTables =>
        [.. TableRegistry.Tables.Where(t => t.Class == TableClass.Tenant).Select(t => t.Name)];

    [Fact]
    public void Latest_rendered_guard_migration_holds_the_render_of_the_production_registry()
    {
        // Forward-only: a registry change adds a migration with a new block, and the latest one counts.
        var block = typeof(MigrationsContext).Assembly.GetTypes()
            .Where(t => typeof(Migration).IsAssignableFrom(t) && !t.IsAbstract)
            .Select(t => (Id: t.GetCustomAttribute<MigrationAttribute>()!.Id, Sql: UpSql(t)))
            .Where(m => m.Sql.Contains(BeginGuard, StringComparison.Ordinal))
            .OrderBy(m => m.Id, StringComparer.Ordinal)
            .Select(m => GuardBlock(m.Sql))
            .LastOrDefault();

        Assert.NotNull(block);
        Assert.Equal(OperationsContract.RenderGuard(OperationsContract.ProductionRegistry).Trim(), block);
    }

    [Fact]
    public async Task Migrated_guard_is_the_production_render()
    {
        var database = await CreateAsync(postgres, registry: null);
        var render = OperationsContract.RenderGuard(OperationsContract.ProductionRegistry);
        var body = render[(render.IndexOf("$$", StringComparison.Ordinal) + 2)..render.LastIndexOf("$$", StringComparison.Ordinal)];

        var stored = await database.ScalarAsync<string>("SELECT prosrc FROM pg_proc WHERE proname = 'job_guard_insert'");

        Assert.Equal(body, stored.ReplaceLineEndings("\n"));
    }

    [Fact]
    public async Task Job_with_neither_a_Tenant_nor_deployment_wide_is_refused()
    {
        var database = await CreateAsync(postgres, TestRegistry);

        var error = await Assert.ThrowsAsync<PostgresException>(() => database.InScopeAsync(
            TableRegistry.Admin,
            null,
            $"INSERT INTO job (id, type, deployment_wide) VALUES (gen_random_uuid(), '{DeploymentTask}', false)"));

        Assert.Equal(CheckViolation, error.SqlState);
        Assert.Equal("job_tenant_or_deployment", error.ConstraintName);
    }

    [Fact]
    public async Task Job_with_both_a_Tenant_and_deployment_wide_is_refused()
    {
        var database = await CreateAsync(postgres, TestRegistry);

        var error = await Assert.ThrowsAsync<PostgresException>(() => database.InScopeAsync(
            TableRegistry.Worker,
            TenantA,
            $"INSERT INTO job (id, type, tenant_id, deployment_wide) VALUES (gen_random_uuid(), '{Notification}', '{TenantA}', true)"));

        Assert.Equal(CheckViolation, error.SqlState);
        Assert.Equal("job_tenant_or_deployment", error.ConstraintName);
    }

    [Fact]
    public async Task Scope_for_one_Tenant_cant_enqueue_for_another()
    {
        var database = await CreateAsync(postgres, TestRegistry);

        var error = await Assert.ThrowsAsync<PostgresException>(() => database.InScopeAsync(
            TableRegistry.Worker,
            TenantA,
            $"INSERT INTO job (id, type, tenant_id) VALUES (gen_random_uuid(), '{Notification}', '{TenantB}')"));

        Assert.Equal(RaisedByTrigger, error.SqlState);
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job"));
    }

    [Fact]
    public async Task Tenant_job_with_no_scope_raises()
    {
        var database = await CreateAsync(postgres, TestRegistry);

        await Assert.ThrowsAsync<PostgresException>(() => database.InScopeAsync(
            TableRegistry.Worker,
            null,
            $"INSERT INTO job (id, type, tenant_id) VALUES (gen_random_uuid(), '{Notification}', '{TenantA}')"));

        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job"));
    }

    [Fact]
    public async Task Tenant_scope_cant_enqueue_a_deployment_wide_job()
    {
        var database = await CreateAsync(postgres, TestRegistry);

        var error = await Assert.ThrowsAsync<PostgresException>(() => database.InScopeAsync(
            TableRegistry.Admin,
            TenantA,
            $"INSERT INTO job (id, type, deployment_wide) VALUES (gen_random_uuid(), '{DeploymentTask}', true)"));

        Assert.Equal(RaisedByTrigger, error.SqlState);
    }

    [Fact]
    public async Task Type_in_the_wrong_scope_is_refused()
    {
        var database = await CreateAsync(postgres, TestRegistry);

        var error = await Assert.ThrowsAsync<PostgresException>(() => database.InScopeAsync(
            TableRegistry.Worker,
            null,
            $"INSERT INTO job (id, type, deployment_wide) VALUES (gen_random_uuid(), '{Notification}', true)"));

        Assert.Equal(RaisedByTrigger, error.SqlState);
    }

    [Fact]
    public async Task Unknown_type_is_refused_by_the_production_guard()
    {
        var database = await CreateAsync(postgres, registry: null);

        var error = await Assert.ThrowsAsync<PostgresException>(() => database.InScopeAsync(
            TableRegistry.Worker,
            null,
            "INSERT INTO job (id, type, deployment_wide) VALUES (gen_random_uuid(), 'tests.unknown.type', true)"));

        Assert.Equal(RaisedByTrigger, error.SqlState);
    }

    [Fact]
    public async Task Guard_starts_every_job_unclaimed()
    {
        var database = await CreateAsync(postgres, TestRegistry);

        await database.InScopeAsync(
            TableRegistry.Admin,
            null,
            $"""
            INSERT INTO job (id, type, deployment_wide, status, attempts, locked_until, finished_at, failure_code)
            VALUES (gen_random_uuid(), '{DeploymentTask}', true, 'done', 7, now(), now(), 'timed_out')
            """);

        Assert.Equal(
            "pending|0|||",
            await database.ScalarAsync<string>(
                "SELECT concat_ws('|', status, attempts, coalesce(locked_until::text, ''), coalesce(finished_at::text, ''), coalesce(failure_code, '')) FROM job"));
    }

    [Theory]
    [MemberData(nameof(ProductionRolesByType))]
    public async Task Production_guard_lets_only_listed_roles_enqueue(string role, string type)
    {
        await AssertRoleMatrixCellAsync(await CreateAsync(postgres, registry: null), OperationsContract.ProductionRegistry, role, type);
    }

    [Theory]
    [MemberData(nameof(TestRolesByType))]
    public async Task Rendered_guard_lets_only_listed_roles_enqueue(string role, string type)
    {
        await AssertRoleMatrixCellAsync(await CreateAsync(postgres, TestRegistry), TestRegistry, role, type);
    }

    [Theory]
    [MemberData(nameof(TenantTables))]
    public async Task Dispatch_cant_read_any_tenant_table(string table)
    {
        var database = await CreateAsync(postgres, registry: null);

        var error = await Assert.ThrowsAsync<PostgresException>(
            () => database.InScopeAsync(TableRegistry.Dispatch, TenantA, $"SELECT 1 FROM {table} LIMIT 1"));

        Assert.Equal(PermissionDenied, error.SqlState);
    }

    [Fact]
    public async Task Payload_holds_only_named_IDs()
    {
        var database = await CreateAsync(postgres, TestRegistry);
        var job = Guid.CreateVersion7();
        await database.InScopeAsync(
            TableRegistry.Worker,
            TenantA,
            $"INSERT INTO job (id, type, tenant_id) VALUES ('{job}', '{Notification}', '{TenantA}')");

        var seventeen = "{" + string.Join(", ", Enumerable.Range(1, 17).Select(i => $"\"id_{i}\": \"{TenantB}\"")) + "}";

        foreach (var ids in new[] { seventeen, """{"email": "person@example.test"}""", """{"user_id": 5}""", """{"Bad": "01900000-0000-7000-8000-00000000000a"}""", "[]" })
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => database.InScopeAsync(
                TableRegistry.Worker,
                TenantA,
                $"INSERT INTO job_payload (tenant_id, job_id, ids) VALUES ('{TenantA}', '{job}', '{ids}')"));

            Assert.Equal(CheckViolation, error.SqlState);
        }

        var plain = await Assert.ThrowsAsync<PostgresException>(() => database.InScopeAsync(
            TableRegistry.Worker,
            TenantA,
            $"INSERT INTO job_payload (tenant_id, job_id, ciphertext) VALUES ('{TenantA}', '{job}', 'https://example.test/reset?token=x')"));
        Assert.Equal(CheckViolation, plain.SqlState);

        await database.InScopeAsync(
            TableRegistry.Worker,
            TenantA,
            $"INSERT INTO job_payload (tenant_id, job_id, ids) VALUES ('{TenantA}', '{job}', '{{\"user_id\": \"{TenantB}\"}}')");
    }

    private static async Task AssertRoleMatrixCellAsync(JobDatabase database, JobRegistry registry, string role, string type)
    {
        var definition = registry.Find(type)!;
        var enqueuer = OperationsContract.CreateEnqueuer(registry, custody: null);
        var tenant = definition.Scope == JobScope.Tenant ? TenantA : (Guid?)null;

        Task Enqueue() => database.InScopeAsync(role, tenant, context => definition.Scope == JobScope.Tenant
            ? enqueuer.EnqueueAsync(context, definition.Type, payload: null, runAfter: null, Cancellation)
            : enqueuer.EnqueueAsync(context, definition.Type, operationId: null, runAfter: null, Cancellation));

        if (definition.EnqueuingRoles.Contains(role))
        {
            await Enqueue();
            Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM job WHERE type = '{type}'"));
            return;
        }

        var error = await Assert.ThrowsAsync<PostgresException>(Enqueue);
        Assert.Equal(NoInsertGrant.Contains(role) ? PermissionDenied : RaisedByTrigger, error.SqlState);
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job"));
    }

    private static TheoryData<string, string> RolesByType(JobRegistry registry)
    {
        var data = new TheoryData<string, string>();
        foreach (var role in TableRegistry.RuntimeRoles)
        {
            foreach (var definition in registry.Definitions)
            {
                data.Add(role, definition.Type.Value);
            }
        }

        return data;
    }

    private static Task NoOp(JobRun run, CancellationToken cancellationToken) => Task.CompletedTask;

    private static string UpSql(Type migration) =>
        string.Concat(((Migration)Activator.CreateInstance(migration)!).UpOperations.OfType<SqlOperation>().Select(o => o.Sql))
            .ReplaceLineEndings("\n");

    private static string GuardBlock(string sql)
    {
        var start = sql.IndexOf(BeginGuard, StringComparison.Ordinal) + BeginGuard.Length;
        return sql[start..sql.IndexOf(EndGuard, start, StringComparison.Ordinal)].Trim();
    }
}
