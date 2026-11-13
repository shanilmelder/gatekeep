using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Tests.Isolation.Jobs;
using Xunit;
using static Gatekeep.Tests.Isolation.Jobs.JobDatabase;

namespace Gatekeep.Tests.Isolation.Operations;

/// <summary>
/// Story 3.5 (AD-1, AD-30): <c>directory.application.purge</c> through the real job path, as <c>gk_worker</c> in the
/// Tenant's own scope. Its one stage reads the Tenant's deleted Applications once and deletes, in owning-module order in
/// one transaction, their tokens and Token Families, sign-in transactions, then client secrets and the Applications,
/// and nothing else: not a kept or system Application's rows, no Session or User, and nothing of another Tenant. An
/// Application deleted after it ran is left for the next purge. A rerun deletes nothing more, and a row still
/// referencing what it deletes keeps nothing of the purge and fails <c>purge_conflict</c>, for a Retry.
/// </summary>
public sealed class ApplicationPurgeOperationTests(PostgresFixture postgres)
{
    private static readonly Guid Deleted = Guid.Parse("01900000-0000-7000-8000-0000000035d1");
    private static readonly Guid AlsoDeleted = Guid.Parse("01900000-0000-7000-8000-0000000035d2");
    private static readonly Guid Kept = Guid.Parse("01900000-0000-7000-8000-0000000035c1");
    private static readonly Guid System = Guid.Parse("01900000-0000-7000-8000-0000000035f1");

    private static readonly string[] Tables = ["token", "authorization", "signin_transaction", "client_secret", "application", "user_session", "user"];

    [Fact]
    public async Task Operation_purges_every_deleted_Application_of_the_Tenant_and_nothing_else()
    {
        var database = await SeededAsync();
        var keptRows = await RowsAsync(database, TenantA, Kept);
        var systemRows = await RowsAsync(database, TenantA, System);
        var tenantB = await TenantRowsAsync(database, TenantB);
        var sessions = await database.ScalarAsync<long>($"SELECT count(*) FROM user_session WHERE tenant_id = '{TenantA}'");

        var operation = await StartAsync(database, OperationsContract.ApplicationPurgeStages);
        await DrainAsync(database);

        Assert.Equal("succeeded", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
        Assert.Equal("succeeded", await StepsAsync(database, operation));

        foreach (var application in new[] { Deleted, AlsoDeleted })
        {
            Assert.Equal("0/0/0/0/0", await CountsAsync(database, TenantA, application));
        }

        Assert.Equal(keptRows, await RowsAsync(database, TenantA, Kept));
        Assert.Equal(systemRows, await RowsAsync(database, TenantA, System));
        Assert.Equal(sessions, await database.ScalarAsync<long>($"SELECT count(*) FROM user_session WHERE tenant_id = '{TenantA}'"));
        Assert.Equal(tenantB, await TenantRowsAsync(database, TenantB));

        // Tenant B's own deleted Application is left for its own purge.
        Assert.Equal("2/1/1/1/1", await CountsAsync(database, TenantB, Deleted));
    }

    [Fact]
    public async Task A_rerun_deletes_nothing_more_and_succeeds()
    {
        var database = await SeededAsync();
        var operation = await StartAsync(database, OperationsContract.ApplicationPurgeStages);
        await DrainAsync(database);
        var after = await TenantRowsAsync(database, TenantA);

        // Reopen every step, as a crash before its commit would have left it, and run the Operation again.
        await database.SuperuserAsync(
            $"UPDATE operation_step SET status = 'pending', result_code = NULL WHERE operation_id = '{operation}'; " +
            $"UPDATE operation SET status = 'running', finished_at = NULL WHERE id = '{operation}'; " +
            $"SET session_replication_role = replica; INSERT INTO job (id, type, deployment_wide, operation_id) VALUES (gen_random_uuid(), 'operations.operation.run', true, '{operation}'); " +
            "SET session_replication_role = DEFAULT");
        await DrainAsync(database);

        Assert.Equal("succeeded", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
        Assert.Equal("succeeded", await StepsAsync(database, operation));
        Assert.Equal(after, await TenantRowsAsync(database, TenantA));
    }

    [Fact]
    public async Task A_Tenant_with_no_deleted_Application_purges_nothing()
    {
        var database = await SeededAsync();
        await database.SuperuserAsync($"UPDATE application SET deleted_at = NULL WHERE tenant_id = '{TenantA}' AND kind <> 'system'");
        var before = await TenantRowsAsync(database, TenantA);

        var operation = await StartAsync(database, OperationsContract.ApplicationPurgeStages);
        await DrainAsync(database);

        Assert.Equal("succeeded", await StepsAsync(database, operation));
        Assert.Equal(before, await TenantRowsAsync(database, TenantA));
    }

    /// <summary>
    /// A row the purge doesn't delete that still references a deleted Application, as a token written while the stage
    /// ran would, is a conflict: here a superuser's table with the same <c>ON DELETE RESTRICT</c> reference. Nothing of
    /// the purge is kept, Sessions' and Authentication's deletes included, the step fails <c>purge_conflict</c>, and a
    /// Retry once the row is gone purges it all.
    /// </summary>
    [Fact]
    public async Task A_conflict_keeps_nothing_of_the_purge_and_a_Retry_finishes_it()
    {
        var database = await SeededAsync();
        var before = await TenantRowsAsync(database, TenantA);
        await database.SuperuserAsync($"""
            CREATE TABLE purge_conflict_ref (tenant_id uuid NOT NULL, application_id uuid NOT NULL,
              FOREIGN KEY (tenant_id, application_id) REFERENCES application (tenant_id, id) ON DELETE RESTRICT);
            INSERT INTO purge_conflict_ref VALUES ('{TenantA}', '{AlsoDeleted}');
            """);

        var operation = await StartAsync(database, OperationsContract.ApplicationPurgeStages);
        await DrainAsync(database);

        Assert.Equal("failed", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
        Assert.Equal("failed:purge_conflict", await StepsAsync(database, operation, withCodes: true));
        Assert.Equal(before, await TenantRowsAsync(database, TenantA));

        // The referencing row gone, the Retry runs the one step again, whole.
        await database.SuperuserAsync("DROP TABLE purge_conflict_ref");
        await database.InScopeAsync(TableRegistry.Admin, null, context =>
            OperationsContract.CreateOperations(OperationsContract.ProductionOperationRegistry).RetryAsync(context, operation, Cancellation));
        await DrainAsync(database);

        Assert.Equal("succeeded", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
        Assert.Equal("0/0/0/0/0", await CountsAsync(database, TenantA, Deleted));
        Assert.Equal("0/0/0/0/0", await CountsAsync(database, TenantA, AlsoDeleted));
    }

    /// <summary>
    /// The stage purges the deleted Applications its one read found, each with live rows in every module. One marked
    /// deleted after it ran is untouched in every module, hidden and revoked, and the next purge Operation removes it.
    /// </summary>
    [Fact]
    public async Task An_Application_deleted_after_the_purge_ran_is_left_whole_for_the_next_one()
    {
        var database = await SeededAsync();
        var first = await StartAsync(database, OperationsContract.ApplicationPurgeStages);
        await DrainAsync(database);
        Assert.Equal("succeeded", await StepsAsync(database, first));

        await database.SuperuserAsync($"UPDATE application SET deleted_at = now() WHERE tenant_id = '{TenantA}' AND id = '{Kept}'");
        Assert.Equal("3/1/1/1/1", await CountsAsync(database, TenantA, Kept, withLoose: true));

        var next = await StartAsync(database, OperationsContract.ApplicationPurgeStages);
        await DrainAsync(database);

        Assert.Equal("succeeded", await StepsAsync(database, next));
        Assert.Equal("0/0/0/0/0", await CountsAsync(database, TenantA, Kept, withLoose: true));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM application WHERE tenant_id = '{TenantA}'"));
    }

    [Fact]
    public async Task One_purge_is_active_per_Tenant()
    {
        var database = await SeededAsync();
        await StartAsync(database, OperationsContract.ApplicationPurgeStages);

        await Assert.ThrowsAsync<OperationAlreadyActiveException>(() => StartAsync(database, OperationsContract.ApplicationPurgeStages));

        // Another Tenant's starts on its own.
        await StartAsync(database, OperationsContract.ApplicationPurgeStages, TenantB);
    }

    /// <summary>
    /// Tenant A and B, each with: a deleted Application, a second deleted one in A, a kept one and A's system Application,
    /// every one but the system one with a secret, a User's Session with a Token Family holding a refresh and an access
    /// token, a family-less token, and a sign-in transaction. Only the system Application has none of them.
    /// </summary>
    private async Task<JobDatabase> SeededAsync()
    {
        var database = await CreateAsync(postgres, registry: null);
        foreach (var tenant in new[] { TenantA, TenantB })
        {
            var sql = $"INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{tenant}', '{System}', 'Account Portal', 'system', now());";
            foreach (var application in tenant == TenantA ? new[] { Deleted, AlsoDeleted, Kept } : [Deleted, Kept])
            {
                var user = Guid.CreateVersion7();
                var session = Guid.CreateVersion7();
                var family = Guid.CreateVersion7();
                sql += $"""

                    INSERT INTO application (tenant_id, id, name, kind, grant_types, created_at, deleted_at)
                    VALUES ('{tenant}', '{application}', 'App', 'web', ARRAY['authorization_code'], now(), {(application == Kept ? "NULL" : "now()")});
                    INSERT INTO client_secret (tenant_id, id, application_id, secret_hash, created_at)
                    VALUES ('{tenant}', gen_random_uuid(), '{application}', sha256(convert_to(gen_random_uuid()::text, 'UTF8')), now());
                    INSERT INTO "user" (tenant_id, id) VALUES ('{tenant}', '{user}');
                    INSERT INTO user_session (tenant_id, id, user_id, id_hash, amr, auth_time, idle_expires_at, absolute_expires_at, created_at)
                    VALUES ('{tenant}', '{session}', '{user}', sha256(convert_to('{session}', 'UTF8')), ARRAY['pwd'], now(), now() + interval '3 days', now() + interval '7 days', now());
                    INSERT INTO "authorization" (tenant_id, id, application_id, user_session_id, status, type, concurrency_token)
                    VALUES ('{tenant}', '{family}', '{application}', '{session}', 'revoked', 'ad-hoc', gen_random_uuid());
                    INSERT INTO token (tenant_id, id, application_id, authorization_id, type, status, concurrency_token)
                    VALUES ('{tenant}', gen_random_uuid(), '{application}', '{family}', 'refresh_token', 'revoked', gen_random_uuid()),
                           ('{tenant}', gen_random_uuid(), '{application}', '{family}', 'access_token', 'revoked', gen_random_uuid()),
                           ('{tenant}', gen_random_uuid(), '{application}', NULL, 'access_token', 'valid', gen_random_uuid());
                    INSERT INTO signin_transaction (tenant_id, id, application_id, binding_hash, parameters, created_at, expires_at)
                    VALUES ('{tenant}', gen_random_uuid(), '{application}', sha256(convert_to(gen_random_uuid()::text, 'UTF8')), jsonb_build_object(), now(), now() + interval '10 minutes');
                    """;
            }

            await database.SuperuserAsync(sql);
        }

        return database;
    }

    private static async Task<Guid> StartAsync(JobDatabase database, IReadOnlyList<OperationCode> stages, Guid? tenant = null)
    {
        var id = tenant ?? TenantA;
        var started = await database.InScopeAsync(TableRegistry.Admin, null, context =>
            OperationsContract.CreateOperations(OperationsContract.ProductionOperationRegistry).StartAsync(
                context,
                OperationsContract.ApplicationPurgeOperation,
                id,
                [.. stages.Select(stage => new OperationStepPlan(stage, id))],
                Cancellation));
        return started.Id;
    }

    private static async Task DrainAsync(JobDatabase database)
    {
        await using var runner = database.Runner(OperationsContract.ProductionRegistry);
        while (await runner.RunOnceAsync(Cancellation))
        {
        }
    }

    private static Task<string> StepsAsync(JobDatabase database, Guid operation, bool withCodes = false) =>
        database.ScalarAsync<string>(
            "SELECT string_agg(status" + (withCodes ? " || CASE WHEN status = 'failed' THEN ':' || coalesce(result_code, '') ELSE '' END" : string.Empty) +
            $", '/' ORDER BY position) FROM operation_step WHERE operation_id = '{operation}'");

    /// <summary>The Application's tokens, families, transactions, secrets and its own row, counted, as <c>t/a/s/c/1</c>.</summary>
    private static Task<string> CountsAsync(JobDatabase database, Guid tenant, Guid application, bool withLoose = false) =>
        database.ScalarAsync<string>($"""
            SELECT concat_ws('/',
              (SELECT count(*) FROM token WHERE tenant_id = '{tenant}' AND application_id = '{application}'{(withLoose ? "" : " AND authorization_id IS NOT NULL")}),
              (SELECT count(*) FROM "authorization" WHERE tenant_id = '{tenant}' AND application_id = '{application}'),
              (SELECT count(*) FROM signin_transaction WHERE tenant_id = '{tenant}' AND application_id = '{application}'),
              (SELECT count(*) FROM client_secret WHERE tenant_id = '{tenant}' AND application_id = '{application}'),
              (SELECT count(*) FROM application WHERE tenant_id = '{tenant}' AND id = '{application}'))
            """);

    /// <summary>Every row of the Application in the purged tables, as text, to compare before and after.</summary>
    private static Task<string> RowsAsync(JobDatabase database, Guid tenant, Guid application) =>
        database.ScalarAsync<string>($"""
            SELECT concat_ws('|',
              (SELECT string_agg(to_jsonb(t)::text, ',' ORDER BY id) FROM token t WHERE tenant_id = '{tenant}' AND application_id = '{application}'),
              (SELECT string_agg(to_jsonb(a)::text, ',' ORDER BY id) FROM "authorization" a WHERE tenant_id = '{tenant}' AND application_id = '{application}'),
              (SELECT string_agg(to_jsonb(s)::text, ',' ORDER BY id) FROM signin_transaction s WHERE tenant_id = '{tenant}' AND application_id = '{application}'),
              (SELECT string_agg(to_jsonb(c)::text, ',' ORDER BY id) FROM client_secret c WHERE tenant_id = '{tenant}' AND application_id = '{application}'),
              (SELECT to_jsonb(p)::text FROM application p WHERE tenant_id = '{tenant}' AND id = '{application}'))
            """);

    /// <summary>Every row of the Tenant in the purged tables and the Sessions and Users, as text.</summary>
    private static Task<string> TenantRowsAsync(JobDatabase database, Guid tenant) =>
        database.ScalarAsync<string>(
            "SELECT concat_ws('|', " +
            string.Join(", ", Tables.Select(t => $"(SELECT string_agg(to_jsonb(r)::text, ',' ORDER BY r.id) FROM \"{t}\" r WHERE r.tenant_id = '{tenant}')")) +
            ")");
}
