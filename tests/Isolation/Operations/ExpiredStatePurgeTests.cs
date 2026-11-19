using System.Collections;
using System.Reflection;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Modules.Sessions.Contracts;
using Gatekeep.Tests.Isolation.Jobs;
using Xunit;
using static Gatekeep.Tests.Isolation.Jobs.JobDatabase;

namespace Gatekeep.Tests.Isolation.Operations;

/// <summary>
/// Story 4.3 (FR-8, NFR-3, AD-13, AD-15): the hourly purge of expired sign-in state through the real job path, as
/// <c>gk_worker</c>. The Deployment-wide sweep enqueues one purge per active Tenant in that Tenant's own scope, never a
/// second while one waits, and deletes nothing. Each purge, in its Tenant's scope and one transaction, deletes expired
/// tokens, then Token Families with no token, then Sessions that are over and anchor no family, then transactions more
/// than an hour past expiry, and writes one System event; a rerun deletes nothing and writes nothing.
/// </summary>
public sealed class ExpiredStatePurgeTests(PostgresFixture postgres)
{
    private static readonly Guid Application = Guid.Parse("01900000-0000-7000-8000-0000000043a1");

    private static readonly Guid Deleting = Guid.Parse("01900000-0000-7000-8000-0000000043dd");

    private static readonly string Purged = SessionsEvents.ExpiredStatePurged.Code.Value;

    /// <summary>Every seeded row's label, by table, that the purge must keep.</summary>
    private static readonly Dictionary<string, string[]> Kept = new(StringComparer.Ordinal)
    {
        ["token"] = ["live-family-refresh", "shared-live-refresh", "loose-unexpiring"],
        ["authorization"] = ["live-family", "shared-live"],
        ["user_session"] = ["idle-expired-with-live-family", "over-with-live-family", "live-no-family", "live-dead-family"],
        ["signin_transaction"] = ["in-retention", "live"],
        // Story 4.7: a verification link goes an hour past its expiry, not before.
        ["one_time_token"] = ["link-in-retention", "link-live"],
    };

    [Fact]
    public void Types_are_registered_scheduled_hourly_and_run_as_gk_worker()
    {
        var sweep = OperationsContract.ProductionRegistry.Find(OperationsContract.SweepExpiredState)!;
        var purge = OperationsContract.ProductionRegistry.Find(OperationsContract.PurgeExpiredState)!;

        Assert.Equal(("sessions.expired_state.sweep", JobScope.DeploymentWide, TableRegistry.Worker), (sweep.Type.Value, sweep.Scope, sweep.RunAs));
        Assert.Equal(("sessions.expired_state.purge", JobScope.Tenant, TableRegistry.Worker), (purge.Type.Value, purge.Scope, purge.RunAs));
        Assert.Equal(new[] { TableRegistry.Worker }, sweep.EnqueuingRoles);
        Assert.Equal(new[] { TableRegistry.Worker }, purge.EnqueuingRoles);
        Assert.NotNull(sweep.Review);
        Assert.NotNull(purge.Review);

        // Host.Worker's code-owned schedule, read from the assembly the Worker runs as: the sweep, hourly.
        var worker = Assembly.LoadFrom(BuildOutput.AssemblyPath("Gatekeep.Host.Worker", "Gatekeep.Host.Worker"));
        var schedule = worker.GetType("Gatekeep.Host.Worker.JobSchedule", throwOnError: true)!;
        var entries = ((IEnumerable)schedule.GetField("Entries", BindingFlags.Public | BindingFlags.Static)!.GetValue(null)!).Cast<object>()
            .Select(e => (Type: e.GetType().GetProperty("Type")!.GetValue(e)!.ToString(), Interval: (TimeSpan)e.GetType().GetProperty("Interval")!.GetValue(e)!))
            .ToList();
        Assert.Contains(("sessions.expired_state.sweep", TimeSpan.FromHours(1)), entries);
    }

    /// <summary>A Tenant no longer active is its deletion's to purge: the sweep skips it, and a purge queued before it ran leaves it alone.</summary>
    [Fact]
    public async Task Deleting_Tenant_gets_no_purge_and_a_queued_one_deletes_nothing()
    {
        var database = await CreateAsync(postgres, registry: null);
        await TestTenants.InsertAsync(postgres.SuperuserConnection(database.Name), Deleting);
        await SeedAsync(database, Deleting);
        var queued = await EnqueuePurgeAsync(database, Deleting);
        await database.SuperuserAsync(
            $"SET session_replication_role = replica; UPDATE tenant SET status = 'deleting' WHERE id = '{Deleting}'; SET session_replication_role = DEFAULT");
        var before = await SnapshotAsync(database, Deleting);

        await EnqueueSweepAsync(database);
        await DrainAsync(database);

        Assert.Equal("done", await database.StatusAsync(queued));
        Assert.Equal(1L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM job WHERE tenant_id = '{Deleting}' AND type = '{OperationsContract.PurgeExpiredState.Value}'"));
        Assert.Equal(before, await SnapshotAsync(database, Deleting));
        Assert.Equal(0L, await EventsAsync(database, Deleting));
    }

    [Fact]
    public async Task Sweep_enqueues_no_second_purge_while_one_is_running()
    {
        var database = await CreateAsync(postgres, registry: null);
        var running = await EnqueuePurgeAsync(database, TenantA);
        await database.SuperuserAsync(
            $"UPDATE job SET status = 'running', attempts = 1, locked_until = now() + interval '1 hour' WHERE id = '{running}'");

        var sweep = await EnqueueSweepAsync(database);
        await using (var runner = database.Runner(OperationsContract.ProductionRegistry))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        Assert.Equal("done", await database.StatusAsync(sweep));
        Assert.Equal(1L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM job WHERE tenant_id = '{TenantA}' AND type = '{OperationsContract.PurgeExpiredState.Value}'"));
        Assert.Equal(1L, await PendingPurgesAsync(database, TenantB));
    }

    /// <summary>
    /// The cutoffs are inclusive, against the job's clock: a token expiring exactly at it goes, and a transaction expired
    /// exactly <see cref="Gatekeep.Kernel.Limits.SecurityLimits.SignInRestartRetention"/> before it goes, while ones a
    /// second younger stay.
    /// </summary>
    [Fact]
    public async Task Cutoffs_are_inclusive_at_the_jobs_clock()
    {
        var database = await CreateAsync(postgres, registry: null);
        var now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var cutoff = now - Gatekeep.Kernel.Limits.SecurityLimits.SignInRestartRetention;
        string At(DateTimeOffset time) => $"'{time.UtcDateTime:yyyy-MM-dd HH:mm:ss}+00'::timestamptz";
        var (atNow, youngerToken, atCutoff, youngerTransaction) = (Guid.CreateVersion7(), Guid.CreateVersion7(), Guid.CreateVersion7(), Guid.CreateVersion7());

        await database.SuperuserAsync($"""
            INSERT INTO application (tenant_id, id, name, kind, grant_types, created_at) VALUES ('{TenantA}', '{Application}', 'App', 'web', ARRAY['authorization_code'], now());
            INSERT INTO token (tenant_id, id, application_id, type, status, expiration_date, concurrency_token)
            VALUES ('{TenantA}', '{atNow}', '{Application}', 'access_token', 'valid', {At(now)}, gen_random_uuid()),
                   ('{TenantA}', '{youngerToken}', '{Application}', 'access_token', 'valid', {At(now.AddSeconds(1))}, gen_random_uuid());
            INSERT INTO signin_transaction (tenant_id, id, application_id, binding_hash, parameters, created_at, expires_at)
            VALUES ('{TenantA}', '{atCutoff}', '{Application}', sha256(convert_to('{atCutoff}', 'UTF8')), jsonb_build_object(), {At(cutoff.AddMinutes(-30))}, {At(cutoff)}),
                   ('{TenantA}', '{youngerTransaction}', '{Application}', sha256(convert_to('{youngerTransaction}', 'UTF8')), jsonb_build_object(), {At(cutoff.AddMinutes(-30))}, {At(cutoff.AddSeconds(1))});
            """);

        await EnqueuePurgeAsync(database, TenantA);
        await using (var runner = database.Runner(OperationsContract.ProductionRegistry, options: FastOptions with { Time = new FixedTime(now) }))
        {
            while (await runner.RunOnceAsync(Cancellation))
            {
            }
        }

        Assert.Equal(new[] { youngerToken }, await IdsAsync(database, TenantA, "token"));
        Assert.Equal(new[] { youngerTransaction }, await IdsAsync(database, TenantA, "signin_transaction"));
        Assert.Equal(1L, await EventsAsync(database, TenantA));
    }

    /// <summary>Every matrix row, in two Tenants: each purged by its own job, which touches no row of the other.</summary>
    [Fact]
    public async Task Sweep_enqueues_one_purge_per_Tenant_and_each_purges_only_its_own_expired_state()
    {
        var database = await CreateAsync(postgres, registry: null);
        var seeds = new Dictionary<Guid, Dictionary<string, Guid>>
        {
            [TenantA] = await SeedAsync(database, TenantA),
            [TenantB] = await SeedAsync(database, TenantB),
        };
        var before = new Dictionary<Guid, string>
        {
            [TenantA] = await SnapshotAsync(database, TenantA),
            [TenantB] = await SnapshotAsync(database, TenantB),
        };

        await EnqueueSweepAsync(database);
        await using (var runner = database.Runner(OperationsContract.ProductionRegistry))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        // The sweep deleted nothing and left one purge waiting in each Tenant's own scope.
        Assert.Equal(before[TenantA], await SnapshotAsync(database, TenantA));
        Assert.Equal(before[TenantB], await SnapshotAsync(database, TenantB));
        Assert.Equal(1L, await PendingPurgesAsync(database, TenantA));
        Assert.Equal(1L, await PendingPurgesAsync(database, TenantB));

        // A second sweep while they wait enqueues no second one. They're held back, so the runner claims the sweep.
        var purges = $"type = '{OperationsContract.PurgeExpiredState.Value}'";
        await database.SuperuserAsync($"UPDATE job SET run_after = now() + interval '1 hour' WHERE {purges}");
        var sweep = await EnqueueSweepAsync(database);
        await using (var runner = database.Runner(OperationsContract.ProductionRegistry))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        Assert.Equal("done", await database.StatusAsync(sweep));
        Assert.Equal(1L, await PendingPurgesAsync(database, TenantA));
        Assert.Equal(1L, await PendingPurgesAsync(database, TenantB));
        await database.SuperuserAsync($"UPDATE job SET run_after = now() WHERE {purges}");

        // One purge runs: its Tenant is purged, and the other's rows are untouched.
        await using (var runner = database.Runner(OperationsContract.ProductionRegistry))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        var first = await database.ScalarAsync<Guid>(
            $"SELECT tenant_id FROM job WHERE type = '{OperationsContract.PurgeExpiredState.Value}' AND status = 'done'");
        var other = first == TenantA ? TenantB : TenantA;
        await AssertPurgedAsync(database, first, seeds[first]);
        Assert.Equal(before[other], await SnapshotAsync(database, other));
        Assert.Equal(0L, await EventsAsync(database, other));

        await DrainAsync(database);

        await AssertPurgedAsync(database, other, seeds[other]);
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job WHERE type LIKE 'sessions.expired_state.%' AND status <> 'done'"));
    }

    [Fact]
    public async Task Second_run_deletes_nothing_and_writes_no_event()
    {
        var database = await CreateAsync(postgres, registry: null);
        await SeedAsync(database, TenantA);
        await EnqueuePurgeAsync(database, TenantA);
        await DrainAsync(database);
        var after = await SnapshotAsync(database, TenantA);
        Assert.Equal(1L, await EventsAsync(database, TenantA));

        await EnqueuePurgeAsync(database, TenantA);
        await DrainAsync(database);

        Assert.Equal(after, await SnapshotAsync(database, TenantA));
        Assert.Equal(1L, await EventsAsync(database, TenantA));
    }

    [Fact]
    public async Task Tenant_with_nothing_expired_gets_no_event()
    {
        var database = await CreateAsync(postgres, registry: null);
        await EnqueueSweepAsync(database);
        await DrainAsync(database);

        Assert.Equal(2L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM job WHERE type = '{OperationsContract.PurgeExpiredState.Value}' AND status = 'done'"));
        Assert.Equal(0L, await EventsAsync(database, TenantA));
        Assert.Equal(0L, await EventsAsync(database, TenantB));
    }

    /// <summary>
    /// A row the purge can't delete past, here a superuser's table referencing an over Session with
    /// <c>ON DELETE RESTRICT</c>, fails the run: nothing of it is kept, tokens and transactions included, and no event
    /// is written. The job is retried, and once the row is gone the retry purges it all.
    /// </summary>
    [Fact]
    public async Task Failed_run_keeps_nothing_and_a_retry_finishes_it()
    {
        var database = await CreateAsync(postgres, registry: null);
        var seed = await SeedAsync(database, TenantA);
        var before = await SnapshotAsync(database, TenantA);
        await database.SuperuserAsync($"""
            CREATE TABLE purge_conflict_ref (tenant_id uuid NOT NULL, user_session_id uuid NOT NULL,
              FOREIGN KEY (tenant_id, user_session_id) REFERENCES user_session (tenant_id, id) ON DELETE RESTRICT);
            INSERT INTO purge_conflict_ref VALUES ('{TenantA}', '{seed["over-no-family"]}');
            """);

        var job = await EnqueuePurgeAsync(database, TenantA);
        await using (var runner = database.Runner(OperationsContract.ProductionRegistry))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        Assert.Equal("pending", await database.StatusAsync(job));
        Assert.Equal(before, await SnapshotAsync(database, TenantA));
        Assert.Equal(0L, await EventsAsync(database, TenantA));

        await database.SuperuserAsync("DROP TABLE purge_conflict_ref");
        await database.MakeDueAsync(job);
        await DrainAsync(database);

        Assert.Equal("done", await database.StatusAsync(job));
        await AssertPurgedAsync(database, TenantA, seed);
    }

    private static async Task AssertPurgedAsync(JobDatabase database, Guid tenant, Dictionary<string, Guid> seed)
    {
        foreach (var (table, labels) in Kept)
        {
            var expected = labels.Select(l => seed[l]).Order().ToList();
            Assert.Equal(expected, await IdsAsync(database, tenant, table));
        }

        // The deleted transactions' kept emails went with them; the kept ones still have their own.
        Assert.Equal(
            "in-retention@example.test,live@example.test",
            await database.ScalarAsync<string>($"SELECT string_agg(identifier, ',' ORDER BY identifier) FROM signin_transaction WHERE tenant_id = '{tenant}'"));

        // The links' credential still has a link, so it stays.
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM password_credential WHERE tenant_id = '{tenant}'"));

        Assert.Equal(1L, await EventsAsync(database, tenant));
        Assert.Equal(1L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Purged}' AND actor_kind = 'system' AND target_kind IS NULL AND target_id IS NULL"));
    }

    /// <summary>
    /// One Tenant's rows for every matrix row, backdated against now, each labelled. Tokens and families carry their
    /// label as <c>subject</c>, so the snapshot reads them; Sessions and transactions are found by their IDs.
    /// </summary>
    private static async Task<Dictionary<string, Guid>> SeedAsync(JobDatabase database, Guid tenant)
    {
        var ids = new Dictionary<string, Guid>(StringComparer.Ordinal);
        Guid Id(string label) => ids.TryGetValue(label, out var id) ? id : ids[label] = Guid.CreateVersion7();
        var user = Guid.CreateVersion7();

        string Session(string label, string idle, string absolute, bool ended = false) =>
            $"""
            INSERT INTO user_session (tenant_id, id, user_id, id_hash, amr, auth_time, idle_expires_at, absolute_expires_at, created_at, ended_at, end_reason)
            VALUES ('{tenant}', '{Id(label)}', '{user}', sha256(convert_to('{Id(label)}', 'UTF8')), ARRAY['pwd'], now() - interval '10 days',
                    now() + interval '{idle}', now() + interval '{absolute}', now() - interval '10 days',
                    {(ended ? "now() - interval '2 hours', 'logout'" : "NULL, NULL")});
            """;

        string Family(string label, string session) =>
            $"""
            INSERT INTO "authorization" (tenant_id, id, application_id, user_session_id, subject, status, type, concurrency_token)
            VALUES ('{tenant}', '{Id(label)}', '{Application}', '{Id(session)}', '{label}', 'valid', 'ad-hoc', gen_random_uuid());
            """;

        string Token(string label, string? family, string? expires, string type = "refresh_token") =>
            $"""
            INSERT INTO token (tenant_id, id, application_id, authorization_id, subject, type, status, expiration_date, concurrency_token)
            VALUES ('{tenant}', '{Id(label)}', '{Application}', {(family is null ? "NULL" : $"'{Id(family)}'")}, '{label}', '{type}', 'valid',
                    {(expires is null ? "NULL" : $"now() + interval '{expires}'")}, gen_random_uuid());
            """;

        var credential = Guid.CreateVersion7();
        string Link(string label, string expires) =>
            $"""
            INSERT INTO one_time_token (tenant_id, id, user_id, credential_id, purpose, token_hash, expires_at, created_at)
            VALUES ('{tenant}', '{Id(label)}', '{user}', '{credential}', 'email_verification', sha256(convert_to('{Id(label)}', 'UTF8')),
                    now() + interval '{expires}', now() + interval '{expires}' - interval '24 hours');
            """;

        string Transaction(string label, string expires, bool completed = false) =>
            $"""
            INSERT INTO signin_transaction (tenant_id, id, application_id, binding_hash, parameters, created_at, expires_at, identifier, authenticated_session_id, completed_at)
            VALUES ('{tenant}', '{Id(label)}', '{Application}', sha256(convert_to('{Id(label)}', 'UTF8')), jsonb_build_object(),
                    now() + interval '{expires}' - interval '30 minutes', now() + interval '{expires}', '{label}@example.test',
                    {(completed ? $"'{Guid.CreateVersion7()}', now() - interval '2 hours'" : "NULL, NULL")});
            """;

        var sql = string.Join(
            "\n",
            $"INSERT INTO application (tenant_id, id, name, kind, grant_types, created_at) VALUES ('{tenant}', '{Application}', 'App', 'web', ARRAY['authorization_code'], now());",
            $"INSERT INTO \"user\" (tenant_id, id) VALUES ('{tenant}', '{user}');",

            // Expired token, family with another unexpired one, idle-expired Session: the token goes, the rest stays (AD-13).
            Session("idle-expired-with-live-family", "-1 hour", "5 days"),
            Family("live-family", "idle-expired-with-live-family"),
            Token("live-family-refresh", "live-family", "1 day"),
            Token("live-family-access", "live-family", "-1 hour", "access_token"),

            // Dead family on an ended Session with no other family: tokens, family, then the Session go.
            Session("ended-dead-family", "1 hour", "5 days", ended: true),
            Family("dead-family", "ended-dead-family"),
            Token("dead-family-refresh", "dead-family", "-2 hours"),
            Token("dead-family-access", "dead-family", "-3 hours", "access_token"),

            // An over Session with a dead family and a live one: only the dead family goes.
            Session("over-with-live-family", "-2 hours", "-1 hour"),
            Family("shared-dead", "over-with-live-family"),
            Token("shared-dead-refresh", "shared-dead", "-1 minute"),
            Family("shared-live", "over-with-live-family"),
            Token("shared-live-refresh", "shared-live", "2 days"),

            // Over Sessions, no family: deleted, whether ended or past either expiry.
            Session("over-no-family", "1 hour", "5 days", ended: true),
            Session("idle-expired-no-family", "-1 minute", "5 days"),
            Session("absolute-expired-no-family", "-2 days", "-1 day"),

            // Live Sessions: they stay, even once their only family is dead.
            Session("live-no-family", "1 hour", "5 days"),
            Session("live-dead-family", "1 hour", "5 days"),
            Family("live-dead", "live-dead-family"),
            Token("live-dead-refresh", "live-dead", "-1 hour"),

            // Family-less tokens: an expired one goes, one with no expiry stays.
            Token("loose-expired", null, "-1 hour", "access_token"),
            Token("loose-unexpiring", null, null, "access_token"),

            // Transactions: in retention and live stay; past retention go with their email, completed or not.
            Transaction("in-retention", "-30 minutes"),
            Transaction("live", "10 minutes"),
            Transaction("past-retention", "-61 minutes"),
            Transaction("past-retention-completed", "-2 hours", completed: true),

            // Story 4.7: verification links of one pending credential. Past the hour's retention goes; inside it and live
            // stay, and so does their credential, which still has a link.
            $"INSERT INTO password_credential (tenant_id, id, user_id, connection_id, password_hash, status) VALUES ('{tenant}', '{credential}', '{user}', gen_random_uuid(), '$argon2id$seeded', 'pending');",
            Link("link-past-retention", "-61 minutes"),
            Link("link-in-retention", "-30 minutes"),
            Link("link-live", "1 day"));

        await database.SuperuserAsync(sql);
        return ids;
    }

    private static async Task<List<Guid>> IdsAsync(JobDatabase database, Guid tenant, string table)
    {
        var text = await database.ScalarAsync<string>(
            $"SELECT coalesce(string_agg(id::text, ',' ORDER BY id), '') FROM \"{table}\" WHERE tenant_id = '{tenant}'");
        return [.. text.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(Guid.Parse).Order()];
    }

    /// <summary>Every row of the Tenant in the purged tables and its purge events, as text.</summary>
    private static Task<string> SnapshotAsync(JobDatabase database, Guid tenant) =>
        database.ScalarAsync<string>(
            "SELECT concat_ws('|', " +
            string.Join(", ", Kept.Keys.Select(t => $"(SELECT string_agg(to_jsonb(r)::text, ',' ORDER BY r.id) FROM \"{t}\" r WHERE r.tenant_id = '{tenant}')")) +
            $", (SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Purged}'))");

    private static Task<long> EventsAsync(JobDatabase database, Guid tenant) =>
        database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Purged}'");

    private static Task<long> PendingPurgesAsync(JobDatabase database, Guid tenant) =>
        database.ScalarAsync<long>(
            $"SELECT count(*) FROM job WHERE tenant_id = '{tenant}' AND type = '{OperationsContract.PurgeExpiredState.Value}' AND status = 'pending'");

    private static Task<Guid> EnqueueSweepAsync(JobDatabase database) =>
        database.InScopeAsync(TableRegistry.Worker, null, context =>
            OperationsContract.CreateEnqueuer(OperationsContract.ProductionRegistry, custody: null)
                .EnqueueAsync(context, OperationsContract.SweepExpiredState, operationId: null, runAfter: null, Cancellation));

    private static Task<Guid> EnqueuePurgeAsync(JobDatabase database, Guid tenant) =>
        database.InScopeAsync(TableRegistry.Worker, tenant, context =>
            OperationsContract.CreateEnqueuer(OperationsContract.ProductionRegistry, custody: null)
                .EnqueueAsync(context, OperationsContract.PurgeExpiredState, payload: null, runAfter: null, Cancellation));

    /// <summary>A clock fixed at one instant, the job's "now".</summary>
    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static async Task DrainAsync(JobDatabase database)
    {
        await using var runner = database.Runner(OperationsContract.ProductionRegistry);
        while (await runner.RunOnceAsync(Cancellation))
        {
        }
    }
}
