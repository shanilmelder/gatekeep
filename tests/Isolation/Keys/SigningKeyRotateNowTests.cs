using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Keys.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Keys;

/// <summary>
/// Story 9.2 (FR-37, AD-11): <see cref="KeysContract.RotateSigningKeyNowAsync"/>, the Tenant Owner's
/// rotation on demand, as <c>gk_admin</c> with the real <c>host-admin</c> custody policy, against the
/// real PostgreSQL and OpenBao. Rows are aged by moving their times back as the superuser, never by
/// waiting. No assertion prints a key name, a version or key material.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class SigningKeyRotateNowTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string Rotated = "keys.signing_key.rotated";
    private const string Promoted = "keys.signing_key.promoted";
    private const string Created = "keys.signing_key.created";

    private const string NewTenantRows = "management/current,management/next,signing/current,signing/next";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task An_aged_next_is_promoted_and_a_new_next_created_with_the_Admin_as_Actor()
    {
        var (database, tenant) = await ProvisionedAsync();
        var current = await IdAsync(database, tenant, "current");
        var next = await IdAsync(database, tenant, "next");
        var management = await SnapshotAsync(database, tenant, "management");
        await PublishedAsync(database, tenant, minutesAgo: 20);
        var admin = Guid.CreateVersion7();

        // current is minutes old: on demand, its age is never what decides.
        using var custody = bao.Custody(OpenBaoFixture.Admin);
        var rotation = await RotateNowAsync(database, tenant, custody, admin);

        Assert.Equal(SigningKeyRotationStatus.Rotated, rotation.Status);
        Assert.Null(rotation.RetryAfter);
        Assert.Equal("previous", await StateAsync(database, current));
        Assert.Equal("current", await StateAsync(database, next));
        Assert.True(await database.ScalarAsync<bool>($"SELECT rotated_at IS NOT NULL FROM signing_key WHERE id = '{current}'"));
        Assert.True(await database.ScalarAsync<bool>($"SELECT promoted_at IS NOT NULL FROM signing_key WHERE id = '{next}'"));

        // The new next: a Transit key made first, then its row, published at insert and not promoted.
        var fresh = await IdAsync(database, tenant, "next");
        Assert.NotEqual(next, fresh);
        Assert.True(await database.ScalarAsync<bool>(
            $"SELECT published_at = created_at AND promoted_at IS NULL AND transit_name = 'sig-{tenant:D}-{fresh:D}' FROM signing_key WHERE id = '{fresh}'"));
        using (var worker = bao.Custody(OpenBaoFixture.Worker))
        {
            Assert.Single(await worker.GetPublicKeysAsync(KeyName.Signing(tenant, fresh), Cancellation));
        }

        Assert.Equal(NewTenantRows + ",signing/previous", await RowsAsync(database, tenant));
        Assert.Equal(management, await SnapshotAsync(database, tenant, "management"));

        // Three events, each the Admin's, and nothing retired, destroyed or queued.
        Assert.Equal("1/1/1", await EventsAsync(database, tenant, Rotated, Promoted, Created));
        Assert.Equal(3L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code IN ('{Rotated}', '{Promoted}', '{Created}') AND actor_kind = 'admin' AND actor_id = '{admin}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM signing_key WHERE tenant_id = '{tenant}' AND state = 'retired'"));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job WHERE type = 'keys.signing_key.destroy'"));
    }

    [Fact]
    public async Task A_next_published_five_minutes_ago_is_not_ready_with_the_time_left_and_nothing_changes()
    {
        var (database, tenant) = await ProvisionedAsync();
        await PublishedAsync(database, tenant, minutesAgo: 5);
        var before = await SnapshotAsync(database, tenant);

        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Admin));
        var rotation = await RotateNowAsync(database, tenant, custody, Guid.CreateVersion7());

        Assert.Equal(SigningKeyRotationStatus.NotReady, rotation.Status);
        var left = Assert.NotNull(rotation.RetryAfter);
        Assert.InRange(left.TotalSeconds, 580, 600);
        Assert.Equal(0, custody.TotalCalls);
        Assert.Equal(before, await SnapshotAsync(database, tenant));
        Assert.Equal("0/0/0", await EventsAsync(database, tenant, Rotated, Promoted, Created));
    }

    [Fact]
    public async Task A_next_just_short_of_its_wait_is_never_under_one_second()
    {
        var (database, tenant) = await ProvisionedAsync();
        await database.BackdateAsync(
            $"UPDATE signing_key SET published_at = now() - interval '14 minutes 59.9 seconds' WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND state = 'next'");

        using var custody = bao.Custody(OpenBaoFixture.Admin);
        var rotation = await RotateNowAsync(database, tenant, custody, Guid.CreateVersion7());

        // Either the wait ended while the request ran, or what remains is reported as at least a second.
        if (rotation.Status == SigningKeyRotationStatus.NotReady)
        {
            Assert.True(rotation.RetryAfter >= TimeSpan.FromSeconds(1));
        }
    }

    [Fact]
    public async Task An_older_previous_stays_previous_beside_the_new_one()
    {
        var (database, tenant) = await ProvisionedAsync();
        using var custody = bao.Custody(OpenBaoFixture.Admin);
        await PublishedAsync(database, tenant, minutesAgo: 20);
        Assert.Equal(SigningKeyRotationStatus.Rotated, (await RotateNowAsync(database, tenant, custody, Guid.CreateVersion7())).Status);
        var older = await IdAsync(database, tenant, "previous");

        await PublishedAsync(database, tenant, minutesAgo: 20);
        Assert.Equal(SigningKeyRotationStatus.Rotated, (await RotateNowAsync(database, tenant, custody, Guid.CreateVersion7())).Status);

        Assert.Equal("previous", await StateAsync(database, older));
        Assert.Equal(2L, await database.ScalarAsync<long>($"SELECT count(*) FROM signing_key WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND state = 'previous'"));
        await AssertOneCurrentAndNextAsync(database, tenant);
        Assert.Equal("2/2/2", await EventsAsync(database, tenant, Rotated, Promoted, Created));
    }

    [Fact]
    public async Task A_Transit_failure_throws_before_any_row_moves_and_the_rollback_leaves_everything()
    {
        var (database, tenant) = await ProvisionedAsync();
        await PublishedAsync(database, tenant, minutesAgo: 20);
        var before = await SnapshotAsync(database, tenant);

        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Admin));
        custody.Failing.Add(KeyOperation.Create);

        await Assert.ThrowsAsync<KeyCustodyException>(() => RotateNowAsync(database, tenant, custody, Guid.CreateVersion7()));

        Assert.Equal(before, await SnapshotAsync(database, tenant));
        Assert.Equal("0/0/0", await EventsAsync(database, tenant, Rotated, Promoted, Created));
    }

    [Fact]
    public async Task Another_Tenants_rows_are_byte_identical_after_a_rotation()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = await AddProvisionedAsync(database);
        var b = await AddProvisionedAsync(database);
        await PublishedAsync(database, a, minutesAgo: 20);
        await PublishedAsync(database, b, minutesAgo: 20);
        var bBefore = await SnapshotAsync(database, b);

        using var custody = bao.Custody(OpenBaoFixture.Admin);
        Assert.Equal(SigningKeyRotationStatus.Rotated, (await RotateNowAsync(database, a, custody, Guid.CreateVersion7())).Status);

        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM signing_key WHERE tenant_id = '{a}' AND state = 'previous'"));
        Assert.Equal(bBefore, await SnapshotAsync(database, b));
        Assert.Equal("0/0/0", await EventsAsync(database, b, Rotated, Promoted, Created));
    }

    [Fact]
    public async Task Two_rotations_at_once_rotate_once_and_the_second_finds_its_next_too_young()
    {
        var (database, tenant) = await ProvisionedAsync();
        await PublishedAsync(database, tenant, minutesAgo: 20);

        // The first holds its Transit create while the second waits on the Tenant's lock.
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var first = new ControlledCustody(bao.Custody(OpenBaoFixture.Admin))
        {
            BeforeCreateAsync = async _ =>
            {
                entered.TrySetResult();
                await release.Task;
            },
        };
        using var second = new ControlledCustody(bao.Custody(OpenBaoFixture.Admin));

        var one = RotateNowAsync(database, tenant, first, Guid.CreateVersion7());
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(30), Cancellation);
        var two = RotateNowAsync(database, tenant, second, Guid.CreateVersion7());
        await WaitForLockWaiterAsync(database);
        release.SetResult();

        Assert.Equal(SigningKeyRotationStatus.Rotated, (await one).Status);
        Assert.Equal(SigningKeyRotationStatus.NotReady, (await two).Status);
        Assert.Equal(0, second.Calls(KeyOperation.Create));
        await AssertOneCurrentAndNextAsync(database, tenant);
        Assert.Equal("1/1/1", await EventsAsync(database, tenant, Rotated, Promoted, Created));
    }

    [Fact]
    public async Task A_Tenant_missing_its_signing_next_is_a_broken_invariant_not_a_refusal()
    {
        var (database, tenant) = await ProvisionedAsync();
        await database.BackdateAsync($"DELETE FROM signing_key WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND state = 'next'");

        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Admin));
        await Assert.ThrowsAsync<InvalidOperationException>(() => RotateNowAsync(database, tenant, custody, Guid.CreateVersion7()));
        Assert.Equal(0, custody.TotalCalls);
    }

    [Fact]
    public async Task It_needs_the_Tenants_own_scope()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = await AddProvisionedAsync(database);
        var b = await AddProvisionedAsync(database);

        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Admin));
        await using var source = NpgsqlDataSource.Create(database.Role(TableRegistry.Admin));
        await using var scope = await TenantScope.BeginAsync(source, a, Cancellation);

        await Assert.ThrowsAsync<InvalidOperationException>(() => KeysContract.RotateSigningKeyNowAsync(
            scope.CreateCommandContext(), custody, AuditContract.CreateAppender(), Actor.Admin(Guid.CreateVersion7()), b, Cancellation));
        Assert.Equal(0, custody.TotalCalls);
    }

    private async Task<(ProtocolDatabase Database, Guid Tenant)> ProvisionedAsync()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        return (database, await AddProvisionedAsync(database));
    }

    private async Task<Guid> AddProvisionedAsync(ProtocolDatabase database)
    {
        var tenant = (await database.AddTenantAsync($"t{Guid.NewGuid():N}.rotate-now.test")).TenantId;
        Assert.True(await database.ProvisionAsync(bao, tenant));
        return tenant;
    }

    /// <summary>The rotation as Host.Admin runs it: as <c>gk_admin</c> in the Tenant's own scope, committed only when it rotated.</summary>
    private static async Task<SigningKeyRotation> RotateNowAsync(ProtocolDatabase database, Guid tenant, IKeyCustody custody, Guid admin)
    {
        await using var source = NpgsqlDataSource.Create(database.Role(TableRegistry.Admin));
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        var rotation = await KeysContract.RotateSigningKeyNowAsync(
            scope.CreateCommandContext(), custody, AuditContract.CreateAppender(), Actor.Admin(admin), tenant, Cancellation);
        if (rotation.Status == SigningKeyRotationStatus.Rotated)
        {
            await scope.CommitAsync(Cancellation);
        }

        return rotation;
    }

    /// <summary>Backdates the Tenant's signing next's publication.</summary>
    private static Task PublishedAsync(ProtocolDatabase database, Guid tenant, int minutesAgo) =>
        database.BackdateAsync(
            $"UPDATE signing_key SET published_at = now() - make_interval(mins => {minutesAgo}) WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND state = 'next'");

    private static async Task WaitForLockWaiterAsync(ProtocolDatabase database)
    {
        const string Waiting = "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted";
        for (var i = 0; i < 300 && await database.ScalarAsync<long>(Waiting) == 0; i++)
        {
            await Task.Delay(50, Cancellation);
        }

        Assert.Equal(1L, await database.ScalarAsync<long>(Waiting));
    }

    private static async Task AssertOneCurrentAndNextAsync(ProtocolDatabase database, Guid tenant) =>
        Assert.Equal(
            NewTenantRows,
            await database.ScalarAsync<string>(
                $"SELECT string_agg(purpose || '/' || state, ',' ORDER BY purpose, state) FROM signing_key WHERE tenant_id = '{tenant}' AND state IN ('current', 'next')"));

    private static Task<Guid> IdAsync(ProtocolDatabase database, Guid tenant, string state) =>
        database.ScalarAsync<Guid>(
            $"SELECT id FROM signing_key WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND state = '{state}' ORDER BY created_at DESC LIMIT 1");

    private static Task<string> StateAsync(ProtocolDatabase database, Guid id) =>
        database.ScalarAsync<string>($"SELECT state FROM signing_key WHERE id = '{id}'");

    private static Task<string> RowsAsync(ProtocolDatabase database, Guid tenant) =>
        database.ScalarAsync<string>(
            $"SELECT string_agg(purpose || '/' || state, ',' ORDER BY purpose, state) FROM signing_key WHERE tenant_id = '{tenant}'");

    /// <summary>Every column of the Tenant's rows (of one purpose, if given), so any change shows.</summary>
    private static Task<string> SnapshotAsync(ProtocolDatabase database, Guid tenant, string? purpose = null) =>
        database.ScalarAsync<string>(
            $"SELECT coalesce(string_agg(to_jsonb(s)::text, ',' ORDER BY id), '') FROM signing_key s WHERE tenant_id = '{tenant}'"
            + (purpose is null ? string.Empty : $" AND purpose = '{purpose}'"));

    private static Task<string> EventsAsync(ProtocolDatabase database, Guid tenant, params string[] codes) =>
        database.ScalarAsync<string>(
            "SELECT " + string.Join(
                " || '/' || ",
                codes.Select(c => $"(SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{c}')")));
}
