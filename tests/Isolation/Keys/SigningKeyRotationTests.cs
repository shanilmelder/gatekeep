using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Keys.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Jobs;
using Gatekeep.Tests.Isolation.Protocol;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Keys;

/// <summary>
/// Story 2.4 (FR-37, AD-11): the daily rotation, retirement with its destroy job, destruction and the
/// orphan sweep, against the real PostgreSQL and OpenBao through the <c>host-worker</c> login. Rows
/// are aged by moving their times back as the superuser, never by waiting, and Transit's creation
/// time is reported older through the custody wrapper. One test or more per row of the story's I/O
/// matrix. No assertion prints a key name, a version or key material.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class SigningKeyRotationTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string Rotated = "keys.signing_key.rotated";
    private const string Promoted = "keys.signing_key.promoted";
    private const string Created = "keys.signing_key.created";
    private const string Retired = "keys.signing_key.retired";
    private const string Destroyed = "keys.signing_key.destroyed";
    private const string DestructionFailed = "keys.signing_key.destruction_failed";
    private const string Swept = "keys.transit_key.swept";

    private const string NewTenantRows = "management/current,management/next,signing/current,signing/next";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Due_current_with_an_aged_next_rotates_and_a_new_next_is_published()
    {
        var (database, tenant) = await ProvisionedAsync();
        var current = await IdAsync(database, tenant, "signing", "current");
        var next = await IdAsync(database, tenant, "signing", "next");
        await AgeAsync(database, tenant, "signing", currentDays: 150, nextPublishedMinutes: 20);

        Assert.True(await database.RotateAsync(bao, tenant));

        Assert.Equal("previous", await StateAsync(database, current));
        Assert.Equal("current", await StateAsync(database, next));
        Assert.True(await database.ScalarAsync<bool>($"SELECT rotated_at IS NOT NULL FROM signing_key WHERE id = '{current}'"));
        Assert.True(await database.ScalarAsync<bool>($"SELECT promoted_at > created_at FROM signing_key WHERE id = '{next}'"));

        // The new next: a fresh Transit key, published at insert, not promoted.
        var fresh = await IdAsync(database, tenant, "signing", "next");
        Assert.NotEqual(next, fresh);
        Assert.True(await database.ScalarAsync<bool>(
            $"SELECT published_at = created_at AND promoted_at IS NULL AND rotated_at IS NULL FROM signing_key WHERE id = '{fresh}'"));
        using var worker = bao.Custody(OpenBaoFixture.Worker);
        Assert.Single(await worker.GetPublicKeysAsync(KeyName.Signing(tenant, fresh), Cancellation));

        Assert.Equal("management/current,management/next,signing/current,signing/next,signing/previous", await RowsAsync(database, tenant));
        Assert.Equal("1/1/1", await EventsAsync(database, tenant, Rotated, Promoted, Created));

        // Nothing was due to retire, so no destroy job yet.
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job WHERE type = 'keys.signing_key.destroy'"));
    }

    [Fact]
    public async Task Due_current_with_a_next_published_five_minutes_ago_changes_nothing()
    {
        var (database, tenant) = await ProvisionedAsync();
        await AgeAsync(database, tenant, "signing", currentDays: 150, nextPublishedMinutes: 5);
        var before = await SnapshotAsync(database, tenant);

        using var counting = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker));
        Assert.False(await database.RotateAsync(bao, tenant, counting));

        Assert.Equal(0, counting.TotalCalls);
        Assert.Equal(before, await SnapshotAsync(database, tenant));
        Assert.Equal("0/0/0", await EventsAsync(database, tenant, Rotated, Promoted, Created));
    }

    [Fact]
    public async Task Due_Management_key_rotates_without_the_publication_wait()
    {
        var (database, tenant) = await ProvisionedAsync();
        var signingBefore = await SnapshotAsync(database, tenant, "signing");
        var current = await IdAsync(database, tenant, "management", "current");
        var next = await IdAsync(database, tenant, "management", "next");

        // A Management next is never published: published_at stays null, and only its age counts.
        await database.BackdateAsync($"UPDATE signing_key SET created_at = now() - interval '150 days' WHERE id = '{current}'");

        Assert.True(await database.RotateAsync(bao, tenant));

        Assert.Equal("previous", await StateAsync(database, current));
        Assert.Equal("current", await StateAsync(database, next));
        var fresh = await IdAsync(database, tenant, "management", "next");
        Assert.True(await database.ScalarAsync<bool>($"SELECT published_at IS NULL FROM signing_key WHERE id = '{fresh}'"));
        Assert.StartsWith("mgmt-", await database.ScalarAsync<string>($"SELECT transit_name FROM signing_key WHERE id = '{fresh}'"), StringComparison.Ordinal);

        // The published set, and so JWKS, didn't change.
        Assert.Equal(signingBefore, await SnapshotAsync(database, tenant, "signing"));
    }

    [Fact]
    public async Task Current_aged_149_days_is_not_due()
    {
        var (database, tenant) = await ProvisionedAsync();
        await AgeAsync(database, tenant, "signing", currentDays: 149, nextPublishedMinutes: 60 * 24 * 149);
        await AgeAsync(database, tenant, "management", currentDays: 149, nextPublishedMinutes: null);
        var before = await SnapshotAsync(database, tenant);

        Assert.False(await database.RotateAsync(bao, tenant));

        Assert.Equal(before, await SnapshotAsync(database, tenant));
    }

    [Fact]
    public async Task Previous_rotated_76_minutes_ago_retires_and_its_destroy_job_is_queued()
    {
        var (database, tenant) = await RotatedAsync();
        var previous = await IdAsync(database, tenant, "signing", "previous");
        await database.BackdateAsync($"UPDATE signing_key SET rotated_at = now() - interval '76 minutes' WHERE id = '{previous}'");

        Assert.True(await database.RotateAsync(bao, tenant));

        Assert.Equal("retired", await StateAsync(database, previous));
        Assert.True(await database.ScalarAsync<bool>($"SELECT retired_at IS NOT NULL AND destroyed_at IS NULL FROM signing_key WHERE id = '{previous}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Retired}'"));

        // One destroy job, in the Tenant's scope, carrying only the row's ID.
        Assert.Equal(
            $"{tenant}|pending|{{\"signing_key_id\": \"{previous}\"}}",
            await database.ScalarAsync<string>(
                "SELECT j.tenant_id || '|' || j.status || '|' || p.ids::text FROM job j JOIN job_payload p ON p.job_id = j.id WHERE j.type = 'keys.signing_key.destroy'"));

        // It has left the published set.
        await using var source = NpgsqlDataSource.Create(database.Hosted);
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        var published = await KeysContract.ReadPublishedSigningKeysAsync(scope.CreateCommandContext(), Cancellation);
        Assert.DoesNotContain(published, k => k.Key.Equals(KeyName.Signing(tenant, previous)));
        Assert.Equal(2, published.Count);
    }

    [Fact]
    public async Task Previous_rotated_74_minutes_ago_stays_previous()
    {
        var (database, tenant) = await RotatedAsync();
        var previous = await IdAsync(database, tenant, "signing", "previous");
        await database.BackdateAsync($"UPDATE signing_key SET rotated_at = now() - interval '74 minutes' WHERE id = '{previous}'");

        Assert.False(await database.RotateAsync(bao, tenant));

        Assert.Equal("previous", await StateAsync(database, previous));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job WHERE type = 'keys.signing_key.destroy'"));
    }

    [Fact]
    public async Task A_promoted_next_as_old_as_its_predecessor_rotates_again_once_its_replacement_has_aged()
    {
        // Age counts from creation, so the first next is as old as the key it replaced (Design Notes).
        var (database, tenant) = await ProvisionedAsync();
        var first = await IdAsync(database, tenant, "signing", "next");
        await database.BackdateAsync(
            $"UPDATE signing_key SET created_at = now() - interval '150 days', published_at = now() - interval '150 days' WHERE tenant_id = '{tenant}' AND purpose = 'signing'");

        Assert.True(await database.RotateAsync(bao, tenant));
        Assert.Equal("current", await StateAsync(database, first));

        // Due again at once, but its replacement was published just now: it waits.
        Assert.False(await database.RotateAsync(bao, tenant));

        var second = await IdAsync(database, tenant, "signing", "next");
        await database.BackdateAsync($"UPDATE signing_key SET published_at = now() - interval '20 minutes' WHERE id = '{second}'");
        Assert.True(await database.RotateAsync(bao, tenant));

        Assert.Equal("previous", await StateAsync(database, first));
        Assert.Equal("current", await StateAsync(database, second));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM signing_key WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND state = 'next'"));
    }

    [Fact]
    public async Task Three_cycles_of_daily_rotation_keep_every_key_under_180_days_and_publish_before_promotion()
    {
        // Every row's times move back a day before each daily run, as if the days had passed.
        var (database, tenant) = await ProvisionedAsync();
        using var worker = bao.Custody(OpenBaoFixture.Worker);

        for (var day = 1; day <= 460; day++)
        {
            await database.BackdateAsync(
                "UPDATE signing_key SET created_at = created_at - interval '1 day', published_at = published_at - interval '1 day', "
                + "promoted_at = promoted_at - interval '1 day', rotated_at = rotated_at - interval '1 day', retired_at = retired_at - interval '1 day' "
                + $"WHERE tenant_id = '{tenant}'");
            await database.RotateAsync(bao, tenant, worker);

            // No key, until it retires, has existed 180 days.
            Assert.Equal(0L, await database.ScalarAsync<long>(
                $"SELECT count(*) FROM signing_key WHERE tenant_id = '{tenant}' AND coalesce(retired_at, now()) - created_at >= interval '180 days'"));
            await AssertOneCurrentAndNextAsync(database, tenant);
        }

        // Every promotion by rotation (a new Tenant's first current is promoted at creation) came at
        // least 15 minutes after the key was published.
        Assert.Equal(0L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM signing_key WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND promoted_at <> created_at "
            + "AND promoted_at - published_at < interval '15 minutes'"));

        // Three cycles, each a double rotation: days 150/151, 300/301 and 450/451, per purpose.
        Assert.Equal(6L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM signing_key WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND promoted_at <> created_at"));
        Assert.Equal(6L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM signing_key WHERE tenant_id = '{tenant}' AND purpose = 'management' AND promoted_at <> created_at"));
    }

    [Fact]
    public async Task Dead_destroy_job_is_queued_again_by_the_next_rotation()
    {
        var (database, tenant, retired) = await RetiredAsync();
        await database.BackdateAsync("UPDATE job SET status = 'dead', finished_at = now() WHERE type = 'keys.signing_key.destroy'");

        Assert.True(await database.RotateAsync(bao, tenant));

        Assert.Equal(
            $"pending|{{\"signing_key_id\": \"{retired}\"}}",
            await database.ScalarAsync<string>(
                "SELECT j.status || '|' || p.ids::text FROM job j JOIN job_payload p ON p.job_id = j.id WHERE j.type = 'keys.signing_key.destroy' AND j.status = 'pending'"));

        // A job already waiting is never doubled.
        Assert.False(await database.RotateAsync(bao, tenant));
        Assert.Equal(1L, await database.ScalarAsync<long>("SELECT count(*) FROM job WHERE type = 'keys.signing_key.destroy' AND status = 'pending'"));
    }

    [Fact]
    public async Task Destroy_rejected_while_the_key_still_exists_records_the_failure_and_retries()
    {
        var (database, tenant, retired) = await RetiredAsync();

        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker));
        custody.FailingWith[KeyOperation.Delete] = KeyCustodyFailure.Rejected;
        await using (var runner = database.Runner(custody))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        Assert.Equal("pending/custody_failed", await database.ScalarAsync<string>(
            "SELECT status || '/' || failure_code FROM job WHERE type = 'keys.signing_key.destroy'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{DestructionFailed}'"));
        Assert.True(await database.ScalarAsync<bool>($"SELECT destroyed_at IS NULL FROM signing_key WHERE id = '{retired}'"));

        using var worker = bao.Custody(OpenBaoFixture.Worker);
        Assert.NotEmpty(await worker.GetPublicKeysAsync(KeyName.Signing(tenant, retired), Cancellation));
    }

    [Fact]
    public async Task Destroy_job_deletes_the_Transit_key_and_sets_destroyed_at()
    {
        var (database, tenant, retired) = await RetiredAsync();
        var others = await SnapshotAsync(database, tenant, excluding: retired);

        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker));
        await using (var runner = database.Runner(custody))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        Assert.Equal("done", await database.ScalarAsync<string>("SELECT status FROM job WHERE type = 'keys.signing_key.destroy'"));
        Assert.True(await database.ScalarAsync<bool>($"SELECT state = 'retired' AND destroyed_at IS NOT NULL FROM signing_key WHERE id = '{retired}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Destroyed}' AND actor_kind = 'system'"));
        Assert.Equal([KeyName.Signing(tenant, retired).Value], custody.Deleted);

        using var worker = bao.Custody(OpenBaoFixture.Worker);
        var gone = await Assert.ThrowsAsync<KeyCustodyException>(() => worker.GetPublicKeysAsync(KeyName.Signing(tenant, retired), Cancellation));
        Assert.Equal(KeyCustodyFailure.Rejected, gone.Failure);
        Assert.Equal(others, await SnapshotAsync(database, tenant, excluding: retired));
    }

    [Fact]
    public async Task Failed_destroy_commits_its_failure_event_retries_and_touches_nothing_else()
    {
        var (database, tenant, retired) = await RetiredAsync();
        var before = await SnapshotAsync(database, tenant);

        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker));
        custody.Failing.Add(KeyOperation.Delete);
        await using (var runner = database.Runner(custody))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        Assert.Equal("pending/custody_failed/1", await database.ScalarAsync<string>(
            "SELECT status || '/' || failure_code || '/' || attempts FROM job WHERE type = 'keys.signing_key.destroy'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{DestructionFailed}' AND actor_kind = 'system'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Destroyed}'"));
        Assert.Equal(before, await SnapshotAsync(database, tenant));
        Assert.Equal(1, custody.Calls(KeyOperation.Delete));

        // The key is still in custody, and the retry destroys it once custody is back.
        using var worker = bao.Custody(OpenBaoFixture.Worker);
        Assert.NotEmpty(await worker.GetPublicKeysAsync(KeyName.Signing(tenant, retired), Cancellation));

        custody.Failing.Clear();
        await database.ExecuteAsync("UPDATE job SET run_after = now() WHERE type = 'keys.signing_key.destroy'");
        await using (var runner = database.Runner(custody))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        Assert.Equal("done", await database.ScalarAsync<string>("SELECT status FROM job WHERE type = 'keys.signing_key.destroy'"));
        Assert.True(await database.ScalarAsync<bool>($"SELECT destroyed_at IS NOT NULL FROM signing_key WHERE id = '{retired}'"));
    }

    [Fact]
    public async Task Destroy_rerun_on_a_destroyed_or_unretired_row_calls_no_custody_and_succeeds()
    {
        var (database, tenant, retired) = await RetiredAsync();
        await using (var runner = database.Runner(bao.Custody(OpenBaoFixture.Worker)))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        var current = await IdAsync(database, tenant, "signing", "current");
        await EnqueueDestroyAsync(database, tenant, retired);
        await EnqueueDestroyAsync(database, tenant, current);
        await EnqueueDestroyAsync(database, tenant, Guid.CreateVersion7());
        var before = await SnapshotAsync(database, tenant);

        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker));
        await using (var runner = database.Runner(custody))
        {
            for (var i = 0; i < 3; i++)
            {
                Assert.True(await runner.RunOnceAsync(Cancellation));
            }
        }

        Assert.Equal(0, custody.TotalCalls);
        Assert.Equal(4L, await database.ScalarAsync<long>("SELECT count(*) FROM job WHERE type = 'keys.signing_key.destroy' AND status = 'done'"));
        Assert.Equal(before, await SnapshotAsync(database, tenant));
        Assert.Equal("current", await StateAsync(database, current));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Destroyed}'"));
    }

    [Fact]
    public async Task Destroy_after_the_key_was_deleted_but_never_recorded_marks_it_destroyed()
    {
        // An earlier attempt deleted the key, then failed before its commit.
        var (database, tenant, retired) = await RetiredAsync();
        using (var worker = bao.Custody(OpenBaoFixture.Worker))
        {
            await worker.DeleteAsync(KeyName.Signing(tenant, retired), Cancellation);
        }

        await using (var runner = database.Runner(bao.Custody(OpenBaoFixture.Worker)))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        Assert.Equal("done", await database.ScalarAsync<string>("SELECT status FROM job WHERE type = 'keys.signing_key.destroy'"));
        Assert.True(await database.ScalarAsync<bool>($"SELECT destroyed_at IS NOT NULL FROM signing_key WHERE id = '{retired}'"));
    }

    [Fact]
    public async Task Rotation_job_rotates_only_the_due_Tenant()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = await AddProvisionedAsync(database);
        var b = await AddProvisionedAsync(database);
        await AgeAsync(database, a, "signing", currentDays: 150, nextPublishedMinutes: 20);
        var bBefore = await SnapshotAsync(database, b);

        await RunJobAsync(database, "keys.signing_keys.rotate", bao.Custody(OpenBaoFixture.Worker));

        Assert.Equal("done", await database.ScalarAsync<string>("SELECT status FROM job WHERE type = 'keys.signing_keys.rotate'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM signing_key WHERE tenant_id = '{a}' AND state = 'previous'"));
        Assert.Equal(bBefore, await SnapshotAsync(database, b));
        Assert.Equal("0/0/0", await EventsAsync(database, b, Rotated, Promoted, Created));
    }

    [Fact]
    public async Task Transit_failure_mid_rotation_rolls_back_that_Tenant_only_and_the_job_retries()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = await AddProvisionedAsync(database);
        var b = await AddProvisionedAsync(database);
        foreach (var tenant in new[] { a, b })
        {
            await AgeAsync(database, tenant, "signing", currentDays: 150, nextPublishedMinutes: 20);
            await AgeAsync(database, tenant, "management", currentDays: 150, nextPublishedMinutes: null);
        }

        var aBefore = await SnapshotAsync(database, a);

        // A's second create, the Management replacement, fails: A's signing rotation goes back with it.
        var aCreates = 0;
        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker))
        {
            BeforeCreate = key =>
            {
                if (key.TenantId == a && ++aCreates == 2)
                {
                    throw new KeyCustodyException(key.Value, KeyOperation.Create, KeyCustodyFailure.Unavailable);
                }
            },
        };
        var logger = new RecordingLogger();

        await RunJobAsync(database, "keys.signing_keys.rotate", custody, logger);

        Assert.Equal(aBefore, await SnapshotAsync(database, a));
        Assert.Equal("0/0/0", await EventsAsync(database, a, Rotated, Promoted, Created));
        Assert.Equal(2L, await database.ScalarAsync<long>($"SELECT count(*) FROM signing_key WHERE tenant_id = '{b}' AND state = 'previous'"));
        Assert.Equal("2/2/2", await EventsAsync(database, b, Rotated, Promoted, Created));

        Assert.Contains(logger.Lines, l => l == $"Key rotation for Tenant {a} failed on KeyCustodyException.");
        Assert.DoesNotContain(logger.Lines, l => l.Contains("sig-", StringComparison.Ordinal) || l.Contains("mgmt-", StringComparison.Ordinal));
        Assert.Equal("pending/handler_failed", await database.ScalarAsync<string>(
            "SELECT status || '/' || failure_code FROM job WHERE type = 'keys.signing_keys.rotate'"));
    }

    [Fact]
    public async Task Rotation_and_backfill_interleaved_leave_one_current_and_one_next_per_purpose()
    {
        // Rotation first: it holds its Transit create while the backfill waits on the Tenant's lock.
        var (database, tenant) = await ProvisionedAsync();
        await AgeAsync(database, tenant, "signing", currentDays: 150, nextPublishedMinutes: 20);

        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var rotating = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker))
        {
            BeforeCreateAsync = async _ =>
            {
                entered.TrySetResult();
                await release.Task;
            },
        };
        using var backfilling = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker));

        var rotation = database.RotateAsync(bao, tenant, rotating);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(30), Cancellation);
        var backfill = database.ProvisionAsync(bao, tenant, backfilling);
        await WaitForLockWaiterAsync(database);
        release.SetResult();

        Assert.True(await rotation);
        Assert.False(await backfill);
        Assert.Equal(0, backfilling.Calls(KeyOperation.Create));
        await AssertOneCurrentAndNextAsync(database, tenant);

        // Backfill first: a Tenant missing its Management next gets it, and the rotation then sees a full set.
        var (second, other) = await ProvisionedAsync();
        await second.BackdateAsync($"DELETE FROM signing_key WHERE tenant_id = '{other}' AND purpose = 'management' AND state = 'next'");
        await AgeAsync(second, other, "management", currentDays: 150, nextPublishedMinutes: null);

        var held = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var go = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var provisioning = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker))
        {
            BeforeCreateAsync = async _ =>
            {
                held.TrySetResult();
                await go.Task;
            },
        };

        var provision = second.ProvisionAsync(bao, other, provisioning);
        await held.Task.WaitAsync(TimeSpan.FromSeconds(30), Cancellation);
        var rotate = second.RotateAsync(bao, other);
        await WaitForLockWaiterAsync(second);
        go.SetResult();

        Assert.True(await provision);
        Assert.True(await rotate);
        await AssertOneCurrentAndNextAsync(second, other);
        Assert.Equal(1L, await second.ScalarAsync<long>($"SELECT count(*) FROM signing_key WHERE tenant_id = '{other}' AND purpose = 'management' AND state = 'previous'"));
    }

    [Fact]
    public async Task Sweep_deletes_an_orphan_older_than_24_hours_with_a_Deployment_event()
    {
        var (database, tenant) = await ProvisionedAsync();
        var orphan = await OrphanAsync(tenant);

        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker));
        custody.Backdated[orphan.Value] = TimeSpan.FromHours(25);
        await RunJobAsync(database, "keys.transit_keys.sweep", custody);

        Assert.Equal("done", await database.ScalarAsync<string>("SELECT status FROM job WHERE type = 'keys.transit_keys.sweep'"));
        Assert.Equal([orphan.Value], custody.Deleted);
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE type_code = '{Swept}' AND actor_kind = 'system'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE type_code = '{Swept}'"));

        using var worker = bao.Custody(OpenBaoFixture.Worker);
        await Assert.ThrowsAsync<KeyCustodyException>(() => worker.GetPublicKeysAsync(orphan, Cancellation));
    }

    [Fact]
    public async Task Sweep_keeps_a_young_orphan_a_key_with_a_row_and_every_secret_class_key()
    {
        var (database, tenant) = await ProvisionedAsync();
        var young = await OrphanAsync(tenant);
        var withRow = KeyName.Signing(tenant, await IdAsync(database, tenant, "signing", "current"));

        using var worker = bao.Custody(OpenBaoFixture.Worker);
        await KeysContract.CreateSecretClassKeysAsync(worker, tenant, Cancellation);

        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker));
        custody.Backdated[young.Value] = TimeSpan.FromHours(1);
        custody.Backdated[withRow.Value] = TimeSpan.FromDays(30);
        foreach (var secret in KeysContract.SecretClassKeys(tenant))
        {
            custody.Backdated[secret.Value] = TimeSpan.FromDays(30);
        }

        // The list never holds a secret class or Deployment key, whatever its age.
        var listed = await custody.ListRowKeysAsync(Cancellation);
        Assert.Contains(listed, k => k.Key.Equals(young));
        Assert.All(listed, k => Assert.Matches("^(sig|mgmt)-", k.Key.Value));

        await RunJobAsync(database, "keys.transit_keys.sweep", custody);

        Assert.Equal("done", await database.ScalarAsync<string>("SELECT status FROM job WHERE type = 'keys.transit_keys.sweep'"));
        Assert.DoesNotContain(young.Value, custody.Deleted);
        Assert.DoesNotContain(withRow.Value, custody.Deleted);
        Assert.Equal(0, custody.Calls(KeyOperation.Delete));
        Assert.NotEmpty(await worker.GetPublicKeysAsync(young, Cancellation));
        Assert.NotEmpty(await worker.GetPublicKeysAsync(withRow, Cancellation));
        Assert.NotEmpty(await worker.GetPublicKeysAsync(KeyName.ForDeployment(DeploymentKeyClass.Records), Cancellation));

        // The token protection key is still there: a fresh wrap under it works.
        Assert.NotNull(await worker.CreateWrappedDataKeyAsync(KeysContract.TokenProtectionKey(tenant), tenant, Cancellation));

        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE type_code = '{Swept}'"));
    }

    [Fact]
    public async Task Sweep_logs_a_failed_removal_by_type_and_goes_on()
    {
        var (database, tenant) = await ProvisionedAsync();
        var stuck = await OrphanAsync(tenant);
        var removable = await OrphanAsync(tenant);

        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker));
        custody.Backdated[stuck.Value] = TimeSpan.FromHours(25);
        custody.Backdated[removable.Value] = TimeSpan.FromHours(25);
        custody.FailingKeys[stuck.Value] = true;
        var logger = new RecordingLogger();

        await RunJobAsync(database, "keys.transit_keys.sweep", custody, logger);

        Assert.Equal([removable.Value], custody.Deleted);
        Assert.Contains(logger.Lines, l => l == "Orphan key sweep skipped a key on KeyCustodyException.");
        Assert.DoesNotContain(logger.Lines, l => l.Contains(stuck.Value, StringComparison.Ordinal));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE type_code = '{Swept}'"));
        Assert.Equal("done", await database.ScalarAsync<string>("SELECT status FROM job WHERE type = 'keys.transit_keys.sweep'"));
    }

    [Fact]
    public async Task Failed_key_list_fails_the_sweep_job()
    {
        var (database, _) = await ProvisionedAsync();
        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker));
        custody.Failing.Add(KeyOperation.List);

        await RunJobAsync(database, "keys.transit_keys.sweep", custody);

        Assert.Equal("pending/custody_failed", await database.ScalarAsync<string>(
            "SELECT status || '/' || failure_code FROM job WHERE type = 'keys.transit_keys.sweep'"));
        Assert.Equal(0, custody.Calls(KeyOperation.Delete));
    }

    [Fact]
    public async Task One_unreadable_key_is_left_out_of_the_list_and_the_others_are_still_swept()
    {
        var (database, tenant) = await ProvisionedAsync();
        var unreadable = await OrphanAsync(tenant);
        var removable = await OrphanAsync(tenant);

        // OpenBao refuses the read of one key: the adapter skips it and lists the rest.
        using var custody = new ControlledCustody(bao.Custody(
            OpenBaoFixture.Worker,
            wrap: inner => new RefuseRead(inner, $"/v1/transit/keys/{unreadable.Value}")));
        custody.Backdated[unreadable.Value] = TimeSpan.FromHours(25);
        custody.Backdated[removable.Value] = TimeSpan.FromHours(25);

        var listed = await custody.ListRowKeysAsync(Cancellation);
        Assert.DoesNotContain(listed, k => k.Key.Equals(unreadable));
        Assert.Contains(listed, k => k.Key.Equals(removable));

        await RunJobAsync(database, "keys.transit_keys.sweep", custody);

        Assert.Equal("done", await database.ScalarAsync<string>("SELECT status FROM job WHERE type = 'keys.transit_keys.sweep'"));
        Assert.Equal([removable.Value], custody.Deleted);
        using var worker = bao.Custody(OpenBaoFixture.Worker);
        Assert.NotEmpty(await worker.GetPublicKeysAsync(unreadable, Cancellation));
    }

    [Theory]
    [InlineData("next")]
    [InlineData("current")]
    [InlineData("previous")]
    public async Task Worker_may_revoke_a_key_in_any_state_but_retired(string state)
    {
        var (database, tenant) = await RotatedAsync();

        await InScopeAsync(database, TableRegistry.Worker, tenant, $"UPDATE signing_key SET state = 'revoked' WHERE state = '{state}' AND purpose = 'signing'");

        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM signing_key WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND state = '{state}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM signing_key WHERE tenant_id = '{tenant}' AND state = 'revoked'"));
    }

    [Fact]
    public async Task Hosted_cant_update_a_key_row()
    {
        var (database, tenant) = await ProvisionedAsync();

        var refused = await Assert.ThrowsAsync<PostgresException>(() => InScopeAsync(
            database, TableRegistry.Hosted, tenant, "UPDATE signing_key SET state = 'revoked' WHERE state = 'next'"));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, refused.SqlState);
    }

    [Fact]
    public async Task A_current_row_without_promoted_at_is_refused()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var tenant = (await database.AddTenantAsync($"t{Guid.NewGuid():N}.rotation.test")).TenantId;
        var id = Guid.CreateVersion7();

        var refused = await Assert.ThrowsAsync<PostgresException>(() => database.ExecuteAsync(
            $"INSERT INTO signing_key (id, tenant_id, purpose, state, transit_name, transit_version, published_at) VALUES ('{id}', '{tenant}', 'signing', 'current', 'sig-{tenant:D}-{id:D}', 1, now())"));
        Assert.Equal("signing_key_promoted_at", refused.ConstraintName);
    }

    [Theory]
    [InlineData("UPDATE signing_key SET state = 'next' WHERE state = 'current' AND purpose = 'signing'")]
    [InlineData("UPDATE signing_key SET state = 'previous' WHERE state = 'next' AND purpose = 'signing'")]
    [InlineData("UPDATE signing_key SET state = 'retired' WHERE state = 'current' AND purpose = 'signing'")]
    [InlineData("UPDATE signing_key SET promoted_at = now() WHERE state = 'current' AND purpose = 'signing'")]
    public async Task Worker_change_outside_AD_11_is_refused_by_the_trigger(string sql)
    {
        var (database, tenant) = await ProvisionedAsync();

        var refused = await Assert.ThrowsAsync<PostgresException>(() => InScopeAsync(database, TableRegistry.Worker, tenant, sql));
        Assert.Equal(PostgresErrorCodes.RaiseException, refused.SqlState);
    }

    [Theory]
    [InlineData("UPDATE signing_key SET transit_name = transit_name")]
    [InlineData("UPDATE signing_key SET published_at = now()")]
    public async Task Worker_change_to_a_key_or_its_publication_is_refused_by_the_grant(string sql)
    {
        var (database, tenant) = await ProvisionedAsync();

        var refused = await Assert.ThrowsAsync<PostgresException>(() => InScopeAsync(database, TableRegistry.Worker, tenant, sql));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, refused.SqlState);
    }

    [Theory]
    [InlineData("UPDATE signing_key SET created_at = now() - interval '1 day' WHERE state = 'current'")]
    [InlineData("UPDATE signing_key SET transit_version = 2 WHERE state = 'current'")]
    [InlineData("UPDATE signing_key SET state = 'current' WHERE state = 'previous'")]
    [InlineData("UPDATE signing_key SET state = 'revoked' WHERE state = 'retired'")]
    [InlineData("UPDATE signing_key SET rotated_at = now() WHERE state = 'previous'")]
    public async Task Even_the_superuser_meets_the_trigger(string sql)
    {
        var (database, tenant, _) = await RetiredAsync();
        await RotateSigningAgainAsync(database, tenant);

        var refused = await Assert.ThrowsAsync<PostgresException>(() => database.ExecuteAsync($"{sql.Replace("WHERE", $"WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND", StringComparison.Ordinal)}"));
        Assert.Equal(PostgresErrorCodes.RaiseException, refused.SqlState);
    }

    [Theory]
    [InlineData("previous", "NULL", "NULL", "NULL", "signing_key_rotated_at")]
    [InlineData("retired", "now()", "NULL", "NULL", "signing_key_retired_at")]
    [InlineData("current", "NULL", "NULL", "now()", "signing_key_destroyed_at")]
    [InlineData("previous", "now()", "NULL", "now()", "signing_key_destroyed_at")]
    public async Task Lifecycle_times_must_match_the_state(string state, string rotated, string retired, string destroyed, string constraint)
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var tenant = (await database.AddTenantAsync($"t{Guid.NewGuid():N}.rotation.test")).TenantId;
        var id = Guid.CreateVersion7();

        var refused = await Assert.ThrowsAsync<PostgresException>(() => database.ExecuteAsync(
            $"INSERT INTO signing_key (id, tenant_id, purpose, state, transit_name, transit_version, published_at, promoted_at, rotated_at, retired_at, destroyed_at) "
            + $"VALUES ('{id}', '{tenant}', 'signing', '{state}', 'sig-{tenant:D}-{id:D}', 1, now(), now(), {rotated}, {retired}, {destroyed})"));
        Assert.Equal(constraint, refused.ConstraintName);
    }

    [Fact]
    public void Job_types_are_registered_with_their_scopes()
    {
        var registry = OperationsContract.ProductionRegistry;
        Assert.Equal("keys.signing_keys.rotate", OperationsContract.RotateSigningKeys.Value);
        Assert.Equal("keys.signing_key.destroy", OperationsContract.DestroySigningKey.Value);
        Assert.Equal("keys.transit_keys.sweep", OperationsContract.SweepTransitKeys.Value);
        Assert.Equal(JobScope.DeploymentWide, registry.Find(OperationsContract.RotateSigningKeys)!.Scope);
        Assert.Equal(JobScope.Tenant, registry.Find(OperationsContract.DestroySigningKey)!.Scope);
        Assert.Equal(JobScope.DeploymentWide, registry.Find(OperationsContract.SweepTransitKeys)!.Scope);
        Assert.All(
            new[] { OperationsContract.RotateSigningKeys, OperationsContract.DestroySigningKey, OperationsContract.SweepTransitKeys },
            type => Assert.Equal([JobRole.Worker], registry.Find(type)!.EnqueuingRoles));
    }

    [Theory]
    [InlineData("sig-0190a000-0000-7000-8000-00000000000a-0190a000-0000-7000-8000-0000000000b1", true)]
    [InlineData("mgmt-0190a000-0000-7000-8000-00000000000a-0190a000-0000-7000-8000-0000000000b1", true)]
    [InlineData("sig-0190A000-0000-7000-8000-00000000000A-0190a000-0000-7000-8000-0000000000b1", false)]
    [InlineData("sig-0190a000-0000-7000-8000-00000000000a", false)]
    [InlineData("sig-0190a000-0000-7000-8000-00000000000a-0190a000-0000-7000-8000-0000000000b1-x", false)]
    [InlineData("tpk-0190a000-0000-7000-8000-00000000000a", false)]
    [InlineData("totp-0190a000-0000-7000-8000-00000000000a", false)]
    [InlineData("dep-records", false)]
    [InlineData("sig-00000000-0000-0000-0000-000000000000-0190a000-0000-7000-8000-0000000000b1", false)]
    [InlineData("", false)]
    public void Only_sig_and_mgmt_row_names_parse(string name, bool parses)
    {
        Assert.Equal(parses, KeyName.TryParseRowKey(name, out var key));
        if (parses)
        {
            Assert.Equal(name, key!.Value);
            Assert.Equal(KeyKind.Signing, key.Kind);
        }
    }

    [Fact]
    public void Orphan_candidates_are_row_keys_at_least_24_hours_old()
    {
        var now = DateTimeOffset.UtcNow;
        var key = KeyName.Signing(Guid.CreateVersion7(), Guid.CreateVersion7());

        Assert.True(KeysContract.IsOrphanCandidate(new ListedKey(key, now - TimeSpan.FromHours(24)), now));
        Assert.False(KeysContract.IsOrphanCandidate(new ListedKey(key, now - TimeSpan.FromHours(23.9)), now));
        Assert.False(KeysContract.IsOrphanCandidate(new ListedKey(KeyName.ForTenant(TenantKeyClass.TokenProtection, Guid.CreateVersion7()), now - TimeSpan.FromDays(30)), now));
    }

    private async Task<(ProtocolDatabase Database, Guid Tenant)> ProvisionedAsync()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        return (database, await AddProvisionedAsync(database));
    }

    private async Task<Guid> AddProvisionedAsync(ProtocolDatabase database)
    {
        var tenant = (await database.AddTenantAsync($"t{Guid.NewGuid():N}.rotation.test")).TenantId;
        Assert.True(await database.ProvisionAsync(bao, tenant));
        return tenant;
    }

    /// <summary>A Tenant whose signing key has rotated once, so it has a fresh previous.</summary>
    private async Task<(ProtocolDatabase Database, Guid Tenant)> RotatedAsync()
    {
        var (database, tenant) = await ProvisionedAsync();
        await AgeAsync(database, tenant, "signing", currentDays: 150, nextPublishedMinutes: 20);
        Assert.True(await database.RotateAsync(bao, tenant));
        return (database, tenant);
    }

    /// <summary>A Tenant with one retired signing key and its destroy job pending.</summary>
    private async Task<(ProtocolDatabase Database, Guid Tenant, Guid Retired)> RetiredAsync()
    {
        var (database, tenant) = await RotatedAsync();
        var previous = await IdAsync(database, tenant, "signing", "previous");
        await database.BackdateAsync($"UPDATE signing_key SET rotated_at = now() - interval '2 hours' WHERE id = '{previous}'");
        Assert.True(await database.RotateAsync(bao, tenant));
        Assert.Equal("retired", await StateAsync(database, previous));
        return (database, tenant, previous);
    }

    /// <summary>Rotates the signing purpose once more, so the Tenant also has a fresh previous.</summary>
    private async Task RotateSigningAgainAsync(ProtocolDatabase database, Guid tenant)
    {
        await AgeAsync(database, tenant, "signing", currentDays: 150, nextPublishedMinutes: 20);
        Assert.True(await database.RotateAsync(bao, tenant));
    }

    /// <summary>
    /// Ages the purpose's current key by its creation time, and its next key's publication, if given.
    /// </summary>
    private static Task AgeAsync(ProtocolDatabase database, Guid tenant, string purpose, int currentDays, int? nextPublishedMinutes) =>
        database.BackdateAsync(
            $"UPDATE signing_key SET created_at = now() - make_interval(days => {currentDays}) WHERE tenant_id = '{tenant}' AND purpose = '{purpose}' AND state = 'current'"
            + (nextPublishedMinutes is { } minutes
                ? $"; UPDATE signing_key SET published_at = now() - make_interval(mins => {minutes}) WHERE tenant_id = '{tenant}' AND purpose = '{purpose}' AND state = 'next'"
                : string.Empty));

    /// <summary>A sig- key in Transit that no row names.</summary>
    private async Task<KeyName> OrphanAsync(Guid tenant)
    {
        var key = KeyName.Signing(tenant, Guid.CreateVersion7());
        using var worker = bao.Custody(OpenBaoFixture.Worker);
        await worker.CreateKeyAsync(key, Cancellation);
        return key;
    }

    private static async Task RunJobAsync(ProtocolDatabase database, string type, IKeyCustody custody, Microsoft.Extensions.Logging.ILogger? logger = null)
    {
        await using (var source = NpgsqlDataSource.Create(database.Role(TableRegistry.Worker)))
        await using (var scope = await DeploymentScope.BeginAsync(source, Cancellation))
        {
            await using var command = scope.CreateCommandContext().CreateCommand();
            command.CommandText = $"INSERT INTO job (id, type, deployment_wide) VALUES (gen_random_uuid(), '{type}', true)";
            await command.ExecuteNonQueryAsync(Cancellation);
            await scope.CommitAsync(Cancellation);
        }

        await using var runner = database.Runner(custody, logger);
        Assert.True(await runner.RunOnceAsync(Cancellation));
    }

    private static async Task EnqueueDestroyAsync(ProtocolDatabase database, Guid tenant, Guid row)
    {
        await using var source = NpgsqlDataSource.Create(database.Role(TableRegistry.Worker));
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        await OperationsContract.CreateEnqueuer(OperationsContract.ProductionRegistry, custody: null).EnqueueAsync(
            scope.CreateCommandContext(),
            OperationsContract.DestroySigningKey,
            new JobPayload(new Dictionary<string, Guid> { [KeysContract.DestroyPayloadId] = row }),
            runAfter: null,
            Cancellation);
        await scope.CommitAsync(Cancellation);
    }

    private static async Task InScopeAsync(ProtocolDatabase database, string role, Guid tenant, string sql)
    {
        await using var source = NpgsqlDataSource.Create(database.Role(role));
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(Cancellation);
        await scope.CommitAsync(Cancellation);
    }

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

    private static Task<Guid> IdAsync(ProtocolDatabase database, Guid tenant, string purpose, string state) =>
        database.ScalarAsync<Guid>($"SELECT id FROM signing_key WHERE tenant_id = '{tenant}' AND purpose = '{purpose}' AND state = '{state}'");

    private static Task<string> StateAsync(ProtocolDatabase database, Guid id) =>
        database.ScalarAsync<string>($"SELECT state FROM signing_key WHERE id = '{id}'");

    private static Task<string> RowsAsync(ProtocolDatabase database, Guid tenant) =>
        database.ScalarAsync<string>(
            $"SELECT string_agg(purpose || '/' || state, ',' ORDER BY purpose, state) FROM signing_key WHERE tenant_id = '{tenant}'");

    /// <summary>Every column of the Tenant's rows (of one purpose, or but one row), so any change shows.</summary>
    private static Task<string> SnapshotAsync(ProtocolDatabase database, Guid tenant, string? purpose = null, Guid? excluding = null) =>
        database.ScalarAsync<string>(
            $"SELECT coalesce(string_agg(to_jsonb(s)::text, ',' ORDER BY id), '') FROM signing_key s WHERE tenant_id = '{tenant}'"
            + (purpose is null ? string.Empty : $" AND purpose = '{purpose}'")
            + (excluding is null ? string.Empty : $" AND id <> '{excluding}'"));

    /// <summary>Answers 403 to every read of one path, as OpenBao does for a key the login may not read.</summary>
    private sealed class RefuseRead(HttpMessageHandler inner, string path) : DelegatingHandler(inner)
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            request.Method == HttpMethod.Get && request.RequestUri!.AbsolutePath == path
                ? Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.Forbidden) { Content = new StringContent("{}") })
                : base.SendAsync(request, cancellationToken);
    }

    private static Task<string> EventsAsync(ProtocolDatabase database, Guid tenant, params string[] codes) =>
        database.ScalarAsync<string>(
            "SELECT " + string.Join(
                " || '/' || ",
                codes.Select(c => $"(SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{c}')")));
}
