using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Keys.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Keys;

/// <summary>
/// Story 9.3 (FR-38, AD-11): <see cref="KeysContract.RevokeSigningKeyAsync"/>, the Tenant Owner's
/// revocation of one published Signing Key, as <c>gk_admin</c> with the real <c>host-admin</c> custody
/// policy, against the real PostgreSQL and OpenBao; then the Worker's destruction of the revoked key. Rows
/// are aged by moving their times back as the superuser, never by waiting. No assertion prints a key name,
/// a version or key material.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class SigningKeyRevokeTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string Revoked = "keys.signing_key.revoked";
    private const string Promoted = "keys.signing_key.promoted";
    private const string PromotedUnaged = "keys.signing_key.promoted_unaged";
    private const string Created = "keys.signing_key.created";
    private const string Destroyed = "keys.signing_key.destroyed";
    private const string DestructionFailed = "keys.signing_key.destruction_failed";

    private const string Destroy = "keys.signing_key.destroy";

    private const string OpenRows = "management/current,management/next,signing/current,signing/next";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_previous_key_is_revoked_alone_and_its_destruction_queued()
    {
        var (database, tenant) = await RotatedAsync();
        var previous = await IdAsync(database, tenant, "previous");
        var open = await OpenSnapshotAsync(database, tenant);
        var admin = Guid.CreateVersion7();

        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Admin));
        var revocation = await RevokeAsync(database, tenant, custody, admin, await KeyIdAsync(database, previous));

        Assert.Equal(SigningKeyRevocationStatus.Revoked, revocation.Status);
        Assert.Equal("revoked", await StateAsync(database, previous));
        Assert.Equal(0, custody.Calls(KeyOperation.Create));
        Assert.Equal(open, await OpenSnapshotAsync(database, tenant));
        Assert.Equal(DestroyPayload(previous), await QueuedAsync(database));
        // The setup's rotation wrote one promoted and one created; revoking previous adds only revoked.
        Assert.Equal("1/1/0/1", await EventsAsync(database, tenant, Revoked, Promoted, PromotedUnaged, Created));
        Assert.Equal(1L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Revoked}' AND actor_kind = 'admin' AND actor_id = '{admin}'"));

        // Out of JWKS at once: the published set no longer names it.
        Assert.DoesNotContain(await KeyIdAsync(database, previous), await PublishedAsync(database, tenant));
    }

    [Fact]
    public async Task A_current_key_with_an_aged_next_promotes_it_and_creates_a_new_next()
    {
        var (database, tenant) = await ProvisionedAsync();
        var current = await IdAsync(database, tenant, "current");
        var next = await IdAsync(database, tenant, "next");
        await PublishedAgoAsync(database, tenant, minutes: 20);
        var management = await SnapshotAsync(database, tenant, "management");
        var admin = Guid.CreateVersion7();

        using var custody = bao.Custody(OpenBaoFixture.Admin);
        var revocation = await RevokeAsync(database, tenant, custody, admin, await KeyIdAsync(database, current));

        Assert.Equal(SigningKeyRevocationStatus.Revoked, revocation.Status);
        Assert.Equal("revoked", await StateAsync(database, current));
        Assert.Equal("current", await StateAsync(database, next));
        Assert.True(await database.ScalarAsync<bool>($"SELECT promoted_at IS NOT NULL FROM signing_key WHERE id = '{next}'"));

        var fresh = await IdAsync(database, tenant, "next");
        Assert.NotEqual(next, fresh);
        Assert.True(await database.ScalarAsync<bool>(
            $"SELECT published_at = created_at AND promoted_at IS NULL AND transit_name = 'sig-{tenant:D}-{fresh:D}' FROM signing_key WHERE id = '{fresh}'"));
        using (var worker = bao.Custody(OpenBaoFixture.Worker))
        {
            Assert.Single(await worker.GetPublicKeysAsync(KeyName.Signing(tenant, fresh), Cancellation));
        }

        await AssertOneCurrentAndNextAsync(database, tenant);
        Assert.Equal(management, await SnapshotAsync(database, tenant, "management"));
        Assert.Equal(DestroyPayload(current), await QueuedAsync(database));
        Assert.Equal("1/1/0/1", await EventsAsync(database, tenant, Revoked, Promoted, PromotedUnaged, Created));
        Assert.Equal(3L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code IN ('{Revoked}', '{Promoted}', '{Created}') AND actor_kind = 'admin' AND actor_id = '{admin}'"));
    }

    [Fact]
    public async Task A_current_key_with_a_young_next_still_promotes_it_and_records_it_unaged()
    {
        var (database, tenant) = await ProvisionedAsync();
        var current = await IdAsync(database, tenant, "current");
        var next = await IdAsync(database, tenant, "next");
        await PublishedAgoAsync(database, tenant, minutes: 2);

        using var custody = bao.Custody(OpenBaoFixture.Admin);
        var revocation = await RevokeAsync(database, tenant, custody, Guid.CreateVersion7(), await KeyIdAsync(database, current));

        Assert.Equal(SigningKeyRevocationStatus.Revoked, revocation.Status);
        Assert.Equal("revoked", await StateAsync(database, current));
        Assert.Equal("current", await StateAsync(database, next));
        await AssertOneCurrentAndNextAsync(database, tenant);
        Assert.Equal("1/0/1/1", await EventsAsync(database, tenant, Revoked, Promoted, PromotedUnaged, Created));
    }

    [Fact]
    public async Task A_next_key_is_replaced_and_current_is_unchanged()
    {
        var (database, tenant) = await ProvisionedAsync();
        var current = await IdAsync(database, tenant, "current");
        var next = await IdAsync(database, tenant, "next");
        var currentBefore = await RowAsync(database, current);

        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Admin));
        var revocation = await RevokeAsync(database, tenant, custody, Guid.CreateVersion7(), await KeyIdAsync(database, next));

        Assert.Equal(SigningKeyRevocationStatus.Revoked, revocation.Status);
        Assert.Equal("revoked", await StateAsync(database, next));
        Assert.Equal(currentBefore, await RowAsync(database, current));
        Assert.Equal(1, custody.Calls(KeyOperation.Create));
        Assert.NotEqual(next, await IdAsync(database, tenant, "next"));
        await AssertOneCurrentAndNextAsync(database, tenant);
        Assert.Equal(DestroyPayload(next), await QueuedAsync(database));
        Assert.Equal("1/0/0/1", await EventsAsync(database, tenant, Revoked, Promoted, PromotedUnaged, Created));
    }

    public static TheoryData<string> Unknown => new()
    {
        "unknown",
        "",
        "sig-",
        ".v1",
        "rowid.v1",
        "{signing}.v2",
        "{signing}.v01",
        "{signing}.v0",
        "{signing}.v",
        "{signing}.v1x",
        "{signing}",
        "{SIGNING}.v1",
        "{management}.v1",
        "{retired}.v1",
        "{revoked}.v1",
        "{other}.v1",
        "{absent}.v1",
    };

    [Theory]
    [MemberData(nameof(Unknown))]
    public async Task A_key_ID_naming_no_published_signing_key_of_the_Tenant_is_not_found_and_writes_nothing(string template)
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var tenant = await AddProvisionedAsync(database);
        var other = await AddProvisionedAsync(database);

        // One retired and one revoked row, as the superuser: neither is published.
        var retired = Guid.CreateVersion7();
        var revoked = Guid.CreateVersion7();
        await database.ExecuteAsync(
            "INSERT INTO signing_key (id, tenant_id, purpose, state, transit_name, transit_version, published_at, promoted_at, rotated_at, retired_at) VALUES "
            + $"('{retired}', '{tenant}', 'signing', 'retired', 'sig-{tenant:D}-{retired:D}', 1, now(), now(), now(), now()), "
            + $"('{revoked}', '{tenant}', 'signing', 'revoked', 'sig-{tenant:D}-{revoked:D}', 1, now(), now(), NULL, NULL)");

        var signing = await IdAsync(database, tenant, "current");
        var keyId = template
            .Replace("{signing}", $"sig-{tenant:D}-{signing:D}", StringComparison.Ordinal)
            .Replace("{SIGNING}", $"sig-{tenant:D}-{signing:D}".ToUpperInvariant(), StringComparison.Ordinal)
            .Replace("{management}", $"mgmt-{tenant:D}-{await ManagementIdAsync(database, tenant):D}", StringComparison.Ordinal)
            .Replace("{retired}", $"sig-{tenant:D}-{retired:D}", StringComparison.Ordinal)
            .Replace("{revoked}", $"sig-{tenant:D}-{revoked:D}", StringComparison.Ordinal)
            .Replace("{other}", $"sig-{other:D}-{await IdAsync(database, other, "current"):D}", StringComparison.Ordinal)
            .Replace("{absent}", $"sig-{tenant:D}-{Guid.CreateVersion7():D}", StringComparison.Ordinal);
        var before = await SnapshotAsync(database, tenant);
        var otherBefore = await SnapshotAsync(database, other);

        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Admin));
        var revocation = await RevokeAsync(database, tenant, custody, Guid.CreateVersion7(), keyId);

        Assert.Equal(SigningKeyRevocationStatus.NotFound, revocation.Status);
        Assert.Equal(0, custody.TotalCalls);
        Assert.Equal(before, await SnapshotAsync(database, tenant));
        Assert.Equal(otherBefore, await SnapshotAsync(database, other));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM job WHERE type = '{Destroy}'"));
        Assert.Equal("0/0/0/0", await EventsAsync(database, tenant, Revoked, Promoted, PromotedUnaged, Created));
    }

    [Fact]
    public async Task A_custody_failure_throws_before_any_row_moves_and_the_rollback_leaves_everything()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var tenant = await AddProvisionedAsync(database);
        var other = await AddProvisionedAsync(database);
        var current = await IdAsync(database, tenant, "current");
        var before = await SnapshotAsync(database, tenant);
        var otherBefore = await SnapshotAsync(database, other);

        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Admin));
        custody.Failing.Add(KeyOperation.Create);
        var keyId = await KeyIdAsync(database, current);

        await Assert.ThrowsAsync<KeyCustodyException>(() => RevokeAsync(database, tenant, custody, Guid.CreateVersion7(), keyId));

        Assert.Equal("current", await StateAsync(database, current));
        Assert.Equal(before, await SnapshotAsync(database, tenant));
        Assert.Equal(otherBefore, await SnapshotAsync(database, other));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM job WHERE type = '{Destroy}'"));
        Assert.Equal("0/0/0/0", await EventsAsync(database, tenant, Revoked, Promoted, PromotedUnaged, Created));
    }

    [Fact]
    public async Task Another_Tenants_rows_are_byte_identical_after_a_revocation()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = await AddProvisionedAsync(database);
        var b = await AddProvisionedAsync(database);
        var bBefore = await SnapshotAsync(database, b);

        using var custody = bao.Custody(OpenBaoFixture.Admin);
        var current = await IdAsync(database, a, "current");
        Assert.Equal(SigningKeyRevocationStatus.Revoked, (await RevokeAsync(database, a, custody, Guid.CreateVersion7(), await KeyIdAsync(database, current))).Status);

        Assert.Equal(bBefore, await SnapshotAsync(database, b));
        Assert.Equal("0/0/0/0", await EventsAsync(database, b, Revoked, Promoted, PromotedUnaged, Created));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM job WHERE tenant_id = '{b}'"));
    }

    [Fact]
    public async Task The_destroy_job_deletes_a_revoked_keys_Transit_key_and_a_failure_retries()
    {
        var (database, tenant) = await RotatedAsync();
        var previous = await IdAsync(database, tenant, "previous");
        using (var admin = bao.Custody(OpenBaoFixture.Admin))
        {
            Assert.Equal(SigningKeyRevocationStatus.Revoked, (await RevokeAsync(database, tenant, admin, Guid.CreateVersion7(), await KeyIdAsync(database, previous))).Status);
        }

        // First attempt: custody fails, the failure is kept and the job retries.
        using (var failing = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker)))
        {
            failing.Failing.Add(KeyOperation.Delete);
            await using var runner = database.Runner(failing);
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        Assert.Equal("pending/custody_failed/1", await database.ScalarAsync<string>(
            $"SELECT status || '/' || failure_code || '/' || attempts FROM job WHERE type = '{Destroy}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{DestructionFailed}'"));
        Assert.True(await database.ScalarAsync<bool>($"SELECT destroyed_at IS NULL FROM signing_key WHERE id = '{previous}'"));

        // The retry, once due, destroys it.
        await database.BackdateAsync($"UPDATE job SET run_after = now() WHERE type = '{Destroy}'");
        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker));
        await using (var runner = database.Runner(custody))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        Assert.Equal("done", await database.ScalarAsync<string>($"SELECT status FROM job WHERE type = '{Destroy}'"));
        Assert.True(await database.ScalarAsync<bool>($"SELECT state = 'revoked' AND destroyed_at IS NOT NULL FROM signing_key WHERE id = '{previous}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Destroyed}' AND actor_kind = 'system'"));
        Assert.Equal([KeyName.Signing(tenant, previous).Value], custody.Deleted);

        using var worker = bao.Custody(OpenBaoFixture.Worker);
        var gone = await Assert.ThrowsAsync<KeyCustodyException>(() => worker.GetPublicKeysAsync(KeyName.Signing(tenant, previous), Cancellation));
        Assert.Equal(KeyCustodyFailure.Rejected, gone.Failure);
    }

    [Fact]
    public async Task A_revoked_keys_dead_destroy_job_is_queued_again_by_the_daily_rotation()
    {
        var (database, tenant) = await ProvisionedAsync();
        var next = await IdAsync(database, tenant, "next");
        using (var admin = bao.Custody(OpenBaoFixture.Admin))
        {
            Assert.Equal(SigningKeyRevocationStatus.Revoked, (await RevokeAsync(database, tenant, admin, Guid.CreateVersion7(), await KeyIdAsync(database, next))).Status);
        }

        await database.BackdateAsync($"UPDATE job SET status = 'dead', finished_at = now() WHERE type = '{Destroy}'");

        Assert.True(await database.RotateAsync(bao, tenant));

        Assert.Equal(
            $"pending|{{\"signing_key_id\": \"{next}\"}}",
            await database.ScalarAsync<string>(
                $"SELECT j.status || '|' || p.ids::text FROM job j JOIN job_payload p ON p.job_id = j.id WHERE j.type = '{Destroy}' AND j.status = 'pending'"));
    }

    [Fact]
    public async Task It_needs_the_Tenants_own_scope()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = await AddProvisionedAsync(database);
        var b = await AddProvisionedAsync(database);
        var keyId = await KeyIdAsync(database, await IdAsync(database, b, "current"));

        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Admin));
        await using var source = NpgsqlDataSource.Create(database.Role(TableRegistry.Admin));
        await using var scope = await TenantScope.BeginAsync(source, a, Cancellation);

        await Assert.ThrowsAsync<InvalidOperationException>(() => KeysContract.RevokeSigningKeyAsync(
            scope.CreateCommandContext(),
            custody,
            AuditContract.CreateAppender(),
            OperationsContract.CreateEnqueuer(OperationsContract.ProductionRegistry, custody: null),
            OperationsContract.DestroySigningKey,
            Actor.Admin(Guid.CreateVersion7()),
            b,
            keyId,
            Cancellation));
        Assert.Equal(0, custody.TotalCalls);
    }

    private async Task<(ProtocolDatabase Database, Guid Tenant)> ProvisionedAsync()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        return (database, await AddProvisionedAsync(database));
    }

    /// <summary>A Tenant whose signing key has rotated once on demand, so it has a previous.</summary>
    private async Task<(ProtocolDatabase Database, Guid Tenant)> RotatedAsync()
    {
        var (database, tenant) = await ProvisionedAsync();
        await PublishedAgoAsync(database, tenant, minutes: 20);
        await using (var source = NpgsqlDataSource.Create(database.Role(TableRegistry.Admin)))
        await using (var scope = await TenantScope.BeginAsync(source, tenant, Cancellation))
        {
            using var custody = bao.Custody(OpenBaoFixture.Admin);
            var rotation = await KeysContract.RotateSigningKeyNowAsync(
                scope.CreateCommandContext(), custody, AuditContract.CreateAppender(), Actor.Admin(Guid.CreateVersion7()), tenant, Cancellation);
            Assert.Equal(SigningKeyRotationStatus.Rotated, rotation.Status);
            await scope.CommitAsync(Cancellation);
        }

        return (database, tenant);
    }

    private async Task<Guid> AddProvisionedAsync(ProtocolDatabase database)
    {
        var tenant = (await database.AddTenantAsync($"t{Guid.NewGuid():N}.revoke.test")).TenantId;
        Assert.True(await database.ProvisionAsync(bao, tenant));
        return tenant;
    }

    /// <summary>The revocation as Host.Admin runs it: as <c>gk_admin</c> in the Tenant's own scope, committed only when it revoked.</summary>
    private static async Task<SigningKeyRevocation> RevokeAsync(ProtocolDatabase database, Guid tenant, IKeyCustody custody, Guid admin, string keyId)
    {
        await using var source = NpgsqlDataSource.Create(database.Role(TableRegistry.Admin));
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        var revocation = await KeysContract.RevokeSigningKeyAsync(
            scope.CreateCommandContext(),
            custody,
            AuditContract.CreateAppender(),
            OperationsContract.CreateEnqueuer(OperationsContract.ProductionRegistry, custody: null),
            OperationsContract.DestroySigningKey,
            Actor.Admin(admin),
            tenant,
            keyId,
            Cancellation);
        if (revocation.Status == SigningKeyRevocationStatus.Revoked)
        {
            await scope.CommitAsync(Cancellation);
        }

        return revocation;
    }

    /// <summary>Backdates the Tenant's signing next's publication.</summary>
    private static Task PublishedAgoAsync(ProtocolDatabase database, Guid tenant, int minutes) =>
        database.BackdateAsync(
            $"UPDATE signing_key SET published_at = now() - make_interval(mins => {minutes}) WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND state = 'next'");

    private static Task<string> KeyIdAsync(ProtocolDatabase database, Guid id) =>
        database.ScalarAsync<string>($"SELECT transit_name || '.v' || transit_version FROM signing_key WHERE id = '{id}'");

    /// <summary>The kids the Tenant's JWKS serves: its signing next, current and previous rows.</summary>
    private static async Task<IReadOnlyList<string>> PublishedAsync(ProtocolDatabase database, Guid tenant) =>
        (await database.ScalarAsync<string>(
            $"SELECT coalesce(string_agg(transit_name || '.v' || transit_version, ','), '') FROM signing_key WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND state IN ('next', 'current', 'previous')"))
        .Split(',', StringSplitOptions.RemoveEmptyEntries);

    private static string DestroyPayload(Guid id) => $"pending|{{\"signing_key_id\": \"{id}\"}}";

    private static Task<string> QueuedAsync(ProtocolDatabase database) =>
        database.ScalarAsync<string>(
            $"SELECT string_agg(j.status || '|' || p.ids::text, ',') FROM job j JOIN job_payload p ON p.job_id = j.id WHERE j.type = '{Destroy}'");

    private static async Task AssertOneCurrentAndNextAsync(ProtocolDatabase database, Guid tenant) =>
        Assert.Equal(
            OpenRows,
            await database.ScalarAsync<string>(
                $"SELECT string_agg(purpose || '/' || state, ',' ORDER BY purpose, state) FROM signing_key WHERE tenant_id = '{tenant}' AND state IN ('current', 'next')"));

    private static Task<Guid> IdAsync(ProtocolDatabase database, Guid tenant, string state) =>
        database.ScalarAsync<Guid>(
            $"SELECT id FROM signing_key WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND state = '{state}' ORDER BY created_at DESC LIMIT 1");

    private static Task<Guid> ManagementIdAsync(ProtocolDatabase database, Guid tenant) =>
        database.ScalarAsync<Guid>($"SELECT id FROM signing_key WHERE tenant_id = '{tenant}' AND purpose = 'management' AND state = 'current'");

    private static Task<string> StateAsync(ProtocolDatabase database, Guid id) =>
        database.ScalarAsync<string>($"SELECT state FROM signing_key WHERE id = '{id}'");

    private static Task<string> RowAsync(ProtocolDatabase database, Guid id) =>
        database.ScalarAsync<string>($"SELECT to_jsonb(s)::text FROM signing_key s WHERE id = '{id}'");

    /// <summary>Every column of the Tenant's open rows, so any change to current, next or previous shows.</summary>
    private static Task<string> OpenSnapshotAsync(ProtocolDatabase database, Guid tenant) =>
        database.ScalarAsync<string>(
            $"SELECT coalesce(string_agg(to_jsonb(s)::text, ',' ORDER BY id), '') FROM signing_key s WHERE tenant_id = '{tenant}' AND state IN ('next', 'current')");

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
