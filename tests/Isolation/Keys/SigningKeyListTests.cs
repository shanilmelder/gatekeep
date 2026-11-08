using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Keys.Contracts;
using Gatekeep.Tests.Isolation.Protocol;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Keys;

/// <summary>
/// Signing key rows in every state for one Tenant, written as the superuser with their lifecycle
/// times backdated (Story 9.1). No Transit key is made: a test that needs the public halves gives
/// custody its own.
/// </summary>
internal static class SigningKeySeeds
{
    /// <summary>One seeded row: its <c>kid</c>, its state and its Transit key.</summary>
    public sealed record Seeded(string KeyId, string State, KeyName Key, int Version);

    /// <summary>
    /// A signing row in each of the five states, a second retired row whose Transit key is destroyed,
    /// and a <c>current</c> and a <c>next</c> Management key. Returns the signing rows in the order the
    /// list must give them, then the Management rows.
    /// </summary>
    public static async Task<(IReadOnlyList<Seeded> Signing, IReadOnlyList<Seeded> Management)> EveryStateAsync(string superuser, Guid tenant)
    {
        // Ages in days. Retired and revoked rows are listed together, newest first.
        var signing = new (string State, int Age)[]
        {
            ("next", 1),
            ("current", 100),
            ("previous", 200),
            ("retired", 300),
            ("revoked", 350),
            ("retired-destroyed", 400),
        };

        var rows = new List<Seeded>();
        var sql = new List<string>();
        foreach (var (state, age) in signing)
        {
            var id = Guid.CreateVersion7();
            var key = KeyName.Signing(tenant, id);
            var stored = state == "retired-destroyed" ? "retired" : state;
            sql.Add(Insert(id, tenant, "signing", stored, key, age, destroyed: state == "retired-destroyed"));
            rows.Add(new Seeded($"{key.Value}.v1", stored, key, 1));
        }

        var management = new List<Seeded>();
        foreach (var state in new[] { "current", "next" })
        {
            var id = Guid.CreateVersion7();
            var key = KeyName.Management(tenant, id);
            sql.Add(Insert(id, tenant, "management", state, key, 1, destroyed: false));
            management.Add(new Seeded($"{key.Value}.v1", state, key, 1));
        }

        await PostgresFixture.ExecuteAsync(superuser, string.Join("; ", sql));
        return (rows, management);
    }

    /// <summary>A Tenant's own <c>current</c> and <c>next</c> of each purpose, as a new Tenant has them. Returns its signing rows, next first.</summary>
    public static async Task<IReadOnlyList<Seeded>> FreshAsync(string superuser, Guid tenant)
    {
        var rows = new List<Seeded>();
        var sql = new List<string>();
        foreach (var purpose in new[] { "signing", "management" })
        {
            foreach (var state in new[] { "next", "current" })
            {
                var id = Guid.CreateVersion7();
                var key = purpose == "signing" ? KeyName.Signing(tenant, id) : KeyName.Management(tenant, id);
                sql.Add(Insert(id, tenant, purpose, state, key, 0, destroyed: false));
                if (purpose == "signing")
                {
                    rows.Add(new Seeded($"{key.Value}.v1", state, key, 1));
                }
            }
        }

        await PostgresFixture.ExecuteAsync(superuser, string.Join("; ", sql));
        return rows;
    }

    private static string Insert(Guid id, Guid tenant, string purpose, string state, KeyName key, int age, bool destroyed)
    {
        var created = $"now() - interval '{age} days'";
        var published = purpose == "signing" ? created : "NULL";
        var promoted = state is "current" or "previous" or "retired" ? created : "NULL";
        var rotated = state is "previous" or "retired" ? created : "NULL";
        var retired = state == "retired" ? created : "NULL";
        var gone = destroyed ? created : "NULL";
        return "INSERT INTO signing_key (id, tenant_id, purpose, state, transit_name, transit_version, created_at, published_at, promoted_at, rotated_at, retired_at, destroyed_at) " +
            $"VALUES ('{id}', '{tenant}', '{purpose}', '{state}', '{key.Value}', 1, {created}, {published}, {promoted}, {rotated}, {retired}, {gone})";
    }
}

/// <summary>
/// Story 9.1 (FR-37, AD-11, AD-33): <see cref="KeysContract.ListSigningKeysAsync"/>, as gk_admin, against
/// the real PostgreSQL. It lists a Tenant's signing rows in every state, in the page's order, never a
/// Management key or another Tenant's, and only in a Tenant scope.
/// </summary>
public sealed class SigningKeyListTests(PostgresFixture postgres)
{
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Every_state_is_listed_in_order_and_never_a_Management_key()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var tenant = (await database.AddTenantAsync("every.list.keys.test")).TenantId;
        var (signing, management) = await SigningKeySeeds.EveryStateAsync(database.Superuser, tenant);

        var listed = await ListAsync(database, tenant);

        Assert.Equal(signing.Select(s => (s.KeyId, s.State)), listed.Select(k => (k.KeyId, Stored(k.State))));
        Assert.Equal(6, listed.Count);
        Assert.Equal(["next", "current", "previous", "retired", "revoked", "retired"], listed.Select(k => Stored(k.State)));
        Assert.All(listed, k => Assert.StartsWith($"sig-{tenant:D}-", k.KeyId, StringComparison.Ordinal));
        Assert.Empty(listed.Select(k => k.KeyId).Intersect(management.Select(m => m.KeyId)));
        Assert.All(listed, k => Assert.Equal(TimeSpan.Zero, k.CreatedAt.Offset));

        // Newest first among retired and revoked rows, by creation time.
        var ended = listed.Skip(3).Select(k => k.CreatedAt).ToList();
        Assert.Equal(ended.OrderDescending(), ended);
    }

    [Fact]
    public async Task A_fresh_Tenant_lists_its_next_and_current_keys_only()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var tenant = (await database.AddTenantAsync("fresh.list.keys.test")).TenantId;
        var fresh = await SigningKeySeeds.FreshAsync(database.Superuser, tenant);

        var listed = await ListAsync(database, tenant);

        Assert.Equal(fresh.Select(s => (s.KeyId, s.State)), listed.Select(k => (k.KeyId, Stored(k.State))));
    }

    [Fact]
    public async Task One_Tenants_list_holds_none_of_anothers_keys()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = (await database.AddTenantAsync("a.list.keys.test")).TenantId;
        var b = (await database.AddTenantAsync("b.list.keys.test")).TenantId;
        var mine = await SigningKeySeeds.FreshAsync(database.Superuser, a);
        await SigningKeySeeds.EveryStateAsync(database.Superuser, b);

        var listed = await ListAsync(database, a);

        Assert.Equal(mine.Select(s => s.KeyId), listed.Select(k => k.KeyId));
    }

    [Fact]
    public async Task The_list_needs_a_Tenant_scope()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database.Name));
        await using var scope = await DeploymentScope.BeginAsync(source, Cancellation);

        await Assert.ThrowsAsync<InvalidOperationException>(() => KeysContract.ListSigningKeysAsync(scope.CreateCommandContext(), Cancellation));
    }

    private async Task<IReadOnlyList<ListedSigningKey>> ListAsync(ProtocolDatabase database, Guid tenant)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database.Name));
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        var listed = await KeysContract.ListSigningKeysAsync(scope.CreateCommandContext(), Cancellation);
        await scope.CommitAsync(Cancellation);
        return listed;
    }

    private static string Stored(SigningKeyState state) => state.ToString().ToLowerInvariant();
}
