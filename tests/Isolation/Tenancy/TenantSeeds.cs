using Gatekeep.Adapters.Postgres.Schema;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Tenancy;

/// <summary>
/// Story 1.29: one row in every <c>tenant</c>-class table the AD-3 registry lists, but Audit's, for a
/// Tenant, so a deletion can be shown to leave none of its rows and every other Tenant's unchanged.
/// A table a later story adds fails <c>TenantPurgeRegistryTests</c> until it has a seed here and a
/// purge in its owner. Seeds are written as the superuser, triggers off, for one Tenant at a time:
/// every statement names that Tenant's ID and nothing else.
/// </summary>
internal static class TenantSeeds
{
    /// <summary>The owner whose chain is kept until its retention ends, so it is never purged with its Tenant.</summary>
    public const string KeptOwner = "Audit";

    /// <summary>Each table's seed, parents before children, for the Tenant and a value unique to the call.</summary>
    public static readonly IReadOnlyList<(string Table, Func<Guid, Guid, string> Sql)> Seeds =
    [
        ("tenant_settings", (t, _) => $"INSERT INTO tenant_settings (tenant_id) VALUES ('{t}') ON CONFLICT DO NOTHING"),
        ("job_payload", (t, n) =>
            $"INSERT INTO job (id, type, tenant_id, deployment_wide, run_after) VALUES ('{n}', 'audit.retention.apply', '{t}', false, now() + interval '30 days'); " +
            $"INSERT INTO job_payload (tenant_id, job_id, ids) VALUES ('{t}', '{n}', '{{}}')"),
        ("application", (t, n) =>
            "INSERT INTO application (tenant_id, id, name, kind, grant_types, created_at) " +
            $"VALUES ('{t}', '{n}', 'Seeded Application', 'machine', ARRAY['client_credentials'], now())"),
        ("client_secret", (t, n) =>
            "INSERT INTO client_secret (tenant_id, id, application_id, secret_hash, created_at) " +
            $"VALUES ('{t}', '{n}', '{n}', sha256(convert_to('{t}{n}', 'UTF8')), now())"),
        ("api", (t, n) =>
            "INSERT INTO api (tenant_id, id, name, identifier, created_at) " +
            $"VALUES ('{t}', '{n}', 'Seeded API', 'https://seeded.example/{n}', now())"),
        ("permission", (t, n) =>
            "INSERT INTO permission (tenant_id, api_id, value, description, created_at) " +
            $"VALUES ('{t}', '{n}', 'seeded:read', 'Seeded', now())"),
        ("api_grant", (t, n) =>
            "INSERT INTO api_grant (tenant_id, api_id, application_id, value) " +
            $"VALUES ('{t}', '{n}', '{n}', 'seeded:read')"),
        ("tenant_attempt", (t, _) =>
            "INSERT INTO tenant_attempt (tenant_id, policy, subject_hash, window_start, attempts) " +
            $"VALUES ('{t}', 'authentication.token_request.tenant', sha256(convert_to('{t}', 'UTF8')), now(), 1) ON CONFLICT DO NOTHING"),
        ("user", (t, n) => $"INSERT INTO \"user\" (tenant_id, id) VALUES ('{t}', '{n}')"),
        ("user_session", (t, n) =>
            "INSERT INTO user_session (tenant_id, id, user_id, id_hash, amr, auth_time, idle_expires_at, absolute_expires_at, created_at) " +
            $"VALUES ('{t}', '{n}', '{n}', sha256(convert_to('{t}{n}', 'UTF8')), ARRAY['pwd'], now(), now() + interval '1 hour', now() + interval '8 hours', now())"),
        ("authorization", (t, n) =>
            "INSERT INTO \"authorization\" (tenant_id, id, user_session_id, status, type, concurrency_token) " +
            $"VALUES ('{t}', '{n}', '{n}', 'valid', 'ad-hoc', gen_random_uuid())"),
        ("token", (t, n) =>
            "INSERT INTO token (tenant_id, id, authorization_id, type, status, concurrency_token) " +
            $"VALUES ('{t}', '{n}', '{n}', 'refresh_token', 'valid', gen_random_uuid())"),
        ("signin_transaction", (t, n) =>
            "INSERT INTO signin_transaction (tenant_id, id, application_id, binding_hash, parameters, created_at, expires_at) " +
            $"VALUES ('{t}', '{n}', '{n}', sha256(convert_to('{t}{n}', 'UTF8')), '{{}}', now(), now() + interval '10 minutes')"),
        ("signing_key", (t, n) =>
            // Retired, so it never collides with the current and next keys a real creation makes.
            "INSERT INTO signing_key (id, tenant_id, purpose, state, transit_name, transit_version, published_at, promoted_at, rotated_at, retired_at) " +
            $"VALUES ('{n}', '{t}', 'signing', 'retired', 'sig-{t}-{n}', 1, now(), now(), now(), now())"),
        ("protection_key_wrap", (t, _) =>
            $"INSERT INTO protection_key_wrap (tenant_id, ciphertext) VALUES ('{t}', 'vault:v1:AAAA') ON CONFLICT DO NOTHING"),
    ];

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    /// <summary>The registry's <c>tenant</c> tables a deletion must purge: every one whose owner isn't Audit.</summary>
    public static IReadOnlyList<string> PurgedTables(IEnumerable<TableEntry> registry) =>
        [.. registry.Where(t => t.Class == TableClass.Tenant && t.Owner != KeptOwner).Select(t => t.Name).Order(StringComparer.Ordinal)];

    /// <summary>Each purged table of <paramref name="registry"/> with no seed here: empty when every one has one.</summary>
    public static IReadOnlyList<string> Unseeded(IEnumerable<TableEntry> registry) =>
        [.. PurgedTables(registry).Except(Seeds.Select(s => s.Table), StringComparer.Ordinal)];

    /// <summary>Writes every seed for <paramref name="tenant"/>, in one transaction, as the superuser with triggers off.</summary>
    public static Task SeedAsync(string superuser, Guid tenant)
    {
        var value = Guid.CreateVersion7();
        return PostgresFixture.ExecuteAsync(
            superuser,
            "SET session_replication_role = replica; " + string.Join("; ", Seeds.Select(s => s.Sql(tenant, value))) + "; SET session_replication_role = DEFAULT");
    }

    /// <summary>The seeded tables that still hold a row of <paramref name="tenant"/>, by name.</summary>
    public static async Task<IReadOnlyList<string>> RowsLeftAsync(string superuser, Guid tenant)
    {
        var left = new List<string>();
        foreach (var (table, _) in Seeds)
        {
            if (await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM \"{table}\" WHERE tenant_id = '{tenant}'") > 0)
            {
                left.Add(table);
            }
        }

        return left;
    }

    /// <summary>
    /// Every row of <paramref name="tenant"/> in every registry table, as JSON per table: each table
    /// with a <c>tenant_id</c> column, and the <c>tenant</c> row itself. Two snapshots are equal only when
    /// no row of the Tenant was added, changed or removed.
    /// </summary>
    public static async Task<Dictionary<string, string>> SnapshotAsync(string superuser, Guid tenant)
    {
        var snapshot = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var entry in TableRegistry.Tables)
        {
            var hasTenantId = await PostgresFixture.ScalarAsync<bool>(
                superuser,
                $"SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '{entry.Name}' AND column_name = 'tenant_id')");
            var where = hasTenantId ? $"tenant_id = '{tenant}'" : entry.Name == "tenant" ? $"id = '{tenant}'" : null;
            if (where is null)
            {
                continue;
            }

            snapshot[entry.Name] = await RowsAsync(superuser, $"SELECT to_jsonb(r)::text FROM \"{entry.Name}\" r WHERE {where} ORDER BY 1");
        }

        return snapshot;
    }

    private static async Task<string> RowsAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(Cancellation);
        var rows = new List<string>();
        while (await reader.ReadAsync(Cancellation))
        {
            rows.Add(reader.GetString(0));
        }

        return string.Join("\n", rows);
    }
}
