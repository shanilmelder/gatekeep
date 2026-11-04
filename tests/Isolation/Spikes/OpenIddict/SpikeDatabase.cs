using Gatekeep.Adapters.Postgres.Schema;
using Npgsql;

namespace Gatekeep.Tests.Isolation.Spikes.OpenIddict;

/// <summary>
/// The store backing for Story 2.2: a migrated clone holding both <c>tenant</c> rows and three
/// spike tables. Each table has <c>tenant_id</c>, the same ENABLE/FORCE row-level security pair
/// as the migrated tenant tables, and only the grants <c>gk_hosted</c> needs. Nothing here is a
/// migration or a <c>TableRegistry</c> entry: the tables exist only in this test database.
/// </summary>
public sealed class SpikeDatabase : IAsyncDisposable
{
    public const string AuditTypeCode = "sessions.token_family.revoked";

    private static readonly string[] Tables = ["spike_application", "spike_authorization", "spike_token"];

    private readonly PostgresFixture _postgres;

    private SpikeDatabase(PostgresFixture postgres, string name)
    {
        _postgres = postgres;
        Name = name;
        Hosted = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Hosted, name));
    }

    public string Name { get; }

    /// <summary>What the request path connects as.</summary>
    public NpgsqlDataSource Hosted { get; }

    /// <summary>For seeding and for assertions only. A superuser bypasses row-level security.</summary>
    public string Superuser => _postgres.SuperuserConnection(Name);

    public static async Task<SpikeDatabase> CreateAsync(PostgresFixture postgres, SpikeTenants tenants)
    {
        var name = await postgres.NewMigratedDatabaseAsync();
        var database = new SpikeDatabase(postgres, name);

        await PostgresFixture.ExecuteAsync(database.Superuser, Schema());

        foreach (var tenant in tenants.All)
        {
            await PostgresFixture.ExecuteAsync(database.Superuser, TestTenants.InsertSql(tenant.Id));
            await SeedApplicationsAsync(database.Superuser, tenant);
        }

        return database;
    }

    public async Task<long> CountAsync(string sql) => await PostgresFixture.ScalarAsync<long>(Superuser, sql);

    public async Task ExecuteAsync(string sql) => await PostgresFixture.ExecuteAsync(Superuser, sql);

    public ValueTask DisposeAsync() => Hosted.DisposeAsync();

    private static string Schema()
    {
        var sql = """
            CREATE TABLE spike_application (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              id uuid NOT NULL,
              client_id text NOT NULL,
              client_secret text NULL,
              client_type text NOT NULL,
              application_type text NULL,
              consent_type text NULL,
              display_name text NULL,
              permissions text[] NOT NULL DEFAULT '{}',
              redirect_uris text[] NOT NULL DEFAULT '{}',
              post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',
              requirements text[] NOT NULL DEFAULT '{}',
              settings jsonb NOT NULL DEFAULT '{}',
              properties jsonb NOT NULL DEFAULT '{}',
              PRIMARY KEY (tenant_id, id),
              UNIQUE (tenant_id, client_id)
            );

            CREATE TABLE spike_authorization (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              id uuid NOT NULL,
              application_id uuid NULL,
              subject text NULL,
              status text NOT NULL,
              type text NOT NULL,
              scopes text[] NOT NULL DEFAULT '{}',
              creation_date timestamptz NULL,
              properties jsonb NOT NULL DEFAULT '{}',
              concurrency_token uuid NOT NULL,
              PRIMARY KEY (tenant_id, id),
              FOREIGN KEY (tenant_id, application_id) REFERENCES spike_application (tenant_id, id) ON DELETE RESTRICT
            );

            CREATE TABLE spike_token (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              id uuid NOT NULL,
              application_id uuid NULL,
              authorization_id uuid NULL,
              subject text NULL,
              type text NOT NULL,
              status text NOT NULL,
              reference_id text NULL,
              payload text NULL,
              creation_date timestamptz NULL,
              expiration_date timestamptz NULL,
              redemption_date timestamptz NULL,
              properties jsonb NOT NULL DEFAULT '{}',
              concurrency_token uuid NOT NULL,
              PRIMARY KEY (tenant_id, id),
              UNIQUE (tenant_id, reference_id),
              FOREIGN KEY (tenant_id, application_id) REFERENCES spike_application (tenant_id, id) ON DELETE RESTRICT,
              FOREIGN KEY (tenant_id, authorization_id) REFERENCES spike_authorization (tenant_id, id) ON DELETE RESTRICT
            );

            GRANT SELECT ON spike_application TO gk_hosted;
            GRANT SELECT, INSERT, UPDATE ON spike_authorization TO gk_hosted;
            GRANT SELECT, INSERT, UPDATE ON spike_token TO gk_hosted;

            """;

        foreach (var table in Tables)
        {
            sql += $"""
                ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
                ALTER TABLE {table} FORCE ROW LEVEL SECURITY;

                CREATE POLICY {table}_permissive ON {table}
                  AS PERMISSIVE FOR ALL
                  USING (true)
                  WITH CHECK (true);

                CREATE POLICY {table}_tenant ON {table}
                  AS RESTRICTIVE FOR ALL
                  USING (tenant_id = current_setting('gatekeep.tenant_id')::uuid)
                  WITH CHECK (tenant_id = current_setting('gatekeep.tenant_id')::uuid);

                """;
        }

        return sql;
    }

    /// <summary>
    /// The same two clients in each Tenant. The confidential one has no secret in its row: a
    /// Gatekeep handler checks its secret (AD-8), so OpenIddict's column stays null.
    /// </summary>
    private static async Task SeedApplicationsAsync(string superuser, SpikeTenant tenant)
    {
        await using var connection = new NpgsqlConnection(superuser);
        await connection.OpenAsync();

        foreach (var client in SpikeClients.All)
        {
            await using var command = new NpgsqlCommand(
                """
                INSERT INTO spike_application
                  (tenant_id, id, client_id, client_type, application_type, consent_type, permissions, redirect_uris)
                VALUES (@tenant_id, @id, @client_id, @client_type, 'web', 'implicit', @permissions, @redirect_uris)
                """,
                connection);
            command.Parameters.AddWithValue("tenant_id", tenant.Id);
            command.Parameters.AddWithValue("id", Guid.CreateVersion7());
            command.Parameters.AddWithValue("client_id", client.ClientId);
            command.Parameters.AddWithValue("client_type", client.ClientType);
            command.Parameters.AddWithValue("permissions", client.Permissions);
            command.Parameters.AddWithValue("redirect_uris", client.RedirectUris);
            await command.ExecuteNonQueryAsync();
        }
    }
}
