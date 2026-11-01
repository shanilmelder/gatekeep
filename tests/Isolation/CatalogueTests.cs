using Gatekeep.Adapters.Postgres.Schema;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation;

public sealed class CatalogueTests(PostgresFixture postgres)
{
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Runs_on_the_pinned_PostgreSQL_engine()
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        var version = await PostgresFixture.ScalarAsync<string>(
            postgres.SuperuserConnection(database), "SELECT version()");

        Assert.StartsWith("PostgreSQL 18.6", version);
    }

    [Fact]
    public async Task Migrated_database_matches_the_registry()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using var connection = await OpenAsync(postgres.SuperuserConnection(database));

        Assert.Empty(await CatalogueAudit.CheckAsync(connection, TableRegistry.Tables));
    }

    [Fact]
    public void Registry_owners_are_real_modules()
    {
        var modules = new[]
        {
            "Tenancy", "Admins", "Identity", "Directory", "Authentication", "Sessions",
            "Keys", "Audit", "Notifications", "Operations",
        };

        Assert.All(TableRegistry.Tables, t => Assert.Contains(t.Owner, modules));
    }

    [Theory]
    // An unregistered table, as the role that could actually create one.
    [InlineData("CREATE TABLE stray (id uuid PRIMARY KEY)", "public.stray: not in the table registry.")]
    [InlineData("CREATE VIEW stray_view AS SELECT 1 AS one", "public.stray_view: not in the table registry.")]
    // Grants the registry doesn't list.
    [InlineData("GRANT SELECT ON tenant TO PUBLIC", "Grant not in the registry: public.tenant PUBLIC SELECT.")]
    [InlineData("GRANT DELETE ON tenant_settings TO gk_admin", "Grant not in the registry: public.tenant_settings gk_admin DELETE.")]
    [InlineData("GRANT SELECT ON tenant_settings TO gk_dispatch", "Grant not in the registry: public.tenant_settings gk_dispatch SELECT.")]
    [InlineData("GRANT SELECT (tenant_id) ON tenant_settings TO gk_cli", "Grant not in the registry: public.tenant_settings.tenant_id gk_cli SELECT.")]
    [InlineData("GRANT SELECT ON migration_history TO gk_hosted", "Grant not in the registry: public.migration_history gk_hosted SELECT.")]
    [InlineData("GRANT SELECT ON tenant TO gk_cli WITH GRANT OPTION", "Grant option not allowed: public.tenant gk_cli SELECT.")]
    [InlineData("GRANT SELECT (id) ON tenant TO gk_cli WITH GRANT OPTION", "Grant option not allowed: public.tenant.id gk_cli SELECT.")]
    // A grant the registry lists but the database has lost.
    [InlineData("REVOKE SELECT ON tenant FROM gk_cli", "Grant missing from the database: public.tenant gk_cli SELECT.")]
    // Row-level security turned down.
    [InlineData("ALTER TABLE tenant_settings NO FORCE ROW LEVEL SECURITY", "tenant_settings: FORCE ROW LEVEL SECURITY is false")]
    [InlineData("ALTER TABLE tenant_settings DISABLE ROW LEVEL SECURITY", "tenant_settings: ENABLE ROW LEVEL SECURITY is false")]
    [InlineData("ALTER TABLE tenant ENABLE ROW LEVEL SECURITY", "tenant: ENABLE ROW LEVEL SECURITY is true")]
    // Policies weakened or added.
    [InlineData("DROP POLICY tenant_settings_tenant ON tenant_settings", "tenant_settings: policies are")]
    [InlineData(
        "ALTER POLICY tenant_settings_tenant ON tenant_settings USING (tenant_id = nullif(current_setting('gatekeep.tenant_id', true), '')::uuid)",
        "tenant_settings: policies are")]
    [InlineData("CREATE POLICY extra ON tenant_settings AS RESTRICTIVE USING (true)", "tenant_settings: policies are")]
    // Foreign key rules.
    [InlineData(
        """
        ALTER TABLE tenant_host DROP CONSTRAINT tenant_host_tenant_id_fkey;
        ALTER TABLE tenant_host ADD CONSTRAINT tenant_host_tenant_id_fkey
          FOREIGN KEY (tenant_id) REFERENCES tenant (id) ON DELETE CASCADE
        """,
        "tenant_host_tenant_id_fkey: foreign key isn't ON DELETE RESTRICT.")]
    public async Task Catalogue_names_each_drift_made_by_the_migrator(string drift, string expected)
    {
        await AssertDriftReportedAsync(TableRegistry.Migrator, drift, expected, TableRegistry.Tables);
    }

    [Theory]
    [InlineData("ALTER ROLE gk_hosted BYPASSRLS", "gk_hosted: holds BYPASSRLS.")]
    [InlineData("ALTER ROLE gk_admin SUPERUSER", "gk_admin: holds superuser.")]
    [InlineData("ALTER TABLE tenant_settings OWNER TO gk_admin", "tenant_settings: owned by gk_admin, not gk_migrator.")]
    [InlineData("GRANT gk_migrator TO gk_hosted", "gk_hosted: is a member of another role.")]
    [InlineData("GRANT CREATE ON SCHEMA public TO gk_hosted", "Schema grant not allowed: gk_hosted CREATE.")]
    [InlineData("GRANT USAGE ON SCHEMA public TO PUBLIC", "Schema grant not allowed: PUBLIC USAGE.")]
    [InlineData("ALTER ROLE gk_sealer REPLICATION", "gk_sealer: holds REPLICATION.")]
    [InlineData("GRANT gk_admin TO pg_monitor", "gk_admin: has members.")]
    [InlineData("ALTER ROLE gk_hosted SET gatekeep.tenant_id = 'x'", "Tenant setting default for gk_hosted in all databases: gatekeep.tenant_id=x.")]
    [InlineData(
        "DO $$ BEGIN EXECUTE format('ALTER DATABASE %I SET gatekeep.tenant_id = ''x''', current_database()); END $$",
        "Tenant setting default for all roles in test_")]
    [InlineData(
        "DO $$ BEGIN EXECUTE format('GRANT TEMPORARY ON DATABASE %I TO PUBLIC', current_database()); END $$",
        "Database grant not allowed: PUBLIC TEMPORARY.")]
    [InlineData(
        "DO $$ BEGIN EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM gk_cli', current_database()); END $$",
        "Database grant missing: gk_cli CONNECT.")]
    public async Task Catalogue_names_each_drift_only_a_superuser_can_make(string drift, string expected)
    {
        await AssertDriftReportedAsync("postgres", drift, expected, TableRegistry.Tables);
    }

    [Fact]
    public async Task Catalogue_refuses_a_single_column_foreign_key_between_tenant_tables()
    {
        var parent = Entry("parent_row", TableClass.Tenant);
        var child = Entry("child_row", TableClass.Tenant);

        await AssertDriftReportedAsync(
            TableRegistry.Migrator,
            """
            CREATE TABLE parent_row (id uuid PRIMARY KEY, tenant_id uuid NOT NULL);
            CREATE TABLE child_row (
              id uuid PRIMARY KEY,
              tenant_id uuid NOT NULL,
              parent_id uuid NOT NULL CONSTRAINT child_row_parent_fkey REFERENCES parent_row (id) ON DELETE RESTRICT
            );
            """,
            "child_row_parent_fkey: foreign key between tenant tables isn't composite on tenant_id.",
            [.. TableRegistry.Tables, parent, child]);
    }

    [Fact]
    public async Task Catalogue_refuses_a_composite_foreign_key_that_crosses_tenant_id()
    {
        await AssertDriftReportedAsync(
            TableRegistry.Migrator,
            """
            CREATE TABLE parent_row (id uuid, tenant_id uuid NOT NULL, PRIMARY KEY (id, tenant_id));
            CREATE TABLE child_row (
              id uuid PRIMARY KEY,
              tenant_id uuid NOT NULL,
              parent_id uuid NOT NULL,
              CONSTRAINT child_row_parent_fkey FOREIGN KEY (tenant_id, parent_id)
                REFERENCES parent_row (id, tenant_id) ON DELETE RESTRICT
            );
            """,
            "child_row_parent_fkey: foreign key between tenant tables isn't composite on tenant_id.",
            [.. TableRegistry.Tables, Entry("parent_row", TableClass.Tenant), Entry("child_row", TableClass.Tenant)]);
    }

    [Fact]
    public async Task Catalogue_accepts_a_composite_foreign_key_between_tenant_tables()
    {
        var problems = await ProblemsAfterDriftAsync(
            TableRegistry.Migrator,
            """
            CREATE TABLE parent_row (id uuid, tenant_id uuid NOT NULL, PRIMARY KEY (tenant_id, id));
            CREATE TABLE child_row (
              id uuid PRIMARY KEY,
              tenant_id uuid NOT NULL,
              parent_id uuid NOT NULL,
              CONSTRAINT child_row_parent_fkey FOREIGN KEY (tenant_id, parent_id)
                REFERENCES parent_row (tenant_id, id) ON DELETE RESTRICT
            );
            """,
            [.. TableRegistry.Tables, Entry("parent_row", TableClass.Tenant), Entry("child_row", TableClass.Tenant)]);

        Assert.DoesNotContain(problems, p => p.Contains("child_row_parent_fkey"));
    }

    [Fact]
    public async Task Catalogue_reports_a_tenant_table_with_no_tenant_id()
    {
        await AssertDriftReportedAsync(
            TableRegistry.Migrator,
            "CREATE TABLE no_tenant (id uuid PRIMARY KEY)",
            "no_tenant: needs tenant_id uuid NOT NULL.",
            [.. TableRegistry.Tables, Entry("no_tenant", TableClass.Tenant)]);
    }

    [Fact]
    public async Task Catalogue_reports_a_registry_entry_with_no_owner()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using var connection = await OpenAsync(postgres.SuperuserConnection(database));
        TableEntry[] registry = [.. TableRegistry.Tables.Select(t => t with { Owner = t.Name == "tenant" ? " " : t.Owner })];

        Assert.Contains("tenant: registry entry has no owner.", await CatalogueAudit.CheckAsync(connection, registry));
    }

    private async Task AssertDriftReportedAsync(
        string role,
        string drift,
        string expected,
        IReadOnlyList<TableEntry> registry)
    {
        var problems = await ProblemsAfterDriftAsync(role, drift, registry);

        Assert.True(
            problems.Any(p => p.StartsWith(expected, StringComparison.Ordinal)),
            $"Expected '{expected}' in: {string.Join(" / ", problems)}");
    }

    private async Task<IReadOnlyList<string>> ProblemsAfterDriftAsync(
        string role,
        string drift,
        IReadOnlyList<TableEntry> registry)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var connectionString = role == TableRegistry.Migrator
            ? postgres.RoleConnection(role, database)
            : postgres.SuperuserConnection(database);

        // Roles are cluster-wide, so a committed role change would reach every other test.
        // The drift and the check share a transaction, which is never committed.
        await using var connection = await OpenAsync(connectionString);
        await using var transaction = await connection.BeginTransactionAsync(Cancellation);
        await using var command = new NpgsqlCommand(drift, connection, transaction);
        await command.ExecuteNonQueryAsync(Cancellation);

        return await CatalogueAudit.CheckAsync(connection, registry);
    }

    private static TableEntry Entry(string name, TableClass tableClass) =>
        new(name, tableClass, "Tenancy", new Dictionary<string, IReadOnlyList<string>>());

    private static async Task<NpgsqlConnection> OpenAsync(string connectionString)
    {
        var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(Cancellation);
        return connection;
    }
}
