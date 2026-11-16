using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 4.6 (FR-17, FR-18): a Tenant's database Connection, its password history and the Tenant settings a sign-up reads.
/// <list type="bullet">
/// <item>Directory's <c>connection</c>: one <c>database</c> Connection per Tenant (<c>connection_one_per_kind</c>), named
/// <c>Username-Password</c>, holding whether it is enabled, whether sign-up is open, and its password policy: the minimum
/// length (12 to 64), the strength (<c>good</c> or <c>excellent</c>), how many earlier passwords may not be reused (0 to 24,
/// 0 meaning off), and the dictionary and personal-data rules. Its column defaults are Directory's defaults, which a test
/// holds equal.</item>
/// <item>Identity's <c>password_history</c>: an earlier password hash of a User, created empty for Stories 4.7 and 4.11 to
/// write. It references the User, never the Connection: Directory is purged before Identity.</item>
/// <item><c>tenant_settings</c> gains the terms URL (an absolute https URL of at most 2048 characters), the Dev-only
/// email verification switch, and the default audience (an API identifier, kept as text: Directory is purged before
/// Tenancy).</item>
/// <item><c>gk_admin</c> reads the Connection and may change only its sign-up switch, its password policy and
/// <c>updated_at</c>. <c>gk_hosted</c> reads it. <c>gk_worker</c> reads, inserts (at Tenant activation and in the hourly
/// backfill) and deletes it (a Tenant's purge).</item>
/// <item><c>gk_hosted</c> reads, inserts and deletes password history; <c>gk_worker</c> reads only its <c>tenant_id</c> and deletes it in a
/// Tenant's purge.</item>
/// <item>Every existing <c>creating</c> or <c>active</c> Tenant gets its database Connection, one Tenant at a time; a rerun
/// inserts nothing.</item>
/// </list>
/// It changes no earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261127000000_ConfigureDatabaseConnection")]
public sealed class Migration20261127000000ConfigureDatabaseConnection : Migration
{
    /// <summary>
    /// The backfill, run once per Tenant with that Tenant's setting in place: the database Connection with the column
    /// defaults, only while the Tenant is <c>creating</c> or <c>active</c> and has none. Its kind and name are Directory's
    /// <c>DatabaseConnectionKind</c> and <c>DatabaseConnectionName</c>; a test holds them equal.
    /// </summary>
    public const string BackfillConnection =
        """
        INSERT INTO connection (tenant_id, id, kind, name)
        SELECT t.id, uuidv7(), 'database', 'Username-Password'
        FROM tenant t
        WHERE t.id = current_setting('gatekeep.tenant_id')::uuid
          AND t.status IN ('creating', 'active')
          AND NOT EXISTS (SELECT 1 FROM connection c WHERE c.tenant_id = t.id AND c.kind = 'database')
        """;

    private static readonly string[] Tables = ["connection", "password_history"];

    protected override void Up(MigrationBuilder migrationBuilder)
    {
        var sql =
            """
            CREATE TABLE connection (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              id uuid NOT NULL,
              kind text NOT NULL CONSTRAINT connection_kind CHECK (kind = 'database'),
              name text NOT NULL DEFAULT 'Username-Password' CONSTRAINT connection_name CHECK (char_length(name) BETWEEN 1 AND 200),
              enabled boolean NOT NULL DEFAULT true,
              signup_enabled boolean NOT NULL DEFAULT true,
              password_min_length integer NOT NULL DEFAULT 12
                CONSTRAINT connection_password_min_length CHECK (password_min_length BETWEEN 12 AND 64),
              password_strength text NOT NULL DEFAULT 'good'
                CONSTRAINT connection_password_strength CHECK (password_strength IN ('good', 'excellent')),
              -- 0 turns the history rule off.
              password_history_count integer NOT NULL DEFAULT 5
                CONSTRAINT connection_password_history_count CHECK (password_history_count BETWEEN 0 AND 24),
              password_dictionary boolean NOT NULL DEFAULT true,
              password_personal_data boolean NOT NULL DEFAULT true,
              created_at timestamptz NOT NULL DEFAULT now(),
              updated_at timestamptz NOT NULL DEFAULT now(),
              PRIMARY KEY (tenant_id, id)
            );

            -- One database Connection per Tenant in v1.
            CREATE UNIQUE INDEX connection_one_per_kind ON connection (tenant_id, kind);

            -- No reference to connection: Directory's purge runs before Identity's.
            CREATE TABLE password_history (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              id uuid NOT NULL,
              user_id uuid NOT NULL,
              password_hash text NOT NULL CONSTRAINT password_history_hash CHECK (char_length(password_hash) BETWEEN 1 AND 512),
              created_at timestamptz NOT NULL DEFAULT now(),
              PRIMARY KEY (tenant_id, id),
              FOREIGN KEY (tenant_id, user_id) REFERENCES "user" (tenant_id, id) ON DELETE RESTRICT
            );

            CREATE INDEX password_history_user ON password_history (tenant_id, user_id, created_at DESC);

            -- The settings a sign-up reads (Stories 4.7 and 4.9). Story 8.5 keeps them.
            ALTER TABLE tenant_settings
              ADD COLUMN terms_url text NULL
                CONSTRAINT tenant_settings_terms_url CHECK (char_length(terms_url) BETWEEN 9 AND 2048 AND terms_url LIKE 'https://%'),
              ADD COLUMN email_verification_off boolean NOT NULL DEFAULT false,
              ADD COLUMN default_audience text NULL
                CONSTRAINT tenant_settings_default_audience CHECK (char_length(default_audience) BETWEEN 1 AND 255);


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

                -- No row reaches a Tenant once its deletion has started (Story 1.29).
                CREATE TRIGGER tenant_row_guard BEFORE INSERT ON {table}
                  FOR EACH ROW EXECUTE FUNCTION tenant_row_guard('creating', 'active');


                """;
        }

        sql +=
            """
            -- Host.Admin: reads the Connection, and changes only its sign-up switch and password policy.
            GRANT SELECT ON connection TO gk_admin;
            GRANT UPDATE (signup_enabled, password_min_length, password_strength, password_history_count,
              password_dictionary, password_personal_data, updated_at) ON connection TO gk_admin;

            -- Host.Hosted: sign-up, sign-in and reset read it (Stories 4.7, 4.9 and 4.11).
            GRANT SELECT ON connection TO gk_hosted;

            -- Host.Worker: the default Connection at Tenant activation and in the hourly backfill, and a Tenant's purge.
            GRANT SELECT, INSERT, DELETE ON connection TO gk_worker;

            -- Host.Hosted keeps a User's earlier password hashes (Stories 4.7 and 4.11); Host.Worker purges them, reading
            -- only the column its WHERE names, never a hash.
            GRANT SELECT, INSERT, DELETE ON password_history TO gk_hosted;
            GRANT SELECT (tenant_id), DELETE ON password_history TO gk_worker;
            """;

        migrationBuilder.Sql(sql);

        // FORCE row-level security holds the migrator too, so the backfill runs one Tenant at a time.
        migrationBuilder.ForEachTenant(BackfillConnection);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
