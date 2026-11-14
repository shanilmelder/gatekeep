using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 3.6 (FR-15, FR-16): a Tenant's APIs, the resource servers its tokens are for, and their Permissions.
/// <list type="bullet">
/// <item>Directory's <c>api</c>: a name, an identifier (1 to 255 characters, unique in the Tenant by exact match), whether
/// it is the built-in Management API (at most one per Tenant, <c>api_one_built_in</c>), offline access, RBAC, and the four
/// token lifetimes with the same defaults and CHECKs as <c>application</c>'s (Story 3.4). An Architecture test pins these
/// numbers to the <c>SecurityLimits</c> constants.</item>
/// <item>Directory's <c>permission</c>: one <c>resource:action</c> value per row, unique per API, with a description of 0 to
/// 200 characters, referencing its API <c>ON DELETE RESTRICT</c>.</item>
/// <item><c>audit_event</c> and <c>deployment_audit_event</c> accept the <c>api</c> target kind.</item>
/// <item><c>gk_admin</c> creates APIs, updates only their offline access, RBAC and lifetimes (never the identifier or
/// name), and adds and removes Permissions. <c>gk_worker</c> writes the built-in Management API and its Permissions at
/// Tenant activation and in the hourly backfill, finding it by <c>built_in</c> and reading which Permissions it has, and deletes both in a Tenant's purge.</item>
/// <item>Every existing <c>creating</c> or <c>active</c> Tenant gets the built-in Management API and its Permissions, one
/// Tenant at a time; a rerun inserts nothing.</item>
/// </list>
/// It changes no earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261119000000_DefineApis")]
public sealed class Migration20261119000000DefineApis : Migration
{
    /// <summary>
    /// The first backfill, run once per Tenant with that Tenant's setting in place: the built-in Management API, only
    /// while the Tenant is <c>creating</c> or <c>active</c> and has none. Its name and identifier are Directory's
    /// <c>ManagementApiName</c> and <c>ManagementApiIdentifier</c>; a test holds them equal.
    /// </summary>
    public const string BackfillApi =
        """
        INSERT INTO api (tenant_id, id, name, identifier, built_in, created_at)
        SELECT t.id, uuidv7(), 'Gatekeep Management API', 'urn:gatekeep:management', true, now()
        FROM tenant t
        WHERE t.id = current_setting('gatekeep.tenant_id')::uuid
          AND t.status IN ('creating', 'active')
          AND NOT EXISTS (SELECT 1 FROM api a WHERE a.tenant_id = t.id AND a.built_in)
        """;

    /// <summary>
    /// The second backfill: each Management Permission the Tenant's built-in API lacks, with its description. The pairs
    /// are Directory's <c>ManagementPermissions</c> and <c>ManagementPermissionDescriptions</c>, literally; an Architecture
    /// test holds them equal.
    /// </summary>
    public const string BackfillPermissions =
        """
        INSERT INTO permission (tenant_id, api_id, value, description, created_at)
        SELECT a.tenant_id, a.id, v.value, v.description, now()
        FROM api a
        CROSS JOIN (VALUES
          ('configuration:read', 'Read Tenant configuration'),
          ('users:read', 'Read Users'),
          ('logs:read', 'Read Log summaries'),
          ('log_detail:read', 'Read raw Log detail'),
          ('applications:manage', 'Manage Applications'),
          ('apis:manage', 'Manage APIs'),
          ('roles:manage', 'Manage Roles'),
          ('users:manage', 'Manage Users'),
          ('theme:manage', 'Manage the theme'),
          ('templates:manage', 'Manage email templates'),
          ('settings:manage', 'Manage Tenant settings'),
          ('connections:toggle', 'Enable or disable Connections'),
          ('configuration:export', 'Export Tenant configuration'),
          ('password_policy:manage', 'Manage the password policy'),
          ('connection_credentials:manage', 'Manage Connection credentials'),
          ('user_data:export', 'Export User data'),
          ('user_data:erase', 'Erase User data')
        ) AS v(value, description)
        WHERE a.tenant_id = current_setting('gatekeep.tenant_id')::uuid AND a.built_in
        ON CONFLICT DO NOTHING
        """;

    private static readonly string[] Tables = ["api", "permission"];

    protected override void Up(MigrationBuilder migrationBuilder)
    {
        var sql =
            """
            CREATE TABLE api (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              id uuid NOT NULL,
              name text NOT NULL CONSTRAINT api_name CHECK (char_length(name) BETWEEN 1 AND 200),
              identifier text NOT NULL CONSTRAINT api_identifier CHECK (char_length(identifier) BETWEEN 1 AND 255),
              built_in boolean NOT NULL DEFAULT false,
              offline_access boolean NOT NULL DEFAULT false,
              rbac boolean NOT NULL DEFAULT false,
              access_token_lifetime integer NOT NULL DEFAULT 900,
              id_token_lifetime integer NOT NULL DEFAULT 900,
              refresh_token_absolute_lifetime integer NOT NULL DEFAULT 2592000,
              refresh_token_inactivity_lifetime integer NOT NULL DEFAULT 604800,
              created_at timestamptz NOT NULL,
              PRIMARY KEY (tenant_id, id),
              CONSTRAINT api_access_token_lifetime CHECK (access_token_lifetime BETWEEN 1 AND 3600),
              CONSTRAINT api_id_token_lifetime CHECK (id_token_lifetime BETWEEN 1 AND 3600),
              CONSTRAINT api_refresh_token_absolute_lifetime CHECK (refresh_token_absolute_lifetime BETWEEN 1 AND 7776000),
              CONSTRAINT api_refresh_token_inactivity_lifetime CHECK (refresh_token_inactivity_lifetime BETWEEN 1 AND 2592000),
              -- The built-in Management API, and no other, has exactly this identifier. The rest of the reserved
              -- urn:gatekeep: prefix is refused by Directory only.
              CONSTRAINT api_reserved_identifier CHECK (built_in = (identifier = 'urn:gatekeep:management'))
            );

            -- Matched exactly: case and every character count.
            CREATE UNIQUE INDEX api_identifier_unique ON api (tenant_id, identifier);

            -- Exactly one per Tenant: Tenant activation and the backfills insert one, and nothing more.
            CREATE UNIQUE INDEX api_one_built_in ON api (tenant_id) WHERE built_in;

            CREATE TABLE permission (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              api_id uuid NOT NULL,
              value text NOT NULL
                CONSTRAINT permission_value
                CHECK (value ~ '^[a-z0-9][a-z0-9_.-]{0,63}:[a-z0-9][a-z0-9_.-]{0,63}$'),
              description text NOT NULL DEFAULT ''
                CONSTRAINT permission_description CHECK (char_length(description) <= 200),
              created_at timestamptz NOT NULL,
              PRIMARY KEY (tenant_id, api_id, value),
              FOREIGN KEY (tenant_id, api_id) REFERENCES api (tenant_id, id) ON DELETE RESTRICT
            );

            -- An API is a target the Log names (Story 3.6).
            ALTER TABLE audit_event DROP CONSTRAINT audit_event_target_kind_check;
            ALTER TABLE audit_event ADD CONSTRAINT audit_event_target_kind_check
              CHECK (target_kind IN ('tenant', 'admin', 'user', 'client', 'api'));
            ALTER TABLE deployment_audit_event DROP CONSTRAINT deployment_audit_event_target_kind_check;
            ALTER TABLE deployment_audit_event ADD CONSTRAINT deployment_audit_event_target_kind_check
              CHECK (target_kind IN ('tenant', 'admin', 'user', 'client', 'api'));


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
            -- Host.Admin: APIs are created and read, and only their settings change: never the identifier or name.
            -- Permissions are added and removed, never edited.
            GRANT SELECT, INSERT ON api TO gk_admin;
            GRANT UPDATE (offline_access, rbac, access_token_lifetime, id_token_lifetime,
              refresh_token_absolute_lifetime, refresh_token_inactivity_lifetime) ON api TO gk_admin;
            GRANT SELECT, INSERT, DELETE ON permission TO gk_admin;

            -- Host.Worker: the built-in Management API at Tenant activation and in the hourly backfill, found by
            -- built_in; and a Tenant's purge, reading only the column each WHERE names.
            GRANT INSERT, DELETE ON api TO gk_worker;
            GRANT SELECT (tenant_id, id, built_in) ON api TO gk_worker;
            GRANT INSERT, DELETE ON permission TO gk_worker;
            GRANT SELECT (tenant_id, api_id, value) ON permission TO gk_worker;
            """;

        migrationBuilder.Sql(sql);

        // FORCE row-level security holds the migrator too, so the backfills run one Tenant at a time.
        migrationBuilder.ForEachTenant(BackfillApi);
        migrationBuilder.ForEachTenant(BackfillPermissions);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
