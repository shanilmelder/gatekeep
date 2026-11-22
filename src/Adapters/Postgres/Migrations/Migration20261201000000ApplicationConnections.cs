using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 4.12 (FR-14, UX-DR32): which Connections each Application allows.
/// <list type="bullet">
/// <item>Directory's <c>application_connection</c>: one row per Application and Connection, with whether it is enabled. A
/// missing row means off. It references both, so neither is deleted while a row names it.</item>
/// <item>The <c>system</c> Application has no rows: it follows every Connection enabled in its Tenant, which Directory's
/// effective rule decides with no stored state, and its row is never edited (<c>GK012</c>).</item>
/// <item><c>gk_admin</c> reads the rows, inserts them (a new Application's defaults) and changes only <c>enabled</c> and
/// <c>updated_at</c>. <c>gk_hosted</c> reads them, to offer and accept only an Application's Connections.
/// <c>gk_worker</c> inserts them for a Connection the hourly backfill ensures, reads only the columns its purges name and
/// deletes them (a Tenant's purge, and a deleted Application's).</item>
/// <item>Every existing non-system Application of a <c>creating</c> or <c>active</c> Tenant gets one enabled row for each
/// of its Tenant's Connections, one Tenant at a time; a rerun inserts nothing.</item>
/// </list>
/// It changes no earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261201000000_ApplicationConnections")]
public sealed class Migration20261201000000ApplicationConnections : Migration
{
    /// <summary>
    /// The backfill, run once per Tenant with that Tenant's setting in place: an enabled row for each non-system
    /// Application, deleted ones included (their purge removes them), and each Connection of the Tenant, only while the
    /// Tenant is <c>creating</c> or <c>active</c>.
    /// </summary>
    public const string Backfill =
        """
        INSERT INTO application_connection (tenant_id, application_id, connection_id, enabled)
        SELECT a.tenant_id, a.id, c.id, true
        FROM application a
        JOIN connection c ON c.tenant_id = a.tenant_id
        JOIN tenant t ON t.id = a.tenant_id
        WHERE a.tenant_id = current_setting('gatekeep.tenant_id')::uuid
          AND a.kind <> 'system'
          AND t.status IN ('creating', 'active')
        ON CONFLICT DO NOTHING
        """;

    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            CREATE TABLE application_connection (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              application_id uuid NOT NULL,
              connection_id uuid NOT NULL,
              enabled boolean NOT NULL,
              updated_at timestamptz NOT NULL DEFAULT now(),
              PRIMARY KEY (tenant_id, application_id, connection_id),
              FOREIGN KEY (tenant_id, application_id) REFERENCES application (tenant_id, id) ON DELETE RESTRICT,
              FOREIGN KEY (tenant_id, connection_id) REFERENCES connection (tenant_id, id) ON DELETE RESTRICT
            );

            -- Database · Applications lists a Connection's Applications.
            CREATE INDEX application_connection_connection ON application_connection (tenant_id, connection_id);

            ALTER TABLE application_connection ENABLE ROW LEVEL SECURITY;
            ALTER TABLE application_connection FORCE ROW LEVEL SECURITY;

            CREATE POLICY application_connection_permissive ON application_connection
              AS PERMISSIVE FOR ALL
              USING (true)
              WITH CHECK (true);

            CREATE POLICY application_connection_tenant ON application_connection
              AS RESTRICTIVE FOR ALL
              USING (tenant_id = current_setting('gatekeep.tenant_id')::uuid)
              WITH CHECK (tenant_id = current_setting('gatekeep.tenant_id')::uuid);

            -- No row reaches a Tenant once its deletion has started (Story 1.29).
            CREATE TRIGGER tenant_row_guard BEFORE INSERT ON application_connection
              FOR EACH ROW EXECUTE FUNCTION tenant_row_guard('creating', 'active');

            -- Host.Admin: a new Application's defaults, and the Application · Connections toggle.
            GRANT SELECT, INSERT ON application_connection TO gk_admin;
            GRANT UPDATE (enabled, updated_at) ON application_connection TO gk_admin;

            -- Host.Hosted: Login offers, and the server accepts, only the Application's Connections.
            GRANT SELECT ON application_connection TO gk_hosted;

            -- Host.Worker: the rows of a Connection the hourly backfill ensures for a Tenant that already has Applications, and a
            -- Tenant's purge and a deleted Application's, reading only what each WHERE names.
            GRANT INSERT, DELETE ON application_connection TO gk_worker;
            GRANT SELECT (tenant_id, application_id) ON application_connection TO gk_worker;
            """);

        // FORCE row-level security holds the migrator too, so the backfill runs one Tenant at a time.
        migrationBuilder.ForEachTenant(Backfill);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
