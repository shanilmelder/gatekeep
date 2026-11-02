using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

[DbContext(typeof(MigrationsContext))]
[Migration("20261102000000_CreateTenantTables")]
public sealed class Migration20261102000000CreateTenantTables : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            CREATE TABLE tenant (
              id uuid PRIMARY KEY,
              created_at timestamptz NOT NULL DEFAULT now()
            );

            CREATE TABLE tenant_host (
              host text PRIMARY KEY CHECK (host <> '' AND host = lower(host)),
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              kind text NOT NULL CHECK (kind IN ('subdomain')),
              created_at timestamptz NOT NULL DEFAULT now()
            );

            CREATE TABLE tenant_settings (
              tenant_id uuid PRIMARY KEY REFERENCES tenant (id) ON DELETE RESTRICT,
              created_at timestamptz NOT NULL DEFAULT now(),
              updated_at timestamptz NOT NULL DEFAULT now()
            );

            ALTER TABLE tenant_settings ENABLE ROW LEVEL SECURITY;
            ALTER TABLE tenant_settings FORCE ROW LEVEL SECURITY;

            CREATE POLICY tenant_settings_permissive ON tenant_settings
              AS PERMISSIVE FOR ALL
              USING (true)
              WITH CHECK (true);

            CREATE POLICY tenant_settings_tenant ON tenant_settings
              AS RESTRICTIVE FOR ALL
              USING (tenant_id = current_setting('gatekeep.tenant_id')::uuid)
              WITH CHECK (tenant_id = current_setting('gatekeep.tenant_id')::uuid);

            GRANT SELECT ON tenant TO gk_hosted, gk_worker, gk_cli;
            GRANT SELECT, INSERT ON tenant TO gk_admin;

            GRANT SELECT ON tenant_host TO gk_hosted, gk_worker;
            GRANT SELECT, INSERT ON tenant_host TO gk_admin;

            GRANT SELECT ON tenant_settings TO gk_hosted, gk_worker;
            GRANT SELECT, INSERT, UPDATE ON tenant_settings TO gk_admin;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
