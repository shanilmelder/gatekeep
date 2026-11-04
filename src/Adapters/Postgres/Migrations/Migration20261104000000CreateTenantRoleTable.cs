using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 1.24 Tenant Roles: <c>tenant_role</c>, a <c>control</c> table owned by Admins (AD-27),
/// holding the one Tenant Role an Admin has in a Tenant. It is <c>control</c>, not <c>tenant</c>,
/// because one Admin's roles are listed across Tenants (Story 1.28), so <c>tenant_id</c> is no
/// row-level security key: the request checks filter by the path Tenant in code. Each key is a
/// single-column reference, kept by <c>RESTRICT</c>: a Tenant or Admin holding roles can't be
/// deleted under them. <c>gk_admin</c> only reads it here; Story 1.27 adds the insert and Story
/// 8.4 the update and delete. No other role, <c>gk_hosted</c> above all (AD-2), gets anything.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261104000000_CreateTenantRoleTable")]
public sealed class Migration20261104000000CreateTenantRoleTable : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            CREATE TABLE tenant_role (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              admin_id uuid NOT NULL REFERENCES admin (id) ON DELETE RESTRICT,
              role text NOT NULL CONSTRAINT tenant_role_role CHECK (role IN ('viewer', 'editor', 'owner')),
              created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
              PRIMARY KEY (tenant_id, admin_id)
            );

            -- One Admin's roles across Tenants, for the Tenant switcher (Story 1.28).
            CREATE INDEX tenant_role_admin ON tenant_role (admin_id);

            GRANT SELECT ON tenant_role TO gk_admin;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
