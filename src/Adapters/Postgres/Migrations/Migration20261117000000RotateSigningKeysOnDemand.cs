using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 9.2: a Tenant Owner rotates the Tenant's Signing Key on demand (FR-37).
/// <list type="bullet">
/// <item><c>gk_admin</c> may insert <c>signing_key</c> rows, the replacement <c>next</c>, in the path
/// Tenant's own scope: row-level security holds it to that Tenant's rows.</item>
/// <item><c>gk_admin</c> may update <c>state</c>, <c>promoted_at</c> and <c>rotated_at</c> only, the
/// promotion and the rotation. Never <c>retired_at</c>, <c>destroyed_at</c> or an identity column, and
/// no DELETE: retirement and destruction stay Host.Worker's. <c>signing_key_guard_update</c> still holds
/// every change to AD-11's transitions.</item>
/// </list>
/// It changes no earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261117000000_RotateSigningKeysOnDemand")]
public sealed class Migration20261117000000RotateSigningKeysOnDemand : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            -- The Signing keys page's Rotate (Story 9.2): the new next key's row, then the promotion and rotation.
            GRANT INSERT ON signing_key TO gk_admin;
            GRANT UPDATE (state, promoted_at, rotated_at) ON signing_key TO gk_admin;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
