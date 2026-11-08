using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 9.1: an Admin views a Tenant's Signing Keys (FR-37, UX-DR44).
/// <list type="bullet">
/// <item><c>gk_admin</c> may read <c>signing_key</c>, in the path Tenant's own scope: row-level
/// security holds it to that Tenant's rows. It gets no other privilege on it, so Host.Admin still
/// changes no key row.</item>
/// </list>
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261106090000_ViewSigningKeys")]
public sealed class Migration20261106090000ViewSigningKeys : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            -- The Signing keys page's list (Story 9.1): reads only, one Tenant at a time.
            GRANT SELECT ON signing_key TO gk_admin;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
