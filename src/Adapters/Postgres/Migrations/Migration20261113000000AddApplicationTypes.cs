using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 3.1 (FR-11, FR-44, AD-20): an Admin registers Applications of four types.
/// <list type="bullet">
/// <item><c>application.kind</c> gains <c>spa</c> (single-page) and <c>native</c>, beside <c>web</c>
/// (regular web), <c>machine</c> (machine-to-machine) and the hidden <c>system</c> Application.</item>
/// <item><c>application_redirect_uris</c> is redefined under the same name: a <c>web</c> row now holds 0 to
/// 10 redirect URIs, since an Admin creates one with only a name and a type and adds its URLs later
/// (Story 3.2), with the grant set <c>{authorization_code}</c> or <c>{authorization_code, refresh_token}</c>
/// as before; every other kind still has none.</item>
/// </list>
/// The <c>system</c> Application's rules (<c>application_system_bare</c>, <c>application_one_system</c> and the
/// <c>GK011</c> to <c>GK013</c> guards) are untouched. It adds no grant and changes no earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261113000000_AddApplicationTypes")]
public sealed class Migration20261113000000AddApplicationTypes : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) =>
        migrationBuilder.Sql(
            """
            ALTER TABLE application DROP CONSTRAINT application_kind;
            ALTER TABLE application ADD CONSTRAINT application_kind
              CHECK (kind IN ('machine', 'native', 'spa', 'system', 'web'));

            ALTER TABLE application DROP CONSTRAINT application_redirect_uris;

            -- A web client signs Users in by the code flow, to a registered redirect URI once it has one, and
            -- may refresh; no other kind has a redirect URI yet.
            ALTER TABLE application ADD CONSTRAINT application_redirect_uris CHECK (
              (kind = 'web'
                AND cardinality(redirect_uris) BETWEEN 0 AND 10
                AND (grant_types = ARRAY['authorization_code']::text[]
                  OR grant_types = ARRAY['authorization_code', 'refresh_token']::text[]))
              OR (kind <> 'web' AND redirect_uris = '{}'));
            """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
