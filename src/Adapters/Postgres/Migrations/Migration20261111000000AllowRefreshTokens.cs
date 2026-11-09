using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 2.10 (FR-15, AD-13): rotating refresh tokens. A <c>web</c> Application's grant set is now
/// <c>{authorization_code}</c> or <c>{authorization_code, refresh_token}</c>, in place of the Story 2.9
/// <c>application_redirect_uris</c> CHECK, which allowed only the first; a <c>machine</c> or
/// <c>system</c> row still has no redirect URI. Directory writes new web clients with both grants, and
/// <see cref="Backfill"/> gives every existing Story 2.9 web client the refresh grant too, so none is left
/// unable to ask for <c>offline_access</c>. <c>gk_hosted</c>'s grants don't change: a rotation, a reuse
/// revocation and a burnt refresh token update only the token columns Story 2.9 granted. It changes no
/// earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261111000000_AllowRefreshTokens")]
public sealed class Migration20261111000000AllowRefreshTokens : Migration
{
    /// <summary>
    /// Run once per Tenant, last: every web client allowed only the code grant is allowed the refresh grant
    /// as well. Running it again changes nothing.
    /// </summary>
    public const string Backfill =
        """
        UPDATE application SET grant_types = ARRAY['authorization_code', 'refresh_token']::text[]
        WHERE tenant_id = current_setting('gatekeep.tenant_id')::uuid
          AND kind = 'web' AND grant_types = ARRAY['authorization_code']::text[]
        """;

    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            ALTER TABLE application DROP CONSTRAINT application_redirect_uris;

            -- A web client signs Users in by the code flow, to a registered redirect URI, and may refresh;
            -- no other kind has a redirect URI.
            ALTER TABLE application ADD CONSTRAINT application_redirect_uris CHECK (
              (kind = 'web'
                AND cardinality(redirect_uris) BETWEEN 1 AND 10
                AND (grant_types = ARRAY['authorization_code']::text[]
                  OR grant_types = ARRAY['authorization_code', 'refresh_token']::text[]))
              OR (kind <> 'web' AND redirect_uris = '{}'));
            """);

        // FORCE row-level security holds the migrator too, so the backfill runs one Tenant at a time.
        migrationBuilder.ForEachTenant(Backfill);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
