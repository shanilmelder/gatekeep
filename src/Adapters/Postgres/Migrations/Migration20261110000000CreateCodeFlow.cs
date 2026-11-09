using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 2.9 (FR-13, FR-23, AD-8, AD-9, AD-13): the authorization code flow with PKCE.
/// <list type="bullet">
/// <item><c>application.kind</c> gains <c>web</c>, a confidential client that signs Users in, and
/// <c>application.redirect_uris</c> holds its registered redirect URIs. <c>application_redirect_uris</c>
/// holds a <c>web</c> row to 1 to 10 redirect URIs and exactly the <c>authorization_code</c> grant, and
/// a <c>machine</c> or <c>system</c> row to none. Directory checks each URI's form before it writes one.</item>
/// <item>The 2.6 and 2.7 deferral: <c>gk_hosted</c>'s table-wide <c>UPDATE</c> on <c>token</c> and
/// <c>"authorization"</c> is narrowed to exactly the columns the Sessions stores and the one revocation
/// path update. A token is updated only in its status, payload, reference ID, redemption date and
/// concurrency token; an authorization only in its status and concurrency token.</item>
/// </list>
/// It changes no earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261110000000_CreateCodeFlow")]
public sealed class Migration20261110000000CreateCodeFlow : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) =>
        migrationBuilder.Sql(
            """
            ALTER TABLE application DROP CONSTRAINT application_kind;
            ALTER TABLE application ADD CONSTRAINT application_kind CHECK (kind IN ('machine', 'system', 'web'));

            ALTER TABLE application ADD COLUMN redirect_uris text[] NOT NULL DEFAULT '{}';

            -- A web client signs Users in by the code flow only, to a registered redirect URI; no other
            -- kind has one.
            ALTER TABLE application ADD CONSTRAINT application_redirect_uris CHECK (
              (kind = 'web'
                AND cardinality(redirect_uris) BETWEEN 1 AND 10
                AND grant_types = ARRAY['authorization_code']::text[])
              OR (kind <> 'web' AND redirect_uris = '{}'));

            -- Only the columns the stores and the revocation path update (Story 2.6 and 2.7 deferral).
            REVOKE UPDATE ON token FROM gk_hosted;
            GRANT UPDATE (status, payload, reference_id, redemption_date, concurrency_token) ON token TO gk_hosted;
            REVOKE UPDATE ON "authorization" FROM gk_hosted;
            GRANT UPDATE (status, concurrency_token) ON "authorization" TO gk_hosted;
            """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
