using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 3.2 (FR-11, FR-13, FR-46, AD-20): an Admin configures an Application's URLs and grants.
/// <list type="bullet">
/// <item><c>application</c> gains <c>post_logout_redirect_uris</c> (the Allowed Logout URLs, for Story 4.13)
/// and <c>web_origins</c> (the Allowed Web Origins), both empty by default.</item>
/// <item><c>application_redirect_uris</c> is replaced by <c>application_settings</c>, which holds each kind to its
/// list counts and grant sets: <c>web</c>, <c>spa</c> and <c>native</c> hold up to 10 callback and 10 logout URLs
/// and the grants <c>{}</c>, <c>{authorization_code}</c> or <c>{authorization_code, refresh_token}</c>, stored
/// sorted; <c>native</c> holds no web origin, the others up to 10; <c>machine</c> holds no URL and <c>{}</c> or
/// <c>{client_credentials}</c>; <c>system</c> holds nothing at all. Every earlier row meets it. The per-URL rules
/// (absolute, scheme, length, no wildcard, distinct, non-empty) are Directory's, not the CHECK's.</item>
/// <item><c>gk_admin</c> may update only those four columns, the settings save's. The <c>GK012</c> guard
/// still refuses any edit of the <c>system</c> Application.</item>
/// </list>
/// The <c>system</c> Application's other rules (<c>application_system_bare</c>, <c>application_one_system</c>
/// and the <c>GK011</c> to <c>GK013</c> guards) are untouched. It changes no earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261114000000_ConfigureApplicationSettings")]
public sealed class Migration20261114000000ConfigureApplicationSettings : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) =>
        migrationBuilder.Sql(
            """
            ALTER TABLE application ADD COLUMN post_logout_redirect_uris text[] NOT NULL DEFAULT '{}';
            ALTER TABLE application ADD COLUMN web_origins text[] NOT NULL DEFAULT '{}';

            ALTER TABLE application DROP CONSTRAINT application_redirect_uris;

            -- The type table (Story 3.2). Grant sets are compared as stored, sorted, so a reordered or
            -- repeated grant is refused like any other set that isn't listed.
            ALTER TABLE application ADD CONSTRAINT application_settings CHECK (
              (kind IN ('web', 'spa', 'native')
                AND cardinality(redirect_uris) <= 10
                AND cardinality(post_logout_redirect_uris) <= 10
                AND cardinality(web_origins) <= (CASE WHEN kind = 'native' THEN 0 ELSE 10 END)
                AND (grant_types = '{}'::text[]
                  OR grant_types = ARRAY['authorization_code']::text[]
                  OR grant_types = ARRAY['authorization_code', 'refresh_token']::text[]))
              OR (kind = 'machine'
                AND redirect_uris = '{}' AND post_logout_redirect_uris = '{}' AND web_origins = '{}'
                AND (grant_types = '{}'::text[] OR grant_types = ARRAY['client_credentials']::text[]))
              OR (kind = 'system'
                AND redirect_uris = '{}' AND post_logout_redirect_uris = '{}' AND web_origins = '{}'
                AND grant_types = '{}'::text[]));

            -- Host.Admin's settings save (Story 3.2): these four columns only, never a name, kind or audience.
            GRANT UPDATE (redirect_uris, post_logout_redirect_uris, web_origins, grant_types) ON application TO gk_admin;
            """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
