using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 3.4 (FR-15, PRD §5.2): an Admin sets an Application's token lifetimes.
/// <list type="bullet">
/// <item><c>application</c> gains four lifetimes in whole seconds, each defaulting to the Deployment default
/// it replaces, so every existing Application keeps today's behavior: <c>access_token_lifetime</c> and
/// <c>id_token_lifetime</c> 900 (15 minutes), <c>refresh_token_absolute_lifetime</c> 2592000 (30 days) and
/// <c>refresh_token_inactivity_lifetime</c> 604800 (7 days).</item>
/// <item>Each is CHECKed between 1 second and its <c>SecurityLimits</c> hard limit: 3600 (1 hour), 3600,
/// 7776000 (90 days) and 2592000 (30 days). An Architecture test pins these numbers to the constants.</item>
/// <item><c>gk_admin</c> may update the four columns, the tokens save's. The <c>GK012</c> guard still refuses
/// any edit of the <c>system</c> Application.</item>
/// </list>
/// It changes no earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261116000000_SetTokenLifetimes")]
public sealed class Migration20261116000000SetTokenLifetimes : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) =>
        migrationBuilder.Sql(
            """
            ALTER TABLE application ADD COLUMN access_token_lifetime integer NOT NULL DEFAULT 900;
            ALTER TABLE application ADD COLUMN id_token_lifetime integer NOT NULL DEFAULT 900;
            ALTER TABLE application ADD COLUMN refresh_token_absolute_lifetime integer NOT NULL DEFAULT 2592000;
            ALTER TABLE application ADD COLUMN refresh_token_inactivity_lifetime integer NOT NULL DEFAULT 604800;

            ALTER TABLE application ADD CONSTRAINT application_access_token_lifetime
              CHECK (access_token_lifetime BETWEEN 1 AND 3600);
            ALTER TABLE application ADD CONSTRAINT application_id_token_lifetime
              CHECK (id_token_lifetime BETWEEN 1 AND 3600);
            ALTER TABLE application ADD CONSTRAINT application_refresh_token_absolute_lifetime
              CHECK (refresh_token_absolute_lifetime BETWEEN 1 AND 7776000);
            ALTER TABLE application ADD CONSTRAINT application_refresh_token_inactivity_lifetime
              CHECK (refresh_token_inactivity_lifetime BETWEEN 1 AND 2592000);

            -- Host.Admin's tokens save (Story 3.4): the four lifetimes only.
            GRANT UPDATE (access_token_lifetime, id_token_lifetime,
              refresh_token_absolute_lifetime, refresh_token_inactivity_lifetime) ON application TO gk_admin;
            """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
