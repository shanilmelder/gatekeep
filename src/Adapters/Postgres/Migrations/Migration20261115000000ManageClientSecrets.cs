using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 3.3 (FR-12, NFR-3, AD-24): a Tenant Owner creates, rotates and revokes an Application's client secrets.
/// <list type="bullet">
/// <item><c>gk_admin</c> may update only a secret's <c>expires_at</c> (a rotation's overlap) and
/// <c>revoked_at</c> (an end or a revocation). Never its hash, Application or creation time.</item>
/// <item><c>client_secret_ended_after_created</c>: a secret never expires or is revoked before it was created.</item>
/// </list>
/// The <c>GK011</c> <c>system_application_guard</c> still refuses any secret naming the <c>system</c>
/// Application. It changes no earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261115000000_ManageClientSecrets")]
public sealed class Migration20261115000000ManageClientSecrets : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) =>
        migrationBuilder.Sql(
            """
            ALTER TABLE client_secret ADD CONSTRAINT client_secret_ended_after_created CHECK (
              (revoked_at IS NULL OR revoked_at >= created_at)
              AND (expires_at IS NULL OR expires_at >= created_at));

            -- Host.Admin's rotation and revocation (Story 3.3): these two columns only.
            GRANT UPDATE (expires_at, revoked_at) ON client_secret TO gk_admin;
            """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
