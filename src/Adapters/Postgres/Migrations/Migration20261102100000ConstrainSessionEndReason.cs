using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// A Session's <c>end_reason</c> is one of the closed set of Sessions' revocation reasons
/// (Story 2.7, AD-13). The codes here match <c>RevocationReason</c> exactly, and a test holds
/// the two together. It also indexes <c>authorization</c> and <c>token</c> by Application for
/// Application-scope revocation. It adds no grant.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261102100000_ConstrainSessionEndReason")]
public sealed class Migration20261102100000ConstrainSessionEndReason : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) =>
        migrationBuilder.Sql(
            """
            ALTER TABLE user_session
              ADD CONSTRAINT user_session_end_reason CHECK (end_reason IN (
                'logout',
                'credential_change',
                'admin_revoke',
                'user_blocked',
                'user_deleted',
                'token_reuse',
                'code_replay',
                'application_deleted',
                'tenant_deleted'
              ));

            -- Application-scope revocation filters both tables by Application.
            CREATE INDEX authorization_application ON "authorization" (tenant_id, application_id);
            CREATE INDEX token_application ON token (tenant_id, application_id);
            """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
