using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 2.11 (RFC 7009, AD-13): a client's own revocation of its refresh token at the revocation
/// endpoint is <c>client_revoke</c>, a new code in the closed set of Sessions' revocation reasons. The
/// <c>user_session_end_reason</c> CHECK (Story 2.7's <c>ConstrainSessionEndReason</c>) is redefined under
/// the same name with it added, so the codes here still match <c>RevocationReason</c> exactly, as a test
/// holds. It adds no grant and changes no earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261112000000_AddClientRevokeReason")]
public sealed class Migration20261112000000AddClientRevokeReason : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) =>
        migrationBuilder.Sql(
            """
            ALTER TABLE user_session DROP CONSTRAINT user_session_end_reason;

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
                'tenant_deleted',
                'client_revoke'
              ));
            """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
