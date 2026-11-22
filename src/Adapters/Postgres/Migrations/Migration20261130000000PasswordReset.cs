using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 4.11 (FR-19): a password reset link is a <c>one_time_token</c> of the purpose <c>password_reset</c>, beside
/// Story 4.7's <c>email_verification</c>. Nothing else changes: <c>gk_hosted</c> already inserts, deletes and marks used
/// <c>one_time_token</c> rows, updates a credential's <c>status</c>, <c>password_hash</c> and <c>updated_at</c>, sets
/// <c>"user".email_verified_at</c> and inserts <c>password_history</c>. It changes no earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261130000000_PasswordReset")]
public sealed class Migration20261130000000PasswordReset : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) =>
        migrationBuilder.Sql(
            """
            ALTER TABLE one_time_token
              DROP CONSTRAINT one_time_token_purpose,
              ADD CONSTRAINT one_time_token_purpose CHECK (purpose IN ('email_verification', 'password_reset'));
            """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
