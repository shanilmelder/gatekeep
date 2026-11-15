using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 4.2 (FR-47, AD-12): what a bound sign-in transaction records as Hosted Login moves it on. The
/// transaction stays the only record of which steps have passed (<c>completed_steps</c>), and gains:
/// <list type="bullet">
/// <item><c>step_version</c>: the version of its current step, which every step moved on increments, so a stale
/// submission returns the current step instead of changing anything.</item>
/// <item><c>identifier</c>: the email as entered, trimmed, at most 254 characters, kept across a restart.</item>
/// <item><c>authenticated_session_id</c>: the Session its authentication started or rotated. It has no foreign key,
/// so Authentication's and Sessions' purges stay independent of each other (AD-30).</item>
/// <item><c>completed_at</c>: when the authorization request it was for completed, after which it is refused.</item>
/// </list>
/// <c>gk_hosted</c>'s table grants already reach the new columns, and no other role's grant changes. It changes no
/// earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261123000000_BindSignInTransactions")]
public sealed class Migration20261123000000BindSignInTransactions : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            ALTER TABLE signin_transaction
              ADD COLUMN step_version int NOT NULL DEFAULT 1 CHECK (step_version > 0),
              ADD COLUMN identifier text NULL CHECK (char_length(identifier) BETWEEN 1 AND 254),
              ADD COLUMN authenticated_session_id uuid NULL,
              ADD COLUMN completed_at timestamptz NULL,
              ADD CHECK (completed_at IS NULL OR authenticated_session_id IS NOT NULL);
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
