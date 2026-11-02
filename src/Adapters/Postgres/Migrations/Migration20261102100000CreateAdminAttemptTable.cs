using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// AD-14 Admin attempt counters: <c>admin_attempt</c>, an <c>UNLOGGED</c> <c>control</c> table
/// owned by Admins. A crash empties it, which AD-14 accepts. The subject is a 32-byte SHA-256
/// only, and the policy a checked code, so no raw address or credential handle can be stored.
/// Only <c>gk_admin</c> counts, and it updates the two counter columns only.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261102100000_CreateAdminAttemptTable")]
public sealed class Migration20261102100000CreateAdminAttemptTable : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            CREATE UNLOGGED TABLE admin_attempt (
              policy text NOT NULL
                CONSTRAINT admin_attempt_policy_code
                CHECK (policy ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$' AND char_length(policy) <= 128),
              subject_hash bytea NOT NULL
                CONSTRAINT admin_attempt_subject_hash_length CHECK (octet_length(subject_hash) = 32),
              window_start timestamptz NOT NULL,
              attempts integer NOT NULL CHECK (attempts >= 1),
              PRIMARY KEY (policy, subject_hash)
            );

            GRANT SELECT, INSERT ON admin_attempt TO gk_admin;
            GRANT UPDATE (window_start, attempts) ON admin_attempt TO gk_admin;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
