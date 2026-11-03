using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 1.23 Admin sign-in: <c>admin_signin_challenge</c>, an <c>UNLOGGED</c> <c>control</c>
/// table owned by Admins, holding each pending sign-in's challenge only as its SHA-256, bound to
/// the browser that began it by the SHA-256 of its <c>__Host-gk-admin-signin</c> cookie. A crash
/// empties it, which only makes an Admin press Sign in again. A challenge lives at most 5 minutes
/// by its CHECK. <c>gk_admin</c> inserts, reads and deletes rows and never updates one: taking a
/// challenge is a <c>DELETE … RETURNING</c>, so it can answer only once.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261103030000_CreateAdminSignInChallengeTable")]
public sealed class Migration20261103030000CreateAdminSignInChallengeTable : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            CREATE UNLOGGED TABLE admin_signin_challenge (
              id uuid PRIMARY KEY,
              binding_hash bytea NOT NULL
                CONSTRAINT admin_signin_challenge_binding_hash_length CHECK (octet_length(binding_hash) = 32)
                CONSTRAINT admin_signin_challenge_binding_hash_unique UNIQUE,
              challenge_sha256 bytea NOT NULL
                CONSTRAINT admin_signin_challenge_challenge_length CHECK (octet_length(challenge_sha256) = 32),
              created_at timestamptz NOT NULL,
              expires_at timestamptz NOT NULL,
              CONSTRAINT admin_signin_challenge_lifetime
                CHECK (expires_at > created_at AND expires_at - created_at <= interval '5 minutes')
            );

            CREATE INDEX admin_signin_challenge_expiry ON admin_signin_challenge (expires_at);

            GRANT SELECT, INSERT, DELETE ON admin_signin_challenge TO gk_admin;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
