using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 1.19 bootstrap state: <c>bootstrap_state</c>, a single-row <c>control</c> table owned
/// by Admins. It holds only the SHA-256 of the one-time bootstrap token, never the token, with
/// its issue and expiry times and, once Story 1.21 consumes it, when bootstrap completed.
/// Column grants split the two writers: <c>gk_cli</c> issues and reissues the token and can't
/// complete it, and <c>gk_admin</c> completes it and can't change the token. A trigger makes a
/// completed row final, for the owner too. No role deletes or truncates the row.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261103000000_CreateBootstrapStateTable")]
public sealed class Migration20261103000000CreateBootstrapStateTable : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            CREATE TABLE bootstrap_state (
              id smallint PRIMARY KEY CONSTRAINT bootstrap_state_single_row CHECK (id = 1),
              token_sha256 bytea NOT NULL
                CONSTRAINT bootstrap_state_token_sha256_length CHECK (octet_length(token_sha256) = 32),
              issued_at timestamptz NOT NULL,
              expires_at timestamptz NOT NULL,
              completed_at timestamptz,
              CONSTRAINT bootstrap_state_expires_after_issue CHECK (expires_at > issued_at)
            );

            -- Once bootstrap is complete the row is final: nothing in it changes, and completed_at
            -- never returns to NULL. It raises for the owner too, whom grants don't stop.
            CREATE FUNCTION bootstrap_state_guard_update() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF OLD.completed_at IS NOT NULL AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
                RAISE EXCEPTION 'bootstrap_state is complete and can''t change';
              END IF;

              RETURN NEW;
            END
            $$;

            -- Firing a trigger needs no EXECUTE, so nobody keeps it.
            REVOKE EXECUTE ON FUNCTION bootstrap_state_guard_update() FROM PUBLIC;

            CREATE TRIGGER bootstrap_state_guard_update BEFORE UPDATE ON bootstrap_state
              FOR EACH ROW EXECUTE FUNCTION bootstrap_state_guard_update();

            GRANT SELECT ON bootstrap_state TO gk_cli, gk_admin;
            GRANT INSERT (id, token_sha256, issued_at, expires_at) ON bootstrap_state TO gk_cli;
            GRANT UPDATE (token_sha256, issued_at, expires_at) ON bootstrap_state TO gk_cli;
            GRANT UPDATE (completed_at) ON bootstrap_state TO gk_admin;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
