using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 1.21 Admins: <c>admin</c> and <c>admin_session</c>, <c>control</c> tables owned by Admins.
/// Bootstrap creates the first Admin, the Deployment Owner, with only an ID: later stories add
/// columns. A partial unique index keeps one Deployment Owner at most. An Admin Session stores
/// only the SHA-256 of its 256-bit ID, never the value, and follows <c>user_session</c> (Story
/// 2.6). Its CSRF token is derived from the ID, so nothing about it is stored. Checks bound its
/// lifetimes to PRD §5.2's 8 hours, and a trigger makes its ending final. <c>gk_admin</c> creates
/// both and updates only the columns setup completion, the idle slide and ending need;
/// <c>gk_cli</c> reads Admins, for <c>recover-admin</c> later. No role deletes.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261103010000_CreateAdminTables")]
public sealed class Migration20261103010000CreateAdminTables : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            CREATE TABLE admin (
              id uuid PRIMARY KEY,
              deployment_owner boolean NOT NULL,
              created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
              -- Set by Story 1.22 once the Admin has registered their credentials.
              setup_completed_at timestamptz NULL
            );

            -- One Deployment Owner at most, whatever path tries to add a second.
            CREATE UNIQUE INDEX admin_one_deployment_owner ON admin (deployment_owner) WHERE deployment_owner;

            CREATE TABLE admin_session (
              id uuid PRIMARY KEY,
              id_hash bytea NOT NULL UNIQUE
                CONSTRAINT admin_session_id_hash_length CHECK (octet_length(id_hash) = 32),
              admin_id uuid NOT NULL REFERENCES admin (id) ON DELETE RESTRICT,
              kind text NOT NULL CONSTRAINT admin_session_kind CHECK (kind IN ('setup', 'full')),
              created_at timestamptz NOT NULL,
              idle_expires_at timestamptz NOT NULL,
              absolute_expires_at timestamptz NOT NULL,
              ended_at timestamptz NULL,
              end_reason text NULL
                CONSTRAINT admin_session_end_reason CHECK (end_reason IN ('signed_out', 'expired', 'revoked', 'superseded')),
              CONSTRAINT admin_session_idle_within_absolute CHECK (idle_expires_at <= absolute_expires_at),
              CONSTRAINT admin_session_idle_after_creation CHECK (idle_expires_at >= created_at),
              CONSTRAINT admin_session_absolute_at_most_8_hours CHECK (absolute_expires_at - created_at <= interval '8 hours'),
              CONSTRAINT admin_session_ended_with_reason CHECK ((ended_at IS NULL) = (end_reason IS NULL)),
              CONSTRAINT admin_session_ended_after_creation CHECK (ended_at IS NULL OR ended_at >= created_at)
            );

            CREATE INDEX admin_session_admin ON admin_session (admin_id);

            -- An ended Session stays ended: its ending is written once, for the owner too.
            CREATE FUNCTION admin_session_guard_update() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF OLD.ended_at IS NOT NULL
                 AND (NEW.ended_at IS DISTINCT FROM OLD.ended_at OR NEW.end_reason IS DISTINCT FROM OLD.end_reason) THEN
                RAISE EXCEPTION 'an ended admin_session can''t change its ending';
              END IF;

              RETURN NEW;
            END
            $$;

            -- Firing a trigger needs no EXECUTE, so nobody keeps it.
            REVOKE EXECUTE ON FUNCTION admin_session_guard_update() FROM PUBLIC;

            CREATE TRIGGER admin_session_guard_update BEFORE UPDATE ON admin_session
              FOR EACH ROW EXECUTE FUNCTION admin_session_guard_update();

            GRANT SELECT, INSERT ON admin TO gk_admin;
            GRANT UPDATE (setup_completed_at) ON admin TO gk_admin;
            GRANT SELECT ON admin TO gk_cli;

            GRANT SELECT, INSERT ON admin_session TO gk_admin;
            GRANT UPDATE (idle_expires_at, ended_at, end_reason) ON admin_session TO gk_admin;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
