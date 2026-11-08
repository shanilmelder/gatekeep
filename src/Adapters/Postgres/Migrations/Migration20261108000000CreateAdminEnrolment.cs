using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 1.32: <c>gatekeep recover-admin</c>'s enrolments (AD-31), a <c>control</c> table owned by Admins.
/// <list type="bullet">
/// <item><c>admin_enrolment</c>: one single-use enrolment per run, held only as the SHA-256 of its
/// 32-byte value, with the Admin it is for, its issue time, an expiry exactly 15 minutes later and
/// the time it was used. No other column holds anything derived from the value.</item>
/// <item><c>gk_cli</c> inserts it, after the Security Alert and the off-server record are confirmed,
/// and reads it; <c>gk_admin</c> reads it and sets <c>used_at</c>, once, at redemption. No other
/// role holds anything on it, and no role deletes.</item>
/// <item><c>admin_enrolment_guard</c> holds every role, the owner too: an enrolment is inserted
/// unused and issued no later than now and no earlier than its lifetime ago, and once inserted only
/// <c>used_at</c> changes, from NULL, once.</item>
/// <item><c>gk_cli</c> loses <c>SELECT</c> on <c>admin_recovery_code</c>, which Story 1.26 granted
/// for this command: <c>recover-admin</c> doesn't read Recovery Codes, so the Cli's reach stays narrow.</item>
/// </list>
/// A recovered Admin's Sessions end at redemption, as <c>revoked</c>, which the end reasons already hold.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261108000000_CreateAdminEnrolment")]
public sealed class Migration20261108000000CreateAdminEnrolment : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            CREATE TABLE admin_enrolment (
              id uuid PRIMARY KEY,
              admin_id uuid NOT NULL REFERENCES admin (id) ON DELETE RESTRICT,
              value_sha256 bytea NOT NULL
                CONSTRAINT admin_enrolment_value_unique UNIQUE
                CONSTRAINT admin_enrolment_value_length CHECK (octet_length(value_sha256) = 32),
              created_at timestamptz NOT NULL,
              expires_at timestamptz NOT NULL,
              used_at timestamptz NULL,
              CONSTRAINT admin_enrolment_lifetime CHECK (expires_at = created_at + interval '15 minutes'),
              CONSTRAINT admin_enrolment_used_after_issue CHECK (used_at IS NULL OR used_at >= created_at)
            );

            -- Issued unused, from no later than now and no earlier than its lifetime ago, so no
            -- caller can issue one that lives past 15 minutes from now; then only used, once.
            CREATE FUNCTION admin_enrolment_guard() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF TG_OP = 'INSERT' THEN
                IF NEW.used_at IS NOT NULL THEN
                  RAISE EXCEPTION 'an admin_enrolment is inserted unused';
                END IF;

                IF NEW.created_at > clock_timestamp() OR NEW.created_at <= clock_timestamp() - interval '15 minutes' THEN
                  RAISE EXCEPTION 'an admin_enrolment is issued now, and lives 15 minutes from its issue';
                END IF;

                RETURN NEW;
              END IF;

              IF NEW.id IS DISTINCT FROM OLD.id
                 OR NEW.admin_id IS DISTINCT FROM OLD.admin_id
                 OR NEW.value_sha256 IS DISTINCT FROM OLD.value_sha256
                 OR NEW.created_at IS DISTINCT FROM OLD.created_at
                 OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
                RAISE EXCEPTION 'only an admin_enrolment''s used_at changes';
              END IF;

              IF OLD.used_at IS NOT NULL AND NEW.used_at IS DISTINCT FROM OLD.used_at THEN
                RAISE EXCEPTION 'an admin_enrolment''s used_at is set once';
              END IF;

              RETURN NEW;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION admin_enrolment_guard() FROM PUBLIC;

            CREATE TRIGGER admin_enrolment_guard BEFORE INSERT OR UPDATE ON admin_enrolment
              FOR EACH ROW EXECUTE FUNCTION admin_enrolment_guard();

            GRANT SELECT, INSERT ON admin_enrolment TO gk_cli;
            GRANT SELECT ON admin_enrolment TO gk_admin;
            GRANT UPDATE (used_at) ON admin_enrolment TO gk_admin;

            REVOKE SELECT ON admin_recovery_code FROM gk_cli;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
