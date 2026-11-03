using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 1.22 Admin WebAuthn credentials: <c>admin_credential</c>, a <c>control</c> table owned by
/// Admins, holding only public material: the credential ID (unique Deployment-wide), its COSE
/// public key, signature counter, AAGUID and transports. <c>admin.webauthn_handle</c> is each
/// Admin's random 64-byte WebAuthn user handle, set once. An Admin Session holds its pending
/// registration challenge only as a SHA-256 with an expiry, and its kind can change only from
/// <c>setup</c> to <c>full</c>. <c>gk_admin</c> inserts credentials and updates only their
/// counter and last use; nobody deletes one.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261103020000_CreateAdminCredentialTable")]
public sealed class Migration20261103020000CreateAdminCredentialTable : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            ALTER TABLE admin
              ADD COLUMN webauthn_handle bytea NULL
                CONSTRAINT admin_webauthn_handle_length CHECK (octet_length(webauthn_handle) = 64)
                CONSTRAINT admin_webauthn_handle_unique UNIQUE;

            -- The user handle and setup completion are written once: neither changes nor returns to NULL.
            CREATE FUNCTION admin_guard_update() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF OLD.webauthn_handle IS NOT NULL AND NEW.webauthn_handle IS DISTINCT FROM OLD.webauthn_handle THEN
                RAISE EXCEPTION 'an admin''s webauthn_handle is set once';
              END IF;

              IF OLD.setup_completed_at IS NOT NULL AND NEW.setup_completed_at IS DISTINCT FROM OLD.setup_completed_at THEN
                RAISE EXCEPTION 'an admin''s setup_completed_at is set once';
              END IF;

              RETURN NEW;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION admin_guard_update() FROM PUBLIC;

            CREATE TRIGGER admin_guard_update BEFORE UPDATE ON admin
              FOR EACH ROW EXECUTE FUNCTION admin_guard_update();

            ALTER TABLE admin_session
              ADD COLUMN registration_challenge_sha256 bytea NULL
                CONSTRAINT admin_session_challenge_length CHECK (octet_length(registration_challenge_sha256) = 32),
              ADD COLUMN registration_challenge_expires_at timestamptz NULL,
              ADD CONSTRAINT admin_session_challenge_with_expiry
                CHECK ((registration_challenge_sha256 IS NULL) = (registration_challenge_expires_at IS NULL));

            -- An ended Session stays ended, and a Session's kind only ever goes from setup to full.
            CREATE OR REPLACE FUNCTION admin_session_guard_update() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF OLD.ended_at IS NOT NULL
                 AND (NEW.ended_at IS DISTINCT FROM OLD.ended_at OR NEW.end_reason IS DISTINCT FROM OLD.end_reason) THEN
                RAISE EXCEPTION 'an ended admin_session can''t change its ending';
              END IF;

              -- From setup, the CHECK allows only full; from full, nothing.
              IF OLD.kind = 'full' AND NEW.kind IS DISTINCT FROM OLD.kind THEN
                RAISE EXCEPTION 'an admin_session''s kind only goes from setup to full';
              END IF;

              RETURN NEW;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION admin_session_guard_update() FROM PUBLIC;

            CREATE TABLE admin_credential (
              id uuid PRIMARY KEY,
              admin_id uuid NOT NULL REFERENCES admin (id) ON DELETE RESTRICT,
              credential_id bytea NOT NULL
                CONSTRAINT admin_credential_credential_id_unique UNIQUE
                CONSTRAINT admin_credential_credential_id_length CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
              public_key bytea NOT NULL
                CONSTRAINT admin_credential_public_key_length CHECK (octet_length(public_key) BETWEEN 1 AND 2048),
              sign_count bigint NOT NULL
                CONSTRAINT admin_credential_sign_count_range CHECK (sign_count BETWEEN 0 AND 4294967295),
              aaguid uuid NOT NULL,
              transports text[] NOT NULL DEFAULT '{}'
                CONSTRAINT admin_credential_transports_known
                  CHECK (transports <@ ARRAY['usb', 'nfc', 'ble', 'smart-card', 'hybrid', 'internal']::text[]),
              created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
              last_used_at timestamptz NULL,
              CONSTRAINT admin_credential_used_after_creation CHECK (last_used_at IS NULL OR last_used_at >= created_at)
            );

            CREATE INDEX admin_credential_admin ON admin_credential (admin_id);

            GRANT UPDATE (webauthn_handle) ON admin TO gk_admin;

            GRANT UPDATE (kind, registration_challenge_sha256, registration_challenge_expires_at) ON admin_session TO gk_admin;

            GRANT SELECT, INSERT ON admin_credential TO gk_admin;
            GRANT UPDATE (sign_count, last_used_at) ON admin_credential TO gk_admin;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
