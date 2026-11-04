using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 1.26: fresh assertions, credential management and Admin Recovery Codes, all
/// <c>control</c> tables owned by Admins.
/// <list type="bullet">
/// <item><c>admin_fresh_assertion</c>, <c>UNLOGGED</c>: one pending ceremony challenge per Admin
/// Session, as its SHA-256, and each verified grant, bound to its Session and to the SHA-256 of
/// its action, Tenant and target, for 5 minutes at most. A stage is a row, never an update:
/// <c>gk_admin</c> inserts and deletes them, so taking a challenge or using up a grant is one
/// <c>DELETE … RETURNING</c>. A crash empties it, which only makes an Admin confirm again.</item>
/// <item><c>admin_credential</c> gains the WebAuthn BE and BS flags, <c>DELETE</c> and
/// <c>UPDATE (backed_up)</c> for <c>gk_admin</c>, and two triggers that lock the Admin's row and
/// refuse an 11th credential and a delete that would leave fewer than two, whoever runs it.</item>
/// <item><c>admin_session.kind</c> gains <c>recovery</c>, which, like <c>setup</c>, only ever
/// becomes <c>full</c>.</item>
/// <item><c>admin_recovery_code</c>: an Admin's offline Recovery Code, held only as an HMAC
/// under the Deployment <c>hmac</c> key with its key version, never the code, a ciphertext or a
/// hint. One unused code per Admin; its confirmation and its use are each written once, and a
/// confirmed one is never deleted. <c>gk_cli</c> reads it, for <c>recover-admin</c> later.</item>
/// </list>
/// No other role gets anything on these tables, <c>gk_hosted</c> above all (AD-2).
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261104010000_ConfirmSensitiveActions")]
public sealed class Migration20261104010000ConfirmSensitiveActions : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            -- NULL for a credential registered before this migration: its flags were never read.
            -- The first verified assertion records them; every new credential has both from the start.
            ALTER TABLE admin_credential
              ADD COLUMN backup_eligible boolean NULL,
              ADD COLUMN backed_up boolean NULL,
              ADD CONSTRAINT admin_credential_backed_up_needs_eligible CHECK (backed_up IS NOT TRUE OR backup_eligible IS TRUE),
              ADD CONSTRAINT admin_credential_backup_flags_together CHECK ((backup_eligible IS NULL) = (backed_up IS NULL));

            -- BE is fixed for a credential (WebAuthn §6.3.3): once known, it never changes or returns to NULL.
            CREATE FUNCTION admin_credential_guard_update() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF OLD.backup_eligible IS NOT NULL AND NEW.backup_eligible IS DISTINCT FROM OLD.backup_eligible THEN
                RAISE EXCEPTION 'an admin_credential''s backup_eligible is set once';
              END IF;

              RETURN NEW;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION admin_credential_guard_update() FROM PUBLIC;

            CREATE TRIGGER admin_credential_guard_update BEFORE UPDATE ON admin_credential
              FOR EACH ROW EXECUTE FUNCTION admin_credential_guard_update();

            -- Both refuse with their own SQLSTATE, GK001, so the host can tell them from any other fault.
            -- At most 10 credentials per Admin, whatever path inserts one. The Admin's row lock
            -- makes two inserts for one Admin take turns, so neither counts past the other.
            CREATE FUNCTION admin_credential_guard_insert() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              PERFORM 1 FROM admin WHERE id = NEW.admin_id FOR UPDATE;
              IF (SELECT count(*) FROM admin_credential WHERE admin_id = NEW.admin_id) >= 10 THEN
                RAISE EXCEPTION 'an admin holds at most 10 credentials' USING ERRCODE = 'GK001';
              END IF;

              RETURN NEW;
            END
            $$;

            -- At least 2 credentials per Admin stay, whatever path deletes one: no removal ever
            -- leaves an Admin locked out. Rows deleted earlier in the same statement count.
            CREATE FUNCTION admin_credential_guard_delete() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              PERFORM 1 FROM admin WHERE id = OLD.admin_id FOR UPDATE;
              IF (SELECT count(*) FROM admin_credential WHERE admin_id = OLD.admin_id) <= 2 THEN
                RAISE EXCEPTION 'an admin keeps at least 2 credentials' USING ERRCODE = 'GK001';
              END IF;

              RETURN OLD;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION admin_credential_guard_insert() FROM PUBLIC;
            REVOKE EXECUTE ON FUNCTION admin_credential_guard_delete() FROM PUBLIC;

            CREATE TRIGGER admin_credential_guard_insert BEFORE INSERT ON admin_credential
              FOR EACH ROW EXECUTE FUNCTION admin_credential_guard_insert();

            CREATE TRIGGER admin_credential_guard_delete BEFORE DELETE ON admin_credential
              FOR EACH ROW EXECUTE FUNCTION admin_credential_guard_delete();

            GRANT DELETE ON admin_credential TO gk_admin;
            GRANT UPDATE (backup_eligible, backed_up) ON admin_credential TO gk_admin;

            -- A recovery Session reaches only credential registration, and becomes full through it.
            ALTER TABLE admin_session
              DROP CONSTRAINT admin_session_kind,
              ADD CONSTRAINT admin_session_kind CHECK (kind IN ('setup', 'full', 'recovery'));

            -- An ended Session stays ended, and a Session's kind only ever goes from setup or
            -- recovery to full. An unknown kind is left to the CHECK.
            CREATE OR REPLACE FUNCTION admin_session_guard_update() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF OLD.ended_at IS NOT NULL
                 AND (NEW.ended_at IS DISTINCT FROM OLD.ended_at OR NEW.end_reason IS DISTINCT FROM OLD.end_reason) THEN
                RAISE EXCEPTION 'an ended admin_session can''t change its ending';
              END IF;

              IF NEW.kind IS DISTINCT FROM OLD.kind
                 AND (OLD.kind = 'full' OR NEW.kind IN ('setup', 'recovery')) THEN
                RAISE EXCEPTION 'an admin_session''s kind only goes from setup or recovery to full';
              END IF;

              RETURN NEW;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION admin_session_guard_update() FROM PUBLIC;

            CREATE UNLOGGED TABLE admin_fresh_assertion (
              id uuid PRIMARY KEY,
              session_id uuid NOT NULL REFERENCES admin_session (id) ON DELETE RESTRICT,
              stage text NOT NULL CONSTRAINT admin_fresh_assertion_stage CHECK (stage IN ('challenge', 'verified')),
              binding_hash bytea NOT NULL
                CONSTRAINT admin_fresh_assertion_binding_hash_length CHECK (octet_length(binding_hash) = 32),
              challenge_sha256 bytea NULL
                CONSTRAINT admin_fresh_assertion_challenge_length CHECK (octet_length(challenge_sha256) = 32),
              credential_id uuid NULL REFERENCES admin_credential (id) ON DELETE RESTRICT,
              created_at timestamptz NOT NULL,
              expires_at timestamptz NOT NULL,
              CONSTRAINT admin_fresh_assertion_challenge_stage CHECK ((challenge_sha256 IS NOT NULL) = (stage = 'challenge')),
              CONSTRAINT admin_fresh_assertion_credential_stage CHECK ((credential_id IS NOT NULL) = (stage = 'verified')),
              CONSTRAINT admin_fresh_assertion_lifetime
                CHECK (expires_at > created_at AND expires_at - created_at <= interval '5 minutes')
            );

            -- One pending ceremony per Session, and one grant per Session and binding.
            CREATE UNIQUE INDEX admin_fresh_assertion_one_challenge ON admin_fresh_assertion (session_id) WHERE stage = 'challenge';
            CREATE UNIQUE INDEX admin_fresh_assertion_one_grant ON admin_fresh_assertion (session_id, binding_hash) WHERE stage = 'verified';
            CREATE INDEX admin_fresh_assertion_expiry ON admin_fresh_assertion (expires_at);
            CREATE INDEX admin_fresh_assertion_credential ON admin_fresh_assertion (credential_id);

            GRANT SELECT, INSERT, DELETE ON admin_fresh_assertion TO gk_admin;

            CREATE TABLE admin_recovery_code (
              id uuid PRIMARY KEY,
              admin_id uuid NOT NULL REFERENCES admin (id) ON DELETE RESTRICT,
              code_hmac bytea NOT NULL
                CONSTRAINT admin_recovery_code_hmac_unique UNIQUE
                CONSTRAINT admin_recovery_code_hmac_length CHECK (octet_length(code_hmac) = 32),
              hmac_key_version integer NOT NULL CONSTRAINT admin_recovery_code_key_version CHECK (hmac_key_version >= 1),
              created_at timestamptz NOT NULL,
              confirmed_at timestamptz NULL,
              used_at timestamptz NULL,
              CONSTRAINT admin_recovery_code_used_after_confirmed CHECK (used_at IS NULL OR confirmed_at IS NOT NULL),
              CONSTRAINT admin_recovery_code_confirmed_after_creation CHECK (confirmed_at IS NULL OR confirmed_at >= created_at),
              CONSTRAINT admin_recovery_code_used_after_confirmation CHECK (used_at IS NULL OR used_at >= confirmed_at)
            );

            -- One unused code per Admin: a new one replaces an unconfirmed one, never a confirmed one.
            CREATE UNIQUE INDEX admin_recovery_code_one_unused ON admin_recovery_code (admin_id) WHERE used_at IS NULL;

            -- Confirmation and use are written once, and a confirmed code is never deleted.
            CREATE FUNCTION admin_recovery_code_guard() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF TG_OP = 'DELETE' THEN
                IF OLD.confirmed_at IS NOT NULL THEN
                  RAISE EXCEPTION 'a confirmed admin_recovery_code is never deleted';
                END IF;

                RETURN OLD;
              END IF;

              IF OLD.confirmed_at IS NOT NULL AND NEW.confirmed_at IS DISTINCT FROM OLD.confirmed_at THEN
                RAISE EXCEPTION 'an admin_recovery_code''s confirmed_at is set once';
              END IF;

              IF OLD.used_at IS NOT NULL AND NEW.used_at IS DISTINCT FROM OLD.used_at THEN
                RAISE EXCEPTION 'an admin_recovery_code''s used_at is set once';
              END IF;

              RETURN NEW;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION admin_recovery_code_guard() FROM PUBLIC;

            CREATE TRIGGER admin_recovery_code_guard BEFORE UPDATE OR DELETE ON admin_recovery_code
              FOR EACH ROW EXECUTE FUNCTION admin_recovery_code_guard();

            GRANT SELECT, INSERT, DELETE ON admin_recovery_code TO gk_admin;
            GRANT UPDATE (confirmed_at, used_at) ON admin_recovery_code TO gk_admin;
            GRANT SELECT ON admin_recovery_code TO gk_cli;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
