using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 1.29: deleting a Tenant without touching others (FR-7, AD-6, AD-30).
/// <list type="bullet">
/// <item>A deleted Tenant is a tombstone, never a deleted row: <c>tenant.status</c> gains
/// <c>deleting</c> and <c>deleted</c>, and the <c>tenant</c> and <c>tenant_host</c> rows stay for
/// good, so the host is never issued again and no <c>ON DELETE RESTRICT</c> key to <c>tenant</c> fires.</item>
/// <item><c>tenant_guard_update</c> keeps every Story 1.27 and 1.28 rule. A status goes only
/// <c>creating</c> to <c>active</c> (<c>gk_worker</c>, once settings exist), <c>creating</c> or
/// <c>active</c> to <c>deleting</c> (<c>gk_admin</c>), and <c>deleting</c> to <c>deleted</c>
/// (<c>gk_worker</c>, once no settings row is left). Nothing leaves <c>deleted</c>.</item>
/// <item><c>tenant_settings_guard_delete</c> lets a settings row go only while its Tenant is
/// <c>deleting</c>, for every role, and so does each <c>signing_key</c> and <c>protection_key_wrap</c> row (Story 2.3). <c>tenant_role_guard_delete</c> holds <c>gk_admin</c>'s
/// <c>DELETE</c> to a <c>deleting</c> Tenant's roles, until Story 8.4 removes single roles.</item>
/// <item><c>gk_admin</c> may set a Tenant's status and delete its roles, the deletion's start;
/// <c>gk_worker</c> may delete a <c>deleting</c> Tenant's settings and key rows, and the Identity, Sessions and
/// Authentication rows its purges delete, reading only their <c>tenant_id</c>.</item>
/// </list>
/// The triggers hold every DML by any role; a table owner or superuser can still disable triggers.
/// Each refusal a caller can meet raises its own SQLSTATE, mapped to a refusal by the code:
/// <c>GK002</c> a host, <c>GK003</c> a Tenant's insert, <c>GK004</c> a role, <c>GK005</c> an
/// activation without settings, <c>GK006</c> a label change on a Tenant that isn't active,
/// <c>GK007</c> a status change outside the lifecycle, <c>GK008</c> a settings delete of a Tenant
/// that isn't deleting, <c>GK009</c> an Admin role delete of a Tenant that isn't deleting and
/// <c>GK010</c> a Tenant row written for a Tenant whose status doesn't allow it: <c>tenant_row_guard</c>
/// lets the purged tables be inserted into only while their Tenant is creating or active (a job
/// payload while it is deleting too), and settings be updated only while it is active.
/// <c>job.failure_code</c> gains <c>tenant_deleted</c>, for a deleted Tenant's pending jobs.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261105020000_DeleteTenants")]
public sealed class Migration20261105020000DeleteTenants : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            ALTER TABLE tenant DROP CONSTRAINT tenant_status;
            ALTER TABLE tenant ADD CONSTRAINT tenant_status CHECK (status IN ('creating', 'active', 'deleting', 'deleted'));

            -- What was derived from the Tenant Subdomain is stored once and never changes; a Tenant's
            -- status follows its lifecycle only, each step by the one role that takes it; and its label
            -- changes only while it is active.
            CREATE OR REPLACE FUNCTION tenant_guard_update() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF NEW.id IS DISTINCT FROM OLD.id
                 OR NEW.issuer IS DISTINCT FROM OLD.issuer
                 OR NEW.rp_id IS DISTINCT FROM OLD.rp_id
                 OR NEW.email_link_base IS DISTINCT FROM OLD.email_link_base
                 OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'a tenant''s id, issuer, rp_id, email_link_base and created_at never change';
              END IF;

              IF NEW.status IS DISTINCT FROM OLD.status THEN
                IF NOT ((OLD.status = 'creating' AND NEW.status = 'active')
                        OR (OLD.status IN ('creating', 'active') AND NEW.status = 'deleting')
                        OR (OLD.status = 'deleting' AND NEW.status = 'deleted')) THEN
                  RAISE EXCEPTION 'a tenant''s status goes only creating to active, creating or active to deleting, and deleting to deleted'
                    USING ERRCODE = 'GK007';
                END IF;

                -- An allow-list: only the one role that takes each step may, and no other role at all.
                IF NOT ((current_user = 'gk_admin' AND NEW.status = 'deleting')
                        OR (current_user = 'gk_worker' AND NEW.status IN ('active', 'deleted'))) THEN
                  RAISE EXCEPTION 'a tenant''s status goes only creating to active, creating or active to deleting, and deleting to deleted'
                    USING ERRCODE = 'GK007';
                END IF;

                IF NEW.status = 'active' AND NOT EXISTS (SELECT 1 FROM tenant_settings WHERE tenant_id = NEW.id) THEN
                  RAISE EXCEPTION 'a tenant becomes active only once its settings exist' USING ERRCODE = 'GK005';
                END IF;

                IF NEW.status = 'deleted' AND EXISTS (SELECT 1 FROM tenant_settings WHERE tenant_id = NEW.id) THEN
                  RAISE EXCEPTION 'a tenant''s status goes only creating to active, creating or active to deleting, and deleting to deleted'
                    USING ERRCODE = 'GK007';
                END IF;
              END IF;

              IF NEW.label IS DISTINCT FROM OLD.label AND OLD.status IS DISTINCT FROM 'active' THEN
                RAISE EXCEPTION 'a tenant''s label changes only while it is active' USING ERRCODE = 'GK006';
              END IF;

              RETURN NEW;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION tenant_guard_update() FROM PUBLIC;

            -- A Tenant's settings, and from Story 2.3 its key rows, go only with its deletion, whoever deletes them.
            CREATE FUNCTION tenant_settings_guard_delete() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF NOT EXISTS (SELECT 1 FROM tenant WHERE id = OLD.tenant_id AND status = 'deleting') THEN
                RAISE EXCEPTION 'a tenant''s settings and key rows are deleted only while it is deleting' USING ERRCODE = 'GK008';
              END IF;

              RETURN OLD;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION tenant_settings_guard_delete() FROM PUBLIC;

            CREATE TRIGGER tenant_settings_guard_delete BEFORE DELETE ON tenant_settings
              FOR EACH ROW EXECUTE FUNCTION tenant_settings_guard_delete();

            -- Host.Admin removes roles only with a Tenant's deletion (Story 1.29). Story 8.4 replaces
            -- this when it removes single roles.
            CREATE FUNCTION tenant_role_guard_delete() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF current_user = 'gk_admin'
                 AND NOT EXISTS (SELECT 1 FROM tenant WHERE id = OLD.tenant_id AND status = 'deleting') THEN
                RAISE EXCEPTION 'gk_admin deletes only the roles of a deleting tenant' USING ERRCODE = 'GK009';
              END IF;

              RETURN OLD;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION tenant_role_guard_delete() FROM PUBLIC;

            CREATE TRIGGER tenant_role_guard_delete BEFORE DELETE ON tenant_role
              FOR EACH ROW EXECUTE FUNCTION tenant_role_guard_delete();

            -- No Tenant row is written for a Tenant whose status the trigger's arguments don't
            -- list: nothing reaches a deleting or deleted Tenant's tables once its deletion has
            -- started, but the deletion's own step jobs' payloads. One function, attached to every
            -- purged tenant-class table; the registry lists the trigger on each, and a test holds
            -- every purged table to it. The read takes no lock (no runtime role may lock tenant
            -- rows but gk_admin and gk_worker): the purge stage's FOR UPDATE waits for every writer
            -- whose foreign-key check holds the Tenant's row.
            CREATE FUNCTION tenant_row_guard() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF NOT EXISTS (SELECT 1 FROM tenant WHERE id = NEW.tenant_id AND status = ANY (TG_ARGV)) THEN
                RAISE EXCEPTION 'a tenant''s rows are written only while its status allows it' USING ERRCODE = 'GK010';
              END IF;

              RETURN NEW;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION tenant_row_guard() FROM PUBLIC;

            CREATE TRIGGER tenant_row_guard BEFORE INSERT ON tenant_settings
              FOR EACH ROW EXECUTE FUNCTION tenant_row_guard('creating', 'active');
            CREATE TRIGGER tenant_row_guard BEFORE INSERT ON "user"
              FOR EACH ROW EXECUTE FUNCTION tenant_row_guard('creating', 'active');
            CREATE TRIGGER tenant_row_guard BEFORE INSERT ON user_session
              FOR EACH ROW EXECUTE FUNCTION tenant_row_guard('creating', 'active');
            CREATE TRIGGER tenant_row_guard BEFORE INSERT ON "authorization"
              FOR EACH ROW EXECUTE FUNCTION tenant_row_guard('creating', 'active');
            CREATE TRIGGER tenant_row_guard BEFORE INSERT ON token
              FOR EACH ROW EXECUTE FUNCTION tenant_row_guard('creating', 'active');
            CREATE TRIGGER tenant_row_guard BEFORE INSERT ON signin_transaction
              FOR EACH ROW EXECUTE FUNCTION tenant_row_guard('creating', 'active');
            CREATE TRIGGER tenant_row_guard BEFORE INSERT ON job_payload
              FOR EACH ROW EXECUTE FUNCTION tenant_row_guard('creating', 'active', 'deleting');

            -- A Tenant's settings change only while it is active.
            CREATE TRIGGER tenant_settings_guard_update BEFORE UPDATE ON tenant_settings
              FOR EACH ROW EXECUTE FUNCTION tenant_row_guard('active');

            -- A deleted Tenant's pending jobs end with their own reason.
            ALTER TABLE job DROP CONSTRAINT job_failure_code_check;
            ALTER TABLE job ADD CONSTRAINT job_failure_code_check
              CHECK (failure_code IN ('handler_failed', 'timed_out', 'unknown_type', 'custody_failed', 'lease_expired', 'tenant_deleted'));

            -- The deletion's start: the Tenant stops resolving, and every role in it ends.
            GRANT UPDATE (status) ON tenant TO gk_admin;
            GRANT DELETE ON tenant_role TO gk_admin;

            -- The deletion Operation's purges, in the Tenant's own scope: only the column each
            -- purge's WHERE reads, never the content.
            GRANT DELETE ON tenant_settings TO gk_worker;
            GRANT SELECT (tenant_id), DELETE ON "user" TO gk_worker;
            GRANT SELECT (tenant_id), DELETE ON user_session TO gk_worker;
            GRANT SELECT (tenant_id), DELETE ON "authorization" TO gk_worker;
            GRANT SELECT (tenant_id), DELETE ON token TO gk_worker;
            GRANT SELECT (tenant_id), DELETE ON signin_transaction TO gk_worker;

            -- Keys (Story 2.3): no key row reaches a Tenant once its deletion has started, and a key
            -- row goes only with its Tenant's deletion, whoever deletes it. Rotation never deletes one.
            CREATE TRIGGER tenant_row_guard BEFORE INSERT ON signing_key
              FOR EACH ROW EXECUTE FUNCTION tenant_row_guard('creating', 'active');
            CREATE TRIGGER tenant_row_guard BEFORE INSERT ON protection_key_wrap
              FOR EACH ROW EXECUTE FUNCTION tenant_row_guard('creating', 'active');

            CREATE TRIGGER signing_key_guard_delete BEFORE DELETE ON signing_key
              FOR EACH ROW EXECUTE FUNCTION tenant_settings_guard_delete();
            CREATE TRIGGER protection_key_wrap_guard_delete BEFORE DELETE ON protection_key_wrap
              FOR EACH ROW EXECUTE FUNCTION tenant_settings_guard_delete();

            GRANT DELETE ON signing_key TO gk_worker;
            GRANT DELETE ON protection_key_wrap TO gk_worker;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
