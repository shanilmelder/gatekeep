using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

[DbContext(typeof(MigrationsContext))]
[Migration("20261102010000_CreateAuditTables")]
public sealed class Migration20261102010000CreateAuditTables : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            CREATE TABLE audit_event (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              id uuid NOT NULL,
              occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
              type_code text NOT NULL CHECK (type_code ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$'),
              actor_kind text NOT NULL CHECK (actor_kind IN ('system', 'anonymous', 'admin', 'user', 'client')),
              actor_id uuid,
              target_kind text CHECK (target_kind IN ('tenant', 'admin', 'user', 'client')),
              target_id uuid,
              seq bigint,
              prev_hash bytea,
              hash bytea,
              PRIMARY KEY (tenant_id, id),
              UNIQUE (tenant_id, seq),
              CHECK ((actor_kind IN ('system', 'anonymous')) = (actor_id IS NULL)),
              CHECK ((target_kind IS NULL) = (target_id IS NULL)),
              CHECK (char_length(type_code) <= 128),
              CHECK ((seq IS NULL) = (hash IS NULL)),
              CHECK (prev_hash IS NULL OR seq IS NOT NULL)
            );

            CREATE TABLE audit_detail (
              tenant_id uuid NOT NULL,
              event_id uuid NOT NULL,
              ip_address inet,
              user_agent text,
              email text,
              PRIMARY KEY (tenant_id, event_id),
              FOREIGN KEY (tenant_id, event_id) REFERENCES audit_event (tenant_id, id) ON DELETE RESTRICT
            );

            CREATE TABLE deployment_audit_event (
              id uuid PRIMARY KEY,
              occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
              type_code text NOT NULL CHECK (type_code ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$'),
              actor_kind text NOT NULL CHECK (actor_kind IN ('system', 'anonymous', 'admin', 'user', 'client')),
              actor_id uuid,
              target_kind text CHECK (target_kind IN ('tenant', 'admin', 'user', 'client')),
              target_id uuid,
              seq bigint UNIQUE,
              prev_hash bytea,
              hash bytea,
              CHECK ((actor_kind IN ('system', 'anonymous')) = (actor_id IS NULL)),
              CHECK ((target_kind IS NULL) = (target_id IS NULL)),
              CHECK (char_length(type_code) <= 128),
              CHECK ((seq IS NULL) = (hash IS NULL)),
              CHECK (prev_hash IS NULL OR seq IS NOT NULL)
            );

            CREATE TABLE deployment_audit_detail (
              event_id uuid PRIMARY KEY REFERENCES deployment_audit_event (id) ON DELETE RESTRICT,
              ip_address inet,
              user_agent text,
              email text
            );

            ALTER TABLE audit_event ENABLE ROW LEVEL SECURITY;
            ALTER TABLE audit_event FORCE ROW LEVEL SECURITY;

            CREATE POLICY audit_event_permissive ON audit_event
              AS PERMISSIVE FOR ALL
              USING (true)
              WITH CHECK (true);

            CREATE POLICY audit_event_tenant ON audit_event
              AS RESTRICTIVE FOR ALL
              USING (tenant_id = current_setting('gatekeep.tenant_id')::uuid)
              WITH CHECK (tenant_id = current_setting('gatekeep.tenant_id')::uuid);

            ALTER TABLE audit_detail ENABLE ROW LEVEL SECURITY;
            ALTER TABLE audit_detail FORCE ROW LEVEL SECURITY;

            CREATE POLICY audit_detail_permissive ON audit_detail
              AS PERMISSIVE FOR ALL
              USING (true)
              WITH CHECK (true);

            CREATE POLICY audit_detail_tenant ON audit_detail
              AS RESTRICTIVE FOR ALL
              USING (tenant_id = current_setting('gatekeep.tenant_id')::uuid)
              WITH CHECK (tenant_id = current_setting('gatekeep.tenant_id')::uuid);

            -- The time is assigned here and the seal comes only from gk_sealer's update, so an
            -- inserting role can't backdate an event or take a sequence number from the sealer.
            CREATE FUNCTION audit_guard_insert() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF NEW.seq IS NOT NULL OR NEW.prev_hash IS NOT NULL OR NEW.hash IS NOT NULL THEN
                RAISE EXCEPTION '% row can''t be inserted with a seal', TG_TABLE_NAME;
              END IF;

              NEW.occurred_at := clock_timestamp();

              RETURN NEW;
            END
            $$;

            -- These raise for the owner too, whom grants don't stop. The envelope comparison
            -- uses the whole row, so a column added later is guarded as well.
            CREATE FUNCTION audit_guard_update() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF current_user <> 'gk_sealer' THEN
                RAISE EXCEPTION '% rows can be changed only by gk_sealer', TG_TABLE_NAME;
              END IF;

              IF OLD.seq IS NOT NULL OR OLD.prev_hash IS NOT NULL OR OLD.hash IS NOT NULL THEN
                RAISE EXCEPTION '% row is already sealed', TG_TABLE_NAME;
              END IF;

              IF (to_jsonb(NEW) - ARRAY['seq', 'prev_hash', 'hash'])
                 IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['seq', 'prev_hash', 'hash']) THEN
                RAISE EXCEPTION '% envelope is immutable', TG_TABLE_NAME;
              END IF;

              RETURN NEW;
            END
            $$;

            -- Each trigger's arguments name the roles that may delete from its table.
            CREATE FUNCTION audit_guard_delete() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF NOT (current_user::text = ANY (TG_ARGV)) THEN
                RAISE EXCEPTION '% rows can''t be deleted by %', TG_TABLE_NAME, current_user;
              END IF;

              -- Nested, because detail tables have no seq column to read.
              IF TG_TABLE_NAME IN ('audit_event', 'deployment_audit_event') THEN
                IF OLD.seq IS NULL THEN
                  RAISE EXCEPTION '% row is unsealed, and only sealed ranges can be deleted', TG_TABLE_NAME;
                END IF;
              END IF;

              RETURN OLD;
            END
            $$;

            CREATE FUNCTION audit_refuse_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              RAISE EXCEPTION '% can''t be truncated', TG_TABLE_NAME;
            END
            $$;

            -- Firing a trigger needs no EXECUTE, so nobody keeps it.
            REVOKE EXECUTE ON FUNCTION
              audit_guard_insert(), audit_guard_update(), audit_guard_delete(), audit_refuse_truncate()
              FROM PUBLIC;

            CREATE TRIGGER audit_event_guard_insert BEFORE INSERT ON audit_event
              FOR EACH ROW EXECUTE FUNCTION audit_guard_insert();
            CREATE TRIGGER audit_event_guard_update BEFORE UPDATE ON audit_event
              FOR EACH ROW EXECUTE FUNCTION audit_guard_update();
            CREATE TRIGGER audit_event_guard_delete BEFORE DELETE ON audit_event
              FOR EACH ROW EXECUTE FUNCTION audit_guard_delete('gk_retention');
            CREATE TRIGGER audit_event_refuse_truncate BEFORE TRUNCATE ON audit_event
              FOR EACH STATEMENT EXECUTE FUNCTION audit_refuse_truncate();

            CREATE TRIGGER deployment_audit_event_guard_insert BEFORE INSERT ON deployment_audit_event
              FOR EACH ROW EXECUTE FUNCTION audit_guard_insert();
            CREATE TRIGGER deployment_audit_event_guard_update BEFORE UPDATE ON deployment_audit_event
              FOR EACH ROW EXECUTE FUNCTION audit_guard_update();
            CREATE TRIGGER deployment_audit_event_guard_delete BEFORE DELETE ON deployment_audit_event
              FOR EACH ROW EXECUTE FUNCTION audit_guard_delete('gk_retention');
            CREATE TRIGGER deployment_audit_event_refuse_truncate BEFORE TRUNCATE ON deployment_audit_event
              FOR EACH STATEMENT EXECUTE FUNCTION audit_refuse_truncate();

            -- No role is granted UPDATE on detail, so its update guard only ever stops the owner.
            CREATE TRIGGER audit_detail_guard_update BEFORE UPDATE ON audit_detail
              FOR EACH ROW EXECUTE FUNCTION audit_guard_update();
            CREATE TRIGGER audit_detail_guard_delete BEFORE DELETE ON audit_detail
              FOR EACH ROW EXECUTE FUNCTION audit_guard_delete('gk_worker', 'gk_retention');
            CREATE TRIGGER audit_detail_refuse_truncate BEFORE TRUNCATE ON audit_detail
              FOR EACH STATEMENT EXECUTE FUNCTION audit_refuse_truncate();

            CREATE TRIGGER deployment_audit_detail_guard_update BEFORE UPDATE ON deployment_audit_detail
              FOR EACH ROW EXECUTE FUNCTION audit_guard_update();
            CREATE TRIGGER deployment_audit_detail_guard_delete BEFORE DELETE ON deployment_audit_detail
              FOR EACH ROW EXECUTE FUNCTION audit_guard_delete('gk_worker', 'gk_retention');
            CREATE TRIGGER deployment_audit_detail_refuse_truncate BEFORE TRUNCATE ON deployment_audit_detail
              FOR EACH STATEMENT EXECUTE FUNCTION audit_refuse_truncate();

            GRANT INSERT ON audit_event TO gk_hosted;
            GRANT SELECT, INSERT ON audit_event TO gk_admin, gk_worker, gk_cli;
            GRANT SELECT ON audit_event TO gk_sealer;
            GRANT UPDATE (seq, prev_hash, hash) ON audit_event TO gk_sealer;
            GRANT SELECT, INSERT, DELETE ON audit_event TO gk_retention;

            GRANT INSERT ON audit_detail TO gk_hosted;
            GRANT SELECT, INSERT ON audit_detail TO gk_admin, gk_cli;
            GRANT SELECT, INSERT, DELETE ON audit_detail TO gk_worker;
            GRANT SELECT, DELETE ON audit_detail TO gk_retention;

            GRANT SELECT, INSERT ON deployment_audit_event TO gk_admin, gk_worker, gk_cli;
            GRANT SELECT ON deployment_audit_event TO gk_sealer;
            GRANT UPDATE (seq, prev_hash, hash) ON deployment_audit_event TO gk_sealer;
            GRANT SELECT, INSERT, DELETE ON deployment_audit_event TO gk_retention;

            GRANT SELECT, INSERT ON deployment_audit_detail TO gk_admin, gk_cli;
            GRANT SELECT, INSERT, DELETE ON deployment_audit_detail TO gk_worker;
            GRANT SELECT, DELETE ON deployment_audit_detail TO gk_retention;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
