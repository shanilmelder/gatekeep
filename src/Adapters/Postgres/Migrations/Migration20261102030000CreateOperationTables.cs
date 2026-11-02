using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// The AD-30 Operation tables, and the job guard re-rendered for the two Operation job
/// types. Neither table has a free-text column: the type, stage and result code are checked
/// codes, so no personal data can be stored. The guard between the markers is the render of
/// the Operations production registry (`OperationsContract.RenderGuard`).
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261102030000_CreateOperationTables")]
public sealed class Migration20261102030000CreateOperationTables : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            CREATE TABLE operation (
              id uuid PRIMARY KEY,
              type text NOT NULL
                CONSTRAINT operation_type_code
                CHECK (type ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$' AND char_length(type) <= 128),
              tenant_id uuid REFERENCES tenant (id) ON DELETE RESTRICT,
              status text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'failed', 'succeeded')),
              created_at timestamptz NOT NULL DEFAULT now(),
              updated_at timestamptz NOT NULL DEFAULT now(),
              finished_at timestamptz
            );

            -- One active Operation per type and scope. The Deployment scope is the nil UUID here.
            CREATE UNIQUE INDEX operation_one_active
              ON operation (type, coalesce(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid))
              WHERE status IN ('running', 'failed');

            CREATE TABLE operation_step (
              id uuid PRIMARY KEY,
              operation_id uuid NOT NULL REFERENCES operation (id) ON DELETE RESTRICT,
              position integer NOT NULL CHECK (position >= 0),
              tenant_id uuid REFERENCES tenant (id) ON DELETE RESTRICT,
              stage text NOT NULL
                CONSTRAINT operation_step_stage_code
                CHECK (stage ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$' AND char_length(stage) <= 64),
              status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'succeeded', 'failed')),
              result_code text
                CONSTRAINT operation_step_result_code
                CHECK (result_code ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$' AND char_length(result_code) <= 64),
              attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
              created_at timestamptz NOT NULL DEFAULT now(),
              updated_at timestamptz NOT NULL DEFAULT now(),
              UNIQUE (operation_id, position)
            );

            CREATE UNIQUE INDEX operation_step_once
              ON operation_step (operation_id, stage, coalesce(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid));
            CREATE INDEX operation_step_tenant ON operation_step (tenant_id) WHERE tenant_id IS NOT NULL;

            -- A Tenant-scoped Operation's steps are for its own Tenant, or for the Deployment.
            CREATE FUNCTION operation_step_guard_insert() RETURNS trigger LANGUAGE plpgsql AS $$
            DECLARE
              owner uuid;
            BEGIN
              SELECT tenant_id INTO owner FROM operation WHERE id = NEW.operation_id;
              IF owner IS NOT NULL AND NEW.tenant_id IS NOT NULL AND NEW.tenant_id <> owner THEN
                RAISE EXCEPTION 'a step can''t be for a Tenant other than its Operation''s';
              END IF;
              RETURN NEW;
            END
            $$;

            -- Firing a trigger needs no EXECUTE, so nobody keeps it.
            REVOKE EXECUTE ON FUNCTION operation_step_guard_insert() FROM PUBLIC;

            CREATE TRIGGER operation_step_guard_insert BEFORE INSERT ON operation_step
              FOR EACH ROW EXECUTE FUNCTION operation_step_guard_insert();

            -- Starting and retrying: insert, and the status columns a retry reopens.
            GRANT SELECT, INSERT ON operation TO gk_admin, gk_cli, gk_worker;
            GRANT UPDATE (status, updated_at, finished_at) ON operation TO gk_admin, gk_cli, gk_worker;
            GRANT SELECT, INSERT ON operation_step TO gk_admin, gk_cli, gk_worker;
            GRANT UPDATE (status, result_code, updated_at) ON operation_step TO gk_admin, gk_cli;
            -- Running steps: their status, result code and attempt count. Never their Operation, Tenant or stage.
            GRANT UPDATE (status, result_code, attempts, updated_at) ON operation_step TO gk_worker;

            -- BEGIN rendered guard
            CREATE OR REPLACE FUNCTION job_guard_insert() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              -- The CHECK constraint refuses neither or both, so such a row isn't judged here.
              IF (NEW.tenant_id IS NULL) IS DISTINCT FROM NEW.deployment_wide THEN
                RETURN NEW;
              END IF;

              -- An unset Tenant raises, as the row-level security policies do.
              IF NEW.tenant_id IS NOT NULL AND NEW.tenant_id <> current_setting('gatekeep.tenant_id')::uuid THEN
                RAISE EXCEPTION 'a job can''t be enqueued for another Tenant';
              END IF;

              IF NEW.deployment_wide AND coalesce(current_setting('gatekeep.tenant_id', true), '') <> '' THEN
                RAISE EXCEPTION 'a Deployment-wide job can''t be enqueued in a Tenant scope';
              END IF;

              CASE NEW.type
                WHEN 'operations.job.purge' THEN
                  IF NOT NEW.deployment_wide THEN
                    RAISE EXCEPTION 'job type % is Deployment-wide', NEW.type;
                  END IF;
                  IF NOT (current_user::text = ANY (ARRAY['gk_worker'])) THEN
                    RAISE EXCEPTION 'job type % can''t be enqueued by %', NEW.type, current_user;
                  END IF;
                WHEN 'operations.operation.run' THEN
                  IF NOT NEW.deployment_wide THEN
                    RAISE EXCEPTION 'job type % is Deployment-wide', NEW.type;
                  END IF;
                  IF NOT (current_user::text = ANY (ARRAY['gk_admin', 'gk_cli', 'gk_worker'])) THEN
                    RAISE EXCEPTION 'job type % can''t be enqueued by %', NEW.type, current_user;
                  END IF;
                WHEN 'operations.operation.step' THEN
                  IF NEW.deployment_wide THEN
                    RAISE EXCEPTION 'job type % is for one Tenant', NEW.type;
                  END IF;
                  IF NOT (current_user::text = ANY (ARRAY['gk_worker'])) THEN
                    RAISE EXCEPTION 'job type % can''t be enqueued by %', NEW.type, current_user;
                  END IF;
                ELSE
                  RAISE EXCEPTION 'job type % isn''t in the registry', NEW.type;
              END CASE;

              -- A job always starts unclaimed, whatever the enqueuer sent.
              NEW.status := 'pending';
              NEW.attempts := 0;
              NEW.locked_until := NULL;
              NEW.failure_code := NULL;
              NEW.finished_at := NULL;
              NEW.created_at := now();
              NEW.run_after := coalesce(NEW.run_after, now());

              RETURN NEW;
            END
            $$;
            -- END rendered guard
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
