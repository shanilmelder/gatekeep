using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// The AD-15 job tables. The guard function between the markers is the render of the
/// Operations production registry (`OperationsContract.RenderGuard`). Migrations are
/// forward-only, so a registry change adds a new migration holding the new render between
/// the same markers. A test compares the latest such block with the registry.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261102020000_CreateJobTables")]
public sealed class Migration20261102020000CreateJobTables : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            CREATE TABLE job (
              id uuid PRIMARY KEY,
              type text NOT NULL CHECK (type ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$' AND char_length(type) <= 128),
              tenant_id uuid REFERENCES tenant (id) ON DELETE RESTRICT,
              deployment_wide boolean NOT NULL DEFAULT false,
              operation_id uuid,
              status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'done', 'dead')),
              attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
              run_after timestamptz NOT NULL DEFAULT now(),
              locked_until timestamptz,
              failure_code text CHECK (failure_code IN ('handler_failed', 'timed_out', 'unknown_type', 'custody_failed', 'lease_expired')),
              created_at timestamptz NOT NULL DEFAULT now(),
              finished_at timestamptz,
              CONSTRAINT job_tenant_or_deployment CHECK ((tenant_id IS NULL) = deployment_wide),
              UNIQUE (tenant_id, id)
            );

            CREATE INDEX job_due ON job (run_after) WHERE status IN ('pending', 'running');
            CREATE INDEX job_type_status ON job (type, status);

            -- IDs only, plus at most one Transit ciphertext. The composite key keeps the
            -- payload's Tenant equal to its job's.
            CREATE TABLE job_payload (
              tenant_id uuid NOT NULL,
              job_id uuid NOT NULL,
              ids jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(ids) = 'object'),
              ciphertext text CHECK (ciphertext ~ '^vault:v[0-9]+:' AND char_length(ciphertext) <= 8192),
              PRIMARY KEY (tenant_id, job_id),
              FOREIGN KEY (tenant_id, job_id) REFERENCES job (tenant_id, id) ON DELETE RESTRICT,
              CONSTRAINT job_payload_ids_bounded CHECK (jsonb_array_length(jsonb_path_query_array(ids, '$.keyvalue()')) <= 16),
              CONSTRAINT job_payload_ids_only CHECK (NOT jsonb_path_exists(
                ids,
                '$.keyvalue() ? (!(@.key like_regex "^[a-z][a-z0-9_]*$") || !(@.value.type() == "string") || !(@.value like_regex "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))'))
            );

            ALTER TABLE job_payload ENABLE ROW LEVEL SECURITY;
            ALTER TABLE job_payload FORCE ROW LEVEL SECURITY;

            CREATE POLICY job_payload_permissive ON job_payload
              AS PERMISSIVE FOR ALL
              USING (true)
              WITH CHECK (true);

            CREATE POLICY job_payload_tenant ON job_payload
              AS RESTRICTIVE FOR ALL
              USING (tenant_id = current_setting('gatekeep.tenant_id')::uuid)
              WITH CHECK (tenant_id = current_setting('gatekeep.tenant_id')::uuid);

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

            CREATE FUNCTION job_notify_insert() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              -- No payload: a listener learns only that something is due.
              PERFORM pg_notify('gatekeep_job', '');
              RETURN NULL;
            END
            $$;

            -- Firing a trigger needs no EXECUTE, so nobody keeps it.
            REVOKE EXECUTE ON FUNCTION job_guard_insert(), job_notify_insert() FROM PUBLIC;

            CREATE TRIGGER job_guard_insert BEFORE INSERT ON job
              FOR EACH ROW EXECUTE FUNCTION job_guard_insert();
            CREATE TRIGGER job_notify_insert AFTER INSERT ON job
              FOR EACH STATEMENT EXECUTE FUNCTION job_notify_insert();

            GRANT INSERT ON job TO gk_hosted, gk_admin, gk_sealer, gk_cli;
            GRANT SELECT, INSERT, DELETE ON job TO gk_worker;
            GRANT UPDATE (status, locked_until, finished_at, failure_code) ON job TO gk_worker;
            GRANT SELECT ON job TO gk_dispatch;
            GRANT UPDATE (status, attempts, run_after, locked_until, failure_code) ON job TO gk_dispatch;

            GRANT INSERT ON job_payload TO gk_hosted, gk_admin, gk_cli;
            GRANT SELECT, INSERT, DELETE ON job_payload TO gk_worker;
            GRANT UPDATE (ciphertext) ON job_payload TO gk_worker;
            GRANT SELECT, INSERT ON job_payload TO gk_sealer;
            GRANT SELECT ON job_payload TO gk_retention;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
