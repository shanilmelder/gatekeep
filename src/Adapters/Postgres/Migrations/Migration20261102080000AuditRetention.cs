using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// AD-16 retention checkpoints. When retention deletes a chain's sealed prefix it writes one
/// <c>audit.retention.checkpoint</c> event naming the last deleted row's <c>epoch</c>,
/// <c>seq</c> and <c>hash</c>, so verification can tell a retention cut from a missing range.
/// Only <c>gk_retention</c> may insert one. The guard is re-rendered for the retention job types.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261102080000_AuditRetention")]
public sealed class Migration20261102080000AuditRetention : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            ALTER TABLE audit_event
              ADD COLUMN checkpoint_epoch bigint,
              ADD COLUMN checkpoint_seq bigint,
              ADD COLUMN checkpoint_hash bytea;

            ALTER TABLE deployment_audit_event
              ADD COLUMN checkpoint_epoch bigint,
              ADD COLUMN checkpoint_seq bigint,
              ADD COLUMN checkpoint_hash bytea;

            -- A checkpoint names the last deleted row; no other event names anything. A comparison
            -- with NULL passes a CHECK, so each column's presence is tested on its own.
            ALTER TABLE audit_event
              ADD CONSTRAINT audit_event_checkpoint CHECK (
                CASE WHEN type_code = 'audit.retention.checkpoint'
                  THEN checkpoint_epoch IS NOT NULL AND checkpoint_seq IS NOT NULL AND checkpoint_hash IS NOT NULL
                    AND checkpoint_epoch >= 1 AND checkpoint_seq >= 1
                  ELSE checkpoint_epoch IS NULL AND checkpoint_seq IS NULL AND checkpoint_hash IS NULL
                END);

            ALTER TABLE deployment_audit_event
              ADD CONSTRAINT deployment_audit_event_checkpoint CHECK (
                CASE WHEN type_code = 'audit.retention.checkpoint'
                  THEN checkpoint_epoch IS NOT NULL AND checkpoint_seq IS NOT NULL AND checkpoint_hash IS NOT NULL
                    AND checkpoint_epoch >= 1 AND checkpoint_seq >= 1
                  ELSE checkpoint_epoch IS NULL AND checkpoint_seq IS NULL AND checkpoint_hash IS NULL
                END);

            -- Retention alone writes a checkpoint, so no other role can pass a deleted range off as one.
            CREATE OR REPLACE FUNCTION audit_guard_insert() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF NEW.seq IS NOT NULL OR NEW.prev_hash IS NOT NULL OR NEW.hash IS NOT NULL OR NEW.epoch IS NOT NULL THEN
                RAISE EXCEPTION '% row can''t be inserted with a seal', TG_TABLE_NAME;
              END IF;

              IF NEW.type_code = 'audit.retention.checkpoint' AND current_user <> 'gk_retention' THEN
                RAISE EXCEPTION '% checkpoint can be inserted only by gk_retention', TG_TABLE_NAME;
              END IF;

              NEW.occurred_at := clock_timestamp();

              RETURN NEW;
            END
            $$;

            -- audit_guard_update() compares the whole row less the four seal columns, so the
            -- checkpoint columns are envelope columns there already, immutable from the insert on.

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
                WHEN 'audit.chain.purge' THEN
                  IF NEW.deployment_wide THEN
                    RAISE EXCEPTION 'job type % is for one Tenant', NEW.type;
                  END IF;
                  IF NOT (current_user::text = ANY (ARRAY['gk_worker'])) THEN
                    RAISE EXCEPTION 'job type % can''t be enqueued by %', NEW.type, current_user;
                  END IF;
                WHEN 'audit.retention.apply' THEN
                  IF NEW.deployment_wide THEN
                    RAISE EXCEPTION 'job type % is for one Tenant', NEW.type;
                  END IF;
                  IF NOT (current_user::text = ANY (ARRAY['gk_worker'])) THEN
                    RAISE EXCEPTION 'job type % can''t be enqueued by %', NEW.type, current_user;
                  END IF;
                WHEN 'audit.retention.deployment' THEN
                  IF NOT NEW.deployment_wide THEN
                    RAISE EXCEPTION 'job type % is Deployment-wide', NEW.type;
                  END IF;
                  IF NOT (current_user::text = ANY (ARRAY['gk_worker'])) THEN
                    RAISE EXCEPTION 'job type % can''t be enqueued by %', NEW.type, current_user;
                  END IF;
                WHEN 'audit.retention.sweep' THEN
                  IF NOT NEW.deployment_wide THEN
                    RAISE EXCEPTION 'job type % is Deployment-wide', NEW.type;
                  END IF;
                  IF NOT (current_user::text = ANY (ARRAY['gk_worker'])) THEN
                    RAISE EXCEPTION 'job type % can''t be enqueued by %', NEW.type, current_user;
                  END IF;
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
