using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 9.3: a Tenant Owner revokes one of the Tenant's Signing Keys (FR-38).
/// <list type="bullet">
/// <item><c>signing_key_destroyed_at</c> now allows <c>destroyed_at</c> on a <c>revoked</c> row as well as a
/// <c>retired</c> one: a revoked key's private material is destroyed by the same Host.Worker job. A
/// <c>next</c>, <c>current</c> or <c>previous</c> row still can't be destroyed.</item>
/// <item>The job guard is re-rendered: <c>keys.signing_key.destroy</c> may now be enqueued by <c>gk_admin</c>
/// too, so a revoked row and its destruction commit together. The job still runs as <c>gk_worker</c>.</item>
/// <item><c>gk_admin</c> may read <c>user_session</c>'s <c>tenant_id</c> and <c>ended_at</c> and change its
/// <c>ended_at</c> and <c>end_reason</c>, and nothing else: what the one revocation path's Tenant-scope
/// statement needs, for a revocation that also ends every Session of the Tenant.</item>
/// </list>
/// <c>gk_admin</c>'s <c>signing_key</c> grants don't change: Story 9.2's column grant on <c>state</c> already
/// lets it set <c>revoked</c>, which <c>signing_key_guard_update</c> allows from any state but <c>retired</c>.
/// It changes no earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261120000000_RevokeSigningKeys")]
public sealed class Migration20261120000000RevokeSigningKeys : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            -- Only a retired or revoked key's Transit key is destroyed.
            ALTER TABLE signing_key
              DROP CONSTRAINT signing_key_destroyed_at,
              ADD CONSTRAINT signing_key_destroyed_at CHECK (destroyed_at IS NULL OR state IN ('retired', 'revoked'));

            -- A revocation that also ends the Tenant's Sessions (Story 9.3), through the one revocation path.
            GRANT SELECT (tenant_id, ended_at) ON user_session TO gk_admin;
            GRANT UPDATE (ended_at, end_reason) ON user_session TO gk_admin;

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
                WHEN 'keys.signing_key.destroy' THEN
                  IF NEW.deployment_wide THEN
                    RAISE EXCEPTION 'job type % is for one Tenant', NEW.type;
                  END IF;
                  IF NOT (current_user::text = ANY (ARRAY['gk_admin', 'gk_worker'])) THEN
                    RAISE EXCEPTION 'job type % can''t be enqueued by %', NEW.type, current_user;
                  END IF;
                WHEN 'keys.signing_keys.rotate' THEN
                  IF NOT NEW.deployment_wide THEN
                    RAISE EXCEPTION 'job type % is Deployment-wide', NEW.type;
                  END IF;
                  IF NOT (current_user::text = ANY (ARRAY['gk_worker'])) THEN
                    RAISE EXCEPTION 'job type % can''t be enqueued by %', NEW.type, current_user;
                  END IF;
                WHEN 'keys.tenant_keys.backfill' THEN
                  IF NOT NEW.deployment_wide THEN
                    RAISE EXCEPTION 'job type % is Deployment-wide', NEW.type;
                  END IF;
                  IF NOT (current_user::text = ANY (ARRAY['gk_worker'])) THEN
                    RAISE EXCEPTION 'job type % can''t be enqueued by %', NEW.type, current_user;
                  END IF;
                WHEN 'keys.transit_keys.sweep' THEN
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
