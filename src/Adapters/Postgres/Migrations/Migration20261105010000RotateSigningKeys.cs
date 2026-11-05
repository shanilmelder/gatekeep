using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 2.4 (FR-37, AD-11): the Signing Key lifecycle's state changes.
/// <list type="bullet">
/// <item><c>signing_key</c> gains <c>promoted_at</c>, <c>rotated_at</c>, <c>retired_at</c> and
/// <c>destroyed_at</c>. A <c>current</c> row from before this migration is taken as promoted when it
/// was created, and an existing <c>previous</c> or <c>retired</c> one rotated and retired then. CHECKs tie
/// each to its state: <c>current</c>, <c>previous</c> and <c>retired</c> have <c>promoted_at</c>, <c>previous</c> and <c>retired</c> have
/// <c>rotated_at</c>, <c>retired</c> has <c>retired_at</c>, and only <c>retired</c> has
/// <c>destroyed_at</c>.</item>
/// <item><c>gk_worker</c> may update those columns and <c>state</c>, and nothing else.</item>
/// <item><c>signing_key_guard_update</c> refuses any state change outside AD-11
/// (<c>next→current</c>, <c>current→previous</c>, <c>previous→retired</c>, any non-retired state to
/// <c>revoked</c>), any change to a row's identity, Transit key or publication, and a second write of
/// a lifecycle time.</item>
/// </list>
/// The job guard is re-rendered for <c>keys.signing_keys.rotate</c>, <c>keys.signing_key.destroy</c>
/// and <c>keys.transit_keys.sweep</c>. A table owner or superuser can still disable the trigger.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261105010000_RotateSigningKeys")]
public sealed class Migration20261105010000RotateSigningKeys : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            ALTER TABLE signing_key
              ADD COLUMN promoted_at timestamptz NULL,
              ADD COLUMN rotated_at timestamptz NULL,
              ADD COLUMN retired_at timestamptz NULL,
              ADD COLUMN destroyed_at timestamptz NULL;
            """);

        // FORCE row-level security holds the migrator too, so the backfill runs one Tenant at a time.
        // Nothing rotated before this story, so any row past next is taken as promoted, rotated and
        // retired when it was created: the constraints below then hold for every existing row.
        migrationBuilder.ForEachTenant(
            "UPDATE signing_key SET promoted_at = created_at WHERE state IN ('current', 'previous', 'retired') AND promoted_at IS NULL");
        migrationBuilder.ForEachTenant(
            "UPDATE signing_key SET rotated_at = created_at WHERE state IN ('previous', 'retired') AND rotated_at IS NULL");
        migrationBuilder.ForEachTenant(
            "UPDATE signing_key SET retired_at = created_at WHERE state = 'retired' AND retired_at IS NULL");

        migrationBuilder.Sql(
            """
            ALTER TABLE signing_key
              -- A key that has signed was promoted: a new Tenant's current at creation, any other at rotation.
              ADD CONSTRAINT signing_key_promoted_at CHECK (state NOT IN ('current', 'previous', 'retired') OR promoted_at IS NOT NULL),
              -- A replaced key keeps when it was replaced: retirement counts from then.
              ADD CONSTRAINT signing_key_rotated_at CHECK (state NOT IN ('previous', 'retired') OR rotated_at IS NOT NULL),
              ADD CONSTRAINT signing_key_retired_at CHECK (state <> 'retired' OR retired_at IS NOT NULL),
              -- Only a retired key's Transit key is destroyed.
              ADD CONSTRAINT signing_key_destroyed_at CHECK (destroyed_at IS NULL OR state = 'retired');

            CREATE FUNCTION signing_key_guard_update() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF NEW.id IS DISTINCT FROM OLD.id
                 OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
                 OR NEW.purpose IS DISTINCT FROM OLD.purpose
                 OR NEW.transit_name IS DISTINCT FROM OLD.transit_name
                 OR NEW.transit_version IS DISTINCT FROM OLD.transit_version
                 OR NEW.created_at IS DISTINCT FROM OLD.created_at
                 OR NEW.published_at IS DISTINCT FROM OLD.published_at THEN
                RAISE EXCEPTION 'a signing_key''s id, tenant_id, purpose, transit_name, transit_version, created_at and published_at never change';
              END IF;

              -- AD-11: next -> current -> previous -> retired, and any state but retired may be revoked.
              IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
                   (OLD.state = 'next' AND NEW.state = 'current')
                OR (OLD.state = 'current' AND NEW.state = 'previous')
                OR (OLD.state = 'previous' AND NEW.state = 'retired')
                OR (OLD.state <> 'retired' AND NEW.state = 'revoked')) THEN
                RAISE EXCEPTION 'a signing_key in state % can''t become %', OLD.state, NEW.state;
              END IF;

              IF (OLD.promoted_at IS NOT NULL AND NEW.promoted_at IS DISTINCT FROM OLD.promoted_at)
                 OR (OLD.rotated_at IS NOT NULL AND NEW.rotated_at IS DISTINCT FROM OLD.rotated_at)
                 OR (OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at)
                 OR (OLD.destroyed_at IS NOT NULL AND NEW.destroyed_at IS DISTINCT FROM OLD.destroyed_at) THEN
                RAISE EXCEPTION 'a signing_key''s lifecycle times are written once';
              END IF;

              RETURN NEW;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION signing_key_guard_update() FROM PUBLIC;

            CREATE TRIGGER signing_key_guard_update BEFORE UPDATE ON signing_key
              FOR EACH ROW EXECUTE FUNCTION signing_key_guard_update();

            -- Rotation, retirement and destruction (Host.Worker). Never a key's name, version or publication.
            GRANT UPDATE (state, promoted_at, rotated_at, retired_at, destroyed_at) ON signing_key TO gk_worker;

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
                  IF NOT (current_user::text = ANY (ARRAY['gk_worker'])) THEN
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
