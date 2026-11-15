using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 4.5 (FR-36, AR-18, AD-14, AD-15): email through the job pipeline.
/// <list type="bullet">
/// <item>Identity's <c>"user"</c> gains <c>email</c>, null until Story 4.7 writes it, unique per Tenant ignoring case.
/// <c>gk_worker</c> may read a User's <c>id</c> and <c>email</c>, to resolve a recipient at send time, and nothing else of it.</item>
/// <item>Notifications' <c>email_template</c>: a Tenant's overrides of the five built-in templates, one row each at most,
/// a subject and a plain-text body. Story 15.4 writes it; <c>gk_worker</c> reads it to send and deletes it in a Tenant's
/// purge. No other role has anything.</item>
/// <item><c>gk_worker</c> counts the per-recipient email limit in <c>tenant_attempt</c>, as <c>gk_hosted</c> counts its own:
/// it may read and insert counters and update their window and count.</item>
/// <item>The job guard is re-rendered with <c>notifications.email.send</c>, for one Tenant, enqueued by <c>gk_hosted</c> and
/// <c>gk_worker</c>.</item>
/// </list>
/// It changes no earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261126000000_SendEmail")]
public sealed class Migration20261126000000SendEmail : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            -- Story 4.7 writes it. One address belongs to one User of a Tenant, whatever its case.
            ALTER TABLE "user" ADD COLUMN email text NULL CONSTRAINT user_email_length CHECK (char_length(email) BETWEEN 3 AND 254);
            CREATE UNIQUE INDEX user_email ON "user" (tenant_id, lower(email)) WHERE email IS NOT NULL;

            -- Host.Worker resolves a recipient from the User's ID when it sends: the ID and address, nothing else.
            GRANT SELECT (id, email) ON "user" TO gk_worker;

            CREATE TABLE email_template (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              template_id uuid NOT NULL CONSTRAINT email_template_id CHECK (template_id IN (
                '01930000-0000-7000-8000-0000000045e1',
                '01930000-0000-7000-8000-0000000045e2',
                '01930000-0000-7000-8000-0000000045e3',
                '01930000-0000-7000-8000-0000000045e4',
                '01930000-0000-7000-8000-0000000045e5')),
              subject text NOT NULL CONSTRAINT email_template_subject CHECK (char_length(subject) BETWEEN 1 AND 200),
              body text NOT NULL CONSTRAINT email_template_body CHECK (char_length(body) BETWEEN 1 AND 10000),
              updated_at timestamptz NOT NULL DEFAULT now(),
              PRIMARY KEY (tenant_id, template_id)
            );

            ALTER TABLE email_template ENABLE ROW LEVEL SECURITY;
            ALTER TABLE email_template FORCE ROW LEVEL SECURITY;

            CREATE POLICY email_template_permissive ON email_template
              AS PERMISSIVE FOR ALL
              USING (true)
              WITH CHECK (true);

            CREATE POLICY email_template_tenant ON email_template
              AS RESTRICTIVE FOR ALL
              USING (tenant_id = current_setting('gatekeep.tenant_id')::uuid)
              WITH CHECK (tenant_id = current_setting('gatekeep.tenant_id')::uuid);

            -- No row reaches a Tenant once its deletion has started (Story 1.29).
            CREATE TRIGGER tenant_row_guard BEFORE INSERT ON email_template
              FOR EACH ROW EXECUTE FUNCTION tenant_row_guard('creating', 'active');

            -- Host.Worker: sending, and a Tenant's purge.
            GRANT SELECT, DELETE ON email_template TO gk_worker;

            -- Host.Worker counts emails per recipient (notifications.email.recipient) as gk_hosted counts its attempts.
            GRANT SELECT, INSERT ON tenant_attempt TO gk_worker;
            GRANT UPDATE (window_start, attempts) ON tenant_attempt TO gk_worker;

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
                WHEN 'notifications.email.send' THEN
                  IF NEW.deployment_wide THEN
                    RAISE EXCEPTION 'job type % is for one Tenant', NEW.type;
                  END IF;
                  IF NOT (current_user::text = ANY (ARRAY['gk_hosted', 'gk_worker'])) THEN
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
                WHEN 'sessions.expired_state.purge' THEN
                  IF NEW.deployment_wide THEN
                    RAISE EXCEPTION 'job type % is for one Tenant', NEW.type;
                  END IF;
                  IF NOT (current_user::text = ANY (ARRAY['gk_worker'])) THEN
                    RAISE EXCEPTION 'job type % can''t be enqueued by %', NEW.type, current_user;
                  END IF;
                WHEN 'sessions.expired_state.sweep' THEN
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
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
