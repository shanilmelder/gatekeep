using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 2.3 (AD-9, AD-10, AD-11): the Keys tables, both <c>tenant</c> class under the AD-3 policy pair.
/// <list type="bullet">
/// <item><c>signing_key</c>: one row per Transit key a Tenant signs with (<c>signing</c>) or will sign
/// Management tokens with (<c>management</c>). The row is authoritative for the key's state, and
/// names its Transit key <c>sig-{tenantId}-{id}</c> or <c>mgmt-{tenantId}-{id}</c> and the version
/// its <c>kid</c> carries. At most one <c>current</c> and one <c>next</c> per Tenant and purpose.</item>
/// <item><c>protection_key_wrap</c>: the Tenant's 256-bit token protection key, only ever as the
/// Transit ciphertext <c>tpk-{tenantId}</c> wrapped it into. Never plaintext.</item>
/// </list>
/// Host.Worker creates both (the Tenant creation stage and the hourly backfill), and Host.Hosted
/// only reads them, for discovery and JWKS. No role updates or deletes a row yet: rotation is
/// Story 2.4's. The job guard is re-rendered for <c>keys.tenant_keys.backfill</c>.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261105000000_CreateSigningKeyTables")]
public sealed class Migration20261105000000CreateSigningKeyTables : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            CREATE TABLE signing_key (
              id uuid NOT NULL CONSTRAINT signing_key_id_v7 CHECK (uuid_extract_version(id) = 7),
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              purpose text NOT NULL CONSTRAINT signing_key_purpose CHECK (purpose IN ('signing', 'management')),
              state text NOT NULL CONSTRAINT signing_key_state CHECK (state IN ('next', 'current', 'previous', 'retired', 'revoked')),
              transit_name text NOT NULL,
              transit_version integer NOT NULL CONSTRAINT signing_key_transit_version CHECK (transit_version >= 1),
              created_at timestamptz NOT NULL DEFAULT now(),
              published_at timestamptz NULL,
              PRIMARY KEY (tenant_id, id),
              UNIQUE (transit_name),
              -- The AD-10 name, from the row's own Tenant and ID: a row can't point at another key.
              CONSTRAINT signing_key_transit_name CHECK (
                transit_name = CASE purpose WHEN 'signing' THEN 'sig-' ELSE 'mgmt-' END || tenant_id::text || '-' || id::text),
              -- A Management key is never published (AD-33).
              CONSTRAINT signing_key_management_unpublished CHECK (purpose <> 'management' OR published_at IS NULL),
              -- A Signing Key is published when its row commits, and Story 2.4's promotion rule counts from then.
              CONSTRAINT signing_key_signing_published CHECK (purpose <> 'signing' OR published_at IS NOT NULL)
            );

            -- AD-11: at most one current and one next per Tenant and purpose.
            CREATE UNIQUE INDEX signing_key_one_current ON signing_key (tenant_id, purpose) WHERE state = 'current';
            CREATE UNIQUE INDEX signing_key_one_next ON signing_key (tenant_id, purpose) WHERE state = 'next';

            CREATE TABLE protection_key_wrap (
              tenant_id uuid PRIMARY KEY REFERENCES tenant (id) ON DELETE RESTRICT,
              -- Transit's own ciphertext form, so a plaintext key can't be stored here by mistake.
              ciphertext text NOT NULL CONSTRAINT protection_key_wrap_ciphertext CHECK (ciphertext ~ '^vault:v[0-9]+:[A-Za-z0-9+/=]+$'),
              created_at timestamptz NOT NULL DEFAULT now()
            );

            ALTER TABLE signing_key ENABLE ROW LEVEL SECURITY;
            ALTER TABLE signing_key FORCE ROW LEVEL SECURITY;

            CREATE POLICY signing_key_permissive ON signing_key
              AS PERMISSIVE FOR ALL
              USING (true)
              WITH CHECK (true);

            CREATE POLICY signing_key_tenant ON signing_key
              AS RESTRICTIVE FOR ALL
              USING (tenant_id = current_setting('gatekeep.tenant_id')::uuid)
              WITH CHECK (tenant_id = current_setting('gatekeep.tenant_id')::uuid);

            ALTER TABLE protection_key_wrap ENABLE ROW LEVEL SECURITY;
            ALTER TABLE protection_key_wrap FORCE ROW LEVEL SECURITY;

            CREATE POLICY protection_key_wrap_permissive ON protection_key_wrap
              AS PERMISSIVE FOR ALL
              USING (true)
              WITH CHECK (true);

            CREATE POLICY protection_key_wrap_tenant ON protection_key_wrap
              AS RESTRICTIVE FOR ALL
              USING (tenant_id = current_setting('gatekeep.tenant_id')::uuid)
              WITH CHECK (tenant_id = current_setting('gatekeep.tenant_id')::uuid);

            -- Host.Hosted reads them for discovery and JWKS; Host.Worker provisions them.
            GRANT SELECT ON signing_key TO gk_hosted;
            GRANT SELECT, INSERT ON signing_key TO gk_worker;
            GRANT SELECT ON protection_key_wrap TO gk_hosted;
            GRANT SELECT, INSERT ON protection_key_wrap TO gk_worker;

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
                WHEN 'keys.tenant_keys.backfill' THEN
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
