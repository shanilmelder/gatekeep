using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// AD-16 seal columns: <c>epoch</c> joins <c>seq</c>, <c>prev_hash</c> and <c>hash</c>, set only
/// by <c>gk_sealer</c> and only once. The guards are replaced so <c>epoch</c> is a seal column too.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261102070000_SealAuditChains")]
public sealed class Migration20261102070000SealAuditChains : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            ALTER TABLE audit_event ADD COLUMN epoch bigint;
            ALTER TABLE deployment_audit_event ADD COLUMN epoch bigint;

            -- A seal is all four columns or none. The genesis row alone has no previous hash.
            ALTER TABLE audit_event
              ADD CONSTRAINT audit_event_seal_epoch CHECK ((seq IS NULL) = (epoch IS NULL)),
              ADD CONSTRAINT audit_event_seal_chain
                CHECK (seq IS NULL OR (seq >= 1 AND epoch >= 1 AND (seq = 1) = (prev_hash IS NULL)));

            ALTER TABLE deployment_audit_event
              ADD CONSTRAINT deployment_audit_event_seal_epoch CHECK ((seq IS NULL) = (epoch IS NULL)),
              ADD CONSTRAINT deployment_audit_event_seal_chain
                CHECK (seq IS NULL OR (seq >= 1 AND epoch >= 1 AND (seq = 1) = (prev_hash IS NULL)));

            -- The sealer reads unsealed rows in ID order.
            CREATE INDEX audit_event_unsealed ON audit_event (tenant_id, id) WHERE seq IS NULL;
            CREATE INDEX deployment_audit_event_unsealed ON deployment_audit_event (id) WHERE seq IS NULL;

            CREATE OR REPLACE FUNCTION audit_guard_insert() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF NEW.seq IS NOT NULL OR NEW.prev_hash IS NOT NULL OR NEW.hash IS NOT NULL OR NEW.epoch IS NOT NULL THEN
                RAISE EXCEPTION '% row can''t be inserted with a seal', TG_TABLE_NAME;
              END IF;

              NEW.occurred_at := clock_timestamp();

              RETURN NEW;
            END
            $$;

            -- The role check comes first: detail tables share this function and have no seal
            -- columns, and no role but the owner reaches their update at all.
            CREATE OR REPLACE FUNCTION audit_guard_update() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF current_user <> 'gk_sealer' THEN
                RAISE EXCEPTION '% rows can be changed only by gk_sealer', TG_TABLE_NAME;
              END IF;

              IF OLD.seq IS NOT NULL OR OLD.prev_hash IS NOT NULL OR OLD.hash IS NOT NULL OR OLD.epoch IS NOT NULL THEN
                RAISE EXCEPTION '% row is already sealed', TG_TABLE_NAME;
              END IF;

              IF (to_jsonb(NEW) - ARRAY['epoch', 'seq', 'prev_hash', 'hash'])
                 IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['epoch', 'seq', 'prev_hash', 'hash']) THEN
                RAISE EXCEPTION '% envelope is immutable', TG_TABLE_NAME;
              END IF;

              RETURN NEW;
            END
            $$;

            GRANT UPDATE (epoch) ON audit_event TO gk_sealer;
            GRANT UPDATE (epoch) ON deployment_audit_event TO gk_sealer;

            -- The seal loop lists the Tenant chains, so it reads the IDs only.
            GRANT SELECT (id) ON tenant TO gk_sealer;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
