using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 1.28: a Tenant Owner changes a Tenant's environment label (FR-7).
/// <list type="bullet">
/// <item><c>gk_admin</c> may update <c>tenant.label</c>, and no other <c>tenant</c> column.
/// <c>gk_worker</c> keeps <c>UPDATE (status)</c> only.</item>
/// <item><c>tenant_guard_update</c> keeps every Story 1.27 rule and adds one: a label changes only
/// while the Tenant is <c>active</c>, so a <c>creating</c> Tenant keeps the label it was created
/// with, whoever runs the update.</item>
/// </list>
/// The trigger holds every DML by any role; a table owner or superuser can still disable triggers.
/// Each refusal a caller can meet in normal use raises its own SQLSTATE, mapped to a refusal by the
/// code: <c>GK002</c> a host, <c>GK003</c> a Tenant's insert, <c>GK004</c> a role, <c>GK005</c> an
/// activation without settings and <c>GK006</c> a label change on a Tenant that isn't active.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261104030000_ChangeTenantLabels")]
public sealed class Migration20261104030000ChangeTenantLabels : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            -- What was derived from the Tenant Subdomain is stored once and never changes, a Tenant
            -- only ever becomes active, once its settings exist, and its label changes only while
            -- it is active.
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
                IF NOT (OLD.status = 'creating' AND NEW.status = 'active') THEN
                  RAISE EXCEPTION 'a tenant''s status only goes from creating to active';
                END IF;

                IF NOT EXISTS (SELECT 1 FROM tenant_settings WHERE tenant_id = NEW.id) THEN
                  RAISE EXCEPTION 'a tenant becomes active only once its settings exist' USING ERRCODE = 'GK005';
                END IF;
              END IF;

              IF NEW.label IS DISTINCT FROM OLD.label AND OLD.status IS DISTINCT FROM 'active' THEN
                RAISE EXCEPTION 'a tenant''s label changes only while it is active' USING ERRCODE = 'GK006';
              END IF;

              RETURN NEW;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION tenant_guard_update() FROM PUBLIC;

            -- A Tenant Owner's label change (FR-7), and nothing else of the Tenant.
            GRANT UPDATE (label) ON tenant TO gk_admin;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
