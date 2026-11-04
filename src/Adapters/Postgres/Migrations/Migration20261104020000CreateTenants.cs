using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 1.27: creating Tenants with permanent subdomains (FR-7, AD-6).
/// <list type="bullet">
/// <item><c>tenant</c> gains its Admin-facing name, its label, its status (<c>creating</c> until its
/// creation Operation succeeds, then <c>active</c>), and the issuer, WebAuthn RP ID and email link
/// base derived once from its Tenant Subdomain and stored. The columns are <c>NOT NULL</c> with no
/// default: no Deployment can hold a Tenant before this story, so a database that has one fails
/// here loudly rather than storing a made-up issuer.</item>
/// <item><c>tenant_guard_insert</c> makes every new Tenant <c>creating</c>. <c>tenant_guard_update</c>
/// refuses any change to a Tenant's ID, issuer, RP ID, link base or creation time, any status change
/// but <c>creating</c> to <c>active</c>, and that one while the Tenant has no <c>tenant_settings</c> row.</item>
/// <item><c>tenant_host</c> holds one host per Tenant and kind. <c>tenant_host_guard_insert</c> lets a
/// host be added only to a <c>creating</c> Tenant; <c>tenant_host_guard</c> refuses every
/// <c>UPDATE</c> and <c>DELETE</c>, and <c>tenant_host_refuse_truncate</c> every <c>TRUNCATE</c>: a
/// host is never changed, and never freed for reuse.</item>
/// <item><c>gk_worker</c> may set a Tenant's status and insert its <c>tenant_settings</c> row, the
/// creation Operation's completion; <c>gk_admin</c> may insert a <c>tenant_role</c>, and
/// <c>tenant_role_guard_insert</c> holds it to the creator's <c>owner</c> role on a <c>creating</c>
/// Tenant (Story 8.4 widens it when role grants arrive).</item>
/// </list>
/// The triggers hold every DML and <c>TRUNCATE</c> by any role; a table owner or superuser can still
/// disable triggers. Each refusal a caller can meet in normal use raises its own SQLSTATE, mapped to a
/// refusal by the code: <c>GK002</c> a host, <c>GK003</c> a Tenant's insert, <c>GK004</c> a role and
/// <c>GK005</c> an activation without settings.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261104020000_CreateTenants")]
public sealed class Migration20261104020000CreateTenants : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            ALTER TABLE tenant
              ADD COLUMN name text NOT NULL CONSTRAINT tenant_name_length CHECK (char_length(name) BETWEEN 1 AND 100),
              ADD COLUMN label text NOT NULL CONSTRAINT tenant_label CHECK (label IN ('dev', 'staging', 'prod')),
              ADD COLUMN status text NOT NULL CONSTRAINT tenant_status CHECK (status IN ('creating', 'active')),
              ADD COLUMN issuer text NOT NULL CONSTRAINT tenant_issuer_unique UNIQUE,
              ADD COLUMN rp_id text NOT NULL CONSTRAINT tenant_rp_id_unique UNIQUE,
              ADD COLUMN email_link_base text NOT NULL;

            ALTER TABLE tenant ALTER COLUMN created_at SET DEFAULT clock_timestamp();

            -- The Tenants list pages by creation time, then ID.
            CREATE INDEX tenant_created ON tenant (created_at, id);

            -- Every Tenant starts creating: only its creation Operation makes it active.
            CREATE FUNCTION tenant_guard_insert() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF NEW.status IS DISTINCT FROM 'creating' THEN
                RAISE EXCEPTION 'a tenant is inserted as creating' USING ERRCODE = 'GK003';
              END IF;

              RETURN NEW;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION tenant_guard_insert() FROM PUBLIC;

            CREATE TRIGGER tenant_guard_insert BEFORE INSERT ON tenant
              FOR EACH ROW EXECUTE FUNCTION tenant_guard_insert();

            -- What was derived from the Tenant Subdomain is stored once and never changes, and a
            -- Tenant only ever becomes active, once its settings exist.
            CREATE FUNCTION tenant_guard_update() RETURNS trigger LANGUAGE plpgsql AS $$
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

              RETURN NEW;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION tenant_guard_update() FROM PUBLIC;

            CREATE TRIGGER tenant_guard_update BEFORE UPDATE ON tenant
              FOR EACH ROW EXECUTE FUNCTION tenant_guard_update();

            -- One host of each kind per Tenant.
            ALTER TABLE tenant_host ADD CONSTRAINT tenant_host_one_per_kind UNIQUE (tenant_id, kind);

            -- A host is issued only to a Tenant being created, which has none of that kind yet.
            CREATE FUNCTION tenant_host_guard_insert() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF NOT EXISTS (SELECT 1 FROM tenant WHERE id = NEW.tenant_id AND status = 'creating')
                 OR EXISTS (SELECT 1 FROM tenant_host WHERE tenant_id = NEW.tenant_id AND kind = NEW.kind) THEN
                RAISE EXCEPTION 'a host is added only to a creating tenant with none of its kind' USING ERRCODE = 'GK002';
              END IF;

              RETURN NEW;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION tenant_host_guard_insert() FROM PUBLIC;

            CREATE TRIGGER tenant_host_guard_insert BEFORE INSERT ON tenant_host
              FOR EACH ROW EXECUTE FUNCTION tenant_host_guard_insert();

            -- A host is issued once, to one Tenant, for good: it is never changed, deleted or reused.
            CREATE FUNCTION tenant_host_guard() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              RAISE EXCEPTION 'a tenant_host row is never changed or removed';
            END
            $$;

            REVOKE EXECUTE ON FUNCTION tenant_host_guard() FROM PUBLIC;

            CREATE TRIGGER tenant_host_guard BEFORE UPDATE OR DELETE ON tenant_host
              FOR EACH ROW EXECUTE FUNCTION tenant_host_guard();

            CREATE TRIGGER tenant_host_refuse_truncate BEFORE TRUNCATE ON tenant_host
              FOR EACH STATEMENT EXECUTE FUNCTION tenant_host_guard();

            -- Host.Admin inserts only the creator's Owner role, on the Tenant it is creating (FR-7).
            -- Story 8.4 widens this when it grants roles to others.
            CREATE FUNCTION tenant_role_guard_insert() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF current_user = 'gk_admin'
                 AND (NEW.role IS DISTINCT FROM 'owner'
                      OR NOT EXISTS (SELECT 1 FROM tenant WHERE id = NEW.tenant_id AND status = 'creating')) THEN
                RAISE EXCEPTION 'gk_admin inserts only the owner role of a creating tenant' USING ERRCODE = 'GK004';
              END IF;

              RETURN NEW;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION tenant_role_guard_insert() FROM PUBLIC;

            CREATE TRIGGER tenant_role_guard_insert BEFORE INSERT ON tenant_role
              FOR EACH ROW EXECUTE FUNCTION tenant_role_guard_insert();

            -- The creation Operation's completion, in the new Tenant's own scope.
            GRANT UPDATE (status) ON tenant TO gk_worker;
            GRANT INSERT ON tenant_settings TO gk_worker;

            -- The creator becomes the new Tenant's Owner (FR-7).
            GRANT INSERT ON tenant_role TO gk_admin;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
