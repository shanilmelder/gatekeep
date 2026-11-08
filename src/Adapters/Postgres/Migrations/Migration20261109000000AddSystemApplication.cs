using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 2.8 (AD-12, AR-43): each Tenant's one hidden <c>system</c> Application, which Portal sign-in
/// binds its <c>signin_transaction</c> to, since the Portal isn't an OIDC client.
/// <list type="bullet">
/// <item><c>application.kind</c> gains <c>system</c>. A <c>system</c> row has no grant type and no audience
/// (<c>application_system_bare</c>), and a Tenant has at most one (<c>application_one_system</c>).</item>
/// <item><c>system_application_guard</c> refuses a <c>client_secret</c>, <c>"authorization"</c> or
/// <c>token</c> row naming it (<c>GK011</c>), so no secret, code or token is ever held for it, even by a
/// later store that skips Directory's filter. <c>signin_transaction</c> has no such guard: it must bind to it.</item>
/// <item><c>application_guard_update</c> refuses any update of a <c>system</c> row, or one that would make a
/// row <c>system</c> (<c>GK012</c>), and <c>application_guard_delete</c> refuses deleting one unless its
/// Tenant is <c>deleting</c> or <c>deleted</c> (<c>GK013</c>), so only the Tenant purge removes it. No role
/// may update <c>application</c> yet; both hold once Epic 3 grants edit and delete.</item>
/// <item><c>gk_worker</c>, which writes the row in Tenant creation's completion, may insert Applications and
/// read only the columns that find a Tenant's <c>system</c> row: <c>tenant_id</c>, <c>id</c> and <c>kind</c>.</item>
/// <item>Every existing <c>active</c> Tenant that has none gets one, named <c>Account Portal</c>.</item>
/// </list>
/// The triggers hold every DML by any role; a table owner or superuser can still disable triggers.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261109000000_AddSystemApplication")]
public sealed class Migration20261109000000AddSystemApplication : Migration
{
    /// <summary>
    /// The backfill, run once per Tenant with that Tenant's setting in place: the <c>system</c> Application
    /// for the Tenant only while it is <c>active</c> and has none. Its name is Directory's
    /// <c>SystemApplicationName</c>; a test holds the two equal.
    /// </summary>
    public const string Backfill =
        """
        INSERT INTO application (tenant_id, id, name, kind, created_at)
        SELECT t.id, uuidv7(), 'Account Portal', 'system', now()
        FROM tenant t
        WHERE t.id = current_setting('gatekeep.tenant_id')::uuid
          AND t.status = 'active'
          AND NOT EXISTS (SELECT 1 FROM application a WHERE a.tenant_id = t.id AND a.kind = 'system')
        """;

    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            ALTER TABLE application DROP CONSTRAINT application_kind;
            ALTER TABLE application ADD CONSTRAINT application_kind CHECK (kind IN ('machine', 'system'));

            -- The system Application grants nothing and names no API: no flow can reach it.
            ALTER TABLE application ADD CONSTRAINT application_system_bare
              CHECK (kind <> 'system' OR (grant_types = '{}' AND audiences = '{}'));

            -- Exactly one per Tenant: Tenant creation and the backfill insert one, and nothing more.
            CREATE UNIQUE INDEX application_one_system ON application (tenant_id) WHERE kind = 'system';

            -- No secret, authorization or token ever names the system Application. The read runs as the
            -- inserting role, which reads application already, and row-level security holds it to the
            -- row's own Tenant.
            CREATE FUNCTION system_application_guard() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF NEW.application_id IS NOT NULL AND EXISTS (
                   SELECT 1 FROM application
                   WHERE tenant_id = NEW.tenant_id AND id = NEW.application_id AND kind = 'system') THEN
                RAISE EXCEPTION 'no % row names a tenant''s system application', TG_TABLE_NAME USING ERRCODE = 'GK011';
              END IF;

              RETURN NEW;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION system_application_guard() FROM PUBLIC;

            CREATE TRIGGER system_application_guard BEFORE INSERT ON client_secret
              FOR EACH ROW EXECUTE FUNCTION system_application_guard();
            CREATE TRIGGER system_application_guard BEFORE INSERT ON "authorization"
              FOR EACH ROW EXECUTE FUNCTION system_application_guard();
            CREATE TRIGGER system_application_guard BEFORE INSERT ON token
              FOR EACH ROW EXECUTE FUNCTION system_application_guard();

            -- The system Application is never edited, and no other Application becomes one.
            CREATE FUNCTION application_guard_update() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF OLD.kind = 'system' OR NEW.kind = 'system' THEN
                RAISE EXCEPTION 'a tenant''s system application is never edited' USING ERRCODE = 'GK012';
              END IF;

              RETURN NEW;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION application_guard_update() FROM PUBLIC;

            CREATE TRIGGER application_guard_update BEFORE UPDATE ON application
              FOR EACH ROW EXECUTE FUNCTION application_guard_update();

            -- It goes only with its Tenant's deletion: the purge runs while the Tenant is deleting.
            CREATE FUNCTION application_guard_delete() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF OLD.kind = 'system'
                 AND NOT EXISTS (SELECT 1 FROM tenant WHERE id = OLD.tenant_id AND status IN ('deleting', 'deleted')) THEN
                RAISE EXCEPTION 'a tenant''s system application is deleted only with the tenant' USING ERRCODE = 'GK013';
              END IF;

              RETURN OLD;
            END
            $$;

            REVOKE EXECUTE ON FUNCTION application_guard_delete() FROM PUBLIC;

            CREATE TRIGGER application_guard_delete BEFORE DELETE ON application
              FOR EACH ROW EXECUTE FUNCTION application_guard_delete();

            -- Tenant creation's completion writes the system Application and finds it first: only the
            -- columns that lookup reads, never a name, grant or audience.
            GRANT INSERT ON application TO gk_worker;
            GRANT SELECT (id, kind) ON application TO gk_worker;
            """);

        // FORCE row-level security holds the migrator too, so the backfill runs one Tenant at a time.
        migrationBuilder.ForEachTenant(Backfill);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
