using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 3.7 (FR-16, AD-33): the Permissions of an API granted to a machine-to-machine Application.
/// <list type="bullet">
/// <item>Directory's <c>api_grant</c>: one row per granted value, <c>(tenant_id, api_id, application_id, value)</c>. It
/// references the Permission and the Application, both <c>ON DELETE RESTRICT</c>: Directory deletes a Permission's grants
/// in the same command as the Permission, and the purges delete grants before Permissions, APIs and Applications. An
/// Application is authorized on an API when it holds at least one row. Only a <c>machine</c> Application, and never on the
/// built-in Management API, is granted: Directory decides both.</item>
/// <item><c>gk_admin</c> reads, inserts and deletes grants. <c>gk_worker</c> deletes them in a Tenant's purge and a deleted
/// Application's, reading only the columns its WHERE names.</item>
/// <item><c>gk_hosted</c> reads what resolving a token's API needs: the API by its identifier, with its offline access and
/// lifetimes, and the values granted to a client.</item>
/// </list>
/// It changes no earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261122000000_AuthorizeMachineApplications")]
public sealed class Migration20261122000000AuthorizeMachineApplications : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            CREATE TABLE api_grant (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              api_id uuid NOT NULL,
              application_id uuid NOT NULL,
              value text NOT NULL,
              PRIMARY KEY (tenant_id, api_id, application_id, value),
              FOREIGN KEY (tenant_id, api_id, value) REFERENCES permission (tenant_id, api_id, value) ON DELETE RESTRICT,
              FOREIGN KEY (tenant_id, application_id) REFERENCES application (tenant_id, id) ON DELETE RESTRICT
            );

            -- A deleted Application's purge finds its grants by Application.
            CREATE INDEX api_grant_application ON api_grant (tenant_id, application_id);

            ALTER TABLE api_grant ENABLE ROW LEVEL SECURITY;
            ALTER TABLE api_grant FORCE ROW LEVEL SECURITY;

            CREATE POLICY api_grant_permissive ON api_grant
              AS PERMISSIVE FOR ALL
              USING (true)
              WITH CHECK (true);

            CREATE POLICY api_grant_tenant ON api_grant
              AS RESTRICTIVE FOR ALL
              USING (tenant_id = current_setting('gatekeep.tenant_id')::uuid)
              WITH CHECK (tenant_id = current_setting('gatekeep.tenant_id')::uuid);

            -- No row reaches a Tenant once its deletion has started (Story 1.29).
            CREATE TRIGGER tenant_row_guard BEFORE INSERT ON api_grant
              FOR EACH ROW EXECUTE FUNCTION tenant_row_guard('creating', 'active');

            -- Host.Admin: grants are set and removed, never updated.
            GRANT SELECT, INSERT, DELETE ON api_grant TO gk_admin;

            -- Host.Worker: a Tenant's purge, and a deleted Application's, reading only the columns each WHERE names.
            GRANT DELETE ON api_grant TO gk_worker;
            GRANT SELECT (tenant_id, application_id) ON api_grant TO gk_worker;

            -- Host.Hosted: an API found by its identifier, with what a token for it needs, and the values granted to a client.
            GRANT SELECT (tenant_id, id, identifier, built_in, offline_access, access_token_lifetime, id_token_lifetime,
              refresh_token_absolute_lifetime, refresh_token_inactivity_lifetime) ON api TO gk_hosted;
            GRANT SELECT (tenant_id, api_id, value) ON permission TO gk_hosted;
            GRANT SELECT ON api_grant TO gk_hosted;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
