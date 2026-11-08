using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 7.4: a Tenant's Log search filters indexed envelope columns only (AD-16). Each index
/// leads with <c>tenant_id</c>, as every read runs in the path Tenant's scope, and the newest-first
/// filters end in <c>id DESC</c>, the order a page is read in. The primary key already serves the
/// unfiltered list. An email resolves to User references through <c>audit_detail (tenant_id, email)</c>.
/// No column, constraint, grant or guard changes: the envelope and its hash are untouched.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261106000000_AuditSearchIndexes")]
public sealed class Migration20261106000000AuditSearchIndexes : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            CREATE INDEX audit_event_search_type ON audit_event (tenant_id, type_code, id DESC);
            CREATE INDEX audit_event_search_actor ON audit_event (tenant_id, actor_kind, actor_id, id DESC);
            CREATE INDEX audit_event_search_target ON audit_event (tenant_id, target_kind, target_id, id DESC);
            CREATE INDEX audit_event_search_time ON audit_event (tenant_id, occurred_at DESC);
            CREATE INDEX audit_detail_search_email ON audit_detail (tenant_id, email);
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
