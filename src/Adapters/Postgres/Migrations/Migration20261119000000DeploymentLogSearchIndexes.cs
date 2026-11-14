using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 7.7: the Deployment Log search filters indexed envelope columns only (AD-16), as Story
/// 7.4's Tenant search does. The Deployment Log is one chain, so no index leads with a Tenant; the
/// newest-first filters end in <c>id DESC</c>, the order a page is read in, and the primary key
/// already serves the unfiltered list. No column, constraint, grant or guard changes: the envelope
/// and its hash are untouched.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261119000000_DeploymentLogSearchIndexes")]
public sealed class Migration20261119000000DeploymentLogSearchIndexes : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            CREATE INDEX deployment_audit_event_search_type ON deployment_audit_event (type_code, id DESC);
            CREATE INDEX deployment_audit_event_search_actor ON deployment_audit_event (actor_kind, actor_id, id DESC);
            CREATE INDEX deployment_audit_event_search_target ON deployment_audit_event (target_kind, target_id, id DESC);
            CREATE INDEX deployment_audit_event_search_time ON deployment_audit_event (occurred_at DESC);
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
