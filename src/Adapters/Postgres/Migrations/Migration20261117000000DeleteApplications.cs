using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 3.5 (FR-11, AD-13, AD-30): an Editor or Owner deletes an Application.
/// <list type="bullet">
/// <item><c>application</c> gains <c>deleted_at</c>, null for every existing row. A set one hides the
/// Application from every read; nothing ever clears it.</item>
/// <item><c>gk_admin</c> may set it, and, for the one revocation path (<c>ISessions.RevokeAccessAsync</c>
/// with the Application scope) in the same transaction, read the columns its <c>WHERE</c> names on
/// <c>token</c> and <c>"authorization"</c> and update only their status and concurrency token. It reads no
/// subject, payload or reference, and holds nothing on <c>user</c>, <c>user_session</c> or
/// <c>signin_transaction</c>.</item>
/// <item><c>gk_worker</c>, which runs the <c>directory.application.purge</c> Operation, reads the columns
/// its Application-scoped deletes name: <c>deleted_at</c> on <c>application</c>, and the Application and
/// family references of the rows it deletes. It already deletes from every one of these tables.</item>
/// </list>
/// The <c>GK012</c> guard still refuses any edit of the <c>system</c> Application, so it is never marked deleted.
/// It changes no earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261117000000_DeleteApplications")]
public sealed class Migration20261117000000DeleteApplications : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) =>
        migrationBuilder.Sql(
            """
            ALTER TABLE application ADD COLUMN deleted_at timestamptz NULL;

            -- Host.Admin's deletion (Story 3.5): the mark, and its revocation of the Application's families and tokens.
            GRANT UPDATE (deleted_at) ON application TO gk_admin;
            GRANT SELECT (tenant_id, id, application_id, status) ON "authorization" TO gk_admin;
            GRANT UPDATE (status, concurrency_token) ON "authorization" TO gk_admin;
            GRANT SELECT (tenant_id, application_id, authorization_id, status) ON token TO gk_admin;
            GRANT UPDATE (status, concurrency_token) ON token TO gk_admin;

            -- Host.Worker's directory.application.purge: only what its WHERE clauses name.
            GRANT SELECT (deleted_at) ON application TO gk_worker;
            GRANT SELECT (application_id) ON client_secret TO gk_worker;
            GRANT SELECT (id, application_id) ON "authorization" TO gk_worker;
            GRANT SELECT (application_id, authorization_id) ON token TO gk_worker;
            GRANT SELECT (application_id) ON signin_transaction TO gk_worker;
            """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
