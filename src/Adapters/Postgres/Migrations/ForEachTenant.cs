using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Data migrations run one Tenant at a time, because <c>FORCE</c> row-level security
/// applies to <c>gk_migrator</c> too (AD-3).
/// </summary>
public static class TenantDataMigration
{
    private const string ReservedQuotePrefix = "$gatekeep_";
    private const string Quote = "$gatekeep_statement$";

    /// <summary>
    /// Runs one SQL statement once per Tenant, with that Tenant's setting in place. It
    /// shares the migration's transaction, so a failure rolls the whole migration back.
    /// </summary>
    public static void ForEachTenant(this MigrationBuilder migrationBuilder, string statement)
    {
        ArgumentNullException.ThrowIfNull(migrationBuilder);
        ArgumentException.ThrowIfNullOrWhiteSpace(statement);

        if (statement.Contains(ReservedQuotePrefix, StringComparison.Ordinal))
        {
            throw new ArgumentException($"A statement can't contain {ReservedQuotePrefix}.", nameof(statement));
        }

        migrationBuilder.Sql(
            $"""
            DO $gatekeep_block$
            DECLARE
              tenant_row record;
            BEGIN
              FOR tenant_row IN SELECT id FROM tenant ORDER BY id LOOP
                PERFORM set_config('gatekeep.tenant_id', tenant_row.id::text, true);
                EXECUTE {Quote}{statement}{Quote};
              END LOOP;
              PERFORM set_config('gatekeep.tenant_id', '', true);
            END
            $gatekeep_block$;
            """);
    }
}
