using System.Data.Common;
using Gatekeep.Adapters.Postgres.Migrations;
using Gatekeep.Adapters.Postgres.Schema;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Gatekeep.Adapters.Postgres;

/// <summary>Thrown when the connection isn't <c>gk_migrator</c>. Nothing has been applied.</summary>
public sealed class WrongMigrationRoleException(string role)
    : Exception($"Migrations run only as {TableRegistry.Migrator}, not {role}.")
{
    public string Role { get; } = role;
}

/// <summary>Applies pending migrations as <c>gk_migrator</c>, and refuses any other role (AD-3).</summary>
public static class GatekeepMigrator
{
    public const string HistoryTable = "migration_history";

    /// <returns>The IDs of the migrations applied, which is empty when none were pending.</returns>
    public static async Task<IReadOnlyList<string>> MigrateAsync(
        string connectionString,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        var options = new DbContextOptionsBuilder<MigrationsContext>()
            .UseNpgsql(connectionString, npgsql => npgsql.MigrationsHistoryTable(HistoryTable))
            .ConfigureWarnings(warnings => warnings.Ignore(RelationalEventId.ModelSnapshotNotFound))
            .Options;

        await using var context = new MigrationsContext(options);

        // The connection stays open, so the role checked is the role that migrates.
        await context.Database.OpenConnectionAsync(cancellationToken);

        var role = await CurrentRoleAsync(context.Database.GetDbConnection(), cancellationToken);
        if (role != TableRegistry.Migrator)
        {
            throw new WrongMigrationRoleException(role);
        }

        var pending = (await context.Database.GetPendingMigrationsAsync(cancellationToken)).ToList();
        await context.Database.MigrateAsync(cancellationToken);

        return pending;
    }

    private static async Task<string> CurrentRoleAsync(DbConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT current_user";

        return (string)(await command.ExecuteScalarAsync(cancellationToken))!;
    }
}
