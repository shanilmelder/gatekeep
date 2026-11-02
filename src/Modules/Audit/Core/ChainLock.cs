using System.Data.Common;
using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Audit.Core;

/// <summary>
/// The one lock every writer of a chain's seal or range takes: the sealer and retention.
/// Transaction-level, so it ends with the caller's transaction. Writers that only append
/// never take it.
/// </summary>
internal static class ChainLock
{
    /// <summary>The first key of every chain lock, so no other advisory lock can collide with one.</summary>
    private const int LockNamespace = 0x41554454;

    public const string DeploymentChain = "deployment";

    private const string LockChain = "SELECT pg_advisory_xact_lock(@namespace, hashtext(@chain))";

    public static async Task TakeAsync(CommandContext context, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = LockChain;
        Add(command, "namespace", LockNamespace);
        Add(command, "chain", context.TenantId?.ToString("D") ?? DeploymentChain);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public static void Add(DbCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }
}
