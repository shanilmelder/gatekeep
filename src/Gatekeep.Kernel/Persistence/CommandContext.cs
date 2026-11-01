using System.Data.Common;

namespace Gatekeep.Kernel.Persistence;

/// <summary>
/// What a state-changing contract method receives. It can run commands in the
/// caller's transaction, but it can't open a scope or end the transaction: only
/// the <see cref="TenantScope"/> holder commits.
/// </summary>
public sealed class CommandContext
{
    private readonly TenantScope _scope;

    internal CommandContext(TenantScope scope) => _scope = scope;

    public Guid TenantId => _scope.TenantId;

    /// <summary>Creates a command enlisted in the scope's transaction.</summary>
    public DbCommand CreateCommand() => _scope.CreateEnlistedCommand();
}
