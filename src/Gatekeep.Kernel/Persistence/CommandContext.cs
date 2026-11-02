using System.Data.Common;

namespace Gatekeep.Kernel.Persistence;

/// <summary>
/// What a state-changing contract method receives. It can run commands in the
/// caller's transaction, but it can't open a scope or end the transaction: only
/// the <see cref="CommandScope"/> holder commits.
/// </summary>
public sealed class CommandContext
{
    private readonly CommandScope _scope;

    internal CommandContext(CommandScope scope) => _scope = scope;

    /// <summary>The Tenant of a <see cref="TenantScope"/>. Null in a <see cref="DeploymentScope"/>.</summary>
    public Guid? TenantId => _scope.ContextTenantId;

    /// <summary>Creates a command enlisted in the scope's transaction.</summary>
    public DbCommand CreateCommand() => _scope.CreateEnlistedCommand();
}
