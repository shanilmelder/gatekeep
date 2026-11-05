namespace Gatekeep.Kernel.Persistence;

/// <summary>
/// One module's Tenant purge (Story 1.29, AD-30): what Tenant deletion calls for each module that
/// owns <c>tenant</c> tables, but Audit, whose chain outlives the Tenant until its retention ends.
/// It deletes every row of the module's own <c>tenant</c> tables for <see cref="CommandContext.TenantId"/>,
/// children before parents, each statement naming <c>tenant_id</c> as well as relying on row-level
/// security, and nothing of any other module or Tenant (AD-1, AD-4). It is idempotent: a second call
/// deletes nothing and succeeds. It writes no audit event: the deletion's completion records it.
/// </summary>
public interface ITenantPurge
{
    /// <exception cref="InvalidOperationException">The context is a Deployment one.</exception>
    [StateChanging]
    Task PurgeAsync(CommandContext context, CancellationToken cancellationToken);
}
