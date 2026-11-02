namespace Gatekeep.Kernel.Persistence;

/// <summary>
/// Commits the durable effect of a refused request (AD-5): rolls back the failed
/// scope, then runs the effect in a fresh scope of the same kind and commits it.
/// </summary>
public static class FailureContext
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Takes no cancellation token, because the caller's may already be cancelled when
    /// the request fails. The whole call has its own limit, and the effect receives it.
    /// If the rollback fails, the effect doesn't run and that failure surfaces.
    /// </summary>
    /// <exception cref="InvalidOperationException"><paramref name="failedScope"/> has already finished.</exception>
    public static async Task CommitAfterRollbackAsync(
        CommandScope failedScope,
        Func<CommandContext, CancellationToken, Task> effect)
    {
        ArgumentNullException.ThrowIfNull(failedScope);
        ArgumentNullException.ThrowIfNull(effect);

        using var limit = new CancellationTokenSource(Limit);

        await failedScope.RollBackAsync(limit.Token);

        await using var scope = await failedScope.BeginFreshAsync(limit.Token);
        await effect(scope.CreateCommandContext(), limit.Token);
        await scope.CommitAsync(limit.Token);
    }
}
