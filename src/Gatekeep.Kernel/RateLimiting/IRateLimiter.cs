using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Kernel.RateLimiting;

/// <summary>
/// Counts attempts per policy and subject in a fixed window (AD-14). Every attempt is counted,
/// refused ones included, in the caller's own transaction: a refused request keeps its count by
/// counting inside <see cref="FailureContext"/>. Counters live in <c>UNLOGGED</c> tables, so a
/// crash resets them, and AD-5 exempts them from audit.
/// </summary>
public interface IRateLimiter
{
    /// <summary>
    /// Counts one attempt by <paramref name="subject"/>, such as a source address or a credential
    /// handle, under <paramref name="policy"/>. The subject is stored only as its SHA-256.
    /// The counter row stays locked until the caller's transaction ends, so count in a short
    /// transaction (its own scope, or <see cref="FailureContext"/>), never around slow work such
    /// as WebAuthn verification.
    /// </summary>
    /// <exception cref="InvalidOperationException">The limiter doesn't serve the context's scope. Nothing has been written.</exception>
    /// <exception cref="ArgumentException"><paramref name="subject"/> is empty or whitespace.</exception>
    [StateChanging]
    Task<RateLimitDecision> AttemptAsync(
        CommandContext context,
        RateLimitPolicy policy,
        string subject,
        CancellationToken cancellationToken);
}
