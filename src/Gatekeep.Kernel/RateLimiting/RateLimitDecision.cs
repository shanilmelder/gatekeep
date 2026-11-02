namespace Gatekeep.Kernel.RateLimiting;

/// <summary>
/// The outcome of one attempt. A refused attempt says how long until its subject's window ends;
/// an allowed one has <see cref="RetryAfter"/> zero.
/// </summary>
public sealed record RateLimitDecision
{
    private RateLimitDecision(bool allowed, TimeSpan retryAfter)
    {
        Allowed = allowed;
        RetryAfter = retryAfter;
    }

    public static RateLimitDecision Allow { get; } = new(true, TimeSpan.Zero);

    public bool Allowed { get; }

    public TimeSpan RetryAfter { get; }

    /// <exception cref="ArgumentOutOfRangeException"><paramref name="retryAfter"/> isn't positive.</exception>
    public static RateLimitDecision Refuse(TimeSpan retryAfter)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(retryAfter, TimeSpan.Zero);
        return new RateLimitDecision(false, retryAfter);
    }
}
