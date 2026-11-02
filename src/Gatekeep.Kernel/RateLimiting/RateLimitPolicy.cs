using System.Text.RegularExpressions;

namespace Gatekeep.Kernel.RateLimiting;

/// <summary>
/// One limit (AD-14): a <c>{domain}.{object}.{action}</c> code like an audit type code, how many
/// attempts a subject may make, and the fixed window they're counted in.
/// </summary>
public sealed partial record RateLimitPolicy
{
    private const int MaxCodeLength = 128;

    private static readonly TimeSpan MinWindow = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan MaxWindow = TimeSpan.FromDays(365);

    public RateLimitPolicy(string code, int limit, TimeSpan window)
    {
        ArgumentNullException.ThrowIfNull(code);

        if (code.Length > MaxCodeLength || !Pattern().IsMatch(code))
        {
            throw new ArgumentException(
                "A rate limit policy code is {domain}.{object}.{action}, at most 128 characters.",
                nameof(code));
        }

        // The stored count saturates at limit + 1, which must still fit the column.
        if (limit is <= 0 or int.MaxValue)
        {
            throw new ArgumentException("A rate limit is at least 1 and below int.MaxValue.", nameof(limit));
        }

        // PostgreSQL keeps microseconds, so a shorter window would store as zero and never refuse;
        // a huge one would overflow window_start + window.
        if (window < MinWindow || window > MaxWindow)
        {
            throw new ArgumentException("A rate limit window is at least 1 second and at most 365 days.", nameof(window));
        }

        Code = code;
        Limit = limit;
        Window = window;
    }

    public string Code { get; }

    /// <summary>Attempts allowed in one window.</summary>
    public int Limit { get; }

    /// <summary>How long a window lasts from its first attempt.</summary>
    public TimeSpan Window { get; }

    public override string ToString() => Code;

    [GeneratedRegex(@"\A[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\z")]
    private static partial Regex Pattern();
}
