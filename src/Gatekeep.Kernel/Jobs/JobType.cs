using System.Text.RegularExpressions;

namespace Gatekeep.Kernel.Jobs;

/// <summary>
/// A job type code, <c>{domain}.{object}.{action}</c> like an audit type code (AD-15, AD-16).
/// The Operations registry decides what each code may do; this only checks its shape.
/// </summary>
public sealed partial record JobType
{
    private const int MaxLength = 128;

    public JobType(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (value.Length > MaxLength || !Pattern().IsMatch(value))
        {
            throw new ArgumentException(
                "A job type code is {domain}.{object}.{action}, at most 128 characters.",
                nameof(value));
        }

        Value = value;
    }

    public string Value { get; }

    public override string ToString() => Value;

    [GeneratedRegex(@"\A[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\z")]
    private static partial Regex Pattern();
}
