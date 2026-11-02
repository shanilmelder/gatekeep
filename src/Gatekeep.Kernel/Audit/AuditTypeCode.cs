using System.Text.RegularExpressions;

namespace Gatekeep.Kernel.Audit;

/// <summary>A stable <c>{domain}.{object}.{action}</c> code. The audit tables check the same pattern and length.</summary>
public sealed partial record AuditTypeCode
{
    private const int MaxLength = 128;

    public AuditTypeCode(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (value.Length > MaxLength || !Pattern().IsMatch(value))
        {
            throw new ArgumentException(
                "An audit type code is {domain}.{object}.{action}, at most 128 characters.",
                nameof(value));
        }

        Value = value;
    }

    public string Value { get; }

    public override string ToString() => Value;

    [GeneratedRegex(@"\A[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\z")]
    private static partial Regex Pattern();
}
