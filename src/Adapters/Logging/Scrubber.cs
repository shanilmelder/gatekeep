using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Adapters.Logging;

/// <summary>
/// Removes credential-equivalent values from log text (AD-24). It catches the Kernel's
/// <see cref="CredentialShapes"/> and the values of sensitive names only. A value held as a
/// plain string, with an innocent name and no known shape, passes: see T-42.
/// </summary>
public static class Scrubber
{
    public const string Mask = CredentialShapes.Mask;

    public static bool IsSensitiveName(string name) => CredentialShapes.IsSensitiveName(name);

    /// <summary>Replaces the text of each <paramref name="values"/> item, then every known shape.</summary>
    public static string Scrub(string text, IEnumerable<string> values)
    {
        // Longest first, so a value that contains another isn't left in part.
        foreach (var value in values.Where(v => v.Length > 0).OrderByDescending(v => v.Length))
        {
            text = text.Replace(value, Mask, StringComparison.Ordinal);
        }

        return CredentialShapes.MaskShapes(text);
    }
}
