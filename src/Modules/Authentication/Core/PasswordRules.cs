using System.Globalization;
using System.Text;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Directory.Contracts;

namespace Gatekeep.Modules.Authentication.Core;

/// <summary>
/// A database Connection's password policy, enforced on the server (Story 4.7, FR-18): each failing rule is named by its
/// stable code (<see cref="PasswordRuleCodes"/>), in a fixed order. Lengths are counted in code points. The character
/// classes are Story 4.6's: lower case (Ll), upper case (Lu), number (Nd), and special, any other character that isn't a
/// letter. The history rule compares against hashes, so it needs the hasher and runs last.
/// </summary>
internal static class PasswordRules
{
    private static readonly Lazy<HashSet<string>> CommonPasswords = new(LoadCommonPasswords);

    /// <summary>The first domain label a personal-data rule refuses: at least 4 characters, so "co" or "io" never count.</summary>
    private const int MinDomainLabelLength = 4;

    /// <summary>
    /// The rules <paramref name="password"/> fails under <paramref name="policy"/> but history's: the length, the maximum
    /// length, the classes, for Excellent the repeats, and when on, the dictionary and the personal data of
    /// <paramref name="email"/>. Empty when it passes them all.
    /// </summary>
    public static List<string> Check(string password, PasswordPolicy policy, string? email)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(policy);

        var failed = new List<string>();
        var length = CodePoints(password);
        if (length < policy.MinLength)
        {
            failed.Add(PasswordRuleCodes.Length);
        }

        if (length > SecurityLimits.PasswordMaximumLength)
        {
            failed.Add(PasswordRuleCodes.TooLong);
        }

        if (CharacterClasses(password) < 3)
        {
            failed.Add(PasswordRuleCodes.Classes);
        }

        if (string.Equals(policy.Strength, PasswordStrengths.Excellent, StringComparison.Ordinal) && HasLongRun(password))
        {
            failed.Add(PasswordRuleCodes.Repeats);
        }

        if (policy.Dictionary && CommonPasswords.Value.Contains(password.ToLowerInvariant()))
        {
            failed.Add(PasswordRuleCodes.Dictionary);
        }

        if (policy.PersonalData && ContainsPersonalData(password, email))
        {
            failed.Add(PasswordRuleCodes.PersonalData);
        }

        return failed;
    }

    /// <summary>
    /// Whether <paramref name="password"/> is one of <paramref name="history"/>, the User's newest earlier hashes, as many as
    /// the policy's history count: the history rule. Each comparison is a full Argon2id verification.
    /// </summary>
    public static async Task<bool> IsReusedAsync(Secret<string> password, IReadOnlyList<string> history)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(history);

        foreach (var hash in history)
        {
            if (await PasswordHasher.VerifyAsync(password, hash))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>How many code points <paramref name="text"/> holds; an unpaired surrogate counts as one.</summary>
    public static int CodePoints(string text)
    {
        var count = 0;
        for (var i = 0; i < text.Length; i++)
        {
            if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
            {
                i++;
            }

            count++;
        }

        return count;
    }

    /// <summary>How many of the four classes <paramref name="text"/> holds: lower case, upper case, number and special.</summary>
    public static int CharacterClasses(string text)
    {
        bool lower = false, upper = false, number = false, special = false;
        foreach (var rune in Runes(text))
        {
            switch (Rune.GetUnicodeCategory(rune))
            {
                case UnicodeCategory.LowercaseLetter:
                    lower = true;
                    break;
                case UnicodeCategory.UppercaseLetter:
                    upper = true;
                    break;
                case UnicodeCategory.DecimalDigitNumber:
                    number = true;
                    break;
                case UnicodeCategory.TitlecaseLetter or UnicodeCategory.ModifierLetter or UnicodeCategory.OtherLetter:
                    // A letter that is neither lower nor upper case counts toward no class.
                    break;
                default:
                    special = true;
                    break;
            }
        }

        return (lower ? 1 : 0) + (upper ? 1 : 0) + (number ? 1 : 0) + (special ? 1 : 0);
    }

    /// <summary>Whether <paramref name="text"/> has more than 2 identical characters in a row, counted by code point.</summary>
    public static bool HasLongRun(string text)
    {
        var runes = Runes(text).ToList();
        for (var i = 2; i < runes.Count; i++)
        {
            if (runes[i] == runes[i - 1] && runes[i] == runes[i - 2])
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Whether <paramref name="password"/> holds the email's local part, or its domain's first label of 4 or more
    /// characters, ignoring case.
    /// </summary>
    public static bool ContainsPersonalData(string password, string? email)
    {
        if (string.IsNullOrEmpty(email))
        {
            return false;
        }

        var at = email.LastIndexOf('@');
        var local = at > 0 ? email[..at] : email;
        var domain = at >= 0 ? email[(at + 1)..] : string.Empty;
        var label = domain.Split('.')[0];

        return Contains(password, local)
            || (CodePoints(label) >= MinDomainLabelLength && Contains(password, label));
    }

    private static bool Contains(string text, string part) =>
        part.Length > 0 && text.Contains(part, StringComparison.OrdinalIgnoreCase);

    /// <summary>The text's code points, an unpaired surrogate as the replacement character.</summary>
    private static IEnumerable<Rune> Runes(string text)
    {
        var index = 0;
        while (index < text.Length)
        {
            Rune.DecodeFromUtf16(text.AsSpan(index), out var rune, out var consumed);
            yield return rune;
            index += Math.Max(1, consumed);
        }
    }

    private static HashSet<string> LoadCommonPasswords()
    {
        using var stream = typeof(PasswordRules).Assembly.GetManifestResourceStream("Gatekeep.Authentication.CommonPasswords")
            ?? throw new InvalidOperationException("The common-password list isn't embedded.");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var passwords = new HashSet<string>(StringComparer.Ordinal);
        while (reader.ReadLine() is { } line)
        {
            var entry = line.Trim();
            if (entry.Length > 0)
            {
                passwords.Add(entry.ToLowerInvariant());
            }
        }

        return passwords;
    }
}
