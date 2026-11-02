namespace Gatekeep.Kernel.Secrets;

/// <summary>
/// The one list of values no host accepts as a secret (AD-26). Compared trimmed and
/// case-insensitively. A password must also be at least <see cref="MinimumPasswordLength"/>
/// characters.
/// </summary>
public static class SecretDefaults
{
    public const int MinimumPasswordLength = 16;

    /// <summary>
    /// Known defaults: common placeholders, the role and product names, and every password
    /// a test in this repository has used, because those are public.
    /// </summary>
    public static readonly IReadOnlyList<string> Known =
    [
        "changeme",
        "change-me",
        "change_me",
        "password",
        "secret",
        "postgres",
        "admin",
        "root",
        "gatekeep",
        "isolation-test-only",
        "hunter2",
        "wrong-secret",
    ];

    /// <summary>True when <paramref name="value"/> is missing, blank or a known default.</summary>
    public static bool IsUnsafe(string? value) =>
        string.IsNullOrWhiteSpace(value)
        || Known.Contains(value.Trim(), StringComparer.OrdinalIgnoreCase);

    /// <summary>True when <paramref name="password"/> is unsafe or shorter than the minimum.</summary>
    public static bool IsUnsafePassword(string? password) =>
        IsUnsafe(password) || password!.Trim().Length < MinimumPasswordLength;
}
