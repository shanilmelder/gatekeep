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

    /// <summary>
    /// True when <paramref name="value"/>, a token or key sent in an HTTP header (Story 1.30), is
    /// unsafe or, once trimmed, holds anything but printable ASCII: whitespace inside it, a control
    /// character or a non-ASCII one. Startup and the adapters both refuse by this one rule, so a
    /// file that passes startup is never refused at the first send.
    /// </summary>
    public static bool IsUnsafeCredential(string? value) =>
        IsUnsafe(value) || value!.Trim().Any(c => c is < '!' or > '~');

    /// <summary>True when <paramref name="password"/> is unsafe or shorter than the minimum.</summary>
    public static bool IsUnsafePassword(string? password) =>
        IsUnsafe(password) || password!.Trim().Length < MinimumPasswordLength;
}
