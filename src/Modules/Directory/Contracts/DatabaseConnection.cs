namespace Gatekeep.Modules.Directory.Contracts;

/// <summary>A database Connection's password strength levels (Story 4.6), in a fixed order. The Design Delta drops None, Low and Fair.</summary>
public static class PasswordStrengths
{
    /// <summary>The minimum length, and at least 3 of the 4 character classes: lower case, upper case, number and special.</summary>
    public const string Good = "good";

    /// <summary>As <see cref="Good"/>, and no more than 2 identical characters in a row.</summary>
    public const string Excellent = "excellent";

    public static IReadOnlyList<string> All { get; } = [Good, Excellent];
}

/// <summary>
/// A database Connection's password policy (Story 4.6, FR-18): the minimum length (12 to 64), the strength (one of
/// <see cref="PasswordStrengths"/>), how many earlier passwords may not be reused (0 to 24; 0 turns the rule off), and
/// whether dictionary words and the User's own data are refused. Story 4.7 enforces it on a password.
/// </summary>
public sealed record PasswordPolicy(int MinLength, string Strength, int HistoryCount, bool Dictionary, bool PersonalData);

/// <summary>
/// A Tenant's database Connection (Story 4.6, FR-17): its row ID, its fixed name, whether it is enabled, whether sign-up is
/// open, its password policy, and when it last changed. A Tenant has exactly one in v1.
/// </summary>
public sealed record DatabaseConnection(Guid Id, string Name, bool Enabled, bool SignupEnabled, PasswordPolicy Policy, DateTimeOffset UpdatedAt);

/// <summary>
/// A password policy save's input as the request gave it (Story 4.6): each part may be missing, and
/// <see cref="DirectoryContract.CheckPasswordPolicy"/> decides.
/// </summary>
public sealed record PasswordPolicyInput(int? MinLength, string? Strength, int? HistoryCount, bool? Dictionary, bool? PersonalData);

/// <summary>The fields a password policy save's errors name (Story 4.6): the request's own member names.</summary>
public static class PasswordPolicyFields
{
    public const string MinLength = "minLength";
    public const string Strength = "strength";
    public const string HistoryCount = "historyCount";
    public const string Dictionary = "dictionary";
    public const string PersonalData = "personalData";

    public static IReadOnlyList<string> All { get; } = [MinLength, Strength, HistoryCount, Dictionary, PersonalData];
}

/// <summary>The reasons a password policy save's errors give (Story 4.6).</summary>
public static class PasswordPolicyReasons
{
    /// <summary>Absent, or null.</summary>
    public const string Required = "required";

    /// <summary>Not one of the allowed values.</summary>
    public const string Invalid = "invalid";

    /// <summary>Below the field's lowest value, such as a minimum length under 12.</summary>
    public const string BelowMinimum = "below_minimum";

    /// <summary>Above the field's highest value.</summary>
    public const string AboveMaximum = "above_maximum";

    public static IReadOnlyList<string> All { get; } = [Required, Invalid, BelowMinimum, AboveMaximum];
}

/// <summary>
/// One refused field of a password policy save (Story 4.6): its name, why, and the rule's text a client shows as it is,
/// such as "Minimum is 12 characters.". Never its value.
/// </summary>
public sealed record PasswordPolicyProblem(string Field, string Reason, string Detail);

/// <summary>How a database Connection save ended (Story 4.6).</summary>
public enum ConnectionWriteStatus
{
    /// <summary>Written, with its one event.</summary>
    Saved,

    /// <summary>The save held what is stored already: nothing written, no event.</summary>
    Unchanged,

    /// <summary>The Tenant has no database Connection. Nothing written.</summary>
    NotFound,
}

/// <summary>A database Connection save's result: its status, and the Connection as it now stands unless none was found.</summary>
public sealed record ConnectionWrite(ConnectionWriteStatus Status, DatabaseConnection? Connection);
