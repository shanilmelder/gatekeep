namespace Gatekeep.Tests.Isolation.Revocation;

/// <summary>How an FR-48 trigger's revocation stands.</summary>
public abstract record Fr48Trigger
{
    /// <summary>Only <see cref="CoveredBy"/> and <see cref="PendingOn"/> derive from this.</summary>
    private Fr48Trigger()
    {
    }

    /// <summary>
    /// Covered by the named test, <c>Class.Method</c>, which drives the trigger and asserts the User's
    /// Sessions and Token Families ended through <c>ISessions.RevokeAccessAsync</c>. The test carries
    /// <c>[Trait("FR-48", "&lt;trigger&gt;")]</c> naming this trigger, and isn't skipped.
    /// </summary>
    public static Fr48Trigger Covered(string test) => new CoveredBy(test);

    /// <summary>Not built yet: the backlog story, by its sprint-status id (such as <c>4-11</c>), that builds it and covers it.</summary>
    public static Fr48Trigger Pending(string story) => new PendingOn(story);

    public sealed record CoveredBy(string Test) : Fr48Trigger;

    public sealed record PendingOn(string Story) : Fr48Trigger;
}

/// <summary>
/// Story 4.10 (FR-48, AR-23, AD-13): every FR-48 trigger, each covered by a named test proving it ends
/// access through <c>ISessions.RevokeAccessAsync</c>, or pending on the story that builds it. Pending
/// entries are held to <c>sprint-status.yaml</c>: once that story is <c>done</c>, its entry must become
/// <see cref="Fr48Trigger.Covered"/>. <see cref="Fr48WalkTests"/> ties <see cref="Required"/> to FR-48's
/// "Triggers:" line in the PRD, so the list can't shrink silently.
/// </summary>
public static class Fr48TriggerRegistry
{
    /// <summary>FR-48's triggers, one per action, fixed: <see cref="Fr48WalkTests"/> fails when one is missing.</summary>
    public static readonly IReadOnlyList<string> Required =
    [
        "password reset",
        "password change",
        "Factor added",
        "Factor removed",
        "Passkey added",
        "Passkey removed",
        "Recovery Codes regenerated",
        "Recovery Code used",
        "email change",
        "User blocked",
        "User deleted",
        "Factor reset",
        "Admin revoke",
    ];

    /// <summary>Each phrase on FR-48's "Triggers:" line, exactly as the PRD writes it, and the entries it splits into.</summary>
    public static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> PrdPhrases =
        new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
        {
            ["password reset or change"] = ["password reset", "password change"],
            ["Factor or Passkey added or removed"] = ["Factor added", "Factor removed", "Passkey added", "Passkey removed"],
            ["Recovery Codes regenerated or used"] = ["Recovery Codes regenerated", "Recovery Code used"],
            ["email change"] = ["email change"],
            ["User blocked or deleted"] = ["User blocked", "User deleted"],
            ["Factor reset"] = ["Factor reset"],
            ["Admin \"revoke\""] = ["Admin revoke"],
        };

    public static readonly IReadOnlyDictionary<string, Fr48Trigger> Triggers = new Dictionary<string, Fr48Trigger>(StringComparer.Ordinal)
    {
        ["password reset"] = Fr48Trigger.Covered("PasswordResetTests.A_completed_reset_ends_every_Session_and_Token_Family_of_the_User_and_starts_none"),
        ["password change"] = Fr48Trigger.Pending("16-4"),
        ["Factor added"] = Fr48Trigger.Pending("16-5"),
        ["Factor removed"] = Fr48Trigger.Pending("16-5"),
        ["Passkey added"] = Fr48Trigger.Pending("16-5"),
        ["Passkey removed"] = Fr48Trigger.Pending("16-5"),
        ["Recovery Codes regenerated"] = Fr48Trigger.Pending("16-6"),
        ["Recovery Code used"] = Fr48Trigger.Pending("6-8"),
        ["email change"] = Fr48Trigger.Pending("16-8"),
        ["User blocked"] = Fr48Trigger.Pending("5-4"),
        ["User deleted"] = Fr48Trigger.Pending("5-5"),
        ["Factor reset"] = Fr48Trigger.Pending("6-10"),
        ["Admin revoke"] = Fr48Trigger.Pending("5-4"),
    };
}
