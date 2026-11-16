using System.Globalization;
using Gatekeep.Kernel.Limits;
using Gatekeep.Modules.Directory.Contracts;

namespace Gatekeep.Modules.Directory.Core;

/// <summary>
/// A database Connection's password policy rules (Story 4.6, FR-18): the minimum length from
/// <see cref="SecurityLimits.PasswordMinimumLengthFloor"/> to <see cref="SecurityLimits.PasswordMinimumLengthCeiling"/>, a
/// strength of <see cref="PasswordStrengths"/>, a history count from 0 to <see cref="SecurityLimits.PasswordHistoryMaximum"/>,
/// and both switches given. The table's CHECKs hold the same bounds.
/// </summary>
internal static class PasswordPolicyRules
{
    /// <summary>The floor's refusal, word for word as FR-18 states it.</summary>
    public static readonly string MinimumText = string.Create(
        CultureInfo.InvariantCulture, $"Minimum is {SecurityLimits.PasswordMinimumLengthFloor} characters.");

    private static readonly string MaximumText = string.Create(
        CultureInfo.InvariantCulture, $"Maximum is {SecurityLimits.PasswordMinimumLengthCeiling} characters.");

    private const string StrengthText = "Choose Good or Excellent.";

    private static readonly string HistoryText = string.Create(
        CultureInfo.InvariantCulture, $"Choose 0 to {SecurityLimits.PasswordHistoryMaximum} passwords.");

    private const string RequiredText = "Required.";

    /// <summary>Every refused field of <paramref name="input"/>, in the fields' order; empty when it may be saved.</summary>
    public static IReadOnlyList<PasswordPolicyProblem> Check(PasswordPolicyInput input, out PasswordPolicy? policy)
    {
        ArgumentNullException.ThrowIfNull(input);
        var problems = new List<PasswordPolicyProblem>();

        switch (input.MinLength)
        {
            case null:
                problems.Add(new(PasswordPolicyFields.MinLength, PasswordPolicyReasons.Required, RequiredText));
                break;
            case < SecurityLimits.PasswordMinimumLengthFloor:
                problems.Add(new(PasswordPolicyFields.MinLength, PasswordPolicyReasons.BelowMinimum, MinimumText));
                break;
            case > SecurityLimits.PasswordMinimumLengthCeiling:
                problems.Add(new(PasswordPolicyFields.MinLength, PasswordPolicyReasons.AboveMaximum, MaximumText));
                break;
        }

        if (input.Strength is null)
        {
            problems.Add(new(PasswordPolicyFields.Strength, PasswordPolicyReasons.Required, StrengthText));
        }
        else if (!PasswordStrengths.All.Contains(input.Strength, StringComparer.Ordinal))
        {
            problems.Add(new(PasswordPolicyFields.Strength, PasswordPolicyReasons.Invalid, StrengthText));
        }

        switch (input.HistoryCount)
        {
            case null:
                problems.Add(new(PasswordPolicyFields.HistoryCount, PasswordPolicyReasons.Required, HistoryText));
                break;
            case < 0:
                problems.Add(new(PasswordPolicyFields.HistoryCount, PasswordPolicyReasons.BelowMinimum, HistoryText));
                break;
            case > SecurityLimits.PasswordHistoryMaximum:
                problems.Add(new(PasswordPolicyFields.HistoryCount, PasswordPolicyReasons.AboveMaximum, HistoryText));
                break;
        }

        if (input.Dictionary is null)
        {
            problems.Add(new(PasswordPolicyFields.Dictionary, PasswordPolicyReasons.Required, RequiredText));
        }

        if (input.PersonalData is null)
        {
            problems.Add(new(PasswordPolicyFields.PersonalData, PasswordPolicyReasons.Required, RequiredText));
        }

        policy = problems.Count == 0
            ? new PasswordPolicy(input.MinLength!.Value, input.Strength!, input.HistoryCount!.Value, input.Dictionary!.Value, input.PersonalData!.Value)
            : null;
        return problems;
    }

    /// <summary>Whether <paramref name="policy"/> breaks no rule: what the store holds to before it writes.</summary>
    public static bool Valid(PasswordPolicy policy) =>
        Check(new PasswordPolicyInput(policy.MinLength, policy.Strength, policy.HistoryCount, policy.Dictionary, policy.PersonalData), out _).Count == 0;
}
