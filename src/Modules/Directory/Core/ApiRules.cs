using System.Text.RegularExpressions;
using Gatekeep.Kernel.Limits;
using Gatekeep.Modules.Directory.Contracts;

namespace Gatekeep.Modules.Directory.Core;

/// <summary>
/// The rules of an API and its Permissions (Story 3.6, FR-16). The tables' CHECKs hold only the same lengths, the same
/// Permission pattern, and that the built-in API, and no other, has exactly <c>urn:gatekeep:management</c> as its
/// identifier. The rest is held here only: an identifier's URI shape, white space and fragment, and the reserved
/// <c>urn:gatekeep:</c> prefix, which no CHECK refuses for any other identifier under it.
/// </summary>
internal static partial class ApiRules
{
    /// <summary>The prefix only the built-in Management API's identifier has: any other under it is reserved.</summary>
    public const string ReservedPrefix = "urn:gatekeep:";

    /// <summary>A Permission value, <c>resource:action</c>: lowercase, each part 1 to 64 characters. The table checks the same.</summary>
    public const string PermissionPattern = "^[a-z0-9][a-z0-9_.-]{0,63}:[a-z0-9][a-z0-9_.-]{0,63}$";

    /// <summary>Every problem with a create's <paramref name="name"/>, already trimmed, and <paramref name="identifier"/>; empty when it may go ahead.</summary>
    public static IReadOnlyList<ApiFieldProblem> CheckCreate(string name, string identifier)
    {
        var problems = new List<ApiFieldProblem>();
        if (!ValidName(name))
        {
            problems.Add(new ApiFieldProblem(ApiFields.Name, ApiReasons.Invalid));
        }

        if (IdentifierReason(identifier) is { } reason)
        {
            problems.Add(new ApiFieldProblem(ApiFields.Identifier, reason));
        }

        return problems;
    }

    /// <summary>Every problem with a Permission's <paramref name="value"/> and <paramref name="description"/>; empty when it may be added.</summary>
    public static IReadOnlyList<ApiFieldProblem> CheckPermission(string value, string description)
    {
        var problems = new List<ApiFieldProblem>();
        if (!ValidPermission(value))
        {
            problems.Add(new ApiFieldProblem(ApiFields.Value, ApiReasons.Invalid));
        }

        if (description is null || description.Length > SecurityLimits.MaxPermissionDescriptionLength || description.Any(char.IsControl))
        {
            problems.Add(new ApiFieldProblem(ApiFields.Description, ApiReasons.Invalid));
        }

        return problems;
    }

    /// <summary>Every lifetime of a settings save outside its limits: the Application's own rules (Story 3.4).</summary>
    public static IReadOnlyList<ApiFieldProblem> CheckSettings(ApiSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return [.. ApplicationLifetimeRules.Check(settings.Lifetimes).Select(p => new ApiFieldProblem(p.Field, p.Reason, p.Maximum))];
    }

    /// <summary>Whether <paramref name="value"/> is a <c>resource:action</c> Permission value.</summary>
    public static bool ValidPermission(string? value) => value is not null && PermissionRegex().IsMatch(value);

    private static bool ValidName(string? name) =>
        !string.IsNullOrEmpty(name)
        && name.Length <= SecurityLimits.MaxApiNameLength
        && !name.Any(char.IsControl)
        && name.Trim().Length == name.Length;

    /// <summary>
    /// Why <paramref name="identifier"/> is refused, or null: 1 to 255 characters, no white space or control
    /// character, an absolute URI with a scheme and no fragment, and not under <see cref="ReservedPrefix"/>. It is
    /// matched exactly, so it isn't normalized.
    /// </summary>
    private static string? IdentifierReason(string? identifier)
    {
        if (string.IsNullOrEmpty(identifier)
            || identifier.Length > SecurityLimits.MaxApiIdentifierLength
            || identifier.Any(c => char.IsWhiteSpace(c) || char.IsControl(c))
            || identifier.Contains('#')
            || !SchemeRegex().IsMatch(identifier)
            || !Uri.TryCreate(identifier, UriKind.Absolute, out _))
        {
            return ApiReasons.Invalid;
        }

        return identifier.StartsWith(ReservedPrefix, StringComparison.OrdinalIgnoreCase) ? ApiReasons.Reserved : null;
    }

    // .NET's $ also matches before a final newline: \z doesn't.
    [GeneratedRegex(@"\A[a-z0-9][a-z0-9_.-]{0,63}:[a-z0-9][a-z0-9_.-]{0,63}\z", RegexOptions.CultureInvariant)]
    private static partial Regex PermissionRegex();

    // RFC 3986's scheme, then its colon and something after it.
    [GeneratedRegex("^[A-Za-z][A-Za-z0-9+.-]*:.", RegexOptions.CultureInvariant)]
    private static partial Regex SchemeRegex();
}
