using Gatekeep.Kernel.Identifiers;

namespace Gatekeep.Modules.Directory.Contracts;

/// <summary>
/// One <c>api</c> row (Story 3.6, FR-16): a resource server a Tenant's tokens are for. Its <paramref name="Identifier"/>
/// is the audience a token will name (Story 3.7), set at creation and never changed. <paramref name="BuiltIn"/> marks
/// the Tenant's one Gatekeep Management API, whose identifier and Permissions are fixed. Its four token lifetimes
/// have the Application's rules and defaults; a token for it lives the shorter of the two (FR-15).
/// </summary>
public sealed record DirectoryApi(
    Guid Id,
    string Name,
    string Identifier,
    bool BuiltIn,
    bool OfflineAccess,
    bool Rbac,
    ApplicationLifetimes Lifetimes,
    DateTimeOffset CreatedAt)
{
    /// <summary>Its public ID: <c>api_</c> and 26 base32 characters.</summary>
    public string PublicId => Gatekeep.Kernel.Identifiers.PublicId.Format(PublicIdType.Api, Id);
}

/// <summary>One of an API's Permissions (Story 3.6): its <c>resource:action</c> value, unique in the API, and its description, possibly empty.</summary>
public sealed record DirectoryPermission(string Value, string Description, DateTimeOffset CreatedAt);

/// <summary>
/// One page of a Tenant's APIs (Story 3.6): the built-in Management API first, then the others newest first, and the
/// ID to pass as the next page's <c>after</c> when another page follows, else null.
/// </summary>
public sealed record DirectoryApiPage(IReadOnlyList<DirectoryApi> Apis, Guid? NextAfter);

/// <summary>An API's settings as a save sends them (Story 3.6): offline access, RBAC and its four token lifetimes. A full replace.</summary>
public sealed record ApiSettings(bool OfflineAccess, bool Rbac, ApplicationLifetimes Lifetimes);

/// <summary>An API settings save's result (Story 3.6): the API as it now stands, and whether anything changed.</summary>
public sealed record ApiSettingsWrite(DirectoryApi Api, bool Changed);

/// <summary>
/// One problem with an API or Permission write (Story 3.6): the <paramref name="Field"/> it is in (one of
/// <see cref="ApiFields"/>, or for a lifetime one of <see cref="ApplicationLifetimeFields"/>), the
/// <paramref name="Reason"/> (one of <see cref="ApiReasons"/> or <see cref="ApplicationLifetimeReasons"/>), and for
/// <see cref="ApplicationLifetimeReasons.AboveMaximum"/> the field's hard limit in seconds.
/// </summary>
public sealed record ApiFieldProblem(string Field, string Reason, int? Maximum = null);

/// <summary>The fields an API or Permission problem names, as the Admin API spells them (Story 3.6).</summary>
public static class ApiFields
{
    public const string Name = "name";

    public const string Identifier = "identifier";

    public const string Value = "value";

    public const string Description = "description";

    public static readonly IReadOnlyList<string> All = [Name, Identifier, Value, Description];
}

/// <summary>Why an API or Permission field is refused (Story 3.6), as the Admin API spells it.</summary>
public static class ApiReasons
{
    /// <summary>Malformed: empty, too long, or not the field's shape.</summary>
    public const string Invalid = "invalid";

    /// <summary>An identifier under <c>urn:gatekeep:</c>, which only the built-in Management API uses.</summary>
    public const string Reserved = "reserved";

    public static readonly IReadOnlyList<string> All = [Invalid, Reserved];
}

/// <summary>How an API create ended (Story 3.6).</summary>
public enum ApiCreateStatus
{
    /// <summary>Written, with its event.</summary>
    Created,

    /// <summary>Another API of the Tenant has that identifier, exactly. Nothing was written.</summary>
    IdentifierTaken,
}

/// <summary>An API create's result: the API when <see cref="Status"/> is <see cref="ApiCreateStatus.Created"/>.</summary>
public sealed record ApiCreate(ApiCreateStatus Status, DirectoryApi? Api = null);

/// <summary>How a Permission add or removal ended (Story 3.6).</summary>
public enum PermissionWriteStatus
{
    /// <summary>Written, with its event.</summary>
    Done,

    /// <summary>The Tenant has no API by that ID, or for a removal the API has no Permission by that value. Nothing was written.</summary>
    NotFound,

    /// <summary>The API is the built-in Management API, whose Permissions are fixed. Nothing was written.</summary>
    BuiltIn,

    /// <summary>The API already has a Permission by that value. Nothing was written.</summary>
    Taken,

    /// <summary>The API already holds <see cref="Gatekeep.Kernel.Limits.SecurityLimits.MaxPermissionsPerApi"/> Permissions. Nothing was written.</summary>
    LimitReached,
}

/// <summary>A Permission write's result (Story 3.6): its status, and the API's Permissions after it when done.</summary>
public sealed record PermissionWrite(PermissionWriteStatus Status, IReadOnlyList<DirectoryPermission>? Permissions = null);
