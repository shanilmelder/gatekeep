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

    /// <summary>A grant's Permissions (Story 3.7): each error names the value's 0-based index in the list sent.</summary>
    public const string Permissions = "permissions";

    public static readonly IReadOnlyList<string> All = [Name, Identifier, Value, Description, Permissions];
}

/// <summary>Why an API or Permission field is refused (Story 3.6), as the Admin API spells it.</summary>
public static class ApiReasons
{
    /// <summary>Malformed: empty, too long, or not the field's shape.</summary>
    public const string Invalid = "invalid";

    /// <summary>An identifier under <c>urn:gatekeep:</c>, which only the built-in Management API uses.</summary>
    public const string Reserved = "reserved";

    /// <summary>A grant's Permission value the list already holds at an earlier index (Story 3.7).</summary>
    public const string Duplicate = "duplicate";

    /// <summary>A grant's Permission value the API has no Permission by (Story 3.7).</summary>
    public const string Unknown = "unknown";

    /// <summary>A grant's Permissions list holding more values than an API can have Permissions (Story 3.7).</summary>
    public const string TooMany = "too_many";

    public static readonly IReadOnlyList<string> All = [Invalid, Reserved, Duplicate, Unknown, TooMany];
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

/// <summary>
/// An API as the protocol endpoints resolve it by its identifier (Story 3.7, RFC 8707): what a token for it needs, and
/// nothing more. <paramref name="BuiltIn"/> marks the Tenant's Management API, which <c>Host.Hosted</c> refuses (AD-33);
/// <paramref name="OfflineAccess"/> says whether a refresh token may be issued for it; a token for it lives the shorter of
/// its <paramref name="Lifetimes"/> and its Application's (FR-15).
/// </summary>
public sealed record DirectoryApiTarget(Guid Id, string Identifier, bool BuiltIn, bool OfflineAccess, ApplicationLifetimes Lifetimes);

/// <summary>
/// One machine-to-machine Application's grant on an API (Story 3.7, FR-16): the Application, its name, and the values of
/// the API's Permissions it holds, in ordinal order. An Application with no value holds no grant.
/// </summary>
public sealed record DirectoryApiGrant(Guid ApplicationId, string ApplicationName, IReadOnlyList<string> Permissions);

/// <summary>How a grant write ended (Story 3.7).</summary>
public enum ApiGrantWriteStatus
{
    /// <summary>Written, with its event.</summary>
    Done,

    /// <summary>Nothing to change: the set was already that, or a removal found no grant. Nothing was written, and no event.</summary>
    Unchanged,

    /// <summary>The Tenant has no API by that ID. Nothing was written.</summary>
    NotFound,

    /// <summary>The Tenant has no visible Application by that ID: unknown, deleted or the hidden system one. Nothing was written.</summary>
    ApplicationNotFound,

    /// <summary>The API is the built-in Management API, granted only by Epic 17's Owner flow. Nothing was written.</summary>
    BuiltIn,

    /// <summary>The Application isn't a <c>machine</c> one. Nothing was written.</summary>
    NotMachine,

    /// <summary>Some value isn't a Permission of the API: <see cref="ApiGrantWrite.UnknownValues"/> names each. Nothing was written.</summary>
    UnknownPermissions,
}

/// <summary>A grant write's result (Story 3.7): its status, and for <see cref="ApiGrantWriteStatus.UnknownPermissions"/> the values the API lacks.</summary>
public sealed record ApiGrantWrite(ApiGrantWriteStatus Status, IReadOnlyList<string>? UnknownValues = null);
