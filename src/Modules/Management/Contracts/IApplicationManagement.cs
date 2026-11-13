using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Modules.Management.Contracts;

/// <summary>How an Applications read or create ended (Story 3.1).</summary>
public enum ApplicationStatus
{
    /// <summary>Done: the result holds the Application or the page.</summary>
    Done,

    /// <summary>The capability isn't held in the path Tenant, decided again here (AD-5).</summary>
    Forbidden,

    /// <summary>The path Tenant has no visible Application by that ID: another Tenant's and the hidden <c>system</c> one alike.</summary>
    NotFound,

    /// <summary>The name or the type is malformed. Nothing was written.</summary>
    Invalid,
}

/// <summary>
/// One Application as the Admin API shows it (Story 3.1): its ID, which is also its OAuth
/// <c>client_id</c>, its name, its stored type (<c>spa</c>, <c>web</c>, <c>native</c> or <c>machine</c>),
/// whether that type authenticates with a credential, and when it was created; from Story 3.2 its callback,
/// logout and web origin URLs as stored and its grant types, sorted. Never a secret.
/// </summary>
public sealed record ManagedApplication(
    Guid Id,
    string ClientId,
    string Name,
    string Type,
    bool CredentialRequired,
    DateTimeOffset CreatedAt,
    IReadOnlyList<string> CallbackUrls,
    IReadOnlyList<string> LogoutUrls,
    IReadOnlyList<string> WebOrigins,
    IReadOnlyList<string> GrantTypes);

/// <summary>One Application read or create's result: the Application when <see cref="Status"/> is <see cref="ApplicationStatus.Done"/>.</summary>
public sealed record ApplicationResult(ApplicationStatus Status, ManagedApplication? Application = null);

/// <summary>An Application's full settings as a save sends them (Story 3.2): every list required, the acknowledgement optional and never stored.</summary>
public sealed record ApplicationSettingsInput(
    IReadOnlyList<string> CallbackUrls,
    IReadOnlyList<string> LogoutUrls,
    IReadOnlyList<string> WebOrigins,
    IReadOnlyList<string> GrantTypes,
    bool AcknowledgeCustomScheme);

/// <summary>
/// One refused line or field of a settings save (Story 3.2): the field (<c>callbackUrls</c>, <c>logoutUrls</c>,
/// <c>webOrigins</c> or <c>grantTypes</c>), the 0-based line or null for the whole field, and the reason.
/// </summary>
public sealed record ApplicationSettingsError(string Field, int? Index, string Reason);

/// <summary>How a settings save ended (Story 3.2).</summary>
public enum ApplicationSettingsStatus
{
    /// <summary>Saved: the result holds the updated Application, and its events are written.</summary>
    Saved,

    /// <summary>The settings are what is stored: nothing written, no event, no grant used.</summary>
    Unchanged,

    /// <summary>The capability isn't held in the path Tenant, decided again here (AD-5). A machine principal never holds it.</summary>
    Forbidden,

    /// <summary>The path Tenant has no visible Application by that ID: another Tenant's and the hidden <c>system</c> one alike.</summary>
    NotFound,

    /// <summary>Some line or field breaks a rule for the type: the result names each. Nothing was written.</summary>
    Invalid,

    /// <summary>A Prod Tenant's save adds a custom-scheme URL without <c>acknowledgeCustomScheme</c>. Nothing was written.</summary>
    AcknowledgementRequired,

    /// <summary>A Prod Tenant's callbacks change and the gate found no fresh assertion: it has answered. Nothing was written.</summary>
    FreshAssertionRequired,
}

/// <summary>A settings save's result: the Application when saved or unchanged, the errors when invalid.</summary>
public sealed record ApplicationSettingsResult(
    ApplicationSettingsStatus Status,
    ManagedApplication? Application = null,
    IReadOnlyList<ApplicationSettingsError>? Errors = null);

/// <summary>A page of Applications when <see cref="Status"/> is <see cref="ApplicationStatus.Done"/>, newest first, and the next page's cursor.</summary>
public sealed record ApplicationPageResult(ApplicationStatus Status, IReadOnlyList<ManagedApplication> Applications, Guid? NextAfter);

/// <summary>
/// One live client secret of an Application as the Admin API shows it (Story 3.3): its row ID, when it was
/// created and, for a rotated-out secret still in its overlap, when it stops; null for the current secret.
/// Never its value or hash.
/// </summary>
public sealed record ManagedClientSecret(Guid Id, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt);

/// <summary>How a client secret list, create, rotation or revocation ended (Story 3.3).</summary>
public enum ApplicationSecretStatus
{
    /// <summary>Done: the result holds the live secrets, and for a create the new secret.</summary>
    Done,

    /// <summary>The capability isn't held in the path Tenant, decided again here (AD-5). A machine principal never holds the write's.</summary>
    Forbidden,

    /// <summary>The path Tenant has no visible Application by that ID, or no live secret by that ID of it. Nothing was written.</summary>
    NotFound,

    /// <summary>The Application is a <c>spa</c> or <c>native</c> one, which needs no secret. Nothing was written.</summary>
    NotApplicable,

    /// <summary>The Application already holds the most live secrets: an old secret still overlaps. Nothing was written.</summary>
    LimitReached,
}

/// <summary>
/// A client secret call's result (Story 3.3): the live secrets when <see cref="Status"/> is
/// <see cref="ApplicationSecretStatus.Done"/>, newest first, and on a create the new secret, shown this once (AD-24).
/// </summary>
public sealed class ApplicationSecretsResult
{
    public required ApplicationSecretStatus Status { get; init; }

    /// <summary>The new secret, on a create or rotation only. Only its SHA-256 is stored.</summary>
    public RevealOnce<string>? Secret { get; init; }

    public IReadOnlyList<ManagedClientSecret> Secrets { get; init; } = [];
}

/// <summary>
/// A Tenant's Applications (Story 3.1, FR-11, FR-44): listed and read with
/// <c>tenant.configuration.read</c>, created with <c>tenant.applications.manage</c>. Each call runs in
/// the path Tenant's own context and decides the capability again (AD-5) from the grant the request
/// checks read. Directory owns the rows; the hidden <c>system</c> Application is never shown.
/// </summary>
public interface IApplicationManagement
{
    /// <summary>One page of the path Tenant's Applications, at most <paramref name="limit"/>, newest first, after <paramref name="after"/>.</summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<ApplicationPageResult> ListAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid? after,
        int limit,
        CancellationToken cancellationToken);

    /// <summary>The path Tenant's Application <paramref name="applicationId"/>, or <see cref="ApplicationStatus.NotFound"/>.</summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<ApplicationResult> GetAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid applicationId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Creates an Application named <paramref name="name"/>, trimmed, 1 to 200 characters with no control
    /// character (duplicates allowed), of <paramref name="type"/>, with no secret, and its
    /// <c>directory.application.created</c> event by the caller, an Admin or a machine client, in the
    /// caller's transaction. A malformed name or type is <see cref="ApplicationStatus.Invalid"/>, with nothing written.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    [StateChanging]
    Task<ApplicationResult> CreateAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        string? name,
        string? type,
        CancellationToken cancellationToken);

    /// <summary>
    /// Saves the Application <paramref name="applicationId"/>'s full settings (Story 3.2, FR-11, FR-13, FR-46)
    /// with <c>tenant.application_callbacks.manage</c>, which no machine principal holds. In order: the
    /// capability; the Tenant's label under its row lock; the Application under its row lock; the type table,
    /// every problem named; in a Prod Tenant, <c>acknowledgeCustomScheme</c> for any custom-scheme callback or
    /// logout URL the field doesn't already hold; nothing changed, which writes nothing and uses no grant; and
    /// in a Prod Tenant whose callback set changes, <paramref name="requireFreshAssertion"/>, the handler's
    /// gate. Then the row and <c>directory.application.updated</c>, with
    /// <c>directory.application.prod_callback_added</c> when a Prod Tenant gains a callback, by the Admin, in
    /// the caller's transaction.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    [StateChanging]
    Task<ApplicationSettingsResult> UpdateSettingsAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid applicationId,
        ApplicationSettingsInput input,
        Func<CancellationToken, Task<bool>> requireFreshAssertion,
        CancellationToken cancellationToken);

    /// <summary>
    /// The live client secrets of the Application <paramref name="applicationId"/> (Story 3.3), newest first, with
    /// <c>tenant.configuration.read</c>: never a value or hash. A <c>spa</c> or <c>native</c> Application lists none.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<ApplicationSecretsResult> ListSecretsAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid applicationId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Creates or rotates the client secret of the <c>web</c> or <c>machine</c> Application
    /// <paramref name="applicationId"/> (Story 3.3, FR-12) with <c>tenant.client_secrets.manage</c>, which only Tenant
    /// Owners hold and no machine principal; the request checks have used up its fresh assertion. With no
    /// current secret it creates one and writes <c>directory.client_secret.created</c>; with one it rotates it
    /// out for the 24-hour overlap and writes <c>directory.client_secret.rotated</c>, by the Admin, in the caller's
    /// transaction. A <c>spa</c> or <c>native</c> Application is <see cref="ApplicationSecretStatus.NotApplicable"/>,
    /// and one whose old secret still overlaps <see cref="ApplicationSecretStatus.LimitReached"/>, with nothing written.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    [StateChanging]
    Task<ApplicationSecretsResult> CreateSecretAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid applicationId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Revokes the live client secret <paramref name="secretId"/> of the Application <paramref name="applicationId"/>
    /// (Story 3.3, FR-12) with <c>tenant.client_secrets.manage</c>: it is refused at once, and
    /// <c>directory.client_secret.revoked</c> is written by the Admin, in the caller's transaction. It ends an old
    /// secret's overlap now and revokes the current one alike. A secret that is unknown, another Application's or
    /// already ended is <see cref="ApplicationSecretStatus.NotFound"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    [StateChanging]
    Task<ApplicationSecretsResult> RevokeSecretAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid applicationId,
        Guid secretId,
        CancellationToken cancellationToken);
}
