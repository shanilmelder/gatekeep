using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;

namespace Gatekeep.Modules.Management.Contracts;

/// <summary>
/// Where Tenant Subdomains sit (AD-6): the Tenant zone, and the Tenant HTTPS port the issuer names
/// when it isn't 443. Read from Host.Admin's settings once, and used only to derive a new Tenant's
/// address at creation.
/// </summary>
public sealed record TenantAddressing
{
    public const int DefaultHttpsPort = 443;

    /// <exception cref="ArgumentException"><paramref name="zone"/> isn't a valid Tenant zone.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="httpsPort"/> isn't 1 to 65535.</exception>
    public TenantAddressing(string zone, int httpsPort = DefaultHttpsPort)
    {
        if (!IsValidZone(zone))
        {
            throw new ArgumentException("The Tenant zone is lower-case LDH labels separated by dots, at least two, at most 200 characters.", nameof(zone));
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(httpsPort, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(httpsPort, 65535);

        Zone = zone;
        HttpsPort = httpsPort;
    }

    public string Zone { get; }

    public int HttpsPort { get; }

    /// <summary>Whether <paramref name="zone"/> is lower-case LDH labels separated by dots, at least two, at most 200 characters.</summary>
    public static bool IsValidZone(string? zone) => TenantZone.IsValid(zone);

    /// <summary>Whether <paramref name="host"/> is <paramref name="zone"/> or a name under it: the Admin hostname must be neither (AD-6).</summary>
    public static bool ZoneCovers(string zone, string host) => TenantZone.Covers(zone, host);
}

/// <summary>The create request's fields as sent: validated by <see cref="ITenantManagement.CreateAsync"/>, never before.</summary>
public sealed record CreateTenantInput(string? Name, string? Subdomain, string? Label);

public enum ManagedOperationStatus
{
    Running,
    Failed,
    Succeeded,
}

public enum ManagedOperationStepStatus
{
    Pending,
    Running,
    Succeeded,
    Failed,
}

/// <summary>One Operation step as an Admin reads it: codes and IDs only (AD-30), never its row ID.</summary>
public sealed record ManagedOperationStep(
    string Stage,
    Guid? TenantId,
    ManagedOperationStepStatus Status,
    string? ResultCode,
    int Attempts,
    DateTimeOffset UpdatedAt);

/// <summary>An Operation as an Admin reads it, with the steps that reader may see.</summary>
public sealed record ManagedOperation(
    Guid Id,
    string Type,
    Guid? TenantId,
    ManagedOperationStatus Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? FinishedAt,
    IReadOnlyList<ManagedOperationStep> Steps);

/// <summary>A creating Tenant's creation Operation: <c>running</c> or <c>failed</c>.</summary>
public sealed record ManagedTenantCreation(Guid OperationId, ManagedOperationStatus Status);

/// <summary>A deleting Tenant's deletion Operation (Story 1.29): <c>running</c> or <c>failed</c>.</summary>
public sealed record ManagedTenantDeletion(Guid OperationId, ManagedOperationStatus Status);

/// <summary>
/// A Tenant as the Tenants list shows it: its stored host, never a subdomain split from it (AD-6),
/// its label and status in their stored spellings, its creation while it is <c>creating</c>, and its
/// deletion while it is <c>deleting</c> (Story 1.29). A <c>deleted</c> Tenant is never listed.
/// </summary>
public sealed record ManagedTenant(
    Guid Id,
    string Name,
    string Host,
    string Label,
    string Status,
    DateTimeOffset CreatedAt,
    ManagedTenantCreation? Creation,
    ManagedTenantDeletion? Deletion = null);

public enum TenantDeletionStatus
{
    /// <summary>The Tenant is deleting, its roles are gone, its Operation started and its event written. The caller commits.</summary>
    Started,

    /// <summary>The handler's own re-check refused it (AD-5): the request checks should have first.</summary>
    Forbidden,

    /// <summary>No Tenant has this ID.</summary>
    NotFound,

    /// <summary>The Tenant is already being deleted, or deleted.</summary>
    AlreadyDeleted,

    /// <summary>The typed value isn't the Tenant's stored host, exactly. Nothing was written.</summary>
    ConfirmationMismatch,

    /// <summary>The Tenant's creation Operation is still running. Nothing was written.</summary>
    Busy,
}

/// <summary>A deletion start's outcome, and its Operation once started.</summary>
public sealed record TenantDeletionResult(TenantDeletionStatus Status, ManagedOperation? Operation = null);

/// <summary>A deletion read: whether the module's own capability check allowed it (AD-5), and the newest deletion Operation, if any.</summary>
public sealed record TenantDeletionRead(bool Allowed, ManagedOperation? Operation);

public enum TenantCreationStatus
{
    Created,

    /// <summary>The handler's own re-check refused it (AD-5): the request checks should have first.</summary>
    Forbidden,

    /// <summary>The name or label is invalid. Nothing was written.</summary>
    TenantInvalid,

    /// <summary>The subdomain is malformed, reserved or taken, alike. Nothing was written.</summary>
    SubdomainRefused,
}

public sealed record TenantCreationResult(TenantCreationStatus Status, ManagedTenant? Tenant = null, ManagedOperation? Operation = null);

/// <summary>
/// A Tenant-path Operation read: whether the module's own capability check allowed it (AD-5), and
/// the Operation, null when it doesn't exist or belongs to another Tenant, alike.
/// </summary>
public sealed record TenantOperationRead(bool Allowed, ManagedOperation? Operation);

/// <summary>One page of Tenants, and the last one's ID when another page follows.</summary>
public sealed record TenantPage(IReadOnlyList<ManagedTenant> Tenants, Guid? NextAfter);

public enum OperationRetryStatus
{
    Retried,

    /// <summary>The handler's own re-check refused it (AD-5).</summary>
    Forbidden,

    /// <summary>No Operation has this ID, or it isn't a Tenant creation.</summary>
    NotFound,

    /// <summary>The Operation isn't <c>failed</c>, so there is nothing to retry.</summary>
    NotFailed,

    /// <summary>A creation whose Tenant is being deleted, or deleted (Story 1.29): it never runs again.</summary>
    TenantDeleted,
}

public sealed record OperationRetryResult(OperationRetryStatus Status, ManagedOperation? Operation = null);

/// <summary>
/// A Tenant the current Admin holds a Tenant Role in, as the Tenant switcher shows it (Story 1.28):
/// its stored host and label, never the role, and never its status, which is always <c>active</c>.
/// </summary>
public sealed record AdminTenant(Guid Id, string Name, string Host, string Label);

/// <summary>A label read: whether the module's own capability check allowed it (AD-5), and the stored label and status.</summary>
public sealed record TenantLabelRead(bool Allowed, string? Label, string? Status = null);

public enum LabelChangeStatus
{
    /// <summary>The label was written, and its event appended. The caller commits.</summary>
    Changed,

    /// <summary>The requested label is the current one: nothing was written, no event, no grant used.</summary>
    Unchanged,

    /// <summary>The handler's own re-check refused it (AD-5), or the Tenant isn't there.</summary>
    Forbidden,

    /// <summary>The requested label isn't <c>dev</c>, <c>staging</c> or <c>prod</c>.</summary>
    Invalid,

    /// <summary>The Tenant is still being created, or stopped being active: its label can't change.</summary>
    NotActive,

    /// <summary>Removing Prod, and the fresh-assertion gate found no grant: it has already answered.</summary>
    FreshAssertionRequired,
}

/// <summary>A label change's outcome, and the label the Tenant has after it when it was changed or unchanged.</summary>
public sealed record LabelChangeResult(LabelChangeStatus Status, string? Label = null);

/// <summary>
/// Creating and listing Tenants for Host.Admin (Story 1.27): the one place that orchestrates
/// Tenancy, Admins and Operations for it (AD-1). Each call runs in the caller's Deployment
/// context, but the label calls (Story 1.28), which run in the path Tenant's, and decides access
/// again itself (AD-5).
/// </summary>
public interface ITenantManagement
{
    /// <summary>The Tenant zone every Tenant Subdomain sits under.</summary>
    string TenantZone { get; }

    /// <summary>
    /// Validates the input, derives the address, inserts the Tenant as <c>creating</c> with its
    /// host, makes <paramref name="principal"/> its Tenant Owner, starts its creation Operation
    /// scoped to it, and appends <see cref="TenancyEvents.TenantCreated"/> on the Deployment chain,
    /// all in the caller's transaction. A refusal writes nothing and leaves the transaction usable.
    /// </summary>
    [StateChanging]
    Task<TenantCreationResult> CreateAsync(
        CommandContext context,
        AdminPrincipal principal,
        CreateTenantInput input,
        CancellationToken cancellationToken);

    /// <summary>
    /// Up to <paramref name="limit"/> Tenants after the one <paramref name="after"/> names, ordered by
    /// creation time then ID; null when <paramref name="principal"/> may not read them.
    /// </summary>
    Task<TenantPage?> ListAsync(
        CommandContext context,
        AdminPrincipal principal,
        Guid? after,
        int limit,
        CancellationToken cancellationToken);

    /// <summary>
    /// The Operation with only <paramref name="tenantId"/>'s steps, read through the Tenant path
    /// only, once <paramref name="principal"/>'s <c>tenant.configuration.read</c> in that Tenant is
    /// checked again here.
    /// </summary>
    Task<TenantOperationRead> GetOperationAsync(
        CommandContext context,
        AdminPrincipal principal,
        Guid tenantId,
        Guid operationId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Retries a <c>failed</c> <c>tenancy.tenant.create</c> Operation's failed steps, and appends
    /// <c>operations.operation.retried</c>. Any other Operation is <see cref="OperationRetryStatus.NotFound"/>.
    /// The Tenant is locked first: one being deleted, or deleted, is
    /// <see cref="OperationRetryStatus.TenantDeleted"/>, and nothing runs (Story 1.29).
    /// </summary>
    [StateChanging]
    Task<OperationRetryResult> RetryCreationAsync(
        CommandContext context,
        AdminPrincipal principal,
        Guid operationId,
        CancellationToken cancellationToken);

    /// <summary>
    /// The <c>active</c> Tenants <paramref name="principal"/> holds a Tenant Role in, ordered by
    /// creation, in a Deployment context (Story 1.28). Self-service: the caller's own roles, so no
    /// capability is checked, and no role is returned.
    /// </summary>
    Task<IReadOnlyList<AdminTenant>> ListForAdminAsync(CommandContext context, AdminPrincipal principal, CancellationToken cancellationToken);

    /// <summary>
    /// The path Tenant's label, in that Tenant's own context, once <c>tenant.configuration.read</c>
    /// is decided again here (AD-5) from <paramref name="grant"/>, the role the request checks read.
    /// </summary>
    Task<TenantLabelRead> GetLabelAsync(
        CommandContext tenantContext,
        AdminPrincipal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Changes the path Tenant's label, in that Tenant's own context (Story 1.28, FR-7): decides
    /// <c>tenant.label.manage</c> again from <paramref name="grant"/> with no second role read,
    /// parses <paramref name="requested"/>, locks the Tenant's row, and only when the change removes
    /// Prod on that locked label awaits <paramref name="requireFreshAssertion"/>, which uses up the
    /// grant in its own committed transaction. Then it writes the label, and only the label, and
    /// appends its event on the Tenant's chain. The caller commits only on
    /// <see cref="LabelChangeStatus.Changed"/>.
    /// </summary>
    [StateChanging]
    Task<LabelChangeResult> ChangeLabelAsync(
        CommandContext tenantContext,
        AdminPrincipal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        string? requested,
        Func<CancellationToken, Task<bool>> requireFreshAssertion,
        CancellationToken cancellationToken);

    /// <summary>
    /// Starts deleting <paramref name="tenantId"/> (Story 1.29, FR-7), in a Deployment context: decides
    /// <c>deployment.tenants.delete</c> again (AD-5), locks the Tenant, refuses one already deleting
    /// or deleted, a <paramref name="confirmation"/> that isn't ordinally its stored host, and one whose
    /// creation is still running; then sets it <c>deleting</c>, removes every Tenant Role in it,
    /// starts <c>tenancy.tenant.delete</c> and appends <see cref="TenancyEvents.DeletionStarted"/> on
    /// the Deployment chain. A refusal writes nothing. The caller commits only on
    /// <see cref="TenantDeletionStatus.Started"/>.
    /// </summary>
    [StateChanging]
    Task<TenantDeletionResult> DeleteAsync(
        CommandContext context,
        AdminPrincipal principal,
        Guid tenantId,
        string? confirmation,
        CancellationToken cancellationToken);

    /// <summary>
    /// The Tenant's newest <c>tenancy.tenant.delete</c> Operation, any status, with every step, once
    /// <c>deployment.tenants.read</c> is decided again here (Story 1.29).
    /// </summary>
    Task<TenantDeletionRead> GetDeletionAsync(CommandContext context, AdminPrincipal principal, Guid tenantId, CancellationToken cancellationToken);

    /// <summary>
    /// Retries a deleting Tenant's <c>failed</c> deletion's failed steps, and appends
    /// <c>operations.operation.retried</c> with the Tenant as target (Story 1.29). No such Tenant is
    /// <see cref="OperationRetryStatus.NotFound"/>; one that isn't deleting, or whose deletion isn't
    /// failed, is <see cref="OperationRetryStatus.NotFailed"/>.
    /// </summary>
    [StateChanging]
    Task<OperationRetryResult> RetryDeletionAsync(CommandContext context, AdminPrincipal principal, Guid tenantId, CancellationToken cancellationToken);
}
