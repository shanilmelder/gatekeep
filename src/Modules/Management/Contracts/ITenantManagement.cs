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

/// <summary>
/// A Tenant as the Tenants list shows it: its stored host, never a subdomain split from it (AD-6),
/// its label and status in their stored spellings, and its creation while it is <c>creating</c>.
/// </summary>
public sealed record ManagedTenant(
    Guid Id,
    string Name,
    string Host,
    string Label,
    string Status,
    DateTimeOffset CreatedAt,
    ManagedTenantCreation? Creation);

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

    /// <summary>The creation isn't <c>failed</c>, so there is nothing to retry.</summary>
    NotFailed,
}

public sealed record OperationRetryResult(OperationRetryStatus Status, ManagedOperation? Operation = null);

/// <summary>
/// Creating and listing Tenants for Host.Admin (Story 1.27): the one place that orchestrates
/// Tenancy, Admins and Operations for it (AD-1). Each call runs in the caller's Deployment
/// context, and decides access again itself (AD-5).
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
    /// </summary>
    [StateChanging]
    Task<OperationRetryResult> RetryCreationAsync(
        CommandContext context,
        AdminPrincipal principal,
        Guid operationId,
        CancellationToken cancellationToken);
}
