using System.Text.Json;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Modules.Management.Contracts;

/// <summary>How an email provider read, save or removal ended (Story 4.4).</summary>
public enum EmailProviderStatus
{
    /// <summary>Done: a read, a save that wrote or changed nothing, or a removal that removed or found nothing.</summary>
    Done,

    /// <summary>The capability isn't held in the path Tenant. Nothing written.</summary>
    Forbidden,

    /// <summary>A field is refused; the result names each. Nothing written.</summary>
    Invalid,

    /// <summary>Key custody is missing or failed to encrypt the secret. Nothing written; the caller rolls back.</summary>
    Unavailable,
}

/// <summary>
/// An email provider save's input as the request gave it (Story 4.4): each part may be missing, and the save decides.
/// The secret is held only as <see cref="Secret{T}"/>, until Notifications encrypts it.
/// </summary>
public sealed record EmailProviderSaveInput(
    string? Kind,
    JsonElement? Settings,
    string? FromAddress,
    string? FromName,
    Secret<string>? Secret);

/// <summary>One refused field of an email provider save: one of <see cref="ManagementContract.EmailProviderFields"/> and why, never its value.</summary>
public sealed record EmailProviderError(string Field, string Reason);

/// <summary>A provider's non-secret settings as stored: only its kind's members are set (Story 4.4).</summary>
public sealed record ManagedEmailProviderSettings
{
    public string? Host { get; init; }

    public int? Port { get; init; }

    public string? Tls { get; init; }

    public string? Username { get; init; }

    public string? Region { get; init; }

    public string? MessageStream { get; init; }

    public string? Domain { get; init; }

    public string? AccessKeyId { get; init; }

    public string? Endpoint { get; init; }

    public string? AuthHeaderName { get; init; }
}

/// <summary>The Tenant's email provider as stored, without its secret: only whether one is stored (Story 4.4).</summary>
public sealed record ManagedEmailProvider(
    string Kind,
    ManagedEmailProviderSettings Settings,
    string FromAddress,
    string? FromName,
    DateTimeOffset UpdatedAt,
    bool SecretSet);

/// <summary>
/// An email provider request's outcome: the provider as it stands, null when none is configured, and on
/// <see cref="EmailProviderStatus.Invalid"/> each refused field. <see cref="Changed"/> says a save or removal wrote.
/// </summary>
public sealed record EmailProviderResult(
    EmailProviderStatus Status,
    ManagedEmailProvider? Provider,
    IReadOnlyList<EmailProviderError> Errors,
    bool Changed);

/// <summary>
/// A Tenant's email provider (Story 4.4, FR-36): read with any Tenant Role, saved and removed by its Tenant Owner only,
/// never a machine principal, each in the path Tenant's own context. The fresh assertion a change needs is the request
/// checks'. The secret is encrypted on the way in and never read back: no result holds it or its ciphertext.
/// </summary>
public interface IEmailProviderManagement
{
    /// <summary>The path Tenant's provider without its secret, once <c>tenant.configuration.read</c> is decided again here (AD-5).</summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<EmailProviderResult> GetAsync(
        CommandContext tenantContext,
        AdminPrincipal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Saves the path Tenant's provider through Notifications, once <c>tenant.email_provider.manage</c> is decided again
    /// here (AD-5), its secret encrypted through <paramref name="custody"/>, with the Admin as Actor. The caller commits
    /// only on <see cref="EmailProviderStatus.Done"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<EmailProviderResult> SaveAsync(
        CommandContext tenantContext,
        IKeyCustody? custody,
        AdminPrincipal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        EmailProviderSaveInput input,
        CancellationToken cancellationToken);

    /// <summary>Removes the path Tenant's provider and its secret, once <c>tenant.email_provider.manage</c> is decided again here (AD-5).</summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<EmailProviderResult> RemoveAsync(
        CommandContext tenantContext,
        AdminPrincipal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        CancellationToken cancellationToken);
}
