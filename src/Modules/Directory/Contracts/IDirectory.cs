using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Modules.Directory.Contracts;

/// <summary>
/// A machine client just created (Story 2.5): its Application, its OAuth <c>client_id</c> (the
/// Application's <c>app_</c> public ID) and its client secret, shown this once (AD-24). The secret is
/// <c>{tenantPublicId}.{base64url of 32 random bytes}</c> (AD-9); only its SHA-256 is stored, so it can
/// never be read back.
/// </summary>
public sealed class CreatedMachineClient
{
    public required Guid ApplicationId { get; init; }

    public required string ClientId { get; init; }

    public required RevealOnce<string> Secret { get; init; }
}

/// <summary>Applications and their client secrets (AD-8, AD-27). Directory owns <c>application</c> and <c>client_secret</c>.</summary>
public interface IDirectory
{
    /// <summary>
    /// Writes a <c>machine</c> Application allowed the <c>client_credentials</c> grant, with no audience
    /// (Story 3.7 adds them), its one client secret, and one <c>directory.application.created</c> audit
    /// event by the System, all in the caller's context and only in its Tenant. Directory writes the rows
    /// itself, never through OpenIddict's manager, whose validation wants a secret column.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    /// <exception cref="ArgumentException"><paramref name="name"/> is empty, longer than 200 characters or holds a NUL character.</exception>
    [StateChanging]
    Task<CreatedMachineClient> CreateMachineClientAsync(CommandContext context, string name, CancellationToken cancellationToken);

    /// <summary>
    /// Whether <paramref name="secret"/> is a live secret of the Application <paramref name="clientId"/>
    /// names, in the context's Tenant: not revoked, and with no <c>expires_at</c> or one still ahead. The
    /// stored hashes are compared in constant time. A malformed or unknown client ID is false, exactly
    /// like a wrong secret. It only reads.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    Task<bool> VerifyClientSecretAsync(CommandContext context, string clientId, Secret<string> secret, CancellationToken cancellationToken);
}
