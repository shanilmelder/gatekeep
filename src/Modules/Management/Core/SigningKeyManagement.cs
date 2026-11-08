using System.Buffers.Text;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Keys.Contracts;
using Gatekeep.Modules.Management.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;

namespace Gatekeep.Modules.Management.Core;

/// <summary>
/// The Signing keys page's reads (Story 9.1): the rows from PostgreSQL, and the public JWKS sample
/// from the public halves custody returns. Only <c>signing</c> rows are read, so no Management key
/// can reach either. Nothing is written, and no event appended.
/// </summary>
internal sealed class SigningKeyManagement(IAuditAppender appender) : ISigningKeyManagement
{
    /// <summary>Every Signing Key is RSA-3072 (AD-9): a modulus of 384 bytes. Any other is never published, as on Host.Hosted.</summary>
    private const int RsaModulusBytes = 3072 / 8;

    private readonly ITenants _tenants = TenancyContract.CreateTenants(appender);

    public async Task<SigningKeyListRead> ListAsync(
        CommandContext tenantContext,
        AdminPrincipal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        // Authorization runs in the module too (AD-5), from the grant the checks read: no second read.
        if (!AdminCapabilities.Allows(AdminCapabilities.TenantConfigurationRead, principal, grant, tenantId))
        {
            return new SigningKeyListRead(SigningKeyReadStatus.Forbidden, []);
        }

        var keys = await KeysContract.ListSigningKeysAsync(tenantContext, cancellationToken);
        return new SigningKeyListRead(SigningKeyReadStatus.Read, [.. keys.Select(k => new SigningKeyListing(k.KeyId, Stored(k.State), k.CreatedAt))]);
    }

    private static string Stored(SigningKeyState state) => state switch
    {
        SigningKeyState.Next => "next",
        SigningKeyState.Current => "current",
        SigningKeyState.Previous => "previous",
        SigningKeyState.Retired => "retired",
        SigningKeyState.Revoked => "revoked",
        _ => throw new ArgumentOutOfRangeException(nameof(state)),
    };

    public async Task<SigningKeyJwksRead> GetJwksAsync(
        CommandContext tenantContext,
        IKeyCustody? custody,
        AdminPrincipal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantConfigurationRead, principal, grant, tenantId))
        {
            return Refused(SigningKeyReadStatus.Forbidden);
        }

        // The stored issuer, never the request's host (AD-6): the URI Host.Hosted's discovery names.
        if (await _tenants.GetIssuerAsync(tenantContext, tenantId, cancellationToken) is not { } issuer)
        {
            return Refused(SigningKeyReadStatus.Forbidden);
        }

        var published = await KeysContract.ReadPublishedSigningKeysAsync(tenantContext, cancellationToken);
        if (published.Count > 0 && custody is null)
        {
            return Refused(SigningKeyReadStatus.Unavailable);
        }

        // One bound for the whole sample, not one per key: a slow custody holds this request and
        // its connection for at most the one limit.
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(SecurityLimits.KeyCustodyCallTimeout);

        var keys = new List<SigningKeyJwk>(published.Count);
        foreach (var key in published)
        {
            if (await PublicJwkAsync(custody!, key, limit.Token, cancellationToken) is not { } jwk)
            {
                return Refused(SigningKeyReadStatus.Unavailable);
            }

            keys.Add(jwk);
        }

        return new SigningKeyJwksRead(SigningKeyReadStatus.Read, issuer.TrimEnd('/') + ISigningKeyManagement.JwksPath, keys);
    }

    /// <summary>The key's public JWK, from custody's public half for the row's own version; null when custody can't give it.</summary>
    private static async Task<SigningKeyJwk?> PublicJwkAsync(
        IKeyCustody custody,
        PublishedSigningKey key,
        CancellationToken limit,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<KeyPublicVersion> versions;
        try
        {
            versions = await custody.GetPublicKeysAsync(key.Key, limit).WaitAsync(limit);
        }
        catch (KeyCustodyException)
        {
            return null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // The bound, not the caller: custody didn't answer in time.
            return null;
        }

        // The row names the version its kid carries; any other is never published as that kid.
        if (versions.SingleOrDefault(v => v.KeyVersion == key.Version) is not { } version)
        {
            return null;
        }

        System.Security.Cryptography.RSAParameters parameters;
        try
        {
            parameters = KeysContract.RsaPublicParameters(version.PublicKeyPem);
        }
        catch (Exception e) when (e is FormatException or ArgumentException)
        {
            // Malformed, or empty: never published, the whole sample is unavailable.
            return null;
        }

        if (parameters.Modulus is not { Length: RsaModulusBytes } modulus || parameters.Exponent is not { Length: > 0 } exponent)
        {
            return null;
        }

        return new SigningKeyJwk("RSA", "sig", ISigningKeyManagement.Algorithm, key.KeyId, Base64Url.EncodeToString(modulus), Base64Url.EncodeToString(exponent));
    }

    private static SigningKeyJwksRead Refused(SigningKeyReadStatus status) => new(status, null, []);

    private static void RequireOwnContext(CommandContext context, Guid tenantId)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (tenantId == Guid.Empty || context.TenantId != tenantId)
        {
            throw new InvalidOperationException("A Tenant's Signing Keys are read in its own context.");
        }
    }
}
