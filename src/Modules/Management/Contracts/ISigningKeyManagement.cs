using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Modules.Management.Contracts;

/// <summary>How a Signing keys read ended.</summary>
public enum SigningKeyReadStatus
{
    /// <summary>Read: the keys are in the result.</summary>
    Read,

    /// <summary><c>tenant.configuration.read</c> isn't held in the path Tenant, or the Tenant is gone.</summary>
    Forbidden,

    /// <summary>Key custody failed, timed out, or has no public half for a published key's version.</summary>
    Unavailable,
}

/// <summary>
/// One Signing Key as the page lists it: its <c>kid</c> (<c>{Transit key name}.v{version}</c>), its state as
/// stored (<c>next</c>, <c>current</c>, <c>previous</c>, <c>retired</c> or <c>revoked</c>) and when it was created.
/// </summary>
public sealed record SigningKeyListing(string KeyId, string State, DateTimeOffset CreatedAt);

/// <summary>The path Tenant's Signing Keys, in every state, or why there are none.</summary>
public sealed record SigningKeyListRead(SigningKeyReadStatus Status, IReadOnlyList<SigningKeyListing> Keys);

/// <summary>
/// One public JSON Web Key (RFC 7517) exactly as the Tenant's JWKS on Host.Hosted serves it: the RSA
/// modulus and exponent, base64url without padding. It has no private member.
/// </summary>
public sealed record SigningKeyJwk(string Kty, string Use, string Alg, string Kid, string N, string E);

/// <summary>The path Tenant's public JWKS sample and where Host.Hosted serves it, or why there is none.</summary>
public sealed record SigningKeyJwksRead(SigningKeyReadStatus Status, string? JwksUri, IReadOnlyList<SigningKeyJwk> Keys);

/// <summary>
/// The Signing keys page's reads (Story 9.1, FR-37): a Tenant's Signing Keys and its public JWKS
/// sample. Both only read, in the path Tenant's own context, and write no event. Never a
/// <c>management</c> key (AD-33), and never key material beyond the public halves.
/// </summary>
public interface ISigningKeyManagement
{
    /// <summary>
    /// Where Host.Hosted serves each Tenant's JWKS, under its issuer: the same path as Protocol's
    /// <c>ProtocolContract.JsonWebKeySetPath</c>, which an architecture test holds it to.
    /// </summary>
    public const string JwksPath = "/.well-known/jwks";

    /// <summary>The algorithm every Signing Key signs with (AD-9): RS256, Deployment-wide.</summary>
    public const string Algorithm = "RS256";

    /// <summary>
    /// The path Tenant's Signing Keys in every state, <c>next</c>, <c>current</c>, <c>previous</c>,
    /// then <c>retired</c> and <c>revoked</c> newest first, once <c>tenant.configuration.read</c> is
    /// decided again here (AD-5) from <paramref name="grant"/>, the role the request checks read. It
    /// reads PostgreSQL only.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<SigningKeyListRead> ListAsync(
        CommandContext tenantContext,
        AdminPrincipal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        CancellationToken cancellationToken);

    /// <summary>
    /// The path Tenant's public JWKS sample: one key per published Signing Key (<c>current</c>,
    /// <c>next</c>, <c>previous</c>, in that order) with exactly the members Host.Hosted's JWKS
    /// serves, built from the public half <paramref name="custody"/> returns for the row's version,
    /// and the Tenant's JWKS URI, its stored issuer plus <see cref="JwksPath"/>. Decided again from
    /// <paramref name="grant"/> first (AD-5). No custody, a custody failure or a missing version is
    /// <see cref="SigningKeyReadStatus.Unavailable"/> for the whole sample.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<SigningKeyJwksRead> GetJwksAsync(
        CommandContext tenantContext,
        IKeyCustody? custody,
        AdminPrincipal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        CancellationToken cancellationToken);
}
