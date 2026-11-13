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

/// <summary>How a Signing Key rotation on demand ended (Story 9.2).</summary>
public enum SigningKeyRotateStatus
{
    /// <summary>Rotated: <c>next</c> is <c>current</c>, the old <c>current</c> is <c>previous</c>, and a new <c>next</c> exists.</summary>
    Rotated,

    /// <summary><c>tenant.signing_keys.rotate</c> isn't held in the path Tenant.</summary>
    Forbidden,

    /// <summary><c>next</c> was published less than 15 minutes ago; the result says how long remains. Nothing was written.</summary>
    NotReady,

    /// <summary>Key custody is missing or failed to create the replacement. The caller rolls the command back.</summary>
    Unavailable,
}

/// <summary>A rotation's outcome, with the time left on <see cref="SigningKeyRotateStatus.NotReady"/> only.</summary>
public sealed record SigningKeyRotateResult(SigningKeyRotateStatus Status, TimeSpan? RetryAfter);

/// <summary>How a Signing Key revocation ended (Story 9.3).</summary>
public enum SigningKeyRevokeStatus
{
    /// <summary>Revoked: the key left JWKS, its destruction is queued, and a revoked <c>current</c> or <c>next</c> was replaced.</summary>
    Revoked,

    /// <summary><c>tenant.signing_keys.revoke</c> isn't held in the path Tenant.</summary>
    Forbidden,

    /// <summary>
    /// The key ID names no published Signing Key of the path Tenant: unknown, malformed, a Management key,
    /// retired, already revoked or another Tenant's. Nothing was written.
    /// </summary>
    NotFound,

    /// <summary>Key custody is missing or failed to create the replacement. The caller rolls the command back.</summary>
    Unavailable,
}

/// <summary>A revocation's outcome (Story 9.3).</summary>
public sealed record SigningKeyRevokeResult(SigningKeyRevokeStatus Status);

/// <summary>
/// The Signing keys page (Stories 9.1 and 9.2, FR-37): a Tenant's Signing Keys and its public JWKS
/// sample, which only read and write no event, and the Tenant Owner's rotation on demand. All run in
/// the path Tenant's own context. Never a <c>management</c> key (AD-33), and never key material beyond
/// the public halves.
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

    /// <summary>
    /// Rotates the path Tenant's Signing Key now (Story 9.2), once <c>tenant.signing_keys.rotate</c> is
    /// decided again here (AD-5) from <paramref name="grant"/>: <c>next</c>, once published for at least
    /// 15 minutes, becomes <c>current</c>, <c>current</c> becomes <c>previous</c>, and a replacement
    /// <c>next</c> is created through <paramref name="custody"/>, with three Log events whose Actor is the
    /// Admin. Management keys are never touched. A younger <c>next</c> is
    /// <see cref="SigningKeyRotateStatus.NotReady"/> with the time left. No custody, or a custody
    /// failure, is <see cref="SigningKeyRotateStatus.Unavailable"/>. The caller commits only on
    /// <see cref="SigningKeyRotateStatus.Rotated"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<SigningKeyRotateResult> RotateAsync(
        CommandContext tenantContext,
        IKeyCustody? custody,
        AdminPrincipal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Revokes one of the path Tenant's published Signing Keys (Story 9.3, FR-38), named by its <c>kid</c>
    /// <paramref name="keyId"/>, once <c>tenant.signing_keys.revoke</c> is decided again here (AD-5) from
    /// <paramref name="grant"/>. The fresh assertion it needs is the request checks'. The key leaves JWKS at
    /// once and its destruction job is queued; a revoked <c>current</c> has <c>next</c> promoted at once,
    /// whatever its age, and a revoked <c>current</c> or <c>next</c> gets a new <c>next</c> through
    /// <paramref name="custody"/>, with the Log events' Actor the Admin. When <paramref name="revokeAccess"/>
    /// is set, every Session, Token Family and token of the Tenant is then revoked through
    /// <c>ISessions.RevokeAccessAsync</c>, the one revocation path, in the same command. An ID naming no
    /// published Signing Key of the Tenant is <see cref="SigningKeyRevokeStatus.NotFound"/>. No custody, or a
    /// custody failure, is <see cref="SigningKeyRevokeStatus.Unavailable"/>. The caller commits only on
    /// <see cref="SigningKeyRevokeStatus.Revoked"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<SigningKeyRevokeResult> RevokeAsync(
        CommandContext tenantContext,
        IKeyCustody? custody,
        AdminPrincipal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        string keyId,
        bool revokeAccess,
        CancellationToken cancellationToken);
}
