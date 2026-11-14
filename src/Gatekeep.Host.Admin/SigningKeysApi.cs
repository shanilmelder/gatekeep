using System.Data.Common;
using System.Globalization;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Management.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>A Tenant's Signing Keys, in every state (Story 9.1).</summary>
public sealed class SigningKeysResponse
{
    /// <summary><c>next</c>, then <c>current</c>, then <c>previous</c>, then <c>retired</c> and <c>revoked</c> newest first.</summary>
    public required IReadOnlyList<SigningKeyResponse> Keys { get; init; }
}

/// <summary>One Signing Key: its ID and state, never its key material or a Management key.</summary>
public sealed class SigningKeyResponse
{
    /// <summary>The <c>kid</c> tokens and JWKS carry: <c>{Transit key name}.v{version}</c>.</summary>
    public required string KeyId { get; init; }

    /// <summary>The algorithm it signs with: <c>RS256</c>.</summary>
    public required string Algorithm { get; init; }

    /// <summary><c>next</c>, <c>current</c>, <c>previous</c>, <c>retired</c> or <c>revoked</c>.</summary>
    public required string State { get; init; }

    /// <summary>When it was created, ISO 8601 in UTC.</summary>
    public required string CreatedAt { get; init; }
}

/// <summary>A Signing Key revocation (Story 9.3).</summary>
public sealed class RevokeSigningKeyRequest
{
    /// <summary>Whether every Session, Token Family and refresh token of the Tenant is revoked too, in the same transaction.</summary>
    public required bool RevokeAccess { get; init; }
}

/// <summary>A Tenant's public JWKS sample, as Host.Hosted serves it, and where it serves it.</summary>
public sealed class SigningKeysJwksResponse
{
    /// <summary>The Tenant's JWKS URI: its stored issuer and <c>/.well-known/jwks</c>.</summary>
    public required string JwksUri { get; init; }

    /// <summary>One public key per published Signing Key: <c>current</c>, then <c>next</c>, then <c>previous</c>.</summary>
    public required IReadOnlyList<JwkResponse> Keys { get; init; }
}

/// <summary>One public RSA JSON Web Key (RFC 7517). It never has a private member.</summary>
public sealed class JwkResponse
{
    /// <summary><c>RSA</c>.</summary>
    public required string Kty { get; init; }

    /// <summary><c>sig</c>.</summary>
    public required string Use { get; init; }

    /// <summary><c>RS256</c>.</summary>
    public required string Alg { get; init; }

    /// <summary>The key's ID, as the Signing Keys list names it.</summary>
    public required string Kid { get; init; }

    /// <summary>The modulus, base64url without padding.</summary>
    public required string N { get; init; }

    /// <summary>The public exponent, base64url without padding.</summary>
    public required string E { get; init; }
}

/// <summary>
/// The Signing keys page's two reads (Story 9.1, FR-37), each with any Tenant Role, and its rotation
/// on demand (Story 9.2) and revocation (Story 9.3), the Tenant Owner's only, all in the path Tenant's own
/// scope. The list reads PostgreSQL only, so it still answers while custody is down; the JWKS sample needs
/// custody's public halves, and the rotation and revocation custody's create. The request checks have
/// decided the capability, and the revocation's fresh assertion, and Management decides the capability
/// again from the same grant. Neither read writes anything.
/// </summary>
internal static class SigningKeysApi
{
    /// <summary>The route value naming the key a revocation's fresh assertion is for: its <c>kid</c>.</summary>
    public const string KeyRouteValue = "keyId";

    /// <summary>A revocation's body is one boolean; anything this long isn't one.</summary>
    private const int MaxRevokeBody = 1024;

    public static async Task ListAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;

        SigningKeyListRead read;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            read = await services.SigningKeys.ListAsync(
                scope.CreateCommandContext(), AdminRequestChecks.Principal(context), path.Grant, path.TenantId, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        if (read.Status != SigningKeyReadStatus.Read)
        {
            await RefuseAsync(context);
            return;
        }

        await AdminResponses.JsonAsync(context, Response(read));
    }

    public static async Task RotateAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var principal = AdminRequestChecks.Principal(context);
        var cancellationToken = context.RequestAborted;
        var custody = context.RequestServices.GetService<IKeyCustody>();

        SigningKeyRotateResult result;
        SigningKeyListRead? listed = null;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            var tenantContext = scope.CreateCommandContext();
            result = await services.SigningKeys.RotateAsync(tenantContext, custody, principal, path.Grant, path.TenantId, cancellationToken);

            if (result.Status == SigningKeyRotateStatus.Rotated)
            {
                // The keys as this rotation leaves them, read in its own transaction. Once the Transit key
                // exists the rows must follow it: a client gone now mustn't undo the rotation.
                listed = await services.SigningKeys.ListAsync(tenantContext, principal, path.Grant, path.TenantId, CancellationToken.None);
                if (listed.Status == SigningKeyReadStatus.Read)
                {
                    await scope.CommitAsync(CancellationToken.None);
                }
            }
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        switch (result.Status)
        {
            case SigningKeyRotateStatus.Rotated when listed is { Status: SigningKeyReadStatus.Read } read:
                await AdminResponses.JsonAsync(context, Response(read), cancellationToken: CancellationToken.None);
                return;

            case SigningKeyRotateStatus.Rotated:
                // The keys couldn't be read after the rotation, so nothing was committed: unavailable, never a refusal.
                Logger(context).LogWarning(
                    "The Signing Keys couldn't be read after a rotation, so it was rolled back, trace {TraceId}.", AdminResponses.TraceId(context));
                await AdminResponses.UnavailableAsync(context);
                return;

            case SigningKeyRotateStatus.NotReady:
                // Whole seconds, rounded up and never under one, in the body and the header alike.
                var seconds = (int)Math.Max(1, Math.Ceiling((result.RetryAfter ?? TimeSpan.Zero).TotalSeconds));
                Logger(context).LogInformation(
                    "A Signing Key rotation was refused with {Problem}, trace {TraceId}.", AdminResponses.SigningKeyNotReady, AdminResponses.TraceId(context));
                await AdminResponses.ProblemAsync(context, StatusCodes.Status409Conflict, AdminResponses.SigningKeyNotReady, errors: null, retryAfterSeconds: seconds);
                return;

            case SigningKeyRotateStatus.Unavailable:
                // The failure's kind only: never a key name, a version or what custody answered.
                Logger(context).LogWarning(
                    "Key custody couldn't create a Signing Key for a rotation, trace {TraceId}.", AdminResponses.TraceId(context));
                await AdminResponses.UnavailableAsync(context);
                return;

            default:
                await RefuseAsync(context);
                return;
        }
    }

    public static async Task RevokeAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var principal = AdminRequestChecks.Principal(context);
        var cancellationToken = context.RequestAborted;
        var custody = context.RequestServices.GetService<IKeyCustody>();
        var keyId = context.GetRouteValue(KeyRouteValue) as string ?? string.Empty;

        var body = await AdminApi.ReadJsonAsync<RevokeSigningKeyRequest>(context.Request, MaxRevokeBody, cancellationToken);
        if (body is null)
        {
            Logger(context).LogInformation(
                "A Signing Key revocation was refused with {Problem}, trace {TraceId}.", AdminResponses.InvalidRequest, AdminResponses.TraceId(context));
            await AdminResponses.ProblemAsync(context, StatusCodes.Status400BadRequest, AdminResponses.InvalidRequest);
            return;
        }

        SigningKeyRevokeResult result;
        SigningKeyListRead? listed = null;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            var tenantContext = scope.CreateCommandContext();
            result = await services.SigningKeys.RevokeAsync(
                tenantContext, custody, principal, path.Grant, path.TenantId, keyId, body.RevokeAccess, cancellationToken);

            if (result.Status == SigningKeyRevokeStatus.Revoked)
            {
                // The keys as this revocation leaves them, read in its own transaction. Once the Transit key
                // exists the rows must follow it: a client gone now mustn't undo the revocation.
                listed = await services.SigningKeys.ListAsync(tenantContext, principal, path.Grant, path.TenantId, CancellationToken.None);
                if (listed.Status == SigningKeyReadStatus.Read)
                {
                    await scope.CommitAsync(CancellationToken.None);
                }
            }
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        switch (result.Status)
        {
            case SigningKeyRevokeStatus.Revoked when listed is { Status: SigningKeyReadStatus.Read } read:
                await AdminResponses.JsonAsync(context, Response(read), cancellationToken: CancellationToken.None);
                return;

            case SigningKeyRevokeStatus.Revoked:
                // The keys couldn't be read after the revocation, so nothing was committed: unavailable, never a refusal.
                Logger(context).LogWarning(
                    "The Signing Keys couldn't be read after a revocation, so it was rolled back, trace {TraceId}.", AdminResponses.TraceId(context));
                await AdminResponses.UnavailableAsync(context);
                return;

            case SigningKeyRevokeStatus.NotFound:
                // The same 404 for every key ID that names no published Signing Key of this Tenant.
                Logger(context).LogInformation(
                    "A Signing Key revocation was refused with {Problem}, trace {TraceId}.", AdminResponses.NotFound, AdminResponses.TraceId(context));
                await AdminResponses.ProblemAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
                return;

            case SigningKeyRevokeStatus.Unavailable:
                // The failure's kind only: never a key name, a version or what custody answered.
                Logger(context).LogWarning(
                    "Key custody couldn't create a Signing Key for a revocation, trace {TraceId}.", AdminResponses.TraceId(context));
                await AdminResponses.UnavailableAsync(context);
                return;

            case SigningKeyRevokeStatus.Forbidden:
                await RefuseAsync(context);
                return;

            default:
                throw new InvalidOperationException("Unknown Signing Key revocation status.");
        }
    }

    /// <summary>The list as the page shows it: the key ID, the one algorithm, the state and the creation time, never more.</summary>
    private static SigningKeysResponse Response(SigningKeyListRead read) => new()
    {
        Keys = [.. read.Keys.Select(k => new SigningKeyResponse
        {
            KeyId = k.KeyId,
            Algorithm = ISigningKeyManagement.Algorithm,
            State = k.State,
            CreatedAt = k.CreatedAt.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture),
        })],
    };

    public static async Task GetJwksAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;
        var custody = context.RequestServices.GetService<IKeyCustody>();

        SigningKeyJwksRead read;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            read = await services.SigningKeys.GetJwksAsync(
                scope.CreateCommandContext(), custody, AdminRequestChecks.Principal(context), path.Grant, path.TenantId, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        switch (read.Status)
        {
            case SigningKeyReadStatus.Read:
                await AdminResponses.JsonAsync(context, new SigningKeysJwksResponse
                {
                    JwksUri = read.JwksUri!,
                    Keys = [.. read.Keys.Select(k => new JwkResponse { Kty = k.Kty, Use = k.Use, Alg = k.Alg, Kid = k.Kid, N = k.N, E = k.E })],
                });
                return;

            case SigningKeyReadStatus.Unavailable:
                // The failure's kind only: never a key name, a version or what custody answered.
                Logger(context).LogWarning(
                    "Key custody gave no public JWKS sample for a Signing keys read, trace {TraceId}.", AdminResponses.TraceId(context));
                await AdminResponses.UnavailableAsync(context);
                return;

            default:
                await RefuseAsync(context);
                return;
        }
    }

    /// <summary>A refusal, logged under its fixed code only.</summary>
    private static Task RefuseAsync(HttpContext context)
    {
        Logger(context).LogInformation(
            "A Signing keys request was refused with {Problem}, trace {TraceId}.", AdminResponses.AccessDenied, AdminResponses.TraceId(context));
        return AdminResponses.ProblemAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied);
    }

    private static ILogger Logger(HttpContext context) =>
        context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Gatekeep.Host.Admin");
}
