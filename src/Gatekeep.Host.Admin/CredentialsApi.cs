using System.Data.Common;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>One of the Admin's own credentials, as Your credentials lists it. Never its WebAuthn credential ID, key, AAGUID, counter or user handle.</summary>
public sealed class AdminCredentialResponse
{
    /// <summary>The credential's public ID: <c>acr_</c> and 26 base32 characters. Its row's, never the WebAuthn credential ID.</summary>
    public required string Id { get; init; }

    /// <summary><c>passkey</c> when backup-eligible or reported internal or hybrid, <c>securityKey</c> otherwise.</summary>
    public required string Kind { get; init; }

    /// <summary>Whether the authenticator last said the credential is backed up, as a synced passkey is.</summary>
    public required bool BackedUp { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>The last sign-in or fresh assertion with it, or null when it was never used.</summary>
    public DateTimeOffset? LastUsedAt { get; init; }

    /// <summary>Whether removing it would keep the Admin at two credentials or more: the server's floor rule.</summary>
    public required bool Removable { get; init; }
}

/// <summary>Your credentials: the Admin's own, oldest first, and whether they hold a confirmed, unused Recovery Code.</summary>
public sealed class AdminCredentialsResponse
{
    public required IReadOnlyList<AdminCredentialResponse> Credentials { get; init; }

    public required bool RecoveryCode { get; init; }
}

/// <summary>
/// A removal that also ended this Session, because the credential removed was the one that confirmed
/// it. The Session cookie is cleared; the client signs in again.
/// </summary>
public sealed class AdminCredentialRemovalResponse
{
    public required bool SessionEnded { get; init; }
}

/// <summary>
/// Your credentials (Story 1.26): the list, self-service and read-only, and a removal, which the
/// request checks have already confirmed by using up its fresh assertion before this runs.
/// </summary>
internal static class CredentialsApi
{
    /// <summary>The route value naming the credential to remove, and the target its fresh assertion is bound to.</summary>
    public const string CredentialRouteValue = "credentialId";

    public static async Task ListAsync(HttpContext context, AdminApiServices services)
    {
        var session = AdminRequestChecks.Session(context);
        var cancellationToken = context.RequestAborted;

        AdminCredentialList list;
        await using (var read = await services.BeginAsync(cancellationToken))
        {
            list = await services.Credentials.ListAsync(read.CreateCommandContext(), session, cancellationToken);
            await read.CommitAsync(cancellationToken);
        }

        await AdminResponses.JsonAsync(context, new AdminCredentialsResponse
        {
            Credentials =
            [
                .. list.Credentials.Select(c => new AdminCredentialResponse
                {
                    Id = PublicId.Format(PublicIdType.AdminCredential, c.Id),
                    Kind = c.Kind == AdminCredentialKind.Passkey ? "passkey" : "securityKey",
                    BackedUp = c.BackedUp,
                    CreatedAt = c.CreatedAt,
                    LastUsedAt = c.LastUsedAt,
                    Removable = c.Removable,
                }),
            ],
            RecoveryCode = list.RecoveryCode,
        });
    }

    public static async Task RemoveAsync(HttpContext context, AdminApiServices services)
    {
        var session = AdminRequestChecks.Session(context);
        var cancellationToken = context.RequestAborted;

        // A malformed ID names no credential: the same 404 as an unknown or another Admin's.
        if (!PublicId.TryParse(PublicIdType.AdminCredential, context.GetRouteValue(CredentialRouteValue) as string, out var credentialId))
        {
            await AdminResponses.NotFoundAsync(context);
            return;
        }

        var confirmedWith = context.Features.Get<FreshAssertionFeature>()?.CredentialRow;
        CredentialRemovalStatus status;
        try
        {
            await using var scope = await services.BeginAsync(cancellationToken);
            status = await services.Credentials.RemoveAsync(scope.CreateCommandContext(), session, credentialId, confirmedWith, cancellationToken);

            // The removal, the Sessions it ended and its events, kept once decided.
            await scope.CommitAsync(CancellationToken.None);
        }
        catch (DbException e) when (e.SqlState == AdminResponses.RaisedByTrigger)
        {
            // The floor trigger refused the delete: the same answer as the code's own check, rolled back.
            AdminRequestChecks.Log(context, e);
            status = CredentialRemovalStatus.Minimum;
        }

        switch (status)
        {
            case CredentialRemovalStatus.Removed:
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                context.Response.Headers.CacheControl = "no-store";
                return;

            case CredentialRemovalStatus.RemovedSessionEnded:
                context.Response.Headers.SetCookie = AdminResponses.ClearedSessionCookie;
                await AdminResponses.JsonAsync(context, new AdminCredentialRemovalResponse { SessionEnded = true }, cancellationToken: CancellationToken.None);
                return;

            case CredentialRemovalStatus.Minimum:
                context.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger("Gatekeep.Host.Admin")
                    .LogInformation(
                        "A credential removal was refused with {Problem}, trace {TraceId}.",
                        AdminResponses.CredentialsMinimum,
                        AdminResponses.TraceId(context));
                await AdminResponses.ProblemAsync(context, StatusCodes.Status409Conflict, AdminResponses.CredentialsMinimum);
                return;

            default:
                await AdminResponses.NotFoundAsync(context);
                return;
        }
    }
}
