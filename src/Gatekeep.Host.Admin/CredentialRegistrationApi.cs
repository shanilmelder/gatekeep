using System.Buffers;
using System.Buffers.Text;
using System.Data.Common;
using System.Text.Json;
using System.Text.Json.Serialization;
using Gatekeep.Adapters.Hosting;
using Gatekeep.Kernel.WebAuthn;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>
/// The creation options for <c>navigator.credentials.create</c>, in WebAuthn's JSON form: every
/// binary value is base64url with no padding.
/// </summary>
public sealed class CredentialCreationOptionsResponse
{
    public required RegistrationRelyingParty Rp { get; init; }

    public required RegistrationUser User { get; init; }

    /// <summary>32 random bytes, answerable once within 5 minutes.</summary>
    public required string Challenge { get; init; }

    public required IReadOnlyList<RegistrationPublicKeyParameter> PubKeyCredParams { get; init; }

    /// <summary>Milliseconds the browser may wait for the authenticator.</summary>
    public required long Timeout { get; init; }

    /// <summary>Always <c>none</c>: no attestation is asked for.</summary>
    public required string Attestation { get; init; }

    public required RegistrationAuthenticatorSelection AuthenticatorSelection { get; init; }

    /// <summary>The Admin's existing credentials, which the authenticator mustn't hold.</summary>
    public required IReadOnlyList<RegistrationExcludedCredential> ExcludeCredentials { get; init; }
}

/// <summary>The Relying Party: the Admin hostname as RP ID, and its name.</summary>
public sealed class RegistrationRelyingParty
{
    public required string Id { get; init; }

    public required string Name { get; init; }
}

/// <summary>The account: the Admin's random 64-byte user handle, base64url, and what the authenticator shows.</summary>
public sealed class RegistrationUser
{
    public required string Id { get; init; }

    public required string Name { get; init; }

    public required string DisplayName { get; init; }
}

/// <summary>An allowed algorithm: ES256 (-7) or RS256 (-257).</summary>
public sealed class RegistrationPublicKeyParameter
{
    public required string Type { get; init; }

    public required int Alg { get; init; }
}

/// <summary>A resident key and user verification are both required: every Admin credential is discoverable, for sign-in.</summary>
public sealed class RegistrationAuthenticatorSelection
{
    public required string ResidentKey { get; init; }

    public required string UserVerification { get; init; }
}

/// <summary>An existing credential, by its base64url ID, with the transports it reported when it was registered.</summary>
public sealed class RegistrationExcludedCredential
{
    public required string Type { get; init; }

    public required string Id { get; init; }

    public required IReadOnlyList<string> Transports { get; init; }
}

/// <summary>The browser's attestation response, in WebAuthn's JSON form: binary values as base64url.</summary>
public sealed class CredentialRegistrationRequest
{
    public required string Id { get; init; }

    public required string RawId { get; init; }

    /// <summary>Always <c>public-key</c>.</summary>
    public required string Type { get; init; }

    public required CredentialAttestationResponse Response { get; init; }
}

/// <summary>The attestation itself: the client data, the attestation object and the transports the browser reports.</summary>
public sealed class CredentialAttestationResponse
{
    [JsonPropertyName("clientDataJSON")]
    public required string ClientDataJson { get; init; }

    public required string AttestationObject { get; init; }

    public IReadOnlyList<string>? Transports { get; init; }
}

/// <summary>A stored credential: how many the Admin has, and whether that completed setup.</summary>
public sealed class CredentialRegistrationResponse
{
    public required int Credentials { get; init; }

    public required bool SetupComplete { get; init; }
}

/// <summary>
/// Admin WebAuthn credential registration (Story 1.22): begin and complete, both setup-allowed
/// and behind the <see cref="AdminRequestChecks"/>. Each is counted per Session under
/// <see cref="AdminsContract.CredentialRegistrationPolicy"/>, in its own transaction, before it
/// runs. The Relying Party is the Admin origin's: its host is the RP ID, given on every call.
/// </summary>
internal static class CredentialRegistrationApi
{
    /// <summary>An attestation body bigger than this is malformed, unread past it.</summary>
    private const int MaxBody = 64 * 1024;

    private const string UniqueViolation = "23505";

    private const string CheckViolation = "23514";

    private const string RelyingPartyName = "Gatekeep";

    /// <summary>How long a complete call's body may take to arrive.</summary>
    private static readonly TimeSpan BodyDeadline = TimeSpan.FromSeconds(10);

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 8,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip,
    };

    public static async Task BeginAsync(HttpContext context, AdminApiServices services)
    {
        var session = AdminRequestChecks.Session(context);
        var cancellationToken = context.RequestAborted;
        if (!await CountAsync(context, services, session))
        {
            return;
        }

        CredentialRegistrationStart start;
        await using (var scope = await services.BeginAsync(cancellationToken))
        {
            start = await services.Registration.BeginAsync(scope.CreateCommandContext(), session, RelyingParty(context), cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }

        if (start.Status == CredentialRegistrationStatus.SessionEnded)
        {
            await AdminResponses.UnauthorizedAsync(context, clearCookie: true);
            return;
        }

        if (start.Status != CredentialRegistrationStatus.Accepted || start.Options is not { } options)
        {
            await AdminResponses.ForbiddenAsync(context);
            return;
        }

        await AdminResponses.JsonAsync(context, new CredentialCreationOptionsResponse
        {
            Rp = new RegistrationRelyingParty { Id = options.RelyingParty.Id, Name = options.RelyingParty.Name },
            User = new RegistrationUser
            {
                Id = Base64Url.EncodeToString(options.User.Handle),
                Name = options.User.Name,
                DisplayName = options.User.DisplayName,
            },
            Challenge = Base64Url.EncodeToString(options.Challenge),
            PubKeyCredParams = [.. options.PublicKeyParameters.Select(p => new RegistrationPublicKeyParameter { Type = p.Type, Alg = p.Algorithm })],
            Timeout = options.TimeoutMilliseconds,
            Attestation = options.Attestation,
            AuthenticatorSelection = new RegistrationAuthenticatorSelection
            {
                ResidentKey = options.ResidentKey,
                UserVerification = options.UserVerification,
            },
            ExcludeCredentials =
            [
                .. options.ExcludeCredentials.Select(c => new RegistrationExcludedCredential
                {
                    Type = c.Type,
                    Id = Base64Url.EncodeToString(c.Id),
                    Transports = c.Transports,
                }),
            ],
        });
    }

    public static async Task CompleteAsync(HttpContext context, AdminApiServices services)
    {
        var session = AdminRequestChecks.Session(context);
        var cancellationToken = context.RequestAborted;
        if (!await CountAsync(context, services, session))
        {
            return;
        }

        // A body that isn't JSON, or can't be read, is a refused finish: its challenge still goes.
        var attestation = AdminApi.IsJson(context.Request) ? await ReadAttestationAsync(context.Request, cancellationToken) : null;

        // The challenge is taken in a transaction of its own, kept before anything is verified,
        // so it is used up whatever happens next: a refusal, a constraint, a fault.
        CredentialRegistrationChallenge challenge;
        await using (var take = await services.BeginAsync(cancellationToken))
        {
            challenge = await services.Registration.TakeChallengeAsync(take.CreateCommandContext(), session, cancellationToken);
            await take.CommitAsync(cancellationToken);
        }

        switch (challenge.Status)
        {
            case CredentialRegistrationStatus.SessionEnded:
                await AdminResponses.UnauthorizedAsync(context, clearCookie: true);
                return;
            case CredentialRegistrationStatus.Complete:
                await AdminResponses.ForbiddenAsync(context);
                return;
        }

        if (challenge.ChallengeSha256 is not { } challengeSha256 || attestation is null)
        {
            await RefusedAsync(context, attestation is null ? WebAuthnRefusal.Malformed : WebAuthnRefusal.ChallengeMismatch);
            return;
        }

        CredentialRegistrationOutcome outcome;
        try
        {
            await using var scope = await services.BeginAsync(cancellationToken);
            outcome = await services.Registration.FinishAsync(
                scope.CreateCommandContext(), session, RelyingParty(context), challengeSha256, attestation, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (e.SqlState is UniqueViolation or CheckViolation)
        {
            // The same credential stored by another Admin since the check, or a value a CHECK
            // refuses: rolled back, so nothing is stored, and the challenge is already gone.
            AdminRequestChecks.Log(context, e);
            await RefusedAsync(context, null);
            return;
        }

        switch (outcome.Status)
        {
            case CredentialRegistrationStatus.Accepted:
                await AdminResponses.JsonAsync(context, new CredentialRegistrationResponse
                {
                    Credentials = outcome.Credentials,
                    SetupComplete = outcome.SetupComplete,
                });
                return;

            case CredentialRegistrationStatus.Refused:
                await RefusedAsync(context, outcome.Refusal);
                return;

            default:
                await AdminResponses.ForbiddenAsync(context);
                return;
        }
    }

    /// <summary>The Admin origin's Relying Party: its host is the RP ID, and the origin is the one a response must name.</summary>
    private static WebAuthnRelyingParty RelyingParty(HttpContext context)
    {
        var origin = context.RequestServices.GetRequiredService<HostOrigin>().Value;
        return new WebAuthnRelyingParty(new Uri(origin).IdnHost, RelyingPartyName, origin);
    }

    /// <summary>Counts the attempt in its own transaction, and answers 429 when it is over the limit.</summary>
    private static async Task<bool> CountAsync(HttpContext context, AdminApiServices services, AdminSession session)
    {
        var cancellationToken = context.RequestAborted;
        Kernel.RateLimiting.RateLimitDecision decision;
        await using (var count = await services.BeginAsync(cancellationToken))
        {
            decision = await services.Limiter.AttemptAsync(
                count.CreateCommandContext(),
                AdminsContract.CredentialRegistrationPolicy,
                session.Id.ToString("N"),
                cancellationToken);
            await count.CommitAsync(cancellationToken);
        }

        if (decision.Allowed)
        {
            return true;
        }

        Logger(context).LogInformation(
            "A credential registration was refused with {Problem}, trace {TraceId}.",
            AdminResponses.RateLimited,
            AdminResponses.TraceId(context));
        context.Response.Headers.RetryAfter = Math.Max(1, (long)Math.Ceiling(decision.RetryAfter.TotalSeconds))
            .ToString(System.Globalization.CultureInfo.InvariantCulture);
        await AdminResponses.ProblemAsync(context, StatusCodes.Status429TooManyRequests, AdminResponses.RateLimited);
        return false;
    }

    private static Task RefusedAsync(HttpContext context, WebAuthnRefusal? refusal)
    {
        // The reason is a fixed name: nothing from the response reaches the log.
        Logger(context).LogInformation(
            "A credential registration was refused with {Problem} ({Refusal}), trace {TraceId}.",
            AdminResponses.CredentialRefused,
            refusal?.ToString() ?? "constraint",
            AdminResponses.TraceId(context));
        return AdminResponses.ProblemAsync(context, StatusCodes.Status400BadRequest, AdminResponses.CredentialRefused);
    }

    private static ILogger Logger(HttpContext context) =>
        context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Gatekeep.Host.Admin");

    /// <summary>
    /// The attestation in the body, decoded, or null for anything malformed: not JSON, too big,
    /// too slow, missing a member, not <c>public-key</c>, an ID that isn't its raw ID, or a value
    /// that isn't base64url. Never throws.
    /// </summary>
    private static async Task<WebAuthnAttestation?> ReadAttestationAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(MaxBody + 1);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(BodyDeadline);
        try
        {
            var length = 0;
            int read;
            while (length <= MaxBody && (read = await request.Body.ReadAsync(buffer.AsMemory(length, MaxBody + 1 - length), deadline.Token)) > 0)
            {
                length += read;
            }

            return length > MaxBody ? null : Parse(buffer.AsSpan(0, length));
        }
        catch (Exception e) when (!cancellationToken.IsCancellationRequested
            && e is OperationCanceledException or IOException)
        {
            // Too slow, cut off or malformed on the wire (BadHttpRequestException is an
            // IOException): a refused finish, never a fault.
            return null;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static WebAuthnAttestation? Parse(ReadOnlySpan<byte> body)
    {
        CredentialRegistrationRequest? request;
        try
        {
            request = JsonSerializer.Deserialize<CredentialRegistrationRequest>(body, Json);
        }
        catch (JsonException)
        {
            return null;
        }

        if (request?.Response is not { } response || request.Type != "public-key"
            || request.Id is null || request.RawId is null || response.ClientDataJson is null || response.AttestationObject is null)
        {
            return null;
        }

        if (Decode(request.RawId) is not { Length: > 0 } rawId || request.Id != Base64Url.EncodeToString(rawId)
            || Decode(response.ClientDataJson) is not { Length: > 0 } clientData
            || Decode(response.AttestationObject) is not { Length: > 0 } attestationObject)
        {
            return null;
        }

        return new WebAuthnAttestation(rawId, clientData, attestationObject, [.. (response.Transports ?? []).OfType<string>()]);
    }

    private static byte[]? Decode(string value)
    {
        try
        {
            return Base64Url.DecodeFromChars(value);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
