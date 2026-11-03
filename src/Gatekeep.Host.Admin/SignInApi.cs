using System.Buffers;
using System.Buffers.Text;
using System.Data.Common;
using System.Text.Json;
using System.Text.Json.Serialization;
using Gatekeep.Adapters.Hosting;
using Gatekeep.Kernel.RateLimiting;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Kernel.WebAuthn;
using Gatekeep.Modules.Admins.Contracts;
using Microsoft.Extensions.Primitives;

namespace Gatekeep.Host.Admin;

/// <summary>
/// The request options for <c>navigator.credentials.get</c>, in WebAuthn's JSON form: the
/// challenge is base64url with no padding.
/// </summary>
public sealed class AdminSignInOptionsResponse
{
    /// <summary>32 random bytes, answerable once within 5 minutes, by the browser holding the binding cookie.</summary>
    public required string Challenge { get; init; }

    /// <summary>The Admin hostname.</summary>
    public required string RpId { get; init; }

    /// <summary>Milliseconds the browser may wait for the authenticator.</summary>
    public required long Timeout { get; init; }

    /// <summary>Always <c>required</c>.</summary>
    public required string UserVerification { get; init; }

    /// <summary>
    /// Always empty: the credential is discoverable, and no credential ID goes to a caller who
    /// hasn't signed in. Typed as WebAuthn's credential descriptor, the same as registration's.
    /// </summary>
    public required IReadOnlyList<RegistrationExcludedCredential> AllowCredentials { get; init; }
}

/// <summary>The browser's assertion response, in WebAuthn's JSON form: binary values as base64url.</summary>
public sealed class AdminSignInRequest
{
    public required string Id { get; init; }

    public required string RawId { get; init; }

    /// <summary>Always <c>public-key</c>.</summary>
    public required string Type { get; init; }

    public required AdminSignInAssertionResponse Response { get; init; }
}

/// <summary>The assertion itself: the client data, the authenticator data, the signature and the user handle.</summary>
public sealed class AdminSignInAssertionResponse
{
    [JsonPropertyName("clientDataJSON")]
    public required string ClientDataJson { get; init; }

    public required string AuthenticatorData { get; init; }

    public required string Signature { get; init; }

    /// <summary>The credential owner's user handle, which a discoverable credential returns. A sign-in without one is refused.</summary>
    public string? UserHandle { get; init; }
}

/// <summary>A sign-in: the Admin, their new Session's CSRF token, and whether they have finished credential setup.</summary>
public sealed class AdminSignInResponse
{
    public required Guid AdminId { get; init; }

    public required string CsrfToken { get; init; }

    /// <summary>Whether the Admin has their two credentials. Until then the Session reaches only setup.</summary>
    public required bool SetupComplete { get; init; }
}

/// <summary>
/// Admin sign-in with WebAuthn (Story 1.23): begin and complete, both sessionless and behind the
/// <see cref="AdminRequestChecks"/>' Origin check. Each is counted per client under its policy,
/// in its own committed transaction, before it runs. The Relying Party is the Admin origin's: its
/// host is the RP ID, given on every call. Every refused complete is the same 400 <c>signin_refused</c>.
/// </summary>
internal static class SignInApi
{
    /// <summary>An assertion body bigger than this is malformed, unread past it.</summary>
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
        if (AdminRequestChecks.Client(context) is not { } client)
        {
            // Not countable on its own, so not served: nothing is counted or stored.
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        var cancellationToken = context.RequestAborted;
        if (!await CountAsync(context, services, AdminsContract.SignInBeginPolicy, client))
        {
            return;
        }

        AdminSignInStart start;
        await using (var scope = await services.BeginAsync(cancellationToken))
        {
            start = await services.SignIn.BeginAsync(
                scope.CreateCommandContext(), RelyingParty(context), Cookie(context, AdminRequestChecks.SignInCookie), cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }

        var options = start.Options;
        context.Response.Headers.SetCookie = start.Binding.Use(AdminResponses.SignInCookie);
        await AdminResponses.JsonAsync(
            context,
            new AdminSignInOptionsResponse
            {
                Challenge = Base64Url.EncodeToString(options.Challenge),
                RpId = options.RpId,
                Timeout = options.TimeoutMilliseconds,
                UserVerification = options.UserVerification,
                AllowCredentials =
                [
                    .. options.AllowCredentials.Select(c => new RegistrationExcludedCredential
                    {
                        Type = c.Type,
                        Id = Base64Url.EncodeToString(c.Id),
                        Transports = c.Transports,
                    }),
                ],
            },
            cancellationToken: CancellationToken.None);
    }

    public static async Task CompleteAsync(HttpContext context, AdminApiServices services)
    {
        if (AdminRequestChecks.Client(context) is not { } client)
        {
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        var cancellationToken = context.RequestAborted;
        if (!await CountAsync(context, services, AdminsContract.SignInCompletePolicy, client))
        {
            return;
        }

        // Counted, so the challenge is taken now, before the body is read, in a transaction of
        // its own, kept even if the client goes: it is used up whatever happens next, a slow or
        // malformed body, a refusal, a constraint or a fault. Only a 429 or a missing client
        // address, above, leave it live.
        byte[]? challenge;
        await using (var take = await services.BeginAsync(cancellationToken))
        {
            challenge = await services.SignIn.TakeChallengeAsync(
                take.CreateCommandContext(), Cookie(context, AdminRequestChecks.SignInCookie), CancellationToken.None);
            await take.CommitAsync(CancellationToken.None);
        }

        // Whatever comes next, the binding has answered: every response from here clears it, a 503 too.
        context.Items[AdminResponses.SignInChallengeTaken] = true;
        context.Response.Headers.SetCookie = AdminResponses.ClearedSignInCookie;

        // A body that isn't JSON, or can't be read, is a refused sign-in.
        var assertion = AdminApi.IsJson(context.Request) ? await ReadAssertionAsync(context.Request, cancellationToken) : null;

        if (challenge is null || assertion is null)
        {
            await RefusedAsync(context, assertion is null ? WebAuthnRefusal.Malformed : WebAuthnRefusal.ChallengeMismatch, audited: false);
            return;
        }

        AdminSignInOutcome outcome;
        try
        {
            await using var scope = await services.BeginAsync(cancellationToken);
            outcome = await services.SignIn.FinishAsync(
                scope.CreateCommandContext(),
                RelyingParty(context),
                challenge,
                assertion,
                Cookie(context, AdminRequestChecks.SessionCookie),
                cancellationToken);

            // A Session, or a refusal's event: either is kept once decided, if the client goes now.
            await scope.CommitAsync(CancellationToken.None);
        }
        catch (DbException e) when (e.SqlState is UniqueViolation or CheckViolation)
        {
            // A value a constraint refuses: rolled back, so no Session, and the challenge is already gone.
            AdminRequestChecks.Log(context, e);
            await RefusedAsync(context, null, audited: false);
            return;
        }

        if (outcome is not { Status: AdminSignInStatus.SignedIn, Session: { } session })
        {
            await RefusedAsync(context, outcome.Refusal, outcome.Audited);
            return;
        }

        // Committed: the Session cookie goes out even if the client has gone.
        context.Response.Headers.SetCookie = new StringValues(
            [session.SessionToken.Use(AdminResponses.SessionCookie), AdminResponses.ClearedSignInCookie]);
        await AdminResponses.JsonAsync(
            context,
            new AdminSignInResponse
            {
                AdminId = session.AdminId,
                CsrfToken = session.CsrfToken.Use(static t => t),
                SetupComplete = outcome.SetupComplete,
            },
            cancellationToken: CancellationToken.None);
    }

    /// <summary>The Admin origin's Relying Party: its host is the RP ID, and the origin is the one a response must name.</summary>
    private static WebAuthnRelyingParty RelyingParty(HttpContext context)
    {
        var origin = context.RequestServices.GetRequiredService<HostOrigin>().Value;
        return new WebAuthnRelyingParty(new Uri(origin).IdnHost, RelyingPartyName, origin);
    }

    /// <summary>A cookie's value as a secret, or null when it wasn't sent or is empty.</summary>
    private static Secret<string>? Cookie(HttpContext context, string name) =>
        context.Request.Cookies.TryGetValue(name, out var value) && !string.IsNullOrEmpty(value) ? new Secret<string>(value) : null;

    /// <summary>Counts the attempt per client in its own transaction, and answers 429 when it is over the limit.</summary>
    private static async Task<bool> CountAsync(HttpContext context, AdminApiServices services, RateLimitPolicy policy, string client)
    {
        var cancellationToken = context.RequestAborted;
        RateLimitDecision decision;
        await using (var count = await services.BeginAsync(cancellationToken))
        {
            decision = await services.Limiter.AttemptAsync(count.CreateCommandContext(), policy, client, cancellationToken);
            await count.CommitAsync(cancellationToken);
        }

        if (decision.Allowed)
        {
            return true;
        }

        Logger(context).LogInformation(
            "An Admin sign-in was refused with {Problem} under {Policy}, trace {TraceId}.",
            AdminResponses.RateLimited,
            policy.Code,
            AdminResponses.TraceId(context));
        context.Response.Headers.RetryAfter = Math.Max(1, (long)Math.Ceiling(decision.RetryAfter.TotalSeconds))
            .ToString(System.Globalization.CultureInfo.InvariantCulture);
        await AdminResponses.ProblemAsync(context, StatusCodes.Status429TooManyRequests, AdminResponses.RateLimited);
        return false;
    }

    private static Task RefusedAsync(HttpContext context, WebAuthnRefusal? refusal, bool audited)
    {
        // The reason is a fixed name, and only here: the response never says why.
        Logger(context).LogInformation(
            "An Admin sign-in was refused with {Problem} ({Refusal}, audited {Audited}), trace {TraceId}.",
            AdminResponses.SignInRefused,
            refusal?.ToString() ?? "constraint",
            audited,
            AdminResponses.TraceId(context));
        return AdminResponses.ProblemAsync(context, StatusCodes.Status400BadRequest, AdminResponses.SignInRefused);
    }

    private static ILogger Logger(HttpContext context) =>
        context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Gatekeep.Host.Admin");

    /// <summary>
    /// The assertion in the body, decoded, or null for anything malformed: not JSON, too big, too
    /// slow, missing a member, not <c>public-key</c>, an ID that isn't its raw ID, or a value that
    /// isn't base64url. Never throws.
    /// </summary>
    private static async Task<WebAuthnAssertion?> ReadAssertionAsync(HttpRequest request, CancellationToken cancellationToken)
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
            // IOException): a refused sign-in, never a fault.
            return null;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static WebAuthnAssertion? Parse(ReadOnlySpan<byte> body)
    {
        AdminSignInRequest? request;
        try
        {
            request = JsonSerializer.Deserialize<AdminSignInRequest>(body, Json);
        }
        catch (JsonException)
        {
            return null;
        }

        if (request?.Response is not { } response || request.Type != "public-key"
            || request.Id is null || request.RawId is null || response.ClientDataJson is null
            || response.AuthenticatorData is null || response.Signature is null)
        {
            return null;
        }

        if (Decode(request.RawId) is not { Length: > 0 } rawId || request.Id != Base64Url.EncodeToString(rawId)
            || Decode(response.ClientDataJson) is not { Length: > 0 } clientData
            || Decode(response.AuthenticatorData) is not { Length: > 0 } authenticatorData
            || Decode(response.Signature) is not { Length: > 0 } signature)
        {
            return null;
        }

        // An absent handle reaches the ceremony, which refuses it; one that isn't base64url is malformed.
        byte[]? userHandle = null;
        if (response.UserHandle is { } encoded && (userHandle = Decode(encoded)) is null)
        {
            return null;
        }

        return new WebAuthnAssertion(rawId, clientData, authenticatorData, signature, userHandle);
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
