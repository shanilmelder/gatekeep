using System.Buffers;
using System.Data.Common;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>The claim's body: the one-time token, with any surrounding whitespace.</summary>
public sealed class BootstrapClaimRequest
{
    public required string Token { get; init; }
}

/// <summary>A successful claim: the new Admin and their Session's CSRF token.</summary>
public sealed class BootstrapClaimResponse
{
    public required string CsrfToken { get; init; }

    public required Guid AdminId { get; init; }
}

/// <summary>The current Admin Session, with its CSRF token.</summary>
public sealed class AdminSessionResponse
{
    public required Guid AdminId { get; init; }

    /// <summary><c>setup</c> until the Admin's credentials are registered, then <c>full</c>.</summary>
    public required string Kind { get; init; }

    public required bool DeploymentOwner { get; init; }

    /// <summary>Whether the Admin has registered their two WebAuthn credentials. Until then only setup is reachable.</summary>
    public required bool SetupComplete { get; init; }

    /// <summary>The WebAuthn credentials the Admin has registered: credential setup's step is this plus one.</summary>
    public required int Credentials { get; init; }

    public required string CsrfToken { get; init; }
}

/// <summary>The Deployment capabilities the current Admin holds. Story 1.24 fills it.</summary>
public sealed class CapabilitiesResponse
{
    public required IReadOnlyList<string> Capabilities { get; init; }
}

/// <summary>
/// The Admin API's <c>/api/v1/deployment</c> endpoints (Story 1.21). Each is behind the
/// <see cref="AdminRequestChecks"/> and returns only fixed problem codes.
/// </summary>
internal static class AdminApi
{
    /// <summary>A claim body bigger than this is a malformed claim, unread past it.</summary>
    private const int MaxClaimBody = 4096;

    /// <summary>The longest token value read: anything longer is malformed, and isn't copied.</summary>
    private const int MaxTokenBytes = 256;

    private const string LockNotAvailable = "55P03";

    private const string Tag = "Deployment";

    /// <summary>How long a claim's body may take to arrive. It is read before a slot is taken.</summary>
    private static readonly TimeSpan ClaimBodyDeadline = TimeSpan.FromSeconds(10);

    public static IServiceCollection AddAdminApi(this IServiceCollection services)
    {
        services.AddSingleton<AdminApiServices>();

        // The document's numbers are numbers: the endpoints write their own JSON, and never as strings.
        services.ConfigureHttpJsonOptions(static options => options.SerializerOptions.NumberHandling = JsonNumberHandling.Strict);
        services.AddAdminOpenApi();
        return services;
    }

    public static IEndpointRouteBuilder MapAdminApi(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/v1/deployment/bootstrap", static (HttpContext context, AdminApiServices services) => ClaimAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, BootstrapClaimEndpoint.Instance)
            .WithName("ClaimBootstrap")
            .WithTags(Tag)
            .WithSummary("Claim bootstrap with the one-time token and create the first Admin.")
            .WithDescription(
                "Consumes the token from gatekeep init, creates the first Admin as Deployment Owner, completes bootstrap and starts a " +
                "setup-restricted Admin Session in one transaction. Needs the exact Admin Origin, and has no session or CSRF check. " +
                "Each claim is counted per client before the token is compared: the sixth in 15 minutes is 429. Once bootstrap is " +
                "complete, or before init, it is the unknown-path 404.")
            .Produces<BootstrapClaimResponse>(StatusCodes.Status201Created)
            .Produces<ApiProblem>(StatusCodes.Status400BadRequest, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status404NotFound)
            .Produces<ApiProblem>(StatusCodes.Status429TooManyRequests, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapGet("/api/v1/deployment/session", static (HttpContext context, AdminApiServices services) => GetSessionAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, SetupAllowed.Instance)
            .WithName("GetSession")
            .WithTags(Tag)
            .WithSummary("The current Admin Session and its CSRF token.")
            .WithDescription("Setup-allowed and read-only: the CSRF token is the Session's, the same each time and in every tab.")
            .Produces<AdminSessionResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/deployment/credentials/registration", static (HttpContext context, AdminApiServices services) => CredentialRegistrationApi.BeginAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, SetupAllowed.Instance)
            .WithName("BeginCredentialRegistration")
            .WithTags(Tag)
            .WithSummary("Begin registering a WebAuthn credential: the options for navigator.credentials.create.")
            .WithDescription(
                "Setup-allowed. Returns creation options for the Admin RP ID and origin, with no attestation, user verification " +
                "required, a resident key preferred, ES256 and RS256, and the Admin's credentials excluded. Its challenge can be " +
                "answered for 5 minutes, by the next complete call only; a new begin replaces it. Refused with 403 once the Admin " +
                "has two credentials. Each begin and complete counts towards 10 per Session in 15 minutes, then 429.")
            .Produces<CredentialCreationOptionsResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces<ApiProblem>(StatusCodes.Status429TooManyRequests, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/deployment/credentials/registration/complete", static (HttpContext context, AdminApiServices services) => CredentialRegistrationApi.CompleteAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, SetupAllowed.Instance, new JsonRequestBody(typeof(CredentialRegistrationRequest)))
            .WithName("CompleteCredentialRegistration")
            .WithTags(Tag)
            .WithSummary("Complete a WebAuthn credential registration with the browser's attestation response.")
            .WithDescription(
                "Setup-allowed. Verifies the response against the pending challenge, the Admin RP ID and the exact Admin origin, " +
                "and stores the credential. The challenge is used up whatever the outcome. A response for another RP ID or origin, " +
                "a cross-origin one, one without user verification, one with no live challenge and one returning an existing " +
                "credential are 400 credential_refused, with nothing stored. The second credential completes setup: the Session " +
                "becomes full. Refused with 403 once the Admin has two credentials.")
            .Produces<CredentialRegistrationResponse>(StatusCodes.Status200OK)
            .Produces<ApiProblem>(StatusCodes.Status400BadRequest, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces<ApiProblem>(StatusCodes.Status429TooManyRequests, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapDelete("/api/v1/deployment/session", static (HttpContext context, AdminApiServices services) => EndSessionAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance)
            .WithName("EndSession")
            .WithTags(Tag)
            .WithSummary("Sign out: end the current Admin Session.")
            .WithDescription(
                "Ends the Session as signed_out and clears the cookie. Not setup-allowed: a setup Session signing out would leave " +
                "the Deployment Owner unable to finish setup.")
            .Produces(StatusCodes.Status204NoContent)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapGet("/api/v1/deployment/capabilities", static (HttpContext context, AdminApiServices services) => GetCapabilitiesAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance)
            .WithName("GetCapabilities")
            .WithTags(Tag)
            .WithSummary("The Deployment capabilities the current Admin holds.")
            .WithDescription("Not setup-allowed: a setup Session gets 403. Empty until Story 1.24 grants capabilities.")
            .Produces<CapabilitiesResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        return app;
    }

    /// <summary>
    /// The claim, in two transactions: the body is read under <see cref="ClaimBodyDeadline"/>, and
    /// the attempt is counted and committed, before anything is held, so a refused claim's count is
    /// never undone, a 429 compares nothing, and a slow sender holds no slot; then, in one of
    /// <see cref="AdminApiServices.MaxConcurrentClaims"/> slots and holding the row lock, the claim
    /// itself. A client with no address can't be counted on its own, so it is refused with 503.
    /// </summary>
    private static async Task ClaimAsync(HttpContext context, AdminApiServices services)
    {
        if (AdminRequestChecks.Client(context) is not { } client)
        {
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        var cancellationToken = context.RequestAborted;
        var logger = context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Gatekeep.Host.Admin");

        // A body that isn't JSON is a malformed claim, refused and counted like a wrong token.
        var token = IsJson(context.Request) ? await ReadTokenAsync(context.Request, cancellationToken) : [];
        try
        {
            Kernel.RateLimiting.RateLimitDecision decision;
            await using (var count = await services.BeginAsync(cancellationToken))
            {
                decision = await services.Limiter.AttemptAsync(count.CreateCommandContext(), AdminsContract.BootstrapClaimPolicy, client, cancellationToken);
                await count.CommitAsync(cancellationToken);
            }

            if (!decision.Allowed)
            {
                logger.LogInformation("A bootstrap claim was refused with {Code}, trace {TraceId}.", AdminResponses.RateLimited, AdminResponses.TraceId(context));
                context.Response.Headers.RetryAfter = Math.Max(1, (long)Math.Ceiling(decision.RetryAfter.TotalSeconds))
                    .ToString(System.Globalization.CultureInfo.InvariantCulture);
                await AdminResponses.ProblemAsync(context, StatusCodes.Status429TooManyRequests, AdminResponses.RateLimited);
                return;
            }

            if (!services.ClaimSlots.Wait(0))
            {
                await AdminResponses.UnavailableAsync(context);
                return;
            }

            try
            {
                await ClaimInSlotAsync(context, services, token, logger);
            }
            finally
            {
                services.ClaimSlots.Release();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(token);
        }
    }

    private static async Task ClaimInSlotAsync(HttpContext context, AdminApiServices services, byte[] token, ILogger logger)
    {
        var cancellationToken = context.RequestAborted;

        BootstrapClaimResult result;
        DbException? commitFailure = null;
        await using (var scope = await services.BeginAsync(cancellationToken))
        {
            try
            {
                result = await services.Claimer.ClaimAsync(scope.CreateCommandContext(), new Secret<byte[]>(token), cancellationToken);
            }
            catch (DbException e) when (e.SqlState == LockNotAvailable)
            {
                AdminRequestChecks.Log(context, e);
                await AdminResponses.UnavailableAsync(context);
                return;
            }

            if (result.Status == BootstrapClaimStatus.Claimed)
            {
                // The lock is held and every write made: a client gone now mustn't undo it.
                try
                {
                    await scope.CommitAsync(CancellationToken.None);
                }
                catch (DbException e)
                {
                    commitFailure = e;
                }
            }
        }

        BootstrapClaimStatus? status = result.Status;
        if (commitFailure is not null)
        {
            // The server may have applied the commit before the failure reached this process.
            AdminRequestChecks.Log(context, commitFailure);
            status = await CommitOutcomeAsync(services, result.Session!);
            if (status is null)
            {
                await AdminResponses.UnavailableAsync(context);
                return;
            }
        }

        switch (status)
        {
            case BootstrapClaimStatus.Claimed:
                services.BootstrapCompleted();
                var session = result.Session!;

                // Committed: the only Session cookie goes out even if the client has gone.
                context.Response.StatusCode = StatusCodes.Status201Created;
                context.Response.Headers.SetCookie = session.SessionToken.Use(SessionCookie);
                await AdminResponses.JsonAsync(
                    context,
                    new BootstrapClaimResponse
                    {
                        CsrfToken = session.CsrfToken.Use(static t => t),
                        AdminId = session.AdminId,
                    },
                    cancellationToken: CancellationToken.None);
                return;

            case BootstrapClaimStatus.NotFound:
                // Completed by another claim since the checks looked: the same 404.
                await AdminResponses.NotFoundAsync(context);
                return;

            default:
                logger.LogInformation("A bootstrap claim was refused with {Code}, trace {TraceId}.", AdminResponses.BootstrapRefused, AdminResponses.TraceId(context));
                await AdminResponses.ProblemAsync(context, StatusCodes.Status400BadRequest, AdminResponses.BootstrapRefused);
                return;
        }
    }

    /// <summary>
    /// After a commit that failed, what the database says happened: <c>Claimed</c> when this
    /// claim's Session is there, <c>NotFound</c> when bootstrap is complete without it, and null
    /// (a 503) when bootstrap is still open or the database can't say. Reading the state updates
    /// the cached completion flag.
    /// </summary>
    private static async Task<BootstrapClaimStatus?> CommitOutcomeAsync(AdminApiServices services, AdminSessionGrant session)
    {
        try
        {
            if (await services.IsBootstrapOpenAsync(CancellationToken.None))
            {
                return null;
            }

            AdminSession? mine;
            await using (var scope = await services.BeginAsync(CancellationToken.None))
            {
                mine = await services.Sessions.AuthenticateAsync(scope.CreateCommandContext(), session.SessionToken, CancellationToken.None);
                await scope.CommitAsync(CancellationToken.None);
            }

            return mine is null ? BootstrapClaimStatus.NotFound : BootstrapClaimStatus.Claimed;
        }
        catch (DbException)
        {
            return null;
        }
    }

    /// <summary>Whether a request's <c>Content-Type</c> is <c>application/json</c>, with any parameters.</summary>
    internal static bool IsJson(HttpRequest request) =>
        Microsoft.Net.Http.Headers.MediaTypeHeaderValue.TryParse(request.ContentType, out var type)
        && type.MediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase);

    private static Task GetSessionAsync(HttpContext context, AdminApiServices services)
    {
        _ = services;
        var session = AdminRequestChecks.Session(context);
        return AdminResponses.JsonAsync(context, new AdminSessionResponse
        {
            AdminId = session.AdminId,
            Kind = session.Kind == AdminSessionKind.Setup ? "setup" : "full",
            DeploymentOwner = session.DeploymentOwner,
            SetupComplete = session.SetupComplete,
            Credentials = session.Credentials,
            CsrfToken = session.CsrfToken.Use(static t => t),
        });
    }

    private static async Task EndSessionAsync(HttpContext context, AdminApiServices services)
    {
        var session = AdminRequestChecks.Session(context);
        var cancellationToken = context.RequestAborted;

        await using (var scope = await services.BeginAsync(cancellationToken))
        {
            await services.Sessions.EndAsync(scope.CreateCommandContext(), session, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }

        context.Response.StatusCode = StatusCodes.Status204NoContent;
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.SetCookie = AdminResponses.ClearedSessionCookie;
    }

    private static Task GetCapabilitiesAsync(HttpContext context, AdminApiServices services)
    {
        _ = AdminRequestChecks.Session(context);
        _ = services;
        return AdminResponses.JsonAsync(context, new CapabilitiesResponse { Capabilities = [] });
    }

    /// <summary>
    /// A browser session cookie (no Domain, Expires or Max-Age), host-only by its prefix, sent
    /// only over HTTPS, only same-site and never to script.
    /// </summary>
    private static string SessionCookie(string token) =>
        $"{AdminRequestChecks.SessionCookie}={token}; Path=/; Secure; HttpOnly; SameSite=Strict";

    /// <summary>
    /// The claim's <c>token</c> as UTF-8 bytes, copied straight out of the JSON with no string
    /// made of it; the caller zeroes them. Never throws: a body that isn't JSON, is too big, has no
    /// string <c>token</c> or one that can't be read (invalid UTF-8, a lone surrogate), has anything
    /// after its closing brace, or is still arriving after <see cref="ClaimBodyDeadline"/> is no
    /// bytes, which is refused like a wrong token.
    /// </summary>
    private static async Task<byte[]> ReadTokenAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(MaxClaimBody + 1);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(ClaimBodyDeadline);
        try
        {
            var length = 0;
            int read;
            while (length <= MaxClaimBody && (read = await request.Body.ReadAsync(buffer.AsMemory(length, MaxClaimBody + 1 - length), deadline.Token)) > 0)
            {
                length += read;
            }

            return length > MaxClaimBody ? [] : TokenIn(buffer.AsSpan(0, length));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // Too slow a sender: a malformed claim, refused like a wrong token.
            return [];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static byte[] TokenIn(ReadOnlySpan<byte> json)
    {
        byte[]? token = null;
        try
        {
            var reader = new Utf8JsonReader(json, new JsonReaderOptions { MaxDepth = 4 });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return [];
            }

            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                var isToken = reader.ValueTextEquals("token"u8);
                if (!reader.Read())
                {
                    return [];
                }

                if (isToken)
                {
                    if (reader.TokenType != JsonTokenType.String || token is not null)
                    {
                        // A second token is ambiguous: neither is used.
                        if (token is not null)
                        {
                            CryptographicOperations.ZeroMemory(token);
                        }

                        return [];
                    }

                    var bytes = new byte[MaxTokenBytes];
                    int written;
                    try
                    {
                        // Unescaped into a bounded buffer: no string, and anything longer is refused.
                        if (reader.HasValueSequence || reader.ValueSpan.Length > MaxTokenBytes * 6)
                        {
                            return [];
                        }

                        written = reader.CopyString(bytes);
                    }
                    catch (Exception e) when (e is ArgumentException or InvalidOperationException)
                    {
                        CryptographicOperations.ZeroMemory(bytes);
                        return [];
                    }

                    token = bytes[..written];
                    CryptographicOperations.ZeroMemory(bytes);
                }
                else
                {
                    reader.Skip();
                }
            }

            // The object closes, and nothing but whitespace follows it.
            if (token is null || reader.TokenType != JsonTokenType.EndObject || reader.Read())
            {
                if (token is not null)
                {
                    CryptographicOperations.ZeroMemory(token);
                }

                return [];
            }

            return token;
        }
        catch (JsonException)
        {
            if (token is not null)
            {
                CryptographicOperations.ZeroMemory(token);
            }

            return [];
        }
    }
}
