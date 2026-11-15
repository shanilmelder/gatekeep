using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace Gatekeep.Modules.Protocol.Core;

/// <summary>
/// The two Hosted Login cookies (Story 4.2, AD-12): <c>__Host-gk_txn</c>, a sign-in transaction's binding, and
/// <c>__Host-gk_session</c>, a User Session's identifier. Both are <c>Secure; HttpOnly; SameSite=Lax; Path=/</c>
/// with no <c>Domain</c>, so the browser keeps them to the one Tenant host that set them. The transaction
/// cookie lives for the browser session; the Session cookie until the Session's absolute expiry. A refused or
/// ended cookie is cleared with <c>Max-Age=0</c>. A presented value without an opaque value's shape is ignored.
/// </summary>
internal static class SignInCookies
{
    private const string Attributes = "Path=/; Secure; HttpOnly; SameSite=Lax";

    /// <summary>The well-formed value of the request's cookie <paramref name="name"/>, or null.</summary>
    public static Secret<string>? Read(HttpContext http, string name) =>
        http.Request.Cookies.TryGetValue(name, out var value) && OpaqueValues.IsWellFormed(value) ? new Secret<string>(value!) : null;

    public static void SetTransaction(HttpContext http, Secret<string> binding) =>
        Append(http, binding.Use(static v => $"{ProtocolContract.TransactionCookie}={v}; {Attributes}"));

    /// <summary>Sets the Session cookie until <paramref name="absoluteExpiresAt"/>, the Session's absolute expiry.</summary>
    public static void SetSession(HttpContext http, Secret<string> token, DateTimeOffset absoluteExpiresAt, DateTimeOffset now)
    {
        var maxAge = Math.Max(0L, (long)Math.Floor((absoluteExpiresAt - now).TotalSeconds));
        Append(http, token.Use(v => string.Create(
            CultureInfo.InvariantCulture, $"{ProtocolContract.SessionCookie}={v}; {Attributes}; Max-Age={maxAge}")));
    }

    public static void Clear(HttpContext http, string name) =>
        Append(http, $"{name}=; {Attributes}; Max-Age=0");

    private static void Append(HttpContext http, string cookie) =>
        http.Response.Headers.Append(HeaderNames.SetCookie, cookie);
}

/// <summary>
/// Hosted Login's CSRF token (Story 4.2, NFR-4): <c>base64url(SHA-256("gatekeep-signin-csrf\0" || binding))</c>, the
/// binding being the <c>__Host-gk_txn</c> value's ASCII text. Derived, never stored, the same for every step of
/// one transaction, and compared in constant time. <c>SameSite</c> is never relied on in its place.
/// </summary>
internal static class SignInCsrf
{
    private static ReadOnlySpan<byte> Label => "gatekeep-signin-csrf\0"u8;

    public static string Derive(Secret<string> binding) => binding.Use(Derive);

    public static bool Matches(Secret<string> binding, string? presented)
    {
        if (string.IsNullOrEmpty(presented))
        {
            return false;
        }

        var expected = Encoding.ASCII.GetBytes(Derive(binding));
        return CryptographicOperations.FixedTimeEquals(expected, Encoding.UTF8.GetBytes(presented));
    }

    private static string Derive(string binding)
    {
        var value = Encoding.ASCII.GetBytes(binding);
        var input = new byte[Label.Length + value.Length];
        try
        {
            Label.CopyTo(input);
            value.CopyTo(input.AsSpan(Label.Length));
            return Base64Url.EncodeToString(SHA256.HashData(input));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(value);
        }
    }
}

/// <summary>The steps a sign-in transaction stands at, as Hosted Login shows them (Story 4.2).</summary>
internal static class SignInStepResponses
{
    /// <summary>A transaction that can't be used: none, completed, another Application's or not at the step needed.</summary>
    public const string InvalidTransaction = "invalid_transaction";

    /// <summary>No credential step is available after Login's email (Story 4.2, until Story 4.9).</summary>
    public const string TemporarilyUnavailable = "temporarily_unavailable";

    public const string OriginMismatch = "origin_mismatch";

    public const string CsrfMismatch = "csrf_mismatch";

    /// <summary>A Hosted Login API request with no body Protocol can read.</summary>
    public const string InvalidRequest = "invalid_request";

    /// <summary>
    /// The transaction's current step, from the steps it records as passed: Login before its email; once
    /// authenticated, the redirect that resumes the authorization request; between the two, with no credential
    /// step available, Generic error <c>temporarily_unavailable</c>.
    /// </summary>
    public static StepResponse Current(
        ResolvedTenant tenant, SignInTransaction transaction, Secret<string> binding, DateTimeOffset now, string traceId, string? error = null, string? email = null)
    {
        var expiresIn = ExpiresIn(transaction.ExpiresAt, now);
        if (transaction.HasPassed(SignInSteps.Authenticated))
        {
            return StepResponse.Redirect(tenant.Name, transaction.StepVersion, expiresIn, ResumeLocation(transaction.Parameters));
        }

        if (transaction.HasPassed(SignInSteps.Identifier))
        {
            return StepResponse.GenericError(tenant.Name, TemporarilyUnavailable, traceId);
        }

        return StepResponse.Login(tenant.Name, transaction.StepVersion, expiresIn, SignInCsrf.Derive(binding), email ?? transaction.Identifier, error);
    }

    /// <summary>The whole seconds left before <paramref name="expiresAt"/>, never below zero.</summary>
    public static int ExpiresIn(DateTimeOffset expiresAt, DateTimeOffset now) =>
        (int)Math.Clamp(Math.Floor((expiresAt - now).TotalSeconds), 0, int.MaxValue);

    /// <summary>
    /// Where a completed authentication resumes its authorization request (Story 4.2): the authorization endpoint
    /// with the parameters the transaction kept and <c>gk_resume=1</c>, a same-origin path the client opens with a
    /// top-level GET.
    /// </summary>
    public static string ResumeLocation(IReadOnlyDictionary<string, string> parameters)
    {
        var query = parameters
            .Where(p => !string.Equals(p.Key, ProtocolContract.ResumeParameter, StringComparison.Ordinal))
            .Select(p => new KeyValuePair<string, string?>(p.Key, p.Value))
            .Append(new KeyValuePair<string, string?>(ProtocolContract.ResumeParameter, "1"));
        return ProtocolContract.AuthorizePath + QueryString.Create(query);
    }
}

/// <summary>
/// Protocol's sign-in (Story 4.2, AD-12), the one <see cref="IAuthorizationSignIn"/>: a resume completes with its
/// bound, authenticated transaction's Session; otherwise a live, fresh enough Session cookie completes the request
/// at once; otherwise a transaction begins, bound to the browser by <c>__Host-gk_txn</c>, and the request goes to Login.
/// </summary>
internal sealed class HostedAuthorizationSignIn(TokenEndpointServices services) : IAuthorizationSignIn
{
    public async ValueTask<AuthorizationSignInOutcome> SignInAsync(
        CommandContext context,
        AuthorizationSignInRequest request,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(http);

        if (request.Resume)
        {
            return await ResumeAsync(context, request, http, cancellationToken);
        }

        // A reusable Session: live, and fresh enough for prompt=login and max_age. Its idle expiry is touched, unaudited.
        if (SignInCookies.Read(http, ProtocolContract.SessionCookie) is { } presented
            && await services.Sessions.FindLiveAsync(context, presented, cancellationToken) is { } live
            && AuthorizeEndpoint.IsFreshEnough(live.AuthTime, request.AuthenticatedSince, request.ExactFreshness)
            && await services.Sessions.TouchAsync(context, live.SessionId, cancellationToken))
        {
            return new AuthorizationSignInOutcome(
                AuthorizationSignInKind.Completed, new AuthenticationResult(live.SessionId, live.UserId, live.Amr, live.AuthTime));
        }

        var started = await services.Authentication.BeginAsync(
            context, new SignInRequest(request.ApplicationId, request.Parameters), cancellationToken);
        SignInCookies.SetTransaction(http, started.Binding);
        return new AuthorizationSignInOutcome(AuthorizationSignInKind.Login);
    }

    /// <summary>
    /// A resume: the cookie's transaction must be this Application's, authenticated, unexpired and not completed, the
    /// request's kept parameters exactly the ones it stored (so no redirect URI, PKCE challenge or state can be swapped
    /// in by a cross-site GET carrying the cookie), and its Session live. It completes, so it can't be presented again, and its cookie is cleared. Its Session counts
    /// as fresh, whatever <c>prompt=login</c> or <c>max_age</c> demand: the User has just authenticated for this request.
    /// </summary>
    private async ValueTask<AuthorizationSignInOutcome> ResumeAsync(
        CommandContext context, AuthorizationSignInRequest request, HttpContext http, CancellationToken cancellationToken)
    {
        var refused = new AuthorizationSignInOutcome(AuthorizationSignInKind.Refused);
        SignInCookies.Clear(http, ProtocolContract.TransactionCookie);

        if (SignInCookies.Read(http, ProtocolContract.TransactionCookie) is not { } binding
            || await services.Authentication.FindAsync(context, binding, cancellationToken) is not { } transaction
            || transaction.CompletedAt is not null
            || transaction.ApplicationId != request.ApplicationId
            || !SameParameters(transaction.Parameters, request.Parameters)
            || !transaction.HasPassed(SignInSteps.Authenticated)
            || transaction.IsExpiredAt(services.Time.GetUtcNow())
            || transaction.AuthenticatedSessionId is not { } sessionId
            || await services.Sessions.FindLiveAsync(context, sessionId, cancellationToken) is not { } session)
        {
            return refused;
        }

        await services.Authentication.CompleteAsync(context, transaction.Id, request.ApplicationId, cancellationToken);
        return new AuthorizationSignInOutcome(
            AuthorizationSignInKind.Completed, new AuthenticationResult(session.SessionId, session.UserId, session.Amr, session.AuthTime));
    }

    /// <summary>Whether the resumed request keeps exactly the parameters the transaction stored, <c>gk_resume</c> aside.</summary>
    private static bool SameParameters(IReadOnlyDictionary<string, string> stored, IReadOnlyDictionary<string, string> requested)
    {
        var resumed = requested.Where(p => !string.Equals(p.Key, ProtocolContract.ResumeParameter, StringComparison.Ordinal)).ToList();
        return resumed.Count == stored.Count
            && resumed.All(p => stored.TryGetValue(p.Key, out var value) && string.Equals(value, p.Value, StringComparison.Ordinal));
    }
}

/// <summary>
/// Hosted Login's sign-in surface (Story 4.2, FR-47, NFR-4), each request in one Tenant scope as <c>gk_hosted</c>:
/// <list type="bullet">
/// <item><c>GET /login</c>: the step page of the transaction <c>__Host-gk_txn</c> binds, its life slid. An expired,
/// uncompleted one within an hour restarts at Login with its email kept, under a new cookie.</item>
/// <item><c>POST /login/api/identifier</c> and <c>POST /login/api/transaction/extend</c>: an exact-host
/// <c>Origin</c>, then the transaction's CSRF token, are checked before anything is read or written, and each
/// answers a JSON step. A stale <c>stepVersion</c> gets the current step, writing nothing.</item>
/// </list>
/// A transaction that is missing, completed or too long expired is refused: Generic error <c>invalid_transaction</c>,
/// 400, its cookie cleared, and nothing written but <c>authentication.signin_transaction.refused</c>, as a wrong
/// Origin or CSRF token is (403 <c>origin_mismatch</c> or <c>csrf_mismatch</c>).
/// </summary>
internal static class LoginEndpoints
{
    /// <summary>The largest API body read: 4 KiB, ample for a 254-character email.</summary>
    private const int MaxBodyBytes = 4 * 1024;

    public static void Map(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(ProtocolContract.LoginPath, (RequestDelegate)PageAsync);
        endpoints.MapPost(ProtocolContract.LoginIdentifierPath, (RequestDelegate)IdentifierAsync);
        endpoints.MapPost(ProtocolContract.LoginExtendPath, (RequestDelegate)ExtendAsync);
    }

    private static async Task PageAsync(HttpContext http)
    {
        var login = Login.Of(http);
        var binding = SignInCookies.Read(http, ProtocolContract.TransactionCookie);

        await using var scope = await TenantScope.BeginAsync(login.Services.Database.Source, login.Tenant.TenantId, login.Cancellation);
        var context = scope.CreateCommandContext();
        var transaction = binding is null ? null : await login.Services.Authentication.FindAsync(context, binding, login.Cancellation);
        var now = login.Services.Time.GetUtcNow();

        if (binding is null || transaction is null || transaction.CompletedAt is not null
            || transaction.ExpiresAt <= now - SecurityLimits.SignInRestartRetention)
        {
            await login.RefuseAsync(scope, StatusCodes.Status400BadRequest, SignInStepResponses.InvalidTransaction, page: true);
            return;
        }

        // Expired before it completed: a new transaction for the same request, with the email kept.
        if (transaction.IsExpiredAt(now))
        {
            var restarted = await login.Services.Authentication.RestartAsync(context, transaction, login.Cancellation);
            await scope.CommitAsync(login.Cancellation);
            SignInCookies.SetTransaction(http, restarted.Binding);
            var step = StepResponse.Login(
                login.Tenant.Name,
                1,
                SignInStepResponses.ExpiresIn(now + SecurityLimits.SignInTransactionLifetime, now),
                SignInCsrf.Derive(restarted.Binding),
                transaction.Identifier);
            await login.Pages.WriteAsync(http, StatusCodes.Status200OK, step, login.Cancellation);
            return;
        }

        var expiresAt = await login.Services.Authentication.ExtendAsync(context, transaction.Id, login.Cancellation);
        await scope.CommitAsync(login.Cancellation);

        var current = SignInStepResponses.Current(login.Tenant, transaction with { ExpiresAt = expiresAt }, binding, now, login.TraceId);
        await login.Pages.WriteAsync(http, StatusCodes.Status200OK, current, login.Cancellation);
    }

    private static async Task IdentifierAsync(HttpContext http)
    {
        var login = Login.Of(http);
        if (await login.CheckAsync() is not { } binding)
        {
            return;
        }

        using var body = await ReadBodyAsync(http, login.Cancellation);
        if (body is null
            || !body.RootElement.TryGetProperty("stepVersion", out var versionElement)
            || versionElement.ValueKind != JsonValueKind.Number
            || !versionElement.TryGetInt32(out var stepVersion)
            || !body.RootElement.TryGetProperty("email", out var emailElement)
            || emailElement.ValueKind != JsonValueKind.String)
        {
            await login.AnswerAsync(StatusCodes.Status400BadRequest, StepResponse.GenericError(login.Tenant.Name, SignInStepResponses.InvalidRequest, login.TraceId));
            return;
        }

        var input = emailElement.GetString();
        await using var scope = await TenantScope.BeginAsync(login.Services.Database.Source, login.Tenant.TenantId, login.Cancellation);
        var context = scope.CreateCommandContext();
        if (await login.UsableAsync(scope, binding) is not { } transaction)
        {
            return;
        }

        var now = login.Services.Time.GetUtcNow();

        // A stale step version, or a transaction already past Login: the current step, and nothing written.
        if (stepVersion != transaction.StepVersion || transaction.CompletedSteps.Count != 0)
        {
            await login.AnswerAsync(StatusCodes.Status200OK, SignInStepResponses.Current(login.Tenant, transaction, binding, now, login.TraceId));
            return;
        }

        if (!AuthenticationContract.TryNormalizeEmail(input, out var email))
        {
            var invalid = SignInStepResponses.Current(
                login.Tenant, transaction, binding, now, login.TraceId, LoginErrors.EmailInvalid, input?.Trim() ?? string.Empty);
            await login.AnswerAsync(StatusCodes.Status200OK, invalid);
            return;
        }

        var identified = await login.Services.Authentication.IdentifyAsync(
            context, transaction, email, SignInCookies.Read(http, ProtocolContract.SessionCookie), login.Cancellation);
        await scope.CommitAsync(login.Cancellation);

        StepResponse next;
        if (identified.Session is { } session)
        {
            SignInCookies.SetSession(http, session.Token, session.AbsoluteExpiresAt, login.Services.Time.GetUtcNow());
            next = StepResponse.Redirect(
                login.Tenant.Name,
                identified.StepVersion,
                SignInStepResponses.ExpiresIn(identified.ExpiresAt, now),
                SignInStepResponses.ResumeLocation(transaction.Parameters));
        }
        else
        {
            next = StepResponse.GenericError(login.Tenant.Name, SignInStepResponses.TemporarilyUnavailable, login.TraceId);
        }

        await login.AnswerAsync(StatusCodes.Status200OK, next);
    }

    private static async Task ExtendAsync(HttpContext http)
    {
        var login = Login.Of(http);
        if (await login.CheckAsync() is not { } binding)
        {
            return;
        }

        await using var scope = await TenantScope.BeginAsync(login.Services.Database.Source, login.Tenant.TenantId, login.Cancellation);
        var context = scope.CreateCommandContext();
        if (await login.UsableAsync(scope, binding) is not { } transaction)
        {
            return;
        }

        var expiresAt = await login.Services.Authentication.ExtendAsync(context, transaction.Id, login.Cancellation);
        await scope.CommitAsync(login.Cancellation);

        var now = login.Services.Time.GetUtcNow();
        await login.AnswerAsync(
            StatusCodes.Status200OK, SignInStepResponses.Current(login.Tenant, transaction with { ExpiresAt = expiresAt }, binding, now, login.TraceId));
    }

    /// <summary>The request body as JSON, or null when it is missing, too large or not a JSON object.</summary>
    private static async Task<JsonDocument?> ReadBodyAsync(HttpContext http, CancellationToken cancellationToken)
    {
        if (http.Request.ContentLength is > MaxBodyBytes)
        {
            return null;
        }

        var buffer = new byte[MaxBodyBytes + 1];
        var read = 0;
        while (read < buffer.Length)
        {
            var count = await http.Request.Body.ReadAsync(buffer.AsMemory(read), cancellationToken);
            if (count == 0)
            {
                break;
            }

            read += count;
        }

        if (read == 0 || read > MaxBodyBytes)
        {
            return null;
        }

        try
        {
            var document = JsonDocument.Parse(buffer.AsMemory(0, read));
            if (document.RootElement.ValueKind == JsonValueKind.Object)
            {
                return document;
            }

            document.Dispose();
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>One Hosted Login request: its resolved Tenant, Protocol's services and the host's step pages.</summary>
    private sealed record Login(HttpContext Http, ResolvedTenant Tenant, TokenEndpointServices Services, IStepPages Pages)
    {
        public CancellationToken Cancellation => Http.RequestAborted;

        public string TraceId => Pages.TraceId(Http);

        public static Login Of(HttpContext http) => new(
            http,
            http.Features.Get<ResolvedTenant>() ?? throw new InvalidOperationException("Hosted Login runs only on a resolved Tenant."),
            http.RequestServices.GetRequiredService<TokenEndpointServices>(),
            http.RequestServices.GetRequiredService<IStepPages>());

        /// <summary>
        /// A state-changing request's checks, before anything is read or written: the <c>Origin</c> must be exactly the
        /// Tenant's issuer origin (scheme, host and port), then <c>X-Gatekeep-CSRF</c> the token derived from the
        /// request's <c>__Host-gk_txn</c>. The binding when both pass; otherwise the request is refused with 403.
        /// </summary>
        public async Task<Secret<string>?> CheckAsync()
        {
            if (ExpectedOrigin(Tenant) is not { } expected || !string.Equals(SingleHeader(Http, "Origin"), expected, StringComparison.Ordinal))
            {
                await RefuseChecksAsync(SignInStepResponses.OriginMismatch);
                return null;
            }

            var binding = SignInCookies.Read(Http, ProtocolContract.TransactionCookie);
            if (binding is null || !SignInCsrf.Matches(binding, SingleHeader(Http, ProtocolContract.CsrfHeader)))
            {
                await RefuseChecksAsync(SignInStepResponses.CsrfMismatch);
                return null;
            }

            return binding;
        }

        /// <summary>
        /// The binding's transaction when it can still move on: unexpired and uncompleted. A missing, completed or too long
        /// expired one is refused; an expired one gets the redirect to <c>/login</c>, which restarts it, with nothing written.
        /// </summary>
        public async Task<SignInTransaction?> UsableAsync(TenantScope scope, Secret<string> binding)
        {
            var transaction = await Services.Authentication.FindAsync(scope.CreateCommandContext(), binding, Cancellation);
            var now = Services.Time.GetUtcNow();
            if (transaction is null || transaction.CompletedAt is not null || transaction.ExpiresAt <= now - SecurityLimits.SignInRestartRetention)
            {
                await RefuseAsync(scope, StatusCodes.Status400BadRequest, SignInStepResponses.InvalidTransaction, page: false);
                return null;
            }

            if (transaction.IsExpiredAt(now))
            {
                await AnswerAsync(StatusCodes.Status200OK, StepResponse.Redirect(Tenant.Name, transaction.StepVersion, 0, ProtocolContract.LoginPath));
                return null;
            }

            return transaction;
        }

        /// <summary>
        /// Refuses the transaction: its work undone, the refusal's event kept through a fresh scope, its cookie cleared,
        /// and Generic error with <paramref name="code"/>, as a page or as JSON.
        /// </summary>
        public async Task RefuseAsync(TenantScope scope, int statusCode, string code, bool page)
        {
            await FailureContext.CommitAfterRollbackAsync(scope, Services.Authentication.RefuseAsync);
            SignInCookies.Clear(Http, ProtocolContract.TransactionCookie);
            var step = StepResponse.GenericError(Tenant.Name, code, TraceId);
            if (page)
            {
                await Pages.WriteAsync(Http, statusCode, step, Cancellation);
            }
            else
            {
                await AnswerAsync(statusCode, step);
            }
        }

        public Task AnswerAsync(int statusCode, StepResponse step) => Pages.WriteJsonAsync(Http, statusCode, step, Cancellation);

        /// <summary>A failed Origin or CSRF check: nothing was read, and only the refusal's event is written, through a fresh scope.</summary>
        private async Task RefuseChecksAsync(string code)
        {
            Services.Logger?.LogInformation("A Hosted Login request was refused: {Code}.", code);
            await using (var scope = await TenantScope.BeginAsync(Services.Database.Source, Tenant.TenantId, Cancellation))
            {
                await FailureContext.CommitAfterRollbackAsync(scope, Services.Authentication.RefuseAsync);
            }

            await AnswerAsync(StatusCodes.Status403Forbidden, StepResponse.GenericError(Tenant.Name, code, TraceId));
        }

        /// <summary>The request's one value of header <paramref name="name"/>, or null for none or several.</summary>
        private static string? SingleHeader(HttpContext http, string name)
        {
            var values = http.Request.Headers[name];
            return values.Count == 1 ? values[0] : null;
        }

        /// <summary>The Tenant's issuer origin, scheme, host and port, from its stored issuer only, never the request.</summary>
        private static string? ExpectedOrigin(ResolvedTenant tenant) =>
            Uri.TryCreate(tenant.Issuer, UriKind.Absolute, out var issuer) ? issuer.GetLeftPart(UriPartial.Authority) : null;
    }
}
