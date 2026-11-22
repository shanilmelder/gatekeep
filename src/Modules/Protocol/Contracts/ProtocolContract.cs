using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Protocol.Adapters;
using Gatekeep.Modules.Protocol.Core;
using Gatekeep.Modules.Tenancy.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;

namespace Gatekeep.Modules.Protocol.Contracts;

/// <summary>
/// Each Tenant's own OpenID Provider on Host.Hosted (Stories 2.3, 2.5, 2.9, 2.10 and 2.11, AD-8, AD-9): OpenIddict
/// 7.7.2, wrapped per Tenant. It serves discovery, JWKS, the authorization endpoint (the code flow with
/// S256 PKCE only), the token endpoint (Client Credentials, the authorization code grant and its
/// rotating refresh tokens), userinfo and revocation.
/// </summary>
public static class ProtocolContract
{
    public const string ConfigurationPath = "/.well-known/openid-configuration";

    public const string JsonWebKeySetPath = "/.well-known/jwks";

    public const string TokenPath = "/connect/token";

    /// <summary>The authorization endpoint (Story 2.9): the code flow with S256 PKCE, and nothing else.</summary>
    public const string AuthorizePath = "/connect/authorize";

    /// <summary>
    /// The userinfo endpoint (Story 2.11, OIDC Core §5.3): GET or POST with this Tenant's access token as a
    /// bearer in the <c>Authorization</c> header only. It answers exactly <c>{"sub": "usr_…"}</c>.
    /// </summary>
    public const string UserinfoPath = "/connect/userinfo";

    /// <summary>
    /// The revocation endpoint (Story 2.11, RFC 7009): a client ends its own refresh token's Token Family.
    /// Access and ID tokens aren't revocable (AD-13) and get <c>unsupported_token_type</c>.
    /// </summary>
    public const string RevocationPath = "/connect/revoke";

    /// <summary>Hosted Login's step page (Story 4.2): the current step of the browser's sign-in transaction.</summary>
    public const string LoginPath = "/login";

    /// <summary>Login's identifier step (Story 4.2): <c>{stepVersion, email}</c>, answered with a step.</summary>
    public const string LoginIdentifierPath = "/login/api/identifier";

    /// <summary>"Keep going" (Story 4.2): slides the sign-in transaction's life, answered with the current step.</summary>
    public const string LoginExtendPath = "/login/api/transaction/extend";

    /// <summary>"Sign up" at Login (Story 4.7): <c>{stepVersion, email}</c>, answered with Signup when sign-up is open.</summary>
    public const string SignupOpenPath = "/login/api/signup/open";

    /// <summary>"Already have an account? Log in" at Signup (Story 4.7): <c>{stepVersion}</c>, answered with Login, the email kept.</summary>
    public const string SignupBackPath = "/login/api/signup/back";

    /// <summary>"Create account" (Story 4.7): <c>{stepVersion, email, password}</c>, answered with Email verification required.</summary>
    public const string SignupPath = "/login/api/signup";

    /// <summary>"Resend email" (Story 4.7): <c>{stepVersion}</c>, answered with Email verification required, resent.</summary>
    public const string VerificationResendPath = "/login/api/verification/resend";

    /// <summary>"I've verified, continue" (Story 4.7): <c>{stepVersion}</c>, answered with the redirect once the email is verified.</summary>
    public const string VerificationContinuePath = "/login/api/verification/continue";

    /// <summary>
    /// The verification link's page (Story 4.7): <c>GET /login/verify-email?token=</c>, Email verified or Link expired. It is
    /// the email template's <c>login/verify-email</c>, under the Tenant's email link base.
    /// </summary>
    public const string VerifyEmailPath = "/login/verify-email";

    /// <summary>"Send a new link" (Story 4.7): <c>{token}</c> with the link-bound CSRF token, always answered with the neutral confirmation.</summary>
    public const string VerificationNewLinkPath = "/login/api/verification/new-link";

    /// <summary>The cookie binding a sign-in transaction to the browser (Story 4.2): host-only, Secure, HttpOnly, SameSite=Lax.</summary>
    public const string TransactionCookie = "__Host-gk_txn";

    /// <summary>The User Session cookie (Story 4.2): host-only, Secure, HttpOnly, SameSite=Lax, until the Session's absolute expiry.</summary>
    public const string SessionCookie = "__Host-gk_session";

    /// <summary>The header every Hosted Login state-changing request carries its CSRF token in (Story 4.2).</summary>
    public const string CsrfHeader = "X-Gatekeep-CSRF";

    /// <summary>The authorization parameter a completed sign-in resumes the request with (Story 4.2). It never reaches the client.</summary>
    public const string ResumeParameter = "gk_resume";

    /// <summary>The <c>kid</c> of the global signing credential, which is inert: no Tenant's JWKS or token carries it.</summary>
    public const string InertSigningKeyId = InertCredentials.SigningKeyId;

    /// <summary>The <c>kid</c> of the global encryption credential, which is inert as well.</summary>
    public const string InertEncryptionKeyId = InertCredentials.EncryptionKeyId;

    /// <summary>
    /// Registers the OpenIddict server, its stores and the Tenant runtimes. Its global options hold only
    /// inert credentials, which throw on any use; the first Gatekeep handler swaps in the request's Tenant
    /// options, built from the same options pipeline, with that Tenant's stored issuer, its Signing
    /// Keys through Transit and its unwrapped token protection key, read in a short read-only Tenant
    /// scope as <c>gk_hosted</c> through <paramref name="hostedConnectionString"/>, read on first use.
    /// The authorization and token endpoints run as <c>gk_hosted</c> too, in one transaction per request.
    /// Key custody is the host's <c>IKeyCustody</c>, and audit the host's <c>IAuditAppender</c>. The token
    /// request limits are <see cref="TokenRequestLimits"/>'s, unless the host registered its own first.
    /// The authorization endpoint completes a sign-in through <see cref="IAuthorizationSignIn"/>, Protocol's own
    /// (Story 4.2). The step after Login's email is the host's <c>ICredentialStep</c> when it registered one (only
    /// tests do), Authentication's release default otherwise, which offers none.
    /// <paramref name="stepPages"/> builds the host's Hosted Login step pages (AD-21, Story 4.1), which the
    /// authorization endpoint shows Generic error through for a request it can't send back to any client, and
    /// Hosted Login's <c>/login</c> surface its steps through. Sign-up (Story 4.7) enqueues its verification email through the
    /// host's <c>IJobEnqueuer</c>, which the host must register, and hashes within <see cref="PasswordHashLimits"/>, the
    /// defaults unless the host registered its own first.
    /// </summary>
    public static IServiceCollection AddGatekeepProtocol(
        this IServiceCollection services,
        Func<IServiceProvider, string> hostedConnectionString,
        Func<IServiceProvider, IStepPages> stepPages)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(hostedConnectionString);
        ArgumentNullException.ThrowIfNull(stepPages);

        services.AddSingleton<ITenantKeyReader>(provider => new TenantKeyReader(() => hostedConnectionString(provider)));

        // One listening connection, as gk_hosted, started on the first Tenant request (Story 2.4).
        services.AddSingleton<ITenantKeyChanges>(provider => new SigningKeyChangeListener(
            () => hostedConnectionString(provider),
            provider.GetService<Microsoft.Extensions.Logging.ILogger<SigningKeyChangeListener>>()));
        services.AddSingleton<IStepPages>(stepPages);

        // Story 4.2: the one sign-in, over the bound sign-in transaction and the Session cookie.
        services.AddSingleton<IAuthorizationSignIn, HostedAuthorizationSignIn>();
        ProtocolServer.Add(services, hostedConnectionString);
        return services;
    }

    /// <summary>
    /// Runs OpenIddict on the request, after Tenant resolution and before routing, then the authorization
    /// endpoint's passthrough, which completes a validated authorization request. A path OpenIddict
    /// doesn't serve passes through to whatever follows.
    /// </summary>
    public static IApplicationBuilder UseGatekeepProtocol(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        app.UseAuthentication();
        return app.Use(AuthorizePassthrough.InvokeAsync);
    }

    /// <summary>
    /// Hosted Login's sign-in surface (Story 4.2), after routing, on the resolved Tenant only: <c>GET /login</c>,
    /// the step page of the transaction the <c>__Host-gk_txn</c> cookie binds, and the state-changing API
    /// requests, <c>POST /login/api/identifier</c>, <c>POST /login/api/transaction/extend</c> and Story 4.7's sign-up and
    /// verification requests, each checked for an exact-host <c>Origin</c> and the transaction's CSRF token before anything
    /// is read or written; and Story 4.7's verification link page, <c>GET /login/verify-email</c>, whose "Send a new link"
    /// is checked for the <c>Origin</c> and a CSRF token bound to the link.
    /// </summary>
    public static IEndpointRouteBuilder MapGatekeepLogin(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        LoginEndpoints.Map(endpoints);
        return endpoints;
    }
}

/// <summary>
/// The sign-in seam of the authorization endpoint (Stories 2.9 and 4.2, AD-8, AD-12). For a validated
/// authorization request it decides, in the request's own Tenant context, whether the request completes now,
/// goes to Hosted Login, or is refused, setting or clearing the request's sign-in cookies as it does:
/// <list type="bullet">
/// <item>A resume (<c>gk_resume</c>) completes with the Session of the transaction its <c>__Host-gk_txn</c>
/// cookie binds, when that transaction is this Application's, authenticated and not completed; its Session
/// counts as fresh. Any other resume is refused.</item>
/// <item>Otherwise a live <c>__Host-gk_session</c> fresh enough for <c>prompt=login</c> and <c>max_age</c>
/// completes the request at once, its idle expiry touched.</item>
/// <item>Otherwise a new transaction starts, bound to this browser, Tenant and Application, and the request
/// goes to Login.</item>
/// </list>
/// Its one implementation in <c>src</c> is Protocol's own, registered by <see cref="ProtocolContract.AddGatekeepProtocol"/>.
/// </summary>
public interface IAuthorizationSignIn
{
    /// <summary>What <paramref name="request"/>, validated on <paramref name="http"/>, comes to.</summary>
    /// <exception cref="ArgumentException">The request's parameters can't be kept. Nothing is written.</exception>
    ValueTask<AuthorizationSignInOutcome> SignInAsync(
        CommandContext context,
        AuthorizationSignInRequest request,
        HttpContext http,
        CancellationToken cancellationToken);
}

/// <summary>
/// A validated authorization request, as the sign-in seam sees it (Story 4.2): its Application, the parameters a
/// transaction keeps, the freshness <c>prompt=login</c> and <c>max_age</c> demand (Story 2.11), whether that
/// freshness is compared exactly (<c>prompt=login</c>), and whether it is a resume.
/// </summary>
public sealed record AuthorizationSignInRequest(
    Guid ApplicationId,
    IReadOnlyDictionary<string, string> Parameters,
    DateTimeOffset? AuthenticatedSince,
    bool ExactFreshness,
    bool Resume);

/// <summary>What an authorization request's sign-in came to (Story 4.2).</summary>
public enum AuthorizationSignInKind
{
    /// <summary>The User is signed in: a code is issued for <see cref="AuthorizationSignInOutcome.Result"/>.</summary>
    Completed,

    /// <summary>A new transaction began, and the request goes to Login, keeping that transaction.</summary>
    Login,

    /// <summary>The resume's transaction is refused: Generic error <c>invalid_transaction</c>, keeping only the refusal's event.</summary>
    Refused,
}

/// <summary>An authorization request's sign-in outcome, with the completed authentication's result.</summary>
public sealed record AuthorizationSignInOutcome(AuthorizationSignInKind Kind, AuthenticationResult? Result = null);

/// <summary>
/// A Tenant's OpenIddict options, as its requests use them: a copy of the Deployment's options
/// with that Tenant's issuer and credentials. A copy is kept for at most five seconds and never
/// when building it failed.
/// </summary>
public interface ITenantServerOptions
{
    /// <exception cref="Gatekeep.Kernel.Secrets.KeyCustodyException">Key custody failed.</exception>
    /// <exception cref="TimeoutException">Key custody or the database didn't answer in time.</exception>
    /// <exception cref="InvalidOperationException">The Tenant's stored issuer or keys can't be served.</exception>
    ValueTask<OpenIddictServerOptions> GetAsync(ResolvedTenant tenant, CancellationToken cancellationToken);
}

/// <summary>
/// The limits a Tenant's token endpoint counts every request under, before its client is
/// authenticated (Story 2.5, AD-14): per Tenant and per source. The defaults are Authentication's
/// policies, from the §5.2 limits; a host registers its own only to test them.
/// </summary>
public sealed record TokenRequestLimits(Gatekeep.Kernel.RateLimiting.RateLimitPolicy Tenant, Gatekeep.Kernel.RateLimiting.RateLimitPolicy Source);

/// <summary>
/// The limits Hosted Login's sign-up counts under (Story 4.8, NFR-6): Create account per Tenant and per source, and the
/// verification emails asked for ("Resend email" and "Send a new link" together) per Tenant and per source. None is keyed
/// by an email address, so a limit can't reveal an account. The defaults are <see cref="Default"/>, from
/// <c>SecurityLimits</c>; a host registers its own only to test them.
/// </summary>
public sealed record SignUpLimits(
    Gatekeep.Kernel.RateLimiting.RateLimitPolicy SignUpTenant,
    Gatekeep.Kernel.RateLimiting.RateLimitPolicy SignUpSource,
    Gatekeep.Kernel.RateLimiting.RateLimitPolicy SendTenant,
    Gatekeep.Kernel.RateLimiting.RateLimitPolicy SendSource)
{
    /// <summary>Create account per Tenant: <c>signup.attempt.tenant</c>, 600 per 15 minutes.</summary>
    public static readonly Gatekeep.Kernel.RateLimiting.RateLimitPolicy SignUpTenantPolicy = new(
        "signup.attempt.tenant", Gatekeep.Kernel.Limits.SecurityLimits.SignUpTenantAttempts, Gatekeep.Kernel.Limits.SecurityLimits.SignUpWindow);

    /// <summary>Create account per source: <c>signup.attempt.source</c>, 10 per 15 minutes.</summary>
    public static readonly Gatekeep.Kernel.RateLimiting.RateLimitPolicy SignUpSourcePolicy = new(
        "signup.attempt.source", Gatekeep.Kernel.Limits.SecurityLimits.SignUpSourceAttempts, Gatekeep.Kernel.Limits.SecurityLimits.SignUpWindow);

    /// <summary>Resend and "Send a new link" per Tenant: <c>verification.send.tenant</c>, 600 per 15 minutes.</summary>
    public static readonly Gatekeep.Kernel.RateLimiting.RateLimitPolicy SendTenantPolicy = new(
        "verification.send.tenant", Gatekeep.Kernel.Limits.SecurityLimits.VerificationSendTenantAttempts, Gatekeep.Kernel.Limits.SecurityLimits.SignUpWindow);

    /// <summary>Resend and "Send a new link" per source: <c>verification.send.source</c>, 10 per 15 minutes.</summary>
    public static readonly Gatekeep.Kernel.RateLimiting.RateLimitPolicy SendSourcePolicy = new(
        "verification.send.source", Gatekeep.Kernel.Limits.SecurityLimits.VerificationSendSourceAttempts, Gatekeep.Kernel.Limits.SecurityLimits.SignUpWindow);

    public static SignUpLimits Default { get; } = new(SignUpTenantPolicy, SignUpSourcePolicy, SendTenantPolicy, SendSourcePolicy);
}
