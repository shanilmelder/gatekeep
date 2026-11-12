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

    /// <summary>
    /// <c>setup</c> until the Admin's credentials are registered, then <c>full</c>; <c>recovery</c> after a
    /// Recovery Code, which reaches only credential registration until one is registered.
    /// </summary>
    public required string Kind { get; init; }

    public required bool DeploymentOwner { get; init; }

    /// <summary>Whether the Admin has registered their two WebAuthn credentials. Until then only setup is reachable.</summary>
    public required bool SetupComplete { get; init; }

    /// <summary>The WebAuthn credentials the Admin has registered: credential setup's step is this plus one.</summary>
    public required int Credentials { get; init; }

    /// <summary>
    /// Whether credential setup may offer an offline Recovery Code instead of a second credential: only
    /// in a setup Session of an Admin who isn't the Deployment Owner, with one credential and no code.
    /// </summary>
    public required bool RecoveryCodeAllowed { get; init; }

    public required string CsrfToken { get; init; }
}

/// <summary>The capabilities the current Admin holds, Deployment-wide or in the path Tenant, in the table's order (Story 1.24).</summary>
public sealed class CapabilitiesResponse
{
    public required IReadOnlyList<string> Capabilities { get; init; }
}

/// <summary>
/// The Admin API's <c>/api/v1/deployment</c> (Story 1.21) and <c>/api/v1/tenants/{tenantId}</c>
/// (Story 1.24) endpoints: every API route is mapped here, and nowhere else. Each is behind the
/// <see cref="AdminRequestChecks"/>, declares exactly one access kind, and returns only fixed
/// problem codes.
/// </summary>
internal static class AdminApi
{
    /// <summary>A claim body bigger than this is a malformed claim, unread past it.</summary>
    private const int MaxClaimBody = 4096;

    /// <summary>The longest token value read: anything longer is malformed, and isn't copied.</summary>
    private const int MaxTokenBytes = 256;

    private const string LockNotAvailable = "55P03";

    private const string Tag = "Deployment";

    private const string TenantTag = "Tenants";

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

        app.MapPost("/api/v1/deployment/signin", static (HttpContext context, AdminApiServices services) => SignInApi.BeginAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, SignInEndpoint.Instance)
            .WithName("BeginSignIn")
            .WithTags(Tag)
            .WithSummary("Begin an Admin sign-in with WebAuthn: the options for navigator.credentials.get.")
            .WithDescription(
                "Sessionless: needs the exact Admin Origin, and has no session or CSRF check. Returns request options for the Admin " +
                "RP ID with user verification required and no allowed credentials listed: the credential is discoverable, so no " +
                "username is asked for and no credential ID is sent. Sets the __Host-gk-admin-signin cookie that binds the challenge " +
                "to this browser; it can be answered once, within 5 minutes, and a new begin replaces it. Each begin is counted per " +
                "client: the 21st in 15 minutes is 429. Before bootstrap completes it is the unknown-path 404.")
            .Produces<AdminSignInOptionsResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status404NotFound)
            .Produces<ApiProblem>(StatusCodes.Status429TooManyRequests, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/deployment/signin/complete", static (HttpContext context, AdminApiServices services) => SignInApi.CompleteAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, SignInEndpoint.Instance, new JsonRequestBody(typeof(AdminSignInRequest)))
            .WithName("CompleteSignIn")
            .WithTags(Tag)
            .WithSummary("Complete an Admin sign-in with the browser's WebAuthn assertion, and start a full Admin Session.")
            .WithDescription(
                "Sessionless: needs the exact Admin Origin and the __Host-gk-admin-signin cookie from the begin. Once the call is " +
                "counted, the challenge that cookie names is taken before the body is read, so it is used up whatever follows, and " +
                "every response clears the cookie. A 429, or a 503 for a missing client address, comes before that and leaves the " +
                "challenge live. Verifies the assertion against the Admin RP ID, the exact " +
                "Admin origin and the registered credential it names, with user verification, the credential owner's user handle " +
                "and a signature counter that advances. Every refusal is the same 400 signin_refused, with no Session. A sign-in " +
                "starts a full Session; an Admin without two credentials still reaches only setup. A live Session this browser " +
                "held is ended as superseded. Each complete is counted per client, a success too: the 11th in 15 minutes is 429. " +
                "Before bootstrap completes it is the unknown-path 404.")
            .Produces<AdminSignInResponse>(StatusCodes.Status200OK)
            .Produces<ApiProblem>(StatusCodes.Status400BadRequest, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status404NotFound)
            .Produces<ApiProblem>(StatusCodes.Status429TooManyRequests, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapGet("/api/v1/deployment/session", static (HttpContext context, AdminApiServices services) => GetSessionAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, SelfService.Instance, SetupAllowed.Instance, RecoveryAllowed.Instance)
            .WithName("GetSession")
            .WithTags(Tag)
            .WithSummary("The current Admin Session and its CSRF token.")
            .WithDescription(
                "Setup-allowed and recovery-allowed, and read-only: the CSRF token is the Session's, the same each time and in " +
                "every tab. recoveryCodeAllowed says whether credential setup may offer an offline Recovery Code.")
            .Produces<AdminSessionResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/deployment/credentials/registration", static (HttpContext context, AdminApiServices services) => CredentialRegistrationApi.BeginAsync(context, services))
            .WithMetadata(
                DeploymentApiEndpoint.Instance,
                SelfService.Instance,
                SetupAllowed.Instance,
                RecoveryAllowed.Instance,
                new RequiresFreshAssertion(AdminFreshAssertions.SelfCredentialsAdd, inHandler: true))
            .WithName("BeginCredentialRegistration")
            .WithTags(Tag)
            .WithSummary("Begin registering a WebAuthn credential: the options for navigator.credentials.create.")
            .WithDescription(
                "Setup-allowed. Returns creation options for the Admin RP ID and origin, with no attestation, user verification " +
                "required, a resident key required, ES256 and RS256, and the Admin's credentials excluded. Its challenge can be " +
                "answered for 5 minutes, by the next complete call only; a new begin replaces it. In a setup or recovery Session it " +
                "needs nothing more: a setup Session registers while its Admin is below the floor of two credentials, or one and a " +
                "Recovery Code, and is refused with a bodiless 403 after; a recovery Session registers once. In a full Session it " +
                "adds a credential: it is 409 credentials_maximum at 10, before anything else, then needs a fresh assertion for " +
                "self.credentials.add, which it uses up, or is 403 fresh_assertion_required. Each begin and complete counts " +
                "towards 10 per Session in 15 minutes, then 429.")
            .Produces<CredentialCreationOptionsResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces<ApiProblem>(StatusCodes.Status409Conflict, AdminResponses.ProblemContentType)
            .Produces<ApiProblem>(StatusCodes.Status429TooManyRequests, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/deployment/credentials/registration/complete", static (HttpContext context, AdminApiServices services) => CredentialRegistrationApi.CompleteAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, SelfService.Instance, SetupAllowed.Instance, RecoveryAllowed.Instance, new JsonRequestBody(typeof(CredentialRegistrationRequest)))
            .WithName("CompleteCredentialRegistration")
            .WithTags(Tag)
            .WithSummary("Complete a WebAuthn credential registration with the browser's attestation response.")
            .WithDescription(
                "Setup-allowed. Verifies the response against the pending challenge, the Admin RP ID and the exact Admin origin, " +
                "and stores the credential. The challenge is used up whatever the outcome. A response for another RP ID or origin, " +
                "a cross-origin one, one without user verification, one with no live challenge and one returning an existing " +
                "credential are 400 credential_refused, with nothing stored. The challenge is taken before the body is read. A " +
                "credential that brings the Admin to the floor completes setup, and one registered in a recovery Session ends it: " +
                "the Session becomes full. Refused with a bodiless 403 when a restricted Session's Admin already meets the floor, " +
                "and 409 credentials_maximum at 10.")
            .Produces<CredentialRegistrationResponse>(StatusCodes.Status200OK)
            .Produces<ApiProblem>(StatusCodes.Status400BadRequest, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces<ApiProblem>(StatusCodes.Status409Conflict, AdminResponses.ProblemContentType)
            .Produces<ApiProblem>(StatusCodes.Status429TooManyRequests, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapDelete("/api/v1/deployment/session", static (HttpContext context, AdminApiServices services) => EndSessionAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, SelfService.Instance, SetupAllowed.Instance, RecoveryAllowed.Instance)
            .WithName("EndSession")
            .WithTags(Tag)
            .WithSummary("Sign out: end the current Admin Session.")
            .WithDescription(
                "Ends the Session as signed_out, writes admin.session.signed_out, and clears the cookie. Setup-allowed and " +
                "recovery-allowed: any Session can always sign out. A Deployment Owner who signs out of setup before registering a " +
                "credential can't sign in again without gatekeep recover-admin.")
            .Produces(StatusCodes.Status204NoContent)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapGet("/api/v1/deployment/capabilities", static (HttpContext context, AdminApiServices services) => GetCapabilitiesAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, SelfService.Instance)
            .WithName("GetCapabilities")
            .WithTags(Tag)
            .WithSummary("The Deployment capabilities the current Admin holds.")
            .WithDescription(
                "Self-service: any Admin may read their own list. Every Deployment capability for the Deployment Owner, in the " +
                "table's order, and none for any other Admin: a Tenant Role grants no Deployment capability. Not setup-allowed: a " +
                "setup Session gets 403.")
            .Produces<CapabilitiesResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapGet("/api/v1/tenants/{tenantId}/capabilities",static (HttpContext context, AdminApiServices services) => GetTenantCapabilitiesAsync(context, services))
            .WithMetadata(TenantApiEndpoint.Instance, new RequiresCapability(AdminCapabilities.TenantConfigurationRead))
            .WithName("GetTenantCapabilities")
            .WithTags(TenantTag)
            .WithSummary("The Tenant capabilities the current Admin holds in the path Tenant.")
            .WithDescription(
                "The Tenant is the tenantId path segment, its public ID, and nothing else: no Session, cookie or header names one. " +
                "Returns the capabilities the Admin's Tenant Role there holds, in the table's order. Being Deployment Owner adds " +
                "nothing in a Tenant. A malformed, unknown or role-less Tenant is the same 403 access_denied, and writes " +
                "admin.access.denied while the Admin is within 30 audited refusals in 15 minutes, and is only logged past that. " +
                "A setup-restricted Session, a wrong Origin or a wrong CSRF token gets a bodiless 403 first. The role is read " +
                "once per request, by the check that allows it, and the list is answered from that same read.")
            .Produces<CapabilitiesResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/deployment/assertions", static (HttpContext context, AdminApiServices services) => FreshAssertionApi.BeginAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, SelfService.Instance, new JsonRequestBody(typeof(FreshAssertionBeginRequest)))
            .WithName("BeginFreshAssertion")
            .WithTags(Tag)
            .WithSummary("Begin confirming a sensitive action with a fresh WebAuthn assertion: the options for navigator.credentials.get.")
            .WithDescription(
                "Self-service, full Sessions only. The body names the action, a Deployment capability whose fresh assertion isn't " +
                "never or self.credentials.add or self.credentials.remove, and its target exactly as the action's request will name " +
                "it, or null. An unknown action, a Tenant capability or a body that isn't JSON is 400 assertion_refused; a Deployment " +
                "capability the Admin doesn't hold is 403 access_denied, counted and audited as the request checks do. Returns " +
                "request options for the Admin RP ID with user verification required and no credential listed. The challenge can be " +
                "answered once, within 5 minutes, and a new begin replaces it and any unused grant for the same action and target. " +
                "Each begin and complete counts towards 10 per Session in 15 minutes, then 429.")
            .Produces<AdminSignInOptionsResponse>(StatusCodes.Status200OK)
            .Produces<ApiProblem>(StatusCodes.Status400BadRequest, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces<ApiProblem>(StatusCodes.Status429TooManyRequests, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/deployment/assertions/complete", static (HttpContext context, AdminApiServices services) => FreshAssertionApi.CompleteAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, SelfService.Instance, new JsonRequestBody(typeof(AdminSignInRequest)))
            .WithName("CompleteFreshAssertion")
            .WithTags(Tag)
            .WithSummary("Complete a fresh WebAuthn assertion, leaving a grant on the Session for the begin's action and target.")
            .WithDescription(
                "Self-service, full Sessions only. Once counted, the Session's pending challenge is taken before the body is read, " +
                "so it is used up whatever follows. Verifies the assertion as sign-in does, against one of the Session's own " +
                "Admin's credentials, with user verification, their user handle and a signature counter that advances. A pass " +
                "stores a grant bound to this Session and the begin's action and target for 5 minutes, writes " +
                "admin.fresh_assertion.verified and is 204. The grant is used up by the first request it matches, whatever that " +
                "request then does. Every refusal is the same 400 assertion_refused, with no grant.")
            .Produces(StatusCodes.Status204NoContent)
            .Produces<ApiProblem>(StatusCodes.Status400BadRequest, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces<ApiProblem>(StatusCodes.Status429TooManyRequests, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapGet("/api/v1/deployment/credentials", static (HttpContext context, AdminApiServices services) => CredentialsApi.ListAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, SelfService.Instance)
            .WithName("ListCredentials")
            .WithTags(Tag)
            .WithSummary("Your credentials: the current Admin's own WebAuthn credentials, oldest first.")
            .WithDescription(
                "Self-service, full Sessions only. Each credential's acr_ public ID, kind, backup state, when it was added and last " +
                "used, and whether removing it would keep the floor of two; and whether the Admin holds a confirmed, unused " +
                "Recovery Code. Never a WebAuthn credential ID, public key, AAGUID, counter or user handle.")
            .Produces<AdminCredentialsResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapDelete("/api/v1/deployment/credentials/{credentialId}", static (HttpContext context, AdminApiServices services) => CredentialsApi.RemoveAsync(context, services))
            .WithMetadata(
                DeploymentApiEndpoint.Instance,
                SelfService.Instance,
                new RequiresFreshAssertion(AdminFreshAssertions.SelfCredentialsRemove, CredentialsApi.CredentialRouteValue))
            .WithName("RemoveCredential")
            .WithTags(Tag)
            .WithSummary("Remove one of the current Admin's own WebAuthn credentials.")
            .WithDescription(
                "Self-service, full Sessions only, after a fresh assertion for self.credentials.remove with this credentialId as " +
                "its target, which the request checks use up before anything else, or 403 fresh_assertion_required. A malformed, " +
                "unknown or another Admin's credential is 404. A removal that would leave fewer than two credentials is 409 " +
                "credentials_minimum. Otherwise it deletes the credential, ends every other live Session of the Admin as revoked, " +
                "writes admin.credential.removed and is 204; this Session stays. When the credential removed is the one whose " +
                "fresh assertion confirmed it, this Session ends too: 200 with sessionEnded true, and the cookie cleared.")
            .Produces(StatusCodes.Status204NoContent)
            .Produces<AdminCredentialRemovalResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status404NotFound)
            .Produces<ApiProblem>(StatusCodes.Status409Conflict, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/deployment/credentials/recovery-code", static (HttpContext context, AdminApiServices services) => RecoveryCodeApi.IssueAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, SelfService.Instance, SetupAllowed.Instance)
            .WithName("IssueRecoveryCode")
            .WithTags(Tag)
            .WithSummary("Issue an offline Recovery Code in place of a second credential, shown this once.")
            .WithDescription(
                "Setup-allowed, and only in a setup Session of an Admin who isn't the Deployment Owner, with exactly one credential " +
                "and no confirmed code; otherwise a bodiless 403. Returns the code once, never cached; only its HMAC under the " +
                "Deployment hmac key is stored, unconfirmed, replacing any unconfirmed one. It can't be redeemed until confirmed. " +
                "A key custody failure is 503 with nothing stored.")
            .Produces<AdminRecoveryCodeResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/deployment/credentials/recovery-code/confirm", static (HttpContext context, AdminApiServices services) => RecoveryCodeApi.ConfirmAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, SelfService.Instance, SetupAllowed.Instance, new JsonRequestBody(typeof(RecoveryCodeConfirmRequest)))
            .WithName("ConfirmRecoveryCode")
            .WithTags(Tag)
            .WithSummary("Confirm the offline Recovery Code was saved, which completes credential setup.")
            .WithDescription(
                "Setup-allowed, under the same rule as the issue; otherwise a bodiless 403. The body names the issueId the issue " +
                "returned: when it isn't the Admin's current unconfirmed code, as after a later issue, it is 409 " +
                "recovery_code_superseded and nothing changes. Confirms the code, writes admin.recovery_code.issued, makes the " +
                "Admin's setup Sessions full, writes admin.setup.completed and is 204.")
            .Produces(StatusCodes.Status204NoContent)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces<ApiProblem>(StatusCodes.Status409Conflict, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/deployment/signin/recovery-code", static (HttpContext context, AdminApiServices services) => RecoveryCodeApi.RedeemAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, SignInEndpoint.Instance, new JsonRequestBody(typeof(RecoveryCodeRedeemRequest)))
            .WithName("RedeemRecoveryCode")
            .WithTags(Tag)
            .WithSummary("Sign in with an offline Recovery Code, to a Session that reaches only credential registration.")
            .WithDescription(
                "Sessionless: needs the exact Admin Origin only. Each call is counted Deployment-wide, then per client, before the " +
                "code is read: the 51st across the Deployment, or a client's 6th, in 15 minutes is 429. A confirmed, unused code is used up, every live Session of its Admin ends as revoked, " +
                "a live Session this browser held is superseded, and a recovery Session starts, which reaches only the Session " +
                "read, sign-out and credential registration until one credential is registered, which ends every other Session " +
                "of the Admin; admin.recovery_code.used is written. A " +
                "wrong, unconfirmed, used or malformed code is the same 400 recovery_code_refused. A key custody failure is 503 " +
                "with nothing used. Before bootstrap completes it is the unknown-path 404.")
            .Produces<AdminSignInResponse>(StatusCodes.Status200OK)
            .Produces<ApiProblem>(StatusCodes.Status400BadRequest, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status404NotFound)
            .Produces<ApiProblem>(StatusCodes.Status429TooManyRequests, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/deployment/signin/enrolment", static (HttpContext context, AdminApiServices services) => EnrolmentApi.RedeemAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, SignInEndpoint.Instance, new JsonRequestBody(typeof(EnrolmentRedeemRequest)))
            .WithName("RedeemEnrolment")
            .WithTags(Tag)
            .WithSummary("Sign in with a gatekeep recover-admin enrolment, to a Session that reaches only credential registration.")
            .WithDescription(
                "Sessionless: needs the exact Admin Origin only. No route issues an enrolment: only gatekeep recover-admin on the " +
                "Docker host does, after its Security Alert and off-server record are confirmed. Each call is counted " +
                "per client, then, while the client is within its limit, Deployment-wide, before the value is looked up: a " +
                "client's 6th, or the 51st counted across the Deployment, in 15 minutes is 429. An unused enrolment within its " +
                "15 minutes is used up, with every other unused one of its Admin, every live Session of its Admin " +
                "ends as revoked, a live Session this browser held is superseded, and a Session starts that reaches only the " +
                "Session read, sign-out and credential registration: setup, needing two credentials, for an Admin below the " +
                "credential floor, and recovery, needing one, otherwise; admin.enrolment.used is written. An unknown, used, " +
                "expired or malformed value is the same 400 enrolment_refused. Before bootstrap completes it is the unknown-path 404.")
            .Produces<AdminSignInResponse>(StatusCodes.Status200OK)
            .Produces<ApiProblem>(StatusCodes.Status400BadRequest, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status404NotFound)
            .Produces<ApiProblem>(StatusCodes.Status429TooManyRequests, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapGet("/api/v1/deployment/tenants", static (HttpContext context, AdminApiServices services) => TenantsApi.ListAsync(context, services))
            .WithMetadata(
                DeploymentApiEndpoint.Instance,
                new RequiresCapability(AdminCapabilities.DeploymentTenantsRead),
                new QueryParameter(TenantsApi.CursorQuery, "The previous page's nextCursor: a ten_ public ID. Anything else is 400 tenant_invalid."))
            .WithName("ListTenants")
            .WithTags(Tag)
            .WithSummary("The Deployment's Tenants, oldest first, 50 a page, and the Tenant zone their hosts sit under.")
            .WithDescription(
                "Deployment Owner only. Each Tenant's ten_ public ID, name, host as stored at creation, label, status and creation " +
                "time; while it is creating, its creation Operation's opr_ ID and whether it is running or failed; while it is " +
                "deleting, its deletion Operation's, alike. A deleted Tenant is never listed. No subdomain is split out of a host. " +
                "nextCursor is the last Tenant's ID when another page follows, else null; pass it back as cursor, which works even " +
                "when it names a Tenant deleted since. A malformed cursor is 400 tenant_invalid.")
            .Produces<TenantListResponse>(StatusCodes.Status200OK)
            .Produces<ApiProblem>(StatusCodes.Status400BadRequest, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/deployment/tenants", static (HttpContext context, AdminApiServices services) => TenantsApi.CreateAsync(context, services))
            .WithMetadata(
                DeploymentApiEndpoint.Instance,
                new RequiresCapability(AdminCapabilities.DeploymentTenantsCreate),
                new JsonRequestBody(typeof(CreateTenantRequest)))
            .WithName("CreateTenant")
            .WithTags(Tag)
            .WithSummary("Create a Tenant with its permanent Tenant Subdomain, and start the Operation that finishes it.")
            .WithDescription(
                "Deployment Owner only. The only request that takes a Tenant Subdomain: it can never be changed, and a host once " +
                "issued is never reused. In one transaction it stores the Tenant as creating, with its host and the issuer, WebAuthn " +
                "RP ID and email link base derived from it once; makes the caller its Tenant Owner; starts its tenancy.tenant.create " +
                "Operation; and writes tenancy.tenant.created. The Operation creates the Tenant's keys, then its settings, and makes " +
                "it active; until then its host isn't served. A body that isn't JSON, is over 4096 bytes, misses a field or has the " +
                "wrong type, and an invalid name or label, is 400 tenant_invalid. A malformed, reserved or taken subdomain is the " +
                "same 400 subdomain_refused, which never says which. Location names the Operation on the Tenant's own path.")
            .Produces<TenantCreatedResponse>(StatusCodes.Status202Accepted)
            .Produces<ApiProblem>(StatusCodes.Status400BadRequest, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/deployment/operations/{operationId}/retry", static (HttpContext context, AdminApiServices services) => TenantsApi.RetryAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, new RequiresCapability(AdminCapabilities.DeploymentTenantsCreate))
            .WithName("RetryOperation")
            .WithTags(Tag)
            .WithSummary("Retry a failed Tenant creation's failed steps.")
            .WithDescription(
                "Deployment Owner only. Reopens only the failed steps of a failed tenancy.tenant.create Operation, which runs again, " +
                "and writes operations.operation.retried. One that is running or succeeded is 409 operation_not_failed, and one whose " +
                "Tenant is being deleted, or deleted, is 409 tenant_deleted, and never runs again. An Operation of any other type, a " +
                "deletion included, and an unknown or malformed operationId, is the unknown-path 404.")
            .Produces<OperationResponse>(StatusCodes.Status202Accepted)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status404NotFound)
            .Produces<ApiProblem>(StatusCodes.Status409Conflict, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/deployment/tenants/{targetTenantId}/deletion", static (HttpContext context, AdminApiServices services) => TenantsApi.StartDeletionAsync(context, services))
            .WithMetadata(
                DeploymentApiEndpoint.Instance,
                new RequiresCapability(AdminCapabilities.DeploymentTenantsDelete),
                new FreshAssertionTarget(TenantsApi.TargetTenantRouteValue),
                new JsonRequestBody(typeof(DeleteTenantRequest)))
            .WithName("DeleteTenant")
            .WithTags(Tag)
            .WithSummary("Delete a Tenant: its host stops resolving, every Tenant Role in it ends, and its deletion Operation starts.")
            .WithDescription(
                "Deployment Owner only, after a fresh assertion for deployment.tenants.delete with this targetTenantId as its target, " +
                "begun on POST /api/v1/deployment/assertions, which the request checks use up before anything else, whatever follows, " +
                "or 403 fresh_assertion_required: a refusal after it needs a new confirmation. The body's confirmation must be the " +
                "Tenant's host exactly as the Tenants list shows it, with no trimming or case folding, or 400 confirmation_mismatch. " +
                "In one transaction it sets the Tenant deleting, so its host gets the same 404 as an unknown host at once; removes " +
                "every Tenant Role in it, so every Tenant route refuses its former members; starts its tenancy.tenant.delete Operation; " +
                "and writes tenancy.tenant.deletion_started. The Operation purges every module's data of the Tenant but its Logs, " +
                "destroys its keys and marks it deleted; its Logs are kept for at least 90 days after, whatever its label. The Tenant " +
                "and its host are never reused. A body that isn't JSON, is over 4096 bytes, or misses confirmation or has the wrong " +
                "type is 400 tenant_invalid. A Tenant already being deleted, or deleted, is 409 tenant_deleted, and one whose creation " +
                "is still running 409 tenant_busy. An unknown or malformed targetTenantId is the unknown-path 404. Location names the " +
                "deletion.")
            .Produces<OperationResponse>(StatusCodes.Status202Accepted)
            .Produces<ApiProblem>(StatusCodes.Status400BadRequest, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status404NotFound)
            .Produces<ApiProblem>(StatusCodes.Status409Conflict, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapGet("/api/v1/deployment/tenants/{targetTenantId}/deletion", static (HttpContext context, AdminApiServices services) => TenantsApi.GetDeletionAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, new RequiresCapability(AdminCapabilities.DeploymentTenantsRead))
            .WithName("GetTenantDeletion")
            .WithTags(Tag)
            .WithSummary("A Tenant's newest deletion Operation, with every step.")
            .WithDescription(
                "Deployment Owner only. The newest tenancy.tenant.delete Operation of the Tenant, whatever its status, with every " +
                "step's codes and IDs, never a step's row ID. A Tenant never deleted, and an unknown or malformed targetTenantId, " +
                "is the unknown-path 404.")
            .Produces<OperationResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/deployment/tenants/{targetTenantId}/deletion/retry", static (HttpContext context, AdminApiServices services) => TenantsApi.RetryDeletionAsync(context, services))
            .WithMetadata(
                DeploymentApiEndpoint.Instance,
                new RequiresCapability(AdminCapabilities.DeploymentTenantsDelete),
                new FreshAssertionTarget(TenantsApi.TargetTenantRouteValue))
            .WithName("RetryTenantDeletion")
            .WithTags(Tag)
            .WithSummary("Retry a Tenant's failed deletion's failed steps.")
            .WithDescription(
                "Deployment Owner only, after a new fresh assertion for deployment.tenants.delete with this targetTenantId as its " +
                "target, which the request checks use up, or 403 fresh_assertion_required. No body and no typed confirmation. " +
                "Reopens only the failed steps of the Tenant's failed tenancy.tenant.delete Operation, which runs again, and writes " +
                "operations.operation.retried. A deletion that is running or succeeded, and a Tenant that isn't being deleted, is " +
                "409 operation_not_failed. An unknown or malformed targetTenantId is the unknown-path 404.")
            .Produces<OperationResponse>(StatusCodes.Status202Accepted)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status404NotFound)
            .Produces<ApiProblem>(StatusCodes.Status409Conflict, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapGet("/api/v1/tenants/{tenantId}/operations/{operationId}", static (HttpContext context, AdminApiServices services) => TenantsApi.GetTenantOperationAsync(context, services))
            .WithMetadata(TenantApiEndpoint.Instance, new RequiresCapability(AdminCapabilities.TenantConfigurationRead))
            .WithName("GetTenantOperation")
            .WithTags(TenantTag)
            .WithSummary("One Operation as the path Tenant sees it: only its own steps.")
            .WithDescription(
                "Any Tenant Role in the path Tenant. Codes and IDs only, never a step's row ID. Another Tenant's Operation, an unknown " +
                "one and a malformed operationId are the same unknown-path 404. A malformed, unknown or role-less Tenant is 403 " +
                "access_denied, audited as every Tenant capability refusal is.")
            .Produces<OperationResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapGet("/api/v1/deployment/my-tenants", static (HttpContext context, AdminApiServices services) => TenantsApi.ListMineAsync(context, services))
            .WithMetadata(DeploymentApiEndpoint.Instance, SelfService.Instance)
            .WithName("ListMyTenants")
            .WithTags(Tag)
            .WithSummary("The active Tenants the current Admin holds a Tenant Role in, for the Tenant switcher.")
            .WithDescription(
                "Self-service, full Sessions only: any Admin may read their own list. Each active Tenant the Admin holds a Tenant " +
                "Role in, oldest first, with its ten_ public ID, name, host as stored at creation and label; never the role, and no " +
                "Tenant still being created. A Deployment Owner holding no Tenant Role gets an empty list, as any other Admin does. " +
                "No paging. A setup or recovery Session gets 403.")
            .Produces<AdminTenantListResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapGet("/api/v1/tenants/{tenantId}/label", static (HttpContext context, AdminApiServices services) => TenantLabelApi.GetAsync(context, services))
            .WithMetadata(TenantApiEndpoint.Instance, new RequiresCapability(AdminCapabilities.TenantConfigurationRead))
            .WithName("GetTenantLabel")
            .WithTags(TenantTag)
            .WithSummary("The path Tenant's environment label: dev, staging or prod.")
            .WithDescription(
                "Any Tenant Role in the path Tenant, whatever the Tenant's status, which it returns too: only an active Tenant's label changes. It takes no lock, so it never waits behind a change. A malformed, unknown or role-less Tenant is 403 " +
                "access_denied, audited as every Tenant capability refusal is.")
            .Produces<TenantLabelResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapGet("/api/v1/tenants/{tenantId}/logs", static (HttpContext context, AdminApiServices services) => TenantLogsApi.SearchAsync(context, services))
            .WithMetadata(
                TenantApiEndpoint.Instance,
                new RequiresCapability(AdminCapabilities.TenantLogsRead),
                new QueryParameter(TenantLogsApi.TypeQuery, "One event type code, {domain}.{object}.{action}, as docs/audit-events.md publishes it."),
                new QueryParameter(
                    TenantLogsApi.UserQuery,
                    "A User: their UUID, or an email, which resolves first to the User references on this Tenant's events whose detail holds exactly it. Events whose Actor or target is that User."),
                new QueryParameter(TenantLogsApi.ApplicationQuery, "An Application's UUID: events whose Actor or target is that client."),
                new QueryParameter(TenantLogsApi.OutcomeQuery, "success or failure: the events whose type the catalogue gives that outcome."),
                new QueryParameter(TenantLogsApi.FromQuery, "An ISO 8601 instant with Z or an offset: events at or after it."),
                new QueryParameter(TenantLogsApi.ToQuery, "An ISO 8601 instant with Z or an offset: events before it. It must come after from."),
                new QueryParameter(TenantLogsApi.CursorQuery, "The previous page's nextCursor: an evt_ public ID."))
            .WithName("SearchTenantLogs")
            .WithTags(TenantTag)
            .WithSummary("Search the path Tenant's Log: newest first, 50 a page.")
            .WithDescription(
                "Any Tenant Role in the path Tenant. Read only, in the Tenant's own scope: no other Tenant's event is ever listed, and the " +
                "read isn't audited. Each event's evt_ ID, time, type code, the catalogue's outcome and summary, and its Actor and " +
                "target as internal references; never its detail, so no IP address, User-Agent or email. Every parameter is optional, " +
                "at most once, and they combine; each filters an indexed envelope column. nextCursor is the last event's ID when an " +
                "older page follows, else null; pass it back as cursor with the same filters. A parameter sent twice or empty, an " +
                "unknown outcome, a code that isn't three lower-case parts, a User that is neither a UUID nor an email, an Application " +
                "that isn't a UUID, a time that isn't an instant, from not before to, or a malformed cursor is 400 invalid_request. An " +
                "email no event names, like any search that matches nothing, is an empty list. A malformed, unknown or role-less " +
                "Tenant is 403 access_denied, audited as every Tenant capability refusal is.")
            .Produces<TenantLogsResponse>(StatusCodes.Status200OK)
            .Produces<ApiProblem>(StatusCodes.Status400BadRequest, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapGet("/api/v1/tenants/{tenantId}/signing-keys", static (HttpContext context, AdminApiServices services) => SigningKeysApi.ListAsync(context, services))
            .WithMetadata(TenantApiEndpoint.Instance, new RequiresCapability(AdminCapabilities.TenantConfigurationRead))
            .WithName("ListSigningKeys")
            .WithTags(TenantTag)
            .WithSummary("The path Tenant's Signing Keys in every state: next, current, previous, retired and revoked.")
            .WithDescription(
                "Any Tenant Role in the path Tenant. Its signing keys only, never a Management key: next, then current, then " +
                "previous, then retired and revoked keys together, newest first; a retired key is listed whether or not its " +
                "Transit key is destroyed yet. Each key has its key ID (the kid tokens and JWKS carry), its algorithm, its " +
                "state and when it was created, and nothing of its key material. It reads the database only, so it answers " +
                "while key custody is down. It writes nothing. A malformed, unknown or role-less Tenant is 403 access_denied, " +
                "audited as every Tenant capability refusal is.")
            .Produces<SigningKeysResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapGet("/api/v1/tenants/{tenantId}/signing-keys/jwks", static (HttpContext context, AdminApiServices services) => SigningKeysApi.GetJwksAsync(context, services))
            .WithMetadata(TenantApiEndpoint.Instance, new RequiresCapability(AdminCapabilities.TenantConfigurationRead))
            .WithName("GetSigningKeysJwks")
            .WithTags(TenantTag)
            .WithSummary("The path Tenant's public JWKS sample, as its Tenant host serves it, and the JWKS URI.")
            .WithDescription(
                "Any Tenant Role in the path Tenant. One public RSA key per published Signing Key (current, then next, then " +
                "previous), with exactly the members the Tenant's own JWKS serves: kty, use, alg, kid, n and e, never a private " +
                "member and never a Management key. The public halves come from key custody, and the URI is the Tenant's stored " +
                "issuer with /.well-known/jwks. Key custody down, or without a published key's version, is 503 for the whole " +
                "sample. It writes nothing. A malformed, unknown or role-less Tenant is 403 access_denied, audited as every " +
                "Tenant capability refusal is.")
            .Produces<SigningKeysJwksResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapGet("/api/v1/tenants/{tenantId}/applications", static (HttpContext context, AdminApiServices services) => ApplicationsApi.ListAsync(context, services))
            .WithMetadata(
                TenantApiEndpoint.Instance,
                new RequiresCapability(AdminCapabilities.TenantConfigurationRead),
                new QueryParameter(ApplicationsApi.CursorQuery, "The previous page's nextCursor: an app_ public ID."))
            .WithName("ListApplications")
            .WithTags(TenantTag)
            .WithSummary("The path Tenant's Applications: newest first, 50 a page.")
            .WithDescription(
                "Any Tenant Role in the path Tenant. Read only, in the Tenant's own scope: no other Tenant's Application is ever " +
                "listed, and neither is the Tenant's hidden system Application. Each Application's ID, which is also its client ID, " +
                "its name, its type, whether that type needs a client secret, and when it was created; never a secret. nextCursor " +
                "is the last Application's ID when an older page follows, else null; pass it back as cursor. A cursor sent twice, " +
                "empty or that isn't an app_ ID is 400 invalid_request. A malformed, unknown or role-less Tenant is 403 " +
                "access_denied, audited as every Tenant capability refusal is.")
            .Produces<ApplicationListResponse>(StatusCodes.Status200OK)
            .Produces<ApiProblem>(StatusCodes.Status400BadRequest, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapGet("/api/v1/tenants/{tenantId}/applications/{applicationId}", static (HttpContext context, AdminApiServices services) => ApplicationsApi.GetAsync(context, services))
            .WithMetadata(TenantApiEndpoint.Instance, new RequiresCapability(AdminCapabilities.TenantConfigurationRead))
            .WithName("GetApplication")
            .WithTags(TenantTag)
            .WithSummary("One of the path Tenant's Applications.")
            .WithDescription(
                "Any Tenant Role in the path Tenant. Read only, in the Tenant's own scope. The same fields as the list, and never a " +
                "secret. An applicationId that isn't an app_ ID, names no Application of this Tenant, names another Tenant's or " +
                "names the hidden system Application is the same 404 not_found. A malformed, unknown or role-less Tenant is 403 " +
                "access_denied, audited as every Tenant capability refusal is.")
            .Produces<ApplicationResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces<ApiProblem>(StatusCodes.Status404NotFound, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/tenants/{tenantId}/applications", static (HttpContext context, AdminApiServices services) => ApplicationsApi.CreateAsync(context, services))
            .WithMetadata(
                TenantApiEndpoint.Instance,
                new RequiresCapability(AdminCapabilities.TenantApplicationsManage),
                new JsonRequestBody(typeof(CreateApplicationRequest)))
            .WithName("CreateApplication")
            .WithTags(TenantTag)
            .WithSummary("Create an Application in the path Tenant, with a name and a type and no secret.")
            .WithDescription(
                "Tenant Editors and Owners. The type is spa (single-page), web (regular web), native or machine " +
                "(machine-to-machine); web and machine need a client secret, which isn't created here, so until one is the " +
                "Application can't authenticate. It starts with no redirect URI and no audience; machine is allowed " +
                "client_credentials and web authorization_code, and spa and native nothing yet. The name is trimmed, then 1 to 200 " +
                "characters with no control character, and two Applications may share one. In one transaction it writes the " +
                "Application and directory.application.created by the caller. A body that isn't JSON, is over 4096 bytes, misses " +
                "a field or has the wrong type, and an invalid name or type, is 400 application_invalid, with nothing written. " +
                "Location names the new Application.")
            .Produces<ApplicationResponse>(StatusCodes.Status201Created)
            .Produces<ApiProblem>(StatusCodes.Status400BadRequest, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces<ApiProblem>(StatusCodes.Status409Conflict, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPut("/api/v1/tenants/{tenantId}/applications/{applicationId}/settings", static (HttpContext context, AdminApiServices services) => ApplicationsApi.UpdateSettingsAsync(context, services))
            .WithMetadata(
                TenantApiEndpoint.Instance,
                new RequiresCapability(AdminCapabilities.TenantApplicationCallbacksManage),
                EvaluatesFreshAssertion.Instance,
                new FreshAssertionTarget(ApplicationsApi.ApplicationRouteValue),
                new JsonRequestBody(typeof(ApplicationSettingsRequest)))
            .WithName("UpdateApplicationSettings")
            .WithTags(TenantTag)
            .WithSummary("Save an Application's callback, logout and web origin URLs and its grant types.")
            .WithDescription(
                "Tenant Editors and Owners; never a machine principal. The body is the full settings, and every list is required " +
                "and replaces what is stored. Every URL is absolute, at most 2000 characters, with no fragment, user info or " +
                "wildcard, and https, or http on 127.0.0.1 or [::1] only; each list holds at most 10 distinct lines. A native " +
                "Application may also register custom-scheme callback and logout URLs, such as com.example.app:/callback, and has " +
                "no web origin; a machine Application has no URL at all. A web origin is scheme://host[:port] alone. Grants are [] " +
                "or [client_credentials] for machine, and [], [authorization_code] or [authorization_code, refresh_token] " +
                "otherwise, in any order, stored sorted. URLs are matched exactly; only a native Application's loopback " +
                "redirect URI may differ in port. Any rule broken is 400 application_invalid with errors naming each field, line " +
                "and reason; a body that isn't JSON, is over 131072 bytes, misses a list or holds a null is 400 " +
                "application_invalid with no errors. In a Prod Tenant a new custom-scheme URL needs acknowledgeCustomScheme: " +
                "true, or it is 400 custom_scheme_acknowledgement_required, and a changed set of callback URLs needs a fresh " +
                "assertion for tenant.application_callbacks.manage on this applicationId, begun on POST " +
                "/api/v1/tenants/{tenantId}/assertions and used up once the locked label is found to be Prod. A save that " +
                "changes something writes directory.application.updated, and in a Prod Tenant that gains a callback " +
                "directory.application.prod_callback_added; a save that changes nothing writes nothing and is 200. An " +
                "applicationId that isn't an app_ ID, names no Application of this Tenant, another Tenant's or the hidden " +
                "system Application is the same 404 not_found.")
            .Produces<ApplicationResponse>(StatusCodes.Status200OK)
            .Produces<ApiProblem>(StatusCodes.Status400BadRequest, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces<ApiProblem>(StatusCodes.Status404NotFound, AdminResponses.ProblemContentType)
            .Produces<ApiProblem>(StatusCodes.Status409Conflict, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapGet("/api/v1/tenants/{tenantId}/applications/{applicationId}/secrets", static (HttpContext context, AdminApiServices services) => ApplicationSecretsApi.ListAsync(context, services))
            .WithMetadata(TenantApiEndpoint.Instance, new RequiresCapability(AdminCapabilities.TenantConfigurationRead))
            .WithName("ListApplicationSecrets")
            .WithTags(TenantTag)
            .WithSummary("An Application's live client secrets: never a value or hash.")
            .WithDescription(
                "Any Tenant Role in the path Tenant. Read only, in the Tenant's own scope. The live secrets, newest first: not " +
                "revoked and not past their expiry. Each has its sec_ ID, when it was created and, for a rotated-out secret still " +
                "in its 24-hour overlap, when it stops working; expiresAt is null for the current secret. No value, hash or part " +
                "of either is ever shown, and ended secrets are seen only in the Log. A spa or native Application always lists " +
                "none. An applicationId that isn't an app_ ID, names no Application of this Tenant, another Tenant's or the " +
                "hidden system Application is the same 404 not_found. A malformed, unknown or role-less Tenant is 403 " +
                "access_denied, audited as every Tenant capability refusal is.")
            .Produces<ApplicationSecretListResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces<ApiProblem>(StatusCodes.Status404NotFound, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/tenants/{tenantId}/applications/{applicationId}/secrets", static (HttpContext context, AdminApiServices services) => ApplicationSecretsApi.CreateAsync(context, services))
            .WithMetadata(
                TenantApiEndpoint.Instance,
                new RequiresCapability(AdminCapabilities.TenantClientSecretsManage),
                new FreshAssertionTarget(ApplicationsApi.ApplicationRouteValue))
            .WithName("CreateApplicationSecret")
            .WithTags(TenantTag)
            .WithSummary("Create or rotate a web or machine Application's client secret, shown in this response only.")
            .WithDescription(
                "Tenant Owners only; never a machine principal. Needs a fresh assertion for tenant.client_secrets.manage with " +
                "this applicationId as its target, begun on POST /api/v1/tenants/{tenantId}/assertions, which the request " +
                "checks use up before anything else, whatever follows, or 403 fresh_assertion_required. It takes no body. With " +
                "no current secret it creates one and writes directory.client_secret.created. With one it rotates: the current " +
                "secret keeps working for 24 hours, then stops, and directory.client_secret.rotated is written. The new secret " +
                "is {tenantPublicId}.{43 base64url characters}, 256 random bits, stored only as its SHA-256 and shown in this " +
                "201 alone, with Cache-Control: no-store, beside the live secrets after the write. An Application holds at most " +
                "two live secrets, so while a rotated-out one still overlaps it is 409 client_secret_limit_reached, and a spa or " +
                "native Application, which needs no secret, is 409 client_secret_not_applicable; neither writes anything. An " +
                "applicationId that isn't an app_ ID, names no Application of this Tenant, another Tenant's or the hidden " +
                "system Application is the same 404 not_found.")
            .Produces<ApplicationSecretCreatedResponse>(StatusCodes.Status201Created)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces<ApiProblem>(StatusCodes.Status404NotFound, AdminResponses.ProblemContentType)
            .Produces<ApiProblem>(StatusCodes.Status409Conflict, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/tenants/{tenantId}/applications/{applicationId}/secrets/{secretId}/revoke", static (HttpContext context, AdminApiServices services) => ApplicationSecretsApi.RevokeAsync(context, services))
            .WithMetadata(
                TenantApiEndpoint.Instance,
                new RequiresCapability(AdminCapabilities.TenantClientSecretsManage),
                new FreshAssertionTarget(ApplicationsApi.ApplicationRouteValue))
            .WithName("RevokeApplicationSecret")
            .WithTags(TenantTag)
            .WithSummary("Revoke one of an Application's live client secrets, or end a rotated-out secret's overlap now.")
            .WithDescription(
                "Tenant Owners only; never a machine principal. Needs a fresh assertion for tenant.client_secrets.manage with " +
                "this applicationId as its target, as a create does, or 403 fresh_assertion_required. It takes no body. The " +
                "secret is refused at the token endpoint at once, and directory.client_secret.revoked is written. Revoking the " +
                "current secret is allowed even when it leaves none, and then the Application can't get tokens until a new one " +
                "is created. The answer is the live secrets after the write. A secretId that isn't a sec_ ID, names no secret " +
                "of this Application, or names one already revoked or expired, and an applicationId that isn't an app_ ID, names " +
                "no Application of this Tenant, another Tenant's or the hidden system Application, are the same 404 not_found.")
            .Produces<ApplicationSecretListResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces<ApiProblem>(StatusCodes.Status404NotFound, AdminResponses.ProblemContentType)
            // The request checks' tenant_mismatch: every state-changing Tenant route declares it (AdminOpenApi).
            .Produces<ApiProblem>(StatusCodes.Status409Conflict, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPut("/api/v1/tenants/{tenantId}/label", static (HttpContext context, AdminApiServices services) => TenantLabelApi.SetAsync(context, services))
            .WithMetadata(
                TenantApiEndpoint.Instance,
                new RequiresCapability(AdminCapabilities.TenantLabelManage),
                EvaluatesFreshAssertion.Instance,
                new JsonRequestBody(typeof(SetTenantLabelRequest)))
            .WithName("SetTenantLabel")
            .WithTags(TenantTag)
            .WithSummary("Change the path Tenant's environment label.")
            .WithDescription(
                "Tenant Owner only, in an active Tenant. The only request that changes a Tenant's label after creation, and it " +
                "changes nothing else: no setting or policy changes with it. Removing the Prod label needs a fresh " +
                "assertion for tenant.label.manage in this Tenant, begun on POST /api/v1/tenants/{tenantId}/assertions, which is " +
                "used up once the locked label is found to be Prod, whatever follows; raising a label, moving between dev and " +
                "staging, and an unchanged label need none, and any change uses up an unused grant this Session holds for it. A change writes tenancy.tenant.label_changed, or " +
                "tenancy.tenant.prod_label_removed, on the Tenant's own Log. An unchanged label writes nothing and is 200. A body " +
                "that isn't JSON, is over 4096 bytes, misses label or has the wrong type, and an unknown label, is 400 " +
                "tenant_invalid. A Tenant still being created is 409 tenant_not_active.")
            .Produces<TenantLabelResponse>(StatusCodes.Status200OK)
            .Produces<ApiProblem>(StatusCodes.Status400BadRequest, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces<ApiProblem>(StatusCodes.Status409Conflict, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status503ServiceUnavailable);

        app.MapPost("/api/v1/tenants/{tenantId}/assertions", static (HttpContext context, AdminApiServices services) => FreshAssertionApi.BeginForTenantAsync(context, services))
            .WithMetadata(
                TenantApiEndpoint.Instance,
                new RequiresCapability(AdminCapabilities.TenantConfigurationRead),
                new JsonRequestBody(typeof(FreshAssertionBeginRequest)))
            .WithName("BeginTenantFreshAssertion")
            .WithTags(TenantTag)
            .WithSummary("Begin confirming a sensitive action in the path Tenant with a fresh WebAuthn assertion.")
            .WithDescription(
                "Any Tenant Role in the path Tenant reaches it; the body names the action, a Tenant capability whose fresh " +
                "assertion isn't never, and its target exactly as the action's request will name it, or null. The action's own " +
                "capability is then decided from the same role: refused, it is 403 access_denied, counted and audited against the " +
                "path Tenant. A self-service action, a Deployment capability, a never capability, an unknown action, a target for an action whose route names none, or a body that " +
                "isn't JSON is 400 assertion_refused, with no challenge stored. Otherwise as the Deployment begin: request options " +
                "for the Admin RP ID with user verification required and no credential listed, bound to this Session, the action, " +
                "this Tenant and the target, answered once within 5 minutes on POST /api/v1/deployment/assertions/complete. A grant " +
                "for one Tenant never serves another. Each begin and complete counts towards 10 per Session in 15 minutes, then 429.")
            .Produces<AdminSignInOptionsResponse>(StatusCodes.Status200OK)
            .Produces<ApiProblem>(StatusCodes.Status400BadRequest, AdminResponses.ProblemContentType)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<ApiProblem>(StatusCodes.Status403Forbidden, AdminResponses.ProblemContentType)
            .Produces<ApiProblem>(StatusCodes.Status409Conflict, AdminResponses.ProblemContentType)
            .Produces<ApiProblem>(StatusCodes.Status429TooManyRequests, AdminResponses.ProblemContentType)
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
                logger.LogInformation("A bootstrap claim was refused with {Problem}, trace {TraceId}.", AdminResponses.RateLimited, AdminResponses.TraceId(context));
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
                logger.LogInformation("A bootstrap claim was refused with {Problem}, trace {TraceId}.", AdminResponses.BootstrapRefused, AdminResponses.TraceId(context));
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

    /// <summary>How long a small JSON body may take to arrive (Story 1.26's begin and redeem bodies).</summary>
    private static readonly TimeSpan BodyDeadline = TimeSpan.FromSeconds(10);

    private static readonly JsonSerializerOptions BodyJson = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 4,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip,
    };

    /// <summary>
    /// A small JSON body as <typeparamref name="T"/>, or null for anything malformed: not
    /// <c>application/json</c>, over <paramref name="maxBytes"/>, still arriving after 10 seconds,
    /// cut off or malformed on the wire (an <see cref="IOException"/>), or JSON that isn't one.
    /// Never throws but for the client's own cancellation.
    /// </summary>
    internal static async Task<T?> ReadJsonAsync<T>(HttpRequest request, int maxBytes, CancellationToken cancellationToken)
        where T : class
    {
        if (!IsJson(request))
        {
            return null;
        }

        var buffer = ArrayPool<byte>.Shared.Rent(maxBytes + 1);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(BodyDeadline);
        try
        {
            var length = 0;
            int read;
            while (length <= maxBytes && (read = await request.Body.ReadAsync(buffer.AsMemory(length, maxBytes + 1 - length), deadline.Token)) > 0)
            {
                length += read;
            }

            if (length > maxBytes)
            {
                return null;
            }

            try
            {
                return JsonSerializer.Deserialize<T>(buffer.AsSpan(0, length), BodyJson);
            }
            catch (JsonException)
            {
                return null;
            }
        }
        catch (Exception e) when (!cancellationToken.IsCancellationRequested && e is OperationCanceledException or IOException)
        {
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
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
            Kind = session.Kind switch
            {
                AdminSessionKind.Setup => "setup",
                AdminSessionKind.Recovery => "recovery",
                _ => "full",
            },
            DeploymentOwner = session.DeploymentOwner,
            SetupComplete = session.SetupComplete,
            Credentials = session.Credentials,
            RecoveryCodeAllowed = session.RecoveryCodeAllowed,
            CsrfToken = session.CsrfToken.Use(static t => t),
        });
    }

    private static async Task EndSessionAsync(HttpContext context, AdminApiServices services)
    {
        var session = AdminRequestChecks.Session(context);
        var cancellationToken = context.RequestAborted;

        // The ending and its admin.session.signed_out event: one transaction.
        await using (var scope = await services.BeginAsync(cancellationToken))
        {
            await services.Sessions.EndAsync(scope.CreateCommandContext(), session, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }

        context.Response.StatusCode = StatusCodes.Status204NoContent;
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.SetCookie = AdminResponses.ClearedSessionCookie;
    }

    private static Task GetCapabilitiesAsync(HttpContext context, AdminApiServices services) =>
        HeldAsync(context, services, CapabilityScope.Deployment, tenantId: null);

    /// <summary>
    /// Answered from the Tenant Role grant the request checks read to allow the request, in their
    /// transaction: no second read, so a role changed in between can't turn an allowed request
    /// into a 200 with a list that disagrees with the check.
    /// </summary>
    private static Task GetTenantCapabilitiesAsync(HttpContext context, AdminApiServices services)
    {
        _ = services;
        var path = AdminRequestChecks.PathTenantGrant(context);
        var held = AdminCapabilities.Held(AdminRequestChecks.Principal(context), CapabilityScope.Tenant, path.Grant, path.TenantId);
        return AdminResponses.JsonAsync(context, new CapabilitiesResponse { Capabilities = [.. held.Select(c => c.Name)] });
    }

    /// <summary>The capabilities of <paramref name="scope"/> the Admin holds, read now in a Deployment scope.</summary>
    private static async Task HeldAsync(HttpContext context, AdminApiServices services, CapabilityScope scope, Guid? tenantId)
    {
        var principal = AdminRequestChecks.Principal(context);
        var cancellationToken = context.RequestAborted;

        IReadOnlyList<Capability> held;
        await using (var read = await services.BeginAsync(cancellationToken))
        {
            held = await services.Authorization.HeldAsync(read.CreateCommandContext(), principal, scope, tenantId, cancellationToken);
            await read.CommitAsync(cancellationToken);
        }

        await AdminResponses.JsonAsync(context, new CapabilitiesResponse { Capabilities = [.. held.Select(c => c.Name)] });
    }

    private static string SessionCookie(string token) => AdminResponses.SessionCookie(token);

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
