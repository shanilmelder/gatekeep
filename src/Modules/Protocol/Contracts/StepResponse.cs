using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;

namespace Gatekeep.Modules.Protocol.Contracts;

/// <summary>
/// One Hosted Login step, as its page embeds it and the client renders it (AD-21, Story 4.1):
/// <c>{step, stepVersion, expiresInSeconds, data, csrfToken}</c>. <see cref="Step"/> is a snake_case step
/// name, the client's only key to its screen, and <see cref="Data"/> that screen's props. A new step is a
/// new data record and a factory here; the page writer serializes any of them unchanged.
/// </summary>
public sealed record StepResponse(string Step, int StepVersion, int? ExpiresInSeconds, object Data, string? CsrfToken)
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        // The page writer makes the JSON safe inside its script element; nothing else is escaped here.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>
    /// Generic error (FR-33): the Tenant's name, the error's code and the request's trace ID, and nothing
    /// else, since the request it answers isn't trusted. It never expires and holds no CSRF token.
    /// </summary>
    public static StepResponse GenericError(string tenant, string code, string traceId) =>
        new(StepNames.GenericError, 1, null, new GenericErrorData(tenant, code, traceId), null);

    /// <summary>
    /// Login (Story 4.2): the identifier step, at <paramref name="stepVersion"/>, with its remaining life and the
    /// transaction's CSRF token. <paramref name="email"/> is the email kept from an earlier attempt, if any, and
    /// <paramref name="error"/> a field error's code, such as <see cref="LoginErrors.EmailInvalid"/>.
    /// </summary>
    public static StepResponse Login(
        string tenant, int stepVersion, int expiresInSeconds, string csrfToken, string? email, string? error = null, bool signupEnabled = false) =>
        new(StepNames.Login, stepVersion, expiresInSeconds, new LoginData(tenant, email, error, signupEnabled), csrfToken);

    /// <summary>
    /// Signup (Story 4.7): the email carried from Login, the password policy the strength meter checks in the browser, and a
    /// field error: <see cref="SignupErrors.EmailInvalid"/>, <see cref="SignupErrors.TermsRequired"/> (Story 4.8), or
    /// <see cref="SignupErrors.PasswordRule"/> with each failing rule's code in <paramref name="rules"/>. From Story 4.8,
    /// <paramref name="termsUrl"/> is the Tenant's terms URL, or null; with one, Signup asks the User to accept it.
    /// </summary>
    public static StepResponse Signup(
        string tenant,
        int stepVersion,
        int expiresInSeconds,
        string csrfToken,
        string? email,
        SignupPolicyData policy,
        string? error = null,
        IReadOnlyList<string>? rules = null,
        string? termsUrl = null) =>
        new(StepNames.Signup, stepVersion, expiresInSeconds, new SignupData(tenant, email, policy, error, rules ?? [], termsUrl), csrfToken);

    /// <summary>
    /// The Password step (Story 4.9): the email recorded at Login, shown in the identifier chip and held in the form's
    /// read-only <c>username</c> field, and the error <see cref="PasswordErrors.Incorrect"/> after a failed submit, alike
    /// for every account.
    /// </summary>
    public static StepResponse Password(string tenant, int stepVersion, int expiresInSeconds, string csrfToken, string? email, string? error = null) =>
        new(StepNames.Password, stepVersion, expiresInSeconds, new PasswordData(tenant, email, error), csrfToken);

    /// <summary>
    /// Email verification required (Story 4.7): the address the link went to, whether this answers "Resend email", and the
    /// error <see cref="VerifyEmailErrors.NotVerifiedYet"/> for "I've verified, continue" before the link was used.
    /// </summary>
    public static StepResponse VerifyEmail(
        string tenant, int stepVersion, int expiresInSeconds, string csrfToken, string? email, bool resent = false, string? error = null) =>
        new(StepNames.VerifyEmail, stepVersion, expiresInSeconds, new VerifyEmailData(tenant, email, resent, error), csrfToken);

    /// <summary>
    /// Email verified (Story 4.7): <see cref="EmailVerifiedContinuations.App"/> with the resume <paramref name="location"/>
    /// when the link was opened in the browser that signed up and its Session started, else
    /// <see cref="EmailVerifiedContinuations.Close"/> with none. It needs no CSRF token.
    /// </summary>
    public static StepResponse EmailVerified(string tenant, string? location) =>
        new(
            StepNames.EmailVerified,
            1,
            null,
            new EmailVerifiedData(tenant, location is null ? EmailVerifiedContinuations.Close : EmailVerifiedContinuations.App, location),
            null);

    /// <summary>
    /// Link expired (Story 4.7): "This link has expired or was already used.", for a malformed, foreign, unknown, expired or
    /// used link. <paramref name="token"/> is the link's own value, kept only when it has a link's shape, which "Send a new
    /// link" posts back with <paramref name="csrfToken"/>, the link-bound token; without one there is nothing to send.
    /// <paramref name="purpose"/> (Story 4.11) is <see cref="LinkPurposes.Verification"/> or <see cref="LinkPurposes.Reset"/>,
    /// which says where "Send a new link" posts.
    /// </summary>
    public static StepResponse LinkExpired(string tenant, string? token, string? csrfToken, string purpose = LinkPurposes.Verification) =>
        new(StepNames.LinkExpired, 1, null, new LinkExpiredData(tenant, token, purpose), token is null ? null : csrfToken);

    /// <summary>The neutral "If an account exists for that email, we've sent a link." (Story 4.7), the same whatever was sent.</summary>
    public static StepResponse LinkSent(string tenant) =>
        new(StepNames.LinkSent, 1, null, new LinkSentData(tenant, Back: false), null);

    /// <summary>
    /// The neutral confirmation after a reset request (Story 4.11), the same for every address, on the sign-in transaction:
    /// its step version, life and CSRF token, so "Back to login" can post. Only those differ between two answers.
    /// </summary>
    public static StepResponse ResetLinkSent(string tenant, int stepVersion, int expiresInSeconds, string csrfToken) =>
        new(StepNames.LinkSent, stepVersion, expiresInSeconds, new LinkSentData(tenant, Back: true), csrfToken);

    /// <summary>
    /// Forgot password (Story 4.11): the email carried from the Password step, and the error
    /// <see cref="ForgotPasswordErrors.EmailInvalid"/> for an address that isn't one.
    /// </summary>
    public static StepResponse ForgotPassword(string tenant, int stepVersion, int expiresInSeconds, string csrfToken, string? email, string? error = null) =>
        new(StepNames.ForgotPassword, stepVersion, expiresInSeconds, new ForgotPasswordData(tenant, email, error), csrfToken);

    /// <summary>
    /// Reset password (Story 4.11): a usable reset link's page, with the policy the strength meter checks, and an error:
    /// <see cref="ResetPasswordErrors.PasswordMismatch"/>, or <see cref="ResetPasswordErrors.PasswordRule"/> with each
    /// failing rule in <paramref name="rules"/>. <paramref name="csrfToken"/> is the reset-link-bound token, and
    /// <paramref name="email"/> the link User's, for password managers' username field. It holds no link: the page keeps the
    /// one in its address.
    /// </summary>
    public static StepResponse ResetPassword(
        string tenant, string csrfToken, SignupPolicyData policy, string? email, string? error = null, IReadOnlyList<string>? rules = null) =>
        new(StepNames.ResetPassword, 1, null, new ResetPasswordData(tenant, email, policy, error, rules ?? []), csrfToken);

    /// <summary>
    /// Password changed (Story 4.11): <see cref="PasswordChangedContinuations.Login"/> when this browser's sign-in went back
    /// to Login, so "Log in" goes there; otherwise <see cref="PasswordChangedContinuations.Close"/>. No CSRF token.
    /// </summary>
    public static StepResponse PasswordChanged(string tenant, bool login) =>
        new(
            StepNames.PasswordChanged,
            1,
            null,
            new PasswordChangedData(tenant, login ? PasswordChangedContinuations.Login : PasswordChangedContinuations.Close),
            null);

    /// <summary>
    /// A redirect (Story 4.2): the client follows <paramref name="location"/>, a same-origin path, with a top-level
    /// GET. It leaves the step and needs no CSRF token.
    /// </summary>
    public static StepResponse Redirect(string tenant, int stepVersion, int? expiresInSeconds, string location) =>
        new(StepNames.Redirect, stepVersion, expiresInSeconds, new RedirectData(tenant, location), null);

    /// <summary>The step as JSON, with camelCase names and every field present, nulls included.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, Json);
}

/// <summary>The Hosted Login step names (snake_case) the client maps to screens.</summary>
public static class StepNames
{
    public const string GenericError = "generic_error";

    /// <summary>Login's identifier step (Story 4.2).</summary>
    public const string Login = "login";

    /// <summary>A step that leaves Hosted Login by a top-level GET (Story 4.2).</summary>
    public const string Redirect = "redirect";

    /// <summary>The Password step, after Login's email (Story 4.9).</summary>
    public const string Password = "password";

    /// <summary>Signup: email, password and the strength meter (Story 4.7).</summary>
    public const string Signup = "signup";

    /// <summary>Email verification required, after a sign-up (Story 4.7).</summary>
    public const string VerifyEmail = "verify_email";

    /// <summary>A verification link was used (Story 4.7).</summary>
    public const string EmailVerified = "email_verified";

    /// <summary>A verification link that can't be used (Story 4.7).</summary>
    public const string LinkExpired = "link_expired";

    /// <summary>The neutral confirmation after "Send a new link" (Story 4.7), or after a reset request (Story 4.11).</summary>
    public const string LinkSent = "link_sent";

    /// <summary>Forgot password, after the Password step's "Forgot password?" (Story 4.11).</summary>
    public const string ForgotPassword = "forgot_password";

    /// <summary>A usable reset link's page: the new password and its confirmation (Story 4.11).</summary>
    public const string ResetPassword = "reset_password";

    /// <summary>A completed reset (Story 4.11).</summary>
    public const string PasswordChanged = "password_changed";
}

/// <summary>The codes a Login field error is sent as; the client shows the catalogue's text for each.</summary>
public static class LoginErrors
{
    /// <summary>"Enter a valid email address."</summary>
    public const string EmailInvalid = "email_invalid";
}

/// <summary>The codes a Signup field error is sent as (Story 4.7); the client shows the catalogue's text for each.</summary>
public static class SignupErrors
{
    /// <summary>"Enter a valid email address."</summary>
    public const string EmailInvalid = LoginErrors.EmailInvalid;

    /// <summary>The password failed the policy: the step's <c>rules</c> name each failing rule.</summary>
    public const string PasswordRule = "password_rule";

    /// <summary>"Accept the terms to continue." (Story 4.8): the Tenant set terms and the sign-up didn't accept them.</summary>
    public const string TermsRequired = "terms_required";
}

/// <summary>The code the Password step's error is sent as (Story 4.9).</summary>
public static class PasswordErrors
{
    /// <summary>"Incorrect email or password.", the same for an unknown account, no password and a wrong one.</summary>
    public const string Incorrect = "incorrect";
}

/// <summary>The code Forgot password's error is sent as (Story 4.11).</summary>
public static class ForgotPasswordErrors
{
    /// <summary>"Enter a valid email address."</summary>
    public const string EmailInvalid = LoginErrors.EmailInvalid;
}

/// <summary>The codes Reset password's errors are sent as (Story 4.11).</summary>
public static class ResetPasswordErrors
{
    /// <summary>"Passwords don't match.", under the confirmation.</summary>
    public const string PasswordMismatch = "password_mismatch";

    /// <summary>The new password failed the policy: the step's <c>rules</c> name each failing rule.</summary>
    public const string PasswordRule = SignupErrors.PasswordRule;
}

/// <summary>Which link a Link expired page is for (Story 4.11), so its "Send a new link" posts to the right place.</summary>
public static class LinkPurposes
{
    /// <summary>An email verification link (Story 4.7).</summary>
    public const string Verification = "verification";

    /// <summary>A password reset link (Story 4.11).</summary>
    public const string Reset = "reset";
}

/// <summary>Where Password changed goes on (Story 4.11).</summary>
public static class PasswordChangedContinuations
{
    /// <summary>"Log in", a top-level GET to Login: this browser's sign-in went back there with the email kept.</summary>
    public const string Login = "login";

    /// <summary>"You can close this page.", with no action: any other browser.</summary>
    public const string Close = "close";
}

/// <summary>The code Email verification required's error is sent as (Story 4.7).</summary>
public static class VerifyEmailErrors
{
    /// <summary>"We haven't seen that yet. Check your inbox."</summary>
    public const string NotVerifiedYet = "not_verified_yet";
}

/// <summary>Where Email verified's page goes on (Story 4.7).</summary>
public static class EmailVerifiedContinuations
{
    /// <summary>Continue, a top-level GET back to the authorization request: the link was opened in the browser that signed up.</summary>
    public const string App = "app";

    /// <summary>"You can close this page.", with no action: any other browser.</summary>
    public const string Close = "close";
}

/// <summary>
/// Login's props (Story 4.2): the Tenant's display name, the email to fill in, if kept, a field error's code, and whether
/// the "Sign up" link shows (Story 4.7): only while the database Connection is enabled with sign-up on.
/// </summary>
public sealed record LoginData(string Tenant, string? Email, string? Error, bool SignupEnabled = false);

/// <summary>The password policy the strength meter checks in the browser (Story 4.7): the minimum length and the strength.</summary>
public sealed record SignupPolicyData(int MinLength, string Strength);

/// <summary>
/// Signup's props (Story 4.7): the email carried from Login, the policy, a field error's code and the failing rules' codes;
/// from Story 4.8 the Tenant's terms URL, or null, which shows the terms row.
/// </summary>
public sealed record SignupData(string Tenant, string? Email, SignupPolicyData Policy, string? Error, IReadOnlyList<string> Rules, string? TermsUrl = null);

/// <summary>The Password step's props (Story 4.9): the email recorded at Login and an error's code, or null.</summary>
public sealed record PasswordData(string Tenant, string? Email, string? Error);

/// <summary>Email verification required's props (Story 4.7): the address, whether the email was just sent again, and an error's code.</summary>
public sealed record VerifyEmailData(string Tenant, string? Email, bool Resent, string? Error);

/// <summary>Email verified's props (Story 4.7): <c>app</c> with the resume location, or <c>close</c> with none.</summary>
public sealed record EmailVerifiedData(string Tenant, string ContinueTo, string? Location);

/// <summary>
/// Link expired's props (Story 4.7): the link's own value, for "Send a new link", when it had a link's shape, and (Story
/// 4.11) which link it is, one of <see cref="LinkPurposes"/>.
/// </summary>
public sealed record LinkExpiredData(string Tenant, string? Token, string Purpose = LinkPurposes.Verification);

/// <summary>The neutral link confirmation's props (Story 4.7): from Story 4.11, whether "Back to login" shows.</summary>
public sealed record LinkSentData(string Tenant, bool Back = false);

/// <summary>Forgot password's props (Story 4.11): the email to fill in and an error's code, or null.</summary>
public sealed record ForgotPasswordData(string Tenant, string? Email, string? Error);

/// <summary>Reset password's props (Story 4.11): the link User's email, the policy, an error's code and the failing rules' codes. No link.</summary>
public sealed record ResetPasswordData(string Tenant, string? Email, SignupPolicyData Policy, string? Error, IReadOnlyList<string> Rules);

/// <summary>Password changed's props (Story 4.11): <c>login</c> or <c>close</c>.</summary>
public sealed record PasswordChangedData(string Tenant, string ContinueTo);

/// <summary>A redirect's props (Story 4.2): the Tenant's display name and the same-origin path the client goes to.</summary>
public sealed record RedirectData(string Tenant, string Location);

/// <summary>Generic error's props: the Tenant's display name, the error code and the trace ID.</summary>
public sealed record GenericErrorData(string Tenant, string Code, string TraceId);

/// <summary>
/// The host's Hosted Login step pages (AD-21, Story 4.1), the port Protocol shows a step through: the
/// built bundle's page with the step embedded as JSON and the Tenant's theme linked in <c>head</c>, sent
/// <c>no-store</c> with the host's AD-21 headers. Host.Hosted registers it with <c>AddGatekeepProtocol</c>.
/// </summary>
public interface IStepPages
{
    /// <summary>The request's trace ID, as the host reports it everywhere else.</summary>
    string TraceId(HttpContext http);

    /// <summary>Writes <paramref name="step"/>'s page as the whole response, with <paramref name="statusCode"/>.</summary>
    Task WriteAsync(HttpContext http, int statusCode, StepResponse step, CancellationToken cancellationToken);

    /// <summary>
    /// Writes <paramref name="step"/> alone, as Hosted Login's API answers (Story 4.2): <c>application/json</c>,
    /// <c>no-store</c> and the same AD-21 headers, with <paramref name="statusCode"/>.
    /// </summary>
    Task WriteJsonAsync(HttpContext http, int statusCode, StepResponse step, CancellationToken cancellationToken);
}
