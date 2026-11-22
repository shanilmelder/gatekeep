using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Sessions.Contracts;

namespace Gatekeep.Modules.Authentication.Contracts;

/// <summary>The stable codes a refused password's rules are named by (Story 4.7, FR-18), in the order they are checked.</summary>
public static class PasswordRuleCodes
{
    /// <summary>Fewer code points than the policy's minimum length.</summary>
    public const string Length = "length";

    /// <summary>More code points than <see cref="SecurityLimits.PasswordMaximumLength"/>.</summary>
    public const string TooLong = "too_long";

    /// <summary>Fewer than 3 of the 4 character classes: lower case, upper case, number and special.</summary>
    public const string Classes = "classes";

    /// <summary>Excellent strength only: more than 2 identical characters in a row.</summary>
    public const string Repeats = "repeats";

    /// <summary>When the policy refuses dictionary words: the lower-cased password is a common password.</summary>
    public const string Dictionary = "dictionary";

    /// <summary>When the policy refuses personal data: the password holds the email's local part or its first domain label of 4 or more characters.</summary>
    public const string PersonalData = "personal_data";

    /// <summary>When the policy keeps a history: the password is one of the User's newest earlier ones.</summary>
    public const string History = "history";

    public static IReadOnlyList<string> All { get; } = [Length, TooLong, Classes, Repeats, Dictionary, PersonalData, History];
}

/// <summary>
/// The hashing budget (Story 4.7, AD-14): how many Argon2id hashes one host computes at once, how many of those one Tenant
/// may hold, and how long a request waits for a slot before it is refused. The defaults are <see cref="Default"/>, from
/// <see cref="SecurityLimits"/>; a host registers its own only to test them.
/// </summary>
public sealed record PasswordHashLimits
{
    public PasswordHashLimits(int concurrency, int tenantShare, TimeSpan wait)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(concurrency);
        ArgumentOutOfRangeException.ThrowIfNegative(tenantShare);
        ArgumentOutOfRangeException.ThrowIfLessThan(wait, TimeSpan.Zero);
        Concurrency = concurrency;
        TenantShare = tenantShare;
        Wait = wait;
    }

    public static PasswordHashLimits Default { get; } = new(
        SecurityLimits.PasswordHashConcurrency, SecurityLimits.PasswordHashTenantShare, SecurityLimits.PasswordHashWait);

    public int Concurrency { get; }

    public int TenantShare { get; }

    public TimeSpan Wait { get; }
}

/// <summary>
/// The hashing budget's gate (Story 4.7, AD-14): a slot for one Argon2id hash for a Tenant, released when disposed, or null
/// when none came free within <see cref="PasswordHashLimits.Wait"/>: the Deployment-wide limit or the Tenant's share is full.
/// </summary>
public interface IPasswordHashGate
{
    Task<IDisposable?> EnterAsync(Guid tenantId, CancellationToken cancellationToken);
}

/// <summary>
/// What Hosted Login shows of the Tenant's sign-up (Story 4.7): whether it is open, which needs the database Connection
/// enabled with sign-up on, and the password policy's minimum length and strength, the rules the strength meter checks in
/// the browser. A Tenant with no database Connection shows sign-up closed, with the policy defaults. From Story 4.8 it
/// also carries the Tenant's terms URL, or null, which Signup asks the User to accept.
/// </summary>
public sealed record SignupPolicy(bool Enabled, int MinLength, string Strength, string? TermsUrl = null);

/// <summary>A sign-in transaction moved on (Story 4.7): its new step version and expiry.</summary>
public sealed record MovedSignIn(int StepVersion, DateTimeOffset ExpiresAt);

/// <summary>How a sign-up ended (Story 4.7).</summary>
public enum SignUpStatus
{
    /// <summary>Sign-up is closed: the transaction went back to Login, and no account was touched.</summary>
    Disabled,

    /// <summary>The password failed the policy: <see cref="SignUpResult.FailedRules"/> names each rule. Nothing written.</summary>
    RuleFailed,

    /// <summary>The Tenant set terms and the sign-up didn't accept them (Story 4.8): checked before the rules and the hash. Nothing written.</summary>
    TermsRequired,

    /// <summary>No hashing slot came free in time: the generic <c>temporarily_unavailable</c>. Nothing written.</summary>
    Unavailable,

    /// <summary>
    /// The sign-up was recorded and the User must verify their email: a new or unverified User got a pending credential,
    /// a link and its email, and an address already verified got nothing but its owner's security notice, identically.
    /// </summary>
    Registered,

    /// <summary>A Dev Tenant with verification off: the User has an active credential and a Session, with no link or email.</summary>
    Authenticated,
}

/// <summary>A sign-up's result (Story 4.7): its status, any failed rules, the transaction's new step version and expiry, and the Session when authenticated.</summary>
public sealed record SignUpResult(
    SignUpStatus Status,
    IReadOnlyList<string> FailedRules,
    int StepVersion,
    DateTimeOffset ExpiresAt,
    StartedSession? Session = null);

/// <summary>"I've verified — continue" (Story 4.7): the transaction's step version and expiry, and the Session once the User's email is verified.</summary>
public sealed record ContinuedSignUp(int StepVersion, DateTimeOffset ExpiresAt, StartedSession? Session);

/// <summary>A verification link's use (Story 4.7): whether it verified, and the Session started when it was opened in the browser that signed up.</summary>
public sealed record LinkVerification(bool Verified, StartedSession? Session, int? StepVersion = null);

/// <summary>
/// Sign-up and email verification through Hosted Login (Story 4.7, FR-17, FR-18), each call one command in the caller's
/// Tenant context and transaction, with its audit events and any email job. No Session exists for a User whose email
/// isn't verified, unless the Tenant is Dev with verification off at sign-up time. Every Session starts through Sessions,
/// with <c>amr: ["pwd"]</c> and the database Connection.
/// </summary>
public interface ISignUp
{
    /// <summary>The Tenant's sign-up as Hosted Login shows it. It writes nothing.</summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    Task<SignupPolicy> ReadPolicyAsync(CommandContext context, CancellationToken cancellationToken);

    /// <summary>
    /// Moves a transaction at Login to Signup (Story 4.7): <see cref="SignInSteps.Signup"/> recorded, <paramref name="email"/>
    /// kept as its identifier when it is a valid address, the step version incremented and the life slid, with
    /// <c>authentication.signin_transaction.extended</c>. Null, writing nothing, when sign-up is closed.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant, or the transaction isn't at Login. Nothing is kept.</exception>
    [StateChanging]
    Task<MovedSignIn?> OpenAsync(CommandContext context, SignInTransaction transaction, string? email, CancellationToken cancellationToken);

    /// <summary>Moves a transaction at Signup back to Login, its identifier kept (Story 4.7), with <c>authentication.signin_transaction.extended</c>.</summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant, or the transaction isn't at Signup. Nothing is kept.</exception>
    [StateChanging]
    Task<MovedSignIn> BackAsync(CommandContext context, SignInTransaction transaction, CancellationToken cancellationToken);

    /// <summary>
    /// Signs up <paramref name="email"/> with <paramref name="password"/> in a transaction at Signup (Story 4.7). Where the
    /// Tenant set a terms URL, <paramref name="acceptTerms"/> must be true, or the sign-up is refused as
    /// <see cref="SignUpStatus.TermsRequired"/> before anything else, writing nothing (Story 4.8); the URL accepted is
    /// recorded on the User. The password is checked against the database Connection's policy first, and refused with every failing rule named and
    /// nothing written; then it is hashed once through the hashing budget, whatever the address, and refused as
    /// unavailable, writing nothing, when no slot comes free. Identity then registers the sign-up: a new or unverified User
    /// gets a pending credential, a link and a verification email in the same command; an address already verified gets
    /// nothing but one <c>security_notification</c> email to its owner (Story 4.8), and the transaction moves on
    /// identically. A Dev Tenant with verification off gets an active credential and
    /// a Session instead, rotating the live one <paramref name="presentedSession"/> names for the same User.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant, or the transaction isn't at Signup. Nothing is kept.</exception>
    /// <exception cref="ArgumentException">The email isn't a valid address (<c>AuthenticationContract.TryNormalizeEmail</c>). Nothing is written.</exception>
    [StateChanging]
    Task<SignUpResult> SignUpAsync(
        CommandContext context,
        SignInTransaction transaction,
        string email,
        Secret<string> password,
        bool acceptTerms,
        Secret<string>? presentedSession,
        CancellationToken cancellationToken);

    /// <summary>
    /// "Resend email" for a registered transaction (Story 4.7): when its sign-up's credential is still pending and its User
    /// unverified, a new link replaces the unused one and the email is enqueued again; otherwise nothing is sent, alike. The
    /// life slides, with <c>authentication.signin_transaction.extended</c>. Its new expiry.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant, or the transaction isn't registered. Nothing is kept.</exception>
    [StateChanging]
    Task<DateTimeOffset> ResendAsync(CommandContext context, SignInTransaction transaction, CancellationToken cancellationToken);

    /// <summary>
    /// "I've verified — continue" for a registered transaction (Story 4.7): once the credential its sign-up made is active,
    /// its User's email verified by a link in this browser or another, a Session starts and
    /// <see cref="SignInSteps.Authenticated"/> is recorded. Otherwise nothing changes, and the Session is null.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant, or the transaction isn't registered. Nothing is kept.</exception>
    [StateChanging]
    Task<ContinuedSignUp> ContinueAsync(
        CommandContext context, SignInTransaction transaction, Secret<string>? presentedSession, CancellationToken cancellationToken);

    /// <summary>
    /// Opens a verification link (Story 4.7): Identity uses it once. When it verified, and <paramref name="transaction"/> is
    /// the live, registered transaction whose sign-up made the link's credential (the same browser), a Session starts and
    /// the transaction records <see cref="SignInSteps.Authenticated"/>. A malformed, foreign, unknown, expired or used link
    /// changes nothing.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    [StateChanging]
    Task<LinkVerification> VerifyLinkAsync(
        CommandContext context,
        Secret<string> token,
        SignInTransaction? transaction,
        Secret<string>? presentedSession,
        CancellationToken cancellationToken);

    /// <summary>
    /// "Send a new link" from an expired or used link's page (Story 4.7): when the link's row still exists and its User is
    /// unverified, a new link for its credential goes out by email; otherwise nothing, and the caller shows the same neutral
    /// confirmation either way. A foreign or malformed link is refused before any lookup.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    [StateChanging]
    Task SendNewLinkAsync(CommandContext context, Secret<string> token, CancellationToken cancellationToken);
}
