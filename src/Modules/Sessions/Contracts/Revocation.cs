namespace Gatekeep.Modules.Sessions.Contracts;

/// <summary>
/// What <see cref="ISessions.RevokeAccessAsync"/> ends (AD-13). A closed set: the only kinds are
/// the nested records here. Every one is limited to the context's Tenant.
/// </summary>
public abstract record RevocationScope
{
    private RevocationScope()
    {
    }

    private static Guid NonEmpty(Guid id, string kind) =>
        id == Guid.Empty ? throw new ArgumentException($"A {kind} scope needs a non-empty ID.", nameof(id)) : id;

    /// <summary>
    /// One Token Family and its tokens. No Session ends. Refresh reuse and code replay use it,
    /// so the User stays signed in.
    /// </summary>
    public sealed record Authorization : RevocationScope
    {
        public Authorization(Guid id) => Id = NonEmpty(id, nameof(Authorization));

        public Guid Id { get; }
    }

    /// <summary>One Session, and every Token Family anchored to it with their tokens.</summary>
    public sealed record Session : RevocationScope
    {
        public Session(Guid id) => Id = NonEmpty(id, nameof(Session));

        public Guid Id { get; }
    }

    /// <summary>
    /// Every live Session of one User, and every Token Family anchored to that User's Sessions
    /// with their tokens. The only scope that can spare an acting Session.
    /// </summary>
    public sealed record User : RevocationScope
    {
        public User(Guid id) => Id = NonEmpty(id, nameof(User));

        public Guid Id { get; }
    }

    /// <summary>
    /// Every Token Family of one Application, and every token of that Application. No Session ends.
    /// </summary>
    public sealed record Application : RevocationScope
    {
        public Application(Guid id) => Id = NonEmpty(id, nameof(Application));

        public Guid Id { get; }
    }

    /// <summary>The whole of the context's Tenant: every live Session, every Token Family and every token.</summary>
    public sealed record Tenant : RevocationScope;
}

/// <summary>
/// Why access was revoked. A closed set with fixed snake_case codes, which become a Session's
/// <c>end_reason</c>. A database check holds the column to exactly these codes.
/// </summary>
public sealed record RevocationReason
{
    public static readonly RevocationReason Logout = new("logout");
    public static readonly RevocationReason CredentialChange = new("credential_change");
    public static readonly RevocationReason AdminRevoke = new("admin_revoke");
    public static readonly RevocationReason UserBlocked = new("user_blocked");
    public static readonly RevocationReason UserDeleted = new("user_deleted");
    public static readonly RevocationReason TokenReuse = new("token_reuse");
    public static readonly RevocationReason CodeReplay = new("code_replay");
    public static readonly RevocationReason ApplicationDeleted = new("application_deleted");
    public static readonly RevocationReason TenantDeleted = new("tenant_deleted");

    /// <summary>Every reason, in declaration order.</summary>
    public static readonly IReadOnlyList<RevocationReason> All =
    [
        Logout,
        CredentialChange,
        AdminRevoke,
        UserBlocked,
        UserDeleted,
        TokenReuse,
        CodeReplay,
        ApplicationDeleted,
        TenantDeleted,
    ];

    private RevocationReason(string code) => Code = code;

    public string Code { get; }

    public override string ToString() => Code;
}

/// <summary>
/// How many rows one revocation changed. A repeated call changes nothing and returns zeros.
/// </summary>
public sealed record RevocationOutcome(int SessionsEnded, int FamiliesRevoked, int TokensRevoked);
