namespace Gatekeep.Tests.Isolation.CrossTenant;

/// <summary>How an FR-8 artifact type's cross-Tenant case stands.</summary>
public abstract record ArtifactCoverage
{
    /// <summary>Covered by the named test, which presents a Tenant A artifact at Tenant B and expects refusal.</summary>
    public static ArtifactCoverage Covered(string test) => new CoveredBy(test);

    /// <summary>Not built yet: the backlog story, by its sprint-status id (such as <c>2-10</c>), that builds it and adds its case.</summary>
    public static ArtifactCoverage Pending(string story) => new PendingOn(story);

    public sealed record CoveredBy(string Test) : ArtifactCoverage;

    public sealed record PendingOn(string Story) : ArtifactCoverage;
}

/// <summary>
/// Story 1.31 (FR-8, AD-9, AD-25): every artifact type FR-8 says one Tenant's can never be used at
/// another, each covered by a named test or pending on the story that builds it. Pending entries are
/// held to <c>sprint-status.yaml</c>: once that story is <c>done</c>, its entry must become
/// <see cref="ArtifactCoverage.Covered"/>, so the list can't go stale.
/// </summary>
public static class ArtifactRegistry
{
    /// <summary>FR-8's list, fixed: <see cref="ArtifactRegistryTests"/> fails when one is missing.</summary>
    public static readonly IReadOnlyList<string> Required =
    [
        "authorization code",
        "refresh token",
        "reset link",
        "email code",
        "verification link",
        "invite",
        "Passkey",
        "Recovery Code",
    ];

    public static readonly IReadOnlyDictionary<string, ArtifactCoverage> Types = new Dictionary<string, ArtifactCoverage>(StringComparer.Ordinal)
    {
        ["authorization code"] = ArtifactCoverage.Covered("AuthorizationCodeTests.Tenant_As_code_presented_at_Tenant_B_is_invalid_grant_and_refused_before_any_lookup"),
        ["refresh token"] = ArtifactCoverage.Pending("2-10"),
        ["verification link"] = ArtifactCoverage.Pending("4-7"),
        ["reset link"] = ArtifactCoverage.Pending("4-11"),
        ["Passkey"] = ArtifactCoverage.Pending("6-3"),
        ["Recovery Code"] = ArtifactCoverage.Pending("6-8"),
        ["invite"] = ArtifactCoverage.Pending("8-3"),
        ["email code"] = ArtifactCoverage.Pending("14-6"),
    };
}
