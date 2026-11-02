using System.Collections;
using System.Reflection;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Jobs;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// AD-15 rules on the production job registry. Tests reference no module, so the
/// registry is read by reflection from Operations' own output folder.
/// </summary>
public class JobRegistryRuleTests
{
    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private const string HostedRole = "gk_hosted";
    private const string AlertDomain = "alerts.";

    private static readonly string[] RunAsRoles = ["gk_worker", "gk_sealer", "gk_retention"];

    /// <summary>Roles that may enqueue only types under one domain (AD-15).</summary>
    private static readonly Dictionary<string, string> DomainOnly = new()
    {
        ["gk_hosted"] = "notifications.",
        ["gk_sealer"] = "alerts.",
    };

    [Fact]
    public void Production_registry_is_found_and_not_empty()
    {
        Assert.NotEmpty(ProductionDefinitions());
    }

    [Fact]
    public void Production_registry_follows_every_rule()
    {
        Assert.Empty(ProductionDefinitions().SelectMany(Violations));
    }

    [Fact]
    public void Unreviewed_deployment_wide_type_is_reported()
    {
        var definition = Sample() with { Review = null };

        Assert.Contains(Violations(definition), v => v.Contains("review", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("", "a reason")]
    [InlineData("A reviewer", " ")]
    public void Review_without_a_reviewer_or_reason_is_reported(string reviewer, string reason)
    {
        var definition = Sample() with { Review = new Review(reviewer, new DateOnly(2026, 11, 2), reason) };

        Assert.Contains(Violations(definition), v => v.Contains("review", StringComparison.Ordinal));
    }

    [Fact]
    public void Reviewed_tenant_or_deployment_type_passes()
    {
        Assert.Empty(Violations(Sample()));
        Assert.Empty(Violations(Sample() with { Scope = "Tenant", Review = null }));
    }

    [Theory]
    [InlineData("gk_hosted", "operations.job.purge", true)]
    [InlineData("gk_hosted", "notifications.email.send", false)]
    [InlineData("gk_sealer", "notifications.email.send", true)]
    [InlineData("gk_sealer", "alerts.security.send", false)]
    [InlineData("gk_worker", "alerts.security.send", false)]
    public void Hosted_and_sealer_enqueue_only_their_domain(string role, string type, bool reported)
    {
        var definition = Sample() with { Type = type, Scope = "Tenant", Roles = [role] };

        Assert.Equal(reported, Violations(definition).Any(v => v.Contains(role, StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("Tenant", false)]
    [InlineData("DeploymentWide", true)]
    public void Hosted_enqueues_only_Tenant_scoped_types(string scope, bool reported)
    {
        var definition = Sample() with { Type = "notifications.email.send", Scope = scope, Roles = ["gk_hosted"] };

        Assert.Equal(reported, Violations(definition).Any(v => v.Contains("Tenant-scoped", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("alerts.security.send", true, false)]
    [InlineData("alerts.security.send", false, true)]
    [InlineData("notifications.email.send", true, true)]
    [InlineData("notifications.email.send", false, false)]
    public void Never_dead_exactly_when_an_alert_type(string type, bool neverDead, bool reported)
    {
        var definition = Sample() with { Type = type, Scope = "Tenant", Roles = ["gk_worker"], NeverDead = neverDead };

        Assert.Equal(reported, Violations(definition).Any(v => v.Contains("never-dead", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("gk_worker", false)]
    [InlineData("gk_sealer", false)]
    [InlineData("gk_retention", false)]
    [InlineData("gk_admin", true)]
    [InlineData("gk_dispatch", true)]
    public void Run_as_is_one_of_the_three_roles(string runAs, bool reported)
    {
        Assert.Equal(reported, Violations(Sample() with { RunAs = runAs }).Any(v => v.Contains("runs as", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("operations.job.purge", false)]
    [InlineData("Operations.Job.Purge", true)]
    [InlineData("operations.purge", true)]
    public void Type_code_matches_the_audit_code_pattern(string type, bool reported)
    {
        Assert.Equal(reported, Violations(Sample() with { Type = type }).Any(v => v.Contains("pattern", StringComparison.Ordinal)));
    }

    private static Definition Sample() => new(
        "operations.job.purge",
        "DeploymentWide",
        ["gk_worker"],
        "gk_worker",
        new Review("A reviewer", new DateOnly(2026, 11, 2), "A reason"));

    private static IEnumerable<string> Violations(Definition definition)
    {
        if (!IsAuditCode(definition.Type))
        {
            yield return $"{definition.Type}: type code doesn't match the audit code pattern.";
        }

        if (definition.Scope == "DeploymentWide"
            && (definition.Review is null
                || string.IsNullOrWhiteSpace(definition.Review.Reviewer)
                || string.IsNullOrWhiteSpace(definition.Review.Reason)
                || definition.Review.Date == default))
        {
            yield return $"{definition.Type}: Deployment-wide type has no recorded review.";
        }

        if (!RunAsRoles.Contains(definition.RunAs))
        {
            yield return $"{definition.Type}: runs as {definition.RunAs}.";
        }

        if (definition.Roles.Contains(HostedRole) && definition.Scope != "Tenant")
        {
            yield return $"{definition.Type}: {HostedRole} may enqueue only Tenant-scoped types.";
        }

        if (definition.NeverDead != definition.Type.StartsWith(AlertDomain, StringComparison.Ordinal))
        {
            yield return $"{definition.Type}: a type is never-dead exactly when it is an {AlertDomain}* type.";
        }

        foreach (var (role, domain) in DomainOnly)
        {
            if (definition.Roles.Contains(role) && !definition.Type.StartsWith(domain, StringComparison.Ordinal))
            {
                yield return $"{definition.Type}: {role} may enqueue only {domain}* types.";
            }
        }
    }

    private static bool IsAuditCode(string type)
    {
        try
        {
            _ = new AuditTypeCode(type);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static List<Definition> ProductionDefinitions()
    {
        // Output folders mirror this test's, so the solution build provides the assembly.
        var output = Path.GetRelativePath(
            Path.Combine(Root, "tests/Architecture"),
            AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        var assembly = Assembly.LoadFrom(
            Path.Combine(Root, "src/Modules/Operations", output, "Gatekeep.Modules.Operations.dll"));

        var contract = assembly.GetType("Gatekeep.Modules.Operations.Contracts.OperationsContract", throwOnError: true)!;
        var registry = contract.GetProperty("ProductionRegistry")!.GetValue(null)!;
        var definitions = (IEnumerable)registry.GetType().GetProperty("Definitions")!.GetValue(registry)!;

        return [.. definitions.Cast<object>().Select(Read)];
    }

    private static Definition Read(object definition)
    {
        object? Get(object target, string name) => target.GetType().GetProperty(name)!.GetValue(target);

        var review = Get(definition, "Review");

        return new Definition(
            ((JobType)Get(definition, "Type")!).Value,
            Get(definition, "Scope")!.ToString()!,
            [.. (IEnumerable<string>)Get(definition, "EnqueuingRoles")!],
            (string)Get(definition, "RunAs")!,
            review is null
                ? null
                : new Review((string)Get(review, "Reviewer")!, (DateOnly)Get(review, "Date")!, (string)Get(review, "Reason")!),
            (bool)Get(definition, "NeverDead")!);
    }

    private sealed record Review(string Reviewer, DateOnly Date, string Reason);

    private sealed record Definition(
        string Type,
        string Scope,
        IReadOnlyList<string> Roles,
        string RunAs,
        Review? Review,
        bool NeverDead = false);
}
