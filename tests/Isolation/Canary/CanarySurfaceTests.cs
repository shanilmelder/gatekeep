using Gatekeep.Kernel.Jobs;
using Gatekeep.Modules.Operations.Contracts;
using Xunit;

namespace Gatekeep.Tests.Isolation.Canary;

/// <summary>
/// Story 7.8: every production surface (job type, Operation type, Cli command, host startup and route)
/// has a canary flow, or a reviewed reason it handles no credential-equivalent value.
/// </summary>
public sealed class CanarySurfaceTests
{
    private static readonly string[] Hosts = ["Admin", "Hosted", "Worker"];

    [Fact]
    public void Every_production_surface_has_a_flow_or_a_reviewed_reason()
    {
        var problems = CanaryFlows.SurfaceProblems(CanaryFlows.ProductionSurfaces(), CanaryFlows.All, CanaryFlows.NoCredentialSurfaces, OperationsContract.ProductionRegistry);

        Assert.Empty(problems);
    }

    [Fact]
    public void Production_surfaces_hold_every_kind()
    {
        var surfaces = CanaryFlows.ProductionSurfaces();

        Assert.Equal(Enum.GetValues<SurfaceKind>(), surfaces.Select(s => s.Kind).Distinct().Order());
        Assert.Equal(
            OperationsContract.ProductionRegistry.Definitions.Count,
            surfaces.Count(s => s.Kind == SurfaceKind.JobType));
        Assert.Equal(Hosts, surfaces.Where(s => s.Kind == SurfaceKind.HostStartup).Select(s => s.Name));
    }

    [Fact]
    public void Cli_commands_are_read_from_the_args_switch()
    {
        var program = File.ReadAllText(Path.Combine(BuildOutput.RepositoryRoot(), "src/Gatekeep.Cli/Program.cs"));

        Assert.Equal(new[] { "audit verify", "init", "migrate" }, CanaryFlows.CliCommands(program));
    }

    [Fact]
    public void Added_Cli_command_is_read()
    {
        const string program =
            """
            return args switch
            {
                ["migrate", "--connection-file", var path] => 0,
                ["tenant", "create", "--name", var name] => 0,
                ["rekey"] when ready => 0,
                _ => ShowUsage(),
            };
            """;

        Assert.Equal(new[] { "migrate", "rekey", "tenant create" }, CanaryFlows.CliCommands(program));
    }

    [Fact]
    public void Fake_job_type_with_no_flow_is_reported()
    {
        var fake = new JobDefinition(
            new JobType("tests.canary.unflowed"),
            JobScope.Tenant,
            [JobRole.Worker],
            JobRole.Worker,
            3,
            (_, _) => Task.CompletedTask,
            mayCarryCredential: true);
        var registry = new JobRegistry([.. OperationsContract.ProductionRegistry.Definitions, fake]);

        var problems = CanaryFlows.SurfaceProblems(Surfaces(registry), CanaryFlows.All, CanaryFlows.NoCredentialSurfaces, registry);

        var problem = Assert.Single(problems);
        Assert.StartsWith("JobType tests.canary.unflowed has no canary flow", problem);
    }

    [Fact]
    public void Fake_Cli_command_with_no_flow_is_reported()
    {
        var surfaces = CanaryFlows.Surfaces(
            OperationsContract.ProductionRegistry,
            OperationsContract.ProductionOperationRegistry,
            ["audit verify", "init", "migrate", "rekey"],
            Hosts,
            CanaryFlows.Routes(BuildOutput.RepositoryRoot()));

        var problem = Assert.Single(CanaryFlows.SurfaceProblems(surfaces, CanaryFlows.All, CanaryFlows.NoCredentialSurfaces, OperationsContract.ProductionRegistry));
        Assert.StartsWith("CliCommand rekey has no canary flow", problem);
    }

    [Fact]
    public void Reason_for_a_surface_that_no_longer_exists_is_reported()
    {
        NoCredentialReason[] reasons =
        [
            .. CanaryFlows.NoCredentialSurfaces,
            new(new(SurfaceKind.JobType, "tests.canary.removed"), "Carries IDs only.", "A reviewer", new DateOnly(2026, 11, 2)),
        ];

        var problem = Assert.Single(CanaryFlows.SurfaceProblems(CanaryFlows.ProductionSurfaces(), CanaryFlows.All, reasons, OperationsContract.ProductionRegistry));
        Assert.StartsWith("JobType tests.canary.removed has a no-credential reason but no longer exists", problem);
    }

    [Theory]
    [InlineData("", "A reviewer", 2026)]
    [InlineData("Carries IDs only.", " ", 2026)]
    [InlineData("Carries IDs only.", "A reviewer", 1)]
    public void Reason_without_text_reviewer_or_date_is_reported(string reason, string reviewer, int year)
    {
        var date = year == 1 ? default : new DateOnly(year, 11, 2);
        var reasons = CanaryFlows.NoCredentialSurfaces
            .Select(r => r.Surface.Name == "operations.job.purge" ? r with { Reason = reason, Reviewer = reviewer, Date = date } : r);

        var problem = Assert.Single(CanaryFlows.SurfaceProblems(CanaryFlows.ProductionSurfaces(), CanaryFlows.All, reasons, OperationsContract.ProductionRegistry));
        Assert.Contains("operations.job.purge has a no-credential reason with no text, reviewer or date", problem);
    }

    [Fact]
    public void Surface_with_both_a_flow_and_a_reason_is_reported()
    {
        NoCredentialReason[] reasons =
        [
            .. CanaryFlows.NoCredentialSurfaces,
            new(new(SurfaceKind.CliCommand, "migrate"), "Reads files only.", "A reviewer", new DateOnly(2026, 11, 2)),
        ];

        var problem = Assert.Single(CanaryFlows.SurfaceProblems(CanaryFlows.ProductionSurfaces(), CanaryFlows.All, reasons, OperationsContract.ProductionRegistry));
        Assert.StartsWith("CliCommand migrate has a canary flow and a no-credential reason", problem);
    }

    [Fact]
    public void Routes_are_the_mapped_patterns_and_the_health_path()
    {
        Assert.Contains("/healthz", CanaryFlows.Routes(BuildOutput.RepositoryRoot()));
        Assert.Equal(
            new[] { "/login", "/token", "/users/{id}" },
            CanaryFlows.RoutesIn(
                """
                app.MapGet("/users/{id}", GetUser);
                app.MapPost( "/token", Token);
                group.MapMethods(@"/login", ["GET", "POST"], Login);
                """).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Fake_route_with_no_flow_is_reported()
    {
        var surfaces = CanaryFlows.Surfaces(
            OperationsContract.ProductionRegistry,
            OperationsContract.ProductionOperationRegistry,
            ["audit verify", "init", "migrate"],
            Hosts,
            [.. CanaryFlows.Routes(BuildOutput.RepositoryRoot()), .. CanaryFlows.RoutesIn("app.MapPost(\"/connect/token\", Token);")]);

        var problem = Assert.Single(CanaryFlows.SurfaceProblems(surfaces, CanaryFlows.All, CanaryFlows.NoCredentialSurfaces, OperationsContract.ProductionRegistry));
        Assert.StartsWith("Route /connect/token has no canary flow", problem);
    }

    [Fact]
    public void Reason_for_a_job_type_that_may_carry_a_credential_is_reported()
    {
        var fake = new JobDefinition(
            new JobType("tests.canary.credential"),
            JobScope.Tenant,
            [JobRole.Worker],
            JobRole.Worker,
            3,
            (_, _) => Task.CompletedTask,
            mayCarryCredential: true);
        var registry = new JobRegistry([.. OperationsContract.ProductionRegistry.Definitions, fake]);
        NoCredentialReason[] reasons =
        [
            .. CanaryFlows.NoCredentialSurfaces,
            new(new(SurfaceKind.JobType, "tests.canary.credential"), "Carries IDs only.", "A reviewer", new DateOnly(2026, 11, 2)),
        ];

        var problem = Assert.Single(CanaryFlows.SurfaceProblems(Surfaces(registry), CanaryFlows.All, reasons, registry));
        Assert.StartsWith("JobType tests.canary.credential may carry a credential", problem);
    }

    [Fact]
    public void Two_reasons_for_one_surface_are_reported()
    {
        NoCredentialReason[] reasons = [.. CanaryFlows.NoCredentialSurfaces, CanaryFlows.NoCredentialSurfaces[0]];

        var problem = Assert.Single(CanaryFlows.SurfaceProblems(
            CanaryFlows.ProductionSurfaces(), CanaryFlows.All, reasons, OperationsContract.ProductionRegistry));
        Assert.StartsWith($"{CanaryFlows.NoCredentialSurfaces[0].Surface} has 2 no-credential reasons", problem);
    }

    [Fact]
    public void Cli_command_with_a_digit_or_underscore_is_read()
    {
        const string program =
            """
            return args switch
            {
                ["rekey_v2"] => 0,
                ["tenant", "export2", "--id", var id] => 0,
                _ => ShowUsage(),
            };
            """;

        Assert.Equal(new[] { "rekey_v2", "tenant export2" }, CanaryFlows.CliCommands(program));
    }

    [Fact]
    public void Cli_arm_the_rule_cant_read_fails()
    {
        const string program =
            """
            return args switch
            {
                ["migrate"] => 0,
                [var command, ..] => Run(command),
                _ => ShowUsage(),
            };
            """;

        var failure = Assert.Throws<InvalidOperationException>(() => CanaryFlows.CliCommands(program));
        Assert.Contains("[var command, ..]", failure.Message);
    }

    private static IReadOnlyList<CanarySurface> Surfaces(JobRegistry registry) =>
        CanaryFlows.Surfaces(
            registry,
            OperationsContract.ProductionOperationRegistry,
            CanaryFlows.CliCommands(File.ReadAllText(Path.Combine(BuildOutput.RepositoryRoot(), "src/Gatekeep.Cli/Program.cs"))),
            CanaryFlows.Hosts(BuildOutput.RepositoryRoot()),
            CanaryFlows.Routes(BuildOutput.RepositoryRoot()));
}
