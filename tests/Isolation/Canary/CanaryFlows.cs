using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Gatekeep.Adapters.AlertChannel;
using Gatekeep.Adapters.Logging;
using Gatekeep.Adapters.OpenBao;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Cli;
using Gatekeep.Kernel.Alerts;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Tests.Isolation.Audit;
using Gatekeep.Tests.Isolation.Hosting;
using Gatekeep.Tests.Isolation.Jobs;
using Gatekeep.Tests.Isolation.OffServer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Canary;

/// <summary>The production surfaces every credential-equivalent value could enter by.</summary>
internal enum SurfaceKind
{
    JobType,
    OperationType,
    CliCommand,
    HostStartup,
    Route,
}

internal sealed record CanarySurface(SurfaceKind Kind, string Name)
{
    public override string ToString() => $"{Kind} {Name}";
}

/// <summary>
/// A reviewed reason a surface handles no credential-equivalent value, so it needs no canary
/// flow. A reason for a surface that no longer exists fails a test, so the list can't go stale.
/// </summary>
internal sealed record NoCredentialReason(CanarySurface Surface, string Reason, string Reviewer, DateOnly Date);

/// <summary>What one run of a flow planted, and everything it left to scan.</summary>
internal sealed class FlowRun
{
    private readonly List<Canary> _canaries = [];
    private readonly List<CanarySource> _outputs = [];

    public IReadOnlyList<Canary> Canaries => _canaries;

    public IReadOnlyList<CanarySource> Outputs => _outputs;

    /// <summary>The database the run wrote to, scanned table by table. Null when it reached none.</summary>
    public string? Database { get; set; }

    /// <summary>A fresh canary of <paramref name="kind"/>: 16 characters at least, and no known default.</summary>
    public Canary Plant(string kind) => Plant(kind, $"cnry-{kind}-{Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8))}");

    /// <summary>A value the run passes that it didn't make, such as the test database's role password.</summary>
    public Canary Plant(string kind, string value)
    {
        var canary = new Canary(kind, value, value);
        _canaries.Add(canary);
        return canary;
    }

    public void Capture(string source, string text) => _outputs.Add(new CanarySource(source, text));

    public void Capture(string command, CliResult result)
    {
        Capture($"{command} stdout", result.StandardOutput);
        Capture($"{command} stderr", result.StandardError);
    }
}

/// <summary>What a flow can use: the database cluster, the Object Lock bucket, OpenBao, a scratch folder, and the test's cancellation.</summary>
internal sealed class CanaryFlowContext(PostgresFixture postgres, string directory, OffServer.ObjectLockFixture bucket, Gatekeep.Tests.Isolation.Custody.OpenBaoFixture? bao = null) : IDisposable
{
    private readonly List<IDisposable> _owned = [];

    public PostgresFixture Postgres => postgres;

    /// <summary>The Object Lock bucket (Story 1.30), whose objects a flow scans with their metadata.</summary>
    public OffServer.ObjectLockFixture Bucket => bucket;

    /// <summary>The real OpenBao, for a flow that signs through Transit (Story 2.5).</summary>
    public Gatekeep.Tests.Isolation.Custody.OpenBaoFixture Bao => bao ?? throw new InvalidOperationException("This run has no OpenBao.");

    public static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public string File(string contents)
    {
        var path = Path.Combine(directory, Guid.NewGuid().ToString("N"));
        System.IO.File.WriteAllText(path, contents);
        return path;
    }

    /// <summary>A fresh, empty, owner-only folder under the scratch folder.</summary>
    public string NewDirectory()
    {
        var path = Path.Combine(directory, Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(path);
        if (!OperatingSystem.IsWindows())
        {
            System.IO.File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        return path;
    }

    public FakeOpenBaoSocket Socket(int status = 200)
    {
        var socket = new FakeOpenBaoSocket(status);
        _owned.Add(socket);
        return socket;
    }

    public void Dispose()
    {
        foreach (var owned in _owned)
        {
            owned.Dispose();
        }
    }
}

/// <summary>
/// Runs one flow, normally when <paramref name="failing"/> is false, otherwise forced down its own
/// failure path: a refused database, a Transit error, an exhausted job, a refused insert. Trace
/// logging is on in both. The flow plants its canaries in <paramref name="run"/> and captures its
/// output there, and asserts it really took the path it names.
/// </summary>
internal delegate Task FlowBody(CanaryFlowContext context, FlowRun run, bool failing);

/// <summary>One code-owned canary flow, and the production surfaces it covers.</summary>
internal sealed record CanaryFlow(string Name, IReadOnlyList<CanarySurface> Surfaces, FlowBody RunAsync)
{
    public override string ToString() => Name;
}

/// <summary>
/// The canary flow registry (NFR-3, AR-33, T-42). Every production surface has a flow here, or a
/// reviewed reason in <see cref="NoCredentialSurfaces"/>: <c>CanarySurfaceTests</c> fails on any
/// other. Each flow plants its canaries through the real path and <c>CanaryFlowTests</c> scans every
/// table, log, stream and response it left, normal and failing, at Trace.
/// </summary>
internal static class CanaryFlows
{
    private const string HealthEndpoint = "/healthz";

    /// <summary>The <c>migrate</c>, <c>audit verify</c>, <c>init</c> and <c>rotate-transit-keys</c> commands, from the Cli's <c>args switch</c>.</summary>
    private const string CliProgram = "src/Gatekeep.Cli/Program.cs";

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-0000000007a8");

    /// <summary>The Cli has no logger, but it gets the hosts' Trace switch too, so nothing it might read is missed.</summary>
    private static readonly Dictionary<string, string> DebugEnvironment = new()
    {
        ["Logging__LogLevel__Default"] = "Trace",
    };

    private static readonly string[] DebugArguments =
        ["--Logging:LogLevel:Default=Trace", "--Logging:LogLevel:Microsoft=Trace", "--Logging:LogLevel:Microsoft.AspNetCore=Trace"];

    private static readonly Regex CliPattern = new(
        @"\A\s*\[\s*""(?<first>[A-Za-z0-9_][A-Za-z0-9_-]*)""(?:\s*,\s*""(?<second>[A-Za-z0-9_][A-Za-z0-9_-]*)"")?",
        RegexOptions.Compiled);

    /// <summary>A route registered with a literal pattern: <c>MapGet("/x", …)</c> and its kin.</summary>
    private static readonly Regex MappedRoute = new(
        @"\bMap(?:Get|Post|Put|Patch|Delete|Methods)?\s*\(\s*@?""(?<route>[^""]*)""",
        RegexOptions.Compiled);

    /// <summary>The health endpoint matches its path itself, as no route is mapped for it.</summary>
    private const string HealthSource = "src/Adapters/Hosting/HealthEndpoint.cs";

    private static readonly Regex HealthPath = new(@"\bconst\s+string\s+Path\s*=\s*""(?<route>/[^""]*)""", RegexOptions.Compiled);

    public static readonly IReadOnlyList<CanaryFlow> All =
    [
        new("cli.migrate", [new(SurfaceKind.CliCommand, "migrate")], MigrateAsync),
        new("cli.audit-verify", [new(SurfaceKind.CliCommand, "audit verify")], AuditVerifyAsync),
        new("cli.init", [new(SurfaceKind.CliCommand, "init")], InitAsync),
        new("cli.rotate-transit-keys", [new(SurfaceKind.CliCommand, "rotate-transit-keys")], RotateTransitKeysAsync),
        new("alerts.channel", [new(SurfaceKind.CliCommand, "alerts test")], AlertsChannelAsync),
        new("records.objectlock", [new(SurfaceKind.CliCommand, "records test")], RecordsObjectLockAsync),
        new("openbao.audit.ship", [new(SurfaceKind.CliCommand, "audit-ship")], AuditShipAsync),
        new("host.hosted", [new(SurfaceKind.HostStartup, "Hosted"), new(SurfaceKind.Route, HealthEndpoint)], HostAsync("Hosted")),
        new("host.admin", [new(SurfaceKind.HostStartup, "Admin"), new(SurfaceKind.Route, HealthEndpoint)], HostAsync("Admin")),
        new("host.worker", [new(SurfaceKind.HostStartup, "Worker"), new(SurfaceKind.Route, HealthEndpoint)], HostAsync("Worker")),
        new(
            "admin.bootstrap",
            [
                new(SurfaceKind.Route, "/api/v1/deployment/bootstrap"),
                new(SurfaceKind.Route, "/api/v1/deployment/session"),
                new(SurfaceKind.Route, "/api/v1/deployment/capabilities"),
            ],
            BootstrapClaimAsync),
        new(
            "admin.credentials",
            [
                new(SurfaceKind.Route, "/api/v1/deployment/credentials/registration"),
                new(SurfaceKind.Route, "/api/v1/deployment/credentials/registration/complete"),
            ],
            CredentialRegistrationAsync),
        new(
            "admin.signin",
            [
                new(SurfaceKind.Route, "/api/v1/deployment/signin"),
                new(SurfaceKind.Route, "/api/v1/deployment/signin/complete"),
                new(SurfaceKind.Route, "/api/v1/tenants/{tenantId}/capabilities"),
            ],
            SignInAsync),
        new(
            "admin.fresh-assertions",
            [
                new(SurfaceKind.Route, "/api/v1/deployment/assertions"),
                new(SurfaceKind.Route, "/api/v1/deployment/assertions/complete"),
                new(SurfaceKind.Route, "/api/v1/deployment/credentials"),
                new(SurfaceKind.Route, "/api/v1/deployment/credentials/{credentialId}"),
            ],
            FreshAssertionAsync),
        new(
            "admin.recovery-code",
            [
                new(SurfaceKind.Route, "/api/v1/deployment/credentials/recovery-code"),
                new(SurfaceKind.Route, "/api/v1/deployment/credentials/recovery-code/confirm"),
                new(SurfaceKind.Route, "/api/v1/deployment/signin/recovery-code"),
            ],
            RecoveryCodeAsync),
        new(
            "admin.enrolment",
            [
                new(SurfaceKind.CliCommand, "recover-admin"),
                new(SurfaceKind.Route, "/api/v1/deployment/signin/enrolment"),
            ],
            EnrolmentAsync),
        new(
            "admin.tenants",
            [
                new(SurfaceKind.Route, "/api/v1/deployment/tenants"),
                new(SurfaceKind.Route, "/api/v1/deployment/operations/{operationId}/retry"),
                new(SurfaceKind.Route, "/api/v1/tenants/{tenantId}/operations/{operationId}"),
            ],
            TenantsAsync),
        new(
            "admin.tenant-label",
            [
                new(SurfaceKind.Route, "/api/v1/deployment/my-tenants"),
                new(SurfaceKind.Route, "/api/v1/tenants/{tenantId}/label"),
                new(SurfaceKind.Route, "/api/v1/tenants/{tenantId}/assertions"),
            ],
            TenantLabelAsync),
        new(
            "admin.tenant-deletion",
            [
                new(SurfaceKind.Route, "/api/v1/deployment/tenants/{targetTenantId}/deletion"),
                new(SurfaceKind.Route, "/api/v1/deployment/tenants/{targetTenantId}/deletion/retry"),
            ],
            TenantDeletionAsync),
        new(
            "admin.tenant-logs",
            [
                new(SurfaceKind.Route, "/api/v1/tenants/{tenantId}/logs"),
            ],
            TenantLogsAsync),

        // No production type carries a credential yet, so this flow takes the runner's credential
        // path with a test type: enqueue, decrypt, run, retry and dead, as every one will.
        new("jobs.credential", [], CredentialJobAsync),
        new("custody.openbao", [], CustodyAsync),
        new("audit.appender", [], AppenderAsync),

        // OpenIddict's routes are no Map… literal, so the token endpoint names no surface: it is covered here.
        new("protocol.client_credentials", [], ClientCredentialsAsync),
        new("protocol.authorization_code", [], AuthorizationCodeAsync),
        new("protocol.refresh_token", [], RefreshTokenAsync),
        new("protocol.userinfo_and_revocation", [], UserinfoAndRevocationAsync),
    ];

    private static readonly DateOnly Reviewed = new(2026, 11, 2);

    private const string Reviewer = "Story 7.8 build review";

    public static readonly IReadOnlyList<NoCredentialReason> NoCredentialSurfaces =
    [
        new(
            new(SurfaceKind.JobType, "operations.job.purge"),
            "Deployment-wide, so it carries no payload. Deletes done job rows by age only.",
            Reviewer,
            Reviewed),
        new(
            new(SurfaceKind.JobType, "operations.operation.run"),
            "Deployment-wide, so it carries no payload. Its only parameter is the operation_id.",
            Reviewer,
            Reviewed),
        new(
            new(SurfaceKind.JobType, "operations.operation.step"),
            "May not carry a credential: its payload is the operation_id and step_id only, as the registry and the job_payload CHECK enforce.",
            Reviewer,
            Reviewed),
        new(
            new(SurfaceKind.JobType, "audit.retention.sweep"),
            "Deployment-wide, so it carries no payload. Reads Tenant IDs and enqueues ID-only jobs.",
            Reviewer,
            Reviewed),
        new(
            new(SurfaceKind.JobType, "audit.retention.apply"),
            "Carries no payload and may not carry a credential. Cuts its own chain by seq and writes a checkpoint of IDs and a hash.",
            Reviewer,
            Reviewed),
        new(
            new(SurfaceKind.JobType, "audit.retention.deployment"),
            "Deployment-wide, so it carries no payload. Cuts the Deployment chain by seq.",
            Reviewer,
            Reviewed),
        new(
            new(SurfaceKind.JobType, "audit.chain.purge"),
            "Carries no payload and may not carry a credential. Deletes one Tenant's sealed chain by its Tenant ID.",
            Reviewer,
            Reviewed),
        new(
            new(SurfaceKind.OperationType, "audit.chain.purge"),
            "Its one Tenant stage stores only fixed result codes, and enqueues the ID-only purge job.",
            Reviewer,
            Reviewed),
        new(
            new(SurfaceKind.JobType, "keys.tenant_keys.backfill"),
            "Deployment-wide, so it carries no payload. Reads active Tenant IDs; per Tenant it creates keys by name in custody "
            + "and stores only key names, versions and Transit's wrapped ciphertext, with an ID-only event. No key material leaves custody.",
            "Story 2.3 build review",
            new DateOnly(2026, 11, 5)),
        new(
            new(SurfaceKind.JobType, "keys.signing_keys.rotate"),
            "Deployment-wide, so it carries no payload. Reads active Tenant IDs; per Tenant it changes key row states and times, "
            + "creates keys by name in custody, stores only names and versions, enqueues ID-only jobs and writes ID-only events. No key material leaves custody.",
            "Story 2.4 build review",
            new DateOnly(2026, 11, 5)),
        new(
            new(SurfaceKind.JobType, "keys.signing_key.destroy"),
            "May not carry a credential: its payload is one signing_key row ID. It deletes a key by the name the row's own IDs make "
            + "and writes ID-only events. Failures are logged by type only.",
            "Story 2.4 build review",
            new DateOnly(2026, 11, 5)),
        new(
            new(SurfaceKind.JobType, "keys.transit_keys.sweep"),
            "Deployment-wide, so it carries no payload. Lists key names and creation times in custody, deletes unnamed old sig-/mgmt- keys "
            + "and writes ID-only Deployment events. Failures are logged by type only, never a key name.",
            "Story 2.4 build review",
            new DateOnly(2026, 11, 5)),
        new(
            new(SurfaceKind.OperationType, "tenancy.tenant.create"),
            "Its Tenant stages create the six secret class keys, then the Signing and Management keys and the wrapped token "
            + "protection key, by name only, storing key names, versions, Transit's ciphertext and fixed result codes; its "
            + "completion inserts an empty settings row, sets the status and writes an ID-only event. No key material leaves custody.",
            "Story 2.3 build review",
            new DateOnly(2026, 11, 5)),
        new(
            new(SurfaceKind.OperationType, "tenancy.tenant.delete"),
            "Its two Tenant stages delete the Tenant's rows by its ID and destroy its six secret class keys and its Signing and "
            + "Management keys by name only, and store fixed result codes; its completion sets the status, writes an ID-only event "
            + "and enqueues the ID-only purge job.",
            "Story 1.29 build review",
            new DateOnly(2026, 11, 5)),
        new(
            new(SurfaceKind.Route, "/api/v1/tenants/{tenantId}/signing-keys"),
            "A read with no body: it returns the path Tenant's signing rows' key IDs, fixed algorithm, states and creation times, "
            + "never key material, ciphertext or a Management key, and writes nothing. Refusals are logged by fixed code only.",
            "Story 9.1 build review",
            new DateOnly(2026, 11, 6)),
        new(
            new(SurfaceKind.Route, "/api/v1/tenants/{tenantId}/signing-keys/jwks"),
            "A read with no body: it returns the public halves custody gives for the path Tenant's published Signing Keys, as JWKS "
            + "members, never a private member or a Management key, and writes nothing. A custody failure logs one fixed message with "
            + "the trace ID, never a key name or version.",
            "Story 9.1 build review",
            new DateOnly(2026, 11, 6)),
        new(
            new(SurfaceKind.Route, "/api/v1/tenants/{tenantId}/applications"),
            "The list reads the path Tenant's Applications' IDs, names, types and creation times; the create takes a name and a "
            + "type only, writes the row and an ID-only event, and creates no client secret. Neither returns or logs a credential: "
            + "refusals are logged by fixed code only, never the name.",
            "Story 3.1 build review",
            new DateOnly(2026, 11, 11)),
        new(
            new(SurfaceKind.Route, "/api/v1/tenants/{tenantId}/applications/{applicationId}"),
            "A read with no body: it returns one of the path Tenant's Applications' ID, name, type and creation time, never a "
            + "secret or hash, and writes nothing. Refusals are logged by fixed code only.",
            "Story 3.1 build review",
            new DateOnly(2026, 11, 11)),
    ];

    /// <summary>Every production surface: the job and Operation registries, the Cli's commands and the hosts.</summary>
    public static IReadOnlyList<CanarySurface> ProductionSurfaces() =>
        Surfaces(
            OperationsContract.ProductionRegistry,
            OperationsContract.ProductionOperationRegistry,
            CliCommands(File.ReadAllText(Path.Combine(BuildOutput.RepositoryRoot(), CliProgram))),
            Hosts(BuildOutput.RepositoryRoot()),
            Routes(BuildOutput.RepositoryRoot()));

    public static IReadOnlyList<CanarySurface> Surfaces(
        JobRegistry jobs,
        OperationRegistry operations,
        IEnumerable<string> cliCommands,
        IEnumerable<string> hosts,
        IEnumerable<string> routes) =>
        [
            .. jobs.Definitions.Select(d => new CanarySurface(SurfaceKind.JobType, d.Type.Value)),
            .. operations.Definitions.Select(d => new CanarySurface(SurfaceKind.OperationType, d.Type.Value)),
            .. cliCommands.Select(c => new CanarySurface(SurfaceKind.CliCommand, c)),
            .. hosts.Select(h => new CanarySurface(SurfaceKind.HostStartup, h)),
            .. routes.Select(r => new CanarySurface(SurfaceKind.Route, r)),
        ];

    /// <summary>
    /// Each command a case of the Cli's <c>args switch</c> starts with: its leading literal
    /// words, before any option. <c>["migrate", "--connection-file", var path]</c> is <c>migrate</c>.
    /// </summary>
    public static IReadOnlyList<string> CliCommands(string program)
    {
        var start = program.IndexOf("args switch", StringComparison.Ordinal);
        if (start < 0)
        {
            throw new InvalidOperationException($"{CliProgram} has no args switch.");
        }

        var end = program.IndexOf("};", start, StringComparison.Ordinal);
        var cases = program[start..(end < 0 ? program.Length : end)];

        var commands = new List<string>();
        foreach (var line in cases.ReplaceLineEndings("\n").Split('\n').Where(l => l.TrimStart().StartsWith('[')))
        {
            // An arm the rule can't read would hide a command, so it fails rather than being skipped.
            var match = CliPattern.Match(line);
            if (!match.Success)
            {
                throw new InvalidOperationException($"{CliProgram} has an args switch arm the canary surface rule can't read: {line.Trim()}");
            }

            commands.Add(match.Groups["second"].Success ? $"{match.Groups["first"].Value} {match.Groups["second"].Value}" : match.Groups["first"].Value);
        }

        return [.. commands.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];
    }

    /// <summary>
    /// Every HTTP route in <c>src</c>: each literal <c>Map…("…")</c> pattern, and the health
    /// endpoint's path, which it matches itself.
    /// </summary>
    public static IReadOnlyList<string> Routes(string root)
    {
        var sources = Directory.EnumerateFiles(Path.Combine(root, "src"), "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(p => p is "bin" or "obj"))
            .Select(File.ReadAllText);

        var health = HealthPath.Match(File.ReadAllText(Path.Combine(root, HealthSource)));
        if (!health.Success)
        {
            throw new InvalidOperationException($"{HealthSource} no longer declares its path.");
        }

        return [.. sources.SelectMany(RoutesIn)
            .Append(health.Groups["route"].Value)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];
    }

    public static IEnumerable<string> RoutesIn(string source) =>
        MappedRoute.Matches(source).Select(m => m.Groups["route"].Value);

    /// <summary>Each <c>src/Gatekeep.Host.*</c> project, by the name its startup refusal uses.</summary>
    public static IReadOnlyList<string> Hosts(string root) =>
        [.. Directory.EnumerateDirectories(Path.Combine(root, "src"), "Gatekeep.Host.*")
            .Select(d => Path.GetFileName(d)["Gatekeep.Host.".Length..])
            .Order(StringComparer.Ordinal)];

    /// <summary>
    /// Every way the surfaces, flows and reasons disagree: a surface with neither a flow nor a
    /// reason, a surface with both, a reason for a surface that no longer exists, two reasons for
    /// one surface, a reason missing its text, reviewer or date, and a no-credential reason for a
    /// job type in <paramref name="jobs"/> that may carry a credential. Empty when they agree.
    /// </summary>
    public static IReadOnlyList<string> SurfaceProblems(
        IReadOnlyList<CanarySurface> surfaces,
        IEnumerable<CanaryFlow> flows,
        IEnumerable<NoCredentialReason> reasons,
        JobRegistry jobs)
    {
        var covered = flows.SelectMany(f => f.Surfaces).ToHashSet();
        var reasonList = reasons.ToList();
        var reasoned = reasonList.Select(r => r.Surface).ToHashSet();
        var existing = surfaces.ToHashSet();
        var credentialTypes = jobs.Definitions
            .Where(d => d.MayCarryCredential)
            .Select(d => new CanarySurface(SurfaceKind.JobType, d.Type.Value))
            .ToHashSet();

        return
        [
            .. SurfaceProblems(surfaces, covered, reasonList, reasoned, existing),
            .. reasonList
                .GroupBy(r => r.Surface)
                .Where(g => g.Count() > 1)
                .Select(g => $"{g.Key} has {g.Count()} no-credential reasons: keep one."),
            .. reasonList
                .Where(r => credentialTypes.Contains(r.Surface))
                .Select(r => $"{r.Surface} may carry a credential, so it needs a canary flow, not a no-credential reason."),
        ];
    }

    private static IEnumerable<string> SurfaceProblems(
        IReadOnlyList<CanarySurface> surfaces,
        HashSet<CanarySurface> covered,
        List<NoCredentialReason> reasonList,
        HashSet<CanarySurface> reasoned,
        HashSet<CanarySurface> existing)
    {

        return
        [
            .. surfaces
                .Where(s => !covered.Contains(s) && !reasoned.Contains(s))
                .Select(s => $"{s} has no canary flow and no reviewed reason it handles no credential-equivalent value."),
            .. surfaces
                .Where(s => covered.Contains(s) && reasoned.Contains(s))
                .Select(s => $"{s} has a canary flow and a no-credential reason: keep one."),
            .. covered
                .Where(s => !existing.Contains(s))
                .Select(s => $"A canary flow covers {s}, which no longer exists."),
            .. reasonList
                .Where(r => !existing.Contains(r.Surface))
                .Select(r => $"{r.Surface} has a no-credential reason but no longer exists: remove the reason."),
            .. reasonList
                .Where(r => string.IsNullOrWhiteSpace(r.Reason) || string.IsNullOrWhiteSpace(r.Reviewer) || r.Date == default)
                .Select(r => $"{r.Surface} has a no-credential reason with no text, reviewer or date."),
        ];
    }

    private static async Task MigrateAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        string connection;
        Canary password;
        if (failing)
        {
            password = run.Plant("password-file");
            connection = RefusedConnection(TableRegistry.Migrator);
        }
        else
        {
            run.Database = await context.Postgres.NewUnmigratedDatabaseAsync();
            password = run.Plant("role-password", PostgresFixture.Password);
            connection = Passwordless(context.Postgres.RoleConnection(TableRegistry.Migrator, run.Database));
        }

        var result = await CliProcess.RunCapturedAsync(
            DebugEnvironment, "migrate", "--connection-file", context.File(connection), "--password-file", context.File(password.Value + "\n"));
        run.Capture("migrate", result);

        Assert.True(result.ExitCode == (failing ? 1 : 0), result.StandardOutput + result.StandardError);
    }

    private static async Task AuditVerifyAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        string connection;
        Canary password;
        if (failing)
        {
            password = run.Plant("password-file");
            connection = RefusedConnection(TableRegistry.Cli);
        }
        else
        {
            var chains = await AuditChains.CreateAsync(context.Postgres, AuditChains.TenantA);
            await chains.SealedChainAsync(AuditChains.TenantA, 2);
            await chains.SealedChainAsync(null, 1);
            run.Database = chains.Name;
            password = run.Plant("role-password", PostgresFixture.Password);
            connection = Passwordless(chains.Connection(TableRegistry.Cli));
        }

        var result = await CliProcess.RunCapturedAsync(
            DebugEnvironment, "audit", "verify", "--connection-file", context.File(connection), "--password-file", context.File(password.Value + "\n"));
        run.Capture("audit verify", result);

        Assert.True(result.ExitCode == (failing ? 1 : 0), result.StandardOutput + result.StandardError);
    }

    /// <summary>
    /// <c>gatekeep rotate-transit-keys</c> (Story 12.7) at Trace, with a canary AppRole secret ID and
    /// OpenBao token on the stand-in socket, as <c>gk_cli</c>, which answers every rotation. Failing,
    /// the database refuses the connection before any key is touched.
    /// </summary>
    private static async Task RotateTransitKeysAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        var secretId = run.Plant("approle-secret-id");
        var token = run.Plant("openbao-token");
        var socket = context.Socket();
        socket.Body = $$$"""{"auth":{"client_token":"{{{token.Value}}}","lease_duration":900},"data":{}}""";

        string connection;
        Canary password;
        if (failing)
        {
            password = run.Plant("password-file");
            connection = RefusedConnection(TableRegistry.Cli);
        }
        else
        {
            run.Database = await context.Postgres.NewMigratedDatabaseAsync();
            await TestTenants.InsertAsync(context.Postgres.SuperuserConnection(run.Database), TenantA);
            password = run.Plant("role-password", PostgresFixture.Password);
            connection = Passwordless(context.Postgres.RoleConnection(TableRegistry.Cli, run.Database));
        }

        var environment = new Dictionary<string, string>(DebugEnvironment)
        {
            ["GATEKEEP_CLI_CONNECTION_FILE"] = context.File(connection),
            ["GATEKEEP_CLI_PASSWORD_FILE"] = context.File(password.Value + "\n"),
            ["GATEKEEP_CUSTODY_SOCKET"] = socket.Path,
            ["GATEKEEP_CUSTODY_ROLE_ID_FILE"] = context.File(Guid.NewGuid().ToString()),
            ["GATEKEEP_CUSTODY_SECRET_ID_FILE"] = context.File(secretId.Value + "\n"),
        };

        var result = await CliProcess.RunCapturedAsync(environment, "rotate-transit-keys");
        run.Capture("rotate-transit-keys", result);

        Assert.True(result.ExitCode == (failing ? 1 : 0), result.StandardOutput + result.StandardError);
    }

    /// <summary>
    /// <c>gatekeep init</c> at Trace, with a canary AppRole secret ID and OpenBao token on the
    /// stand-in socket, as <c>gk_cli</c>. The token it issues is read back from its file and
    /// scanned for too. Failing, the database refuses the connection after the keys are ensured.
    /// </summary>
    private static async Task InitAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        var secretId = run.Plant("approle-secret-id");
        var token = run.Plant("openbao-token");
        var socket = context.Socket();
        // One body answers the AppRole login and every key creation, the signing key's included.
        const string Keys = """{"keys":{"1":{"public_key":"-----BEGIN PUBLIC KEY-----\nQ05SWQ==\n-----END PUBLIC KEY-----\n"}}}""";
        socket.Body = $$"""{"auth":{"client_token":"{{token.Value}}","lease_duration":900},"data":""" + Keys + "}";

        string connection;
        Canary password;
        if (failing)
        {
            password = run.Plant("password-file");
            connection = RefusedConnection(TableRegistry.Cli);
        }
        else
        {
            run.Database = await context.Postgres.NewMigratedDatabaseAsync();
            password = run.Plant("role-password", PostgresFixture.Password);
            connection = Passwordless(context.Postgres.RoleConnection(TableRegistry.Cli, run.Database));
        }

        var directory = context.NewDirectory();
        var environment = new Dictionary<string, string>(DebugEnvironment)
        {
            ["GATEKEEP_CLI_CONNECTION_FILE"] = context.File(connection),
            ["GATEKEEP_CLI_PASSWORD_FILE"] = context.File(password.Value + "\n"),
            ["GATEKEEP_CUSTODY_SOCKET"] = socket.Path,
            ["GATEKEEP_CUSTODY_ROLE_ID_FILE"] = context.File(Guid.NewGuid().ToString()),
            ["GATEKEEP_CUSTODY_SECRET_ID_FILE"] = context.File(secretId.Value + "\n"),
        };

        var result = await CliProcess.RunCapturedAsync(environment, "init", "--token-dir", directory);
        run.Capture("init", result);

        Assert.True(result.ExitCode == (failing ? 1 : 0), result.StandardOutput + result.StandardError);

        var file = Path.Combine(directory, "bootstrap-token");
        Assert.Equal(!failing, File.Exists(file));
        if (!failing)
        {
            run.Plant("bootstrap-token", (await File.ReadAllTextAsync(file, CanaryFlowContext.Cancellation)).TrimEnd('\n'));
        }
    }

    /// <summary>
    /// Starts the host at Trace with a canary password in every connection string and a canary
    /// AppRole secret ID, then asks <c>/healthz</c>. Failing, the database refuses the connection.
    /// </summary>
    private static FlowBody HostAsync(string host) => async (context, run, failing) =>
    {
        var secretId = run.Plant("approle-secret-id");
        var socket = context.Socket();
        var health = HostProcess.FreePort();

        var arguments = new List<string>(DebugArguments)
        {
            $"--Custody:SocketPath={socket.Path}",
            $"--Custody:RoleIdFile={context.File(Guid.NewGuid().ToString())}",
            $"--Custody:SecretIdFile={context.File(secretId.Value + "\n")}",
            $"--Gatekeep:HealthPort={health}",
            $"--Gatekeep:PublicPort={HostProcess.FreePort()}",
        };

        if (failing)
        {
            var password = run.Plant("connection-password");
            var closed = HostProcess.FreePort();
            arguments.AddRange(Databases(host).Select(d =>
                $"--ConnectionStrings:{d.Name}=Host=127.0.0.1;Port={closed};Database=gatekeep;Username={d.Role};Password={password.Value}"));
        }
        else
        {
            var database = await context.Postgres.NewMigratedDatabaseAsync();
            run.Database = database;
            run.Plant("role-password", PostgresFixture.Password);
            arguments.AddRange(Databases(host).Select(d => $"--ConnectionStrings:{d.Name}={context.Postgres.RoleConnection(d.Role, database)}"));
        }

        using var process = HostProcess.Start(host, arguments);
        var (status, body) = await process.GetAsync(health, HealthEndpoint, Timeout, CanaryFlowContext.Cancellation);
        run.Capture($"{host} {HealthEndpoint} response", $"{(int)status} {body}");

        // Let a running Worker take a few passes of its loops before it's stopped.
        await Task.Delay(TimeSpan.FromSeconds(2), CanaryFlowContext.Cancellation);
        await process.StopAsync(Timeout, CanaryFlowContext.Cancellation);
        run.Capture($"{host} stdout", process.StandardOutput);
        run.Capture($"{host} stderr", process.StandardError);

        Assert.Equal(
            failing ? (HttpStatusCode.ServiceUnavailable, "unhealthy: database") : (HttpStatusCode.OK, "healthy"),
            (status, body));
        Assert.Matches(@"""LogLevel"":""(?:Trace|Debug)""", process.StandardOutput);
    };

    /// <summary>
    /// Story 1.21's claim on the real Host.Admin at Trace, with a token issued as <c>gatekeep init</c>
    /// does. Normally the right token claims, then the setup Session reads the Session endpoint and
    /// is refused capabilities, then signs out, which any Session may; the token must appear in no response, and the Session
    /// ID and both CSRF tokens, planted once they're issued, in no log or table. Failing, a wrong
    /// token is refused and an unissued Session cookie is refused, with every response scanned.
    /// </summary>
    private static async Task BootstrapClaimAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        await using var host = await Admins.AdminHost.StartAsync(context.Postgres, null, DebugArguments);
        run.Database = host.Database;
        run.Plant("role-password", PostgresFixture.Password);
        var token = run.Plant("bootstrap-token", await host.IssueTokenAsync());

        if (failing)
        {
            var wrong = run.Plant("wrong-bootstrap-token", Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)));
            using var refused = await host.ClaimAsync(wrong.Value);
            run.Capture("refused claim response", await ResponseTextAsync(refused));
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);

            var unissued = run.Plant("unissued-session-id", Admins.AdminHost.Unissued());
            using var unknown = await host.SendAsync(HttpMethod.Get, "/api/v1/deployment/session", unissued.Value);
            run.Capture("unknown session response", await ResponseTextAsync(unknown));
            Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        }
        else
        {
            using var claimed = await host.ClaimAsync(token.Value);
            Assert.Equal(HttpStatusCode.Created, claimed.StatusCode);
            // The response carries the Session ID and CSRF token by design, but never the token.
            Assert.DoesNotContain(token.Value, await ResponseTextAsync(claimed), StringComparison.Ordinal);
            var (cookie, csrf, _) = await Admins.AdminHost.ReadClaimAsync(claimed);

            using var session = await host.SendAsync(HttpMethod.Get, "/api/v1/deployment/session", cookie);
            Assert.Equal(HttpStatusCode.OK, session.StatusCode);
            Assert.DoesNotContain(token.Value, await ResponseTextAsync(session), StringComparison.Ordinal);
            using var json = System.Text.Json.JsonDocument.Parse(await session.Content.ReadAsStringAsync(CanaryFlowContext.Cancellation));
            var rotated = json.RootElement.GetProperty("csrfToken").GetString()!;

            using var capabilities = await host.SendAsync(HttpMethod.Get, "/api/v1/deployment/capabilities", cookie);
            run.Capture("capabilities response", await ResponseTextAsync(capabilities));
            Assert.Equal(HttpStatusCode.Forbidden, capabilities.StatusCode);

            // A setup Session can always sign out (Story 1.26).
            using var signOut = await host.SendAsync(HttpMethod.Delete, "/api/v1/deployment/session", cookie, rotated, Admins.AdminHost.Origin);
            run.Capture("sign-out response", await ResponseTextAsync(signOut));
            Assert.Equal(HttpStatusCode.NoContent, signOut.StatusCode);

            run.Plant("admin-session-id", cookie);
            run.Plant("admin-csrf-token", csrf);
            run.Plant("admin-rotated-csrf-token", rotated);
        }

        await host.StopAsync();
        run.Capture("Admin output", host.Output);
        Assert.Matches(@"""LogLevel"":""(?:Trace|Debug)""", host.Output);
    }

    /// <summary>
    /// Story 1.22's credential registration on the real Host.Admin at Trace, with a software
    /// authenticator. Normally the setup Session registers two credentials, which completes setup;
    /// failing, a response for another origin and a malformed body are refused. The Session ID and
    /// CSRF token, planted once they're issued, must appear in no log or table, and no response
    /// may echo them but where they're designed to be.
    /// </summary>
    private static async Task CredentialRegistrationAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        await using var host = await Admins.AdminHost.StartAsync(context.Postgres, null, DebugArguments);
        run.Database = host.Database;
        run.Plant("role-password", PostgresFixture.Password);
        var (cookie, csrf, _) = await host.ClaimedAsync();
        using var first = new Admins.SoftwareAuthenticator();
        using var second = new Admins.SoftwareAuthenticator();

        var (begin, options) = await host.BeginRegistrationAsync(cookie, csrf);
        using (begin)
        {
            run.Capture("registration options response", await ResponseTextAsync(begin));
            Assert.Equal(HttpStatusCode.OK, begin.StatusCode);
        }

        if (failing)
        {
            using var foreign = await host.CompleteRegistrationAsync(
                cookie,
                csrf,
                first.Attest(options, Admins.AdminHost.Origin, new Admins.AttestationTweaks { Origin = "https://elsewhere.test" }));
            run.Capture("refused registration response", await ResponseTextAsync(foreign));
            Assert.Equal(HttpStatusCode.BadRequest, foreign.StatusCode);

            using var malformed = await host.CompleteRegistrationAsync(cookie, csrf, $$"""{"id":"{{csrf}}","rawId":"!","type":"public-key"}""");
            run.Capture("malformed registration response", await ResponseTextAsync(malformed));
            Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
        }
        else
        {
            using (var complete = await host.CompleteRegistrationAsync(cookie, csrf, first.Attest(options, Admins.AdminHost.Origin)))
            {
                run.Capture("first registration response", await ResponseTextAsync(complete));
                Assert.Equal(HttpStatusCode.OK, complete.StatusCode);
            }

            var (again, more) = await host.BeginRegistrationAsync(cookie, csrf);
            again.Dispose();
            using var last = await host.CompleteRegistrationAsync(cookie, csrf, second.Attest(more, Admins.AdminHost.Origin));
            run.Capture("second registration response", await ResponseTextAsync(last));
            Assert.Equal(HttpStatusCode.OK, last.StatusCode);
        }

        run.Plant("admin-session-id", cookie);
        run.Plant("admin-csrf-token", csrf);

        await host.StopAsync();
        run.Capture("Admin output", host.Output);
        Assert.Matches(@"""LogLevel"":""(?:Trace|Debug)""", host.Output);
    }

    /// <summary>
    /// Story 1.23's Admin sign-in on the real Host.Admin at Trace, with a software authenticator.
    /// Normally an Admin with two credentials signs in and out; failing, an assertion with a bad
    /// signature and a malformed body are refused. The binding cookie, the new Session ID and its
    /// CSRF token, planted once issued, must appear in no log or table, and no captured response
    /// may echo them.
    /// </summary>
    private static async Task SignInAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        await using var host = await Admins.AdminHost.StartAsync(context.Postgres, null, DebugArguments);
        run.Database = host.Database;
        run.Plant("role-password", PostgresFixture.Password);
        using var first = new Admins.SoftwareAuthenticator();
        using var second = new Admins.SoftwareAuthenticator();
        var (setup, _) = await host.AdminWithCredentialsAsync(first, second);
        run.Plant("admin-setup-session-id", setup);

        // The begin's response holds the binding by design, so only its body is captured.
        var (begin, options, binding) = await host.BeginSignInAsync();
        using (begin)
        {
            Assert.Equal(HttpStatusCode.OK, begin.StatusCode);
            run.Capture("sign-in options", await begin.Content.ReadAsStringAsync(CanaryFlowContext.Cancellation));
        }

        run.Plant("admin-signin-binding", binding!);
        if (failing)
        {
            using var forged = await host.CompleteSignInAsync(binding, first.Assert(options, Admins.AdminHost.Origin, new Admins.AssertionTweaks { OtherKey = true }));
            run.Capture("refused sign-in response", await ResponseTextAsync(forged));
            Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);

            var (again, _, rebound) = await host.BeginSignInAsync();
            again.Dispose();
            run.Plant("admin-signin-second-binding", rebound!);
            using var malformed = await host.CompleteSignInAsync(rebound, $$"""{"id":"{{rebound}}","rawId":"!","type":"public-key"}""");
            run.Capture("malformed sign-in response", await ResponseTextAsync(malformed));
            Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
        }
        else
        {
            string cookie;
            string csrf;
            using (var complete = await host.CompleteSignInAsync(binding, first.Assert(options, Admins.AdminHost.Origin)))
            {
                Assert.Equal(HttpStatusCode.OK, complete.StatusCode);
                cookie = Admins.AdminHost.CookieValue(complete, Admins.AdminHost.Cookie)!;
                using var json = System.Text.Json.JsonDocument.Parse(await complete.Content.ReadAsStringAsync(CanaryFlowContext.Cancellation));
                csrf = json.RootElement.GetProperty("csrfToken").GetString()!;
            }

            // Story 1.24: the Session on the Tenant surface, refused and audited in a Tenant it holds no role in.
            var tenant = Gatekeep.Kernel.Identifiers.PublicId.Format(Gatekeep.Kernel.Identifiers.PublicIdType.Tenant, Guid.CreateVersion7());
            using (var denied = await host.SendAsync(HttpMethod.Get, $"/api/v1/tenants/{tenant}/capabilities", cookie))
            {
                run.Capture("tenant capabilities response", await ResponseTextAsync(denied));
                Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            }

            using var signOut = await host.SendAsync(HttpMethod.Delete, "/api/v1/deployment/session", cookie, csrf, Admins.AdminHost.Origin);
            run.Capture("sign-out response", await ResponseTextAsync(signOut));
            Assert.Equal(HttpStatusCode.NoContent, signOut.StatusCode);

            run.Plant("admin-session-id", cookie);
            run.Plant("admin-csrf-token", csrf);
        }

        await host.StopAsync();
        run.Capture("Admin output", host.Output);
        Assert.Matches(@"""LogLevel"":""(?:Trace|Debug)""", host.Output);
    }

    /// <summary>
    /// Story 1.26's fresh assertions and Your credentials on the real Host.Admin at Trace, with
    /// software authenticators. Normally the Owner confirms a removal, removes a credential, which
    /// ends their other Session, and reads the list; failing, a forged assertion is refused and a
    /// removal with no grant is 403. The Session IDs and CSRF tokens, planted once issued, must
    /// appear in no log or table, and no captured response may echo them.
    /// </summary>
    private static async Task FreshAssertionAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        await using var host = await Admins.AdminHost.StartAsync(context.Postgres, null, DebugArguments);
        run.Database = host.Database;
        run.Plant("role-password", PostgresFixture.Password);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync(3);
        var (other, otherCsrf) = await host.SignInAsync(authenticators[1]);
        var ids = await host.CredentialIdsAsync(cookie);

        var (begin, options) = await host.BeginAssertionAsync(cookie, csrf, "self.credentials.remove", ids[2]);
        using (begin)
        {
            run.Capture("fresh assertion options", await ResponseTextAsync(begin));
            Assert.Equal(HttpStatusCode.OK, begin.StatusCode);
        }

        if (failing)
        {
            using var forged = await host.CompleteAssertionAsync(
                cookie, csrf, authenticators[0].Assert(options, Admins.AdminHost.Origin, new Admins.AssertionTweaks { OtherKey = true }));
            run.Capture("refused fresh assertion response", await ResponseTextAsync(forged));
            Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);

            using var unconfirmed = await host.RemoveCredentialAsync(cookie, csrf, ids[2]);
            run.Capture("unconfirmed removal response", await ResponseTextAsync(unconfirmed));
            Assert.Equal(HttpStatusCode.Forbidden, unconfirmed.StatusCode);
        }
        else
        {
            using (var complete = await host.CompleteAssertionAsync(cookie, csrf, authenticators[0].Assert(options, Admins.AdminHost.Origin)))
            {
                run.Capture("fresh assertion response", await ResponseTextAsync(complete));
                Assert.Equal(HttpStatusCode.NoContent, complete.StatusCode);
            }

            using (var removed = await host.RemoveCredentialAsync(cookie, csrf, ids[2]))
            {
                run.Capture("removal response", await ResponseTextAsync(removed));
                Assert.Equal(HttpStatusCode.NoContent, removed.StatusCode);
            }

            using var list = await host.SendAsync(HttpMethod.Get, Admins.AdminHost.CredentialsPath, cookie);
            run.Capture("credentials response", await ResponseTextAsync(list));
            Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        }

        run.Plant("admin-session-id", cookie);
        run.Plant("admin-csrf-token", csrf);
        run.Plant("admin-other-session-id", other);
        run.Plant("admin-other-csrf-token", otherCsrf);
        foreach (var authenticator in authenticators)
        {
            authenticator.Dispose();
        }

        await host.StopAsync();
        run.Capture("Admin output", host.Output);
        Assert.Matches(@"""LogLevel"":""(?:Trace|Debug)""", host.Output);
    }

    /// <summary>
    /// Story 1.32's <c>gatekeep recover-admin</c> through the Cli's core, with the alert token, the
    /// bucket credential and the database password planted, to the AlertSink and the Object Lock
    /// bucket, then its redemption on the real Host.Admin at Trace. The enrolment's value is planted:
    /// it must appear in no table, log, alert, record, error or response. Only the Cli's standard
    /// output holds it, by design, as the link, so it alone is left out. Normally the value is
    /// redeemed for a recovery Session; failing, the alert is refused, so nothing is issued, and an
    /// unknown value is refused at redemption.
    /// </summary>
    private static async Task EnrolmentAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        await using var host = await Admins.AdminHost.StartAsync(context.Postgres, null, DebugArguments);
        run.Database = host.Database;
        run.Plant("role-password", PostgresFixture.Password);
        var (cookie, csrf, _) = await host.ClaimedAsync();
        run.Plant("admin-setup-session-id", cookie);
        run.Plant("admin-setup-csrf-token", csrf);

        var token = run.Plant("alert-token");
        await using var sink = await AlertSinkFixture.StartAsync();
        sink.Status = failing ? 500 : 204;
        var bucket = context.Bucket;
        run.Plant("bucket-access-key-id", bucket.AccessKeyId);
        run.Plant("bucket-secret-key", bucket.SecretAccessKey);
        using var store = bucket.Store();
        var output = new StringWriter();
        var error = new StringWriter();

        var exit = await RecoverAdminCommand.RunAsync(
            new RecoverAdminOptions
            {
                ConnectionString = context.Postgres.RoleConnection(TableRegistry.Cli, host.Database),
                Alerts = new WebhookAlertOptions { Url = sink.Url, TokenFile = context.File(token.Value + "\n") },
            },
            new AlertDeployment("admin.gatekeep-admin.test"),
            ObjectLockFixture.Permitted(),
            new SigningCustody(),
            store,
            TimeProvider.System,
            output,
            error,
            CanaryFlowContext.Cancellation);
        run.Capture("recover-admin stderr", error.ToString());
        var request = Assert.Single(sink.Requests);
        Assert.Equal($"Bearer {token.Value}", request.Headers["Authorization"]);
        run.Capture("alert body", Encoding.UTF8.GetString(request.Body));
        run.Capture("alert headers", string.Join('\n', request.Headers.Where(h => h.Key != "Authorization").Select(h => $"{h.Key}: {h.Value}")));

        if (failing)
        {
            Assert.Equal(1, exit);
            Assert.Equal(RecoverAdminCommand.AlertRejected, error.ToString().Trim());
            Assert.Empty(output.ToString());

            using var refused = await host.RedeemEnrolmentAsync(run.Plant("unissued-enrolment", Admins.AdminHost.Unissued()).Value);
            run.Capture("unknown enrolment response", await ResponseTextAsync(refused));
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        }
        else
        {
            Assert.Equal(0, exit);
            // The link is the one place the value is meant to be: standard output, shown once.
            var printed = output.ToString();
            var value = Regex.Match(printed, @"/recover#(?<value>[A-Za-z0-9_-]{43})").Groups["value"].Value;
            run.Plant("admin-enrolment", value);

            var key = Regex.Match(printed, @"(?<key>records/admin_recovery/\S+\.json)").Groups["key"].Value;
            foreach (var (name, text) in await bucket.DumpAsync(key))
            {
                run.Capture(name, text);
            }

            // The redeem's response holds the new Session by design, so it isn't captured; it mustn't hold the value.
            using var redeemed = await host.RedeemEnrolmentAsync(value, session: cookie);
            Assert.Equal(HttpStatusCode.OK, redeemed.StatusCode);
            var body = await redeemed.Content.ReadAsStringAsync(CanaryFlowContext.Cancellation);
            Assert.DoesNotContain(value, body, StringComparison.Ordinal);
            using (var json = System.Text.Json.JsonDocument.Parse(body))
            {
                run.Plant("admin-enrolment-csrf-token", json.RootElement.GetProperty("csrfToken").GetString()!);
            }

            run.Plant("admin-enrolment-session-id", Admins.AdminHost.CookieValue(redeemed, Admins.AdminHost.Cookie)!);

            using var again = await host.RedeemEnrolmentAsync(value);
            run.Capture("used enrolment response", await ResponseTextAsync(again));
            Assert.Equal(HttpStatusCode.BadRequest, again.StatusCode);
        }

        await host.StopAsync();
        run.Capture("Admin output", host.Output);
        Assert.Matches(@"""LogLevel"":""(?:Trace|Debug)""", host.Output);
    }

    /// <summary>
    /// Story 1.26's Admin Recovery Codes on the real Host.Admin at Trace, with the OpenBao stand-in
    /// computing the Deployment HMAC. A seeded Admin who isn't the Owner issues a code; normally
    /// they confirm and redeem it, getting a recovery Session; failing, a wrong code and the
    /// unconfirmed one are refused. The code, in both its spellings, must appear in no log or
    /// table, and no captured response but the issue's, which holds it by design and is left out.
    /// </summary>
    private static async Task RecoveryCodeAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        await using var host = await Admins.AdminHost.StartAsync(context.Postgres, null, DebugArguments);
        run.Database = host.Database;
        run.Plant("role-password", PostgresFixture.Password);
        await host.ClaimedAsync();
        var (cookie, csrf, _) = await host.InsertSetupAdminAsync();
        using var key = new Admins.SoftwareAuthenticator();
        await host.RegisterAsync(cookie, csrf, key);

        var (code, issueId) = await host.IssueRecoveryCodeAsync(cookie, csrf);
        run.Plant("admin-recovery-code", code);
        run.Plant("admin-recovery-code-normalized", code.Replace("-", string.Empty, StringComparison.Ordinal));

        if (failing)
        {
            var wrong = run.Plant("admin-wrong-recovery-code", "ZZZZ-ZZZY-ZZZX-ZZZW");
            using var refused = await host.RedeemAsync(wrong.Value);
            run.Capture("wrong recovery code response", await ResponseTextAsync(refused));
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);

            using var unconfirmed = await host.RedeemAsync(code);
            run.Capture("unconfirmed recovery code response", await ResponseTextAsync(unconfirmed));
            Assert.Equal(HttpStatusCode.BadRequest, unconfirmed.StatusCode);
        }
        else
        {
            using (var confirmed = await host.ConfirmRecoveryCodeAsync(cookie, csrf, issueId))
            {
                run.Capture("confirm response", await ResponseTextAsync(confirmed));
                Assert.Equal(HttpStatusCode.NoContent, confirmed.StatusCode);
            }

            // The redeem's response holds the new Session by design, so only its body is captured.
            using var redeemed = await host.RedeemAsync(code.ToLowerInvariant());
            Assert.Equal(HttpStatusCode.OK, redeemed.StatusCode);
            var recovery = Admins.AdminHost.CookieValue(redeemed, Admins.AdminHost.Cookie)!;
            var body = await redeemed.Content.ReadAsStringAsync(CanaryFlowContext.Cancellation);
            Assert.DoesNotContain(code, body, StringComparison.OrdinalIgnoreCase);
            using (var json = System.Text.Json.JsonDocument.Parse(body))
            {
                run.Plant("admin-recovery-csrf-token", json.RootElement.GetProperty("csrfToken").GetString()!);
            }

            run.Plant("admin-recovery-session-id", recovery);
        }

        run.Plant("admin-setup-session-id", cookie);
        run.Plant("admin-setup-csrf-token", csrf);

        await host.StopAsync();
        run.Capture("Admin output", host.Output);
        Assert.Matches(@"""LogLevel"":""(?:Trace|Debug)""", host.Output);
    }

    /// <summary>
    /// Story 1.27: the Owner's Session and CSRF token through every Tenant route: a creation, the
    /// list, the Operation on the Tenant path and a retry, or each one's refusals.
    /// </summary>
    private static async Task TenantsAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        await using var host = await Admins.AdminHost.StartAsync(context.Postgres, null, DebugArguments);
        run.Database = host.Database;
        run.Plant("role-password", PostgresFixture.Password);
        var (cookie, csrf, _) = await host.OwnerSessionAsync();
        run.Plant("admin-session-id", cookie);
        run.Plant("admin-csrf-token", csrf);

        const string tenants = "/api/v1/deployment/tenants";
        var unknown = Gatekeep.Kernel.Identifiers.PublicId.Format(Gatekeep.Kernel.Identifiers.PublicIdType.Operation, Guid.CreateVersion7());

        if (failing)
        {
            using (var reserved = await host.SendAsync(HttpMethod.Post, tenants, cookie, csrf, Admins.AdminHost.Origin, """{"name":"Acme","subdomain":"admin","label":"dev"}"""))
            {
                run.Capture("refused creation response", await ResponseTextAsync(reserved));
                Assert.Equal(HttpStatusCode.BadRequest, reserved.StatusCode);
            }

            using (var malformed = await host.SendAsync(HttpMethod.Post, tenants, cookie, csrf, Admins.AdminHost.Origin, "{"))
            {
                run.Capture("malformed creation response", await ResponseTextAsync(malformed));
                Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
            }

            using (var cursor = await host.SendAsync(HttpMethod.Get, $"{tenants}?cursor=nope", cookie))
            {
                run.Capture("malformed cursor response", await ResponseTextAsync(cursor));
                Assert.Equal(HttpStatusCode.BadRequest, cursor.StatusCode);
            }

            using var retry = await host.SendAsync(HttpMethod.Post, $"/api/v1/deployment/operations/{unknown}/retry", cookie, csrf, Admins.AdminHost.Origin);
            run.Capture("unknown retry response", await ResponseTextAsync(retry));
            Assert.Equal(HttpStatusCode.NotFound, retry.StatusCode);
        }
        else
        {
            string tenant;
            string operation;
            using (var created = await host.SendAsync(HttpMethod.Post, tenants, cookie, csrf, Admins.AdminHost.Origin, """{"name":"Acme","subdomain":"acme","label":"dev"}"""))
            {
                var text = await ResponseTextAsync(created);
                run.Capture("creation response", text);
                Assert.Equal(HttpStatusCode.Accepted, created.StatusCode);
                using var json = System.Text.Json.JsonDocument.Parse(await created.Content.ReadAsStringAsync(CanaryFlowContext.Cancellation));
                tenant = json.RootElement.GetProperty("tenant").GetProperty("id").GetString()!;
                operation = json.RootElement.GetProperty("operation").GetProperty("id").GetString()!;
            }

            using (var list = await host.SendAsync(HttpMethod.Get, tenants, cookie))
            {
                run.Capture("list response", await ResponseTextAsync(list));
                Assert.Equal(HttpStatusCode.OK, list.StatusCode);
            }

            using (var read = await host.SendAsync(HttpMethod.Get, $"/api/v1/tenants/{tenant}/operations/{operation}", cookie))
            {
                run.Capture("operation response", await ResponseTextAsync(read));
                Assert.Equal(HttpStatusCode.OK, read.StatusCode);
            }

            using var retry = await host.SendAsync(HttpMethod.Post, $"/api/v1/deployment/operations/{operation}/retry", cookie, csrf, Admins.AdminHost.Origin);
            run.Capture("retry response", await ResponseTextAsync(retry));
            Assert.Equal(HttpStatusCode.Conflict, retry.StatusCode);
        }

        await host.StopAsync();
        run.Capture("Admin output", host.Output);
        Assert.Matches(@"""LogLevel"":""(?:Trace|Debug)""", host.Output);
    }

    /// <summary>
    /// Story 1.28: the Owner's Session and CSRF token through the switcher's list, the label read,
    /// the Tenant-surface begin and complete and a Prod removal; failing, a mismatched page Tenant, a
    /// malformed body, an unconfirmed removal and a refused begin.
    /// </summary>
    private static async Task TenantLabelAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        await using var host = await Admins.AdminHost.StartAsync(context.Postgres, null, DebugArguments);
        run.Database = host.Database;
        run.Plant("role-password", PostgresFixture.Password);
        var tenant = await Tenancy.TenantRequests.InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await Tenancy.TenantRequests.OwnerOfAsync(host, tenant);
        run.Plant("admin-session-id", cookie);
        run.Plant("admin-csrf-token", csrf);
        var id = Tenancy.TenantRequests.Id(tenant);

        using (var list = await host.SendAsync(HttpMethod.Get, Tenancy.TenantRequests.MyTenantsPath, cookie))
        {
            run.Capture("my tenants response", await ResponseTextAsync(list));
            Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        }

        using (var read = await Tenancy.TenantRequests.GetLabelAsync(host, cookie, tenant))
        {
            run.Capture("label response", await ResponseTextAsync(read));
            Assert.Equal(HttpStatusCode.OK, read.StatusCode);
        }

        if (failing)
        {
            using (var mismatch = await Tenancy.TenantRequests.SetLabelAsync(host, cookie, csrf, tenant, "dev", "ten_other"))
            {
                run.Capture("mismatch response", await ResponseTextAsync(mismatch));
                Assert.Equal(HttpStatusCode.Conflict, mismatch.StatusCode);
            }

            using (var malformed = await Tenancy.TenantRequests.SetBodyAsync(host, cookie, csrf, Tenancy.TenantRequests.LabelPath(tenant), "{", id))
            {
                run.Capture("malformed label response", await ResponseTextAsync(malformed));
                Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
            }

            using (var unconfirmed = await Tenancy.TenantRequests.SetLabelAsync(host, cookie, csrf, tenant, "dev"))
            {
                run.Capture("unconfirmed removal response", await ResponseTextAsync(unconfirmed));
                Assert.Equal(HttpStatusCode.Forbidden, unconfirmed.StatusCode);
            }

            var (refused, _) = await Tenancy.TenantRequests.BeginAsync(host, cookie, csrf, tenant, """{"action":"self.credentials.add","target":null}""");
            using (refused)
            {
                run.Capture("refused begin response", await ResponseTextAsync(refused));
                Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
            }
        }
        else
        {
            var (begin, options) = await Tenancy.TenantRequests.BeginAsync(host, cookie, csrf, tenant, """{"action":"tenant.label.manage","target":null}""");
            using (begin)
            {
                run.Capture("tenant begin response", await ResponseTextAsync(begin));
                Assert.Equal(HttpStatusCode.OK, begin.StatusCode);
            }

            using (var complete = await host.CompleteAssertionAsync(cookie, csrf, authenticators[0].Assert(options, Admins.AdminHost.Origin)))
            {
                run.Capture("complete response", await ResponseTextAsync(complete));
                Assert.Equal(HttpStatusCode.NoContent, complete.StatusCode);
            }

            using var removed = await Tenancy.TenantRequests.SetLabelAsync(host, cookie, csrf, tenant, "staging");
            run.Capture("removal response", await ResponseTextAsync(removed));
            Assert.Equal(HttpStatusCode.OK, removed.StatusCode);
        }

        foreach (var authenticator in authenticators)
        {
            authenticator.Dispose();
        }

        await host.StopAsync();
        run.Capture("Admin output", host.Output);
        Assert.Matches(@"""LogLevel"":""(?:Trace|Debug)""", host.Output);
    }

    /// <summary>
    /// Story 7.4: a Viewer's Session reading the Tenant's Log by outcome; failing, a cross-Tenant read,
    /// which writes the rejection to the other Tenant's Log, and malformed filters, cursor and range.
    /// </summary>
    private static async Task TenantLogsAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        await using var host = await Admins.AdminHost.StartAsync(context.Postgres, null, DebugArguments);
        run.Database = host.Database;
        run.Plant("role-password", PostgresFixture.Password);
        var tenant = await host.InsertTenantAsync();
        var (cookie, csrf, _) = await Tenancy.TenantRequests.RoleSessionAsync(host, tenant, "viewer");
        run.Plant("admin-session-id", cookie);
        run.Plant("admin-csrf-token", csrf);
        var path = $"/api/v1/tenants/{Tenancy.TenantRequests.Id(tenant)}/logs";

        if (failing)
        {
            // A refused cross-Tenant read writes to the other Tenant's Log; malformed filters read nothing.
            var other = await host.InsertTenantAsync();
            using (var refused = await host.SendAsync(HttpMethod.Get, $"/api/v1/tenants/{Tenancy.TenantRequests.Id(other)}/logs", cookie))
            {
                run.Capture("cross-Tenant logs response", await ResponseTextAsync(refused));
                Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
            }

            foreach (var query in new[] { "?outcome=maybe", "?cursor=evt_x", "?user=not%20an%20id", "?from=2026-01-01" })
            {
                using var malformed = await host.SendAsync(HttpMethod.Get, path + query, cookie);
                run.Capture($"malformed logs response {query}", await ResponseTextAsync(malformed));
                Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
            }
        }
        else
        {
            using var read = await host.SendAsync(HttpMethod.Get, path + "?outcome=failure", cookie);
            run.Capture("logs response", await ResponseTextAsync(read));
            Assert.Equal(HttpStatusCode.OK, read.StatusCode);
        }

        await host.StopAsync();
        run.Capture("Admin output", host.Output);
        Assert.Matches(@"""LogLevel"":""(?:Trace|Debug)""", host.Output);
    }

    /// <summary>
    /// Story 1.29: a Tenant's deletion, logging at Trace. Failing, an unconfirmed start, a
    /// confirmed one with a wrong typed host, an unconfirmed retry and a read of no deletion;
    /// succeeding, a confirmed start, its read and a confirmed retry of a deletion still running.
    /// </summary>
    private static async Task TenantDeletionAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        await using var host = await Admins.AdminHost.StartAsync(context.Postgres, null, DebugArguments);
        run.Database = host.Database;
        run.Plant("role-password", PostgresFixture.Password);
        var tenant = await Tenancy.TenantRequests.InsertAsync(host);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync();
        run.Plant("admin-session-id", cookie);
        run.Plant("admin-csrf-token", csrf);
        var id = Tenancy.TenantRequests.Id(tenant);
        var path = $"/api/v1/deployment/tenants/{id}/deletion";
        var body = System.Text.Json.JsonSerializer.Serialize(new { confirmation = TestTenants.Host(tenant) });

        if (failing)
        {
            using (var unconfirmed = await host.SendAsync(HttpMethod.Post, path, cookie, csrf, Admins.AdminHost.Origin, body))
            {
                run.Capture("unconfirmed deletion response", await ResponseTextAsync(unconfirmed));
                Assert.Equal(HttpStatusCode.Forbidden, unconfirmed.StatusCode);
            }

            await host.ConfirmAsync(cookie, csrf, authenticators[0], "deployment.tenants.delete", id);
            using (var mismatch = await host.SendAsync(HttpMethod.Post, path, cookie, csrf, Admins.AdminHost.Origin, """{"confirmation":"wrong"}"""))
            {
                run.Capture("mismatched deletion response", await ResponseTextAsync(mismatch));
                Assert.Equal(HttpStatusCode.BadRequest, mismatch.StatusCode);
            }

            using (var retry = await host.SendAsync(HttpMethod.Post, path + "/retry", cookie, csrf, Admins.AdminHost.Origin))
            {
                run.Capture("unconfirmed retry response", await ResponseTextAsync(retry));
                Assert.Equal(HttpStatusCode.Forbidden, retry.StatusCode);
            }

            using var read = await host.SendAsync(HttpMethod.Get, path, cookie);
            run.Capture("no deletion response", await ResponseTextAsync(read));
            Assert.Equal(HttpStatusCode.NotFound, read.StatusCode);
        }
        else
        {
            await host.ConfirmAsync(cookie, csrf, authenticators[0], "deployment.tenants.delete", id);
            using (var started = await host.SendAsync(HttpMethod.Post, path, cookie, csrf, Admins.AdminHost.Origin, body))
            {
                run.Capture("deletion response", await ResponseTextAsync(started));
                Assert.Equal(HttpStatusCode.Accepted, started.StatusCode);
            }

            using (var read = await host.SendAsync(HttpMethod.Get, path, cookie))
            {
                run.Capture("deletion read response", await ResponseTextAsync(read));
                Assert.Equal(HttpStatusCode.OK, read.StatusCode);
            }

            await host.ConfirmAsync(cookie, csrf, authenticators[0], "deployment.tenants.delete", id);
            using var retry = await host.SendAsync(HttpMethod.Post, path + "/retry", cookie, csrf, Admins.AdminHost.Origin);
            run.Capture("retry response", await ResponseTextAsync(retry));
            Assert.Equal(HttpStatusCode.Conflict, retry.StatusCode);
        }

        foreach (var authenticator in authenticators)
        {
            authenticator.Dispose();
        }

        await host.StopAsync();
        run.Capture("Admin output", host.Output);
        Assert.Matches(@"""LogLevel"":""(?:Trace|Debug)""", host.Output);
    }

    /// <summary>
    /// Story 2.5: Client Credentials on the real Protocol pipeline at Trace, through the hosts' scrubbing
    /// logging, with a real machine client signing through the real Transit. Normally the client gets a
    /// token by both secret methods; failing, a wrong secret is refused at its Tenant and its real one
    /// at another Tenant. The client secret, its random part and every issued token must appear in no
    /// log or table; a token response holds its token by design, so only its other fields are captured.
    /// </summary>
    private static async Task ClientCredentialsAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        const string hostA = "canary-a.tokens.test";
        const string hostB = "canary-b.tokens.test";

        var database = await Protocol.ProtocolDatabase.CreateAsync(context.Postgres);
        run.Database = database.Name;
        run.Plant("role-password", PostgresFixture.Password);
        var a = await database.AddTenantAsync(hostA);
        var b = await database.AddTenantAsync(hostB);
        Assert.True(await database.ProvisionAsync(context.Bao, a.TenantId));
        Assert.True(await database.ProvisionAsync(context.Bao, b.TenantId));

        var client = await database.CreateClientAsync(a.TenantId);
        run.Plant("client-secret", client.Secret);
        run.Plant("client-secret-random", client.Secret[(client.Secret.IndexOf('.', StringComparison.Ordinal) + 1)..]);

        var captured = new CapturedConsole();
        await using (var host = await Protocol.ProtocolHost.StartAsync(database.Hosted, context.Bao, logging: logging =>
        {
            logging.AddGatekeepLogging().SetMinimumLevel(LogLevel.Trace);
            logging.Services.AddSingleton<Microsoft.Extensions.Logging.Console.ConsoleFormatter>(captured);
            logging.Services.Configure<Microsoft.Extensions.Logging.Console.ConsoleLoggerOptions>(options => options.FormatterName = captured.Name);
        }))
        {
            if (failing)
            {
                var wrong = run.Plant("client-secret-wrong", client.Secret[..(client.Secret.IndexOf('.', StringComparison.Ordinal) + 1)] + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24)));
                using (var refused = await Protocol.ClientCredentialsTests.TokenAsync(host, hostA, client.ClientId, wrong.Value))
                {
                    run.Capture("wrong secret response", refused.Body.RootElement.GetRawText());
                    Assert.Equal("invalid_client", refused.Error);
                }

                using var cross = await Protocol.ClientCredentialsTests.TokenAsync(host, hostB, client.ClientId, client.Secret, "post");
                run.Capture("cross-Tenant response", cross.Body.RootElement.GetRawText());
                Assert.Equal("invalid_client", cross.Error);
            }
            else
            {
                foreach (var method in new[] { "basic", "post" })
                {
                    using var issued = await Protocol.ClientCredentialsTests.TokenAsync(host, hostA, client.ClientId, client.Secret, method);
                    Assert.Equal(HttpStatusCode.OK, issued.Status);
                    run.Plant($"access-token-{method}", issued.AccessToken);
                    run.Capture($"{method} token response", $"{issued.Body.RootElement.GetProperty("token_type").GetString()} {issued.Body.RootElement.GetProperty("expires_in").GetInt32()}");
                }
            }
        }

        run.Capture("Hosted log", captured.Text);
        Assert.Contains("connect/token", captured.Text, StringComparison.Ordinal);
    }

    /// <summary>
    /// Story 2.9: the authorization code flow with PKCE on the real Protocol pipeline at Trace, through the
    /// hosts' scrubbing logging, with a real web client, the test-only sign-in and the real Transit. Normally
    /// a code is issued and redeemed for an access and an ID token; failing, a wrong verifier is refused,
    /// then the code is redeemed and replayed, which revokes its family. The client secret, the code, its
    /// random part, the verifier and every issued token must appear in no log or table; a response holds
    /// its code or tokens by design, so only its other fields are captured.
    /// </summary>
    private static async Task AuthorizationCodeAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        const string hostA = "canary-a.code.test";
        const string hostB = "canary-b.code.test";

        var flow = await Protocol.CodeFlowSetup.CreateAsync(context.Postgres, context.Bao, hostA, hostB);
        run.Database = flow.Database.Name;
        run.Plant("role-password", PostgresFixture.Password);
        run.Plant("client-secret", flow.ClientA.Secret);
        run.Plant("client-secret-random", flow.ClientA.Secret[(flow.ClientA.Secret.IndexOf('.', StringComparison.Ordinal) + 1)..]);

        var pkce = Protocol.Pkce.New();
        run.Plant("code-verifier", pkce.Verifier);

        var captured = new CapturedConsole();
        await using (var host = await flow.StartHostAsync(logging: logging =>
        {
            logging.AddGatekeepLogging().SetMinimumLevel(LogLevel.Trace);
            logging.Services.AddSingleton<Microsoft.Extensions.Logging.Console.ConsoleFormatter>(captured);
            logging.Services.Configure<Microsoft.Extensions.Logging.Console.ConsoleLoggerOptions>(options => options.FormatterName = captured.Name);
        }))
        {
            var code = await Protocol.CodeFlow.CodeAsync(host, hostA, flow.ClientA.ClientId, Protocol.CodeFlowSetup.Callback, pkce, flow.UserA);
            run.Plant("authorization-code", code);
            run.Plant("authorization-code-random", code[(code.IndexOf('.', StringComparison.Ordinal) + 1)..]);

            if (failing)
            {
                var wrong = Protocol.Pkce.New();
                run.Plant("code-verifier-wrong", wrong.Verifier);
                using (var refused = await Protocol.CodeFlow.ExchangeAsync(
                    host, hostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Protocol.CodeFlowSetup.Callback, wrong.Verifier))
                {
                    run.Capture("wrong verifier response", refused.Body.RootElement.GetRawText());
                    Assert.Equal("invalid_grant", refused.Error);
                }
            }

            using (var issued = await Protocol.CodeFlow.ExchangeAsync(
                host, hostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Protocol.CodeFlowSetup.Callback, pkce.Verifier))
            {
                Assert.Equal(HttpStatusCode.OK, issued.Status);
                run.Plant("access-token", issued.AccessToken);
                run.Plant("id-token", issued.Body.RootElement.GetProperty("id_token").GetString()!);
                run.Capture("token response", $"{issued.Body.RootElement.GetProperty("token_type").GetString()} {issued.Body.RootElement.GetProperty("expires_in").GetInt32()}");
            }

            if (failing)
            {
                using var replay = await Protocol.CodeFlow.ExchangeAsync(
                    host, hostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Protocol.CodeFlowSetup.Callback, pkce.Verifier);
                run.Capture("replay response", replay.Body.RootElement.GetRawText());
                Assert.Equal("invalid_grant", replay.Error);
            }
        }

        run.Capture("Hosted log", captured.Text);
        Assert.Contains("connect/authorize", captured.Text, StringComparison.Ordinal);
        Assert.Contains("connect/token", captured.Text, StringComparison.Ordinal);
    }

    /// <summary>
    /// Story 2.10: the refresh grant on a Tenant's token endpoint, through the real Protocol registration and
    /// the hosts' scrubbing logging, with a real web client, the test-only sign-in and the real Transit. A code
    /// flow with <c>offline_access</c> is exchanged for a refresh token, which is then rotated for a new one;
    /// failing, the rotated-out token is presented again, which is reuse and revokes the family, and the
    /// newest one is then refused. The client secret, the code, the verifier, both refresh tokens and their
    /// random parts and every issued token must appear in no log or table; a response holds its tokens by
    /// design, so only its other fields are captured.
    /// </summary>
    private static async Task RefreshTokenAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        const string hostA = "canary-a.refresh.test";
        const string hostB = "canary-b.refresh.test";

        var flow = await Protocol.CodeFlowSetup.CreateAsync(context.Postgres, context.Bao, hostA, hostB);
        run.Database = flow.Database.Name;
        run.Plant("role-password", PostgresFixture.Password);
        run.Plant("client-secret", flow.ClientA.Secret);
        run.Plant("client-secret-random", flow.ClientA.Secret[(flow.ClientA.Secret.IndexOf('.', StringComparison.Ordinal) + 1)..]);

        var pkce = Protocol.Pkce.New();
        run.Plant("code-verifier", pkce.Verifier);

        var captured = new CapturedConsole();
        await using (var host = await flow.StartHostAsync(logging: logging =>
        {
            logging.AddGatekeepLogging().SetMinimumLevel(LogLevel.Trace);
            logging.Services.AddSingleton<Microsoft.Extensions.Logging.Console.ConsoleFormatter>(captured);
            logging.Services.Configure<Microsoft.Extensions.Logging.Console.ConsoleLoggerOptions>(options => options.FormatterName = captured.Name);
        }))
        {
            var code = await Protocol.CodeFlow.CodeAsync(
                host, hostA, flow.ClientA.ClientId, Protocol.CodeFlowSetup.Callback, pkce, flow.UserA, scope: "openid offline_access");
            run.Plant("authorization-code", code);
            run.Plant("authorization-code-random", code[(code.IndexOf('.', StringComparison.Ordinal) + 1)..]);

            string first;
            using (var issued = await Protocol.CodeFlow.ExchangeAsync(
                host, hostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Protocol.CodeFlowSetup.Callback, pkce.Verifier))
            {
                Assert.Equal(HttpStatusCode.OK, issued.Status);
                first = issued.RefreshToken;
                run.Plant("refresh-token", first);
                run.Plant("refresh-token-random", first[(first.IndexOf('.', StringComparison.Ordinal) + 1)..]);
                run.Plant("access-token", issued.AccessToken);
                run.Plant("id-token", issued.Body.RootElement.GetProperty("id_token").GetString()!);
                run.Capture("token response", $"{issued.Body.RootElement.GetProperty("token_type").GetString()} {issued.Body.RootElement.GetProperty("expires_in").GetInt32()}");
            }

            string second;
            using (var refreshed = await Protocol.CodeFlow.RefreshAsync(host, hostA, flow.ClientA.ClientId, flow.ClientA.Secret, first))
            {
                Assert.Equal(HttpStatusCode.OK, refreshed.Status);
                second = refreshed.RefreshToken;
                run.Plant("refresh-token-rotated", second);
                run.Plant("refresh-token-rotated-random", second[(second.IndexOf('.', StringComparison.Ordinal) + 1)..]);
                run.Plant("refreshed-access-token", refreshed.AccessToken);
                run.Plant("refreshed-id-token", refreshed.Body.RootElement.GetProperty("id_token").GetString()!);
                run.Capture("refresh response", $"{refreshed.Body.RootElement.GetProperty("token_type").GetString()} {refreshed.Body.RootElement.GetProperty("expires_in").GetInt32()}");
            }

            if (failing)
            {
                using (var reused = await Protocol.CodeFlow.RefreshAsync(host, hostA, flow.ClientA.ClientId, flow.ClientA.Secret, first))
                {
                    run.Capture("reuse response", reused.Body.RootElement.GetRawText());
                    Assert.Equal("invalid_grant", reused.Error);
                }

                using var revoked = await Protocol.CodeFlow.RefreshAsync(host, hostA, flow.ClientA.ClientId, flow.ClientA.Secret, second);
                run.Capture("revoked family response", revoked.Body.RootElement.GetRawText());
                Assert.Equal("invalid_grant", revoked.Error);
            }
        }

        run.Capture("Hosted log", captured.Text);
        Assert.Contains("connect/token", captured.Text, StringComparison.Ordinal);
    }

    /// <summary>
    /// Story 2.11: the userinfo and revocation endpoints on the real Protocol registration, through the hosts'
    /// scrubbing logging at Trace, with a real web client, the test-only sign-in and the real Transit. A code flow
    /// with <c>offline_access</c> is exchanged; its access token is sent to userinfo as a bearer, and its refresh
    /// token is revoked by its client. Failing, userinfo is sent the ID token and a garbage bearer, the access
    /// token is presented for revocation, the refresh token is revoked with a wrong secret and at another Tenant,
    /// and then refreshed after its revocation. The client secret, the code, the verifier, the refresh token and its
    /// random part and every issued token must appear in no log or table; userinfo's and revocation's responses
    /// hold none of them, so they are captured whole.
    /// </summary>
    private static async Task UserinfoAndRevocationAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        const string hostA = "canary-a.revoke.test";
        const string hostB = "canary-b.revoke.test";

        var flow = await Protocol.CodeFlowSetup.CreateAsync(context.Postgres, context.Bao, hostA, hostB);
        run.Database = flow.Database.Name;
        run.Plant("role-password", PostgresFixture.Password);
        run.Plant("client-secret", flow.ClientA.Secret);
        run.Plant("client-secret-random", flow.ClientA.Secret[(flow.ClientA.Secret.IndexOf('.', StringComparison.Ordinal) + 1)..]);
        var clientB = await flow.Database.CreateWebClientAsync(flow.B.TenantId, [Protocol.CodeFlowSetup.Callback]);
        run.Plant("client-b-secret", clientB.Secret);

        var pkce = Protocol.Pkce.New();
        run.Plant("code-verifier", pkce.Verifier);

        var captured = new CapturedConsole();
        await using (var host = await flow.StartHostAsync(logging: logging =>
        {
            logging.AddGatekeepLogging().SetMinimumLevel(LogLevel.Trace);
            logging.Services.AddSingleton<Microsoft.Extensions.Logging.Console.ConsoleFormatter>(captured);
            logging.Services.Configure<Microsoft.Extensions.Logging.Console.ConsoleLoggerOptions>(options => options.FormatterName = captured.Name);
        }))
        {
            var code = await Protocol.CodeFlow.CodeAsync(
                host, hostA, flow.ClientA.ClientId, Protocol.CodeFlowSetup.Callback, pkce, flow.UserA, scope: "openid offline_access");
            run.Plant("authorization-code", code);
            run.Plant("authorization-code-random", code[(code.IndexOf('.', StringComparison.Ordinal) + 1)..]);

            string access;
            string id;
            string refresh;
            using (var issued = await Protocol.CodeFlow.ExchangeAsync(
                host, hostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Protocol.CodeFlowSetup.Callback, pkce.Verifier))
            {
                Assert.Equal(HttpStatusCode.OK, issued.Status);
                access = issued.AccessToken;
                id = issued.Body.RootElement.GetProperty("id_token").GetString()!;
                refresh = issued.RefreshToken;
                run.Plant("userinfo-bearer-access-token", access);
                run.Plant("id-token", id);
                run.Plant("revoked-refresh-token", refresh);
                run.Plant("revoked-refresh-token-random", refresh[(refresh.IndexOf('.', StringComparison.Ordinal) + 1)..]);
                run.Capture("token response", $"{issued.Body.RootElement.GetProperty("token_type").GetString()} {issued.Body.RootElement.GetProperty("expires_in").GetInt32()}");
            }

            using (var userinfo = await Protocol.UserinfoAndRevocationTests.UserinfoAsync(host, hostA, access))
            {
                Assert.Equal(HttpStatusCode.OK, userinfo.Status);
                run.Capture("userinfo response", $"{(int)userinfo.Status} {userinfo.Body}");
            }

            if (failing)
            {
                foreach (var (name, bearer) in new[] { ("ID token", id), ("garbage", run.Plant("userinfo-garbage-bearer").Value) })
                {
                    using var refused = await Protocol.UserinfoAndRevocationTests.UserinfoAsync(host, hostA, bearer);
                    Assert.Equal(HttpStatusCode.Unauthorized, refused.Status);
                    run.Capture($"userinfo {name} response", $"{(int)refused.Status} {refused.WwwAuthenticate} {refused.Body}");
                }

                using (var unsupported = await Protocol.UserinfoAndRevocationTests.RevokeAsync(host, hostA, flow.ClientA.ClientId, flow.ClientA.Secret, access))
                {
                    Assert.Equal("unsupported_token_type", unsupported.Error);
                    run.Capture("access token revocation response", $"{(int)unsupported.Status} {unsupported.Body}");
                }

                var wrong = run.Plant("client-secret-wrong", flow.ClientA.Secret[..(flow.ClientA.Secret.IndexOf('.', StringComparison.Ordinal) + 1)] + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24)));
                using (var badClient = await Protocol.UserinfoAndRevocationTests.RevokeAsync(host, hostA, flow.ClientA.ClientId, wrong.Value, refresh))
                {
                    Assert.Equal("invalid_client", badClient.Error);
                    run.Capture("wrong secret revocation response", $"{(int)badClient.Status} {badClient.Body}");
                }

                using (var cross = await Protocol.UserinfoAndRevocationTests.RevokeAsync(host, hostB, clientB.ClientId, clientB.Secret, refresh))
                {
                    Assert.Equal(HttpStatusCode.OK, cross.Status);
                    run.Capture("cross-Tenant revocation response", $"{(int)cross.Status} {cross.Body}");
                }
            }

            using (var revoked = await Protocol.UserinfoAndRevocationTests.RevokeAsync(host, hostA, flow.ClientA.ClientId, flow.ClientA.Secret, refresh))
            {
                Assert.Equal(HttpStatusCode.OK, revoked.Status);
                run.Capture("revocation response", $"{(int)revoked.Status} {revoked.Body}");
            }

            if (failing)
            {
                using var afterRevocation = await Protocol.CodeFlow.RefreshAsync(host, hostA, flow.ClientA.ClientId, flow.ClientA.Secret, refresh);
                Assert.Equal("invalid_grant", afterRevocation.Error);
                run.Capture("refresh after revocation response", afterRevocation.Body.RootElement.GetRawText());
            }
        }

        run.Capture("Hosted log", captured.Text);
        Assert.Contains("connect/userinfo", captured.Text, StringComparison.Ordinal);
        Assert.Contains("connect/revoke", captured.Text, StringComparison.Ordinal);
    }

    /// <summary>A response's status, every header and its body, as one text to scan.</summary>
    private static async Task<string> ResponseTextAsync(HttpResponseMessage response)
    {
        var headers = response.Headers.Concat(response.Content.Headers).Select(h => $"{h.Key}: {string.Join(", ", h.Value)}");
        return $"{(int)response.StatusCode}\n{string.Join("\n", headers)}\n{await response.Content.ReadAsStringAsync(CanaryFlowContext.Cancellation)}";
    }

    /// <summary>
    /// Story 1.30: <c>gatekeep alerts test</c> through the webhook adapter to a sink, with a canary
    /// bearer token and a canary in the hook's path, as webhook services put a secret there. What
    /// left the process is scanned: the body and every header but <c>Authorization</c>, which must be
    /// exactly the token, plus the Cli's output. Failing, the sink answers 500 with a body.
    /// </summary>
    private static async Task AlertsChannelAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        var token = run.Plant("alert-token");
        var hook = run.Plant("webhook-path");
        await using var sink = await AlertSinkFixture.StartAsync();
        sink.Status = failing ? 500 : 204;
        var options = new WebhookAlertOptions { Url = new Uri(sink.Url, $"/hooks/{hook.Value}"), TokenFile = context.File(token.Value + "\n") };
        var output = new StringWriter();
        var error = new StringWriter();

        var exit = await AlertsTestCommand.SendAsync(
            options, new AlertDeployment("admin.gatekeep-admin.test"), ObjectLockFixture.Permitted(), TimeProvider.System, output, error, CanaryFlowContext.Cancellation);
        run.Capture("alerts test stdout", output.ToString());
        run.Capture("alerts test stderr", error.ToString());

        var request = Assert.Single(sink.Requests);
        Assert.Equal($"Bearer {token.Value}", request.Headers["Authorization"]);
        run.Capture("webhook body", Encoding.UTF8.GetString(request.Body));
        run.Capture(
            "webhook headers",
            string.Join('\n', request.Headers.Where(h => h.Key != "Authorization").Select(h => $"{h.Key}: {h.Value}")));

        Assert.Equal(failing ? 1 : 0, exit);
        Assert.Equal(failing ? AlertsTestCommand.Rejected : string.Empty, error.ToString().Trim());
    }

    /// <summary>
    /// Story 1.30: <c>gatekeep records test</c> through the record writer and the Object Lock adapter
    /// to the bucket, with the server credential planted as canaries. The objects it wrote are
    /// scanned with their metadata, beside the Cli's output. Failing, the secret key is a wrong
    /// canary value, so the bucket refuses the write.
    /// </summary>
    private static async Task RecordsObjectLockAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        var bucket = context.Bucket;
        run.Plant("bucket-access-key-id", bucket.AccessKeyId);
        var secretKeyFile = failing
            ? context.File(run.Plant("wrong-bucket-secret-key").Value + "\n")
            : bucket.SecretAccessKeyFile;
        if (!failing)
        {
            run.Plant("bucket-secret-key", bucket.SecretAccessKey);
        }

        var output = new StringWriter();
        var error = new StringWriter();
        var exit = await RecordsTestCommand.WriteAsync(
            bucket.Options(secretAccessKeyFile: secretKeyFile), new SigningCustody(), ObjectLockFixture.Permitted(), TimeProvider.System,
            output, error, CanaryFlowContext.Cancellation);
        run.Capture("records test stdout", output.ToString());
        run.Capture("records test stderr", error.ToString());

        Assert.Equal(failing ? 1 : 0, exit);
        if (failing)
        {
            Assert.Equal(RecordsTestCommand.Rejected, error.ToString().Trim());
            return;
        }

        var key = output.ToString().Trim()[(RecordsTestCommand.Written.Length + 1)..];
        var dumped = await bucket.DumpAsync(key);
        Assert.Equal(2, dumped.Count);
        foreach (var (name, text) in dumped)
        {
            run.Capture(name, text);
        }
    }

    /// <summary>
    /// Story 1.30: <c>gatekeep audit-ship --once</c> over an audit file of HMAC'd entries, as OpenBao
    /// writes them, to the bucket, with the server credential planted as canaries. The chunks it wrote
    /// are scanned with their metadata, beside the shipper's output. Failing, the secret key is a
    /// wrong canary value, so the bucket refuses each chunk and nothing ships.
    /// </summary>
    private static async Task AuditShipAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        var bucket = context.Bucket;
        run.Plant("bucket-access-key-id", bucket.AccessKeyId);
        var secretKeyFile = failing
            ? context.File(run.Plant("wrong-bucket-secret-key").Value + "\n")
            : bucket.SecretAccessKeyFile;
        if (!failing)
        {
            run.Plant("bucket-secret-key", bucket.SecretAccessKey);
        }

        static string Hmac() => "hmac-sha256:" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        var auditFile = context.File(string.Concat(Enumerable.Range(0, 3).Select(i =>
            "{\"type\":\"request\",\"auth\":{\"client_token\":\"" + Hmac() + "\"},\"request\":{\"path\":\"transit/encrypt/social-" + i
            + "\",\"data\":{\"plaintext\":\"" + Hmac() + "\"}}}\n")));
        var state = context.NewDirectory();
        var output = new StringWriter();
        var error = new StringWriter();

        var exit = await AuditShipCommand.ShipAsync(
            bucket.Options(secretAccessKeyFile: secretKeyFile), auditFile, state, ObjectLockFixture.Permitted(), TimeProvider.System,
            output, error, once: true, AuditShipCommand.Interval, CanaryFlowContext.Cancellation);
        run.Capture("audit-ship stdout", output.ToString());
        run.Capture("audit-ship stderr", error.ToString());

        Assert.Equal(failing ? 1 : 0, exit);
        var fileId = File.ReadAllLines(Path.Combine(state, "state"))[0];
        var dumped = await bucket.DumpAsync($"openbao-audit/{DateTime.UtcNow:yyyy/MM/dd}/{fileId}-");
        Assert.Equal(failing ? 0 : 2, dumped.Count);
        foreach (var (name, text) in dumped)
        {
            run.Capture(name, text);
        }
    }

    /// <summary>
    /// A credential job through the real enqueuer and runner, logging at Trace through the hosts'
    /// logging. Failing, the handler throws with the decrypted value in its message on every
    /// attempt, until the job goes dead.
    /// </summary>
    private static async Task CredentialJobAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        const int MaxAttempts = 2;

        var credential = run.Plant("job-credential");
        var type = new JobType("tests.canary.credential");
        var registry = new JobRegistry(
        [
            new JobDefinition(type, JobScope.Tenant, [JobRole.Worker], JobRole.Worker, MaxAttempts, HandleAsync, mayCarryCredential: true),
        ]);

        var database = await JobDatabase.CreateAsync(context.Postgres, registry);
        run.Database = database.Name;
        var custody = new FakeKeyCustody();
        var payload = new JobPayload(
            new Dictionary<string, Guid> { ["user_id"] = Guid.CreateVersion7() },
            new Secret<byte[]>(Encoding.UTF8.GetBytes(credential.Value)));

        var job = await database.InScopeAsync(
            TableRegistry.Worker,
            JobDatabase.TenantA,
            c => OperationsContract.CreateEnqueuer(registry, custody).EnqueueAsync(c, type, payload, runAfter: null, CanaryFlowContext.Cancellation));

        var captured = new CapturedConsole();
        using (var logging = CapturedLogging.Create(captured, LogLevel.Trace))
        {
            var logger = logging.GetRequiredService<ILoggerFactory>().CreateLogger("Gatekeep.Modules.Operations.JobRunner");

            // A job that succeeds logs nothing, so this line shows the Trace capture is live.
            logger.LogDebug("Running canary job {JobId}.", job);
            await using var runner = database.Runner(registry, custody, logger);

            for (var attempt = 1; attempt <= (failing ? MaxAttempts : 1); attempt++)
            {
                await database.MakeDueAsync(job);
                Assert.True(await runner.RunOnceAsync(CanaryFlowContext.Cancellation));
            }
        }

        run.Capture("job runner log", captured.Text);

        Assert.Equal(failing ? "dead" : "done", await database.StatusAsync(job));
        Assert.Equal(failing ? MaxAttempts : 1, custody.Decrypts);

        async Task HandleAsync(JobRun jobRun, CancellationToken cancellationToken)
        {
            var secret = await jobRun.DecryptCredentialAsync(cancellationToken);
            if (failing)
            {
                // A handler bug that puts the value in its exception: the runner keeps a fixed code only.
                secret.Use<int>(bytes => throw new InvalidOperationException($"Delivery failed for {Encoding.UTF8.GetString(bytes)}"));
            }
        }
    }

    /// <summary>
    /// The OpenBao adapter over the stand-in socket: an AppRole login with a canary secret ID, then
    /// a Transit encrypt of a canary plaintext, answered with a canary token. Failing, the login succeeds and Transit answers an error echoing the plaintext.
    /// </summary>
    private static async Task CustodyAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        var secretId = run.Plant("approle-secret-id");
        var token = run.Plant("openbao-token");
        var plaintext = run.Plant("payload-plaintext");

        var socket = context.Socket();
        socket.Body = $$$"""{"auth":{"client_token":"{{{token.Value}}}","lease_duration":900},"data":{"ciphertext":"vault:v1:Y2lwaGVydGV4dA=="}}""";
        if (failing)
        {
            // The login succeeds, then Transit fails echoing the plaintext, as an error body may.
            var login = socket.Body;
            socket.Respond = path => path.Contains("/auth/", StringComparison.Ordinal)
                ? (200, login)
                : (500, $$"""{"errors":["encrypt failed for plaintext {{plaintext.Value}}"]}""");
        }

        using var custody = new OpenBaoKeyCustody(
            new OpenBaoOptions
            {
                SocketPath = socket.Path,
                RoleIdFile = context.File(Guid.NewGuid().ToString()),
                SecretIdFile = context.File(secretId.Value + "\n"),
            },
            TimeProvider.System);

        var captured = new CapturedConsole();
        using (var logging = CapturedLogging.Create(captured, LogLevel.Trace))
        {
            var logger = logging.GetRequiredService<ILoggerFactory>().CreateLogger("Gatekeep.Adapters.OpenBao");
            try
            {
                var ciphertext = await custody.EncryptAsync(
                    KeyName.ForTenant(TenantKeyClass.Payload, TenantA),
                    TenantA,
                    new Secret<byte[]>(Encoding.UTF8.GetBytes(plaintext.Value)),
                    CanaryFlowContext.Cancellation);

                logger.LogDebug("Encrypted a payload as {Ciphertext}", ciphertext);
                Assert.False(failing, "A failing Transit encrypted a payload.");
            }
            catch (KeyCustodyException e) when (failing)
            {
                logger.LogError(e, "Key custody failed with {Failure}", e.Failure);
                run.Capture("custody exception", e.ToString());
                Assert.Equal(KeyCustodyFailure.Unavailable, e.Failure);
            }
        }

        run.Capture("custody log", captured.Text);
    }

    /// <summary>
    /// The audit appender with canary-shaped User-Agents, on a Tenant and the Deployment chain.
    /// Failing, the role may insert the event but not its detail, so the insert carrying the masked
    /// User-Agent is refused and its error is logged.
    /// </summary>
    private static async Task AppenderAsync(CanaryFlowContext context, FlowRun run, bool failing)
    {
        var bearer = run.Plant("bearer-user-agent");
        var query = run.Plant("query-token-user-agent");
        var database = await context.Postgres.NewMigratedDatabaseAsync();
        run.Database = database;
        await PostgresFixture.ExecuteAsync(context.Postgres.SuperuserConnection(database), TestTenants.InsertSql(TenantA));

        var appender = AuditContract.CreateAppender();
        var auditEvent = new AuditEvent(new AuditTypeCode("tests.canary.appended"), Actor.Anonymous);
        AuditDetail[] details =
        [
            new(IPAddress.Parse("192.0.2.7"), $"Bearer {bearer.Value}", "person@example.test"),
            new(IPAddress.Parse("192.0.2.8"), $"agent/1.0 (+https://example.test/?access_token={query.Value})", null),
        ];

        var captured = new CapturedConsole();
        using (var logging = CapturedLogging.Create(captured, LogLevel.Trace))
        {
            var logger = logging.GetRequiredService<ILoggerFactory>().CreateLogger("Gatekeep.Modules.Audit");
            await using var source = NpgsqlDataSource.Create(
                context.Postgres.RoleConnection(failing ? TableRegistry.Retention : TableRegistry.Admin, database));

            foreach (var tenantId in new Guid?[] { TenantA, null })
            {
                foreach (var detail in details)
                {
                    try
                    {
                        await using CommandScope scope = tenantId is { } id
                            ? await TenantScope.BeginAsync(source, id, CanaryFlowContext.Cancellation)
                            : await DeploymentScope.BeginAsync(source, CanaryFlowContext.Cancellation);
                        await appender.AppendAsync(scope.CreateCommandContext(), auditEvent, detail, CanaryFlowContext.Cancellation);
                        await scope.CommitAsync(CanaryFlowContext.Cancellation);
                        logger.LogDebug("Appended {Detail} for {UserAgent}", detail, detail.UserAgent);
                        Assert.False(failing, "A role with no detail grant appended an event.");
                    }
                    catch (NpgsqlException e) when (failing)
                    {
                        logger.LogError(e, "Append failed for {Detail}", detail);
                        run.Capture("append exception", e.ToString());
                    }
                }
            }
        }

        run.Capture("appender log", captured.Text);
    }

    private static IReadOnlyList<(string Name, string Role)> Databases(string host) => host switch
    {
        "Hosted" => [("Hosted", TableRegistry.Hosted)],
        "Admin" => [("Admin", TableRegistry.Admin)],
        "Worker" =>
        [
            ("Dispatch", TableRegistry.Dispatch),
            ("Worker", TableRegistry.Worker),
            ("Sealer", TableRegistry.Sealer),
            ("Retention", TableRegistry.Retention),
        ],
        _ => throw new ArgumentOutOfRangeException(nameof(host)),
    };

    /// <summary>A connection to a loopback port nothing listens on, so it's refused at once.</summary>
    private static string RefusedConnection(string role) =>
        $"Host=127.0.0.1;Port={HostProcess.FreePort()};Database=gatekeep;Username={role};Timeout=5";

    /// <summary>The connection the Compose secrets pattern uses: the password comes from its own file.</summary>
    private static string Passwordless(string connection) =>
        new NpgsqlConnectionStringBuilder(connection) { Password = null }.ConnectionString;
}
