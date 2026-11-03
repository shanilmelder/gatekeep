using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Gatekeep.Adapters.OpenBao;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Tests.Isolation.Audit;
using Gatekeep.Tests.Isolation.Hosting;
using Gatekeep.Tests.Isolation.Jobs;
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

/// <summary>What a flow can use: the database cluster, a scratch folder, and the test's cancellation.</summary>
internal sealed class CanaryFlowContext(PostgresFixture postgres, string directory) : IDisposable
{
    private readonly List<IDisposable> _owned = [];

    public PostgresFixture Postgres => postgres;

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

    /// <summary>The <c>migrate</c>, <c>audit verify</c> and <c>init</c> commands, from the Cli's <c>args switch</c>.</summary>
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

        // No production type carries a credential yet, so this flow takes the runner's credential
        // path with a test type: enqueue, decrypt, run, retry and dead, as every one will.
        new("jobs.credential", [], CredentialJobAsync),
        new("custody.openbao", [], CustodyAsync),
        new("audit.appender", [], AppenderAsync),
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
    /// is refused capabilities and signing out, which isn't setup-allowed, though it sends the
    /// Origin and CSRF token; the token must appear in no response, and the Session
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

            // A setup Session can't sign out: it would strand the only Deployment Owner.
            using var signOut = await host.SendAsync(HttpMethod.Delete, "/api/v1/deployment/session", cookie, rotated, Admins.AdminHost.Origin);
            run.Capture("sign-out response", await ResponseTextAsync(signOut));
            Assert.Equal(HttpStatusCode.Forbidden, signOut.StatusCode);

            run.Plant("admin-session-id", cookie);
            run.Plant("admin-csrf-token", csrf);
            run.Plant("admin-rotated-csrf-token", rotated);
        }

        await host.StopAsync();
        run.Capture("Admin output", host.Output);
        Assert.Matches(@"""LogLevel"":""(?:Trace|Debug)""", host.Output);
    }

    /// <summary>A response's status, every header and its body, as one text to scan.</summary>
    private static async Task<string> ResponseTextAsync(HttpResponseMessage response)
    {
        var headers = response.Headers.Concat(response.Content.Headers).Select(h => $"{h.Key}: {string.Join(", ", h.Value)}");
        return $"{(int)response.StatusCode}\n{string.Join("\n", headers)}\n{await response.Content.ReadAsStringAsync(CanaryFlowContext.Cancellation)}";
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
        await PostgresFixture.ExecuteAsync(context.Postgres.SuperuserConnection(database), $"INSERT INTO tenant (id) VALUES ('{TenantA}')");

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
