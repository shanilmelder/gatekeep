using System.Reflection;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>AD-4 and AD-28 rules, which the compiler can't enforce alone.</summary>
public class PersistenceRuleTests
{
    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private const BindingFlags AllInstance = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance;

    /// <summary>The compiler-made property on every record, which holds no data.</summary>
    private const string EqualityContract = "EqualityContract";

    private static readonly string[] SkippedDirectories = ["bin", "obj"];

    private static readonly string[] SetConfigOwners =
    [
        "src/Gatekeep.Kernel/Persistence/TenantScope.cs",
        "src/Adapters/Postgres/Migrations/ForEachTenant.cs",
    ];

    private static readonly Regex ForbiddenInContracts = new(
        @"\b(?:Tenant|Deployment|Command)Scope\b|\bFailureContext\b|\bDbDataSource\b|\.\s*(?:Commit|Rollback)(?:Async)?\b|\.\s*(?:Transaction|Connection)\b|(?i:\b(?:COMMIT|ROLLBACK)\b)",
        RegexOptions.Compiled);

    private static readonly Regex SetConfigCall = new(@"\bset_config\s*\(", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex Comment = new(
        @"//[^\r\n]*|/\*.*?\*/|--[^\r\n]*",
        RegexOptions.Singleline | RegexOptions.Compiled);

    // `UPDATE <identifier> [alias] SET` is ordinary SQL, so it's removed before looking
    // for a SET statement. So is the ON CONFLICT form, which names no table.
    private static readonly Regex UpdateSet = new(
        @"\bUPDATE\s+(?:ONLY\s+)?(?!SET\b)[\w.""]+(?:\s+(?:AS\s+)?(?!SET\b)[\w""]+)?\s+SET\b|\bDO\s+UPDATE\s+SET\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SessionSet = new(
        @"\bSET\s+(?:SESSION\s+(?!CHARACTERISTICS)\S|ROLE\b|TIME\s+ZONE\b|SCHEMA\b|NAMES\b|LOCAL\s+""?gatekeep\.tenant_id\b|[\w.""]+\s*(?:=|\bTO\b))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    [Fact]
    public void Kernel_uses_no_package()
    {
        var kernel = XDocument.Load(Path.Combine(Root, "src/Gatekeep.Kernel/Gatekeep.Kernel.csproj"));

        Assert.Empty(kernel.Descendants("PackageReference"));
    }

    [Fact]
    public void CommandContext_has_no_public_constructor()
    {
        Assert.Empty(typeof(CommandContext).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
    }

    [Fact]
    public void CommandContext_has_no_commit_or_rollback_member()
    {
        var members = typeof(CommandContext)
            .GetMembers(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static)
            .Select(m => m.Name);

        Assert.DoesNotContain(
            members,
            m => m.Contains("Commit", StringComparison.OrdinalIgnoreCase)
                || m.Contains("Rollback", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Audit_envelope_holds_only_a_code_and_internal_references()
    {
        Type[] allowed = [typeof(Guid), typeof(Guid?), typeof(Actor), typeof(AuditTypeCode), typeof(AuditTargetKind?)];

        var members = StoredMemberTypes(typeof(AuditEvent)).ToList();

        Assert.NotEmpty(members);
        Assert.All(members, t => Assert.Contains(t, allowed));
    }

    [Fact]
    public void Actor_holds_only_a_kind_and_an_ID()
    {
        Type[] allowed = [typeof(ActorKind), typeof(Guid?)];

        var members = StoredMemberTypes(typeof(Actor)).ToList();

        Assert.NotEmpty(members);
        Assert.All(members, t => Assert.Contains(t, allowed));
    }

    [Fact]
    public void AuditTypeCode_holds_only_its_one_string_value()
    {
        var property = Assert.Single(typeof(AuditTypeCode).GetProperties(AllInstance), p => p.Name != EqualityContract);

        Assert.Equal(nameof(AuditTypeCode.Value), property.Name);
        Assert.Equal(typeof(string), property.PropertyType);
        Assert.All(StoredMemberTypes(typeof(AuditTypeCode)), t => Assert.Equal(typeof(string), t));
    }

    [Fact]
    public void Every_module_is_inspected_for_state_changing_contract_methods()
    {
        var assemblies = ModuleAssemblies();
        var projects = Directory
            .EnumerateFiles(Path.Combine(Root, "src/Modules"), "Gatekeep.Modules.*.csproj", SearchOption.AllDirectories)
            .Select(Path.GetFileNameWithoutExtension);

        Assert.Equal(projects.Order(), assemblies.Select(a => a.GetName().Name).Order());
        Assert.Empty(assemblies
            .Append(typeof(CommandContext).Assembly)
            .SelectMany(a => a.GetTypes())
            .SelectMany(MethodsMissingCommandContext));
    }

    [Fact]
    public void State_changing_method_without_a_context_is_reported()
    {
        var reported = MethodsMissingCommandContext(typeof(SampleContract));

        Assert.Equal([$"{nameof(SampleContract)}.{nameof(SampleContract.Missing)}"], reported);
    }

    [Fact]
    public void Contracts_cant_name_a_scope_data_source_or_commit()
    {
        var offenders = SourceFiles(Path.Combine(Root, "src/Modules"), "*.cs")
            .Where(f => f.Replace('\\', '/').Contains("/Contracts/"))
            .Where(f => ForbiddenInContracts.IsMatch(File.ReadAllText(f)));

        Assert.Empty(offenders);
    }

    [Theory]
    [InlineData("Task Run(TenantScope scope);", true)]
    [InlineData("Task Run(DeploymentScope scope);", true)]
    [InlineData("Task Run(CommandScope scope);", true)]
    [InlineData("await FailureContext.CommitAfterRollbackAsync(scope, Write);", true)]
    [InlineData("Task Run(DbDataSource source);", true)]
    [InlineData("context.CreateCommand().Transaction!.Commit();", true)]
    [InlineData("await transaction.CommitAsync(ct);", true)]
    [InlineData("await transaction.RollbackAsync(ct);", true)]
    [InlineData("var transaction = command.Transaction;", true)]
    [InlineData("var connection = command.Connection;", true)]
    [InlineData("command.CommandText = \"COMMIT\";", true)]
    [InlineData("command.CommandText = \"ROLLBACK\";", true)]
    [InlineData("command.CommandText = \"rollback\";", true)]
    [InlineData("Task Run(CommandContext context, CancellationToken ct);", false)]
    [InlineData("Task CommitToPlan(CommandContext context);", false)]
    public void Forbidden_contract_name_detection(string source, bool expected)
    {
        Assert.Equal(expected, ForbiddenInContracts.IsMatch(source));
    }

    [Fact]
    public void Source_has_no_session_level_set()
    {
        var offenders = PersistenceSource().Where(f => HasSessionSet(File.ReadAllText(f)));

        Assert.Empty(offenders);
    }

    [Theory]
    [InlineData("SET gatekeep.tenant_id = 'x'", true)]
    [InlineData("set gatekeep.tenant_id to 'x'", true)]
    [InlineData("SET SESSION gatekeep.tenant_id = 'x'", true)]
    [InlineData("\"SET search_path TO public\"", true)]
    [InlineData("SET ROLE gk_migrator", true)]
    [InlineData("SET SESSION AUTHORIZATION gk_migrator", true)]
    [InlineData("ALTER ROLE gk_hosted SET gatekeep.tenant_id = 'x'", true)]
    [InlineData("// Update the setting.\n\"SET gatekeep.tenant_id = 'x'\"", true)]
    [InlineData("/* UPDATE t */ SET gatekeep.tenant_id = 'x'", true)]
    [InlineData("-- update it\nSET gatekeep.tenant_id = 'x'", true)]
    [InlineData("SET TIME ZONE 'UTC'", true)]
    [InlineData("SET SCHEMA 'public'", true)]
    [InlineData("SET NAMES 'UTF8'", true)]
    [InlineData("SET LOCAL gatekeep.tenant_id = 'x'", true)]
    [InlineData("SET LOCAL \"gatekeep.tenant_id\" = 'x'", true)]
    [InlineData("UPDATE ONLY tenant_settings AS s SET updated_at = now()", false)]
    [InlineData("UPDATE tenant_settings s SET updated_at = now()", false)]
    [InlineData("// SET gatekeep.tenant_id = 'x'", false)]
    [InlineData("SET LOCAL statement_timeout = 5", false)]
    [InlineData("UPDATE tenant_settings SET updated_at = now()", false)]
    [InlineData("UPDATE tenant_settings\n  SET updated_at = now()\n  WHERE true", false)]
    [InlineData("ON CONFLICT (id) DO UPDATE SET updated_at = now()", false)]
    [InlineData("ALTER TABLE t ALTER COLUMN c SET DEFAULT 1", false)]
    [InlineData("ALTER TABLE t ALTER COLUMN c SET NOT NULL", false)]
    [InlineData("<summary>Session-level SET is forbidden.</summary>", false)]
    public void Session_set_detection(string source, bool expected)
    {
        Assert.Equal(expected, HasSessionSet(source));
    }

    [Fact]
    public void Source_calls_set_config_only_transaction_locally()
    {
        var offenders = PersistenceSource().Where(f => HasNonLocalSetConfig(File.ReadAllText(f)));

        Assert.Empty(offenders);
    }

    [Theory]
    [InlineData("SELECT set_config('gatekeep.tenant_id', @id, false)", true)]
    [InlineData("SELECT set_config('gatekeep.tenant_id', @id, @local)", true)]
    [InlineData("SELECT SET_CONFIG('a', b, FALSE)", true)]
    [InlineData("SELECT set_config('a', upper(b), false)", true)]
    [InlineData("SELECT set_config('a', b", true)]
    [InlineData("SELECT set_config('gatekeep.tenant_id', @id, true)", false)]
    [InlineData("PERFORM set_config('gatekeep.tenant_id', tenant_row.id::text, true);", false)]
    [InlineData("SELECT set_config('a', upper(b), TRUE)", false)]
    public void Non_local_set_config_detection(string source, bool expected)
    {
        Assert.Equal(expected, HasNonLocalSetConfig(source));
    }

    [Fact]
    public void Only_TenantScope_and_ForEachTenant_call_set_config()
    {
        var callers = PersistenceSource()
            .Where(f => SetConfigCall.IsMatch(File.ReadAllText(f)))
            .Select(f => Path.GetRelativePath(Root, f).Replace('\\', '/'))
            .Order();

        Assert.Equal(SetConfigOwners.Order(), callers);
    }

    /// <summary>Instance properties and fields, as a field could hold what a property can't.</summary>
    private static IEnumerable<Type> StoredMemberTypes(Type type) =>
        type.GetProperties(AllInstance)
            .Where(p => p.Name != EqualityContract)
            .Select(p => p.PropertyType)
            .Concat(type.GetFields(AllInstance).Select(f => f.FieldType));

    private static List<Assembly> ModuleAssemblies()
    {
        // Tests reference no module: the edge list stays the real dependency graph. Output
        // folders mirror this test's, so the solution build provides each assembly.
        var output = Path.GetRelativePath(
            Path.Combine(Root, "tests/Architecture"),
            AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

        return Directory.EnumerateDirectories(Path.Combine(Root, "src/Modules"))
            .Select(module => Path.Combine(module, output, $"Gatekeep.Modules.{Path.GetFileName(module)}.dll"))
            .Select(Assembly.LoadFrom)
            .ToList();
    }

    private static IEnumerable<string> MethodsMissingCommandContext(Type type) =>
        type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
            .Where(m => m.GetCustomAttribute<StateChangingAttribute>() is not null)
            .Where(m => m.GetParameters().All(p => p.ParameterType != typeof(CommandContext)))
            .Select(m => $"{type.Name}.{m.Name}");

    private static bool HasSessionSet(string source) =>
        SessionSet.IsMatch(UpdateSet.Replace(Comment.Replace(source, string.Empty), string.Empty));

    private static bool HasNonLocalSetConfig(string source) =>
        SetConfigCall.Matches(source).Any(match => !LastArgumentIsTrue(source, match.Index + match.Length));

    /// <summary>Reads to the call's closing parenthesis. <paramref name="start"/> follows the opening one.</summary>
    private static bool LastArgumentIsTrue(string source, int start)
    {
        var depth = 1;
        var lastComma = start;

        for (var i = start; i < source.Length; i++)
        {
            switch (source[i])
            {
                case '(':
                    depth++;
                    break;
                case ',' when depth == 1:
                    lastComma = i;
                    break;
                case ')' when --depth == 0:
                    return source[(lastComma + 1)..i].Trim().Equals("true", StringComparison.OrdinalIgnoreCase);
            }
        }

        return false;
    }

    private static IEnumerable<string> PersistenceSource() =>
        from directory in new[] { "src", "deploy" }
        from pattern in new[] { "*.cs", "*.sql" }
        from file in SourceFiles(Path.Combine(Root, directory), pattern)
        select file;

    private static IEnumerable<string> SourceFiles(string directory, string pattern)
    {
        var nested = Directory.EnumerateDirectories(directory)
            .Where(d => !SkippedDirectories.Contains(Path.GetFileName(d)))
            .SelectMany(d => SourceFiles(d, pattern));

        return Directory.EnumerateFiles(directory, pattern).Concat(nested);
    }

    private sealed class SampleContract
    {
        [StateChanging]
        public void Missing()
        {
        }

        [StateChanging]
        public void Present(CommandContext context)
        {
        }

        public void NotStateChanging()
        {
        }
    }
}
