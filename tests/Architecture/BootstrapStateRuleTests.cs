using System.Collections;
using System.Reflection;
using System.Text.RegularExpressions;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// Story 1.19: <c>bootstrap_state</c> in the AD-3 registry with its column grants and trigger, no
/// code that deletes or drops it or completes bootstrap, which is Story 1.21's, a token file
/// created owner-only and never widened, and an issuer whose times come only from the database.
/// Tests reference no adapter, so the registry is read by reflection from the Postgres adapter's
/// own output folder.
/// </summary>
public class BootstrapStateRuleTests
{
    private const string Table = "bootstrap_state";
    private const string TokenFile = "src/Gatekeep.Cli/BootstrapTokenFile.cs";
    private const string Issuer = "src/Modules/Admins/Core/BootstrapIssuer.cs";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] SkippedDirectories = ["bin", "obj", "node_modules", "secrets"];

    private static readonly string[] Patterns = ["*.cs", "*.sql", "*.sh", "*.hcl"];

    // The table, with an optional schema and quotes on either part.
    private const string Name = @"(?:""?\w+""?\s*\.\s*)?""?bootstrap_state""?\b";

    private static readonly Regex Removes = new(
        $@"\bDELETE\s+FROM\s+(?:ONLY\s+)?{Name}|\bTRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?(?:\w+\s*,\s*)*{Name}|\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:\w+\s*,\s*)*{Name}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // An assignment, quoted or qualified, or the parenthesised SET (a, completed_at) = (…) form.
    private static readonly Regex Completes = new(
        @"(?:\b|"")completed_at""?\s*=(?!=)|\bSET\s*\([^)]*\bcompleted_at\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    [Fact]
    public void Registry_lists_bootstrap_state_as_an_Admins_control_table_with_its_trigger()
    {
        var entry = Entry();

        Assert.Equal("Control", Get(entry, "Class")!.ToString());
        Assert.Equal("Admins", Get(entry, "Owner"));
        Assert.False((bool)Get(entry, "Unlogged")!);
        Assert.Equal(["bootstrap_state_guard_update"], (IEnumerable<string>)Get(entry, "Triggers")!);
    }

    [Fact]
    public void Cli_issues_and_Admin_completes_through_column_grants_and_neither_deletes()
    {
        var entry = Entry();
        var grants = ((IEnumerable)Get(entry, "Grants")!)
            .Cast<object>()
            .ToDictionary(
                g => (string)Get(g, "Key")!,
                g => ((IEnumerable<string>)Get(g, "Value")!).Order(StringComparer.Ordinal).ToList());

        Assert.Equal(["gk_admin", "gk_cli"], grants.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(["SELECT"], grants["gk_admin"]);
        Assert.Equal(["SELECT"], grants["gk_cli"]);

        var columns = ((IEnumerable)Get(entry, "ColumnGrants")!)
            .Cast<object>()
            .SelectMany(g => ((IEnumerable)Get(g, "Value")!).Cast<object>().Select(c =>
                $"{Get(g, "Key")} {Get(c, "Privilege")} {string.Join(",", ((IEnumerable<string>)Get(c, "Columns")!).Order(StringComparer.Ordinal))}"))
            .Order(StringComparer.Ordinal);

        Assert.Equal(
            [
                "gk_admin UPDATE completed_at",
                "gk_cli INSERT expires_at,id,issued_at,token_sha256",
                "gk_cli UPDATE expires_at,issued_at,token_sha256",
            ],
            columns);
    }

    [Fact]
    public void No_source_deletes_drops_or_completes_bootstrap_state()
    {
        var offenders = new[] { "src", "deploy" }
            .SelectMany(d => SourceFiles(Path.Combine(Root, d)))
            .Where(f => Mentions(File.ReadAllText(f)))
            .Select(f => Path.GetRelativePath(Root, f).Replace('\\', '/'));

        Assert.Empty(offenders);
    }

    [Theory]
    [InlineData("DELETE FROM bootstrap_state", true)]
    [InlineData("delete from \"bootstrap_state\" where id = 1", true)]
    [InlineData("DELETE FROM public.bootstrap_state", true)]
    [InlineData("DELETE FROM \"public\".\"bootstrap_state\"", true)]
    [InlineData("DELETE FROM ONLY public . bootstrap_state", true)]
    [InlineData("TRUNCATE bootstrap_state", true)]
    [InlineData("TRUNCATE TABLE ONLY bootstrap_state", true)]
    [InlineData("TRUNCATE admin_attempt, bootstrap_state", true)]
    [InlineData("truncate public.\"bootstrap_state\"", true)]
    [InlineData("DROP TABLE bootstrap_state", true)]
    [InlineData("DROP TABLE IF EXISTS public.bootstrap_state", true)]
    [InlineData("DROP TABLE job, bootstrap_state", true)]
    [InlineData("UPDATE bootstrap_state SET completed_at = now()", true)]
    [InlineData("UPDATE bootstrap_state SET completed_at=now()", true)]
    [InlineData("UPDATE bootstrap_state SET \"completed_at\" = now()", true)]
    [InlineData("UPDATE bootstrap_state b SET b.completed_at = now()", true)]
    [InlineData("UPDATE bootstrap_state SET (completed_at) = ROW (now())", true)]
    [InlineData("UPDATE bootstrap_state SET (expires_at, completed_at) = (now(), now())", true)]
    [InlineData("SELECT completed_at IS NOT NULL FROM bootstrap_state WHERE id = 1", false)]
    [InlineData("WHERE bootstrap_state.completed_at IS NULL", false)]
    [InlineData("GRANT UPDATE (completed_at) ON bootstrap_state TO gk_admin;", false)]
    [InlineData("IF OLD.completed_at IS NOT NULL AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN", false)]
    [InlineData("DELETE FROM admin_attempt", false)]
    [InlineData("DROP TABLE bootstrap_state_history", false)]
    public void Delete_drop_and_completion_detection(string source, bool expected)
    {
        Assert.Equal(expected, Mentions(source));
    }

    [Fact]
    public void Token_file_is_created_new_and_owner_only_and_never_has_its_mode_changed()
    {
        var source = File.ReadAllText(Path.Combine(Root, TokenFile));

        Assert.Contains("Mode = FileMode.CreateNew,", source);
        Assert.Contains("options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;", source);
        Assert.Single(Regex.Matches(source, @"\bUnixCreateMode\b"));
        Assert.DoesNotContain("SetUnixFileMode", source);
        Assert.DoesNotMatch(@"FileMode\.(?:Create|OpenOrCreate|Truncate|Append)\b(?!New)", source);
    }

    [Fact]
    public void Issuer_takes_its_times_from_clock_timestamp_and_sends_only_the_hash()
    {
        var source = File.ReadAllText(Path.Combine(Root, Issuer));

        Assert.Contains("SELECT clock_timestamp() AS t", source);
        Assert.DoesNotMatch(@"\bnow\s*\(", source);
        Assert.DoesNotMatch(@"\bDateTime(?:Offset)?\s*\.\s*(?:Now|UtcNow)\b|TimeProvider", source);
        Assert.Equal(
            ["hash"],
            Regex.Matches(source, @"ParameterName\s*=\s*""(?<name>[^""]+)""").Select(m => m.Groups["name"].Value));
    }

    /// <summary>A completion names the column with an assignment; a delete, truncate or drop names the table.</summary>
    private static bool Mentions(string source) => Removes.IsMatch(source) || Completes.IsMatch(source);

    private static object Entry()
    {
        var output = Path.GetRelativePath(
            Path.Combine(Root, "tests/Architecture"),
            AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        var assembly = Assembly.LoadFrom(Path.Combine(Root, "src/Adapters/Postgres", output, "Gatekeep.Adapters.Postgres.dll"));
        var registry = assembly.GetType("Gatekeep.Adapters.Postgres.Schema.TableRegistry", throwOnError: true)!;
        var tables = (IEnumerable)registry.GetField("Tables")!.GetValue(null)!;

        return Assert.Single(tables.Cast<object>(), t => (string)Get(t, "Name")! == Table);
    }

    private static object? Get(object target, string name) => target.GetType().GetProperty(name)!.GetValue(target);

    private static IEnumerable<string> SourceFiles(string directory)
    {
        var nested = Directory.EnumerateDirectories(directory)
            .Where(d => !SkippedDirectories.Contains(Path.GetFileName(d)))
            .SelectMany(SourceFiles);

        return Patterns.SelectMany(p => Directory.EnumerateFiles(directory, p)).Concat(nested);
    }
}
