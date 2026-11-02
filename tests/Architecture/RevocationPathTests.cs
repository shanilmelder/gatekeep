using System.Text.RegularExpressions;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// AD-13 and AR-23: <c>ISessions.RevokeAccessAsync</c> is the one revocation path. Production
/// SQL is hand-written text. A source other than the Sessions revocation file fails when it names
/// OpenIddict's revoked status (<c>Statuses.Revoked</c>), or when it updates <c>user_session</c>,
/// <c>authorization</c> or <c>token</c> and also holds a revoked value (a <c>'revoked'</c> SQL
/// literal, a <c>"revoked"</c> C# string or an <c>@revoked</c> parameter) or sets
/// <c>ended_at</c> or <c>end_reason</c>. Reads of those columns, and other tables' own
/// <c>'revoked'</c> states such as a Signing Key's, are allowed.
/// </summary>
public class RevocationPathTests
{
    private const string RevocationFile = "src/Modules/Sessions/Core/SessionRevocation.cs";

    /// <summary>The spike's <c>SpikeTokenStore.RevokeFamilyAsync</c>, exactly: a bound revoked status.</summary>
    private const string SpikeTokenStoreForm =
        """"
        await SpikeSql.ExecuteAsync(
            context,
            """
            UPDATE spike_token SET status = @revoked, concurrency_token = gen_random_uuid()
            WHERE authorization_id = @authorization_id AND status <> @revoked
            """,
            cancellationToken,
            ("revoked", Statuses.Revoked),
            ("authorization_id", authorizationId));
        """";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] SkippedDirectories = ["bin", "obj", "node_modules"];

    private static readonly string[] Patterns = ["*.cs", "*.sql"];

    private static readonly Regex OpenIddictRevoked = new(@"\bStatuses\s*\.\s*Revoked\b", RegexOptions.Compiled);

    /// <summary>An UPDATE of a Sessions revocation table, with the reserved name quoted, escaped or doubled.</summary>
    private static readonly Regex UpdatesRevocationTable = new(
        @"\bUPDATE\s+(?:ONLY\s+)?(?:public\.)?(?:user_session\b|token\b|[\\""]+authorization[\\""]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex RevokedValue = new(
        @"'revoked'|""revoked""|@revoked\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>A SET clause, up to its WHERE, FROM, RETURNING or statement end, naming either column.</summary>
    private static readonly Regex SetsEndColumn = new(
        @"\bSET\b(?:(?!\b(?:WHERE|FROM|RETURNING)\b|;).)*?\b(?:ended_at|end_reason)\b",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    [Fact]
    public void Only_the_Sessions_revocation_file_ends_a_Session_or_revokes_a_family_or_token()
    {
        var offenders = SourceFiles(Path.Combine(Root, "src"))
            .Where(f => Relative(f) != RevocationFile)
            .Where(f => Revokes(File.ReadAllText(f)))
            .Select(Relative);

        Assert.Empty(offenders);
    }

    [Fact]
    public void Scan_finds_both_patterns_in_the_revocation_file()
    {
        var path = Path.Combine(Root, RevocationFile);
        Assert.True(File.Exists(path), $"{RevocationFile} is missing, so the scan would pass vacuously.");

        var source = File.ReadAllText(path);

        Assert.Matches(UpdatesRevocationTable, source);
        Assert.Matches(RevokedValue, source);
        Assert.Matches(SetsEndColumn, source);
        Assert.True(Revokes(source));
        Assert.Contains(RevocationFile, SourceFiles(Path.Combine(Root, "src")).Select(Relative));
    }

    [Theory]
    [InlineData("UPDATE user_session SET ended_at = now(), end_reason = 'logout'", true)]
    [InlineData("UPDATE user_session SET end_reason='logout'", true)]
    [InlineData("UPDATE user_session SET \"ended_at\" = now()", true)]
    [InlineData("UPDATE user_session SET (ended_at, end_reason) = (now(), 'logout') WHERE id = @id", true)]
    [InlineData("UPDATE \"authorization\" SET status = 'revoked'", true)]
    [InlineData("UPDATE \\\"authorization\\\" SET status = @revoked", true)]
    [InlineData("UPDATE \"\"authorization\"\" SET status = @revoked", true)]
    [InlineData("UPDATE token SET status = 'REVOKED' WHERE id = @id", true)]
    [InlineData("UPDATE token SET status = @status\", (\"status\", \"revoked\")", true)]
    [InlineData(SpikeTokenStoreForm, true)]
    [InlineData("var status = Statuses.Revoked;", true)]
    [InlineData("CHECK ((ended_at IS NULL) = (end_reason IS NULL))", false)]
    [InlineData("ended_at timestamptz NULL, end_reason text NULL", false)]
    [InlineData("CHECK (end_reason IN ('logout', 'token_reuse'))", false)]
    [InlineData("SELECT id FROM user_session WHERE ended_at IS NULL", false)]
    [InlineData("SELECT id FROM user_session WHERE end_reason = @r", false)]
    [InlineData("UPDATE user_session SET idle_expires_at = @at WHERE ended_at IS NULL", false)]
    [InlineData("UPDATE token SET status = 'redeemed'", false)]
    [InlineData("UPDATE signing_key SET state = 'revoked'", false)]
    public void Revocation_detection(string source, bool expected)
    {
        Assert.Equal(expected, Revokes(source));
    }

    private static bool Revokes(string source) =>
        OpenIddictRevoked.IsMatch(source)
        || (UpdatesRevocationTable.IsMatch(source) && (RevokedValue.IsMatch(source) || SetsEndColumn.IsMatch(source)));

    private static string Relative(string path) => Path.GetRelativePath(Root, path).Replace('\\', '/');

    private static IEnumerable<string> SourceFiles(string directory)
    {
        var nested = Directory.EnumerateDirectories(directory)
            .Where(d => !SkippedDirectories.Contains(Path.GetFileName(d)))
            .SelectMany(SourceFiles);

        return Patterns.SelectMany(p => Directory.EnumerateFiles(directory, p)).Concat(nested);
    }
}
