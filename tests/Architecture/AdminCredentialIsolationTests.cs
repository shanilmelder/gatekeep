using System.Collections;
using System.Reflection;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// Story 1.23, FR-46: a Tenant User's credential can't authenticate an Admin, because no table or
/// flow is shared. <c>gk_admin</c>, the role Admin sign-in runs as, holds no grant on any table
/// Identity, Authentication or Sessions owns, but Story 3.5's revocation columns on <c>token</c> and
/// <c>"authorization"</c> and Story 9.3's on <c>user_session</c>, which hold no credential; and neither Admins nor the Fido2 adapter reaches
/// those modules, directly or through another module, in the edge list the build enforces.
/// </summary>
public class AdminCredentialIsolationTests
{
    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] UserModules = ["Identity", "Authentication", "Sessions"];

    [Fact]
    public void Admin_role_holds_no_grant_on_any_User_module_table()
    {
        var tables = Tables().Where(t => UserModules.Contains((string)Get(t, "Owner")!)).ToList();

        // Today's: user, user_session, authorization, token and signin_transaction, and any added later.
        Assert.Superset(
            new HashSet<string>(["user", "user_session", "authorization", "token", "signin_transaction"]),
            tables.Select(t => (string)Get(t, "Name")!).ToHashSet());

        foreach (var table in tables)
        {
            var name = (string)Get(table, "Name")!;
            Assert.DoesNotContain("gk_admin", Roles(Get(table, "Grants")));

            // Story 3.5: an Application's deletion revokes its Token Families and tokens through the one revocation
            // path, in Host.Admin's transaction; Story 9.3: a Signing Key revocation may end every Session of its
            // Tenant the same way. Those are the only column grants gk_admin holds here: it reads the references the
            // revocation's WHERE names and sets a row's status or end, never a credential, subject or payload.
            if (RevocationGrants.TryGetValue(name, out var grants))
            {
                Assert.Equal(grants, ColumnGrants(Get(table, "ColumnGrants"), "gk_admin"));
            }
            else
            {
                Assert.DoesNotContain("gk_admin", Roles(Get(table, "ColumnGrants")));
            }
        }
    }

    /// <summary>
    /// gk_admin's column grants on each table the one revocation path writes as it (Stories 3.5 and 9.3), sorted:
    /// the columns its statements read, and the ones they set.
    /// </summary>
    private static readonly Dictionary<string, string[]> RevocationGrants = new(StringComparer.Ordinal)
    {
        ["authorization"] = ["SELECT application_id,id,status,tenant_id", "UPDATE concurrency_token,status"],
        ["token"] = ["SELECT application_id,authorization_id,status,tenant_id", "UPDATE concurrency_token,status"],
        ["user_session"] = ["SELECT ended_at,tenant_id", "UPDATE end_reason,ended_at"],
    };

    private static List<string> ColumnGrants(object? grants, string role) =>
        grants is IEnumerable entries
            ? [.. entries.Cast<object>()
                .Where(g => (string)Get(g, "Key")! == role)
                .SelectMany(g => ((IEnumerable)Get(g, "Value")!).Cast<object>())
                .Select(c => $"{Get(c, "Privilege")} {string.Join(",", ((IEnumerable<string>)Get(c, "Columns")!).Order(StringComparer.Ordinal))}")
                .Order(StringComparer.Ordinal)]
            : [];

    [Theory]
    [InlineData("Admins")]
    [InlineData("Adapters.Fido2")]
    public void Admins_and_the_WebAuthn_adapter_reach_no_User_module(string project)
    {
        Assert.Empty(Reached(project).Intersect(UserModules));
    }

    [Fact]
    public void Walk_finds_a_User_module_reached_through_another_module()
    {
        // Host.Hosted has no edge to Directory: it reaches it only through Protocol.
        Assert.DoesNotContain(EdgeList.Load(Root), e => e.From == "Host.Hosted" && e.To == "Directory");
        Assert.Contains("Directory", Reached("Host.Hosted"));
        Assert.Contains("Identity", Reached("Protocol"));
    }

    /// <summary>Every project <paramref name="project"/> reaches by its edges, directly or through others.</summary>
    private static HashSet<string> Reached(string project)
    {
        var edges = EdgeList.Load(Root);
        var reached = new HashSet<string>();
        var pending = new Queue<string>([project]);
        while (pending.TryDequeue(out var from))
        {
            foreach (var edge in edges.Where(e => e.From == from))
            {
                if (reached.Add(edge.To))
                {
                    pending.Enqueue(edge.To);
                }
            }
        }

        return reached;
    }

    private static IEnumerable<string> Roles(object? grants) =>
        grants is IEnumerable entries ? entries.Cast<object>().Select(g => (string)Get(g, "Key")!) : [];

    private static IEnumerable<object> Tables()
    {
        var output = Path.GetRelativePath(
            Path.Combine(Root, "tests/Architecture"),
            AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        var assembly = Assembly.LoadFrom(Path.Combine(Root, "src/Adapters/Postgres", output, "Gatekeep.Adapters.Postgres.dll"));
        var registry = assembly.GetType("Gatekeep.Adapters.Postgres.Schema.TableRegistry", throwOnError: true)!;
        return ((IEnumerable)registry.GetField("Tables")!.GetValue(null)!).Cast<object>();
    }

    private static object? Get(object target, string name) => target.GetType().GetProperty(name)!.GetValue(target);
}
