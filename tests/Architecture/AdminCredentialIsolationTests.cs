using System.Collections;
using System.Reflection;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// Story 1.23, FR-46: a Tenant User's credential can't authenticate an Admin, because no table or
/// flow is shared. <c>gk_admin</c>, the role Admin sign-in runs as, holds no grant on any table
/// Identity, Authentication or Sessions owns; and neither Admins nor the Fido2 adapter reaches
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
            var roles = Roles(Get(table, "Grants")).Concat(Roles(Get(table, "ColumnGrants")));
            Assert.DoesNotContain("gk_admin", roles);
        }
    }

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
