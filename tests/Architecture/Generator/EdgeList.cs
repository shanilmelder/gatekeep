using System.Text;

namespace Gatekeep.Tests.Architecture;

internal sealed record Edge(string Kind, string From, string To);

/// <summary>Reads the edge list and renders the diagram from it.</summary>
internal static class EdgeList
{
    public const string ListPath = "tests/Architecture/module-edges.txt";
    public const string DiagramPath = "docs/architecture/module-dependencies.md";
    public const string RegenerateCommand = "dotnet run --project tests/Architecture/Generator";

    public const string Dependency = "dependency";
    public const string Composition = "composition";

    public static string FindRepositoryRoot(string start)
    {
        for (var directory = new DirectoryInfo(start); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Gatekeep.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException($"No Gatekeep.slnx at or above {start}.");
    }

    public static IReadOnlyList<Edge> Load(string root) =>
        Parse(File.ReadAllLines(Path.Combine(root, ListPath)));

    public static IReadOnlyList<Edge> Parse(IEnumerable<string> lines)
    {
        var edges = new List<Edge>();

        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            var parts = line.Split(' ');
            if (parts is not [Dependency or Composition, _, "->", _])
            {
                throw new FormatException($"Bad line in {ListPath}: '{line}'.");
            }

            var edge = new Edge(parts[0], parts[1], parts[3]);
            if (edges.Exists(e => e.From == edge.From && e.To == edge.To))
            {
                throw new FormatException($"Duplicate edge in {ListPath}: '{line}'.");
            }

            edges.Add(edge);
        }

        return edges;
    }

    public static string RenderDiagram(IReadOnlyList<Edge> edges)
    {
        var text = new StringBuilder();
        text.Append($"<!-- Generated from {ListPath}. Do not edit. Regenerate: {RegenerateCommand} -->\n\n");
        text.Append("# Module dependencies\n\n");
        text.Append("Every solid arrow is one allowed direct dependency. Every dashed arrow is a composition root ");
        text.Append("wiring a module's adapter registration. Transitive reach grants nothing. ");
        text.Append("Every module and host may also reference Kernel, not drawn.\n\n");
        text.Append("```mermaid\nflowchart TD\n");

        foreach (var name in edges.SelectMany(e => new[] { e.From, e.To }).Distinct())
        {
            text.Append($"  {NodeId(name)}[{name}]\n");
        }

        foreach (var edge in edges)
        {
            var arrow = edge.Kind == Composition ? "-.->" : "-->";
            text.Append($"  {NodeId(edge.From)} {arrow} {NodeId(edge.To)}\n");
        }

        text.Append("```\n");
        return text.ToString();
    }

    private static string NodeId(string name) => name.Replace(".", string.Empty);
}
