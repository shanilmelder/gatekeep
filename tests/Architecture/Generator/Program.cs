using Gatekeep.Tests.Architecture;

const string Project = "tests/Architecture/Generator";

var root = EdgeList.FindRepositoryRoot(Directory.GetCurrentDirectory());
var diagramPath = Path.Combine(root, EdgeList.DiagramPath);

Directory.CreateDirectory(Path.GetDirectoryName(diagramPath)!);
File.WriteAllText(diagramPath, EdgeList.RenderDiagram(EdgeList.Load(root)));
Console.WriteLine($"Wrote {EdgeList.DiagramPath}");

// The catalogue reads each module's build output, so the solution must be built first.
var cataloguePath = Path.Combine(root, AuditCatalogue.DocPath);
var published = File.Exists(cataloguePath) ? File.ReadAllText(cataloguePath) : null;

// A published code is a public contract: regenerating must not hide its removal.
var (text, problems) = AuditCatalogue.Regenerate(published, AuditCatalogue.Load(root, Project));
if (text is null)
{
    foreach (var problem in problems)
    {
        Console.Error.WriteLine(problem);
    }

    Console.Error.WriteLine($"Left {AuditCatalogue.DocPath} unchanged.");
    return 1;
}

File.WriteAllText(cataloguePath, text);
Console.WriteLine($"Wrote {AuditCatalogue.DocPath}");
return 0;
