using Gatekeep.Tests.Architecture;

var root = EdgeList.FindRepositoryRoot(Directory.GetCurrentDirectory());
var diagramPath = Path.Combine(root, EdgeList.DiagramPath);

Directory.CreateDirectory(Path.GetDirectoryName(diagramPath)!);
File.WriteAllText(diagramPath, EdgeList.RenderDiagram(EdgeList.Load(root)));
Console.WriteLine($"Wrote {EdgeList.DiagramPath}");
