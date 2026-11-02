using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace Gatekeep.Tests.Architecture;

/// <summary>One published audit event, read from its module's catalogue.</summary>
internal sealed record CatalogueEvent(string Code, string Module, string Summary, string? TenantLogClass);

/// <summary>
/// One FR-40 Tenant Log class. <see cref="Name"/> is the Kernel <c>TenantLogClass</c> member.
/// <see cref="PendingStory"/> names the story that will add its event, while no catalogued code
/// proves it. A class whose story is done, or a class both pending and mapped, fails a test.
/// </summary>
internal sealed record LogClass(string Name, string Title, string? PendingStory);

/// <summary>
/// Reads every module's <c>{Module}Events</c> catalogue and renders <see cref="DocPath"/>. It
/// references no module, so it reads each catalogue by reflection from that module's own output
/// folder, as the solution build left it. The generator, the Architecture tests and the Isolation
/// tests share this file.
/// </summary>
internal static class AuditCatalogue
{
    public const string DocPath = "docs/audit-events.md";
    public const string RegenerateCommand = "dotnet run --project tests/Architecture/Generator";

    private const string DefinitionType = "Gatekeep.Kernel.Audit.AuditEventDefinition";
    private const string CodeType = "Gatekeep.Kernel.Audit.AuditTypeCode";

    /// <summary>
    /// The 11 FR-40 Tenant classes, in the Kernel enum's order. Every one is pending today: the
    /// epic order builds the flows that write them after Epic 7 (Story 7.8).
    /// </summary>
    public static readonly IReadOnlyList<LogClass> TenantLogClasses =
    [
        new("SignIn", "Sign-ins and failures", "4.9"),
        new("PasswordReset", "Password resets", "4.11"),
        new("EmailChange", "Email changes", "16.8"),
        new("Factor", "Factor events", "6.1"),
        new("RecoveryCode", "Recovery Code events", "6.8"),
        new("SessionRevocation", "Session and token revocation", null),
        new("AdminChange", "Admin changes", "8.2"),
        new("KeyOperation", "Key operations", "9.2"),
        new("ManagementApiGrant", "Management API grants", "17.2"),
        new("TokenFamilyRevocation", "Token Family revocations", "2.10"),
        new("CrossTenantRejection", "Rejected cross-Tenant attempts", "7.4"),
    ];

    private static readonly Regex DocCode = new(@"^\|\s*`(?<code>[^`]+)`\s*\|", RegexOptions.Multiline | RegexOptions.Compiled);

    /// <summary>The module folders under <c>src/Modules</c> that hold a catalogue file.</summary>
    public static IReadOnlyList<string> CatalogueModules(string root) =>
        [.. Directory.EnumerateDirectories(Path.Combine(root, "src", "Modules"))
            .Select(Path.GetFileName)
            .OfType<string>()
            .Where(module => File.Exists(Path.Combine(root, CatalogueFile(module))))
            .Order(StringComparer.Ordinal)];

    public static string CatalogueFile(string module) => $"src/Modules/{module}/Contracts/{module}Events.cs";

    /// <summary>
    /// Every catalogued event, sorted by code. <paramref name="project"/> is the calling project's
    /// folder, relative to <paramref name="root"/>: output folders mirror each other, so a module's
    /// assembly is found at the same relative path below its own folder.
    /// </summary>
    public static IReadOnlyList<CatalogueEvent> Load(string root, string project)
    {
        var events = new List<CatalogueEvent>();
        foreach (var module in CatalogueModules(root))
        {
            var typeName = $"Gatekeep.Modules.{module}.Contracts.{module}Events";
            var catalogue = ModuleAssembly(root, module, project).GetType(typeName)
                ?? throw new InvalidOperationException($"{CatalogueFile(module)} declares no public {typeName}.");

            // Only public static fields are read, so any other shape would drop from the document.
            var problems = MemberProblems(catalogue);
            if (problems.Count > 0)
            {
                throw new InvalidOperationException(string.Join(Environment.NewLine, problems));
            }

            var definitions = catalogue.GetFields(BindingFlags.Public | BindingFlags.Static)
                .Where(f => f.FieldType.FullName == DefinitionType)
                .Select(f => f.GetValue(null)!)
                .ToList();

            if (definitions.Count == 0)
            {
                throw new InvalidOperationException($"{typeName} declares no public static AuditEventDefinition field.");
            }

            events.AddRange(definitions.Select(d => Read(d, module)));
        }

        return [.. events.OrderBy(e => e.Code, StringComparer.Ordinal)];
    }

    /// <summary>
    /// Each member of <paramref name="catalogue"/> <see cref="Load"/> wouldn't read: one typed
    /// <c>AuditEventDefinition</c> that isn't a public static field (a property, a method, an instance
    /// member or a non-public field), and any member typed <c>AuditTypeCode</c>, which is a code with
    /// no definition.
    /// </summary>
    public static IReadOnlyList<string> MemberProblems(Type catalogue)
    {
        const BindingFlags All = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static
            | BindingFlags.Instance | BindingFlags.DeclaredOnly;

        static bool Catalogued(Type? type) => type?.FullName is DefinitionType or CodeType;

        return [.. catalogue.GetMembers(All)
            .Where(member => member switch
            {
                FieldInfo field => field.FieldType.FullName == CodeType
                    || (field.FieldType.FullName == DefinitionType && !(field.IsPublic && field.IsStatic)),
                PropertyInfo property => Catalogued(property.PropertyType),
                MethodInfo method => Catalogued(method.ReturnType) && !method.IsSpecialName,
                _ => false,
            })
            // A property's compiler-made backing field is reported as the property.
            .Where(member => !member.Name.Contains("k__BackingField", StringComparison.Ordinal))
            .Select(member => $"{catalogue.FullName}.{member.Name} isn't a public static AuditEventDefinition field, so the catalogue wouldn't read it.")];
    }

    /// <summary>
    /// The new document for <paramref name="events"/>, or the reasons it can't be written: a missing
    /// <paramref name="published"/> document, or a published code no catalogue declares any more.
    /// </summary>
    public static (string? Text, IReadOnlyList<string> Problems) Regenerate(string? published, IReadOnlyList<CatalogueEvent> events)
    {
        if (published is null)
        {
            return (null, [$"{DocPath} is missing, so the codes it published can't be checked. Restore it from git first."]);
        }

        var breaks = ContractBreaks(published, events);
        return breaks.Count > 0 ? (null, breaks) : (Render(events), []);
    }

    /// <summary>The codes a committed catalogue document publishes.</summary>
    public static IReadOnlyList<string> PublishedCodes(string document) =>
        [.. DocCode.Matches(document.ReplaceLineEndings("\n")).Select(m => m.Groups["code"].Value)];

    /// <summary>
    /// Each code <paramref name="document"/> publishes that no catalogue declares any more. A code
    /// is a public contract, so the generator refuses to drop one and a test fails on it.
    /// </summary>
    public static IReadOnlyList<string> ContractBreaks(string document, IEnumerable<CatalogueEvent> events)
    {
        var declared = events.Select(e => e.Code).ToHashSet(StringComparer.Ordinal);

        return [.. PublishedCodes(document)
            .Where(code => !declared.Contains(code))
            .Select(code => $"Contract break: {code} is published in {DocPath} but no catalogue declares it. A published code can't be removed or renamed.")];
    }

    public static string Render(IReadOnlyList<CatalogueEvent> events)
    {
        var titles = TenantLogClasses.ToDictionary(c => c.Name, c => c.Title, StringComparer.Ordinal);

        var text = new StringBuilder();
        text.Append($"<!-- Generated from each module's Contracts/{{Module}}Events.cs. Do not edit. Regenerate: {RegenerateCommand} -->\n\n");
        text.Append("# Audit event catalogue\n\n");
        text.Append("Every audit type code Gatekeep writes, declared in its module's contract. Codes are ");
        text.Append("`{domain}.{object}.{action}` and a public contract: removing or renaming a published code is a ");
        text.Append("contract break, which the generator refuses and `AuditCatalogueTests` fails on.\n\n");
        text.Append("| Code | Module | Summary | FR-40 class |\n");
        text.Append("| --- | --- | --- | --- |\n");

        foreach (var item in events.OrderBy(e => e.Code, StringComparer.Ordinal))
        {
            var logClass = item.TenantLogClass is { } name ? titles.GetValueOrDefault(name, name) : "None";
            text.Append($"| `{item.Code}` | {item.Module} | {item.Summary} | {logClass} |\n");
        }

        text.Append("\n## FR-40 Tenant Log classes\n\n");
        text.Append("Each class a Tenant's Log must cover, and the codes that prove it. A pending class names the ");
        text.Append("story that adds its event; `EventClassTests` fails once that story is done and the class is still pending.\n\n");
        text.Append("| Class | Codes | Status |\n");
        text.Append("| --- | --- | --- |\n");

        foreach (var logClass in TenantLogClasses)
        {
            var codes = events.Where(e => e.TenantLogClass == logClass.Name).Select(e => $"`{e.Code}`").ToList();
            var status = logClass.PendingStory is { } story ? $"Pending: Story {story}" : "Proved";
            text.Append($"| {logClass.Title} | {(codes.Count == 0 ? "None yet" : string.Join(", ", codes))} | {status} |\n");
        }

        return text.ToString();
    }

    /// <summary>
    /// The module's assembly: the one the caller already references, if it does, as a second copy
    /// of an assembly can't load beside it; otherwise the one in the module's own output folder.
    /// </summary>
    public static Assembly ModuleAssembly(string root, string module, string project)
    {
        var name = $"Gatekeep.Modules.{module}";
        try
        {
            return Assembly.Load(new AssemblyName(name));
        }
        catch (FileNotFoundException)
        {
            var output = Path.GetRelativePath(
                Path.Combine(root, project),
                AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            var path = Path.Combine(root, "src", "Modules", module, output, $"{name}.dll");
            if (!File.Exists(path))
            {
                throw new InvalidOperationException($"No {path}. Build the solution first: dotnet build Gatekeep.slnx");
            }

            return Assembly.LoadFrom(path);
        }
    }

    private static CatalogueEvent Read(object definition, string module)
    {
        object? Get(object target, string name) =>
            target.GetType().GetProperty(name)?.GetValue(target)
            ?? (name == "TenantLogClass" ? null : throw new InvalidOperationException($"AuditEventDefinition has no {name}."));

        var code = Get(Get(definition, "Code")!, "Value")!.ToString()!;
        var summary = (string)Get(definition, "Summary")!;
        var logClass = Get(definition, "TenantLogClass")?.ToString();

        return new CatalogueEvent(code, module, summary, logClass);
    }
}
