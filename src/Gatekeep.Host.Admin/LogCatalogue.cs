using System.Reflection;
using Gatekeep.Kernel.Audit;

namespace Gatekeep.Host.Admin;

/// <summary>
/// Every published audit event by its code (Story 7.4), composed here from each module's
/// <c>Gatekeep.Modules.{Module}.Contracts.{Module}Events</c> catalogue, the same members
/// <c>docs/audit-events.md</c> is generated from. Host.Admin references only some modules, so
/// it reads the catalogues of the module assemblies beside it, which its references bring into
/// its output. A Log row's summary and outcome come from here, and an outcome search is a search
/// by the codes this gives that outcome. Read once, on first use: the OpenAPI build never reads it.
/// </summary>
internal static class LogCatalogue
{
    private const string ModulePrefix = "Gatekeep.Modules.";

    private static readonly Lazy<IReadOnlyDictionary<string, AuditEventDefinition>> Definitions = new(Load);

    /// <summary>Every catalogued code, ordinally sorted.</summary>
    public static IReadOnlyList<string> Codes => [.. Definitions.Value.Keys.Order(StringComparer.Ordinal)];

    /// <summary>The definition published for <paramref name="code"/>, or null for a code no catalogue declares.</summary>
    public static AuditEventDefinition? Find(string code) => Definitions.Value.GetValueOrDefault(code);

    /// <summary>The catalogued codes whose outcome is <paramref name="outcome"/>.</summary>
    public static IReadOnlyList<AuditTypeCode> CodesWith(AuditOutcome outcome) =>
        [.. Definitions.Value.Values.Where(d => d.Outcome == outcome).Select(d => d.Code).OrderBy(c => c.Value, StringComparer.Ordinal)];

    private static IReadOnlyDictionary<string, AuditEventDefinition> Load()
    {
        var definitions = new Dictionary<string, AuditEventDefinition>(StringComparer.Ordinal);
        var files = Directory.EnumerateFiles(AppContext.BaseDirectory, ModulePrefix + "*.dll").Order(StringComparer.Ordinal);
        foreach (var file in files)
        {
            var name = Path.GetFileNameWithoutExtension(file);
            var module = name[ModulePrefix.Length..];
            if (module.Length == 0 || module.Contains('.'))
            {
                continue;
            }

            var catalogue = Assembly.Load(new AssemblyName(name)).GetType($"{name}.Contracts.{module}Events");
            if (catalogue is null)
            {
                continue;
            }

            foreach (var field in catalogue.GetFields(BindingFlags.Public | BindingFlags.Static)
                .Where(f => f.FieldType == typeof(AuditEventDefinition)))
            {
                var definition = (AuditEventDefinition)field.GetValue(null)!;
                if (!definitions.TryAdd(definition.Code.Value, definition))
                {
                    throw new InvalidOperationException($"Two catalogues declare {definition.Code.Value}.");
                }
            }
        }

        if (definitions.Count == 0)
        {
            throw new InvalidOperationException("No module audit catalogue was found beside Host.Admin.");
        }

        return definitions;
    }
}
