using Gatekeep.Kernel.Audit;

namespace Gatekeep.Host.Admin;

/// <summary>One published audit code as a Log shows it: its outcome and one-line summary.</summary>
internal sealed record LogCatalogueEntry(string Code, AuditOutcome Outcome, string Summary);

/// <summary>
/// Every published audit event by its code (Story 7.4). The table is generated into
/// <c>LogCatalogue.Generated.cs</c> from each module's <c>{Module}Events</c> catalogue, the same
/// members <c>docs/audit-events.md</c> is generated from, because Host.Admin may reference only
/// some modules (<c>tests/Architecture/module-edges.txt</c>). <c>AuditCatalogueTests</c> fails
/// when it is stale. A Log row's summary and outcome come from here, and an outcome search is a
/// search by the codes this gives that outcome.
/// </summary>
internal static partial class LogCatalogue
{
    // Lazy: the generated field is in another part of this class, and initializers across
    // partial files run in no defined order.
    private static readonly Lazy<IReadOnlyDictionary<string, LogCatalogueEntry>> Table =
        new(() => Generated.ToDictionary(e => e.Code, StringComparer.Ordinal));

    private static IReadOnlyDictionary<string, LogCatalogueEntry> ByCode => Table.Value;

    /// <summary>Every catalogued code, ordinally sorted.</summary>
    public static IReadOnlyList<string> Codes => [.. ByCode.Keys.Order(StringComparer.Ordinal)];

    /// <summary>The entry published for <paramref name="code"/>, or null for a code no catalogue declares.</summary>
    public static LogCatalogueEntry? Find(string code) => ByCode.GetValueOrDefault(code);

    /// <summary>The catalogued codes whose outcome is <paramref name="outcome"/>.</summary>
    public static IReadOnlyList<AuditTypeCode> CodesWith(AuditOutcome outcome) =>
        [.. Generated.Where(e => e.Outcome == outcome).Select(e => new AuditTypeCode(e.Code)).OrderBy(c => c.Value, StringComparer.Ordinal)];
}
