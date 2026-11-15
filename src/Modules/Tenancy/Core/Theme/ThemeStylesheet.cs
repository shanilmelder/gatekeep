using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Gatekeep.Modules.Tenancy.Contracts;

namespace Gatekeep.Modules.Tenancy.Core.Theme;

/// <summary>
/// A Tenant's Hosted Login theme stylesheet (AD-21, AD-22, Story 4.1): its <c>--gk-*</c> colour tokens
/// under <c>[data-gk-theme]</c>, for light, for dark under <c>prefers-color-scheme</c> with
/// <c>data-gk-scheme="auto"</c>, and for a forced <c>data-gk-scheme</c> of light or dark. Every selector
/// is one attribute more specific than the bundle's tokens.css, so the theme wins whatever order the
/// stylesheets load in. Every Tenant has the default tokens until Epic 15 adds per-Tenant overrides.
/// </summary>
internal static class ThemeStylesheet
{
    /// <summary>The hex characters of the content's SHA-256 its URL carries.</summary>
    public const int HashLength = 16;

    /// <summary>
    /// Every scheme token, read from the generated <see cref="DesignTokens.Light"/> and
    /// <see cref="DesignTokens.Dark"/>, so a token the generator adds is in the theme too: each
    /// constant's name in kebab case as <c>--gk-color-*</c>, and the shadow as <c>--gk-elevation-sh</c>.
    /// </summary>
    internal static readonly IReadOnlyList<(string Name, string Light, string Dark)> Colours = SchemeTokens();

    private static (string Name, string Light, string Dark)[] SchemeTokens()
    {
        static Dictionary<string, string> Read(Type scheme) =>
            scheme.GetFields(BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static)
                .Where(static f => f.IsLiteral && f.FieldType == typeof(string))
                .ToDictionary(static f => f.Name, static f => (string)f.GetRawConstantValue()!, StringComparer.Ordinal);

        var light = Read(typeof(DesignTokens.Light));
        var dark = Read(typeof(DesignTokens.Dark));
        if (light.Count == 0 || !light.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(dark.Keys))
        {
            throw new InvalidOperationException("The generated light and dark schemes must hold the same tokens.");
        }

        return
        [
            .. light.Keys.Order(StringComparer.Ordinal)
                .Select(name => (Property(name), light[name], dark[name])),
        ];
    }

    /// <summary><c>AcSf</c> as <c>color-ac-sf</c>; the shadow, <c>Sh</c>, as <c>elevation-sh</c>.</summary>
    private static string Property(string constant)
    {
        if (constant == nameof(DesignTokens.Light.Sh))
        {
            return "elevation-sh";
        }

        var kebab = new StringBuilder("color-");
        for (var i = 0; i < constant.Length; i++)
        {
            if (char.IsUpper(constant[i]) && i > 0)
            {
                kebab.Append('-');
            }

            kebab.Append(char.ToLowerInvariant(constant[i]));
        }

        return kebab.ToString();
    }

    // Every Tenant's is the default theme for now, so it is built once.
    private static readonly Lazy<TenantTheme> Default = new(() => Build(Generate()));

    /// <summary>The theme of <paramref name="tenant"/>: the default tokens until Epic 15.</summary>
    public static TenantTheme For(ResolvedTenant tenant)
    {
        ArgumentNullException.ThrowIfNull(tenant);
        return Default.Value;
    }

    private static TenantTheme Build(string css)
    {
        var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(css)))[..HashLength];
        return new TenantTheme(css, hash);
    }

    private static string Generate()
    {
        var css = new StringBuilder();
        css.Append("/* Hosted Login theme: the Tenant's design tokens (AD-21, AD-22). */\n");
        Rule(css, "", "[data-gk-theme][data-gk-theme],\n[data-gk-theme] [data-gk-scheme],\n[data-gk-theme][data-gk-scheme=\"light\"],\n[data-gk-theme] [data-gk-scheme=\"light\"]", "light", static c => c.Light);
        Rule(css, "", "[data-gk-theme][data-gk-scheme=\"dark\"],\n[data-gk-theme] [data-gk-scheme=\"dark\"]", "dark", static c => c.Dark);
        css.Append("@media (prefers-color-scheme: dark) {\n");
        Rule(css, "  ", "[data-gk-theme][data-gk-scheme=\"auto\"],\n  [data-gk-theme] [data-gk-scheme=\"auto\"]", "dark", static c => c.Dark);
        css.Append("}\n");
        return css.ToString();
    }

    private static void Rule(StringBuilder css, string indent, string selectors, string scheme, Func<(string Name, string Light, string Dark), string> value)
    {
        css.Append(indent).Append(selectors).Append(" {\n");
        css.Append(indent).Append("  color-scheme: ").Append(scheme).Append(";\n");
        foreach (var colour in Colours)
        {
            css.Append(indent).Append("  --gk-").Append(colour.Name).Append(": ").Append(value(colour)).Append(";\n");
        }

        css.Append(indent).Append("}\n");
    }
}
