using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;

namespace Gatekeep.Adapters.Hosting;

/// <summary>
/// A Hosted Login step page (AD-21, Story 4.1): the built bundle's <c>index.html</c>, read from the web
/// root and checked once at startup (<see cref="TryLoad"/>), with three server-side additions and nothing else. Its <c>&lt;html&gt;</c> tag becomes
/// <see cref="HtmlTag"/>; <see cref="HeadMarker"/> becomes a link to the Tenant's theme stylesheet,
/// inside <c>head</c>; <see cref="StepMarker"/> becomes the step as a JSON data block, which the
/// client reads and renders with no fetch. The page carries no other inline script, no style and no
/// <c>data:</c> URL, so the exact AD-21 policy holds, and every step response is <c>no-store</c>.
/// </summary>
public sealed partial class StepPageTemplate
{
    /// <summary>The comment in <c>head</c> the theme stylesheet link replaces.</summary>
    public const string HeadMarker = "<!--gk-head-->";

    /// <summary>The comment in <c>body</c> the step's JSON data block replaces.</summary>
    public const string StepMarker = "<!--gk-step-->";

    /// <summary>The <c>id</c> of the step's JSON data block.</summary>
    public const string StepElementId = "gk-step";

    /// <summary>Every step page's <c>&lt;html&gt;</c> tag: English, the Hosted surface, following the device's scheme.</summary>
    public const string HtmlTag = """<html lang="en" data-gk-surface="hosted" data-gk-scheme="auto">""";

    /// <summary>The bundle's page, relative to the web root.</summary>
    public const string IndexFile = "index.html";

    /// <summary>The setting a host without a valid bundle refuses to start on: ASP.NET Core's web root.</summary>
    public const string WebRootSetting = "webroot";

    private readonly string _template;

    private StepPageTemplate(string template) => _template = template;

    /// <summary>
    /// Reads and checks the bundle's <c>index.html</c> in <paramref name="webRoot"/> once, at startup: it
    /// must exist, hold both markers once, the head marker inside <c>head</c>, and an <c>html</c> tag, and
    /// the web root must hold the <c>assets</c> folder. Null otherwise, so the host refuses to start
    /// (<see cref="WebRootSetting"/>) rather than answer its first step with a 500.
    /// </summary>
    public static StepPageTemplate? TryLoad(string? webRoot)
    {
        if (string.IsNullOrEmpty(webRoot) || !Directory.Exists(Path.Combine(webRoot, "assets")))
        {
            return null;
        }

        try
        {
            return new StepPageTemplate(Prepare(File.ReadAllText(Path.Combine(webRoot, IndexFile), Encoding.UTF8)));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>
    /// The page for one step: the theme link at <paramref name="themeHref"/>, a same-origin path, and the
    /// step's JSON, <paramref name="stepJson"/>, made HTML-safe by <see cref="EscapeForScript"/>.
    /// </summary>
    public string Render(string themeHref, string stepJson)
    {
        ArgumentException.ThrowIfNullOrEmpty(themeHref);
        ArgumentException.ThrowIfNullOrEmpty(stepJson);
        if (!themeHref.StartsWith('/') || themeHref.StartsWith("//", StringComparison.Ordinal) || themeHref.IndexOfAny(['"', '<', '>', '&', '\'']) >= 0)
        {
            throw new ArgumentException("The theme stylesheet must be a plain same-origin path.", nameof(themeHref));
        }

        var link = $"""<link rel="stylesheet" href="{themeHref}">""";
        var data = $"""<script type="application/json" id="{StepElementId}">{EscapeForScript(stepJson)}</script>""";
        return _template.Replace(HeadMarker, link, StringComparison.Ordinal).Replace(StepMarker, data, StringComparison.Ordinal);
    }

    /// <summary>
    /// Writes the page for one step with <paramref name="statusCode"/>: <c>text/html; charset=utf-8</c>,
    /// <c>no-store</c> and the AD-21 headers.
    /// </summary>
    public async Task WriteAsync(HttpContext context, int statusCode, string themeHref, string stepJson, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var page = Encoding.UTF8.GetBytes(Render(themeHref, stepJson));

        var response = context.Response;
        response.StatusCode = statusCode;
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";
        SecurityHeaders.Apply(response.Headers);
        response.ContentType = "text/html; charset=utf-8";
        response.ContentLength = page.Length;
        await response.Body.WriteAsync(page, cancellationToken);
    }

    /// <summary>
    /// Writes one step as Hosted Login's API answers it (Story 4.2), with <paramref name="statusCode"/>:
    /// <paramref name="stepJson"/> as <c>application/json; charset=utf-8</c>, <c>no-store</c> and the AD-21 headers.
    /// </summary>
    public static async Task WriteJsonAsync(HttpContext context, int statusCode, string stepJson, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(stepJson);
        var body = Encoding.UTF8.GetBytes(stepJson);

        var response = context.Response;
        response.StatusCode = statusCode;
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";
        SecurityHeaders.Apply(response.Headers);
        response.ContentType = "application/json; charset=utf-8";
        response.ContentLength = body.Length;
        await response.Body.WriteAsync(body, cancellationToken);
    }

    /// <summary>
    /// JSON made safe inside a <c>script</c> element: <c>&lt;</c>, <c>&gt;</c>, <c>&amp;</c>, U+2028 and
    /// U+2029 become <c>\uXXXX</c> escapes, so no value, a Tenant's name included, can close the block or
    /// open a comment in it. In valid JSON they occur only inside strings, where the escape means the same.
    /// </summary>
    public static string EscapeForScript(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        var escaped = new StringBuilder(json.Length);
        foreach (var character in json)
        {
            if (character is '<' or '>' or '&' or '\u2028' or '\u2029')
            {
                escaped.Append("\\u").Append(((int)character).ToString("x4", CultureInfo.InvariantCulture));
            }
            else
            {
                escaped.Append(character);
            }
        }

        return escaped.ToString();
    }

    private static string Prepare(string index)
    {
        if (CountOf(index, HeadMarker) != 1 || CountOf(index, StepMarker) != 1)
        {
            throw new InvalidOperationException($"The Hosted Login index.html must hold {HeadMarker} and {StepMarker} once each.");
        }

        var head = index.IndexOf("</head>", StringComparison.OrdinalIgnoreCase);
        if (head < 0 || index.IndexOf(HeadMarker, StringComparison.Ordinal) > head)
        {
            throw new InvalidOperationException($"The Hosted Login index.html must hold {HeadMarker} inside head.");
        }

        var html = HtmlOpening().Match(index);
        if (!html.Success)
        {
            throw new InvalidOperationException("The Hosted Login index.html has no html tag.");
        }

        return string.Concat(index.AsSpan(0, html.Index), HtmlTag, index.AsSpan(html.Index + html.Length));
    }

    private static int CountOf(string text, string value)
    {
        var count = 0;
        for (var at = text.IndexOf(value, StringComparison.Ordinal); at >= 0; at = text.IndexOf(value, at + value.Length, StringComparison.Ordinal))
        {
            count++;
        }

        return count;
    }

    [GeneratedRegex("<html(?:\\s[^>]*)?>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HtmlOpening();
}
