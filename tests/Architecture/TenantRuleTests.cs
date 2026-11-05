using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// Story 1.27 (FR-7, AD-6): a Tenant Subdomain is taken by one request only and never changed; no
/// code but Tenancy reads <c>tenant_host</c>; Host.Hosted resolves its Tenant first, from the host
/// alone, never from a forwarded header; and only <c>TenantAddress</c> builds an issuer. Story 1.28
/// (FR-9, AD-19): only the request checks name <c>X-Gatekeep-Tenant</c> and never parse it, every
/// Tenant-path write documents it and its 409, and only the label route and Create Tenant take a
/// label. Each rule
/// has a self-check that a violation is caught. Tests reference no module, so sources are read as
/// text and the API as the committed OpenAPI document.
/// </summary>
public class TenantRuleTests
{
    private const string Document = "docs/api/openapi-v1.json";
    private const string HostedProgram = "src/Gatekeep.Host.Hosted/Program.cs";
    private const string CreatePath = "/api/v1/deployment/tenants";
    private const string AddressFile = "src/Modules/Tenancy/Contracts/TenantAddress.cs";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] Writes = ["post", "put", "patch", "delete"];

    /// <summary>
    /// The reviewed writes under the Deployment Tenants path: creation (Story 1.27), and a deletion's
    /// start and retry (Story 1.29). A Tenant is never changed there, and a delete or patch is reported.
    /// </summary>
    private static readonly string[] ReviewedWrites =
    [
        "post /api/v1/deployment/tenants",
        "post /api/v1/deployment/tenants/{targetTenantId}/deletion",
        "post /api/v1/deployment/tenants/{targetTenantId}/deletion/retry",
    ];

    /// <summary>Where <c>tenant_host</c> may appear: Tenancy, and the schema it lives in.</summary>
    private static readonly string[] TenantHostOwners = ["src/Modules/Tenancy/", "src/Adapters/Postgres/"];

    private static readonly Regex ForwardedHost = new(
        @"X-Forwarded-Host|XForwardedHost|X-Original-Host|XOriginalHost|""Forwarded""|HeaderNames\.Forwarded\b|ForwardedHeaders\.All",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex IssuerLiteral = new(@"\$?@?""https://", RegexOptions.Compiled);

    [Fact]
    public void Only_the_create_request_takes_a_subdomain()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, Document)));

        Assert.Contains(SubdomainTakers(document), t => t == $"post {CreatePath}");
        Assert.Empty(SubdomainViolations(document));
    }

    [Fact]
    public void A_second_subdomain_taker_is_reported()
    {
        using var document = JsonDocument.Parse(
            """
            {
              "paths": {
                "/api/v1/deployment/tenants": { "post": { "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CreateTenantRequest" } } } } } },
                "/api/v1/tenants/{tenantId}/host": { "patch": { "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/HostChange" } } } } } },
                "/api/v1/tenants/{tenantId}/rename": { "post": { "parameters": [ { "name": "subdomain", "in": "query" } ] } }
              },
              "components": { "schemas": {
                "CreateTenantRequest": { "properties": { "subdomain": { "type": "string" } } },
                "HostChange": { "properties": { "Subdomain": { "type": "string" } } }
              } }
            }
            """);

        Assert.Equal(
            [
                "HostChange has a subdomain property: only CreateTenantRequest may.",
                "patch /api/v1/tenants/{tenantId}/host takes a subdomain: only post /api/v1/deployment/tenants may.",
                "post /api/v1/tenants/{tenantId}/rename takes a subdomain: only post /api/v1/deployment/tenants may.",
            ],
            SubdomainViolations(document));
    }

    [Fact]
    public void No_Tenant_is_changed_or_deleted_under_the_Deployment_Tenants_path()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, Document)));

        Assert.Equal(ReviewedWrites.Order(StringComparer.Ordinal), Operations(document)
            .Where(o => IsUnderTenantsPath(o.Path) && Writes.Contains(o.Method))
            .Select(o => $"{o.Method} {o.Path}")
            .Order(StringComparer.Ordinal));
        Assert.Empty(WriteViolations(document));
    }

    [Fact]
    public void A_write_under_the_Tenants_path_is_reported()
    {
        using var document = JsonDocument.Parse(
            """
            { "paths": {
                "/api/v1/deployment/tenants": { "get": {}, "post": {} },
                "/api/v1/deployment/tenants/{targetTenantId}/deletion": { "post": {}, "get": {}, "delete": {} },
                "/api/v1/deployment/tenants/{id}": { "delete": {}, "patch": {} },
                "/api/v1/deployment/tenants/{id}/rename": { "post": {} },
                "/api/v1/deployment/tenantsx": { "put": {} }
            } }
            """);

        Assert.Equal(
            [
                "delete /api/v1/deployment/tenants/{id}",
                "delete /api/v1/deployment/tenants/{targetTenantId}/deletion",
                "patch /api/v1/deployment/tenants/{id}",
                "post /api/v1/deployment/tenants/{id}/rename",
            ],
            WriteViolations(document));
    }

    /// <summary>Story 1.29: only the delete body carries a typed confirmation.</summary>
    [Fact]
    public void Only_the_delete_request_has_a_confirmation()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, Document)));

        Assert.True(HasProperty(document.RootElement.GetProperty("components").GetProperty("schemas").GetProperty(DeleteRequest), "confirmation"));
        Assert.Empty(ConfirmationViolations(document));
    }

    [Fact]
    public void A_second_confirmation_is_reported()
    {
        using var document = JsonDocument.Parse(
            """
            { "components": { "schemas": {
                "DeleteTenantRequest": { "properties": { "confirmation": { "type": "string" } } },
                "RemoveUserRequest": { "properties": { "Confirmation": { "type": "string" } } },
                "CreateTenantRequest": { "properties": { "name": { "type": "string" } } }
            } } }
            """);

        Assert.Equal(["RemoveUserRequest has a confirmation property: only DeleteTenantRequest may."], ConfirmationViolations(document));
    }

    private const string DeleteRequest = "DeleteTenantRequest";

    private static List<string> ConfirmationViolations(JsonDocument document) =>
        [.. document.RootElement.GetProperty("components").GetProperty("schemas").EnumerateObject()
            .Where(s => s.Name != DeleteRequest && HasProperty(s.Value, "confirmation"))
            .Select(s => $"{s.Name} has a confirmation property: only {DeleteRequest} may.")
            .Order(StringComparer.Ordinal)];

    private static bool IsUnderTenantsPath(string path) =>
        path == CreatePath || path.StartsWith(CreatePath + "/", StringComparison.Ordinal);

    [Fact]
    public void Host_Hosted_resolves_its_Tenant_before_anything_else()
    {
        Assert.Null(ResolutionViolation(File.ReadAllText(Path.Combine(Root, HostedProgram))));
    }

    [Theory]
    [InlineData("var app = builder.Build();\napp.UseRouting();\napp.UseTenantResolution(() => \"x\");\n", "app.UseRouting();")]
    [InlineData("var app = builder.Build();\napp.MapGet(\"/\", () => 1);\napp.UseTenantResolution(() => \"x\");\n", "app.MapGet(\"/\", () => 1);")]
    [InlineData("var app = builder.Build();\napp.UseForwardedHeaders();\napp.UseTenantResolution(() => \"x\");\n", "app.UseForwardedHeaders();")]
    [InlineData("var app = builder.Build();\napp.UseTenantResolution(() => \"x\");\napp.UseGatekeepForwardedClient();\n", "app.UseGatekeepForwardedClient();")]
    [InlineData("var app = builder.Build();\n", "no app.UseTenantResolution")]
    public void Late_or_missing_resolution_is_reported(string program, string expected)
    {
        Assert.Contains(expected, ResolutionViolation(program));
    }

    [Fact]
    public void Only_Tenancy_reads_tenant_host()
    {
        Assert.Empty(TenantHostViolations(SourceFiles()));
    }

    [Fact]
    public void A_tenant_host_read_outside_Tenancy_is_reported()
    {
        (string, string)[] files =
        [
            ("src/Modules/Tenancy/Core/Tenants.cs", "SELECT host FROM tenant_host"),
            ("src/Adapters/Postgres/Migrations/M.cs", "CREATE TABLE tenant_host ()"),
            ("src/Modules/Protocol/Core/Issuer.cs", "SELECT tenant_id FROM tenant_host WHERE host = @host"),
        ];

        Assert.Equal(["src/Modules/Protocol/Core/Issuer.cs reads tenant_host: only Tenancy may (AD-6)."], TenantHostViolations(files));
    }

    [Fact]
    public void Nothing_reads_a_forwarded_host()
    {
        Assert.Empty(ForwardedHostViolations(SourceFiles()));
    }

    [Theory]
    [InlineData("var host = request.Headers[\"X-Forwarded-Host\"];")]
    [InlineData("options.ForwardedHeaders = ForwardedHeaders.XForwardedHost;")]
    [InlineData("options.ForwardedHeaders = ForwardedHeaders.All;")]
    [InlineData("var forwarded = request.Headers[\"Forwarded\"];")]
    [InlineData("var forwarded = request.Headers[HeaderNames.Forwarded];")]
    [InlineData("var original = request.Headers[\"X-Original-Host\"];")]
    public void A_forwarded_host_read_is_reported(string source)
    {
        Assert.Single(ForwardedHostViolations([("src/Modules/Protocol/Core/Discovery.cs", source)]));
    }

    [Fact]
    public void Forwarded_client_address_isnt_a_forwarded_host()
    {
        Assert.Empty(ForwardedHostViolations([("src/Adapters/Hosting/GatekeepHosting.cs", "ForwardedHeaders = ForwardedHeaders.XForwardedFor,")]));
    }

    [Fact]
    public void Only_TenantAddress_builds_an_issuer()
    {
        var files = SourceFiles();

        Assert.Contains(files, f => f.Path == AddressFile && IssuerLiteral.IsMatch(Code(f.Source)));
        Assert.Empty(IssuerViolations(files));
    }

    [Theory]
    [InlineData("var issuer = $\"https://{host}/\";")]
    [InlineData("var issuer = \"https://\" + host + \"/\";")]
    [InlineData("options.SetIssuer(new Uri(request.Host.Value));")]
    public void An_issuer_built_elsewhere_is_reported(string source)
    {
        Assert.Single(IssuerViolations([("src/Modules/Protocol/Core/Discovery.cs", source)]));
    }

    [Fact]
    public void An_https_URL_in_a_comment_isnt_an_issuer()
    {
        Assert.Empty(IssuerViolations([("src/Adapters/Hosting/HostSettings.cs", "/// The origin, such as <c>https://admin.example.com</c>.\n// see https://example.com\nvar x = 1;")]));
    }

    // Story 1.28 (FR-9, AD-4, AD-19): the page's Tenant header is only compared, and documented on
    // every Tenant-path write; only the label route and Create Tenant take a label.

    [Fact]
    public void Only_the_request_checks_name_the_Tenant_header_and_never_parse_it()
    {
        var files = SourceFiles();

        Assert.Contains(files, f => f.Path == RequestChecksFile && f.Source.Contains(TenantHeaderName, StringComparison.Ordinal));
        Assert.Empty(TenantHeaderViolations(files));
    }

    [Theory]
    [InlineData("src/Gatekeep.Host.Admin/TenantLabelApi.cs", "var page = context.Request.Headers[\"X-Gatekeep-Tenant\"];")]
    [InlineData("src/Modules/Management/Core/TenantManagement.cs", "const string Header = \"x-gatekeep-tenant\";")]
    [InlineData(RequestChecksFile, "PublicId.TryParse(PublicIdType.Tenant, request.Headers[TenantHeader], out var t);")]
    [InlineData(RequestChecksFile, "PublicId.TryParse(\n  PublicIdType.Tenant,\n  SingleValue(context.Request.Headers[TenantHeader]),\n  out var t);")]
    public void A_Tenant_header_read_elsewhere_or_parsed_is_reported(string path, string source)
    {
        Assert.Single(TenantHeaderViolations([(path, source)]));
    }

    [Fact]
    public void A_comment_naming_the_Tenant_header_isnt_a_read()
    {
        Assert.Empty(TenantHeaderViolations([("src/Gatekeep.Host.Admin/TenantLabelApi.cs", "// Compared with X-Gatekeep-Tenant by the checks.\nvar x = 1;")]));
    }

    [Fact]
    public void Every_Tenant_path_write_documents_the_Tenant_header_and_its_409()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, Document)));

        Assert.Contains(Operations(document), o => o.Path.StartsWith(TenantPrefix, StringComparison.Ordinal) && o.Method != "get");
        Assert.Empty(MismatchDocumentViolations(document));
    }

    [Fact]
    public void A_Tenant_path_write_without_the_header_or_409_is_reported()
    {
        using var document = JsonDocument.Parse(
            """
            { "paths": {
                "/api/v1/tenants/{tenantId}/a": { "put": { "parameters": [ { "name": "X-Gatekeep-Tenant", "in": "header", "required": true } ], "responses": { "409": {} } } },
                "/api/v1/tenants/{tenantId}/b": { "post": { "responses": { "409": {} } } },
                "/api/v1/tenants/{tenantId}/c": { "delete": { "parameters": [ { "name": "X-Gatekeep-Tenant", "in": "header", "required": false } ], "responses": { "409": {} } } },
                "/api/v1/tenants/{tenantId}/d": { "patch": { "parameters": [ { "name": "X-Gatekeep-Tenant", "in": "header", "required": true } ], "responses": {} } },
                "/api/v1/tenants/{tenantId}/e": { "get": {} },
                "/api/v1/deployment/f": { "post": {} }
            } }
            """);

        Assert.Equal(
            [
                "delete /api/v1/tenants/{tenantId}/c doesn't require X-Gatekeep-Tenant.",
                "patch /api/v1/tenants/{tenantId}/d doesn't document its 409.",
                "post /api/v1/tenants/{tenantId}/b doesn't require X-Gatekeep-Tenant.",
            ],
            MismatchDocumentViolations(document));
    }

    [Fact]
    public void Only_the_label_route_and_Create_Tenant_take_a_label()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, Document)));

        Assert.Contains(LabelTakers(document), t => t == $"put {LabelPath}");
        Assert.Empty(LabelViolations(document));
    }

    [Fact]
    public void A_second_label_taker_is_reported()
    {
        using var document = JsonDocument.Parse(
            """
            {
              "paths": {
                "/api/v1/deployment/tenants": { "post": { "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CreateTenantRequest" } } } } } },
                "/api/v1/tenants/{tenantId}/label": { "put": { "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SetTenantLabelRequest" } } } } } },
                "/api/v1/tenants/{tenantId}/settings": { "patch": { "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SettingsChange" } } } } } },
                "/api/v1/tenants/{tenantId}/other": { "post": { "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SetTenantLabelRequest" } } } } } }
              },
              "components": { "schemas": {
                "CreateTenantRequest": { "properties": { "label": { "type": "string" } } },
                "SetTenantLabelRequest": { "properties": { "label": { "type": "string" } } },
                "SettingsChange": { "properties": { "Label": { "type": "string" } } },
                "TenantLabelResponse": { "properties": { "label": { "type": "string" } } }
              } }
            }
            """);

        Assert.Equal(
            [
                "SettingsChange is a request body with a label property: only CreateTenantRequest and SetTenantLabelRequest may.",
                "patch /api/v1/tenants/{tenantId}/settings takes a label: only post /api/v1/deployment/tenants and put /api/v1/tenants/{tenantId}/label may.",
                "post /api/v1/tenants/{tenantId}/other takes a label: only post /api/v1/deployment/tenants and put /api/v1/tenants/{tenantId}/label may.",
            ],
            LabelViolations(document));
    }

    private const string RequestChecksFile = "src/Gatekeep.Host.Admin/AdminRequestChecks.cs";
    private const string TenantHeaderName = "X-Gatekeep-Tenant";
    private const string TenantPrefix = "/api/v1/tenants/{tenantId}/";
    private const string LabelPath = "/api/v1/tenants/{tenantId}/label";

    private static readonly string[] LabelRequests = ["CreateTenantRequest", "SetTenantLabelRequest"];

    private static List<string> TenantHeaderViolations(IEnumerable<(string Path, string Source)> files)
    {
        var problems = new List<string>();
        foreach (var (path, source) in files)
        {
            var code = Code(source);
            if (path != RequestChecksFile && code.Contains(TenantHeaderName, StringComparison.OrdinalIgnoreCase))
            {
                problems.Add($"{path} names {TenantHeaderName}: only {RequestChecksFile} may, to compare it (AD-4).");
            }

            if (path == RequestChecksFile)
            {
                // Every TryParse call's whole argument list, across lines: the header never reaches one.
                foreach (Match call in Regex.Matches(code, @"PublicId\s*\.\s*TryParse\s*\((?<arguments>[^;]*)", RegexOptions.Singleline))
                {
                    var arguments = call.Groups["arguments"].Value;
                    if (arguments.Contains("TenantHeader", StringComparison.Ordinal) || arguments.Contains(TenantHeaderName, StringComparison.OrdinalIgnoreCase))
                    {
                        problems.Add($"{path} parses {TenantHeaderName}: it is only ever compared with the path (AD-19).");
                    }
                }
            }
        }

        return problems;
    }

    private static List<string> MismatchDocumentViolations(JsonDocument document)
    {
        var problems = new List<string>();
        foreach (var (path, method, operation) in Operations(document))
        {
            if (!path.StartsWith(TenantPrefix, StringComparison.Ordinal) || method is "get" or "head")
            {
                continue;
            }

            var header = operation.TryGetProperty("parameters", out var parameters)
                && parameters.EnumerateArray().Any(p =>
                    p.TryGetProperty("name", out var name) && name.GetString() == TenantHeaderName
                    && p.TryGetProperty("in", out var location) && location.GetString() == "header"
                    && p.TryGetProperty("required", out var required) && required.ValueKind == JsonValueKind.True);
            if (!header)
            {
                problems.Add($"{method} {path} doesn't require {TenantHeaderName}.");
            }

            if (!operation.TryGetProperty("responses", out var responses) || !responses.TryGetProperty("409", out _))
            {
                problems.Add($"{method} {path} doesn't document its 409.");
            }
        }

        return [.. problems.Order(StringComparer.Ordinal)];
    }

    private static List<string> LabelTakers(JsonDocument document) =>
        [.. Operations(document)
            .Where(o => RequestSchemas(document, o.Operation).Any(s => HasProperty(s.Schema, "label")))
            .Select(o => $"{o.Method} {o.Path}")];

    private static List<string> LabelViolations(JsonDocument document)
    {
        var problems = new List<string>();
        var bodies = Operations(document)
            .SelectMany(o => RequestSchemas(document, o.Operation))
            .Where(s => s.Name is not null && HasProperty(s.Schema, "label"))
            .Select(s => s.Name!)
            .Distinct()
            .Where(n => !LabelRequests.Contains(n));
        foreach (var name in bodies)
        {
            problems.Add($"{name} is a request body with a label property: only {string.Join(" and ", LabelRequests)} may.");
        }

        foreach (var taker in LabelTakers(document).Where(t => t != $"post {CreatePath}" && t != $"put {LabelPath}"))
        {
            problems.Add($"{taker} takes a label: only post {CreatePath} and put {LabelPath} may.");
        }

        return [.. problems.Order(StringComparer.Ordinal)];
    }

    /// <summary>An operation's JSON request body schemas, with their component names when they are references.</summary>
    private static IEnumerable<(string? Name, JsonElement Schema)> RequestSchemas(JsonDocument document, JsonElement operation)
    {
        if (!operation.TryGetProperty("requestBody", out var body) || !body.TryGetProperty("content", out var content))
        {
            yield break;
        }

        foreach (var media in content.EnumerateObject())
        {
            if (!media.Value.TryGetProperty("schema", out var schema))
            {
                continue;
            }

            if (schema.TryGetProperty("$ref", out var reference) && reference.GetString() is { } target)
            {
                var name = target[(target.LastIndexOf('/') + 1)..];
                if (document.RootElement.GetProperty("components").GetProperty("schemas").TryGetProperty(name, out var referenced))
                {
                    yield return (name, referenced);
                }
            }
            else
            {
                yield return (null, schema);
            }
        }
    }

    private static bool HasProperty(JsonElement schema, string property) =>
        schema.ValueKind == JsonValueKind.Object
        && schema.TryGetProperty("properties", out var properties)
        && properties.EnumerateObject().Any(p => string.Equals(p.Name, property, StringComparison.OrdinalIgnoreCase));

    private static List<string> SubdomainTakers(JsonDocument document) =>
        [.. Operations(document).Where(o => TakesSubdomain(document, o.Operation)).Select(o => $"{o.Method} {o.Path}")];

    private static List<string> SubdomainViolations(JsonDocument document)
    {
        var problems = new List<string>();

        if (document.RootElement.TryGetProperty("components", out var components)
            && components.TryGetProperty("schemas", out var schemas))
        {
            foreach (var schema in schemas.EnumerateObject())
            {
                if (schema.Name != "CreateTenantRequest" && HasSubdomain(schema.Value))
                {
                    problems.Add($"{schema.Name} has a subdomain property: only CreateTenantRequest may.");
                }
            }
        }

        foreach (var taker in SubdomainTakers(document).Where(t => t != $"post {CreatePath}"))
        {
            problems.Add($"{taker} takes a subdomain: only post {CreatePath} may.");
        }

        return [.. problems.Order(StringComparer.Ordinal)];
    }

    private static bool TakesSubdomain(JsonDocument document, JsonElement operation)
    {
        if (operation.TryGetProperty("parameters", out var parameters)
            && parameters.EnumerateArray().Any(p => p.TryGetProperty("name", out var name)
                && string.Equals(name.GetString(), "subdomain", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (!operation.TryGetProperty("requestBody", out var body) || !body.TryGetProperty("content", out var content))
        {
            return false;
        }

        foreach (var media in content.EnumerateObject())
        {
            if (!media.Value.TryGetProperty("schema", out var schema))
            {
                continue;
            }

            if (HasSubdomain(schema))
            {
                return true;
            }

            if (schema.TryGetProperty("$ref", out var reference)
                && reference.GetString() is { } target
                && document.RootElement.GetProperty("components").GetProperty("schemas")
                    .TryGetProperty(target[(target.LastIndexOf('/') + 1)..], out var referenced)
                && HasSubdomain(referenced))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasSubdomain(JsonElement schema) =>
        schema.ValueKind == JsonValueKind.Object
        && schema.TryGetProperty("properties", out var properties)
        && properties.EnumerateObject().Any(p => string.Equals(p.Name, "subdomain", StringComparison.OrdinalIgnoreCase));

    private static List<string> WriteViolations(JsonDocument document) =>
        [.. Operations(document)
            .Where(o => IsUnderTenantsPath(o.Path) && Writes.Contains(o.Method))
            .Select(o => $"{o.Method} {o.Path}")
            .Where(w => !ReviewedWrites.Contains(w))
            .Order(StringComparer.Ordinal)];

    /// <summary>
    /// Null when the first <c>app.</c> call after the app is built is <c>UseTenantResolution</c> and
    /// no forwarded-headers middleware is used; otherwise what came first or is wrong.
    /// </summary>
    private static string? ResolutionViolation(string program)
    {
        var code = Code(program);
        var built = code.IndexOf("builder.Build()", StringComparison.Ordinal);
        if (built < 0)
        {
            return "no builder.Build()";
        }

        var calls = Regex.Matches(code[built..], @"^\s*(?<call>app\.[A-Za-z]+\(.*)$", RegexOptions.Multiline)
            .Select(m => m.Groups["call"].Value.Trim())
            .ToList();

        var forwarded = calls.FirstOrDefault(c => c.StartsWith("app.UseForwardedHeaders", StringComparison.Ordinal)
            || c.StartsWith("app.UseGatekeepForwardedClient", StringComparison.Ordinal));
        if (forwarded is not null)
        {
            return forwarded;
        }

        if (calls.Count == 0 || !calls.Any(c => c.StartsWith("app.UseTenantResolution(", StringComparison.Ordinal)))
        {
            return "no app.UseTenantResolution";
        }

        return calls[0].StartsWith("app.UseTenantResolution(", StringComparison.Ordinal) ? null : calls[0];
    }

    private static List<string> TenantHostViolations(IEnumerable<(string Path, string Source)> files) =>
        [.. files
            .Where(f => !TenantHostOwners.Any(o => f.Path.StartsWith(o, StringComparison.Ordinal)))
            .Where(f => Regex.IsMatch(Code(f.Source), @"\btenant_host\b"))
            .Select(f => $"{f.Path} reads tenant_host: only Tenancy may (AD-6).")];

    private static List<string> ForwardedHostViolations(IEnumerable<(string Path, string Source)> files) =>
        [.. files
            .Where(f => ForwardedHost.IsMatch(Code(f.Source)))
            .Select(f => $"{f.Path} reads a forwarded host: the Tenant comes from the request host alone (AD-4, AD-6).")];

    private static List<string> IssuerViolations(IEnumerable<(string Path, string Source)> files) =>
        [.. files
            .Where(f => f.Path != AddressFile)
            .Where(f => IssuerLiteral.IsMatch(Code(f.Source)) || Code(f.Source).Contains("SetIssuer(", StringComparison.Ordinal))
            .Select(f => $"{f.Path} builds an issuer: only TenantAddress may, once, at creation (AD-6).")];

    /// <summary>The source without its comments, so a URL in documentation isn't code.</summary>
    private static string Code(string source) =>
        string.Join('\n', source.Split('\n').Select(line =>
        {
            var trimmed = line.TrimStart();
            if (trimmed.StartsWith("//", StringComparison.Ordinal))
            {
                return string.Empty;
            }

            var comment = line.IndexOf(" // ", StringComparison.Ordinal);
            return comment >= 0 ? line[..comment] : line;
        }));

    private static List<(string Path, string Source)> SourceFiles() =>
        [.. Directory.EnumerateFiles(Path.Combine(Root, "src"), "*.cs", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(Root, f).Replace('\\', '/'))
            .Where(f => !f.Contains("/bin/", StringComparison.Ordinal) && !f.Contains("/obj/", StringComparison.Ordinal))
            .Select(f => (f, File.ReadAllText(Path.Combine(Root, f))))];

    private static IEnumerable<(string Path, string Method, JsonElement Operation)> Operations(JsonDocument document) =>
        document.RootElement.GetProperty("paths").EnumerateObject()
            .SelectMany(p => p.Value.EnumerateObject().Select(o => (p.Name, o.Name, o.Value)));
}
