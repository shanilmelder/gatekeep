using System.Text.Json.Nodes;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;

namespace Gatekeep.Host.Admin;

/// <summary>
/// The v1 OpenAPI document (Story 1.21), generated at build time from the mapped endpoints and
/// committed as <c>docs/api/openapi-v1.json</c>, which <c>packages/api-client</c> is generated
/// from. It names the Admin Session cookie and the CSRF header each operation needs, and the
/// problem responses. It is never served.
/// </summary>
internal static class AdminOpenApi
{
    private const string SessionScheme = "adminSession";

    private const string CsrfScheme = "csrf";

    public static IServiceCollection AddAdminOpenApi(this IServiceCollection services) =>
        services.AddOpenApi("v1", options =>
        {
            options.AddDocumentTransformer(static (document, _, _) =>
            {
                document.Info = new OpenApiInfo
                {
                    Title = "Gatekeep Admin API",
                    Version = "v1",
                    Description =
                        "The Admin Dashboard's API on Host.Admin. Every /api/v1/deployment endpoint but the bootstrap claim needs the " +
                        "__Host-gk-admin Session cookie; every state-changing one also needs the exact Admin Origin and the Session's " +
                        "X-Gatekeep-CSRF token. A refusal's body is only a fixed code and the trace ID.",
                };

                // The stand-in server's address isn't part of the contract.
                document.Servers = [];

                document.Components ??= new OpenApiComponents();
                document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
                document.Components.SecuritySchemes[SessionScheme] = new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.ApiKey,
                    In = ParameterLocation.Cookie,
                    Name = AdminRequestChecks.SessionCookie,
                    Description = "The Admin Session: Secure, HttpOnly, SameSite=Strict, host-only. 30 minutes idle, 8 hours absolute.",
                };
                document.Components.SecuritySchemes[CsrfScheme] = new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.ApiKey,
                    In = ParameterLocation.Header,
                    Name = AdminRequestChecks.CsrfHeader,
                    Description = "The Session's CSRF token, from the claim or GET /api/v1/deployment/session. Required on state-changing requests.",
                };

                return Task.CompletedTask;
            });

            // Closed sets: the Session kinds, and the codes a problem body can carry.
            options.AddSchemaTransformer(static (schema, context, _) =>
            {
                var type = context.JsonTypeInfo.Type;
                if (type == typeof(AdminSessionResponse))
                {
                    Enumerate(schema, "kind", ["setup", "full"]);
                }
                else if (type == typeof(ApiProblem))
                {
                    Enumerate(schema, "code", AdminResponses.ProblemCodes);
                }

                return Task.CompletedTask;
            });

            options.AddOperationTransformer(static async (operation, context, cancellationToken) =>
            {
                var metadata = context.Description.ActionDescriptor.EndpointMetadata;

                // Machine-readable: whether a setup Session may call it.
                operation.Extensions ??= new Dictionary<string, IOpenApiExtension>();
                operation.Extensions[SetupAllowedExtension] =
                    new JsonNodeExtension(JsonValue.Create(metadata.OfType<SetupAllowed>().Any()));

                if (metadata.OfType<BootstrapClaimEndpoint>().Any())
                {
                    // No session yet: the claim needs only the exact Origin, and sets the cookie.
                    operation.Security = [];

                    // Declared here, not with Accepts, which routing would enforce: a claim sent
                    // as another type must reach the endpoint, to be refused and counted.
                    var request = await context.GetOrCreateSchemaAsync(typeof(BootstrapClaimRequest), null, cancellationToken);
                    context.Document?.AddComponent(nameof(BootstrapClaimRequest), request);
                    operation.RequestBody = new OpenApiRequestBody
                    {
                        Required = true,
                        Content = new Dictionary<string, OpenApiMediaType>
                        {
                            ["application/json"] = new OpenApiMediaType
                            {
                                Schema = new OpenApiSchemaReference(nameof(BootstrapClaimRequest), context.Document),
                            },
                        },
                    };
                    if (operation.Responses?.TryGetValue("201", out var created) == true && created is OpenApiResponse response)
                    {
                        response.Headers ??= new Dictionary<string, IOpenApiHeader>();
                        response.Headers["Set-Cookie"] = new OpenApiHeader
                        {
                            Description =
                                "The Admin Session: __Host-gk-admin={43 base64url characters}; Path=/; Secure; HttpOnly; SameSite=Strict. " +
                                "A browser session cookie, with no Domain, Expires or Max-Age.",
                            Schema = new OpenApiSchema { Type = JsonSchemaType.String },
                        };
                    }

                    if (operation.Responses?.TryGetValue("429", out var limited) == true && limited is OpenApiResponse limitedResponse)
                    {
                        limitedResponse.Headers ??= new Dictionary<string, IOpenApiHeader>();
                        limitedResponse.Headers["Retry-After"] = new OpenApiHeader
                        {
                            Description = "Whole seconds until this client's claim window ends and it may claim again.",
                            Required = true,
                            Schema = new OpenApiSchema { Type = JsonSchemaType.Integer, Minimum = "1" },
                        };
                    }

                    return;
                }

                var requirement = new OpenApiSecurityRequirement
                {
                    [new OpenApiSecuritySchemeReference(SessionScheme, context.Document)] = [],
                };

                var method = context.Description.HttpMethod ?? string.Empty;
                if (!(HttpMethods.IsGet(method) || HttpMethods.IsHead(method)))
                {
                    requirement[new OpenApiSecuritySchemeReference(CsrfScheme, context.Document)] = [];
                }

                operation.Security = [requirement];
                return;
            });
        });

    private const string SetupAllowedExtension = "x-gatekeep-setup-allowed";

    private static void Enumerate(OpenApiSchema schema, string property, IEnumerable<string> values)
    {
        if (schema.Properties?.TryGetValue(property, out var found) == true && found is OpenApiSchema target)
        {
            target.Enum = [.. values.Select(v => (JsonNode)JsonValue.Create(v))];
        }
    }
}
