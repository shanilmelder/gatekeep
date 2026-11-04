using System.Text.Json.Nodes;
using Gatekeep.Modules.Admins.Contracts;
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
                        "The Admin Dashboard's API on Host.Admin: the Deployment surface under /api/v1/deployment and the Tenant " +
                        "surface under /api/v1/tenants/{tenantId}, whose Tenant comes from that path segment only. Every endpoint but " +
                        "the bootstrap claim and Admin sign-in needs the __Host-gk-admin Session cookie; every state-changing one also " +
                        "needs the exact Admin Origin and the Session's X-Gatekeep-CSRF token. The claim and sign-in need the exact " +
                        "Admin Origin only. Each operation's x-gatekeep-access names its one access declaration: a capability from the " +
                        "capability table, self-service, or sessionless. A refusal's body is only a fixed code and the trace ID.",
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
                else if (type == typeof(CredentialCreationOptionsResponse))
                {
                    Enumerate(schema, "attestation", ["none"]);
                }
                else if (type == typeof(RegistrationAuthenticatorSelection))
                {
                    Enumerate(schema, "residentKey", ["required"]);
                    Enumerate(schema, "userVerification", ["required"]);
                }
                else if (type == typeof(AdminSignInOptionsResponse))
                {
                    Enumerate(schema, "userVerification", ["required"]);

                    // Always empty: no credential ID goes to a caller who hasn't signed in.
                    if (schema.Properties?.TryGetValue("allowCredentials", out var allowed) == true && allowed is OpenApiSchema list)
                    {
                        list.MaxItems = 0;
                    }
                }
                else if (type == typeof(RegistrationPublicKeyParameter) || type == typeof(RegistrationExcludedCredential)
                    || type == typeof(CredentialRegistrationRequest) || type == typeof(AdminSignInRequest))
                {
                    Enumerate(schema, "type", ["public-key"]);
                }
                else if (type == typeof(ApiProblem))
                {
                    Enumerate(schema, "code", AdminResponses.ProblemCodes);
                }
                else if (type == typeof(CapabilitiesResponse))
                {
                    // Every name the capability table holds, read from it, never restated.
                    if (schema.Properties?.TryGetValue("capabilities", out var list) == true
                        && list is OpenApiSchema array && array.Items is OpenApiSchema items)
                    {
                        items.Enum = [.. AdminCapabilities.All.Select(c => (JsonNode)JsonValue.Create(c.Name))];
                    }
                }

                return Task.CompletedTask;
            });

            options.AddOperationTransformer(static async (operation, context, cancellationToken) =>
            {
                var metadata = context.Description.ActionDescriptor.EndpointMetadata;

                // Exactly one access declaration, or the build that generates the document fails.
                var declaration = AccessDeclaration.Of(metadata, "/" + context.Description.RelativePath)
                    ?? throw new InvalidOperationException(
                        $"{context.Description.HttpMethod} {context.Description.RelativePath} needs exactly one API marker and one valid access declaration.");

                // Machine-readable: whether a setup Session may call it, and its access.
                operation.Extensions ??= new Dictionary<string, IOpenApiExtension>();
                operation.Extensions[SetupAllowedExtension] =
                    new JsonNodeExtension(JsonValue.Create(metadata.OfType<SetupAllowed>().Any()));
                operation.Extensions[AccessExtension] = new JsonNodeExtension(Access(declaration));

                if (declaration.Tenant)
                {
                    // The Tenant comes from this segment only: its canonical public ID.
                    operation.Parameters ??= [];
                    var existing = operation.Parameters.FirstOrDefault(p => p.Name == AdminRequestChecks.TenantRouteValue);
                    if (existing is not null)
                    {
                        operation.Parameters.Remove(existing);
                    }

                    operation.Parameters.Insert(0, new OpenApiParameter
                    {
                        Name = AdminRequestChecks.TenantRouteValue,
                        In = ParameterLocation.Path,
                        Required = true,
                        Description =
                            "The Tenant's public ID: ten_ and the UUID's 16 bytes in lowercase RFC 4648 base32 with no padding, whose " +
                            "last character carries two zero bits. Only this canonical spelling, after URL decoding, names a Tenant, and " +
                            "the empty UUID's never does; anything else is refused like a Tenant the Admin holds no role in.",
                        Schema = new OpenApiSchema { Type = JsonSchemaType.String, Pattern = TenantIdPattern },
                    });
                }

                if (declaration.Kind == AccessKind.Capability
                    && operation.Responses?.TryGetValue("403", out var forbidden) == true && forbidden is OpenApiResponse forbiddenResponse)
                {
                    // Two shapes: the capability refusal's problem, or no body from an earlier gate.
                    forbiddenResponse.Description =
                        "access_denied, with the problem body, when the capability is refused. No body when an earlier check " +
                        "refuses first: a Session restricted to setup, or on a state-changing call a wrong Origin or CSRF token.";
                }

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

                if (metadata.OfType<JsonRequestBody>().FirstOrDefault() is { } body)
                {
                    // Read by the endpoint itself, like the claim's: another type is refused there.
                    var name = body.Type.Name;
                    var schema = await context.GetOrCreateSchemaAsync(body.Type, null, cancellationToken);
                    context.Document?.AddComponent(name, schema);
                    operation.RequestBody = new OpenApiRequestBody
                    {
                        Required = true,
                        Content = new Dictionary<string, OpenApiMediaType>
                        {
                            ["application/json"] = new OpenApiMediaType { Schema = new OpenApiSchemaReference(name, context.Document) },
                        },
                    };
                }

                if (operation.Responses?.TryGetValue("429", out var tooMany) == true && tooMany is OpenApiResponse tooManyResponse)
                {
                    tooManyResponse.Headers ??= new Dictionary<string, IOpenApiHeader>();
                    tooManyResponse.Headers["Retry-After"] = new OpenApiHeader
                    {
                        Description = "Whole seconds until the rate-limit window allows another request.",
                        Required = true,
                        Schema = new OpenApiSchema { Type = JsonSchemaType.Integer, Minimum = "1" },
                    };
                }

                if (metadata.OfType<SignInEndpoint>().Any())
                {
                    // No session yet: sign-in needs only the exact Origin, and its cookies.
                    operation.Security = [];
                    if (operation.Responses?.TryGetValue("200", out var ok) == true && ok is OpenApiResponse okResponse)
                    {
                        okResponse.Headers ??= new Dictionary<string, IOpenApiHeader>();
                        okResponse.Headers["Set-Cookie"] = new OpenApiHeader
                        {
                            Description = metadata.OfType<JsonRequestBody>().Any()
                                ? "The Admin Session: __Host-gk-admin={43 base64url characters}; Path=/; Secure; HttpOnly; SameSite=Strict, a " +
                                  "browser session cookie with no Domain, Expires or Max-Age. And __Host-gk-admin-signin cleared with Max-Age=0, " +
                                  "as on every complete."
                                : "The sign-in binding: __Host-gk-admin-signin={43 base64url characters}; Path=/; Secure; HttpOnly; " +
                                  "SameSite=Strict; Max-Age=300. The complete call must carry it.",
                            Schema = new OpenApiSchema { Type = JsonSchemaType.String },
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

    private const string AccessExtension = "x-gatekeep-access";

    /// <summary>The canonical spelling: 25 base32 characters, then one whose two unused low bits are zero.</summary>
    private const string TenantIdPattern = "^ten_[a-z2-7]{25}[aeimquy4]$";

    /// <summary>The <c>x-gatekeep-access</c> value: the declaration, and a capability's flags as the table holds them.</summary>
    private static JsonObject Access(AccessDeclaration declaration) => declaration.Kind switch
    {
        AccessKind.Capability => new JsonObject
        {
            ["kind"] = "capability",
            ["capability"] = declaration.Capability!.Name,
            ["scope"] = declaration.Capability.Scope == CapabilityScope.Tenant ? "tenant" : "deployment",
            ["machineAllowed"] = declaration.Capability.MachineAllowed,
            ["freshAssertion"] = declaration.Capability.FreshAssertion switch
            {
                FreshAssertion.Never => "never",
                FreshAssertion.Always => "always",
                FreshAssertion.WhenProdTenant => "whenProdTenant",
                FreshAssertion.WhenLoweringPolicy => "whenLoweringPolicy",
                _ => throw new InvalidOperationException("A capability has an unknown fresh assertion."),
            },
        },
        AccessKind.Self => new JsonObject { ["kind"] = "self" },
        AccessKind.Sessionless => new JsonObject { ["kind"] = "sessionless" },
        _ => throw new InvalidOperationException("An access declaration has an unknown kind."),
    };

    private static void Enumerate(OpenApiSchema schema, string property, IEnumerable<string> values)
    {
        if (schema.Properties?.TryGetValue(property, out var found) == true && found is OpenApiSchema target)
        {
            target.Enum = [.. values.Select(v => (JsonNode)JsonValue.Create(v))];
        }
    }
}
