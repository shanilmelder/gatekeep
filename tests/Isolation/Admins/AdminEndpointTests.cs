using Gatekeep.Tests.Isolation.Hosting;
using Microsoft.AspNetCore.Routing;
using Xunit;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Story 1.21: every endpoint the real <c>Host.Admin</c> maps under <c>/api/v1/deployment</c> carries
/// the request checks' marker. The host's own entry point runs in its own load context with real
/// settings, and its endpoints are read from its started routing, as requests would reach them
/// (<see cref="RunningRoutes"/>).
/// </summary>
public sealed class AdminEndpointTests
{
    private const string Prefix = "/api/v1/deployment";

    [Fact]
    public async Task Every_deployment_route_of_the_running_host_has_the_request_checks_marker()
    {
        var endpoints = await RunningRoutes.AdminEndpointsAsync();

        var deployment = endpoints
            .Where(e => e.RoutePattern.RawText?.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase) == true)
            .ToList();

        Assert.Equal(
            [
                "/api/v1/deployment/assertions",
                "/api/v1/deployment/assertions/complete",
                "/api/v1/deployment/bootstrap",
                "/api/v1/deployment/capabilities",
                "/api/v1/deployment/credentials",
                "/api/v1/deployment/credentials/recovery-code",
                "/api/v1/deployment/credentials/recovery-code/confirm",
                "/api/v1/deployment/credentials/registration",
                "/api/v1/deployment/credentials/registration/complete",
                "/api/v1/deployment/credentials/{credentialId}",
                "/api/v1/deployment/logs",
                "/api/v1/deployment/logs/{eventId}",
                "/api/v1/deployment/my-tenants",
                "/api/v1/deployment/operations/{operationId}/retry",
                "/api/v1/deployment/session",
                "/api/v1/deployment/session",
                "/api/v1/deployment/signin",
                "/api/v1/deployment/signin/complete",
                "/api/v1/deployment/signin/enrolment",
                "/api/v1/deployment/signin/recovery-code",
                "/api/v1/deployment/tenants",
                "/api/v1/deployment/tenants",
                "/api/v1/deployment/tenants/{targetTenantId}/deletion",
                "/api/v1/deployment/tenants/{targetTenantId}/deletion",
                "/api/v1/deployment/tenants/{targetTenantId}/deletion/retry",
            ],
            deployment.Select(e => e.RoutePattern.RawText!).Order(StringComparer.Ordinal));
        foreach (var endpoint in deployment)
        {
            Assert.True(
                endpoint.Metadata.Any(m => m.GetType().Name == "DeploymentApiEndpoint"),
                $"{endpoint.DisplayName} has no request checks marker.");
        }

        // The unknown-path fallback is the only other API route, and it answers 404 alone.
        Assert.Contains(endpoints, e => e.RoutePattern.RawText == "/api/{**path}");
    }

    /// <summary>
    /// Story 1.24: every <c>/api/</c> route of the running host but the fallback has one API
    /// marker and exactly one access declaration, and the live routes and methods are exactly the
    /// committed document's operations, so no route escapes the document the access rules read.
    /// </summary>
    [Fact]
    public async Task Every_API_route_declares_one_access_kind_and_the_live_table_is_the_document()
    {
        var endpoints = await RunningRoutes.AdminEndpointsAsync();

        var api = endpoints
            .Where(e => e.RoutePattern.RawText?.StartsWith("/api/", StringComparison.OrdinalIgnoreCase) == true)
            .Where(e => e.RoutePattern.RawText != "/api/{**path}")
            .ToList();

        Assert.Contains(api, e => e.RoutePattern.RawText == "/api/v1/tenants/{tenantId}/capabilities");
        foreach (var endpoint in api)
        {
            var names = endpoint.Metadata.Select(m => m.GetType().Name).ToList();
            var markers = names.Count(n => n is "DeploymentApiEndpoint" or "TenantApiEndpoint");
            var declarations = names.Count(n => n is "RequiresCapability" or "SelfService" or "BootstrapClaimEndpoint" or "SignInEndpoint");
            Assert.True(markers == 1, $"{endpoint.DisplayName} has {markers} API markers.");
            Assert.True(declarations == 1, $"{endpoint.DisplayName} has {declarations} access declarations.");

            var tenant = endpoint.RoutePattern.RawText!.StartsWith("/api/v1/tenants/{tenantId}/", StringComparison.Ordinal);
            Assert.Equal(tenant, names.Contains("TenantApiEndpoint"));
            if (tenant)
            {
                Assert.Contains("RequiresCapability", names);
            }
        }

        var live = api
            .SelectMany(e => (e.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? new[] { "*" })
                .Select(m => $"{m.ToLowerInvariant()} {e.RoutePattern.RawText}"))
            .Order(StringComparer.Ordinal)
            .ToList();

        using var document = System.Text.Json.JsonDocument.Parse(
            await File.ReadAllTextAsync(Path.Combine(BuildOutput.RepositoryRoot(), "docs", "api", "openapi-v1.json"), TestContext.Current.CancellationToken));
        var documented = document.RootElement.GetProperty("paths").EnumerateObject()
            .SelectMany(p => p.Value.EnumerateObject().Select(o => $"{o.Name} {p.Name}"))
            .Order(StringComparer.Ordinal)
            .ToList();

        Assert.Equal(documented, live);
    }
}
