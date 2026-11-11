using System.Net;
using System.Security.Cryptography;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Gatekeep.Tests.Isolation.Applications;

/// <summary>
/// Story 3.1's inert-client row: an Application an Admin just created has no secret, and a
/// single-page or native one no grant, so none of them obtains a token at its Tenant's token
/// endpoint, whatever it presents. Created the one Directory way the Admin API uses, then asked
/// for a token through the real Protocol registration as <c>gk_hosted</c>.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class InertApplicationTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string TenantHost = "inert.tokens.test";

    public static TheoryData<string, string, string> Requests => new()
    {
        { "spa", "client_credentials", "post" },
        { "spa", "authorization_code", "post" },
        { "spa", "refresh_token", "post" },
        { "native", "client_credentials", "post" },
        { "native", "authorization_code", "post" },
        { "web", "client_credentials", "basic" },
        { "web", "authorization_code", "basic" },
        { "web", "authorization_code", "post" },
        { "machine", "client_credentials", "basic" },
        { "machine", "client_credentials", "post" },
    };

    [Theory]
    [MemberData(nameof(Requests))]
    public async Task A_new_Application_gets_no_token_with_no_secret_or_any_secret(string kind, string grant, string method)
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var tenant = await database.AddTenantAsync(TenantHost);
        Assert.True(await database.ProvisionAsync(bao, tenant.TenantId));
        var (applicationId, clientId) = await database.CreateApplicationAsync(tenant.TenantId, kind);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        // No secret at all, then a well-formed one of this Tenant's shape that was never issued.
        var guessed = $"{PublicId.Format(PublicIdType.Tenant, tenant.TenantId)}.{Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32))}";
        foreach (var secret in new[] { null, guessed })
        {
            var extra = grant switch
            {
                "authorization_code" => ("code", "not-a-code"),
                "refresh_token" => ("refresh_token", "not-a-token"),
                _ => ((string, string)?)null,
            };
            using var response = await ClientCredentialsTests.TokenAsync(host, TenantHost, clientId, secret, method, grant, extra);

            Assert.True(response.Status is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized, $"{kind} {grant} {method}: {response.Status}");
            Assert.Contains(response.Error, new[] { "invalid_client", "unauthorized_client" });
            Assert.False(response.Body.RootElement.TryGetProperty("access_token", out _));
        }

        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM token"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM client_secret WHERE application_id = '{applicationId}'"));
    }
}
