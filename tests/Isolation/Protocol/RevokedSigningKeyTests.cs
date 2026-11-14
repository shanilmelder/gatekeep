using System.Net;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Keys.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Protocol;

/// <summary>
/// Story 9.3 (FR-38, UJ-3): a token signed with a Signing Key while it was <c>current</c> stops being
/// trusted once the Tenant Owner revokes that key. The token is the real code flow's access token, signed
/// in Transit by the key, exactly what an attacker holding the key's private material could forge. A
/// fixture resource server, a relying party validating against the Tenant's JWKS as
/// <c>ClientCredentialsTests</c> does, accepts it before the revocation and rejects it on its next fetch
/// of the JWKS, the one it makes once its cached copy reaches the 15-minute cache limit: the key's
/// <c>kid</c> is no longer published. Host.Hosted's own userinfo rejects it too. No assertion prints a
/// token, a key name or key material.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class RevokedSigningKeyTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.revoked-key.test";
    private const string HostB = "beta.revoked-key.test";

    private static readonly TimeSpan NotificationWait = TimeSpan.FromSeconds(15);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_token_signed_with_a_revoked_key_is_rejected_by_a_resource_server_after_its_JWKS_refresh_and_by_userinfo()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await UserinfoAndRevocationTests.TokensAsync(host, flow, HostA);
        var current = await flow.Database.ScalarAsync<string>(
            $"SELECT transit_name || '.v' || transit_version FROM signing_key WHERE tenant_id = '{flow.A.TenantId}' AND purpose = 'signing' AND state = 'current'");
        Assert.True(new JsonWebToken(tokens.Access).Kid == current, "The access token wasn't signed with the current key.");

        // Before: the resource server's JWKS fetch has the key, and the token validates; userinfo answers.
        var before = await ValidateAsync(await JwksAsync(host), tokens.Access, flow.A.Issuer);
        Assert.True(before.IsValid, "The token didn't validate before the revocation.");
        using (var answered = await UserinfoAndRevocationTests.UserinfoAsync(host, HostA, tokens.Access))
        {
            Assert.Equal(HttpStatusCode.OK, answered.Status);
        }

        await RevokeAsync(flow, current);

        // The JWKS the resource server fetches next, once its cached copy expires, no longer names the key.
        var deadline = DateTimeOffset.UtcNow + NotificationWait;
        JsonWebKeySet jwks;
        while ((jwks = await JwksAsync(host)).Keys.Any(k => k.Kid == current) && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(25), Cancellation);
        }

        Assert.DoesNotContain(jwks.Keys, k => k.Kid == current);
        Assert.Equal(2, jwks.Keys.Count);

        var after = await ValidateAsync(jwks, tokens.Access, flow.A.Issuer);
        Assert.False(after.IsValid, "The token still validated after the revocation.");
        Assert.IsAssignableFrom<SecurityTokenInvalidSignatureException>(after.Exception);

        using var refused = await UserinfoAndRevocationTests.UserinfoAsync(host, HostA, tokens.Access);
        Assert.Equal(HttpStatusCode.Unauthorized, refused.Status);
        Assert.Contains("error=\"invalid_token\"", refused.WwwAuthenticate, StringComparison.Ordinal);

        // Tenant B's keys are untouched.
        Assert.Equal(2L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM signing_key WHERE tenant_id = '{flow.B.TenantId}' AND purpose = 'signing' AND state IN ('current', 'next')"));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM signing_key WHERE tenant_id = '{flow.B.TenantId}' AND state = 'revoked'"));
    }

    /// <summary>The Tenant Owner's revocation as Host.Admin runs it: as <c>gk_admin</c> with its custody login, committed.</summary>
    private async Task RevokeAsync(CodeFlowSetup flow, string keyId)
    {
        using var custody = bao.Custody(OpenBaoFixture.Admin);
        await using var source = NpgsqlDataSource.Create(flow.Database.Role(TableRegistry.Admin));
        await using var scope = await TenantScope.BeginAsync(source, flow.A.TenantId, Cancellation);
        var revocation = await KeysContract.RevokeSigningKeyAsync(
            scope.CreateCommandContext(),
            custody,
            AuditContract.CreateAppender(),
            OperationsContract.CreateEnqueuer(OperationsContract.ProductionRegistry, custody: null),
            OperationsContract.DestroySigningKey,
            Actor.Admin(Guid.CreateVersion7()),
            flow.A.TenantId,
            keyId,
            Cancellation);
        Assert.Equal(SigningKeyRevocationStatus.Revoked, revocation.Status);
        await scope.CommitAsync(Cancellation);
    }

    /// <summary>The fixture resource server's JWKS fetch: the Tenant's own, as any relying party reads it.</summary>
    private static async Task<JsonWebKeySet> JwksAsync(ProtocolHost host)
    {
        using var response = await host.Http.GetAsync(new Uri($"http://{HostA}{ProtocolContract.JsonWebKeySetPath}"), Cancellation);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return new JsonWebKeySet(document.RootElement.GetRawText());
    }

    /// <summary>The fixture resource server's check: signature by a published key, issuer, lifetime, RS256 and <c>at+jwt</c>.</summary>
    private static Task<TokenValidationResult> ValidateAsync(JsonWebKeySet jwks, string token, string issuer) =>
        new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            IssuerSigningKeys = jwks.GetSigningKeys(),
            ValidIssuer = issuer,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            ValidTypes = ["at+jwt"],
            TryAllIssuerSigningKeys = false,
        });
}
