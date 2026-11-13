using System.Net;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Applications;

/// <summary>
/// Story 3.5's refusal rows (FR-11, AD-13) through the real Tenant resolution and Protocol registration as
/// <c>gk_hosted</c>, with the test-only sign-in: once an Application is deleted, the one Directory way, as
/// <c>gk_admin</c>, the token, authorization and revocation endpoints treat it as an unknown client. A confidential
/// client's old secret is <c>invalid_client</c> with "The client credentials are invalid.", on Client Credentials and
/// on a refresh alike, exactly as an unknown client's; a public client's authorize request is the static page, and
/// its refresh <c>invalid_client</c>. No refused request writes a token.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class ApplicationDeletionProtocolTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.deletion.test";

    private const string HostB = "beta.deletion.test";

    private const string Offline = "openid offline_access";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("basic")]
    [InlineData("post")]
    public async Task A_deleted_machine_clients_old_secret_is_invalid_client_as_an_unknown_clients(string method)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var machine = await flow.Database.CreateClientAsync(flow.A.TenantId);
        await using var host = await flow.StartHostAsync();

        using (var issued = await ClientCredentialsTests.TokenAsync(host, HostA, machine.ClientId, machine.Secret, method))
        {
            Assert.Equal(HttpStatusCode.OK, issued.Status);
        }

        var tokens = await TokenRowsAsync(flow);
        await DeleteAsync(flow, machine.ApplicationId);

        using var refused = await ClientCredentialsTests.TokenAsync(host, HostA, machine.ClientId, machine.Secret, method);
        using var unknown = await ClientCredentialsTests.TokenAsync(
            host, HostA, PublicId.Format(PublicIdType.Application, Guid.CreateVersion7()), machine.Secret, method);

        AssertInvalidClient(refused);
        Assert.Equal(unknown.Status, refused.Status);
        Assert.Equal(unknown.Body.RootElement.ToString(), refused.Body.RootElement.ToString());
        Assert.Equal(tokens, await TokenRowsAsync(flow));
    }

    [Fact]
    public async Task A_deleted_web_clients_refresh_with_its_old_secret_is_invalid_client()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        var pkce = Pkce.New();
        var code = await CodeFlow.CodeAsync(host, HostA, flow.ClientA.ClientId, CodeFlowSetup.Callback, pkce, flow.UserA, scope: Offline);
        using var issued = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, CodeFlowSetup.Callback, pkce.Verifier);
        Assert.Equal(HttpStatusCode.OK, issued.Status);

        await DeleteAsync(flow, flow.ClientA.ApplicationId);
        var tokens = await TokenRowsAsync(flow);

        using var refused = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, issued.RefreshToken);

        AssertInvalidClient(refused);
        Assert.Equal(tokens, await TokenRowsAsync(flow));

        // Its family was revoked with the deletion, through the one revocation path.
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND application_id = '{flow.ClientA.ApplicationId}' AND status <> 'revoked' AND type LIKE '%refresh_token'"));

        // The revocation endpoint knows it no more than the token endpoint does.
        using var revoke = await UserinfoAndRevocationTests.RevokeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, issued.RefreshToken, method: "post");
        Assert.Equal("invalid_client", revoke.Error);
    }

    [Theory]
    [InlineData("spa")]
    [InlineData("native")]
    public async Task A_deleted_public_client_is_refused_at_authorize_and_its_refresh_is_invalid_client(string kind)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var (applicationId, clientId) = await flow.Database.CreateApplicationAsync(flow.A.TenantId, kind);
        await flow.Database.ExecuteAsync(
            $"UPDATE application SET redirect_uris = ARRAY['{CodeFlowSetup.Callback}'], grant_types = ARRAY['authorization_code', 'refresh_token'] WHERE id = '{applicationId}'");
        await using var host = await flow.StartHostAsync();

        var pkce = Pkce.New();
        var code = await CodeFlow.CodeAsync(host, HostA, clientId, CodeFlowSetup.Callback, pkce, flow.UserA, scope: Offline);
        using var issued = await PublicAsync(host, clientId, new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = CodeFlowSetup.Callback,
            ["code_verifier"] = pkce.Verifier,
        });
        Assert.Equal(HttpStatusCode.OK, issued.Status);

        await DeleteAsync(flow, applicationId);
        var transactions = await flow.Database.ScalarAsync<long>("SELECT count(*) FROM signin_transaction");
        var tokens = await TokenRowsAsync(flow);

        // Authorize treats it as unknown: the static page, never a redirect, and no sign-in begun.
        using (var authorize = await CodeFlow.AuthorizeAsync(host, HostA, clientId, CodeFlowSetup.Callback, Pkce.New(), flow.UserA, state: "echo-me-not"))
        {
            Assert.Equal(HttpStatusCode.BadRequest, authorize.StatusCode);
            Assert.Null(authorize.Headers.Location);
            Assert.Equal("text/html", authorize.Content.Headers.ContentType?.MediaType);
            Assert.DoesNotContain("echo-me-not", await authorize.Content.ReadAsStringAsync(Cancellation), StringComparison.Ordinal);
        }

        Assert.Equal(transactions, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM signin_transaction"));

        using var refreshed = await PublicAsync(host, clientId, new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = issued.RefreshToken,
        });

        AssertInvalidClient(refreshed);
        Assert.Equal(tokens, await TokenRowsAsync(flow));
    }

    [Fact]
    public async Task Another_Application_of_the_Tenant_still_gets_its_tokens()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var deleted = await flow.Database.CreateClientAsync(flow.A.TenantId, "Deleted");
        var kept = await flow.Database.CreateClientAsync(flow.A.TenantId, "Kept");
        await DeleteAsync(flow, deleted.ApplicationId);
        await using var host = await flow.StartHostAsync();

        using var ok = await ClientCredentialsTests.TokenAsync(host, HostA, kept.ClientId, kept.Secret);

        Assert.Equal(HttpStatusCode.OK, ok.Status);
    }

    /// <summary>Deletes the Application the one Directory way, as <c>gk_admin</c> in its Tenant's scope, as the Admin API does.</summary>
    private async Task DeleteAsync(CodeFlowSetup flow, Guid applicationId)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, flow.Database.Name));
        await using var scope = await TenantScope.BeginAsync(source, flow.A.TenantId, Cancellation);
        Assert.True(await DirectoryContract.CreateDirectory(AuditContract.CreateAppender(), TimeProvider.System)
            .DeleteApplicationAsync(scope.CreateCommandContext(), Actor.Admin(Guid.CreateVersion7()), applicationId, Cancellation));
        await scope.CommitAsync(Cancellation);
    }

    private static void AssertInvalidClient(TokenResponse response)
    {
        Assert.True(response.Status is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized, response.Status.ToString());
        Assert.Equal("invalid_client", response.Error);
        Assert.Equal("The client credentials are invalid.", response.Body.RootElement.GetProperty("error_description").GetString());
        Assert.False(response.Body.RootElement.TryGetProperty("access_token", out _));
    }

    private static Task<long> TokenRowsAsync(CodeFlowSetup flow) =>
        flow.Database.ScalarAsync<long>("SELECT count(*) FROM token");

    /// <summary>A token request as a public client sends it: its client_id in the form, and no secret.</summary>
    private static async Task<TokenResponse> PublicAsync(ProtocolHost host, string clientId, Dictionary<string, string> form)
    {
        form["client_id"] = clientId;
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"http://{HostA}{ProtocolContract.TokenPath}"))
        {
            Content = new FormUrlEncodedContent(form),
        };
        var response = await host.Http.SendAsync(request, Cancellation);
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        return new TokenResponse(response, JsonDocument.Parse(body));
    }
}
