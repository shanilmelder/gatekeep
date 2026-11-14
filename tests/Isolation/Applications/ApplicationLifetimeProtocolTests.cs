using System.Net;
using Gatekeep.Kernel.Limits;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Microsoft.IdentityModel.JsonWebTokens;
using Xunit;

namespace Gatekeep.Tests.Isolation.Applications;

/// <summary>
/// Story 3.4's issuance rows (FR-15, PRD §5.2) through the real Tenant resolution and Protocol registration as
/// <c>gk_hosted</c>, with the test-only sign-in: each token a request issues lives its Application's saved
/// lifetime, on authorization_code, refresh_token and client_credentials alike. The access token's
/// <c>exp</c> − <c>iat</c> and <c>expires_in</c> are its access lifetime, the ID token's its ID lifetime, and a
/// refresh token expires its inactivity lifetime after issue, never past its family's absolute end, which a
/// refresh reads from the Application as it stands. Each Application's lifetimes are written as the save
/// writes them, to the row.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class ApplicationLifetimeProtocolTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.lifetimes.test";

    private const string HostB = "beta.lifetimes.test";

    private const string Offline = "openid offline_access";

    private const string RefreshType = "urn:ietf:params:oauth:token-type:refresh_token";

    [Fact]
    public async Task Untouched_lifetimes_issue_the_Deployment_defaults()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var issued = await OfflineAsync(host, flow);

        AssertLifetimes(issued, SecurityLimits.DefaultAccessTokenLifetime, SecurityLimits.DefaultIdentityTokenLifetime);
        Assert.Equal(1L, await RefreshRowsAsync(flow, Lasting("7 days")));
    }

    [Fact]
    public async Task A_code_exchange_and_its_refreshes_use_the_saved_lifetimes()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await SetAsync(flow, flow.ClientA.ApplicationId, 300, 600, 864000, 86400);
        await using var host = await flow.StartHostAsync();

        using var issued = await OfflineAsync(host, flow);

        AssertLifetimes(issued, TimeSpan.FromSeconds(300), TimeSpan.FromSeconds(600));
        Assert.Equal(1L, await RefreshRowsAsync(flow, Lasting("1 day")));

        // The refresh grant issues for them too, and its new refresh token expires a day after its own issue.
        using var refreshed = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, issued.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        AssertLifetimes(refreshed, TimeSpan.FromSeconds(300), TimeSpan.FromSeconds(600));
        Assert.Equal(2L, await RefreshRowsAsync(flow, Lasting("1 day")));
    }

    [Fact]
    public async Task A_lifetime_saved_after_the_code_exchange_applies_from_the_next_refresh()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var issued = await OfflineAsync(host, flow);
        AssertLifetimes(issued, SecurityLimits.DefaultAccessTokenLifetime, SecurityLimits.DefaultIdentityTokenLifetime);

        await SetAsync(flow, flow.ClientA.ApplicationId, 120, 240, 2592000, 604800);
        using var refreshed = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, issued.RefreshToken);

        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        AssertLifetimes(refreshed, TimeSpan.FromSeconds(120), TimeSpan.FromSeconds(240));
    }

    [Fact]
    public async Task A_machine_Applications_client_credentials_token_uses_its_access_lifetime()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var machine = await flow.Database.CreateClientAsync(flow.A.TenantId);
        await SetAsync(flow, machine.ApplicationId, 120, 900, 2592000, 604800);
        await using var host = await flow.StartHostAsync();

        using var response = await ClientCredentialsTests.TokenAsync(host, HostA, machine.ClientId, machine.Secret);

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Equal(120, response.Body.RootElement.GetProperty("expires_in").GetInt32());
        var token = new JsonWebToken(response.AccessToken);
        Assert.Equal(TimeSpan.FromSeconds(120), token.ValidTo - token.IssuedAt);

        // Another Application's lifetimes are its own: the web client still issues for the defaults.
        using var other = await OfflineAsync(host, flow);
        AssertLifetimes(other, SecurityLimits.DefaultAccessTokenLifetime, SecurityLimits.DefaultIdentityTokenLifetime);
    }

    /// <summary>Story 3.7's shorter-wins row (FR-15): an Application's 900 seconds and its API's 300 issue a 300-second token.</summary>
    [Fact]
    public async Task A_client_credentials_token_lives_the_shorter_of_its_Applications_and_its_APIs_lifetime()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var machine = await flow.Database.CreateClientAsync(flow.A.TenantId);
        await SetAsync(flow, machine.ApplicationId, 900, 900, 2592000, 604800);
        await flow.Database.ExecuteAsync(
            $"UPDATE api SET access_token_lifetime = 300 WHERE tenant_id = '{flow.A.TenantId}' AND identifier = '{ProtocolDatabase.TestApi}'");
        await using var host = await flow.StartHostAsync();

        using var response = await ClientCredentialsTests.TokenAsync(host, HostA, machine.ClientId, machine.Secret);

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Equal(300, response.Body.RootElement.GetProperty("expires_in").GetInt32());
        var token = new JsonWebToken(response.AccessToken);
        Assert.Equal(TimeSpan.FromSeconds(300), token.ValidTo - token.IssuedAt);

        // The API's longer lifetime never lengthens the Application's shorter one.
        await SetAsync(flow, machine.ApplicationId, 120, 900, 2592000, 604800);
        using var shorter = await ClientCredentialsTests.TokenAsync(host, HostA, machine.ClientId, machine.Secret);
        Assert.Equal(120, shorter.Body.RootElement.GetProperty("expires_in").GetInt32());
    }

    /// <summary>
    /// Story 3.7's shorter-wins row on the code flow (FR-15): an authorization naming an API whose access and refresh absolute
    /// lifetimes are shorter than its Application's issues the exchange's and each refresh's tokens for the API's, and caps
    /// every refresh token of the family at the API's absolute end.
    /// </summary>
    [Fact]
    public async Task A_code_flow_naming_an_API_lives_the_shorter_of_its_Applications_and_its_APIs_lifetimes()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await flow.Database.ExecuteAsync(
            $"UPDATE api SET offline_access = true, access_token_lifetime = 300, refresh_token_absolute_lifetime = 3600 " +
            $"WHERE tenant_id = '{flow.A.TenantId}' AND identifier = '{ProtocolDatabase.TestApi}'");
        await using var host = await flow.StartHostAsync();

        var pkce = Pkce.New();
        using var authorize = await CodeFlow.AuthorizeAsync(
            host, HostA, flow.ClientA.ClientId, CodeFlowSetup.Callback, pkce, flow.UserA, scope: Offline, extra: [("resource", ProtocolDatabase.TestApi)]);
        var code = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(authorize.Headers.Location!.Query)["code"].ToString();
        using var issued = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, CodeFlowSetup.Callback, pkce.Verifier);

        Assert.Equal(HttpStatusCode.OK, issued.Status);
        AssertLifetimes(issued, TimeSpan.FromSeconds(300), SecurityLimits.DefaultIdentityTokenLifetime);
        Assert.Equal(1L, await RefreshRowsAsync(flow, Lasting("1 hour")));

        using var refreshed = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, issued.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        AssertLifetimes(refreshed, TimeSpan.FromSeconds(300), SecurityLimits.DefaultIdentityTokenLifetime);
        Assert.Equal(2L, await RefreshRowsAsync(flow, Lasting("1 hour")));
    }

    [Fact]
    public async Task A_public_clients_refresh_uses_its_own_lifetimes()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var (applicationId, clientId) = await flow.Database.CreateApplicationAsync(flow.A.TenantId, "spa");
        await flow.Database.ExecuteAsync(
            $"UPDATE application SET redirect_uris = ARRAY['{CodeFlowSetup.Callback}'], grant_types = ARRAY['authorization_code', 'refresh_token'] WHERE id = '{applicationId}'");
        await SetAsync(flow, applicationId, 60, 90, 2592000, 7200);
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
        AssertLifetimes(issued, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(90));

        using var refreshed = await PublicAsync(host, clientId, new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = issued.RefreshToken,
        });
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        AssertLifetimes(refreshed, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(90));
        Assert.Equal(2L, await RefreshRowsAsync(flow, Lasting("2 hours")));
    }

    [Fact]
    public async Task A_shortened_inactivity_lifetime_ends_a_refresh_token_unused_that_long()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await SetAsync(flow, flow.ClientA.ApplicationId, 900, 900, 2592000, 3600);
        var time = new ShiftedTimeProvider();
        await using var host = await flow.StartHostAsync(time);

        using var issued = await OfflineAsync(host, flow);
        Assert.Equal(1L, await RefreshRowsAsync(flow, Lasting("1 hour")));

        time.Advance(TimeSpan.FromHours(1) + TimeSpan.FromSeconds(1));
        using var refused = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, issued.RefreshToken);

        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("invalid_grant", refused.Error);
        Assert.False(refused.Body.RootElement.TryGetProperty("access_token", out _));
    }

    [Fact]
    public async Task A_shortened_absolute_lifetime_ends_an_older_family_at_its_next_refresh()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var time = new ShiftedTimeProvider();
        await using var host = await flow.StartHostAsync(time);

        using var issued = await OfflineAsync(host, flow);

        // Three days on, the family is within the default 30 days and its token within its 7: it refreshes.
        time.Advance(TimeSpan.FromDays(3));
        using var ok = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, issued.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, ok.Status);

        // Shortened to 2 days, the 3-day-old family is past its end: the next refresh is refused, and nothing revoked.
        await SetAsync(flow, flow.ClientA.ApplicationId, 900, 900, 172800, 604800);
        using var refused = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, ok.RefreshToken);

        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("invalid_grant", refused.Error);
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND status = 'revoked'"));
    }

    [Fact]
    public async Task A_refresh_token_never_outlives_its_familys_absolute_end()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);

        // An absolute lifetime shorter than the inactivity one: every refresh token stops at the family's end.
        await SetAsync(flow, flow.ClientA.ApplicationId, 900, 900, 7200, 86400);
        await using var host = await flow.StartHostAsync();

        using var issued = await OfflineAsync(host, flow);

        var familyEnd = "a.creation_date + interval '2 hours'";
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM token t JOIN \"authorization\" a ON a.tenant_id = t.tenant_id AND a.id = t.authorization_id WHERE t.tenant_id = '{flow.A.TenantId}' AND t.type = '{RefreshType}' AND t.expiration_date > {familyEnd}"));
        Assert.Equal(1L, await RefreshRowsAsync(flow, "expiration_date - creation_date <= interval '2 hours'"));
    }

    /// <summary>Writes an Application's four lifetimes, in seconds, as the tokens save writes them.</summary>
    private static Task SetAsync(CodeFlowSetup flow, Guid applicationId, int access, int id, int absolute, int inactivity) =>
        flow.Database.ExecuteAsync(
            $"UPDATE application SET access_token_lifetime = {access}, id_token_lifetime = {id}, refresh_token_absolute_lifetime = {absolute}, " +
            $"refresh_token_inactivity_lifetime = {inactivity} WHERE id = '{applicationId}'");

    /// <summary>A code flow with <c>offline_access</c> for the setup's User and web client in Tenant A, exchanged.</summary>
    private static async Task<TokenResponse> OfflineAsync(ProtocolHost host, CodeFlowSetup flow)
    {
        var pkce = Pkce.New();
        var code = await CodeFlow.CodeAsync(host, HostA, flow.ClientA.ClientId, CodeFlowSetup.Callback, pkce, flow.UserA, scope: Offline);
        var issued = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, CodeFlowSetup.Callback, pkce.Verifier);
        Assert.Equal(HttpStatusCode.OK, issued.Status);
        return issued;
    }

    /// <summary>A token request as a public client sends it: its client_id in the form, and no secret.</summary>
    private static async Task<TokenResponse> PublicAsync(ProtocolHost host, string clientId, Dictionary<string, string> form)
    {
        form["client_id"] = clientId;
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"http://{HostA}{Gatekeep.Modules.Protocol.Contracts.ProtocolContract.TokenPath}"))
        {
            Content = new FormUrlEncodedContent(form),
        };
        var response = await host.Http.SendAsync(request, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return new TokenResponse(response, System.Text.Json.JsonDocument.Parse(body));
    }

    /// <summary>The access token's <c>exp</c> − <c>iat</c> and <c>expires_in</c>, and the ID token's <c>exp</c> − <c>iat</c>.</summary>
    private static void AssertLifetimes(TokenResponse response, TimeSpan access, TimeSpan identity)
    {
        var token = new JsonWebToken(response.AccessToken);
        Assert.Equal(access, token.ValidTo - token.IssuedAt);
        Assert.Equal((int)access.TotalSeconds, response.Body.RootElement.GetProperty("expires_in").GetInt32());
        var id = new JsonWebToken(response.Body.RootElement.GetProperty("id_token").GetString()!);
        Assert.Equal(identity, id.ValidTo - id.IssuedAt);
    }

    /// <summary>A refresh token row that lasts <paramref name="interval"/> from its issue, to within its row's stamping.</summary>
    private static string Lasting(string interval) =>
        $"expiration_date - creation_date BETWEEN interval '{interval}' - interval '1 minute' AND interval '{interval}'";

    private static Task<long> RefreshRowsAsync(CodeFlowSetup flow, string condition) =>
        flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND type = '{RefreshType}' AND ({condition})");
}
