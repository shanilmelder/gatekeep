using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Gatekeep.Tests.Isolation.Applications;

/// <summary>
/// Story 3.2's protocol rows (FR-11, FR-13, RFC 8252, RFC 9700) through the real Tenant resolution and
/// Protocol registration as <c>gk_hosted</c>, with the test-only sign-in: single-page and native
/// Applications are public clients that exchange a code with PKCE and no secret, and are refused when they
/// send one; only a native Application's loopback redirect URI may differ in port; and a grant turned off
/// is refused at the authorization endpoint, with the static page and no redirect, and at the token
/// endpoint, with <c>unauthorized_client</c>. Each Application's settings are written as the save writes
/// them, to the row.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class ApplicationSettingsProtocolTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.settings.test";

    private const string HostB = "beta.settings.test";

    private const string Callback = "https://app.settings.test/cb";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("spa", "https://app.settings.test/cb")]
    [InlineData("native", "com.example.app:/cb")]
    public async Task A_public_client_exchanges_its_code_with_PKCE_and_no_secret(string kind, string callback)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var clientId = await PublicClientAsync(flow, kind, [callback]);
        await using var host = await flow.StartHostAsync();

        var pkce = Pkce.New();
        var code = await CodeFlow.CodeAsync(host, HostA, clientId, callback, pkce, flow.UserA);
        using var issued = await ExchangeAsync(host, clientId, code, callback, pkce.Verifier);

        Assert.Equal(HttpStatusCode.OK, issued.Status);
        Assert.True(issued.Body.RootElement.TryGetProperty("access_token", out _));
        Assert.True(issued.Body.RootElement.TryGetProperty("id_token", out _));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM \"authorization\" a JOIN application p ON p.tenant_id = a.tenant_id AND p.id = a.application_id WHERE p.kind = '{kind}'"));
    }

    [Theory]
    [InlineData("spa")]
    [InlineData("native")]
    public async Task A_public_client_that_sends_a_secret_or_no_verifier_gets_no_token(string kind)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var clientId = await PublicClientAsync(flow, kind, [Callback]);
        await using var host = await flow.StartHostAsync();
        var shaped = $"{PublicId.Format(PublicIdType.Tenant, flow.A.TenantId)}.{Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32))}";

        foreach (var secret in new[] { shaped, "anything" })
        {
            var pkce = Pkce.New();
            var code = await CodeFlow.CodeAsync(host, HostA, clientId, Callback, pkce, flow.UserA);
            using var refused = await ExchangeAsync(host, clientId, code, Callback, pkce.Verifier, secret);

            Assert.Equal("invalid_client", refused.Error);
            Assert.False(refused.Body.RootElement.TryGetProperty("access_token", out _));

            // Sent by Basic, the same.
            using var basic = await CodeFlow.ExchangeAsync(host, HostA, clientId, secret, code, Callback, pkce.Verifier);
            Assert.Equal("invalid_client", basic.Error);
        }

        var unverified = Pkce.New();
        var unverifiedCode = await CodeFlow.CodeAsync(host, HostA, clientId, Callback, unverified, flow.UserA);
        using var noVerifier = await ExchangeAsync(host, clientId, unverifiedCode, Callback, verifier: null);
        Assert.NotNull(noVerifier.Error);
        Assert.False(noVerifier.Body.RootElement.TryGetProperty("access_token", out _));

        // PKCE is required at authorize too: no challenge is an error sent back to the trusted callback.
        using var noChallenge = await CodeFlow.AuthorizeAsync(host, HostA, clientId, Callback, pkce: null, flow.UserA);
        Assert.Equal(HttpStatusCode.Found, noChallenge.StatusCode);
        Assert.True(QueryHelpers.ParseQuery(noChallenge.Headers.Location!.Query).ContainsKey("error"));
    }

    /// <summary>A confidential client still needs its secret: sending none is invalid_client, as before.</summary>
    [Fact]
    public async Task A_confidential_client_sending_no_secret_is_still_invalid_client()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        var pkce = Pkce.New();
        var code = await CodeFlow.CodeAsync(host, HostA, flow.ClientA.ClientId, CodeFlowSetup.Callback, pkce, flow.UserA);
        using var refused = await ExchangeAsync(host, flow.ClientA.ClientId, code, CodeFlowSetup.Callback, pkce.Verifier);

        Assert.Equal("invalid_client", refused.Error);
        Assert.False(refused.Body.RootElement.TryGetProperty("access_token", out _));
    }

    [Theory]
    [InlineData("http://127.0.0.1/cb", "http://127.0.0.1:51004/cb")]
    [InlineData("http://[::1]:8080/cb", "http://[::1]:51004/cb")]
    [InlineData("http://127.0.0.1:8080/cb", "http://127.0.0.1/cb")]
    public async Task A_native_loopback_redirect_may_differ_in_port_and_its_code_is_exchanged_on_that_port(string registered, string requested)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var clientId = await PublicClientAsync(flow, "native", [registered]);
        await using var host = await flow.StartHostAsync();

        var pkce = Pkce.New();
        using var authorize = await CodeFlow.AuthorizeAsync(host, HostA, clientId, requested, pkce, flow.UserA);

        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        var location = authorize.Headers.Location!;
        Assert.StartsWith(requested + "?", location.OriginalString, StringComparison.Ordinal);
        var code = QueryHelpers.ParseQuery(location.Query)["code"].ToString();
        Assert.False(string.IsNullOrEmpty(code));

        using var issued = await ExchangeAsync(host, clientId, code, requested, pkce.Verifier);
        Assert.Equal(HttpStatusCode.OK, issued.Status);
    }

    [Theory]
    [InlineData("web")]
    [InlineData("spa")]
    [InlineData("native")]
    public async Task Any_other_redirect_is_matched_exactly_and_refused_with_the_static_page(string kind)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var clientId = kind == "web"
            ? await WebClientAsync(flow, ["http://127.0.0.1/cb", "https://app.settings.test/cb"])
            : await PublicClientAsync(flow, kind, ["http://127.0.0.1/cb", "https://app.settings.test/cb"]);
        await using var host = await flow.StartHostAsync();

        var refused = new List<string> { "http://localhost:51004/cb", "https://app.settings.test/cb/", "https://app.settings.test:443/cb", "http://127.0.0.1:51004/cb/" };
        if (kind != "native")
        {
            // The port exception is a native Application's alone.
            refused.Add("http://127.0.0.1:51004/cb");
        }

        foreach (var redirectUri in refused)
        {
            using var response = await CodeFlow.AuthorizeAsync(host, HostA, clientId, redirectUri, Pkce.New(), flow.UserA, state: "echo-me-not");
            await AssertStaticPageAsync(response, redirectUri);
        }

        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM \"authorization\""));
    }

    [Theory]
    [InlineData("web")]
    [InlineData("spa")]
    [InlineData("native")]
    public async Task Authorize_without_authorization_code_is_the_static_page_and_never_a_redirect(string kind)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var clientId = kind == "web"
            ? flow.ClientA.ClientId
            : await PublicClientAsync(flow, kind, [CodeFlowSetup.Callback]);
        await flow.Database.ExecuteAsync(
            $"UPDATE application SET grant_types = '{{}}' WHERE tenant_id = '{flow.A.TenantId}' AND id = '{IdOf(clientId)}'");
        await using var host = await flow.StartHostAsync();

        using var response = await CodeFlow.AuthorizeAsync(host, HostA, clientId, CodeFlowSetup.Callback, Pkce.New(), flow.UserA, state: "echo-me-not");

        await AssertStaticPageAsync(response, CodeFlowSetup.Callback);
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM signin_transaction"));
    }

    [Fact]
    public async Task A_refresh_after_the_refresh_grant_is_turned_off_is_unauthorized_client()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var pkce = Pkce.New();
        var code = await CodeFlow.CodeAsync(host, HostA, flow.ClientA.ClientId, CodeFlowSetup.Callback, pkce, flow.UserA, scope: "openid offline_access");
        using var issued = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, CodeFlowSetup.Callback, pkce.Verifier);
        Assert.Equal(HttpStatusCode.OK, issued.Status);

        await flow.Database.ExecuteAsync($"UPDATE application SET grant_types = ARRAY['authorization_code'] WHERE id = '{flow.ClientA.ApplicationId}'");
        using var refused = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, issued.RefreshToken);

        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("unauthorized_client", refused.Error);
        Assert.False(refused.Body.RootElement.TryGetProperty("access_token", out _));
    }

    [Fact]
    public async Task Client_credentials_for_a_machine_Application_with_no_grants_is_unauthorized_client()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var machine = await flow.Database.CreateClientAsync(flow.A.TenantId);
        await flow.Database.ExecuteAsync($"UPDATE application SET grant_types = '{{}}' WHERE id = '{machine.ApplicationId}'");
        await using var host = await flow.StartHostAsync();

        using var refused = await ClientCredentialsTests.TokenAsync(host, HostA, machine.ClientId, machine.Secret);

        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("unauthorized_client", refused.Error);
    }

    /// <summary>A single-page or native Application with the settings given, as the save stores them: the code grant, sorted.</summary>
    private static async Task<string> PublicClientAsync(CodeFlowSetup flow, string kind, string[] callbacks)
    {
        var (applicationId, clientId) = await flow.Database.CreateApplicationAsync(flow.A.TenantId, kind);
        await flow.Database.ExecuteAsync(
            $"UPDATE application SET redirect_uris = {SqlArray(callbacks)}, grant_types = ARRAY['authorization_code'] WHERE id = '{applicationId}'");
        return clientId;
    }

    /// <summary>A regular web Application, with a secret, and only <paramref name="callbacks"/>.</summary>
    private static async Task<string> WebClientAsync(CodeFlowSetup flow, string[] callbacks)
    {
        var (_, clientId, _) = await flow.Database.CreateWebClientAsync(flow.A.TenantId, callbacks);
        return clientId;
    }

    private static string SqlArray(string[] values) => $"ARRAY[{string.Join(", ", values.Select(v => $"'{v.Replace("'", "''", StringComparison.Ordinal)}'"))}]::text[]";

    private static Guid IdOf(string clientId) =>
        PublicId.TryParse(PublicIdType.Application, clientId, out var id) ? id : throw new ArgumentException("Not an app_ ID.", nameof(clientId));

    /// <summary>A code exchange as a public client sends it: the client_id in the form, and a secret only when one is given.</summary>
    private static async Task<TokenResponse> ExchangeAsync(ProtocolHost host, string clientId, string code, string redirectUri, string? verifier, string? secret = null)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = clientId,
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
        };
        if (verifier is not null)
        {
            form["code_verifier"] = verifier;
        }

        if (secret is not null)
        {
            form["client_secret"] = secret;
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"http://{HostA}{ProtocolContract.TokenPath}"))
        {
            Content = new FormUrlEncodedContent(form),
        };
        var response = await host.Http.SendAsync(request, Cancellation);
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        return new TokenResponse(response, JsonDocument.Parse(body));
    }

    private static async Task AssertStaticPageAsync(HttpResponseMessage response, string redirectUri)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        Assert.Contains("<h1>Something went wrong</h1>", body, StringComparison.Ordinal);
        Assert.DoesNotContain("echo-me-not", body, StringComparison.Ordinal);
        Assert.DoesNotContain(redirectUri, body, StringComparison.Ordinal);
    }
}
