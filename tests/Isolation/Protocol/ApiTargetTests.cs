using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Protocol;

/// <summary>
/// Story 3.7's token rows (FR-16, FR-15, RFC 8707, AD-33): the API a request names, by <c>resource</c> or <c>audience</c>,
/// is its access token's <c>aud</c>; a Client Credentials token carries exactly the Permissions it is granted now, narrowed
/// to its <c>scope</c>, as the <c>permissions</c> array and the <c>scope</c> claim; the Management API is refused at
/// <c>Host.Hosted</c>; and an API's offline access decides whether a refresh token is issued, at the code exchange and at
/// each refresh. Through the real Tenant resolution and Protocol registration as <c>gk_hosted</c>; grants are written the
/// one Directory way, as <c>gk_admin</c>.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class ApiTargetTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.targets.test";
    private const string HostB = "beta.targets.test";
    private const string Invoices = "https://api.ex";
    private const string Offline = "openid offline_access";

    private static readonly IDirectory Directory = DirectoryContract.CreateDirectory(AuditContract.CreateAppender(), TimeProvider.System);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("resource")]
    [InlineData("audience")]
    public async Task A_granted_client_gets_its_API_as_aud_and_every_granted_Permission(string parameter)
    {
        var (flow, _, machine) = await GrantedAsync(["invoices:read", "payments:write"]);
        await using var host = await flow.StartHostAsync();

        using var response = await ClientCredentialsTests.TokenAsync(host, HostA, machine.ClientId, machine.Secret, extra: (parameter, Invoices));

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Equal("invoices:read payments:write", response.Body.RootElement.GetProperty("scope").GetString());
        var token = new JsonWebToken(response.AccessToken);
        Assert.Equal([Invoices], token.Audiences);
        Assert.Equal(["invoices:read", "payments:write"], Permissions(token));
        Assert.Equal("invoices:read payments:write", token.GetPayloadValue<string>("scope"));
    }

    [Fact]
    public async Task A_requested_scope_narrows_the_Permissions_and_an_ungranted_one_is_dropped_silently()
    {
        var (flow, _, machine) = await GrantedAsync(["invoices:read", "payments:write"]);
        await using var host = await flow.StartHostAsync();

        using var response = await TokenAsync(host, machine, ("resource", Invoices), ("scope", "invoices:read admin:all"));

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Equal("invoices:read", response.Body.RootElement.GetProperty("scope").GetString());
        var token = new JsonWebToken(response.AccessToken);
        Assert.Equal(["invoices:read"], Permissions(token));
        Assert.Equal("invoices:read", token.GetPayloadValue<string>("scope"));
    }

    [Fact]
    public async Task A_narrowed_grant_and_a_removed_Permission_are_gone_from_the_next_token()
    {
        var (flow, api, machine) = await GrantedAsync(["invoices:read", "payments:write", "reports:read"]);
        await using var host = await flow.StartHostAsync();

        await AsAdminAsync(flow, c => Directory.SetApiGrantAsync(c, Actor.System, api, machine.ApplicationId, ["invoices:read", "reports:read"], Cancellation));
        using (var narrowed = await ClientCredentialsTests.TokenAsync(host, HostA, machine.ClientId, machine.Secret, extra: ("resource", Invoices)))
        {
            Assert.Equal(["invoices:read", "reports:read"], Permissions(new JsonWebToken(narrowed.AccessToken)));
        }

        // Removing a Permission removes its grant rows in the same command.
        var removed = await AsAdminAsync(flow, c => Directory.RemovePermissionAsync(c, Actor.System, api, "reports:read", Cancellation));
        Assert.Equal(PermissionWriteStatus.Done, removed.Status);
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM api_grant WHERE api_id = '{api}' AND value = 'reports:read'"));

        using var next = await ClientCredentialsTests.TokenAsync(host, HostA, machine.ClientId, machine.Secret, extra: ("resource", Invoices));
        Assert.Equal(["invoices:read"], Permissions(new JsonWebToken(next.AccessToken)));

        // And with the grant removed, a token still names the API, with no Permission at all.
        await AsAdminAsync(flow, c => Directory.RemoveApiGrantAsync(c, Actor.System, api, machine.ApplicationId, Cancellation));
        using var none = await ClientCredentialsTests.TokenAsync(host, HostA, machine.ClientId, machine.Secret, extra: ("resource", Invoices));
        AssertNoPermissions(none, Invoices);
    }

    [Fact]
    public async Task A_client_never_granted_gets_the_API_as_aud_and_no_Permission()
    {
        var (flow, _, _) = await GrantedAsync(["invoices:read"]);
        var other = await flow.Database.CreateClientAsync(flow.A.TenantId, "Never granted");
        await using var host = await flow.StartHostAsync();

        using var response = await TokenAsync(host, other, ("resource", Invoices), ("scope", "invoices:read"));

        AssertNoPermissions(response, Invoices);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("unknown")]
    [InlineData("both")]
    [InlineData("two")]
    [InlineData("management")]
    [InlineData("other-tenant")]
    public async Task A_missing_unknown_doubled_or_Management_API_is_invalid_target(string shape)
    {
        var (flow, _, machine) = await GrantedAsync(["invoices:read"]);
        await EnsureBuiltInAsync(flow, flow.A.TenantId);
        await flow.Database.ExecuteAsync(
            $"INSERT INTO api (tenant_id, id, name, identifier, created_at) VALUES ('{flow.B.TenantId}', '{Guid.CreateVersion7()}', 'B only', 'https://b-only.ex', now())");

        await using var host = await flow.StartHostAsync();

        (string, string)[] parameters = shape switch
        {
            "none" => [],
            "unknown" => [("resource", "https://nope")],
            "both" => [("resource", Invoices), ("audience", Invoices)],
            "two" => [("resource", Invoices), ("resource", ProtocolDatabase.TestApi)],
            "management" => [("resource", DirectoryContract.ManagementApiIdentifier)],
            "other-tenant" => [("resource", "https://b-only.ex")],
            _ => throw new ArgumentOutOfRangeException(nameof(shape)),
        };

        using var response = await TokenAsync(host, machine, parameters);

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_target", response.Error);
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}'"));
    }

    [Fact]
    public async Task A_code_flow_naming_an_API_gets_it_as_aud_and_a_refresh_token_only_while_its_offline_access_is_on()
    {
        var (flow, api, _) = await GrantedAsync(["invoices:read"]);
        await SetOfflineAsync(flow, api, true);
        await using var host = await flow.StartHostAsync();

        // Offline access on: the exchange returns a refresh token, and the access token names the API.
        using var issued = await CodeFlowAsync(host, flow, Offline, exchangeResource: Invoices);
        Assert.True(issued.Status == HttpStatusCode.OK, issued.Body.RootElement.GetRawText());
        Assert.Equal([Invoices], new JsonWebToken(issued.AccessToken).Audiences);
        Assert.False(new JsonWebToken(issued.AccessToken).TryGetPayloadValue<object>("permissions", out _));
        var refreshToken = issued.RefreshToken;

        // A refresh re-reads the API: still on, still a refresh token, still the API as aud.
        using (var refreshed = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, refreshToken))
        {
            Assert.Equal(HttpStatusCode.OK, refreshed.Status);
            Assert.Equal([Invoices], new JsonWebToken(refreshed.AccessToken).Audiences);
            refreshToken = refreshed.RefreshToken;
        }

        // Turned off later: the next refresh issues a new access token and no new refresh token.
        await SetOfflineAsync(flow, api, false);
        using (var last = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, refreshToken))
        {
            Assert.Equal(HttpStatusCode.OK, last.Status);
            Assert.Equal([Invoices], new JsonWebToken(last.AccessToken).Audiences);
            Assert.False(last.Body.RootElement.TryGetProperty("refresh_token", out _));
        }

        // Off at the exchange: no refresh token at all, though offline_access was asked for and allowed.
        using var off = await CodeFlowAsync(host, flow, Offline, exchangeResource: null);
        Assert.Equal(HttpStatusCode.OK, off.Status);
        Assert.Equal([Invoices], new JsonWebToken(off.AccessToken).Audiences);
        Assert.False(off.Body.RootElement.TryGetProperty("refresh_token", out _));
    }

    [Fact]
    public async Task A_refresh_for_an_API_since_removed_is_invalid_grant()
    {
        var (flow, api, _) = await GrantedAsync(["invoices:read"]);
        await SetOfflineAsync(flow, api, true);
        await using var host = await flow.StartHostAsync();

        using var issued = await CodeFlowAsync(host, flow, Offline, exchangeResource: null);
        Assert.Equal(HttpStatusCode.OK, issued.Status);

        await flow.Database.ExecuteAsync(
            $"DELETE FROM api_grant WHERE api_id = '{api}'; DELETE FROM permission WHERE api_id = '{api}'; DELETE FROM api WHERE id = '{api}'");

        using var refused = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, issued.RefreshToken);
        Assert.True(refused.Status == HttpStatusCode.BadRequest, refused.Body.RootElement.GetRawText());
        Assert.Equal("invalid_grant", refused.Error);
    }

    [Theory]
    [InlineData("https://nope", "invalid_target")]
    [InlineData(DirectoryContract.ManagementApiIdentifier, "invalid_target")]
    [InlineData(null, "invalid_target")]
    public async Task An_authorization_naming_no_available_API_or_two_is_an_invalid_target_redirect(string? resource, string error)
    {
        var (flow, _, _) = await GrantedAsync(["invoices:read"]);
        await EnsureBuiltInAsync(flow, flow.A.TenantId);
        await using var host = await flow.StartHostAsync();

        (string, string)[] extra = resource is null ? [("resource", Invoices), ("audience", Invoices)] : [("resource", resource)];
        using var authorize = await CodeFlow.AuthorizeAsync(
            host, HostA, flow.ClientA.ClientId, CodeFlowSetup.Callback, Pkce.New(), flow.UserA, state: "s", extra: extra);

        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        var query = QueryHelpers.ParseQuery(authorize.Headers.Location!.Query);
        Assert.Equal(error, query["error"].ToString());
        Assert.False(query.ContainsKey("code"));
    }

    [Fact]
    public async Task A_code_exchange_and_a_refresh_may_repeat_their_authorizations_API()
    {
        var (flow, api, _) = await GrantedAsync(["invoices:read"]);
        await SetOfflineAsync(flow, api, true);
        await using var host = await flow.StartHostAsync();

        using var issued = await CodeFlowAsync(host, flow, Offline, exchangeResource: Invoices);
        Assert.Equal(HttpStatusCode.OK, issued.Status);
        Assert.Equal([Invoices], new JsonWebToken(issued.AccessToken).Audiences);

        using var refreshed = await PostAsync(
            host,
            flow.ClientA.ClientId,
            flow.ClientA.Secret,
            [new("grant_type", "refresh_token"), new("refresh_token", issued.RefreshToken), new("resource", Invoices)]);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        Assert.Equal([Invoices], new JsonWebToken(refreshed.AccessToken).Audiences);
    }

    [Fact]
    public async Task A_client_credentials_scope_of_only_ungranted_values_gets_a_token_with_no_Permission()
    {
        var (flow, _, machine) = await GrantedAsync(["invoices:read"]);
        await using var host = await flow.StartHostAsync();

        using var response = await TokenAsync(host, machine, ("resource", Invoices), ("scope", "admin:all reports:read"));

        AssertNoPermissions(response, Invoices);
    }

    [Fact]
    public async Task A_code_exchange_naming_another_API_than_its_authorization_is_invalid_target()
    {
        var (flow, _, _) = await GrantedAsync(["invoices:read"]);
        await using var host = await flow.StartHostAsync();

        using var other = await CodeFlowAsync(host, flow, "openid", exchangeResource: ProtocolDatabase.TestApi);
        Assert.Equal(HttpStatusCode.BadRequest, other.Status);
        Assert.Equal("invalid_target", other.Error);

        // An API the authorization never named, on a code exchange without one, is refused the same way.
        using var none = await CodeFlowAsync(host, flow, "openid", exchangeResource: Invoices, authorizeResource: null);
        Assert.Equal(HttpStatusCode.BadRequest, none.Status);
        Assert.Equal("invalid_target", none.Error);
    }

    [Fact]
    public async Task A_users_code_flow_naming_an_API_gets_no_Permission_scope_even_when_it_asks()
    {
        var (flow, _, _) = await GrantedAsync(["invoices:read"]);
        await using var host = await flow.StartHostAsync();

        using var issued = await CodeFlowAsync(host, flow, "openid invoices:read", exchangeResource: null);

        Assert.Equal(HttpStatusCode.OK, issued.Status);
        var token = new JsonWebToken(issued.AccessToken);
        Assert.Equal([Invoices], token.Audiences);
        Assert.False(token.TryGetPayloadValue<object>("permissions", out _));
        Assert.DoesNotContain("invoices:read", token.TryGetPayloadValue<string>("scope", out var scope) ? scope : string.Empty, StringComparison.Ordinal);
    }

    /// <summary>
    /// A code flow setup with an API identified by <see cref="Invoices"/> in Tenant A, offline access off, holding
    /// <c>invoices:read</c>, <c>payments:write</c>, <c>reports:read</c> and <c>admin:all</c>, and a machine client granted
    /// <paramref name="granted"/> through Directory.
    /// </summary>
    private async Task<(CodeFlowSetup Flow, Guid Api, (Guid ApplicationId, string ClientId, string Secret) Machine)> GrantedAsync(string[] granted)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var api = Guid.CreateVersion7();
        await flow.Database.ExecuteAsync(
            $"INSERT INTO api (tenant_id, id, name, identifier, created_at) VALUES ('{flow.A.TenantId}', '{api}', 'Invoices', '{Invoices}', now()); " +
            "INSERT INTO permission (tenant_id, api_id, value, created_at) SELECT " +
            $"'{flow.A.TenantId}', '{api}', v, now() FROM unnest(ARRAY['payments:write', 'invoices:read', 'reports:read', 'admin:all']) AS v");
        var machine = await flow.Database.CreateClientAsync(flow.A.TenantId);
        var write = await AsAdminAsync(flow, c => Directory.SetApiGrantAsync(c, Actor.System, api, machine.ApplicationId, granted, Cancellation));
        Assert.Equal(ApiGrantWriteStatus.Done, write.Status);
        return (flow, api, machine);
    }

    private async Task<T> AsAdminAsync<T>(CodeFlowSetup flow, Func<CommandContext, Task<T>> call)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, flow.Database.Name));
        await using var scope = await TenantScope.BeginAsync(source, flow.A.TenantId, Cancellation);
        var result = await call(scope.CreateCommandContext());
        await scope.CommitAsync(Cancellation);
        return result;
    }

    private async Task EnsureBuiltInAsync(CodeFlowSetup flow, Guid tenant)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Worker, flow.Database.Name));
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        await Directory.EnsureBuiltInApiAsync(scope.CreateCommandContext(), Cancellation);
        await scope.CommitAsync(Cancellation);
    }

    private static Task SetOfflineAsync(CodeFlowSetup flow, Guid api, bool on) =>
        flow.Database.ExecuteAsync($"UPDATE api SET offline_access = {(on ? "true" : "false")} WHERE id = '{api}'");

    /// <summary>
    /// A code flow for the setup's User and web client, the authorization naming <paramref name="authorizeResource"/> and
    /// the exchange <paramref name="exchangeResource"/>, each by <c>resource</c> when not null.
    /// </summary>
    private static async Task<TokenResponse> CodeFlowAsync(
        ProtocolHost host, CodeFlowSetup flow, string scope, string? exchangeResource, string? authorizeResource = Invoices)
    {
        var pkce = Pkce.New();
        using var authorize = await CodeFlow.AuthorizeAsync(
            host,
            HostA,
            flow.ClientA.ClientId,
            CodeFlowSetup.Callback,
            pkce,
            flow.UserA,
            scope: scope,
            extra: authorizeResource is null ? null : [("resource", authorizeResource)]);
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        var query = QueryHelpers.ParseQuery(authorize.Headers.Location!.Query);
        Assert.False(query.TryGetValue("error", out var error), $"The authorization request failed: {error}, {query.GetValueOrDefault("error_description")}.");

        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "authorization_code"),
            new("code", query["code"].ToString()),
            new("redirect_uri", CodeFlowSetup.Callback),
            new("code_verifier", pkce.Verifier),
        };
        if (exchangeResource is not null)
        {
            form.Add(new("resource", exchangeResource));
        }

        return await PostAsync(host, flow.ClientA.ClientId, flow.ClientA.Secret, form);
    }

    /// <summary>A Client Credentials request with exactly <paramref name="parameters"/>, repeats kept, by Basic.</summary>
    private static Task<TokenResponse> TokenAsync(
        ProtocolHost host, (Guid ApplicationId, string ClientId, string Secret) client, params (string Name, string Value)[] parameters) =>
        PostAsync(
            host,
            client.ClientId,
            client.Secret,
            [new("grant_type", "client_credentials"), .. parameters.Select(p => new KeyValuePair<string, string>(p.Name, p.Value))]);

    private static async Task<TokenResponse> PostAsync(ProtocolHost host, string clientId, string secret, List<KeyValuePair<string, string>> form)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"http://{HostA}{ProtocolContract.TokenPath}"))
        {
            Content = new FormUrlEncodedContent(form),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(secret)}")));

        var response = await host.Http.SendAsync(request, Cancellation);
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        return new TokenResponse(response, JsonDocument.Parse(body));
    }

    /// <summary>The token's <c>permissions</c> claim, which must be a JSON array, in order.</summary>
    private static List<string> Permissions(JsonWebToken token)
    {
        using var payload = JsonDocument.Parse(Base64UrlEncoder.Decode(token.EncodedPayload));
        var permissions = payload.RootElement.GetProperty("permissions");
        Assert.Equal(JsonValueKind.Array, permissions.ValueKind);
        return [.. permissions.EnumerateArray().Select(p => p.GetString()!)];
    }

    private static void AssertNoPermissions(TokenResponse response, string audience)
    {
        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.False(response.Body.RootElement.TryGetProperty("scope", out _));
        var token = new JsonWebToken(response.AccessToken);
        Assert.Equal([audience], token.Audiences);
        Assert.False(token.TryGetPayloadValue<object>("permissions", out _));
        Assert.False(token.TryGetPayloadValue<object>("scope", out _));
    }
}
