using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Xunit;

namespace Gatekeep.Tests.Isolation.Identity;

/// <summary>
/// Story 4.7's fixture: Story 4.2's two Tenants, each with Keys provisioned and its database Connection, Tenant A with a web
/// client, and the requests a browser makes to sign up through Hosted Login. The password every test signs up with meets
/// the default policy and holds nothing of the emails used here.
/// </summary>
internal sealed record SignUpFlow(CodeFlowSetup Flow)
{
    /// <summary>A password the default policy accepts, for any email the tests use.</summary>
    public const string Password = "Correct-Horse-7battery";

    /// <summary>A second accepted password, for a second sign-up of one address.</summary>
    public const string OtherPassword = "Another-Horse-8battery";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public ProtocolDatabase Database => Flow.Database;

    public Guid TenantA => Flow.A.TenantId;

    /// <summary>
    /// The two Tenants with their database Connections, sign-up on unless <paramref name="signupEnabled"/> is false. With
    /// <paramref name="verificationOff"/>, Tenant A stores email verification off; it counts only while A is Dev, which
    /// test Tenants are unless a test relabels one.
    /// </summary>
    public static async Task<SignUpFlow> CreateAsync(
        PostgresFixture postgres, OpenBaoFixture bao, string hostA, string hostB, bool signupEnabled = true, bool verificationOff = false)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, hostA, hostB);
        foreach (var tenant in new[] { flow.A.TenantId, flow.B.TenantId })
        {
            await flow.Database.ExecuteAsync(
                $"INSERT INTO connection (tenant_id, id, kind, signup_enabled) VALUES ('{tenant}', gen_random_uuid(), 'database', {(signupEnabled ? "true" : "false")})");
        }

        if (verificationOff)
        {
            await flow.Database.ExecuteAsync(
                $"INSERT INTO tenant_settings (tenant_id, email_verification_off) VALUES ('{flow.A.TenantId}', true) "
                + "ON CONFLICT (tenant_id) DO UPDATE SET email_verification_off = true");
        }

        return new SignUpFlow(flow);
    }

    public Task<ProtocolHost> StartHostAsync(Gatekeep.Modules.Authentication.Contracts.PasswordHashLimits? hashLimits = null) =>
        ProtocolHost.StartAsync(Flow.Database.Hosted, Flow.Bao, hashLimits: hashLimits);

    /// <summary>A browser at Tenant A's Login for a new authorization request of A's web client.</summary>
    public async Task<SignUpBrowser> BeginAsync(ProtocolHost host, string tenantHost)
    {
        var browser = new HostedBrowser(host, tenantHost);
        var pkce = Pkce.New();
        using (var begun = await browser.GetAsync(CodeFlow.AuthorizeUrl(Flow.ClientA.ClientId, CodeFlowSetup.Callback, pkce)))
        {
            Assert.True(HostedBrowser.IsLoginRedirect(begun), $"The authorization request answered {(int)begun.StatusCode}.");
        }

        return new SignUpBrowser(browser, pkce);
    }

    /// <summary>A browser at Tenant A, moved to Signup and through Create account with <paramref name="email"/> and <paramref name="password"/>.</summary>
    public async Task<(SignUpBrowser Browser, JsonDocument Step)> SignUpAsync(ProtocolHost host, string tenantHost, string email, string password = Password)
    {
        var browser = await BeginAsync(host, tenantHost);
        using var signup = await browser.OpenAsync(email);
        Assert.Equal(StepNames.Signup, Name(signup));
        return (browser, await browser.CreateAsync(signup, email, password));
    }

    public Task<long> CountAsync(string sql) => Database.ScalarAsync<long>(sql);

    /// <summary>How many rows of the Tenant's <paramref name="table"/> there are, optionally filtered further.</summary>
    public Task<long> RowsAsync(string table, string? where = null) =>
        Database.ScalarAsync<long>($"SELECT count(*) FROM \"{table}\" WHERE tenant_id = '{TenantA}'{(where is null ? string.Empty : " AND " + where)}");

    /// <summary>How many audit events of <paramref name="code"/> Tenant A's Log holds.</summary>
    public Task<long> EventsAsync(string code) =>
        Database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{TenantA}' AND type_code = '{code}'");

    /// <summary>The ID of Tenant A's User with <paramref name="email"/>.</summary>
    public Task<Guid> UserAsync(string email) =>
        Database.ScalarAsync<Guid>($"SELECT id FROM \"user\" WHERE tenant_id = '{TenantA}' AND lower(email) = lower('{email}')");

    /// <summary>How many verification email jobs Tenant A's job table holds.</summary>
    public Task<long> EmailJobsAsync() =>
        Database.ScalarAsync<long>($"SELECT count(*) FROM job WHERE tenant_id = '{TenantA}' AND type = 'notifications.email.send'");

    public static string Name(JsonDocument step) => step.RootElement.GetProperty("step").GetString()!;

    public static JsonElement Data(JsonDocument step) => step.RootElement.GetProperty("data");

    /// <summary>The hex of the SHA-256 of <paramref name="value"/>'s ASCII bytes, as a link is stored.</summary>
    public static string HashHex(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(value)));

    /// <summary>The link-bound CSRF token of <paramref name="token"/>, derived as the server derives it.</summary>
    public static string LinkCsrf(string token)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(token));
        var input = "gatekeep-link-csrf\0"u8.ToArray().Concat(hash).ToArray();
        return Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(SHA256.HashData(input));
    }

    /// <summary>The verification link page for <paramref name="token"/>, as the email's link opens it.</summary>
    public static string LinkPath(string token) => $"{ProtocolContract.VerifyEmailPath}?token={Uri.EscapeDataString(token)}";

    /// <summary>The step a page embeds.</summary>
    public static async Task<JsonDocument> PageStepAsync(HttpResponseMessage page)
    {
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        return StepPage.Read(await page.Content.ReadAsStringAsync(Cancellation));
    }
}

/// <summary>One browser signing up at a Tenant host: the Hosted Login requests in order, each answering its step.</summary>
internal sealed class SignUpBrowser(HostedBrowser browser, Pkce pkce)
{
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public HostedBrowser Http => browser;

    public Pkce Pkce => pkce;

    /// <summary>The page's current step, from <c>GET /login</c>.</summary>
    public async Task<JsonDocument> PageAsync()
    {
        using var page = await browser.GetAsync(ProtocolContract.LoginPath);
        return await SignUpFlow.PageStepAsync(page);
    }

    /// <summary>"Sign up" from the page's Login step, with the email typed there.</summary>
    public async Task<JsonDocument> OpenAsync(string email)
    {
        var login = await browser.LoginStepAsync();
        return await PostAsync(ProtocolContract.SignupOpenPath, new { stepVersion = login.StepVersion, email }, login.Csrf);
    }

    /// <summary>Create account from <paramref name="signup"/>'s step.</summary>
    public Task<JsonDocument> CreateAsync(JsonDocument signup, string email, string password) =>
        PostAsync(ProtocolContract.SignupPath, new { stepVersion = Version(signup), email, password }, Csrf(signup));

    /// <summary>"Resend email" from <paramref name="verify"/>'s step.</summary>
    public Task<JsonDocument> ResendAsync(JsonDocument verify) =>
        PostAsync(ProtocolContract.VerificationResendPath, new { stepVersion = Version(verify) }, Csrf(verify));

    /// <summary>"I've verified — continue" from <paramref name="verify"/>'s step.</summary>
    public Task<JsonDocument> ContinueAsync(JsonDocument verify) =>
        PostAsync(ProtocolContract.VerificationContinuePath, new { stepVersion = Version(verify) }, Csrf(verify));

    /// <summary>Opens a verification link in this browser, with its cookies.</summary>
    public async Task<JsonDocument> OpenLinkAsync(string token)
    {
        using var page = await browser.GetAsync(SignUpFlow.LinkPath(token));
        return await SignUpFlow.PageStepAsync(page);
    }

    /// <summary>Follows a redirect step's location, or Email verified's Continue, back to the authorization endpoint.</summary>
    public Task<HttpResponseMessage> FollowAsync(string location) => browser.GetAsync(location);

    /// <summary>POSTs <paramref name="body"/> to <paramref name="path"/> with <paramref name="csrf"/> and the exact Origin, expecting a 200 step.</summary>
    public async Task<JsonDocument> PostAsync(string path, object body, string? csrf)
    {
        using var response = await browser.PostAsync(path, body, csrf);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
    }

    public static int Version(JsonDocument step) => step.RootElement.GetProperty("stepVersion").GetInt32();

    public static string Csrf(JsonDocument step) => step.RootElement.GetProperty("csrfToken").GetString()!;
}
