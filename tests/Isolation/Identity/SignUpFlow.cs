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
            // The verification link is enqueued as payload ciphertext, under the Tenant's payload key.
            await ProtocolDatabase.ProvisionSecretClassesAsync(bao, tenant);
            // Story 4.12: enabled for the web client, which was created before it.
            await flow.Database.ExecuteAsync(TestTenants.DatabaseConnectionSql(tenant, signupEnabled));
        }

        if (verificationOff)
        {
            await flow.Database.ExecuteAsync(
                $"INSERT INTO tenant_settings (tenant_id, email_verification_off) VALUES ('{flow.A.TenantId}', true) "
                + "ON CONFLICT (tenant_id) DO UPDATE SET email_verification_off = true");
        }

        return new SignUpFlow(flow);
    }

    /// <summary>
    /// The host, with <paramref name="hashLimits"/>, (Story 4.8) <paramref name="signUpLimits"/> and (Story 4.9)
    /// <paramref name="signInLimits"/> in place of the defaults when given; with <paramref name="releaseSignIn"/> (Story 4.12)
    /// the release build's credential step, so Login with no Connection is Generic error as on Host.Hosted.
    /// </summary>
    public Task<ProtocolHost> StartHostAsync(
        Gatekeep.Modules.Authentication.Contracts.PasswordHashLimits? hashLimits = null,
        SignUpLimits? signUpLimits = null,
        SignInLimits? signInLimits = null,
        PasswordResetLimits? resetLimits = null,
        TimeProvider? time = null,
        bool releaseSignIn = false) =>
        ProtocolHost.StartAsync(
            Flow.Database.Hosted,
            Flow.Bao,
            time: time,
            releaseSignIn: releaseSignIn,
            hashLimits: hashLimits,
            signUpLimits: signUpLimits,
            signInLimits: signInLimits,
            resetLimits: resetLimits);

    /// <summary>Story 4.11: reset request limits no test reaches by accident, for one that sends many.</summary>
    public static PasswordResetLimits GenerousReset { get; } = new(
        new("reset.request.tenant", 10_000, TimeSpan.FromMinutes(15)),
        new("reset.request.source", 10_000, TimeSpan.FromMinutes(15)),
        new("reset.request.recipient", 10_000, TimeSpan.FromMinutes(15)));

    /// <summary>
    /// Story 4.11: a browser at <paramref name="tenantHost"/> through Login's Continue with <paramref name="email"/>,
    /// "Forgot password?" and "Send reset link" with <paramref name="requested"/> (by default the same address). Returns
    /// the browser and the step the request answered.
    /// </summary>
    public async Task<(SignUpBrowser Browser, JsonDocument Step)> RequestResetAsync(
        ProtocolHost host, string tenantHost, string email, string? requested = null, string? source = null)
    {
        var browser = await BeginAsync(host, tenantHost, source);
        using var password = await browser.IdentifyAsync(email);
        Assert.Equal(StepNames.Password, Name(password));
        using var forgot = await browser.ForgotAsync(password);
        Assert.Equal(StepNames.ForgotPassword, Name(forgot));
        return (browser, await browser.RequestResetAsync(forgot, requested ?? email));
    }

    /// <summary>The reset-link-bound CSRF token of <paramref name="token"/> (Story 4.11), derived as the server derives it.</summary>
    public static string ResetCsrf(string token)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(token));
        var input = "gatekeep-reset-csrf\0"u8.ToArray().Concat(hash).ToArray();
        return Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(SHA256.HashData(input));
    }

    /// <summary>The reset link page for <paramref name="token"/> (Story 4.11), as the email's link opens it.</summary>
    public static string ResetLinkPath(string token) => $"{ProtocolContract.ResetPasswordPath}?token={Uri.EscapeDataString(token)}";

    /// <summary>
    /// Story 4.9: a User of Tenant A with <paramref name="email"/> and an active password credential holding
    /// <paramref name="passwordHash"/> (by default <see cref="Password"/>'s hash under the current parameters), under Tenant
    /// A's database Connection, verified unless <paramref name="verified"/> is false, as an earlier sign-up leaves one.
    /// Returns the User's and the credential's IDs.
    /// </summary>
    public async Task<(Guid UserId, Guid CredentialId)> AddPasswordUserAsync(string email, string? passwordHash = null, bool verified = true)
    {
        var hash = passwordHash ?? await Gatekeep.Modules.Authentication.Contracts.AuthenticationContract.HashPasswordAsync(
            new Gatekeep.Kernel.Secrets.Secret<string>(Password));
        var user = Guid.CreateVersion7();
        var credential = Guid.CreateVersion7();
        await Database.ExecuteAsync(
            $"INSERT INTO \"user\" (tenant_id, id, email, email_verified_at) VALUES ('{TenantA}', '{user}', '{email}', {(verified ? "now()" : "NULL")}); "
            + "INSERT INTO password_credential (tenant_id, id, user_id, connection_id, password_hash, status) "
            + $"SELECT '{TenantA}', '{credential}', '{user}', id, '{hash}', 'active' FROM connection WHERE tenant_id = '{TenantA}' AND kind = 'database'");
        return (user, credential);
    }

    /// <summary>Story 4.9: limits no test reaches by accident, for one that sends many password submits.</summary>
    public static SignInLimits GenerousSignIn { get; } = new(
        new("signin.attempt.tenant", 10_000, TimeSpan.FromMinutes(15)),
        new("signin.attempt.source", 10_000, TimeSpan.FromMinutes(15)));

    /// <summary>Limits no test reaches by accident (Story 4.8), for one that sends many sign-ups or resends.</summary>
    public static SignUpLimits Generous { get; } = new(
        new("signup.attempt.tenant", 10_000, TimeSpan.FromMinutes(15)),
        new("signup.attempt.source", 10_000, TimeSpan.FromMinutes(15)),
        new("verification.send.tenant", 10_000, TimeSpan.FromMinutes(15)),
        new("verification.send.source", 10_000, TimeSpan.FromMinutes(15)));

    /// <summary>Stores <paramref name="termsUrl"/> as <paramref name="tenantId"/>'s terms URL (Story 4.8).</summary>
    public Task SetTermsAsync(Guid tenantId, string termsUrl) =>
        Database.ExecuteAsync(
            $"INSERT INTO tenant_settings (tenant_id, terms_url) VALUES ('{tenantId}', '{termsUrl}') "
            + $"ON CONFLICT (tenant_id) DO UPDATE SET terms_url = '{termsUrl}'");

    /// <summary>
    /// A browser at <paramref name="tenantHost"/>'s Login for a new authorization request of the web client
    /// <paramref name="clientId"/>, by default Tenant A's, naming <paramref name="source"/> as its address when given (Story 4.8).
    /// </summary>
    public async Task<SignUpBrowser> BeginAsync(ProtocolHost host, string tenantHost, string? source = null, string? clientId = null)
    {
        var browser = new HostedBrowser(host, tenantHost) { Source = source };
        var pkce = Pkce.New();
        using (var begun = await browser.GetAsync(CodeFlow.AuthorizeUrl(clientId ?? Flow.ClientA.ClientId, CodeFlowSetup.Callback, pkce)))
        {
            Assert.True(HostedBrowser.IsLoginRedirect(begun), $"The authorization request answered {(int)begun.StatusCode}.");
        }

        return new SignUpBrowser(browser, pkce);
    }

    /// <summary>
    /// A browser at <paramref name="tenantHost"/> (by default for Tenant A's web client), moved to Signup and through Create
    /// account with <paramref name="email"/> and <paramref name="password"/>, and <c>acceptTerms</c> when given.
    /// </summary>
    public async Task<(SignUpBrowser Browser, JsonDocument Step)> SignUpAsync(
        ProtocolHost host,
        string tenantHost,
        string email,
        string password = Password,
        bool? acceptTerms = null,
        string? source = null,
        string? clientId = null)
    {
        var browser = await BeginAsync(host, tenantHost, source, clientId);
        using var signup = await browser.OpenAsync(email);
        Assert.Equal(StepNames.Signup, Name(signup));
        return (browser, await browser.CreateAsync(signup, email, password, acceptTerms));
    }

    public Task<long> CountAsync(string sql) => Database.ScalarAsync<long>(sql);

    /// <summary>How many rows of the Tenant's <paramref name="table"/> there are, optionally filtered further.</summary>
    /// <remarks>
    /// For <c>"user"</c> only Users with an email count: the code-flow fixture's own User has none, and no sign-up made it.
    /// </remarks>
    public Task<long> RowsAsync(string table, string? where = null) =>
        Database.ScalarAsync<long>(
            $"SELECT count(*) FROM \"{table}\" WHERE tenant_id = '{TenantA}'"
            + (table == "user" ? " AND email IS NOT NULL" : string.Empty)
            + (where is null ? string.Empty : " AND " + where));

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

    /// <summary>Create account from <paramref name="signup"/>'s step, with <c>acceptTerms</c> (Story 4.8) when given.</summary>
    public Task<JsonDocument> CreateAsync(JsonDocument signup, string email, string password, bool? acceptTerms = null) =>
        PostAsync(ProtocolContract.SignupPath, CreateBody(signup, email, password, acceptTerms), Csrf(signup));

    /// <summary>Create account's body, without <c>acceptTerms</c> when <paramref name="acceptTerms"/> is null.</summary>
    public static object CreateBody(JsonDocument signup, string email, string password, bool? acceptTerms = null) =>
        acceptTerms is { } accept
            ? new { stepVersion = Version(signup), email, password, acceptTerms = accept }
            : new { stepVersion = Version(signup), email, password };

    /// <summary>Story 4.9: Continue from the page's Login step with <paramref name="email"/>, answering the Password step.</summary>
    public async Task<JsonDocument> IdentifyAsync(string email)
    {
        var login = await browser.LoginStepAsync();
        return await PostAsync(ProtocolContract.LoginIdentifierPath, new { stepVersion = login.StepVersion, email }, login.Csrf);
    }

    /// <summary>Story 4.9: Log in from <paramref name="step"/>, the Password step, with <paramref name="password"/>.</summary>
    public Task<JsonDocument> LogInAsync(JsonDocument step, string password) =>
        PostAsync(ProtocolContract.PasswordPath, new { stepVersion = Version(step), password }, Csrf(step));

    /// <summary>Story 4.9: the identifier chip's Edit from <paramref name="step"/>, the Password step.</summary>
    public Task<JsonDocument> EditAsync(JsonDocument step) =>
        PostAsync(ProtocolContract.PasswordBackPath, new { stepVersion = Version(step) }, Csrf(step));

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

    /// <summary>Story 4.11: "Forgot password?" from <paramref name="step"/>, the Password step.</summary>
    public Task<JsonDocument> ForgotAsync(JsonDocument step) =>
        PostAsync(ProtocolContract.ResetOpenPath, new { stepVersion = Version(step) }, Csrf(step));

    /// <summary>Story 4.11: "Send reset link" from <paramref name="step"/>, Forgot password, for <paramref name="email"/>.</summary>
    public Task<JsonDocument> RequestResetAsync(JsonDocument step, string email) =>
        PostAsync(ProtocolContract.ResetPath, new { stepVersion = Version(step), email }, Csrf(step));

    /// <summary>Story 4.11: "Back to login" from <paramref name="step"/>, Forgot password or its confirmation.</summary>
    public Task<JsonDocument> ResetBackAsync(JsonDocument step) =>
        PostAsync(ProtocolContract.ResetBackPath, new { stepVersion = Version(step) }, Csrf(step));

    /// <summary>Story 4.11: opens a reset link in this browser, with its cookies.</summary>
    public async Task<JsonDocument> OpenResetLinkAsync(string token)
    {
        using var page = await browser.GetAsync(SignUpFlow.ResetLinkPath(token));
        return await SignUpFlow.PageStepAsync(page);
    }

    /// <summary>Story 4.11: "Reset password" with <paramref name="token"/>, in this browser, with the reset-link CSRF token.</summary>
    public Task<JsonDocument> CompleteResetAsync(string token, string password, string? confirm = null) =>
        PostAsync(ProtocolContract.ResetCompletePath, new { token, password, confirm = confirm ?? password }, SignUpFlow.ResetCsrf(token));

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
