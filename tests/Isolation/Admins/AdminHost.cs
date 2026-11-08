using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Tests.Isolation.Hosting;
using Gatekeep.Tests.Isolation.Stack;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// A real <c>Host.Admin</c> process on its own migrated database, serving the built Admin Dashboard
/// bundle, with an OpenBao stand-in. Requests go to its public port with no cookie jar, so each
/// test sends exactly the cookie, Origin and CSRF header it means to.
/// </summary>
internal sealed class AdminHost : IAsyncDisposable
{
    public const string Origin = HostProcess.AdminOrigin;

    public const string Cookie = "__Host-gk-admin";

    public const string CsrfHeader = "X-Gatekeep-CSRF";

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    private static readonly string Bundle = Path.Combine(Repository.Root, "apps", "admin-dashboard", "dist");

    private readonly PostgresFixture _postgres;
    private readonly HostProcess _process;
    private readonly FakeOpenBaoSocket _socket;
    private readonly string _directory;

    private AdminHost(PostgresFixture postgres, string database, int port, HostProcess process, FakeOpenBaoSocket socket, string directory)
    {
        _postgres = postgres;
        Database = database;
        Port = port;
        _process = process;
        _socket = socket;
        _directory = directory;
        Http = new HttpClient(new SocketsHttpHandler { UseCookies = false, AllowAutoRedirect = false, UseProxy = false })
        {
            BaseAddress = new Uri($"http://127.0.0.1:{port}"),
            Timeout = TimeSpan.FromSeconds(60),
        };
    }

    /// <summary>The key the OpenBao stand-in computes the Deployment HMAC with, so a test can compute a stored value.</summary>
    public static readonly byte[] HmacKey = SHA256.HashData("gatekeep-tests-dep-hmac"u8);

    public string Database { get; }

    public int Port { get; }

    public HttpClient Http { get; }

    /// <summary>The OpenBao stand-in: a test may make it fail, as by setting <see cref="FakeOpenBaoSocket.RespondToBody"/>.</summary>
    public FakeOpenBaoSocket OpenBao => _socket;

    /// <summary>Everything the host has written so far.</summary>
    public string Output => _process.Output;

    public string Superuser => _postgres.SuperuserConnection(Database);

    /// <summary>The host's own <c>gk_admin</c> connection, for calling the Admins module directly.</summary>
    public string AdminConnection => _postgres.RoleConnection(TableRegistry.Admin, Database);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    /// <summary>Starts Host.Admin on a fresh migrated database, or on <paramref name="database"/>, and waits until it's healthy.</summary>
    public static async Task<AdminHost> StartAsync(PostgresFixture postgres, string? database = null, params IEnumerable<string> arguments)
    {
        Assert.True(File.Exists(Path.Combine(Bundle, "index.html")), "apps/admin-dashboard/dist is missing: build the apps first (pnpm -r build).");

        database ??= await postgres.NewMigratedDatabaseAsync();
        var directory = Directory.CreateTempSubdirectory("gatekeep-admin-host-").FullName;
        var socket = new FakeOpenBaoSocket { RespondToBody = Custody };
        var health = HostProcess.FreePort();
        var port = HostProcess.FreePort();

        var process = HostProcess.Start(
            "Admin",
            new[]
            {
                $"--ConnectionStrings:Admin={postgres.RoleConnection(TableRegistry.Admin, database)}",
                $"--Custody:SocketPath={socket.Path}",
                $"--Custody:RoleIdFile={SecretFile(directory, "role-id")}",
                $"--Custody:SecretIdFile={SecretFile(directory, "secret-id")}",
                $"--Gatekeep:HealthPort={health}",
                $"--Gatekeep:PublicPort={port}",
                $"--webroot={Bundle}",
            }.Concat(arguments));

        var host = new AdminHost(postgres, database, port, process, socket, directory);
        try
        {
            var (status, body) = await process.GetAsync(health, "/healthz", Timeout, Cancellation);
            Assert.True(status == HttpStatusCode.OK, $"Host.Admin isn't healthy: {body}");
            return host;
        }
        catch
        {
            await host.DisposeAsync();
            throw;
        }
    }

    /// <summary>Issues a bootstrap token as <c>gatekeep init</c> does, as <c>gk_cli</c>, and returns it.</summary>
    public async Task<string> IssueTokenAsync()
    {
        var token = BootstrapToken.Generate();
        try
        {
            await using var source = NpgsqlDataSource.Create(_postgres.RoleConnection(TableRegistry.Cli, Database));
            await using var scope = await DeploymentScope.BeginAsync(source, Cancellation);
            var issued = await AdminsContract.CreateBootstrapIssuer(AuditContract.CreateAppender())
                .IssueAsync(scope.CreateCommandContext(), new Secret<byte[]>(token), Cancellation);
            Assert.NotNull(issued);
            await scope.CommitAsync(Cancellation);
            return Encoding.ASCII.GetString(token);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(token);
        }
    }

    /// <summary>Moves the issued token's times into the past, so it has expired.</summary>
    public Task ExpireTokenAsync() =>
        PostgresFixture.ExecuteAsync(
            Superuser,
            "UPDATE bootstrap_state SET issued_at = clock_timestamp() - interval '1 hour', expires_at = clock_timestamp() - interval '45 minutes'");

    /// <summary>POSTs a claim of <paramref name="token"/> as JSON, with the Admin Origin unless another is given.</summary>
    public Task<HttpResponseMessage> ClaimAsync(string token, string? origin = Origin, IEnumerable<(string, string)>? headers = null) =>
        ClaimBodyAsync(System.Text.Json.JsonSerializer.Serialize(new { token }), origin, headers);

    public Task<HttpResponseMessage> ClaimBodyAsync(string body, string? origin = Origin, IEnumerable<(string, string)>? headers = null) =>
        SendAsync(HttpMethod.Post, "/api/v1/deployment/bootstrap", origin: origin, body: body, headers: headers);

    public async Task<HttpResponseMessage> SendAsync(
        HttpMethod method,
        string path,
        string? cookie = null,
        string? csrf = null,
        string? origin = null,
        string? body = null,
        IEnumerable<(string Name, string Value)>? headers = null,
        string contentType = "application/json")
    {
        using var request = new HttpRequestMessage(method, path);
        if (cookie is not null)
        {
            request.Headers.TryAddWithoutValidation("Cookie", $"{Cookie}={cookie}");
        }

        if (csrf is not null)
        {
            request.Headers.TryAddWithoutValidation(CsrfHeader, csrf);
        }

        if (origin is not null)
        {
            request.Headers.TryAddWithoutValidation("Origin", origin);
        }

        foreach (var (name, value) in headers ?? [])
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }

        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, new MediaTypeHeaderValue(contentType));
        }

        var response = await Http.SendAsync(request, Cancellation);
        await response.Content.LoadIntoBufferAsync(Cancellation);
        return response;
    }

    /// <summary>A claimed bootstrap: the Session cookie value and the CSRF token from the 201.</summary>
    public async Task<(string Cookie, string Csrf, Guid AdminId)> ClaimedAsync()
    {
        var token = await IssueTokenAsync();
        using var response = await ClaimAsync(token);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return await ReadClaimAsync(response);
    }

    public static async Task<(string Cookie, string Csrf, Guid AdminId)> ReadClaimAsync(HttpResponseMessage response)
    {
        var setCookie = Assert.Single(response.Headers.GetValues("Set-Cookie"));
        var cookie = setCookie[(Cookie.Length + 1)..setCookie.IndexOf(';', StringComparison.Ordinal)];
        using var json = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return (cookie, json.RootElement.GetProperty("csrfToken").GetString()!, json.RootElement.GetProperty("adminId").GetGuid());
    }

    /// <summary>The SHA-256 of a base64url secret's 32 bytes, as the database stores it.</summary>
    public static byte[] Hash(string secret)
    {
        var bytes = Base64Url.DecodeFromChars(secret);
        Assert.Equal(32, bytes.Length);
        return SHA256.HashData(bytes);
    }

    /// <summary>The CSRF token Host.Admin derives from a Session ID: base64url(SHA-256("gatekeep-admin-csrf\0" || ID)).</summary>
    public static string Csrf(string sessionId) =>
        Base64Url.EncodeToString(SHA256.HashData([.. "gatekeep-admin-csrf\0"u8, .. Base64Url.DecodeFromChars(sessionId)]));

    /// <summary>
    /// A <c>full</c> Session, inserted as the superuser since sign-in is Story 1.23's, for an Admin
    /// who isn't the Owner, with <paramref name="credentials"/> WebAuthn credentials: two unless
    /// said, so that the Session isn't held to setup. Returns its cookie value and CSRF token.
    /// </summary>
    public async Task<(string Cookie, string Csrf, Guid SessionId)> InsertFullSessionAsync(int credentials = 2)
    {
        var raw = RandomNumberGenerator.GetBytes(32);
        var sessionId = Guid.CreateVersion7();
        await using var connection = new NpgsqlConnection(Superuser);
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand(
            """
            WITH a AS (INSERT INTO admin (id, deployment_owner) VALUES (@admin, false) RETURNING id)
            INSERT INTO admin_session (id, id_hash, admin_id, kind, created_at, idle_expires_at, absolute_expires_at)
            SELECT @id, @hash, a.id, 'full', now(), now() + interval '30 minutes', now() + interval '8 hours'
            FROM a;

            INSERT INTO admin_credential (id, admin_id, credential_id, public_key, sign_count, aaguid)
            SELECT gen_random_uuid(), s.admin_id, decode(md5(random()::text || n), 'hex'), '\x01', 0, gen_random_uuid()
            FROM admin_session AS s, generate_series(1, @credentials) AS n
            WHERE s.id = @id
            """,
            connection);
        command.Parameters.AddWithValue("admin", Guid.CreateVersion7());
        command.Parameters.AddWithValue("id", sessionId);
        command.Parameters.AddWithValue("hash", SHA256.HashData(raw));
        command.Parameters.AddWithValue("credentials", credentials);
        await command.ExecuteNonQueryAsync(Cancellation);

        var cookie = Base64Url.EncodeToString(raw);
        return (cookie, Csrf(cookie), sessionId);
    }

    /// <summary>Begins a credential registration for the Session, with its CSRF token and the Admin Origin.</summary>
    public async Task<(HttpResponseMessage Response, JsonElement Options)> BeginRegistrationAsync(string cookie, string csrf)
    {
        var response = await SendAsync(HttpMethod.Post, RegistrationPath, cookie, csrf, Origin);
        var options = response.StatusCode == HttpStatusCode.OK
            ? JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation)).RootElement.Clone()
            : default;
        return (response, options);
    }

    /// <summary>Completes a credential registration with <paramref name="body"/>, the page's JSON.</summary>
    public Task<HttpResponseMessage> CompleteRegistrationAsync(string cookie, string csrf, string body, string contentType = "application/json") =>
        SendAsync(HttpMethod.Post, RegistrationPath + "/complete", cookie, csrf, Origin, body, contentType: contentType);

    /// <summary>Begins and completes one registration with <paramref name="authenticator"/>, which must succeed.</summary>
    public async Task<JsonElement> RegisterAsync(string cookie, string csrf, SoftwareAuthenticator authenticator)
    {
        var (begin, options) = await BeginRegistrationAsync(cookie, csrf);
        using (begin)
        {
            Assert.Equal(HttpStatusCode.OK, begin.StatusCode);
        }

        using var complete = await CompleteRegistrationAsync(cookie, csrf, authenticator.Attest(options, Origin));
        Assert.Equal(HttpStatusCode.OK, complete.StatusCode);
        return JsonDocument.Parse(await complete.Content.ReadAsStringAsync(Cancellation)).RootElement.Clone();
    }

    public const string RegistrationPath = "/api/v1/deployment/credentials/registration";

    public const string SignInPath = "/api/v1/deployment/signin";

    public const string SignInCookie = "__Host-gk-admin-signin";

    /// <summary>
    /// Begins a sign-in with the Admin Origin unless another is given, sending
    /// <paramref name="binding"/> as the binding cookie when there is one. Returns the options and
    /// the new binding cookie's value, when it was a 200.
    /// </summary>
    public async Task<(HttpResponseMessage Response, JsonElement Options, string? Binding)> BeginSignInAsync(
        string? binding = null,
        string? origin = Origin,
        IEnumerable<(string, string)>? headers = null)
    {
        var response = await SendAsync(HttpMethod.Post, SignInPath, origin: origin, headers: Cookies(binding, null).Concat(headers ?? []));
        if (response.StatusCode != HttpStatusCode.OK)
        {
            return (response, default, null);
        }

        var options = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation)).RootElement.Clone();
        return (response, options, CookieValue(response, SignInCookie));
    }

    /// <summary>Completes a sign-in with <paramref name="body"/>, the page's JSON, the binding cookie and any Session cookie the browser holds.</summary>
    public Task<HttpResponseMessage> CompleteSignInAsync(
        string? binding,
        string body,
        string? session = null,
        string contentType = "application/json",
        string? origin = Origin,
        IEnumerable<(string, string)>? headers = null) =>
        SendAsync(
            HttpMethod.Post,
            SignInPath + "/complete",
            origin: origin,
            body: body,
            headers: Cookies(binding, session).Concat(headers ?? []),
            contentType: contentType);

    /// <summary>Begins and completes one sign-in with <paramref name="authenticator"/>, which must succeed. Returns the new Session's cookie and CSRF token.</summary>
    public async Task<(string Cookie, string Csrf)> SignInAsync(SoftwareAuthenticator authenticator, string? session = null)
    {
        var (begin, options, binding) = await BeginSignInAsync();
        using (begin)
        {
            Assert.Equal(HttpStatusCode.OK, begin.StatusCode);
        }

        using var complete = await CompleteSignInAsync(binding, authenticator.Assert(options, Origin), session);
        Assert.Equal(HttpStatusCode.OK, complete.StatusCode);
        using var json = JsonDocument.Parse(await complete.Content.ReadAsStringAsync(Cancellation));
        return (CookieValue(complete, Cookie)!, json.RootElement.GetProperty("csrfToken").GetString()!);
    }

    /// <summary>
    /// A claimed bootstrap whose Admin has registered <paramref name="authenticators"/>, so the
    /// Deployment has an Admin who can sign in. Returns the setup Session's cookie and the Admin.
    /// </summary>
    public async Task<(string Cookie, Guid AdminId)> AdminWithCredentialsAsync(params SoftwareAuthenticator[] authenticators)
    {
        var (cookie, csrf, adminId) = await ClaimedAsync();
        foreach (var authenticator in authenticators)
        {
            await RegisterAsync(cookie, csrf, authenticator);
        }

        return (cookie, adminId);
    }

    /// <summary>
    /// The Deployment Owner with a full Session (Story 1.24): bootstrap claimed, two credentials
    /// registered, then signed in. Returns the full Session's cookie and CSRF token, and the Owner.
    /// </summary>
    public async Task<(string Cookie, string Csrf, Guid AdminId)> OwnerSessionAsync()
    {
        using var first = new SoftwareAuthenticator();
        using var second = new SoftwareAuthenticator();
        var (_, adminId) = await AdminWithCredentialsAsync(first, second);
        var (cookie, csrf) = await SignInAsync(first);
        return (cookie, csrf, adminId);
    }

    public const string AssertionsPath = "/api/v1/deployment/assertions";

    public const string CredentialsPath = "/api/v1/deployment/credentials";

    public const string RecoveryCodePath = "/api/v1/deployment/credentials/recovery-code";

    public const string RedeemPath = "/api/v1/deployment/signin/recovery-code";

    /// <summary>Begins a fresh assertion for <paramref name="action"/> on <paramref name="target"/>. Returns the options when it was a 200.</summary>
    public async Task<(HttpResponseMessage Response, JsonElement Options)> BeginAssertionAsync(string cookie, string csrf, string action, string? target = null)
    {
        var response = await SendAsync(HttpMethod.Post, AssertionsPath, cookie, csrf, Origin, JsonSerializer.Serialize(new { action, target }));
        var options = response.StatusCode == HttpStatusCode.OK
            ? JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation)).RootElement.Clone()
            : default;
        return (response, options);
    }

    public Task<HttpResponseMessage> CompleteAssertionAsync(string cookie, string csrf, string body, string contentType = "application/json") =>
        SendAsync(HttpMethod.Post, AssertionsPath + "/complete", cookie, csrf, Origin, body, contentType: contentType);

    /// <summary>Confirms <paramref name="action"/> on <paramref name="target"/> with <paramref name="authenticator"/>: begin and complete, which must pass.</summary>
    public async Task ConfirmAsync(string cookie, string csrf, SoftwareAuthenticator authenticator, string action, string? target = null)
    {
        var (begin, options) = await BeginAssertionAsync(cookie, csrf, action, target);
        using (begin)
        {
            Assert.Equal(HttpStatusCode.OK, begin.StatusCode);
        }

        using var complete = await CompleteAssertionAsync(cookie, csrf, authenticator.Assert(options, Origin));
        Assert.Equal(HttpStatusCode.NoContent, complete.StatusCode);
    }

    /// <summary>Adds <paramref name="added"/> from a full Session: a fresh assertion with <paramref name="confirmWith"/>, then the registration.</summary>
    public async Task AddCredentialAsync(string cookie, string csrf, SoftwareAuthenticator confirmWith, SoftwareAuthenticator added)
    {
        await ConfirmAsync(cookie, csrf, confirmWith, "self.credentials.add");
        await RegisterAsync(cookie, csrf, added);
    }

    /// <summary>The Session's own credentials, as GET /credentials lists them.</summary>
    public async Task<JsonElement> CredentialsAsync(string cookie)
    {
        using var response = await SendAsync(HttpMethod.Get, CredentialsPath, cookie);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation)).RootElement.Clone();
    }

    /// <summary>The <c>acr_</c> IDs of the Session's credentials, oldest first.</summary>
    public async Task<List<string>> CredentialIdsAsync(string cookie) =>
        [.. (await CredentialsAsync(cookie)).GetProperty("credentials").EnumerateArray().Select(c => c.GetProperty("id").GetString()!)];

    public Task<HttpResponseMessage> RemoveCredentialAsync(string cookie, string csrf, string id) =>
        SendAsync(HttpMethod.Delete, $"{CredentialsPath}/{id}", cookie, csrf, Origin);

    /// <summary>
    /// The Deployment Owner with a full Session and <paramref name="count"/> credentials (Story
    /// 1.26): two registered at setup, signed in with the first, then the rest added each after a
    /// fresh assertion. Returns the Session and the authenticators, in registration order.
    /// </summary>
    public async Task<(string Cookie, string Csrf, Guid AdminId, SoftwareAuthenticator[] Authenticators)> OwnerWithCredentialsAsync(int count = 2)
    {
        var authenticators = Enumerable.Range(0, count).Select(_ => new SoftwareAuthenticator()).ToArray();
        var (_, adminId) = await AdminWithCredentialsAsync(authenticators[0], authenticators[1]);
        var (cookie, csrf) = await SignInAsync(authenticators[0]);
        foreach (var added in authenticators.Skip(2))
        {
            await AddCredentialAsync(cookie, csrf, authenticators[0], added);
        }

        return (cookie, csrf, adminId, authenticators);
    }

    /// <summary>
    /// A seeded Admin who isn't the Deployment Owner, as Story 8.3's invites will make one, with a
    /// live setup Session inserted as the superuser and nothing registered. Bootstrap must be
    /// complete first, for sign-in and Recovery Codes to exist. Returns the Session and the Admin.
    /// </summary>
    public async Task<(string Cookie, string Csrf, Guid AdminId)> InsertSetupAdminAsync()
    {
        var raw = RandomNumberGenerator.GetBytes(32);
        var adminId = Guid.CreateVersion7();
        await using var connection = new NpgsqlConnection(Superuser);
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand(
            """
            INSERT INTO admin (id, deployment_owner) VALUES (@admin, false);
            INSERT INTO admin_session (id, id_hash, admin_id, kind, created_at, idle_expires_at, absolute_expires_at)
            VALUES (@id, @hash, @admin, 'setup', now(), now() + interval '30 minutes', now() + interval '8 hours');
            """,
            connection);
        command.Parameters.AddWithValue("admin", adminId);
        command.Parameters.AddWithValue("id", Guid.CreateVersion7());
        command.Parameters.AddWithValue("hash", SHA256.HashData(raw));
        await command.ExecuteNonQueryAsync(Cancellation);

        var cookie = Base64Url.EncodeToString(raw);
        return (cookie, Csrf(cookie), adminId);
    }

    /// <summary>Issues a Recovery Code in the setup Session, which must pass. Returns it as shown, and its issue.</summary>
    public async Task<(string Code, Guid IssueId)> IssueRecoveryCodeAsync(string cookie, string csrf)
    {
        using var response = await SendAsync(HttpMethod.Post, RecoveryCodePath, cookie, csrf, Origin);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return (json.RootElement.GetProperty("code").GetString()!, json.RootElement.GetProperty("issueId").GetGuid());
    }

    public Task<HttpResponseMessage> ConfirmRecoveryCodeAsync(string cookie, string csrf, Guid issueId) =>
        SendAsync(HttpMethod.Post, RecoveryCodePath + "/confirm", cookie, csrf, Origin, JsonSerializer.Serialize(new { issueId }));

    /// <summary>Redeems <paramref name="code"/> at sign-in, sessionless, with any Session cookie the browser holds.</summary>
    public Task<HttpResponseMessage> RedeemAsync(string code, string? session = null, IEnumerable<(string, string)>? headers = null) =>
        SendAsync(
            HttpMethod.Post,
            RedeemPath,
            origin: Origin,
            body: JsonSerializer.Serialize(new { code }),
            headers: Cookies(null, session).Concat(headers ?? []));

    public const string EnrolmentPath = "/api/v1/deployment/signin/enrolment";

    /// <summary>Redeems a <c>recover-admin</c> enrolment at sign-in (Story 1.32), sessionless, with any Session cookie the browser holds.</summary>
    public Task<HttpResponseMessage> RedeemEnrolmentAsync(string enrolment, string? session = null, IEnumerable<(string, string)>? headers = null) =>
        SendAsync(
            HttpMethod.Post,
            EnrolmentPath,
            origin: Origin,
            body: JsonSerializer.Serialize(new { enrolment }),
            headers: Cookies(null, session).Concat(headers ?? []));

    /// <summary>
    /// A seeded non-Owner Admin with one credential and a confirmed Recovery Code: their setup
    /// Session is then full. Returns it, the code as shown and the authenticator.
    /// </summary>
    public async Task<(string Cookie, string Csrf, Guid AdminId, string Code, SoftwareAuthenticator Authenticator)> AdminWithRecoveryCodeAsync()
    {
        var (cookie, csrf, adminId) = await InsertSetupAdminAsync();
        var authenticator = new SoftwareAuthenticator();
        await RegisterAsync(cookie, csrf, authenticator);
        var (code, issueId) = await IssueRecoveryCodeAsync(cookie, csrf);
        using var confirmed = await ConfirmRecoveryCodeAsync(cookie, csrf, issueId);
        Assert.Equal(HttpStatusCode.NoContent, confirmed.StatusCode);
        return (cookie, csrf, adminId, code, authenticator);
    }

    /// <summary>The Admin whose Session <paramref name="sessionId"/> is.</summary>
    public Task<Guid> AdminOfSessionAsync(Guid sessionId) =>
        ScalarAsync<Guid>($"SELECT admin_id FROM admin_session WHERE id = '{sessionId}'");

    /// <summary>A new Tenant row, as the superuser, since creating Tenants is Story 1.27's. Returns its ID.</summary>
    public async Task<Guid> InsertTenantAsync()
    {
        var id = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(Superuser, TestTenants.InsertSql(id));
        return id;
    }

    /// <summary>Gives <paramref name="adminId"/> <paramref name="role"/> (<c>viewer</c>, <c>editor</c> or <c>owner</c>) in the Tenant, as the superuser.</summary>
    public Task GrantTenantRoleAsync(Guid tenantId, Guid adminId, string role) =>
        TestTenants.GrantRoleAsync(Superuser, tenantId, adminId, role);

    /// <summary>Removes the Admin's role in the Tenant, as the superuser, since removing roles is Story 8.4's.</summary>
    public Task RevokeTenantRoleAsync(Guid tenantId, Guid adminId) =>
        PostgresFixture.ExecuteAsync(Superuser, $"DELETE FROM tenant_role WHERE tenant_id = '{tenantId}' AND admin_id = '{adminId}'");

    /// <summary>The value a response's <c>Set-Cookie</c> gives <paramref name="name"/>, or null when it sets none.</summary>
    public static string? CookieValue(HttpResponseMessage response, string name) =>
        response.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.Where(v => v.StartsWith(name + "=", StringComparison.Ordinal))
                .Select(v => v[(name.Length + 1)..v.IndexOf(';', StringComparison.Ordinal)])
                .FirstOrDefault()
            : null;

    private static IEnumerable<(string, string)> Cookies(string? binding, string? session)
    {
        var pairs = new List<string>();
        if (binding is not null)
        {
            pairs.Add($"{SignInCookie}={binding}");
        }

        if (session is not null)
        {
            pairs.Add($"{Cookie}={session}");
        }

        return pairs.Count == 0 ? [] : [("Cookie", string.Join("; ", pairs))];
    }

    /// <summary>A well-formed secret nobody issued.</summary>
    public static string Unissued() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));

    /// <summary>
    /// A response as bytes on the wire would compare: status, every header but Date, sorted, and
    /// the body's bytes.
    /// </summary>
    public static async Task<string> SnapshotAsync(HttpResponseMessage response)
    {
        var headers = response.Headers.Concat(response.Content.Headers)
            .Where(h => !h.Key.Equals("Date", StringComparison.OrdinalIgnoreCase))
            .Select(h => $"{h.Key.ToLowerInvariant()}: {string.Join(", ", h.Value)}")
            .Order(StringComparer.Ordinal);
        var body = await response.Content.ReadAsByteArrayAsync(Cancellation);
        return $"{(int)response.StatusCode}\n{string.Join("\n", headers)}\n{Convert.ToHexString(body)}";
    }

    public async Task<T> ScalarAsync<T>(string sql) => await PostgresFixture.ScalarAsync<T>(Superuser, sql);

    public async Task StopAsync() => await _process.StopAsync(Timeout, Cancellation);

    public ValueTask DisposeAsync()
    {
        Http.Dispose();
        _process.Dispose();
        _socket.Dispose();
        Directory.Delete(_directory, recursive: true);
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// The OpenBao stand-in's answers (Story 1.26): an AppRole login, and Transit HMAC on
    /// <c>dep-hmac</c> as HMAC-SHA256 under <see cref="HmacKey"/>, at key version 1. Anything else
    /// is the default empty 200.
    /// </summary>
    public static (int Status, string Body) Custody(string path, string body)
    {
        if (path.Contains("/auth/", StringComparison.Ordinal))
        {
            return (200, """{"auth":{"client_token":"test-token","lease_duration":3600}}""");
        }

        if (path.EndsWith("/transit/hmac/dep-hmac", StringComparison.Ordinal))
        {
            using var json = JsonDocument.Parse(body);
            var input = Convert.FromBase64String(json.RootElement.GetProperty("input").GetString()!);
            return (200, $$$"""{"data":{"hmac":"vault:v1:{{{Convert.ToBase64String(HMACSHA256.HashData(HmacKey, input))}}}"}}""");
        }

        return (200, "{}");
    }

    /// <summary>What <c>admin_recovery_code.code_hmac</c> holds for a normalized code: the stand-in's HMAC of the domain-separated input.</summary>
    public static byte[] RecoveryCodeHmac(string normalized) =>
        HMACSHA256.HashData(HmacKey, (byte[])[.. "gatekeep-admin-recovery-code\0"u8, .. Encoding.ASCII.GetBytes(normalized)]);

    private static string SecretFile(string directory, string name)
    {
        var path = Path.Combine(directory, $"{name}-{Guid.NewGuid():N}");
        File.WriteAllText(path, Guid.NewGuid().ToString());
        return path;
    }
}
