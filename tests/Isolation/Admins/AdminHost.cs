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

    public string Database { get; }

    public int Port { get; }

    public HttpClient Http { get; }

    /// <summary>Everything the host has written so far.</summary>
    public string Output => _process.Output;

    public string Superuser => _postgres.SuperuserConnection(Database);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    /// <summary>Starts Host.Admin on a fresh migrated database, or on <paramref name="database"/>, and waits until it's healthy.</summary>
    public static async Task<AdminHost> StartAsync(PostgresFixture postgres, string? database = null, params IEnumerable<string> arguments)
    {
        Assert.True(File.Exists(Path.Combine(Bundle, "index.html")), "apps/admin-dashboard/dist is missing: build the apps first (pnpm -r build).");

        database ??= await postgres.NewMigratedDatabaseAsync();
        var directory = Directory.CreateTempSubdirectory("gatekeep-admin-host-").FullName;
        var socket = new FakeOpenBaoSocket();
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

    private static string SecretFile(string directory, string name)
    {
        var path = Path.Combine(directory, $"{name}-{Guid.NewGuid():N}");
        File.WriteAllText(path, Guid.NewGuid().ToString());
        return path;
    }
}
