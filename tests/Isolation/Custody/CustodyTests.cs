using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using Gatekeep.Adapters.OpenBao;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Tests.Isolation.Canary;
using CanaryValue = Gatekeep.Tests.Isolation.Canary.Canary;
using Xunit;

namespace Gatekeep.Tests.Isolation.Custody;

[Collection(OpenBaoCollection.Name)]
public sealed class CustodyTests(OpenBaoFixture bao)
{
    private static readonly byte[] Data = "credential-equivalent value"u8.ToArray();

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Deploy_config_serves_on_the_socket_unsealed_with_raft_and_the_static_seal()
    {
        var status = await bao.ExecAsync("bao", "status", "-format=json", $"-address={OpenBaoFixture.Socket}");

        Assert.Equal(0, status.ExitCode);
        using var json = JsonDocument.Parse(status.Stdout);
        Assert.True(json.RootElement.GetProperty("initialized").GetBoolean());
        Assert.False(json.RootElement.GetProperty("sealed").GetBoolean());
        Assert.Equal("static", json.RootElement.GetProperty("type").GetString());
        Assert.Equal("raft", json.RootElement.GetProperty("storage_type").GetString());

        var socket = await bao.ExecAsync("stat", "-c", "%a %U %G", "/run/openbao/openbao.sock");
        Assert.Equal("660 openbao gatekeep-custody", socket.Stdout.Trim());
    }

    [Fact]
    public async Task Master_key_is_32_bytes_root_only_and_the_service_copy_is_its_own()
    {
        var key = await bao.ExecAsync("stat", "-c", "%a %U %G %s", OpenBaoFixture.KeyFile);
        var credential = await bao.ExecAsync("stat", "-c", "%a %U %s", "/run/credentials/openbao.service/master-key");

        Assert.Equal("400 root root 32", key.Stdout.Trim());
        Assert.Equal("400 openbao 32", credential.Stdout.Trim());
    }

    [Fact]
    public async Task Ciphertext_bound_to_one_Tenant_is_rejected_for_another()
    {
        var social = KeyName.ForTenant(TenantKeyClass.Social, bao.TenantA);
        using var cli = bao.Custody(OpenBaoFixture.Cli);
        using var worker = bao.Custody(OpenBaoFixture.Worker);

        var ciphertext = await cli.EncryptAsync(social, bao.TenantA, new Secret<byte[]>(Data), Cancellation);
        var own = await worker.DecryptAsync(social, bao.TenantA, ciphertext, Cancellation);

        // The adapter won't send another Tenant's ID, so OpenBao's own check is shown raw.
        Assert.Equal(Data, own.Use(b => b));
        Assert.Equal(HttpStatusCode.OK, await RawDecryptAsync(social, ciphertext, bao.TenantA));
        Assert.Equal(HttpStatusCode.BadRequest, await RawDecryptAsync(social, ciphertext, bao.TenantB));
    }

    [Fact]
    public async Task Rejected_ciphertext_names_only_the_key_and_operation()
    {
        var social = KeyName.ForTenant(TenantKeyClass.Social, bao.TenantA);
        using var cli = bao.Custody(OpenBaoFixture.Cli);
        using var worker = bao.Custody(OpenBaoFixture.Worker);
        var ciphertext = await cli.EncryptAsync(social, bao.TenantA, new Secret<byte[]>(Data), Cancellation);
        var tampered = new KeyCiphertext(ciphertext.Value[..^4] + (ciphertext.Value.EndsWith("AAAA", StringComparison.Ordinal) ? "BBBB" : "AAAA"));

        var rejected = await Assert.ThrowsAsync<KeyCustodyException>(
            () => worker.DecryptAsync(social, bao.TenantA, tampered, Cancellation));

        Assert.Equal(KeyCustodyFailure.Rejected, rejected.Failure);
        Assert.Equal($"Key custody rejected Decrypt on key {social}.", rejected.Message);
        Assert.Null(rejected.InnerException);
        Assert.DoesNotContain(tampered.Value, rejected.ToString());
    }

    [Fact]
    public async Task Wrong_Tenant_binding_throws_before_any_Transit_request()
    {
        var counter = new CountingHandler();
        using var worker = bao.Custody(OpenBaoFixture.Worker, wrap: counter.Wrap);
        var socialA = KeyName.ForTenant(TenantKeyClass.Social, bao.TenantA);
        var depEmail = KeyName.ForDeployment(DeploymentKeyClass.Email);
        var ciphertext = new KeyCiphertext("vault:v1:AAAA");

        await Assert.ThrowsAsync<ArgumentException>(() => worker.DecryptAsync(socialA, null, ciphertext, Cancellation));
        await Assert.ThrowsAsync<ArgumentException>(() => worker.DecryptAsync(depEmail, bao.TenantA, ciphertext, Cancellation));
        await Assert.ThrowsAsync<ArgumentException>(() => worker.DecryptAsync(socialA, bao.TenantB, ciphertext, Cancellation));

        Assert.Equal(0, counter.Count("/transit/"));
    }

    [Fact]
    public async Task Wrapped_token_protection_key_unwraps_only_for_its_Tenant()
    {
        var tpk = KeyName.ForTenant(TenantKeyClass.TokenProtection, bao.TenantA);
        using var worker = bao.Custody(OpenBaoFixture.Worker);
        using var hosted = bao.Custody(OpenBaoFixture.Hosted);

        var wrapped = await worker.CreateWrappedDataKeyAsync(tpk, bao.TenantA, Cancellation);
        var unwrapped = await hosted.DecryptAsync(tpk, bao.TenantA, wrapped, Cancellation);

        Assert.Equal(32, unwrapped.Use(b => b.Length));
        Assert.Equal(HttpStatusCode.BadRequest, await RawDecryptAsync(tpk, wrapped, bao.TenantB, OpenBaoFixture.Hosted));
    }

    [Fact]
    public async Task Rotation_adds_version_2_and_old_values_still_verify_and_decrypt()
    {
        var tenant = Guid.CreateVersion7();
        var signing = KeyName.Signing(tenant, Guid.CreateVersion7());
        var payload = KeyName.ForTenant(TenantKeyClass.Payload, tenant);
        using var worker = bao.Custody(OpenBaoFixture.Worker);
        using var hosted = bao.Custody(OpenBaoFixture.Hosted);
        await worker.CreateKeyAsync(signing, Cancellation);
        await worker.CreateKeyAsync(payload, Cancellation);

        var oldSignature = await hosted.SignAsync(signing, Data, Cancellation);
        var oldCiphertext = await hosted.EncryptAsync(payload, tenant, new Secret<byte[]>(Data), Cancellation);
        await worker.RotateAsync(signing, Cancellation);
        await worker.RotateAsync(payload, Cancellation);
        var newSignature = await hosted.SignAsync(signing, Data, Cancellation);
        var newCiphertext = await hosted.EncryptAsync(payload, tenant, new Secret<byte[]>(Data), Cancellation);
        var versions = await worker.GetPublicKeysAsync(signing, Cancellation);

        Assert.Equal(1, oldSignature.KeyVersion);
        Assert.Equal(2, newSignature.KeyVersion);
        Assert.Equal([1, 2], versions.Select(v => v.KeyVersion));
        Assert.True(VerifiesLocally(versions[0].PublicKeyPem, oldSignature));
        Assert.True(VerifiesLocally(versions[1].PublicKeyPem, newSignature));
        Assert.Equal(Data, (await worker.DecryptAsync(payload, tenant, oldCiphertext, Cancellation)).Use(b => b));
        Assert.StartsWith("vault:v2:", newCiphertext.Value, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Master_key_script_refuses_to_replace_a_key()
    {
        var before = await bao.ReadKeyFileAsync();

        var again = await bao.ExecAsync("sh", "/opt/gatekeep/openbao/generate-master-key.sh", OpenBaoFixture.KeyFile);

        Assert.NotEqual(0, again.ExitCode);
        Assert.Contains("already exists", again.Stderr);
        Assert.Equal(before, await bao.ReadKeyFileAsync());
    }
    [Theory]
    [InlineData(OpenBaoFixture.Worker, true)]
    [InlineData(OpenBaoFixture.Cli, true)]
    [InlineData(OpenBaoFixture.Hosted, false)]
    [InlineData(OpenBaoFixture.Admin, false)]
    public async Task Only_Worker_and_Cli_sign_deployment_records(string role, bool allowed)
    {
        var records = KeyName.ForDeployment(DeploymentKeyClass.Records);
        using var custody = bao.Custody(role);

        if (allowed)
        {
            var signature = await custody.SignAsync(records, Data, Cancellation);
            Assert.True(await custody.VerifyAsync(records, Data, signature, Cancellation));
        }
        else
        {
            var refused = await Assert.ThrowsAsync<KeyCustodyException>(() => custody.SignAsync(records, Data, Cancellation));
            Assert.Equal(KeyCustodyFailure.Refused, refused.Failure);
            Assert.Equal("Key custody refused Sign on key dep-records.", refused.Message);
        }
    }

    [Theory]
    [MemberData(nameof(PolicyMatrixTests.Roles), MemberType = typeof(PolicyMatrixTests))]
    public async Task AppRole_login_gives_a_15_minute_token_with_only_its_own_policy(string role)
    {
        using var http = new HttpClient { BaseAddress = bao.Address };
        var options = bao.Options(role);
        using var response = await http.PostAsJsonAsync(
            "v1/auth/approle/login",
            new { role_id = await File.ReadAllTextAsync(options.RoleIdFile, Cancellation), secret_id = await File.ReadAllTextAsync(options.SecretIdFile, Cancellation) },
            Cancellation);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        var auth = body.RootElement.GetProperty("auth");

        Assert.Equal(900, auth.GetProperty("lease_duration").GetInt32());
        Assert.Equal([role], auth.GetProperty("policies").EnumerateArray().Select(p => p.GetString()));
    }

    [Fact]
    public async Task Setup_revokes_the_root_token_and_leaks_no_secret()
    {
        Assert.Equal(0, bao.Setup.ExitCode);

        var escrowMode = await bao.ExecAsync("stat", "-c", "%a %U", OpenBaoFixture.EscrowFile);
        Assert.Equal("400 root", escrowMode.Stdout.Trim());

        using var escrow = JsonDocument.Parse(await bao.ReadTextAsync(OpenBaoFixture.EscrowFile));
        var rootToken = escrow.RootElement.GetProperty("root_token").GetString()!;
        var masterKey = await bao.ReadKeyFileAsync();

        List<CanaryValue> canaries =
        [
            new("root-token", rootToken, rootToken),
            new("master-key-hex", Convert.ToHexStringLower(masterKey), string.Empty),
            new("master-key-base64", Convert.ToBase64String(masterKey), string.Empty),
        ];
        foreach (var field in new[] { "recovery_keys_b64", "recovery_keys_hex" })
        {
            canaries.AddRange(escrow.RootElement.GetProperty(field).EnumerateArray()
                .Select(k => new CanaryValue("recovery-key", k.GetString()!, string.Empty)));
        }

        foreach (var role in OpenBaoFixture.Roles)
        {
            var secretId = (await File.ReadAllTextAsync(bao.Options(role).SecretIdFile, Cancellation)).Trim();
            canaries.Add(new CanaryValue("secret-id", secretId, string.Empty));
            var roleId = (await File.ReadAllTextAsync(bao.Options(role).RoleIdFile, Cancellation)).Trim();
            canaries.Add(new CanaryValue("role-id", roleId, string.Empty));
        }

        var (logOut, logErr) = await bao.Container.GetLogsAsync(ct: Cancellation);
        CanarySource[] sources =
        [
            new("setup stdout", bao.Setup.Stdout),
            new("setup stderr", bao.Setup.Stderr),
            new("container stdout", logOut),
            new("container stderr", logErr),
            new("audit log", await bao.ReadTextAsync(OpenBaoFixture.AuditLog)),
        ];

        Assert.NotEmpty(bao.Setup.Stdout);
        CanaryScanner.ThrowIfFound(CanaryScanner.Scan(canaries, sources));

        using var http = new HttpClient { BaseAddress = bao.Address };
        http.DefaultRequestHeaders.Add("X-Vault-Token", rootToken);
        using var lookup = await http.GetAsync("v1/auth/token/lookup-self", Cancellation);
        Assert.Equal(HttpStatusCode.Forbidden, lookup.StatusCode);
    }

    [Fact]
    public async Task Setup_refuses_to_run_twice()
    {
        var again = await bao.ExecAsync("sh", "/opt/gatekeep/openbao/setup.sh");

        Assert.NotEqual(0, again.ExitCode);
        Assert.Contains("already exists", again.Stderr);
    }

    [Fact]
    public async Task Adapter_reaches_OpenBao_over_a_unix_socket()
    {
        var path = Path.Combine(Path.GetTempPath(), $"gk-{Guid.NewGuid():N}.sock");
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(path));
        listener.Listen();
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Cancellation);
        var proxy = ForwardAsync(listener, bao.Address, stop.Token);

        try
        {
            var options = bao.Options(OpenBaoFixture.Worker) with { Address = null, SocketPath = path };
            using var worker = new OpenBaoKeyCustody(options, TimeProvider.System);
            var records = KeyName.ForDeployment(DeploymentKeyClass.Records);

            var signature = await worker.SignAsync(records, Data, Cancellation);

            Assert.True(await worker.VerifyAsync(records, Data, signature, Cancellation));
        }
        finally
        {
            await stop.CancelAsync();
            listener.Close();
            await proxy;
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Setup_that_fails_after_init_still_revokes_the_root_token()
    {
        await using var container = OpenBaoFixture.Build(generateKey: true)
            .WithPortBinding(8210, assignRandomHostPort: true)
            .WithWaitStrategy(DotNet.Testcontainers.Builders.Wait.ForUnixContainer().UntilMessageIsLogged("OpenBao server started"))
            .Build();
        await container.StartAsync(Cancellation);

        // Every policy file exists, so the checks before init pass, and one can't be parsed.
        var broken = await container.ExecAsync(
            ["sh", "-c", "mkdir -p /tmp/policies && cp /opt/gatekeep/openbao/policies/*.hcl /tmp/policies/ && echo 'path {' > /tmp/policies/host-admin.hcl"],
            Cancellation);
        Assert.Equal(0, broken.ExitCode);

        var setup = await container.ExecAsync(
            ["env", "GATEKEEP_POLICY_DIR=/tmp/policies", "sh", "/opt/gatekeep/openbao/setup.sh"],
            Cancellation);
        Assert.NotEqual(0, setup.ExitCode);

        using var escrow = JsonDocument.Parse(System.Text.Encoding.UTF8.GetString(
            await container.ReadFileAsync(OpenBaoFixture.EscrowFile, Cancellation)));
        var rootToken = escrow.RootElement.GetProperty("root_token").GetString()!;

        using var http = new HttpClient
        {
            BaseAddress = new UriBuilder(Uri.UriSchemeHttp, container.Hostname, container.GetMappedPublicPort(8210)).Uri,
        };
        http.DefaultRequestHeaders.Add("X-Vault-Token", rootToken);
        using var lookup = await http.GetAsync("v1/auth/token/lookup-self", Cancellation);
        Assert.Equal(HttpStatusCode.Forbidden, lookup.StatusCode);
    }

    /// <summary>OpenBao's own Tenant check, with associated data the adapter refuses to send.</summary>
    private async Task<HttpStatusCode> RawDecryptAsync(
        KeyName key,
        KeyCiphertext ciphertext,
        Guid boundTenant,
        string role = OpenBaoFixture.Worker)
    {
        using var http = new HttpClient { BaseAddress = bao.Address };
        http.DefaultRequestHeaders.Add("X-Vault-Token", await bao.LoginAsync(role));
        using var response = await http.PostAsJsonAsync(
            $"v1/transit/decrypt/{key}",
            new
            {
                ciphertext = ciphertext.Value,
                associated_data = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(boundTenant.ToString("D"))),
            },
            Cancellation);
        return response.StatusCode;
    }

    /// <summary>Checks the signature is plain RS256, with no help from OpenBao.</summary>
    private static bool VerifiesLocally(string publicKeyPem, KeySignature signature)
    {
        using var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportFromPem(publicKeyPem);
        return rsa.VerifyData(
            Data,
            signature.Value,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
    }

    /// <summary>Windows can't reach the container's socket, so this one forwards to the test listener.</summary>
    private static async Task ForwardAsync(Socket listener, Uri target, CancellationToken cancellationToken)
    {
        var connections = new List<Task>();
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var client = await listener.AcceptAsync(cancellationToken);
                connections.Add(Task.Run(
                    async () =>
                    {
                        using var accepted = client;
                        using var upstream = new TcpClient();
                        await upstream.ConnectAsync(target.Host, target.Port, cancellationToken);
                        await using var a = new NetworkStream(accepted, ownsSocket: false);
                        await using var b = upstream.GetStream();
                        await Task.WhenAny(a.CopyToAsync(b, cancellationToken), b.CopyToAsync(a, cancellationToken));
                    },
                    cancellationToken));
            }
        }
        catch (Exception exception) when (exception is OperationCanceledException or SocketException or ObjectDisposedException)
        {
        }

        try
        {
            await Task.WhenAll(connections);
        }
        catch (Exception exception) when (exception is OperationCanceledException or IOException or SocketException)
        {
        }
    }
}
