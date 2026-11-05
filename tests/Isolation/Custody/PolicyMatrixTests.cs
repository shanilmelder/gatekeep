using System.Net;
using System.Net.Http.Json;
using Gatekeep.Kernel.Secrets;
using Xunit;

namespace Gatekeep.Tests.Isolation.Custody;

public enum CustodyOp
{
    Create,
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    Hmac,
    Wrap,
    Rotate,
    Rewrap,
    Delete,
    ReadPublic,
}

/// <summary>
/// Every operation on every key class, as each host's AppRole. The grants below restate
/// AD-10 and nothing else: anything missing from them must be refused with 403.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class PolicyMatrixTests(OpenBaoFixture bao)
{
    private static readonly string[] SigningTargets = ["sig", "mgmt", "dep-records"];
    private static readonly string[] AeadTargets = ["totp", "social", "email", "payload", "tpk", "dep-email", "dep-payload"];
    private static readonly string[] HmacTargets = ["hmac", "dep-hmac"];
    private static readonly string[] TenantTargets = ["sig", "mgmt", "totp", "social", "email", "payload", "hmac", "tpk"];
    private static readonly string[] DeploymentTargets = ["dep-email", "dep-payload", "dep-hmac", "dep-records"];

    private static readonly byte[] Data = "gatekeep custody test"u8.ToArray();

    private static readonly Dictionary<string, HashSet<(CustodyOp, string)>> Granted = new()
    {
        [OpenBaoFixture.Hosted] =
        [
            (CustodyOp.Sign, "sig"), (CustodyOp.ReadPublic, "sig"),
            (CustodyOp.Encrypt, "totp"), (CustodyOp.Encrypt, "payload"),
            (CustodyOp.Decrypt, "totp"), (CustodyOp.Decrypt, "social"), (CustodyOp.Decrypt, "tpk"),
            (CustodyOp.Hmac, "hmac"),
        ],
        [OpenBaoFixture.Admin] =
        [
            (CustodyOp.Create, "sig"), (CustodyOp.Create, "mgmt"), (CustodyOp.Sign, "mgmt"),
            (CustodyOp.Encrypt, "social"), (CustodyOp.Encrypt, "email"), (CustodyOp.Encrypt, "payload"),
            (CustodyOp.Encrypt, "dep-email"), (CustodyOp.Encrypt, "dep-payload"),
            (CustodyOp.Hmac, "dep-hmac"),
        ],
        [OpenBaoFixture.Worker] =
        [
            .. TenantTargets.SelectMany(t => new[] { (CustodyOp.Create, t), (CustodyOp.Rotate, t), (CustodyOp.Delete, t) }),
            (CustodyOp.ReadPublic, "sig"), (CustodyOp.ReadPublic, "mgmt"), (CustodyOp.ReadPublic, "dep-records"),
            (CustodyOp.Wrap, "tpk"),
            (CustodyOp.Decrypt, "social"), (CustodyOp.Decrypt, "email"), (CustodyOp.Decrypt, "payload"),
            (CustodyOp.Decrypt, "dep-email"), (CustodyOp.Decrypt, "dep-payload"),
            (CustodyOp.Sign, "dep-records"), (CustodyOp.Verify, "dep-records"),
        ],
        [OpenBaoFixture.Cli] =
        [
            .. TenantTargets.Concat(DeploymentTargets).SelectMany(t => new[] { (CustodyOp.Create, t), (CustodyOp.Rotate, t) }),
            .. TenantTargets.Select(t => (CustodyOp.Delete, t)),
            .. AeadTargets.Select(t => (CustodyOp.Rewrap, t)),
            (CustodyOp.Encrypt, "social"), (CustodyOp.Encrypt, "email"), (CustodyOp.Encrypt, "dep-email"),
            (CustodyOp.Sign, "dep-records"), (CustodyOp.Verify, "dep-records"),
            (CustodyOp.ReadPublic, "sig"), (CustodyOp.ReadPublic, "mgmt"), (CustodyOp.ReadPublic, "dep-records"),
        ],
    };

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public static TheoryData<string, CustodyOp, string, bool> Matrix()
    {
        var data = new TheoryData<string, CustodyOp, string, bool>();
        foreach (var role in OpenBaoFixture.Roles)
        {
            foreach (var (op, target) in Operations())
            {
                data.Add(role, op, target, Granted[role].Contains((op, target)));
            }
        }

        return data;
    }

    public static TheoryData<string> Roles => [.. OpenBaoFixture.Roles];

    [Theory]
    [MemberData(nameof(Matrix))]
    public async Task Role_can_do_only_what_AD_10_grants(string role, CustodyOp op, string target, bool granted)
    {
        var prepared = await PrepareAsync(op, target);
        using var custody = bao.Custody(role);

        if (granted && op == CustodyOp.Rewrap)
        {
            // The policy lets it through, but OpenBao 2.7.2 rewrap takes no associated data,
            // so every Gatekeep ciphertext fails authentication there (G-16).
            var rejected = await Assert.ThrowsAsync<KeyCustodyException>(() => RunAsync(custody, op, target, prepared));
            Assert.Equal(KeyCustodyFailure.Rejected, rejected.Failure);
        }
        else if (granted)
        {
            await RunAsync(custody, op, target, prepared);
        }
        else
        {
            var refused = await Assert.ThrowsAsync<KeyCustodyException>(() => RunAsync(custody, op, target, prepared));
            Assert.Equal(KeyCustodyFailure.Refused, refused.Failure);
            Assert.Equal(prepared.Key.Value, refused.KeyName);
        }
    }

    [Fact]
    public void Grants_name_only_operations_the_matrix_runs()
    {
        var operations = Operations().ToHashSet();

        Assert.All(Granted.Values.SelectMany(g => g), grant => Assert.Contains(grant, operations));
    }

    [Theory]
    [MemberData(nameof(Roles))]
    public async Task Export_backup_restore_and_exportable_keys_are_refused(string role)
    {
        var token = await bao.LoginAsync(role);
        using var http = new HttpClient { BaseAddress = bao.Address };
        http.DefaultRequestHeaders.Add("X-Vault-Token", token);

        var social = KeyName.ForTenant(TenantKeyClass.Social, bao.TenantA).Value;
        var fresh = KeyName.ForTenant(TenantKeyClass.Social, Guid.CreateVersion7()).Value;
        var signing = bao.SigningA.Value;

        (HttpMethod Method, string Path, object? Body)[] requests =
        [
            (HttpMethod.Get, $"v1/transit/export/encryption-key/{social}", null),
            (HttpMethod.Get, $"v1/transit/export/hmac-key/{social}", null),
            (HttpMethod.Get, $"v1/transit/export/signing-key/{signing}", null),
            (HttpMethod.Get, $"v1/transit/export/public-key/{signing}", null),
            (HttpMethod.Get, $"v1/transit/backup/{social}", null),
            (HttpMethod.Get, "v1/transit/backup/dep-records", null),
            (HttpMethod.Post, $"v1/transit/restore/{fresh}", new { backup = "AAAA" }),
            (HttpMethod.Post, $"v1/transit/keys/{fresh}", new { type = "aes256-gcm96", exportable = true }),
            (HttpMethod.Post, $"v1/transit/keys/{fresh}", new { type = "aes256-gcm96", allow_plaintext_backup = true }),
            (HttpMethod.Post, $"v1/transit/keys/{social}/config", new { exportable = true }),
            (HttpMethod.Post, $"v1/transit/keys/{social}/config", new { allow_plaintext_backup = true }),
            (HttpMethod.Post, $"v1/transit/keys/{signing}/config", new { exportable = true }),
            (HttpMethod.Post, "v1/transit/keys/dep-records/config", new { exportable = true }),
            (HttpMethod.Post, $"v1/transit/keys/{fresh}/import", new { type = "aes256-gcm96", ciphertext = "AAAA", hash_function = "SHA256" }),
            (HttpMethod.Post, $"v1/transit/keys/{social}/import_version", new { ciphertext = "AAAA" }),
            (HttpMethod.Post, $"v1/transit/keys/{signing}/import_version", new { public_key = "AAAA" }),
            (HttpMethod.Post, "v1/transit/keys/dep-email/import_version", new { ciphertext = "AAAA" }),
            (HttpMethod.Post, $"v1/transit/keys/{social}/trim", new { min_available_version = 1 }),
            (HttpMethod.Post, "v1/transit/keys/dep-records/trim", new { min_available_version = 1 }),
            (HttpMethod.Post, $"v1/transit/keys/{social}/config", new { min_decryption_version = 1 }),
            (HttpMethod.Post, "v1/transit/keys/dep-payload/config", new { min_decryption_version = 1 }),
            (HttpMethod.Post, "v1/transit/keys/dep-records/config", new { deletion_allowed = true }),
            (HttpMethod.Post, "v1/transit/keys/dep-hmac/config", new { deletion_allowed = true }),
            (HttpMethod.Get, "v1/transit/wrapping_key", null),
            (HttpMethod.Post, "v1/transit/datakey/plaintext/" + KeyName.ForTenant(TenantKeyClass.TokenProtection, bao.TenantA).Value, new { bits = 256 }),
        ];

        foreach (var (method, path, body) in requests)
        {
            using var request = new HttpRequestMessage(method, path);
            if (body is not null)
            {
                request.Content = JsonContent.Create(body);
            }

            using var response = await http.SendAsync(request, Cancellation);
            Assert.True(response.StatusCode == HttpStatusCode.Forbidden, $"{role} {method} {path}: {(int)response.StatusCode}");
        }
    }

    [Theory]
    [MemberData(nameof(Roles))]
    public async Task Only_the_Worker_lists_keys_and_the_list_holds_only_row_keys(string role)
    {
        using var custody = bao.Custody(role);

        if (role != OpenBaoFixture.Worker)
        {
            var refused = await Assert.ThrowsAsync<KeyCustodyException>(() => custody.ListRowKeysAsync(Cancellation));
            Assert.Equal(KeyCustodyFailure.Refused, refused.Failure);
            return;
        }

        var listed = await custody.ListRowKeysAsync(Cancellation);
        var signing = Assert.Single(listed, k => k.Key.Equals(bao.SigningA));
        Assert.InRange(signing.CreatedAt, DateTimeOffset.UtcNow - TimeSpan.FromHours(2), DateTimeOffset.UtcNow + TimeSpan.FromMinutes(5));
        Assert.Contains(listed, k => k.Key.Equals(bao.ManagementA));
        Assert.All(listed, k => Assert.True(KeyName.TryParseRowKey(k.Key.Value, out _)));
    }

    [Theory]
    [InlineData(OpenBaoFixture.Cli, "dep-records")]
    [InlineData(OpenBaoFixture.Worker, "dep-records")]
    [InlineData(OpenBaoFixture.Admin, "sig")]
    [InlineData(OpenBaoFixture.Hosted, "sig")]
    public async Task Refused_delete_leaves_the_key_in_place(string role, string target)
    {
        var key = target == "sig" ? bao.SigningA : Deployment(target);
        using var custody = bao.Custody(role);
        using var worker = bao.Custody(OpenBaoFixture.Worker);

        var refused = await Assert.ThrowsAsync<KeyCustodyException>(() => custody.DeleteAsync(key, Cancellation));

        Assert.Equal(KeyCustodyFailure.Refused, refused.Failure);
        Assert.NotEmpty(await worker.GetPublicKeysAsync(key, Cancellation));
    }

    /// <summary>
    /// Known limit, recorded as T-45: a policy glob on <c>transit/keys/sig-*</c> also reaches
    /// <c>/rotate</c>, and OpenBao ignores the pinned <c>type</c> there, so a crafted request lets
    /// <c>Host.Admin</c> add a version to a Signing or Management key. The adapter's own rotate
    /// sends no parameters and is refused, as the matrix shows. Nothing is exported either way.
    /// </summary>
    [Fact]
    public async Task Known_limit_admin_can_rotate_its_keys_with_a_crafted_request()
    {
        var token = await bao.LoginAsync(OpenBaoFixture.Admin);
        using var http = new HttpClient { BaseAddress = bao.Address };
        http.DefaultRequestHeaders.Add("X-Vault-Token", token);
        var key = KeyName.Management(bao.TenantA, Guid.CreateVersion7());
        using (var admin = bao.Custody(OpenBaoFixture.Admin))
        {
            await admin.CreateKeyAsync(key, Cancellation);
        }

        using var bare = await http.PostAsJsonAsync($"v1/transit/keys/{key}/rotate", new { }, Cancellation);
        using var crafted = await http.PostAsJsonAsync($"v1/transit/keys/{key}/rotate", new { type = "rsa-3072" }, Cancellation);

        Assert.Equal(HttpStatusCode.Forbidden, bare.StatusCode);
        Assert.Equal(HttpStatusCode.OK, crafted.StatusCode);
    }

    private static IEnumerable<(CustodyOp Op, string Target)> Operations()
    {
        foreach (var target in SigningTargets)
        {
            foreach (var op in new[] { CustodyOp.Create, CustodyOp.Sign, CustodyOp.Verify, CustodyOp.Rotate, CustodyOp.Delete, CustodyOp.ReadPublic })
            {
                yield return (op, target);
            }
        }

        foreach (var target in AeadTargets)
        {
            foreach (var op in new[] { CustodyOp.Create, CustodyOp.Encrypt, CustodyOp.Decrypt, CustodyOp.Rotate, CustodyOp.Rewrap, CustodyOp.Delete })
            {
                yield return (op, target);
            }
        }

        yield return (CustodyOp.Wrap, "tpk");

        foreach (var target in HmacTargets)
        {
            foreach (var op in new[] { CustodyOp.Create, CustodyOp.Hmac, CustodyOp.Rotate, CustodyOp.Delete })
            {
                yield return (op, target);
            }
        }
    }

    private sealed record Prepared(KeyName Key, Guid? TenantId, KeyCiphertext? Ciphertext, KeySignature? Signature);

    /// <summary>
    /// The key and any input an operation needs, made by a role that's allowed to make it.
    /// Create and Delete use a new Tenant key, so a granted call really creates or destroys.
    /// </summary>
    private async Task<Prepared> PrepareAsync(CustodyOp op, string target)
    {
        var tenant = target.StartsWith("dep-", StringComparison.Ordinal) ? (Guid?)null : bao.TenantA;

        if (op is CustodyOp.Create or CustodyOp.Delete && tenant is not null)
        {
            tenant = Guid.CreateVersion7();
            var key = Key(target, tenant.Value);
            if (op == CustodyOp.Delete)
            {
                using var worker = bao.Custody(OpenBaoFixture.Worker);
                await worker.CreateKeyAsync(key, Cancellation);
            }

            return new Prepared(key, tenant, null, null);
        }

        var name = tenant is { } id ? Key(target, id) : Deployment(target);
        KeyCiphertext? ciphertext = null;
        KeySignature? signature = null;

        if (op is CustodyOp.Decrypt or CustodyOp.Rewrap)
        {
            ciphertext = await CiphertextAsync(target, name, tenant);
        }

        if (op == CustodyOp.Verify)
        {
            var signer = target switch { "sig" => OpenBaoFixture.Hosted, "mgmt" => OpenBaoFixture.Admin, _ => OpenBaoFixture.Worker };
            using var custody = bao.Custody(signer);
            signature = await custody.SignAsync(name, Data, Cancellation);
        }

        return new Prepared(name, tenant, ciphertext, signature);
    }

    private async Task<KeyCiphertext> CiphertextAsync(string target, KeyName key, Guid? tenant)
    {
        if (target == "tpk")
        {
            using var worker = bao.Custody(OpenBaoFixture.Worker);
            return await worker.CreateWrappedDataKeyAsync(key, tenant!.Value, Cancellation);
        }

        var encrypter = target switch
        {
            "totp" or "payload" => OpenBaoFixture.Hosted,
            "dep-payload" => OpenBaoFixture.Admin,
            _ => OpenBaoFixture.Cli,
        };

        using var custody = bao.Custody(encrypter);
        return await custody.EncryptAsync(key, tenant, new Secret<byte[]>(Data), Cancellation);
    }

    private static async Task RunAsync(IKeyCustody custody, CustodyOp op, string target, Prepared p)
    {
        switch (op)
        {
            case CustodyOp.Create:
                var created = await custody.CreateKeyAsync(p.Key, Cancellation);
                Assert.Equal(p.Key.Kind == KeyKind.Signing, created.Count > 0);
                break;
            case CustodyOp.Sign:
                var signature = await custody.SignAsync(p.Key, Data, Cancellation);
                Assert.NotEmpty(signature.Value);
                break;
            case CustodyOp.Verify:
                Assert.True(await custody.VerifyAsync(p.Key, Data, p.Signature!, Cancellation));
                Assert.False(await custody.VerifyAsync(p.Key, "other"u8.ToArray(), p.Signature!, Cancellation));
                break;
            case CustodyOp.Encrypt:
                var ciphertext = await custody.EncryptAsync(p.Key, p.TenantId, new Secret<byte[]>(Data), Cancellation);
                Assert.DoesNotContain(Convert.ToBase64String(Data), ciphertext.Value);
                break;
            case CustodyOp.Decrypt:
                var plaintext = await custody.DecryptAsync(p.Key, p.TenantId, p.Ciphertext!, Cancellation);
                if (target != "tpk")
                {
                    Assert.Equal(Data, plaintext.Use(b => b));
                }
                else
                {
                    Assert.Equal(32, plaintext.Use(b => b.Length));
                }

                break;
            case CustodyOp.Hmac:
                var hmac = await custody.HmacAsync(p.Key, new Secret<byte[]>(Data), Cancellation);
                Assert.Equal(32, hmac.Value.Length);
                break;
            case CustodyOp.Wrap:
                await custody.CreateWrappedDataKeyAsync(p.Key, p.TenantId!.Value, Cancellation);
                break;
            case CustodyOp.Rotate:
                await custody.RotateAsync(p.Key, Cancellation);
                break;
            case CustodyOp.Rewrap:
                var rewrapped = await custody.RewrapAsync(p.Key, p.TenantId, p.Ciphertext!, Cancellation);
                Assert.StartsWith("vault:v", rewrapped.Value, StringComparison.Ordinal);
                break;
            case CustodyOp.Delete:
                await custody.DeleteAsync(p.Key, Cancellation);
                break;
            case CustodyOp.ReadPublic:
                var versions = await custody.GetPublicKeysAsync(p.Key, Cancellation);
                Assert.All(versions, v => Assert.StartsWith("-----BEGIN PUBLIC KEY-----", v.PublicKeyPem, StringComparison.Ordinal));
                Assert.NotEmpty(versions);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(op));
        }
    }

    private KeyName Key(string target, Guid tenant) => target switch
    {
        "sig" => tenant == bao.TenantA ? bao.SigningA : KeyName.Signing(tenant, Guid.CreateVersion7()),
        "mgmt" => tenant == bao.TenantA ? bao.ManagementA : KeyName.Management(tenant, Guid.CreateVersion7()),
        "totp" => KeyName.ForTenant(TenantKeyClass.Totp, tenant),
        "social" => KeyName.ForTenant(TenantKeyClass.Social, tenant),
        "email" => KeyName.ForTenant(TenantKeyClass.Email, tenant),
        "payload" => KeyName.ForTenant(TenantKeyClass.Payload, tenant),
        "hmac" => KeyName.ForTenant(TenantKeyClass.Hmac, tenant),
        "tpk" => KeyName.ForTenant(TenantKeyClass.TokenProtection, tenant),
        _ => throw new ArgumentOutOfRangeException(nameof(target)),
    };

    private static KeyName Deployment(string target) => target switch
    {
        "dep-email" => KeyName.ForDeployment(DeploymentKeyClass.Email),
        "dep-payload" => KeyName.ForDeployment(DeploymentKeyClass.Payload),
        "dep-hmac" => KeyName.ForDeployment(DeploymentKeyClass.Hmac),
        "dep-records" => KeyName.ForDeployment(DeploymentKeyClass.Records),
        _ => throw new ArgumentOutOfRangeException(nameof(target)),
    };
}
