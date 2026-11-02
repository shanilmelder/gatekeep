using System.Net;
using Gatekeep.Adapters.OpenBao;
using Gatekeep.Kernel.Secrets;
using Xunit;

namespace Gatekeep.Tests.Isolation.Custody;

/// <summary>How the adapter reads OpenBao's answers, against a stub with no container.</summary>
public sealed class AdapterMappingTests : IDisposable
{
    private static readonly KeyName Records = KeyName.ForDeployment(DeploymentKeyClass.Records);
    private static readonly byte[] Data = "data"u8.ToArray();

    private readonly string _directory = Path.Combine(Path.GetTempPath(), "gatekeep-stub-" + Guid.NewGuid().ToString("N"));

    public AdapterMappingTests()
    {
        Directory.CreateDirectory(_directory);
        File.WriteAllText(Path.Combine(_directory, "role-id"), "stub-role");
        File.WriteAllText(Path.Combine(_directory, "secret-id"), "stub-secret");
    }

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData(HttpStatusCode.BadRequest, KeyCustodyFailure.Rejected)]
    [InlineData(HttpStatusCode.NotFound, KeyCustodyFailure.Rejected)]
    [InlineData(HttpStatusCode.Forbidden, KeyCustodyFailure.Refused)]
    [InlineData(HttpStatusCode.TooManyRequests, KeyCustodyFailure.Unavailable)]
    [InlineData(HttpStatusCode.InternalServerError, KeyCustodyFailure.Unavailable)]
    [InlineData(HttpStatusCode.ServiceUnavailable, KeyCustodyFailure.Unavailable)]
    public async Task Status_maps_to_a_failure(HttpStatusCode status, KeyCustodyFailure expected)
    {
        using var custody = Custody(new StubOpenBao(status));

        var failure = await Assert.ThrowsAsync<KeyCustodyException>(() => custody.SignAsync(Records, Data, Cancellation));

        Assert.Equal(expected, failure.Failure);
        Assert.Equal(KeyOperation.Sign, failure.Operation);
    }

    [Theory]
    [InlineData(HttpStatusCode.ServiceUnavailable, KeyCustodyFailure.Unavailable)]
    [InlineData(HttpStatusCode.InternalServerError, KeyCustodyFailure.Unavailable)]
    [InlineData(HttpStatusCode.BadRequest, KeyCustodyFailure.LoginFailed)]
    [InlineData(HttpStatusCode.Forbidden, KeyCustodyFailure.LoginFailed)]
    public async Task Login_status_maps_to_a_failure(HttpStatusCode loginStatus, KeyCustodyFailure expected)
    {
        using var custody = Custody(new StubOpenBao(HttpStatusCode.OK, loginStatus: loginStatus));

        var failure = await Assert.ThrowsAsync<KeyCustodyException>(() => custody.SignAsync(Records, Data, Cancellation));

        Assert.Equal(expected, failure.Failure);
    }

    [Theory]
    [InlineData("vault:v-1:AAAA")]
    [InlineData("vault:v+1:AAAA")]
    [InlineData("vault:v 1:AAAA")]
    [InlineData("vault:v0:AAAA")]
    [InlineData("vault:vx:AAAA")]
    [InlineData("vault:v:AAAA")]
    [InlineData("vault:v1:not base64!")]
    [InlineData("vault:v1")]
    [InlineData("other:v1:AAAA")]
    public async Task Malformed_versioned_value_is_unavailable(string signature)
    {
        using var custody = Custody(new StubOpenBao(HttpStatusCode.OK, $$$"""{"data":{"signature":"{{{signature}}}"}}"""));

        var failure = await Assert.ThrowsAsync<KeyCustodyException>(() => custody.SignAsync(Records, Data, Cancellation));

        Assert.Equal(KeyCustodyFailure.Unavailable, failure.Failure);
    }

    [Fact]
    public async Task Well_formed_signature_is_read()
    {
        using var custody = Custody(new StubOpenBao(HttpStatusCode.OK, """{"data":{"signature":"vault:v12:AQID"}}"""));

        var signature = await custody.SignAsync(Records, Data, Cancellation);

        Assert.Equal(12, signature.KeyVersion);
        Assert.Equal([1, 2, 3], signature.Value);
    }

    [Theory]
    [InlineData("""{"data":{"keys":{}}}""")]
    [InlineData("""{"data":{"keys":{"1":1793610269}}}""")]
    [InlineData("""{"data":{}}""")]
    public async Task No_public_key_is_unavailable(string body)
    {
        using var custody = Custody(new StubOpenBao(HttpStatusCode.OK, body));

        var failure = await Assert.ThrowsAsync<KeyCustodyException>(() => custody.GetPublicKeysAsync(Records, Cancellation));

        Assert.Equal(KeyCustodyFailure.Unavailable, failure.Failure);
    }

    [Fact]
    public void Key_names_follow_AD_10()
    {
        var tenant = Guid.Parse("01900000-0000-7000-8000-00000000000a");
        var row = Guid.Parse("01900000-0000-7000-8000-0000000000b1");

        Assert.Equal($"sig-{tenant}-{row}", KeyName.Signing(tenant, row).Value);
        Assert.Equal($"mgmt-{tenant}-{row}", KeyName.Management(tenant, row).Value);
        Assert.Equal(
            [$"totp-{tenant}", $"social-{tenant}", $"email-{tenant}", $"payload-{tenant}", $"hmac-{tenant}", $"tpk-{tenant}"],
            Enum.GetValues<TenantKeyClass>().Select(c => KeyName.ForTenant(c, tenant).Value));
        Assert.Equal(
            ["dep-email", "dep-payload", "dep-hmac", "dep-records"],
            Enum.GetValues<DeploymentKeyClass>().Select(c => KeyName.ForDeployment(c).Value));
        Assert.Equal(tenant, KeyName.ForTenant(TenantKeyClass.Hmac, tenant).TenantId);
        Assert.Equal(KeyKind.Hmac, KeyName.ForTenant(TenantKeyClass.Hmac, tenant).Kind);
        Assert.Equal(KeyKind.Signing, KeyName.ForDeployment(DeploymentKeyClass.Records).Kind);
        Assert.Null(KeyName.ForDeployment(DeploymentKeyClass.Email).TenantId);
    }

    [Fact]
    public void Empty_IDs_name_no_key()
    {
        Assert.Throws<ArgumentException>(() => KeyName.Signing(Guid.Empty, Guid.CreateVersion7()));
        Assert.Throws<ArgumentException>(() => KeyName.Management(Guid.CreateVersion7(), Guid.Empty));
        Assert.Throws<ArgumentException>(() => KeyName.ForTenant(TenantKeyClass.Social, Guid.Empty));
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private OpenBaoKeyCustody Custody(HttpMessageHandler handler) => new(
        handler,
        new OpenBaoOptions
        {
            Address = new Uri("http://stub/"),
            RoleIdFile = Path.Combine(_directory, "role-id"),
            SecretIdFile = Path.Combine(_directory, "secret-id"),
        },
        TimeProvider.System);
}
