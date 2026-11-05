using System.Text.Json;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Keys.Contracts;
using Xunit;

namespace Gatekeep.Tests.Isolation.Custody;

/// <summary>
/// Story 1.27 (AD-10): a new Tenant's six secret class keys, created through the Keys contract on
/// the real OpenBao under the <c>host-worker</c> policy, the only host policy that may. Creating
/// them again leaves every key at version 1, so the creation stage repeats safely, and
/// <c>host-admin</c> is refused. Story 1.29: the Worker destroys them, a repeat succeeds, another
/// Tenant's are untouched, and <c>host-admin</c> and <c>host-hosted</c> are refused.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class SecretClassKeyTests(OpenBaoFixture bao)
{
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Worker_creates_the_six_keys_and_a_repeat_changes_none()
    {
        var tenant = Guid.CreateVersion7();
        using var worker = bao.Custody(OpenBaoFixture.Worker);

        await KeysContract.CreateSecretClassKeysAsync(worker, tenant, Cancellation);
        var first = await VersionsAsync(tenant);

        await KeysContract.CreateSecretClassKeysAsync(worker, tenant, Cancellation);
        var second = await VersionsAsync(tenant);

        Assert.Equal(
            [$"totp-{tenant:D}", $"social-{tenant:D}", $"email-{tenant:D}", $"payload-{tenant:D}", $"hmac-{tenant:D}", $"tpk-{tenant:D}"],
            KeysContract.SecretClassKeys(tenant).Select(k => k.Value));
        Assert.Equal(6, first.Count);
        Assert.All(first.Values, v => Assert.Equal(1, v));
        Assert.Equal(first, second);
    }

    [Theory]
    [InlineData(OpenBaoFixture.Admin)]
    [InlineData(OpenBaoFixture.Hosted)]
    public async Task Other_hosts_cant_create_them(string role)
    {
        var tenant = Guid.CreateVersion7();
        using var custody = bao.Custody(role);

        var refused = await Assert.ThrowsAsync<KeyCustodyException>(() => KeysContract.CreateSecretClassKeysAsync(custody, tenant, Cancellation));

        Assert.Equal(KeyCustodyFailure.Refused, refused.Failure);
        Assert.Equal(KeyOperation.Create, refused.Operation);
        Assert.Empty(await VersionsAsync(tenant));
    }

    /// <summary>Story 1.29: the Worker destroys a Tenant's six keys, every version, and a repeat, or a rerun part way, succeeds.</summary>
    [Fact]
    public async Task Worker_destroys_the_six_keys_and_a_repeat_succeeds()
    {
        var tenant = Guid.CreateVersion7();
        var other = Guid.CreateVersion7();
        using var worker = bao.Custody(OpenBaoFixture.Worker);
        await KeysContract.CreateSecretClassKeysAsync(worker, tenant, Cancellation);
        await KeysContract.CreateSecretClassKeysAsync(worker, other, Cancellation);
        await worker.RotateAsync(KeyName.ForTenant(TenantKeyClass.Hmac, tenant), Cancellation);
        var others = await VersionsAsync(other);

        await KeysContract.DestroySecretClassKeysAsync(worker, tenant, Cancellation);
        Assert.Empty(await VersionsAsync(tenant));

        // Already gone: destroyed. And after a rerun that stopped part way, the rest goes.
        await KeysContract.DestroySecretClassKeysAsync(worker, tenant, Cancellation);
        await worker.CreateKeyAsync(KeyName.ForTenant(TenantKeyClass.TokenProtection, tenant), Cancellation);
        await KeysContract.DestroySecretClassKeysAsync(worker, tenant, Cancellation);
        Assert.Empty(await VersionsAsync(tenant));

        // Another Tenant's keys, and their versions, are untouched.
        Assert.Equal(6, others.Count);
        Assert.Equal(others, await VersionsAsync(other));
    }

    [Theory]
    [InlineData(OpenBaoFixture.Admin)]
    [InlineData(OpenBaoFixture.Hosted)]
    public async Task Other_hosts_cant_destroy_them(string role)
    {
        var tenant = Guid.CreateVersion7();
        using var worker = bao.Custody(OpenBaoFixture.Worker);
        using var custody = bao.Custody(role);
        await KeysContract.CreateSecretClassKeysAsync(worker, tenant, Cancellation);

        var refused = await Assert.ThrowsAsync<KeyCustodyException>(() => KeysContract.DestroySecretClassKeysAsync(custody, tenant, Cancellation));

        Assert.Equal(KeyCustodyFailure.Refused, refused.Failure);
        Assert.Equal(KeyOperation.Delete, refused.Operation);
        Assert.Equal(6, (await VersionsAsync(tenant)).Count);
    }

    /// <summary>Each of the Tenant's secret class keys that exists, and its latest version, read as the Worker.</summary>
    private async Task<Dictionary<string, int>> VersionsAsync(Guid tenant)
    {
        var token = await bao.LoginAsync(OpenBaoFixture.Worker);
        using var http = new HttpClient { BaseAddress = bao.Address };
        http.DefaultRequestHeaders.Add("X-Vault-Token", token);

        var versions = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var key in KeysContract.SecretClassKeys(tenant))
        {
            using var response = await http.GetAsync($"v1/transit/keys/{key.Value}", Cancellation);
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                continue;
            }

            response.EnsureSuccessStatusCode();
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
            versions[key.Value] = body.RootElement.GetProperty("data").GetProperty("latest_version").GetInt32();
        }

        return versions;
    }
}
