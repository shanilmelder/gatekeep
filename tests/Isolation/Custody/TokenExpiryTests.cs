using Gatekeep.Kernel.Secrets;
using Xunit;

namespace Gatekeep.Tests.Isolation.Custody;

/// <summary>
/// Tokens here live three seconds. The clock is frozen, so the adapter believes its token
/// is still fresh and only OpenBao's 403 tells it otherwise.
/// </summary>
public sealed class TokenExpiryTests(ShortTokenOpenBaoFixture bao) : IClassFixture<ShortTokenOpenBaoFixture>
{
    private static readonly byte[] Data = "record"u8.ToArray();

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Expired_token_logs_in_again_once_and_the_call_succeeds()
    {
        var counter = new CountingHandler();
        using var worker = bao.Custody(OpenBaoFixture.Worker, new FrozenTime(), counter.Wrap);
        var records = KeyName.ForDeployment(DeploymentKeyClass.Records);

        await worker.SignAsync(records, Data, Cancellation);
        await Task.Delay(TimeSpan.FromSeconds(5), Cancellation);
        var signature = await worker.SignAsync(records, Data, Cancellation);

        Assert.True(await worker.VerifyAsync(records, Data, signature, Cancellation));
        Assert.Equal(2, counter.Count("/login"));
        Assert.Equal(3, counter.Count("/transit/sign/"));
    }

    /// <summary>Story 1.29: destroying a key reads it first, and that read logs in again once on an expired token too.</summary>
    [Fact]
    public async Task Expired_token_logs_in_again_once_and_a_delete_succeeds()
    {
        var counter = new CountingHandler();
        using var worker = bao.Custody(OpenBaoFixture.Worker, new FrozenTime(), counter.Wrap);
        var hmac = KeyName.ForTenant(TenantKeyClass.Hmac, Guid.CreateVersion7());

        await worker.CreateKeyAsync(hmac, Cancellation);
        await Task.Delay(TimeSpan.FromSeconds(5), Cancellation);
        await worker.DeleteAsync(hmac, Cancellation);

        Assert.Equal(2, counter.Count("/login"));

        // Gone: a second destroy finds no key and succeeds, with no new login.
        await worker.DeleteAsync(hmac, Cancellation);
        Assert.Equal(2, counter.Count("/login"));
    }

    [Fact]
    public async Task Refusal_retries_once_after_a_new_login_then_fails()
    {
        var counter = new CountingHandler();
        using var worker = bao.Custody(OpenBaoFixture.Worker, new FrozenTime(), counter.Wrap);
        var records = KeyName.ForDeployment(DeploymentKeyClass.Records);
        var totp = KeyName.ForTenant(TenantKeyClass.Totp, bao.TenantA);

        await worker.SignAsync(records, Data, Cancellation);
        var refused = await Assert.ThrowsAsync<KeyCustodyException>(
            () => worker.EncryptAsync(totp, bao.TenantA, new Secret<byte[]>(Data), Cancellation));

        Assert.Equal(KeyCustodyFailure.Refused, refused.Failure);
        Assert.Equal(2, counter.Count("/login"));
        Assert.Equal(2, counter.Count("/transit/encrypt/"));
    }

    [Fact]
    public async Task Refusal_with_a_fresh_token_isnt_retried()
    {
        var counter = new CountingHandler();
        using var worker = bao.Custody(OpenBaoFixture.Worker, new FrozenTime(), counter.Wrap);
        var totp = KeyName.ForTenant(TenantKeyClass.Totp, bao.TenantA);

        var refused = await Assert.ThrowsAsync<KeyCustodyException>(
            () => worker.EncryptAsync(totp, bao.TenantA, new Secret<byte[]>(Data), Cancellation));

        Assert.Equal(KeyCustodyFailure.Refused, refused.Failure);
        Assert.Equal(1, counter.Count("/login"));
        Assert.Equal(1, counter.Count("/transit/encrypt/"));
    }
}
