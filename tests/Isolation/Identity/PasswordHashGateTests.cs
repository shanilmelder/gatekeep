using Gatekeep.Modules.Authentication.Contracts;
using Xunit;

namespace Gatekeep.Tests.Isolation.Identity;

/// <summary>
/// Story 4.7 (AD-14): the hashing budget's gate, used directly with no wait, so every refusal is immediate. A Tenant
/// holding its share is refused while another is admitted, the Deployment-wide limit refuses every Tenant, and a
/// disposed slot is free again.
/// </summary>
public sealed class PasswordHashGateTests
{
    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-0000000048a1");
    private static readonly Guid TenantB = Guid.Parse("01900000-0000-7000-8000-0000000048a2");
    private static readonly Guid TenantC = Guid.Parse("01900000-0000-7000-8000-0000000048a3");

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private static IPasswordHashGate Gate() =>
        AuthenticationContract.CreatePasswordHashGate(new PasswordHashLimits(concurrency: 3, tenantShare: 2, wait: TimeSpan.Zero), new FixedTime());

    [Fact]
    public async Task A_Tenant_holding_its_share_is_refused_while_another_is_admitted()
    {
        var gate = Gate();
        using var first = await gate.EnterAsync(TenantA, Cancellation);
        using var second = await gate.EnterAsync(TenantA, Cancellation);
        Assert.NotNull(first);
        Assert.NotNull(second);

        Assert.Null(await gate.EnterAsync(TenantA, Cancellation));
        using var other = await gate.EnterAsync(TenantB, Cancellation);
        Assert.NotNull(other);
    }

    [Fact]
    public async Task The_Deployment_wide_limit_refuses_every_Tenant()
    {
        var gate = Gate();
        using var a1 = await gate.EnterAsync(TenantA, Cancellation);
        using var a2 = await gate.EnterAsync(TenantA, Cancellation);
        using var b1 = await gate.EnterAsync(TenantB, Cancellation);
        Assert.NotNull(b1);

        // Three slots held: B still has share left, and C has all of its own, but neither gets in.
        Assert.Null(await gate.EnterAsync(TenantB, Cancellation));
        Assert.Null(await gate.EnterAsync(TenantC, Cancellation));
    }

    [Fact]
    public async Task A_disposed_slot_is_free_again()
    {
        var gate = Gate();
        for (var entry = 0; entry < 5; entry++)
        {
            using var slot = await gate.EnterAsync(TenantA, Cancellation);
            Assert.NotNull(slot);
        }

        // Disposing twice frees one slot, not two.
        var held = await gate.EnterAsync(TenantA, Cancellation);
        held!.Dispose();
        held.Dispose();
        using var x = await gate.EnterAsync(TenantA, Cancellation);
        using var y = await gate.EnterAsync(TenantA, Cancellation);
        Assert.NotNull(y);
        Assert.Null(await gate.EnterAsync(TenantA, Cancellation));
    }

    /// <summary>A clock that never moves: a zero wait is the whole budget, so the gate never waits.</summary>
    private sealed class FixedTime : TimeProvider
    {
        private readonly DateTimeOffset _now = DateTimeOffset.UtcNow;

        public override DateTimeOffset GetUtcNow() => _now;
    }
}
