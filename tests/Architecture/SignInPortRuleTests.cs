using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// Story 2.9 (AD-8): a release build completes no sign-in. Protocol's <c>IAuthorizationSignIn</c> port
/// has exactly one implementation in <c>src</c>, <c>UnavailableSignIn</c>, which completes nothing, so
/// no code is issued until Stories 4.1 and 4.2. The test-only authenticator, which trusts the User it
/// is given, lives only in the Isolation tests. The built <c>src</c> assemblies are read by reflection
/// in their own load context, as <see cref="TenantKeyedTypeTests"/> reads them.
/// </summary>
public sealed class SignInPortRuleTests
{
    private const string Port = "Gatekeep.Modules.Protocol.Contracts.IAuthorizationSignIn";

    private const string ReleaseDefault = "Gatekeep.Modules.Protocol.Contracts.UnavailableSignIn";

    [Fact]
    public void The_only_src_sign_in_completion_is_the_one_that_completes_nothing()
    {
        var types = TenantKeyedTypeTests.Source.Value.Types;

        // The port exists, so the rule isn't vacuous.
        Assert.Contains(types, t => t.FullName == Port && t.IsInterface);

        var implementations = types
            .Where(t => !t.IsInterface && t.GetInterfaces().Any(i => i.FullName == Port))
            .Select(t => t.FullName)
            .ToList();

        Assert.Equal([ReleaseDefault], implementations);
    }

    [Fact]
    public void The_test_only_authenticator_is_no_src_type()
    {
        var types = TenantKeyedTypeTests.Source.Value.Types;

        Assert.DoesNotContain(types, t => t.Name.StartsWith("TestOnly", StringComparison.Ordinal));
    }
}
