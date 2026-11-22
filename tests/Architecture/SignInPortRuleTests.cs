using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// Stories 2.9 and 4.2 (AD-8, AD-12): a release build signs a User in only through Hosted Login. Protocol's
/// <c>IAuthorizationSignIn</c> port has exactly one implementation in <c>src</c>, Protocol's own, over the bound
/// sign-in transaction and the Session cookie. Authentication's <c>ICredentialStep</c> port has exactly one too,
/// the empty default, which authenticates no one at Continue, so a User signs in only through Story 4.9's Password
/// step. The test-only credential step and authenticator, which trust the User they are given, live only in
/// the Isolation tests. The built <c>src</c> assemblies are read by reflection in their own load context, as
/// <see cref="TenantKeyedTypeTests"/> reads them.
/// </summary>
public sealed class SignInPortRuleTests
{
    private const string Port = "Gatekeep.Modules.Protocol.Contracts.IAuthorizationSignIn";

    private const string HostedSignIn = "Gatekeep.Modules.Protocol.Core.HostedAuthorizationSignIn";

    private const string CredentialStepPort = "Gatekeep.Modules.Authentication.Contracts.ICredentialStep";

    private const string EmptyCredentialStep = "Gatekeep.Modules.Authentication.Core.NoCredentialStep";

    [Fact]
    public void The_only_src_sign_in_is_Protocols_own()
    {
        Assert.Equal([HostedSignIn], Implementations(Port));
    }

    [Fact]
    public void The_only_src_credential_step_is_the_empty_default()
    {
        Assert.Equal([EmptyCredentialStep], Implementations(CredentialStepPort));
    }

    [Fact]
    public void The_test_only_authenticator_is_no_src_type()
    {
        var types = TenantKeyedTypeTests.Source.Value.Types;

        Assert.DoesNotContain(types, t => t.Name.StartsWith("TestOnly", StringComparison.Ordinal));
    }

    /// <summary>The <c>src</c> types implementing <paramref name="port"/>, which must exist so the rule isn't vacuous.</summary>
    private static List<string?> Implementations(string port)
    {
        var types = TenantKeyedTypeTests.Source.Value.Types;

        Assert.Contains(types, t => t.FullName == port && t.IsInterface);

        return types
            .Where(t => !t.IsInterface && t.GetInterfaces().Any(i => i.FullName == port))
            .Select(t => t.FullName)
            .ToList();
    }
}
