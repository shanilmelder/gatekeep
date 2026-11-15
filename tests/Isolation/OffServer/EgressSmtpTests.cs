using System.Security.Cryptography.X509Certificates;
using Gatekeep.Adapters.Egress;
using Gatekeep.Tests.Isolation.Notifications;
using Xunit;

namespace Gatekeep.Tests.Isolation.OffServer;

/// <summary>
/// Story 4.5: how the SMTP path builds a server's certificate chain. Revocation is never checked and no certificate is
/// downloaded, since a CRL, OCSP or issuer URL the certificate names would be fetched outside the egress checks. In
/// production the platform's roots are trusted; a test permit trusts its own root and nothing else.
/// </summary>
public sealed class EgressSmtpTests
{
    [Fact]
    public void Production_chain_policy_checks_no_revocation_downloads_nothing_and_trusts_the_system_roots()
    {
        var policy = EgressSmtp.Create().CreateChainPolicy();

        Assert.Equal(X509RevocationMode.NoCheck, policy.RevocationMode);
        Assert.True(policy.DisableCertificateDownloads);
        Assert.Equal(X509ChainTrustMode.System, policy.TrustMode);
        Assert.Empty(policy.CustomTrustStore);
    }

    [Fact]
    public void Test_permit_chain_policy_trusts_only_its_root()
    {
        var permit = new EgressPermit(PrivateAddresses: false, PlainHttp: false, TrustedRoot: TestCertificates.Root);

        var policy = EgressSmtp.Create(permit).CreateChainPolicy();

        Assert.Equal(X509RevocationMode.NoCheck, policy.RevocationMode);
        Assert.True(policy.DisableCertificateDownloads);
        Assert.Equal(X509ChainTrustMode.CustomRootTrust, policy.TrustMode);
        Assert.Equal(TestCertificates.Root.Thumbprint, Assert.Single(policy.CustomTrustStore).Thumbprint);
    }
}
