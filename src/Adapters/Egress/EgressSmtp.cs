using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace Gatekeep.Adapters.Egress;

/// <summary>
/// The one outbound SMTP path (AD-26, Story 4.5): the same vetted connect as <see cref="EgressHttp"/>. It resolves the
/// name itself, refuses one with no public address, and connects only to an address it has checked, so DNS rebinding
/// can't swap a private one in after the check, and gives up connecting after <see cref="ConnectTimeout"/>. It hands
/// back the bare TCP stream: the SMTP client then runs STARTTLS or implicit TLS over it, building the certificate chain
/// with <see cref="CreateChainPolicy"/>. There is no plaintext SMTP.
/// </summary>
public sealed class EgressSmtp
{
    public static readonly TimeSpan ConnectTimeout = EgressHttp.ConnectTimeout;

    private readonly EgressPermit _permit;
    private readonly Func<string, CancellationToken, Task<IPAddress[]>> _resolve;
    private readonly Func<IPEndPoint, CancellationToken, ValueTask<Stream>> _connect;

    private EgressSmtp(
        EgressPermit permit,
        Func<string, CancellationToken, Task<IPAddress[]>>? resolve,
        Func<IPEndPoint, CancellationToken, ValueTask<Stream>>? connect)
    {
        _permit = permit;
        _resolve = resolve ?? Dns.GetHostAddressesAsync;
        _connect = connect ?? EgressHttp.ConnectSocketAsync;
    }

    /// <summary>With every refusal in force and the platform's certificate validation.</summary>
    public static EgressSmtp Create() => new(EgressPermit.None, null, null);

    /// <summary>
    /// The test seam: may relax what <paramref name="permit"/> names, trust its test root, and stand in for the name
    /// lookup and the TCP connect, as <see cref="EgressHttp"/>'s does.
    /// </summary>
    internal static EgressSmtp Create(
        EgressPermit permit,
        Func<string, CancellationToken, Task<IPAddress[]>>? resolve = null,
        Func<IPEndPoint, CancellationToken, ValueTask<Stream>>? connect = null)
    {
        ArgumentNullException.ThrowIfNull(permit);
        return new EgressSmtp(permit, resolve, connect);
    }

    /// <summary>
    /// How the server's certificate chain is built (Story 4.5): against the platform's roots, or only a test permit's
    /// root, with revocation unchecked and no certificate downloaded. The SMTP host is a Tenant's choice, so nothing its
    /// certificate names (a CRL, OCSP or issuer URL) is ever fetched: such a fetch would leave outside the egress checks.
    /// A new policy each call, owned by the caller.
    /// </summary>
    public X509ChainPolicy CreateChainPolicy()
    {
        var policy = new X509ChainPolicy
        {
            RevocationMode = X509RevocationMode.NoCheck,
            DisableCertificateDownloads = true,
        };
        if (_permit.TrustedRoot is { } root)
        {
            policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            policy.CustomTrustStore.Add(root);
        }

        return policy;
    }

    /// <summary>A TCP stream to a checked address of <paramref name="host"/>. The caller owns and disposes it.</summary>
    /// <exception cref="EgressRefusedException">The name has no address egress may reach.</exception>
    public async Task<Stream> OpenAsync(string host, int port, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);

        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(ConnectTimeout);
        return await EgressHttp.ConnectCheckedAsync(host, port, _permit, _resolve, _connect, limit.Token);
    }
}
