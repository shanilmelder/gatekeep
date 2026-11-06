using System.Net;
using System.Net.Sockets;

namespace Gatekeep.Adapters.Egress;

/// <summary>Why <see cref="EgressHttp"/> refused a request.</summary>
public enum EgressRefusal
{
    /// <summary>The name has no address outbound HTTP may reach: every one is private, loopback, link-local or reserved.</summary>
    PrivateAddress,

    /// <summary>The request isn't HTTPS.</summary>
    PlainHttp,
}

/// <summary>
/// <see cref="EgressHttp"/> refused to connect. It names the host and the reason, never the
/// addresses the name resolved to.
/// </summary>
public sealed class EgressRefusedException : Exception
{
    public EgressRefusedException(string host, EgressRefusal reason)
        : base(reason == EgressRefusal.PlainHttp
            ? $"Outbound HTTP to {host} is refused: only HTTPS leaves the Deployment."
            : $"Outbound HTTP to {host} is refused: it has no public address.")
    {
        Host = host;
        Reason = reason;
    }

    public string Host { get; }

    public EgressRefusal Reason { get; }

    /// <summary>The refusal anywhere in <paramref name="exception"/>'s inner chain, as an HTTP client wraps it.</summary>
    public static EgressRefusedException? Find(Exception? exception)
    {
        for (var e = exception; e is not null; e = e.InnerException)
        {
            if (e is EgressRefusedException refused)
            {
                return refused;
            }
        }

        return null;
    }
}

/// <summary>
/// What the isolation tests may relax, in process only: every fixture they reach sits on a
/// private address and speaks plain HTTP. No setting, environment variable, Cli argument or
/// Compose value reaches this; <see cref="EgressHttp.Create()"/> always uses <see cref="None"/>.
/// </summary>
internal sealed record EgressPermit(bool PrivateAddresses, bool PlainHttp)
{
    public static readonly EgressPermit None = new(PrivateAddresses: false, PlainHttp: false);
}

/// <summary>
/// The one outbound HTTP path (AD-26, Story 1.30). Every outbound request in <c>src/</c> goes
/// through a handler made here, except OpenBao's unix socket and the loopback health probe.
/// Its connect step resolves the name itself and connects only to an address it has checked, so
/// DNS rebinding can't swap a private address in after the check. It has no proxy, follows no
/// redirect, keeps no cookie, refuses plain HTTP and gives up connecting after 10 seconds.
/// </summary>
public static class EgressHttp
{
    public static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);

    /// <summary>A new handler with every refusal in force. The caller owns and disposes it.</summary>
    public static SocketsHttpHandler Create() => Create(EgressPermit.None);

    /// <summary>
    /// The test seam: a handler that may relax what <paramref name="permit"/> names, and may stand
    /// in for the name lookup (<paramref name="resolve"/>) and the TCP connect (<paramref name="connect"/>),
    /// so a test can show which checked addresses are dialled, in which order.
    /// </summary>
    internal static SocketsHttpHandler Create(
        EgressPermit permit,
        Func<string, CancellationToken, Task<IPAddress[]>>? resolve = null,
        Func<IPEndPoint, CancellationToken, ValueTask<Stream>>? connect = null)
    {
        ArgumentNullException.ThrowIfNull(permit);

        return new SocketsHttpHandler
        {
            UseProxy = false,
            Proxy = null,
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = ConnectTimeout,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            ConnectCallback = (context, cancellationToken) =>
                ConnectAsync(context, permit, resolve ?? Dns.GetHostAddressesAsync, connect ?? ConnectSocketAsync, cancellationToken),
        };
    }

    private static async ValueTask<Stream> ConnectAsync(
        SocketsHttpConnectionContext context,
        EgressPermit permit,
        Func<string, CancellationToken, Task<IPAddress[]>> resolve,
        Func<IPEndPoint, CancellationToken, ValueTask<Stream>> connect,
        CancellationToken cancellationToken)
    {
        var host = context.DnsEndPoint.Host;
        var scheme = context.InitialRequestMessage.RequestUri?.Scheme;
        if (scheme != Uri.UriSchemeHttps && !permit.PlainHttp)
        {
            throw new EgressRefusedException(host, EgressRefusal.PlainHttp);
        }

        var literal = host.StartsWith('[') && host.EndsWith(']') ? host[1..^1] : host;
        IPAddress[] candidates = IPAddress.TryParse(literal, out var address)
            ? [address]
            : await resolve(host, cancellationToken);

        // IPv4 first: a host with no IPv6 route would otherwise spend the whole connect timeout
        // on an IPv6 address before trying one that works.
        var allowed = candidates
            .Where(a => permit.PrivateAddresses || !EgressAddresses.IsRefused(a))
            .OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
            .ToList();
        if (allowed.Count == 0)
        {
            throw new EgressRefusedException(host, EgressRefusal.PrivateAddress);
        }

        // Only the addresses checked above are ever connected to: no second lookup happens.
        SocketException? last = null;
        foreach (var target in allowed)
        {
            try
            {
                return await connect(new IPEndPoint(target, context.DnsEndPoint.Port), cancellationToken);
            }
            catch (SocketException e)
            {
                last = e;
            }
        }

        throw last!;
    }

    private static async ValueTask<Stream> ConnectSocketAsync(IPEndPoint target, CancellationToken cancellationToken)
    {
        var socket = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(target, cancellationToken);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
