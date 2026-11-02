using System.Net;

namespace Gatekeep.Adapters.OpenBao;

/// <summary>
/// Whether OpenBao answers on its socket, initialized, unsealed and active, for a host's
/// <c>/healthz</c>. It asks <c>sys/health</c>, which needs no token, so it never logs in.
/// </summary>
public sealed class OpenBaoHealth : IDisposable
{
    private const string SocketBaseAddress = "http://openbao/";

    private readonly HttpClient _http;

    public OpenBaoHealth(OpenBaoOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _http = new HttpClient(OpenBaoKeyCustody.CreateHandler(options), disposeHandler: true)
        {
            // With the trailing slash OpenBaoKeyCustody adds, so a path prefix in the address is kept.
            BaseAddress = options.SocketPath is null ? WithTrailingSlash(options.Address!) : new Uri(SocketBaseAddress),
            Timeout = TimeSpan.FromSeconds(3),
        };
    }

    /// <summary>True only for 200: a sealed, standby or uninitialized OpenBao can't serve a host.</summary>
    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var response = await _http.GetAsync("v1/sys/health", cancellationToken);
            return response.StatusCode == HttpStatusCode.OK;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return false;
        }
    }

    public void Dispose() => _http.Dispose();

    private static Uri WithTrailingSlash(Uri address) =>
        address.AbsoluteUri.EndsWith('/') ? address : new Uri(address.AbsoluteUri + "/");
}
