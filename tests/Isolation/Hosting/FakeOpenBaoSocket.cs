using System.Net.Sockets;
using System.Text;

namespace Gatekeep.Tests.Isolation.Hosting;

/// <summary>
/// A unix socket that answers every HTTP request with <see cref="Status"/>, standing in for
/// OpenBao's <c>sys/health</c>: 200 when active, 503 when sealed, 501 when not initialized.
/// Deleting the socket file stands in for OpenBao having gone.
/// </summary>
internal sealed class FakeOpenBaoSocket : IDisposable
{
    private readonly Socket _listener = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
    private readonly CancellationTokenSource _stop = new();

    private bool _disposed;

    public FakeOpenBaoSocket(int status = 200)
    {
        Status = status;
        // Short: a unix socket path is limited to about 100 characters.
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"gk-{Guid.NewGuid():N}"[..12] + ".sock");
        _listener.Bind(new UnixDomainSocketEndPoint(Path));
        _listener.Listen(16);
        _ = AcceptAsync();
    }

    public string Path { get; }

    /// <summary>The status every request gets. A test may change it while the socket runs.</summary>
    public int Status { get; set; }

    public void Dispose()
    {
        // A test may stop OpenBao early, and the class disposes it again at the end.
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _stop.Cancel();
        _listener.Dispose();
        _stop.Dispose();
        File.Delete(Path);
    }

    private async Task AcceptAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await _listener.AcceptAsync(_stop.Token);
            }
            catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            _ = AnswerAsync(client);
        }
    }

    private async Task AnswerAsync(Socket client)
    {
        using (client)
        {
            try
            {
                var buffer = new byte[4096];
                var request = new StringBuilder();
                while (!request.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
                {
                    var read = await client.ReceiveAsync(buffer);
                    if (read == 0)
                    {
                        return;
                    }

                    request.Append(Encoding.ASCII.GetString(buffer, 0, read));
                }

                await client.SendAsync(Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 {Status} Fake\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"));
            }
            catch (SocketException)
            {
            }
        }
    }
}
