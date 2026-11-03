using System.Net.Sockets;

namespace Gatekeep.Tests.Isolation.Bootstrap;

/// <summary>
/// A unix socket that forwards every connection to the test OpenBao's HTTP listener, so the real
/// Cli reaches the real OpenBao the way the <c>cli</c> service does, on a socket. Testcontainers
/// can't share the container's own socket with this process, so this stands in for the
/// <c>openbao-socket</c> volume.
/// </summary>
internal sealed class OpenBaoSocketProxy : IDisposable
{
    private readonly Socket _listener = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
    private readonly CancellationTokenSource _stop = new();
    private readonly Uri _target;

    public OpenBaoSocketProxy(Uri target)
    {
        _target = target;
        // Short: a unix socket path is limited to about 100 characters.
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"gk-{Guid.NewGuid():N}"[..12] + ".sock");
        _listener.Bind(new UnixDomainSocketEndPoint(Path));
        if (!OperatingSystem.IsWindows())
        {
            // A Cli run as the cli uid connects too, as the custody group does in Compose.
            File.SetUnixFileMode(Path, (UnixFileMode)0x1FF);
        }

        _listener.Listen(16);
        _ = AcceptAsync();
    }

    public string Path { get; }

    public void Dispose()
    {
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

            _ = ForwardAsync(client);
        }
    }

    private async Task ForwardAsync(Socket client)
    {
        try
        {
            using var upstream = new TcpClient();
            await upstream.ConnectAsync(_target.Host, _target.Port);
            await using var downstream = new NetworkStream(client, ownsSocket: true);
            await using var up = upstream.GetStream();

            await Task.WhenAny(downstream.CopyToAsync(up), up.CopyToAsync(downstream));
        }
        catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException)
        {
            // The Cli or OpenBao closed its side: nothing more to forward.
        }
        finally
        {
            client.Dispose();
        }
    }
}
