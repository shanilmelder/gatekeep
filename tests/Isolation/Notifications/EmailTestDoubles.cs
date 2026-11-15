using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Gatekeep.Adapters.Egress;
using Gatekeep.Adapters.Email;
using Gatekeep.Kernel.Email;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Gatekeep.Tests.Isolation.Notifications;

/// <summary>One send the recording sender was handed: the transport's kind and secret, and the message.</summary>
internal sealed record RecordedSend(string Kind, string? Secret, EmailMessage Message);

/// <summary>A stand-in for the email adapters: records each send and answers <see cref="Result"/>.</summary>
internal sealed class RecordingEmailSender : IEmailSender
{
    private readonly Lock _lock = new();
    private readonly List<RecordedSend> _sends = [];

    public EmailSendResult Result { get; set; } = EmailSendResult.Sent;

    public IReadOnlyList<RecordedSend> Sends
    {
        get
        {
            lock (_lock)
            {
                return [.. _sends];
            }
        }
    }

    public Task<EmailSendResult> SendAsync(EmailTransport transport, EmailMessage message, CancellationToken cancellationToken)
    {
        lock (_lock)
        {
            _sends.Add(new RecordedSend(transport.Kind, transport.Secret?.Use(static s => s), message));
        }

        return Task.FromResult(Result);
    }
}

/// <summary>
/// A test root and a server certificate it issued for every provider host the adapters name, so the adapters' TLS runs
/// with validation on: only <see cref="EgressPermit.TrustedRoot"/> makes the root trusted, in process.
/// </summary>
internal static class TestCertificates
{
    public const string SmtpHost = "smtp.mail.test";

    public static readonly string[] Hosts =
    [
        "api.sendgrid.com",
        "api.eu.sendgrid.com",
        "api.postmarkapp.com",
        "api.mailgun.net",
        "api.eu.mailgun.net",
        "email.eu-west-1.amazonaws.com",
        "hooks.mail.test",
        SmtpHost,
    ];

    private static readonly Lazy<(X509Certificate2 Root, X509Certificate2 Server)> Pair = new(Create);

    private static readonly Lazy<X509Certificate2> SelfSigned = new(CreateUntrusted);

    /// <summary>A certificate for the same hosts that no trusted root issued: every TLS session to it must be refused.</summary>
    public static X509Certificate2 Untrusted => SelfSigned.Value;

    private static X509Certificate2 CreateUntrusted()
    {
        var now = DateTimeOffset.UtcNow;
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=mail.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        var names = new SubjectAlternativeNameBuilder();
        foreach (var host in Hosts)
        {
            names.AddDnsName(host);
        }

        request.CertificateExtensions.Add(names.Build());
        using var certificate = request.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null);
    }

    public static X509Certificate2 Root => Pair.Value.Root;

    /// <summary>The server certificate, with its private key.</summary>
    public static X509Certificate2 Server => Pair.Value.Server;

    private static (X509Certificate2, X509Certificate2) Create()
    {
        var now = DateTimeOffset.UtcNow;
        using var rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest("CN=Gatekeep Email Test Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
        using var root = rootRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(2));

        using var serverKey = RSA.Create(2048);
        var serverRequest = new CertificateRequest("CN=mail.test", serverKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        serverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        serverRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root, true, false));
        var names = new SubjectAlternativeNameBuilder();
        foreach (var host in Hosts)
        {
            names.AddDnsName(host);
        }

        serverRequest.CertificateExtensions.Add(names.Build());
        using var issued = serverRequest.Create(root, now.AddDays(-1), now.AddDays(1), RandomNumberGenerator.GetBytes(12));
        using var withKey = issued.CopyWithPrivateKey(serverKey);

        return (
            X509CertificateLoader.LoadCertificate(root.RawData),
            X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pfx), null));
    }
}

/// <summary>
/// The real adapters, reaching loopback fixtures only through the egress seams: every provider name resolves to
/// <see cref="ResolvedAddress"/>, a public address the checks allow, unless <see cref="Resolve"/> says otherwise, and
/// the connect the checks hand that address to dials the fixture's loopback port instead. No private-address or
/// plain-HTTP permit is given: only the test root is trusted.
/// </summary>
internal sealed class LoopbackEgress
{
    public static readonly IPAddress ResolvedAddress = IPAddress.Parse("8.8.4.4");

    private readonly Lock _lock = new();
    private readonly List<IPEndPoint> _dialled = [];

    /// <summary>Where a dial to any checked address lands: the HTTPS sink or the SMTP fake.</summary>
    public int HttpsPort { get; set; }

    public int SmtpPort { get; set; }

    /// <summary>What every name resolves to.</summary>
    public IPAddress[] Resolve { get; set; } = [ResolvedAddress];

    /// <summary>Every checked address the egress path handed to connect.</summary>
    public IReadOnlyList<IPEndPoint> Dialled
    {
        get
        {
            lock (_lock)
            {
                return [.. _dialled];
            }
        }
    }

    public EmailSender Sender(TimeProvider? time = null)
    {
        var permit = new EgressPermit(PrivateAddresses: false, PlainHttp: false, TrustedRoot: TestCertificates.Root);
        return new EmailSender(
            EgressHttp.Create(permit, ResolveAsync, (endpoint, ct) => DialAsync(endpoint, HttpsPort, ct)),
            EgressSmtp.Create(permit, ResolveAsync, (endpoint, ct) => DialAsync(endpoint, SmtpPort, ct)),
            time ?? TimeProvider.System);
    }

    private Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(Resolve);

    private async ValueTask<Stream> DialAsync(IPEndPoint endpoint, int port, CancellationToken cancellationToken)
    {
        lock (_lock)
        {
            _dialled.Add(endpoint);
        }

        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port), cancellationToken);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}

/// <summary>One request the HTTPS sink received.</summary>
internal sealed record ProviderRequest(string Method, string Host, string PathAndQuery, IReadOnlyDictionary<string, string> Headers, byte[] Body)
{
    public string Text => Encoding.UTF8.GetString(Body);
}

/// <summary>Every HTTPS provider at once: a loopback Kestrel listener presenting the test server certificate.</summary>
internal sealed class ProviderSink : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly List<ProviderRequest> _requests = [];
    private readonly Lock _lock = new();

    private ProviderSink(WebApplication app) => _app = app;

    public int Status { get; set; } = 202;

    public int Port { get; private set; }

    public IReadOnlyList<ProviderRequest> Requests
    {
        get
        {
            lock (_lock)
            {
                return [.. _requests];
            }
        }
    }

    public static async Task<ProviderSink> StartAsync(X509Certificate2? certificate = null)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseKestrel(k => k.Listen(IPAddress.Loopback, 0, o => o.UseHttps(certificate ?? TestCertificates.Server)));

        ProviderSink? sink = null;
        var app = builder.Build();
        app.Run(async context =>
        {
            using var body = new MemoryStream();
            await context.Request.Body.CopyToAsync(body, context.RequestAborted);
            var headers = context.Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString(), StringComparer.OrdinalIgnoreCase);
            lock (sink!._lock)
            {
                sink._requests.Add(new ProviderRequest(
                    context.Request.Method,
                    context.Request.Host.Value ?? string.Empty,
                    context.Request.Path + context.Request.QueryString,
                    headers,
                    body.ToArray()));
            }

            context.Response.StatusCode = sink.Status;
            await context.Response.WriteAsync("{\"message\":\"ok\"}", context.RequestAborted);
        });

        sink = new ProviderSink(app);
        await app.StartAsync();
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        sink.Port = new Uri(address).Port;
        return sink;
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}

/// <summary>What the SMTP fake was handed in one session.</summary>
internal sealed record SmtpSession(
    IReadOnlyList<string> Commands,
    bool Tls,
    string? AuthUser,
    string? AuthPassword,
    string? MailFrom,
    IReadOnlyList<string> Recipients,
    string? Data);

/// <summary>
/// A loopback SMTP server presenting the test server certificate: STARTTLS on a plain connection (unless
/// <see cref="OfferStartTls"/> is off), or TLS from the first byte when <see cref="Implicit"/>. AUTH PLAIN is offered only
/// over TLS. It records every command and the one message of each session.
/// </summary>
internal sealed class FakeSmtpServer : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly List<SmtpSession> _sessions = [];
    private readonly Lock _lock = new();
    private Task? _loop;

    public bool Implicit { get; init; }

    public bool OfferStartTls { get; init; } = true;

    /// <summary>The certificate it presents: the test root's server certificate unless a test names another.</summary>
    public X509Certificate2 Certificate { get; init; } = TestCertificates.Server;

    /// <summary>Answers AUTH with <c>535</c>, as a server refusing the credential does.</summary>
    public bool RejectAuth { get; init; }

    /// <summary>Closes the connection on <c>QUIT</c> without answering, as a server may once the message is queued.</summary>
    public bool DropOnQuit { get; init; }

    /// <summary>The reply to <c>RCPT TO</c>.</summary>
    public string RecipientReply { get; set; } = "250 2.1.5 OK";

    public int Port { get; private set; }

    public IReadOnlyList<SmtpSession> Sessions
    {
        get
        {
            lock (_lock)
            {
                return [.. _sessions];
            }
        }
    }

    public FakeSmtpServer Start()
    {
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _loop = AcceptAsync(_stop.Token);
        return this;
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        _listener.Stop();
        if (_loop is not null)
        {
            try
            {
                await _loop;
            }
            catch (Exception)
            {
                // Stopping.
            }
        }

        _stop.Dispose();
    }

    private async Task AcceptAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var client = await _listener.AcceptTcpClientAsync(cancellationToken);
            _ = Task.Run(async () =>
            {
                using (client)
                {
                    try
                    {
                        await SessionAsync(client.GetStream(), cancellationToken);
                    }
                    catch (Exception) when (!cancellationToken.IsCancellationRequested)
                    {
                        // A client that leaves mid-session.
                    }
                }
            }, cancellationToken);
        }
    }

    private async Task SessionAsync(Stream network, CancellationToken cancellationToken)
    {
        var commands = new List<string>();
        var recipients = new List<string>();
        string? user = null, password = null, from = null, data = null;
        var tls = false;
        Stream stream = network;

        if (Implicit)
        {
            stream = await TlsAsync(network, cancellationToken);
            tls = true;
        }

        var (reader, writer) = Open(stream);
        await writer.WriteAsync("220 smtp.mail.test ESMTP fake\r\n");

        try
        {
            while (await reader.ReadLineAsync(cancellationToken) is { } line)
            {
                commands.Add(line.StartsWith("AUTH", StringComparison.OrdinalIgnoreCase) ? "AUTH" : line);
                var verb = line.Split(' ', 2)[0].ToUpperInvariant();
                switch (verb)
                {
                    case "EHLO":
                        var lines = new List<string> { "smtp.mail.test" };
                        if (!tls && OfferStartTls)
                        {
                            lines.Add("STARTTLS");
                        }

                        if (tls)
                        {
                            lines.Add("AUTH PLAIN");
                        }

                        for (var i = 0; i < lines.Count; i++)
                        {
                            await writer.WriteAsync($"250{(i == lines.Count - 1 ? ' ' : '-')}{lines[i]}\r\n");
                        }

                        break;
                    case "STARTTLS" when !tls && OfferStartTls:
                        await writer.WriteAsync("220 2.0.0 Ready to start TLS\r\n");
                        stream = await TlsAsync(network, cancellationToken);
                        tls = true;
                        (reader, writer) = Open(stream);
                        break;
                    case "AUTH" when tls:
                        var parts = line.Split(' ');
                        var response = parts.Length > 2 ? parts[2] : null;
                        if (response is null)
                        {
                            await writer.WriteAsync("334 \r\n");
                            response = await reader.ReadLineAsync(cancellationToken);
                        }

                        if (RejectAuth)
                        {
                            await writer.WriteAsync("535 5.7.8 Authentication credentials invalid\r\n");
                            break;
                        }

                        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(response!)).Split('\0');
                        (user, password) = (decoded[1], decoded[2]);
                        await writer.WriteAsync("235 2.7.0 Authentication successful\r\n");
                        break;
                    case "MAIL":
                        from = Address(line);
                        await writer.WriteAsync("250 2.1.0 OK\r\n");
                        break;
                    case "RCPT":
                        recipients.Add(Address(line));
                        await writer.WriteAsync(RecipientReply + "\r\n");
                        break;
                    case "DATA":
                        await writer.WriteAsync("354 End data with <CR><LF>.<CR><LF>\r\n");
                        var body = new StringBuilder();
                        while (await reader.ReadLineAsync(cancellationToken) is { } dataLine && dataLine != ".")
                        {
                            body.Append(dataLine).Append("\r\n");
                        }

                        data = body.ToString();
                        await writer.WriteAsync("250 2.0.0 Queued\r\n");
                        break;
                    case "QUIT" when DropOnQuit:
                        return;
                    case "QUIT":
                        await writer.WriteAsync("221 2.0.0 Bye\r\n");
                        return;
                    case "RSET" or "NOOP":
                        await writer.WriteAsync("250 2.0.0 OK\r\n");
                        break;
                    default:
                        await writer.WriteAsync("502 5.5.2 Not offered\r\n");
                        break;
                }
            }
        }
        finally
        {
            lock (_lock)
            {
                _sessions.Add(new SmtpSession(commands, tls, user, password, from, recipients, data));
            }
        }
    }

    private static string Address(string line)
    {
        var start = line.IndexOf('<', StringComparison.Ordinal);
        var end = line.IndexOf('>', StringComparison.Ordinal);
        return start >= 0 && end > start ? line[(start + 1)..end] : line;
    }

    private async Task<Stream> TlsAsync(Stream network, CancellationToken cancellationToken)
    {
        var ssl = new SslStream(network, leaveInnerStreamOpen: true);
        await ssl.AuthenticateAsServerAsync(
            new SslServerAuthenticationOptions { ServerCertificate = Certificate },
            cancellationToken);
        return ssl;
    }

    private static (StreamReader Reader, StreamWriter Writer) Open(Stream stream) =>
        (new StreamReader(stream, Encoding.ASCII, false, 1024, leaveOpen: true),
            new StreamWriter(stream, new UTF8Encoding(false), 1024, leaveOpen: true) { AutoFlush = true, NewLine = "\r\n" });
}
