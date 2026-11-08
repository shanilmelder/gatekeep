using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Gatekeep.Tests.Isolation.OffServer;

/// <summary>One request the sink received, with everything that left the process.</summary>
internal sealed record SinkRequest(string Method, string PathAndQuery, IReadOnlyDictionary<string, string> Headers, byte[] Body)
{
    /// <summary>The request as one text, for the canary scan: request line, every header and the body.</summary>
    public string Text =>
        $"{Method} {PathAndQuery}\n{string.Join('\n', Headers.Select(h => $"{h.Key}: {h.Value}"))}\n\n{System.Text.Encoding.UTF8.GetString(Body)}";
}

/// <summary>
/// Story 1.30: an alert service outside the Deployment, as an in-process Kestrel listener on
/// loopback inside the tests container. It records each request and answers with
/// <see cref="Status"/>, after <see cref="Delay"/>, with <see cref="Location"/> when set.
/// </summary>
internal sealed class AlertSinkFixture : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly List<SinkRequest> _requests = [];
    private readonly Lock _lock = new();

    private AlertSinkFixture(WebApplication app) => _app = app;

    public int Status { get; set; } = (int)HttpStatusCode.NoContent;

    public TimeSpan Delay { get; set; } = TimeSpan.Zero;

    public string? Location { get; set; }

    /// <summary>The hook's URL, plain HTTP on loopback: only EgressHttp's test permit reaches it.</summary>
    public Uri Url { get; private set; } = null!;

    public IReadOnlyList<SinkRequest> Requests
    {
        get
        {
            lock (_lock)
            {
                return [.. _requests];
            }
        }
    }

    public static async Task<AlertSinkFixture> StartAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseKestrel(k => k.Listen(IPAddress.Loopback, 0));

        AlertSinkFixture? sink = null;
        var app = builder.Build();
        app.Run(async context =>
        {
            using var body = new MemoryStream();
            await context.Request.Body.CopyToAsync(body, context.RequestAborted);
            var headers = context.Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString(), StringComparer.OrdinalIgnoreCase);
            lock (sink!._lock)
            {
                sink._requests.Add(new SinkRequest(
                    context.Request.Method,
                    context.Request.Path + context.Request.QueryString,
                    headers,
                    body.ToArray()));
            }

            if (sink.Delay > TimeSpan.Zero)
            {
                try
                {
                    await Task.Delay(sink.Delay, context.RequestAborted);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }

            context.Response.StatusCode = sink.Status;
            if (sink.Location is { } location)
            {
                context.Response.Headers.Location = location;
            }

            if (sink.Status >= 400)
            {
                // A body an error may echo: nothing of it may reach the Cli's output.
                await context.Response.WriteAsync($"sink error for {context.Request.Path}", context.RequestAborted);
            }
        });

        sink = new AlertSinkFixture(app);
        await app.StartAsync();
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        var port = new Uri(address).Port;
        sink.Url = new Uri($"http://127.0.0.1:{port}/hooks/gatekeep?channel=security");
        return sink;
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}
