using System.Globalization;
using System.Net;
using Microsoft.Extensions.Configuration;

namespace Gatekeep.Adapters.Hosting;

/// <summary>
/// The container healthcheck. The images have no shell or HTTP client, so the host binary
/// runs as its own probe: <c>dotnet Host.dll --health-probe</c> asks this container's
/// <c>/healthz</c> on loopback and exits 0 only for 200. It writes nothing.
/// </summary>
public static class HealthProbe
{
    public const string Argument = "--health-probe";

    public static bool IsRequested(string[] args) => args is [Argument, ..];

    public static async Task<int> RunAsync(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        // The sources WebApplication reads for the port, in its order, so the probe asks the
        // port the host listens on: JSON settings from the content root, then the environment.
        var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT")
            ?? Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT")
            ?? "Production";
        var configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: true)
            .AddJsonFile($"appsettings.{environment}.json", optional: true)
            .AddEnvironmentVariables()
            .AddCommandLine(args[1..])
            .Build();

        var port = int.TryParse(
            configuration[HostSettingNames.HealthPort],
            NumberStyles.None,
            CultureInfo.InvariantCulture,
            out var configured)
            ? configured
            : HostSettingNames.DefaultHealthPort;

        using var http = new HttpClient(new SocketsHttpHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(5) };
        try
        {
            using var response = await http.GetAsync(new Uri($"http://127.0.0.1:{port}{HealthEndpoint.Path}"));
            return response.StatusCode == HttpStatusCode.OK ? 0 : 1;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            return 1;
        }
    }
}
