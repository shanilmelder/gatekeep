using Gatekeep.Adapters.AlertChannel;
using Gatekeep.Adapters.Egress;
using Gatekeep.Adapters.ObjectLock;
using Gatekeep.Adapters.OpenBao;
using Gatekeep.Kernel.Alerts;
using Gatekeep.Kernel.Records;
using Gatekeep.Kernel.Secrets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;

namespace Gatekeep.Adapters.Hosting;

/// <summary>The startup every host shares (AD-26).</summary>
public static class GatekeepHosting
{
    private const string PasswordFilePrefix = "Database__";
    private const string PasswordFileSuffix = "__Password";

    /// <summary>
    /// Reads password files from the secrets directory, resolves and checks every setting
    /// <paramref name="profile"/> needs, wires key custody when it's configured, and listens
    /// on the private health port, plus the public port if the host has one. Nothing is
    /// refused here: <see cref="RunGatekeepAsync"/> does that once logging exists.
    /// </summary>
    public static WebApplicationBuilder AddGatekeepHost(this WebApplicationBuilder builder, HostProfile profile)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(profile);

        var secrets = builder.Configuration[HostSettingNames.SecretsDirectory] ?? HostSettingNames.DefaultSecretsDirectory;
        if (Directory.Exists(secrets))
        {
            builder.Configuration.AddKeyPerFile(source =>
            {
                source.FileProvider = new PhysicalFileProvider(Path.GetFullPath(secrets));
                source.Optional = true;
                source.ReloadOnChange = false;
                // Only password files become settings. Other secrets, such as the AppRole
                // files, are read by path and never enter configuration.
                source.IgnoreCondition = name =>
                    !(name.StartsWith(PasswordFilePrefix, StringComparison.Ordinal)
                        && name.EndsWith(PasswordFileSuffix, StringComparison.Ordinal));
            });
        }

        var settings = HostSettings.Resolve(builder.Configuration, profile);

        builder.Services.AddSingleton(settings);
        builder.Services.AddSingleton(new HostDatabases(settings.Databases));
        builder.Services.AddSingleton<HealthEndpoint>();
        builder.Services.AddSingleton<IStartupFilter, HealthStartupFilter>();
        if (settings.Origin is { } origin)
        {
            builder.Services.AddSingleton(origin);
        }

        if (settings.Custody is { } custody)
        {
            builder.Services.AddOpenBaoKeyCustody(custody);
        }

        if (settings.OffServer is { } offServer)
        {
            AddOffServer(builder.Services, offServer);
        }

        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.AddServerHeader = false;
            // Health only on loopback: the container's own healthcheck asks it there, and no
            // other container, Caddy included, can reach it (Story 1.11).
            kestrel.Listen(System.Net.IPAddress.Loopback, settings.HealthPort);
            if (profile.HasPublicEndpoint)
            {
                kestrel.ListenAnyIP(settings.PublicPort);
            }
        });

        return builder;
    }

    /// <summary>
    /// The alert channel and the off-server store, each over its own <see cref="EgressHttp"/> handler,
    /// the only outbound path, plus the record writer that signs with <c>dep-records</c> (Story 1.30).
    /// Each is built when first asked for, and nothing is sent at startup.
    /// </summary>
    private static void AddOffServer(IServiceCollection services, OffServerSettings offServer)
    {
        services.AddSingleton(offServer.Deployment);
        services.AddSingleton<IAlertChannel>(_ => new WebhookAlertChannel(EgressHttp.Create(), offServer.Alerts));
        services.AddSingleton<IOffServerStore>(provider =>
            new S3ObjectLockStore(EgressHttp.Create(), offServer.Records, provider.GetService<TimeProvider>() ?? TimeProvider.System));
        services.AddSingleton(provider => new OffServerRecordWriter(
            provider.GetRequiredService<IKeyCustody>(),
            provider.GetRequiredService<IOffServerStore>(),
            provider.GetService<TimeProvider>() ?? TimeProvider.System));
    }

    /// <summary>
    /// Makes the connection's remote address the client Caddy forwarded, when the peer is in
    /// <see cref="HostSettingNames.ForwardedBy"/>: one <c>X-Forwarded-For</c> hop, from that network
    /// only. Caddy replaces any <c>X-Forwarded-For</c> a client sends, so the value is the address
    /// it saw. With <see cref="HostSettingNames.NoProxy"/> nothing is believed, and the client is the peer.
    /// </summary>
    public static IApplicationBuilder UseGatekeepForwardedClient(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        var settings = app.ApplicationServices.GetRequiredService<ResolvedSettings>();
        if (settings.ForwardedBy is not { } network)
        {
            return app;
        }

        var options = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor,
            ForwardLimit = 1,
        };

        // Empty lists would believe any peer, so the one network replaces the loopback defaults.
        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();
        options.KnownIPNetworks.Add(network);
        return app.UseForwardedHeaders(options);
    }

    /// <summary>
    /// Runs the host, or refuses: with any setting missing, empty or a known default it logs
    /// the settings' names only and returns 1.
    /// </summary>
    public static async Task<int> RunGatekeepAsync(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);

        var settings = app.Services.GetRequiredService<ResolvedSettings>();
        if (settings.Refused.Count > 0)
        {
            app.Services.GetRequiredService<ILoggerFactory>()
                .CreateLogger("Gatekeep.Host")
                .LogCritical(
                    "{Host} refuses to start. Missing or unsafe settings: {Settings}.",
                    settings.Profile.Name,
                    string.Join(", ", settings.Refused.Distinct()));

            // Disposing the host flushes the log.
            await app.DisposeAsync();
            return 1;
        }

        await app.RunAsync();
        return 0;
    }
}
