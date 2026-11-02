using Gatekeep.Adapters.OpenBao;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
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

        if (settings.Custody is { } custody)
        {
            builder.Services.AddOpenBaoKeyCustody(custody);
        }

        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.AddServerHeader = false;
            kestrel.ListenAnyIP(settings.HealthPort);
            if (profile.HasPublicEndpoint)
            {
                kestrel.ListenAnyIP(settings.PublicPort);
            }
        });

        return builder;
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
