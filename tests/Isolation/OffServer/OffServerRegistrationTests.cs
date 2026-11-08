using System.Reflection;
using System.Security.Cryptography;
using Gatekeep.Adapters.AlertChannel;
using Gatekeep.Adapters.Hosting;
using Gatekeep.Adapters.ObjectLock;
using Gatekeep.Kernel.Alerts;
using Gatekeep.Kernel.Records;
using Gatekeep.Tests.Isolation.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Gatekeep.Tests.Isolation.OffServer;

/// <summary>
/// Story 1.30: with valid settings, Host.Worker's own profile, read from its built assembly, gets the
/// alert channel, the off-server store and the record writer from the shared startup, each over
/// EgressHttp, and builds them without sending anything. A host whose profile doesn't use them,
/// as Host.Admin's and Host.Hosted's don't, gets none of them even when the settings are there.
/// </summary>
public sealed class OffServerRegistrationTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("gatekeep-registration-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Fact]
    public async Task Worker_profile_resolves_the_alert_channel_the_store_and_the_record_writer()
    {
        var profile = WorkerProfile();
        Assert.True(profile.UsesOffServer);

        await using var app = Build(profile);

        Assert.IsType<WebhookAlertChannel>(app.Services.GetRequiredService<IAlertChannel>());
        Assert.IsType<S3ObjectLockStore>(app.Services.GetRequiredService<IOffServerStore>());
        Assert.NotNull(app.Services.GetRequiredService<OffServerRecordWriter>());
        Assert.Equal("admin.gatekeep-admin.test", app.Services.GetRequiredService<AlertDeployment>().Name);
    }

    [Fact]
    public async Task Profile_that_doesnt_use_them_gets_no_alert_channel_or_store_even_with_the_settings_there()
    {
        await using var app = Build(new HostProfile("Host.Admin", ["Admin"], HasPublicEndpoint: false));

        Assert.Null(app.Services.GetService<IAlertChannel>());
        Assert.Null(app.Services.GetService<IOffServerStore>());
        Assert.Null(app.Services.GetService<OffServerRecordWriter>());
    }

    [Theory]
    [InlineData("Gatekeep.Host.Admin")]
    [InlineData("Gatekeep.Host.Hosted")]
    public void Admin_and_Hosted_profiles_never_ask_for_them(string project)
    {
        var program = File.ReadAllText(Path.Combine(BuildOutput.RepositoryRoot(), "src", project, "Program.cs"));

        Assert.Contains("new HostProfile(", program, StringComparison.Ordinal);
        Assert.DoesNotContain("UsesOffServer", program, StringComparison.Ordinal);
    }

    /// <summary>Host.Worker's <c>WorkerSettings.Profile</c>, from the assembly the Worker runs as.</summary>
    private static HostProfile WorkerProfile()
    {
        var worker = Assembly.LoadFrom(BuildOutput.AssemblyPath("Gatekeep.Host.Worker", "Gatekeep.Host.Worker"));
        var settings = worker.GetType("Gatekeep.Host.Worker.WorkerSettings", throwOnError: true)!;
        return (HostProfile)settings.GetField("Profile", BindingFlags.Public | BindingFlags.Static)!.GetValue(null)!;
    }

    /// <summary>The shared startup for <paramref name="profile"/>, with every setting valid and nothing reachable.</summary>
    private WebApplication Build(HostProfile profile)
    {
        string Secret(string contents)
        {
            var path = Path.Combine(_directory, Guid.NewGuid().ToString("N"));
            File.WriteAllText(path, contents);
            return path;
        }

        var settings = new Dictionary<string, string?>
        {
            [HostSettingNames.SecretsDirectory] = Directory.CreateDirectory(Path.Combine(_directory, "secrets")).FullName,
            [HostSettingNames.CustodySocketPath] = Path.Combine(_directory, "openbao.sock"),
            [HostSettingNames.CustodyRoleIdFile] = Secret(Guid.NewGuid().ToString()),
            [HostSettingNames.CustodySecretIdFile] = Secret(Guid.NewGuid().ToString()),
        };
        foreach (var database in profile.Databases)
        {
            settings[HostSettingNames.ConnectionString(database)] =
                $"Host=localhost;Username=gk_{database.ToLowerInvariant()};Password={Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16))}";
        }

        foreach (var (name, value) in HostProcess.OffServerDefaults.Value)
        {
            settings[name] = value;
        }

        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(settings);
        builder.AddGatekeepHost(profile);
        return builder.Build();
    }
}
