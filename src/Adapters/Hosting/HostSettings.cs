using Gatekeep.Adapters.OpenBao;
using Gatekeep.Kernel.Secrets;
using Microsoft.Extensions.Configuration;
using Npgsql;

namespace Gatekeep.Adapters.Hosting;

/// <summary>What a host needs: its name, its database connections and whether it has a public port.</summary>
/// <param name="Name">The host's name in logs, such as <c>Host.Worker</c>.</param>
/// <param name="Databases">Each connection, by its name under <c>ConnectionStrings</c>.</param>
/// <param name="HasPublicEndpoint">Whether the host listens on a public port besides health.</param>
public sealed record HostProfile(string Name, IReadOnlyList<string> Databases, bool HasPublicEndpoint);

/// <summary>
/// The names of every setting a host reads. A refusal names these, never a value. None of
/// them is a sensitive word followed by <c>:</c> or <c>=</c>, which the log scrubber would mask.
/// </summary>
public static class HostSettingNames
{
    /// <summary>Where Compose mounts secrets. Only <c>Database__{name}__Password</c> files are read from it.</summary>
    public const string SecretsDirectory = "Gatekeep:SecretsDirectory";

    public const string DefaultSecretsDirectory = "/run/secrets";

    public const string HealthPort = "Gatekeep:HealthPort";

    public const string PublicPort = "Gatekeep:PublicPort";

    public const int DefaultHealthPort = 8081;

    public const int DefaultPublicPort = 8080;

    public const string CustodySocketPath = "Custody:SocketPath";

    public const string CustodyRoleIdFile = "Custody:RoleIdFile";

    public const string CustodySecretIdFile = "Custody:SecretIdFile";

    /// <summary>The connection string, which may leave out its password.</summary>
    public static string ConnectionString(string database) => $"ConnectionStrings:{database}";

    /// <summary>The password, from a secret file. It replaces any password in the connection string.</summary>
    public static string Password(string database) => $"Database:{database}:Password";
}

/// <summary>The connection strings a host resolved at startup, each with its password.</summary>
public sealed class HostDatabases(IReadOnlyDictionary<string, string> connectionStrings)
{
    public string this[string database] => connectionStrings[database];
}

/// <summary>Settings after resolution, and the name of every setting refused.</summary>
internal sealed record ResolvedSettings(
    HostProfile Profile,
    IReadOnlyDictionary<string, string> Databases,
    OpenBaoOptions? Custody,
    int HealthPort,
    int PublicPort,
    IReadOnlyList<string> Refused);

internal static class HostSettings
{
    public static ResolvedSettings Resolve(IConfiguration configuration, HostProfile profile)
    {
        var refused = new List<string>();
        var databases = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var database in profile.Databases)
        {
            if (ResolveDatabase(configuration, database, refused) is { } connectionString)
            {
                databases[database] = connectionString;
            }
        }

        var custody = ResolveCustody(configuration, refused);

        var healthPort = Port(configuration, HostSettingNames.HealthPort, HostSettingNames.DefaultHealthPort, refused);
        var publicPort = profile.HasPublicEndpoint
            ? Port(configuration, HostSettingNames.PublicPort, HostSettingNames.DefaultPublicPort, refused)
            : 0;

        if (profile.HasPublicEndpoint && healthPort == publicPort)
        {
            // Health must never share the public port.
            refused.Add(HostSettingNames.HealthPort);
        }

        return new ResolvedSettings(profile, databases, custody, healthPort, publicPort, refused);
    }

    private static string? ResolveDatabase(IConfiguration configuration, string database, List<string> refused)
    {
        var connectionName = HostSettingNames.ConnectionString(database);
        var passwordName = HostSettingNames.Password(database);
        var connectionString = configuration[connectionName];

        if (string.IsNullOrWhiteSpace(connectionString))
        {
            refused.Add(connectionName);
            return null;
        }

        NpgsqlConnectionStringBuilder builder;
        try
        {
            builder = new NpgsqlConnectionStringBuilder(connectionString);
        }
        catch (Exception e) when (e is ArgumentException or FormatException or InvalidCastException)
        {
            // The message can quote the connection string, so it's dropped.
            refused.Add(connectionName);
            return null;
        }

        if (configuration[passwordName] is { } password)
        {
            password = password.TrimEnd('\r', '\n');
            if (SecretDefaults.IsUnsafePassword(password))
            {
                refused.Add(passwordName);
                return null;
            }

            builder.Password = password;
        }
        else if (string.IsNullOrEmpty(builder.Password))
        {
            // No password file, and none in the connection string: the file is what's missing.
            refused.Add(passwordName);
            return null;
        }
        else if (SecretDefaults.IsUnsafePassword(builder.Password))
        {
            refused.Add(connectionName);
            return null;
        }

        return builder.ConnectionString;
    }

    private static OpenBaoOptions? ResolveCustody(IConfiguration configuration, List<string> refused)
    {
        var socket = configuration[HostSettingNames.CustodySocketPath];
        var roleIdFile = configuration[HostSettingNames.CustodyRoleIdFile];
        var secretIdFile = configuration[HostSettingNames.CustodySecretIdFile];

        // Every host uses custody (AD-10), so each setting is required.
        var before = refused.Count;
        if (string.IsNullOrWhiteSpace(socket))
        {
            refused.Add(HostSettingNames.CustodySocketPath);
        }

        CheckSecretFile(roleIdFile, HostSettingNames.CustodyRoleIdFile, refused);
        CheckSecretFile(secretIdFile, HostSettingNames.CustodySecretIdFile, refused);

        return refused.Count > before
            ? null
            : new OpenBaoOptions { SocketPath = socket, RoleIdFile = roleIdFile!, SecretIdFile = secretIdFile! };
    }

    /// <summary>The file must be readable and hold a value that isn't a default. Its contents aren't kept.</summary>
    private static void CheckSecretFile(string? path, string name, List<string> refused)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            refused.Add(name);
            return;
        }

        try
        {
            if (SecretDefaults.IsUnsafe(File.ReadAllText(path)))
            {
                refused.Add(name);
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            refused.Add(name);
        }
    }

    private static int Port(IConfiguration configuration, string name, int defaultPort, List<string> refused)
    {
        var text = configuration[name];
        if (text is null)
        {
            return defaultPort;
        }

        if (int.TryParse(text, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var port)
            && port is > 0 and <= 65535)
        {
            return port;
        }

        refused.Add(name);
        return defaultPort;
    }
}
