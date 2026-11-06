using Gatekeep.Adapters.AlertChannel;
using Gatekeep.Adapters.ObjectLock;
using Gatekeep.Adapters.OpenBao;
using Gatekeep.Kernel.Alerts;
using Gatekeep.Kernel.Secrets;
using Microsoft.Extensions.Configuration;
using Npgsql;

namespace Gatekeep.Adapters.Hosting;

/// <summary>What a host needs: its name, its database connections and whether it has a public port.</summary>
/// <param name="Name">The host's name in logs, such as <c>Host.Worker</c>.</param>
/// <param name="Databases">Each connection, by its name under <c>ConnectionStrings</c>.</param>
/// <param name="HasPublicEndpoint">Whether the host listens on a public port besides health.</param>
/// <param name="HasPublicOrigin">
/// Whether the host needs its browser origin (<see cref="HostSettingNames.PublicOrigin"/>), as
/// Host.Admin does to check the <c>Origin</c> of every state-changing request.
/// </param>
/// <param name="HasForwardingProxy">
/// Whether the host must be told who forwards to it (<see cref="HostSettingNames.ForwardedBy"/>),
/// as Host.Admin must, since it counts attempts by client address.
/// </param>
/// <param name="RefusedHostSettings">
/// The host's own settings it refuses, by name, such as Host.Admin's lock timeout: checked at
/// startup with the rest, so a malformed one stops the host rather than failing each request.
/// </param>
/// <param name="UsesOffServer">
/// Whether the host needs the alert channel and the off-server bucket (Story 1.30), as Host.Worker
/// does: every <c>Alerts:*</c> and <c>Records:*</c> setting in <see cref="HostSettingNames"/> is then
/// required, and the host gets <c>IAlertChannel</c> and <c>IOffServerStore</c> over
/// <c>EgressHttp</c>. Only a host whose Compose service joins the <c>egress</c> network sets it.
/// </param>
public sealed record HostProfile(
    string Name,
    IReadOnlyList<string> Databases,
    bool HasPublicEndpoint,
    bool HasPublicOrigin = false,
    bool HasForwardingProxy = false,
    Func<IConfiguration, IEnumerable<string>>? RefusedHostSettings = null,
    bool UsesOffServer = false);

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

    /// <summary>
    /// The origin browsers reach the host at, such as <c>https://admin.example.com</c>: a scheme,
    /// a host and an optional port, with nothing after. Compose sets it from the Admin hostname.
    /// </summary>
    public const string PublicOrigin = "Gatekeep:PublicOrigin";

    /// <summary>
    /// The one network, in CIDR form, whose <c>X-Forwarded-For</c> the host believes, which is
    /// Caddy's edge subnet in Compose, or <see cref="NoProxy"/> to believe none, so the client is
    /// the connection's peer. Required where the profile has a forwarding proxy, optional elsewhere.
    /// </summary>
    public const string ForwardedBy = "Gatekeep:ForwardedBy";

    /// <summary>The <see cref="ForwardedBy"/> value that names no proxy.</summary>
    public const string NoProxy = "none";

    public const string CustodySocketPath = "Custody:SocketPath";

    public const string CustodyRoleIdFile = "Custody:RoleIdFile";

    public const string CustodySecretIdFile = "Custody:SecretIdFile";

    /// <summary>The alert channel's webhook: an absolute <c>https</c> URL with no user info (Story 1.30).</summary>
    public const string AlertUrl = "Alerts:Url";

    /// <summary>The file holding the webhook's bearer token, a Compose secret.</summary>
    public const string AlertTokenFile = "Alerts:TokenFile";

    /// <summary>The Admin hostname, which names the Deployment in every alert.</summary>
    public const string AlertDeployment = "Alerts:Deployment";

    /// <summary>The bucket's S3 API endpoint: an absolute <c>https</c> URL with nothing after the host and port.</summary>
    public const string RecordsEndpoint = "Records:Endpoint";

    public const string RecordsRegion = "Records:Region";

    public const string RecordsBucket = "Records:Bucket";

    /// <summary>The file holding the write-only credential's access key ID, a Compose secret.</summary>
    public const string RecordsAccessKeyIdFile = "Records:AccessKeyIdFile";

    /// <summary>The file holding the write-only credential's secret key, a Compose secret.</summary>
    public const string RecordsSecretAccessKeyFile = "Records:SecretAccessKeyFile";

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

/// <summary>
/// The host's browser origin, serialized as browsers send it in <c>Origin</c>: lower-case scheme
/// and host, and the port only when it isn't the scheme's default.
/// </summary>
public sealed class HostOrigin
{
    internal HostOrigin(string value) => Value = value;

    public string Value { get; }

    /// <summary>Whether <paramref name="origin"/>, an <c>Origin</c> header, is exactly this origin.</summary>
    public bool Matches(string? origin) => string.Equals(origin, Value, StringComparison.Ordinal);

    public override string ToString() => Value;

    /// <summary>The serialized origin of <paramref name="text"/>, or null when it isn't only an http or https origin.</summary>
    internal static string? Serialize(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)
            || !Uri.TryCreate(text.Trim(), UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)
            || uri.UserInfo.Length > 0
            || uri.AbsolutePath != "/"
            || uri.Query.Length > 0
            || uri.Fragment.Length > 0
            || uri.Host.Length == 0)
        {
            return null;
        }

        var host = uri.HostNameType == UriHostNameType.IPv6 ? uri.Host : uri.IdnHost;
        return uri.IsDefaultPort ? $"{uri.Scheme}://{host}" : $"{uri.Scheme}://{host}:{uri.Port}";
    }
}

/// <summary>The alert channel and the off-server bucket, resolved (Story 1.30).</summary>
internal sealed record OffServerSettings(WebhookAlertOptions Alerts, AlertDeployment Deployment, ObjectLockOptions Records);

/// <summary>Settings after resolution, and the name of every setting refused.</summary>
internal sealed record ResolvedSettings(
    HostProfile Profile,
    IReadOnlyDictionary<string, string> Databases,
    OpenBaoOptions? Custody,
    int HealthPort,
    int PublicPort,
    IReadOnlyList<string> Refused)
{
    /// <summary>The browser origin, when the profile has one and it resolved.</summary>
    public HostOrigin? Origin { get; init; }

    /// <summary>The network whose forwarded client address is believed, when one is set.</summary>
    public System.Net.IPNetwork? ForwardedBy { get; init; }

    /// <summary>The alert channel and bucket, when the profile uses them and every setting resolved.</summary>
    public OffServerSettings? OffServer { get; init; }
}

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

        HostOrigin? origin = null;
        if (profile.HasPublicOrigin)
        {
            if (HostOrigin.Serialize(configuration[HostSettingNames.PublicOrigin]) is { } serialized)
            {
                origin = new HostOrigin(serialized);
            }
            else
            {
                refused.Add(HostSettingNames.PublicOrigin);
            }
        }

        System.Net.IPNetwork? forwardedBy = null;
        var network = configuration[HostSettingNames.ForwardedBy]?.Trim();
        if (string.IsNullOrEmpty(network))
        {
            if (profile.HasForwardingProxy)
            {
                // Unset isn't "none": the host must be told it has no proxy.
                refused.Add(HostSettingNames.ForwardedBy);
            }
        }
        else if (network != HostSettingNames.NoProxy)
        {
            if (System.Net.IPNetwork.TryParse(network, out var parsed))
            {
                forwardedBy = parsed;
            }
            else
            {
                refused.Add(HostSettingNames.ForwardedBy);
            }
        }

        if (profile.RefusedHostSettings is { } hostSettings)
        {
            refused.AddRange(hostSettings(configuration));
        }

        var offServer = profile.UsesOffServer ? ResolveOffServer(configuration, refused) : null;

        return new ResolvedSettings(profile, databases, custody, healthPort, publicPort, refused)
        {
            Origin = origin,
            ForwardedBy = forwardedBy,
            OffServer = offServer,
        };
    }

    /// <summary>
    /// Every alert and bucket setting, each required: a URL that isn't absolute <c>https</c> or has
    /// user info, a bucket or region that breaks S3 naming, a Deployment name that isn't a hostname,
    /// and a secret file that is missing, empty, a known default or, for a token or key, anything
    /// but printable ASCII are each refused by name. Only settings and files are checked: nothing is
    /// sent at startup.
    /// </summary>
    private static OffServerSettings? ResolveOffServer(IConfiguration configuration, List<string> refused)
    {
        var before = refused.Count;

        var url = WebhookAlertOptions.TryParseUrl(configuration[HostSettingNames.AlertUrl]);
        if (url is null)
        {
            refused.Add(HostSettingNames.AlertUrl);
        }

        var tokenFile = configuration[HostSettingNames.AlertTokenFile];
        CheckSecretFile(tokenFile, HostSettingNames.AlertTokenFile, refused, credential: true);

        var deployment = configuration[HostSettingNames.AlertDeployment]?.Trim();
        if (!AlertDeployment.IsValid(deployment))
        {
            refused.Add(HostSettingNames.AlertDeployment);
        }

        var endpoint = ObjectLockOptions.TryParseEndpoint(configuration[HostSettingNames.RecordsEndpoint]);
        if (endpoint is null)
        {
            refused.Add(HostSettingNames.RecordsEndpoint);
        }

        var region = configuration[HostSettingNames.RecordsRegion]?.Trim();
        if (!ObjectLockOptions.IsValidRegion(region))
        {
            refused.Add(HostSettingNames.RecordsRegion);
        }

        var bucket = configuration[HostSettingNames.RecordsBucket]?.Trim();
        if (!ObjectLockOptions.IsValidBucket(bucket))
        {
            refused.Add(HostSettingNames.RecordsBucket);
        }

        var accessKeyIdFile = configuration[HostSettingNames.RecordsAccessKeyIdFile];
        CheckSecretFile(accessKeyIdFile, HostSettingNames.RecordsAccessKeyIdFile, refused, credential: true);
        var secretAccessKeyFile = configuration[HostSettingNames.RecordsSecretAccessKeyFile];
        CheckSecretFile(secretAccessKeyFile, HostSettingNames.RecordsSecretAccessKeyFile, refused, credential: true);

        if (refused.Count > before)
        {
            return null;
        }

        return new OffServerSettings(
            new WebhookAlertOptions { Url = url!, TokenFile = tokenFile! },
            new AlertDeployment(deployment!),
            new ObjectLockOptions
            {
                Endpoint = endpoint!,
                Region = region!,
                Bucket = bucket!,
                AccessKeyIdFile = accessKeyIdFile!,
                SecretAccessKeyFile = secretAccessKeyFile!,
            });
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

    /// <summary>
    /// The file must be readable and hold a value that isn't a default. A <paramref name="credential"/>,
    /// sent in an HTTP header, must also pass <see cref="SecretDefaults.IsUnsafeCredential"/>, the rule
    /// the adapters refuse it by. Its contents aren't kept.
    /// </summary>
    private static void CheckSecretFile(string? path, string name, List<string> refused, bool credential = false)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            refused.Add(name);
            return;
        }

        try
        {
            var value = File.ReadAllText(path);
            if (credential ? SecretDefaults.IsUnsafeCredential(value) : SecretDefaults.IsUnsafe(value))
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
