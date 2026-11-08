using Gatekeep.Adapters.AlertChannel;
using Gatekeep.Adapters.ObjectLock;
using Gatekeep.Kernel.Alerts;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Cli;

/// <summary>
/// The alert channel and bucket settings the <c>alerts test</c>, <c>records test</c> and
/// <c>audit-ship</c> commands read from their own <c>GATEKEEP_*</c> variables (Story 1.30), refused
/// by name as <c>Host.Worker</c> refuses its own, before anything is sent. A refusal names the
/// variable, never its value.
/// </summary>
public static class OffServerSettings
{
    public const string AlertUrlVariable = "GATEKEEP_ALERT_URL";
    public const string AlertTokenFileVariable = "GATEKEEP_ALERT_TOKEN_FILE";
    public const string AlertDeploymentVariable = "GATEKEEP_ALERT_DEPLOYMENT";
    public const string RecordsEndpointVariable = "GATEKEEP_RECORDS_ENDPOINT";
    public const string RecordsRegionVariable = "GATEKEEP_RECORDS_REGION";
    public const string RecordsBucketVariable = "GATEKEEP_RECORDS_BUCKET";
    public const string RecordsAccessKeyIdFileVariable = "GATEKEEP_RECORDS_ACCESS_KEY_ID_FILE";
    public const string RecordsSecretAccessKeyFileVariable = "GATEKEEP_RECORDS_SECRET_ACCESS_KEY_FILE";
    public const string AuditLogFileVariable = "GATEKEEP_AUDIT_LOG_FILE";
    public const string AuditShipStateVariable = "GATEKEEP_AUDIT_SHIP_STATE_DIR";

    /// <summary>The webhook and the Deployment's name, or null with each refused variable added to <paramref name="refused"/>.</summary>
    public static (WebhookAlertOptions Options, AlertDeployment Deployment)? Alerts(Func<string, string?> environment, List<string> refused)
    {
        ArgumentNullException.ThrowIfNull(environment);
        var before = refused.Count;

        var url = WebhookAlertOptions.TryParseUrl(environment(AlertUrlVariable));
        if (url is null)
        {
            refused.Add(AlertUrlVariable);
        }

        var tokenFile = environment(AlertTokenFileVariable);
        CheckSecretFile(tokenFile, AlertTokenFileVariable, refused);

        var deployment = environment(AlertDeploymentVariable)?.Trim();
        if (!AlertDeployment.IsValid(deployment))
        {
            refused.Add(AlertDeploymentVariable);
        }

        return refused.Count > before
            ? null
            : (new WebhookAlertOptions { Url = url!, TokenFile = tokenFile! }, new AlertDeployment(deployment!));
    }

    /// <summary>The bucket, or null with each refused variable added to <paramref name="refused"/>.</summary>
    public static ObjectLockOptions? Records(Func<string, string?> environment, List<string> refused)
    {
        ArgumentNullException.ThrowIfNull(environment);
        var before = refused.Count;

        var endpoint = ObjectLockOptions.TryParseEndpoint(environment(RecordsEndpointVariable));
        if (endpoint is null)
        {
            refused.Add(RecordsEndpointVariable);
        }

        var region = environment(RecordsRegionVariable)?.Trim();
        if (!ObjectLockOptions.IsValidRegion(region))
        {
            refused.Add(RecordsRegionVariable);
        }

        var bucket = environment(RecordsBucketVariable)?.Trim();
        if (!ObjectLockOptions.IsValidBucket(bucket))
        {
            refused.Add(RecordsBucketVariable);
        }

        var accessKeyIdFile = environment(RecordsAccessKeyIdFileVariable);
        CheckSecretFile(accessKeyIdFile, RecordsAccessKeyIdFileVariable, refused);
        var secretAccessKeyFile = environment(RecordsSecretAccessKeyFileVariable);
        CheckSecretFile(secretAccessKeyFile, RecordsSecretAccessKeyFileVariable, refused);

        return refused.Count > before
            ? null
            : new ObjectLockOptions
            {
                Endpoint = endpoint!,
                Region = region!,
                Bucket = bucket!,
                AccessKeyIdFile = accessKeyIdFile!,
                SecretAccessKeyFile = secretAccessKeyFile!,
            };
    }

    /// <summary>The one line every refusal prints: the variables, then what didn't happen.</summary>
    public static string Refusal(IEnumerable<string> refused, string consequence) =>
        $"Refusing to run: these settings are missing or unsafe: {string.Join(", ", refused.Distinct())}. {consequence}";

    /// <summary>
    /// The directory must exist and take a file: the shipper saves its offset after every chunk,
    /// and a save that fails after the write would write the same chunk again on every pass.
    /// </summary>
    public static bool IsWritableDirectory(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
        {
            return false;
        }

        var probe = Path.Combine(path, $".write-probe-{Guid.NewGuid():N}");
        try
        {
            File.WriteAllText(probe, string.Empty);
            File.Delete(probe);
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// The file must be readable and hold a token or key that isn't a default and is printable
    /// ASCII alone (<see cref="SecretDefaults.IsUnsafeCredential"/>), the rule the adapters refuse
    /// it by at each send. Its contents aren't kept.
    /// </summary>
    public static void CheckSecretFile(string? path, string name, List<string> refused)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            refused.Add(name);
            return;
        }

        try
        {
            if (SecretDefaults.IsUnsafeCredential(File.ReadAllText(path)))
            {
                refused.Add(name);
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            refused.Add(name);
        }
    }
}
