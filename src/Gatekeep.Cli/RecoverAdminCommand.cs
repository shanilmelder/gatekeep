using System.Data.Common;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Gatekeep.Adapters.AlertChannel;
using Gatekeep.Adapters.Egress;
using Gatekeep.Adapters.ObjectLock;
using Gatekeep.Adapters.OpenBao;
using Gatekeep.Kernel.Alerts;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Records;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Audit.Contracts;
using Npgsql;

namespace Gatekeep.Cli;

/// <summary>What one <c>recover-admin</c> run is given: the <c>gk_cli</c> connection, the chosen Admin's public ID, if any, and the alert webhook.</summary>
public sealed record RecoverAdminOptions
{
    public required string ConnectionString { get; init; }

    /// <summary>The <c>adm_</c> public ID <c>--admin</c> named, or null when it wasn't given.</summary>
    public string? Admin { get; init; }

    public required WebhookAlertOptions Alerts { get; init; }
}

/// <summary>
/// <c>gatekeep recover-admin</c> (Story 1.32, AD-31): lets an Admin who lost every WebAuthn
/// credential, or a first Admin whose setup Session ended, register new ones, and never quietly.
/// In a fixed order, as <c>gk_cli</c>: it finds the Admin and reads the database clock; makes the
/// enrolment's value; sends the <c>admin.recovery.started</c> Security Alert and waits for a 2xx;
/// signs and writes the <c>admin_recovery</c> off-server record and waits for the store; only then
/// stores the value's SHA-256 with <c>admin.enrolment.issued</c> in one transaction and commits;
/// and only then prints the link, once. A failure at any step exits 1 with nothing stored or
/// printed. The alert and the record carry the Admin, the enrolment and its times, never the value.
/// </summary>
public static class RecoverAdminCommand
{
    /// <summary>The off-server record's kind, so its key is <c>records/admin_recovery/{yyyy}/{MM}/{dd}/{recordId}.json</c>.</summary>
    public const string RecordKind = "admin_recovery";

    public const string Issued = "Nothing was issued.";

    public const string NoAdmin =
        "No Admin exists yet, so bootstrap isn't complete: run gatekeep init and claim the Deployment instead. Nothing was issued.";

    public const string AlertRejected = "Alert channel rejected the Security Alert, so no enrolment was issued.";
    public const string AlertUnavailable = "Alert channel unavailable, so no enrolment was issued.";
    public const string AlertRefusedPrivate = "Alert channel refused: private address. No enrolment was issued.";
    public const string AlertRefusedToken = "Alert channel refused: token file unusable. No enrolment was issued.";

    public const string RecordRejected = "Off-server store rejected the record, so no enrolment was issued. The Security Alert was already sent.";
    public const string RecordUnavailable = "Off-server store unavailable, so no enrolment was issued. The Security Alert was already sent.";
    public const string RecordRefusedPrivate = "Off-server store refused: private address. No enrolment was issued. The Security Alert was already sent.";
    public const string RecordRefusedCredential = "Off-server store refused: credential file unusable. No enrolment was issued. The Security Alert was already sent.";

    /// <summary>Appended to a failure once the Security Alert was delivered.</summary>
    public const string AlertSent = "The Security Alert was already sent.";

    /// <summary>Appended to a failure once the off-server record was written.</summary>
    public const string RecordWritten = "The off-server record was already written.";

    /// <summary>The link's path on the Admin hostname. The value goes in the fragment, which no request line or log carries.</summary>
    public const string RecoverPath = "/recover";

    private const int Success = 0;
    private const int Failure = 1;
    private const string CliRole = "gk_cli";

    private enum Phase
    {
        BeforeAlert,

        /// <summary>The Security Alert was delivered.</summary>
        Alerted,

        /// <summary>The off-server record was written too.</summary>
        Recorded,
        Committing,
        Committed,
    }

    /// <summary>The command as the <c>cli</c> service runs it, with its settings from the environment and SIGINT and SIGTERM cancelling it cleanly.</summary>
    public static async Task<int> RunAsync(string connectionString, string? admin)
    {
        var refused = new List<string>();
        var alerts = OffServerSettings.Alerts(Environment.GetEnvironmentVariable, refused);
        var records = OffServerSettings.Records(Environment.GetEnvironmentVariable, refused);
        var custody = InitCommand.CustodyOptions(Environment.GetEnvironmentVariable, refused);
        if (alerts is not { } resolved || records is null || custody is null)
        {
            await Console.Error.WriteLineAsync(OffServerSettings.Refusal(refused, "Nothing was sent or issued."));
            return Failure;
        }

        using var cancellation = new CancellationTokenSource();
        using var interrupt = PosixSignalRegistration.Create(PosixSignal.SIGINT, Cancel);
        using var terminate = PosixSignalRegistration.Create(PosixSignal.SIGTERM, Cancel);

        void Cancel(PosixSignalContext context)
        {
            context.Cancel = true;
            cancellation.Cancel();
        }

        using var keys = new OpenBaoKeyCustody(custody, TimeProvider.System);
        using var store = new S3ObjectLockStore(EgressHttp.Create(), records, TimeProvider.System);
        return await RunAsync(
            new RecoverAdminOptions { ConnectionString = connectionString, Admin = admin, Alerts = resolved.Options },
            resolved.Deployment,
            EgressHttp.Create(),
            keys,
            store,
            TimeProvider.System,
            Console.Out,
            Console.Error,
            cancellation.Token);
    }

    /// <summary>
    /// The run itself, with every dependency given: <see cref="EgressHttp"/>'s handler for the
    /// alert, or the isolation tests' permit; custody that signs with <c>dep-records</c>; and the
    /// off-server store. <paramref name="alertHandler"/> is disposed with the channel.
    /// </summary>
    public static async Task<int> RunAsync(
        RecoverAdminOptions options,
        AlertDeployment deployment,
        HttpMessageHandler alertHandler,
        IKeyCustody custody,
        IOffServerStore store,
        TimeProvider time,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(deployment);
        ArgumentNullException.ThrowIfNull(alertHandler);
        ArgumentNullException.ThrowIfNull(custody);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        using var channel = new WebhookAlertChannel(alertHandler, options.Alerts);

        NpgsqlDataSource source;
        try
        {
            source = NpgsqlDataSource.Create(options.ConnectionString);
        }
        catch (ArgumentException)
        {
            // Its message can quote the connection string, which holds the password.
            await error.WriteLineAsync("The connection file isn't a valid connection string. Nothing was issued.");
            return Failure;
        }

        await using var ownedSource = source;
        var issuer = AdminsContract.CreateEnrolmentIssuer(AuditContract.CreateAppender());
        var phase = Phase.BeforeAlert;

        try
        {
            // 1. The Admin, and the database's time, which the enrolment's issue and expiry come from.
            EnrolmentCandidates candidates;
            await using (var scope = await DeploymentScope.BeginAsync(source, cancellationToken))
            {
                var context = scope.CreateCommandContext();
                var role = await CurrentRoleAsync(context, cancellationToken);
                if (role != CliRole)
                {
                    await error.WriteLineAsync($"Recover-admin runs only as {CliRole}, not {role}. Nothing was issued.");
                    return Failure;
                }

                candidates = await issuer.ReadAsync(context, cancellationToken);
                await scope.CommitAsync(cancellationToken);
            }

            if (Choose(candidates.Admins, options.Admin, out var refusal) is not { } admin)
            {
                await error.WriteLineAsync(refusal);
                return Failure;
            }

            // 2. The value, and the enrolment it will be stored under.
            var value = AdminEnrolmentValue.Generate();
            var enrolment = issuer.Plan(admin.AdminId, candidates.Now);

            // 3. The Security Alert, confirmed by a 2xx, before anything else leaves.
            var alert = SecurityAlert.Raise(
                SecurityAlertCode.AdminRecovery,
                deployment,
                time,
                enrolment: new AlertEnrolment(enrolment.AdminId, enrolment.Id, enrolment.IssuedAt, enrolment.ExpiresAt));
            if (await SendAlertAsync(channel, alert, error, cancellationToken) is false)
            {
                return Failure;
            }

            phase = Phase.Alerted;

            // 4. The signed off-server record, confirmed by the store.
            if (await WriteRecordAsync(new OffServerRecordWriter(custody, store, time), enrolment, error, cancellationToken) is not { } record)
            {
                return Failure;
            }

            phase = Phase.Recorded;

            // 5. Only the value's SHA-256 and the issue event, in one transaction.
            await using (var scope = await DeploymentScope.BeginAsync(source, cancellationToken))
            {
                await issuer.IssueAsync(scope.CreateCommandContext(), enrolment, value, cancellationToken);
                phase = Phase.Committing;
                await scope.CommitAsync(cancellationToken);
                phase = Phase.Committed;
            }

            // 6. Committed: the link, this once.
            await output.WriteLineAsync($"Security Alert {alert.AlertId:D} delivered and off-server record {record.Key} written.");
            await output.WriteLineAsync(string.Create(
                CultureInfo.InvariantCulture,
                $"Enrolment {enrolment.Id:D} for Admin {admin.PublicId} works once, until {enrolment.ExpiresAt.UtcDateTime:yyyy-MM-dd HH:mm:ss} UTC."));
            await output.WriteLineAsync("Open this link on the Admin's device and register new WebAuthn credentials. It is shown only now:");
            await output.WriteLineAsync(value.Use(v => Link(deployment, v)));
            return Success;
        }
        catch (Exception e)
        {
            await error.WriteLineAsync(FailureMessage(e, phase, cancellationToken.IsCancellationRequested));
            return Failure;
        }
    }

    /// <summary>
    /// The Admin <paramref name="named"/> names, or the only Admin there is. Null, with the refusal
    /// listing every Admin's public ID, when none or several could be meant.
    /// </summary>
    internal static EnrolmentCandidate? Choose(IReadOnlyList<EnrolmentCandidate> admins, string? named, out string refusal)
    {
        refusal = string.Empty;
        if (admins.Count == 0)
        {
            refusal = NoAdmin;
            return null;
        }

        var listed = $"The Admins are: {string.Join(", ", admins.Select(a => a.PublicId))}.";
        if (named is not null)
        {
            if (PublicId.TryParse(PublicIdType.Admin, named, out var id) && admins.FirstOrDefault(a => a.AdminId == id) is { } match)
            {
                return match;
            }

            refusal = $"--admin names no Admin. {listed} {Issued}";
            return null;
        }

        if (admins.Count > 1)
        {
            refusal = $"There is more than one Admin, so choose one with --admin <public Admin ID>. {listed} {Issued}";
            return null;
        }

        return admins[0];
    }

    private static async Task<bool> SendAlertAsync(WebhookAlertChannel channel, SecurityAlert alert, TextWriter error, CancellationToken cancellationToken)
    {
        try
        {
            await channel.SendAsync(alert, cancellationToken);
            return true;
        }
        catch (AlertChannelException e)
        {
            await error.WriteLineAsync(e.Failure switch
            {
                AlertChannelFailure.Rejected => AlertRejected,
                AlertChannelFailure.Unavailable => AlertUnavailable,
                // The token file is read again at the send, so it can have changed since the check.
                _ when e.Refusal == AlertRefusal.TokenFile => AlertRefusedToken,
                _ => AlertRefusedPrivate,
            });
            return false;
        }
    }

    private static async Task<OffServerRecord?> WriteRecordAsync(
        OffServerRecordWriter writer,
        AdminEnrolment enrolment,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        var payload = new JsonObject
        {
            ["adminId"] = enrolment.AdminId.ToString("D"),
            ["enrolmentId"] = enrolment.Id.ToString("D"),
            ["issuedAt"] = Timestamp(enrolment.IssuedAt),
            ["expiresAt"] = Timestamp(enrolment.ExpiresAt),
        };

        try
        {
            return await writer.WriteAsync(RecordKind, payload, cancellationToken);
        }
        catch (KeyCustodyException e)
        {
            await error.WriteLineAsync(
                $"Key custody failed ({e.Failure}), so the off-server record wasn't signed or written. No enrolment was issued. The Security Alert was already sent.");
            return null;
        }
        catch (OffServerStoreException e)
        {
            await error.WriteLineAsync(e.Failure switch
            {
                OffServerStoreFailure.Rejected => RecordRejected,
                OffServerStoreFailure.Unavailable => RecordUnavailable,
                // The credential files are read again at the write, so they can have changed since the check.
                _ when e.Refusal == OffServerRefusal.CredentialFile => RecordRefusedCredential,
                _ => RecordRefusedPrivate,
            });
            return null;
        }
    }

    /// <summary>One fixed line naming only the exception's type and SQL state, and whether anything was issued.</summary>
    private static string FailureMessage(Exception e, Phase phase, bool cancelled)
    {
        if (phase == Phase.Committed)
        {
            return $"Recover-admin issued the enrolment, but failed after the commit ({e.GetType().Name}): run it again for a new link.";
        }

        var cause = cancelled
            ? "Recover-admin was cancelled"
            : e is DbException db
                ? $"Recover-admin failed: {e.GetType().Name} {db.SqlState}".TrimEnd()
                : $"Recover-admin failed: {e.GetType().Name}";

        return phase switch
        {
            Phase.Committing =>
                $"{cause}. The commit's outcome is unknown and no link was shown, so any enrolment stored expires unused: run it again. {AlertSent} {RecordWritten}",
            Phase.Recorded => $"{cause}. No enrolment was issued. {AlertSent} {RecordWritten}",
            Phase.Alerted => $"{cause}. No enrolment was issued. {AlertSent}",
            _ => $"{cause}. No enrolment was issued.",
        };
    }

    /// <summary>
    /// <c>https://{Admin hostname}/recover#{value}</c>, on the default port: the Admin hostname is
    /// <see cref="AlertDeployment"/>'s, which the <c>cli</c> service gets as the Deployment's name.
    /// </summary>
    internal static string Link(AlertDeployment deployment, string value) =>
        new UriBuilder(Uri.UriSchemeHttps, deployment.Name) { Path = RecoverPath, Fragment = value }.Uri.AbsoluteUri;

    /// <summary>RFC 3339 in UTC to the microsecond, as the alert and audit events are.</summary>
    private static string Timestamp(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);

    private static async Task<string> CurrentRoleAsync(CommandContext context, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = "SELECT current_user::text";
        return (string)(await command.ExecuteScalarAsync(cancellationToken))!;
    }
}
