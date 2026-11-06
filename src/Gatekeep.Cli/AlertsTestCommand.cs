using Gatekeep.Adapters.AlertChannel;
using Gatekeep.Adapters.Egress;
using Gatekeep.Kernel.Alerts;

namespace Gatekeep.Cli;

/// <summary>
/// <c>gatekeep alerts test</c> (Story 1.30): sends one <c>operations.alert.test</c> Security Alert
/// through the alert channel, so the Operator proves at install that it reaches someone outside
/// the Deployment. It refuses before sending anything when a setting is missing or unsafe, and
/// prints only fixed lines and the alert's ID: never the address, the token or the channel's answer.
/// </summary>
public static class AlertsTestCommand
{
    public const string Delivered = "Test alert delivered.";
    public const string Rejected = "Alert channel rejected the alert.";
    public const string Unavailable = "Alert channel unavailable.";
    public const string RefusedPrivate = "Alert channel refused: private address.";
    public const string RefusedToken = "Alert channel refused: token file unusable.";

    private const int Success = 0;
    private const int Failure = 1;

    public static Task<int> RunAsync()
    {
        var refused = new List<string>();
        var settings = OffServerSettings.Alerts(Environment.GetEnvironmentVariable, refused);
        if (settings is not { } resolved)
        {
            Console.Error.WriteLine(OffServerSettings.Refusal(refused, "Nothing was sent."));
            return Task.FromResult(Failure);
        }

        return SendAsync(resolved.Options, resolved.Deployment, EgressHttp.Create(), TimeProvider.System, Console.Out, Console.Error, CancellationToken.None);
    }

    /// <summary>The send itself, with the handler given: <see cref="EgressHttp"/>'s, or the isolation tests' permit.</summary>
    public static async Task<int> SendAsync(
        WebhookAlertOptions options,
        AlertDeployment deployment,
        HttpMessageHandler handler,
        TimeProvider time,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        var alert = SecurityAlert.Raise(SecurityAlertCode.Test, deployment, time);
        using var channel = new WebhookAlertChannel(handler, options);

        try
        {
            await channel.SendAsync(alert, cancellationToken);
        }
        catch (AlertChannelException e)
        {
            await error.WriteLineAsync(e.Failure switch
            {
                AlertChannelFailure.Rejected => Rejected,
                AlertChannelFailure.Unavailable => Unavailable,
                // The token file is read again at the send, so it can have changed since the check.
                _ when e.Refusal == AlertRefusal.TokenFile => RefusedToken,
                _ => RefusedPrivate,
            });
            return Failure;
        }

        await output.WriteLineAsync($"{Delivered} Alert ID: {alert.AlertId:D}");
        return Success;
    }
}
