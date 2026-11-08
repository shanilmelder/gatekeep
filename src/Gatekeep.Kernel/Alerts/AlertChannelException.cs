namespace Gatekeep.Kernel.Alerts;

/// <summary>An <see cref="IAlertChannel"/> operation, named in a failure.</summary>
public enum AlertOperation
{
    Send,
}

public enum AlertChannelFailure
{
    /// <summary>
    /// Nothing was sent: the channel's address resolves only to a private, loopback or link-local
    /// address, or its settings can't be read.
    /// </summary>
    Refused,

    /// <summary>The channel answered, with anything but 2xx, a redirect included.</summary>
    Rejected,

    /// <summary>The channel couldn't be reached, or didn't answer in time.</summary>
    Unavailable,
}

/// <summary>Why a <see cref="AlertChannelFailure.Refused"/> send sent nothing, so the Cli can say which.</summary>
public enum AlertRefusal
{
    /// <summary>The egress rule refused the channel's address: it has no public one.</summary>
    Address,

    /// <summary>The token file can't be read, or holds an unusable token.</summary>
    TokenFile,
}

/// <summary>
/// An alert channel failure, shaped like <c>KeyCustodyException</c>: the operation and the kind of
/// failure only. Never a response body or header, the channel's address, its token or the remote
/// error text, and no inner exception, whose message could hold the address.
/// </summary>
public sealed class AlertChannelException : Exception
{
    public AlertChannelException(AlertOperation operation, AlertChannelFailure failure, AlertRefusal? refusal = null)
        : base($"The alert channel {Describe(failure)} {operation}.")
    {
        Operation = operation;
        Failure = failure;
        Refusal = failure == AlertChannelFailure.Refused ? refusal : null;
    }

    public AlertOperation Operation { get; }

    public AlertChannelFailure Failure { get; }

    /// <summary>Why nothing was sent, when <see cref="Failure"/> is <see cref="AlertChannelFailure.Refused"/>.</summary>
    public AlertRefusal? Refusal { get; }

    private static string Describe(AlertChannelFailure failure) => failure switch
    {
        AlertChannelFailure.Refused => "refused",
        AlertChannelFailure.Rejected => "rejected",
        _ => "was unavailable for",
    };
}
