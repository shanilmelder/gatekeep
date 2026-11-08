namespace Gatekeep.Kernel.Records;

/// <summary>An <see cref="IOffServerStore"/> operation, named in a failure.</summary>
public enum OffServerOperation
{
    Put,
}

public enum OffServerStoreFailure
{
    /// <summary>
    /// Nothing was sent: the bucket's address resolves only to a private, loopback or link-local
    /// address, or its credential files can't be read.
    /// </summary>
    Refused,

    /// <summary>The bucket answered, with anything but 2xx.</summary>
    Rejected,

    /// <summary>The bucket couldn't be reached, or didn't answer in time.</summary>
    Unavailable,
}

/// <summary>Why a <see cref="OffServerStoreFailure.Refused"/> write sent nothing, so the Cli can say which.</summary>
public enum OffServerRefusal
{
    /// <summary>The egress rule refused the bucket's address: it has no public one.</summary>
    Address,

    /// <summary>A credential file can't be read, or holds an unusable value.</summary>
    CredentialFile,
}

/// <summary>
/// An off-server store failure, shaped like <c>KeyCustodyException</c>: the operation and the kind
/// of failure only. Never a response body or header, the bucket's address or name, the credential
/// or the remote error text, and no inner exception, whose message could hold the address.
/// </summary>
public sealed class OffServerStoreException : Exception
{
    public OffServerStoreException(OffServerOperation operation, OffServerStoreFailure failure, OffServerRefusal? refusal = null)
        : base($"The off-server store {Describe(failure)} {operation}.")
    {
        Operation = operation;
        Failure = failure;
        Refusal = failure == OffServerStoreFailure.Refused ? refusal : null;
    }

    public OffServerOperation Operation { get; }

    public OffServerStoreFailure Failure { get; }

    /// <summary>Why nothing was sent, when <see cref="Failure"/> is <see cref="OffServerStoreFailure.Refused"/>.</summary>
    public OffServerRefusal? Refusal { get; }

    private static string Describe(OffServerStoreFailure failure) => failure switch
    {
        OffServerStoreFailure.Refused => "refused",
        OffServerStoreFailure.Rejected => "rejected",
        _ => "was unavailable for",
    };
}
