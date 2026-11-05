namespace Gatekeep.Kernel.Secrets;

/// <summary>An <see cref="IKeyCustody"/> operation, named in a failure.</summary>
public enum KeyOperation
{
    Create,
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    Hmac,
    WrapDataKey,
    Rotate,
    Rewrap,
    Delete,
    ReadPublicKey,
    List,
}

public enum KeyCustodyFailure
{
    /// <summary>The caller's policy doesn't allow the operation on this key.</summary>
    Refused,

    /// <summary>The caller couldn't log in.</summary>
    LoginFailed,

    /// <summary>The key or value was rejected, for example a ciphertext bound to another Tenant.</summary>
    Rejected,

    /// <summary>Key custody couldn't be reached or answered with an error.</summary>
    Unavailable,
}

/// <summary>
/// A key custody failure. It names the key, the operation and the kind of failure only:
/// never key material, plaintext, ciphertext or the custody service's own error text.
/// </summary>
public sealed class KeyCustodyException : Exception
{
    public KeyCustodyException(string keyName, KeyOperation operation, KeyCustodyFailure failure)
        : base($"Key custody {Describe(failure)} {operation} on key {keyName}.")
    {
        KeyName = keyName;
        Operation = operation;
        Failure = failure;
    }

    public string KeyName { get; }

    public KeyOperation Operation { get; }

    public KeyCustodyFailure Failure { get; }

    private static string Describe(KeyCustodyFailure failure) => failure switch
    {
        KeyCustodyFailure.Refused => "refused",
        KeyCustodyFailure.LoginFailed => "couldn't log in for",
        KeyCustodyFailure.Rejected => "rejected",
        _ => "was unavailable for",
    };
}
