using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Modules.Keys.Contracts;

/// <summary>What a <c>signing_key</c> row's key is for (AD-9, AD-33).</summary>
public enum SigningKeyPurpose
{
    /// <summary>Signs the Tenant's tokens. Its public half is published in the Tenant's JWKS.</summary>
    Signing,

    /// <summary>Signs Management API tokens (AD-33). Never published, and Host.Hosted can't use it.</summary>
    Management,
}

/// <summary>A published Signing Key's state (AD-11): the states JWKS serves.</summary>
public enum PublishedKeyState
{
    /// <summary>Published ahead of its promotion, so relying parties have it before it signs.</summary>
    Next,

    /// <summary>The one key that signs.</summary>
    Current,

    /// <summary>Replaced, and still published until the tokens it signed have expired.</summary>
    Previous,
}

/// <summary>
/// One Signing Key the Tenant's JWKS publishes: its Transit key, the version its <c>kid</c> names and
/// its state. Never a <c>management</c> key.
/// </summary>
public sealed record PublishedSigningKey(KeyName Key, int Version, PublishedKeyState State)
{
    /// <summary>The <c>kid</c> (AD-10): <c>{transit key name}.v{version}</c>.</summary>
    public string KeyId => $"{Key.Value}.v{Version.ToString(System.Globalization.CultureInfo.InvariantCulture)}";
}
