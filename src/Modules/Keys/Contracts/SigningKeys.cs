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

/// <summary>Any <c>signing_key</c> row's state (AD-11): the three published ones, and the two that left JWKS.</summary>
public enum SigningKeyState
{
    /// <summary>Published ahead of its promotion.</summary>
    Next,

    /// <summary>The one key that signs.</summary>
    Current,

    /// <summary>Replaced, and still published until the tokens it signed have expired.</summary>
    Previous,

    /// <summary>Out of JWKS for good once the tokens it signed expired; its Transit key is destroyed after.</summary>
    Retired,

    /// <summary>Taken out of JWKS at once, as compromised.</summary>
    Revoked,
}

/// <summary>
/// One of a Tenant's Signing Keys as the Signing keys page lists it (Story 9.1): its Transit key,
/// the version its <c>kid</c> names, its state and when its row was created. Never a
/// <c>management</c> key, and nothing of the key material.
/// </summary>
public sealed record ListedSigningKey(KeyName Key, int Version, SigningKeyState State, DateTimeOffset CreatedAt)
{
    /// <summary>The <c>kid</c> (AD-10): <c>{transit key name}.v{version}</c>, as JWKS publishes it.</summary>
    public string KeyId => $"{Key.Value}.v{Version.ToString(System.Globalization.CultureInfo.InvariantCulture)}";
}
