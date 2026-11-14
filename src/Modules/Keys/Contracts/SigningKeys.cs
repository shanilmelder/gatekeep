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

/// <summary>How an on-demand rotation of a Tenant's Signing Key ended (Story 9.2).</summary>
public enum SigningKeyRotationStatus
{
    /// <summary><c>next</c> became <c>current</c>, <c>current</c> became <c>previous</c>, and a new <c>next</c> was created.</summary>
    Rotated,

    /// <summary><c>next</c> was published less than 15 minutes ago: nothing was written.</summary>
    NotReady,
}

/// <summary>
/// An on-demand rotation's outcome (Story 9.2). <see cref="RetryAfter"/> is set only on
/// <see cref="SigningKeyRotationStatus.NotReady"/>: how long until <c>next</c> has been published for
/// 15 minutes, by database time, never under one second.
/// </summary>
public sealed record SigningKeyRotation(SigningKeyRotationStatus Status, TimeSpan? RetryAfter);

/// <summary>How a revocation of one of a Tenant's Signing Keys ended (Story 9.3).</summary>
public enum SigningKeyRevocationStatus
{
    /// <summary>The key left JWKS, its destruction was queued, and a revoked <c>current</c> or <c>next</c> was replaced.</summary>
    Revoked,

    /// <summary>
    /// The key ID names no published Signing Key of this Tenant: unknown, malformed, a Management key,
    /// retired, already revoked or another Tenant's. Nothing was written.
    /// </summary>
    NotFound,
}

/// <summary>A Signing Key revocation's outcome (Story 9.3).</summary>
public sealed record SigningKeyRevocation(SigningKeyRevocationStatus Status);
