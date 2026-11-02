namespace Gatekeep.Kernel.Secrets;

/// <summary>What a key can do, which decides its Transit type.</summary>
public enum KeyKind
{
    /// <summary>RSA-3072, signing with RS256 (AD-9).</summary>
    Signing,

    /// <summary>AES-256-GCM, with the Tenant ID as associated data (AD-10).</summary>
    Aead,

    /// <summary>A key used only for HMAC (AD-24).</summary>
    Hmac,
}

/// <summary>A Tenant's secret classes (AD-10). Each has its own key per Tenant.</summary>
public enum TenantKeyClass
{
    /// <summary>TOTP seeds and pending Recovery Codes.</summary>
    Totp,

    /// <summary>Social provider credentials.</summary>
    Social,

    /// <summary>Email provider credentials.</summary>
    Email,

    /// <summary>Credential-equivalent job payloads.</summary>
    Payload,

    /// <summary>Email codes and Recovery Codes, as HMAC.</summary>
    Hmac,

    /// <summary>The wrap key for the token protection key.</summary>
    TokenProtection,
}

/// <summary>The Deployment's own keys (AD-10, AD-17).</summary>
public enum DeploymentKeyClass
{
    Email,
    Payload,
    Hmac,

    /// <summary>Signs off-server records. Only <c>Host.Worker</c> and <c>Gatekeep.Cli</c> may use it.</summary>
    Records,
}

/// <summary>
/// A Transit key name, built only in the AD-10 forms: <c>sig-{tenantId}-{rowId}</c>,
/// <c>mgmt-{tenantId}-{rowId}</c>, <c>{class}-{tenantId}</c> and <c>dep-{class}</c>.
/// Policies separate keys by these prefixes, so no other name can be made.
/// </summary>
public sealed class KeyName : IEquatable<KeyName>
{
    private KeyName(string value, KeyKind kind, Guid? tenantId)
    {
        Value = value;
        Kind = kind;
        TenantId = tenantId;
    }

    public string Value { get; }

    public KeyKind Kind { get; }

    /// <summary>The owning Tenant, or <see langword="null"/> for a Deployment key.</summary>
    public Guid? TenantId { get; }

    /// <summary>A Signing Key, named from its pre-generated <c>signing_key</c> row ID (AD-10).</summary>
    public static KeyName Signing(Guid tenantId, Guid rowId) =>
        new($"sig-{Id(tenantId, nameof(tenantId))}-{Id(rowId, nameof(rowId))}", KeyKind.Signing, tenantId);

    /// <summary>A Management key (AD-33), named from its pre-generated row ID.</summary>
    public static KeyName Management(Guid tenantId, Guid rowId) =>
        new($"mgmt-{Id(tenantId, nameof(tenantId))}-{Id(rowId, nameof(rowId))}", KeyKind.Signing, tenantId);

    public static KeyName ForTenant(TenantKeyClass keyClass, Guid tenantId)
    {
        var (prefix, kind) = keyClass switch
        {
            TenantKeyClass.Totp => ("totp", KeyKind.Aead),
            TenantKeyClass.Social => ("social", KeyKind.Aead),
            TenantKeyClass.Email => ("email", KeyKind.Aead),
            TenantKeyClass.Payload => ("payload", KeyKind.Aead),
            TenantKeyClass.Hmac => ("hmac", KeyKind.Hmac),
            TenantKeyClass.TokenProtection => ("tpk", KeyKind.Aead),
            _ => throw new ArgumentOutOfRangeException(nameof(keyClass)),
        };

        return new($"{prefix}-{Id(tenantId, nameof(tenantId))}", kind, tenantId);
    }

    public static KeyName ForDeployment(DeploymentKeyClass keyClass)
    {
        var (suffix, kind) = keyClass switch
        {
            DeploymentKeyClass.Email => ("email", KeyKind.Aead),
            DeploymentKeyClass.Payload => ("payload", KeyKind.Aead),
            DeploymentKeyClass.Hmac => ("hmac", KeyKind.Hmac),
            DeploymentKeyClass.Records => ("records", KeyKind.Signing),
            _ => throw new ArgumentOutOfRangeException(nameof(keyClass)),
        };

        return new($"dep-{suffix}", kind, null);
    }

    public bool Equals(KeyName? other) => other is not null && Value == other.Value;

    public override bool Equals(object? obj) => Equals(obj as KeyName);

    public override int GetHashCode() => Value.GetHashCode(StringComparison.Ordinal);

    public override string ToString() => Value;

    private static string Id(Guid id, string parameter) =>
        id == Guid.Empty ? throw new ArgumentException("An empty ID names no key.", parameter) : id.ToString("D");
}
