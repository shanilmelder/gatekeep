using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Gatekeep.Modules.Audit.Contracts;

namespace Gatekeep.Modules.Audit.Core;

/// <summary>
/// <c>hash = SHA-256(prev_hash || canonical envelope)</c> (AD-16). The genesis row has no
/// previous hash, so its input is the envelope alone. <c>seq</c> and <c>epoch</c> are inside
/// the envelope, so a moved or renumbered row no longer matches its hash.
/// </summary>
internal static class ChainHash
{
    private const string TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'";

    public static string CanonicalEnvelope(ChainEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        return CanonicalJson.Write(
        [
            new("actor_id", Text(envelope.ActorId)),
            new("actor_kind", envelope.ActorKind),
            new("epoch", envelope.Epoch),
            new("id", Text(envelope.Id)),
            new("occurred_at", envelope.OccurredAt.UtcDateTime.ToString(TimeFormat, CultureInfo.InvariantCulture)),
            new("seq", envelope.Seq),
            new("target_id", Text(envelope.TargetId)),
            new("target_kind", envelope.TargetKind),
            new("tenant_id", Text(envelope.TenantId)),
            new("type_code", envelope.TypeCode),
        ]);
    }

    public static byte[] Compute(byte[]? previousHash, ChainEnvelope envelope)
    {
        var body = Encoding.UTF8.GetBytes(CanonicalEnvelope(envelope));
        var input = previousHash is null ? body : [.. previousHash, .. body];

        return SHA256.HashData(input);
    }

    /// <summary>The "D" format is lower case.</summary>
    private static string? Text(Guid? id) => id?.ToString("D");
}
