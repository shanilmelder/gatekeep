using Gatekeep.Kernel.Audit;
using Gatekeep.Modules.Audit.Adapters;
using Gatekeep.Modules.Audit.Core;

namespace Gatekeep.Modules.Audit.Contracts;

/// <summary>What a composition root uses to wire the Kernel <see cref="IAuditAppender"/> port, and to seal chains.</summary>
public static class AuditContract
{
    public static IAuditAppender CreateAppender() => new AuditAppender();

    /// <summary>The chain sealer (AD-16). It must run as <c>gk_sealer</c>, the only role that may set seal columns.</summary>
    public static IAuditSealer CreateSealer() => new AuditSealer();

    /// <summary>
    /// RFC 8785 JSON for one flat object of string, integer and null values.
    /// </summary>
    /// <exception cref="ArgumentException">A name repeats, a value has another type, an integer
    /// is outside the I-JSON range, or a string holds a lone surrogate.</exception>
    public static string CanonicalJson(IEnumerable<KeyValuePair<string, object?>> members) =>
        Core.CanonicalJson.Write(members);

    /// <summary>The canonical envelope a row's hash is taken over.</summary>
    public static string CanonicalEnvelope(ChainEnvelope envelope) => ChainHash.CanonicalEnvelope(envelope);

    /// <summary>
    /// <c>SHA-256(prev_hash || canonical envelope)</c>. <paramref name="previousHash"/> is null
    /// for the genesis row only. Verification recomputes each row with this.
    /// </summary>
    public static byte[] ChainHashOf(byte[]? previousHash, ChainEnvelope envelope) =>
        ChainHash.Compute(previousHash, envelope);
}
