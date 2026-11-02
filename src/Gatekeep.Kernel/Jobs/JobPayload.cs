using System.Collections.ObjectModel;
using System.Text.RegularExpressions;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Kernel.Jobs;

/// <summary>
/// What a Tenant job carries (AD-15): named internal IDs, and at most one
/// credential-equivalent value, which is stored only as Transit ciphertext under the
/// Tenant's <c>payload</c> key and erased when the job finishes. Nothing else fits.
/// </summary>
public sealed partial class JobPayload
{
    public const int MaxIds = 16;

    private const int MaxNameLength = 63;

    public JobPayload(IReadOnlyDictionary<string, Guid> ids, Secret<byte[]>? credential = null)
    {
        ArgumentNullException.ThrowIfNull(ids);

        if (ids.Count > MaxIds)
        {
            throw new ArgumentException($"A job payload holds at most {MaxIds} IDs.", nameof(ids));
        }

        foreach (var (name, id) in ids)
        {
            if (name is null || name.Length > MaxNameLength || !NamePattern().IsMatch(name))
            {
                throw new ArgumentException("An ID name is lower-case snake_case, at most 63 characters.", nameof(ids));
            }

            if (id == Guid.Empty)
            {
                throw new ArgumentException("A job payload ID can't be empty.", nameof(ids));
            }
        }

        Ids = new ReadOnlyDictionary<string, Guid>(new Dictionary<string, Guid>(ids, StringComparer.Ordinal));
        Credential = credential;
    }

    public IReadOnlyDictionary<string, Guid> Ids { get; }

    /// <summary>The one credential-equivalent value, if the job type allows one.</summary>
    public Secret<byte[]>? Credential { get; }

    public override string ToString() => nameof(JobPayload);

    [GeneratedRegex(@"\A[a-z][a-z0-9_]*\z")]
    private static partial Regex NamePattern();
}
