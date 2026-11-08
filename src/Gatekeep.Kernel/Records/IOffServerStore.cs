using Gatekeep.Kernel.Retention;

namespace Gatekeep.Kernel.Records;

/// <summary>
/// The off-server record (AD-17): an S3-API bucket on a separate provider, with Object Lock in
/// compliance mode, chosen at install. The server's credential may only write.
/// </summary>
public interface IOffServerStore
{
    /// <summary>
    /// Writes one object at <paramref name="key"/>, in compliance mode, retained until at least
    /// <see cref="RetentionPeriods.LogDays"/> days after the write. A second write to the same key adds a
    /// version; the first stays, still locked. Either the bucket answers 2xx or this throws
    /// <see cref="OffServerStoreException"/>, and it is never retried inside the store.
    /// </summary>
    /// <param name="key">An <see cref="OffServerObjectKey"/>-shaped key, such as <c>records/test/2026/11/06/{id}.json</c>.</param>
    Task PutAsync(string key, ReadOnlyMemory<byte> content, string contentType, CancellationToken cancellationToken);
}

/// <summary>The shape every object key has: segments of letters, digits, <c>.</c>, <c>_</c> and <c>-</c>, joined by <c>/</c>.</summary>
public static class OffServerObjectKey
{
    private const int MaxLength = 1024;

    public static bool IsValid(string? key) =>
        !string.IsNullOrEmpty(key)
        && key.Length <= MaxLength
        && key.Split('/').All(segment =>
            segment.Length > 0
            && segment != "."
            && segment != ".."
            && segment.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-'));
}
