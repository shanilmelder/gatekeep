using System.Globalization;
using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Audit.Contracts;

/// <summary>What is wrong at one place in a chain.</summary>
public enum ChainProblemKind
{
    /// <summary>A row is there, but its hash, link or epoch doesn't hold.</summary>
    Altered,

    /// <summary>Rows that should be there aren't, and no retention checkpoint accounts for them.</summary>
    Missing,
}

/// <summary>
/// One problem in one chain, by position only: no row content. <paramref name="Epoch"/> is
/// null for a missing range, whose rows' epoch can't be read.
/// </summary>
public sealed record ChainProblem(ChainProblemKind Kind, long? Epoch, long FromSeq, long ToSeq, string Reason)
{
    /// <summary>For example <c>epoch 1 seq 3: altered (hash doesn't match)</c> or <c>seq 1-2: missing (no checkpoint names seq 2)</c>.</summary>
    public override string ToString()
    {
        var position = FromSeq == ToSeq
            ? string.Create(CultureInfo.InvariantCulture, $"seq {FromSeq}")
            : string.Create(CultureInfo.InvariantCulture, $"seq {FromSeq}-{ToSeq}");

        if (Epoch is { } epoch)
        {
            position = string.Create(CultureInfo.InvariantCulture, $"epoch {epoch} {position}");
        }

        var kind = Kind == ChainProblemKind.Altered ? "altered" : "missing";
        return $"{position}: {kind} ({Reason})";
    }
}

/// <summary>One chain's verification: how many sealed rows it walked, and every problem found.</summary>
public sealed record ChainReport(long SealedRows, IReadOnlyList<ChainProblem> Problems)
{
    public bool Intact => Problems.Count == 0;
}

/// <summary>
/// Walks one chain (AD-16, FR-40): the context's Tenant chain, or the Deployment chain when
/// the context has no Tenant. It only reads, so <c>gk_cli</c> runs it.
/// </summary>
public interface IAuditVerifier
{
    /// <summary>
    /// Reads the chain's sealed rows in <c>seq</c> order and checks that no <c>seq</c> is
    /// skipped, that each <c>prev_hash</c> is the previous row's <c>hash</c>, that each hash
    /// recomputes from its envelope, that the epoch stays the same from row to row, and that
    /// only <c>seq = 1</c> lacks a <c>prev_hash</c>. A first row above <c>seq = 1</c> must be
    /// accounted for by a checkpoint that names <c>seq - 1</c>, that row's <c>prev_hash</c> and
    /// its epoch: a sealed one in the chain whose own hash holds, or one not yet sealed, which
    /// only <c>gk_retention</c> can have written.
    /// </summary>
    Task<ChainReport> VerifyAsync(CommandContext context, CancellationToken cancellationToken);
}
