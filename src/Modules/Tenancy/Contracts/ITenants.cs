using System.Globalization;
using System.Text;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Tenancy.Contracts;

/// <summary>A Tenant's environment label (FR-7): <c>dev</c>, <c>staging</c> or <c>prod</c> in JSON and the database.</summary>
public enum TenantLabel
{
    Dev,
    Staging,
    Prod,
}

/// <summary>
/// A Tenant's lifecycle: <c>creating</c> until its creation Operation succeeds, then <c>active</c>;
/// from Story 1.29, <c>deleting</c> from its deletion's start, and <c>deleted</c> once its deletion
/// Operation succeeds. Nothing leaves <c>deleting</c> but to <c>deleted</c>, and nothing leaves <c>deleted</c>.
/// </summary>
public enum TenantStatus
{
    Creating,
    Active,
    Deleting,
    Deleted,
}

/// <summary>The stored spellings of <see cref="TenantLabel"/> and <see cref="TenantStatus"/>, and the label's one parser.</summary>
public static class TenantValues
{
    public static string Stored(TenantLabel label) => label switch
    {
        TenantLabel.Dev => "dev",
        TenantLabel.Staging => "staging",
        TenantLabel.Prod => "prod",
        _ => throw new ArgumentOutOfRangeException(nameof(label)),
    };

    public static string Stored(TenantStatus status) => status switch
    {
        TenantStatus.Creating => "creating",
        TenantStatus.Active => "active",
        TenantStatus.Deleting => "deleting",
        TenantStatus.Deleted => "deleted",
        _ => throw new ArgumentOutOfRangeException(nameof(status)),
    };

    /// <summary>The label <paramref name="text"/> spells exactly, in its stored form only.</summary>
    public static bool TryParseLabel(string? text, out TenantLabel label)
    {
        (var known, label) = text switch
        {
            "dev" => (true, TenantLabel.Dev),
            "staging" => (true, TenantLabel.Staging),
            "prod" => (true, TenantLabel.Prod),
            _ => (false, default),
        };

        return known;
    }

    internal static TenantLabel ParseLabel(string stored) =>
        TryParseLabel(stored, out var label) ? label : throw new InvalidOperationException("Unknown Tenant label.");

    internal static TenantStatus ParseStatus(string stored) => stored switch
    {
        "creating" => TenantStatus.Creating,
        "active" => TenantStatus.Active,
        "deleting" => TenantStatus.Deleting,
        "deleted" => TenantStatus.Deleted,
        _ => throw new InvalidOperationException("Unknown Tenant status."),
    };
}

/// <summary>
/// A Tenant's Admin-facing name <c>[ASSUMPTION]</c>: trimmed, then 1 to 100 characters with no
/// control character (Unicode <c>Cc</c>), no format character (<c>Cf</c>: bidi controls, zero-width
/// characters) and no lone surrogate. The dashboard checks the same rule, from shared test vectors. FR-10's display name is a separate <c>tenant_settings</c> value.
/// </summary>
public static class TenantName
{
    public const int MaxLength = 100;

    /// <summary>The trimmed name, when <paramref name="text"/> is one.</summary>
    public static bool TryNormalize(string? text, out string name)
    {
        name = string.Empty;
        var trimmed = text?.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed.Length > MaxLength)
        {
            return false;
        }

        for (var i = 0; i < trimmed.Length; i++)
        {
            // A lone surrogate isn't text, and can't be stored: refused here, never by the database.
            if (char.IsHighSurrogate(trimmed[i]) && i + 1 < trimmed.Length && char.IsLowSurrogate(trimmed[i + 1]))
            {
                i++;
            }
            else if (char.IsSurrogate(trimmed[i]))
            {
                return false;
            }
        }

        // Controls, and format characters: bidi overrides and isolates, zero-width characters, those
        // above U+FFFF included, so each code point is judged whole.
        foreach (var rune in trimmed.EnumerateRunes())
        {
            if (Rune.GetUnicodeCategory(rune) is UnicodeCategory.Control or UnicodeCategory.Format)
            {
                return false;
            }
        }

        name = trimmed;
        return true;
    }
}

/// <summary>
/// The one encoding of <c>WhenProdTenant</c> for a Tenant's label (FR-7, FR-46; Story 1.28): only
/// removing Prod needs a fresh assertion. Raising to Prod, Dev to Staging, Staging to Dev and an
/// unchanged label never do.
/// </summary>
public static class TenantLabelChange
{
    /// <summary>Whether going from <paramref name="current"/> to <paramref name="requested"/> removes the Prod label.</summary>
    public static bool RemovesProd(TenantLabel current, TenantLabel requested) =>
        current == TenantLabel.Prod && requested != TenantLabel.Prod;
}

/// <summary>A Tenant's label and status, as read under its row lock.</summary>
public sealed record TenantLabelState(TenantLabel Label, TenantStatus Status);

/// <summary>
/// A Tenant's status and stored <c>subdomain</c> host, as read under its row lock by a deletion's
/// start (Story 1.29). The host is null for a Tenant with none, which no typed value then matches.
/// </summary>
public sealed record TenantDeletionState(TenantStatus Status, string? Host);

/// <summary>A new Tenant, validated, with its ID and its address already derived.</summary>
public sealed record TenantDraft(Guid Id, string Name, TenantLabel Label, TenantAddress Address);

/// <summary>A Tenant as the Tenants list shows it: its stored host, never a subdomain split from it (AD-6).</summary>
public sealed record TenantRecord(Guid Id, string Name, TenantLabel Label, TenantStatus Status, string Host, DateTimeOffset CreatedAt);

public enum TenantInsertStatus
{
    Inserted,

    /// <summary>The host, or the issuer or RP ID derived from it, is already some Tenant's. Nothing of this Tenant was written.</summary>
    SubdomainTaken,
}

/// <summary>An insert's outcome, and the new Tenant's creation time when it was inserted.</summary>
public sealed record TenantInsertResult(TenantInsertStatus Status, DateTimeOffset? CreatedAt = null);

/// <summary>
/// The Tenants and their hosts (AD-6, AD-27): <c>tenant</c> and <c>tenant_host</c> are written only
/// here, and only <see cref="InsertAsync"/> takes a host. A host is never changed or removed.
/// </summary>
public interface ITenants
{
    /// <summary>
    /// Inserts the Tenant as <c>creating</c> and its <c>subdomain</c> host, in a Deployment context,
    /// under a savepoint: a host already issued, to any Tenant ever, is
    /// <see cref="TenantInsertStatus.SubdomainTaken"/>, and leaves the caller's transaction usable
    /// with nothing of this Tenant in it.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<TenantInsertResult> InsertAsync(CommandContext context, TenantDraft draft, CancellationToken cancellationToken);

    /// <summary>
    /// Up to <paramref name="limit"/> Tenants with their hosts, ordered by creation time then ID, after
    /// the one <paramref name="after"/> names: the page cursor stands for both. An unknown one is an
    /// empty page. A <c>deleted</c> Tenant is never listed, though a cursor naming one still works.
    /// </summary>
    Task<IReadOnlyList<TenantRecord>> ListAsync(CommandContext context, Guid? after, int limit, CancellationToken cancellationToken);

    /// <summary>
    /// Completes a creation, in that Tenant's own context: locks its row and, only while it is
    /// <c>creating</c>, inserts its <c>tenant_settings</c> row if it has none, makes it <c>active</c>,
    /// and appends <see cref="TenancyEvents.TenantActivated"/> on its chain. Repeating it, or calling it
    /// for a Tenant that is being deleted (Story 1.29), changes nothing.
    /// </summary>
    /// <returns>Whether this call activated the Tenant.</returns>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    [StateChanging]
    Task<bool> ActivateAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken);

    /// <summary>
    /// The <c>active</c> Tenants among <paramref name="ids"/>, with their <c>subdomain</c> host,
    /// ordered by creation time then ID, in one query. No IDs is no query and an empty list.
    /// </summary>
    Task<IReadOnlyList<TenantRecord>> ListActiveAsync(CommandContext context, IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken);

    /// <summary>
    /// Locks the Tenant's row (<c>FOR NO KEY UPDATE</c>) in its own context and reads its label and
    /// status, or null when there is no such Tenant. The lock is held until the caller's
    /// transaction ends, so a decision on the label holds for the write that follows. It doesn't
    /// block the <c>FOR KEY SHARE</c> of a foreign-key insert referencing the Tenant.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<TenantLabelState?> LockLabelAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken);

    /// <summary>The Tenant's label and status, read with no lock, in its own context; null when there is no such Tenant.</summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<TenantLabelState?> GetLabelAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken);

    /// <summary>
    /// Sets an <c>active</c> Tenant's label, and nothing else, in its own context, and appends
    /// <see cref="TenancyEvents.ProdLabelRemoved"/> when <paramref name="removedProd"/>, else
    /// <see cref="TenancyEvents.LabelChanged"/>, on its chain, the Actor <paramref name="actor"/>
    /// and the target the Tenant. The caller holds the row lock from <see cref="LockLabelAsync"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s, or no active Tenant was changed.</exception>
    [StateChanging]
    Task SetLabelAsync(CommandContext context, Guid tenantId, TenantLabel label, Actor actor, bool removedProd, CancellationToken cancellationToken);

    /// <summary>
    /// Locks the Tenant's row (<c>FOR NO KEY UPDATE</c>) in a Deployment context, and reads its
    /// status and <c>subdomain</c> host, or null when there is no such Tenant (Story 1.29). The lock
    /// is held until the caller's transaction ends, so a deletion's decision holds for its writes.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    Task<TenantDeletionState?> LockForDeletionAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken);

    /// <summary>
    /// Sets a <c>creating</c> or <c>active</c> Tenant <c>deleting</c>, in a Deployment context: its
    /// host stops resolving at once. The caller holds the lock from <see cref="LockForDeletionAsync"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant, or no Tenant was changed.</exception>
    [StateChanging]
    Task BeginDeletionAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken);

    /// <summary>
    /// The Tenant's status under a <c>FOR SHARE</c> lock, in its own context, or null when there is no
    /// such Tenant (Story 1.29). It conflicts with a deletion's start, so an Operation stage's
    /// decision on it holds for the stage's transaction.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<TenantStatus?> LockStatusAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken);

    /// <summary>
    /// The Tenant's status under a <c>FOR UPDATE</c> lock, in its own context, or null when there is no
    /// such Tenant: the purge stage's lock (Story 1.29). It conflicts with the <c>FOR KEY SHARE</c> every
    /// foreign-key insert referencing the Tenant holds until it commits, so a writer that passed the
    /// row guard before the deletion started commits first, and its row is purged with the rest.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<TenantStatus?> LockForPurgeAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken);

    /// <summary>
    /// Completes a deletion, in the Tenant's own context: locks its row and, while it is
    /// <c>deleting</c>, makes it <c>deleted</c> and appends <see cref="TenancyEvents.TenantDeleted"/>
    /// on its chain. A <c>deleted</c> Tenant is left alone, with nothing written.
    /// </summary>
    /// <returns>Whether this call marked the Tenant deleted.</returns>
    /// <exception cref="InvalidOperationException">
    /// The context isn't <paramref name="tenantId"/>'s, or the Tenant is neither deleting nor deleted.
    /// </exception>
    [StateChanging]
    Task<bool> MarkDeletedAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken);
}

/// <summary>
/// The Tenant a Host.Hosted request's host resolved to, by exact match on the stored host of an
/// active Tenant (AD-6): its ID and the issuer, RP ID and email link base stored at creation. It is
/// the only Tenant source on Host.Hosted (AD-4): no header, cookie, Session or claim names one.
/// </summary>
public sealed record ResolvedTenant(Guid TenantId, string Issuer, string RpId, string EmailLinkBase);
