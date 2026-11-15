using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Notifications.Core;

namespace Gatekeep.Modules.Notifications.Contracts;

/// <summary>What other modules use to reach a Tenant's notification settings (Story 4.4).</summary>
public static class NotificationsContract
{
    /// <summary>
    /// The context Tenant's email provider, without its secret, or null when it has none. It writes nothing.
    /// Host.Admin reads every column but <c>secret_ciphertext</c>, which only Host.Worker may.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't a Tenant's.</exception>
    public static Task<EmailProviderConfiguration?> ReadEmailProviderAsync(CommandContext context, CancellationToken cancellationToken) =>
        EmailProviderStore.ReadAsync(context, cancellationToken);

    /// <summary>
    /// Saves the context Tenant's email provider (Story 4.4, FR-36, AD-10): the kind's settings, validated per
    /// kind with unknown members refused, the From address and name, and the provider's one secret, encrypted
    /// through <paramref name="custody"/> under the Tenant's <c>email-</c> key with its ID as associated data,
    /// before anything is written. A secret is needed when no provider is stored, when the kind changes, or for
    /// an SMTP username with none stored, or any change of settings but Postmark's message stream; omitted otherwise,
    /// the stored ciphertext stays. Saves and removals of one Tenant wait for each other. A save that changes nothing writes nothing; any other writes the row and
    /// <c>notifications.email_provider.updated</c>, with <paramref name="actor"/> and the Tenant as target, in
    /// the caller's transaction, which commits only on <see cref="EmailProviderSaveStatus.Saved"/> or
    /// <see cref="EmailProviderSaveStatus.Unchanged"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't a Tenant's.</exception>
    [StateChanging]
    public static Task<EmailProviderSave> SaveEmailProviderAsync(
        CommandContext context,
        IKeyCustody? custody,
        IAuditAppender appender,
        Actor actor,
        EmailProviderInput input,
        CancellationToken cancellationToken) =>
        EmailProviderStore.SaveAsync(context, custody, appender, actor, input, cancellationToken);

    /// <summary>
    /// Removes the context Tenant's email provider and its stored secret (Story 4.4), with
    /// <c>notifications.email_provider.removed</c>, <paramref name="actor"/> and the Tenant as target. True when
    /// one was removed; removing none writes nothing and is false.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't a Tenant's.</exception>
    [StateChanging]
    public static Task<bool> RemoveEmailProviderAsync(
        CommandContext context,
        IAuditAppender appender,
        Actor actor,
        CancellationToken cancellationToken) =>
        EmailProviderStore.RemoveAsync(context, appender, actor, cancellationToken);

    /// <summary>Notifications' Tenant purge (Story 4.4, AD-30): deletes the context Tenant's <c>email_provider</c> row.</summary>
    public static ITenantPurge TenantPurge { get; } = new NotificationsPurge();
}
