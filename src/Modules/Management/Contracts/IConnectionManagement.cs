using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Modules.Management.Contracts;

/// <summary>How a database Connection or Tenant settings read or save ended (Story 4.6).</summary>
public enum ConnectionStatus
{
    /// <summary>Done: a read, or a save that wrote its one event or changed nothing.</summary>
    Done,

    /// <summary>The capability isn't held in the path Tenant. Nothing written.</summary>
    Forbidden,

    /// <summary>A field is refused; the result names each. Nothing written.</summary>
    Invalid,

    /// <summary>The Tenant isn't active: still being created, or being deleted. Nothing written.</summary>
    NotActive,

    /// <summary>The Tenant has no database Connection. Nothing written.</summary>
    NotFound,
}

/// <summary>One refused field (Story 4.6): the request's member, the reason, and the rule's text a client shows as it is. Never its value.</summary>
public sealed record ConnectionFieldError(string Field, string Reason, string Detail);

/// <summary>A database Connection's password policy as the Admin API shows it (Story 4.6).</summary>
public sealed record ManagedPasswordPolicy(int MinLength, string Strength, int HistoryCount, bool Dictionary, bool PersonalData);

/// <summary>A Tenant's database Connection as the Admin API shows it (Story 4.6): its fixed name, switches, policy and last change.</summary>
public sealed record ManagedDatabaseConnection(string Name, bool Enabled, bool SignupEnabled, ManagedPasswordPolicy PasswordPolicy, DateTimeOffset UpdatedAt);

/// <summary>A database Connection request's outcome: the Connection as it stands, and on <see cref="ConnectionStatus.Invalid"/> each refused field.</summary>
public sealed record DatabaseConnectionResult(
    ConnectionStatus Status,
    ManagedDatabaseConnection? Connection,
    IReadOnlyList<ConnectionFieldError> Errors,
    bool Changed);

/// <summary>A password policy save's input as the request gave it (Story 4.6): each part may be missing, and the save decides.</summary>
public sealed record PasswordPolicySaveInput(int? MinLength, string? Strength, int? HistoryCount, bool? Dictionary, bool? PersonalData);

/// <summary>
/// A Tenant's database Connection (Story 4.6, FR-17, FR-18), in the path Tenant's own context: read with
/// <c>tenant.configuration.read</c>, sign-up toggled with <c>tenant.connections.toggle</c> and the password policy saved
/// with <c>tenant.password_policy.manage</c>, each decided again here (AD-5). Each save is one command writing its state and
/// one Tenant-targeted event, and only when a value changed.
/// </summary>
public interface IDatabaseConnectionManagement
{
    /// <summary>The path Tenant's database Connection.</summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<DatabaseConnectionResult> GetAsync(
        CommandContext tenantContext, Principal principal, TenantRoleGrant? grant, Guid tenantId, CancellationToken cancellationToken);

    /// <summary>Turns sign-up on or off. A null <paramref name="signupEnabled"/> is refused as <c>required</c>. The caller commits only on <see cref="ConnectionStatus.Done"/>.</summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<DatabaseConnectionResult> SetSettingsAsync(
        CommandContext tenantContext, Principal principal, TenantRoleGrant? grant, Guid tenantId, bool? signupEnabled, CancellationToken cancellationToken);

    /// <summary>Replaces the password policy, every field refused named. The caller commits only on <see cref="ConnectionStatus.Done"/>.</summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<DatabaseConnectionResult> SetPasswordPolicyAsync(
        CommandContext tenantContext, Principal principal, TenantRoleGrant? grant, Guid tenantId, PasswordPolicySaveInput input, CancellationToken cancellationToken);
}

/// <summary>
/// A Tenant's settings as the Admin API shows them (Story 4.6): the terms URL, whether email verification is off, which
/// is false unless the Tenant is Dev, whether turning it off is available (the Tenant is Dev), and the default audience.
/// </summary>
public sealed record ManagedTenantSettings(string? TermsUrl, bool EmailVerificationOff, bool EmailVerificationOffAvailable, string? DefaultAudience);

/// <summary>A Tenant settings request's outcome: the settings as they stand, and on <see cref="ConnectionStatus.Invalid"/> each refused field.</summary>
public sealed record TenantSettingsResult(
    ConnectionStatus Status,
    ManagedTenantSettings? Settings,
    IReadOnlyList<ConnectionFieldError> Errors,
    bool Changed);

/// <summary>A Tenant settings save's input as the request gave it (Story 4.6).</summary>
public sealed record TenantSettingsSaveInput(string? TermsUrl, bool? EmailVerificationOff, string? DefaultAudience);

/// <summary>
/// A Tenant's settings a sign-up reads (Story 4.6): read with <c>tenant.configuration.read</c> and saved with
/// <c>tenant.settings.manage</c>, decided again here (AD-5), in the path Tenant's own context. The default audience must
/// name one of the Tenant's APIs other than the built-in Management API, checked through Directory; email verification may
/// be turned off only while the Tenant is Dev, judged under the label's lock.
/// </summary>
public interface ITenantSettingsManagement
{
    /// <summary>The path Tenant's settings.</summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<TenantSettingsResult> GetAsync(
        CommandContext tenantContext, Principal principal, TenantRoleGrant? grant, Guid tenantId, CancellationToken cancellationToken);

    /// <summary>Replaces the path Tenant's settings, every field refused named. The caller commits only on <see cref="ConnectionStatus.Done"/>.</summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<TenantSettingsResult> SaveAsync(
        CommandContext tenantContext, Principal principal, TenantRoleGrant? grant, Guid tenantId, TenantSettingsSaveInput input, CancellationToken cancellationToken);
}
