using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Management.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;

namespace Gatekeep.Modules.Management.Core;

/// <summary>
/// The Database page's reads and saves (Story 4.6), over Directory's contract, with each capability decided again here (AD-5).
/// A save runs only while the Tenant is active, decided under its row's lock.
/// </summary>
internal sealed class DatabaseConnectionManagement(IAuditAppender appender) : IDatabaseConnectionManagement
{
    private const string RequiredText = "Required.";

    private readonly IDirectory _directory = DirectoryContract.CreateDirectory(appender, TimeProvider.System);

    private readonly ITenants _tenants = TenancyContract.CreateTenants(appender);

    public async Task<DatabaseConnectionResult> GetAsync(
        CommandContext tenantContext, Principal principal, TenantRoleGrant? grant, Guid tenantId, CancellationToken cancellationToken)
    {
        Scope.RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantConfigurationRead, principal, grant, tenantId))
        {
            return Refused(ConnectionStatus.Forbidden);
        }

        return await _directory.FindDatabaseConnectionAsync(tenantContext, cancellationToken) is { } connection
            ? new DatabaseConnectionResult(ConnectionStatus.Done, Managed(connection), [], Changed: false)
            : Refused(ConnectionStatus.NotFound);
    }

    public async Task<DatabaseConnectionResult> SetSettingsAsync(
        CommandContext tenantContext, Principal principal, TenantRoleGrant? grant, Guid tenantId, bool? signupEnabled, CancellationToken cancellationToken)
    {
        Scope.RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantConnectionsToggle, principal, grant, tenantId))
        {
            return Refused(ConnectionStatus.Forbidden);
        }

        if (signupEnabled is not { } enabled)
        {
            return new DatabaseConnectionResult(
                ConnectionStatus.Invalid, null, [new ConnectionFieldError("signupEnabled", PasswordPolicyReasons.Required, RequiredText)], Changed: false);
        }

        if (!await ActiveAsync(tenantContext, tenantId, cancellationToken))
        {
            return Refused(ConnectionStatus.NotActive);
        }

        var write = await _directory.UpdateDatabaseConnectionSettingsAsync(tenantContext, Scope.ActorOf(principal), enabled, cancellationToken);
        return Written(write);
    }

    public async Task<DatabaseConnectionResult> SetPasswordPolicyAsync(
        CommandContext tenantContext, Principal principal, TenantRoleGrant? grant, Guid tenantId, PasswordPolicySaveInput input, CancellationToken cancellationToken)
    {
        Scope.RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(input);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantPasswordPolicyManage, principal, grant, tenantId))
        {
            return Refused(ConnectionStatus.Forbidden);
        }

        // Every field named, before anything is locked or written.
        var problems = DirectoryContract.CheckPasswordPolicy(
            new PasswordPolicyInput(input.MinLength, input.Strength, input.HistoryCount, input.Dictionary, input.PersonalData), out var policy);
        if (policy is null)
        {
            return new DatabaseConnectionResult(
                ConnectionStatus.Invalid, null, [.. problems.Select(p => new ConnectionFieldError(p.Field, p.Reason, p.Detail))], Changed: false);
        }

        if (!await ActiveAsync(tenantContext, tenantId, cancellationToken))
        {
            return Refused(ConnectionStatus.NotActive);
        }

        var write = await _directory.UpdatePasswordPolicyAsync(tenantContext, Scope.ActorOf(principal), policy, cancellationToken);
        return Written(write);
    }

    public async Task<ApplicationConnectionsResult> GetApplicationConnectionsAsync(
        CommandContext tenantContext, Principal principal, TenantRoleGrant? grant, Guid tenantId, Guid applicationId, CancellationToken cancellationToken)
    {
        Scope.RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantConfigurationRead, principal, grant, tenantId))
        {
            return new ApplicationConnectionsResult(ConnectionStatus.Forbidden, [], Changed: false);
        }

        return await _directory.ListApplicationConnectionsAsync(tenantContext, applicationId, cancellationToken) is { } connections
            ? new ApplicationConnectionsResult(ConnectionStatus.Done, [.. connections.Select(Managed)], Changed: false)
            : new ApplicationConnectionsResult(ConnectionStatus.NotFound, [], Changed: false);
    }

    public async Task<ApplicationConnectionsResult> SetApplicationConnectionAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid applicationId,
        string connectionId,
        bool? enabled,
        CancellationToken cancellationToken)
    {
        Scope.RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantConnectionsToggle, principal, grant, tenantId))
        {
            return new ApplicationConnectionsResult(ConnectionStatus.Forbidden, [], Changed: false);
        }

        // In v1 a Connection's ID is its kind, and the one kind is database.
        if (!string.Equals(connectionId, DirectoryContract.DatabaseConnectionKind, StringComparison.Ordinal))
        {
            return new ApplicationConnectionsResult(ConnectionStatus.NotFound, [], Changed: false);
        }

        if (enabled is not { } value)
        {
            return new ApplicationConnectionsResult(ConnectionStatus.Invalid, [], Changed: false);
        }

        if (!await ActiveAsync(tenantContext, tenantId, cancellationToken))
        {
            return new ApplicationConnectionsResult(ConnectionStatus.NotActive, [], Changed: false);
        }

        var write = await _directory.SetApplicationConnectionAsync(
            tenantContext, Scope.ActorOf(principal), applicationId, connectionId, value, cancellationToken);
        return write.Status switch
        {
            ApplicationConnectionWriteStatus.Saved => new ApplicationConnectionsResult(ConnectionStatus.Done, [Managed(write.Connection!)], Changed: true),
            ApplicationConnectionWriteStatus.Unchanged => new ApplicationConnectionsResult(ConnectionStatus.Done, [Managed(write.Connection!)], Changed: false),
            ApplicationConnectionWriteStatus.NotFound => new ApplicationConnectionsResult(ConnectionStatus.NotFound, [], Changed: false),
            _ => throw new InvalidOperationException("Unknown Application Connection write status."),
        };
    }

    public async Task<ConnectionApplicationsResult> GetConnectionApplicationsAsync(
        CommandContext tenantContext, Principal principal, TenantRoleGrant? grant, Guid tenantId, CancellationToken cancellationToken)
    {
        Scope.RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantConfigurationRead, principal, grant, tenantId))
        {
            return new ConnectionApplicationsResult(ConnectionStatus.Forbidden, []);
        }

        return await _directory.ListConnectionApplicationsAsync(tenantContext, DirectoryContract.DatabaseConnectionKind, cancellationToken) is { } applications
            ? new ConnectionApplicationsResult(
                ConnectionStatus.Done, [.. applications.Select(a => new ManagedConnectionApplication(a.ClientId, a.Name, a.Kind))])
            : new ConnectionApplicationsResult(ConnectionStatus.NotFound, []);
    }

    private static ManagedApplicationConnection Managed(ApplicationConnection connection) =>
        new(connection.Kind, connection.Name, connection.Kind, connection.Enabled, connection.TenantEnabled);

    /// <summary>Whether the Tenant is active, under its row's lock, which a deletion's start waits for.</summary>
    private async Task<bool> ActiveAsync(CommandContext tenantContext, Guid tenantId, CancellationToken cancellationToken) =>
        await _tenants.LockLabelAsync(tenantContext, tenantId, cancellationToken) is { Status: TenantStatus.Active };

    private static DatabaseConnectionResult Written(ConnectionWrite write) => write.Status switch
    {
        ConnectionWriteStatus.Saved => new DatabaseConnectionResult(ConnectionStatus.Done, Managed(write.Connection!), [], Changed: true),
        ConnectionWriteStatus.Unchanged => new DatabaseConnectionResult(ConnectionStatus.Done, Managed(write.Connection!), [], Changed: false),
        ConnectionWriteStatus.NotFound => Refused(ConnectionStatus.NotFound),
        _ => throw new InvalidOperationException("Unknown database Connection write status."),
    };

    private static ManagedDatabaseConnection Managed(DatabaseConnection connection) =>
        new(
            connection.Name,
            connection.Enabled,
            connection.SignupEnabled,
            new ManagedPasswordPolicy(
                connection.Policy.MinLength,
                connection.Policy.Strength,
                connection.Policy.HistoryCount,
                connection.Policy.Dictionary,
                connection.Policy.PersonalData),
            connection.UpdatedAt);

    private static DatabaseConnectionResult Refused(ConnectionStatus status) => new(status, null, [], Changed: false);
}

/// <summary>
/// The Tenant settings card's read and save (Story 4.6), over Tenancy's contract, with the default audience checked through
/// Directory's and the capability decided again here (AD-5).
/// </summary>
internal sealed class TenantSettingsManagement(IAuditAppender appender) : ITenantSettingsManagement
{
    private const string AudienceText = "Choose one of the Tenant's APIs.";

    private readonly IDirectory _directory = DirectoryContract.CreateDirectory(appender, TimeProvider.System);

    private readonly ITenants _tenants = TenancyContract.CreateTenants(appender);

    public async Task<TenantSettingsResult> GetAsync(
        CommandContext tenantContext, Principal principal, TenantRoleGrant? grant, Guid tenantId, CancellationToken cancellationToken)
    {
        Scope.RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantConfigurationRead, principal, grant, tenantId))
        {
            return Refused(ConnectionStatus.Forbidden);
        }

        return await _tenants.GetSettingsAsync(tenantContext, tenantId, cancellationToken) is { } state
            ? new TenantSettingsResult(ConnectionStatus.Done, Managed(state), [], Changed: false)
            : Refused(ConnectionStatus.Forbidden);
    }

    public async Task<TenantSettingsResult> SaveAsync(
        CommandContext tenantContext, Principal principal, TenantRoleGrant? grant, Guid tenantId, TenantSettingsSaveInput input, CancellationToken cancellationToken)
    {
        Scope.RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(input);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantSettingsManage, principal, grant, tenantId))
        {
            return Refused(ConnectionStatus.Forbidden);
        }

        // The label's lock first: the Dev-only rule is judged on the label the write then holds.
        if (await _tenants.LockSettingsAsync(tenantContext, tenantId, cancellationToken) is not { } state)
        {
            return Refused(ConnectionStatus.Forbidden);
        }

        if (state.Status != TenantStatus.Active)
        {
            return Refused(ConnectionStatus.NotActive);
        }

        var problems = TenancyContract.CheckSettings(
            new TenantSettingsInput(input.TermsUrl, input.EmailVerificationOff, input.DefaultAudience), state.Label, out var settings);
        var errors = problems.Select(p => new ConnectionFieldError(p.Field, p.Reason, p.Detail)).ToList();

        // A well-formed audience must name one of the Tenant's own APIs, and never the built-in Management API. Only a new
        // one is looked up: the stored one, whose API may since be gone (token issue falls back), is kept as it is, so it
        // never blocks saving the other settings.
        if (input.DefaultAudience is { } audience
            && !string.Equals(audience, state.Settings.DefaultAudience, StringComparison.Ordinal)
            && !problems.Any(p => p.Field == TenantSettingsFields.DefaultAudience))
        {
            var api = await _directory.FindApiByIdentifierAsync(tenantContext, audience, cancellationToken);
            if (api is null)
            {
                errors.Add(new ConnectionFieldError(TenantSettingsFields.DefaultAudience, TenantSettingsReasons.NotFound, AudienceText));
            }
            else if (api.BuiltIn)
            {
                errors.Add(new ConnectionFieldError(TenantSettingsFields.DefaultAudience, TenantSettingsReasons.BuiltIn, AudienceText));
            }
        }

        if (errors.Count != 0 || settings is null)
        {
            return new TenantSettingsResult(ConnectionStatus.Invalid, null, [.. OrderedByField(errors)], Changed: false);
        }

        var changed = await _tenants.SaveSettingsAsync(tenantContext, tenantId, settings, Scope.ActorOf(principal), cancellationToken);
        return new TenantSettingsResult(
            ConnectionStatus.Done, Managed(new TenantSettingsState(settings, state.Label, state.Status)), [], changed);
    }

    private static IEnumerable<ConnectionFieldError> OrderedByField(List<ConnectionFieldError> errors) =>
        errors.OrderBy(e => Array.IndexOf([.. TenantSettingsFields.All], e.Field));

    /// <summary>Verification off as it counts: only while the Tenant is Dev.</summary>
    private static ManagedTenantSettings Managed(TenantSettingsState state)
    {
        var dev = state.Label == TenantLabel.Dev;
        return new ManagedTenantSettings(
            state.Settings.TermsUrl, state.Settings.EmailVerificationOff && dev, dev, state.Settings.DefaultAudience);
    }

    private static TenantSettingsResult Refused(ConnectionStatus status) => new(status, null, [], Changed: false);
}

/// <summary>What both of Story 4.6's managements share: the context check and the Actor of a principal.</summary>
internal static class Scope
{
    public static Actor ActorOf(Principal principal) => principal switch
    {
        AdminPrincipal admin => Actor.Admin(admin.AdminId),
        MachinePrincipal machine => Actor.Client(machine.ClientId),
        _ => throw new ArgumentOutOfRangeException(nameof(principal)),
    };

    public static void RequireOwnContext(CommandContext context, Guid tenantId)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (tenantId == Guid.Empty || context.TenantId != tenantId)
        {
            throw new InvalidOperationException("A Tenant's Connection and settings are read and written in its own context.");
        }
    }
}
