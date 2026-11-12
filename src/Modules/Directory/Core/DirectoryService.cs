using System.Buffers.Text;
using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Directory.Contracts;

namespace Gatekeep.Modules.Directory.Core;

internal sealed class DirectoryService(IAuditAppender audit, TimeProvider time) : IDirectory
{
    private const int MaxNameLength = DirectoryContract.MaxNameLength;

    /// <summary>The random part of a client secret: 32 bytes, 256 bits (AD-9).</summary>
    private const int SecretBytes = 32;

    private const string InsertApplication =
        """
        INSERT INTO application (tenant_id, id, name, kind, grant_types, audiences, created_at)
        VALUES (@tenant_id, @id, @name, 'machine', ARRAY['client_credentials']::text[], '{}', @created_at)
        """;

    // Story 2.9: the code flow, to the registered redirect URIs, which the table holds to 1 to 10; from
    // Story 2.10 with rotating refresh tokens.
    private const string InsertWebApplication =
        """
        INSERT INTO application (tenant_id, id, name, kind, grant_types, audiences, redirect_uris, created_at)
        VALUES (@tenant_id, @id, @name, 'web', ARRAY['authorization_code', 'refresh_token']::text[], '{}', @redirect_uris, @created_at)
        """;

    // Story 3.1: an Admin's Application, with its kind's default grants and nothing else: no redirect URI,
    // audience or secret. A web row may have no redirect URI from Story 3.1's migration.
    private const string InsertAdminApplication =
        """
        INSERT INTO application (tenant_id, id, name, kind, grant_types, audiences, created_at)
        VALUES (@tenant_id, @id, @name, @kind, @grant_types, '{}', @created_at)
        """;

    // grant_types and audiences take their empty defaults, which the system CHECK requires (Story 2.8).
    // A concurrent insert that won leaves this one doing nothing, so the caller re-selects the winner.
    private const string InsertSystemApplication =
        """
        INSERT INTO application (tenant_id, id, name, kind, created_at)
        VALUES (@tenant_id, @id, @name, 'system', @created_at)
        ON CONFLICT (tenant_id) WHERE kind = 'system' DO NOTHING
        """;

    private const string InsertSecret =
        """
        INSERT INTO client_secret (tenant_id, id, application_id, secret_hash, created_at)
        VALUES (@tenant_id, @id, @application_id, @secret_hash, @created_at)
        """;

    // now() is the database's clock, so an expiry is judged the same way however the caller's clock runs.
    private const string LiveSecretHashes =
        """
        SELECT secret_hash FROM client_secret
        WHERE tenant_id = @tenant_id AND application_id = @application_id
          AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
        """;

    private readonly IAuditAppender _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    private readonly TimeProvider _time = time ?? throw new ArgumentNullException(nameof(time));

    public async Task<CreatedMachineClient> CreateMachineClientAsync(CommandContext context, string name, CancellationToken cancellationToken)
    {
        var (applicationId, clientId, secret) = await CreateClientAsync(context, name, InsertApplication, redirectUris: null, cancellationToken);
        return new CreatedMachineClient { ApplicationId = applicationId, ClientId = clientId, Secret = secret.Use(static value => new RevealOnce<string>(value)) };
    }

    public async Task<CreatedWebClient> CreateWebClientAsync(
        CommandContext context,
        string name,
        IReadOnlyList<string> redirectUris,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var checkedUris = RedirectUris.Checked(redirectUris);

        var (applicationId, clientId, secret) = await CreateClientAsync(context, name, InsertWebApplication, checkedUris, cancellationToken);
        return new CreatedWebClient { ApplicationId = applicationId, ClientId = clientId, Secret = secret.Use(static value => new RevealOnce<string>(value)) };
    }

    /// <summary>
    /// The one way an Application with a secret is written (Stories 2.5 and 2.9): its row, its first
    /// secret and its <c>directory.application.created</c> event, in the caller's context.
    /// </summary>
    private async Task<(Guid ApplicationId, string ClientId, Secret<string> Secret)> CreateClientAsync(
        CommandContext context,
        string name,
        string insert,
        string[]? redirectUris,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("An Application is created only in a Tenant context.");

        if (string.IsNullOrWhiteSpace(name) || name.Length > MaxNameLength || name.Contains('\0'))
        {
            throw new ArgumentException("An Application name is 1 to 200 characters, with no NUL character.", nameof(name));
        }

        var now = _time.GetUtcNow();
        var applicationId = Guid.CreateVersion7(now);
        var secret = ClientSecrets.Create(tenantId);

        await using (var command = context.CreateCommand())
        {
            command.CommandText = insert;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", applicationId);
            Add(command, "name", name);
            Add(command, "created_at", now);
            if (redirectUris is not null)
            {
                Add(command, "redirect_uris", redirectUris);
            }

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = InsertSecret;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", Guid.CreateVersion7(now));
            Add(command, "application_id", applicationId);
            Add(command, "secret_hash", secret.Use(ClientSecrets.Hash));
            Add(command, "created_at", now);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        // Only tests and the system path call this (Story 3.1's Admin create is CreateApplicationAsync): the System created it.
        await _audit.AppendAsync(
            context,
            new AuditEvent(DirectoryEvents.ApplicationCreated.Code, Actor.System, AuditTargetKind.Client, applicationId),
            detail: null,
            cancellationToken);

        return (
            applicationId,
            PublicId.Format(PublicIdType.Application, applicationId),
            secret);
    }

    public async Task<DirectoryApplication> CreateApplicationAsync(
        CommandContext context,
        Actor actor,
        string name,
        string kind,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(actor);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("An Application is created only in a Tenant context.");

        if (string.IsNullOrWhiteSpace(name) || name.Length > MaxNameLength || name.Any(char.IsControl))
        {
            throw new ArgumentException("An Application name is 1 to 200 characters, with no control character.", nameof(name));
        }

        string[] grantTypes = kind switch
        {
            DirectoryContract.MachineKind => ["client_credentials"],
            DirectoryContract.WebKind => ["authorization_code"],
            DirectoryContract.SpaKind or DirectoryContract.NativeKind => [],
            _ => throw new ArgumentException("An Admin creates only a spa, web, native or machine Application.", nameof(kind)),
        };

        var now = _time.GetUtcNow();
        var applicationId = Guid.CreateVersion7(now);

        await using (var command = context.CreateCommand())
        {
            command.CommandText = InsertAdminApplication;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", applicationId);
            Add(command, "name", name);
            Add(command, "kind", kind);
            Add(command, "grant_types", grantTypes);
            Add(command, "created_at", now);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await _audit.AppendAsync(
            context,
            new AuditEvent(DirectoryEvents.ApplicationCreated.Code, actor, AuditTargetKind.Client, applicationId),
            detail: null,
            cancellationToken);

        return new DirectoryApplication(
            applicationId,
            PublicId.Format(PublicIdType.Application, applicationId),
            name,
            kind,
            [.. grantTypes],
            [],
            [],
            [],
            [],
            now);
    }

    public Task<DirectoryApplicationPage> ListApplicationsPageAsync(
        CommandContext context,
        Guid? after,
        int limit,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        return ApplicationRows.ListPageAsync(context, after, limit, cancellationToken);
    }

    public Task<DirectoryApplication?> FindApplicationAsync(CommandContext context, Guid id, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        return ApplicationRows.FindAsync(context, id, cancellationToken);
    }

    public Task<DirectoryApplication?> LockApplicationAsync(CommandContext context, Guid id, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        return ApplicationRows.FindAsync(context, id, cancellationToken, locked: true);
    }

    public async Task<DirectoryApplication?> UpdateApplicationSettingsAsync(
        CommandContext context,
        Actor actor,
        Guid id,
        ApplicationSettings settings,
        bool prodCallbackAdded,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(settings);
        _ = context.TenantId ?? throw new InvalidOperationException("An Application is updated only in a Tenant context.");

        // The kind the rules are decided on, under the row's lock: the same row the update then writes.
        if (await ApplicationRows.FindAsync(context, id, cancellationToken, locked: true) is not { } current)
        {
            return null;
        }

        if (ApplicationSettingsRules.Check(current.Kind, settings).Count != 0)
        {
            throw new ArgumentException("The settings break a rule for the Application's type.", nameof(settings));
        }

        var updated = await ApplicationRows.UpdateSettingsAsync(context, id, settings, cancellationToken);
        if (updated is null)
        {
            return null;
        }

        await _audit.AppendAsync(
            context,
            new AuditEvent(DirectoryEvents.ApplicationUpdated.Code, actor, AuditTargetKind.Client, id),
            detail: null,
            cancellationToken);

        if (prodCallbackAdded)
        {
            await _audit.AppendAsync(
                context,
                new AuditEvent(DirectoryEvents.ApplicationProdCallbackAdded.Code, actor, AuditTargetKind.Client, id),
                detail: null,
                cancellationToken);
        }

        return updated;
    }

    public async Task<bool> VerifyClientSecretAsync(CommandContext context, string clientId, Secret<string> secret, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(secret);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("A client secret is verified only in a Tenant context.");

        // Hashed before the client_id is parsed, so every request pays for the hash; a malformed
        // client_id still returns before the lookup.
        var presented = secret.Use(ClientSecrets.Hash);
        if (!PublicId.TryParse(PublicIdType.Application, clientId, out var applicationId))
        {
            return false;
        }

        var stored = new List<byte[]>();
        await using (var command = context.CreateCommand())
        {
            command.CommandText = LiveSecretHashes;
            Add(command, "tenant_id", tenantId);
            Add(command, "application_id", applicationId);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                stored.Add(reader.GetFieldValue<byte[]>(0));
            }
        }

        // Every live secret is compared, matched or not, in constant time each.
        var matched = false;
        foreach (var hash in stored)
        {
            matched |= CryptographicOperations.FixedTimeEquals(hash, presented);
        }

        return matched;
    }

    public async Task<Guid> EnsureSystemApplicationAsync(CommandContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("The system Application is ensured only in a Tenant context.");

        if (await ApplicationRows.FindSystemAsync(context, cancellationToken) is { } existing)
        {
            return existing;
        }

        var now = _time.GetUtcNow();
        await using (var command = context.CreateCommand())
        {
            command.CommandText = InsertSystemApplication;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", Guid.CreateVersion7(now));
            Add(command, "name", DirectoryContract.SystemApplicationName);
            Add(command, "created_at", now);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        return await ApplicationRows.FindSystemAsync(context, cancellationToken)
            ?? throw new InvalidOperationException("The Tenant's system Application was neither inserted nor found.");
    }

    public Task<Guid?> FindSystemApplicationAsync(CommandContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        return ApplicationRows.FindSystemAsync(context, cancellationToken);
    }

    public Task<IReadOnlyList<DirectoryApplication>> ListApplicationsAsync(CommandContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        return ApplicationRows.ListAsync(context, cancellationToken);
    }

    internal static void Add(DbCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }
}

/// <summary>The client secret shape (AD-9, AD-24): <c>{tenantPublicId}.{base64url of 32 random bytes}</c>, stored as its SHA-256.</summary>
internal static class ClientSecrets
{
    public static Secret<string> Create(Guid tenantId)
    {
        var random = RandomNumberGenerator.GetBytes(32);
        try
        {
            return new Secret<string>(PublicId.Format(PublicIdType.Tenant, tenantId) + "." + Base64Url.EncodeToString(random));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(random);
        }
    }

    /// <summary>The SHA-256 of the whole secret's UTF-8 bytes, prefix included: all that is stored.</summary>
    public static byte[] Hash(string secret) => SHA256.HashData(Encoding.UTF8.GetBytes(secret));
}

/// <summary>
/// Reads Applications (AD-8). Every query that hands Applications to a caller, OpenIddict's store
/// included, holds to <see cref="Visible"/>, so the hidden <c>system</c> Application (AD-12, Story 2.8)
/// is an unknown <c>client_id</c> to OpenIddict and is never listed. Only <see cref="FindSystemAsync"/>
/// selects it, and returns only its ID.
/// </summary>
internal static class ApplicationRows
{
    /// <summary>The one predicate that hides the <c>system</c> Application from every caller-facing read.</summary>
    public const string Visible = "kind <> 'system'";

    private const string Columns = "id, name, kind, grant_types, audiences, redirect_uris, post_logout_redirect_uris, web_origins, created_at";

    private const string Select =
        $"SELECT {Columns} FROM application WHERE tenant_id = @tenant_id AND id = @id AND {Visible}";

    private const string List =
        $"SELECT {Columns} FROM application WHERE tenant_id = @tenant_id AND {Visible} ORDER BY created_at, id";

    // Story 3.1: newest first by the UUIDv7 ID, keyset after the previous page's last.
    private const string FirstPage =
        $"SELECT {Columns} FROM application WHERE tenant_id = @tenant_id AND {Visible} ORDER BY id DESC LIMIT @limit";

    private const string NextPage =
        $"SELECT {Columns} FROM application WHERE tenant_id = @tenant_id AND {Visible} AND id < @after ORDER BY id DESC LIMIT @limit";

    private const string SelectSystem =
        "SELECT id FROM application WHERE tenant_id = @tenant_id AND kind = 'system'";

    // Story 3.2: the settings save's lock. FOR NO KEY UPDATE, so no foreign-key insert waits on it.
    private const string SelectLocked = Select + " FOR NO KEY UPDATE";

    // Story 3.2: the four settings columns only, and never the system Application, which GK012 refuses too.
    private const string UpdateSettings =
        $"""
        UPDATE application
        SET redirect_uris = @redirect_uris, post_logout_redirect_uris = @post_logout_redirect_uris,
            web_origins = @web_origins, grant_types = @grant_types
        WHERE tenant_id = @tenant_id AND id = @id AND {Visible}
        RETURNING {Columns}
        """;

    public static async Task<DirectoryApplication?> FindAsync(CommandContext context, Guid id, CancellationToken cancellationToken, bool locked = false)
    {
        var tenantId = TenantOf(context);

        await using var command = context.CreateCommand();
        command.CommandText = locked ? SelectLocked : Select;
        DirectoryService.Add(command, "tenant_id", tenantId);
        DirectoryService.Add(command, "id", id);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? Read(reader) : null;
    }

    public static async Task<DirectoryApplication?> UpdateSettingsAsync(
        CommandContext context, Guid id, ApplicationSettings settings, CancellationToken cancellationToken)
    {
        var tenantId = TenantOf(context);

        await using var command = context.CreateCommand();
        command.CommandText = UpdateSettings;
        DirectoryService.Add(command, "tenant_id", tenantId);
        DirectoryService.Add(command, "id", id);
        DirectoryService.Add(command, "redirect_uris", settings.CallbackUrls.ToArray());
        DirectoryService.Add(command, "post_logout_redirect_uris", settings.LogoutUrls.ToArray());
        DirectoryService.Add(command, "web_origins", settings.WebOrigins.ToArray());
        DirectoryService.Add(command, "grant_types", ApplicationSettingsRules.Sorted(settings.GrantTypes));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? Read(reader) : null;
    }

    public static async Task<IReadOnlyList<DirectoryApplication>> ListAsync(CommandContext context, CancellationToken cancellationToken)
    {
        var tenantId = TenantOf(context);

        await using var command = context.CreateCommand();
        command.CommandText = List;
        DirectoryService.Add(command, "tenant_id", tenantId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var applications = new List<DirectoryApplication>();
        while (await reader.ReadAsync(cancellationToken))
        {
            applications.Add(Read(reader));
        }

        return applications;
    }

    public static async Task<DirectoryApplicationPage> ListPageAsync(CommandContext context, Guid? after, int limit, CancellationToken cancellationToken)
    {
        var tenantId = TenantOf(context);

        await using var command = context.CreateCommand();
        command.CommandText = after is null ? FirstPage : NextPage;
        DirectoryService.Add(command, "tenant_id", tenantId);
        if (after is { } cursor)
        {
            DirectoryService.Add(command, "after", cursor);
        }

        // One more than a page says whether another follows.
        DirectoryService.Add(command, "limit", limit + 1);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var applications = new List<DirectoryApplication>();
        while (await reader.ReadAsync(cancellationToken))
        {
            applications.Add(Read(reader));
        }

        if (applications.Count <= limit)
        {
            return new DirectoryApplicationPage(applications, null);
        }

        var page = applications.Take(limit).ToList();
        return new DirectoryApplicationPage(page, page[^1].Id);
    }

    public static async Task<Guid?> FindSystemAsync(CommandContext context, CancellationToken cancellationToken)
    {
        var tenantId = TenantOf(context);

        await using var command = context.CreateCommand();
        command.CommandText = SelectSystem;
        DirectoryService.Add(command, "tenant_id", tenantId);
        return await command.ExecuteScalarAsync(cancellationToken) is Guid id ? id : null;
    }

    private static Guid TenantOf(CommandContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.TenantId
            ?? throw new InvalidOperationException("Applications are read only in a Tenant context.");
    }

    private static DirectoryApplication Read(DbDataReader reader) =>
        new(
            reader.GetGuid(0),
            PublicId.Format(PublicIdType.Application, reader.GetGuid(0)),
            reader.GetString(1),
            reader.GetString(2),
            [.. reader.GetFieldValue<string[]>(3)],
            [.. reader.GetFieldValue<string[]>(4)],
            [.. reader.GetFieldValue<string[]>(5)],
            [.. reader.GetFieldValue<string[]>(6)],
            [.. reader.GetFieldValue<string[]>(7)],
            reader.GetFieldValue<DateTimeOffset>(8));
}
