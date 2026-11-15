using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Notifications.Contracts;

namespace Gatekeep.Modules.Notifications.Core;

/// <summary>
/// The SQL on <c>email_provider</c> (Story 4.4, AD-10): one row per Tenant, its secret only as Transit ciphertext under
/// the Tenant's <c>email-</c> key. Host.Admin writes it and reads every column but the ciphertext; only Host.Worker reads
/// that, to send (Story 4.5), and deletes the row in a Tenant's purge.
/// </summary>
internal static partial class EmailProviderStore
{
    /// <summary>The first key of every Notifications advisory lock, so no other advisory lock can collide with one.</summary>
    private const int LockNamespace = 0x4E544659;

    // Two saves of one Tenant wait for each other, so each decides on the row the other left.
    private const string Lock = "SELECT pg_advisory_xact_lock(@namespace, hashtext(@tenant_id::text))";

    // Every column but the ciphertext, which gk_admin may not read: an SMTP provider with no username has no secret,
    // and every other has one, as the table's CHECK holds it.
    private const string Select =
        """
        SELECT kind, settings::text, from_address, from_name, updated_at
        FROM email_provider WHERE tenant_id = @tenant_id
        """;

    private const string Insert =
        """
        INSERT INTO email_provider (tenant_id, kind, settings, from_address, from_name, secret_ciphertext, updated_at)
        VALUES (@tenant_id, @kind, CAST(@settings AS jsonb), @from_address, @from_name, @secret_ciphertext, now())
        RETURNING updated_at
        """;

    private const string UpdateKeepingSecret =
        """
        UPDATE email_provider
        SET kind = @kind, settings = CAST(@settings AS jsonb), from_address = @from_address, from_name = @from_name, updated_at = now()
        WHERE tenant_id = @tenant_id
        RETURNING updated_at
        """;

    private const string UpdateWithSecret =
        """
        UPDATE email_provider
        SET kind = @kind, settings = CAST(@settings AS jsonb), from_address = @from_address, from_name = @from_name,
            secret_ciphertext = @secret_ciphertext, updated_at = now()
        WHERE tenant_id = @tenant_id
        RETURNING updated_at
        """;

    // Host.Worker only: gk_admin may not read the ciphertext.
    private const string SelectForSend =
        """
        SELECT kind, settings::text, from_address, from_name, updated_at, secret_ciphertext
        FROM email_provider WHERE tenant_id = @tenant_id
        """;

    internal const string Delete = "DELETE FROM email_provider WHERE tenant_id = @tenant_id";

    public static async Task<EmailProviderConfiguration?> ReadAsync(CommandContext context, CancellationToken cancellationToken)
    {
        var tenantId = RequireTenant(context);
        return await SelectAsync(context, tenantId, cancellationToken);
    }

    /// <summary>The provider with its secret's ciphertext, as Host.Worker reads it to send (Story 4.5); null when there is none.</summary>
    public static async Task<EmailDelivery?> ReadForSendAsync(CommandContext context, CancellationToken cancellationToken)
    {
        var tenantId = RequireTenant(context);

        await using var command = context.CreateCommand();
        command.CommandText = SelectForSend;
        Add(command, "tenant_id", tenantId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var kind = reader.GetString(0);
        var settings = EmailProviderRules.Parse(reader.GetString(1));
        var provider = new EmailProviderConfiguration(
            kind,
            settings,
            reader.GetString(2),
            reader.IsDBNull(3) ? null : reader.GetString(3),
            reader.GetFieldValue<DateTimeOffset>(4),
            EmailProviderRules.UsesSecret(kind, settings));
        return new EmailDelivery(provider, reader.IsDBNull(5) ? null : reader.GetString(5));
    }

    public static async Task<EmailProviderSave> SaveAsync(
        CommandContext context,
        IKeyCustody? custody,
        IAuditAppender appender,
        Actor actor,
        EmailProviderInput input,
        CancellationToken cancellationToken)
    {
        var tenantId = RequireTenant(context);
        ArgumentNullException.ThrowIfNull(appender);
        ArgumentNullException.ThrowIfNull(actor);

        var errors = EmailProviderRules.Validate(input, out var valid);
        if (valid is null)
        {
            return new EmailProviderSave(EmailProviderSaveStatus.Invalid, null, errors);
        }

        await LockAsync(context, tenantId, cancellationToken);

        var stored = await SelectAsync(context, tenantId, cancellationToken);

        // A secret is needed unless the stored one is kept for exactly the destination it was given for: a first save, a
        // change of kind, SMTP gaining a username, or any change of settings but Postmark's message stream needs a new one,
        // so a stored secret can never be sent somewhere else.
        if (valid.UsesSecret && valid.Secret is null
            && (stored is null || stored.Kind != valid.Kind || !stored.SecretSet || !SameDestination(stored.Settings, valid.Settings)))
        {
            return new EmailProviderSave(EmailProviderSaveStatus.Invalid, null, [new(EmailProviderFields.Secret, EmailProviderReasons.Required)]);
        }

        var clearsSecret = !valid.UsesSecret && stored is { SecretSet: true };
        if (stored is not null && valid.Secret is null && !clearsSecret
            && stored.Kind == valid.Kind && stored.Settings == valid.Settings
            && stored.FromAddress == valid.FromAddress && stored.FromName == valid.FromName)
        {
            return new EmailProviderSave(EmailProviderSaveStatus.Unchanged, stored, []);
        }

        // Encrypted before anything is written, so a custody failure leaves nothing behind.
        string? ciphertext = null;
        if (valid.Secret is { } secret)
        {
            if (custody is null)
            {
                return new EmailProviderSave(EmailProviderSaveStatus.Unavailable, null, []);
            }

            ciphertext = await EncryptAsync(custody, tenantId, secret, cancellationToken);
            if (ciphertext is null)
            {
                return new EmailProviderSave(EmailProviderSaveStatus.Unavailable, null, []);
            }
        }

        DateTimeOffset updatedAt;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = stored is null ? Insert : ciphertext is not null || clearsSecret ? UpdateWithSecret : UpdateKeepingSecret;
            Add(command, "tenant_id", tenantId);
            Add(command, "kind", valid.Kind);
            Add(command, "settings", EmailProviderRules.Json(valid.Settings));
            Add(command, "from_address", valid.FromAddress);
            Add(command, "from_name", valid.FromName);
            if (stored is null || ciphertext is not null || clearsSecret)
            {
                Add(command, "secret_ciphertext", ciphertext);
            }

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                throw new InvalidOperationException("The email provider row wasn't written.");
            }

            updatedAt = reader.GetFieldValue<DateTimeOffset>(0);
        }

        await appender.AppendAsync(
            context,
            new AuditEvent(NotificationsEvents.EmailProviderUpdated.Code, actor, AuditTargetKind.Tenant, tenantId),
            detail: null,
            cancellationToken);

        return new EmailProviderSave(
            EmailProviderSaveStatus.Saved,
            new EmailProviderConfiguration(valid.Kind, valid.Settings, valid.FromAddress, valid.FromName, updatedAt, valid.UsesSecret),
            []);
    }

    public static async Task<bool> RemoveAsync(CommandContext context, IAuditAppender appender, Actor actor, CancellationToken cancellationToken)
    {
        var tenantId = RequireTenant(context);
        ArgumentNullException.ThrowIfNull(appender);
        ArgumentNullException.ThrowIfNull(actor);

        // As a save takes it, so a removal never lands between a save's read and its write.
        await LockAsync(context, tenantId, cancellationToken);

        int deleted;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = Delete;
            Add(command, "tenant_id", tenantId);
            deleted = await command.ExecuteNonQueryAsync(cancellationToken);
        }

        if (deleted == 0)
        {
            return false;
        }

        await appender.AppendAsync(
            context,
            new AuditEvent(NotificationsEvents.EmailProviderRemoved.Code, actor, AuditTargetKind.Tenant, tenantId),
            detail: null,
            cancellationToken);
        return true;
    }

    /// <summary>Saves and removals of one Tenant wait for each other, so each decides on the row the other left.</summary>
    private static async Task LockAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = Lock;
        Add(command, "namespace", LockNamespace);
        Add(command, "tenant_id", tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <summary>Whether two settings send to the same place with the same credential: equal but for Postmark's message stream.</summary>
    private static bool SameDestination(EmailProviderSettings stored, EmailProviderSettings saved) =>
        stored with { MessageStream = null } == saved with { MessageStream = null };

    /// <summary>The secret as Transit ciphertext under the Tenant's email key, bound to its ID; null when custody fails or answers oddly.</summary>
    private static async Task<string?> EncryptAsync(IKeyCustody custody, Guid tenantId, Secret<string> secret, CancellationToken cancellationToken)
    {
        var bytes = secret.Use(Encoding.UTF8.GetBytes);
        try
        {
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            limit.CancelAfter(SecurityLimits.KeyCustodyCallTimeout);
            var ciphertext = await custody
                .EncryptAsync(KeyName.ForTenant(TenantKeyClass.Email, tenantId), tenantId, new Secret<byte[]>(bytes), limit.Token)
                .WaitAsync(limit.Token);

            // The table's CHECK would abort the caller's whole transaction instead.
            return ciphertext.Value.Length <= SecurityLimits.MaxEmailProviderCiphertextLength && CiphertextPattern().IsMatch(ciphertext.Value)
                ? ciphertext.Value
                : null;
        }
        catch (KeyCustodyException)
        {
            return null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // The bound, not the caller: custody didn't answer in time.
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static async Task<EmailProviderConfiguration?> SelectAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = Select;
        Add(command, "tenant_id", tenantId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var kind = reader.GetString(0);
        var settings = EmailProviderRules.Parse(reader.GetString(1));
        return new EmailProviderConfiguration(
            kind,
            settings,
            reader.GetString(2),
            reader.IsDBNull(3) ? null : reader.GetString(3),
            reader.GetFieldValue<DateTimeOffset>(4),
            EmailProviderRules.UsesSecret(kind, settings));
    }

    private static Guid RequireTenant(CommandContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.TenantId is { } tenantId && tenantId != Guid.Empty
            ? tenantId
            : throw new InvalidOperationException("A Tenant's email provider is read and written in that Tenant's own scope.");
    }

    internal static void Add(DbCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }

    [GeneratedRegex(@"\Avault:v[0-9]+:[A-Za-z0-9+/=]+\z", RegexOptions.CultureInvariant)]
    private static partial Regex CiphertextPattern();
}
