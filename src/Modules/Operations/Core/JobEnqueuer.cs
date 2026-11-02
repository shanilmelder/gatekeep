using System.Text.Json;
using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Operations.Contracts;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>
/// Writes a job, and a Tenant job's payload, through the caller's context. Everything
/// the registry decides in code is checked before the first insert; the database's
/// guard checks the Tenant and the enqueuing role again.
/// </summary>
internal sealed class JobEnqueuer(JobRegistry registry, IKeyCustody? custody) : IJobEnqueuer
{
    private const string InsertTenantJob =
        """
        INSERT INTO job (id, type, tenant_id, deployment_wide, run_after)
        VALUES (@id, @type, @tenant_id, false, @run_after)
        """;

    private const string InsertDeploymentJob =
        """
        INSERT INTO job (id, type, deployment_wide, operation_id, run_after)
        VALUES (@id, @type, true, @operation_id, @run_after)
        """;

    private const string InsertPayload =
        """
        INSERT INTO job_payload (tenant_id, job_id, ids, ciphertext)
        VALUES (@tenant_id, @job_id, @ids::jsonb, @ciphertext)
        """;

    /// <summary>The <c>job_payload.ciphertext</c> CHECK's limit.</summary>
    private const int MaxCiphertextLength = 8192;

    private readonly JobRegistry _registry = registry ?? throw new ArgumentNullException(nameof(registry));

    public async Task<Guid> EnqueueAsync(
        CommandContext context,
        JobType type,
        JobPayload? payload,
        DateTimeOffset? runAfter,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(type);

        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("A Tenant job is enqueued only in a Tenant's scope.");

        var definition = Definition(type, JobScope.Tenant);

        if (payload?.Credential is not null && !definition.MayCarryCredential)
        {
            throw new ArgumentException($"Job type {type} carries IDs only, not a credential.", nameof(payload));
        }

        if (payload?.Credential is not null && custody is null)
        {
            throw new InvalidOperationException("No key custody is wired to encrypt a job credential.");
        }

        // Encrypted before any insert, so a custody failure leaves nothing behind.
        KeyCiphertext? ciphertext = null;
        if (payload?.Credential is { } credential)
        {
            ciphertext = await custody!.EncryptAsync(
                KeyName.ForTenant(TenantKeyClass.Payload, tenantId),
                tenantId,
                credential,
                cancellationToken);
        }

        // The schema's CHECK would abort the caller's whole transaction instead.
        if (ciphertext is not null && ciphertext.Value.Length > MaxCiphertextLength)
        {
            throw new ArgumentException($"A job credential's ciphertext is at most {MaxCiphertextLength} characters.", nameof(payload));
        }

        var id = Guid.CreateVersion7();

        await using (var command = context.CreateCommand())
        {
            command.CommandText = InsertTenantJob;
            Sql.Add(command, "id", id);
            Sql.Add(command, "type", type.Value);
            Sql.Add(command, "tenant_id", tenantId);
            Sql.Add(command, "run_after", Utc(runAfter));
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        if (payload is null)
        {
            return id;
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = InsertPayload;
            Sql.Add(command, "tenant_id", tenantId);
            Sql.Add(command, "job_id", id);
            Sql.Add(command, "ids", JsonSerializer.Serialize(payload.Ids.ToDictionary(p => p.Key, p => p.Value.ToString("D"))));
            Sql.Add(command, "ciphertext", ciphertext?.Value);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        return id;
    }

    public async Task<Guid> EnqueueAsync(
        CommandContext context,
        JobType type,
        Guid? operationId,
        DateTimeOffset? runAfter,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(type);

        if (context.TenantId is not null)
        {
            throw new InvalidOperationException("A Deployment-wide job is enqueued only in a Deployment scope.");
        }

        if (operationId == Guid.Empty)
        {
            throw new ArgumentException("An Operation ID can't be empty.", nameof(operationId));
        }

        Definition(type, JobScope.DeploymentWide);

        var id = Guid.CreateVersion7();

        await using var command = context.CreateCommand();
        command.CommandText = InsertDeploymentJob;
        Sql.Add(command, "id", id);
        Sql.Add(command, "type", type.Value);
        Sql.Add(command, "operation_id", operationId);
        Sql.Add(command, "run_after", Utc(runAfter));
        await command.ExecuteNonQueryAsync(cancellationToken);

        return id;
    }

    /// <summary>Npgsql writes <c>timestamptz</c> only from a UTC offset.</summary>
    private static DateTimeOffset? Utc(DateTimeOffset? value) => value?.ToUniversalTime();

    private JobDefinition Definition(JobType type, JobScope scope)
    {
        var definition = _registry.Find(type)
            ?? throw new ArgumentException($"Job type {type} isn't in the registry.", nameof(type));

        if (definition.Scope != scope)
        {
            throw new ArgumentException($"Job type {type} isn't a {scope} type.", nameof(type));
        }

        return definition;
    }
}
