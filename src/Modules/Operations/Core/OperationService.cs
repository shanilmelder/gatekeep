using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Operations.Contracts;
using Npgsql;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>
/// Starts, retries and reads Operations in the caller's context (AD-30). Start and retry
/// write the Operation, its steps and its run job in the caller's one transaction.
/// </summary>
internal sealed class OperationService(OperationRegistry registry) : IOperations
{
    private const string UniqueViolation = "23505";
    private const string ForeignKeyViolation = "23503";

    private const string Savepoint = "operation_start";

    private const string InsertOperation =
        """
        INSERT INTO operation (id, type, tenant_id, status)
        VALUES (@id, @type, @tenant_id, 'running')
        """;

    private const string InsertStep =
        """
        INSERT INTO operation_step (id, operation_id, position, tenant_id, stage, status)
        VALUES (@id, @operation_id, @position, @tenant_id, @stage, 'pending')
        """;

    // Retry locks the Operation's steps before the Operation, the order the Worker takes them in.
    private const string LockSteps = "SELECT id FROM operation_step WHERE operation_id = @id ORDER BY position FOR NO KEY UPDATE";

    private const string FindActiveForTenants =
        """
        SELECT tenant_id, id, status FROM operation
        WHERE type = @type AND tenant_id = ANY (@tenant_ids) AND status IN ('running', 'failed')
        """;

    private const string ReopenOperation =
        """
        UPDATE operation
        SET status = 'running', updated_at = now(), finished_at = NULL
        WHERE id = @id AND status = 'failed'
        """;

    private const string ReopenFailedSteps =
        """
        UPDATE operation_step
        SET status = 'pending', result_code = NULL, updated_at = now()
        WHERE operation_id = @id AND status = 'failed'
        """;

    private const string FindActive =
        """
        SELECT id FROM operation
        WHERE type = @type AND tenant_id IS NOT DISTINCT FROM @tenant_id::uuid AND status IN ('running', 'failed')
        """;

    private const string FindLatest =
        """
        SELECT id FROM operation
        WHERE type = @type AND tenant_id = @tenant_id
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """;

    private readonly OperationRegistry _registry = registry ?? throw new ArgumentNullException(nameof(registry));

    private readonly JobEnqueuer _enqueuer = new(ProductionJobs.Registry, custody: null);

    public async Task<OperationResource> StartAsync(
        CommandContext context,
        OperationType type,
        Guid? tenantId,
        IReadOnlyList<OperationStepPlan> steps,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(type);
        ArgumentNullException.ThrowIfNull(steps);
        RequireDeployment(context);

        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("A Tenant-scoped Operation needs a Tenant ID.", nameof(tenantId));
        }

        Validate(type, tenantId, steps);

        var id = Guid.CreateVersion7();

        // A refusal leaves the caller's transaction usable, with nothing of this Operation in it.
        await OperationStore.ExecuteAsync(context, $"SAVEPOINT {Savepoint}", cancellationToken);
        try
        {
            await using (var command = context.CreateCommand())
            {
                command.CommandText = InsertOperation;
                Sql.Add(command, "id", id);
                Sql.Add(command, "type", type.Value);
                Sql.Add(command, "tenant_id", tenantId);
                await command.ExecuteNonQueryAsync(cancellationToken);
            }

            for (var position = 0; position < steps.Count; position++)
            {
                await using var command = context.CreateCommand();
                command.CommandText = InsertStep;
                Sql.Add(command, "id", Guid.CreateVersion7());
                Sql.Add(command, "operation_id", id);
                Sql.Add(command, "position", position);
                Sql.Add(command, "tenant_id", steps[position].TenantId);
                Sql.Add(command, "stage", steps[position].Stage.Value);
                await command.ExecuteNonQueryAsync(cancellationToken);
            }
        }
        catch (PostgresException e)
        {
            await OperationStore.ExecuteAsync(context, $"ROLLBACK TO SAVEPOINT {Savepoint}", cancellationToken);

            if (e.SqlState == UniqueViolation && e.ConstraintName == OperationStore.ActiveIndex)
            {
                throw new OperationAlreadyActiveException(type, tenantId);
            }

            if (e.SqlState == ForeignKeyViolation)
            {
                throw new ArgumentException("The Operation or a step names a Tenant that doesn't exist.", nameof(tenantId));
            }

            throw;
        }

        await OperationStore.ExecuteAsync(context, $"RELEASE SAVEPOINT {Savepoint}", cancellationToken);

        await _enqueuer.EnqueueAsync(context, ProductionJobs.RunOperation, id, runAfter: null, cancellationToken);

        return (await OperationStore.ReadAsync(context, id, stepTenantId: null, cancellationToken))!;
    }

    public async Task<OperationResource> RetryAsync(CommandContext context, Guid operationId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        RequireDeployment(context);

        await using (var command = context.CreateCommand())
        {
            command.CommandText = LockSteps;
            Sql.Add(command, "id", operationId);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = ReopenOperation;
            Sql.Add(command, "id", operationId);

            if (await command.ExecuteNonQueryAsync(cancellationToken) == 0)
            {
                throw new OperationNotFailedException(operationId);
            }
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = ReopenFailedSteps;
            Sql.Add(command, "id", operationId);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await _enqueuer.EnqueueAsync(context, ProductionJobs.RunOperation, operationId, runAfter: null, cancellationToken);

        return (await OperationStore.ReadAsync(context, operationId, stepTenantId: null, cancellationToken))!;
    }

    public Task<OperationResource?> GetAsync(CommandContext context, Guid operationId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Every Tenant's steps: never on a Tenant's path. That's GetForTenantAsync.
        RequireDeployment(context);
        return OperationStore.ReadAsync(context, operationId, stepTenantId: null, cancellationToken);
    }

    public async Task<OperationResource?> FindActiveAsync(
        CommandContext context,
        OperationType type,
        Guid? tenantId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(type);
        RequireDeployment(context);

        Guid id;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = FindActive;
            Sql.Add(command, "type", type.Value);
            Sql.Add(command, "tenant_id", tenantId);

            if (await command.ExecuteScalarAsync(cancellationToken) is not Guid found)
            {
                return null;
            }

            id = found;
        }

        return await OperationStore.ReadAsync(context, id, stepTenantId: null, cancellationToken);
    }

    public async Task<OperationResource?> FindLatestAsync(
        CommandContext context,
        OperationType type,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(type);
        RequireDeployment(context);

        Guid id;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = FindLatest;
            Sql.Add(command, "type", type.Value);
            Sql.Add(command, "tenant_id", tenantId);

            if (await command.ExecuteScalarAsync(cancellationToken) is not Guid found)
            {
                return null;
            }

            id = found;
        }

        return await OperationStore.ReadAsync(context, id, stepTenantId: null, cancellationToken);
    }

    public async Task<IReadOnlyDictionary<Guid, (Guid OperationId, OperationStatus Status)>> FindActiveForTenantsAsync(
        CommandContext context,
        OperationType type,
        IReadOnlyCollection<Guid> tenantIds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(type);
        ArgumentNullException.ThrowIfNull(tenantIds);
        RequireDeployment(context);

        var found = new Dictionary<Guid, (Guid, OperationStatus)>();
        if (tenantIds.Count == 0)
        {
            return found;
        }

        await using var command = context.CreateCommand();
        command.CommandText = FindActiveForTenants;
        Sql.Add(command, "type", type.Value);
        Sql.Add(command, "tenant_ids", tenantIds.ToArray());

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            found[reader.GetGuid(0)] = (reader.GetGuid(1), reader.GetString(2) == "failed" ? OperationStatus.Failed : OperationStatus.Running);
        }

        return found;
    }

    public async Task<OperationResource?> GetForTenantAsync(
        CommandContext context,
        Guid operationId,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("A Tenant read needs a Tenant ID.", nameof(tenantId));
        }

        if (context.TenantId is { } scoped && scoped != tenantId)
        {
            throw new ArgumentException("A Tenant read in a Tenant's context reads that Tenant only.", nameof(tenantId));
        }

        var operation = await OperationStore.ReadAsync(context, operationId, tenantId, cancellationToken);

        return operation switch
        {
            null => null,
            { TenantId: { } owner } when owner != tenantId => null,
            { TenantId: null, Steps.Count: 0 } => null,
            _ => operation,
        };
    }

    private static void RequireDeployment(CommandContext context)
    {
        if (context.TenantId is not null)
        {
            throw new InvalidOperationException("An Operation is started, retried and read whole only in a Deployment context.");
        }
    }

    private void Validate(OperationType type, Guid? tenantId, IReadOnlyList<OperationStepPlan> steps)
    {
        var definition = _registry.Find(type)
            ?? throw new ArgumentException($"Operation type {type} isn't in the registry.", nameof(type));

        // Its completion handler runs only in its own Tenant's scope (Story 1.27): refused here, so it
        // never throws on a success instead.
        if (definition.OnSucceeded is not null
            && (tenantId is null || steps.Any(s => s?.TenantId is not { } step || step != tenantId)))
        {
            throw new ArgumentException($"Operation type {type} has a completion handler, so it is scoped to one Tenant and every step is for it.", nameof(tenantId));
        }

        if (steps.Count == 0)
        {
            throw new ArgumentException("An Operation plans at least one step.", nameof(steps));
        }

        var seen = new HashSet<(string, Guid?)>();

        foreach (var step in steps)
        {
            ArgumentNullException.ThrowIfNull(step, nameof(steps));
            ArgumentNullException.ThrowIfNull(step.Stage, nameof(steps));

            var stage = definition.Find(step.Stage)
                ?? throw new ArgumentException($"Stage {step.Stage} isn't a stage of {type}.", nameof(steps));

            if (stage.Kind == OperationStageKind.Tenant && (step.TenantId is null || step.TenantId == Guid.Empty))
            {
                throw new ArgumentException($"Tenant stage {step.Stage} needs a Tenant.", nameof(steps));
            }

            if (stage.Kind == OperationStageKind.Deployment && step.TenantId is not null)
            {
                throw new ArgumentException($"Deployment stage {step.Stage} takes no Tenant.", nameof(steps));
            }

            if (tenantId is not null && step.TenantId is not null && step.TenantId != tenantId)
            {
                throw new ArgumentException("A Tenant-scoped Operation's steps are for its own Tenant only.", nameof(steps));
            }

            if (!seen.Add((step.Stage.Value, step.TenantId)))
            {
                throw new ArgumentException($"Stage {step.Stage} is planned twice for the same Tenant.", nameof(steps));
            }
        }
    }
}
