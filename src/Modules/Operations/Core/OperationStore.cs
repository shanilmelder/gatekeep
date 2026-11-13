using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Operations.Contracts;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>
/// What Operations' own job handlers need beyond the context: the run-as database, the Operation
/// registry, the runner's key custody for stage handlers, null when the Worker has none, and the
/// runner's logger, for a handler that reports a failure it doesn't throw (Story 2.3).
/// </summary>
internal sealed record JobRunServices(NpgsqlDataSource Source, OperationRegistry Operations, IKeyCustody? Custody = null, ILogger? Logger = null)
{
    public override string ToString() => nameof(JobRunServices);
}

/// <summary>The production Operation types (AD-30).</summary>
internal static class ProductionOperations
{
    /// <summary>
    /// <c>audit.chain.purge</c> deletes a deleted Tenant's audit chain once its retention ends
    /// (AD-16). Its one Tenant stage enqueues the <c>audit.chain.purge</c> job, which runs as
    /// <c>gk_retention</c>. It has no production caller: a deletion's completion enqueues the same
    /// job itself, from the Tenant's scope.
    /// <c>tenancy.tenant.create</c> (Story 1.27) creates a new Tenant's secret class keys, then, on
    /// success, its settings, and makes it active. <c>tenancy.tenant.delete</c> (Story 1.29) purges
    /// a deleting Tenant's data and destroys its keys, then, on success, marks it deleted.
    /// <c>directory.application.purge</c> (Story 3.5) removes the rows of a Tenant's deleted Applications from each owning module.
    /// </summary>
    public static readonly OperationRegistry Registry = new(
    [
        new OperationDefinition(
            AuditRetentionJobs.PurgeOperation,
            [new OperationStage(AuditRetentionJobs.PurgeStage, OperationStageKind.Tenant, AuditRetentionJobs.PurgeStageAsync)]),
        TenantCreation.Definition,
        TenantDeletion.Definition,
        ApplicationPurge.Definition,
    ]);
}

/// <summary>The SQL on <c>operation</c> and <c>operation_step</c>, both <c>control</c> tables.</summary>
internal static class OperationStore
{
    public const string ActiveIndex = "operation_one_active";

    private const string Savepoint = "operation_step_savepoint";

    private const string SelectOperation =
        """
        SELECT id, type, tenant_id, status, created_at, updated_at, finished_at
        FROM operation WHERE id = @id
        """;

    private const string SelectSteps =
        """
        SELECT id, stage, tenant_id, status, result_code, attempts, updated_at
        FROM operation_step
        WHERE operation_id = @id AND (@tenant_id::uuid IS NULL OR tenant_id = @tenant_id)
        ORDER BY position
        """;

    // NO KEY UPDATE, not UPDATE: with FOR UPDATE, two steps finishing together were observed to
    // deadlock (40P01) on this row in the concurrent-finish test. Two finishers still exclude each other.
    private const string LockOperation = "SELECT status FROM operation WHERE id = @id FOR NO KEY UPDATE";

    // Run after the lock, as its own statement. It relies on READ COMMITTED: its snapshot is taken
    // after the lock was granted, so it sees every step committed before then.
    private const string FinishOperation =
        """
        UPDATE operation
        SET status = CASE WHEN EXISTS (SELECT 1 FROM operation_step WHERE operation_id = @id AND status = 'failed')
                          THEN 'failed' ELSE 'succeeded' END,
            updated_at = now(), finished_at = now()
        WHERE id = @id AND status = 'running'
          AND NOT EXISTS (SELECT 1 FROM operation_step WHERE operation_id = @id AND status IN ('pending', 'running'))
        RETURNING status, type, tenant_id
        """;

    private const string StartStep =
        """
        UPDATE operation_step
        SET status = 'running', attempts = attempts + 1, updated_at = now()
        WHERE id = @id AND status IN ('pending', 'running')
        RETURNING attempts
        """;

    private const string RecordStep =
        """
        UPDATE operation_step
        SET status = @status, result_code = @result_code, updated_at = now()
        WHERE id = @id
        """;

    public static async Task<OperationResource?> ReadAsync(
        CommandContext context,
        Guid operationId,
        Guid? stepTenantId,
        CancellationToken cancellationToken)
    {
        OperationResource? operation = null;

        await using (var command = context.CreateCommand())
        {
            command.CommandText = SelectOperation;
            Sql.Add(command, "id", operationId);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return null;
            }

            operation = new OperationResource(
                reader.GetGuid(0),
                new OperationType(reader.GetString(1)),
                reader.IsDBNull(2) ? null : reader.GetGuid(2),
                ParseOperationStatus(reader.GetString(3)),
                reader.GetFieldValue<DateTimeOffset>(4),
                reader.GetFieldValue<DateTimeOffset>(5),
                reader.IsDBNull(6) ? null : reader.GetFieldValue<DateTimeOffset>(6),
                []);
        }

        var steps = new List<OperationStepResource>();

        await using (var command = context.CreateCommand())
        {
            command.CommandText = SelectSteps;
            Sql.Add(command, "id", operationId);
            Sql.Add(command, "tenant_id", stepTenantId);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                steps.Add(new OperationStepResource(
                    reader.GetGuid(0),
                    new OperationCode(reader.GetString(1)),
                    reader.IsDBNull(2) ? null : reader.GetGuid(2),
                    ParseStepStatus(reader.GetString(3)),
                    reader.IsDBNull(4) ? null : new OperationCode(reader.GetString(4)),
                    reader.GetInt32(5),
                    reader.GetFieldValue<DateTimeOffset>(6)));
            }
        }

        return operation with { Steps = steps };
    }

    /// <summary>
    /// Sets the Operation's final status once no step is pending or running. Whichever step
    /// finishes last does it, under a row lock on the Operation, so two finishing together
    /// can't both miss it, and only one ever makes the transition. When it is <c>succeeded</c> and
    /// the type has a completion handler (Story 1.27), the handler runs here, in this same
    /// transaction, so it commits with the success or neither does.
    /// </summary>
    /// <returns>The status this call set, or null when it set none.</returns>
    /// <exception cref="InvalidOperationException">
    /// A completion handler would run for a Deployment Operation, or outside its Tenant's own scope.
    /// </exception>
    public static async Task<OperationStatus?> TryFinishAsync(
        CommandContext context,
        OperationRegistry registry,
        Guid operationId,
        CancellationToken cancellationToken)
    {
        await using (var command = context.CreateCommand())
        {
            command.CommandText = LockOperation;
            Sql.Add(command, "id", operationId);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        OperationStatus status;
        string type;
        Guid? tenantId;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = FinishOperation;
            Sql.Add(command, "id", operationId);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return null;
            }

            status = ParseOperationStatus(reader.GetString(0));
            type = reader.GetString(1);
            tenantId = reader.IsDBNull(2) ? null : reader.GetGuid(2);
        }

        if (status == OperationStatus.Succeeded && registry.Find(type)?.OnSucceeded is { } onSucceeded)
        {
            if (tenantId is not { } tenant || context.TenantId != tenant)
            {
                throw new InvalidOperationException("A completion handler runs only for a Tenant-scoped Operation, in that Tenant's own scope.");
            }

            await onSucceeded(new OperationCompletion(operationId, tenant, context), cancellationToken);
        }

        return status;
    }

    /// <summary>
    /// Marks the step running, runs its handler and records the result, in the context's
    /// transaction. A throwing handler's writes are undone to a savepoint, and only a fixed
    /// code is recorded: nothing from the exception is kept. A step no longer pending or running
    /// is left alone.
    /// </summary>
    public static async Task RunStepAsync(
        CommandContext context,
        OperationRegistry registry,
        Guid operationId,
        Guid stepId,
        OperationType type,
        OperationCode stage,
        Guid? tenantId,
        IKeyCustody? custody,
        CancellationToken cancellationToken)
    {
        int attempt;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = StartStep;
            Sql.Add(command, "id", stepId);

            if (await command.ExecuteScalarAsync(cancellationToken) is not int started)
            {
                return;
            }

            attempt = started;
        }

        var expected = tenantId is null ? OperationStageKind.Deployment : OperationStageKind.Tenant;
        var handler = registry.Find(type)?.Find(stage) is { } found && found.Kind == expected ? found.Handler : null;

        OperationStepResult result;
        if (handler is null)
        {
            result = OperationStepResult.Failure(OperationResultCodes.UnknownStage);
        }
        else
        {
            await ExecuteAsync(context, $"SAVEPOINT {Savepoint}", cancellationToken);

            OperationStepResult? returned;
            try
            {
                var run = new OperationStepRun(operationId, stepId, type, stage, tenantId, attempt, context, custody);
                returned = await handler(run, cancellationToken);
            }
            catch (Exception) when (!cancellationToken.IsCancellationRequested)
            {
                // Nothing from the exception is kept. Stopping or out of lease escapes instead:
                // the job runs again, and so does this step.
                returned = null;
            }

            if (returned is null)
            {
                await ExecuteAsync(context, $"ROLLBACK TO SAVEPOINT {Savepoint}", cancellationToken);
                result = OperationStepResult.Failure(OperationResultCodes.HandlerFailed);
            }
            else
            {
                await ExecuteAsync(context, $"RELEASE SAVEPOINT {Savepoint}", cancellationToken);
                result = returned;
            }
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = RecordStep;
            Sql.Add(command, "id", stepId);
            Sql.Add(command, "status", result.Succeeded ? "succeeded" : "failed");
            Sql.Add(command, "result_code", result.Code.Value);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    public static async Task ExecuteAsync(CommandContext context, string sql, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static OperationStatus ParseOperationStatus(string status) => status switch
    {
        "running" => OperationStatus.Running,
        "failed" => OperationStatus.Failed,
        "succeeded" => OperationStatus.Succeeded,
        _ => throw new InvalidOperationException("Unknown Operation status."),
    };

    private static OperationStepStatus ParseStepStatus(string status) => status switch
    {
        "pending" => OperationStepStatus.Pending,
        "running" => OperationStepStatus.Running,
        "succeeded" => OperationStepStatus.Succeeded,
        "failed" => OperationStepStatus.Failed,
        _ => throw new InvalidOperationException("Unknown Operation step status."),
    };
}
