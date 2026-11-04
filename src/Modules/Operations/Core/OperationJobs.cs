using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Operations.Contracts;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>
/// The two Operation job handlers (AD-30). <c>operations.operation.run</c> is Deployment-wide:
/// in its own scope it touches only <c>operation</c> and <c>operation_step</c>, runs the
/// Deployment steps, and fans each pending Tenant step out into one
/// <c>operations.operation.step</c> job, enqueued in that Tenant's own scope. Both are
/// idempotent: a step runs only while it's pending or running.
/// </summary>
internal static class OperationJobs
{
    public const string OperationIdName = "operation_id";
    public const string StepIdName = "step_id";

    private const string SelectRunning = "SELECT type FROM operation WHERE id = @id AND status = 'running'";

    private const string SelectPendingTenantSteps =
        """
        SELECT id, tenant_id FROM operation_step
        WHERE operation_id = @id AND tenant_id IS NOT NULL AND status = 'pending'
        ORDER BY position
        """;

    private const string SelectDeploymentSteps =
        """
        SELECT id, stage FROM operation_step
        WHERE operation_id = @id AND tenant_id IS NULL AND status IN ('pending', 'running')
        ORDER BY position
        FOR UPDATE SKIP LOCKED
        """;

    private const string DispatchTenantStep =
        """
        UPDATE operation_step
        SET status = 'running', updated_at = now()
        WHERE id = @id AND operation_id = @operation_id AND tenant_id = @tenant_id AND status = 'pending'
        """;

    private const string SelectStepForTenant =
        """
        SELECT o.type, s.stage
        FROM operation_step s
        JOIN operation o ON o.id = s.operation_id
        WHERE s.id = @id AND s.operation_id = @operation_id AND s.tenant_id = @tenant_id
          AND s.status IN ('pending', 'running') AND o.status = 'running'
        FOR UPDATE OF s
        """;

    // Built on use: the production registry names these handlers, so it can't be read while it's being built.
    private static JobEnqueuer Enqueuer => new(ProductionJobs.Registry, custody: null);

    public static async Task RunAsync(JobRun run, CancellationToken cancellationToken)
    {
        // A malformed job fails with a fixed code rather than finishing done.
        var operationId = run.OperationId
            ?? throw new InvalidOperationException("An Operation run job carries an Operation ID.");

        var context = run.Context;

        OperationType type;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = SelectRunning;
            Sql.Add(command, "id", operationId);

            // Finished, or not an Operation: nothing to do, which keeps a rerun harmless.
            if (await command.ExecuteScalarAsync(cancellationToken) is not string value)
            {
                return;
            }

            type = new OperationType(value);
        }

        var tenantSteps = new List<(Guid Id, Guid TenantId)>();
        await using (var command = context.CreateCommand())
        {
            command.CommandText = SelectPendingTenantSteps;
            Sql.Add(command, "id", operationId);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                tenantSteps.Add((reader.GetGuid(0), reader.GetGuid(1)));
            }
        }

        foreach (var (stepId, tenantId) in tenantSteps)
        {
            await DispatchAsync(run.Services, operationId, stepId, tenantId, cancellationToken);
        }

        var deploymentSteps = new List<(Guid Id, OperationCode Stage)>();
        await using (var command = context.CreateCommand())
        {
            command.CommandText = SelectDeploymentSteps;
            Sql.Add(command, "id", operationId);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                deploymentSteps.Add((reader.GetGuid(0), new OperationCode(reader.GetString(1))));
            }
        }

        foreach (var (stepId, stage) in deploymentSteps)
        {
            await OperationStore.RunStepAsync(
                context, run.Services.Operations, operationId, stepId, type, stage, tenantId: null, run.Services.Custody, cancellationToken);
        }

        await OperationStore.TryFinishAsync(context, run.Services.Operations, operationId, cancellationToken);
    }

    public static async Task StepAsync(JobRun run, CancellationToken cancellationToken)
    {
        // IDs are re-checked against the step row, never trusted. A malformed job fails with a fixed code.
        if (run.TenantId is not { } tenantId
            || !run.Ids.TryGetValue(OperationIdName, out var operationId)
            || !run.Ids.TryGetValue(StepIdName, out var stepId))
        {
            throw new InvalidOperationException("An Operation step job carries its Tenant, Operation ID and step ID.");
        }

        var context = run.Context;

        OperationType type;
        OperationCode stage;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = SelectStepForTenant;
            Sql.Add(command, "id", stepId);
            Sql.Add(command, "operation_id", operationId);
            Sql.Add(command, "tenant_id", tenantId);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return;
            }

            type = new OperationType(reader.GetString(0));
            stage = new OperationCode(reader.GetString(1));
        }

        await OperationStore.RunStepAsync(
            context, run.Services.Operations, operationId, stepId, type, stage, tenantId, run.Services.Custody, cancellationToken);

        // For a type with a completion handler this is always the finisher, in the Tenant's own scope.
        await OperationStore.TryFinishAsync(context, run.Services.Operations, operationId, cancellationToken);
    }

    /// <summary>
    /// Marks one Tenant step dispatched and enqueues its job, together in that Tenant's own
    /// scope. A step already dispatched is left alone, so a rerun enqueues nothing twice.
    /// </summary>
    private static async Task DispatchAsync(
        JobRunServices services,
        Guid operationId,
        Guid stepId,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        await using var scope = await TenantScope.BeginAsync(services.Source, tenantId, cancellationToken);
        var context = scope.CreateCommandContext();

        await using (var command = context.CreateCommand())
        {
            command.CommandText = DispatchTenantStep;
            Sql.Add(command, "id", stepId);
            Sql.Add(command, "operation_id", operationId);
            Sql.Add(command, "tenant_id", tenantId);

            if (await command.ExecuteNonQueryAsync(cancellationToken) == 0)
            {
                return;
            }
        }

        var payload = new JobPayload(new Dictionary<string, Guid>
        {
            [OperationIdName] = operationId,
            [StepIdName] = stepId,
        });

        await Enqueuer.EnqueueAsync(context, ProductionJobs.RunOperationStep, payload, runAfter: null, operationId, cancellationToken);
        await scope.CommitAsync(cancellationToken);
    }
}
